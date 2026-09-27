// Multi-tenant CA-instance resolution. Given a
// ca_instance_id from a virtualized protocol path (/endpoints/{id}/...), resolve
// the effective signing material for that instance, applying the global
// SIGNING_CA_* config as the fallback when the instance pins nothing.
#pragma once
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <openssl/types.h>   // opaque X509 / EVP_PKEY (no full API pulled in)

namespace pki {

class Db;
struct Config;
struct CaUrls;   // defined in pki/x509.hpp

struct ResolvedCa {
    std::string id;
    // WHY it is not servable, because "disabled" was answering for two different
    // things. `active` goes false both when an operator disabled the CA and when this
    // NODE holds no signing key for it — the ordinary state of a mesh peer, since
    // `certs` replicates every DC's CAs and only one of them has the key. Reporting both
    // as "CA instance disabled" sent an operator looking at a CAs page that correctly
    // showed the CA as active, which is a contradiction the product created, not him.
    bool has_local_key{true};
    std::vector<unsigned char> cert_der; // CA cert DER from DB certs table
    // EVERY live certificate this CA has, newest first — cert_der is chain_ders
    // front(). One entry normally; two while a rekey is rolling over, and BOTH belong
    // in a chain a client receives: a relying party still anchored on the old
    // certificate has to be able to build a path, which is the whole reason renewal
    // cross-signs instead of swapping. Anything serving a chain should send all of
    // these; anything SIGNING uses cert_der, which is the newest.
    std::vector<std::vector<unsigned char>> chain_ders;
    std::string cert_serial;             // serial for cache invalidation
    // Every chain serial, joined. cert_serial alone cannot detect the shrink at
    // the END of a rollover — when the old certificate expires the chain goes 2 -> 1
    // while the NEWEST serial is unchanged, so a cache keyed on cert_serial would keep
    // handing out the expired one. This changes on both edges.
    std::string chain_ref;
    std::string key;                     // effective signing key: PEM path or pkcs11: URI
    bool found{false};                   // is the id a registered ca_instance?
    bool active{false};                  // status == "active"
    // The CA's own certificate is revoked (certs.status = -1). Kept distinct from
    // `active` even though it forces `active` false, because the three reasons a CA is
    // unusable need three different messages: disabled is an operator switch and
    // reversible, no-local-key is a mesh peer's ordinary state, and revoked is neither.
    bool revoked{false};
    // Revoked with reason certificateHold (`revoked` is true too): unusable until an operator
    // releases the hold, which is the one revocation that can be undone.
    bool on_hold{false};
    // Past its own notAfter. Nobody decided this — time did — but it makes the CA just as
    // unusable, and it was the one unusable state that stayed invisible: get_ca_cert_der()
    // filters on notAfter, and the signing_ca_pem fallback below does not.
    bool expired{false};
};

// Resolve a ca_instance by id. found=false if the id isn't registered; active
// reflects its status. cert_pem/key fall back to the global SIGNING_CA_* when
// the instance doesn't pin its own crypto backing.
ResolvedCa resolve_ca_instance(Db& db, const Config& cfg, const std::string& id);

// Why a resolved CA cannot be used, phrased for an operator. THREE different facts had
// all been reported as "disabled" across four call sites: an operator switch (reversible),
// a mesh peer holding no local key for a CA it replicates (normal, not a fault), and a
// revoked CA certificate (irreversible, and published to relying parties). Telling an
// operator "disabled" about a revoked CA describes the one state it is not in.
std::string ca_unavailable_reason(const ResolvedCa& rc);

// The loaded signing material for a CA instance, handed to issuance.
// shared_ptr because concurrent request threads share one cached copy and a
// rotation may replace the cache entry while an in-flight request still holds it.
struct LoadedCa {
    std::shared_ptr<X509>     cert;
    std::shared_ptr<EVP_PKEY> key;
    std::string               id;    // resolved ca_instance id
    // Every LIVE certificate of this CA, parsed, newest first — `cert` is
    // chain.front(). `cert` is what SIGNS; `chain` is what a client should be given, and
    // during a rekey rollover those differ: the old certificate is still an anchor for
    // everyone who has not moved yet. A protocol that hands out a chain (MS-WSTEP's
    // PKCS#7) walks this; one that only signs uses `cert`.
    std::vector<std::shared_ptr<X509>> chain;
};

// Process-wide cache of loaded signing material, keyed by ca_instance id.
// Thread-safe. get() re-resolves the id against the DB every call (a cheap indexed
// read — the same lookup each protocol already does per request) and reloads the
// X509/EVP_PKEY only when the row's material *reference* (cert_pem path or key URI)
// differs from what was cached. So a CA created, key-rotated (new reference), or
// disabled in the console is picked up by the enrolment daemons — which are separate
// processes — WITHOUT a restart, because invalidation is pull-based, not a push the
// other processes could never receive. This generalizes CMP's per-request active_ca
// reload and replaces the other binaries' uncached per-request load.
//
// With material resolved lazily through this cache, no binary needs to
// preload a global signing CA at startup — a CA-less deploy starts, base routes 404,
// and each /{ca_id} route serves as soon as that CA exists in the DB.
class CaMaterialCache {
public:
    // Resolve `id` and return its loaded material. On failure returns nullopt and
    // sets `status`/`msg` for the caller to emit: 404 unknown/inert (not a servable
    // CA), 503 disabled or an incomplete backing (e.g. a mesh node without the key),
    // 500 material present but failed to load.
    std::optional<LoadedCa> get(Db& db, const Config& cfg, const std::string& id,
                                int& status, std::string& msg);
    // Drop one entry / everything. The reference-compare in get() already handles a
    // reference change; these force a reload even when the reference is unchanged
    // (e.g. the console rotated a key in place, same process).
    void invalidate(const std::string& id);
    void clear();

private:
    struct Entry {
        std::shared_ptr<X509>     cert;
        std::shared_ptr<EVP_PKEY> key;
        std::vector<std::shared_ptr<X509>> chain;   // every live cert, newest first
        std::string cert_ref;   // signing_ca_pem this entry was loaded from
        std::string key_ref;    // signing_ca_key this entry was loaded from
        std::string chain_ref;  // every live serial — catches BOTH rollover edges
    };
    std::mutex mu_;
    std::unordered_map<std::string, Entry> cache_;
};

// Which data centers a certificate's URLs may name.
//
// ⚠️ THIS IS A PROPERTY OF THE CERTIFICATE, NOT OF THE DEPLOYMENT, which is why it is a
// parameter rather than a setting. A service credential is presented by the CMP, SCEP or
// OCSP service running on THIS node, so a relying party only ever validates it while this
// node is answering — if the node is gone, so is the service that would have presented it,
// and a second address names a data center that has nothing to do with the question. An
// end-entity certificate outlives any particular node's availability, so for it the
// fallback is worth having and kAllDataCenters is the default.
enum class CaUrlScope {
    kAllDataCenters,   // every data center's address, so a relying party unable to reach
                       // one has another to try. The default, for end-entity certificates.
    kThisNode,         // this node's address alone — for certificates FastPKI issues to
                       // itself and presents from this node.
};

// The per-CA AIA/CRLDP URLs to bake into certs issued by ca_id. Looks up the
// CA's tenant and returns derive_ca_urls(). One call per issuance site sets
// IssuanceInput::ca_urls.
//
// ⚠️ WHAT A PEER'S ADDRESS IS WORTH, so a caller can judge whether it wants one. A CRL and a
// CA certificate are signed artifacts the mesh replicates, so a peer can serve another data
// center's copy — but only a copy: the data center holding the CA's key is the one that signs
// that CA's CRL, so once it has been gone past `nextUpdate` every replicated copy is expired,
// and a verifier that checks revocation treats an expired CRL as a failure rather than as "no
// information". The fallback buys time, not independence.
//
// An OCSP response is weaker still as a peer offering: it is signed PER REQUEST with that
// CA's `ocsp-ra-<ca_id>` private key, which a peer has no row for unless an operator chose to
// replicate it, and whether a key may leave its token is a policy decision.
CaUrls ca_urls_for_instance(Db& db, const Config& cfg, const std::string& ca_id,
                            CaUrlScope scope = CaUrlScope::kAllDataCenters);

// The client-certificate trust anchors for a protocol that authenticates callers
// by mTLS. Two additive DB-first sources, mirroring what CMP does:
//
//   ids     comma-separated ca_instance ids — their certificate rows are read from the
//           DB and the issuer chain above each is walked up to the self-signed root,
//           because OpenSSL treats an X509_STORE_add_cert() intermediate as untrusted
//           and chain validation fails without the root.
//   bundle  PEM text for external CAs that are not registered here at all.
//
// `anchors` receives the number actually added; a bad id or an unparseable bundle entry
// is skipped with a log line naming `who` and the key, never a silent zero. Returns an
// X509_STORE the caller owns.
//
// ⚠️ Both CMP and EST call THIS — do not copy it into a third protocol. A second
// implementation that got the root-walk right but the leaf rejection wrong (or vice
// versa) would authenticate callers one protocol refuses.
X509_STORE* build_client_trust_store(Db* db, const std::string& ids,
                                     const std::string& bundle,
                                     const char* who, const char* id_key,
                                     const char* bundle_key, int& anchors);

// A cheap fingerprint of the anchor set above, so a background refresher rebuilds the
// store only when something actually changed. Includes each anchor CA's current cert
// serial, so rotating an anchor CA is picked up as well as adding or removing one.
std::string client_anchor_sig(Db* db, const std::string& ids, const std::string& bundle);

// Install `store` as an httplib SSLServer's client-certificate verifier.
// SSL_VERIFY_PEER WITHOUT SSL_VERIFY_FAIL_IF_NO_PEER_CERT is deliberate and is the
// whole semantic: a client that presents NO certificate completes the handshake and
// falls through to the protocol's password authentication (RFC 7030 §3.2.3), while a
// client that presents one it cannot back up is killed at the handshake. That is what
// makes `req.peer_cert()` non-empty imply "verified against these anchors" — the
// property every caller of it relies on.
// Install a client-certificate trust store on a listener, and bind what it accepts.
//
// `db` is optional and, when given, closes the gap every mTLS path shares: they resolve a
// presented certificate to a local account BY SERIAL, which is safe only while everything
// completing the handshake was issued by us. With a foreign anchor configured it is not, so
// a verify callback refuses a certificate whose serial matches one of our rows and whose
// bytes do not. Pass it wherever a listener accepts client certificates.
bool install_client_trust(void* ssl_ctx, X509_STORE* store, class Db* db = nullptr);

// Set SSL_VERIFY_PEER on a listener AND bind what it accepts to the `certs` rows.
//
// ⚠️ Call this rather than SSL_CTX_set_verify. Every mTLS path resolves a presented
// certificate to a local account BY SERIAL, and a serial is a field the issuer chooses — so
// with any foreign anchor trusted, a certificate carrying a serial we issued would inherit
// that row's owner. The callback refuses exactly that case and leaves everything else alone.
// install_client_trust() calls it; a listener that builds its trust store some other way
// must call it too, or the binding is installed on only one way in.
void bind_client_certs(void* ssl_ctx, class Db* db);

// NOTE: there is deliberately no "resolve the default/first CA" helper. The
// enrolment protocols (EST/ACME/SCEP/CMP/MS) are id-based — every request names a
// /{ca_id} — because "the first CA" is ambiguous once there is a root and one or
// more sub-CAs. OCSP is the one exception: it is not an enrolment protocol and needs
// no id, so its shared /ocsp picks the signer from the requested cert's issuer.

} // namespace pki
