#pragma once
// Service credentials — the CMP RA, the OCSP responder and the SCEP
// RA. All three arrived at the same shape: ONE key for the process, N certificates,
// one per CA, each issued BY that CA and held in `certs` under
// cert_id "<prefix>-<ca_id>". A credential fronting CA 'a' must be certified by 'a'
// (RFC 6960 §4.2.2.2 says so outright for the responder), so a single instance-wide
// certificate can only ever be correct for one of them.
//
// This header exists because the same three facts were about to be written a third time:
// which credentials are configured, when one is due for renewal, and what "publish it"
// means. The accumulation hazard was once fixed in the test harness only, and the product
// path kept it until the lab surfaced it — one shared place is how that
// stops recurring.
#include <optional>
#include <string>
#include <vector>

#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/x509.hpp"

namespace pki {

// What a service credential IS — one definition, so the console form, the CLI and the
// renewal path cannot disagree about it.
//
// ⚠️ THIS USED TO LIVE ONLY IN THE CONSOLE'S JAVASCRIPT (`PURPOSE_EXT`), which meant the
// CLI could not create a service credential at all: `fastpki-ca` had no idea what subject
// or purposes one carries, so an unattended install — the AWS module, the Proxmox module,
// Kubernetes — finished with no OCSP responder, no CMP RA and self-signed listeners, and
// somebody had to open a browser. Putting the answer here is what lets both callers ask
// the same question. Add a credential HERE and every caller follows; there is no second
// place to remember.
struct ServiceCredSpec {
    std::string prefix;    // cert_id, or its PREFIX for the per-CA ones (<prefix>-<ca_id>)
    std::string label;     // human name: "OCSP responder", "CMP RA", "Console TLS"
    bool        per_ca{false};   // true  -> id is "<prefix>-<ca_id>", resolved per CA
                                 // false -> a global transport certificate, id is `prefix`
    // ⚠️ AN EMPTY CN MEANS "USE PKI_DNS", and that is the listeners' rule rather than an
    // omission: a TLS certificate has to carry the name a client actually dials, so it is
    // the deployment's own FQDN in both the subject CN and a dNSName SAN. The RA and
    // responder credentials are not TLS servers and never appear in a client's SNI, so
    // they carry a fixed, descriptive name instead.
    std::string cn{};
    bool        san_from_pki_dns{false};

    // ⚠️ NEVER LEAVE BOTH `eku` AND `eku_oids` EMPTY. An empty purpose list makes issuance
    // fall back to the profile's default_eku — {serverAuth, clientAuth} — so deleting the
    // last purpose silently grants two, which is the opposite of what deleting it meant.
    // ⚠️ `{}` ON EVERY MEMBER, even where it changes nothing. GCC's
    // -Wmissing-field-initializers fires for a designated initializer that omits a member
    // WITHOUT a default member initializer, and the tables below deliberately omit most of
    // them. Clang does not warn, so a macOS build stays clean while the Alpine image — and
    // tests/build_warnings.sh, which fails on any compiler output at all — does not.
    std::vector<std::string> ku{};        // key usages, OpenSSL names
    std::vector<std::string> eku{};       // extended key usages OpenSSL has a short name for
    std::vector<std::string> eku_oids{};  // and those it does not, as dotted strings

    // A delegated OCSP responder points at nothing for its own status: AIA and a CRL DP
    // would be a loop (RFC 6960 §4.2.2.2.1).
    bool omit_aia_crldp{false};
};

// Every service credential this build knows about, in a stable order.
std::vector<ServiceCredSpec> service_cred_specs();

// The spec for one cert_id or prefix, or nullopt when it names none.
std::optional<ServiceCredSpec> service_cred_spec_for(const std::string& id_or_prefix);

// A configured service credential: the cert_id prefix and the key the process holds.
struct ServiceCred {
    std::string prefix;    // "ocsp-ra" | "cmp-ra" | "scep-ra" — the cert_id PREFIX
    std::string key_ref;   // pkcs11: URI (a file only as a last resort, §3f)
    std::string label;     // human name for logs: "OCSP responder", "CMP RA", "SCEP RA"
    // ⚠️ `prefix` may have been RENAMED by *_CERT_ID_PREFIX, so it cannot be used to look
    // a spec up. This is the spec's own prefix, always one of the three canonical names,
    // and it is what service_cred_spec_for() answers to.
    std::string canonical;
};

// The credentials this configuration actually has a key for. A credential with no key
// is not "disabled" — the service simply has nothing to sign with and says so; there is
// nothing here to renew either.
std::vector<ServiceCred> configured_service_creds(const Config& cfg);

// ⚠️ Publish `row` as THE certificate for its cert_id: retire any existing active holder
// FIRST, then insert.
//
// A cert_id names ONE active certificate. get_cert_by_cert_id() selects status=0 and
// breaks ties on notAfter/serial, so two live rows make the service resolve an ARBITRARY
// one — and if that is not the certificate matching the key the process holds, it signs
// with one key while presenting the other and every response fails to verify. That is
// not hypothetical: it is what re-issuing an OCSP responder did on the lab, and two of
// three nodes still verified because the tie-break happened to land right.
//
// The previous certificate is RETIRED (status 3, superseded), not deleted: it stays
// auditable, and superseding is a different statement from revoking.
void publish_service_cert(Db& db, const CertRow& row);

// Is this certificate far enough through its life to be reissued?
//
// The threshold is a FRACTION of the certificate's own lifetime, not a fixed lead time:
// 30 days is most of a 90-day responder certificate and a rounding error on a ten-year
// one. 3/4 of lifetime was chosen as the better threshold.
bool service_cert_due(const X509* cert, double fraction);

// Reissue `old_cert` for `svc_key` from this CA: same subject and the same extensions
// that made it a service credential, fresh validity, new serial. Mints nothing — the key
// is the one the process already holds, which is the whole point of "one key, N certs".
// `urls` as for create_service_cert(): the signing CA's addresses, or nullptr to carry
// none. A renewal that dropped them would quietly strip revocation information from a
// credential that had it.
X509Ptr reissue_service_cert(const Config& cfg, X509* ca_cert, EVP_PKEY* ca_key,
                             X509* old_cert, EVP_PKEY* svc_key, const CaUrls* urls);

// Outcome of a renewal pass over one CA. `notes` are for the operator; `errors` are the
// reasons anything failed, so a caller can report them instead of just a count.
struct ServiceRenewResult {
    int checked = 0;   // credentials examined — provisioned ones, plus the missing ones
                       // when create_missing asked for those too
    int renewed = 0;   // reissued (or, under dry_run, would have been)
    // Counted apart from `renewed` because they are different events for an operator:
    // a renewal replaces a certificate, a creation gives the CA a credential — and a key —
    // it did not have. A run that says "created 3" is one to look at.
    int created = 0;
    // ⚠️ NOT a failure: this node holds no signing key for that CA. In a mesh every node
    // sees every CA — its own with a pkcs11 key, the others as keyless trust anchors it
    // verifies against and never signs with. Counting that as an error made a healthy
    // three-DC lab report "failed 4" on every node, every day, which is an alarm that
    // fires forever for the normal state. The node that DOES hold the key renews it.
    int skipped = 0;
    int failed  = 0;
    std::vector<std::string> notes;
    std::vector<std::string> errors;
};

// Renew every service credential this CA has issued, if due (or unconditionally when
// `force`). Idempotent: a credential that is not due, or not provisioned for this CA, is
// left alone.
//
// ⚠️ CASCADE ON REKEY — the settled rule: if a CA certificate is re-keyed, the
// dependent certificates must be re-signed, and that has to be automatic. After a rekey
// the service credentials are still signed by the OLD CA key, so they only chain to the
// new CA through the cross-certificate. That is not theoretical: it is exactly why the
// lab's DC1 responder answered "Response Verify Failure" until the intermediate was
// supplied by hand. Re-signing them under the new key restores a direct chain, so the
// console's rekey handler calls this with force=true and the operator does not have to
// know that a rekey silently made three other certificates awkward.
// `replicable` mints a NEW key extractable, so it can later be copied into the other host
// of an HA pair and a promotion needs no re-issuance. It is the operator's call, not the
// product's: whether a credential may leave its token trades blast radius against
// availability, and which side of that a deployment wants depends on its threat model.
// Ignored for a key that already exists — CKA_EXTRACTABLE is fixed at generation and
// PKCS#11 forbids granting it afterwards, so this only ever applies where a key is minted.
ServiceRenewResult renew_service_certs_for_ca(const Config& cfg, Db& db,
                                              const std::string& ca_id,
                                              bool force, bool dry_run,
                                              bool create_missing = false,
                                              bool replicable = false);

// Whether `key` is the key a current certificate of the service credential `prefix` (e.g.
// "ocsp-ra") certifies, under any CA. True when the credential has no certificate yet, since
// there is nothing for the key to disagree with.
//
// ⚠️ A KEY IS NOT PRESENT BECAUSE ITS LABEL IS. A credential's key URI is a config value that
// every host of a pair shares, so each host's token has an object under the same label — and
// when the two hosts ever minted their own, one of those objects matches no certificate while
// every label lookup still finds it. The responses it signs then fail to verify, and nothing
// that asks only "is there a key called ocsp-ra" can tell.
bool service_cred_key_matches(Db& db, const std::string& prefix, EVP_PKEY* key);

// The key settings for one credential — what to MINT when `create_missing` has to make a
// key that does not exist yet. `canonical` is ServiceCred::canonical.
//
// ⚠️ SCEP always answers "rsa" whatever else is configured, because its key decrypts the
// PKIOperation envelope and there is no config key that could say otherwise.
ServiceKeySpec service_key_spec_for(const Config& cfg, const std::string& canonical);

// The issuance request a spec implies, built WITHOUT issuing and without a key.
//
// ⚠️ This is separate from create_service_cert() so a caller that must MINT a key can run
// validate_leaf_request() FIRST. A request rejected after the key exists leaves a token
// object no certificate will ever name — untracked, in hardware, with nothing to notice it
// later. The console splits the same two steps for the same reason (see x509.hpp).
LeafRequest service_cred_request(const Config& cfg, const ServiceCredSpec& spec);

// Create a service credential from its SPEC rather than from a certificate it replaces:
// the subject, key usages and purposes come from service_cred_specs(), because on this
// path there is no previous certificate to copy them from. Mints nothing itself — the
// caller supplies a key.
//
// This is the half `reissue_service_cert` cannot do, and its absence is why an unattended
// install had no OCSP responder until somebody opened the console.
// ⚠️ `urls` IS WHAT PUTS AIA AND CRLDP ON THE CERTIFICATE, and passing nullptr leaves a
// credential with neither. Both minting paths took nullptr once, so no service credential
// carried revocation information at all — and the OCSP responder, the ONE that is supposed
// to carry none (RFC 6960 §4.2.2.2.1: a responder pointing at itself is a loop), was
// correct only by accident. `spec.omit_aia_crldp` is what expresses that intent, and it can
// only do its job when there is something to omit.
//
// The addresses belong to the CA that SIGNS this credential: a node with two issuing CAs
// mints a full set per CA, tagged <prefix>-<ca_id>, and each set must point at its own CA's
// CRL. `ca_urls_for_instance(db, cfg, ca_id)` is where the caller gets them.
X509Ptr create_service_cert(const Config& cfg, X509* ca_cert, EVP_PKEY* ca_key,
                            const ServiceCredSpec& spec, EVP_PKEY* svc_key,
                            const CaUrls* urls);

}  // namespace pki
