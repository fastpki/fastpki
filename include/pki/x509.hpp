#pragma once
#include <ctime>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
// imported_crl() returns std::optional. libc++ pulls <optional> in transitively so
// the Mac build was clean; Alpine's libstdc++ does not, and the image build failed with
// "'optional' in namespace 'std' does not name a template type". Include what you use.
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "pki/cert_profile.hpp"   // CustomExt, carried on LeafRequest

namespace pki {

// ⚠️ EVERY TIME-STAMPED ARTEFACT WE SIGN IS BACKDATED BY THIS MUCH.
//
// A certificate or CRL stamped with the instant we produced it is not yet valid on any
// client whose clock trails ours — and the client checks it milliseconds later, so the
// window in which the stamp is wrong is exactly the window of first use.
//
// Measured, not assumed: the lab's Windows client runs 1.75s behind the issuing DC,
// steady across samples. `certreq` rejected its own brand-new certificate with
// CERT_E_EXPIRED (0x800B0101) — "not within its validity period when verifying against
// the current system clock" — for a certificate whose notAfter was two years out.
// CryptoAPI returns that code for BOTH ends of the window; the end we tripped was the
// near one. The same run flagged the CRL and the OCSP response.
//
// ONE definition, deliberately: the certificate path (x509.cpp) and the CRL path
// (crl.cpp) must not drift apart, and a single name is greppable when someone asks
// "what else do we stamp?". Five minutes is the order AD CS uses (ClockSkewMinutes,
// default 10). Do NOT set it to zero to make a test's arithmetic neat — the zero IS
// the bug.
inline constexpr long kClockSkewBackdateSec = 300;

struct Config;

// RAII deleters for OpenSSL types we use across modules.
struct X509Deleter      { void operator()(X509* p)      const noexcept { X509_free(p); } };
struct EvpPkeyDeleter   { void operator()(EVP_PKEY* p)  const noexcept { EVP_PKEY_free(p); } };
struct X509ReqDeleter   { void operator()(X509_REQ* p)  const noexcept { X509_REQ_free(p); } };

using X509Ptr    = std::unique_ptr<X509, X509Deleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using X509ReqPtr = std::unique_ptr<X509_REQ, X509ReqDeleter>;

X509Ptr    load_cert_pem(const std::filesystem::path& path);
X509Ptr    load_cert_der(const std::filesystem::path& path);
X509Ptr    parse_cert_der(const std::vector<unsigned char>& der);  // from DB bytes
EvpPkeyPtr load_privkey_pem(const std::filesystem::path& path);

// A private key that may live in a FILE or in a token, chosen by the reference shape.
// For server identities that are not CA signing keys — the CMP/SCEP RA credential. A CA
// key has no file form at all (see load_signing_key); an RA credential does, because
// it is commonly issued to the deployment as a PEM, and forcing it into a token would
// remove a shape that works rather than closing a hole.
EvpPkeyPtr load_key_file_or_token(const std::string& key_ref, const Config& cfg);

// Can this key still SIGN? For a token key that is the only honest liveness
// question — the token lives in a separate container, and when it restarts every handle
// held across the process becomes invalid while looking perfectly fine.
//
// ⚠️ Loading is NOT a substitute. The OpenSSL pkcs11 provider serves a load from its own
// cache and returns a key after the token has gone; a load-based check reported healthy
// on a listener that could not complete a single handshake. Only an operation that must
// reach the token tells the truth, so this signs a fixed scratch buffer and throws the
// signature away.
//
// Cheap enough to call on a cached key: one small signature. Always true for a software
// key that loaded, which is the correct answer — a file cannot lose a session.
bool key_usable(EVP_PKEY* key);

// Parse zero or more certificates from an in-memory PEM string (not a file) —
// used for the CMP client-auth trust bundle held in the DB config. Skips malformed
// trailing data rather than throwing; returns what parsed cleanly.
std::vector<X509Ptr> load_certs_pem_mem(const std::string& pem);
// The CA certificate held in CaInstance::signing_ca_pem, which is now ALWAYS the
// certificate itself and never a path. Throws when the PEM holds none.
X509Ptr load_ca_cert_pem(const std::string& pem);

// Load a CA *signing* key given its reference `key_ref` (the `private_key` column on
// that CA's certificate row): a "pkcs11:" URI — a key resident in a PKCS#11 HSM / SoftHSM, loaded via the
// pkcs11 provider + OSSL_STORE so it never leaves the hardware (the default
// location for keys) — or, only as a last resort, an on-disk PEM path. `cfg` supplies
// the pkcs11 provider config. Returns nullptr when key_ref is empty. The returned
// EVP_PKEY drives X509_sign / X509_CRL_sign / CMS signing transparently.
// A CA's signing key reference: ONE pkcs11: URI, or SEVERAL separated by newlines, tried in
// order so signing survives the loss of the node holding any one of them.
//
// Pass `expect` — the CA's own certificate — wherever it is available. Without it a
// candidate that loads is accepted, which cannot tell a stale token from a current one; with
// it, each candidate is checked against the certificate first, so "the first URL that works"
// means the first that holds THIS key rather than the first that answers. A candidate that
// holds a different key is skipped and logged at error; one that is merely unreachable is
// logged at info, that being ordinary in a multi-node deployment.
EvpPkeyPtr load_signing_key(const std::string& key_ref, const Config& cfg,
                            X509* expect = nullptr);

// The individual URLs in a key reference, in order, blank entries dropped. Newline is the
// separator because RFC 7512 already gives a pkcs11 URI both ';' and '&' internally.
std::vector<std::string> split_key_urls(const std::string& key_ref);

// Detect whether `key` is an EC private key backed by a PKCS#11 provider
// (SoftHSM2 etc.).  Used by the signing helpers and audit to pre-hash
// the TBS in software before signing with CKM_ECDSA.
bool is_ec_p11_key(EVP_PKEY* key);

// Detect whether `key` is an EdDSA (Ed25519/Ed448) private key backed by a
// PKCS#11 provider.  SoftHSM2's EdDSA mechanism (CKM_EDDSA) rejects
// EVP_DigestSignInit when a non-null digest is supplied; the signing helper
// must use EVP_DigestSign with a null digest instead.
bool is_eddsa_p11_key(EVP_PKEY* key);

// Detect whether `key` is an RSA-PSS private key backed by a PKCS#11 provider.
// The pkcs11 provider's digest_sign path (C_SignUpdate) does not work for
// RSA-PSS mechanisms on SoftHSM2; the signing helpers must use X509_sign_ctx
// (for certs) or X509_CRL_sign_ctx (for CRLs) with pre-configured PSS
// parameters so the provider selects CKM_*_RSA_PKCS_PSS.
bool is_rsa_pss_p11_key(EVP_PKEY* key);

// Does this key need RSA-PSS padding when signing? Delegates to
// EVP_PKEY_is_a(key, "RSA-PSS") — the pkcs11 provider reports the
// correct type at generation time, and our provider patch makes it
// correct for loaded keys too.
bool p11_rsa_requires_pss(EVP_PKEY* key);

// Sign an X.509 certificate, working around provider-specific quirks:
// - RSA-PSS on pkcs11: X509_sign_ctx with PSS params.
// - EC keys on pkcs11: pre-hash TBS, sign raw digest with CKM_ECDSA.
// - EdDSA keys (any provider): override md to NULL — EdDSA hashes internally
//   and OpenSSL rejects any explicit digest.
// - All other key types delegate to X509_sign.
// Returns the (possibly different) X509* — callers must use the returned
// value and free the original when it differs.
X509* sign_x509(X509* cert, EVP_PKEY* key, const EVP_MD* md);

// --- CA bootstrap -----------------------------------------------------------

// Generate a fresh private key. algo: "rsa" (rsa_bits, default 4096) or "ec"
// (NIST P-256). For HSM-backed keys, generate the key in the token out of band
// and reference it with a pkcs11: URI instead.
EvpPkeyPtr generate_key(const std::string& algo, int rsa_bits = 4096);

// Extended key generation for the CA-creation page:
//  - "rsa"  : rsa_bits (2048/3072/4096)
//  - "ec"   : ec_curve ("P-256"/"P-384"/"P-521"), default P-256
//  - "ed25519" / "ed448"
//  - a provider algorithm name for PQC, e.g. "ML-DSA-44/65/87", "SLH-DSA-..."
//    (available when built against OpenSSL >= 3.5). Case-insensitive.
EvpPkeyPtr generate_key_ex(const std::string& algo, int rsa_bits, const std::string& ec_curve);
// The value to record in `certs.keyAlgo` for a key we MINTED ourselves.
//
// The key type is stored in the DB so the code knows, without trial and error, which kind
// of RSA key it is dealing with. Today `insert_cert` DERIVES this column from
// the certificate's SPKI — and for the keys this exists to distinguish, the SPKI is exactly
// what is wrong: an RSA-PSS token key is certified `rsaEncryption`, so the derived value
// says `RSA` and the one fact worth recording is lost at the moment it was known.
//
// ⚠️ NOT the same string generate_key_in_token() hands the PROVIDER, and deliberately not
// merged with it. That one answers "what do I call this key type to pkcs11" (`ED25519`);
// this one answers "what kind of key is this" in the vocabulary `certs.keyAlgo` already
// uses everywhere else (`Ed25519`, from EVP_PKEY_base_id). Two questions, two answers —
// collapsing them would silently change the value the dashboard groups by.
//
// They do NOT simply agree — the provider calls it `RSA-PSS` and this column has always
// spelled it `RSASSA-PSS` (OBJ_nid2sn), which is why merging them would split the one key
// type the dashboard groups by into two buckets. `pss_loaded_key_signing.sh` pins the
// stored spelling rather than leaving it to a comment.
std::string db_key_algo(const std::string& algo_in);


// Generate a new keypair INSIDE a PKCS#11 token: the
// private key is created as a permanent token object and never leaves the HSM.
// `key_uri` is the pkcs11: URI naming where to store it (token + object label + id).
// The returned EVP_PKEY references the in-token key. RSA/EC/Ed25519.
//
// ⚠️ `replicable` IS DECIDED HERE OR NEVER. It mints the private key with CKA_EXTRACTABLE
// set, so it can later be copied — wrapped — into another node's token (an HA pair, or a
// mesh node that must sign from elsewhere). PKCS#11 fixes the attribute at generation and
// cannot grant it afterwards, so a key minted without it can never leave this token. The
// OpenSSL pkcs11 provider has no parameter for the attribute, so a replicable key is minted
// through PKCS#11 directly and loaded back by URI. Every CA key algorithm is supported
// (pkcs11_replicable_refusal()); anything else throws before the token is touched.
EvpPkeyPtr generate_key_in_token(const std::string& key_uri, const Config& cfg,
                                 const std::string& algo,
                                 int rsa_bits, const std::string& ec_curve,
                                 bool replicable = false);

// Full RFC 5280 CA attribute surface for the console CA-creation page.
// Empty/zero fields fall back to sensible CA defaults.
struct CaCertParams {
    std::string subject_dn;                 // OpenSSL one-line "/CN=.../O=..."
    int64_t     not_before = 0;             // epoch seconds; 0 => now
    int64_t     not_after  = 0;             // epoch seconds; 0 => now + 3650d
    bool        never_expire = false;       // RFC 5280 99991231235959Z notAfter
    int         pathlen = -1;               // <0 => omit pathLenConstraint
    std::vector<std::string> key_usage;     // empty => keyCertSign,cRLSign
    // NameConstraints, e.g. "DNS:example.com", "IP:10.0.0.0/8". An IP entry may be
    // written CIDR or address/netmask; RFC 5280 encodes address+mask, and the CIDR
    // form is expanded on the way in (see nc_normalize_ip).
    std::vector<std::string> permitted;
    std::vector<std::string> excluded;
    std::vector<std::string> crldp;         // CRL DistributionPoint URIs
    std::vector<std::string> aia_issuers;   // AIA caIssuers URIs
    std::vector<std::string> aia_ocsp;      // AIA OCSP URIs
    std::vector<std::string> policies;      // certificatePolicies OIDs
    std::string md = "sha256";              // signature hash (ignored for EdDSA/ML-DSA/SLH-DSA)
    // Opens the signature floor for `md` above. Defaults to closed: a CA certificate is the
    // anchor everything under it chains through, so the caller has to carry the
    // deployment's opt-in in deliberately rather than inherit it by omission.
    bool allow_weak_md{false};
};
// Build (optionally sign) a CA certificate from the full parameter set.
X509Ptr build_ca_certificate_ex(EVP_PKEY* subject_key, const CaCertParams& p, X509* issuer_cert = nullptr);
X509Ptr create_ca_certificate_ex(EVP_PKEY* subject_key, const CaCertParams& p,
                                 X509* issuer_cert = nullptr, EVP_PKEY* issuer_key = nullptr);

// Certify one CA key under another CA's signature — the primitive CA rekeying is
// built from. The result is an ordinary CA certificate carrying `subject_pubkey`, issued
// by `signer_cert` and signed with `signer_key`, over the SAME subject as signer_cert
// (a CA's identity does not change when its key does).
//
// Renewal calls it TWICE, in opposite directions, so trust holds whichever anchor a
// relying party has:
//   (old_cert, old_key, new_pub)  the new key, vouched for by the old CA
//   (new_cert, new_key, old_pub)  the old key, vouched for by the new CA
X509Ptr cross_sign_ca(X509* signer_cert, EVP_PKEY* signer_key,
                      EVP_PKEY* subject_pubkey, const CaCertParams& p);

// Renew a CA: a new certificate for the SAME CA over `subject_pubkey` — its current key or
// a new one — signed by its parent (`issuer_cert`/`issuer_key`), or self-signed with
// `issuer_key` when `issuer_cert` is null (a root). The subject and the CA's constraints and
// policies are carried over from `current_cert`; validity, digest and the CRL DP / AIA URLs
// come from `p`, and notAfter never passes the issuer's. Unlike cross_sign_ca, the result
// chains to the parent (or is itself an anchor), so it can outlive the certificate it
// renews — which is what renewing a CA is for.
X509Ptr renew_ca_certificate(X509* current_cert, EVP_PKEY* subject_pubkey,
                             X509* issuer_cert, EVP_PKEY* issuer_key, const CaCertParams& p);

// Cross-sign a FOREIGN CA — a different organisation's root, so that relying
// parties anchored on ours will accept certificates issued under theirs.
//
// Deliberately NOT cross_sign_ca() above. That one copies the SIGNER's subject, because
// in a rekey the signer and the subject are the same CA. Here they are not: the subject
// is somebody else's, and getting that wrong would mint a certificate claiming our own
// name over their key.
//
// The safety envelope is enforced HERE rather than left to callers, because a
// cross-certificate without it is an unbounded delegation of our trust:
//   * p.permitted must be non-empty — name constraints are mandatory, so the foreign CA
//     can only certify names inside the scope we grant it.
//   * p.pathlen must be >= 0 — a deliberate depth, so it cannot mint further CAs
//     without our having said so.
// Both throw rather than defaulting. A default here would be a silent grant, and the
// whole point of the operation is that the grant is explicit.
X509Ptr cross_sign_foreign_ca(X509* signer_cert, EVP_PKEY* signer_key,
                              X509* foreign_cert, const CaCertParams& p);

// Create a CA certificate for `subject_key` with subject `subject_dn` (OpenSSL
// one-line "/CN=.../O=..." form), valid `days`, with basicConstraints CA:TRUE,
// keyUsage keyCertSign+cRLSign, and subject/authority key identifiers. Returns a
// self-signed root when issuer_cert/issuer_key are null, otherwise a Sub-CA
// signed by that issuer.
X509Ptr create_ca_certificate(EVP_PKEY* subject_key, const std::string& subject_dn,
                              int days, X509* issuer_cert = nullptr,
                              EVP_PKEY* issuer_key = nullptr);

// The digest create_ca_certificate() signs a CA certificate with: an RFC 4055 restriction
// published by the signer's own certificate if there is one, otherwise sized from the
// signing key. Exposed so a caller that must build through CaCertParams — to add AIA and
// CRLDP, say — can ask for the SAME digest the simple form would have chosen, instead of
// changing how a CA is signed as a side effect of changing what it carries.
const EVP_MD* ca_signing_md(EVP_PKEY* key, X509* key_cert);

// Publish this node's data center serial prefix to the certificate minter.
// Every certificate this node MINTS — leaves, our own CA certs, our self-signed transport
// certs — then carries `prefix` in the top two octets of its serial, which is what makes a
// cross-data-center serial collision impossible (the serial is the certs primary key, and a
// collision stalls a peer's replication apply worker).
//
// dc_id empty => single node, no prefix. prefix must be 1..32767 (the high bit must stay
// clear or DER pads the serial to 21 octets, out of RFC 5280 §4.1.2.2).
//
// Call it through resolve_datacenter_prefix() (config.hpp), which reads the value from
// this node's own `datacenters` row — that table is the single source of truth.
void set_datacenter_serial_prefix(const std::string& dc_id, int prefix);
// The same fact, for certs.ins_seq. 0 = no data center configured (single node),
// which is prefix-space 0 — a space no DC may occupy, so it cannot collide with a mesh.
int  datacenter_serial_prefix();

// Build a CA certificate (same fields/extensions as create_ca_certificate) but
// WITHOUT signing it — for callers that sign externally.
X509Ptr build_ca_certificate_unsigned(EVP_PKEY* subject_key, const std::string& subject_dn,
                                      int days, X509* issuer_cert = nullptr);

// A PKCS#10 certification request for a CA key that lives HERE while the signature has
// to come from a CA that lives somewhere else — the cross-datacenter sub-CA case, where
// the subordinate's key must stay inside its own node's token and only the parent can
// sign it.
//
// The request carries what the requester is ASKING for as an extensionRequest attribute:
// basicConstraints CA:TRUE (with pathlen when set), keyUsage, nameConstraints and
// certificatePolicies. It deliberately does not carry AIA/CRLDP or the key identifiers —
// those name the ISSUER, so only the signer can fill them in, and a requester that
// supplied them would be describing a chain it does not control.
//
// `key` signs the request, which is the proof of possession. Everything in `p` other than
// the fields above is ignored: validity is the signer's decision, not the requester's.
X509ReqPtr build_ca_csr(EVP_PKEY* key, const CaCertParams& p);

// Sign a certification request in place, returning it. The counterpart of sign_x509 and
// it carries the same three provider workarounds, because the key signing a CSR for a CA
// is a token key just as often: EdDSA's NULL digest, the PSS parameters a
// PSS-restricted token key needs, and the EC pre-hash.
X509_REQ* sign_x509_req(X509_REQ* req, EVP_PKEY* key, const EVP_MD* md);

// Write a cert / private key to a PEM file. The key file is created 0600.
void write_cert_pem(const std::filesystem::path& path, X509* cert);
void write_privkey_pem(const std::filesystem::path& path, EVP_PKEY* key);

// The INTERMEDIATE chain above `leaf`, walked through the registered CAs by
// issuer name (and by authority-key-id where the leaf carries one). The self-signed
// root is deliberately NOT in the returned string — a TLS server sends intermediates
// only (RFC 8446 §4.4.2) and the client is expected to hold the anchor.
//
// Exported, and adds `anchor_pem`: when non-null it receives that root's PEM,
// because the Postgres path needs BOTH halves and they come from one walk. Postgres
// serves ssl_cert_file (leaf + intermediates) while the application dials it with
// sslmode=verify-full sslrootcert=<anchor>, so producing one without the other leaves
// a database nobody can connect to. Empty when the walk never reached a trust anchor.
std::string build_issuer_chain(class Db& db, X509* leaf, std::string* anchor_pem = nullptr);

// Generate a self-signed TLS *server* certificate (EC P-256, CA:FALSE, EKU
// serverAuth, SAN) entirely in memory — how a listener comes up over HTTPS before
// any CA exists (a fresh deployment has no CAs). Called by
// resolve_transport_cert, which publishes the result and replaces it as soon as a
// CA-issued certificate appears for that id. Returns {cert_pem, key_pem};
// `dns_sans` defaults to just `cn` when empty.
struct ServiceKeySpec;   // config.hpp; referenced only, never by value here

// `keyspec` is the SERVICE's own key choice. It defaults to the same ec/P-256 this
// always produced, so an unconfigured deployment is byte-for-byte unchanged — what moves
// is that <SVC>_KEY_ALGO / _BITS / _CURVE now mean something on a FILE key, not only on a
// pkcs11: one. Before this they were parsed, documented and silently ignored on the path
// certgen.sh actually writes.
std::pair<std::string, std::string>
make_selfsigned_tls_pem(const std::string& cn,
                        const std::vector<std::string>& dns_sans, int days);
// The same thing with the SERVICE's own key choice. An OVERLOAD rather than a
// defaulted argument because this header only forward-declares ServiceKeySpec (it does not
// include config.hpp), and a default of `{}` would need the complete type. The three-arg
// form keeps producing ec/P-256, so an unconfigured deployment is unchanged.
std::pair<std::string, std::string>
make_selfsigned_tls_pem(const std::string& cn,
                        const std::vector<std::string>& dns_sans, int days,
                        const ServiceKeySpec& keyspec);

// Pick the transport cert for an HTTPS protocol listener (EST/ACME/MS).
// If cert_path AND key_path both exist on disk, use them (use_files=true). Otherwise
// generate a temporary in-memory self-signed cert (via make_selfsigned_tls_pem; CN from
// `dns`, or "localhost") so the listener comes up on a CA-less deploy instead of
// crash-looping — a real CA-issued cert on disk always wins on the next start.
struct TransportCert {
    bool use_files{false};     // true → cert_pem/key_pem are file paths; false → PEM content
    std::string cert_pem;      // file path (use_files=true) or PEM content (false)
    std::string key_pem;       // file path (use_files=true) or PEM content (false)
    std::string chain_pem;     // CA chain PEM content (intermediates + root); empty = self-signed
    // A token-resident key CANNOT be serialised to PEM — that is the point of an
    // HSM. When the key lives in a PKCS#11 token this carries the provider-backed
    // handle and key_pem is empty; load_tls_context installs it with
    // SSL_CTX_use_PrivateKey. shared_ptr because TransportCert is copied into lambdas.
    std::shared_ptr<EVP_PKEY> key;
};
TransportCert resolve_transport_cert(const std::filesystem::path& cert_path,
                                     const std::filesystem::path& key_path,
                                     const std::string& dns,
                                     const ServiceKeySpec& keyspec);
// DB-first overload: check certs table for cert_id, load key via load_signing_key
// (supports pkcs11: URIs), then fall back to filesystem / self-signed.
// Builds the CA chain from each registered CA's stored certificate when available.
class Db;
//
// `keyspec` is the SERVICE's own key choice: each listener passes its own
// cfg.<service>_key rather than a single shared setting, because "give a customer full
// control over keys for each service" is exactly what one shared answer cannot do.
// The row id a LISTENER's transport certificate actually lives under.
//
// `certs` is replicated, so a bare id like `ms` names the SAME ROW on every node in a
// mesh — and publish_service_cert retires the previous holder of an id, by id alone. Three
// nodes each issuing `ms` against their own HSM key therefore leave ONE active row and two
// superseded ones. Nothing fails at issuance; each listener keeps serving what it loaded,
// and the node only breaks on its NEXT restart, when it finds no active row and falls back
// to a temporary self-signed certificate. On the lab that surfaced ~50 minutes after
// everything had been verified as correct.
//
// So a listener certificate is scoped by NODE. ⚠️ Not by CA, which is what the RA
// credentials do (`cmp-ra-<ca_id>`): an RA credential genuinely belongs to a CA because it
// signs for it, but a transport certificate belongs to the node — it is bound to that
// node's HSM key and its hostname. Two nodes serving the same CA is a perfectly ordinary
// mesh, and per-CA scoping would collide there in exactly the same silent way.
//
// DATACENTER_ID is the node's identity in the mesh and is already what keeps SERIALS from
// colliding, so this reuses the identifier operators already set rather than adding
// one. Empty (single-node) yields the bare id, so nothing changes for them.
std::string listener_cert_id(const Config& cfg, const std::string& base);

// The same node scoping for the KEY the certificate belongs to: rewrites `object=` in a
// pkcs11: URI to <object>-<DATACENTER_ID>, idempotently, and returns the input untouched
// for a file path or an unset DATACENTER_ID.
//
// ⚠️ FOR THE FOUR LISTENER KEYS ONLY (web-tls, est-tls, acme-tls, ms-tls) — the ones whose
// cert id already goes through listener_cert_id(). A shared token makes `object=` ambiguous
// because CKA_LABEL is free text and every node mints its own key under the same name; the
// certificate is node-scoped and the key was not, which is the mismatch. A CA key must NOT
// be scoped this way — the shared-token shape depends on one label naming one object from
// every node — and nor must the RA credentials, whose cert id is `<prefix>-<ca_id>` and
// which therefore belong to the CA rather than to the node.
std::string listener_key_uri(const Config& cfg, const std::string& raw);

// Outcome of promoting this node's self-signed listener certificates to CA-issued ones.
struct TransportReissueResult {
    int checked  = 0;   // listener certificates examined
    int reissued = 0;   // promoted (or, under dry_run, would have been)
    int skipped  = 0;   // already CA-issued, not published yet, or another node's identity
    int failed   = 0;
    std::vector<std::string> notes;
    std::vector<std::string> errors;
};

// ⚠️ Re-issue this node's SELF-SIGNED listener certificates, keeping each existing key.
// The signing CA is `requested_ca` when given (--ca), else HTTPS_CA_ID, else this node's
// only issuing CA — and it is chosen only when a listener actually needs promoting, so a
// node whose listeners are all CA-issued never fails over which CA it would have used.
//
// A listener mints a 90-day self-signed certificate at first start because it has to
// answer HTTPS before any CA exists. Once one does, that certificate should be replaced
// by a CA-issued one — but nothing promotes it: resolve_transport_cert only re-issues a
// certificate that was ALREADY CA-issued, under the CA that issued it, so a self-signed
// one stays self-signed forever unless an operator opens the console. This is that step,
// and it belongs to the same moment as `renew-service-certs --create-missing`: both are
// things that could not be done until a CA existed.
//
// The KEY IS NOT TOUCHED. Only the issuer changes, and the subject and SANs are the ones
// the listener would have chosen itself, so this promotes an identity rather than
// replacing it. A named root is honoured but noted; a root is never chosen automatically.
TransportReissueResult reissue_self_signed_transport_certs(const Config& cfg, Db& db,
                                                           const std::string& requested_ca,
                                                           bool dry_run);

// Renew this node's CA-ISSUED listener certificates (console, EST, ACME, MS) once each is
// past SERVICE_CERT_RENEW_FRACTION of its lifetime, or all of them with `force`. The key,
// the subject, the subjectAltNames and the lifetime are kept, and the CA is the one that
// issued the current certificate.
//
// ⚠️ UNLESS PKI_DNS DISAGREES WITH THE CERTIFICATE, in which case the new NAME is used and
// the note says so. A listener certificate has to carry the name a client dials, so one that
// no longer matches PKI_DNS is stale by definition — and keeping the subject would mean every
// renewal faithfully reproducing a mistake the operator has already corrected. Since a
// certificate's name cannot be changed after issuance, re-issuing is the only repair, and
// without this there was none: `--re-issue-self-signed` skips these as "already CA-issued"
// and `--force` renewed them under the old name. `only_ca`, when set, limits the run to certificates that
// CA issued. The predecessor is marked superseded.
//
// ⚠️ WITHOUT THIS NOTHING RENEWED THEM. The RA credentials had renew_service_certs_for_ca,
// the self-signed ones had the promotion above, and a listener re-issues at startup only
// once its certificate has EXPIRED — so every listener served an expired certificate for
// however long it ran past the date, and fell back to self-signed if the expiry sweep got
// there before a restart. The running listener picks the renewal up without a restart
// (serve_renewed_transport_certs, transport_reload.hpp).
TransportReissueResult renew_ca_issued_transport_certs(const Config& cfg, Db& db,
                                                       const std::string& only_ca,
                                                       bool force, bool dry_run);

TransportCert resolve_transport_cert(Db& db, const std::string& cert_id,
                                     const std::filesystem::path& cert_path,
                                     const std::filesystem::path& key_path,
                                     const Config& cfg,
                                     const std::string& dns,
                                     const ServiceKeySpec& keyspec);

// ⚠️ Say which transport certificate a listener actually came up on. EST, ACME and MS
// each used to log "serving HTTPS on a TEMPORARY self-signed cert" from the branch that
// resolve_transport_cert returns for BOTH outcomes — so a listener that had correctly
// picked up its CA-issued certificate announced the opposite, every start. That is not
// cosmetic: it is the first line an operator reads when a Windows client will not
// enrol, and it sends them looking for a missing certificate they already have. It cost
// a live investigation twenty minutes.
//
// `chain_pem` is the honest discriminator and always has been — see TransportCert, where
// it is documented as "empty = self-signed".
void log_transport_cert(const char* service, const TransportCert& tc, const std::string& dns);

// DER → PEM conversions for certificates and keys.
std::string der_to_pem_cert(const std::vector<unsigned char>& der);
std::string evp_pkey_to_pem(EVP_PKEY* pkey);

// Load cert + chain + key into an SSL_CTX for use with httplib's
// ContextSetupCallback. Returns true on success. thread-safe.
// ssl_ctx is an opaque pointer (SSL_CTX* from OpenSSL).
bool load_tls_context(void* ssl_ctx, const TransportCert& tc);

// ---- CSR / issuance --------------------------------------------------------

// Parse a PKCS#10 CertificationRequest from PEM or DER input. Verifies the
// embedded signature (POP). Throws pki::Error on malformed or bad-signature.
X509ReqPtr parse_csr(std::string_view bytes);

struct CaUrls;   // per-CA AIA/CRLDP URLs (defined below); IssuanceInput holds a pointer

// Inputs to issue_cert(): the policy distilled from cfg + the authenticated
// user the resulting cert is bound to.
struct IssuanceInput {
    // A reference member has no empty value to default to, and Config is only
    // forward-declared here; every caller supplies cfg in the aggregate initializer.
    // cppcheck-suppress uninitMemberVarNoCtor
    const Config& cfg;
    X509*         ca_cert{nullptr};  // signing CA
    EVP_PKEY*     ca_key{nullptr};   // signing CA private key
    X509_REQ*     csr{nullptr};      // verified CSR (subject + pubkey + reqd exts)
    std::string   owner_username;   // CN of authenticated user → stored in DB.owner
    std::string   profile;          // cert policy profile name.
                                    // Set from resolve_profile() (identity→profile
                                    // assignment → CA default). NO role of any
                                    // kind enters a certificate — not the console RBAC
                                    // role, and not an org label either.
    bool          acme{false};      // true → skip domains.txt allowlist (DV done)
    // Context-aware identity mapping. When set, the issued
    // subject is bound to the *authenticated* identity rather than the CSR's:
    // `subject_cn` replaces the CSR's CN (Username → CN), and each `org_units`
    // entry is stamped as an OU (Group → OU). Empty → keep the CSR subject as-is.
    std::string              subject_cn{};   // "" → keep the CSR's CN
    std::vector<std::string> org_units{};    // OU entries from the caller's groups
    // ⚠️ THE PROVIDER IS NOT PART OF THE PERSON'S NAME. A federated or directory session
    // is `<provider>\<user>`, and putting that whole string in the commonName made the CN
    // stop being a name -- it became a name plus an authentication detail, complete with a
    // backslash inside a DN component.
    //
    // It is stamped as a domainComponent instead, which is what names the authority a
    // subject was asserted by. Deliberately NOT an OU: `org_units` already carries the
    // caller's GROUPS, so a provider stamped there would be indistinguishable from a group
    // the user happens to be in -- the DN would no longer say which was which.
    std::string              subject_domain{};   // DC entry naming the asserting provider
    // Discard the REQUESTED name entirely and build it from the authenticated identity:
    // every RDN of the CSR subject is dropped before `subject_cn`/`org_units` are applied,
    // and the CSR's subjectAltName is not copied onto the certificate.
    //
    // ⚠️ `subject_cn` ALONE IS NOT A NAME BINDING. It replaces the commonName and leaves
    // every other RDN standing, so a CSR carrying `emailAddress=victim@…` — or any SAN at
    // all — still names somebody else in the issued certificate. Wherever the policy is
    // "the requester may not choose who this certificate is for", both halves are needed.
    //
    // The certificate-template model this mirrors expresses exactly that: when a template
    // does not grant enrollee-supplies-subject, the CA constructs the name and the request
    // has no say in it.
    bool replace_subject{false};
    // Request-extension OIDs to copy verbatim into the issued cert.
    // MS-WSTEP sets the Microsoft certificate-template OIDs so a Windows-issued
    // cert keeps its template identity. Empty for every other caller.
    std::vector<std::string> passthrough_ext_oids{};
    // Per-CA AIA/CRLDP override. When set, the issued cert's AIA (caIssuers +
    // OCSP) and CRL DP are taken from these derived per-tenant/per-CA URLs instead of
    // the global cfg.aia_*/crl_distribution_points. Callers set it via
    // derive_ca_urls(); must outlive the issue_cert() call. null → global cfg.
    const CaUrls* ca_urls{nullptr};
    // What this REQUEST asks to leave out — an authorized OCSP responder carries
    // neither (RFC 6960 §4.2.2.2.1). Honoured only when the resolved profile permits it
    // (manage_aia / manage_crldp); asking is never enough on its own.
    bool omit_aia{false};
    bool omit_crldp{false};
    // A profile supplied BY THE CALLER instead of looked up by name. Only the EST
    // device self-renewal path sets it, with pki::profile_from_cert() applied to the
    // certificate being renewed — a kind of VIRTUAL profile that allows only the same
    // attributes on the CSR as the provided certificate already carries.
    //
    // ⚠️ Not registered anywhere and not nameable. `profile` is looked up in
    // cfg.cert_profiles, so a client that could name this one could use it; this exists
    // for the length of one request. Must outlive the issue_cert() call. null = the
    // ordinary lookup by name, which is every other caller.
    const CertProfile* profile_override{nullptr};
    // The digest this request asks for. Honoured only where a choice exists —
    // RSA/RSA-PSS CA keys, and never over an RFC 4055 restriction. See leaf_signing_md().
    // Empty (every enrolment protocol) means the CA's own default, unchanged.
    std::string requested_md{};
};

// Lower-level issuance from already-extracted parts. Used directly by the CMP
// path (which gets subject/pubkey/extensions from a CRMF template rather than
// a PKCS#10 CSR). `san_exts` may be nullptr; if present, a SubjectAltName
// extension is copied from it. Caller owns all inputs.
// `owner_username`, when non-empty, is emitted in a Subject Directory Attributes
// extension (RFC 5280 §4.2.1.8) as a synthesized owner DN — and that is
// the ONLY thing the SDA carries. The id-at-role attribute is gone. A
// certificate says who you are; what you may do is RBAC's, and lives outside it.
// CMP callers leave owner empty.
X509Ptr issue_cert_from_parts(const Config& cfg, X509* ca_cert, EVP_PKEY* ca_key,
                              X509_NAME* subject, EVP_PKEY* subject_pubkey,
                              STACK_OF(X509_EXTENSION)* req_exts,
                              const std::string& role, bool acme = false,
                              const std::string& owner_username = "",
                              const std::vector<std::string>& passthrough_ext_oids = {},
                              const CaUrls* ca_urls = nullptr,
                              // What this REQUEST asks to leave out. Suppression
                              // still requires the resolved profile to permit it
                              // (manage_aia / manage_crldp), so a caller cannot drop AIA
                              // by asking — the profile decides whether asking counts.
                              bool omit_aia = false, bool omit_crldp = false,
                              // Use THIS profile rather than resolving `role` in
                              // cfg.cert_profiles. See IssuanceInput::profile_override.
                              const CertProfile* profile_override = nullptr,
                              // The digest THIS request asks the CA to sign with.
                              // Honoured only where a choice exists — see
                              // leaf_signing_md(). Empty means "the CA's default".
                              const std::string& requested_md = "");

// The signature digest for a leaf — the CA default, overridden by `requested` only
// when the CA key is RSA/RSA-PSS and no RFC 4055 restriction forbids it. EC and the
// one-shot schemes always auto-match.
// `allow_weak` opens the signature floor (SHA-1, MD5 and friends). It DEFAULTS TO CLOSED
// so that a call site which does not know the deployment's posture refuses rather than
// permits — the safe direction for a default that will be got wrong somewhere.
const EVP_MD* leaf_signing_md(EVP_PKEY* ca_key, X509* ca_cert, const std::string& requested,
                              bool allow_weak = false);
// True for digests that are broken as SIGNATURE hashes. Compared by NID, so every spelling
// EVP_get_digestbyname accepts ("sha1", "SHA1", "RSA-SHA1") is covered by one entry.
bool is_weak_signature_digest(const EVP_MD* md);
// leaf_signing_md() plus a NULL for the one-shot schemes, for a signer that has no
// EdDSA/ML-DSA branch of its own (CMS_add1_signer). Never returns EVP_sha256() for a key
// that cannot use it.
// True for signature schemes that carry their own hash and expose NO separate
// digest -- Ed25519, Ed448 and the ML-DSA family.
//
// This is not only an internal signing detail. RFC 5929 tls-server-end-point channel
// binding hashes the server certificate with the digest named by ITS signature
// algorithm, so a certificate signed by one of these schemes has no digest to name:
// libpq looks it up, gets NID_undef and refuses the connection outright with
//   could not find digest for NID UNDEF
// before authentication is even attempted. A Postgres server certificate signed by
// such a CA is therefore unusable to every libpq client that negotiates channel
// binding, which is the default. Measured on a 3-node lab, where the node whose sub
// CA held an Ed448 key could not be replicated to and could not reach its own
// database on any NEW connection -- while looking healthy, because the connections
// opened before the certificate was installed stayed up.
//
// ⚠️ MATCHED BY NAME, not by base id, for the reason spelled out below.
bool signature_scheme_has_no_digest(EVP_PKEY* key);

const EVP_MD* response_signing_md(EVP_PKEY* key, X509* signer_cert,
                                  const std::string& requested, bool allow_weak = false);

// Produce a signed X.509 cert from `in`. Caller is responsible for persisting
// the resulting cert via Db::insert_cert. Throws pki::Error on policy fail.
//
// The CSR's subject is rewritten first when the caller supplies an identity
// (replace_subject, subject_cn, org_units, subject_domain). Everything else is
// issue_cert_from_parts(): enforce_issuance_policy() under `in.profile` (the built-in
// default when empty), the random serial, the per-CA AIA and CRL DP, and the owner in
// a Subject Directory Attributes extension.
X509Ptr issue_cert(const IssuanceInput& in);

// The parts of a leaf request for a caller that has no PKCS#10 to take them from.
// The console's HSM path is one: the private key is minted inside the token,
// so the browser cannot build and sign a CSR, and signing one server-side would be
// a proof of possession the server would be making to itself.
struct LeafRequest {
    std::string subject_dn;                  // OpenSSL one-line "/CN=.../O=..."
    std::vector<std::string> sans;           // raw user input, typed by general_name_of()
    std::vector<std::string> key_usage;      // "digitalSignature", "keyEncipherment", ...
    std::vector<std::string> ext_key_usage;  // "serverAuth", ... or dotted OIDs
    // Extensions that are neither KU nor EKU. The console's HSM form has no field
    // for these and should not grow one — the case that needs them is
    // id-pkix-ocsp-nocheck on an OCSP-signing certificate, which RFC 6960 §2.1.2 makes
    // mandatory rather than optional, so the server adds it instead of asking.
    std::vector<CustomExt> custom_exts;
    // What THIS request asks to leave out. Honoured only where the resolved
    // profile sets manage_aia / manage_crldp — the profile decides whether the choice
    // exists, the request makes it. Both false is the ordinary certificate.
    bool omit_aia{false};
    bool omit_crldp{false};
    // The digest THIS request asks the CA to sign with. Requesting a certificate —
    // even a leaf — should let the caller choose the hashing function, except for modern
    // keys that support only one.
    //
    // ⚠️ 19c5126 gave issue_cert_from_parts() a `requested_md` and the console's HSM form
    // a picker — but NOT this struct, which is the path that form posts to. The control
    // was rendered, the value was never carried, and the certificate came out signed with
    // the CA default. Honoured only where a choice exists (leaf_signing_md): RSA/RSA-PSS
    // only, never over an RFC 4055 restriction. Empty means "the CA's default".
    std::string requested_md;
};

// Type one SAN the way a user typed it, returning an OpenSSL GeneralName string
// ("DNS:a", "IP:1.2.3.4", "email:a@b", "URI:...", "otherName:<oid>;UTF8:<v>").
// The rules match the console's in-browser encoder so a SAN means the same thing
// whether the key was made in the browser or in the token: an explicit
// "upn:<v>" or "othername:<oid>;<v>" prefix wins, then "://" is a URI, an IPv4 or
// IPv6 literal is an IP, an embedded "@" is an email, and anything else is a DNS
// name. Exposed for the same reason it is centralised: two encoders would drift.
std::string general_name_of(const std::string& san);

// Issue a leaf certificate for `subject_key`'s public half from `r`. Only the source
// of the subject, public key and requested extensions differs from the CSR path —
// policy, profile, SDA owner and per-CA AIA/CRLDP all run through the same
// issue_cert_from_parts() as every other issuer. When `subject_key` references a
// PKCS#11 object the private half never enters this process.
// `profile_override`, when set, is the profile resolve_profile() returned — a merged one
// has no name to look up — and `profile` is then only its label.
X509Ptr issue_leaf_from_request(const Config& cfg, X509* ca_cert, EVP_PKEY* ca_key,
                                const LeafRequest& r, EVP_PKEY* subject_key,
                                const std::string& profile,
                                const std::string& owner_username = "",
                                const CaUrls* ca_urls = nullptr,
                                const std::string& key_algo = "",
                                const CertProfile* profile_override = nullptr);

// Run everything issuance would reject `r` for, WITHOUT a key: the SAN encoding, the
// extendedKeyUsage OIDs, the domain/IP allowlists and the profile's KU/EKU allow-list.
// Throws pki::Error(1, …) with the same message issuance would have produced.
//
// The HSM path needs this because its key is minted in a token. If a request is only
// checked on the way through issue_leaf_from_request(), a rejected request has already
// created a keypair the certificate will never name — an object nothing tracks, in
// hardware, with no way to notice it later. So the console validates first and mints
// second. Only the key-size check cannot run here, and that is a property of the key
// the operator picks from a fixed list, not something a form can get wrong.
void validate_leaf_request(const Config& cfg, const LeafRequest& r,
                           const std::string& profile,
                           const CertProfile* profile_override = nullptr);

// ---- Helpers ---------------------------------------------------------------

std::vector<unsigned char> x509_to_der(X509* x);
std::string x509_to_pem_string(X509* x);   // "" when x is null or encoding fails
// The same, for a certification request — the CSR half of a cross-node sub-CA is
// handed to the operator as PEM, because it has to travel to another machine.
std::string csr_to_pem_string(X509_REQ* r);   // "" when r is null or encoding fails
// An X509_NAME in OpenSSL one-line "/CN=…/O=…" form — the shape CaCertParams::subject_dn
// and every console form use, so a subject read off a CSR can be handed straight back in.
std::string x509_name_oneline(const X509_NAME* n);
std::string x509_fingerprint_sha256_hex(X509* x);

// ⚠️ SELF-ISSUED IS NOT SELF-SIGNED, and conflating the two has already cost us a bug.
//
//   self-ISSUED  subject == issuer. Says only that the certificate NAMES itself as its own
//                issuer. A CA that has been RE-KEYED is self-issued and is signed by its
//                PREVIOUS key — it still has a parent, and it is not a trust anchor.
//   self-SIGNED  the signature verifies under the certificate's OWN public key. This is
//                the property that makes something a root / trust anchor.
//
// Every self-signed certificate is self-issued; the converse is false, and the difference is
// invisible to a name comparison. On the lab, DC1's issuing CA is a re-key: its subject and
// issuer match, its self-signature FAILS, and it verifies against its own previous key — so
// `X509_NAME_cmp(subject, issuer) == 0` presented an online intermediate as a root CA.
//
// Use x509_is_self_signed() for anything that means "root", "trust anchor", or "has no
// parent". Use x509_is_self_issued() only where the NAME relation is genuinely the question
// (finding a parent by name, OCSP CertID matching, CMP sender matching).
//
// Both answer false for a null certificate. x509_is_self_signed() performs a real public-key
// signature verification, so prefer to call it once per certificate rather than per row.
// It deliberately does NOT use OpenSSL's X509_self_signed(): both of that function's modes are
// gated on EXFLAG_SS, a heuristic (AKID/SKID plus signature-algorithm match) that fails OPEN
// on a self-issued certificate with no AKID and CLOSED on a real root whose AKID does not
// match its own SKID. The measurements are recorded at the definition in x509.cpp.
bool x509_is_self_issued(X509* x);
bool x509_is_self_signed(X509* x);
// The SHA-1 thumbprint, for comparing against Windows / certutil / browser UIs,
// which still label that digest "Thumbprint". A fingerprint only — never a signature.
std::string x509_fingerprint_sha1_hex(X509* x);

// RFC 4387 §2.2 certificate-store selector hashes, each as lowercase-hex SHA-1
// (matching fastpki-store's sha1_hex). These are populated on the cert row at
// issuance so a FastPKI-issued cert is findable by hash, exactly like the PHP
// server's certs.sHash / iAndSHash / sKIDHash columns:
//   s_hash       SHA-1(DER-encoded subject Name)
//   i_and_s_hash SHA-1(DER-encoded IssuerAndSerialNumber)
//   skid_hash    SHA-1(subjectKeyIdentifier value); empty if the cert has no SKID
struct CertStoreHashes {
    std::string s_hash, i_hash, i_and_s_hash, skid_hash;
};
CertStoreHashes x509_store_hashes(X509* x);
// The full human-readable certificate dump (equivalent to `openssl x509 -text`),
// for the console's "show all attributes" detail view. Empty
// when x is null.
std::string x509_text(X509* x);
// The uniformResourceIdentifier GeneralNames in the cert's SubjectAltName — the
// values the RFC 4387 §2 `uri` selector matches. A cert may carry
// several; the store indexes each in cert_uris at issuance. Empty when there is
// no SAN or it holds no URI.
std::vector<std::string> x509_san_uris(X509* x);
std::string x509_cn(X509* x);   // first CN in subject; "" if absent

// What a certificate ACTUALLY carries, read back out of its own extensions — as opposed
// to what derive_ca_urls()/ca_urls_for_instance() say a certificate minted now WOULD
// carry. The two answer different questions and only the first survives a change to
// PKI_DNS or BASE_URL: those supply the host in every AIA and CRL distribution point,
// and an issued certificate can never be told a new one. So an operator who corrects the
// public name needs to see the gap between them to know which CAs to re-issue.
// Empty when the extension is absent, which is the normal state of a self-signed root.
std::vector<std::string> x509_aia_ca_issuers(X509* x);  // AIA accessMethod id-ad-caIssuers
std::vector<std::string> x509_aia_ocsp(X509* x);        // AIA accessMethod id-ad-ocsp
std::vector<std::string> x509_crl_urls(X509* x);        // CRLDP distributionPoint URIs

// ── renewal binding (shared by SCEP and EST) ───────────────────────────────────
//
// Every name in a SAN, TYPE-TAGGED so "DNS:host" and "IP:host" can never be mistaken for
// each other. The tagging is not decoration: without it a client could present an IP
// entry that string-matches a DNS name in the old certificate and obtain a certificate
// for a name it never held. An unrecognised GeneralName type is recorded by tag+DER
// rather than dropped, so a CSR cannot smuggle in an otherName the comparison never sees.
// Does this certificate certify this private key? Use INSTEAD of X509_check_private_key.
//
// ⚠️ X509_check_private_key compares EVP_PKEY TYPES, not just the RSA components, and since
// Since commit 8406d1f a PSS-restricted leaf publishes id-RSASSA-PSS in its SPKI
// while the same key loaded back through the pkcs11 provider reports as plain RSA — the
// provider picks its keymgmt from CKA_KEY_TYPE and there is no PSS key type there. Same
// modulus, same exponent, "different key pair".
//
// It is not hypothetical and it is not cosmetic: it took fastpki-ocsp down for every
// PSS-restricted responder, which answered `internalerror` to every request while the
// certificate sat valid in the database. CMP had already hit it and fixed it inline; three
// other call sites had the same bug and no test. One definition now.
bool cert_certifies_key(X509* cert, EVP_PKEY* key);

std::set<std::string> cert_sans(X509* x);
std::set<std::string> csr_sans(X509_REQ* req);
// The same walk over an already-extracted extension set. CMP's `ir`/`cr`/`kur` carry a
// CRMF certTemplate rather than a PKCS#10, so there is no X509_REQ to ask — and without
// this, a per-name limit would apply to `p10cr` senders and be inert for everyone else.
std::set<std::string> exts_sans(const STACK_OF(X509_EXTENSION)* exts);

// The CN of a name, "" when it has none. Lived as a file-local `cn_from_name` in
// policy.cpp; three more places need it, and two definitions of "which RDN is
// the name" is exactly how a limit ends up enforced against a different string than the
// one the certificate is issued for.
std::string name_cn(X509_NAME* n);

// A renewal must ask for the identity it already holds. Returns "" when `csr` is a
// legitimate renewal of `old_cert`, otherwise the reason it is not.
//
// Subject: exact match, via X509_NAME_cmp on the CANONICAL encoding — a client that
// re-encodes PrintableString as UTF8String still matches, so this is not a byte compare.
// SANs: the CSR's must be a SUBSET. Dropping a name you already hold is a legitimate
// renewal when a hostname is retired; ADDING one is the escalation.
//
// ⚠️ Lives here, not in one protocol, because SCEP renewal and EST device
// self-service are the SAME rule. Two copies would drift, and the copy that drifts
// is the one that stops refusing something.
std::string renewal_mismatch(X509* old_cert, X509_REQ* csr);
// Lowercase-hex serial, no leading zeros, matching how the PHP `certs.serial`
// column is populated.
std::string x509_serial_hex(X509* x);
// ⚠️ THE SAME RULE, FOR A SERIAL THAT ARRIVES AS TEXT — a peer certificate, a URL path
// segment, a CMP/SCEP message field. `certs.serial` is written by x509_serial_hex() and
// looked up by exact string match, so every reader has to spell the value the same way or
// its query silently finds nothing.
//
// It had been spelled four separate times and TWO of them were wrong. EST's
// self-renewal and the console's /api/certs/<serial> (detail AND revoke) lowercased but
// did not strip leading zeros, while httplib's PeerCert::serial() renders BN_bn2hex
// output verbatim — so a certificate whose top nibble is zero, one in sixteen, was
// "not issued here" to its own issuer. Measured on est_mtls_role.sh: two failures in
// nine runs, each on a serial beginning `0`.
//
// A lookup that misses looks exactly like a permission decision, which is why this went
// unnoticed: the device was refused, the log said so politely, and nothing was broken
// enough to investigate. One function now, so a fifth caller cannot invent a fifth form.
std::string canonical_serial(std::string s);
// The certificate's own validity in epoch seconds; 0 when absent/unconvertible.
// Storing an existing certificate used to invent `now` and `now + 3650d` because there
// was no way to ask — so an imported CA's recorded expiry had nothing to do with its own.
// Unix seconds for an ASN1_TIME (0 when absent or unparseable). The one conversion every
// date in this codebase goes through, rather than being reimplemented per call
// site.
int64_t asn1_time_to_unix(const ASN1_TIME* t);
int64_t x509_not_before_unix(X509* x);
int64_t x509_not_after_unix(X509* x);

// Build an RFC 5652 SignedData "certs-only" structure (PKCS#7) containing the
// given certs and no signers. Returned bytes are DER-encoded.
std::vector<unsigned char> pkcs7_certs_only(const std::vector<X509*>& certs);

// Build a degenerate SignedData (PKCS#7) carrying a single CRL and no signers —
// the messageData a SCEP GetCRL response wraps. Returned bytes are DER-encoded.
std::vector<unsigned char> pkcs7_crl_only(X509_CRL* crl);

// RFC 5280 §5.3.1 CRLReason values.
constexpr int kReasonUnspecified   = 0;
constexpr int kReasonCertificateHold = 6;
constexpr int kReasonRemoveFromCrl = 8;

// Why `reason` may not be given to a revocation, or "" when it may. One rule for every path
// that revokes (console, CMP, ACME, MCP):
//   refused  7 (unused), 8 removeFromCRL (only a delta CRL says it, for a released hold),
//            10 aACompromise (attribute certificates, which FastPKI does not issue), and
//            anything outside 0..10
//   accepted 0 1 2 3 4 5 6 9 — 6 certificateHold is the one that can be released
std::string revocation_reason_refusal(int reason);

// Generate a DER-encoded X.509 CRL listing the currently-revoked certs of one CA
// instance from `db`, signed by that CA (SHA-256). issuer = CA subject;
// nextUpdate is cfg.crl_next_update_days out. ca_instance_id "default" is the
// global/legacy CA. When `base_crl_number` > 0 the result is a **delta CRL**
// (RFC 5280 §5.2.4): it carries a critical Delta CRL Indicator = that base and
// lists only the certs revoked since that base point (our crlNumber == issuance
// unix time, so base N == "changes since time N"), plus the holds released since then, with
// reason removeFromCRL. A certificate on hold is on every CRL until it is released.
std::vector<unsigned char> generate_crl(const Config& cfg, class Db& db,
                                        X509* ca_cert, EVP_PKEY* ca_key,
                                        const std::string& ca_instance_id = "default",
                                        int64_t base_crl_number = 0);

// The public AIA/CRLDP URLs a CA advertises in the certs it issues. Derived
// (read-only) from the deployment base + ca_id so the web UI can pre-fill them
// and admins can't mistype them.
// ⚠️ LISTS, ONE ENTRY PER DATA CENTER. A certificate carries these for as long as it
// lives and cannot learn a new address later, so if it names only the node that issued
// it, a relying party has nowhere else to go when that node is unreachable — and the
// replicated CRLs every peer already serves become unreachable in exactly the outage
// they exist for. Built from `datacenters.base_url`, which each node declares for
// itself, so a joining data center appears in later certificates without anyone
// remembering to edit a config key.
struct CaUrls {
    std::vector<std::string> ca_issuers;   // AIA caIssuers — this CA's cert (DER, non-TLS)
    std::vector<std::string> ocsp;         // AIA OCSP responder — /ocsp
    std::vector<std::string> crl;          // CRL Distribution Point
};

// The GENERATION token in a publication URL — the signing certificate's
// subjectKeyIdentifier, lowercase hex, or "" when the certificate carries no SKID.
//
// ⚠️ WHY THE SKI AND NOT THE SERIAL. A leaf's authorityKeyIdentifier.keyid IS its signer's
// SKI, so a client that holds the leaf already holds the exact token naming the URL it must
// fetch — no lookup, no guessing. Our serial is 18 bytes of RAND_bytes (set_random_serial)
// with no relation to the signer, and a counter would be a second thing to keep in step.
std::string cert_ski_hex(const std::vector<unsigned char>& cert_der);

// Derive a CA's public AIA/CRLDP URLs. EVERY CA has a real id, so the URLs
// always name it — no id-less form:
//   caIssuers  <base>/{ca_id}.crt   (non-TLS DER cert)
//   CRL DP     <base>/{ca_id}.crl
//   OCSP       <base>/ocsp          (same path for every CA — the responder picks
//                                    its signing cert from the requested cert)
// Scheme/host come from cfg.base_url (or https://PKI_DNS).
CaUrls derive_ca_urls(const Config& cfg, const std::string& ca_id);

// The CRL an OFFLINE root signed elsewhere, if one has been imported for this CA.
//
// FastPKI generates every other CRL from a local key, so a CA whose key it does not hold
// has none — and /{ca_id}.crl, the certstore route and SCEP GetCRL all refuse with 503.
// This is what those three consult BEFORE refusing. Returns std::nullopt when nothing is
// stored, which is still a refusal: there is no CRL rather than a stale one.
//
// ⚠️ An EXPIRED stored CRL is still served, and `stale_note` says so. Hiding it would turn
// "your published CRL is out of date" into "this CA has no revocation information at all",
// and the second is both less true and less actionable — every client already treats a
// past nextUpdate as an error. The operator sees the warning in the log; the client sees
// the bytes and decides.
std::optional<std::vector<unsigned char>>
imported_crl(class Db& db, const std::string& ca_id, bool is_delta, std::string& stale_note);

// Store a CRL this node just signed in the `crls` table, so the mesh replicates it and a
// peer can serve this CA's revocation after the node holding its key is gone. A no-op when
// the stored copy already lists the same revocations and is still in the first half of its
// validity, so an unchanging CA does not churn the mesh once per cache TTL.
//
// Full CRLs only — see the note at the definition for why a delta must not be stored.
// Never throws: failing to publish must not fail the request that generated the CRL.
void publish_generated_crl(const Config& cfg, class Db& db, const std::string& ca_id,
                           const std::vector<unsigned char>& der);

// Thread-safe TTL cache around generate_crl(): regenerates a CA instance's CRL at
// most once per `ttl_sec` so it isn't rebuilt from the DB on every request.
// Caches per ca_instance_id, so one CrlCache serves the global CA and any number
// of tenant CAs.
class CrlCache {
public:
    explicit CrlCache(int ttl_sec) : ttl_(ttl_sec) {}
    std::vector<unsigned char> get(const Config& cfg, class Db& db,
                                   X509* ca_cert, EVP_PKEY* ca_key,
                                   const std::string& ca_instance_id = "default");
private:
    struct Entry { std::vector<unsigned char> cached; std::time_t generated_at{0}; };
    int ttl_;
    std::mutex mu_;
    std::map<std::string, Entry> entries_;
};

} // namespace pki
