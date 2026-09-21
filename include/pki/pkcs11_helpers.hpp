#pragma once
// PKCS#11 slot enumeration for the web console HSM form.
// Uses dlopen/dlsym to avoid a hard link against any PKCS#11 module.
// Only C_GetSlotList / C_GetTokenInfo are needed.

#include <filesystem>
#include <string>
#include <vector>

namespace pki {

struct Pkcs11Slot {
    unsigned long id{0};
    std::string   token_label;   // 32-char padded, trimmed
    // Key-pair-generation mechanisms this token ADVERTISES, as CKM_* values.
    // Not every mechanism — only the keygen ones, because the single question a caller
    // asks is "can this token make me a key of algorithm X".
    //
    // It has to be the token's own answer rather than a list we maintain: the console
    // offered seven algorithms while the reachable token could do three, and the four
    // that could not came back as CKR_TOKEN_NOT_PRESENT — a message about slots, for a
    // problem about algorithms. What is reachable also differs from what the module
    // supports, because p11-kit relays only part of the list.
    std::vector<unsigned long> keygen_mechanisms;
};

struct Pkcs11Info {
    std::string              module_path;   // resolved .so/.dylib path
    std::vector<Pkcs11Slot>  slots;         // slots that carry a token
    // Why the list is empty, when it is empty for a reason other than "no tokens".
    // An empty list with no explanation is how the console silently dropped its HSM
    // option and looked to an operator like the feature had been removed.
    std::string              error;
};

// The algorithm names (as the console's forms spell them) that a slot's advertised
// keygen mechanisms can produce. One mechanism can answer for several names: a token
// that mints CKK_RSA mints keys for both `rsa` and `rsa-pss`, and one ML-DSA keygen
// mechanism covers all three parameter sets.
//
// Empty means the token would not say — never "supports nothing".
std::vector<std::string> pkcs11_slot_algorithms(const Pkcs11Slot& slot);

// One attribute of a pkcs11: URI, percent-decoded; "" when absent. RFC 7512 puts the
// attributes before the '?', so `pin-source` and friends in the query part are not
// searched.
std::string pkcs11_uri_attr(const std::string& uri, const std::string& name);

// The `token=` attribute — the common case, spelled out.
std::string pkcs11_uri_token(const std::string& uri);

// A pkcs11: URI with its `pin-value=` blanked, for anywhere a key handle is shown or
// logged. RFC 7512 lets the PIN sit in the URI itself, and a handle is printed in a
// dozen places — the console's config page, and every error path that names the key it
// could not use. Redacting the one attribute keeps the handle identifying, which is the
// reason it is printed at all.
std::string pkcs11_uri_redacted(const std::string& uri);

// The token user PIN for a key URI: `?pin-value=` if the URI carries it, else the file
// named by `?pin-source=`, else `pin_file` (PKCS11_PIN_FILE). "" when none resolves.
std::string pkcs11_resolve_pin(const std::string& uri,
                               const std::filesystem::path& pin_file);

struct Pkcs11DestroyResult {
    int         destroyed{0};   // objects actually removed (public + private halves)
    std::string error;          // empty on success; a sentence fit to log
};

// Remove the token objects a pkcs11: URI names.
//
// The caller is the one that minted the key and then failed to use it — issuance throws
// after `generate_key_in_token()` succeeded, and without this the keypair stays in the
// HSM referenced by nothing, indistinguishable from a real key.
//
// A read-write, logged-in session is required, so `pin` must be the token's user PIN.
// Refuses rather than guesses when the URI names no object= or id=: deleting from the
// wrong token would be much worse than leaving one orphan.
Pkcs11DestroyResult pkcs11_destroy_key(const std::filesystem::path& module,
                                       const std::string& key_uri,
                                       const std::string& pin);

// Why `algo` cannot be generated in the token that `key_uri` names — a sentence fit to
// show an operator — or "" to go ahead.
//
// Silence is consent, deliberately. An unreadable module, a URI naming no token, a
// token this process did not enumerate, or a token that advertises no keygen mechanism
// all return "": this refuses only on a POSITIVE statement from the token that it does
// not do this algorithm. A pre-flight that guessed would be worse than the error it
// replaces, because it would block work that in fact succeeds.
std::string pkcs11_keygen_refusal(const Pkcs11Info& info, const std::string& key_uri,
                                  const std::string& algo);

// Enumerate PKCS#11 slots that hold an initialized token. On failure `slots` is
// empty and `error` says why — callers must surface that rather than treat it as
// "this deployment has no HSM".
//
// C_Initialize is called with CKF_OS_LOCKING_OK. Without it a module is entitled to
// refuse with CKR_CANT_LOCK in a multi-threaded process, and fastpki-web is one — which
// is exactly why this returned nothing on a box where `pkcs11-tool --list-slots` worked
// with the same module. C_Finalize is never called: OpenSSL's pkcs11 provider may hold
// the module open, and tearing it down breaks key loading and signing until restart.
Pkcs11Info pkcs11_enumerate_slots(const std::filesystem::path& module);

// ── what is actually IN the token ──────────────────────────────────────────
// As of now, HSM keys are hidden from everyone.
//
// The console could mint into a token and never show what was there. A key created by
// mistake, an orphan from a failure the mint guard did not cover, or a key left behind by
// a service that has since been reconfigured were all invisible until somebody ran
// `pkcs11-tool` on the host — which is exactly the access a PKI console exists to avoid
// needing. pkcs11_enumerate_slots() answers "which tokens are there"; this answers "what
// do they hold".
//
// Private keys are only visible to a LOGGED-IN session, so a PIN is required. Nothing
// secret is returned: a label, an id, a class and a key type are the same facts the URI
// an operator types already contains.
struct Pkcs11Object {
    std::string label;       // CKA_LABEL — the `object=` half of a pkcs11: URI
    std::string id;          // CKA_ID, hex; often empty on keys this console minted
    std::string klass;       // "private" | "public" | "certificate" | "secret" | "other"
    std::string key_type;    // "RSA" | "EC" | "Ed25519" | "ML-DSA" | "" for a certificate
    unsigned long bits{0};   // RSA: CKA_MODULUS_BITS, else |CKA_MODULUS|*8. EC: curve degree
    // The NIST name of an EC key's curve ("P-256"), from CKA_EC_PARAMS. Empty for
    // every other key type, and for a curve OpenSSL knows no NIST name for (then `bits`
    // still carries the degree).
    std::string curve;
    // CKA_EXTRACTABLE on a private key: whether `key replicate` can ever copy it to another
    // token. Fixed when the key was generated. False for anything that is not a private key.
    bool extractable{false};
};
struct Pkcs11Objects {
    std::string                token;     // the token label listed
    std::vector<Pkcs11Object>  objects;
    std::string                error;     // empty on success; a sentence fit to show
};

// List the objects in the token `token_label` names (empty = the first initialized one).
// `pin` must be the token's user PIN, or private keys simply will not appear — which is
// worse than an error, so an empty PIN is refused rather than silently listing half.
Pkcs11Objects pkcs11_list_objects(const std::filesystem::path& module,
                                  const std::string& token_label,
                                  const std::string& pin);

// ── replicating a CA private key from one node's token into another's ──────────────
//
// Every node has its own token, and a CA whose key exists in only one of them dies with
// that node: the survivors cannot issue under it, and — worse — cannot renew or revoke
// anything it already signed. Replication is what makes losing a node survivable, and
// `docs/architecture.md` §5-§6 is the design record for it.
//
// ⚠️ THE KEY NEVER EXISTS IN PLAINTEXT OUTSIDE A TOKEN, which is what makes this a
// replication mechanism rather than an export. It travels under envelope encryption:
//
//   1. the destination has a long-lived key-encryption keypair (KEK) in its OWN token,
//      and publishes only the public half;
//   2. the source generates an EPHEMERAL EC keypair in its own token, ECDH-derives an
//      AES-256 key from it and the destination's KEK public point, and C_WrapKey's the
//      CA private key under that AES key;
//   3. the destination ECDH-derives the same AES key from its KEK private half and the
//      ephemeral public point, and C_UnwrapKey's the CA key straight into its token.
//
// Every private value is a token object at both ends. What crosses the wire is a wrapped
// blob and two public EC points.
//
// ⚠️ ECDH RATHER THAN RSA-OAEP, and that is a measured choice, not a preference. The
// shipped patched SoftHSM accepts RSA-OAEP with SHA-256; a stock 2.7.0 refuses it and
// takes SHA-1 only. CKM_ECDH1_DERIVE behaves identically on both. tests/wrapprobe.c
// proves the whole round trip — generate, wrap, unwrap, sign with the unwrapped handle,
// verify against the ORIGINAL public key — and its header says how to re-run it after a
// SoftHSM or p11-kit bump.
//
// ⚠️ EACH CALL BELOW OPENS AND CLOSES THE MODULE ITSELF, unlike pkcs11_enumerate_slots()
// which deliberately never calls C_Finalize. That is not tidiness: `p11-kit-client.so`
// reads P11_KIT_SERVER_ADDRESS at C_Initialize, and a replication run has to reach the
// SOURCE node's token over the tunnel and then this node's own. Without the finalize the
// second call would silently keep talking to the first node's token — and would appear to
// succeed, having replicated a key onto the machine that already had it.

// The public half of this node's key-encryption keypair, created on first use.
struct Pkcs11Kek {
    std::vector<unsigned char> ec_point;   // CKA_EC_POINT exactly as the token returns it
    std::string                error;      // empty on success; a sentence fit to show
};

// Find-or-create the KEK in this node's own token and return its public point. The
// private half is a token object, CKA_SENSITIVE and NOT extractable: it decrypts
// incoming keys and must never itself be replicable.
Pkcs11Kek pkcs11_kek_public(const std::filesystem::path& module,
                            const std::string& token_label,
                            const std::string& pin,
                            const std::string& kek_label);

// What the source produces. `key_type` travels with the blob because C_UnwrapKey needs a
// template naming the key type it is creating, and only the source can see it.
struct Pkcs11Wrapped {
    std::vector<unsigned char> blob;           // the CA private key under the AES key
    std::vector<unsigned char> ephemeral_pub;  // CKA_EC_POINT of the source's ephemeral key
    std::string                key_type;       // "EC" | "RSA" | "RSA-PSS" | "EdDSA" | "ML-DSA"
    // CKA_ALLOWED_MECHANISMS at the source, raw. The wrapped blob does not carry it, and an
    // RSA-PSS key without it is a different key policy under the same certificate.
    std::vector<unsigned char> allowed_mechanisms;
    std::string                error;
    // Set when `error` describes something no retry can change — today only a key the
    // token will not let out at all. A caller that retries on a schedule needs this:
    // without it a nightly convergence job hammers a peer forever over a CA that can
    // never be replicated, and buries the one message saying so.
    bool                       permanent = false;
};

// SOURCE side: wrap the private key `key_uri` names for the holder of `kek_ec_point`.
//
// ⚠️ FAILS IF THE KEY WAS GENERATED NON-EXTRACTABLE, and that cannot be fixed afterwards:
// CKA_EXTRACTABLE is set at generation and PKCS#11 forbids granting it later. Whether a
// CA can ever be replicated is therefore decided when the CA is created — see
// pkcs11_generate_replicable_keypair(). The error says so rather than reporting a
// mechanism failure, because the operator's next step is to create the CA differently.
Pkcs11Wrapped pkcs11_wrap_for_peer(const std::filesystem::path& module,
                                   const std::string& key_uri,
                                   const std::string& pin,
                                   const std::vector<unsigned char>& kek_ec_point);

// DESTINATION side: unwrap into this node's own token under `dest_label` / `dest_id`.
// Returns "" on success, else a sentence fit to show.
//
// ⚠️ `spki_der` IS THE CA CERTIFICATE'S SubjectPublicKeyInfo, AND IT IS NOT OPTIONAL
// DECORATION. C_UnwrapKey creates the PRIVATE object only, and the OpenSSL pkcs11 provider
// reaches a private key's public half through the matching CKA_ID — with no public object
// in the token it fails at `p11prov_obj_find_associated`, so the EVP_PKEY that loads back
// carries no public key. Everything that merely SIGNS still works, which is what makes this
// so easy to miss; what breaks is every comparison against the certificate, including the
// `expect` check load_signing_key() makes whenever a CA names more than one key URL. So the
// public half is reconstructed from the certificate and written beside the private one.
std::string pkcs11_unwrap_into(const std::filesystem::path& module,
                               const std::string& token_label,
                               const std::string& pin,
                               const std::string& kek_label,
                               const Pkcs11Wrapped& w,
                               const std::string& dest_label,
                               const std::string& dest_id,
                               const std::vector<unsigned char>& spki_der);

// Generate a CA keypair that CAN be replicated, straight through PKCS#11 rather than
// through OpenSSL's pkcs11 provider.
//
// ⚠️ THE PROVIDER IS BYPASSED FOR ONE ATTRIBUTE ONLY. generate_key_in_token()
// (src/lib/x509.cpp) drives the provider, which decides CKA_EXTRACTABLE itself and gives
// no OSSL_PARAM to say otherwise — so a CA minted that way can never leave its token,
// whatever the operator later wants. This exists to make that a CHOICE at creation, which
// is the only moment it can be one. Everything else about the key is identical, and the
// key it makes is used through the provider exactly like any other.
//
// `algo` is "ec" (P-256 unless `curve` says otherwise) or "rsa" (`bits`, default 4096).
// Returns "" on success, else a sentence fit to show.
// A mutually authenticated tunnel to a peer's published token, for the length of ONE
// operation.
//
// ⚠️ IT IS TRANSIENT ON PURPOSE. A standing tunnel that presented a peer's token on this
// node's own socket is the arrangement FastPKI does not have: every node signs from its
// own token, and one shared token means losing that host stops all signing and strands
// every certificate it issued. This exists only so a replication run can reach the source
// token for as long as the wrap takes, and it is torn down again.
//
// The material is what certgen minted under P11_TLS=on: this node's `client.crt` with its
// private half a `p11-client` object in this node's token, verified against the peer
// certificates the mesh replicated into `<tls_dir>/servers`.
class P11Tunnel {
public:
    P11Tunnel() = default;
    P11Tunnel(const P11Tunnel&) = delete;
    P11Tunnel& operator=(const P11Tunnel&) = delete;
    ~P11Tunnel();

    // Raise it. Returns "" on success, else a sentence fit to show. `host_port` is the
    // peer's published `fastpki-p11-tls` address.
    std::string start(const std::string& host_port,
                      const std::filesystem::path& tls_dir,
                      const std::filesystem::path& module,
                      const std::filesystem::path& pin_file,
                      const std::string& token);

    // Tear it down. Idempotent, and the destructor calls it.
    void stop();

    // `unix:path=...` for P11_KIT_SERVER_ADDRESS. Empty until start() succeeds.
    const std::string& address() const { return address_; }

private:
    std::string address_;
    std::string dir_;
    int         pid_{-1};
};

// Why a key of `algo` (and, for EC, `curve`) cannot be minted replicable — or "" when it
// can. Every CA key algorithm is accepted — RSA, RSA-PSS, EC P-256/P-384/P-521, Ed25519,
// Ed448, ML-DSA-44/65/87 — and anything else is refused. An empty `algo` means RSA, as it
// does for generate_key_in_token(). Needs no token, so a form can ask it BEFORE anything is
// minted or overwritten.
std::string pkcs11_replicable_refusal(const std::string& algo, const std::string& curve);

// Mint a keypair with CKA_EXTRACTABLE set, through PKCS#11 directly. Callers normally reach
// this through generate_key_in_token(..., replicable=true), which loads the key back.
std::string pkcs11_generate_replicable_keypair(const std::filesystem::path& module,
                                               const std::string& key_uri,
                                               const std::string& pin,
                                               const std::string& algo,
                                               const std::string& curve,
                                               unsigned long bits);

} // namespace pki
