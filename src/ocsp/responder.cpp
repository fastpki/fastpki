#include "responder.hpp"
#include "pki/ca_instance.hpp"     // resolve_ca_instance: the CA's LIVE certificates
#include "pki/endpoint_gate.hpp"   // exit_if_token_died
#include "pki/error.hpp"
#include "pki/log.hpp"
#include "pki/x509.hpp"            // p11_rsa_requires_pss
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <chrono>
#include <atomic>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <cctype>

namespace pki::ocsp {
namespace {

struct OcspRequestDeleter      { void operator()(OCSP_REQUEST* p)       const noexcept { OCSP_REQUEST_free(p); } };
struct OcspResponseDeleter     { void operator()(OCSP_RESPONSE* p)      const noexcept { OCSP_RESPONSE_free(p); } };
struct OcspBasicDeleter        { void operator()(OCSP_BASICRESP* p)     const noexcept { OCSP_BASICRESP_free(p); } };
struct OcspCertIdDeleter       { void operator()(OCSP_CERTID* p)        const noexcept { OCSP_CERTID_free(p); } };
struct Asn1TimeDeleter         { void operator()(ASN1_TIME* p)          const noexcept { ASN1_TIME_free(p); } };

using OcspReqPtr   = std::unique_ptr<OCSP_REQUEST,   OcspRequestDeleter>;
using OcspRespPtr  = std::unique_ptr<OCSP_RESPONSE,  OcspResponseDeleter>;
using OcspBasicPtr = std::unique_ptr<OCSP_BASICRESP, OcspBasicDeleter>;
using OcspCertIdPtr= std::unique_ptr<OCSP_CERTID,    OcspCertIdDeleter>;
using Asn1TimePtr  = std::unique_ptr<ASN1_TIME,      Asn1TimeDeleter>;

// Serialize an OCSP_RESPONSE into a DER byte vector.
std::vector<unsigned char> to_der(OCSP_RESPONSE* resp) {
    int len = i2d_OCSP_RESPONSE(resp, nullptr);
    if (len <= 0) throw Error(2, "i2d_OCSP_RESPONSE size failed: " + openssl_errors());
    std::vector<unsigned char> out(static_cast<size_t>(len));
    unsigned char* p = out.data();
    if (i2d_OCSP_RESPONSE(resp, &p) != len)
        throw Error(2, "i2d_OCSP_RESPONSE encode failed: " + openssl_errors());
    return out;
}

// Sign a basic OCSP response, working around the same pkcs11 quirk `crl.cpp` does.
//
// `OCSP_basic_sign` builds its own EVP_MD_CTX and configures nothing on it, so for an
// RSA-PSS key the pkcs11 provider asks the token for CKM_SHA256_RSA_PKCS -- which a
// PSS-only key correctly refuses. That is the "provider signature failure", and it
// is the identical defect already fixed for CRLs and for the audit chain. The cure
// is the same: pre-configure the context and hand it to `OCSP_basic_sign_ctx`, which does
// everything `OCSP_basic_sign` does (responder id, cert chain, producedAt) except build
// the context itself.
//
// Whether the key needs PSS is determined from the cert's SPKI -- not from probing the
// HSM. The cert's SPKI was set by our own CA when this credential was issued; it is the
// authoritative source for the key's algorithm.
int basic_sign_compat(OCSP_BASICRESP* basic, X509* signer, EVP_PKEY* key,
                      const EVP_MD* md, STACK_OF(X509)* certs) {
    // --- EdDSA and ML-DSA must be handed a NULL digest ----------------------
    //
    // Both are one-shot schemes that hash internally, and OpenSSL rejects an explicit
    // digest with "invalid digest". This function was always called with EVP_sha256(),
    // so an Ed25519 or ML-DSA responder credential could not sign a single response —
    // `ocsp_perca.sh` went 29/0 to 22/7 with `status good (got '')` for both, because the
    // responder produced nothing and the client had no answer to parse.
    //
    // ⚠️ THIS IS THE SAME RULE sign_x509() HAS LONG CARRIED, one file away, and the
    // OCSP path simply never got it. The open question is whether the full key range
    // works on the services that use an RA credential instead of TLS; for OCSP the answer
    // was no, and this is why.
    //
    // Decided from the KEY, not the certificate: the SPKI is the right source for "does
    // this need PSS" (below) because our own CA wrote it, but the digest rule is a property
    // of the signing algorithm itself, and the key is what will be asked to sign.
    {
        // ⚠️ MATCHED BY NAME, NEVER BY BASE ID. EVP_PKEY_get_base_id() is not dependable
        // for provider-backed keys, and I got this wrong TWICE by trusting it:
        //
        //   1. ML-DSA. `EVP_PKEY_ML_DSA_65` exists as a macro (NID 1458), so
        //      `base == EVP_PKEY_ML_DSA_65` compiles and reads correctly — but a real key
        //      reports base_id 0. Measured on OpenSSL 3.6:
        //          base_id=0  type_name=ML-DSA-65  is_a("ML-DSA-65")=1
        //   2. EdDSA. `base == EVP_PKEY_ED25519` DID work on the dev box, so I left it —
        //      and it does not work in the shipped image (OpenSSL 3.5.7, musl, with our
        //      providers loaded), where Ed25519 kept failing "invalid digest" while the
        //      same binary passed locally.
        //
        // Each time the wrong half looked fixed because the other half was green. The name
        // is what EVP_PKEY_is_a() resolves through the provider's namemap, and it is the
        // only answer that holds across both toolchains.
        const bool one_shot =
            EVP_PKEY_is_a(key, "ED25519")   || EVP_PKEY_is_a(key, "ED448")   ||
            EVP_PKEY_is_a(key, "ML-DSA-44") || EVP_PKEY_is_a(key, "ML-DSA-65") ||
            EVP_PKEY_is_a(key, "ML-DSA-87");
        if (one_shot)
            return OCSP_basic_sign(basic, signer, key, nullptr, certs, 0);
    }

    EVP_PKEY* signer_pub = X509_get0_pubkey(signer);
    bool is_pss = signer_pub && EVP_PKEY_base_id(signer_pub) == EVP_PKEY_RSA_PSS;
    if (!is_pss)
        return OCSP_basic_sign(basic, signer, key, md, certs, 0);

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (!mctx) return 0;
    EVP_PKEY_CTX* pctx = nullptr;
    if (EVP_DigestSignInit(mctx, &pctx, md, nullptr, key) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
        EVP_MD_CTX_free(mctx);
        return 0;
    }
    int ok = OCSP_basic_sign_ctx(basic, signer, mctx, certs, 0);
    EVP_MD_CTX_free(mctx);
    return ok;
}

// 1. Define a clean deleter struct
struct OpenSSLDeleter {
    void operator()(void* ptr) const {
        OPENSSL_free(ptr);
    }
};

// Extract the serial number from an OCSP_CERTID as lowercase hex (no leading
// zeros), matching how the PHP server stores it in the `certs` table.
std::string certid_serial_hex(OCSP_CERTID* id) {
    ASN1_OCTET_STRING* name_hash = nullptr;
    ASN1_OCTET_STRING* key_hash  = nullptr;
    ASN1_OBJECT*       md        = nullptr;
    ASN1_INTEGER*      serial    = nullptr;
    if (!OCSP_id_get0_info(&name_hash, &md, &key_hash, &serial, id) || !serial)
        throw Error(1, "OCSP_id_get0_info failed");

    std::unique_ptr<BIGNUM, decltype(&BN_free)> bn(ASN1_INTEGER_to_BN(serial, nullptr), &BN_free);
    if (!bn) throw Error(1, "ASN1_INTEGER_to_BN failed");
    //std::unique_ptr<char, decltype(&OPENSSL_free)> hex(BN_bn2hex(bn.get()), [](char* p){ OPENSSL_free(p); });
    std::unique_ptr<char, OpenSSLDeleter> hex(BN_bn2hex(bn.get()));
    
    if (!hex) throw Error(1, "BN_bn2hex failed");
    std::string s(hex.get());
    // BN_bn2hex emits uppercase but no leading sign for positives; PHP code
    // stores serials lowercase-hex with no leading zeros. Normalize both.
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    size_t first = s.find_first_not_of('0');
    s = (first == std::string::npos) ? "0" : s.substr(first);
    return s;
}

Asn1TimePtr asn1_time_from_unix(int64_t t) {
    Asn1TimePtr out{ASN1_TIME_set(nullptr, static_cast<time_t>(t))};
    if (!out) throw Error(2, "ASN1_TIME_set failed");
    return out;
}

} // namespace

namespace {

X509Ptr der_to_x509(const std::vector<unsigned char>& der) {
    const unsigned char* p = der.data();
    X509Ptr cert{d2i_X509(nullptr, &p, static_cast<long>(der.size()))};
    if (!cert) throw pki::Error(2, "CA cert DER parse failed: " + pki::openssl_errors());
    return cert;
}

// Load a CA signing key WITHOUT making its absence an internal error.
//
// load_signing_key() returns null for an empty reference (an offline root, which the CRL
// route already answers 503 for) and THROWS for a pkcs11 URI it cannot resolve. On a mesh
// that second case is routine and is not a fault: every DC holds a row for every CA, and
// only the node whose token holds the key can sign. The throw escaped the constructor,
// pick_responder caught it, and the client got 500 "CA material unavailable" — which sends
// whoever is debugging at the server rather than at their URL, when in fact the answer is
// simply "not here".
//
// Reported, never swallowed: the reason is logged once at construction and repeated in the
// 503 body, so a genuinely broken token still says so loudly.
EvpPkeyPtr load_ca_key_or_explain(const std::string& ref, const Config& cfg,
                                  const std::string& ca_id, std::string& why) {
    if (ref.empty()) {
        why = "CA '" + ca_id + "' has no signing key configured (an offline root is the "
              "recommended posture) — this node cannot produce its CRL, but it still "
              "publishes what was already decided.";
        return nullptr;
    }
    try {
        auto k = load_signing_key(ref, cfg);
        if (k) return k;
        why = "CA '" + ca_id + "': " + ref + " resolved to no key.";
    } catch (const std::exception& e) {
        why = "CA '" + ca_id + "': its signing key " + ref + " is not available on this "
              "node (" + e.what() + "). On a multi-node mesh only the node whose token "
              "holds the key can sign this CA's CRL.";
    }
    log::info("OCSP: " + why);
    return nullptr;
}

} // namespace

Responder::Responder(const Config& cfg, Db& db, std::string ca_id,
                     // By value on purpose: the call site hands over a temporary vector, so
                     // it materialises directly in this parameter and a const& would remove
                     // no copy. The signature is also declared in responder.hpp and the two
                     // must agree.
                     // cppcheck-suppress passedByValue
                     std::vector<unsigned char> ca_cert_der, const std::string& ca_key_ref,
                     const std::vector<std::vector<unsigned char>>& chain_ders)
    : cfg_(cfg), db_(db), ca_id_(std::move(ca_id)),
      ca_cert_(der_to_x509(ca_cert_der)),
      ca_key_(nullptr) {
    // ⚠️ NOT IN THE INITIALISER LIST. Members are initialised in DECLARATION order, and
    // `ca_key_why_` is declared after `ca_key_` — so an initialiser
    // `ca_key_(load_ca_key_or_explain(..., ca_key_why_))` writes into a std::string that
    // has not been constructed yet (undefined behaviour), and its default constructor
    // then runs and wipes the message to empty. The 503 fell back to the generic
    // sentence and named no CA, which is the one thing this change exists to fix.
    //
    // Caught only because the suite asserts the BODY, not just the status code: 503 was
    // already correct while the message was silently gone.
    ca_key_ = load_ca_key_or_explain(ca_key_ref, cfg, ca_id_, ca_key_why_);
    // Parse once, here — handle() runs per request and must not re-parse DER.
    for (const auto& der : chain_ders)
        if (auto c = parse_cert_der(der)) ca_chain_.push_back(std::move(c));
    // ONE responder key for the process, loaded once. The CERTIFICATE is per CA and
    // is resolved per request from the DB — see resolve_responder_cert().
    //
    // OCSP_RESPONDER_CERT (a PEM path, one file for the whole instance) is gone. It could
    // not be right on a multi-CA instance: RFC 6960 §4.2.2.2 requires the responder
    // certificate to be issued by the CA whose status it asserts, and one file is issued
    // by at most one of them.
    //
    // ⚠️ Second half: this must NOT throw. It used to, and pick_responder turned
    // the throw into 500 "CA material unavailable" for EVERY route this responder serves
    // — including /{ca_id}.crl, which is signed by the CA key above and never touches the
    // responder key. Measured on lab DC3: /issuing.crl 500 and /issuing-dc3.crl 200 from
    // one process, differing only in whether the responder key happened to load.
    //
    // The absence is recorded instead. resolve_responder_cert() already has a `why`
    // channel for exactly this and reports it per request, so OCSP still refuses — with a
    // sentence naming the cause — while the CRL route is unaffected by a credential it
    // does not use.
    if (!cfg.ocsp_responder_key.empty()) {
        try {
            responder_key_ = load_key_file_or_token(cfg.ocsp_responder_key.string(), cfg);
            if (!responder_key_)
                responder_key_why_ = "OCSP_RESPONDER_KEY (" + cfg.ocsp_responder_key.string() +
                                     ") resolved to no key on this node.";
        } catch (const std::exception& e) {
            responder_key_why_ = "OCSP_RESPONDER_KEY (" + cfg.ocsp_responder_key.string() +
                                 ") could not be loaded on this node: " + e.what();
        }
        if (!responder_key_)
            log::err("OCSP: CA '" + ca_id_ + "': " + responder_key_why_ +
                     " This CA cannot answer OCSP here; its CRL is unaffected.");
    }
}

X509Ptr Responder::resolve_responder_cert(std::string& why) const {
    if (!responder_key_) {
        // Distinguish "never configured" from "configured but not loadable here".
        // A mesh node that simply does not hold this credential is a fact about where
        // the material is, and saying so beats telling an operator to provision a key
        // they already provisioned somewhere else.
        why = responder_key_why_.empty()
            ? "OCSP_RESPONDER_KEY is not set, so this responder has no signing credential. "
              "Responses are never signed with the CA key: provision an OCSP "
              "responder key in the HSM and issue a certificate for it from CA '" +
              ca_id_ + "'."
            : responder_key_why_;
        return nullptr;
    }
    const std::string cert_id = cfg_.ocsp_responder_cert_id_prefix + "-" + ca_id_;
    auto der = db_.get_cert_by_cert_id(cert_id);   // status=0 only: covers revocation
    if (!der || der->empty()) {
        why = "no valid certificate for cert_id '" + cert_id + "' (missing, or revoked) — "
              "CA '" + ca_id_ + "' cannot answer OCSP until one is issued BY that CA "
              "(Inventory -> Request, key in HSM -> Serve as OCSP responder).";
        return nullptr;
    }
    const unsigned char* p = der->data();
    X509Ptr cert{d2i_X509(nullptr, &p, static_cast<long>(der->size()))};
    if (!cert) { why = "the certificate for cert_id '" + cert_id + "' does not parse"; return nullptr; }

    // Validity, every request — so an expiry that happens under a running process takes
    // effect without a restart. This was checked nowhere for the CMP RA.
    if (X509_cmp_current_time(X509_get0_notAfter(cert.get())) < 0) {
        why = "the OCSP responder certificate '" + cert_id + "' has EXPIRED — issue a new "
              "one from CA '" + ca_id_ + "'";
        return nullptr;
    }
    if (X509_cmp_current_time(X509_get0_notBefore(cert.get())) > 0) {
        why = "the OCSP responder certificate '" + cert_id + "' is not valid YET "
              "(notBefore is in the future) — check the clock on this host";
        return nullptr;
    }
    // The certificate must certify the key this process holds. Get that wrong and
    // OCSP_basic_sign fails with unattributed OpenSSL noise (learned the hard
    // way); reissuing is exactly when a fresh key pair gets minted by mistake.
    // ⚠️ pki::cert_certifies_key, NOT X509_check_private_key. This site used the latter and
    // The SPKI fix (8406d1f) broke it outright: the responder certificate publishes
    // id-RSASSA-PSS while the token hands the key back as plain RSA, so the types differ and
    // every OCSP request got `internalerror` from a responder holding a perfectly valid
    // certificate. Caught by pss_loaded_key_signing.sh.
    if (!pki::cert_certifies_key(cert.get(), responder_key_.get())) {
        why = "the certificate '" + cert_id + "' does not match the OCSP responder key "
              "this process holds — it was issued for a DIFFERENT key pair. Reissue it "
              "for the key at OCSP_RESPONDER_KEY.";
        return nullptr;
    }
    // RFC 6960 §2.1.2: a non-CA delegated responder MUST carry id-pkix-ocsp-nocheck, or
    // clients recurse on the responder's own revocation status.
    if (X509_check_ca(cert.get()) == 0 &&
        X509_get_ext_by_NID(cert.get(), NID_id_pkix_OCSP_noCheck, -1) < 0) {
        why = "the OCSP responder certificate '" + cert_id + "' is non-CA but lacks "
              "id-pkix-ocsp-nocheck (RFC 6960 §2.1.2)";
        return nullptr;
    }
    // Contradictory to tell a client not to check this certificate's status and then point
    // it at revocation info for exactly that. Warn, do not refuse — the response is still
    // valid and an operator can fix the profile. These lived in the constructor; they moved
    // here with the certificate they describe.
    if (X509_get_ext_by_NID(cert.get(), NID_info_access, -1) >= 0)
        log::err("OCSP responder certificate '" + cert_id + "' has id-pkix-ocsp-nocheck "
                 "but also carries Authority Information Access (OCSP) — contradictory");
    if (X509_get_ext_by_NID(cert.get(), NID_crl_distribution_points, -1) >= 0)
        log::err("OCSP responder certificate '" + cert_id + "' has id-pkix-ocsp-nocheck "
                 "but also carries CRL Distribution Points — contradictory");
    return cert;
}

// Does this CertID name a CA WE answer for?
//
// A CertID identifies the certificate by its ISSUER (a hash of the issuer's name and a hash
// of the issuer's public key) plus the serial. The serial lookup below proves only that
// some CA in this database issued that number -- not that the CA the client asked about is
// this one. On a multi-CA instance, which is the shipped model, that means the responder
// would happily answer for a certificate a DIFFERENT CA issued, and the answer would carry
// no binding to the authority the client actually named.
//
// Matched against EVERY live certificate of this CA, not just the newest. During a rekey the
// CA holds more than one, and a certificate issued before the rekey carries the OLD key's
// hash in its CertID -- so matching the newest alone would answer `unauthorized` for every
// certificate issued under the previous generation, which is precisely the failure
// tests/ocsp_rekeyed_chain.sh was written about.
static bool certid_names_this_ca(OCSP_CERTID* id, X509* primary,
                                 const std::vector<X509Ptr>& chain) {
    ASN1_OBJECT*       alg = nullptr;
    ASN1_OCTET_STRING* nh  = nullptr;
    ASN1_OCTET_STRING* kh  = nullptr;
    ASN1_INTEGER*      sn  = nullptr;
    if (!OCSP_id_get0_info(&nh, &alg, &kh, &sn, id)) return false;
    // The client chooses the hash. A digest this build cannot compute is not evidence of a
    // match, so it is not treated as one -- the request is refused rather than answered on
    // an unchecked identity.
    const EVP_MD* md = EVP_get_digestbyobj(alg);
    if (!md) return false;
    const auto same_issuer = [&](X509* ca) {
        if (!ca) return false;
        OcspCertIdPtr ref{OCSP_cert_id_new(md, X509_get_subject_name(ca),
                                           X509_get0_pubkey_bitstr(ca), sn)};
        // OCSP_id_issuer_cmp compares the issuer name hash and key hash ONLY, which is
        // exactly the question here -- the serial is answered separately, from the database.
        return ref && OCSP_id_issuer_cmp(ref.get(), id) == 0;
    };
    if (same_issuer(primary)) return true;
    for (const auto& c : chain) if (same_issuer(c.get())) return true;
    return false;
}

std::vector<unsigned char> Responder::status_response(int ocsp_status) {
    OcspRespPtr r{OCSP_response_create(ocsp_status, nullptr)};
    if (!r) throw Error(2, "OCSP_response_create failed: " + openssl_errors());
    return to_der(r.get());
}

std::vector<unsigned char> Responder::handle(const unsigned char* req_der, size_t len) {
    try {
        const unsigned char* p = req_der;
        OcspReqPtr req{d2i_OCSP_REQUEST(nullptr, &p, static_cast<long>(len))};
        if (!req) {
            log::err("malformed OCSP request: " + openssl_errors());
            return status_response(OCSP_RESPONSE_STATUS_MALFORMEDREQUEST);
        }

        // ⚠️ A SIGNATURE WE DO NOT CHECK IS WORSE THAN NO SIGNATURE. Request signing is
        // optional in RFC 6960 §3.1 and almost no client uses it -- but this used to log
        // "signer validation TODO" and answer anyway, so a deployment that turned on
        // request signing expecting it to authenticate the requester got no such property
        // and nothing said so.
        //
        // The trust anchor needs no new configuration: it is this CA's own certificates,
        // which the responder already holds in order to sign responses, used as the anchor
        // directly (see PARTIAL_CHAIN below). The rule that gives is exact -- the signer must
        // chain to THIS CA -- and it matches the realistic signer, a client holding a
        // certificate this CA issued. A deployment whose OCSP clients sign under some OTHER
        // anchor is refused, and refusal is the honest answer until there is a configured
        // store to point at.
        //
        // OCSP_request_verify does both halves: the signature over the tbsRequest, and the
        // chain from the embedded signer to the store. `unauthorized` (RFC 6960 §2.3) is
        // the status for a request this responder will not answer.
        if (OCSP_request_is_signed(req.get())) {
            std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>
                store{X509_STORE_new(), X509_STORE_free};
            if (!store) {
                log::err("signed OCSP request: could not create a trust store");
                return status_response(OCSP_RESPONSE_STATUS_INTERNALERROR);
            }
            if (ca_cert_) X509_STORE_add_cert(store.get(), ca_cert_.get());
            for (const auto& c : ca_chain_) X509_STORE_add_cert(store.get(), c.get());
            // ⚠️ PARTIAL_CHAIN, OR THIS REFUSES EVERY LEGITIMATE SIGNER ON A SUB-CA.
            // OCSP_request_verify chains under X509_PURPOSE_OCSP_HELPER, whose trust model
            // is COMPAT: without this flag the path must terminate in a SELF-SIGNED
            // certificate that is IN the store. This store holds one CA's own certificates,
            // so on the shipped root -> issuing topology a signer that the issuing CA itself
            // issued cannot reach a self-signed anchor and verification fails. Measured
            // against a real root/issuing/leaf chain on the shipped OpenSSL:
            //
            //   store={issuing CA}                      -> 0  certificate verify error
            //   store={issuing CA} + PARTIAL_CHAIN      -> 1
            //   store={issuing CA, root}                -> 1
            //
            // and a stranger-signed request stays 0 in all three, which is the property that
            // matters. PARTIAL_CHAIN is also the more accurate rule: the question is whether
            // the signer chains to THIS CA, not whether it reaches some root -- so this CA is
            // the anchor, and its ancestors are deliberately not added.
            X509_STORE_set_flags(store.get(), X509_V_FLAG_PARTIAL_CHAIN);
            // OCSP_TRUSTOTHER is NOT passed: it would accept the signer on the strength of
            // being handed to us, which is the very check this is here to make.
            if (OCSP_request_verify(req.get(), nullptr, store.get(), 0) != 1) {
                log::err("signed OCSP request rejected: " + openssl_errors());
                return status_response(OCSP_RESPONSE_STATUS_UNAUTHORIZED);
            }
            log::info("signed OCSP request: signer verified against this CA's chain");
        }

        OcspBasicPtr basic{OCSP_BASICRESP_new()};
        if (!basic) throw Error(2, "OCSP_BASICRESP_new failed: " + openssl_errors());

        // NOTE: expired certs are marked by a periodic background sweep in
        // fastpki-ocsp (OCSP_EXPIRY_SWEEP_SEC), not on the request path — keeps
        // responses fast under load.

        const int n = OCSP_request_onereq_count(req.get());
        const auto now    = std::chrono::system_clock::now();
        const auto now_s  = std::chrono::system_clock::to_time_t(now);
        const auto next_s = now_s + 3600; // nextUpdate +1h — conservative

        // ⚠️ BACKDATE thisUpdate, FOR THE SAME REASON EVERY CERTIFICATE AND CRL WE SIGN IS
        // BACKDATED. A response generated per request is stamped at exactly `now`, so any
        // client whose clock is even a second behind ours receives one dated in its own
        // future and refuses it.
        //
        // The CRL comment beside kClockSkewBackdateSec says OCSP "escapes this" because
        // OCSP_check_validity takes a 300s skew argument. That is true of OPENSSL clients
        // and of nothing else. Windows applies its own rule: measured on a domain client
        // whose clock was SIX SECONDS behind the responder, `certutil -urlfetch -verify`
        // reported the leaf's OCSP as `Expired` while the CRL — which is backdated —
        // verified from the same host in the same run. openssl, with its 300s tolerance,
        // called the identical response `Response verify OK`.
        //
        // Backdating the STAMP only. `now_s` still drives nextUpdate, so the validity
        // window is not shortened; it starts 300s earlier, which is what tolerance means.
        Asn1TimePtr this_update{ASN1_TIME_set(nullptr, now_s - pki::kClockSkewBackdateSec)};
        Asn1TimePtr next_update{ASN1_TIME_set(nullptr, next_s)};

        // Set when we answer for a serial we never issued (RFC 6960 §2.2):
        // such responses must carry the id-pkix-ocsp-extended-revoke extension.
        bool need_extended_revoke = false;

        for (int i = 0; i < n; ++i) {
            OCSP_ONEREQ* one = OCSP_request_onereq_get0(req.get(), i);
            OCSP_CERTID* id  = OCSP_onereq_get0_id(one);
            if (!id) {
                log::err("OCSP_onereq_get0_id returned null");
                continue;
            }

            std::string serial = certid_serial_hex(id);
            auto row = db_.get_cert(serial);

            // ⚠️ A ROW IN `certs` IS NOT PROOF WE ISSUED IT. A listener's own
            // self-signed TLS certificate is an ordinary row here (tagged with a
            // cert_id, and with ca_instance_id NULL because no CA issued it). Answering
            // `good` for one would be this CA vouching for a certificate it never
            // issued — and the RFC 4387 store would serve it too.
            //
            // Treat "no CA of ours issued this" exactly like "we have never heard of
            // it": the non-issued path below is already the right answer.
            if (row && row->ca_instance_id.empty()) {
                log::info("OCSP: serial " + serial + " is in the inventory but no CA of "
                          "ours issued it (self-signed) — answering as non-issued");
                row.reset();
            }
            // ⚠️ NOR IS IT PROOF *THIS* CA ISSUED IT — but the test for that is the stored
            // certificate's ISSUER, not its ca_instance_id. get_cert() looks a serial up with
            // no CA predicate, and the CertID check below is not a substitute: issuerNameHash
            // and issuerKeyHash are computed from public bytes, so a request can name THIS CA
            // while carrying a serial another CA issued, and this responder would answer
            // `good` for a certificate it never issued.
            //
            // ca_instance_id is deliberately NOT used here. It is an ownership/partition key
            // — a label an operator's seeding or an import path may set to something other
            // than the responder's configured id — so comparing it would refuse legitimate
            // certificates (tests/ocsp_responder.sh seeds ca_instance_id='ca' under
            // SIGNING_CA_ID=ca-global). The issuer read off the certificate cannot disagree
            // with the certificate.
            //
            // Rows with NO DER are a supported shape, and for those there is nothing to
            // check — the ca_instance_id.empty() guard above already covers the self-signed
            // case, and anything else is left to the CertID match below.
            if (row && !row->cert_der.empty()) {
                const unsigned char* rp = row->cert_der.data();
                X509Ptr rc{d2i_X509(nullptr, &rp, static_cast<long>(row->cert_der.size()))};
                if (rc) {
                    bool issued_here =
                        X509_NAME_cmp(X509_get_issuer_name(rc.get()),
                                      X509_get_subject_name(ca_cert_.get())) == 0;
                    if (!issued_here)
                        for (const auto& c : ca_chain_)
                            if (c && X509_NAME_cmp(X509_get_issuer_name(rc.get()),
                                                   X509_get_subject_name(c.get())) == 0) {
                                issued_here = true; break;
                            }
                    if (!issued_here) {
                        log::info("OCSP: serial " + serial + " was issued by another CA — "
                                  "answering as non-issued rather than vouching for it");
                        row.reset();
                    }
                }
            }

            // ⚠️ AND THE CertID MUST NAME THIS CA. The check above is narrower: it rules
            // out certificates NO CA of ours issued, not ones a DIFFERENT CA of ours
            // issued. `unauthorized` rather than the non-issued path below, because the two
            // say different things -- non-issued means "this CA never issued that serial",
            // which is an answer ABOUT this CA, while a CertID naming another issuer is a
            // question this responder is not the authority for.
            bool ours = certid_names_this_ca(id, ca_cert_.get(), ca_chain_);
            if (!ours) {
                // ⚠️ ASK THE DATABASE BEFORE REFUSING. Responders are cached per CA for the
                // life of the process, so a CA that has been REKEYED since startup holds a
                // chain here that predates its newest generation — and a certificate issued
                // under that generation carries a key hash this object has never seen.
                // Refusing on the cached copy alone would turn a rekey into an outage for
                // every certificate issued after it, until someone restarted the service.
                // Only on a miss, so the ordinary request still costs nothing.
                try {
                    const auto rc = pki::resolve_ca_instance(db_, cfg_, ca_id_);
                    if (rc.found) {
                        std::vector<X509Ptr> live;
                        const auto take = [&](const std::vector<unsigned char>& der) {
                            if (der.empty()) return;
                            const unsigned char* pp = der.data();
                            X509Ptr c{d2i_X509(nullptr, &pp, static_cast<long>(der.size()))};
                            if (c) live.push_back(std::move(c));
                        };
                        take(rc.cert_der);
                        for (const auto& d : rc.chain_ders) take(d);
                        ours = certid_names_this_ca(id, nullptr, live);
                    }
                } catch (const std::exception& e) {
                    log::err(std::string("OCSP: could not re-read CA '") + ca_id_ +
                             "' to match a CertID: " + e.what());
                }
            }
            if (!ours) {
                log::info("OCSP: CertID for serial " + serial + " names an issuer that is "
                          "not CA '" + ca_id_ + "' — answering unauthorized");
                return status_response(OCSP_RESPONSE_STATUS_UNAUTHORIZED);
            }

            if (!row) {
                // Per RFC 6960 §2.2 "non-issued" handling: revoked with
                // revocationTime = 1970-01-01 and reason = certificateHold,
                // plus the ExtendedRevoke extension on the response.
                Asn1TimePtr epoch{ASN1_TIME_set(nullptr, 0)};
                OCSP_basic_add1_status(basic.get(), id,
                    V_OCSP_CERTSTATUS_REVOKED, OCSP_REVOKED_STATUS_CERTIFICATEHOLD,
                    epoch.get(), this_update.get(), next_update.get());
                need_extended_revoke = true; // extension added once, after the loop
                continue;
            }

            switch (row->status) {
                case 0: // valid
                    OCSP_basic_add1_status(basic.get(), id,
                        V_OCSP_CERTSTATUS_GOOD, 0, nullptr,
                        this_update.get(), next_update.get());
                    break;
                case 1: // expired — RFC says we still return "good" but with
                        // notAfter past. We follow PHP: keep status good and
                        // let the client check validity dates itself.
                    OCSP_basic_add1_status(basic.get(), id,
                        V_OCSP_CERTSTATUS_GOOD, 0, nullptr,
                        this_update.get(), next_update.get());
                    break;
                case 3: // superseded: renewal replaced it under the same cert_id
                    // ⚠️ GOOD, NOT UNKNOWN. Superseded is FastPKI's own bookkeeping — the newer
                    // certificate is the one its services use — and nobody revoked this one, so
                    // the CRL does not list it. RFC 6960 §2.2 "good" means exactly "not revoked";
                    // "unknown" means the responder does not know the certificate, which is
                    // false about one this CA issued and contradicts the CRL beside it. An
                    // operator who wants it refused revokes it, reason superseded.
                    OCSP_basic_add1_status(basic.get(), id,
                        V_OCSP_CERTSTATUS_GOOD, 0, nullptr,
                        this_update.get(), next_update.get());
                    break;
                case -1: { // revoked, or on hold (reason certificateHold)
                    auto when = asn1_time_from_unix(row->revocation_date);
                    // unspecified is sent as no revocationReason at all, as the CRL does
                    // (RFC 5280 §5.3.1: absent rather than unspecified).
                    OCSP_basic_add1_status(basic.get(), id,
                        V_OCSP_CERTSTATUS_REVOKED,
                        row->revocation_reason == pki::kReasonUnspecified
                            ? OCSP_REVOKED_STATUS_NOSTATUS : row->revocation_reason,
                        when.get(), this_update.get(), next_update.get());
                    break;
                }
                case 2: { // pending: CMP issued it and waits for the client's certConf
                          // (RFC 4210 §5.3.18), so it is held until confirmed
                    auto when = asn1_time_from_unix(row->not_before);
                    OCSP_basic_add1_status(basic.get(), id,
                        V_OCSP_CERTSTATUS_REVOKED, OCSP_REVOKED_STATUS_CERTIFICATEHOLD,
                        when.get(), this_update.get(), next_update.get());
                    break;
                }
                default:
                    OCSP_basic_add1_status(basic.get(), id,
                        V_OCSP_CERTSTATUS_UNKNOWN, 0, nullptr,
                        this_update.get(), next_update.get());
            }
        }

        // Copy the nonce extension from the request, if present (RFC 6960 §4.4.1).
        // RFC 8954 §2.1 bounds the nonce to 1..32 octets; an over-long nonce is a
        // request-forgery/amplification vector, so we reject it with
        // malformedRequest. A short (pre-8954) nonce is still echoed for interop.
        {
            int idx = OCSP_REQUEST_get_ext_by_NID(req.get(), NID_id_pkix_OCSP_Nonce, -1);
            if (idx >= 0) {
                X509_EXTENSION* ext = OCSP_REQUEST_get_ext(req.get(), idx);
                if (ext) {
                    // extnValue is DER of an OCTET STRING wrapping the nonce bytes.
                    const ASN1_OCTET_STRING* raw = X509_EXTENSION_get_data(ext);
                    int nonce_len = -1;
                    if (raw) {
                        const unsigned char* np = ASN1_STRING_get0_data(raw);
                        ASN1_OCTET_STRING* inner =
                            d2i_ASN1_OCTET_STRING(nullptr, &np, ASN1_STRING_length(raw));
                        if (inner) { nonce_len = ASN1_STRING_length(inner); ASN1_OCTET_STRING_free(inner); }
                        else       { nonce_len = ASN1_STRING_length(raw); } // non-conformant wrapping
                    }
                    if (nonce_len > 32) {
                        log::err("OCSP: nonce too long (" + std::to_string(nonce_len) +
                                 " > 32 octets, RFC 8954) — malformedRequest");
                        return status_response(OCSP_RESPONSE_STATUS_MALFORMEDREQUEST);
                    }
                    if (nonce_len >= 1)
                        OCSP_BASICRESP_add_ext(basic.get(), ext, -1);
                }
            }
        }

        // RFC 6960 §4.4.8: when reporting "non-issued = revoked", attach the
        // id-pkix-ocsp-extended-revoke extension (OID 1.3.6.1.5.5.7.48.1.9),
        // value DER NULL.
        if (need_extended_revoke) {
            std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>
                obj(OBJ_txt2obj("1.3.6.1.5.5.7.48.1.9", 1), &ASN1_OBJECT_free);
            std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)>
                val(ASN1_OCTET_STRING_new(), &ASN1_OCTET_STRING_free);
            static const unsigned char der_null[2] = {0x05, 0x00};
            if (obj && val && ASN1_OCTET_STRING_set(val.get(), der_null, 2)) {
                X509_EXTENSION* ext = X509_EXTENSION_create_by_OBJ(
                    nullptr, obj.get(), 0, val.get());
                if (ext) {
                    OCSP_BASICRESP_add_ext(basic.get(), ext, -1);
                    X509_EXTENSION_free(ext);
                }
            }
        }

        // Sign with SHA-256, with the delegated responder credential when one is
        // configured, otherwise with the CA.
        //
        // ⚠️ SCOPE NOTE. The settled position is that we should never
        // sign a status assertion with the CA certificate, and I agree. Making that
        // MANDATORY is deliberately not done here: it takes OCSP dark for any CA without
        // a responder certificate (the consequence accepted for CMP), it needs the
        // responder key minted and a certificate issued per CA at deploy time, and it
        // touches the 18 suites that run fastpki-ocsp. That is his call to confirm on
        // and not one to take unilaterally — so the flip stays a
        // one-line change here and the per-CA credential is what ships now.
        // ⚠️ The CA key NEVER signs a status response. There is no fallback.
        //
        // An OCSP response must never be signed with the CA certificate — each CA
        // needs its own responder certificate. A delegated
        // responder is the whole point of RFC 6960 §4.2.2.2, and keeping a silent
        // fall-back to the CA key meant the property held only where someone had
        // remembered to provision one — which is not a property at all.
        //
        // Consequence, accepted deliberately: a CA with no responder credential stops
        // answering OCSP for its own certificates. That is why this landed only after
        // the credential was provisioned on every DC and in the harness — an unprovisioned
        // CA now gets a loud, actionable refusal rather than a quietly CA-signed answer.
        std::string why;
        X509Ptr responder_cert = responder_key_ ? resolve_responder_cert(why) : nullptr;
        if (!responder_cert) {
            if (!responder_key_)
                // ⚠️ "NOT SET" AND "SET BUT UNUSABLE" ARE DIFFERENT FAULTS, and reporting
                // the first when it is the second sends an operator to provision something
                // they already provisioned. Measured: the key was present in the config
                // table and a single leading tab kept it from parsing as a PKCS#11 URI, so
                // the console displayed the URI while this line denied having one. The
                // overlay now trims, but the message still has to tell the two apart.
                //
                // The value is NOT logged: it can carry pin-value=, and no secret reaches
                // the log at any level (tests/secret_leak.sh).
                why = cfg_.ocsp_responder_key.empty()
                    ? "OCSP_RESPONDER_KEY is not set, so this process holds no responder "
                      "credential at all"
                    : "OCSP_RESPONDER_KEY is set but no key could be loaded from it — the "
                      "value is not a usable PKCS#11 URI, or the token did not yield that "
                      "object";
            log::err("OCSP: refusing to answer for CA '" + ca_id_ + "' — " + why +
                     ". The CA key does not sign status responses; issue a responder "
                     "certificate for cert_id '" + cfg_.ocsp_responder_cert_id_prefix + "-" + ca_id_ +
                     "' from that CA (Inventory -> Request, key in HSM -> Serve as OCSP "
                     "responder).");
            return status_response(OCSP_RESPONSE_STATUS_INTERNALERROR);
        }
        X509*     sign_cert = responder_cert.get();
        EVP_PKEY* sign_key  = responder_key_.get();
        STACK_OF(X509)* certs = sk_X509_new_null();
        if (!certs) throw Error(2, "sk_X509_new_null failed");
        // Signer first, then the CA, so a client can build responder -> CA from what the
        // response itself carries.
        sk_X509_push(certs, sign_cert);
        // Always delegated now, so the CA always belongs in the chain —
        // a client that trusts the CA can verify the responder from the response alone.
        //
        // ⚠️ ALL of the CA's live certificates, not just the newest. After a rekey
        // the newest is SELF-ISSUED (new key certified by the old one); on its own it lets
        // a client reach the CA and no further, so anyone anchored at the root got
        //   "ocsp_verify_signer:certificate verify error: unable to get issuer certificate"
        // for a certificate that was perfectly good. Sending the whole set is what rekeying
        // says a chain-server should do — "anything serving a chain should send all of
        // these" — and OCSP was the one consumer of chain_ders that did not.
        if (ca_chain_.empty()) {
            sk_X509_push(certs, ca_cert_.get());
        } else {
            for (const auto& c : ca_chain_) sk_X509_push(certs, c.get());
        }
        // Has signing EVER worked in this process? Only then is a failure evidence
        // that a working token died, rather than one that was never usable — a fresh
        // process whose key loads but cannot sign stays up and answers with an error so an
        // admin can investigate, instead of crash-looping.
        //
        // ⚠️ ONE declaration, in the enclosing scope, deliberately. This was written as two
        // separate `static std::atomic<bool> ever_signed{false}` — one inside the failure
        // branch below and one after it. Same name, different scopes, so they were two
        // different variables: the success path stored into the outer one and the failure
        // path read the inner one, which nothing ever wrote. It was therefore always false,
        // exit_if_token_died was unreachable, and the guard against a crash loop had become
        // "never exit" — which is the liveness gap back again for ocsp, silently. Caught by
        // token_key_liveness.sh's three ocsp assertions, which went red at that commit.
        static std::atomic<bool> ever_signed{false};
        // The digest is the operator's OCSP_RESPONSE_MD, resolved by the SAME helper
        // issuance uses. This was a hardcoded EVP_sha256() — so the sha2/sha3 question
        // that was asked could not even be posed for OCSP, and an operator running a
        // sha384 estate had one signature left at sha256 with nothing to change.
        //
        // ⚠️ THE SIGNER HERE IS THE RESPONDER CREDENTIAL, NOT THE CA. leaf_signing_md's
        // first act is to read an RFC 4055 §3.1 restriction off the certificate it is
        // given, so it must be given `sign_cert` — the delegated responder certificate
        // whose key is about to sign — not the CA's. Passing the CA cert would read a
        // restriction belonging to a different key and could force a digest this key may
        // not use.
        if (!basic_sign_compat(basic.get(), sign_cert, sign_key,
                               leaf_signing_md(sign_key, sign_cert, cfg_.ocsp_response_md,
                                               cfg_.allow_weak_signature_digest),
                               certs)) {
            sk_X509_free(certs);
            const std::string err = openssl_errors();
            if (ever_signed.load(std::memory_order_relaxed)) {
                exit_if_token_died(sign_key, "fastpki-ocsp response signing");
            } else {
                log::err("fastpki-ocsp response signing: OCSP_basic_sign failed: " + err);
            }
            throw Error(2, "OCSP_basic_sign failed: " + err);
        }
        ever_signed.store(true, std::memory_order_relaxed);
        sk_X509_free(certs);

        OcspRespPtr resp{OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic.get())};
        if (!resp) throw Error(2, "OCSP_response_create failed: " + openssl_errors());

        return to_der(resp.get());
    } catch (const Error& e) {
        log::err(std::string("OCSP error: ") + e.what());
        // Map our error code domain to OCSP response statuses; default to
        // internalError when in doubt.
        switch (e.code()) {
            case 1: return status_response(OCSP_RESPONSE_STATUS_MALFORMEDREQUEST);
            case 5: return status_response(OCSP_RESPONSE_STATUS_SIGREQUIRED);
            case 6: return status_response(OCSP_RESPONSE_STATUS_UNAUTHORIZED);
            default: return status_response(OCSP_RESPONSE_STATUS_INTERNALERROR);
        }
    } catch (const std::exception& e) {
        log::err(std::string("OCSP unexpected: ") + e.what());
        return status_response(OCSP_RESPONSE_STATUS_INTERNALERROR);
    }
}

} // namespace pki::ocsp
