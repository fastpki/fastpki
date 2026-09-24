#include "pki/pkcs11_helpers.hpp"
#include "pki/x509.hpp"
#include "pki/endpoint_gate.hpp"   // exit_if_token_died
#include "pki/config.hpp"
#include "pki/cert_profile.hpp"
#include "pki/ca_instance.hpp"   // ca_urls_for_instance for the listener leaf
#include "pki/auth.hpp"        // subject_user/subject_provider: the owner attribute is a DN
#include "pki/db.hpp"
#include "pki/error.hpp"
#include "pki/log.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <fstream>
#include <mutex>
#include <set>
#include "pki/policy.hpp"
#include "pki/service_cert.hpp"   // service_cert_due: listener renewal uses the RA threshold
#include <algorithm>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/param_build.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/store.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/x509v3.h>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace pki {


std::string openssl_errors() {
    std::ostringstream os;
    unsigned long e;
    char buf[256];
    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, buf, sizeof buf);
        os << buf << "; ";
    }
    return os.str();
}

namespace {
struct BioDeleter { void operator()(BIO* b) const noexcept { if (b) BIO_free(b); } };
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

// Open a file through OpenSSL's own BIO_new_file rather than handing OpenSSL an
// app-CRT FILE* (PEM_read_X509(FILE*) etc.). On Windows that FILE*-across-the-
// CRT-boundary path requires the OPENSSL_Applink shim and aborts with
// "no OPENSSL_Applink" when the app and the OpenSSL DLL use different CRTs
// (e.g. vcpkg builds). BIO_new_file opens the file inside OpenSSL, so it works
// uniformly on Linux and Windows. The path is passed UTF-8 (OpenSSL handles the
// encoding); on Windows OpenSSL uses the narrow CRT fopen internally.
BioPtr open_r(const std::filesystem::path& p) {
    BIO* b = BIO_new_file(p.string().c_str(), "rb");
    if (!b) throw Error(2, "cannot open " + p.string() + ": " + openssl_errors());
    return BioPtr{b};
}
} // namespace

// Detect whether `key` is an EC private key backed by a PKCS#11 provider.
// SoftHSM2 (and some other tokens) do not support CKM_ECDSA_SHA256 — only raw
// CKM_ECDSA.  When OpenSSL's pkcs11 provider handles X509_sign() with an EC
// key and EVP_sha256(), it selects CKM_ECDSA_SHA256, which fails.  The callers
// of this predicate pre-hash the TBS in software and sign the raw digest via
// CKM_ECDSA instead.
bool is_ec_p11_key(EVP_PKEY* key) {
    if (!key || EVP_PKEY_get_base_id(key) != EVP_PKEY_EC) return false;
    const OSSL_PROVIDER* prov = EVP_PKEY_get0_provider(key);
    if (!prov) return false;
    const char* name = OSSL_PROVIDER_get0_name(prov);
    return name && std::string(name) == "pkcs11";
}

// Detect EdDSA (Ed25519/Ed448) keys on a PKCS#11 provider.  SoftHSM2's
// CKM_EDDSA rejects EVP_DigestSignInit with a non-null digest — EdDSA must
// be signed with NULL md.
bool is_eddsa_p11_key(EVP_PKEY* key) {
    if (!key) return false;
    int base = EVP_PKEY_get_base_id(key);
    if (base != EVP_PKEY_ED25519 && base != EVP_PKEY_ED448) return false;
    const OSSL_PROVIDER* prov = EVP_PKEY_get0_provider(key);
    if (!prov) return false;
    const char* name = OSSL_PROVIDER_get0_name(prov);
    return name && std::string(name) == "pkcs11";
}

// The digest to pair with an EC key on a PKCS#11 token.  Must match the
// curve's security level so the raw-digest length accepted by CKM_ECDSA
// is correct (P-256→SHA-256, P-384→SHA-384, P-521→SHA-512).
static const EVP_MD* ec_p11_md(EVP_PKEY* key) {
    int bits = EVP_PKEY_get_bits(key);
    if (bits <= 256) return EVP_sha256();
    if (bits <= 384) return EVP_sha384();
    return EVP_sha512();
}

// The digest to sign a certificate with, derived from the CA KEY rather than
// hardcoded. The ruling on the ticket: auto-match, no operator control — a control
// that can only be set wrong is worth not having.
//
//   EC    the curve's security level (P-256->SHA-256, P-384->SHA-384, P-521->SHA-512).
//         This is what ec_p11_md already computed, but nothing reached it: it is the
//         fallback for a NULL md and every caller passed EVP_sha256() explicitly, so a
//         P-384 token CA signed with SHA-256 — a real mismatch, not a style point.
//   RSA   SHA-256 to 3072 bits, SHA-384 from 4096. Pairing a 4096-bit modulus with
//         SHA-256 is not broken, but the digest becomes the weakest part of the pair
//         and the operator who chose the larger key did not ask for that.
//   else  SHA-256. EdDSA ignores it (Ed25519 has its own hash) and sign_x509 passes
//         NULL for those keys anyway.
// The RSA digest ladder lives HERE and nowhere else. Two callers must agree about it or a
// self-signed RSA-PSS CA contradicts itself: ca_signing_md() picks what the certificate is
// SIGNED with, and rsa_pss_restricted_public() picks the hash named inside the RFC 4055
// SPKI restriction. If those diverge the certificate says "this key is PSS-with-SHA-256"
// and then signs itself with SHA-384. One function, so they cannot drift apart.
static const EVP_MD* rsa_md_for_bits(int bits) {
    return bits >= 4096 ? EVP_sha384() : EVP_sha256();
}

// ⚠️ An RFC 4055 SPKI restriction is BINDING on the key, not decoration.
//
// When a certificate's SubjectPublicKeyInfo is id-RSASSA-PSS with an explicit
// hashAlgorithm, that names the ONLY digest this key may sign with. Sign anything with a
// different one and OpenSSL refuses to verify it:
//
//     rsa_check_padding:digest not allowed
//
// That is exactly what happened: a 4096-bit sub-CA created with md=sha256 published a
// SHA-256 restriction, then issued leaves with SHA-384 because the bits ladder below says
// so for 4096. Every certificate it signed was unverifiable. The CA's own certificate
// verified fine, which is what made it look like a leaf problem.
//
// So the certificate wins over the ladder. The ladder is a DEFAULT for choosing a digest;
// a restriction is a statement of what the key is permitted to do, and it was written
// when the CA was created. Reading it here is what makes the two agree by construction
// instead of by two code paths happening to compute the same number.
static const EVP_MD* pss_restricted_md(X509* key_cert) {
    if (!key_cert) return nullptr;
    EVP_PKEY* pub = X509_get0_pubkey(key_cert);
    if (!pub || !EVP_PKEY_is_a(pub, "RSA-PSS")) return nullptr;
    char name[64] = {0};
    // Absent on an RSA-PSS key with no parameters, which RFC 4055 §3.1 leaves unrestricted
    // — nothing to obey, so fall through to the ladder.
    if (EVP_PKEY_get_utf8_string_param(pub, OSSL_PKEY_PARAM_RSA_DIGEST, name, sizeof name, nullptr) != 1) {
        ERR_clear_error();
        return nullptr;
    }
    return EVP_get_digestbyname(name);
}

// Digests that are broken as SIGNATURE hashes and must not be used to sign a certificate
// or a protocol response unless a deployment has explicitly said otherwise.
//
// ⚠️ COMPARED BY NID, NEVER BY THE NAME THE CALLER WROTE. EVP_get_digestbyname resolves
// "sha1", "SHA1", "sha-1" and "RSA-SHA1" to the same EVP_MD, so a blacklist of name
// strings refuses the spellings someone thought of and honours the rest — a filter that
// looks like a control and is not one.
//
// The floor covers the whole family rather than the two names that get quoted: MD5 and
// SHA-1 are the ones people ask for, but MD2/MD4 and the combined MD5-SHA1 are reachable
// through the same lookup and are no better. RIPEMD-160 and MDC-2 are below the modern bar
// too and nothing in this product has a reason to sign with them.
//
// Not a list of "old" digests — a list of digests whose collision resistance is broken
// enough that a chosen-prefix collision has been demonstrated or is within reach. SHA-224
// and up stay allowed.
bool is_weak_signature_digest(const EVP_MD* md) {
    if (!md) return false;
    switch (EVP_MD_get_type(md)) {
        case NID_md2:
        case NID_md4:
        case NID_md5:
        case NID_md5_sha1:
        case NID_sha1:
        case NID_mdc2:
        case NID_ripemd160:
            return true;
        default:
            return false;
    }
}

const EVP_MD* ca_signing_md(EVP_PKEY* key, X509* key_cert) {
    if (!key) return EVP_sha256();
    // Before anything else: if the certificate restricts the key, that is the answer.
    if (const EVP_MD* forced = pss_restricted_md(key_cert)) return forced;
    const int base = EVP_PKEY_get_base_id(key);
    // A pkcs11 private key is a handle, not key material: the provider reports 0 bits for
    // it, which silently sized every token CA as "small" and handed back SHA-256 for
    // everything. The certificate holds the real public key, so take the size from there
    // and fall back to the handle only when no certificate is available.
    int bits = key_cert ? EVP_PKEY_get_bits(X509_get0_pubkey(key_cert)) : 0;
    if (bits <= 0) bits = EVP_PKEY_get_bits(key);
    if (base == EVP_PKEY_EC) {
        if (bits <= 256) return EVP_sha256();
        if (bits <= 384) return EVP_sha384();
        return EVP_sha512();
    }
    if (base == EVP_PKEY_RSA || base == EVP_PKEY_RSA_PSS)
        return rsa_md_for_bits(bits);
    return EVP_sha256();
}

// The digest for a LEAF, which is ca_signing_md() plus an operator choice where a
// choice actually exists. The ruling, and it is right that the earlier cut over-applied:
//
//   Auto-match does not hold for all key types. RSA keys are flexible: requesting a
//   certificate, even a leaf one, should let the caller select the hashing function,
//   with an exception for modern keys that support only one — while EC keys legitimately
//   do auto-match.
//
// So the rule is per key type, not global:
//
//   RSA / RSA-PSS   honour the request. The ladder above is a sensible DEFAULT, not a
//                   property of the key — an RSA key can sign under any digest, sha3
//                   included (EVP_get_digestbyname resolves "sha3-256" &c.), and it
//                   was enforcing a default as though it were a constraint.
//   EC              auto-match, always. The digest must match the curve's security level
//                   or CKM_ECDSA gets a raw digest of the wrong length; a picker here can
//                   only be set wrong, which was the true half of the complaint.
//   Ed25519/ML-DSA  one-shot schemes with their own built-in digest. sign_x509 passes a
//                   null md for these and there is nothing to choose.
//
// ⚠️ AN RFC 4055 §3.1 RESTRICTION IS NOT A PREFERENCE AND OVERRIDES THE REQUEST. When the
// CA's certificate publishes id-RSASSA-PSS with an explicit hashAlgorithm, that names the
// only digest the key may sign with; anything else produces certificates OpenSSL refuses
// to verify with `rsa_check_padding:digest not allowed`. That is the failure
// seen on a 4096-bit sub-CA created with md=sha256, and honouring a picker
// over the restriction would reintroduce it — for a key that, by construction, cannot use
// what was asked for.
//
// An unknown or unresolvable name falls back to auto-match rather than failing the
// issuance: the request named a digest this build of OpenSSL does not have, and refusing
// to issue over a cosmetic field would be the wrong trade.
const EVP_MD* leaf_signing_md(EVP_PKEY* ca_key, X509* ca_cert, const std::string& requested,
                              bool allow_weak) {
    if (const EVP_MD* forced = pss_restricted_md(ca_cert)) return forced;
    if (requested.empty()) return ca_signing_md(ca_key, ca_cert);
    if (!ca_key) return ca_signing_md(ca_key, ca_cert);
    const int base = EVP_PKEY_get_base_id(ca_key);
    if (base != EVP_PKEY_RSA && base != EVP_PKEY_RSA_PSS)
        return ca_signing_md(ca_key, ca_cert);
    const EVP_MD* md = EVP_get_digestbyname(requested.c_str());
    if (!md) {
        ERR_clear_error();
        log::err("issuance: unknown digest '" + requested + "' requested; using the CA default");
        return ca_signing_md(ca_key, ca_cert);
    }
    if (!allow_weak && is_weak_signature_digest(md)) {
        log::err("issuance: refusing the requested signature digest '" + requested +
                 "' — it is below the signature floor; using the CA default instead");
        return ca_signing_md(ca_key, ca_cert);
    }
    return md;
}

// The digest for a signed PROTOCOL RESPONSE (a SCEP CertRep today), for callers that
// hand the digest straight to a signer with no one-shot branch of their own.
//
// leaf_signing_md() answers "which digest", and never null — a certificate signer
// (sign_x509) has its own EdDSA/ML-DSA branch and OCSP's basic_sign_compat has another, so
// neither needs one. `CMS_add1_signer` has none: give it EVP_sha256() for an Ed25519 key
// and it fails outright, which is why CMS_sign's implicit "ask the key for its default"
// worked for those keys before there was a setting at all.
//
// ⚠️ MATCHED BY NAME, not by base id — EVP_PKEY_get_base_id() reports 0 for a
// provider-backed ML-DSA key, and the EdDSA base-id comparison that works on a dev box
// does not hold in the shipped image. That mistake is recorded twice in this tree already
// (src/ocsp/responder.cpp basic_sign_compat); this is the same rule, asked the same way.
bool signature_scheme_has_no_digest(EVP_PKEY* key) {
    if (!key) return false;
    return EVP_PKEY_is_a(key, "ED25519")   || EVP_PKEY_is_a(key, "ED448")     ||
           EVP_PKEY_is_a(key, "ML-DSA-44") || EVP_PKEY_is_a(key, "ML-DSA-65") ||
           EVP_PKEY_is_a(key, "ML-DSA-87");
}

const EVP_MD* response_signing_md(EVP_PKEY* key, X509* signer_cert,
                                  const std::string& requested, bool allow_weak) {
    if (!key) return nullptr;
    if (signature_scheme_has_no_digest(key))
        return nullptr;                       // one-shot: the scheme carries its own hash
    return leaf_signing_md(key, signer_cert, requested, allow_weak);
}

// Detect RSA-PSS key on a PKCS#11 provider.  SoftHSM2 stores
// RSA-PSS as CKK_RSA; the pkcs11 provider exposes the type name "RSA-PSS".
// EVP_DigestSign (C_SignUpdate) fails for RSA-PSS mechanisms; callers must
// use EVP_PKEY_sign (C_Sign one-shot) with CKM_SHA256_RSA_PKCS_PSS instead.
bool is_rsa_pss_p11_key(EVP_PKEY* key) {
    if (!key) return false;
    const char* tn = EVP_PKEY_get0_type_name(key);
    if (!tn || std::string(tn).find("RSA-PSS") == std::string::npos) return false;
    const OSSL_PROVIDER* prov = EVP_PKEY_get0_provider(key);
    if (!prov) return false;
    const char* name = OSSL_PROVIDER_get0_name(prov);
    return name && std::string(name) == "pkcs11";
}

// Any RSA handle belonging to the pkcs11 provider, whatever the provider calls its type.
bool is_p11_rsa_key(EVP_PKEY* key) {
    if (!key) return false;
    const int base = EVP_PKEY_get_base_id(key);
    if (base != EVP_PKEY_RSA && base != EVP_PKEY_RSA_PSS) return false;
    const OSSL_PROVIDER* prov = EVP_PKEY_get0_provider(key);
    if (!prov) return false;
    const char* name = OSSL_PROVIDER_get0_name(prov);
    return name && std::string(name) == "pkcs11";
}

bool p11_rsa_requires_pss(EVP_PKEY* key) {
    if (!is_p11_rsa_key(key)) return false;
    bool is_pss = EVP_PKEY_is_a(key, "RSA-PSS");
    #ifndef NDEBUG
    fprintf(stderr, "FK-DEBUG p11_rsa_requires_pss: base_id=%d is_pss=%d type_name=%s provider=%s\n",
        EVP_PKEY_get_base_id(key), (int)is_pss,
        EVP_PKEY_get0_type_name(key) ? EVP_PKEY_get0_type_name(key) : "(null)",
        EVP_PKEY_get0_provider(key) ? OSSL_PROVIDER_get0_name(EVP_PKEY_get0_provider(key)) : "(null)");
#endif
    return is_pss;
}

// DER-encoded AlgorithmIdentifier for ecdsa-with-SHA256 (RFC 5754 §2.4).
static const unsigned char ECDSA_SHA256_ALG_DER[] = {
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
};

// Build the DER-encoded AlgorithmIdentifier for an ecdsa-with-SHAxxx OID.
static std::vector<unsigned char> ecdsa_alg_der(int sigalg_nid) {
    if (sigalg_nid == NID_ecdsa_with_SHA256)
        return {ECDSA_SHA256_ALG_DER, ECDSA_SHA256_ALG_DER + sizeof(ECDSA_SHA256_ALG_DER)};
    // Generic path: SEQUENCE { OID } — no parameter for ECDSA-with-SHA.
    int oid_len = i2d_ASN1_OBJECT(OBJ_nid2obj(sigalg_nid), nullptr);
    if (oid_len <= 0) throw Error(2, "i2d_ASN1_OBJECT(sigalg) failed");
    std::vector<unsigned char> out;
    if (oid_len < 128) {
        out.push_back(0x30);
        out.push_back(static_cast<unsigned char>(oid_len));
    } else {
        out.push_back(0x30);
        out.push_back(0x81);
        out.push_back(static_cast<unsigned char>(oid_len));
    }
    out.resize(out.size() + oid_len);
    unsigned char* p = out.data() + out.size() - oid_len;
    i2d_ASN1_OBJECT(OBJ_nid2obj(sigalg_nid), &p);
    return out;
}

// Encode a DER tag+length into a buffer.  `tag` is the DER tag byte
// (e.g. 0x30 for SEQUENCE, 0x03 for BIT STRING).  Returns the total
// number of bytes written (tag + length encoding).
static int der_encode_tl(unsigned char tag, size_t len, unsigned char* buf) {
    buf[0] = tag;
    if (len < 128) {
        buf[1] = static_cast<unsigned char>(len);
        return 2;
    } else if (len < 256) {
        buf[1] = 0x81;
        buf[2] = static_cast<unsigned char>(len);
        return 3;
    } else if (len < 65536) {
        buf[1] = 0x82;
        buf[2] = static_cast<unsigned char>(len >> 8);
        buf[3] = static_cast<unsigned char>(len & 0xff);
        return 4;
    }
    throw Error(2, "DER length too large");
}

// Rebuild a signed X509 cert by reconstructing the DER from three components:
// TBSCertificate + AlgorithmIdentifier + BIT_STRING(signature).
// Returns a newly allocated X509* (caller must free the old one).
static X509* rebuild_cert_from_tbs_and_sig(
        X509* cert, int sigalg_nid,
        const unsigned char* sig, size_t sig_len) {
    // TBS DER must be extracted AFTER the TBS-internal signatureAlgorithm
    // has been set (via X509_ALGOR_set0 in sign_x509).
    int tbs_len = i2d_re_X509_tbs(cert, nullptr);
    if (tbs_len <= 0) throw Error(2, "i2d_re_X509_tbs failed");
    std::vector<unsigned char> tbs(static_cast<size_t>(tbs_len));
    unsigned char* tp = tbs.data();
    if (i2d_re_X509_tbs(cert, &tp) != tbs_len)
        throw Error(2, "i2d_re_X509_tbs mismatch");

    // AlgorithmIdentifier for ecdsa-with-SHAxxx.
    auto alg = ecdsa_alg_der(sigalg_nid);

    // BIT STRING: tag 0x03, content = 0x00 (unused bits) + sig.
    size_t bs_content = 1 + sig_len;
    unsigned char bs_tl[5];
    int bs_tl_len = der_encode_tl(0x03, bs_content, bs_tl);

    // Outer SEQUENCE.
    size_t content_len = tbs_len + alg.size() + bs_tl_len + 1 + sig_len;
    unsigned char seq_tl[5];
    int seq_tl_len = der_encode_tl(0x30, content_len, seq_tl);

    size_t total = seq_tl_len + content_len;
    std::vector<unsigned char> der(total);
    unsigned char* wp = der.data();
    memcpy(wp, seq_tl, seq_tl_len); wp += seq_tl_len;
    memcpy(wp, tbs.data(), tbs_len);  wp += tbs_len;
    memcpy(wp, alg.data(), alg.size()); wp += alg.size();
    memcpy(wp, bs_tl, bs_tl_len);   wp += bs_tl_len;
    *wp++ = 0x00;  // unused-bits byte for BIT STRING
    memcpy(wp, sig, sig_len);

    const unsigned char* dp = der.data();
    X509* result = d2i_X509(nullptr, &dp, static_cast<long>(total));
    if (!result) throw Error(2, "d2i_X509(rebuilt) failed: " + openssl_errors());
    return result;
}

// Sign an X.509 certificate.  Returns the (possibly different) X509 pointer.
// Provider-specific workarounds:
//  - RSA-PSS on pkcs11: X509_sign_ctx with PSS params.
//  - EC on pkcs11: pre-hash TBS, sign raw digest with CKM_ECDSA.
//  - EdDSA (any provider): must use NULL md — EdDSA handles hashing
//    internally and OpenSSL rejects any explicit digest.
// The returned pointer may differ from the input — callers must use the
// returned value and free the original.
// The ECDSA signature-algorithm OID for a digest, or NID_undef when this build has none.
//
// FIPS 186-5 approves ECDSA with the whole SHA-2 family AND the whole SHA-3 family, and the
// prehash path below is exactly the case where the digest is a free choice: the hash is
// computed in software and only the raw signature happens in the token, so the token's own
// mechanism list has no say in it. The only real constraint is whether an OID exists to name
// the pair in the certificate — refusing a digest for any other reason is us inventing a
// restriction the standard does not have.
//
// SHAKE128/SHAKE256 are approved by 186-5 too but have no ecdsa-with-SHAKE OID in this
// OpenSSL, so they still fall through to NID_undef. That is a naming gap, not a policy, and
// the message says so rather than implying the algorithm is unwelcome.
int ecdsa_sigalg_nid(int md_nid) {
    switch (md_nid) {
        case NID_sha224:   return NID_ecdsa_with_SHA224;
        case NID_sha256:   return NID_ecdsa_with_SHA256;
        case NID_sha384:   return NID_ecdsa_with_SHA384;
        case NID_sha512:   return NID_ecdsa_with_SHA512;
        case NID_sha3_224: return NID_ecdsa_with_SHA3_224;
        case NID_sha3_256: return NID_ecdsa_with_SHA3_256;
        case NID_sha3_384: return NID_ecdsa_with_SHA3_384;
        case NID_sha3_512: return NID_ecdsa_with_SHA3_512;
        default:           return NID_undef;
    }
}

X509* sign_x509(X509* cert, EVP_PKEY* key, const EVP_MD* md) {
    // --- EdDSA (any provider): must use NULL md ---------------
    // EdDSA is a one-shot scheme that hashes internally; OpenSSL rejects
    // any explicit digest with "invalid digest".  Override md to NULL
    // regardless of what the caller requested.
    {
        int base = EVP_PKEY_get_base_id(key);
        if (base == EVP_PKEY_ED25519 || base == EVP_PKEY_ED448) {
            if (!X509_sign(cert, key, nullptr))
                throw Error(2, "X509_sign(EdDSA) failed: " + openssl_errors());
            return cert;
        }
    }

    // --- RSA-PSS on pkcs11: X509_sign_ctx with PSS params -----
    // X509_sign builds its own EVP_MD_CTX with no PSS parameters, so the provider asks for
    // CKM_SHA256_RSA_PKCS — which a PSS-restricted key refuses. X509_sign_ctx lets us
    // pre-configure PSS so it asks for CKM_SHA256_RSA_PKCS_PSS instead.
    //
    // Ask the TOKEN, not the type name. p11_rsa_requires_pss() probes with v1.5,
    // which is the only thing that distinguishes the two — see its comment. This is what
    // fixes sub-CA, CRL and audit signing, all of which load their key and so lost the
    // "RSA-PSS" type name is_rsa_pss_p11_key() depends on.
    if (p11_rsa_requires_pss(key)) {
        const EVP_MD* use_md = md ? md : EVP_sha256();
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        if (!mctx) throw Error(2, "EVP_MD_CTX_new failed");
        EVP_PKEY_CTX* pctx = nullptr;
        if (EVP_DigestSignInit(mctx, &pctx, use_md, nullptr, key) <= 0) {
            EVP_MD_CTX_free(mctx);
            throw Error(2, "EVP_DigestSignInit(RSA-PSS) failed: " + openssl_errors());
        }
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, use_md) <= 0 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
            EVP_MD_CTX_free(mctx);
            throw Error(2, "EVP_PKEY_CTX RSA-PSS params failed: " + openssl_errors());
        }
        if (!X509_sign_ctx(cert, mctx)) {
            EVP_MD_CTX_free(mctx);
            throw Error(2, "X509_sign_ctx(RSA-PSS) failed: " + openssl_errors());
        }
        EVP_MD_CTX_free(mctx);
        return cert;
    }

    // --- EC on pkcs11: pre-hash then sign with CKM_ECDSA -----
    if (!is_ec_p11_key(key)) {
        if (!X509_sign(cert, key, md))
            {
                // A signing failure on a token key may mean the token (or its
                // sidecar) restarted, which kills this PROCESS's provider connection for
                // good. Ask whether the key can sign AT ALL; if not, exit so the restart
                // policy supplies a fresh connection. Returns normally for an ordinary
                // signing error, which then propagates as one.
                const std::string err = openssl_errors();
                exit_if_token_died(key, "cert signing");
                throw Error(2, "X509_sign failed: " + err);
            }
        return cert;
    }
    // EC on pkcs11: pre-hash then sign with CKM_ECDSA.
    const EVP_MD* use_md = md ? md : ec_p11_md(key);
    int sigalg_nid = ecdsa_sigalg_nid(EVP_MD_get_type(use_md));
    if (sigalg_nid == NID_undef)
        throw Error(2, std::string("no ECDSA signature OID for digest ") +
                       (EVP_MD_get0_name(use_md) ? EVP_MD_get0_name(use_md) : "?") +
                       " — FIPS 186-5 permits SHA-2 and SHA-3, and this build has an OID for each");

    // 1. Populate the TBS-internal signatureAlgorithm so i2d_re_X509_tbs()
    //    can DER-encode the unsigned cert.  OpenSSL 3.x leaves this field
    //    UNDEF until X509_sign() runs; X509_get0_tbs_sigalg() returns const
    //    but the underlying ASN1 object is modifiable memory.
    const X509_ALGOR* calg = X509_get0_tbs_sigalg(cert);
    X509_ALGOR_set0(const_cast<X509_ALGOR*>(calg),
                    OBJ_nid2obj(sigalg_nid), V_ASN1_UNDEF, nullptr);

    // 2. Extract TBS DER.
    int tbs_len = i2d_re_X509_tbs(cert, nullptr);
    if (tbs_len <= 0)
        throw Error(2, "i2d_re_X509_tbs failed: " + openssl_errors());
    std::vector<unsigned char> tbs(static_cast<size_t>(tbs_len));
    unsigned char* tp = tbs.data();
    if (i2d_re_X509_tbs(cert, &tp) != tbs_len)
        throw Error(2, "i2d_re_X509_tbs mismatch");

    // 3. Hash TBS in software.
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (!EVP_Digest(tbs.data(), tbs.size(), hash, &hash_len, use_md, nullptr))
        throw Error(2, "TBS digest failed: " + openssl_errors());

    // 4. Sign the raw hash via EVP_PKEY_sign (bypasses the EVP_DigestSign
    //    layer which would still select CKM_ECDSA_SHA256 even with NULL md
    //    because the pkcs11 provider defaults to the key's digest for EC).
    //    EVP_PKEY_sign sends the pre-hashed data straight to CKM_ECDSA.
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(key, nullptr);
    if (!pctx) throw Error(2, "EVP_PKEY_CTX_new failed");
    if (EVP_PKEY_sign_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw Error(2, "EVP_PKEY_sign_init failed: " + openssl_errors());
    }
    size_t sig_len = 0;
    if (EVP_PKEY_sign(pctx, nullptr, &sig_len, hash, hash_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw Error(2, "EVP_PKEY_sign size-query failed: " + openssl_errors());
    }
    std::vector<unsigned char> sig_buf(sig_len);
    if (EVP_PKEY_sign(pctx, sig_buf.data(), &sig_len, hash, hash_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw Error(2, "EVP_PKEY_sign(prehash) failed: " + openssl_errors());
    }
    EVP_PKEY_CTX_free(pctx);

    // 5. Rebuild cert DER from TBS + AlgorithmIdentifier + BIT_STRING(sig),
    //    then parse into a new X509 object.
    X509* result = rebuild_cert_from_tbs_and_sig(cert, sigalg_nid, sig_buf.data(), sig_len);
    X509_free(cert);
    return result;
}

X509Ptr load_cert_pem(const std::filesystem::path& path) {
    auto b = open_r(path);
    X509* x = PEM_read_bio_X509(b.get(), nullptr, nullptr, nullptr);
    if (!x) throw Error(2, "PEM_read_bio_X509 failed for " + path.string() + ": " + openssl_errors());
    return X509Ptr{x};
}

X509Ptr load_cert_der(const std::filesystem::path& path) {
    auto b = open_r(path);
    X509* x = d2i_X509_bio(b.get(), nullptr);
    if (!x) throw Error(2, "d2i_X509_bio failed for " + path.string() + ": " + openssl_errors());
    return X509Ptr{x};
}

X509Ptr parse_cert_der(const std::vector<unsigned char>& der) {
    if (der.empty()) throw Error(2, "empty DER buffer");
    const unsigned char* p = der.data();
    X509* x = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
    if (!x) throw Error(2, "d2i_X509 (DER buffer) failed: " + openssl_errors());
    return X509Ptr{x};
}

std::vector<X509Ptr> load_certs_pem_mem(const std::string& pem) {
    std::vector<X509Ptr> out;
    if (pem.empty()) return out;
    BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
    if (!bio) return out;
    while (X509* x = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr))
        out.emplace_back(x);
    ERR_clear_error();   // loop terminates on a benign "no start line" once certs run out
    return out;
}

EvpPkeyPtr load_privkey_pem(const std::filesystem::path& path) {
    auto b = open_r(path);
    EVP_PKEY* k = PEM_read_bio_PrivateKey(b.get(), nullptr, nullptr, nullptr);
    if (!k) throw Error(2, "PEM_read_bio_PrivateKey failed for " + path.string() + ": " + openssl_errors());
    return EvpPkeyPtr{k};
}

namespace {
// Load the pkcs11 OpenSSL provider per cfg, alongside the default
// provider (signing still needs its algorithms). Idempotent — the providers are
// process-wide statics. Used both to reference an existing token key
// (load_signing_key) and to generate a new one (generate_key_in_token).
void ensure_pkcs11_provider(const Config& cfg) {
    // ⚠️ SERIALISED, BECAUSE setenv() IS NOT THREAD-SAFE. It may reallocate the environment
    // block and free the old value while another thread's getenv() — inside the pkcs11
    // provider — is walking it, and on musl two concurrent setenv() calls on one name can
    // free the same pointer twice. The shipped image is Alpine, so that is the platform this
    // actually runs on, and the shipped config sets PKCS11_MODULE, so the branch fires on
    // every call rather than never.
    //
    // "Idempotent" below is about REPEATED calls, which the function-local statics do handle;
    // it says nothing about CONCURRENT ones. This is reached from request threads (the SCEP
    // RA key is reloaded per request) and from the detached token-liveness pollers in every
    // protocol binary, which run every few seconds — so a single-request deployment still
    // races its own prober.
    //
    // The same hazard is already recorded and guarded in src/msxcep/kerberos.cpp for
    // KRB5_KTNAME. This is the sibling copy that was missed.
    static std::mutex p11_env_mu;
    std::lock_guard<std::mutex> p11_lk(p11_env_mu);

    if (!cfg.pkcs11_module.empty()) {
        const std::string mod = cfg.pkcs11_module.string();
        ::setenv("PKCS11_PROVIDER_MODULE", mod.c_str(), 1);
    }
    // Also process-global libctx state, and mutated with the same lack of synchronisation.
    if (!cfg.pkcs11_provider_path.empty() &&
        !OSSL_PROVIDER_set_default_search_path(nullptr, cfg.pkcs11_provider_path.string().c_str()))
        throw Error(2, "OSSL_PROVIDER_set_default_search_path failed: " + openssl_errors());
    static OSSL_PROVIDER* deflt = OSSL_PROVIDER_load(nullptr, "default");
    (void)deflt;
    static OSSL_PROVIDER* p11 = OSSL_PROVIDER_load(nullptr, "pkcs11");
    if (!p11) throw Error(2, "failed to load the pkcs11 OpenSSL provider (PKCS11_PROVIDER_PATH?): "
                             + openssl_errors());
}
} // namespace

bool key_usable(EVP_PKEY* key) {
    if (!key) return false;
    // A fixed scratch buffer: the CONTENT is irrelevant, only that producing a signature
    // forces the provider to reach the token. See the header for why a load is not enough.
    static const unsigned char probe[] = "fastpki key liveness";
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>
        md(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!md) return false;
    const int kid = EVP_PKEY_get_id(key);
    const bool is_rsa = (kid == EVP_PKEY_RSA || kid == EVP_PKEY_RSA_PSS);
    size_t n = 0;
    // A null digest is required by the one-shot algorithms (Ed25519, ML-DSA) and rejected
    // by RSA/EC, so try the null form first and fall back to SHA-256.
    for (const EVP_MD* d : { static_cast<const EVP_MD*>(nullptr), EVP_sha256() }) {
        if (is_rsa && d == nullptr) continue;   // RSA never works with null digest
        if (is_rsa) {
            // Both RSA and RSA-PSS keys can appear in SoftHSM; the web console doesn't
            // distinguish them.  Try both padding modes before giving up.
            for (int pad : { RSA_PKCS1_PSS_PADDING, RSA_PKCS1_PADDING }) {
                EVP_MD_CTX_reset(md.get());
                EVP_PKEY_CTX* pctx = nullptr;
                if (EVP_DigestSignInit(md.get(), &pctx, d, nullptr, key) <= 0) continue;
                EVP_PKEY_CTX_set_rsa_padding(pctx, pad);
                if (EVP_DigestSign(md.get(), nullptr, &n, probe, sizeof probe - 1) <= 0) continue;
                std::vector<unsigned char> sig(n);
                if (EVP_DigestSign(md.get(), sig.data(), &n, probe, sizeof probe - 1) > 0) return true;
            }
            continue;   // tried both RSA modes, no point in the generic fallthrough
        }
        EVP_MD_CTX_reset(md.get());
        if (EVP_DigestSignInit(md.get(), nullptr, d, nullptr, key) <= 0) continue;
        if (EVP_DigestSign(md.get(), nullptr, &n, probe, sizeof probe - 1) <= 0) continue;
        std::vector<unsigned char> sig(n);
        if (EVP_DigestSign(md.get(), sig.data(), &n, probe, sizeof probe - 1) > 0) return true;
    }
    return false;
}

EvpPkeyPtr load_key_file_or_token(const std::string& key_ref, const Config& cfg) {
    if (key_ref.empty()) return nullptr;
    if (key_ref.rfind("pkcs11:", 0) != 0) return load_privkey_pem(key_ref);
    return load_signing_key(key_ref, cfg);
}

// A CA private key lives in a token. There is no on-disk branch here — not as a
// fallback, not as a last resort. `load_privkey_pem` still exists and is still right for
// the SCEP RA key and for client keys, which are not CA keys; what is gone is the idea
// that a CA signing key may be a file.
// One URL's worth of loading. load_signing_key() below is the entry point and handles a
// LIST; this is what it tries per entry.
static EvpPkeyPtr load_signing_key_one(const std::string& key, const Config& cfg) {
    if (key.rfind("pkcs11:", 0) != 0)
        throw Error(2, "a CA signing key must be a pkcs11: handle, not a file path (got '" +
                       key + "')");

    // PKCS#11 HSM / smart-card CA key. The pkcs11 provider is a
    // runtime concern (no build dependency): point it at the token module, load
    // it alongside the default provider, then pull the key handle via OSSL_STORE.
    // The private key stays in the token; the EVP_PKEY only references it.
    ensure_pkcs11_provider(cfg);

    std::unique_ptr<OSSL_STORE_CTX, decltype(&OSSL_STORE_close)>
        ctx(OSSL_STORE_open(key.c_str(), nullptr, nullptr, nullptr, nullptr), &OSSL_STORE_close);
    // ⚠️ REDACTED, and that matters because this text becomes e.what() at every catch site.
    // RFC 7512 lets the token PIN sit in the URI as `pin-value=`; fastpki-cmp logs this
    // exception at info on a deployment whose RA key does not exist yet, so an unredacted
    // handle put the PIN in the log on every start.
    // kErrTokenUnavailable: the store would not even OPEN, so this is the token or the
    // provider, never a missing object — the lookup never got far enough to miss one.
    if (!ctx) throw Error(kErrTokenUnavailable,
                          "OSSL_STORE_open failed for " + pkcs11_uri_redacted(key) +
                          ": " + openssl_errors());

    EvpPkeyPtr pkey;
    while (!OSSL_STORE_eof(ctx.get())) {
        std::unique_ptr<OSSL_STORE_INFO, decltype(&OSSL_STORE_INFO_free)>
            info(OSSL_STORE_load(ctx.get()), &OSSL_STORE_INFO_free);
        if (!info) continue;
        if (OSSL_STORE_INFO_get_type(info.get()) == OSSL_STORE_INFO_PKEY) {
            pkey.reset(OSSL_STORE_INFO_get1_PKEY(info.get()));
            break;
        }
    }
    // Say WHY. This used to be the bare sentence, and it is a lie in the case that
    // actually happens: OSSL_STORE_open succeeds against a dead or not-yet-ready token,
    // every OSSL_STORE_load returns null, the loop above discards each error, and we
    // announce "no private key found" about a key the operator can see in the token with
    // pkcs11-tool. The error queue holds the real cause (login failed, module not
    // initialised, no such slot) and was being thrown away — line 594 above already
    // appends it for the open failure, this one did not.
    if (!pkey) {
        const std::string errs = openssl_errors();
        // ⚠️ THE EMPTY QUEUE IS THE DISCRIMINATOR, and it is measured rather than assumed.
        // With the token UP and no such object, `openssl storeutl` against that handle prints
        // NOTHING and the queue is empty. With the token DOWN it prints
        //     error:40000002:pkcs11:p11prov_ctx_status:...:Module initialization failed!
        // so the queue is populated. An empty queue therefore means "reachable, no such
        // object" — the ordinary state of a fresh install, which must keep serving — and a
        // populated one means the token or this process's provider is the problem, which only
        // a new process can fix.
        //
        // The empty case keeps code 2 deliberately: if a dead session ever does present with
        // an empty queue, the consequence is a slower recovery rather than a restart loop,
        // and that is the safe direction to be wrong in.
        throw Error(errs.empty() ? 2 : kErrTokenUnavailable,
                    "no private key found at pkcs11 URI: " + pkcs11_uri_redacted(key) +
                       (errs.empty()
                            ? " (the token is reachable but holds nothing under that object "
                              "label, which is normal before the credential has been created)"
                            : ": " + errs));
    }
    return pkey;
}

std::vector<std::string> split_key_urls(const std::string& key_ref) {
    std::vector<std::string> out;
    std::string cur;
    // Newline-separated. NOT comma or semicolon: RFC 7512 gives a pkcs11 URI both of those
    // as internal separators, so either would split a single handle down the middle.
    for (char c : key_ref) {
        if (c == '\n' || c == '\r') { out.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    out.push_back(cur);
    std::vector<std::string> kept;
    for (auto& u : out) {
        const size_t b = u.find_first_not_of(" \t");
        if (b == std::string::npos) continue;                 // blank line
        const size_t e = u.find_last_not_of(" \t");
        kept.push_back(u.substr(b, e - b + 1));
    }
    return kept;
}

// ⚠️ THIS IS KEY SELECTION ACROSS A CA'S GENERATIONS, NOT HOST FAILOVER. A CA may name
// several key URLs because ONE CA HAS MORE THAN ONE KEY OVER ITS LIFE: a re-key adds a
// certificate and the key that goes with it, and a cross-signed certificate is another
// certificate over a key already in the list. Both generations stay live through a rollover
// — resolve_ca_instance() serves every one of them in chain_ders — so the CA row has to
// carry every key, and the CERTIFICATE IN USE is what says which one signs.
//
// That is what `expect` does, and it is the mechanism rather than a safety net:
//
// ⚠️ 1. "THE FIRST THAT WORKS" MEANS THE FIRST THAT HOLDS THIS KEY, not the first that
//    answers. Pass `expect` — the certificate this operation signs under — and each
//    candidate is checked against it, so the right generation's key is the one returned. It
//    catches a genuinely wrong key too: a token that is up with the wrong key is far more
//    dangerous than one that is down, because it loads instantly and signs certificates that
//    chain to nothing.
//
// ⚠️ IT DOES NOT SPAN HOSTS. Every candidate is opened through load_signing_key_one(), which
//    uses the ONE PKCS#11 module this process has (ensure_pkcs11_provider). The URLs select a
//    different token on that module, never a different machine. Surviving the loss of a host
//    needs an appliance presenting several tokens, or the key replicated into this node's own
//    token — see docs/architecture.md §5-§6. Do not describe this list as HA.
//
// ⚠️ 2. A MISMATCH IS LOUD. It is skipped rather than fatal, because one stale token must not
//    take the CA down when a good one is listed after it — but it is a real misconfiguration
//    and is logged at error, never passed over in silence. Without `expect` there is no way
//    to tell a wrong key from a right one, so the first that LOADS is returned; that is the
//    honest limit of a caller that has no certificate to compare against.
//
// An unreachable URL is ordinary in a multi-node deployment and logs at info.
EvpPkeyPtr load_signing_key(const std::string& key_ref, const Config& cfg, X509* expect) {
    if (key_ref.empty()) return nullptr;                    // no key configured
    const std::vector<std::string> urls = split_key_urls(key_ref);
    if (urls.empty()) return nullptr;
    // ⚠️ A SINGLE URL KEEPS TODAY'S BEHAVIOUR EXACTLY, including its errors. There is
    // nothing to fail over TO, so skipping a mismatched key here would only replace the
    // caller's precise "the certificate and its private key do not match, check the pkcs11
    // object" with a generic "no usable candidate" — worse for the one deployment shape
    // where the operator can actually act on it. Verification stays the caller's, as it was.
    if (urls.size() == 1) return load_signing_key_one(urls[0], cfg);

    std::string why;
    for (size_t i = 0; i < urls.size(); ++i) {
        const std::string redacted = pkcs11_uri_redacted(urls[i]);
        try {
            EvpPkeyPtr k = load_signing_key_one(urls[i], cfg);
            if (!k) { why += "\n  " + redacted + ": no key"; continue; }
            if (expect && !cert_certifies_key(expect, k.get())) {
                log::err("CA signing key at " + redacted + " does NOT match this CA's "
                         "certificate — skipping it. Nothing signed by it would verify "
                         "against the published CA certificate; that token holds a "
                         "different or stale key and needs re-provisioning.");
                why += "\n  " + redacted + ": holds a different key";
                continue;
            }
            if (i > 0)
                log::info("CA signing key: failed over to " + redacted + " (candidate " +
                          std::to_string(i + 1) + " of " + std::to_string(urls.size()) + ")");
            return k;
        } catch (const std::exception& e) {
            // Ordinary on a node whose peer is down, so info rather than error — the
            // refusal below is where it becomes a failure, and it names every candidate.
            log::info("CA signing key at " + redacted + " is not usable: " + e.what());
            why += "\n  " + redacted + ": " + e.what();
        }
    }
    throw Error(2, "no usable signing key among " + std::to_string(urls.size()) +
                   " candidate(s):" + why);
}

// ---- CSR parsing -----------------------------------------------------------

X509ReqPtr parse_csr(std::string_view bytes) {
    if (bytes.empty()) throw Error(1, "empty CSR");
    BIO* bio = BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size()));
    if (!bio) throw Error(2, "BIO_new_mem_buf failed");
    X509_REQ* req = nullptr;
    // Try PEM first; if it fails, rewind and try DER.
    req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
    if (!req) {
        BIO_free(bio);
        bio = BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size()));
        const unsigned char* p = reinterpret_cast<const unsigned char*>(bytes.data());
        req = d2i_X509_REQ(nullptr, &p, static_cast<long>(bytes.size()));
    }
    BIO_free(bio);
    if (!req) throw Error(1, "CSR is not valid PEM or DER: " + openssl_errors());

    X509ReqPtr out{req};
    EVP_PKEY* pk = X509_REQ_get0_pubkey(out.get());
    if (!pk) throw Error(1, "CSR missing public key");
    if (X509_REQ_verify(out.get(), pk) != 1)
        throw Error(1, "CSR signature (POP) verification failed: " + openssl_errors());
    return out;
}

// ---- Issuance --------------------------------------------------------------

namespace {

// ── this node's data center serial prefix ────────────────────────────────────────
//
// A PROCESS-WIDE fact, not a per-call argument, and deliberately so. The rule is one
// rule for everything this node MINTS — leaf certificates, our own CA certificates,
// our self-signed transport certificates — and there are four mint sites reached
// through six public entry points. Threading a prefix through all of them is six
// chances to pass 0 and silently mint into another datacenter's space; a single fact
// set once at startup has one.
//
// The certificates WITHOUT our prefix are the ones we did not issue: an imported or
// cross-signed foreign root, a sub-CA signed by the offline root, a transport cert
// from an outside CA. Those arrive as DER we store, never through this file.
//
// Set by resolve_datacenter_prefix() (config.cpp) right after overlay_config().
// A binary that mints without calling it does NOT go unnoticed: on a meshed node the
// per-node guard trigger rejects the resulting serial, because it will not carry this
// node's prefix. That trigger is the net; this is the rule.
std::mutex g_dc_mu;
std::string g_dc_id;                  // configured DATACENTER_ID; "" = single node
int g_dc_prefix = 0;                  // resolved prefix; 0 = none

// Generate the certificate serial: a positive random `bytes_n`-byte integer, carrying
// this data center's 2-octet prefix in the top two bytes when this node is in a mesh.
//
// The prefix is what keeps two datacenters from ever minting the same serial — the certs
// primary key IS the serial, so a collision is a replication conflict that stalls an apply
// worker. It replaced a [min, max) range fold: same guarantee, but with nothing to
// configure, validate for overlap, or keep in step with the guard trigger by hand.
//
// ⚠️ WHY 1..32767 AND NOT 1..65535. DER integers are SIGNED. A leading octet with its top
// bit set makes the value negative, so OpenSSL prepends a 0x00 to keep it positive — which
// silently pushes a 20-octet serial to 21 and out of RFC 5280 §4.1.2.2. Constraining the
// prefix to 0x0001-0x7FFF keeps the high bit clear by construction, which is also why the
// old `raw[0] &= 0x7F` fixup is not needed on the prefixed path.
//
// ⚠️ A PREFIXED SERIAL MUST BE 20 OCTETS. The mesh guard finds the prefix positionally,
// as the first 4 hex characters of `lpad(lower(serial),40,'0')`, and the database has no
// way to know CERT_SERIAL_BYTES. At any other width the padding shifts the prefix off
// position 1 and the guard compares the wrong characters — it would reject every serial
// this node mints, or worse, accept one that is not ours. 20 is also the RFC 5280 §4.1.2.2
// maximum, so this rejects nothing anyone should be configuring in a mesh.
//
// ⚠️ 18 random octets remain, so 144 bits of entropy — far above the CA/Browser Forum's
// 64-bit floor. The prefix costs entropy but buys the collision guarantee outright.
void set_random_serial(X509* cert, int bytes_n) {
    int prefix = 0;
    {
        std::lock_guard<std::mutex> lk(g_dc_mu);
        if (!g_dc_id.empty()) {
            if (g_dc_prefix == 0)
                throw Error(1, "refusing to assign a serial: DATACENTER_ID=" + g_dc_id +
                               " but no serial prefix is resolved for this node");
            prefix = g_dc_prefix;
        }
    }
    if (prefix != 0 && bytes_n != 20)
        throw Error(1, "CERT_SERIAL_BYTES=" + std::to_string(bytes_n) + " but a data center "
                       "prefix requires exactly 20 (the mesh guard reads the prefix at a "
                       "fixed position in a 40-hex-character serial)");

    std::vector<unsigned char> raw(static_cast<size_t>(bytes_n));
    if (RAND_bytes(raw.data(), bytes_n) != 1)
        throw Error(2, "RAND_bytes failed: " + openssl_errors());
    if (prefix != 0) {
        raw[0] = static_cast<unsigned char>((prefix >> 8) & 0xFF);   // <= 0x7F by construction
        raw[1] = static_cast<unsigned char>(prefix & 0xFF);
    } else {
        raw[0] &= 0x7F; // make it positive
        if (raw[0] == 0) raw[0] = 1;
    }
    std::unique_ptr<BIGNUM, decltype(&BN_free)> bn(
        BN_bin2bn(raw.data(), bytes_n, nullptr), &BN_free);
    if (!bn) throw Error(2, "BN_bin2bn failed");

    std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)>
        ai(ASN1_INTEGER_new(), &ASN1_INTEGER_free);
    if (!ai) throw Error(2, "ASN1_INTEGER_new failed");
    if (!BN_to_ASN1_INTEGER(bn.get(), ai.get()))
        throw Error(2, "BN_to_ASN1_INTEGER failed: " + openssl_errors());
    if (!X509_set_serialNumber(cert, ai.get()))
        throw Error(2, "X509_set_serialNumber failed: " + openssl_errors());
}

// RFC 5280 §4.2.1.10 encodes an iPAddress name constraint as address + MASK, and
// OpenSSL's parser demands the mask spelled out in full ("10.0.0.0/255.0.0.0"). Operators
// — and this product's own console, which printed `IP:10.0.0.0/8` as its worked example
// since the CA form shipped — write CIDR. The result was `bad ip address` with nothing
// pointing at the syntax.
//
// CIDR is the notation to accept, not the one to document around: prefix-length to mask
// is exact and total, so nothing is lost by converting. Anything that is not `IP:…/<n>`
// is passed through untouched, including the netmask form itself.
std::string nc_normalize_ip(const std::string& entry) {
    if (entry.rfind("IP:", 0) != 0) return entry;
    const auto slash = entry.rfind('/');
    if (slash == std::string::npos) return entry;
    const std::string addr = entry.substr(3, slash - 3);
    const std::string suffix = entry.substr(slash + 1);
    if (suffix.empty() ||
        suffix.find_first_not_of("0123456789") != std::string::npos) return entry;  // already a mask
    const int bits = std::atoi(suffix.c_str());
    const bool v6 = addr.find(':') != std::string::npos;
    const int width = v6 ? 128 : 32;
    if (bits < 0 || bits > width)
        throw Error(1, "name constraint " + entry + ": prefix length must be 0-" +
                       std::to_string(width));
    // Build the mask as raw bytes, then print it in the family's own literal form.
    std::vector<unsigned char> m(static_cast<size_t>(width) / 8, 0);
    for (int i = 0; i < bits; ++i) m[static_cast<size_t>(i) / 8] |= (0x80 >> (i % 8));
    std::string mask;
    if (v6) {
        char buf[8];
        for (size_t i = 0; i < m.size(); i += 2) {
            std::snprintf(buf, sizeof buf, "%x", (m[i] << 8) | m[i + 1]);
            if (!mask.empty()) mask += ":";
            mask += buf;
        }
    } else {
        for (size_t i = 0; i < m.size(); ++i) {
            if (!mask.empty()) mask += ".";
            mask += std::to_string(m[i]);
        }
    }
    return "IP:" + addr + "/" + mask;
}

void add_ext_text(X509V3_CTX& ctx, X509* cert, int nid, const std::string& val) {
    if (val.empty()) return;
    X509_EXTENSION* ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, val.c_str());
    if (!ex) throw Error(2, "X509V3_EXT_conf_nid failed for nid=" + std::to_string(nid) + ": " + openssl_errors());
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
}

// Add an arbitrary custom extension by dotted OID. `value` must be an
// OpenSSL "generic extension" spec ("DER:05:00", "ASN1:UTF8:text", …) — the only
// form that works for OIDs OpenSSL has no built-in method for (X509V3_EXT_nconf
// takes the generic path when the value starts with DER:/ASN1:, regardless of
// whether the OID resolves to a known NID). Empty value ⇒ DER NULL (05 00), the
// id-pkix-ocsp-nocheck form. Skips an OID already present so we never emit a
// duplicate extension (invalid per RFC 5280 §4.2).
void add_ext_oid(X509V3_CTX& ctx, X509* cert, const std::string& oid,
                 const std::string& value, bool critical) {
    if (oid.empty()) return;
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>
        obj(OBJ_txt2obj(oid.c_str(), 1), &ASN1_OBJECT_free);   // 1 = dotted only
    if (!obj) throw Error(1, "custom extension: bad OID '" + oid + "'");
    if (X509_get_ext_by_OBJ(cert, obj.get(), -1) >= 0) return;  // already present
    std::string spec = value.empty() ? "DER:05:00" : value;    // ASN.1 NULL default
    if (critical) spec = "critical," + spec;
    X509_EXTENSION* ex = X509V3_EXT_nconf(nullptr, &ctx, oid.c_str(), spec.c_str());
    if (!ex) throw Error(1, "custom extension '" + oid + "': " + openssl_errors());
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
}

std::string join(const std::vector<std::string>& v, std::string_view prefix, std::string_view sep) {
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += sep;
        out += prefix;
        out += v[i];
    }
    return out;
}

// Copy the SubjectAltName extension (if any) from a request extension stack
// onto the cert being built. Does not take ownership of `req_exts`.
// Copy the SubjectAltName from the request into the cert. RFC 5280 §4.2.1.6: if
// the certificate's subject is empty, the SAN MUST be marked critical.
void copy_san_from_exts(X509* cert, STACK_OF(X509_EXTENSION)* req_exts, bool make_critical) {
    if (!req_exts) return;
    int idx = X509v3_get_ext_by_NID(req_exts, NID_subject_alt_name, -1);
    if (idx < 0) return;
    X509_EXTENSION* san = X509v3_get_ext(req_exts, idx);
    if (!san) return;
    // Add a copy so we can set criticality without mutating the request's ext.
    X509_EXTENSION* copy = X509_EXTENSION_dup(san);
    if (!copy) return;
    X509_EXTENSION_set_critical(copy, make_critical ? 1 : 0);
    X509_add_ext(cert, copy, -1);
    X509_EXTENSION_free(copy);
}

// Add an RFC 4043 permanentIdentifier to the certificate's SubjectAltName, merged with what
// is there, keeping its criticality (or `make_critical` when there was none):
//
//   PermanentIdentifier ::= SEQUENCE { identifierValue UTF8String OPTIONAL,
//                                      assigner OBJECT IDENTIFIER OPTIONAL }
//
// Only identifierValue is written. Called for the serial number Apple attested, never for a
// value taken from a request.
void add_permanent_identifier_san(X509* cert, const std::string& value, bool make_critical) {
    if (value.empty() || value.size() > 100)
        throw Error(1, "an attested serial number of " + std::to_string(value.size()) +
                       " characters cannot be a permanentIdentifier");
    std::vector<unsigned char> der;   // SEQUENCE { UTF8String value } — short-form lengths
    der.push_back(0x30);
    der.push_back(static_cast<unsigned char>(value.size() + 2));
    der.push_back(0x0c);
    der.push_back(static_cast<unsigned char>(value.size()));
    der.insert(der.end(), value.begin(), value.end());

    GENERAL_NAMES* gens = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (!gens) gens = GENERAL_NAMES_new();
    ASN1_STRING* seq = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
    ASN1_TYPE* val = ASN1_TYPE_new();
    ASN1_OBJECT* oid = OBJ_txt2obj("1.3.6.1.5.5.7.8.3", 1);   // id-on-permanentIdentifier
    GENERAL_NAME* gn = GENERAL_NAME_new();
    bool ok = gens && seq && val && oid && gn &&
              ASN1_STRING_set(seq, der.data(), static_cast<int>(der.size())) == 1;
    if (ok) {
        ASN1_TYPE_set(val, V_ASN1_SEQUENCE, seq);   // val owns seq from here
        seq = nullptr;
        ok = GENERAL_NAME_set0_othername(gn, oid, val) == 1;   // gn owns oid and val
        if (ok) { oid = nullptr; val = nullptr; }
    }
    if (ok) {
        ok = sk_GENERAL_NAME_push(gens, gn) > 0;
        if (ok) gn = nullptr;
    }
    ASN1_STRING_free(seq);
    ASN1_TYPE_free(val);
    ASN1_OBJECT_free(oid);
    GENERAL_NAME_free(gn);
    if (!ok) {
        GENERAL_NAMES_free(gens);
        throw Error(2, "could not build the permanentIdentifier SAN: " + openssl_errors());
    }
    bool critical = make_critical;
    const int idx = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if (idx >= 0) {
        critical = X509_EXTENSION_get_critical(X509_get_ext(cert, idx)) != 0;
        X509_EXTENSION_free(X509_delete_ext(cert, idx));
    }
    const int added = X509_add1_ext_i2d(cert, NID_subject_alt_name, gens, critical ? 1 : 0,
                                        X509V3_ADD_DEFAULT);
    GENERAL_NAMES_free(gens);
    if (added != 1) throw Error(2, "could not add the SubjectAltName: " + openssl_errors());
}

// Copy specific request extensions verbatim (by dotted OID) onto the cert being
// built, preserving their value and criticality. Opt-in: only OIDs the caller
// names are copied, so it can't smuggle arbitrary CSR extensions. Used by
// MS-WSTEP to carry the Microsoft certificate-template extensions
// (szOID_ENROLL_CERTTYPE_EXTENSION 1.3.6.1.4.1.311.20.2 /
// szOID_CERTIFICATE_TEMPLATE 1.3.6.1.4.1.311.21.7) from a Windows client's CSR
// into the issued cert, so the cert keeps its template identity.
// Skips an OID already present on the cert. Does not take ownership of req_exts.
//
// `allow_any` is the profile's `allowed_custom_extensions` containing "*".
// It widens WHICH request extensions are eligible; it does not widen what they may
// overwrite. Every extension the CA decides for itself — basicConstraints (written
// `critical,CA:FALSE` above), keyUsage, extendedKeyUsage, subjectAltName — is already on
// `cert` by the time this runs, and the skip below leaves those alone. So "any" admits
// exactly the extensions the CA expresses no opinion about.
void copy_exts_by_oid(X509* cert, STACK_OF(X509_EXTENSION)* req_exts,
                      const std::vector<std::string>& oids, bool allow_any) {
    if (!req_exts || (oids.empty() && !allow_any)) return;
    char buf[128];
    for (int i = 0; i < X509v3_get_ext_count(req_exts); ++i) {
        X509_EXTENSION* ext = X509v3_get_ext(req_exts, i);
        if (!ext) continue;
        ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
        if (OBJ_obj2txt(buf, sizeof(buf), obj, 1) <= 0) continue;   // 1 = dotted only
        std::string dotted(buf);
        bool want = allow_any;
        if (!want) for (const auto& o : oids) if (o == dotted) { want = true; break; }
        if (!want) continue;
        // ⚠️ The SDA is the CA's statement about WHO OWNS this certificate, so a
        // request may never supply it. It cannot be protected the way basicConstraints,
        // keyUsage, extendedKeyUsage and subjectAltName are — those are already on `cert`
        // when this runs, and the "already present" test below skips them — because
        // add_subject_directory_attributes() writes the SDA ~55 lines AFTER this call.
        // So the skip could not see it, the CSR's copy was taken, and the CA then appended
        // a SECOND one: the issued certificate carried two, the requester's FIRST, which
        // is the one X509_get_ext_by_NID(..., -1) returns. Measured with a CSR naming
        // CN=mallory under the `admin` profile (allowed_custom_extensions = "*").
        //
        // Named explicitly rather than fixed by reordering: an ordering fix is silent if
        // the order ever changes again, and this says WHY the extension is not the
        // requester's to set.
        if (OBJ_obj2nid(obj) == NID_subject_directory_attributes) continue;
        // ⚠️ AIA AND THE CRL DP ARE THE SAME CASE, and were missed when the SDA was fixed.
        // Both are written AFTER this call (the ca_urls block ~5 lines below), so the
        // "already present" test cannot see them either — and the requester's copy is
        // therefore taken and lands FIRST, which is the one X509_get_ext_by_NID(..., -1)
        // returns. With a profile granting allowed_custom_extensions="*" a CSR could name
        // its own OCSP responder and its own CRL distribution point; add id-pkix-ocsp-nocheck
        // and the CA's real responder is not consulted at all. Where a certificate says to
        // check its revocation status is the CA's statement, never the requester's.
        if (OBJ_obj2nid(obj) == NID_info_access) continue;
        if (OBJ_obj2nid(obj) == NID_crl_distribution_points) continue;
        if (X509_get_ext_by_OBJ(cert, obj, -1) >= 0) continue;      // already present
        X509_EXTENSION* copy = X509_EXTENSION_dup(ext);
        if (!copy) continue;
        X509_add_ext(cert, copy, -1);
        X509_EXTENSION_free(copy);
    }
}

// True if the key can do RSA key transport — keyEncipherment / dataEncipherment, and the
// decryption a SCEP RA performs on the PKIOperation envelope.
//
// ⚠️ RSA-PSS does NOT qualify, and this used to say it did. An id-RSASSA-PSS key is
// signature-only by construction: OpenSSL refuses both directions, and it refuses at
// context-init so the CMS layer cannot even build the envelope —
//
//   $ openssl pkeyutl -encrypt -inkey pss.key ...
//   ossl_rsa_key_op_get_protect:operation not supported for this keytype ... operation: 512
//   $ openssl pkeyutl -decrypt -inkey pss.key ...
//   ossl_rsa_key_op_get_protect:operation not supported for this keytype ... operation: 1024
//
// (measured on 3.6.3; plain RSA succeeds on the same inputs). The console's own
// KEY_KU_VALID map already excluded rsa-pss from keyEncipherment, so the client and the
// server disagreed and the server was the wrong one — it would stamp keyEncipherment onto
// a certificate whose key can never perform it.
bool key_can_encipher(EVP_PKEY* pk) {
    if (!pk) return false;
    return EVP_PKEY_get_base_id(pk) == EVP_PKEY_RSA;
}

// Drop keyEncipherment / dataEncipherment from a KU list when the key can't do
// them (non-RSA). Returns the possibly-filtered comma list.
std::string key_usage_for_key(const std::string& ku, EVP_PKEY* pk) {
    if (key_can_encipher(pk)) return ku;
    std::string out;
    size_t i = 0;
    while (i < ku.size()) {
        size_t comma = ku.find(',', i);
        std::string tok = ku.substr(i, comma == std::string::npos ? comma : comma - i);
        // trim
        size_t a = tok.find_first_not_of(" \t"); size_t b = tok.find_last_not_of(" \t");
        std::string t = (a == std::string::npos) ? "" : tok.substr(a, b - a + 1);
        std::string tc = t; for (auto& c : tc) c = (char)std::tolower((unsigned char)c);
        if (tc != "keyencipherment" && tc != "dataencipherment" && !t.empty()) {
            if (!out.empty()) out += ", ";
            out += t;
        }
        if (comma == std::string::npos) break;
        i = comma + 1;
    }
    return out;
}

// certificatePolicies (RFC 5280 §4.2.1.4), built through the ASN.1 API.
//
// ⚠️ THE CONF-STRING PARSER CANNOT DO THIS AT ALL ON OUR CONTEXTS, and its refusal has
// nothing to do with the value. certificatePolicies is one of the few extensions OpenSSL
// exposes only through an `r2i` method, and `do_ext_nconf()` rejects EVERY r2i extension
// outright when the context carries no config database — before it ever parses what it
// was given. Every context here is `X509V3_set_ctx_nodb()`, so
// `X509V3_EXT_conf_nid(..., NID_certificate_policies, "1.3.6.1.4.1.99999.1")` answers
// `no config database` for a perfectly legal bare OID. That is what made CA creation
// return 500 whenever the console's "Certificate policy OIDs" field was filled in, and
// why the error text points at an `@section` feature nobody used. A bare OID needs no
// config section at all, so building the structure directly is both simpler and honest.
//
// A bad OID THROWS rather than being dropped: this is operator input from a form, and an
// extension that silently does not appear is the worst of the three outcomes.
void add_certificate_policies(X509* cert, const std::vector<std::string>& oids) {
    auto free_pols = [](CERTIFICATEPOLICIES* p) { sk_POLICYINFO_pop_free(p, POLICYINFO_free); };
    std::unique_ptr<CERTIFICATEPOLICIES, decltype(free_pols)>
        pols(sk_POLICYINFO_new_null(), free_pols);
    if (!pols) throw Error(2, "certificatePolicies: allocation failed");
    for (const auto& raw : oids) {
        // Trim: these arrive from a comma-separated form field, so "a, b" yields a
        // leading or trailing space that OBJ_txt2obj would reject as a malformed OID.
        size_t a = raw.find_first_not_of(" \t");
        if (a == std::string::npos) continue;
        std::string oid = raw.substr(a, raw.find_last_not_of(" \t") - a + 1);
        POLICYINFO* pi = POLICYINFO_new();
        if (!pi) throw Error(2, "certificatePolicies: allocation failed");
        ASN1_OBJECT_free(pi->policyid);
        pi->policyid = OBJ_txt2obj(oid.c_str(), 1);   // 1 = dotted numeric form only
        if (!pi->policyid) {
            POLICYINFO_free(pi);
            throw Error(1, "certificatePolicies: '" + oid + "' is not a dotted OID");
        }
        if (!sk_POLICYINFO_push(pols.get(), pi)) {
            POLICYINFO_free(pi);
            throw Error(2, "certificatePolicies: could not add policy");
        }
    }
    if (sk_POLICYINFO_num(pols.get()) == 0) return;
    if (!X509_add1_ext_i2d(cert, NID_certificate_policies, pols.get(), 0, 0))
        throw Error(2, "certificatePolicies: could not encode extension");
}

// First dNSName in the request's SAN ("" if none) — used to synthesize a CN when
// the CSR subject is empty (e.g. ACME/certbot).
std::string first_dns_san(STACK_OF(X509_EXTENSION)* req_exts) {
    if (!req_exts) return {};
    int idx = X509v3_get_ext_by_NID(req_exts, NID_subject_alt_name, -1);
    if (idx < 0) return {};
    X509_EXTENSION* ext = X509v3_get_ext(req_exts, idx);
    if (!ext) return {};
    auto* gens = static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(ext));
    if (!gens) return {};
    std::string out;
    for (int i = 0; i < sk_GENERAL_NAME_num(gens); ++i) {
        GENERAL_NAME* g = sk_GENERAL_NAME_value(gens, i);
        if (g && g->type == GEN_DNS) {
            const unsigned char* d = ASN1_STRING_get0_data(g->d.dNSName);
            out.assign(reinterpret_cast<const char*>(d), ASN1_STRING_length(g->d.dNSName));
            break;
        }
    }
    GENERAL_NAMES_free(gens);
    return out;
}

} // namespace

// The one writer of the process-wide data center facts read by set_random_serial().
// resolve_datacenter_prefix() (config.cpp) is its only caller; it is exported rather than
// inlined there so the fact lives beside the code that consumes it.
void set_datacenter_serial_prefix(const std::string& dc_id, int prefix) {
    if (prefix != 0 && (prefix < 1 || prefix > 32767))
        throw Error(1, "data center serial prefix out of range (1..32767): " +
                       std::to_string(prefix));
    std::lock_guard<std::mutex> lk(g_dc_mu);
    g_dc_id     = dc_id;
    g_dc_prefix = dc_id.empty() ? 0 : prefix;
}

// The SAME fact, read by insert_cert for certs.ins_seq. It is exported rather than
// duplicated so the serial and the insertion-ordering key cannot disagree about which
// data center minted a row — they are two encodings of one number.
//
// 0 means "no data center configured" (single-node), which is a legitimate answer: ins_seq
// then lives in prefix-space 0, which no DC is allowed to occupy (serial_prefix is
// 1..32767), so a single-node value can never collide with a mesh node's.
int datacenter_serial_prefix() {
    std::lock_guard<std::mutex> lk(g_dc_mu);
    return g_dc_prefix;
}

// Defined below (after build_name): the Subject Directory Attributes.
static void add_subject_directory_attributes(X509* cert, const std::string& owner_username);

// Will the certificate about to be built carry id-pkix-ocsp-nocheck?
//
// Two routes put it there and both must be seen, or the answer is right half the time:
// the PROFILE's custom_extensions, and a request's own custom_exts, which reach here
// as an extension in `req_exts` that is only copied out if its OID is also named in
// `passthrough_ext_oids` — being in the stack is not enough (see the comment at the end of
// build_leaf_exts).
//
// Compare by NID, not by string. The two writers in this tree spell it "1.3.6.1.5.5.7.48.1.5",
// but a profile's custom_extensions come from operator-authored JSON, and OpenSSL accepts a
// short name there just as happily.
// ⚠️ `allow_any` must be threaded through here too, not only into the copy. A
// profile carrying "*" in allowed_custom_extensions WILL carry a request's nocheck onto
// the certificate, and this function decides whether AIA/CRLDP are then suppressed. Miss
// it and the wildcard issues certificates asserting both "do not check revocation" and
// "check it, here" — the exact contradiction this exists to prevent.
static bool carries_ocsp_nocheck(STACK_OF(X509_EXTENSION)* req_exts,
                                 const std::vector<std::string>& passthrough_ext_oids,
                                 bool allow_any,
                                 const CertProfile& profile) {
    for (const auto& x : profile.custom_extensions)
        if (OBJ_txt2nid(x.oid.c_str()) == NID_id_pkix_OCSP_noCheck) return true;
    if (!req_exts || X509v3_get_ext_by_NID(req_exts, NID_id_pkix_OCSP_noCheck, -1) < 0)
        return false;
    if (allow_any) return true;
    for (const auto& oid : passthrough_ext_oids)
        if (OBJ_txt2nid(oid.c_str()) == NID_id_pkix_OCSP_noCheck) return true;
    return false;
}

// Forward — defined later in this file; used here via issue_cert_from_parts.
static EvpPkeyPtr rsa_pss_restricted_public(EVP_PKEY* key, const EVP_MD* md,
                                             const std::string& known_key_algo = "");

X509Ptr issue_cert_from_parts(const Config& cfg, X509* ca_cert, EVP_PKEY* ca_key,
                              X509_NAME* subject, EVP_PKEY* subject_pubkey,
                              STACK_OF(X509_EXTENSION)* req_exts,
                              const std::string& role, bool acme,
                              const std::string& owner_username,
                              const std::vector<std::string>& passthrough_ext_oids,
                              const CaUrls* ca_urls,
                              bool omit_aia, bool omit_crldp,
                              const CertProfile* profile_override,
                              const std::string& requested_md,
                              const std::string& attested_serial) {
    // Resolve the cert policy profile for this role:
    // it governs the domain/wildcard + SAN-type checks and the KU/EKU the cert
    // may carry. Enforce the CA issuance policy before building anything.
    //
    // Unless the caller brought its own. A device renewing its own certificate is
    // judged against THAT certificate, not against a stored profile — there is no stored
    // profile that describes one device without being either too broad or invented per
    // device, which is exactly the reason all three alternatives were rejected.
    const CertProfile& profile =
        profile_override ? *profile_override : resolve_cert_profile(cfg, role);
    enforce_issuance_policy(cfg, subject, subject_pubkey, req_exts, profile, acme);

    // KU/EKU honored from the CSR within the profile's allow-list (or the
    // profile defaults); throws if the CSR requests something not permitted.
    const ProfileExtensions prof_exts = evaluate_profile_extensions(profile, req_exts);

    // Which CSR-supplied custom extensions survive. The profile's
    // `allowed_custom_extensions` is ADDITIVE to whatever the calling protocol needs for
    // its own sake — MS-WSTEP names the two Microsoft certificate-template OIDs because a
    // Windows client's certificate is not recognisable without them, which is a protocol
    // fact rather than a policy the operator chose. Before this, the profile had no say at
    // all and msxcep was the ONLY caller that named anything, so no CSR-supplied custom
    // extension reached an issued certificate on EST, ACME, CMP, SCEP or the console.
    std::vector<std::string> pass_oids = passthrough_ext_oids;
    bool pass_any = false;
    for (const auto& o : profile.allowed_custom_extensions) {
        if (o == "*") { pass_any = true; continue; }
        pass_oids.push_back(o);
    }

    X509Ptr cert{X509_new()};
    if (!cert) throw Error(2, "X509_new failed");

    if (!X509_set_version(cert.get(), 2))   // v3
        throw Error(2, "X509_set_version failed");

    set_random_serial(cert.get(), cfg.cert_serial_bytes);

    if (!subject) throw Error(1, "issuance: missing subject");
    // Empty-subject CSRs (ACME/certbot): synthesize a CN from the first DNS SAN so
    // the cert has a usable identity. If none is available the subject stays
    // empty and the SAN is marked critical below (RFC 5280 §4.2.1.6).
    bool subject_empty = (X509_NAME_entry_count(subject) == 0);
    if (subject_empty) {
        std::string dns = first_dns_san(req_exts);
        if (!dns.empty()) {
            if (X509_NAME_add_entry_by_NID(subject, NID_commonName, MBSTRING_UTF8,
                    reinterpret_cast<const unsigned char*>(dns.c_str()), -1, -1, 0))
                subject_empty = false;
        }
    }
    if (!X509_set_subject_name(cert.get(), subject))
        throw Error(2, "X509_set_subject_name failed: " + openssl_errors());
    if (!X509_set_issuer_name(cert.get(), X509_get_subject_name(ca_cert)))
        throw Error(2, "X509_set_issuer_name failed: " + openssl_errors());

    if (!subject_pubkey) throw Error(1, "issuance: missing public key");
    // RFC 4055 §3.1 — a PSS-restricted key published as rsaEncryption
    // tells a relying party it can verify with PKCS#1 v1.5, which the token
    // refuses.  The CA builders already apply this; the leaf path did not.
    if (EvpPkeyPtr restricted = rsa_pss_restricted_public(subject_pubkey, nullptr)) {
        if (!X509_set_pubkey(cert.get(), restricted.get()))
            throw Error(2, "X509_set_pubkey(RSA-PSS) failed: " + openssl_errors());
    } else if (!X509_set_pubkey(cert.get(), subject_pubkey)) {
        throw Error(2, "X509_set_pubkey failed: " + openssl_errors());
    }

    if (!X509_gmtime_adj(X509_getm_notBefore(cert.get()), -kClockSkewBackdateSec))
        throw Error(2, "notBefore adj failed");
    // Validity = the profile's STATED validity where it has one (an MS template says what
    // the CA will issue, so it is honoured rather than bounded), else the cfg default.
    // max_validity_days still only ever shortens, which is what a cap means.
    int validity_days = profile.validity_days > 0 ? profile.validity_days
                                                  : cfg.cert_validity_days;
    if (profile.max_validity_days > 0 && profile.max_validity_days < validity_days)
        validity_days = profile.max_validity_days;
    if (!X509_gmtime_adj(X509_getm_notAfter(cert.get()),
                         60L * 60 * 24 * validity_days))
        throw Error(2, "notAfter adj failed");
    // ⚠️ A LEAF MAY NOT OUTLIVE THE CERTIFICATE THAT SIGNS IT. Nothing checked this on the
    // leaf path — only the CA re-key path clamped — so an issuing CA in its last year would
    // hand out certificates running years past its own expiry. They look valid on their
    // face and cannot be chained by anybody, because the only path to them runs through an
    // expired certificate. The failure surfaces later, somewhere else, as an unexplained
    // trust error on a certificate that reads as current.
    //
    // Clamped rather than refused, for the same reason the CA path clamps: refusing would
    // make ordinary issuance fail outright for every CA inside its last validity period,
    // which is a working PKI stopping dead over something a shorter certificate satisfies.
    // Announced, because a validity that is not what was asked for must never be silent.
    if (ca_cert &&
        ASN1_TIME_compare(X509_get0_notAfter(cert.get()), X509_get0_notAfter(ca_cert)) == 1) {
        if (!X509_set1_notAfter(cert.get(), X509_get0_notAfter(ca_cert)))
            throw Error(2, "could not clamp the leaf notAfter to the issuer's: " +
                           openssl_errors());
        log::info("issuance: requested validity ran past the issuing CA's own notAfter — "
                  "clamped to it, since no relying party could chain past that date");
    }

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert, cert.get(), nullptr, nullptr, 0);

    // KU/EKU come from the cert policy profile: the
    // CSR's requested bits honored within the profile's allow-list, else the
    // profile defaults. evaluate_profile_extensions() already vetted them.
    add_ext_text(ctx, cert.get(), NID_basic_constraints,     "critical,CA:FALSE");
    // KeyUsage must match the key type: keyEncipherment/dataEncipherment are only
    // valid for RSA. Strip them for EC/EdDSA keys so we never emit an illegal KU
    // (certbot defaults to EC).
    const std::string ku = key_usage_for_key(prof_exts.key_usage, subject_pubkey);
    if (!ku.empty())
        add_ext_text(ctx, cert.get(), NID_key_usage,         ku);
    if (!prof_exts.ext_key_usage.empty())
        add_ext_text(ctx, cert.get(), NID_ext_key_usage,     prof_exts.ext_key_usage);
    add_ext_text(ctx, cert.get(), NID_subject_key_identifier, "hash");
    add_ext_text(ctx, cert.get(), NID_authority_key_identifier, "keyid:always");

    // ACME certs are domain-validated: assert the CA/Browser Forum DV policy OID
    // (2.23.140.1.2.1) so relying parties can see the validation level.
    if (acme)
        add_certificate_policies(cert.get(), {"2.23.140.1.2.1"});

    // SAN critical iff the subject is empty (RFC 5280 §4.2.1.6).
    copy_san_from_exts(cert.get(), req_exts, /*make_critical=*/subject_empty);
    // The serial Apple attested, when the profile asks for it (device_serial_san). Added by
    // the CA after the policy check, so it is never subject to what a requester may name.
    if (!attested_serial.empty() && profile.device_serial_san)
        add_permanent_identifier_san(cert.get(), attested_serial, subject_empty);

    // Carry named request extensions verbatim: MS-WSTEP passes the
    // Microsoft certificate-template OIDs so a Windows-issued cert keeps its
    // template identity. Empty for every other caller → no change.
    copy_exts_by_oid(cert.get(), req_exts, pass_oids, pass_any);

    // AIA (caIssuers + OCSP) and CRL DP. When the caller supplies per-CA URLs
    // (derive_ca_urls(): per-tenant host + first-CA-base/subsequent-{ca_id}), bake
    // those; otherwise fall back to the global cfg.aia_*/crl_distribution_points.
    {
        std::string aia;
        std::string crldp;
        if (ca_urls) {
            // Every entry, not the first: the point of the list is that a relying party
            // unable to reach one data center has another to try.
            for (const auto& v : ca_urls->ca_issuers) {
                if (!aia.empty()) aia += ",";
                aia += "caIssuers;URI:" + v;
            }
            for (const auto& v : ca_urls->ocsp) {
                if (!aia.empty()) aia += ",";
                aia += "OCSP;URI:" + v;
            }
            if (!ca_urls->crl.empty()) crldp = join(ca_urls->crl, "URI:", ",");
        } else {
            for (const auto& u : cfg.aia_ca_issuers) { if (!aia.empty()) aia += ","; aia += "caIssuers;URI:" + u; }
            for (const auto& u : cfg.aia_ocsp)       { if (!aia.empty()) aia += ","; aia += "OCSP;URI:" + u; }
            if (!cfg.crl_distribution_points.empty()) crldp = join(cfg.crl_distribution_points, "URI:", ",");
        }
        // AIA / CRL DP are suppressed only when the profile DELEGATES the
        // choice (manage_*) and this request MAKES it (r.omit_*). Either alone emits the
        // extension: a profile that permits omission does not omit by itself, and a
        // request cannot omit under a profile that does not allow it.
        // The case this exists for is an authorized OCSP responder, which carries neither
        // (RFC 6960 §4.2.2.2.1) — while the same profile still issues ordinary certs.
        // …and unconditionally when the certificate carries id-pkix-ocsp-nocheck.
        // That extension (RFC 6960 §4.2.2.2.1) says "do not check this certificate's
        // revocation status"; AIA(OCSP) and CRL DP say "check it, here". Emitting both puts
        // two opposite instructions in one certificate, and `fastpki-ocsp` logs an ERR for
        // each on EVERY request it answers because its own responder credential had them.
        //
        // NOT routed through manage_aia/omit_aia like the case above. Those express an
        // operator's *preference*, and the two decisions were being made in different
        // places that knew nothing about each other: the responder profile adds nocheck
        // while derive_ca_urls()/ca_urls_for_instance() add AIA and CRLDP from the issuing
        // CA. This is not a preference — the combination is never correct — so it is
        // decided here, where both facts are in scope.
        const bool nocheck = carries_ocsp_nocheck(req_exts, pass_oids, pass_any, profile);
        const bool drop_aia   = nocheck || (profile.manage_aia   && omit_aia);
        const bool drop_crldp = nocheck || (profile.manage_crldp && omit_crldp);
        if (!drop_aia && !aia.empty())
            add_ext_text(ctx, cert.get(), NID_info_access, aia);
        if (!drop_crldp && !crldp.empty())
            add_ext_text(ctx, cert.get(), NID_crl_distribution_points, crldp);
    }

    // Arbitrary custom extensions declared by the profile (e.g.
    // id-pkix-ocsp-nocheck on an OCSP-responder cert). Applied after the standard
    // extensions; a duplicate OID is skipped inside add_ext_oid.
    for (const auto& x : profile.custom_extensions)
        add_ext_oid(ctx, cert.get(), x.oid, x.value, x.critical);

    // Carry the authenticated identity in a Subject Directory Attributes
    // extension (RFC 5280 §4.2.1.8) — added before signing so it's
    // covered by the signature. OWNER ONLY.
    //
    // X509 certificates are about authentication, not authorization. In the PKI
    // model authorization lives externally, not inside the certificate, so any code that
    // writes or reads roles to or from the subject DN or the SDA has to go. Roles belong
    // to RBAC — assigned to users, groups and DNs, never to certificates. So id-at-role
    // (2.5.4.72) is gone, and the profile's org_role that fed it with it. `owner` stays:
    // it says WHOSE certificate this is — identity, not permission — and was never in
    // scope for removal.
    add_subject_directory_attributes(cert.get(), owner_username);

    // ⚠️ A CERTIFICATE HAS TO NAME SOMEBODY, AND THIS IS THE LAST POINT THAT CAN TELL.
    //
    // A template may grant CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT — the built-in GenericUser
    // does, via subject_name_flags 0x9 — which means the CA honours whatever subject the
    // request carries. `certreq -q -enroll <template>` builds its request from the template
    // alone and carries NO subject, so "whatever the request carries" is nothing, and a
    // certificate came out with an empty subject and no subjectAltName. It identified
    // nobody, and it was issued silently: the request, the response and the log all read as
    // an ordinary success.
    //
    // RFC 5280 §4.1.2.6 allows an empty subject ONLY when the identity is carried in a
    // critical subjectAltName. With neither there is no identity in any form, relying
    // parties disagree on whether the thing is even usable, and a real Windows CA refuses
    // such a request rather than issuing it.
    //
    // Refused rather than repaired: substituting a name here would invent an identity the
    // requester did not ask for and the template did not authorise. The empty-subject case
    // that IS legitimate — identity in the SAN — passes this check untouched, which is why
    // the test is "neither", not "no subject".
    if (X509_NAME_entry_count(X509_get_subject_name(cert.get())) == 0 &&
        X509_get_ext_by_NID(cert.get(), NID_subject_alt_name, -1) < 0)
        throw Error(1, "issuance: refusing to sign a certificate with an empty subject and "
                       "no subjectAltName — it would identify nobody. The template grants "
                       "enrollee-supplies-subject and the request named nothing; send a "
                       "subject or a subjectAltName, or use a template where the CA builds "
                       "the name.");

    // Detect RSA-PSS CA keys. OpenSSL 3.x's X509_sign handles RSA-PSS keys
    // correctly: it uses PSS padding (MGF1-SHA-256) and encodes id-RSASSA-PSS
    // in the signatureAlgorithm. The salt length follows the key's defaults (20).
    // For all other key types (RSA/EC/EdDSA/PQC), X509_sign uses the key's
    // native signing scheme (PKCS#1 v1.5 for RSA, ECDSA for EC, etc.).
    cert.reset(sign_x509(cert.release(), ca_key,
                         leaf_signing_md(ca_key, ca_cert, requested_md,
                                         cfg.allow_weak_signature_digest)));

    return cert;
}

// Helper to check if an extension NID already exists in the stack
/*bool has_extension(STACK_OF(X509_EXTENSION)* exts, int nid) {
    if (!exts) return false;
    return X509v3_get_ext_by_NID(exts, nid, -1) >= 0;
}

// Helper to add an extension if it's missing
void add_ext_if_missing(STACK_OF(X509_EXTENSION)*& exts, X509V3_CTX* ctx, int nid, const char* value) {
    if (has_extension(exts, nid)) {
        return; // Already present, don't overwrite
    }

    // Create the extension from the string value
    X509_EXTENSION* ext = X509V3_EXT_nconf(nullptr, ctx, OBJ_nid2sn(nid), const_cast<char*>(value));
    if (!ext) {
        throw std::runtime_error("Failed to create extension: " + std::string(OBJ_nid2sn(nid)));
    }

    // If the stack doesn't exist yet, allocate it
    if (!exts) {
        exts = sk_X509_EXTENSION_new_null();
        if (!exts) {
            X509_EXTENSION_free(ext);
            throw std::bad_alloc();
        }
    }

    // Push to stack
    if (!sk_X509_EXTENSION_push(exts, ext)) {
        X509_EXTENSION_free(ext);
        throw std::bad_alloc();
    }
}*/

X509Ptr issue_cert(const IssuanceInput& in) {
    STACK_OF(X509_EXTENSION)* req_exts = X509_REQ_get_extensions(in.csr);
    
    try {
        X509_NAME* subject = X509_REQ_get_subject_name(in.csr);

        // If you need to avoid mutating the original CSR:
        //X509_NAME* original_subject = X509_REQ_get_subject_name(in.csr);
        //X509_NAME* subject = X509_NAME_dup(original_subject); // Creates a safe copy

        // Context-aware identity mapping. Bind the subject to
        // the authenticated identity instead of trusting the CSR: replace the CN
        // with the caller's identity (Username → CN) and stamp their groups as OUs
        // (Group → OU). Only set by the self-service console path for non-admins.
        // A caller that may not choose the name asks for the REQUESTED one to be discarded
        // outright, not merely overwritten. Dropping only the commonName would leave any
        // other RDN the request carried — `emailAddress` above all — naming whoever the
        // requester liked, and leave the requested subjectAltName untouched, which is the
        // half that actually impersonates in a client-auth certificate.
        if (in.replace_subject) {
            while (X509_NAME_entry_count(subject) > 0)
                X509_NAME_ENTRY_free(X509_NAME_delete_entry(subject, 0));
            // req_exts is OUR stack (X509_REQ_get_extensions returns a copy we free below),
            // so removing the SAN here cannot disturb the request itself.
            if (req_exts) {
                for (int i = X509v3_get_ext_by_NID(req_exts, NID_subject_alt_name, -1);
                     i >= 0;
                     i = X509v3_get_ext_by_NID(req_exts, NID_subject_alt_name, -1))
                    X509_EXTENSION_free(sk_X509_EXTENSION_delete(req_exts, i));
            }
        }
        if (!in.subject_cn.empty()) {
            for (int i = X509_NAME_entry_count(subject) - 1; i >= 0; --i) {
                X509_NAME_ENTRY* e = X509_NAME_get_entry(subject, i);
                if (OBJ_obj2nid(X509_NAME_ENTRY_get_object(e)) == NID_commonName)
                    X509_NAME_ENTRY_free(X509_NAME_delete_entry(subject, i));
            }
            if (!X509_NAME_add_entry_by_NID(subject, NID_commonName, MBSTRING_UTF8,
                    reinterpret_cast<const unsigned char*>(in.subject_cn.c_str()), -1, -1, 0))
                throw std::runtime_error("Failed to set identity CN on Subject DN");
        }
        for (const auto& ou : in.org_units) {
            if (ou.empty()) continue;
            if (!X509_NAME_add_entry_by_NID(subject, NID_organizationalUnitName, MBSTRING_UTF8,
                    reinterpret_cast<const unsigned char*>(ou.c_str()), -1, -1, 0))
                throw std::runtime_error("Failed to add OU to Subject DN");
        }
        // The authority that asserted this identity, kept out of the commonName so the CN
        // stays a person's name. Added after the OUs so the DN reads name-then-authority.
        if (!in.subject_domain.empty()) {
            if (!X509_NAME_add_entry_by_NID(subject, NID_domainComponent, MBSTRING_UTF8,
                    reinterpret_cast<const unsigned char*>(in.subject_domain.c_str()), -1, -1, 0))
                throw std::runtime_error("Failed to add provider DC to Subject DN");
        }

        // Note: If you use X509_NAME_dup, make sure to call X509_NAME_free(subject)
        // in your cleanup/catch block so you don't leak memory.

        EVP_PKEY* pubkey  = X509_REQ_get0_pubkey(in.csr);

        // Policy profile. Callers resolve it up front with pki::resolve_profile() and
        // pass the result in `in.profile_override` — a merged profile has no name to look
        // up — with `in.profile` as its label. A profile looked up by name here is the
        // service-credential path's; an empty one defensively falls back to the built-in
        // default.
        const std::string profile_name = in.profile.empty() ? kDefaultProfile : in.profile;
        // Forward profile + acme so enforce_issuance_policy() applies the correct
        // rules and ACME's own DV bypasses the domains.txt allowlist. (Must pass
        // in.acme, not a hardcoded false, or ACME orders fail the allowlist.)
        // owner rides in a Subject Directory Attributes extension built inside
        // from_parts (before signing). Owner is all it carries — no role.
        auto cert = issue_cert_from_parts(in.cfg, in.ca_cert, in.ca_key, subject,
                                          pubkey, req_exts, profile_name, in.acme,
                                          in.owner_username,
                                          in.passthrough_ext_oids, in.ca_urls,
                                          in.omit_aia, in.omit_crldp,
                                          in.profile_override, in.requested_md,
                                          in.attested_serial);

        if (req_exts) sk_X509_EXTENSION_pop_free(req_exts, X509_EXTENSION_free);
        return cert;

    } catch (...) {
        if (req_exts) sk_X509_EXTENSION_pop_free(req_exts, X509_EXTENSION_free);
        throw;
    }
}

// ---- Helpers ---------------------------------------------------------------

std::vector<unsigned char> x509_to_der(X509* x) {
    int len = i2d_X509(x, nullptr);
    if (len <= 0) throw Error(2, "i2d_X509 size failed: " + openssl_errors());
    std::vector<unsigned char> out(static_cast<size_t>(len));
    unsigned char* p = out.data();
    if (i2d_X509(x, &p) != len)
        throw Error(2, "i2d_X509 encode failed: " + openssl_errors());
    return out;
}

namespace {
std::string x509_digest_hex(X509* x, const EVP_MD* md_alg, const char* what) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    if (!X509_digest(x, md_alg, md, &n))
        throw Error(2, std::string("X509_digest(") + what + ") failed: " + openssl_errors());
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < n; ++i) os << std::setw(2) << static_cast<int>(md[i]);
    return os.str();
}
}  // namespace

std::string x509_fingerprint_sha256_hex(X509* x) {
    return x509_digest_hex(x, EVP_sha256(), "sha256");
}

// See the contract in x509.hpp: self-ISSUED is a statement about NAMES, self-SIGNED is
// a statement about the SIGNATURE, and only the second one means "root".
bool x509_is_self_issued(X509* x) {
    if (!x) return false;
    return X509_NAME_cmp(X509_get_subject_name(x), X509_get_issuer_name(x)) == 0;
}

bool x509_is_self_signed(X509* x) {
    if (!x) return false;
    // The name relation is a necessary condition and a cheap early out: a certificate whose
    // issuer names somebody else is not self-signed, and this skips a public-key operation
    // for every ordinary leaf and intermediate.
    if (!x509_is_self_issued(x)) return false;
    EVP_PKEY* pub = X509_get0_pubkey(x);   // borrowed, not freed
    if (!pub) { ERR_clear_error(); return false; }
    const bool ok = X509_verify(x, pub) == 1;
    // A failed verification leaves its reason on the error queue. Left there it surfaces on
    // the NEXT unrelated OpenSSL call — and for a re-keyed CA this fails on every page load,
    // so it would be a steady drip rather than a one-off.
    if (!ok) ERR_clear_error();
    return ok;
}
// ⚠️ WHY NOT X509_self_signed(), WHICH IS THE HOUSE IDIOM ELSEWHERE. Both of its modes are
// gated on EXFLAG_SS, which OpenSSL sets from subject == issuer PLUS two heuristics: the AKID
// matches the SKID, and the signature algorithm matches the public-key algorithm. That gate
// is wrong in both directions, and it was measured rather than reasoned about:
//   * with verify_signature = 0 it FAILS OPEN — X509_check_akid() returns X509_V_OK for an
//     ABSENT AKID, so a self-issued re-key carrying no AKID is reported self-signed;
//   * with verify_signature = 1 it FAILS CLOSED — a genuine self-signed root whose AKID does
//     not match its own SKID never reaches the verification and is reported not-self-signed.
// FastPKI's own issuance always emits `keyid:always`, so certificates WE mint dodge the first
// case; an imported or cross-signed foreign CA does not, and those arrive through
// `fastpki-ca add --ca-pem` and the console's import path. Asking the signature directly has
// neither failure mode.

// SHA-1 as well, because that is the one an operator is usually comparing
// AGAINST. Windows' certificate UI, `certutil`, and most browsers still label the SHA-1
// digest "Thumbprint", so a console that offers only SHA-256 leaves the commonest
// comparison to be done by hand.
//
// It is a FINGERPRINT, never a signature: the digest is over the DER of a certificate
// that is already signed, so SHA-1's collision weakness does not apply the way it does
// to signing. Nothing in FastPKI authenticates on this value.
std::string x509_fingerprint_sha1_hex(X509* x) {
    return x509_digest_hex(x, EVP_sha1(), "sha1");
}

namespace {
// SHA-1 of a byte range as lowercase hex — mirrors fastpki-store's sha1_hex so
// the stored selector hashes compare equal to a client's query value.
std::string sha1_lc_hex(const unsigned char* d, size_t n) {
    unsigned char md[SHA_DIGEST_LENGTH];
    SHA1(d, n, md);
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (unsigned char c : md) os << std::setw(2) << static_cast<int>(c);
    return os.str();
}
} // namespace

CertStoreHashes x509_store_hashes(X509* x) {
    CertStoreHashes h;
    if (!x) return h;

    // sHash — SHA-1 of the DER-encoded subject Name.
    if (X509_NAME* subj = X509_get_subject_name(x)) {
        unsigned char* der = nullptr;
        int len = i2d_X509_NAME(subj, &der);
        if (len > 0 && der) h.s_hash = sha1_lc_hex(der, static_cast<size_t>(len));
        OPENSSL_free(der);
    }

    // iHash — SHA-1 of the DER-encoded issuer Name (RFC 4387 §2.2).
    if (X509_NAME* iss = X509_get_issuer_name(x)) {
        unsigned char* der = nullptr;
        int len = i2d_X509_NAME(iss, &der);
        if (len > 0 && der) h.i_hash = sha1_lc_hex(der, static_cast<size_t>(len));
        OPENSSL_free(der);
    }

    // iAndSHash — SHA-1 of the DER-encoded IssuerAndSerialNumber (RFC 5652).
    if (PKCS7_ISSUER_AND_SERIAL* ias = PKCS7_ISSUER_AND_SERIAL_new()) {
        // X509_NAME_set / ASN1_STRING copies duplicate into the fresh struct, so
        // freeing `ias` below does not touch the cert's own fields.
        if (X509_NAME_set(&ias->issuer, X509_get_issuer_name(x))) {
            ASN1_INTEGER_free(ias->serial);
            ias->serial = ASN1_INTEGER_dup(X509_get0_serialNumber(x));
            if (ias->serial) {
                unsigned char* der = nullptr;
                int len = i2d_PKCS7_ISSUER_AND_SERIAL(ias, &der);
                if (len > 0 && der) h.i_and_s_hash = sha1_lc_hex(der, static_cast<size_t>(len));
                OPENSSL_free(der);
            }
        }
        PKCS7_ISSUER_AND_SERIAL_free(ias);
    }

    // sKIDHash — SHA-1 of the subjectKeyIdentifier value (empty if absent).
    if (const ASN1_OCTET_STRING* skid = X509_get0_subject_key_id(x))
        h.skid_hash = sha1_lc_hex(ASN1_STRING_get0_data(skid),
                                  static_cast<size_t>(ASN1_STRING_length(skid)));

    return h;
}

std::string x509_text(X509* x) {
    // The full human-readable dump — the same content as `openssl x509 -text`,
    // so the console can show every attribute/extension without sending the user
    // to the command line. RFC 2253 name formatting; cflag 0
    // prints the whole certificate including all extensions.
    if (!x) return {};
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
    if (!bio) return {};
    if (!X509_print_ex(bio.get(), x, XN_FLAG_RFC2253, 0)) return {};
    char* data = nullptr;
    long n = BIO_get_mem_data(bio.get(), &data);
    return (data && n > 0) ? std::string(data, static_cast<size_t>(n)) : std::string();
}

std::vector<std::string> x509_san_uris(X509* x) {
    // The uniformResourceIdentifier GeneralNames in the SubjectAltName — the set
    // a client can match with the RFC 4387 §2 `uri` selector. A cert
    // may carry several; each is stored verbatim (URIs are case-sensitive).
    std::vector<std::string> out;
    if (!x) return out;
    auto* gens = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(x, NID_subject_alt_name, nullptr, nullptr));
    if (!gens) return out;
    for (int i = 0; i < sk_GENERAL_NAME_num(gens); ++i) {
        GENERAL_NAME* g = sk_GENERAL_NAME_value(gens, i);
        if (g && g->type == GEN_URI) {
            const unsigned char* d = ASN1_STRING_get0_data(g->d.uniformResourceIdentifier);
            int n = ASN1_STRING_length(g->d.uniformResourceIdentifier);
            if (d && n > 0) out.emplace_back(reinterpret_cast<const char*>(d),
                                             static_cast<size_t>(n));
        }
    }
    GENERAL_NAMES_free(gens);
    return out;
}

// ── what a certificate actually carries ───────────────────────────────────────
//
// Read back rather than derived. ca_urls_for_instance() answers "what would be minted
// now"; these answer "what is in this certificate", and after PKI_DNS or BASE_URL is
// corrected the two disagree for everything minted under the old value. A certificate
// cannot be told a new URL, so the difference is the repair list.

static std::vector<std::string> aia_urls_for(X509* x, int nid_method) {
    std::vector<std::string> out;
    if (!x) return out;
    auto* aia = static_cast<AUTHORITY_INFO_ACCESS*>(
        X509_get_ext_d2i(x, NID_info_access, nullptr, nullptr));
    if (!aia) return out;
    for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); ++i) {
        ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia, i);
        if (!ad || OBJ_obj2nid(ad->method) != nid_method) continue;
        if (!ad->location || ad->location->type != GEN_URI) continue;
        const unsigned char* d =
            ASN1_STRING_get0_data(ad->location->d.uniformResourceIdentifier);
        int n = ASN1_STRING_length(ad->location->d.uniformResourceIdentifier);
        if (d && n > 0) out.emplace_back(reinterpret_cast<const char*>(d),
                                         static_cast<size_t>(n));
    }
    AUTHORITY_INFO_ACCESS_free(aia);
    return out;
}

std::vector<std::string> x509_aia_ca_issuers(X509* x) {
    return aia_urls_for(x, NID_ad_ca_issuers);
}

std::vector<std::string> x509_aia_ocsp(X509* x) {
    return aia_urls_for(x, NID_ad_OCSP);
}

std::vector<std::string> x509_crl_urls(X509* x) {
    // Only the fullName URIs. A CRLDP may also carry a relative name or a CRL issuer;
    // FastPKI issues neither, and a certificate from elsewhere that does is reported as
    // having no URL here rather than as having a URL we cannot check.
    std::vector<std::string> out;
    if (!x) return out;
    auto* dps = static_cast<CRL_DIST_POINTS*>(
        X509_get_ext_d2i(x, NID_crl_distribution_points, nullptr, nullptr));
    if (!dps) return out;
    for (int i = 0; i < sk_DIST_POINT_num(dps); ++i) {
        DIST_POINT* dp = sk_DIST_POINT_value(dps, i);
        if (!dp || !dp->distpoint || dp->distpoint->type != 0) continue;
        GENERAL_NAMES* names = dp->distpoint->name.fullname;
        for (int j = 0; j < sk_GENERAL_NAME_num(names); ++j) {
            GENERAL_NAME* g = sk_GENERAL_NAME_value(names, j);
            if (!g || g->type != GEN_URI) continue;
            const unsigned char* d =
                ASN1_STRING_get0_data(g->d.uniformResourceIdentifier);
            int n = ASN1_STRING_length(g->d.uniformResourceIdentifier);
            if (d && n > 0) out.emplace_back(reinterpret_cast<const char*>(d),
                                             static_cast<size_t>(n));
        }
    }
    CRL_DIST_POINTS_free(dps);
    return out;
}

std::string x509_cn(X509* x) {
    X509_NAME* n = X509_get_subject_name(x);
    if (!n) return {};
    int idx = X509_NAME_get_index_by_NID(n, NID_commonName, -1);
    if (idx < 0) return {};
    X509_NAME_ENTRY* e = X509_NAME_get_entry(n, idx);
    if (!e) return {};
    ASN1_STRING* s = X509_NAME_ENTRY_get_data(e);
    if (!s) return {};
    unsigned char* utf8 = nullptr;
    int len = ASN1_STRING_to_UTF8(&utf8, s);
    if (len < 0 || !utf8) return {};
    std::string out(reinterpret_cast<char*>(utf8), static_cast<size_t>(len));
    OPENSSL_free(utf8);
    return out;
}

// 1. Define a clean deleter struct
struct OpenSSLDeleter {
    void operator()(void* ptr) const {
        OPENSSL_free(ptr);
    }
};

// A CA's certificate from CaInstance::signing_ca_pem.
//
// That field is now ALWAYS the certificate itself — db_postgres builds it by PEM-wrapping
// the DER stored on the CA's own `certs` row. It used to be a path OR an inline PEM
// depending on who had registered the CA, and every reader had to guess which. The guess
// went wrong in both directions: a leading newline made a real certificate look like a
// path (that cost a live lab CA), and a path is only meaningful to a process that can see
// that exact filesystem, so a CA registered from the console was invisible to fastpki-cmp
// in another container and silently stopped being servable.
//
// One form, one loader, no guess.
X509Ptr load_ca_cert_pem(const std::string& pem) {
    auto v = load_certs_pem_mem(pem);
    if (v.empty()) throw Error(1, "no certificate in the CA's stored PEM");
    return std::move(v.front());
}

// A certificate's real validity, in epoch seconds. Added because there was no way
// to ask for it: every caller storing an EXISTING certificate — the console's CA import,
// `fastpki-ca add` — wrote `now` and `now + 3650 days` instead, so a CA imported with two
// years left was recorded as having ten. The bytes have always said; nothing read them.
//
// Via ASN1_TIME_diff against the epoch rather than parsing the string, so GeneralizedTime
// and the 2-digit-year UTCTime sliding window are OpenSSL's problem, not ours. Returns 0
// when the field is absent or unconvertible; callers treat 0 as "unknown", which is what
// CertRow already means by it.
// Exported so fastpki-ca can record an imported CRL's thisUpdate/nextUpdate with
// the SAME conversion every certificate date already uses. A second implementation of
// "ASN1_TIME to unix" is a second set of edge cases (two-digit years, GeneralizedTime,
// the epoch clamp) to get wrong independently.
int64_t asn1_time_to_unix(const ASN1_TIME* t) {
    if (!t) return 0;
    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)>
        epoch(ASN1_TIME_set(nullptr, static_cast<time_t>(0)), &ASN1_TIME_free);
    if (!epoch) return 0;
    int days = 0, secs = 0;
    if (ASN1_TIME_diff(&days, &secs, epoch.get(), t) != 1) return 0;
    return static_cast<int64_t>(days) * 86400 + secs;
}

int64_t x509_not_before_unix(X509* x) {
    return x ? asn1_time_to_unix(X509_get0_notBefore(x)) : 0;
}

int64_t x509_not_after_unix(X509* x) {
    return x ? asn1_time_to_unix(X509_get0_notAfter(x)) : 0;
}

std::string x509_serial_hex(X509* x) {
    const ASN1_INTEGER* ai = X509_get0_serialNumber(x);
    if (!ai) return {};
    std::unique_ptr<BIGNUM, decltype(&BN_free)> bn(ASN1_INTEGER_to_BN(ai, nullptr), &BN_free);
    if (!bn) return {};
    //std::unique_ptr<char, decltype(&OPENSSL_free)> hex(BN_bn2hex(bn.get()), [](char* p){ OPENSSL_free(p); });
    std::unique_ptr<char, OpenSSLDeleter> hex(BN_bn2hex(bn.get()));                                                      
    if (!hex) return {};
    return canonical_serial(hex.get());
}

std::string canonical_serial(std::string s) {
    if (s.empty()) return {};
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    const size_t first = s.find_first_not_of('0');
    return (first == std::string::npos) ? "0" : s.substr(first);
}

std::vector<unsigned char> pkcs7_certs_only(const std::vector<X509*>& certs) {
    PKCS7* p7 = PKCS7_new();
    if (!p7) throw Error(2, "PKCS7_new failed");
    std::unique_ptr<PKCS7, decltype(&PKCS7_free)> guard(p7, &PKCS7_free);
    if (!PKCS7_set_type(p7, NID_pkcs7_signed))
        throw Error(2, "PKCS7_set_type failed: " + openssl_errors());
    if (!PKCS7_content_new(p7, NID_pkcs7_data))
        throw Error(2, "PKCS7_content_new failed: " + openssl_errors());
    for (X509* c : certs) {
        if (!PKCS7_add_certificate(p7, c))
            throw Error(2, "PKCS7_add_certificate failed: " + openssl_errors());
    }
    int len = i2d_PKCS7(p7, nullptr);
    if (len <= 0) throw Error(2, "i2d_PKCS7 size failed: " + openssl_errors());
    std::vector<unsigned char> out(static_cast<size_t>(len));
    unsigned char* p = out.data();
    if (i2d_PKCS7(p7, &p) != len)
        throw Error(2, "i2d_PKCS7 encode failed: " + openssl_errors());
    return out;
}

std::vector<unsigned char> pkcs7_crl_only(X509_CRL* crl) {
    PKCS7* p7 = PKCS7_new();
    if (!p7) throw Error(2, "PKCS7_new failed");
    std::unique_ptr<PKCS7, decltype(&PKCS7_free)> guard(p7, &PKCS7_free);
    if (!PKCS7_set_type(p7, NID_pkcs7_signed))
        throw Error(2, "PKCS7_set_type failed: " + openssl_errors());
    if (!PKCS7_content_new(p7, NID_pkcs7_data))
        throw Error(2, "PKCS7_content_new failed: " + openssl_errors());
    if (!PKCS7_add_crl(p7, crl))   // up-refs the CRL; caller still owns it
        throw Error(2, "PKCS7_add_crl failed: " + openssl_errors());
    int len = i2d_PKCS7(p7, nullptr);
    if (len <= 0) throw Error(2, "i2d_PKCS7 size failed: " + openssl_errors());
    std::vector<unsigned char> out(static_cast<size_t>(len));
    unsigned char* p = out.data();
    if (i2d_PKCS7(p7, &p) != len)
        throw Error(2, "i2d_PKCS7 encode failed: " + openssl_errors());
    return out;
}

// --- CA bootstrap -----------------------------------

namespace {
// Parse an OpenSSL one-line DN ("/CN=Foo Bar/O=Acme") into a fresh X509_NAME.
// Values may contain spaces; a literal '/' inside a value is not supported.
std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> build_name(const std::string& dn) {
    std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> name(X509_NAME_new(), &X509_NAME_free);
    if (!name) throw Error(2, "X509_NAME_new failed");
    size_t i = 0;
    if (i < dn.size() && dn[i] == '/') ++i;
    while (i < dn.size()) {
        size_t eq = dn.find('=', i);
        if (eq == std::string::npos) break;
        std::string type = dn.substr(i, eq - i);
        size_t end = dn.find('/', eq + 1);
        std::string val = dn.substr(eq + 1, end == std::string::npos ? std::string::npos : end - (eq + 1));
        if (!type.empty() &&
            X509_NAME_add_entry_by_txt(name.get(), type.c_str(), MBSTRING_UTF8,
                reinterpret_cast<const unsigned char*>(val.c_str()), -1, -1, 0) != 1)
            throw Error(1, "invalid DN component '" + type + "=" + val + "': " + openssl_errors());
        i = (end == std::string::npos) ? dn.size() : end + 1;
    }
    return name;
}
} // namespace

// ---- Subject Directory Attributes (RFC 5280 §4.2.1.8) ----------------------
// OpenSSL has the OID (NID_subject_directory_attributes) but no high-level
// builder for the value, so we assemble the DER by hand:
//   SubjectDirectoryAttributes ::= SEQUENCE OF Attribute
//   Attribute ::= SEQUENCE { type OID, values SET OF AttributeValue }
namespace {
// DER tag+length wrap of `content` for a universal, constructed tag.
std::vector<unsigned char> der_wrap(int tag, const std::vector<unsigned char>& content) {
    const int total = ASN1_object_size(1, static_cast<int>(content.size()), tag);
    std::vector<unsigned char> out(static_cast<size_t>(total) - content.size());
    unsigned char* p = out.data();
    ASN1_put_object(&p, 1, static_cast<int>(content.size()), tag, V_ASN1_UNIVERSAL);
    out.insert(out.end(), content.begin(), content.end());
    return out;
}
std::vector<unsigned char> der_of_oid(const char* oid) {
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> o(OBJ_txt2obj(oid, 1), ASN1_OBJECT_free);
    std::vector<unsigned char> out(o ? static_cast<size_t>(i2d_ASN1_OBJECT(o.get(), nullptr)) : 0);
    if (!out.empty()) { unsigned char* p = out.data(); i2d_ASN1_OBJECT(o.get(), &p); }
    return out;
}
std::vector<unsigned char> der_of_name(X509_NAME* n) {
    std::vector<unsigned char> out(static_cast<size_t>(i2d_X509_NAME(n, nullptr)));
    unsigned char* p = out.data(); i2d_X509_NAME(n, &p);
    return out;
}
// Attribute ::= SEQUENCE { type, SET { value } }
std::vector<unsigned char> attr_der(const char* oid, const std::vector<unsigned char>& value) {
    std::vector<unsigned char> content = der_of_oid(oid);
    std::vector<unsigned char> set = der_wrap(V_ASN1_SET, value);
    content.insert(content.end(), set.begin(), set.end());
    return der_wrap(V_ASN1_SEQUENCE, content);
}
} // namespace

static void add_subject_directory_attributes(X509* cert, const std::string& owner_username) {
    std::vector<unsigned char> attrs;
    if (!owner_username.empty()) {
        // Synthesize a DN for the owner value (id-at-owner has DN syntax).
        //
        // ⚠️ SPLIT THE QUALIFIER HERE TOO. `owner_username` is the provider-qualified
        // subject, and this is a DN like any other -- `CN=corp\alice` puts a backslash
        // inside a DN component, which is the same defect the leaf's own commonName was
        // fixed for. The provider becomes a domainComponent beside it, so the attribute
        // still says which authority asserted the owner without the name ceasing to be one.
        // ⚠️ BUILT ENTRY BY ENTRY, NOT THROUGH build_name(). build_name splits components on
        // '/', so composing "CN=<user>/DC=<provider>" re-parses the VALUE: a Kerberos service
        // principal owner such as `HTTP/host` yields a component typed `host/DC`, which
        // X509_NAME_add_entry_by_txt rejects and build_name turns into a thrown Error --
        // failing the whole issuance where the old code merely truncated the name silently.
        // Neither is acceptable, and adding the entries directly avoids the parse entirely.
        const std::string own_user = pki::subject_user(owner_username);
        const std::string own_prov = pki::subject_provider(owner_username);
        std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> name(X509_NAME_new(), &X509_NAME_free);
        if (name) {
            const auto add = [&](const char* t, const std::string& v) {
                return v.empty() || X509_NAME_add_entry_by_txt(
                    name.get(), t, MBSTRING_UTF8,
                    reinterpret_cast<const unsigned char*>(v.c_str()), -1, -1, 0) == 1;
            };
            // A value the encoder will not take is not worth failing an issuance over: this
            // attribute is a record of the owner, not a security control, so it is omitted.
            if (!add("CN", own_user) || !add("DC", own_prov)) name.reset();
        }
        if (name) {
            auto a = attr_der("2.5.4.32", der_of_name(name.get()));
            attrs.insert(attrs.end(), a.begin(), a.end());
        }
    }
    if (attrs.empty()) return;
    std::vector<unsigned char> sda = der_wrap(V_ASN1_SEQUENCE, attrs);

    std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)>
        os(ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free);
    ASN1_OCTET_STRING_set(os.get(), sda.data(), static_cast<int>(sda.size()));
    // Non-critical (crit=0), as RFC 5280 requires for this extension.
    X509_EXTENSION* ext = X509_EXTENSION_create_by_NID(nullptr, NID_subject_directory_attributes, 0, os.get());
    if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
}

EvpPkeyPtr generate_key_ex(const std::string& algo_in, int rsa_bits, const std::string& ec_curve) {
    std::string algo = algo_in;
    for (auto& c : algo) c = static_cast<char>(std::tolower((unsigned char)c));
    EVP_PKEY* k = nullptr;
    if (algo.empty() || algo == "rsa" || algo == "rsa-pss") {
        if (algo == "rsa-pss") {
            // RSA-PSS via the default provider (OSSL_PARAM, not legacy ctrl).
            std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>
                ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA-PSS", nullptr), &EVP_PKEY_CTX_free);
            if (!ctx) throw Error(2, "RSA-PSS: EVP_PKEY_CTX_new_from_name failed: " + openssl_errors());
            if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
                throw Error(2, "RSA-PSS keygen_init failed: " + openssl_errors());
            int ks = rsa_bits > 0 ? rsa_bits : 4096;
            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_BITS, &ks),
                OSSL_PARAM_construct_end()
            };
            if (EVP_PKEY_CTX_set_params(ctx.get(), params) <= 0)
                throw Error(2, "RSA-PSS keygen: failed to set key size " + std::to_string(ks) + ": " + openssl_errors());
            if (EVP_PKEY_keygen(ctx.get(), &k) <= 0)
                throw Error(2, "RSA-PSS keygen failed: " + openssl_errors());
        } else {
            k = EVP_RSA_gen(rsa_bits > 0 ? static_cast<unsigned int>(rsa_bits) : 4096u);
        }
    } else if (algo == "ec" || algo == "ecdsa" || algo == "p256") {
        std::string curve = ec_curve.empty() ? "P-256" : ec_curve;
        k = EVP_EC_gen(curve.c_str());
    } else {
        // EdDSA and PQC (ML-DSA / SLH-DSA) via the provider by algorithm name.
        std::string name = algo;
        for (auto& c : name) c = static_cast<char>(std::toupper((unsigned char)c));   // ED25519, ML-DSA-65, …
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>
            ctx(EVP_PKEY_CTX_new_from_name(nullptr, name.c_str(), nullptr), &EVP_PKEY_CTX_free);
        if (!ctx) throw Error(1, "unsupported key algorithm '" + algo_in +
                                 "' (need RSA/RSA-PSS/EC/Ed25519 or an OpenSSL >= 3.5 PQC name)");
        if (EVP_PKEY_keygen_init(ctx.get()) <= 0 || EVP_PKEY_keygen(ctx.get(), &k) <= 0)
            throw Error(2, "keygen failed for '" + name + "': " + openssl_errors());
    }
    if (!k) throw Error(2, "key generation failed: " + openssl_errors());
    return EvpPkeyPtr{k};
}

EvpPkeyPtr generate_key(const std::string& algo, int rsa_bits) {
    return generate_key_ex(algo, rsa_bits, "");
}

// Generate a NEW keypair INSIDE the PKCS#11 token. The
// private key is created as a permanent token object and never leaves the HSM;
// the returned EVP_PKEY references it (usable both as the cert's public key and,
// for a self-signed root, as the signer). `key_uri` is the pkcs11: URI naming WHERE
// to store the key (token + object label + id). The algorithm is whatever the token
// and the pkcs11 provider both support — RSA, RSA-PSS, EC, Ed25519 and the PQC
// signature algorithms (ML-DSA-44/65/87) where the token offers them.
// See the header for why this is NOT the same mapping generate_key_in_token()
// uses for the provider.
std::string db_key_algo(const std::string& algo_in) {
    std::string a = algo_in;
    for (auto& c : a) c = static_cast<char>(std::tolower((unsigned char)c));
    if (a.empty() || a == "rsa")                            return "RSA";
    // ⚠️ "RSASSA-PSS", not "RSA-PSS". This is the spelling the DERIVED path already
    // stores — insert_cert falls through to OBJ_nid2sn(EVP_PKEY_RSA_PSS) for a CA, whose
    // SPKI genuinely says rsassaPss — and `certs.keyAlgo` is what the dashboard
    // groups by. A second spelling for one key type would split that bucket in two.
    //
    // Caught by watching the guard fail: on the unfixed binary the CA row read
    // `RSASSA-PSS` and the assertion I had written expected `RSA-PSS`. My comment in
    // x509.hpp claimed the two vocabularies "agree on the case that matters" — they did
    // not, and this is the case.
    if (a == "rsa-pss")                                     return "RSASSA-PSS";
    if (a == "ec" || a == "ecdsa" || a == "p256")           return "EC";
    if (a == "ed25519")                                     return "Ed25519";
    // Anything else — ML-DSA-44/65/87 and whatever PQC name comes next — is recorded as
    // the operator spelled it, upper-cased. generate_key_in_token() hands the same string
    // to the provider by name for exactly the same reason: a list of names is the thing
    // that goes stale, and an ML-DSA CA failed on an allow-list that had one.
    for (auto& c : a) c = static_cast<char>(std::toupper((unsigned char)c));
    return a;
}

EvpPkeyPtr generate_key_in_token(const std::string& key_uri, const Config& cfg,
                                 const std::string& algo_in,
                                 int rsa_bits, const std::string& ec_curve,
                                 bool replicable) {
    const std::string uri = key_uri;
    if (uri.rfind("pkcs11:", 0) != 0)
        throw Error(1, "generate_key_in_token: need a pkcs11: key handle to name the new key");
    ensure_pkcs11_provider(cfg);

    if (replicable) {
        const std::string gerr = pkcs11_generate_replicable_keypair(
            cfg.pkcs11_module, uri, pkcs11_resolve_pin(uri, cfg.pkcs11_pin_file),
            algo_in.empty() ? std::string("rsa") : algo_in, ec_curve,
            static_cast<unsigned long>(rsa_bits > 0 ? rsa_bits : 4096));
        if (!gerr.empty()) throw Error(2, gerr);
        // ⚠️ LOADED BACK BY URI, which the provider path below avoids for RSA-PSS (a reloaded
        // PSS key loses its type name). Replicable RSA-PSS keys come through here all the same
        // — minted as CKK_RSA restricted to PSS by CKA_ALLOWED_MECHANISMS — because reloading is
        // the only way to get a handle onto a key PKCS#11 minted directly.
        // tests/key_replication.sh section 8 measures that such a key signs, in the shipped
        // image, before and after replication.
        EvpPkeyPtr k = load_signing_key(uri, cfg);
        if (!k)
            throw Error(2, "the replicable key was created but could not be loaded back from " +
                           pkcs11_uri_redacted(uri));
        return k;
    }

    std::string algo = algo_in;
    for (auto& c : algo) c = static_cast<char>(std::tolower((unsigned char)c));
    std::string name = "RSA";
    std::string group;
    if (algo == "ec" || algo == "ecdsa" || algo == "p256") {
        name = "EC"; group = ec_curve.empty() ? "P-256" : ec_curve;
    } else if (algo == "ed25519") {
        name = "ED25519";
    } else if (algo == "rsa-pss") {
        name = "RSA-PSS";   // pkcs11 provider keygen name; SoftHSM stores as CKK_RSA
    } else if (!algo.empty() && algo != "rsa") {
        // Anything else goes to the provider BY NAME, the way the software path
        // (generate_key_ex) already does — ML-DSA-44/65/87 and any later PQC name.
        //
        // This used to be an allow-list that threw here, which meant a token could
        // support an algorithm and still not be askable for it: that ML-DSA CA
        // failed on THIS line, with SoftHSM advertising CKM_ML_DSA_KEY_PAIR_GEN and
        // the pkcs11 provider carrying p11prov_mldsa_gen. The allow-list was the
        // only thing missing, and a list of names is exactly the thing that goes
        // stale — so it is gone rather than extended.
        name = algo_in;
        for (auto& c : name) c = static_cast<char>(std::toupper((unsigned char)c));
    }

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>
        ctx(EVP_PKEY_CTX_new_from_name(nullptr, name.c_str(), "?provider=pkcs11"), &EVP_PKEY_CTX_free);
    if (!ctx) throw Error(1, "generate_key_in_token: the pkcs11 provider has no key type '" +
                             name + "' (from algorithm '" + algo_in + "'): " + openssl_errors());
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
        throw Error(2, "pkcs11 keygen_init failed: " + openssl_errors());

    // Direct the pkcs11 provider WHERE to store the new key (the URI carries the
    // token, object label and id), plus the key size/curve. The provider creates
    // a token object rather than an in-memory key.
    std::vector<OSSL_PARAM> params;
    params.push_back(OSSL_PARAM_construct_utf8_string(
        "pkcs11_uri", const_cast<char*>(uri.c_str()), 0));
    size_t bits_sz = static_cast<size_t>(rsa_bits > 0 ? rsa_bits : 4096);
    if (name == "RSA" || name == "RSA-PSS")
        params.push_back(OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS, &bits_sz));
    if (!group.empty())
        params.push_back(OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(group.c_str()), 0));
    params.push_back(OSSL_PARAM_construct_end());
    if (EVP_PKEY_CTX_set_params(ctx.get(), params.data()) <= 0)
        throw Error(2, "pkcs11 keygen params (uri/bits/group) rejected: " + openssl_errors());

    EVP_PKEY* k = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &k) <= 0 || !k)
        throw Error(2, "in-token key generation failed (pkcs11 provider): " + openssl_errors());
    return EvpPkeyPtr{k};
}

// Type one SAN as the user typed it. Mirrors derGeneralNames() in the console's
// in-browser CSR encoder so the two self-service paths agree on what a given line
// means. Order matters: the explicit prefixes are checked first, because
// "upn:alice@corp" also contains an "@" and would otherwise become an rfc822Name.
std::string general_name_of(const std::string& san) {
    auto starts_with_ci = [&](const char* pfx) {
        const size_t n = std::strlen(pfx);
        if (san.size() < n) return false;
        for (size_t i = 0; i < n; ++i)
            if (std::tolower((unsigned char)san[i]) != std::tolower((unsigned char)pfx[i])) return false;
        return true;
    };
    // 1.3.6.1.4.1.311.20.2.3 — the Microsoft UPN otherName.
    if (starts_with_ci("upn:"))
        return "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:" + san.substr(4);
    if (starts_with_ci("othername:")) {
        const std::string rest = san.substr(10);
        const size_t semi = rest.find(';');
        if (semi == std::string::npos)
            throw Error(1, "othername SAN needs '<dotted-oid>;<value>': '" + san + "'");
        return "otherName:" + rest.substr(0, semi) + ";UTF8:" + rest.substr(semi + 1);
    }
    if (san.find("://") != std::string::npos) return "URI:" + san;

    // An IP literal — ASN1_STRING-free check: let OpenSSL decide, it owns the
    // parsing rules for both families and we would only reimplement them worse.
    if (std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)>
            ip(a2i_IPADDRESS(san.c_str()), &ASN1_OCTET_STRING_free); ip)
        return "IP:" + san;

    // An '@' anywhere but the first character: "@host" has no local part, so it is a
    // dNSName rather than an rfc822Name.
    if (san.find('@') != std::string::npos && !san.starts_with('@')) return "email:" + san;
    return "DNS:" + san;
}

// The requested extensions of a LeafRequest, in the shape a CSR would have carried
// them. Shared by issuance and by the pre-flight check, so what gets validated is
// byte-for-byte what gets issued rather than a second reading of the same fields.
// Throws on a malformed SAN or an extendedKeyUsage OpenSSL cannot parse — which is
// what makes it usable as a validator.
using ExtStackPtr =
    std::unique_ptr<STACK_OF(X509_EXTENSION), void(*)(STACK_OF(X509_EXTENSION)*)>;
static ExtStackPtr build_leaf_exts(const LeafRequest& r) {
    ExtStackPtr exts(sk_X509_EXTENSION_new_null(),
                     [](STACK_OF(X509_EXTENSION)* s) { sk_X509_EXTENSION_pop_free(s, X509_EXTENSION_free); });
    if (!exts) throw Error(2, "sk_X509_EXTENSION_new_null failed");

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, nullptr, nullptr, nullptr, nullptr, 0);
    auto add = [&](int nid, const std::string& val) {
        if (val.empty()) return;
        X509_EXTENSION* ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, val.c_str());
        if (!ex) throw Error(1, std::string("leaf request: bad ") + OBJ_nid2sn(nid) +
                                " value '" + val + "': " + openssl_errors());
        if (!sk_X509_EXTENSION_push(exts.get(), ex)) {
            X509_EXTENSION_free(ex);
            throw Error(2, "sk_X509_EXTENSION_push failed");
        }
    };
    std::vector<std::string> gns;
    gns.reserve(r.sans.size());
    for (const auto& s : r.sans) if (!s.empty()) gns.push_back(general_name_of(s));
    add(NID_subject_alt_name, join(gns,             "", ","));
    add(NID_key_usage,        join(r.key_usage,     "", ","));
    add(NID_ext_key_usage,    join(r.ext_key_usage, "", ","));
    // Extensions that are neither KU nor EKU — currently only id-pkix-ocsp-nocheck,
    // which the console cannot express (its form has no extension field) and which RFC 6960
    // §2.1.2 makes mandatory on a delegated responder rather than optional.
    // Same encoder the profile path uses (add_ext_oid), so a value written for a profile
    // means exactly the same thing here — two spellings of "DER:05:00" would be a bug
    // waiting to happen.
    for (const auto& x : r.custom_exts) {
        if (x.oid.empty()) continue;
        std::string spec = x.value.empty() ? "DER:05:00" : x.value;   // ASN.1 NULL default
        if (x.critical) spec = "critical," + spec;
        X509_EXTENSION* ex = X509V3_EXT_nconf(nullptr, &ctx, x.oid.c_str(), spec.c_str());
        if (!ex) throw Error(1, "leaf request: custom extension '" + x.oid + "': " + openssl_errors());
        if (!sk_X509_EXTENSION_push(exts.get(), ex)) {
            X509_EXTENSION_free(ex);
            throw Error(2, "sk_X509_EXTENSION_push failed");
        }
    }
    return exts;
}

// Issue a leaf whose subject, public key and requested extensions come from
// plain parts instead of a PKCS#10. The console's HSM path needs this — the private
// key is minted inside the token, so there is no browser-side key to build and sign
// a CSR with, and a server-signed CSR would only be the server proving possession to
// itself. Everything downstream is the ordinary path: enforce_issuance_policy(), the
// resolved profile, the SDA owner and the per-CA AIA/CRLDP all run inside
// issue_cert_from_parts() exactly as they do for a CSR.
X509Ptr issue_leaf_from_request(const Config& cfg, X509* ca_cert, EVP_PKEY* ca_key,
                                const LeafRequest& r, EVP_PKEY* subject_key,
                                const std::string& profile,
                                const std::string& owner_username,
                                const CaUrls* ca_urls,
                                const std::string& key_algo,
                                const CertProfile* profile_override) {
    if (!subject_key) throw Error(1, "leaf request: no subject key");
    // When the caller knows this is an RSA-PSS key (web console form,
    // cert row keyAlgo), pass a software PSS-restricted public key so the
    // SPKI carries id-RSASSA-PSS.  The provider cannot detect PSS on loaded
    // keys (CKA_ALLOWED_MECHANISMS is empty on public keys).
    EvpPkeyPtr restricted;
    if (!key_algo.empty()) {
        restricted = rsa_pss_restricted_public(subject_key, nullptr, key_algo);
        if (restricted) subject_key = restricted.get();
    }
    auto subject = build_name(r.subject_dn);
    auto exts = build_leaf_exts(r);

    // ⚠️ issue_cert_from_parts does NOT copy arbitrary extensions out of `exts` — that is
    // deliberate. KU/EKU are rebuilt from the PROFILE (an allow-list, so a caller cannot
    // widen its own certificate), the SAN is copied explicitly, and everything else must be
    // named in passthrough_ext_oids to survive. Building an extension without listing it
    // here silently drops it, which is what the first attempt did.
    std::vector<std::string> passthrough;
    passthrough.reserve(r.custom_exts.size());
    for (const auto& x : r.custom_exts) if (!x.oid.empty()) passthrough.push_back(x.oid);

    // Carry the request's omit choices through. They are still subject to the
    // profile's manage_* flags inside issue_cert_from_parts.
    // Carry the requested digest. issue_cert_from_parts has taken `requested_md`
    // since 19c5126; this call site passed the two omit flags and stopped, so the console's
    // HSM form could offer a picker whose value died here.
    return issue_cert_from_parts(cfg, ca_cert, ca_key, subject.get(), subject_key,
                                 exts.get(), profile, /*acme=*/false, owner_username,
                                 passthrough, ca_urls, r.omit_aia, r.omit_crldp,
                                 profile_override, r.requested_md);
}

void validate_leaf_request(const Config& cfg, const LeafRequest& r,
                           const std::string& profile,
                           const CertProfile* profile_override) {
    auto subject = build_name(r.subject_dn);
    auto exts = build_leaf_exts(r);   // throws on a malformed SAN or a bogus EKU OID
    const CertProfile& prof = profile_override ? *profile_override
                                               : resolve_cert_profile(cfg, profile);
    // No key yet — that is the entire point. `enforce_issuance_policy` skips the
    // key-size check when the key is null; everything else it checks (the CN
    // allowlist, SAN types, DNS/IP ranges) needs only the request.
    enforce_issuance_policy(cfg, subject.get(), /*pubkey=*/nullptr, exts.get(), prof,
                            /*acme=*/false);
    evaluate_profile_extensions(prof, exts.get());   // KU/EKU against the allow-list
}

// The signature digest for a CA cert, chosen by the SIGNING key's type: EdDSA
// and the PQC signature algorithms are one-shot (no prehash) and must be signed
// with a null md; RSA/EC honour the requested hash (default SHA-256).
static const EVP_MD* pick_sig_md(EVP_PKEY* sign_key, const std::string& md_name,
                                 bool allow_weak) {
    const char* tn = EVP_PKEY_get0_type_name(sign_key);
    if (tn && (std::strcmp(tn, "ED25519") == 0 || std::strcmp(tn, "ED448") == 0 ||
               std::strstr(tn, "ML-DSA") || std::strstr(tn, "SLH-DSA")))
        return nullptr;
    std::string n = md_name.empty() ? "sha256" : md_name;
    const EVP_MD* md = EVP_get_digestbyname(n.c_str());
    if (!md) return EVP_sha256();
    // A CA certificate signed under SHA-1 is worse than a leaf signed under SHA-1: it is
    // the anchor every leaf beneath it chains through, and it lives for years. The floor
    // applies here for the same reason it applies to leaves, and defaults to ON — the flag
    // has to be carried in deliberately by a caller that read the deployment's setting, so
    // a path that forgets to pass it refuses rather than permits.
    if (!allow_weak && is_weak_signature_digest(md)) {
        log::err("CA certificate: refusing signature digest '" + n +
                 "' — below the signature floor; signing with SHA-256 instead");
        return EVP_sha256();
    }
    return md;
}

// RFC 4055 §3.1: an RSA-PSS key's SubjectPublicKeyInfo carries id-RSASSA-PSS
// (1.2.840.113549.1.1.10), not rsaEncryption. That is what makes the key RESTRICTED to
// PSS — a relying party seeing rsaEncryption is entitled to use it with PKCS#1 v1.5.
//
// ⚠️ WHY THIS IS NEEDED AT ALL. The key generated in the token IS of type RSA-PSS, but the
// pkcs11 provider's encoder writes the SPKI as plain rsaEncryption, so asking the console
// for an RSA-PSS CA produced a certificate that SIGNED with PSS while publishing an
// unrestricted key. `key=rsa` and `key=rsa-pss` then differed only in signature algorithm,
// which `md` already selects — the option promised a restriction it did not deliver.
// Follow RFC 4055 — the standards exist for a reason.
//
// Rather than patch the encoded AlgorithmIdentifier by hand, rebuild the PUBLIC half as a
// software RSA-PSS key carrying the restriction, and let OpenSSL's own encoder emit the
// parameters. Hand-built ASN.1 here would have to get DEFAULT-omission right (RFC 4055's
// defaults are SHA-1/MGF1-SHA1/salt 20, so anything stronger MUST be explicit) and that is
// exactly the kind of detail a library already knows.
//
// Returns nullptr when this does not apply or cannot be done, and the caller keeps the
// key it had — a CA that publishes rsaEncryption is worse than one that does not exist.
static EvpPkeyPtr rsa_pss_restricted_public(EVP_PKEY* key, const EVP_MD* md,
                                             const std::string& known_key_algo) {
    if (!key) return nullptr;
    bool is_pss = (known_key_algo == "rsa-pss" || known_key_algo == "RSASSA-PSS");
    if (!is_pss && !EVP_PKEY_is_a(key, "RSA-PSS")) return nullptr;

    OSSL_PARAM* pub = nullptr;
    if (EVP_PKEY_todata(key, EVP_PKEY_PUBLIC_KEY, &pub) <= 0 || !pub) {
        ERR_clear_error();
        return nullptr;
    }
    // n and e, plus the three restriction parameters. OSSL_PARAM_merge does not exist for
    // this shape, so build a fresh array: the public numbers are copied by reference into
    // the builder, which is fine because `pub` outlives the fromdata call.
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    EvpPkeyPtr out;
    if (bld) {
        bool ok = true;
        // ⚠️ OSSL_PARAM_BLD_push_BN stores a REFERENCE, not a copy — the BIGNUM must stay
        // alive until OSSL_PARAM_BLD_to_param() has read it. Freeing each one right after
        // pushing (the obvious-looking thing) is a use-after-free that SIGSEGVs inside
        // BN_num_bits, taking fastpki-web down with it. Hold them, convert, then free.
        std::vector<BIGNUM*> keep;
        int modbits = 0;
        for (const OSSL_PARAM* q = pub; q && q->key; ++q) {
            const bool is_n = std::strcmp(q->key, OSSL_PKEY_PARAM_RSA_N) == 0;
            if (is_n || std::strcmp(q->key, OSSL_PKEY_PARAM_RSA_E) == 0) {
                BIGNUM* bn = nullptr;
                if (OSSL_PARAM_get_BN(q, &bn) && bn) {
                    keep.push_back(bn);
                    if (is_n) modbits = BN_num_bits(bn);
                    ok = ok && OSSL_PARAM_BLD_push_BN(bld, q->key, bn);
                } else ok = false;
            }
        }
        // ⚠️ When the caller names no digest, this MUST land on the same one the
        // certificate will actually be signed with — otherwise a self-signed CA publishes
        // "this key is restricted to PSS-with-SHA-256" and then signs itself with SHA-384,
        // which contradicts the very restriction being expressed. ca_signing_md() switches
        // at 4096 bits, so mirror it here, sized from the real modulus (a pkcs11 handle
        // reports 0 bits, but todata above gave us the genuine n).
        if (!md) md = modbits >= 4096 ? EVP_sha384() : EVP_sha256();
        const char* mdname = EVP_MD_get0_name(md);
        ok = ok && OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_RSA_DIGEST, mdname, 0);
        ok = ok && OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_RSA_MASKGENFUNC, "mgf1", 0);
        ok = ok && OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, mdname, 0);
        ok = ok && OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, EVP_MD_get_size(md));
        OSSL_PARAM* arr = ok ? OSSL_PARAM_BLD_to_param(bld) : nullptr;
        if (arr) {
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA-PSS", nullptr);
            EVP_PKEY* np = nullptr;
            if (ctx && EVP_PKEY_fromdata_init(ctx) > 0 &&
                EVP_PKEY_fromdata(ctx, &np, EVP_PKEY_PUBLIC_KEY, arr) > 0 && np)
                out.reset(np);
            if (ctx) EVP_PKEY_CTX_free(ctx);
            OSSL_PARAM_free(arr);
        }
        OSSL_PARAM_BLD_free(bld);
        for (BIGNUM* bn : keep) BN_free(bn);
    }
    OSSL_PARAM_free(pub);
    if (!out) ERR_clear_error();
    return out;
}

// ⚠️ A CA CERTIFICATE MAY NOT OUTLIVE THE CERTIFICATE THAT SIGNS IT. Past the issuer's
// notAfter the only path to it runs through an expired certificate, so the tail looks valid
// on its face and cannot be chained by anybody. Every CA certificate built with an issuer
// goes through here — a sub CA created under a parent, a CSR signed from the CAs page or by
// `fastpki-ca sign-csr`, a re-key's cross-certificates and a cross-signed foreign CA — and
// before this only the re-key cut its dates, while a sub CA created with the default ten
// years outlived any root that was not brand new. Clamped rather than refused, as leaf
// issuance does: refusing would stop every CA creation under a parent in its last decade.
// Announced, because a validity other than the one asked for must never be silent.
static void clamp_not_after_to_issuer(X509* cert, X509* issuer_cert) {
    if (!issuer_cert) return;
    if (ASN1_TIME_compare(X509_get0_notAfter(cert), X509_get0_notAfter(issuer_cert)) != 1) return;
    if (!X509_set1_notAfter(cert, X509_get0_notAfter(issuer_cert)))
        throw Error(2, "could not limit the CA certificate's notAfter to its issuer's: " +
                       openssl_errors());
    log::info("CA certificate: the requested validity ran past the issuer's own notAfter — "
              "shortened to it, since no relying party could chain past that date");
}

X509Ptr build_ca_certificate_unsigned(EVP_PKEY* subject_key, const std::string& subject_dn,
                                      int days, X509* issuer_cert) {
    if (!subject_key) throw Error(1, "create_ca: missing subject key");

    X509Ptr cert{X509_new()};
    if (!cert) throw Error(2, "X509_new failed");
    if (!X509_set_version(cert.get(), 2)) throw Error(2, "X509_set_version failed");   // v3
    // A CA certificate WE mint carries this node's prefix like everything else —
    // we drew it from our own randomness, so it can collide with a peer's. The mesh guard
    // exempts `NEW.is_ca` because at INSERT time the database cannot tell our own CA cert
    // from one we merely imported; that exemption is the net, this is the rule.
    set_random_serial(cert.get(), 20);

    auto subj = build_name(subject_dn);
    if (!X509_set_subject_name(cert.get(), subj.get()))
        throw Error(2, "X509_set_subject_name failed: " + openssl_errors());
    // Issuer = the issuer cert's subject (Sub-CA) or our own subject (self-signed).
    X509_NAME* issuer_name = issuer_cert ? X509_get_subject_name(issuer_cert) : subj.get();
    if (!X509_set_issuer_name(cert.get(), issuer_name))
        throw Error(2, "X509_set_issuer_name failed: " + openssl_errors());

    // RFC 4055 §3.1: publish the RESTRICTED form for an RSA-PSS key, so the
    // certificate says the key is PSS-only instead of merely being signed with PSS.
    // Falls back to the key as-is when it does not apply.
    // nullptr md: the helper sizes it from the modulus the same way ca_signing_md() does,
    // which is what create_ca_certificate() signs with — so the two cannot disagree.
    if (EvpPkeyPtr restricted = rsa_pss_restricted_public(subject_key, nullptr)) {
        if (!X509_set_pubkey(cert.get(), restricted.get()))
            throw Error(2, "X509_set_pubkey(RSA-PSS) failed: " + openssl_errors());
    } else if (!X509_set_pubkey(cert.get(), subject_key)) {
        throw Error(2, "X509_set_pubkey failed: " + openssl_errors());
    }
    if (!X509_gmtime_adj(X509_getm_notBefore(cert.get()), -kClockSkewBackdateSec) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60L * 60 * 24 * days))
        throw Error(2, "validity adj failed");
    clamp_not_after_to_issuer(cert.get(), issuer_cert);

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    // The AKID keyid comes from the issuer (self for a root).
    X509V3_set_ctx(&ctx, issuer_cert ? issuer_cert : cert.get(), cert.get(), nullptr, nullptr, 0);
    add_ext_text(ctx, cert.get(), NID_basic_constraints,        "critical,CA:TRUE");
    // A CA signs certificates and CRLs — that is all this default grants. It used
    // to include digitalSignature because CMP protected its responses with the CA's own
    // key (edb2b45), which let one protocol's implementation detail dictate the key usage
    // of every CA in the deployment. CMP now protects with a dedicated RA credential and
    // has no CA-key fallback, so the reason is gone.
    add_ext_text(ctx, cert.get(), NID_key_usage,
                 "critical,keyCertSign,cRLSign");
    add_ext_text(ctx, cert.get(), NID_subject_key_identifier,   "hash");
    add_ext_text(ctx, cert.get(), NID_authority_key_identifier, "keyid:always");
    return cert;
}

X509Ptr create_ca_certificate(EVP_PKEY* subject_key, const std::string& subject_dn,
                              int days, X509* issuer_cert, EVP_PKEY* issuer_key) {
    EVP_PKEY* sign_key = issuer_key ? issuer_key : subject_key;   // self-sign if no issuer
    X509Ptr cert = build_ca_certificate_unsigned(subject_key, subject_dn, days, issuer_cert);
    // Self-signed: the certificate being built carries the signing key's own public
    // half, so it is the right thing to size from. With an issuer, size from theirs.
    cert.reset(sign_x509(cert.release(), sign_key,
                         ca_signing_md(sign_key, issuer_cert ? issuer_cert : cert.get())));
    return cert;
}

// ---- Full RFC 5280 CA builder for the console CA-creation page --------

// Sign a certification request. Structurally identical to sign_x509 above, and
// deliberately so — a CSR for a sub-CA is signed by the key that is being certified, and
// that key lives in a token, so it hits exactly the same three provider quirks. Keeping
// the two in step matters more than sharing code: if one grows a fourth workaround and
// the other does not, the failure is a CSR that a token refuses to sign, reported as an
// opaque provider error.
X509_REQ* sign_x509_req(X509_REQ* req, EVP_PKEY* key, const EVP_MD* md) {
    // --- EdDSA (any provider): must use NULL md ----------------------------
    {
        int base = EVP_PKEY_get_base_id(key);
        if (base == EVP_PKEY_ED25519 || base == EVP_PKEY_ED448) {
            if (!X509_REQ_sign(req, key, nullptr))
                throw Error(2, "X509_REQ_sign(EdDSA) failed: " + openssl_errors());
            return req;
        }
    }

    // --- RSA-PSS on pkcs11: X509_REQ_sign_ctx with PSS params --------------
    if (p11_rsa_requires_pss(key)) {
        const EVP_MD* use_md = md ? md : EVP_sha256();
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        if (!mctx) throw Error(2, "EVP_MD_CTX_new failed");
        EVP_PKEY_CTX* pctx = nullptr;
        if (EVP_DigestSignInit(mctx, &pctx, use_md, nullptr, key) <= 0) {
            EVP_MD_CTX_free(mctx);
            throw Error(2, "EVP_DigestSignInit(RSA-PSS) failed: " + openssl_errors());
        }
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, use_md) <= 0 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
            EVP_MD_CTX_free(mctx);
            throw Error(2, "EVP_PKEY_CTX RSA-PSS params failed: " + openssl_errors());
        }
        if (X509_REQ_sign_ctx(req, mctx) <= 0) {
            EVP_MD_CTX_free(mctx);
            throw Error(2, "X509_REQ_sign_ctx(RSA-PSS) failed: " + openssl_errors());
        }
        EVP_MD_CTX_free(mctx);
        return req;
    }

    if (!is_ec_p11_key(key)) {
        if (!X509_REQ_sign(req, key, md)) {
            // Same reasoning as sign_x509 — a signing failure on a token key may
            // mean the token (or its sidecar) restarted, which kills this PROCESS's
            // provider connection for good.
            const std::string err = openssl_errors();
            exit_if_token_died(key, "CSR signing");
            throw Error(2, "X509_REQ_sign failed: " + err);
        }
        return req;
    }

    // --- EC on pkcs11: pre-hash then sign with CKM_ECDSA -------------------
    // Simpler than the certificate case: CertificationRequestInfo has NO
    // signatureAlgorithm field of its own (RFC 2986 §4), so there is nothing to
    // pre-populate before encoding the TBS — only the outer AlgorithmIdentifier to fill
    // in afterwards.
    const EVP_MD* use_md = md ? md : ec_p11_md(key);
    int sigalg_nid = ecdsa_sigalg_nid(EVP_MD_get_type(use_md));
    if (sigalg_nid == NID_undef)
        throw Error(2, std::string("no ECDSA signature OID for digest ") +
                       (EVP_MD_get0_name(use_md) ? EVP_MD_get0_name(use_md) : "?") +
                       " — FIPS 186-5 permits SHA-2 and SHA-3, and this build has an OID for each");

    int tbs_len = i2d_re_X509_REQ_tbs(req, nullptr);
    if (tbs_len <= 0) throw Error(2, "i2d_re_X509_REQ_tbs failed: " + openssl_errors());
    std::vector<unsigned char> tbs(static_cast<size_t>(tbs_len));
    unsigned char* tp = tbs.data();
    if (i2d_re_X509_REQ_tbs(req, &tp) != tbs_len)
        throw Error(2, "i2d_re_X509_REQ_tbs mismatch");

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (!EVP_Digest(tbs.data(), tbs.size(), hash, &hash_len, use_md, nullptr))
        throw Error(2, "CSR TBS digest failed: " + openssl_errors());

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(key, nullptr);
    if (!pctx) throw Error(2, "EVP_PKEY_CTX_new failed");
    if (EVP_PKEY_sign_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw Error(2, "EVP_PKEY_sign_init failed: " + openssl_errors());
    }
    size_t sig_len = 0;
    if (EVP_PKEY_sign(pctx, nullptr, &sig_len, hash, hash_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw Error(2, "EVP_PKEY_sign size-query failed: " + openssl_errors());
    }
    std::vector<unsigned char> sig_buf(sig_len);
    if (EVP_PKEY_sign(pctx, sig_buf.data(), &sig_len, hash, hash_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw Error(2, "EVP_PKEY_sign(prehash) failed: " + openssl_errors());
    }
    EVP_PKEY_CTX_free(pctx);

    // Write the algorithm and the signature straight onto the request. The TBS encoding
    // was cached by i2d_re_X509_REQ_tbs above, so i2d_X509_REQ re-emits the very bytes
    // that were hashed rather than a fresh encoding that might differ.
    const ASN1_BIT_STRING* csig = nullptr;
    const X509_ALGOR*      calg = nullptr;
    X509_REQ_get0_signature(req, &csig, &calg);
    X509_ALGOR_set0(const_cast<X509_ALGOR*>(calg), OBJ_nid2obj(sigalg_nid), V_ASN1_UNDEF, nullptr);
    ASN1_BIT_STRING* sig = const_cast<ASN1_BIT_STRING*>(csig);
    if (!ASN1_STRING_set(sig, sig_buf.data(), static_cast<int>(sig_len)))
        throw Error(2, "ASN1_STRING_set(CSR signature) failed: " + openssl_errors());
    sig->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    sig->flags |= ASN1_STRING_FLAG_BITS_LEFT;    // an unused-bit count of 0, explicitly
    return req;
}

// The CSR half of the cross-data-center sub-CA round trip.
X509ReqPtr build_ca_csr(EVP_PKEY* key, const CaCertParams& p) {
    if (!key) throw Error(1, "build_ca_csr: missing key");

    X509ReqPtr req{X509_REQ_new()};
    if (!req) throw Error(2, "X509_REQ_new failed");
    // RFC 2986: the only defined value is v1, encoded as 0.
    if (!X509_REQ_set_version(req.get(), 0)) throw Error(2, "X509_REQ_set_version failed");

    auto subj = build_name(p.subject_dn);
    if (!X509_REQ_set_subject_name(req.get(), subj.get()))
        throw Error(2, "X509_REQ_set_subject_name failed: " + openssl_errors());

    // RFC 4055 §3.1: an RSA-PSS key is published in its restricted form here too.
    // The signer copies the CSR's public key onto the certificate, so getting this wrong
    // in the request produces an unrestricted sub-CA no matter what the signer does.
    if (EvpPkeyPtr restricted = rsa_pss_restricted_public(
            key, EVP_get_digestbyname(p.md.empty() ? "sha256" : p.md.c_str()))) {
        if (!X509_REQ_set_pubkey(req.get(), restricted.get()))
            throw Error(2, "X509_REQ_set_pubkey(RSA-PSS) failed: " + openssl_errors());
    } else if (!X509_REQ_set_pubkey(req.get(), key)) {
        throw Error(2, "X509_REQ_set_pubkey failed: " + openssl_errors());
    }

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    // No subject and no issuer certificate exist yet, so the ctx names the request. That
    // rules out `hash`-valued key identifiers, which is correct: SKI/AKI are the signer's
    // to compute.
    X509V3_set_ctx(&ctx, nullptr, nullptr, req.get(), nullptr, 0);

    std::unique_ptr<STACK_OF(X509_EXTENSION), void(*)(STACK_OF(X509_EXTENSION)*)>
        exts(sk_X509_EXTENSION_new_null(),
             [](STACK_OF(X509_EXTENSION)* s){ sk_X509_EXTENSION_pop_free(s, X509_EXTENSION_free); });
    if (!exts) throw Error(2, "sk_X509_EXTENSION_new_null failed");
    auto add = [&](int nid, const std::string& val) {
        if (val.empty()) return;
        X509_EXTENSION* ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, val.c_str());
        if (!ex) throw Error(2, "X509V3_EXT_conf_nid failed for nid=" + std::to_string(nid) +
                                ": " + openssl_errors());
        if (!sk_X509_EXTENSION_push(exts.get(), ex)) {
            X509_EXTENSION_free(ex);
            throw Error(2, "sk_X509_EXTENSION_push failed");
        }
    };

    std::string bc = "critical,CA:TRUE";
    if (p.pathlen >= 0) bc += ",pathlen:" + std::to_string(p.pathlen);
    add(NID_basic_constraints, bc);
    // Same default as build_ca_certificate_ex: sign certificates and CRLs, nothing
    // more. Asking for it in the request is what lets the signer see the request was for a
    // CA at all, rather than inferring it from basicConstraints alone.
    add(NID_key_usage, "critical," + (p.key_usage.empty() ? std::string("keyCertSign,cRLSign")
                                                          : join(p.key_usage, "", ",")));

    std::vector<std::string> nc;
    for (const auto& e : p.permitted) nc.push_back("permitted;" + nc_normalize_ip(e));
    for (const auto& e : p.excluded)  nc.push_back("excluded;" + nc_normalize_ip(e));
    if (!nc.empty()) add(NID_name_constraints, "critical," + join(nc, "", ","));
    if (!p.policies.empty()) add(NID_certificate_policies, join(p.policies, "", ","));

    if (sk_X509_EXTENSION_num(exts.get()) > 0 &&
        !X509_REQ_add_extensions(req.get(), exts.get()))
        throw Error(2, "X509_REQ_add_extensions failed: " + openssl_errors());

    req.reset(sign_x509_req(req.release(), key,
                            pick_sig_md(key, p.md, p.allow_weak_md)));
    return req;
}

X509Ptr build_ca_certificate_ex(EVP_PKEY* subject_key, const CaCertParams& p, X509* issuer_cert) {
    if (!subject_key) throw Error(1, "create_ca: missing subject key");

    X509Ptr cert{X509_new()};
    if (!cert) throw Error(2, "X509_new failed");
    if (!X509_set_version(cert.get(), 2)) throw Error(2, "X509_set_version failed");   // v3
    // A CA certificate WE mint carries this node's prefix like everything else —
    // we drew it from our own randomness, so it can collide with a peer's. The mesh guard
    // exempts `NEW.is_ca` because at INSERT time the database cannot tell our own CA cert
    // from one we merely imported; that exemption is the net, this is the rule.
    set_random_serial(cert.get(), 20);

    auto subj = build_name(p.subject_dn);
    if (!X509_set_subject_name(cert.get(), subj.get()))
        throw Error(2, "X509_set_subject_name failed: " + openssl_errors());
    X509_NAME* issuer_name = issuer_cert ? X509_get_subject_name(issuer_cert) : subj.get();
    if (!X509_set_issuer_name(cert.get(), issuer_name))
        throw Error(2, "X509_set_issuer_name failed: " + openssl_errors());
    // RFC 4055 §3.1: publish the RESTRICTED form for an RSA-PSS key, so the
    // certificate says the key is PSS-only instead of merely being signed with PSS.
    // Falls back to the key as-is when it does not apply.
    //
    // ⚠️ The restriction digest cannot be arbitrary, so an incompatible request must
    // die HERE, naming the fix, not three frames deeper inside OpenSSL. The digest
    // becomes BOTH hashAlg and MGF1 in the SPKI's id-RSASSA-PSS parameters, and:
    //   * OpenSSL cannot encode MGF1 parameters that name a SHA-3 digest —
    //     X509_PUBKEY_set fails with "error:0580006F:x509 certificate routines::
    //     unsupported algorithm" (x_pubkey.c raises it because the SPKI encoder
    //     produced nothing; measured on 3.5.x and 3.6.x);
    //   * an RFC 4055 restriction BINDS the key (see pss_restricted_md), so whatever
    //     digest is published here is also the only one this CA can ever sign with.
    // A caller asking for sha3-* over an RSA-PSS key is therefore asking for a
    // certificate that cannot exist — say exactly that instead of letting it look like
    // a broken token or a broken build.
    const EVP_MD* rmd = nullptr;
    if (EVP_PKEY_is_a(subject_key, "RSA-PSS")) {
        rmd = EVP_get_digestbyname(p.md.empty() ? "sha256" : p.md.c_str());
        const int nid = rmd ? EVP_MD_get_type(rmd) : NID_undef;
        if (nid != NID_sha1 && nid != NID_sha224 && nid != NID_sha256 &&
            nid != NID_sha384 && nid != NID_sha512)
            throw Error(1, "RSA-PSS key with --md '" + p.md +
                               "': the SPKI restriction digest must be sha256, sha384 or "
                               "sha512 — OpenSSL cannot encode id-RSASSA-PSS MGF1 "
                               "parameters with SHA-3 digests, and an RFC 4055 restriction "
                               "must match the signature digest, so no certificate can "
                               "carry this combination.");
    }
    if (EvpPkeyPtr restricted = rsa_pss_restricted_public(subject_key, rmd)) {
        if (!X509_set_pubkey(cert.get(), restricted.get()))
            throw Error(2, "X509_set_pubkey(RSA-PSS) failed: " + openssl_errors());
    } else if (!X509_set_pubkey(cert.get(), subject_key)) {
        throw Error(2, "X509_set_pubkey failed: " + openssl_errors());
    }

    // Validity: explicit notBefore/notAfter epochs, else CA defaults. RFC 5280
    // §4.1.2.5 — a CA with no well-defined expiry uses the 99991231235959Z GT.
    ASN1_TIME* nb = X509_getm_notBefore(cert.get());
    if (p.not_before > 0) { if (!ASN1_TIME_set(nb, (time_t)p.not_before)) throw Error(2, "notBefore set failed"); }
    else if (!X509_gmtime_adj(nb, -kClockSkewBackdateSec)) throw Error(2, "notBefore adj failed");
    ASN1_TIME* na = X509_getm_notAfter(cert.get());
    if (p.never_expire) {
        if (!ASN1_GENERALIZEDTIME_set_string(na, "99991231235959Z"))
            throw Error(2, "never-expire notAfter set failed");
    } else if (p.not_after > 0) {
        if (!ASN1_TIME_set(na, (time_t)p.not_after)) throw Error(2, "notAfter set failed");
    } else if (!X509_gmtime_adj(na, 60L * 60 * 24 * 3650)) throw Error(2, "notAfter adj failed");
    clamp_not_after_to_issuer(cert.get(), issuer_cert);

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer_cert ? issuer_cert : cert.get(), cert.get(), nullptr, nullptr, 0);

    std::string bc = "critical,CA:TRUE";
    if (p.pathlen >= 0) bc += ",pathlen:" + std::to_string(p.pathlen);
    add_ext_text(ctx, cert.get(), NID_basic_constraints, bc);

    // Same reasoning as build_ca_certificate_unsigned: sign certificates and CRLs,
    // nothing more. An explicit key_usage from the caller still wins — this is the
    // default, not a floor, so a deployment that really does need digitalSignature on a
    // CA (one signing OCSP responses directly rather than via a delegated responder,
    // RFC 6960 §4.2.2.2) can still ask for it.
    std::string ku = p.key_usage.empty() ? std::string("keyCertSign,cRLSign")
                                         : join(p.key_usage, "", ",");
    add_ext_text(ctx, cert.get(), NID_key_usage, "critical," + ku);

    add_ext_text(ctx, cert.get(), NID_subject_key_identifier,   "hash");
    add_ext_text(ctx, cert.get(), NID_authority_key_identifier, "keyid:always");

    // NameConstraints (RFC 5280 §4.2.1.10) — MUST be critical.
    std::vector<std::string> nc;
    for (const auto& e : p.permitted) nc.push_back("permitted;" + nc_normalize_ip(e));
    for (const auto& e : p.excluded)  nc.push_back("excluded;" + nc_normalize_ip(e));
    if (!nc.empty()) add_ext_text(ctx, cert.get(), NID_name_constraints, "critical," + join(nc, "", ","));

    // AIA: caIssuers (this CA's own cert) and/or OCSP.
    std::vector<std::string> aia;
    for (const auto& u : p.aia_issuers) aia.push_back("caIssuers;URI:" + u);
    for (const auto& u : p.aia_ocsp)    aia.push_back("OCSP;URI:" + u);
    if (!aia.empty()) add_ext_text(ctx, cert.get(), NID_info_access, join(aia, "", ","));

    if (!p.crldp.empty())
        add_ext_text(ctx, cert.get(), NID_crl_distribution_points, join(p.crldp, "URI:", ","));
    add_certificate_policies(cert.get(), p.policies);
    return cert;
}

X509Ptr create_ca_certificate_ex(EVP_PKEY* subject_key, const CaCertParams& p,
                                 X509* issuer_cert, EVP_PKEY* issuer_key) {
    EVP_PKEY* sign_key = issuer_key ? issuer_key : subject_key;   // self-sign if no issuer
    X509Ptr cert = build_ca_certificate_ex(subject_key, p, issuer_cert);
    // When the ISSUER's certificate restricts its key to one digest (RFC 4055 §3.1),
    // that beats `p.md`. p.md is the operator's choice for the certificate being CREATED —
    // it says nothing about what the signer is permitted to sign with, and using it anyway
    // produces a sub-CA certificate its own parent cannot verify.
    //
    // Self-signed (no issuer_cert): the signer IS the subject, and the restriction being
    // written into this very certificate comes from p.md, so pick_sig_md agrees already.
    // Only a real restriction overrides. An unrestricted issuer leaves p.md alone, so an
    // operator who asks for SHA-512 still gets it.
    const EVP_MD* restricted = pss_restricted_md(issuer_cert);
    cert.reset(sign_x509(cert.release(), sign_key,
                         restricted ? restricted : pick_sig_md(sign_key, p.md, p.allow_weak_md)));
    return cert;
}

// Certify one CA key under another CA's signature — the primitive CA rekeying is
// built from.
//
// Rekeying does not replace a certificate, it adds one. A new key is minted in the token
// and then TWO cross-certificates are produced, which is the confirmed design:
//
//   cross_sign_ca(old_cert, old_key, new_pub, …)   the NEW key, signed by the OLD
//                                                  -> anyone anchored on the old CA
//                                                     already trusts the new key
//   cross_sign_ca(new_cert, new_key, old_pub, …)   the OLD key, signed by the NEW
//                                                  -> anyone who has moved to the new
//                                                     anchor still trusts everything
//                                                     the old key signed
//
// Both are ordinary CA certificates over the SAME subject — the CA's identity does not
// change when its key does — differing only in which public key they carry and which key
// signed them. `serial` is fresh on each (set_random_serial), which is required rather
// than incidental: both rows live in `certs` at once and serial is the primary key.
//
// The subject Name is copied STRUCTURALLY from the certificate rather than re-parsed from
// params.subject_dn. "The same subject" has to mean byte-identical DER: a one-line DN put
// back through build_name() can return different ASN.1 string types (PrintableString vs
// UTF8String), which changes the encoded Name, changes its sHash, and stops a relying
// party matching this certificate against the issuer field of everything the CA signed.
// A cross-certificate that does not chain is worse than none.
// A rekeyed generation is the SAME CA. Everything the certificate says about that
// CA — where its CRL is published, where its issuer's certificate is fetched, how deep it
// may delegate, which names it is constrained to, which policies it asserts — describes
// the CA, not the key, so it has to survive a key change. Otherwise the rekey quietly
// installs a WEAKER and less usable CA than the one it replaces.
//
// Measured on the lab: `certutil -urlfetch -verify` on an issued leaf reported
// BOTH intermediate generations as "Certificate AIA: No URLs" / "Certificate CDP: No
// URLs", and the chain came back CERT_TRUST_REVOCATION_STATUS_UNKNOWN (0x40). The renew
// handler builds a CaCertParams carrying only a subject, a validity and a digest — every
// other field defaults empty, and empty means OMIT. So the rekey dropped the CA's AIA,
// its CRLDP, its certificatePolicies, its nameConstraints and its pathLenConstraint in
// one step. The last two are the alarming ones: a constrained CA came back unconstrained.
//
// Carried as DER rather than parsed back into CaCertParams and re-encoded, for the same
// reason the subject Name is copied structurally below — a re-encode can legitimately
// produce different bytes (string types, ordering), and a nameConstraints that changes
// shape across a rekey is a policy change nobody asked for.
//
// SKI and AKI are the two that must NOT carry over: they identify the key, and the key is
// exactly what changed. build_ca_certificate_ex has already computed both correctly — the
// SKI from the key being certified, the AKI from the signer.
static void copy_ca_identity_exts(X509* dst, X509* src, bool keep_dst_urls = false) {
    const int n = X509_get_ext_count(src);
    for (int i = 0; i < n; ++i) {
        X509_EXTENSION* ext = X509_get_ext(src, i);
        if (!ext) continue;
        ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
        const int nid = OBJ_obj2nid(obj);
        if (nid == NID_subject_key_identifier || nid == NID_authority_key_identifier) continue;
        // A renewal signed by the parent takes the parent's CURRENT CRL DP and AIA — which
        // reflect data centers added since the old certificate was minted — rather than the
        // addresses the old certificate happened to carry.
        if (keep_dst_urls && (nid == NID_info_access || nid == NID_crl_distribution_points))
            continue;
        // Replace, never append: the destination already carries a basicConstraints and a
        // keyUsage built from the defaults, and RFC 5280 §4.2 permits at most one instance
        // of an extension. Matched by OBJ rather than NID so an extension OpenSSL has no
        // NID for still replaces its own kind instead of doubling up.
        for (int loc = X509_get_ext_by_OBJ(dst, obj, -1); loc >= 0;
             loc = X509_get_ext_by_OBJ(dst, obj, -1)) {
            X509_EXTENSION_free(X509_delete_ext(dst, loc));
        }
        if (!X509_add_ext(dst, ext, -1))
            throw Error(2, "cross_sign_ca: could not carry extension " + std::to_string(nid) +
                           " onto the rekeyed certificate: " + openssl_errors());
    }
}

X509Ptr cross_sign_ca(X509* signer_cert, EVP_PKEY* signer_key,
                      EVP_PKEY* subject_pubkey, const CaCertParams& p) {
    if (!signer_cert)    throw Error(1, "cross_sign_ca: no signing CA certificate");
    if (!signer_key)     throw Error(1, "cross_sign_ca: no signing CA key");
    if (!subject_pubkey) throw Error(1, "cross_sign_ca: no key to certify");

    // issuer_cert = signer_cert, so the AKI is the signer's SKI and the issuer Name is
    // the signer's subject. The SKI is hashed from subject_pubkey, so it identifies the
    // key being certified — which is the whole point of the exercise.
    X509Ptr cert = build_ca_certificate_ex(subject_pubkey, p, signer_cert);

    if (!X509_set_subject_name(cert.get(), X509_get_subject_name(signer_cert)))
        throw Error(2, "cross_sign_ca: could not copy the subject name: " + openssl_errors());

    // The CA's own extension set, carried forward across the key change.
    copy_ca_identity_exts(cert.get(), signer_cert);

    // A generation may not outlive the certificate that signs it: build_ca_certificate_ex
    // cut notAfter to signer_cert's (clamp_not_after_to_issuer). The lab's re-keyed
    // intermediate once ran to 2036 under a generation expiring in 2031, and the renew
    // handler's `days` defaults to 3650, so that cut is the ordinary case here.

    cert.reset(sign_x509(cert.release(), signer_key, pick_sig_md(signer_key, p.md, p.allow_weak_md)));
    return cert;
}

// Renewal — the certificate cross_sign_ca() cannot produce. A cross-certificate is signed
// by the CA's own previous generation, so a relying party reaches it only THROUGH that
// generation and it can never outlive it. A renewal is signed by the CA's parent, or is a
// new self-signed anchor for a root, so it chains on its own and carries its own validity.
X509Ptr renew_ca_certificate(X509* current_cert, EVP_PKEY* subject_pubkey,
                             X509* issuer_cert, EVP_PKEY* issuer_key, const CaCertParams& p) {
    if (!current_cert)   throw Error(1, "renew_ca_certificate: no current CA certificate");
    if (!subject_pubkey) throw Error(1, "renew_ca_certificate: no key to certify");
    if (!issuer_key)     throw Error(1, "renew_ca_certificate: no signing key");

    // Validity from `p`, cut to issuer_cert's notAfter when there is one; a self-signed
    // root has no issuer to be bounded by.
    X509Ptr cert = build_ca_certificate_ex(subject_pubkey, p, issuer_cert);

    // The same CA: the subject copied structurally (see cross_sign_ca for why a re-parsed
    // one-line DN is not good enough), and for a root the issuer is that same Name.
    if (!X509_set_subject_name(cert.get(), X509_get_subject_name(current_cert)))
        throw Error(2, "renew_ca_certificate: could not copy the subject name: " + openssl_errors());
    if (!issuer_cert && !X509_set_issuer_name(cert.get(), X509_get_subject_name(current_cert)))
        throw Error(2, "renew_ca_certificate: could not set the issuer name: " + openssl_errors());

    // Constraints, key usage and policies describe the CA and carry over; the CRL DP and
    // AIA come from `p`, derived from the parent now.
    copy_ca_identity_exts(cert.get(), current_cert, /*keep_dst_urls=*/true);

    // The parent's RFC 4055 restriction beats p.md, exactly as for a sub CA created under it.
    const EVP_MD* restricted = pss_restricted_md(issuer_cert);
    cert.reset(sign_x509(cert.release(), issuer_key,
                         restricted ? restricted : pick_sig_md(issuer_key, p.md, p.allow_weak_md)));
    return cert;
}

// Cross-sign a FOREIGN CA. See the header for why this is not cross_sign_ca().
X509Ptr cross_sign_foreign_ca(X509* signer_cert, EVP_PKEY* signer_key,
                              X509* foreign_cert, const CaCertParams& p) {
    if (!signer_cert)  throw Error(1, "cross_sign_foreign_ca: no signing CA certificate");
    if (!signer_key)   throw Error(1, "cross_sign_foreign_ca: no signing CA key");
    if (!foreign_cert) throw Error(1, "cross_sign_foreign_ca: no foreign CA certificate");

    // The envelope, refused rather than defaulted (header explains why).
    if (p.permitted.empty())
        throw Error(1, "cross_sign_foreign_ca: refusing to cross-sign without name "
                       "constraints — a cross-certificate with no permitted subtrees "
                       "lets the foreign CA certify any name at all");
    if (p.pathlen < 0)
        throw Error(1, "cross_sign_foreign_ca: refusing to cross-sign without an explicit "
                       "pathlen — omitting it lets the foreign CA create further CAs under "
                       "our trust");

    // It must actually BE a CA. Cross-signing a leaf would hand out a certificate that
    // says CA:TRUE over a key whose owner never asked to be one.
    if (X509_check_ca(foreign_cert) == 0)
        throw Error(1, "cross_sign_foreign_ca: the certificate to cross-sign is not a CA");

    EVP_PKEY* foreign_pub = X509_get0_pubkey(foreign_cert);
    if (!foreign_pub)
        throw Error(2, "cross_sign_foreign_ca: no public key in the foreign certificate");

    X509Ptr cert = build_ca_certificate_ex(foreign_pub, p, signer_cert);

    // THEIR subject, copied structurally — the same DER-identity argument as the rekey
    // path: a re-parsed DN can come back with different ASN.1 string types, change the
    // encoded Name, and stop the cross-certificate chaining to anything they issued.
    if (!X509_set_subject_name(cert.get(), X509_get_subject_name(foreign_cert)))
        throw Error(2, "cross_sign_foreign_ca: could not copy the foreign subject: " +
                       openssl_errors());

    // The requested digest where the signing key has a choice (RSA), the key's own rule
    // otherwise — leaf_signing_md() is that rule. ⚠️ ca_signing_md() alone ignored p.md, so
    // the console's Hash field and the CLI's --md changed nothing on a cross-certificate.
    cert.reset(sign_x509(cert.release(), signer_key,
                         leaf_signing_md(signer_key, signer_cert, p.md, p.allow_weak_md)));
    return cert;
}

void write_cert_pem(const std::filesystem::path& path, X509* cert) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_file(path.string().c_str(), "w"), &BIO_free);
    if (!bio) throw Error(2, "cannot open " + path.string() + " for write: " + openssl_errors());
    if (!PEM_write_bio_X509(bio.get(), cert))
        throw Error(2, "PEM_write_bio_X509 failed: " + openssl_errors());
}

void write_privkey_pem(const std::filesystem::path& path, EVP_PKEY* key) {
    // ⚠️ CREATED 0600, NOT NARROWED TO IT AFTERWARDS. This used BIO_new_file(path, "w"),
    // which creates with the process umask — commonly 0644 — and only then chmod'd to 0600.
    // Between those two calls a PRIVATE KEY sat on disk readable by anyone the umask allowed,
    // and the window covers the whole PEM write, not an instant. open() with the mode set
    // means the file never exists with wider permissions than it should.
    //
    // O_EXCL is deliberately NOT used: callers legitimately overwrite (a re-key writes the
    // same path), and refusing that would be a behaviour change. O_TRUNC keeps the overwrite.
    const int fd = ::open(path.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        throw Error(2, "cannot open " + path.string() + " for write: " + std::strerror(errno));
    {
        // BIO_CLOSE: the BIO owns the descriptor and closes it when it is freed.
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_fd(fd, BIO_CLOSE), &BIO_free);
        if (!bio) { ::close(fd); throw Error(2, "BIO_new_fd failed: " + openssl_errors()); }
        if (!PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr))
            throw Error(2, "PEM_write_bio_PrivateKey failed: " + openssl_errors());
    }
    // Still asserted afterwards: an existing file keeps its own mode through O_CREAT, so a
    // path that was already too open stays too open without this.
    std::error_code ec;
    std::filesystem::permissions(path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, ec);
}

// Self-sign a TLS server cert with a key the caller supplies — which may live in
// a PKCS#11 token, where generating one in memory would defeat the purpose. Split out of
// make_selfsigned_tls_pem so both paths build an identical certificate.
// The same TLS server certificate as selfsign_tls_cert(), but ISSUED BY one of our
// CAs instead of by itself.
//
// The testing posture: use end-entity service certificates (TLS, RA) issued by our sub
// CAs rather than self-signed ones — trust the root CA, place its certificate in the MS
// trusted-root store, and the sub-CA certificate in the Intermediate CA store.
//
// ⚠️ The extension set is deliberately IDENTICAL to the self-signed one, including the
// The rule is that keyEncipherment is asserted only for RSA. A listener certificate does
// not become a different KIND of certificate because a CA signed it, and having two
// slightly different shapes is how "it works self-signed but not CA-issued" bugs start.
// The differences are exactly three: the issuer name, the signing key, and AIA/CRLDP —
// which only a CA-issued certificate can carry, since a self-signed one has no issuer to
// point at.
//
// `like`, when given, is the certificate being RENEWED: its subject and its subjectAltName
// extension are carried over verbatim instead of being rebuilt from `cn` / `dns_sans`. A
// listener certificate an operator issued from the console may carry an O, an OU, extra
// DNS names, IP addresses or a UPN, and a renewal that quietly narrowed it to CN=PKI_DNS
// would break every client that connects by one of the dropped names.
X509Ptr ca_issue_tls_cert(const Config& cfg, Db& db, const std::string& ca_id,
                          X509* ca_cert, EVP_PKEY* ca_key, EVP_PKEY* key,
                          const std::string& cn, const std::vector<std::string>& dns_sans,
                          int days, X509* like = nullptr) {
    if (!ca_cert || !ca_key || !key) throw Error(2, "ca_issue_tls_cert: missing material");
    X509Ptr cert{X509_new()};
    if (!cert) throw Error(2, "X509_new failed");
    if (!X509_set_version(cert.get(), 2)) throw Error(2, "X509_set_version failed");
    set_random_serial(cert.get(), 20);

    auto subj = build_name("/CN=" + cn);
    if (!X509_set_subject_name(cert.get(), like ? X509_get_subject_name(like) : subj.get()) ||
        !X509_set_issuer_name(cert.get(), X509_get_subject_name(ca_cert)) ||
        !X509_set_pubkey(cert.get(), key))
        throw Error(2, "transport subject/issuer/pubkey set failed: " + openssl_errors());
    if (!X509_gmtime_adj(X509_getm_notBefore(cert.get()), -kClockSkewBackdateSec) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60L * 60 * 24 * days))
        throw Error(2, "validity adj failed");

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert, cert.get(), nullptr, nullptr, 0);
    add_ext_text(ctx, cert.get(), NID_basic_constraints, "critical,CA:FALSE");
    const int base_id = EVP_PKEY_get_base_id(key);
    const bool rsa = (base_id == EVP_PKEY_RSA || base_id == EVP_PKEY_RSA_PSS);
    add_ext_text(ctx, cert.get(), NID_key_usage,
                 rsa ? "critical,digitalSignature,keyEncipherment"
                     : "critical,digitalSignature");
    add_ext_text(ctx, cert.get(), NID_ext_key_usage,            "serverAuth");
    add_ext_text(ctx, cert.get(), NID_subject_key_identifier,   "hash");
    add_ext_text(ctx, cert.get(), NID_authority_key_identifier, "keyid:always");
    const int like_san = like ? X509_get_ext_by_NID(like, NID_subject_alt_name, -1) : -1;
    if (like_san >= 0) {
        // X509_add_ext copies the extension, criticality included.
        if (X509_add_ext(cert.get(), X509_get_ext(like, like_san), -1) != 1)
            throw Error(2, "could not carry the subjectAltName over: " + openssl_errors());
    } else {
        std::vector<std::string> sans = dns_sans.empty()
            ? std::vector<std::string>{cn} : dns_sans;
        std::string san;
        // ⚠️ TYPE-TAG EACH NAME, do not assume DNS. PKI_DNS may legitimately be an IP
        // literal — a lab, an appliance, anything reached by address — and a dNSName
        // holding "192.0.2.10" matches nothing: a client connecting by IP requires an
        // iPAddress SAN, so it rejects the certificate with "IP address mismatch,
        // certificate is not valid for ...". Measured with certbot against an ACME
        // listener whose SAN was DNS:192.0.2.10. general_name_of() already decides this
        // correctly for every other issuance path; these two were the ones hardcoding it.
        for (const auto& d : sans) { if (!san.empty()) san += ","; san += general_name_of(d); }
        add_ext_text(ctx, cert.get(), NID_subject_alt_name, san);
    }
    // AIA + CRLDP name the ISSUER, never the subject — derived from the issuing
    // CA's id exactly as issuance does, so a verifier can fetch the chain and the CRL.
    try {
        // ⚠️ THIS NODE'S ADDRESSES ALONE. A listener's TLS certificate is presented by a
        // listener on THIS host, during a handshake with this host. If the host is down no
        // handshake happens and nobody is validating the certificate, so naming another data
        // center only ever matters in the case where the certificate is never presented. It
        // also costs an address that is wrong whenever that data center holds no replica of
        // this CA, and a certificate's URLs cannot be corrected once it is issued.
        auto urls = ca_urls_for_instance(db, cfg, ca_id, CaUrlScope::kThisNode);
        if (!urls.ca_issuers.empty() || !urls.ocsp.empty()) {
            std::string aia;
            for (const auto& v : urls.ocsp) {
                if (!aia.empty()) aia += ",";
                aia += "OCSP;URI:" + v;
            }
            for (const auto& v : urls.ca_issuers) {
                if (!aia.empty()) aia += ",";
                aia += "caIssuers;URI:" + v;
            }
            add_ext_text(ctx, cert.get(), NID_info_access, aia);
        }
        if (!urls.crl.empty())
            add_ext_text(ctx, cert.get(), NID_crl_distribution_points,
                         join(urls.crl, "URI:", ","));
    } catch (...) { /* a listener cert without AIA still serves TLS; do not fail over it */ }

    X509* signed_cert = sign_x509(cert.get(), ca_key, ca_signing_md(ca_key, cert.get()));
    // sign_x509 TAKES OWNERSHIP on the path where it returns a DIFFERENT X509*: it has
    // already called X509_free() on the one passed in. So the unique_ptr has to let go
    // WITHOUT freeing, and release()'s value is deliberately discarded — using it, or
    // reset() on its own, would double-free.
    // cppcheck-suppress ignoredReturnValue
    if (signed_cert != cert.get()) { cert.release(); cert.reset(signed_cert); }
    return cert;
}

// `requested_md` is the operator's <SVC>_KEY_MD. Routed through leaf_signing_md
// rather than compared here, so the listener certificate obeys exactly the same per-key
// rule as an issued leaf: honoured for RSA/RSA-PSS, ignored for EC and the one-shot
// schemes (which have no choice to make), and never over an RFC 4055 §3.1 restriction.
// Empty is the previous behaviour, so a deployment that sets nothing is unchanged.
X509Ptr selfsign_tls_cert(EVP_PKEY* key, const std::string& cn,
                          const std::vector<std::string>& dns_sans, int days,
                          const std::string& requested_md = "") {
    if (!key) throw Error(2, "selfsign_tls_cert: no key");
    X509Ptr cert{X509_new()};
    if (!cert) throw Error(2, "X509_new failed");
    if (!X509_set_version(cert.get(), 2)) throw Error(2, "X509_set_version failed");   // v3
    // Our own self-signed transport cert is minted here, so it carries our prefix
    // too. It runs before any CA exists, which is fine — the prefix comes from the
    // `datacenters` table, not from a CA, and resolve_datacenter_prefix() has already run
    // by the time any listener builds its cert.
    set_random_serial(cert.get(), 20);

    auto subj = build_name("/CN=" + cn);
    if (!X509_set_subject_name(cert.get(), subj.get()) ||
        !X509_set_issuer_name(cert.get(), subj.get()) ||          // self-signed
        !X509_set_pubkey(cert.get(), key))
        throw Error(2, "self-signed subject/pubkey set failed: " + openssl_errors());
    if (!X509_gmtime_adj(X509_getm_notBefore(cert.get()), -kClockSkewBackdateSec) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60L * 60 * 24 * days))
        throw Error(2, "validity adj failed");

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);
    add_ext_text(ctx, cert.get(), NID_basic_constraints,         "critical,CA:FALSE");
    // ⚠️ keyEncipherment ONLY for RSA. The bit means "this key wraps a session key",
    // which is TLS_RSA key transport — an EC, Ed25519 or ML-DSA key cannot do it by any
    // mechanism, so asserting it states a capability the key does not have. RFC 5280
    // §4.2.1.3 ties each bit to what the key is actually for.
    //
    // It is not cosmetic here: these are the certificates a deployment SERVES from first
    // boot, before any CA exists, and their keys are minted in the token — where EC is the
    // default (make_selfsigned_tls_pem below generates P-256). So the non-compliant shape
    // was the ORDINARY one, not an edge case, and every listener presented it.
    const int base_id = EVP_PKEY_get_base_id(key);
    const bool rsa = (base_id == EVP_PKEY_RSA || base_id == EVP_PKEY_RSA_PSS);
    add_ext_text(ctx, cert.get(), NID_key_usage,
                 rsa ? "critical,digitalSignature,keyEncipherment"
                     : "critical,digitalSignature");
    add_ext_text(ctx, cert.get(), NID_ext_key_usage,             "serverAuth");
    add_ext_text(ctx, cert.get(), NID_subject_key_identifier,    "hash");
    add_ext_text(ctx, cert.get(), NID_authority_key_identifier,  "keyid:always");
    {   // SAN — modern TLS clients ignore CN and require it; default to the CN.
        std::vector<std::string> sans = dns_sans.empty()
            ? std::vector<std::string>{cn} : dns_sans;
        std::string san;
        // ⚠️ TYPE-TAG EACH NAME, do not assume DNS. PKI_DNS may legitimately be an IP
        // literal — a lab, an appliance, anything reached by address — and a dNSName
        // holding "192.0.2.10" matches nothing: a client connecting by IP requires an
        // iPAddress SAN, so it rejects the certificate with "IP address mismatch,
        // certificate is not valid for ...". Measured with certbot against an ACME
        // listener whose SAN was DNS:192.0.2.10. general_name_of() already decides this
        // correctly for every other issuance path; these two were the ones hardcoding it.
        for (const auto& d : sans) { if (!san.empty()) san += ","; san += general_name_of(d); }
        add_ext_text(ctx, cert.get(), NID_subject_alt_name, san);
    }
    // sign_x509 carries the provider workarounds a token key needs: the EC
    // pre-hash on pkcs11, the EdDSA null-md, RSA-PSS. Plain X509_sign fails on a
    // SoftHSM EC key. It may return a different X509*, so adopt whatever comes back.
    X509* signed_cert = sign_x509(cert.get(), key, leaf_signing_md(key, cert.get(), requested_md));
    // sign_x509 TAKES OWNERSHIP on the path where it returns a DIFFERENT X509*: it has
    // already called X509_free() on the one passed in. So the unique_ptr has to let go
    // WITHOUT freeing, and release()'s value is deliberately discarded — using it, or
    // reset() on its own, would double-free.
    // cppcheck-suppress ignoredReturnValue
    if (signed_cert != cert.get()) { cert.release(); cert.reset(signed_cert); }
    return cert;
}

// Encode a cert as a PEM string.
std::string x509_to_pem_string(X509* c) {
    std::unique_ptr<BIO, decltype(&BIO_free)> b(BIO_new(BIO_s_mem()), &BIO_free);
    if (!b || !PEM_write_bio_X509(b.get(), c)) return {};
    char* p = nullptr; long n = BIO_get_mem_data(b.get(), &p);
    return std::string(p, n > 0 ? static_cast<size_t>(n) : 0);
}

std::string csr_to_pem_string(X509_REQ* r) {
    std::unique_ptr<BIO, decltype(&BIO_free)> b(BIO_new(BIO_s_mem()), &BIO_free);
    if (!b || !PEM_write_bio_X509_REQ(b.get(), r)) return {};
    char* p = nullptr; long n = BIO_get_mem_data(b.get(), &p);
    return std::string(p, n > 0 ? static_cast<size_t>(n) : 0);
}

std::string x509_name_oneline(const X509_NAME* n) {
    if (!n) return {};
    char buf[512] = {0};
    X509_NAME_oneline(const_cast<X509_NAME*>(n), buf, static_cast<int>(sizeof buf));
    return std::string(buf);
}

std::pair<std::string, std::string>
make_selfsigned_tls_pem(const std::string& cn,
                        const std::vector<std::string>& dns_sans, int days) {
    return make_selfsigned_tls_pem(cn, dns_sans, days, ServiceKeySpec{});
}

// Honour the service's key choice on a FILE key, not only on a pkcs11: one.
// ServiceKeySpec{} is ec/P-256 — the value this hardcoded — so a deployment that has not
// set <SVC>_KEY_ALGO produces exactly what it produced before.
std::pair<std::string, std::string>
make_selfsigned_tls_pem(const std::string& cn,
                        const std::vector<std::string>& dns_sans, int days,
                        const ServiceKeySpec& keyspec) {
    EvpPkeyPtr key = generate_key_ex(keyspec.algo, keyspec.bits, keyspec.curve);
    if (!key) throw Error(2, "make_selfsigned_tls: key generation failed");
    X509Ptr cert = selfsign_tls_cert(key.get(), cn, dns_sans, days, keyspec.md);

    auto bio_to_string = [](BIO* b) {
        char* p = nullptr; long n = BIO_get_mem_data(b, &p);
        return std::string(p, n > 0 ? static_cast<size_t>(n) : 0);
    };
    std::unique_ptr<BIO, decltype(&BIO_free)> cbio(BIO_new(BIO_s_mem()), &BIO_free);
    std::unique_ptr<BIO, decltype(&BIO_free)> kbio(BIO_new(BIO_s_mem()), &BIO_free);
    if (!cbio || !kbio) throw Error(2, "BIO_new failed");
    if (!PEM_write_bio_X509(cbio.get(), cert.get()))
        throw Error(2, "PEM_write_bio_X509 failed: " + openssl_errors());
    if (!PEM_write_bio_PrivateKey(kbio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr))
        throw Error(2, "PEM_write_bio_PrivateKey failed: " + openssl_errors());
    return { bio_to_string(cbio.get()), bio_to_string(kbio.get()) };
}

TransportCert resolve_transport_cert(const std::filesystem::path& cert_path,
                                     const std::filesystem::path& key_path,
                                     const std::string& dns,
                                     const ServiceKeySpec& keyspec) {
    std::error_code ec;
    if (!cert_path.empty() && !key_path.empty() &&
        std::filesystem::exists(cert_path, ec) && std::filesystem::exists(key_path, ec))
        return { true, {}, {}, {}, {} };              // a real CA-issued cert on disk wins
    const std::string cn = !dns.empty() ? dns : std::string("localhost");
    std::vector<std::string> sans{ cn };
    if (cn != "localhost") sans.emplace_back("localhost");
    auto [cert_pem, key_pem] = make_selfsigned_tls_pem(cn, sans, 90, keyspec);
    return { false, std::move(cert_pem), std::move(key_pem), {}, {} };
}

namespace {

// A cert is only servable with the key we actually hold. Nothing checked this
// before, so a row belonging to another node (or a stale one) would have been handed
// to the listener as a mismatched pair and failed every handshake.
// Compare two public keys by their encoded SubjectPublicKeyInfo. EVP_PKEY_eq compares
// key OBJECTS and fails across providers when the same EC key is described differently
// (named curve vs explicit parameters), which is what a pkcs11 public object does. The
// SPKI bytes are canonical, and every provider can emit them — `openssl storeutl` prints
// a token's public object as a PUBLIC KEY PEM, which is exactly this encoding.
bool same_public_key(EVP_PKEY* a, EVP_PKEY* b) {
    if (!a || !b) return false;
    unsigned char *da = nullptr, *db = nullptr;
    const int la = i2d_PUBKEY(a, &da);
    const int lb = i2d_PUBKEY(b, &db);
    const bool ok = la > 0 && la == lb && std::memcmp(da, db, static_cast<size_t>(la)) == 0;
    OPENSSL_free(da); OPENSSL_free(db);
    ERR_clear_error();
    return ok;
}

// Load the PUBLIC object at a pkcs11 URI. load_signing_key() accepts only
// OSSL_STORE_INFO_PKEY and throws on anything else, so it cannot be reused: a token's
// public object arrives as OSSL_STORE_INFO_PUBKEY.
EvpPkeyPtr load_pubkey_uri(const std::string& uri, const Config& cfg) {
    if (uri.rfind("pkcs11:", 0) != 0) return nullptr;
    ensure_pkcs11_provider(cfg);
    std::unique_ptr<OSSL_STORE_CTX, decltype(&OSSL_STORE_close)>
        ctx(OSSL_STORE_open(uri.c_str(), nullptr, nullptr, nullptr, nullptr), &OSSL_STORE_close);
    if (!ctx) { ERR_clear_error(); return nullptr; }
    EvpPkeyPtr pub;
    while (!OSSL_STORE_eof(ctx.get())) {
        std::unique_ptr<OSSL_STORE_INFO, decltype(&OSSL_STORE_INFO_free)>
            info(OSSL_STORE_load(ctx.get()), &OSSL_STORE_INFO_free);
        if (!info) continue;
        if (OSSL_STORE_INFO_get_type(info.get()) == OSSL_STORE_INFO_PUBKEY) {
            pub.reset(OSSL_STORE_INFO_get1_PUBKEY(info.get()));
            break;
        }
    }
    ERR_clear_error();
    return pub;
}

}  // namespace — build_issuer_chain is exported, so it leaves the anonymous one

// Build the intermediate chain for a transport cert by walking issuers through
// the registered CAs. Endpoints previously sent only the leaf, so a client that trusts
// the ROOT (the normal case — a GPO-distributed root) could not build a path and failed
// with WinHttp 12045 unless every intermediate was installed by hand on each machine.
// The root itself is deliberately NOT appended: a server should send intermediates only
// (RFC 8446 §4.4.2), and the client is expected to hold the anchor.
// `anchor_pem`, when the caller passes one, receives the self-signed root the walk
// stops at. Both halves come out of ONE walk on purpose — Postgres serves the leaf +
// intermediates while the app dials it with sslrootcert=<anchor>, and a caller that
// computed those separately could pair a chain with the wrong anchor and produce a
// database nothing can connect to.
std::string build_issuer_chain(Db& db, X509* leaf, std::string* anchor_pem) {
    if (anchor_pem) anchor_pem->clear();
    if (!leaf) return {};
    std::string chain;
    X509Ptr owned;                 // keeps the current link alive while we walk
    X509* cur = leaf;
    std::set<std::string> seen;    // guards a mis-registered CA that loops
    for (int depth = 0; depth < 8; ++depth) {
        X509_NAME* iss = X509_get_issuer_name(cur);
        X509_NAME* sub = X509_get_subject_name(cur);
        // ⚠️ SELF-ISSUED IS NOT SELF-SIGNED. This used to stop on
        // `X509_NAME_cmp(iss, sub) == 0`, which is true of a REKEYED CA: rekeying certifies
        // the new key under the CA's OWN OLD key, so subject == issuer while the signature
        // does not verify against its own public key. The walk stopped dead there, neither
        // the previous generation nor the root went on the wire, and a client anchored on
        // the root was back to exactly the WinHttp 12045 failure this function exists to
        // prevent — reintroduced by the act of rekeying. Only a real trust anchor, one
        // whose signature verifies with its own key, ends a chain.
        if (!iss || !sub) break;
        if (x509_is_self_signed(cur)) break;                  // the signature, not EXFLAG_SS
        // ⚠️ BOTH GENERATIONS OF A REKEYED CA CARRY THE SAME SUBJECT, so "the CA whose
        // subject equals my issuer" is ambiguous mid-rollover and can hand back the very
        // certificate we are standing on. The AKI names the KEY that signed this one;
        // prefer the generation whose SKI matches it, and fall back to the name only when
        // there is nothing better (a CA registered without a subjectKeyIdentifier).
        const ASN1_OCTET_STRING* akid = X509_get0_authority_key_id(cur);
        X509Ptr found;
        std::string found_id;
        try {
            for (int pass = 0; pass < 2 && !found; ++pass) {
                const bool require_key = (pass == 0) && akid != nullptr;
                for (const auto& ci : db.list_ca_instances()) {
                    // Try BOTH sources and pick whichever actually has the issuer's
                    // subject. get_ca_cert_der() is not the CA's own certificate — it
                    // returns the newest cert ISSUED BY that CA (an enrolment leaf), so
                    // testing only it silently matched nothing while looking like it had
                    // a candidate. signing_ca_pem is where fastpki-ca pins the CA cert.
                    X509Ptr cand;
                    auto subject_is_issuer = [&](const X509Ptr& c) {
                        if (!c || X509_NAME_cmp(X509_get_subject_name(c.get()), iss) != 0)
                            return false;
                        if (!require_key) return true;
                        const ASN1_OCTET_STRING* skid = X509_get0_subject_key_id(c.get());
                        return skid && ASN1_OCTET_STRING_cmp(akid, skid) == 0;
                    };
                    if (auto info = db.get_ca_cert_der(ci.id); info && !info->der.empty()) {
                        X509Ptr from_db = parse_cert_der(info->der);
                        if (subject_is_issuer(from_db)) cand = std::move(from_db);
                    }
                    // signing_ca_pem is the certificate itself. This used to test
                    // std::filesystem::exists() on it and open it as a file — which, once
                    // the field became PEM content, could only ever fail, silently, on the
                    // path that decides whether a chain can be built at all.
                    if (!cand && !ci.signing_ca_pem.empty()) {
                        try {
                            X509Ptr stored = load_ca_cert_pem(ci.signing_ca_pem);
                            if (subject_is_issuer(stored)) cand = std::move(stored);
                        } catch (...) {}
                    }
                    // Both of those are the NEWEST generation. A certificate signed by an
                    // older, still-live generation's key (issued before the CA was renewed
                    // with a new key) matches none of them by key, and the name-only pass
                    // would then pick the newest — the wrong key, and for a root the wrong
                    // anchor. Every live generation is a candidate for the key match.
                    if (!cand && require_key) {
                        try {
                            for (const auto& g : db.get_ca_chain_ders(ci.id)) {
                                X509Ptr gx = parse_cert_der(g.der);
                                if (subject_is_issuer(gx)) { cand = std::move(gx); break; }
                            }
                        } catch (...) {}
                    }
                    if (cand) {
                        found = std::move(cand);
                        found_id = ci.id;
                        break;
                    }
                }
                if (!akid) break;   // pass 1 would repeat pass 0 exactly
            }
        } catch (...) { break; }
        if (!found) break;
        // Only intermediates go on the wire; stop once we reach a self-signed root.
        // ⚠️ Same distinction as above, and it bit harder here: this decided is_root by
        // name and then broke BEFORE appending, so a leaf issued by a rekeyed CA got an
        // EMPTY chain — not merely a short one.
        const bool is_root = x509_is_self_signed(found.get());
        std::string der_key;
        { auto d = x509_to_der(found.get()); der_key.assign(d.begin(), d.end()); }
        if (!seen.insert(der_key).second) break;
        if (is_root) {
            if (anchor_pem) *anchor_pem = x509_to_pem_string(found.get());
            // ⚠️ A ROOT RENEWED WITH A NEW KEY HAS A BRIDGE: its new key certified by the
            // previous root. The bridge is not an anchor, and a relying party still anchored
            // on the previous root reaches the new key only through it — so it goes on the
            // wire even though the walk ends here. A root that was never renewed with a new
            // key has no such generation and nothing is added.
            if (!found_id.empty()) {
                try {
                    for (const auto& g : db.get_ca_chain_ders(found_id)) {
                        X509Ptr gx = parse_cert_der(g.der);
                        if (!gx || x509_is_self_signed(gx.get())) continue;
                        std::string k;
                        { auto d = x509_to_der(gx.get()); k.assign(d.begin(), d.end()); }
                        if (seen.insert(k).second) chain += x509_to_pem_string(gx.get());
                    }
                } catch (...) {}
            }
            break;
        }
        chain += x509_to_pem_string(found.get());
        // ⚠️ Send EVERY live generation of this CA, not just the one that signed the
        // previous link. ResolvedCa says it outright — "anything serving a chain should
        // send all of these" — and this function was sending one. A client anchored on the
        // ROOT needs the older generation to bridge a rekeyed (self-issued) certificate
        // back to the parent; without it the path cannot be built at all. Walking on from
        // the OLDEST generation is also what lets the loop reach the root in the first
        // place, since the newest one's issuer is the CA itself.
        X509Ptr oldest;
        if (!found_id.empty()) {
            try {
                for (const auto& g : db.get_ca_chain_ders(found_id)) {
                    X509Ptr gx = parse_cert_der(g.der);
                    if (!gx) continue;
                    std::string k;
                    { auto d = x509_to_der(gx.get()); k.assign(d.begin(), d.end()); }
                    if (!seen.insert(k).second) continue;                 // already sent
                    if (x509_is_self_signed(gx.get())) continue;          // anchors stay off the wire
                    chain += x509_to_pem_string(gx.get());
                    oldest = std::move(gx);                               // newest-first, so this ends oldest
                }
            } catch (...) {}
        }
        if (oldest) { cur = oldest.get(); owned = std::move(oldest); }
        else        { cur = found.get();  owned = std::move(found); }
    }
    return chain;
}

namespace {

// Hand an owned EVP_PKEY to TransportCert, which is copied into listener lambdas.
std::shared_ptr<EVP_PKEY> share_key(EvpPkeyPtr k) {
    return std::shared_ptr<EVP_PKEY>(k.release(), [](EVP_PKEY* p) { EVP_PKEY_free(p); });
}

// `pub_for_match` is the token's own public object, supplied when the private key is
// token-resident and therefore carries no comparable public component itself.
bool cert_matches_key(const std::string& cert_pem, EVP_PKEY* key,
                      EVP_PKEY* pub_for_match = nullptr) {
    if (!key || cert_pem.empty()) return false;
    auto certs = load_certs_pem_mem(cert_pem);
    if (certs.empty()) return false;
    X509* c = certs.front().get();
    if (X509_check_private_key(c, key) == 1) return true;
    ERR_clear_error();
    EVP_PKEY* cert_pub = X509_get0_pubkey(c);
    if (!cert_pub) return false;
    if (same_public_key(cert_pub, pub_for_match ? pub_for_match : key)) return true;
    return false;
}

// Publish a transport cert into the certs table under `cert_id` so the next
// start finds it instead of minting a new identity.
//
// `ca_instance_id` NAMES THE ISSUER, and empty means self-signed. It used to be
// hardcoded empty here on the grounds that "a transport cert is not issued by any of our
// CAs" — which stopped being true the moment this file learned to issue one, and the
// omission cost more than a wrong column:
//
//   - a CA-issued listener certificate was stored looking self-signed, so the candidate
//     query's `ORDER BY (ca_instance_id IS NOT NULL) DESC` could not prefer it over a
//     90-day self-signed fallback, and "never persist over a CA-issued row" could
//     not see it either — both of those turn on telling the two apart;
//   - and because the issuer was not recorded, the CA had to be named again in config on
//     every start. That is the whole reason the TRANSPORT_CA_ID key existed.
//
// The issuing CA should be knowable from its leaf certificate, and unnecessary
// redundancy is worth avoiding. Correct on both counts. The column is how every
// other service certificate already records it (service_cert.cpp), and the key is gone.
void publish_transport_cert(Db& db, const std::string& cert_id, X509* cert,
                            const std::string& ca_instance_id = {}) {
    // Transport certs are tagged rows in `certs` now. insert_cert derives the
    // RFC 4387 selector hashes, key/sig algorithms and is_ca from the DER, so only the
    // identifying fields are set here.
    //
    // ⚠️ insert_cert has no ON CONFLICT — it throws on a duplicate serial. That is
    // correct here: a re-published identical cert is already in the table, and the
    // accumulates rather than upserting, so silently overwriting would be wrong.
    pki::CertRow row;
    row.serial     = x509_serial_hex(cert);
    row.status     = 0;
    row.cert_der   = x509_to_der(cert);
    row.cert_id    = cert_id;
    row.ca_instance_id = ca_instance_id;   // empty => self-signed, as before
    row.cn         = x509_cn(cert);
    row.subject    = row.cn;          // same convention as the console's insert paths
    row.not_before = x509_not_before_unix(cert);
    row.not_after  = x509_not_after_unix(cert);
    db.insert_cert(row);
}

} // namespace

// See the header for why a listener certificate is scoped by NODE and not by CA.
std::string listener_cert_id(const Config& cfg, const std::string& base) {
    if (base.empty() || cfg.datacenter_id.empty()) return base;
    // Idempotent: an operator who already wrote MS_CERT_ID=ms-dc1 gets ms-dc1, not
    // ms-dc1-dc1. Without this, one explicit config would double-suffix on every start
    // and the id would drift away from the row that holds the certificate.
    const std::string suffix = "-" + cfg.datacenter_id;
    if (base.size() > suffix.size() &&
        base.compare(base.size() - suffix.size(), suffix.size(), suffix) == 0) return base;
    return base + suffix;
}

// ⚠️ AND THE KEY OBJECT IS SCOPED THE SAME WAY, OR THE TWO HALVES DISAGREE ON A SHARED
// TOKEN. `object=` is not a unique selector — CKA_LABEL is free text, PKCS#11 permits
// duplicates, and the provider returns AN arbitrary match. With a token per node that never
// mattered: one node, one `web-tls`. Under P11_TLS or a network HSM every node reaches ONE
// token and each mints its own key under the SAME label, so `object=acme-tls` resolves to a
// peer's object while the certificate is this node's — and `type=private` and `type=public`
// are two independent lookups, so a listener can even load one node's private half beside
// another's public half. Measured on a three-node mesh: two objects each labelled web-tls,
// est-tls and acme-tls, and a listener refusing to start with
//
//     transport TLS: the token-resident private key was refused ... key values mismatch
//
// The cert id is already node-scoped by listener_cert_id(); this makes the key agree.
// DERIVED rather than written into the config on purpose: both halves then come out of the
// same cfg.datacenter_id in the same place and cannot drift, and no installer has to encode
// the rule — deploy/bootstrap.compose.conf is bind-mounted READ-ONLY and the file wins over
// the environment for every key but PG_CONNINFO, so there is no per-node channel there.
//
// ⚠️ ONLY THE FOUR LISTENER KEYS GO THROUGH HERE. A CA key must NOT: the shared-token shape
// exists precisely because `object=<ca_id>` names the same object from every node, which is
// what `fastpki-ca key add` relies on. Nor the RA credentials — their certificate id is
// `<prefix>-<ca_id>` with no node component, so they belong to the CA and are correctly
// shared; giving each node its own would make every node's issuance retire its peers'.
std::string listener_key_uri(const Config& cfg, const std::string& raw) {
    if (raw.empty() || cfg.datacenter_id.empty()) return raw;
    if (raw.rfind("pkcs11:", 0) != 0) return raw;   // a file path is already node-local
    const std::string needle = "object=";
    const size_t p = raw.find(needle);
    if (p == std::string::npos) return raw;
    const size_t vs = p + needle.size();
    size_t ve = raw.find_first_of(";?", vs);
    if (ve == std::string::npos) ve = raw.size();
    const std::string obj = raw.substr(vs, ve - vs);
    if (obj.empty()) return raw;
    // Idempotent for the same reason listener_cert_id() is: an operator who already wrote
    // object=web-tls-dc1 gets that, not web-tls-dc1-dc1 on every start.
    const std::string suffix = "-" + cfg.datacenter_id;
    if (obj.size() > suffix.size() &&
        obj.compare(obj.size() - suffix.size(), suffix.size(), suffix) == 0) return raw;
    return raw.substr(0, ve) + suffix + raw.substr(ve);
}

TransportCert resolve_transport_cert(Db& db, const std::string& raw_cert_id,
                                     const std::filesystem::path& cert_path,
                                     const std::filesystem::path& key_path,
                                     const Config& cfg,
                                     const std::string& dns,
                                     const ServiceKeySpec& keyspec) {
    // Scope the id to this node BEFORE anything looks it up or publishes under it,
    // so the lookup and the publish cannot disagree — that disagreement is the bug.
    const std::string cert_id = listener_cert_id(cfg, raw_cert_id);
    // The key object is scoped to this node for the same reason, and in the same breath —
    // every use below goes through this, never through key_path directly.
    const std::string key_uri = listener_key_uri(cfg, key_path.string());
    // The local private key gates everything: a cert we cannot sign with is useless,
    // whichever source it came from. Loaded once, from a file or a token — a TRANSPORT
    // key is not a CA key, so unlike load_signing_key this side still accepts a path
    // (the deploy-time self-signed pair in §3c is exactly that shape).
    const bool token_key = key_uri.rfind("pkcs11:", 0) == 0;
    EvpPkeyPtr pkey;
    // ⚠️ "THE TOKEN DID NOT ANSWER" IS FATAL TO THIS PROCESS, SO DO NOT CARRY ON WITH IT.
    // PKCS#11 is initialised once per process: a provider that came up against an absent
    // token stays broken for this process's life. Measured — a listener in that state never
    // recovered across four 20-second retries while a fresh process read the same object
    // immediately, and only a restart fixed it. Carrying on means serving a self-signed
    // certificate no client can verify until somebody notices, which on an HA pair is one
    // host silently unverifiable — the symptom that produced this check: three listeners left that
    // way by the restarts an ordinary demo run performs).
    //
    // Exiting is safe here precisely BECAUSE the cases are now distinguishable. A fresh
    // install, where the token answers and holds no object yet, throws code 2 and is left to
    // the tolerant path below — it must keep serving so the console is reachable to create
    // the CA at all. Only kErrTokenUnavailable exits, and if the token really is down then a
    // listener that is down is the honest state, not one presenting a certificate that
    // cannot be verified.
    try { pkey = load_key_file_or_token(key_uri, cfg); }
    catch (const Error& e) {
        if (e.code() == kErrTokenUnavailable) {
            log::err(std::string("the PKCS#11 token did not answer for '") + raw_cert_id +
                     "': " + e.what() +
                     " — PKCS#11 is initialised once per process, so this one cannot recover. "
                     "Exiting so the restart policy supplies a fresh provider connection "
                     "rather than serving a certificate no client can verify.");
            std::_Exit(0);
        }
    }
    catch (...) {}
    // A token key is minted on first use — there is nothing to find until then,
    // and a token will not accept an imported one.
    if (token_key && !pkey) {
        try {
            // Was hardcoded `ec`/P-256 here, which made the choice invisible to
            // whoever installs FastPKI — and then briefly ONE shared setting, which made
            // it a choice they could not make per service. Defaults are unchanged.
            pkey = generate_key_in_token(key_uri, cfg, keyspec.algo,
                                         keyspec.bits, keyspec.curve);
            pki::log::info("generated a " + keyspec.algo +
                           " transport key inside the token for '" + cert_id + "'");
        } catch (const std::exception& e) {
            pki::log::info(std::string("could not generate a token key for '") + cert_id +
                           "': " + e.what());
        }
    }
    // A `type=private` URI loads only the private object, which carries no public
    // component, so keep the token's matching PUBLIC object for cert comparison.
    EvpPkeyPtr token_pub;
    if (token_key && pkey) {
        std::string pub_uri = key_uri;
        const std::string needle = "type=private";
        if (auto at = pub_uri.find(needle); at != std::string::npos)
            pub_uri.replace(at, needle.size(), "type=public");
        token_pub = load_pubkey_uri(pub_uri, cfg);
        // Say so when it is missing. A private object without its public twin cannot be
        // compared against a certificate, so every candidate would be rejected and the
        // listener would fall back with nothing in the log to say why. This is a real
        // shape a token can be in — SoftHSM will happily hold a private object whose
        // public twin was never created — and the whole decision is invisible without it.
        if (!token_pub)
            pki::log::info("transport key for '" + cert_id + "' has no public object in the "
                           "token, so no certificate can be matched to it — the listener will "
                           "fall back. Regenerate the key so the pair exists.");
    }

    // A self-signed fallback must NEVER overwrite a CA-issued row.  Track
    // whether the existing DB entry (if any) was issued by one of our CAs, so the
    // fallback at the bottom can decide whether to persist or keep it in memory only.
    // has_ca_issued is GONE, deliberately. It was a guard against a
    // self-signed fallback overwriting a CA-issued row — but with transport certs as
    // tagged rows in `certs`, insert_cert keys on serial and has no ON CONFLICT, so
    // nothing can overwrite anything. The protection is now structural. Keeping the
    // flag would also have made it unreachable: every path where cert_matches_key
    // succeeds RETURNS below, so it could never be true where it used to be read.
    // What can still go wrong is a self-signed row being CHOSEN over a CA-issued one,
    // and that is handled by the candidate ordering, not by a flag.

    // 1. The certs published under this cert_id — every DC's, because `certs`
    //    replicates. Only the one matching THIS node's key is ours.
    // Does a LIVE CA-issued certificate already exist under this cert_id, for some
    // key? If so we must not mint another — see the re-issue block below.
    bool live_ca_issued = false;
    if (pkey) {
        try {
            for (const auto& cand : db.list_transport_candidates(cert_id)) {
                if (cand.der.empty()) continue;
                if (!cand.ca_instance_id.empty()) live_ca_issued = true;
                std::string cert_pem = der_to_pem_cert(cand.der);
                if (cert_matches_key(cert_pem, pkey.get(), token_pub.get())) {
                    std::string chain;   // intermediates, so clients that trust
                    {                    // only the root can build a path.
                        auto lc = load_certs_pem_mem(cert_pem);
                        if (!lc.empty()) chain = build_issuer_chain(db, lc.front().get());
                    }
                    if (token_key)   // no PEM exists for a token key
                        return { false, std::move(cert_pem), {}, std::move(chain),
                                 share_key(std::move(pkey)) };
                    std::string key_pem = evp_pkey_to_pem(pkey.get());
                    if (!key_pem.empty())
                        return { false, std::move(cert_pem), std::move(key_pem),
                                 std::move(chain), {} };
                }
                // Not ours — almost certainly a peer's row for the same cert_id, which
                // is normal on a mesh. Keep looking; do NOT log per row.
            }
        } catch (const std::exception& e) {
            // Was a bare `catch (...) {}`. The DB genuinely may not be ready yet, which is
            // why this is not fatal — but swallowing it without a word means the one
            // decision an operator cares about (which certificate am I serving, and why
            // not the one I just issued?) has no explanation anywhere.
            pki::log::info(std::string("could not use the published transport cert for '") +
                           cert_id + "': " + e.what() + " — falling back");
        } catch (...) {
            pki::log::info("could not use the published transport cert for '" + cert_id +
                           "' (unknown error) — falling back");
        }
    }

    // 2. Adopt a cert sitting beside the key. Deployments provisioned before the DB
    //    have a real CA-issued cert on disk that nothing reads any more, because the
    //    *_CERT config keys were dropped; publish it instead of replacing it.
    std::filesystem::path disk = cert_path;
    if (disk.empty() && !key_path.empty() && key_path.string().rfind("pkcs11:", 0) != 0) {
        disk = key_path;                       // …/ms.key → …/ms.crt
        disk.replace_extension(".crt");
    }
    std::error_code ec;
    if (pkey && !disk.empty() && std::filesystem::exists(disk, ec)) {
        try {
            X509Ptr on_disk = load_cert_pem(disk);
            if (on_disk && X509_check_private_key(on_disk.get(), pkey.get()) == 1) {
                try {
                    publish_transport_cert(db, cert_id, on_disk.get());
                    pki::log::info("adopted the on-disk transport cert " + disk.string() +
                              " as '" + cert_id + "'");
                } catch (...) { /* DB write failed — still serve it this run */ }
                // Return the PEM itself, NOT use_files: `disk` may have been derived
                // from the key path, and the caller only knows the (now empty) *_CERT
                // setting — handing it use_files would leave it with no cert at all.
                // Read the file verbatim so any chain in it is preserved.
                std::ifstream in(disk, std::ios::binary);
                std::string cert_pem((std::istreambuf_iterator<char>(in)),
                                      std::istreambuf_iterator<char>());
                std::string chain = build_issuer_chain(db, on_disk.get());
                if (token_key && !cert_pem.empty())
                    return { false, std::move(cert_pem), {}, std::move(chain),
                             share_key(std::move(pkey)) };
                std::string key_pem = evp_pkey_to_pem(pkey.get());
                if (!cert_pem.empty() && !key_pem.empty())
                    return { false, std::move(cert_pem), std::move(key_pem), std::move(chain), {} };
            }
        } catch (...) { /* unreadable — fall through to self-signed */ }
    }

    // 2c. ISSUE IT FROM ONE OF OUR CAs, when the deployment names one.
    //
    // The testing posture: end-entity service certificates (TLS, RA) issued by our sub
    // CAs, not self-signed ones. Until now `resolve_transport_cert` had three
    // paths — a published row, a cert adopted from disk, self-sign — and NONE of them
    // asked a CA. Measured on the lab: web, est and acme all served self-signed
    // certificates; `ms` looked CA-issued only because a legacy ms.crt beside its key was
    // being adopted by the path above.
    //
    // ⚠️ THIS RUNS BEFORE THE SELF-SIGN FALLBACK AND AFTER EVERYTHING ELSE, and the order
    // is the design. Self-sign is NOT dead code to be removed once this works: a fresh
    // deployment has no CA at all and the console must still serve TLS so an
    // admin can log in and create the first one. A node with no PREVIOUS CA-issued
    // listener certificate, or whose recorded CA is not resolvable here, keeps exactly
    // its old behaviour.
    //
    // ⚠️ WHICH CA IS READ OFF THE LAST CERTIFICATE, NOT OUT OF CONFIG. This used to
    // consult a TRANSPORT_CA_ID key; that was redundant, since the issuing CA is
    // knowable from the leaf certificate itself. The issuer is
    // recorded on the row by publish_transport_cert, so re-issuing after expiry asks the
    // certificate we last served who signed it. The FIRST CA-issued listener certificate
    // still comes from an operator, through the console's "Serve as ..." flow, exactly as
    // every RA credential does; nothing here mints one from a CA nobody chose.
    //
    // ⚠️ A CA this node holds no KEY for is not an error — in a mesh every node sees every
    // CA, its own with a pkcs11 key and the others as keyless trust anchors. That is the
    // same distinction service_cert.cpp draws when renewing RA credentials, and getting it
    // wrong would make two thirds of a healthy mesh log failures on every start.
    // ⚠️ ONLY WHEN NO LIVE CA-ISSUED CERTIFICATE EXISTS. The trigger is an EXPIRED
    // predecessor, not an unmatched one. The case to protect is a valid CA-issued row for a key
    // this node cannot match — a peer's row, since `certs` replicates — and there the
    // established behaviour is to self-sign for serving and leave that row alone. Minting
    // a second certificate there would be this node deciding it should hold a credential
    // for an identity another node already holds, which is not what was asked for and
    // would silently change a guarantee transport_cert_stable.sh pins.
    const std::string prev_ca_id =
        (pkey && !live_ca_issued) ? db.get_transport_ca_id(cert_id) : std::string();
    if (pkey && !prev_ca_id.empty()) {
        const std::string cn = !dns.empty() ? dns : std::string("localhost");
        std::vector<std::string> sans{ cn };
        if (cn != "localhost") sans.emplace_back("localhost");
        try {
            auto mat = db.get_ca_instance(prev_ca_id);
            // ⚠️ THE REVOKED/EXPIRED GATE APPLIES HERE TOO. This reads signing_ca_pem and
            // signing_ca_key straight off the CaInstance, so it never passed through
            // resolve_ca_instance() — the one place that refuses a revoked or expired CA. It
            // runs unattended when a transport certificate is re-issued, so a CA an operator
            // had just revoked would sign again with nobody asking it to. Falling back to
            // self-signing is the existing, correct behaviour for "this CA cannot sign here",
            // and it is what the no-local-key branch already does.
            if (!mat || mat->signing_ca_pem.empty() || mat->signing_ca_key.empty() ||
                mat->revoked || mat->expired) {
                pki::log::info("transport cert '" + cert_id + "': not re-issuing under CA '" +
                               prev_ca_id + "' (" +
                               (!mat ? "unknown CA"
                                     : mat->revoked ? "its certificate is revoked"
                                     : mat->expired ? "its certificate has expired"
                                     : "this node holds no signing key for it") +
                               ") — self-signing instead");
            } else {
                auto cacert = load_ca_cert_pem(mat->signing_ca_pem);
                auto cakey  = load_signing_key(mat->signing_ca_key, cfg);
                if (cacert && cakey) {
                    X509Ptr c = ca_issue_tls_cert(cfg, db, prev_ca_id, cacert.get(),
                                                  cakey.get(), pkey.get(), cn, sans, 90);
                    // The same check service_cert.cpp makes: a certificate that does not
                    // certify the key we hold would have us sign with one key and present
                    // another, and every handshake would fail to verify. Catch it HERE,
                    // where the log says why, not at the first request.
                    if (c && cert_certifies_key(c.get(), pkey.get())) {
                        try { publish_transport_cert(db, cert_id, c.get(), prev_ca_id); }
                        catch (const std::exception& e) {
                            pki::log::err("could not persist the CA-issued transport cert '" +
                                          cert_id + "': " + e.what());
                        }
                        std::string pem = x509_to_pem_string(c.get());
                        std::string chain = build_issuer_chain(db, c.get());
                        if (!pem.empty()) {
                            pki::log::info("re-issued the transport cert for '" + cert_id +
                                           "' from CA '" + prev_ca_id +
                                           "', which issued the previous one");
                            if (token_key)
                                return { false, std::move(pem), {}, std::move(chain),
                                         share_key(std::move(pkey)) };
                            std::string key_pem = evp_pkey_to_pem(pkey.get());
                            if (!key_pem.empty())
                                return { false, std::move(pem), std::move(key_pem),
                                         std::move(chain), {} };
                        }
                    } else {
                        pki::log::err("the CA-issued transport cert for '" + cert_id +
                                      "' does not match this node's key — self-signing");
                    }
                }
            }
        } catch (const std::exception& e) {
            pki::log::info(std::string("could not re-issue the transport cert for '") + cert_id +
                           "' from CA '" + prev_ca_id + "': " + e.what() +
                           " — self-signing instead");
        }
    }

    // 3. Nothing usable: self-sign ONCE and persist BOTH halves, so the next start
    //    reuses this identity instead of handing every client a brand-new one.
    //    Persist ONLY when nothing is there, or when what is there is itself
    //    self-signed — never over a CA-issued row.
    if (token_key && pkey) {
        // Self-sign against the token key: make_selfsigned_tls_pem() generates its own
        // in-memory key, which would defeat the point.
        const std::string cn = !dns.empty() ? dns : std::string("localhost");
        std::vector<std::string> sans{ cn };
        if (cn != "localhost") sans.emplace_back("localhost");
        try {
            X509Ptr c = selfsign_tls_cert(pkey.get(), cn, sans, 90);
            if (c) {
                // Publish unconditionally. Nothing can be overwritten — rows key
                // on serial and insert_cert has no ON CONFLICT — so that concern is
                // structurally answered. A CA-issued row that already exists keeps
                // winning the candidate ordering on the next start regardless.
                //
                // ⚠️ Do NOT swallow the error the way this used to. If the insert fails
                // the node cannot persist its identity and will re-mint one on every
                // start; that must be visible, not a bare `catch (...) {}`.
                try {
                    publish_transport_cert(db, cert_id, c.get());
                } catch (const std::exception& e) {
                    pki::log::err("could not persist the self-signed transport cert '" +
                                  cert_id + "': " + e.what() +
                                  " — this node will generate a NEW identity on every start "
                                  "until this is fixed");
                }
                std::string pem = x509_to_pem_string(c.get());
                if (!pem.empty()) {
                    pki::log::info("self-signed a transport cert for '" + cert_id +
                                   "' with the token key");
                    return { false, std::move(pem), {}, {}, share_key(std::move(pkey)) };
                }
            }
        } catch (const std::exception& e) {
            pki::log::info(std::string("token self-sign failed for '") + cert_id +
                           "': " + e.what());
        }
    }
    TransportCert tc = resolve_transport_cert(cert_path, key_path, dns, keyspec);
    if (tc.use_files || tc.cert_pem.empty() || tc.key_pem.empty()) return tc;
    const bool key_on_disk =
        !key_path.empty() && key_path.string().rfind("pkcs11:", 0) != 0;
    try {
        auto certs = load_certs_pem_mem(tc.cert_pem);
        if (!certs.empty()) {
            // Key first. A cert published with no key to sign with is the one state
            // that leaves the listener unable to come up on the next start.
            if (key_on_disk) {
                std::unique_ptr<BIO, decltype(&BIO_free)>
                    kb(BIO_new_mem_buf(tc.key_pem.data(),
                                       static_cast<int>(tc.key_pem.size())), &BIO_free);
                EvpPkeyPtr fresh(kb ? PEM_read_bio_PrivateKey(kb.get(), nullptr, nullptr, nullptr)
                                    : nullptr);
                if (fresh) {
                    std::filesystem::create_directories(key_path.parent_path(), ec);
                    write_privkey_pem(key_path, fresh.get());
                    publish_transport_cert(db, cert_id, certs.front().get());
                    pki::log::info("generated and published a self-signed transport cert for '" +
                              cert_id + "' (serial " + x509_serial_hex(certs.front().get()) +
                              ") — it will be reused on restart");
                }
            } else if (!key_uri.empty() && key_uri.rfind("pkcs11:", 0) == 0) {
                // ⚠️ DO NOT PUBLISH THIS ONE. Reaching here with a pkcs11: key configured
                // means the token key could NOT be loaded — the branch above returns early
                // whenever it could — so the pair being served was minted in memory and its
                // private half is in NO token. Publishing it advertises, in a replicated
                // table, an identity that nothing anywhere holds.
                //
                // Measured on a live pair: nine containers restarted at once, three of them
                // lost the race to the p11-kit server, and each published one of these. The
                // rows outlived the cause, and on an HA pair — where both hosts already
                // share one cert_id — they make "which row is this node's?" harder for every
                // reader, while the listener went on serving a certificate no client could
                // verify until it was restarted again.
                //
                // Serving the in-memory pair is still right: a listener that refuses to
                // start is worse, and the next start retries the token. Persisting it is
                // not, because the reason to persist — "or every start mints another one" —
                // only holds for a key that will still be there next time.
                // ⚠️ THE SCOPED URI, which is the object that was actually looked for. Printing
                // the raw configured path sent an operator after `object=ms-tls` when the
                // object is `ms-tls-1` — listener_key_uri appends DATACENTER_ID, and the load
                // above used that form. Measured in the lab: the advice named a handle that
                // does not exist, which is the same unactionable-message failure this whole
                // area keeps producing.
                pki::log::err("serving a TEMPORARY in-memory self-signed cert for '" +
                              cert_id + "': the token key " +
                              pkcs11_uri_redacted(key_uri) +
                              " could not be loaded, so this pair is NOT in the token and is "
                              "deliberately not published. RESTART THIS SERVICE once the "
                              "token answers — this process cannot recover on its own, "
                              "because PKCS#11 is initialised once per process. "
                              "`pkcs11-tool --list-objects` shows whether the object is "
                              "there, and a burst of simultaneous starts is the usual "
                              "reason it is not.");
                // ⚠️ AND AN IN-PROCESS RETRY CANNOT FIX THIS — measured, so that nobody adds
                // one again. A watcher here — the shape watch_for_ra_key uses for the RA
                // credentials — retried every 20s for 80s while the token was back and a
                // FRESH process could read the very same object; the stuck process never
                // succeeded, and only `docker compose restart ms` recovered it. The reason is
                // the one endpoint_gate's token_died() already states: the PKCS#11 module is
                // initialised ONCE per process, so a provider that came up against an absent
                // token stays broken for that process's life.
                //
                // Exiting here instead would recover it, but not unconditionally: this branch
                // is also the ordinary state of a FRESH install, where the token answers and
                // simply holds no such object yet, and exiting there is the crash loop the
                // tolerance above exists to prevent. Separating the two means distinguishing
                // "the token said no such object" from "the token did not answer", which the
                // load path knows internally and does not report in a form this can branch
                // on, which is why the code below carries it instead.
            } else {
                // No key configured at all: the in-memory pair is the only identity there
                // is, so publish it or every start mints another one.
                publish_transport_cert(db, cert_id, certs.front().get());
                pki::log::info("published the self-signed transport cert for '" + cert_id + "'");
            }
        }
    } catch (const std::exception& e) {
        // Serve the in-memory pair anyway; the identity churns until this succeeds.
        pki::log::info(std::string("could not persist the transport cert for '") + cert_id +
                  "' (" + e.what() + ") — it will be regenerated on the next start");
    }
    return tc;
}

namespace {
// Which CA promotes a self-signed listener certificate: the one the caller named (--ca),
// else HTTPS_CA_ID, else this node's only issuing CA. Empty, with `why` set, when none can
// be chosen; `from` says which of the three answered, for the messages that follow.
//
// ⚠️ A ROOT IS NEVER CHOSEN AUTOMATICALLY, but it is honoured when named. Signing an
// end-entity certificate directly with a root is what a sub CA exists to avoid; refusing a
// named one outright would make the CLI stricter than the console, which issues from
// whichever CA the operator picks. Tested with x509_is_self_signed(), never subject ==
// issuer, because a RE-KEYED CA is self-ISSUED without being a root.
//
// ⚠️ SEVERAL ISSUING CAS ARE REFUSED, NOT RANKED. Which CA a node's HTTPS identity chains
// to is the operator's decision; "first created" or "alphabetical" would be a guess that
// looks like a rule.
std::string listener_signer(const Config& cfg, Db& db, const std::string& requested,
                            std::string& from, std::string& why) {
    if (!requested.empty()) { from = "--ca"; return requested; }
    if (!cfg.https_ca_id.empty()) { from = "HTTPS_CA_ID"; return cfg.https_ca_id; }   // pending-restart: maintenance read
    std::vector<std::string> candidates;
    for (const auto& ca : db.list_ca_instances()) {
        if (ca.signing_ca_pem.empty() || ca.signing_ca_key.empty()) continue;
        if (ca.revoked || ca.expired) continue;
        try {
            auto x = load_ca_cert_pem(ca.signing_ca_pem);
            if (x && x509_is_self_signed(x.get())) continue;
        } catch (...) { continue; }
        candidates.push_back(ca.id);
    }
    if (candidates.size() == 1) { from = "this node's only issuing CA"; return candidates.front(); }
    if (candidates.empty()) {
        why = "no issuing CA on this node can sign the HTTPS certificates: create a sub CA "
              "(a root is never chosen automatically), or name one with HTTPS_CA_ID or --ca";
    } else {
        why = "this node has more than one issuing CA, so it does not choose which one signs "
              "the HTTPS certificates: set HTTPS_CA_ID to one of them (the Config page, or "
              "fastpki-config set HTTPS_CA_ID <id>), or name it with --ca. Candidates:";
        for (const auto& c : candidates) why += " " + c;
    }
    return {};
}
}  // namespace

TransportReissueResult reissue_self_signed_transport_certs(const Config& cfg, Db& db,
                                                           const std::string& requested_ca,
                                                           bool dry_run) {
    TransportReissueResult out;

    // The same name the listener would self-sign with, so re-issuing changes the ISSUER
    // and nothing else. A certificate that suddenly carried a different name would be a
    // different identity, not a promoted one.
    const std::string cn = cfg.pki_dns.empty() ? std::string("localhost") : cfg.pki_dns;
    std::vector<std::string> sans{ cn };
    if (cn != "localhost") sans.emplace_back("localhost");

    // ⚠️ THESE READS ARE MAINTENANCE, NOT SERVING, and the marker below is load-bearing.
    // pki_lib links into every binary, so tests/web_config_pending_restart.sh treats any
    // read of a config field here as proof that EVERY service reads it — which would make
    // the console's "restart fastpki-est" advice for EST_KEY a lie. It is not one: this
    // function is reachable only from `fastpki-ca renew-service-certs` and the console's
    // rekey cascade, and no protocol binary calls it. The marker exempts exactly these
    // lines, so a future read on the SERVING path is still caught.
    struct Listener { std::string raw_id{}; std::string key_ref{}; const char* label{nullptr}; };
    const Listener listeners[] = {
        { cfg.web_cert_id,  cfg.web_tls_key.string(),         "web console TLS" },
        { cfg.est_cert_id,  cfg.est_server_key_pem,  "EST listener TLS" },   // pending-restart: maintenance read
        { cfg.acme_cert_id, cfg.acme_server_key_pem, "ACME listener TLS" },  // pending-restart: maintenance read
        { cfg.ms_cert_id,   cfg.ms_server_key_pem,   "MS-XCEP/WSTEP listener TLS" },  // pending-restart: maintenance read
    };

    // This node's listeners still serving the certificate they self-signed at first start.
    struct Pending { std::string cert_id{}; const char* label{nullptr}; EvpPkeyPtr pkey{};
                     std::string self_signed_serial{}; };
    std::vector<Pending> pending;
    for (const auto& l : listeners) {
        // A protocol this deployment never installed has no key configured, and a
        // certificate for a listener that does not run is noise in the inventory.
        if (l.raw_id.empty() || l.key_ref.empty()) continue;

        // ⚠️ SCOPED, because a listener certificate belongs to the NODE. `certs`
        // replicates, so a bare "web" would name the same row on every node in the mesh;
        // listener_cert_id appends DATACENTER_ID exactly as the listener itself does.
        const std::string cert_id = listener_cert_id(cfg, l.raw_id);

        // ⚠️ THE SAME ORDERING THE LISTENER USES, not get_cert_by_cert_id(). A cert_id
        // legitimately holds more than one live row: the two hosts of an HA pair publish
        // under the same one, each for its own key, and get_cert_by_cert_id breaks its tie
        // on notAfter/serial with no notion of whose key a row certifies. It once handed
        // back a self-signed row that looked un-promoted, and every run issued again,
        // accumulating a CA-issued certificate per invocation. Asking the question the way
        // the listener asks it is the only answer that stays true.
        std::vector<Db::TransportCandidate> cands;
        try { cands = db.list_transport_candidates(cert_id); } catch (const std::exception&) { cands.clear(); }
        // Nothing published yet: the listener has not started, and it will mint its own
        // self-signed certificate when it does. Creating one here would race that.
        if (cands.empty()) {
            out.notes.push_back("skipped " + cert_id + " (" + l.label +
                                ") — nothing published yet; the listener creates its own at first start");
            ++out.skipped;
            continue;
        }
        ++out.checked;

        // ⚠️ THIS NODE'S OWN CANDIDATE, NOT cands.front(). The ordering ranks CA-issued
        // ahead of self-signed across EVERY row under this cert_id, and the scope above is
        // DATACENTER_ID — which does not separate the two hosts of an HA pair, because a
        // pair is one data center twice. So the front row is the PEER's certificate as
        // often as it is ours, and asking about it reported "already CA-issued" on a
        // promoted standby whose own four listeners were still serving the self-signed
        // certificates they minted at install. That state was permanent: --force skips
        // here too, so no operator command could replace them, while this loop reported
        // "re-issued 0, skipped 4, failed 0" every day.
        //
        // The key is what settles ownership, so it is loaded BEFORE the question is asked.
        // resolve_transport_cert already picks the first candidate whose key it holds and
        // walks past the rest ("not ours — almost certainly a peer's row"); this has to
        // select the same certificate or the two disagree about what is being served.
        const std::string key_ref = listener_key_uri(cfg, l.key_ref);
        EvpPkeyPtr pkey;
        // ⚠️ KEEP THE REASON, AND REDACT THE HANDLE. load_key_file_or_token THROWS on every
        // failure rather than returning null, and the throw carries the one sentence an
        // operator can act on — whether the token is reachable but empty under that label,
        // or this process's PKCS#11 session is dead. Swallowing it left a nightly job saying
        // only "could not load the listener key", which is the unactionable output this
        // whole area exists to stop producing.
        //
        // And the handle goes through pkcs11_uri_redacted, as every other error path in this
        // file does: RFC 7512 allows the PIN inline as ?pin-value=, this product reads that
        // form, and this text is printed to stderr by a job whose output is logged.
        try { pkey = load_key_file_or_token(key_ref, cfg); }
        catch (const std::exception& e) {
            out.errors.push_back(cert_id + ": could not load the listener key " +
                                 pkcs11_uri_redacted(key_ref) + ": " + e.what());
            ++out.failed;
            continue;
        }
        if (!pkey) {
            out.errors.push_back(cert_id + ": could not load the listener key " +
                                 pkcs11_uri_redacted(key_ref));
            ++out.failed;
            continue;
        }
        const Db::TransportCandidate* mine = nullptr;
        X509Ptr cur;
        // A row that does not parse is still worth saying out loud. The previous shape
        // reported it as an error because it examined exactly one candidate; walking the
        // list must not turn a corrupt row into silence, or a cert_id whose rows are all
        // unreadable looks identical to one that simply has none.
        int unparsable = 0;
        for (const auto& cand : cands) {
            if (cand.der.empty()) continue;
            const unsigned char* p = cand.der.data();
            X509Ptr x{d2i_X509(nullptr, &p, static_cast<long>(cand.der.size()))};
            if (!x) { ++unparsable; continue; }
            if (cert_certifies_key(x.get(), pkey.get())) {
                mine = &cand; cur = std::move(x); break;
            }
        }
        if (!mine && unparsable > 0)
            out.errors.push_back(cert_id + ": " + std::to_string(unparsable) +
                                 " stored certificate(s) under this id do not parse");
        // Every row under this id certifies someone else's key: this node has published
        // nothing of its own yet, and its listener mints a self-signed certificate at its
        // first start. Issuing here would race that, exactly as it would with no rows.
        if (!mine) {
            out.notes.push_back("skipped " + cert_id + " (" + l.label +
                                ") — nothing published for this node's key yet; its "
                                "listener creates its own at first start");
            ++out.skipped;
            continue;
        }
        // THE WHOLE POINT: only a self-signed one is promoted. A certificate already
        // issued by a CA is left alone — re-issuing it would be a renewal, which
        // resolve_transport_cert already does under the CA that issued it.
        if (!mine->ca_instance_id.empty() || !x509_is_self_signed(cur.get())) {
            out.notes.push_back("skipped " + cert_id + " (" + l.label +
                                ") — already CA-issued");
            ++out.skipped;
            continue;
        }
        pending.push_back({cert_id, l.label, std::move(pkey), mine->serial});
    }

    // ⚠️ THE CA IS CHOSEN ONLY NOW, once something needs one. Choosing it first made the
    // daily job — which names no --ca — fail on every run on a node with two issuing CAs,
    // even when all four listeners had been CA-issued for months.
    if (pending.empty()) return out;
    const auto fail_all = [&](const std::string& why) {
        out.errors.push_back(why);
        out.failed += static_cast<int>(pending.size());
        return out;
    };
    std::string from, why;
    const std::string ca_id = listener_signer(cfg, db, requested_ca, from, why);
    if (ca_id.empty()) return fail_all(why);
    const std::string named = "CA '" + ca_id + "' (" + from + ")";
    auto mat = db.get_ca_instance(ca_id);
    if (!mat || mat->signing_ca_pem.empty() || mat->signing_ca_key.empty())
        return fail_all(named + ": this node holds no signing key for it");
    if (mat->revoked || mat->expired)
        return fail_all(named + (mat->revoked ? " is revoked" : " has expired") + " and must not sign");
    auto cacert = load_ca_cert_pem(mat->signing_ca_pem);
    auto cakey  = load_signing_key(mat->signing_ca_key, cfg);
    if (!cacert || !cakey)
        return fail_all(named + ": could not load its certificate or key");
    if (x509_is_self_signed(cacert.get()))
        out.notes.push_back("note: " + named + " is a root, so these listener certificates "
                            "will be signed directly by it — an issuing CA beneath the root "
                            "is the usual arrangement");

    for (auto& p : pending) {
        if (dry_run) {
            out.notes.push_back("would re-issue " + p.cert_id + " (" + p.label +
                                ") under " + named);
            ++out.reissued;
            continue;
        }
        try {
            X509Ptr fresh = ca_issue_tls_cert(cfg, db, ca_id, cacert.get(), cakey.get(),
                                              p.pkey.get(), cn, sans, 90);
            if (!fresh || !cert_certifies_key(fresh.get(), p.pkey.get())) {
                out.errors.push_back(p.cert_id + ": the re-issued certificate does not match "
                                     "the listener key — refusing to publish it");
                ++out.failed;
                continue;
            }
            publish_transport_cert(db, p.cert_id, fresh.get(), ca_id);
            // ⚠️ AND THE SELF-SIGNED ROW IT REPLACES IS SUPERSEDED, exactly as renewal below
            // supersedes a CA-issued predecessor. The listener would never pick it again —
            // list_transport_candidates ranks CA-issued first — but left at status 0 it sat
            // in every node's inventory as a second live certificate for the listener,
            // one per promotion. The serial is the row certifying THIS node's key, never a
            // lookup by cert_id, so an HA peer's certificate under the same id is untouched.
            try { db.set_cert_status(p.self_signed_serial, 3); }
            catch (const std::exception& e) {
                out.notes.push_back(p.cert_id + ": the self-signed certificate " +
                                    p.self_signed_serial + " could not be marked superseded: " +
                                    e.what());
            }
            out.notes.push_back("re-issued " + p.cert_id + " (" + p.label + ") under " +
                                named + " -> " + x509_serial_hex(fresh.get()));
            ++out.reissued;
        } catch (const std::exception& e) {
            out.errors.push_back(p.cert_id + ": " + e.what());
            ++out.failed;
        }
    }
    return out;
}

TransportReissueResult renew_ca_issued_transport_certs(const Config& cfg, Db& db,
                                                       const std::string& only_ca,
                                                       bool force, bool dry_run) {
    TransportReissueResult out;
    struct Listener { std::string raw_id{}; std::string key_ref{}; const char* label{nullptr}; };
    const Listener listeners[] = {
        { cfg.web_cert_id,  cfg.web_tls_key.string(), "web console TLS" },
        { cfg.est_cert_id,  cfg.est_server_key_pem,   "EST listener TLS" },   // pending-restart: maintenance read
        { cfg.acme_cert_id, cfg.acme_server_key_pem,  "ACME listener TLS" },  // pending-restart: maintenance read
        { cfg.ms_cert_id,   cfg.ms_server_key_pem,    "MS-XCEP/WSTEP listener TLS" },  // pending-restart: maintenance read
    };
    for (const auto& l : listeners) {
        if (l.raw_id.empty() || l.key_ref.empty()) continue;
        const std::string cert_id = listener_cert_id(cfg, l.raw_id);

        std::vector<Db::TransportCandidate> cands;
        try { cands = db.list_transport_candidates(cert_id); } catch (const std::exception&) { cands.clear(); }
        // Nothing published is not this function's business: the listener self-signs at
        // first start and --re-issue-self-signed promotes that. Silently, so a node that does
        // not run a listener adds no noise to the nightly output.
        if (cands.empty()) continue;

        const std::string key_ref = listener_key_uri(cfg, l.key_ref);
        EvpPkeyPtr pkey;
        try { pkey = load_key_file_or_token(key_ref, cfg); } catch (const std::exception&) { pkey.reset(); }
        if (!pkey) {
            out.errors.push_back(cert_id + ": could not load the listener key " +
                                 pkcs11_uri_redacted(key_ref) + " to find this node's certificate");
            ++out.failed;
            continue;
        }
        // ⚠️ THE ROW THAT CERTIFIES THIS NODE'S KEY decides, never the first row under the
        // id — the same rule the listener and the self-signed promotion use, because an HA
        // pair publishes under one id and a peer's row must not be renewed as ours.
        const Db::TransportCandidate* mine = nullptr;
        X509Ptr cur;
        for (const auto& cand : cands) {
            if (cand.der.empty()) continue;
            const unsigned char* p = cand.der.data();
            X509Ptr x{d2i_X509(nullptr, &p, static_cast<long>(cand.der.size()))};
            if (x && cert_certifies_key(x.get(), pkey.get())) { mine = &cand; cur = std::move(x); break; }
        }
        if (!mine || mine->ca_instance_id.empty() || x509_is_self_signed(cur.get())) continue;
        if (!only_ca.empty() && mine->ca_instance_id != only_ca) continue;
        ++out.checked;
        if (!force && !service_cert_due(cur.get(), cfg.service_cert_renew_fraction)) continue;

        const std::string& ca_id = mine->ca_instance_id;
        auto mat = db.get_ca_instance(ca_id);
        if (!mat || mat->signing_ca_pem.empty() || mat->signing_ca_key.empty() ||
            mat->revoked || mat->expired) {
            out.notes.push_back("skipped " + cert_id + " (" + l.label + ") — its CA '" + ca_id + "' " +
                                (!mat ? std::string("is not registered here")
                                      : mat->revoked ? std::string("is revoked")
                                      : mat->expired ? std::string("has expired")
                                      : std::string("has no signing key on this node")));
            ++out.skipped;
            continue;
        }
        if (dry_run) {
            out.notes.push_back("would renew " + cert_id + " (" + l.label + ") under CA '" + ca_id + "'");
            ++out.reissued;
            continue;
        }
        try {
            auto cacert = load_ca_cert_pem(mat->signing_ca_pem);
            auto cakey  = load_signing_key(mat->signing_ca_key, cfg);
            if (!cacert || !cakey) throw Error(2, "could not load CA '" + ca_id + "'");
            // Keep the lifetime the certificate was given: 90 days for one FastPKI issued by
            // itself, whatever the profile allowed for one issued from the console.
            const long lifetime = x509_not_after_unix(cur.get()) - x509_not_before_unix(cur.get());
            const int days = static_cast<int>(std::max<long>(1, (lifetime + 86399) / 86400));
            // ⚠️ A CORRECTED PKI_DNS HAS TO REACH THE LISTENERS, or an operator who fixes
            // their deployment's public name has no way to repair the certificates minted
            // under the wrong one — and a certificate's name cannot be changed after it is
            // issued, so re-issuing is the only repair there is.
            //
            // `like` copies the subject and the SAN extension VERBATIM. That is right for an
            // ordinary renewal, where the identity must not drift, and wrong for exactly this
            // case, where the identity is what was wrong: carrying it forward means every
            // renewal faithfully reproduces the mistake. Measured on a deployment whose
            // PKI_DNS was corrected after the CAs existed: the console kept serving
            // CN=pki.example.org through --force renewals, and nothing offered a way out.
            //
            // A listener certificate's name IS PKI_DNS — it has to be the name a client
            // dials (see ServiceCredSpec) — so a mismatch is a stale certificate by
            // definition. X509_check_host asks the question a verifying client asks, rather
            // than comparing the CN and missing a name that is only a SAN.
            const std::string want = cfg.pki_dns;
            const bool stale_name =
                !want.empty() &&
                X509_check_host(cur.get(), want.c_str(), want.size(), 0, nullptr) != 1;
            X509Ptr fresh =
                stale_name
                    ? ca_issue_tls_cert(cfg, db, ca_id, cacert.get(), cakey.get(), pkey.get(),
                                        want, {want}, days, nullptr)
                    : ca_issue_tls_cert(cfg, db, ca_id, cacert.get(), cakey.get(), pkey.get(),
                                        x509_cn(cur.get()), {}, days, cur.get());
            if (stale_name)
                out.notes.push_back(cert_id + ": was issued for '" + x509_cn(cur.get()) +
                                    "' and PKI_DNS is now '" + want +
                                    "' — re-issued under the new name");
            if (!fresh || !cert_certifies_key(fresh.get(), pkey.get()))
                throw Error(2, "the renewed certificate does not match the listener key — refusing to publish it");
            publish_transport_cert(db, cert_id, fresh.get(), ca_id);
            // One cert_id, one active certificate for this key: the predecessor is superseded,
            // not revoked — it stays valid for anything still presenting it, and the listener
            // swaps to the new one within kTransportReloadIntervalSec (transport_reload.hpp).
            try { db.set_cert_status(mine->serial, 3); }
            catch (const std::exception& e) {
                out.notes.push_back(cert_id + ": the previous certificate " + mine->serial +
                                    " could not be marked superseded: " + e.what());
            }
            out.notes.push_back("renewed " + cert_id + " (" + l.label + ") under CA '" + ca_id +
                                "' -> " + x509_serial_hex(fresh.get()));
            ++out.reissued;
        } catch (const std::exception& e) {
            out.errors.push_back(cert_id + ": " + e.what());
            ++out.failed;
        }
    }
    return out;
}

std::string der_to_pem_cert(const std::vector<unsigned char>& der) {
    const unsigned char* p = der.data();
    X509* x = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
    if (!x) return {};
    X509Ptr xptr{x};
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
    PEM_write_bio_X509(bio.get(), xptr.get());
    char* s = nullptr; long n = BIO_get_mem_data(bio.get(), &s);
    return std::string(s, n > 0 ? static_cast<size_t>(n) : 0);
}

std::string evp_pkey_to_pem(EVP_PKEY* pkey) {
    if (!pkey) return {};
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
    PEM_write_bio_PrivateKey(bio.get(), pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char* s = nullptr; long n = BIO_get_mem_data(bio.get(), &s);
    return std::string(s, n > 0 ? static_cast<size_t>(n) : 0);
}

void log_transport_cert(const char* service, const TransportCert& tc, const std::string& dns) {
    const std::string who = std::string("fastpki-") + service;
    // Operator-configured file: name the path. `chain_pem` says nothing useful here (a
    // perfectly good CA-issued file cert routinely has none), so guessing self-signed
    // vs CA-issued from it would just move the wrong claim to a different branch.
    if (tc.use_files) {
        pki::log::info(who + ": serving HTTPS on the configured certificate file " + tc.cert_pem);
        return;
    }
    // ⚠️ ASK THE CERTIFICATE, not the chain. My first version keyed on `chain_pem` being
    // empty, which is wrong in a case this repo already exercises: when the issuer IS the
    // root, a server must not send the anchor (RFC 8446 §4.4.2), so a perfectly
    // CA-issued cert legitimately carries no chain. That would have reported the same
    // false "temporary self-signed" for it — the original bug, one branch narrower.
    // ⚠️ And "issuer == subject" is not it either — that is self-ISSUED. This log line
    // chooses between "CA-issued" and "TEMPORARY self-signed", so a self-issued listener
    // certificate signed by a real CA key would be announced as temporary, which is the
    // log-line-that-lies shape this comment block already exists to prevent.
    auto oneline = [](X509_NAME* n) {
        if (!n) return std::string();
        char buf[512];
        X509_NAME_oneline(n, buf, static_cast<int>(sizeof buf));
        return std::string(buf);
    };
    std::string subj, issuer;
    bool self_signed = true;
    if (!tc.cert_pem.empty()) {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(
            BIO_new_mem_buf(tc.cert_pem.data(), static_cast<int>(tc.cert_pem.size())), &BIO_free);
        if (bio) {
            X509Ptr x{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
            if (x) {
                subj        = oneline(X509_get_subject_name(x.get()));
                issuer      = oneline(X509_get_issuer_name(x.get()));
                self_signed = x509_is_self_signed(x.get());
            }
        }
    }
    if (!subj.empty() && !self_signed) {
        pki::log::info(who + ": serving HTTPS on a CA-issued certificate (" + subj +
                       ", issued by " + issuer + ")");
        return;
    }
    pki::log::info(who + ": serving HTTPS on a TEMPORARY self-signed cert (CN=" +
                   (dns.empty() ? std::string("localhost") : dns) +
                   ") — no CA-issued certificate for this listener yet; it will be "
                   "replaced once one is issued.");
}

bool load_tls_context(void* ssl_ctx, const TransportCert& tc) {
    // WARNING: EVERY FAILURE HERE NAMES ITSELF. This returned a bare false from nine places
    // and the caller printed "TLS setup failed (check WEB_TLS_KEY)" -- a setting this path
    // does not read, because the certificate and the key both come from the resolved
    // transport cert. An operator who had just issued a CA-signed transport certificate was
    // sent to inspect a file that had nothing to do with the fault.
    auto fail = [](const char* what) {
        log::err(std::string("transport TLS: ") + what + ": " + openssl_errors());
        return false;
    };
    if (!ssl_ctx) return fail("no SSL context");
    auto* ctx = static_cast<SSL_CTX*>(ssl_ctx);

    // Load leaf certificate.
    {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(
            BIO_new_mem_buf(tc.cert_pem.data(), static_cast<int>(tc.cert_pem.size())),
            &BIO_free);
        if (!bio) return fail("could not buffer the leaf certificate");
        X509* x = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
        if (!x) return fail("the leaf certificate is not readable PEM");
        X509Ptr xptr{x};
        if (SSL_CTX_use_certificate(ctx, xptr.get()) != 1) return fail("the leaf certificate was refused");
    }

    // Load CA chain (intermediates + root) via SSL_CTX_add_extra_chain_cert.
    if (!tc.chain_pem.empty()) {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(
            BIO_new_mem_buf(tc.chain_pem.data(), static_cast<int>(tc.chain_pem.size())),
            &BIO_free);
        if (bio) {
            X509* x = nullptr;
            while ((x = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)) != nullptr) {
                X509Ptr xptr{x};
                // SSL_CTX_add_extra_chain_cert takes ownership on success.
                if (SSL_CTX_add_extra_chain_cert(ctx, xptr.release()) != 1)
                    return fail("a chain certificate was refused");
            }
        }
    }

    // Load private key. A token-resident key has no PEM form — install the
    // provider-backed handle; SSL_CTX_check_private_key is the authoritative pairing
    // check and is provider-aware.
    if (tc.key) {
        if (SSL_CTX_use_PrivateKey(ctx, tc.key.get()) != 1)
            return fail("the token-resident private key was refused (is the PKCS#11 provider "
                        "loaded in this process, and the token reachable?)");
    } else {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(
            BIO_new_mem_buf(tc.key_pem.data(), static_cast<int>(tc.key_pem.size())),
            &BIO_free);
        if (!bio) return fail("could not buffer the private key");
        EVP_PKEY* k = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
        if (!k) return fail("the private key is not readable PEM");
        EvpPkeyPtr kptr{k};
        if (SSL_CTX_use_PrivateKey(ctx, kptr.get()) != 1) return fail("the private key was refused");
    }
    // The authoritative pairing check -- and the one that fires when a transport certificate
    // is re-issued while the key it is paired with is not replaced alongside it.
    if (SSL_CTX_check_private_key(ctx) == 1) return true;
    return fail("the certificate and the private key do not match -- the key is not the one "
                "this certificate was issued for");
}

// The generation token — see the header for why this is the SKI and not the serial.
std::string cert_ski_hex(const std::vector<unsigned char>& cert_der) {
    if (cert_der.empty()) return {};
    const unsigned char* p = cert_der.data();
    std::unique_ptr<X509, decltype(&X509_free)> x(
        d2i_X509(nullptr, &p, static_cast<long>(cert_der.size())), &X509_free);
    if (!x) { ERR_clear_error(); return {}; }
    const ASN1_OCTET_STRING* skid = X509_get0_subject_key_id(x.get());
    if (!skid) return {};                       // no SKID -> no qualified URL, caller falls back
    const unsigned char* d = ASN1_STRING_get0_data(skid);
    const int n = ASN1_STRING_length(skid);
    if (!d || n <= 0) return {};
    static const char* hx = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<size_t>(n) * 2);
    for (int i = 0; i < n; ++i) { out += hx[d[i] >> 4]; out += hx[d[i] & 0x0f]; }
    return out;
}

CaUrls derive_ca_urls(const Config& cfg, const std::string& ca_id) {
    // ⚠️ ALL THREE of these URLs are served by fastpki-ocsp, which is a plain
    // HTTP listener on OCSP_PORT. So the URL baked into a certificate is
    //     http://<host>:<OCSP_PORT>/…
    // and neither half of that is cosmetic:
    //
    //   * scheme — https here pointed a validator at a TLS port that does not
    //     serve these paths. It is also wrong in principle: AIA/CRLDP fetches must not
    //     require the PKI they are being used to validate (RFC 5280 §4.2.2.1), which is
    //     why caIssuers is DER over plain HTTP.
    //   * port — we must not rely on a load-balancer existing to redirect
    //     requests to the correct ports, because a load-balancer is out of scope for
    //     this solution. Omitting it only worked if
    //     something the product does not ship was listening on :80 and proxying.
    //
    // BASE_URL still names the deployment's public HOST — that is the operator's call
    // and cannot be derived — but its scheme and any port it carries are NOT authoritative
    // for these three, because they describe the console, not the OCSP listener.
    std::string host;
    {
        const std::string b = cfg.base_url.empty() ? cfg.pki_dns : cfg.base_url;
        auto s = b.find("://");
        host = (s != std::string::npos) ? b.substr(s + 3) : b;
        auto slash = host.find('/');                // strip any path
        if (slash != std::string::npos) host.resize(slash);
        // Strip a port BASE_URL carried: it is the console's, not the OCSP listener's.
        // Guard IPv6 literals ("[::1]:8090") by taking the colon after the bracket only.
        auto colon = (!host.empty() && host.front() == '[') ? host.find(':', host.find(']'))
                                                            : host.rfind(':');
        if (colon != std::string::npos) host.resize(colon);
    }
    // :80 is the scheme's own default, so writing it out changes nothing about which
    // socket a client opens — that is the one port that may be left implicit.
    const std::string port = (cfg.ocsp_port == 80) ? std::string()
                                                   : (":" + std::to_string(cfg.ocsp_port));
    const std::string base = "http://" + host + port;

    CaUrls u;
    // Every CA has a real id, so the URLs always name it.
    // This node's own URLs. ca_urls_for_instance() adds the other data centers'; a
    // deployment that is a single data center therefore behaves exactly as before.
    u.crl        = { base + "/" + ca_id + ".crl" };   // fastpki-ocsp serves /{ca_id}.crl
    u.ca_issuers = { base + "/" + ca_id + ".crt" };   // /{ca_id}.crt (DER, non-TLS)
    // Shared responder: signing cert picked from the requested cert, so one path.
    u.ocsp       = { base + "/ocsp" };
    return u;
}

// ── what makes a renewal a RENEWAL ──────────────────────────────────────────
// Moved here from src/scep/main.cpp when EST device self-service needed the
// same rule. One definition, two protocols.
// ── what makes a renewal a RENEWAL ──────────────────────────────────────────
//
// Every name in a SAN extension, type-tagged so "DNS:host" and "IP:host" can never be
// mistaken for each other. Type-tagging is not decoration: without it a client could
// present an IP address entry that string-matches a DNS name in the old certificate and
// obtain a certificate for a name it never held.
// File-local: the tagging rule the two public helpers below share. Not declared in the
// header — callers want cert_sans/csr_sans, not a GENERAL_NAMES walker.
static std::set<std::string> san_names(GENERAL_NAMES* gens) {
    std::set<std::string> out;
    if (!gens) return out;
    for (int i = 0; i < sk_GENERAL_NAME_num(gens); ++i) {
        GENERAL_NAME* g = sk_GENERAL_NAME_value(gens, i);
        if (!g) continue;
        auto str = [&](ASN1_STRING* a) {
            return std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(a)),
                               static_cast<size_t>(ASN1_STRING_length(a)));
        };
        switch (g->type) {
            case GEN_DNS:   out.insert("DNS:"   + str(g->d.dNSName));                 break;
            case GEN_EMAIL: out.insert("EMAIL:" + str(g->d.rfc822Name));              break;
            case GEN_URI:   out.insert("URI:"   + str(g->d.uniformResourceIdentifier)); break;
            case GEN_IPADD: {
                // Raw octets, not text: 4 bytes for v4, 16 for v6. Comparing the raw
                // form on both sides needs no parser and cannot disagree with one.
                const unsigned char* d = ASN1_STRING_get0_data(g->d.iPAddress);
                int n = ASN1_STRING_length(g->d.iPAddress);
                std::string hex; static const char* H = "0123456789abcdef";
                for (int k = 0; k < n; ++k) { hex += H[d[k] >> 4]; hex += H[d[k] & 0xf]; }
                out.insert("IP:" + hex);
                break;
            }
            default:
                // ⚠️ An unrecognised type is NOT ignored. Dropping it here would let a
                // CSR carry an otherName / directoryName the comparison never sees, which
                // is precisely the "add a name the old certificate did not have" case the
                // whole check exists to stop. Record it by tag+DER so it must also have
                // been present before.
                {
                    unsigned char* der = nullptr;
                    int n = i2d_GENERAL_NAME(g, &der);
                    std::string hex = "type" + std::to_string(g->type) + ":";
                    static const char* H = "0123456789abcdef";
                    for (int k = 0; k < n; ++k) { hex += H[der[k] >> 4]; hex += H[der[k] & 0xf]; }
                    OPENSSL_free(der);
                    out.insert(hex);
                }
                break;
        }
    }
    return out;
}

bool cert_certifies_key(X509* cert, EVP_PKEY* key) {
    if (!cert || !key) return false;
    if (X509_check_private_key(cert, key) == 1) { ERR_clear_error(); return true; }
    ERR_clear_error();
    // ⚠️ BORROWED, NOT OWNED. X509_get0_pubkey hands back the pointer the certificate owns
    // and takes no reference; wrapping it in an EvpPkeyPtr freed the caller's certificate's
    // public key and produced failures somewhere else entirely (measured on the CMP RA:
    // client-certificate auth started refusing valid clients while PBM kept working).
    EVP_PKEY* cert_pk = X509_get0_pubkey(cert);
    if (!cert_pk) { ERR_clear_error(); return false; }
    BIGNUM* cert_n = nullptr; BIGNUM* cert_e = nullptr;
    BIGNUM* key_n  = nullptr; BIGNUM* key_e  = nullptr;
    bool match = false;
    if (EVP_PKEY_get_bn_param(cert_pk, "n", &cert_n) &&
        EVP_PKEY_get_bn_param(cert_pk, "e", &cert_e) &&
        EVP_PKEY_get_bn_param(key,     "n", &key_n)  &&
        EVP_PKEY_get_bn_param(key,     "e", &key_e)) {
        match = (BN_cmp(cert_n, key_n) == 0 && BN_cmp(cert_e, key_e) == 0);
    }
    // No n/e on one side means it is not an RSA pair (an EC or ML-DSA credential), so the
    // RSA-vs-RSA-PSS type mismatch cannot be what happened — X509_check_private_key above
    // already gave the right answer, and it was no.
    BN_free(cert_n); BN_free(cert_e);
    BN_free(key_n);  BN_free(key_e);
    ERR_clear_error();
    return match;
}

std::set<std::string> cert_sans(X509* x) {
    auto* gens = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(x, NID_subject_alt_name, nullptr, nullptr));
    auto out = san_names(gens);
    GENERAL_NAMES_free(gens);
    return out;
}

std::set<std::string> exts_sans(const STACK_OF(X509_EXTENSION)* exts) {
    if (!exts) return {};
    auto* e = const_cast<STACK_OF(X509_EXTENSION)*>(exts);
    int idx = X509v3_get_ext_by_NID(e, NID_subject_alt_name, -1);
    if (idx < 0) return {};
    X509_EXTENSION* ext = X509v3_get_ext(e, idx);
    if (!ext) return {};
    auto* gens = static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(ext));
    auto out = san_names(gens);
    GENERAL_NAMES_free(gens);
    return out;
}

std::set<std::string> csr_sans(X509_REQ* req) {
    STACK_OF(X509_EXTENSION)* exts = X509_REQ_get_extensions(req);
    if (!exts) return {};
    auto out = exts_sans(exts);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return out;
}

std::string name_cn(X509_NAME* n) {
    if (!n) return {};
    int idx = X509_NAME_get_index_by_NID(n, NID_commonName, -1);
    if (idx < 0) return {};
    X509_NAME_ENTRY* e = X509_NAME_get_entry(n, idx);
    if (!e) return {};
    ASN1_STRING* s = X509_NAME_ENTRY_get_data(e);
    unsigned char* u = nullptr;
    int len = ASN1_STRING_to_UTF8(&u, s);
    if (len < 0 || !u) return {};
    std::string out(reinterpret_cast<char*>(u), static_cast<size_t>(len));
    OPENSSL_free(u);
    return out;
}

// A renewal must ask for the identity it already holds. Returns "" when the CSR is a
// legitimate renewal of `old`, otherwise the reason it is not.
//
// ⚠️ This is the whole of the renewal binding (and of EST device self-service too). Before it, "renewal" meant only "the CMS is signed by an
// unrevoked certificate this CA issued" — and nothing afterwards compared the CSR to that
// certificate. A holder of ANY such certificate could obtain one for ANY subject the
// shared SCEP profile permits, with no challengePassword. It did not even have to be a
// certificate issued over SCEP.
//
// Subject: exact match. X509_NAME_cmp compares the CANONICAL encoding, so a client that
// re-encodes PrintableString as UTF8String, or reorders nothing, still matches — this is
// not a byte comparison of the DER.
//
// SANs: the CSR's must be a SUBSET of the old certificate's. Not equality — dropping a
// name you already hold is harmless and a client legitimately does it when a hostname is
// retired, whereas ADDING one is exactly the escalation. Requiring equality would refuse
// honest renewals for no security gain.
std::string renewal_mismatch(X509* old_cert, X509_REQ* csr) {
    if (X509_NAME_cmp(X509_REQ_get_subject_name(csr), X509_get_subject_name(old_cert)) != 0)
        return "the CSR subject differs from the certificate being renewed";
    const auto have = cert_sans(old_cert);
    for (const auto& want : csr_sans(csr))
        if (!have.count(want))
            return "the CSR asks for a subjectAltName the certificate being renewed does "
                   "not hold";
    return {};
}

} // namespace pki
