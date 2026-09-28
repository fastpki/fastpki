#pragma once
// Shared SCEP (RFC 8894) CMS helpers used by both fastpki-scep (server) and the
// scep-testclient (test/reference client): the SCEP authenticated
// attribute OIDs and small get/add wrappers over CMS_SignerInfo, plus a nonce
// generator. Header-only so the two binaries share one definition without a
// pki_lib dependency on the SCEP-specific bits.

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/cms.h>
#include <openssl/objects.h>
#include <openssl/rand.h>

#include <cctype>
#include <memory>
#include <string>
#include <vector>

namespace pki::scep {

// RAII for the OpenSSL handles both binaries juggle.
struct CmsDeleter { void operator()(CMS_ContentInfo* c) const noexcept { if (c) CMS_ContentInfo_free(c); } };
using CmsPtr = std::unique_ptr<CMS_ContentInfo, CmsDeleter>;
struct BioDeleter { void operator()(BIO* b) const noexcept { if (b) BIO_free(b); } };
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

inline std::vector<unsigned char> cms_to_der(CMS_ContentInfo* cms) {
    int len = i2d_CMS_ContentInfo(cms, nullptr);
    std::vector<unsigned char> out(len > 0 ? len : 0);
    if (len > 0) { unsigned char* p = out.data(); i2d_CMS_ContentInfo(cms, &p); }
    return out;
}

inline std::vector<unsigned char> bio_to_vec(BIO* b) {
    BUF_MEM* bm = nullptr;
    BIO_get_mem_ptr(b, &bm);
    if (!bm || bm->length == 0) return {};
    return std::vector<unsigned char>(bm->data, bm->data + bm->length);
}

// Authenticated-attribute OIDs (Verisign arc 2.16.840.1.113733.1.9.x).
inline constexpr const char* OID_messageType    = "2.16.840.1.113733.1.9.2";
inline constexpr const char* OID_pkiStatus      = "2.16.840.1.113733.1.9.3";
inline constexpr const char* OID_failInfo       = "2.16.840.1.113733.1.9.4";
inline constexpr const char* OID_senderNonce    = "2.16.840.1.113733.1.9.5";
inline constexpr const char* OID_recipientNonce = "2.16.840.1.113733.1.9.6";
inline constexpr const char* OID_transactionID  = "2.16.840.1.113733.1.9.7";

// messageType values.
inline constexpr const char* MSG_PKCSReq        = "19";  // PKCS#10 enrollment request
inline constexpr const char* MSG_CertRep        = "3";   // CA response
inline constexpr const char* MSG_GetCertInitial = "20";  // poll a pending request (txid)
inline constexpr const char* MSG_GetCert        = "21";  // fetch a cert by issuer+serial
inline constexpr const char* MSG_GetCRL         = "22";  // fetch the CA CRL

// pkiStatus values.
// RFC 8894 3.2.1.4 failInfo — the reason a pkiStatus=FAILURE carries. A client that
// cannot read one has to guess, and every guess is "try again later", which is wrong for
// all five of these. Only the values the server can actually distinguish are listed.
inline constexpr const char* FAIL_BAD_ALG           = "0";  // unrecognised/unsupported algorithm
inline constexpr const char* FAIL_BAD_MESSAGE_CHECK = "1";  // integrity check failed
inline constexpr const char* FAIL_BAD_REQUEST       = "2";  // transaction not permitted/supported
inline constexpr const char* FAIL_BAD_TIME          = "3";  // signingTime too far from server time
inline constexpr const char* FAIL_BAD_CERT_ID       = "4";  // no certificate for the given id

inline constexpr const char* STATUS_SUCCESS = "0";
inline constexpr const char* STATUS_FAILURE = "2";
inline constexpr const char* STATUS_PENDING = "3";

inline std::vector<unsigned char> random_nonce(int n = 16) {
    std::vector<unsigned char> v(static_cast<size_t>(n));
    RAND_bytes(v.data(), n);
    return v;
}

// Add a PrintableString signed attribute (messageType, pkiStatus, transactionID).
inline bool add_str_attr(CMS_SignerInfo* si, const char* oid, const std::string& val) {
    ASN1_OBJECT* o = OBJ_txt2obj(oid, 1);
    if (!o) return false;
    int r = CMS_signed_add1_attr_by_OBJ(si, o, V_ASN1_PRINTABLESTRING,
                                        val.data(), static_cast<int>(val.size()));
    ASN1_OBJECT_free(o);
    return r == 1;
}

// Add an OCTET STRING signed attribute (sender/recipient nonces).
inline bool add_octet_attr(CMS_SignerInfo* si, const char* oid,
                           const std::vector<unsigned char>& val) {
    ASN1_OBJECT* o = OBJ_txt2obj(oid, 1);
    if (!o) return false;
    int r = CMS_signed_add1_attr_by_OBJ(si, o, V_ASN1_OCTET_STRING,
                                        val.data(), static_cast<int>(val.size()));
    ASN1_OBJECT_free(o);
    return r == 1;
}

inline std::string get_str_attr(CMS_SignerInfo* si, const char* oid) {
    ASN1_OBJECT* o = OBJ_txt2obj(oid, 1);
    if (!o) return {};
    auto* s = static_cast<ASN1_STRING*>(
        CMS_signed_get0_data_by_OBJ(si, o, -1, V_ASN1_PRINTABLESTRING));
    ASN1_OBJECT_free(o);
    if (!s) return {};
    return std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(s)),
                       static_cast<size_t>(ASN1_STRING_length(s)));
}

inline std::vector<unsigned char> get_octet_attr(CMS_SignerInfo* si, const char* oid) {
    ASN1_OBJECT* o = OBJ_txt2obj(oid, 1);
    if (!o) return {};
    auto* s = static_cast<ASN1_STRING*>(
        CMS_signed_get0_data_by_OBJ(si, o, -1, V_ASN1_OCTET_STRING));
    ASN1_OBJECT_free(o);
    if (!s) return {};
    const unsigned char* d = ASN1_STRING_get0_data(s);
    return std::vector<unsigned char>(d, d + ASN1_STRING_length(s));
}

// First SignerInfo of a parsed SignedData (SCEP messages carry exactly one).
inline CMS_SignerInfo* first_signer(CMS_ContentInfo* cms) {
    STACK_OF(CMS_SignerInfo)* sis = CMS_get0_SignerInfos(cms);
    return (sis && sk_CMS_SignerInfo_num(sis) > 0)
               ? sk_CMS_SignerInfo_value(sis, 0) : nullptr;
}

} // namespace pki::scep
