#include "pki/cmc.hpp"

#include <openssl/asn1.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#include <string>

namespace pki {
namespace {

// Read the TLV at `p`, require its tag, and leave `p` at the CONTENT with `avail` set to
// the content length. False on a malformed header, the wrong tag, or a length that runs
// past what is readable.
//
// ⚠️ Everything here reads a structure a caller supplied, so every step is bounds-checked
// and any surprise returns empty. ASN1_get_object already refuses a length that overruns
// `avail`; the explicit re-check below costs nothing and does not depend on that staying
// true.
bool der_enter(const unsigned char*& p, long& avail, int want_tag, int want_class) {
    int tag = 0, cls = 0;
    long len = 0;
    const unsigned char* q = p;
    if (ASN1_get_object(&q, &len, &tag, &cls, avail) & 0x80) return false;
    if (tag != want_tag || cls != want_class) return false;
    if (len > avail - (q - p)) return false;
    p = q;
    avail = len;
    return true;
}

// Step over the whole TLV at `p`, decrementing `avail` by header + content.
bool der_skip(const unsigned char*& p, long& avail) {
    int tag = 0, cls = 0;
    long len = 0;
    const unsigned char* q = p;
    if (ASN1_get_object(&q, &len, &tag, &cls, avail) & 0x80) return false;
    const long header = q - p;
    if (len > avail - header) return false;
    p = q + len;
    avail -= header + len;
    return true;
}
} // namespace


// The DER of the PKCS#10 carried by a CMC full PKI request, or empty when `der` is not one.
std::vector<unsigned char> cmc_extract_pkcs10(const unsigned char* der, size_t n) {
    const unsigned char* dp = der;
    CMS_ContentInfo* cms = d2i_CMS_ContentInfo(nullptr, &dp, static_cast<long>(n));
    if (!cms) { ERR_clear_error(); return {}; }   // not a CMS at all: the ordinary case
    std::vector<unsigned char> out;
    do {
        // id-cct-PKIData. A CMS carrying anything else is not a CMC request, and guessing
        // at its content would be reading a structure nobody claimed to have sent.
        const ASN1_OBJECT* ect = CMS_get0_eContentType(cms);
        char oid[128] = {0};
        if (!ect || OBJ_obj2txt(oid, sizeof oid, ect, 1) <= 0) break;
        if (std::string(oid) != "1.3.6.1.5.5.7.12.2") break;
        ASN1_OCTET_STRING** content = CMS_get0_content(cms);
        if (!content || !*content) break;         // detached: there is nothing to unwrap
        const unsigned char* p = ASN1_STRING_get0_data(*content);
        long avail = ASN1_STRING_length(*content);
        if (!p || avail <= 0) break;

        // PKIData ::= SEQUENCE { controlSequence, reqSequence, cmsSequence, otherMsgSequence }
        if (!der_enter(p, avail, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL)) break;
        if (!der_skip(p, avail)) break;                                   // controlSequence
        if (!der_enter(p, avail, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL)) break;  // reqSequence
        // The first TaggedRequest. RFC 5272's module is IMPLICIT, so `tcr [0]
        // TaggedCertificationRequest` is a constructed context-0 in place of the SEQUENCE.
        if (!der_enter(p, avail, 0, V_ASN1_CONTEXT_SPECIFIC)) break;
        if (!der_skip(p, avail)) break;                                   // bodyPartID
        // What remains at `p` is the CertificationRequest, and a complete TLV is exactly
        // what d2i_X509_REQ wants — so hand back the whole thing, header included.
        const unsigned char* start = p;
        if (!der_skip(p, avail)) break;
        out.assign(start, p);
    } while (false);
    CMS_ContentInfo_free(cms);
    return out;
}

} // namespace pki
