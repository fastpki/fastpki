// pki::csr_requested_template() decodes the two Microsoft certificate-template extensions
// off a CSR — bytes a requester chose — and both decoders are hand-rolled ASN.1:
//
//   V1  1.3.6.1.4.1.311.20.2   the template NAME as a BMPString, decoded UTF-16 by hand
//   V2  1.3.6.1.4.1.311.21.7   SEQUENCE { templateID OID, ... }, walked with ASN1_get_object
//
// ⚠️ THE FUZZ DATA IS INJECTED AS THE EXTENSION VALUE, NOT PARSED AS A WHOLE CSR. The
// obvious harness — d2i_X509_REQ(data) then call the function — is nearly worthless: almost
// every input dies in OpenSSL's own well-tested request parser and never reaches the two
// decoders this exists to exercise. So a valid CSR is built ONCE here and the input becomes
// the extension's octets, which puts every single input through the hand-rolled code.
//
// The first byte selects which extension to plant, so one campaign covers both decoders;
// the rest is the value. That costs one byte of entropy and avoids running two harnesses.
#include "pki/ms_template.hpp"

#include "lsan_suppressions.h"

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

// The catalogue the V2 OID is resolved against. Built once: it is not what is under test,
// and rebuilding it per input would dominate the profile.
const std::vector<pki::MsTemplate>& catalogue() {
    static const std::vector<pki::MsTemplate> k = pki::default_ms_templates();
    return k;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    const bool v2  = (data[0] & 1) != 0;
    const char* oid = v2 ? "1.3.6.1.4.1.311.21.7" : "1.3.6.1.4.1.311.20.2";
    const uint8_t* body = data + 1;
    const int body_len  = static_cast<int>(size - 1);

    X509_REQ* req = X509_REQ_new();
    if (!req) return 0;

    // The extension value is an OCTET STRING wrapping the fuzzed bytes, which is what
    // X509_EXTENSION_create_by_OBJ takes and what ext_der() will hand to the decoders.
    ASN1_OCTET_STRING* val = ASN1_OCTET_STRING_new();
    ASN1_OBJECT* obj = OBJ_txt2obj(oid, 1);
    if (val && obj && ASN1_OCTET_STRING_set(val, body, body_len)) {
        if (X509_EXTENSION* ext = X509_EXTENSION_create_by_OBJ(nullptr, obj, 0, val)) {
            if (STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null()) {
                if (sk_X509_EXTENSION_push(exts, ext) > 0) {
                    X509_REQ_add_extensions(req, exts);
                    (void)pki::csr_requested_template(req, catalogue());
                    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
                } else {
                    X509_EXTENSION_free(ext);
                    sk_X509_EXTENSION_free(exts);
                }
            } else {
                X509_EXTENSION_free(ext);
            }
        }
    }
    ASN1_OBJECT_free(obj);
    ASN1_OCTET_STRING_free(val);
    X509_REQ_free(req);
    return 0;
}
