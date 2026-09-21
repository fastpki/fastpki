// cmp_asn1.hpp — minimal, self-contained ASN.1 decoding of the few CMP
// PKIMessage fields the OpenSSL CMP *server* API does not expose.
//
// OpenSSL 3.x makes OSSL_CMP_MSG / OSSL_CMP_PKIHEADER opaque and ships no
// public accessor for the request sender, the senderKID, the implicitConfirm
// flag, or the per-RevDetails CRLReason. The internal struct layout
// (crypto/cmp/cmp_local.h) is not installed, so the `msg->body->value.rr`
// / `header->sender` snippets only compile inside the OpenSSL source tree.
//
// Rather than vendor private headers, we decode the raw request bytes (which we
// already hold in the HTTP handler) with our own ASN.1 templates, built only on
// the public GENERAL_NAME / X509_EXTENSION items. This is the "own ASN.1, no
// internal-header dependency" path that was agreed, scoped to just
// the fields we need.
#pragma once
#include <string>

namespace pki {

// What we recover from one CMP request. Fields are best-effort: absent or
// unparseable fields are simply left empty/default.
struct CmpRequestInfo {
    std::string sender_dn;            // header.sender, when a directoryName (X509_NAME oneline)
    std::string sender_cn;            // CN of header.sender (directoryName), if present
    // header.recipient — who the client believes it is talking to. RFC 9810 §5.1.1
    // says it SHOULD name the intended CA/RA, and option (a) was chosen: refuse
    // a recipient that is neither the RA nor the issuing CA. Empty when the field is a
    // NULL-DN (an empty RDN sequence), which is what `openssl cmp` sends with no
    // -recipient and no -srvcert — so "absent" and "present but wrong" are the same
    // refusal, which is what (a) asks for.
    std::string recipient_dn;         // header.recipient, when a directoryName
    std::string recipient_cn;         // CN of header.recipient, if present
    std::string sender_kid;           // header.senderKID octet string, raw bytes as text
    bool        implicit_confirm = false; // header.generalInfo carries id-it-implicitConfirm
    bool        protection_pbm   = false; // protectionAlg is id-PasswordBasedMAC (vs signature)
    bool        sender_in_extracerts = false; // a cert in extraCerts has subject == header.sender
    // The SERIAL of that extraCerts entry, lowercase hex, "" when there is none.
    //
    // A signature-protected request is made BY a certificate, and the identity that
    // certificate belongs to is `certs.owner` — the value FastPKI itself wrote at issuance
    // and also emitted as the SDA owner. The server used to authorize such a request as its
    // header.sender CN, which is the certificate's SUBJECT: for a cert issued to
    // `/CN=example.com` on behalf of `alice` that is a hostname, so `may_enrol` refused a
    // renewal of a certificate the server had just issued. The serial is what makes the
    // lookup exact — a subject is not unique across renewals, an owner is not derivable
    // from a name, and only the DB knows the answer (§3f).
    std::string sender_serial;        // serial of the extraCerts cert whose subject == sender
    bool        has_rev_reason   = false; // a CRLReason was present in the rr body
    int         rev_reason       = 0;     // CRLReason value from the first RevDetails
};

// Decode `der`/`len` (a full DER PKIMessage). `bodytype` is the value from
// OSSL_CMP_MSG_get_bodytype(); the revocation reason is only parsed when it
// indicates a revocation request (rr == 11). Returns false only if the header
// itself cannot be decoded (not a PKIMessage); a true return with empty fields
// is normal for requests that simply don't carry them.
bool parse_cmp_request(const unsigned char* der, long len, int bodytype,
                       CmpRequestInfo& out);

} // namespace pki
