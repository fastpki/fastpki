// cmp_asn1.cpp — see cmp_asn1.hpp. Minimal ASN.1 templates for the CMP request
// fields OpenSSL's public CMP server API hides. We re-decode the raw request
// bytes with our own types, using only the public ASN.1 engine + the public
// GENERAL_NAME / X509_EXTENSION items. Nothing here depends on OpenSSL internal
// (crypto/cmp/*) headers.
//
// RFC 4210 ASN.1 uses EXPLICIT tags, so every [n] header field is ASN1_EXP_*.
// We define the structures fully enough that real messages decode, but capture
// the parts we don't care about (CertTemplate, the PKIBody CHOICE, the header
// when parsing the rr body) as ASN1_ANY so we never have to model them.

#include "pki/cmp_asn1.hpp"
#include "pki/x509.hpp"

// IMPLEMENT_ASN1_FUNCTIONS emits a full new/free/d2i/i2d set per type; we only
// call a few of them, so the rest are unused-but-correct generated boilerplate.
#if defined(__GNUC__)
#  pragma GCC diagnostic ignored "-Wunused-function"
#endif

#include <cctype>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {

// ── InfoTypeAndValue (for header.generalInfo; we only test infoType) ────────
typedef struct {
    ASN1_OBJECT* infoType;
    ASN1_TYPE*   infoValue;   // OPTIONAL, ANY DEFINED BY infoType
} MIN_ITAV;

ASN1_SEQUENCE(MIN_ITAV) = {
    ASN1_SIMPLE(MIN_ITAV, infoType, ASN1_OBJECT),
    ASN1_OPT(MIN_ITAV, infoValue, ASN1_ANY),
    // OpenSSL's ASN.1 template DSL is a table-definition macro language, not
    // statements: cppcheck's tokenizer cannot expand ASN1_SEQUENCE_END and reports
    // it as an unknown macro. A parser limitation, not a defect here.
    // cppcheck-suppress unknownMacro
} ASN1_SEQUENCE_END(MIN_ITAV)
DECLARE_ASN1_FUNCTIONS(MIN_ITAV)
IMPLEMENT_ASN1_FUNCTIONS(MIN_ITAV)
DEFINE_STACK_OF(MIN_ITAV)

// ── PKIHeader (we read sender, senderKID, generalInfo) ──────────────────────
typedef struct {
    ASN1_INTEGER*              pvno;
    GENERAL_NAME*              sender;
    GENERAL_NAME*              recipient;
    ASN1_GENERALIZEDTIME*      messageTime;     // [0]
    X509_ALGOR*                protectionAlg;   // [1]
    ASN1_OCTET_STRING*         senderKID;       // [2]
    ASN1_OCTET_STRING*         recipKID;        // [3]
    ASN1_OCTET_STRING*         transactionID;   // [4]
    ASN1_OCTET_STRING*         senderNonce;     // [5]
    ASN1_OCTET_STRING*         recipNonce;      // [6]
    STACK_OF(ASN1_UTF8STRING)* freeText;        // [7] PKIFreeText
    STACK_OF(MIN_ITAV)*        generalInfo;     // [8]
} MIN_PKIHEADER;

ASN1_SEQUENCE(MIN_PKIHEADER) = {
    ASN1_SIMPLE(MIN_PKIHEADER, pvno, ASN1_INTEGER),
    ASN1_SIMPLE(MIN_PKIHEADER, sender, GENERAL_NAME),
    ASN1_SIMPLE(MIN_PKIHEADER, recipient, GENERAL_NAME),
    ASN1_EXP_OPT(MIN_PKIHEADER, messageTime, ASN1_GENERALIZEDTIME, 0),
    ASN1_EXP_OPT(MIN_PKIHEADER, protectionAlg, X509_ALGOR, 1),
    ASN1_EXP_OPT(MIN_PKIHEADER, senderKID, ASN1_OCTET_STRING, 2),
    ASN1_EXP_OPT(MIN_PKIHEADER, recipKID, ASN1_OCTET_STRING, 3),
    ASN1_EXP_OPT(MIN_PKIHEADER, transactionID, ASN1_OCTET_STRING, 4),
    ASN1_EXP_OPT(MIN_PKIHEADER, senderNonce, ASN1_OCTET_STRING, 5),
    ASN1_EXP_OPT(MIN_PKIHEADER, recipNonce, ASN1_OCTET_STRING, 6),
    ASN1_EXP_SEQUENCE_OF_OPT(MIN_PKIHEADER, freeText, ASN1_UTF8STRING, 7),
    ASN1_EXP_SEQUENCE_OF_OPT(MIN_PKIHEADER, generalInfo, MIN_ITAV, 8),
} ASN1_SEQUENCE_END(MIN_PKIHEADER)
DECLARE_ASN1_FUNCTIONS(MIN_PKIHEADER)
IMPLEMENT_ASN1_FUNCTIONS(MIN_PKIHEADER)

// ── PKIMessage prefix for header extraction: body captured as ANY so any
//    PKIBody CHOICE alternative decodes. ─────────────────────────────────────
typedef struct {
    MIN_PKIHEADER*   header;
    ASN1_TYPE*       body;          // ANY: whatever [n] CHOICE the request carries
    ASN1_BIT_STRING* protection;    // [0] OPTIONAL
    STACK_OF(X509)*  extraCerts;    // [1] OPTIONAL
} MIN_HDRMSG;

ASN1_SEQUENCE(MIN_HDRMSG) = {
    ASN1_SIMPLE(MIN_HDRMSG, header, MIN_PKIHEADER),
    ASN1_SIMPLE(MIN_HDRMSG, body, ASN1_ANY),
    ASN1_EXP_OPT(MIN_HDRMSG, protection, ASN1_BIT_STRING, 0),
    ASN1_EXP_SEQUENCE_OF_OPT(MIN_HDRMSG, extraCerts, X509, 1),
} ASN1_SEQUENCE_END(MIN_HDRMSG)
DECLARE_ASN1_FUNCTIONS(MIN_HDRMSG)
IMPLEMENT_ASN1_FUNCTIONS(MIN_HDRMSG)

// ── RevDetails / rr body (we read crlEntryDetails → CRLReason) ───────────────
typedef struct {
    ASN1_TYPE*                certDetails;      // CertTemplate, captured as ANY
    STACK_OF(X509_EXTENSION)* crlEntryDetails;  // OPTIONAL Extensions
} MIN_REVDETAILS;

ASN1_SEQUENCE(MIN_REVDETAILS) = {
    ASN1_SIMPLE(MIN_REVDETAILS, certDetails, ASN1_ANY),
    ASN1_SEQUENCE_OF_OPT(MIN_REVDETAILS, crlEntryDetails, X509_EXTENSION),
} ASN1_SEQUENCE_END(MIN_REVDETAILS)
DECLARE_ASN1_FUNCTIONS(MIN_REVDETAILS)
IMPLEMENT_ASN1_FUNCTIONS(MIN_REVDETAILS)
DEFINE_STACK_OF(MIN_REVDETAILS)

// PKIMessage whose body is rr [11] EXPLICIT RevReqContent (SEQUENCE OF
// RevDetails). Header captured as ANY (already parsed via MIN_HDRMSG). Only
// decoded when get_bodytype() == 11, so the [11] body and [0] protection never
// collide.
typedef struct {
    ASN1_TYPE*                header;     // ANY: skip
    STACK_OF(MIN_REVDETAILS)* rr;         // [11] EXPLICIT
    ASN1_BIT_STRING*          protection; // [0] OPTIONAL
    STACK_OF(X509)*           extraCerts; // [1] OPTIONAL
} MIN_RRMSG;

ASN1_SEQUENCE(MIN_RRMSG) = {
    ASN1_SIMPLE(MIN_RRMSG, header, ASN1_ANY),
    ASN1_EXP_SEQUENCE_OF_OPT(MIN_RRMSG, rr, MIN_REVDETAILS, 11),
    ASN1_EXP_OPT(MIN_RRMSG, protection, ASN1_BIT_STRING, 0),
    ASN1_EXP_SEQUENCE_OF_OPT(MIN_RRMSG, extraCerts, X509, 1),
} ASN1_SEQUENCE_END(MIN_RRMSG)
DECLARE_ASN1_FUNCTIONS(MIN_RRMSG)
IMPLEMENT_ASN1_FUNCTIONS(MIN_RRMSG)

constexpr int CMP_BODY_RR = 11; // PKIBody rr alternative (no public macro)

} // namespace

namespace pki {

bool parse_cmp_request(const unsigned char* der, long len, int bodytype,
                       CmpRequestInfo& out) {
    const unsigned char* p = der;
    MIN_HDRMSG* m = d2i_MIN_HDRMSG(nullptr, &p, len);
    if (m == nullptr)
        return false; // not a decodable PKIMessage

    if (m->header != nullptr) {
        const MIN_PKIHEADER* h = m->header;
        X509_NAME* sender_name = nullptr;
        if (h->sender != nullptr && h->sender->type == GEN_DIRNAME &&
            h->sender->d.directoryName != nullptr) {
            sender_name = h->sender->d.directoryName;
            char* s = X509_NAME_oneline(sender_name, nullptr, 0);
            if (s != nullptr) { out.sender_dn = s; OPENSSL_free(s); }
            char cn[256] = {0};
            if (X509_NAME_get_text_by_NID(sender_name, NID_commonName, cn, sizeof cn) > 0)
                out.sender_cn = cn;
        }
        // Header.recipient, same shape as sender. A NULL-DN decodes as a
        // directoryName with zero RDNs, so both strings come back empty and the caller
        // cannot tell it from an absent field — which is correct here, because the rule
        // treats them alike.
        if (h->recipient != nullptr && h->recipient->type == GEN_DIRNAME &&
            h->recipient->d.directoryName != nullptr) {
            X509_NAME* rn = h->recipient->d.directoryName;
            if (X509_NAME_entry_count(rn) > 0) {
                char* s = X509_NAME_oneline(rn, nullptr, 0);
                if (s != nullptr) { out.recipient_dn = s; OPENSSL_free(s); }
                char cn[256] = {0};
                if (X509_NAME_get_text_by_NID(rn, NID_commonName, cn, sizeof cn) > 0)
                    out.recipient_cn = cn;
            }
        }
        // Protection algorithm: distinguish PBM (shared secret) from a signature.
        if (h->protectionAlg != nullptr) {
            const ASN1_OBJECT* alg = nullptr;
            X509_ALGOR_get0(&alg, nullptr, nullptr, h->protectionAlg);
            if (alg != nullptr && OBJ_obj2nid(alg) == NID_id_PasswordBasedMAC)
                out.protection_pbm = true;
        }
        // Anti-spoof binding: a signature-protected request that OpenSSL validated
        // carries the signer cert in extraCerts. Confirm the header sender matches
        // one of those subjects, so a valid signer cannot claim another's DN.
        // ⚠️ ONE MATCH, OR NONE. This took the FIRST extraCerts entry whose subject equals
        // the header sender and made its serial the authenticated identity — but extraCerts
        // is an attacker-supplied list in attacker-chosen order, and `sender` is an
        // attacker-chosen name. Two entries sharing a subject DN therefore decided the
        // caller's identity by DER ordering rather than by which key actually signed:
        // include the victim's certificate (public, and freely obtainable) ahead of one's
        // own certificate carrying the same DN, and cmp_identity() resolves the VICTIM's
        // owner from the victim's serial.
        //
        // The binding OpenSSL gives us is "some entry validated the protection"; the
        // binding we need is "the entry naming this identity is the one that signed". Where
        // the list cannot answer that unambiguously, the right answer is to refuse rather
        // than to pick. A legitimate client sends exactly one certificate for its own DN.
        if (sender_name != nullptr && m->extraCerts != nullptr) {
            int matches = 0;
            X509* match = nullptr;
            for (int i = 0; i < sk_X509_num(m->extraCerts); ++i) {
                X509* c = sk_X509_value(m->extraCerts, i);
                if (c != nullptr &&
                    X509_NAME_cmp(X509_get_subject_name(c), sender_name) == 0) {
                    ++matches;
                    if (match == nullptr) match = c;
                }
            }
            if (matches == 1 && match != nullptr) {
                out.sender_in_extracerts = true;
                // Carry the serial too. The caller authorizes by the certificate's
                // OWNER, and the serial is the only field that names one certificate.
                //
                // ⚠️ x509_serial_hex(), NOT a hand-rolled BN_bn2hex. `certs.serial` is
                // written by that function, which runs canonical_serial() — lowercase
                // AND leading zeros stripped. This code used to only lowercase, and
                // BN_bn2hex pads to an even digit count, so any serial whose top nibble
                // is zero came out as "0abc…" against a stored "abc…". get_cert() then
                // missed, cmp_identity() fell back to the subject CN, and the owner's
                // own renewal was refused with "this identity may not enrol over CMP".
                // One serial in sixteen — it passed on my machine and failed in the
                // image, which reads exactly like a platform difference and is not one.
                // Two spellings of one identifier is the bug; there is now one.
                out.sender_serial = x509_serial_hex(match);
            }
            // matches > 1 leaves sender_in_extracerts false, and cmp_identity() then has no
            // bound identity — the caller refuses with "cannot determine the authenticated
            // signer for revocation" / no enrolment identity. Reported there rather than
            // here: this translation unit is a fuzz target and stays free of the log
            // dependency, so a malformed message cannot make the harness write output.
        }
        if (h->senderKID != nullptr && h->senderKID->length > 0) {
            out.sender_kid.assign(reinterpret_cast<const char*>(h->senderKID->data),
                                  static_cast<size_t>(h->senderKID->length));
        }
        if (h->generalInfo != nullptr) {
            for (int i = 0; i < sk_MIN_ITAV_num(h->generalInfo); ++i) {
                const MIN_ITAV* it = sk_MIN_ITAV_value(h->generalInfo, i);
                if (it != nullptr && it->infoType != nullptr &&
                    OBJ_obj2nid(it->infoType) == NID_id_it_implicitConfirm) {
                    out.implicit_confirm = true;
                    break;
                }
            }
        }
    }
    MIN_HDRMSG_free(m);

    if (bodytype == CMP_BODY_RR) {
        const unsigned char* q = der;
        MIN_RRMSG* r = d2i_MIN_RRMSG(nullptr, &q, len);
        if (r != nullptr) {
            if (r->rr != nullptr && sk_MIN_REVDETAILS_num(r->rr) > 0) {
                const MIN_REVDETAILS* rd = sk_MIN_REVDETAILS_value(r->rr, 0);
                if (rd != nullptr && rd->crlEntryDetails != nullptr) {
                    int n = sk_X509_EXTENSION_num(rd->crlEntryDetails);
                    for (int i = 0; i < n; ++i) {
                        X509_EXTENSION* ex = sk_X509_EXTENSION_value(rd->crlEntryDetails, i);
                        if (ex == nullptr) continue;
                        if (OBJ_obj2nid(X509_EXTENSION_get_object(ex)) != NID_crl_reason)
                            continue;
                        const ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ex);
                        if (data == nullptr) continue;
                        const unsigned char* dp = data->data;
                        ASN1_ENUMERATED* en =
                            d2i_ASN1_ENUMERATED(nullptr, &dp, data->length);
                        if (en != nullptr) {
                            out.rev_reason = static_cast<int>(ASN1_ENUMERATED_get(en));
                            out.has_rev_reason = true;
                            ASN1_ENUMERATED_free(en);
                        }
                        break;
                    }
                }
            }
            MIN_RRMSG_free(r);
        }
    }
    return true;
}

} // namespace pki
