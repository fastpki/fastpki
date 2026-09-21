// CMP test client: a pollReq whose transactionID and PBM identity are BOTH chosen by the
// caller. It exists for one reason — `openssl cmp` generates its own transactionID per
// invocation and offers no way to name somebody else's, so the case where one requester
// polls another's in-flight transaction cannot be expressed with the CLI at all, and the
// server-side refusal for it had no end-to-end test.
//
// It also builds the `ir` that sets that case up. An ordinary client polls its own
// request a second after making it, and the server releases the deferral on that first
// poll — so by the time a second identity could try, there is nothing deferred left to
// try against. This client requests and then stops, leaving the transaction live.
//
// Same role as the SCEP reference client: not a product binary, and deliberately minimal.
//
//   cmp-testclient --url http://host:port/cmp/<ca>
//                          --txid <hex> --ref <senderKID> --secret <shared secret>
//                          [--ir --cn <subject> [--certout <file>]]
//
// Prints the decoded answer as `body=<n> <name>` plus any PKIStatusInfo text, so a suite
// asserts on what came back rather than on an exit code. Exit 0 means a well-formed
// PKIMessage was received and decoded, whatever it says — a refusal is a successful
// measurement, not a failure of this tool.
// IMPLEMENT_ASN1_FUNCTIONS emits a full new/free/d2i/i2d set per type; this client calls
// only some of them, so the rest are unused-but-correct generated boilerplate. Same
// suppression, for the same reason, as the server-side decoder.
#if defined(__GNUC__)
#  pragma GCC diagnostic ignored "-Wunused-function"
#endif

#include <openssl/asn1t.h>
#include <stdexcept>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

namespace {

// ── The slice of PKIMessage this client builds ──────────────────────────────
// The same shape the server-side decoder uses, for the same reason: OpenSSL keeps
// OSSL_CMP_MSG opaque and ships no public constructor for a bare pollReq, so the message
// is encoded here from public ASN.1 items only. `body` is ANY, which lets one template
// carry any PKIBody alternative — we write a pollReq into it and read whatever comes back.
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
    STACK_OF(ASN1_UTF8STRING)* freeText;        // [7]
    STACK_OF(ASN1_TYPE)*       generalInfo;     // [8]
} CL_PKIHEADER;

ASN1_SEQUENCE(CL_PKIHEADER) = {
    ASN1_SIMPLE(CL_PKIHEADER, pvno, ASN1_INTEGER),
    ASN1_SIMPLE(CL_PKIHEADER, sender, GENERAL_NAME),
    ASN1_SIMPLE(CL_PKIHEADER, recipient, GENERAL_NAME),
    ASN1_EXP_OPT(CL_PKIHEADER, messageTime, ASN1_GENERALIZEDTIME, 0),
    ASN1_EXP_OPT(CL_PKIHEADER, protectionAlg, X509_ALGOR, 1),
    ASN1_EXP_OPT(CL_PKIHEADER, senderKID, ASN1_OCTET_STRING, 2),
    ASN1_EXP_OPT(CL_PKIHEADER, recipKID, ASN1_OCTET_STRING, 3),
    ASN1_EXP_OPT(CL_PKIHEADER, transactionID, ASN1_OCTET_STRING, 4),
    ASN1_EXP_OPT(CL_PKIHEADER, senderNonce, ASN1_OCTET_STRING, 5),
    ASN1_EXP_OPT(CL_PKIHEADER, recipNonce, ASN1_OCTET_STRING, 6),
    ASN1_EXP_SEQUENCE_OF_OPT(CL_PKIHEADER, freeText, ASN1_UTF8STRING, 7),
    ASN1_EXP_SEQUENCE_OF_OPT(CL_PKIHEADER, generalInfo, ASN1_ANY, 8),
// cppcheck cannot parse OpenSSL's ASN.1 template DSL, so the closing macro of every
// ASN1_SEQUENCE in this file reads as an unknown macro to it. Parser limitation only.
// cppcheck-suppress unknownMacro
} ASN1_SEQUENCE_END(CL_PKIHEADER)
DECLARE_ASN1_FUNCTIONS(CL_PKIHEADER)
IMPLEMENT_ASN1_FUNCTIONS(CL_PKIHEADER)

typedef struct {
    CL_PKIHEADER*    header;
    ASN1_TYPE*       body;
    ASN1_BIT_STRING* protection;    // [0] OPTIONAL
    STACK_OF(X509)*  extraCerts;    // [1] OPTIONAL
} CL_PKIMSG;

ASN1_SEQUENCE(CL_PKIMSG) = {
    ASN1_SIMPLE(CL_PKIMSG, header, CL_PKIHEADER),
    ASN1_SIMPLE(CL_PKIMSG, body, ASN1_ANY),
    ASN1_EXP_OPT(CL_PKIMSG, protection, ASN1_BIT_STRING, 0),
    ASN1_EXP_SEQUENCE_OF_OPT(CL_PKIMSG, extraCerts, X509, 1),
} ASN1_SEQUENCE_END(CL_PKIMSG)
DECLARE_ASN1_FUNCTIONS(CL_PKIMSG)
IMPLEMENT_ASN1_FUNCTIONS(CL_PKIMSG)

// ProtectedPart ::= SEQUENCE { header PKIHeader, body PKIBody } — RFC 4210 §5.1.3.
// The protection is computed over THIS, not over the whole message.
typedef struct {
    CL_PKIHEADER* header;
    ASN1_TYPE*    body;
} CL_PROTPART;

ASN1_SEQUENCE(CL_PROTPART) = {
    ASN1_SIMPLE(CL_PROTPART, header, CL_PKIHEADER),
    ASN1_SIMPLE(CL_PROTPART, body, ASN1_ANY),
} ASN1_SEQUENCE_END(CL_PROTPART)
DECLARE_ASN1_FUNCTIONS(CL_PROTPART)
IMPLEMENT_ASN1_FUNCTIONS(CL_PROTPART)

std::string ossl_err() {
    std::string s; unsigned long e;
    while ((e = ERR_get_error())) { char b[256]; ERR_error_string_n(e, b, sizeof b); if (!s.empty()) s += "; "; s += b; }
    return s;
}

bool hex_to_bytes(const std::string& hex, std::vector<unsigned char>& out) {
    if (hex.size() % 2) return false;
    out.clear(); out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

// A GeneralName carrying a directoryName of /CN=<cn>. The server does not authorize on
// this — PBM identity is the senderKID — but the field is mandatory in the header.
GENERAL_NAME* dirname_gn(const char* cn) {
    X509_NAME* n = X509_NAME_new();
    if (!n) return nullptr;
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
    GENERAL_NAME* gn = GENERAL_NAME_new();
    if (!gn) { X509_NAME_free(n); return nullptr; }
    GENERAL_NAME_set0_value(gn, GEN_DIRNAME, n);
    return gn;
}

// Wrap `content` in a constructed TLV of the given tag and class. Both PKIBody
// alternatives this client builds are an explicit context tag around DER produced
// elsewhere, so this is the only encoding either of them needs.
int der_wrap(const unsigned char* content, int clen, int tag, int cls, unsigned char** out) {
    int total = ASN1_object_size(/*constructed=*/1, clen, tag);
    unsigned char* buf = static_cast<unsigned char*>(OPENSSL_malloc(total));
    if (!buf) return -1;
    unsigned char* p = buf;
    ASN1_put_object(&p, 1, clen, tag, cls);
    memcpy(p, content, static_cast<size_t>(clen));
    *out = buf;
    return total;
}

// PKIBody pollReq: [25] EXPLICIT PollReqContent, PollReqContent ::= SEQUENCE OF
// SEQUENCE { certReqId INTEGER }. Built as raw DER and carried in the ANY slot.
ASN1_TYPE* pollreq_body(long cert_req_id) {
    // innermost: SEQUENCE { INTEGER certReqId }
    ASN1_INTEGER* id = ASN1_INTEGER_new();
    if (!id || !ASN1_INTEGER_set(id, cert_req_id)) { ASN1_INTEGER_free(id); return nullptr; }
    unsigned char* idder = nullptr;
    int idlen = i2d_ASN1_INTEGER(id, &idder);
    ASN1_INTEGER_free(id);
    if (idlen <= 0) return nullptr;

    unsigned char* one = nullptr;                                   // SEQUENCE{INTEGER}
    int onelen = der_wrap(idder, idlen, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL, &one);
    OPENSSL_free(idder);
    if (onelen <= 0) return nullptr;
    unsigned char* seqof = nullptr;                                 // SEQUENCE OF the above
    int seqoflen = der_wrap(one, onelen, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL, &seqof);
    OPENSSL_free(one);
    if (seqoflen <= 0) return nullptr;
    unsigned char* body = nullptr;                                  // [25] EXPLICIT
    int bodylen = der_wrap(seqof, seqoflen, 25, V_ASN1_CONTEXT_SPECIFIC, &body);
    OPENSSL_free(seqof);
    if (bodylen <= 0) return nullptr;

    const unsigned char* bp = body;
    ASN1_TYPE* t = d2i_ASN1_TYPE(nullptr, &bp, bodylen);
    OPENSSL_free(body);
    return t;
}

// PKIBody ir: [0] EXPLICIT CertReqMessages. `CertReqMessages` is a SEQUENCE OF
// CertReqMsg, which OpenSSL already models as STACK_OF(OSSL_CRMF_MSG) with a public
// encoder — so nothing here hand-rolls CRMF, only the outer body tag. The freshly
// generated key is handed back because the proof-of-possession is signed with it.
//
// Why this client sends its own ir at all: the case under test needs a transaction that
// is STILL deferred when a second identity polls it. Any ordinary client polls its own
// request about a second later, and the server releases the deferral on that first poll,
// so there is nothing left to attack. This one requests and then simply stops.
ASN1_TYPE* ir_body(long cert_req_id, const char* subject_cn, EVP_PKEY** keyout) {
    *keyout = nullptr;
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
    if (!pkey) return nullptr;

    X509_NAME* subj = X509_NAME_new();
    if (!subj || !X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(subject_cn), -1, -1, 0)) {
        X509_NAME_free(subj); EVP_PKEY_free(pkey); return nullptr;
    }

    OSSL_CRMF_MSG*  crm  = OSSL_CRMF_MSG_new();
    OSSL_CRMF_MSGS* msgs = sk_OSSL_CRMF_MSG_new_null();
    unsigned char* inner = nullptr;
    int innerlen = 0;
    if (crm && msgs
        && OSSL_CRMF_MSG_set_certReqId(crm, static_cast<int>(cert_req_id))
        && OSSL_CRMF_CERTTEMPLATE_fill(OSSL_CRMF_MSG_get0_tmpl(crm), pkey, subj,
                                       nullptr, nullptr)
        && OSSL_CRMF_MSG_create_popo(OSSL_CRMF_POPO_SIGNATURE, crm, pkey, EVP_sha256(),
                                     nullptr, nullptr)
        && sk_OSSL_CRMF_MSG_push(msgs, crm)) {
        crm = nullptr;                                  // the stack owns it now
        innerlen = i2d_OSSL_CRMF_MSGS(msgs, &inner);
    }
    X509_NAME_free(subj);
    OSSL_CRMF_MSG_free(crm);                            // no-op once pushed
    OSSL_CRMF_MSGS_free(msgs);
    if (innerlen <= 0) { OPENSSL_free(inner); EVP_PKEY_free(pkey); return nullptr; }

    unsigned char* body = nullptr;
    int bodylen = der_wrap(inner, innerlen, 0, V_ASN1_CONTEXT_SPECIFIC, &body);
    OPENSSL_free(inner);
    if (bodylen <= 0) { EVP_PKEY_free(pkey); return nullptr; }

    const unsigned char* bp = body;
    ASN1_TYPE* t = d2i_ASN1_TYPE(nullptr, &bp, bodylen);
    OPENSSL_free(body);
    if (!t) { EVP_PKEY_free(pkey); return nullptr; }
    *keyout = pkey;
    return t;
}

// ── Just enough of the ANSWER to report it ──────────────────────────────────
// The point of this client is that a suite asserts on what the server SAID, so the
// PKIStatusInfo is decoded rather than inferred from an exit code. The certificate is
// pulled out too, so the "and the rightful owner can still collect it" half of the test
// asserts against a real certificate instead of a status number.
typedef struct {
    ASN1_INTEGER*              status;
    STACK_OF(ASN1_UTF8STRING)* statusString;    // OPTIONAL
    ASN1_BIT_STRING*           failInfo;        // OPTIONAL
} CL_STATUSINFO;

ASN1_SEQUENCE(CL_STATUSINFO) = {
    ASN1_SIMPLE(CL_STATUSINFO, status, ASN1_INTEGER),
    ASN1_SEQUENCE_OF_OPT(CL_STATUSINFO, statusString, ASN1_UTF8STRING),
    ASN1_OPT(CL_STATUSINFO, failInfo, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(CL_STATUSINFO)
DECLARE_ASN1_FUNCTIONS(CL_STATUSINFO)
IMPLEMENT_ASN1_FUNCTIONS(CL_STATUSINFO)

// CertifiedKeyPair's first field is a CHOICE whose `certificate` alternative is [0]
// EXPLICIT. Only that alternative is modelled: this server never returns an encrypted
// certificate, and a template that tried to carry both would collide with the optional
// [0] privateKey field that follows it. An encrypted answer therefore fails to decode
// here and is reported as such rather than silently read as "no certificate".
typedef struct {
    X509* cert;
} CL_CERTKEYPAIR;

ASN1_SEQUENCE(CL_CERTKEYPAIR) = {
    ASN1_EXP(CL_CERTKEYPAIR, cert, X509, 0),
} ASN1_SEQUENCE_END(CL_CERTKEYPAIR)
DECLARE_ASN1_FUNCTIONS(CL_CERTKEYPAIR)
IMPLEMENT_ASN1_FUNCTIONS(CL_CERTKEYPAIR)

typedef struct {
    ASN1_INTEGER*      certReqId;
    CL_STATUSINFO*     status;
    CL_CERTKEYPAIR*    certifiedKeyPair;        // OPTIONAL
    ASN1_OCTET_STRING* rspInfo;                 // OPTIONAL
} CL_CERTRESPONSE;

ASN1_SEQUENCE(CL_CERTRESPONSE) = {
    ASN1_SIMPLE(CL_CERTRESPONSE, certReqId, ASN1_INTEGER),
    ASN1_SIMPLE(CL_CERTRESPONSE, status, CL_STATUSINFO),
    ASN1_OPT(CL_CERTRESPONSE, certifiedKeyPair, CL_CERTKEYPAIR),
    ASN1_OPT(CL_CERTRESPONSE, rspInfo, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(CL_CERTRESPONSE)
DECLARE_ASN1_FUNCTIONS(CL_CERTRESPONSE)
IMPLEMENT_ASN1_FUNCTIONS(CL_CERTRESPONSE)
DEFINE_STACK_OF(CL_CERTRESPONSE)

typedef struct {
    STACK_OF(X509)*            caPubs;          // [1] OPTIONAL
    STACK_OF(CL_CERTRESPONSE)* response;
} CL_CERTREP;

ASN1_SEQUENCE(CL_CERTREP) = {
    ASN1_EXP_SEQUENCE_OF_OPT(CL_CERTREP, caPubs, X509, 1),
    ASN1_SEQUENCE_OF(CL_CERTREP, response, CL_CERTRESPONSE),
} ASN1_SEQUENCE_END(CL_CERTREP)
DECLARE_ASN1_FUNCTIONS(CL_CERTREP)
IMPLEMENT_ASN1_FUNCTIONS(CL_CERTREP)

typedef struct {
    CL_STATUSINFO*             status;
    ASN1_INTEGER*              errorCode;       // OPTIONAL
    STACK_OF(ASN1_UTF8STRING)* errorDetails;    // OPTIONAL
} CL_ERRORMSG;

ASN1_SEQUENCE(CL_ERRORMSG) = {
    ASN1_SIMPLE(CL_ERRORMSG, status, CL_STATUSINFO),
    ASN1_OPT(CL_ERRORMSG, errorCode, ASN1_INTEGER),
    ASN1_SEQUENCE_OF_OPT(CL_ERRORMSG, errorDetails, ASN1_UTF8STRING),
} ASN1_SEQUENCE_END(CL_ERRORMSG)
DECLARE_ASN1_FUNCTIONS(CL_ERRORMSG)
IMPLEMENT_ASN1_FUNCTIONS(CL_ERRORMSG)

const char* status_name(long v) {
    switch (v) {
        case 0: return "accepted";           case 1: return "grantedWithMods";
        case 2: return "rejection";          case 3: return "waiting";
        case 4: return "revocationWarning";  case 5: return "revocationNotification";
        case 6: return "keyUpdateWarning";
        default: return "?";
    }
}

void print_statusinfo(const CL_STATUSINFO* si) {
    if (!si) return;
    long v = ASN1_INTEGER_get(si->status);
    std::printf("status=%ld %s\n", v, status_name(v));
    for (int i = 0; si->statusString && i < sk_ASN1_UTF8STRING_num(si->statusString); ++i) {
        const ASN1_UTF8STRING* t = sk_ASN1_UTF8STRING_value(si->statusString, i);
        std::printf("statusString=%.*s\n", ASN1_STRING_length(t), ASN1_STRING_get0_data(t));
    }
    if (si->failInfo) {
        long bits = 0;
        for (int b = 0; b < 32; ++b)
            if (ASN1_BIT_STRING_get_bit(const_cast<ASN1_BIT_STRING*>(si->failInfo), b))
                bits |= (1L << b);
        std::printf("failInfo=0x%lx\n", bits);
    }
}

const char* body_name(int tag) {
    switch (tag) {
        case 0:  return "ir";      case 1:  return "ip";
        case 2:  return "cr";      case 3:  return "cp";
        case 7:  return "kur";     case 8:  return "kup";
        case 11: return "rr";      case 12: return "rp";
        case 19: return "pkiconf"; case 21: return "genm";
        case 22: return "genp";    case 23: return "error";
        case 25: return "pollReq"; case 26: return "pollRep";
        default: return "?";
    }
}

}  // namespace

int main(int argc, char** argv) {
    std::string url, txid_hex, ref, secret, sender_cn = "cmp-testclient", recip_cn = "CMP";
    std::string mode = "pollreq", cn, certout, recipnonce_hex;
    long certreqid = 0;
    for (int i = 1; i < argc; ++i) {
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) { std::fprintf(stderr, "%s needs a value\n", what); std::exit(2); }
            return argv[++i];
        };
        std::string a = argv[i];
        if      (a == "--url")      url = next("--url");
        else if (a == "--txid")     txid_hex = next("--txid");
        else if (a == "--ref")      ref = next("--ref");
        else if (a == "--secret")   secret = next("--secret");
        else if (a == "--sender")   sender_cn = next("--sender");
        // The server refuses a request whose recipient names an authority that is not it,
        // so this has to be the CA's (or its RA's) subject CN, not a placeholder.
        else if (a == "--recipient") recip_cn = next("--recipient");
        else if (a == "--certreqid") certreqid = std::stol(next("--certreqid"));
        else if (a == "--ir")       mode = "ir";
        else if (a == "--cn")       cn = next("--cn");
        else if (a == "--certout")  certout = next("--certout");
        else if (a == "--recipnonce") recipnonce_hex = next("--recipnonce");
        else if (a == "-h" || a == "--help") {
            std::printf("usage: %s --url URL --txid HEX --ref KID --secret SECRET\n"
                        "         [--ir --cn NAME [--certout FILE]]   send an ir instead of a pollReq\n"
                        "         [--recipnonce HEX]  echo the nonce a previous answer carried\n"
                        "         [--sender CN] [--recipient CN] [--certreqid N]\n", argv[0]);
            return 0;
        } else { std::fprintf(stderr, "unknown argument: %s\n", a.c_str()); return 2; }
    }
    if (url.empty() || txid_hex.empty() || ref.empty() || secret.empty()) {
        std::fprintf(stderr, "--url, --txid, --ref and --secret are all required\n");
        return 2;
    }
    if (mode == "ir" && cn.empty()) {
        std::fprintf(stderr, "--ir needs --cn (the subject of the certificate to request)\n");
        return 2;
    }
    std::vector<unsigned char> txid;
    if (!hex_to_bytes(txid_hex, txid) || txid.empty()) {
        std::fprintf(stderr, "--txid must be non-empty hex\n"); return 2;
    }

    CL_PKIMSG* msg = CL_PKIMSG_new();
    if (!msg) { std::fprintf(stderr, "alloc failed\n"); return 1; }
    CL_PKIHEADER* h = msg->header;

    ASN1_INTEGER_set(h->pvno, 2);                       // cmp2000
    GENERAL_NAME_free(h->sender);    h->sender    = dirname_gn(sender_cn.c_str());
    GENERAL_NAME_free(h->recipient); h->recipient = dirname_gn(recip_cn.c_str());
    if (!h->sender || !h->recipient) { std::fprintf(stderr, "name build failed\n"); return 1; }

    h->messageTime = ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME_new(), time(nullptr));
    h->senderKID = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(h->senderKID,
                          reinterpret_cast<const unsigned char*>(ref.data()),
                          static_cast<int>(ref.size()));
    h->transactionID = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(h->transactionID, txid.data(), static_cast<int>(txid.size()));
    unsigned char nonce[16];
    // Checked: the senderNonce is the message's replay protection, so an uninitialised
    // one is worse than no message.
    if (RAND_bytes(nonce, sizeof nonce) != 1)
        throw std::runtime_error("RAND_bytes failed generating a CMP senderNonce");
    h->senderNonce = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(h->senderNonce, nonce, sizeof nonce);
    // A message continuing a transaction must echo the senderNonce of the answer before
    // it, or the server rejects it on nonce continuity before any of its own callbacks
    // run. The value is printed by this client for exactly that purpose, so a caller can
    // chain one message onto another.
    if (!recipnonce_hex.empty()) {
        std::vector<unsigned char> rn;
        if (!hex_to_bytes(recipnonce_hex, rn) || rn.empty()) {
            std::fprintf(stderr, "--recipnonce must be non-empty hex\n"); return 2;
        }
        h->recipNonce = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(h->recipNonce, rn.data(), static_cast<int>(rn.size()));
    }

    // PBM (RFC 4210 §5.1.3.1). Both halves come from OpenSSL's public CRMF API rather than
    // a hand-rolled iterated hash, so the client cannot disagree with the server about the
    // one thing this test is not trying to exercise.
    OSSL_CRMF_PBMPARAMETER* pbmp = OSSL_CRMF_pbmp_new(nullptr, 16, NID_sha256, 1024, NID_hmac_sha1);
    if (!pbmp) { std::fprintf(stderr, "pbmp_new: %s\n", ossl_err().c_str()); return 1; }
    h->protectionAlg = X509_ALGOR_new();
    {
        unsigned char* pder = nullptr;
        int plen = i2d_OSSL_CRMF_PBMPARAMETER(pbmp, &pder);
        if (plen <= 0) { std::fprintf(stderr, "i2d pbmp failed\n"); return 1; }
        ASN1_STRING* as = ASN1_STRING_new();
        ASN1_STRING_set0(as, pder, plen);              // takes ownership of pder
        X509_ALGOR_set0(h->protectionAlg, OBJ_nid2obj(NID_id_PasswordBasedMAC),
                        V_ASN1_SEQUENCE, as);
    }

    EVP_PKEY* newkey = nullptr;
    ASN1_TYPE_free(msg->body);
    msg->body = (mode == "ir") ? ir_body(certreqid, cn.c_str(), &newkey)
                               : pollreq_body(certreqid);
    if (!msg->body) {
        std::fprintf(stderr, "could not build the %s body: %s\n",
                     mode.c_str(), ossl_err().c_str());
        return 1;
    }

    // Protection over ProtectedPart, not over the message.
    std::vector<unsigned char> mac;
    {
        CL_PROTPART pp;
        pp.header = msg->header;
        pp.body   = msg->body;
        unsigned char* ppder = nullptr;
        int pplen = i2d_CL_PROTPART(&pp, &ppder);
        if (pplen <= 0) { std::fprintf(stderr, "i2d ProtectedPart: %s\n", ossl_err().c_str()); return 1; }
        unsigned char* macbuf = nullptr; size_t maclen = 0;
        int ok = OSSL_CRMF_pbm_new(nullptr, nullptr, pbmp, ppder, static_cast<size_t>(pplen),
                                   reinterpret_cast<const unsigned char*>(secret.data()),
                                   secret.size(), &macbuf, &maclen);
        OPENSSL_free(ppder);
        if (!ok) { std::fprintf(stderr, "pbm_new: %s\n", ossl_err().c_str()); return 1; }
        mac.assign(macbuf, macbuf + maclen);
        OPENSSL_free(macbuf);
    }
    msg->protection = ASN1_BIT_STRING_new();
    ASN1_BIT_STRING_set(msg->protection, mac.data(), static_cast<int>(mac.size()));
    msg->protection->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    msg->protection->flags |= ASN1_STRING_FLAG_BITS_LEFT;

    unsigned char* out = nullptr;
    int outlen = i2d_CL_PKIMSG(msg, &out);
    if (outlen <= 0) { std::fprintf(stderr, "i2d PKIMessage: %s\n", ossl_err().c_str()); return 1; }

    // ---- send it -----------------------------------------------------------------
    std::string host, path;
    {
        std::string u = url;
        bool tls = u.rfind("https://", 0) == 0;
        size_t s = u.find("://");
        std::string rest = (s == std::string::npos) ? u : u.substr(s + 3);
        size_t slash = rest.find('/');
        host = (tls ? "https://" : "http://") + rest.substr(0, slash == std::string::npos ? rest.size() : slash);
        path = (slash == std::string::npos) ? "/" : rest.substr(slash);
    }
    httplib::Client cli(host.c_str());
    cli.enable_server_certificate_verification(false);
    cli.set_read_timeout(30, 0);
    auto res = cli.Post(path.c_str(), std::string(reinterpret_cast<char*>(out), outlen),
                        "application/pkixcmp");
    OPENSSL_free(out);
    if (!res) { std::fprintf(stderr, "transport: no response from %s%s\n", host.c_str(), path.c_str()); return 1; }
    std::printf("http=%d\n", res->status);
    if (res->body.empty()) { std::fprintf(stderr, "empty response body\n"); return 1; }

    // ---- decode the answer -------------------------------------------------------
    const unsigned char* rp = reinterpret_cast<const unsigned char*>(res->body.data());
    CL_PKIMSG* rsp = d2i_CL_PKIMSG(nullptr, &rp, static_cast<long>(res->body.size()));
    if (!rsp) { std::fprintf(stderr, "response is not a PKIMessage: %s\n", ossl_err().c_str()); return 1; }
    int tag = -1;
    if (rsp->body && rsp->body->type == V_ASN1_OTHER && rsp->body->value.asn1_string) {
        const unsigned char* bp = rsp->body->value.asn1_string->data;
        if (rsp->body->value.asn1_string->length > 0) tag = bp[0] & 0x1f;
    }
    std::printf("body=%d %s\n", tag, body_name(tag));
    if (rsp->header && rsp->header->senderNonce) {
        const unsigned char* d = ASN1_STRING_get0_data(rsp->header->senderNonce);
        int n = ASN1_STRING_length(rsp->header->senderNonce);
        std::printf("senderNonce=");
        for (int i = 0; i < n; ++i) std::printf("%02x", d[i]);
        std::printf("\n");
    }

    // Step inside the body's context tag and decode the alternative it turned out to be.
    // A body this client cannot decode is said so out loud: silence would read as "the
    // server answered nothing", which is a different finding entirely.
    if (rsp->body && rsp->body->type == V_ASN1_OTHER && rsp->body->value.asn1_string) {
        const unsigned char* p = rsp->body->value.asn1_string->data;
        long clen = 0; int ctag = 0, cclass = 0;
        long total = rsp->body->value.asn1_string->length;
        if (ASN1_get_object(&p, &clen, &ctag, &cclass, total) & 0x80) {
            std::fprintf(stderr, "could not step into the body: %s\n", ossl_err().c_str());
        } else if (tag == 1 || tag == 3 || tag == 8) {            // ip / cp / kup
            const unsigned char* q = p;
            CL_CERTREP* rep = d2i_CL_CERTREP(nullptr, &q, clen);
            if (!rep) {
                std::fprintf(stderr, "could not decode CertRepMessage: %s\n", ossl_err().c_str());
            } else {
                for (int i = 0; i < sk_CL_CERTRESPONSE_num(rep->response); ++i) {
                    CL_CERTRESPONSE* cr = sk_CL_CERTRESPONSE_value(rep->response, i);
                    print_statusinfo(cr->status);
                    X509* c = cr->certifiedKeyPair ? cr->certifiedKeyPair->cert : nullptr;
                    if (!c) continue;
                    char* sub = X509_NAME_oneline(X509_get_subject_name(c), nullptr, 0);
                    std::printf("cert_subject=%s\n", sub ? sub : "");
                    OPENSSL_free(sub);
                    if (!certout.empty()) {
                        FILE* f = std::fopen(certout.c_str(), "wb");
                        if (!f) { std::fprintf(stderr, "cannot write %s\n", certout.c_str()); }
                        else { PEM_write_X509(f, c); std::fclose(f);
                               std::printf("certout=%s\n", certout.c_str()); }
                    }
                }
                CL_CERTREP_free(rep);
            }
        } else if (tag == 23) {                                    // error
            const unsigned char* q = p;
            CL_ERRORMSG* em = d2i_CL_ERRORMSG(nullptr, &q, clen);
            if (!em) {
                std::fprintf(stderr, "could not decode ErrorMsgContent: %s\n", ossl_err().c_str());
            } else {
                print_statusinfo(em->status);
                if (em->errorCode)
                    std::printf("errorCode=%ld\n", ASN1_INTEGER_get(em->errorCode));
                for (int i = 0; em->errorDetails && i < sk_ASN1_UTF8STRING_num(em->errorDetails); ++i) {
                    const ASN1_UTF8STRING* t = sk_ASN1_UTF8STRING_value(em->errorDetails, i);
                    std::printf("errorDetail=%.*s\n",
                                ASN1_STRING_length(t), ASN1_STRING_get0_data(t));
                }
                CL_ERRORMSG_free(em);
            }
        }
    }

    CL_PKIMSG_free(rsp);
    CL_PKIMSG_free(msg);
    OSSL_CRMF_PBMPARAMETER_free(pbmp);
    EVP_PKEY_free(newkey);
    return 0;
}
