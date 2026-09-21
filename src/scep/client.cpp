// scep-testclient — a minimal OpenSSL-based SCEP client used to exercise
// fastpki-scep in tests (and as a reference for the message construction). No
// new CI dependency: it reuses pki_lib + OpenSSL CMS, the same primitives the
// server uses. HTTP is left to the test harness (curl) — this tool only builds
// the request bytes and parses the response bytes.
//
//   build <ca.pem> <client_cert.pem> <client_key.pem> <csr.der> <out_request.der>
//       Wrap the CSR in a SCEP PKCSReq pkiMessage: EnvelopedData(CSR -> CA),
//       SignedData signed by the client cert with messageType=PKCSReq +
//       transactionID + senderNonce. Prints the transactionID to stdout.
//
//   getcertinitial <ca.pem> <client_cert.pem> <client_key.pem> <txid> <out.der>
//       A GetCertInitial poll for a pending request (IssuerAndSubject payload),
//       reusing the given transactionID.
//
//   getcert <ca.pem> <client_cert.pem> <client_key.pem> <issuer.pem> <serial_hex> <out.der>
//       A GetCert query (IssuerAndSerialNumber payload).
//
//   getcrl <ca.pem> <client_cert.pem> <client_key.pem> <issuer.pem> <out.der>
//       A GetCRL query (IssuerAndSerialNumber payload).
//
//   parse <client_cert.pem> <client_key.pem> <response.der> <out_issued.der>
//       Verify+open the CertRep, print pkiStatus, decrypt the EnvelopedData with
//       the client key, and write the issued certificate (DER). Exit 0 on
//       SUCCESS, 2 on a non-success pkiStatus.
//
//   parsecrl <client_cert.pem> <client_key.pem> <response.der> <out_crl.der>
//       Like parse, but extracts the CRL from a GetCRL CertRep.

#include "scep_cms.hpp"
#include "pki/x509.hpp"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

using namespace pki::scep;

namespace {

std::vector<unsigned char> read_file(const char* path) {
    std::ifstream f(path, std::ios::binary);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(f)),
                                      std::istreambuf_iterator<char>());
}
bool write_file(const char* path, const std::vector<unsigned char>& d) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(d.data()), static_cast<std::streamsize>(d.size()));
    return static_cast<bool>(f);
}
std::string hex(const std::vector<unsigned char>& b) {
    static const char* h = "0123456789abcdef";
    std::string s;
    for (unsigned char c : b) { s += h[c >> 4]; s += h[c & 0xf]; }
    return s;
}

// DER SEQUENCE wrapper around an already-encoded body (definite length).
std::vector<unsigned char> der_sequence(const std::vector<unsigned char>& body) {
    std::vector<unsigned char> out{0x30};
    size_t n = body.size();
    if (n < 0x80) out.push_back(static_cast<unsigned char>(n));
    else {
        std::vector<unsigned char> len;
        while (n) { len.insert(len.begin(), static_cast<unsigned char>(n & 0xff)); n >>= 8; }
        out.push_back(static_cast<unsigned char>(0x80 | len.size()));
        out.insert(out.end(), len.begin(), len.end());
    }
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

// IssuerAndSubject ::= SEQUENCE { issuer Name, subject Name } — both taken from
// the client cert's subject (the server keys off transactionID, not this).
std::vector<unsigned char> make_issuer_and_subject(X509* cc) {
    X509_NAME* nm = X509_get_subject_name(cc);
    int nlen = i2d_X509_NAME(nm, nullptr);
    std::vector<unsigned char> name(static_cast<size_t>(nlen));
    unsigned char* p = name.data(); i2d_X509_NAME(nm, &p);
    std::vector<unsigned char> body = name;       // issuer
    body.insert(body.end(), name.begin(), name.end());  // subject
    return der_sequence(body);
}

// IssuerAndSerialNumber from an issuer cert + a hex serial.
std::vector<unsigned char> make_issuer_and_serial(X509* issuer, const char* serial_hex) {
    PKCS7_ISSUER_AND_SERIAL* ias = PKCS7_ISSUER_AND_SERIAL_new();
    X509_NAME_set(&ias->issuer, X509_get_subject_name(issuer));
    BIGNUM* bn = nullptr; BN_hex2bn(&bn, serial_hex);
    ASN1_INTEGER_free(ias->serial);
    ias->serial = BN_to_ASN1_INTEGER(bn, nullptr);
    BN_free(bn);
    int len = i2d_PKCS7_ISSUER_AND_SERIAL(ias, nullptr);
    std::vector<unsigned char> out(static_cast<size_t>(len));
    unsigned char* p = out.data(); i2d_PKCS7_ISSUER_AND_SERIAL(ias, &p);
    PKCS7_ISSUER_AND_SERIAL_free(ias);
    return out;
}

// Build a SCEP pkiMessage: EnvelopedData(payload -> ca) wrapped in a SignedData
// signed by the client cert with messageType/transactionID/senderNonce attrs.
int build_message(X509* ca, X509* cc, EVP_PKEY* ck, const char* msg_type,
                  const std::string& txid, const std::vector<unsigned char>& payload,
                  const char* out_path) {
    BioPtr pbio{BIO_new_mem_buf(payload.data(), static_cast<int>(payload.size()))};
    STACK_OF(X509)* recips = sk_X509_new_null();
    sk_X509_push(recips, ca);
    CmsPtr env{CMS_encrypt(recips, pbio.get(), EVP_aes_256_cbc(), CMS_BINARY)};
    sk_X509_free(recips);
    if (!env) { std::fprintf(stderr, "CMS_encrypt failed\n"); return 1; }
    auto env_der = cms_to_der(env.get());

    BioPtr envbio{BIO_new_mem_buf(env_der.data(), static_cast<int>(env_der.size()))};
    CmsPtr sd{CMS_sign(cc, ck, nullptr, envbio.get(),
                       CMS_PARTIAL | CMS_BINARY | CMS_NOSMIMECAP)};
    if (!sd) { std::fprintf(stderr, "CMS_sign failed\n"); return 1; }
    CMS_SignerInfo* si = first_signer(sd.get());
    add_str_attr(si, OID_messageType, msg_type);
    add_str_attr(si, OID_transactionID, txid);
    add_octet_attr(si, OID_senderNonce, random_nonce());
    if (CMS_final(sd.get(), envbio.get(), nullptr, CMS_BINARY) != 1) {
        std::fprintf(stderr, "CMS_final failed\n"); return 1;
    }
    return write_file(out_path, cms_to_der(sd.get())) ? 0 : 1;
}

int do_build(char** a) {
    pki::X509Ptr    ca = pki::load_cert_pem(a[0]);
    pki::X509Ptr    cc = pki::load_cert_pem(a[1]);
    pki::EvpPkeyPtr ck = pki::load_privkey_pem(a[2]);
    auto csr = read_file(a[3]);
    if (csr.empty()) { std::fprintf(stderr, "empty CSR\n"); return 1; }
    std::string txid = "TXID-" + hex(random_nonce(8));
    int rc = build_message(ca.get(), cc.get(), ck.get(), MSG_PKCSReq, txid, csr, a[4]);
    if (rc == 0) std::printf("%s\n", txid.c_str());   // emit txid for GetCertInitial
    return rc;
}

// A CSR whose challengePassword is a BOOLEAN rather than a string.
//
// ⚠️ IT MUST BE PROPERLY SIGNED. `parse_csr` verifies the POP before the SCEP handler ever
// looks at the attribute, so a CSR mutated with sed would be rejected one step too early
// and the suite would prove nothing. An attacker has exactly this capability — it is their
// own key — so the CSR is BUILT with the odd type and then signed normally.
//
// This lives in the test client because no legitimate client can produce it: `openssl req`
// only ever writes challengePassword as a string.
int do_badcsr(char** a) {
    pki::EvpPkeyPtr key = pki::load_privkey_pem(a[0]);
    pki::X509ReqPtr req{X509_REQ_new()};
    if (!req) { std::fprintf(stderr, "X509_REQ_new failed\n"); return 1; }
    X509_REQ_set_version(req.get(), 0);
    X509_NAME* nm = X509_REQ_get_subject_name(req.get());
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(a[1]), -1, -1, 0);
    if (!X509_REQ_set_pubkey(req.get(), key.get())) {
        std::fprintf(stderr, "set_pubkey failed\n"); return 1; }
    // V_ASN1_BOOLEAN: ASN1_TYPE::value.boolean is an int, and it ALIASES the
    // asn1_string pointer member of the same union. 0xFF is what the server used to
    // dereference.
    X509_ATTRIBUTE* at = X509_ATTRIBUTE_create(NID_pkcs9_challengePassword,
                                               V_ASN1_BOOLEAN,
                                               reinterpret_cast<void*>(static_cast<intptr_t>(0xFF)));
    if (!at) { std::fprintf(stderr, "X509_ATTRIBUTE_create failed\n"); return 1; }
    if (!X509_REQ_add1_attr(req.get(), at)) {
        X509_ATTRIBUTE_free(at); std::fprintf(stderr, "add1_attr failed\n"); return 1; }
    X509_ATTRIBUTE_free(at);
    if (!X509_REQ_sign(req.get(), key.get(), EVP_sha256())) {
        std::fprintf(stderr, "X509_REQ_sign failed\n"); return 1; }
    unsigned char* der = nullptr;
    const int n = i2d_X509_REQ(req.get(), &der);
    if (n <= 0) { std::fprintf(stderr, "i2d_X509_REQ failed\n"); return 1; }
    std::vector<unsigned char> out(der, der + n);
    OPENSSL_free(der);
    return write_file(a[2], out) ? 0 : 1;
}

int do_getcertinitial(char** a) {
    pki::X509Ptr    ca = pki::load_cert_pem(a[0]);
    pki::X509Ptr    cc = pki::load_cert_pem(a[1]);
    pki::EvpPkeyPtr ck = pki::load_privkey_pem(a[2]);
    std::string txid = a[3];
    return build_message(ca.get(), cc.get(), ck.get(), MSG_GetCertInitial, txid,
                         make_issuer_and_subject(cc.get()), a[4]);
}

int do_getcert(char** a) {
    pki::X509Ptr    ca  = pki::load_cert_pem(a[0]);
    pki::X509Ptr    cc  = pki::load_cert_pem(a[1]);
    pki::EvpPkeyPtr ck  = pki::load_privkey_pem(a[2]);
    pki::X509Ptr    iss = pki::load_cert_pem(a[3]);
    std::string txid = "TXID-" + hex(random_nonce(8));
    return build_message(ca.get(), cc.get(), ck.get(), MSG_GetCert, txid,
                         make_issuer_and_serial(iss.get(), a[4]), a[5]);
}

int do_getcrl(char** a) {
    pki::X509Ptr    ca  = pki::load_cert_pem(a[0]);
    pki::X509Ptr    cc  = pki::load_cert_pem(a[1]);
    pki::EvpPkeyPtr ck  = pki::load_privkey_pem(a[2]);
    pki::X509Ptr    iss = pki::load_cert_pem(a[3]);
    std::string txid = "TXID-" + hex(random_nonce(8));
    return build_message(ca.get(), cc.get(), ck.get(), MSG_GetCRL, txid,
                         make_issuer_and_serial(iss.get(), "01"), a[4]);
}

// Verify a CertRep and return its pkiStatus + the decrypted, inner messageData
// (a degenerate PKCS7). Returns false if the response is not a SUCCESS the
// caller can open; `status` is always set.
bool open_certrep(char** a, std::string& status, std::vector<unsigned char>& inner_p7) {
    pki::X509Ptr    cc = pki::load_cert_pem(a[0]);
    pki::EvpPkeyPtr ck = pki::load_privkey_pem(a[1]);
    auto resp = read_file(a[2]);
    if (resp.empty()) { std::fprintf(stderr, "empty response\n"); return false; }

    const unsigned char* p = resp.data();
    CmsPtr sd{d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(resp.size()))};
    if (!sd) { std::fprintf(stderr, "response is not SignedData\n"); return false; }
    BioPtr envbio{BIO_new(BIO_s_mem())};
    if (CMS_verify(sd.get(), nullptr, nullptr, nullptr, envbio.get(),
                   CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY) != 1) {
        std::fprintf(stderr, "CertRep signature verify failed\n"); return false;
    }
    CMS_SignerInfo* si = first_signer(sd.get());
    status = get_str_attr(si, OID_pkiStatus);
    if (status != STATUS_SUCCESS) return false;

    auto env_der = bio_to_vec(envbio.get());
    const unsigned char* ep = env_der.data();
    CmsPtr env{d2i_CMS_ContentInfo(nullptr, &ep, static_cast<long>(env_der.size()))};
    if (!env) { std::fprintf(stderr, "inner is not EnvelopedData\n"); return false; }
    BioPtr p7bio{BIO_new(BIO_s_mem())};
    if (CMS_decrypt(env.get(), ck.get(), cc.get(), nullptr, p7bio.get(), CMS_BINARY) != 1) {
        std::fprintf(stderr, "CMS_decrypt failed\n"); return false;
    }
    inner_p7 = bio_to_vec(p7bio.get());
    return true;
}

int do_parse(char** a) {
    std::string status; std::vector<unsigned char> p7der;
    bool ok = open_certrep(a, status, p7der);
    std::printf("pkiStatus=%s\n", status.c_str());
    if (!ok) return status == STATUS_SUCCESS ? 1 : 2;
    const unsigned char* pp = p7der.data();
    CmsPtr p7{d2i_CMS_ContentInfo(nullptr, &pp, static_cast<long>(p7der.size()))};
    if (!p7) { std::fprintf(stderr, "messageData is not a PKCS7\n"); return 1; }
    STACK_OF(X509)* certs = CMS_get1_certs(p7.get());
    if (!certs || sk_X509_num(certs) < 1) { std::fprintf(stderr, "no cert in CertRep\n"); return 1; }
    X509* issued = sk_X509_value(certs, 0);
    int rc = write_file(a[3], pki::x509_to_der(issued)) ? 0 : 1;
    sk_X509_pop_free(certs, X509_free);
    return rc;
}

int do_parsecrl(char** a) {
    std::string status; std::vector<unsigned char> p7der;
    bool ok = open_certrep(a, status, p7der);
    std::printf("pkiStatus=%s\n", status.c_str());
    if (!ok) return status == STATUS_SUCCESS ? 1 : 2;
    const unsigned char* pp = p7der.data();
    CmsPtr p7{d2i_CMS_ContentInfo(nullptr, &pp, static_cast<long>(p7der.size()))};
    if (!p7) { std::fprintf(stderr, "messageData is not a PKCS7\n"); return 1; }
    STACK_OF(X509_CRL)* crls = CMS_get1_crls(p7.get());
    if (!crls || sk_X509_CRL_num(crls) < 1) { std::fprintf(stderr, "no CRL in CertRep\n"); return 1; }
    X509_CRL* crl = sk_X509_CRL_value(crls, 0);
    int len = i2d_X509_CRL(crl, nullptr);
    std::vector<unsigned char> der(static_cast<size_t>(len));
    unsigned char* dp = der.data(); i2d_X509_CRL(crl, &dp);
    int rc = write_file(a[3], der) ? 0 : 1;
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    return rc;
}

} // namespace

int main(int argc, char** argv) {
    OpenSSL_add_all_algorithms();
    try {
        std::string cmd = argc > 1 ? argv[1] : "";
        if (cmd == "build"          && argc == 7) return do_build(argv + 2);
        if (cmd == "badcsr"         && argc == 5) return do_badcsr(argv + 2);
        if (cmd == "getcertinitial" && argc == 7) return do_getcertinitial(argv + 2);
        if (cmd == "getcert"        && argc == 8) return do_getcert(argv + 2);
        if (cmd == "getcrl"         && argc == 7) return do_getcrl(argv + 2);
        if (cmd == "parse"          && argc == 6) return do_parse(argv + 2);
        if (cmd == "parsecrl"       && argc == 6) return do_parsecrl(argv + 2);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "scep-testclient: %s\n", e.what());
        return 1;
    }
    std::fprintf(stderr,
        "Usage:\n"
        "  scep-testclient build <ca.pem> <client_cert.pem> <client_key.pem> <csr.der> <out.der>\n"
        "  scep-testclient badcsr <key.pem> <cn> <out.der>   (BOOLEAN challengePassword)\n"
        "  scep-testclient getcertinitial <ca.pem> <client_cert.pem> <client_key.pem> <txid> <out.der>\n"
        "  scep-testclient getcert <ca.pem> <client_cert.pem> <client_key.pem> <issuer.pem> <serial_hex> <out.der>\n"
        "  scep-testclient getcrl <ca.pem> <client_cert.pem> <client_key.pem> <issuer.pem> <out.der>\n"
        "  scep-testclient parse <client_cert.pem> <client_key.pem> <response.der> <out_issued.der>\n"
        "  scep-testclient parsecrl <client_cert.pem> <client_key.pem> <response.der> <out_crl.der>\n");
    return 2;
}
