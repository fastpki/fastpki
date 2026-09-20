// fastpki-scep — SCEP (RFC 8894) server for legacy network devices / MDM.
//
// SCEP runs over plain HTTP; all security is in the CMS (PKCS#7) message layer,
// so this binds a plain httplib::Server (no TLS). One endpoint
// (default /scep/pkiclient.exe) routes on the `operation` query parameter:
//
//   GET  ?operation=GetCACert      -> the CA certificate (DER)
//   GET  ?operation=GetCACaps      -> capability list (text/plain)
//   POST ?operation=PKIOperation   -> a SCEP pkiMessage (PKCS#7) carrying a
//                                      PKCSReq (CSR); returns a CertRep.
//   GET  ?operation=PKIOperation&message=<b64> -> legacy GET form of the above
//
// Issuance reuses the shared pki_lib (parse_csr / issue_cert / Db), so RBAC,
// validity, and audit hooks behave identically to EST.

#include "pki/audit.hpp"
#include "pki/version.hpp"
#include "pki/ca_instance.hpp"
#include "pki/cert_profile.hpp"
#include "pki/enrol_creds.hpp"   // per-user challengePassword
#include "pki/auth.hpp"        // directory_groups_for()
#include "pki/enrol_gate.hpp"    // may_enrol("scep:enrol")
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/endpoint_gate.hpp"
#include "pki/error.hpp"
#include "pki/listen.hpp"
#include "pki/log.hpp"
#include "pki/policy.hpp"
#include "pki/x509.hpp"

#include "scep_cms.hpp"

#include "httplib.h"
#include <stdexcept>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <set>
#include <vector>

namespace {

struct ServerState {
    pki::Config     cfg;
    // The issuing CA is resolved per request from the DB via ca_cache and
    // shared into this state (shared_ptr so .get() still yields the X509*/EVP_PKEY*
    // the handlers use). Not preloaded at startup — a CA-less deploy starts.
    std::shared_ptr<X509>     ca_cert;
    std::shared_ptr<EVP_PKEY> ca_key;
    pki::X509Ptr    ra_cert;          // RA mode: message-layer identity
    pki::EvpPkeyPtr ra_key;
    bool            ra_mode{false};
    pki::X509Ptr    next_ca_cert;     // RFC 8894 §3.5.3: rollover CA cert, if configured
    pki::Db*        db{nullptr};
    pki::CaMaterialCache* ca_cache{nullptr};
    std::string     instance_id{};   // CA instance this state issues for

    // The cert/key that fronts the SCEP message layer: the RA in RA mode, else the
    // signing CA. Clients encrypt PKIOperation envelopes to msg_cert() and the
    // server signs CertReps + decrypts envelopes with this pair. Issuance always
    // uses ca_cert/ca_key (the RA does not sign certs).
    X509*     msg_cert() const { return ra_mode ? ra_cert.get() : ca_cert.get(); }
    EVP_PKEY* msg_key()  const { return ra_mode ? ra_key.get()  : ca_key.get();  }
};

std::string random_token() {
    unsigned char b[16];
    // Checked: an ignored failure leaves `b` uninitialised and mints a guessable token.
    if (RAND_bytes(b, sizeof b) != 1)
        throw std::runtime_error("RAND_bytes failed generating a SCEP token");
    static const char* h = "0123456789abcdef";
    std::string s;
    for (unsigned char c : b) { s += h[c >> 4]; s += h[c & 0xf]; }
    return s;
}

void set_log_level_from_string(std::string_view s) {
    using pki::log::Level;
    if      (s == "debug") pki::log::set_level(Level::Debug);
    else if (s == "info")  pki::log::set_level(Level::Info);
    else                   pki::log::set_level(Level::Err);
}

using pki::scep::CmsPtr;
using pki::scep::BioPtr;
using pki::scep::cms_to_der;
using pki::scep::bio_to_vec;


// base64 decode (for the legacy GET ?message=<b64> form).
std::vector<unsigned char> b64_decode(const std::string& in) {
    std::string clean;
    for (char c : in) if (!std::isspace(static_cast<unsigned char>(c))) clean += c;
    BioPtr b64{BIO_new(BIO_f_base64())};
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_new_mem_buf(clean.data(), static_cast<int>(clean.size()));
    BIO* chain = BIO_push(b64.get(), mem);
    std::vector<unsigned char> out(clean.size());
    int n = BIO_read(chain, out.data(), static_cast<int>(out.size()));
    BIO_pop(b64.get()); BIO_free(mem);
    if (n <= 0) return {};
    out.resize(static_cast<size_t>(n));
    return out;
}

// PKCS#9 challengePassword from a CSR, if present.
std::string csr_challenge_password(X509_REQ* req) {
    int idx = X509_REQ_get_attr_by_NID(req, NID_pkcs9_challengePassword, -1);
    if (idx < 0) return {};
    X509_ATTRIBUTE* attr = X509_REQ_get_attr(req, idx);
    if (!attr) return {};
    // ⚠️ ASN1_TYPE::value IS A TAGGED UNION, AND THIS RAN BEFORE ANY CREDENTIAL WAS
    // CHECKED. It used to read `t->value.asn1_string` without looking at `t->type`.
    // Attribute parsing does not coerce a value to whatever the attribute's NID implies,
    // so an attacker could encode challengePassword as a BOOLEAN: `value.boolean` is an
    // int (0xFF), it aliases the `asn1_string` pointer, the non-null check passes, and
    // ASN1_STRING_get0_data() then dereferences 0xFF. Segfault.
    //
    // Reachable with NO credentials: require_challenge is unconditional for a non-renewal
    // PKCSReq, the CMS signer is self-signed and verified with CMS_NO_SIGNER_CERT_VERIFY,
    // and GetCACert hands out the certificate to encrypt to. So anyone who could reach the
    // port could restart the process at will.
    //
    // Ask OpenSSL to type-filter instead of trusting the tag. X509_ATTRIBUTE_get0_data
    // returns NULL unless the value really carries the requested type, so the union is
    // never read as the wrong member.
    //
    // RFC 2985 defines challengePassword as a DirectoryString — PrintableString or
    // UTF8String — and real devices also emit IA5String and T61String. Accept those four
    // and nothing else: a challenge that arrives as some other type is not a password we
    // can compare, and treating it as one is how this started.
    static const int kTypes[] = { V_ASN1_UTF8STRING, V_ASN1_PRINTABLESTRING,
                                  V_ASN1_IA5STRING,  V_ASN1_T61STRING };
    for (int ty : kTypes) {
        auto* s = static_cast<ASN1_STRING*>(X509_ATTRIBUTE_get0_data(attr, 0, ty, nullptr));
        if (!s) continue;
        const unsigned char* d = ASN1_STRING_get0_data(s);
        const int n = ASN1_STRING_length(s);
        if (!d || n <= 0) return {};
        return std::string(reinterpret_cast<const char*>(d), static_cast<size_t>(n));
    }
    return {};
}

// ── GetCACert (RFC 8894 §4.2) ──────────────────────────────────────────────
// Return the cert the client encrypts PKIOperation envelopes to. In RA mode that
// is the RA cert, returned together with the CA cert as a certs-only PKCS#7 with
// Content-Type application/x-x509-ca-ra-cert (RA first, then CA). Otherwise the
// single signing-CA cert with Content-Type application/x-x509-ca-cert.
void handle_get_cacert(const ServerState& st, httplib::Response& res) {
    res.status = 200;
    if (st.ra_mode) {
        auto p7 = pki::pkcs7_certs_only({st.ra_cert.get(), st.ca_cert.get()});
        res.set_content(std::string(reinterpret_cast<const char*>(p7.data()), p7.size()),
                        "application/x-x509-ca-ra-cert");
        return;
    }
    auto der = pki::x509_to_der(st.ca_cert.get());
    res.set_content(std::string(reinterpret_cast<const char*>(der.data()), der.size()),
                    "application/x-x509-ca-cert");
}

// ── GetCACaps (RFC 8894 §3.5.2) ────────────────────────────────────────────
// Advertise the message-layer capabilities this server supports, one per line.
// "Renewal" and "GetNextCACert" are advertised only when actually enabled.
void handle_get_cacaps(const ServerState& st, httplib::Response& res) {
    std::string caps =
        "POSTPKIOperation\n"
        "SHA-256\n"
        "AES\n"
        "SCEPStandard\n";
    if (st.cfg.scep_allow_sha1) caps += "SHA-1\n";
    if (st.cfg.scep_allow_des3) caps += "DES3\n";
    if (st.cfg.scep_renewal)   caps += "Renewal\n";
    if (st.next_ca_cert)       caps += "GetNextCACert\n";
    res.status = 200;
    res.set_content(caps, "text/plain");
}

// ── GetNextCACert (RFC 8894 §3.5.3 / §4.7) ─────────────────────────────────
// Return the rollover CA certificate signed by the *current* CA key, so a client
// can trust the CA transition. The payload is a SignedData (certs carried in the
// SignerInfo certificate set) over an empty content, per the "next CA cert" form.
void handle_get_next_cacert(const ServerState& st, httplib::Response& res) {
    if (!st.next_ca_cert) {
        res.status = 404;
        res.set_content("no next CA certificate configured", "text/plain");
        return;
    }
    BioPtr content{BIO_new(BIO_s_mem())};
    // Same digest choice as the CertRep — this is a signed response too, and leaving
    // it on the key default while the CertRep obeys the setting would be two answers to
    // one question.
    const unsigned kSignFlags = CMS_PARTIAL | CMS_BINARY | CMS_NOSMIMECAP;
    CmsPtr sd{CMS_sign(nullptr, nullptr, nullptr, content.get(), kSignFlags)};
    if (!sd) { res.status = 500; res.set_content("sign failed", "text/plain"); return; }
    if (!CMS_add1_signer(sd.get(), st.ca_cert.get(), st.ca_key.get(),
                         pki::response_signing_md(st.ca_key.get(), st.ca_cert.get(),
                                                  st.cfg.scep_response_md,
                                                  st.cfg.allow_weak_signature_digest),
                         kSignFlags)) {
        res.status = 500; res.set_content("sign failed", "text/plain"); return;
    }
    // Carry the next CA cert in the SignedData certificate set.
    CMS_add1_cert(sd.get(), st.next_ca_cert.get());
    if (CMS_final(sd.get(), content.get(), nullptr, CMS_BINARY) != 1) {
        res.status = 500; res.set_content("sign finalize failed", "text/plain"); return;
    }
    auto der = cms_to_der(sd.get());
    res.status = 200;
    res.set_content(std::string(reinterpret_cast<const char*>(der.data()), der.size()),
                    "application/x-x509-next-ca-cert");
}

// Parse a DER X.509 cert from memory.
pki::X509Ptr x509_from_der(const std::vector<unsigned char>& der) {
    const unsigned char* p = der.data();
    return pki::X509Ptr{d2i_X509(nullptr, &p, static_cast<long>(der.size()))};
}

// ASN1_INTEGER serial -> lowercase hex, no leading zeros (matches x509_serial_hex
// and how the certs.serial column is keyed).
std::string asn1_int_to_serial_hex(const ASN1_INTEGER* ai) {
    if (!ai) return {};
    std::unique_ptr<BIGNUM, decltype(&BN_free)> bn(ASN1_INTEGER_to_BN(ai, nullptr), &BN_free);
    if (!bn) return {};
    char* h = BN_bn2hex(bn.get());
    if (!h) return {};
    std::string s(h);
    OPENSSL_free(h);
    // The stored form is defined once, in pki::canonical_serial(). This was one of four
    // hand-written copies of the rule; two of the four had drifted (see x509.hpp).
    return pki::canonical_serial(std::move(s));
}

// Decrypt a SCEP EnvelopedData (the inner pkcsPKIEnvelope) with the CA key,
// returning the plaintext messageData. std::nullopt on any failure.
std::optional<std::vector<unsigned char>>
decrypt_env(ServerState& st, const std::vector<unsigned char>& env_der) {
    const unsigned char* ep = env_der.data();
    CmsPtr env{d2i_CMS_ContentInfo(nullptr, &ep, static_cast<long>(env_der.size()))};
    if (!env) return std::nullopt;
    BioPtr out{BIO_new(BIO_s_mem())};
    if (CMS_decrypt(env.get(), st.msg_key(), st.msg_cert(), nullptr,
                    out.get(), CMS_BINARY) != 1)
        return std::nullopt;
    return bio_to_vec(out.get());
}

// ── CertRep (RFC 8894 §3.3) ────────────────────────────────────────────────
// Build the SCEP response. `message_data` is the degenerate PKCS#7 (certs-only
// for issuance/GetCert, crl-only for GetCRL) to wrap; on SUCCESS with a non-empty
// payload and a recipient it is encrypted to the requester (EnvelopedData), then
// the whole thing is signed by the CA (SignedData) with the SCEP authenticated
// attributes. FAILURE/PENDING carry no enveloped messageData.
std::vector<unsigned char> build_certrep_raw(ServerState& st,
                                             const std::vector<unsigned char>& message_data,
                                             X509* recip, const std::string& txid,
                                             const std::vector<unsigned char>& req_sender_nonce,
                                             const char* status,
                                             const char* fail_info = nullptr) {
    BioPtr content{BIO_new(BIO_s_mem())};   // eContent the CA signs over
    if (std::strcmp(status, pki::scep::STATUS_SUCCESS) == 0 && !message_data.empty() && recip) {
        BioPtr p7bio{BIO_new_mem_buf(message_data.data(), static_cast<int>(message_data.size()))};
        STACK_OF(X509)* recips = sk_X509_new_null();
        sk_X509_push(recips, recip);
        CmsPtr env{CMS_encrypt(recips, p7bio.get(), EVP_aes_256_cbc(), CMS_BINARY)};
        sk_X509_free(recips);
        if (!env) return {};
        auto env_der = cms_to_der(env.get());
        BIO_write(content.get(), env_der.data(), static_cast<int>(env_der.size()));
    }
    // The CertRep signature digest is the operator's SCEP_RESPONSE_MD.
    //
    // ⚠️ CMS_sign TAKES NO DIGEST. It asks the key for its default (SHA-256 for RSA), which
    // is why SCEP_ALLOW_SHA1 only ever constrained what a CLIENT could send while the
    // server's own answer was fixed. Naming a signer explicitly is the documented way to
    // choose: CMS_sign with a null cert/key builds the partial structure, CMS_add1_signer
    // adds the SignerInfo with the digest we want. Same flags on both calls, so the
    // SignerInfo is built exactly as before apart from the digest, and the signer
    // certificate still lands in the SignedData certificate set.
    const unsigned kSignFlags = CMS_PARTIAL | CMS_BINARY | CMS_NOSMIMECAP;
    CmsPtr sd{CMS_sign(nullptr, nullptr, nullptr, content.get(), kSignFlags)};
    if (!sd) return {};
    CMS_SignerInfo* si = CMS_add1_signer(
        sd.get(), st.msg_cert(), st.msg_key(),
        pki::response_signing_md(st.msg_key(), st.msg_cert(), st.cfg.scep_response_md,
                                 st.cfg.allow_weak_signature_digest),
        kSignFlags);
    if (!si) return {};
    pki::scep::add_str_attr(si, pki::scep::OID_messageType, pki::scep::MSG_CertRep);
    pki::scep::add_str_attr(si, pki::scep::OID_pkiStatus, status);
    // A FAILURE without a failInfo tells the client only "no". RFC 8894 3.2.1.4
    // makes the attribute mandatory on a failure, and it is the difference between a
    // client reporting "the CA refused this request" and reporting a network problem.
    if (std::strcmp(status, pki::scep::STATUS_FAILURE) == 0)
        pki::scep::add_str_attr(si, pki::scep::OID_failInfo,
                                fail_info ? fail_info : pki::scep::FAIL_BAD_REQUEST);
    pki::scep::add_str_attr(si, pki::scep::OID_transactionID, txid);
    pki::scep::add_octet_attr(si, pki::scep::OID_recipientNonce, req_sender_nonce);
    pki::scep::add_octet_attr(si, pki::scep::OID_senderNonce, pki::scep::random_nonce());
    if (CMS_final(sd.get(), content.get(), nullptr, CMS_BINARY) != 1) return {};
    return cms_to_der(sd.get());
}

// Convenience wrapper: a CertRep carrying a single issued certificate.
std::vector<unsigned char> build_certrep(ServerState& st, X509* issued, X509* recip,
                                         const std::string& txid,
                                         const std::vector<unsigned char>& req_sender_nonce,
                                         const char* status,
                                         const char* fail_info = nullptr) {
    std::vector<unsigned char> msg_data;
    if (std::strcmp(status, pki::scep::STATUS_SUCCESS) == 0 && issued)
        msg_data = pki::pkcs7_certs_only({issued});
    return build_certrep_raw(st, msg_data, recip, txid, req_sender_nonce, status, fail_info);
}

// Send a CertRep (or an HTTP error if it could not be built).
void send_certrep(httplib::Response& res, const std::vector<unsigned char>& rep) {
    if (rep.empty()) {
        res.status = 500;
        res.set_content("failed to build CertRep", "text/plain");
        return;
    }
    res.status = 200;
    res.set_content(std::string(rep.begin(), rep.end()), "application/x-pki-message");
}

// Subject CN of a CSR (for the operator's view of a pending request).
std::string csr_subject_cn(X509_REQ* req) {
    X509_NAME* nm = X509_REQ_get_subject_name(req);
    if (!nm) return {};
    char buf[256];
    int n = X509_NAME_get_text_by_NID(nm, NID_commonName, buf, sizeof buf);
    return n > 0 ? std::string(buf, static_cast<size_t>(n)) : "";
}

// Issue a cert from a verified CSR via the shared lib, persist it, audit it.
// Returns the issued cert and sets out_serial. Throws pki::Error on policy fail.
// Shared by the inline PKCSReq path and the admin --approve path.
pki::X509Ptr issue_from_csr(ServerState& st, X509_REQ* csr, const std::string& actor_ip,
                            const std::string& txid, std::string& out_serial,
                            const std::string& requested_profile = "",
                            const std::string& username = "",
                            // The per-requester cap, resolved by the caller because only it
                            // knows the group set that widens it. Unset means no cap
                            // applies — a dynamic token or a renewal names no subject.
                            const std::optional<int>& max_certs = std::nullopt) {
    // Cert policy profile for SCEP enrollments: SCEP shares the
    // "scep" identity, so a `user:scep` assignment gives all SCEP-issued certs a
    // device-class profile; empty -> the role default.
    //
    // `requested_profile` is the profile a DYNAMIC challenge token was minted
    // for. `--issue-challenge` writes it (scep_challenges.profile) and consume_scep_challenge()
    // returns it, but the call site kept only .has_value() and threw the name away — so
    // a one-time token could not constrain what it issued, which is the only thing that
    // made it different from the shared secret. It goes through resolve_profile() like
    // any other request, so an operator cannot mint a token for a profile the SCEP
    // identity is not allowed to use.
    //
    // When a PER-USER challengePassword identified the caller, the profile is
    // resolved for THAT user — so a per-user credential gets the same profile treatment
    // as the same person enrolling over EST or CMP, instead of everyone sharing one
    // "scep" identity. Without a user it stays "scep", which is every other SCEP path.
    const std::string owner = username.empty() ? std::string("scep") : username;
    const pki::EffectiveProfile profile =
        pki::resolve_profile(*st.db, st.cfg, pki::ProfileIdentity{owner, "",
                                 pki::directory_groups_for(st.cfg, st.db, owner)},
                             /*requested=*/requested_profile);
    pki::IssuanceInput in{
        .cfg = st.cfg, .ca_cert = st.ca_cert.get(), .ca_key = st.ca_key.get(),
        .csr = csr, .owner_username = owner, .profile = profile.name
    };
    in.profile_override = &profile.profile;
    pki::CaUrls urls = pki::ca_urls_for_instance(*st.db, st.cfg, st.instance_id);   // per-CA AIA/CDP
    in.ca_urls = &urls;
    auto cert = pki::issue_cert(in);

    pki::CertRow row;
    row.serial = pki::x509_serial_hex(cert.get());
    row.status = 0;
    // Read from the CERTIFICATE, never the clock. Issuance does not use
    // cert_validity_days verbatim — the profile's max_validity_days can cap it, and
    // notBefore is backdated — so a clock-derived row describes a certificate
    // that does not exist. These columns drive the CA-chain liveness filter, expiry
    // notification and the reissue schedule, all of which then answer about the wrong
    // certificate.
    row.not_before = pki::x509_not_before_unix(cert.get());
    row.not_after  = pki::x509_not_after_unix(cert.get());
    row.cn = pki::x509_cn(cert.get());
    row.subject = row.cn;
    row.owner = owner;
    row.cert_der = pki::x509_to_der(cert.get());
    row.fingerprint = pki::x509_fingerprint_sha256_hex(cert.get());
    row.ca_instance_id = st.instance_id;   // partition key
    // ⚠️ THE CAP IS DECIDED WITH THE WRITE. The handler refuses early with a CertRep the
    // client can read, but that check and this insert are separate statements — two
    // requests can both read max-1 and both commit. pki::Error(1) is what this function
    // already throws for a policy refusal, and the caller renders it as a CertRep.
    if (max_certs && !row.owner.empty()) {
        if (!st.db->insert_cert_within_quota(row, row.owner, *max_certs)) {
            pki::log::info("SCEP refusing '" + row.owner + "' — certificate limit of " +
                           std::to_string(*max_certs) + " reached");
            throw pki::Error(1, "certificate limit reached");
        }
    } else {
        st.db->insert_cert(row);
    }
    out_serial = row.serial;

    try {
        pki::AuditEvent ev;
        ev.category = pki::audit_cat::kLifecycle; ev.action = "cert_issued";
        ev.actor = owner; ev.actor_ip = actor_ip; ev.target = row.serial;
        ev.status = pki::audit_status::kSuccess;
        ev.detail = "protocol=SCEP cn=" + row.cn + " txid=" + txid +
                    " ca_instance=" + st.instance_id;
        st.db->append_audit(ev);
    } catch (const std::exception& e) {
        pki::log::err(std::string("SCEP audit append failed: ") + e.what());
    }
    return cert;
}

// Load an issued cert by serial and build a SUCCESS CertRep carrying it.
std::vector<unsigned char> certrep_for_serial(ServerState& st, const std::string& serial,
                                              X509* recip, const std::string& txid,
                                              const std::vector<unsigned char>& nonce) {
    auto row = st.db->get_cert(serial);
    if (!row || row->cert_der.empty()) return {};
    auto x = x509_from_der(row->cert_der);
    if (!x) return {};
    return build_certrep(st, x.get(), recip, txid, nonce, pki::scep::STATUS_SUCCESS);
}

// ── PKCSReq (RFC 8894 §3.3.1) ──────────────────────────────────────────────
// Inline issuance, or — under SCEP_MANUAL_APPROVAL — park the request as PENDING
// for an operator to approve/reject, with the client polling via GetCertInitial.
void handle_pkcsreq(ServerState& st, const httplib::Request& req, httplib::Response& res,
                    const std::vector<unsigned char>& env_der, X509* client_cert,
                    const std::string& txid, const std::vector<unsigned char>& sender_nonce) {
    auto fail = [&](int http, const std::string& m) {
        pki::log::err("SCEP PKCSReq: " + m);
        res.status = http; res.set_content(m, "text/plain");
    };

    auto plain = decrypt_env(st, env_der);
    if (!plain) return fail(400, "could not decrypt EnvelopedData with the CA key");

    try {
        auto csr = pki::parse_csr(std::string_view(
            reinterpret_cast<const char*>(plain->data()), plain->size()));

        // Renewal (RFC 8894 §3.3.2): if the pkiMessage is signed by a certificate
        // this CA issued that is still valid, possession of that key authenticates
        // the request — no challengePassword is required. We confirm the signer
        // cert verifies under our CA key and its serial is a currently-valid row.
        bool is_renewal = false;
        // WHOSE certificate is being renewed — the identity issuance must speak
        // for. Proof-of-possession authenticates the caller, but a caller is not
        // a subject: resolve_profile() needs the username whose roles decide which
        // profile applies, and the issued row must be owned by the same account
        // that owned its predecessor (CMP authorizes revocation by exactly this
        // certs.owner equality). Left empty for non-renewals and for rows with no
        // owner, which then fall back to the historical "scep" identity downstream.
        std::string renew_owner;
        if (st.cfg.scep_renewal && client_cert) {
            const std::string sn = pki::x509_serial_hex(client_cert);
            std::string why;                       // why this is NOT a renewal
            EVP_PKEY* capub = X509_get0_pubkey(st.ca_cert.get());
            if (!capub || X509_verify(client_cert, capub) != 1) {
                why = "the signer certificate was not issued by this CA";
            } else if (X509_cmp_current_time(X509_get0_notAfter(client_cert)) < 0) {
                // An EXPIRED certificate is not a credential. Nothing checked
                // this, so an expired-but-unrevoked certificate renewed forever — and
                // expiry is the ONLY thing that ever removes a certificate that was never
                // revoked, so without this the renewal right was permanent.
                why = "the signer certificate has expired";
            } else if (X509_cmp_current_time(X509_get0_notBefore(client_cert)) > 0) {
                why = "the signer certificate is not valid yet (check the clock)";
            } else {
                try {
                    auto row = st.db->get_cert(sn);
                    if (!row)                  why = "the signer certificate is not in this database";
                    else if (row->status != 0) why = "the signer certificate is revoked";
                    else                       renew_owner = row->owner;
                } catch (const std::exception& e) {
                    // ⚠️ A lookup FAILURE is not "not revoked". Treating it as one would
                    // turn a database blip into an open renewal window.
                    why = std::string("the signer certificate's status could not be read (") +
                          e.what() + ")";
                }
                // THE binding. A renewal must ask for the identity it already
                // holds; see renewal_mismatch(). Without this the two checks above only
                // proved the caller holds SOME certificate from this CA, and the CSR could
                // then name anything the shared SCEP profile allows — with no challenge.
                if (why.empty()) why = pki::renewal_mismatch(client_cert, csr.get());
                if (why.empty()) is_renewal = true;
            }
            if (is_renewal) {
                pki::log::info("SCEP renewal: authenticated by existing cert serial=" + sn +
                               " (txid=" + txid + ")");
            } else {
                // Not an error by itself — the request simply falls back to needing a
                // challengePassword. But say why, or a client whose renewal was refused
                // sees only "bad challengePassword" and has nothing to act on.
                pki::log::info("SCEP: not treated as a renewal (serial=" + sn + ", txid=" +
                               txid + "): " + why + " — a challengePassword is required");
            }
        }

        // challengePassword: a PER-USER credential or a one-time dynamic
        // token. A renewal (proof-of-possession of a valid issued cert, bound to its
        // identity) bypasses it.
        //
        // ⚠️ THE DEPLOYMENT-WIDE SCEP_CHALLENGE IS GONE — the global value is out of
        // config and out of the demo, because the challenge is per user now. One secret
        // shared by every device names nobody, so `scep:enrol` could not be enforced for
        // it and revoking one device's access meant rotating the value for all of them.
        // SCEP has an identity now; this removes the thing that was standing in for one.
        //
        // ⚠️ THIS CHECK USED TO BE CONDITIONAL, and the condition was a hole of
        // exactly the shape he asked to remove:
        //
        //     require_challenge = !is_renewal &&
        //         (!scep_challenge.empty() || scep_dynamic_challenge);
        //
        // An empty SCEP_CHALLENGE with dynamic off therefore required NO challengePassword
        // at all — SCEP enrolled anyone who could reach the port. It logged a startup
        // WARNING and carried on, which is precisely what AUTH_BACKEND=none did: a
        // legitimate key whose VALUE switches authentication off, guarded only by a log
        // line. install.sh generates a challenge, so a wizard install was safe; a
        // deployment that skipped the wizard, or an admin who cleared the field in the
        // console, was not.
        //
        // Now unconditional. A caller must present something that verifies as a per-user
        // credential or a one-time token. Neither is a config key: per-user challenges
        // read the `keys` table and dynamic tokens the `scep_challenges` table, so there
        // is no longer any value an operator can set that makes SCEP accept everyone.
        const bool require_challenge = !is_renewal;
        // The profile a dynamic token was issued for. `--issue-challenge` writes it and
        // consume_scep_challenge() returns it; the call site used to keep only
        // .has_value() and drop the name, so a one-time token could not pin the profile
        // it was minted for — a reader with no writer, in the direction that matters.
        std::string token_profile;
        // The user a PER-USER challengePassword identified, "" for every other
        // path. This is the identity SCEP has never had, and it is what makes
        // `scep:enrol` enforceable rather than decorative. The kid is the plain
        // username, so this is that value verbatim.
        std::string scep_user;
        if (require_challenge) {
            const std::string presented = csr_challenge_password(csr.get());
            bool ok = false;
            // ⚠️ PER-USER FIRST. A per-user value is "<user>:<secret>" and a dynamic
            // token is a single base64url field with no colon, so the two shapes cannot be
            // confused — but checking this one first means the identity is available for the
            // gate below rather than discovered after the decision.
            {
                std::string kid, secret;
                if (pki::parse_scep_challenge(presented, kid, secret)) {
                    try {
                        auto stored = st.db->get_shared_secret(kid, pki::keyproto::kScep);
                        // Constant-time on the SECRET.
                        if (stored && stored->size() == secret.size() && !secret.empty() &&
                            CRYPTO_memcmp(stored->data(), secret.data(), secret.size()) == 0) {
                            ok = true;
                            scep_user = kid;
                        }
                    } catch (const std::exception& e) {
                        pki::log::err(std::string("SCEP per-user challenge lookup failed: ") + e.what());
                    }
                }
            }
            if (!ok && st.cfg.scep_dynamic_challenge && !presented.empty()) {
                try {
                    if (auto prof = st.db->consume_scep_challenge(presented)) {
                        ok = true;
                        token_profile = *prof;
                    }
                } catch (const std::exception& e) {
                    pki::log::err(std::string("SCEP challenge lookup failed: ") + e.what());
                }
            }
            if (!ok) {
                try {
                    pki::AuditEvent ev;
                    ev.category = pki::audit_cat::kAuth; ev.action = "auth_fail";
                    ev.actor_ip = req.remote_addr; ev.status = pki::audit_status::kFailure;
                    ev.detail = "protocol=SCEP reason=challenge_password";
                    st.db->append_audit(ev);
                } catch (...) {}
                pki::log::info("SCEP rejected: bad challengePassword (txid=" + txid + ")");
                return send_certrep(res, build_certrep(st, nullptr, nullptr, txid,
                                                       sender_nonce, pki::scep::STATUS_FAILURE));
            }
        }

        // The scep:enrol gate. It can exist now BECAUSE the challenge carried an
        // identity — that is the whole reason SCEP was left ungated, and the reasoning at
        // the enforcement site below says so. A request that authenticated some
        // OTHER way (shared secret, dynamic token, renewal) has no user, so there is
        // still nothing to authorize and it passes through exactly as before.
        // ⚠️ CARRIED OUT OF THE BLOCK so the cap can be enforced WITH the insert, which
        // happens in issue_from_csr below. It stays unset for the credentials that name
        // nobody — a dynamic token caps itself by being single-use, and a renewal
        // replaces rather than adds — exactly as the refusal below already reasons.
        std::optional<int> enrol_cap;
        if (!scep_user.empty()) {
            std::string role;
            try {
                if (auto row = st.db->get_web_user(scep_user)) role = row->role;
            } catch (const std::exception& e) {
                // ⚠️ A lookup failure is not "no role". may_enrol fails closed on its own
                // tables; letting a database blip decide the role here would hand it the
                // default instead.
                pki::log::err(std::string("SCEP: role lookup for '") + scep_user +
                              "' failed: " + e.what());
                return send_certrep(res, build_certrep(st, nullptr, nullptr, txid,
                                                       sender_nonce, pki::scep::STATUS_FAILURE));
            }
            // As for CMP — a per-user challenge carries no group list, but a
            // group-granted scep:enrol is still this user's permission.
            // Hoisted, because the CAP below needs the same list the GATE uses.
            // Asking one question with the groups and the next without produced a caller
            // who was admitted on a group-granted role and then had none of that role's
            // limits applied.
            const std::vector<std::string> scep_groups =
                pki::directory_groups_for(st.cfg, st.db, scep_user);
            if (!pki::may_enrol(*st.db, scep_user, role, "scep:enrol", st.instance_id,
                                scep_groups)) {
                try {
                    pki::AuditEvent ev;
                    ev.category = pki::audit_cat::kAuth; ev.action = "auth_fail";
                    ev.actor = scep_user; ev.actor_ip = req.remote_addr;
                    ev.status = pki::audit_status::kFailure;
                    ev.detail = "protocol=SCEP reason=scep:enrol ca=" + st.instance_id;
                    st.db->append_audit(ev);
                } catch (...) {}
                pki::log::info("SCEP rejected: '" + scep_user + "' holds no scep:enrol for CA '" +
                               st.instance_id + "' (txid=" + txid + ")");
                return send_certrep(res, build_certrep(st, nullptr, nullptr, txid,
                                                       sender_nonce, pki::scep::STATUS_FAILURE));
            }

            // The issuance limits, now that SCEP HAS a subject to apply them to.
            //
            // The closing question for SCEP was whether it is now per-user and whether it
            // should be capped as well — yes to both, and SCEP was the
            // only enrolment protocol with no cap at all: EST, CMP, ACME, MS-WSTEP and the
            // console each call role_limit_refusal(); this file called it zero times.
            //
            // ⚠️ WHY IT WAS EXEMPT, AND WHY THAT STOPPED BEING TRUE. When the limits shipped the
            // three limits I wrote "SCEP gets nothing — a challenge password is not a
            // subject", and that was correct THEN: the only credential was a deployment-wide
            // secret naming nobody. SCEP then got a per-user challenge ("<user>:<secret>")
            // and the shared one was deleted, so the premise expired without the exemption
            // being revisited. This is the "reader with no writer" shape in reverse — a rule
            // that outlived its reason.
            //
            // Still inside `if (!scep_user.empty())` on purpose. The two other credentials
            // that still enrol name NOBODY: a one-time dynamic token (single use, so it caps
            // itself) and a renewal, which is bound to the certificate it renews and
            // replaces rather than adds. Applying a per-subject quota to either would mean
            // inventing a subject, which was removed everywhere else.
            const auto lim = pki::role_limits(*st.db, scep_user, role, scep_groups);
            enrol_cap = lim.max_certs;
            const std::string why = pki::role_limit_refusal(
                *st.db, lim, scep_user, csr_subject_cn(csr.get()),
                static_cast<int>(pki::csr_sans(csr.get()).size()));
            if (!why.empty()) {
                try {
                    pki::AuditEvent ev;
                    ev.category = pki::audit_cat::kAuth; ev.action = "authz_fail";
                    ev.actor = scep_user; ev.actor_ip = req.remote_addr;
                    ev.status = pki::audit_status::kFailure;
                    ev.detail = "protocol=SCEP reason=issuance-limit ca=" + st.instance_id;
                    st.db->append_audit(ev);
                } catch (...) {}
                pki::log::info("SCEP refusing '" + scep_user + "' — " + why +
                               " (txid=" + txid + ")");
                // A policy refusal is an ANSWER, not a transport failure — a CertRep
                // carrying badRequest, so the client is told rather than left guessing.
                return send_certrep(res, build_certrep(st, nullptr, nullptr, txid,
                                                       sender_nonce, pki::scep::STATUS_FAILURE,
                                                       pki::scep::FAIL_BAD_REQUEST));
            }
        }

        // Manual-approval (async) enrollment: park as PENDING, idempotent on retry.
        if (st.cfg.scep_manual_approval) {
            if (auto existing = st.db->get_scep_pending(txid)) {
                if (existing->status == 1)        // already approved + issued
                    return send_certrep(res, certrep_for_serial(st, existing->serial,
                                                                client_cert, txid, sender_nonce));
                if (existing->status == 2)        // rejected
                    return send_certrep(res, build_certrep(st, nullptr, nullptr, txid,
                                                           sender_nonce, pki::scep::STATUS_FAILURE));
                // still pending
                return send_certrep(res, build_certrep(st, nullptr, nullptr, txid,
                                                       sender_nonce, pki::scep::STATUS_PENDING));
            }
            pki::Db::ScepPending pend;
            pend.txid = txid;
            pend.subject = csr_subject_cn(csr.get());
            pend.csr_der = *plain;
            st.db->add_scep_pending(pend);
            pki::log::info("SCEP parked pending txid=" + txid + " cn=" + pend.subject);
            return send_certrep(res, build_certrep(st, nullptr, nullptr, txid,
                                                   sender_nonce, pki::scep::STATUS_PENDING));
        }

        // Inline issuance (same path as EST).
        std::string serial;
        // A renewal speaks for the identity that owns the certificate it renews
        // (see renew_owner above) — not the anonymous "scep" fallback, whose lack
        // of any role made resolve_profile() refuse every renewal with "this
        // identity holds no profile permission" the moment per-user challenges
        // gave the ENROLMENT path a real subject.
        auto cert = issue_from_csr(st, csr.get(), req.remote_addr, txid, serial,
                                   token_profile, is_renewal ? renew_owner : scep_user,
                                   is_renewal ? std::nullopt : enrol_cap);
        pki::log::info("SCEP issued serial=" + serial + " cn=" + pki::x509_cn(cert.get()) +
                       " txid=" + txid);
        return send_certrep(res, build_certrep(st, cert.get(), client_cert, txid,
                                               sender_nonce, pki::scep::STATUS_SUCCESS));
    } catch (const pki::Error& e) {
        // A POLICY refusal is an answer, not a transport failure. Error(1) is what
        // issue_from_csr throws for a wildcard the profile forbids, a domain outside
        // allowed_domains, a key below the minimum — decisions this CA made deliberately.
        // Rendering them as HTTP 400 with a text body meant no SCEP client could read
        // them: they surface as a network error, which sends whoever is debugging to the
        // load balancer instead of to their CSR. The two refusal paths in this one handler
        // also disagreed — a bad challengePassword already returned a signed CertRep.
        //
        // Anything else stays an HTTP status, because it genuinely is transport-level: an
        // undecryptable envelope or an internal fault is not a decision about the request.
        if (e.code() == 1) {
            pki::log::err(std::string("SCEP PKCSReq refused by policy: ") + e.what());
            return send_certrep(res, build_certrep(st, nullptr, client_cert, txid,
                                                   sender_nonce, pki::scep::STATUS_FAILURE,
                                                   pki::scep::FAIL_BAD_REQUEST));
        }
        return fail(500, std::string("issuance error: ") + e.what());
    } catch (const std::exception& e) {
        return fail(500, std::string("unexpected: ") + e.what());
    }
}

// ── GetCertInitial (RFC 8894 §3.3.2) ───────────────────────────────────────
// Poll a manual-approval request by transactionID: PENDING / FAILURE / SUCCESS.
void handle_getcertinitial(ServerState& st, httplib::Response& res, X509* client_cert,
                           const std::string& txid,
                           const std::vector<unsigned char>& sender_nonce) {
    std::optional<pki::Db::ScepPending> pend;
    try { pend = st.db->get_scep_pending(txid); }
    catch (const std::exception& e) {
        pki::log::err(std::string("SCEP GetCertInitial lookup failed: ") + e.what());
        res.status = 500; res.set_content("lookup failed", "text/plain"); return;
    }
    if (!pend || pend->status == 2)   // unknown or rejected
        return send_certrep(res, build_certrep(st, nullptr, nullptr, txid, sender_nonce,
                                               pki::scep::STATUS_FAILURE));
    if (pend->status == 0)            // still awaiting an operator
        return send_certrep(res, build_certrep(st, nullptr, nullptr, txid, sender_nonce,
                                               pki::scep::STATUS_PENDING));
    // approved + issued: return the cert, encrypted to the polling client.
    pki::log::info("SCEP GetCertInitial -> issued serial=" + pend->serial + " txid=" + txid);
    return send_certrep(res, certrep_for_serial(st, pend->serial, client_cert, txid, sender_nonce));
}

// ── GetCert (RFC 8894 §3.3.3) ──────────────────────────────────────────────
// Fetch a previously issued cert named by IssuerAndSerialNumber in the envelope.
void handle_getcert(ServerState& st, httplib::Response& res,
                    const std::vector<unsigned char>& env_der, X509* client_cert,
                    const std::string& txid, const std::vector<unsigned char>& sender_nonce) {
    auto plain = decrypt_env(st, env_der);
    if (!plain) { res.status = 400; res.set_content("decrypt failed", "text/plain"); return; }
    const unsigned char* ip = plain->data();
    std::unique_ptr<PKCS7_ISSUER_AND_SERIAL, decltype(&PKCS7_ISSUER_AND_SERIAL_free)>
        ias(d2i_PKCS7_ISSUER_AND_SERIAL(nullptr, &ip, static_cast<long>(plain->size())),
            &PKCS7_ISSUER_AND_SERIAL_free);
    if (!ias) { res.status = 400; res.set_content("bad IssuerAndSerial", "text/plain"); return; }
    const std::string serial = asn1_int_to_serial_hex(ias->serial);
    auto rep = certrep_for_serial(st, serial, client_cert, txid, sender_nonce);
    if (rep.empty()) {   // not found
        pki::log::info("SCEP GetCert miss serial=" + serial + " txid=" + txid);
        return send_certrep(res, build_certrep(st, nullptr, nullptr, txid, sender_nonce,
                                               pki::scep::STATUS_FAILURE));
    }
    pki::log::info("SCEP GetCert hit serial=" + serial + " txid=" + txid);
    return send_certrep(res, rep);
}

// ── GetCRL (RFC 8894 §3.3.4) ───────────────────────────────────────────────
// Return the CA's CRL (single signing CA, so the IssuerAndSerial in the request
// is not used to choose among CAs) wrapped in a crl-only degenerate PKCS#7.
void handle_getcrl(ServerState& st, httplib::Response& res, X509* client_cert,
                   const std::string& txid, const std::vector<unsigned char>& sender_nonce) {
    try {
        // This route WRAPS the CRL in a CMS reply, so unlike the two HTTP routes it
        // needs the bytes rather than a response — an imported CRL is fed through exactly
        // the same wrapping as a generated one, and a GetCRL client cannot tell which it
        // got, which is the point.
        std::vector<unsigned char> crl_der;
        if (!st.ca_key) {   // remote CA key — nothing local to sign with
            std::string stale;
            auto stored = pki::imported_crl(*st.db, st.instance_id, /*is_delta=*/false, stale);
            if (!stored) {
                res.status = 503;
                res.set_content("CRL unavailable: the CA signing key is remote and no "
                                "signed CRL has been imported for this CA", "text/plain");
                return;
            }
            if (!stale.empty()) pki::log::err(stale);
            // Never silent, for the same reason as the other two serving paths: this is
            // otherwise the only place a CA whose key is unreachable here differs from a
            // healthy one, and GetCRL succeeds either way.
            pki::log::info("GetCRL for CA '" + st.instance_id + "': no usable signing key "
                           "here — serving the stored CRL instead");
            crl_der = std::move(*stored);
        } else {
            crl_der = pki::generate_crl(st.cfg, *st.db, st.ca_cert.get(), st.ca_key.get(),
                                        st.instance_id);   // this instance's CRL
        }
        const unsigned char* cp = crl_der.data();
        std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)>
            crl(d2i_X509_CRL(nullptr, &cp, static_cast<long>(crl_der.size())), &X509_CRL_free);
        if (!crl) { res.status = 500; res.set_content("CRL parse failed", "text/plain"); return; }
        auto msg_data = pki::pkcs7_crl_only(crl.get());
        pki::log::info("SCEP GetCRL served (txid=" + txid + ")");
        return send_certrep(res, build_certrep_raw(st, msg_data, client_cert, txid,
                                                   sender_nonce, pki::scep::STATUS_SUCCESS));
    } catch (const std::exception& e) {
        pki::log::err(std::string("SCEP GetCRL failed: ") + e.what());
        res.status = 500; res.set_content("CRL generation failed", "text/plain");
    }
}

// ── PKIOperation (RFC 8894 §4.3) ───────────────────────────────────────────
// Parse + verify the outer SignedData common to every pkiMessage, then dispatch
// on messageType.
void handle_pki_operation(ServerState& st, const httplib::Request& req,
                          httplib::Response& res) {
    auto fail = [&](int http, const std::string& m) {
        pki::log::err("SCEP PKIOperation: " + m);
        res.status = http; res.set_content(m, "text/plain");
    };

    std::vector<unsigned char> msg;
    if (req.method == "POST")
        msg.assign(req.body.begin(), req.body.end());
    else
        msg = b64_decode(req.get_param_value("message"));
    if (msg.empty()) return fail(400, "empty pkiMessage");

    const unsigned char* p = msg.data();
    CmsPtr sd{d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(msg.size()))};
    if (!sd) return fail(400, "pkiMessage is not a valid SignedData");
    BioPtr envbio{BIO_new(BIO_s_mem())};
    // SCEP signers are self-signed; skip chain verification but still check the
    // signature over the content.
    if (CMS_verify(sd.get(), nullptr, nullptr, nullptr, envbio.get(),
                   CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY) != 1)
        return fail(400, "SignedData signature verification failed");

    CMS_SignerInfo* si = pki::scep::first_signer(sd.get());
    if (!si) return fail(400, "pkiMessage has no SignerInfo");
    const std::string msg_type = pki::scep::get_str_attr(si, pki::scep::OID_messageType);
    const std::string txid     = pki::scep::get_str_attr(si, pki::scep::OID_transactionID);
    const auto sender_nonce    = pki::scep::get_octet_attr(si, pki::scep::OID_senderNonce);

    // ⚠️ get0 REFERS TO THE CERTIFICATES, NOT TO THE STACK. CMS_get0_signers() allocates
    // the STACK_OF(X509) container and the caller owns it; the X509s inside stay owned by
    // the CMS structure, which is why this is sk_X509_free and never sk_X509_pop_free.
    // Nothing freed it, on any path, so every PKIOperation leaked one container.
    // sk_X509_free is a MACRO, so it has no address to take — the deleter is a lambda.
    auto free_sk = [](STACK_OF(X509)* sk) { sk_X509_free(sk); };
    std::unique_ptr<STACK_OF(X509), decltype(free_sk)>
        signers(CMS_get0_signers(sd.get()), free_sk);
    X509* client_cert = (signers && sk_X509_num(signers.get()) > 0)
                            ? sk_X509_value(signers.get(), 0) : nullptr;
    if (!client_cert) return fail(400, "no signer certificate in pkiMessage");

    const auto env_der = bio_to_vec(envbio.get());

    if (msg_type == pki::scep::MSG_PKCSReq)
        handle_pkcsreq(st, req, res, env_der, client_cert, txid, sender_nonce);
    else if (msg_type == pki::scep::MSG_GetCertInitial)
        handle_getcertinitial(st, res, client_cert, txid, sender_nonce);
    else if (msg_type == pki::scep::MSG_GetCert)
        handle_getcert(st, res, env_der, client_cert, txid, sender_nonce);
    else if (msg_type == pki::scep::MSG_GetCRL)
        handle_getcrl(st, res, client_cert, txid, sender_nonce);
    else
        fail(400, "unsupported messageType " + msg_type);
}

void route(ServerState& st, const httplib::Request& req, httplib::Response& res) {
    const std::string op = req.get_param_value("operation");
    if (op == "GetCACert")        handle_get_cacert(st, res);
    else if (op == "GetCACaps")   handle_get_cacaps(st, res);
    else if (op == "GetNextCACert") handle_get_next_cacert(st, res);
    else if (op == "PKIOperation") handle_pki_operation(st, req, res);
    else {
        res.status = 400;
        res.set_content("unknown or missing operation", "text/plain");
    }
}

// Resolve THIS CA's RA certificate from the DB, per request.
//
// One RA key for the process (SCEP_RA_KEY, a pkcs11: URI), N certificates — one per CA,
// each issued BY that CA and stored under cert_id "<scep_ra_cert_id_prefix>-<ca_id>". The same
// shape the CMP RA reached for, and the OCSP responder after it, for the same
// reason: an RA that fronts CA 'a' must be certified by 'a', so a single instance-wide
// PEM file could be correct for at most one CA.
//
// Per request rather than at startup so a reissue takes effect with no restart, and so
// expiry and revocation are actually noticed. Returns nullptr with `why` filled in.
static pki::X509Ptr resolve_ra_cert(const pki::Config& cfg, pki::Db& db,
                                    const std::string& ca_id, EVP_PKEY* ra_key,
                                    std::string& why) {
    const std::string cert_id = cfg.scep_ra_cert_id_prefix + "-" + ca_id;
    auto der = db.get_cert_by_cert_id(cert_id);   // status=0 only: covers revocation
    if (!der || der->empty()) {
        why = "no valid certificate for cert_id '" + cert_id + "' (missing, or revoked) — "
              "SCEP RA mode is configured for CA '" + ca_id + "' but that CA has issued no "
              "RA certificate (Inventory -> Request, key in HSM -> Serve as SCEP RA).";
        return nullptr;
    }
    const unsigned char* p = der->data();
    pki::X509Ptr cert{d2i_X509(nullptr, &p, static_cast<long>(der->size()))};
    if (!cert) { why = "the certificate for cert_id '" + cert_id + "' does not parse"; return nullptr; }

    if (X509_cmp_current_time(X509_get0_notAfter(cert.get())) < 0) {
        why = "the SCEP RA certificate '" + cert_id + "' has EXPIRED — issue a new one "
              "from CA '" + ca_id + "'";
        return nullptr;
    }
    if (X509_cmp_current_time(X509_get0_notBefore(cert.get())) > 0) {
        why = "the SCEP RA certificate '" + cert_id + "' is not valid YET (notBefore is in "
              "the future) — check the clock on this host";
        return nullptr;
    }
    // The certificate must certify the key this process holds. Without this the failure
    // surfaces as unattributed OpenSSL noise from deep inside the CMS envelope open
    // (learned the hard way), and reissuing is exactly when a fresh key pair
    // gets minted by mistake.
    // ⚠️ pki::cert_certifies_key handles the RSA-vs-RSA-PSS type mismatch that
    // X509_check_private_key alone reports as a different key pair. A PSS-restricted SCEP
    // RA credential would otherwise be refused here for a reason that is not true.
    if (ra_key && !pki::cert_certifies_key(cert.get(), ra_key)) {
        why = "the certificate '" + cert_id + "' does not match the SCEP RA key this "
              "process holds — it was issued for a DIFFERENT key pair. Reissue it for the "
              "key at SCEP_RA_KEY.";
        return nullptr;
    }
    return cert;
}

// Virtualized per-CA SCEP: <scep_path>/{id} — a trailing path segment,
// consistent with EST's inline label and CMP's /cmp/{id}. SCEP secures
// the message (not the channel), and every crypto operation — GetCACert,
// envelope decryption, CertRep signing — uses the state's CA pair. So we build a
// per-request ServerState bound to the instance's signing material and route
// through it; the issuance handler tags certs with instance_id. The trust anchor,
// rollover CA, and RA identity are propagated so GetCACert/GetNextCACert/RA mode
// work here too. Also serves the base (no-id) route via the tenant default CA.
void route_instance(const ServerState& st, const std::string& id,
                    const httplib::Request& req, httplib::Response& res) {
    try {
        // Resolve + load this instance's material from the DB via the shared
        // cache (loaded on a miss / reference change, reused otherwise — no pkcs11
        // re-read per request; no preloaded global). Unknown/inert -> 404, disabled or
        // an incomplete backing -> 503.
        int code = 500; std::string err;
        auto m = st.ca_cache->get(*st.db, st.cfg, id, code, err);
        if (!m) {
            // ⚠️ SCEP CANNOT SERVE A REPLICATED CRL, AND THAT IS THE PROTOCOL, NOT AN
            // OVERSIGHT. A GetCRL reply is a signed certRep — build_certrep_raw() calls
            // CMS_add1_signer(st.msg_cert(), st.msg_key()) — so answering requires the CA's
            // (or RA's) private key. A peer that holds only a replicated CRL has neither,
            // and a bare DER CRL is not something a SCEP client can parse.
            //
            // The store's RFC 4387 route and the OCSP daemon's /{ca_id}.crl both serve the
            // CRL as bytes, so both DO fall back to the replicated copy for a CA this node
            // cannot sign for. SCEP does not, and a client whose CA's node is down must
            // fetch revocation over one of those instead.
            //
            // (A guard here once tested `operation == "GetCRL"`. GetCRL is a messageType
            // INSIDE a PKIOperation body, never an operation value — route() accepts only
            // GetCACert, GetCACaps, GetNextCACert and PKIOperation — so it could not fire.)
            res.status = code; res.set_content(err, "text/plain"); return;
        }
        ServerState ist;
        ist.cfg = st.cfg; ist.db = st.db; ist.instance_id = m->id;
        ist.ca_cert = m->cert;
        ist.ca_key  = m->key;
        // Propagate the trust anchor, rollover CA, and RA identity so GetCACert
        // (chain), GetNextCACert (RFC 8894 §3.5.3), and RA mode all work
        // on the per-CA route too: an RA fronts the named tenant CA.
        if (!st.cfg.scep_next_ca_cert_pem.empty())
            ist.next_ca_cert = pki::load_cert_pem(st.cfg.scep_next_ca_cert_pem);
        // RA mode is driven by the KEY alone; the certificate comes from the DB,
        // per CA, per request.
        //
        // ⚠️ load_key_file_or_token, NOT load_privkey_pem. The latter is
        // PEM_read_bio_PrivateKey on a FILE and has no pkcs11 branch, so SCEP could not
        // hold a token key AT ALL — a pkcs11: URI in SCEP_RA_KEY was handed to a PEM
        // reader and rejected. CMP and OCSP have used the token-capable loader since
        // SCEP was missed by that change. The reported symptom was that SCEP does not
        // notice an HSM restart because it holds no keys — this is the cause.
        if (!st.cfg.scep_ra_key_pem.empty()) {
            ist.ra_key = pki::load_key_file_or_token(st.cfg.scep_ra_key_pem.string(), st.cfg);
            // ⚠️ The SCEP RA key DECRYPTS the PKIOperation envelope (CMS_decrypt
            // below), so it must be able to do RSA key transport. Nothing checked, and a
            // non-RSA key therefore failed only when a client actually enrolled — as an
            // opaque 400 "could not decrypt EnvelopedData", naming neither the key nor the
            // cause. Refusing on both ends is the agreed behaviour; this is the serving
            // end, the console's issuance guard is the other.
            //
            // RSA-PSS is NOT acceptable and is not a pedantic exclusion: OpenSSL refuses
            // the operation at context-init, so such a client cannot even build the
            // envelope to send us.
            if (ist.ra_key && EVP_PKEY_get_base_id(ist.ra_key.get()) != EVP_PKEY_RSA) {
                const char* tn = EVP_PKEY_get0_type_name(ist.ra_key.get());
                const std::string w =
                    std::string("SCEP RA key is ") + (tn ? tn : "not RSA") +
                    ", but the RA decrypts the PKIOperation envelope and that needs RSA key "
                    "transport. Issue the SCEP RA credential with an RSA key (SCEP_RA_KEY).";
                pki::log::err("SCEP RA (CA '" + m->id + "'): " + w);
                res.status = 503; res.set_content(w, "text/plain"); return;
            }
            std::string why;
            ist.ra_cert = resolve_ra_cert(st.cfg, *st.db, m->id, ist.ra_key.get(), why);
            if (!ist.ra_cert) {
                // Refusing loudly beats silently falling back to the CA key for the message
                // layer: that is the very thing RA mode exists to avoid, and a silent
                // downgrade would be indistinguishable from working (and the rule
                // that a missing RA credential is an error, not a fallback).
                pki::log::err("SCEP RA (CA '" + m->id + "'): " + why);
                res.status = 503; res.set_content(why, "text/plain"); return;
            }
            ist.ra_mode = true;
        }
        route(ist, req, res);
    } catch (const std::exception& e) {
        pki::log::err(std::string("SCEP instance '") + id + "': " + e.what());
        res.status = 500; res.set_content("CA material unavailable", "text/plain");
    }
}

} // namespace

// ── SCEP's enrol:* gate applies to a PER-USER challenge, and only to that ──────
//
// SCEP was left ungated, and the reason was sound:
//
//     SCEP stays untagged. The only identity in SCEP is a certificate and an optional
//     challenge password, so it is left open for anyone to use — devices in most cases,
//     not humans.
//
// That is a statement about SCEP as it then was: there was no user to authorize, so
// `scep:enrol` was removed, because a permission nothing enforces is
// an assurance the product does not keep.
//
// SCEP has an identity now. A per-user challengePassword is "<user>:<secret>",
// minted alongside the CMP and ACME credentials, so a request carrying one names a
// `web_users` row — chosen over substituting the deployment-wide SCEP_CHALLENGE into
// every user's downloadable config, as the more secure option that still does not break
// the SCEP RFC.
// Nothing about RFC 8894 changes: the challengePassword is a PKCS#9 attribute and the
// RFC never said its value had to be shared. The shared value was then removed
// entirely — "it's per user now".
//
// ⚠️ The gate therefore applies to THAT path and nothing else. A device presenting a
// one-time dynamic token, or renewing an existing certificate, still has no user, so
// there is still nothing to authorize and it passes exactly as before. That ruling
// is intact for the case it was about — device enrolment does not break — and the new
// permission is enforced everywhere it can mean something.

int main(int argc, char** argv) {
    if (pki::handled_version_flag(argc, argv)) return 0;
    std::string conf_path = "config/bootstrap.conf";
    std::string mint_profile; bool do_mint = false; int64_t mint_ttl = 3600;
    std::string approve_txid, reject_txid, approve_ca; bool do_list_pending = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) conf_path = argv[++i];
        else if (std::strcmp(argv[i], "--issue-challenge") == 0) {
            do_mint = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') mint_profile = argv[++i];
        }
        else if (std::strcmp(argv[i], "--ttl") == 0 && i + 1 < argc) mint_ttl = std::atoll(argv[++i]);
        else if (std::strcmp(argv[i], "--approve") == 0 && i + 1 < argc) approve_txid = argv[++i];
        else if (std::strcmp(argv[i], "--ca") == 0 && i + 1 < argc) approve_ca = argv[++i];
        else if (std::strcmp(argv[i], "--reject") == 0 && i + 1 < argc) reject_txid = argv[++i];
        else if (std::strcmp(argv[i], "--list-pending") == 0) do_list_pending = true;
        else if (std::strcmp(argv[i], "--help") == 0) {
            std::cout << "Usage: fastpki-scep [--config path]\n"
                         "       fastpki-scep --config path --issue-challenge [profile] [--ttl seconds]\n"
                         "         issue a one-time challenge token (requires SCEP_DYNAMIC_CHALLENGE)\n"
                         "       fastpki-scep --config path --list-pending\n"
                         "       fastpki-scep --config path --approve <txid> --ca <ca_id>\n"
                         "       fastpki-scep --config path --reject  <txid>\n"
                         "         operate the manual-approval queue (SCEP_MANUAL_APPROVAL)\n";
            return 0;
        }
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    try {
        ServerState st;
        st.cfg = pki::Config::load(conf_path);
        set_log_level_from_string(st.cfg.log_level);

        // No signing CA is preloaded at startup — every PKIOperation resolves
        // its CA per request from the DB via ca_cache (route_instance), so a CA-less
        // deploy starts. The base (no-id) path 404s; RA/rollover material is opt-in and
        // loaded per request into the instance state below.

        // RA mode: SCEP_RA_KEY alone enables it. The
        // certificate is per CA and resolved from the DB per request (resolve_ra_cert),
        // so nothing is loaded here — a CA-less deploy still starts, and an RA
        // certificate issued later needs no restart.
        //
        // SCEP_RA_CERT is gone, so the "needs both" error is gone with it. Validating the
        // key here would also be wrong: with the token behind p11-kit the key may not be
        // reachable at startup, which is the liveness problem.
        std::unique_ptr<pki::Db> db_owner;
        db_owner = pki::make_postgres_db(st.cfg.pg_conninfo);
        st.db = db_owner.get();
        pki::overlay_config(st.cfg, st.db->get_config());   // DB config overlay
        pki::load_cert_profiles(st.cfg, *st.db);              // the replicated profiles
        // ⚠️ RE-APPLIED AFTER overlay_config, AND THAT IS THE WHOLE POINT. The level was
        // set above from bootstrap.conf ALONE, so LOG_LEVEL=debug in the `config` table — the
        // console's Config page, which is where an operator actually sets it — reached
        // st.cfg only here and never reached the logger at all. The reported symptom is
        // exactly that: "nothing is written in the logs even when LOG_LEVEL is set to
        // DEBUG in the Config table", which reads as a product with no diagnostics rather
        // than as a setting that was silently ignored.
        //
        // Applied TWICE on purpose. The early call governs anything logged before the
        // database is reachable — a bad conninfo, a dead token — which the DB obviously
        // cannot configure. This one governs everything after, and the DB is the source of
        // truth once it can be read.
        //
        // Same shape as the AUTH_BACKEND and SCEP-challenge lines fixed earlier in this
        // family: a value read before the overlay describes bootstrap.conf, not the deployment.
        set_log_level_from_string(st.cfg.log_level);
        pki::load_allowed_domains(st.cfg, *st.db);
        pki::resolve_datacenter_prefix(st.cfg, *st.db);

        // This used to warn that "enrollment requires no challenge password", which
        // was true and was ignored. A challengePassword is now ALWAYS required, so the
        // statement to make is not a warning about a hole — it is which credentials can
        // satisfy it. The deployment-wide value is gone, so per-user is no longer
        // one option among several: unless dynamic tokens are on, it is the only way in.
        if (!st.cfg.scep_dynamic_challenge)
            // ⚠️ Keep "requires a PER-USER challengePassword" on ONE source line.
            // no_insecure_settings.sh greps this file for that phrase, and a string split
            // across two literals is invisible to grep while the LOG still reads correctly
            // — a guard that goes quietly vacuous with nothing to notice.
            pki::log::info("SCEP: dynamic challenge tokens are off — enrolment requires a PER-USER challengePassword"
                           " (\"<user>:<secret>\", issued with the user's role)."
                           " A challenge is never optional.");

        // ⚠️ MOVED HERE with the challenge check, and for the same reason (e47051f):
        // both read config, and everything that reads config has to run AFTER the DB
        // overlay or it sees bootstrap.conf instead of what the operator actually set.
        //
        // The rollover certificate is the one that was not merely mis-logged: it is LOADED
        // here, so SCEP_NEXT_CA_CERT set from the console produced no st.next_ca_cert at
        // all — GetNextCACert stayed off and nothing said why. A file-only setting is not
        // what the console promises.
        //
        // CA key rollover (RFC 8894 §3.5.3): load the next/rollover CA cert if set.
        if (!st.cfg.scep_next_ca_cert_pem.empty()) {
            st.next_ca_cert = pki::load_cert_pem(st.cfg.scep_next_ca_cert_pem);
            pki::log::info("SCEP GetNextCACert enabled: " + st.cfg.scep_next_ca_cert_pem.string());
        }

        // RA mode: SCEP_RA_KEY alone enables it. The
        // certificate is per CA and resolved from the DB per request (resolve_ra_cert), so
        // nothing is loaded here — a CA-less deploy still starts, and an RA certificate
        // issued later needs no restart. Only the banner moved: the ENABLEMENT was always
        // read per request (route_instance), so RA mode from the console did work; the
        // startup line just failed to mention it.
        if (!st.cfg.scep_ra_key_pem.empty())
            pki::log::info("SCEP RA mode: message layer fronted by the RA key at "
                           + st.cfg.scep_ra_key_pem.string() + "; certificate per CA from "
                           "the DB under cert_id '" + st.cfg.scep_ra_cert_id_prefix + "-<ca_id>'");

        // The shared per-{ca-id} material cache. Used by the server routes
        // (route_instance) and by the CLI approve path below.
        pki::CaMaterialCache ca_cache;
        st.ca_cache = &ca_cache;

        // Admin: mint a one-time challenge token and exit (don't start the server).
        if (do_mint) {
            if (!st.cfg.scep_dynamic_challenge)
                pki::log::err("WARNING: SCEP_DYNAMIC_CHALLENGE is not enabled — this "
                              "token won't be accepted until it is.");
            // Now that the profile on a token is actually USED, minting one the
            // SCEP identity is not entitled to has to fail HERE, at the mistake, and not
            // silently three weeks later when a device tries to enrol and gets an
            // unexplained failure. resolve_profile() throws for an unpermitted request;
            // this asks it the same question with the same arguments the enrolment will.
            if (!mint_profile.empty()) {
                try {
                    // A STARTUP check, not a request: there is no caller and therefore no
                    // groups. Written out rather than left to default so the empty list is
                    // a statement, not an omission the next reader has to judge.
                    (void)pki::resolve_profile(*st.db, st.cfg,
                                               pki::ProfileIdentity{"scep", "", {}}, mint_profile);
                } catch (const std::exception& e) {
                    std::cerr << "fastpki-scep: refusing to issue a challenge for profile '"
                              << mint_profile << "': " << e.what()
                              << "\n  Grant it to the SCEP identity first: give a role a "
                                 "`profile:use` permission scoped to '" << mint_profile
                              << "' and assign that role to user 'scep'.\n";
                    return 1;
                }
            }
            std::string token = random_token();
            st.db->add_scep_challenge(token, mint_profile,
                                      std::time(nullptr) + mint_ttl);
            std::cout << token << "\n";
            std::cerr << "issued SCEP challenge (profile='" << mint_profile
                      << "', ttl=" << mint_ttl << "s)\n";
            return 0;
        }

        // Admin: list pending manual-approval requests and exit.
        if (do_list_pending) {
            auto pend = st.db->list_scep_pending(0);
            std::cerr << pend.size() << " pending request(s)\n";
            for (const auto& p : pend)
                std::cout << p.txid << "\t" << p.subject << "\n";
            return 0;
        }

        // Admin: approve a pending request — issue the parked CSR and record the
        // serial so the client's next GetCertInitial returns SUCCESS.
        if (!approve_txid.empty()) {
            auto pend = st.db->get_scep_pending(approve_txid);
            if (!pend) { std::cerr << "no pending request with txid " << approve_txid << "\n"; return 1; }
            if (pend->status != 0) { std::cerr << "txid " << approve_txid
                                               << " is not pending (status=" << pend->status << ")\n"; return 1; }
            auto csr = pki::parse_csr(std::string_view(
                reinterpret_cast<const char*>(pend->csr_der.data()), pend->csr_der.size()));
            // No default CA — the operator names the issuing CA with --ca <ca_id>
            // (the pending queue records no per-CA instance).
            if (approve_ca.empty()) {
                std::cerr << "cannot approve: name the issuing CA with --ca <ca_id>\n"; return 1; }
            int ca_code = 500; std::string ca_err;
            auto m = ca_cache.get(*st.db, st.cfg, approve_ca, ca_code, ca_err);
            if (!m) { std::cerr << "cannot approve: CA '" << approve_ca << "' unavailable: "
                                << ca_err << "\n"; return 1; }
            st.ca_cert = m->cert; st.ca_key = m->key; st.instance_id = m->id;
            std::string serial;
            issue_from_csr(st, csr.get(), "cli", approve_txid, serial);
            st.db->set_scep_pending_status(approve_txid, 1, serial);
            std::cout << serial << "\n";
            std::cerr << "approved txid " << approve_txid << " -> serial " << serial << "\n";
            return 0;
        }

        // Admin: reject a pending request.
        if (!reject_txid.empty()) {
            auto pend = st.db->get_scep_pending(reject_txid);
            if (!pend) { std::cerr << "no pending request with txid " << reject_txid << "\n"; return 1; }
            st.db->set_scep_pending_status(reject_txid, 2, "");
            std::cerr << "rejected txid " << reject_txid << "\n";
            return 0;
        }

        httplib::Server srv;   // plain HTTP — SCEP secures the message, not the channel
        srv.set_payload_max_length(256 * 1024);
        // The base (no-id) path serves the request tenant's DEFAULT (first) CA
        // — routed through the same per-instance path as a named <path>/{id}. A
        // tenant with no servable CA yet (a fresh deploy) → 404.
        // SCEP is an enrolment protocol, so it is id-based — every request names a
        // /{ca_id}. There is no base (no-id) route: with a root + subCA hierarchy "the
        // first CA" is ambiguous, so we never guess one.
        auto base = [&](const httplib::Request&, httplib::Response& res) {
            res.status = 404;
            res.set_content("this endpoint is per-CA: use <scep_path>/{ca_id}", "text/plain");
        };
        srv.Get (st.cfg.scep_path, base);
        srv.Post(st.cfg.scep_path, base);
        // Virtualized per-CA SCEP: <scep_path>/{ca_instance_id}
        // (trailing segment, matching CMP's /cmp/{id}).
        const std::string ipath = st.cfg.scep_path + R"(/([^/]+))";
        srv.Get (ipath,
                 [&](const httplib::Request& req, httplib::Response& res) {
                     route_instance(st, req.matches[1].str(), req, res); });
        srv.Post(ipath,
                 [&](const httplib::Request& req, httplib::Response& res) {
                     route_instance(st, req.matches[1].str(), req, res); });

        pki::log::info("fastpki-scep listening on " + st.cfg.scep_bind_addr + ":" +
                       std::to_string(st.cfg.scep_port) + " (" + st.cfg.scep_path + ")");
        // Never open the port while this protocol is switched off in the
        // console, and stop if it is switched off later.
        //
        // WATCH THE RA KEY. This call used to pass neither the config nor a key,
        // and `probe_token` in endpoint_gate.cpp is `app_cfg != nullptr && uri starts
        // with pkcs11:` — so scep was the one service that never probed its token at
        // all (cmp/est/acme/ms all pass theirs). Two consequences, both permanent for
        // the life of the process, because the pkcs11 provider is loaded into a
        // function-local static in ensure_pkcs11_provider() and initialises ONCE:
        //
        //   * scep starts before the p11-kit sidecar is reachable -> the provider load
        //     fails once and is never retried, so every later request fails even after
        //     the sidecar is healthy. This is the deployment race that was hit.
        //   * the sidecar restarts under a running scep -> this process's session is
        //     dead, and nothing notices.
        //
        // Both surface as `no private key found at pkcs11 URI` on every request while
        // the key is plainly in the token. The probe makes scep exit so the restart
        // policy hands it a fresh provider connection, which is what the other services
        // have long been doing.
        //
        // An empty SCEP_RA_KEY (no RA mode) or a file path leaves probe_token false, so
        // this costs nothing when there is no token key to watch.
        pki::gate_protocol(*st.db, "scep", &st.cfg,
                           [u = st.cfg.scep_ra_key_pem.string()] { return u; });
        std::string bound;
        if (!pki::bind_listener(srv, st.cfg.scep_bind_addr, st.cfg.scep_port, bound)) {
            std::cerr << "listen failed\n";
            return 1;
        }
        if (!srv.listen_after_bind()) {
            std::cerr << "listen failed\n";
            return 1;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << '\n';
        return 1;
    }
}
