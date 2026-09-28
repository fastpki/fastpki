// A stand-in for the Microsoft endpoints fastpki-scep talks to for Intune: Entra's token
// endpoint, the two Graph calls (the Intune service list and the app registration, with
// addKey/removeKey), and Intune's SCEP validation and revocation services — all on one HTTPS
// port. tests/intune_scep.sh drives fastpki-scep against it.
//
// It CHECKS what it is sent rather than accepting anything: a client assertion must be a
// PS256 JWT whose x5t#S256 names a registered certificate and whose signature verifies with
// that certificate's key; an addKey/removeKey proof must be an RS256 JWT signed by a
// registered certificate, issued by the app's object id, for Graph's audience. So the suite
// proves the credential really works the way Entra requires, not merely that requests arrive.
//
// ⚠️ TEST-ONLY, and not named fastpki-*: the image copies binaries by that prefix, so this
// is excluded from the product by the glob. See dnsstub.cpp.
//
// Usage: intune-stub <port> <cert.pem> <key.pem> <state-dir>
//
// State directory:
//   registered/<sha1>.der   certificates the app registration holds. The suite copies one
//                           in to play the administrator's upload; addKey/removeKey edit it.
//   revoke                  serial numbers (one per line) the next revocation download hands
//                           out, then removed — Intune hands a batch to one caller.
//   events.log              one line per request handled, for the suite to assert on.
//
// The challenge decides the validation answer: "intune-good" -> Success, "intune-expired" ->
// ChallengeExpired, "intune-notifyfail" -> Success, but the success notification for that
// transaction is refused.
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include "../../third_party/nlohmann/json.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

std::string g_state;
std::mutex g_mu;
std::map<std::string, std::string> g_challenge_by_txid;
constexpr const char* kObjectId = "11111111-2222-3333-4444-555555555555";

void event(const std::string& line) {
    std::lock_guard<std::mutex> lk(g_mu);
    std::ofstream(g_state + "/events.log", std::ios::app) << line << "\n";
}

std::vector<unsigned char> b64dec(std::string s, bool url) {
    if (url) {
        for (auto& c : s) { if (c == '-') c = '+'; else if (c == '_') c = '/'; }
        while (s.size() % 4) s += '=';
    }
    std::vector<unsigned char> out(s.size());
    int n = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(s.data()),
                            static_cast<int>(s.size()));
    if (n < 0) return {};
    size_t len = static_cast<size_t>(n);
    for (size_t i = s.size(); i > 0 && s[i - 1] == '=' && len; --i) --len;
    out.resize(len);
    return out;
}
std::string b64enc(const std::vector<unsigned char>& v, bool url) {
    std::string out(4 * ((v.size() + 2) / 3) + 1, '\0');
    int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), v.data(), static_cast<int>(v.size()));
    out.resize(static_cast<size_t>(n));
    if (url) {
        for (auto& c : out) { if (c == '+') c = '-'; else if (c == '/') c = '_'; }
        while (!out.empty() && out.back() == '=') out.pop_back();
    }
    return out;
}
std::vector<unsigned char> md(const EVP_MD* m, const std::vector<unsigned char>& in) {
    std::vector<unsigned char> o(EVP_MAX_MD_SIZE);
    unsigned n = 0;
    EVP_Digest(in.data(), in.size(), o.data(), &n, m, nullptr);
    o.resize(n);
    return o;
}
std::string hex(const std::vector<unsigned char>& v) {
    static const char* h = "0123456789abcdef";
    std::string s;
    for (unsigned char c : v) { s += h[c >> 4]; s += h[c & 15]; }
    return s;
}
std::vector<unsigned char> read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}
// A keyId is a GUID; derive a stable one from the thumbprint.
std::string key_id_of(const std::string& sha1) {
    return sha1.substr(0, 8) + "-" + sha1.substr(8, 4) + "-" + sha1.substr(12, 4) + "-" +
           sha1.substr(16, 4) + "-" + sha1.substr(20, 12);
}

struct Reg { std::string sha1; std::vector<unsigned char> der; };
std::vector<Reg> registered() {
    std::vector<Reg> out;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(g_state + "/registered", ec)) {
        if (e.path().extension() != ".der") continue;
        out.push_back({e.path().stem().string(), read_file(e.path())});
    }
    return out;
}

// Verify a compact JWT against a registered certificate named by its header. `thumb_key` is
// "x5t#S256" (SHA-256) or "x5t" (SHA-1); `pss` selects PS256 over RS256. Returns the claims,
// or null with `why` set.
json verify_jwt(const std::string& tok, const char* thumb_key, bool pss, std::string& why,
                std::string* cert_sha1 = nullptr) {
    const auto d1 = tok.find('.'), d2 = tok.find('.', d1 + 1);
    if (d1 == std::string::npos || d2 == std::string::npos) { why = "not a JWT"; return nullptr; }
    const auto hb = b64dec(tok.substr(0, d1), true), cb = b64dec(tok.substr(d1 + 1, d2 - d1 - 1), true);
    const auto sig = b64dec(tok.substr(d2 + 1), true);
    const json h = json::parse(std::string(hb.begin(), hb.end()), nullptr, false);
    const json c = json::parse(std::string(cb.begin(), cb.end()), nullptr, false);
    if (!h.is_object() || !c.is_object()) { why = "unparseable JWT"; return nullptr; }
    if (h.value("alg", "") != (pss ? "PS256" : "RS256")) { why = "wrong alg " + h.value("alg", ""); return nullptr; }
    if (!h.contains(thumb_key)) { why = std::string("no ") + thumb_key; return nullptr; }
    const std::string want = h[thumb_key].get<std::string>();
    for (const auto& r : registered()) {
        const bool s256 = std::string(thumb_key) == "x5t#S256";
        if (b64enc(md(s256 ? EVP_sha256() : EVP_sha1(), r.der), true) != want) continue;
        const unsigned char* p = r.der.data();
        X509* x = d2i_X509(nullptr, &p, static_cast<long>(r.der.size()));
        EVP_PKEY* k = x ? X509_get_pubkey(x) : nullptr;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX* pctx = nullptr;
        bool ok = k && EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), nullptr, k) == 1;
        if (ok && pss) ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
                            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_AUTO) > 0;
        const std::string in = tok.substr(0, d2);
        if (ok) ok = EVP_DigestVerify(ctx, sig.data(), sig.size(),
                                      reinterpret_cast<const unsigned char*>(in.data()), in.size()) == 1;
        EVP_MD_CTX_free(ctx); EVP_PKEY_free(k); X509_free(x);
        if (!ok) { why = "signature does not verify"; return nullptr; }
        if (c.value("exp", 0LL) < static_cast<long long>(std::time(nullptr))) { why = "expired"; return nullptr; }
        if (cert_sha1) *cert_sha1 = r.sha1;
        return c;
    }
    why = "AADSTS700027: the certificate is not registered on the app";
    return nullptr;
}

bool bearer_ok(const httplib::Request& req) {
    return req.get_header_value("Authorization").rfind("Bearer tok-", 0) == 0;
}
void reply(httplib::Response& res, int status, const json& j) {
    res.status = status;
    res.set_content(j.dump(), "application/json");
}

std::string challenge_of(const std::string& csr_b64) {
    const auto der = b64dec(csr_b64, false);
    const unsigned char* p = der.data();
    X509_REQ* r = d2i_X509_REQ(nullptr, &p, static_cast<long>(der.size()));
    if (!r) return {};
    std::string out;
    int i = X509_REQ_get_attr_by_NID(r, NID_pkcs9_challengePassword, -1);
    if (i >= 0) {
        X509_ATTRIBUTE* a = X509_REQ_get_attr(r, i);
        ASN1_TYPE* t = a ? X509_ATTRIBUTE_get0_type(a, 0) : nullptr;
        if (t && (t->type == V_ASN1_PRINTABLESTRING || t->type == V_ASN1_UTF8STRING ||
                  t->type == V_ASN1_IA5STRING))
            out.assign(reinterpret_cast<const char*>(t->value.asn1_string->data),
                       static_cast<size_t>(t->value.asn1_string->length));
    }
    X509_REQ_free(r);
    return out;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 5) {
        std::cerr << "usage: intune-stub <port> <cert.pem> <key.pem> <state-dir>\n";
        return 2;
    }
    const int port = std::atoi(argv[1]);
    g_state = argv[4];
    fs::create_directories(g_state + "/registered");
    httplib::SSLServer srv(argv[2], argv[3]);
    if (!srv.is_valid()) { std::cerr << "intune-stub: cannot load the TLS pair\n"; return 1; }

    // ── Entra: client-credentials token, authenticated by a certificate assertion ──
    srv.Post(R"(/([^/]+)/oauth2/v2\.0/token)", [](const httplib::Request& req, httplib::Response& res) {
        const std::string tenant = req.matches[1];
        const std::string client = req.get_param_value("client_id"), scope = req.get_param_value("scope");
        if (req.get_param_value("grant_type") != "client_credentials" ||
            req.get_param_value("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") {
            event("token refused: wrong grant");
            return reply(res, 400, {{"error", "invalid_request"}, {"error_description", "wrong grant"}});
        }
        std::string why, sha1;
        const json c = verify_jwt(req.get_param_value("client_assertion"), "x5t#S256", true, why, &sha1);
        const std::string aud_tail = "/" + tenant + "/oauth2/v2.0/token";
        if (c.is_null() || c.value("iss", "") != client || c.value("sub", "") != client ||
            c.value("aud", "").size() < aud_tail.size() ||
            c.value("aud", "").compare(c.value("aud", "").size() - aud_tail.size(), aud_tail.size(), aud_tail) != 0) {
            if (why.empty()) why = "iss/sub/aud do not match";
            event("token refused: " + why);
            return reply(res, 401, {{"error", "invalid_client"}, {"error_description", why}});
        }
        event("token scope=" + scope + " cert=" + sha1);
        reply(res, 200, {{"token_type", "Bearer"}, {"expires_in", 3600},
                         {"access_token", "tok-" + sha1.substr(0, 8)}});
    });

    // ── Graph: the Intune service list ──
    srv.Get(R"(/v1\.0/servicePrincipals/appId=0000000a-0000-0000-c000-000000000000/endpoints)",
            [](const httplib::Request& req, httplib::Response& res) {
        if (!bearer_ok(req)) return reply(res, 401, {{"error", {{"message", "no token"}}}});
        const std::string base = "https://" + req.get_header_value("Host");
        event("discovery");
        reply(res, 200, {{"value", json::array({
            {{"providerName", "ScepRequestValidationFEService"}, {"uri", base + "/svc/scep"}},
            {{"providerName", "PkiConnectorFEService"}, {"uri", base + "/svc/pki"}}})}});
    });

    // ── Graph: the app registration and its certificates ──
    srv.Get(R"(/v1\.0/applications\(appId='([^']+)'\))", [](const httplib::Request& req, httplib::Response& res) {
        if (!bearer_ok(req)) return reply(res, 401, {{"error", {{"message", "no token"}}}});
        json keys = json::array();
        for (const auto& r : registered()) {
            std::vector<unsigned char> raw;
            for (size_t i = 0; i + 1 < r.sha1.size(); i += 2)
                raw.push_back(static_cast<unsigned char>(std::stoi(r.sha1.substr(i, 2), nullptr, 16)));
            keys.push_back({{"keyId", key_id_of(r.sha1)}, {"type", "AsymmetricX509Cert"},
                            {"usage", "Verify"}, {"customKeyIdentifier", b64enc(raw, false)}, {"key", nullptr}});
        }
        reply(res, 200, {{"id", kObjectId}, {"appId", std::string(req.matches[1])}, {"keyCredentials", keys}});
    });
    auto check_proof = [](const json& body, std::string& why) {
        const json c = verify_jwt(body.value("proof", ""), "x5t", false, why);
        if (c.is_null()) return false;
        if (c.value("iss", "") != kObjectId) { why = "proof issuer is not the app object id"; return false; }
        if (c.value("aud", "") != "00000002-0000-0000-c000-000000000000") { why = "proof audience"; return false; }
        return true;
    };
    srv.Post(std::string("/v1.0/applications/") + kObjectId + "/addKey",
             [check_proof](const httplib::Request& req, httplib::Response& res) {
        if (!bearer_ok(req)) return reply(res, 401, {{"error", {{"message", "no token"}}}});
        const json b = json::parse(req.body, nullptr, false);
        std::string why;
        if (!b.is_object() || !check_proof(b, why)) {
            event("addKey refused: " + why);
            return reply(res, 400, {{"error", {{"message", why}}}});
        }
        const auto der = b64dec(b["keyCredential"].value("key", ""), false);
        const std::string sha1 = hex(md(EVP_sha1(), der));
        std::ofstream(g_state + "/registered/" + sha1 + ".der", std::ios::binary)
            .write(reinterpret_cast<const char*>(der.data()), static_cast<std::streamsize>(der.size()));
        event("addKey " + sha1);
        reply(res, 200, {{"keyId", key_id_of(sha1)}});
    });
    srv.Post(std::string("/v1.0/applications/") + kObjectId + "/removeKey",
             [check_proof](const httplib::Request& req, httplib::Response& res) {
        if (!bearer_ok(req)) return reply(res, 401, {{"error", {{"message", "no token"}}}});
        const json b = json::parse(req.body, nullptr, false);
        std::string why;
        if (!b.is_object() || !check_proof(b, why)) {
            event("removeKey refused: " + why);
            return reply(res, 400, {{"error", {{"message", why}}}});
        }
        for (const auto& r : registered())
            if (key_id_of(r.sha1) == b.value("keyId", "")) {
                fs::remove(g_state + "/registered/" + r.sha1 + ".der");
                event("removeKey " + r.sha1);
                res.status = 204;
                return;
            }
        reply(res, 404, {{"error", {{"message", "No credentials found to be removed"}}}});
    });

    // ── Intune: SCEP validation and notifications ──
    srv.Post("/svc/scep/ScepActions/validateRequest", [](const httplib::Request& req, httplib::Response& res) {
        if (!bearer_ok(req) || req.get_header_value("api-version") != "2018-02-20")
            return reply(res, 401, {{"code", "Unknown"}});
        const json b = json::parse(req.body, nullptr, false);
        const json r = b.is_object() ? b.value("request", json::object()) : json::object();
        const std::string txid = r.value("transactionId", ""), ch = challenge_of(r.value("certificateRequest", ""));
        {
            std::lock_guard<std::mutex> lk(g_mu);
            g_challenge_by_txid[txid] = ch;
        }
        event("validate txid=" + txid + " challenge=" + ch + " caller=" + r.value("callerInfo", ""));
        if (ch == "intune-good" || ch == "intune-notifyfail") return reply(res, 200, {{"code", "Success"}});
        if (ch == "intune-expired")
            return reply(res, 200, {{"code", "ChallengeExpired"}, {"errorDescription", "the challenge has expired"}});
        reply(res, 200, {{"code", "ChallengeDecryptionError"}, {"errorDescription", "not an Intune challenge"}});
    });
    srv.Post("/svc/scep/ScepActions/successNotification", [](const httplib::Request& req, httplib::Response& res) {
        if (!bearer_ok(req)) return reply(res, 401, {{"code", "Unknown"}});
        const json n = json::parse(req.body, nullptr, false).value("notification", json::object());
        const std::string txid = n.value("transactionId", "");
        std::string ch;
        {
            std::lock_guard<std::mutex> lk(g_mu);
            ch = g_challenge_by_txid[txid];
        }
        event("success txid=" + txid + " serial=" + n.value("certificateSerialNumber", "") +
              " thumbprint=" + n.value("certificateThumbprint", "") +
              " expiry=" + n.value("certificateExpirationDateUtc", "") +
              " issuer=" + n.value("issuingCertificateAuthority", ""));
        if (ch == "intune-notifyfail")
            return reply(res, 200, {{"code", "ScepProfileNoLongerTargetedToTheClient"},
                                    {"errorDescription", "refused by the stub"}});
        reply(res, 200, {{"code", "Success"}});
    });
    srv.Post("/svc/scep/ScepActions/failureNotification", [](const httplib::Request& req, httplib::Response& res) {
        if (!bearer_ok(req)) return reply(res, 401, {{"code", "Unknown"}});
        const json n = json::parse(req.body, nullptr, false).value("notification", json::object());
        event("failure txid=" + n.value("transactionId", "") + " hresult=" +
              std::to_string(n.value("hResult", 0L)) + " description=" + n.value("errorDescription", ""));
        reply(res, 200, {{"code", "Success"}});
    });

    // ── Intune: revocation requests ──
    srv.Post("/svc/pki/CertificateAuthorityRequests/downloadRevocationRequests",
             [](const httplib::Request& req, httplib::Response& res) {
        if (!bearer_ok(req) || req.get_header_value("api-version") != "5019-05-05")
            return reply(res, 401, {{"code", "Unknown"}});
        const json p = json::parse(req.body, nullptr, false).value("downloadParameters", json::object());
        json value = json::array();
        const std::string f = g_state + "/revoke";
        std::ifstream in(f);
        std::string line;
        int n = 0;
        while (std::getline(in, line))
            if (!line.empty())
                value.push_back({{"requestContext", "ctx-" + std::to_string(++n)}, {"serialNumber", line},
                                 {"issuerName", p.value("issuerName", "")}, {"caConfiguration", ""}});
        in.close();
        fs::remove(f);
        event("download issuer=" + p.value("issuerName", "") + " count=" + std::to_string(n));
        reply(res, 200, {{"value", value}});
    });
    srv.Post("/svc/pki/CertificateAuthorityRequests/uploadRevocationResults",
             [](const httplib::Request& req, httplib::Response& res) {
        if (!bearer_ok(req)) return reply(res, 401, {{"code", "Unknown"}});
        const json b = json::parse(req.body, nullptr, false);
        for (const auto& r : b.value("results", json::array()))
            event("upload " + r.value("requestContext", "") + " succeeded=" +
                  (r.value("succeeded", false) ? "true" : "false") + " code=" + r.value("errorCode", ""));
        reply(res, 200, {{"value", true}});
    });

    if (!srv.bind_to_port("127.0.0.1", port)) { std::cerr << "intune-stub: cannot bind " << port << "\n"; return 1; }
    std::cout << "READY" << std::endl;
    srv.listen_after_bind();
    return 0;
}
