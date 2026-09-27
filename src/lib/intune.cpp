// Microsoft Intune SCEP validation, revocation and credential rollover. See intune.hpp.
#include "pki/intune.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <chrono>
#include <cctype>
#include <ctime>
#include <map>
#include <mutex>
#include <set>

#include "pki/audit.hpp"
#include "pki/error.hpp"
#include "pki/jws.hpp"
#include "pki/log.hpp"
#include "pki/service_cert.hpp"   // renew_service_certs_for_ca: the credential
#include "pki/x509.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include "../../third_party/nlohmann/json.hpp"

namespace pki::intune {

using json = nlohmann::json;

namespace {

// The versions and names Microsoft's reference library sends. They are part of the wire
// format, not tuning: api-version 5019-05-05 is Microsoft's own value.
constexpr const char* kValidationService = "ScepRequestValidationFEService";
constexpr const char* kValidationVersion = "2018-02-20";
constexpr const char* kRevocationService = "PkiConnectorFEService";
constexpr const char* kRevocationVersion = "5019-05-05";
// The Intune service principal every tenant has; its endpoints are where the Intune
// services live.
constexpr const char* kIntuneAppId = "0000000a-0000-0000-c000-000000000000";
// Audience of the proof-of-possession token Graph addKey/removeKey require.
constexpr const char* kPopAudience = "00000002-0000-0000-c000-000000000000";
constexpr const char* kCaller = "FastPKI";

std::string b64url(const std::string& s) {
    return jws::base64url_encode(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}
std::string b64url(const std::vector<unsigned char>& v) {
    return jws::base64url_encode(v.data(), v.size());
}
std::string b64(const std::vector<unsigned char>& v) {
    std::string out(4 * ((v.size() + 2) / 3) + 1, '\0');
    const int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), v.data(),
                                  static_cast<int>(v.size()));
    out.resize(n > 0 ? static_cast<size_t>(n) : 0);
    return out;
}
std::vector<unsigned char> unb64(const std::string& s) {
    std::string t;
    for (char c : s) if (!std::isspace(static_cast<unsigned char>(c))) t += c;
    std::vector<unsigned char> out(t.size());
    const int n = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(t.data()),
                                  static_cast<int>(t.size()));
    if (n < 0) return {};
    size_t len = static_cast<size_t>(n);
    // EVP_DecodeBlock counts the padding as output bytes.
    for (size_t i = t.size(); i > 0 && t[i - 1] == '=' && len > 0; --i) --len;
    out.resize(len);
    return out;
}
std::vector<unsigned char> digest(const EVP_MD* md, const std::vector<unsigned char>& in) {
    std::vector<unsigned char> out(EVP_MAX_MD_SIZE);
    unsigned int n = 0;
    if (EVP_Digest(in.data(), in.size(), out.data(), &n, md, nullptr) != 1)
        throw Error(2, "intune: digest failed");
    out.resize(n);
    return out;
}
std::string hex(const std::vector<unsigned char>& v) {
    static const char* h = "0123456789abcdef";
    std::string s;
    for (unsigned char c : v) { s += h[c >> 4]; s += h[c & 15]; }
    return s;
}

// Sign `data` with `key`: RSASSA-PSS/SHA-256 for PS256, PKCS#1 v1.5/SHA-256 for RS256.
std::vector<unsigned char> sign(EVP_PKEY* key, const std::string& data, bool pss) {
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (!mctx) throw Error(2, "intune: out of memory");
    EVP_PKEY_CTX* pctx = nullptr;
    bool ok = EVP_DigestSignInit(mctx, &pctx, EVP_sha256(), nullptr, key) == 1;
    if (ok && pss)
        ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
             EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0;
    size_t len = 0;
    if (ok) ok = EVP_DigestSign(mctx, nullptr, &len,
                                reinterpret_cast<const unsigned char*>(data.data()), data.size()) == 1;
    std::vector<unsigned char> sig(len);
    if (ok) ok = EVP_DigestSign(mctx, sig.data(), &len,
                                reinterpret_cast<const unsigned char*>(data.data()), data.size()) == 1;
    EVP_MD_CTX_free(mctx);
    if (!ok) throw Error(2, "intune: signing the token with the credential key failed");
    sig.resize(len);
    return sig;
}

std::string jwt(const json& header, const json& claims, EVP_PKEY* key, bool pss) {
    const std::string in = b64url(header.dump()) + "." + b64url(claims.dump());
    return in + "." + b64url(sign(key, in, pss));
}

// ── HTTP ─────────────────────────────────────────────────────────────────────
struct Resp { int status{0}; std::string body{}; };

void split(const std::string& url, std::string& base, std::string& path) {
    const auto s = url.find("://");
    const auto p = s == std::string::npos ? std::string::npos : url.find('/', s + 3);
    if (p == std::string::npos) { base = url; path = "/"; }
    else { base = url.substr(0, p); path = url.substr(p); }
}
httplib::Client client_for(const std::string& base) {
    httplib::Client cli(base);
    cli.set_connection_timeout(10, 0);
    cli.set_read_timeout(30, 0);
    // Server verification is not a choice; the system trust store holds Microsoft's roots.
    cli.enable_server_certificate_verification(true);
    return cli;
}
Resp post(const std::string& url, const std::string& body, const std::string& ctype,
          const httplib::Headers& h) {
    std::string base, path;
    split(url, base, path);
    auto cli = client_for(base);
    auto r = cli.Post(path, h, body, ctype);
    if (!r) throw Error(2, "intune: POST " + base + " failed: " + httplib::to_string(r.error()));
    return {r->status, r->body};
}
Resp get(const std::string& url, const httplib::Headers& h) {
    std::string base, path;
    split(url, base, path);
    auto cli = client_for(base);
    auto r = cli.Get(path, h);
    if (!r) throw Error(2, "intune: GET " + base + " failed: " + httplib::to_string(r.error()));
    return {r->status, r->body};
}
std::string urlenc(const std::string& s) {
    static const char* h = "0123456789ABCDEF";
    std::string o;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') o += static_cast<char>(c);
        else { o += '%'; o += h[c >> 4]; o += h[c & 15]; }
    }
    return o;
}
std::string trim_slash(std::string s) {
    while (!s.empty() && s.back() == '/') s.pop_back();
    return s;
}
// Microsoft's error text, for the operator: Entra puts it in error_description, Graph in
// error.message, Intune in errorDescription.
std::string ms_error(const Resp& r) {
    const json j = json::parse(r.body, nullptr, false);
    if (j.is_object()) {
        if (j.contains("error_description") && j["error_description"].is_string())
            return j["error_description"].get<std::string>();
        if (j.contains("error") && j["error"].is_object() && j["error"].contains("message"))
            return j["error"]["message"].get<std::string>();
        if (j.contains("errorDescription") && j["errorDescription"].is_string())
            return j["errorDescription"].get<std::string>();
    }
    return "HTTP " + std::to_string(r.status);
}

// ── caches ───────────────────────────────────────────────────────────────────
// Tokens and the discovered Intune service URLs, per connection. A token is keyed by the
// certificate that obtained it too, so a renewed credential never reuses one.
struct Cached { std::string value{}; int64_t expires{0}; };
std::mutex g_mu;
std::map<std::string, Cached> g_tokens;
std::map<std::string, std::map<std::string, std::string>> g_services;

int64_t now_unix() { return static_cast<int64_t>(std::time(nullptr)); }

// The credential: the key in this node's token and the certificates that certify it, the
// active one first and then every unexpired one it replaced. A renewed certificate is not
// registered with Entra until sync_credential() runs, and in between the app still
// authenticates with the previous one — same key, so the same signature works for both.
struct Credential {
    EvpPkeyPtr key;
    std::vector<X509Ptr> certs;
};
Credential load_credential(const Config& cfg, Db& db, const std::string& ca_id) {
    Credential c;
    const std::string id = cert_id_for(ca_id);
    auto der = db.get_cert_by_cert_id(id);
    if (!der || der->empty())
        throw Error(2, "intune: CA '" + ca_id + "' has no Intune credential certificate (" + id + ")");
    try { c.key = load_key_file_or_token(key_uri(cfg), cfg); } catch (const std::exception&) {}
    if (!c.key)
        throw Error(2, "intune: this node's token holds no Intune credential key — replicate "
                       "it with `fastpki-ca key sync`");
    auto cur = parse_cert_der(*der);
    if (!cur || !cert_certifies_key(cur.get(), c.key.get()))
        throw Error(2, "intune: the Intune key in this node's token does not match certificate " + id);
    c.certs.push_back(std::move(cur));
    for (const auto& r : db.retired_certs(id)) {
        auto x = parse_cert_der(r);
        if (!x || x509_not_after_unix(x.get()) <= now_unix()) continue;
        if (!cert_certifies_key(x.get(), c.key.get())) continue;
        c.certs.push_back(std::move(x));
    }
    return c;
}

std::string sha1_hex(X509* x) { return hex(digest(EVP_sha1(), x509_to_der(x))); }

// An Entra token for `scope`, authenticated by a client assertion signed with the credential
// key. Each certificate is tried in turn until Entra accepts one.
std::string token(const Db::IntuneConnectionRow& row, const Credential& cred,
                  const std::string& scope) {
    const std::string cache_key = row.id + "|" + scope;
    {
        std::lock_guard<std::mutex> lk(g_mu);
        auto it = g_tokens.find(cache_key);
        if (it != g_tokens.end() && it->second.expires > now_unix() + 120) return it->second.value;
    }
    const std::string url = trim_slash(row.login_url) + "/" + urlenc(row.tenant_id) +
                            "/oauth2/v2.0/token";
    std::string last;
    for (const auto& cert : cred.certs) {
        const auto der = x509_to_der(cert.get());
        const int64_t t = now_unix();
        const json header = {{"alg", "PS256"}, {"typ", "JWT"},
                             {"x5t#S256", b64url(digest(EVP_sha256(), der))},
                             {"x5t", b64url(digest(EVP_sha1(), der))}};
        const json claims = {{"aud", url}, {"iss", row.app_id}, {"sub", row.app_id},
                             {"jti", new_uuid()}, {"iat", t}, {"nbf", t}, {"exp", t + 600}};
        const std::string body =
            "client_id=" + urlenc(row.app_id) + "&scope=" + urlenc(scope) +
            "&grant_type=client_credentials" +
            "&client_assertion_type=" + urlenc("urn:ietf:params:oauth:client-assertion-type:jwt-bearer") +
            "&client_assertion=" + jwt(header, claims, cred.key.get(), /*pss=*/true);
        const Resp r = post(url, body, "application/x-www-form-urlencoded", {});
        if (r.status == 200) {
            const json j = json::parse(r.body, nullptr, false);
            if (j.is_object() && j.contains("access_token") && j["access_token"].is_string()) {
                const int64_t life = j.contains("expires_in") && j["expires_in"].is_number()
                                         ? j["expires_in"].get<int64_t>() : 3600;
                std::lock_guard<std::mutex> lk(g_mu);
                g_tokens[cache_key] = {j["access_token"].get<std::string>(), now_unix() + life};
                return g_tokens[cache_key].value;
            }
        }
        last = ms_error(r);
    }
    throw Error(2, "intune: Entra refused the app's certificate for tenant '" + row.tenant_id +
                   "': " + last + " — upload the certificate from the console to the app "
                   "registration (Certificates & secrets)");
}

void forget(const std::string& connection_id) {
    std::lock_guard<std::mutex> lk(g_mu);
    g_services.erase(connection_id);
}

// The URL of one Intune service for this tenant, from the Intune service principal's
// endpoints in Graph. Cached until a call to it fails.
std::string service_url(const Db::IntuneConnectionRow& row, const Credential& cred,
                        const std::string& service) {
    std::string lower = service;
    for (auto& ch : lower) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    {
        std::lock_guard<std::mutex> lk(g_mu);
        auto it = g_services.find(row.id);
        if (it != g_services.end()) {
            auto s = it->second.find(lower);
            if (s != it->second.end()) return s->second;
        }
    }
    const std::string graph = trim_slash(row.graph_url);
    const std::string tok = token(row, cred, graph + "/.default");
    const Resp r = get(graph + "/v1.0/servicePrincipals/appId=" + kIntuneAppId + "/endpoints",
                       {{"Authorization", "Bearer " + tok}, {"client-request-id", new_uuid()}});
    if (r.status != 200)
        throw Error(2, "intune: Graph did not list the Intune services: " + ms_error(r) +
                       " — the app needs the Application.Read.All permission");
    const json j = json::parse(r.body, nullptr, false);
    if (!j.is_object() || !j.contains("value") || !j["value"].is_array())
        throw Error(2, "intune: Graph returned no Intune service list");
    std::map<std::string, std::string> m;
    for (const auto& e : j["value"]) {
        const json& n = e.contains("providerName") && e["providerName"].is_string()
                            ? e["providerName"] : (e.contains("serviceName") ? e["serviceName"] : json());
        if (!n.is_string() || !e.contains("uri") || !e["uri"].is_string()) continue;
        std::string k = n.get<std::string>();
        for (auto& ch : k) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        m[k] = trim_slash(e["uri"].get<std::string>());
    }
    std::lock_guard<std::mutex> lk(g_mu);
    g_services[row.id] = m;
    auto s = m.find(lower);
    if (s == m.end())
        throw Error(2, "intune: this tenant lists no " + service + " service — is Intune licensed?");
    return s->second;
}

json intune_post(const Db::IntuneConnectionRow& row, const Credential& cred,
                 const std::string& service, const std::string& version,
                 const std::string& suffix, const json& body) {
    const std::string base = service_url(row, cred, service);
    const std::string tok = token(row, cred, row.intune_resource + "/.default");
    Resp r;
    try {
        r = post(base + "/" + suffix, body.dump(), "application/json",
                 {{"Authorization", "Bearer " + tok}, {"client-request-id", new_uuid()},
                  {"api-version", version}});
    } catch (...) {
        forget(row.id);   // the service may have moved
        throw;
    }
    if (r.status < 200 || r.status > 299) {
        forget(row.id);
        throw Error(2, "intune: " + suffix + " failed: " + ms_error(r));
    }
    json j = json::parse(r.body, nullptr, false);
    if (j.is_discarded()) throw Error(2, "intune: " + suffix + " returned something that is not JSON");
    return j;
}

Verdict verdict_of(const json& j) {
    Verdict v;
    if (j.is_object() && j.contains("code") && j["code"].is_string()) v.code = j["code"].get<std::string>();
    if (j.is_object() && j.contains("errorDescription") && j["errorDescription"].is_string())
        v.description = j["errorDescription"].get<std::string>();
    v.ok = v.code == "Success";
    return v;
}

// A JSON member by name, ignoring case: the revocation API's responses are deserialised by
// a case-insensitive reader in Microsoft's library, so both spellings occur.
std::string member(const json& o, const std::string& name) {
    for (auto it = o.begin(); it != o.end(); ++it) {
        std::string k = it.key();
        if (k.size() != name.size()) continue;
        bool eq = true;
        for (size_t i = 0; i < k.size() && eq; ++i)
            eq = std::tolower(static_cast<unsigned char>(k[i])) ==
                 std::tolower(static_cast<unsigned char>(name[i]));
        if (eq && it.value().is_string()) return it.value().get<std::string>();
    }
    return {};
}

std::string iso_utc(int64_t t) {
    const std::time_t tt = static_cast<std::time_t>(t);
    std::tm tm{};
    gmtime_r(&tt, &tm);
    char buf[40];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%S.000Z", &tm);
    return buf;
}

// The Graph application object: its object id (the proof token's issuer) and the SHA-1
// thumbprint and keyId of each certificate it holds.
struct AppKeys {
    std::string object_id{};
    std::map<std::string, std::string> key_by_thumb;   // sha1 hex -> keyId
};
AppKeys app_keys(const Db::IntuneConnectionRow& row, const std::string& graph_token) {
    const std::string graph = trim_slash(row.graph_url);
    const Resp r = get(graph + "/v1.0/applications(appId='" + urlenc(row.app_id) +
                           "')?%24select=id,keyCredentials",
                       {{"Authorization", "Bearer " + graph_token}});
    if (r.status != 200)
        throw Error(2, "intune: Graph did not return the app registration: " + ms_error(r) +
                       " — the app needs the Application.Read.All permission");
    const json j = json::parse(r.body, nullptr, false);
    AppKeys a;
    if (!j.is_object() || !j.contains("id") || !j["id"].is_string())
        throw Error(2, "intune: Graph returned an app registration without an id");
    a.object_id = j["id"].get<std::string>();
    if (j.contains("keyCredentials") && j["keyCredentials"].is_array())
        for (const auto& k : j["keyCredentials"]) {
            const std::string kid = member(k, "keyId"), cki = member(k, "customKeyIdentifier");
            if (kid.empty() || cki.empty()) continue;
            // Graph returns the thumbprint base64-encoded; a certificate uploaded in the
            // portal carries it as the 20 raw bytes, one added through the API may carry the
            // 40 hex characters instead.
            const auto raw = unb64(cki);
            std::string th;
            if (raw.size() == 20) th = hex(raw);
            else if (raw.size() == 40) th.assign(raw.begin(), raw.end());
            for (auto& ch : th) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            if (th.size() == 40) a.key_by_thumb[th] = kid;
        }
    return a;
}

std::string pop_token(const std::string& object_id, EVP_PKEY* key, X509* registered) {
    const auto der = x509_to_der(registered);
    std::string kid = hex(digest(EVP_sha1(), der));
    for (auto& ch : kid) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    const int64_t t = now_unix();
    const json header = {{"alg", "RS256"}, {"typ", "JWT"}, {"kid", kid},
                         {"x5t", b64url(digest(EVP_sha1(), der))}};
    const json claims = {{"aud", kPopAudience}, {"iss", object_id},
                         {"iat", t}, {"nbf", t}, {"exp", t + 600}};
    return jwt(header, claims, key, /*pss=*/false);
}

}  // namespace

std::string new_uuid() {
    unsigned char b[16];
    if (RAND_bytes(b, sizeof b) != 1) throw Error(2, "intune: no randomness for a request id");
    b[6] = static_cast<unsigned char>((b[6] & 0x0f) | 0x40);
    b[8] = static_cast<unsigned char>((b[8] & 0x3f) | 0x80);
    const std::string h = hex(std::vector<unsigned char>(b, b + 16));
    return h.substr(0, 8) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4) + "-" +
           h.substr(16, 4) + "-" + h.substr(20);
}

std::string connection_id_refusal(const std::string& id) {
    if (id.empty() || id.size() > 40) return "a connection id is 1 to 40 characters";
    for (char c : id)
        if (!(std::islower(static_cast<unsigned char>(c)) || std::isdigit(static_cast<unsigned char>(c)) || c == '-'))
            return "a connection id uses only lowercase letters, digits and '-'";
    return {};
}

namespace {
bool is_guid(const std::string& s) {
    if (s.size() != 36) return false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (s[i] != '-') return false; }
        else if (!std::isxdigit(static_cast<unsigned char>(s[i]))) return false;
    }
    return true;
}
bool is_domain(const std::string& s) {
    if (s.empty() || s.size() > 253 || s.find('.') == std::string::npos) return false;
    for (char c : s)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '.')) return false;
    return true;
}
}  // namespace

std::string connection_refusal(const Db::IntuneConnectionRow& c) {
    if (auto why = connection_id_refusal(c.id); !why.empty()) return why;
    if (!is_guid(c.tenant_id) && !is_domain(c.tenant_id))
        return "the tenant is the Directory (tenant) ID from Entra, a GUID, or the tenant's domain name";
    if (!is_guid(c.app_id)) return "the app is the Application (client) ID from Entra, a GUID";
    if (c.ca_instance_id.empty()) return "name the CA that issues the devices' certificates";
    for (const std::string* u : {&c.login_url, &c.graph_url, &c.intune_resource})
        if (u->rfind("https://", 0) != 0 || u->size() <= 8) return "'" + *u + "' is not an https URL";
    return {};
}

std::vector<std::string> save_connection(const Config& cfg, Db& db,
                                         const Db::IntuneConnectionRow& c,
                                         const std::string& role) {
    if (auto why = connection_refusal(c); !why.empty()) throw Error(1, why);
    const auto ca = db.get_ca_instance(c.ca_instance_id);
    if (!ca) throw Error(1, "there is no CA '" + c.ca_instance_id + "'");
    if (ca->signing_ca_key.empty())
        throw Error(1, "CA '" + c.ca_instance_id + "' is a trust anchor here: this deployment holds no key to issue from it");
    if (auto x = load_ca_cert_pem(ca->signing_ca_pem); x && x509_is_self_signed(x.get()))
        throw Error(1, "CA '" + c.ca_instance_id + "' is a root, and a root signs only sub CAs");
    if (!role.empty()) {
        bool known = false;
        for (const auto& r : db.list_roles()) if (r.name == role) { known = true; break; }
        if (!known) throw Error(1, "there is no role '" + role + "'");
    }
    std::vector<std::string> notes;
    db.upsert_intune_connection(c);
    if (!role.empty()) {
        Db::SubjectRole sr;
        sr.selector_type = "user";
        sr.selector_value = subject_for(c.id);
        sr.role = role;
        sr.created = now_unix();
        db.add_subject_role(sr);
        notes.push_back("granted role '" + role + "' to " + sr.selector_value);
    }
    const auto r = renew_service_certs_for_ca(cfg, db, c.ca_instance_id, /*force=*/false,
                                              /*dry_run=*/false, /*create_missing=*/true,
                                              cfg.service_keys_replicable, "intune");
    notes.insert(notes.end(), r.notes.begin(), r.notes.end());
    for (const auto& e : r.errors) notes.push_back("ERROR: " + e);
    return notes;
}

bool remove_connection(Db& db, const std::string& id) {
    if (!db.delete_intune_connection(id)) return false;
    const std::string subject = subject_for(id);
    for (const auto& r : db.list_subject_roles())
        if (r.selector_type == "user" && r.selector_value == subject)
            db.delete_subject_role(r.selector_type, r.selector_value, r.role);
    return true;
}

std::string credential_pem(Db& db, const std::string& ca_id) {
    auto der = db.get_cert_by_cert_id(cert_id_for(ca_id));
    if (!der || der->empty()) return {};
    auto x = parse_cert_der(*der);
    return x ? x509_to_pem_string(x.get()) : std::string();
}

std::string issuer_name(Db& db, const std::string& ca_id) {
    const auto ca = db.get_ca_instance(ca_id);
    if (!ca || ca->signing_ca_pem.empty()) return ca_id;
    auto x = load_ca_cert_pem(ca->signing_ca_pem);
    const std::string cn = x ? x509_cn(x.get()) : std::string();
    return cn.empty() ? ca_id : cn;
}

PollResult poll_revocations(const Config& cfg, Db& db, const Db::IntuneConnectionRow& conn) {
    PollResult out;
    Client ic(cfg, db, conn);
    const std::string txid = new_uuid();
    const auto reqs = ic.download_revocations(txid, 100, issuer_name(db, conn.ca_instance_id));
    out.requested = static_cast<int>(reqs.size());
    if (reqs.empty()) return out;
    const std::string subject = subject_for(conn.id);
    std::vector<RevocationResult> results;
    for (const auto& r : reqs) {
        RevocationResult res;
        res.request_context = r.request_context;
        const std::string serial = canonical_serial(r.serial);
        std::optional<CertRow> row;
        try { row = db.get_cert(serial); } catch (const std::exception&) { row.reset(); }
        if (!row) {
            res.error_code = "CertificateNotFoundError";
            res.error_message = "no certificate with serial " + serial;
        } else if (row->ca_instance_id != conn.ca_instance_id || row->owner != subject) {
            res.error_code = "NotSupportedError";
            res.error_message = "serial " + serial + " was not issued through this Intune connection";
        } else {
            try {
                if (row->status != -1)
                    db.revoke_cert(serial, 5 /* cessationOfOperation */, now_unix());
                res.succeeded = true;
                res.error_code = "None";
                log::info("intune '" + conn.id + "': revoked serial=" + serial + " at Intune's request");
                AuditEvent ev;
                ev.category = audit_cat::kLifecycle; ev.action = "cert_revoked";
                ev.actor = subject; ev.target = serial; ev.status = audit_status::kSuccess;
                ev.detail = "protocol=SCEP intune=" + conn.id + " reason=cessationOfOperation";
                try { db.append_audit(ev); } catch (...) {}
            } catch (const std::exception& e) {
                res.error_code = "RetryableServiceException";
                res.error_message = e.what();
            }
        }
        if (res.succeeded) ++out.revoked; else ++out.refused;
        results.push_back(std::move(res));
    }
    ic.upload_revocation_results(txid, results);
    return out;
}

Client::Client(const Config& cfg, Db& db, Db::IntuneConnectionRow row)
    : cfg_(cfg), db_(db), row_(std::move(row)) {}

Verdict Client::validate(const std::string& txid, const std::string& csr_b64) {
    const auto cred = load_credential(cfg_, db_, row_.ca_instance_id);
    const json body = {{"request", {{"transactionId", txid}, {"certificateRequest", csr_b64},
                                    {"callerInfo", kCaller}}}};
    return verdict_of(intune_post(row_, cred, kValidationService, kValidationVersion,
                                  "ScepActions/validateRequest", body));
}

Verdict Client::notify_success(const std::string& txid, const std::string& csr_b64, X509* cert,
                               const std::string& issuing_ca) {
    const auto cred = load_credential(cfg_, db_, row_.ca_instance_id);
    std::string thumb = sha1_hex(cert);
    for (auto& ch : thumb) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    const json body = {{"notification", {
        {"transactionId", txid}, {"certificateRequest", csr_b64},
        {"certificateThumbprint", thumb},
        {"certificateSerialNumber", x509_serial_hex(cert)},
        {"certificateExpirationDateUtc", iso_utc(x509_not_after_unix(cert))},
        {"issuingCertificateAuthority", issuing_ca},
        {"callerInfo", kCaller},
        {"caConfiguration", row_.ca_instance_id},
        {"certificateAuthority", issuing_ca}}}};
    return verdict_of(intune_post(row_, cred, kValidationService, kValidationVersion,
                                  "ScepActions/successNotification", body));
}

Verdict Client::notify_failure(const std::string& txid, const std::string& csr_b64,
                               long hresult, const std::string& description) {
    const auto cred = load_credential(cfg_, db_, row_.ca_instance_id);
    const json body = {{"notification", {
        {"transactionId", txid}, {"certificateRequest", csr_b64},
        {"hResult", hresult}, {"errorDescription", description.empty() ? "refused" : description},
        {"callerInfo", kCaller}}}};
    return verdict_of(intune_post(row_, cred, kValidationService, kValidationVersion,
                                  "ScepActions/failureNotification", body));
}

std::vector<RevocationRequest> Client::download_revocations(const std::string& txid, int max,
                                                            const std::string& issuer_name) {
    const auto cred = load_credential(cfg_, db_, row_.ca_instance_id);
    json params = {{"maxRequests", max < 1 ? 1 : (max > 500 ? 500 : max)}};
    if (!issuer_name.empty()) params["issuerName"] = issuer_name;
    (void)txid;   // correlates the download and the upload in Microsoft's logs only
    const json j = intune_post(row_, cred, kRevocationService, kRevocationVersion,
                               "CertificateAuthorityRequests/downloadRevocationRequests",
                               {{"downloadParameters", params}});
    std::vector<RevocationRequest> out;
    if (!j.is_object() || !j.contains("value") || !j["value"].is_array())
        throw Error(2, "intune: the revocation download carried no list");
    for (const auto& e : j["value"]) {
        if (!e.is_object()) continue;
        RevocationRequest r;
        r.request_context  = member(e, "requestContext");
        r.serial           = member(e, "serialNumber");
        r.issuer_name      = member(e, "issuerName");
        r.ca_configuration = member(e, "caConfiguration");
        if (!r.request_context.empty()) out.push_back(std::move(r));
    }
    return out;
}

void Client::upload_revocation_results(const std::string& txid,
                                       const std::vector<RevocationResult>& results) {
    if (results.empty()) return;
    (void)txid;
    const auto cred = load_credential(cfg_, db_, row_.ca_instance_id);
    json arr = json::array();
    for (const auto& r : results) {
        json o = {{"requestContext", r.request_context}, {"succeeded", r.succeeded}};
        if (!r.succeeded) {
            o["errorCode"] = r.error_code;
            o["errorMessage"] = r.error_message;
        }
        arr.push_back(std::move(o));
    }
    const json j = intune_post(row_, cred, kRevocationService, kRevocationVersion,
                               "CertificateAuthorityRequests/uploadRevocationResults",
                               {{"results", arr}});
    const bool accepted = j.is_object() && j.contains("value") &&
        ((j["value"].is_boolean() && j["value"].get<bool>()) ||
         (j["value"].is_string() && j["value"].get<std::string>() == "true"));
    if (!accepted) throw Error(2, "intune: Intune did not record the revocation results");
}

CredentialStatus Client::sync_credential(bool apply) {
    const auto cred = load_credential(cfg_, db_, row_.ca_instance_id);
    const std::string graph = trim_slash(row_.graph_url);
    const std::string tok = token(row_, cred, graph + "/.default");
    const AppKeys app = app_keys(row_, tok);
    CredentialStatus st;

    X509* current = cred.certs.front().get();
    const std::string cur = sha1_hex(current);
    // A certificate of ours the app still accepts, to sign the proof token with.
    X509* registered = nullptr;
    for (const auto& c : cred.certs)
        if (app.key_by_thumb.count(sha1_hex(c.get()))) { registered = c.get(); break; }

    if (app.key_by_thumb.count(cur)) {
        st.registered = true;
        std::set<std::string> retired;
        for (const auto& d : db_.retired_certs(cert_id_for(row_.ca_instance_id))) {
            auto x = parse_cert_der(d);
            if (x) retired.insert(sha1_hex(x.get()));
        }
        int removed = 0;
        for (const auto& [thumb, key_id] : app.key_by_thumb) {
            if (!retired.count(thumb)) continue;
            if (!apply) { st.note = "a replaced FastPKI certificate is still registered"; continue; }
            const json body = {{"keyId", key_id},
                               {"proof", pop_token(app.object_id, cred.key.get(), current)}};
            const Resp r = post(graph + "/v1.0/applications/" + urlenc(app.object_id) + "/removeKey",
                                body.dump(), "application/json",
                                {{"Authorization", "Bearer " + tok}});
            if (r.status < 200 || r.status > 299)
                throw Error(2, "intune: removing a replaced certificate from the app failed: " + ms_error(r));
            ++removed;
        }
        if (removed) st.note = "removed " + std::to_string(removed) + " replaced certificate(s) from the app";
        else if (st.note.empty()) st.note = "the current certificate is registered";
        return st;
    }
    if (!registered) {
        // Only reachable when Entra accepted a token from a certificate the app does not
        // list, which happens while a portal upload propagates. Nothing to sign a proof with.
        st.note = "the app does not list FastPKI's current certificate — upload it from the console";
        return st;
    }
    if (!apply) {
        st.note = "the renewed certificate is not registered with the app yet";
        return st;
    }
    const json body = {{"keyCredential", {{"type", "AsymmetricX509Cert"}, {"usage", "Verify"},
                                          {"key", b64(x509_to_der(current))}}},
                       {"passwordCredential", nullptr},
                       {"proof", pop_token(app.object_id, cred.key.get(), registered)}};
    const Resp r = post(graph + "/v1.0/applications/" + urlenc(app.object_id) + "/addKey",
                        body.dump(), "application/json", {{"Authorization", "Bearer " + tok}});
    if (r.status < 200 || r.status > 299)
        throw Error(2, "intune: registering the renewed certificate with the app failed: " + ms_error(r));
    st.registered = true;
    st.note = "registered the renewed certificate with the app";
    return st;
}

}  // namespace pki::intune
