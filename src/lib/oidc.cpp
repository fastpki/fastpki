// OpenID Connect (Authorization Code + PKCE) client.
#include "pki/oidc.hpp"
#include "pki/auth.hpp"   // qualify_subject
#include "pki/config.hpp"
#include "pki/error.hpp"
#include "pki/jws.hpp"
#include "pki/log.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

#include <chrono>
#include <mutex>

namespace pki {

using json = nlohmann::json;

namespace {

// Split a full URL into the scheme://host[:port] base (for httplib::Client) and
// the path+query that follows.
std::pair<std::string, std::string> split_url(const std::string& url) {
    auto scheme_end = url.find("://");
    if (scheme_end == std::string::npos) return {url, "/"};
    auto path_start = url.find('/', scheme_end + 3);
    if (path_start == std::string::npos) return {url, "/"};
    return {url.substr(0, path_start), url.substr(path_start)};
}

std::string urlencode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') out += static_cast<char>(c);
        else { out += '%'; out += hex[c >> 4]; out += hex[c & 0xf]; }
    }
    return out;
}

// One of: a string, or the first element if it's an array.
bool json_contains_aud(const json& aud, const std::string& want) {
    if (aud.is_string()) return aud.get<std::string>() == want;
    if (aud.is_array()) for (const auto& a : aud) if (a.is_string() && a.get<std::string>() == want) return true;
    return false;
}

} // namespace

struct OidcClient::Impl {
    // ⚠️ THE PROVIDER ID IS KEPT SO GROUPS CAN BE QUALIFIED. An IdP asserts bare group
    // names, and two IdPs can both assert "Admins" — so a role granted to one silently
    // authorized the other the moment a second provider was configured. Subjects have
    // been `provider\user` for a while; their groups had not caught up.
    std::string provider_id;
    std::string issuer, client_id, client_secret, redirect_uri, scopes;
    std::string username_claim, groups_claim, ca_cert;
    std::mutex mu;
    // Cached discovery + JWKS (fetched lazily).
    std::string authz_ep, token_ep, jwks_uri;
    json jwks;

    // ⚠️ AN EMPTY COLUMN MEANS "NOT SET", NOT "EMPTY STRING". Three of these carry a
    // default that the flat-config path applied for years — an id_token is requested with
    // `openid email profile` and the username comes from `email` unless someone says
    // otherwise. Copying the blank straight through asks the IdP for no scopes and then
    // looks for a claim called "", which authenticates nobody while every setting on the
    // screen still looks right.
    static std::string or_default(const std::string& v, const char* d) { return v.empty() ? d : v; }
    explicit Impl(const Db::OidcProviderRow& r)
        : provider_id(r.id), issuer(r.issuer), client_id(r.client_id), client_secret(r.client_secret),
          redirect_uri(r.redirect_uri),
          scopes(or_default(r.scopes, "openid email profile")),
          username_claim(or_default(r.username_claim, "email")),
          groups_claim(or_default(r.groups_claim, "groups")), ca_cert(r.ca_cert) {}
    httplib::Client client(const std::string& base) {
        httplib::Client cli(base);
        cli.set_connection_timeout(5, 0);
        cli.set_read_timeout(15, 0);
        if (!ca_cert.empty()) cli.set_ca_cert_path(ca_cert);
        // Settings that weaken the product's security — OIDC_TLS_SKIP_VERIFY among
        // them — are removed. Verification is no longer a
        // choice. A private issuer CA is served by the provider's ca_cert above, which is the
        // supported way to trust one -- not by trusting everything.
        cli.enable_server_certificate_verification(true);
        return cli;
    }

    json http_get_json(const std::string& url) {
        auto [base, path] = split_url(url);
        auto cli = client(base);
        auto res = cli.Get(path.c_str());
        if (!res) throw Error(2, "oidc: GET " + url + " transport error: " + httplib::to_string(res.error()));
        if (res->status != 200) throw Error(2, "oidc: GET " + url + " HTTP " + std::to_string(res->status));
        return json::parse(res->body);
    }

    void ensure_discovery() {
        if (!authz_ep.empty()) return;
        std::string base = issuer;
        while (!base.empty() && base.back() == '/') base.pop_back();
        json d = http_get_json(base + "/.well-known/openid-configuration");
        authz_ep = d.at("authorization_endpoint").get<std::string>();
        token_ep = d.at("token_endpoint").get<std::string>();
        jwks_uri = d.at("jwks_uri").get<std::string>();
        log::info("oidc: discovered IdP endpoints for " + issuer);
    }

    const json& find_jwk(const std::string& kid) {
        if (jwks.is_null()) jwks = http_get_json(jwks_uri);
        for (const auto& k : jwks.at("keys")) {
            if (kid.empty() || (k.contains("kid") && k.at("kid").get<std::string>() == kid))
                return k;
        }
        // kid not found — refresh once (key rotation) then retry.
        jwks = http_get_json(jwks_uri);
        for (const auto& k : jwks.at("keys"))
            if (kid.empty() || (k.contains("kid") && k.at("kid").get<std::string>() == kid))
                return k;
        throw Error(1, "oidc: no JWKS key for kid '" + kid + "'");
    }

    // Verify a compact ID token (header.payload.signature) and return its payload.
    json verify_id_token(const std::string& jwt, const std::string& expected_nonce) {
        auto d1 = jwt.find('.');
        auto d2 = jwt.find('.', d1 + 1);
        if (d1 == std::string::npos || d2 == std::string::npos)
            throw Error(1, "oidc: malformed id_token");
        const std::string h_b64 = jwt.substr(0, d1);
        const std::string p_b64 = jwt.substr(d1 + 1, d2 - d1 - 1);
        const std::string s_b64 = jwt.substr(d2 + 1);

        auto hb = jws::base64url_decode(h_b64);
        json header = json::parse(std::string(hb.begin(), hb.end()));
        const std::string alg = header.value("alg", "");
        const std::string kid = header.value("kid", "");

        jws::ParsedJws pj;
        pj.protected_b64 = h_b64;
        pj.payload_b64   = p_b64;
        pj.signature_bytes = jws::base64url_decode(s_b64);
        pj.alg = alg;
        jws::verify(pj, find_jwk(kid));   // throws on bad signature

        auto pb = jws::base64url_decode(p_b64);
        json claims = json::parse(std::string(pb.begin(), pb.end()));

        // Standard ID-token validation (RFC/OIDC §3.1.3.7).
        std::string iss = claims.value("iss", "");
        std::string norm_issuer = issuer;
        while (!norm_issuer.empty() && norm_issuer.back() == '/') norm_issuer.pop_back();
        std::string norm_iss = iss;
        while (!norm_iss.empty() && norm_iss.back() == '/') norm_iss.pop_back();
        if (norm_iss != norm_issuer) throw Error(1, "oidc: issuer mismatch");
        if (!claims.contains("aud") || !json_contains_aud(claims.at("aud"), client_id))
            throw Error(1, "oidc: audience mismatch");
        const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (!claims.contains("exp") || claims.at("exp").get<int64_t>() < now)
            throw Error(1, "oidc: id_token expired");
        if (!expected_nonce.empty() && claims.value("nonce", "") != expected_nonce)
            throw Error(1, "oidc: nonce mismatch");
        return claims;
    }
};

OidcClient::OidcClient(const Db::OidcProviderRow& row) : p_(std::make_unique<Impl>(row)) {}
OidcClient::~OidcClient() = default;

bool OidcClient::enabled() const {
    return !p_->issuer.empty() && !p_->client_id.empty() && !p_->redirect_uri.empty();
}

std::string OidcClient::auth_url(const std::string& state, const std::string& nonce,
                                 const std::string& code_challenge) {
    std::lock_guard<std::mutex> lk(p_->mu);
    p_->ensure_discovery();
    return p_->authz_ep + "?response_type=code"
           "&client_id=" + urlencode(p_->client_id) +
           "&redirect_uri=" + urlencode(p_->redirect_uri) +
           "&scope=" + urlencode(p_->scopes) +
           "&state=" + urlencode(state) +
           "&nonce=" + urlencode(nonce) +
           "&code_challenge=" + urlencode(code_challenge) +
           "&code_challenge_method=S256";
}

OidcClaims OidcClient::exchange(const std::string& code, const std::string& code_verifier,
                                const std::string& expected_nonce) {
    std::lock_guard<std::mutex> lk(p_->mu);
    p_->ensure_discovery();

    // Token request (client_secret_post + PKCE verifier).
    std::string body = "grant_type=authorization_code"
        "&code=" + urlencode(code) +
        "&redirect_uri=" + urlencode(p_->redirect_uri) +
        "&client_id=" + urlencode(p_->client_id) +
        "&code_verifier=" + urlencode(code_verifier);
    if (!p_->client_secret.empty()) body += "&client_secret=" + urlencode(p_->client_secret);

    auto [base, path] = split_url(p_->token_ep);
    auto cli = p_->client(base);
    auto res = cli.Post(path.c_str(), body, "application/x-www-form-urlencoded");
    if (!res) throw Error(2, "oidc: token request transport error: " + httplib::to_string(res.error()));
    if (res->status != 200)
        throw Error(1, "oidc: token endpoint HTTP " + std::to_string(res->status) + ": " + res->body);
    json tok = json::parse(res->body);
    if (!tok.contains("id_token")) throw Error(1, "oidc: token response has no id_token");

    json claims = p_->verify_id_token(tok.at("id_token").get<std::string>(), expected_nonce);

    OidcClaims out;
    out.raw = claims;
    out.subject = claims.value("sub", "");
    if (claims.contains(p_->username_claim) && claims.at(p_->username_claim).is_string())
        out.username = claims.at(p_->username_claim).get<std::string>();
    if (out.username.empty()) out.username = out.subject;   // fall back to sub
    // OIDC Core 5.1's `email`. An address the provider itself calls unverified is not taken:
    // it would send certificate notices to a mailbox nobody proved they read. Some
    // providers send the flag as a string.
    if (claims.contains("email") && claims.at("email").is_string()) {
        bool unverified = false;
        if (claims.contains("email_verified")) {
            const auto& v = claims.at("email_verified");
            unverified = (v.is_boolean() && !v.get<bool>()) || (v.is_string() && v.get<std::string>() == "false");
        }
        if (!unverified) out.email = claims.at("email").get<std::string>();
    }
    if (claims.contains(p_->groups_claim) && claims.at(p_->groups_claim).is_array())
        for (const auto& g : claims.at(p_->groups_claim))
            if (g.is_string())
                // Qualified at the SOURCE, so every downstream consumer — the console gate,
                // enrol_gate, subject_roles — compares the same shape and cannot cross
                // providers by accident. qualify_subject() returns the name unchanged when
                // the provider id is empty, which is exactly "this is a local name".
                out.groups.push_back(qualify_subject(p_->provider_id, g.get<std::string>()));
    return out;
}

} // namespace pki
