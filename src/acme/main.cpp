// fastpki-acme — RFC 8555 ACME server.
//
// Implemented:
//   GET  /directory, GET/HEAD /new-nonce
//   POST /new-account (with External Account Binding), /new-order,
//        /order/<id>, /order/<id>/finalize, /authz/<id>,
//        /chall/<id> (async http-01, dns-01 and tls-alpn-01 verifiers),
//        /cert/<serial>, /account/<id> (deactivation),
//        /key-change (RFC 8555 §7.3.5), /revoke-cert (§7.6)

#include "pki/acme_db.hpp"
#include "pki/version.hpp"
#include "pki/ca_instance.hpp"
#include "pki/auth.hpp"        // directory_groups_for()
#include "pki/enrol_gate.hpp"
#include "pki/cert_profile.hpp"
#include "pki/client_addr.hpp"
#include "pki/device_attest.hpp"
#include "pki/enrol_codes.hpp"
#include "pki/config.hpp"
#include "pki/license.hpp"
#include "pki/db.hpp"
#include "pki/endpoint_gate.hpp"
#include "pki/enrol_creds.hpp"
#include "pki/error.hpp"
#include "pki/jws.hpp"
#include "pki/listen.hpp"
#include "pki/log.hpp"
#include "pki/policy.hpp"
#include "pki/x509.hpp"
#include "pki/transport_reload.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT   // ACME terminates its own TLS (HTTPS-only)
#include "../../third_party/httplib.h"
#include "../../third_party/nlohmann/json.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <set>
#include <string>
#include <thread>

// POSIX sockets for the DNS-01 TXT resolver + TLS-ALPN-01 client (glibc + musl).
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

using json = nlohmann::json;

namespace {

// ⚠️ THE ADDRESS ON THE SOCKET IS THE PROXY'S WHEN THERE IS ONE IN FRONT. Read it through
// pki::real_client_ip() everywhere, so the audit log attributes the right client and the
// per-address half of the login backoff stays per-client. With TRUSTED_PROXIES unset — the
// default — this returns the socket address unchanged and nothing behaves differently.
//
// Held here rather than read from the config on each call because every listener loads its
// configuration once at startup; the key is pending-restart and says so in the reference.
std::vector<std::string> g_trusted_proxies;
std::string client_ip(const httplib::Request& req) {
    return pki::real_client_ip(g_trusted_proxies, req.remote_addr,
                               req.get_header_value("X-Forwarded-For"));
}

// The EAB kid IS the subject. It used to be `<user>:eab`, so both call sites had to
// strip the suffix, and they once disagreed about it — newOrder gated on
// `demo` while finalize asked resolve_profile for the roles of a subject called `demo:eab`,
// which is nobody. There is no suffix to strip now: `keys.protocol` distinguishes a user's
// three secrets, so the kid a client sends is the username, and `post->account->kid` can go
// straight to may_enrol/resolve_profile/owner_username with no derivation between them.
// The safest fix for "two spellings of one thing" is for there to be only one spelling.

// ⚠️ RAND_bytes CAN FAIL, and its return was ignored at every site here. On failure the
// buffer is left UNINITIALISED and gets base64'd and handed out as if it were random — a
// replay nonce or a challenge token an attacker may be able to predict, with nothing
// anywhere saying the RNG stopped working. Throwing is the only safe answer: there is no
// weaker value to fall back to, and continuing means issuing on a guessable token.
void must_random(unsigned char* buf, size_t n) {
    if (RAND_bytes(buf, static_cast<int>(n)) != 1)
        throw std::runtime_error("RAND_bytes failed — refusing to use unseeded randomness");
}

std::string random_nonce() {
    unsigned char buf[16];
    must_random(buf, sizeof buf);
    return pki::jws::base64url_encode(buf, sizeof buf);
}

std::string random_id_decimal() {
    unsigned char buf[8];
    must_random(buf, sizeof buf);
    uint64_t n = 0;
    for (int i = 0; i < 8; ++i) n = (n << 8) | buf[i];
    return std::to_string(n & 0x7fffffffffffffffULL);
}

int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// RFC 3339 / ISO-8601 UTC timestamp — ACME timestamp fields (order.expires,
// challenge.validated, authz.expires) are strings, not unix integers.
std::string rfc3339(int64_t t) {
    char buf[32]; std::tm tm{};
    time_t tt = static_cast<time_t>(t);
    gmtime_r(&tt, &tm);
    std::strftime(buf, sizeof buf, "%FT%TZ", &tm);
    return buf;
}

void set_nonce_header(pki::AcmeDb& adb, const httplib::Request& req, httplib::Response& res,
                      int ttl_sec) {
    std::string n = random_nonce();
    adb.save_nonce(n, client_ip(req), now_unix() + ttl_sec);
    res.set_header("Replay-Nonce", n);
    res.set_header("Cache-Control", "no-store");
}

// RFC 8555 §6.5: every response to a POST (success OR error) must carry a
// fresh Replay-Nonce, else the client can't retry. send_problem always issues
// one so no error path can forget it.
void send_problem(pki::AcmeDb& adb, const httplib::Request& req, httplib::Response& res,
                  int http, const std::string& type, const std::string& detail,
                  int ttl = 300) {
    set_nonce_header(adb, req, res, ttl);
    // Every refusal is logged. Without this the client alone saw why: a Mac's ACME
    // profile failed with "bad request" and the server log had nothing, at any level.
    // `detail` is our own text and the path carries no secret.
    pki::log::info("ACME " + req.method + " " + req.path + " refused " +
                   std::to_string(http) + " " + type + ": " + detail);
    json j = {
        {"type",   "urn:ietf:params:acme:error:" + type},
        {"detail", detail},
    };
    res.status = http;
    res.set_content(j.dump(), "application/problem+json");
}

// Parse + validate a JWS-protected request body. On any failure, writes a
// problem document into `res` and returns std::nullopt.
//
// On success returns the ParsedJws and (if the protected header carried `jwk`)
// the verified SPKI bytes — for `kid` requests, the caller must look up the
// account and verify against its stored JWK separately.
struct AcmePost {
    pki::jws::ParsedJws    parsed;
    std::vector<unsigned char> verified_spki;  // empty for kid requests
    std::optional<pki::AcmeAccount> account;   // populated for kid requests
};

std::optional<AcmePost> parse_acme_post(const pki::Config& cfg, pki::AcmeDb& adb,
                                        const httplib::Request& req,
                                        httplib::Response& res,
                                        const std::string& expected_url,
                                        pki::Db* audit_db = nullptr) {
    const int ttl = cfg.nonce_expires_sec;
    if (req.get_header_value("Content-Type") != "application/jose+json") {
        send_problem(adb, req, res, 415, "malformed", "expected application/jose+json", ttl);
        return std::nullopt;
    }
    pki::jws::ParsedJws parsed;
    try { parsed = pki::jws::parse(req.body); }
    catch (const pki::Error& e) {
        send_problem(adb, req, res, 400, "malformed", e.what(), ttl);
        return std::nullopt;
    }
    if (parsed.url != expected_url) {
        send_problem(adb, req, res, 400, "unauthorized", "url mismatch", ttl);
        return std::nullopt;
    }
    if (!adb.consume_nonce(parsed.nonce)) {
        send_problem(adb, req, res, 400, "badNonce", "stale or unknown nonce", ttl);
        return std::nullopt;
    }

    AcmePost out;
    out.parsed = std::move(parsed);

    try {
        if (out.parsed.jwk) {
            out.verified_spki = pki::jws::verify(out.parsed, *out.parsed.jwk);
        } else {
            // kid-form: kid is the account URL; the trailing segment is the id.
            // parse() guarantees exactly one of jwk/kid, so kid is set here — but
            // guard defensively rather than dereference the optional unconditionally.
            if (!out.parsed.kid) { send_problem(adb, req, res, 400, "malformed", "JWS missing kid", ttl); return std::nullopt; }
            std::string kid = *out.parsed.kid;
            auto slash = kid.find_last_of('/');
            std::string id = (slash == std::string::npos) ? kid : kid.substr(slash + 1);
            auto acc = adb.get_account_by_id(id);
            if (!acc) { send_problem(adb, req, res, 400, "accountDoesNotExist", "no such account", ttl); return std::nullopt; }
            json jwk = json::parse(acc->jwk_json);
            out.verified_spki = pki::jws::verify(out.parsed, jwk);
            out.account = std::move(acc);
        }
    } catch (const pki::Error& e) {
        // Audit: JWS signature verification failure is an auth event.
        if (audit_db) {
            try {
                pki::AuditEvent ev;
                ev.category = pki::audit_cat::kAuth;
                ev.action   = "auth_fail";
                ev.actor    = out.parsed.kid ? *out.parsed.kid : std::string();
                ev.actor_ip = client_ip(req);
                ev.status   = pki::audit_status::kFailure;
                ev.detail   = "protocol=ACME reason=jws_verify url=" + expected_url;
                audit_db->append_audit(ev);
            } catch (const std::exception& ae) {
                pki::log::err(std::string("ACME audit append failed: ") + ae.what());
            }
        }
        send_problem(adb, req, res, 401, "unauthorized", e.what(), ttl);
        return std::nullopt;
    }

    // ⚠️ A DEACTIVATED ACCOUNT MUST BE REFUSED EVERYWHERE, NOT JUST AT ISSUANCE.
    // RFC 8555 §7.3.6: "A deactivated account can no longer request certificate
    // issuance or access resources related to the account, such as orders or
    // authorizations. If a server receives a POST or POST-as-GET from a deactivated
    // account, it MUST return an error response with status code 401 (Unauthorized)
    // and type urn:ietf:params:acme:error:unauthorized."
    //
    // The reason this belongs HERE and not in each handler: deactivation is what a
    // client does when it believes the account key is COMPROMISED. If the check sits
    // in the handlers, every handler that forgets it is a route the compromised key
    // still works on — and the whole point of deactivating was to make the key inert.
    // Every authenticated request already funnels through this function, so this is
    // the one place that cannot be forgotten by a future route.
    //
    // Placed AFTER signature verification on purpose: answering "this account is
    // deactivated" to someone who cannot sign for it would confirm the account exists
    // to anyone who can guess a kid.
    if (out.account && out.account->status == 1) {
        send_problem(adb, req, res, 401, "unauthorized",
                     "account is deactivated", ttl);
        return std::nullopt;
    }
    return out;
}

// ---------------------------------------------------------------------------

struct ServerState {
    pki::Config  cfg;
    pki::AcmeDb* adb{nullptr};
    pki::Db*     certs_db{nullptr};
    std::string  base;     // base_url + acme_base_path
    pki::CaMaterialCache* ca_cache{nullptr};   // per-request signing material
};

// ⚠️ READ WHERE IT IS USED, NOT ONCE AT STARTUP. ACME_DNS_RESOLVER lives in the `config`
// table, which the console and `fastpki-config set` can both change — and a setting the
// console offers to change while the server only reads it at boot is one that silently does
// nothing until somebody restarts the service. Nothing said so, in the console or the logs.
//
// It matters beyond tidiness: pointing the server at a resolver that answers the dns-01
// challenge TXT is the one step demo provisioning could not do over the API, which is why
// that script carried an ssh, a `docker exec` and a kubectl mode to reach the host's own
// CLI. With the value read at use, an admin session is enough on every platform.
//
// Cached for a few seconds because a single new-order checks CAA once per identity, so a
// multi-name order would otherwise be a query apiece. Short enough that an operator who
// changes the value sees it take effect immediately in any human sense.
std::string dns_resolver_now(const ServerState& s) {
    static std::mutex mu;
    static std::string cached;
    static std::time_t taken = 0;
    static bool have = false;
    const std::time_t now = std::time(nullptr);
    std::lock_guard<std::mutex> lk(mu);
    if (!have || now - taken >= 5) {
        // Best effort: a database that cannot be read here must not fail a validation that
        // would otherwise succeed, so the startup value stands in.
        try {
            const auto rows = s.certs_db->get_config();
            const auto it = rows.find("ACME_DNS_RESOLVER");
            cached = (it != rows.end()) ? it->second : s.cfg.acme_dns_resolver;
        } catch (const std::exception& e) {
            pki::log::debug(std::string("could not re-read ACME_DNS_RESOLVER (") + e.what() +
                            ") — using the value this server started with");
            cached = s.cfg.acme_dns_resolver;
        }
        taken = now;
        have = true;
    }
    return cached;
}

// Per-request base URL. When BASE_URL isn't configured explicitly, the
// pre-routing handler fills this from the request's Host header so the
// directory advertises endpoints on the address/port the client actually used
// (instead of a stale default). Empty → fall back to the configured base.
thread_local std::string g_req_base;

// The CA instance for the current request, parsed from the first
// path segment after {acme_base_path} — i.e. {acme_base_path}/<id>/... (the
// trailing-segment style, e.g. /acme/<id>/directory) — by the
// pre-routing handler; "" for the non-virtualized paths. Because every
// advertised ACME URL is built from g_req_base (which carries the same prefix),
// the whole order flow stays in-instance and each request — including finalize
// — knows its instance.
thread_local std::string g_req_instance = "";   // "" = base route → the first CA
// The request's Host header, captured in the pre-routing handler, so the
// directory/finalize handlers can bind the /{ca_id} to the tenant of the host.
thread_local std::string g_req_host;

std::string url_for(const ServerState& s, std::string_view sub) {
    const std::string& base = g_req_base.empty() ? s.base : g_req_base;
    return base + std::string(sub);
}

json directory_json(const ServerState& s) {
    json d = {
        {"newNonce",   url_for(s, "/new-nonce")},
        {"newAccount", url_for(s, "/new-account")},
        {"newOrder",   url_for(s, "/new-order")},
        {"revokeCert", url_for(s, "/revoke-cert")},
        {"keyChange",  url_for(s, "/key-change")},
        {"meta", {
            {"termsOfService", url_for(s, "/terms")},
            {"externalAccountRequired", true},
        }},
    };
    // Pre-authorization is optional (RFC 8555 §7.4.1): advertise newAuthz only
    // when enabled, so clients that key off its presence behave correctly.
    if (s.cfg.acme_new_authz) d["newAuthz"] = url_for(s, "/new-authz");
    return d;
}

void handle_directory(const ServerState& s, httplib::Response& res) {
    // Reject an unknown/disabled tenant up front so clients don't start a flow
    // they can't finalize.
    // ACME is id-based — a base (no-id) request names no CA, so it 404s.
    if (g_req_instance.empty()) {
        res.status = 404;
        res.set_content("this endpoint is per-CA: use " + s.cfg.acme_base_path + "/{ca_id}/directory", "text/plain");
        return;
    }
    {
        auto rc = pki::resolve_ca_instance(*s.certs_db, s.cfg, g_req_instance);
        // A /{ca_id} route is honoured only for a CA of the request's tenant.
        if (!rc.found)
            { res.status = 404; res.set_content("unknown CA instance", "text/plain"); return; }
        // A mesh peer holds every CA's certificate and only its own CA's key,
        // so "disabled" was the wrong word about two CAs in three.
        if (!rc.active) { res.status = 503; res.set_content(pki::ca_unavailable_reason(rc), "text/plain"); return; }
    }
    res.status = 200;
    res.set_content(directory_json(s).dump(), "application/json");
}

// Verify an ACME external-account-binding (RFC 8555 §7.3.4). Returns the bound
// external account id (kid) on success; throws pki::Error on failure. The
// per-kid HMAC key is read from the `keys` table via get_shared_secret
// (base64url-encoded), and the binding's inner payload must equal the
// account's public JWK.
std::string verify_eab(ServerState& s, const json& eab, const json& account_jwk,
                       const std::string& expected_url) {
    // ⚠️ TYPE-CHECKED, NOT JUST PRESENCE-CHECKED. contains() says a member is there; it says
    // nothing about it being a string, and .get<std::string>() on a number, object or array
    // throws nlohmann::json::type_error — which is NOT a pki::Error, so it escaped the
    // handler's catch and became a 500. A malformed binding is a client error and RFC 8555
    // has a problem document for it; answering 500 blames the server for the client's JSON.
    for (const char* m : {"protected", "payload", "signature"})
        if (!eab.contains(m) || !eab[m].is_string())
            throw pki::Error(1, std::string("malformed binding object: '") + m +
                                "' must be present and a string");
    std::string prot_b64 = eab["protected"].get<std::string>();
    std::string payl_b64 = eab["payload"].get<std::string>();
    std::string sig_b64  = eab["signature"].get<std::string>();

    auto prot_bytes = pki::jws::base64url_decode(prot_b64);
    json prot = json::parse(std::string(prot_bytes.begin(), prot_bytes.end()));
    if (prot.value("alg", "") != "HS256") throw pki::Error(1, "alg must be HS256");
    std::string kid = prot.value("kid", "");
    if (kid.empty()) throw pki::Error(1, "missing kid");
    if (prot.value("url", "") != expected_url) throw pki::Error(1, "url mismatch");

    auto keyb64 = s.certs_db->get_shared_secret(kid, pki::keyproto::kEab);   // keys table
    if (!keyb64) throw pki::Error(1, "unknown kid");
    auto key = pki::jws::base64url_decode(*keyb64);

    std::string signing_input = prot_b64 + "." + payl_b64;
    unsigned char mac[EVP_MAX_MD_SIZE]; unsigned int maclen = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(signing_input.data()),
         signing_input.size(), mac, &maclen);
    auto sig = pki::jws::base64url_decode(sig_b64);
    if (sig.size() != maclen || CRYPTO_memcmp(mac, sig.data(), maclen) != 0)
        throw pki::Error(1, "signature invalid");

    // The inner payload is the account public key JWK; it must match the
    // account key in the outer request.
    auto payl = pki::jws::base64url_decode(payl_b64);
    json eab_jwk = json::parse(std::string(payl.begin(), payl.end()));
    if (eab_jwk != account_jwk) throw pki::Error(1, "key does not match account key");
    return kid;
}

void handle_new_nonce(const ServerState& s, const httplib::Request& req,
                      httplib::Response& res) {
    set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
    res.status = 204;
}

void handle_new_account(ServerState& s, const httplib::Request& req,
                        httplib::Response& res) {
    auto post = parse_acme_post(s.cfg, *s.adb, req, res, url_for(s, "/new-account"), s.certs_db);
    if (!post) return;
    if (!post->parsed.jwk) { send_problem(*s.adb, req, res,400, "malformed", "newAccount must use jwk"); return; }

    // Compute the JWK hash and look up an existing account.
    std::string hash;
    try { hash = pki::jws::thumbprint(*post->parsed.jwk); }
    catch (const pki::Error& e) { send_problem(*s.adb, req, res,400, "badPublicKey", e.what()); return; }

    auto existing = s.adb->get_account_by_jwk_hash(hash);
    json payload;
    if (!post->parsed.payload_bytes.empty()) {
        try { payload = json::parse(std::string(post->parsed.payload_bytes.begin(),
                                                post->parsed.payload_bytes.end())); }
        catch (const std::exception& e) {
            send_problem(*s.adb, req, res,400, "malformed", std::string("payload: ") + e.what()); return;
        }
    }

    if (payload.value("onlyReturnExisting", false) && !existing) {
        send_problem(*s.adb, req, res,400, "accountDoesNotExist", "no account for this key"); return;
    }

    pki::AcmeAccount acc;
    if (existing) {
        acc = *existing;
        res.status = 200;
    } else {
        // External Account Binding (RFC 8555 §7.3.4): bind the new ACME account
        // to a pre-shared identity. The per-kid HMAC key lives in the `keys`
        // table (get_shared_secret), base64url-encoded — the PHP model.
        //
        // MANDATORY. ACME_EAB_REQUIRED used to make this optional, and with it off
        // any client could self-generate an account key and enrol — the account carried no
        // kid, so `handle_new_order` skipped BOTH the acme:enrol check and the per-holder cap
        // (see there). An internal CA has no reason to accept an account it cannot name.
        std::string eab_kid;
        if (payload.contains("externalAccountBinding")) {
            try {
                eab_kid = verify_eab(s, payload["externalAccountBinding"],
                                     *post->parsed.jwk, url_for(s, "/new-account"));
            } catch (const pki::Error& e) {
                send_problem(*s.adb, req, res, 401, "unauthorized",
                             std::string("externalAccountBinding: ") + e.what());
                return;
            }
            acc.eab_json = payload["externalAccountBinding"].dump();
        } else if (s.adb->device_tickets_outstanding(now_unix()) || s.adb->any_device_serials()) {
            // ⚠️ AN ACCOUNT WITH NO BINDING CAN ONLY PROVE A DEVICE. Apple's ACME client has
            // no way to send an external account binding; the attestation it answers the
            // device-attest-01 challenge with takes that place. Such an account keeps an
            // empty kid, and handle_new_order refuses it everything except a
            // permanent-identifier order backed by an unclaimed ticket, which an
            // administrator issued, or naming a registered device serial. Accepted only while a
            // ticket is outstanding or a serial is registered, so a deployment that uses neither
            // refuses these accounts exactly as before.
            pki::log::info("ACME: account created without an external account binding; it "
                           "can place device-attestation orders only");
        } else {
            send_problem(*s.adb, req, res, 400, "externalAccountRequired",
                         "external account binding is required");
            return;
        }

        acc.id            = random_id_decimal();
        acc.status        = 0;        // valid
        acc.terms_agreed  = payload.value("termsOfServiceAgreed", false) ? 1 : 0;
        acc.jwk_hash      = hash;
        acc.jwk_json      = post->parsed.jwk->dump();
        acc.kid           = eab_kid;  // external identity this account is bound to
        if (payload.contains("contact"))
            acc.contacts_json = payload["contact"].dump();
        s.adb->save_account(acc);
        res.status = 201;
    }

    set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
    res.set_header("Location", url_for(s, "/account/" + acc.id));

    json body = {
        {"status",  "valid"},
        {"contact", acc.contacts_json.empty() ? json::array() : json::parse(acc.contacts_json)},
        {"orders",  url_for(s, "/account/" + acc.id + "/orders")},
    };
    res.set_content(body.dump(), "application/json");
}

// ============================================================================
// Orders, authz, challenges, finalize, certificate
// ============================================================================

// Helpers for URL building of nested resources.
std::string order_url(const ServerState& s, const std::string& id)    { return url_for(s, "/order/"  + id); }
std::string finalize_url(const ServerState& s, const std::string& id) { return url_for(s, "/order/"  + id + "/finalize"); }
std::string authz_url(const ServerState& s, const std::string& id)    { return url_for(s, "/authz/"  + id); }
std::string chall_url(const ServerState& s, const std::string& id)    { return url_for(s, "/chall/"  + id); }
std::string cert_url(const ServerState& s, const std::string& serial) { return url_for(s, "/cert/"   + serial); }

// Retry-After hint (seconds) for objects the client must poll while the server
// works asynchronously: a triggered challenge (RFC 8555 §8.2), a still-pending
// authorization (§7.5.1), and a "processing" order (§7.1.3).
//
// It must sit well inside kKeepAliveSec. certbot sleeps exactly Retry-After and then
// sends the next POST-as-GET on its pooled connection; if the server has closed that
// connection for idleness in the meantime, the request fails with RemoteDisconnected and
// urllib3 does not retry a POST, so the order fails. A hint equal to the idle timeout
// loses that race whenever latency pushes the send past it. The idle timeout is
// not raised instead, because every idle keep-alive connection holds a worker thread.
static constexpr int    kRetryAfterSec = 2;
static constexpr time_t kKeepAliveSec  = 5;
static_assert(2 * kRetryAfterSec < kKeepAliveSec,
              "the ACME poll hint must leave at least half the keep-alive window");

const char* order_status_str(int s) {
    switch (s) { case 0: return "pending"; case 1: return "ready";
                 case 2: return "processing"; case 3: return "valid";
                 default: return "invalid"; }
}
const char* authz_status_str(int s) {
    switch (s) { case 0: return "pending"; case 1: return "valid";
                 case -2: return "deactivated"; default: return "invalid"; }
}
const char* chall_status_str(int s) {
    switch (s) { case 0: return "pending"; case 1: return "processing";
                 case 2: return "valid"; default: return "invalid"; }
}

// RFC 7515-style key authorization: `token + "." + base64url(SHA256(canonical(jwk)))`.
std::string key_authorization(const std::string& token, const json& jwk) {
    // The thumbprint helper already returns base64url(SHA256(canonical JWK)).
    return token + "." + pki::jws::thumbprint(jwk);
}

json order_to_json(const ServerState& s, const pki::AcmeOrder& o) {
    json out;
    out["status"] = order_status_str(o.status);
    if (o.expires) out["expires"] = rfc3339(o.expires);
    out["identifiers"] = o.identifiers_json.empty()
        ? json::array() : json::parse(o.identifiers_json);

    auto authzs = s.adb->authz_for_order(o.id);
    json az = json::array();
    for (auto& a : authzs) az.push_back(authz_url(s, a.id));
    out["authorizations"] = az;
    out["finalize"]       = finalize_url(s, o.id);
    if (!o.cert_serial.empty()) out["certificate"] = cert_url(s, o.cert_serial);
    return out;
}

json authz_to_json(const ServerState& s, const pki::AcmeAuthz& a) {
    json out;
    out["status"]     = authz_status_str(a.status);
    out["identifier"] = a.identifier_json.empty()
                          ? json::object() : json::parse(a.identifier_json);
    if (a.expires)  out["expires"]  = rfc3339(a.expires);
    if (a.wildcard) out["wildcard"] = true;
    auto challs = s.adb->challenges_for_authz(a.id);
    json arr = json::array();
    for (auto& c : challs) {
        json cj;
        cj["type"]   = c.type;
        cj["url"]    = c.url;
        cj["status"] = chall_status_str(c.status);
        cj["token"]  = c.token;
        if (c.validated) cj["validated"] = rfc3339(c.validated);
        if (!c.error.empty()) cj["error"] = json{{"detail", c.error}};
        arr.push_back(std::move(cj));
    }
    out["challenges"] = arr;
    return out;
}

// Create one authorization for `ident` (tied to `order_id`, which may be a
// pre-authorization key for /new-authz) with its challenge set. Every authz
// offers all three challenge types. Returns the new authz id.
//
// ⚠️ THE AUTHZ IDENTIFIER IS THE BASE DOMAIN, NEVER "*.something" — RFC 8555 §7.1.3:
// "An authorization returned by the server for a wildcard domain name identifier MUST
// NOT include the asterisk and full stop ("*.") prefix in the authorization identifier
// value. The returned authorization MUST include the optional "wildcard" field, with a
// value of true." §7.1.4 says it again: "Wildcard domain names (with "*" as the first
// label) MUST NOT be included in authorization objects." The ORDER keeps the wildcard
// (that is what goes in the certificate); the AUTHZ carries the base name plus the flag.
//
// ⚠️ A WILDCARD IS OFFERED dns-01 AND NOTHING ELSE, AND THAT IS OUR POLICY RATHER THAN THE
// PROTOCOL'S. State it that way round, because a comment here once cited "RFC 8555 §8.4 /
// RFC 8737 §3" for it and neither section says any such thing — the word "wildcard" does
// not appear anywhere in §8 of RFC 8555, nor anywhere at all in RFC 8737. Anyone who
// re-checks that citation will find it false and may conclude the restriction is a mistake.
// It is not; it is a deliberate issuance policy, for this reason:
//
//   http-01 and tls-alpn-01 are answered by whoever currently occupies ONE host. A
//   wildcard grants every name under the zone. So satisfying "*.example.com" by serving a
//   file from one machine that happens to answer for example.com hands out authority far
//   wider than what was proven. dns-01 proves control of the ZONE, which is exactly the
//   thing a wildcard delegates.
//
// The two connect-based challenges are perfectly capable of validating a wildcard's base
// name — an earlier defect stored the raw "*.example.com" as the authz identifier, so a
// validator dialled a host literally named that, and it was the resulting failure rather
// than any policy that made them look incapable. They work. We decline to accept them
// here anyway, which is a different statement and the honest one.
std::string make_authz(ServerState& s, const std::string& order_id,
                       const std::string& account_id, const json& ident, int64_t expires) {
    const std::string raw = ident.value("value", "");
    const bool wildcard = (raw.rfind("*.", 0) == 0);
    json authz_ident = ident;
    if (wildcard) authz_ident["value"] = raw.substr(2);
    pki::AcmeAuthz a;
    a.id = random_id_decimal();
    a.status = 0;
    a.expires = expires;
    a.identifier_json = authz_ident.dump();
    a.wildcard = wildcard ? 1 : 0;
    a.order_id = order_id;       // "" for a pre-authorization
    a.account_id = account_id;
    s.adb->save_authz(a);

    auto add_challenge = [&](const char* type) {
        pki::AcmeChallenge c;
        c.id   = random_id_decimal();
        c.type = type;
        c.url  = chall_url(s, c.id);
        c.status = 0;
        unsigned char tok[16]; must_random(tok, sizeof tok);  // token: base64url(16 bytes)
        c.token = pki::jws::base64url_encode(tok, sizeof tok);
        c.authz_id = a.id;
        s.adb->save_challenge(c);
    };
    // A device is proven by attestation and by nothing else: the identifier is a ticket,
    // not a name anyone could serve a file or a TXT record for.
    if (ident.value("type", "") == "permanent-identifier") {
        add_challenge("device-attest-01");
        return a.id;
    }
    if (!wildcard) {
        add_challenge("http-01");
        add_challenge("tls-alpn-01");
    }
    add_challenge("dns-01");
    return a.id;
}

// Does this order name a device rather than DNS names? Read from the payload at new-order
// and from the stored identifiers at finalize, so both decide it the same way.
bool is_device_order(const json& identifiers) {
    if (!identifiers.is_array()) return false;
    for (const auto& i : identifiers)
        if (i.is_object() && i.value("type", "") == "permanent-identifier") return true;
    return false;
}

// ---- new-order for a device (device-attest-01) ----
//
// The identifier's value is the device's ClientIdentifier, and it is one of two things:
//
//   * a one-time TICKET an administrator or the user issued (`fastpki-acme
//     --issue-device-ticket`, or the console's Apple ACME profile). The ticket, not the
//     account, says who the certificate is for: it names the CA, the owner RBAC is asked
//     about, and the profile. This order claims it in one statement, so it backs one order.
//   * the device's SERIAL NUMBER, registered for this CA (acme_device_serials) — the MDM
//     path, where one profile serves a fleet and fills the serial in per device. The order
//     gets a ticket of its own, created already claimed, carrying the serial it expects:
//     the attestation must then prove exactly that serial, which Apple signs.
//
// Either way the challenge and finalize find the ticket by this order, so the rest of the
// flow cannot tell the two apart.
void handle_device_order(ServerState& s, const httplib::Request& req, httplib::Response& res,
                         const AcmePost& post, const json& payload) {
    const json& idents = payload["identifiers"];
    if (idents.size() != 1 || !idents[0].is_object() ||
        idents[0].value("type", "") != "permanent-identifier" ||
        !idents[0].contains("value") || !idents[0]["value"].is_string()) {
        send_problem(*s.adb, req, res, 400, "malformed",
                     "a device order carries exactly one permanent-identifier and nothing else");
        return;
    }
    const std::string value = idents[0]["value"].get<std::string>();
    // One answer for every way an identifier can be unusable, so the route tells a caller
    // nothing about which tickets or serials exist.
    auto refuse = [&]() {
        pki::log::info("ACME: device order refused on CA '" + g_req_instance +
                       "': not an unused ticket for this CA, nor a serial registered for it");
        send_problem(*s.adb, req, res, 403, "unauthorized",
                     "the device ticket is unknown, expired, already used, or for another CA, "
                     "and no device with this serial number is registered for this CA");
    };
    const int64_t now = now_unix();
    std::string owner, profile, expected_serial;
    auto t = s.adb->get_device_ticket(value);
    if (t && t->ca_instance_id == g_req_instance && t->expires > now && t->order_id.empty()) {
        owner = t->owner;
        profile = t->profile;
    } else if (auto ds = s.adb->get_device_serial(value, g_req_instance)) {
        owner = ds->owner;
        profile = ds->profile;
        expected_serial = ds->serial;
    } else {
        refuse();
        return;
    }
    // RBAC is asked about the owner, as it would be about an EAB-bound user. Asked again at
    // finalize, so a grant revoked in between takes effect.
    const std::vector<std::string> groups = pki::directory_groups_for(s.cfg, s.certs_db, owner);
    if (!pki::may_enrol(*s.certs_db, owner, "", "acme:enrol", g_req_instance, groups)) {
        pki::log::info("ACME: device order refused: '" + owner +
                       "' holds no acme:enrol for CA '" + g_req_instance + "'");
        send_problem(*s.adb, req, res, 403, "unauthorized",
                     "the owner of this device may not enrol over ACME against CA '" +
                         g_req_instance + "'");
        return;
    }

    pki::AcmeOrder o;
    o.id               = random_id_decimal();
    o.status           = 0;
    o.expires          = now + 60LL * 60 * 24 * s.cfg.order_expires_days;
    if (expected_serial.empty()) o.expires = std::min<int64_t>(o.expires, t->expires);
    o.identifiers_json = idents.dump();
    o.account_id       = post.account->id;
    o.ca_instance_id   = g_req_instance;
    if (expected_serial.empty()) {
        if (!s.adb->claim_device_ticket(value, g_req_instance, o.id, now)) {
            refuse();   // another order claimed it between the read above and now
            return;
        }
    } else {
        pki::AcmeDeviceTicket own;
        unsigned char raw[16];
        must_random(raw, sizeof raw);
        own.ticket          = "serial:" + pki::jws::base64url_encode(raw, sizeof raw);
        own.ca_instance_id  = g_req_instance;
        own.owner           = owner;
        own.profile         = profile;
        own.created         = now;
        own.expires         = o.expires;
        own.order_id        = o.id;
        own.expected_serial = expected_serial;
        s.adb->create_device_ticket(own);
    }
    s.adb->save_order(o);
    make_authz(s, o.id, post.account->id, idents[0], o.expires);
    pki::log::info("ACME: device order " + o.id + " for '" + owner + "' on CA '" +
                   g_req_instance + "'" +
                   (expected_serial.empty() ? std::string(" (ticket)")
                                            : " (registered serial " + expected_serial + ")"));

    set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
    res.set_header("Location", order_url(s, o.id));
    res.status = 201;
    res.set_content(order_to_json(s, o).dump(), "application/json");
}

// ---- new-order ----
void handle_new_order(ServerState& s, const httplib::Request& req,
                      httplib::Response& res) {
    auto post = parse_acme_post(s.cfg, *s.adb, req, res, url_for(s, "/new-order"), s.certs_db);
    if (!post) return;
    if (!post->account) { send_problem(*s.adb, req, res,400, "malformed", "kid required"); return; }

    // A device order is authorized by its ticket, not by the account's binding, so it is
    // decided before the binding check below. Any account may present a ticket; an account
    // without a binding can do nothing else.
    {
        json early;
        try {
            early = json::parse(std::string(post->parsed.payload_bytes.begin(),
                                            post->parsed.payload_bytes.end()));
        } catch (...) {}
        if (early.is_object() && early.contains("identifiers") &&
            is_device_order(early["identifiers"])) {
            handle_device_order(s, req, res, *post, early);
            return;
        }
    }

    // May the identity this account is bound to enrol over ACME against
    // THIS CA? The binding is the EAB kid, which a role grant mints and which is the plain
    // username, so it IS the subject — nothing to derive.
    //
    // ⚠️ THIS USED TO BE `if (!kid.empty())` — AND THAT WAS THE BYPASS. An account
    // with no kid skipped this authorization check AND the cap below, silently, and
    // ACME_EAB_REQUIRED=false was all it took to create one. With EAB mandatory
    // `acc.kid = eab_kid` always runs at new-account, so an empty kid is no longer an
    // anonymous-but-legitimate account — it is a row that cannot be authorized, and
    // refusing is the only safe reading. A permissive fallback on a state that should be
    // unreachable is exactly how the old switch turned into a hole.
    //
    // Checked HERE rather than at new-account, so revoking a role takes effect on the
    // next order instead of only for accounts created afterwards.
    //
    // The refusal is an RFC 8555 problem document, not a bare 403: an ACME client parses
    // `type` and shows `detail`, and "unauthorized" is the registered type for exactly
    // this. urn:ietf:params:acme:error: is prefixed by send_problem.
    if (post->account->kid.empty()) {
        send_problem(*s.adb, req, res, 403, "unauthorized",
                     "this account carries no external account binding and cannot enrol");
        return;
    }
    // Hoisted out of the block below: the per-name and per-SAN limits cannot be decided
    // until the identifiers are parsed, so the resolved limits and the identity have to
    // outlive the authorization check that produced them.
    // ONE definition of "which user does this kid belong to". This used to be an
    // ad-hoc substr here and nothing at all at finalize, which is how the two disagreed.
    const std::string acct_user = post->account->kid;
    pki::RoleLimits acct_limits;
    {
        // Same gap as CMP/SCEP. The ACME account is bound to a user by its EAB key,
        // so the username is known and its group-granted roles must count.
        // Hoisted — the CAP below must ask about the same identity this GATE did.
        const std::vector<std::string> acme_groups =
            pki::directory_groups_for(s.cfg, s.certs_db, acct_user);
        if (!pki::may_enrol(*s.certs_db, acct_user, "", "acme:enrol", g_req_instance,
                            acme_groups)) {
            try {
                pki::AuditEvent ev;
                ev.category = pki::audit_cat::kAuth;
                ev.action   = "authz_fail";
                ev.actor    = acct_user;
                ev.actor_ip = client_ip(req);
                ev.target   = g_req_instance;
                ev.status   = pki::audit_status::kFailure;
                ev.detail   = "protocol=ACME need=acme:enrol ca=" + g_req_instance;
                s.certs_db->append_audit(ev);
            } catch (const std::exception& e) {
                pki::log::err(std::string("ACME authz audit append failed: ") + e.what());
            }
            send_problem(*s.adb, req, res, 403, "unauthorized",
                         "this account may not enrol over ACME against CA '" +
                         g_req_instance + "'");
            return;
        }

        // The per-REQUESTER cap from `roles.max_certs`.
        //
        // ⚠️ ACME DOES have a subject here, and an earlier commit message said it did not —
        // corrected on the ticket. An account with External Account Binding carries a kid
        // whose username half is exactly what `may_enrol` above is given, so a role cap can
        // read it. Without EAB there is no kid, this whole block is skipped, and no cap
        // applies — which is right: an account key is not an identity the RBAC tables know.
        // SCEP is the protocol that genuinely gets nothing; a challenge password is not a
        // subject at all.
        //
        // The refusal is an RFC 8555 problem document, not a bare 429: an ACME client parses
        // `type` and shows `detail`. "rateLimited" is the registered type for exactly this.
        acct_limits = pki::role_limits(*s.certs_db, acct_user, "", acme_groups);
        // Only the per-requester half can be decided here — max_cn and max_san need the
        // identifiers, which are in the payload below. Passing "" / -1 says "not read"
        // rather than passing 0 and silently satisfying a limit that was never tested.
        const std::string why =
            pki::role_limit_refusal(*s.certs_db, acct_limits, acct_user, "", -1);
        if (!why.empty()) {
            pki::log::info("ACME: refusing '" + acct_user + "' — " + why);
            send_problem(*s.adb, req, res, 429, "rateLimited", why);
            return;
        }
    }

    json payload;
    try { payload = json::parse(std::string(post->parsed.payload_bytes.begin(),
                                            post->parsed.payload_bytes.end())); }
    catch (...) { send_problem(*s.adb, req, res,400, "malformed", "bad payload"); return; }
    if (!payload.contains("identifiers") || !payload["identifiers"].is_array()
        || payload["identifiers"].empty()) {
        send_problem(*s.adb, req, res,400, "malformed", "identifiers[] required"); return;
    }

    // Validate every identifier up front so we never persist a partial order.
    //
    // ⚠️ THE VALUE IS CHECKED, NOT JUST THE TYPE. A `dns` identifier used to be accepted
    // as any string at all: it became the authz name, then the CSR SAN the comparison at
    // finalize demands, then the dNSName in the certificate — and policy.cpp deliberately
    // skips the domain allowlist for ACME, so nothing anywhere looked at the bytes. An
    // identifier of `evil.example\0.attacker.example` is resolvable inside a zone the
    // caller controls (DNS splits on '.', so the NUL sits harmlessly inside a label), the
    // dns-01 challenge for it therefore SOLVES, and the certificate then carries a name a
    // client reading the SAN as a C string sees as `evil.example`. policy.cpp now refuses
    // it at issuance; refusing it HERE is what makes the refusal useful, because at
    // finalize the client has already solved every challenge for nothing.
    //
    // rejectedIdentifier is the registered problem type for exactly this (RFC 8555 §6.7).
    for (auto& ident : payload["identifiers"]) {
        if (!ident.is_object() || ident.value("type", "") != "dns") {
            send_problem(*s.adb, req, res, 400, "malformed", "only dns identifiers supported");
            return;
        }
        const std::string v = ident.value("value", "");
        if (!pki::valid_dns_name(v)) {
            send_problem(*s.adb, req, res, 400, "rejectedIdentifier",
                         "identifier is not a valid DNS name");
            return;
        }
    }

    // The other two role limits, now that the names are known.
    //
    // ⚠️ ACME has no CN and no SubjectAltName at newOrder — it has identifiers, and the CSR
    // arrives later at finalize. But every identifier BECOMES a SAN entry and the first one
    // becomes the CN, so the numbers are decidable here, and here is where refusing costs
    // the client nothing: at finalize it would already have solved every challenge.
    //
    // ⚠️ The per-name check runs for EVERY identifier, not just the first. A limit that only
    // looked at the CN would be trivially bypassed by asking for the capped name second.
    if (!acct_user.empty() && (acct_limits.max_cn || acct_limits.max_san)) {
        const int n_ident = static_cast<int>(payload["identifiers"].size());
        for (auto& ident : payload["identifiers"]) {
            const std::string name = ident.value("value", "");
            const std::string why = pki::role_limit_refusal(*s.certs_db, acct_limits,
                                                            /*user=*/"", name, n_ident);
            if (!why.empty()) {
                pki::log::info("ACME: refusing '" + acct_user + "' — " + why);
                send_problem(*s.adb, req, res, 429, "rateLimited", why);
                return;
            }
        }
    }

    pki::AcmeOrder o;
    o.id               = random_id_decimal();
    o.status           = 0; // pending
    o.expires          = now_unix() + 60LL * 60 * 24 * s.cfg.order_expires_days;
    o.identifiers_json = payload["identifiers"].dump();
    o.account_id       = post->account->id;
    // Pin the order to the CA whose acme:enrol gate it just passed (above). This
    // is the whole fix — finalize picks its signing CA from ITS url, so without a CA
    // recorded on the order there was nothing to check the finalize CA against, and an
    // account gated on one CA could finalize under another. g_req_instance is the CA in
    // the new-order url; on a base (no-id) route it resolves to the tenant's first CA the
    // same way issuance does, so the value stored is the CA that will actually sign.
    o.ca_instance_id   = g_req_instance;
    s.adb->save_order(o);

    // One authorization per identifier. If pre-authorization (§7.4.1) is enabled
    // and the account already holds a valid authz for the identifier, reuse it by
    // attaching an order-scoped copy that is already valid (no re-validation).
    bool all_valid = true;
    for (auto& ident : payload["identifiers"]) {
        std::optional<pki::AcmeAuthz> reuse;
        if (s.cfg.acme_new_authz)
            reuse = s.adb->find_valid_authz(post->account->id, ident.dump(), now_unix());
        if (reuse) {
            pki::AcmeAuthz a = *reuse;
            a.id = random_id_decimal();
            a.order_id = o.id;
            a.account_id = post->account->id;
            a.status = 1;                 // already validated
            s.adb->save_authz(a);
        } else {
            make_authz(s, o.id, post->account->id, ident, o.expires);
            all_valid = false;
        }
    }
    // If every identifier resolved to a reused valid authz, the order is ready.
    if (all_valid) { o.status = 1; s.adb->save_order(o); }

    set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
    res.set_header("Location", order_url(s, o.id));
    res.status = 201;
    res.set_content(order_to_json(s, o).dump(), "application/json");
}

// ---- new-authz: pre-authorization (RFC 8555 §7.4.1) ----
// POST { "identifier": {"type":"dns","value":"..."} } creates a standalone
// authorization the client can complete ahead of placing an order. It is keyed
// to the account (order = "preauth:<account_id>") so a later new-order for the
// same identifier can reuse the validated result. Enabled by ACME_NEW_AUTHZ.
void handle_new_authz(ServerState& s, const httplib::Request& req,
                      httplib::Response& res) {
    auto post = parse_acme_post(s.cfg, *s.adb, req, res, url_for(s, "/new-authz"), s.certs_db);
    if (!post) return;
    if (!post->account) { send_problem(*s.adb, req, res, 400, "malformed", "kid required"); return; }

    json payload;
    try { payload = json::parse(std::string(post->parsed.payload_bytes.begin(),
                                            post->parsed.payload_bytes.end())); }
    catch (...) { send_problem(*s.adb, req, res, 400, "malformed", "bad payload"); return; }
    const json& ident = payload.contains("identifier") ? payload["identifier"] : json::object();
    if (!ident.is_object() || ident.value("type", "") != "dns" || ident.value("value", "").empty()) {
        send_problem(*s.adb, req, res, 400, "malformed", "identifier {type:dns,value} required");
        return;
    }

    const int64_t expires = now_unix() + 60LL * 60 * 24 * s.cfg.order_expires_days;
    std::string authz_id = make_authz(s, /*order_id=*/"", post->account->id, ident, expires);
    auto a = s.adb->get_authz(authz_id);

    set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
    res.set_header("Location", authz_url(s, authz_id));
    res.status = 201;
    if (a) res.set_content(authz_to_json(s, *a).dump(), "application/json");
}

// ---- account URL: fetch info + deactivation (RFC 8555 §7.3.6) ----
void handle_account(ServerState& s, const httplib::Request& req,
                    httplib::Response& res, const std::string& account_id) {
    auto post = parse_acme_post(s.cfg, *s.adb, req, res, url_for(s, "/account/" + account_id), s.certs_db);
    if (!post) return;
    // ⚠️ THE SIGNER MUST OWN THE ACCOUNT IT IS ACTING ON. This read the account straight
    // out of the URL and acted on it, never comparing it to the authenticated signer — so
    // any account holding a valid key could POST {"status":"deactivated"} to any other
    // account's URL. RFC 8555 §7.3.6 makes deactivation IRREVERSIBLE ("the server will not
    // accept further requests authorized by this account key"), so that is a permanent
    // denial of service against any account whose id an attacker can see, recoverable only
    // by an operator reissuing EAB credentials. handle_account_orders() 30 lines below has
    // always carried exactly this check; this handler simply never got it.
    if (!post->account || post->account->id != account_id) {
        send_problem(*s.adb, req, res, 401, "unauthorized",
                     "an account may only be read or deactivated by its own key");
        return;
    }
    auto acc = s.adb->get_account_by_id(account_id);
    if (!acc) { send_problem(*s.adb, req, res, 400, "accountDoesNotExist", "no such account"); return; }

    // Client deactivation: POST {"status":"deactivated"}.
    //
    // ⚠️ THE PARSE IS GUARDED; THE WRITE IS NOT. A malformed payload must not 500, which is
    // what the try is for — but it used to span save_account() as well, so a failed write
    // was swallowed and the 200 below rendered the IN-MEMORY object. A client deactivating
    // a compromised account was told it had succeeded while the row stayed untouched and
    // the account went on enrolling.
    bool want_deactivate = false;
    if (!post->parsed.payload_bytes.empty()) {
        try {
            auto p = json::parse(std::string(post->parsed.payload_bytes.begin(),
                                              post->parsed.payload_bytes.end()));
            want_deactivate = (p.value("status", "") == "deactivated");
        } catch (...) {}
    }
    if (want_deactivate) {
        const int prev = acc->status;
        acc->status = 1; // deactivated
        try {
            s.adb->save_account(*acc);
        } catch (const std::exception& e) {
            acc->status = prev;   // the response must not claim what the row does not say
            pki::log::err(std::string("ACME: could not deactivate account ") + acc->id
                          + ": " + e.what());
            send_problem(*s.adb, req, res, 500, "serverInternal",
                         "the deactivation could not be recorded");
            return;
        }
        pki::log::info("ACME account deactivated id=" + acc->id);
    }

    set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
    res.set_header("Location", url_for(s, "/account/" + acc->id));
    res.status = 200;
    json body = {
        {"status",  acc->status == 1 ? "deactivated" : "valid"},
        {"contact", acc->contacts_json.empty() ? json::array() : json::parse(acc->contacts_json)},
        {"orders",  url_for(s, "/account/" + acc->id + "/orders")},
    };
    res.set_content(body.dump(), "application/json");
}

// ---- account orders list (RFC 8555 §7.1.2.1) ----
// POST-as-GET to the account's `orders` URL returns { "orders": [ orderURL, ... ] }.
// The request must be signed by the account itself; a mismatch is unauthorized.
void handle_account_orders(ServerState& s, const httplib::Request& req,
                           httplib::Response& res, const std::string& account_id) {
    auto post = parse_acme_post(s.cfg, *s.adb,  req, res,
                                url_for(s, "/account/" + account_id + "/orders"), s.certs_db);
    if (!post) return;
    if (!post->account || post->account->id != account_id) {
        send_problem(*s.adb, req, res, 401, "unauthorized",
                     "orders list must be requested by the owning account");
        return;
    }
    json arr = json::array();
    for (const auto& o : s.adb->orders_for_account(account_id)) {
        // RFC 8555 §7.1.2.1: the list contains every order the server has not
        // deleted; the pending/valid/etc. status is fetched via each order URL.
        arr.push_back(order_url(s, o.id));
    }
    set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
    res.status = 200;
    res.set_content(json{{"orders", arr}}.dump(), "application/json");
}

// ---- key roll-over (RFC 8555 §7.3.5) ----
// Outer JWS is kid-form, signed by the OLD account key (validated by
// parse_acme_post). Its payload is an inner JWS, jwk-form, signed by the NEW
// key, whose payload is { "account": <account URL>, "oldKey": <old JWK> }.
void handle_key_change(ServerState& s, const httplib::Request& req,
                       httplib::Response& res) {
    const std::string url = url_for(s, "/key-change");
    auto post = parse_acme_post(s.cfg, *s.adb, req, res, url, s.certs_db);
    if (!post) return;
    if (!post->account) {  // must be kid-form (signed by the existing account key)
        send_problem(*s.adb, req, res, 400, "malformed", "key-change must be signed by the account (kid) key");
        return;
    }
    pki::AcmeAccount acc = *post->account;

    // Parse + verify the inner JWS (signed by the new key). It carries no nonce,
    // so we can't reuse pki::jws::parse — build the struct and verify directly.
    pki::jws::ParsedJws in;
    json inner_payload;
    try {
        json inner = json::parse(std::string(post->parsed.payload_bytes.begin(),
                                              post->parsed.payload_bytes.end()));
        in.protected_b64 = inner.at("protected").get<std::string>();
        in.payload_b64   = inner.at("payload").get<std::string>();
        in.signature_b64 = inner.at("signature").get<std::string>();
        auto pb = pki::jws::base64url_decode(in.protected_b64);
        in.protected_header = json::parse(std::string(pb.begin(), pb.end()));
        in.alg = in.protected_header.value("alg", "");
        in.url = in.protected_header.value("url", "");
        if (!in.protected_header.contains("jwk"))
            throw pki::Error(1, "inner JWS must carry jwk (the new key)");
        in.jwk = in.protected_header.at("jwk");
        in.payload_bytes   = pki::jws::base64url_decode(in.payload_b64);
        in.signature_bytes = pki::jws::base64url_decode(in.signature_b64);
        inner_payload = json::parse(std::string(in.payload_bytes.begin(), in.payload_bytes.end()));
    } catch (const std::exception& e) {
        send_problem(*s.adb, req, res, 400, "malformed", std::string("inner JWS: ") + e.what());
        return;
    }
    if (in.url != url) {
        send_problem(*s.adb, req, res, 400, "malformed", "inner JWS url does not match key-change");
        return;
    }
    try { pki::jws::verify(in, *in.jwk); }
    catch (const pki::Error& e) {
        send_problem(*s.adb, req, res, 401, "unauthorized", std::string("inner signature: ") + e.what());
        return;
    }

    // Bindings: the inner payload must name this account and carry its old key.
    const std::string acct_url = url_for(s, "/account/" + acc.id);
    if (inner_payload.value("account", "") != acct_url) {
        send_problem(*s.adb, req, res, 400, "malformed", "inner 'account' does not match the signer");
        return;
    }
    json old_key;
    try { old_key = json::parse(acc.jwk_json); } catch (...) {}
    if (!inner_payload.contains("oldKey") || inner_payload["oldKey"] != old_key) {
        send_problem(*s.adb, req, res, 400, "malformed", "inner 'oldKey' does not match the account key");
        return;
    }

    // The new key must not already belong to a different account.
    std::string new_hash;
    try { new_hash = pki::jws::thumbprint(*in.jwk); }
    catch (const pki::Error& e) { send_problem(*s.adb, req, res, 400, "badPublicKey", e.what()); return; }
    auto other = s.adb->get_account_by_jwk_hash(new_hash);
    if (other && other->id != acc.id) {
        set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
        res.set_header("Location", url_for(s, "/account/" + other->id));
        res.status = 409;
        res.set_content(json{{"type","urn:ietf:params:acme:error:malformed"},
                             {"detail","new key is already in use by another account"}}.dump(),
                        "application/problem+json");
        return;
    }

    acc.jwk_json = in.jwk->dump();
    acc.jwk_hash = new_hash;
    s.adb->save_account(acc);
    pki::log::info("ACME key-change for account id=" + acc.id);

    set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
    res.set_header("Location", acct_url);
    res.status = 200;
    json body = {
        {"status",  acc.status == 1 ? "deactivated" : "valid"},
        {"contact", acc.contacts_json.empty() ? json::array() : json::parse(acc.contacts_json)},
        {"orders",  url_for(s, "/account/" + acc.id + "/orders")},
    };
    res.set_content(body.dump(), "application/json");
}

// ---- GET-as-POST handlers for /order, /authz, /cert ----
void handle_order_get(ServerState& s, const httplib::Request& req,
                      httplib::Response& res, const std::string& order_id) {
    auto post = parse_acme_post(s.cfg, *s.adb, req, res, order_url(s, order_id), s.certs_db);
    if (!post) return;
    auto o = s.adb->get_order(order_id);
    if (!o) { send_problem(*s.adb, req, res,404, "malformed", "no such order"); return; }
    // ⚠️ THE SIGNER MUST OWN THE ORDER. Same defect the account and authz handlers carried:
    // the object came from the URL and was returned without being compared to the
    // authenticated account. An order body names its identifiers, its authorization URLs and
    // — once issued — its certificate URL, so this handed one account another's pending work
    // and the URL to fetch the result.
    if (!post->account || o->account_id != post->account->id) {
        send_problem(*s.adb, req, res, 401, "unauthorized",
                     "an order may only be read by the account that created it");
        return;
    }
    set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
    // A "processing" order is being worked on asynchronously (RFC 8555 §7.1.3);
    // tell the client when to poll again.
    if (o->status == 2) res.set_header("Retry-After", std::to_string(kRetryAfterSec));
    res.status = 200;
    res.set_content(order_to_json(s, *o).dump(), "application/json");
}

void handle_authz_post(ServerState& s, const httplib::Request& req,
                       httplib::Response& res, const std::string& authz_id) {
    auto post = parse_acme_post(s.cfg, *s.adb, req, res, authz_url(s, authz_id), s.certs_db);
    if (!post) return;
    auto a = s.adb->get_authz(authz_id);
    if (!a) { send_problem(*s.adb, req, res,404, "malformed", "no such authz"); return; }
    // ⚠️ AND THE SIGNER MUST OWN THIS AUTHORIZATION. Same defect as handle_account above:
    // the object came from the URL and was acted on without ever being compared to the
    // authenticated account. Deactivating another account's authz destroys work it has
    // already done (RFC 8555 §7.5.2 — a deactivated authz cannot be reused and the order
    // depending on it can no longer be finalised), and the response body hands back that
    // authz's challenge tokens. AcmeAuthz::account_id is the owning account and is set for
    // every authz, including pre-authorizations, so there is nothing to derive.
    if (!post->account || a->account_id != post->account->id) {
        send_problem(*s.adb, req, res, 401, "unauthorized",
                     "an authorization may only be acted on by the account that owns it");
        return;
    }

    // Client may deactivate by POSTing {"status":"deactivated"}.
    //
    // Same split as the account handler above, for the same reason: the try exists so a
    // malformed payload does not 500, and it used to swallow save_authz() too — leaving a
    // 200 that rendered the in-memory object and told the client an authorization was
    // deactivated when the row still said otherwise.
    bool want_deactivate = false;
    if (!post->parsed.payload_bytes.empty()) {
        try {
            auto p = json::parse(std::string(post->parsed.payload_bytes.begin(),
                                              post->parsed.payload_bytes.end()));
            want_deactivate = (p.value("status", "") == "deactivated");
        } catch (...) {}
    }
    if (want_deactivate) {
        const int prev = a->status;
        a->status = -2;
        try {
            s.adb->save_authz(*a);
        } catch (const std::exception& e) {
            a->status = prev;
            pki::log::err(std::string("ACME: could not deactivate authz ") + a->id
                          + ": " + e.what());
            send_problem(*s.adb, req, res, 500, "serverInternal",
                         "the deactivation could not be recorded");
            return;
        }
    }

    set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
    if (a->status == 0) res.set_header("Retry-After", std::to_string(kRetryAfterSec));
    res.status = 200;
    res.set_content(authz_to_json(s, *a).dump(), "application/json");
}

// ---- HTTP-01 / DNS-01 verifier (synchronous; called from a detached thread) ----
namespace verifier {

// Minimal DNS over UDP — just enough to resolve a single TXT record. Raw rather
// than libresolv so it's portable (musl/Alpine) and can target a specific
// resolver (host[:port]) for testing.
void dns_encode_name(std::string& out, const std::string& name) {
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        size_t len = dot - start;
        if (len == 0 || len > 63) break;
        out.push_back(static_cast<char>(len));
        out.append(name, start, len);
        start = dot + 1;
    }
    out.push_back('\0');
}

// Advance `pos` past a (possibly compressed) name. Returns false on malformed.
bool dns_skip_name(const unsigned char* msg, size_t len, size_t& pos) {
    while (pos < len) {
        unsigned char b = msg[pos];
        if ((b & 0xC0) == 0xC0) { pos += 2; return pos <= len; } // pointer ends the name
        if (b == 0) { pos += 1; return true; }
        pos += 1 + b;
    }
    return false;
}

// ── the resolver socket, shared by query_txt() and query_caa() ──────────────────
//
// ⚠️ ACME_DNS_RESOLVER USED TO BE AN IPv4 LITERAL AND NOTHING ELSE. Both queries ran
// inet_pton(AF_INET) over the configured string, so a hostname, an IPv6 literal, and
// an IPv6 `nameserver` line in /etc/resolv.conf all failed the same silent way: the
// query returned an EMPTY vector, which every caller reads as "that name has no
// records". A resolver we could not even parse was indistinguishable from a name that
// genuinely has nothing at it.
//
// That surfaced during the demo work. On Docker Desktop, `host-gateway` — the only address a
// container can use to reach the host — is IPv6 (measured: fdc4:f303:9324::254), and
// the compose bridge gateway the demo used instead is NOT the host at all there: the
// datagram never arrives. So the dns-01 authz sat pending until the order timed out,
// with nothing anywhere naming the cause.
//
// getaddrinfo() takes all three forms, which is what an operator would naturally write
// in the config key. AF_UNSPEC because either family is a legitimate answer.
//
// ⚠️ AND IT ASKS EVERY ADDRESS, not just the first. connect() on a UDP socket performs
// no handshake — it only fixes the default peer — so it succeeds against an address
// where nothing is listening, and "did connect() work" is NOT a test of reachability.
// A name routinely resolves to several addresses (`localhost` gives ::1 before
// 127.0.0.1 on most hosts), so stopping at the first would report "this name has no
// records" whenever the resolver answers on the other family. The only honest test is
// to send the query and see whether an answer comes back.
static ssize_t dns_exchange(const std::string& resolver_cfg, const std::string& q,
                            unsigned char* buf, size_t buflen, int timeout_sec = 3) {
    std::string host = resolver_cfg, port = "53";
    if (host.empty()) {
        std::ifstream rc("/etc/resolv.conf"); std::string line;
        while (std::getline(rc, line)) {
            if (line.rfind("nameserver", 0) == 0) {
                std::istringstream is(line); std::string k, v; is >> k >> v;
                if (!v.empty()) { host = v; break; }
            }
        }
        if (host.empty()) host = "127.0.0.1";
    } else if (host.front() == '[') {
        // [2001:db8::1]:5353 — the only unambiguous way to give a v6 literal a port.
        auto rb = host.find(']');
        if (rb == std::string::npos) return -1;   // unterminated [ — not an address
        if (rb + 1 < host.size() && host[rb + 1] == ':') port = host.substr(rb + 2);
        host = host.substr(1, rb - 1);
    } else if (auto c = host.find(':');
               c != std::string::npos && host.find(':', c + 1) == std::string::npos) {
        // ⚠️ EXACTLY ONE COLON means host:port. TWO OR MORE means a bare IPv6 literal
        // carrying no port — splitting on the first colon there would turn
        // fdc4:f303:9324::254 into the host "fdc4" and a nonsense port.
        port = host.substr(c + 1); host.resize(c);
    }
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP; hints.ai_flags = AI_NUMERICSERV;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) return -1;
    ssize_t n = -1;
    for (addrinfo* a = res; a && n < 12; a = a->ai_next) {
        int fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv{timeout_sec, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0 &&
            send(fd, q.data(), q.size(), 0) >= 0) {
            n = recv(fd, buf, buflen, 0);
        }
        close(fd);
    }
    freeaddrinfo(res);
    return n;
}

// ── a datagram is only an ANSWER if it answers the question we asked ────────────
//
// ⚠️ THE QUERY ID WAS GENERATED AND THEN NEVER LOOKED AT. Both queries below draw a
// random 16-bit ID with RAND_bytes, write it into the header, and then parse whatever
// datagram comes back without ever comparing it. That is the whole defence against an
// off-path forgery, discarded at exactly the point it was meant to be spent. recv() on a
// connected UDP socket already drops datagrams from any source but the resolver, so an
// attacker has to spoof the resolver's address either way — but with the ID unchecked the
// FIRST spoofed datagram to arrive wins, rather than having to match a value it cannot
// see. That is the difference between guessing a 16-bit ephemeral port and guessing the
// port AND the ID.
//
// What it buys an attacker here is domain validation itself. dns-01 reads the TXT at
// _acme-challenge.<domain> and compares it to the key authorization: a forged reply
// carrying that string validates an authorization for a domain the client does not
// control, and the order then issues. CAA is the same shape pointed the other way — a
// forged answer with no records removes the issuer restriction entirely.
//
// The question section is compared too. We do not do 0x20 encoding, so a resolver
// normally echoes it byte for byte; the case-insensitive compare is there because a
// resolver is permitted to change the case, and an answer ABOUT A DIFFERENT NAME is not
// an answer to this one. Case-folding cannot make two different bytes compare equal here:
// the only non-name bytes are the length octets and the QTYPE/QCLASS trailer, and
// dns_encode_name caps a label at 63 (0x3F), below the 0x41–0x5A range folding touches.
static bool dns_reply_is_ours(const unsigned char* buf, size_t n,
                              const std::string& q, const unsigned char id[2]) {
    if (n < 12 || q.size() < 12) return false;
    if (buf[0] != id[0] || buf[1] != id[1]) return false;    // a different transaction
    if ((buf[2] & 0x80) == 0) return false;                  // QR=0: a query, not a reply
    if (((buf[4] << 8) | buf[5]) != 1) return false;         // exactly the one question
    const size_t qlen = q.size() - 12;
    if (n < 12 + qlen) return false;
    for (size_t i = 0; i < qlen; ++i) {
        const unsigned char a = static_cast<unsigned char>(q[12 + i]);
        const unsigned char b = buf[12 + i];
        if (std::tolower(a) != std::tolower(b)) return false;
    }
    return true;
}

// Return the TXT strings at `name`, querying `resolver_cfg` (host[:port], port
// defaults to 53; empty → first nameserver in /etc/resolv.conf).
std::vector<std::string> query_txt(const std::string& resolver_cfg, const std::string& name) {
    std::vector<std::string> out;

    std::string q;
    // The query ID is what matches a reply to this question; an uninitialised one would
    // accept whichever datagram happened to arrive. Returning empty is a failed lookup,
    // which every caller already handles — no new throw path through the resolver.
    unsigned char id[2];
    if (RAND_bytes(id, 2) != 1) {
        pki::log::err("dns: RAND_bytes failed — cannot build a query ID, treating as no answer");
        return out;
    }
    const unsigned char hdr[12] = { id[0], id[1], 0x01, 0x00, 0,1, 0,0, 0,0, 0,0 };
    q.append(reinterpret_cast<const char*>(hdr), 12);
    dns_encode_name(q, name);
    const unsigned char tail[4] = { 0,16, 0,1 };  // QTYPE=TXT(16), QCLASS=IN(1)
    q.append(reinterpret_cast<const char*>(tail), 4);

    unsigned char buf[2048];
    ssize_t n = dns_exchange(resolver_cfg, q, buf, sizeof buf);
    if (n < 12) return out;
    if (!dns_reply_is_ours(buf, static_cast<size_t>(n), q, id)) {
        pki::log::info("dns: discarding a TXT datagram that does not answer our question "
                       "for " + name + " — treating it as no answer");
        return out;
    }
    size_t len = static_cast<size_t>(n), pos = 12;
    int qd = (buf[4] << 8) | buf[5];
    int an = (buf[6] << 8) | buf[7];
    for (int i = 0; i < qd; ++i) { if (!dns_skip_name(buf, len, pos)) return out; pos += 4; }
    for (int i = 0; i < an; ++i) {
        if (!dns_skip_name(buf, len, pos)) return out;
        if (pos + 10 > len) return out;
        int type  = (buf[pos] << 8) | buf[pos + 1];
        int rdlen = (buf[pos + 8] << 8) | buf[pos + 9];
        pos += 10;
        if (pos + rdlen > len) return out;
        if (type == 16) {  // TXT: one or more <len><bytes> character-strings
            size_t rp = pos; std::string txt;
            while (rp < pos + rdlen) {
                int slen = buf[rp++];
                if (rp + slen > pos + rdlen) break;
                txt.append(reinterpret_cast<char*>(buf) + rp, slen);
                rp += slen;
            }
            out.push_back(txt);
        }
        pos += rdlen;
    }
    return out;
}

// One CAA resource record (RFC 8659 §4.1): a critical flag, a property tag
// ("issue"/"issuewild"/"iodef"/…), and its value.
struct CaaRecord { bool critical{false}; std::string tag, value; };

// The three things a CAA lookup can mean, which used to be ONE empty vector.
//
// ⚠️ "NO RECORDS" AND "COULD NOT ASK" ARE OPPOSITE ANSWERS HERE. Empty means the node
// published no CAA RRset, and the caller climbs to the parent — with none anywhere,
// issuance is unrestricted. So collapsing a failure into empty does not merely lose
// information: it switches the whole policy off, and it does so exactly when the network
// is unhealthy, which is when an attacker would most like it off. RFC 8659 §3 and
// CA/Browser Forum BR 3.2.2.8 both say a failed lookup MUST refuse.
enum class CaaLookup { kRecords, kEmpty, kFailed };

// Query CAA (type 257) at `name`, filling `out` with the records present at that exact
// node. Same hand-rolled UDP resolver as query_txt().
//
// NXDOMAIN is the one non-zero RCODE that is a real answer — the name does not exist, so
// it has no CAA RRset and the climb continues. SERVFAIL, REFUSED, FORMERR and NOTIMP are
// the resolver saying it could not answer, and a truncated or unparsable reply is no
// answer either. All of those are kFailed.
CaaLookup query_caa(const std::string& resolver_cfg, const std::string& name,
                    std::vector<CaaRecord>& out) {
    out.clear();

    std::string q;
    // kFailed, not kEmpty. "The resolver could not answer" is what a broken RNG is, and
    // this distinction is load-bearing: kEmpty means the name genuinely has no CAA RRset
    // and issuance may continue, while kFailed refuses. Returning kEmpty here would make
    // an RNG failure look like permission to issue.
    unsigned char id[2];
    if (RAND_bytes(id, 2) != 1) {
        pki::log::err("dns: RAND_bytes failed — cannot build a CAA query ID, treating the "
                      "lookup as FAILED (not as 'no records')");
        return CaaLookup::kFailed;
    }
    const unsigned char hdr[12] = { id[0], id[1], 0x01, 0x00, 0,1, 0,0, 0,0, 0,0 };
    q.append(reinterpret_cast<const char*>(hdr), 12);
    dns_encode_name(q, name);
    const unsigned char tail[4] = { 1,1, 0,1 };  // QTYPE=CAA(257), QCLASS=IN(1)
    q.append(reinterpret_cast<const char*>(tail), 4);

    unsigned char buf[2048];
    ssize_t n = dns_exchange(resolver_cfg, q, buf, sizeof buf);
    // A short read covers every transport failure dns_exchange folds into -1: the resolver
    // string would not resolve, no route, send() failed, or the 3s receive timeout expired.
    if (n < 12) return CaaLookup::kFailed;
    if (!dns_reply_is_ours(buf, static_cast<size_t>(n), q, id)) {
        pki::log::err("dns: discarding a CAA datagram that does not answer our question for " +
                      name + " — treating the lookup as FAILED, not as 'no records'");
        return CaaLookup::kFailed;
    }
    size_t len = static_cast<size_t>(n), pos = 12;
    const int rcode = buf[3] & 0x0f;
    const bool truncated = (buf[2] & 0x02) != 0;
    if (rcode == 3) return CaaLookup::kEmpty;          // NXDOMAIN: a real "nothing here"
    if (rcode != 0) return CaaLookup::kFailed;         // SERVFAIL / REFUSED / FORMERR / …
    // TC=1 means the answer did not fit in the datagram, so what we hold is a PREFIX of
    // the RRset. Reading it would be reading a partial policy — the missing record could
    // be the one that authorizes us, or the critical one that forbids everyone.
    if (truncated) return CaaLookup::kFailed;
    int qd = (buf[4] << 8) | buf[5];
    int an = (buf[6] << 8) | buf[7];
    for (int i = 0; i < qd; ++i) {
        if (!dns_skip_name(buf, len, pos)) return CaaLookup::kFailed;
        pos += 4;
    }
    for (int i = 0; i < an; ++i) {
        if (!dns_skip_name(buf, len, pos)) return CaaLookup::kFailed;
        if (pos + 10 > len) return CaaLookup::kFailed;
        int type  = (buf[pos] << 8) | buf[pos + 1];
        int rdlen = (buf[pos + 8] << 8) | buf[pos + 9];
        pos += 10;
        if (pos + rdlen > len) return CaaLookup::kFailed;
        if (type == 257 && rdlen >= 2) {          // CAA RDATA: flags, taglen, tag, value
            size_t rp = pos;
            unsigned char flags = buf[rp++];
            unsigned int taglen = buf[rp++];
            if (rp + taglen <= pos + static_cast<size_t>(rdlen)) {
                CaaRecord r;
                r.critical = (flags & 0x80) != 0;
                r.tag.assign(reinterpret_cast<char*>(buf) + rp, taglen);
                rp += taglen;
                r.value.assign(reinterpret_cast<char*>(buf) + rp, (pos + rdlen) - rp);
                for (auto& ch : r.tag) ch = static_cast<char>(std::tolower((unsigned char)ch));
                out.push_back(std::move(r));
            }
        }
        pos += rdlen;
    }
    return out.empty() ? CaaLookup::kEmpty : CaaLookup::kRecords;
}

// The issuer-domain-name of a CAA issue/issuewild value = the text before the
// first ';' (parameters), trimmed and lowercased. Empty → authorizes no CA.
std::string caa_issuer_domain(const std::string& value) {
    std::string v = value.substr(0, value.find(';'));
    size_t a = v.find_first_not_of(" \t"); size_t b = v.find_last_not_of(" \t");
    if (a == std::string::npos) return {};
    v = v.substr(a, b - a + 1);
    for (auto& c : v) c = static_cast<char>(std::tolower((unsigned char)c));
    return v;
}

// RFC 8555 §8.1.1 + RFC 8659 §3/§5.3: may `identity` issue for `identifier`?
// Climb from the FQDN to its parents until a CAA RRset is found (the "relevant"
// RRset); with none anywhere, issuance is unrestricted. A found RRset authorizes
// us iff an applicable issue/issuewild property names our identity. A critical
// unrecognized property forbids issuance.
//
// `why` is filled on every refusal and is the difference between "the domain says
// no" and "we could not find out". A lookup that FAILS refuses here — it does not climb.
bool caa_allows(const std::string& resolver, const std::string& identifier,
                const std::string& identity, std::string& why) {
    why.clear();
    bool is_wild = identifier.rfind("*.", 0) == 0;
    std::string name = is_wild ? identifier.substr(2) : identifier;
    std::string want = identity;
    for (auto& c : want) c = static_cast<char>(std::tolower((unsigned char)c));

    for (; !name.empty(); ) {
        std::vector<CaaRecord> recs;
        CaaLookup st = query_caa(resolver, name, recs);
        // RFC 8659 §3 permits one retry before giving up; a single lost UDP datagram is
        // not a policy statement. The retry is here rather than inside query_caa so a
        // clean NXDOMAIN is never asked twice.
        if (st == CaaLookup::kFailed) st = query_caa(resolver, name, recs);
        if (st == CaaLookup::kFailed) {
            // ⚠️ REFUSE, AND SAY SO. This branch used to be indistinguishable from an
            // empty answer, so a dead or slow resolver turned CAA off and issuance went
            // ahead with nothing in the log to show the check had not run.
            why = "CAA lookup for " + name + " failed (resolver " +
                  (resolver.empty() ? std::string("/etc/resolv.conf") : resolver) +
                  ") — refusing rather than treating it as no policy";
            pki::log::err("CAA: " + why);
            return false;
        }
        if (st == CaaLookup::kRecords) {
            bool have_issue = false, allow_issue = false;
            bool have_issuewild = false, allow_issuewild = false;
            for (const auto& r : recs) {
                if (r.tag == "issue" || r.tag == "issuewild") {
                    bool ok = !caa_issuer_domain(r.value).empty() &&
                              caa_issuer_domain(r.value) == want;
                    if (r.tag == "issue")     { have_issue = true;     allow_issue     = allow_issue     || ok; }
                    else                      { have_issuewild = true; allow_issuewild = allow_issuewild || ok; }
                } else if (r.tag != "iodef" && r.critical) {
                    // RFC 8659 §4.1: critical + unrecognized ⇒ refuse
                    why = "CAA at " + name + " carries a critical property we do not "
                          "understand (" + r.tag + ")";
                    return false;
                }
            }
            // §5.3: a wildcard request uses issuewild when present, else issue;
            // a non-wildcard request uses issue only. No applicable issue property
            // (only iodef/other) ⇒ issuance is not restricted.
            if (is_wild && have_issuewild) {
                if (!allow_issuewild) why = "CAA issuewild at " + name + " does not name " + want;
                return allow_issuewild;
            }
            if (have_issue) {
                if (!allow_issue) why = "CAA issue at " + name + " does not name " + want;
                return allow_issue;
            }
            return true;
        }
        size_t dot = name.find('.');
        if (dot == std::string::npos) break;   // reached the TLD with no CAA
        name = name.substr(dot + 1);
    }
    return true;   // no CAA RRset in the tree ⇒ any CA may issue
}

// RFC 8555 §8.4: TXT at _acme-challenge.<domain> must equal
// base64url(SHA256(key authorization)).
//
// The "*." strip that used to live here is gone: it was compensating, at validation time,
// for an authz identifier that should never have carried the prefix (see make_authz). The
// authz identifier is now the base domain for every challenge type, so all three
// validators agree on the name without one of them special-casing it.
bool fetch_dns01(const std::string& resolver, const std::string& identifier,
                 const std::string& key_auth) {
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(key_auth.data()), key_auth.size(), h);
    std::string expected = pki::jws::base64url_encode(h, sizeof h);
    const std::string qname = "_acme-challenge." + identifier;
    const auto txts = query_txt(resolver, qname);
    // ⚠️ SAY WHICH RESOLVER WAS ASKED, INCLUDING WHEN IT WAS NOBODY IN PARTICULAR. A failed
    // dns-01 reports "TXT record missing or mismatched" to the client and wrote nothing
    // anywhere, so the three cases an operator has to tell apart — the record is absent, the
    // record is there but differs, and we asked the WRONG nameserver — all looked identical.
    // The empty case matters most: with ACME_DNS_RESOLVER unset, dns_exchange() falls back to
    // /etc/resolv.conf, so the query goes to the system resolver and a record published in a
    // purpose-started nameserver is invisible while everything appears configured.
    //
    // The digest is safe to log at this level: it is published in public DNS by design. Only
    // counts are logged, which is enough to separate "no answer" from "no match".
    pki::log::info("dns-01: asked " +
                   (resolver.empty() ? std::string("the system resolver — ACME_DNS_RESOLVER "
                                                   "is not set")
                                     : resolver) +
                   " for " + qname + " — " + std::to_string(txts.size()) + " TXT record(s)");
    for (const auto& txt : txts)
        if (txt == expected) return true;
    if (!txts.empty())
        pki::log::info("dns-01: " + std::to_string(txts.size()) + " record(s) came back for " +
                       qname + " and none matched the expected value");
    return false;
}

// RFC 8737 TLS-ALPN-01. Connect to identifier:port with ALPN "acme-tls/1" and
// SNI = identifier; the peer must present a (self-signed) certificate carrying a
// critical id-pe-acmeIdentifier extension (1.3.6.1.5.5.7.1.31) whose value is an
// OCTET STRING holding SHA-256(key authorization). We don't verify the chain
// (the validation cert is throwaway) — the extension is the binding.
// ⚠️ ONE FALSE, SIX CAUSES — SAY WHICH. `matched` stays false when the host does not
// resolve, the TCP connect fails, the TLS handshake fails, the peer negotiates something
// other than acme-tls/1, it presents no certificate, the certificate carries no
// acmeIdentifier extension, or the digest inside that extension differs. Those need
// completely different fixes — "something else is listening on this port" and "your
// responder computed the wrong key authorization" are not the same problem — and the
// caller used to render all seven as "validation certificate missing or mismatched".
// The reason lands in the challenge's `error` field, so the client sees it too.
bool fetch_tlsalpn01(const std::string& identifier, int port,
                     const std::string& key_auth, std::string* why) {
    auto fail = [&](const char* reason) { if (why) *why = reason; return false; };
    unsigned char want[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(key_auth.data()), key_auth.size(), want);

    // Resolve + connect (TCP).
    struct addrinfo hints{}, *ai = nullptr;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(identifier.c_str(), std::to_string(port).c_str(), &hints, &ai) != 0 || !ai)
        return fail("the identifier does not resolve");
    int fd = -1;
    for (auto* p = ai; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv{5, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(ai);
    if (fd < 0) return fail("nothing accepted a TLS connection on the tls-alpn-01 port");

    bool matched = false;
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx) {
        // ALPN "acme-tls/1" (1-byte length prefix = 10 + the 10-byte token).
        static const unsigned char alpn[] = { 10, 'a','c','m','e','-','t','l','s','/','1' };
        SSL_CTX_set_alpn_protos(ctx, alpn, sizeof alpn);
        SSL* ssl = SSL_new(ctx);
        if (ssl) {
            SSL_set_fd(ssl, fd);
            SSL_set_tlsext_host_name(ssl, identifier.c_str());
            if (SSL_connect(ssl) != 1) {
                if (why) *why = "the TLS handshake failed";
            } else {
                const unsigned char* sel = nullptr; unsigned int sellen = 0;
                SSL_get0_alpn_selected(ssl, &sel, &sellen);
                if (!(sel && sellen == 10 && std::memcmp(sel, "acme-tls/1", 10) == 0)) {
                    // The commonest real-world cause is an ordinary web server on this
                    // port: it completes the handshake happily and simply does not speak
                    // this ALPN, which is indistinguishable from a bad responder unless
                    // we say so.
                    if (why) *why = sellen
                        ? "the peer negotiated ALPN '" + std::string((const char*)sel, sellen) +
                          "' instead of acme-tls/1 — is another server listening on this port?"
                        : "the peer negotiated no ALPN at all — is another server listening "
                          "on this port?";
                } else {
                    X509* peer = SSL_get1_peer_certificate(ssl);
                    if (!peer) { if (why) *why = "the peer presented no certificate"; }
                    else {
                        std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>
                            oid(OBJ_txt2obj("1.3.6.1.5.5.7.1.31", 1), &ASN1_OBJECT_free);
                        int idx = oid ? X509_get_ext_by_OBJ(peer, oid.get(), -1) : -1;
                        if (idx < 0 && why)
                            *why = "the certificate carries no acmeIdentifier extension "
                                   "(1.3.6.1.5.5.7.1.31)";
                        if (idx >= 0) {
                            X509_EXTENSION* ext = X509_get_ext(peer, idx);
                            const ASN1_OCTET_STRING* raw = ext ? X509_EXTENSION_get_data(ext) : nullptr;
                            if (raw) {
                                // extnValue is DER of OCTET STRING { 32-byte digest }.
                                const unsigned char* dp = ASN1_STRING_get0_data(raw);
                                ASN1_OCTET_STRING* inner =
                                    d2i_ASN1_OCTET_STRING(nullptr, &dp, ASN1_STRING_length(raw));
                                if (inner && ASN1_STRING_length(inner) == SHA256_DIGEST_LENGTH &&
                                    std::memcmp(ASN1_STRING_get0_data(inner), want, SHA256_DIGEST_LENGTH) == 0)
                                    matched = true;
                                else if (why)
                                    *why = "the acmeIdentifier digest does not match this "
                                           "challenge's key authorization";
                                if (inner) ASN1_OCTET_STRING_free(inner);
                            }
                        }
                        X509_free(peer);
                    }
                }
            }
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        SSL_CTX_free(ctx);
    }
    close(fd);
    return matched;
}

// ⚠️ SAY WHICH FAILURE IT WAS, for the same reason fetch_tlsalpn01 does. Every cause here used
// to render as "http-01 challenge response missing or mismatched", which names the one thing
// that is usually NOT wrong. Measured: against a deployment whose resolver did not know the
// challenge hostname at all, the client was told the response mismatched — and the name not
// resolving was invisible, so the search went to the load balancer, to what might be listening
// on :80, and to the client's own responder before reaching the server that already knew. The
// reason lands in the challenge's `error` field, so the client sees it too.
bool fetch_http01(const std::string& host, const std::string& token,
                  const std::string& expected_key_auth, std::string* why) {
    auto fail = [&](const char* reason) { if (why) *why = reason; return false; };
    // Resolved explicitly rather than left to the HTTP client, because "cannot resolve" and
    // "connected and answered wrongly" are different operator problems and httplib reports
    // both as an empty result.
    {
        struct addrinfo hints{}, *ai = nullptr;
        hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host.c_str(), "80", &hints, &ai) != 0 || !ai)
            return fail("the identifier does not resolve");
        freeaddrinfo(ai);
    }
    httplib::Client cli(host, 80);
    cli.set_connection_timeout(5);
    cli.set_read_timeout(10);
    cli.set_follow_location(true);
    auto r = cli.Get(std::string("/.well-known/acme-challenge/") + token);
    if (!r) return fail("nothing answered on port 80 at the identifier");
    if (r->status != 200) {
        if (why) *why = "the challenge URL answered HTTP " + std::to_string(r->status) +
                        ", not 200";
        return false;
    }
    // RFC 8555: response body may have trailing whitespace; compare prefix.
    auto body = r->body;
    while (!body.empty() && (body.back() == '\n' || body.back() == '\r'
                              || body.back() == ' ' || body.back() == '\t'))
        body.pop_back();
    if (body != expected_key_auth)
        return fail("the challenge response did not match the key authorization");
    return true;
}

// challenge_id is taken BY VALUE deliberately: run() is launched as a detached
// thread (std::thread(verifier::run, &s, c->id).detach()) that outlives the
// caller, so a const& would dangle on the caller's freed string.
// cppcheck-suppress passedByValueCallback
void run(ServerState* s, std::string challenge_id) {
    try {
        auto c = s->adb->get_challenge(challenge_id);
        if (!c) return;
        auto a = s->adb->get_authz(c->authz_id);
        if (!a) return;
        // The authz belongs to an order, or — for a pre-authorization (§7.4.1) —
        // to the synthetic "preauth:<account_id>" key. Resolve the account either way.
        std::optional<pki::AcmeOrder> o;
        if (!a->order_id.empty()) o = s->adb->get_order(a->order_id);
        std::optional<pki::AcmeAccount> acc;
        if (o) acc = s->adb->get_account_by_id(o->account_id);
        else   acc = s->adb->get_account_by_id(a->account_id);  // pre-authorization
        if (!acc) return;

        json ident = json::parse(a->identifier_json);
        json jwk   = json::parse(acc->jwk_json);
        std::string ka = key_authorization(c->token, jwk);

        // ⚠️ THE POLICY IS ENFORCED HERE, NOT ONLY BY WHAT make_authz OFFERS. Withholding a
        // challenge from the authorization object decides what a WELL-BEHAVED client sees;
        // it is not a control. A challenge row that predates this rule, or one reached by
        // any path that creates challenges without going through make_authz, would still
        // validate — and the whole point is that a wildcard must not become valid on the
        // strength of a single host answering. So the refusal lives at the one place that
        // can mark an authorization valid.
        if (a->wildcard && c->type != "dns-01") {
            c->status = -1;  // invalid
            c->error = "a wildcard authorization can only be validated by dns-01";
            s->adb->save_challenge(*c);
            return;
        }

        bool ok = false;
        if (c->type == "http-01") {
            std::string why;
            ok = fetch_http01(ident.value("value", ""), c->token, ka, &why);
            if (!ok) c->error = "http-01 validation failed: " +
                                (why.empty() ? std::string("challenge response missing or "
                                                           "mismatched") : why);
        } else if (c->type == "dns-01") {
            ok = fetch_dns01(dns_resolver_now(*s), ident.value("value", ""), ka);
            if (!ok) c->error = "dns-01 TXT record missing or mismatched";
        } else if (c->type == "tls-alpn-01") {
            std::string why;
            ok = fetch_tlsalpn01(ident.value("value", ""), s->cfg.acme_tls_alpn_port, ka, &why);
            if (!ok) c->error = "tls-alpn-01 validation failed: " +
                                (why.empty() ? std::string("validation certificate missing "
                                                           "or mismatched") : why);
        } else {
            c->error = "unsupported challenge type: " + c->type;
        }

        if (ok) {
            c->status = 2; // valid
            c->validated = now_unix();
            c->error.clear();
            s->adb->save_challenge(*c);

            // Drop sibling challenges; only the verified one survives.
            for (auto& sib : s->adb->challenges_for_authz(a->id))
                if (sib.id != c->id) s->adb->delete_challenge(sib.id);

            a->status = 1;  // valid
            s->adb->save_authz(*a);

            // If this authz backs a real order and all its authz are valid, mark
            // the order ready. Pre-authorizations (no order) just become valid.
            if (o) {
                bool all = true;
                for (auto& other : s->adb->authz_for_order(o->id))
                    if (other.status != 1) { all = false; break; }
                if (all) { o->status = 1; s->adb->save_order(*o); }
            }
        } else {
            c->status = -1; // invalid
            if (c->error.empty()) c->error = "challenge validation failed";
            s->adb->save_challenge(*c);
        }
    } catch (const std::exception& e) {
        pki::log::err(std::string("verifier exception: ") + e.what());
    }
}

} // namespace verifier

// The attestation roots beside Apple's: ACME_ATTESTATION_ROOTS as PEM, or as base64 of PEM so
// a bundle fits on one line of a config file.
std::string attestation_roots_pem(const pki::Config& cfg) {
    const std::string& v = cfg.acme_attestation_roots;
    if (v.empty() || v.find("-----BEGIN") != std::string::npos) return v;
    std::string b64;
    for (const char ch : v) if (!std::isspace(static_cast<unsigned char>(ch))) b64 += ch;
    std::string out(b64.size(), '\0');
    const int n = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                  reinterpret_cast<const unsigned char*>(b64.data()),
                                  static_cast<int>(b64.size()));
    if (n < 0) throw pki::Error(2, "ACME_ATTESTATION_ROOTS is neither PEM nor base64 of PEM");
    out.resize(static_cast<size_t>(n));
    return out;
}

// ---- device-attest-01 (draft-ietf-acme-device-attest) ----
//
// The device POSTs {"attObj": base64url(CBOR attestation object)}. Verified here, in the
// request, because there is nothing to fetch: the proof is the object itself. On success
// the attested serial, UDID and key are recorded on the ticket — finalize issues only for a
// CSR carrying exactly that key.
void handle_device_attest(ServerState& s, const httplib::Request& req, httplib::Response& res,
                          pki::AcmeChallenge c, const AcmePost& post) {
    auto a = s.adb->get_authz(c.authz_id);
    auto o = (a && !a->order_id.empty()) ? s.adb->get_order(a->order_id) : std::nullopt;
    auto reply = [&]() {
        set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
        if (a) res.set_header("Link", "<" + authz_url(s, a->id) + ">;rel=\"up\"");
        res.status = 200;
        json j{{"type", c.type}, {"url", c.url}, {"status", chall_status_str(c.status)},
               {"token", c.token}};
        if (c.validated) j["validated"] = rfc3339(c.validated);
        if (!c.error.empty()) j["error"] = json{{"detail", c.error}};
        res.set_content(j.dump(), "application/json");
    };
    if (c.status != 0) { reply(); return; }   // already decided: no second verification
    if (!a || !o) { send_problem(*s.adb, req, res, 404, "malformed", "no such challenge"); return; }

    std::string att_b64;
    try {
        const json p = json::parse(std::string(post.parsed.payload_bytes.begin(),
                                                post.parsed.payload_bytes.end()));
        if (p.is_object() && p.contains("attObj") && p["attObj"].is_string())
            att_b64 = p["attObj"].get<std::string>();
    } catch (...) {}
    if (att_b64.empty()) {
        send_problem(*s.adb, req, res, 400, "malformed",
                     "a device-attest-01 response carries {\"attObj\": <base64url CBOR>}");
        return;
    }

    // By the ORDER, not the identifier: an order placed by a registered serial has a ticket of
    // its own, and the identifier is then the serial, not a ticket.
    auto t = s.adb->get_device_ticket_by_order(o->id);
    if (!t) {
        send_problem(*s.adb, req, res, 403, "unauthorized",
                     "this order no longer holds its device ticket");
        return;
    }

    pki::attest::AppleDevice dev;
    try {
        const auto raw = pki::jws::base64url_decode(att_b64);
        const auto obj = pki::attest::parse_attestation_object(raw.data(), raw.size());
        dev = pki::attest::verify_apple(obj, c.token, attestation_roots_pem(s.cfg));
        // An order placed by a registered serial must be answered by THAT device: the
        // ClientIdentifier is only a claim, and the attested serial is what Apple signed.
        if (!t->expected_serial.empty() && dev.serial != t->expected_serial)
            throw pki::Error(1, "the attested serial number is not the one this order names");
        // Posture (ACME_ATTEST_MIN_OS, ACME_ATTEST_REQUIRE_SIP): each only adds a refusal.
        if (!s.cfg.acme_attest_min_os.empty()) {
            if (dev.os_version.empty())
                throw pki::Error(1, "the attestation carries no OS version (the device is older "
                                    "than iOS 17.2 or macOS 14.2), and ACME_ATTEST_MIN_OS is " +
                                    s.cfg.acme_attest_min_os);
            if (pki::attest::compare_versions(dev.os_version, s.cfg.acme_attest_min_os) < 0)
                throw pki::Error(1, "the attested OS version " + dev.os_version +
                                    " is below ACME_ATTEST_MIN_OS " + s.cfg.acme_attest_min_os);
        }
        if (s.cfg.acme_attest_require_sip && dev.sip > 0)
            throw pki::Error(1, "the attestation says System Integrity Protection is off, and "
                                "ACME_ATTEST_REQUIRE_SIP is on");
    } catch (const pki::Error& e) {
        c.status = -1;
        c.error  = std::string("badAttestationStatement: ") + e.what();
        s.adb->save_challenge(c);
        send_problem(*s.adb, req, res, 400, "badAttestationStatement", e.what());
        return;
    }

    s.adb->record_device_attestation(t->ticket, dev.serial, dev.udid,
                                     std::string(dev.leaf_spki_der.begin(),
                                                 dev.leaf_spki_der.end()));
    c.status    = 2;
    c.validated = now_unix();
    c.error.clear();
    s.adb->save_challenge(c);
    a->status = 1;
    s.adb->save_authz(*a);
    bool all = true;
    for (auto& other : s.adb->authz_for_order(o->id))
        if (other.status != 1) { all = false; break; }
    if (all) { o->status = 1; s.adb->save_order(*o); }
    pki::log::info("ACME: device attestation verified for order " + o->id + ": serial " +
                   dev.serial + ", owner '" + t->owner + "'");
    reply();
}

void handle_chall_post(ServerState& s, const httplib::Request& req,
                       httplib::Response& res, const std::string& chall_id) {
    auto post = parse_acme_post(s.cfg, *s.adb, req, res, chall_url(s, chall_id), s.certs_db);
    if (!post) return;
    auto c = s.adb->get_challenge(chall_id);
    if (!c) { send_problem(*s.adb, req, res,404, "malformed", "no such challenge"); return; }

    // ⚠️ THE CHALLENGE ID WAS THE ONLY THING THIS ROUTE CHECKED. The JWS proves the
    // caller is *an* account; nothing tied the challenge to *that* account. So any
    // registered client could POST to any challenge URL and both drive somebody
    // else's validation and read back the response, which carries the `token`.
    //
    // Ownership runs the same way the verifier resolves it: an authz belongs to an
    // order, or — for a pre-authorization — directly to an account.
    {
        auto a = s.adb->get_authz(c->authz_id);
        std::string owner;
        if (a) {
            if (!a->order_id.empty()) {
                if (auto o = s.adb->get_order(a->order_id)) owner = o->account_id;
            } else {
                owner = a->account_id;
            }
        }
        // The same answer an unknown challenge id gets. A distinct "not yours" would
        // turn this route into an oracle for which challenge ids exist.
        if (!post->account || owner.empty() || owner != post->account->id) {
            send_problem(*s.adb, req, res, 404, "malformed", "no such challenge");
            return;
        }
    }

    if (c->type == "device-attest-01") {
        handle_device_attest(s, req, res, *c, *post);
        return;
    }

    // Move to processing and kick off verification in the background.
    if (c->status == 0) {
        c->status = 1;
        s.adb->save_challenge(*c);
        std::thread(verifier::run, &s, c->id).detach();
    }

    auto a = s.adb->get_authz(c->authz_id);
    set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
    if (a) res.set_header("Link", "<" + authz_url(s, a->id) + ">;rel=\"up\"");
    // Validation runs asynchronously; while the challenge is still pending or
    // processing the client polls this URL (RFC 8555 §8.2) — hint the interval.
    if (c->status == 0 || c->status == 1) res.set_header("Retry-After", std::to_string(kRetryAfterSec));
    res.status = 200;
    json j;
    j["type"]   = c->type;
    j["url"]    = c->url;
    j["status"] = chall_status_str(c->status);
    j["token"]  = c->token;
    res.set_content(j.dump(), "application/json");
}

// ---- finalize ----
void handle_finalize(ServerState& s, const httplib::Request& req,
                     httplib::Response& res, const std::string& order_id,
                     const std::string& instance = "") {
    auto post = parse_acme_post(s.cfg, *s.adb, req, res, finalize_url(s, order_id), s.certs_db);
    if (!post || !post->account) return;
    auto o = s.adb->get_order(order_id);
    if (!o) { send_problem(*s.adb, req, res,404, "malformed", "no such order"); return; }
    if (o->account_id != post->account->id) {
        send_problem(*s.adb, req, res,403, "unauthorized", "wrong account"); return;
    }
    // A device order is issued to its ticket's owner, under its ticket's profile, for the
    // key the device attested — not for names the account validated.
    std::optional<pki::AcmeDeviceTicket> dev_ticket;
    {
        json ids;
        try { ids = json::parse(o->identifiers_json); } catch (...) {}
        if (is_device_order(ids)) {
            // By the order, as the challenge does: a registered-serial order's ticket is not
            // named by its identifier.
            dev_ticket = s.adb->get_device_ticket_by_order(o->id);
            if (!dev_ticket) {
                send_problem(*s.adb, req, res, 403, "unauthorized",
                             "this order no longer holds its device ticket");
                return;
            }
        }
    }
    const bool device = dev_ticket.has_value();
    // ⚠️ FINALIZE IS BOUND TO THE CA THAT AUTHORIZED THE ORDER. The signing CA is
    // taken from THIS url (below), and new-order gated acme:enrol against the CA in ITS
    // url. Without this check the two could differ: an account granted acme:enrol on a
    // low-trust CA-A could new-order + solve there, then POST the finalize to CA-B and be
    // issued under CA-B — past CA-B's grant, profile and caps. RFC 8555 has no cross-CA
    // notion; an order belongs to the CA it was created under.
    //
    // NULL ca_instance_id means the order predates this fix (mixed-version rollout). Those
    // are NOT waved through — the may_enrol re-check below still runs, so an older order
    // finalized after the deploy is authorized against the finalize CA exactly as a fresh
    // order would be. Only a stored, non-matching CA is a hard reject here.
    if (!o->ca_instance_id.empty() && o->ca_instance_id != instance) {
        try {
            pki::AuditEvent ev;
            ev.category = pki::audit_cat::kAuth; ev.action = "authz_fail";
            ev.actor = post->account->kid; ev.actor_ip = client_ip(req);
            ev.target = instance; ev.status = pki::audit_status::kFailure;
            ev.detail = "protocol=ACME reason=cross-ca-finalize order-ca=" +
                        o->ca_instance_id + " finalize-ca=" + instance;
            s.certs_db->append_audit(ev);
        } catch (...) {}
        pki::log::info("ACME finalize refused: order " + order_id + " was authorized under CA '" +
                       o->ca_instance_id + "' but finalize named CA '" + instance + "'");
        send_problem(*s.adb, req, res, 403, "unauthorized",
                     "this order was authorized under a different CA");
        return;
    }
    // Re-run the acme:enrol gate at finalize against the CA that will sign, so a
    // grant REVOKED between new-order and finalize takes effect — and so an older order
    // (NULL ca above) is still authorized against the finalize CA rather than skipped.
    // ⚠️ AT FUNCTION SCOPE, because the quota re-check at the insert below needs the same
    // two values. Same reasoning as the gate re-run in this block: what was true at
    // new-order is not necessarily true now, and the insert is the moment that counts.
    const std::string acct_user = device ? dev_ticket->owner : post->account->kid;
    const std::vector<std::string> acme_groups =
        pki::directory_groups_for(s.cfg, s.certs_db, acct_user);
    {
        if (!pki::may_enrol(*s.certs_db, acct_user, "", "acme:enrol", instance, acme_groups)) {
            try {
                pki::AuditEvent ev;
                ev.category = pki::audit_cat::kAuth; ev.action = "authz_fail";
                ev.actor = acct_user; ev.actor_ip = client_ip(req);
                ev.target = instance; ev.status = pki::audit_status::kFailure;
                ev.detail = "protocol=ACME need=acme:enrol phase=finalize ca=" + instance;
                s.certs_db->append_audit(ev);
            } catch (...) {}
            pki::log::info("ACME finalize refused: '" + acct_user +
                           "' holds no acme:enrol for CA '" + instance + "'");
            send_problem(*s.adb, req, res, 403, "unauthorized",
                         "this account may not enrol under this CA");
            return;
        }
    }
    if (o->status != 1) {
        send_problem(*s.adb, req, res,403, "orderNotReady", "order is not ready"); return;
    }

    json payload;
    try { payload = json::parse(std::string(post->parsed.payload_bytes.begin(),
                                             post->parsed.payload_bytes.end())); }
    catch (...) { send_problem(*s.adb, req, res,400, "malformed", "bad payload"); return; }
    if (!payload.contains("csr")) {
        send_problem(*s.adb, req, res,400, "malformed", "csr required"); return;
    }

    std::vector<unsigned char> der;
    try { der = pki::jws::base64url_decode(payload["csr"].get<std::string>()); }
    catch (const pki::Error& e) { send_problem(*s.adb, req, res,400, "badCSR", e.what()); return; }

    try {
        std::string_view sv(reinterpret_cast<const char*>(der.data()), der.size());
        auto csr = pki::parse_csr(sv);

        if (device) {
            // The attested key and nothing else: Apple requires the CSR key to be the
            // attestation leaf's key, byte for byte, or badCSR. That is what makes the
            // certificate belong to the Secure Enclave key the device proved it holds.
            EVP_PKEY* csr_key = X509_REQ_get0_pubkey(csr.get());
            const int klen = csr_key ? i2d_PUBKEY(csr_key, nullptr) : -1;
            std::string spki(klen > 0 ? static_cast<size_t>(klen) : 0, '\0');
            if (klen > 0) {
                auto* w = reinterpret_cast<unsigned char*>(spki.data());
                i2d_PUBKEY(csr_key, &w);
            }
            if (dev_ticket->attested_spki.empty() || spki != dev_ticket->attested_spki) {
                send_problem(*s.adb, req, res, 400, "badCSR",
                             "the CSR key is not the key the device attested");
                return;
            }
        } else {
            // Verify the CSR's SANs cover exactly the ordered identifiers.
            std::vector<std::string> ordered;
            for (auto& id : json::parse(o->identifiers_json))
                ordered.push_back(id.value("value", ""));
            std::sort(ordered.begin(), ordered.end());

            // ⚠️ THE SHARED HELPER, NOT A SECOND WALKER. This used to hand-roll its own
            // GENERAL_NAMES loop that collected GEN_DNS and ignored every other type — so an
            // rfc822Name, iPAddress, URI or otherName in the CSR was compared against nothing
            // and passed straight into the certificate. newOrder accepts `dns` identifiers and
            // only those, so a solved challenge proves control of a DOMAIN; a CSR carrying the
            // validated domain plus `email:someone@victim.example` was issued with that mailbox
            // in it. The profile layer is no backstop — the default allowed_san_types is
            // {dns,ip,email,uri}, GEN_EMAIL has no content check at all, and iPAddress is bounded
            // only by ALLOWED_IPS_REGEX (default 10.0.0.0/8).
            //
            // pki::csr_sans() returns every entry TYPE-TAGGED ("DNS:host", "EMAIL:…",
            // "IP:<hex>", unknown types by tag+DER), which makes an unexpected type impossible
            // to overlook rather than merely unlikely. renewal_mismatch() has compared in that
            // form since it was written, for exactly this reason; the walker here was a second,
            // weaker copy of a problem already solved once.
            //
            // Refused, not stripped: silently dropping a name the client asked for hands back a
            // certificate that is not the one requested, and it finds out much later.
            const std::set<std::string> have = pki::csr_sans(csr.get());
            std::set<std::string> want;
            for (const auto& id : ordered) want.insert("DNS:" + id);
            if (have != want) {
                std::string extra;
                for (const auto& h : have)
                    if (!want.count(h)) { extra = h; break; }
                send_problem(*s.adb, req, res, 400, "badCSR",
                             extra.empty()
                                 ? std::string("the CSR does not carry the identifiers this "
                                               "order authorized")
                                 : "the CSR carries the subjectAltName " + extra + ", which this "
                                   "order never validated — it authorized DNS identifiers only");
                return;
            }

            // ⚠️ THE SUBJECT CN MUST ALSO BE AN AUTHORIZED IDENTIFIER (RFC 8555 §7.4).
            // Only the SANs were compared above; the CN was never looked at, and policy.cpp
            // skips the CN domain-allowlist for ACME (correctly — DV authorizes via the
            // ordered identifiers, not the allowlist). So a CSR with SAN=attacker-owned.com
            // (which passes the check above) plus CN=victim.com produced a CA-signed DV
            // certificate ASSERTING victim.com. Modern browsers ignore CN, but plenty of
            // non-browser TLS stacks still match it, so the certificate is a real
            // impersonation of a name the account never proved it controls.
            //
            // certbot and every conforming client send an EMPTY subject and let the CA
            // synthesise the CN from the first SAN (x509.cpp), so empty is the common case and
            // is allowed. A non-empty CN is allowed ONLY when it is one of the identifiers the
            // account just validated — anything else is refused.
            {
                X509_NAME* sn = X509_REQ_get_subject_name(csr.get());
                char cnbuf[256] = {0};
                int cnlen = sn ? X509_NAME_get_text_by_NID(sn, NID_commonName, cnbuf, sizeof cnbuf) : -1;
                if (cnlen > 0) {
                    std::string cn(cnbuf, static_cast<size_t>(cnlen));
                    if (!std::binary_search(ordered.begin(), ordered.end(), cn)) {
                        pki::log::info("ACME finalize refused: CSR CN '" + cn +
                                       "' is not among the ordered identifiers");
                        send_problem(*s.adb, req, res, 400, "badCSR",
                                     "CSR subject CN is not one of the authorized identifiers");
                        return;
                    }
                }
            }

            // CAA re-check at issuance time (RFC 8555 §8.1.1, RFC 8659). Opt-in: only
            // when this CA's identity is configured. Refuse if any ordered DNS
            // identifier's CAA policy doesn't authorize us.
            if (!s.cfg.acme_caa_identity.empty()) {
                for (const auto& ident : ordered) {
                    // `why` distinguishes "the domain forbids us" from "we could not
                    // find out" — both refuse, and the client is told which. A failed lookup
                    // used to be read as "no CAA anywhere", so a dead resolver disabled the
                    // policy and the order went through with nothing in the log.
                    std::string caa_why;
                    if (!verifier::caa_allows(dns_resolver_now(s), ident,
                                              s.cfg.acme_caa_identity, caa_why)) {
                        send_problem(*s.adb, req, res, 403, "caa",
                                     caa_why.empty() ? "CAA forbids issuance for " + ident
                                                     : caa_why + " (for " + ident + ")");
                        return;
                    }
                }
            }
        }

        // Select the issuing CA: resolve + load this order's CA
        // from the DB via the cache — no preloaded global. The order was created under
        // the CA's virtual prefix, so a base (no-id) finalize names no CA and 404s.
        const std::string& eff_instance = instance;
        if (eff_instance.empty()) {
            send_problem(*s.adb, req, res, 404, "malformed", "this endpoint is per-CA: use /{ca_id}"); return;
        }
        int ca_code = 500; std::string ca_err;
        auto ca_m = s.ca_cache->get(*s.certs_db, s.cfg, eff_instance, ca_code, ca_err);
        if (!ca_m) {
            if      (ca_code == 404) send_problem(*s.adb, req, res, 404, "malformed",    ca_err);
            else if (ca_code == 503) send_problem(*s.adb, req, res, 403, "unauthorized", ca_err);
            else                     send_problem(*s.adb, req, res, 500, "serverInternal", ca_err);
            return;
        }
        X509* ca_cert = ca_m->cert.get();
        EVP_PKEY* ca_key = ca_m->key.get();

        // NOT "master". This used to be `role = "master"` -- "the ACME path was
        // 'master' in PHP" -- so every certificate ACME ever issued was recorded under the
        // most privileged legacy value, for a caller that holds no console role at all.
        // An ACME client authenticates with an account key, not a web_users row; there is
        // no role to record, and `row.owner` already carries the account id or its bound
        // EAB kid. Empty is the truthful answer, and it is the ABSENCE of a vocabulary
        // rather than a fourth one.
        //
        // Safe by construction: certs.role never reaches the certificate, and
        // NO role of any kind does — the Subject Directory Attributes extension carries
        // the owner and nothing else (src/lib/x509.cpp, add_subject_directory_attributes).
        // The rule: x509 certificates are about authentication, not authorization.
        // This changes a DB record, not issued bytes.
        std::string role = "";
        // Owner for the Subject Directory Attributes ext: the bound
        // external account (kid) when present, else the ACME account id — never
        // empty, so the owner is always recorded.
        const std::string acme_owner =
            device ? dev_ticket->owner
                   : (post->account->kid.empty() ? post->account->id : post->account->kid);
        // Policy profile: resolve from the account identity rather
        // than the hardcoded "master" role. Defaults to the built-in "standard"
        // (identical KU/EKU to master), so cert shape is unchanged; an account may
        // be moved to a stricter profile by granting its roles `profile:use` on that one
        // — the union is what resolve_profile answers from.
        // ⚠️ AUTHORIZE AS THE USER — and the kid IS the user. It used to be
        // `<user>:eab`, and resolve_profile answers from the union of the SUBJECT's role
        // grants, so passing the kid asked for the roles of a subject called `demo:eab`,
        // which is nobody: every EAB-bound account was refused at finalize with "this
        // identity holds no profile permission" while newOrder, 900 lines up, stripped the
        // suffix and let the order validate. Measured on dc3 over http-01 and tls-alpn-01.
        // The suffix is gone, so the two call sites can no longer disagree about it.
        const std::string profile_subject = acme_owner;
        const pki::EffectiveProfile profile =
            pki::resolve_profile(*s.certs_db, s.cfg,
                                 pki::ProfileIdentity{profile_subject, "",
                                     pki::directory_groups_for(s.cfg, s.certs_db, profile_subject)},
                                 /*requested=*/device ? dev_ticket->profile : std::string());
        pki::IssuanceInput in{
            .cfg = s.cfg, .ca_cert = ca_cert, .ca_key = ca_key,
            .csr = csr.get(), .owner_username = acme_owner,
            .profile = profile.name,
            // ACME does its own domain validation. A device order validated no name, so
            // its names go through the full issuance policy, as a SCEP request's do.
            .acme = !device
        };
        in.profile_override = &profile.profile;
        // Added to the SAN only when the profile sets device_serial_san.
        if (device) in.attested_serial = dev_ticket->device_serial;
        pki::CaUrls urls = pki::ca_urls_for_instance(*s.certs_db, s.cfg, eff_instance);  // per-CA AIA/CDP
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
        row.cn         = pki::x509_cn(cert.get());
        row.subject    = row.cn;
        row.owner      = acme_owner;
        row.cert_der   = pki::x509_to_der(cert.get());
        row.fingerprint= pki::x509_fingerprint_sha256_hex(cert.get());
        row.ca_instance_id = eff_instance;   // partition key
        // ⚠️ THE QUOTA IS DECIDED HERE, WITH THE WRITE. It was also checked at newOrder,
        // which is where a client gets a useful refusal before generating a key — but
        // that check and this insert are different requests, arbitrarily far apart, so a
        // client could create many orders while under the cap and then finalise them
        // all. Locking at newOrder could not have helped; only counting and writing
        // together can. An account with no cap inserts exactly as before.
        {
            const auto fin_lim = pki::role_limits(*s.certs_db, acct_user, "", acme_groups);
            if (fin_lim.max_certs && !row.owner.empty()) {
                if (!s.certs_db->insert_cert_within_quota(row, row.owner, *fin_lim.max_certs)) {
                    pki::log::info("ACME: refusing finalize for '" + acct_user +
                                   "' — certificate limit of " +
                                   std::to_string(*fin_lim.max_certs) + " reached");
                    send_problem(*s.adb, req, res, 429, "rateLimited",
                                 "certificate limit reached for this account");
                    return;
                }
            } else {
                s.certs_db->insert_cert(row);
            }
        }

        // Audit: record issuance; never abort on audit failure.
        try {
            pki::AuditEvent ev;
            ev.category = pki::audit_cat::kLifecycle;
            ev.action   = "cert_issued";
            ev.actor    = row.owner;
            ev.actor_ip = client_ip(req);
            ev.target   = row.serial;
            ev.status   = pki::audit_status::kSuccess;
            ev.detail   = "protocol=ACME cn=" + row.cn + " ca_instance=" + instance;
            if (device) ev.detail += " device_serial=" + dev_ticket->device_serial;
            s.certs_db->append_audit(ev);
        } catch (const std::exception& e) {
            pki::log::err(std::string("ACME audit append failed: ") + e.what());
        }

        // A device keeps one certificate. Apple's client never renews — every install of the
        // profile makes a new key and a new order — so the previous certificate of the same
        // attested device is revoked as superseded (reason 4) once this one exists. Matched by
        // the attested serial number, which the device cannot choose.
        if (device) {
            s.adb->set_device_ticket_cert(dev_ticket->ticket, row.serial);
            for (const auto& old : s.adb->device_cert_serials(dev_ticket->device_serial,
                                                              dev_ticket->ticket)) {
                try {
                    if (!s.certs_db->revoke_cert(old, 4, now_unix())) continue;
                    pki::log::info("ACME: revoked " + old + " as superseded by " + row.serial +
                                   " for device " + dev_ticket->device_serial);
                    pki::AuditEvent ev;
                    ev.category = pki::audit_cat::kLifecycle;
                    ev.action   = "cert_revoked";
                    ev.actor    = row.owner;
                    ev.actor_ip = client_ip(req);
                    ev.target   = old;
                    ev.status   = pki::audit_status::kSuccess;
                    ev.detail   = "protocol=ACME reason=4 superseded_by=" + row.serial +
                                  " device_serial=" + dev_ticket->device_serial;
                    s.certs_db->append_audit(ev);
                } catch (const std::exception& e) {
                    pki::log::err("ACME: could not revoke " + old + ", superseded by " +
                                  row.serial + ": " + e.what());
                }
            }
        }

        o->status = 3; // valid
        o->cert_serial = row.serial;
        s.adb->save_order(*o);

        set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
        res.set_header("Location", order_url(s, o->id));
        res.status = 200;
        res.set_content(order_to_json(s, *o).dump(), "application/json");
    } catch (const pki::Error& e) {
        send_problem(*s.adb, req, res,400, "badCSR", e.what());
    } catch (const std::exception& e) {
        send_problem(*s.adb, req, res,500, "serverInternal", e.what());
    }
}

// ---- certificate (PEM chain) ----
void handle_cert(ServerState& s, const httplib::Request& req,
                 httplib::Response& res, const std::string& serial) {
    auto post = parse_acme_post(s.cfg, *s.adb, req, res, cert_url(s, serial), s.certs_db);
    if (!post) return;
    auto row = s.certs_db->get_cert(serial);
    if (!row) { send_problem(*s.adb, req, res,404, "malformed", "no such cert"); return; }
    // ⚠️ AND THE SIGNER MUST OWN THE CERTIFICATE. `certs.owner` is written at issuance as
    // `kid.empty() ? account id : kid` (see the issuance path), so the same expression is
    // what identifies the requesting account here. Without it any account could download any
    // certificate this ACME endpoint has ever issued by serial — which is a URL an order body
    // hands out, and serials are guessable in bulk.
    if (!post->account) {
        send_problem(*s.adb, req, res, 401, "unauthorized", "no account for this request");
        return;
    }
    {
        const std::string want = post->account->kid.empty() ? post->account->id
                                                            : post->account->kid;
        // A device order's certificate is owned by its ticket's owner, not by the account
        // that enrolled it, so the account is also allowed a certificate that one of ITS OWN
        // orders produced. Found on a real Mac: the attestation verified, the certificate was
        // issued, and the download was refused, which failed the profile install with
        // NSURLErrorDomain -1012.
        bool owns = (row->owner == want);
        if (!owns)
            for (const auto& o : s.adb->orders_for_account(post->account->id))
                if (o.cert_serial == serial) { owns = true; break; }
        if (!owns) {
            send_problem(*s.adb, req, res, 401, "unauthorized",
                         "a certificate may only be fetched by the account it was issued to");
            return;
        }
    }

    // Convert leaf DER → PEM, then append CA + root PEM.
    auto to_pem = [](const std::vector<unsigned char>& der) {
        std::string b64;
        BIO* mem = BIO_new(BIO_s_mem());
        BIO* b64bio = BIO_new(BIO_f_base64());
        BIO* chain = BIO_push(b64bio, mem);
        BIO_write(chain, der.data(), static_cast<int>(der.size()));
        BIO_flush(chain);
        BUF_MEM* bp = nullptr;
        BIO_get_mem_ptr(chain, &bp);
        std::string body(bp->data, bp->length);
        BIO_free_all(chain);
        return "-----BEGIN CERTIFICATE-----\n" + body + "-----END CERTIFICATE-----\n";
    };

    std::string out = to_pem(row->cert_der);

    // Append the issuing CA's cert + the root. There is no global signing CA —
    // the chain comes from the CA's own certificate row, loaded from DB as DER.
    try {
        auto rc = pki::resolve_ca_instance(*s.certs_db, s.cfg, row->ca_instance_id);
        // EVERY live CA certificate, not just the newest. While a rekey is rolling
        // over there are two, and RFC 8555 §7.4.2 lets the chain carry both — a client
        // anchored on either can then build a path from what it was given. Sending only
        // the newest strands everyone who has not moved to the new anchor yet.
        if (rc.found) {
            if (!rc.chain_ders.empty())
                for (const auto& der : rc.chain_ders) out += to_pem(der);
            else
                out += to_pem(rc.cert_der);
        }
    } catch (const std::exception&) { /* no issuer cert to append */ }
    // The trust anchor comes from the DB, per CA. It used to be appended from
    // ROOT_CA_PEM — one file for every hierarchy, which could only ever be right for
    // one of them. Ancestors ship parent-first, so the chain stays ordered leaf -> root
    // as RFC 8555 §7.4.2 expects.
    try {
        for (const auto& a : s.certs_db->get_ca_ancestor_ders(row->ca_instance_id))
            out += to_pem(a.der);
    } catch (const std::exception&) { /* anchor unavailable — the issuer chain still ships */ }

    set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
    res.status = 200;
    res.set_content(out, "application/pem-certificate-chain");
}

// ---- revoke-cert (RFC 8555 §7.6) ----
void handle_revoke_cert(ServerState& s, const httplib::Request& req,
                        httplib::Response& res) {
    auto post = parse_acme_post(s.cfg, *s.adb, req, res, url_for(s, "/revoke-cert"), s.certs_db);
    if (!post) return;

    json payload;
    try { payload = json::parse(std::string(post->parsed.payload_bytes.begin(),
                                            post->parsed.payload_bytes.end())); }
    catch (...) { send_problem(*s.adb, req, res, 400, "malformed", "bad payload"); return; }
    if (!payload.contains("certificate")) {
        send_problem(*s.adb, req, res, 400, "malformed", "certificate required"); return;
    }
    int reason = payload.value("reason", 0);

    std::vector<unsigned char> der;
    try { der = pki::jws::base64url_decode(payload["certificate"].get<std::string>()); }
    catch (const pki::Error& e) { send_problem(*s.adb, req, res, 400, "malformed", e.what()); return; }

    const unsigned char* p = der.data();
    pki::X509Ptr cert{d2i_X509(nullptr, &p, static_cast<long>(der.size()))};
    if (!cert) { send_problem(*s.adb, req, res, 400, "malformed", "bad certificate"); return; }

    std::string serial = pki::x509_serial_hex(cert.get());
    auto row = s.certs_db->get_cert(serial);
    if (!row) { send_problem(*s.adb, req, res, 400, "malformed", "unknown certificate"); return; }

    // The posted certificate is only ever a way of NAMING the row: `serial` selects it, and
    // everything trusted below is read back out of `row`. Nothing compares the posted bytes
    // to the stored ones — a client that kept the certificate as PEM and re-encoded it can
    // legitimately produce a different outer encoding for the same certificate (string types
    // and length forms vary), and rejecting that would stop a key holder revoking a
    // compromised certificate.
    // RFC 8555 §7.6: an unsupported reason is badRevocationReason. Same rule as every other
    // path that revokes (pki::revocation_reason_refusal).
    if (const std::string why = pki::revocation_reason_refusal(reason); !why.empty()) {
        send_problem(*s.adb, req, res, 400, "badRevocationReason", why);
        return;
    }
    // A certificate on hold can still be revoked for good; anything else not valid cannot.
    const bool held = row->status == -1 && row->revocation_reason == pki::kReasonCertificateHold;
    if (row->status != 0 && !(held && reason != pki::kReasonCertificateHold)) {
        send_problem(*s.adb, req, res, 400, "alreadyRevoked", "certificate is not currently valid");
        return;
    }

    // Authorization (RFC 8555 §7.6): the account that owns the cert, OR a
    // request signed by the certificate's own key pair.
    bool authorized = false;
    if (post->account) {
        std::string acct = post->account->kid.empty() ? post->account->id : post->account->kid;
        if (!row->owner.empty() && row->owner == acct) authorized = true;
    }
    if (!authorized && post->parsed.jwk) {
        // ⚠️ THE KEY COMES FROM THE STORED CERTIFICATE, NEVER FROM THE REQUEST. RFC 8555
        // §7.6 asks whether this JWS was signed with the private key belonging to the
        // certificate BEING REVOKED — that is our row, not the blob the client posted.
        // Reading the public key out of `cert` instead put both halves of the comparison
        // under the requester's control, so they matched by construction: mint a
        // self-signed certificate carrying somebody else's serial and your own key, sign
        // the JWS with that key, and the check passed against a row you had never held.
        // Serials are public in the CRL, in OCSP and in the RFC 4387 store, and this branch
        // needs no account, so that was unauthenticated revocation of anything issued here.
        const unsigned char* rp = row->cert_der.data();
        pki::X509Ptr stored{d2i_X509(nullptr, &rp, static_cast<long>(row->cert_der.size()))};
        EVP_PKEY* cpk = stored ? X509_get0_pubkey(stored.get()) : nullptr;
        int len = cpk ? i2d_PUBKEY(cpk, nullptr) : 0;
        if (len > 0) {
            std::vector<unsigned char> cert_spki(static_cast<size_t>(len));
            unsigned char* q = cert_spki.data();
            i2d_PUBKEY(cpk, &q);
            // i2d_PUBKEY is a canonical SubjectPublicKeyInfo encoding produced by OpenSSL on
            // both sides — here from our stored certificate, and in jws::verify() from the
            // request's JWK — so this compares keys, not the shapes they arrived in.
            if (cert_spki == post->verified_spki) authorized = true;
        }
    }
    if (!authorized) {
        send_problem(*s.adb, req, res, 403, "unauthorized",
                     "not authorized to revoke this certificate");
        return;
    }

    s.certs_db->revoke_cert(serial, reason, now_unix());
    try {
        pki::AuditEvent ev;
        ev.category = pki::audit_cat::kLifecycle;
        ev.action   = "cert_revoked";
        ev.actor    = post->account
                        ? (post->account->kid.empty() ? post->account->id
                                                       : post->account->kid)
                        : std::string();
        ev.actor_ip = client_ip(req);
        ev.target   = serial;
        ev.status   = pki::audit_status::kSuccess;
        ev.detail   = "protocol=ACME reason=" + std::to_string(reason);
        s.certs_db->append_audit(ev);
    } catch (const std::exception& e) {
        pki::log::err(std::string("ACME audit append failed: ") + e.what());
    }
    pki::log::info("ACME revoked serial=" + serial + " reason=" + std::to_string(reason));
    set_nonce_header(*s.adb, req, res, s.cfg.nonce_expires_sec);
    res.status = 200;
}

void set_log_level_from_string(std::string_view s) {
    using pki::log::Level;
    if      (s == "debug") pki::log::set_level(Level::Debug);
    else if (s == "info")  pki::log::set_level(Level::Info);
    else                   pki::log::set_level(Level::Err);
}

} // namespace

int main(int argc, char** argv) {
    if (pki::handled_version_flag(argc, argv)) return 0;
    std::string conf_path = "config/bootstrap.conf";
    bool issue_ticket = false;
    std::string ticket_ca, ticket_owner, ticket_profile;
    int64_t ticket_ttl = 7LL * 24 * 3600;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) conf_path = argv[++i];
        else if (std::strcmp(argv[i], "--issue-device-ticket") == 0) issue_ticket = true;
        else if (std::strcmp(argv[i], "--ca") == 0 && i + 1 < argc) ticket_ca = argv[++i];
        else if (std::strcmp(argv[i], "--owner") == 0 && i + 1 < argc) ticket_owner = argv[++i];
        else if (std::strcmp(argv[i], "--profile") == 0 && i + 1 < argc) ticket_profile = argv[++i];
        else if (std::strcmp(argv[i], "--ttl") == 0 && i + 1 < argc) ticket_ttl = std::atoll(argv[++i]);
        else if (std::strcmp(argv[i], "--help") == 0) {
            std::cout << "Usage: fastpki-acme [--config path]\n"
                         "       fastpki-acme [--config path] --issue-device-ticket --ca <ca_id> "
                         "--owner <user> [--profile <name>] [--ttl <seconds>]\n"
                         "         print a one-time ticket for ACME device attestation: put it in "
                         "an Apple ACME\n"
                         "         profile as ClientIdentifier. It enrols one device against "
                         "<ca_id>, issued to\n"
                         "         <user> under <name> (default: <user>'s profiles). Default "
                         "--ttl is 7 days.\n";
            return 0;
        }
    }
    if (issue_ticket && (ticket_ca.empty() || ticket_owner.empty() || ticket_ttl <= 0)) {
        std::cerr << "fastpki-acme: --issue-device-ticket needs --ca <ca_id> and --owner <user>, "
                     "and a positive --ttl\n";
        return 2;
    }

    try {
        ServerState st;
        st.cfg = pki::Config::load(conf_path);

        // ACME nonce/order store: use the same backend as the cert store.
        std::unique_ptr<pki::AcmeDb> adb_owner;
        adb_owner = pki::make_acme_postgres_db(st.cfg.pg_conninfo);
        st.adb = adb_owner.get();
        // Cert store uses Postgres, like every other service.
        std::unique_ptr<pki::Db> certs_owner;
        certs_owner = pki::make_postgres_db(st.cfg.pg_conninfo);
        st.certs_db = certs_owner.get();
        pki::overlay_config(st.cfg, st.certs_db->get_config());   // DB config overlay
        // Say which licence this node is running under, once, now that the database overlay has
        // been applied and the effective value is known. Reported, never enforced.
        pki::log_license(pki::license_status(st.cfg, pki::license_eval_started(*st.certs_db)));
        g_trusted_proxies = st.cfg.trusted_proxies;         // after the overlay, so the DB wins
        pki::load_cert_profiles(st.cfg, *st.certs_db);              // the replicated profiles
        // ACME issues but does NOT call load_allowed_domains (it validates domains
        // itself), so this line has no sibling to copy — see config.hpp.
        pki::resolve_datacenter_prefix(st.cfg, *st.certs_db);
        set_log_level_from_string(st.cfg.log_level);

        if (issue_ticket) {
            // Every check an enrolment will make is made HERE, at the mistake, so a ticket
            // that could never work is refused now rather than failing on a device later
            // with nothing on its screen but "bad request". The console's Apple profile
            // download issues tickets through the same function.
            try {
                const std::string ticket = pki::issue_device_ticket(
                    *st.certs_db, *st.adb, st.cfg, ticket_ca, ticket_owner, ticket_profile, ticket_ttl);
                std::cout << ticket << "\n";
                std::cerr << "issued a device ticket for CA '" << ticket_ca << "', owner '"
                          << ticket_owner << "', profile '"
                          << (ticket_profile.empty() ? "(the owner's)" : ticket_profile)
                          << "', expires " << rfc3339(now_unix() + ticket_ttl) << "\n";
            } catch (const std::exception& e) {
                std::cerr << "fastpki-acme: refusing to issue a device ticket: " << e.what() << "\n";
                return 1;
            }
            return 0;
        }

        st.base = st.cfg.base_url + st.cfg.acme_base_path;

        // No signing CA is preloaded — issuance material is resolved per order
        // from the DB via the cache, so a CA-less deploy starts and each /{ca_id} serves
        // once that CA exists.
        pki::CaMaterialCache ca_cache;
        st.ca_cache = &ca_cache;

        // Background sweep of expired nonces + orders instead of
        // relying on a triggering request. Detached — runs for the process
        // lifetime; AcmeDb methods are mutex-guarded so it's safe alongside
        // request/verifier threads.
        if (st.cfg.acme_sweep_sec > 0) {
            pki::AcmeDb* adbp = st.adb;
            int interval = st.cfg.acme_sweep_sec;
            std::thread([adbp, interval]() {
                for (;;) {
                    std::this_thread::sleep_for(std::chrono::seconds(interval));
                    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    try { adbp->delete_expired_nonces(now); adbp->delete_expired_orders(now); }
                    catch (const std::exception& e) {
                        pki::log::err(std::string("ACME expiry sweep failed: ") + e.what());
                    }
                }
            }).detach();
            pki::log::info("ACME expiry sweep every " + std::to_string(interval) + "s");
        }

        // Come up on a temporary self-signed cert when no CA-issued ACME cert
        // exists yet (CA-less deploy) instead of crash-looping; a real cert on disk wins
        // on the next start. See pki::resolve_transport_cert.
        auto acme_tc = pki::resolve_transport_cert(*st.certs_db, st.cfg.acme_cert_id, st.cfg.acme_server_cert_pem, st.cfg.acme_server_key_pem, st.cfg, st.cfg.pki_dns, st.cfg.acme_key);
        std::unique_ptr<httplib::SSLServer> acme_srv_owner;
        if (acme_tc.use_files) {
            acme_srv_owner = std::make_unique<httplib::SSLServer>(
                st.cfg.acme_server_cert_pem.c_str(), st.cfg.acme_server_key_pem.c_str());
            pki::log_transport_cert("acme", acme_tc, st.cfg.pki_dns);
        } else {
            auto tc_ptr = std::make_shared<pki::TransportCert>(std::move(acme_tc));
            httplib::tls::ContextSetupCallback cb =
                [tc_ptr](void* ctx) { return pki::load_tls_context(ctx, *tc_ptr); };
            acme_srv_owner = std::make_unique<httplib::SSLServer>(cb);
            // Say which certificate we ACTUALLY came up on. This branch is taken for
            // both outcomes, so announcing "TEMPORARY self-signed" unconditionally told
            // every correctly-configured deployment the opposite of the truth.
            pki::log_transport_cert("acme", *tc_ptr, st.cfg.pki_dns);
            // Serve a renewal as soon as renew-service-certs publishes one (transport_reload.hpp).
            if (acme_srv_owner->is_valid())
                pki::serve_renewed_transport_certs(acme_srv_owner->tls_context(), st.certs_db,
                                                   st.cfg, st.cfg.acme_cert_id, *tc_ptr, "acme");
        }
        httplib::SSLServer& srv = *acme_srv_owner;
        srv.set_payload_max_length(256 * 1024); // cap ACME bodies
        srv.set_keep_alive_timeout(kKeepAliveSec); // paired with the poll hint (kRetryAfterSec)

        // Decide the base URL for advertised endpoints on every request. With an
        // explicit BASE_URL (production behind a TLS proxy) we use it verbatim;
        // otherwise we reflect the request's Host header + scheme so the
        // directory points at the address/port the client actually reached us on.
        srv.set_pre_routing_handler(
            [&](const httplib::Request& req, httplib::Response&) {
                // Detect per-CA instance via trailing-segment pattern:
                // {acme_base_path}/{id}/...
                // Fold it into both the request instance and the advertised base,
                // so every URL the directory/order flow generates stays in-tenant.
                std::string inst_prefix;
                g_req_instance = "";
                g_req_host = req.get_header_value("Host");   // for host binding
                {
                    const std::string& base = st.cfg.acme_base_path;
                    if (req.path.rfind(base, 0) == 0) {
                        std::string rest = req.path.substr(base.size());
                        if (rest.size() > 0 && rest[0] == '/') {
                            rest = rest.substr(1);  // skip leading /
                            size_t slash = rest.find('/');
                            std::string id = (slash == std::string::npos) ? rest : rest.substr(0, slash);
                            // Check if this looks like an instance ID (not a known endpoint).
                            // Route like any other instance id.
                            if (!id.empty() &&
                                id != "directory" && id != "new-nonce" &&
                                id != "new-account" && id != "new-order" && id != "new-authz" &&
                                id != "key-change" && id != "revoke-cert" && id != "account" &&
                                id != "order" && id != "authz" && id != "chall" && id != "cert") {
                                g_req_instance = id;
                                inst_prefix = "/" + id;  // will be appended to base_path
                            }
                        }
                    }
                }
                // ACME is an enrolment protocol, so it is id-based — every request
                // names a /{ca_id}. A base (no-id) path leaves g_req_instance empty and
                // the handlers 404; we never guess a "first CA" (ambiguous under a
                // root + subCA hierarchy).
                if (st.cfg.base_url_explicit) {
                    g_req_base = st.cfg.base_url + st.cfg.acme_base_path + inst_prefix;
                } else {
                    std::string host = req.get_header_value("Host");
                    if (host.empty())
                        host = "localhost:" + std::to_string(st.cfg.acme_port);
                    // ⚠️ ONLY FROM A PROXY WE TRUST. This header decides the scheme of every
                    // URL the directory advertises, and it is set by whoever sends it: an
                    // untrusted caller could otherwise make the server hand back http://
                    // URLs. The fallback below is https, so ignoring it is the safe
                    // direction, and BASE_URL — checked above — stays the supported answer
                    // for a deployment that terminates TLS at a proxy.
                    std::string scheme =
                        pki::is_trusted_proxy(g_trusted_proxies, req.remote_addr)
                            ? req.get_header_value("X-Forwarded-Proto") : std::string{};
                    if (scheme.empty()) scheme = "https";  // ACME terminates TLS
                    g_req_base = scheme + "://" + host + st.cfg.acme_base_path + inst_prefix;
                }
                return httplib::Server::HandlerResponse::Unhandled;
            });

        const std::string p = st.cfg.acme_base_path;
        srv.Get (p + "/directory",
                 [&](const httplib::Request&, httplib::Response& res) { handle_directory(st, res); });
        srv.Get (p + "/new-nonce",
                 [&](const httplib::Request& q, httplib::Response& res) { handle_new_nonce(st, q, res); });
        //srv.Head(p + "/new-nonce",
        srv.Get(p + "/new-nonce",
                 [&](const httplib::Request& q, httplib::Response& res) { handle_new_nonce(st, q, res); });
        srv.Post(p + "/new-account",
                 [&](const httplib::Request& q, httplib::Response& res) { handle_new_account(st, q, res); });

        // Stubs — see comment at top of file. Routes that still need work are
        // registered further down once their handlers exist.
        srv.Post(p + "/new-order",
                 [&](const httplib::Request& q, httplib::Response& res) { handle_new_order(st, q, res); });
        if (st.cfg.acme_new_authz)
            srv.Post(p + "/new-authz",
                     [&](const httplib::Request& q, httplib::Response& res) { handle_new_authz(st, q, res); });

        // Per-id routes — httplib treats these as std::regex patterns.
        auto reg_post = [&](const std::string& pattern, auto fn) {
            srv.Post(pattern, fn);
        };
        reg_post(p + R"(/account/(\d+))",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     handle_account(st, q, res, q.matches[1].str()); });
        reg_post(p + R"(/account/(\d+)/orders)",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     handle_account_orders(st, q, res, q.matches[1].str()); });
        reg_post(p + R"(/order/(\d+))",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     handle_order_get(st, q, res, q.matches[1].str()); });
        reg_post(p + R"(/order/(\d+)/finalize)",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     // Base finalize issues from the tenant's default CA — the
                     // pre-routing handler resolved it into g_req_instance.
                     handle_finalize(st, q, res, q.matches[1].str(), g_req_instance); });
        reg_post(p + R"(/authz/(\d+))",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     handle_authz_post(st, q, res, q.matches[1].str()); });
        reg_post(p + R"(/chall/(\d+))",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     handle_chall_post(st, q, res, q.matches[1].str()); });
        reg_post(p + R"(/cert/([0-9a-f]+))",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     handle_cert(st, q, res, q.matches[1].str()); });

        srv.Post(p + "/key-change",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     handle_key_change(st, q, res); });
        srv.Post(p + "/revoke-cert",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     handle_revoke_cert(st, q, res); });

        // Virtualized per-CA ACME: mirror every route under
        // {acme_base_path}/{ca_instance_id}/... The pre-routing handler sets
        // g_req_instance + g_req_base from the path, so the handlers and every
        // advertised URL stay in-tenant; only finalize needs the instance
        // explicitly (to choose the issuing CA). For these regex routes the
        // instance is matches[1] and any trailing id is matches[2].
        const std::string ip = p + R"(/([^/]+))";
        srv.Get (ip + "/directory",
                 [&](const httplib::Request&, httplib::Response& res) { handle_directory(st, res); });
        srv.Get (ip + "/new-nonce",
                 [&](const httplib::Request& q, httplib::Response& res) { handle_new_nonce(st, q, res); });
        srv.Post(ip + "/new-account",
                 [&](const httplib::Request& q, httplib::Response& res) { handle_new_account(st, q, res); });
        srv.Post(ip + "/new-order",
                 [&](const httplib::Request& q, httplib::Response& res) { handle_new_order(st, q, res); });
        if (st.cfg.acme_new_authz)
            srv.Post(ip + "/new-authz",
                     [&](const httplib::Request& q, httplib::Response& res) { handle_new_authz(st, q, res); });
        reg_post(ip + R"(/account/(\d+))",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     handle_account(st, q, res, q.matches[2].str()); });
        reg_post(ip + R"(/account/(\d+)/orders)",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     handle_account_orders(st, q, res, q.matches[2].str()); });
        reg_post(ip + R"(/order/(\d+))",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     handle_order_get(st, q, res, q.matches[2].str()); });
        reg_post(ip + R"(/order/(\d+)/finalize)",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     handle_finalize(st, q, res, q.matches[2].str(), q.matches[1].str()); });
        reg_post(ip + R"(/authz/(\d+))",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     handle_authz_post(st, q, res, q.matches[2].str()); });
        reg_post(ip + R"(/chall/(\d+))",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     handle_chall_post(st, q, res, q.matches[2].str()); });
        reg_post(ip + R"(/cert/([0-9a-f]+))",
                 [&](const httplib::Request& q, httplib::Response& res) {
                     handle_cert(st, q, res, q.matches[2].str()); });
        srv.Post(ip + "/key-change",
                 [&](const httplib::Request& q, httplib::Response& res) { handle_key_change(st, q, res); });
        srv.Post(ip + "/revoke-cert",
                 [&](const httplib::Request& q, httplib::Response& res) { handle_revoke_cert(st, q, res); });

        std::string bound;
        if (!pki::bind_listener(srv, st.cfg.acme_bind_addr, st.cfg.acme_port, bound)) {
            std::cerr << "listen failed\n";
            return 1;
        }
        // Named after the bind: the wildcard falls back to IPv4 where there is no IPv6
        // stack, and announcing an address before it is bound can announce the wrong one.
        pki::log::info("fastpki-acme listening on " + bound + ":" +
                       std::to_string(st.cfg.acme_port));
        // Never open the port while this protocol is switched off in the
        // console, and stop if it is switched off later.
        pki::gate_protocol(*st.certs_db, "acme", &st.cfg,
                           [u = pki::listener_key_uri(st.cfg, st.cfg.acme_server_key_pem)] { return u; });
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
