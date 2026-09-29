#include "pki/endpoint_gate.hpp"
#include "pki/pkcs11_helpers.hpp"
#include <openssl/provider.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <memory>
#include <thread>
#include <vector>

#include <openssl/evp.h>

#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/x509.hpp"
#include "pki/log.hpp"

namespace pki {
namespace {

// How often the flag is re-read. Long enough to be free at rest, short enough that a
// console toggle feels immediate rather than like nothing happened.
constexpr auto kPoll = std::chrono::seconds(10);

bool truthy(std::string v) {
    std::transform(v.begin(), v.end(), v.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return !(v == "0" || v == "false" || v == "no" || v == "off");
}

// Read the flag straight from the database rather than from the process's Config: the
// whole point is to notice a change made after this process started.
bool enabled_now(Db& db, const std::string& key) {
    try {
        const auto cfg = db.get_config();
        const auto it = cfg.find(key);
        return it == cfg.end() || truthy(it->second);
    } catch (...) {
        // A database blip must not take a healthy listener down. Staying up is the
        // safe failure here — the operator can always try again.
        return true;
    }
}


// Can this token key still SIGN? Loading is not enough — the OpenSSL pkcs11
// provider serves a load from its own cache and still returns a key after the token has
// gone, which is how the first version of this probe reported healthy on a listener that
// could not complete a handshake. Only an operation that must reach the token tells the
// truth.
bool token_key_usable(const Config& cfg, const std::string& uri) {
    try { return key_usable(load_key_file_or_token(uri, cfg).get()); }
    catch (...) { return false; }
}

void token_died(const std::string& label, const std::string& uri) {
    // ⚠️ REDACTED. RFC 7512 allows pin-value= in the URI, and this is an err-level line —
    // it reaches the log at every level, so a deployment that puts the PIN in the handle
    // published it the moment the sidecar restarted.
    log::err(label + ": the PKCS#11 token key " + pkcs11_uri_redacted(uri) +
             " can no longer be used — the token or its sidecar has restarted, so this "
             "PROCESS's provider connection is dead. Reloading cannot fix it: the PKCS#11 "
             "module is initialised once per process. Stopping so the restart policy "
             "brings us back with a fresh one.");
    std::_Exit(0);
}

// Is this handle a key the pkcs11 provider owns? A file-backed key cannot lose a session,
// so a signing failure on one is an ordinary error and must stay one.
bool is_p11_key(EVP_PKEY* key) {
    if (!key) return false;
    const OSSL_PROVIDER* prov = EVP_PKEY_get0_provider(key);
    if (!prov) return false;
    const char* name = OSSL_PROVIDER_get0_name(prov);
    return name && std::string(name) == "pkcs11";
}

} // namespace

void exit_if_token_died(EVP_PKEY* key, const std::string& where) {
    if (!is_p11_key(key)) return;          // file key, or no key: nothing to diagnose
    if (key_usable(key)) return;           // the token is fine; this was a real signing error
    log::err(where + ": signing with the PKCS#11 token key failed and the token can no "
             "longer sign at all — the token or its sidecar has restarted, so this "
             "PROCESS's provider connection is dead. The PKCS#11 module is initialised "
             "once per process, so no reload can recover it. Stopping so the restart "
             "policy brings us back with a fresh connection; this request is lost.");
    std::_Exit(0);
}

std::string endpoint_enabled_key(const std::string& proto) {
    std::string k = proto;
    std::transform(k.begin(), k.end(), k.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return k + "_ENABLED";
}

std::string endpoint_restart_key(const std::string& proto) {
    std::string k = proto;
    std::transform(k.begin(), k.end(), k.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return k + "_RESTART_AT";
}

std::string endpoint_started_key(const std::string& proto) {
    std::string k = proto;
    std::transform(k.begin(), k.end(), k.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return k + "_STARTED_AT";
}

// "__UNSET__" is not a shape any config key has: every real one is
// SCREAMING_SNAKE with single underscores, so a doubled-underscore sentinel cannot
// collide with one and cannot be mistaken for a setting an operator could edit.
static const char* kUnsetPrefix = "__UNSET__";

std::string config_unset_key(const std::string& key) {
    return std::string(kUnsetPrefix) + key;
}

std::string config_unset_key_target(const std::string& key) {
    const std::string p = kUnsetPrefix;
    if (key.size() <= p.size() || key.compare(0, p.size(), p) != 0) return {};
    return key.substr(p.size());
}

bool endpoint_enabled(const std::map<std::string, std::string>& cfg_values,
                      const std::string& proto) {
    const auto it = cfg_values.find(endpoint_enabled_key(proto));
    return it == cfg_values.end() || truthy(it->second);
}

void gate_protocol(Db& db, const std::string& proto,
                   const Config* app_cfg, std::function<std::string()> token_key_uri,
                   std::function<void()> on_key_live) {
    const std::string key = endpoint_enabled_key(proto);
    const std::string rkey = endpoint_restart_key(proto);
    // Anything stamped at or before this instant is a restart we have already
    // served, so a marker left in the table by an earlier run cannot loop us.
    const int64_t started = static_cast<int64_t>(std::time(nullptr));

    // Blocked start: never open the port while switched off.
    bool announced = false;
    while (!enabled_now(db, key)) {
        if (!announced) {
            log::info(proto + " is switched off (" + key + "=false) — not listening. "
                      "Re-enable it in the console; this takes effect within " +
                      std::to_string(kPoll.count()) + "s, no restart needed.");
            announced = true;
        }
        std::this_thread::sleep_for(kPoll);
    }
    if (announced) log::info(proto + " switched back on — starting the listener");

    // Stamp the moment this process's gate opened, so the console can tell whether
    // a setting change has actually reached the process that reads it. Written HERE and
    // not at entry: `started` above is when we began waiting, and a process blocked on
    // the off-switch has not started serving anything.
    //
    // A database blip must not stop a listener from coming up — the whole gate is written
    // that way — so this is best-effort. A missing stamp reads as "this process has not
    // reported a start", which the console treats as "not running", not as "up to date".
    try {
        db.set_config(endpoint_started_key(proto),
                      std::to_string(static_cast<int64_t>(std::time(nullptr))));
    } catch (const std::exception& e) {
        log::info(proto + ": could not record the start marker (" + e.what() +
                  ") — the Config page cannot show whether this process has picked up a "
                  "setting change until it starts again.");
    }

    // Running: exit when switched off, so the restart policy brings us back to the
    // block above with the port closed. Detached because it outlives this call and
    // owns nothing that needs unwinding.
    std::thread([&db, key, rkey, proto, started, app_cfg, token_key_uri, on_key_live] {
        // ⚠️ "NEVER THERE" IS NOT "DIED", AND ONLY ONE OF THEM IS WORTH EXITING FOR.
        // token_key_usable() is false for both an absent key and a dead provider session,
        // and treating them alike turns every FRESH deployment into a crash loop: a
        // service credential cannot exist until a CA does, the CAs are created after the
        // deployment comes up, so the key this probe is watching is legitimately absent
        // for the first minutes of a deployment's life. Exiting there does not heal
        // anything — the restart policy hands back a process whose key is still absent —
        // it just replaces a clear log line with a flapping pod. Measured on a fresh
        // three-cluster mesh, where fastpki-scep alone crash-looped while ocsp and cmp, which
        // degrade instead, stayed up and reported the real problem.
        //
        // So the exit is armed only by a key that HAS worked in this process. That is
        // exactly the case the probe was written for: a live SSL_CTX whose session the
        // sidecar has since restarted underneath.
        bool ever_usable      = false;
        bool absent_announced = false;
        for (;;) {
            std::this_thread::sleep_for(kPoll);

            // Is the token still there? A dead handle is invisible from the
            // outside — the listener keeps accepting and every handshake fails inside
            // the provider — so the only way to notice is to try using it.
            //
            // Exit rather than attempt a reload: the key is already wired into a live
            // SSL_CTX that this process cannot rebuild underneath its own listener, and
            // the restart policy gives us a clean one for free. Same crash-only
            // reasoning as the two checks below.
            // See token_key_usable(). Exit rather than reload: the key is
            // already wired into a live SSL_CTX this process cannot rebuild under its
            // own listener, and the restart policy gives us a clean one for free.
            // ⚠️ ASKED FOR EACH POLL. Freezing this at startup meant a process that acquires
            // its credential later — cmp, whose RA key can be replicated into the token
            // minutes after boot — never armed the probe at all, and so kept a stale handle
            // across a sidecar restart instead of exiting for a fresh one. An empty string
            // still means "nothing to watch yet", which is what keeps a fresh install from
            // crash-looping on a key that legitimately does not exist.
            const std::string uri = token_key_uri ? token_key_uri() : std::string{};
            const bool probe_token = app_cfg != nullptr && uri.rfind("pkcs11:", 0) == 0;
            if (probe_token) {
                bool usable = token_key_usable(*app_cfg, uri);
                if (usable) {
                    ever_usable      = true;
                    absent_announced = false;
                    if (on_key_live) on_key_live();
                } else if (!ever_usable) {
                    // Absent, not dead: say so once and keep serving. Every request that
                    // needs this key still fails, with its own message naming what it
                    // could not do — which is information, where a restart loop is none.
                    // ⚠️ DO NOT NAME ONE CAUSE WHEN THERE ARE TWO. token_key_usable() is
                    // false both for "no object under that label" and for "the token did
                    // not answer just now" — and this line asserted the first, telling the
                    // operator to run --create-missing. Measured on a live pair: three
                    // listeners logged exactly this while their keys WERE in the token
                    // (pkcs11-tool listed all of them), after nine containers started at
                    // once and contended for the p11-kit server. The suggested command
                    // would have minted nothing, and the real cause went unstated.
                    if (!absent_announced) {
                        log::err(proto + ": no usable key at " +
                                 pkcs11_uri_redacted(uri) +
                                 " yet. Either it has not been created — `fastpki-ca "
                                 "renew-service-certs --create-missing` creates it once a "
                                 "signing CA exists — or the token did not answer this "
                                 "probe, which happens when many processes open it at "
                                 "once. `pkcs11-tool --list-objects` says which. Serving "
                                 "without it; requests that need it will be refused until "
                                 "it is there.");
                        absent_announced = true;
                    }
                } else {
                    // ⚠️ REDACTED, for the same reason as token_died() eleven lines into
                    // this file: RFC 7512 permits pin-value= in the handle, and this is an
                    // err-level line, so it reaches the log at every level. This site
                    // printed the URI verbatim while the function it calls on the very next
                    // line redacted it — the PIN was published by whichever of the two
                    // logged first.
                    log::err(proto + ": token probe failed for " +
                             pkcs11_uri_redacted(uri) +
                             " — the key can no longer sign.  Stopping.");
                    token_died(proto, uri);
                }
            }
            // The probe above creates a FRESH OSSL_STORE session, so it sees a
            // live token even after a sidecar restart — while the caller's in-memory
            // key handle is from the old (dead) session.  on_key_live lets the caller
            // reload its handle from a session that matches the one the probe just
            // confirmed works.

            // ONE config read serves both checks. Two would double the query rate of
            // every endpoint for no benefit, and could see the two keys at different
            // instants.
            std::map<std::string, std::string> cfg;
            try { cfg = db.get_config(); }
            catch (...) { continue; }   // a database blip must not take a listener down

            const auto e = cfg.find(key);
            if (e != cfg.end() && !truthy(e->second)) {
                log::info(proto + " was switched off in the console — stopping. It will "
                          "come back up idle, with its port closed, until re-enabled.");
                // _Exit, not exit: other worker threads may be mid-request and running
                // static destructors under them is how you get a crash instead of a
                // clean stop. Same reasoning as /api/restart.
                std::_Exit(0);
            }

            const auto r = cfg.find(rkey);
            if (r != cfg.end() && std::atoll(r->second.c_str()) > started) {
                log::info(proto + " restart requested in the console — stopping so the "
                          "restart policy brings it straight back up.");
                std::_Exit(0);
            }
        }
    }).detach();
}

void watch_token_key(const Config& cfg, const std::string& token_key_uri,
                     const std::string& label) {
    if (token_key_uri.rfind("pkcs11:", 0) != 0) return;   // a file cannot lose a session
    std::thread([&cfg, token_key_uri, label] {
        // ⚠️ "NEVER THERE" IS NOT "DIED" — the same rule gate_protocol's watcher states at
        // length, and this function was the one place that did not follow it. Exiting for a
        // key that has never worked cannot heal anything: the restart policy hands back a
        // process whose key is still absent. Measured on a fresh single-node install, where
        // a URI naming an object that did not exist put the console into a ten-second
        // restart loop while every other service stayed up and served.
        //
        // So the exit is armed only by a key that HAS worked in THIS process, which is
        // exactly the case the probe exists for: a live handle whose provider session the
        // sidecar has since restarted underneath. Until then an unusable key is reported
        // once and polled on.
        bool ever_usable = false, warned = false;
        for (;;) {
            std::this_thread::sleep_for(kPoll);
            if (token_key_usable(cfg, token_key_uri)) { ever_usable = true; warned = false; continue; }
            if (ever_usable) token_died(label, token_key_uri);
            if (!warned) {
                warned = true;
                log::err(label + ": the token key " + pkcs11_uri_redacted(token_key_uri) +
                          " is not usable yet. This is normal before the CA that signs this "
                          "node's credentials exists; it is a misconfiguration only if it "
                          "persists once one does.");
            }
        }
    }).detach();
}

} // namespace pki
