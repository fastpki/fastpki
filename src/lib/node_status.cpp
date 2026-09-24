// Host self-reports and the Replication page's overview. See include/pki/node_status.hpp.

#include "pki/node_status.hpp"
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/log.hpp"
#include "pki/pg_tls.hpp"
#include "pki/pkcs11_helpers.hpp"
#include "pki/service_cert.hpp"
#include "pki/version.hpp"
#include "pki/x509.hpp"
#include "../../third_party/nlohmann/json.hpp"

#include <cstdlib>
#include <ctime>
#include <map>
#include <set>
#include <vector>

using json = nlohmann::json;

namespace pki {

namespace {

std::string env_str(const char* k) {
    const char* v = ::getenv(k);
    return v ? std::string(v) : std::string();
}

// A value from a libpq keyword=value conninfo, at a token boundary (so `host=` does not match
// `sslrootcert=`). Quoted values do not occur in the conninfo FastPKI writes.
std::string conninfo_get(const std::string& ci, const std::string& key) {
    size_t i = 0;
    while (i < ci.size()) {
        while (i < ci.size() && (ci[i] == ' ' || ci[i] == '\t' || ci[i] == '\n')) ++i;
        const size_t tok = i;
        while (i < ci.size() && ci[i] != ' ' && ci[i] != '\t' && ci[i] != '\n') ++i;
        const std::string t = ci.substr(tok, i - tok);
        const size_t eq = t.find('=');
        if (eq != std::string::npos && t.substr(0, eq) == key) return t.substr(eq + 1);
    }
    return {};
}

std::vector<std::string> split_commas(const std::string& v) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : v) {
        if (c == ',') { if (!cur.empty()) out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// The object label a key reference names — the first URL that names one. For a CA that is the
// key its newest row signs with.
std::string key_label(const std::string& key_ref) {
    for (const auto& u : split_key_urls(key_ref)) {
        std::string l = pkcs11_uri_attr(u, "object");
        if (!l.empty()) return l;
    }
    return {};
}

int64_t jint(const json& j, const char* k) {
    auto it = j.find(k);
    if (it == j.end() || !it->is_number()) return 0;
    return it->get<int64_t>();
}
std::string jstr(const json& j, const char* k) {
    auto it = j.find(k);
    if (it == j.end() || !it->is_string()) return {};
    return it->get<std::string>();
}
bool jbool(const json& j, const char* k) {
    auto it = j.find(k);
    return it != j.end() && it->is_boolean() && it->get<bool>();
}
const json& jobj(const json& j, const char* k) {
    static const json empty = json::object();
    auto it = j.find(k);
    return (it != j.end() && it->is_object()) ? *it : empty;
}
const json& jarr(const json& j, const char* k) {
    static const json empty = json::array();
    auto it = j.find(k);
    return (it != j.end() && it->is_array()) ? *it : empty;
}

} // namespace

std::string node_host_id(const Config& cfg) {
    const std::string b = env_str("PG_BIND");
    return b.empty() ? cfg.pki_dns : b;
}

std::string collect_node_report(const Config& cfg, Db& db) {
    json r;
    r["at"]         = static_cast<int64_t>(std::time(nullptr));
    r["version"]    = fastpki_version();
    r["pki_dns"]    = cfg.pki_dns;
    r["pg_bind"]    = env_str("PG_BIND");
    r["standby_of"] = env_str("STANDBY_OF");
    r["p11_tls"]    = env_str("P11_TLS") == "on";
    // Which platform the host runs on, for a reader of the report. NOTHING BRANCHES ON IT: every
    // deployment path has a token per server and the same key sync, so a refusal or a button
    // that depended on the platform would describe a difference that does not exist.
    // KUBERNETES_SERVICE_HOST is injected into every pod by the kubelet, so it is present by
    // construction rather than by configuration; `pg_bind` is not a substitute, being empty on
    // a standalone Compose host too.
    r["platform"]   = env_str("KUBERNETES_SERVICE_HOST").empty() ? "" : "kubernetes";

    // ── the database this host's services use ─────────────────────────────────────────
    json d;
    const auto server = db.connected_server();
    d["connected_host"] = server.first;
    d["connected_port"] = server.second;
    d["conninfo_hosts"] = split_commas(conninfo_get(cfg.pg_conninfo, "host"));
    d["sslmode"]        = conninfo_get(cfg.pg_conninfo, "sslmode");
    d["target_session_attrs"] = conninfo_get(cfg.pg_conninfo, "target_session_attrs");
    try {
        d["state"] = json::parse(db.replication_state_json());
    } catch (const std::exception& e) {
        d["state_error"] = e.what();
    }
    // Each host of the conninfo, verified the way this host's services would verify it after a
    // promotion. Empty when the conninfo names one host.
    json probes = json::array();
    try {
        for (const auto& p : probe_pg_hosts(cfg, 3))
            probes.push_back({{"host", p.host}, {"ok", p.ok}, {"tls_failure", p.tls_failure},
                              {"verifies", p.deployment_verifies}, {"detail", p.detail}});
    } catch (...) {}
    d["probes"] = probes;
    r["database"] = d;

    // ── the keys this host's token holds ──────────────────────────────────────────────
    json tok;
    std::map<std::string, bool> private_keys;   // label -> extractable
    bool readable = false;
    if (cfg.pkcs11_module.empty()) {
        tok["error"] = "PKCS11_MODULE is not set";
    } else {
        const auto o = pkcs11_list_objects(cfg.pkcs11_module, cfg.pkcs11_token,
                                           pkcs11_resolve_pin({}, cfg.pkcs11_pin_file));
        if (o.error.empty()) {
            readable = true;
            for (const auto& obj : o.objects)
                if (obj.klass == "private") private_keys[obj.label] = obj.extractable;
        } else {
            tok["error"] = o.error;
        }
    }
    tok["readable"] = readable;
    r["token"] = tok;

    // ⚠️ LISTED, NEVER LOADED. Whether a key under the label is the certificate's own is a
    // question only loading it answers, and this runs inside fastpki-web — on the reporter
    // thread as the console starts and on every Replication page request — beside the request
    // threads loading the same CA keys through the same pkcs11 provider. Loading keys here was
    // tried and measured under the sanitizer build: the console's CA key loads then failed with
    // "no private key found" for the life of the process, and once the process died on a null
    // pointer. `fastpki-ca key sync` makes that comparison in a process of its own, and replaces
    // a key that does not match, so this reports what the token lists and nothing more.
    const auto key_state = [&](const std::string& key_ref, json& e) {
        const std::string label = key_label(key_ref);
        e["object"] = label;
        if (!readable || label.empty()) { e["key"] = "unknown"; return; }
        const auto it = private_keys.find(label);
        if (it == private_keys.end()) { e["key"] = "missing"; return; }
        e["key"] = "present";
        e["extractable"] = it->second;
    };
    json cas = json::array();
    const auto instances = db.list_ca_instances();
    for (const auto& c : instances) {
        json e = {{"id", c.id}};
        if (c.signing_ca_key.empty()) e["key"] = "none";     // a trust anchor: nothing to hold
        else key_state(c.signing_ca_key, e);
        cas.push_back(std::move(e));
    }
    r["cas"] = cas;
    json creds = json::array();
    for (const auto& sc : configured_service_creds(cfg)) {
        // Issued at all? A credential with no certificate anywhere is not missing on this host,
        // it has not been created — the same distinction `key sync` makes.
        bool issued = false;
        for (const auto& inst : instances) {
            try {
                if (db.get_cert_by_cert_id(sc.prefix + "-" + inst.id)) { issued = true; break; }
            } catch (...) {}
        }
        json e = {{"prefix", sc.prefix}, {"name", sc.label}, {"issued", issued}};
        key_state(sc.key_ref, e);
        creds.push_back(std::move(e));
    }
    r["credentials"] = creds;
    return r.dump();
}

void publish_node_report(const Config& cfg, Db& db) {
    const std::string host = node_host_id(cfg);
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    std::string text = collect_node_report(cfg, db);

    // ⚠️ A SUBSCRIPTION'S ERROR COUNTERS ARE A LIFETIME TOTAL, and a page that only reads them
    // cannot tell "broken now" from "was broken once". pg_stat_subscription_stats counts since
    // the subscription was created or last reset, and carries no timestamp for the last error,
    // so a single fault in the morning warned for ever — measured: 115 sync errors from one
    // missing column, every table back at 'r', nothing in the log for hours, and the page still
    // red. What IS knowable is whether the number is still moving, and this host reports about
    // once a minute, so each report carries forward when the counts last changed.
    json rep = json::parse(text, nullptr, false);
    if (rep.is_object()) {
        json prev;
        try {
            for (const auto& n : db.list_node_status())
                if (n.host_id == host) { prev = json::parse(n.report, nullptr, false); break; }
        } catch (const std::exception&) { /* first report, or the table cannot be read */ }
        auto prev_sub = [&](const std::string& name) -> json {
            if (!prev.is_object()) return json();
            for (const auto& s : jarr(jobj(jobj(prev, "database"), "state"), "subscriptions"))
                if (jstr(s, "name") == name) return s;
            return json();
        };
        if (rep.contains("database") && rep["database"].is_object() &&
            rep["database"].contains("state") && rep["database"]["state"].is_object() &&
            rep["database"]["state"].contains("subscriptions") &&
            rep["database"]["state"]["subscriptions"].is_array()) {
            for (auto& s : rep["database"]["state"]["subscriptions"]) {
                const json p = prev_sub(jstr(s, "name"));
                const bool same = p.is_object() &&
                                  jint(p, "apply_errors") == jint(s, "apply_errors") &&
                                  jint(p, "sync_errors")  == jint(s, "sync_errors");
                // Unchanged: keep the moment they stopped moving. Changed, or never seen
                // before: that moment is now.
                s["errors_stable_since"] = same ? (jint(p, "errors_stable_since") > 0
                                                       ? jint(p, "errors_stable_since") : now)
                                                : now;
            }
            text = rep.dump();
        }
    }
    db.publish_node_report(host, cfg.datacenter_id, now, text);
}

std::string replication_overview_json(const Config& cfg, Db& db, const std::string& self,
                                      int64_t now) {
    json ov;
    ov["self"]      = self;
    ov["now"]       = now;
    ov["pgTlsCaId"] = cfg.pg_tls_ca_id;

    std::set<std::string> client, server;
    try { for (const auto& p : db.list_p11_transport_certs(false)) client.insert(p.first); } catch (...) {}
    try { for (const auto& p : db.list_p11_transport_certs(true))  server.insert(p.first); } catch (...) {}

    json nodes = json::array();
    for (const auto& n : db.list_node_status()) {
        json e;
        e["hostId"]         = n.host_id;
        e["dcId"]           = n.dc_id;
        e["reportedAt"]     = n.reported_at;
        e["keySyncAt"]      = n.key_sync_at;
        e["keySyncRequest"] = n.key_sync_request;
        e["requestedAt"]    = n.requested_at;
        e["requestedBy"]    = n.requested_by;
        e["transport"]      = {{"client", client.count(n.host_id) > 0},
                               {"server", server.count(n.host_id) > 0}};
        // A row that does not parse is shown as absent rather than failing the whole page.
        try { e["report"]  = n.report.empty()   ? json(nullptr) : json::parse(n.report); }
        catch (...) { e["report"] = nullptr; }
        try { e["keySync"] = n.key_sync.empty() ? json(nullptr) : json::parse(n.key_sync); }
        catch (...) { e["keySync"] = nullptr; }
        nodes.push_back(std::move(e));
    }
    ov["nodes"] = nodes;

    json dcs = json::array();
    try {
        for (const auto& [dc, url] : db.list_datacenter_base_urls())
            dcs.push_back({{"dcId", dc}, {"baseUrl", url}});
    } catch (...) {}
    ov["datacenters"] = dcs;

    ov["warnings"] = json::parse(replication_warnings_json(ov.dump(), now));
    return ov.dump();
}

std::string key_sync_running_json(int64_t now, int64_t request, const std::string& by) {
    return json{{"at", now}, {"state", "running"}, {"request", request}, {"by", by}}.dump();
}

std::string key_sync_refused_json(int64_t now, int64_t request, const std::string& by,
                                  const std::string& why) {
    return json{{"at", now}, {"state", "refused"}, {"rc", -1}, {"message", why},
                {"request", request}, {"by", by}}.dump();
}

std::string key_sync_finished_json(const std::string& recorded, int64_t started, int rc,
                                   const std::string& output, int64_t request,
                                   const std::string& by, int64_t now) {
    json r;
    // fastpki-ca's own record of this run, when it wrote one after we started it. Otherwise it
    // could not start or could not reach the database, and the exit code and output are all
    // there is.
    try {
        const json j = json::parse(recorded);
        if (j.is_object() && j.contains("rc") && !j.contains("state") && jint(j, "at") >= started)
            r = j;
    } catch (...) {}
    if (!r.is_object()) r = {{"at", now}, {"rc", rc}, {"failed_ids", json::array()}};
    r["state"]   = "finished";
    r["exit"]    = rc;
    r["request"] = request;
    r["by"]      = by;
    // Output is text from fastpki-ca; keep the tail, which is where the verdict is. Invalid
    // UTF-8 would make the whole record unserialisable, so the dump replaces it.
    r["output"] = output.size() > 8192 ? output.substr(output.size() - 8192) : output;
    return r.dump(-1, ' ', false, json::error_handler_t::replace);
}

std::string key_sync_refusal(const std::string& report_json) {
    json r;
    try { r = json::parse(report_json); } catch (...) { return "this host has not reported"; }
    // ⚠️ NOT "ONLY A STANDBY". Key sync copies what this host is missing from the other hosts of
    // its data center, and a primary can be missing a key a standby minted — so the only
    // host with nothing to do is one with no token tunnel to copy over.
    if (!jbool(r, "p11_tls"))
        return "this host has P11_TLS off, so it has no token tunnel to copy keys over";
    return {};
}

std::string replication_warnings_json(const std::string& overview_json, int64_t now) {
    const json ov = json::parse(overview_json);
    json out = json::array();
    const auto warn = [&](const char* severity, const std::string& host, const std::string& msg) {
        out.push_back({{"severity", severity}, {"host", host}, {"message", msg}});
    };
    // A host that has not reported for this long has a console that is down, or cannot write to
    // the database — either way everything below about it is out of date.
    constexpr int64_t kStaleSec = 300;
    constexpr double  kLagSec   = 60.0;

    // What has already been said, so a fact both hosts of a pair report is stated once. Keyed
    // by data center, because that is the scope a shared catalogue belongs to.
    std::set<std::string> said;

    // Hosts that have reported, grouped by data center. An HA pair is two hosts in ONE data
    // center (they share DATACENTER_ID), or a host that says it follows another.
    std::map<std::string, std::vector<const json*>> groups;
    for (const auto& n : jarr(ov, "nodes")) {
        if (!n.is_object() || !n.contains("report") || !n["report"].is_object()) continue;
        groups[jstr(n, "dcId")].push_back(&n);
    }

    for (const auto& [dc, hosts] : groups) {
        bool pair = hosts.size() >= 2;
        for (const json* h : hosts)
            if (!jstr((*h)["report"], "standby_of").empty()) pair = true;

        for (const json* hp : hosts) {
            const json& h = *hp;
            const std::string host = jstr(h, "hostId");
            const json& R = h["report"];
            const json& D = jobj(R, "database");
            const json& S = jobj(D, "state");

            const int64_t age = now - jint(h, "reportedAt");
            if (age > kStaleSec)
                warn("warning", host, "has not reported for " + std::to_string(age / 60) +
                     " minutes. Its console is not running, or cannot write to the database, so "
                     "what this page shows about it is out of date.");

            // Mesh subscriptions, on any host that has them.
            for (const auto& s : jarr(S, "subscriptions")) {
                const std::string name = jstr(s, "name");
                if (!jbool(s, "enabled"))
                    warn("error", host, "subscription " + name + " is disabled: nothing from that "
                         "data center arrives here.");
                else if (!jbool(s, "worker"))
                    warn("error", host, "subscription " + name + " has no running apply worker, "
                         "so nothing from that data center is arriving. Check this node's "
                         "Postgres log for the error that stopped it.");
                // ⚠️ THESE ARE LIFETIME TOTALS, AND BOTH HOSTS OF A PAIR REPORT THE SAME ONES —
                // a standby is a physical copy of the primary's catalogue. So warn once per
                // data center, and say whether the number is still MOVING: the counter carries
                // no timestamp, and a fault fixed hours ago otherwise warns for ever with
                // nothing to distinguish it from one happening now.
                if ((jint(s, "apply_errors") > 0 || jint(s, "sync_errors") > 0) &&
                    said.insert("suberr|" + dc + "|" + name).second) {
                    const std::string counts = std::to_string(jint(s, "apply_errors")) +
                        " apply and " + std::to_string(jint(s, "sync_errors")) + " sync errors";
                    const int64_t stable = jint(s, "errors_stable_since");
                    const int64_t quiet = (stable > 0 && now > stable) ? (now - stable) : 0;
                    if (quiet >= 600)
                        warn("warning", host, "subscription " + name + " has recorded " + counts +
                             " in its lifetime, none in the last " + std::to_string(quiet / 60) +
                             " minutes. That is history unless something else here says otherwise: "
                             "the counter runs from when the subscription was created and is only "
                             "cleared by pg_stat_reset_subscription_stats().");
                    else
                        warn("error", host, "subscription " + name + " has recorded " + counts +
                             ", and the count is still rising — replication from that data center "
                             "is failing now. This node's Postgres log has the reason.");
                }
                const int64_t last = jint(s, "last_msg_receipt");
                if (jbool(s, "enabled") && last > 0 && now - last > 600)
                    warn("warning", host, "subscription " + name + " last heard from its "
                         "publisher " + std::to_string((now - last) / 60) + " minutes ago.");
            }

            if (!pair) continue;

            // ── the silent failures docs/high-availability.md describes ──────────────────────────────
            const std::string pg_bind = jstr(R, "pg_bind");
            if (pg_bind.empty())
                warn("error", host, "PG_BIND is not set. The two hosts of a pair share PKI_DNS, "
                     "so both publish their token-transport certificates under that one name, "
                     "the second overwrites the first, and no key can be copied between them.");
            std::vector<std::string> ci_hosts;
            for (const auto& x : jarr(D, "conninfo_hosts"))
                if (x.is_string()) ci_hosts.push_back(x.get<std::string>());
            if (ci_hosts.size() < 2)
                warn("error", host, "PG_CONNINFO names only one database host, so this host's "
                     "services cannot follow a promotion to the other.");
            bool own_verifies = false;
            for (const auto& p : jarr(D, "probes")) {
                const std::string ph = jstr(p, "host");
                if (ph == pg_bind && jbool(p, "ok")) own_verifies = true;
                if (!jbool(p, "ok") && jbool(p, "tls_failure"))
                    warn(jbool(p, "verifies") ? "error" : "warning", host,
                         "the database on " + ph + " presents a certificate this host's services "
                         "cannot verify (" + jstr(p, "detail") + "). If that host is promoted, "
                         "every service fails to connect to it — issue its certificate with "
                         "fastpki-ca pg-tls.");
            }
            // ⚠️ A LOOPBACK FIRST ENTRY ALREADY IS "THIS HOST FIRST", and comparing by NAME
            // could not see that. `127.0.0.1` is not the string `fastpki-node-0.fastpki-node`, so this
            // warned on every healthy Kubernetes server, for ever, and its remedy was wrong
            // twice over: the loopback entry is what lets a pod reach its own database when
            // cluster DNS is down (the case that occurred when the lost node also ran
            // CoreDNS), and every pod shares one PG_CONNINFO from the fastpki-bootstrap ConfigMap, so
            // `127.0.0.1` is the only spelling that means "this host" on all of them at once.
            //
            // A warning that is always present on a healthy deployment teaches operators to
            // skim the page where the real ones appear.
            const auto loopback_first = [](const std::string& h) {
                return h == "127.0.0.1" || h == "::1" || h == "[::1]" || h == "localhost";
            };
            if (own_verifies && ci_hosts.size() >= 2 && ci_hosts.front() != pg_bind &&
                !loopback_first(ci_hosts.front()))
                warn("warning", host, "PG_CONNINFO lists " + ci_hosts.front() + " first. Now that "
                     "this host's own database certificate verifies, list this host first, so a "
                     "peer that is being rebuilt cannot take this host's tools down with it.");
            if (jbool(R, "p11_tls")) {
                const json& t = jobj(h, "transport");
                if (!jbool(t, "client") || !jbool(t, "server"))
                    warn("warning", host, "has not published both of its token-transport "
                         "certificates, so the other host cannot admit it and key sync cannot "
                         "copy keys to or from it.");
            }
            const json& tok = jobj(R, "token");
            if (!jbool(tok, "readable"))
                warn("warning", host, "could not list its token (" + jstr(tok, "error") +
                     "), so its key copies below are unknown.");
            for (const auto& c : jarr(R, "cas"))
                if (jstr(c, "key") == "missing")
                    warn("error", host, "has no key for CA '" + jstr(c, "id") + "' in its token: "
                         "it cannot issue under that CA, and neither could it after a promotion. "
                         "Key sync copies it.");
            for (const auto& c : jarr(R, "credentials"))
                if (jbool(c, "issued") && jstr(c, "key") == "missing")
                    warn("error", host, "has no key for the " + jstr(c, "name") + " credential in "
                         "its token. While this host serves, or after it is promoted, that "
                         "protocol refuses every request. Key sync copies it.");

            // Whichever host ran it: every host of a pair syncs from the others, so a primary's
            // failed run leaves keys out of the token that is serving now.
            const json& ks = h.contains("keySync") ? h["keySync"] : json(nullptr);
            if (ks.is_object() && ks.contains("rc") && jint(ks, "rc") != 0) {
                std::string ids;
                for (const auto& x : jarr(ks, "failed_ids"))
                    if (x.is_string()) ids += (ids.empty() ? "" : ", ") + x.get<std::string>();
                warn(jint(ks, "rc") == 2 ? "error" : "warning", host,
                     std::string("its last key sync ") +
                     (jint(ks, "rc") == 2 ? "failed for keys that were created without replicable "
                                            "key and can never be copied"
                                          : "did not complete") +
                     (ids.empty() ? std::string(".") : ": " + ids + "."));
            }
        }

        if (!pair) continue;
        const std::string first = hosts.empty() ? std::string() : jstr(*hosts.front(), "hostId");

        // A key only some hosts hold, minted where it cannot be copied.
        std::map<std::string, std::vector<std::string>> missing_on, fixed_on;
        for (const json* hp : hosts) {
            const std::string host = jstr(*hp, "hostId");
            for (const auto& c : jarr((*hp)["report"], "cas")) {
                const std::string st = jstr(c, "key");
                if (st == "missing") missing_on[jstr(c, "id")].push_back(host);
                if (st == "present" && !jbool(c, "extractable")) fixed_on[jstr(c, "id")].push_back(host);
            }
        }
        for (const auto& [ca, where] : fixed_on) {
            auto m = missing_on.find(ca);
            if (m == missing_on.end()) continue;
            std::string to;
            for (const auto& x : m->second) to += (to.empty() ? "" : ", ") + x;
            warn("error", where.front(), "CA '" + ca + "' has a key that was created without "
                 "replicable key, so it can never be copied to " + to + ". That host cannot "
                 "sign under this CA, before or after a promotion.");
        }

        if (jstr(ov, "pgTlsCaId").empty())
            warn("warning", first, "PG_TLS_CA_ID is not set, so neither host of this pair renews "
                 "its database certificate on its own (docs/high-availability.md §3).");

        // Streaming, as the primary sees it. Every host of a pair reaches the primary, so any
        // host's report that came from a server not in recovery carries the list.
        bool saw_primary = false, streaming = false, hidden = false;
        for (const json* hp : hosts) {
            const json& S = jobj(jobj((*hp)["report"], "database"), "state");
            if (S.empty() || jbool(S, "in_recovery")) continue;
            saw_primary = true;
            for (const auto& rep : jarr(S, "replication")) {
                if (rep.contains("state") && rep["state"].is_null()) hidden = true;
                if (jstr(rep, "state") == "streaming") {
                    streaming = true;
                    const auto lag = rep.find("replay_lag");
                    if (lag != rep.end() && lag->is_number() && lag->get<double>() > kLagSec)
                        warn("warning", first, "the standby at " + jstr(rep, "client_addr") +
                             " is replaying " + std::to_string(static_cast<int>(lag->get<double>())) +
                             "s behind the primary.");
                }
            }
        }
        if (hidden)
            warn("warning", first, "the database role cannot read pg_stat_replication, so the "
                 "standby's state is hidden. Grant it pg_read_all_stats to see it here.");
        else if (saw_primary && !streaming)
            warn("error", first, "no standby is streaming from this data center's primary. A "
                 "promotion now would lose the database.");
    }
    return out.dump();
}

} // namespace pki
