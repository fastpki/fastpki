// fastpki-mcp — Model Context Protocol server for the PKI.
//
// Exposes the FastPKI inventory to MCP clients (agents, IDEs) over the
// stdio transport: newline-delimited JSON-RPC 2.0 on stdin/stdout. This first
// slice is strictly READ-ONLY — it surfaces the same data as the web console
// as MCP *tools*, so an agent can answer "which certs expire this
// week?" or "is serial <x> revoked?" without write access. Issuance/revocation
// tools are a later slice and would sit behind explicit auth.
//
//   fastpki-mcp --config bootstrap.conf      # speaks MCP on stdin/stdout
//
// Protocol: each line on stdin is one JSON-RPC request; each response is one
// line on stdout. Implements initialize, tools/list, tools/call. Logs go to
// stderr only (stdout is reserved for protocol frames).

#include "pki/audit.hpp"
#include "pki/version.hpp"
#include "pki/config.hpp"
#include "pki/license.hpp"
#include "pki/db.hpp"
#include "pki/error.hpp"
#include "pki/x509.hpp"   // revocation_reason_refusal

#include "../../third_party/nlohmann/json.hpp"

#include <cctype>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <memory>
#include <string>

using json = nlohmann::json;

namespace {

std::unique_ptr<pki::Db> open_db(const pki::Config& cfg) {
    return pki::make_postgres_db(cfg.pg_conninfo);
}

std::string rfc3339(int64_t t) {
    if (t <= 0) return "";
    std::time_t tt = static_cast<std::time_t>(t); std::tm tm{};
    gmtime_r(&tt, &tm);
    char buf[32]; std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// The console's labels: `on_hold` is a revocation with reason certificateHold; status 2 is
// a CMP certificate waiting for the client's certConf.
const char* cert_status_text(int s, int reason) {
    switch (s) {
        case 0:  return "valid";
        case 1:  return "expired";
        case -1: return reason == pki::kReasonCertificateHold ? "on_hold" : "revoked";
        case 2:  return "pending";
        case 3:  return "superseded";
        default: return "unknown";
    }
}

int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

int clamp_int(const json& v, int def, int lo, int hi) {
    if (!v.is_number_integer()) return def;
    int x = v.get<int>();
    return x < lo ? lo : (x > hi ? hi : x);
}

json cert_brief(const pki::CertRow& r) {
    return json{{"serial", r.serial}, {"cn", r.cn}, {"subject", r.subject},
                {"owner", r.owner},
                {"status", cert_status_text(r.status, r.revocation_reason)},
                {"notBefore", rfc3339(r.not_before)}, {"notAfter", rfc3339(r.not_after)},
                {"fingerprint", r.fingerprint}};
}

// ── tool definitions (advertised by tools/list) ────────────────────────────
json tool_defs(bool allow_write) {
    auto paged = json{{"type", "object"}, {"properties", json{
        {"limit",  json{{"type", "integer"}, {"description", "max rows (1-500, default 50)"}}},
        {"offset", json{{"type", "integer"}, {"description", "rows to skip (default 0)"}}}}}};
    json tools = json::array({
        json{{"name", "list_certificates"},
             {"description", "List managed certificates (newest first), with status and validity."},
             {"inputSchema", paged}},
        json{{"name", "get_certificate"},
             {"description", "Get one managed certificate by hex serial, including SANs/issuer detail."},
             {"inputSchema", json{{"type", "object"},
                 {"properties", json{{"serial", json{{"type", "string"},
                     {"description", "lowercase hex serial"}}}}},
                 {"required", json::array({"serial"})}}}},
        json{{"name", "list_expiring"},
             {"description", "List valid certificates expiring within N days (default 30)."},
             {"inputSchema", json{{"type", "object"}, {"properties", json{
                 {"days", json{{"type", "integer"}, {"description", "window in days (default 30)"}}}}}}}},
        json{{"name", "list_discovered"},
             {"description", "List discovered (unmanaged) certificates harvested from the network."},
             {"inputSchema", paged}},
        json{{"name", "list_audit"},
             {"description", "List the tamper-evident audit log, newest first."},
             {"inputSchema", paged}},
        json{{"name", "summary"},
             {"description", "Headline counts: managed certs, audit entries, discovered certs."},
             {"inputSchema", json{{"type", "object"}, {"properties", json::object()}}}},
    });
    // Write tools: advertised only when MCP_ALLOW_WRITE is set.
    if (allow_write) {
        tools.push_back(json{{"name", "revoke_certificate"},
            {"description", "Revoke a managed certificate by hex serial (sets it revoked so OCSP/CRL reflect it). Audited."},
            {"inputSchema", json{{"type", "object"},
                {"properties", json{
                    {"serial", json{{"type", "string"}, {"description", "lowercase hex serial"}}},
                    {"reason", json{{"type", "integer"}, {"description", "RFC 5280 CRLReason (default 0): 0-6 or 9; 6 certificateHold can be released from the console"}}}}},
                {"required", json::array({"serial"})}}}});
    }
    return tools;
}

// Run a tool, returning the result text (JSON, pretty-ish). Throws on bad input.
std::string run_tool(pki::Db& db, bool allow_write, const std::string& name, const json& args) {
    if (name == "revoke_certificate") {
        if (!allow_write) throw pki::Error(1, "writes are disabled (set MCP_ALLOW_WRITE=true)");
        std::string serial = args.value("serial", "");
        for (auto& c : serial) c = static_cast<char>(std::tolower((unsigned char)c));
        if (serial.empty()) throw pki::Error(1, "serial is required");
        auto row = db.get_cert(serial);
        if (!row) return json{{"error", "no such serial"}, {"serial", serial}}.dump(2);
        const json rv = args.value("reason", json(0));
        const int reason = rv.is_number_integer() ? rv.get<int>() : -1;
        if (const std::string why = pki::revocation_reason_refusal(reason); !why.empty())
            throw pki::Error(1, why);
        // Already revoked for good, or on hold and asked to hold again. A certificate on
        // hold is revoked for good by any other reason.
        if (!db.revoke_cert(serial, reason, now_unix()))
            return json{{"serial", serial},
                        {"status", cert_status_text(row->status, row->revocation_reason)},
                        {"alreadyRevoked", true}}.dump(2);
        try {
            pki::AuditEvent ev;
            ev.category = pki::audit_cat::kLifecycle;
            ev.action   = "mcp_cert_revoked";
            ev.target   = serial;
            ev.status   = pki::audit_status::kSuccess;
            ev.detail   = "iface=mcp reason=" + std::to_string(reason);
            db.append_audit(ev);
        } catch (...) {}
        return json{{"serial", serial},
                    {"status", reason == pki::kReasonCertificateHold ? "on_hold" : "revoked"},
                    {"reason", reason}}.dump(2);
    }
    if (name == "list_certificates") {
        int limit = clamp_int(args.value("limit", json{}), 50, 1, 500);
        int offset = clamp_int(args.value("offset", json{}), 0, 0, 1000000);
        json out = json::array();
        for (const auto& r : db.list_certs(limit, offset)) out.push_back(cert_brief(r));
        return out.dump(2);
    }
    if (name == "get_certificate") {
        std::string serial = args.value("serial", "");
        for (auto& c : serial) c = static_cast<char>(std::tolower((unsigned char)c));
        if (serial.empty()) throw pki::Error(1, "serial is required");
        auto row = db.get_cert(serial);
        if (!row) return json{{"error", "no such serial"}, {"serial", serial}}.dump(2);
        json j = cert_brief(*row);
        j["revocationReason"] = row->revocation_reason;
        j["revocationDate"] = rfc3339(row->revocation_date);
        return j.dump(2);
    }
    if (name == "list_expiring") {
        int days = clamp_int(args.value("days", json{}), 30, 1, 3650);
        json out = json::array();
        for (const auto& e : db.get_expiring_certs(now_unix() + int64_t(days) * 86400)) {
            int64_t left = (e.not_after - now_unix()) / 86400;
            out.push_back(json{{"serial", e.serial_hex}, {"cn", e.cn}, {"owner", e.owner},
                               {"notAfter", rfc3339(e.not_after)}, {"daysLeft", left}});
        }
        return out.dump(2);
    }
    if (name == "list_discovered") {
        int limit = clamp_int(args.value("limit", json{}), 50, 1, 500);
        int offset = clamp_int(args.value("offset", json{}), 0, 0, 1000000);
        json out = json::array();
        for (const auto& d : db.list_discovered(limit, offset))
            out.push_back(json{{"target", d.target}, {"subject", d.subject}, {"issuer", d.issuer},
                               {"keyAlgo", d.key_algo}, {"keyBits", d.key_bits},
                               {"sigAlgo", d.sig_algo}, {"notAfter", rfc3339(d.not_after)},
                               {"flags", d.flags}, {"fingerprint", d.fingerprint}});
        return out.dump(2);
    }
    if (name == "list_audit") {
        int limit = clamp_int(args.value("limit", json{}), 50, 1, 500);
        int offset = clamp_int(args.value("offset", json{}), 0, 0, 1000000);
        json out = json::array();
        for (const auto& r : db.list_audit_desc(limit, offset))
            out.push_back(json{{"seq", r.seq}, {"ts", rfc3339(r.ev.ts)},
                               {"category", r.ev.category}, {"action", r.ev.action},
                               {"actor", r.ev.actor}, {"target", r.ev.target},
                               {"status", r.ev.status}, {"detail", r.ev.detail},
                               {"hash", r.hash}});
        return out.dump(2);
    }
    if (name == "summary") {
        return json{{"certs", db.list_certs(1000000, 0).size()},
                    {"audit", db.list_audit_desc(1000000, 0).size()},
                    {"discovered", db.list_discovered(1000000, 0).size()}}.dump(2);
    }
    throw pki::Error(1, "unknown tool: " + name);
}

// JSON-RPC helpers.
json rpc_result(const json& id, const json& result) {
    return json{{"jsonrpc", "2.0"}, {"id", id}, {"result", result}};
}
json rpc_error(const json& id, int code, const std::string& msg) {
    return json{{"jsonrpc", "2.0"}, {"id", id},
                {"error", json{{"code", code}, {"message", msg}}}};
}

void send(const json& msg) { std::cout << msg.dump() << "\n" << std::flush; }

} // namespace

int main(int argc, char** argv) {
    if (pki::handled_version_flag(argc, argv)) return 0;
    std::string conf_path = "config/bootstrap.conf";
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) conf_path = argv[++i];
        else if (std::strcmp(argv[i], "--help") == 0) {
            std::cout << "Usage: fastpki-mcp [--config path]  (speaks MCP on stdio)\n";
            return 0;
        }
    }

    std::unique_ptr<pki::Db> db;
    bool allow_write = false;
    try {
        pki::Config cfg = pki::Config::load(conf_path);
        db = open_db(cfg);
        // The stored settings, as every service applies them: MCP_ALLOW_WRITE is on the
        // console's Config page, and without the overlay a value saved there did nothing here.
        pki::overlay_config(cfg, db->get_config());
        // Say which licence this node is running under, once, now that the database overlay has
        // been applied and the effective value is known. Reported, never enforced.
        pki::log_license(pki::license_status(cfg, pki::license_eval_started(*db)));
        allow_write = cfg.mcp_allow_write;
    } catch (const std::exception& e) {
        std::cerr << "fastpki-mcp: fatal: " << e.what() << "\n";
        return 1;
    }
    std::cerr << "fastpki-mcp: ready (MCP stdio" << (allow_write ? ", writes enabled" : "") << ")\n";

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        json req;
        try { req = json::parse(line); }
        catch (const std::exception&) { send(rpc_error(nullptr, -32700, "parse error")); continue; }

        const json id = req.contains("id") ? req["id"] : json(nullptr);
        const std::string method = req.value("method", "");
        const bool is_notification = !req.contains("id");

        if (method == "initialize") {
            send(rpc_result(id, json{
                {"protocolVersion", "2024-11-05"},
                {"capabilities", json{{"tools", json::object()}}},
                {"serverInfo", json{{"name", "fastpki-mcp"}, {"version", "1.0.0"}}}}));
        } else if (method == "notifications/initialized" || is_notification) {
            // no response to notifications
        } else if (method == "tools/list") {
            send(rpc_result(id, json{{"tools", tool_defs(allow_write)}}));
        } else if (method == "tools/call") {
            const json params = req.value("params", json::object());
            const std::string name = params.value("name", "");
            const json args = params.value("arguments", json::object());
            try {
                std::string text = run_tool(*db, allow_write, name, args);
                send(rpc_result(id, json{
                    {"content", json::array({json{{"type", "text"}, {"text", text}}})}}));
            } catch (const std::exception& e) {
                // Tool-level failure: report as an isError result (MCP convention)
                // so the model sees the message rather than a transport error.
                send(rpc_result(id, json{
                    {"isError", true},
                    {"content", json::array({json{{"type", "text"},
                        {"text", std::string("error: ") + e.what()}}})}}));
            }
        } else {
            send(rpc_error(id, -32601, "method not found: " + method));
        }
    }
    return 0;
}
