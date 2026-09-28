// fastpki-notify — certificate-expiration scanner + alert dispatcher.
//
//   fastpki-notify --config <bootstrap.conf> [--days 30,14,7] [--webhook <url>]
//                  [--webhook-format json|slack|teams] [--include-discovered] [--json]
//                  [--no-email] [--dry-run] [--test-email <address>]
//
// Scans the `certs` table for valid certificates expiring within the largest
// warning window, buckets each by severity (expired / critical / warning /
// info), prints a report, and — if a webhook is given — POSTs it to the URL in the
// chosen format. With SMTP_SERVER set it also emails each certificate's owner. Run it
// from cron daily.
//
// ⚠️ THE FORMAT IS THE RECEIVER'S, NOT OURS. The report's own JSON document suits a generic
// receiver (a Jira Automation or ServiceNow endpoint, a script). Slack incoming webhooks
// refuse a body without `text`, and Teams webhooks refuse one that is not a message carrying
// an Adaptive Card — so "they all accept JSON" was true of the transport and false of the
// payload, and a report sent to either was dropped with a 400.

#include "pki/auth.hpp"
#include "pki/config.hpp"
#include "pki/version.hpp"
#include "pki/db.hpp"
#include "pki/error.hpp"
#include "pki/notify_mail.hpp"
#include "pki/smtp.hpp"
#include "pki/x509.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT   // allow https webhook URLs
#include "../../third_party/httplib.h"
#include "../../third_party/nlohmann/json.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace {

int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::unique_ptr<pki::Db> open_db(const pki::Config& cfg) {
    return pki::make_postgres_db(cfg.pg_conninfo);
}

std::vector<int> parse_days(const std::string& s) {
    std::vector<int> d;
    size_t i = 0;
    while (i < s.size()) {
        size_t c = s.find(',', i);
        std::string tok = s.substr(i, c == std::string::npos ? std::string::npos : c - i);
        // A window of 0 days or less is no window, and 0 is the stage an expired certificate
        // is emailed at — the console ignores such a value too.
        if (!tok.empty()) { const int v = std::stoi(tok); if (v > 0) d.push_back(v); }
        if (c == std::string::npos) break;
        i = c + 1;
    }
    std::sort(d.begin(), d.end(), std::greater<int>());  // largest window first
    d.erase(std::unique(d.begin(), d.end()), d.end());
    return d;
}

// ⚠️ ONE RULE FOR THE REPORT, THE CONSOLE'S PREVIEW AND THE EMAILS, in pki_lib. A copy here
// once used "within the second-smallest" for warning, which agreed with the console for
// exactly three windows and disagreed for any other count.
const char* severity_for(int64_t days_left, const std::vector<int>& th) {
    return pki::expiry_severity(days_left, th);
}
int severity_rank(const std::string& s) { return pki::expiry_severity_rank(s); }
int64_t days_left_of(int64_t not_after, int64_t now) { return pki::expiry_days_left(not_after, now); }

std::string rfc3339(int64_t t) {
    std::time_t tt = static_cast<std::time_t>(t);
    std::tm tm{};
    gmtime_r(&tt, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// Built with a JSON library, every format: a CN or owner is whatever a requester chose, and a
// hand escaper that knew only quote, backslash and newline turned a tab into invalid JSON.
using ojson = nlohmann::ordered_json;

// The report as FastPKI's own document: --json output, and the `json` webhook format.
std::string make_summary_json(const std::vector<pki::Db::ExpiringCert>& rows,
                              int64_t now, const std::vector<int>& th) {
    ojson j;
    j["generated"] = rfc3339(now);
    j["count"] = rows.size();
    j["certificates"] = ojson::array();
    for (const auto& e : rows) {
        const int64_t days_left = days_left_of(e.not_after, now);
        j["certificates"].push_back({{"serial", e.serial_hex}, {"cn", e.cn}, {"owner", e.owner},
                                     {"notAfter", rfc3339(e.not_after)}, {"daysLeft", days_left},
                                     {"severity", severity_for(days_left, th)}});
    }
    return j.dump();
}

// A chat message is read by a person, so it lists at most this many certificates and says
// how many more there are; Slack and Teams both cap a message's size.
constexpr size_t kChatListMax = 50;

struct ChatReport { std::string title; std::vector<std::string> lines; size_t more{0};
                    int counts[4]{0, 0, 0, 0}; };   // expired, critical, warning, info

// What a chat message says, independent of how Slack or Teams mark it up. `bold` wraps the
// severity in that receiver's emphasis; `clean` removes what its markup would interpret in
// requester-chosen text.
ChatReport chat_report(const std::vector<pki::Db::ExpiringCert>& rows, int64_t now,
                       const std::vector<int>& th, const char* bold,
                       std::string (*clean)(const std::string&)) {
    ChatReport r;
    for (const auto& e : rows) {
        const int64_t days_left = days_left_of(e.not_after, now);
        const std::string sev = severity_for(days_left, th);
        ++r.counts[3 - severity_rank(sev)];
        if (r.lines.size() >= kChatListMax) { ++r.more; continue; }
        const std::string name = e.cn.empty() ? e.serial_hex : e.cn;
        const std::string left = days_left < 0 ? "expired " + std::to_string(-days_left) + " day(s) ago"
                                               : std::to_string(days_left) + " day(s) left";
        r.lines.push_back(std::string(bold) + sev + bold + "  " + clean(name) + " (serial " +
                          clean(e.serial_hex) + "), owner " + clean(e.owner.empty() ? "-" : e.owner) +
                          ", expires " + rfc3339(e.not_after).substr(0, 10) + ", " + left);
    }
    r.title = "FastPKI: " + std::to_string(rows.size()) + " certificate(s) expiring within " +
              std::to_string(th.empty() ? 0 : th.front()) + " days";
    return r;
}

// Slack: `text` in Slack's mrkdwn. &, < and > are the three characters it asks to escape.
std::string slack_clean(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c == '&') o += "&amp;"; else if (c == '<') o += "&lt;"; else if (c == '>') o += "&gt;";
        else if (c == '*' || c == '_' || c == '~' || c == '`') o += ' ';
        else o += c;
    }
    return o;
}
std::string slack_message(const std::vector<pki::Db::ExpiringCert>& rows, int64_t now,
                          const std::vector<int>& th) {
    const ChatReport r = chat_report(rows, now, th, "*", slack_clean);
    std::string text = "*" + r.title + "*\nexpired " + std::to_string(r.counts[0]) +
                       " · critical " + std::to_string(r.counts[1]) + " · warning " +
                       std::to_string(r.counts[2]) + " · info " + std::to_string(r.counts[3]);
    for (const auto& l : r.lines) text += "\n• " + l;
    if (r.more) text += "\n…and " + std::to_string(r.more) + " more";
    return ojson{{"text", text}}.dump();
}

// Teams: a message carrying one Adaptive Card, the payload both a Workflows "when a webhook
// request is received" flow and an incoming webhook accept. TextBlock markdown reads * and _.
std::string teams_clean(const std::string& s) {
    std::string o;
    for (char c : s) o += (c == '*' || c == '_' || c == '[' || c == ']') ? ' ' : c;
    return o;
}
std::string teams_message(const std::vector<pki::Db::ExpiringCert>& rows, int64_t now,
                          const std::vector<int>& th) {
    const ChatReport r = chat_report(rows, now, th, "**", teams_clean);
    ojson body = ojson::array();
    body.push_back({{"type", "TextBlock"}, {"size", "Medium"}, {"weight", "Bolder"},
                    {"wrap", true}, {"text", r.title}});
    body.push_back({{"type", "FactSet"}, {"facts", ojson::array({
        {{"title", "Expired"},  {"value", std::to_string(r.counts[0])}},
        {{"title", "Critical"}, {"value", std::to_string(r.counts[1])}},
        {{"title", "Warning"},  {"value", std::to_string(r.counts[2])}},
        {{"title", "Info"},     {"value", std::to_string(r.counts[3])}}})}});
    std::string list;
    for (const auto& l : r.lines) list += (list.empty() ? "- " : "\n- ") + l;
    if (r.more) list += "\n\n…and " + std::to_string(r.more) + " more";
    if (!list.empty())
        body.push_back({{"type", "TextBlock"}, {"wrap", true}, {"text", list}});
    ojson card = {{"$schema", "http://adaptivecards.io/schemas/adaptive-card.json"},
                  {"type", "AdaptiveCard"}, {"version", "1.4"}, {"body", body}};
    ojson msg = {{"type", "message"},
                 {"attachments", ojson::array({{{"contentType", "application/vnd.microsoft.card.adaptive"},
                                                {"contentUrl", nullptr}, {"content", card}}})}};
    return msg.dump();
}

// The body for one webhook POST, in the receiver's format.
std::string webhook_body(const std::string& format, const std::vector<pki::Db::ExpiringCert>& rows,
                         int64_t now, const std::vector<int>& th) {
    if (format == "slack") return slack_message(rows, now, th);
    if (format == "teams") return teams_message(rows, now, th);
    return make_summary_json(rows, now, th);
}

// POST `body` as application/json to `url`. Returns true on a 2xx response;
// `note` is set to a short status string for logging.
bool post_webhook(const std::string& url, const std::string& body, std::string& note) {
    std::string base = url, path = "/";
    size_t sp = url.find("://");
    size_t slash = url.find('/', sp == std::string::npos ? 0 : sp + 3);
    if (slash != std::string::npos) { base = url.substr(0, slash); path = url.substr(slash); }
    httplib::Client cli(base);
    cli.set_connection_timeout(5);
    auto res = cli.Post(path, body, "application/json");
    if (!res) { note = "no response"; return false; }
    note = "HTTP " + std::to_string(res->status);
    return res->status / 100 == 2;
}

// Load an owner→webhook routing table: one "owner=url" (or "owner<ws>url") per
// line, # comments allowed. Lets each team get only its own certs.
std::map<std::string, std::string> load_routes(const std::string& path) {
    std::map<std::string, std::string> m;
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) {
        line = pki::strip_inline_comment(line);
        size_t sep = line.find('=');
        if (sep == std::string::npos) sep = line.find_first_of(" \t");
        if (sep == std::string::npos) continue;
        auto trim = [](const std::string& s) {
            size_t b = s.find_first_not_of(" \t\r\n");
            size_t e = s.find_last_not_of(" \t\r\n");
            return b == std::string::npos ? std::string() : s.substr(b, e - b + 1);
        };
        std::string owner = trim(line.substr(0, sep)), url = trim(line.substr(sep + 1));
        if (!owner.empty() && !url.empty()) m[owner] = url;
    }
    return m;
}

int usage() {
    std::cerr << "Usage: fastpki-notify --config <bootstrap.conf> [--days 30,14,7] "
                 "[--webhook <url>] [--webhook-format json|slack|teams] [--routes <file>] "
                 "[--fail-on <severity>] [--include-discovered] [--json]\n"
                 "                      [--no-email] [--dry-run] [--test-email <address>]\n"
                 "\n"
                 "  With SMTP_SERVER set, each certificate's owner is emailed once as the certificate\n"
                 "  enters each window and once when it expires. --no-email skips the emails;\n"
                 "  --dry-run prints what would be posted and emailed and sends and records nothing;\n"
                 "  --test-email sends one test message through the relay and exits.\n";
    return 2;
}

// The expiry emails. Returns false when a delivery failed.
bool email_owners(const pki::Config& cfg, pki::Db& db, const pki::SmtpSettings& smtp,
                  const std::vector<pki::Db::ExpiringCert>& managed, int64_t now,
                  const std::vector<int>& th, bool dry_run) {
    // ⚠️ A STANDBY SENDS NOTHING. Its database is read-only, so it could not record what it
    // sent and would email the same owners every day; the primary of the pair sends them.
    if (db.in_recovery()) {
        std::cerr << "fastpki-notify: email: this database is a standby, so its primary sends the emails\n";
        return true;
    }
    // ⚠️ EACH DATA CENTER EMAILS ABOUT THE CERTIFICATES IT ISSUED, AND NO OTHERS. Every node
    // of a mesh holds every certificate, so without this each site would email the same
    // owner about the same certificate. The serial prefix says which site minted a serial,
    // and exactly one site has it.
    pki::resolve_datacenter_prefix(cfg, db);
    const int prefix = pki::datacenter_serial_prefix();
    const auto sent = db.notify_stages_sent();
    const pki::NotifyTemplate tpl = pki::load_notify_template(db);

    struct Batch {
        std::string to;
        std::set<std::string> owners;
        std::vector<pki::Db::ExpiringCert> certs;
        std::vector<int> stages;
    };
    std::map<std::string, Batch> batches;                // keyed by address
    std::map<std::string, std::string> address_of;       // owner -> address, "" for none
    std::map<std::string, size_t> no_address;            // owner -> certificates
    size_t elsewhere = 0, already = 0, replaced = 0;
    const bool have_fallback = pki::plausible_mailbox(cfg.notify_email_fallback);
    if (!cfg.notify_email_fallback.empty() && !have_fallback)
        std::cerr << "fastpki-notify: email: NOTIFY_EMAIL_FALLBACK is not a single address: '"
                  << cfg.notify_email_fallback << "'\n";

    for (const auto& e : managed) {
        if (!pki::issued_by_prefix(e.serial_hex, prefix)) { ++elsewhere; continue; }
        const int stage = pki::expiry_stage(e.not_after, now, th);
        if (stage < 0) continue;
        if (auto it = sent.find(e.serial_hex); it != sent.end() && stage >= it->second) { ++already; continue; }
        if (pki::already_replaced(db, e)) { ++replaced; continue; }
        auto a = address_of.find(e.owner);
        if (a == address_of.end()) a = address_of.emplace(e.owner, pki::owner_email(cfg, &db, e.owner)).first;
        std::string to = a->second;
        if (to.empty()) {
            ++no_address[e.owner.empty() ? "(no owner)" : e.owner];
            if (!have_fallback) continue;
            to = cfg.notify_email_fallback;
        }
        Batch& b = batches[to];
        b.to = to;
        b.owners.insert(e.owner.empty() ? "(no owner)" : e.owner);
        b.certs.push_back(e);
        b.stages.push_back(stage);
    }

    std::vector<pki::MailMessage> msgs;
    std::vector<const Batch*> order;
    for (const auto& [to, b] : batches) {
        std::string owners;
        for (const auto& o : b.owners) owners += (owners.empty() ? "" : ", ") + o;
        msgs.push_back(pki::compose_expiry_email(tpl, to, owners, b.certs, now, th));
        order.push_back(&b);
    }
    for (const auto& [owner, n] : no_address)
        std::cerr << "fastpki-notify: email: no address for owner " << owner << " (" << n
                  << " certificate(s))" << (have_fallback ? ", sent to NOTIFY_EMAIL_FALLBACK" : "") << "\n";

    bool ok = true;
    size_t delivered = 0, failed = 0;
    if (dry_run) {
        for (size_t i = 0; i < msgs.size(); ++i)
            std::cerr << "fastpki-notify: email (dry run) -> " << msgs[i].to << ": "
                      << order[i]->certs.size() << " certificate(s), subject \"" << msgs[i].subject << "\"\n";
    } else if (!msgs.empty()) {
        std::vector<std::string> results;
        try {
            results = pki::smtp_send(smtp, msgs);
        } catch (const std::exception& ex) {
            std::cerr << "fastpki-notify: email: " << ex.what() << "\n";
            results.assign(msgs.size(), "not sent");
            ok = false;
        }
        for (size_t i = 0; i < msgs.size(); ++i) {
            if (results[i].empty()) {
                ++delivered;
                // Recorded only once the relay has accepted it, so a relay that was down
                // today is simply tried again tomorrow.
                for (size_t k = 0; k < order[i]->certs.size(); ++k)
                    db.record_notify_stage(order[i]->certs[k].serial_hex, order[i]->stages[k]);
                std::cerr << "fastpki-notify: email -> " << msgs[i].to << ": "
                          << order[i]->certs.size() << " certificate(s)\n";
            } else {
                ++failed;
                ok = false;
                if (results[i] != "not sent")
                    std::cerr << "fastpki-notify: email -> " << msgs[i].to << ": refused: " << results[i] << "\n";
            }
        }
    }
    if (!dry_run) db.prune_notify_sent();
    std::cerr << "fastpki-notify: email: " << delivered << " sent, " << failed << " failed, "
              << already << " already emailed at this stage, " << replaced << " already replaced, "
              << elsewhere << " issued by another data center\n";
    return ok;
}

} // namespace

int main(int argc, char** argv) {
    if (pki::handled_version_flag(argc, argv)) return 0;
    std::string conf_path = "config/bootstrap.conf", days_str, webhook;
    std::string routes_file, fail_on, format, test_email;
    bool as_json = false, include_discovered = false, no_email = false, dry_run = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--config"  && i + 1 < argc) conf_path   = argv[++i];
        else if (a == "--days"    && i + 1 < argc) days_str    = argv[++i];
        else if (a == "--webhook" && i + 1 < argc) webhook     = argv[++i];
        else if (a == "--webhook-format" && i + 1 < argc) format = argv[++i];
        else if (a == "--routes"  && i + 1 < argc) routes_file = argv[++i];
        else if (a == "--fail-on" && i + 1 < argc) fail_on     = argv[++i];
        else if (a == "--include-discovered")      include_discovered = true;
        else if (a == "--json")                    as_json     = true;
        else if (a == "--no-email")                no_email    = true;
        else if (a == "--dry-run")                 dry_run     = true;
        else if (a == "--test-email" && i + 1 < argc) test_email = argv[++i];
        else if (a == "--help" || a == "-h")       return usage();
    }

    try {
        pki::Config cfg = pki::Config::load(conf_path);
        auto db = open_db(cfg);
        // ⚠️ THE STORED SETTINGS, as every service reads them. Without the overlay this tool
        // saw bootstrap.conf and the environment only, so NOTIFY_DAYS and NOTIFY_WEBHOOK saved
        // on the console's Notifications page — which says they are this tool's defaults —
        // never reached it. The flags still win when given.
        pki::overlay_config(cfg, db->get_config());
        if (!test_email.empty()) {
            const auto smtp = pki::smtp_settings(cfg);
            if (!smtp) { std::cerr << "fastpki-notify: --test-email: SMTP_SERVER is not set\n"; return 1; }
            const auto r = pki::smtp_send(*smtp, {pki::expiry_test_email(test_email, smtp->helo)});
            if (!r.front().empty()) {
                std::cerr << "fastpki-notify: --test-email: the relay refused it: " << r.front() << "\n";
                return 1;
            }
            std::cerr << "fastpki-notify: test email accepted by " << smtp->host << " for " << test_email << "\n";
            return 0;
        }
        if (days_str.empty()) days_str = cfg.notify_days;
        if (webhook.empty())  webhook  = cfg.notify_webhook;
        if (format.empty())   format   = cfg.notify_webhook_format;
        if (format != "json" && format != "slack" && format != "teams") {
            std::cerr << "fastpki-notify: --webhook-format must be json, slack or teams, got '"
                      << format << "'\n";
            return usage();
        }
        std::vector<int> th = parse_days(days_str);
        if (th.empty()) return usage();
        const int64_t now = now_unix();
        const int64_t cutoff = now + int64_t(th.front()) * 86400;

        // A relay configured wrongly fails the run, but not the report or the webhook: those
        // are how an operator hears about expiring certificates even while email is broken.
        std::optional<pki::SmtpSettings> smtp;
        bool email_misconfigured = false;
        if (!no_email) {
            try { smtp = pki::smtp_settings(cfg); }
            catch (const std::exception& ex) {
                std::cerr << "fastpki-notify: email not sent: " << ex.what() << "\n";
                email_misconfigured = true;
            }
        }

        const auto managed = db->get_expiring_certs(cutoff);
        auto rows = managed;

        // Also alert on expiring *discovered* (unmanaged) certs:
        // the things you found on the network but don't manage are exactly the
        // ones that lapse unnoticed. Map them into the same expiring-cert flow
        // with a "discovered" owner so they route/report/fail-on uniformly.
        if (include_discovered) {
            for (const auto& d : db->list_discovered(1000000, 0)) {
                if (d.not_after <= 0 || d.not_after > cutoff) continue;
                pki::Db::ExpiringCert e;
                e.serial_hex = d.serial;
                e.cn = d.subject.empty() ? d.target : d.subject;
                e.owner = "discovered";
                e.not_after = d.not_after;
                rows.push_back(std::move(e));
            }
            std::sort(rows.begin(), rows.end(),
                      [](const auto& a, const auto& b){ return a.not_after < b.not_after; });
        }

        // Bucket counts for the report + the highest severity seen (for --fail-on).
        int counts[4] = {0, 0, 0, 0};  // expired, critical, warning, info
        int max_rank = -1;
        for (const auto& e : rows) {
            int64_t days_left = days_left_of(e.not_after, now);
            std::string sev = severity_for(days_left, th);
            if (sev == "expired") counts[0]++;
            else if (sev == "critical") counts[1]++;
            else if (sev == "warning")  counts[2]++;
            else counts[3]++;
            max_rank = std::max(max_rank, severity_rank(sev));
        }
        // Full JSON summary: the --json output (and the `json` webhook body, built per POST).
        std::string j = make_summary_json(rows, now, th);

        if (as_json) {
            std::cout << j << "\n";
        } else {
            std::cout << "Certificate expiry report (" << rfc3339(now) << ")\n";
            std::cout << "  expiring within " << th.front() << " days: " << rows.size()
                      << "  [expired=" << counts[0] << " critical=" << counts[1]
                      << " warning=" << counts[2] << " info=" << counts[3] << "]\n";
            for (const auto& e : rows) {
                int64_t days_left = days_left_of(e.not_after, now);
                std::cout << "  [" << severity_for(days_left, th) << "] "
                          << (e.cn.empty() ? e.serial_hex : e.cn)
                          << " owner=" << e.owner
                          << " expires=" << rfc3339(e.not_after)
                          << " (" << days_left << "d)\n";
            }
        }

        bool dispatch_failed = false;

        // The webhook: the whole report to one endpoint, in the receiver's format.
        if (!webhook.empty() && dry_run) {
            std::cerr << "fastpki-notify: webhook (dry run): would post the report in the "
                      << format << " format\n";
        } else if (!webhook.empty()) {
            std::string note;
            bool ok = post_webhook(webhook, webhook_body(format, rows, now, th), note);
            std::cerr << "fastpki-notify: webhook -> " << note << "\n";
            if (!ok) dispatch_failed = true;
        }

        // Per-owner routing: each owner's subset to its own endpoint.
        if (!routes_file.empty() && !dry_run) {
            auto routes = load_routes(routes_file);
            std::map<std::string, std::vector<pki::Db::ExpiringCert>> by_owner;
            for (const auto& e : rows) by_owner[e.owner].push_back(e);
            for (const auto& [owner, url] : routes) {
                auto it = by_owner.find(owner);
                if (it == by_owner.end()) continue;   // nothing to send this owner
                std::string note;
                bool ok = post_webhook(url, webhook_body(format, it->second, now, th), note);
                std::cerr << "fastpki-notify: route owner=" << owner << " ("
                          << it->second.size() << " cert(s)) -> " << note << "\n";
                if (!ok) dispatch_failed = true;
            }
        }

        // Email to each certificate's owner. Managed certificates only: a discovered one has
        // no owner FastPKI knows.
        if (smtp && !email_owners(cfg, *db, *smtp, managed, now, th, dry_run)) dispatch_failed = true;
        if (email_misconfigured) dispatch_failed = true;

        if (dispatch_failed) return 1;

        // Monitoring gate: exit 3 if any cert is at/above the given severity, so a
        // cron/CI caller can alert on it independently of dispatch success.
        if (!fail_on.empty() && max_rank >= severity_rank(fail_on)) {
            std::cerr << "fastpki-notify: --fail-on " << fail_on
                      << " threshold met\n";
            return 3;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fastpki-notify: " << e.what() << "\n";
        return 1;
    }
}
