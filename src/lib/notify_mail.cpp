// See include/pki/notify_mail.hpp.
#include "pki/notify_mail.hpp"

#include "pki/x509.hpp"

#include <openssl/x509.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <memory>
#include <set>

namespace pki {

int64_t expiry_days_left(int64_t not_after, int64_t now) {
    // Floor, not truncation: a certificate that expired an hour ago has -1 days left, not 0,
    // so it is reported as expired rather than as still critical.
    const int64_t d = not_after - now;
    return d >= 0 ? d / 86400 : -((-d + 86399) / 86400);
}

const char* expiry_severity(int64_t days_left, const std::vector<int>& th) {
    if (days_left < 0) return "expired";
    if (!th.empty() && days_left <= th.back()) return "critical";   // <= smallest
    if (th.size() >= 2 && days_left <= th[1]) return "warning";     // <= second-largest
    return "info";
}

int expiry_severity_rank(const std::string& s) {
    if (s == "expired")  return 3;
    if (s == "critical") return 2;
    if (s == "warning")  return 1;
    return 0;
}

int expiry_stage(int64_t not_after, int64_t now, const std::vector<int>& th) {
    if (not_after <= now) return 0;
    const int64_t d = expiry_days_left(not_after, now);
    int best = -1;
    for (int w : th)
        if (w > 0 && d <= w && (best < 0 || w < best)) best = w;
    return best;
}

NotifyTemplate default_notify_template() {
    NotifyTemplate t;
    t.subject = "FastPKI: {{count}} certificate(s) expiring or expired ({{severity}})";
    t.line = "- [{{severity}}] {{name}}, serial {{serial}}, from {{ca}}: expires {{expires}}, {{when}}";
    t.body =
        "Hello,\n"
        "\n"
        "These certificates belong to {{owner}} and expire soon or have expired:\n"
        "\n"
        "{{certificates}}\n"
        "\n"
        "Renew or replace each one before it expires. An expired certificate stops working "
        "for every client that checks it. A certificate that is no longer needed can be left "
        "to expire.\n"
        "\n"
        "You will be emailed again only when a certificate reaches a nearer warning "
        "({{days}} days before it expires) and when it expires.\n";
    return t;
}

NotifyTemplate load_notify_template(Db& db) {
    NotifyTemplate t = default_notify_template();
    if (auto row = db.get_notify_template(kExpiryTemplateName)) {
        t.subject = row->subject;
        t.line = row->line;
        t.body = row->body;
        t.stored = true;
    }
    return t;
}

namespace {

std::set<std::string> names_of(const std::vector<unsigned char>& der) {
    const unsigned char* p = der.data();
    std::unique_ptr<X509, decltype(&X509_free)> x(
        d2i_X509(nullptr, &p, static_cast<long>(der.size())), &X509_free);
    return x ? cert_sans(x.get()) : std::set<std::string>{};
}

std::string ymd(int64_t t) {
    std::time_t tt = static_cast<std::time_t>(t);
    std::tm tm{};
    gmtime_r(&tt, &tm);
    char buf[16];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    return buf;
}

} // namespace

bool already_replaced(Db& db, const Db::ExpiringCert& e) {
    if (e.owner.empty() || e.subject.empty()) return false;
    const auto newer = db.newer_valid_certs(e.owner, e.subject, e.serial_hex, e.not_after);
    if (newer.empty()) return false;
    const auto old = db.get_cert(e.serial_hex);
    if (!old || old->cert_der.empty()) return false;
    // The NAMES too, not only the subject: two certificates for one host under one owner
    // with different SANs are two certificates, and one expiring is news.
    const std::set<std::string> names = names_of(old->cert_der);
    return std::any_of(newer.begin(), newer.end(),
                       [&](const std::vector<unsigned char>& der) { return names_of(der) == names; });
}

bool issued_by_prefix(const std::string& serial_hex, int prefix) {
    if (prefix == 0) return true;
    std::string s;
    for (char c : serial_hex) s += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (s.size() > 40) return false;
    s.insert(0, 40 - s.size(), '0');
    static const char* kHex = "0123456789abcdef";
    std::string want(4, '0');
    for (int i = 3, p = prefix; i >= 0; --i, p >>= 4) want[static_cast<size_t>(i)] = kHex[p & 0xF];
    return s.compare(0, 4, want) == 0;
}

std::string fill_placeholders(const std::string& text, const std::map<std::string, std::string>& vars) {
    // One pass over the TEMPLATE. A value is never scanned again, so a CN a requester wrote
    // as "{{owner}}" stays those characters rather than becoming someone's name.
    std::string out;
    out.reserve(text.size() + 256);
    size_t i = 0;
    while (i < text.size()) {
        const size_t open = text.find("{{", i);
        if (open == std::string::npos) { out.append(text, i, std::string::npos); break; }
        const size_t close = text.find("}}", open + 2);
        if (close == std::string::npos) { out.append(text, i, std::string::npos); break; }
        out.append(text, i, open - i);
        const std::string name = text.substr(open + 2, close - open - 2);
        if (auto it = vars.find(name); it != vars.end()) out += it->second;
        else out.append(text, open, close + 2 - open);
        i = close + 2;
    }
    return out;
}

MailMessage expiry_test_email(const std::string& to, const std::string& node) {
    MailMessage m;
    m.to = to;
    m.subject = "FastPKI: test email";
    m.body = "This is a test message from FastPKI on " + node + ".\n"
             "\n"
             "The mail relay accepted it, so expiry emails from this node can be delivered.\n";
    return m;
}

MailMessage compose_expiry_email(const NotifyTemplate& t, const std::string& to,
                                 const std::string& owners,
                                 const std::vector<Db::ExpiringCert>& certs, int64_t now,
                                 const std::vector<int>& th) {
    std::vector<Db::ExpiringCert> sorted = certs;
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) { return a.not_after < b.not_after; });
    std::string worst = "info", lines;
    for (const auto& e : sorted) {
        const int64_t days = expiry_days_left(e.not_after, now);
        const std::string sev = expiry_severity(days, th);
        if (expiry_severity_rank(sev) > expiry_severity_rank(worst)) worst = sev;
        const std::string when =
            e.not_after <= now ? (now - e.not_after < 86400 ? std::string("expired today")
                                                            : "expired " + std::to_string(-days) + " day(s) ago")
                               : days == 0 ? std::string("within a day")
                                           : "in " + std::to_string(days) + " day(s)";
        const std::map<std::string, std::string> v = {
            {"severity", sev},
            {"name", !e.cn.empty() ? e.cn : !e.subject.empty() ? e.subject : e.serial_hex},
            {"cn", e.cn},
            {"subject", e.subject},
            {"serial", e.serial_hex},
            {"ca", e.ca_instance_id.empty() ? "-" : e.ca_instance_id},
            {"owner", e.owner},
            {"expires", ymd(e.not_after)},
            {"days_left", std::to_string(days)},
            {"when", when},
        };
        if (!lines.empty()) lines += "\n";
        lines += fill_placeholders(t.line, v);
    }
    std::string days_list;
    for (size_t i = 0; i < th.size(); ++i) days_list += (i ? ", " : "") + std::to_string(th[i]);
    const std::map<std::string, std::string> v = {
        {"owner", owners},
        {"count", std::to_string(sorted.size())},
        {"severity", worst},
        {"certificates", lines},
        {"days", days_list},
    };
    MailMessage m;
    m.to = to;
    m.subject = fill_placeholders(t.subject, v);
    m.body = fill_placeholders(t.body, v);
    return m;
}

} // namespace pki
