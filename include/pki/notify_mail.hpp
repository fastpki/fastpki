// Expiry notifications: the rules the report, the console preview and the owner emails
// share, and the email template.
#pragma once

#include "pki/db.hpp"
#include "pki/smtp.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace pki {

// Whole days until `not_after`, rounded DOWN: -1 an hour after expiry, never 0.
int64_t expiry_days_left(int64_t not_after, int64_t now);

// expired (< 0 days left); critical within the smallest window; warning within any window
// but the largest; info within the largest only. `windows_desc` is NOTIFY_DAYS, largest
// first. ONE definition, so the page an operator checks says what is sent.
const char* expiry_severity(int64_t days_left, const std::vector<int>& windows_desc);
int expiry_severity_rank(const std::string& severity);   // expired 3 … info 0

// How far a certificate has gone: 0 once it has expired, otherwise the smallest window it is
// inside, or -1 when it is outside every window. An owner is emailed when a certificate
// reaches a smaller stage than the last one emailed.
int expiry_stage(int64_t not_after, int64_t now, const std::vector<int>& windows_desc);

// The row name the template is stored under.
inline constexpr const char* kExpiryTemplateName = "expiry";

struct NotifyTemplate {
    std::string subject, line, body;
    bool stored{false};   // false: the built-in text
};
NotifyTemplate default_notify_template();
NotifyTemplate load_notify_template(Db& db);

// Has this certificate been replaced already? True when the same owner holds a newer valid
// certificate with the same subject and the same names — what an ACME, EST, CMP, SCEP or
// Windows renewal leaves behind. The old one is still valid until it expires, and emailing
// its owner about it would only teach them to ignore the emails.
bool already_replaced(Db& db, const Db::ExpiringCert& e);

// Did the data center with serial prefix `prefix` mint this serial? Prefix 0 means a single
// node, which issued everything it holds. The same test the database's prefix guard makes:
// the first four hex digits of the 40-digit serial.
bool issued_by_prefix(const std::string& serial_hex, int prefix);

// Replace {{name}} with vars[name]. A placeholder the map does not have is left as written,
// so a typo in a template shows in the email instead of vanishing.
std::string fill_placeholders(const std::string& text, const std::map<std::string, std::string>& vars);

// The message behind "Send test email" and `fastpki-notify --test-email`: it proves the relay
// settings deliver, and says which node sent it.
MailMessage expiry_test_email(const std::string& to, const std::string& node);

// One email about `certs`, which all go to `to`. `owners` is who they belong to: the owner,
// or every owner listed when the address is the fallback.
MailMessage compose_expiry_email(const NotifyTemplate& t, const std::string& to,
                                 const std::string& owners,
                                 const std::vector<Db::ExpiringCert>& certs, int64_t now,
                                 const std::vector<int>& windows_desc);

} // namespace pki
