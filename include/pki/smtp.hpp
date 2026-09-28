// Submitting mail to a relay: the SMTP client behind fastpki-notify's expiry emails.
//
// Written over the OpenSSL this library already links rather than pulling in a mail
// library, because what is needed is small: one connection, TLS, optional AUTH, and a
// plain-text message per recipient.
//
// ⚠️ TLS UNLESS THE OPERATOR SAID NONE, AND NEVER A PASSWORD WITHOUT IT. With
// SMTP_TLS=starttls the relay must offer STARTTLS, and a relay that does not is refused before
// anything is sent; SMTP_TLS=tls speaks TLS from the first byte; with either, the relay's
// certificate is verified, name included. SMTP_TLS=none is for an internal relay that speaks
// no TLS, and is refused together with SMTP_USER: a message about certificates is not secret,
// but the AUTH credentials that would travel with it are.
#pragma once

#include <optional>
#include <string>
#include <vector>

namespace pki {

struct Config;

struct SmtpSettings {
    std::string host;
    int         port{0};
    bool        implicit_tls{false};   // SMTP_TLS=tls
    bool        plain{false};          // SMTP_TLS=none: no TLS, and therefore no AUTH
                                       // (neither set: STARTTLS is required)
    std::string user;
    std::string password;
    std::string from;
    std::string ca_file;
    std::string helo;                  // the name this node gives in EHLO
    int         timeout_sec{20};
};

// The relay settings from the effective configuration, or nullopt when SMTP_SERVER is
// empty, which is how email is switched off. Throws pki::Error naming the key when the
// server is set but cannot be used: a port that is not a number, no SMTP_FROM, a sender
// that is not an address, SMTP_TLS=none with SMTP_USER set.
std::optional<SmtpSettings> smtp_settings(const Config& cfg);

struct MailMessage {
    std::string to;        // one address
    std::string subject;   // UTF-8; line breaks are removed, non-ASCII is encoded
    std::string body;      // UTF-8 plain text
};

// One mailbox, `local@domain`, in ASCII: no spaces, angle brackets, commas or control
// characters. Deliberately narrower than RFC 5321 — an address that does not pass is
// reported as unusable rather than sent somewhere surprising.
bool plausible_mailbox(const std::string& addr);

// The message as it goes on the wire after DATA, without the terminating dot. Exposed so a
// test can check the headers without a relay.
std::string format_mail(const SmtpSettings& s, const MailMessage& m, long long now_unix);

// Deliver `msgs` over one connection. The result has one entry per message: "" when the
// relay accepted it, otherwise the relay's reason (or, when the connection broke part way,
// that failure for every message not yet accepted). Throws pki::Error only when nothing
// could be sent at all — no connection, a failed TLS handshake or certificate check, a
// relay without STARTTLS, refused credentials.
std::vector<std::string> smtp_send(const SmtpSettings& s, const std::vector<MailMessage>& msgs);

} // namespace pki
