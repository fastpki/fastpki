// See include/pki/smtp.hpp.
#include "pki/smtp.hpp"

#include "pki/config.hpp"
#include "pki/error.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <utility>

namespace pki {
namespace {

std::string upper(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

std::string b64(const std::string& in) {
    if (in.empty()) return {};
    std::string out(4 * ((in.size() + 2) / 3) + 1, '\0');
    const int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                  reinterpret_cast<const unsigned char*>(in.data()),
                                  static_cast<int>(in.size()));
    out.resize(n < 0 ? 0 : static_cast<size_t>(n));
    return out;
}

// What a relay said, fit for an error message: its own words, control characters removed.
std::string printable(const std::string& s) {
    std::string o;
    for (char c : s) o += (static_cast<unsigned char>(c) < 0x20 && c != '\n') ? ' ' : c;
    return o.size() > 300 ? o.substr(0, 300) + "…" : o;
}

bool is_ip_literal(const std::string& h) {
    unsigned char buf[sizeof(struct in6_addr)];
    return inet_pton(AF_INET, h.c_str(), buf) == 1 || inet_pton(AF_INET6, h.c_str(), buf) == 1;
}

// One connection to the relay, plain until STARTTLS and TLS after it.
class Conn {
public:
    explicit Conn(const SmtpSettings& s) : s_(s) {}
    ~Conn() { close_(); }
    Conn(const Conn&) = delete;
    Conn& operator=(const Conn&) = delete;

    void open() {
        connect_tcp_();
        if (s_.implicit_tls) start_tls();
    }

    void start_tls() {
        // ⚠️ NOTHING MAY ARRIVE BETWEEN "220 ready to start TLS" AND THE HANDSHAKE. Bytes
        // already buffered there were sent in plaintext by whoever sits on the path, and
        // reading them after the handshake would treat an injected reply as the relay's
        // own (the STARTTLS command-injection class of bug). Refuse rather than discard.
        if (!buf_.empty())
            throw Error(2, "SMTP: " + s_.host + " sent data before the TLS handshake; refusing to continue");
        ctx_ = SSL_CTX_new(TLS_client_method());
        if (!ctx_) throw Error(2, "SMTP: cannot create a TLS context: " + openssl_errors());
        SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
        if (SSL_CTX_set_default_verify_paths(ctx_) != 1)
            throw Error(2, "SMTP: cannot load the system trust store: " + openssl_errors());
        if (!s_.ca_file.empty() &&
            SSL_CTX_load_verify_locations(ctx_, s_.ca_file.c_str(), nullptr) != 1)
            throw Error(2, "SMTP: SMTP_CA_FILE '" + s_.ca_file + "' could not be read: " +
                           openssl_errors());
        ssl_ = SSL_new(ctx_);
        if (!ssl_) throw Error(2, "SMTP: cannot create a TLS session: " + openssl_errors());
        // The name check is the half of verification that is easy to leave out: without it
        // any certificate a trusted CA ever issued would do.
        if (is_ip_literal(s_.host)) {
            X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl_), s_.host.c_str());
        } else {
            SSL_set_tlsext_host_name(ssl_, s_.host.c_str());
            SSL_set1_host(ssl_, s_.host.c_str());
        }
        SSL_set_fd(ssl_, fd_);
        if (SSL_connect(ssl_) != 1) {
            const long vr = SSL_get_verify_result(ssl_);
            const std::string why = vr != X509_V_OK
                ? std::string("the relay's certificate did not verify (") +
                      X509_verify_cert_error_string(vr) + ")"
                : openssl_errors();
            throw Error(2, "SMTP: TLS with " + s_.host + " failed: " + why);
        }
    }

    void send_line(const std::string& line) { write_all_(line + "\r\n"); }
    void send_raw(const std::string& data) { write_all_(data); }

    // One reply: its code, and the text of every line joined by newlines.
    std::pair<int, std::string> reply() {
        std::string text;
        for (int lines = 0; lines < 512; ++lines) {
            const std::string l = read_line_();
            if (l.size() < 3 || !std::isdigit(static_cast<unsigned char>(l[0])) ||
                !std::isdigit(static_cast<unsigned char>(l[1])) ||
                !std::isdigit(static_cast<unsigned char>(l[2])) ||
                (l.size() > 3 && l[3] != ' ' && l[3] != '-'))
                throw Error(2, "SMTP: " + s_.host + " sent something that is not an SMTP reply: '" +
                               printable(l) + "'");
            if (!text.empty()) text += "\n";
            if (l.size() > 4) text += l.substr(4);
            if (l.size() == 3 || l[3] == ' ') return {std::stoi(l.substr(0, 3)), text};
        }
        throw Error(2, "SMTP: " + s_.host + " sent a reply of more than 512 lines");
    }

private:
    void connect_tcp_() {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        const std::string port = std::to_string(s_.port);
        if (int rc = getaddrinfo(s_.host.c_str(), port.c_str(), &hints, &res); rc != 0 || !res)
            throw Error(2, "SMTP: cannot resolve " + s_.host + ": " + gai_strerror(rc));
        std::string last = "no address";
        for (addrinfo* a = res; a && fd_ < 0; a = a->ai_next) {
            int fd = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
            if (fd < 0) { last = std::strerror(errno); continue; }
            // A connect that nobody answers blocks for minutes by default, and this runs from
            // cron: bound it the same as every read.
            const int flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            int rc = ::connect(fd, a->ai_addr, a->ai_addrlen);
            if (rc != 0 && errno == EINPROGRESS) {
                pollfd p{fd, POLLOUT, 0};
                const int pr = ::poll(&p, 1, s_.timeout_sec * 1000);
                if (pr == 1) {
                    int err = 0;
                    socklen_t len = sizeof err;
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
                    if (err == 0) rc = 0;
                    else errno = err;
                } else if (pr == 0) {
                    errno = ETIMEDOUT;
                }
            }
            if (rc != 0) { last = std::strerror(errno); ::close(fd); continue; }
            fcntl(fd, F_SETFL, flags);
            timeval tv{};
            tv.tv_sec = s_.timeout_sec;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
#ifdef SO_NOSIGPIPE
            int one = 1;
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
            fd_ = fd;
        }
        freeaddrinfo(res);
        if (fd_ < 0)
            throw Error(2, "SMTP: cannot connect to " + s_.host + ":" + port + ": " + last);
    }

    void write_all_(const std::string& data) {
        size_t off = 0;
        while (off < data.size()) {
            const size_t want = data.size() - off;
            long n;
            if (ssl_) {
                n = SSL_write(ssl_, data.data() + off, static_cast<int>(want > 65536 ? 65536 : want));
            } else {
#ifdef MSG_NOSIGNAL
                n = ::send(fd_, data.data() + off, want, MSG_NOSIGNAL);
#else
                n = ::send(fd_, data.data() + off, want, 0);
#endif
            }
            if (n <= 0) throw Error(2, "SMTP: the connection to " + s_.host + " failed while sending");
            off += static_cast<size_t>(n);
        }
    }

    std::string read_line_() {
        for (;;) {
            if (const size_t nl = buf_.find('\n'); nl != std::string::npos) {
                std::string line = buf_.substr(0, nl);
                buf_.erase(0, nl + 1);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                return line;
            }
            if (buf_.size() > 16384)
                throw Error(2, "SMTP: " + s_.host + " sent a line longer than 16384 bytes");
            char tmp[4096];
            long n = ssl_ ? SSL_read(ssl_, tmp, sizeof tmp) : ::recv(fd_, tmp, sizeof tmp, 0);
            if (n <= 0)
                throw Error(2, "SMTP: " + s_.host + " closed the connection or did not answer within " +
                               std::to_string(s_.timeout_sec) + "s");
            buf_.append(tmp, static_cast<size_t>(n));
        }
    }

    void close_() {
        if (ssl_) { SSL_shutdown(ssl_); SSL_free(ssl_); ssl_ = nullptr; }
        if (ctx_) { SSL_CTX_free(ctx_); ctx_ = nullptr; }
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    }

    const SmtpSettings& s_;
    int fd_{-1};
    SSL_CTX* ctx_{nullptr};
    SSL* ssl_{nullptr};
    std::string buf_;
};

// Does an EHLO reply advertise `keyword`? The first line is the relay's name, each line
// after it one extension with its parameters.
bool offers(const std::string& ehlo, const std::string& keyword, std::string* params = nullptr) {
    size_t start = ehlo.find('\n');
    while (start != std::string::npos) {
        const size_t end = ehlo.find('\n', start + 1);
        const std::string line = upper(ehlo.substr(start + 1, end == std::string::npos
                                                                  ? std::string::npos : end - start - 1));
        // `AUTH=PLAIN LOGIN` is the pre-standard spelling some relays still send alongside.
        if (line == keyword || line.rfind(keyword + " ", 0) == 0 || line.rfind(keyword + "=", 0) == 0) {
            if (params) *params = line.size() > keyword.size() ? line.substr(keyword.size() + 1) : "";
            return true;
        }
        start = end;
    }
    return false;
}

std::string said(const std::pair<int, std::string>& r) {
    return std::to_string(r.first) + " " + printable(r.second);
}

// RFC 5322 date. Built by hand because strftime's %a and %b follow the locale.
std::string mail_date(long long now) {
    static const char* kDay[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char* kMon[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    std::time_t t = static_cast<std::time_t>(now);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[64];
    std::snprintf(buf, sizeof buf, "%s, %02d %s %04d %02d:%02d:%02d +0000", kDay[tm.tm_wday % 7],
                  tm.tm_mday, kMon[tm.tm_mon % 12], tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

// A Subject header value: one line, and RFC 2047 encoded-words when it is not plain ASCII.
std::string subject_header(const std::string& raw) {
    std::string s;
    for (char c : raw) {
        const unsigned char u = static_cast<unsigned char>(c);
        // A line break in a header value would start a header of the requester's choosing.
        s += (u < 0x20 || u == 0x7f) ? ' ' : c;
    }
    // Long enough for any sensible subject, short enough that no line comes near 998 octets;
    // the cut never splits a UTF-8 sequence.
    if (s.size() > 300) {
        size_t cut = 300;
        while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80) --cut;
        s.resize(cut);
    }
    bool ascii = true;
    for (char c : s) if (static_cast<unsigned char>(c) >= 0x80) { ascii = false; break; }
    if (ascii) return s;
    // Encoded-words of at most 75 characters: 45 input octets make 60 of base64, plus the
    // 12 of "=?UTF-8?B?" and "?=". A chunk ends before a continuation byte, so no word
    // carries half a character.
    std::string out;
    size_t i = 0;
    while (i < s.size()) {
        size_t n = std::min<size_t>(45, s.size() - i);
        while (n > 0 && i + n < s.size() && (static_cast<unsigned char>(s[i + n]) & 0xC0) == 0x80) --n;
        if (n == 0) n = std::min<size_t>(45, s.size() - i);
        if (!out.empty()) out += "\r\n ";
        out += "=?UTF-8?B?" + b64(s.substr(i, n)) + "?=";
        i += n;
    }
    return out;
}

std::string random_hex(int bytes) {
    unsigned char b[32];
    if (bytes > 32) bytes = 32;
    if (RAND_bytes(b, bytes) != 1) throw Error(2, "SMTP: RAND_bytes failed: " + openssl_errors());
    static const char* kHex = "0123456789abcdef";
    std::string o;
    for (int i = 0; i < bytes; ++i) { o += kHex[b[i] >> 4]; o += kHex[b[i] & 0x0f]; }
    return o;
}

} // namespace

bool plausible_mailbox(const std::string& a) {
    if (a.size() < 3 || a.size() > 254) return false;
    const size_t at = a.find('@');
    if (at == std::string::npos || at == 0 || at + 1 >= a.size() || a.find('@', at + 1) != std::string::npos)
        return false;
    for (char c : a) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u <= 0x20 || u >= 0x7f || std::strchr("<>(),;:\"[]\\", c)) return false;
    }
    const std::string dom = a.substr(at + 1);
    return dom.front() != '.' && dom.back() != '.' && dom.find("..") == std::string::npos;
}

std::optional<SmtpSettings> smtp_settings(const Config& cfg) {
    if (cfg.smtp_server.empty()) return std::nullopt;
    SmtpSettings s;
    s.implicit_tls = cfg.smtp_tls == "tls";
    s.plain = cfg.smtp_tls == "none";
    const std::string& hp = cfg.smtp_server;
    if (hp.find("://") != std::string::npos)
        throw Error(2, "config: SMTP_SERVER is host[:port], not a URL: '" + hp + "'");
    std::string port;
    if (hp.front() == '[') {
        const size_t e = hp.find(']');
        if (e == std::string::npos) throw Error(2, "config: SMTP_SERVER has an unclosed '[': '" + hp + "'");
        s.host = hp.substr(1, e - 1);
        if (e + 1 < hp.size()) {
            if (hp[e + 1] != ':') throw Error(2, "config: SMTP_SERVER is not host[:port]: '" + hp + "'");
            port = hp.substr(e + 2);
        }
    } else if (const size_t c = hp.find(':'); c == std::string::npos) {
        s.host = hp;
    } else if (hp.find(':', c + 1) != std::string::npos) {
        throw Error(2, "config: SMTP_SERVER: write an IPv6 address in brackets, e.g. [2001:db8::25]:587");
    } else {
        s.host = hp.substr(0, c);
        port = hp.substr(c + 1);
    }
    if (s.host.empty()) throw Error(2, "config: SMTP_SERVER names no host: '" + hp + "'");
    if (port.empty()) {
        s.port = s.implicit_tls ? 465 : s.plain ? 25 : 587;
    } else {
        for (char ch : port)
            if (!std::isdigit(static_cast<unsigned char>(ch)))
                throw Error(2, "config: SMTP_SERVER port is not a number: '" + hp + "'");
        s.port = port.size() > 5 ? 0 : std::stoi(port);
        if (s.port < 1 || s.port > 65535)
            throw Error(2, "config: SMTP_SERVER port is out of range: '" + hp + "'");
    }
    s.user = cfg.smtp_user;
    s.password = cfg.smtp_password;
    if (s.plain && !s.user.empty())
        throw Error(2, "config: SMTP_TLS=none cannot be used with SMTP_USER, because the password "
                       "would cross the network unencrypted. Clear SMTP_USER and SMTP_PASSWORD for a "
                       "relay that accepts this server without signing in, or use starttls or tls");
    s.ca_file = cfg.smtp_ca_file;
    s.from = cfg.smtp_from;
    if (s.from.empty())
        throw Error(2, "config: SMTP_FROM is empty; set the sender address the relay accepts");
    if (!plausible_mailbox(s.from))
        throw Error(2, "config: SMTP_FROM is not a single address: '" + s.from + "'");
    s.helo = cfg.pki_dns;
    if (s.helo.empty() || s.helo.find_first_of(" \t\r\n") != std::string::npos) s.helo = "localhost";
    return s;
}

std::string format_mail(const SmtpSettings& s, const MailMessage& m, long long now) {
    std::string out;
    out += "From: " + s.from + "\r\n";
    out += "To: " + m.to + "\r\n";
    out += "Subject: " + subject_header(m.subject) + "\r\n";
    out += "Date: " + mail_date(now) + "\r\n";
    out += "Message-ID: <" + random_hex(16) + "@" + s.from.substr(s.from.find('@') + 1) + ">\r\n";
    out += "MIME-Version: 1.0\r\n";
    out += "Content-Type: text/plain; charset=utf-8\r\n";
    out += "Content-Transfer-Encoding: base64\r\n";
    // RFC 3834: an automatic message, so a vacation responder does not answer it.
    out += "Auto-Submitted: auto-generated\r\n";
    out += "\r\n";
    // Base64 rather than 8bit: a CN or owner is whatever a requester chose, and base64 lines
    // can neither exceed the line limit nor begin with the dot that ends DATA.
    std::string body;
    body.reserve(m.body.size() + 64);
    for (size_t i = 0; i < m.body.size(); ++i) {
        if (m.body[i] == '\n' && (i == 0 || m.body[i - 1] != '\r')) body += '\r';
        body += m.body[i];
    }
    const std::string enc = b64(body);
    for (size_t i = 0; i < enc.size(); i += 76) out += enc.substr(i, 76) + "\r\n";
    return out;
}

std::vector<std::string> smtp_send(const SmtpSettings& s, const std::vector<MailMessage>& msgs) {
    std::vector<std::string> result(msgs.size());
    if (msgs.empty()) return result;
    Conn c(s);
    c.open();
    auto r = c.reply();
    if (r.first != 220) throw Error(2, "SMTP: " + s.host + " refused the connection: " + said(r));
    auto ehlo = [&] {
        c.send_line("EHLO " + s.helo);
        auto e = c.reply();
        if (e.first != 250) throw Error(2, "SMTP: " + s.host + " refused EHLO: " + said(e));
        return e.second;
    };
    std::string caps = ehlo();
    // The same refusal smtp_settings() makes, here too, because a caller can build the
    // settings by hand and the password is what is at stake.
    if (s.plain && !s.user.empty())
        throw Error(2, "SMTP: refusing to sign in to " + s.host + " without TLS");
    if (!s.implicit_tls && !s.plain) {
        if (!offers(caps, "STARTTLS"))
            throw Error(2, "SMTP: " + s.host + " does not offer STARTTLS, which SMTP_TLS=starttls "
                           "requires. Use SMTP_TLS=tls if this relay expects TLS from the first byte "
                           "(usually port 465), or SMTP_TLS=none if it speaks no TLS at all");
        c.send_line("STARTTLS");
        r = c.reply();
        if (r.first != 220) throw Error(2, "SMTP: " + s.host + " refused STARTTLS: " + said(r));
        c.start_tls();
        caps = ehlo();   // RFC 3207: what was learned before the handshake is discarded
    }
    if (!s.user.empty()) {
        std::string mechs;
        offers(caps, "AUTH", &mechs);
        mechs = " " + mechs + " ";
        if (mechs.find(" PLAIN ") != std::string::npos) {
            c.send_line("AUTH PLAIN " + b64(std::string(1, '\0') + s.user + std::string(1, '\0') + s.password));
            r = c.reply();
        } else if (mechs.find(" LOGIN ") != std::string::npos) {
            c.send_line("AUTH LOGIN");
            r = c.reply();
            if (r.first == 334) { c.send_line(b64(s.user)); r = c.reply(); }
            if (r.first == 334) { c.send_line(b64(s.password)); r = c.reply(); }
        } else {
            throw Error(2, "SMTP: " + s.host + " offers neither AUTH PLAIN nor AUTH LOGIN, so SMTP_USER "
                           "cannot sign in; clear SMTP_USER if the relay accepts this node without it");
        }
        // The reply only: the credentials are never repeated, not even the user's own name
        // beside a refusal that could quote them back.
        if (r.first != 235)
            throw Error(2, "SMTP: " + s.host + " refused the SMTP_USER credentials: " + said(r));
    }
    const long long now = static_cast<long long>(std::time(nullptr));
    size_t i = 0;
    try {
        for (; i < msgs.size(); ++i) {
            const MailMessage& m = msgs[i];
            if (!plausible_mailbox(m.to)) { result[i] = "not a usable address"; continue; }
            auto fail = [&](const std::pair<int, std::string>& why) {
                result[i] = said(why);
                c.send_line("RSET");
                c.reply();
            };
            c.send_line("MAIL FROM:<" + s.from + ">");
            r = c.reply();
            if (r.first != 250) { fail(r); continue; }
            c.send_line("RCPT TO:<" + m.to + ">");
            r = c.reply();
            if (r.first != 250 && r.first != 251) { fail(r); continue; }
            c.send_line("DATA");
            r = c.reply();
            if (r.first != 354) { fail(r); continue; }
            c.send_raw(format_mail(s, m, now) + ".\r\n");
            r = c.reply();
            if (r.first != 250) result[i] = said(r);
        }
    } catch (const std::exception& e) {
        // ⚠️ THE CONNECTION FAILED PART WAY, AND WHAT WENT BEFORE WAS DELIVERED. Throwing
        // here would report every message as unsent, so the caller would record none of them
        // and email the same people again tomorrow. The message in flight is unknown — the
        // relay may have queued it before the reply was lost — and is reported as failed,
        // which errs toward one more email rather than none.
        for (size_t k = i; k < msgs.size(); ++k)
            if (result[k].empty()) result[k] = e.what();
        return result;
    }
    try { c.send_line("QUIT"); c.reply(); } catch (const std::exception&) { /* already delivered */ }
    return result;
}

} // namespace pki
