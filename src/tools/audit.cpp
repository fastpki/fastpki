// fastpki-audit — operate on the tamper-evident audit log.
//
//   fastpki-audit --config <bootstrap.conf> verify [--ca <ca_id>]
//       Recompute the whole hash chain, then check the latest signed checkpoint.
//       Exit 0 if intact, 1 if a break/gap/tamper/truncation is detected
//       (suitable for a cron integrity check).
//
//   fastpki-audit --config <bootstrap.conf> sign --ca <ca_id>
//       Sign a checkpoint over the current head, so a truncated log fails verify.
//
//   fastpki-audit --config <bootstrap.conf> append <category> <action> <actor>
//                 <status> [target] [detail]
//       Append one event (for administrative/script-driven events and tests).
//
//   fastpki-audit --config <bootstrap.conf> export [after_seq]
//       Print all rows after `after_seq` (default 0) as JSON lines — the basis
//       for SIEM forwarding / compliance export (tasks 3.3.3 / 3.3.4).
//
//   fastpki-audit --config <bootstrap.conf> export-signed [--after seq] --ca <ca_id> --out <path>
//       Write the range as NDJSON plus a detached CA signature (<path>.sig) over
//       its digest — a verifiable compliance export.
//   fastpki-audit --config <bootstrap.conf> verify-export --ca <ca_id> --out <path>
//       Recompute the digest and check the signature against that CA's certificate,
//       read from the database; fail closed if either the bytes or the signature
//       were altered.
//
// Every command that signs or checks a signature names its CA with --ca: `sign`,
// both export commands, and `verify` once a checkpoint exists. There is no default CA.
//
// The DB backend and location come from the config, so this
// tool shares the exact code path the servers use.

#include "pki/audit.hpp"
#include "pki/version.hpp"
#include "pki/ca_instance.hpp"
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/endpoint_gate.hpp"
#include "pki/error.hpp"
#include "pki/x509.hpp"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

// ⚠️ NO `Expect: 100-continue`, AND THIS IS A CORRECTNESS FIX RATHER THAN A PREFERENCE.
// The HTTP client library adds that header by itself once a body passes 1 KiB, and then
// withholds the body until the server answers `100 Continue`. A collector that does not
// implement the handshake — and plenty do not — answers the final status straight away,
// the body is never sent, and the shipper sees a 200 and marks those audit rows delivered.
// Records that were recorded, reported successful, and never left the machine.
//
// Measured: five audit rows make a 2005-byte body, which crossed the threshold; three rows
// did not. So the failure appears only once a deployment has enough audit traffic to fill
// a batch, which is exactly when it is least likely to be noticed.
//
// Sending headers and body together costs nothing here (the batch is small and the token
// is already in the headers) and makes the 200 an unambiguous acknowledgement.
#define CPPHTTPLIB_EXPECT_100_THRESHOLD 0
#include "httplib.h"

#include <chrono>
#include <thread>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <netdb.h>
#include <optional>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace {

int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string rfc3339(int64_t t) {
    std::time_t tt = static_cast<std::time_t>(t); std::tm tm{};
    gmtime_r(&tt, &tm);
    char buf[32]; std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// Escape a value for an RFC 5424 structured-data param ( \ " ] ).
std::string sd_escape(const std::string& s) {
    std::string o;
    for (char c : s) { if (c == '\\' || c == '"' || c == ']') o += '\\'; o += c; }
    return o;
}

// Format an audit row as an RFC 5424 syslog message. Facility = security/authpriv
// (10); severity = warning (4) for failures, else informational (6).
std::string syslog_line(const pki::AuditRow& r, const std::string& host) {
    int sev = (r.ev.status == "failure") ? 4 : 6;
    int pri = 10 * 8 + sev;
    auto p = [](const std::string& s) { return sd_escape(s); };
    std::string sd = "[fastpki@32473 seq=\"" + std::to_string(r.seq) +
                     "\" category=\"" + p(r.ev.category) + "\" actor=\"" + p(r.ev.actor) +
                     "\" actor_ip=\"" + p(r.ev.actor_ip) + "\" target=\"" + p(r.ev.target) +
                     "\" status=\"" + p(r.ev.status) + "\" hash=\"" + r.hash + "\"]";
    std::string msg = r.ev.action + (r.ev.detail.empty() ? "" : (" " + r.ev.detail));
    return "<" + std::to_string(pri) + ">1 " + rfc3339(r.ev.ts) + " " +
           (host.empty() ? "-" : host) + " fastpki - " + r.ev.action + " " + sd + " " + msg;
}

// ── Shipping a message to a collector ──────────────────────────────────────────────
//
// ⚠️ TCP SYSLOG IS FRAMED AND UDP SYSLOG IS NOT, and getting that wrong produces a
// collector that connects, accepts every byte and displays nothing — the least
// debuggable failure in this file. Over a stream there is no message boundary, so
// RFC 6587 §3.4.1 prefixes each message with its octet count and a space:
//
//     47 <86>1 2003-10-11T22:14:15.003Z host fastpki - ...
//
// Over a datagram the boundary IS the datagram, and a length prefix would be parsed as
// part of the message. So the framing belongs to the transport, not to syslog_line().
std::string octet_framed(const std::string& msg) {
    return std::to_string(msg.size()) + " " + msg;
}

// A syslog stream: TCP, optionally wrapped in TLS. One connection carries many messages,
// which is the point of using TCP at all.
class SyslogStream {
public:
    SyslogStream(std::string host, std::string port, bool tls, std::string ca_pem)
        // Init order follows the DECLARATION order below (host_, port_, ca_pem_, then
        // tls_) — a mismatch is a -Wreorder-ctor warning, and the build gate treats any
        // warning as a failure precisely so a real one is never lost in the noise.
        : host_(std::move(host)), port_(std::move(port)), ca_pem_(std::move(ca_pem)), tls_(tls) {}
    ~SyslogStream() { close_(); }

    // Returns an empty string on success, else the reason — which is reported, never
    // swallowed: a shipper that cannot reach its collector and says nothing is
    // indistinguishable from one with nothing to send.
    std::string send(const std::string& msg) {
        if (!bio_ && !connect_(/*err=*/nullptr)) {
            std::string e;
            if (!connect_(&e)) return e.empty() ? "cannot connect" : e;
        }
        const std::string framed = octet_framed(msg);
        if (BIO_write(bio_, framed.data(), static_cast<int>(framed.size())) > 0 &&
            BIO_flush(bio_) > 0)
            return "";
        // One reconnect, then give up for this pass. A collector that restarts drops the
        // connection, and re-establishing it is ordinary rather than exceptional.
        close_();
        std::string e;
        if (!connect_(&e)) return e.empty() ? "cannot reconnect" : e;
        if (BIO_write(bio_, framed.data(), static_cast<int>(framed.size())) > 0 &&
            BIO_flush(bio_) > 0)
            return "";
        close_();
        return "write failed";
    }

private:
    bool connect_(std::string* err) {
        const std::string hp = host_ + ":" + port_;
        if (!tls_) {
            bio_ = BIO_new_connect(hp.c_str());
            if (!bio_ || BIO_do_connect(bio_) <= 0) {
                if (err) *err = "connect to " + hp + " failed";
                close_(); return false;
            }
            return true;
        }
        ctx_ = SSL_CTX_new(TLS_client_method());
        if (!ctx_) { if (err) *err = "SSL_CTX_new failed"; return false; }
        SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
        // ⚠️ VERIFY, ALWAYS. The audit trail is the record of who did what; handing it to
        // whoever answers on that port would be worse than not forwarding it at all.
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
        if (!ca_pem_.empty()) {
            // A named CA anchors the collector, for an internal Splunk whose certificate
            // is not in the host trust store.
            BIO* mem = BIO_new_mem_buf(ca_pem_.data(), static_cast<int>(ca_pem_.size()));
            X509_STORE* store = SSL_CTX_get_cert_store(ctx_);
            bool any = false;
            while (X509* x = PEM_read_bio_X509(mem, nullptr, nullptr, nullptr)) {
                X509_STORE_add_cert(store, x); X509_free(x); any = true;
            }
            BIO_free(mem);
            if (!any) { if (err) *err = "the configured anchor held no certificate"; close_(); return false; }
        } else if (SSL_CTX_set_default_verify_paths(ctx_) != 1) {
            // One statement per line: `if (err) *err = ...; close_(); return false;` reads
            // as though the last two are guarded by the `if`, and -Wmisleading-indentation
            // says so. They never were -- the siblings above and below brace the whole
            // group, which is why only this one warned.
            if (err) *err = "no system trust store";
            close_(); return false;
        }
        bio_ = BIO_new_ssl_connect(ctx_);
        if (!bio_) { if (err) *err = "BIO_new_ssl_connect failed"; close_(); return false; }
        BIO_set_conn_hostname(bio_, hp.c_str());
        SSL* ssl = nullptr;
        BIO_get_ssl(bio_, &ssl);
        if (ssl) {
            SSL_set_tlsext_host_name(ssl, host_.c_str());
            // Name checking is separate from chain verification and is the half that is
            // easy to leave out; without it any certificate the anchor signed is accepted.
            SSL_set1_host(ssl, host_.c_str());
        }
        if (BIO_do_connect(bio_) <= 0 || BIO_do_handshake(bio_) <= 0) {
            if (err) *err = "TLS handshake with " + hp + " failed";
            close_(); return false;
        }
        return true;
    }
    void close_() {
        if (bio_) { BIO_free_all(bio_); bio_ = nullptr; }
        if (ctx_) { SSL_CTX_free(ctx_); ctx_ = nullptr; }
    }
    std::string host_, port_, ca_pem_;
    bool tls_{false};
    BIO* bio_{nullptr};
    SSL_CTX* ctx_{nullptr};
};

// Send one datagram to host:port over UDP. Returns true on success.
bool udp_send(const std::string& host, const std::string& port, const std::string& msg) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) return false;
    bool ok = false;
    for (auto* a = res; a; a = a->ai_next) {
        int fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        if (sendto(fd, msg.data(), msg.size(), 0, a->ai_addr, a->ai_addrlen) >= 0) ok = true;
        close(fd);
        if (ok) break;
    }
    freeaddrinfo(res);
    return ok;
}

std::unique_ptr<pki::Db> open_db(const pki::Config& cfg) {
    return pki::make_postgres_db(cfg.pg_conninfo);
}

// Split "https://host:8088/services/collector/event" into the origin httplib::Client
// wants and the path it takes separately.
bool split_url(const std::string& url, std::string& base, std::string& path) {
    const auto sep = url.find("://");
    if (sep == std::string::npos) return false;
    const auto slash = url.find('/', sep + 3);
    if (slash == std::string::npos) { base = url; path = "/"; return true; }
    base = url.substr(0, slash);
    path = url.substr(slash);
    return true;
}

std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) switch (c) {
        case '"':  o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n";  break;
        case '\r': o += "\\r";  break;
        case '\t': o += "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                static const char* h = "0123456789abcdef";
                o += "\\u00"; o += h[(c >> 4) & 0xf]; o += h[c & 0xf];
            } else o += c;
    }
    return o;
}

std::string json_line(const pki::AuditRow& r) {
    auto f = [](const std::string& s) { return json_escape(s); };
    std::ostringstream o;
    o << "{"
      << "\"seq\":" << r.seq
      << ",\"ts\":" << r.ev.ts
      << ",\"category\":\"" << f(r.ev.category) << "\""
      << ",\"action\":\""   << f(r.ev.action)   << "\""
      << ",\"actor\":\""    << f(r.ev.actor)    << "\""
      << ",\"actor_ip\":\"" << f(r.ev.actor_ip) << "\""
      << ",\"target\":\""   << f(r.ev.target)   << "\""
      << ",\"status\":\""   << f(r.ev.status)   << "\""
      << ",\"detail\":\""   << f(r.ev.detail)   << "\""
      << ",\"prev_hash\":\"" << r.prev_hash << "\""
      << ",\"hash\":\""      << r.hash      << "\""
      << "}\n";
    return o.str();
}

void print_json_line(const pki::AuditRow& r) { std::cout << json_line(r); }

// Subject CN of a cert, for stamping the export with the signer identity.
std::string cert_cn(X509* x) {
    X509_NAME* n = X509_get_subject_name(x);
    char buf[256];
    int l = X509_NAME_get_text_by_NID(n, NID_commonName, buf, sizeof buf);
    return l > 0 ? std::string(buf, static_cast<size_t>(l)) : "";
}

std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

int usage() {
    std::cerr <<
        "Usage:\n"
        "  fastpki-audit --config <bootstrap.conf> verify [--ca <ca_id>]\n"
        "      --ca is required once a signed checkpoint exists.\n"
        "  fastpki-audit --config <bootstrap.conf> sign --ca <ca_id>\n"
        "  fastpki-audit --config <bootstrap.conf> append <category> <action> <actor> <status> [target] [detail]\n"
        "  fastpki-audit --config <bootstrap.conf> export [after_seq]\n"
        "  fastpki-audit --config <bootstrap.conf> export-signed [--after seq] --ca <ca_id> --out <path>\n"
        "  fastpki-audit --config <bootstrap.conf> verify-export --ca <ca_id> --out <path>\n"
        "  fastpki-audit --config <bootstrap.conf> forward [--follow] [--after seq]\n"
        "                [--syslog host:port] [--stdout]\n"
        "      Ship audit rows to the collector named by AUDIT_FORWARD/AUDIT_FORWARD_TARGET.\n"
        "      Where it got to is remembered per destination, so restarting resumes rather\n"
        "      than re-sending or skipping. --follow keeps going; --after overrides the\n"
        "      stored position for one run without moving it.\n";
    return 2;
}

} // namespace

int main(int argc, char** argv) {
    if (pki::handled_version_flag(argc, argv)) return 0;
    std::string conf_path = "config/bootstrap.conf", syslog_target, out_path, ca_id;
    int64_t after_seq = 0;
    bool follow = false, to_stdout = false, after_given = false;
    std::vector<std::string> pos;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--config" && i + 1 < argc) conf_path = argv[++i];
        else if (a == "--syslog" && i + 1 < argc) syslog_target = argv[++i];
        else if (a == "--after"  && i + 1 < argc) { after_seq = std::stoll(argv[++i]); after_given = true; }
        else if (a == "--out"    && i + 1 < argc) out_path = argv[++i];
        else if (a == "--ca"     && i + 1 < argc) ca_id = argv[++i];
        else if (a == "--follow") follow = true;
        else if (a == "--stdout") to_stdout = true;
        else if (a == "--help" || a == "-h") return usage();
        else pos.push_back(std::move(a));
    }
    if (pos.empty()) return usage();
    const std::string& cmd = pos[0];

    try {
        pki::Config cfg = pki::Config::load(conf_path);
        auto db = open_db(cfg);

        // No default CA — the CA that signs/verifies audit checkpoints & exports is
        // named with --ca <ca_id> and resolved from the DB. Returns {cert_der, key_ref}.
        auto audit_ca = [&](bool need_key) -> std::pair<std::vector<unsigned char>, std::string> {
            if (ca_id.empty())
                throw std::runtime_error("name the CA with --ca <ca_id> (there is no default CA)");
            auto rc = pki::resolve_ca_instance(*db, cfg, ca_id);
            if (!rc.found) throw std::runtime_error("unknown CA instance '" + ca_id + "'");
            if (need_key && rc.key.empty())
                throw std::runtime_error("CA '" + ca_id + "' has no signing key on this node");
            return { rc.cert_der, rc.key };
        };

        if (cmd == "verify") {
            auto rows = db->get_audit(0, 0);
            auto res = pki::verify_audit_chain(rows);
            if (!res.ok) {
                std::cout << "AUDIT FAIL at seq " << res.broken_seq << ": " << res.reason
                          << " (" << res.count << " entries scanned)\n";
                return 1;
            }
            std::cout << "AUDIT OK: " << res.count << " entries, chain intact. head="
                      << (res.head_hash.empty() ? "(empty)" : res.head_hash) << "\n";

            // Validate the latest signed checkpoint: proves the log
            // hasn't been truncated below the anchored head.
            auto cp = db->latest_audit_checkpoint();
            if (!cp) { std::cout << "  (no signed checkpoint)\n"; return 0; }
            pki::X509Ptr ca = pki::parse_cert_der(audit_ca(false).first);
            EVP_PKEY* pub = X509_get_pubkey(ca.get());
            bool sig_ok = pub && pki::audit_verify_head(pub, cp->head_seq, cp->head_hash, cp->signature);
            if (pub) EVP_PKEY_free(pub);
            if (!sig_ok) {
                std::cout << "CHECKPOINT FAIL: signature invalid for head_seq="
                          << cp->head_seq << "\n";
                return 1;
            }
            // The chain must still contain the checkpointed head.
            const pki::AuditRow* anchor = nullptr;
            for (const auto& r : rows) if (r.seq == cp->head_seq) { anchor = &r; break; }
            if (!anchor) {
                std::cout << "CHECKPOINT FAIL: log truncated — checkpointed head_seq="
                          << cp->head_seq << " is missing (current "
                          << (rows.empty() ? 0 : rows.back().seq) << ")\n";
                return 1;
            }
            if (anchor->hash != cp->head_hash) {
                std::cout << "CHECKPOINT FAIL: head at seq=" << cp->head_seq
                          << " diverged from the signed hash\n";
                return 1;
            }
            std::cout << "  checkpoint OK: head_seq=" << cp->head_seq
                      << " signed and present (signed at " << cp->at << ")\n";
            return 0;
        }

        if (cmd == "sign") {
            auto rows = db->get_audit(0, 0);
            auto res = pki::verify_audit_chain(rows);
            if (!res.ok) {
                std::cout << "refusing to sign: chain is broken at seq "
                          << res.broken_seq << " (" << res.reason << ")\n";
                return 1;
            }
            if (rows.empty()) { std::cout << "nothing to sign (empty log)\n"; return 1; }
            pki::EvpPkeyPtr key = pki::load_signing_key(audit_ca(true).second, cfg);
            pki::Db::AuditCheckpoint cp;
            cp.at        = now_unix();
            cp.head_seq  = rows.back().seq;
            cp.head_hash = res.head_hash;
            cp.signature = pki::audit_sign_head(key.get(), cp.head_seq, cp.head_hash);
            db->store_audit_checkpoint(cp);
            std::cout << "signed checkpoint: head_seq=" << cp.head_seq
                      << " head=" << cp.head_hash << "\n";
            return 0;
        }

        if (cmd == "append") {
            if (pos.size() < 5) return usage();
            pki::AuditEvent ev;
            ev.category = pos[1];
            ev.action   = pos[2];
            ev.actor    = pos[3];
            ev.status   = pos[4];
            ev.target   = (pos.size() > 5) ? pos[5] : "";
            ev.detail   = (pos.size() > 6) ? pos[6] : "";
            auto row = db->append_audit(ev);
            std::cout << "appended seq=" << row.seq << " hash=" << row.hash << "\n";
            return 0;
        }

        if (cmd == "export") {
            int64_t after = (pos.size() > 1) ? std::stoll(pos[1]) : 0;
            for (const auto& r : db->get_audit(after, 0)) print_json_line(r);
            return 0;
        }

        // Signed compliance export: write the audit range
        // as NDJSON plus a detached CA signature over the file digest, so an
        // auditor can verify authenticity + integrity offline (the UI's
        // "Export Compliance Report" wraps this; the verifiable core is here).
        if (cmd == "export-signed") {
            if (out_path.empty()) { std::cerr << "export-signed needs --out <path>\n"; return 2; }
            auto res = pki::verify_audit_chain(db->get_audit(0, 0));
            if (!res.ok) {
                std::cout << "refusing to export-sign: chain broken at seq "
                          << res.broken_seq << " (" << res.reason << ")\n";
                return 1;
            }
            auto rows = db->get_audit(after_seq, 0);
            std::string nd;
            for (const auto& r : rows) nd += json_line(r);
            {
                std::ofstream of(out_path, std::ios::binary | std::ios::trunc);
                if (!of) { std::cerr << "cannot write " << out_path << "\n"; return 1; }
                of.write(nd.data(), static_cast<std::streamsize>(nd.size()));
            }
            const std::string digest = pki::sha256_hex(nd);
            const int64_t head_seq = rows.empty() ? 0 : rows.back().seq;
            pki::EvpPkeyPtr key = pki::load_signing_key(audit_ca(true).second, cfg);
            const std::string sig = pki::audit_sign_head(key.get(), head_seq, digest);
            pki::X509Ptr ca = pki::parse_cert_der(audit_ca(false).first);
            std::ofstream sf(out_path + ".sig", std::ios::trunc);
            sf << "sha256="    << digest      << "\n"
               << "head_seq="  << head_seq    << "\n"
               << "count="     << rows.size() << "\n"
               << "after_seq=" << after_seq   << "\n"
               << "signed_at=" << now_unix()  << "\n"
               << "signer="    << cert_cn(ca.get()) << "\n"
               << "signature=" << sig         << "\n";
            std::cout << "exported " << rows.size() << " event(s) to " << out_path
                      << " (+ .sig), head_seq=" << head_seq << "\n";
            return 0;
        }

        if (cmd == "verify-export") {
            if (out_path.empty()) { std::cerr << "verify-export needs --out <path>\n"; return 2; }
            const std::string nd = read_file(out_path);
            const std::string sigtext = read_file(out_path + ".sig");
            if (sigtext.empty()) { std::cout << "EXPORT FAIL: missing " << out_path << ".sig\n"; return 1; }
            std::map<std::string, std::string> m;
            std::istringstream is(sigtext);
            std::string line;
            while (std::getline(is, line)) {
                auto eq = line.find('=');
                if (eq == std::string::npos) continue;
                std::string v = line.substr(eq + 1);
                if (!v.empty() && v.back() == '\r') v.pop_back();
                m[line.substr(0, eq)] = v;
            }
            const std::string have = pki::sha256_hex(nd);
            if (m["sha256"] != have) {
                std::cout << "EXPORT FAIL: content digest mismatch — the export was altered\n";
                return 1;
            }
            const int64_t head_seq = m.count("head_seq") ? std::stoll(m["head_seq"]) : 0;
            pki::X509Ptr ca = pki::parse_cert_der(audit_ca(false).first);
            EVP_PKEY* pub = X509_get_pubkey(ca.get());
            bool ok = pub && pki::audit_verify_head(pub, head_seq, have, m["signature"]);
            if (pub) EVP_PKEY_free(pub);
            if (!ok) { std::cout << "EXPORT FAIL: CA signature invalid\n"; return 1; }
            std::cout << "EXPORT OK: " << m["count"] << " event(s), digest "
                      << have.substr(0, 16) << "… signed by " << m["signer"]
                      << " (head_seq=" << head_seq << ")\n";
            return 0;
        }

        if (cmd == "forward") {
            // Ship the audit trail to a collector. The destination comes from the config —
            // and therefore from the DB overlay like every other setting — so a deployment
            // is repointed by changing a key, not by editing a command line.
            pki::overlay_config(cfg, db->get_config());

            // `--syslog host:port` still works and overrides the config, because it is what
            // makes this testable and is a reasonable way to try a collector out.
            std::string mode   = cfg.audit_forward;
            std::string target = cfg.audit_forward_target;
            if (!syslog_target.empty()) { mode = "syslog"; target = syslog_target; }

            // Nothing configured. The two callers want opposite things, so they get
            // opposite answers rather than one compromise:
            //   * `--follow` is the service. It must ship nothing and exit, or a
            //     deployment that never asked for forwarding would print its entire audit
            //     log to the container's stdout every interval — turning the feature off
            //     into a log-spam feature.
            //   * a one-shot run is a person at a terminal, and printing the messages is
            //     the useful thing to do (and what this command has always done). It is a
            //     diagnostic, so it does NOT move the stored position: a replay you can
            //     see is not a delivery, and letting it advance the mark would make the
            //     next real pass skip everything you just looked at.
            if (mode == "off" && !to_stdout) {
                if (follow) {
                    std::cerr << "fastpki-audit: AUDIT_FORWARD is off — nothing to forward "
                                 "(set it to 'syslog' or 'hec')\n";
                    return 0;
                }
                to_stdout = true;
            }
            if (!to_stdout && target.empty()) {
                std::cerr << "fastpki-audit: AUDIT_FORWARD=" << mode
                          << " but AUDIT_FORWARD_TARGET is empty\n";
                return 1;
            }

            char hn[256] = {0};
            if (gethostname(hn, sizeof hn - 1) != 0) hn[0] = '\0';
            const std::string host = hn;

            // ⚠️ THE MARK IS KEYED BY THE DESTINATION, and `--after` overrides it for this
            // run only. Without a stored mark the only choices on restart are to re-send
            // the whole log or to skip whatever arrived while the shipper was down; a
            // duplicate audit record is noise, a missing one is the failure this exists to
            // prevent, and neither is acceptable as a default.
            const std::string mark_key = mode + ":" + target;
            // ⚠️ WHETHER THE FLAG WAS GIVEN, not whether its value is non-zero. `--after 0`
            // is the natural way to ask for a full replay, and testing the VALUE made that
            // request silently mean "use the stored mark" — i.e. the one spelling most
            // likely to be typed did nothing at all.
            // ⚠️ PRINTING TO A TERMINAL IS NOT DELIVERY, so the stdout path must not move
            // the mark either. It did once: the position was stored under a "stdout" key,
            // so a bare `forward` run to look at the log advanced it and the same command
            // a minute later printed nothing at all — and, worse, the comment beside it
            // claimed this could not happen.
            const bool mark_overridden = after_given || to_stdout;

            std::string sh, sp;
            if (mode == "syslog") {
                const auto c = target.rfind(':');
                sh = (c == std::string::npos) ? target : target.substr(0, c);
                sp = (c == std::string::npos) ? (cfg.audit_forward_tls ? "6514" : "514")
                                              : target.substr(c + 1);
            }
            // The anchor for a TLS collector, when one is named. Read once: a CA row does
            // not change under us mid-run, and re-reading it per batch would put a DB query
            // in the hot path for no gain.
            std::string anchor_pem;
            if (mode == "syslog" && cfg.audit_forward_tls && !cfg.audit_forward_ca_id.empty()) {
                auto rc = pki::resolve_ca_instance(*db, cfg, cfg.audit_forward_ca_id);
                if (!rc.found)
                    throw std::runtime_error("AUDIT_FORWARD_CA_ID names no CA instance: " +
                                             cfg.audit_forward_ca_id);
                anchor_pem = pki::der_to_pem_cert(rc.cert_der);
            }
            std::unique_ptr<SyslogStream> stream;
            if (mode == "syslog" && cfg.audit_forward_proto == "tcp" && !to_stdout)
                stream = std::make_unique<SyslogStream>(sh, sp, cfg.audit_forward_tls, anchor_pem);

            const int batch = cfg.audit_forward_batch > 0 ? cfg.audit_forward_batch : 500;
            long long total = 0;

            // One pass: read the rows past the mark, ship them, and advance the mark ONLY
            // for what actually went. Returns false when the pass could not deliver, so
            // --follow backs off instead of spinning against a dead collector.
            auto one_pass = [&]() -> bool {
                const int64_t from = mark_overridden ? after_seq
                                                     : db->get_audit_forward_mark(mark_key);
                auto rows = db->get_audit(from, batch);
                if (rows.empty()) return true;

                if (mode == "hec" && !to_stdout) {
                    // HEC takes the whole batch in one request, which is the reason to use
                    // it. A 200 is a real acknowledgement, unlike a successful socket write.
                    std::string base, path;
                    if (!split_url(target, base, path))
                        throw std::runtime_error("AUDIT_FORWARD_TARGET is not a URL: " + target);
                    std::string body;
                    for (const auto& r : rows)
                        body += "{\"time\":" + std::to_string(r.ev.ts) +
                                ",\"host\":\"" + json_escape(host) + "\"" +
                                ",\"sourcetype\":\"fastpki:audit\"" +
                                ",\"event\":" + json_line(r).substr(0, json_line(r).size() - 1) +
                                "}\n";
                    httplib::Client cli(base);
                    cli.set_read_timeout(30, 0);
                    httplib::Headers h;
                    if (!cfg.audit_forward_token.empty())
                        h.emplace("Authorization", "Splunk " + cfg.audit_forward_token);
                    auto res = cli.Post(path, h, body, "application/json");
                    if (!res || res->status != 200) {
                        // Never echo the token, and never echo the body: the audit detail
                        // it carries is exactly the material this deployment is trying to
                        // keep in one place.
                        std::cerr << "fastpki-audit: HEC POST to " << base << path << " -> "
                                  << (res ? std::to_string(res->status) : std::string("no response"))
                                  << "\n";
                        return false;
                    }
                    if (!mark_overridden) db->set_audit_forward_mark(mark_key, rows.back().seq);
                    total += static_cast<long long>(rows.size());
                    return true;
                }

                // syslog (or stdout): one message per row, and the mark follows the last
                // row that was actually accepted — so a collector that dies half way
                // through a batch costs a retry of the remainder, not of the whole log.
                int64_t last_ok = 0;
                long long sent = 0;
                for (const auto& r : rows) {
                    const std::string line = syslog_line(r, host);
                    if (to_stdout) { std::cout << line << "\n"; last_ok = r.seq; ++sent; continue; }
                    if (cfg.audit_forward_proto == "udp") {
                        if (!udp_send(sh, sp, line)) {
                            std::cerr << "fastpki-audit: UDP send to " << target << " failed\n";
                            break;
                        }
                    } else {
                        const std::string e = stream->send(line);
                        if (!e.empty()) {
                            std::cerr << "fastpki-audit: syslog to " << target << ": " << e << "\n";
                            break;
                        }
                    }
                    last_ok = r.seq;
                    ++sent;
                }
                if (last_ok && !mark_overridden) db->set_audit_forward_mark(mark_key, last_ok);
                total += sent;
                return last_ok == rows.back().seq;
            };

            if (!follow) {
                const bool ok = one_pass();
                std::cerr << "fastpki-audit: forwarded " << total << " event(s) to "
                          << (to_stdout ? "stdout" : target) << "\n";
                return ok ? 0 : 1;
            }
            // Stamp when this shipper started serving, the same way every listener does.
            // The Config page decides whether a setting change has reached the process
            // that READS it by comparing the change against that process's start marker,
            // and the AUDIT_FORWARD_* keys are read here and nowhere else. Without this
            // row the console has no evidence about this process at all — and its section
            // default would answer for the eight listeners instead, clearing the "pending
            // restart" mark once THEY had restarted while this shipper carried on with the
            // previous collector address.
            //
            // Stamped HERE, not at entry: the branches above exit without shipping when
            // forwarding is off or unconfigured, and a process that ships nothing has not
            // started. Best-effort, like the listeners' own stamp — a database blip must
            // not stop the shipper; a missing marker reads as "has not reported a start".
            try {
                db->set_config(pki::endpoint_started_key("auditfwd"),
                               std::to_string(static_cast<int64_t>(std::time(nullptr))));
            } catch (const std::exception& e) {
                std::cerr << "fastpki-audit: could not record the start marker (" << e.what()
                          << ") — the Config page cannot show whether this process has "
                             "picked up a setting change until it starts again\n";
            }
            const int iv = cfg.audit_forward_interval_sec > 0 ? cfg.audit_forward_interval_sec : 10;
            std::cerr << "fastpki-audit: following the audit log, shipping to "
                      << (to_stdout ? "stdout" : target) << " every " << iv << "s\n";
            for (;;) {
                try { one_pass(); }
                catch (const std::exception& e) {
                    // A pass that throws must not kill the shipper: a collector outage or a
                    // DB blip is temporary, and exiting here would stop forwarding until
                    // somebody noticed the container had gone.
                    std::cerr << "fastpki-audit: pass failed: " << e.what() << "\n";
                }
                std::this_thread::sleep_for(std::chrono::seconds(iv));
            }
        }

        return usage();
    } catch (const std::exception& e) {
        std::cerr << "fastpki-audit: " << e.what() << "\n";
        return 1;
    }
}
