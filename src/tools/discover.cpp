// fastpki-discover — pull-based TLS certificate discovery.
//
//   fastpki-discover --config <bootstrap.conf> [--targets <file>] [--timeout 5]
//                    [--json] [host:port ...]
//
// TLS-connects to each target (no verification — we harvest what's served,
// including untrusted/self-signed certs), records the leaf certificate in the
// `discovered_certs` inventory, and flags compliance issues (weak key, expired/
// expiring, self-signed, weak signature). Targets come from positional args
// and/or a --targets file (one host:port per line, # comments allowed). A target
// may be an IPv4 CIDR (e.g. 10.0.0.0/29:8443), which is expanded to its usable
// host addresses before scanning.

#include "pki/config.hpp"
#include "pki/version.hpp"
#include "pki/db.hpp"
#include "pki/error.hpp"
#include "pki/x509.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT   // allow https migration-webhook URLs
#include "../../third_party/httplib.h"

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <netdb.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace {

int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::unique_ptr<pki::Db> open_db(const pki::Config& cfg) {
    return pki::make_postgres_db(cfg.pg_conninfo);
}

// TCP connect with a timeout, then a no-verify TLS handshake; return the served
// leaf certificate (or nullptr + err).
pki::X509Ptr harvest(const std::string& host, const std::string& port,
                     int timeout_sec, std::string& err) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) {
        err = "DNS resolution failed"; return nullptr;
    }
    int fd = -1;
    for (auto* p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        int rc = connect(fd, p->ai_addr, p->ai_addrlen);
        bool ok = (rc == 0);
        if (rc < 0 && errno == EINPROGRESS) {
            fd_set wf; FD_ZERO(&wf); FD_SET(fd, &wf);
            struct timeval tv{timeout_sec, 0};
            if (select(fd + 1, nullptr, &wf, nullptr, &tv) > 0) {
                int soerr = 0; socklen_t l = sizeof soerr;
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &l);
                ok = (soerr == 0);
            }
        }
        if (ok) { fcntl(fd, F_SETFL, fl); break; }
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) { err = "TCP connect failed/timeout"; return nullptr; }

    struct timeval tv{timeout_sec, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    // A discovery scanner must harvest legacy/weak endpoints too — drop the
    // security level so the handshake accepts SHA-1 / small-key server certs.
    SSL_CTX_set_security_level(ctx, 0);
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host.c_str());   // SNI
    pki::X509Ptr leaf;
    if (SSL_connect(ssl) == 1) {
        X509* c = SSL_get1_peer_certificate(ssl);
        if (c) leaf.reset(c); else err = "no peer certificate";
    } else {
        err = "TLS handshake failed";
    }
    SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
    return leaf;
}

std::string name_str(X509_NAME* n) {
    if (!n) return {};
    BIO* b = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(b, n, 0, XN_FLAG_RFC2253);
    char* d = nullptr; long len = BIO_get_mem_data(b, &d);
    std::string s(d, d + (len > 0 ? len : 0));
    BIO_free(b);
    return s;
}

int64_t asn1_to_unix(const ASN1_TIME* t) {
    if (!t) return 0;
    struct tm tm{};
    if (ASN1_TIME_to_tm(t, &tm) != 1) return 0;
    return static_cast<int64_t>(timegm(&tm));
}

std::string collect_sans(X509* x) {
    std::string out;
    auto* gs = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(x, NID_subject_alt_name, nullptr, nullptr));
    if (!gs) return out;
    for (int i = 0; i < sk_GENERAL_NAME_num(gs); ++i) {
        GENERAL_NAME* g = sk_GENERAL_NAME_value(gs, i);
        std::string v;
        if (g->type == GEN_DNS) {
            ASN1_STRING* a = g->d.dNSName;
            v.assign(reinterpret_cast<const char*>(ASN1_STRING_get0_data(a)),
                     ASN1_STRING_length(a));
        } else if (g->type == GEN_IPADD) {
            ASN1_OCTET_STRING* a = g->d.iPAddress;
            const unsigned char* p = ASN1_STRING_get0_data(a);
            int n = ASN1_STRING_length(a);
            if (n == 4) v = std::to_string(p[0]) + "." + std::to_string(p[1]) + "." +
                            std::to_string(p[2]) + "." + std::to_string(p[3]);
        }
        if (!v.empty()) { if (!out.empty()) out += ","; out += v; }
    }
    GENERAL_NAMES_free(gs);
    return out;
}

pki::Db::DiscoveredCert describe(const std::string& target, X509* x) {
    pki::Db::DiscoveredCert d;
    d.target      = target;
    d.serial      = pki::x509_serial_hex(x);
    d.subject     = name_str(X509_get_subject_name(x));
    d.issuer      = name_str(X509_get_issuer_name(x));
    d.not_before  = asn1_to_unix(X509_get0_notBefore(x));
    d.not_after   = asn1_to_unix(X509_get0_notAfter(x));
    d.sig_algo    = OBJ_nid2ln(X509_get_signature_nid(x));
    d.sans        = collect_sans(x);
    d.fingerprint = pki::x509_fingerprint_sha256_hex(x);
    // A real signature check, not a name comparison — a discovered listener serving a
    // re-keyed CA certificate is self-ISSUED but not self-signed, and the inventory would
    // have recorded it as an untrusted self-signed cert.
    d.self_signed = pki::x509_is_self_signed(x);
    d.discovered_at = now_unix();
    // Keep the leaf DER so the console can show every attribute later.
    unsigned char* der = nullptr;
    int dl = i2d_X509(x, &der);
    if (dl > 0 && der) { d.cert_der.assign(der, der + dl); OPENSSL_free(der); }

    EVP_PKEY* pk = X509_get0_pubkey(x);
    d.key_bits = pk ? EVP_PKEY_get_bits(pk) : 0;
    int base = pk ? EVP_PKEY_get_base_id(pk) : 0;
    d.key_algo = base == EVP_PKEY_RSA ? "RSA"
               : base == EVP_PKEY_EC  ? "EC"
               : base == EVP_PKEY_ED25519 ? "Ed25519"
               : (base ? OBJ_nid2sn(base) : "unknown");

    // Compliance flags.
    std::vector<std::string> f;
    const int64_t now = now_unix();
    if (d.not_after && d.not_after < now) f.push_back("expired");
    else if (d.not_after && d.not_after < now + 30LL * 86400) f.push_back("expiring");
    if ((d.key_algo == "RSA" && d.key_bits < 2048) ||
        (d.key_algo == "EC"  && d.key_bits < 256))
        f.push_back("weak_key");
    if (d.self_signed) f.push_back("self_signed");
    if (d.sig_algo.find("sha1") != std::string::npos ||
        d.sig_algo.find("md5")  != std::string::npos)
        f.push_back("weak_sig");
    for (size_t i = 0; i < f.size(); ++i) { if (i) d.flags += ","; d.flags += f[i]; }
    return d;
}

std::string rfc3339(int64_t t) {
    std::time_t tt = static_cast<std::time_t>(t); std::tm tm{};
    gmtime_r(&tt, &tm);
    char buf[32]; std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}
std::string json_escape(const std::string& s) {
    std::string o;
    for (char c : s) { if (c == '"' || c == '\\') o += '\\'; o += c; }
    return o;
}

// Parse a dotted-quad IPv4 into a host-order uint32. Strict: exactly 4 octets 0-255.
bool parse_ipv4(const std::string& s, uint32_t& out) {
    unsigned a, b, c, d; char extra;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4)
        return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    out = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}
std::string ipv4_str(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xff) + "." + std::to_string((ip >> 16) & 0xff)
         + "." + std::to_string((ip >> 8) & 0xff) + "." + std::to_string(ip & 0xff);
}

// Smallest CIDR prefix we will expand — /16 (65 536 addresses). Anything larger
// is almost certainly a mistake (an internet-wide sweep), so reject it.
constexpr int kMinCidrPrefix = 16;

// Expand one target into concrete host:port entries. An IPv4 CIDR host part
// (e.g. 10.0.0.0/29:8443) fans out to its usable host addresses; everything else
// (hostnames, single IPs, IPv6) passes through unchanged. Returns false with
// `err` set if a CIDR is malformed or too large to sweep.
bool expand_target(const std::string& t, std::vector<std::string>& out, std::string& err) {
    std::string hostpart = t, port = "443";
    auto colon = t.rfind(':');   // IPv4/CIDR has no colon, so the rightmost is the port
    if (colon != std::string::npos) { hostpart = t.substr(0, colon); port = t.substr(colon + 1); }

    auto slash = hostpart.find('/');
    if (slash == std::string::npos) { out.push_back(t); return true; }   // not a CIDR

    uint32_t base;
    if (!parse_ipv4(hostpart.substr(0, slash), base)) { out.push_back(t); return true; }
    int prefix = -1;
    try { prefix = std::stoi(hostpart.substr(slash + 1)); } catch (...) { prefix = -1; }
    if (prefix < 0 || prefix > 32) { err = "bad CIDR prefix in '" + t + "'"; return false; }
    if (prefix < kMinCidrPrefix) {
        err = "CIDR '" + t + "' too large to sweep (prefix < /" + std::to_string(kMinCidrPrefix) + ")";
        return false;
    }

    uint32_t mask    = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
    uint32_t network = base & mask;
    uint32_t bcast   = network | ~mask;
    // /31 and /32 have no network/broadcast convention — scan every address;
    // larger blocks skip the network and broadcast addresses.
    uint32_t lo = (prefix >= 31) ? network : network + 1;
    uint32_t hi = (prefix >= 31) ? bcast   : bcast - 1;
    for (uint32_t ip = lo; ip <= hi; ++ip) {
        out.push_back(ipv4_str(ip) + ":" + port);
        if (ip == 0xFFFFFFFFu) break;   // guard against uint32 wrap at 255.255.255.255
    }
    return true;
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

int usage() {
    std::cerr << "Usage: fastpki-discover --config <bootstrap.conf> [--targets <file>] "
                 "[--timeout 5] [--json] [--migrate-webhook <url>] "
                 "[host:port | CIDR:port ...]\n";
    return 2;
}

} // namespace

int main(int argc, char** argv) {
    if (pki::handled_version_flag(argc, argv)) return 0;
    std::string conf_path = "config/bootstrap.conf", targets_file, migrate_webhook;
    int timeout_sec = 5; bool as_json = false;
    std::vector<std::string> targets;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--config"  && i + 1 < argc) conf_path = argv[++i];
        else if (a == "--targets" && i + 1 < argc) targets_file = argv[++i];
        else if (a == "--timeout" && i + 1 < argc) timeout_sec = std::stoi(argv[++i]);
        else if (a == "--migrate-webhook" && i + 1 < argc) migrate_webhook = argv[++i];
        else if (a == "--json")                    as_json = true;
        else if (a == "--help" || a == "-h")       return usage();
        else if (!a.empty() && a[0] != '-')        targets.push_back(a);
    }
    if (!targets_file.empty()) {
        std::ifstream f(targets_file);
        std::string line;
        while (std::getline(f, line)) {
            auto h = line.find('#'); if (h != std::string::npos) line.resize(h);
            // trim
            size_t b = line.find_first_not_of(" \t\r\n");
            size_t e = line.find_last_not_of(" \t\r\n");
            if (b != std::string::npos) targets.push_back(line.substr(b, e - b + 1));
        }
    }
    if (targets.empty()) { std::cerr << "no targets\n"; return usage(); }

    // Fan out any IPv4 CIDR targets into concrete host:port entries.
    std::vector<std::string> expanded;
    for (const auto& t : targets) {
        std::string err;
        if (!expand_target(t, expanded, err)) {
            std::cerr << "fastpki-discover: " << err << "\n";
            return 2;
        }
    }

    OpenSSL_add_all_algorithms();
    try {
        pki::Config cfg = pki::Config::load(conf_path);
        auto db = open_db(cfg);

        int found = 0, failed = 0, flagged = 0;
        std::vector<pki::Db::DiscoveredCert> flagged_list;  // non-compliant -> migration work list
        bool first = true;
        if (as_json) std::cout << "[";
        for (const auto& t : expanded) {
            std::string host = t, port = "443";
            auto colon = t.rfind(':');
            if (colon != std::string::npos) { host = t.substr(0, colon); port = t.substr(colon + 1); }

            std::string err;
            auto cert = harvest(host, port, timeout_sec, err);
            if (!cert) {
                ++failed;
                if (!as_json) std::cout << "  [ERROR] " << t << ": " << err << "\n";
                continue;
            }
            auto d = describe(t, cert.get());
            db->record_discovered(d);
            ++found;
            if (!d.flags.empty()) { ++flagged; flagged_list.push_back(d); }

            if (as_json) {
                if (!first) std::cout << ",";
                first = false;
                std::cout << "{\"target\":\"" << json_escape(d.target) << "\",\"subject\":\""
                          << json_escape(d.subject) << "\",\"issuer\":\"" << json_escape(d.issuer)
                          << "\",\"notAfter\":\"" << rfc3339(d.not_after) << "\",\"keyAlgo\":\""
                          << d.key_algo << "\",\"keyBits\":" << d.key_bits << ",\"sigAlgo\":\""
                          << json_escape(d.sig_algo) << "\",\"fingerprint\":\"" << d.fingerprint
                          << "\",\"flags\":\"" << d.flags << "\"}";
            } else {
                std::cout << "  [FOUND] " << d.target << "  " << d.subject
                          << "  " << d.key_algo << "-" << d.key_bits
                          << "  expires=" << rfc3339(d.not_after)
                          << (d.flags.empty() ? "" : ("  FLAGS=" + d.flags)) << "\n";
            }
        }
        if (as_json) std::cout << "]\n";
        else std::cout << "discovered " << found << " cert(s), " << flagged
                       << " flagged, " << failed << " unreachable\n";

        // Migration trigger: hand the non-compliant endpoints to an
        // external re-enrollment agent (Ansible / EST / ACME cron) as a work list.
        if (!migrate_webhook.empty()) {
            std::string body = "{\"generated\":\"" + rfc3339(now_unix()) +
                               "\",\"count\":" + std::to_string(flagged_list.size()) +
                               ",\"migrations\":[";
            for (size_t i = 0; i < flagged_list.size(); ++i) {
                const auto& d = flagged_list[i];
                if (i) body += ",";
                body += "{\"target\":\"" + json_escape(d.target) + "\",\"subject\":\"" +
                        json_escape(d.subject) + "\",\"fingerprint\":\"" + d.fingerprint +
                        "\",\"notAfter\":\"" + rfc3339(d.not_after) + "\",\"keyAlgo\":\"" +
                        d.key_algo + "\",\"keyBits\":" + std::to_string(d.key_bits) +
                        ",\"flags\":\"" + d.flags + "\"}";
            }
            body += "]}";
            std::string note;
            bool ok = post_webhook(migrate_webhook, body, note);
            std::cerr << "fastpki-discover: migration webhook (" << flagged_list.size()
                      << " cert(s)) -> " << note << "\n";
            if (!ok) return 1;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fastpki-discover: " << e.what() << "\n";
        return 1;
    }
}
