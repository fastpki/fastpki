// A tiny UDP DNS server for the test suite. It answers exactly two record types —
// TXT (16) and CAA (257) — because those are the two ACME needs: the dns-01 challenge
// TXT at _acme-challenge.<domain>, and the CAA record §8.1.1 re-checks at issuance.
//
// ── WHY THIS IS A BINARY AND NOT A SHELL SCRIPT ──────────────────────────────────
//
// Tests are shell-only, and this is the one place that cannot be. fastpki-acme
// resolves dns-01 by speaking raw DNS over UDP (src/acme/main.cpp), with no test hook, so
// a self-contained test has to actually answer a DNS query. Shell cannot:
//
//   * shell variables cannot hold NUL bytes, and DNS packets are full of them — every
//     packet would have to round-trip through od -> hex -> printf via temp files;
//   * `nc -u` behaves differently on BSD (macOS) and busybox (the Alpine CI image), which
//     is precisely the platform-dependence §3d exists to prevent.
//
// It replaced the DNS half of the three ACME Python drivers (acme_dns01.py, acme_caa.py,
// acme_retry_after.py, ~20 lines of each); the ACME half of all three is driven in shell by
// tests/acme_jws.sh. All three are now deleted.
//
// ⚠️ IT IS NOT PART OF THE PRODUCT. The image copies binaries by prefix —
// `COPY --from=build /src/build/fastpki-* /usr/local/bin/` — and `dnsstub` does not match,
// so it is excluded by the glob rather than by anyone remembering. CMakeLists.txt has no
// install() rules either. It links nothing of ours, and no deployment needs it: a real
// one points ACME_DNS_RESOLVER at a real resolver.
//
// Usage:
//   dnsstub <port> [TXT:<name>=<value>]... [CAA:<name>=<issuer-domain>]...
//                  [RCODE:<name>=<n>]... [FORGE:<name>=id|qname]...
//
// A name with no matching record gets NOERROR with zero answers — which is what "this
// domain has no CAA" means, and acme_caa.sh needs that case to be distinguishable from
// a failure.
//
// RCODE:<name>=<n>: every query for that exact name is answered with response
// code <n> and no records — 2 = SERVFAIL, 3 = NXDOMAIN, 5 = REFUSED. It is per NAME and
// not global on purpose: a dns-01 order needs the TXT at _acme-challenge.<domain> to keep
// working while the CAA query at <domain> fails, which is the only way to reach the CAA
// re-check at finalize at all. Prints "READY" on stdout once bound, so a suite can wait for it rather than
// sleep and hope.
//
// FORGE:<name>=id|qname: answer queries for that exact name with a WRONG transaction id,
// or with a question about a different name, while still carrying the records asked for.
// This stub used to echo both verbatim, which is precisely why no test could see that
// fastpki-acme drew a random query id and then never compared it — an honest resolver and
// a spoofer looked identical from here. A forged reply is what an off-path attacker sends,
// and the resolver must discard it: a TXT it accepts validates a dns-01 challenge for a
// domain nobody controls, and a CAA it accepts erases the issuer restriction.
//
// Per NAME for the same reason RCODE is: forging every answer would break the dns-01
// challenge first, and the order would never reach the finalize-time CAA re-check that
// this is meant to exercise.

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct Record {
    std::string name;   // lower-cased, no trailing dot
    uint16_t    type;   // 16 = TXT, 257 = CAA
    std::string value;  // TXT: the string. CAA: the issuer domain for tag "issue".
};

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Decode a QNAME into dotted form. Returns false on a malformed or compressed name —
// a query is never compressed, so refusing is right rather than clever.
bool decode_name(const uint8_t* buf, size_t len, size_t& off, std::string& out) {
    out.clear();
    while (off < len) {
        const uint8_t n = buf[off];
        if (n == 0) { ++off; return true; }
        if ((n & 0xC0) != 0) return false;          // pointer: not expected in a question
        ++off;
        if (off + n > len) return false;
        if (!out.empty()) out += '.';
        out.append(reinterpret_cast<const char*>(buf + off), n);
        off += n;
    }
    return false;
}

void put16(std::vector<uint8_t>& v, uint16_t x) { v.push_back(x >> 8); v.push_back(x & 0xFF); }
void put32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(x >> 24); v.push_back((x >> 16) & 0xFF); v.push_back((x >> 8) & 0xFF); v.push_back(x & 0xFF);
}

// RDATA for the two types we serve.
std::vector<uint8_t> rdata_for(const Record& r) {
    std::vector<uint8_t> rd;
    if (r.type == 16) {                              // TXT: one <len><bytes> string
        size_t n = r.value.size() > 255 ? 255 : r.value.size();
        rd.push_back(static_cast<uint8_t>(n));
        rd.insert(rd.end(), r.value.begin(), r.value.begin() + static_cast<long>(n));
    } else {                                         // CAA (RFC 8659): flags, tag, value
        rd.push_back(0);                             // flags: not critical
        static const char kTag[] = "issue";
        rd.push_back(static_cast<uint8_t>(sizeof(kTag) - 1));
        rd.insert(rd.end(), kTag, kTag + sizeof(kTag) - 1);
        rd.insert(rd.end(), r.value.begin(), r.value.end());
    }
    return rd;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
            "usage: %s <addr:port|port> [TXT:<name>=<value>]... [CAA:<name>=<issuer>]...\n", argv[0]);
        return 2;
    }
    // Accepted forms: "port", "addr:port", "[v6addr]:port", "v6addr".
    //
    // ⚠️ SPLITTING ON THE FIRST COLON IS WRONG FOR IPv6 — "::1" would become the address
    // "" and the port ":1". An IPv6 literal is exactly what this needs to bind now: on
    // Docker Desktop the only address a container can use to reach the host
    // (`host-gateway`) is IPv6, so the resolver form the ACME server must cope with
    // cannot be exercised by a v4-only stub.
    std::string bind_arg = argv[1], addr = "127.0.0.1", port_s;
    if (!bind_arg.empty() && bind_arg.front() == '[') {
        const size_t rb = bind_arg.find(']');
        if (rb == std::string::npos) {
            std::fprintf(stderr, "dnsstub: unterminated '[' in '%s'\n", bind_arg.c_str());
            return 2;
        }
        addr = bind_arg.substr(1, rb - 1);
        if (rb + 1 < bind_arg.size() && bind_arg[rb + 1] == ':') port_s = bind_arg.substr(rb + 2);
    } else if (const size_t colon = bind_arg.find(':');
               colon != std::string::npos && bind_arg.find(':', colon + 1) == std::string::npos) {
        addr = bind_arg.substr(0, colon);          // exactly one colon ⇒ addr:port
        port_s = bind_arg.substr(colon + 1);
    } else if (bind_arg.find(':') != std::string::npos) {
        addr = bind_arg;                            // two or more ⇒ bare v6 literal
    } else {
        port_s = bind_arg;                          // digits only ⇒ port on the default addr
    }
    if (port_s.empty()) port_s = "53";

    std::vector<Record> db;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        const size_t colon = a.find(':'), eq = a.find('=');
        if (colon == std::string::npos || eq == std::string::npos || eq < colon) {
            std::fprintf(stderr, "dnsstub: cannot parse record '%s'\n", a.c_str());
            return 2;
        }
        const std::string kind = a.substr(0, colon);
        Record r;
        r.name  = lower(a.substr(colon + 1, eq - colon - 1));
        r.value = a.substr(eq + 1);
        if      (kind == "TXT")   r.type = 16;
        else if (kind == "CAA")   r.type = 257;
        else if (kind == "RCODE") r.type = 0;        // pseudo: an error response, not a record
        else if (kind == "FORGE") r.type = 65280;    // pseudo: a spoofed reply, private-use type
        else { std::fprintf(stderr, "dnsstub: unknown type '%s'\n", kind.c_str()); return 2; }
        if (!r.name.empty() && r.name.back() == '.') r.name.pop_back();
        if (r.type == 65280 && r.value != "id" && r.value != "qname") {
            std::fprintf(stderr, "dnsstub: FORGE must be id or qname, got '%s'\n", r.value.c_str());
            return 2;
        }
        if (r.type == 0) {
            const int rc = std::atoi(r.value.c_str());
            if (rc < 1 || rc > 15) {
                std::fprintf(stderr, "dnsstub: RCODE must be 1..15, got '%s'\n", r.value.c_str());
                return 2;
            }
        }
        db.push_back(r);
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP; hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    addrinfo* ai = nullptr;
    if (const int rc = ::getaddrinfo(addr.c_str(), port_s.c_str(), &hints, &ai); rc != 0 || !ai) {
        std::fprintf(stderr, "dnsstub: bad bind address '%s': %s\n",
                     argv[1], ::gai_strerror(rc));
        return 1;
    }
    int fd = -1;
    for (addrinfo* a = ai; a; a = a->ai_next) {
        fd = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        int one = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (::bind(fd, a->ai_addr, a->ai_addrlen) == 0) break;
        ::close(fd); fd = -1;
    }
    ::freeaddrinfo(ai);
    if (fd < 0) { std::perror("bind"); return 1; }
    // The suite waits for this instead of sleeping — a fixed sleep is either slower than
    // it needs to be or, on a loaded box, not long enough.
    std::printf("READY\n");
    std::fflush(stdout);

    for (;;) {
        uint8_t q[1500];
        sockaddr_storage peer{};          // v4 or v6 — the stub binds either
        socklen_t plen = sizeof(peer);
        const ssize_t n = ::recvfrom(fd, q, sizeof(q), 0,
                                     reinterpret_cast<sockaddr*>(&peer), &plen);
        if (n < 12) continue;                        // shorter than a header: ignore

        size_t off = 12;
        std::string qname;
        if (!decode_name(q, static_cast<size_t>(n), off, qname)) continue;
        if (off + 4 > static_cast<size_t>(n)) continue;
        const uint16_t qtype = static_cast<uint16_t>((q[off] << 8) | q[off + 1]);
        const size_t qend = off + 4;                 // qtype + qclass
        qname = lower(qname);

        // An RCODE entry wins over any record at the same name — it is how the
        // suite says "this lookup does not work" rather than "this name has nothing".
        int forced_rcode = 0;
        for (const auto& r : db)
            if (r.type == 0 && r.name == qname) { forced_rcode = std::atoi(r.value.c_str()); break; }

        bool forge_id = false, forge_qname = false;
        for (const auto& r : db)
            if (r.type == 65280 && r.name == qname) {
                if (r.value == "id") forge_id = true; else forge_qname = true;
            }

        std::vector<const Record*> hits;
        if (forced_rcode == 0)
            for (const auto& r : db)
                if (r.type == qtype && r.name == qname) hits.push_back(&r);

        std::vector<uint8_t> resp;
        // ^0xFF, not a fixed value: whatever the client drew, this is not it.
        if (forge_id) { resp.push_back(q[0] ^ 0xFF); resp.push_back(q[1] ^ 0xFF); }
        else          { resp.push_back(q[0]);        resp.push_back(q[1]); }
        put16(resp, static_cast<uint16_t>(0x8180 | forced_rcode));   // QR=1, RD=1, RA=1
        put16(resp, 1);                              // QDCOUNT
        put16(resp, static_cast<uint16_t>(hits.size()));
        put16(resp, 0); put16(resp, 0);              // NSCOUNT, ARCOUNT
        // The question, echoed verbatim — or, under FORGE:qname, an answer about some
        // other name. Only a LETTER is altered, and only in the label CONTENT: touching a
        // length octet would make the packet unparseable, which every parser rejects for
        // the wrong reason. Case is not enough — the comparison is deliberately
        // case-insensitive, since a resolver may legitimately change it.
        {
            std::vector<uint8_t> qs(q + 12, q + qend);
            if (forge_qname) {
                for (size_t p = 0; p < qs.size() && qs[p]; ) {
                    const size_t lab = qs[p]; bool done = false;
                    for (size_t k = p + 1; k <= p + lab && k < qs.size(); ++k) {
                        if (std::isalpha(qs[k])) {
                            qs[k] = (lower(std::string(1, static_cast<char>(qs[k])))[0] == 'a')
                                    ? 'b' : 'a';
                            done = true; break;
                        }
                    }
                    if (done) break;
                    p += lab + 1;
                }
            }
            resp.insert(resp.end(), qs.begin(), qs.end());
        }

        for (const auto* r : hits) {
            put16(resp, 0xC00C);                     // NAME: pointer to the question
            put16(resp, r->type);
            put16(resp, 1);                          // CLASS IN
            put32(resp, 30);                         // TTL
            const std::vector<uint8_t> rd = rdata_for(*r);
            put16(resp, static_cast<uint16_t>(rd.size()));
            resp.insert(resp.end(), rd.begin(), rd.end());
        }
        ::sendto(fd, resp.data(), resp.size(), 0,
                 reinterpret_cast<sockaddr*>(&peer), plen);
    }
}
