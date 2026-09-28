#include "pki/client_addr.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

namespace pki {
namespace {

// A parsed address: the family, and the bytes in network order. 4 bytes for IPv4, 16 for
// IPv6. `ok` false means it did not parse and nothing should match it.
struct Addr {
    bool ok{false};
    int  bits{0};                     // 32 or 128 — the address width, not a prefix
    std::array<unsigned char, 16> b{};
};

std::string trim(const std::string& s) {
    const auto a = s.find_first_not_of(" \t");
    if (a == std::string::npos) return "";
    const auto b = s.find_last_not_of(" \t");
    return s.substr(a, b - a + 1);
}

// ⚠️ THE MAPPED-ADDRESS FOLD IS HERE AND NOWHERE ELSE, so every caller gets it. An IPv4
// client on a dual-stack listener is ::ffff:a.b.c.d — the same host as a.b.c.d, and an
// operator writing 10.0.0.0/8 means both. ::ffff:0:0/96 is the mapped range; anything in
// it becomes its four trailing bytes as IPv4.
Addr parse_addr(const std::string& in) {
    Addr a;
    const std::string s = trim(in);
    if (s.empty()) return a;

    // A bracketed literal, as a URL or a Host header carries it.
    const std::string t = (s.size() > 2 && s.front() == '[' && s.back() == ']')
                              ? s.substr(1, s.size() - 2) : s;

    if (t.find(':') == std::string::npos) {
        if (inet_pton(AF_INET, t.c_str(), a.b.data()) != 1) return a;
        a.ok = true; a.bits = 32;
        return a;
    }
    std::array<unsigned char, 16> v6{};
    if (inet_pton(AF_INET6, t.c_str(), v6.data()) != 1) return a;

    static const unsigned char kMappedPrefix[12] =
        {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff};
    if (std::memcmp(v6.data(), kMappedPrefix, sizeof kMappedPrefix) == 0) {
        a.ok = true; a.bits = 32;
        std::memcpy(a.b.data(), v6.data() + 12, 4);
        return a;
    }
    a.ok = true; a.bits = 128; a.b = v6;
    return a;
}

// The first `prefix` bits of two equal-width addresses.
bool same_prefix(const Addr& x, const Addr& y, int prefix) {
    const int whole = prefix / 8;
    const int rest  = prefix % 8;
    if (whole && std::memcmp(x.b.data(), y.b.data(), static_cast<size_t>(whole)) != 0)
        return false;
    if (rest == 0) return true;
    // ⚠️ THE PARTIAL BYTE IS NOT OPTIONAL. Dropping it turns /12 into /8, which quietly
    // widens every prefix an operator writes to the byte boundary below it — a trusted
    // range sixteen times larger than the one they asked for.
    const unsigned char mask = static_cast<unsigned char>(0xFF << (8 - rest));
    return (x.b[static_cast<size_t>(whole)] & mask) == (y.b[static_cast<size_t>(whole)] & mask);
}

}  // namespace

bool ip_in_cidr(const std::string& ip, const std::string& cidr) {
    const std::string c = trim(cidr);
    if (c.empty()) return false;

    std::string net = c;
    int prefix = -1;
    if (const auto slash = c.find('/'); slash != std::string::npos) {
        net = c.substr(0, slash);
        const std::string p = trim(c.substr(slash + 1));
        if (p.empty() || p.find_first_not_of("0123456789") != std::string::npos) return false;
        try { prefix = std::stoi(p); } catch (...) { return false; }
    }

    const Addr n = parse_addr(net);
    const Addr a = parse_addr(ip);
    if (!n.ok || !a.ok) return false;
    // A bare address is that one host.
    if (prefix < 0) prefix = n.bits;
    if (prefix > n.bits) return false;
    // ⚠️ A PREFIX IS MEANINGLESS ACROSS FAMILIES. 10.0.0.0/8 does not contain an IPv6
    // client and 2001:db8::/32 does not contain an IPv4 one — and after the mapped fold
    // above, a genuine IPv4 client is width 32 on both sides, so this does not reject the
    // dual-stack case it would be easy to mistake it for.
    if (n.bits != a.bits) return false;
    return same_prefix(n, a, prefix);
}

bool is_trusted_proxy(const std::vector<std::string>& trusted, const std::string& peer) {
    return std::any_of(trusted.begin(), trusted.end(),
                       [&peer](const std::string& c) { return ip_in_cidr(peer, c); });
}

std::string real_client_ip(const std::vector<std::string>& trusted,
                           const std::string& peer,
                           const std::string& xff) {
    // Nothing configured: the socket address, exactly as before. This is the default and
    // the only safe one — see the header.
    if (trusted.empty()) return peer;

    const auto is_trusted = [&trusted](const std::string& ip) {
        return is_trusted_proxy(trusted, ip);
    };

    // ⚠️ THE PEER ITSELF MUST BE A TRUSTED PROXY BEFORE THE HEADER MEANS ANYTHING. A direct
    // client that sets X-Forwarded-For is just a client telling us a story about itself.
    if (!is_trusted(peer)) return peer;
    if (xff.empty()) return peer;

    std::vector<std::string> hops;
    for (size_t i = 0, j; i <= xff.size(); i = j + 1) {
        j = xff.find(',', i);
        if (j == std::string::npos) j = xff.size();
        if (const std::string h = trim(xff.substr(i, j - i)); !h.empty()) hops.push_back(h);
    }
    if (hops.empty()) return peer;

    // Right to left, past our own proxies, to the first address none of them is.
    for (auto it = hops.rbegin(); it != hops.rend(); ++it) {
        if (!is_trusted(*it)) {
            // Only an address we can parse. An entry like "unknown" or an obfuscated
            // identifier is a legal X-Forwarded-For value and is not an address; recording
            // it would put a non-address into the audit log's actor_ip.
            return parse_addr(*it).ok ? *it : peer;
        }
    }
    // ⚠️ EVERY HOP IS TRUSTED, WHICH MEANS THE CLIENT IS INSIDE THE TRUSTED RANGE. That is
    // an operator who wrote one internal prefix instead of listing each proxy, which is a
    // normal thing to do. The leftmost entry is still what the outermost proxy saw, so it is
    // the client, and it is the answer.
    //
    // Returning the peer here instead — the obvious "we ran out of untrusted hops" reading,
    // and what this did first — records the PROXY, which is the entire defect this function
    // exists to remove. Measured with nginx in front of the console and TRUSTED_PROXIES set
    // to a prefix covering both it and the client: every request was attributed to nginx.
    return parse_addr(hops.front()).ok ? hops.front() : peer;
}

}  // namespace pki
