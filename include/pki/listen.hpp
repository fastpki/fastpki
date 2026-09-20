#pragma once
// One place where every FastPKI listener decides which address family it serves.
//
// ⚠️ THE WILDCARD IS `::`, NOT `0.0.0.0`, AND THE DIFFERENCE IS NOT COSMETIC. A socket
// bound to 0.0.0.0 accepts IPv4 and NOTHING ELSE, so a node on an IPv6 network starts
// every service, logs "listening", reports itself healthy — and answers no client at all.
// The failure appears at the far end as a connection timeout against a server that looks
// perfectly well, which is the most expensive shape a misconfiguration can take.
//
// `::` is strictly more capable on any host with IPv6 enabled: cpp-httplib leaves
// CPPHTTPLIB_IPV6_V6ONLY false, so the socket is DUAL-STACK and an IPv4 client arrives as
// an IPv4-mapped address. That is why this is a changed default rather than a new option —
// there is no deployment that wanted the narrower one.
//
// ⚠️ AND A HOST WITH IPv6 TURNED OFF MUST NOT CRASH-LOOP. `ipv6.disable=1` on the kernel
// command line makes bind(::) fail outright, and a service that merely died there would be
// a working deployment broken by an upgrade, with nothing in the log naming the cause. The
// wildcard therefore falls back to 0.0.0.0 and SAYS SO. An address the operator asked for
// explicitly is never second-guessed: if `WEB_BIND=2001:db8::1` cannot be bound, that is a
// real error and gets reported as one.
#include <string>

#include "pki/log.hpp"

namespace pki {

inline bool is_wildcard_bind(const std::string& addr) {
    return addr == "::" || addr == "[::]";
}

// Binds `srv` to addr:port, falling back to the IPv4 wildcard when the IPv6 wildcard is
// unavailable. Returns false if nothing could be bound; `bound_addr` receives whatever was.
// Templated on the server so this header does not include third_party/httplib.h, which the
// image build refetches from upstream and which must stay unpatched.
template <class Server>
bool bind_listener(Server& srv, const std::string& addr, int port, std::string& bound_addr) {
    bound_addr = addr;
    if (srv.bind_to_port(addr, port)) return true;
    if (!is_wildcard_bind(addr)) return false;
    if (!srv.bind_to_port("0.0.0.0", port)) return false;
    bound_addr = "0.0.0.0";
    // err, not info: a node serving half the internet it was asked to serve has to be
    // visible at the log level a production deployment actually runs at.
    log::err("cannot bind the IPv6 wildcard [::]:" + std::to_string(port) +
              " — this host has no usable IPv6 stack (ipv6.disable=1, or a container "
              "without IPv6). Serving IPv4 only, on 0.0.0.0:" + std::to_string(port) +
              ". IPv6 clients cannot reach this service.");
    return true;
}

}  // namespace pki
