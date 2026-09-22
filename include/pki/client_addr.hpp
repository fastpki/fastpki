#pragma once
// include/pki/client_addr.hpp — who the client really is, when a proxy is in front.
//
// ── WHY THIS EXISTS ───────────────────────────────────────────────────────────────────
//
// Every listener records the address it sees on the socket. Behind a reverse proxy or a
// load balancer — which is the shape docs/high-availability.md documents for an HA pair —
// that address is the PROXY's, identically for every client. Two things then break, and
// both of them matter for a certificate authority:
//
//   * The audit log cannot say who did anything. Every issuance, revocation and
//     configuration change is stamped with one address.
//   * The login throttle stops being per-client. src/lib/login_throttle.cpp backs off per
//     account AND per address; with one address for everybody, one person's mistyped
//     password delays everyone else.
//
// ⚠️ AN UNTRUSTED X-Forwarded-For IS ATTACKER-CONTROLLED, so trust is explicit and there is
// no default. A client that can set its own header could otherwise forge the audit trail
// and side-step the throttle by inventing a new address per attempt — strictly worse than
// recording the proxy's address honestly. So with TRUSTED_PROXIES unset, the header is
// ignored everywhere and the socket address is used, exactly as before.
//
// ── WHAT THIS IS NOT FOR ──────────────────────────────────────────────────────────────
//
// Not for authorization. Nothing decides what a caller may do from the value this returns:
// it feeds the audit log and the throttle. A forged address that slipped past the trust
// check would cost attribution, not access.
#include <string>
#include <vector>

namespace pki {

// True when `ip` falls inside `cidr`. `cidr` is "address/prefix", or a bare address, which
// means a single host (/32 or /128). A malformed cidr never matches.
//
// ⚠️ IPv4-MAPPED IPv6 IS NORMALISED FIRST, AND THAT IS THE WHOLE TRAP. Every listener binds
// the IPv6 wildcard with V6ONLY off (include/pki/listen.hpp), so an IPv4 client arrives as
// ::ffff:10.0.0.1 rather than 10.0.0.1. Compared literally, an operator's 10.0.0.0/8 entry
// would never match anything and the setting would look configured while doing nothing —
// the worst kind of security control, the sort that reports success. Both sides are mapped
// down to IPv4 before the families are compared.
bool ip_in_cidr(const std::string& ip, const std::string& cidr);

// The client's own address.
//
//   trusted  the configured proxy addresses/prefixes (TRUSTED_PROXIES). Empty disables
//            the whole mechanism and `peer` is returned unchanged.
//   peer     the address on the socket.
//   xff      the X-Forwarded-For header value, or empty if there is none.
//
// ⚠️ THE HEADER IS READ FROM RIGHT TO LEFT, NOT LEFT TO RIGHT. Each proxy APPENDS the
// address it saw, so the rightmost entries are the ones nearest this server and the only
// ones written by something we trust. A client can put anything it likes at the front of
// the list before the first proxy ever sees it, so taking the leftmost entry — the obvious
// reading, and a common mistake — takes the value the attacker chose. Walking from the
// right and stopping at the first entry that is NOT itself a trusted proxy yields the
// address the outermost trusted hop actually observed.
std::string real_client_ip(const std::vector<std::string>& trusted,
                           const std::string& peer,
                           const std::string& xff);

// True when `peer` is one of the configured proxies, so a header it set may be believed.
// Empty `trusted` is false for everything — there is no default trust.
//
// This exists for the OTHER proxy-set header: X-Forwarded-Proto, which ACME and MS-XCEP use
// to build the URLs they advertise back to a client. Those services fall back to "https"
// when it is absent, so gating it means an untrusted caller can no longer talk the server
// into advertising http:// to itself. BASE_URL remains the supported answer for a
// deployment that terminates TLS at a proxy, and it is checked first in both services.
bool is_trusted_proxy(const std::vector<std::string>& trusted, const std::string& peer);

}  // namespace pki
