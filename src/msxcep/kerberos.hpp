// SPNEGO/GSSAPI acceptor for MS-WSTEP Kerberos authentication.
//
// Verifies an HTTP `Authorization: Negotiate <token>` ticket against a service
// keytab and returns the authenticated client principal. Compiled into
// fastpki-ms unconditionally, but the GSSAPI implementation is only built when
// -DFASTPKI_WITH_KERBEROS=ON (which links libgssapi_krb5). When the support is
// not built, available() is false and accept_spnego() returns an error so the
// caller falls back to password auth.
#pragma once
#include <string>
#include <vector>
#include <utility>

namespace pki::krb {

struct AcceptResult {
    bool        ok = false;
    std::string principal;   // authenticated client, e.g. "user@REALM" or "HOST$@REALM"
    std::string error;       // human-readable reason when !ok
};

// True if this binary was built with Kerberos/GSSAPI support.
bool available();

// Accept a SPNEGO security context from a single decoded Negotiate token.
//   token  : raw (already base64-decoded) SPNEGO/GSS token bytes
//   keytab : path to the service keytab (exported via KRB5_KTNAME)
//   spn    : expected service principal name (informational; the acceptor uses
//            the keytab's default credential)
// Returns ok=true + the client principal on a completed Kerberos exchange.
AcceptResult accept_spnego(const std::string& token,
                           const std::string& keytab);

// Render a krb5.conf for `realm` with `kdcs` (comma-separated hosts) and point the krb5
// library at it by exporting KRB5_CONFIG. Returns the path written, or "" when there is
// nothing to write (no realm) or the write failed.
//
// ⚠️ THIS EXISTS BECAUSE WINDOWS DOES NOT USE krb5.conf. A domain-joined client learns its
// KDCs from the domain; our acceptor is a Linux process holding a keytab and no such
// membership, so without this MIT krb5 falls back to `_kerberos._tcp.REALM` SRV lookups
// against whatever resolver the container happens to have — which on a lab node is not the
// AD DNS, and the failure is a timeout rather than a message naming the cause.
// Several realms in one file. A deployment with two AD domains has two keytabs and two
// realms, and krb5 reads them all from one [realms] section -- so the acceptor needs one
// file listing every configured domain, not one file per domain that overwrite each other.
// The FIRST entry supplies default_realm. Returns the path written, or "" if nothing
// usable was produced (a realm with no KDC is refused, as it always was).
std::string write_krb5_conf(const std::vector<std::pair<std::string, std::string>>& realms,
                            const std::string& path);

std::string write_krb5_conf(const std::string& realm,
                            const std::string& kdcs,
                            const std::string& path);

} // namespace pki::krb
