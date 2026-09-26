// LDAP authenticator — compiled only when FASTPKI_WITH_LDAP is set (see
// CMakeLists). Mirrors the auth() flow of the PHP helper_functions.php: try
// each configured directory URI in turn, and for each, attempt to bind as the
// user under each configured base DN until one succeeds.

#include "pki/auth.hpp"
#include "pki/config.hpp"
#include "pki/log.hpp"

#define LDAP_DEPRECATED 0
#include <ldap.h>

#include <sys/time.h>   // struct timeval — pulled in transitively by glibc but
                        // NOT by musl/Alpine, where <ldap.h> omits it.
#include <algorithm>
#include <string>
#include <vector>

namespace pki {

namespace {

// Attempt a simple bind of `bind_dn` / `password` against one server URI.
bool try_bind(const LdapProvider& p, const std::string& uri,
              const std::string& bind_dn, const std::string& password) {
    LDAP* ld = nullptr;
    if (ldap_initialize(&ld, uri.c_str()) != LDAP_SUCCESS || !ld) {
        log::err("ldap_initialize failed for " + uri);
        return false;
    }

    int version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    // Same reasoning as connect_and_bind_service() below: never chase a referral, because
    // libldap chases anonymously and would both fail against AD and, with a rebind proc,
    // send the credential somewhere the operator did not name.
    ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

    struct timeval tv{p.network_timeout_sec, 0};
    ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);

    if (!p.ca_cert_file.empty()) {
        ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTFILE, p.ca_cert_file.c_str());
        int demand = LDAP_OPT_X_TLS_DEMAND;
        ldap_set_option(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &demand);
        // ⚠️ AND REBUILD THE TLS CONTEXT, OR THE TWO OPTIONS ABOVE DO NOTHING.
        // OpenLDAP applies per-handle TLS settings when it BUILDS the context; a handle
        // from ldap_initialize() already carries the process default, so setting the CA
        // file on it and connecting uses the DEFAULT trust store and ignores what was just
        // set. LDAP_OPT_X_TLS_NEWCTX with 0 forces a fresh context from the current
        // options, and must come last.
        //
        // Without it, ldaps:// against a private CA can never verify: the handshake fails
        // and libldap reports `Can't contact LDAP server`, which the console then renders
        // as "could not bind ... this directory has no search account" — naming a bind DN
        // that is present and correct. Measured against a Windows DC whose LDAPS
        // certificate FastPKI had issued: `ldapwhoami` with LDAPTLS_CACERT succeeded
        // (the env var seeds the default context BEFORE any handle exists) while this code
        // failed on the same anchor, which is exactly the comparison that misleads.
        int newctx = 0;
        ldap_set_option(ld, LDAP_OPT_X_TLS_NEWCTX, &newctx);
    }

    berval cred{};
    cred.bv_val = const_cast<char*>(password.c_str());
    cred.bv_len = password.size();

    int rc = ldap_sasl_bind_s(ld, bind_dn.c_str(), LDAP_SASL_SIMPLE, &cred,
                              nullptr, nullptr, nullptr);
    ldap_unbind_ext_s(ld, nullptr, nullptr);

    if (rc == LDAP_SUCCESS) return true;
    log::info("ldap bind failed (" + bind_dn + " @ " + uri + "): " +
              std::string(ldap_err2string(rc)));
    return false;
}

// RFC 4515 §3 filter escaping. `username` reaches the search filter below from a login
// form, so without this a username of `*)(objectClass=*` rewrites the filter and selects
// entries the caller never named. Escaping five characters is the whole defence.
std::string filter_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        switch (c) {
            case '*':  out += "\\2a"; break;
            case '(':  out += "\\28"; break;
            case ')':  out += "\\29"; break;
            case '\\': out += "\\5c"; break;
            case '\0': out += "\\00"; break;
            default:   out += static_cast<char>(c);
        }
    }
    return out;
}

// Open `uri` and bind as the service account (p.bind_dn) or anonymously — the
// same connection setup ldap_list_groups() does, factored out so the group lookup for
// ONE user cannot drift from the group listing the console imports from.
LDAP* connect_and_bind_service(const LdapProvider& p, const std::string& uri, const char* who) {
    LDAP* ld = nullptr;
    if (ldap_initialize(&ld, uri.c_str()) != LDAP_SUCCESS || !ld) {
        log::err(std::string(who) + ": ldap_initialize failed for " + uri);
        return nullptr;
    }
    int version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    // ⚠️ DO NOT CHASE REFERRALS. libldap chases them by DEFAULT, and it chases them
    // ANONYMOUSLY unless the caller installs a rebind procedure — which we do not, and
    // should not, because it would mean handing the bind password to whatever host a
    // referral names.
    //
    // Active Directory returns referrals for the subordinate naming contexts as soon as a
    // subtree search starts at a domain root, which is the base DN every AD deployment
    // naturally configures. The anonymous chase is then refused and libldap reports the
    // whole search as `Operations error` — an error that names neither referrals nor
    // credentials. Measured against Windows Server 2022: base `DC=fastpki,DC=lab` failed
    // exactly so, while `CN=Users,DC=fastpki,DC=lab` (which generates no referral)
    // succeeded with the same bind, so it read as a base-DN or permissions problem.
    //
    // `ldapsearch` does not reproduce it: it installs a rebind proc that re-authenticates
    // with the same credentials, so hand-testing the exact DN and password from a shell
    // succeeds and confirms the wrong theory.
    //
    // Off is also the correct behaviour independent of the bug: searches are scoped to the
    // base DNs an operator configured, and silently following a referral into another
    // domain would search somewhere nobody named.
    ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    struct timeval tv{p.network_timeout_sec, 0};
    ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);
    if (!p.ca_cert_file.empty()) {
        ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTFILE, p.ca_cert_file.c_str());
        int demand = LDAP_OPT_X_TLS_DEMAND;
        ldap_set_option(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &demand);
        // ⚠️ AND REBUILD THE TLS CONTEXT, OR THE TWO OPTIONS ABOVE DO NOTHING.
        // OpenLDAP applies per-handle TLS settings when it BUILDS the context; a handle
        // from ldap_initialize() already carries the process default, so setting the CA
        // file on it and connecting uses the DEFAULT trust store and ignores what was just
        // set. LDAP_OPT_X_TLS_NEWCTX with 0 forces a fresh context from the current
        // options, and must come last.
        //
        // Without it, ldaps:// against a private CA can never verify: the handshake fails
        // and libldap reports `Can't contact LDAP server`, which the console then renders
        // as "could not bind ... this directory has no search account" — naming a bind DN
        // that is present and correct. Measured against a Windows DC whose LDAPS
        // certificate FastPKI had issued: `ldapwhoami` with LDAPTLS_CACERT succeeded
        // (the env var seeds the default context BEFORE any handle exists) while this code
        // failed on the same anchor, which is exactly the comparison that misleads.
        int newctx = 0;
        ldap_set_option(ld, LDAP_OPT_X_TLS_NEWCTX, &newctx);
    }
    berval cred{};
    const char* bind_dn = nullptr;
    if (!p.bind_dn.empty()) {
        bind_dn = p.bind_dn.c_str();
        cred.bv_val = const_cast<char*>(p.bind_pw.c_str());
        cred.bv_len = p.bind_pw.size();
    }
    int rc = ldap_sasl_bind_s(ld, bind_dn, LDAP_SASL_SIMPLE, &cred, nullptr, nullptr, nullptr);
    if (rc != LDAP_SUCCESS) {
        log::info(std::string(who) + ": bind failed @ " + uri + ": " + ldap_err2string(rc));
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return nullptr;
    }
    return ld;
}

// RFC 4514 §2.4: escape the characters that are special in a DN attribute VALUE. Without
// this the username is spliced straight into `CN=<user>,<base>`, so a name containing a
// comma or a plus redraws the DN — `alice,OU=Admins` binds somewhere the caller did not
// name, and a leading `#` makes the parser read the value as hex-encoded BER instead.
//
// The practical reach here is limited (an attacker still needs the target's password for
// the bind to succeed) which is why this is a hardening item rather than a bypass. It is
// still wrong to build a structured identifier out of unescaped user input, and a bind DN
// that does not mean what it says is a bad thing to leave in an authentication path.
//
// ⚠️ POSITION MATTERS for three of these. A leading space, a leading '#' and a trailing
// space are special only where they are, so escaping them everywhere would corrupt an
// ordinary name that merely contains a space.
std::string escape_dn_value(const std::string& v) {
    std::string out;
    out.reserve(v.size() + 8);
    for (size_t i = 0; i < v.size(); ++i) {
        const char c = v[i];
        switch (c) {
            case '"': case '+': case ',': case ';': case '<': case '>': case '\\':
                out += '\\'; out += c; break;
            case '#':
                if (i == 0) out += '\\';
                out += c; break;
            case ' ':
                if (i == 0 || i + 1 == v.size()) out += '\\';
                out += c; break;
            default:
                // A NUL cannot appear in a DN at all; encode it rather than truncating the
                // string at it, which is how a filter check gets walked past.
                if (c == '\0') out += "\\00"; else out += c;
                break;
        }
    }
    return out;
}

} // namespace

bool ldap_bind_check(const LdapProvider& p, const std::string& username,
                     const std::string& password) {
    if (username.empty() || password.empty()) return false;
    if (p.uris.empty() || p.base_dns.empty()) {
        log::err("ldap_bind_check: no LDAP URIs/base DNs configured");
        return false;
    }
    for (const auto& uri : p.uris) {
        for (const auto& base : p.base_dns) {
            // AD accepts userPrincipalName / sAMAccountName binds, but the
            // portable form is a DN: CN=<user>,<base>. If your directory keys
            // users by a different attribute, adjust here.
            std::string bind_dn = "CN=" + escape_dn_value(username) + "," + base;
            if (try_bind(p, uri, bind_dn, password)) return true;
        }
    }
    return false;
}

// Search each directory for group entries and return their display names. Used by
// the console's "Import from LDAP" picker. Best-effort: the first server
// that answers wins; failures are logged and skipped.
std::vector<std::string> ldap_list_groups(const LdapProvider& p, std::string* error) {
    std::vector<std::string> out;
    std::string last_err;
    if (p.uris.empty() || p.base_dns.empty()) return out;
    const std::string filter = p.group_filter.empty()
        ? "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=group)(objectClass=posixGroup))"
        : p.group_filter;
    const std::string attr = p.group_attr.empty() ? "cn" : p.group_attr;

    for (const auto& uri : p.uris) {
        // Bind: service account if configured, else anonymous simple bind. Shared with
        // ldap_groups_for_user() so the console's picker and the per-user membership
        // lookup cannot end up reading the directory two different ways.
        LDAP* ld = connect_and_bind_service(p, uri, "ldap_list_groups");
        if (!ld) { last_err = "could not bind to " + uri +
                              " (this directory has no search account: set its bind DN "
                              "and password on the Directories page, or with "
                              "`fastpki-config auth-providers-add " + p.id +
                              " --bind-dn <dn> --bind-pw-file <file>`)"; continue; }
        struct timeval tv{p.network_timeout_sec, 0};

        char* attrs[] = { const_cast<char*>(attr.c_str()), nullptr };
        for (const auto& base : p.base_dns) {
            LDAPMessage* result = nullptr;
            int rc = ldap_search_ext_s(ld, base.c_str(), LDAP_SCOPE_SUBTREE, filter.c_str(),
                                   attrs, 0, nullptr, nullptr, &tv, 1000, &result);
            if (rc == LDAP_SUCCESS && result) {
                for (LDAPMessage* e = ldap_first_entry(ld, result); e; e = ldap_next_entry(ld, e)) {
                    berval** vals = ldap_get_values_len(ld, e, attr.c_str());
                    if (vals && vals[0]) {
                        out.emplace_back(vals[0]->bv_val, vals[0]->bv_len);
                    } else {                          // no display attr → fall back to the DN
                        char* dn = ldap_get_dn(ld, e);
                        if (dn) { out.emplace_back(dn); ldap_memfree(dn); }
                    }
                    if (vals) ldap_value_free_len(vals);
                }
            } else if (rc != LDAP_SUCCESS) {
                const std::string why = ldap_err2string(rc);
                log::info(std::string("ldap_list_groups: search under ") + base + " failed: " + why);
                last_err = "search under " + base + " failed: " + why;
                // AD's reply to an anonymous search. Naming the key turns an opaque
                // two-word LDAP error into something an operator can act on.
                if (why == "Operations error" && p.bind_dn.empty())
                    last_err += " — this directory does not allow anonymous searches. "
                                "Give it a read-only search account: Directories -> edit '" +
                                p.id + "' -> bind DN and password, or `fastpki-config "
                                "auth-providers-add " + p.id + " --bind-dn <dn> "
                                "--bind-pw-file <file>`";
            }
            if (result) ldap_msgfree(result);
        }
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        if (!out.empty()) break;                      // first directory that answers wins
    }

    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    // Only report a failure when it left us with nothing: a directory that answered from
    // one URI and refused from another did give us its groups, and surfacing an error
    // beside a populated list would be its own kind of lie.
    if (error && out.empty() && !last_err.empty()) *error = last_err;
    return out;
}

// ── MS certificate templates, read from the directory instead of a CSV ─────────────────
namespace {

// AD stores pKIExpirationPeriod / pKIOverlapPeriod as an 8-byte LITTLE-ENDIAN signed
// FILETIME interval in 100-nanosecond units, and NEGATIVE — it is a duration measured
// backwards from an expiry, not a point in time. Reading it as a positive big-endian
// integer (the obvious mistake) turns "one year" into a number in the billions.
// Returns the span in SECONDS, or -1 when the attribute is absent or malformed — which is
// not the same as 0. A directory may legitimately configure a zero overlap ("renew at
// expiry"), and folding that into the same answer as "not set" would silently replace an
// operator's decision with our derived default.
long long filetime_interval_seconds(const berval* v) {
    if (!v || v->bv_len != 8) return -1;
    const unsigned char* b = reinterpret_cast<const unsigned char*>(v->bv_val);
    unsigned long long raw = 0;
    for (int i = 7; i >= 0; --i) raw = (raw << 8) | b[i];
    if (raw == 0) return 0;                     // a real zero span, not an absent attribute
    if (!(raw >> 63)) return -1;                // stored positive: not a backwards duration
    // The span is the two's-complement negation, taken in UNSIGNED arithmetic on purpose:
    // negating the signed form is undefined for the one value that has no positive
    // counterpart, and a directory is under no obligation to hold a sane number.
    const unsigned long long span = ~raw + 1ull;
    if (span > 9223372036854775807ull) return -1;
    return static_cast<long long>(span / 10000000ull);
}

long long filetime_interval_days(const berval* v) {
    const long long sec = filetime_interval_seconds(v);
    return sec <= 0 ? 0 : sec / 86400LL;
}

// pKIKeyUsage is the CONTENTS of the KeyUsage BIT STRING — the raw bytes, most significant
// bit first, one or two of them — not a DER-wrapped value and not a number. MsTemplate
// carries the same 16-bit bitmap (0xA000 = digitalSignature|keyEncipherment), so a
// one-byte value has to be shifted into the high half rather than used as-is.
unsigned key_usage_bits(const berval* v) {
    if (!v || v->bv_len == 0) return 0;
    const unsigned char* b = reinterpret_cast<const unsigned char*>(v->bv_val);
    if (v->bv_len == 1) return static_cast<unsigned>(b[0]) << 8;
    return (static_cast<unsigned>(b[0]) << 8) | b[1];
}

// pKIDefaultCSPs values are ORDER-PREFIXED: "1,Microsoft RSA SChannel Cryptographic
// Provider". The number is the display order in the Windows UI and is not part of the
// provider name; leaving it in produces a template whose CSP nothing matches.
std::string strip_csp_order(const std::string& v) {
    const size_t comma = v.find(',');
    if (comma == std::string::npos) return v;
    for (size_t i = 0; i < comma; ++i)
        if (!std::isdigit(static_cast<unsigned char>(v[i]))) return v;   // no order prefix
    return v.substr(comma + 1);
}

std::string first_value(LDAP* ld, LDAPMessage* e, const char* attr) {
    berval** vals = ldap_get_values_len(ld, e, attr);
    std::string out;
    if (vals && vals[0]) out.assign(vals[0]->bv_val, vals[0]->bv_len);
    if (vals) ldap_value_free_len(vals);
    return out;
}

int first_int(LDAP* ld, LDAPMessage* e, const char* attr, int dflt) {
    const std::string v = first_value(ld, e, attr);
    if (v.empty()) return dflt;
    try { return std::stoi(v); } catch (...) { return dflt; }
}

std::vector<std::string> all_values(LDAP* ld, LDAPMessage* e, const char* attr) {
    std::vector<std::string> out;
    berval** vals = ldap_get_values_len(ld, e, attr);
    if (vals) for (int i = 0; vals[i]; ++i) out.emplace_back(vals[i]->bv_val, vals[i]->bv_len);
    if (vals) ldap_value_free_len(vals);
    return out;
}

// The configuration naming context, asked of the server. NOT derived from a base DN: in a
// forest the configuration NC is not a suffix of the domain NC, and a deployment whose
// LDAP_BASE_DNS point at an OU rather than the domain root would produce a DN that does
// not exist. The RootDSE is readable on an anonymous or service bind either way.
std::string root_dse_value(LDAP* ld, const char* attr) {
    struct timeval tv{10, 0};
    char* attrs[] = { const_cast<char*>(attr), nullptr };
    LDAPMessage* r = nullptr;
    const int rc = ldap_search_ext_s(ld, "", LDAP_SCOPE_BASE, "(objectClass=*)",
                                     attrs, 0, nullptr, nullptr, &tv, 1, &r);
    std::string out;
    if (rc == LDAP_SUCCESS && r) {
        if (LDAPMessage* e = ldap_first_entry(ld, r)) out = first_value(ld, e, attr);
    }
    if (r) ldap_msgfree(r);
    return out;
}

std::string config_naming_context(LDAP* ld) {
    return root_dse_value(ld, "configurationNamingContext");
}

}  // namespace

// The domain's OTHER TWO NAMES, asked of the domain itself.
//
// A login may name a directory by its id, its NetBIOS short name, its DNS root or its
// Kerberos realm, and the last three are facts AD already knows -- so making an operator
// type them is asking them to copy something the directory can be asked for, and to get it
// right. Windows does exactly this lookup: the crossRef object for a domain carries
// `nETBIOSName` and `dnsRoot`, and it is how the LSA turns `CORP\alice` into a realm.
//
// ⚠️ THE DOMAIN IS THE ROOT DSE'S defaultNamingContext, NOT the configured base DN. A
// deployment whose base DN points at an OU (`OU=People,DC=corp,DC=example`) has a base DN
// that is not the domain, and matching a crossRef on it finds nothing. Both naming contexts
// come from the RootDSE for the same reason config_naming_context() does: in a forest the
// configuration NC is not a suffix of the domain NC, so neither can be derived from the
// other.
//
// Returns false and leaves the outputs untouched when the directory cannot be asked. That is
// not an error worth failing a save over -- the operator can always type the two names -- so
// every caller treats it as advisory.
bool ldap_discover_domain_names(const LdapProvider& p, std::string& netbios,
                                std::string& dns_root, std::string* error) {
    if (p.uris.empty()) {
        if (error) *error = "this directory has no URIs to ask";
        return false;
    }
    std::string last_err;
    for (const auto& uri : p.uris) {
        LDAP* ld = connect_and_bind_service(p, uri, "ldap_discover_domain_names");
        if (!ld) { last_err = "could not bind to " + uri; continue; }
        const std::string cnc    = config_naming_context(ld);
        const std::string domain = root_dse_value(ld, "defaultNamingContext");
        if (cnc.empty() || domain.empty()) {
            last_err = uri + " did not answer for its naming contexts (not an AD server?)";
            ldap_unbind_ext_s(ld, nullptr, nullptr);
            continue;
        }
        const std::string base   = "CN=Partitions," + cnc;
        const std::string filter = "(&(objectCategory=crossRef)(nCName=" +
                                   filter_escape(domain) + "))";
        char* attrs[] = { const_cast<char*>("nETBIOSName"),
                          const_cast<char*>("dnsRoot"), nullptr };
        struct timeval tv{10, 0};
        LDAPMessage* r = nullptr;
        const int rc = ldap_search_ext_s(ld, base.c_str(), LDAP_SCOPE_ONELEVEL, filter.c_str(),
                                         attrs, 0, nullptr, nullptr, &tv, 1, &r);
        bool got = false;
        if (rc == LDAP_SUCCESS && r) {
            if (LDAPMessage* e = ldap_first_entry(ld, r)) {
                const std::string nb = first_value(ld, e, "nETBIOSName");
                const std::string dr = first_value(ld, e, "dnsRoot");
                // Each is filled only if it was blank: an operator's explicit value is a
                // decision and outranks anything discovered.
                if (!nb.empty() && netbios.empty())  { netbios  = nb; got = true; }
                if (!dr.empty() && dns_root.empty()) { dns_root = dr; got = true; }
                if (!nb.empty() || !dr.empty()) got = true;
            } else {
                last_err = "no crossRef for " + domain + " under " + base;
            }
        } else if (rc != LDAP_SUCCESS) {
            last_err = std::string("crossRef search failed: ") + ldap_err2string(rc);
        }
        if (r) ldap_msgfree(r);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        if (got) return true;
    }
    if (error) *error = last_err.empty() ? "the directory did not answer" : last_err;
    return false;
}

std::vector<MsTemplate> ldap_fetch_ms_templates(const LdapProvider& p, std::string* error) {
    std::vector<MsTemplate> out;
    std::string last_err;
    if (p.uris.empty()) {
        if (error) *error = "this directory has no URIs — set them on its row "
                            "(Directories page, or `fastpki-config auth-providers-add --uris`)";
        return out;
    }
    for (const auto& uri : p.uris) {
        LDAP* ld = connect_and_bind_service(p, uri, "ldap_fetch_ms_templates");
        if (!ld) {
            last_err = "could not bind to " + uri +
                       " (this directory has no search account: set its bind DN and password "
                       "on the Directories page, or with `fastpki-config auth-providers-add " +
                       p.id + " --bind-dn <dn> --bind-pw-file <file>`)";
            continue;
        }
        // An explicit base wins and skips discovery entirely. Discovery is the better
        // default — it is what makes this work on a forest whose configuration NC is not a
        // suffix of the domain NC — but it depends on the server advertising
        // configurationNamingContext, and not every directory does.
        std::string base = p.template_base;
        if (base.empty()) {
            const std::string conf_nc = config_naming_context(ld);
            if (conf_nc.empty()) {
                last_err = uri + " did not report a configurationNamingContext, so the "
                                 "templates container could not be located — set this "
                                 "directory's template base to name it directly "
                                 "(Directories -> edit '" + p.id + "', or `fastpki-config "
                                 "auth-providers-add " + p.id + " --template-base <dn>`)";
                ldap_unbind_ext_s(ld, nullptr, nullptr);
                continue;
            }
            base = "CN=Certificate Templates,CN=Public Key Services,CN=Services," + conf_nc;
        }

        struct timeval tv{p.network_timeout_sec, 0};
        // Named explicitly rather than asking for everything: a template object carries a
        // security descriptor and other attributes this import has no business reading,
        // and a service account that can read the subtree should still be asked narrowly.
        const char* want[] = {
            "cn", "displayName", "msPKI-Cert-Template-OID", "msPKI-Template-Schema-Version",
            "revision", "msPKI-Template-Minor-Revision", "msPKI-Minimal-Key-Size",
            "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-Private-Key-Flag",
            "flags", "pKIExpirationPeriod", "pKIOverlapPeriod", "pKIKeyUsage",
            "pKIDefaultKeySpec", "pKIDefaultCSPs", "pKIExtendedKeyUsage", nullptr };
        std::vector<char*> attrs;
        for (const char** a = want; *a; ++a) attrs.push_back(const_cast<char*>(*a));
        attrs.push_back(nullptr);

        LDAPMessage* result = nullptr;
        // ONELEVEL: templates are direct children of that container. A subtree search would
        // also pick up whatever else somebody has parked underneath it.
        const int rc = ldap_search_ext_s(ld, base.c_str(), LDAP_SCOPE_ONELEVEL,
                                         "(objectClass=pKICertificateTemplate)",
                                         attrs.data(), 0, nullptr, nullptr, &tv, 500, &result);
        if (rc != LDAP_SUCCESS) {
            const std::string why = ldap_err2string(rc);
            last_err = "search under " + base + " failed: " + why;
            if (why == "Operations error" && p.bind_dn.empty())
                last_err += " — this directory does not allow anonymous searches. "
                            "Give it a read-only search account: Directories -> edit '" +
                            p.id + "' -> bind DN and password, or `fastpki-config "
                            "auth-providers-add " + p.id + " --bind-dn <dn> "
                            "--bind-pw-file <file>`";
            if (result) ldap_msgfree(result);
            ldap_unbind_ext_s(ld, nullptr, nullptr);
            continue;
        }
        for (LDAPMessage* e = ldap_first_entry(ld, result); e; e = ldap_next_entry(ld, e)) {
            MsTemplate t;
            t.name = first_value(ld, e, "cn");
            t.oid  = first_value(ld, e, "msPKI-Cert-Template-OID");
            // ⚠️ Both are REQUIRED by the same rule the CSV import applies. A template with
            // no OID cannot be offered over XCEP at all, and importing it would put a row in
            // the table that every enrolment path then skips — a silent half-import.
            if (t.name.empty() || t.oid.empty()) continue;

            t.schema            = first_int(ld, e, "msPKI-Template-Schema-Version", t.schema);
            t.major_rev         = first_int(ld, e, "revision", t.major_rev);
            t.minor_rev         = first_int(ld, e, "msPKI-Template-Minor-Revision", t.minor_rev);
            t.min_key_size      = first_int(ld, e, "msPKI-Minimal-Key-Size", t.min_key_size);
            t.subject_name_flags= first_int(ld, e, "msPKI-Certificate-Name-Flag", t.subject_name_flags);
            t.enrollment_flags  = first_int(ld, e, "msPKI-Enrollment-Flag", t.enrollment_flags);
            t.private_key_flags = first_int(ld, e, "msPKI-Private-Key-Flag", t.private_key_flags);
            t.general_flags     = first_int(ld, e, "flags", t.general_flags);
            t.key_spec          = first_int(ld, e, "pKIDefaultKeySpec", t.key_spec);

            if (berval** v = ldap_get_values_len(ld, e, "pKIExpirationPeriod")) {
                if (v[0]) { const long long d = filetime_interval_days(v[0]);
                            if (d > 0) t.validity_days = static_cast<int>(d); }
                ldap_value_free_len(v);
            }
            // The renewal overlap, kept in SECONDS. A directory routinely gives a
            // short-lived template an overlap measured in hours, and rounding that to whole
            // days would quietly turn it into "renew at expiry".
            if (berval** v = ldap_get_values_len(ld, e, "pKIOverlapPeriod")) {
                if (v[0]) { const long long s = filetime_interval_seconds(v[0]);
                            if (s >= 0) t.overlap_seconds = s; }
                ldap_value_free_len(v);
            }
            if (berval** v = ldap_get_values_len(ld, e, "pKIKeyUsage")) {
                if (v[0]) { const unsigned ku = key_usage_bits(v[0]);
                            if (ku) t.key_usage = ku; }
                ldap_value_free_len(v);
            }
            for (const auto& csp : all_values(ld, e, "pKIDefaultCSPs"))
                t.crypto_providers.push_back(strip_csp_order(csp));
            t.ekus = all_values(ld, e, "pKIExtendedKeyUsage");
            out.push_back(std::move(t));
        }
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        if (!out.empty()) break;                 // first directory that answers wins
    }
    // Same rule as the group listing: report a failure only when it left us with nothing.
    // An error printed beside a populated list is its own kind of lie.
    if (error && out.empty() && !last_err.empty()) *error = last_err;
    return out;
}

// The filter value for a user's PRIMARY group, built from the user's own objectSid
// and primaryGroupID.
//
// ⚠️ AD DOES NOT RECORD PRIMARY-GROUP MEMBERSHIP IN THE GROUP. `Domain Users` — the group
// an administrator reaches for first to give everyone a baseline role — carries no
// `member` entry for the accounts whose primary group it is. The relationship lives as
// `primaryGroupID` on the USER and is synthesised by the server from the RID. So the
// (member=<userDN>) search below can never match it: the grant is accepted, displayed
// beside grants that work, and silently applies to nobody. Measured against the lab
// domain, the same search FastPKI issues returned only `Remote Desktop Users`.
//
// A SID is revision(1) subAuthorityCount(1) identifierAuthority(6) subAuthority[n](4, LE).
// The user's SID is <domain SID>-<user RID> and the primary group's is
// <domain SID>-<primaryGroupID>, so this copies the SID and overwrites the LAST
// sub-authority. Returns "" for anything that is not a well-formed SID — every non-AD
// directory included, where the attribute simply is not there.
static std::string ad_primary_group_sid_filter(const berval* sid, unsigned long rid) {
    if (!sid || sid->bv_len < 8) return {};
    std::string raw(sid->bv_val, sid->bv_len);
    const size_t n = static_cast<unsigned char>(raw[1]);      // subAuthorityCount
    if (n == 0 || raw.size() != 8 + 4 * n) return {};
    const size_t off = 8 + 4 * (n - 1);
    raw[off + 0] = static_cast<char>( rid        & 0xffUL);
    raw[off + 1] = static_cast<char>((rid >>  8) & 0xffUL);
    raw[off + 2] = static_cast<char>((rid >> 16) & 0xffUL);
    raw[off + 3] = static_cast<char>((rid >> 24) & 0xffUL);
    // RFC 4515 3: a binary assertion value goes in a filter as \XX per byte. Escaping only
    // the special characters would corrupt any SID containing a 0x00 or a parenthesis.
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(raw.size() * 3);
    for (char ch : raw) {
        const unsigned char c = static_cast<unsigned char>(ch);
        out += '\\'; out += kHex[c >> 4]; out += kHex[c & 0x0f];
    }
    return out;
}

// The groups ONE user belongs to. See auth.hpp for why this searches by member
// rather than reading `memberOf`: the search returns the same LDAP_GROUP_ATTR value the
// console's picker imported into `subject_roles`, and a grant that does not match the
// name at login is a grant that does nothing.
std::vector<std::string> ldap_groups_for_user(const LdapProvider& p, const std::string& username) {
    std::vector<std::string> out;
    if (username.empty() || p.uris.empty() || p.base_dns.empty()) return out;

    const std::string group_filter = p.group_filter.empty()
        ? "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=group)(objectClass=posixGroup))"
        : p.group_filter;
    const std::string attr = p.group_attr.empty() ? "cn" : p.group_attr;
    const std::string esc  = filter_escape(username);

    for (const auto& uri : p.uris) {
        LDAP* ld = connect_and_bind_service(p, uri, "ldap_groups_for_user");
        if (!ld) continue;
        struct timeval tv{p.network_timeout_sec, 0};

        // 1. The user's DN. AD keys users by sAMAccountName, OpenLDAP usually by uid;
        //    `cn` catches the directories that key by display name. If the search finds
        //    nothing (a service account that may not read user entries, say), fall back
        //    to the CN=<user>,<base> form ldap_bind_check() binds with — that DN is known
        //    to exist, because the caller has just bound as it.
        std::string user_dn;
        std::string primary_sid_filter;      // "" unless this is AD
        const std::string user_filter =
            "(|(sAMAccountName=" + esc + ")(uid=" + esc + ")(cn=" + esc + "))";
        for (const auto& base : p.base_dns) {
            LDAPMessage* r = nullptr;
            // objectSid + primaryGroupID come back in the SAME lookup that finds the
            // DN. They are AD-only constructed/normal attributes; a directory that does not
            // have them returns the entry without them and everything below no-ops.
            char* want[] = { const_cast<char*>("objectSid"),
                             const_cast<char*>("primaryGroupID"), nullptr };
            int rc = ldap_search_ext_s(ld, base.c_str(), LDAP_SCOPE_SUBTREE, user_filter.c_str(),
                                       want, 0, nullptr, nullptr, &tv, 2, &r);
            if (rc == LDAP_SUCCESS && r) {
                if (LDAPMessage* e = ldap_first_entry(ld, r)) {
                    if (char* dn = ldap_get_dn(ld, e)) { user_dn = dn; ldap_memfree(dn); }
                    berval** sid = ldap_get_values_len(ld, e, "objectSid");
                    berval** pgid = ldap_get_values_len(ld, e, "primaryGroupID");
                    if (sid && sid[0] && pgid && pgid[0]) {
                        const std::string rid_s(pgid[0]->bv_val, pgid[0]->bv_len);
                        try {
                            primary_sid_filter =
                                ad_primary_group_sid_filter(sid[0], std::stoul(rid_s));
                        } catch (const std::exception&) { /* not a number: not AD's shape */ }
                    }
                    if (sid) ldap_value_free_len(sid);
                    if (pgid) ldap_value_free_len(pgid);
                }
            }
            if (r) ldap_msgfree(r);
            if (!user_dn.empty()) break;
        }
        // ⚠️ THE SECOND SITE THAT BUILDS A DN FROM A USERNAME, and it has to escape for the
        // same reason as the bind above. Fixing one of a pair and leaving the other is the
        // defect shape this codebase keeps producing; there are exactly two, and both are
        // covered. This one is the fallback used when the search did not find the user, so
        // the DN it guesses is then handed to a group filter — an unescaped comma there
        // does not just break the string, it silently asks about a different DN.
        if (user_dn.empty() && !p.base_dns.empty())
            user_dn = "CN=" + escape_dn_value(username) + "," + p.base_dns.front();

        // 2. Groups pointing at that DN. memberUid holds a bare username (posixGroup),
        //    the other two hold a DN — all three are asked at once so one filter covers
        //    AD, OpenLDAP with groupOfNames, and posix groups.
        const std::string dn_esc = filter_escape(user_dn);
        char* attrs[] = { const_cast<char*>(attr.c_str()), nullptr };

        // Run one group filter across every base and append whatever it names. `quiet`
        // is for the AD-only filters: an LDAP server that does not implement the
        // extensible match answers with an error, and that is a fact about the DIRECTORY,
        // not a fault — logging it at info on every OpenLDAP login would be noise that
        // trains people to ignore this line.
        auto collect = [&](const std::string& filter, bool quiet) {
            for (const auto& base : p.base_dns) {
                LDAPMessage* result = nullptr;
                int rc = ldap_search_ext_s(ld, base.c_str(), LDAP_SCOPE_SUBTREE, filter.c_str(),
                                           attrs, 0, nullptr, nullptr, &tv, 1000, &result);
                if (rc == LDAP_SUCCESS && result) {
                    for (LDAPMessage* e = ldap_first_entry(ld, result); e; e = ldap_next_entry(ld, e)) {
                        berval** vals = ldap_get_values_len(ld, e, attr.c_str());
                        if (vals && vals[0]) {
                            out.emplace_back(vals[0]->bv_val, vals[0]->bv_len);
                        } else {                      // no display attr -> fall back to the DN
                            char* dn = ldap_get_dn(ld, e);
                            if (dn) { out.emplace_back(dn); ldap_memfree(dn); }
                        }
                        if (vals) ldap_value_free_len(vals);
                    }
                } else if (rc != LDAP_SUCCESS && !quiet) {
                    log::info(std::string("ldap_groups_for_user: search under ") + base +
                              " failed: " + ldap_err2string(rc));
                }
                if (result) ldap_msgfree(result);
            }
        };

        // (a) DIRECT membership, portable. memberUid holds a bare username (posixGroup),
        //     the other two hold a DN — all three at once covers AD, OpenLDAP with
        //     groupOfNames, and posix groups.
        collect("(&" + group_filter + "(|(member=" + dn_esc +
                ")(uniqueMember=" + dn_esc + ")(memberUid=" + esc + ")))", false);

        // (b) the PRIMARY group, by SID. Nothing else can find it — see
        //     ad_primary_group_sid_filter(). Empty on every non-AD directory, so this
        //     costs one skipped string test there and no query at all.
        if (!primary_sid_filter.empty())
            collect("(&" + group_filter + "(objectSid=" + primary_sid_filter + "))", true);

        // (c) NESTED membership, via AD's LDAP_MATCHING_RULE_IN_CHAIN. The filters
        //     above match `member` by equality, so only DIRECT membership is found: a user
        //     in Helpdesk, where Helpdesk is a member of IT-Staff, does not match a grant
        //     on IT-Staff. This walks the chain server-side.
        //
        //     Its own search rather than another branch of (a), so an unknown extensible
        //     matching rule can never put the PORTABLE path at risk.
        //
        //     ⚠️ MEASURED, because I first wrote the opposite as though it were fact:
        //     folding this into the single filter does NOT break the Homebrew slapd the
        //     suite runs against — group resolution stayed 48/0 either way. So this
        //     separation is DEFENSIVE, not required by any directory we have tested.
        //     RFC 4511 4.5.1 leaves an unrecognised matchingRule to the server (an
        //     `inappropriateMatching` result is permitted), so the behaviour is
        //     server-dependent; keeping it separate costs one query on AD and nothing
        //     anywhere else, and bounds the blast radius of a directory that answers
        //     differently. Do not restate the collapse as a fact — it was not observed.
        if (!user_dn.empty())
            collect("(&" + group_filter + "(member:1.2.840.113556.1.4.1941:=" + dn_esc + "))", true);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        if (!out.empty()) break;                      // first directory that answers wins
    }

    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

// The `mail` attribute of ONE user, found by the same filter ldap_groups_for_user() uses to
// find the user's entry, so a name that resolves to groups resolves to the same person here.
std::string ldap_mail_for_user(const LdapProvider& p, const std::string& username) {
    if (username.empty() || p.uris.empty() || p.base_dns.empty()) return {};
    const std::string esc = filter_escape(username);
    const std::string user_filter =
        "(|(sAMAccountName=" + esc + ")(uid=" + esc + ")(cn=" + esc + "))";
    for (const auto& uri : p.uris) {
        LDAP* ld = connect_and_bind_service(p, uri, "ldap_mail_for_user");
        if (!ld) continue;
        struct timeval tv{p.network_timeout_sec, 0};
        char* want[] = { const_cast<char*>("mail"), nullptr };
        std::string mail;
        for (const auto& base : p.base_dns) {
            LDAPMessage* r = nullptr;
            int rc = ldap_search_ext_s(ld, base.c_str(), LDAP_SCOPE_SUBTREE, user_filter.c_str(),
                                       want, 0, nullptr, nullptr, &tv, 2, &r);
            if (rc == LDAP_SUCCESS && r) {
                if (LDAPMessage* e = ldap_first_entry(ld, r)) {
                    if (berval** v = ldap_get_values_len(ld, e, "mail")) {
                        if (v[0]) mail.assign(v[0]->bv_val, v[0]->bv_len);
                        ldap_value_free_len(v);
                    }
                }
            }
            if (r) ldap_msgfree(r);
            if (!mail.empty()) break;
        }
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        // The directory answered: its answer stands, including "this user has no mail".
        // A second replica of the same directory would say the same.
        return mail;
    }
    return {};
}


// The attributes that carry a login name, in the order a directory is likely to mean them:
// AD presents sAMAccountName, OpenLDAP usually uid, and cn catches directories that key by
// display name. Same order ldap_groups_for_user() uses to FIND a user, so a name picked
// here is a name that resolves at login — which is the entire point.
static const char* kUserNameAttrs[] = { "sAMAccountName", "uid", "cn" };

// Read one entry into an LdapUser. Returns false when nothing usable is there.
static bool read_user_entry(LDAP* ld, LDAPMessage* e, LdapUser& out) {
    for (const char* a : kUserNameAttrs) {
        berval** v = ldap_get_values_len(ld, e, a);
        if (v && v[0] && v[0]->bv_len) {
            out.username.assign(v[0]->bv_val, v[0]->bv_len);
            ldap_value_free_len(v);
            break;
        }
        if (v) ldap_value_free_len(v);
    }
    if (berval** d = ldap_get_values_len(ld, e, "displayName")) {
        if (d[0] && d[0]->bv_len) out.display.assign(d[0]->bv_val, d[0]->bv_len);
        ldap_value_free_len(d);
    }
    if (char* dn = ldap_get_dn(ld, e)) { out.dn = dn; ldap_memfree(dn); }
    if (out.username.empty()) return false;
    if (out.display.empty()) out.display = out.username;
    return true;
}

// The objectClasses that mean "a person" across AD and OpenLDAP. `posixAccount` is there
// for directories that carry no inetOrgPerson at all.
static std::string user_object_filter() {
    return "(|(objectClass=user)(objectClass=person)(objectClass=inetOrgPerson)"
           "(objectClass=posixAccount))";
}

std::vector<LdapUser> ldap_list_users(const LdapProvider& p, const std::string& q,
                                      std::string* error) {
    std::vector<LdapUser> out;
    if (error) error->clear();
    if (p.uris.empty() || p.base_dns.empty()) {
        if (error) *error = "this directory has no URIs or base DNs — set them on its row "
                            "(Directories page, or `fastpki-config auth-providers-add`)";
        return out;
    }
    // ⚠️ THE MACHINE-ACCOUNT EXCLUSION IS IN CODE, NOT IN THE FILTER, and that is not a
    // style choice. AD marks computer accounts objectClass=user too, so they must go — but
    // `(!(sAMAccountName=*$))` in the filter matches NOTHING on a directory whose entries
    // have no sAMAccountName at all. RFC 4511 §4.5.1: a filter item on an absent attribute
    // evaluates to **Undefined**, and NOT(Undefined) is Undefined, not TRUE — so the
    // enclosing AND fails for every OpenLDAP person. Measured: the picker came back empty
    // with no error, because the search genuinely succeeded and matched zero entries.
    std::string filter = "(&" + user_object_filter();
    if (!q.empty()) {
        const std::string e = filter_escape(q);
        filter += "(|(sAMAccountName=*" + e + "*)(uid=*" + e + "*)(cn=*" + e +
                  "*)(displayName=*" + e + "*))";
    }
    filter += ")";

    std::string last_err;
    for (const auto& uri : p.uris) {
        LDAP* ld = connect_and_bind_service(p, uri, "ldap_list_users");
        if (!ld) { last_err = "could not bind to " + uri +
                              " (this directory has no search account: set its bind DN "
                              "and password on the Directories page, or with "
                              "`fastpki-config auth-providers-add " + p.id +
                              " --bind-dn <dn> --bind-pw-file <file>`)"; continue; }
        struct timeval tv{p.network_timeout_sec, 0};
        char* attrs[] = { const_cast<char*>("sAMAccountName"), const_cast<char*>("uid"),
                          const_cast<char*>("cn"), const_cast<char*>("displayName"), nullptr };
        for (const auto& base : p.base_dns) {
            LDAPMessage* r = nullptr;
            int rc = ldap_search_ext_s(ld, base.c_str(), LDAP_SCOPE_SUBTREE, filter.c_str(),
                                       attrs, 0, nullptr, nullptr, &tv, 2000, &r);
            if (rc == LDAP_SUCCESS && r) {
                for (LDAPMessage* e = ldap_first_entry(ld, r); e; e = ldap_next_entry(ld, e)) {
                    LdapUser u;
                    if (!read_user_entry(ld, e, u)) continue;
                    // AD computer accounts, excluded from the "import a user" picker.
                    //
                    // ⚠️ The RULE is principal_kind()'s, not this line's. It used to
                    // spell out `back() == '$'` here while web/main.cpp spelled out its own
                    // copy — two sites, one of which had since gained the service-form `/`
                    // rule required here and the other had not. Asking the shared
                    // classifier is what keeps "is this a computer?" one answer.
                    if (principal_kind(u.username) == PrincipalKind::Computer) continue;
                    out.push_back(std::move(u));
                }
            } else if (rc != LDAP_SUCCESS) {
                const std::string why = ldap_err2string(rc);
                last_err = "search under " + base + " failed: " + why;
                // Same operator-facing hint ldap_list_groups gives: AD answers an
                // anonymous search with a bare "Operations error".
                if (why == "Operations error" && p.bind_dn.empty())
                    last_err += " — this directory does not allow anonymous searches. "
                                "Give it a read-only search account: Directories -> edit '" +
                                p.id + "' -> bind DN and password, or `fastpki-config "
                                "auth-providers-add " + p.id + " --bind-dn <dn> "
                                "--bind-pw-file <file>`";
                log::info("ldap_list_users: " + last_err);
            }
            if (r) ldap_msgfree(r);
        }
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        if (!out.empty()) break;                     // first directory that answers wins
    }
    std::sort(out.begin(), out.end(),
              [](const LdapUser& a, const LdapUser& b) { return a.username < b.username; });
    out.erase(std::unique(out.begin(), out.end(),
                          [](const LdapUser& a, const LdapUser& b) {
                              return a.username == b.username;
                          }), out.end());
    // Only report failure when it left us with nothing: a directory that answered from one
    // URI and refused from another did give us its users.
    if (error && out.empty() && !last_err.empty()) *error = last_err;
    return out;
}

std::vector<LdapUser> ldap_group_members(const LdapProvider& p, const std::string& group,
                                         std::string* error) {
    std::vector<LdapUser> out;
    if (error) error->clear();
    if (group.empty() || p.uris.empty() || p.base_dns.empty()) {
        if (error) *error = "this directory has no URIs or base DNs — set them on its row "
                            "(Directories page, or `fastpki-config auth-providers-add`)";
        return out;
    }
    const std::string group_filter = p.group_filter.empty()
        ? "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=group)(objectClass=posixGroup))"
        : p.group_filter;
    const std::string attr = p.group_attr.empty() ? "cn" : p.group_attr;
    const std::string esc  = filter_escape(group);
    const std::string find_group = "(&" + group_filter + "(" + attr + "=" + esc + "))";

    // Two different failures, reported differently. `bind_err` only matters when NOTHING
    // worked — a first URI that is down while the second answers is not an error the
    // operator needs to see. `uri_err` is a search that failed on the URI whose results we
    // KEEP, which means the list we are about to return is SHORT, and that must be said
    // out loud even though the call "succeeded".
    std::string last_err, bind_err;
    for (const auto& uri : p.uris) {
        LDAP* ld = connect_and_bind_service(p, uri, "ldap_group_members");
        if (!ld) { bind_err = "could not bind to " + uri; continue; }
        std::string uri_err;
        struct timeval tv{p.network_timeout_sec, 0};

        // 1. The group entry: its member lists, and its SID for the primary-group half.
        std::vector<std::string> member_dns, member_uids;
        std::string rid_filter, group_dn;
        bool ranged = false;          // AD capped `member` — see the range loop below
        char* gattrs[] = { const_cast<char*>("member"), const_cast<char*>("uniqueMember"),
                           const_cast<char*>("memberUid"), const_cast<char*>("objectSid"),
                           nullptr };
        for (const auto& base : p.base_dns) {
            LDAPMessage* r = nullptr;
            int rc = ldap_search_ext_s(ld, base.c_str(), LDAP_SCOPE_SUBTREE, find_group.c_str(),
                                       gattrs, 0, nullptr, nullptr, &tv, 2, &r);
            // ⚠️ A REFUSED SEARCH IS NOT AN EMPTY GROUP. Only a failed BIND used to reach
            // last_err, so a directory that authenticated us and then refused the search
            // returned zero members with HTTP 200 and no searchError — the console then
            // renders "this group has no members", which is the lie the endpoint was
            // written to prevent, told with more confidence than before.
            if (rc != LDAP_SUCCESS) {
                uri_err = std::string("group search on ") + base + " failed: " +
                           ldap_err2string(rc);
            } else if (r) {
                if (LDAPMessage* e = ldap_first_entry(ld, r)) {
                    if (char* gd = ldap_get_dn(ld, e)) { group_dn = gd; ldap_memfree(gd); }
                    // AD returns `member;range=0-1499` INSTEAD of `member` once a group
                    // exceeds MaxValRange, and a plain get_values_len("member") then
                    // answers NULL — zero members, no error, for the largest groups in
                    // the directory. Detect it here; collect it after the loop.
                    BerElement* be = nullptr;
                    for (char* a = ldap_first_attribute(ld, e, &be); a;
                         a = ldap_next_attribute(ld, e, be)) {
                        if (std::string(a).rfind("member;range=", 0) == 0) ranged = true;
                        ldap_memfree(a);
                    }
                    if (be) ber_free(be, 0);
                    for (const char* a : { "member", "uniqueMember" })
                        if (berval** v = ldap_get_values_len(ld, e, a)) {
                            for (int i = 0; v[i]; ++i) member_dns.emplace_back(v[i]->bv_val, v[i]->bv_len);
                            ldap_value_free_len(v);
                        }
                    if (berval** v = ldap_get_values_len(ld, e, "memberUid")) {
                        for (int i = 0; v[i]; ++i) member_uids.emplace_back(v[i]->bv_val, v[i]->bv_len);
                        ldap_value_free_len(v);
                    }
                    // The primary-group case in reverse: the group's own RID is what its members
                    // carry in primaryGroupID.
                    if (berval** v = ldap_get_values_len(ld, e, "objectSid")) {
                        if (v[0]) {
                            const std::string raw(v[0]->bv_val, v[0]->bv_len);
                            const size_t n = raw.size() > 1 ? static_cast<unsigned char>(raw[1]) : 0;
                            if (n && raw.size() == 8 + 4 * n) {
                                const size_t off = 8 + 4 * (n - 1);
                                unsigned long rid = 0;
                                for (int b = 3; b >= 0; --b)
                                    rid = (rid << 8) | static_cast<unsigned char>(raw[off + b]);
                                rid_filter = std::to_string(rid);
                            }
                        }
                        ldap_value_free_len(v);
                    }
                }
            }
            if (r) ldap_msgfree(r);
            if (!member_dns.empty() || !member_uids.empty() || !rid_filter.empty() || ranged) break;
        }

        // 1b. RANGED RETRIEVAL. Once a group passes AD's MaxValRange (1500 by default) the
        //     server stops returning `member` at all and returns `member;range=0-1499`
        //     instead, so the read above collects NOTHING for exactly the groups an
        //     operator most wants enumerated. Ask for the next window until the server
        //     answers with an open upper bound, which is how it says "that was the last".
        //     BASE-scoped on the group's own DN — we already know which entry it is.
        if (ranged && !group_dn.empty()) {
            unsigned long lo = 0;
            for (int guard = 0; guard < 512; ++guard) {   // bounded: never loop on a server that will not advance
                const std::string want = "member;range=" + std::to_string(lo) + "-*";
                char* rattrs[] = { const_cast<char*>(want.c_str()), nullptr };
                LDAPMessage* rr = nullptr;
                int rc = ldap_search_ext_s(ld, group_dn.c_str(), LDAP_SCOPE_BASE,
                                           "(objectClass=*)", rattrs, 0, nullptr, nullptr,
                                           &tv, 1, &rr);
                if (rc != LDAP_SUCCESS) {
                    uri_err = std::string("ranged member read failed at ") +
                               std::to_string(lo) + ": " + ldap_err2string(rc);
                    if (rr) ldap_msgfree(rr);
                    break;
                }
                bool last = true;
                unsigned long high = lo;
                if (LDAPMessage* e = rr ? ldap_first_entry(ld, rr) : nullptr) {
                    BerElement* be = nullptr;
                    for (char* a = ldap_first_attribute(ld, e, &be); a;
                         a = ldap_next_attribute(ld, e, be)) {
                        const std::string an(a);
                        if (an.rfind("member;range=", 0) == 0) {
                            if (berval** v = ldap_get_values_len(ld, e, a)) {
                                for (int i = 0; v[i]; ++i)
                                    member_dns.emplace_back(v[i]->bv_val, v[i]->bv_len);
                                ldap_value_free_len(v);
                            }
                            // "…=0-1499" means more follow; "…=1500-*" is the final window.
                            const size_t dash = an.rfind('-');
                            if (dash != std::string::npos && an.substr(dash + 1) != "*") {
                                last = false;
                                try { high = std::stoul(an.substr(dash + 1)); } catch (...) { last = true; }
                            }
                        }
                        ldap_memfree(a);
                    }
                    if (be) ber_free(be, 0);
                }
                if (rr) ldap_msgfree(rr);
                if (last || high < lo) break;
                lo = high + 1;
            }
        }

        // 2. Resolve each member DN to the name the directory presents at login. Read the
        //    ENTRY rather than parsing the DN's first RDN: a DN's CN is a display name and
        //    is frequently not the sAMAccountName, so parsing it would produce names that
        //    look right and never match a login (the same silent-failure mode again).
        char* uattrs[] = { const_cast<char*>("sAMAccountName"), const_cast<char*>("uid"),
                           const_cast<char*>("cn"), const_cast<char*>("displayName"), nullptr };
        //
        // ⚠️ AND IT MUST FILTER TO A PERSON. `member` holds whatever the directory put
        // there — nested groups and computer accounts included — and read_user_entry
        // accepts any entry carrying a `cn`, which every group has. So a nested group was
        // emitted as a person, with its cn as the username: an account that cannot log in,
        // offered for import as though it could. ldap_list_users has always applied
        // user_object_filter() and ldap.sh asserts "does NOT offer a group as a user" for
        // it; this path was the one that skipped it. A BASE search with a filter returns
        // no entry when the entry does not match, which is exactly the discrimination
        // wanted here — no second round trip.
        const std::string person = user_object_filter();
        for (const auto& dn : member_dns) {
            LDAPMessage* r = nullptr;
            int rc = ldap_search_ext_s(ld, dn.c_str(), LDAP_SCOPE_BASE, person.c_str(),
                                       uattrs, 0, nullptr, nullptr, &tv, 1, &r);
            // LDAP_NO_SUCH_OBJECT is a member DN that no longer resolves — a stale
            // reference, not a directory failure; it must not poison the whole answer.
            if (rc != LDAP_SUCCESS && rc != LDAP_NO_SUCH_OBJECT) {
                uri_err = std::string("member lookup failed: ") + ldap_err2string(rc);
            } else if (r) {
                if (LDAPMessage* e = ldap_first_entry(ld, r)) {
                    LdapUser u;
                    if (read_user_entry(ld, e, u)) out.push_back(std::move(u));
                }
            }
            if (r) ldap_msgfree(r);
        }
        // posixGroup lists bare usernames, which need no resolution.
        for (const auto& uid : member_uids) {
            LdapUser u; u.username = uid; u.display = uid; out.push_back(std::move(u));
        }

        // 3. The PRIMARY members, which appear in no member list at all.
        if (!rid_filter.empty()) {
            const std::string pf = "(&" + user_object_filter() +
                                   "(primaryGroupID=" + rid_filter + "))";
            for (const auto& base : p.base_dns) {
                LDAPMessage* r = nullptr;
                int rc = ldap_search_ext_s(ld, base.c_str(), LDAP_SCOPE_SUBTREE, pf.c_str(),
                                           uattrs, 0, nullptr, nullptr, &tv, 2000, &r);
                if (rc != LDAP_SUCCESS) {
                    uri_err = std::string("primary-member search on ") + base +
                               " failed: " + ldap_err2string(rc);
                } else if (r) {
                    for (LDAPMessage* e = ldap_first_entry(ld, r); e; e = ldap_next_entry(ld, e)) {
                        LdapUser u;
                        if (read_user_entry(ld, e, u)) out.push_back(std::move(u));
                    }
                }
                if (r) ldap_msgfree(r);
            }
        }
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        if (!uri_err.empty()) last_err = uri_err;
        if (!out.empty()) break;
    }
    std::sort(out.begin(), out.end(),
              [](const LdapUser& a, const LdapUser& b) { return a.username < b.username; });
    out.erase(std::unique(out.begin(), out.end(),
                          [](const LdapUser& a, const LdapUser& b) {
                              return a.username == b.username;
                          }), out.end());
    // ⚠️ Reported even when the list is NOT empty. A search refused partway through
    // yields a SHORT list, and a short list rendered as the complete membership is the
    // same lie as an empty one — just harder to notice.
    if (error) {
        if (!last_err.empty())                        *error = last_err;
        else if (out.empty() && !bind_err.empty())    *error = bind_err;
    }
    return out;
}

} // namespace pki
