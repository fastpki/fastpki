// Issuance policy — faithful port of the PHP server's check_cn(),
// Extension::checkSubjectAltName() and the key-size checks in
// subject_pubkey_info.php / certificate.php.

#include "pki/policy.hpp"
#include "pki/config.hpp"
#include "pki/cert_profile.hpp"
#include "pki/db.hpp"
#include "pki/error.hpp"
#include "pki/log.hpp"
#include "pki/x509.hpp"   // name_cn — one definition of "which RDN is the name"

#include <openssl/x509v3.h>

#include <algorithm>
#include <fstream>
#include <regex>
#include <string>
#include <vector>

namespace pki {
namespace {

// This moved to x509.cpp as pki::name_cn — three more callers need it, and two
// answers to "which RDN is the name" is how a limit gets enforced against a different
// string than the certificate is issued for. Kept as a one-line alias so the reads below
// stay readable.
std::string cn_from_name(X509_NAME* n) {
    return name_cn(n);
}

// Escape ECMAScript-regex metacharacters in a literal domain suffix.
std::string regex_escape(const std::string& s) {
    static const std::string meta = R"(.^$|()[]{}*+?\)";
    std::string out;
    for (char c : s) {
        if (meta.find(c) != std::string::npos) out += '\\';
        out += c;
    }
    return out;
}

// Port of PHP check_cn(): is this name acceptable?
//   - unqualified (no dot): allowed; wildcard form only if the profile permits
//   - qualified: must match a suffix in domains.txt (wildcard label regex gated
//     on the profile)
bool check_cn(const Config& cfg, const std::string& cn, bool allow_wildcard) {
    if (cn.empty()) return false;
    bool master = allow_wildcard;

    if (cn.find('.') == std::string::npos) {           // unqualified
        if (cn.find('*') != std::string::npos) return master;
        return true;
    }

    // No allow-list configured: don't restrict by domain —
    // issuance is still gated by auth, the policy profile, key sizes and SAN
    // limits. The list is loaded at startup from the allowed_domains table.
    if (cfg.allowed_domains.empty()) return true;

    // Per-role label prefix (mirrors the PHP regex). Master may use '*' labels.
    const std::string prefix = master
        ? R"(([a-zA-Z0-9\*]\.|[a-zA-Z0-9\-]*[a-zA-Z0-9]\.)*)"
        : R"(([a-zA-Z0-9]\.|[a-zA-Z0-9\-]*[a-zA-Z0-9]\.)*)";

    for (const auto& dom : cfg.allowed_domains) {
        if (dom.empty() || dom[0] == '#') continue;
        try {
            std::regex re("^" + prefix + regex_escape(dom) + "$");
            if (std::regex_match(cn, re)) return true;
        } catch (const std::regex_error&) {
            // skip malformed domain entry
        }
    }
    return false;
}

// Render a name safely for an error message and a log line. The whole point of the check
// this serves is that the string may hold bytes a hostname cannot — so echoing it raw into
// a log or an HTTP body is the same class of mistake one layer down.
std::string printable(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        if (c >= 0x20 && c < 0x7f) { out += static_cast<char>(c); continue; }
        static const char* H = "0123456789abcdef";
        out += "\\x"; out += H[c >> 4]; out += H[c & 0xf];
    }
    return out;
}

// Convert a GENERAL_NAME IP (ASN1_OCTET_STRING) to dotted-quad / colon form.
std::string ip_to_string(const ASN1_OCTET_STRING* ip) {
    if (!ip) return {};
    int n = ASN1_STRING_length(ip);
    const unsigned char* d = ASN1_STRING_get0_data(ip);
    if (n == 4) {
        return std::to_string(d[0]) + "." + std::to_string(d[1]) + "." +
               std::to_string(d[2]) + "." + std::to_string(d[3]);
    }
    // IPv6 (or unexpected length): render as hex so the allowlist regex fails.
    std::string s;
    char buf[4];
    for (int i = 0; i < n; ++i) { std::snprintf(buf, sizeof buf, "%02x", d[i]); s += buf; }
    return s;
}

// Syntax, not policy — see the header for why the two are kept apart.
bool dns_name_ok(const std::string& n) {
    if (n.empty() || n.size() > 253) return false;
    size_t i = 0;
    if (n.compare(0, 2, "*.") == 0) i = 2;      // wildcard: a policy question, not this one
    if (i >= n.size()) return false;            // "*." and nothing after it
    size_t label = 0;
    for (size_t k = i; k < n.size(); ++k) {
        const unsigned char c = static_cast<unsigned char>(n[k]);
        if (c == '.') {
            if (label == 0) return false;                 // "", "a..b", ".a"
            if (n[k - 1] == '-') return false;            // label may not end in a hyphen
            label = 0;
            continue;
        }
        const bool ldh = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                         (c >= '0' && c <= '9') || c == '-' || c == '_';
        if (!ldh) return false;                           // NUL, space, control, '/', ...
        if (c == '-' && label == 0) return false;         // nor start with one
        if (++label > 63) return false;
    }
    if (label == 0) return false;                         // trailing dot
    if (n.back() == '-') return false;
    return true;
}

void check_key_size(const Config& cfg, EVP_PKEY* pk) {
    if (!pk) throw Error(1, "policy: missing public key");
    int bits = EVP_PKEY_get_bits(pk);
    switch (EVP_PKEY_get_base_id(pk)) {
        case EVP_PKEY_RSA:
        case EVP_PKEY_RSA_PSS:
            if (bits < cfg.min_rsa_bits)
                throw Error(1, "policy: RSA key too short (" + std::to_string(bits) +
                               " < " + std::to_string(cfg.min_rsa_bits) + ")");
            break;
        case EVP_PKEY_DSA:
            if (bits < cfg.min_dsa_bits)
                throw Error(1, "policy: DSA key too short (" + std::to_string(bits) +
                               " < " + std::to_string(cfg.min_dsa_bits) + ")");
            break;
        case EVP_PKEY_EC:
            if (bits < cfg.min_ec_bits)
                throw Error(1, "policy: EC key too short (" + std::to_string(bits) +
                               " < " + std::to_string(cfg.min_ec_bits) + ")");
            break;
        case EVP_PKEY_ED25519:   // EdDSA curves are fixed-strength (Ed25519 ~128-bit,
        case EVP_PKEY_ED448:     // Ed448 ~224-bit security) — no min-bits knob applies.
            break;
        case 0:
            // Provider-based keys (e.g. ML-DSA) may report base_id=0.
            // Accept any well-known PQ algorithm with a fixed security strength.
            if (EVP_PKEY_is_a(pk, "ML-DSA-44") ||
                EVP_PKEY_is_a(pk, "ML-DSA-65") ||
                EVP_PKEY_is_a(pk, "ML-DSA-87"))
                break;
            // fallthrough
        default:
            throw Error(1, "policy: unsupported key algorithm");
    }
}

} // namespace

// The key floor on its own, without the subject/SAN checks that only make sense for a
// leaf. enforce_issuance_policy() has always applied this to every certificate we ISSUE,
// but the console's CA routes never called any policy at all: POST /api/ca-instances
// checked basicConstraints CA:TRUE and nothing else, so a 1024-bit RSA CA could be
// imported, and a CA key could be minted below the floor its own leaves must clear.
// A CA is the one key in the deployment that must be at least as strong as everything
// under it, so it is the last place to skip this.
void enforce_key_policy(const Config& cfg, EVP_PKEY* pubkey) {
    check_key_size(cfg, pubkey);
}

void enforce_issuance_policy(const Config& cfg, X509_NAME* subject,
                             EVP_PKEY* pubkey, STACK_OF(X509_EXTENSION)* req_exts,
                             const CertProfile& profile, bool acme) {
    const bool allow_wildcard = profile.allow_wildcard;
    auto san_type_allowed = [&](const char* t) { return profile.allowed_san_types.count(t) > 0; };

    // 1. Key algorithm + size — enforced whenever there is a key to check. A null key
    // means a pre-flight (validate_leaf_request): the caller is asking whether this
    // request is acceptable BEFORE minting a key for it, so there is nothing to
    // measure yet. Every issuance path passes a real key and is unaffected.
    if (pubkey) check_key_size(cfg, pubkey);

    // 2. Subject CN — domain allowlist (skipped for ACME, which does DV).
    std::string cn = cn_from_name(subject);
    if (!acme && !cn.empty() && !check_cn(cfg, cn, allow_wildcard))
        throw Error(1, "policy: CN '" + cn + "' is not in the approved domains");

    // 3. SubjectAltName — DNS allowlist, IP allowlist, type restriction, count.
    if (!req_exts) return;
    int idx = X509v3_get_ext_by_NID(req_exts, NID_subject_alt_name, -1);
    if (idx < 0) return;
    X509_EXTENSION* ext = X509v3_get_ext(req_exts, idx);
    if (!ext) return;
    GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(ext));
    if (!names) throw Error(1, "policy: malformed SubjectAltName");

    int count = sk_GENERAL_NAME_num(names);
    auto fail = [&](const std::string& m) { GENERAL_NAMES_free(names); throw Error(1, m); };

    // The SAN COUNT limit used to be here, against cfg.max_san. It is `roles.max_san` now
    // and is enforced at each protocol's entry point, because a per-role number needs
    // the requester and this function is not given one — it is the pure policy layer and
    // deliberately knows nothing about RBAC. The TYPE restrictions below stay: which
    // GeneralName kinds are permitted is the profile's business, not the role's.

    for (int i = 0; i < count; ++i) {
        GENERAL_NAME* gn = sk_GENERAL_NAME_value(names, i);
        switch (gn->type) {
            case GEN_EMAIL:
                if (!san_type_allowed("email"))
                    fail("policy: email SAN not permitted by profile '" + profile.name + "'");
                break;
            case GEN_DNS: {
                if (!san_type_allowed("dns"))
                    fail("policy: DNS SAN not permitted by profile '" + profile.name + "'");
                const unsigned char* p = ASN1_STRING_get0_data(gn->d.dNSName);
                int l = ASN1_STRING_length(gn->d.dNSName);
                std::string dns(reinterpret_cast<const char*>(p), static_cast<size_t>(l));
                // ⚠️ THIS ONE RUNS FOR ACME TOO, and on that path it is the ONLY content
                // check a dNSName gets — the allowlist below is skipped because an ACME
                // name is proven by challenge instead. Without it a certificate could
                // assert `evil.example\0.attacker.example`, which a client reading the
                // SAN as a C string sees as `evil.example`. Syntax is not a policy the
                // challenge can substitute for.
                if (!dns_name_ok(dns))
                    fail("policy: SAN DNS '" + printable(dns) +
                         "' is not a syntactically valid DNS name");
                if (!acme && !check_cn(cfg, dns, allow_wildcard))
                    fail("policy: SAN DNS '" + printable(dns) + "' is not in the approved domains");
                break;
            }
            case GEN_IPADD: {
                if (!san_type_allowed("ip"))
                    fail("policy: IP SAN not permitted by profile '" + profile.name + "'");
                std::string ip = ip_to_string(gn->d.iPAddress);
                // ⚠️ EMPTY MEANS UNRESTRICTED, THE SAME AS AN EMPTY DOMAIN ALLOW-LIST.
                // Without this line it meant the exact opposite, twelve lines below the
                // control it contradicts: check_cn() returns true when allowed_domains is
                // empty, while std::regex("") matches nothing, so clearing this field
                // REFUSED EVERY IP SAN. Two adjacent policy controls in one function, with
                // opposite meanings for "not configured", and no way to tell from the
                // outside — the catch below only fires on a MALFORMED regex, and "" is
                // perfectly valid, so an operator who cleared the field to lift the
                // restriction got a total block with no error and no log line.
                //
                // "Not configured" now means the same thing everywhere in this function.
                // Note the shipped DEFAULT is not empty (10.0.0.0/8), so this changes
                // nothing for a deployment that never touched the setting; it only stops
                // punishing the one who did.
                if (!cfg.allowed_ips_regex.empty()) {
                    std::regex re;
                    try { re = std::regex(cfg.allowed_ips_regex); }
                    catch (const std::regex_error&) { fail("policy: bad allowed_ips_regex config"); }
                    if (!std::regex_match(ip, re))
                        fail("policy: SAN IP '" + ip + "' is not in the approved range");
                }
                break;
            }
            case GEN_URI:
                // URI SANs (opt-in per profile). Gate on the type; the
                // URI value itself isn't domain-restricted (URIs aren't hostnames).
                if (!san_type_allowed("uri"))
                    fail("policy: URI SAN not permitted by profile '" + profile.name + "'");
                break;
            case GEN_OTHERNAME:
                // otherName SANs (e.g. UPN). Opt-in per profile.
                if (!san_type_allowed("othername"))
                    fail("policy: otherName SAN not permitted by profile '" + profile.name + "'");
                break;
            default:
                fail("policy: unsupported SAN GeneralName type " + std::to_string(gn->type) +
                     " (email, DNS, IP, URI, otherName allowed)");
        }
    }
    GENERAL_NAMES_free(names);
}

bool valid_dns_name(const std::string& name) { return dns_name_ok(name); }

// Populate cfg.allowed_domains from the `allowed_domains` table — the SOLE
// source. A DOMAINS_FILE used to be merged in on top, described in this very comment
// as a "backward compat / migration source"; that is the shape §3f exists to delete.
// It also meant the effective policy differed per node, since a file is only visible
// to a process that can see that filesystem, while the table replicates.
void load_allowed_domains(Config& cfg, Db& db) {
    std::vector<std::string> out;
    try { out = db.list_allowed_domains(); }
    catch (const std::exception& e) {
        log::err(std::string("policy: list_allowed_domains failed: ") + e.what());
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    cfg.allowed_domains = std::move(out);

    // ⚠️ AN UNRESTRICTED POLICY IS ANNOUNCED AT err, AND THAT IS DELIBERATE. Both controls
    // in enforce_issuance_policy() treat EMPTY as "no restriction", which is the consistent
    // reading and the one an operator expects — but it means the protective case and the
    // wide-open case look identical from outside the process. The only thing that told them
    // apart was this line, and it was logged at info while LOG_LEVEL defaults to err, so on
    // a default deployment it was never printed at all.
    //
    // There is no warn level, and err is the only one that always emits (see log.cpp), so
    // that is where a security-relevant state has to go if it is to be seen. The wording
    // carries the severity instead of the level: this is a configuration report, not a
    // failure, and nothing is refused because of it.
    if (cfg.allowed_domains.empty())
        log::err("policy: NO approved domains configured — issuance is UNRESTRICTED by "
                 "domain name");
    else
        log::info("policy: loaded " + std::to_string(cfg.allowed_domains.size()) +
                  " approved domain(s)");

    // The sibling control, reported the same way and for the same reason. It is read from
    // config rather than the database, so it is not "loaded" here — but this is the one
    // place a process says out loud what its issuance policy actually is, and splitting the
    // two halves across different lines in different files is how one of them stops being
    // said. ALLOWED_IPS_REGEX ships as 10.0.0.0/8, so a deployment that never touched it
    // sees the ordinary info line.
    if (cfg.allowed_ips_regex.empty())
        log::err("policy: ALLOWED_IPS_REGEX is empty — every IP SAN is permitted");
    else
        log::info("policy: IP SANs restricted to /" + cfg.allowed_ips_regex + "/");
}

} // namespace pki
