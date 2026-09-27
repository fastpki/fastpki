#pragma once
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <string>

namespace pki {

struct Config;
struct CertProfile;
class Db;

// Load the approved-domain allow-list into cfg.allowed_domains: the
// allowed_domains DB table — the sole source.
// Call once at startup after overlay_config(); enforce_issuance_policy() then
// reads the in-memory list instead of the file.
void load_allowed_domains(Config& cfg, Db& db);

// ── is this string a DNS name at all? ───────────────────────────────────────────
// RFC 5280 §4.2.1.6 says a dNSName holds a name in "preferred name syntax", and nothing
// in this product checked that. The domain ALLOWLIST (check_cn) is a different question
// and is deliberately skipped for ACME, whose names are proven by challenge instead — so
// on the ACME path there was no content check on a dNSName of any kind, and with no
// allowed_domains rows configured (a shipped default) there was none on the other paths
// either. A dNSName carrying a NUL, a space or a control character would have been
// certified: the classic embedded-NUL name, where a client that reads the SAN as a C
// string sees a prefix that was never validated.
//
// Syntax only, and deliberately permissive about POLICY: a leading "*." is accepted here
// whatever the profile says, because whether a wildcard may be ISSUED is check_cn's
// question and this must not quietly answer it differently. Single-label names are legal
// (machine certificates carry them). '_' is accepted because internal deployments use it
// in host labels; every character this rejects is one that cannot appear in a hostname
// at all.
bool valid_dns_name(const std::string& name);

// The key-algorithm and key-size floor on its own — the same check
// enforce_issuance_policy() applies to a leaf, without the CN/SAN rules that do not
// apply to a CA. Throws pki::Error(1, …) with a human-readable reason. Used by the
// console's CA import and CA creation routes, which enforced no key policy at all.
void enforce_key_policy(const Config& cfg, EVP_PKEY* pubkey);

// Enforce the CA issuance policy ported from the PHP server
// (check_cn + checkSubjectAltName + key-size checks). Throws pki::Error(1, …)
// with a human-readable reason on any violation; returns normally if the
// request is acceptable.
//
//   subject   – requested subject name (its CN is policy-checked)
//   pubkey    – requested public key (algorithm + size checked)
//   req_exts  – requested extensions (SAN is policy-checked); may be null
//   profile   – the resolved cert policy profile: governs whether wildcard names
//               are allowed and which SubjectAltName GeneralName types are
//               permitted
//   acme      – true for the ACME path, which performs its own domain
//               validation and therefore bypasses the domains.txt allowlist
//               (key-size, IP-SAN and GeneralName-type checks still apply)
void enforce_issuance_policy(const Config& cfg, X509_NAME* subject,
                             EVP_PKEY* pubkey, STACK_OF(X509_EXTENSION)* req_exts,
                             const CertProfile& profile, bool acme);

} // namespace pki
