// MS certificate templates. Windows enrollment clients fetch the
// available certificate templates via MS-XCEP GetPolicies; fastpki-ms serves
// them. Originally three were hard-coded (GenericUser, Email, GenericComputer);
// this lets an admin import templates exported from Active Directory (as CSV)
// into a DB table and manage them in the web console. The struct mirrors the
// MS-XCEP policy fields the Windows WCF validator needs.
#pragma once
#include "pki/cert_profile.hpp"

#include <openssl/x509.h>

#include <string>
#include <vector>

namespace pki {

class Db;

// Sentinel for a nillable flag that should be emitted as xsi:nil (i.e. "absent"
// in AD). In CSV an empty cell maps to this.
constexpr int kMsNil = -1;

struct MsTemplate {
    std::string oid;                       // msPKI-Cert-Template-OID
    std::string name;                      // template / common name (unique key)
    int         schema{1};                 // policySchema
    bool        enroll{true};
    bool        auto_enroll{false};
    int         validity_days{730};
    // pKIOverlapPeriod — the renewal OVERLAP, i.e. how long BEFORE expiry a client should
    // start renewing. kMsNil means the directory did not say and the serializer derives a
    // default; 0 is a real answer ("renew at expiry") and must survive as one.
    //
    // ⚠️ SECONDS, WHERE THE VALIDITY BESIDE IT IS DAYS, AND THAT ASYMMETRY IS DELIBERATE.
    // The wire element is a count of seconds, and directory overlaps are routinely shorter
    // than a day — a week-long template is given hours, not days. Rounding those to a whole
    // number of days turns "renew 8 hours early" into "renew at expiry", which is a
    // different policy that still looks like a plausible number. A validity has no such
    // sub-day case, so it stays in the unit its column already uses.
    long long   overlap_seconds{kMsNil};
    int         min_key_size{2048};
    // 0 = CNG (a Key Storage Provider names no keySpec); 1 = CryptoAPI AT_KEYEXCHANGE.
    // The built-ins offer a KSP first, so 0 is the spelling that matches them. A template
    // that names a KSP and then claims AT_KEYEXCHANGE is describing two different key
    // stores at once.
    int         key_spec{0};
    unsigned    key_usage{0xA000u};        // 16-bit KeyUsage bitmap
    int         major_rev{1};
    int         minor_rev{0};
    int         private_key_flags{0x10};   // msPKI-Private-Key-Flag
    int         subject_name_flags{0x9};   // msPKI-Certificate-Name-Flag
    int         enrollment_flags{kMsNil};  // msPKI-Enrollment-Flag (kMsNil = absent)
    int         general_flags{kMsNil};     // Flags (kMsNil = absent)
    std::string pk_oid{"1.2.840.113549.1.1.1"};   // public-key algorithm OID (RSA)
    std::string pk_name{"RSA"};
    std::string hash_oid{"2.16.840.1.101.3.4.2.1"}; // SHA-256
    std::string hash_name{"sha256"};
    std::vector<std::string> crypto_providers;
    std::vector<std::string> ekus;         // EKU friendly names
    // msPKI-Private-Key-Security-Descriptor, emitted as
    // <privateKeyAttributes><permissions>. An SDDL string, e.g.
    // "O:COG:CGD:(A;;GASDWOKA;;;CO)"; empty means xsi:nil (no ACL requested).
    std::string private_key_permissions;
    bool        enabled{true};
};

// The built-in defaults (GenericUser, Email, GenericComputer) — served when the
// ms_templates table is empty, so a fresh install keeps the legacy behavior.
std::vector<MsTemplate> default_ms_templates();

// Parse a CSV of templates (header row + one template per line; list cells like
// `ekus` use '|' as the in-cell separator) into MsTemplate records. On a
// malformed row, returns the rows parsed so far and sets `err` (1-based line).
// The accepted columns are the struct field names; missing optional columns take
// the struct defaults. `name` and `oid` are required.
std::vector<MsTemplate> parse_ms_templates_csv(const std::string& csv, std::string& err);

// The canonical CSV header (also what the web UI's CSV upload expects).
std::string ms_templates_csv_header();

// Serialize/deserialize the two list fields for DB storage ('|'-joined).
std::string join_pipe(const std::vector<std::string>& v);
std::vector<std::string> split_pipe(const std::string& s);

// ── The template as an ISSUANCE decision ───────────────────────────────
//
// Profiles and templates are treated identically as resources, and semantically they are
// the same: profiles apply to every protocol except MS-WSTEP, templates apply only to
// MS-WSTEP. Whatever the template allows must be honoured in the CSR, and a CSR that does
// not match its template is denied.
//
// Before this, `template:use|<name>` gated exactly one thing — the console's template
// catalogue — and MS-WSTEP resolved a PROFILE instead, with the requested template
// hardcoded empty. So a Windows client naming `GenericComputer` got a certificate whose
// shape came from a profile tiebreak, while the certificate itself carried the template
// name it never honoured. The template was decoration.
//
// ⚠️ THIS IS NOT A SECOND POLICY ENGINE. The template is converted to a CertProfile and
// handed to the same `enforce_issuance_policy()` every other protocol uses
// (IssuanceInput::profile_override). That was the one real cost of making the template the
// grant, and it is avoidable — so it is avoided. Only `min_key_size` has no CertProfile
// equivalent and is checked separately.

// The template name a Windows client asked for, "" if it named none.
//
// Two extensions carry it and a client may send either. The V1 form
// (szOID_ENROLL_CERTTYPE_EXTENSION, 1.3.6.1.4.1.311.20.2) is the name itself as a
// BMPString. The V2 form (szOID_CERTIFICATE_TEMPLATE, 1.3.6.1.4.1.311.21.7) is a SEQUENCE
// whose first element is the template's OID, which only means something against the
// catalogue — hence `known`.
std::string csr_requested_template(X509_REQ* csr, const std::vector<MsTemplate>& known);

// Every template name this identity's roles grant `template:use` or `template:edit` on.
// `*` expands against the catalogue, exactly as the profile union does.
//
// ⚠️ TAKES GROUPS. A template granted through a group is invisible without them, and that
// omission has now been found twelve times in this codebase under different names.
std::vector<std::string> templates_for_identity(Db& db, const ProfileIdentity& id,
                                                const std::vector<MsTemplate>& known);

// Which template applies. Mirrors resolve_profile's rules so the two cannot drift:
// an explicit request is honoured only if permitted; no request resolves only when the
// permitted set has exactly one member; anything else THROWS naming the choice.
//
// ⚠️ An empty permitted set REFUSES. It must never fall through to "honour what the client
// asked for" — that shape has been measured as a straight escalation path here before.
MsTemplate resolve_ms_template(Db& db, const ProfileIdentity& id,
                               const std::string& requested,
                               const std::vector<MsTemplate>& known);

// The template expressed as the policy the shared engine already enforces. `allowed_*`
// equals `default_*`, so a CSR asking for a key usage or EKU the template does not list is
// denied by `enforce_issuance_policy()` rather than by anything written here.
CertProfile profile_from_ms_template(const MsTemplate& t);

// The one template rule a CertProfile cannot express. Returns "" when the CSR's public key
// satisfies `min_key_size`, else the reason to refuse. Symmetric keys have no modulus, so
// this asks the key for its size in bits and compares.
std::string ms_template_key_refusal(const MsTemplate& t, X509_REQ* csr);

// May the ENROLLEE choose the name on the certificate?
//
// `subject_name_flags` is the certificate-template name-flag bitmask, and its low bit is
// the enrollee-supplies-subject grant. When it is SET the requester's own subject and
// subjectAltName are honoured; when it is CLEAR the directory is authoritative and the CA
// builds the name itself — which is the whole point of the flag, and the reason a caller
// must not be able to enrol under a name that is not theirs.
//
// ⚠️ THE FLAG IS AN UNSIGNED 32-BIT MASK held in a signed int. A directory hands back
// values with the top bit set (e.g. 0xA6000000 arrives as a negative decimal), so test the
// bit — never compare the value, and never assume a negative one means "unset".
//
// A template with NO name flags recorded (the nil marker) says nothing about who chooses
// the name. Treat that as the safe reading: the CA builds it.
bool ms_template_enrollee_supplies_subject(const MsTemplate& t);

} // namespace pki
