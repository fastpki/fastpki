// Certificate policy profiles. A profile (also called a
// "role") declares which CSR-requested attributes the CA will honor: the Key
// Usage / Extended Key Usage bits it may carry, whether wildcard names are
// allowed, which SubjectAltName types are permitted, and a validity cap. At
// issuance the requested KU/EKU are honored only if they fall inside the
// profile's allow-list (else the request is denied); when the CSR requests none,
// the profile's defaults are applied. This replaces the previously hard-coded
// KU/EKU and the wildcard rule the permissive built-in now carries.
//
// The enforcement engine + the two built-ins + the profiles stored in the replicated
// `cert_profiles` table. Which profiles a subject may USE is not decided here — a profile is
// a RESOURCE its roles hold `profile:use`/`profile:edit` on, and `resolve_profile()` below
// is the one rule every protocol asks.
#pragma once
#include <set>
#include <string>
#include <vector>

#include <openssl/x509.h>

namespace pki {

struct Config;
class Db;
struct EffectiveProfile;   // defined below CertProfile, which it holds

// The built-in cert-profile names, in ONE place. They were renamed —
// `master` -> `admin`, `standard` -> `requester` — so that a profile and the role granted
// it share a name — it is simpler for a user to connect two things that have the same
// name.
//
// ⚠️ ONE list, deliberately. This repo has been bitten four separate times by a built-in
// whose name lived in several hardcoded lists and was only ever half-renamed, and every
// one of those was invisible until a custom role or profile existed. `kDefaultProfile` is
// the same argument for the ten `resolve_profile(..., ca_default)` call sites, which were
// ten copies of the string `"standard"`.
inline constexpr const char* kBuiltinProfiles[] = {"requester", "admin"};
inline constexpr const char* kDefaultProfile    = "requester";

// The authenticated identity of an enrollment request. Only fields the caller can vouch
// for should be filled — never the CSR subject, which the requester controls (that would
// let them pick a privileged profile).
//
// A profile is no longer SELECTED for a subject by `profile_assignments`;
// it is a RESOURCE the subject's ROLES hold `profile:use`/`profile:edit` on. So what matters
// here is the username and the role — the same two `may_enrol` takes — and the union of
// profiles follows from the roles those resolve to.
//
// ⚠️ `dn` and `groups` are GONE with the selector table, and nothing is lost: `subject_roles`
// carries the same three selector kinds (`user`, `dn`, `group`) via `subject_roles`/
// `roles_for_subject`, so subject -> roles -> profiles composes to strictly more than
// subject -> profiles ever did. A group-selected profile is now a group-selected ROLE that
// holds the profile — and unlike before, that role also mints enrolment credentials.
struct ProfileIdentity {
    std::string username;   // authenticated username
    std::string role;       // what authenticate() returned, "" when the protocol has none
    // The directory groups authenticate() resolved, so a profile reached through a
    // role granted to an LDAP group resolves the same way it does at the enrolment gate.
    // ⚠️ Must be filled wherever `role` is: profile resolution and may_enrol() share
    // subject_roles(), and giving one of them the groups and not the other is exactly the
    // "two readers that disagree about who exists" this file's header warns about.
    std::vector<std::string> groups;
};

// THE UNION: every profile this identity may use, sorted by name.
//
// Load them all as a union, with no priorities, and if nothing in the CSR matches
// that union, reject — so this is a SET, and `priority` is
// gone with `profile_assignments`. A grant `profile:use|*` or `profile:edit|*` means every
// profile; a named scope means that one.
//
// Fails CLOSED (empty) if the tables cannot be read.
std::vector<std::string> profiles_for_identity(Db& db, const ProfileIdentity& id);

// True iff this identity's roles hold `profile:use` or `profile:edit` covering `profile_name`.
// Used to authorize a client-requested certProfile: a profile may be honored only if the
// identity may actually use it, so a client cannot escalate by naming a more permissive
// one. Never throws.
bool identity_allows_profile(Db& db, const ProfileIdentity& id,
                             const std::string& profile_name);

// The profile an issuance request is issued under — ONE rule for every protocol except
// MS-WSTEP, whose client always names its template.
//
// The profiles a subject's roles hold `profile:use`/`profile:edit` on form a UNION with no
// priority among them, and the union is the whole answer:
//
//   0. an EMPTY union THROWS. A subject that has been granted no profile may use none —
//      the ordinary, permanent state of any subject nobody granted one to, not a
//      deployment that has yet to adopt the feature, so there is no fallback.
//   1. a `requested` profile (CMP certProfile, the console's `profile`, a SCEP token's
//      profile) is honoured ONLY if it is in the union, and then applies ALONE. Anything
//      else is DENIED so a client cannot escalate by naming a permissive one.
//      ⚠️ Two exemptions have been written here and BOTH were escalation paths: "an empty
//      union honours any request", and "naming the CA default is allowed". Do not add a
//      third.
//   2. nothing requested, ONE member: that profile.
//   3. nothing requested, several: the MERGE of all of them. What a request may carry is
//      the union of what the members ALLOW — KU/EKU bits, SAN types, wildcards, custom
//      extensions, omitting AIA/CRL DP, the longest validity cap. What a profile ADDS when
//      the request says nothing (default KU/EKU, a stated validity, stamped extensions) is
//      the members' common value; where they differ, the profile named after the
//      subject's PRIMARY role (the role it authenticated with, else its web_users row's)
//      decides; where that is not a member either, the default is left UNDECIDED and
//      issuance refuses only if the request relies on it, naming what to ask for.
//
// ⚠️ PRIMARY ROLE, NOT "ANY ROLE WHOSE NAME MATCHES". Matching every role the subject holds
// took the first match in `roles ORDER BY name` — a tiebreak by spelling, which is exactly
// the priority this design removed. A subject has one primary role.
//
// ⚠️ THE MERGE IS ABOUT ALLOWED ATTRIBUTES, NOT DEFAULTS, and that is the agreed rule
// rather than a convenience: "what I meant is allowed attributes, not default values. If
// CSR contains a attribute set that is not allowed in any of the user profiles, then
// reject it. Otherwise, honor what is in CSR." A not-allowed attribute is dropped
// (evaluate_profile_extensions), as agreed alongside it.
//
// Throws pki::Error(1) for every refusal; each caller renders that as its own protocol's
// policy failure. `cfg` supplies the profile definitions; a granted name with no
// definition is refused rather than replaced by a built-in.
EffectiveProfile resolve_profile(Db& db, const Config& cfg, const ProfileIdentity& id,
                                 const std::string& requested);

// One entry of an EST /csrattrs response (RFC 7030 §4.5.2 AttrOrOID): a bare
// OID (values empty → the "oid" CHOICE alternative) or an Attribute (values
// non-empty → SEQUENCE { type OID, values SET OF OID }). All OIDs are dotted.
struct CsrAttr {
    std::string oid;                    // attribute type / bare OID
    std::vector<std::string> values;    // value OIDs (empty = bare OID form)
};

// An arbitrary custom X.509v3 extension to stamp on certs issued under a
// profile. `value` is an OpenSSL "generic extension" spec — the only form
// that works for OIDs OpenSSL has no built-in method for:
//   "DER:05:00"        raw DER (colon-separated hex) — e.g. ASN.1 NULL
//   "ASN1:UTF8:text"   the ASN1_generate config syntax
// An empty `value` is treated as DER NULL (05 00), the id-pkix-ocsp-nocheck form.
// Use case: an authorized OCSP-responder cert carries id-pkix-ocsp-nocheck
// (1.3.6.1.5.5.7.48.1.5) and no AIA/CRLDP — the latter via the profile's
// manage_aia/manage_crldp, which let the REQUEST ask for them to be left out.
struct CustomExt {
    std::string oid;            // dotted OID, e.g. "1.3.6.1.5.5.7.48.1.5"
    std::string value;          // generic-ext spec ("DER:05:00" / "ASN1:…"); empty ⇒ NULL
    bool critical{false};
};

struct CertProfile {
    std::string name;
    // CSR-requested KU/EKU are honored only if every requested item is in these
    // allow-lists; otherwise issuance is denied. Names are OpenSSL config tokens
    // (KU: "digitalSignature", "keyEncipherment", …; EKU: "serverAuth", … or an
    // OID). CA-only KU bits (keyCertSign, cRLSign) are always refused for an
    // end-entity cert regardless of the allow-list.
    std::set<std::string> allowed_ku;
    std::set<std::string> allowed_eku;
    // Applied when the CSR requests no KU / no EKU.
    std::vector<std::string> default_ku;
    std::vector<std::string> default_eku;
    bool allow_wildcard{false};
    // Put the serial number Apple attested into the SubjectAltName as an RFC 4043
    // permanentIdentifier — only on a certificate issued through ACME device attestation,
    // the one path where a serial is proven rather than typed. Off by default: a certificate
    // presented to arbitrary servers would otherwise hand every one of them the serial.
    bool device_serial_san{false};
    // Permitted SubjectAltName GeneralName types ("dns", "ip", "email").
    std::set<std::string> allowed_san_types{"dns", "ip", "email"};
    int max_validity_days{0};   // 0 => use cfg.cert_validity_days
    // ⚠️ A GRANT, NOT A BOUND — and the difference is the whole point where it is set.
    // `max_validity_days` can only ever SHORTEN cfg.cert_validity_days, so a profile
    // asking for longer than the deployment default silently gets the default. That is
    // wrong for an MS certificate template: the template is a published contract telling a
    // Windows client what this CA will issue, so a template stating one year must produce
    // one year even where CERT_VALIDITY_DAYS is 90. Announcing one validity and issuing
    // another breaks the contract silently — the client cannot see the difference and the
    // certificate looks correct in every other respect.
    // 0 => not stated; the cfg default applies, capped by max_validity_days as before.
    // The issuer's own notAfter still clamps this: a leaf may not outlive its signer, which
    // is a physical constraint rather than a policy choice.
    int validity_days{0};
    // CSR attributes/OIDs this profile asks EST clients to include, served by
    // GET /.well-known/est/csrattrs.
    // Empty → the endpoint falls back to the global EST_CSRATTRS, else 204.
    std::vector<CsrAttr> csr_attrs;
    // Arbitrary custom extensions stamped on every cert issued under this profile
    // — e.g. id-pkix-ocsp-nocheck for an OCSP-responder cert.
    std::vector<CustomExt> custom_extensions;
    // Which CSR-supplied custom extensions survive issuance. `"*"` means
    // any. Empty (the default) means none, which is what every profile did before this
    // field existed — `"any" or "*"` was required on the `admin` profile.
    //
    // ⚠️ Do NOT confuse this with `custom_extensions` above. That one is what the profile
    // STAMPS on every certificate; this one is what a REQUESTER may carry in. They were
    // the same word in his sentence and are opposite directions in the code.
    //
    // A wildcard cannot smuggle a privilege. `issue_cert_from_parts` writes
    // basicConstraints `critical,CA:FALSE`, KU, EKU and SAN BEFORE copying anything in,
    // and `copy_exts_by_oid` skips an OID already on the certificate — so `"*"` only ever
    // admits extensions the CA does not write itself.
    std::set<std::string> allowed_custom_extensions;
    // Suppress the CA-added AIA / CRL DP extensions for this profile.
    // An authorized OCSP-responder cert carries neither (RFC 6960 §4.2.2.2.1).
    // NOT "always omit" — the requester MAY omit. The options to leave out AIA and
    //   CRLDP belong on the request form when the profile allows them to be modified,
    //   which is why the two profile flags are named manageAIA and manageCRLDP rather
    //   than omitAIA and omitCRLDP.
    // The old meaning could not express his case at all: an admin needs ONE profile that
    // issues ordinary certificates AND lets him issue an OCSP responder without AIA or
    // CRLDP. A profile that always omits cannot do the first; one that never omits cannot
    // do the second. Delegating the choice to the request is what makes one profile cover
    // both. When false, the request's omit flags are ignored and the extensions are
    // emitted as usual.
    bool manage_aia{false};
    bool manage_crldp{false};
    // When true, WEB_SELFSERVICE_IDENTITY_SUBJECT is ignored for users assigned
    // this profile — the CSR's Subject DN is kept as-is.
    bool no_override_subject{false};
    // basicConstraints. For consistency the CA-creation page consults the profile,
    // which implies basicConstraints has to be part of a profile.
    //
    // May a certificate issued under this profile be a CA? Only the console's CA-creation
    // path reads it — every LEAF path writes `basicConstraints critical,CA:FALSE`
    // unconditionally, and that does not change here: turning a leaf into a CA is a much
    // larger question than the one he asked, and the CAs page is the path that creates CAs.
    //
    // ⚠️ DEFAULTS FALSE, including for a stored profile whose definition has no such key.
    // The safe direction for "may mint a CA" is no, and a missing key must not read as
    // permission. `admin` ships true; `requester` ships false.
    bool allow_ca{false};
    // Cap on the pathLenConstraint a CA created under this profile may carry.
    //   < 0  no cap — any depth, including an unconstrained CA (no pathLenConstraint)
    //   >= 0 the maximum, AND an unconstrained CA is refused: "at most N" cannot be
    //        satisfied by "unlimited", and silently substituting the cap would grant a
    //        different certificate than the operator asked for.
    int max_path_len{-1};
    // RUNTIME ONLY, never stored: the defaults a MERGED profile could not decide (see
    // resolve_profile), by the words the refusal uses — "default key usage", "default
    // extended key usage", "validity", "stamped custom extensions". Issuance refuses only
    // when the request relies on one of them.
    std::set<std::string> undecided{};
};

// The profile a request is issued under, and what to call it in logs and messages: one
// profile's own name, or the members of a merged profile joined with '+'.
struct EffectiveProfile {
    std::string name{};
    CertProfile profile{};
};

// The VIRTUAL profile for a device renewing its own certificate.
//
// Three proposals were rejected — a profile column on `certs`, resolving from
// `certs.role`, and a built-in `device` profile — in favour of this:
//
//   It is a kind of VIRTUAL profile: it allows only the same attributes on the CSR as the
//   provided certificate already carries, and a validity no longer than the existing one.
//   In other words, renew with the existing set of attributes, revoke, and nothing else.
//
//   Not the requester's role profile — that is too broad for a particular device, since a
//   human requester would normally have more allowed attributes than one device has.
//
// So the policy is not looked up anywhere — it is READ OFF the certificate being renewed.
// Nothing stored, nothing to grant, nothing to keep in step with a device's real needs,
// and the ceiling is that device's own certificate rather than a human's role.
//
// ⚠️ The result is a CEILING, not a template. It permits exactly what the held certificate
// already carries, so a renewal can only ever narrow. It is never registered in
// `cfg.cert_profiles` and cannot be named by a client: it exists for the length of one
// request, built from a certificate we hold and the caller has proved possession of.
CertProfile profile_from_cert(X509* held);

// Install the built-in profiles (kBuiltinProfiles) into cfg.cert_profiles if absent.
// Called once after config load; an EDITED built-in persisted in the database wins.
void ensure_builtin_profiles(Config& cfg);

// Parse a JSON object of profiles ({ "<name>": { "allowed_ku":[…],
// "allowed_eku":[…], "default_ku":[…], "default_eku":[…], "allow_wildcard":bool,
// "allowed_san_types":[…], "max_validity_days":int, "custom_extensions":
// [{oid,value,critical}, …], "manage_aia":bool, "manage_crldp":bool }, … }) into
// cfg.cert_profiles (overriding same-named entries). Throws pki::Error on malformed JSON.
// The shape `fastpki-config profiles-import` reads and `profiles-export` writes.
void install_cert_profiles_json(Config& cfg, const std::string& json);

// Replace cfg.cert_profiles with the `cert_profiles` table plus the built-ins it does not
// override. Every service calls it once after the config overlay; the console also calls
// it before it reads or writes a profile, so an edit made on another node, or with
// fastpki-config, is what it sees. A row that does not parse is logged and skipped — the
// other profiles still load. Throws only if the table cannot be read.
void load_cert_profiles(Config& cfg, Db& db);

// Persist `p` as its `cert_profiles` row. A built-in identical to its code default is
// stored as NO row (an existing one is deleted), so a later improvement to that default
// still reaches this deployment.
void store_cert_profile(Db& db, const CertProfile& p);

// Every STORED profile as one JSON object, { "<name>": {fields…}, … } — what
// install_cert_profiles_json() reads back, and what the backup and profiles-export carry.
std::string stored_cert_profiles_json(Db& db);

// The profile to apply for the given profile name. Falls back to kDefaultProfile when
// the name is unknown, so issuance never fails for a missing profile (it just gets the
// conservative default).
const CertProfile& resolve_cert_profile(const Config& cfg, const std::string& name);

// The KU / EKU OpenSSL config strings to put on the issued cert, computed from
// the profile and the CSR's requested extensions (honor-within-allow-list, else
// throw pki::Error(1, …); defaults when the CSR requests none). `key_usage`
// includes the "critical," prefix; `ext_key_usage` is empty when the effective
// EKU set is empty (so the caller omits the extension).
struct ProfileExtensions {
    std::string key_usage;
    std::string ext_key_usage;
};
ProfileExtensions evaluate_profile_extensions(const CertProfile& profile,
                                              STACK_OF(X509_EXTENSION)* req_exts);

// JSON array of the configured profiles (name + fields + a "builtin" flag for
// the built-ins), for the console's profiles view.
// `only` (when non-null) restricts the listing to those profile NAMES. This list is a
// MANAGEMENT view — /api/my-profiles is the issuance one — and with the write path now
// enforcing the grant's scope, a caller holding profile:edit on ONE profile could still read
// every other tenant's policy body out of it. Filtering here keeps the list and the write
// gate answering the same question.
std::string cert_profiles_json(const Config& cfg, const std::set<std::string>* only = nullptr);

// True for the code-defined built-in profile names, which the console may edit and clone
// but not delete.
bool is_builtin_profile(const std::string& name);

// Encode a list of CsrAttr as the RFC 7030 §4.5.2 /csrattrs body: a DER
// SEQUENCE OF AttrOrOID (each a bare OID, or an Attribute SEQUENCE{type, SET OF
// value-OID}). Returns empty when `attrs` is empty (caller answers 204). Skips
// any entry whose OID doesn't parse. Also parses the legacy flat EST_CSRATTRS
// string (comma/space-separated bare OIDs) via csr_attrs_from_oid_list().
std::vector<unsigned char> build_csrattrs_der(const std::vector<CsrAttr>& attrs);
std::vector<CsrAttr> csr_attrs_from_oid_list(const std::string& csv);
// Parse a JSON array of AttrOrOID (bare-OID string | {"oid":…,"values":[…]}) —
// used by the web Profiles editor to round-trip per-profile csr_attrs.
std::vector<CsrAttr> csr_attrs_from_json_str(const std::string& json_array);

// Parse a JSON array of custom extensions ([{oid, value, critical}, …]) — used by
// the web Profiles editor to round-trip a profile's custom_extensions.
// Malformed JSON yields an empty list.
std::vector<CustomExt> custom_exts_from_json_str(const std::string& json_array);

} // namespace pki
