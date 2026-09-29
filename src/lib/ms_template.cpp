// MS certificate templates: the built-in defaults, the CSV import
// parser, and the small (de)serialization helpers for the two list fields.
#include "pki/ms_template.hpp"

#include <map>
#include <sstream>
#include <stdexcept>

namespace pki {

std::string join_pipe(const std::vector<std::string>& v) {
    std::string o;
    for (size_t i = 0; i < v.size(); ++i) { if (i) o += "|"; o += v[i]; }
    return o;
}

std::vector<std::string> split_pipe(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == '|') { if (!cur.empty()) out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::vector<MsTemplate> default_ms_templates() {
    // ⚠️ THE KSP FIRST, AND THE LEGACY CSP BEHIND IT.
    //
    // These templates shipped naming ONE provider, and it was a legacy CryptoAPI CSP. A
    // legacy CSP cannot acquire a SILENT context, and silent is the normal case:
    // autoenrolment, scheduled tasks and anything running as a service have no desktop to
    // prompt on. Measured with the real Windows enrolment client:
    //
    //     certreq -q -enroll -machine ...
    //       -> Provider could not perform the action since the context was acquired as
    //          silent. 0x80090022 (NTE_SILENT_CONTEXT)
    //
    // and that error disappears when the template names a Key Storage Provider instead.
    //
    // ⚠️ THE PROVIDER SET AND THE SCHEMA VERSION ARE ONE DECISION, NOT TWO. A template's
    // msPKI-Template-Schema-Version decides which providers Windows will even consider:
    // schema 1 and 2 are CryptoAPI and allow ONLY legacy CSPs; a Key Storage Provider
    // requires schema 3. keySpec belongs to the same decision -- CryptoAPI wants
    // AT_KEYEXCHANGE (1), CNG names no keySpec (0).
    //
    // These built-ins are inherited from the original PHP server, where all three were a
    // coherent schema-1 set: legacy CSP, keySpec 1. Moving them to a KSP and keySpec 0 (so
    // that unattended enrolment can acquire a silent context, which a legacy CSP cannot)
    // changed two thirds of that decision and left the schema at 1 -- a CNG provider named
    // on a CryptoAPI template, which is not a combination Windows accepts. This completes
    // the move rather than reverting it.
    //
    // The legacy CSP goes with it. It was kept as a fallback for a client too old for CNG,
    // but such a client cannot read a schema-3 template at all, so the entry could never be
    // reached -- and leaving it in is what makes the set look self-contradictory.
    const int         schema_v3 = 3;
    const std::vector<std::string> csp = {"Microsoft Software Key Storage Provider"};
    // ⚠️ EVERY FLAG FIELD CARRIES A VALUE. kMsNil is the right default for a template
    // IMPORTED from a directory, where the attribute may genuinely be absent — but a
    // built-in is authored here, so "we did not say" is never the honest answer for one.
    // Left at the default, the wire carried
    //
    //     <enrollmentFlags xsi:nil="true"/>
    //     <generalFlags xsi:nil="true"/>
    //
    // and a real Windows client refused to read the policy it had just accepted:
    // Add-CertificateEnrollmentPolicyServer succeeded (the document validates), then
    // `certutil -PolicyServer <url> -Kerberos -Policy` failed 0x80094004
    // CERTSRV_E_PROPERTY_EMPTY — "the requested property value is empty" — and
    // `certreq -enroll <name>` could not find any template at all. Measured on a
    // domain-joined Server 2022 client against this CA.
    //
    // ⚠️ AND enrollmentFlags MUST AGREE WITH <permission><autoEnroll>. The two say the
    // same thing in different places: a template offered for autoenrolment while its own
    // msPKI-Enrollment-Flag omits CT_FLAG_AUTO_ENROLLMENT (0x20) is self-contradictory,
    // and that contradiction is what "the flags are messy" describes.
    const int kAutoEnroll = 0x20;   // CT_FLAG_AUTO_ENROLLMENT
    const int kMachine    = 0x40;   // CT_FLAG_MACHINE_TYPE, in the template's own Flags
    MsTemplate user;
    user.oid  = "1.3.6.1.4.1.311.21.8.3216253.15123779.9062035.8017536.559549.172.5014266.7858498";
    user.name = "GenericUser"; user.auto_enroll = false; user.key_usage = 0xA000u;
    user.schema = schema_v3;
    user.subject_name_flags = 0x9; user.crypto_providers = csp;
    user.enrollment_flags = 0;                    // not offered for autoenrolment
    user.general_flags    = 0;                    // a user template: MACHINE_TYPE clear
    user.ekus = {"TLS Web Server Authentication", "TLS Web Client Authentication"};
    MsTemplate email;
    email.oid  = "1.3.6.1.4.1.311.21.8.3216253.15123779.9062035.8017536.559549.172.5014266.7858497";
    email.name = "Email"; email.auto_enroll = true; email.key_usage = 0xE000u;
    email.schema = schema_v3;
    // ⚠️ A USER TEMPLATE DERIVES ITS SUBJECT; IT DOES NOT ASK THE ENROLLEE FOR ONE.
    // 0x8 is CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME, which only ever applies to a
    // RENEWAL, so on its own it left a first enrolment with no source for the subject.
    // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x1) answered that by letting the REQUESTER choose
    // the name -- on an autoenrolling template whose EKU is E-mail Protection, i.e. anyone
    // who may enrol could obtain an S/MIME certificate in somebody else's name, which is
    // the very thing ms_template_enrollee_supplies_subject() gates and msxcep/main.cpp
    // discards a requested subject to prevent. It also made this the only built-in still
    // exercising that branch stop exercising it, so nothing tested the gate at all.
    //
    // The fix is the one GenericComputer already uses for the identical problem: say where
    // the name comes FROM. SUBJECT_REQUIRE_COMMON_NAME | SUBJECT_ALT_REQUIRE_EMAIL is what
    // AD's own user-facing templates carry, and it matches what this CA actually does when
    // the grant is absent -- the CN is the authenticated principal and the provider becomes
    // its own domainComponent.
    email.subject_name_flags = 0x40000000 | 0x04000000 | 0x8; email.crypto_providers = csp;
    // 0x1 is CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS, which this template already carried.
    email.enrollment_flags = 0x1 | kAutoEnroll;
    email.general_flags    = 0;
    email.ekus = {"E-mail Protection"};
    MsTemplate comp;
    comp.oid  = "1.3.6.1.4.1.311.21.8.3216253.15123779.9062035.8017536.559549.172.5014266.7858499";
    comp.name = "GenericComputer"; comp.auto_enroll = true; comp.key_usage = 0xA000u;
    comp.schema = schema_v3;
    // ⚠️ A MACHINE TEMPLATE MUST TELL THE CLIENT TO BUILD ITS OWN SUBJECT. This carried
    // 0x9 — CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT | CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME
    // — which asks the caller for a subject and, failing that, takes it from the
    // certificate being renewed. Unattended enrolment has neither: `certreq -enroll
    // -machine <template>` passes no subject and there is no old certificate on a first
    // enrolment, so the client had no source for the name and gave up with
    // `A certificate request could not be created. Access denied. 0x80090010 (NTE_PERM)`.
    //
    // The domain's own `Machine` template, which enrols on this same client, says
    // 0x18000000 — CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN | CT_FLAG_SUBJECT_ALT_REQUIRE_DNS —
    // i.e. "put the machine's DNS name in the CN and in a dNSName SAN, and work it out
    // yourself". That is what autoenrolment needs and what this now says.
    comp.subject_name_flags = 0x10000000 | 0x08000000;
    comp.crypto_providers = csp;
    comp.enrollment_flags = kAutoEnroll;
    // ⚠️ generalFlags REPEATS autoenrolment, and the AD template proves it is expected:
    // the domain's `Machine` carries 0x10260 — AUTO_ENROLLMENT | MACHINE_TYPE |
    // ADD_TEMPLATE_NAME | IS_DEFAULT. IS_DEFAULT is AD's own marker and is not ours to
    // claim, but the other three describe this template exactly.
    comp.general_flags    = kMachine | kAutoEnroll | 0x200 /* CT_FLAG_ADD_TEMPLATE_NAME */;
    comp.ekus = {"TLS Web Server Authentication", "TLS Web Client Authentication"};
    return {user, email, comp};
}

std::string ms_templates_csv_header() {
    return "name,oid,schema,enroll,auto_enroll,validity_days,min_key_size,key_spec,"
           "key_usage,major_rev,minor_rev,private_key_flags,subject_name_flags,"
           "enrollment_flags,general_flags,pk_oid,pk_name,hash_oid,hash_name,"
           "crypto_providers,ekus,private_key_permissions,overlap_seconds,enabled";
}

namespace {
std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}
std::vector<std::string> split_comma(const std::string& line) {
    std::vector<std::string> out; std::string cur;
    for (char c : line) { if (c == ',') { out.push_back(cur); cur.clear(); } else cur += c; }
    out.push_back(cur);
    return out;
}
// Decimal or 0x-hex; empty → kMsNil (used for the nillable flag fields).
int to_int_or_nil(const std::string& s) {
    std::string t = trim(s);
    if (t.empty()) return kMsNil;
    return static_cast<int>(std::stol(t, nullptr, 0));
}
long to_long(const std::string& s, long dflt) {
    std::string t = trim(s);
    if (t.empty()) return dflt;
    return std::stol(t, nullptr, 0);
}
bool to_bool(const std::string& s, bool dflt) {
    std::string t = trim(s);
    if (t.empty()) return dflt;
    return t == "1" || t == "true" || t == "yes" || t == "TRUE" || t == "True";
}
}  // namespace

std::vector<MsTemplate> parse_ms_templates_csv(const std::string& csv, std::string& err) {
    err.clear();
    std::vector<MsTemplate> out;
    std::istringstream in(csv);
    std::string line;
    std::vector<std::string> header;
    int lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        std::vector<std::string> cells = split_comma(line);
        if (header.empty()) {
            for (auto& c : cells) header.push_back(trim(c));
            continue;
        }
        std::map<std::string, std::string> row;
        for (size_t i = 0; i < header.size() && i < cells.size(); ++i)
            row[header[i]] = cells[i];
        auto val = [&](const char* k) -> std::string {
            auto it = row.find(k); return it == row.end() ? "" : it->second;
        };
        try {
            MsTemplate m;  // start from struct defaults
            m.name = trim(val("name"));
            m.oid  = trim(val("oid"));
            if (m.name.empty() || m.oid.empty()) {
                err = "line " + std::to_string(lineno) + ": name and oid are required";
                return out;
            }
            if (row.count("schema"))             m.schema = static_cast<int>(to_long(val("schema"), m.schema));
            if (row.count("enroll"))             m.enroll = to_bool(val("enroll"), m.enroll);
            if (row.count("auto_enroll"))        m.auto_enroll = to_bool(val("auto_enroll"), m.auto_enroll);
            if (row.count("validity_days"))      m.validity_days = static_cast<int>(to_long(val("validity_days"), m.validity_days));
            if (row.count("min_key_size"))       m.min_key_size = static_cast<int>(to_long(val("min_key_size"), m.min_key_size));
            if (row.count("key_spec"))           m.key_spec = static_cast<int>(to_long(val("key_spec"), m.key_spec));
            if (row.count("key_usage"))          m.key_usage = static_cast<unsigned>(to_long(val("key_usage"), m.key_usage));
            if (row.count("major_rev"))          m.major_rev = static_cast<int>(to_long(val("major_rev"), m.major_rev));
            if (row.count("minor_rev"))          m.minor_rev = static_cast<int>(to_long(val("minor_rev"), m.minor_rev));
            if (row.count("private_key_flags"))  m.private_key_flags = static_cast<int>(to_long(val("private_key_flags"), m.private_key_flags));
            if (row.count("subject_name_flags")) m.subject_name_flags = static_cast<int>(to_long(val("subject_name_flags"), m.subject_name_flags));
            if (row.count("enrollment_flags"))   m.enrollment_flags = to_int_or_nil(val("enrollment_flags"));
            if (row.count("general_flags"))      m.general_flags = to_int_or_nil(val("general_flags"));
            if (!trim(val("pk_oid")).empty())    m.pk_oid = trim(val("pk_oid"));
            if (!trim(val("pk_name")).empty())   m.pk_name = trim(val("pk_name"));
            if (!trim(val("hash_oid")).empty())  m.hash_oid = trim(val("hash_oid"));
            if (!trim(val("hash_name")).empty()) m.hash_name = trim(val("hash_name"));
            if (row.count("crypto_providers"))   m.crypto_providers = split_pipe(trim(val("crypto_providers")));
            if (row.count("ekus"))               m.ekus = split_pipe(trim(val("ekus")));
            if (row.count("private_key_permissions")) m.private_key_permissions = trim(val("private_key_permissions"));
            // An EMPTY cell means "no overlap configured, derive one" — the same thing an
            // absent column means. Falling back to the struct default here rather than to
            // 0 is the whole point: 0 is a real policy ("renew at expiry").
            if (row.count("overlap_seconds"))    m.overlap_seconds = to_long(val("overlap_seconds"), m.overlap_seconds);
            if (row.count("enabled"))            m.enabled = to_bool(val("enabled"), true);
            out.push_back(std::move(m));
        } catch (const std::exception& e) {
            err = "line " + std::to_string(lineno) + ": " + e.what();
            return out;
        }
    }
    if (out.empty() && err.empty()) err = "no template rows found (need a header line + at least one row)";
    return out;
}

} // namespace pki
