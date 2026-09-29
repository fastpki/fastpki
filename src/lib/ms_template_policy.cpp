// The MS certificate template as an issuance decision.
//
// In the Microsoft world the template is what a client selects and what the CA enforces.
// Here it used to be neither: `template:use|<name>` gated only the console catalogue, and
// MS-WSTEP resolved a *profile* with the requested template hardcoded empty. A Windows
// client asking for `GenericComputer` got whatever shape a profile tiebreak picked, and
// the issued certificate then carried the template name it had never honoured.
//
// The rules below share `resolve_profile()`'s first half — no grant refuses, a named
// template applies only if permitted, one member is that member — and deliberately NOT its
// merge. A Windows client names the template it wants, and a template is a contract with
// that client about what the CA will issue; a certificate shaped by the union of several
// templates would match none of the contracts. So several templates with none named is a
// refusal here, where several profiles are merged.

#include "pki/ms_template.hpp"
#include "pki/db.hpp"
#include "pki/enrol_gate.hpp"
#include "pki/error.hpp"
#include "pki/log.hpp"

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <set>

namespace pki {
namespace {

constexpr const char* kOidCertTypeV1 = "1.3.6.1.4.1.311.20.2";   // name, as a BMPString
constexpr const char* kOidCertTypeV2 = "1.3.6.1.4.1.311.21.7";   // SEQUENCE { OID, ... }

// The requested extensions of a CSR, or nullptr. Caller frees.
STACK_OF(X509_EXTENSION)* req_exts(X509_REQ* csr) {
    return csr ? X509_REQ_get_extensions(csr) : nullptr;
}

// The DER octets of the extension with this dotted OID, empty if absent.
std::string ext_der(STACK_OF(X509_EXTENSION)* exts, const char* oid) {
    if (!exts) return {};
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>
        want(OBJ_txt2obj(oid, 1), &ASN1_OBJECT_free);
    if (!want) return {};
    for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION* e = sk_X509_EXTENSION_value(exts, i);
        if (OBJ_cmp(X509_EXTENSION_get_object(e), want.get()) != 0) continue;
        const ASN1_OCTET_STRING* v = X509_EXTENSION_get_data(e);
        if (!v) return {};
        return std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(v)),
                           static_cast<size_t>(ASN1_STRING_length(v)));
    }
    return {};
}

// V1: the extension value is a BMPString holding the template name. BMPString is UCS-2
// big-endian, so every ASCII character arrives as 0x00 <byte> — take the low octets. A
// template name outside ASCII is not something AD produces and is not guessed at here.
std::string decode_bmp_name(const std::string& der) {
    const unsigned char* p = reinterpret_cast<const unsigned char*>(der.data());
    std::unique_ptr<ASN1_STRING, decltype(&ASN1_STRING_free)>
        s(d2i_ASN1_BMPSTRING(nullptr, &p, static_cast<long>(der.size())), &ASN1_STRING_free);
    if (!s) { ERR_clear_error(); return {}; }
    const unsigned char* d = ASN1_STRING_get0_data(s.get());
    const int n = ASN1_STRING_length(s.get());
    std::string out;
    for (int i = 0; i + 1 < n; i += 2) {
        if (d[i] != 0x00) return {};              // non-ASCII: do not guess
        out.push_back(static_cast<char>(d[i + 1]));
    }
    return out;
}

// V2: SEQUENCE { templateID OBJECT IDENTIFIER, major INTEGER, minor INTEGER OPTIONAL }.
// Only the OID is needed — the revision numbers select a version of a template we do not
// version. Hand-walked rather than given an ASN1_ITEM: it is one tag and one field.
std::string decode_v2_oid(const std::string& der) {
    const unsigned char* p = reinterpret_cast<const unsigned char*>(der.data());
    long len = 0; int tag = 0, xclass = 0;
    if (ASN1_get_object(&p, &len, &tag, &xclass, static_cast<long>(der.size())) & 0x80) {
        ERR_clear_error(); return {};
    }
    if (tag != V_ASN1_SEQUENCE) return {};
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>
        obj(d2i_ASN1_OBJECT(nullptr, &p, len), &ASN1_OBJECT_free);
    if (!obj) { ERR_clear_error(); return {}; }
    char buf[128];
    if (OBJ_obj2txt(buf, sizeof buf, obj.get(), 1) <= 0) return {};
    return buf;
}

// The MS 16-bit KeyUsage bitmap, in the order Windows packs it: the first octet is the
// familiar X.509 KeyUsage bits (digitalSignature at 0x80 downwards), the second carries
// decipherOnly. Mapped to the OpenSSL config tokens `enforce_issuance_policy()` compares
// against, so the two halves of the rule speak one vocabulary.
std::vector<std::string> ku_from_ms_bitmap(unsigned ku) {
    struct Bit { unsigned mask; const char* name; };
    static const Bit kBits[] = {
        {0x8000u, "digitalSignature"}, {0x4000u, "nonRepudiation"},
        {0x2000u, "keyEncipherment"},  {0x1000u, "dataEncipherment"},
        {0x0800u, "keyAgreement"},     {0x0400u, "keyCertSign"},
        {0x0200u, "cRLSign"},          {0x0100u, "encipherOnly"},
        {0x0080u, "decipherOnly"},
    };
    std::vector<std::string> out;
    for (const auto& b : kBits)
        if (ku & b.mask) out.emplace_back(b.name);
    return out;
}

} // namespace

std::string csr_requested_template(X509_REQ* csr, const std::vector<MsTemplate>& known) {
    STACK_OF(X509_EXTENSION)* exts = req_exts(csr);
    if (!exts) return {};
    std::string name;

    if (std::string der = ext_der(exts, kOidCertTypeV1); !der.empty())
        name = decode_bmp_name(der);

    // V2 wins when both are present: it is the newer form, and a client that sends both
    // sends the same template twice. Resolving the OID against the catalogue is the only
    // way to get a name out of it, which is also the check that the OID means anything
    // here — an unknown OID leaves `name` empty and the caller refuses on the ambiguity
    // rather than silently issuing under a template nobody named.
    if (std::string der = ext_der(exts, kOidCertTypeV2); !der.empty()) {
        const std::string oid = decode_v2_oid(der);
        if (!oid.empty())
            for (const auto& t : known)
                if (t.oid == oid) { name = t.name; break; }
    }

    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    return name;
}

std::vector<std::string> templates_for_identity(Db& db, const ProfileIdentity& id,
                                                const std::vector<MsTemplate>& known) {
    if (id.username.empty() && id.role.empty()) return {};
    SubjectRoles sr;
    try {
        // ⚠️ id.groups, not just the username. A template granted to a group the caller is
        // in is otherwise invisible, which is the single defect shape this codebase has
        // repeated most often — and it fails OPEN-looking: the caller simply "has no
        // templates" and the refusal reads like a missing grant rather than a dropped one.
        sr = subject_roles(db, id.username, id.role, id.groups);
    } catch (const std::exception& e) {
        log::err(std::string("template permission lookup failed: ") + e.what());
        return {};                                   // fails closed: caller refuses
    }
    std::set<std::string> named;
    bool any_star = false;
    try {
        for (const auto& r : sr.known)
            for (const auto& g : db.list_role_grants(r.name)) {
                if (scope_kind(g.permission) != ScopeKind::Template) continue;
                // The issuance union, same shape as profiles: `template:use` alone.
                // `template:edit` gates the management page and confers no issuance.
                if (g.permission != "template:use") continue;
                if (g.scope == "*") any_star = true; else named.insert(g.scope);
            }
    } catch (const std::exception& e) {
        log::err(std::string("template grant lookup failed: ") + e.what());
        return {};
    }
    if (any_star)
        for (const auto& t : known) if (t.enabled) named.insert(t.name);

    // A grant may name a template that no longer exists — a rename, or a CSV import that
    // dropped a row. Keeping it in the union would let the resolver "succeed" on a name
    // with no row behind it, and the issuance shape would then come from nowhere.
    std::vector<std::string> out;
    for (const auto& n : named)
        for (const auto& t : known)
            if (t.name == n && t.enabled) { out.push_back(n); break; }
    return out;
}

MsTemplate resolve_ms_template(Db& db, const ProfileIdentity& id,
                               const std::string& requested,
                               const std::vector<MsTemplate>& known) {
    const std::vector<std::string> allowed = templates_for_identity(db, id, known);

    auto row = [&known](const std::string& n) -> MsTemplate {
        for (const auto& t : known) if (t.name == n) return t;
        throw Error(1, "policy: template '" + n + "' is permitted but has no row");
    };

    // No grant is a permanent, ordinary state, and the answer to "which template may it
    // use" is none. It is NOT a deployment that has yet to adopt the feature, and must not
    // be treated as one: "empty means allow what was asked for" is the exact shape that
    // handed out `master` and wildcards on the profile side before it was deleted.
    if (allowed.empty())
        throw Error(1, "policy: this identity holds no template permission, so no MS "
                       "certificate template applies. Grant one of its roles template:use "
                       "or template:edit on the template it should enrol under.");

    if (!requested.empty()) {
        if (std::find(allowed.begin(), allowed.end(), requested) != allowed.end())
            return row(requested);
        throw Error(1, "policy: MS template '" + requested +
                       "' is not permitted for this identity");
    }

    // No request. Exactly one permitted template is unambiguous; more than one is not,
    // because their key usages and validity differ and picking arbitrarily would make the
    // issued certificate depend on something nobody chose.
    if (allowed.size() == 1) return row(allowed.front());

    std::string list;
    for (const auto& n : allowed) { if (!list.empty()) list += ", "; list += n; }
    throw Error(1, "policy: this identity may enrol under several MS templates (" + list +
                   ") and the request named none, so which one applies is undefined. "
                   "Have the client select a template, or narrow the grants.");
}

CertProfile profile_from_ms_template(const MsTemplate& t) {
    CertProfile p;
    p.name = t.name;

    // allowed == default is the whole point. `enforce_issuance_policy()` already denies a
    // CSR that asks for a key usage or EKU outside `allowed_*`, so "if CSR does not match
    // the template, the request should be denied" needs no new code — it needs the
    // template's own fields put where the existing check reads them.
    const std::vector<std::string> ku = ku_from_ms_bitmap(t.key_usage);
    p.default_ku.assign(ku.begin(), ku.end());
    p.allowed_ku.insert(ku.begin(), ku.end());

    p.default_eku.assign(t.ekus.begin(), t.ekus.end());
    p.allowed_eku.insert(t.ekus.begin(), t.ekus.end());

    // ⚠️ THE TEMPLATE'S VALIDITY IS HONOURED, NOT CAPPED. This used to set only
    // max_validity_days, which can only SHORTEN cfg.cert_validity_days — so a template
    // stating one year issued 90 days wherever CERT_VALIDITY_DAYS was 90, and the console
    // showed one year while the certificate carried three months.
    //
    // These are Microsoft templates and they follow Microsoft's rules rather than a policy
    // of ours. A template exists to tell a client what this CA will issue; if we advertise
    // a validity and then issue a different one we have broken that contract, and broken it
    // invisibly — the client cannot see the difference and every other field is correct.
    // CERT_VALIDITY_DAYS is a default for requests that state nothing, and a template
    // states something. (A global setting could not express per-template lifetimes anyway,
    // so with more than one imported template no single value is right.)
    //
    // The cap is kept alongside the grant so the pair still reads as "never more than the
    // template"; being equal it is a no-op, and issuance clamps to the signer's own
    // notAfter regardless, which is physics rather than policy.
    p.validity_days     = t.validity_days;
    p.max_validity_days = t.validity_days;

    // Nothing in an AD template authorises a wildcard subject, and a Windows client does
    // not ask for one. Left false rather than inherited from anywhere.
    p.allow_wildcard = false;
    return p;
}

std::string ms_template_key_refusal(const MsTemplate& t, X509_REQ* csr) {
    if (t.min_key_size <= 0 || !csr) return {};
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>
        pk(X509_REQ_get_pubkey(csr), &EVP_PKEY_free);
    if (!pk) { ERR_clear_error(); return "the request carries no readable public key"; }
    const int bits = EVP_PKEY_get_bits(pk.get());
    if (bits <= 0) return {};       // a scheme with no meaningful bit count: nothing to compare
    if (bits >= t.min_key_size) return {};
    return "the key is " + std::to_string(bits) + " bits and template '" + t.name +
           "' requires at least " + std::to_string(t.min_key_size);
}

bool ms_template_enrollee_supplies_subject(const MsTemplate& t) {
    // ⚠️ THE NIL MARKER IS -1, AND -1 HAS THIS BIT SET. Testing the bit first would read a
    // template with no recorded name flags as "the requester may name anyone" — the exact
    // reading this function exists to prevent. Absent means the flags say nothing, and a
    // policy that says nothing does not grant.
    if (t.subject_name_flags == kMsNil) return false;
    // Cast before masking: the field holds a 32-bit mask in a signed int, and a directory
    // hands back top-bit-set values that arrive negative.
    constexpr uint32_t kEnrolleeSuppliesSubject = 0x00000001u;
    return (static_cast<uint32_t>(t.subject_name_flags) & kEnrolleeSuppliesSubject) != 0;
}

} // namespace pki
