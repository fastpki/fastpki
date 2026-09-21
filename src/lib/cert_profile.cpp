// Certificate policy profiles — see cert_profile.hpp.
#include "pki/cert_profile.hpp"
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/enrol_gate.hpp"   // subject_roles / scope_kind — ONE role resolution
#include "pki/error.hpp"
#include "pki/log.hpp"
#include "pki/x509.hpp"   // cert_sans / name_cn — read the ceiling off the cert
#include <algorithm>
#include <map>
#include <set>

#include "../../third_party/nlohmann/json.hpp"

#include <openssl/x509v3.h>

namespace pki {

using json = nlohmann::json;

namespace {

// KeyUsage bit positions (RFC 5280 §4.2.1.3) -> OpenSSL config token.
const char* const KU_NAMES[9] = {
    "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
    "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"
};

bool is_ca_only_ku(const std::string& k) { return k == "keyCertSign" || k == "cRLSign"; }

std::string join(const std::vector<std::string>& v, const std::string& sep) {
    std::string out;
    for (const auto& s : v) { if (!out.empty()) out += sep; out += s; }
    return out;
}

// The KU bit names a CSR requests (empty if no KeyUsage extension present).
std::vector<std::string> requested_ku(STACK_OF(X509_EXTENSION)* exts) {
    std::vector<std::string> out;
    if (!exts) return out;
    int idx = X509v3_get_ext_by_NID(exts, NID_key_usage, -1);
    if (idx < 0) return out;
    X509_EXTENSION* ext = X509v3_get_ext(exts, idx);
    if (!ext) return out;
    ASN1_BIT_STRING* ku = static_cast<ASN1_BIT_STRING*>(X509V3_EXT_d2i(ext));
    if (!ku) throw Error(1, "policy: malformed KeyUsage in CSR");
    for (int b = 0; b < 9; ++b)
        if (ASN1_BIT_STRING_get_bit(ku, b)) out.push_back(KU_NAMES[b]);
    ASN1_BIT_STRING_free(ku);
    return out;
}

// One KeyPurposeId has three spellings — the OpenSSL short name ("serverAuth"), the long
// name ("TLS Web Server Authentication") and the dotted OID ("1.3.6.1.5.5.7.3.1") — and
// every one of them arrives from somewhere: CSRs through requested_eku() give short names,
// the built-in MS templates are written with long ones, Active Directory's
// pKIExtendedKeyUsage gives OIDs, and a console-defined profile carries whatever was typed.
// OBJ_txt2nid accepts all three, so this reduces any of them to the short name.
//
// ⚠️ AN UNRECOGNISED TOKEN IS RETURNED UNCHANGED, not dropped. A private KeyPurposeId that
// OpenSSL has no NID for is a legitimate thing to put in a profile, and it still matches
// itself; turning it into an empty string here would silently widen the allow-list.
std::string canonical_eku(const std::string& tok) {
    if (tok.empty() || tok == "*") return tok;
    const int nid = OBJ_txt2nid(tok.c_str());
    if (nid == NID_undef) return tok;
    const char* sn = OBJ_nid2sn(nid);
    return sn ? std::string(sn) : tok;
}

// The EKU tokens a CSR requests (SN where known, else dotted OID).
std::vector<std::string> requested_eku(STACK_OF(X509_EXTENSION)* exts) {
    std::vector<std::string> out;
    if (!exts) return out;
    int idx = X509v3_get_ext_by_NID(exts, NID_ext_key_usage, -1);
    if (idx < 0) return out;
    X509_EXTENSION* ext = X509v3_get_ext(exts, idx);
    if (!ext) return out;
    EXTENDED_KEY_USAGE* eku = static_cast<EXTENDED_KEY_USAGE*>(X509V3_EXT_d2i(ext));
    if (!eku) throw Error(1, "policy: malformed ExtendedKeyUsage in CSR");
    for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i) {
        ASN1_OBJECT* o = sk_ASN1_OBJECT_value(eku, i);
        int nid = OBJ_obj2nid(o);
        if (nid != NID_undef && OBJ_nid2sn(nid)) {
            out.emplace_back(OBJ_nid2sn(nid));
        } else {
            char buf[128];
            OBJ_obj2txt(buf, sizeof buf, o, 1);   // numeric OID
            out.emplace_back(buf);
        }
    }
    sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
    return out;
}

// Trim surrounding whitespace from a token: a profile CSV typed as
// "digitalSignature, keyEncipherment" would otherwise yield " keyEncipherment",
// which OpenSSL's X509V3_EXT_conf_nid rejects as an "unknown bit string argument".
std::string trim_tok(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::set<std::string> to_set(const json& arr) {
    std::set<std::string> s;
    if (arr.is_array()) for (const auto& e : arr) if (e.is_string()) {
        std::string t = trim_tok(e.get<std::string>());
        if (!t.empty()) s.insert(t);
    }
    return s;
}
std::vector<std::string> to_vec(const json& arr) {
    std::vector<std::string> v;
    if (arr.is_array()) for (const auto& e : arr) if (e.is_string()) {
        std::string t = trim_tok(e.get<std::string>());
        if (!t.empty()) v.push_back(t);
    }
    return v;
}

} // namespace

// Defined below; shared by the config loader and the web Profiles editor.
static std::vector<CsrAttr> csr_attrs_from_json_array(const json& arr);

// Parse a JSON array of custom extensions: each element an object
// { "oid": <dotted>, "value": <generic-ext spec>, "critical": bool }. Entries
// without an OID are dropped. Shared by the config loader and the web editor.
static std::vector<CustomExt> custom_exts_from_json_array(const json& arr) {
    std::vector<CustomExt> out;
    if (!arr.is_array()) return out;
    for (const auto& e : arr) {
        if (!e.is_object()) continue;
        CustomExt x;
        x.oid      = trim_tok(e.value("oid", std::string()));
        x.value    = trim_tok(e.value("value", std::string()));
        x.critical = e.value("critical", false);
        if (!x.oid.empty()) out.push_back(std::move(x));
    }
    return out;
}
static json custom_exts_to_json(const std::vector<CustomExt>& v) {
    json arr = json::array();
    for (const auto& x : v) {
        json o; o["oid"] = x.oid; o["value"] = x.value; o["critical"] = x.critical;
        arr.push_back(std::move(o));
    }
    return arr;
}

// ⚠️ ONE definition of a built-in's code-defined shape, used both to install it and
// to recognise an untouched one when persisting. Two copies of these values would drift,
// and the failure would be silent: an unedited built-in serialised as "edited" and frozen
// into the database, or an edited one dropped on save.
static CertProfile builtin_profile_default(const std::string& name) {
    // A generous-but-safe allow-list for the END-ENTITY built-in: every common
    // end-entity KU, so honoring a CSR's request rarely denies — the value is in
    // *gating* genuinely incompatible requests and in letting custom profiles tighten
    // this. keyCertSign and cRLSign are excluded here; see ku_ca below.
    const std::set<std::string> ku_ee = {
        "digitalSignature", "nonRepudiation", "keyEncipherment",
        "dataEncipherment", "keyAgreement", "encipherOnly", "decipherOnly"
    };
    // Without keyCertSign and cRLSign, admin must not be able to issue CA
    // certificates. The two CA bits used to be refused for EVERY profile by a blanket
    // check in evaluate_profile_extensions() that ran BEFORE the allow-list was consulted
    // — so listing them here without also relaxing that check would have been inert.
    // Both halves moved together; the refusal is now "not permitted by this profile"
    // rather than "CA-only", which is the same sentence every other bit gets.
    const std::set<std::string> ku_ca = [&] {
        std::set<std::string> s = ku_ee;
        s.insert("keyCertSign");
        s.insert("cRLSign");
        return s;
    }();
    const std::set<std::string> eku_all = {
        "serverAuth", "clientAuth", "codeSigning", "emailProtection",
        // cmcRA (1.3.6.1.5.5.7.3.28) — RFC 9810 §8.6 wants it on a CMP RA signer, and
        // without it here the console could not issue a compliant RA certificate at all.
        // That failure is SILENT: an EKU no profile permits is dropped, so the
        // console would report success and hand back an RA certificate missing the one
        // purpose that makes it an RA certificate.
        //
        // Permitting it does not confer authority. FastPKI trusts an RA because the
        // certificate is PUBLISHED as cert_id "<CMP_RA_CERT_ID_PREFIX>-<ca_id>", which only an admin
        // can do — the EKU alone changes nothing here. And OCSPSigning, already permitted,
        // is the strictly more dangerous of the two: a delegated responder asserts
        // revocation status. Refusing cmcRA while allowing that was not a coherent line.
        "timeStamping", "OCSPSigning", "cmcRA", "ipsecIKE", "msSmartcardLogin",
        // ⚠️ A DOTTED STRING on purpose, not a short name. This is Microsoft's
        // Certificate Request Agent (CEP) EKU, required for the SCEP RA:
        // SCEP should carry CEP (1.3.6.1.4.1.311.20.2.1). OpenSSL 3.x has
        // no NID for it, so requested_eku() cannot map it to a name and it arrives here
        // in exactly this form. Matching is a plain set lookup with no OID
        // canonicalisation (see the refusal below), so the literal is what must be
        // listed — spell it any other way and the SCEP RA request 400s with
        // "ExtendedKeyUsage '1.3.6.1.4.1.311.20.2.1' is not permitted".
        "1.3.6.1.4.1.311.20.2.1"
    };
    // The specification for the two built-ins:
    //
    //   admin      every allowed attribute checked, including the ability to suppress
    //              default extensions, with a special custom extension 'any' or '*' among
    //              the allowed custom extensions — EST CSR attributes and default values
    //              left blank
    //   requester  as the previous standard profile, except keyEncipherment removed from
    //              the default KU, ServerAuth and ClientAuth removed from the default
    //              EKU, and URI added to the allowed SAN types
    //
    // Named fields, not a positional aggregate. The old form was `CertProfile{name, ku_all,
    // …, {}, {}, {}}` with three trailing braces nobody could name, and two comments in the
    // header existed only to warn that adding a field in the wrong place would silently
    // shift them. Adding `allowed_custom_extensions` is exactly that change, so the shape
    // goes rather than the warning being restated.
    const bool is_admin = (name == "admin");
    CertProfile p;
    p.name        = name;
    p.allowed_ku  = is_admin ? ku_ca : ku_ee;
    // "all EKUs should be allowed for admin profile." A wildcard, not a longer
    // list — any OID is a valid KeyPurposeId, so an enumeration can never mean "all",
    // and the next EKU somebody needs would be another ticket. `*` is already the
    // spelling this profile uses for allowed_custom_extensions, so it is one convention
    // rather than two. `requester` keeps the named list below.
    p.allowed_eku = is_admin ? std::set<std::string>{"*"} : eku_all;
    // "default values blank" for admin. `requester` keeps digitalSignature and loses
    // keyEncipherment; its default EKU goes empty (serverAuth and clientAuth both named).
    p.default_ku  = is_admin ? std::vector<std::string>{}
                             : std::vector<std::string>{"digitalSignature"};
    p.default_eku = {};
    // `admin` is the permissive one: wildcards allowed.
    p.allow_wildcard = is_admin;
    // "all allowed attributes checked" — every SAN type the console offers. `requester`
    // gains `uri` on top of the three it had.
    p.allowed_san_types = is_admin
        ? std::set<std::string>{"dns", "ip", "email", "uri", "othername"}
        : std::set<std::string>{"dns", "ip", "email", "uri"};
    p.max_validity_days = 0;
    p.csr_attrs = {};             // "leave est csr attributes blank"
    p.custom_extensions = {};     // what the profile STAMPS — neither built-in stamps any
    // …as against what a REQUESTER may carry in. `*` = any, on `admin` only.
    if (is_admin) p.allowed_custom_extensions = {"*"};
    // "ability to suppress default extensions" — the profile DELEGATES the AIA/CRLDP
    // choice to the request. It does not omit them by itself; the request still
    // has to ask, which is what lets one profile issue both ordinary certificates and an
    // OCSP responder.
    p.manage_aia   = is_admin;
    p.manage_crldp = is_admin;
    // ⚠️ `admin` ships with this TICKED, and that is what makes deleting the
    // capability check below safe. The subject rewrite (CN <- username) is now decided by
    // the PROFILE alone; if `admin` defaulted to false like `requester`, every
    // admin-issued certificate would come out CN=admin — including every server
    // certificate — the moment the capability clause went away.
    //
    // Read as policy it is also the right default: an admin picking the `admin` profile
    // is issuing FOR something else (a host, a service), so the CSR subject stands. An
    // admin who deliberately picks `requester` gets the identity binding, which is what
    // choosing that profile means.
    p.no_override_subject = is_admin;
    // Only `admin` may mint a CA, and only through the CAs page. Without
    // keyCertSign and cRLSign, admin must not be able to issue CA certificates — the KU
    // half landed in 7e84ab4; this is the basicConstraints half that followed.
    p.allow_ca      = is_admin;
    p.max_path_len  = -1;         // no depth cap on either built-in
    return p;
}

void ensure_builtin_profiles(Config& cfg) {
    // `if (!count(...))` is what lets an EDITED built-in, loaded from the database,
    // survive: the code default fills in only when nothing was persisted.
    for (const char* name : kBuiltinProfiles)
        if (!cfg.cert_profiles.count(name))
            cfg.cert_profiles[name] = builtin_profile_default(name);
}

void install_cert_profiles_json(Config& cfg, const std::string& s) {
    if (s.empty()) return;
    json j;
    try { j = json::parse(s); }
    catch (const std::exception& e) { throw Error(1, std::string("certificate profiles: bad JSON: ") + e.what()); }
    if (!j.is_object()) throw Error(1, "certificate profiles must be a JSON object of name -> definition");
    for (auto it = j.begin(); it != j.end(); ++it) {
        const json& p = it.value();
        CertProfile prof;
        prof.name = it.key();
        prof.allowed_ku  = to_set(p.value("allowed_ku", json::array()));
        prof.allowed_eku = to_set(p.value("allowed_eku", json::array()));
        prof.default_ku  = to_vec(p.value("default_ku", json::array()));
        prof.default_eku = to_vec(p.value("default_eku", json::array()));
        prof.allow_wildcard = p.value("allow_wildcard", false);
        if (p.contains("allowed_san_types"))
            prof.allowed_san_types = to_set(p.at("allowed_san_types"));
        prof.max_validity_days = p.value("max_validity_days", 0);
        // A profile that STATES a validity is honoured rather than bounded; absent (0)
        // leaves the cfg default in force. Round-tripped so an MS template stored as a
        // profile does not lose the one field that says what it will issue.
        prof.validity_days     = p.value("validity_days", 0);
        // EST /csrattrs: a list whose entries are a bare OID (string)
        // or an Attribute { "oid": <type>, "values": [<value-OID>, …] }.
        if (p.contains("csr_attrs"))
            prof.csr_attrs = csr_attrs_from_json_array(p.at("csr_attrs"));
        // Descriptive org label stamped into the SDA `role` attribute.
        // Arbitrary custom extensions + suppress-default-extension flags.
        if (p.contains("custom_extensions"))
            prof.custom_extensions = custom_exts_from_json_array(p.at("custom_extensions"));
        // Which CSR-supplied extensions may be carried through ("*" = any).
        if (p.contains("allowed_custom_extensions"))
            prof.allowed_custom_extensions = to_set(p.at("allowed_custom_extensions"));
        prof.manage_aia   = p.value("manage_aia", false);
        prof.manage_crldp = p.value("manage_crldp", false);
        prof.no_override_subject = p.value("no_override_subject", false);
        // basicConstraints.
        //
        // ⚠️ ABSENT is not FALSE for a BUILT-IN, and getting this wrong broke every
        // existing deployment in testing. `admin` ships allow_ca=true, but a stored
        // definition written before this field existed has no such key — and a plain
        // `value("allow_ca", false)` therefore turned the shipped default off for every
        // deployment that had ever saved a profile. CA creation then failed with "the
        // profile 'admin' does not permit basicConstraints CA:TRUE" on a profile nobody
        // had edited. ensure_builtin_profiles() cannot help: it fills in a whole profile
        // only when the NAME is missing, and the name was there.
        //
        // JSON does distinguish the two cases, so use it: a key that is PRESENT is
        // honoured whatever it says (an admin who turned CA:TRUE off keeps it off), and a
        // key that is ABSENT inherits the shipped default for that built-in. A profile
        // that is not a built-in has no shipped default, so absent stays false — the safe
        // direction for "may mint a CA".
        if (p.contains("allow_ca")) {
            prof.allow_ca = p.value("allow_ca", false);
        } else {
            prof.allow_ca = is_builtin_profile(prof.name) &&
                            builtin_profile_default(prof.name).allow_ca;
        }
        prof.max_path_len = p.value("max_path_len", -1);
        cfg.cert_profiles[prof.name] = std::move(prof);
    }
}

// ── EST /csrattrs DER encoding ─────────────────────────────────
namespace {
void csr_der_len(std::vector<unsigned char>& out, size_t n) {
    if (n < 0x80) { out.push_back(static_cast<unsigned char>(n)); return; }
    unsigned char tmp[8]; int i = 0;
    while (n) { tmp[i++] = static_cast<unsigned char>(n & 0xff); n >>= 8; }
    out.push_back(static_cast<unsigned char>(0x80 | i));
    for (int k = i - 1; k >= 0; --k) out.push_back(tmp[k]);
}
// Append the DER of a dotted OID (full 06-len-bytes TLV). Returns false + logs
// if the OID doesn't parse (skipped by the caller).
bool csr_oid_tlv(const std::string& dotted, std::vector<unsigned char>& out) {
    ASN1_OBJECT* o = OBJ_txt2obj(dotted.c_str(), 1);   // 1 = dotted-decimal only
    if (!o) { log::err("csrattrs: bad OID '" + dotted + "' — skipped"); return false; }
    int len = i2d_ASN1_OBJECT(o, nullptr);
    bool ok = false;
    if (len > 0) {
        size_t off = out.size(); out.resize(off + static_cast<size_t>(len));
        unsigned char* p = out.data() + off; i2d_ASN1_OBJECT(o, &p); ok = true;
    }
    ASN1_OBJECT_free(o);
    return ok;
}
} // namespace

std::vector<unsigned char> build_csrattrs_der(const std::vector<CsrAttr>& attrs) {
    std::vector<unsigned char> body;   // concatenated AttrOrOID elements
    for (const auto& a : attrs) {
        if (a.values.empty()) {
            csr_oid_tlv(a.oid, body);          // bare OID alternative
            continue;
        }
        // Attribute ::= SEQUENCE { type OID, values SET OF OID }
        std::vector<unsigned char> type_tlv;
        if (!csr_oid_tlv(a.oid, type_tlv)) continue;
        std::vector<std::vector<unsigned char>> vtlvs;
        for (const auto& v : a.values) {
            std::vector<unsigned char> t;
            if (csr_oid_tlv(v, t)) vtlvs.push_back(std::move(t));
        }
        if (vtlvs.empty()) { body.insert(body.end(), type_tlv.begin(), type_tlv.end()); continue; }
        std::sort(vtlvs.begin(), vtlvs.end());  // DER SET OF: sort by encoding
        std::vector<unsigned char> setbody;
        for (auto& t : vtlvs) setbody.insert(setbody.end(), t.begin(), t.end());
        std::vector<unsigned char> setv{0x31}; csr_der_len(setv, setbody.size());
        setv.insert(setv.end(), setbody.begin(), setbody.end());
        std::vector<unsigned char> seqbody = type_tlv;
        seqbody.insert(seqbody.end(), setv.begin(), setv.end());
        body.push_back(0x30); csr_der_len(body, seqbody.size());
        body.insert(body.end(), seqbody.begin(), seqbody.end());
    }
    if (body.empty()) return {};
    std::vector<unsigned char> out{0x30}; csr_der_len(out, body.size());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

std::vector<CsrAttr> csr_attrs_from_oid_list(const std::string& csv) {
    std::vector<CsrAttr> out; std::string tok;
    auto flush = [&] {
        size_t a = tok.find_first_not_of(" \t"); size_t b = tok.find_last_not_of(" \t");
        if (a != std::string::npos) out.push_back(CsrAttr{tok.substr(a, b - a + 1), {}});
        tok.clear();
    };
    for (char c : csv) { if (c == ',' || c == ' ' || c == '\t') flush(); else tok += c; }
    flush();
    return out;
}

// Parse a JSON array of RFC 7030 AttrOrOID (bare-OID string | {oid, values:[…]})
// into CsrAttr list. Shared by the config loader and the web Profiles editor.
static std::vector<CsrAttr> csr_attrs_from_json_array(const json& arr) {
    std::vector<CsrAttr> out;
    if (!arr.is_array()) return out;
    for (const auto& e : arr) {
        CsrAttr a;
        if (e.is_string()) a.oid = e.get<std::string>();
        else if (e.is_object()) {
            a.oid = e.value("oid", std::string());
            if (e.contains("values") && e.at("values").is_array())
                for (const auto& v : e.at("values"))
                    if (v.is_string()) a.values.push_back(v.get<std::string>());
        }
        if (!a.oid.empty()) out.push_back(std::move(a));
    }
    return out;
}
std::vector<CsrAttr> csr_attrs_from_json_str(const std::string& s) {
    try { return csr_attrs_from_json_array(json::parse(s)); }
    catch (...) { return {}; }
}
std::vector<CustomExt> custom_exts_from_json_str(const std::string& s) {
    try { return custom_exts_from_json_array(json::parse(s)); }
    catch (...) { return {}; }
}

const CertProfile& resolve_cert_profile(const Config& cfg, const std::string& name) {
    auto it = cfg.cert_profiles.find(name);
    if (it != cfg.cert_profiles.end()) return it->second;
    auto def_it = cfg.cert_profiles.find(kDefaultProfile);
    if (def_it != cfg.cert_profiles.end()) return def_it->second;
    // Last-resort default (e.g. a Config not built via load()): conservative, and named
    // after the built-in it stands in for so a decoded cert cannot be traced to a profile
    // name that does not exist.
    static const CertProfile fallback = [] {
        CertProfile f;
        f.name = kDefaultProfile;
        f.allowed_ku  = {"digitalSignature", "nonRepudiation", "keyEncipherment",
                         "dataEncipherment", "keyAgreement"};
        f.allowed_eku = {"serverAuth", "clientAuth", "codeSigning", "emailProtection"};
        f.default_ku  = {"digitalSignature"};
        f.allowed_san_types = {"dns", "ip", "email", "uri"};
        return f;
    }();
    return fallback;
}

std::string cert_profiles_json(const Config& cfg, const std::set<std::string>* only) {
    json arr = json::array();
    // Filtered to what this caller may manage, when the caller is confined.
    for (const auto& [name, p] : cfg.cert_profiles) {
        if (only && !only->count(name)) continue;
        json j;
        j["name"]              = name;
        j["builtin"]           = is_builtin_profile(name);
        j["allowed_ku"]        = std::vector<std::string>(p.allowed_ku.begin(), p.allowed_ku.end());
        j["allowed_eku"]       = std::vector<std::string>(p.allowed_eku.begin(), p.allowed_eku.end());
        j["default_ku"]        = p.default_ku;
        j["default_eku"]       = p.default_eku;
        j["allow_wildcard"]    = p.allow_wildcard;
        j["allowed_san_types"] = std::vector<std::string>(p.allowed_san_types.begin(), p.allowed_san_types.end());
        j["max_validity_days"] = p.max_validity_days;
        j["validity_days"]     = p.validity_days;
        { json ca = json::array();               // csr_attrs (string | {oid,values})
          for (const auto& a : p.csr_attrs) {
              if (a.values.empty()) ca.push_back(a.oid);
              else { json o; o["oid"] = a.oid; o["values"] = a.values; ca.push_back(std::move(o)); } }
          j["csr_attrs"] = std::move(ca); }   // SDA org label
        j["custom_extensions"] = custom_exts_to_json(p.custom_extensions);
        j["allowed_custom_extensions"] = std::vector<std::string>(
            p.allowed_custom_extensions.begin(), p.allowed_custom_extensions.end());
        j["manage_aia"]        = p.manage_aia;
        j["manage_crldp"]      = p.manage_crldp;
        j["no_override_subject"] = p.no_override_subject;
        j["allow_ca"]          = p.allow_ca;        // basicConstraints
        j["max_path_len"]      = p.max_path_len;
        arr.push_back(std::move(j));
    }
    return arr.dump();
}

bool is_builtin_profile(const std::string& name) {
    for (const char* b : kBuiltinProfiles) if (name == b) return true;
    return false;
}

// One encoder, used both to persist a profile and to compare a built-in against its code
// default. A second hand-written comparison would drift from the encoder and mis-classify.
static json profile_to_json(const CertProfile& p) {
        json j;
        j["allowed_ku"]        = std::vector<std::string>(p.allowed_ku.begin(), p.allowed_ku.end());
        j["allowed_eku"]       = std::vector<std::string>(p.allowed_eku.begin(), p.allowed_eku.end());
        j["default_ku"]        = p.default_ku;
        j["default_eku"]       = p.default_eku;
        j["allow_wildcard"]    = p.allow_wildcard;
        j["allowed_san_types"] = std::vector<std::string>(p.allowed_san_types.begin(), p.allowed_san_types.end());
        j["max_validity_days"] = p.max_validity_days;
        j["validity_days"]     = p.validity_days;
        { json ca = json::array();               // csr_attrs (string | {oid,values})
          for (const auto& a : p.csr_attrs) {
              if (a.values.empty()) ca.push_back(a.oid);
              else { json o; o["oid"] = a.oid; o["values"] = a.values; ca.push_back(std::move(o)); } }
          j["csr_attrs"] = std::move(ca); }   // SDA org label
        j["custom_extensions"] = custom_exts_to_json(p.custom_extensions);
        j["allowed_custom_extensions"] = std::vector<std::string>(
            p.allowed_custom_extensions.begin(), p.allowed_custom_extensions.end());
        j["manage_aia"]        = p.manage_aia;
        j["manage_crldp"]      = p.manage_crldp;
        j["no_override_subject"] = p.no_override_subject;
        j["allow_ca"]          = p.allow_ca;        // basicConstraints
        j["max_path_len"]      = p.max_path_len;
        return j;
}

void load_cert_profiles(Config& cfg, Db& db) {
    const auto rows = db.list_cert_profiles();   // throws: the caller decides what an unreadable table means
    cfg.cert_profiles.clear();
    for (const auto& [name, definition] : rows) {
        // One row at a time, so a single malformed definition costs that profile and not
        // every other one — a whole-catalogue failure is what turned a bad config row into
        // "the console serves built-in defaults as the live configuration".
        try {
            json one = json::object();
            one[name] = json::parse(definition);
            install_cert_profiles_json(cfg, one.dump());
        } catch (const std::exception& e) {
            log::err("certificate profile '" + name + "' is stored malformed and was not loaded: " +
                     e.what());
        }
    }
    ensure_builtin_profiles(cfg);
}

void store_cert_profile(Db& db, const CertProfile& p) {
    // An UNTOUCHED built-in is not stored: writing it would freeze today's code default into
    // the database, and a later improvement to that default would never reach this
    // deployment. ensure_builtin_profiles() fills a built-in in only when no row exists, so
    // deleting the row is how an edit back to the default hands it back to the code.
    const json j = profile_to_json(p);
    if (is_builtin_profile(p.name) && j == profile_to_json(builtin_profile_default(p.name))) {
        db.delete_cert_profile(p.name);
        return;
    }
    db.upsert_cert_profile(p.name, j.dump());
}

std::string stored_cert_profiles_json(Db& db) {
    json obj = json::object();
    for (const auto& [name, definition] : db.list_cert_profiles()) {
        try { obj[name] = json::parse(definition); }
        catch (const std::exception&) { /* not exportable; load_cert_profiles logs it */ }
    }
    return obj.dump();
}

// THE UNION. A profile is a RESOURCE a role holds `profile:use`/`profile:edit`
// on — the agreed design — not something a selector table picks for you.
//
// ⚠️ The roles come from pki::subject_roles(), the SAME resolution may_enrol() uses. That
// function has two inert cases that are not bugs (a deployment with no `roles` rows at all;
// a subject holding only an ISSUANCE role like `standard`), and a second resolver that
// reproduced four of those five facts would hand profiles to subjects the permission gate
// does not recognise — the second-gate shape. Nothing here reconstructs it.
//
// Sorted by name so the answer is stable: the console renders this list and two calls that
// disagreed on order would look like a change nobody made.
std::vector<std::string> profiles_for_identity(Db& db, const ProfileIdentity& id) {
    if (id.username.empty() && id.role.empty()) return {};
    SubjectRoles sr;
    try {
        sr = subject_roles(db, id.username, id.role, id.groups);
    } catch (const std::exception& e) {
        // Fails CLOSED, and since this slice that is a REFUSAL, not a downgrade. The
        // sentence here used to end "...and resolve_profile() then falls back to the CA
        // default rather than refusing outright, so a database blip does not stop
        // issuance" — true when it was written, and describing the fallback this slice
        // deletes. An empty union now throws, so a lookup failure stops issuance for that
        // request, which is the right answer to "we cannot tell what this subject may do".
        log::err(std::string("profile permission lookup failed: ") + e.what());
        return {};
    }
    std::set<std::string> named;      // every profile named by a scope
    bool any_star = false;            // some grant says `*`: every profile
    try {
        for (const auto& r : sr.known)
            for (const auto& g : db.list_role_grants(r.name)) {
                if (scope_kind(g.permission) != ScopeKind::Profile) continue;
                // The ISSUANCE union. `profile:use` is the whole of it now: `profile:edit`
                // meant "use AND edit" and is decomposed into the two atomic verbs, so a
                // holder of the old rw carries `use` and appears here exactly as before.
                // `profile:edit` is deliberately NOT counted — editing a profile is not
                // entitlement to issue under it, which is the separation profile:edit
                // was reintroduced to express.
                if (g.permission != "profile:use") continue;
                if (g.scope == "*") any_star = true; else named.insert(g.scope);
            }
    } catch (const std::exception& e) {
        log::err(std::string("profile grant lookup failed: ") + e.what());
        return {};
    }
    if (any_star) {
        // `*` means every profile that EXISTS, so it has to be expanded against the
        // catalogue rather than returned as a literal — the console offers this list and a
        // caller comparing against "*" would match nothing.
        Config c;
        try { load_cert_profiles(c, db); } catch (...) { ensure_builtin_profiles(c); }
        for (const auto& [name, _] : c.cert_profiles) named.insert(name);
    }
    return std::vector<std::string>(named.begin(), named.end());   // std::set => sorted
}

bool identity_allows_profile(Db& db, const ProfileIdentity& id,
                             const std::string& profile_name) {
    if (profile_name.empty()) return false;
    // Same list the console picker offers, so what it shows and what issuance accepts
    // cannot disagree. Fails CLOSED via profiles_for_identity.
    auto v = profiles_for_identity(db, id);
    return std::find(v.begin(), v.end(), profile_name) != v.end();
}

namespace {

bool same_exts(const std::vector<CustomExt>& a, const std::vector<CustomExt>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (a[i].oid != b[i].oid || a[i].value != b[i].value || a[i].critical != b[i].critical)
            return false;
    return true;
}

// Several profiles as one: allowances unioned, defaults agreed or decided by `primary`
// (the member named after the subject's primary role, or null), else left undecided.
CertProfile merge_profiles(const std::vector<const CertProfile*>& members,
                           const CertProfile* primary) {
    CertProfile m;
    m.allowed_san_types.clear();   // the struct's own default would leak into the union
    for (const auto* p : members) {
        if (!m.name.empty()) m.name += "+";
        m.name += p->name;
        m.allowed_ku.insert(p->allowed_ku.begin(), p->allowed_ku.end());
        m.allowed_eku.insert(p->allowed_eku.begin(), p->allowed_eku.end());
        m.allowed_san_types.insert(p->allowed_san_types.begin(), p->allowed_san_types.end());
        m.allowed_custom_extensions.insert(p->allowed_custom_extensions.begin(),
                                           p->allowed_custom_extensions.end());
        m.allow_wildcard      = m.allow_wildcard      || p->allow_wildcard;
        m.manage_aia          = m.manage_aia          || p->manage_aia;
        m.manage_crldp        = m.manage_crldp        || p->manage_crldp;
        m.no_override_subject = m.no_override_subject || p->no_override_subject;
        m.allow_ca            = m.allow_ca            || p->allow_ca;
    }
    // A cap of 0 (validity) or -1 (path length) means none, and none is the widest.
    const auto widest = [&](int CertProfile::*f, int none) {
        int w = members.front()->*f;
        for (const auto* p : members) {
            if (p->*f == none || w == none) { w = none; continue; }
            w = std::max(w, p->*f);
        }
        return w;
    };
    m.max_validity_days = widest(&CertProfile::max_validity_days, 0);
    m.max_path_len      = widest(&CertProfile::max_path_len, -1);

    // A default: every member's value when they agree, else the primary role's profile's,
    // else undecided under `label`.
    const auto decide = [&](const char* label, auto get, auto same, auto set) {
        const auto& first = get(*members.front());
        bool agree = true;
        for (const auto* p : members) agree = agree && same(get(*p), first);
        if (agree)        set(first);
        else if (primary) set(get(*primary));
        else              m.undecided.insert(label);
    };
    const auto sorted = [](std::vector<std::string> v) { std::sort(v.begin(), v.end()); return v; };
    decide("default key usage",
           [](const CertProfile& p) -> const std::vector<std::string>& { return p.default_ku; },
           [&](const auto& a, const auto& b) { return sorted(a) == sorted(b); },
           [&](const auto& v) { m.default_ku = v; });
    decide("default extended key usage",
           [](const CertProfile& p) -> const std::vector<std::string>& { return p.default_eku; },
           [&](const auto& a, const auto& b) { return sorted(a) == sorted(b); },
           [&](const auto& v) { m.default_eku = v; });
    decide("validity",
           [](const CertProfile& p) -> const int& { return p.validity_days; },
           [](int a, int b) { return a == b; },
           [&](int v) { m.validity_days = v; });
    decide("stamped custom extensions",
           [](const CertProfile& p) -> const std::vector<CustomExt>& { return p.custom_extensions; },
           same_exts,
           [&](const auto& v) { m.custom_extensions = v; });
    // EST's csrattrs is a HINT served before a request exists, so a disagreement is no
    // reason to refuse anything: it is simply not offered.
    {
        bool agree = true;
        for (const auto* p : members)
            agree = agree && p->csr_attrs.size() == members.front()->csr_attrs.size() &&
                    std::equal(p->csr_attrs.begin(), p->csr_attrs.end(),
                               members.front()->csr_attrs.begin(),
                               [](const CsrAttr& a, const CsrAttr& b) {
                                   return a.oid == b.oid && a.values == b.values; });
        if (agree)        m.csr_attrs = members.front()->csr_attrs;
        else if (primary) m.csr_attrs = primary->csr_attrs;
    }
    return m;
}

}  // namespace

EffectiveProfile resolve_profile(Db& db, const Config& cfg, const ProfileIdentity& id,
                                 const std::string& requested) {
    const std::vector<std::string> allowed = profiles_for_identity(db, id);

    // 0. No grant, no profile — see the header for why there is no fallback.
    if (allowed.empty())
        throw Error(1, "policy: this identity holds no profile permission, so no "
                       "certificate profile applies. Grant one of its roles profile:use "
                       "on the profile it should use.");

    const auto defined = [&cfg](const std::string& n) -> const CertProfile& {
        auto it = cfg.cert_profiles.find(n);
        if (it == cfg.cert_profiles.end())
            throw Error(1, "policy: profile '" + n + "' is granted but not defined on this node");
        return it->second;
    };

    // 1. A named profile applies alone, and only if the subject may use it.
    if (!requested.empty()) {
        if (std::find(allowed.begin(), allowed.end(), requested) == allowed.end())
            throw Error(1, "policy: profile '" + requested +
                           "' is not permitted for this identity");
        return {requested, defined(requested)};
    }

    // 2. One member is that member.
    if (allowed.size() == 1) return {allowed.front(), defined(allowed.front())};

    // 3. Several: the merge. The primary role is the one the subject authenticated with;
    //    CMP and ACME authenticate without one, so it is the web_users row's.
    std::string primary = id.role;
    if (primary.empty() && !id.username.empty()) {
        try { if (auto u = db.get_web_user(id.username)) primary = u->role; }
        catch (...) { /* no row: no primary role, so no tiebreak — undecided instead */ }
    }
    std::vector<const CertProfile*> members;
    const CertProfile* prim = nullptr;
    for (const auto& n : allowed) {
        members.push_back(&defined(n));
        if (n == primary) prim = members.back();
    }
    CertProfile merged = merge_profiles(members, prim);
    return {merged.name, std::move(merged)};
}


ProfileExtensions evaluate_profile_extensions(const CertProfile& profile,
                                              STACK_OF(X509_EXTENSION)* req_exts) {
    // ⚠️ A MERGED PROFILE'S UNDECIDED DEFAULTS, checked before anything uses a default. Here
    // because both the issuance path and the console's pre-flight pass through, so a request
    // cannot be accepted by one and refused by the other. Refused only when the request
    // relies on the default: a CSR that asks for its key usages has chosen them.
    if (!profile.undecided.empty()) {
        std::vector<std::string> relied;
        if (profile.undecided.count("default key usage") && requested_ku(req_exts).empty())
            relied.push_back("key usage");
        if (profile.undecided.count("default extended key usage") && requested_eku(req_exts).empty())
            relied.push_back("extended key usage");
        const size_t requestable = relied.size();
        // No request carries these, so a request always relies on the profiles for them.
        for (const char* d : {"validity", "stamped custom extensions"})
            if (profile.undecided.count(d)) relied.push_back(d);
        if (!relied.empty()) {
            std::string list;
            for (const auto& r : relied) { if (!list.empty()) list += ", "; list += r; }
            throw Error(1, "policy: the profiles this identity holds (" + profile.name +
                           ") set a different " + list + ", none of them is named after its "
                           "role, and the request does not decide it. " +
                           (requestable == relied.size()
                              ? "Ask for the key usages in the request, or name one of the profiles."
                              : "Name one of the profiles, or make them agree."));
        }
    }
    // KeyUsage: honor the CSR's request within the allow-list, else default.
    std::vector<std::string> ku = requested_ku(req_exts);
    if (ku.empty()) ku = profile.default_ku;
    // Normalize tokens: any profile source (incl. the web CSV form)
    // may leave stray whitespace that OpenSSL rejects as an unknown KU bit.
    for (auto& k : ku) k = trim_tok(k);
    ku.erase(std::remove(ku.begin(), ku.end(), std::string()), ku.end());
    // ⚠️ DROP, DO NOT DENY. Dropping the not-allowed attribute is the confirmed
    // behaviour — a bit the profile does not permit is removed from the request rather
    // than refusing the whole thing. This replaced a throw; a later change moved the
    // CA-only bits under `allowed_ku` so there is one rule for every bit.
    //
    // THE ONE EXCEPTION IS AN EMPTY RESULT, and it is his too: "we should not issue a cert
    // without any key usage because it would violate the RFC5280 4.2.1.3 'When the keyUsage
    // extension appears in a certificate, at least one of the bits MUST be set to 1'. ...
    // So in cases like this, the request should be denied." Dropping every bit would
    // otherwise silently widen the certificate — no KeyUsage means no restriction at all —
    // which is the opposite of what the profile asked for.
    std::vector<std::string> ku_dropped;
    {
        std::vector<std::string> kept;
        for (const auto& k : ku) {
            if (profile.allowed_ku.count(k)) kept.push_back(k);
            else                             ku_dropped.push_back(k);
        }
        if (kept.empty() && !ku.empty())
            throw Error(1, "policy: profile '" + profile.name + "' permits none of the requested "
                           "KeyUsage bits (" + join(ku, ",") + "), and a certificate cannot carry an "
                           "EMPTY KeyUsage (RFC 5280 4.2.1.3), so the request is refused rather than "
                           "issued with no key-usage restriction at all" +
                           (std::any_of(ku.begin(), ku.end(), is_ca_only_ku)
                              ? ". One of them is a CA-only bit: grant it on the profile if this "
                                "profile really should issue CA certificates." : ""));
        ku = kept;
    }

    // ExtendedKeyUsage: same honor-within-allow-list.
    std::vector<std::string> eku = requested_eku(req_exts);
    if (eku.empty()) eku = profile.default_eku;
    for (auto& e : eku) e = trim_tok(e);
    eku.erase(std::remove(eku.begin(), eku.end(), std::string()), eku.end());
    // `*` in allowed_eku means every KeyPurposeId, which is what the `admin`
    // built-in now carries. Same spelling and same meaning as allowed_custom_extensions.
    const bool any_eku = profile.allowed_eku.count("*") > 0;
    // Same drop, DIFFERENT empty case — also his: "For EKU a special case when any is
    // allowed is emphasized by anyExtendedKeyUsage but no EKU extension may be rejected by
    // an application. So if no EKU in CSR matches profiles union, we might actually issue a
    // cert without EKU extension". An absent EKU is not a widening the way an absent
    // KeyUsage is: it says nothing rather than "everything", and a relying application may
    // refuse it. So an empty result omits the extension instead of refusing the request.
    // ⚠️ COMPARE KeyPurposeIds, NOT SPELLINGS. "serverAuth", "TLS Web Server
    // Authentication" and "1.3.6.1.5.5.7.3.1" are one purpose with three names, and this
    // list and the profile's reach us from sources that disagree about which to use:
    // requested_eku() emits OpenSSL SHORT names, the built-in MS templates are written
    // with LONG ones (src/lib/ms_template.cpp), AD hands us dotted OIDs
    // (pKIExtendedKeyUsage), and a DB profile carries whatever was typed into the console.
    // A std::set lookup on the raw string made every one of those a mismatch: a Windows
    // CSR carrying exactly the EKU the template told it to request had it dropped, and the
    // certificate was issued with no EKU extension at all — the template announcing a
    // critical restriction the certificate then did not carry.
    {
        std::set<std::string> allowed;
        for (const auto& a : profile.allowed_eku) allowed.insert(canonical_eku(a));
        std::vector<std::string> kept;
        for (const auto& e : eku) {
            const std::string c = canonical_eku(e);
            // The canonical form is what is kept, so the extension text handed to
            // OpenSSL is one spelling regardless of which one arrived.
            if (any_eku || allowed.count(c)) kept.push_back(c);
        }
        eku = kept;
    }

    // RFC 5280 §4.2.1.12 — enforce EKU→KU compatibility. Each EKU purpose
    // requires specific KU bits; if a bit is missing, add it (audit-trail only,
    // since the client-side syncGenKu should have set it already).
    static const std::map<std::string, std::vector<std::string>> eku_ku_required = {
        {"serverAuth",      {"digitalSignature"}},
        {"clientAuth",      {"digitalSignature"}},
        {"codeSigning",     {"digitalSignature"}},
        {"emailProtection", {"digitalSignature"}},
        {"timeStamping",    {"digitalSignature"}},
        // ⚠️ WAS "ocspSigning", which this map could never match. Tokens reach here
        // normalised through OBJ_nid2sn (line ~64), and OpenSSL's short name is
        // "OCSPSigning" — measured: `-addext extendedKeyUsage=ocspSigning` is REJECTED by
        // OpenSSL outright. So the entry was dead, and the KU implication it exists to
        // apply never fired. Harmless so far only because the client side sets the bit.
        {"OCSPSigning",     {"digitalSignature"}},
        {"cmcRA",           {"digitalSignature"}},
        // Same OID as the allow-list entry above: an enrolment agent signs requests on
        // another entity's behalf, so digitalSignature is implied. Belt-and-braces for
        // the paste-a-CSR paths — the console preset already checks the box.
        {"1.3.6.1.4.1.311.20.2.1", {"digitalSignature"}}
    };
    std::set<std::string> ku_set(ku.begin(), ku.end());
    for (const auto& e : eku) {
        auto it = eku_ku_required.find(e);
        if (it == eku_ku_required.end()) continue;
        for (const auto& req : it->second) {
            if (!ku_set.count(req)) {
                // ⚠️ Only a bit the profile actually permits. This implication exists to
                // ADD a bit the client forgot; adding one the profile forbids would put
                // back through the back door exactly what the drop above just took out.
                // A profile that allows an EKU while forbidding the KU it implies is
                // internally inconsistent — an admin error, not something to paper over —
                // so the purpose is kept and the bit is not invented.
                if (!profile.allowed_ku.count(req)) continue;
                // Bit missing — add it (this is a safety net; the browser should
                // have auto-checked it, but paste-a-CSR paths bypass the client).
                ku.push_back(req);
                ku_set.insert(req);
            }
        }
    }

    ProfileExtensions out;
    if (!ku.empty()) out.key_usage = "critical," + join(ku, ",");
    out.ext_key_usage = join(eku, ",");
    return out;
}


// Read the policy off the certificate being renewed. See cert_profile.hpp for
// the ruling and why none of the stored-profile options worked.
CertProfile profile_from_cert(X509* held) {
    CertProfile p;
    p.name = "self-renewal";
    if (!held) return p;

    // ---- KU: exactly the bits the held certificate asserts -------------------------
    // ⚠️ Both allowed_ku AND default_ku. `allowed` is the ceiling for a CSR that asks;
    // `default` is what a CSR that asks for nothing receives. Setting only the first
    // would silently drop key usage from a device whose CSR carries no KU extension —
    // a renewal that quietly issues a WEAKER certificate than the one it replaces, which
    // is the shape that never gets noticed until something stops working.
    if (auto* ku = static_cast<ASN1_BIT_STRING*>(
            X509_get_ext_d2i(held, NID_key_usage, nullptr, nullptr))) {
        static const struct { int bit; const char* name; } kKu[] = {
            {0, "digitalSignature"}, {1, "nonRepudiation"}, {2, "keyEncipherment"},
            {3, "dataEncipherment"}, {4, "keyAgreement"},   {5, "keyCertSign"},
            {6, "cRLSign"},          {7, "encipherOnly"},   {8, "decipherOnly"},
        };
        for (const auto& e : kKu)
            if (ASN1_BIT_STRING_get_bit(ku, e.bit)) {
                p.allowed_ku.insert(e.name);
                p.default_ku.push_back(e.name);
            }
        ASN1_BIT_STRING_free(ku);
    }

    // ---- EKU: exactly the purposes it already has ----------------------------------
    if (auto* eku = static_cast<EXTENDED_KEY_USAGE*>(
            X509_get_ext_d2i(held, NID_ext_key_usage, nullptr, nullptr))) {
        for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i) {
            char buf[128];
            if (OBJ_obj2txt(buf, sizeof buf, sk_ASN1_OBJECT_value(eku, i), 0) > 0) {
                p.allowed_eku.insert(buf);
                p.default_eku.emplace_back(buf);
            }
        }
        EXTENDED_KEY_USAGE_free(eku);
    }

    // ---- SAN types and wildcards: only what is already there ------------------------
    // ⚠️ STARTS EMPTY. CertProfile's own default is {dns, ip, email}, so leaving this
    // alone would let a device holding a DNS-only certificate renew into one carrying an
    // email or IP name — widening, from a profile whose whole purpose is a ceiling.
    p.allowed_san_types.clear();
    for (const auto& s : cert_sans(held)) {
        if      (s.rfind("DNS:",   0) == 0) p.allowed_san_types.insert("dns");
        else if (s.rfind("IP:",    0) == 0) p.allowed_san_types.insert("ip");
        else if (s.rfind("EMAIL:", 0) == 0) p.allowed_san_types.insert("email");
        else if (s.rfind("URI:",   0) == 0) p.allowed_san_types.insert("uri");
        if (s.find(":*.") != std::string::npos) p.allow_wildcard = true;
    }
    if (name_cn(X509_get_subject_name(held)).rfind("*.", 0) == 0) p.allow_wildcard = true;

    // ---- Validity: "should not be longer than existing one" -------------------------
    // The held certificate's OWN span, not its remaining life. A device renewing on its
    // last day would otherwise get a one-day certificate and be locked into an ever
    // shortening cycle. `max_validity_days` is a cap, so a CA configured for less still
    // wins; this only stops a renewal being LONGER than what it replaces.
    if (const ASN1_TIME* nb = X509_get0_notBefore(held)) {
        if (const ASN1_TIME* na = X509_get0_notAfter(held)) {
            int days = 0, secs = 0;
            if (ASN1_TIME_diff(&days, &secs, nb, na) && days > 0) p.max_validity_days = days;
        }
    }

    // ---- Subject: already proved identical, so never rewrite it ---------------------
    // renewal_mismatch() has compared the CSR subject to this certificate's with
    // X509_NAME_cmp before we get here. Letting the identity-subject rule fire as well
    // would rewrite the CN to the AUTHENTICATED USERNAME — which for a device is the
    // machine account, not the hostname it holds a certificate for.
    p.no_override_subject = true;

    // Nothing is stamped and nothing extra may be carried in: `custom_extensions` and
    // `allowed_custom_extensions` both stay empty. A renewal is not the moment to acquire
    // an extension the certificate did not have.
    return p;
}

} // namespace pki
