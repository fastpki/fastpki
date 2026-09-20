// fastpki-ms — MS-XCEP (certificate enrollment policy) + MS-WSTEP (WS-Trust
// X.509 token enrollment). Both protocols are SOAP 1.2 and share one HTTP
// listener, mirroring the PHP deployment.
//
//   POST /msxcep   → GetPolicies → GetPoliciesResponse (certificate templates)
//   POST /mswstep  → RequestSecurityToken (wraps a PKCS#10) → issued cert
//
// The SOAP envelopes we EMIT are hand-built rather than generated from the WSDLs. gSOAP
// would be the production-grade route (it consumes the provided WSDLs directly); for this
// port the outgoing message shapes are fixed enough that targeted construction is simpler.
//
// ⚠️ Request READING is a different matter and no longer hand-rolled. It used to be,
// justified as "dependency-free" — which was false for the image we ship: pki_lib has
// linked libxml2 since the SAML work, so every binary already carried a real XML parser
// while the most attacker-exposed parser in the codebase remained a find/substr scanner.
// Incoming bodies now go through pki::XmlDoc (src/lib/xml.cpp), which parses with entity
// substitution, external entities, DTD loading and network access all off and refuses any
// DOCTYPE outright. Matching is still by local name, ignoring namespace prefixes.
//
// The XCEP policy response offers the templates in the `ms_templates` table (imported from
// AD), or the built-in defaults in src/lib/ms_template.cpp when that table is empty. The
// WSTEP response carries the issued certificate as BinarySecurityTokens: a CMS SignedData
// with the chain, and the X.509 certificate itself.

#include "pki/auth.hpp"
#include "pki/cmc.hpp"
#include "pki/version.hpp"
#include "pki/ca_instance.hpp"
#include "pki/enrol_gate.hpp"
#include "pki/cert_profile.hpp"
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/endpoint_gate.hpp"
#include "pki/error.hpp"
#include "pki/listen.hpp"
#include "pki/log.hpp"
#include "pki/policy.hpp"
#include "pki/x509.hpp"
#include "pki/transport_reload.hpp"
#include "pki/xml.hpp"

#include "kerberos.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT   // MS-XCEP/WSTEP is HTTPS-only
#include "httplib.h"
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>   // mint this node's XCEP policy GUID
#include <openssl/x509v3.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <unistd.h>   // getpid(): the staging keytab name must be unique per PROCESS

namespace {

// ── Certificate template table (mirrors msxcep/globals.php defaults) ───────
// Field set + values follow the original PHP server (pki/msxcep/globals.php) so the
// GetPoliciesResponse satisfies the Windows WCF policy validator (xcep.xsd).
constexpr int kNil = -1;   // sentinel: emit the (nillable) element as xsi:nil
// The template model + the built-in defaults now live in pki/ms_template.hpp /
// ms_template.cpp so the DB layer, the CSV importer and the web
// console can share them. fastpki-ms serves DB-stored templates when present,
// else these defaults. kNil here == pki::kMsNil (the nillable-flag sentinel).
using pki::MsTemplate;

// One KeyPurposeId, three spellings: the OpenSSL short name ("serverAuth"), the long name
// ("TLS Web Server Authentication") and the dotted OID. OBJ_txt2obj accepts all three, so
// every source lands on the same object.
//
// ⚠️ THIS USED TO MATCH THREE LITERAL LONG NAMES and return "" for anything else, which
// der_eku() then skipped. An AD-imported template — pKIExtendedKeyUsage holds dotted OIDs —
// therefore advertised an EMPTY extendedKeyUsage SEQUENCE, two bytes of `30 00`, which
// RFC 5280 §4.2.1.12 forbids: the extension must name at least one purpose.
ASN1_OBJECT* eku_obj(const std::string& tok) {
    if (tok.empty()) return nullptr;
    return OBJ_txt2obj(tok.c_str(), 0);   // 0: accept names as well as dotted OIDs
}

// ── small helpers ─────────────────────────────────────────────────────────
// xml_escape now lives in pki_lib. There used to be two file-local copies of this
// — here and in saml.cpp — differing in exactly one character: saml escaped ' and this one
// did not. Neither was wrong for its own call sites, which is precisely how two spellings
// of one function survive. The shared one escapes all five.
using pki::xml_escape;


std::string b64_encode(const unsigned char* d, size_t n) {
    BIO* mem = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* chain = BIO_push(b64, mem);
    BIO_write(chain, d, static_cast<int>(n));
    BIO_flush(chain);
    BUF_MEM* bp = nullptr; BIO_get_mem_ptr(chain, &bp);
    std::string out(bp->data, bp->length);
    BIO_free_all(chain);
    return out;
}

std::vector<unsigned char> b64_decode(const std::string& in) {
    BIO* mem = BIO_new_mem_buf(in.data(), static_cast<int>(in.size()));
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* chain = BIO_push(b64, mem);
    std::vector<unsigned char> out(in.size());
    int n = BIO_read(chain, out.data(), static_cast<int>(out.size()));
    BIO_free_all(chain);
    if (n <= 0) return {};
    out.resize(static_cast<size_t>(n));
    return out;
}


// ── DER encoders for the certificate-template <extensions> values ──────────
// The MS-XCEP <Extension><value> carries the *DER of the extension value*
// (base64), exactly as the original PHP setKeyUsage/setExtendedKeyUsage/
// setCertificateTemplateName produce. These let the Windows client build a
// proper PKCS#10 from the template.

// X.509 KeyUsage BIT STRING from the 16-bit globals.php bitmap (bit 15 =
// digitalSignature … bit 7 = decipherOnly), mapped to X.509 bit positions.
std::vector<unsigned char> der_key_usage(unsigned ku) {
    ASN1_BIT_STRING* bs = ASN1_BIT_STRING_new();
    // X.509 KeyUsage bit i ← globals.php bit (15 - i).
    static const int php_bit[9] = {15, 14, 13, 12, 11, 10, 9, 8, 7};
    for (int i = 0; i < 9; ++i)
        if (ku & (1u << php_bit[i])) ASN1_BIT_STRING_set_bit(bs, i, 1);
    int len = i2d_ASN1_BIT_STRING(bs, nullptr);
    std::vector<unsigned char> out(len > 0 ? len : 0);
    if (len > 0) { unsigned char* p = out.data(); i2d_ASN1_BIT_STRING(bs, &p); }
    ASN1_BIT_STRING_free(bs);
    return out;
}

// extendedKeyUsage: DER SEQUENCE OF OBJECT IDENTIFIER.
std::vector<unsigned char> der_eku(const std::vector<std::string>& friendly) {
    EXTENDED_KEY_USAGE* eku = sk_ASN1_OBJECT_new_null();
    for (const auto& f : friendly) {
        ASN1_OBJECT* o = eku_obj(f);
        if (o) sk_ASN1_OBJECT_push(eku, o);
    }
    // ⚠️ NOTHING RESOLVED MEANS NO EXTENSION, not an empty one. i2d of an empty
    // EXTENDED_KEY_USAGE is the two bytes `30 00`, and RFC 5280 §4.2.1.12 requires the
    // extension to name at least one purpose — so an empty result is returned as empty
    // and the caller omits the element entirely.
    if (sk_ASN1_OBJECT_num(eku) <= 0) {
        sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
        return {};
    }
    int len = i2d_EXTENDED_KEY_USAGE(eku, nullptr);
    std::vector<unsigned char> out(len > 0 ? len : 0);
    if (len > 0) { unsigned char* p = out.data(); i2d_EXTENDED_KEY_USAGE(eku, &p); }
    sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
    return out;
}

// Microsoft certificate-template-name extension value: a DER BMPString
// (UTF-16BE) of the template name. Names are short ASCII, so short-form length.
std::vector<unsigned char> der_template_name(const std::string& name) {
    std::vector<unsigned char> body;
    for (char c : name) { body.push_back(0); body.push_back(static_cast<unsigned char>(c)); }
    std::vector<unsigned char> out;
    out.push_back(0x1E);                                  // BMPString tag
    out.push_back(static_cast<unsigned char>(body.size())); // assumes < 128
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

struct State {
    pki::Config cfg;
    pki::Db*    db{nullptr};
    pki::CaMaterialCache* ca_cache{nullptr};   // per-request signing material
    std::vector<MsTemplate> templates;
};

// ── MS-XCEP: GetPoliciesResponse ───────────────────────────────────────────
// `req_msg_id` is the <a:MessageID> the client sent; we echo it back as
// <a:RelatesTo> so the WCF enrollment-policy client (used by
// Add-CertificateEnrollmentPolicyServer) can correlate the reply. Omitting it
// works for a raw HTTP probe but the real Windows client rejects the response.
// The public base ("scheme://host[:port]") to advertise inside the policy.
// Same rule as ACME's g_req_base (src/acme/main.cpp) — the identical problem: we
// must hand a client an ABSOLUTE url it will then follow, while being HTTPS-native
// on our own port and possibly behind a proxy.
//
//   - an operator-set BASE_URL wins (proxy / non-standard port);
//   - otherwise mirror the Host the client actually reached us on (carries the port
//     for free, so a direct/unproxied client gets a URL it can actually follow).
//
// NOTE: this is right for the policy's cAURI *because* it is a live answer to a
// request. Do NOT copy it to AIA/CRLDP: those are baked into certs that outlive the
// request and must stay canonical/operator-controlled (derive_ca_urls()).
std::string ms_public_base(const State& st, const httplib::Request& req) {
    if (st.cfg.base_url_explicit) return st.cfg.base_url;
    std::string host = req.get_header_value("Host");
    if (host.empty()) host = st.cfg.pki_dns + ":" + std::to_string(st.cfg.ms_port);
    std::string scheme = req.get_header_value("X-Forwarded-Proto");
    if (scheme.empty()) scheme = "https";      // MS-XCEP/WSTEP is HTTPS-only
    return scheme + "://" + host;
}

// `ca_cert` is the CA this policy advertises and `ca_id` its instance id, so
// the <cAURI> points the client at that CA's own WSTEP route (<wstep_path>/{ca_id})
// and <certificate> carries its cert. This is how a Windows client discovers the
// per-CA enrolment URL: only the XCEP URL has to be configured in GPO. `base` is
// ms_public_base() — the host this client can actually reach us on.
//
// Nothing inside <cAs> is a literal any more. The URI list, each URI's
// clientAuthentication / priority / renewalOnly, and the CA's enrollPermission all
// come from the DB (ca_xcep_uris + the CA row's ms_enroll_permission). A CA with no
// URI rows — and a row whose uri is empty — still advertises this server's own WSTEP
// endpoint for it, so a freshly created CA is enrollable with no extra configuration.
//
// `ca_cert` stays the SINGLE newest certificate even while a rekey is rolling
// over, and that is deliberate. In xcep.xsd a <cA> is a certification authority, not a
// certificate — it carries one <certificate> plus its own URI collection and
// enrollPermission — so publishing a CA's two live certificates as two <cA> entries
// would advertise it as two different CAs and need matching <cAReference> bookkeeping in
// every <policy>. The certificate the client will enrol against is the newest one, and
// the rollover chain reaches it where a chain belongs: the WSTEP response's PKCS#7.
// ⚠️ THE CATALOGUE IS A PARAMETER, NOT `st.templates`. The set a caller may see is the
// set their roles grant, which is a per-request answer — so the whole catalogue is no
// longer reachable from inside this function by accident. Reading it off `st` was how
// every authenticated caller came to be offered templates they could never enrol under.
// Defined below, beside the readiness predicate it shares. Declared here because the
// policy document has to say whether this deployment accepts Kerberos, and that is a fact
// about the directories rather than about XCEP.
static bool krb_any_directory_keytab(const State& st);

std::string build_xcep_response(const State& st, const std::string& req_msg_id,
                                X509* ca_cert, const std::string& ca_id,
                                const std::string& base,
                                const std::vector<pki::MsTemplate>& tmpls) {
    auto ca_der = pki::x509_to_der(ca_cert);
    std::string ca_b64 = b64_encode(ca_der.data(), ca_der.size());
    const int N = static_cast<int>(tmpls.size());
    const int ext_off = 3 * N;   // matches PHP: numOIDs(=N) + N*2

    // Helper: emit a nillable xs:int element as a value or xsi:nil. SIGNED — use this only
    // for the elements the schema really types xs:int (the OID references). Everything
    // unsigned goes through u32 / nil_uint below.
    auto nil_int = [](const char* tag, int v) -> std::string {
        if (v == kNil)
            return std::string("<") + tag + " xsi:nil=\"true\"/>";
        return std::string("<") + tag + ">" + std::to_string(v) + "</" + tag + ">";
    };
    // ⚠️ EVERY xs:unsignedInt ELEMENT GOES THROUGH THIS, NOT JUST THE ONES KNOWN TO BREAK.
    // A negative decimal in an unsigned element makes the WCF reader reject the WHOLE
    // policy document, so one bad value takes down every template in the response — which
    // is why the census matters more than any single site. The flag bitmasks were fixed
    // first because they are negative most often; these are the rest of the unsigned set
    // (policySchema, minimalKeyLength, keySpec, keyUsageProperty, the two revisions,
    // clientAuthentication and priority), each of which is a plain signed int in our model
    // and could carry a value whose top bit is set.
    //
    // Both helpers exist so the rule has NO exceptions: an element the schema types
    // unsigned is never built with a bare std::to_string. u64 takes an already-unsigned
    // value and only looks redundant — it is what lets the guarding test assert the rule
    // by pattern, instead of having to know which variables happen to be unsigned today.
    auto u32 = [](int v) { return std::to_string(static_cast<uint32_t>(v)); };
    auto u64 = [](uint64_t v) { return std::to_string(v); };
    auto nil_uint = [&u32](const char* tag, int v) -> std::string {
        if (v == kNil)
            return std::string("<") + tag + " xsi:nil=\"true\"/>";
        return std::string("<") + tag + ">" + u32(v) + "</" + tag + ">";
    };
    // ⚠️ THE FLAG FIELDS ARE UNSIGNED ON THE WIRE, AND A SIGNED RENDERING BREAKS THE CLIENT
    // OUTRIGHT. These four are 32-bit BITMASKS whose top bit is routinely set — a directory
    // returns msPKI-Certificate-Name-Flag as the signed decimal -1509949440 for what is
    // really 0xA6000000. xcep types them unsignedInt, so emitting the negative made the
    // Windows client refuse the whole policy response with WS_E_NUMERIC_OVERFLOW
    // (0x803d0002) — the policy server could not be added at all.
    //
    // It stayed hidden because the built-in templates use small positive values (0x9,
    // 0x10); it appears the moment real directory templates are imported. Measured on one
    // directory: 12 of 33 templates carry a negative value in this attribute.
    //
    // The value is NOT wrong in the database — a bitmask has no sign — so this converts at
    // the point where the sign becomes meaningful, which is the wire.
    auto nil_flags = [](const char* tag, int v) -> std::string {
        if (v == kNil)
            return std::string("<") + tag + " xsi:nil=\"true\"/>";
        return std::string("<") + tag + ">" +
               std::to_string(static_cast<uint32_t>(v)) + "</" + tag + ">";
    };
    // ── <keyUsageProperty> IS A CNG POLICY, NOT THE X.509 KeyUsage EXTENSION ────────
    //
    // ⚠️ THESE ARE TWO DIFFERENT BITMAPS AND WE WERE SENDING THE WRONG ONE. MS-XCEP's
    // keyUsageProperty is NCRYPT_KEY_USAGE_PROPERTY — NCRYPT_ALLOW_DECRYPT_FLAG (0x1),
    // NCRYPT_ALLOW_SIGNING_FLAG (0x2), NCRYPT_ALLOW_KEY_AGREEMENT_FLAG (0x4), or
    // NCRYPT_ALLOW_ALL_USAGES (0xffffff). The template's `key_usage` is the X.509 KeyUsage
    // bit string, and it is emitted CORRECTLY as the KeyUsage extension further down; it
    // was ALSO being emitted here verbatim.
    //
    // So a template with digitalSignature|keyEncipherment (0xA000) told the client to set a
    // CNG usage policy of 40960 — bits 13 and 15, neither of which is a defined
    // NCRYPT_ALLOW_* flag. CNG refuses it, and the enrolment dies at key creation, before
    // anything reaches us:
    //
    //     A certificate request could not be created.
    //     Access denied. 0x80090010 (-2146893808 NTE_PERM)
    //
    // Measured on a domain-joined Server 2022 client, as SYSTEM, against this CA — and the
    // same client creates a machine CNG key happily with a plain `certreq -new`, which is
    // what rules out a permission or profile cause.
    //
    // The mapping is by MEANING: anything that signs asks for SIGNING, anything that
    // unwraps or decrypts asks for DECRYPT, key agreement asks for KEY_AGREEMENT.
    auto cng_key_usage = [](unsigned x509_ku) -> unsigned {
        unsigned out = 0;
        if (x509_ku & (0x8000u | 0x4000u | 0x0400u | 0x0200u)) out |= 0x2u;  // sign/nonRep/certSign/cRLSign
        if (x509_ku & (0x2000u | 0x1000u))                     out |= 0x1u;  // key/dataEncipherment
        if (x509_ku &  0x0800u)                                out |= 0x4u;  // keyAgreement
        // A template that asserts no KeyUsage at all constrains the key not at all, which
        // is what NCRYPT_ALLOW_ALL_USAGES says. Zero would say "no usage is permitted".
        return out ? out : 0x00ffffffu;
    };
    auto der_b64 = [](const std::vector<unsigned char>& d) {
        return d.empty() ? std::string() : b64_encode(d.data(), d.size());
    };
    // ⚠️ OMITTED, NOT EMPTIED. A template whose EKUs resolve to nothing — one imported
    // without pKIExtendedKeyUsage, say — must not advertise an empty extendedKeyUsage:
    // i2d of an empty EXTENDED_KEY_USAGE is the two bytes `30 00`, and RFC 5280 §4.2.1.12
    // requires the extension to name at least one purpose. The oIDReference values are
    // explicit rather than positional, so dropping the element shifts nothing after it.
    auto eku_extension = [&der_b64](const MsTemplate& t, int ref) {
        const std::vector<unsigned char> d = der_eku(t.ekus);
        if (d.empty()) return std::string();
        return "<extension>"
               "<oIDReference>" + std::to_string(ref) + "</oIDReference>"
               "<critical>true</critical>"
               "<value>" + der_b64(d) + "</value>"
               "</extension>";
    };
    // <cryptoProviders> holds 1..n <provider> entries; a template with none still
    // emits one empty element so the collection is well-formed for the WCF validator.
    auto providers = [](const MsTemplate& t) {
        if (t.crypto_providers.empty()) return std::string("<provider></provider>");
        std::string s;
        for (const auto& p : t.crypto_providers)
            s += "<provider>" + xml_escape(p) + "</provider>";
        return s;
    };

    // ── <cAs><cA> : this CA's advertised endpoints, from the DB ────────────
    const std::string own_wstep =
        base + st.cfg.wstep_path + (ca_id.empty() ? "" : "/" + ca_id);
    std::vector<pki::Db::CaXcepUri> uris;
    bool ca_enroll = true;
    try {
        uris = st.db->list_ca_xcep_uris(ca_id);
        if (auto ci = st.db->get_ca_instance(ca_id)) ca_enroll = ci->ms_enroll_permission;
    } catch (const std::exception& e) {
        pki::log::info(std::string("msxcep: could not read CA XCEP config for ") + ca_id +
                       " (" + e.what() + ") — advertising this server's own WSTEP URL");
    }
    // xcep.xsd requires CAURICollection to hold at least one <cAURI>, so a CA with no
    // configured rows falls back to this server's own endpoint.
    //
    // ⚠️ ADVERTISE THE AUTHENTICATION WE ACTUALLY ACCEPT. The fallback used to emit a
    // default-constructed row, whose client_auth is 4 -- USERNAME AND PASSWORD ONLY. A
    // domain machine enrolling through certreq runs as SYSTEM: it holds a Kerberos ticket
    // and has no password to offer, so it was told the enrolment endpoint could not take
    // the only credential it has. The request never went out and Windows reported
    // `ERROR_INVALID_PARAMETER`, which names no field and sent me looking at the template
    // metadata for a day.
    //
    // clientAuthentication is ONE value per <cAURI>, not a bitmask, so a service that
    // accepts two schemes has to advertise two URIs. Kerberos goes first -- lower priority
    // number wins -- and username/password stays for clients that have no ticket, which is
    // exactly the fallback matrix the 401 challenge already offers.
    if (uris.empty()) {
        if (krb_any_directory_keytab(st)) {
            pki::Db::CaXcepUri k{};
            k.client_auth = 2;      // Kerberos
            k.priority    = 1;
            uris.push_back(k);
        }
        pki::Db::CaXcepUri pw{};    // 4 = username/password, the struct default
        pw.priority = krb_any_directory_keytab(st) ? 2 : 1;
        uris.push_back(pw);
    }
    std::string ca_uris;
    for (const auto& u : uris)
        ca_uris +=
            "<cAURI>"
              "<clientAuthentication>" + u32(u.client_auth) + "</clientAuthentication>"
              "<uri>" + xml_escape(u.uri.empty() ? own_wstep : u.uri) + "</uri>"
              + nil_uint("priority", u.priority) +
              "<renewalOnly>" + (u.renewal_only ? "true" : "false") + "</renewalOnly>"
            "</cAURI>";

    // ── <policies> : one <policy> per template, full <attributes> in XSD order
    std::string policies;
    for (int i = 0; i < N; ++i) {
        const MsTemplate& t = tmpls[i];
        const int pk_ref   = N + 2 * i;
        const int hash_ref = N + 2 * i + 1;
        // ⚠️ BOTH OF THESE ARE xs:unsignedLong, AND THE RENEWAL ONE USED TO GO NEGATIVE.
        //
        // It was emitted as `validity - 30 days`, which is wrong twice over. A template
        // shorter than 30 days — and the directory defaults include a 7-day and a 14-day
        // one — produced a negative number in an unsigned element, and that does not spoil
        // just its own template: the client rejects the ENTIRE policy document, so all 33
        // templates became unusable and adding the policy server failed outright. It looked
        // like a size limit, because trimming the offered set to a handful that happened to
        // exclude the short ones made it work.
        //
        // The second error is the meaning. renewalPeriodSeconds is the OVERLAP — how long
        // BEFORE expiry a client should start renewing — so `validity - 30 days` told a
        // one-year template to begin renewing 335 days early, i.e. almost immediately.
        //
        // The directory carries the real figure in its overlap-period attribute, and when
        // the template was imported from one we use it. A template that carries no overlap
        // — hand-made, from a CSV, or a built-in — keeps the derived default: the same
        // shape the directory's own defaults use (six weeks), never more than half the
        // lifetime, which is what keeps a short-lived template sane.
        //
        // ⚠️ AND THE DIRECTORY'S OWN NUMBER IS STILL CLAMPED. Nothing stops an
        // administrator configuring an overlap longer than the validity, and emitting that
        // says "start renewing before this certificate was issued". It is not a type
        // violation — the element is unsigned either way — but it is exactly the class of
        // value that made the whole document unusable last time, so the ceiling is the
        // lifetime itself. A stored overlap is honoured up to that and not past it.
        const uint64_t valid_sec =
            t.validity_days > 0 ? uint64_t(t.validity_days) * 86400ull : 0ull;
        const uint64_t renew_sec =
            t.overlap_seconds >= 0
                ? std::min<uint64_t>(static_cast<uint64_t>(t.overlap_seconds), valid_sec)
                : std::min<uint64_t>(42ull * 86400ull, valid_sec / 2);
        policies +=
            "<policy>"
              "<policyOIDReference>" + std::to_string(i) + "</policyOIDReference>"
              "<cAs><cAReference>0</cAReference></cAs>"
              "<attributes>"
                "<commonName>" + xml_escape(t.name) + "</commonName>"
                "<policySchema>" + u32(t.schema) + "</policySchema>"
                "<certificateValidity>"
                  "<validityPeriodSeconds>" + u64(valid_sec) + "</validityPeriodSeconds>"
                  "<renewalPeriodSeconds>" + u64(renew_sec) + "</renewalPeriodSeconds>"
                "</certificateValidity>"
                "<permission>"
                  "<enroll>" + (t.enroll ? "true" : "false") + "</enroll>"
                  "<autoEnroll>" + (t.auto_enroll ? "true" : "false") + "</autoEnroll>"
                "</permission>"
                "<privateKeyAttributes>"
                  "<minimalKeyLength>" + u32(t.min_key_size) + "</minimalKeyLength>"
                  + nil_uint("keySpec", t.key_spec)
                  + ("<keyUsageProperty>" + u32(static_cast<int>(cng_key_usage(t.key_usage)))
                     + "</keyUsageProperty>")
                  // The template's SDDL private-key security descriptor
                  // (msPKI-Private-Key-Security-Descriptor); nillable when unset.
                  + (t.private_key_permissions.empty()
                       ? std::string("<permissions xsi:nil=\"true\"/>")
                       : "<permissions>" + xml_escape(t.private_key_permissions) +
                         "</permissions>") +
                  "<algorithmOIDReference>" + std::to_string(pk_ref) + "</algorithmOIDReference>"
                  // <provider> is 1..n in xcep.xsd — emit every configured CSP,
                  // in order, not just the first (schema-1/2 clients pick from the list).
                  "<cryptoProviders>" + providers(t) + "</cryptoProviders>"
                "</privateKeyAttributes>"
                "<revision>"
                  "<majorRevision>" + u32(t.major_rev) + "</majorRevision>"
                  "<minorRevision>" + u32(t.minor_rev) + "</minorRevision>"
                "</revision>"
                "<supersededPolicies xsi:nil=\"true\"/>"
                + nil_flags("privateKeyFlags",  t.private_key_flags)
                + nil_flags("subjectNameFlags", t.subject_name_flags)
                + nil_flags("enrollmentFlags",  t.enrollment_flags)
                + nil_flags("generalFlags",     t.general_flags)
                + nil_int("hashAlgorithmOIDReference", hash_ref) +
                "<rARequirements xsi:nil=\"true\"/>"
                "<keyArchivalAttributes xsi:nil=\"true\"/>"
                "<extensions>"
                  "<extension>"
                    "<oIDReference>" + std::to_string(ext_off) + "</oIDReference>"
                    "<critical>false</critical>"
                    "<value>" + der_b64(der_key_usage(t.key_usage)) + "</value>"
                  "</extension>"
                + eku_extension(t, ext_off + 1) +
                  "<extension>"
                    "<oIDReference>" + std::to_string(ext_off + 2) + "</oIDReference>"
                    "<critical>false</critical>"
                    "<value>" + der_b64(der_template_name(t.name)) + "</value>"
                  "</extension>"
                "</extensions>"
              "</attributes>"
            "</policy>";
    }

    // ── <oIDs> : policy OIDs (grp 9), then per-template pk(2)+hash(1), then the
    //    three extension OIDs (grp 6) — exact order + reference IDs from the PHP.
    auto oid_elem = [&](const std::string& value, int group, int ref,
                        const std::string& def) {
        return "<oID><value>" + xml_escape(value) + "</value><group>" +
               std::to_string(group) + "</group><oIDReferenceID>" +
               std::to_string(ref) + "</oIDReferenceID><defaultName>" +
               xml_escape(def) + "</defaultName></oID>";
    };
    std::string oids;
    for (int p = 0; p < N; ++p)
        oids += oid_elem(tmpls[p].oid, 9, p, tmpls[p].name);
    for (int i = 0; i < N; ++i) {
        oids += oid_elem(tmpls[i].pk_oid,   2, N + 2 * i,     tmpls[i].pk_name);
        oids += oid_elem(tmpls[i].hash_oid, 1, N + 2 * i + 1, tmpls[i].hash_name);
    }
    oids += oid_elem("2.5.29.15",            6, ext_off,     "Key Usage");
    oids += oid_elem("2.5.29.37",            6, ext_off + 1, "Extended Key Usage");
    oids += oid_elem("1.3.6.1.4.1.311.20.2", 6, ext_off + 2, "Certificate Template Name");

    std::string body =
        "<GetPoliciesResponse"
            " xmlns=\"http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy\""
            " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
          "<response>"
            "<policyID>" + xml_escape(st.cfg.ms_xcep_guid) + "</policyID>"
            "<policyFriendlyName>" + xml_escape(st.cfg.ms_xcep_friendly_name) + "</policyFriendlyName>"
            // See MS_XCEP_NEXT_UPDATE_HOURS in config.hpp for why this is not a literal.
            //
            // ⚠️ u32, NOT std::to_string — nextUpdateHours is xs:unsignedInt on the wire and
            // the value is a signed int in our model. A raw signed conversion is the exact
            // shape that made subjectNameFlags emit -1509949440 for 0xA6000000, which the
            // WCF reader rejects with WS_E_NUMERIC_OVERFLOW — and it rejects the WHOLE
            // policy document, so one bad element takes every template down with it.
            // tests/ms_xcep_unsigned.sh scans for this pattern precisely because a field
            // added later is where it comes back; it caught this one the day it was added.
            "<nextUpdateHours>" + u32(st.cfg.ms_xcep_next_update_hours) +
              "</nextUpdateHours>"
            "<policiesNotChanged xsi:nil=\"true\"/>"
            "<policies>" + policies + "</policies>"
          "</response>"
          "<cAs>"
            "<cA>"
              "<uris>" + ca_uris + "</uris>"
              "<certificate>" + ca_b64 + "</certificate>"
              "<enrollPermission>" + (ca_enroll ? "true" : "false") + "</enrollPermission>"
              "<cAReferenceID>0</cAReferenceID>"
            "</cA>"
          "</cAs>"
          "<oIDs>" + oids + "</oIDs>"
        "</GetPoliciesResponse>";

    return
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
                    "xmlns:a=\"http://www.w3.org/2005/08/addressing\">"
          "<s:Header>"
            "<a:Action s:mustUnderstand=\"1\">"
              "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse"
            "</a:Action>"
            + (req_msg_id.empty() ? std::string()
               : "<a:RelatesTo>" + xml_escape(req_msg_id) + "</a:RelatesTo>") +
            "<a:To s:mustUnderstand=\"1\">"
              "http://www.w3.org/2005/08/addressing/anonymous"
            "</a:To>"
          "</s:Header>"
          "<s:Body>" + body + "</s:Body>"
        "</s:Envelope>";
}

// ── MS-WCCE 2.2.2.8 CMC full PKI response ──────────────────────────────────
// ⚠️ THE ENROLLMENT POLICY GUID IS THIS NODE'S, AND IT IS MINTED HERE.
//
// It used to be a literal compiled into config.hpp, so every FastPKI deployment on earth
// — and all three DCs of one mesh — advertised the SAME <policyID>. Windows keys its
// enrollment policy cache on that id: point a machine at a second DC and it believes it
// already holds that policy, and the two servers fight over one cache entry. That is the
// conflict described above.
//
// Minted on first start rather than at install time, deliberately. The `config` table is
// node-local — it is NOT in the replication publication (pinned in
// tests/lab_replication_mesh.sh), so a value written here stays on this DC and every node
// mints its own with nothing to configure and nothing to keep in step. An install-time
// generator would also have left the three DCs that already exist sharing the old literal
// until someone reinstalled them.
//
// claim_config, never set_config: two `ms` replicas on one DC start together, and the
// loser must adopt the winner's id rather than overwrite it — the value is worthless if
// it is not stable for the node.
void resolve_xcep_guid(State& st) {
    if (!st.cfg.ms_xcep_guid.empty()) return;   // pinned by an operator; leave it alone
    unsigned char b[16];
    if (RAND_bytes(b, sizeof b) != 1) {
        pki::log::err("MS_XCEP_GUID: RAND_bytes failed; XCEP will advertise no policy id");
        return;
    }
    b[6] = static_cast<unsigned char>((b[6] & 0x0F) | 0x40);   // RFC 4122 version 4
    b[8] = static_cast<unsigned char>((b[8] & 0x3F) | 0x80);   // variant 10x
    char u[40];
    std::snprintf(u, sizeof u,
        "{%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
        b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7], b[8],b[9], b[10],b[11],b[12],b[13],b[14],b[15]);
    // Braced and lowercase: that is the shape MS-XCEP §3.1.4.1.3.3 shows and what the
    // literal we are replacing used, so nothing downstream has to learn a new format.
    try {
        st.cfg.ms_xcep_guid = st.db->claim_config("MS_XCEP_GUID", u);
        if (st.cfg.ms_xcep_guid == u)
            pki::log::info(std::string("MS_XCEP_GUID: created this node's enrollment policy id ") + u);
        else
            pki::log::info("MS_XCEP_GUID: adopted the id another instance had already stored");
    } catch (const std::exception& e) {
        pki::log::err(std::string("MS_XCEP_GUID: could not persist a policy id: ") + e.what());
    }
}

// The RSTR's PKCS7 BinarySecurityToken is a CMS SignedData, signed by the CA,
// whose encapsulated content is a CMC PKIResponse (id-cct-PKIResponse) and whose
// certificate set carries the issued cert + CA chain. Mirrors the original PHP
// (pki/mswstep/classes.php builds the same ContentInfo/PKIResponse/SignerInfo).
// A degenerate certs-only PKCS#7 is NOT accepted by the WCF enrollment client.
//
// `ca_chain` is every LIVE certificate of the signing CA, newest first. Normally
// that is just `ca` and this behaves exactly as before. During a rekey rollover it is
// two, and both have to reach the client: the response is signed by the new key, but a
// relying party still anchored on the old certificate can only build a path if the old
// one travels with it. CMS_add1_signer already puts `ca` in the certificate set, so the
// loop adds the others and skips the signer rather than sending it twice.
std::vector<unsigned char> build_cmc_full_response(X509* issued, X509* ca,
                                                   EVP_PKEY* ca_key,
                                                   const std::vector<std::shared_ptr<X509>>& ca_chain) {
    // Minimal CMC ResponseBody (RFC 5272): SEQUENCE { controlSequence SEQ{},
    // cmsSequence SEQ{}, otherMsgSequence SEQ{} } — all empty.
    static const unsigned char pki_response[] = {
        0x30, 0x06, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00
    };
    std::vector<unsigned char> out;
    BIO* content = BIO_new_mem_buf(pki_response, sizeof(pki_response));
    STACK_OF(X509)* extra = sk_X509_new_null();
    if (content && extra) {
        sk_X509_push(extra, issued);               // include the issued cert
        for (const auto& c : ca_chain)             // the CA's other live certs
            if (c && X509_cmp(c.get(), ca) != 0) sk_X509_push(extra, c.get());
        CMS_ContentInfo* cms = CMS_sign(nullptr, nullptr, extra, content,
                                        CMS_PARTIAL | CMS_BINARY);
        if (cms) {
            ASN1_OBJECT* pki_oid = OBJ_txt2obj("1.3.6.1.5.5.7.12.3", 1); // id-cct-PKIResponse
            CMS_set1_eContentType(cms, pki_oid);
            ASN1_OBJECT_free(pki_oid);
            // Sign with the CA key (adds the CA cert to the certificate set).
            // CMS_NOSMIMECAP: omit the S/MIME-capabilities attribute (PHP doesn't
            // emit it; keeps the response minimal like the reference server).
            CMS_add1_signer(cms, ca, ca_key, EVP_sha256(), CMS_NOSMIMECAP);
            if (CMS_final(cms, content, nullptr, CMS_BINARY) == 1) {
                int len = i2d_CMS_ContentInfo(cms, nullptr);
                if (len > 0) {
                    out.resize(len);
                    unsigned char* p = out.data();
                    i2d_CMS_ContentInfo(cms, &p);
                }
            }
            CMS_ContentInfo_free(cms);
        }
    }
    if (extra) sk_X509_free(extra);
    if (content) BIO_free(content);
    return out;
}

// ── a CMC full PKI request, unwrapped ──────────────────────────────────────
//
// The parser moved to pki_lib (include/pki/cmc.hpp) so fuzz/fuzz_cmc.cpp can reach it:
// a hand-rolled DER walker over caller-supplied bytes is exactly the shape this
// project already fuzzes three of, and it could not be linked from inside this binary.

// ── MS-WSTEP: RequestSecurityTokenResponse ─────────────────────────────────
// Mirrors the original PHP server (pki/mswstep/classes.php): a RSTRC carrying
//   - TokenType (X509v3),
//   - DispositionMessage "Issued" (enrollment namespace),
//   - a PKCS#7 BinarySecurityToken with the cert chain, and
//   - RequestedSecurityToken → the single issued cert (X509v3).
// `cert_b64` is the issued cert DER (base64); `pkcs7_b64` the cert-chain PKCS#7.
std::string build_wstep_response(const std::string& cert_b64,
                                 const std::string& pkcs7_b64,
                                 const std::string& req_msg_id) {
    const char* WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    const char* X509 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    const char* B64  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary";
    const char* P7   = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7";
    const char* ENROLL = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";
    return
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
            "xmlns:a=\"http://www.w3.org/2005/08/addressing\" "
            "xmlns:wst=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\" "
            "xmlns:wsse=\"" + std::string(WSSE) + "\">"
          "<s:Header>"
            "<a:Action s:mustUnderstand=\"1\">"
              "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep"
            "</a:Action>"
            + (req_msg_id.empty() ? std::string()
               : "<a:RelatesTo>" + xml_escape(req_msg_id) + "</a:RelatesTo>") +
          "</s:Header>"
          "<s:Body>"
            "<wst:RequestSecurityTokenResponseCollection>"
              "<wst:RequestSecurityTokenResponse>"
                "<wst:TokenType>" + X509 + "</wst:TokenType>"
                "<DispositionMessage xmlns=\"" + ENROLL + "\" xml:lang=\"en-US\">Issued</DispositionMessage>"
                "<wsse:BinarySecurityToken ValueType=\"" + P7 + "\" EncodingType=\"" + B64 + "\">"
                  + pkcs7_b64 +
                "</wsse:BinarySecurityToken>"
                "<wst:RequestedSecurityToken>"
                  "<wsse:BinarySecurityToken ValueType=\"" + X509 + "\" EncodingType=\"" + B64 + "\">"
                    + cert_b64 +
                  "</wsse:BinarySecurityToken>"
                "</wst:RequestedSecurityToken>"
              "</wst:RequestSecurityTokenResponse>"
            "</wst:RequestSecurityTokenResponseCollection>"
          "</s:Body>"
        "</s:Envelope>";
}

// Dump the inbound request (method, path, headers, body) at debug level so we
// can inspect exactly what the real Windows enrollment client (WCF) sends —
// invaluable when iterating on certreq/Add-CertificateEnrollmentPolicyServer
// interop. No-op unless LOG_LEVEL=debug.
// ⚠️ HEADER NAMES AND SHAPE ONLY — NEVER VALUES, NEVER THE BODY. This logged every header
// verbatim and then the raw body, and it runs BEFORE the authentication ladder, so at
// LOG_LEVEL=debug — which docs/admin-guide.md recommends for troubleshooting enrolment —
// every Windows client deposited a working credential in the container log twice over:
// `Authorization: Basic <base64 user:password>` in the headers, and the cleartext
// <wsse:Password> of a WS-Security UsernameToken in the body.
//
// What is actually useful when debugging MS-XCEP/WSTEP is which request arrived, how big it
// was, and which headers were present — not what they said. A caller who needs the body has
// a packet capture and an authorization to take one.
void debug_log_request(const char* tag, const httplib::Request& req) {
    if (pki::log::level() != pki::log::Level::Debug) return;
    std::string names;
    for (const auto& kv : req.headers) { if (!names.empty()) names += ", "; names += kv.first; }
    pki::log::debug(std::string("[") + tag + "] " + req.method + " " + req.path +
                    " content-type=" + req.get_header_value("Content-Type") +
                    " bytes=" + std::to_string(req.body.size()) +
                    " headers-present: " + names);
}

// A SOAP 1.2 Fault envelope. WS-Trust / [MS-WSTEP] signal enrollment
// errors — including a rejected credential — as a soap:Fault, not an HTTP status.
// `subcode` is a wsse-namespaced local name (e.g. "FailedAuthentication"); the
// client echoes the request MessageID via <a:RelatesTo>. `sender` picks the
// Code Value (Sender for a client fault, Receiver for a server-side error).
std::string build_soap_fault(const std::string& req_msg_id, const std::string& subcode,
                             const std::string& reason, bool sender = true) {
    return
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
                    "xmlns:a=\"http://www.w3.org/2005/08/addressing\">"
          "<s:Header>"
            "<a:Action s:mustUnderstand=\"1\">"
              "http://www.w3.org/2005/08/addressing/soap/fault"
            "</a:Action>"
            + (req_msg_id.empty() ? std::string()
               : "<a:RelatesTo>" + xml_escape(req_msg_id) + "</a:RelatesTo>") +
            "<a:To s:mustUnderstand=\"1\">"
              "http://www.w3.org/2005/08/addressing/anonymous"
            "</a:To>"
          "</s:Header>"
          "<s:Body>"
            "<s:Fault>"
              "<s:Code>"
                "<s:Value>" + std::string(sender ? "s:Sender" : "s:Receiver") + "</s:Value>"
                "<s:Subcode>"
                  "<s:Value xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
                    "wsse:" + xml_escape(subcode) +
                  "</s:Value>"
                "</s:Subcode>"
              "</s:Code>"
              "<s:Reason><s:Text xml:lang=\"en\">" + xml_escape(reason) + "</s:Text></s:Reason>"
            "</s:Fault>"
          "</s:Body>"
        "</s:Envelope>";
}

// The ONE definition of "who is calling an MS endpoint".
//
// Three accepted methods, tried in order:
//   (a) HTTP `Authorization: Negotiate` — Kerberos/SPNEGO, passwordless for
//       domain-joined Windows clients (needs MS_KERBEROS_KEYTAB + a build with
//       FASTPKI_WITH_KERBEROS);
//   (b) HTTP `Authorization: Basic` — username/password over the header;
//   (c) WS-Security UsernameToken in the SOAP body (the legacy default).
//
// ⚠️ WHY IT IS A FUNCTION NOW. It used to live inline in handle_wstep, so WSTEP was
// authenticated and XCEP — the POLICY endpoint, in the same binary, one lambda away —
// read no credential at all. MS-XCEP is normally authenticated by Microsoft — the
// earlier PHP version did not, but there is no reason not to follow MS here.
//
// A copy for XCEP would have been the second-gate shape: one ladder edited, the other left
// behind, and nothing to notice it. `doc` may be null — XCEP's GetPolicies carries no
// UsernameToken in practice, and a caller with no SOAP body simply cannot use method (c).
struct MsAuth {
    bool        ok = false;
    std::string user;
    // ⚠️ THE DEFAULT IS EMPTY, AND EVERY BRANCH MUST FILL IT FROM THE USER'S ROW.
    //
    // It used to default to "standard" — a word that stopped being a console role, matches
    // no `roles` row and therefore grants nothing, while being written into the audit line
    // as though it decided something. Emptying it was right; leaving the Kerberos branch
    // to fall through to that empty was not. Every other branch assigns the row's role,
    // and a principal that authenticated over SSO was then authorized only by
    // subject_roles — so the role an admin set on that user, and which the console shows,
    // decided nothing at all. One identity, two answers depending on how it signed in.
    std::string role{};
    // Directory groups. Basic and UsernameToken get them from authenticate(); the Kerberos
    // branch resolves them from the principal name, because a service ticket proves a
    // principal and not a membership, and a role granted to a group is the normal way
    // permissions are given on an AD-facing path.
    std::vector<std::string> groups{};
    std::string method;      // "kerberos" | "basic" | "usernametoken" | "" (none offered)
};
// ⚠️ "CONFIGURED" IS NOT "USABLE" — AND THE UPLOAD FLOW GUARANTEES THE GAP.
//
// Every one of these sites used to ask `!cfg.ms_kerberos_keytab.empty()`, which is
// "did an admin type a path", not "is there a keytab there". The console's upload
// REFUSES to run until the path is set, so setting the path before any keytab exists
// is not an edge case -- it is the documented first step. In that window the server
// answered every 401 with `WWW-Authenticate: Negotiate`, so a domain-joined client
// tried SPNEGO against a keytab that was not there and failed inside GSSAPI, instead
// of going straight to the scheme that would have worked.
//
// An EMPTY file is as unusable as an absent one and is the more likely of the two:
// `install -m 600 /dev/null` and a half-finished bind mount both produce it.
//
// Deliberately NOT validating the contents here. A keytab that exists but holds the
// wrong principal or the wrong enctype is a different failure, and it already has a
// better answer than silence: accept_spnego reports the krb5 minor status, which is
// the whole point of the decoding work above. This predicate only decides whether to
// CLAIM Kerberos, so it asks the one question a claim depends on -- is there anything
// to authenticate WITH.
static bool krb_keytab_usable(const std::filesystem::path& p) {
    if (p.empty()) return false;
    std::error_code ec;
    if (!std::filesystem::is_regular_file(p, ec)) return false;
    return std::filesystem::file_size(p, ec) > 0 && !ec;
}

// ── ONE ACCEPTOR CREDENTIAL FROM EVERY DIRECTORY'S KEYTAB ──────────────────────────────
//
// A keytab holds ONE realm's service key, so a single deployment-wide MS_KERBEROS_KEYTAB
// could serve exactly one domain: a second directory's clients presented a ticket the
// acceptor had no key for, and the failure arrived as a GSSAPI error with NO minor status
// -- indistinguishable from a wrong principal or a stale kvno.
//
// The keytab format makes merging trivial and is why this is a file rather than a loop
// over directories: a keytab is a 2-byte version header followed by independent records,
// so concatenating the bodies under one header produces a valid keytab holding every
// principal. krb5 then does the matching itself, which it is far better at than we are --
// it selects by principal AND kvno AND enctype out of however many records are present.
//
// REBUILT WHENEVER THE INPUTS CHANGE, which is what preserves the property that uploading a
// keytab takes effect without restarting the service -- the same property the readiness
// check above exists to give. It used to be rebuilt on EVERY call, and that was a race:
// this runs on httplib worker threads, and every one of them wrote the same fixed
// `fastpki-merged.keytab.new` with ios::trunc. Two concurrent XCEP/WSTEP requests
// interleaved their record bytes into that one file and then renamed the corrupt result
// into place -- or the losing rename left a single realm's keytab behind. Under Windows
// autoenrolment the whole fleet polls at once, so the symptom was intermittent SPNEGO
// failures with no minor status, on a deployment that had been working.
//
// Two changes, both needed. The mutex makes the build atomic with respect to other
// builders; the cache means the common case does not build at all. The key is every part's
// path, size and mtime, so a re-uploaded keytab still takes effect immediately -- the
// hot-reload property is kept by making the key follow the FILES rather than by rebuilding
// blindly. (A keytab rewritten within one filesystem timestamp tick AND to the same byte
// length would be missed; last_write_time is nanosecond-resolution on Linux, and the upload
// path writes through a temp file and rename, so this is not reachable in practice.)
static std::mutex krb_merge_mu;
static std::string krb_merge_key;    // guarded by krb_merge_mu
static std::string krb_merge_path;   // guarded by krb_merge_mu
static unsigned long krb_merge_seq = 0;  // guarded by krb_merge_mu
static std::string krb_merged_keytab(State& st) {
    std::vector<std::filesystem::path> parts;
    for (const auto& p : pki::ldap_providers(st.cfg, st.db)) {
        if (!p.enabled) continue;
        if (krb_keytab_usable(p.krb_keytab)) parts.emplace_back(p.krb_keytab);
    }
    if (parts.empty()) return {};
    // One directory needs no merge, and handing krb5 the original file keeps the error
    // messages pointing at something the operator recognises.
    if (parts.size() == 1) return parts.front().string();

    // Everything from here builds or reads the shared merged file.
    std::lock_guard<std::mutex> lk(krb_merge_mu);

    // The identity of the INPUTS. Same key, same bytes -- so the merge is skipped and the
    // previous file is handed back, which is what makes this cheap enough to keep calling
    // per request.
    std::string key;
    for (const auto& part : parts) {
        std::error_code ec1, ec2;
        const auto sz = std::filesystem::file_size(part, ec1);
        const auto mt = std::filesystem::last_write_time(part, ec2);
        key += part.string() + ':' + (ec1 ? "?" : std::to_string(sz)) + ':' +
               // static_cast, because file_clock's rep is not the same integer type on
               // every platform: on macOS/libc++ it is wide enough that std::to_string is
               // AMBIGUOUS and the whole binary fails to compile there, while Alpine/libstdc++
               // picks an overload happily. The value is a file timestamp in a cache key —
               // long long holds it with centuries to spare.
               (ec2 ? "?" : std::to_string(
                    static_cast<long long>(mt.time_since_epoch().count()))) + '\n';
    }
    if (key == krb_merge_key && !krb_merge_path.empty()) {
        std::error_code ig;
        if (std::filesystem::exists(krb_merge_path, ig)) return krb_merge_path;
        // The file went away under us (a tmp reaper, another instance). Fall through and
        // rebuild rather than hand krb5 a path that is no longer there.
    }

    // temp_directory_path(), not a hardcoded /tmp: it honours TMPDIR, which is how two
    // instances on one host (and two suites in one gate) avoid writing over each other's
    // merged keytab. The krb5.conf beside it already had this and this did not.
    // ⚠️ THE DESTINATION IS PER-PROCESS TOO, not just the staging name. Two fastpki-ms
    // instances sharing a TMPDIR -- the case the paragraph above says TMPDIR handles -- each
    // rename their own merge onto one shared path. Neither file is torn, but the LAST writer
    // wins and the other instance's cache still says "valid": it checked its inputs and that
    // the path exists, never that the bytes are the ones it wrote. It would then hand krb5 a
    // keytab built from a DIFFERENT directory set, which fails as a GSSAPI error with no
    // minor status -- the same unattributable symptom this whole function exists to avoid.
    const std::string out = (std::filesystem::temp_directory_path() /
                             ("fastpki-merged." + std::to_string(::getpid()) + ".keytab")).string();
    // ⚠️ THE STAGING PATH IS PER-BUILD, not a fixed ".new". The mutex above already
    // serialises this process's builders, but a SECOND fastpki-ms sharing the same TMPDIR
    // is not covered by any lock we can hold -- and that is exactly the two-instances case
    // the comment above says TMPDIR handles. A unique name makes the write private and
    // leaves rename() as the only shared step, which is atomic.
    const std::string tmp = out + "." + std::to_string(::getpid()) + "." +
                            std::to_string(krb_merge_seq++) + ".new";
    try {
        std::ofstream o(tmp, std::ios::binary | std::ios::trunc);
        if (!o) {
            // Say so. Falling back to ONE directory's keytab silently means every other
            // domain's clients fail SPNEGO against a key this acceptor does not hold, and
            // that failure carries no minor status to explain itself.
            pki::log::err("MS-XCEP: cannot write the merged keytab at '" + tmp +
                          "' — falling back to a SINGLE directory's keytab (" +
                          parts.front().string() + "); other domains will not authenticate.");
            return parts.front().string();
        }
        bool wrote_header = false;
        for (const auto& part : parts) {
            std::ifstream in(part, std::ios::binary);
            if (!in) continue;
            std::vector<char> buf((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());
            if (buf.size() < 3) continue;                 // header only: no records to take
            if (!wrote_header) { o.write(buf.data(), 2); wrote_header = true; }
            o.write(buf.data() + 2, static_cast<std::streamsize>(buf.size() - 2));
        }
        o.close();
        if (!wrote_header) { std::error_code ig; std::filesystem::remove(tmp, ig); return {}; }
        std::filesystem::permissions(tmp, std::filesystem::perms::owner_read |
                                          std::filesystem::perms::owner_write,
                                     std::filesystem::perm_options::replace);
        std::filesystem::rename(tmp, out);
    } catch (const std::exception& e) {
        std::error_code ig; std::filesystem::remove(tmp, ig);
        krb_merge_key.clear();   // do not cache a failure as if it were the answer
        pki::log::err(std::string("could not merge directory keytabs: ") + e.what());
        return parts.front().string();
    }
    krb_merge_key  = key;
    krb_merge_path = out;
    return out;
}

// Whether ANY enabled directory holds a usable keytab -- i.e. whether this deployment can
// accept SPNEGO at all. The policy document needs the same answer the 401 challenge gives,
// or it advertises an authentication the service does not offer (or withholds one it does).
static bool krb_any_directory_keytab(const State& st) {
    try {
        for (const auto& p : pki::ldap_providers(st.cfg, st.db))
            if (p.enabled && krb_keytab_usable(p.krb_keytab)) return true;
    } catch (...) { /* no database, no directories — no Kerberos */ }
    return false;
}

MsAuth ms_authenticate(State& st, const httplib::Request& req, const pki::XmlDoc* doc,
                       const char* tag) {
    MsAuth a;
    const std::string authz = req.get_header_value("Authorization");
    const std::string krb_ktab = krb_merged_keytab(st);
    const bool krb_configured = !krb_ktab.empty();

    // (a) Kerberos / SPNEGO.
    if (krb_configured && authz.rfind("Negotiate ", 0) == 0) {
        a.method = "kerberos";
        auto raw = b64_decode(authz.substr(10));
        auto kr = pki::krb::accept_spnego(std::string(raw.begin(), raw.end()), krb_ktab);
        if (kr.ok) {
            a.ok = true;
            // Principal is "user@REALM" (or machine "HOST$@REALM"): the name before '@'
            // and the directory it belongs to, which is why both halves are kept below.
            //
            // MASTER_USERS used to set role="master" here, and is gone. That value
            // was doing nothing good even before it went: `master` has not been a console
            // role once it was renamed to `admin`, so may_enrol() saw an unknown role,
            // role_cert_cap() found no cap, and the string was written verbatim into the
            // issued certificate's role attribute. A Kerberos principal's authorization
            // comes from its web_users row and subject_roles, like everyone else's.
            // ⚠️ THE REALM NAMES THE DIRECTORY, SO IT IS THE QUALIFIER — DO NOT DROP IT.
            // Basic and UsernameToken below both authorize `AuthResult::subject`, which is
            // the provider-qualified `<directory>\\<user>`. This branch used to keep only
            // the part before '@', and a bare name is by definition the LOCAL namespace.
            //
            // With two directories each holding an `alice`, a ticket for `alice@PARTNER.LAB`
            // therefore authorized bare `alice`: directory_groups_for() saw no qualifier and
            // unioned the memberships of BOTH domains, a second web_users row was onboarded
            // under the bare name, and a role granted to `corp\\alice` -- the name every
            // other transport uses -- never matched. One account, authorized differently
            // depending on how it signed in.
            //
            // The mapping needs nothing stored: a directory's realm IS its DNS root
            // upper-cased (LdapProvider::realm()), which is how Windows forms it too, so the
            // ticket's realm names the directory exactly, or it names none of ours.
            //
            // ⚠️ AND WHEN IT NAMES NONE, THE TICKET IS REFUSED -- never called local. A bare
            // name means the web_users table, so treating an unattributable directory
            // principal as local would authorize it against a LOCAL account of the same name.
            // The operator's fix is one field: set that directory's DNS root so its realm
            // resolves. Refusing says which field; guessing would not.
            // rfind, not find: the NT-ENTERPRISE form Windows uses for UPN logon is
            // `alice@corp.local@REALM`, and splitting on the FIRST '@' takes
            // `corp.local@REALM` as the realm, which matches no directory.
            const std::string krb_bare = kr.principal.substr(0, kr.principal.rfind('@'));
            std::string krb_provider;
            {
                const auto at = kr.principal.rfind('@');
                std::string realm = (at == std::string::npos) ? "" : kr.principal.substr(at + 1);
                for (char& c : realm) if (c >= 'a' && c <= 'z') c = char(c - 'a' + 'A');
                // ldap_providers() does NOT throw on a database it cannot read -- it logs and
                // returns {} (src/lib/auth.cpp). So "no directories" and "could not ask" look
                // identical here, and both mean the same thing: we cannot attribute this
                // ticket, which is a refusal and never a fallback to a bare name.
                const auto provs = pki::ldap_providers(st.cfg, st.db);
                // ⚠️ THE REALM IS THE ONLY THING THAT NAMES THE CLIENT'S AUTHORITY, and the
                // keytab is NOT a second opinion. A service ticket is encrypted with the
                // TARGET service's key, so under a cross-forest trust the sole holder of our
                // keytab accepts tickets for clients from EVERY realm that trusts it.
                // Attributing by "whose keytab accepted it" would therefore hand
                // `alice@PARTNER.LAB` the identity `corp\alice` -- inheriting the real corp
                // alice's roles and LDAP groups. That is impersonation of a named account,
                // strictly worse than the unqualified name this ticket set out to fix.
                //
                // ⚠️ AND AMBIGUITY IS REFUSED, NOT RANKED. Two enabled directories can derive
                // the same realm (the same forest reached through different DCs or base DNs,
                // which is a shape multi-provider exists to express). Taking the first would
                // resolve by priority order -- the exact thing the naming rule forbids -- so
                // a realm claimed twice is as unattributable as a realm claimed by nobody.
                int matches = 0;
                for (const auto& p : provs) {
                    if (!p.enabled || realm.empty()) continue;
                    if (p.realm() != realm) continue;
                    if (matches++ == 0) krb_provider = p.id;
                }
                if (matches != 1) {
                    krb_provider.clear();
                    pki::log::err(
                        std::string("MS-XCEP: Kerberos realm '") + realm + "' is claimed by " +
                        std::to_string(matches) + " directories — cannot say which asserted '" +
                        krb_bare + "', so the ticket is refused. A realm is a directory's DNS "
                        "root upper-cased: set exactly one directory's DNS root to match.");
                    a.ok = false;
                    return a;
                }
                // ⚠️ AND A NAME WITH A BACKSLASH CANNOT BE QUALIFIED. krb5_unparse_name escapes
                // '@', '/' and '\' inside a component, so a principal may legitimately contain
                // a backslash -- and our qualified form uses that character as the separator.
                // Joining them would produce a name that splits back into something else
                // entirely, silently naming a different directory or user.
                if (krb_bare.find('\\') != std::string::npos) {
                    pki::log::err("MS-XCEP: Kerberos principal '" + krb_bare + "' contains a "
                                  "backslash, which is the provider separator — refusing rather "
                                  "than producing a name that resolves to something else.");
                    a.ok = false;
                    return a;
                }
            }
            a.user = pki::qualify_subject(krb_provider, krb_bare);
            // A service ticket proves a PRINCIPAL, not a directory membership — but
            // the principal name is exactly what directory_groups_for() takes, and this is
            // the most AD-facing path we have, where a role granted to a group is the
            // normal way permissions are given. The helper exists for protocols that
            // know who the caller is without getting groups from authenticate(), wired it
            // into CMP, SCEP and ACME, and left this one out — so may_enrol and
            // resolve_profile below were both handed an empty list.
            a.groups = pki::directory_groups_for(st.cfg, st.db, a.user);
            // RECORD HOW THIS IDENTITY AUTHENTICATED. The ticket's own title promises
            // "local / LDAP / SAML / OIDC / Kerberos / DN" and sql/createdb.sql documents
            // `kerberos` as a value of web_users.auth_provider — but nothing wrote it, and
            // nothing could: this file never touched web_users at all, so a SPNEGO
            // principal was authorized through subject_roles and then did not exist in the
            // Users tab. Five of the six promised values had a writer; this is the sixth.
            //
            // Mirrors the EST mTLS onboarding (est/main.cpp): role `none`, no password
            // hash — the Kerberos ticket is the credential, and an empty hash cannot
            // verify, so the row does not become a second, weaker way in. The principal
            // still cannot enrol until an admin gives it a role, exactly as before; what
            // changes is that an admin can now SEE it to do so.
            if (st.db && !a.user.empty()) {
                try {
                    // ⚠️ THE ROW'S ROLE IS THE ANSWER, AND IT USED TO BE THROWN AWAY.
                    //
                    // This lookup existed only to decide whether to onboard, so an
                    // EXISTING principal's role was fetched and dropped on the floor and
                    // `a.role` stayed empty. Authorization then came from subject_roles
                    // alone — a user selector or a directory group — while the role an
                    // admin had actually set on that user, and which the console displays,
                    // decided nothing.
                    //
                    // The effect was that one identity was authorized two different ways
                    // depending on how it signed in: over Basic, authenticate() returns the
                    // row's role and it counts; over Kerberos it did not. A principal given
                    // `requester` in the console therefore held every requester grant at an
                    // EST or console login and none over SSO, which surfaces as templates
                    // that "are no longer accessible" rather than as a permission error.
                    if (auto existing = st.db->get_web_user(a.user)) {
                        a.role = existing->role;
                    } else {
                        pki::Db::WebUserRow row;
                        row.username      = a.user;
                        row.role          = "none";
                        row.auth_provider = "kerberos";
                        row.created       = static_cast<int64_t>(std::time(nullptr));
                        st.db->upsert_web_user(row);
                        a.role = row.role;
                        pki::log::info(std::string(tag) + ": onboarded Kerberos principal '" +
                                       a.user + "' with role 'none' — it cannot enrol until "
                                       "an admin assigns it a role in the console");
                    }
                } catch (const std::exception& e) {
                    // Never fail the AUTHENTICATION over a bookkeeping write: the ticket
                    // verified, and refusing here would turn a Users-tab nicety into an
                    // enrolment outage.
                    pki::log::err(std::string(tag) + ": could not record the Kerberos "
                                  "principal '" + a.user + "': " + e.what());
                }
            }
            return a;
        }
        pki::log::info(std::string(tag) + " Kerberos auth failed: " + kr.error);
    }

    // (b) HTTP Basic.
    if (authz.rfind("Basic ", 0) == 0) {
        a.method = "basic";
        auto raw = b64_decode(authz.substr(6));
        std::string creds(raw.begin(), raw.end());
        auto colon = creds.find(':');
        if (colon != std::string::npos) {
            try {
                auto r = pki::authenticate(st.cfg, creds.substr(0, colon),
                                           creds.substr(colon + 1), st.db, req.remote_addr);
                if (r.ok) {
                    // ⚠️ r.subject, NOT what the client typed — and there are TWO auth
                    // paths in this file (Basic here, UsernameToken below). Changing one
                    // and not the other is the second-gate shape: a qualified login would
                    // authorize correctly over one transport and be refused over the
                    // other, for the same account.
                    a.ok = true; a.user = r.subject; a.role = r.role;
                    a.groups = std::move(r.groups);
                    return a;
                }
            } catch (const std::exception& e) {
                pki::log::err(std::string(tag) + " basic auth error: " + e.what());
            }
        }
    }

    // (c) WS-Security UsernameToken (SOAP body).
    if (doc) {
        auto user = doc->text("Username");
        auto pass = doc->text("Password");
        if (user && pass) {
            a.method = "usernametoken";
            try {
                auto r = pki::authenticate(st.cfg, *user, *pass, st.db, req.remote_addr);
                if (r.ok) { a.ok = true; a.user = r.subject; a.role = r.role;
                            a.groups = std::move(r.groups); return a; }   // see the Basic path above
            } catch (const std::exception& e) {
                pki::log::err(std::string(tag) + " auth error: " + e.what());
            }
        }
    }
    return a;
}

// The failed-authentication audit event, shared for the same reason as the ladder.
// ONE function for both outcomes, because an audit trail that records only
// failures shows attacks and typos but not use — and the successful authentication is the
// one that establishes trust, which is what an auditor asks about and what an incident
// review needs to reconstruct which identities were active.
//
// It is also what made the reporter's own debugging harder than it needed to be: when the
// request finally succeeded the server said nothing, which is indistinguishable from the
// request never arriving, and it read as a routing failure.
//
// `ok` rather than a second near-identical function: the two would drift, and the only
// differences are the action and the status.
void ms_audit_auth(State& st, const httplib::Request& req, const std::string& protocol,
                   const std::string& actor, const std::string& method, bool ok,
                   const std::string& ca_id = "") {
    try {
        pki::AuditEvent ev;
        ev.category = pki::audit_cat::kAuth;
        ev.action   = ok ? "auth_ok" : "auth_fail";
        ev.actor    = actor;
        ev.actor_ip = req.remote_addr;
        ev.status   = ok ? pki::audit_status::kSuccess : pki::audit_status::kFailure;
        ev.detail   = "protocol=" + protocol + (method.empty() ? "" : " method=" + method) +
                      (ca_id.empty() ? "" : " ca=" + ca_id);
        st.db->append_audit(ev);
    } catch (const std::exception& e) {
        // An audit failure must not fail an otherwise good request, but it must be loud.
        pki::log::err(protocol + " audit append failed: " + e.what());
    }
}

// Issue from `ca_cert`/`ca_key` — the CA named by `instance_id` — rather than
// the global SIGNING_CA_*, so MS-WSTEP is id-based like EST/ACME/SCEP/CMP. The
// caller resolves and tenant-binds the instance; here it is already trusted.
void handle_wstep(State& st, const httplib::Request& req, httplib::Response& res,
                  X509* ca_cert, EVP_PKEY* ca_key, const std::string& instance_id,
                  const std::vector<std::shared_ptr<X509>>& ca_chain) {
    debug_log_request("WSTEP", req);
    // ONE parse for the whole request. This body is unauthenticated attacker input,
    // and handle_wstep needs four values out of it — re-parsing per value would build the
    // DOM four times for every request that reaches us.
    auto doc = pki::XmlDoc::parse(req.body);
    if (!doc) {
        // Malformed, oversized, or carrying a DOCTYPE. There is no recovered parse and no
        // MessageID to correlate a fault with, so this is a flat refusal.
        res.status = 400;
        res.set_content("malformed SOAP request", "text/plain");
        return;
    }
    const std::string msg_id = doc->text("MessageID").value_or("");
    // 1. Extract the PKCS#10 (BinarySecurityToken, base64 DER).
    auto bst = doc->text("BinarySecurityToken");
    if (!bst) { res.status = 400; res.set_content("missing BinarySecurityToken", "text/plain"); return; }

    // 2. Authenticate — ms_authenticate() is now the single ladder, shared with XCEP.
    const pki::XmlDoc* adoc = doc ? &*doc : nullptr;
    const MsAuth auth = ms_authenticate(st, req, adoc, "WSTEP");
    std::string role      = auth.role;
    std::string auth_user = auth.user;
    const std::vector<std::string>& groups = auth.groups;
    const bool authed     = auth.ok;
    const std::string& method = auth.method;
    const std::string krb_ktab = krb_merged_keytab(st);
    const bool krb_configured = !krb_ktab.empty();
    auto user = doc->text("Username");

    if (!authed) {
        // Audit: failed authentication is a mandatory security event.
        try {
            pki::AuditEvent ev;
            ev.category = pki::audit_cat::kAuth;
            ev.action   = "auth_fail";
            ev.actor    = auth_user.empty() ? user.value_or("") : auth_user;
            ev.actor_ip = req.remote_addr;
            ev.status   = pki::audit_status::kFailure;
            ev.detail   = "protocol=MS-WSTEP" + (method.empty() ? "" : " method=" + method);
            st.db->append_audit(ev);
        } catch (const std::exception& e) {
            pki::log::err(std::string("WSTEP audit append failed: ") + e.what());
        }
        // A WS-Security UsernameToken (a SOAP-body credential) that fails to
        // authenticate is a WS-Trust error → a soap:Fault, not an HTTP 401 Basic
        // challenge. Otherwise the WCF client reports "server requires basic auth"
        // instead of an authentication failure. SOAP 1.2 sends faults
        // with HTTP 500 and application/soap+xml. Failed *transport* auth (HTTP
        // Basic / Negotiate-SPNEGO) stays a 401 challenge below — that's the
        // correct HTTP-layer re-challenge semantics for those schemes.
        if (method == "usernametoken") {
            res.status = 500;
            res.set_content(build_soap_fault(msg_id, "FailedAuthentication",
                                             "The security token could not be authenticated or authorized."),
                            "application/soap+xml; charset=utf-8");
            return;
        }
        // HTTP Basic/Negotiate failure or no credential at all: challenge over HTTP
        // so a Basic/Negotiate client knows to (re)authenticate (Task 1.4a.4
        // fallback matrix — advertise both).
        if (krb_configured) res.set_header("WWW-Authenticate", "Negotiate");
        res.set_header("WWW-Authenticate", "Basic realm=\"FastPKI MS-WSTEP\"");
        res.status = 401; res.set_content("unauthorized", "text/plain"); return;
    }

    // Authenticated, but may they enrol over MS-WSTEP against THIS CA?
    // A refusal is a WS-Trust authorization failure, not a transport challenge — the
    // credentials were accepted, so re-presenting them cannot help. A UsernameToken
    // caller gets a soap:Fault for the same reason a failed one does: the WCF
    // client reports an HTTP 401 as "server requires basic auth", which describes the
    // wrong problem.
    if (!pki::may_enrol(*st.db, auth_user, role, "ms:enrol", instance_id, groups)) {
        try {
            pki::AuditEvent ev;
            ev.category = pki::audit_cat::kAuth;
            ev.action   = "authz_fail";
            ev.actor    = auth_user;
            ev.actor_ip = req.remote_addr;
            ev.target   = instance_id;
            ev.status   = pki::audit_status::kFailure;
            ev.detail   = "protocol=MS-WSTEP need=ms:enrol ca=" + instance_id;
            st.db->append_audit(ev);
        } catch (const std::exception& e) {
            pki::log::err(std::string("WSTEP authz audit append failed: ") + e.what());
        }
        // The refusal names the GRANT that would fix it. `WSTEP 403 — FASTPKI-WIN$
        // lacks ms:enrol on issuing` was a correct diagnosis in one line; what it could
        // not say was WHICH grant to write, and for a machine
        // account the answer is not "assign a role to the computer" (there is no account
        // to assign it to) but "grant a role to a group the computer is in". Naming the
        // roles the subject actually holds is the other half — "none" and "holds a role
        // that lacks this permission" are different problems with the same 403.
        pki::log::info("WSTEP 403 — " + std::string(pki::principal_kind_name(auth_user)) +
                       " " + auth_user + " holds roles [" +
                       pki::effective_roles(*st.db, auth_user, role, groups) +
                       "], none granting ms:enrol scoped to " + instance_id +
                       ". Fix: give one of its roles the permission ms:enrol with scope " +
                       instance_id + (pki::is_computer_principal(auth_user)
                         ? " — a domain computer has no account of its own, so grant the "
                           "role to a group it belongs to (Domain Computers is its primary "
                           "group; FastPKI resolves primary membership)."
                         : "."));
        if (method == "usernametoken") {
            res.status = 500;
            res.set_content(build_soap_fault(msg_id, "FailedAuthentication",
                                             "This account is not permitted to enrol against this CA."),
                            "application/soap+xml; charset=utf-8");
            return;
        }
        res.status = 403;
        res.set_content("forbidden: this account may not enrol over MS-WSTEP against " +
                        instance_id, "text/plain");
        return;
    }


    try {
        // The WCF client wraps the base64 PKCS#10 with XML carriage-return character
        // references (&#xD;) as line breaks. libxml2 decodes those for us, so the
        // hand-rolled four-entity stripper that used to live here is gone — it only
        // handled the exact spellings &#xD; &#13; &#xA; &#10;, so &#x0D; or &#xd; from a
        // different client would have survived it and corrupted the base64.
        std::string b64;
        for (char c : *bst) if (!std::isspace(static_cast<unsigned char>(c))) b64 += c;
        auto der = b64_decode(b64);
        // A Windows client submits a CMC full PKI request, not a bare PKCS#10; every other
        // client we have sends the PKCS#10 itself. cmc_extract_pkcs10() returns empty for
        // anything that is not a CMC, so the older path is unchanged.
        const char* token_kind = "PKCS#10";
        if (auto inner = pki::cmc_extract_pkcs10(der.data(), der.size()); !inner.empty()) {
            der = std::move(inner);
            token_kind = "CMC";
        }
        pki::log::info(std::string("WSTEP: ") + token_kind + " request from '" +
                       (auth_user.empty() ? std::string("<anonymous>") : auth_user) + "'");
        std::string_view sv(reinterpret_cast<const char*>(der.data()), der.size());
        auto csr = pki::parse_csr(sv);

        // The three per-role issuance limits. Below the parse, because two of
        // the three are questions about what this CSR asks for.
        //
        // ⚠️ The refusal has to be encoded the way THIS protocol's clients read, exactly as
        // the authorization refusal above is. A UsernameToken caller gets a soap:Fault
        // because the WCF client reports a bare HTTP status as "server requires basic auth",
        // which describes the wrong problem entirely.
        // ⚠️ CARRIED OUT OF THE BLOCK so the cap is enforced WITH the insert further
        // down. It stays unset when no subject was authenticated, which is the same
        // condition this block already guards on: a cap needs somebody to cap.
        std::optional<int> enrol_cap;
        if (!auth_user.empty()) {
            // `groups` is the caller's, from ms_authenticate — the same list the
            // enrolment gate used. Without it a group-granted role carries no cap.
            const auto lim = pki::role_limits(*st.db, auth_user, role, groups);
            enrol_cap = lim.max_certs;
            const std::string why = pki::role_limit_refusal(
                *st.db, lim, auth_user, pki::name_cn(X509_REQ_get_subject_name(csr.get())),
                static_cast<int>(pki::csr_sans(csr.get()).size()));
            if (!why.empty()) {
                pki::log::info("WSTEP: refusing '" + auth_user + "' — " + why);
                if (method == "usernametoken") {
                    res.status = 500;
                    res.set_content(build_soap_fault(msg_id, "FailedAuthentication",
                                                     "Issuance limit reached: " + why),
                                    "application/soap+xml; charset=utf-8");
                    return;
                }
                res.status = 429;
                res.set_content(why, "text/plain");
                return;
            }
        }

        // THE TEMPLATE IS THE POLICY HERE, not a profile.
        //
        // Profiles and templates are identically resources and semantically the same:
        // profiles apply to every protocol except MS-WSTEP, templates only to MS-WSTEP.
        // This used to resolve a PROFILE with the
        // requested template hardcoded empty, so a client asking for `GenericComputer` got
        // whatever a profile tiebreak picked — and the issued certificate then carried the
        // template name it had never honoured. `template:use` gated only the console
        // catalogue and changed nothing about issuance.
        //
        // The template is converted to a CertProfile and passed as `profile_override`, so
        // "if CSR does not match the template, the request should be denied" is enforced by
        // the same enforce_issuance_policy() every other protocol uses. There is still one
        // policy engine; only its input is template-shaped.
        const std::string want_tmpl = pki::csr_requested_template(csr.get(), st.templates);
        pki::MsTemplate  tmpl;
        pki::CertProfile tprof;
        try {
            tmpl  = pki::resolve_ms_template(
                        *st.db, pki::ProfileIdentity{auth_user, role, groups},
                        want_tmpl, st.templates);
            tprof = pki::profile_from_ms_template(tmpl);
        } catch (const std::exception& e) {
            // ⚠️ Encoded the way THIS protocol's clients read, exactly like the authz and
            // issuance-limit refusals above: a UsernameToken caller shown a bare HTTP
            // status reports it as "server requires basic auth", which names the wrong
            // problem entirely.
            pki::log::info("WSTEP refused '" + auth_user + "' (template=" +
                           (want_tmpl.empty() ? "<none requested>" : want_tmpl) + "): " +
                           e.what());
            if (method == "usernametoken") {
                res.status = 500;
                res.set_content(build_soap_fault(msg_id, "FailedAuthentication", e.what()),
                                "application/soap+xml; charset=utf-8");
                return;
            }
            res.status = 403;
            res.set_content(e.what(), "text/plain");
            return;
        }
        // The one template rule a CertProfile cannot carry.
        if (const std::string why = pki::ms_template_key_refusal(tmpl, csr.get());
            !why.empty()) {
            pki::log::info("WSTEP refused '" + auth_user + "': " + why);
            if (method == "usernametoken") {
                res.status = 500;
                res.set_content(build_soap_fault(msg_id, "FailedAuthentication", why),
                                "application/soap+xml; charset=utf-8");
                return;
            }
            res.status = 403;
            res.set_content(why, "text/plain");
            return;
        }
        pki::IssuanceInput in{
            .cfg = st.cfg, .ca_cert = ca_cert, .ca_key = ca_key,
            .csr = csr.get(), .owner_username = auth_user, .profile = tmpl.name
        };
        in.profile_override = &tprof;
        // WHO THE CERTIFICATE IS FOR IS THE TEMPLATE'S DECISION, NOT THE REQUESTER'S.
        //
        // The name flags carry an enrollee-supplies-subject grant. Where a template does
        // not give it, the directory is authoritative and the CA constructs the name — so
        // the requested subject and subjectAltName are discarded and the name is bound to
        // the principal who actually authenticated.
        //
        // ⚠️ Nothing here used to set the subject at all, so the CSR's name was copied
        // verbatim onto every certificate this endpoint issued. Any caller who could enrol
        // under a template could therefore obtain a client-auth certificate carrying
        // somebody else's common name or UPN — the policy was advertised in the enrolment
        // policy document and enforced nowhere. Templates are checked and enforced the same
        // way profiles are; this is the half of that which the profile engine cannot see,
        // because a profile has no opinion about whose name it is.
        if (!pki::ms_template_enrollee_supplies_subject(tmpl)) {
            // ⚠️ THE PROVIDER IS NOT PART OF THE PERSON'S NAME. `auth_user` is the
            // provider-qualified subject -- `<directory>\\user` for a directory identity --
            // and putting that whole string here would put a backslash inside the
            // commonName, which is the defect include/pki/x509.hpp spells out and the
            // console was fixed for. The provider goes in its own domainComponent, so two
            // directories asserting one username are still told apart without the CN
            // ceasing to be a name.
            in.subject_cn      = pki::subject_user(auth_user);
            in.subject_domain  = pki::subject_provider(auth_user);
            in.replace_subject = true;
        }
        // Keep the Microsoft certificate-template identity a Windows client puts
        // in its CSR (szOID_ENROLL_CERTTYPE_EXTENSION / szOID_CERTIFICATE_TEMPLATE)
        // on the issued cert, like a real AD CA does — needed for autoenrollment /
        // renewal correlation and template-based filtering.
        in.passthrough_ext_oids = { "1.3.6.1.4.1.311.20.2", "1.3.6.1.4.1.311.21.7" };
        // Bake the AIA/CDP of the CA that actually signs this cert. (Before the
        // per-CA route existed this was hardcoded to the magic string "default".)
        pki::CaUrls urls = pki::ca_urls_for_instance(*st.db, st.cfg, instance_id);
        in.ca_urls = &urls;
        auto cert = pki::issue_cert(in);

        pki::CertRow row;
        row.serial = pki::x509_serial_hex(cert.get());
        row.status = 0;
        // Read from the CERTIFICATE, never the clock. Issuance does not use
        // cert_validity_days verbatim — the profile's max_validity_days can cap it, and
        // notBefore is backdated — so a clock-derived row describes a certificate
        // that does not exist. These columns drive the CA-chain liveness filter, expiry
        // notification and the reissue schedule, all of which then answer about the wrong
        // certificate.
        row.not_before = pki::x509_not_before_unix(cert.get());
        row.not_after  = pki::x509_not_after_unix(cert.get());
        row.cn = pki::x509_cn(cert.get());
        row.subject = row.cn;
        row.owner = auth_user;
        row.cert_der = pki::x509_to_der(cert.get());
        row.fingerprint = pki::x509_fingerprint_sha256_hex(cert.get());
        row.ca_instance_id = instance_id;   // partition key
        // ⚠️ THE CAP IS DECIDED WITH THE WRITE. The pre-flight above refuses early with a
        // SOAP fault the Windows client renders; this is the one that cannot be raced,
        // because the count and the insert are one transaction under a per-owner lock.
        if (enrol_cap && !row.owner.empty()) {
            if (!st.db->insert_cert_within_quota(row, row.owner, *enrol_cap)) {
                pki::log::info("MS-WSTEP: refusing '" + row.owner +
                               "' — certificate limit of " +
                               std::to_string(*enrol_cap) + " reached");
                res.status = 500;
                res.set_content(build_soap_fault(msg_id, "FailedAuthentication",
                                                 "Issuance limit reached"),
                                "application/soap+xml; charset=utf-8");
                return;
            }
        } else {
            st.db->insert_cert(row);
        }

        // Audit: record MS-WSTEP issuance.
        try {
            pki::AuditEvent ev;
            ev.category = pki::audit_cat::kLifecycle;
            ev.action   = "cert_issued";
            ev.actor    = auth_user;
            ev.actor_ip = req.remote_addr;
            ev.target   = row.serial;
            ev.status   = pki::audit_status::kSuccess;
            ev.detail   = "protocol=MS-WSTEP cn=" + row.cn +
                          " role=" + pki::effective_roles(*st.db, auth_user, role, groups) +
                          " ca_instance=" + instance_id;
            st.db->append_audit(ev);
        } catch (const std::exception& e) {
            pki::log::err(std::string("WSTEP audit append failed: ") + e.what());
        }

        std::string cert_b64 = b64_encode(row.cert_der.data(), row.cert_der.size());
        // CMC full PKI response (signed by the CA) for the RSTR's PKCS7 token.
        auto p7 = build_cmc_full_response(cert.get(), ca_cert, ca_key, ca_chain);
        std::string p7_b64 = b64_encode(p7.data(), p7.size());
        pki::log::info("WSTEP issued serial=" + row.serial + " user=" + auth_user +
                       " ca_instance=" + instance_id);

        res.status = 200;
        res.set_content(build_wstep_response(cert_b64, p7_b64, msg_id),
                        "application/soap+xml; charset=utf-8");
    } catch (const pki::Error& e) {
        pki::log::err(std::string("WSTEP error: ") + e.what());
        res.status = (e.code() == 1) ? 400 : 500;
        res.set_content(e.what(), "text/plain");
    }
}

// ── per-CA route plumbing ──────────────────────────────────────────────────
// Resolve the /{ca_id} segment of an MS route and hand back that CA's material.
// Mirrors the EST/SCEP/CMP contract exactly: unknown or another tenant's id → 404
// (indistinguishable, so a foreign tenant can't probe for which CAs exist),
// disabled → 503. `hold_*` own any freshly loaded material for the call's
// duration; the returned raw pointers may instead alias the preloaded globals.
struct MsSite {
    X509*       cert{nullptr};
    EVP_PKEY*   key{nullptr};
    std::string id;
    pki::LoadedCa held;         // keeps cert/key alive for the request (shared with the cache)
};

bool resolve_ms_site(State& st, const std::string& id, const httplib::Request& req,
                     httplib::Response& res, MsSite& out) {
    (void)req;
    // Resolve + load from the DB via the cache — no preloaded global. The
    // cache re-checks the row each call and reloads only on a reference change, so the
    // pkcs11 key isn't re-read per request.
    int code = 500; std::string err;
    auto m = st.ca_cache->get(*st.db, st.cfg, id, code, err);
    if (!m) { res.status = code; res.set_content(err, "text/plain"); return false; }
    out.held = *m;
    out.id   = out.held.id;
    out.cert = out.held.cert.get();
    out.key  = out.held.key.get();
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (pki::handled_version_flag(argc, argv)) return 0;
    std::string conf_path = "config/bootstrap.conf";
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) conf_path = argv[++i];
        else if (std::strcmp(argv[i], "--help") == 0) {
            std::cout << "Usage: fastpki-ms [--config path]\n";
            return 0;
        }
    }

    OpenSSL_add_all_algorithms();

    try {
        State st;
        st.cfg = pki::Config::load(conf_path);
        if (st.cfg.log_level == "debug") pki::log::set_level(pki::log::Level::Debug);
        else if (st.cfg.log_level == "info") pki::log::set_level(pki::log::Level::Info);

        std::unique_ptr<pki::Db> db_owner;
        db_owner = pki::make_postgres_db(st.cfg.pg_conninfo);
        st.db = db_owner.get();
        pki::overlay_config(st.cfg, st.db->get_config());   // DB config overlay

        // ⚠️ RE-APPLIED AFTER overlay_config, AND THAT IS THE WHOLE POINT. The level was
        // set above from bootstrap.conf ALONE, so LOG_LEVEL=debug in the `config` table — the
        // console's Config page, which is where an operator actually sets it — reached
        // st.cfg only here and never reached the logger at all. The reported symptom is
        // exactly that: "nothing is written in the logs even when LOG_LEVEL is set to
        // DEBUG in the Config table", which reads as a product with no diagnostics rather
        // than as a setting that was silently ignored.
        //
        // Applied TWICE on purpose. The early call governs anything logged before the
        // database is reachable — a bad conninfo, a dead token — which the DB obviously
        // cannot configure. This one governs everything after, and the DB is the source of
        // truth once it can be read.
        //
        // Same shape as the AUTH_BACKEND and SCEP-challenge lines fixed earlier in this
        // family: a value read before the overlay describes bootstrap.conf, not the deployment.
        if (st.cfg.log_level == "debug") pki::log::set_level(pki::log::Level::Debug);
        else if (st.cfg.log_level == "info") pki::log::set_level(pki::log::Level::Info);
        else pki::log::set_level(pki::log::Level::Err);
        pki::load_allowed_domains(st.cfg, *st.db);
        pki::resolve_datacenter_prefix(st.cfg, *st.db);
        resolve_xcep_guid(st);   // this node's own policy id, minted once

        // ⚠️ AFTER overlay_config, and that is the whole point. This ran BEFORE it, so it
        // reported the value in bootstrap.conf rather than the effective one — an operator who
        // set AUTH_BACKEND=ldap in the console still read
        //
        //     WARNING: AUTH_BACKEND=none — MS-WSTEP accepts any username/password
        //
        // at every start, forever. A log line that lies about an AUTHENTICATION posture is
        // the worst kind: the reader either believes it and hunts a hole that is not there,
        // or learns to distrust the log. Same defect fixed for the SCEP challenge in
        // e47051f; this is the same shape in another binary.
        // Same as EST — the value this warned about no longer parses, so the
        // branch that printed it could never be true again.
        pki::log::info("MS-WSTEP password auth backend: " + st.cfg.auth_backend);

        // ── Kerberos realm + KDCs, rendered into a krb5.conf ─────────────────────────
        // Windows does not use krb5.conf, so nothing told our krb5 library where the KDCs
        // are: without this it falls back to `_kerberos._tcp.REALM` SRV lookups against
        // whatever resolver this container has, which on a lab node is not the AD DNS —
        // and the failure is a timeout, not a message naming the cause.
        //
        // ⚠️ DERIVED FROM THE DIRECTORIES WHEN THE KEYS ARE UNSET, because both facts are
        // already recorded there and a second copy is a second thing to keep in step. A
        // directory's DNS root upper-cased IS the realm, and its own URIs name its domain
        // controllers, which ARE the KDCs. The keys exist for the deployment whose KDCs
        // are not its LDAP servers.
        // ⚠️ EVERY DIRECTORY THAT HAS A KEYTAB, not one global realm. A deployment with
        // two AD domains has two of each, and krb5 reads them all from one [realms]
        // section -- so the file lists every configured domain and the first supplies
        // default_realm.
        //
        // Nothing is stored twice: a directory's DNS root upper-cased IS its realm, and
        // its own URIs name its domain controllers, which ARE its KDCs. The old
        // MS_KERBEROS_REALM / MS_KERBEROS_KDCS keys were overrides for a deployment whose
        // KDCs are not its LDAP servers; they are gone with the global keytab, because a
        // single value cannot describe two domains and a per-directory override that
        // nobody had asked for would be inventing a requirement.
        {
            std::vector<std::pair<std::string, std::string>> realms;
            try {
                for (const auto& p : pki::ldap_providers(st.cfg, st.db)) {
                    if (!p.enabled || p.dns_root.empty()) continue;
                    if (!krb_keytab_usable(p.krb_keytab)) continue;   // no key: nothing to accept
                    std::string kdcs;
                    for (const auto& u : p.uris) {
                        const auto sep = u.find("://");
                        std::string h = (sep == std::string::npos) ? u : u.substr(sep + 3);
                        const auto colon = h.find(':');
                        if (colon != std::string::npos) h.resize(colon);   // drop the port
                        const auto slash = h.find('/');
                        if (slash != std::string::npos) h.resize(slash);   // drop any path
                        if (!h.empty()) kdcs += (kdcs.empty() ? "" : ",") + h;
                    }
                    realms.emplace_back(p.realm(), kdcs);
                }
            } catch (const std::exception& e) {
                pki::log::err(std::string("MS-XCEP: could not read the directories for a "
                                          "Kerberos realm: ") + e.what());
            }
            // ⚠️ SAY SO WHEN THERE ARE KEYS BUT NO REALM. A directory can carry a keytab
            // and no DNS root, and then nothing is rendered -- SPNEGO falls back to DNS SRV
            // discovery, which succeeds on a host whose resolver happens to reach AD and
            // fails everywhere else. The two are indistinguishable without this line.
            bool any_keytab = false;
            try {
                for (const auto& p : pki::ldap_providers(st.cfg, st.db))
                    if (p.enabled && krb_keytab_usable(p.krb_keytab)) { any_keytab = true; break; }
            } catch (...) {}
            if (realms.empty() && any_keytab)
                pki::log::err("MS-XCEP: a directory has a keytab but no Kerberos realm/KDCs "
                              "could be determined (give it a DNS root and URIs) — SPNEGO "
                              "will rely on DNS SRV discovery instead");
            if (!realms.empty()) {
                const std::string path = (std::filesystem::temp_directory_path() / "fastpki-krb5.conf").string();
                const std::string wrote = pki::krb::write_krb5_conf(realms, path);
                if (!wrote.empty()) {
                    std::string names;
                    for (const auto& [r, k] : realms) names += (names.empty() ? "" : ", ") + r + " (" + k + ")";
                    pki::log::info("MS-XCEP Kerberos realms: " + names + " — wrote " + wrote);
                } else {
                    // ⚠️ SAY SO. A keytab with no realm still ACCEPTS a ticket on a host
                    // whose resolver happens to reach AD, and fails everywhere else — the
                    // difference between the two is invisible without this line.
                    pki::log::err("MS-XCEP: a directory has a keytab but no Kerberos realm/KDCs "
                                  "could be determined (give each directory a DNS root and "
                                  "URIs) — SPNEGO will rely on DNS SRV discovery instead");
                }
            }
        }

        // No signing CA is preloaded — XCEP/WSTEP resolve their CA per request
        // from the DB via the cache (the /{ca_id} routes by id; the base paths by the
        // primary designation), so a CA-less deploy starts.
        pki::CaMaterialCache ca_cache;
        st.ca_cache = &ca_cache;

        // Certificate templates: serve the templates imported from AD
        // into the ms_templates table; when none are configured, fall back to the
        // built-in defaults so a fresh install keeps working.
        st.templates = st.db->list_ms_templates(/*enabled_only=*/true);
        const bool from_db = !st.templates.empty();
        if (!from_db) st.templates = pki::default_ms_templates();
        pki::log::info("MS-XCEP serving " + std::to_string(st.templates.size()) +
                       " certificate template(s) " + (from_db ? "(from DB)" : "(built-in defaults)"));

        // Come up on a temporary self-signed cert when no CA-issued MS cert exists
        // yet (CA-less deploy) instead of crash-looping; a real cert on disk wins on the
        // next start. See pki::resolve_transport_cert.
        auto ms_tc = pki::resolve_transport_cert(*st.db, st.cfg.ms_cert_id, st.cfg.ms_server_cert_pem, st.cfg.ms_server_key_pem, st.cfg, st.cfg.pki_dns, st.cfg.ms_key);
        std::unique_ptr<httplib::SSLServer> ms_srv_owner;
        if (ms_tc.use_files) {
            ms_srv_owner = std::make_unique<httplib::SSLServer>(
                st.cfg.ms_server_cert_pem.c_str(), st.cfg.ms_server_key_pem.c_str());
            pki::log_transport_cert("ms", ms_tc, st.cfg.pki_dns);
        } else {
            auto tc_ptr = std::make_shared<pki::TransportCert>(std::move(ms_tc));
            httplib::tls::ContextSetupCallback cb =
                [tc_ptr](void* ctx) { return pki::load_tls_context(ctx, *tc_ptr); };
            ms_srv_owner = std::make_unique<httplib::SSLServer>(cb);
            // Say which certificate we ACTUALLY came up on. This branch is taken for
            // both outcomes, so announcing "TEMPORARY self-signed" unconditionally told
            // every correctly-configured deployment the opposite of the truth.
            pki::log_transport_cert("ms", *tc_ptr, st.cfg.pki_dns);
            // Serve a renewal as soon as renew-service-certs publishes one (transport_reload.hpp).
            if (ms_srv_owner->is_valid())
                pki::serve_renewed_transport_certs(ms_srv_owner->tls_context(), st.db, st.cfg,
                                                   st.cfg.ms_cert_id, *tc_ptr, "ms");
        }
        httplib::SSLServer& srv = *ms_srv_owner;
        srv.set_payload_max_length(1 * 1024 * 1024); // 1 MiB cap on SOAP bodies
        // MS is id-based like every other enrolment protocol —
        // <xcep_path>/{ca_id} and <wstep_path>/{ca_id} resolve the named CA. There is no
        // default CA, so the base (no-id) paths 404, exactly like EST/ACME/SCEP/CMP.
        // Windows names the CA id in its enrolment URL: the XCEP URL is configurable
        // (GPO/registry), and GetPolicies then hands the client that CA's own id-bearing
        // WSTEP URI in <cAs><cA><uris><cAURI><uri>, so the whole flow stays id-based.
        auto do_xcep = [&](const httplib::Request& req, httplib::Response& res,
                           const std::string& ca_id) {
            debug_log_request("XCEP", req);
            // XCEP only wants MessageID, but the parse still gates on the body
            // being well-formed and DOCTYPE-free before we echo anything back.
            auto xdoc = pki::XmlDoc::parse(req.body);
            const std::string msg_id = xdoc ? xdoc->text("MessageID").value_or("") : "";

            // AUTHENTICATE. GetPolicies used to read no credential at all — the
            // policy endpoint was open while WSTEP, in this same binary, ran the full
            // ladder. MS-XCEP is normally authenticated by Microsoft, and there is no
            // reason not to follow MS: Windows fronts XCEP with IIS auth (Kerberos/NTLM/Basic/client
            // cert); the same ladder WSTEP uses is our equivalent.
            //
            // ⚠️ A 401 WITH A CHALLENGE, never a soap:Fault. This is the FIRST call a
            // Windows autoenrolment client makes, before it holds any credential context,
            // and it expects to be challenged and to retry with Negotiate. A fault here
            // would end the flow instead of starting it — which is why the UsernameToken
            // fault path that WSTEP needs is deliberately NOT copied here.
            const pki::XmlDoc* adoc = xdoc ? &*xdoc : nullptr;
            const MsAuth xauth = ms_authenticate(st, req, adoc, "XCEP");
            if (!xauth.ok) {
                ms_audit_auth(st, req, "MS-XCEP", xauth.user, xauth.method, false, ca_id);
                pki::log::info("XCEP 401 — no accepted credential (" +
                               (xauth.method.empty() ? std::string("none offered")
                                                     : "method=" + xauth.method) + ")");
                if (!krb_merged_keytab(st).empty())
                    res.set_header("WWW-Authenticate", "Negotiate");
                res.set_header("WWW-Authenticate", "Basic realm=\"FastPKI MS-XCEP\"");
                res.status = 401;
                res.set_content("unauthorized", "text/plain");
                return;
            }
            // Record the SUCCESS too — actor, how they authenticated, and which CA's
            // policy they read. Everything here is already in MsAuth; only the call was
            // missing, so the trail could not answer "who successfully retrieved enrolment
            // policy, and how did they authenticate?".
            ms_audit_auth(st, req, "MS-XCEP", xauth.user, xauth.method, true, ca_id);
            pki::log::info("XCEP authenticated " +
                           (xauth.user.empty() ? std::string("(anonymous)") : xauth.user) +
                           " via " + (xauth.method.empty() ? std::string("unknown") : xauth.method) +
                           " for CA '" + ca_id + "'");

            // ⚠️ AUTHENTICATION ONLY, no ms:enrol check. GetPolicies hands back the
            // template catalogue, not a certificate; a subject who may sign in but not
            // enrol should still be able to read the policy and then be refused at WSTEP,
            // where the refusal describes the real problem. Requiring ms:enrol here would
            // make "you cannot enrol" arrive as "there is no policy", which is the shape
            // that sends the reader to the wrong place.

            // ⚠️ AND THE CA IS RESOLVED ONLY NOW, AFTER the credential is accepted. My first
            // version resolved first, which made CA ids enumerable by anyone who could reach
            // the port: measured on all three DCs, an anonymous POST answered 401 for a real
            // id and 404 for a made-up one, so the status code alone was an oracle. Nothing
            // about which CAs exist should be readable before authenticating.
            MsSite site;
            if (!resolve_ms_site(st, ca_id, req, res, site)) return;

            // A caller is offered only the templates their roles actually grant, which is
            // what a real AD returns — a domain client sees the templates it holds Enroll
            // on and nothing else. Before this, every authenticated caller got the whole
            // catalogue while WSTEP refused anything they did not hold, so an autoenrolling
            // client would pick a template it could never obtain and retry it forever; the
            // operator saw repeated issuance failures rather than "not offered to you".
            //
            // ⚠️ GROUPS, not just the username and role. A template granted through a group
            // is invisible without them, and this is the defect shape this codebase has
            // repeated most often — here it would fail QUIETLY, as a caller whose templates
            // simply vanished from the policy response.
            std::vector<pki::MsTemplate> visible;
            {
                const auto allowed = pki::templates_for_identity(
                    *st.db, pki::ProfileIdentity{xauth.user, xauth.role, xauth.groups},
                    st.templates);
                for (const auto& t : st.templates)
                    if (t.enabled &&
                        std::find(allowed.begin(), allowed.end(), t.name) != allowed.end())
                        visible.push_back(t);
            }
            // ⚠️ ZERO IS A WARNING, AND IT IS THE MOST DIAGNOSTIC LINE THIS SERVICE EMITS.
            // A caller with no template grant gets a valid 200 carrying an EMPTY <policies>
            // list, and Windows turns that into an error naming nothing about permissions:
            // `Add-CertificateEnrollmentPolicyServer` reports WS_E_INVALID_FORMAT and
            // `certreq` reports ERROR_INVALID_PARAMETER (0x80070057). Both read as a
            // malformed policy document, which is where six disproved hypotheses went --
            // template schema, keySpec, provider, the cAURI list, the WS-Addressing headers
            // and the XSD -- while this line sat at INFO among startup chatter saying
            // exactly what was wrong.
            //
            // The count is not an error on the server's terms: authenticating and being
            // authorised for nothing is a legitimate state. But it is never what an operator
            // INTENDED, so it is logged as one.
            if (visible.empty())
                pki::log::err("XCEP offering 0 of " + std::to_string(st.templates.size()) +
                              " templates to '" + xauth.user + "' — this identity holds no "
                              "template:use/rw grant, so the policy document will be EMPTY and "
                              "the client will refuse it with a message that names no "
                              "permission. Grant a role carrying template:use on the templates "
                              "it should enrol under.");
            else
                pki::log::info("XCEP offering " + std::to_string(visible.size()) + " of " +
                               std::to_string(st.templates.size()) + " templates to '" +
                               xauth.user + "'");

            res.status = 200;
            res.set_content(build_xcep_response(st, msg_id, site.cert, site.id,
                                                ms_public_base(st, req), visible),
                            "application/soap+xml; charset=utf-8");
        };
        auto do_wstep = [&](const httplib::Request& req, httplib::Response& res,
                            const std::string& ca_id) {
            MsSite site;
            if (!resolve_ms_site(st, ca_id, req, res, site)) return;
            handle_wstep(st, req, res, site.cert, site.key, site.id, site.held.chain);
        };
        auto ms_base_404 = [](const std::string& path) {
            return [path](const httplib::Request&, httplib::Response& res) {
                res.status = 404;
                res.set_content("this endpoint is per-CA: use " + path + "/{ca_id}", "text/plain");
            };
        };
        srv.Post(st.cfg.xcep_path, ms_base_404(st.cfg.xcep_path));
        srv.Post(st.cfg.xcep_path + R"(/([^/]+))",
                 [&](const httplib::Request& req, httplib::Response& res) {
                     do_xcep(req, res, req.matches[1]);
                 });
        srv.Post(st.cfg.wstep_path, ms_base_404(st.cfg.wstep_path));
        srv.Post(st.cfg.wstep_path + R"(/([^/]+))",
                 [&](const httplib::Request& req, httplib::Response& res) {
                     do_wstep(req, res, req.matches[1]);
                 });

        // Never open the port while this protocol is switched off in the
        // console, and stop if it is switched off later.
        pki::gate_protocol(*st.db, "ms", &st.cfg,
                           [u = pki::listener_key_uri(st.cfg, st.cfg.ms_server_key_pem)] { return u; });
        std::string bound;
        if (!pki::bind_listener(srv, st.cfg.ms_bind_addr, st.cfg.ms_port, bound)) {
            std::cerr << "listen failed\n";
            return 1;
        }
        // Named after the bind: the wildcard falls back to IPv4 where there is no IPv6
        // stack, and announcing an address before it is bound can announce the wrong one.
        pki::log::info("fastpki-ms listening on " + bound + ":" +
                       std::to_string(st.cfg.ms_port) +
                       " (" + st.cfg.xcep_path + ", " + st.cfg.wstep_path +
                       ", per-CA: <path>/{ca_id})");
        if (!srv.listen_after_bind()) {
            std::cerr << "listen failed\n";
            return 1;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << '\n';
        return 1;
    }
}
