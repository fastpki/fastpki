// SAML 2.0 SP-initiated Web SSO.
//
// SECURITY MODEL (this is the whole point of the file): a SAML Response is
// attacker-reachable HTML form input. The only thing standing between it and a
// forged admin session is the XML signature on the assertion. We therefore:
//   * pin trust to the provider's own IdP certificate (its `idp_cert`) and load
//     that key directly into the verify context, so a Response's embedded
//     <KeyInfo> can NOT introduce a different signing key;
//   * require the assertion itself to be signed (enveloped) and verify the
//     signature is a direct child of the one-and-only assertion;
//   * harden against XML Signature Wrapping (XSW): exactly one <Assertion> in the
//     whole document, the signed Reference URI must equal that assertion's ID,
//     the ID must be unique, no DTD/DOCTYPE (kills XXE + entity expansion), and
//     SHA-1/MD5 signature & digest methods are rejected;
//   * validate Status=Success, Audience == our EntityID, the Conditions /
//     SubjectConfirmationData time windows (with clock skew), the ACS Recipient,
//     and InResponseTo against an AuthnRequest we actually issued.
//
// Built only with -DFASTPKI_WITH_SAML=ON (libxml2 + libxmlsec1 + zlib). Without
// it the class compiles to a disabled stub so fastpki-web links unchanged.
#include "pki/saml.hpp"
#include "pki/auth.hpp"   // qualify_subject
#include "pki/config.hpp"
#include "pki/error.hpp"
#include "pki/log.hpp"
#include "pki/xml.hpp"   // the shared xml_escape

#include <stdexcept>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <ctime>
#include <cstring>

// The whole real implementation — including `namespace pki` itself — lives inside
// the guard. Opening pki outside it left the namespace UNCLOSED in a SAML-off build
// (its closing brace is inside the guarded block), so the stub below re-opened pki
// nested inside itself: "namespace 'pki' does not enclose namespace 'SamlSp'".
#ifdef FASTPKI_WITH_SAML

namespace pki {

namespace {

std::string urlencode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') out += static_cast<char>(c);
        else { out += '%'; out += hex[c >> 4]; out += hex[c & 0xf]; }
    }
    return out;
}

// xml_escape moved to pki_lib — see include/pki/xml.hpp.

// Standard base64 (RFC 4648, with padding; no line breaks).
const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string b64_encode(const unsigned char* d, size_t n) {
    std::string o;
    o.reserve((n + 2) / 3 * 4);
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = d[i] << 16;
        if (i + 1 < n) v |= d[i + 1] << 8;
        if (i + 2 < n) v |= d[i + 2];
        o += kB64[(v >> 18) & 0x3f];
        o += kB64[(v >> 12) & 0x3f];
        o += (i + 1 < n) ? kB64[(v >> 6) & 0x3f] : '=';
        o += (i + 2 < n) ? kB64[v & 0x3f] : '=';
    }
    return o;
}
std::string b64_decode(const std::string& s) {
    int t[256]; std::memset(t, -1, sizeof t);
    for (int i = 0; i < 64; ++i) t[(unsigned char)kB64[i]] = i;
    std::string o; int val = 0, bits = -8;
    for (unsigned char c : s) {
        if (c == '=' ) break;
        if (t[c] < 0) continue;             // skip whitespace/newlines
        val = (val << 6) | t[c]; bits += 6;
        if (bits >= 0) { o += char((val >> bits) & 0xff); bits -= 8; }
    }
    return o;
}

std::string random_id() {
    unsigned char b[16];
    // Checked: a SAML request ID is what correlates a response to the request that asked
    // for it, so a predictable one weakens replay detection.
    if (RAND_bytes(b, sizeof b) != 1)
        throw std::runtime_error("RAND_bytes failed generating a SAML ID");
    static const char* hex = "0123456789abcdef";
    std::string s = "_";                    // SAML ID is an xs:ID (NCName) -> lead with '_'
    for (unsigned char c : b) { s += hex[c >> 4]; s += hex[c & 0xf]; }
    return s;
}

std::string utc_now() {
    std::time_t now = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&now, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

} // namespace

} // namespace pki

#endif // FASTPKI_WITH_SAML


// ============================ stub build ====================================
#ifndef FASTPKI_WITH_SAML

namespace pki {

struct SamlSp::Impl {};
SamlSp::SamlSp(const Db::SamlProviderRow&) {}
SamlSp::~SamlSp() = default;
bool SamlSp::built() { return false; }
bool SamlSp::enabled() const { return false; }
std::string SamlSp::login_redirect(const std::string&, std::string&) {
    throw Error(1, "SAML not built (rebuild with -DFASTPKI_WITH_SAML=ON)");
}
SamlAssertion SamlSp::consume(const std::string&, const std::function<bool(const std::string&)>&) {
    throw Error(1, "SAML not built (rebuild with -DFASTPKI_WITH_SAML=ON)");
}
std::string SamlSp::metadata() const {
    throw Error(1, "SAML not built (rebuild with -DFASTPKI_WITH_SAML=ON)");
}

} // namespace pki

#else // ===================== real implementation ===========================

#include <zlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/valid.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/version.h>
#include <xmlsec/keys.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>
#include <xmlsec/openssl/evp.h>

#include <mutex>

namespace pki {

namespace {

const xmlChar* NS_PROTO  = BAD_CAST "urn:oasis:names:tc:SAML:2.0:protocol";
const xmlChar* NS_ASSERT = BAD_CAST "urn:oasis:names:tc:SAML:2.0:assertion";
const char* STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

// One-time libxml2 + xmlsec process init.
void ensure_xmlsec_init() {
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        xmlInitParser();
        if (xmlSecInit() < 0) return;
        if (xmlSecCheckVersion() != 1) { xmlSecShutdown(); return; }
        if (xmlSecCryptoAppInit(nullptr) < 0) { xmlSecShutdown(); return; }
        if (xmlSecCryptoInit() < 0) { xmlSecCryptoAppShutdown(); xmlSecShutdown(); return; }
        ok = true;
    });
    if (!ok) throw Error(2, "SAML: libxmlsec1 initialization failed");
}

// Raw DEFLATE (RFC 1951, no zlib header) — the HTTP-Redirect binding encoding.
std::string deflate_raw(const std::string& in) {
    z_stream zs{};
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        throw Error(2, "SAML: deflateInit2 failed");
    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
    zs.avail_in = static_cast<uInt>(in.size());
    std::string out; char buf[16384]; int rc;
    do {
        zs.next_out = reinterpret_cast<Bytef*>(buf);
        zs.avail_out = sizeof buf;
        rc = deflate(&zs, Z_FINISH);
        out.append(buf, sizeof(buf) - zs.avail_out);
    } while (rc == Z_OK);
    deflateEnd(&zs);
    if (rc != Z_STREAM_END) throw Error(2, "SAML: deflate failed");
    return out;
}

// First descendant (self-or-below, document order) with the given ns + local name.
xmlNodePtr find_desc(xmlNodePtr n, const xmlChar* ns, const char* local) {
    for (; n; n = n->next) {
        if (n->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(n->name, BAD_CAST local) &&
                n->ns && xmlStrEqual(n->ns->href, ns))
                return n;
            if (auto c = find_desc(n->children, ns, local)) return c;
        }
    }
    return nullptr;
}
int count_desc(xmlNodePtr n, const xmlChar* ns, const char* local) {
    int c = 0;
    for (; n; n = n->next)
        if (n->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(n->name, BAD_CAST local) && n->ns && xmlStrEqual(n->ns->href, ns)) ++c;
            c += count_desc(n->children, ns, local);
        }
    return c;
}
// Direct element child with ns + local name.
xmlNodePtr find_child(xmlNodePtr p, const xmlChar* ns, const char* local) {
    if (!p) return nullptr;
    for (xmlNodePtr n = p->children; n; n = n->next)
        if (n->type == XML_ELEMENT_NODE && xmlStrEqual(n->name, BAD_CAST local) &&
            n->ns && xmlStrEqual(n->ns->href, ns))
            return n;
    return nullptr;
}

std::string node_text(xmlNodePtr n) {
    if (!n) return {};
    xmlChar* c = xmlNodeGetContent(n);
    std::string s = c ? reinterpret_cast<char*>(c) : "";
    if (c) xmlFree(c);
    // trim
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    return (a == std::string::npos) ? std::string() : s.substr(a, b - a + 1);
}
std::string attr(xmlNodePtr n, const char* name) {
    if (!n) return {};
    xmlChar* v = xmlGetProp(n, BAD_CAST name);
    std::string s = v ? reinterpret_cast<char*>(v) : "";
    if (v) xmlFree(v);
    return s;
}

// Count elements anywhere in the doc carrying ID="want" (XSW: must be exactly 1).
int count_id(xmlNodePtr n, const std::string& want) {
    int c = 0;
    for (; n; n = n->next)
        if (n->type == XML_ELEMENT_NODE) {
            if (attr(n, "ID") == want) ++c;
            c += count_id(n->children, want);
        }
    return c;
}
// Register every ID attribute in the tree so xmlsec can resolve URI="#id".
void register_ids(xmlNodePtr n, xmlDocPtr doc) {
    for (; n; n = n->next)
        if (n->type == XML_ELEMENT_NODE) {
            if (xmlAttrPtr a = xmlHasProp(n, BAD_CAST "ID")) {
                xmlChar* v = xmlNodeListGetString(doc, a->children, 1);
                if (v) { xmlAddID(nullptr, doc, v, a); xmlFree(v); }
            }
            register_ids(n->children, doc);
        }
}

// Parse XSD dateTime (UTC) -> time_t. Accepts trailing 'Z', fractional seconds,
// and ±hh:mm offsets. Returns false on malformed input.
bool parse_instant(const std::string& s, std::time_t& out) {
    std::tm tm{}; int y, mo, d, h, mi, sec;
    if (std::sscanf(s.c_str(), "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &sec) != 6)
        return false;
    tm.tm_year = y - 1900; tm.tm_mon = mo - 1; tm.tm_mday = d;
    tm.tm_hour = h; tm.tm_min = mi; tm.tm_sec = sec;
    std::time_t t = timegm(&tm);
    if (t == static_cast<std::time_t>(-1)) return false;
    // Apply an explicit ±hh:mm offset if present (anything other than Z/none).
    auto tpos = s.find('T');
    auto off = s.find_first_of("+-", tpos == std::string::npos ? 0 : tpos + 1);
    if (off != std::string::npos) {
        int oh = 0, om = 0;
        if (std::sscanf(s.c_str() + off + 1, "%d:%d", &oh, &om) >= 1) {
            int delta = (oh * 3600 + om * 60) * (s[off] == '-' ? -1 : 1);
            t -= delta;   // convert local-with-offset to UTC
        }
    }
    out = t;
    return true;
}

// Reject SHA-1 / MD5 anywhere in a signature/digest method URI.
bool is_weak_alg(const std::string& uri) {
    auto has = [&](const char* w) { return uri.find(w) != std::string::npos; };
    return has("sha1") || has("#sha1") || has("md5") || has("rsa-sha1") ||
           has("ecdsa-sha1") || has("dsa-sha1") || has("hmac-sha1");
}

struct DocGuard {
    xmlDocPtr d{nullptr};
    ~DocGuard() { if (d) xmlFreeDoc(d); }
};

// Load the public key from a PEM certificate and wrap it as an xmlSecKey, using
// xmlsec's OpenSSL EVP binding directly. This sidesteps the app-level key loader
// (xmlSecCryptoAppKeyLoad) which was removed/changed in xmlsec 1.3; the EVP
// binding API is stable across 1.2 and 1.3. Returns nullptr on failure.
xmlSecKeyPtr load_pinned_signkey(const std::string& cert_path) {
    BIO* b = BIO_new_file(cert_path.c_str(), "r");
    if (!b) return nullptr;
    X509* x = PEM_read_bio_X509(b, nullptr, nullptr, nullptr);
    BIO_free(b);
    if (!x) return nullptr;
    EVP_PKEY* pk = X509_get_pubkey(x);   // own reference
    X509_free(x);
    if (!pk) return nullptr;

    xmlSecKeyDataPtr kd = xmlSecOpenSSLEvpKeyAdopt(pk);   // takes ownership of pk on success
    if (!kd) { EVP_PKEY_free(pk); return nullptr; }
    xmlSecKeyPtr key = xmlSecKeyCreate();
    if (!key) { xmlSecKeyDataDestroy(kd); return nullptr; }
    if (xmlSecKeySetValue(key, kd) < 0) {   // takes ownership of kd on success
        xmlSecKeyDataDestroy(kd);
        xmlSecKeyDestroy(key);
        return nullptr;
    }
    return key;
}

} // namespace

struct SamlSp::Impl {
    // Kept so the groups this IdP asserts can be qualified — see the note in oidc.cpp.
    // Two IdPs can each assert "Admins"; unqualified, a grant to one authorizes the other.
    std::string provider_id;
    std::string idp_entity_id, idp_sso_url, idp_cert;
    std::string sp_entity_id, sp_acs_url;
    std::string username_attr, groups_attr, admin_group, auditor_group;
    int skew{120};

    // ⚠️ THE SKEW COMES FROM THE ROW's clock_skew_sec, and an unset or non-positive value
    // falls back to 120 rather than 0, which would reject every assertion whose clocks are
    // not identical.
    // ⚠️ `groups_attr` EMPTY MEANS "NOT SET", and the assertion attribute has a
    // conventional name the flat-config path defaulted to. Left blank the SP looks for an
    // attribute called "", finds no groups on any assertion, and every federated login
    // lands with no role — which reads as an IdP that stopped sending groups.
    // `username_attr` is the exception: empty there genuinely means "use the NameID".
    explicit Impl(const Db::SamlProviderRow& r)
        : provider_id(r.id), idp_entity_id(r.idp_entity_id), idp_sso_url(r.idp_sso_url),
          idp_cert(r.idp_cert), sp_entity_id(r.sp_entity_id),
          sp_acs_url(r.sp_acs_url), username_attr(r.username_attr),
          groups_attr(r.groups_attr.empty() ? "groups" : r.groups_attr),
          admin_group(r.admin_group),
          auditor_group(r.auditor_group),
          skew(r.clock_skew_sec > 0 ? r.clock_skew_sec : 120) {}
    // Verify the assertion's enveloped signature against the pinned IdP cert.
    // Returns the verified <Assertion> node (still owned by `doc`).
    xmlNodePtr verify_signed_assertion(xmlDocPtr doc) {
        xmlNodePtr root = xmlDocGetRootElement(doc);
        if (!root) throw Error(1, "SAML: empty document");
        if (xmlGetIntSubset(doc)) throw Error(1, "SAML: DOCTYPE not allowed");   // anti-XXE
        if (!xmlStrEqual(root->name, BAD_CAST "Response") ||
            !root->ns || !xmlStrEqual(root->ns->href, NS_PROTO))
            throw Error(1, "SAML: root is not a samlp:Response");

        // Exactly one assertion in the whole document (anti-XSW).
        if (count_desc(root, NS_ASSERT, "Assertion") != 1)
            throw Error(1, "SAML: expected exactly one Assertion");
        xmlNodePtr assertion = find_desc(root, NS_ASSERT, "Assertion");
        std::string aid = attr(assertion, "ID");
        if (aid.empty()) throw Error(1, "SAML: assertion has no ID");
        if (count_id(root, aid) != 1) throw Error(1, "SAML: duplicate assertion ID");

        // The signature must be a direct child of THAT assertion (enveloped).
        xmlNodePtr sig = find_child(assertion, xmlSecDSigNs, "Signature");
        if (!sig) throw Error(1, "SAML: assertion is not signed");

        // Inspect SignedInfo: exactly one Reference, URI == "#<assertion ID>",
        // and no SHA-1/MD5 signature or digest methods.
        xmlNodePtr si = find_child(sig, xmlSecDSigNs, "SignedInfo");
        if (!si) throw Error(1, "SAML: signature has no SignedInfo");
        if (is_weak_alg(attr(find_child(si, xmlSecDSigNs, "SignatureMethod"), "Algorithm")))
            throw Error(1, "SAML: weak SignatureMethod");
        if (count_desc(si->children, xmlSecDSigNs, "Reference") != 1)
            throw Error(1, "SAML: expected exactly one signature Reference");
        xmlNodePtr ref = find_child(si, xmlSecDSigNs, "Reference");
        if (attr(ref, "URI") != "#" + aid)
            throw Error(1, "SAML: signature does not cover the assertion");
        if (is_weak_alg(attr(find_child(ref, xmlSecDSigNs, "DigestMethod"), "Algorithm")))
            throw Error(1, "SAML: weak DigestMethod");

        register_ids(root, doc);

        // Verify with the pinned cert's key loaded DIRECTLY into the context, so
        // the Response's own <KeyInfo> can never substitute the signing key.
        xmlSecDSigCtxPtr ctx = xmlSecDSigCtxCreate(nullptr);
        if (!ctx) throw Error(2, "SAML: cannot create dsig context");
        struct CtxG { xmlSecDSigCtxPtr c; ~CtxG() { if (c) xmlSecDSigCtxDestroy(c); } } cg{ctx};

        // Load just the pinned cert's public key via OpenSSL and adopt it into
        // xmlsec (the version-stable EVP binding — the app-level loader changed
        // incompatibly between xmlsec 1.2 and 1.3). With signKey preset, xmlsec
        // verifies against THIS key and the Response's own <KeyInfo> cannot
        // substitute a different one.
        ctx->signKey = load_pinned_signkey(idp_cert);
        if (!ctx->signKey) throw Error(2, "SAML: cannot load IdP certificate " + idp_cert);

        if (xmlSecDSigCtxVerify(ctx, sig) < 0)
            throw Error(1, "SAML: signature verification error");
        if (ctx->status != xmlSecDSigStatusSucceeded)
            throw Error(1, "SAML: assertion signature is INVALID");
        return assertion;
    }

    void validate_conditions_and_subject(xmlNodePtr response, xmlNodePtr assertion,
                                          const std::function<bool(const std::string&)>& known) {
        const std::time_t now = std::time(nullptr);
        auto not_before_ok = [&](const std::string& s) {
            std::time_t t; return s.empty() || (parse_instant(s, t) && now + skew >= t);
        };
        auto not_after_ok = [&](const std::string& s) {
            std::time_t t; return s.empty() || (parse_instant(s, t) && now - skew < t);
        };

        // Status = Success.
        xmlNodePtr status = find_child(response, NS_PROTO, "Status");
        xmlNodePtr sc = find_child(status, NS_PROTO, "StatusCode");
        if (attr(sc, "Value") != STATUS_SUCCESS)
            throw Error(1, "SAML: Response Status is not Success");

        // Issuer (optional pin).
        if (!idp_entity_id.empty()) {
            std::string iss = node_text(find_child(assertion, NS_ASSERT, "Issuer"));
            if (iss != idp_entity_id) throw Error(1, "SAML: unexpected assertion Issuer");
        }

        // Conditions: time window + audience.
        xmlNodePtr cond = find_child(assertion, NS_ASSERT, "Conditions");
        if (cond) {
            if (!not_before_ok(attr(cond, "NotBefore")) || !not_after_ok(attr(cond, "NotOnOrAfter")))
                throw Error(1, "SAML: assertion Conditions time window invalid");
            if (xmlNodePtr ar = find_child(cond, NS_ASSERT, "AudienceRestriction")) {
                bool match = false;
                for (xmlNodePtr a = ar->children; a; a = a->next)
                    if (a->type == XML_ELEMENT_NODE && xmlStrEqual(a->name, BAD_CAST "Audience") &&
                        node_text(a) == sp_entity_id) { match = true; break; }
                if (!match) throw Error(1, "SAML: audience does not match the SP EntityID");
            }
        }

        // Subject confirmation: time window, Recipient = our ACS, InResponseTo.
        xmlNodePtr subj = find_child(assertion, NS_ASSERT, "Subject");
        xmlNodePtr scf  = find_child(subj, NS_ASSERT, "SubjectConfirmation");
        xmlNodePtr scd  = find_child(scf, NS_ASSERT, "SubjectConfirmationData");
        std::string in_response_to = attr(response, "InResponseTo");
        if (scd) {
            if (!not_after_ok(attr(scd, "NotOnOrAfter")))
                throw Error(1, "SAML: SubjectConfirmationData expired");
            std::string recip = attr(scd, "Recipient");
            if (!recip.empty() && recip != sp_acs_url)
                throw Error(1, "SAML: SubjectConfirmationData Recipient mismatch");
            if (std::string irt = attr(scd, "InResponseTo"); !irt.empty()) in_response_to = irt;
        }
        if (in_response_to.empty() || !known(in_response_to))
            throw Error(1, "SAML: InResponseTo does not match a pending AuthnRequest");
    }
};

// The row carries exactly the fields the Config did, so this is the same object built
// from the source that can hold more than one of them.
SamlSp::SamlSp(const Db::SamlProviderRow& row) : p_(std::make_unique<Impl>(row)) {}
SamlSp::~SamlSp() = default;

bool SamlSp::built() { return true; }

bool SamlSp::enabled() const {
    return !p_->idp_sso_url.empty() && !p_->idp_cert.empty() &&
           !p_->sp_entity_id.empty() && !p_->sp_acs_url.empty();
}

std::string SamlSp::login_redirect(const std::string& relay_state, std::string& out_request_id) {
    if (!enabled()) throw Error(1, "SAML not configured");
    out_request_id = random_id();
    std::string xml =
        "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
        " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\""
        " ID=\"" + out_request_id + "\" Version=\"2.0\""
        " IssueInstant=\"" + utc_now() + "\""
        " Destination=\"" + xml_escape(p_->idp_sso_url) + "\""
        " AssertionConsumerServiceURL=\"" + xml_escape(p_->sp_acs_url) + "\""
        " ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">"
        "<saml:Issuer>" + xml_escape(p_->sp_entity_id) + "</saml:Issuer>"
        "<samlp:NameIDPolicy AllowCreate=\"true\"/>"
        "</samlp:AuthnRequest>";
    std::string defl = deflate_raw(xml);
    std::string enc = urlencode(b64_encode(reinterpret_cast<const unsigned char*>(defl.data()), defl.size()));
    std::string url = p_->idp_sso_url + (p_->idp_sso_url.find('?') == std::string::npos ? "?" : "&")
                    + "SAMLRequest=" + enc;
    if (!relay_state.empty()) url += "&RelayState=" + urlencode(relay_state);
    return url;
}

SamlAssertion SamlSp::consume(const std::string& saml_response_b64,
                              const std::function<bool(const std::string&)>& is_known_request) {
    if (!enabled()) throw Error(1, "SAML not configured");
    ensure_xmlsec_init();

    std::string xml = b64_decode(saml_response_b64);
    if (xml.empty()) throw Error(1, "SAML: empty/undecodable Response");

    DocGuard dg;
    dg.d = xmlReadMemory(xml.data(), static_cast<int>(xml.size()), "saml-response.xml",
                         nullptr, XML_PARSE_NONET);   // no network, no DTD substitution
    if (!dg.d) throw Error(1, "SAML: Response is not well-formed XML");

    xmlNodePtr assertion = p_->verify_signed_assertion(dg.d);     // throws unless trusted
    xmlNodePtr response  = xmlDocGetRootElement(dg.d);
    p_->validate_conditions_and_subject(response, assertion, is_known_request);

    SamlAssertion out;
    xmlNodePtr subj = find_child(assertion, NS_ASSERT, "Subject");
    xmlNodePtr name_id_node = find_child(subj, NS_ASSERT, "NameID");
    out.name_id = node_text(name_id_node);

    // The email attributes identity providers actually send, in this order: the claim type
    // AD FS and Entra ID use, the LDAP `mail` OID Shibboleth uses, and the two bare names.
    // An ordered list rather than a setting, because it names one fact about the person and
    // the first present answer is the same answer every time.
    static const char* kEmailAttrs[] = {
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "urn:oid:0.9.2342.19200300.100.1.3", "mail", "email"};
    const size_t kNoEmail = sizeof kEmailAttrs / sizeof kEmailAttrs[0];
    size_t email_rank = kNoEmail;

    // Attributes (groups + optional username attribute + email).
    if (xmlNodePtr as = find_child(assertion, NS_ASSERT, "AttributeStatement")) {
        for (xmlNodePtr at = as->children; at; at = at->next) {
            if (at->type != XML_ELEMENT_NODE || !xmlStrEqual(at->name, BAD_CAST "Attribute")) continue;
            std::string name = attr(at, "Name");
            for (xmlNodePtr v = at->children; v; v = v->next) {
                if (v->type != XML_ELEMENT_NODE || !xmlStrEqual(v->name, BAD_CAST "AttributeValue")) continue;
                std::string val = node_text(v);
                if (val.empty()) continue;
                if (!p_->groups_attr.empty() && name == p_->groups_attr) out.groups.push_back(qualify_subject(p_->provider_id, val));
                if (!p_->username_attr.empty() && name == p_->username_attr && out.username.empty())
                    out.username = val;
                for (size_t k = 0; k < email_rank; ++k)
                    if (name == kEmailAttrs[k]) { out.email = val; email_rank = k; break; }
            }
        }
    }
    if (out.email.empty() && name_id_node &&
        attr(name_id_node, "Format") == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        out.email = out.name_id;
    if (out.username.empty()) out.username = out.name_id;        // default: NameID is the username
    if (out.username.empty()) throw Error(1, "SAML: assertion has no usable NameID/username");
    return out;
}

std::string SamlSp::metadata() const {
    if (!enabled()) throw Error(1, "SAML not configured");
    return
        "<?xml version=\"1.0\"?>\n"
        "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\""
        " entityID=\"" + xml_escape(p_->sp_entity_id) + "\">"
        "<md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\""
        " protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
        "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified</md:NameIDFormat>"
        "<md:AssertionConsumerService"
        " Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""
        " Location=\"" + xml_escape(p_->sp_acs_url) + "\" index=\"0\"/>"
        "</md:SPSSODescriptor></md:EntityDescriptor>";
}

} // namespace pki

#endif // FASTPKI_WITH_SAML
