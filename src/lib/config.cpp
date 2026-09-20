#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/x509.hpp"
#include "pki/error.hpp"
#include "pki/log.hpp"
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

// ⚠️ THE SOCKET THE CLIENT SHIM READS, DEFAULTED HERE SO A HAND-RUN CLI WORKS. p11-kit's
// client module takes the server address from P11_KIT_SERVER_ADDRESS at C_Initialize and
// from nowhere else. The OpenRC services export it (deploy/native/openrc/fastpki.initd),
// and compose and Kubernetes put it in the pod/container environment — so every SERVICE has
// it and no operator shell does.
//
// The consequence was the first command a native or cloud deployment asks anyone to run.
// `fastpki-ca create` reached the shim with no address, and the failure surfaced as
//     pkcs11 keygen_init failed: error:40800002:pkcs11::Host out of memory
// which names memory on a node with 2.5 GB free, and a token that `--list-token-slots`
// reports as "No slots" while the token service is started and the token exists on disk.
// Nothing in that points at an environment variable.
//
// ⚠️ NOT A CONFIG KEY, for the same reason P11_TLS_DIR is not one: the path is fixed by the
// deployment layout, every shape puts the socket there, and an operator who has to be told
// about a setting has already lost the time this exists to save. A value already in the
// environment always wins, so a deployment that sets it is untouched.
static void default_p11_server_address(const pki::Config& c) {
    const char* have = std::getenv("P11_KIT_SERVER_ADDRESS");
    if (have && *have) return;
    const std::string m = c.pkcs11_module.string();
    if (m.find("p11-kit-client") == std::string::npos) return;   // a real HSM module needs none
    ::setenv("P11_KIT_SERVER_ADDRESS", "unix:path=/run/p11/pkcs11.sock", 0);
}



namespace pki {
namespace {

std::string trim(std::string s) {
    auto issp = [](unsigned char c){ return std::isspace(c); };
    s.erase(s.begin(), std::find_if_not(s.begin(), s.end(), issp));
    s.erase(std::find_if_not(s.rbegin(), s.rend(), issp).base(), s.end());
    return s;
}

}  // namespace

std::vector<std::string> split_csv(const std::string& v) {
    std::vector<std::string> out;
    std::string cur;
    for (char ch : v) {
        if (ch == ',') { if (!cur.empty()) out.push_back(trim(cur)); cur.clear(); }
        else cur += ch;
    }
    if (!cur.empty()) out.push_back(trim(cur));
    return out;
}

// Like split_csv but separates on ';' — for list values whose individual
// elements contain commas, so comma can't be the delimiter. LDAP base DNs are
// the case: "dc=corp,dc=example" is ONE base DN, and multiple are joined with
// ';' ("dc=corp,dc=example;ou=eu,dc=corp,dc=example").
std::vector<std::string> split_semi(const std::string& v) {
    std::vector<std::string> out;
    std::string cur;
    for (char ch : v) {
        if (ch == ';') { if (!trim(cur).empty()) out.push_back(trim(cur)); cur.clear(); }
        else cur += ch;
    }
    if (!trim(cur).empty()) out.push_back(trim(cur));
    return out;
}

namespace {

// std::stoi that reports which config key was bad instead of throwing an
// opaque std::invalid_argument out of Config::load.
int to_int(const std::string& key, const std::string& val) {
    try {
        size_t pos = 0;
        int n = std::stoi(val, &pos);
        if (pos != val.size()) throw std::invalid_argument("trailing chars");
        return n;
    } catch (const std::exception&) {
        throw Error(2, "config: " + key + " must be an integer, got '" + val + "'");
    }
}

// The key dispatch is split across apply1/2/3 (chained by apply()). The original reason
// was MSVC's nested-block limit (error C1061), which no longer applies — MSVC is not a
// supported compiler. The split stays because one else-if chain over every config
// key is unreadable at this length, not because a compiler demands it; add another split
// if the key list keeps growing.
bool apply1(Config& c, const std::string& key, const std::string& val) {
    if      (key == "PKI_DNS")            { c.pki_dns = val; if (c.base_url.rfind("https://pki.example.org", 0) == 0 || c.base_url.empty()) c.base_url = "https://" + val; }
    else if (key == "BASE_URL")           { c.base_url = val; c.base_url_explicit = true; }   // explicit override (proxy / non-standard port / http for testing)
    else if (key == "PKCS11_MODULE")        c.pkcs11_module = val;
    else if (key == "PKCS11_PROVIDER_PATH") c.pkcs11_provider_path = val;
    else if (key == "PKCS11_TOKEN")         c.pkcs11_token = val;
    else if (key == "PKCS11_PIN_FILE")      c.pkcs11_pin_file = val;
    // Per SERVICE, not one shared answer.
    else if (key == "WEB_KEY_ALGO")      c.web_key.algo    = val;
    else if (key == "WEB_KEY_BITS")      { try { c.web_key.bits    = std::stoi(val); } catch (...) {} }
    else if (key == "WEB_KEY_CURVE")     c.web_key.curve   = val;
    else if (key == "WEB_KEY_MD")          c.web_key.md      = val;   // digest axis
    else if (key == "EST_KEY_ALGO")      c.est_key.algo    = val;
    else if (key == "EST_KEY_BITS")      { try { c.est_key.bits    = std::stoi(val); } catch (...) {} }
    else if (key == "EST_KEY_CURVE")     c.est_key.curve   = val;
    else if (key == "EST_KEY_MD")          c.est_key.md      = val;   // digest axis
    else if (key == "ACME_KEY_ALGO")     c.acme_key.algo   = val;
    else if (key == "ACME_KEY_BITS")     { try { c.acme_key.bits   = std::stoi(val); } catch (...) {} }
    else if (key == "ACME_KEY_CURVE")    c.acme_key.curve  = val;
    else if (key == "ACME_KEY_MD")         c.acme_key.md      = val;   // digest axis
    else if (key == "MS_KEY_ALGO")       c.ms_key.algo     = val;
    else if (key == "MS_KEY_BITS")       { try { c.ms_key.bits     = std::stoi(val); } catch (...) {} }
    else if (key == "MS_KEY_CURVE")      c.ms_key.curve    = val;
    else if (key == "MS_KEY_MD")           c.ms_key.md      = val;   // digest axis
    else if (key == "PG_CONNINFO")        c.pg_conninfo = val;
    else if (key == "PG_TLS_DIR")         c.pg_tls_dir = val;
    else if (key == "PG_TLS_SANS")        c.pg_tls_sans = val;
    else if (key == "PG_TLS_CA_ID")       c.pg_tls_ca_id = val;
    else if (key == "DATACENTER_ID")          c.datacenter_id = val;
    else if (key == "OCSP_BIND")          c.ocsp_bind_addr = val;
    else if (key == "OCSP_PORT")          c.ocsp_port = to_int(key, val);
    else if (key == "CRL_PATH")           c.crl_path = val;
    // OCSP_RESPONDER_CERT is GONE, not deprecated. It named one PEM file for the
    // whole instance, and a delegated responder certificate has to be issued by the CA
    // whose status it asserts (RFC 6960 §4.2.2.2) — one file cannot be that for several
    // CAs. The certificate now lives in the DB per CA under "<OCSP_RESPONDER_CERT_ID_PREFIX>-<ca_id>".
    else if (key == "OCSP_RESPONDER_KEY")  c.ocsp_responder_key = val;
    // The key TYPE, as distinct from the URI above: what to mint when the credential is
    // created after a CA exists. Same reach as a listener — a responder answers everything.
    else if (key == "OCSP_RESPONDER_KEY_ALGO")  c.ocsp_responder_key_spec.algo  = val;
    else if (key == "OCSP_RESPONDER_KEY_BITS")  { try { c.ocsp_responder_key_spec.bits = std::stoi(val); } catch (...) {} }
    else if (key == "OCSP_RESPONDER_KEY_CURVE") c.ocsp_responder_key_spec.curve = val;
    else if (key == "SERVICE_CERT_RENEW_FRACTION") { try { c.service_cert_renew_fraction = std::stod(val); } catch (...) {} }
    else if (key == "HTTPS_CA_ID")        c.https_ca_id = val;
    else if (key == "OCSP_RESPONDER_CERT_ID_PREFIX")        c.ocsp_responder_cert_id_prefix = val;
    else if (key == "OCSP_RESPONSE_MD")    c.ocsp_response_md = val;   // digest axis
    else if (key == "CRL_NEXT_UPDATE_DAYS") c.crl_next_update_days = to_int(key, val);
    else if (key == "CRL_DELTA")          c.crl_delta_enabled = (val == "1" || val == "true" || val == "yes");
    else if (key == "OCSP_EXPIRY_SWEEP_SEC") c.ocsp_expiry_sweep_sec = to_int(key, val);
    else if (key == "CRL_CACHE_TTL_SEC")     c.crl_cache_ttl_sec = to_int(key, val);
    else if (key == "CRL_PUBLISH_SWEEP_SEC") c.crl_publish_sweep_sec = to_int(key, val);
    else if (key == "EST_BIND")           c.est_bind_addr = val;
    else if (key == "EST_CERT")           c.est_server_cert_pem = val;
    else if (key == "EST_KEY")            c.est_server_key_pem = val;
// ⚠️ AN EMPTY *_CERT_ID IS IGNORED, NOT APPLIED. These four have non-empty compiled
// defaults ("web"/"est"/"acme"/"ms") and there is no such thing as a listener with no
// cert_id, so an empty value is never a legitimate setting -- it can only arrive from a
// blank override in bootstrap.conf or, as happened on a lab DC, a blank row in the `config`
// table that overlay_config then applied over the default.
//
// It was unrecoverable rather than merely wrong: insert_cert maps an empty cert_id to SQL
// NULL (db_postgres.cpp:168) while the reader is an equality match (:1195), and
// `cert_id = ''` never matches NULL. So the listener published a transport cert it could
// never read back, and minted a fresh self-signed identity on EVERY start -- four orphaned
// rows had accumulated per listener before anyone looked.
    else if (key == "EST_CERT_ID")        { if (!val.empty()) c.est_cert_id = val; }
    else if (key == "EST_PORT")           c.est_port = to_int(key, val);
    else if (key == "EST_CSRATTRS")       c.est_csrattrs = val;
    else if (key == "EST_DEFAULT_PROFILE") c.est_default_profile = val;
    else if (key == "EST_SERVERKEYGEN")   c.est_serverkeygen = (val == "1" || val == "true" || val == "yes");
    else if (key == "EST_SERVERKEYGEN_ENCRYPT") c.est_serverkeygen_encrypt = (val == "1" || val == "true" || val == "yes");
    else if (key == "EST_SERVERKEYGEN_BITS") c.est_serverkeygen_bits = to_int(key, val);
    else if (key == "EST_CLIENT_CA_ID")     c.est_client_ca_id = val;
    else if (key == "EST_CLIENT_CA_BUNDLE") c.est_client_ca_bundle = val;
    else if (key == "ACME_BIND")          c.acme_bind_addr = val;
    else if (key == "ACME_PORT")          c.acme_port = to_int(key, val);
    else if (key == "ACME_CERT")          c.acme_server_cert_pem = val;
    else if (key == "ACME_KEY")           c.acme_server_key_pem = val;
    else if (key == "ACME_CERT_ID")        { if (!val.empty()) c.acme_cert_id = val; }
    else if (key == "ACME_BASE_PATH")     c.acme_base_path = val;
    else if (key == "NONCE_EXPIRES_SEC")  c.nonce_expires_sec = to_int(key, val);
    else if (key == "ORDER_EXPIRES_DAYS") c.order_expires_days = to_int(key, val);
    else return false;
    return true;
}
bool apply2(Config& c, const std::string& key, const std::string& val) {
    if      (key == "ACME_DNS_RESOLVER")  c.acme_dns_resolver = val;
    else if (key == "ACME_TLS_ALPN_PORT") c.acme_tls_alpn_port = to_int(key, val);
    else if (key == "ACME_NEW_AUTHZ")     c.acme_new_authz = (val == "1" || val == "true" || val == "yes");
    else if (key == "ACME_CAA_IDENTITY")  c.acme_caa_identity = val;
    else if (key == "ACME_SWEEP_SEC")     c.acme_sweep_sec = to_int(key, val);
    else if (key == "NOTIFY_DAYS")        c.notify_days = val;
    else if (key == "NOTIFY_WEBHOOK")     c.notify_webhook = val;
    else if (key == "NOTIFY_WEBHOOK_FORMAT") {
        // Refused rather than defaulted: a report sent in a shape the receiver rejects is
        // dropped with nothing downstream saying so.
        if (val != "json" && val != "slack" && val != "teams")
            throw Error(2, "config: NOTIFY_WEBHOOK_FORMAT must be 'json', 'slack' or 'teams', got '" +
                           val + "'");
        c.notify_webhook_format = val;
    }
    else if (key == "UPDATE_FEED_URL")    c.update_feed_url = val;
    else if (key == "RELEASE_PUBKEY")     c.release_pubkey = val;
    else if (key == "DISCOVER_BIN")       c.discover_bin = val;
    else if (key == "CMP_BIND")           c.cmp_bind_addr = val;
    else if (key == "CMP_PORT")           c.cmp_port = to_int(key, val);
    else if (key == "CMP_PATH")           c.cmp_path = val;
    else if (key == "CMP_EXTRACERTS_CA")  c.include_signing_ca_in_extracerts = (val == "1" || val == "true" || val == "yes");
    else if (key == "CMP_CLIENT_CA_ID")   c.cmp_client_ca_id = val;
    else if (key == "CMP_CLIENT_CA_BUNDLE") c.cmp_client_ca_bundle = val;
    else if (key == "CMP_CLIENT_CA_REFRESH_SEC") c.cmp_client_ca_refresh_sec = to_int(key, val);
    else if (key == "CMP_RA_KEY")         c.cmp_ra_key_pem = val;
    // Widest of the three: the CMP client is OpenSSL, so Ed25519/Ed448 and ML-DSA are all
    // usable here even though a TLS listener could not negotiate them.
    else if (key == "CMP_RA_KEY_ALGO")    c.cmp_ra_key_spec.algo  = val;
    else if (key == "CMP_RA_KEY_BITS")    { try { c.cmp_ra_key_spec.bits = std::stoi(val); } catch (...) {} }
    else if (key == "CMP_RA_KEY_CURVE")   c.cmp_ra_key_spec.curve = val;
    else if (key == "CMP_RA_CERT_ID_PREFIX")        c.cmp_ra_cert_id_prefix = val;
    else if (key == "MS_BIND")            c.ms_bind_addr = val;
    else if (key == "MS_PORT")            c.ms_port = to_int(key, val);
    else if (key == "MS_CERT")            c.ms_server_cert_pem = val;
    else if (key == "MS_KEY")             c.ms_server_key_pem = val;
    else if (key == "MS_CERT_ID")        { if (!val.empty()) c.ms_cert_id = val; }
    else if (key == "XCEP_PATH")          c.xcep_path = val;
    else if (key == "WSTEP_PATH")         c.wstep_path = val;
    else if (key == "MS_XCEP_GUID")       c.ms_xcep_guid = val;
    else if (key == "MS_XCEP_FRIENDLY_NAME") c.ms_xcep_friendly_name = val;
    else if (key == "MS_XCEP_NEXT_UPDATE_HOURS") {
        // ⚠️ REFUSED RATHER THAN CLAMPED. A negative cache lifetime has no meaning, and the
        // element is xs:unsignedInt on the wire, so -1 does not become "a bit less than
        // zero" — it becomes 4294967295, i.e. "cache this policy for 490,000 years". A
        // clamp would silently turn a typo into a value; refusing names the key.
        // 0 stays reachable and means "do not cache", which is distinct from unset (24).
        const int h = to_int(key, val);
        if (h < 0)
            throw Error(2, "config: MS_XCEP_NEXT_UPDATE_HOURS must be >= 0 "
                           "(0 = do not cache), got '" + val + "'");
        c.ms_xcep_next_update_hours = h;
    }
    else if (key == "STORE_BIND")         c.store_bind_addr = val;
    else if (key == "STORE_PORT")         c.store_port = to_int(key, val);
    else if (key == "WEB_BIND")           c.web_bind_addr = val;
    else if (key == "WEB_PORT")           c.web_port = to_int(key, val);
    else if (key == "WEB_TOKEN")          c.web_token = val;
    else if (key == "WEB_TLS_CERT")       c.web_tls_cert = val;
    else if (key == "WEB_TLS_KEY")        c.web_tls_key = val;
    else if (key == "WEB_CLIENT_CA")      c.web_client_ca = val;
    else if (key == "WEB_CLIENT_CA_ID")     c.web_client_ca_id = val;
    else if (key == "WEB_CLIENT_CA_BUNDLE") c.web_client_ca_bundle = val;
    else if (key == "WEB_ALLOW_REVOKE")   c.web_allow_revoke = (val == "1" || val == "true" || val == "yes");
    else if (key == "WEB_CERT_ID")        { if (!val.empty()) c.web_cert_id = val; }
    else if (key == "WEB_SELFSERVICE_IDENTITY_SUBJECT") c.web_selfservice_identity_subject = (val == "1" || val == "true" || val == "yes");
    else return false;
    return true;
}
void apply3(Config& c, const std::string& key, const std::string& val) {
    if      (key == "MCP_ALLOW_WRITE")    c.mcp_allow_write = (val == "1" || val == "true" || val == "yes");
    else if (key == "SCEP_BIND")          c.scep_bind_addr = val;
    else if (key == "SCEP_PORT")          c.scep_port = to_int(key, val);
    else if (key == "SCEP_PATH")          c.scep_path = val;
    else if (key == "SCEP_DYNAMIC_CHALLENGE") c.scep_dynamic_challenge = (val == "1" || val == "true" || val == "yes");
    else if (key == "SCEP_MANUAL_APPROVAL") c.scep_manual_approval = (val == "1" || val == "true" || val == "yes");
    else if (key == "SCEP_RA_KEY")        c.scep_ra_key_pem = val;
    // ⚠️ SIZE ONLY — there is deliberately no SCEP_RA_KEY_ALGO. The RA key decrypts the
    // PKIOperation envelope, so it must be plain RSA (keyEncipherment); offering the choice
    // would only offer a way to break SCEP, and the refusal already lives in the SCEP
    // service and the console.
    else if (key == "SCEP_RA_KEY_BITS")   { try { c.scep_ra_key_spec.bits = std::stoi(val); } catch (...) {} }
    else if (key == "SCEP_RA_CERT_ID_PREFIX")    c.scep_ra_cert_id_prefix = val;
    else if (key == "SCEP_RENEWAL")       c.scep_renewal = (val == "1" || val == "true" || val == "yes");
    else if (key == "SCEP_NEXT_CA_CERT")  c.scep_next_ca_cert_pem = val;
    else if (key == "SCEP_ALLOW_SHA1")   c.scep_allow_sha1  = (val == "1" || val == "true" || val == "yes");
    else if (key == "ALLOW_WEAK_SIGNATURE_DIGEST")
        c.allow_weak_signature_digest = (val == "1" || val == "true" || val == "yes");
    else if (key == "LOGIN_FAILURE_THRESHOLD") c.login_failure_threshold = std::atoi(val.c_str());
    else if (key == "LOGIN_LOCKOUT_SEC")       c.login_lockout_sec       = std::atoi(val.c_str());
    else if (key == "SCEP_ALLOW_DES3")   c.scep_allow_des3  = (val == "1" || val == "true" || val == "yes");
    else if (key == "SCEP_RESPONSE_MD")  c.scep_response_md = val;   // digest axis
    else if (key == "CMP_RESPONSE_MD")   c.cmp_response_md = val;    // digest axis
    else if (key == "DIRECTORY_GROUP_REFRESH_SEC") c.directory_group_refresh_sec = to_int(key, val);
    else if (key == "CERT_VALIDITY_DAYS") c.cert_validity_days = to_int(key, val);
    else if (key == "CERT_SERIAL_BYTES")  c.cert_serial_bytes = to_int(key, val);
    else if (key == "MIN_RSA_BITS")       c.min_rsa_bits = to_int(key, val);
    else if (key == "MIN_DSA_BITS")       c.min_dsa_bits = to_int(key, val);
    else if (key == "MIN_EC_BITS")        c.min_ec_bits = to_int(key, val);
    else if (key == "ALLOWED_IPS_REGEX")  c.allowed_ips_regex = val;
    else if (key == "CRL_DPS")            c.crl_distribution_points = split_csv(val);
    else if (key == "AIA_CA_ISSUERS")     c.aia_ca_issuers = split_csv(val);
    else if (key == "AIA_OCSP")           c.aia_ocsp = split_csv(val);
    // `none` is no longer a value. Refused HERE, at parse time, rather than left to
    // deny every login later — a service that starts happily and then rejects everybody is
    // the confusing failure, and the operator would have no line telling them which key is
    // at fault. This throws with the key named, which is what the AUTH_BACKEND=none
    // deployment needed and did not get: it started, warned once, and
    // issued certificates to anyone.
    // ⚠️ THE LDAP_* KEYS ARE GONE, AND ADDING ONE BACK WOULD BE A SECOND SOURCE. A
    // directory is a row in auth_providers + ldap_providers now: a flat key-value config
    // names exactly one directory, which is why several domains were never expressible.
    // `AUTH_BACKEND` stays because it chooses a BACKEND, which is not a directory.
    // LDAP_AUTH went with them — it was a legacy alias whose only effect was to set
    // AUTH_BACKEND=ldap, and a legacy alias is exactly what does not get kept here.
    else if (key == "AUTH_BACKEND") {
        if (val != "local" && val != "ldap")
            throw Error(2, "config: AUTH_BACKEND must be 'local' or 'ldap', got '" + val +
                           "'. `none` was removed — it accepted any username with "
                           "any password.");
        c.auth_backend = val;
    }
    else if (key == "LOG_LEVEL")          c.log_level = val;
    else if (key == "AUDIT_FORWARD") {
        // Refuse an unknown value rather than silently treating it as `off`. A typo here
        // would leave a deployment believing it forwards its audit trail when it ships
        // nothing at all, and nothing downstream would ever say so.
        if (val != "off" && val != "syslog" && val != "hec")
            throw Error(2, "config: AUDIT_FORWARD must be 'off', 'syslog' or 'hec', got '" +
                           val + "'");
        c.audit_forward = val;
    }
    else if (key == "AUDIT_FORWARD_TARGET")   c.audit_forward_target = val;
    else if (key == "AUDIT_FORWARD_PROTO") {
        if (val != "tcp" && val != "udp")
            throw Error(2, "config: AUDIT_FORWARD_PROTO must be 'tcp' or 'udp', got '" + val + "'");
        c.audit_forward_proto = val;
    }
    else if (key == "AUDIT_FORWARD_TLS")      c.audit_forward_tls = (val == "1" || val == "true" || val == "yes");
    else if (key == "AUDIT_FORWARD_TOKEN")    c.audit_forward_token = val;
    else if (key == "AUDIT_FORWARD_CA_ID")    c.audit_forward_ca_id = val;
    else if (key == "AUDIT_FORWARD_INTERVAL_SEC") c.audit_forward_interval_sec = std::atoi(val.c_str());
    else if (key == "AUDIT_FORWARD_BATCH")    c.audit_forward_batch = std::atoi(val.c_str());
    else if (key == "SERVICE_KEYS_REPLICABLE")
        c.service_keys_replicable = (val == "1" || val == "true" || val == "yes");
    else if (key == "OCSP_RESPONDER_KEYS_REPLICATED")
        c.ocsp_responder_keys_replicated = (val == "1" || val == "true" || val == "yes");
    else if (key == "NOTIFY_EMAIL_FALLBACK")  c.notify_email_fallback = val;
    else if (key == "SMTP_SERVER")            c.smtp_server = val;
    else if (key == "SMTP_TLS") {
        // Refused rather than defaulted: a typo read as `none` would send in the clear without
        // anyone having chosen to. `none` itself is refused beside SMTP_USER in smtp_settings().
        if (val != "starttls" && val != "tls" && val != "none")
            throw Error(2, "config: SMTP_TLS must be 'starttls', 'tls' or 'none', got '" + val + "'");
        c.smtp_tls = val;
    }
    else if (key == "SMTP_USER")              c.smtp_user = val;
    else if (key == "SMTP_PASSWORD")          c.smtp_password = val;
    else if (key == "SMTP_FROM")              c.smtp_from = val;
    else if (key == "SMTP_CA_FILE")           c.smtp_ca_file = val;
}

void apply(Config& c, const std::string& key, const std::string& val) {
    if (apply1(c, key, val)) return;
    if (apply2(c, key, val)) return;
    apply3(c, key, val);
}

} // namespace

std::string strip_inline_comment(const std::string& line) {
    bool in_quotes = false;
    for (size_t i = 0; i < line.size(); ++i) {
        const char ch = line[i];
        if (ch == '"') { in_quotes = !in_quotes; continue; }
        if (in_quotes || ch != '#') continue;
        // A '#' with a non-space character immediately before it is part of the value —
        // a password, a URL fragment, a regex — not the start of a comment.
        if (i > 0 && line[i - 1] != ' ' && line[i - 1] != '\t') continue;
        return line.substr(0, i);
    }
    return line;
}

Config Config::load(const std::filesystem::path& file) {
    Config c = from_env();
    std::ifstream f(file);
    if (!f) {
        // ⚠️ ABSENT IS OPTIONAL; PRESENT BUT UNREADABLE IS FATAL. A CLI run without --config
        // looks for a default path that need not exist, and the environment then supplies
        // everything. A file that EXISTS and cannot be opened is a different case: the
        // operator configured this process and it cannot see the configuration. Treated as
        // absent, a native service whose bootstrap.conf had lost its group read bit started
        // on built-in defaults with no error at all — no DATACENTER_ID, the console on 8090
        // instead of 443, PKI_DNS pki.example.org — and reached the database anyway, because
        // libpq's defaults lead to the local socket, which pg_hba trusts. Measured on a
        // cloud node. The same silence met an operator who ran fastpki-config as a user
        // outside the fastpki group.
        const int err = errno;
        std::error_code ec;
        if (std::filesystem::exists(file, ec) || ec)
            throw Error(2, "config: cannot read " + file.string() + ": " +
                           std::strerror(err ? err : EACCES) +
                           " (on a native host it is 0640 root:fastpki — run as fastpki or root)");
        return c;
    }
    std::string line;
    while (std::getline(f, line)) {
        line = strip_inline_comment(line);
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        auto k = trim(line.substr(0, eq));
        auto v = trim(line.substr(eq + 1));
        if (!v.empty() && v.front() == '"' && v.back() == '"')
            v = v.substr(1, v.size() - 2);
        if (!k.empty()) {
            // A bootstrap key comes from the deployment environment when the environment
            // ACTUALLY SETS IT — the tracked config file must not overwrite a real
            // deployment value. Skipping it unconditionally goes too far: a
            // single-node install that configures PG_CONNINFO only in bootstrap.conf, which is
            // what docs/deployment.md documents, would have its own setting discarded and fall
            // back to libpq's PG* environment defaults — connecting somewhere it was
            // never told to, with nothing in the log to say so. Found by the test
            // harness, which sets PG_CONNINFO in the file and not the environment: the
            // servers silently used whatever PGDATABASE happened to be exported.
            if (is_bootstrap_config_key(k)) {
                const char* from_environment = std::getenv(k.c_str());
                if (from_environment && *from_environment) continue;   // env wins
            }
            apply(c, k, v);
        }
    }
    ensure_builtin_profiles(c);   // the stored ones arrive from the database: load_cert_profiles()
    default_p11_server_address(c);
    return c;
}

bool is_bootstrap_config_key(const std::string& key) {
    return key == "PG_CONNINFO";
}

int overlay_config(Config& c, const std::map<std::string, std::string>& kv) {
    int n = 0;
    for (const auto& [k, v] : kv) {
        if (is_bootstrap_config_key(k)) continue;   // can't reconfigure how to reach the DB
        // ⚠️ TRIMMED, EXACTLY LIKE THE FILE PATH. The conf-file parser trims both sides of
        // every value; this one used to hand the DB's bytes to apply() verbatim, so the two
        // sources of the same setting did not mean the same thing.
        //
        // A value that picks up surrounding whitespace — pasted into the console's Config
        // page, or imported from a file with a tab after the '=' — then fails only where the
        // value has to MATCH something. Measured: OCSP_RESPONDER_KEY stored as
        // "\tpkcs11:token=…" is not recognised as a PKCS#11 URI, so the responder loaded no
        // credential and refused every request for the CA while reporting the key as NOT
        // SET. The console showed the URI, the database held it, and it was one tab from
        // working.
        apply(c, trim(k), trim(v));
        ++n;
    }
    return n;
}

Config Config::from_env() {
    Config c;
    auto get = [](const char* k) -> const char* { return std::getenv(k); };
    for (const char* k : {
        "PKI_DNS","BASE_URL",
        "PKCS11_MODULE","PKCS11_PROVIDER_PATH","PKCS11_TOKEN","PKCS11_PIN_FILE",
        "WEB_KEY_ALGO","WEB_KEY_BITS","WEB_KEY_CURVE","WEB_KEY_MD",
        "EST_KEY_ALGO","EST_KEY_BITS","EST_KEY_CURVE","EST_KEY_MD",
        "ACME_KEY_ALGO","ACME_KEY_BITS","ACME_KEY_CURVE","ACME_KEY_MD",
        "MS_KEY_ALGO","MS_KEY_BITS","MS_KEY_CURVE","MS_KEY_MD",
        "PG_CONNINFO","PG_TLS_DIR","PG_TLS_SANS","PG_TLS_CA_ID",
        "DATACENTER_ID",
        "OCSP_BIND","OCSP_PORT","CRL_PATH","CRL_NEXT_UPDATE_DAYS","CRL_DELTA",
        "CRL_CACHE_TTL_SEC","CRL_PUBLISH_SWEEP_SEC",
        "OCSP_RESPONDER_KEY","OCSP_RESPONDER_CERT_ID_PREFIX","OCSP_RESPONSE_MD",
        "OCSP_RESPONDER_KEY_ALGO","OCSP_RESPONDER_KEY_BITS","OCSP_RESPONDER_KEY_CURVE",
        "SERVICE_CERT_RENEW_FRACTION","HTTPS_CA_ID",
        // A pair's switch (HA_ENABLED) sets it at install. Compose's config file is shared
        // and tracked, so there it can only arrive through .env, like DATACENTER_ID.
        "SERVICE_KEYS_REPLICABLE",
        "EST_BIND","EST_PORT",
        "EST_CSRATTRS","EST_DEFAULT_PROFILE","EST_SERVERKEYGEN","EST_SERVERKEYGEN_ENCRYPT","EST_SERVERKEYGEN_BITS",
        "EST_CLIENT_CA_ID","EST_CLIENT_CA_BUNDLE",
        "ACME_BIND","ACME_PORT","ACME_BASE_PATH",
        "ACME_DNS_RESOLVER","ACME_TLS_ALPN_PORT","ACME_NEW_AUTHZ","ACME_SWEEP_SEC",
        "NONCE_EXPIRES_SEC","ORDER_EXPIRES_DAYS",
        "CMP_BIND","CMP_PORT","CMP_PATH","CMP_EXTRACERTS_CA",
        "CMP_CLIENT_CA_ID","CMP_CLIENT_CA_BUNDLE","CMP_CLIENT_CA_REFRESH_SEC","CMP_RA_KEY",
        "CMP_RA_KEY_ALGO","CMP_RA_KEY_BITS","CMP_RA_KEY_CURVE",
        "CMP_RESPONSE_MD",
        "MS_BIND","MS_PORT","XCEP_PATH","WSTEP_PATH","MS_XCEP_GUID","MS_XCEP_FRIENDLY_NAME",
        "MS_XCEP_NEXT_UPDATE_HOURS",
        "STORE_BIND","STORE_PORT",
        "WEB_BIND","WEB_PORT","WEB_TOKEN","WEB_ALLOW_REVOKE","MCP_ALLOW_WRITE",
        "WEB_TLS_CERT","WEB_TLS_KEY","WEB_CLIENT_CA","WEB_CLIENT_CA_ID","WEB_CLIENT_CA_BUNDLE",
        "SCEP_BIND","SCEP_PORT","SCEP_PATH","SCEP_DYNAMIC_CHALLENGE",
        "SCEP_MANUAL_APPROVAL","SCEP_RA_KEY","SCEP_RA_KEY_BITS","SCEP_RA_CERT_ID_PREFIX","SCEP_RENEWAL","SCEP_NEXT_CA_CERT",
        "SCEP_RESPONSE_MD",
        // The LDAP_* env vars are gone with the keys: from_env() hands each name to
        // apply(), which no longer knows them, so keeping them here would read the
        // operator's environment and silently discard it.
        "DIRECTORY_GROUP_REFRESH_SEC",
        "CERT_VALIDITY_DAYS","CERT_SERIAL_BYTES",
        "MIN_RSA_BITS","MIN_DSA_BITS","MIN_EC_BITS","ALLOWED_IPS_REGEX",
        "CRL_DPS","AIA_CA_ISSUERS","AIA_OCSP","AUTH_BACKEND",
        "LOG_LEVEL",
        "AUDIT_FORWARD","AUDIT_FORWARD_TARGET","AUDIT_FORWARD_PROTO","AUDIT_FORWARD_TLS",
        "AUDIT_FORWARD_TOKEN","AUDIT_FORWARD_CA_ID","AUDIT_FORWARD_INTERVAL_SEC",
        "AUDIT_FORWARD_BATCH"
    }) {
        if (auto v = get(k)) apply(c, k, v);
    }
    ensure_builtin_profiles(c);   // the stored ones arrive from the database: load_cert_profiles()
    default_p11_server_address(c);
    return c;
}

// See the header for why forgetting this call is loud rather than silent.
void resolve_datacenter_prefix(const Config& c, Db& db) {
    std::string dc = c.datacenter_id;

    // ⚠️ AN ABSENT DATACENTER_ID IS THE DANGEROUS HALF, AND IT USED TO BE THE SILENT ONE.
    // A WRONG id throws below and the node refuses to start. An ABSENT id simply minted
    // full-width serials with no prefix — valid certificates, successful enrolment, and
    // nothing anywhere saying that everything issued from that moment sits outside the
    // data center's partition for good. `certs_dc_range` then refuses those rows on a
    // LOCAL insert, which is what a database restore is, and a serial cannot be corrected
    // after issuance.
    //
    // Every installer writes DATACENTER_ID, so an empty one means a hand-written .env —
    // in practice an HA standby, whose template omitted it. A pair is one data center
    // twice, so the answer is not a guess when exactly one row exists: adopt it. With
    // several it IS a guess, and guessing wrong collides serials across a mesh, so that
    // case keeps the old behaviour and says what it is doing.
    if (dc.empty()) {
        const auto ids = db.list_datacenter_ids();
        if (ids.size() == 1) {
            dc = ids.front();
            log::info("DATACENTER_ID is unset; adopting '" + dc + "', the only data center "
                      "this deployment has, so serials assigned here carry its prefix");
        } else {
            if (ids.size() > 1)
                log::err("DATACENTER_ID is unset and this deployment has " +
                         std::to_string(ids.size()) + " data centers, so this node cannot "
                         "tell which one it is. It will assign FULL-WIDTH serials with no "
                         "prefix: they sit outside every partition permanently and are "
                         "refused on a local restore. Set DATACENTER_ID to this node's id.");
            set_datacenter_serial_prefix("", 0);
            return;
        }
    }

    auto p = db.get_datacenter_prefix(dc);
    if (!p)
        throw Error(1, "DATACENTER_ID=" + dc + " has no row in `datacenters`, "
                       "so this node has no serial prefix and must not issue. Apply the "
                       "topology first: fastpki-mesh --map <topology> | psql \"$PG_CONNINFO\"");
    set_datacenter_serial_prefix(dc, *p);
}

} // namespace pki
