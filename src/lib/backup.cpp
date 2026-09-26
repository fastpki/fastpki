// Config backup & restore — shared by fastpki-config and fastpki-web.
#include "pki/backup.hpp"
#include "pki/cert_profile.hpp"
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/error.hpp"
#include "pki/ms_template.hpp"
#include "pki/notify_mail.hpp"
#include "pki/x509.hpp"   // restore recreates a CA's certificate row
#include "../../third_party/nlohmann/json.hpp"

#include <ctime>
#include <vector>
#include <cstring>
#include <memory>

#include <openssl/evp.h>
#include <openssl/rand.h>

namespace pki {

using json = nlohmann::json;

std::string build_config_backup(Db& db) {
    json b;
    b["fastpki_backup"] = 1;
    b["created"] = static_cast<long>(std::time(nullptr));
    // Node-local PROCESS state is not configuration and must not travel.
    //
    // <PROTO>_STARTED_AT is stamped by each listener when its gate opens and
    // <PROTO>_RESTART_AT when an admin asks one to restart. Both are facts about the
    // processes on THIS node at THIS moment. Exporting them puts one machine's timings
    // into a portable artifact, and restoring them writes a peer's (or a month-old)
    // start times over this node's — after which the Config page answers "has this
    // change reached the process?" from numbers that describe a different process. It
    // would be wrong in both directions, including the dangerous one.
    //
    // The `config` table is deliberately not replicated for the same reason: some
    // of what it holds is per-node identity, not shared policy.
    {
        auto cfg = db.get_config();
        for (auto it = cfg.begin(); it != cfg.end(); ) {
            const std::string& k = it->first;
            const bool marker = k.size() > 11 &&
                (k.compare(k.size() - 11, 11, "_STARTED_AT") == 0 ||
                 k.compare(k.size() - 11, 11, "_RESTART_AT") == 0);
            if (marker) it = cfg.erase(it); else ++it;
        }
        b["config"] = cfg;
    }
    json wu = json::array();
    for (const auto& u : db.list_web_users())
        // auth_provider too: without it a restored directory or SSO account came back with no
        // record of how it signs in, and the console listed it as `external`.
        wu.push_back({{"username", u.username}, {"role", u.role}, {"hash", u.hash},
                     {"must_reset", u.must_reset}, {"auth_provider", u.auth_provider},
                     {"email", u.email}});
    b["web_users"] = wu;
    // A CA is a row of `certs`, so the backup carries its SERIAL — the row's key —
    // and its certificate inline. parent_id is exported for a human reading the file and
    // is not restored: it is derived from the certificates' issuer/subject, so writing it
    // back would be writing a second, staler copy of what the bytes say.
    // The JSON key stays "ca_instances": it is a wire format an operator may already have
    // files in, and renaming it would break reading them for no gain.
    json ci = json::array();
    for (const auto& c : db.list_ca_instances())
        ci.push_back({{"serial", c.serial}, {"id", c.id}, {"name", c.name},
                     {"parent_id", c.parent_id},
                     {"status", c.status}, {"signing_ca_pem", c.signing_ca_pem},
                     {"signing_ca_key", c.signing_ca_key}, {"created", c.created},
                     {"ms_enroll_permission", c.ms_enroll_permission}});
    b["ca_instances"] = ci;
    // `profile_assignments` used to be a section here. It is gone, and what replaced
    // it is not one table but three — a subject's issuance profile is now a `profile:use|rw`
    // grant on a role the subject holds. Dropping the old section without carrying the new
    // tables would have made a restore come back with its CAs, its users and its config,
    // and with every custom role and every profile grant silently missing: the console
    // would look right and nobody could enrol under the profile they had. Roles ARE
    // management configuration, so they belong in a configuration backup.
    json rl = json::array();
    for (const auto& r : db.list_roles()) {
        json grants = json::array();
        for (const auto& g : db.list_role_grants(r.name))
            grants.push_back({{"permission", g.permission}, {"scope", g.scope}});
        json one = {{"name", r.name}, {"description", r.description},
                    {"builtin", r.builtin}, {"grants", grants}};
        // max_certs is nullable and 0 is a real value, so the flag decides whether the key
        // appears at all — writing 0 unconditionally would turn "use the deployment
        // default" into "this role may issue nothing" on every round-trip.
        if (r.has_max_certs) one["max_certs"] = r.max_certs;
        // ⚠️ AND THE OTHER TWO LIMITS, the same way. Only max_certs was carried, and restore's
        // upsert writes an absent limit as NULL — so a restore silently lifted every role's
        // per-name and per-certificate-SAN limits on the database it was restored into.
        if (r.has_max_cn)  one["max_cn"]  = r.max_cn;
        if (r.has_max_san) one["max_san"] = r.max_san;
        rl.push_back(std::move(one));
    }
    b["roles"] = rl;
    json sr = json::array();
    for (const auto& s : db.list_subject_roles())
        sr.push_back({{"selector_type", s.selector_type}, {"selector_value", s.selector_value},
                      {"role", s.role}, {"created", s.created}});
    b["subject_roles"] = sr;
    json mt = json::array();
    for (const auto& t : db.list_ms_templates(/*enabled_only=*/false))   // a disabled one is still configuration
        mt.push_back({{"name", t.name}, {"oid", t.oid}, {"schema", t.schema},
                     {"enroll", t.enroll}, {"auto_enroll", t.auto_enroll},
                     {"validity_days", t.validity_days}, {"min_key_size", t.min_key_size},
                     {"key_spec", t.key_spec}, {"key_usage", t.key_usage},
                     {"major_rev", t.major_rev}, {"minor_rev", t.minor_rev},
                     {"private_key_flags", t.private_key_flags}, {"subject_name_flags", t.subject_name_flags},
                     {"enrollment_flags", t.enrollment_flags}, {"general_flags", t.general_flags},
                     {"pk_oid", t.pk_oid}, {"pk_name", t.pk_name}, {"hash_oid", t.hash_oid},
                     {"hash_name", t.hash_name}, {"crypto_providers", t.crypto_providers},
                     {"ekus", t.ekus}, {"enabled", t.enabled},
                     {"private_key_permissions", t.private_key_permissions},
                     {"overlap_seconds", t.overlap_seconds}});
    b["ms_templates"] = mt;
    // Certificate profiles as stored: every custom one and every edited built-in, in the
    // same { "<name>": {fields…} } shape `fastpki-config profiles-import` reads. They left
    // the `config` section when they became a table, so without this a restore would bring
    // back the roles granting profiles and not the profiles they name.
    b["cert_profiles"] = json::parse(stored_cert_profiles_json(db));
    // The expiry email template, when an administrator has written one. It is a replicated
    // table like the profiles, and just as absent from the `config` section.
    if (auto t = db.get_notify_template(kExpiryTemplateName))
        b["notify_templates"] = {{kExpiryTemplateName,
                                  {{"subject", t->subject}, {"line", t->line}, {"body", t->body}}}};
    return b.dump(2);
}

std::string restore_config_backup(Db& db, const std::string& json_text) {
    json b;
    try { b = json::parse(json_text); }
    catch (const std::exception& e) { throw Error(1, std::string("bad backup JSON: ") + e.what()); }
    if (!b.contains("fastpki_backup")) throw Error(1, "not a fastpki backup file");

    int n_cfg = 0, n_usr = 0, n_ca = 0, n_rl = 0, n_sr = 0, n_mt = 0;
    if (b.contains("config"))
        for (auto& [k, v] : b["config"].items()) { db.set_config(k, v.get<std::string>()); ++n_cfg; }
    if (b.contains("web_users"))
        for (const auto& u : b["web_users"]) {
            Db::WebUserRow r;
            r.username = u.value("username", ""); r.role = u.value("role", "");
            r.hash = u.value("hash", "");
            r.must_reset = u.value("must_reset", false);
            r.auth_provider = u.value("auth_provider", "");
            r.email = u.value("email", "");
            if (!r.username.empty()) {
                db.upsert_web_user(r);
                // upsert writes the email only on insert; restoring over an existing row is
                // what this line is for.
                db.set_web_user_email(r.username, r.email);
                ++n_usr;
            }
        }
    if (b.contains("ca_instances"))
        for (const auto& c : b["ca_instances"]) {
            Db::CaInstance ca;
            ca.serial = c.value("serial", "");
            ca.id = c.value("id", ""); ca.name = c.value("name", "");
            ca.status = c.value("status", "active");
            ca.signing_ca_pem = c.value("signing_ca_pem", ""); ca.signing_ca_key = c.value("signing_ca_key", "");
            ca.created = c.value("created", static_cast<int64_t>(0));
            ca.ms_enroll_permission = c.value("ms_enroll_permission", true);
            if (ca.id.empty()) continue;
            // Registering a CA means stamping its identity onto its own certificate
            // row, so that row has to exist. Restore it from the PEM the backup carries —
            // which is why the backup carries the certificate and not a path to one.
            if (!ca.serial.empty() && !ca.signing_ca_pem.empty() && !db.get_cert(ca.serial)) {
                try {
                    X509Ptr x = load_ca_cert_pem(ca.signing_ca_pem);
                    CertRow cr;
                    cr.serial      = ca.serial;
                    cr.status      = 0;
                    cr.not_before  = x509_not_before_unix(x.get());
                    cr.not_after   = x509_not_after_unix(x.get());
                    cr.cn          = x509_cn(x.get());
                    cr.subject     = cr.cn;
                    cr.cert_der    = x509_to_der(x.get());
                    cr.fingerprint = x509_fingerprint_sha256_hex(x.get());
                    cr.ca_instance_id = ca.id;
                    cr.ca_id       = ca.id;
                    cr.private_key = ca.signing_ca_key;
                    db.insert_cert(cr);
                } catch (const std::exception&) { /* reported by add_ca_instance below */ }
            }
            try { db.add_ca_instance(ca); ++n_ca; }       // tolerate an already-present id
            catch (const std::exception&) { db.set_ca_instance_status(ca.id, ca.status); }
        }
    // Roles before subject_roles: a membership naming a role that does not exist yet is a
    // row pointing at nothing. Both are upserts, so restoring over a live database adds the
    // backup's roles and leaves anything the target already had.
    if (b.contains("roles"))
        for (const auto& r : b["roles"]) {
            Db::RoleRow row;
            row.name = r.value("name", "");
            if (row.name.empty()) continue;
            row.description = r.value("description", "");
            row.builtin     = r.value("builtin", false);
            row.has_max_certs = r.contains("max_certs");
            if (row.has_max_certs) row.max_certs = r.value("max_certs", 0);
            row.has_max_cn = r.contains("max_cn");
            if (row.has_max_cn) row.max_cn = r.value("max_cn", 0);
            row.has_max_san = r.contains("max_san");
            if (row.has_max_san) row.max_san = r.value("max_san", 0);
            db.upsert_role(row);
            std::vector<Db::RoleGrant> grants;
            for (const auto& g : r.value("grants", json::array()))
                grants.push_back({g.value("permission", ""), g.value("scope", "*")});
            // set_role_grants REPLACES the role's grants. That is what makes a restore
            // faithful rather than additive: a backup taken after a permission was revoked
            // must not leave the revoked grant in place on the target.
            db.set_role_grants(row.name, grants);
            ++n_rl;
        }
    if (b.contains("subject_roles"))
        for (const auto& s : b["subject_roles"]) {
            Db::SubjectRole r;
            r.selector_type  = s.value("selector_type", "");
            r.selector_value = s.value("selector_value", "");
            r.role           = s.value("role", "");
            r.created        = s.value("created", static_cast<int64_t>(0));
            if (r.selector_value.empty() || r.role.empty()) continue;
            db.add_subject_role(r); ++n_sr;
        }
    if (b.contains("ms_templates"))
        for (const auto& m : b["ms_templates"]) {
            MsTemplate t;
            t.name = m.value("name", ""); t.oid = m.value("oid", "");
            t.schema = m.value("schema", t.schema); t.enroll = m.value("enroll", t.enroll);
            t.auto_enroll = m.value("auto_enroll", t.auto_enroll);
            t.validity_days = m.value("validity_days", t.validity_days);
            t.min_key_size = m.value("min_key_size", t.min_key_size);
            t.key_spec = m.value("key_spec", t.key_spec);
            t.key_usage = m.value("key_usage", t.key_usage);
            t.major_rev = m.value("major_rev", t.major_rev); t.minor_rev = m.value("minor_rev", t.minor_rev);
            t.private_key_flags = m.value("private_key_flags", t.private_key_flags);
            t.subject_name_flags = m.value("subject_name_flags", t.subject_name_flags);
            t.enrollment_flags = m.value("enrollment_flags", t.enrollment_flags);
            t.general_flags = m.value("general_flags", t.general_flags);
            t.pk_oid = m.value("pk_oid", t.pk_oid); t.pk_name = m.value("pk_name", t.pk_name);
            t.hash_oid = m.value("hash_oid", t.hash_oid); t.hash_name = m.value("hash_name", t.hash_name);
            t.crypto_providers = m.value("crypto_providers", std::vector<std::string>{});
            t.ekus = m.value("ekus", std::vector<std::string>{});
            t.private_key_permissions = m.value("private_key_permissions", std::string{});
            t.overlap_seconds = m.value("overlap_seconds", t.overlap_seconds);
            t.enabled = m.value("enabled", true);
            if (!t.name.empty()) { db.upsert_ms_template(t); ++n_mt; }
        }
    int n_pf = 0;
    if (b.contains("cert_profiles") && b["cert_profiles"].is_object())
        for (const auto& [name, def] : b["cert_profiles"].items()) {
            // Parsed before it is stored, so a restore cannot plant a row no service loads.
            Config probe;
            json one = json::object();
            one[name] = def;
            install_cert_profiles_json(probe, one.dump());
            db.upsert_cert_profile(name, def.dump());
            ++n_pf;
        }
    if (b.contains("notify_templates") && b["notify_templates"].is_object())
        for (const auto& [name, t] : b["notify_templates"].items()) {
            if (!t.is_object()) continue;
            db.upsert_notify_template(name, {t.value("subject", ""), t.value("line", ""),
                                             t.value("body", "")});
        }
    return "restored: " + std::to_string(n_cfg) + " config key(s), " + std::to_string(n_usr) +
           " user(s), " + std::to_string(n_ca) + " CA instance(s), " + std::to_string(n_rl) +
           " role(s), " + std::to_string(n_sr) + " role assignment(s), " +
           std::to_string(n_mt) + " template(s), " + std::to_string(n_pf) + " profile(s)";
}


// ── Passphrase encryption ──────────────────────────────────────
// Format + rationale documented in backup.hpp.
namespace {
constexpr char kMagic[]   = "FPKIBAK1";
constexpr size_t kMagicLen = 8;      // no NUL on the wire
constexpr size_t kSaltLen  = 16;
constexpr size_t kIvLen    = 12;     // GCM standard nonce
constexpr size_t kTagLen   = 16;
constexpr size_t kKeyLen   = 32;     // AES-256
constexpr int    kIters    = 210000; // matches the console password KDF

std::vector<unsigned char> derive_key(const std::string& pass,
                                      const unsigned char* salt) {
    std::vector<unsigned char> key(kKeyLen);
    if (PKCS5_PBKDF2_HMAC(pass.data(), static_cast<int>(pass.size()),
                          salt, static_cast<int>(kSaltLen), kIters, EVP_sha256(),
                          static_cast<int>(kKeyLen), key.data()) != 1)
        throw Error(1, "backup: key derivation failed");
    return key;
}
} // namespace

bool is_encrypted_backup(const std::string& blob) {
    return blob.size() >= kMagicLen && std::memcmp(blob.data(), kMagic, kMagicLen) == 0;
}

std::string encrypt_backup(const std::string& plaintext, const std::string& passphrase) {
    if (passphrase.empty()) throw Error(1, "backup: a passphrase is required to encrypt");
    unsigned char salt[kSaltLen], iv[kIvLen];
    if (RAND_bytes(salt, sizeof salt) != 1 || RAND_bytes(iv, sizeof iv) != 1)
        throw Error(1, "backup: RNG failure");
    auto key = derive_key(passphrase, salt);

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
        ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) throw Error(1, "backup: cipher init failed");
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kIvLen), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv) != 1)
        throw Error(1, "backup: cipher init failed");

    std::vector<unsigned char> ct(plaintext.size() + 32);
    int len = 0, total = 0;
    if (EVP_EncryptUpdate(ctx.get(), ct.data(), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1)
        throw Error(1, "backup: encryption failed");
    total = len;
    if (EVP_EncryptFinal_ex(ctx.get(), ct.data() + total, &len) != 1)
        throw Error(1, "backup: encryption failed");
    total += len;
    unsigned char tag[kTagLen];
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagLen), tag) != 1)
        throw Error(1, "backup: encryption failed");

    std::string out;
    out.reserve(kMagicLen + kSaltLen + kIvLen + total + kTagLen);
    out.append(kMagic, kMagicLen);
    out.append(reinterpret_cast<const char*>(salt), kSaltLen);
    out.append(reinterpret_cast<const char*>(iv), kIvLen);
    out.append(reinterpret_cast<const char*>(ct.data()), total);
    out.append(reinterpret_cast<const char*>(tag), kTagLen);
    return out;
}

std::string decrypt_backup(const std::string& blob, const std::string& passphrase) {
    if (!is_encrypted_backup(blob)) throw Error(1, "backup: not an encrypted FastPKI backup");
    if (passphrase.empty()) throw Error(1, "backup: this backup is encrypted \xe2\x80\x94 a passphrase is required");
    const size_t hdr = kMagicLen + kSaltLen + kIvLen;
    if (blob.size() < hdr + kTagLen) throw Error(1, "backup: file is truncated");

    const auto* p = reinterpret_cast<const unsigned char*>(blob.data());
    const unsigned char* salt = p + kMagicLen;
    const unsigned char* iv   = salt + kSaltLen;
    const unsigned char* ct   = iv + kIvLen;
    const size_t ct_len = blob.size() - hdr - kTagLen;
    const unsigned char* tag  = ct + ct_len;
    auto key = derive_key(passphrase, salt);

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
        ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) throw Error(1, "backup: cipher init failed");
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kIvLen), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv) != 1)
        throw Error(1, "backup: cipher init failed");

    std::string out(ct_len + 32, '\0');
    int len = 0, total = 0;
    if (EVP_DecryptUpdate(ctx.get(), reinterpret_cast<unsigned char*>(&out[0]), &len,
                          ct, static_cast<int>(ct_len)) != 1)
        throw Error(1, "backup: decryption failed");
    total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagLen),
                            const_cast<unsigned char*>(tag)) != 1)
        throw Error(1, "backup: decryption failed");
    // The tag check is the wrong-passphrase signal as well as the tamper signal.
    if (EVP_DecryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char*>(&out[0]) + total, &len) != 1)
        throw Error(1, "backup: wrong passphrase, or the file is corrupt");
    total += len;
    out.resize(total);
    return out;
}

} // namespace pki
