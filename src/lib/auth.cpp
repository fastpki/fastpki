// Authentication dispatcher + PBKDF2 password hashing.
// Users live in the `web_users` table — there is no file backend.
// LDAP is a separate backend (ldap_auth.cpp) selected via AUTH_BACKEND=ldap.

#include "pki/auth.hpp"
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/error.hpp"
#include "pki/log.hpp"
#include "pki/login_throttle.hpp"
#include "pki/smtp.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <mutex>
#include <sstream>
#include <vector>

namespace pki {
namespace {

constexpr int kSaltLen = 16;
constexpr int kHashLen = 32; // SHA-256 output

std::string to_hex(const unsigned char* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 0xf]; }
    return s;
}

std::vector<unsigned char> from_hex(const std::string& h) {
    std::vector<unsigned char> out;
    if (h.size() % 2) return out;
    auto nyb = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < h.size(); i += 2) {
        int hi = nyb(h[i]), lo = nyb(h[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return out;
}

std::vector<unsigned char> pbkdf2(const std::string& pass,
                                  const unsigned char* salt, int saltlen,
                                  int iterations) {
    std::vector<unsigned char> out(kHashLen);
    if (PKCS5_PBKDF2_HMAC(pass.data(), static_cast<int>(pass.size()),
                          salt, saltlen, iterations, EVP_sha256(),
                          kHashLen, out.data()) != 1)
        throw Error(2, "PBKDF2 failed: " + openssl_errors());
    return out;
}

std::vector<std::string> split(const std::string& s, char d) {
    std::vector<std::string> out; std::string cur; std::istringstream is(s);
    while (std::getline(is, cur, d)) out.push_back(cur);
    return out;
}

} // namespace

// See the contract in include/pki/auth.hpp — this is the only implementation of it.
PrincipalKind principal_kind(const std::string& principal) {
    // ⚠️ The realm goes FIRST, or the `$` test is dead for every caller that holds the
    // realm-qualified form: `FASTPKI-WIN$@FASTPKI.LAB` ends in `B`.
    //
    // The PROVIDER qualifier needs no such handling and deliberately gets none: msxcep now
    // stores `corp\FASTPKI-WIN$`, and both tests below look at the tail or the interior of
    // the name, which a `provider\` prefix does not disturb. So the qualified spelling, the
    // realm-qualified spelling and the bare one all classify alike — that equality is the
    // point of the function, and it is what lets an operator type a grant in whichever form
    // they hold without the console labelling the same machine two different ways.
    const std::string name = principal.substr(0, principal.find('@'));
    if (!name.empty() && name.back() == '$')          return PrincipalKind::Computer;
    if (name.find('/') != std::string::npos)          return PrincipalKind::Computer;
    return PrincipalKind::User;
}

const char* principal_kind_name(const std::string& principal) {
    return principal_kind(principal) == PrincipalKind::Computer ? "computer" : "user";
}

std::string hash_password(const std::string& password, int iterations) {
    unsigned char salt[kSaltLen];
    if (RAND_bytes(salt, kSaltLen) != 1) throw Error(2, "RAND_bytes failed");
    auto h = pbkdf2(password, salt, kSaltLen, iterations);
    return "pbkdf2$" + std::to_string(iterations) + "$" +
           to_hex(salt, kSaltLen) + "$" + to_hex(h.data(), h.size());
}

bool verify_password(const std::string& password, const std::string& stored) {
    auto parts = split(stored, '$');
    if (parts.size() != 4 || parts[0] != "pbkdf2") return false;
    int iter = 0;
    try { iter = std::stoi(parts[1]); } catch (...) { return false; }
    auto salt = from_hex(parts[2]);
    auto want = from_hex(parts[3]);
    if (salt.empty() || want.size() != static_cast<size_t>(kHashLen)) return false;
    auto got = pbkdf2(password, salt.data(), static_cast<int>(salt.size()), iter);
    return CRYPTO_memcmp(got.data(), want.data(), kHashLen) == 0;
}

// The password check itself, with no rate limiting. Kept separate so that the accounting
// below wraps EVERY exit from it — this function returns an empty result from six
// different places, and a counter sprinkled through those would eventually miss one.
static AuthResult authenticate_unthrottled(const Config& cfg, const std::string& username,
                                           const std::string& password, Db* db) {
    if (username.empty() || password.empty()) return {};

    // A row whose hash is not a real PBKDF2 hash has NO local password: it is the
    // `!external` sentinel the console writes when it onboards a federated
    // identity, and verify_password() can only ever say no for it. Treated as authoritative
    // it silently turns "authenticate this directory user" into a permanent denial — and
    // once console login onboards LDAP users, the FIRST login would persist such a row
    // and every later one would be refused. So the local store does not answer for these,
    // and the configured backend does.
    //
    // The row's ROLE is still the subject's role — only the password is external, so it
    // is carried past the local branch and applied to whatever the backend returns.
    std::string external_role;

    // Console-managed users (web_users table) are the user store: if the username
    // exists in the DB it is authoritative — verify against its stored hash and
    // do NOT fall through to the LDAP backend.
    bool local_answered = false;
    AuthResult local;
    if (db) {
        try {
            if (auto row = db->get_web_user(username)) {
              if (row->hash.rfind("pbkdf2$", 0) != 0) {
                external_role = row->role;
                log::info("auth: '" + username + "' has no local password (external "
                          "identity) — asking the '" + cfg.auth_backend + "' backend");
              } else {
                local_answered = true;
                AuthResult& r = local;
                r.ok = verify_password(password, row->hash);
                if (!r.ok) log::info("auth: DB user '" + username + "' password mismatch");
                // An account that has never had its password set by its owner is
                // not usable for enrolment either. The console already refuses one
                // (fastpki-web's pre-routing gate lets a must_reset session reach only
                // /api/me, /api/password and /api/logout) — but the console does its own
                // lookup and never calls this function, so without this the SAME row
                // authenticated EST/MS/SCEP/CMP Basic auth with the seeded password.
                // Gating one door and not the other leaves the well-known default live
                // on the path that actually mints certificates.
                if (r.ok && row->must_reset) {
                    log::info("auth: DB user '" + username +
                              "' must change its password before it can enrol — denying");
                    return {};
                }
                if (r.ok && !row->role.empty()) r.role = row->role;
                // A local identity is its own subject, unqualified: it belongs to no
                // directory, so there is nothing to qualify it BY.
                //
                // ⚠️ THE CANONICAL ROW NAME, NOT WHAT WAS TYPED. get_web_user() matches
                // `lower(username)=lower($1)` and returns the stored row precisely so that
                // "Admin" resolves "admin" — and this then threw that away and handed the
                // caller's spelling on as the authorization subject. Everything downstream
                // compares it EXACTLY: roles_for_subject() matches `selector_value=$2` with
                // no lower(), so a grant bound to `boss` was invisible to a caller who
                // signed in as `BOSS`; and the name is written to `certs.owner`, which the
                // console's mTLS path now compares against a certificate's CN. One identity
                // spelled two ways is two subjects to every one of those.
                if (r.ok) r.subject = row->username;
              }
            }
        } catch (const std::exception& e) {
            log::err(std::string("auth: DB user lookup failed: ") + e.what());
            // fall through to the configured backend (ldap has its own store)
        }
    }
    if (local_answered) return local;

    const std::string& be = cfg.auth_backend;
    if (be == "local") {
        // "local" IS the web_users table, which was just consulted above. Getting
        // here means the username is not in it (or there is no DB at all), so the
        // answer is a deny — there is no file to fall back to.
        log::info("auth: no such user '" + username + "' in web_users — denying");
        return {};
    }
    // ⚠️ The branch below assigns no role DIRECTLY, and that has not changed. MASTER_USERS
    // used to name usernames that got "admin" here — an authorization decision taken from
    // a config file, invisible to the console and unreplicated.
    //
    // The other half of the sentence that replaced it is: "…or a
    // `subject_roles` grant, like every other subject". A directory identity could not
    // HAVE such a grant, because the only selector that fits one is `group` and nobody
    // ever resolved a user's groups. Now the bind is followed by a membership lookup and
    // the groups travel with the result, so the grant an admin makes in the console is
    // the grant the gate applies. Still no role decided here — the tables decide.
    if (be == "ldap") {
#ifdef FASTPKI_WITH_LDAP
        // The login names ONE directory and only that directory is asked. The groups below
        // therefore come from the provider that accepted the bind, not from a second lookup
        // that might land elsewhere.
        const auto providers = ldap_providers(cfg, db);
        // ⚠️ AN EMPTY PROVIDER TABLE IS A CONFIGURATION STATE, AND IT HAS TO SAY SO.
        // AUTH_BACKEND=ldap with no directory rows refuses every login, and the refusal is
        // indistinguishable from a wrong password — an operator who moved the LDAP_* keys
        // into their environment file rather than the config table sees "no such user" for
        // everybody and nothing pointing at the cause.
        //
        // Said ONCE per process, not per attempt: a message repeated on every failed login
        // is how the token probe drowned the log until it was unreadable, and the fact
        // being reported here does not change between requests.
        if (providers.empty()) {
            static std::once_flag told;
            std::call_once(told, [] {
                log::err("auth: AUTH_BACKEND=ldap but no directory is configured — every "
                         "directory login will be refused. Add one with "
                         "`fastpki-config auth-providers-add <id> --uris ... --base-dns ...`; "
                         "the LDAP_* config keys are no longer read.");
            });
            return {};
        }

        // ⚠️ SPLIT BEFORE THE BIND, AND SEND THE BARE NAME ON. ldap_bind_check builds
        // `CN=<username>,<base>`, so handing it `CORP\alice` asks the directory for an
        // entry called `CN=CORP\alice` — which nothing has. A qualified login could not
        // succeed at all before this; it was a missing feature, not a broken path.
        const QualifiedLogin q = split_qualified_login(username, providers);
        if (q.user.empty()) {
            // Only `DOMAIN\user` with an unknown or malformed domain lands here. Refusing
            // is the point: retrying it as a plain name would ask every directory for a
            // literal `NOSUCH\alice`, and an entry with that name would authenticate.
            log::info("auth: '" + username + "' names a directory this deployment has not "
                      "configured — denying rather than retrying it as a plain username");
            return {};
        }
        // ⚠️ AN UNQUALIFIED LOGIN IS A LOCAL ACCOUNT, AND THE LOCAL TABLE HAS ALREADY
        // ANSWERED. Getting here with no qualifier means web_users has no such row, so the
        // answer is a deny — NOT a sweep of every directory.
        //
        // Binding a bare name against each directory in turn until one accepted was the
        // product picking an identity: with the same username in two domains, the PASSWORD
        // decided which authority the person belonged to. It also sent that password to
        // every configured directory, a partner organisation's included, on the way to
        // finding the one that matched.
        //
        // There is no "how many directories are configured" test here on purpose. The rule
        // is the same with one directory as with ten, because it is a rule about what a name
        // MEANS: no qualifier, no directory. Someone who means a directory identity types
        // `CORP\alice` or `alice@corp.example`, and the sign-in page's domain picker fills
        // that in for them — its first option is "local account", so a directory is always a
        // deliberate choice rather than one inherited from list order.
        if (q.provider.empty()) {
            log::info("auth: '" + username + "' carries no directory — an unqualified name is "
                      "a local account, and web_users has no such row. Sign in as "
                      "`<directory>\\" + username + "` (or pick the domain on the sign-in "
                      "page) to authenticate against a directory.");
            return {};
        }

        for (const auto& p : providers) {
            if (!p.enabled) continue;
            // A qualified login is tried against THAT directory and no other. Falling
            // through to the rest would defeat the qualification: `CORP\alice` would
            // authenticate against PARTNER if PARTNER happened to hold an `alice`.
            // Unconditional now: q.provider cannot be empty past the check above.
            if (p.id != q.provider) continue;
            AuthResult r;
            r.ok = ldap_bind_check(p, q.user, password);
            if (!r.ok) continue;
            r.role   = external_role;   // empty unless a `!external` row named one
            // ⚠️ THE ROW IS KEYED ON THE SUBJECT, NOT ON WHAT WAS TYPED. A directory user
            // onboarded into web_users is stored under `<provider>\\<user>`, so a bare
            // `alice` at the prompt finds nothing in the lookup at the top of this
            // function and arrives here with no role. Ask again under the name the
            // directory just gave us, or an onboarded user silently loses their role
            // every time they log in with the short form.
            if (external_role.empty() && db) {
                try {
                    if (auto row = db->get_web_user(qualify_subject(p.id, q.user)))
                        if (!row->role.empty()) r.role = row->role;
                } catch (const std::exception& e) {
                    log::err(std::string("auth: qualified web_user lookup failed: ") + e.what());
                }
            }
            // ⚠️ QUALIFIED, like r.subject on the next line. Bare group CNs were the whole
            // of this defect: a role granted to CORP\Admins matched PARTNER's Admins by
            // plain string equality, so configuring a second directory silently widened
            // every group grant already in place.
            for (auto& g : ldap_groups_for_user(p, q.user))
                r.groups.push_back(qualify_subject(p.id, g));
            // The directory that ACCEPTED the credentials names the subject — not the
            // string the client typed, and not a second lookup that might land elsewhere.
            r.subject = qualify_subject(p.id, q.user);
            if (r.groups.empty())
                log::info("auth: ldap user '" + r.subject + "' is in no group directory '" +
                          p.id + "' reports — it holds only what `subject_roles` grants "
                          "that subject");
            return r;
        }
        return {};
#else
        log::err("AUTH_BACKEND=ldap but built without FASTPKI_WITH_LDAP — denying");
        return {};
#endif
    }
    // `none` is GONE. It returned ok=true for any username with no web_users row and
    // any non-empty password, and `AuthResult.role` defaulted to `requester` — a seeded
    // console role holding est:enrol|*, ms:enrol|* and cert:request|*. Measured against a
    // fresh database, `curl -u mallory:whatever .../simpleenroll` returned HTTP 200 and a
    // certificate, for a username in no table at all. Our own deploy/bootstrap.compose.conf
    // shipped it.
    //
    // The rule: settings that weaken the product's security and open holes for attacks —
    // AUTH_BACKEND=none among them — are removed rather than defaulted off.
    //
    // It falls to the unknown-backend deny below — which is the right landing place: an
    // operator who still has AUTH_BACKEND=none in a config gets a refusal naming the key,
    // not a silent downgrade to something weaker.
    log::err("auth: unknown AUTH_BACKEND '" + be + "' — denying (valid: local, ldap)");
    return {};
}

// The directories to try, in order. ALWAYS DEFINED — a build without LDAP still asks, and
// gets an empty list.
//
// The configuration describes ONE directory, so that is what this returns today: the
// per-provider tables and the console that manages them are the next slice. The point of
// routing every caller through here first is that they stop reading `cfg.ldap_*`
// individually — nine functions and nine call sites each had their own copy of "which
// directory am I talking to", and every one of them would have had to learn about the
// second directory separately.
// ── Which directory does this login name? ─────────────────────────────────────────────
//
// See the header for why the two accepted forms are treated differently: `DOMAIN\user` is
// unambiguous and an unknown domain is an ERROR, while `user@domain` is ambiguous with an
// email address and only splits when the suffix names a configured directory.
static std::string ascii_lower(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    return s;
}

QualifiedLogin split_qualified_login(const std::string& login,
                                     const std::vector<LdapProvider>& providers) {
    // Resolve a typed domain to a configured provider id. Case-insensitive throughout: a
    // user types the domain the way their organisation says it, which need not be the case
    // of anything we store.
    //
    // ⚠️ FOUR SPELLINGS NAME ONE DIRECTORY, and a directory that answers to only one of
    // them refuses the other three as an unknown domain. A Windows domain has a NetBIOS
    // short name (`CORP`), a DNS root (`corp.contoso.com`) and a Kerberos realm
    // (`CORP.CONTOSO.COM`) — Windows forms the realm by upper-casing the root — and there
    // is no string conversion between the short name and the FQDN, which is why both are
    // stored rather than derived. The realm is matched via `realm()` and never stored.
    //
    // The id and display name stay first: they are what a deployment that has never heard
    // of Active Directory uses, and they must keep working unchanged.
    auto resolve = [&](const std::string& domain) -> std::string {
        const std::string want = ascii_lower(domain);
        for (const auto& p : providers) {
            if (ascii_lower(p.id) == want || ascii_lower(p.display_name) == want)
                return p.id;
            if (!p.netbios_name.empty() && ascii_lower(p.netbios_name) == want) return p.id;
            if (!p.dns_root.empty() &&
                (ascii_lower(p.dns_root) == want || ascii_lower(p.realm()) == want))
                return p.id;
        }
        return "";
    };

    if (const auto bs = login.find('\\'); bs != std::string::npos) {
        const std::string domain = login.substr(0, bs);
        const std::string user   = login.substr(bs + 1);
        if (domain.empty() || user.empty()) return {};   // `\alice`, `CORP\` — not a login
        const std::string id = resolve(domain);
        if (id.empty()) return {};                       // unknown domain: refuse, see header
        return { id, user };
    }

    // `user@domain`. Split on the LAST `@` so a name that legitimately contains one still
    // resolves its trailing domain, and only when that domain is configured.
    if (const auto at = login.rfind('@'); at != std::string::npos && at + 1 < login.size()) {
        const std::string id = resolve(login.substr(at + 1));
        if (!id.empty()) return { id, login.substr(0, at) };
    }
    return { "", login };
}

std::string qualify_subject(const std::string& provider_id, const std::string& user) {
    if (provider_id.empty()) return user;
    return provider_id + "\\" + user;
}

std::string subject_provider(const std::string& subject) {
    const auto bs = subject.find('\\');
    return bs == std::string::npos ? std::string() : subject.substr(0, bs);
}

std::string subject_user(const std::string& subject) {
    const auto bs = subject.find('\\');
    return bs == std::string::npos ? subject : subject.substr(bs + 1);
}

std::vector<LdapProvider> ldap_providers(const Config& cfg, Db* db) {
    (void)cfg;
    // ⚠️ THE TABLES ARE THE ONLY SOURCE, AND NO DATABASE HONESTLY MEANS NO DIRECTORIES.
    // This used to build one provider out of the LDAP_* config keys, which is why a
    // deployment could only ever have ONE directory: a flat key-value file names a single
    // service, so "several AD domains" was not a missing feature but a shape the
    // configuration could not express. Those keys are no longer read here — not even as a
    // fallback, because a fallback would mean two sources that can disagree, and the one
    // that wins would depend on whether a row happened to exist.
    if (!db) return {};
    std::vector<LdapProvider> out;
    try {
        for (const auto& r : db->list_ldap_providers()) {
            LdapProvider p;
            p.id           = r.id;
            p.display_name = r.display_name;
            p.enabled      = r.enabled;
            p.priority     = r.priority;
            // ⚠️ SPLIT THE WAY THE CONFIG PARSER SPLIT THEM, using its own functions. URIs
            // are comma-separated; base DNs are SEMICOLON-separated because a DN contains
            // commas — "dc=corp,dc=example" is one base. A second, private idea of how a
            // list is spelled would shred every base DN on this path while the old one
            // kept them whole.
            p.uris         = split_csv(r.uris);
            p.base_dns     = split_semi(r.base_dns);
            p.bind_dn      = r.bind_dn;
            p.bind_pw      = r.bind_pw;
            p.group_filter = r.group_filter;
            p.group_attr   = r.group_attr;
            p.ca_cert_file = r.ca_cert_file;
            p.network_timeout_sec = r.network_timeout_sec;
            p.template_base       = r.template_base;
            p.netbios_name        = r.netbios_name;
            p.krb_keytab          = r.krb_keytab;
            p.dns_root            = r.dns_root;
            out.push_back(std::move(p));
        }
    } catch (const std::exception& e) {
        // A directory list we cannot read is not an empty directory list. Saying so
        // matters because every caller treats {} as "no directories are configured", and
        // that is a configuration statement rather than an outage.
        log::err(std::string("auth: cannot read the auth provider tables: ") + e.what());
        return {};
    }
    return out;
}

AuthResult authenticate(const Config& cfg, const std::string& username,
                        const std::string& password, Db* db,
                        const std::string& client_ip) {
    auto& t = login_throttle();
    t.configure(cfg);

    // Asked BEFORE the password is looked at. A locked-out attempt must not cost a PBKDF2
    // hash or an LDAP bind — otherwise the rate limiter is itself the amplifier, turning
    // cheap guesses into expensive server work.
    if (const int wait = t.retry_after(username, client_ip); wait > 0) {
        log::info("auth: '" + username + "' is in password-guessing backoff for another " +
                  std::to_string(wait) + "s — denying without checking the password");
        AuthResult denied;
        denied.retry_after = wait;
        return denied;
    }

    AuthResult r = authenticate_unthrottled(cfg, username, password, db);

    // ⚠️ EVERY non-ok outcome counts, not only a wrong password. An account that must
    // change its password before it can be used is refused here with the password
    // CORRECT — so exempting that case would leave exactly one unthrottled oracle for
    // confirming a guess, on precisely the accounts still holding a seeded password.
    if (r.ok) t.record_success(username, client_ip);
    else      t.record_failure(username, client_ip);
    return r;
}


// See auth.hpp. Deliberately tolerant — an unreachable directory returns {}, which
// grants nothing extra and never blocks an enrolment that would otherwise succeed on the
// user's own grants.
std::vector<std::string> directory_groups_for(const Config& cfg, Db* db, const std::string& username) {
    if (username.empty()) return {};
    // ⚠️ Gated on LDAP being CONFIGURED, not on AUTH_BACKEND. This used to require
    // auth_backend == "ldap", which made the whole helper inert for the deployment shape
    // it is most needed in: SSO through OIDC or SAML with the groups still living in AD.
    // AUTH_BACKEND has only two legal values and cannot describe
    // SAML or OIDC at all — so keying off it answered "this user has no groups" for every
    // federated identity. The question here is what the DIRECTORY says, and that is
    // answerable whenever there is a directory to ask.
    //
    // What this still cannot do: a pure OIDC/SAML deployment with no LDAP at all carries
    // group membership only in the assertion, i.e. only in the SESSION. For the caller
    // themselves that is `groups_of(req)` and the console uses it; for some OTHER user
    // there is nothing to query, and {} is the honest answer rather than a silent one.
#ifdef FASTPKI_WITH_LDAP
    // The union across directories: a subject may exist in one domain and its groups are
    // that domain's. Asking only the first configured directory would answer "no groups"
    // for everybody in the second one — the silent half-answer this ticket is about.
    //
    // ⚠️ ONE DIRECTORY FAILING MUST NOT LOSE THE OTHERS' ANSWERS. The catch is per
    // provider, so an unreachable domain costs its own groups and nothing else — with a
    // single try around the whole loop, the first timeout would discard the memberships
    // already collected from directories that answered.
    //
    // ⚠️ THE ARGUMENT IS A SUBJECT, AND A DIRECTORY SUBJECT CARRIES ITS DIRECTORY. Every
    // caller passes the name the request was AUTHORIZED under, which for a directory
    // identity is `<provider>\\<user>` — and the directory has no entry by that name, so
    // handing it through unsplit asks for `CN=<provider>\<user>,<base>`, finds nothing,
    // and answers "this subject is in no group". That is the same silent, safe-direction
    // failure as an unresolved membership: the caller is simply refused, with nothing to
    // say a grant went unseen. The login path already splits before it binds; this is the
    // second reader of the same name and it has to split by the same rule.
    const auto providers = ldap_providers(cfg, db);
    const QualifiedLogin q = split_qualified_login(username, providers);
    // A name that NAMES a directory this deployment does not have is not a plain username:
    // answering {} is the same refusal the login path makes, rather than asking every
    // directory about a literal backslash.
    if (q.user.empty()) return {};

    // ⚠️ AN UNQUALIFIED SUBJECT IS LOCAL, SO IT HAS NO DIRECTORY GROUPS -- {} IS THE ANSWER.
    // This used to fall through to the loop with an empty provider, which the filter below
    // does not narrow, so a BARE name collected the memberships of EVERY enabled directory
    // and was authorized by all of them at once. That is the same silent privilege widening
    // qualification was introduced to close, reached by the other door: a local `alice` was
    // handed `CORP\Admins` and `PARTNER\Admins` together.
    //
    // Narrowing, not widening: a caller that genuinely means a directory identity has to say
    // which directory, which is the whole point of the qualifier. A name that does not say
    // means the web_users table, and the web_users table has no groups.
    if (q.provider.empty()) return {};

    std::vector<std::string> all;
    for (const auto& p : providers) {
        if (!p.enabled) continue;
        // A qualified subject belongs to ONE directory. Asking the others would rebuild
        // exactly the collision qualification removes: `CORP\alice` would collect
        // `PARTNER\alice`'s memberships and be authorized by them.
        if (p.id != q.provider) continue;
        try {
            for (auto& g : ldap_groups_for_user(p, q.user)) all.push_back(qualify_subject(p.id, g));
        } catch (const std::exception& e) {
            log::err("directory_groups_for('" + username + "') on directory '" + p.id +
                     "': " + e.what());
        }
    }
    return all;
#else
    return {};
#endif
}

// See auth.hpp.
std::string owner_email(const Config& cfg, Db* db, const std::string& owner, std::string* source) {
    if (owner.empty() || !db) return {};
#ifdef FASTPKI_WITH_LDAP
    // The same split directory_groups_for() makes, for the same reason: `CORP\alice` is a
    // question for CORP and nobody else, and a bare name is a local account.
    const auto providers = ldap_providers(cfg, db);
    const QualifiedLogin q = split_qualified_login(owner, providers);
    if (!q.provider.empty() && !q.user.empty()) {
        for (const auto& p : providers) {
            if (!p.enabled || p.id != q.provider) continue;
            try {
                const std::string mail = ldap_mail_for_user(p, q.user);
                if (plausible_mailbox(mail)) {
                    if (source) *source = "directory";
                    return mail;
                }
            } catch (const std::exception& e) {
                log::err("owner_email('" + owner + "') on directory '" + p.id + "': " + e.what());
            }
        }
    }
#else
    (void)cfg;
#endif
    // The account's own field: a local account, an SSO account filled at sign-in, or a
    // directory account whose directory holds no address.
    try {
        if (auto row = db->get_web_user(owner); row && plausible_mailbox(row->email)) {
            if (source) *source = "account";
            return row->email;
        }
    } catch (const std::exception& e) {
        log::err("owner_email('" + owner + "'): cannot read the account: " + std::string(e.what()));
    }
    return {};
}

} // namespace pki
