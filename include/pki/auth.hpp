#pragma once
#include <string>
#include <vector>

#include "pki/ms_template.hpp"

namespace pki {

struct Config;
class Db;

// Result of a username/password authentication.
struct AuthResult {
    bool        ok{false};
    // ⚠️ ONE FIELD, TWO NAMESPACES — do not "tidy" this without reading the note below.
    //
    // `pki::authenticate()` is called by fastpki-est, fastpki-msxcep, and the console's
    // /api/login when the local hash does not answer and AUTH_BACKEND is not `local`. Its
    // enrolment consumers read this field differently:
    //
    //   - may_enrol() and role_cert_cap() put it in the claimed-roles set and intersect
    //     that with list_roles() — the CONSOLE/RBAC namespace (admin | requester | ...).
    //     An LDAP or none-backend user has no web_users row, so for them this value is
    //     the ONLY thing either has to go on.
    //   - cert profile resolution reads the ISSUANCE namespace (standard | master),
    //     which is a different set of words in the same column.
    //
    // ⚠️ THE WORST CONSEQUENCE of that ambiguity is gone, so the note above is
    // shorter than it was. `est/main.cpp` used to compare this field to "master" to pick
    // between two per-name caps depending on WHO asked. Those keys are all gone, the
    // per-requester cap lives in `roles.max_certs`, and nothing compares this
    // string to "master" any more.
    //
    // The field still carries two namespaces, and splitting it is still the real fix —
    // reads it as a cert-profile name. It is no longer load-bearing for a quota.
    //
    // ⚠️ EMPTY BY DEFAULT, and that is the point — no defaults. It used to default
    // to "requester" — not a placeholder, a SEEDED console role holding est:enrol|*,
    // ms:enrol|* and cert:request|*. So every authentication path that did not set a role
    // explicitly handed out real enrolment permission: measurably, under AUTH_BACKEND=none
    // an unknown username with any password got a certificate recorded as role=requester.
    // A default role is a grant nobody made. Empty means "this subject claims nothing",
    // and the gate decides from the tables.
    std::string role{};

    // The directory groups this subject belongs to, filled by the LDAP backend
    // and empty for a `web_users` password. This is what makes a directory identity
    // AUTHORIZABLE rather than merely authenticated.
    //
    // ⚠️ THESE ARE THE SELECTOR VALUES, not decoration. `subject_roles` has carried a
    // `group` selector kind for a long time and the console has imported LDAP group names
    // into it — but nothing ever resolved a user's memberships, so every `group`
    // row was a grant that could not match. An admin could see the group in the picker,
    // grant it a role, and the grant did nothing. Filling this field is the reader that
    // writer never had.
    //
    // They must be spelled the way `ldap_list_groups()` spells them (LDAP_GROUP_ATTR,
    // default `cn`), or a grant made from the picker will not match the membership
    // resolved at login. Both go through the same filter+attribute for that reason.
    std::vector<std::string> groups{};

    // Non-zero when this attempt was refused by the guessing backoff rather than by the
    // password being wrong: the number of seconds before another attempt is worth making.
    // A caller that speaks HTTP should answer 429 with this as Retry-After, so a real user
    // who is locked out is told what happened instead of concluding their password broke.
    int retry_after{0};

    // ⚠️ THE NAME TO AUTHORIZE ON — not the string the client sent. Set whenever `ok`.
    //
    // A directory identity is qualified by the directory that accepted it:
    // `<provider>\<user>`. A local `web_users` identity stays bare. Both `CORP\alice` and
    // `alice@CORP` at the prompt therefore reach authorization as the SAME subject,
    // `CORP\alice`, and `alice` in two different directories are two different subjects.
    //
    // Callers MUST use this rather than the username they passed in. EST did the latter:
    // it assigned `a.username = user` before authenticating, so a qualified login bound
    // correctly against the directory and was then measured for grants under the raw
    // string — authenticated, then refused, with nothing saying why.
    std::string subject;
};


// Authenticate username/password against the configured AUTH_BACKEND:
//   "local" — the web_users table (PBKDF2 hashes), managed from the console or
//             `fastpki-config web-user`. This is the only user store.
//   "ldap"  — bind against a directory (built only with FASTPKI_WITH_LDAP)
// The backend is selected by cfg.auth_backend. The role comes from the web_users row and
// from nowhere else — MASTER_USERS, which used to name usernames that got "admin" under
// ldap/none, is gone: no master users, and no globals.
//
// web_users is consulted FIRST whenever `db` is provided, and is authoritative if
// the username exists there; the configured backend is reached only for usernames
// not in the DB — which under "local" means the login is simply denied.
//
// ⚠️ RATE LIMITED. Repeated failures for the same account, or from the same address, earn
// a growing delay; while it is in force this returns a denial WITHOUT checking the
// password, with `retry_after` set. `client_ip` may be empty (a caller with no address to
// offer), in which case only the account is counted. See LoginThrottle — and note that the
// console does its own local password check and reaches this only for directory logins, so
// this is one of two doors, not the only one.
AuthResult authenticate(const Config& cfg, const std::string& username,
                        const std::string& password, Db* db = nullptr,
                        const std::string& client_ip = "");

// ── A COMPUTER IS NOT A USER ───────────────────────────────────────────────────
//
// The requirement: a user/computer distinction is needed everywhere. This is the
// ONE place the distinction is decided, so that "everywhere" is a list of call sites
// rather than a list of re-implementations. Both signals come out of the Kerberos client
// principal name, which is what every path already carries:
//
//   trailing `$`  — AD REQUIRES a machine account's sAMAccountName to end in it, so a
//                   domain computer authenticates as FASTPKI-WIN$. Not a heuristic: the
//                   directory enforces it.
//   a `/`         — a service-form principal (host/foo@REALM) is never a person. This is
//                   the rule that was chosen, and it is the more general one:
//                   it catches non-Windows clients (a Linux host with a keytab), which
//                   the `$` test alone would miss entirely. Windows machine accounts do
//                   NOT use that form, so it is both rules, not either.
//
// The realm is stripped first, so `FASTPKI-WIN$@FASTPKI.LAB` classifies the same as the
// realm-stripped `FASTPKI-WIN$` that msxcep/main.cpp stores. Callers hand us whichever
// they hold and get the same answer — that equality is the point of the function.
//
// ⚠️ DERIVED, NEVER STORED. It is a pure function of the name, so a column holding a copy
// could only ever disagree with it — and a rule re-implemented per call site is exactly
// the shape that produced several of them. `tests/user_computer_kind.sh` census-checks
// that no other site spells the rule out.
enum class PrincipalKind { User, Computer };
PrincipalKind principal_kind(const std::string& principal);

// "user" | "computer" — the wire and UI spelling, for JSON and log lines.
const char* principal_kind_name(const std::string& principal);

inline bool is_computer_principal(const std::string& principal) {
    return principal_kind(principal) == PrincipalKind::Computer;
}

// Produce a storable hash string "pbkdf2$<iter>$<salthex>$<hashhex>" for a
// password (what goes in web_users.hash). Throws pki::Error on failure.
std::string hash_password(const std::string& password, int iterations = 210000);

// Verify a password against a stored "pbkdf2$..." hash string. Constant-time.
bool verify_password(const std::string& password, const std::string& stored);

// ── One directory ──────────────────────────────────────────────────────────────────
//
// An organisation routinely has several AD domains, and often several forests. Each is a
// separate directory with its OWN service account, base DNs and group naming — so a
// directory is an object here, not a set of global settings.
//
// ⚠️ THE OLD SHAPE COULD ALREADY LIST SEVERAL SERVERS AND STILL COULDN'T DO THIS. The
// configuration carried `LDAP_URIS` and `LDAP_BASE_DNS` as lists and the search loops
// walked the cross product of them — but there was exactly ONE `LDAP_BIND_DN` and one
// password for the lot. That expresses "several replicas of one domain", which is
// failover; it cannot express "two domains", because the second domain will not accept
// the first one's service account. Reading the plural key names as multi-domain support
// is the mistake this type exists to make impossible.
//
// `uris` are the replicas OF THIS ONE DIRECTORY, tried in order until one answers.
struct LdapProvider {
    std::string id;                 // stable identifier, referenced by web_users.auth_provider
    std::string display_name;       // what the console shows in a domain selector
    bool        enabled{true};
    int         priority{100};      // lower is tried first when several could match
    std::vector<std::string> uris;      // replicas of THIS directory: ldaps://dc1, ldaps://dc2
    std::vector<std::string> base_dns;
    std::string bind_dn;            // this directory's own service account
    std::string bind_pw;
    std::string group_filter;       // default: groupOfNames/group/posixGroup
    std::string group_attr;         // default: cn
    std::string ca_cert_file;
    int         network_timeout_sec{3};
    std::string template_base;      // MS template container, when discovery cannot work
    // The other two names this directory answers to. A Windows domain is known by a
    // NetBIOS short name (`CORP`), a DNS root (`corp.contoso.com`) and a Kerberos realm
    // (`CORP.CONTOSO.COM`), and users type whichever their organisation taught them.
    // Optional: empty means only the id and display name resolve, which is what a
    // single-directory deployment has always had.
    std::string netbios_name;
    std::string dns_root;
    // This directory's Kerberos keytab. Per directory because a keytab holds ONE realm's
    // service key: a single deployment-wide path could serve one domain and left every
    // other domain's clients failing SPNEGO against a key the acceptor did not hold.
    // Empty means this directory does not accept SPNEGO.
    std::string krb_keytab;
    // The realm is DERIVED, never stored: Windows itself forms it by upper-casing the DNS
    // root, and a stored copy is a second source that can disagree with the first.
    std::string realm() const {
        std::string r = dns_root;
        for (char& c : r) if (c >= 'a' && c <= 'z') c = char(c - 'a' + 'A');
        return r;
    }
};

// The directories this deployment authenticates against, in the order they should be
// tried. ALWAYS DEFINED — an empty list means "no directory is configured", which every
// caller already handles.
//
// ⚠️ THE PROVIDER TABLES ARE THE SOURCE, AND `db == nullptr` RETURNS {}. The LDAP_* config
// keys are not consulted, not even as a fallback: a fallback is two sources that can
// disagree, with the winner decided by whether a row happens to exist. A caller with no
// database has no provider table, so it has no directories — which is the truth, and it is
// also what makes an unconfigured deployment refuse a directory login instead of guessing.
//
// `cfg` stays in the signature because the SAML and OIDC providers land beside these and
// still read it, and because callers pass the effective config anyway.
std::vector<LdapProvider> ldap_providers(const Config& cfg, Db* db);

// ── A login name, split into the directory that owns it ───────────────────────────────
//
// Accepts the two forms an operator actually types. `provider` is empty when the name
// carries no directory.
//
// ⚠️ AN EMPTY `provider` MEANS LOCAL, NOT "TRY THEM ALL". It used to say the latter, and
// callers that took it literally re-created the collision qualification exists to remove:
// asking every directory about a bare name unions two domains' identically-named accounts
// into one set of grants. A name that does not say which authority it belongs to belongs to
// none of them -- it is the built-in web_users table.
//
// The LOGIN path follows this like everything else: authenticate() refuses an unqualified
// name that web_users does not hold, rather than binding it against each directory in turn
// until one accepts. There is no "how many directories are configured" case -- the rule is
// about what the name means. The sign-in page's domain picker supplies the qualifier, and
// its first option is "local account" so a directory is always a deliberate choice.
struct QualifiedLogin {
    std::string provider;   // "" when the login named no directory
    std::string user;       // always the BARE name to bind with
};

// Split `CORP\alice` or `alice@CORP` into { "CORP", "alice" }, resolving the domain part
// against the CONFIGURED providers (case-insensitively, matching id or display name).
//
// ⚠️ THE TWO FORMS ARE NOT SYMMETRIC, deliberately.
//   `DOMAIN\user` is unambiguous — a backslash appears in no username we accept — so an
//   UNKNOWN domain is an error: {"", ""} , which the caller must refuse rather than retry
//   as a plain name. Silently falling back would let `NOSUCH\alice` authenticate as
//   whatever directory happens to hold `NOSUCH\alice` as a literal.
//   `user@domain` is ambiguous with an email address, and console usernames routinely ARE
//   email addresses. So it splits ONLY when the suffix names a configured provider;
//   otherwise the whole string is the username. Without that, `dana@example.com` becomes
//   user `dana` in a directory nobody configured.
QualifiedLogin split_qualified_login(const std::string& login,
                                     const std::vector<LdapProvider>& providers);

// The canonical authorization subject for a directory identity: `<provider>\<user>`.
// One spelling, so a grant made in the console and a login at a protocol agree.
std::string qualify_subject(const std::string& provider_id, const std::string& user);

// The two halves of a qualified subject, for callers that need the parts rather than the
// whole -- a certificate names the PERSON in its commonName and the authenticating
// authority somewhere else. Exact, not heuristic: qualify_subject() joins with a
// backslash and a backslash appears in no username we accept, so the first one is the
// separator. An unqualified subject is all user and no provider.
std::string subject_provider(const std::string& subject);   // "" when unqualified
std::string subject_user(const std::string& subject);       // the whole string when unqualified

// LDAP backend — only *defined* when built with FASTPKI_WITH_LDAP.
bool ldap_bind_check(const LdapProvider& p, const std::string& username,
                     const std::string& password);

// Search the directory for group names (console "Import from LDAP"). Binds
// with the service account (cfg.ldap_bind_dn) or anonymously, searches each base
// DN for cfg.ldap_group_filter, and returns cfg.ldap_group_attr values (deduped,
// sorted; DN as fallback). Only *defined* when built with FASTPKI_WITH_LDAP.
// `error`, when non-null, receives the directory's own words for a bind or search
// that FAILED. Without it the caller cannot tell "this directory has no groups" from
// "this directory refused to answer" — and those rendered identically in the console,
// which is why an Active Directory `Operations error` (its reply to an anonymous search)
// was reported to the operator as an empty result for as long as the feature existed.
std::vector<std::string> ldap_list_groups(const LdapProvider& p, std::string* error = nullptr);

// Read the MS certificate templates straight out of the directory, instead of asking an
// operator to export a CSV from AD and paste it back in.
//
// Templates live in the CONFIGURATION naming context, not under any of the base DNs used
// for users and groups — `CN=Certificate Templates,CN=Public Key Services,CN=Services,` +
// whatever the RootDSE reports as configurationNamingContext. That context is read from
// the server rather than derived from a base DN, because a forest's configuration NC is
// not a suffix of the domain NC in the general case, and guessing it is how this kind of
// import ends up working on one domain and not the next one.
//
// Returns the templates it could read. On failure `error` (when given) carries a reason a
// person can act on. Declared here rather than in a header of its own because it is the
// same connection, the same service bind and the same failure modes as the group listing
// above — the only difference is which subtree is asked.
// Ask the domain for its NetBIOS short name and DNS root (the crossRef object AD keeps for
// exactly this, and the same lookup the LSA does to turn `CORP\alice` into a realm). Each
// output is filled only when it is EMPTY -- an operator's typed value is a decision and
// outranks a discovered one. Returns false when the directory cannot be asked, which is
// advisory: the two names can always be typed, so no caller fails a save over it.
bool ldap_discover_domain_names(const LdapProvider& p, std::string& netbios,
                                std::string& dns_root, std::string* error = nullptr);

std::vector<MsTemplate> ldap_fetch_ms_templates(const LdapProvider& p, std::string* error = nullptr);

// The groups ONE user belongs to, named exactly as ldap_list_groups() names them
// so a role granted to a picker-imported group actually matches at login.
//
// Two lookups, because directories disagree about which end of the membership is
// authoritative: first the user entry is found (by sAMAccountName / uid / cn, then the
// CN=<user>,<base> form ldap_bind_check uses), then groups are searched by
// (member|uniqueMember|memberUid) pointing at it. The SEARCH direction is used rather
// than reading the user's `memberOf` because a search returns the same LDAP_GROUP_ATTR
// value the picker imported; `memberOf` returns DNs, which would have to be re-mapped to
// names and would not match a grant made from the console.
//
// Best-effort and never throws: an unreachable directory returns an empty list, which
// grants nothing. Only *defined* when built with FASTPKI_WITH_LDAP.
std::vector<std::string> ldap_groups_for_user(const LdapProvider& p, const std::string& username);

// The `mail` attribute of one user, found the same way ldap_groups_for_user() finds the
// user. "" when the entry has none or the directory cannot be asked. Only *defined* when
// built with FASTPKI_WITH_LDAP.
std::string ldap_mail_for_user(const LdapProvider& p, const std::string& username);

// The directory groups for `username`, ALWAYS DEFINED — {} when this build has no
// LDAP or the deployment authenticates locally. It exists because EST and MS-XCEP pass
// groups to may_enrol() and CMP, SCEP and ACME did not: those three authenticate by a
// per-user secret rather than a directory bind, so they had no AuthResult to take groups
// from and simply left them out. A directory user whose enrolment role comes from a group
// was therefore admitted by the console, given credentials, and then refused at the
// protocol gate — that shape once more. Call this wherever a protocol knows WHO the
// caller is but did not get their groups from authenticate().
std::vector<std::string> directory_groups_for(const Config& cfg, Db* db, const std::string& username);

// Where to email a certificate owner. A directory subject (`CORP\alice`) is asked of THAT
// directory's `mail`; failing that — or for any other subject — the account's own Email
// field. "" when neither gives a usable address. `source`, when given, is set to
// "directory" or "account" for the answer used.
//
// The qualifier decides which directory is asked, exactly as it does for groups: a name
// that names no directory is never looked up in one.
std::string owner_email(const Config& cfg, Db* db, const std::string& owner,
                        std::string* source = nullptr);

// Enumerate directory USERS, so an operator can pick one instead of typing a
// username that must match exactly what the directory presents at sign-in. A mistyped
// web_users row is not an error anywhere — it simply never applies, which is the silent
// failure this removes. `q` is a substring; empty lists everything the bind can see.
// Uses the same service-account bind as ldap_list_groups().
struct LdapUser {
    std::string username;   // the value the directory will present at login
    std::string dn;
    std::string display;    // displayName/cn, for telling two similar accounts apart
};
std::vector<LdapUser> ldap_list_users(const LdapProvider& p, const std::string& q,
                                      std::string* error = nullptr);

// The MEMBERS of one group, named as ldap_list_users() names users.
//
// ⚠️ NOT just the `member` attribute. In AD a group is also the PRIMARY group of every
// account whose primaryGroupID is its RID, and those accounts are absent from
// `member`. `Domain Users` is the extreme case: it holds essentially every account and
// lists almost none of them. A members view built on `member` alone would show that group
// as empty — the very group whose grants were in question — so this also searches users by
// primaryGroupID against the group's own RID.
std::vector<LdapUser> ldap_group_members(const LdapProvider& p, const std::string& group,
                                         std::string* error = nullptr);

} // namespace pki
