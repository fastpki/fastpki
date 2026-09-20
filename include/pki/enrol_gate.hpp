#pragma once
#include "pki/db.hpp"
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace pki {

class Db;

// May this subject enrol over this protocol, against this CA?
//
// The five `enrol:*` verbs have been granted, replicated and editable in the console
// since step 3 — and no enrolment binary read them, so narrowing a role's protocols in
// the UI changed nothing. This is the reader.
//
// `verb` is one of "est:enrol" | "acme:enrol" | "cmp:enrol" | "ms:enrol" (see the SCEP
// note below). `user` is the authenticated identity — the Basic/mTLS username for EST and
// MS, the senderKID reference or sender CN for CMP, the EAB kid's username half for ACME.
// `primary_role` is what authenticate() returned; it matters because a deployment may
// authenticate against a directory (LDAP/AD, OIDC, SAML) or mTLS, where there is no
// `web_users` row and the role is all the identity there is.
//
// The effective grant set is the UNION of the primary role and any roles held through
// `subject_roles` — the same rule the console gate uses, and the same reason: holding two
// roles cannot grant less than holding one.
//
// `ca_id` is the CA the request names. A grant carrying `ca_id='*'` allows every CA; a
// grant naming one CA allows only that one, which is how a role is confined to a CA
// (option (a), step 2b).
//
// FAILS CLOSED, with one deliberate exception. If the tables cannot be read the answer is
// false, because a permission system that fails open is worse than one that is down. The
// exception is a deployment that has no `roles` rows AT ALL — a database predating the
// RBAC schema — where every enrolment would otherwise stop dead; there, the gate is
// inert and says so once in the log rather than refusing traffic it cannot judge.
bool may_enrol(Db& db, const std::string& user, const std::string& primary_role,
               const std::string& verb, const std::string& ca_id,
               const std::vector<std::string>& groups = {});
//
// `groups`: the directory groups the caller authenticated with, from
// AuthResult.groups. They become `group` selectors alongside the username, so a role an
// admin granted to an LDAP group in the console is a role this subject actually holds.
// Empty for every protocol that has no directory identity (CMP's PBM secret, ACME's EAB
// HMAC), which is why it defaults — those callers claim no groups, not "all groups".

// Does one of this subject's roles grant `verb` for `ca_id`? The STRICT form.
//
// ⚠️ THE DIFFERENCE FROM may_enrol() IS THE WHOLE POINT, so do not "unify" them. may_enrol
// has two deliberate inert cases — a database with no `roles` rows, and a subject whose
// only role is outside the RBAC namespace — where it returns TRUE, because refusing there
// would stop every enrolment on a deployment that has not adopted RBAC. This function has
// none: unknown subject, unknown role, unreadable tables and no roles at all ALL answer
// false.
//
// That is required for the questions it is asked. It guards actions whose default answer
// is no — revoking a certificate somebody else owns (this replaced MASTER_USERS) —
// where "we cannot tell" must mean refuse. Routing those through may_enrol would hand
// revoke-any to every caller on a deployment with no roles defined, which is the
// inert-fallback-is-the-bypass shape this codebase has now produced three times.
bool subject_holds(Db& db, const std::string& user, const std::string& primary_role,
                   const std::string& verb, const std::string& ca_id,
                   const std::vector<std::string>& groups = {});

// ── which namespace a permission's SCOPE lives in ───────────────────────────────
//
// `role_permissions.scope` is one column serving several kinds of name, and the VERB is
// what says which. `est:enrol|issuing` scopes to a CA id; `profile:use|requester` scopes to
// a cert-profile name; `template:edit|generic-user` to an MS template. That is the whole
// design that was set out, and it is why the column had to stop being called
// `ca_id`.
//
// ⚠️ THIS EXISTS BECAUSE ONE READER GETS IT WRONG BY DEFAULT. `ca_scope_for_roles()` is
// "the CA ids these roles are confined to" and was a bare `SELECT DISTINCT ca_id FROM
// role_permissions` — every permission of the role, indiscriminately. The moment a profile
// name can sit in that column, that query starts returning profile names as CA ids and a
// role scoped to profile `requester` reads as scoped to a CA called `requester`. A comment
// saying "the verb says which namespace" would not have stopped it; a function both the
// query and the gate call does.
//
// Returns "ca", "profile", "template". An unrecognised verb answers "ca" — the namespace
// every older verb used — so a verb added later and forgotten here keeps the behaviour
// it would have had, rather than silently joining a namespace it was never checked against.
// The roles a subject holds, resolved ONCE for every gate that asks.
//
// ⚠️ Exported because `profiles_for_identity()` (cert_profile.cpp) must ask the same
// question `may_enrol()` does. The set is a union of three sources and has two inert cases
// that are NOT bugs — a deployment with no `roles` rows at all, and a subject whose only
// role is an ISSUANCE role (`master`/`standard`) rather than a console one. A second
// reader that reconstructed four of those five facts would hand profiles to subjects the
// permission gate does not recognise, which is the second-gate shape exactly.
struct SubjectRoles {
    bool                     any_defined{false};  // false: this deployment has no roles
    std::set<std::string>    claimed;             // everything the subject names
    std::vector<Db::RoleRow> known;               // the subset that ARE console roles
};

// Throws if the tables cannot be read; each caller decides what that means for it —
// may_enrol denies, profile resolution falls back to the CA default.
SubjectRoles subject_roles(Db& db, const std::string& user, const std::string& primary_role,
                           const std::vector<std::string>& groups = {});

// The roles this subject ACTUALLY holds, comma-separated, for an audit line. "-" when it
// holds none.
//
// The audit recorded the role the protocol was CARRYING, which for MS-WSTEP
// was the struct placeholder `standard` — a word that is not a console role, grants
// nothing, and had no connection to the `requester` grant that actually let the request
// through. An audit trail that names a value the decision did not use is worse than one
// that names nothing, because it reads as an answer.
//
// Resolved through subject_roles(), so it reports exactly what the gate judged — same
// user, same groups, same union. Never throws; an unreadable table gives "-".
std::string effective_roles(Db& db, const std::string& user, const std::string& primary_role,
                            const std::vector<std::string>& groups = {});

// ── The permission model: resource : verb, plus a scope ────────────────────────────────
//
// A permission names a RESOURCE and a VERB — `cert:read`, `ca:manage`, `est:enrol`. The
// resource is also the SCOPE NAMESPACE: it says what the `scope` column's value means, so a
// scope can never be read as the wrong kind of name. `*:*` is the wildcard in every position.
//
// ⚠️ THE RESOURCE IS WHY scope_kind() TAKES A PERMISSION AND NOT A GUESS. It used to return
// Ca for everything that was not `profile:` or `template:`, which meant `self:manage`'s scope
// was scanned as a CA id by ca_scope_for_roles() — one starred grant on a verb that has
// nothing to do with a CA silently unconfined a CA-scoped role across the whole estate.
// Deriving the namespace from the resource makes that unrepresentable rather than guarded.
std::string permission_resource(const std::string& permission);   // "cert:read" -> "cert"
std::string permission_verb(const std::string& permission);       // "cert:read" -> "read"

// A scope value that names no instance. `*` is every instance in the resource's namespace;
// `own` restricts to objects the caller owns and is NOT a name, so neither may be handed to
// ca_scope_for_roles() as a CA id.
bool scope_is_reserved(const std::string& scope);                 // "*" or "own"

enum class ScopeKind { Ca, Profile, Template, None };
ScopeKind scope_kind(const std::string& permission);

// Does a grant carrying `grant_scope` cover `want`? `*` is every name in that namespace.
// Four lines, and it is the one place the star is interpreted — `enrol_gate.cpp` used to
// spell it inline and the console spelled its own default separately.
bool in_scope(const std::string& grant_scope, const std::string& want);

// Does holding `held` satisfy a check for `wanted`? True when they are equal, when `held` is
// the `*:*` wildcard, or when both name the same RESOURCE and that resource orders its verbs
// so `held` is the stronger — `ca:manage` answers a check for `ca:read`.
//
// ⚠️ ORDERINGS ARE PER RESOURCE AND MOST RESOURCES HAVE NONE. `cert`'s read/request/revoke
// are three separate acts, the five protocols are peers, and `profile`/`template` are the
// case this must never be extended to: `edit` deliberately does NOT imply `use`, because
// `use` is issuance entitlement and an administrator who may edit every profile must not
// thereby be able to issue under every profile.
//
// ⚠️ AND THIS IS FOR GATES ONLY. A gate asks "may this caller do X". may_assign_role() asks
// "may this caller GIVE X to somebody else", and there an implication would let a holder hand
// over a grant it does not literally have — a scope row whose effect depends on the
// recipient's other grants, not on the entitlement that justified the implication.
bool permission_implies(const std::string& held, const std::string& wanted);

// How many active certificates may this subject HOLD? `std::nullopt` = no limit.
//
// `roles.max_certs` was chosen over a profile property, and the reason matters:
// profiles live in one JSON blob in the `config` table, which is deliberately excluded from
// the replication publication, so a profile-borne cap would silently differ per
// data center. `roles` IS published, so a number set here reaches every node.
//
// This is a cap on the REQUESTER — "you may hold N certificates" — and is a different limit
// from the deleted `MAX_CERTS_PER_CN`, which capped a NAME ("at most N live certs for a
// hostname"). Both can fire; they answer different questions.
//
// ⚠️ IT SHARES may_enrol's ROLE RESOLUTION, and must. A subject's roles come from three
// places (the primary role, the `web_users` row, `subject_roles`) and the gate has two
// deliberate inert cases — no roles defined at all, and a role outside the RBAC namespace.
// A second resolver that reproduced four of those five facts would apply a cap to subjects
// the permission gate does not recognise, which is the second-gate failure again.
//
// Across several roles the MOST PERMISSIVE number wins, for the same reason may_enrol takes
// the union of grants: holding two roles must not be worse than holding one.
//
// The other two came later, in the same shape and resolved by the
// same read. `std::nullopt` on any of them = that role sets no limit, which is what every
// role ships with, so a deployment that has never opened the role editor sees no change.
struct RoleLimits {
    std::optional<int> max_certs;   // active certificates this SUBJECT may hold
    std::optional<int> max_cn;      // active certificates for the requested NAME
    std::optional<int> max_san;     // SubjectAltName entries in ONE certificate
};
RoleLimits role_limits(Db& db, const std::string& user, const std::string& primary_role,
                       const std::vector<std::string>& groups = {});

// Apply all three and return "" when the request is inside them, else the reason.
//
// ⚠️ ONE function rather than three checks copied into six protocols. `max_certs` used to
// be exactly that — six near-identical blocks — and it was already one edit away from the
// second-gate shape where a later limit lands in five of them. Every protocol ENCODES the
// refusal its own way (CMP throws a PKIStatusInfo, MS a soap:Fault, ACME an RFC 8555
// problem document, EST/web a 429); only the decision is shared.
//
// `requested_cn` empty skips the per-name check; `san_count` < 0 skips the SAN check —
// a caller that genuinely does not have that part of the request yet says so, rather than
// passing 0 and quietly passing a limit it never tested.
std::string role_limit_refusal(Db& db, const RoleLimits& lim, const std::string& user,
                               const std::string& requested_cn, int san_count);


// The certificate row behind a client credential — but ONLY when this deployment still
// stands behind it.
//
// ⚠️ `get_cert()` answers "is there a row with this serial". Four call sites used it as
// though it answered "may this certificate authenticate", which it never did: it returns
// REVOKED rows, and it is not partitioned by CA. The results were that a revoked client
// certificate still enrolled over EST and CMP, that an EST self-renewal could mint from a
// CA the caller holds no grant on, and that a CMP revocation scoped to one CA reached
// certificates belonging to another.
//
// Returns the row only when `status == 0`, and — when `instance_id` is non-empty — only
// when the row belongs to that CA. std::nullopt otherwise, INCLUDING on a database error:
// a credential that cannot be judged is one to refuse, the same discipline may_enrol()
// already applies.
std::optional<CertRow> authoritative_cert(Db& db, const std::string& serial_hex,
                                          const std::string& instance_id = "");
}  // namespace pki
