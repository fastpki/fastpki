#include "pki/enrol_gate.hpp"
#include "pki/db.hpp"
#include "pki/log.hpp"

#include <algorithm>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace pki {

namespace {

// Said once per process, not once per request: a protocol daemon under load would
// otherwise turn a configuration fact into a log flood.
void say_once(const std::string& msg) {
    static std::mutex mu;
    static std::set<std::string> seen;
    std::lock_guard<std::mutex> lk(mu);
    if (seen.insert(msg).second) log::info(msg);
}

// The roles a subject actually holds, resolved ONCE for both readers below.
//
// ⚠️ Every caller must share this. The set is a union of three sources, and there are two
// inert cases that are not bugs — a deployment with no `roles` rows at all, and a subject
// whose only role is an ISSUANCE role (`master`/`standard`) rather than a console one. A
// reader that reconstructed most of that would judge some subjects the permission gate
// does not judge, and the two would disagree about who exists.
}  // namespace

SubjectRoles subject_roles(Db& db, const std::string& user, const std::string& primary_role,
                           const std::vector<std::string>& groups) {
    SubjectRoles s;
    if (!primary_role.empty()) s.claimed.insert(primary_role);

    auto all = db.list_roles();
    s.any_defined = !all.empty();
    if (!s.any_defined) return s;

    // The directory groups the caller authenticated with, resolved at bind time by
    // pki::authenticate(). `group` has long been a selector kind and the console has
    // imported LDAP group names into `subject_roles`, but this is the first
    // reader — before it, every `group` row was a grant that could never match, and an
    // LDAP identity could authenticate and hold nothing.
    //
    // ⚠️ Asked in the SAME query as the user selector, not a second one. The effective
    // permission is the UNION over all selectors (see roles_for_subject), so splitting it
    // would work but would also be the place where "user grants" and "group grants" could
    // start being judged by two slightly different rules.
    std::vector<std::pair<std::string, std::string>> selectors;
    if (!user.empty()) selectors.emplace_back("user", user);
    for (const auto& g : groups)
        if (!g.empty()) selectors.emplace_back("group", g);

    if (!user.empty()) {
        // The subject's OWN role, looked up here rather than taken from the caller. Only
        // EST and MS authenticate against `web_users` and therefore know it; CMP proves
        // identity with a PBM secret and ACME with an EAB HMAC, so both arrive with a
        // username and no role at all. Reading it here is what makes both readers mean the
        // same thing for all four — the first version of the gate trusted the caller's
        // role and silently let every CMP request through.
        try {
            if (auto u = db.get_web_user(user); u && !u->role.empty()) s.claimed.insert(u->role);
        } catch (...) { /* no such user is not an error: the caller falls through */ }
    }
    if (!selectors.empty()) {
        auto extra = db.roles_for_subject(selectors);
        s.claimed.insert(extra.begin(), extra.end());
    }
    for (auto& r : all)
        if (s.claimed.count(r.name)) s.known.push_back(std::move(r));
    return s;
}


std::string effective_roles(Db& db, const std::string& user, const std::string& primary_role,
                            const std::vector<std::string>& groups) {
    SubjectRoles sr;
    try {
        sr = subject_roles(db, user, primary_role, groups);
    } catch (const std::exception& e) {
        log::err(std::string("audit: cannot read roles for '") + user + "': " + e.what());
        return "-";
    }
    // sr.known, NOT sr.claimed: `claimed` includes whatever word the caller arrived with,
    // which is the placeholder this function exists to stop reporting. `known` is the
    // subset that are real `roles` rows — the ones a grant can hang off.
    std::string out;
    for (const auto& r : sr.known) { if (!out.empty()) out += ","; out += r.name; }
    return out.empty() ? "-" : out;
}

std::string permission_resource(const std::string& permission) {
    const auto c = permission.find(':');
    return c == std::string::npos ? permission : permission.substr(0, c);
}

std::string permission_verb(const std::string& permission) {
    const auto c = permission.find(':');
    return c == std::string::npos ? std::string() : permission.substr(c + 1);
}

bool scope_is_reserved(const std::string& scope) {
    return scope == "*" || scope == "own";
}

// ⚠️ THE RESOURCE DECIDES, and that is the whole fix. This returned Ca for every permission
// that was not `profile:` or `template:`, so `self:manage`, `audit:read`, `user:manage` and
// the rest reached ca_scope_for_roles()'s CA-id scan. One starred grant on any of them made
// `if (id == "*") return std::nullopt` fire and unconfined the whole role across every CA —
// and `self:manage|*` ships on three builtin roles, so it was one grant away in the console.
//
// Now a resource that has no per-instance scope says so, and that scan skips it.
ScopeKind scope_kind(const std::string& permission) {
    const std::string r = permission_resource(permission);
    if (r == "profile")  return ScopeKind::Profile;
    if (r == "template") return ScopeKind::Template;
    // Resources whose instances ARE CAs: the CA itself, the certificates it issues, and the
    // enrolment protocols, which are granted per CA.
    if (r == "ca" || r == "cert" ||
        r == "est" || r == "acme" || r == "cmp" || r == "ms" || r == "scep") return ScopeKind::Ca;
    // `*:*` is the wildcard and is deliberately Ca: a `*:*|<ca-id>` grant is how a CA-scoped
    // administrator is expressed, and that scope must still confine.
    if (r == "*") return ScopeKind::Ca;
    // Everything else — self, user, role, audit, config, backup, hsm — has no per-instance
    // namespace. Its scope column is not a name, and nothing may read it as one.
    return ScopeKind::None;
}

// The verb orderings, one entry per resource that HAS one. Two do:
//   ca   — managing a CA (create, renew, cross-sign, delete) subsumes reading its list and
//          its certificate, which fastpki-ocsp already serves unauthenticated anyway.
//   hsm  — creating and adopting objects in the token subsumes listing what is in it.
// Everything absent from this table is peers-only, and two absences are deliberate:
// `profile` and `template`, where `edit` must never imply `use` (see the header).
bool permission_implies(const std::string& held, const std::string& wanted) {
    if (held == wanted || held == "*:*") return true;
    const std::string hr = permission_resource(held);
    if (hr != permission_resource(wanted)) return false;
    const std::string hv = permission_verb(held), wv = permission_verb(wanted);
    if ((hr == "ca" || hr == "hsm") && hv == "manage" && wv == "read") return true;
    return false;
}

bool in_scope(const std::string& grant_scope, const std::string& want) {
    return grant_scope == "*" || grant_scope == want;
}

bool may_enrol(Db& db, const std::string& user, const std::string& primary_role,
               const std::string& verb, const std::string& ca_id,
               const std::vector<std::string>& groups) {
    SubjectRoles sr;
    try {
        sr = subject_roles(db, user, primary_role, groups);
    } catch (const std::exception& e) {
        log::err(std::string("enrol gate: cannot read roles (") + e.what() + ") — denying");
        return false;
    }
    // ⚠️ BOTH INERT BRANCHES ARE GONE — no defaults. They used to return TRUE —
    // "this deployment has no roles at all" and "this subject's role is not one I
    // recognise" — and each was written as a transitional kindness. Neither was
    // transitional:
    //
    //   * "no roles at all" cannot happen on a database born from sql/createdb.sql, which
    //     seeds four. It could only describe a deployment whose roles an admin had
    //     deleted, where "nobody is authorized" is the correct answer, not "everybody is".
    //
    //   * "role I do not recognise" was the PERMANENT state for every enrolment account
    //     holding the old issuance words (`standard`, `master`), and for every caller
    //     carrying a struct default. It is what let AUTH_BACKEND=none hand a certificate
    //     to `mallory:whatever`, and what let an mTLS client with no
    //     web_users row enrol on the strength of its certificate alone.
    //
    // An unrecognised role now grants nothing, which is what an unrecognised role means.
    // The subject's own `web_users.role` and its `subject_roles` grants are read inside
    // subject_roles() above, so a real account is unaffected; what is refused is a claim
    // that matches no row.
    if (!sr.any_defined) {
        say_once("enrol gate: this database has no roles at all — every enrolment is "
                 "refused. Restore them from sql/createdb.sql or create them in the console.");
        return false;
    }
    std::set<std::string> known;
    for (const auto& r : sr.known) known.insert(r.name);
    if (known.empty()) {
        if (!sr.claimed.empty())
            say_once("enrol gate: role '" + *sr.claimed.begin() + "' matches no row in "
                     "`roles`, so it grants nothing — refusing");
        return false;
    }
    const std::set<std::string>& roles = known;

    std::vector<Db::RoleGrant> grants;
    try {
        for (const auto& r : roles)
            for (auto& g : db.list_role_grants(r)) grants.push_back(std::move(g));
    } catch (const std::exception& e) {
        log::err(std::string("enrol gate: cannot read grants (") + e.what() + ") — denying");
        return false;
    }

    for (const auto& g : grants) {
        // *:* is the wildcard the console gate already honours for an unmapped
        // route; it has to mean the same thing here or an admin would be refused a
        // protocol purely because nobody listed it explicitly.
        // Same rule as the console gate — one definition, so the two cannot drift. No
        // enrolment verb orders today (the five protocols are peers and cert's three acts
        // are separate), so this is currently equivalent to a literal match; it is here so
        // that a resource which DOES gain an ordering is honoured at every gate at once.
        if (!permission_implies(g.permission, verb)) continue;
        if (in_scope(g.scope, ca_id)) return true;
    }
    return false;
}

bool subject_holds(Db& db, const std::string& user, const std::string& primary_role,
                   const std::string& verb, const std::string& ca_id,
                   const std::vector<std::string>& groups) {
    SubjectRoles sr;
    try {
        sr = subject_roles(db, user, primary_role, groups);
    } catch (const std::exception& e) {
        log::err(std::string("capability check: cannot read roles (") + e.what() +
                 ") — denying");
        return false;
    }
    // NO inert cases. See the header: this answers questions whose default is refuse, so
    // "no roles defined" and "role outside the RBAC namespace" are both a plain no.
    for (const auto& r : sr.known) {
        std::vector<Db::RoleGrant> grants;
        try {
            grants = db.list_role_grants(r.name);
        } catch (const std::exception& e) {
            log::err(std::string("capability check: cannot read grants (") + e.what() +
                     ") — denying");
            return false;
        }
        for (const auto& g : grants) {
            if (!permission_implies(g.permission, verb)) continue;
            if (in_scope(g.scope, ca_id)) return true;
        }
    }
    return false;
}

RoleLimits role_limits(Db& db, const std::string& user,
                       const std::string& primary_role,
                       const std::vector<std::string>& groups) {
    SubjectRoles sr;
    try {
        sr = subject_roles(db, user, primary_role, groups);
    } catch (const std::exception& e) {
        // ⚠️ FAILS OPEN, and unlike may_enrol that is the right way round. A permission
        // gate that cannot read its tables must refuse; a quota that cannot read its
        // tables must not invent one — refusing every issuance because a SELECT failed
        // turns a database hiccup into an outage, and the permission gate above has
        // already had its say about whether this subject may be here at all.
        log::err(std::string("role limits: cannot read roles (") + e.what() +
                 ") — no per-role issuance limit applied");
        return {};
    }
    // The same two inert cases as may_enrol, for the same reasons: a database with no
    // roles at all, and a subject holding only an issuance role (`master`/`standard`)
    // that the RBAC tables do not describe. Neither can carry a number.
    if (!sr.any_defined || sr.known.empty()) return {};

    RoleLimits out;
    // NULL is "this role sets no limit", which is what every role ships with. 0 means the
    // same: the console writes 0 for an empty field, and "a role that permits zero
    // certificates" is not a policy anyone expresses through a blank box.
    auto widen = [](std::optional<int>& slot, bool has, int v) {
        if (has && v > 0) slot = slot ? std::max(*slot, v) : v;
    };
    for (const auto& r : sr.known) {
        widen(out.max_certs, r.has_max_certs, r.max_certs);
        widen(out.max_cn,    r.has_max_cn,    r.max_cn);
        widen(out.max_san,   r.has_max_san,   r.max_san);
    }
    return out;
}

std::string role_limit_refusal(Db& db, const RoleLimits& lim, const std::string& user,
                               const std::string& requested_cn, int san_count) {
    // Cheapest first, and no DB round-trip at all when a limit is unset — which is every
    // deployment until someone types a number in.
    if (lim.max_san && san_count >= 0 && san_count > *lim.max_san)
        return "too many SubjectAltName entries (" + std::to_string(san_count) +
               " > " + std::to_string(*lim.max_san) + " permitted by this role)";

    // ⚠️ Both counts FAIL OPEN for the same reason role_limits() does: a quota that cannot
    // read its table must not invent one. Logged, never silent.
    if (lim.max_certs && !user.empty()) {
        try {
            const int held = db.count_active_for_owner(user);
            if (held >= *lim.max_certs)
                return "per-requester issuance limit reached: '" + user + "' already holds " +
                       std::to_string(held) + " active certificate(s), role cap is " +
                       std::to_string(*lim.max_certs);
        } catch (const std::exception& e) {
            log::err(std::string("role limits: count_active_for_owner failed (") + e.what() +
                     ") — per-requester cap not applied");
        }
    }
    if (lim.max_cn && !requested_cn.empty()) {
        try {
            const int held = db.count_active_for_cn(requested_cn);
            if (held >= *lim.max_cn)
                return "per-name issuance limit reached: '" + requested_cn + "' already has " +
                       std::to_string(held) + " active certificate(s), role cap is " +
                       std::to_string(*lim.max_cn);
        } catch (const std::exception& e) {
            log::err(std::string("role limits: count_active_for_cn failed (") + e.what() +
                     ") — per-name cap not applied");
        }
    }
    return {};
}


std::optional<CertRow> authoritative_cert(Db& db, const std::string& serial_hex,
                                          const std::string& instance_id) {
    if (serial_hex.empty()) return std::nullopt;
    try {
        auto row = db.get_cert(serial_hex);
        if (!row) return std::nullopt;
        // status: 0 = live. -1 is revoked; the expiry sweep marks expired rows too, and
        // neither may speak for an identity.
        if (row->status != 0) return std::nullopt;
        // A credential is only good against the CA that issued it. Empty instance_id
        // means the caller genuinely has no CA in hand (there is no endpoint CA to
        // compare against) and is asking the status question alone.
        if (!instance_id.empty() && row->ca_instance_id != instance_id) return std::nullopt;
        return row;
    } catch (const std::exception& e) {
        log::err(std::string("authoritative_cert: refusing a credential that could not be "
                             "checked (serial ") + serial_hex + "): " + e.what());
        return std::nullopt;
    }
}
}  // namespace pki
