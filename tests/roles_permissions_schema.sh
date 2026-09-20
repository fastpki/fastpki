#!/usr/bin/env bash
# Roles and their permissions become DATA. Expand only — nothing reads these
# tables yet, path_allowed() is still the hardcoded switch, so this asserts the SHAPE and
# that the builtins reproduce exactly what the switch grants today. Step 2 will delete the
# switch and this suite becomes the thing that says the behaviour did not change.
#
# The assertion that matters most is the last one: `admin` must not be able to lock
# everyone out. With editable roles an admin can strip role:manage from the only role that
# has it, and the console is then unadministrable with no way back except SQL.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup roles_permissions
trap 'pg_cleanup' EXIT
apply_step(){ "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
    --single-transaction -q -v ON_ERROR_STOP=1 -f "$1" >/dev/null; }
n(){ pg_exec "$1" | tr -d ' '; }

echo "=== 1. a fresh database is born with the tables and the builtins ==="
chk "roles table exists"            1 "$(n "SELECT count(*) FROM information_schema.tables WHERE table_name='roles';")"
chk "role_permissions exists"       1 "$(n "SELECT count(*) FROM information_schema.tables WHERE table_name='role_permissions';")"
chk "four builtin roles"            4 "$(n "SELECT count(*) FROM roles WHERE builtin;")"
# ⚠️ EQUALITY NOW. createdb.sql is the ONLY definition of the schema — the 39 steps that
# carried already-deployed databases forward were collapsed into it — so a fresh database
# must be born at exactly the version the binary requires, or the startup guard tells a
# brand-new install to run a migration that does not exist. This was `>= 3` back when the
# head version moved with every step that landed.
NEED=$(sed -n 's/^constexpr int kSchemaVersion = \([0-9]*\);.*/\1/p' "$ROOT/include/pki/schema.hpp" | head -1)
chk "a fresh schema is born at exactly kSchemaVersion" "$NEED" \
    "$(n "SELECT COALESCE(MAX(version),0) FROM schema_version;")"
chk "max_certs is nullable"       YES "$(n "SELECT is_nullable FROM information_schema.columns WHERE table_name='roles' AND column_name='max_certs';")"

echo "=== 2. `scope` is part of the permission — folded in, not kept beside ==="
# Renamed this column from `ca_id` (step 0017). It holds THREE kinds of name now and
# the VERB says which — pki::scope_kind(): a CA id for enrol:*/ca:*/cert:*, a cert-profile
# name for profile:use/rw, an MS template name for template:use/rw. A column called `ca_id`
# holding a profile name is a name that lies.
chk "role_permissions has scope"    1 "$(n "SELECT count(*) FROM information_schema.columns WHERE table_name='role_permissions' AND column_name='scope';")"
# ⚠️ And the OLD name is gone. A rename that leaves both columns is two writers for one
# fact; asserting only the new one would pass against exactly that.
chk "  and no ca_id column remains" 0 "$(n "SELECT count(*) FROM information_schema.columns WHERE table_name='role_permissions' AND column_name='ca_id';")"
# '*' rather than NULL, and the test says WHY: a key column cannot be NULL, so the first
# version of this table silently rejected every builtin grant — 22 assertions caught it.
chk "scope is NOT NULL ('*' = everything)" NO \
    "$(n "SELECT is_nullable FROM information_schema.columns WHERE table_name='role_permissions' AND column_name='scope';")"
chk "its default is the star"        "'*'::text" \
    "$(n "SELECT column_default FROM information_schema.columns WHERE table_name='role_permissions' AND column_name='scope';")"
# The same verb may be granted on two different CAs — that IS the scope, expressed once.
pg_exec "INSERT INTO roles(name) VALUES('scoped-admin') ON CONFLICT DO NOTHING;" >/dev/null
pg_exec "INSERT INTO role_permissions(role,permission,scope) VALUES
         ('scoped-admin','ca:manage','issuing'),('scoped-admin','ca:manage','root');" >/dev/null
chk "one verb over two CAs"         2 "$(n "SELECT count(*) FROM role_permissions WHERE role='scoped-admin' AND permission='ca:manage';")"
# "no row" and "row with NULL" must be distinguishable — one is denied, one is allowed
# everywhere, and confusing them widens access.
chk "an every-CA grant is a real row" 1 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='admin' AND permission='ca:manage' AND scope='*';")"
chk "and a denied verb has none"     0 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='auditor' AND permission='ca:manage';")"

echo "=== 3. the builtins reproduce today's hardcoded switch ==="
has(){ n "SELECT count(*) FROM role_permissions WHERE role='$1' AND permission='$2';"; }
# Ownership is a SCOPE now, not part of the verb: `cert:read|own` versus `cert:read|*`.
# `has` alone cannot tell those apart, so anything asserting reach needs the scope too.
hass(){ n "SELECT count(*) FROM role_permissions WHERE role='$1' AND permission='$2' AND scope='$3';"; }
# admin: everything, so adding a capability and forgetting to grant it fails HERE rather
# than in production. TWO deliberate exceptions, both of the same shape — a WIDER grant that
# supersedes a narrower one, where holding both would tell some code path that checks the
# narrow one that admin's reach is limited:
#   :own  — admin holds cert:read / cert:revoke instead
#   :ro   — admin holds profile:use / template:use instead
chk "admin holds every verb but the narrowings it supersedes" 0 \
    "$(n "SELECT count(DISTINCT permission) FROM role_permissions
           WHERE permission NOT LIKE '%:own'
             AND permission NOT LIKE '%:ro'
             AND permission NOT IN (SELECT permission FROM role_permissions WHERE role='admin');")"
# ...and the supersession is a claim, so measure it rather than assuming it. Every `:ro`
# verb granted anywhere must have admin holding its `:rw` counterpart, or the exception
# above is just a hole in the coverage check.
# Every resource somebody may USE, admin may EDIT. `:ro`/`:rw` decomposed into the two
# atomic verbs, so the rule is stated on those rather than on a string substitution.
chk "every :use verb has admin holding the matching :edit" 0 \
    "$(n "SELECT count(DISTINCT p.permission) FROM role_permissions p
           WHERE p.permission LIKE '%:use'
             AND NOT EXISTS (SELECT 1 FROM role_permissions a
                              WHERE a.role='admin'
                                AND a.permission = replace(p.permission, ':use', ':edit'));")"
# Ownership is a scope. admin holds none of the own-restricted grants: its reach is the
# estate, and an `own` row would tell any predicate that reads scope that it is not.
chk "...and does NOT hold the narrow ones" 0 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='admin' AND scope='own';")"
chk "auditor reads audit"           1 "$(has auditor audit:read)"
chk "auditor cannot manage CAs"     0 "$(has auditor ca:manage)"
chk "auditor cannot read all certs" 0 "$(has auditor cert:read)"
chk "requester requests"            1 "$(has requester cert:request)"
chk "requester reads only its own"   1 "$(hass requester cert:read own)"
chk "...and NOT everyone's"          0 "$(hass requester cert:read '*')"
chk "requester revokes only its own" 1 "$(hass requester cert:revoke own)"
chk "...and not everyone's either"   0 "$(hass requester cert:revoke '*')"
chk "requester reads the CA list"   1 "$(has requester ca:read)"
chk "...but cannot manage CAs"      0 "$(has requester ca:manage)"
# Creating a key inside the HSM is its own capability. The gate matches by PREFIX,
# so /api/certs/request-hsm inherited `cert:request` — the self-service permission — and a
# requester could mint a hardware-resident object nobody can enumerate from the console.
chk "admin may mint in the token"   1 "$(has admin hsm:manage)"
chk "admin may read the token"      1 "$(has admin hsm:read)"
chk "auditor reads the token"       1 "$(has auditor hsm:read)"
chk "...and may NOT mint in it"     0 "$(has auditor hsm:manage)"
chk "requester may NOT mint in it"  0 "$(has requester hsm:manage)"
chk "...nor even read it"           0 "$(has requester hsm:read)"
# `:manage` is gone — profile:edit/template:manage were redundant
# with profile:use/template:use, and they were: path_allowed() matches the VERB only.
# `template-editor` is GONE — it only ever meant "template:use on everything",
# which is a grant, not a role: the template-editor ROLE goes too.
chk "template-editor no longer exists"  0 "$(n "SELECT count(*) FROM roles WHERE name='template-editor';")"
chk "  and holds no grants"             0 "$(n "SELECT count(*) FROM role_permissions WHERE role='template-editor';")"
# Its replacement: requester READS the three built-ins, admin WRITES everything.
chk "requester holds template:use rows"  3 "$(has requester template:use)"
chk "  on exactly the three built-ins"  3 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='requester' AND permission='template:use' AND scope IN ('GenericUser','Email','GenericComputer');")"
chk "  and writes none of them"         0 "$(has requester template:edit)"
# ⚠️ admin held its template access ONLY through template:manage. Deleting the verb without
# re-granting leaves the Templates page unreachable for everyone, which no other assertion
# here would notice.
chk "admin still manages templates"     1 "$(has admin template:use)"
chk "template:manage is gone entirely"    0 \
    "$(n "SELECT count(*) FROM role_permissions WHERE permission = 'template:manage';")"
# ⚠️ profile:edit IS BACK, AND IT IS NOT THE VERB THAT WAS RETIRED. The old one was
# removed for being a redundant spelling of profile:use — it authorised exactly the same
# things. This one authorises strictly LESS: it permits WRITING a profile and is deliberately
# not counted by profiles_for_identity(), so it does not permit issuing under one.
#
# That split exists because /api/profiles now enforces the grant's scope on write and delete
# (a profile:use|tenant-a holder could previously rewrite the built-in tls-server to
# allow_ca=true for every tenant). With the scope enforced, the built-in admin needs a
# wildcard to administer profiles at all — and a wildcard on profile:use would widen its
# ISSUANCE union to everything, which the two assertions below and profile_choice.sh forbid.
chk "admin manages every profile"         1 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='admin' AND permission='profile:edit' AND scope='*';")"
# ...and management does NOT come with the right to issue: the union stays {admin}.
# admin reaches /api/profiles through the profile:use it already holds, NOT through a
# new profile:use|* — that would widen its usable-profile UNION from {admin} to everything.
chk "admin holds profile:use"            1 "$(has admin profile:use)"
chk "  and scoped, not wildcard"        0 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='admin' AND permission='profile:use' AND scope='*';")"
chk "'none' holds nothing"          0 "$(n "SELECT count(*) FROM role_permissions WHERE role='none';")"

echo "=== 4. the gated enrolment protocols are separate grants, not one 'all' ==="
# The permission asked for first: individually removable, one row each.
#
# FIVE now, and the history is the point. SCEP was deliberately ungated (
# ⚠️ SCEP IS LEFT UNTAGGED: it is used by devices in most cases, not
# humans"), and `scep:enrol` was DELETED — a SCEP request carried a
# certificate and an optional challenge password, not an account to authorize, so the row
# was read by nothing and an admin could revoke it believing SCEP was closed.
#
# Gave SCEP an identity: a per-user challengePassword "<user>:<secret>", minted
# alongside the CMP and ACME credentials. A request carrying one names a web_users row, so
# the permission is enforceable and comes back (step 0016).
#
# ⚠️ It gates ONLY that path. A device presenting the shared SCEP_CHALLENGE, a one-time
# dynamic token, or renewing an existing certificate still has no user and is still
# ungated — that ruling stands for the case it was about. `tests/scep.sh` asserts that
# directly, with the shared challenge still enrolling while scep:enrol is revoked from
# every role; it is the assertion that would catch this being turned into a blanket gate.
chk "requester holds the five gated protocols" 5 "$(n "SELECT count(*) FROM role_permissions WHERE role='requester' AND permission LIKE '%:enrol';")"
for p in est acme cmp ms scep; do
  chk "  $p:enrol is its own row"   1 "$(has requester "$p:enrol")"
done
chk "admin holds it too"            1 "$(has admin "scep:enrol")"

echo "=== Profile and template are permissioned RESOURCES ==="
# The design: a profile is held like an MS template is, not selected
# for you. The verbs exist before anything reads them — this slice is the vocabulary and
# the generic scope column; the gate that consults them is slice 2.
for v in profile:use profile:use template:use template:use; do
  chk "$v is grantable" yes \
      "$(grep -q "\"$v\"" "$ROOT/src/web/main.cpp" && echo yes || echo no)"
done
# ⚠️ And their scope is NOT a CA namespace. A grant scoped to a profile must not show up
# in ca_scope_for_roles, or a role holding profile:use|requester reads as confined to a CA
# called `requester` — silently, in the direction that DENIES access.
pg_exec "INSERT INTO roles(name) VALUES('proftest') ON CONFLICT DO NOTHING;" >/dev/null
pg_exec "INSERT INTO role_permissions(role,permission,scope) VALUES
         ('proftest','profile:use','requester'),('proftest','ca:read','issuing');" >/dev/null
chk "one role, two namespaces, two rows" 2 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='proftest';")"

echo "=== 4b. self:manage is held by everyone EXCEPT 'none' ==="
# /api/me and /api/logout are the true floor and need no capability. /api/password does
# need one, because `none` — an SSO user awaiting a role — deliberately cannot reach it.
# Making the gate table-driven must not quietly grant it.
for r in admin auditor requester; do
  chk "  $r holds self:manage"      1 "$(has $r self:manage)"
done
chk "'none' does NOT hold it"       0 "$(has none self:manage)"
# *:* is the catch-all for routes the map does not name: an unmapped route stays
# admin-only, which is what the hardcoded switch does today. ONLY admin may hold it.
chk "admin holds the catch-all"     1 "$(has admin *:*)"
chk "and it is admin's alone"       1 "$(n "SELECT count(*) FROM role_permissions WHERE permission='*:*';")"

echo "=== 5. deleting a role takes its permissions with it ==="
pg_exec "DELETE FROM roles WHERE name='scoped-admin';" >/dev/null
chk "cascade removed its permissions" 0 "$(n "SELECT count(*) FROM role_permissions WHERE role='scoped-admin';")"

echo "=== 6. admin is marked builtin so the console can refuse to break it ==="
# The lockout: strip role:manage from the only role that has it and the deployment is
# unadministrable with no way back except SQL. The DB records the intent; step 3 enforces
# it in the role editor. Assert the flag exists and is set, so enforcement has something
# to key on.
chk "admin is builtin"              t "$(n "SELECT builtin FROM roles WHERE name='admin';")"
chk "admin is the only role with role:manage" 1 \
    "$(n "SELECT count(*) FROM role_permissions WHERE permission='role:manage';")"


echo
echo "=== ROLES PERMISSIONS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
