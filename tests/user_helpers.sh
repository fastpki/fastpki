#!/usr/bin/env bash
# Seed a login into web_users — the ONLY user store. One row serves the
# console AND EST/MS Basic auth: pki::authenticate() resolves every username against
# this table, so there is no PBKDF2 users file and no `fastpki-passwd` any more.
#
# The role string is stored verbatim. Console RBAC reads it as a console role
# (admin | requester | auditor) while EST/MS read it as an
# issuance role ("master" lifts the per-CN cap) — two namespaces sharing one column,
# so pass the one the suite under test actually asserts on and do not "translate".
#
# Uses $PG_CONNINFO (set by pg_setup), so call it any time AFTER pg_setup — no need
# for the server's bootstrap.conf to exist yet. Requires $ROOT + build/fastpki-config.
#
# Step 2b: the 4th argument is still "limit this user to these CAs", but the
# mechanism changed with option (a). There is no `web_users.scope` any more —
# scope is a property of the ROLE, so this mints a scoped role `<role>@<csv>` holding the
# base role's permissions with `ca_id` rewritten to each id, and gives the user THAT role
# instead of the unscoped one. Assigning the unscoped role as well would silently widen
# them back to every CA, since scope is the union over the roles held.
#
#   seed_web_user <username> <password> <role> [ca-scope-csv]
seed_web_user() {
    local user="$1" pw="$2" role="${3:-admin}" scope="${4:-}"
    local cfg out rc; cfg="$(mktemp)"
    printf 'PG_CONNINFO=%s\n' "$PG_CONNINFO" > "$cfg"
    if [ -n "$scope" ]; then
        local scoped="$role@$scope"
        # Build the role from the base role's own grants so it stays in step with the
        # schema's builtins — spelling out a permission list here would rot the day one
        # is added. `ca_id='*'` becomes the requested id; a grant that is already scoped
        # is left alone rather than widened.
        psql "$PG_CONNINFO" -v ON_ERROR_STOP=1 -q >/dev/null <<SQL
INSERT INTO roles(name, description, builtin)
  VALUES('$scoped', 'test: $role limited to $scope', false)
  ON CONFLICT (name) DO NOTHING;
SQL
        local id
        for id in ${scope//,/ }; do
            psql "$PG_CONNINFO" -v ON_ERROR_STOP=1 -q >/dev/null <<SQL
INSERT INTO role_permissions(role, permission, scope)
  SELECT '$scoped', permission, '$id' FROM role_permissions WHERE role='$role'
  ON CONFLICT DO NOTHING;
SQL
        done
        role="$scoped"
    fi
    out=$("$ROOT/build/fastpki-config" --config "$cfg" web-user "$user" "$pw" --role "$role" 2>&1); rc=$?
    rm -f "$cfg"
    # A silent seed failure surfaces much later as an unexplained 401, so say so here.
    [ "$rc" -eq 0 ] || echo "seed_web_user: FAILED to seed '$user': $out" >&2
    return $rc
}

# The set of profiles a subject may use is the UNION of `profile:use|rw`
# grants over the roles it holds — `profile_assignments` is gone, and with it the
# priority-ordered "first match wins" pick.
#
#   grant_profile <username> <profile>       (repeatable: the profiles accumulate)
#
# ⚠️ This does NOT just add a grant, and the difference is the whole point. The builtin
# console roles already carry one profile each (`admin`->admin, `requester`->requester,
# required), so simply adding a second would leave the union with two members, and a
# request naming neither is issued under their MERGE — the builtin's allowances and
# defaults mixed into the profile the suite meant to test. (Before the merge it was a
# refusal: web_hsm_leaf 226/0 -> 122/100, store_uri unable to issue at all.)
#
# So it builds the shape `restricted-admin` in cert_profiles.sh spells out by hand: a
# per-user carrier role holding the SAME console grants as the user's builtin role MINUS
# `profile:*`, plus the requested profile, and the user is moved onto it. That is the union
# model's replacement for what priorities used to do, and what was ruled out
# priorities.
#
# ⚠️ It also grants the enrol:* verbs when the user holds no console role at all (an
# ISSUANCE role like `master`/`standard`, or an LDAP identity with no web_users row).
# Handing such a user ANY role the RBAC tables know about moves them out of may_enrol()'s
# "RBAC has no opinion" bypass and INTO enforcement — without the verbs the profile lands
# and every issuance is then refused, which reads exactly like the profile not applying, in
# both directions. Cost a full debug cycle on profile_assign.sh.
grant_profile() {
    local user="$1" profile="$2" carrier="prof@$1"
    psql "$PG_CONNINFO" -v ON_ERROR_STOP=1 -q >/dev/null <<SQL
INSERT INTO roles(name, description, builtin)
  VALUES('$carrier', 'test: profile carrier for $user', false) ON CONFLICT (name) DO NOTHING;

-- Copy the user's console role, minus its profile grant. Nothing happens when the user
-- holds an issuance role or has no row: there is no matching roles entry to copy.
INSERT INTO role_permissions(role, permission, scope)
  SELECT '$carrier', p.permission, p.scope
    FROM role_permissions p
    JOIN web_users u ON u.role = p.role
    JOIN roles r     ON r.name = p.role
   WHERE u.username = '$user' AND p.permission NOT LIKE 'profile:%'
  ON CONFLICT DO NOTHING;

-- ...and when that copied nothing, the identity needs the enrolment verbs on their own.
INSERT INTO role_permissions(role, permission, scope)
  SELECT '$carrier', permission, scope FROM role_permissions
   WHERE role = 'requester' AND permission LIKE '%:enrol'
     AND NOT EXISTS (SELECT 1 FROM role_permissions WHERE role = '$carrier')
  ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role, permission, scope)
  VALUES('$carrier', 'profile:use', '$profile') ON CONFLICT DO NOTHING;

-- Move the console user onto the carrier so the builtin's own profile grant leaves the
-- union. subject_roles as well, because an LDAP/EST identity has no web_users row and the
-- carrier can only reach it through the selector table.
UPDATE web_users SET role = '$carrier' WHERE username = '$user' AND role <> '$carrier';
INSERT INTO subject_roles(selector_type, selector_value, role, created)
  VALUES('user', '$user', '$carrier', 0) ON CONFLICT DO NOTHING;
SQL
}

# Drop ONE profile from a subject's union, leaving the carrier role and every other grant
# in place.
#
#   ungrant_profile <username> <profile>
#
# ⚠️ Needed more often than it looks. A subject holding TWO profiles gets their MERGE for
# any request that names neither, and where their defaults differ (with no member named
# after its primary role) a request relying on a default is refused. A suite that grants a
# second profile to exercise a chooser (SCEP's dynamic token) has therefore changed the
# answer for every LATER section that enrols without naming one.
ungrant_profile() {
    psql "$PG_CONNINFO" -v ON_ERROR_STOP=1 -q >/dev/null <<SQL
DELETE FROM role_permissions
 WHERE role = 'prof@$1' AND permission IN ('profile:use','profile:use') AND scope = '$2';
SQL
}

# ── an enrolment credential needs an IDENTITY ───────────────────────────────────
#
#   seed_enrolling_identity <username> [profile]
#
# A `keys` row on its own no longer issues anything: resolve_profile refuses when the
# caller holds no `profile:use|rw` grant — if the role has no permissions
# to any profiles - simple, deny the request!". Production never has a bare credential
# either: enrolment creds are minted FROM a web_users row holding an enrolling role, and
# the CMP senderKID / ACME EAB kid IS the username. Suites that seeded only the credential
# were taking a shortcut the product does not offer.
#
# ⚠️ IT DOES NOT OVERWRITE AN EXISTING USER'S ROLE. cmp_authz seeds `boss` with a
# `cert-revoker` role and then asserts that role's power; seeding it again as `requester`
# would quietly delete the thing under test. So the user row is created only when absent,
# while grant_profile is always safe — it COPIES whatever role the user holds into a
# `prof@<user>` carrier and adds the profile grant, so existing permissions survive.
seed_enrolling_identity() {   # <username> [profile]
    local user="${1:-}" profile="${2:-requester}"
    [ -n "$user" ] || return 0
    # ⚠️ Ordering, said out loud. This needs a database, so it must run AFTER pg_setup.
    # Called too early it died with "PG_CONNINFO: unbound variable" pointing at
    # user_helpers.sh — an error that names neither the caller nor the real problem.
    [ -n "${PG_CONNINFO:-}" ] || {
        echo "seed_enrolling_identity: no PG_CONNINFO yet — call this after pg_setup" >&2
        return 1
    }
    local have
    have=$(psql "$PG_CONNINFO" -tAc \
        "SELECT count(*) FROM web_users WHERE username='$user';" 2>/dev/null | tr -d ' ')
    [ "${have:-0}" = 0 ] && seed_web_user "$user" "x${user}pw" requester >/dev/null 2>&1
    grant_profile "$user" "$profile" >/dev/null 2>&1 || true
}

# The SCEP challengePassword for a user, in the wire form "<user>:<secret>".
#
# The deployment-wide SCEP_CHALLENGE is gone — the global
# SCEP_CHALLENGE from config and demo - it's per user now." So a suite that used to write
# `SCEP_CHALLENGE=secret123` into bootstrap.conf and put `secret123` in the CSR now asks for the
# credential the product minted for a real user, which is the only thing SCEP accepts.
#
# ⚠️ It returns EMPTY rather than a made-up value when the user has no credential. A
# fabricated fallback would be refused by the server, and the suite would then be
# measuring "SCEP refuses an unknown secret" while its assertions claimed to measure
# something else — a green-for-the-wrong-reason of exactly the shape these helpers exist
# to prevent. Callers should assert non-empty before using it.
scep_challenge_for() {   # <username> -> "<user>:<secret>" on stdout, "" if none
    # The kid IS the username and `keys.protocol` says which secret it is, so the
    # wire form lost its middle field. Read the row the product reads.
    local user="${1:-}"
    [ -n "$user" ] || return 0
    [ -n "${PG_CONNINFO:-}" ] || {
        echo "scep_challenge_for: no PG_CONNINFO yet — call this after pg_setup" >&2
        return 1
    }
    local secret
    secret=$(psql "$PG_CONNINFO" -tAc \
        "SELECT key FROM keys WHERE kid='${user}' AND protocol='scep';" 2>/dev/null | tr -d ' \r')
    [ -n "$secret" ] && printf '%s:%s\n' "$user" "$secret"
}

# ── Seed a DIRECTORY into the auth-provider tables ────────────────────────────────────
#
# The LDAP_* config keys are no longer read by anything: a flat key-value file names
# exactly one directory, which is why "several AD domains" was never a missing feature but
# a shape the configuration could not express. `auth_providers` + `ldap_providers` are the
# source now, so a suite that wants a directory has to put one there.
#
# ⚠️ THE BIND PASSWORD GOES THROUGH A FILE, not an argument. `ps` shows argv to every user
# on the host, and the tool refuses to take it any other way for that reason.
#
# ⚠️ base-dns is SEMICOLON-separated, uris are COMMA-separated — the same split the config
# parser used, because a DN contains commas and "dc=corp,dc=example" is ONE base.
#
# Uses $PG_CONNINFO (set by pg_setup), so call it any time AFTER pg_setup.
#
#   seed_ldap_provider <id> <uris> <base-dns> [bind-dn] [bind-pw] [extra fastpki-config args...]
seed_ldap_provider() {
    local id="$1" uris="$2" bases="$3" binddn="${4:-}" bindpw="${5:-}"
    shift 5 2>/dev/null || shift $#
    local cfg pwf out rc; cfg="$(mktemp)"; pwf="$(mktemp)"
    printf 'PG_CONNINFO=%s\n' "$PG_CONNINFO" > "$cfg"
    printf '%s' "$bindpw" > "$pwf"
    out=$("$ROOT/build/fastpki-config" --config "$cfg" auth-providers-add "$id" \
            --uris "$uris" --base-dns "$bases" \
            ${binddn:+--bind-dn "$binddn"} ${bindpw:+--bind-pw-file "$pwf"} \
            "$@" 2>&1); rc=$?
    rm -f "$cfg" "$pwf"
    # ⚠️ REPORT THE FAILURE. A suite whose directory silently failed to seed then measures
    # a deployment with NO directories and reports every login refusal as a product bug —
    # which is exactly the shape a missing fixture takes when nobody checks the seeding.
    [ $rc -eq 0 ] || echo "seed_ldap_provider($id) FAILED: $out" >&2
    return $rc
}
