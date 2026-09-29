#!/usr/bin/env bash
# Step 2b — scope is a property of the ROLE, not of the user.
#
# ── What changed and why a test has to say it ────────────────────────────────────
#
# `web_users.scope` was a CSV of CA ids on the person. Step 2a moved permissions into
# `role_permissions(role, permission, scope)`, and the two cannot coexist: scope was
# per-USER, grants are per-ROLE, so "alice is an admin over `dept-a` only" had nowhere
# left to live once admin's rows are shared with every other admin. Under scoped roles
# she holds a role whose rows carry `ca_id='dept-a'`, and a CA id appears in exactly one
# place in the system.
#
# ── The three things most likely to be got wrong later ───────────────────────────
#
# 1. **Scope is a UNION over the roles held, not an intersection.** Section 3 grants the
#    scoped alice the plain `admin` role as well and requires that she then sees EVERY
#    CA. That is not a bug being enshrined: a role is a grant, and holding two grants
#    cannot give less than holding one. Anyone who "fixes" this into an intersection
#    turns adding a role into a way of REMOVING access, which is the opposite of what an
#    operator will expect when they click it.
#
# 2. **Scope is re-derived per request, not cached at login.** The old CSV was copied
#    into the session, so a scope change did nothing until the session expired. Section 4
#    changes a live user's role and requires the SAME cookie to see the new scope.
#
# 3. **A role name is data.** The console used to validate assignments against a
#    hardcoded list of five builtins, which made a scoped role — the entire mechanism —
#    unassignable through the UI. Section 5 covers both directions.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: a test must not assume a Linux layout. Without this the default path simply does
# not exist on a Mac, mk() below writes no PEM, the CA rows are never seeded, and TEN
# assertions fail with "expected 2 got 0" — which reads like a scoping bug in the
# product and is nothing of the kind. Fall back rather than mislead.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
[ -n "$OSSL" ] || { echo "SKIP: no openssl on PATH"; exit 0; }
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18475
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup web_scoped_roles
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
NOW=$(date +%s)

# Two CAs and one leaf each, so "which CAs do you see" and "which certs do you see" are
# separate questions with different answers.
mk(){ "$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.pem" -days 3650 \
        -subj "/CN=$2" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1; }
mk depta "Dept A CA"
mk deptb "Dept B CA"
pg_seed_ca_row dept-a depta.pem "" true
pg_seed_ca_row dept-b deptb.pem "" true
pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,ca_instance_id)
         VALUES('a1',0,$((NOW-86400)),$((NOW+86400)),'CN=a.host','x','a.host','fa','dept-a'),
               ('b1',0,$((NOW-86400)),$((NOW+86400)),'CN=b.host','x','b.host','fb','dept-b');" >/dev/null

seed_web_user boss  bosspw  admin            # unscoped
seed_web_user alice alicepw admin dept-a     # scoped: mints role admin@dept-a

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" WEB_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat srv.log; exit 1; }
U="http://127.0.0.1:$PORT"
curl -s -c boss.cj  -d 'username=boss&password=bosspw'   "$U/api/login" >/dev/null
curl -s -c alice.cj -d 'username=alice&password=alicepw' "$U/api/login" >/dev/null

cas(){    curl -s -b "$1" "$U/api/ca-instances"; }
n_cas(){  cas "$1" | grep -o '"id":"[^"]*"' | wc -l | tr -d ' '; }
sees(){   cas "$1" | grep -q "\"id\":\"$2\"" && echo yes || echo no; }
n_certs(){ curl -s -b "$1" "$U/api/certs?limit=100" | grep -o '"serial":"[^"]*"' | wc -l | tr -d ' '; }

echo "=== 1. the column is gone, not merely ignored ==="
# A column left in place is a second answer to "what is this user's scope" waiting to
# disagree with the first one.
chk "web_users has no scope column"    0 \
    "$(pg_exec "SELECT count(*) FROM information_schema.columns WHERE table_name='web_users' AND column_name='scope';" | tr -d ' ')"
chk "web_sessions has no scope column" 0 \
    "$(pg_exec "SELECT count(*) FROM information_schema.columns WHERE table_name='web_sessions' AND column_name='scope';" | tr -d ' ')"
# ⚠️ EQUALITY, NOT A MINIMUM. createdb.sql is the ONLY definition of the schema now — the
# 39 steps that carried already-deployed databases forward were collapsed into it — so a
# fresh database must be born at exactly the version the binary requires. This was `>= 8`
# back when the head version moved with every step that landed.
NEED=$(sed -n 's/^constexpr int kSchemaVersion = \([0-9]*\);.*/\1/p' "$ROOT/include/pki/schema.hpp" | head -1)
chk "a fresh schema is born at exactly kSchemaVersion" "$NEED" \
    "$(pg_exec "SELECT COALESCE(MAX(version),0) FROM schema_version;" | tr -d ' ')"

echo "=== 2. the scoped role confines its holder ==="
chk "the scoped role exists"           1 \
    "$(pg_exec "SELECT count(*) FROM roles WHERE name='admin@dept-a';" | tr -d ' ')"
chk "and every one of its grants names dept-a" 0 \
    "$(pg_exec "SELECT count(*) FROM role_permissions WHERE role='admin@dept-a' AND scope<>'dept-a';" | tr -d ' ')"
chk "boss sees both CAs"               2   "$(n_cas boss.cj)"
chk "alice sees one"                   1   "$(n_cas alice.cj)"
chk "  and it is dept-a"               yes "$(sees alice.cj dept-a)"
chk "  not dept-b"                     no  "$(sees alice.cj dept-b)"
chk "boss sees both leaves"            2   "$(n_certs boss.cj)"
chk "alice sees only dept-a's leaf"    1   "$(n_certs alice.cj)"
# ⚠️ /api/notify TOOK A Scope AND NEVER CONSULTED IT. Both leaves above expire tomorrow, so
# both fall inside the notify window — and alice was served dept-b's CN, owner and serial.
# Every other inventory reader filters on ca_instance_id; ExpiringCert did not carry the
# column, so this one had nothing to filter on and the parameter sat unused.
n_notify(){ curl -s -b "$1" "$U/api/notify" | grep -o '"serial":"[^"]*"' | wc -l | tr -d ' '; }
chk "boss's expiry notifications cover both CAs" 2   "$(n_notify boss.cj)"
chk "alice's cover only dept-a"                 1   "$(n_notify alice.cj)"
chk "  and dept-b's leaf is not among them"     no  \
    "$(curl -s -b alice.cj "$U/api/notify" | grep -q '\"serial\":\"b1\"' && echo yes || echo no)"
# The bucket counters are incremented in the SAME loop that emits the items, so a filter
# applied only at emit time would still have handed alice the estate-wide totals. Summed
# rather than matched per-bucket, so this does not depend on how NOTIFY_DAYS buckets them.
sumcounts(){ curl -s -b "$1" "$U/api/notify" \
    | sed -n 's/.*"counts":{\([^}]*\)}.*/\1/p' | grep -o '[0-9][0-9]*' \
    | awk '{s+=$1} END{print s+0}'; }
chk "boss's summary counts total 2"             2   "$(sumcounts boss.cj)"
chk "  and alice's total 1 — the counts are scoped too" 1 "$(sumcounts alice.cj)"

echo "=== 3. scope is the UNION of the roles held — adding a role never subtracts ==="
# Deliberately asserted. An intersection would make "grant this person another role"
# a way to take access AWAY, which no operator would predict from the button.
curl -s -o /dev/null -b boss.cj -X POST "$U/api/subject-roles" \
    --data-urlencode 'selector_type=user' --data-urlencode 'selector_value=alice' \
    --data-urlencode 'role=admin'
chk "alice now holds the unscoped admin too" 1 \
    "$(pg_exec "SELECT count(*) FROM subject_roles WHERE selector_value='alice' AND role='admin';" | tr -d ' ')"
chk "so she sees every CA"             2   "$(n_cas alice.cj)"
chk "  including dept-b"               yes "$(sees alice.cj dept-b)"

echo "=== 4. scope is re-derived per request, not frozen into the session ==="
# Same cookie throughout: no re-login anywhere in this section. The old CSV was copied
# into the session row at login, so a scope change did nothing until it expired.
curl -s -o /dev/null -b boss.cj -X DELETE \
    "$U/api/subject-roles?selector_type=user&selector_value=alice&role=admin"
chk "the extra grant is gone"          0 \
    "$(pg_exec "SELECT count(*) FROM subject_roles WHERE selector_value='alice' AND role='admin';" | tr -d ' ')"
chk "the SAME session is confined again" 1 "$(n_cas alice.cj)"
chk "  back to dept-a only"            yes "$(sees alice.cj dept-a)"
# And a change to the ROLE's rows reaches her too, without touching her user record.
pg_exec "INSERT INTO role_permissions(role, permission, scope)
         SELECT 'admin@dept-a', permission, 'dept-b' FROM role_permissions
          WHERE role='admin@dept-a' AND scope='dept-a' ON CONFLICT DO NOTHING;" >/dev/null
chk "widening the ROLE widens her live session" 2 "$(n_cas alice.cj)"
pg_exec "DELETE FROM role_permissions WHERE role='admin@dept-a' AND scope='dept-b';" >/dev/null
chk "and narrowing it narrows her again"        1 "$(n_cas alice.cj)"

echo "=== 5. a role name is data, not a hardcoded list of five ==="
code(){ curl -s -o /dev/null -w '%{http_code}' -b boss.cj -X POST "$@"; }
chk "assigning a role that does not exist -> 400" 400 \
    "$(code "$U/api/subject-roles" --data-urlencode 'selector_type=user' \
        --data-urlencode 'selector_value=boss' --data-urlencode 'role=no-such-role')"
chk "assigning the scoped role -> 201"            201 \
    "$(code "$U/api/subject-roles" --data-urlencode 'selector_type=user' \
        --data-urlencode 'selector_value=boss' --data-urlencode 'role=admin@dept-a')"
# `none` means "onboarded, no access". As an EXTRA grant beside a real role it says
# nothing while reading like a denial, so it is refused rather than silently ignored.
chk "granting 'none' as an extra role -> 400"     400 \
    "$(code "$U/api/subject-roles" --data-urlencode 'selector_type=user' \
        --data-urlencode 'selector_value=boss' --data-urlencode 'role=none')"
chk "creating a user with an unknown primary role -> 400" 400 \
    "$(code "$U/api/users" --data-urlencode 'username=carol' --data-urlencode 'password=carolpw12' \
        --data-urlencode 'role=not-a-role' --data-urlencode 'create=1')"
chk "creating one with the scoped role -> 201"    201 \
    "$(code "$U/api/users" --data-urlencode 'username=carol' --data-urlencode 'password=carolpw12' \
        --data-urlencode 'role=admin@dept-a' --data-urlencode 'create=1')"
chk "  and she is confined by it"      1 \
    "$(curl -s -c carol.cj -d 'username=carol&password=carolpw12' "$U/api/login" >/dev/null; n_cas carol.cj)"

echo
echo "=== WEB SCOPED ROLES: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
