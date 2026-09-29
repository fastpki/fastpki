#!/usr/bin/env bash
# Regression: a console user with the 'admin' role (the natural
# privileged role name) must get full admin access — not a 403 on every request,
# which made the whole console look broken/blank.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18324
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

pg_setup web_master_role
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
# The reported setup: a web user with role 'master' in the WEB_USERS file.
source "$ROOT/tests/user_helpers.sh"
seed_web_user boss MasterPw12345 admin
seed_web_user joe StdPw1234567 requester
# Custom roles built from the documented permissions, for the section that checks each page's
# routes answer the permission its tab is shown for.
pg_exec "INSERT INTO roles(name,description,builtin) VALUES
           ('opsadmin','',false),('useradmin','',false),('wildonly','',false);
         INSERT INTO role_permissions(role,permission,scope) VALUES
           ('opsadmin','config:manage','*'),('useradmin','user:manage','*'),('wildonly','*:*','*');" >/dev/null
seed_web_user ops  OpsPw1234567  opsadmin
seed_web_user uadm UadmPw1234567 useradmin
seed_web_user wild WildPw1234567 wildonly
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
WEB_TOKEN=bearer-for-the-me-check-0123456789
LOG_LEVEL=err
EOF
"$WEB" --config web.conf >web.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"

curl -s -c boss.cj -X POST "$U/api/login" -d 'username=boss&password=MasterPw12345' >/dev/null
curl -s -c joe.cj  -X POST "$U/api/login" -d 'username=joe&password=StdPw1234567'   >/dev/null

echo "=== A 'master' user gets full console access (was 403 everywhere) ==="
chk "login as admin works (/api/me 200)"      200 "$(code -b boss.cj "$U/api/me")"
chk "admin -> /api/certs 200"                 200 "$(code -b boss.cj "$U/api/certs")"
chk "admin -> /api/config/db 200"             200 "$(code -b boss.cj "$U/api/config/db")"
chk "admin -> /api/users 200"                 200 "$(code -b boss.cj "$U/api/users")"
chk "admin -> /api/profiles 200"              200 "$(code -b boss.cj "$U/api/profiles")"
chk "admin -> /api/ca-instances 200"          200 "$(code -b boss.cj "$U/api/ca-instances")"

echo "=== the RBAC gate still restricts a non-privileged role ==="
# /api/users is deliberately NOT a wall any more — every role holding self:manage
# reaches it, narrowed by the handler to their own row (web_self_manage_users.sh proves
# the narrowing). So the "still gated" claim moves to a surface that really is
# user-administration: assigning roles to other subjects.
chk "requester -> /api/users 200 (own row only)" 200 "$(code -b joe.cj "$U/api/users")"
chk "requester -> /api/subject-roles 403 (still gated)" 403 "$(code -b joe.cj "$U/api/subject-roles")"
chk "requester -> /api/certs 200 (self-service)" 200 "$(code -b joe.cj "$U/api/certs")"
# the denial is now logged (no more silent 403s)
chk "a 403 denial is logged to stderr" yes "$(grep -q '403 forbidden' web.log && echo yes || echo no)"

echo "=== each page's routes answer the permission its tab is shown for ==="
# ⚠️ These routes fell to the *:* default, so a role holding the permission a tab is shown for
# saw the tab and an empty table. The tab and the route must answer the same question.
curl -s -c ops.cj  -X POST "$U/api/login" -d 'username=ops&password=OpsPw1234567'   >/dev/null
curl -s -c uadm.cj -X POST "$U/api/login" -d 'username=uadm&password=UadmPw1234567' >/dev/null
curl -s -c wild.cj -X POST "$U/api/login" -d 'username=wild&password=WildPw1234567' >/dev/null
chk "config:manage -> /api/endpoints 200"        200 "$(code -b ops.cj "$U/api/endpoints")"
chk "config:manage -> /api/endpoints/health 200" 200 "$(code -b ops.cj "$U/api/endpoints/health")"
chk "config:manage -> /api/notify 200"           200 "$(code -b ops.cj "$U/api/notify")"
chk "config:manage -> /api/version 200"          200 "$(code -b ops.cj "$U/api/version")"
chk "config:manage -> /api/discovered 403 (that is ca:manage)" 403 "$(code -b ops.cj "$U/api/discovered")"
chk "config:manage -> starting a scan 403 (that stays *:*)" 403 \
    "$(code -b ops.cj -X POST "$U/api/discover" -d 'targets=127.0.0.1:1')"
chk "user:manage -> /api/ldap/groups 200"        200 "$(code -b uadm.cj "$U/api/ldap/groups")"
chk "user:manage -> /api/directory-subjects 200" 200 "$(code -b uadm.cj "$U/api/directory-subjects")"
chk "requester -> /api/compliance 200"           200 "$(code -b joe.cj "$U/api/compliance")"
chk "requester -> /api/cert-algos 200"           200 "$(code -b joe.cj "$U/api/cert-algos")"
chk "requester -> /api/endpoints 403"            403 "$(code -b joe.cj "$U/api/endpoints")"
# *:* past the gate: /api/users decided "manages every account" by a literal user:manage, so a
# role holding only the wildcard passed the gate and was then refused as self-only.
chk "a *:*-only role lists every account, not only its own" yes \
    "$(curl -s -b wild.cj "$U/api/users" | grep -q '"username":"joe"' && echo yes || echo no)"
# /api/me reported capabilities for cookie sessions only, so the console showed a
# Dashboard-only page to the bearer token (and to client-certificate and open-mode callers).
chk "/api/me reports capabilities for a cookie session" yes \
    "$(curl -s -b joe.cj "$U/api/me" | grep -q '"capabilities":\[' && echo yes || echo no)"
chk "  and for the bearer token" yes \
    "$(curl -s -H 'Authorization: Bearer bearer-for-the-me-check-0123456789' "$U/api/me" \
        | grep -q '"capabilities":\[[^]]*"\*:\*"' && echo yes || echo no)"

echo
echo "=== WEB MASTER ROLE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
