#!/usr/bin/env bash
# DB-backed console users + initial admin + forced reset.
# In open mode (loopback, no users) you bootstrap the first admin via POST
# /api/users; that flips the server into login-required mode. A user created with
# mustReset must change its password before doing anything else.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18200
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

pg_setup web_users
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
"$WEB" --config web.conf >web.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"

echo "=== open mode bootstraps the first admin ==="
chk "open mode reports admin" yes "$(has "$(curl -s "$U/api/me")" '"role":"admin"')"
chk "open mode: login not required" yes "$(has "$(curl -s "$U/api/me")" '"loginRequired":false')"
chk "create first admin -> 201" 201 "$(code -X POST "$U/api/users" -d 'username=boss&password=bosspw12&role=admin')"
# Creating the first user flips the server into login-required mode.
chk "now unauthenticated -> 401" 401 "$(code "$U/api/certs")"
chk "login required now" yes "$(has "$(curl -s -X POST "$U/api/login" -d 'username=boss&password=bosspw12')" '"role":"admin"')"
curl -s -c boss.cj -X POST "$U/api/login" -d 'username=boss&password=bosspw12' >/dev/null
chk "boss session reaches /api/certs" 200 "$(code -b boss.cj "$U/api/certs")"
# Replaced the literal "db" with how the identity ACTUALLY authenticates, so a
# password account reports `local`. This assertion kept asserting the removed value and
# went red the moment auth_provider landed — caught by a later full run.
chk "boss listed as a LOCAL password user" yes "$(has "$(curl -s -b boss.cj "$U/api/users")" '"username":"boss","role":"admin","mustReset":false,"kind":"user","source":"local"')"

# ⚠️ A COMPUTER IS NOT A USER. A domain computer authenticates as its machine
# account — AD requires the sAMAccountName to end in `$`, so msxcep stores FASTPKI-WIN$ —
# and the console used to refuse that name outright with "invalid username", so there was
# no way to give an already-authenticated computer a role.
# The `/` case is the same question one step out: host/foo@REALM is never a person, and it
# is what a non-Windows client presents, which the `$` test alone would miss.
echo "=== Machine and service principals are accepted, and labelled 'computer' ==="
# ⚠️ WITH a password. Creating any user needs one ("new user needs a password >= 8 chars")
# and my first version omitted it, so both rows 400'd and I read it as valid_user still
# refusing the name. It was not. The real flow msxcep drives does not create the row here
# at all — it onboards the principal itself and an admin only assigns it a role — but this
# endpoint runs the same validator, which is the thing under test.
chk "a machine account can be created"   201 \
    "$(code -b boss.cj -X POST "$U/api/users" -d 'username=FASTPKI-WIN$&password=machinepw1&role=requester')"
chk "a service principal can be created" 201 \
    "$(code -b boss.cj -X POST "$U/api/users" -d 'username=host/node1.example.org&password=servicepw1&role=requester')"
UL=$(curl -s -b boss.cj "$U/api/users")
chk "  the machine account is kind=computer" yes \
    "$(has "$UL" '"username":"FASTPKI-WIN\$","role":"requester","mustReset":false,"kind":"computer"')"
chk "  the service principal is kind=computer" yes \
    "$(has "$UL" '"username":"host/node1.example.org","role":"requester","mustReset":false,"kind":"computer"')"
# The control that keeps those honest: an ordinary name must NOT be called a computer.
chk "  an ordinary username is still kind=user" yes \
    "$(has "$UL" '"username":"boss","role":"admin","mustReset":false,"kind":"user"')"
# Still rejected: the characters Kerberos never produces.
chk "a name with a space is still refused" 400 \
    "$(code -b boss.cj -X POST "$U/api/users" -d 'username=bad name&password=whatever1&role=requester')"

echo "=== login is case-insensitive and resolves to the canonical username ==="
chk "login BOSS (uppercase) -> 200" 200 "$(code -X POST "$U/api/login" -d 'username=BOSS&password=bosspw12')"
chk "login Boss resolves canonical 'boss'" yes "$(has "$(curl -s -X POST "$U/api/login" -d 'username=Boss&password=bosspw12')" '"user":"boss"')"
chk "login BOSS wrong pw still 401" 401 "$(code -X POST "$U/api/login" -d 'username=BOSS&password=wrongpw12')"

echo "=== a must-reset user is forced to change password ==="
chk "create alice (auditor, mustReset) -> 201" 201 "$(code -b boss.cj -X POST "$U/api/users" -d 'username=alice&password=alicepw12&role=auditor&mustReset=true')"
curl -s -c alice.cj -X POST "$U/api/login" -d 'username=alice&password=alicepw12' >/dev/null
chk "alice login reports mustReset" yes "$(has "$(curl -s -b alice.cj "$U/api/me")" '"mustReset":true')"
chk "alice blocked from her allowed view until reset (403)" 403 "$(code -b alice.cj "$U/api/audit")"
chk "alice may still see /api/me" 200 "$(code -b alice.cj "$U/api/me")"
chk "alice changes password -> 200" 200 "$(code -b alice.cj -X POST "$U/api/password" -d 'old=alicepw12&new=alicenewpw')"
chk "alice can now reach /api/audit" 200 "$(code -b alice.cj "$U/api/audit")"
chk "old password no longer works" 401 "$(code -X POST "$U/api/login" -d 'username=alice&password=alicepw12')"
chk "new password works" 200 "$(code -X POST "$U/api/login" -d 'username=alice&password=alicenewpw')"

echo "=== RBAC: an auditor cannot manage users ==="
chk "alice (auditor) POST /api/users -> 403" 403 "$(code -b alice.cj -X POST "$U/api/users" -d 'username=x&password=xxxxxxxx&role=admin')"

echo "=== an absent role means UNCHANGED, never a silent demotion ==="
# POST /api/users fell back to `requester` whenever `role` was absent, and the "role is
# required" refusal only fired when a password was ALSO being set. So editing any other
# field of an existing account — clearing a must-reset flag, say — posting neither role nor
# password, silently stripped the target of its role and answered 200.
curl -s -b boss.cj -X POST "$U/api/users" \
     -d 'username=keepme&password=keepmepw12&role=auditor&create=1' >/dev/null
chk "fixture: keepme starts as auditor" yes \
    "$(has "$(curl -s -b boss.cj "$U/api/users")" '"username":"keepme","role":"auditor"')"
# The exact shape that demoted: no role, no password.
chk "editing with no role posted -> 200" 200 \
    "$(code -b boss.cj -X POST "$U/api/users" -d 'username=keepme&mustReset=true')"
chk "  and the role is UNCHANGED, not requester" yes \
    "$(has "$(curl -s -b boss.cj "$U/api/users")" '"username":"keepme","role":"auditor"')"
chk "  while the field that was posted did change" yes \
    "$(has "$(curl -s -b boss.cj "$U/api/users")" '"username":"keepme","role":"auditor","mustReset":true')"
# A CREATE has nothing to keep, so an absent role is still refused rather than guessed.
chk "creating with no role -> 400" 400 \
    "$(code -b boss.cj -X POST "$U/api/users" -d 'username=brandnew&password=brandnewpw1&create=1')"
chk "  and no such account was created" no \
    "$(has "$(curl -s -b boss.cj "$U/api/users")" '"username":"brandnew"')"

echo "=== a forced reset the account cannot act on is refused ==="
# /api/password needs self:manage; a must-reset session can reach nothing else. So `none`
# with a forced reset was locked out for good.
chk "mustReset on a 'none' account -> 400" 400 \
    "$(code -b boss.cj -X POST "$U/api/users" -d 'username=nobody&password=nobodypw12&role=none&create=1&mustReset=true')"
chk "  and says why" yes "$(has "$(curl -s -b boss.cj -X POST "$U/api/users" -d 'username=nobody&password=nobodypw12&role=none&create=1&mustReset=true')" 'self:manage')"
chk "an administrator's password edit has the same 8-character floor" 400 \
    "$(code -b boss.cj -X POST "$U/api/users" -d 'username=keepme&password=short')"

echo "=== delete + self-delete guard ==="
chk "boss cannot delete self -> 400" 400 "$(code -b boss.cj -X DELETE "$U/api/users?username=boss")"
curl -s -c alice2.cj -X POST "$U/api/login" -d 'username=alice&password=alicenewpw' >/dev/null
chk "fixture: alice holds an extra role binding" 201 \
    "$(code -b boss.cj -X POST "$U/api/subject-roles" -d 'selector_type=user&selector_value=alice&role=requester')"
chk "boss deletes alice -> 200" 200 "$(code -b boss.cj -X DELETE "$U/api/users?username=alice")"
chk "deleted user can't log in -> 401" 401 "$(code -X POST "$U/api/login" -d 'username=alice&password=alicenewpw')"
# Bindings are keyed by NAME, so a later account called alice inherited them; and an open
# session kept working until it expired.
chk "  her role bindings went with her" 0 \
    "$(pg_exec "SELECT count(*) FROM subject_roles WHERE selector_type='user' AND lower(selector_value)='alice';")"
chk "  and her open session ended" 401 "$(code -b alice2.cj "$U/api/audit")"

echo
echo "=== WEB USERS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
