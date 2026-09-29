#!/usr/bin/env bash
# `self:manage` opens the Users page, narrowed to the caller's own record.
#
# The shape this suite exists to catch: widening a path gate and forgetting to narrow
# the handlers behind it. Making the Users tab reachable is one line; if the API still
# answers with every account, or still honours DELETE, or still lets the caller pick
# their own role, the ticket is not done — it is a privilege escalation with a nicer
# menu. So every assertion here is about what the SERVER hands back, and the two
# escalation paths (self-promotion, deleting someone else) are checked in the DATABASE
# afterwards, not by reading a status code.
#
# carol = auditor  -> self:manage, no user:manage, and NO cert:request either, which is
#                     what proves /api/enrolment-credentials really opened for
#                     self:manage rather than riding on the requester's grant.
# dave  = requester -> self:manage + cert:request, the ordinary self-service user.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
WEB="$ROOT/build/fastpki-web"
[ -x "$WEB" ] || { echo "SKIP: $WEB not built"; exit 0; }
W="$(mktemp -d)"; cd "$W"; PORT=18244
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
# Count how many user objects a /api/users body carries, and name them. Both matter:
# "one row" and "the RIGHT row" are different bugs.
names(){ grep -o '"username":"[^"]*"' | sed 's/.*:"//; s/"$//' | sort | tr '\n' ' '; }

pg_setup web_self_manage_users
P=""
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
# No CA: nothing here issues a certificate, and a CA-less instance still serves the
# console (§4a). That also keeps the suite off the token, so it runs everywhere
# rather than SKIPping on a machine that cannot mint a key in SoftHSM.
source "$ROOT/tests/user_helpers.sh"
seed_web_user admin adminpw admin
seed_web_user carol carolpw auditor
seed_web_user dave  davepw  requester
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
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat srv.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c admin.cj -d 'username=admin&password=adminpw' "$U/api/login" >/dev/null
curl -s -c carol.cj -d 'username=carol&password=carolpw' "$U/api/login" >/dev/null
curl -s -c dave.cj  -d 'username=dave&password=davepw'   "$U/api/login" >/dev/null
code(){ curl -s -o /dev/null -w '%{http_code}' -b "$1" "${@:2}"; }
n(){ psql "$PG_CONNINFO" -tAq -c "$1" 2>/dev/null | tr -d ' '; }

echo "=== the page is reachable with self:manage alone ==="
chk "auditor  GET /api/users (200)"  200 "$(code carol.cj "$U/api/users")"
chk "requester GET /api/users (200)" 200 "$(code dave.cj  "$U/api/users")"

echo "=== …and shows ONLY the caller ==="
chk "auditor sees just carol"   "carol " "$(curl -s -b carol.cj "$U/api/users" | names)"
chk "requester sees just dave"  "dave "  "$(curl -s -b dave.cj  "$U/api/users" | names)"
chk "admin still sees everyone" "admin carol dave " "$(curl -s -b admin.cj "$U/api/users" | names)"

echo "=== the role editor stays admin-only (it edits OTHER subjects) ==="
chk "auditor GET /api/subject-roles (403)" 403 "$(code carol.cj "$U/api/subject-roles")"

echo "=== enrolment credentials open for self:manage, not just cert:request ==="
# carol holds NO cert:request. This used to be 403 for her, which would have left
# the ticket's stated purpose — "get their CMP secret and ACME EAB keys" — unreachable
# from the very page it just opened.
chk "auditor GET /api/enrolment-credentials (200)" 200 "$(code carol.cj "$U/api/enrolment-credentials")"
chk "the credentials returned are the CALLER's" \
    "carol " "$(curl -s -b carol.cj "$U/api/enrolment-credentials" | names)"
chk "requester's creds are real (enrolment:true)" 1 \
    "$(curl -s -b dave.cj "$U/api/enrolment-credentials" | grep -c '"enrolment":true')"

echo "=== a self:manage user can change their OWN password ==="
# Only with the CURRENT password, as /api/password asks: a session alone must not be able to
# replace the password and lock the owner out.
chk "without the current password it is refused (401)" 401 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b dave.cj -X POST -d 'username=dave&password=hijackpw11' "$U/api/users")"
chk "  and the password is unchanged" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -c d1.cj -d 'username=dave&password=davepw' "$U/api/login")"
curl -s -o /dev/null -b dave.cj -X POST -d 'username=dave&old=davepw&password=newdavepw11' "$U/api/users"
# Assert by USING the credential, not by reading the status code: a 200 that did not
# write anything looks identical from the outside.
chk "the change ended dave's other session" 401 "$(code d1.cj "$U/api/users")"
chk "  and kept the one that made it" 200 "$(code dave.cj "$U/api/users")"
chk "the new password logs in"  200 "$(curl -s -o /dev/null -w '%{http_code}' -c d2.cj -d 'username=dave&password=newdavepw11' "$U/api/login")"
chk "the old password does not" 401 "$(curl -s -o /dev/null -w '%{http_code}' -c d3.cj -d 'username=dave&password=davepw' "$U/api/login")"

echo "=== …but cannot promote themselves ==="
curl -s -o /dev/null -b dave.cj -X POST -d 'username=dave&password=stillmine11&role=admin' "$U/api/users"
chk "dave is still a requester in the DB" "requester" \
    "$(n "SELECT role FROM web_users WHERE username='dave';")"
chk "dave holds no admin row"            0 \
    "$(n "SELECT count(*) FROM web_users WHERE username='dave' AND role='admin';")"

echo "=== …cannot touch anybody else ==="
chk "POST for another user (403)" 403 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b dave.cj -X POST -d 'username=admin&password=pwnedpw1234' "$U/api/users")"
chk "the admin password is unchanged" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -c a2.cj -d 'username=admin&password=adminpw' "$U/api/login")"
chk "creating a user (403)" 403 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b dave.cj -X POST -d 'username=mallory&password=mallorypw1&create=1&role=admin' "$U/api/users")"
chk "mallory was not created" 0 "$(n "SELECT count(*) FROM web_users WHERE username='mallory';")"

echo "=== …and cannot delete ==="
chk "DELETE another user (403)" 403 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b dave.cj -X DELETE "$U/api/users?username=carol")"
chk "carol still exists" 1 "$(n "SELECT count(*) FROM web_users WHERE username='carol';")"
chk "admin CAN still delete" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X DELETE "$U/api/users?username=carol")"
chk "carol is gone" 0 "$(n "SELECT count(*) FROM web_users WHERE username='carol';")"

echo "=== the served console asks for the CAPABILITY, not the role name ==="
# §3e: the shell harness cannot run the JS, so assert the wiring. `isAdmin()` here would
# hide the page's own gear from every self-service user the ticket is written for.
JS=$(curl -s -b admin.cj "$U/" | tr '\n' ' ')
chk "the Users tab is listed for self:manage" 1 \
    "$(echo "$JS" | grep -c "users: \['user:manage','self:manage'\]")"
chk "renderUsers gates the toolbar on user:manage" 1 \
    "$(echo "$JS" | grep -c "ME.writeEnabled && hasCap('user:manage')")"
# hasCap must mirror the server's caps_allow() EXACTLY, and both now honour the `*:*`
# wildcard. The rule is not "no wildcard" — it is "the same rule on both sides". A wildcard
# in one and not the other is the "control that lies" shape in either direction: buttons
# that 403 on click, or buttons hidden from someone who holds the permission.
#
# ⚠️ Pin the RULE, not one expression's exact text. This grepped for
# `caps.includes('*:*') || caps.includes(c)` and broke the moment the check moved into
# capImplies() — the wildcard was still honoured on both sides, so the guard reported a
# regression that did not exist and cost a gate run to diagnose. It reads the helper
# hasCap delegates to, and separately that hasCap still delegates there: a wildcard
# honoured in a function nothing calls is the same hole as no wildcard at all.
# $JS has had its newlines flattened to spaces, so these slice the blob rather than
# matching line-anchored: capImplies' body is what lies between the two declarations, and
# hasCap's is up to its first closing brace.
CAPIMPL=$(printf '%s' "$JS" | sed -n 's/.*function capImplies\(.*\)function hasCap.*/\1/p')
HASCAP=$(printf '%s' "$JS"  | sed -n 's/.*function hasCap(c){\([^}]*\)}.*/\1/p')
chk "capImplies honours the *:* wildcard, like caps_allow" 1 \
    "$(printf '%s' "$CAPIMPL" | grep -c "'\*:\*'")"
chk "  and hasCap is what consults it"      1 \
    "$(printf '%s' "$HASCAP" | grep -c 'capImplies')"

echo
echo "=== SELF-MANAGE USERS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
