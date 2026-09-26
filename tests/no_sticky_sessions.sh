#!/usr/bin/env bash
# tests/no_sticky_sessions.sh — the console runs behind a load balancer with NO
# session affinity. Console sessions live in the shared DB (web_sessions) and are read
# through it, so a session minted by ONE fastpki-web instance is honoured by ANOTHER
# instance that shares the same database. That is the property that lets a client scale
# the app tier horizontally (N replicas + an LB): the LB may route any request to any
# instance without sticky sessions.
#
# Two fastpki-web instances, SAME PG_CONNINFO, different ports. Log in on A, then use
# that cookie on B — B must accept it (validated from the DB, not from A's memory). A
# bogus cookie on B must be rejected, proving B really validates rather than waving it
# through.
#
# ⚠️ A CHANGE TO A SESSION MADE ON ONE INSTANCE HOLDS ON EVERY INSTANCE, AT ONCE. Each
# instance used to keep its own copy of every session it had seen, and never read the table
# again for it. So on an HA pair, where one Service spreads a browser's requests over both
# servers, three things held on one server only:
#   - the forced first-login reset: after the new password, the other server still answered
#     403 "password reset required" (the console's New CA form showed "no HSM slots: HTTP 403");
#   - sign-out: the cookie kept working on the other server;
#   - a password change ending the user's other sessions: a stolen cookie kept working there.
# Each case below touches B first, so B has seen the session, then changes it on A.
#
# Self-contained (§3d) + shell-only (§3e); SKIPs cleanly without Postgres.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PA=18271; PB=18272
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi
[ -x "$WEB" ] || { echo "SKIP: fastpki-web not built"; exit 0; }

pg_setup no_sticky
A=""; B=""
trap 'pg_cleanup; kill $A $B 2>/dev/null' EXIT
seed_web_user admin adminpw12 admin

mkconf(){ cat > "$1" <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$2
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
}
mkconf a.conf $PA; mkconf b.conf $PB
"$WEB" --config a.conf >a.log 2>&1 & A=$!
"$WEB" --config b.conf >b.log 2>&1 & B=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "a.conf" WEB_PORT "$A" || true
kill -0 $A 2>/dev/null || { echo "web A died:"; cat a.log; exit 1; }
kill -0 $B 2>/dev/null || { echo "web B died:"; cat b.log; exit 1; }
UA="http://127.0.0.1:$PA"; UB="http://127.0.0.1:$PB"

echo "=== two independent web instances share one DB (like N pods behind an LB) ==="
chk "instance A is up" 200 "$(code "$UA/")"
chk "instance B is up" 200 "$(code "$UB/")"
# Both are separate processes with their own in-memory session cache.

echo "=== log in on A, then use that SAME session on B (no session affinity) ==="
curl -s -c jar.txt -X POST "$UA/api/login" -d 'username=admin&password=adminpw12' >/dev/null
chk "login on A set a fastpki_session cookie" yes "$(grep -q fastpki_session jar.txt && echo yes || echo no)"
chk "A honours its own session (/api/users 200)"       200 "$(code -b jar.txt "$UA/api/users")"
chk "B honours the session MINTED ON A (200, from DB)" 200 "$(code -b jar.txt "$UB/api/users")"

echo "=== B really validates: a bogus cookie is rejected ==="
chk "B rejects a forged session (401)" 401 "$(code -H 'Cookie: fastpki_session=deadbeefdeadbeefdeadbeef' "$UB/api/users")"
chk "unauthenticated is rejected on B (401)" 401 "$(code "$UB/api/users")"

echo "=== a forced reset cleared on A is cleared on B ==="
"$ROOT/build/fastpki-config" --config a.conf web-user firstlogin firstpw12 --role admin --must-reset >/dev/null
curl -s -c r.txt -X POST "$UA/api/login" -d 'username=firstlogin&password=firstpw12' >/dev/null
chk "before the change, B blocks the session (403)"     403 "$(code -b r.txt "$UB/api/users")"
chk "the new password is accepted on A"                 200 "$(code -b r.txt -X POST "$UA/api/password" -d 'old=firstpw12&new=firstpw34')"
chk "B then serves the session (200, not 403)"          200 "$(code -b r.txt "$UB/api/users")"

echo "=== sign-out on one instance ends the session on the other ==="
curl -s -c l.txt -X POST "$UA/api/login" -d 'username=admin&password=adminpw12' >/dev/null
chk "A serves the session"                              200 "$(code -b l.txt "$UA/api/users")"
chk "B serves the session"                              200 "$(code -b l.txt "$UB/api/users")"
curl -s -b l.txt -X POST "$UB/api/logout" >/dev/null 2>&1
chk "after sign-out on B, B rejects the session"        401 "$(code -b l.txt "$UB/api/users")"
chk "after sign-out on B, A rejects it too"             401 "$(code -b l.txt "$UA/api/users")"

echo "=== a password change on A ends the user's other sessions on B ==="
curl -s -c s1.txt -X POST "$UA/api/login" -d 'username=admin&password=adminpw12' >/dev/null
curl -s -c s2.txt -X POST "$UB/api/login" -d 'username=admin&password=adminpw12' >/dev/null
chk "the second session works on B"                     200 "$(code -b s2.txt "$UB/api/users")"
chk "the password change on A is accepted"              200 "$(code -b s1.txt -X POST "$UA/api/password" -d 'old=adminpw12&new=adminpw34')"
chk "the second session is rejected on B"               401 "$(code -b s2.txt "$UB/api/users")"
chk "the second session is rejected on A"               401 "$(code -b s2.txt "$UA/api/users")"
chk "the session that changed it still works on B"      200 "$(code -b s1.txt "$UB/api/users")"

echo
echo "=== NO STICKY SESSIONS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
