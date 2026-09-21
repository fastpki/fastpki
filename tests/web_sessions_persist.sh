#!/usr/bin/env bash
# Persisted console sessions (groundwork). Sessions used to live only in the
# web process's memory, so a restart (or an LB failover to another instance on the same
# DB) logged everyone out. They are now written through to a
# `web_sessions` table so they survive a restart and are shared across instances.
#
# Security property this guards: the DB row is keyed by the SHA-256 of the token, NEVER
# the token, so a DB dump / backup cannot reconstruct a live session.
#
# Self-contained (§3d) + shell-only (§3e): ephemeral Postgres, own port, temp dir, SKIPs
# cleanly when no Postgres is reachable.
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
W="$(mktemp -d)"; cd "$W"; PORT=18263
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
PSQL(){ "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -tAc "$1" 2>/dev/null; }
start_web(){ "$WEB" --config web.conf >web.log 2>&1 & P=$!; sleep 1;
  kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat web.log; exit 1; }; }

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi

pg_setup web_sessions_persist
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
seed_web_user admin adminpw12 admin
start_web
U="http://127.0.0.1:$PORT"

echo "=== a session is written through to the DB, hashed ==="
curl -s -c s.cj -X POST "$U/api/login" -d 'username=admin&password=adminpw12' >/dev/null
TOK=$(awk '/fastpki_session/{print $NF}' s.cj)
chk "login establishes a session"       200 "$(code -b s.cj "$U/api/me")"
chk "one row in web_sessions"           1   "$(PSQL 'select count(*) from web_sessions')"
chk "the RAW token is NOT stored"       0   "$(PSQL "select count(*) from web_sessions where token_hash='$TOK'")"
chk "a hash IS stored (64 hex chars)"   64  "$(PSQL 'select length(token_hash) from web_sessions')"
chk "the row carries the username"      admin "$(PSQL 'select username from web_sessions')"

echo "=== the session survives a full process restart ==="
kill $P 2>/dev/null; wait $P 2>/dev/null
start_web
chk "same cookie still authenticates"   200 "$(code -b s.cj "$U/api/me")"
chk "and resolves the same user"        admin "$(curl -s -b s.cj "$U/api/me" | sed -n 's/.*\"user\":\"\([^\"]*\)\".*/\1/p')"
# A forged / unknown cookie must NOT authenticate.
chk "an unknown cookie -> 401"          401 "$(code -H 'Cookie: fastpki_session=deadbeefdeadbeef' "$U/api/me")"

echo "=== logout removes the persisted session ==="
curl -s -b s.cj -X POST "$U/api/logout" >/dev/null
chk "the DB row is gone"                0   "$(PSQL 'select count(*) from web_sessions')"
chk "the cookie no longer authenticates" 401 "$(code -b s.cj "$U/api/me")"
# And it stays dead across a restart (not resurrected from a stale cache).
kill $P 2>/dev/null; wait $P 2>/dev/null; start_web
chk "still 401 after logout + restart"  401 "$(code -b s.cj "$U/api/me")"

echo "=== expired sessions are pruned, not honoured ==="
curl -s -c s2.cj -X POST "$U/api/login" -d 'username=admin&password=adminpw12' >/dev/null
chk "second session is live"            200 "$(code -b s2.cj "$U/api/me")"
# Force it to look expired directly in the DB, restart to drop the memory cache, then it
# must be rejected (and pruned by the startup sweep).
PSQL 'update web_sessions set expires=1' >/dev/null
kill $P 2>/dev/null; wait $P 2>/dev/null; start_web
chk "an expired session -> 401"         401 "$(code -b s2.cj "$U/api/me")"
chk "startup pruned the expired row"    0   "$(PSQL 'select count(*) from web_sessions')"

echo
echo "=== WEB SESSIONS PERSIST: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
