#!/usr/bin/env bash
# tests/web_session_timeout.sh — how a console session ends, and what the page is told.
#
# ⚠️ WHY THIS IS A TEST. A session had one limit, 12 hours from sign-in, and nothing else:
# a console left open on a desk stayed signed in all day. When the session did end, every
# tab's loader read the 401 as "no rows", so the console showed 0 CAs, 0 certificates and a
# zeroed dashboard, as if the data were gone, with nothing saying to sign in again. And no
# response carried a caching header, so nothing stopped a browser or proxy keeping the page
# or its per-user data.
#
# Asserted here:
#   - a session unused for 15 minutes ends, and one used within them does not;
#   - using a session moves its last-seen time, at most once a minute;
#   - the 12-hour limit still ends a session that is in use;
#   - the 401 for "no valid session" carries X-FastPKI-Login: required, and a refused
#     password (also a 401) does not, so the page reloads to the sign-in form for the first
#     and shows the error for the second;
#   - the page reloads on that header, and only after it has signed in once;
#   - Cache-Control: no-store on the page, on API answers and on the gate's own 401.
#
# The 15 minutes are not waited out: the test moves a session's last_seen back in the table.
# Self-contained (§3d) + shell-only (§3e); SKIPs cleanly without Postgres.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PA=18281
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
hdr(){ curl -s -o /dev/null -D - "${@:2}" | tr -d '\r' | sed -n "s/^$1: //Ip" | head -1; }

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi
[ -x "$WEB" ] || { echo "SKIP: fastpki-web not built"; exit 0; }

pg_setup web_session_timeout
A=""
trap 'pg_cleanup; kill $A 2>/dev/null' EXIT
seed_web_user admin adminpw12 admin
sql(){ psql "$PG_CONNINFO" -tAq -c "$1"; }

cat > a.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PA
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
"$WEB" --config a.conf >a.log 2>&1 & A=$!
wait_conf "a.conf" WEB_PORT "$A" || true
kill -0 $A 2>/dev/null || { echo "web died:"; cat a.log; exit 1; }
U="http://127.0.0.1:$PA"
login(){ rm -f "$1"; curl -s -c "$1" -o /dev/null -X POST "$U/api/login" -d 'username=admin&password=adminpw12'; }
# The one session row a jar's cookie names.
tokhash(){ printf '%s' "$(sed -n 's/.*fastpki_session\t//p' "$1" | tail -1)" | openssl dgst -sha256 -r | cut -d' ' -f1; }
now(){ date +%s; }

echo "=== a new session records when it was last used ==="
login s.jar
H=$(tokhash s.jar)
chk "PRECONDITION: the session row exists"               1   "$(sql "select count(*) from web_sessions where token_hash='$H'")"
_ls=$(sql "select last_seen from web_sessions where token_hash='$H'")
chk "last_seen is set at sign-in"                        yes "$([ "$(( $(now) - _ls ))" -le 5 ] && echo yes || echo no)"

echo "=== used within 15 minutes: still signed in, and last_seen moves ==="
sql "update web_sessions set last_seen = $(( $(now) - 14*60 )) where token_hash='$H'"
chk "a session idle for 14 minutes still works"          200 "$(code -b s.jar "$U/api/users")"
_ls=$(sql "select last_seen from web_sessions where token_hash='$H'")
chk "using it moved last_seen to now"                    yes "$([ "$(( $(now) - _ls ))" -le 5 ] && echo yes || echo no)"
sql "update web_sessions set last_seen = $(( $(now) - 30 )) where token_hash='$H'"
code -b s.jar "$U/api/users" >/dev/null
_ls=$(sql "select last_seen from web_sessions where token_hash='$H'")
chk "but not more than once a minute (30 s ago stays)"   yes "$([ "$(( $(now) - _ls ))" -ge 25 ] && echo yes || echo no)"

echo "=== unused for more than 15 minutes: the session ends ==="
sql "update web_sessions set last_seen = $(( $(now) - 15*60 - 5 )) where token_hash='$H'"
chk "a session idle for 15 minutes is refused (401)"     401 "$(code -b s.jar "$U/api/users")"
chk "  and its row is gone"                              0   "$(sql "select count(*) from web_sessions where token_hash='$H'")"

echo "=== the 12-hour limit still ends a session in use ==="
login t.jar
H2=$(tokhash t.jar)
sql "update web_sessions set expires = $(( $(now) - 1 )) where token_hash='$H2'"
chk "a session past its absolute end is refused"         401 "$(code -b t.jar "$U/api/users")"

echo "=== the page is told which 401 means 'sign in again' ==="
chk "no valid session: X-FastPKI-Login: required"        required "$(hdr X-FastPKI-Login -b s.jar "$U/api/users")"
chk "no cookie at all: the same"                         required "$(hdr X-FastPKI-Login "$U/api/summary")"
login p.jar
chk "PRECONDITION: a wrong current password is a 401"    401 "$(code -b p.jar -X POST "$U/api/password" -d 'old=wrongpw99&new=whatever99')"
chk "  and it carries no X-FastPKI-Login"                ""  "$(hdr X-FastPKI-Login -b p.jar -X POST "$U/api/password" -d 'old=wrongpw99&new=whatever99')"
curl -s "$U/" > page.html
chk "the page reloads on X-FastPKI-Login: required"      yes "$(grep -q "r.headers.get('X-FastPKI-Login') === 'required'" page.html && grep -q 'location.reload()' page.html && echo yes || echo no)"
chk "  only once it has signed in (no reload loop)"      yes "$(grep -q 'if (SIGNED_IN && r.status === 401' page.html && grep -q '^  SIGNED_IN = true;' page.html && echo yes || echo no)"
chk "  and the sign-in form then says why"               yes "$(grep -q 'Your session has ended. Sign in again.' page.html && echo yes || echo no)"

echo "=== nothing the console serves may be kept (Cache-Control: no-store) ==="
chk "the page"                                           no-store "$(hdr Cache-Control "$U/")"
chk "an API answer"                                      no-store "$(hdr Cache-Control -b p.jar "$U/api/me")"
chk "a list"                                             no-store "$(hdr Cache-Control -b p.jar "$U/api/users")"
chk "the gate's own 401"                                 no-store "$(hdr Cache-Control "$U/api/users")"

echo
echo "=== WEB SESSION TIMEOUT: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
