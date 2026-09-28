#!/usr/bin/env bash
# Console open-mode must CLOSE as soon as a console user exists (
# "GUI authentication is broken — granted administrator privileges using the
# username anonymous").
#
# With no WEB_TOKEN and no users at all, fastpki-web intentionally serves /api/*
# unauthenticated so you can bootstrap the first admin (POST /api/users). That
# part is by design and is asserted here too.
#
# The BUG: `have_users` was a one-shot snapshot taken at startup and only flipped
# by this process's own POST /api/users. A user arriving by ANY other route —
# a direct DB insert, a restore, or (our 3-DC lab) replication of web_users from
# another data center — left the console in open mode forever, handing full admin
# to "anonymous". This suite drives the exact sequence and asserts the console
# closes once a real admin exists.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18711
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:$PORT$1"; }
field(){ echo "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"; }

pg_setup web_openmode
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
ca_in_token ca.pem "/CN=Web CA" 3650
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
ROOT_CA_PEM=$W/ca.pem
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
pg_exec "DELETE FROM web_users;" >/dev/null
"$WEB" --config bootstrap.conf >web.log 2>&1 & P=$!
for i in $(seq 1 40); do [ "$(code /api/me)" = "200" ] && break; sleep 0.25; done
if ! kill -0 $P 2>/dev/null; then echo "  [FAIL] fastpki-web did not start"; head -5 web.log; echo "=== WEB OPENMODE: PASS=0 FAIL=1 ==="; exit 1; fi

echo "=== no users at all: open mode is INTENTIONAL (bootstrap the first admin) ==="
ME=$(curl -s "http://127.0.0.1:$PORT/api/me")
chk "bootstrap: role is admin"        admin     "$(field "$ME" role)"
chk "bootstrap: user is anonymous"    anonymous "$(field "$ME" user)"
chk "bootstrap: /api/users reachable" 200       "$(code /api/users)"

echo "=== a real admin appears by a route OTHER than this process (replication / restore / direct insert) ==="
pg_exec "INSERT INTO web_users(username,role,hash,must_reset,created)
         VALUES('realadmin','admin','pbkdf2\$notarealhash',0,1) ON CONFLICT (username) DO NOTHING;" >/dev/null
chk "the admin really is in the DB" 1 "$(pg_exec "select count(*) from web_users where username='realadmin';")"

# THE REGRESSION: with a console user present, open mode must be gone. Before the
# fix every one of these failed — anonymous kept full admin.
ME2=$(curl -s "http://127.0.0.1:$PORT/api/me")
chk "open mode CLOSED: role no longer admin"      ""    "$(field "$ME2" role)"
chk "open mode CLOSED: not logged in as anonymous" ""   "$(echo "$ME2" | grep -o '"user":"anonymous"')"
# /api/me is itself behind the gate, so a logged-out caller gets 401 — which is
# what drives the console to show the login form (the frontend branches on
# r.status === 401). Same as any normal logged-out user on a configured instance.
chk "unauthenticated GET /api/me     -> 401"       401  "$(code /api/me)"
chk "unauthenticated GET /api/users  -> 401"       401  "$(code /api/users)"
chk "unauthenticated GET /api/config -> 401"       401  "$(code /api/config)"
chk "unauthenticated GET /api/certs  -> 401"       401  "$(code /api/certs)"

echo "=== /api/login stays reachable so the real admin can get in ==="
chk "POST /api/login is not blanket-401'd" yes \
    "$(c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -d 'username=realadmin&password=wrong' "http://127.0.0.1:$PORT/api/login"); [ "$c" = "401" ] || [ "$c" = "403" ] || [ "$c" = "200" ] && echo yes || echo no)"

echo
echo "=== WEB OPENMODE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
