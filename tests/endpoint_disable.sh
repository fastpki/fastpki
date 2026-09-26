#!/usr/bin/env bash
# Switching a protocol off from the console must actually close its
# port — not just grey out a button.
#
# The enforcement deliberately lives in the protocol's OWN process (pki::gate_protocol),
# not in the console: a PKI web console must never hold the Docker socket, because that
# turns "admin can click a button" into "admin can read the HSM PIN out of any
# container". So the console writes a config key and the owning process obeys it.
#
# What this asserts, by connecting to the port rather than trusting a status field:
#   * a protocol started with <PROTO>_ENABLED=false NEVER opens its port
#   * flipping the key in the database lets it start listening, with no restart
#   * the API refuses nonsense (unknown protocol, non-boolean) instead of storing it
#   * an absent key means enabled, so an existing deployment is unaffected
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
unset OPENSSL_CONF
STORE="$ROOT/build/fastpki-store"
W="$(mktemp -d)"; cd "$W"; PORT=18151
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
listening(){ curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/" 2>/dev/null && echo yes || echo no; }

pg_setup endpoint_disable
trap 'pg_cleanup; kill ${P:-0} 2>/dev/null' EXIT

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
STORE_BIND=127.0.0.1
STORE_PORT=$PORT
LOG_LEVEL=info
EOF

# fastpki-store is the simplest listener with no CA or TLS prerequisites, so it isolates
# the gate from everything else that could keep a port shut.
echo "=== 1. switched OFF at startup: the port is never opened ==="
psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
  -qc "INSERT INTO config(key,value,updated) VALUES ('STORE_ENABLED','false',0)
       ON CONFLICT (key) DO UPDATE SET value='false'" >/dev/null 2>&1
"$STORE" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" STORE_PORT "$P" || true
chk "process is alive"        yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"
chk "port is CLOSED"          no  "$(listening)"
chk "it says why, once"       yes "$(grep -qi 'switched off' srv.log && echo yes || echo no)"
chk "...naming the key"       yes "$(grep -q 'STORE_ENABLED' srv.log && echo yes || echo no)"

echo "=== 2. switched ON in the database: it starts listening, no restart ==="
psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
  -qc "UPDATE config SET value='true' WHERE key='STORE_ENABLED'" >/dev/null 2>&1
UP=no
for _ in $(seq 1 20); do [ "$(listening)" = "yes" ] && { UP=yes; break; }; sleep 2; done
chk "port OPEN after re-enable" yes "$UP"
chk "same process, never restarted" yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"
kill $P 2>/dev/null; wait $P 2>/dev/null; P=

echo "=== 3. an absent key means enabled (existing deployments unaffected) ==="
psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
  -qc "DELETE FROM config WHERE key='STORE_ENABLED'" >/dev/null 2>&1
"$STORE" --config bootstrap.conf >srv2.log 2>&1 & P=$!
UP=no
for _ in $(seq 1 15); do [ "$(listening)" = "yes" ] && { UP=yes; break; }; sleep 1; done
chk "listens with no key set" yes "$UP"
kill $P 2>/dev/null; wait $P 2>/dev/null; P=

echo "=== 4. the console API validates instead of storing rubbish ==="
WEB="$ROOT/build/fastpki-web"; WPORT=$((PORT+1))
source "$ROOT/tests/user_helpers.sh"
seed_web_user boss bosspw admin
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$WPORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
U="http://127.0.0.1:$WPORT"
curl -s -c b.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null
code(){ curl -s -o /dev/null -w '%{http_code}' -b b.cj -X POST "$U/api/endpoints/$1/enabled?enabled=$2"; }
chk "unknown protocol -> 404"  404 "$(code nosuch false)"
chk "non-boolean -> 400"       400 "$(code est maybe)"
chk "missing value -> 400"     400 "$(curl -s -o /dev/null -w '%{http_code}' -b b.cj -X POST "$U/api/endpoints/est/enabled")"
chk "valid disable -> 200"     200 "$(code est false)"
chk "...and it was stored"     false \
    "$(psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -tAc "SELECT value FROM config WHERE key='EST_ENABLED'" 2>/dev/null | tr -d '[:space:]')"
chk "valid enable -> 200"      200 "$(code est true)"
chk "...and it was stored"     true \
    "$(psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -tAc "SELECT value FROM config WHERE key='EST_ENABLED'" 2>/dev/null | tr -d '[:space:]')"
# The listing must report it so the console can draw the switch in the right state.
chk "listing reports gateable" yes \
    "$(curl -s -b b.cj "$U/api/endpoints" | grep -q '"gateable":true' && echo yes || echo no)"
chk "listing reports enabled"  yes \
    "$(curl -s -b b.cj "$U/api/endpoints" | grep -q '"enabled":' && echo yes || echo no)"
# CRL is served by OCSP, not its own process — it must not offer a dead switch.
chk "CRL is not gateable"      yes \
    "$(curl -s -b b.cj "$U/api/endpoints" | grep -o '{"protocol":"CRL"[^}]*}' | grep -q '"gateable":false' && echo yes || echo no)"

echo "=== 5. the enforcement is NOT in the console ==="
# If this ever fails, someone has given the web console container control over other
# containers. That is the thing this design exists to avoid.
# Look for EXECUTION, not mention: the Backup page legitimately prints `docker compose`
# lines as instructions for the operator to run by hand, and a crude grep flags those.
chk "web never EXECUTES docker" no \
    "$(grep -qE '(system|popen|execlp?|execvp?)[^;]*"[^"]*(docker|podman)' "$ROOT/src/web/main.cpp" && echo yes || echo no)"
chk "the gate lives in the lib"      yes \
    "$([ -f "$ROOT/src/lib/endpoint_gate.cpp" ] && echo yes || echo no)"
chk "every protocol binary gates"    7 \
    "$(grep -l 'gate_protocol' "$ROOT"/src/est/main.cpp "$ROOT"/src/acme/main.cpp "$ROOT"/src/cmp/main.cpp \
        "$ROOT"/src/scep/main.cpp "$ROOT"/src/msxcep/main.cpp "$ROOT"/src/ocsp/main.cpp \
        "$ROOT"/src/certstore/main.cpp 2>/dev/null | wc -l | tr -d ' ')"

echo
echo "=== ENDPOINT DISABLE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ] || echo "RESULT: FAIL"
exit 0
