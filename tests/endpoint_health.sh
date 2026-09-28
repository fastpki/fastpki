#!/usr/bin/env bash
# Endpoint health probe: the Endpoints page shows a healthy/unhealthy badge
# per protocol, from a TCP-connect probe of each listener. This guards the real probe
# behaviour — up vs down, keyed correctly by protocol — not just the markup.
#
# Deterministic without standing up all nine protocol services: point HEALTH_PROBE_HOST
# at 127.0.0.1, aim one protocol's port at the web's OWN listener (so its probe finds a
# live socket) and another at a closed port. The probe must report the first healthy and
# the second unhealthy with an error.
#
# Self-contained (§3d) + shell-only (§3e): ephemeral Postgres, own port, temp dir, SKIPs
# cleanly when no Postgres is reachable. Asserts on the served bytes of a running server.
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
W="$(mktemp -d)"; cd "$W"; PORT=18262
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
# value of a JSON field for a given protocol block: field($proto,$key)
field(){ tr '{' '\n' < health.json | grep "\"protocol\":\"$1\"" | sed -n "s/.*\"$2\":\"\{0,1\}\([^,\"}]*\).*/\1/p" | head -1; }

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi

pg_setup endpoint_health
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
# OCSP points at the web's own port (a live listener -> healthy); EST at port 1 (closed).
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
OCSP_PORT=$PORT
EST_PORT=1
LOG_LEVEL=err
EOF
seed_web_user admin adminpw12 admin
seed_web_user auditor auditpw12 auditor
# Also set a bogus HEALTH_PROBE_PREFIX: HEALTH_PROBE_HOST must win over it (the OCSP
# probe still resolves to 127.0.0.1 and reads healthy), proving the k8s prefix override
# exists and that HOST takes precedence over PREFIX.
HEALTH_PROBE_HOST=127.0.0.1 HEALTH_PROBE_PREFIX=zz-nonexistent- "$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c admin.cj -X POST "$U/api/login" -d 'username=admin&password=adminpw12' >/dev/null
curl -s -c aud.cj   -X POST "$U/api/login" -d 'username=auditor&password=auditpw12' >/dev/null

echo "=== /api/endpoints/health probes every listener ==="
chk "endpoint is admin-only" 403 "$(code -b aud.cj "$U/api/endpoints/health")"
chk "admin gets 200"         200 "$(code -b admin.cj "$U/api/endpoints/health")"
curl -s -b admin.cj "$U/api/endpoints/health" -o health.json
# All nine protocol rows are present (same set as the endpoints map).
chk "reports all 9 protocols" 9 "$(grep -o '"protocol"' health.json | wc -l | tr -d ' ')"

echo "=== a live listener reads healthy, a closed port reads unhealthy ==="
chk "OCSP (points at a live port) healthy"  true  "$(field OCSP healthy)"
chk "CRL (shares OCSP's port) healthy"      true  "$(field CRL healthy)"
chk "EST (closed port) unhealthy"           false "$(field EST healthy)"
chk "EST carries a connect error"           yes   "$([ -n "$(field EST error)" ] && echo yes || echo no)"
chk "a healthy probe carries no error"      yes   "$([ -z "$(field OCSP error)" ] && echo yes || echo no)"
# The probe must never take forever on a dead port: 1.5s timeout per listener.
chk "EST reports a latency number"          yes   "$(field EST ms | grep -qE '^[0-9]+$' && echo yes || echo no)"

echo "=== HEALTH_PROBE_HOST wins over HEALTH_PROBE_PREFIX (k8s override present) ==="
# A bogus prefix is set alongside HOST=127.0.0.1; OCSP still reads healthy, so HOST won.
chk "OCSP still healthy despite bogus prefix" true "$(field OCSP healthy)"

echo "=== the console ships the health UI ==="
curl -s "$U/" -o index.html
chk "Health column in the endpoints table" yes "$(grep -qF "['health','Health']" index.html && echo yes || echo no)"
chk "health badge renderer present"        yes "$(grep -qF 'function renderEpHealth' index.html && echo yes || echo no)"
chk "badge is keyed by protocol"           yes "$(grep -qF 'data-proto=' index.html && echo yes || echo no)"
chk "a Recheck action is shipped"          yes "$(grep -qF 'id="ephcheck"' index.html && echo yes || echo no)"
chk "healthy/unhealthy badge styles"       yes "$(grep -qF '.hbadge.up{' index.html && grep -qF '.hbadge.down{' index.html && echo yes || echo no)"

echo "=== the probe works when the console holds more than 1024 descriptors ==="
# The probe waited on its socket with select(), putting it in an fd_set with FD_SET. An
# fd_set holds descriptors below FD_SETSIZE (1024) and FD_SET does not check, so once the
# console held enough connections the next probe wrote past the fd_set on the stack. A
# second console is started with descriptors 20..1100 already open (inherited from the
# shell that launches it), so every socket it creates is numbered above 1024.
#
# ⚠️ THIS SECTION ALONE DOES NOT CATCH THE OLD CODE EVERYWHERE. The wait is reached only
# when connect() returns EINPROGRESS, and a loopback connect can complete at once — on the
# Mac it does, and the old code passed here. What it does show is that the console probes
# and survives with descriptors above 1024. The source check after it is the guard that
# fails without the fix.
kill $P 2>/dev/null; wait $P 2>/dev/null
if ( ulimit -n 4096 ) 2>/dev/null; then
    (
        ulimit -n 4096
        _i=20; while [ $_i -le 1100 ]; do eval "exec $_i</dev/null"; _i=$((_i+1)); done
        HEALTH_PROBE_HOST=127.0.0.1 exec "$WEB" --config web.conf >web2.log 2>&1
    ) & P=$!
    wait_conf "web.conf" WEB_PORT "$P" || true
    # The descriptors the console holds, counted from outside it.
    nfds(){ if [ -d "/proc/$P/fd" ]; then ls "/proc/$P/fd" | wc -l; else lsof -p "$P" 2>/dev/null | wc -l; fi | tr -d ' '; }
    chk "PRECONDITION: the console holds more than 1024 descriptors" yes \
        "$([ "$(nfds)" -gt 1024 ] && echo yes || echo no)"
    curl -s -c admin.cj -X POST "$U/api/login" -d 'username=admin&password=adminpw12' >/dev/null
    curl -s -b admin.cj "$U/api/endpoints/health" -o health.json
    chk "OCSP (a live port) still reads healthy"          true  "$(field OCSP healthy)"
    chk "EST (a closed port) still reads unhealthy"       false "$(field EST healthy)"
    chk "the console survived the probes"                 yes   "$(kill -0 $P 2>/dev/null && echo yes || echo no)"
    chk "  and answers a second round"                    200   "$(code -b admin.cj "$U/api/endpoints/health")"
    kill $P 2>/dev/null; wait $P 2>/dev/null
else
    chk "PRECONDITION: this shell may raise its open-file limit to 4096" yes no
fi
# The shape, not the two sites: no source file may wait on a socket through an fd_set.
# Comment lines are skipped, since the comments above the fixes name what they replaced.
chk "no FD_SET, FD_ZERO or select() in src/" "" \
    "$(grep -rnE '(FD_SET|FD_ZERO|[^a-zA-Z_.>]select)[[:space:]]*\(' "$ROOT/src" | grep -vE '^[^:]*:[0-9]+:[[:space:]]*//')"

echo
echo "=== ENDPOINT HEALTH: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
