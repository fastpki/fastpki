#!/usr/bin/env bash
# Console-initiated certificate discovery: an admin triggers a scan
# from the web console (POST /api/discover), fastpki-web runs fastpki-discover
# against the targets, and the harvested cert shows up in /api/discovered.
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
W="$(mktemp -d)"; cd "$W"; PORT=18326; TLSPORT=18327
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

# a TLS endpoint to discover
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout t.key -out t.crt -days 2 -subj "/CN=discovered.example" >/dev/null 2>&1
"$OSSL" s_server -accept "$TLSPORT" -cert t.crt -key t.key -quiet >/dev/null 2>&1 & SRV=$!
pg_setup web_discover
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
DISCOVER_BIN=$ROOT/build/fastpki-discover
LOG_LEVEL=err
EOF
"$WEB" --config web.conf >web.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P $SRV 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"
code -X POST "$U/api/users" -d 'username=boss&password=bosspw12&role=admin' >/dev/null
curl -s -c boss.cj -X POST "$U/api/login" -d 'username=boss&password=bosspw12' >/dev/null
code -b boss.cj -X POST "$U/api/users" -d 'username=al&password=alpw123456&role=requester' >/dev/null
curl -s -c al.cj -X POST "$U/api/login" -d 'username=al&password=alpw123456' >/dev/null

echo "=== Admin triggers a scan from the console ==="
chk "discovered starts empty" yes "$(has "$(curl -s -b boss.cj "$U/api/discovered")" '\[\]')"
RESP=$(curl -s -b boss.cj -X POST "$U/api/discover" --data-urlencode "targets=127.0.0.1:$TLSPORT")
chk "scan returns scanned=1"  yes "$(has "$RESP" '"scanned":1')"
chk "scan rc=0"               yes "$(has "$RESP" '"rc":0')"
sleep 1
DISC=$(curl -s -b boss.cj "$U/api/discovered")
chk "discovered now lists the target" yes "$(has "$DISC" "127.0.0.1:$TLSPORT")"
chk "discovered cert subject captured" yes "$(has "$DISC" 'discovered.example')"

echo "=== Full decoded certificate text (openssl x509 -text) ==="
DID=$(echo "$DISC" | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*')
chk "discovered row exposes an id" yes "$([ -n "$DID" ] && echo yes || echo no)"
CT=$(curl -s -b boss.cj "$U/api/discovered/$DID/cert-text")
chk "cert-text is a full X509 dump"   yes "$(has "$CT" 'Certificate:')"
chk "cert-text shows the subject CN"  yes "$(has "$CT" 'discovered.example')"
chk "cert-text decodes v3 extensions" yes "$(has "$CT" 'X509v3')"
chk "unknown discovered id -> 404" 404 "$(code -b boss.cj "$U/api/discovered/999999/cert-text")"

echo "=== RBAC + validation ==="
chk "requester cannot scan (403)" 403 "$(code -b al.cj -X POST "$U/api/discover" --data-urlencode "targets=127.0.0.1:$TLSPORT")"
chk "unauthenticated cannot scan"     401 "$(code -X POST "$U/api/discover" --data-urlencode "targets=127.0.0.1:$TLSPORT")"
chk "a shell-metachar target is rejected (400)" 400 "$(code -b boss.cj -X POST "$U/api/discover" --data-urlencode 'targets=x;rm -rf /')"

echo "=== the scanner's result reaches the caller ==="
# Its exit status and output were dropped, so a range it refused and a scan that reached
# nothing both answered as success.
chk "a range the scanner refuses to sweep -> 400" 400 \
    "$(code -b boss.cj -X POST "$U/api/discover" --data-urlencode 'targets=10.0.0.0/8:443')"
chk "  and the reply carries the scanner's reason" yes \
    "$(has "$(curl -s -b boss.cj -X POST "$U/api/discover" --data-urlencode 'targets=10.0.0.0/8:443')" 'too large')"
R0=$(curl -s -b boss.cj -X POST "$U/api/discover" --data-urlencode 'targets=127.0.0.1:1')
chk "an unreachable target is counted, not reported as found" "yes yes" \
    "$(has "$R0" '"found":0') $(has "$R0" '"unreachable":1')"
chk "the found count is reported" yes "$(has "$RESP" '"found":1')"

echo
echo "=== WEB DISCOVER: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
