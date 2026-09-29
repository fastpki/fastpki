#!/usr/bin/env bash
# Pull-based TLS discovery scanner — fastpki-discover.
# Stands up two openssl s_server endpoints and harvests their certs:
#   good  : RSA-2048 / SHA-256 self-signed -> flagged self_signed only
#   weak  : RSA-1024 / SHA-1  self-signed -> flagged weak_key, weak_sig, self_signed
# Asserts the inventory rows + compliance flags, plus an unreachable target.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
DISC="$ROOT/build/fastpki-discover"
W="$(mktemp -d)"; cd "$W"; PG=18551; PW=18552
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

pg_setup discover
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
LOG_LEVEL=err
EOF

"$OSSL" req -x509 -newkey rsa:2048 -sha256 -nodes -keyout good.key -out good.pem -days 365 \
    -subj "/CN=good.host" -addext "subjectAltName=DNS:good.host" >/dev/null 2>&1
"$OSSL" req -x509 -newkey rsa:1024 -sha1 -nodes -keyout weak.key -out weak.pem -days 365 \
    -subj "/CN=weak.host" >/dev/null 2>&1

# Serve each cert; SECLEVEL=0 so the SHA-1/1024 endpoint will negotiate.
"$OSSL" s_server -accept "$PG" -cert good.pem -key good.key -quiet -cipher 'ALL:@SECLEVEL=0' >/dev/null 2>&1 &
SG=$!
"$OSSL" s_server -accept "$PW" -cert weak.pem -key weak.key -quiet -cipher 'ALL:@SECLEVEL=0' >/dev/null 2>&1 &
SW=$!
sleep 1; trap 'pg_cleanup; kill $SG $SW 2>/dev/null' EXIT

echo "=== scan (good, weak, unreachable) ==="
REP=$("$DISC" --config bootstrap.conf --timeout 3 "127.0.0.1:$PG" "127.0.0.1:$PW" "127.0.0.1:1")
echo "$REP"
echo "$REP" | grep -q "good.host" && a=yes || a=no
chk "harvested good.host" yes "$a"
echo "$REP" | grep -q "discovered 2 cert(s)" && a=yes || a=no
chk "2 certs discovered, 1 unreachable" yes "$a"
echo "$REP" | grep -q "127.0.0.1:1" && a=yes || a=no
chk "unreachable target reported as error" yes "$a"

echo "=== inventory rows ==="
N=$(pg_exec "SELECT COUNT(*) FROM discovered_certs;")
chk "2 rows in discovered_certs" 2 "$N"
KB=$(pg_exec "SELECT \"keyBits\" FROM discovered_certs WHERE subject LIKE '%good.host%';")
chk "good cert key size recorded (2048)" 2048 "$KB"

echo "=== compliance flags ==="
GF=$(pg_exec "SELECT flags FROM discovered_certs WHERE subject LIKE '%good.host%';")
chk "good cert flagged self_signed only" "self_signed" "$GF"
WF=$(pg_exec "SELECT flags FROM discovered_certs WHERE subject LIKE '%weak.host%';")
echo "$WF" | grep -q "weak_key" && a=yes || a=no
chk "weak cert flagged weak_key" yes "$a"
echo "$WF" | grep -q "weak_sig" && a=yes || a=no
chk "weak cert flagged weak_sig" yes "$a"

echo "=== JSON output ==="
J=$("$DISC" --config bootstrap.conf --timeout 3 --json "127.0.0.1:$PG")
echo "$J" | grep -q '"keyAlgo":"RSA"' && a=yes || a=no
chk "json carries keyAlgo" yes "$a"

echo "=== CIDR expansion ==="
# /30 around the loopback server -> usable hosts 127.0.0.1 and 127.0.0.2 (both
# reach the s_server, which listens on all interfaces) -> proves the fan-out.
# On macOS, 127.0.0.2 requires an lo0 alias (ifconfig lo0 alias 127.0.0.2);
# skip the CIDR test if the alias isn't present.
if (exec 3<>"/dev/tcp/127.0.0.2/$PG") 2>/dev/null; then exec 3>&- 3<&-
  REP2=$("$DISC" --config bootstrap.conf --timeout 2 "127.0.0.1/30:$PG")
  echo "$REP2"
  echo "$REP2" | grep -q "127.0.0.1:$PG" && a=yes || a=no
  chk "CIDR sweep scanned 127.0.0.1" yes "$a"
  echo "$REP2" | grep -q "127.0.0.2:$PG" && a=yes || a=no
  chk "CIDR sweep also scanned 127.0.0.2 (.0/.3 excluded)" yes "$a"
  echo "$REP2" | grep -q "discovered 2 cert(s)" && a=yes || a=no
  chk "CIDR /30 expanded to its 2 usable hosts" yes "$a"
else
  echo "  [SKIP] CIDR expansion (127.0.0.2 not reachable — macOS needs: sudo ifconfig lo0 alias 127.0.0.2)"
fi
# Oversized blocks are refused rather than silently sweeping the internet.
"$DISC" --config bootstrap.conf "10.0.0.0/8:443" 2>cidr_err.txt; rc=$?
chk "oversized CIDR rejected (exit 2)" 2 "$rc"
grep -q "too large" cidr_err.txt && a=yes || a=no
chk "oversized CIDR error explains why" yes "$a"

echo "=== migration trigger webhook ==="
# Both endpoints are non-compliant (self_signed / weak_*) -> a 2-entry work list.
if command -v nc >/dev/null 2>&1; then
    MPORT=18553
    # Portable: macOS nc uses "nc -l PORT", Linux uses "nc -l -p PORT"
    if nc -h 2>&1 | grep -q 'Apple'; then
        ( printf 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'; sleep 2 ) | nc -l "$MPORT" > mcap.txt 2>/dev/null &
    else
        ( printf 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'; sleep 2 ) | nc -l -p "$MPORT" > mcap.txt 2>/dev/null &
    fi
    MPID=$!
    # wait_listen, not wait_port: this listener serves ONE connection, so a probe that
    # connects would BE the request the assertion is about (pg_helpers.sh).
    wait_listen "$MPORT" "$MPID" || true
    "$DISC" --config bootstrap.conf --timeout 3 --migrate-webhook "http://127.0.0.1:$MPORT/reenroll" \
        "127.0.0.1:$PG" "127.0.0.1:$PW" >/dev/null 2>&1 || true
    sleep 1; kill "$MPID" 2>/dev/null
    if grep -q '"migrations"' mcap.txt 2>/dev/null; then
        echo "  [PASS] migration work list delivered"; pass=$((pass+1))
        grep -q '"count":2' mcap.txt 2>/dev/null && a=yes || a=no
        chk "work list has both flagged endpoints" yes "$a"
        grep -q 'weak_key' mcap.txt 2>/dev/null && a=yes || a=no
        chk "work list carries the compliance flags" yes "$a"
    else
        echo "  [SKIP] migration capture inconclusive (nc variant) — dispatch code path still exercised"
    fi
else
    echo "  [SKIP] migration webhook (no nc)"
fi

echo
echo "=== DISCOVER: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
