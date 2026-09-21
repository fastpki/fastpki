#!/usr/bin/env bash
# A guard for demo/pki-bench.sh. NOT a performance test — it asserts the benchmark
# still stands up a throwaway deployment and that every protocol still issues.
#
# Why this exists: pki-bench.sh had been unable to create a CA at all. It built the CA as
# a self-signed pair of files and INSERTed it into ca_instances — a table since dropped —
# with the error sent to /dev/null. demo/pki-demo.sh had the same fault, but it also had
# tests/demo_clients.sh watching it, which is the only reason anyone noticed. pki-bench.sh
# had nothing, so it stayed broken.
#
# The numbers are deliberately not asserted; they depend on the machine and would make this
# flaky for no gain. What is asserted is the part that rots: the deployment comes up and
# each protocol reports N/N rather than 0/N or a skip.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

command -v psql >/dev/null 2>&1 || { echo "SKIP: psql not available"; exit 0; }
psql -h localhost -U fastpki -d postgres -c 'SELECT 1' >/dev/null 2>&1 \
    || { echo "SKIP: no local Postgres reachable as fastpki"; exit 0; }
hsm_available || { echo "SKIP: CA keys are token-only — $(hsm_skip_reason)"; exit 0; }

N=2
PROTOS="est cmp ocsp store"
echo "=== demo/pki-bench.sh still runs and every protocol issues (n=$N) ==="
OUT=$(cd "$ROOT" && bash demo/pki-bench.sh -n "$N" -k rsa2048 -p "$(echo "$PROTOS" | tr ' ' ',')" 2>&1)
rc=$?
chk "the benchmark exits 0" 0 "$rc"

# Each row is:  proto  key/op  count  seconds  ops/s   where count is "<done>/<asked>".
for p in $PROTOS; do
    line=$(printf '%s\n' "$OUT" | grep -E "^$p[[:space:]]" | head -1)
    chk "$p produced a result row" yes "$([ -n "$line" ] && echo yes || echo no)"
    [ -n "$line" ] || continue
    # Assert the FULL count, not merely that a number appeared: a broken deployment still
    # prints a row, it just reports 0/N — which is exactly how this stayed unnoticed.
    chk "$p completed $N/$N operations" "$N/$N" "$(printf '%s' "$line" | awk '{print $3}')"
done

chk "no step reported a skip" yes "$(printf '%s\n' "$OUT" | grep -qi '(skip)' && echo no || echo yes)"

echo
echo "=== BENCH SMOKE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
