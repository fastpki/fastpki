#!/usr/bin/env bash
# §4.2: the one-time bootstrap must seed the console admin over a real
# (TLS-authenticated) Postgres connection, and FAIL LOUDLY if Postgres never becomes
# ready — not swallow the error (the old `|| echo WARN`) and leave a deployment with
# no console admin. `pg_isready` (the wait-postgres gate) only proves the TCP port is
# open, so the seed itself retries the real operation and exits non-zero on exhaustion.
#
# Self-contained (§3d/§3e): drives deploy/bootstrap.sh with PKI_DIR/PKI_CONF pointed at
# a temp dir + an ephemeral Postgres. SKIPs cleanly without Postgres or the binaries.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
BOOT="$ROOT/deploy/bootstrap.sh"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

[ -x "$ROOT/build/fastpki-config" ] || { echo "SKIP: fastpki-config not built"; exit 0; }
command -v psql >/dev/null 2>&1 || { echo "SKIP: psql not installed"; exit 0; }
# bootstrap.sh calls the tools by bare name — put build/ on PATH
export PATH="$ROOT/build:$PATH"

W="$(mktemp -d)"; cd "$W"
pg_setup bootstrap_seed
if [ "$(pg_exec 'SELECT 1;' 2>/dev/null)" != "1" ]; then echo "SKIP: no Postgres available"; exit 0; fi
trap 'pg_cleanup' EXIT
printf 'PG_CONNINFO=%s\n' "$PG_CONNINFO" > live.conf

echo "=== 1. ready Postgres: bootstrap seeds the admin and exits 0 ==="
PKI_DIR="$W/p1" PKI_CONF="$W/live.conf" sh "$BOOT" >b1.log 2>&1
chk "bootstrap exits 0 on a ready DB"  0 "$?"
chk "console admin row was created"    1 "$(pg_exec "SELECT count(*) FROM web_users WHERE username='admin';")"

echo "=== 1b. idempotent re-run ==="
PKI_DIR="$W/p1" PKI_CONF="$W/live.conf" sh "$BOOT" >b1b.log 2>&1
chk "re-run exits 0 (idempotent)"      0 "$?"
chk "still exactly one admin row"      1 "$(pg_exec "SELECT count(*) FROM web_users WHERE username='admin';")"

echo "=== 2. Postgres unreachable: bootstrap FAILS LOUDLY, no silent WARN ==="
printf 'PG_CONNINFO=host=127.0.0.1 port=1 dbname=fastpki user=x password=x connect_timeout=1\n' > dead.conf
PKI_DIR="$W/p2" PKI_CONF="$W/dead.conf" \
    BOOTSTRAP_SEED_RETRIES=3 BOOTSTRAP_SEED_DELAY=1 sh "$BOOT" >b2.log 2>&1
rc=$?
chk "exits NON-ZERO when the DB never comes up" nonzero "$([ "$rc" -ne 0 ] && echo nonzero || echo zero)"
chk "prints a loud ERROR"                  yes "$(grep -q 'ERROR: could not seed' b2.log && echo yes || echo no)"
chk "old swallow-and-continue WARN is gone"  no "$(grep -q 'WARN: could not seed' b2.log && echo yes || echo no)"
chk "it actually retried the seed"         yes "$(grep -q 'retry 1/3' b2.log && echo yes || echo no)"

echo
echo "=== BOOTSTRAP SEED: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
