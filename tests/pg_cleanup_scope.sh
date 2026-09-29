#!/usr/bin/env bash
# pg_cleanup must only ever drop a database pg_setup created.
#
# ── The bug this is about ────────────────────────────────────────────────────────
#
# pg_cleanup dropped whatever $PGDATABASE named, with no check that it was ours. And
# $PGDATABASE defaults to the DEVELOPER'S OWN `fastpki` (tests/pg_helpers.sh) for any suite
# that never calls pg_setup -- there were five of those.
#
# It was not theoretical and it was not even hard to reach: `ca_in_token`'s SKIP path
# (tests/hsm_helpers.sh) calls pg_cleanup unconditionally, so on any box whose PKCS#11
# toolchain is incomplete -- a fresh dev machine, CI without SoftHSM -- running
# tests/pg_smoke.sh printed one SKIP line and DELETED the developer's database.
#
# ⚠️ WHY THIS FILE EXISTS AT ALL. The guard shipped in 068e788 with no test. The two suites
# cited as proof of it, pg_no_leak and trap_cleanup, pass identically whether the guard is
# present or absent -- they check that a THROWAWAY database is reaped, which is the half
# that always worked. So the data-destroying half could have been reverted silently.
# A guard nobody can fail is a decoration; this is the assertion that fails.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"

pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

"$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'SELECT 1' >/dev/null 2>&1 \
  || { echo "SKIP: no Postgres at $PGHOST:$PGPORT"; echo "PASS=0 FAIL=0"; exit 0; }

exists(){ "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAq \
            -c "SELECT count(*) FROM pg_database WHERE datname='$1';" 2>/dev/null | tr -d ' '; }

# A stand-in for the developer's own database. Named nothing like fpki_<test>_<pid>, which
# is the whole point -- pg_setup builds that shape and nothing else does.
VICTIM="devdb_probe_$$"
trap '"$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres \
        -c "DROP DATABASE IF EXISTS $VICTIM;" >/dev/null 2>&1' EXIT
"$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres \
    -c "DROP DATABASE IF EXISTS $VICTIM;" >/dev/null 2>&1
"$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres \
    -c "CREATE DATABASE $VICTIM;" >/dev/null 2>&1
chk "the stand-in database exists to begin with (not a vacuous pass)" 1 "$(exists "$VICTIM")"

echo "=== an ambient \$PGDATABASE nobody created must SURVIVE pg_cleanup ==="
# Exactly the state the five pg_setup-less suites were in: PGDATABASE points at a database
# this run did not create, and something calls pg_cleanup.
( PGDATABASE="$VICTIM"; pg_cleanup ) >/dev/null 2>&1
chk "pg_cleanup left it alone" 1 "$(exists "$VICTIM")"

echo "=== the real path that destroyed it: ca_in_token's SKIP branch ==="
# ⚠️ Drive the PRODUCTION helper, not a re-implementation of it. The destructive call is
# inside hsm_helpers.sh; a test that only called pg_cleanup directly would keep passing if
# someone added a second unguarded drop elsewhere in that file.
cat > "$ROOT/tests/.pgscope_probe.sh" <<'PROBE'
export FASTPKI_ROOT="${FASTPKI_ROOT}"
source "$FASTPKI_ROOT/tests/pg_helpers.sh"
source "$FASTPKI_ROOT/tests/hsm_helpers.sh"
hsm_available() { return 1; }          # a box with no working PKCS#11 toolchain
ca_in_token /tmp/pgscope_ca.pem "/CN=pgscope probe" 1
PROBE
( export FASTPKI_ROOT="$ROOT" PGDATABASE="$VICTIM"
  bash "$ROOT/tests/.pgscope_probe.sh" ) >/dev/null 2>&1
rm -f "$ROOT/tests/.pgscope_probe.sh" /tmp/pgscope_ca.pem
chk "the SKIP path did not drop it either" 1 "$(exists "$VICTIM")"

echo "=== and a database pg_setup DID create is still reaped ==="
# The guard must not be a blanket refusal: if it stopped dropping our own throwaways we
# would be back to the 1329 leaked databases.
( pg_setup pgscope >/dev/null 2>&1
  MINE="$PGDATABASE"
  [ -n "$MINE" ] || { echo "  [FAIL] pg_setup produced no database name"; exit 1; }
  case "$MINE" in fpki_pgscope_*) ;; *) echo "  [FAIL] unexpected name $MINE"; exit 1 ;; esac
  before=$("$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAq \
             -c "SELECT count(*) FROM pg_database WHERE datname='$MINE';" | tr -d ' ')
  pg_cleanup
  after=$("$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAq \
             -c "SELECT count(*) FROM pg_database WHERE datname='$MINE';" | tr -d ' ')
  printf '%s %s\n' "$before" "$after" > /tmp/pgscope_reap.$$ ) >/dev/null 2>&1
read -r B A < /tmp/pgscope_reap.$$ 2>/dev/null || { B=x; A=x; }
rm -f /tmp/pgscope_reap.$$
chk "a pg_setup database existed" 1 "$B"
chk "  and pg_cleanup still dropped it" 0 "$A"

echo
echo "=== PG CLEANUP SCOPE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
