#!/usr/bin/env bash
# An ephemeral test database is dropped even when the suite loses its EXIT trap.
#
# pg_setup's caller arms `trap 'pg_cleanup; …' EXIT`. Most suites then arm a SECOND
# `trap 'kill $SRV' EXIT` once the daemon is up, and bash does not stack EXIT traps —
# the second REPLACES the first. pg_cleanup silently stopped running in 85 suites and
# every PG-tier run leaked its databases; 1329 of them (11GB) had accumulated before
# anyone noticed, because a leaked database breaks nothing until the disk fills.
#
# So the guard is not "pg_cleanup works" — it did. It is that a suite which CLOBBERS
# its trap, exactly like those 85 do, still ends up with no database left behind.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
exists(){ "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAq \
            -c "SELECT count(*) FROM pg_database WHERE datname='$1';" 2>/dev/null | tr -d ' '; }

"$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'SELECT 1' >/dev/null 2>&1 \
  || { echo "SKIP: no Postgres at $PGHOST:$PGPORT"; exit 0; }

# A stand-in for the 85 real suites: set up a database, then clobber the EXIT trap
# the way they do. It must run as its own PROCESS — the reaper keys on the owning
# pid, and `$$` inside a subshell is still the parent's.
cat > "$W/clobberer.sh" <<'EOF'
source "$FASTPKI_ROOT/tests/pg_helpers.sh"
pg_setup no_leak_probe
trap 'pg_cleanup' EXIT      # what pg_setup's caller arms
echo "$PGDATABASE"          # tell the parent which database to look for
trap 'true' EXIT            # …and what the suite arms once its daemon is up
EOF
DB=$(FASTPKI_ROOT="$ROOT" bash "$W/clobberer.sh" | tail -1)

echo "=== the clobbered trap really does leak (the bug being guarded) ==="
chk "the probe created a database"        1   "$([ -n "$DB" ] && echo 1 || echo 0)"
chk "and it survived the probe's exit"    1   "$(exists "$DB")"

echo "=== the next pg_setup reaps it anyway ==="
# Any later suite triggers the reap; use a real one so this asserts the actual path.
pg_setup no_leak_reaper >/dev/null 2>&1
chk "the orphaned database is gone"       0   "$(exists "$DB")"
chk "the live suite's own database stays" 1   "$(exists "$PGDATABASE")"

echo "=== the registry does not grow without bound ==="
chk "the reaped entry was dropped from the registry" no \
    "$(grep -q " $DB\$" "$_PG_REGISTRY" 2>/dev/null && echo yes || echo no)"

pg_cleanup >/dev/null 2>&1
chk "pg_cleanup still drops the current database" 0 "$(exists "$PGDATABASE")"

echo
echo "=== PG NO-LEAK: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
