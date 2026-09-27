#!/usr/bin/env bash
# Sourcing tests/pg_helpers.sh must never block, whatever the Postgres endpoint does.
#
# ⚠️ A SOURCE-TIME NETWORK CALL WITH ITS STDERR DISCARDED. pg_helpers aligns the pg_dump
# client to the server major, and to do that it asks the server its version — at SOURCE
# time, unbounded, with 2>/dev/null. A host that ACCEPTS the connection and then never
# answers therefore blocked every caller forever and printed nothing at all.
#
# The visible symptom belongs to whoever sourced it. For the clients demo the last line on
# screen was "loading helpers...", so it read as the demo doing nothing — reported twice
# that way, with no output anyone could attribute to Postgres.
#
# ⚠️ AN ORDINARY "NO SERVER" NEVER SHOWED THIS. A closed port REFUSES, instantly, which is
# what every developer machine and every CI run does — so the healthy path and the broken
# path were indistinguishable right up to the moment someone had a container port held
# open by a server that had not finished starting.
#
# The fixture below is that exact shape and nothing else: accept, then stay silent.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

HELPER="${PG_HELPERS_UNDER_TEST:-$ROOT/tests/pg_helpers.sh}"

# ── preconditions ────────────────────────────────────────────────────────────────
# ⚠️ WITHOUT THESE THE SUITE PASSES WITHOUT TESTING ANYTHING. The probe is guarded by
# `command -v pg_dump`, so on a host with no Postgres client the function returns before
# it ever opens a socket — and a "returned quickly" assertion is then satisfied by code
# that did not run. Same for python3, which is the fixture.
have(){ command -v "$1" >/dev/null 2>&1 && echo yes || echo no; }
chk "PRECONDITION: pg_dump exists, so the probe is actually reached" yes "$(have pg_dump)"
chk "PRECONDITION: psql exists, so the probe can attempt a connection" yes "$(have psql)"
chk "PRECONDITION: python3 exists to hold a port open" yes "$(have python3)"
if [ "$(have pg_dump)" != yes ] || [ "$(have psql)" != yes ] || [ "$(have python3)" != yes ]; then
    echo "  [SKIP] no Postgres client or python3 on this host — the probe is unreachable here"
    echo "=== PG HELPERS NO BLOCK: PASS=$pass FAIL=$fail ==="
    [ "$fail" -eq 0 ] || exit 1
    exit 0
fi

# ── the fixture: a port that accepts and then never speaks ───────────────────────
# Port 0 so this never collides with a real Postgres, or with a parallel run of itself.
PORTFILE=$(mktemp); LISTENER=
cleanup(){
    if [ -n "$LISTENER" ]; then
        kill -9 "$LISTENER" 2>/dev/null
        # Reap it, so job control does not print "Killed: 9" over the suite's own result.
        wait "$LISTENER" 2>/dev/null
    fi
    rm -f "$PORTFILE"
}
trap cleanup EXIT
python3 -c '
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0)); s.listen(8)
sys.stdout.write("%d\n" % s.getsockname()[1]); sys.stdout.flush()
held = []
while True:
    c, _ = s.accept()      # accept, then never answer: the whole point of the fixture
    held.append(c)
' > "$PORTFILE" &
LISTENER=$!

PORT=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
    PORT=$(head -1 "$PORTFILE" 2>/dev/null)
    [ -n "$PORT" ] && break
    sleep 1
done
chk "PRECONDITION: the silent listener came up and reported a port" yes \
    "$([ -n "$PORT" ] && echo yes || echo no)"
[ -n "$PORT" ] || { echo "=== PG HELPERS NO BLOCK: PASS=$pass FAIL=$fail ==="; exit 1; }

# ── the assertion ────────────────────────────────────────────────────────────────
# NOT `timeout`: coreutils, absent on macOS. Background the source and poll, which is what
# pg_priv.sh does for the same reason.
DEADLINE=30
OUT=$(mktemp)
(
  FASTPKI_PG_AUTOSTART=0 PG_PROBE_TIMEOUT=3 \
  PGHOST=127.0.0.1 PGPORT="$PORT" PGUSER=fastpki PGPASSWORD=fastpki \
  bash -c 'source "$1"; echo SOURCE_RETURNED' _ "$HELPER"
) > "$OUT" 2>&1 &
SRCPID=$!
waited=0
while [ "$waited" -lt "$DEADLINE" ] && kill -0 "$SRCPID" 2>/dev/null; do
    sleep 1; waited=$((waited+1))
done
if kill -0 "$SRCPID" 2>/dev/null; then
    kill -9 "$SRCPID" 2>/dev/null; wait "$SRCPID" 2>/dev/null
    RETURNED=no
else
    wait "$SRCPID" 2>/dev/null
    RETURNED=$(grep -q '^SOURCE_RETURNED$' "$OUT" && echo yes || echo no)
fi

chk "sourcing pg_helpers returns against a port that never answers" yes "$RETURNED"
chk "it returned well inside the deadline, not at it" yes \
    "$([ "$waited" -lt "$DEADLINE" ] && echo yes || echo no)"

# ⚠️ RETURNING QUIETLY WOULD BE ITS OWN BUG. Alignment is skipped here, so dump/restore
# suites can now fail with a version mismatch — that must be attributable to this, not
# discovered three suites later as somebody else's assertion.
chk "it names the endpoint that did not answer" yes \
    "$(grep -q "127.0.0.1:$PORT" "$OUT" && echo yes || echo no)"
chk "it says alignment was skipped, so a later mismatch is attributable" yes \
    "$(grep -qi 'without client-version alignment' "$OUT" && echo yes || echo no)"
rm -f "$OUT"

echo "=== PG HELPERS NO BLOCK: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ] || exit 1
