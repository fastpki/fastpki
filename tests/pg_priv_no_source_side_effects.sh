#!/usr/bin/env bash
# Sourcing a helper must not RUN anything, and no privilege probe may block forever.
#
# The clients demo sources pg_helpers.sh (which pulls in pg_priv.sh) before it prints
# its first line. A probe that blocks there blocks the whole script with a blank
# screen: no banner, no error, nothing for a user to report except that it sits and
# does nothing. `id` and `su` can both block indefinitely — they consult every NSS
# backend the host has configured, and `su` also runs the PAM stack — so neither is
# safe to call at source time, and neither is safe to call unbounded.
#
# This cannot reproduce on a developer machine by accident: the probe only runs as
# root, so the whole hazard is invisible unless a test fakes being root. That is what
# the stub PATH below is for.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
        else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
BIN="$W/bin"; mkdir -p "$BIN"

# `id -u` says 0, so the code under test believes it is root and probes. Every named
# account "exists", so it gets as far as attempting the drop.
cat > "$BIN/id" <<'EOS'
#!/bin/sh
case "$1" in
  -u) echo 0 ;;
  *)  exit 0 ;;
esac
EOS
# A `su` that never returns — the failure being guarded against.
cat > "$BIN/su" <<EOS
#!/bin/sh
: > "$W/su-was-run"
sleep 30
EOS
chmod +x "$BIN/id" "$BIN/su"

# A deadline in portable shell. NOT \`timeout\`: macOS does not ship it, and a guard
# that cannot run on the machine the code is written on is not a guard.
bounded() {   # <seconds> <cmd...>  -> 124 if it had to be killed
    local secs=$1; shift
    "$@" >/dev/null 2>&1 &
    local pid=$! n=0
    while [ "$n" -lt "$secs" ] && kill -0 "$pid" 2>/dev/null; do sleep 1; n=$((n+1)); done
    if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; return 124
    fi
    wait "$pid"
}

echo "=== sourcing pg_priv.sh runs no program, even when it believes it is root ==="
cat > "$W/src.sh" <<EOS
PATH="$BIN:\$PATH"
source "$ROOT/tests/pg_priv.sh"
EOS
bounded 8 bash "$W/src.sh"; RC=$?
chk "sourcing returns instead of hanging"          0  "$RC"
chk "  and no 'su' was run by the source itself"   no "$([ -f "$W/su-was-run" ] && echo yes || echo no)"

echo "=== when a caller DOES need the drop, the probe is bounded, not infinite ==="
rm -f "$W/su-was-run"
cat > "$W/use.sh" <<EOS
PATH="$BIN:\$PATH"
source "$ROOT/tests/pg_priv.sh"
pg_as true
EOS
bounded 25 bash "$W/use.sh"; RC=$?
chk "pg_as returns despite a 'su' that never does"  0   "$RC"
# ⚠️ Without this the assertion above would also pass if the drop were simply deleted:
# "did not hang" and "did nothing" look identical from the outside.
chk "  and it really did attempt the drop"          yes "$([ -f "$W/su-was-run" ] && echo yes || echo no)"

echo
echo "=== PG PRIV SOURCE SIDE EFFECTS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
