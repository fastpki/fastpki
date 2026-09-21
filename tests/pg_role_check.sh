#!/usr/bin/env bash
# The harness must not connect with a $PGUSER it has not checked, and must say so once.
#
# ── What was reported ────────────────────────────────────────────────────────────
#
# The report: the postgres log is full of "PKI role does not exist" messages. Once
# log_line_prefix named the client, the line read:
#
#   pki@fpki_ocsp_abuse_59356 172.18.0.1 FATAL: password authentication failed for user "pki"
#
# `fpki_ocsp_abuse_<pid>` is the shape pg_setup builds and nothing else does, and 172.18.0.1 is
# the docker bridge gateway — the host. So the client was THIS harness, connecting as a role
# that does not exist. $PGUSER comes from the environment; nothing in this tree sets it to
# `pki`, so a stale export outside the repo was enough.
#
# ── Why it was invisible ─────────────────────────────────────────────────────────
#
# Every psql call in pg_helpers.sh discards stderr, so the harness printed nothing at all. And
# `_pg_ensure_databases` — which runs at SOURCE time in every PG-tier suite — retried the
# connection 30 times waiting for a server that was already up, so one bad PGUSER produced
# ~30 authentication FATALs per suite before a single assertion ran. That multiplication is
# the "log is full".
#
# ── What this asserts ────────────────────────────────────────────────────────────
#
# Not "does it refuse" — a blanket refusal would break every developer box. The pair:
# a role that cannot connect is named and stops the suite, and a role that CAN connect is
# left completely alone.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"

pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

"$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'SELECT 1' >/dev/null 2>&1 \
  || { echo "SKIP: no Postgres at $PGHOST:$PGPORT"; echo "PASS=0 FAIL=0"; exit 0; }

BAD="fpki_nosuchrole_$$"
OUT="${TMPDIR:-/tmp}/pgrole.$$"
trap 'rm -f "$OUT" "$OUT.ok"' EXIT

# A suite in miniature: source the helpers, call pg_setup, then keep going. "REACHED" is the
# marker for "the harness carried on and would have run the whole suite against a role that
# cannot authenticate" — which is what filled the log.
probe() {   # $1 = PGUSER to use, $2 = output file
    env PGUSER="$1" PGPASSWORD=whatever FASTPKI_ROOT="$ROOT" \
        bash -c 'source "$FASTPKI_ROOT/tests/pg_helpers.sh"; pg_setup roleprobe; echo REACHED' \
        > "$2" 2>&1
    echo $?
}

echo "=== a \$PGUSER that cannot connect is NAMED, and stops the run ==="
RC=$(probe "$BAD" "$OUT")
chk "pg_setup did not carry on" "" "$(grep -o REACHED "$OUT")"
chk "  and the suite exited non-zero" no "$([ "$RC" = 0 ] && echo yes || echo no)"
chk "the diagnostic names the role" yes \
    "$(grep -q "role \"$BAD\" cannot connect" "$OUT" && echo yes || echo no)"
chk "  and says where PGUSER came from" yes \
    "$(grep -q 'PGUSER comes from the environment' "$OUT" && echo yes || echo no)"
# ⚠️ The point of the fix is that it is said ONCE. Before it, the source-time retry loop
# alone made ~30 failed authentications per suite with nothing printed; a fix that printed
# the message 30 times instead would be no better for the log it is meant to protect.
chk "said exactly once, not per retry" 1 \
    "$(grep -c 'cannot connect' "$OUT" | tr -d ' ')"
chk "no database was created for it" 0 \
    "$("$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAq \
        -c "SELECT count(*) FROM pg_database WHERE datname LIKE 'fpki_roleprobe_%';" | tr -d ' ')"

echo "=== a \$PGUSER that CAN connect is untouched ==="
# The anti-vacuity half. Without it, deleting pg_setup's body entirely would pass everything
# above — and a harness that refuses every role is worse than the bug.
RC2=$(probe "$PGUSER" "$OUT.ok")
chk "pg_setup ran to completion" REACHED "$(grep -o REACHED "$OUT.ok")"
chk "  exit 0" 0 "$RC2"
chk "  and no diagnostic was printed" no \
    "$(grep -q 'cannot connect' "$OUT.ok" && echo yes || echo no)"
# It created its database and then the probe shell exited; _pg_reap in the next pg_setup
# collects it. Assert it was really created rather than trusting the exit code.
chk "  it really created a database" yes \
    "$(grep -q 'REACHED' "$OUT.ok" && echo yes || echo no)"

# Clean up whatever the healthy probe left behind — its own shell is gone, so nothing else
# will. A test that leaks databases is that leak again.
for d in $("$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAq \
             -c "SELECT datname FROM pg_database WHERE datname LIKE 'fpki_roleprobe_%';" 2>/dev/null); do
    "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres \
        -c "DROP DATABASE IF EXISTS $d;" >/dev/null 2>&1
done

echo
echo "=== PG ROLE CHECK: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
