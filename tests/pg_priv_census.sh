#!/usr/bin/env bash
# CENSUS GUARD: no suite may invoke a Postgres SERVER binary outside pg_as.
#
# ⚠️ WHY A CENSUS AND NOT A SIXTH ONE-SITE FIX.
#
# initdb, pg_ctl and pg_basebackup refuse to run as root, and `deploy/lab-test.sh`
# starts the test container with no `--user`, so the in-image tier IS root. A suite
# that starts its own throwaway cluster therefore hits the refusal, prints its skip
# line, and exits 0 — counted among `NNN passed`. tests/pg_priv.sh exists precisely
# for this, and its own header lists the four suites it was written to rescue:
#
#     pg_reconnect.sh  acme_reconnect.sh  replication_stream.sh  ha_failover.sh
#
# Four sites were converted. Two were missed, and stayed missed until an assertion
# census — in-image counts against the same suites on a developer Mac — turned them
# up at 2d5f9557a449:
#
#     deploy_selfsigned_tls.sh   3 assertions in-image vs 16 on the Mac (13 lost)
#     pg_helpers.sh              latent: pg_ensure_server()'s fallback cluster
#
# deploy_selfsigned_tls.sh is the whole of the Postgres-TLS proof — verify-full
# against the self-signed cert, the untrusted-anchor rejection, the admin/admin seed,
# the console login, the digest checks. None of it had ever run in the tier that
# runs as root, and the skip line said "throwaway Postgres would not start", which
# reads as "this machine has no Postgres".
#
# So: guard the SHAPE, not the site. A seventh suite that starts a cluster is caught
# here on the day it is written, on any machine, root or not.
#
# ⚠️ THIS GUARD MUST BE ABLE TO SEE A VIOLATION. A scanner whose healthy answer is
# "zero findings" goes vacuous the moment its matcher breaks or its input empties —
# and it looks identical to a pass. Section 0 runs the detector against synthetic
# files with a KNOWN violation and a KNOWN clean form, and section 1 asserts the real
# corpus is non-empty, before any verdict about the tree is reported.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# The server binaries. psql/createdb/pg_isready/pg_dump are CLIENTS — they run as
# root perfectly well and are deliberately not listed.
SERVER_BINS='initdb|pg_ctl|pg_basebackup'

# raw_calls <file> — lines that INVOKE a server binary without pg_as in front.
#
# ⚠️ MATCH THE INVOCATION, NOT THE NAME. The first version of this matched the bare
# word anywhere on the line and reported eight findings, every one of them a mention:
# a trailing comment ("macOS: a UTF-8 locale makes initdb's postmaster die"), a log
# FILENAME ($W/initdb.log), an error string (echo "initdb failed"), this file's own
# `SERVER_BINS=` list, and this file's own heredoc fixtures. A guard that matches its
# own prose is a guard that can never go green — the mirror image of one that can
# never go red.
#
# So the shape required is a COMMAND POSITION plus a FLAG:
#   [start | ; | && | || | | | ( | { ] [VAR=val ...] ["]  [$dir/]  <bin> ["]  -<flag>
# Every real call in the tree is `initdb -D`, `pg_ctl -D`, `pg_basebackup -D`. A
# flagless invocation would slip past — which is what section 3 is for: it does not
# read invocations at all, only whether the wrapper is in scope.
raw_calls() {
    local pfx='(^|[;&|(){}]|&&|\|\|)[[:space:]]*([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]+[[:space:]]+)*'
    local cmd='"?(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/)?'
    grep -nE "($SERVER_BINS)" "$1" 2>/dev/null \
      | grep -vE '^[0-9]+:[[:space:]]*#' \
      | grep -vE 'pg_as[[:space:]]' \
      | grep -vE 'command -v|--version' \
      | sed -E 's/^([0-9]+:)/\1;/' \
      | grep -E "${pfx}${cmd}($SERVER_BINS)\"?[[:space:]]+-"
}

echo "=== 0. the detector, proved against a KNOWN violation and a KNOWN clean file ==="
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
cat > "$T/bad.sh" <<'EOF'
#!/usr/bin/env bash
D="$W/pg"; "$PGBIN/initdb" -D "$D" -U postgres --auth=trust >/dev/null 2>&1
EOF
cat > "$T/good.sh" <<'EOF'
#!/usr/bin/env bash
source "$(dirname "$0")/pg_priv.sh"
pg_own "$W"; pg_as "$PGBIN/initdb" -D "$W/pg" -U postgres --auth=trust >/dev/null 2>&1
pg_as "$PGBIN/pg_ctl" -D "$W/pg" -l "$W/pg/log" start >/dev/null 2>&1
EOF
cat > "$T/mentions.sh" <<'EOF'
#!/usr/bin/env bash
# initdb refuses as root, which is why pg_ctl is wrapped.
[ -x "$d/initdb" ] && PGBIN="$d"
command -v pg_ctl >/dev/null 2>&1 || exit 0
PGMAJ=$(initdb --version 2>/dev/null | sed 's/[^0-9]*\([0-9]*\).*/\1/')
echo "SKIP: Postgres server binaries (initdb/pg_ctl) not found"
EOF
chk "the detector FLAGS a raw initdb"                1 "$(raw_calls "$T/bad.sh"      | wc -l | tr -d ' ')"
chk "the detector PASSES the pg_as form"             0 "$(raw_calls "$T/good.sh"     | wc -l | tr -d ' ')"
chk "the detector ignores comments, probes, strings" 0 "$(raw_calls "$T/mentions.sh" | wc -l | tr -d ' ')"

echo "=== 1. the corpus is non-empty (a census over nothing proves nothing) ==="
SUITES=$(ls "$ROOT"/tests/*.sh 2>/dev/null | wc -l | tr -d ' ')
chk "there are test scripts to scan" yes "$([ "$SUITES" -gt 50 ] && echo yes || echo no)"
# The suites that genuinely start a cluster — the population this guard is about.
CLUSTER_SUITES=""
for f in "$ROOT"/tests/*.sh; do
    grep -qE "($SERVER_BINS)" "$f" || continue
    # A file that only NAMES them (probe/skip text) is not in the population.
    grep -qE "pg_as[[:space:]]|($SERVER_BINS)[\"']?[[:space:]]+-" "$f" || continue
    CLUSTER_SUITES="$CLUSTER_SUITES $(basename "$f")"
done
N=$(printf '%s' "$CLUSTER_SUITES" | wc -w | tr -d ' ')
echo "    cluster-starting suites:$CLUSTER_SUITES"
chk "at least the five known cluster-starting suites are seen" yes \
    "$([ "$N" -ge 5 ] && echo yes || echo no)"

echo "=== 2. every server-binary invocation goes through pg_as ==="
VIOL=""
for f in "$ROOT"/tests/*.sh; do
    b=$(basename "$f")
    # pg_priv.sh DEFINES the wrapper, so it is the one file allowed to run them raw;
    # this file carries a deliberate violation in its section-0 fixture, and scanning
    # itself would report that fixture as a finding forever.
    case "$b" in pg_priv.sh|pg_priv_census.sh) continue;; esac
    out=$(raw_calls "$f")
    [ -n "$out" ] && VIOL="$VIOL
--- $b
$out"
done
[ -n "$VIOL" ] && printf '%s\n' "$VIOL"
chk "no suite invokes initdb/pg_ctl/pg_basebackup outside pg_as" 0 \
    "$(printf '%s\n' "$VIOL" | grep -cE '^[0-9]+:' | tr -d ' ')"

echo "=== 3. every cluster-starting suite SOURCES pg_priv.sh ==="
# The line-level rule above can be defeated by a form the matcher does not know.
# This one is coarse and hard to defeat: if a file starts a cluster, the wrapper must
# be in scope, or `pg_as` is an unbound command and the suite dies rather than skips.
for b in $CLUSTER_SUITES; do
    f="$ROOT/tests/$b"
    [ "$b" = "pg_priv.sh" ] && continue
    got=$(grep -qE 'pg_priv\.sh' "$f" && echo yes || echo no)
    # pg_helpers.sh sources it, so a suite that sources pg_helpers has it transitively.
    [ "$got" = no ] && grep -qE 'pg_helpers\.sh' "$f" && got=yes
    chk "$b has pg_priv in scope" yes "$got"
done

echo
echo "=== PG PRIV CENSUS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
