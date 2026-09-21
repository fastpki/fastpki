#!/usr/bin/env bash
# Every shipped binary must answer `--version` WITHOUT a database.
#
# ⚠️ THIS IS THE ONE QUESTION YOU ASK A BINARY WHEN A BUG REPORT ARRIVES, and it could not
# be answered without the thing you were trying to debug. Every server main() parsed its
# arguments, fell through to Config::load(), and connected to postgres — so on any machine
# that was not already a working deployment:
#
#     $ fastpki-web --version
#     fatal: postgres connect failed: connection to server on socket "/tmp/.s.PGSQL.5432" ...
#
# and `fastpki-mesh --version` did not know the flag at all. A release tag does not fix
# "nobody can tell us what they are running" if the binaries still cannot say.
#
# ⚠️ RUN WITH NO DATABASE REACHABLE, deliberately. Pointing these at a live postgres would
# let a binary connect first and still pass — which is the exact bug. PGHOST is aimed at a
# port nothing listens on so a connection attempt FAILS fast and visibly.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
BIN="${FASTPKI_BIN:-$ROOT/build}"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# Discover the binaries rather than listing them: a new service added next year gets this
# guard for free, and a list here would go stale the first time one is added.
BINS=$(ls "$BIN"/fastpki-* 2>/dev/null | grep -vE 'testclient|\.dSYM' | sort)
chk "PRECONDITION: there are binaries to check" yes \
    "$([ -n "$BINS" ] && echo yes || echo no)"
[ -n "$BINS" ] || { echo "=== VERSION FLAG: PASS=$pass FAIL=$fail ==="; exit 1; }

echo "=== every binary answers --version with no database reachable ==="
BAD=""
for b in $BINS; do
    n=$(basename "$b")
    # 5432 on a host that refuses instantly: no timeout, and any attempt to connect shows
    # up as a failure rather than a hang.
    out=$(PGHOST=127.0.0.1 PGPORT=1 PGDATABASE=nope PGUSER=nope \
          "$b" --version 2>&1 | head -1)
    case "$out" in
        *"postgres"*|*"connect"*|*"unknown argument"*|*"Usage"*|"") BAD="$BAD $n($out)";;
    esac
done
chk "no binary needs a database to say what it is" "" "$BAD"

# ⚠️ AND THE ANSWER MUST BE THE VERSION, not merely non-empty. A binary printing its own
# name would satisfy "said something" while telling a bug reporter nothing.
V=$("$BIN/fastpki-web" --version 2>/dev/null | head -1)
chk "the answer looks like a version" yes \
    "$(printf '%s' "$V" | grep -qE '^(v?[0-9]+\.[0-9]+|[0-9a-f]{7,})' && echo yes || echo no)"
# Every binary in one build reports the SAME version. Two answers means two builds got
# mixed, which is worse than no version at all because it looks authoritative.
U=$(for b in $BINS; do "$b" --version 2>/dev/null | head -1; done | sort -u | wc -l | tr -d ' ')
chk "  and every binary agrees on it" 1 "$U"

echo
echo "=== VERSION FLAG: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
