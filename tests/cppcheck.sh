#!/usr/bin/env bash
# Static-analysis gate. Runs cppcheck over FastPKI's own code
# (src/ + include/pki) — NOT the vendored third_party/ headers and NOT the standalone
# top-level lib/ (own-crypto, out of scope here). Fails on any error / warning /
# performance / portability finding. Self-skips when cppcheck isn't installed.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
if ! command -v cppcheck >/dev/null 2>&1; then
    echo "SKIP: cppcheck not installed (apt-get install cppcheck)"; exit 0
fi
OUT="$(mktemp)"; PROG="$(mktemp)"
trap 'rm -f "$OUT" "$PROG"' EXIT

# ⚠️ PIN THE OUTPUT FORMAT, OR THE DETECTOR READS NOTHING. This counted lines matching a
# PARENTHESISED severity — `(warning)` — which is cppcheck 1.x's `cppcheck1` template. 2.x
# defaults to the gcc template, `file:line:col: warning: message [id]`, with no parentheses
# anywhere. Combined with --error-exitcode=0 throwing cppcheck's own verdict away, that left
# the grep as the only detector and it matched NOTHING: every real finding counted 0, the
# suite printed "(none)" and "findings=0", and exited 0. Introduce a genuine uninitialised
# member or use-after-free and this gate passed. --template removes the dependency on
# whatever default the installed cppcheck happens to have.
# ⚠️ SUPPRESS third_party IN THE ANALYSIS, NOT AFTERWARDS. Filtering the vendored headers out
# of the output afterwards leaves --error-exitcode reflecting THEM, so cppcheck exited non-zero
# on a tree whose own code was clean and the exit status stopped meaning anything. Suppressing
# by path makes the exit status describe OUR code alone. They are out of scope by this suite's
# own definition and unfixable here regardless: both are untracked, and the Dockerfile refetches
# them from upstream during the image build, so a local edit is silently discarded.
cppcheck --enable=warning,performance,portability --std=c++20 --language=c++ \
    --inline-suppr --suppress=missingInclude --suppress=missingIncludeSystem \
    --suppress='*:*/third_party/*' \
    --template='{file}:{line}: {severity}: {message} [{id}]' \
    --error-exitcode=2 -I "$ROOT/include" -I "$ROOT/third_party" \
    "$ROOT/src" "$ROOT/include/pki" 2>"$OUT" >"$PROG"
RC=$?

PAT='^[^:]+:[0-9]+: (error|warning|performance|portability): '
# ⚠️ EXCLUDE third_party, WHICH THIS SUITE'S SCOPE ALREADY EXCLUDES. `-I third_party` puts
# httplib.h and nlohmann/json.hpp on the include path, so cppcheck analyses them and reports
# them: 37 of the 77 findings measured on Alpine's cppcheck 2.21 came from those two headers
# alone. They are UNTRACKED and the Dockerfile refetches them from upstream during the image
# build, so a local edit is discarded — there is nothing this repository could fix, and
# counting them would make the gate permanently red for reasons outside our control.
FINDINGS="$(grep -E "$PAT" "$OUT" | grep -v '/third_party/')"
N=$(printf '%s' "$FINDINGS" | grep -c . )
# ⚠️ PRECONDITION, because "no findings" and "analysed nothing" print identically. Every
# other guard in this harness carries one (no_insecure_settings.sh and suite_exit_honest.sh
# both assert their own search still finds something that IS there); this file had none, so
# an option a newer cppcheck rejects, a path matching no files, or a parse abort all read as
# a clean run. cppcheck announces each translation unit on stdout as it goes.
CHECKED=$(grep -c '^Checking ' "$PROG")

echo "=== cppcheck findings (error/warning/performance/portability) ==="
printf '%s\n' "$FINDINGS" | grep -E . || echo "  (none)"
echo

fail=0
if [ "$CHECKED" -eq 0 ]; then
    echo "  [FAIL] PRECONDITION: cppcheck analysed no translation unit at all — this is not a"
    echo "         clean run, it is a run that could not have found anything. Its stderr:"
    sed -n '1,10p' "$OUT" | sed 's/^/           /'
    fail=$((fail+1))
fi
[ "$N" -eq 0 ] || fail=$((fail+1))
# cppcheck itself failing (bad option, crash) is distinct from it reporting findings, and
# --error-exitcode makes the two distinguishable rather than both looking like success.
if [ "$RC" -ne 0 ] && [ "$N" -eq 0 ]; then
    echo "  [FAIL] cppcheck exited $RC while reporting no parsable finding — it did not run"
    echo "         the way this gate assumes. Its stderr:"
    sed -n '1,10p' "$OUT" | sed 's/^/           /'
    fail=$((fail+1))
fi

echo "=== CPPCHECK: files_checked=$CHECKED findings=$N exit=$RC FAIL=$fail ==="
[ "$fail" -eq 0 ]
