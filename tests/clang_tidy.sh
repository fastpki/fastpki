#!/usr/bin/env bash
# Deep static-analysis gate — the clang static analyzer.
# Runs clang-tidy's path-sensitive clang-analyzer checks (null deref, leaks,
# use-after-free, uninitialised reads) plus a few reliable bugprone checks over
# FastPKI's own translation units, and fails on any finding. This is the heavier
# companion to cppcheck.sh; it needs a compile DB so it configures its own build
# dir. Self-skips without clang-tidy/cmake. Not in the always-on tier (slow) — run
# it on demand: `tests/clang_tidy.sh`.
#
# db_postgres.cpp is excluded because the analyzer walks into libpq's headers and reports
# there, not because the file is optional — PostgreSQL is unconditional
# (`find_package(PostgreSQL REQUIRED)`) and the file is in every build. There is no
# -DFASTPKI_WITH_POSTGRES flag; this comment named one for a long time.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
command -v clang-tidy >/dev/null 2>&1 || { echo "SKIP: clang-tidy not installed"; exit 0; }
command -v cmake >/dev/null 2>&1 || { echo "SKIP: cmake not installed"; exit 0; }
BUILD="$ROOT/build-tidy"
if [ ! -f "$BUILD/compile_commands.json" ]; then
    # ⚠️ /opt/openssl-3.5 is the CONTAINER path and does not exist on a Mac, so this
    # defaulted to an unusable root, the configure failed, and the suite SKIPPED silently
    # on the machine it says to run it on. Fall back to the Homebrew root when the
    # container one is absent, and let CMake search if neither is there.
    OSSL_ROOT="${OPENSSL_ROOT:-}"
    if [ -z "$OSSL_ROOT" ]; then
        for c in /opt/openssl-3.5 /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3; do
            [ -d "$c" ] && { OSSL_ROOT="$c"; break; }
        done
    fi
    cmake -S "$ROOT" -B "$BUILD" ${OSSL_ROOT:+-DOPENSSL_ROOT_DIR=$OSSL_ROOT} \
        -DFASTPKI_WITH_LDAP=ON -DCMAKE_EXPORT_COMPILE_COMMANDS=ON >/dev/null 2>&1 \
        || { echo "SKIP: could not configure a compile DB"; exit 0; }
fi
FILES=$(ls "$ROOT"/src/lib/*.cpp "$ROOT"/src/*/main.cpp "$ROOT"/src/tools/*.cpp 2>/dev/null | grep -v 'db_postgres')
OUT="$(mktemp)"
# clang-analyzer-* is path-sensitive (reliable); add bugprone checks that don't
# false-positive on early-return guards. (bugprone-unchecked-optional-access and
# the style/atoi checks are intentionally excluded — too noisy / not path-aware.)
CHECKS='-*,clang-analyzer-*,-clang-analyzer-optin.performance.*,bugprone-use-after-move,bugprone-dangling-handle,bugprone-string-constructor,bugprone-suspicious-memory-comparison,bugprone-misplaced-widening-cast,bugprone-integer-division'
# ⚠️ ONE PROCESS PER FILE, IN PARALLEL. clang-tidy analyses translation units one after another
# whatever the machine has, so a single invocation over every file used one core and took
# 13m32s on a 2-core lab runner — and on a 4-core GitHub-hosted runner, which is slower per
# core, it ran past the harness's 1200s SUITE_TIMEOUT and the gate failed with no output at
# all. The analysis is per translation unit and shares nothing between them, so it parallelises
# exactly.
#
# Each process writes its OWN file rather than appending to a shared one: concurrent appends
# interleave, and a finding split across two lines stops matching `warning:` — which would
# turn a real finding into a silent pass, the one failure this gate must not have.
JOBS=$(nproc 2>/dev/null || echo 4)
PARTS="$(mktemp -d)"
printf '%s\n' $FILES | xargs -P "$JOBS" -I{} sh -c '
    out="$4/$(basename "$3").tidy"
    clang-tidy -p "$1" --checks="$2" --header-filter="$5" "$3" > "$out" 2>/dev/null
' _ "$BUILD" "$CHECKS" {} "$PARTS" "$ROOT/include/pki/"
cat "$PARTS"/*.tidy > "$OUT" 2>/dev/null
rm -rf "$PARTS"
# ⚠️ THIRD-PARTY HEADERS ARE NOT OURS TO FIX, and --header-filter cannot exclude them: the
# analyzer reports them by the path it reached them through, and
# `include/pki/../../third_party/nlohmann/json.hpp` textually MATCHES a filter anchored on
# `include/pki/`. Four bugprone-use-after-move hits inside nlohmann/json.hpp arrive that way.
# The Dockerfile already takes this position for the same reason, building the three vendored
# PKCS#11 projects with -w: a wall of warnings nobody can act on is where a real one hides.
# Drop them by path, so what remains is FastPKI's own code and a finding here is actionable.
grep -vE 'third_party/' "$OUT" > "$OUT.own" && mv "$OUT.own" "$OUT"
N=$(grep -cE 'warning:|error:' "$OUT")
echo "=== clang-analyzer findings ==="
grep -E 'warning:|error:' "$OUT" | sed "s#$ROOT/##" | head -30 || echo "  (none)"
echo
echo "=== CLANG-TIDY: findings=$N ==="
[ "$N" -eq 0 ]
