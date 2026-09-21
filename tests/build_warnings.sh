#!/usr/bin/env bash
# ⚠️ BUILD WARNINGS ARE NOT IGNORED — uninitialized members, unused functions and the rest
# are defects, and the build must be clean.
#
# This had to be asked for twice, which is the part that matters: the warnings were visible
# on every build and nothing made them impossible to walk past. Fixing the five
# that existed would have earned a third reminder. This is the gate.
#
# CMakeLists already sets -Wall -Wextra -Wpedantic. This configures a THROWAWAY build tree
# and fails if the compiler says anything at all.
#
# ⚠️ Why a whole build rather than a grep: a warning is a fact about compilation, and the
# only instrument that reports it is a compiler. It is slow (~minutes) for the same reason
# cppcheck.sh is, and it is worth it — one of the five warnings this closed was
# `missing field 'groups' initializer` in cmp/scep/acme, which was not cosmetic at all: it
# marked the enrolment gate ignoring a user's directory groups, the same defect already
# filed three separate times. The compiler had been reporting it all along.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

command -v cmake >/dev/null 2>&1 || { echo "SKIP: no cmake"; echo "PASS=0 FAIL=0"; exit 0; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

# The warning flags must actually be ON — a zero-warning build proves nothing if nothing
# is being asked. Checked against the source of truth rather than assumed.
chk "the build asks for warnings (-Wall -Wextra)" yes \
    "$(grep -q -- '-Wall' "$ROOT/CMakeLists.txt" && grep -q -- '-Wextra' "$ROOT/CMakeLists.txt" \
       && echo yes || echo no)"

# ⚠️ AND THAT NOBODY QUIETLY TURNED THEM BACK OFF. A `-Wno-` is how a warning gate stops
# meaning anything: the count below goes to zero and reads as "clean". Two exist on
# purpose and both are pinned here by name, so a third has to be argued for rather than
# absorbed — `-Wno-unused-parameter` tree-wide (an unused parameter is routine in an
# interface implementation), and `-Wno-deprecated-declarations` on the LDAP file, which
# macOS deprecates wholesale in favour of its own framework and Linux does not deprecate
# at all. Listed sorted and compared as one string: a NEW suppression fails this even if
# it is added next to an existing one.
# ⚠️ STRIP COMMENTS FIRST. This scan reads the build file as text, and the build file
# ARGUES about suppressions in prose -- the note by the third_party include explains why a
# `-Wno-` would have been the wrong instrument there. Grepping the prose reported that
# very flag as though someone had enabled it, so the guard failed on an explanation of why
# the thing it guards against was NOT done. A comment is not a compiler flag.
SUPPRESSIONS=$(sed 's/#.*//' "$ROOT/CMakeLists.txt" | grep -o '\-Wno-[a-z-]*' | sort -u | tr '\n' ' ')
chk "the only warning suppressions are the two argued for" \
    "-Wno-deprecated-declarations -Wno-unused-parameter " "$SUPPRESSIONS"
# The LDAP one must stay scoped to ONE file and to Apple. A per-file property that grew a
# second file, or lost its platform guard, would silence a platform that has no such
# deprecation — the shape where an exemption written for one host applies everywhere.
chk "  the LDAP suppression is per-file, not tree-wide" 1 \
    "$(grep -c 'set_source_files_properties(src/lib/ldap_auth.cpp' "$ROOT/CMakeLists.txt" | tr -d ' ')"
chk "  and it is guarded on Apple" yes \
    "$(awk '/^    if\(APPLE\)/{a=1} a&&/ldap_auth\.cpp/{print "yes"; exit}' "$ROOT/CMakeLists.txt" | head -1)"

# ⚠️ ONE GNU-ONLY DIAGNOSTIC IS CHEAP TO CHECK LEXICALLY, AND THIS HOST CANNOT SEE IT.
#
# A `//` comment ending in a backslash CONTINUES onto the next line -- which is how code
# gets commented out by accident -- and GCC's -Wcomment says so. clang does not, so it
# reached the shipped build unseen, in a usage block where the backslash was deliberate
# shell line-continuation.
#
# Grepping is the wrong instrument for "is this build warning-free"; the compiler is, which
# is why the rest of this file runs one. But this particular rule is LEXICAL -- no
# preprocessing, no types, no configuration -- so a scan answers exactly what the compiler
# would, and answers it on the developer machine instead of three hours later in an image.
# ⚠️ find + -exec, NOT `grep --include`. busybox grep does not implement --include and
# answers NOTHING, so in the shipped image this scan would report a clean tree no matter
# what was in it -- the exact vacuum tests/suite_exit_honest.sh exists to catch, and which
# it caught here.
BSLASH=$(find "$ROOT/src" "$ROOT/include" \
              \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) \
              -exec grep -n '^[[:space:]]*//.*\\$' {} + 2>/dev/null | cut -d: -f1,2 | tr '\n' ' ')
chk "no // comment continues onto the next line with a backslash" "" "$BSLASH"

# ⚠️ A THROWAWAY TREE CONFIGURED FROM SCRATCH IS NOT THE TREE THAT GETS BUILT, and a clean
# result from the wrong configuration is worse than no result. Measured while writing this:
# a bare `cmake -S . -B <tmp>` reported ZERO warnings while the developer's own `build/`
# reported three — that tree was configured WITH xmlsec and so compiled src/lib/xml.cpp
# against a different libxml2. Same shape as `build/` being unable to compile the LDAP
# branch at all, and the reason this file exists is that nobody was looking.
#
# So the measurement runs in the CONFIGURED TREE, replaying its own cache, and forces a
# full recompile — an incremental build says nothing about files it did not touch, which
# for a "are we warning-free?" question is the whole population.
BT=""
for cand in "$ROOT/build" "$ROOT/build-ldap"; do
    [ -f "$cand/CMakeCache.txt" ] && { BT="$cand"; break; }
done
if [ -z "$BT" ]; then
    echo "SKIP: no configured build tree to measure (run cmake -S . -B build first)"
    echo "PASS=$pass FAIL=$fail"
    [ "$fail" -eq 0 ]; exit $?
fi
echo "  [note] measuring $(basename "$BT"), which is the tree this machine actually builds"
# ⚠️ SAY WHICH COMPILER ANSWERED, because the answer is only about that one.
#
# The image ships a GCC build, and several diagnostics are GNU-only --
# -Wmisleading-indentation and -Wtype-limits among them, which is exactly the pair that
# came back after this gate had been passing. A clang host reports neither, so "0 warnings"
# here is a narrower claim than it looks, and nothing on screen said so.
#
# It is a note rather than a failure: refusing to run without GCC would make this gate skip
# on every developer Mac, and a skip is the thing that reads as "not my problem". Naming
# the compiler puts the limit of the measurement next to the measurement.
_CXX=$(sed -n 's/^CMAKE_CXX_COMPILER:[^=]*=//p' "$BT/CMakeCache.txt" 2>/dev/null | head -1)
_CXXV=$("$_CXX" --version 2>/dev/null | head -1)
case "$_CXXV" in
    *GCC*|*Free\ Software\ Foundation*) echo "  [note] compiler: $_CXXV — the family the image ships";;
    *) echo "  [note] compiler: ${_CXXV:-unknown} — NOT the GCC the image ships, so GNU-only"
       echo "         diagnostics (-Wmisleading-indentation, -Wtype-limits) are not covered here";;
esac
echo "  [note] optional components: $(grep -E '^FASTPKI_[A-Z_]*:BOOL=ON' "$BT/CMakeCache.txt" 2>/dev/null | sed 's/:BOOL=ON//' | tr '\n' ' ')"

# --clean-first rebuilds every object in the tree. It costs minutes, for the same reason
# cppcheck.sh does, and it is the only way the answer covers more than today's edits.
#
# ⚠️ PARALLELISM IS CAPPED BY MEMORY, NOT BY CORE COUNT ALONE. `-j$(nproc)` assumes a core
# brings its own RAM with it, and a CI runner is where that is least true. Measured: the lab
# runner was rebuilt with 4 cores and the same 4 GB it had with 2, so this went from -j2 to
# -j4, and the clean rebuild of a tree containing a 17.5k-line translation unit was
# OOM-killed — taking the GitHub runner process down with it (`Failed with result
# 'oom-kill'`), so the job died as "exit code 137" and a lost runner rather than as anything
# naming memory.
#
# ~1.5 GB per job is what the widest translation units here actually want. MemAvailable is
# the right number to divide (it counts reclaimable cache, unlike MemFree); where it cannot
# be read — macOS, a kernel without /proc — this falls back to the core count as before.
_jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
if [ -r /proc/meminfo ]; then
    _avail_mb=$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)
    if [ -n "${_avail_mb:-}" ] && [ "$_avail_mb" -gt 0 ]; then
        _memjobs=$((_avail_mb / 1536))
        [ "$_memjobs" -lt 1 ] && _memjobs=1
        [ "$_memjobs" -lt "$_jobs" ] && _jobs=$_memjobs
    fi
fi
echo "  [note] building with -j$_jobs"
cmake --build "$BT" --clean-first -j"$_jobs" >"$W/build.log" 2>&1
BUILD_RC=$?
chk "the tree builds" 0 "$BUILD_RC"

# ⚠️ NOT `grep -c … || echo 0`: grep -c PRINTS 0 and also EXITS 1 when there is no match,
# so the fallback fires too and the variable becomes "0\n0" — which then fails the numeric
# test and reports a warning-free build as broken. It did exactly that here.
N=$(grep -c "warning:" "$W/build.log" 2>/dev/null); N=${N:-0}
chk "the build emits ZERO compiler warnings" 0 "$N"
# What was actually compiled, so a green result can be read for what it covers.
echo "  [note] $(grep -c 'Building CXX object' "$W/build.log" 2>/dev/null) translation units compiled"
if [ "${N:-0}" -ne 0 ]; then
    echo "  --- warnings ---"
    grep "warning:" "$W/build.log" | sed "s|$ROOT/||" | sort -u | head -40 | sed 's/^/    /'
    echo "  ⚠️ Read each one before silencing it. A 'missing field initializer' is how"
    echo "     all three were visible in the compiler output for months."
fi

echo
echo "=== BUILD WARNINGS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
