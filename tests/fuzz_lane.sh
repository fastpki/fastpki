#!/usr/bin/env bash
# The fuzz harnesses must BUILD AND RUN, not just exist.
#
# ⚠️ WHY THIS EXISTS. fuzz/fuzz_jws.cpp and fuzz/fuzz_cmp_asn1.cpp were committed
# complete — good harnesses, careful comments — and then nothing ever compiled them:
# no CMake target, no CI lane, no test. That is the same shape as a reader with no
# writer: the artifact is present, the intent is documented, and the thing does not
# happen. Worse than absent, because it reads as covered.
#
# So this asserts the two properties that make a harness real:
#   1. it still COMPILES against today's headers (a harness silently rots when the
#      API it calls changes — parse_cmp_request's signature, jws::parse's return);
#   2. it RUNS on real input without crashing, hanging or tripping ASan/UBSan.
#
# By default it is deliberately short (a fixed 2000 runs each): a build-and-liveness gate
# for every suite run. `FUZZ_SECONDS=900` turns it into a real campaign, and
# `FUZZ_CORPUS_DIR=<dir>` makes that campaign compound instead of restarting from the
# committed seeds. Any crash becomes its own regression test with the reproducer committed
# under fuzz/corpus/.
#
# ⚠️ This is the ONLY fuzz entry point. tests/fuzz.sh used to sit beside it, compiling its
# own binaries — which was the one thing it did that this could not, and the reason it
# survived. It covered two of the three harnesses, ran with detect_leaks=0, and asserted
# nothing about whether the fuzzer had actually executed. Its campaign mode and persistent
# corpus are folded in here; the rest went with it.
#
# SKIPs cleanly where clang is absent (§3d), because libFuzzer is clang-only and the
# GCC/Alpine build must stay unaffected.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
skipout(){ echo "  [SKIP] $1"; echo; echo "PASS=$pass FAIL=$fail"; exit 0; }

CLANGXX=$(command -v clang++ 2>/dev/null || true)
[ -n "$CLANGXX" ] || skipout "no clang++ — libFuzzer is clang-only, GCC builds are unaffected"

# Does this clang actually have libFuzzer? Apple's clang ships it; some distro
# packages split it out. Judged by compiling a stub, not by the version string.
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
cat > "$W/probe.cc" <<'EOF'
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t*, size_t) { return 0; }
EOF
if ! "$CLANGXX" -fsanitize=fuzzer "$W/probe.cc" -o "$W/probe" >/dev/null 2>&1; then
    skipout "clang++ has no libFuzzer runtime (-fsanitize=fuzzer does not link)"
fi

# ⚠️ DISCOVERED FROM fuzz/, NEVER A HARDCODED LIST. Three separate lists in this file
# named the same three harnesses, so a NEW harness was compiled by nobody and run by
# nobody: fuzz_cmc.cpp and fuzz_ms_template.cpp were added, built cleanly, and this gate
# still reported three green harnesses without ever touching them. A list that has to be
# updated by hand is the same failure this file's own header describes — a harness that
# exists and is never run — one level up, in the thing meant to catch it.
HARNESSES=""
for _h in "$ROOT"/fuzz/fuzz_*.cpp; do
    [ -e "$_h" ] || continue
    _b=$(basename "$_h" .cpp)
    HARNESSES="$HARNESSES ${_b#fuzz_}"
done
chk "PRECONDITION: at least one harness was discovered" yes \
    "$([ -n "$(echo $HARNESSES | tr -d ' ')" ] && echo yes || echo no)"
echo "  harnesses: $HARNESSES"

echo "=== the harnesses still compile against today's headers ==="
# Compile-only, against the real headers. This is the half that catches API drift,
# and it does not need the whole library to link.
for f in $HARNESSES; do
    out=$("$CLANGXX" -std=c++20 -fsyntax-only -I"$ROOT/include" -I"$ROOT/third_party" \
          "$ROOT/fuzz/fuzz_$f.cpp" 2>&1)
    rc=$?
    chk "fuzz_$f.cpp compiles" 0 "$rc"
    [ "$rc" -eq 0 ] || echo "$out" | head -4
done

# Linking needs pki_lib, which needs the full dependency set (OpenSSL, libpq, ...).
# Building that here would make this suite a second build system; instead, use the
# tree's own build if it is configured with FASTPKI_FUZZ, and otherwise say so.
echo "=== and they RUN on input without crashing ==="
# ⚠️ REUSE A TREE ONLY IF IT HAS EVERY HARNESS, not just one of them. This probed for
# fuzz_jws alone, so a tree built before a new harness existed looked complete: the build
# below was skipped and the new harness was reported missing rather than built. Same class
# of bug as the hardcoded list above — an assumption that the set never grows.
BIN=""
for d in "$ROOT/build-fuzz" "$ROOT/build"; do
    _all=yes
    for f in $HARNESSES; do [ -x "$d/fuzz_$f" ] || { _all=no; break; }; done
    [ "$_all" = yes ] && { BIN="$d"; break; }
done
if [ -z "$BIN" ]; then
    # ⚠️ This used to SKIP here, and that is the single reason tests/fuzz.sh had to exist
    # alongside it: on an ordinary `cmake -S . -B build` checkout — the documented build —
    # the run half never executed and the lane degraded to three
    # -fsyntax-only checks while still reporting PASS. A gate that silently stops gating on
    # every normal checkout is the exact failure this is about. So BUILD them.
    echo "  [info] no fuzz build tree — configuring one (this is the first run here)"
    if cmake -S "$ROOT" -B "$ROOT/build-fuzz" -DFASTPKI_FUZZ=ON \
             -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ >"$W/cmake.log" 2>&1 &&
       cmake --build "$ROOT/build-fuzz" --target $(for f in $HARNESSES; do printf "fuzz_%s " "$f"; done) \
             -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" >>"$W/cmake.log" 2>&1; then
        BIN="$ROOT/build-fuzz"
    else
        # Only a genuine toolchain gap skips — and it says so with the compiler's own words
        # rather than a generic message that could mean anything.
        tail -5 "$W/cmake.log" | sed 's/^/         /'
        skipout "could not build the fuzzers with $CLANGXX (see the compiler output above)"
    fi
fi

# ⚠️ Leak detection is ON here, and getting it back took attributing the leak.
#
# This block used to export `detect_leaks=0` wholesale, on the reasoning that both
# harnesses report a LeakSanitizer hit "at exit on EVERY input ... a one-time
# static-initialiser allocation made before main(), not a parser bug". The first half was
# right and the conclusion was a guess: symbolizing the stack shows the 56 bytes are
# allocated by libFuzzer's OWN driver, inside main —
#
#     operator new -> fuzzer::FuzzerDriver(...) FuzzerDriver.cpp:832 -> main
#
# so it is neither ours nor a static initialiser. The cost of the blanket switch was that
# this lane ran with NO leak detection on the parsers at all — a leak in jws.cpp or
# cmp_asn1.cpp would have sailed through.
#
# fuzz/lsan_suppressions.h now suppresses that one frame and nothing else, so LSan is
# back on for everything we actually wrote. It needs llvm-symbolizer present to match
# (the Dockerfile installs `llvm` for exactly this); without one the suppression silently
# misses and the harness aborts after ~3 executions, which is what the execution floor
# below exists to catch.

for f in $HARNESSES; do
    [ -x "$BIN/fuzz_$f" ] || { chk "fuzz_$f binary present" yes no; continue; }
    # -runs bounded, not -max_total_time: a fixed amount of WORK is reproducible
    # across machines, where a fixed amount of TIME makes a slow box do less and a
    # fast one do more, and the assertion silently means something different on each.
    # Start from the committed corpus so the run begins PAST the parser's entry gate.
    # cmp_asn1 cannot be reached without it: parse_cmp_request() returns immediately
    # unless the input decodes as a whole PKIMessage (nested SEQUENCE, pvno INTEGER,
    # sender + recipient GeneralName, body), and random mutation does not stumble onto
    # that — measured at 0 crossings in 600,000 random inputs and 0 new coverage in
    # 188,000,000 real fuzzer executions.
    # ⚠️ NAMED EXPLICITLY, AND THE FALLBACK SEEDS NOTHING. This used to end in
    # `*) SEEDC=.../jws`, so every harness that was not cmp_asn1 or ms_xml started from the
    # JWS corpus — JSON blobs fed to a DER parser. That is worse than an empty corpus: the
    # fuzzer spends its first minutes proving that JSON is not ASN.1, and the seeds it keeps
    # are all rejects. Measured on fuzz_cmc: coverage 54 with a JWS seed, because almost
    # nothing got past d2i_CMS_ContentInfo. A wrong seed looks exactly like a working one.
    case "$f" in
        jws)         SEEDC="$ROOT/fuzz/corpus/jws" ;;
        cmp_asn1)    SEEDC="$ROOT/fuzz/corpus/cmp" ;;
        ms_xml)      SEEDC="$ROOT/fuzz/corpus/msxml" ;;
        cmc)         SEEDC="$ROOT/fuzz/corpus/cmc" ;;
        ms_template) SEEDC="$ROOT/fuzz/corpus/mstemplate" ;;
        attest)      SEEDC="$ROOT/fuzz/corpus/attest" ;;
        *)           SEEDC="" ;;   # no seed beats the wrong seed
    esac
    # Campaign mode, folded in from the retired tests/fuzz.sh: FUZZ_SECONDS asks for a
    # time-bounded soak instead of the fixed work the gate uses. FUZZ_CORPUS_DIR keeps what
    # the campaign finds interesting, which is the difference between a soak that compounds
    # across runs and one that starts from the committed seeds every time.
    CORP="$W/corp_$f"
    [ -n "${FUZZ_CORPUS_DIR:-}" ] && CORP="$FUZZ_CORPUS_DIR/$f"
    mkdir -p "$CORP"; [ -d "$SEEDC" ] && cp "$SEEDC"/* "$CORP/" 2>/dev/null
    ART="$W/"; [ -n "${FUZZ_CORPUS_DIR:-}" ] && { mkdir -p "$FUZZ_CORPUS_DIR/crashes"; ART="$FUZZ_CORPUS_DIR/crashes/"; }
    if [ -n "${FUZZ_SECONDS:-}" ]; then
        BOUND="-max_total_time=$FUZZ_SECONDS"; WHAT="${FUZZ_SECONDS}s"
    else
        # -runs bounded by default: a fixed amount of WORK is reproducible across machines,
        # where a fixed amount of TIME makes a slow box do less and a fast one do more, and
        # the assertion silently means something different on each.
        BOUND="-runs=2000 -seed=1"; WHAT="2000 runs"
    fi
    ( cd "$W" && "$BIN/fuzz_$f" $BOUND -timeout=10 -rss_limit_mb=2048 \
        -print_final_stats=1 -artifact_prefix="$ART$f-" "$CORP" ) >"$W/$f.log" 2>&1
    rc=$?
    chk "fuzz_$f survives $WHAT (no crash / ASan / UBSan)" 0 "$rc"

    # ⚠️ COVERAGE FLOOR. "no crash" from a fuzzer that never entered the function is
    # worth nothing, and that is not hypothetical: FASTPKI_FUZZ put -fsanitize on the
    # fuzz_* executables only, while the parsers live in pki_lib and were built with
    # no instrumentation at all — so libFuzzer saw the harness and nothing else, and a
    # 900-second campaign reported "clean" while watching almost none of the code.
    # libFuzzer prints "cov: N"; if N is tiny the run proves nothing, so fail loudly
    # rather than pass silently.
    COV=$(sed -n 's/.*cov: \([0-9][0-9]*\).*/\1/p' "$W/$f.log" | tail -1)
    chk "  and actually COVERS the parser (cov > 50, got ${COV:-0})" yes \
        "$([ "${COV:-0}" -gt 50 ] 2>/dev/null && echo yes || echo no)"

    # ⚠️ EXECUTION FLOOR — the same lesson one level down. We asked for -runs=2000, so
    # anything far below that means the fuzzer stopped early for a reason the exit code
    # did not carry. It is not hypothetical either: LeakSanitizer treats a leak found
    # while reading the seed corpus as fatal, and libFuzzer's OWN driver leaks 56 bytes,
    # so on Linux this harness ran FOUR executions of a 900-second campaign and still
    # printed "crashes: 0". Suppressed now — in fuzz/lsan_suppressions.h, matched
    # on libFuzzer's frame alone so real leaks are still caught — but the suppression
    # needs llvm-symbolizer to match, so it can silently stop working. This assertion is
    # what notices when it does.
    RUNS=$(sed -n 's/.*number_of_executed_units: *\([0-9][0-9]*\).*/\1/p' "$W/$f.log" | tail -1)
    [ -n "$RUNS" ] || RUNS=$(sed -n 's/^#\([0-9][0-9]*\).*DONE.*/\1/p' "$W/$f.log" | tail -1)
    # In campaign mode the ask is a DURATION, so "1000 of the 2000" is meaningless — but
    # the floor still matters, because the failure it catches (a fatal leak in the seed
    # corpus aborting after ~4 executions) looks identical either way. Scale it: any real
    # campaign clears 1000 executions in seconds.
    if [ -n "${FUZZ_SECONDS:-}" ]; then
        chk "  and actually RAN the inputs (campaign, got ${RUNS:-0})" yes \
            "$([ "${RUNS:-0}" -ge 1000 ] 2>/dev/null && echo yes || echo no)"
    else
        chk "  and actually RAN the inputs (>= 1000 of the 2000 asked for, got ${RUNS:-0})" yes \
            "$([ "${RUNS:-0}" -ge 1000 ] 2>/dev/null && echo yes || echo no)"
    fi
    if [ "$rc" -ne 0 ]; then
        echo "    --- last lines ---"; tail -12 "$W/$f.log" | sed 's/^/    /'
        # libFuzzer writes the reproducer into CWD; surface it, it IS the bug report.
        for c in "$W"/crash-* "$W"/leak-* "$W"/timeout-* "$W"/oom-*; do
            [ -e "$c" ] || continue
            cp "$c" "$ROOT/fuzz/" 2>/dev/null && \
                echo "    reproducer saved to fuzz/$(basename "$c") — commit it as the regression case"
        done
    fi
done

echo "=== every hand-rolled ASN.1 walker has a harness ==="
# ⚠️ THIS IS THE HALF THAT CATCHES A PARSER NOBODY FUZZED. Everything above asserts that
# the harnesses which EXIST still work, which by construction cannot notice a parser that
# never got one. That is not hypothetical: pki::cmc_extract_pkcs10 — a DER walker reached
# by every Windows enrolment — shipped with no coverage and nothing in the tree objected,
# because the only fuzz gate was checking the harnesses rather than the parsers.
#
# ⚠️ NOT AN EXEMPTION LIST. A file that hand-walks ASN.1 either has a harness or this fails.
# Adding "known gaps" here would turn the census into a record of what is not covered,
# which is how the coverage stops moving.
#
# The signal is ASN1_get_object: OpenSSL's d2i_* parsers are extensively fuzzed upstream
# and are not the risk — a hand-written walk over attacker-shaped tags and lengths is.
# The map says which harness reaches which file; a file with no entry fails, which is
# exactly what should happen when a new parser lands.
_uncovered=""
for src in $(cd "$ROOT" && grep -rl "ASN1_get_object" src/ 2>/dev/null | sort); do
    case "$src" in
        src/lib/cmc.cpp)                 want=cmc ;;
        src/lib/cmp_asn1.cpp)            want=cmp_asn1 ;;
        src/lib/ms_template_policy.cpp)  want=ms_template ;;
        # ⚠️ The CMP test client is a TEST TOOL and is named WITHOUT the fastpki- prefix so
        # the image's `COPY /src/build/fastpki-*` glob cannot pick it up. It never runs
        # against anything but our own server in a suite, parsing what our own code just
        # emitted, so it has no business in a production image.
        src/cmp/client.cpp)              want=- ;;
        *)                               want="" ;;
    esac
    [ "$want" = "-" ] && continue
    if [ -z "$want" ] || ! echo " $HARNESSES " | grep -q " $want "; then
        _uncovered="$_uncovered $src"
    fi
done
chk "no hand-rolled ASN.1 parser is without a fuzz harness" "" "$_uncovered"

echo
echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] || echo "RESULT: FAIL"
exit 0
