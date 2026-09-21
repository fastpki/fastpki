#!/usr/bin/env bash
# Every function the demo appears to define at column 0 must ACTUALLY be defined by the
# time the script starts working.
#
# ⚠️ THE DEFECT THIS GUARDS, MEASURED. server_key_show's closing brace was missing, so its
# body ran from its own first line all the way to the end of the last definition after it.
# ocsp_key_show and cmp_ra_key_show sat at column 0, looked top-level to every reader, and
# did not EXIST until server_key_show had been CALLED. Nothing noticed for as long as the
# only callers were the three show steps, which run one after another in the single order
# that defines each just before it is needed.
#
# It surfaced the moment a fourth function in that block was needed EARLIER, by the code
# that brings the stack up:
#
#     demo/pki-demo.sh: line 834: scep_ra_setup: command not found
#
# and the demo carried on to report "RA mode is not on" — a true statement whose cause it
# could not name. A definition whose availability depends on CALL ORDER is a landmine, and
# indentation hides it: the file reads as if everything is top-level.
#
# ⚠️ ASKED OF BASH, NOT OF A REGEX. Counting braces in shell text is guesswork — `${x}`,
# `$(...)`, case arms and quoted strings all carry them. FASTPKI_DEMO_DEFS_ONLY makes the
# demo print `declare -F` at the point where every definition has run and no work has
# started, so the answer comes from the same parser that will run it for real.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fi
       [ "$2" = "$3" ] || fail=$((fail+1)); }

# Names written at column 0 in the file, and names bash actually holds. The difference is
# the answer. Both lists come from the SAME file on every call, so the helper can be
# pointed at a planted file to prove it still reports.
#
# ⚠️ SCOPED TO WHAT THE HOOK CAN SEE, and this was a real false positive: the first cut
# compared EVERY column-0 name in the file and reported eight, all of which turned out to
# be defined BELOW the hook — perfectly top-level, just later. "Not yet defined" and
# "nested inside another function" are indistinguishable from the hook's vantage point, so
# only the names written above it are compared. Definitions after the hook are not covered
# here; the ones that exist are ACME helpers used only by the leg that defines them.
hook_line(){ grep -n 'FASTPKI_DEMO_DEFS_ONLY' "$1" | head -1 | cut -d: -f1; }
written_defs(){ awk -v n="$(hook_line "$1")" 'NR<n' "$1" \
                  | grep -oE '^[A-Za-z_][A-Za-z0-9_]*\(\)' | tr -d '()' | sort -u; }
# ⚠️ NO MODE FLAG. The first cut passed --throwaway, which pki-bench.sh rejects with
# "unknown option" and exits BEFORE the hook — so its list came back empty and all twelve
# of its functions read as swallowed. An empty answer from the instrument is not a finding
# about the file, which is why the count is asserted separately below.
real_defs(){    FASTPKI_DEMO_DEFS_ONLY=1 bash "$1" 2>/dev/null | sort -u; }
swallowed(){    comm -23 <(written_defs "$1") <(real_defs "$1") | tr '\n' ' ' | sed 's/ $//'; }

for d in pki-demo pki-bench; do
    F="$ROOT/demo/$d.sh"
    [ -f "$F" ] || continue
    echo "=== $d.sh ==="
    # ⚠️ ANTI-VACUITY FIRST. If the hook is absent or the demo dies before reaching it,
    # real_defs is empty and every name reads as swallowed — a loud failure, but for the
    # wrong reason. If the grep breaks, written_defs is empty and the check passes over
    # nothing, which is the dangerous direction. Both are named here.
    nw=$(written_defs "$F" | grep -c .)
    nr=$(real_defs   "$F" | grep -c .)
    chk "  it has the defs-only hook"                  yes "$([ -n "$(hook_line "$F")" ] && echo yes || echo no)"
    chk "  the file declares functions at column 0"   yes "$([ "$nw" -ge 10 ] && echo yes || echo no)"
    chk "  and the defs-only hook answers"            yes "$([ "$nr" -ge 10 ] && echo yes || echo no)"
    chk "no column-0 function is nested inside another" "" "$(swallowed "$F")"
done

echo "=== PRECONDITION: the check reports a planted nesting ==="
# The exact shape of the defect, small enough to read: beta sits at column 0 but inside
# alpha's body, so bash defines alpha and gamma and NOT beta. Same helper, same code path.
cat > "$W/synth.sh" <<'EOS'
alpha(){
  :
beta(){ :; }
}
gamma(){ :; }
if [ -n "${FASTPKI_DEMO_DEFS_ONLY:-}" ]; then declare -F | awk '{print $3}'; exit 0; fi
EOS
chk "  a nested definition is reported" "beta" "$(swallowed "$W/synth.sh")"
# And the same file with beta pulled out is clean, so the report above is about the
# NESTING and not about beta's name, its position, or the helper simply always firing.
printf 'alpha(){\n  :\n}\nbeta(){ :; }\ngamma(){ :; }\nif [ -n "${FASTPKI_DEMO_DEFS_ONLY:-}" ]; then declare -F | awk %s; exit 0; fi\n' "'{print \$3}'" > "$W/fixed.sh"
chk "  and the same file with it un-nested is clean" "" "$(swallowed "$W/fixed.sh")"

echo "=== DEMO FUNCTIONS TOP-LEVEL: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
