#!/usr/bin/env bash
# A suite's LAST `trap … EXIT` must clean up everything its earlier traps promised.
#
# ── The bug this is about ────────────────────────────────────────────────────────
#
# Bash does not stack EXIT traps: a second `trap … EXIT` REPLACES the first. The house
# pattern is
#
#     pg_setup foo
#     trap 'pg_cleanup; kill $P 2>/dev/null' EXIT     # armed by pg_setup's caller
#     "$BIN" --config … & SRV=$!
#     trap 'kill $SRV 2>/dev/null' EXIT               # …and pg_cleanup is now GONE
#
# which is how 1329 leaked databases (11GB) accumulated before anyone looked — a leaked
# database breaks nothing until the disk fills. `pg_no_leak.sh` guards the DB half by
# proving the reaper catches it. This guards the CAUSE, for every resource: run over the
# suites and require the final trap to be a superset of the earlier ones.
#
# Ten suites were still dropping `pg_cleanup` when this was written, and one was dropping
# two process kills. They are not the same ten as last time — the pattern comes back
# whenever someone arms a trap after starting a daemon, which is the natural thing to do.
#
# ── Reading the output ───────────────────────────────────────────────────────────
#
# A `kill $X` is only counted when `X=$!` appears in the file: several suites carry a
# `kill $P` for a variable they never assign, and dropping a no-op is not a leak.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# pg_no_leak.sh clobbers its own trap ON PURPOSE — that is the scenario it exists to
# exhibit, and "fixing" it would delete the test. Named here with the reason, so the
# exemption is a decision rather than a hole.
EXEMPT="pg_no_leak.sh"

echo "=== every suite's final EXIT trap is a superset of its earlier ones ==="
# Same analysis in shell (§3e). For each suite with more than one EXIT trap, the LAST one
# must still cover everything the earlier ones did -- a later `trap` REPLACES the previous
# handler, so re-arming a narrower one silently drops a cleanup. A dropped `kill:$VAR` only
# counts when the suite actually backgrounds something into that variable (VAR=$!);
# otherwise the name is decoration and dropping it costs nothing.
trap_parts() {   # <trap body> -> one token per line
    printf '%s\n' "$1" | grep -q 'pg_cleanup' && echo 'pg_cleanup'
    printf '%s\n' "$1" | grep -oE 'kill[^;]*' | grep -oE '\$\{?[A-Za-z_][A-Za-z0-9_]*' \
        | sed -E 's/^\$\{?/kill:$/'
    return 0
}
REPORT=""
for f in "$ROOT"/tests/*.sh; do
    base=$(basename "$f")
    [ "$base" = "$EXEMPT" ] && continue
    # ⚠️ ALL THREE FORMS, NOT JUST THE SINGLE-QUOTED ONE. This matched only
    # `trap '...' EXIT`, so `trap cleanup EXIT` — a bare function name, which is the
    # commonest way a suite re-arms — was invisible. A suite whose second trap took that
    # form looked like it had only ONE trap, failed the `-ge 2` test, and was skipped
    # entirely: ms_kerberos.sh dropped pg_cleanup that way and leaked a database on every
    # run while this guard reported green over it.
    # ⚠️ AND A trap THAT IS NOT THE FIRST THING ON ITS LINE. All three patterns anchor on
    # `^[[:space:]]*trap`, so the house form for re-arming after backgrounding a daemon —
    #     sleep 1; trap 'kill $SRV 2>/dev/null' EXIT        # <- pg_cleanup dropped here
    # — was invisible. 106 of the files in tests/ carry a trap in that position, and a suite
    # whose SECOND trap took it looked like it had only one, failed the `-ge 2` gate below and
    # was skipped entirely. Three suites were dropping pg_cleanup exactly that way while this
    # guard reported green over them — acme_eab.sh, acme_orders.sh and acme_keychange.sh each
    # arm `pg_cleanup; kill $P` and then re-arm `kill $SRV` alone, leaking a database per run.
    # That is the failure this file exists for; it leaked 1329 databases once.
    #
    # Normalise first, so such a trap begins a line of its own. awk rather than sed: a newline
    # in a sed REPLACEMENT is a GNU extension, and this has to work on BSD sed and busybox too.
    norm=$(awk '{ gsub(/;[ \t]*trap[ \t]+/, "\ntrap "); print }' "$f" 2>/dev/null)
    bodies=$(printf '%s\n' "$norm" |
             sed -nE "s/^[[:space:]]*trap[[:space:]]+'([^']*)'[[:space:]]+EXIT.*/\1/p;
                      s/^[[:space:]]*trap[[:space:]]+\"([^\"]*)\"[[:space:]]+EXIT.*/\1/p;
                      s/^[[:space:]]*trap[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]+EXIT.*/\1/p" \
                     2>/dev/null)
    # A bare name is a FUNCTION; what it drops is decided by its body, not by its name.
    bodies=$(printf '%s\n' "$bodies" | while IFS= read -r b; do
        if printf '%s' "$b" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*$' \
           && grep -qE "^[[:space:]]*$b\(\)" "$f"; then
            sed -nE "/^[[:space:]]*$b\(\)/,/^[[:space:]]*\}/p" "$f" | tr '\n' ' '
        else
            printf '%s\n' "$b"
        fi
    done)
    [ "$(printf '%s\n' "$bodies" | grep -c .)" -ge 2 ] || continue
    last=$(printf '%s\n' "$bodies" | grep . | tail -1)
    earlier=$(printf '%s\n' "$bodies" | grep . | sed '$d')
    ep=$(printf '%s\n' "$earlier" | while IFS= read -r b; do [ -n "$b" ] && trap_parts "$b"; done | sort -u)
    lp=$(trap_parts "$last" | sort -u)
    real=""
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        printf '%s\n' "$lp" | grep -qxF "$d" && continue      # still covered
        if [ "$d" = "pg_cleanup" ]; then real="$real${real:+,}$d"; continue; fi
        var=$(printf '%s' "$d" | sed 's/^kill:\$//')
        grep -qE "\b${var}=\\\$!" "$f" && real="$real${real:+,}$d"
    done <<EOF
$ep
EOF
    [ -n "$real" ] && REPORT="$REPORT${REPORT:+; }$base drops $real"
done
chk "no suite's last trap drops an earlier cleanup" "" "$REPORT"

echo "=== the exemption is real and still needed ==="
# If pg_no_leak.sh ever stops clobbering its trap, the exemption above is dead weight and
# should go — an exemption nobody re-checks is how a hole opens.
chk "$EXEMPT still clobbers its trap on purpose" yes \
    "$(grep -q "trap 'pg_cleanup' EXIT" "$ROOT/tests/$EXEMPT" && \
       grep -q "trap 'true' EXIT" "$ROOT/tests/$EXEMPT" && echo yes || echo no)"

echo
echo "=== TRAP CLEANUP: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
