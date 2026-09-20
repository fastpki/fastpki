#!/usr/bin/env bash
# The demo target descriptor: one writer, one key set, and names the deployment approves.
#
# provision-target.sh has four modes — native over the console API, local docker compose,
# Kubernetes, and a remote deployment over SSH — and each used to end in its OWN
# `{ ... } > "$OUT"` block. They had drifted: the remote one emitted 15 keys where the
# local one emitted 17, missing CA_ID and DEMO_DOMAIN. CA_ID is not optional, so
# provisioning a real deployment produced a descriptor that could not drive either demo:
#
#   demo/pki-bench.sh: line 179: CA_ID: target file missing CA_ID
#
# and the script exited 0 having printed "✓ wrote". The remote block had also never picked
# up the checked write the local one carries, so a failed redirect left a stale descriptor
# in place and the demo then drove the wrong ports and the wrong CA.
#
# ⚠️ THE DRIFT IS THE DEFECT, NOT EITHER MISSING KEY. Adding CA_ID to the second writer
# would fix today's symptom and leave the mechanism intact. So this asserts the SHAPE:
# there is exactly one writer, both modes reach it, and every variable it reads is
# assigned in both modes' setup. A mode that forgets one would emit `SCEP_PATH=` — present,
# empty, and read by the demo as a path.
#
# It also covers the second half of the same failure. With a valid descriptor the bench
# still issued 0/N on every cell, because every CN it built was hardcoded under
# `.internal` while the deployment approved other domains. The refusal was correct; the
# table of zeroes read as a throughput result.
#
# Static analysis of two shell scripts, so it needs no deployment and no network.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
PT="$ROOT/demo/provision-target.sh"
BENCH="$ROOT/demo/pki-bench.sh"
DEMO="$ROOT/demo/pki-demo.sh"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

for f in "$PT" "$BENCH" "$DEMO"; do
    [ -r "$f" ] || { echo "SKIP: $f not readable"; echo "=== DEMO TARGET DESCRIPTOR: PASS=0 FAIL=0 ==="; exit 0; }
done

echo "== there is exactly ONE descriptor writer =="

# The redirect that creates the descriptor. Two of these is the bug.
# ⚠️ Strip comments first: the explanation above the writer quotes the very pattern this
# counts, so an uncommented grep counts its own prose and can never reach 1.
chk "provision-target.sh redirects to \$OUT in exactly one place" 1 \
    "$(grep -vE '^[[:space:]]*#' "$PT" | grep -c '} > "\$OUT"')"
# ...and it is inside the shared function, not in a mode branch.
chk "  and that redirect is inside emit_descriptor()" yes \
    "$(awk '/^emit_descriptor\(\) \{/{f=1} f&&/} > "\$OUT"/{print "yes"; exit}' "$PT")"
chk "the one provisioning path calls emit_descriptor" 1 \
    "$(grep -c '^ *emit_descriptor$' "$PT")"

echo "== every variable the writer reads is set by BOTH modes =="

# Derive the list from the writer itself rather than hardcoding it, so a key added
# tomorrow is covered on the day it lands. Only the port/path variables: TARGET_HOST,
# MODE_NOTE, CA_ID and DEMO_DOMAIN are asserted separately below.
sed -n '/^emit_descriptor() {/,/^}/p' "$PT" \
  | grep -oE '\$(EST|CMP|OCSP|STORE|SCEP|ACME)_[A-Z_]+' | tr -d '$' | sort -u > "$W/vars"
chk "the writer reads the twelve port/path variables" 12 "$(wc -l < "$W/vars" | tr -d ' ')"

# ⚠️ THE PORTS MOVED INTO discover_endpoints(), AND THIS TEST DID NOT FOLLOW. It used to
# slice "the local mode block" from `if [ "$MODE" = local ]` to its emit_descriptor and grep
# THAT for the twelve variables. When the k8s mode arrived the assignments were factored out
# into discover_endpoints() above, so the slice stopped containing any of them and this
# assertion failed on every run — reporting all twelve missing from a script that sets them
# all. It went unnoticed because the lab-amd64 runner was lost at about the same time.
#
# The shape worth asserting is per BRANCH, not per block: discover_endpoints has one branch
# per non-SSH mode, and a branch that forgets a variable is exactly the drift this file
# exists to catch. So slice the function into its branches and check each.
sed -n '/^discover_endpoints() {/,/^}/p' "$PT" > "$W/discover"
chk "discover_endpoints() was located" yes "$([ -s "$W/discover" ] && echo yes || echo no)"

# Each `return 0` ends a branch; the last branch runs to the closing brace.
awk '/^discover_endpoints\(\) \{/{next} {print}' "$W/discover" \
    | awk -v d="$W" 'BEGIN{n=1} {print > (d "/branch" n)} /return 0/{n++}'
BRANCHES=$(ls "$W"/branch* 2>/dev/null | wc -l | tr -d ' ')
chk "discover_endpoints has one branch per mode" 2 "$BRANCHES"

for b in "$W"/branch*; do
    missing=""
    while read -r v; do
        # `;`-separated on one line — EST_PORT=8443; EST_BASE_PATH=/... — so anchor on a
        # line start OR a separator, not on the line start alone.
        grep -qE "(^|[[:space:]]|;)$v=" "$b" || missing="$missing $v"
    done < "$W/vars"
    chk "$(basename "$b") assigns every one of them" "" "$missing"
done

# ⚠️ ONE PROVISIONING PATH NOW, so this no longer compares two. The SSH mode and --k8s are
# gone: the console API does what both did, and a descriptor is written in one place from one
# block. What is still worth pinning is that the block assigns EVERY variable the descriptor
# carries — the defect this suite was written for was a mode that quietly left some unset.
LOCAL_START=$(grep -n 'if \[ "\$MODE" = local \]' "$PT" | head -1 | cut -d: -f1)
LOCAL_END=$(awk -v s="$LOCAL_START" 'NR>s && /^ *emit_descriptor$/{print NR; exit}' "$PT")
sed -n "${LOCAL_START},${LOCAL_END}p" "$PT" > "$W/local"
chk "the provisioning block was located" yes "$([ -s "$W/local" ] && echo yes || echo no)"

# The two that were actually missing once, named explicitly so the regression is unmistakable.
chk "it establishes CA_ID"       yes \
    "$(grep -qE '(^|[^A-Z_])CA_ID=' "$W/local" && echo yes || echo no)"
chk "it establishes DEMO_DOMAIN" yes \
    "$(grep -qE '(^|[^A-Z_])DEMO_DOMAIN=' "$W/local" && echo yes || echo no)"

# ⚠️ AND THE REMOVED MODES STAY REMOVED, with a message rather than silence. A flag that is
# simply unrecognised reads as a typo; these two were documented for a long time and somebody
# will still type them.
chk "--k8s refuses and names the replacement" yes \
    "$(bash "$PT" --k8s 2>&1 | grep -q -- '--web-url' && echo yes || echo no)"
chk "a bare ssh target refuses and names the replacement" yes \
    "$(bash "$PT" admin@example.org 2>&1 | grep -q -- '--web-url' && echo yes || echo no)"

echo "== the write is checked in the one place it now happens =="

# A descriptor is the demo's whole idea of what it is talking to. A failed redirect that
# still reports success leaves a stale one, which is worse than none, because none stops.
W_BODY=$(sed -n '/^emit_descriptor() {/,/^}/p' "$PT")
chk "the redirect failure is fatal" yes \
    "$(printf '%s' "$W_BODY" | grep -q 'could not write' && echo yes || echo no)"
chk "an empty descriptor is fatal" yes \
    "$(printf '%s' "$W_BODY" | grep -q 'is empty after writing' && echo yes || echo no)"
chk "a failed chmod is fatal" yes \
    "$(printf '%s' "$W_BODY" | grep -q 'could not chmod' && echo yes || echo no)"
# An empty CA_ID= would pass pki-bench.sh's `${CA_ID:?}` and then build a URL with an
# empty path segment — a 404 halfway through instead of a clear refusal at startup.
chk "CA_ID is written only when discovered" yes \
    "$(printf '%s' "$W_BODY" | grep -q '\[ -n "\$CA_ID" \].*CA_ID=' && echo yes || echo no)"

echo "== the demos issue for a name the deployment approves =="

# provision-target.sh writes DEMO_DOMAIN for exactly this. pki-demo.sh honoured it and
# pki-bench.sh did not, so every bench cell against a live deployment reported 0/N.
for f in "$BENCH" "$DEMO"; do
    chk "$(basename "$f") defaults DEMO_DOMAIN" yes \
        "$(grep -q 'DEMO_DOMAIN="\${DEMO_DOMAIN:-internal}"' "$f" && echo yes || echo no)"
done

# Every enrolment CN the bench builds must follow it. Comments still discuss `.internal`,
# so strip them before judging or this matches its own explanation.
chk "pki-bench.sh hardcodes no .internal name in executable lines" 0 \
    "$(grep -vE '^[[:space:]]*#' "$BENCH" | grep -c '\.internal')"

# pki-demo.sh's enrolment names follow DEMO_DOMAIN. The ones it still pins are the ACME
# ones, and that is not the same defect: those names are served by the CoreDNS stub the
# demo starts for challenge validation, so the CN and the DNS zone have to agree and
# neither can move on its own. Assert the split rather than a blanket count, so a NEW
# hardcoded enrolment name is still caught.
#
# ⚠️ THE FLOOR, NOT A COUNT. Four was every enrolment name when this assertion was
# written; the key/hash matrix added sweeps whose probe/RA/client names are built the
# same way, so the honest property is "every non-ACME name moves with DEMO_DOMAIN",
# approximated as: at least one per protocol family, and ZERO pinned .internal names
# outside the ACME challenge set (asserted below).
_nd=$(grep -vE '^[[:space:]]*#' "$DEMO" | grep -c '\.\$DEMO_DOMAIN')
chk "pki-demo.sh builds its EST/CMP/SCEP/store names from DEMO_DOMAIN" yes \
    "$([ "${_nd:-0}" -ge 4 ] && echo yes || echo no)"
chk "  and every name it still pins is an ACME challenge name" 0 \
    "$(grep -vE '^[[:space:]]*#' "$DEMO" | grep '\.internal' | grep -cvE 'acme-demo|wild-demo|chal-demo|_acme-challenge|docker\.internal')"

# ⚠️ THE CLEANUP FILTER HAS TO MOVE WITH THE NAMES. It selects which certificates to
# revoke by CN; left on `.internal` it would match nothing, report "revoked 0/0", and
# leave every certificate of the run active until the next one hits the per-requester cap.
# A cleanup that targets the wrong object reports success and does nothing.
chk "the bench cleanup filter follows DEMO_DOMAIN" yes \
    "$(sed -n '/^revoke_bench_certs()/,/^}/p' "$BENCH" | grep -q 'DEMO_DOMAIN' && echo yes || echo no)"

echo "== both scripts still parse =="
for f in "$PT" "$BENCH" "$DEMO"; do
    chk "$(basename "$f") parses" ok "$(bash -n "$f" 2>/dev/null && echo ok || echo broken)"
done

echo "=== DEMO TARGET DESCRIPTOR: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
