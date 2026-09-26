#!/usr/bin/env bash
# A schema step must not manage its own transaction, and schema-apply.sh's filter for the
# warnings that would cause must not be able to hide a real error.
#
# ⚠️ WHY THIS PAIR EXISTS. schema-apply.sh feeds every step to psql under
# --single-transaction, so a step that also writes BEGIN/COMMIT makes psql say:
#
#     WARNING:  there is already a transaction in progress     (the nested BEGIN)
#     WARNING:  there is no transaction in progress            (the wrapper's COMMIT)
#
# Cosmetic that reads like a fault, on every fresh install, reported as exactly that.
#
# ⚠️ AND IT IS NOT ALWAYS COSMETIC. The step's COMMIT ENDS THE WRAPPER'S TRANSACTION.
# Anything after it runs unprotected, and the apply failure message -- "the database is
# unchanged by this step (it ran in one transaction)" -- would then be false. So no step
# may manage its own transaction.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
STEPS="$ROOT/sql/steps"
APPLY="$ROOT/deploy/schema-apply.sh"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# Section 1 needs steps to scan; it must not report a pass over an empty set. Sections 3
# and 4 are about schema-apply.sh itself and hold either way.
if [ "$(ls "$STEPS"/[0-9]*.sql 2>/dev/null | wc -l | tr -d " ")" -gt 0 ]; then
  echo "=== 1. no step manages its own transaction ==="
  chk "PRECONDITION: there are step files to scan" yes \
      "$([ "$(ls "$STEPS"/[0-9]*.sql 2>/dev/null | wc -l | tr -d ' ')" -gt 0 ] && echo yes || echo no)"
  
  # Only a BEGIN/COMMIT that is a whole statement. `DO $$ ... BEGIN ... END $$;` opens no
  # transaction and appears at line start in many steps, so requiring the semicolon is what
  # separates a transaction control statement from a PL/pgSQL block body.
  FOUND=$(grep -liE '^[[:space:]]*(BEGIN|COMMIT)[[:space:]]*;' "$STEPS"/[0-9]*.sql 2>/dev/null \
          | sed 's#.*/##' | sort | tr '\n' ' ' | sed 's/ *$//')
  chk "no step contains a BEGIN; or COMMIT; statement" "" "$FOUND"
else
  chk "no step exists, so none can manage its own transaction" yes \
      "$([ ! -d "$STEPS" ] && echo yes || echo no)"
fi


echo "=== 3. the apply still wraps steps, and still filters only those two lines ==="
# ⚠️ ASSERT ON CODE, NOT ON PROSE. The comment at the call site quotes both warning texts
# verbatim, so grepping the file for them would match the explanation and pass forever.
# Everything below looks at non-comment lines only.
CODE=$(grep -vE '^[[:space:]]*#' "$APPLY")
chk "steps are still wrapped in one transaction" yes \
    "$(printf '%s\n' "$CODE" | grep -q -- '--single-transaction' && echo yes || echo no)"
chk "the stderr filter is defined" yes \
    "$(printf '%s\n' "$CODE" | grep -q '_step_stderr()' && echo yes || echo no)"
# Both paths: the failure branch and the success branch. One alone leaks the warnings on
# whichever path was missed, which is how a filter looks installed and is not.
CALLS=$(printf '%s\n' "$CODE" | grep -c '_step_stderr "')
chk "it is applied on both the failure and the success path" yes \
    "$([ "${CALLS:-0}" -ge 2 ] && echo yes || echo no)"

echo "=== 4. the filter matches what psql actually says ==="
# The pattern is only useful if it matches the real message. Feed both literal warnings
# through the script's own expression rather than restating it here.
PAT=$(printf '%s\n' "$CODE" | sed -n "s/.*grep -vE '\([^']*\)'.*/\1/p" | head -1)
chk "PRECONDITION: the filter expression was found in the script" yes \
    "$([ -n "$PAT" ] && echo yes || echo no)"
if [ -n "$PAT" ]; then
    for msg in "WARNING:  there is already a transaction in progress" \
               "WARNING:  there is no transaction in progress"; do
        chk "it matches: $msg" yes \
            "$(printf '%s\n' "$msg" | grep -qE "$PAT" && echo yes || echo no)"
    done
    # And nothing else. A real error must survive the filter.
    chk "a genuine error is NOT filtered" yes \
        "$(printf '%s\n' 'ERROR:  relation "certs" does not exist' | grep -qvE "$PAT" && echo yes || echo no)"
fi

echo "=== SCHEMA STEP TRANSACTIONS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ] || exit 1
