#!/usr/bin/env bash
# A schema step must not manage its own transaction, and the filter that hides the
# fallout from the ones that already do must not be able to hide a new one.
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
# unchanged by this step (it ran in one transaction)" -- would then be false. That is
# survivable today only because COMMIT is the LAST statement in all of the steps that do
# it, which is section 2 below, asserted rather than assumed.
#
# A shipped step is immutable: editing one is a no-op against exactly the databases it
# targets, so the existing offenders cannot be repaired and are grandfathered BY NAME. A
# sixth goes red here rather than joining them silently.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
STEPS="$ROOT/sql/steps"
APPLY="$ROOT/deploy/schema-apply.sh"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# The steps that predate this guard. NOT a shield: section 2 holds each of them to the
# property that makes the filter safe, so being on this list is not a free pass.
GRANDFATHERED="0033-qualify-directory-subjects.sql 0035-provider-domain-names.sql 0036-saml-oidc-provider-tables.sql 0037-saml-provider-local-user-and-skew.sql 0038-per-directory-keytab.sql"

# ⚠️ SECTIONS 1 AND 2 ONLY MEAN SOMETHING WHILE STEPS EXIST. The 39 steps were
# collapsed into sql/createdb.sql — they only ever applied to a database that already
# existed, and there are none. Guarded rather than deleted, because the rule returns
# with the next step; and stated rather than skipped, because a section that passes
# over an empty set is how a guard stops guarding. Sections 3 and 4 are about
# schema-apply.sh itself and hold either way.
if [ "$(ls "$STEPS"/[0-9]*.sql 2>/dev/null | wc -l | tr -d " ")" -gt 0 ]; then
  echo "=== 1. no NEW step manages its own transaction ==="
  chk "PRECONDITION: there are step files to scan" yes \
      "$([ "$(ls "$STEPS"/[0-9]*.sql 2>/dev/null | wc -l | tr -d ' ')" -gt 0 ] && echo yes || echo no)"
  
  # Only a BEGIN/COMMIT that is a whole statement. `DO $$ ... BEGIN ... END $$;` opens no
  # transaction and appears at line start in many steps, so requiring the semicolon is what
  # separates a transaction control statement from a PL/pgSQL block body.
  FOUND=$(grep -liE '^[[:space:]]*(BEGIN|COMMIT)[[:space:]]*;' "$STEPS"/[0-9]*.sql 2>/dev/null \
          | sed 's#.*/##' | sort | tr '\n' ' ' | sed 's/ *$//')
  WANT=$(printf '%s\n' $GRANDFATHERED | sort | tr '\n' ' ' | sed 's/ *$//')
  chk "the set of steps using BEGIN/COMMIT is exactly the grandfathered list" "$WANT" "$FOUND"
  
  echo "=== 2. in every such step, COMMIT is the LAST statement ==="
  # This is the whole reason the warnings are only cosmetic. A step that commits early and
  # then keeps going has silently left the wrapper's transaction, and schema-apply.sh would
  # report a failure there as "the database is unchanged", which would not be true.
  for b in $GRANDFATHERED; do
      f="$STEPS/$b"
      if [ ! -f "$f" ]; then chk "$b exists to be checked" yes no; continue; fi
      last=$(grep -vE '^[[:space:]]*(--|$)' "$f" | tail -1 | tr -d ' \t')
      chk "$b: COMMIT is its final statement" "COMMIT;" "$last"
  done
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
