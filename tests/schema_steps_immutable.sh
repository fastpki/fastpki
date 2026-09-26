#!/usr/bin/env bash
# `sql/createdb.sql` IS the schema, it must agree with the binary, and a shipped step is
# immutable.
#
# ⚠️ THE DEFECT THIS EXISTS FOR, measured on a live node. Two columns were added to
# `saml_providers` by editing a step that had ALREADY been applied. `schema-apply.sh`
# records each step's version and never re-runs it, so the edit was a no-op against every
# database that had run it — the file claimed the columns existed and the database did not
# have them. The console answered
#
#     list_saml_providers: ERROR: column s.require_local_user does not exist
#
# while the SAME code passed the entire local suite, because a test database is built from
# `createdb.sql` and is therefore born current. That asymmetry is the whole trap: editing a
# step is invisible to exactly the databases the step was written to change, and it is
# invisible to every test that does not start from an old database.
#
# ⚠️ AND THE STEPS ARE GONE — DELIBERATELY, AS A BASELINE RESET. The schema reached 39
# through 39 incremental steps, every one of which existed to carry an ALREADY-DEPLOYED
# database forward. There are none: createdb.sql has always been born current, and
# schema-apply.sh skips every step whose number is not greater than the version createdb
# seeds, so on a fresh install those 39 files never executed once. They were inert for
# every install anyone could do while carrying the schema's whole private history into a
# public release. Collapsed to one baseline; the next real schema change starts at 0002.
#
# So section 1 runs ALWAYS and is the one that matters now: createdb.sql is the only
# definition of the schema, so it must be declarative and it must tell the startup guard
# the truth. Sections 2 and 3 stay armed for the step that comes back.
#
# Pure file checks — no database, no build. Runs anywhere.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
STEPS="$ROOT/sql/steps"
MANIFEST="$STEPS/CHECKSUMS"
CREATEDB="$ROOT/sql/createdb.sql"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

NEED=$(grep -oE 'kSchemaVersion = [0-9]+' "$ROOT/include/pki/schema.hpp" | grep -oE '[0-9]+')

echo "=== 1. createdb.sql is the schema, and it agrees with the binary ==="
chk "PRECONDITION: createdb.sql exists" yes "$([ -s "$CREATEDB" ] && echo yes || echo no)"
chk "PRECONDITION: kSchemaVersion was read" yes "$([ -n "$NEED" ] && echo yes || echo no)"

# ⚠️ A FRESH DATABASE NEVER RUNS A STEP, so the version createdb.sql seeds is the ONLY
# thing telling the startup guard the schema is current. Left behind, every NEW deployment
# refuses to start with a message telling the operator to run a migration that does not
# apply to them — and that is the failure an install hits, not one an upgrade hits.
FRESH=$(grep -A1 'insert into schema_version(version, name, applied)' "$CREATEDB" \
          | grep -oE 'values *\( *[0-9]+' | grep -oE '[0-9]+' | tail -1)
chk "createdb.sql seeds a version" yes "$([ -n "$FRESH" ] && echo yes || echo no)"
chk "  and it is exactly kSchemaVersion" "$NEED" "$FRESH"

# ⚠️ DECLARATIVE, NOT A MIGRATION. createdb.sql runs against an EMPTY database and nothing
# else — there is no deployment for it to carry forward. An ALTER or a DROP in here means
# the file has started describing a state it also has to repair, which is the shape the
# steps existed for; the two must not merge, or a fresh install begins by undoing itself.
for kw in ALTER DROP; do
    n=$(grep -ciE "^[[:space:]]*$kw" "$CREATEDB" | tr -d ' ')
    chk "createdb.sql contains no $kw statement" 0 "$n"
done
# Anti-vacuity: the two counts above are only meaningful if the file really was scanned.
chk "  PRECONDITION: it does define tables" yes \
    "$([ "$(grep -ciE '^[[:space:]]*create table' "$CREATEDB" | tr -d ' ')" -gt 0 ] && echo yes || echo no)"

STEPFILES=$(ls "$STEPS"/[0-9]*.sql 2>/dev/null | wc -l | tr -d ' ')
if [ "$STEPFILES" -gt 0 ]; then
    echo "=== 2. every shipped step is listed, and unchanged ==="
    SHA=$(command -v sha256sum || command -v shasum || true)
    if [ -z "$SHA" ]; then
        echo "  [SKIP] no sha256sum/shasum on this host"
    else
        sum(){ case "$SHA" in *shasum) "$SHA" -a 256 "$1" | cut -d' ' -f1;; *) "$SHA" "$1" | cut -d' ' -f1;; esac; }
        chk "the manifest exists" yes "$([ -s "$MANIFEST" ] && echo yes || echo no)"
        chk "the manifest covers every step file" "$STEPFILES" "$(grep -c . "$MANIFEST" | tr -d ' ')"
        drift=""; missing=""
        for f in "$STEPS"/[0-9]*.sql; do
            b=$(basename "$f")
            want=$(awk -v n="$b" '$2==n{print $1}' "$MANIFEST")
            if [ -z "$want" ]; then missing="$missing $b"; continue; fi
            [ "$(sum "$f")" = "$want" ] || drift="$drift $b"
        done
        chk "no shipped step has been edited" "" "$drift"
        chk "no step is missing from the manifest" "" "$missing"
        # A manifest line naming a file that is gone means a step was DELETED — which an
        # applied database can never un-apply, so it is the same class of mistake.
        gone=""
        while read -r _h n; do [ -z "$n" ] && continue; [ -f "$STEPS/$n" ] || gone="$gone $n"; done < "$MANIFEST"
        chk "no manifest entry names a deleted step" "" "$gone"
    fi

    echo "=== 3. the binary requires the newest step ==="
    # ⚠️ ADDING A STEP WITHOUT BUMPING kSchemaVersion is the other half of the same defect:
    # the column exists in the file, nothing forces the deployment to apply it before the
    # binaries roll, and the first read fails at runtime instead of at startup with a
    # named fix.
    NEWEST=$(ls "$STEPS"/[0-9]*.sql | sed 's#.*/##; s/-.*//' | sed 's/^0*//' | sort -n | tail -1)
    chk "schema.hpp requires the newest step" "$NEWEST" "$NEED"
    NEWFILE=$(ls "$STEPS"/[0-9]*.sql | tail -1)
    chk "the newest step records its own version" yes \
        "$(grep -qE "VALUES *\( *$NEWEST," "$NEWFILE" && echo yes || echo no)"
else
    echo "=== 2. the baseline reset is complete ==="
    # Not a skip: with no steps the assertions above are the whole guard, and this states
    # the precondition that makes them sufficient rather than passing over an empty set.
    chk "no step directory exists, so createdb.sql is the only schema definition" yes \
        "$([ ! -d "$STEPS" ] && echo yes || echo no)"
    chk "  and the baseline the binary requires is 1" 1 "$NEED"
fi

echo
echo "=== SCHEMA STEPS IMMUTABLE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
