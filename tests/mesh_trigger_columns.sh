#!/usr/bin/env bash
# A replication trigger must not name a column that does not exist.
#
# ── The bug this exists for ────────────────────────────────────────────────────────
#
# `fastpki-mesh` generates one PL/pgSQL function per replicated management table:
# `fastpki_lww_<t>()` resolves last-writer-wins conflicts and `fastpki_<t>_skip_dup()`
# swallows duplicate inserts. Both are built from a hardcoded PRIMARY-KEY column list in
# src/tools/mesh.cpp, and both run ONLY during replication apply (ENABLE REPLICA TRIGGER).
#
# Renamed `role_permissions.ca_id` -> `scope`. mesh.cpp was updated in the same commit.
# The LIVE databases were not, because nothing re-runs the generator — and **Postgres does
# not re-check a PL/pgSQL body when a column is renamed**, so the deployed function kept
# saying `ca_id`. It compiled, it loaded, it was attached to the table, and it failed only
# when a row actually replicated:
#
#     ERROR: column role_permissions.ca_id does not exist
#     CONTEXT: PL/pgSQL function fastpki_lww_role_permissions() line 5
#     background worker "logical replication apply worker" exited with exit code 1
#
# Both apply workers on all three lab DCs jammed for hours, ~1700 errors per node in two,
# and nothing else showed it: the publication was right, the subscriptions were enabled,
# `schema_version` was 18 everywhere, and the PUBLISHER was completely healthy. That left
# the identical trap behind once already (`web_users.tenant_id`), which is the second time
# this shape has cost a silent replication outage.
#
# ── What this asserts ──────────────────────────────────────────────────────────────
#
# Not "the columns mesh.cpp names today are right" — that would just re-state the source.
# It builds a database from the CURRENT schema, applies the CURRENT generator output, and
# asks POSTGRES whether every column those function bodies reference actually exists. A
# rename that misses one side fails here rather than on a DC.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
MESH="$ROOT/build/fastpki-mesh"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

[ -x "$MESH" ] || { echo "  [SKIP] fastpki-mesh not built"; echo "=== MESH TRIGGER COLUMNS: PASS=0 FAIL=0 SKIP=1 ==="; exit 0; }
pg_setup meshtrig
trap 'pg_cleanup' EXIT

echo "=== the generator applies against the current schema ==="
OUT=$("$MESH" --triggers 2>&1)
chk "--triggers emits SQL without a topology file" yes \
    "$(echo "$OUT" | grep -q 'CREATE OR REPLACE FUNCTION fastpki_lww_' && echo yes || echo no)"
# NOTICEs are expected (DROP TRIGGER IF EXISTS on a fresh database), so select ERRORs.
APPLY=$(echo "$OUT" | psql "$PG_CONNINFO" -v ON_ERROR_STOP=1 -q 2>&1 | grep -i "^ERROR" || true)
chk "...and applies cleanly" "" "$APPLY"

echo "=== every column the trigger bodies name exists ==="
# ⚠️ Ask Postgres, not a regex over the source. A function body is opaque text until it
# runs, which is the whole reason the bug is invisible: the only authority on "does this
# body reference a real column" is the parser. plpgsql_check is not available, so this
# forces the parse the cheap way — a body naming a missing column raises when its
# statement is planned, and EXPLAIN on the same SELECT does that without touching a row.
#
# Extract each `FROM public.<t> WHERE <cols...>` predicate the generator emitted and plan
# it. NEW.<col> is not available outside a trigger, so the NEW side is replaced by the
# column itself: the point is whether the NAME resolves, and both sides of the comparison
# are the same name.
# ⚠️ [a-z0-9_], NOT [a-z_]. `FROM public.p11_transport` matched only `public.p` under
# the narrower class, so $TBL was wrong, the predicate extraction below found nothing, and
# the function was skipped by the `continue` rather than probed. The count then said 17 of
# 18, with nothing to say which one — a table silently leaving the probe is precisely what
# the exact-number assertion exists to catch, and the pattern defeated it.
BAD=0; PROBED=0
for fn in $(psql "$PG_CONNINFO" -tAc "SELECT proname FROM pg_proc WHERE proname LIKE 'fastpki_%' AND prokind='f';"); do
    SRC=$(psql "$PG_CONNINFO" -tAc "SELECT prosrc FROM pg_proc WHERE proname='$fn';")
    TBL=$(echo "$SRC" | grep -oE 'FROM public\.[a-z_][a-z0-9_]*' | head -1 | sed 's/.*\.//')
    [ -n "$TBL" ] || continue
    # ⚠️ TWO emitted shapes, and the first version of this loop only handled one:
    #   lww:      SELECT updated FROM public.<t> WHERE <t>.<col> = NEW.<col> AND ...
    #   skip_dup: IF EXISTS (SELECT 1 FROM public.<t> WHERE <col> = NEW.<col> ...)
    # The skip_dup predicate has no table prefix, so a prefix-anchored pattern silently
    # matched nothing and four functions were never probed at all. Take the text after
    # WHERE up to the first ')' or ';' instead, which covers both.
    PRED=$(echo "$SRC" | tr '\n' ' ' | sed -n "s/.*FROM public\.$TBL WHERE \([^;)]*\).*/\1/p" | sed 's/NEW\.//g')
    [ -n "$PRED" ] || continue
    PROBED=$((PROBED+1))
    ERR=$(psql "$PG_CONNINFO" -v ON_ERROR_STOP=1 -tAc "EXPLAIN SELECT 1 FROM public.$TBL WHERE $PRED;" 2>&1 >/dev/null)
    if [ -n "$ERR" ]; then
        echo "      $fn -> $(echo "$ERR" | head -1)"
        BAD=$((BAD+1))
    fi
done
# 7 last-writer-wins tables + 4 skip-duplicate tables = 11 generated functions today.
# Asserting the exact number rather than ">= something" is deliberate: a table quietly
# leaving the replication set is as much a defect as a stale column name, and a floor
# would not notice it.
EXPECT=$(( $("$MESH" --triggers | grep -c 'CREATE OR REPLACE FUNCTION fastpki_') - 1 ))   # -1: fastpki_stamp_updated has no predicate
chk "the probe reached EVERY generated function" "$EXPECT" "$PROBED"
chk "no generated trigger names a column that does not exist" 0 "$BAD"

echo "=== every last-writer-wins trigger matches on the table's WHOLE primary key ==="
# A COLUMN THAT EXISTS IS NOT ENOUGH. The section above asks "does every name resolve",
# which is the scope rename. The other half of the same family: `keys` gained a
# `protocol` column and its primary key became (kid, protocol), while kMgmtTables still
# said `kid` alone. Every name still resolved, so the probe above stayed green — and the
# trigger would have located a row by kid only, treating one user's CMP, EAB and SCEP
# secrets as ONE row. An arriving EAB key deletes her CMP secret as a stale version of
# itself, on the peer, with nothing logged.
#
# So compare the SET the generator matches on against the PRIMARY KEY Postgres actually
# has. Both sides are read from the live database: the predicate out of pg_proc, the key
# out of pg_index. Neither restates mesh.cpp.
KEYBAD=0; KEYSEEN=0
for fn in $(psql "$PG_CONNINFO" -tAc \
        "SELECT proname FROM pg_proc WHERE proname LIKE 'fastpki_lww_%' AND prokind='f';"); do
    TBL=${fn#fastpki_lww_}
    SRC=$(psql "$PG_CONNINFO" -tAc "SELECT prosrc FROM pg_proc WHERE proname='$fn';")
    # The columns the body matches on, as "a,b,c" sorted.
    HAVE=$(echo "$SRC" | tr '\n' ' ' | grep -oE "$TBL\.[a-z_][a-z0-9_]* = NEW\.[a-z_][a-z0-9_]*" \
           | sed -E "s/^$TBL\.([a-z_][a-z0-9_]*).*/\1/" | sort -u | paste -sd, -)
    # The table's real primary key, same shape.
    WANT=$(psql "$PG_CONNINFO" -tAc "
        SELECT string_agg(a.attname, ',' ORDER BY a.attname)
          FROM pg_index i
          JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
         WHERE i.indrelid = 'public.$TBL'::regclass AND i.indisprimary;")
    [ -n "$WANT" ] || continue      # a table with no PK is not this check's business
    KEYSEEN=$((KEYSEEN+1))
    if [ "$HAVE" != "$WANT" ]; then
        echo "      $TBL: trigger matches on [$HAVE] but the primary key is [$WANT]"
        KEYBAD=$((KEYBAD+1))
    fi
done
chk "every LWW table was compared" yes "$([ "$KEYSEEN" -ge 7 ] && echo yes || echo no)"
chk "no LWW trigger matches on less than the whole primary key" 0 "$KEYBAD"

echo "=== the check can actually see a break (anti-vacuity) ==="
# Rename a column out from under a generated function, exactly as that did, and require the
# loop above to notice. Without this the whole suite would pass just as well if the loop
# planned nothing at all -- which is how it would fail, since every step of the extraction
# `continue`s on an empty match.
psql "$PG_CONNINFO" -v ON_ERROR_STOP=1 -q -c "ALTER TABLE role_permissions RENAME COLUMN scope TO scope_moved;" 2>/dev/null
ERR=$(psql "$PG_CONNINFO" -tAc "EXPLAIN SELECT 1 FROM public.role_permissions WHERE role_permissions.role = role AND role_permissions.permission = permission AND role_permissions.scope = scope;" 2>&1 >/dev/null)
chk "a renamed column IS detected by the same probe" yes \
    "$(echo "$ERR" | grep -q 'does not exist' && echo yes || echo no)"
psql "$PG_CONNINFO" -v ON_ERROR_STOP=1 -q -c "ALTER TABLE role_permissions RENAME COLUMN scope_moved TO scope;" 2>/dev/null

# ...and the same for the key-set check, which the rename probe above cannot see: widen a
# table's primary key without touching the trigger and the comparison must go red. This is
# exactly that shape, staged on a table the suite is free to alter.
psql "$PG_CONNINFO" -v ON_ERROR_STOP=1 -q -c "
  ALTER TABLE allowed_domains DROP CONSTRAINT allowed_domains_pkey;
  ALTER TABLE allowed_domains ADD COLUMN IF NOT EXISTS probe_col text NOT NULL DEFAULT '';
  ALTER TABLE allowed_domains ADD PRIMARY KEY (domain, probe_col);" 2>/dev/null
WIDER=$(psql "$PG_CONNINFO" -tAc "
    SELECT string_agg(a.attname, ',' ORDER BY a.attname)
      FROM pg_index i
      JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
     WHERE i.indrelid = 'public.allowed_domains'::regclass AND i.indisprimary;")
chk "a widened primary key IS visible to the same comparison" yes \
    "$([ "$WIDER" = "domain,probe_col" ] && echo yes || echo no)"
SRC=$(psql "$PG_CONNINFO" -tAc "SELECT prosrc FROM pg_proc WHERE proname='fastpki_lww_allowed_domains';")
HAVE=$(echo "$SRC" | tr '\n' ' ' | grep -oE "allowed_domains\.[a-z_][a-z0-9_]* = NEW\.[a-z_][a-z0-9_]*" \
       | sed -E "s/^allowed_domains\.([a-z_][a-z0-9_]*).*/\1/" | sort -u | paste -sd, -)
chk "  and the trigger, unchanged, no longer matches it" yes \
    "$([ "$HAVE" != "$WIDER" ] && echo yes || echo no)"
psql "$PG_CONNINFO" -v ON_ERROR_STOP=1 -q -c "
  ALTER TABLE allowed_domains DROP CONSTRAINT allowed_domains_pkey;
  ALTER TABLE allowed_domains DROP COLUMN probe_col;
  ALTER TABLE allowed_domains ADD PRIMARY KEY (domain);" 2>/dev/null

echo
echo "=== MESH TRIGGER COLUMNS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
