#!/usr/bin/env bash
# A table that must replicate has to be PUT on the wire by something.
#
# `src/tools/mesh.cpp` names every table that replicates, and `tests/mesh.sh` proves the
# generator emits them. Neither says anything about the deployment, and that is the gap
# this suite exists for: fastpki-mesh is a SQL GENERATOR an operator runs by hand. Nothing
# in schema-apply.sh or the compose roll invokes it. So a table created by a schema step
# lands in every node's SCHEMA and in nobody's PUBLICATION — the feature works perfectly
# on each node in isolation while the data silently stays per-node.
#
# Measured, not theorised: the change that created `foreign_anchors` applied cleanly
# on all three lab DCs; pg_publication_tables then held zero rows for it, and an anchor
# registered on dc1 was invisible on dc2 and dc3. `roles` and `role_permissions` were dead
# on the same lab for months for exactly this reason.
#
# THE RULE, checked here: if a replicated table is created by a schema STEP rather than
# being part of the baseline schema, some step must also add it to the publication. A
# table in the baseline is fine — the publication is generated after createdb.sql runs, so
# it picks those up on its own.
#
# Static on purpose. It needs no database, no cluster and no mesh, so it runs everywhere
# and cannot be skipped into a false pass on a machine without Postgres.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MESH_SRC="$ROOT/src/tools/mesh.cpp"
CREATEDB="$ROOT/sql/createdb.sql"
STEPS="$ROOT/sql/steps"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# The replicated-table list, read out of the product rather than restated here — a second
# copy would be a second source of truth, and the copy nobody reads is the one that drifts.
# kPublicTables is a run of C string literals with comments between them: take the literal
# bodies only, drop the parenthesised column list that follows `certs`, and split on commas.
TABLES=$(awk '
    /^const char\* kPublicTables =/ { grab = 1; next }
    grab && /^[[:space:]]*\/\// { next }
    grab { line = $0
           if (line ~ /;[[:space:]]*$/) grab = 0
           while (match(line, /"[^"]*"/)) {
               s = substr(line, RSTART + 1, RLENGTH - 2)
               out = out s
               line = substr(line, RSTART + RLENGTH)
           }
         }
    END { print out }
' "$MESH_SRC" \
  | sed 's/([^)]*)//g' \
  | tr ',' '\n' | tr -d ' "' | sed '/^$/d' | sort -u)

chk "the replicated-table list was parsed out of mesh.cpp" yes \
    "$([ "$(printf '%s\n' "$TABLES" | wc -l | tr -d ' ')" -ge 8 ] && echo yes || echo no)"
# Prove the parse really sees table names and not, say, one run-on blob. If this is wrong
# every other check below passes vacuously.
chk "  ... and it contains a table we know replicates (web_users)" yes \
    "$(printf '%s\n' "$TABLES" | grep -qx 'web_users' && echo yes || echo no)"

# ⚠️ ALSO A STEPS-ONLY RULE. With the steps collapsed into createdb.sql, no table is
# created by a step, so there is nothing here for a step to publish: the publication is
# generated after createdb.sql runs and picks the whole baseline up on its own. Guarded
# rather than deleted — the rule returns with the first step that creates a table.
if [ "$(ls "$STEPS"/[0-9]*.sql 2>/dev/null | wc -l | tr -d " ")" -gt 0 ]; then
  echo "=== a table a STEP creates is a table a step must publish ==="
  # Order matters here, and getting it wrong makes this section vacuous. A new table is
  # normally added in BOTH places: createdb.sql so a fresh database is born current, and a
  # step so existing databases catch up. Asking "is it in createdb.sql?" first therefore
  # skips every table this check exists for — which is exactly what the first draft did, and
  # it reported a clean pass over the very bug that motivated the suite.
  #
  # So: if a STEP creates it, a step must publish it, whether or not createdb.sql also has
  # it. The step path is the one that reaches a running cluster, and a running cluster is
  # where the publication is.
  checked=0
  for t in $TABLES; do
      born=$(grep -liE "create table( if not exists)? +$t\b" "$STEPS"/*.sql 2>/dev/null | head -1)
      [ -n "$born" ] || continue   # baseline-only: the publication is generated after
                                   # createdb.sql runs, so it picks these up on its own.
      checked=$((checked+1))
      published=$(grep -lE "ALTER PUBLICATION .* (ADD|SET) TABLE[^;]*\b$t\b" "$STEPS"/*.sql 2>/dev/null | head -1)
      chk "$t (created by $(basename "$born")) is published by a step" yes \
          "$([ -n "$published" ] && echo yes || echo no)"
  done
  # Without this, a parse that silently stopped matching would leave the loop empty and the
  # suite green. A vacuous pass is the failure mode this whole file is about.
  chk "the loop above actually examined a table" yes \
      "$([ "$checked" -gt 0 ] && echo yes || echo no)"
else
  chk "no step exists, so no table can be created outside the baseline" yes \
      "$([ ! -d "$STEPS" ] && echo yes || echo no)"
fi

echo "=== something actually refreshes the subscribers ==="
# Publishing is half the job. A subscriber keeps the table set it last resolved, so a
# newly published table stays invisible to every peer until its subscription is refreshed
# — which looks exactly like success on the node you ran the step from.
#
# It CANNOT be the step's own job: ALTER SUBSCRIPTION ... REFRESH cannot run inside a
# transaction block and schema-apply.sh applies every step with --single-transaction, so a
# step that tried would fail at apply time on a live DC. (Verified against the lab
# cluster, not assumed.) So the refresh must live in schema-apply.sh, after the loop.
APPLY="$ROOT/deploy/schema-apply.sh"
chk "schema-apply.sh refreshes subscriptions" yes \
    "$(grep -q 'REFRESH PUBLICATION' "$APPLY" && echo yes || echo no)"
# pg_subscription is a SHARED catalog listing every database's subscriptions. Unscoped,
# a deploy would reach into throwaway test databases on the same cluster.
chk "  ... scoped to the current database" yes \
    "$(grep -q 'current_database()' "$APPLY" && echo yes || echo no)"
# The refresh must sit OUTSIDE the --single-transaction step loop, or it cannot run at all.
chk "  ... not inside the --single-transaction step application" yes \
    "$(awk '/--single-transaction/{t=NR} /REFRESH PUBLICATION/{r=NR} END{print (r>t)?"yes":"no"}' "$APPLY")"

# ⚠️ BOTH SECTIONS BELOW ARE ABOUT SCHEMA STEPS, AND THE STEPS WERE COLLAPSED into
# sql/createdb.sql — they only ever applied to a database that already existed, and
# there are none. That also RETIRES THE HAZARD the LWW check exists for: the danger was
# a table appearing mid-rollout, so that one node published `updated` while its peers
# lacked the column. Every table is now in the baseline, created before any node runs
# the trigger generator, which is the case the generator has always been safe for.
# Guarded rather than deleted, because the hazard returns with the first step that
# creates an LWW table.
if [ "$(ls "$STEPS"/[0-9]*.sql 2>/dev/null | wc -l | tr -d " ")" -gt 0 ]; then
  echo "=== no step tries to do the refresh itself (it would fail at apply time) ==="
  for f in "$STEPS"/*.sql; do
      [ -e "$f" ] || continue
      # A comment may discuss it; an executable statement must not exist. Strip comments
      # first, or every step that explains the rule fails the check that enforces it.
      body=$(sed 's/--.*//' "$f")
      chk "$(basename "$f") issues no ALTER SUBSCRIPTION" yes \
          "$(printf '%s' "$body" | grep -qi 'ALTER SUBSCRIPTION' && echo no || echo yes)"
  done
  
  echo '=== a step-created LWW table declares its own updated column ==='
  # ⚠️ MEASURED ON THE LAB, NOT REASONED ABOUT. fastpki-mesh --triggers supplies the
  # last-writer-wins timestamp with `ALTER TABLE ... ADD COLUMN IF NOT EXISTS updated`, and
  # for a BASELINE table that is harmless — the generator runs at first mesh setup, before
  # any row exists, so every node gets the column at the same point in its life.
  #
  # A table created by a schema STEP appears afterwards, and during a rolling update each
  # node runs the generator at a DIFFERENT moment. The first node rolled therefore starts
  # publishing rows carrying `updated` while its peers' copy of the table still lacks it.
  # What that looks like: the apply worker exits with "logical replication target relation
  # is missing replicated column: updated", the subscription sits at 'd' (copy in progress)
  # indefinitely, the row never arrives — and every health check reports green, because the
  # subscription IS enabled and the publication DOES list the table.
  #
  # So a step-created LWW table has to declare the column itself. The generator's
  # ADD COLUMN IF NOT EXISTS then becomes a no-op and the ordering stops mattering.
  #
  # Scoped to step-created tables on purpose: the baseline tables predate this and several
  # do not declare it, which is safe for the reason above. Asserting over them would be a
  # failing check nobody can act on, which is how a guard gets deleted.
  # The LWW set is kMgmtTables, which is a different list from kPublicTables above: a table
  # can replicate without carrying a conflict-resolution trigger. Parsed from the same file.
  LWW=$(awk '/^const std::vector<MgmtTable> kMgmtTables =/{g=1; next} g&&/^};/{exit}
             g && match($0, /\{"[a-z_][a-z0-9_]*"/) { print substr($0, RSTART+2, RLENGTH-3) }' "$MESH_SRC")
  # ⚠️ "CREATED BY A STEP" IS NOT "ABSENT FROM createdb.sql". createdb.sql is born current,
  # so it contains every table including the ones a step introduced — an earlier version of
  # this check skipped on that and examined NOTHING, passing while the column was missing.
  # The discriminator is simply: does some sql/steps file CREATE this table.
  #
  # Comments are stripped before looking for the column, because these files explain the
  # column in prose right beside it and a plain grep matches the explanation.
  step_lww_missing=""; step_lww_seen=0
  for t in $LWW; do
      for f in "$STEPS"/*.sql; do
          [ -f "$f" ] || continue
          sed 's/--.*//' "$f" | tr '\n' ' ' \
            | grep -qiE "create table( if not exists)? +$t *\\(" || continue
          step_lww_seen=$((step_lww_seen + 1))
          sed 's/--.*//' "$f" | tr '\n' ' ' \
            | sed -E "s/.*create table( if not exists)? +$t *\\(//I; s/\\);.*//" \
            | grep -qE '(^|,)[[:space:]]*updated[[:space:]]+bigint' \
            || step_lww_missing="$step_lww_missing $t"
          break
      done
  done
  chk "every step-created LWW table declares its own updated column" "" "$(echo $step_lww_missing)"
  # Anti-vacuity: this loop examines only tables a step creates, and an earlier version of it
  # matched none at all and passed over an empty set. If the count is zero the discriminator
  # has rotted, not the schema.
  chk "  PRECONDITION: the scan found a step-created LWW table to examine" yes \
      "$([ "$step_lww_seen" -gt 0 ] && echo yes || echo no)"
else
  chk "no step exists, so no LWW table can appear mid-rollout" yes \
      "$([ ! -d "$STEPS" ] && echo yes || echo no)"
fi


# ⚠️ EVERY TABLE MUST BE CLASSIFIED — REPLICATED OR DELIBERATELY NODE-LOCAL.
#
# sql/createdb.sql is the only place tables are defined, and adding one there used to be
# enough to ship it: a table absent from kPublicTables does not replicate, silently, and
# nothing compared the two lists. That is the same shape as the mesh failing to converge —
# every health signal green while one node's data never leaves it. It is worse now that the
# 39 schema steps were collapsed into createdb.sql, because createdb.sql is the ONLY place
# a new table can appear.
#
# Found by this check when it was first written: `client_configs` was in neither list. It is
# admin-authored content keyed by an admin-chosen `kind`, its body is written in the console,
# and set_client_config() already stamped `updated` with a microsecond epoch — the exact
# column the last-writer-wins triggers need, present and unused. An admin who authored an
# enrolment config on one DC simply did not have it on the others.
#
# Asserted in BOTH directions so neither list can drift: a table in createdb.sql and in
# neither list is unclassified, and a name in either list that createdb.sql does not define
# is a typo or a table that was dropped.
echo "=== every table in createdb.sql is classified: replicated or node-local ==="
# Static suite: no pg_setup, so it makes its own scratch dir and removes it on exit.
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
# ⚠️ TABLE NAMES CONTAIN DIGITS, and every pattern in this suite read [a-z_]+ once.
# On the createdb.sql side that TRUNCATED `p11_transport` to `p`; on the list side it
# dropped the name entirely. So the first table with a digit in it reported itself as an
# unclassified table called `p` — a name that matches nothing anyone can grep for, about a
# table that was in fact classified correctly.
tbl_list() {   # extract a comma-separated C string list, dropping comments and column lists
    awk -v v="$1" 'index($0, "const char* " v " =") {f=1; next} f {print} f && /";[[:space:]]*$/ {exit}' "$MESH_SRC" \
      | sed 's|//.*||' | tr -d '\n' | sed 's/([^)]*)//g' \
      | grep -oE '"[^"]*"' | tr -d '"' | tr ',' '\n' \
      | sed 's/^ *//; s/ *$//' | grep -E '^[a-z_][a-z0-9_]*$' | sort -u
}
tbl_list kPublicTables    > "$W/pub.txt"
tbl_list kNodeLocalTables > "$W/local.txt"
grep -oiE '^[[:space:]]*create table( if not exists)? +([a-z_][a-z0-9_]*)' "$CREATEDB" \
  | awk '{print tolower($NF)}' | sort -u > "$W/all.txt"

chk "PRECONDITION: createdb.sql defines tables"      yes "$([ -s "$W/all.txt" ] && echo yes || echo no)"
chk "PRECONDITION: kPublicTables was parsed"         yes "$([ -s "$W/pub.txt" ] && echo yes || echo no)"
chk "PRECONDITION: kNodeLocalTables was parsed"      yes "$([ -s "$W/local.txt" ] && echo yes || echo no)"
# No table may be in both — that is a contradiction rather than a harmless overlap.
chk "no table is both replicated and node-local"     "" \
    "$(comm -12 "$W/pub.txt" "$W/local.txt" | tr '\n' ' ' | sed 's/ $//')"
sort -u "$W/pub.txt" "$W/local.txt" > "$W/classified.txt"
chk "every createdb.sql table is classified"         "" \
    "$(comm -23 "$W/all.txt" "$W/classified.txt" | tr '\n' ' ' | sed 's/ $//')"
chk "  and neither list names a table createdb.sql does not define" "" \
    "$(comm -13 "$W/all.txt" "$W/classified.txt" | tr '\n' ' ' | sed 's/ $//')"
# Anti-vacuity: the two lists must actually add up to the file, not merely fail to disagree
# with an empty parse. If the extraction rots, these counts diverge and this fires.
chk "  PRECONDITION: the classified set IS the createdb.sql set" \
    "$(wc -l < "$W/all.txt" | tr -d ' ')" "$(wc -l < "$W/classified.txt" | tr -d ' ')"

# A replicated table needs a conflict answer or the apply worker stalls on the first
# duplicate — the failure that put every node into a retry loop on datacenter_ranges_pkey.
# certs has its own hand-written skip-dup, so it is named here rather than parsed.
SKIP=$(awk '/kSkipDupTables/{g=1} g&&/^};/{exit} g' "$MESH_SRC" \
        | grep -oE '\{"[a-z_][a-z0-9_]*",' | tr -d '{",' | sort -u)
LWW=$(awk '/kMgmtTables/{g=1} g&&/^};/{exit} g' "$MESH_SRC" \
        | grep -oE '\{"[a-z_][a-z0-9_]*",' | tr -d '{",' | sort -u)
printf '%s\n%s\ncerts\n' "$SKIP" "$LWW" | grep -E '^[a-z_][a-z0-9_]*$' | sort -u > "$W/handled.txt"
chk "every replicated table has a conflict answer"   "" \
    "$(comm -23 "$W/pub.txt" "$W/handled.txt" | tr '\n' ' ' | sed 's/ $//')"
echo
echo "=== MESH PUBLICATION COMPLETE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
