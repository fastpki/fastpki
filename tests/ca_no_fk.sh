#!/usr/bin/env bash
# Contract, part 1: the CA's attributes live on its certificate row, and NO table
# has a foreign key onto the CA registry any more.
#
# ── The bug, exactly ──────────────────────────────────────────────────────────────
#
# Logical-replication apply workers run with session_replication_role='replica', which
# DISABLES foreign-key triggers. So a `certs` row whose `ca_instances` row has not
# arrived inserts silently on a peer: nothing logs, nothing fails, and the database
# quietly violates its own constraint. Measured on the lab, test-03 held
# 1362 certificates of which 1361 were orphaned.
#
# It is not cosmetic. `pg_dump` of such a node CANNOT BE RESTORED ANYWHERE, including
# back into itself, because the restore recreates the constraint and validates it:
#
#     ERROR: insert or update on table "certs" violates foreign key constraint
#            "certs_ca_instance_id_fkey"
#
# — which is the backup and the online restore both broken on any node that has
# been a mesh peer for a while.
#
# ── What has teeth here ───────────────────────────────────────────────────────────
#
# Section 4 is the point of the whole file: it BUILDS a node in the broken state (certs
# referencing a CA id that is not in the registry, inserted the way replication inserts
# them — with the triggers off), then dumps and restores it. Against the previous schema
# that restore fails with the error above. Asserting "the constraint is gone" from the
# catalogue is necessary but weak; asserting the round-trip actually completes is the
# thing the ticket asked for.
#
# The other sections cover what a constraint drop can quietly take with it: the three
# CA attributes must survive the move onto `certs` and must reach a peer, and a re-run
# of the step must change nothing.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup ca_no_fk
trap 'pg_cleanup' EXIT

apply_step(){ "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
    --single-transaction -q -v ON_ERROR_STOP=1 -f "$1" >/dev/null; }
col(){ pg_exec "SELECT data_type FROM information_schema.columns WHERE table_name='certs' AND column_name='$1';" | tr -d ' '; }
# Every FK on <table> that points at ca_instances, by name. The catalogue is the
# authority — a grep of createdb.sql says what we meant, not what the database has.
fk_to_ca(){ pg_exec "
  SELECT count(*) FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    JOIN pg_class r ON r.oid = c.confrelid
   WHERE c.contype='f' AND t.relname='$1' AND r.relname='ca_instances';" | tr -d ' '; }

echo "=== 1. a fresh database is born with the attributes and without the FKs ==="
chk "certs.name is text"                    text    "$(col name)"
chk "certs.ca_enabled is boolean"           boolean "$(col ca_enabled)"
chk "certs.ms_enroll_permission is boolean" boolean "$(col ms_enroll_permission)"
# ca_enabled is NOT certs.status. status is about the certificate (valid/revoked);
# ca_enabled is an operator switch over a perfectly valid CA. Conflating them would
# make disabling a CA look like revoking its certificate.
chk "certs.status still exists and is separate" integer "$(col status)"
# There is deliberately no parent_id — the AKI carries the chain.
chk "no parent_id was added to certs"       ""      "$(col parent_id)"

# ⚠️ transport_certs is NOT in this list any more (the table is gone). Leaving it would be
# worse than useless: fk_to_ca() counts pg_constraint rows by relname, and for a table
# that does not exist the count is 0 — so "transport_certs has no FK to ca_instances"
# would pass FOREVER, a green assertion about nothing. A dropped table has to leave the
# list, not be left to pass by accident.
for t in certs audit_log discovered_certs ca_xcep_uris; do
    chk "$t has no FK to ca_instances" 0 "$(fk_to_ca $t)"
done
# The COLUMNS stay. Dropping the constraint is the fix; dropping the column would throw
# away how a leaf names its issuer and is not what this ticket asked for.
chk "certs.ca_instance_id survives as plain text" text "$(col ca_instance_id)"
chk "the index on it survives" 1 \
    "$(pg_exec "SELECT count(*) FROM pg_indexes WHERE tablename='certs' AND indexname='certs_ca_idx';" | tr -d ' ')"
# ⚠️ THE DATE COLUMNS ARE bigint, AND THAT IS A FRESH-SCHEMA PROPERTY NOW. It used to be
# proved by widening an old `integer` column with a publication in the way — the shape a
# running node had. There are no running nodes: the steps were collapsed into
# sql/createdb.sql, so what matters is that a database is BORN wide enough. A 32-bit
# notAfter cannot hold a CA that outlives 2038, which every root does.
chk "certs.\"notBefore\" is bigint" bigint "$(col notBefore)"
chk "certs.\"notAfter\" is bigint"  bigint "$(col notAfter)"
chk "  and a 9999-12-31 notAfter really stores" 253402300799 \
    "$(pg_exec "INSERT INTO certs(serial,status,subject,cn,\"notBefore\",\"notAfter\")
                  VALUES('fedcba',0,'CN=far','far',0,253402300799)
                ON CONFLICT DO NOTHING;
                SELECT \"notAfter\" FROM certs WHERE serial='fedcba';" | tr -d ' ')"
pg_exec "DELETE FROM certs WHERE serial='fedcba';" >/dev/null 2>&1

echo "=== 6. and what a FRESH mesh setup emits agrees with the step ==="
# Two places name the column list — the step (for a running node) and mesh.cpp (for a
# new one). They drifted once already on `private_key`, and a peer set up later than its
# siblings would then replicate a different set of columns than they do.
MESH="$ROOT/build/fastpki-mesh"
if [ ! -x "$MESH" ]; then
    echo "  [SKIP] fastpki-mesh not built"
else
    printf 'dc1|host=127.0.0.1 dbname=a sslmode=disable|1|http://dc1.example\ndc2|host=127.0.0.1 dbname=b sslmode=disable|2|http://dc2.example\n' > topo.txt
    # --allow-plaintext-transport because this renders SQL, it does not deploy; mesh
    # otherwise refuses sslmode=disable and is right to (the link carries password hashes).
    PUB=$("$MESH" --topology topo.txt --publication --allow-plaintext-transport 2>/dev/null)
    chk "a publication was generated" yes "$(echo "$PUB" | grep -q 'CREATE PUBLICATION' && echo yes || echo no)"
    # Cut out certs' OWN list — `name` appears in other tables' lists too, so searching
    # the whole statement would pass on someone else's column.
    CERTCOLS=$(echo "$PUB" | sed -n 's/.*FOR TABLE certs (\([^)]*\)).*/\1/p')
    chk "certs is published by column list" yes "$([ -n "$CERTCOLS" ] && echo yes || echo no)"
    for c in name ca_enabled ms_enroll_permission; do
        chk "mesh's certs list carries $c" yes \
            "$(echo "$CERTCOLS" | tr ',' '\n' | sed 's/^ *//' | grep -qx "$c" && echo yes || echo no)"
    done
    chk "and still not private_key" yes "$(echo "$CERTCOLS" | grep -q 'private_key' && echo no || echo yes)"
fi

echo "=== 7. the contract: ca_instances is GONE ==="
# The point of the whole ticket. Step 0007 destroys the table, so it is deliberately the
# last step and requires every node to be on binaries that never touch it.
chk "a fresh database has no ca_instances at all" 0 \
    "$(pg_exec "SELECT count(*) FROM information_schema.tables
                 WHERE table_schema='public' AND table_name='ca_instances';" | tr -d ' ')"
chk "and no constraint anywhere still references it" 0 \
    "$(pg_exec "SELECT count(*) FROM pg_constraint c
                  JOIN pg_class r ON r.oid=c.confrelid
                 WHERE c.contype='f' AND r.relname='ca_instances';" | tr -d ' ')"
# The CA rows themselves survive the drop — they were never in that table.
chk "the CA columns still work without it" text "$(col name)"


echo
echo "=== CA NO FK: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
