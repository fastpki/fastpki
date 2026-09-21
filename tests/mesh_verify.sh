#!/usr/bin/env bash
# `fastpki-mesh --verify` must report a PARTIALLY applied mesh.
#
# fastpki-mesh emits SQL and an operator pipes it into psql. Nothing afterwards asks
# whether all of it landed, and a partial application is SILENT, because the half that
# applied keeps working perfectly.
#
# Found on our own 3-DC lab, where this had been the live state for as long as anyone
# could tell:
#
#     publication fastpki_pub   present
#     trigger certs_skip_dup    present
#     trigger certs_dc_range    present, correct per-node bounds
#     data center map          0 ROWS      <- the --map preamble had never been applied
#
# Every node could enforce its own serial range and no node could see any other node's.
# (That state is worse than blind: a node reads its own row to learn the serial
# prefix it mints under, so an empty map means a node that refuses to issue.)
# Issuance was fine, replication was fine, nothing anywhere reported a problem. It is not
# specific to one lab either: every multi-DC deployment applies this SQL by hand.
#
# ⚠️ A ONE-NODE TOPOLOGY, DELIBERATELY. N data centers means N*(N-1) subscriptions, and
# CREATE SUBSCRIPTION really dials the peer — with fake peers the setup half of this test
# would hang or fail on connection, which says nothing about --verify. With one node there
# are zero subscriptions and everything else (publication, map, triggers, the range guard)
# is exercised for real against a real database. The subscription checks are covered on the
# lab instead, where the peers exist.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
MESH="$ROOT/build/fastpki-mesh"
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

[ -x "$MESH" ] || { echo "SKIP: $MESH not built"; echo "PASS=0 FAIL=0"; exit 0; }

pg_setup mesh_verify
trap 'pg_cleanup' EXIT

PFX=7
cat > topo.txt <<EOF
dc1|host=127.0.0.1 dbname=$PGDATABASE user=$PGUSER sslmode=disable|$PFX|http://dc1.example
EOF

# `--allow-plaintext-transport` because this topology is a loopback fixture; the generator
# would otherwise inject sslmode=verify-full and refuse the explicit `disable`.
gen() { "$MESH" --topology topo.txt --allow-plaintext-transport "$@" 2>/dev/null; }

# How many problems does --verify report right now?
problems() {
    gen --node dc1 --verify > v.sql
    pg_exec_file v.sql 2>/dev/null | grep -cE '^\s*(publication|datacenters|trigger|function|subscription)' || true
}
# ...and the text, for asserting WHICH problem.
problem_text() { gen --node dc1 --verify > v.sql; pg_exec_file v.sql 2>/dev/null; }

# pg_helpers has pg_exec (a single statement); the generated script needs a file.
pg_exec_file() { PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" \
                   -d "$PGDATABASE" -v ON_ERROR_STOP=0 -f "$1"; }

echo "=== BEFORE the setup is applied, --verify must complain about everything ==="
# ⚠️ This is the assertion that makes the rest meaningful. A --verify that reports 0 on an
# EMPTY database would report 0 on the lab's broken node too, and would have been green
# for the exact bug that motivated the ticket.
BEFORE=$(problems)
chk "an unconfigured node reports problems" yes "$([ "${BEFORE:-0}" -gt 0 ] && echo yes || echo no)"
chk "  including the missing publication" yes \
    "$(problem_text | grep -q 'publication fastpki_pub' && echo yes || echo no)"
chk "  and the missing map row" yes \
    "$(problem_text | grep -q 'datacenters row for dc1' && echo yes || echo no)"

echo "=== apply the mesh setup, then --verify must be SILENT ==="
gen --publication > pub.sql; pg_exec_file pub.sql >/dev/null 2>&1
gen --map        > map.sql; pg_exec_file map.sql >/dev/null 2>&1
gen --node dc1   > node.sql; pg_exec_file node.sql >/dev/null 2>&1
chk "a fully applied node reports NOTHING" 0 "$(problems)"

echo "=== the bug that motivated the ticket: the --map preamble never applied ==="
pg_exec "DELETE FROM datacenters;" >/dev/null 2>&1
chk "the missing map row is reported" yes \
    "$(problem_text | grep -q 'datacenters row for dc1' && echo yes || echo no)"
pg_exec_file map.sql >/dev/null 2>&1
chk "  and it goes quiet once the map is applied" 0 "$(problems)"

echo "=== a trigger dropped by hand ==="
pg_exec "DROP TRIGGER IF EXISTS certs_skip_dup ON certs;" >/dev/null 2>&1
chk "the missing trigger is named" yes \
    "$(problem_text | grep -q 'trigger certs_skip_dup' && echo yes || echo no)"
pg_exec_file node.sql >/dev/null 2>&1
chk "  and restoring it clears the report" 0 "$(problems)"

echo "=== a table that fell out of the publication (the FROZEN-publication failure) ==="
# ⚠️ Per-table, not just "does the publication exist". A table added to kPublicTables after
# the initial setup does NOT join a live publication by itself — that is how the lab's
# publication stayed frozen at its first shape while every presence check passed.
pg_exec "ALTER PUBLICATION fastpki_pub DROP TABLE keys;" >/dev/null 2>&1
chk "the unpublished table is named" yes \
    "$(problem_text | grep -q 'publication table keys' && echo yes || echo no)"
chk "  and the publication ITSELF is not reported missing" no \
    "$(problem_text | grep -q 'publication fastpki_pub *|' && echo yes || echo no)"
pg_exec_file pub.sql >/dev/null 2>&1
chk "  re-running --publication fixes it" 0 "$(problems)"

echo "=== a prefix guard left over from an OLDER topology ==="
# Presence is not enough: the prefix is compiled into the function body at generation time,
# so a guard built for a different topology exists, fires, and enforces the WRONG partition.
# It has to be read back and compared.
#
# ⚠️ This cuts deeper than a stale peer view. The node reads its own row to learn
# the prefix it mints under, so a stale row moves the APP and the GUARD together, in step —
# which is exactly the kind of wrongness no comparison between the two could ever reveal.
cat > topo2.txt <<EOF
dc1|host=127.0.0.1 dbname=$PGDATABASE user=$PGUSER sslmode=disable|9|http://dc1.example
EOF
"$MESH" --topology topo2.txt --allow-plaintext-transport --node dc1 --verify 2>/dev/null > v2.sql
OUT2=$(pg_exec_file v2.sql 2>/dev/null)
chk "a stale guard prefix is detected" yes \
    "$(echo "$OUT2" | grep -q 'fastpki_dc_range_guard' && echo yes || echo no)"
chk "  and the stale map row too" yes \
    "$(echo "$OUT2" | grep -q 'datacenters prefix for dc1' && echo yes || echo no)"
# ⚠️ And the reverse, or the two assertions above prove only that --verify complains about
# SOMETHING. Re-run the ORIGINAL topology against the same database: it must be silent, so
# we know the two above fired on the prefix difference and not on unrelated drift.
chk "  while the topology it was built from stays silent" 0 "$(problems)"

echo "=== --verify refuses to guess which node it is checking ==="
# The bounds and the subscription set are per node, so verifying "the mesh" without a node
# would report another data center's expectations as this one's problems.
"$MESH" --topology topo.txt --allow-plaintext-transport --verify >/dev/null 2>err.txt
chk "--verify without --node is refused" yes \
    "$(grep -qi 'needs --node' err.txt && echo yes || echo no)"

echo
echo "=== MESH VERIFY: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
