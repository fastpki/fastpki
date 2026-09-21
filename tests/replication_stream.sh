#!/usr/bin/env bash
# Live active-active logical-replication proof. Spins up TWO throwaway
# wal_level=logical Postgres clusters (= two data centers), wires them with the
# real fastpki-mesh active-active mesh, and proves the properties the DDL-only
# tests cannot:
#   - a cert issued on node A streams to node B, and vice-versa (active-active);
#   - the tenant registry (ca_instances) replicates, but the per-CA signing key
#     does NOT (stays node-local);
#   - a FULL bidirectional partition: both nodes keep issuing while isolated,
#     neither sees the other's writes during the outage, and on heal BOTH sides
#     converge;
#   - one node's database replaced by a dump of itself (`fastpki-mesh --restore`)
#     converges with the newer rows of its peer and keeps what only the dump held.
#
# This is what proves the per-node serial-range guard is a TRIGGER, not a CHECK:
# a CHECK rejects replicated certs from other DCs' ranges and stalls the mesh.
#
# Self-contained: needs the Postgres server binaries (initdb/pg_ctl). Skips
# cleanly if they're absent.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
# NB --allow-plaintext-transport: fastpki-mesh refuses a topology whose conninfo
# does not request TLS, because inter-DC replication carries web_users (incl. the
# pbkdf2 password hash) and the conninfo embeds the replication password. These
# suites drive throwaway clusters on 127.0.0.1 — a genuinely closed link — so they
# take the documented override rather than weakening the guard. See mesh_tls.sh.
MESH="$ROOT/build/fastpki-mesh"

# macOS: a UTF-8 locale makes the postmaster spawn threads during startup and it
# dies with "postmaster became multithreaded during startup". Without this the
# whole suite silently SKIPped on Mac (it read as "no Postgres binaries") and we
# got zero replication coverage there. Harmless on Linux.
export LC_ALL=C

# Locate the Postgres server binaries.
PGBIN=""
if command -v pg_ctl >/dev/null 2>&1; then PGBIN="$(dirname "$(command -v pg_ctl)")"
else PGBIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)"; fi
if [ -z "$PGBIN" ] || [ ! -x "$PGBIN/initdb" ]; then
    echo "SKIP: Postgres server binaries (initdb/pg_ctl) not found"; exit 0
fi
source "$ROOT/tests/pg_priv.sh"

W="$(mktemp -d)"; PA=${PA:-16544}; PB=${PB:-16545}
# mktemp -d is 0700 root-owned, so the dropped-privilege server cannot create its
# data directory inside it. No-op unless we are root (tests/pg_priv.sh).
pg_own "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
psqlp(){ "$PGBIN/psql" -h 127.0.0.1 -p "$1" -U postgres -d pki -tAc "$2" 2>&1; }
A(){ psqlp "$PA" "$1"; }
B(){ psqlp "$PB" "$1"; }
waitp(){ local port="$1" q="$2" want="$3" i; for i in $(seq 1 20); do [ "$(psqlp "$port" "$q")" = "$want" ] && { echo yes; return; }; sleep 0.5; done; echo no; }
cleanup(){ pg_as "$PGBIN/pg_ctl" -D "$W/a_sb" -m immediate stop >/dev/null 2>&1; pg_as "$PGBIN/pg_ctl" -D "$W/a" -m immediate stop >/dev/null 2>&1; pg_as "$PGBIN/pg_ctl" -D "$W/b" -m immediate stop >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT

start_node(){ # <dir> <port>
  # ⚠️ DO NOT DISCARD initdb's OUTPUT. This used to be `>/dev/null 2>&1`, so a failing
  # initdb left no postgresql.conf, the append below reported "No such file or directory",
  # pg_ctl had nothing to start, and the suite exited 0 with "SKIP: could not start the
  # throwaway clusters" — a green run that had proven nothing about replication, with the
  # actual reason (a full disk, in the run that exposed this) thrown away. The binaries
  # being absent is a legitimate skip and is checked above; the binaries being PRESENT and
  # initdb failing is a fault, so say what went wrong and fail loudly.
  if ! pg_as "$PGBIN/initdb" -D "$1" -U postgres --auth=trust > "$W/initdb.$$.log" 2>&1; then
      echo "FAIL: initdb could not create the cluster at $1"
      sed 's/^/    initdb: /' "$W/initdb.$$.log"
      exit 1
  fi
  cat >> "$1/postgresql.conf" <<EOF
wal_level = logical
max_wal_senders = 10
max_replication_slots = 10
listen_addresses = '127.0.0.1'
port = $2
unix_socket_directories = '$1'
EOF
  pg_as "$PGBIN/pg_ctl" -D "$1" -l "$1/pg.log" start >/dev/null 2>&1
  local i; for i in $(seq 1 40); do "$PGBIN/pg_isready" -h 127.0.0.1 -p "$2" >/dev/null 2>&1 && break; sleep 0.5; done
  "$PGBIN/createdb" -h 127.0.0.1 -p "$2" -U postgres pki >/dev/null 2>&1
  "$PGBIN/psql" -h 127.0.0.1 -p "$2" -U postgres -d pki -f "$ROOT/sql/createdb.sql" >/dev/null 2>&1
}
echo "=== bring up two data centers (separate clusters) ==="
start_node "$W/a" "$PA"
start_node "$W/b" "$PB"
if ! "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PA" >/dev/null 2>&1 || ! "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PB" >/dev/null 2>&1; then
    echo "SKIP: could not start the throwaway clusters"; exit 0
fi

# ---- a PHYSICAL standby of node_a, built BEFORE the mesh creates its slots --------
# ⚠️ THAT ORDER IS THE PRODUCTION ORDER AND IT IS LOAD-BEARING. compose starts postgres,
# the standby seeds from it, and fastpki-mesh is applied later — so the standby always
# predates the logical slots. Build the standby AFTER the slots and its restart point is
# already past the WAL those slots still need; the sync worker then refuses forever with
#   "the remote slot needs WAL at LSN X ... but the standby has LSN Y"
# and no amount of waiting fixes it. Getting this backwards is an easy way to "prove"
# PG17 slot sync is broken when it is the test that is wrong.
PSB=${PSB:-16546}
SLOTSYNC=0
PGMAJ=$("$PGBIN/initdb" --version 2>/dev/null | sed 's/[^0-9]*\([0-9]*\).*/\1/')
if [ "${PGMAJ:-0}" -ge 17 ]; then
  SLOTSYNC=1
  pg_as "$PGBIN/pg_basebackup" -h 127.0.0.1 -p "$PA" -U postgres -D "$W/a_sb" -Fp -Xs -R -P \
      -C -S node_a_sb -d "host=127.0.0.1 port=$PA user=postgres dbname=pki" >/dev/null 2>&1
  cat >> "$W/a_sb/postgresql.conf" <<EOF
port = $PSB
unix_socket_directories = '$W/a_sb'
sync_replication_slots = on
hot_standby_feedback = on
hot_standby = on
EOF
  # Hold node_a's logical subscribers back until this standby has the WAL. Without it a
  # peer can consume past a position the standby never received, and a promote then
  # hands that peer a slot positioned AHEAD of the new primary's own WAL — measured to
  # deliver nothing, forever, with active=t and zero errors.
  # ⚠️ SEPARATE statements: psql sends one -c as an implicit transaction, and
  # ALTER SYSTEM refuses inside one. Sent together this failed silently and the
  # setting was never applied — the assertions below still passed, which is how a
  # broken setup can look like a working one.
  psqlp "$PA" "ALTER SYSTEM SET synchronized_standby_slots = 'node_a_sb'" >/dev/null 2>&1
  psqlp "$PA" "SELECT pg_reload_conf()" >/dev/null 2>&1
  pg_as "$PGBIN/pg_ctl" -D "$W/a_sb" -l "$W/a_sb/pg.log" start >/dev/null 2>&1
  for i in $(seq 1 40); do "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PSB" >/dev/null 2>&1 && break; sleep 0.5; done
else
  echo "  SKIP: failover-slot sync needs PostgreSQL 17+ (found ${PGMAJ:-unknown}) — those assertions NOT run"
fi

# Each node's 2-octet serial prefix. The nodes must differ, or the guard trigger on
# one would reject what the other minted the moment it was applied locally.
PFX_A=1
PFX_B=2
# ⚠️ Fixture serials must have the SHAPE THE PRODUCT MINTS, or the guard trigger rejects
# every local INSERT this suite makes and the whole thing reads as "replication is broken".
# A serial is 20 octets = 40 hex characters, and the node's prefix is the first four of
# them. `serial_for <prefix> <tail>` builds exactly that. Where a test helper has to differ
# from the product, the difference is the bug — so it does not differ.
serial_for(){ printf '%04x%036s' "$1" "$2" | tr ' ' '0'; }
sa(){ serial_for "$PFX_A" "$1"; }
sb(){ serial_for "$PFX_B" "$1"; }
S_A1=$(sa a1);   S_B1=$(sb b1)
S_A2=$(sa a2);   S_B2=$(sb b2)
S_A3=$(sa a3);   S_A4=$(sa a4);   S_A5=$(sa a5);   S_B5=$(sb b5)
S_ASSS=$(sa 555)
cat > "$W/topo.txt" <<EOF
node_a|host=127.0.0.1 port=$PA dbname=pki user=postgres|$PFX_A|http://node_a.example
node_b|host=127.0.0.1 port=$PB dbname=pki user=postgres|$PFX_B|http://node_b.example
EOF
# Pass 2 against a peer that has not published is refused. Emitted, its CREATE SUBSCRIPTION
# succeeds with only a warning, and on PostgreSQL 17 the subscription then fails on every
# change for good, even after the peer publishes.
"$MESH" --allow-plaintext-transport --topology "$W/topo.txt" --node node_a > "$W/early.out" 2> "$W/early.err"
chk "--node before the peer has published is refused" 2 "$?"
chk "  and says to run pass 1 there" yes \
    "$(grep -q "does not publish anything yet" "$W/early.err" && echo yes || echo no)"
chk "  and emits nothing" 0 "$(grep -c 'CREATE SUBSCRIPTION' "$W/early.out")"
"$MESH" --allow-plaintext-transport --topology "$W/topo.txt" --publication | "$PGBIN/psql" -h 127.0.0.1 -p "$PA" -U postgres -d pki >/dev/null 2>&1
"$MESH" --allow-plaintext-transport --topology "$W/topo.txt" --publication | "$PGBIN/psql" -h 127.0.0.1 -p "$PB" -U postgres -d pki >/dev/null 2>&1
"$MESH" --allow-plaintext-transport --topology "$W/topo.txt" --node node_a | "$PGBIN/psql" -h 127.0.0.1 -p "$PA" -U postgres -d pki > "$W/a.out" 2>&1
"$MESH" --allow-plaintext-transport --topology "$W/topo.txt" --node node_b | "$PGBIN/psql" -h 127.0.0.1 -p "$PB" -U postgres -d pki > "$W/b.out" 2>&1
chk "mesh DDL applied without errors" 0 "$(cat "$W/a.out" "$W/b.out" | grep -c ERROR)"

# Re-apply verbatim. The whole point of the converge rework is that this DDL is safe to
# run again on an already-meshed cluster -- that is how a table added later starts
# replicating. It was NOT safe: CREATE SUBSCRIPTION and ALTER SUBSCRIPTION ... REFRESH
# are both illegal inside the DO block it used to emit, so a fresh mesh never formed and
# an existing one never picked anything up. Both failures are invisible unless you grep
# psql's output, which nothing did. This assertion is the grep.
"$MESH" --allow-plaintext-transport --topology "$W/topo.txt" --node node_a | "$PGBIN/psql" -h 127.0.0.1 -p "$PA" -U postgres -d pki > "$W/a2.out" 2>&1
"$MESH" --allow-plaintext-transport --topology "$W/topo.txt" --node node_b | "$PGBIN/psql" -h 127.0.0.1 -p "$PB" -U postgres -d pki > "$W/b2.out" 2>&1
chk "mesh DDL is idempotent (re-apply is clean)" 0 "$(cat "$W/a2.out" "$W/b2.out" | grep -c ERROR)"
sleep 3

echo "=== active-active streaming ==="
A "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('$S_A1',0,'host-a.internal',NULL);" >/dev/null
chk "cert issued on node_a appears on node_b" yes "$(waitp "$PB" "select count(*) from certs where serial='$S_A1'" 1)"
B "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('$S_B1',0,'host-b.internal',NULL);" >/dev/null
chk "cert issued on node_b appears on node_a" yes "$(waitp "$PA" "select count(*) from certs where cn='host-b.internal'" 1)"

if [ "$SLOTSYNC" = 1 ]; then
echo "=== node_a's failover slot syncs to its standby and SURVIVES a promote ==="
SB(){ psqlp "$PSB" "$1"; }
# node_b's subscription to node_a owns the slot `sub_node_b_from_node_a` ON node_a, and
# it is a REAL walsender that keeps advancing — which is required. PG17 will not promote
# a synced slot out of TEMPORARY while the remote slot's position has not moved, so a
# slot nobody consumes never persists and is lost on promote. That is why this proof
# lives here, next to a live subscription, and not in ha_failover.sh.
SLOT=sub_node_b_from_node_a
# ⚠️ THE GENERATOR ASSERTION. This is what src/tools/mesh.cpp's `failover = true` buys:
# an unflagged slot is silently ignored by sync_replication_slots — the primary reports
# a healthy slot, the standby reports clean streaming, and the DC leaves the mesh
# exactly one promote later.
chk "the mesh created it as a FAILOVER slot" t \
    "$(A "SELECT failover FROM pg_replication_slots WHERE slot_name='$SLOT'")"
chk "  and node_b's subscription agrees" t \
    "$(B "SELECT subfailover FROM pg_subscription WHERE subname='$SLOT'")"

# POLL — persistence is not bounded (measured 0.6s to 6.8s on identical setups).
SY=no
for i in $(seq 1 60); do
  [ "$(SB "SELECT count(*) FROM pg_replication_slots WHERE slot_name='$SLOT' AND synced AND NOT temporary")" = "1" ] \
      && { SY=yes; break; }
  sleep 0.5
done
# temporary=false is the crux, NOT synced=true: PG17 creates a synced slot TEMPORARY and
# a temporary slot is dropped when the sync worker exits — which is what promotion does.
chk "the slot reached the standby, synced and PERSISTED" yes "$SY"
[ "$SY" = yes ] || { SB "SELECT slot_name,temporary,synced,confirmed_flush_lsn FROM pg_replication_slots" | sed 's/^/    /'
                     grep -iE 'sync|slot' "$W/a_sb/pg.log" 2>/dev/null | tail -6 | sed 's/^/    /'; }

# ⚠️ WATCHED FAILING: revert mesh.cpp's `failover = true`, or any one of -C -S /
# sync_replication_slots / hot_standby_feedback / the dbname in primary_conninfo, and
# the slot count below is 0. That is the failure exactly — the node keeps serving and has
# silently stopped feeding its peers.
pg_as "$PGBIN/pg_ctl" -D "$W/a_sb" promote >/dev/null 2>&1
for i in $(seq 1 40); do [ "$(SB "SELECT pg_is_in_recovery()")" = "f" ] && break; sleep 0.5; done
chk "the standby promoted to read-write" f "$(SB "SELECT pg_is_in_recovery()")"
chk "the failover slot SURVIVED the promotion" 1 \
    "$(SB "SELECT count(*) FROM pg_replication_slots WHERE slot_name='$SLOT' AND NOT temporary")"
chk "  and it is not invalidated" 0 \
    "$(SB "SELECT count(*) FROM pg_replication_slots WHERE slot_name='$SLOT' AND (conflicting IS TRUE OR wal_status='lost')")"
# The inheritance trap: synchronized_standby_slots came across in the basebackup and
# names a physical slot this node does not have. Left set, every logical walsender here
# waits forever on it — slot present, active, moving nothing.
# ⚠️ THE INVARIANT, not the literal value: whatever synchronized_standby_slots names on
# a node, that slot must EXIST there — otherwise every logical walsender on it waits
# forever on a slot that is never coming, and the only trace is a WARNING nobody tails.
# A promoted node inherits the setting through pg_basebackup while inheriting none of
# the standby's slots, which is why deploy/pg-promote.sh clears it.
SSS=$(SB "SHOW synchronized_standby_slots")
chk "the promoted node names no slot it does not have" yes \
    "$([ -z "$SSS" ] && echo yes || echo "$(SB "SELECT CASE WHEN count(*)=1 THEN 'yes' ELSE 'no' END FROM pg_replication_slots WHERE slot_name='$SSS'")")"

# ---- RESTORE, or the rest of this suite runs against a stalled mesh ------------------
# ⚠️ THIS IS THE AVAILABILITY COST OF synchronized_standby_slots, and it is not
# hypothetical: promoting a_sb leaves node_a's physical slot node_a_sb permanently
# inactive, so node_a's logical walsenders HOLD every change back waiting for a standby
# that will never consume again. Four later assertions in this file failed that way
# before this block existed. The same is true in production — if a DC's standby is gone
# for good, clear the setting or that DC stops feeding its peers.
pg_as "$PGBIN/pg_ctl" -D "$W/a_sb" -m immediate stop >/dev/null 2>&1
psqlp "$PA" "ALTER SYSTEM SET synchronized_standby_slots = ''" >/dev/null 2>&1
psqlp "$PA" "SELECT pg_reload_conf()" >/dev/null 2>&1
psqlp "$PA" "SELECT pg_drop_replication_slot('node_a_sb') FROM pg_replication_slots WHERE slot_name='node_a_sb' AND NOT active;" >/dev/null 2>&1
# ⚠️ ASSERT DELIVERY, NOT LIVENESS. The earlier version checked the slot was `active`,
# which stayed true while node_a delivered nothing — synchronized_standby_slots still
# named the physical slot just dropped, so every logical walsender waited forever. That
# green assertion sat directly above 17 red ones. Write a row and watch it ARRIVE.
A "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('$S_ASSS',0,'sss-cleared.internal',NULL);" >/dev/null
chk "node_a resumes FEEDING its peers once the dead standby is released" yes \
    "$(waitp "$PB" "select count(*) from certs where serial='$S_ASSS'" 1)"
fi

echo "=== CA certificates replicate, the private key stays node-local ==="
# Removed ca_instances: a CA is a row of `certs` carrying is_ca, with its key
# reference in certs.private_key. The property under test is exactly the one this block
# always asserted -- every DC holds every CA CERTIFICATE, no DC holds another node's KEY
# -- but it had to move to the surviving table. It asserted against the dropped one until
# now, which is part of why this suite was red.
# ⚠️ Deliberately NOT a prefixed serial. is_ca=true, so the guard trigger exempts
# it — which is the shape of a CA this node imported or one signed by an offline root. If
# that exemption ever regressed, this INSERT would fail and the assertions below go red.
A "INSERT INTO certs(serial,status,cn,subject,cert,is_ca,private_key) VALUES('a1ca',0,'Dept A CA','CN=Dept A CA',decode('43455254','hex'),true,'pkcs11:object=deptA-key') ON CONFLICT (serial) DO NOTHING;" >/dev/null
chk "CA row appears on node_b" yes "$(waitp "$PB" "select count(*) from certs where cn='Dept A CA'" 1)"
chk "the CA certificate replicated"        "CERT" "$(B "select encode(cert,'escape') from certs where cn='Dept A CA';")"
chk "the CA private key did NOT replicate" ""     "$(B "select coalesce(private_key,'') from certs where cn='Dept A CA';")"

echo "=== FULL bidirectional partition -> heal ==="
A "ALTER SUBSCRIPTION sub_node_a_from_node_b DISABLE;" >/dev/null
B "ALTER SUBSCRIPTION sub_node_b_from_node_a DISABLE;" >/dev/null
A "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('$S_A2',0,'iso-a.internal',NULL);" >/dev/null
B "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('$S_B2',0,'iso-b.internal',NULL);" >/dev/null
chk "node_a can still issue while isolated" 1 "$(A "select count(*) from certs where cn='iso-a.internal';")"
chk "node_b can still issue while isolated" 1 "$(B "select count(*) from certs where cn='iso-b.internal';")"
sleep 2
chk "isolated: node_a's cert NOT on node_b" 0 "$(B "select count(*) from certs where cn='iso-a.internal';")"
chk "isolated: node_b's cert NOT on node_a" 0 "$(A "select count(*) from certs where cn='iso-b.internal';")"
A "ALTER SUBSCRIPTION sub_node_a_from_node_b ENABLE;" >/dev/null
B "ALTER SUBSCRIPTION sub_node_b_from_node_a ENABLE;" >/dev/null
chk "after heal: node_b received node_a's isolated cert" yes "$(waitp "$PB" "select count(*) from certs where cn='iso-a.internal'" 1)"
chk "after heal: node_a received node_b's isolated cert" yes "$(waitp "$PA" "select count(*) from certs where cn='iso-b.internal'" 1)"
chk "both nodes converged to the same cert count" "$(A "select count(*) from certs;")" "$(B "select count(*) from certs;")"
chk "no apply errors on node_b (a CHECK would stall here)" "0|0" \
    "$(B "select apply_error_count||'|'||sync_error_count from pg_stat_subscription_stats;")"

echo "=== Data center FULLY OFFLINE (node down, not just unsubscribed) ==="
# Distinct failure mode from the partition above: there the peer is ALIVE and we
# only disable the subscriptions. Here node_b's whole cluster is STOPPED, so the
# subscriber cannot connect at all and node_a's replication slot has to buffer WAL
# for it. Proven on the 3-DC lab (a `docker compose stop` of a whole DC:
# survivors kept issuing, slots held ~6.4 KB, and the DC drained it on restart).
# Regression risk this guards: a dead peer must NOT stall the survivors, and the
# slot must NOT be dropped (dropping it loses the backlog -> permanent divergence,
# because subscriptions are created copy_data=false and never backfill).
pg_as "$PGBIN/pg_ctl" -D "$W/b" -m fast stop >/dev/null 2>&1
chk "node_b is actually down" no \
    "$("$PGBIN/pg_isready" -h 127.0.0.1 -p "$PB" >/dev/null 2>&1 && echo yes || echo no)"
# The survivor must keep issuing with a dead peer.
A "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('$S_A5',0,'offline-a.internal',NULL);" >/dev/null
chk "node_a still issues while node_b is DOWN" 1 "$(A "select count(*) from certs where cn='offline-a.internal';")"
# node_b's slot (it lives on the publisher, node_a) must go inactive but SURVIVE,
# retaining the WAL that node_b has not consumed yet.
chk "node_b's slot on node_a is inactive"  f "$(A "select active from pg_replication_slots where slot_name='sub_node_b_from_node_a';")"
chk "node_b's slot still EXISTS (backlog retained, not dropped)" 1 \
    "$(A "select count(*) from pg_replication_slots where slot_name='sub_node_b_from_node_a';")"
chk "slot is retaining WAL for the dead node" yes \
    "$(A "select (restart_lsn is not null)::int from pg_replication_slots where slot_name='sub_node_b_from_node_a';" | grep -q 1 && echo yes || echo no)"
# Bring it back: the buffered backlog must drain without operator intervention.
pg_as "$PGBIN/pg_ctl" -D "$W/b" -l "$W/b/pg.log" start >/dev/null 2>&1
for i in $(seq 1 40); do "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PB" >/dev/null 2>&1 && break; sleep 0.5; done
chk "node_b is back up" yes \
    "$("$PGBIN/pg_isready" -h 127.0.0.1 -p "$PB" >/dev/null 2>&1 && echo yes || echo no)"
chk "recovered node_b caught up on the cert issued while it was down" yes \
    "$(waitp "$PB" "select count(*) from certs where cn='offline-a.internal'" 1)"
# ...and replication must be bidirectional again, not just inbound.
B "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('$S_B5',0,'offline-b.internal',NULL);" >/dev/null
chk "recovered node_b can issue and reach node_a" yes \
    "$(waitp "$PA" "select count(*) from certs where cn='offline-b.internal'" 1)"
chk "both nodes converged after the outage" "$(A "select count(*) from certs;")" "$(B "select count(*) from certs;")"
# Killing node_b mid-stream makes node_a's apply worker log a transient
# "could not send end-of-streaming message to primary" and bump apply_error_count.
# That is the OUTAGE we just staged, not an apply failure, and the later
# section asserts a cumulative 0|0 — so clear the counters here to keep that
# assertion meaningful. Convergence above is what proves the outage was handled.
A "select pg_stat_reset_subscription_stats(NULL);" >/dev/null 2>&1
B "select pg_stat_reset_subscription_stats(NULL);" >/dev/null 2>&1

echo "=== cert_uris: the RFC 4387 uri side-table replicates with the cert ==="
A "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('$S_A4',0,'uri-host.internal',NULL);" >/dev/null
A "INSERT INTO cert_uris(serial,uri) VALUES('$S_A4','https://uri-host.internal/id/1');" >/dev/null
chk "cert_uri row replicated to node_b" yes "$(waitp "$PB" "select count(*) from cert_uris where serial='$S_A4'" 1)"

echo "=== idempotent apply: a duplicate cert (backfill/re-sync) is skipped, not stalled ==="
# Pre-seed node_b with a serial node_a is about to mint+replicate — mimics a
# backfill where the row already exists on the subscriber. Without certs_skip_dup
# the apply worker crash-loops on the duplicate PK and stalls the whole mesh.
SDUP=$(sa dd)   # node_a mints it, so it carries node_a's prefix
B "SET session_replication_role='replica'; INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('$SDUP',0,'dup.internal',NULL);" >/dev/null
A "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('$SDUP',0,'dup.internal',NULL);" >/dev/null
sleep 2
# A later cert from node_a must still arrive -> proves the worker didn't stall.
A "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('$S_A3',0,'after-dup.internal',NULL);" >/dev/null
chk "apply continues past the duplicate (later cert reaches node_b)" yes "$(waitp "$PB" "select count(*) from certs where cn='after-dup.internal'" 1)"
chk "still no apply errors after the duplicate" "0|0" \
    "$(B "select apply_error_count||'|'||sync_error_count from pg_stat_subscription_stats where subname='sub_node_b_from_node_a';")"

echo "=== CONSOLE USERS replicate cluster-wide: identity, ROLE, SCOPE and PASSWORD ==="
# A user is only usable on another DC if the whole credential travels — the pbkdf2
# hash included. Asserting merely "a row appeared" would pass even if the password
# or role were dropped, and the operator would find out by failing to log in.
# (This is what makes an admin created on DC1 able to sign in on DC2/DC3; verified
# live on the 3-DC lab.) Contrast ca_instances below, where the signing
# key deliberately does NOT travel.
A "INSERT INTO web_users(username,role,hash) VALUES('carol','auditor','pbkdf2\$210000\$deadbeefcafe');" >/dev/null
chk "user row reaches node_b"            yes "$(waitp "$PB" "select count(*) from web_users where username='carol'" 1)"
chk "  role replicated"              auditor "$(B "select role from web_users where username='carol';")"
chk "  PASSWORD HASH replicated intact" 'pbkdf2$210000$deadbeefcafe' \
    "$(B "select hash from web_users where username='carol';")"
chk "  hash is byte-identical on both nodes" yes \
    "$([ "$(A "select md5(hash) from web_users where username='carol';")" = \
        "$(B "select md5(hash) from web_users where username='carol';")" ] && echo yes || echo no)"
# ...and in the other direction, so this isn't one-way.
B "INSERT INTO web_users(username,role,hash) VALUES('dave','admin','pbkdf2\$210000\$0badc0de');" >/dev/null
chk "a user created on node_b reaches node_a" yes "$(waitp "$PA" "select count(*) from web_users where username='dave'" 1)"
chk "  ...with its role"                admin "$(A "select role from web_users where username='dave';")"
# A password CHANGE must propagate too — otherwise a rotated credential still works
# on the peer, or the user is locked out there.
B "UPDATE web_users SET hash='pbkdf2\$210000\$rotated' WHERE username='dave';" >/dev/null
chk "a password change propagates" 'pbkdf2$210000$rotated' \
    "$(waitp "$PA" "select hash from web_users where username='dave'" 'pbkdf2$210000$rotated' >/dev/null; A "select hash from web_users where username='dave';")"
# Deleting a user must revoke them cluster-wide, not just locally.
A "DELETE FROM web_users WHERE username='carol';" >/dev/null
chk "a deleted user is removed cluster-wide" yes "$(waitp "$PB" "select count(*) from web_users where username='carol'" 0)"
# The other admin tables ride the same mechanism.
A "INSERT INTO subject_roles(selector_type,selector_value,role) VALUES('user','dave','auditor');" >/dev/null
chk "subject_roles (extra console roles) replicate" yes \
    "$(waitp "$PB" "select count(*) from subject_roles where selector_value='dave'" 1)"
A "INSERT INTO allowed_domains(domain) VALUES('replicated.example');" >/dev/null
chk "allowed_domains replicate" yes \
    "$(waitp "$PB" "select count(*) from allowed_domains where domain='replicated.example'" 1)"

echo "=== Admin tables replicate cluster-wide with last-writer-wins ==="
# Basic: a user created on node_a reaches node_b.
A "INSERT INTO web_users(username,role,hash) VALUES('alice','requester','h0');" >/dev/null
chk "web_users row replicates node_a -> node_b" yes "$(waitp "$PB" "select count(*) from web_users where username='alice'" 1)"
# The local stamp trigger populated updated (>0) so LWW has an ordering key.
# ⚠️ COMPARE THE VALUE, DO NOT grep FOR A DIGIT. psqlp() folds stderr into its output
# (`-tAc "$2" 2>&1`), and psql reports a statement error over two lines, the second being
# `LINE 1: select (updated>0)…`. `grep -q 1` matched the 1 in "LINE 1", so dropping or
# renaming web_users.updated — the column-shape failure that stalls an apply worker with
# "target relation is missing replicated column" — printed PASS while nothing had stamped
# anything. A failed connection did the same, via the port number in psql's error.
chk "local write stamped updated>0" 1 \
    "$(A "select (updated>0)::int from web_users where username='alice';")"

# Conflict resolution during a partition. Disable both directions, write
# conflicting rows on each node (node_b writes LATER, so its timestamp is newer),
# heal, and confirm the newer write wins on BOTH nodes without stalling.
A "ALTER SUBSCRIPTION sub_node_a_from_node_b DISABLE;" >/dev/null
B "ALTER SUBSCRIPTION sub_node_b_from_node_a DISABLE;" >/dev/null
# INSERT/INSERT conflict on a brand-new username.
A "INSERT INTO web_users(username,role,hash) VALUES('bob','requester','hA');" >/dev/null
# UPDATE/UPDATE conflict on the existing 'alice'.
# ⚠️ THE TWO SIDES MUST WRITE DIFFERENT VALUES, or neither assertion below can fail. Both
# wrote 'auditor', which is also what both checks expect — so 'auditor' was the only value
# the row could hold afterwards, whichever write survived. Deleting the last-writer-wins
# trigger, inverting it so the OLDER stamp wins, or never enabling node_a's subscription at
# all left both checks printing PASS. The INSERT pair above is the only half that ever
# discriminated, because there the nodes write 'requester' and 'admin'. alice starts as
# 'requester' (line 374), so node_a's older write has to be a third distinct value: if the
# older write wins, the role reads 'admin' and both checks go red, which is the point.
A "UPDATE web_users SET role='admin' WHERE username='alice';" >/dev/null
sleep 1   # ensure node_b's writes get a strictly newer microsecond stamp
B "INSERT INTO web_users(username,role,hash) VALUES('bob','admin','hB');" >/dev/null
B "UPDATE web_users SET role='auditor' WHERE username='alice';" >/dev/null
A "ALTER SUBSCRIPTION sub_node_a_from_node_b ENABLE;" >/dev/null
B "ALTER SUBSCRIPTION sub_node_b_from_node_a ENABLE;" >/dev/null
sleep 3
chk "LWW INSERT: newer node_b 'bob' (admin) wins on node_a" admin "$(A "select role from web_users where username='bob';")"
chk "LWW INSERT: node_b keeps its own newer 'bob' (admin)"  admin "$(B "select role from web_users where username='bob';")"
chk "LWW UPDATE: newer node_b 'alice' (auditor) wins on node_a" auditor \
    "$(A "select role from web_users where username='alice';")"
chk "LWW UPDATE: node_b keeps its own newer 'alice'"        auditor \
    "$(B "select role from web_users where username='alice';")"
chk "no apply errors on node_a after the conflicts" "0|0" \
    "$(A "select apply_error_count||'|'||sync_error_count from pg_stat_subscription_stats where subname='sub_node_a_from_node_b';")"
chk "no apply errors on node_b after the conflicts" "0|0" \
    "$(B "select apply_error_count||'|'||sync_error_count from pg_stat_subscription_stats where subname='sub_node_b_from_node_a';")"

# config stays node-local: it is NOT in the publication, so a config write on one
# node must NOT cross to the other.
A "INSERT INTO config(key,value,updated) VALUES('DATACENTER_ID','node_a',0) ON CONFLICT (key) DO UPDATE SET value='node_a';" >/dev/null
sleep 2
chk "config is DC-local (not replicated)" 0 "$(B "select count(*) from config where key='DATACENTER_ID';")"
# ⚠️ AND CERTIFICATE PROFILES ARE NOT CONFIG. They were a config key, so a profile stayed on
# the node where it was edited while the role grants naming it replicated. A profile row
# written on node_a must reach node_b, and deleting it there must follow.
A "INSERT INTO cert_profiles(name,definition) VALUES('replprof','{\"allowed_ku\":[\"digitalSignature\"]}');" >/dev/null
chk "a certificate profile replicates node_a -> node_b" yes \
    "$(waitp "$PB" "select count(*) from cert_profiles where name='replprof'" 1)"
chk "  stamped for last-writer-wins" 1 "$(A "select (updated>0)::int from cert_profiles where name='replprof';")"
A "DELETE FROM cert_profiles WHERE name='replprof';" >/dev/null
chk "  and its deletion follows" yes "$(waitp "$PB" "select count(*) from cert_profiles where name='replprof'" 0)"

echo "=== the same certificate written on two nodes: identity and status merge ==="
# A CA request is signed on one node, which records the certificate with no id; the node
# holding the key registers the CA on its own copy. In a mesh bootstrap both happen before
# replication, and certs_skip_dup used to keep whichever row a node had: the signer never
# learned the CA's identity and a revocation on either copy never reached the other.
# is_ca rows throughout, so the per-node serial guard does not apply to either insert.
A "ALTER SUBSCRIPTION sub_node_a_from_node_b DISABLE;" >/dev/null
B "ALTER SUBSCRIPTION sub_node_b_from_node_a DISABLE;" >/dev/null
CERTX="decode('5355424341','hex')"
A "INSERT INTO certs(serial,status,cn,cert,is_ca,ca_instance_id) VALUES('m1',0,'Sub CA M',$CERTX,true,'a1ca');" >/dev/null
B "INSERT INTO certs(serial,status,cn,cert,is_ca,ca_instance_id,id,name,ca_enabled,private_key)
   VALUES('m1',0,'Sub CA M',$CERTX,true,'subm','subm','Sub M',true,'pkcs11:object=subm');" >/dev/null
A "INSERT INTO certs(serial,status,cn,cert,is_ca) VALUES('m2',0,'Revoked on B',$CERTX,true);" >/dev/null
B "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",cn,cert,is_ca) VALUES('m2',-1,1,1700000002,'Revoked on B',$CERTX,true);" >/dev/null
A "INSERT INTO certs(serial,status,cn,cert,is_ca) VALUES('m3',3,'Superseded on A',$CERTX,true);" >/dev/null
B "INSERT INTO certs(serial,status,cn,cert,is_ca) VALUES('m3',0,'Superseded on A',$CERTX,true);" >/dev/null
# A hold and its release are the one revocation state that goes BOTH ways, so between them the
# later "revocationDate" has to win — and a revocation for good has to win over either.
#   m4  hold on A at t10, release on B at t20   -> released on both
#   m5  release on B at t20, hold on A at t30   -> on hold on both
#   m6  hold on A at t40, revoked for good on B at t35 -> revoked on both (final beats a later hold)
ins_rev(){ # node serial status reason date
  "$1" "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",cn,cert,is_ca) VALUES('$2',$3,$4,$5,'Hold $2',$CERTX,true);" >/dev/null; }
ins_rev A m4 -1 6 1700000010; ins_rev B m4 0 8 1700000020
ins_rev A m5 -1 6 1700000030; ins_rev B m5 0 8 1700000020
ins_rev A m6 -1 6 1700000040; ins_rev B m6 -1 1 1700000035
A "ALTER SUBSCRIPTION sub_node_a_from_node_b ENABLE;" >/dev/null
B "ALTER SUBSCRIPTION sub_node_b_from_node_a ENABLE;" >/dev/null
chk "the signer's plain record adopts the CA identity registered on the peer" yes \
    "$(waitp "$PA" "select coalesce(id,'')||'|'||ca_instance_id||'|'||name from certs where serial='m1'" 'subm|subm|Sub M')"
chk "  the peer keeps its registration" "subm" "$(B "select id from certs where serial='m1';")"
chk "  and the key reference stays on the node that has the key" "" \
    "$(A "select coalesce(private_key,'') from certs where serial='m1';")"
chk "a revocation on either copy holds on both" "-1 -1" \
    "$(waitp "$PA" "select status from certs where serial='m2'" -1 >/dev/null; A "select status from certs where serial='m2';") $(B "select status from certs where serial='m2';")"
chk "a supersession on either copy holds on both" "3 3" \
    "$(waitp "$PB" "select status from certs where serial='m3'" 3 >/dev/null; A "select status from certs where serial='m3';") $(B "select status from certs where serial='m3';")"
st_of(){ "$1" "select status||'/'||\"revocationReason\" from certs where serial='$2';"; }
chk "a release later than the hold wins on both copies" "0/8 0/8" \
    "$(waitp "$PA" "select status from certs where serial='m4'" 0 >/dev/null; st_of A m4) $(st_of B m4)"
chk "a hold later than the release wins on both copies" "-1/6 -1/6" \
    "$(waitp "$PB" "select status||'/'||\"revocationReason\" from certs where serial='m5'" '-1/6' >/dev/null; st_of A m5) $(st_of B m5)"
chk "a revocation for good beats even a later hold" "-1/1 -1/1" \
    "$(waitp "$PA" "select \"revocationReason\" from certs where serial='m6'" 1 >/dev/null; st_of A m6) $(st_of B m6)"
chk "no apply errors from the merges" "0|0 0|0" \
    "$(A "select apply_error_count||'|'||sync_error_count from pg_stat_subscription_stats where subname='sub_node_a_from_node_b';") $(B "select apply_error_count||'|'||sync_error_count from pg_stat_subscription_stats where subname='sub_node_b_from_node_a';")"
A "DELETE FROM certs WHERE serial IN ('m1','m2','m3','m4','m5','m6');" >/dev/null

echo "=== ONE data center restored from a dump (fastpki-mesh --restore) ==="
# node_b's database is replaced by a dump of itself while node_a keeps serving. What makes
# this more than "load the dump" is that node_a's rows are NEWER than the dump, so each
# fixture below is a row the naive restore gets wrong:
#   S_RB    revoked on node_a AFTER the dump     -> must be revoked on node_b (skip-dup would keep valid)
#   gone    deleted on node_a AFTER the dump     -> must NOT come back on node_b
#   S_RA    revoked on node_b, never reached node_a, in the dump -> revoked everywhere
#   S_BO    issued on node_b, never reached node_a, in the dump  -> present everywhere
#   S_SU    superseded on node_b (a renewal), never reached node_a, in the dump -> superseded
#           everywhere; left live, a service would meet two credentials for one cert_id
#   b2ca    node_b's CA row: its key reference is node-local and only the dump has it
RS="$W/restore-b.sql"
# Every node of a real mesh carries the data-center map (docs/deployment.md §9.1 pass 1); this
# suite skipped it until now, and --verify on node_a below asks for it.
"$MESH" --allow-plaintext-transport --topology "$W/topo.txt" --map | "$PGBIN/psql" -h 127.0.0.1 -p "$PA" -U postgres -d pki >/dev/null 2>&1
"$MESH" --allow-plaintext-transport --topology "$W/topo.txt" --node node_b --restore > "$RS" 2>/dev/null
run_step(){ # <port> <node> <step>
  "$PGBIN/psql" -h 127.0.0.1 -p "$1" -U postgres -d pki -v node="$2" -v step="$3" -f "$RS" \
      > "$W/rs-$2-$3.out" 2>&1
}
CNT0=$(B "select count(*) from certs;")
"$PGBIN/psql" -h 127.0.0.1 -p "$PB" -U postgres -d pki -f "$RS" > "$W/rs-none.out" 2>&1
chk "without -v node and -v step the file changes nothing" "$CNT0" "$(B "select count(*) from certs;")"
chk "  and says how to run it" yes "$(grep -q 'Run with -v node=' "$W/rs-none.out" && echo yes || echo no)"
run_step "$PA" node_a rebuild
chk "rebuild on a node that is not the one restored is refused" yes \
    "$(grep -q 'does not run on data center' "$W/rs-node_a-rebuild.out" && echo yes || echo no)"

S_RA=$(sa ra1); S_RB=$(sb rb1); S_BO=$(sb b0); S_AR=$(sa ar1); S_BR=$(sb br1); S_SU=$(sb 5u1)
B "INSERT INTO certs(serial,status,cn,is_ca,private_key) VALUES('b2ca',0,'Dept B CA',true,'pkcs11:object=deptB-key');" >/dev/null
A "INSERT INTO certs(serial,status,cn) VALUES('$S_RA',0,'rev-in-dump.internal');" >/dev/null
B "INSERT INTO certs(serial,status,cn) VALUES('$S_RB',0,'rev-after-dump.internal');" >/dev/null
B "INSERT INTO certs(serial,status,cn,cert_id) VALUES('$S_SU',0,'renewed-in-dump.internal','svc-b');" >/dev/null
A "INSERT INTO web_users(username,role,hash) VALUES('gone','auditor','h');" >/dev/null
chk "fixture: rows exchanged before the dump" "yes yes yes" \
    "$(waitp "$PB" "select count(*) from certs where serial='$S_RA'" 1) $(waitp "$PA" "select count(*) from certs where serial in ('$S_RB','b2ca','$S_SU')" 3) $(waitp "$PB" "select count(*) from web_users where username='gone'" 1)"
# node_a stops hearing from node_b; node_b still hears node_a.
A "ALTER SUBSCRIPTION sub_node_a_from_node_b DISABLE;" >/dev/null
B "UPDATE certs SET status=-1, \"revocationReason\"=1, \"revocationDate\"=1700000000 WHERE serial='$S_RA';" >/dev/null
B "UPDATE certs SET status=3 WHERE serial='$S_SU';" >/dev/null
B "INSERT INTO certs(serial,status,cn,ins_seq) VALUES('$S_BO',0,'only-in-dump.internal',(2::bigint<<48)|500);" >/dev/null
"$PGBIN/pg_dump" -h 127.0.0.1 -p "$PB" -U postgres pki > "$W/b.sql" 2>"$W/dump.err"
chk "fixture: node_b dumped" yes "$([ -s "$W/b.sql" ] && echo yes || echo no)"
A "UPDATE certs SET status=-1, \"revocationReason\"=4, \"revocationDate\"=1700000001 WHERE serial='$S_RB';" >/dev/null
A "DELETE FROM web_users WHERE username='gone';" >/dev/null
chk "fixture: node_a's changes after the dump reached node_b" yes \
    "$(waitp "$PB" "select count(*) from web_users where username='gone'" 0)"

run_step "$PA" node_a detach
run_step "$PB" node_b detach
chk "detach ran clean on both nodes" 0 "$(cat "$W/rs-node_a-detach.out" "$W/rs-node_b-detach.out" | grep -c ERROR)"
"$PGBIN/dropdb" -h 127.0.0.1 -p "$PB" -U postgres pki > "$W/dropdb.out" 2>&1; RC=$?
chk "node_b's database can be dropped: no subscription or slot holds it" 0 "$RC"
[ "$RC" = 0 ] || sed 's/^/    /' "$W/dropdb.out"
"$PGBIN/createdb" -h 127.0.0.1 -p "$PB" -U postgres pki >/dev/null 2>&1
grep -viE '^[[:space:]]*(DROP|CREATE|ALTER)[[:space:]]+(SUBSCRIPTION|PUBLICATION)([[:space:]]|$)' "$W/b.sql" \
  | "$PGBIN/psql" -h 127.0.0.1 -p "$PB" -U postgres -d pki -v ON_ERROR_STOP=1 --single-transaction -q -f - \
      > "$W/load.out" 2>&1; RC=$?
chk "the dump loads into the new database" 0 "$RC"
run_step "$PB" node_b rebuild
chk "rebuild ran clean" 0 "$(grep -c ERROR "$W/rs-node_b-rebuild.out")"
grep ERROR "$W/rs-node_b-rebuild.out" | head -3 | sed 's/^/    /'
run_step "$PA" node_a resubscribe
chk "resubscribe ran clean" 0 "$(grep -c ERROR "$W/rs-node_a-resubscribe.out")"
run_step "$PB" node_b finish
chk "finish ran clean" 0 "$(grep -c ERROR "$W/rs-node_b-finish.out")"
grep ERROR "$W/rs-node_b-finish.out" | head -3 | sed 's/^/    /'
run_step "$PA" node_a resubscribe
chk "a second resubscribe is refused, not silently skipped" yes \
    "$(grep -q 'already exists' "$W/rs-node_a-resubscribe.out" && echo yes || echo no)"

chk "a revocation made elsewhere after the dump holds on node_b" -1 "$(B "select status from certs where serial='$S_RB';")"
chk "a user deleted elsewhere after the dump does not come back" 0 "$(B "select count(*) from web_users where username='gone';")"
chk "a revocation only the dump held is back on node_b" -1 "$(B "select status from certs where serial='$S_RA';")"
chk "  and reaches node_a" yes "$(waitp "$PA" "select status from certs where serial='$S_RA'" -1)"
chk "a supersession only the dump held is back on node_b" 3 "$(B "select status from certs where serial='$S_SU';")"
chk "  and reaches node_a" yes "$(waitp "$PA" "select status from certs where serial='$S_SU'" 3)"
chk "a certificate only the dump held is back on node_b" 1 "$(B "select count(*) from certs where serial='$S_BO';")"
chk "  and reaches node_a" yes "$(waitp "$PA" "select count(*) from certs where serial='$S_BO'" 1)"
chk "node_b's CA key reference is back" 'pkcs11:object=deptB-key' "$(B "select private_key from certs where serial='b2ca';")"
chk "  and is still not on node_a" "" "$(A "select coalesce(private_key,'') from certs where serial='b2ca';")"
chk "node_b's insertion sequence is past the values it used" yes \
    "$([ "$(B "select last_value from certs_seq_local;")" -ge 500 ] 2>/dev/null && echo yes || echo no)"
chk "the rows set aside are cleaned up" "" "$(B "select to_regclass('public.fastpki_restore_certs');")"
A "INSERT INTO certs(serial,status,cn) VALUES('$S_AR',0,'after-restore-a.internal');" >/dev/null
B "INSERT INTO certs(serial,status,cn) VALUES('$S_BR',0,'after-restore-b.internal');" >/dev/null
chk "after the restore node_a's new certificate reaches node_b" yes "$(waitp "$PB" "select count(*) from certs where serial='$S_AR'" 1)"
chk "after the restore node_b's new certificate reaches node_a" yes "$(waitp "$PA" "select count(*) from certs where serial='$S_BR'" 1)"
chk "both nodes hold the same certificates" "$(A "select md5(string_agg(serial||status,',' order by serial)) from certs;")" \
    "$(B "select md5(string_agg(serial||status,',' order by serial)) from certs;")"
chk "node_a holds one slot, active: node_b's new subscription" "1|1" \
    "$(A "select count(*)||'|'||count(*) filter (where active) from pg_replication_slots where slot_name like 'sub_%';")"
chk "node_b holds one slot, active: node_a's new subscription" "1|1" \
    "$(B "select count(*)||'|'||count(*) filter (where active) from pg_replication_slots where slot_name like 'sub_%';")"
chk "--verify finds nothing missing on node_b" "" \
    "$("$MESH" --allow-plaintext-transport --topology "$W/topo.txt" --node node_b --verify 2>/dev/null | "$PGBIN/psql" -h 127.0.0.1 -p "$PB" -U postgres -d pki -tAq 2>&1)"
chk "--verify finds nothing missing on node_a" "" \
    "$("$MESH" --allow-plaintext-transport --topology "$W/topo.txt" --node node_a --verify 2>/dev/null | "$PGBIN/psql" -h 127.0.0.1 -p "$PA" -U postgres -d pki -tAq 2>&1)"
chk "no apply errors on either new subscription" "0|0 0|0" \
    "$(A "select apply_error_count||'|'||sync_error_count from pg_stat_subscription_stats where subname='sub_node_a_from_node_b';") $(B "select apply_error_count||'|'||sync_error_count from pg_stat_subscription_stats where subname='sub_node_b_from_node_a';")"

echo
echo "=== REPL-STREAM: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
