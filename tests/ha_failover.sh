#!/usr/bin/env bash
# tests/ha_failover.sh — the promotion and app-re-homing MECHANISM.
#
# ⚠️ A MECHANISM TEST, NOT A DEPLOYMENT SHAPE. It builds its own Postgres pair with initdb
# + pg_basebackup in a temp directory, so both halves run on this one machine. A real
# deployment puts the standby on a SECOND HOST (deploy/ha-join.sh, docs/high-availability.md) — nothing
# here is a model for how to arrange one, and a pair on one machine would protect nothing.
# What IS the same either way is everything below: libpq's multi-host selection and the
# reconnect path do not care which machines the two endpoints are on.
#
# Proves that mechanism end-to-end, and — the important part — proves it needs NO
# third-party dependency (no Patroni/etcd/repmgr) and NO change to the running app. It
# rides two capabilities FastPKI already has:
#   * the app passes PG_CONNINFO verbatim to libpq (config.cpp), so a *multi-host*
#     conninfo with target_session_attrs=read-write is honoured natively; and
#   * the reconnect-before-issue path (db_postgres.cpp ensure_conn/PQreset) re-runs that
#     multi-host connect after the backend drops.
# Put together: primary dies -> operator promotes the standby -> the app's next
# statement PQresets, skips the dead primary, and re-homes onto the promoted (now
# read-write) standby WITH NO RESTART. That is the HA guarantee.
#
# Flow (self-contained §3d, shell-only §3e — stands up its OWN two clusters, no
# reliance on a running server, its own high ports, cleans up on exit; SKIPs when the
# Postgres tools or the binaries are absent):
#   1. initdb a PRIMARY with streaming replication; start it; load the schema.
#   2. pg_basebackup -> a hot STANDBY streaming from the primary; start it read-only.
#   3. start fastpki-web on the MULTI-HOST conninfo -> it connects to the primary (RW).
#   4. log in + create a console user -> a real WRITE that lands on the primary and
#      REPLICATES to the standby (asserted by querying the standby directly).
#   5. crash the primary (pg_ctl -m immediate); while degraded, a write FAILS.
#   6. promote the standby (pg_ctl promote) -> it becomes read-write.
#   7. through the SAME web process, create another user -> the WRITE SUCCEEDS,
#      proving the app re-homed onto the promoted standby without a restart.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/pg_priv.sh"
export LC_ALL=C                        # macOS initdb multithread issue (§3d)
WEB="$ROOT/build/fastpki-web"
CONFIG="$ROOT/build/fastpki-config"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' --max-time 12 "$@"; }

# --- dependencies: SKIP cleanly if anything is missing ----------------------
for b in initdb pg_ctl pg_basebackup psql pg_isready; do
  command -v "$b" >/dev/null 2>&1 || { echo "SKIP: $b not installed"; exit 0; }
done
[ -x "$WEB" ]    || { echo "SKIP: fastpki-web not built"; exit 0; }
[ -x "$CONFIG" ] || { echo "SKIP: fastpki-config not built"; exit 0; }

W="$(mktemp -d)"; cd "$W"
PRIMARY="$W/primary"; STANDBY="$W/standby"; PGU="pki"
# mktemp -d is 0700 root-owned; the dropped-privilege server must be able to create
# its data directories and write its log inside it. No-op unless we are root.
pg_own "$W"
WEBPID=""
cleanup(){
  [ -n "$WEBPID" ] && kill "$WEBPID" 2>/dev/null
  pg_as pg_ctl -D "$STANDBY" -m immediate stop >/dev/null 2>&1
  pg_as pg_ctl -D "$PRIMARY" -m immediate stop >/dev/null 2>&1
  rm -rf "$W"
}
trap cleanup EXIT

# --- pick three free ports (avoid a local pg on 5432, etc.) -----------------
inuse(){ (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&- 3<&-; return 0; } || return 1; }
pick(){ local p=$1; while inuse "$p"; do p=$((p+1)); done; echo "$p"; }
# ⚠️ 15500, NOT 55432 — THE OLD BASE SAT INSIDE THE EPHEMERAL PORT RANGE. Linux allocates
# outgoing connections' SOURCE ports from /proc/sys/net/ipv4/ip_local_port_range, which is
# 32768-60999 in the shipped image, so 55432-55434 were ports the kernel could hand to any
# curl, psql or libpq connection at any moment. A full sequential run makes thousands of
# them. When one landed on the port picked here, fastpki-web's bind failed and the suite
# reported the useless `web died: / listen failed` — intermittently, and far more often
# under CI, where 249 suites share one network namespace on a slow two-core runner.
#
# `inuse()` below cannot see this: it detects a LISTENER, and an ephemeral client socket is
# not one. Nor would any probe fix it, because the port is picked and bound in two separate
# steps and the kernel is free to use it in between. The only reliable fix is to pick from
# a range the kernel will never allocate on its own, which is what every other suite does
# by using the harness's own 18000-19999 band. 15500 is below the ephemeral floor by 17336
# ports and is unused elsewhere in the tree.
P1=$(pick 15500); P2=$(pick $((P1+1))); WP=$(pick $((P2+1)))

echo "=== 1. PRIMARY with streaming replication enabled ==="
pg_as initdb -A trust -U "$PGU" -D "$PRIMARY" --no-sync >/dev/null 2>&1 \
  || { echo "SKIP: initdb failed — $(pg_priv_reason)"; exit 0; }
# wal_level MUST be logical, not replica: the shipped compose runs logical, and the
# slot synchronisation only ever applies to LOGICAL slots. Testing failover under a
# config the product never runs proves nothing about the product.
cat >> "$PRIMARY/postgresql.conf" <<EOF
wal_level = logical
max_wal_senders = 8
max_replication_slots = 10
hot_standby = on
EOF
echo "host replication $PGU 127.0.0.1/32 trust" >> "$PRIMARY/pg_hba.conf"
pg_as pg_ctl -D "$PRIMARY" -l "$W/primary.log" -o "-p $P1" -w -t 30 start >/dev/null 2>&1 \
  || { echo "primary start failed:"; cat "$W/primary.log"; exit 1; }
psql -h 127.0.0.1 -p "$P1" -U "$PGU" -d postgres -c "CREATE DATABASE pki;" >/dev/null 2>&1
psql -h 127.0.0.1 -p "$P1" -U "$PGU" -d pki -f "$ROOT/sql/createdb.sql" >/dev/null 2>&1
chk "primary is up and read-write" f \
  "$(psql -h 127.0.0.1 -p "$P1" -U "$PGU" -d pki -tAc 'SELECT pg_is_in_recovery()' 2>/dev/null | tr -d ' ')"

echo "=== 2. STANDBY: a hot streaming replica (pg_basebackup) ==="
# Is this toolchain new enough to have failover slots at all? PG17 is where
# sync_replication_slots, pg_replication_slots.synced and the CREATE SUBSCRIPTION
# `failover` option arrive. The SKIP must NAME the version it found — a silent skip
# that nobody reads is how coverage is lost (the libFuzzer probe skipped on every
# machine and passed forever).
PGMAJ=$(initdb --version 2>/dev/null | sed 's/[^0-9]*\([0-9]*\).*/\1/')
SLOTSYNC=0
if [ "${PGMAJ:-0}" -ge 17 ]; then
  SLOTSYNC=1
else
  echo "  SKIP: failover-slot sync needs PostgreSQL 17+ (found ${PGMAJ:-unknown}) — those assertions NOT run"
fi

# NB: the physical slot 'sb1' is created by pg_basebackup's own -C below. Pre-creating
# it AND passing -C makes the backup die with 'replication slot "sb1" already exists'.
# The LOGICAL failover slot is created LATER, once the standby is streaming — see 2b.
#
# -C -S makes -R write primary_slot_name; -d supplies a REAL dbname, which -R records
# into primary_conninfo and the slot-sync worker connects to. pg_basebackup does not
# invent one, so without -d the conninfo inherits whatever is in the environment.
BB_SLOT=""; [ "$SLOTSYNC" = 1 ] && BB_SLOT="-C -S sb1"
pg_as pg_basebackup -h 127.0.0.1 -p "$P1" -U "$PGU" -D "$STANDBY" -R -X stream -c fast $BB_SLOT \
  -d "host=127.0.0.1 port=$P1 user=$PGU dbname=pki" >/dev/null 2>&1 \
  || { echo "basebackup failed"; cat "$W/primary.log"; exit 1; }
if [ "$SLOTSYNC" = 1 ]; then
  cat >> "$STANDBY/postgresql.conf" <<EOF
sync_replication_slots = on
hot_standby_feedback = on
EOF
fi
pg_as pg_ctl -D "$STANDBY" -l "$W/standby.log" -o "-p $P2" -w -t 30 start >/dev/null 2>&1 \
  || { echo "standby start failed:"; cat "$W/standby.log"; exit 1; }
st=""
for _ in $(seq 1 30); do
  st=$(psql -h 127.0.0.1 -p "$P1" -U "$PGU" -d pki -tAc "SELECT state FROM pg_stat_replication" 2>/dev/null | tr -d ' ')
  [ "$st" = "streaming" ] && break; sleep 0.5
done
chk "standby is streaming from the primary" streaming "$st"
chk "standby is read-only (in recovery)" t \
  "$(psql -h 127.0.0.1 -p "$P2" -U "$PGU" -d pki -tAc 'SELECT pg_is_in_recovery()' 2>/dev/null | tr -d ' ')"

# NOTE: the failover-slot MECHANISM is NOT proven here. It needs a slot that a
# real subscriber is continuously consuming — PG17 refuses to persist a synced slot
# whose remote catalog_xmin has not advanced, and pg_logical_slot_get_changes() is not
# a good enough stand-in for a live walsender (measured: the slot stayed temporary and
# the sync worker logged "Synchronization could lead to data loss ... catalog xmin 825
# ... standby has ... catalog xmin 831" indefinitely). This suite has two clusters and
# no logical subscriber, so the proof lives in tests/replication_stream.sh, which
# already has a real publisher/subscriber pair. What this suite DOES now carry is the
# shipped standby's own wiring — wal_level=logical, -C -S <slot>, and a real dbname in
# primary_conninfo — so it exercises the configuration the product deploys.

echo "=== 3. fastpki-web on a MULTI-HOST conninfo (native libpq failover) ==="
# Seed the console admin on the primary (replicates to the standby).
export PG_CONNINFO="host=127.0.0.1 port=$P1 dbname=pki user=$PGU"
seed_web_user admin adminpw12 admin
# The HA conninfo the APP runs on: BOTH hosts, prefer the read-write one, bounded
# connect so a dead host fails fast instead of hanging.
HA_CI="host=127.0.0.1,127.0.0.1 port=$P1,$P2 dbname=pki user=$PGU target_session_attrs=read-write connect_timeout=3"
# Drop the single-host PG_CONNINFO used for seeding above, or the app never sees HA_CI.
# Since 7a58fbf the ENVIRONMENT wins over the config file for PG_CONNINFO -- that
# is deliberate, so a compose deployment can inject the generated password -- which means
# an exported single-host conninfo silently overrides the multi-host one in web.conf. The
# app then knows one host, cannot fail over, and this suite fails at step 7 with the app
# retrying the dead primary forever. Nothing in the log says a config value was ignored.
unset PG_CONNINFO
cat > web.conf <<EOF
PG_CONNINFO=$HA_CI
WEB_BIND=127.0.0.1
WEB_PORT=$WP
WEB_ALLOW_REVOKE=true
LOG_LEVEL=info
EOF
"$WEB" --config web.conf >web.log 2>&1 & WEBPID=$!
disown "$WEBPID" 2>/dev/null   # silence bash job-control "Terminated" noise on cleanup
# ⚠️ NOT A READINESS WAIT — DO NOT REPLACE IT WITH wait_conf/wait_port. This suite fails
# a Postgres primary over to a standby; the second is for replication and the app's
# connection to settle, not for the web port to open. A port poll returns in ~50ms and the
# app then answers 000, which reads as a failover bug.
sleep 1
kill -0 "$WEBPID" 2>/dev/null || { echo "web died:"; cat web.log; exit 1; }
U="http://127.0.0.1:$WP"
curl -s -c admin.cj -X POST "$U/api/login" -d 'username=admin&password=adminpw12' >/dev/null
chk "app is serving (connected to the primary)" 200 "$(code -b admin.cj "$U/api/users")"

echo "=== 4. a real WRITE lands on the primary and replicates ==="
mkuser(){ curl -s -b admin.cj --max-time 12 -X POST "$U/api/users" \
            -d "username=$1&password=changeme123&role=auditor&create=1"; }
mkuser before_ha >/dev/null
curl -s -b admin.cj "$U/api/users" -o users1.json
chk "write is visible through the app" yes "$(grep -q '"before_ha"' users1.json && echo yes || echo no)"
chk "write replicated to the standby"  1 \
  "$(psql -h 127.0.0.1 -p "$P2" -U "$PGU" -d pki -tAc "SELECT count(*) FROM web_users WHERE username='before_ha'" 2>/dev/null | tr -d ' ')"

echo "=== 5. CRASH the primary; while degraded a write must FAIL ==="
pg_as pg_ctl -D "$PRIMARY" -m immediate stop >/dev/null 2>&1
pg_isready -h 127.0.0.1 -p "$P1" >/dev/null 2>&1; rc=$?   # 0=up; 1=rejecting; 2=no response
chk "primary is down" down "$([ "$rc" -ne 0 ] && echo down || echo up)"
# standby is still read-only -> target_session_attrs=read-write finds no RW host.
degraded="$(mkuser during_outage 2>/dev/null)"
chk "write is refused while no primary exists" no \
  "$(echo "$degraded" | grep -q '"error"\|reconnect\|read-write\|connection' && echo no || ([ -z "$degraded" ] && echo no || echo yes))"

echo "=== 6. PROMOTE the standby (manual, by design) ==="
pg_as pg_ctl -D "$STANDBY" promote >/dev/null 2>&1
rec="t"
for _ in $(seq 1 30); do
  rec=$(psql -h 127.0.0.1 -p "$P2" -U "$PGU" -d pki -tAc 'SELECT pg_is_in_recovery()' 2>/dev/null | tr -d ' ')
  [ "$rec" = "f" ] && break; sleep 0.5
done
chk "standby promoted to read-write" f "$rec"

echo "=== 7. the SAME web process re-homes onto the promoted standby ==="
kill -0 "$WEBPID" 2>/dev/null; chk "web process never restarted" 0 "$?"
mkuser after_ha >/dev/null
curl -s -b admin.cj "$U/api/users" -o users2.json
chk "post-failover WRITE succeeded (app re-homed, no restart)" yes \
  "$(grep -q '"after_ha"' users2.json && echo yes || echo no)"
chk "the new row is on the promoted standby" 1 \
  "$(psql -h 127.0.0.1 -p "$P2" -U "$PGU" -d pki -tAc "SELECT count(*) FROM web_users WHERE username='after_ha'" 2>/dev/null | tr -d ' ')"

echo
echo "=== HA FAILOVER: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
