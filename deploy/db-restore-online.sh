#!/usr/bin/env bash
# deployment-path: compose-only — the native restore is docs/postgres.md
# deploy/db-restore-online.sh — restore a dump into a live deployment without taking the
# protocols down, by restoring into the STANDBY and then cutting over to it.
#
# ⚠️ RUN THIS ON THE STANDBY HOST. The pair is two machines: the primary keeps serving
# every protocol while the restore happens here, and the applications only move when the
# roles swap at step 4. Reaching the primary is therefore a NETWORK connection, not
# `docker compose exec` — that only ever works on the host you are standing on.
#
#   PRIMARY_HOST=<primary address> ./db-restore-online.sh <dump.sql> [--no-rebuild] [--force]
#
# ROLES SWAP. When this finishes, THIS host is the primary and the old primary is gone
# until it is rebuilt as a standby (step 5). That is deliberate — it is what makes the pair
# reusable, so the next restore runs the same way in the other direction. See docs/high-availability.md.
#
# NOT A TIME MACHINE. A restore is a point-in-time rollback: certificates issued between
# the dump and the cutover vanish from the DB while still existing in the world, and
# will validate against a CRL/OCSP that no longer knows them. The preflight warns when
# the newest certificate is younger than the dump; --force proceeds anyway.
set -eu

DUMP="${1:-}"
REBUILD=1
FORCE=0
for a in "$@"; do
  case "$a" in
    --no-rebuild) REBUILD=0 ;;
    --force)      FORCE=1 ;;
  esac
done
[ -n "$DUMP" ] && [ -f "$DUMP" ] || {
  echo "usage: PRIMARY_HOST=<address> $0 <dump.sql> [--no-rebuild] [--force]" >&2; exit 2; }

DC="${DOCKER_COMPOSE:-docker compose}"
# The standby is THIS host's own Postgres — the ordinary `postgres` service, brought up as
# a standby by STANDBY_OF (deploy/ha-join.sh).
STANDBY="${STANDBY_SVC:-postgres}"
PGUSER_="${PGUSER:-fastpki}"
PGDB="${PGDATABASE:-fastpki}"
DATA=/var/lib/postgresql/data
PRIMARY_HOST="${PRIMARY_HOST:-}"
PRIMARY_PORT="${PRIMARY_PORT:-5432}"

# ⚠️ REFUSE WITHOUT A DISTINCT PRIMARY ENDPOINT. Defaulting this to a local service name is
# how the procedure silently degrades into "restore into a second database on this same
# machine", which protects nothing and destroys the only copy if this host is the one that
# fails. The address is the whole difference between a restore and a rehearsal.
[ -n "$PRIMARY_HOST" ] || {
  echo "FAIL: PRIMARY_HOST is not set. This restores into THIS host's standby and then" >&2
  echo "      promotes it, so it needs the address of the primary it is replacing —" >&2
  echo "      the same address this host streams from. See docs/high-availability.md." >&2
  exit 2; }

say(){ printf '== %s\n' "$*"; }

# psql against the standby on THIS host, through compose.
q(){ $DC exec -T "$STANDBY" psql -U "$PGUSER_" -d "$PGDB" -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

# psql against the REMOTE primary, over TLS, from inside the standby container — it already
# holds the trust anchor and the password, and this way nothing has to be installed here.
# ⚠️ primary-ca.crt, not ca.crt: on a joining host ca.crt is this node's own self-signed
# transport cert, which the primary was never issued by. ha-join.sh puts the primary's
# anchor at the first path; fall back only for a node that shares the primary's trust.
qp(){
  $DC exec -T "$STANDBY" sh -ec '
    ROOT=/pki/tls/pg/primary-ca.crt
    [ -f "$ROOT" ] || ROOT=/pki/tls/pg/ca.crt
    psql -d "host='"$PRIMARY_HOST"' port='"$PRIMARY_PORT"' user='"$PGUSER_"' dbname='"$PGDB"' \
          sslmode=verify-full sslrootcert=$ROOT connect_timeout=5" -tAc '"'$1'"' 2>/dev/null
  ' | tr -d '[:space:]'
}

# ---- 1. preflight ---------------------------------------------------------------
say "preflight"
[ "$(qp 'SELECT 1')" = "1" ] || { echo "FAIL: the primary at $PRIMARY_HOST is not answering — this is a no-downtime restore, it needs a live primary. Use the offline restore." >&2; exit 1; }
[ "$(qp 'SELECT pg_is_in_recovery()')" = "f" ] || { echo "FAIL: $PRIMARY_HOST is in recovery, so it is not the primary. Check which node is." >&2; exit 1; }
[ "$(q 'SELECT pg_is_in_recovery()')" = "t" ] || { echo "FAIL: the local $STANDBY is not a streaming standby. Join this host to the primary first: ./ha-join.sh $PRIMARY_HOST <primary-ca.crt> && $DC up -d" >&2; exit 1; }
say "primary=$PRIMARY_HOST (read-write, remote)  standby=$STANDBY (streaming, this host)"

# A rollback that discards live certificates is a data decision, not a downtime one —
# surface it before anything is touched rather than after the cutover.
NEWEST="$(qp 'SELECT COALESCE(MAX("notBefore"),0) FROM certs')"
DUMPTS="$(date -r "$DUMP" +%s 2>/dev/null || stat -c %Y "$DUMP" 2>/dev/null || echo 0)"
if [ -n "$NEWEST" ] && [ "$NEWEST" -gt 0 ] && [ "$DUMPTS" -gt 0 ] && [ "$NEWEST" -gt "$DUMPTS" ]; then
  echo "WARN: the newest certificate in the live database is NEWER than this dump."
  echo "      Restoring will forget certificates that exist in the world and will keep"
  echo "      validating until they expire. Re-dump, or pass --force to accept that."
  [ "$FORCE" = "1" ] || exit 1
fi

# ---- 2. detach the standby, keeping it invisible to the apps --------------------
say "detaching $STANDBY (promote, but held read-only so no app selects it)"
$DC exec -T "$STANDBY" sh -ec '
  AS="$(command -v gosu || command -v su-exec)"
  $AS postgres psql -U '"$PGUSER_"' -d '"$PGDB"' -qc "ALTER SYSTEM SET default_transaction_read_only = on"
  $AS postgres pg_ctl -D '"$DATA"' promote
'
printf 'waiting for it to leave recovery'
for _ in $(seq 1 30); do
  [ "$(q 'SELECT pg_is_in_recovery()')" = "f" ] && break
  printf '.'; sleep 1
done
echo
[ "$(q 'SELECT pg_is_in_recovery()')" = "f" ] || { echo "FAIL: $STANDBY did not promote — check '$DC logs $STANDBY'." >&2; exit 1; }
# Make the read-only guard take effect for NEW sessions (promote reset the reload).
$DC exec -T "$STANDBY" sh -ec 'AS="$(command -v gosu || command -v su-exec)"; $AS postgres psql -U '"$PGUSER_"' -d '"$PGDB"' -qc "SELECT pg_reload_conf()"' >/dev/null
RO="$(q 'SHOW transaction_read_only')"
[ "$RO" = "on" ] || { echo "FAIL: $STANDBY is promoted but NOT read-only ($RO). Aborting rather than risk apps writing to a database that is about to be overwritten." >&2; exit 1; }
say "detached: writable by us, invisible to the apps (transaction_read_only=on)"

# ---- 3. restore into the detached node — the primary keeps serving throughout ----
say "restoring $(basename "$DUMP") into $STANDBY (apps still on $PRIMARY_HOST)"
# PGOPTIONS, not a `SET` statement. The restore runs --single-transaction, and a
# transaction's read-only-ness is fixed when it BEGINS: `SET default_transaction_read_only
# = off` as the first statement is already inside that transaction and changes nothing,
# so every CREATE/INSERT fails with "cannot execute ... in a read-only transaction".
# PGOPTIONS is applied at connection startup, before the transaction opens, so this
# session is read-write while every other connection — the apps' included — still sees
# the guard and stays away.
# Strip replication-topology DDL. Two independent reasons, both fatal without this:
#   * `DROP SUBSCRIPTION` cannot run inside a transaction block, and --single-transaction
#     is exactly that — on a mesh node a plain `pg_dump --clean` emits one per peer,
#     so the restore aborts at the first line before touching any data.
#   * Subscriptions and publications are NODE-LOCAL topology, not application data.
#     Recreating this node's mesh wiring from a dump — possibly taken on a different
#     node — is wrong even when it parses. The mesh is re-established deliberately
#     afterwards; see the multi-DC note in docs/high-availability.md.
# grep, not `sed //Id` — BSD sed ignores the case-insensitivity flag on an address, so
# the filter silently passes everything through and the failure reappears on macOS.
# ⚠️ session_replication_role=replica, OR A MESH NODE CANNOT BE RESTORED AT ALL.
# `certs_dc_range` refuses any leaf whose serial does not carry THIS node's 2-octet prefix.
# That is right for a local mint — it is what stops two data centers issuing the same serial
# — and it is an ORIGIN trigger precisely so replicated rows bypass it. A restore is neither:
# it is a local INSERT of rows this node did not mint, and a converged node's `certs` table
# is mostly its PEERS' rows. With ON_ERROR_STOP and --single-transaction the first one
# aborts the whole restore:
#
#     ERROR: serial 0002bb… does not carry this data center's prefix
#
# Measured against a live data center 1 node: a peer-prefix row and a pre-mesh prefix-less
# row are both refused, and both insert cleanly under session_replication_role=replica.
# This is the same lever `pg_restore --disable-triggers` pulls. The skip-dup and
# last-writer-wins triggers are ENABLE REPLICA, so they still fire and still resolve
# duplicates — only the origin-only guard steps aside, which is exactly the intent.
grep -viE '^[[:space:]]*(DROP|CREATE|ALTER)[[:space:]]+(SUBSCRIPTION|PUBLICATION)([[:space:]]|$)' "$DUMP" \
  | $DC exec -T -e PGOPTIONS='-c default_transaction_read_only=off -c session_replication_role=replica' "$STANDBY" \
      psql -U "$PGUSER_" -d "$PGDB" -v ON_ERROR_STOP=1 --single-transaction -q -f -
say "restore complete"

# ---- 4. cut over ----------------------------------------------------------------
# Stop the old primary FIRST, then lift the read-only guard. That order leaves a brief
# window with no writable host — the apps retry — instead of a window with two, which is
# how a split brain starts.
#
# ⚠️ THE OLD PRIMARY IS ON ANOTHER MACHINE, so this script cannot stop it and must not
# pretend to. It waits for the operator instead, and verifies the stop actually happened
# before lifting the guard — an unverified "I stopped it" is exactly the assumption that
# produces two read-write databases holding different data.
say "cutting over"
echo
echo "   STOP THE PRIMARY NOW, on $PRIMARY_HOST:"
echo "       docker compose stop postgres"
echo
printf '   waiting for %s to stop answering' "$PRIMARY_HOST"
STOPPED=0
for _ in $(seq 1 120); do
  [ "$(qp 'SELECT 1')" = "1" ] || { STOPPED=1; break; }
  printf '.'; sleep 5
done
echo
# ⚠️ RE-RUNNING CANNOT HELP FROM HERE, so do not offer it. Step 2 promoted this host and step
# 3 restored the dump into it, so preflight now refuses both ways: with the old primary stopped
# it fails "the primary is not answering", and with it still up it fails "the local standby is
# not a streaming standby", because this host has left recovery. --force bypasses neither. The
# restored data is intact HERE and only here, in a read-only database, and the one action left
# is the pair of statements the lines below would have run.
[ "$STOPPED" = "1" ] || {
  echo "FAIL: $PRIMARY_HOST is still answering after 10 minutes." >&2
  echo "      NOT lifting the read-only guard — that would give you two read-write databases" >&2
  echo "      with different data." >&2
  echo "      The restore itself SUCCEEDED: this host holds the restored data and is already a" >&2
  echo "      primary, serving it read-only. Re-running this script cannot continue from here," >&2
  echo "      because preflight needs a live REMOTE primary and this host in recovery, and" >&2
  echo "      neither is true any more." >&2
  echo "      Confirm $PRIMARY_HOST is down and staying down, then lift the guard yourself:" >&2
  echo "        $DC exec -T $STANDBY psql -U $PGUSER_ -d $PGDB -qc \\" >&2
  echo "            \"ALTER SYSTEM RESET default_transaction_read_only\"" >&2
  echo "        $DC exec -T $STANDBY psql -U $PGUSER_ -d $PGDB -qc \"SELECT pg_reload_conf()\"" >&2
  exit 1; }
say "old primary is down"
$DC exec -T "$STANDBY" sh -ec '
  AS="$(command -v gosu || command -v su-exec)"
  $AS postgres psql -U '"$PGUSER_"' -d '"$PGDB"' -qc "ALTER SYSTEM RESET default_transaction_read_only"
  $AS postgres psql -U '"$PGUSER_"' -d '"$PGDB"' -qc "SELECT pg_reload_conf()"
' >/dev/null
for _ in $(seq 1 30); do
  [ "$(q 'SHOW transaction_read_only')" = "off" ] && break; sleep 1
done
[ "$(q 'SHOW transaction_read_only')" = "off" ] || { echo "FAIL: $STANDBY stayed read-only after cutover — apps cannot write. Investigate NOW." >&2; exit 1; }
say "this host is the primary and serving the restored data"
say "apps re-home on their next statement (target_session_attrs=read-write, reconnect)"

# ---- 5. rebuild the old primary as the new standby ------------------------------
# Never just restart it: its timeline diverged the moment this node was promoted, so it
# would stream garbage or refuse. It has to be re-seeded from the new primary — which is
# what ha-join.sh does, and it runs on that host, not this one.
if [ "$REBUILD" = "1" ]; then
  say "rebuild $PRIMARY_HOST as a standby of this host"
  echo "   ON $PRIMARY_HOST, discard its diverged database and re-join:"
  echo "       docker compose down"
  echo "       docker volume rm -f \$(docker volume ls -q -f name=_pgdata\$ | head -1)"
  echo "       ./ha-join.sh <this host's address> primary-ca.crt"
  echo "       docker compose up -d"
  echo "   (the roles are now swapped: this host is the primary. See docs/high-availability.md.)"
else
  say "left $PRIMARY_HOST alone (--no-rebuild); the deployment has NO standby until you rebuild it"
fi

echo
say "done — restored online, no protocol was ever refusing requests"
