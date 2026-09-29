#!/usr/bin/env bash
# deploy/db-restore-online.sh — restore a dump into a live pair without taking the protocols
# down, by restoring into the STANDBY and then cutting over to it.
#
#   Compose, ON THE STANDBY HOST, in deploy/:
#     PRIMARY_HOST=<primary address> ./db-restore-online.sh <dump.sql> [--no-rebuild] [--force]
#   Native or cloud, ON THE STANDBY HOST, as root:
#     PRIMARY_HOST=<primary address> /usr/share/fastpki/db-restore-online.sh <dump.sql> [...]
#
#   Kubernetes, from any machine with kubectl for the cluster, naming the standby's pod:
#     NAMESPACE=fastpki ./db-restore-online.sh <dump.sql> fastpki-node-1 [--no-rebuild] [--force]
#
# The pair is two servers: the primary keeps serving every protocol while the restore happens
# on the standby, and the applications only move when the roles swap at step 4.
#
# ROLES SWAP. When this finishes, the standby is the primary. The old primary is rebuilt as
# its standby (step 5): by this script on Kubernetes, by the operator on the other host on
# Compose and native. That is what makes the pair reusable, so the next restore runs the same
# way in the other direction. See docs/high-availability.md.
#
# NOT A TIME MACHINE. A restore is a point-in-time rollback: certificates issued between
# the dump and the cutover vanish from the DB while still existing in the world, and
# will validate against a CRL/OCSP that no longer knows them. The preflight warns when
# the newest certificate is younger than the dump; --force proceeds anyway.
set -eu

DUMP=""; POD=""; REBUILD=1; FORCE=0
for a in "$@"; do
  case "$a" in
    --no-rebuild) REBUILD=0 ;;
    --force)      FORCE=1 ;;
    -*)           echo "unknown option: $a" >&2; exit 2 ;;
    *)            if [ -z "$DUMP" ]; then DUMP=$a; else POD=$a; fi ;;
  esac
done
usage() {
  echo "usage: PRIMARY_HOST=<address> $0 <dump.sql> [--no-rebuild] [--force]        (compose, native)" >&2
  echo "       NAMESPACE=<ns> $0 <dump.sql> fastpki-node-<N> [--no-rebuild] [--force]  (kubernetes)" >&2
  exit 2
}
[ -n "$DUMP" ] && [ -f "$DUMP" ] || usage

# ── WHICH DEPLOYMENT IS THIS ──────────────────────────────────────────────────────────
# Detected the way pg-promote.sh detects it: a server pod is named fastpki-node-N, a native
# host has /etc/fastpki and OpenRC, anything else is compose. FASTPKI_RESTORE_MODE overrides.
MODE="${FASTPKI_RESTORE_MODE:-}"
if [ -z "$MODE" ]; then
  case "$POD" in
    fastpki-node-[0-9]*) MODE=k8s ;;
    *) if [ -f docker-compose.yml ] || [ -f compose.yml ] || [ -n "${DOCKER_COMPOSE:-}" ]; then
         MODE=compose
       elif [ -f /etc/fastpki/bootstrap.conf ] && command -v rc-service >/dev/null 2>&1; then
         MODE=native
       else
         MODE=compose
       fi ;;
  esac
fi
case "$MODE" in
  compose|native) [ -z "$POD" ] || usage ;;
  k8s) command -v kubectl >/dev/null 2>&1 || { echo "FAIL: kubernetes mode needs kubectl" >&2; exit 2; }
       case "$POD" in fastpki-node-[0-9]*) ;; *) usage ;; esac ;;
  *) echo "FAIL: FASTPKI_RESTORE_MODE must be compose, native or k8s (got '$MODE')" >&2; exit 2 ;;
esac

DC="${DOCKER_COMPOSE:-docker compose}"
STANDBY="${STANDBY_SVC:-postgres}"      # compose: this host's own postgres service
PGUSER_="${PGUSER:-fastpki}"
PGDB="${PGDATABASE:-fastpki}"
NS="${NAMESPACE:-fastpki}"
NATIVE_CONF=/etc/fastpki/bootstrap.conf
NATIVE_ENV=/etc/conf.d/fastpki
PRIMARY_HOST="${PRIMARY_HOST:-}"
PRIMARY_PORT="${PRIMARY_PORT:-5432}"
OLD=""                                  # kubernetes: the primary's pod

say(){ printf '== %s\n' "$*"; }
kx(){ _p=$1; _c=$2; shift 2; kubectl exec -n "$NS" "$_p" -c "$_c" -- "$@"; }

# ⚠️ REFUSE WITHOUT A DISTINCT PRIMARY ENDPOINT on compose and native. Defaulting it to a local
# name is how the procedure silently degrades into "restore into a second database on this
# same machine", which protects nothing and destroys the only copy if this host is the one
# that fails. On Kubernetes the primary is found: it is the other server pod.
if [ "$MODE" != k8s ] && [ -z "$PRIMARY_HOST" ]; then
  echo "FAIL: PRIMARY_HOST is not set. This restores into THIS host's standby and then" >&2
  echo "      promotes it, so it needs the address of the primary it is replacing —" >&2
  echo "      the same address this host streams from. See docs/high-availability.md." >&2
  exit 2
fi

# ── WHAT THIS SCRIPT DOES TO A DATABASE, ONCE EACH PER PATH ───────────────────────────
# Every path-specific command lives here, so the procedure below reads the same for all three.
# Native runs psql and pg_ctl as the postgres system user over the local socket: peer
# authentication, superuser, no password — as pg-promote.sh does. The statement travels as an
# argument, never spliced into the command string. `--` before the user: busybox su reads every
# dashed word after it as its own option.

# q: one value from the STANDBY.
q(){
  case "$MODE" in
    compose) $DC exec -T "$STANDBY" psql -U "$PGUSER_" -d "$PGDB" -tAc "$1" 2>/dev/null ;;
    native)  su -s /bin/sh -c 'exec psql -d "$0" -tAc "$1"' -- postgres "$PGDB" "$1" 2>/dev/null ;;
    k8s)     kx "$POD" postgres psql -U "$PGUSER_" -d "$PGDB" -tAc "$1" 2>/dev/null ;;
  esac | tr -d '[:space:]'
}
# qp: one value from the PRIMARY. On compose, over TLS from inside the standby container, which
# already holds the trust anchor and the password. ⚠️ primary-ca.crt, not ca.crt: on a joining
# host ca.crt is this node's own self-signed transport cert, which the primary was never issued
# by; ha-join.sh puts the primary's anchor at the first path. On native, with this host's own
# PG_CONNINFO pointed at the primary: its password and trust anchor are the ones the services
# already reach the primary with. On Kubernetes, inside the primary's own pod.
qp(){
  case "$MODE" in
    compose) $DC exec -T "$STANDBY" sh -ec '
               ROOT=/pki/tls/pg/primary-ca.crt
               [ -f "$ROOT" ] || ROOT=/pki/tls/pg/ca.crt
               psql -d "host='"$PRIMARY_HOST"' port='"$PRIMARY_PORT"' user='"$PGUSER_"' dbname='"$PGDB"' \
                     sslmode=verify-full sslrootcert=$ROOT connect_timeout=5" -tAc '"'$1'"' 2>/dev/null' ;;
    native)  _ci=$(sed -n 's/^PG_CONNINFO=//p' "$NATIVE_CONF" | head -1 \
                   | sed -e "s/host=[^ ]*/host=$PRIMARY_HOST/" -e "s/port=[^ ]*/port=$PRIMARY_PORT/" \
                         -e 's/ *target_session_attrs=[^ ]*//' -e 's/ *connect_timeout=[^ ]*//')
             psql "$_ci connect_timeout=5" -tAc "$1" 2>/dev/null ;;
    k8s)     kx "$OLD" postgres psql -U "$PGUSER_" -d "$PGDB" -tAc "$1" 2>/dev/null ;;
  esac | tr -d '[:space:]'
}
# su_exec: statements on the standby as a superuser, each its own -c: ALTER SYSTEM refuses a
# transaction block.
su_exec(){
  _args=(); for _s in "$@"; do _args+=(-c "$_s"); done
  case "$MODE" in
    compose) $DC exec -T "$STANDBY" sh -ec 'AS="$(command -v gosu || command -v su-exec)"; u=$1; d=$2; shift 2
                                            $AS postgres psql -U "$u" -d "$d" -q "$@"' sh "$PGUSER_" "$PGDB" "${_args[@]}" ;;
    native)  su -s /bin/sh -c 'exec psql -d "$0" -q "$@"' -- postgres "$PGDB" "${_args[@]}" ;;
    k8s)     kx "$POD" postgres psql -U "$PGUSER_" -d "$PGDB" -q "${_args[@]}" ;;
  esac >/dev/null
}
# promote: pg_ctl as the postgres user. Native asks for the data directory rather than assuming
# it: it is version-numbered, and a major-version bump would move it silently.
promote(){
  case "$MODE" in
    compose) $DC exec -T "$STANDBY" sh -ec 'AS="$(command -v gosu || command -v su-exec)"; $AS postgres pg_ctl -D /var/lib/postgresql/data promote' ;;
    k8s)     kx "$POD" postgres sh -ec 'AS="$(command -v gosu || command -v su-exec || true)"; ${AS:+$AS postgres} pg_ctl -D /var/lib/postgresql/data promote' ;;
    native)  _pgdata="$(q 'SHOW data_directory')"
             [ -n "$_pgdata" ] || { echo "FAIL: cannot find the data directory — is Postgres running here?" >&2; exit 1; }
             su -s /bin/sh -c 'exec pg_ctl -D "$0" promote' -- postgres "$_pgdata" ;;
  esac
}
# recreate_db: an empty database on the detached standby, as the offline restore makes one
# (docs/postgres.md §6.1). Read-write for this session only: the guard stays on for the apps.
recreate_db(){
  case "$MODE" in
    compose) $DC exec -T -e PGOPTIONS='-c default_transaction_read_only=off' "$STANDBY" \
               psql -U "$PGUSER_" -d postgres -q -c "DROP DATABASE IF EXISTS $PGDB WITH (FORCE)" -c "CREATE DATABASE $PGDB OWNER $PGUSER_" ;;
    native)  su -s /bin/sh -c 'PGOPTIONS="-c default_transaction_read_only=off" exec psql -d postgres -q -c "DROP DATABASE IF EXISTS $0 WITH (FORCE)" -c "CREATE DATABASE $0 OWNER $1"' \
               -- postgres "$PGDB" "$PGUSER_" ;;
    k8s)     kx "$POD" postgres env PGOPTIONS='-c default_transaction_read_only=off' \
               psql -U "$PGUSER_" -d postgres -q -c "DROP DATABASE IF EXISTS $PGDB WITH (FORCE)" -c "CREATE DATABASE $PGDB OWNER $PGUSER_" ;;
  esac >/dev/null
}
# restore_stdin: the dump on stdin, into the standby, in one transaction (step 3 says why).
PGOPT='-c default_transaction_read_only=off -c session_replication_role=replica'
restore_stdin(){
  case "$MODE" in
    compose) $DC exec -T -e PGOPTIONS="$PGOPT" "$STANDBY" \
               psql -U "$PGUSER_" -d "$PGDB" -v ON_ERROR_STOP=1 --single-transaction -q -f - ;;
    native)  su -s /bin/sh -c 'PGOPTIONS="$1" exec psql -d "$0" -v ON_ERROR_STOP=1 --single-transaction -q -f -' \
               -- postgres "$PGDB" "$PGOPT" ;;
    k8s)     kubectl exec -i -n "$NS" "$POD" -c postgres -- env PGOPTIONS="$PGOPT" \
               psql -U "$PGUSER_" -d "$PGDB" -v ON_ERROR_STOP=1 --single-transaction -q -f - ;;
  esac
}

# ---- 1. preflight ---------------------------------------------------------------
say "preflight ($MODE)"
if [ "$MODE" = k8s ]; then
  for _o in $(kubectl get pods -n "$NS" -l app.kubernetes.io/component=node -o name 2>/dev/null \
              | sed 's|^pod/||' | grep -vx "$POD" || true); do
    OLD=$_o
    [ "$(qp 'SELECT pg_is_in_recovery()')" = f ] && break
    OLD=""
  done
  [ -n "$OLD" ] || { echo "FAIL: no other server pod in '$NS' is a read-write primary — this is a no-downtime restore, it needs a live primary. Use the offline restore." >&2; exit 1; }
  PRIMARY_HOST=$OLD
fi
[ "$(qp 'SELECT 1')" = "1" ] || { echo "FAIL: the primary at $PRIMARY_HOST is not answering — this is a no-downtime restore, it needs a live primary. Use the offline restore." >&2; exit 1; }
[ "$(qp 'SELECT pg_is_in_recovery()')" = "f" ] || { echo "FAIL: $PRIMARY_HOST is in recovery, so it is not the primary. Check which server is." >&2; exit 1; }
[ "$(q 'SELECT pg_is_in_recovery()')" = "t" ] || { echo "FAIL: the database to restore into is not a streaming standby. Join it to the primary first (docs/high-availability.md)." >&2; exit 1; }
# ⚠️ NOT A DATA CENTER IN A MESH. Most of its database is a copy of rows the other data centers
# hold newer, so loading a dump and replicating again keeps the dump's stale rows, and the
# replication links remember positions in the database that is replaced. That restore is
# docs/postgres.md §6.3. Asked of the standby, which holds the same catalog as the primary.
SUBS="$(q "SELECT count(*) FROM pg_subscription s JOIN pg_database d ON d.oid = s.subdbid WHERE d.datname = current_database()")"
[ "${SUBS:-0}" = 0 ] || { echo "FAIL: this data center is part of a mesh ($SUBS subscriptions). Restore it with docs/postgres.md §6.3, not with this script." >&2; exit 1; }
say "primary=$PRIMARY_HOST (read-write)  standby=${POD:-this host} (streaming)"

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
say "detaching the standby (promote, but held read-only so no app selects it)"
su_exec "ALTER SYSTEM SET default_transaction_read_only = on"
promote
printf 'waiting for it to leave recovery'
for _ in $(seq 1 30); do
  [ "$(q 'SELECT pg_is_in_recovery()')" = "f" ] && break
  printf '.'; sleep 1
done
echo
[ "$(q 'SELECT pg_is_in_recovery()')" = "f" ] || { echo "FAIL: the standby did not promote — check its Postgres log." >&2; exit 1; }
# Make the read-only guard take effect for NEW sessions (promote reset the reload).
su_exec "SELECT pg_reload_conf()"
RO="$(q 'SHOW transaction_read_only')"
[ "$RO" = "on" ] || { echo "FAIL: the standby is promoted but NOT read-only ($RO). Aborting rather than risk apps writing to a database that is about to be overwritten." >&2; exit 1; }
say "detached: writable by us, invisible to the apps (transaction_read_only=on)"

# ---- 3. restore into the detached server — the primary keeps serving throughout ----
say "restoring $(basename "$DUMP") (apps still on $PRIMARY_HOST)"
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
# ⚠️ INTO AN EMPTY DATABASE, as the offline restore does. The standby holds every table
# already, and a plain `pg_dump` — the command docs/postgres.md gives for every path — carries
# no DROP statements, so loading one on top stopped at its first CREATE TABLE:
#     ERROR:  relation "accounts" already exists
# Only a `--clean` dump, like the console's, loaded at all. The database is recreated on the
# detached standby, where no application is connected, and either kind of dump then loads.
# The rows the dump itself prints (its set_config SELECTs) are not shown; errors still are.
recreate_db
grep -viE '^[[:space:]]*(DROP|CREATE|ALTER)[[:space:]]+(SUBSCRIPTION|PUBLICATION)([[:space:]]|$)' "$DUMP" \
  | restore_stdin >/dev/null
say "restore complete"

# ---- 4. cut over ----------------------------------------------------------------
# Stop the old primary FIRST, then lift the read-only guard. That order leaves a brief
# window with no writable server — the apps retry — instead of a window with two, which is
# how a split brain starts.
say "cutting over"
if [ "$MODE" = k8s ]; then
  # On Kubernetes the old primary is a pod this script can reach, so it stops it itself. Its
  # container restarts, and start-postgres.sh then refuses to start a second primary beside
  # this one, which is read-write now: the old primary stays down until step 5 rebuilds it.
  kx "$OLD" postgres sh -ec 'AS="$(command -v gosu || command -v su-exec || true)"; ${AS:+$AS postgres} pg_ctl -D /var/lib/postgresql/data stop -m fast' >/dev/null 2>&1 || true
  printf '   waiting for %s to stay down' "$OLD"
else
  # ⚠️ THE OLD PRIMARY IS ON ANOTHER MACHINE, so this script cannot stop it and must not
  # pretend to. It waits for the operator instead, and verifies the stop actually happened
  # before lifting the guard — an unverified "I stopped it" is exactly the assumption that
  # produces two read-write databases holding different data.
  echo
  echo "   STOP THE PRIMARY NOW, on $PRIMARY_HOST:"
  case "$MODE" in
    compose) echo "       docker compose stop postgres" ;;
    native)  echo "       rc-service postgresql stop" ;;
  esac
  echo
  printf '   waiting for %s to stop answering' "$PRIMARY_HOST"
fi
# Down means "not a read-write primary", seen twice in a row 5s apart, so a Kubernetes
# container caught between a stop and its restart does not read as stopped for good.
STOPPED=0; _down=0
for _ in $(seq 1 120); do
  if [ "$(qp 'SELECT pg_is_in_recovery()')" = "f" ]; then _down=0; else _down=$((_down + 1)); fi
  [ "$_down" -ge 2 ] && { STOPPED=1; break; }
  printf '.'; sleep 5
done
echo
# ⚠️ RE-RUNNING CANNOT HELP FROM HERE, so do not offer it. Step 2 promoted the standby and step
# 3 restored the dump into it, so preflight now refuses both ways. --force bypasses neither.
# The restored data is intact on the standby and only there, in a read-only database, and the
# one action left is the pair of statements the lines below would have run.
[ "$STOPPED" = "1" ] || {
  echo "FAIL: $PRIMARY_HOST is still a read-write primary after 10 minutes." >&2
  echo "      NOT lifting the read-only guard — that would give you two read-write databases" >&2
  echo "      with different data." >&2
  echo "      The restore itself SUCCEEDED: the standby holds the restored data and is already a" >&2
  echo "      primary, serving it read-only. Re-running this script cannot continue from here." >&2
  echo "      Confirm $PRIMARY_HOST is down and staying down, then lift the guard on the standby:" >&2
  echo "        ALTER SYSTEM RESET default_transaction_read_only;   then   SELECT pg_reload_conf();" >&2
  exit 1; }
say "old primary is down"
su_exec "ALTER SYSTEM RESET default_transaction_read_only" "SELECT pg_reload_conf()"
for _ in $(seq 1 30); do
  [ "$(q 'SHOW transaction_read_only')" = "off" ] && break; sleep 1
done
[ "$(q 'SHOW transaction_read_only')" = "off" ] || { echo "FAIL: the standby stayed read-only after cutover — apps cannot write. Investigate NOW." >&2; exit 1; }
say "the standby is the primary and serving the restored data"
say "apps re-home on their next statement (target_session_attrs=read-write, reconnect)"

# ---- 4b. it is a primary now: finish the promotion --------------------------------
# A restore is a promotion, and a promoted server needs more than leaving recovery: its own
# applications must reach it (the conninfo host order and trust anchor were its former
# primary's, so they could not verify it), the inherited synchronized_standby_slots stalls
# every logical walsender, the standby mark stops a compose or native Postgres at its next
# restart, and the listeners need restarting. pg-promote.sh does all of that after a failover;
# --already-promoted runs exactly those steps, so both operations share one implementation.
say "finishing the promotion (pg-promote.sh --already-promoted)"
_pp="$(cd "$(dirname "$0")" && pwd)/pg-promote.sh"
if ! FASTPKI_PROMOTE_MODE="$MODE" NAMESPACE="$NS" bash "$_pp" "${POD:-$STANDBY}" --already-promoted; then
  echo "WARN: the restored data is in place and served, but the steps after the promotion did" >&2
  echo "      not all complete (above). Run them again:" >&2
  echo "        FASTPKI_PROMOTE_MODE=$MODE NAMESPACE=$NS $_pp ${POD:-$STANDBY} --already-promoted" >&2
fi

# ---- 5. rebuild the old primary as the new standby ------------------------------
# Never just restart it: its timeline diverged the moment the standby was promoted, so it
# would stream garbage or refuse. It has to be re-seeded from the new primary. Done only now,
# after the guard is lifted: a copy taken while it was on would carry it into the new standby.
if [ "$REBUILD" = "1" ]; then
  say "rebuild $PRIMARY_HOST as a standby of the restored server"
  case "$MODE" in
    compose)
      echo "   ON $PRIMARY_HOST, discard its diverged database and re-join:"
      echo "       docker compose down"
      echo "       docker volume rm -f \$(docker volume ls -q -f name=_pgdata\$ | head -1)"
      echo "       ./ha-join.sh <this host's address> primary-ca.crt [--primary-pin-file <file>]"
      echo "       docker compose up -d"
      echo "   and on this host:  ./ha-join.sh --on-primary $PRIMARY_HOST"
      echo "   (or both at once from your own computer: deploy/ha-join-pair.sh)" ;;
    native)
      echo "   ON $PRIMARY_HOST, as root, re-join it to this host, replacing its diverged database:"
      echo "       /usr/share/fastpki/ha-join.sh <this host's address> <this host's ca.crt> \\"
      echo "           --primary-password-file <file> --replace-local-database"
      echo "   and on this host:  /usr/share/fastpki/ha-join.sh --on-primary $PRIMARY_HOST"
      echo "   (or both at once from your own computer: deploy/ha-join-pair.sh)" ;;
    k8s)
      # Its claim holds the diverged history; without it the pod seeds from the new primary on
      # its next start (start-postgres.sh), the way the guide rebuilds a server after a failover.
      kubectl delete pvc -n "$NS" "pgdata-$OLD" --wait=false >/dev/null
      kubectl delete pod -n "$NS" "$OLD" --wait=false >/dev/null
      printf '   waiting for %s to come back as a streaming standby' "$OLD"
      _ok=0
      for _ in $(seq 1 72); do
        [ "$(qp 'SELECT pg_is_in_recovery()')" = "t" ] && { _ok=1; break; }
        printf '.'; sleep 5
      done
      echo
      if [ "$_ok" = 1 ]; then
        say "$OLD is a streaming standby of $POD"
      else
        echo "WARN: $OLD is not a streaming standby after 6 minutes. Check:" >&2
        echo "      kubectl -n $NS logs $OLD -c postgres" >&2
      fi ;;
  esac
  echo "   (the roles are now swapped. See docs/high-availability.md.)"
else
  say "left $PRIMARY_HOST alone (--no-rebuild); the deployment has NO standby until you rebuild it"
fi

echo
say "done — restored online, no protocol was ever refusing requests"
