#!/usr/bin/env bash
# deploy/pg-promote.sh — promote this host's streaming standby to primary after the
# primary on the OTHER host has failed.
#
# Run ON THE STANDBY HOST, from the deploy/ directory (where docker-compose.yml is).
# The app services use a multi-host PG_CONNINFO with target_session_attrs=read-write, so
# they re-home onto the promoted node automatically on their next DB statement — no app
# restart, provided that conninfo names BOTH hosts. See docs/high-availability.md.
#
# ⚠️ STOP THE OLD PRIMARY FIRST. Promotion does not demote anything: run this while the
# other host is still serving and you have two read-write databases, with applications
# free to land on either.
#
#   ./pg-promote.sh                     # promote the 'postgres' service on this host
#   ./pg-promote.sh <service>           # if the standby service is named differently
#   ./pg-promote.sh <service> --force   # promote even if the mesh check refuses
#
#   FASTPKI_PROMOTE_MODE=k8s NAMESPACE=fastpki ./pg-promote.sh fastpki-node-1
#                                       # Kubernetes: promote that server pod's database,
#                                       # from any machine with kubectl for the cluster
set -eu
SVC="${1:-postgres}"
DC="${DOCKER_COMPOSE:-docker compose}"
FORCE=0; [ "${2:-}" = "--force" ] && FORCE=1
NS="${NAMESPACE:-fastpki}"

# ── WHICH DEPLOYMENT IS THIS ──────────────────────────────────────────────────────────
#
# ⚠️ THE GUIDES SENT NATIVE AND CLOUD OPERATORS HERE, AND EVERY COMMAND WAS `docker compose`.
# A native host has no compose file, no container and no .env, so the first call failed and
# the checks this script exists for — refusing a promotion that would silently drop the data
# center out of the mesh, clearing the inherited synchronized_standby_slots, rewriting the
# conninfo and the anchor, removing STANDBY_OF — never ran at all. A cloud node IS a native
# install, so that covered every deployment shape except the packaged one.
#
# Detected rather than asked: an operator reaching for this in the middle of a failover
# should not also have to name their own deployment shape. FASTPKI_PROMOTE_MODE overrides it
# for anything unusual.
#
# ⚠️ AND KUBERNETES, WHICH IS A FOURTH SHAPE OF THE SAME PAIR. Each fastpki-node pod is a whole server
# with its own token and database, so a promotion there is the same operation — promote one
# server's database, clear what it inherited, stop describing it as a standby, give it certificates
# its applications accept, restart its listeners — reached through `kubectl exec` into that pod's
# containers. A server pod is named `fastpki-node-N`, which is also how the mode is recognised.
MODE="${FASTPKI_PROMOTE_MODE:-}"
if [ -z "$MODE" ]; then
    case "$SVC" in
        fastpki-node-[0-9]*) MODE=k8s ;;
        *)
            if [ -f docker-compose.yml ] || [ -f compose.yml ] || [ -n "${DOCKER_COMPOSE:-}" ]; then
                MODE=compose
            elif [ -f /etc/fastpki/bootstrap.conf ] && command -v rc-service >/dev/null 2>&1; then
                MODE=native
            else
                MODE=compose
            fi ;;
    esac
fi
case "$MODE" in
    compose|native) ;;
    k8s) command -v kubectl >/dev/null 2>&1 || { echo "pg-promote: k8s mode needs kubectl" >&2; exit 2; }
         case "$SVC" in
             fastpki-node-[0-9]*) ;;
             *) echo "pg-promote: in k8s mode name the server pod to promote, e.g. fastpki-node-1 (got '$SVC')" >&2; exit 2 ;;
         esac ;;
    *) echo "pg-promote: FASTPKI_PROMOTE_MODE must be compose, native or k8s (got '$MODE')" >&2; exit 2 ;;
esac
# One container of the named server pod.
kx() { _c=$1; shift; kubectl exec -n "$NS" "$SVC" -c "$_c" -- "$@"; }

# Native paths. NATIVE_CONF carries PG_CONNINFO; NATIVE_ENV is what fastpki.initd exports to
# every service (PG_BIND, P11_TLS, STANDBY_OF), which is where a standby is marked.
NATIVE_CONF=/etc/fastpki/bootstrap.conf
NATIVE_ENV=/etc/conf.d/fastpki

# ── THE FOUR THINGS THIS SCRIPT DOES TO A DATABASE, ONCE EACH ─────────────────────────
# Every mode-specific command lives here so the logic below reads the same for both, and so
# a check can never exist on one path and quietly not on the other.
#
# Native runs psql as the postgres SYSTEM user over the local socket: peer authentication,
# superuser, no password anywhere — the same reason the compose path can use -U fastpki
# inside the container. `su -s /bin/sh` because the postgres account's shell is nologin.
pg_query() {   # one value, empty on any failure
    case "$MODE" in
        compose) $DC exec -T "$SVC" psql -U fastpki -d fastpki -tAc "$1" 2>/dev/null | tr -d '[:space:]' ;;
        native)  su postgres -s /bin/sh -c "psql -d fastpki -tAc \"$(printf '%s' "$1" | sed 's/"/\\"/g')\"" 2>/dev/null | tr -d '[:space:]' ;;
        k8s)     kx postgres psql -U fastpki -d fastpki -tAc "$1" 2>/dev/null | tr -d '[:space:]' ;;
    esac
}
pg_exec2() {   # two statements as separate -c flags; ALTER SYSTEM refuses a transaction block
    case "$MODE" in
        compose) $DC exec -T "$SVC" psql -U fastpki -d fastpki -c "$1" -c "$2" >/dev/null 2>&1 ;;
        native)  su postgres -s /bin/sh -c "psql -d fastpki -c \"$1\" -c \"$2\"" >/dev/null 2>&1 ;;
        k8s)     kx postgres psql -U fastpki -d fastpki -c "$1" -c "$2" >/dev/null 2>&1 ;;
    esac
}
pg_promote_now() {
    case "$MODE" in
        compose) $DC exec -T "$SVC" sh -ec '
                     AS="$(command -v gosu || command -v su-exec)"
                     $AS postgres pg_ctl -D /var/lib/postgresql/data promote
                 ' ;;
        k8s)     kx postgres sh -ec '
                     AS="$(command -v gosu || command -v su-exec)"
                     $AS postgres pg_ctl -D /var/lib/postgresql/data promote
                 ' ;;
        # The data directory is asked for rather than assumed: it is version-numbered
        # (/var/lib/postgresql/17/data) and a major-version bump would move it silently.
        # SHOW works while the server is still in recovery, which is the only state this runs in.
        native)  _pgdata="$(pg_query 'SHOW data_directory')"
                 [ -n "$_pgdata" ] || { echo "pg-promote: cannot find the data directory — is Postgres running here?" >&2; exit 1; }
                 su postgres -s /bin/sh -c "pg_ctl -D '$_pgdata' promote" ;;
    esac
}
# ⚠️ NATIVE RUNS THE CLI AS `fastpki`, NEVER AS ROOT. The token server answers only the user
# it runs as, so a root `fastpki-ca` finds no key in its own token: measured on a cloud
# standby, root's `key sync` reported "5 missing, 0 replicated, 5 failed" where the same
# command as fastpki reported every key present. Every step below that signs — the database
# certificate, the listener certificates — failed that way at the one moment it is needed.
# PG_BIND goes along because it names this machine in the database certificate; the nightly
# job passes it the same way. Exported rather than put on the command line, so nothing
# secret passed to this reaches the process list.
NATIVE_BIND=""
[ "$MODE" = native ] && NATIVE_BIND=$(sed -n 's/^PG_BIND=//p' "$NATIVE_ENV" 2>/dev/null | head -1)
# The `--` before the user is needed: busybox su reads every dashed word on its command line
# as its own option, so `--config` after the command stopped it with "unrecognized option".
nfastpki() {   # nfastpki <command> [args...] — as the fastpki user, from a directory it can read
    ( export PG_BIND="$NATIVE_BIND"; su -s /bin/sh -c 'cd / && exec "$0" "$@"' -- fastpki "$@" )
}
# Run a command with its output indented, returning the COMMAND's exit status. `cmd | sed`
# returns sed's, so every "WARN: could not ..." below was unreachable: a promotion whose
# certificate steps failed printed the failure indented and carried on as if they had worked.
indented() {   # indented <command> [args...]
    _io=$("$@" 2>&1); _irc=$?
    [ -z "$_io" ] || printf '%s\n' "$_io" | sed 's/^/  /'
    return "$_irc"
}
fastpki_ca() {   # the CLI, against this deployment's own config
    case "$MODE" in
        compose) $DC exec -T web fastpki-ca "$@" ;;
        native)  nfastpki fastpki-ca --config "$NATIVE_CONF" "$@" ;;
        k8s)     kx renew fastpki-ca --config /app/config/bootstrap.conf "$@" ;;
    esac
}
# Replace a file with a filter's output, keeping its owner and mode. The copy made first is
# what carries them: a file written fresh by root takes root's umask, which turned
# bootstrap.conf — 0640 root:fastpki, holding the database password — into 0644 root:root.
rewrite() {   # rewrite <file> <filter> [args...] — the filter reads <file>, appended last
    _rf=$1; shift
    if cp -p "$_rf" "$_rf.promote.tmp" && "$@" "$_rf" > "$_rf.promote.tmp" && mv "$_rf.promote.tmp" "$_rf"; then
        return 0
    fi
    rm -f "$_rf.promote.tmp"; return 1
}

echo "== promote: $SVC -> read-write primary ($MODE) =="

# ⚠️ ON KUBERNETES, REFUSE WHILE ANOTHER SERVER IS STILL READ-WRITE. Promotion demotes nothing,
# and a Compose operator is told to stop the old primary first. A server pod whose node is merely
# unreachable from here may still be serving, and one whose node comes back starts on its own —
# so the check is made rather than trusted to the reader: every other fastpki-node pod that answers
# is asked whether its database is in recovery.
if [ "$MODE" = k8s ]; then
    _others=$(kubectl get pods -n "$NS" -l app.kubernetes.io/component=node -o name 2>/dev/null \
              | sed 's|^pod/||' | grep -vx "$SVC" || true)
    for _o in $_others; do
        _r=$(kubectl exec -n "$NS" "$_o" -c postgres -- psql -U fastpki -d fastpki -tAc \
               'SELECT pg_is_in_recovery()' 2>/dev/null | tr -d '[:space:]' || true)
        if [ "$_r" = f ]; then
            echo "REFUSING to promote $SVC: $_o is still a read-write primary." >&2
            echo "  Two primaries give applications two databases to land on, and they diverge." >&2
            echo "  If $_o's node is gone but the pod is reported running, confirm the node is" >&2
            echo "  down (kubectl get nodes) and delete the pod first. Accept anyway with: $0 $SVC --force" >&2
            [ "$FORCE" = 1 ] || exit 1
            echo "  --force given: promoting anyway." >&2
        fi
    done
fi

# ---- PRE-FLIGHT: would this promotion drop the DC out of the mesh? ----------------
# Logical replication slots are NOT copied to a physical standby by WAL. PG17
# synchronises the ones flagged failover=true — but only into a slot that starts
# TEMPORARY and is dropped the instant the sync worker exits, which is what promotion
# does. Measured, with everything else identical: temporary=f survives a promote with
# byte-identical LSNs; temporary=t leaves zero slots behind. So "the slot is present"
# and "the slot survives a promote" are different facts, and only the second one
# matters here.
#
# Promoting without them is the whole failure: the DC keeps serving locally, the apps
# re-home exactly as promised, nothing logs an error, and it has silently stopped
# feeding its peers.
#
# ⚠️ ASSIGN, then test — never test a $( ) inline under set -eu. And an EMPTY answer
# (container down, PG < 17, psql failed) must not read as "0 of 0, fine": that is the
# shape that turns a broken probe into a silent pass.
slotq(){ pg_query "$1"; }

# PEERS comes from pg_subscription, which is catalog data the standby already holds.
# It is readable with the primary DOWN — the realistic failover case, and exactly when
# the primary-side slot list is not available to compare against. fastpki-mesh builds a
# FULL mesh (N*(N-1)), so the number of peers this node subscribes TO equals the number
# of outbound slots those peers consume FROM it.
PEERS=$(slotq "SELECT count(*) FROM pg_subscription s
                 JOIN pg_database d ON d.oid = s.subdbid
                WHERE d.datname = current_database();")
# Persisted, synced, and not invalidated. wal_status='lost' is the max_slot_wal_keep_size
# cap having fired; such a slot exists as a row and can never resume.
READY=$(slotq "SELECT count(*) FROM pg_replication_slots
                WHERE slot_type='logical' AND slot_name LIKE 'sub_%'
                  AND synced AND NOT temporary
                  AND (conflicting IS NOT TRUE) AND wal_status <> 'lost';")

case "${PEERS}${READY}" in
  ''|*[!0-9]*)
    # ⚠️ SAY WHICH OF THE TWO HAPPENED. With --force this path PROMOTES, so printing
    # "REFUSING" and then "re-run with --force" to an operator who had already passed it
    # reported the opposite of what the script did — at the one moment in a deployment's
    # life that cannot be re-read afterwards, because the node is a read-write primary by
    # the time the next line scrolls past. Nothing later corrected it either: with PEERS
    # empty, ${PEERS:-0} silences both the mesh block and the pre-flight line below. The
    # mesh branch has always distinguished refusing from proceeding; this one did not.
    echo "WARNING: cannot read $SVC's replication state (is it up? is it PostgreSQL 17+?)." >&2
    echo "         'synced' does not exist before PG17, so this reads empty on an old server." >&2
    if [ "$FORCE" = 1 ]; then
      echo "  --force given: promoting anyway." >&2
    else
      echo "REFUSING to promote. Accept the consequence with:  $0 $SVC --force" >&2
      exit 1
    fi ;;
esac

# PEERS = 0 is a single-DC deployment with no mesh at all. It has no
# logical slots to lose, and must not be blocked by a mesh concern it does not have.
if [ "${PEERS:-0}" -gt 0 ] && [ "${READY:-0}" -lt "${PEERS:-0}" ]; then
  echo "REFUSING to promote: only ${READY:-0} of ${PEERS:-0} peer logical slots are synced and persisted on $SVC." >&2
  echo "  Promoting now takes this DC OUT of the cross-DC mesh: it will keep serving" >&2
  echo "  locally and silently stop replicating, and the peers cannot be re-pointed back." >&2
  echo "  On the standby, check the four things PG17 requires — each one missing gives the" >&2
  echo "  same symptom (no synced slots, nothing in any log):" >&2
  echo "    SHOW sync_replication_slots;   -- must be on" >&2
  echo "    SHOW hot_standby_feedback;     -- must be on" >&2
  echo "    SHOW primary_slot_name;        -- must be non-empty" >&2
  echo "    SHOW primary_conninfo;         -- must carry a REAL dbname, not dbname=replication" >&2
  echo "  and on the primary, that every sub_% slot has failover = true." >&2
  echo "  Accept the consequence with:  $0 $SVC --force" >&2
  [ "$FORCE" = 1 ] || exit 1
  echo "  --force given: promoting anyway." >&2
fi
[ "${PEERS:-0}" -eq 0 ] || echo "  pre-flight: ${READY}/${PEERS} peer slots synced and persisted."

# ---- promote ----------------------------------------------------------------------
# pg_ctl promote as the postgres user: inside the standby container on compose, on the host
# itself on native.
pg_promote_now

# Wait for it to leave recovery (become read-write).
rec=t
printf 'waiting for read-write'
for _ in $(seq 1 30); do
  rec="$(pg_query 'SELECT pg_is_in_recovery()')"
  [ "$rec" = "f" ] && break
  printf '.'; sleep 1
done
echo

if [ "$rec" = "f" ]; then
  # ⚠️ synchronized_standby_slots is INHERITED through pg_basebackup and names
  # the physical slot of a standby this node no longer has. Left in place, every
  # logical walsender here waits forever on a slot that does not exist — and the only
  # sign is a WARNING nobody is tailing:
  #   "replication slot \"fastpki_<standby address>\" specified in parameter
  #    \"synchronized_standby_slots\" does not exist"
  # The slots survived, they are active, and they move nothing. Clear it.
  # ⚠️ SEPARATE -c FLAGS: both in one is an implicit transaction and ALTER SYSTEM
  # refuses with "cannot run inside a transaction block".
  if pg_exec2 "ALTER SYSTEM SET synchronized_standby_slots = ''" "SELECT pg_reload_conf()"; then
    echo "cleared the inherited synchronized_standby_slots — it named a standby this node no longer has."
  else
    echo "WARN: could not clear synchronized_standby_slots — logical decoding here may stall." >&2
  fi

  echo "OK: $SVC is now a read-write primary."
  echo "The app services re-home onto it on their next query (no restart needed)."

  # ---- this node is a primary now, so stop describing it as a standby ----------------
  #
  # ⚠️ STANDBY_OF LEFT BEHIND MAKES THE NEXT RESTART FAIL. The entrypoint reads it to decide
  # whether to seed with pg_basebackup instead of starting on the data it has, and after a
  # promotion that is exactly the wrong answer. It refuses rather than re-seeding — the data
  # directory is already initialised, and destroying a freshly promoted primary would be the
  # worst possible reading of an ambiguous variable — so the node simply will not come back:
  #
  #   postgres: STANDBY_OF=<addr> but the data directory is already PG17 — refusing to start.
  #
  # That is a good refusal and a bad state to be left in: nothing restarts a container on
  # purpose the day it is promoted, so this is found weeks later by an unrelated reboot.
  # Rewritten with rewrite() rather than `sed -i`: busybox sed does not take a suffix the way
  # GNU and BSD do, and .env carries the database password, so it keeps its own mode.
  # Native keeps the same mark in /etc/conf.d/fastpki, which fastpki.initd exports to every
  # service; there it is what makes the console keep calling this host a standby and the
  # nightly job keep trying to copy keys from the host that failed.
  # Kubernetes keeps it as /var/pki/standby_of on the server's own claim (start-postgres.sh writes
  # it when the pod seeds), read by the console and the renewal loop when they start.
  _sf=""
  case "$MODE" in
    compose) _sf=.env ;;
    native)  _sf="$NATIVE_ENV" ;;
    k8s)     if kx postgres rm -f /pki/standby_of 2>/dev/null; then
                 echo "removed /var/pki/standby_of from $SVC — this server is a primary now."
             else
                 echo "WARN: could not remove /pki/standby_of in $SVC's postgres container. Do it by" >&2
                 echo "      hand, or the console and the renewal loop keep calling it a standby." >&2
             fi ;;
  esac
  if [ -n "$_sf" ] && [ -f "$_sf" ] && grep -q '^STANDBY_OF=' "$_sf" 2>/dev/null; then
      if rewrite "$_sf" grep -v '^STANDBY_OF='; then
          echo "removed STANDBY_OF from $_sf — this node is a primary, and with it set its"
          echo "  Postgres would refuse to start on its next restart."
      else
          echo "WARN: could not remove STANDBY_OF from $_sf. Do it by hand: with it set," >&2
          echo "      this node's Postgres refuses to start on its next restart." >&2
      fi
  fi

  # ---- this host is the writer now, so its own conninfo must say so -----------------
  #
  # ⚠️ ha-join.sh WROTE THE OTHER NODE FIRST, AND THAT WAS CORRECT AT JOIN TIME. A freshly
  # joined standby is itself the unverifiable host, so its override names the PRIMARY first and
  # points `sslrootcert` at the copy of the primary's anchor (primary-ca.crt). A promotion swaps
  # which host is which, and nothing rewrites either value — so this node, now the writer, keeps
  # naming its peer first and keeps verifying against the other machine's anchor.
  #
  # Neither is fatal on its own, which is why it survives: target_session_attrs=read-write still
  # finds the writer. But every NEW connection tries the peer first and waits out
  # connect_timeout before falling through, and the moment that peer is REBUILT — serving the
  # self-signed pair certgen makes — libpq stops at the first host it cannot verify and never
  # tries the second. Measured on a promoted pair whose old primary was being rebuilt: this
  # node's own CLI failed with
  #   fastpki-config: postgres connect failed: connection to server at "<the peer>" ...
  #   SSL error: certificate verify failed
  # on a node that was perfectly healthy, with an error naming the OTHER machine. Everything
  # administrative stopped — the trust sync the rebuild needed included.
  #
  # The anchor is the half worth insisting on: primary-ca.crt is a COPY of the old primary's
  # ca.crt, so it verifies this node's own database only while both certificates happen to come
  # from the same CA. That is true when the sweep maintains them and false on a pair built before
  # that, which makes it a coincidence rather than a design.
  # This host's own address is PG_BIND in .env — the same value that identifies it in
  # p11_transport, and the only per-host address a pair has (PKI_DNS is shared by design).
  # Native carries the same two facts in different files: PG_BIND in /etc/conf.d/fastpki (it
  # is exported to the services), and the conninfo itself in bootstrap.conf rather than in a
  # compose override. The rewrite below is identical either way, so only the filenames move.
  # ⚠️ KUBERNETES HAS NOTHING TO REWRITE, AND THAT IS DESIGNED RATHER THAN MISSED. Every server
  # shares one conninfo naming every pod, and verifies with a trust bundle holding every pod's
  # anchor and the PKI's roots (deploy/k8s/pg-trust.sh) — so no order and no single anchor can go
  # stale at a promotion.
  _self=""; _cfile=""
  case "$MODE" in
    compose) _self=$(sed -n 's/^PG_BIND=//p' .env 2>/dev/null | head -1)
             _cfile=docker-compose.override.yml ;;
    native)  _self=$(sed -n 's/^PG_BIND=//p' "$NATIVE_ENV" 2>/dev/null | head -1)
             [ -n "$_self" ] || _self=$(sed -n 's/^PG_BIND=//p' "$NATIVE_CONF" 2>/dev/null | head -1)
             _cfile="$NATIVE_CONF" ;;
    k8s)     _self="$SVC.fastpki-node" ;;
  esac
  # ⚠️ SAY SO WHEN THIS IS SKIPPED. Both paths guarded on "$_self" being known and did nothing
  # when it was not — and a rewrite that silently does not happen during a failover is the
  # worst kind, because the symptom (every new connection waiting out a connect_timeout
  # against the dead host, and verification failing outright once it is rebuilt) arrives
  # later and points at the other machine. Measured on a node installed before PG_BIND was
  # recorded at all: neither /etc/conf.d/fastpki nor bootstrap.conf carried it.
  if [ -z "$_self" ]; then
      echo "NOTE: this host's own address is not recorded (PG_BIND), so its conninfo was left"
      echo "  as it is. If it names the failed host first, put this host first by hand:"
      echo "    $_cfile — the PG_CONNINFO host= list, this address first"
  fi
  if [ -n "$_cfile" ] && [ -f "$_cfile" ] && [ -n "$_self" ]; then
    _before=$(grep -m1 -oE 'host=[0-9a-zA-Z.,:_-]+' "$_cfile" 2>/dev/null || true)
    # Rebuild the host list as: this host, then every other entry, in order. ONE substitution
    # per line, no loop: each PG_CONNINFO sits on its own line, and a loop here re-matched the
    # text it had just rewritten and never terminated — which would have hung this script in the
    # middle of a failover, the worst possible moment. Unit-tested against a list already in the
    # right order, one in the wrong order, and a single-host list.
    rewrite "$_cfile" awk -v self="$_self" '
      {
        if (match($0, /host=[0-9a-zA-Z.,:_-]+/)) {
          list = substr($0, RSTART + 5, RLENGTH - 5)
          n = split(list, a, ","); out = self
          for (i = 1; i <= n; i++) if (a[i] != self && a[i] != "") out = out "," a[i]
          $0 = substr($0, 1, RSTART - 1) "host=" out substr($0, RSTART + RLENGTH)
        }
        print
      }' || true
    # Verify against THIS node's own anchor, not the copy of its former primary's.
    if grep -q 'primary-ca.crt' "$_cfile" 2>/dev/null; then
      rewrite "$_cfile" sed 's|sslrootcert=/var/pki/tls/pg/primary-ca.crt|sslrootcert=/var/pki/tls/pg/ca.crt|g' || true
    fi
    echo "  rewrote this host's application conninfo for its new role:"
    echo "    was: $_before"
    echo "    now: $(grep -m1 -oE 'host=[0-9a-zA-Z.,:_-]+' "$_cfile" 2>/dev/null)" \
         "(and sslrootcert now this node's own ca.crt)"
    # Native services read bootstrap.conf when they start, and the restart below does that. A
    # compose `restart` keeps each container's old environment, so the override needs a recreate.
    case "$MODE" in
      compose) echo "  the services take it on their next recreate:  docker compose up -d" ;;
      native)  echo "  the services read it when they restart, below." ;;
    esac
  fi

  # ---- and give it a database certificate its own applications will accept -----------
  #
  # ⚠️ USUALLY A NO-OP, AND THAT IS THE POINT — `--if-needed` makes it safe to run always.
  # A standby is NOT unable to issue: its applications dial the multi-host PG_CONNINFO with
  # target_session_attrs=read-write, so they reach the PRIMARY's database and a write from
  # here lands there like any other. The real precondition is the CA key being in this node's
  # token, which `key sync` puts there and certrenew does unprompted — and a standby that has
  # it issues its own database certificate while still in recovery. Measured on one reporting
  # pg_is_in_recovery() = t: issuer was the issuing CA, with this host's own address in the
  # SANs.
  #
  # What follows is for a standby that joined WITHOUT key replication. With no CA key it
  # genuinely cannot sign, its Postgres still serves the self-signed pair certgen made at
  # deploy time, and the tool that would fix that needs the very connection the bad
  # certificate breaks. Its applications verify against the PRIMARY's anchor, which does not
  # certify that, so every one of them fails:
  #
  #   connection to server at "<this host>", port 5432 failed: SSL error: certificate verify failed
  #
  # and `fastpki-ca pg-tls`, which would replace it, cannot connect either. The way out is a
  # ONE-SHOT connection that does not verify — used for this single command, at the single
  # moment the node has just become writable and its own certificate is still the wrong one.
  # Nothing is left configured that way: the pair written here chains to the deployment's
  # root, and every later connection verifies normally.
  # ⚠️ NO ca-id HERE, DELIBERATELY. Which CA issues the database certificate is
  # PG_TLS_CA_ID, and that is a row in the `config` TABLE — not a .env key — so reading it
  # from .env would miss on every deployment that set it the documented way. `pg-tls` with
  # no argument resolves it itself, and says so plainly when it is unset. `--if-needed`
  # makes this a no-op on a node whose certificate is already right, which is what lets it
  # run unconditionally after every promotion.
  #
  # ⚠️ host=$SVC, NOT 127.0.0.1. This is a one-shot `compose run` container with its own
  # network namespace, so loopback is the container itself and the connection is refused.
  # The service name resolves on the compose network, which is what every app already uses.
  #
  # Native needs the same one-shot escape for the same reason, but builds it differently:
  # there is no compose network, so the host is loopback, and the password is the one in this
  # node's own PG_CONNINFO rather than a compose variable. PG_CONNINFO is passed in the
  # environment, which overrides the file for this single command and leaves nothing behind.
  echo "issuing this node's own database certificate..."
  case "$MODE" in
    compose) _pw="$(sed -n 's/^POSTGRES_PASSWORD=//p' .env 2>/dev/null | head -1)"
             _pgtls() { $DC run --rm --no-deps \
                 -e PG_CONNINFO="host=$SVC port=5432 dbname=fastpki user=fastpki password=$_pw sslmode=require connect_timeout=5" \
                 --entrypoint fastpki-ca web --config /app/config/bootstrap.conf \
                 pg-tls --if-needed; } ;;
    native)  _npw="$(sed -n 's/^PG_CONNINFO=.*password=\([^ ]*\).*/\1/p' "$NATIVE_CONF" 2>/dev/null | head -1)"
             _pgtls() { ( export PG_CONNINFO="host=127.0.0.1 port=5432 dbname=fastpki user=fastpki password=$_npw sslmode=require connect_timeout=5"
                          nfastpki fastpki-ca --config "$NATIVE_CONF" pg-tls --if-needed ); } ;;
    # The server's own database is on loopback inside its pod, and PGPASSWORD is already in
    # the renew container's environment from the Secret.
    k8s)     _pgtls() { kx renew env PG_CONNINFO="host=127.0.0.1 port=5432 dbname=fastpki user=fastpki sslmode=require connect_timeout=5" \
                 fastpki-ca --config /app/config/bootstrap.conf pg-tls --if-needed; } ;;
  esac
  if ! indented _pgtls; then
      echo "WARN: could not issue this node's database certificate. Until it is issued," >&2
      echo "      this node serves the self-signed pair certgen made and its own apps" >&2
      echo "      refuse it with 'certificate verify failed'. See docs/high-availability.md." >&2
  fi

  # ---- this node's LISTENER certificates, for the same reason --------------------------
  #
  # ⚠️ ALSO USUALLY A NO-OP, for the same reason as the database certificate above: a standby
  # holding the CA key promotes its own listener certificates while still a standby, and its
  # certrenew does it unprompted — measured, `listener certificates: checked 4, re-issued 4`
  # on a node reporting pg_is_in_recovery() = t.
  #
  # It stays here because it costs nothing when there is nothing to do and is the difference
  # between serving and not when there is. For a standby that joined without key replication
  # these are still the self-signed certificates certgen made at install, missed for far longer
  # than the database one because nothing refuses them from inside the deployment. Leaving that
  # case to the daily certrenew tick means up to a day of four listeners serving a certificate
  # no strict client accepts: measured, the
  # demo fails five steps on it and certbot aborts with CERTIFICATE_VERIFY_FAILED.
  echo "promoting this node's self-signed listener certificates..."
  if ! indented fastpki_ca renew-service-certs --re-issue-self-signed; then
      # The command also checks the RA and responder credentials, so a failure is not
      # necessarily a listener's: the lines above name each one that failed.
      echo "WARN: renew-service-certs failed for the certificates named above. A listener still" >&2
      echo "      on a self-signed certificate is refused by strict clients, and an RA or" >&2
      echo "      responder credential that failed is not renewed. See docs/high-availability.md." >&2
  fi

  # ⚠️ AND RESTART, WHICH IS THE HALF THAT GETS LEFT OUT. Two separate caches make a
  # promotion look complete while the node serves nothing:
  #
  #   - a re-issued listener certificate is a new row, and the listener picks its
  #     certificate at START — publishing one changes nothing until it looks again;
  #   - the RA credentials of a node that booted as a standby land in its token later, from
  #     `key sync`. ocsp and cmp re-check for one that was absent at startup and put it into
  #     service themselves, and scep reads its own per request, so this is no longer required
  #     for them — it only makes the change immediate instead of within the re-check
  #     interval, which is worth having at the one moment an operator is watching a failover.
  #
  # ocsp, cmp and scep serve plain HTTP and have no listener certificate of their own,
  # which makes them precisely the three an operator leaves out of a restart — and
  # precisely the three that then fail. So the list is explicit and not narrowed.
  echo "restarting the protocol services so they re-read certificates and credentials..."
  # Native runs the same eight under OpenRC, one service each, and a protocol this deployment
  # did not install simply has no init script — so a missing one is skipped rather than
  # reported as a failure.
  case "$MODE" in
    compose) indented $DC restart ocsp cmp scep est acme ms store web || \
                 echo "WARN: restart the protocol services by hand before relying on this node." >&2 ;;
    native)  for _s in ocsp cmp scep est acme ms store web; do
                 [ -x "/etc/init.d/fastpki-$_s" ] || continue
                 indented rc-service "fastpki-$_s" restart || \
                     echo "WARN: fastpki-$_s did not restart — do it by hand before relying on this node." >&2
             done ;;
    # Each container restarted in place — never the pod, which would take the database this
    # just promoted down with it. `renew` too: it reads STANDBY_OF when it starts.
    k8s)     for _s in ocsp cmp scep est acme ms store web renew; do
                 kx "$_s" kill 1 >/dev/null 2>&1 || \
                     echo "WARN: $SVC's $_s container did not restart — do it by hand before relying on this server." >&2
             done
             echo "  restarted the listeners, the console and the renewal loop of $SVC" ;;
  esac

  # ---- do this node's CA certificates name a host that still exists? -----------------
  #
  # ⚠️ CRLDP AND AIA ARE BAKED WHEN A CA CERTIFICATE IS MINTED, from BASE_URL or PKI_DNS.
  # A pair whose hierarchy was created on the primary therefore carries the PRIMARY's own
  # name in every CA certificate, and a promotion leaves those URLs pointing at the host
  # that just died. Leaves are unaffected — this node issues those under its own name — so
  # nothing fails until a relying party does strict validation, and then it fails at
  # depth 1 with `unable to get certificate CRL` against a PKI that is otherwise healthy.
  #
  # Best effort only, and never fatal: it reads the CA rows and looks for this node's own
  # name among the URLs they advertise. A pair fronted by a shared DNS name or VIP — the
  # arrangement that makes a promotion invisible — will not match it either, which is why
  # this asks the operator to confirm rather than declaring a fault.
  case "$MODE" in
    compose) _selfname="$(sed -n 's/^PKI_DNS=//p' .env 2>/dev/null | head -1)" ;;
    native)  _selfname="$(sed -n 's/^PKI_DNS=//p' "$NATIVE_CONF" 2>/dev/null | head -1)" ;;
    k8s)     _selfname="$(kx renew sh -c 'sed -n "s/^PKI_DNS=//p" /app/config/bootstrap.conf' 2>/dev/null | tail -1)" ;;
  esac
  if [ -n "$_selfname" ]; then
      _cas=$(pg_query "SELECT string_agg(encode(cert,'base64'), ' ') FROM certs WHERE is_ca AND cert IS NOT NULL")
      _bad=0
      for _b64 in $_cas; do
          # Native decodes on the host, where openssl is installed alongside the binaries;
          # compose borrows the container's, since the host may have none.
          case "$MODE" in
            compose) _urls=$(printf '%s' "$_b64" | $DC exec -T "$SVC" sh -c \
                               'base64 -d 2>/dev/null | openssl x509 -inform DER -noout -text 2>/dev/null' \
                             | sed -n 's/.*URI:\([^ ]*\).*/\1/p') ;;
            native)  _urls=$(printf '%s' "$_b64" | base64 -d 2>/dev/null \
                             | openssl x509 -inform DER -noout -text 2>/dev/null \
                             | sed -n 's/.*URI:\([^ ]*\).*/\1/p') ;;
            k8s)     _urls=$(printf '%s' "$_b64" | kubectl exec -i -n "$NS" "$SVC" -c renew -- sh -c \
                               'base64 -d 2>/dev/null | openssl x509 -inform DER -noout -text 2>/dev/null' \
                             | sed -n 's/.*URI:\([^ ]*\).*/\1/p') ;;
          esac
          [ -n "$_urls" ] || continue
          printf '%s\n' "$_urls" | grep -q "$_selfname" || _bad=$((_bad+1))
      done
      if [ "$_bad" -gt 0 ]; then
          echo
          echo "CHECK THE CA URLs: $_bad CA certificate(s) advertise a CRLDP/AIA host that is not"
          echo "  $_selfname. If that host is the primary you just replaced, every relying party"
          echo "  doing strict validation now fails at depth 1 with 'unable to get certificate CRL',"
          echo "  while this node serves the same CRL correctly under its own name."
          echo "  A certificate cannot be told a new URL, so the repair is to re-issue the CA"
          echo "  certificates under the SAME keys with the URLs corrected — serials change and"
          echo "  nothing issued under them becomes invalid, because leaves chain by key and name."
          echo "  If instead they name a shared DNS name or VIP in front of the pair, this is"
          echo "  correct and there is nothing to do. See docs/high-availability.md."
      fi
  fi
  if [ "${PEERS:-0}" -gt 0 ]; then
    echo
    echo "MESH: this node now serves its peers from the synced slots. The peers reach it"
    echo "      because their subscriptions name BOTH servers of this data center"
    echo "      (host=<primary>,<standby> port=5432,5432 target_session_attrs=read-write), which"
    echo "      deploy/mesh-join.sh writes when the data center is given as <primary>+<standby>."
    echo "      A peer whose subscription names only the failed server has to be re-pointed on"
    echo "      that peer:"
    echo "        ALTER SUBSCRIPTION <name> CONNECTION '<the two-host conninfo>';"
  fi
  echo
  if [ "$MODE" = k8s ]; then
    # The protocol Services select every server pod, so the address clients use already reaches
    # this one; there is nothing to move.
    echo "The protocol Services already reach $SVC: they spread across every server pod."
    echo
    echo "IMPORTANT: promotion is one-way. To restore redundancy, rebuild the OLD primary as a"
    echo "fresh standby of this server — its timeline diverged, and its pod refuses to start as a"
    echo "second primary. Delete its database claim and pod once its node is back:"
    echo "  kubectl -n $NS delete pvc pgdata-<old-pod> --wait=false"
    echo "  kubectl -n $NS delete pod <old-pod>"
    echo "It seeds from $SVC on its next start. docs/deployment.md 8.5 has the whole sequence."
  else
  # ⚠️ THE DATABASE IS PROMOTED; THE ADDRESS HAS NOT MOVED. A pair advertises one address,
  # and every certificate this CA issued names it — so until it follows the survivor,
  # clients are still dialling the host that failed. Said here because this is the moment
  # an operator believes the failover is finished.
  echo "NEXT: move the pair's shared address to this host, or clients keep reaching the"
  echo "      old one — the name in every issued certificate does not change."
  echo "        on a VIP/keepalived pair: it follows on its own"
  echo "        in a cloud VPC it cannot: deploy/cloud/aws-ha-address.sh move \\"
  echo "          --deployment <name> --node <N> --to-instance <id> --ssh <user@this-host> -i <ssh key>"
  echo "      docs/high-availability.md 4a explains why keepalived cannot work in a VPC."
  echo
  echo "IMPORTANT: promotion is one-way. To restore redundancy, rebuild the OLD primary"
  echo "as a fresh standby of this node (never just restart it — its timeline diverged)."
  echo "From your own machine, once the old primary's host is back:"
  echo "  deploy/ha-join-pair.sh --primary <user>@<this host> --standby <user>@<old primary> \\"
  echo "      --replace-local-database -i <ssh key>"
  fi
else
  case "$MODE" in
    compose) echo "WARN: $SVC did not leave recovery — check '$DC logs $SVC'." >&2 ;;
    native)  echo "WARN: Postgres did not leave recovery — check its log under the data" >&2
             echo "      directory, and 'rc-service postgresql status'." >&2 ;;
    k8s)     echo "WARN: $SVC's database did not leave recovery — check" >&2
             echo "      kubectl -n $NS logs $SVC -c postgres" >&2 ;;
  esac
  exit 1
fi
