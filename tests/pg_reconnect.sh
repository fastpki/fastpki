#!/usr/bin/env bash
# The PostgreSQL backend must auto-reconnect after its connection drops
# (server restart / failover / administrative disconnect). Before the fix a
# service held one PGconn for its whole lifetime and, once Postgres bounced,
# every query failed with "no connection to the server" until the *process* was
# restarted (observed on the lab after `docker compose up -d postgres`).
#
# This spins a throwaway cluster, seeds one cert, proves fastpki-store finds it,
# RESTARTS the cluster (severing the store's connection), then proves the store
# recovers on its own — same pid, no restart. Fails before the fix (the store
# stays broken -> non-200 forever), passes after.
#
# Self-contained: needs the Postgres server binaries (initdb/pg_ctl) + curl.
# Skips if they're absent -> CORE-safe but really a PG-tier suite.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
BIN=${BIN:-$ROOT/build}
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}

PGBIN=""
if command -v pg_ctl >/dev/null 2>&1; then PGBIN="$(dirname "$(command -v pg_ctl)")"; fi
if [ -z "$PGBIN" ] || [ ! -x "$PGBIN/initdb" ]; then
    # Highest major first — glob order is lexicographic, so plain `*` puts 16 ahead
    # of 17 and this suite would quietly keep testing the old major.
    for d in $(ls -d /usr/lib/postgresql/*/bin /usr/pgsql-*/bin \
                     /opt/homebrew/opt/postgresql*/bin 2>/dev/null | sort -V -r) \
             /opt/homebrew/opt/libpq/bin; do
        [ -x "$d/initdb" ] && PGBIN="$d" && break
    done
fi
if [ -z "$PGBIN" ] || [ ! -x "$PGBIN/initdb" ]; then echo "SKIP: Postgres server binaries (initdb/pg_ctl) not found"; exit 0; fi
source "$ROOT/tests/pg_priv.sh"
# ⚠️ LC_ALL, for the same reason postgres asks for it. On macOS a Homebrew postgres 17
# postmaster refuses to start when the locale is unset:
#
#     FATAL:  postmaster became multithreaded during startup
#     HINT:   Set the LC_ALL environment variable to a valid locale.
#
# so this suite skipped on a dev machine as well as in-image, for a completely different
# reason from the one below. A throwaway cluster has no collation requirements, so C is
# the right answer and it costs nothing where the locale was already fine.
export LC_ALL="${LC_ALL:-C}"

command -v curl >/dev/null 2>&1 || { echo "SKIP: curl not found"; exit 0; }

W="$(mktemp -d)"; cd "$W"
# mktemp -d is 0700 root-owned, so the dropped-privilege server cannot create its
# data directory inside it. No-op unless we are root (tests/pg_priv.sh).
pg_own "$W"
PORT=$(( (RANDOM % 2000) + 15600 )); STORE=18493
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fi; [ "$2" = "$3" ] || fail=$((fail+1)); }
psqlp(){ "$PGBIN/psql" -h 127.0.0.1 -p "$PORT" -U postgres -d pki -tAc "$1" 2>/dev/null; }
# ⚠️ -d postgres, EXPLICITLY. psql with no -d falls back to $PGDATABASE, and
# deploy/lab-test.sh exports PGDATABASE=fastpki for the container-wide cluster it
# creates for the PG tier. This suite builds its OWN throwaway cluster, which has no
# such database, so every probe below failed with
#
#     FATAL:  database "fastpki" does not exist
#
# forty times, and the suite skipped. That is why it asserted nothing in-image while
# counting as ok in the run totals — the cluster started perfectly; only the
# database NAME was wrong, and the skip message blamed the cluster. Never rely on an
# ambient PGDATABASE/PGUSER in a suite that provisions its own server.
waitpg(){ local i; for i in $(seq 1 40); do "$PGBIN/psql" -h 127.0.0.1 -p "$PORT" -U postgres -d postgres -tAc 'SELECT 1' >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1; }
cleanup(){ [ -n "${S:-}" ] && kill "$S" 2>/dev/null; pg_as "$PGBIN/pg_ctl" -D "$W/pg" -m immediate stop >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT
S=""

pg_as "$PGBIN/initdb" -D "$W/pg" -U postgres --auth=trust >/dev/null 2>&1
[ -f "$W/pg/postgresql.conf" ] || { echo "SKIP: initdb produced no data dir — $(pg_priv_reason)"; exit 0; }
{ echo "port = $PORT"; echo "listen_addresses = '127.0.0.1'"; } >> "$W/pg/postgresql.conf"
pg_as "$PGBIN/pg_ctl" -D "$W/pg" -l "$W/pg/pg.log" start >/dev/null 2>&1
# ⚠️ PRINT WHAT THE SERVER SAID. "could not start the throwaway cluster" is a message
# that cannot be acted on, and this suite spent an unknown number of in-image runs
# emitting it while counting as `ok`. postgres always explains itself in its own log; the
# only reason nobody saw it is that the workdir is removed on exit.
waitpg || { echo "SKIP: the throwaway cluster never accepted a connection — postgres said:";
            sed -n "s/^/       /p" "$W/pg/pg.log" 2>/dev/null | tail -6; exit 0; }
"$PGBIN/psql" -h 127.0.0.1 -p "$PORT" -U postgres -d postgres -tAc "CREATE DATABASE pki" >/dev/null 2>&1
"$PGBIN/psql" -h 127.0.0.1 -p "$PORT" -U postgres -d pki -f "$ROOT/sql/createdb.sql" >/dev/null 2>&1

# Seed one cert directly (no issuance path needed — we're testing the DB layer).
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.pem -days 3 \
    -subj "/CN=recon.internal" >/dev/null 2>&1
DER_HEX=$("$OSSL" x509 -in leaf.pem -outform DER 2>/dev/null | od -An -v -tx1 | tr -d ' \n')
psqlp "INSERT INTO certs(serial,status,subject,cn,cert) VALUES('0a0b0c',0,'CN=recon.internal','recon.internal',decode('$DER_HEX','hex'))" >/dev/null
chk "seed cert present in DB" 1 "$(psqlp "SELECT count(*) FROM certs WHERE cn='recon.internal'")"

# Minimal CA material so fastpki-store starts.
ca_in_token ca.pem "/CN=PG Reconnect CA" 3
cp ca.pem root.pem
cat > store.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=host=127.0.0.1 port=$PORT dbname=pki user=postgres
LOG_LEVEL=err
STORE_BIND=127.0.0.1
STORE_PORT=$STORE
EOF
seed_ca_from_conf store.conf   # register the CA (SIGNING_CA_* no longer seed it)

"$BIN/fastpki-store" --config store.conf >store.log 2>&1 & S=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$STORE" "$S" || true
kill -0 "$S" 2>/dev/null || { echo "fastpki-store died:"; cat store.log; exit 1; }
SPID=$S

search_code(){ curl -s -o /dev/null -w "%{http_code}" -G "http://127.0.0.1:$STORE/certificates/search" --data-urlencode "cn=recon.internal"; }

echo "=== healthy search (before restart) ==="
chk "store finds the seeded cert (200)" 200 "$(search_code)"

echo "=== RESTART Postgres — severs the store's connection ==="
pg_as "$PGBIN/pg_ctl" -D "$W/pg" -m fast -l "$W/pg/pg.log" restart >/dev/null 2>&1
waitpg || { echo "cluster did not come back"; exit 1; }

echo "=== store recovers on its own — no process restart ==="
recovered=no
for i in $(seq 1 10); do
    [ "$(search_code)" = "200" ] && { recovered=yes; break; }
    sleep 0.5
done
chk "store search recovers after PG restart" yes "$recovered"
chk "store did NOT need a restart (same pid)" yes "$(kill -0 "$SPID" 2>/dev/null && [ "$S" = "$SPID" ] && echo yes)"

echo
echo "=== PG RECONNECT: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
