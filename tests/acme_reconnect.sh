#!/usr/bin/env bash
# tests/acme_reconnect.sh — the ACME sibling of pg_reconnect.sh.
#
# The ACME service keeps its OWN Postgres connection (acme_db_postgres.cpp), separate
# from the main Db. Only the main Db was taught to reconnect — so before this fix, once
# Postgres bounced (restart / HA failover), AcmePostgres held a dead PGconn and every
# ACME DB op failed until the *process* was restarted. That made ACME the one protocol
# that would NOT re-home on a single-DC failover. This proves it now does.
#
# Stands up its OWN throwaway cluster (so it can restart it), starts fastpki-acme, mints
# a nonce (GET /new-nonce -> save_nonce = a real WRITE), RESTARTS the cluster to sever
# the connection, then mints another nonce: before the fix that stays broken forever
# (non-2xx, no new row); after, AcmePostgres PQresets and the write lands — same pid,
# no restart. Fails before the fix, passes after.
#
# Self-contained (§3d) + shell-only (§3e). SKIPs without the Postgres server binaries.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
export LC_ALL=C
ACME="$ROOT/build/fastpki-acme"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
is2xx(){ case "$1" in 2*) echo yes;; *) echo no;; esac; }

# Locate the Postgres server binaries (mirror pg_reconnect.sh).
PGBIN=""
command -v pg_ctl >/dev/null 2>&1 && PGBIN="$(dirname "$(command -v pg_ctl)")"
if [ -z "$PGBIN" ] || [ ! -x "$PGBIN/initdb" ]; then
  # Highest major first — plain glob order is lexicographic, so 16 beats 17.
  for d in $(ls -d /usr/lib/postgresql/*/bin /usr/pgsql-*/bin \
                   /opt/homebrew/opt/postgresql*/bin 2>/dev/null | sort -V -r) \
           /opt/homebrew/opt/libpq/bin; do
    [ -x "$d/initdb" ] && PGBIN="$d" && break
  done
fi
[ -n "$PGBIN" ] && [ -x "$PGBIN/initdb" ] || { echo "SKIP: Postgres server binaries not found"; exit 0; }
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
[ -x "$ACME" ] || { echo "SKIP: fastpki-acme not built"; exit 0; }

W="$(mktemp -d)"; cd "$W"
# mktemp -d is 0700 root-owned, so the dropped-privilege server cannot create its
# data directory inside it. No-op unless we are root (tests/pg_priv.sh).
pg_own "$W"
PORT=$(( (RANDOM % 2000) + 15800 ))     # throwaway pg port
APORT=$(( (RANDOM % 2000) + 17800 ))    # acme https port
SRV=""
cleanup(){ [ -n "$SRV" ] && kill "$SRV" 2>/dev/null; pg_as "$PGBIN/pg_ctl" -D "$W/pg" -m immediate stop >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT
psqlp(){ "$PGBIN/psql" -h 127.0.0.1 -p "$PORT" -U postgres -d pki -tAc "$1" 2>/dev/null | tr -d ' '; }
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

# fastpki-acme is HTTPS-only: give it a CA + a listener cert.
ca_in_token ca.pem "/CN=ACME Reconnect CA" 3
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
cat > bootstrap.conf <<EOF
BASE_URL=https://localhost:$APORT
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
ACME_CERT=$W/acme.pem
ACME_KEY=$W/acme.key
PG_CONNINFO=host=127.0.0.1 port=$PORT dbname=pki user=postgres
ACME_BIND=127.0.0.1
ACME_PORT=$APORT
ACME_BASE_PATH=/acme
LOG_LEVEL=info
EOF
# ⚠️ NO CA is seeded here, deliberately. A `seed_ca_from_conf bootstrap.conf` line used to sit
# on this spot and had NEVER run: this suite sources only hsm_helpers.sh, so the function
# was not in scope and every run printed `seed_ca_from_conf: command not found` while
# passing. Sourcing pg_helpers.sh to "fix" it would be the wrong repair — this suite
# brings up its OWN postgres (its own port, dbname=pki, user=postgres) and asserts
# nonce writes and reconnection after a DB bounce. It never issues a certificate, so it
# needs no CA. The line was copy-paste from an earlier sweep, doing nothing but noise.
"$ACME" --config bootstrap.conf > srv.log 2>&1 & SRV=$!
# ⚠️ NOT A READINESS WAIT — DO NOT REPLACE IT WITH wait_conf/wait_port. This suite is
# about RECONNECTING to Postgres, and the second is for the cluster and the server's
# connection to it to settle, not for the ACME port to open. A port poll returns in ~50ms
# and every request then fails with 000, which reads as a dead server.
sleep 1
kill -0 $SRV 2>/dev/null || { echo "fastpki-acme died:"; cat srv.log; exit 1; }
NONCE_URL="https://127.0.0.1:$APORT/acme/ca/new-nonce"

echo "=== 1. ACME mints a nonce (a real WRITE) before any outage ==="
c1=$(curl -sk -o /dev/null -w '%{http_code}' "$NONCE_URL")
chk "new-nonce is served (2xx)"       yes "$(is2xx "$c1")"
chk "a nonce row was written"         1   "$(psqlp 'SELECT count(*) FROM nonces')"

echo "=== 2. RESTART Postgres — sever the ACME service's connection ==="
pg_as "$PGBIN/pg_ctl" -D "$W/pg" -m fast -l "$W/pg/pg.log" restart >/dev/null 2>&1
waitpg || { echo "cluster did not come back"; exit 1; }
n_mid="$(psqlp 'SELECT count(*) FROM nonces')"   # the pre-restart nonce is durable => 1

echo "=== 3. ACME recovers on its own — no process restart ==="
# libpq only marks the conn CONNECTION_BAD once an op fails on it, so the first
# request after the drop is sacrificial (throws once); ensure_conn PQresets on the
# next one. Same self-healing loop as pg_reconnect.sh. Before the fix NO number of
# retries recovers (AcmePostgres never resets) -> this stays 'no' -> the suite fails.
kill -0 $SRV 2>/dev/null; chk "fastpki-acme still running (same pid)" 0 "$?"
recovered=no
for _ in $(seq 1 10); do
  [ "$(is2xx "$(curl -sk -o /dev/null -w '%{http_code}' "$NONCE_URL")")" = "yes" ] && { recovered=yes; break; }
  sleep 0.5
done
chk "new-nonce recovers after the DB bounce (AcmePostgres reconnected)" yes "$recovered"
# Decisive: the recovered WRITE actually reached the restarted backend — row count grew.
chk "a nonce was persisted after the restart (count grew)" yes \
  "$([ "$(psqlp 'SELECT count(*) FROM nonces')" -gt "${n_mid:-1}" ] && echo yes || echo no)"

echo
echo "=== ACME RECONNECT: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
