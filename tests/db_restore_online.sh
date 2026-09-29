#!/usr/bin/env bash
# Restoring the database must not take FastPKI down.
#
# deploy/db-restore-online.sh restores into the HA standby while the primary keeps
# serving, then cuts over. The whole design rests on ONE claim about libpq, and this
# suite exists to prove that claim rather than assume it:
#
#   a promoted node carrying `default_transaction_read_only=on` is writable by us,
#   and INVISIBLE to a client using `target_session_attrs=read-write`.
#
# If that is not true, promoting the standby early would leave two read-write hosts and
# a reconnecting app could land on the half-restored one. So the suite asserts it
# directly, then asserts the restore mechanics that depend on it.
#
# Self-contained, like every suite: builds its own cluster, no compose, no lab.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
unset OPENSSL_CONF
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup db_restore_online
# The guard is applied with ALTER DATABASE, never ALTER SYSTEM. ALTER SYSTEM writes
# postgresql.auto.conf and PERSISTS: a suite that died between setting and clearing it
# would leave the shared cluster read-only and every later suite would fail with
# "cannot execute CREATE DATABASE in a read-only transaction". Scoping it to this
# suite's ephemeral database gets the same libpq behaviour and disappears with the DB.
guard_on(){  psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -qc "ALTER DATABASE $PGDATABASE SET default_transaction_read_only = on"  >/dev/null 2>&1; }
guard_off(){ psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -qc "ALTER DATABASE $PGDATABASE RESET default_transaction_read_only" >/dev/null 2>&1; }
trap 'guard_off; pg_cleanup' EXIT
P="-h $PGHOST -p $PGPORT -U $PGUSER -d $PGDATABASE"
W="$(mktemp -d)"

# A row that exists now and must survive / be replaced by the restore.
psql $P -qc "CREATE TABLE IF NOT EXISTS ronline(id int primary key, note text)" >/dev/null 2>&1
psql $P -qc "INSERT INTO ronline VALUES (1,'live') ON CONFLICT DO NOTHING"      >/dev/null 2>&1

echo "=== 1. the lever: default_transaction_read_only hides a host from libpq ==="
# Baseline: the host IS selectable by a read-write client.
OUT=$(psql "host=$PGHOST port=$PGPORT user=$PGUSER dbname=$PGDATABASE target_session_attrs=read-write" \
      -tAc "SELECT 'selected'" 2>&1 | tail -1)
chk "read-write client selects a normal primary" "selected" "$OUT"

guard_on
GUARD=$(psql $P -tAc 'SHOW transaction_read_only' 2>/dev/null)
chk "guard is active on the node" "on" "$GUARD"

# The claim the whole script depends on.
OUT=$(psql "host=$PGHOST port=$PGPORT user=$PGUSER dbname=$PGDATABASE target_session_attrs=read-write" \
      -tAc "SELECT 'selected'" 2>&1 | tail -1)
chk "read-write client now REFUSES the guarded host" "yes" \
    "$(echo "$OUT" | grep -qi 'read-only' && echo yes || echo no)"
# ...while a plain client (no target_session_attrs) can still reach it for reads.
OUT=$(psql $P -tAc "SELECT count(*) FROM ronline" 2>/dev/null)
chk "reads still work on the guarded host" "1" "$OUT"

echo "=== 2. a --single-transaction restore needs PGOPTIONS, not SET ==="
cat > "$W/dump.sql" <<'SQL'
DROP TABLE IF EXISTS ronline;
CREATE TABLE ronline(id int primary key, note text);
INSERT INTO ronline VALUES (1,'restored'), (2,'restored-two');
SQL
# The wrong way: the transaction has already begun read-only, so SET is too late.
OUT=$(psql $P -v ON_ERROR_STOP=1 --single-transaction -q \
        -c 'SET default_transaction_read_only = off' -f "$W/dump.sql" 2>&1 | tail -1)
chk "SET inside the transaction FAILS (read-only transaction)" "yes" \
    "$(echo "$OUT" | grep -qi 'read-only transaction' && echo yes || echo no)"
chk "...and the data is untouched by the failed attempt" "live" \
    "$(psql $P -tAc "SELECT note FROM ronline WHERE id=1" 2>/dev/null)"

# The right way: applied at connection startup, before the transaction opens.
PGOPTIONS='-c default_transaction_read_only=off' \
  psql $P -v ON_ERROR_STOP=1 --single-transaction -q -f "$W/dump.sql" >/dev/null 2>&1
chk "PGOPTIONS restore succeeds under the same guard" "restored" \
    "$(psql $P -tAc "SELECT note FROM ronline WHERE id=1" 2>/dev/null)"
chk "...and the whole dump landed" "2" \
    "$(psql $P -tAc "SELECT count(*) FROM ronline" 2>/dev/null)"

echo "=== 3. the guard still holds after the restore — apps have not drifted over ==="
OUT=$(psql "host=$PGHOST port=$PGPORT user=$PGUSER dbname=$PGDATABASE target_session_attrs=read-write" \
      -tAc "SELECT 'selected'" 2>&1 | tail -1)
chk "read-write client still refused mid-restore" "yes" \
    "$(echo "$OUT" | grep -qi 'read-only' && echo yes || echo no)"

echo "=== 4. cutover: lifting the guard makes it selectable again ==="
guard_off
for _ in 1 2 3 4 5; do
  [ "$(psql $P -tAc 'SHOW transaction_read_only' 2>/dev/null)" = "off" ] && break; sleep 1
done
chk "guard lifted" "off" "$(psql $P -tAc 'SHOW transaction_read_only' 2>/dev/null)"
OUT=$(psql "host=$PGHOST port=$PGPORT user=$PGUSER dbname=$PGDATABASE target_session_attrs=read-write" \
      -tAc "SELECT note FROM ronline WHERE id=1" 2>&1 | tail -1)
chk "read-write client selects it and sees the RESTORED data" "restored" "$OUT"

echo "=== 5. the script itself is sane ==="
S="$ROOT/deploy/db-restore-online.sh"
chk "script exists"            yes "$([ -f "$S" ] && echo yes || echo no)"
chk "script parses"            yes "$(bash -n "$S" 2>/dev/null && echo yes || echo no)"
chk "refuses a missing dump"   2   "$(bash "$S" /nonexistent.sql >/dev/null 2>&1; echo $?)"
chk "refuses with no argument" 2   "$(bash "$S" >/dev/null 2>&1; echo $?)"
# The requirement that avoids a split brain: the read-only guard is lifted only once the old
# primary can no longer take writes. Two read-write databases with different data is the one
# outcome this whole procedure exists to prevent.
#
# ⚠️ ASSERT THE REQUIREMENT, NOT THE MECHANISM — for the second time in this file's history
# (see the commit "the restore assertion matched a literal, not the requirement"). This used
# to grep for `stop "$PRIMARY"` preceding the RESET, which was the SAME-HOST implementation:
# one compose project, so the script could stop the primary itself. Deleting the same-host
# standby made this a two-machine procedure — the primary is another host and this script
# cannot stop it — so the literal vanished and the assertion failed while the guarantee had
# in fact got stronger: the script now waits for the primary to stop answering and REFUSES to
# lift the guard if it is still up, rather than assuming an ordering held.
FENCELINE=$(grep -n 'NOT lifting the read-only guard' "$S" | head -1 | cut -d: -f1)
# ⚠️ THE STATEMENT THAT EXECUTES, NOT A MENTION OF IT. The refusal above now prints the two
# statements an operator must run by hand — re-running this script cannot continue once the
# host has been promoted and restored — so the first match for this pattern became an `echo`
# INSIDE that message, ten lines before the real one. Both assertions below then compared two
# lines of the same message to each other and one of them passed for no reason. Skip the
# quoted forms.
RESETLINE=$(grep -n 'RESET default_transaction_read_only' "$S" \
            | grep -v 'echo' | head -1 | cut -d: -f1)
chk "the guard is lifted only after the old primary is confirmed down" yes \
    "$([ -n "$FENCELINE" ] && [ -n "$RESETLINE" ] && [ "$FENCELINE" -lt "$RESETLINE" ] && echo yes || echo no)"
# And that the refusal is a hard stop, not a warning it carries on past.
#
# ⚠️ THE `exit 1` DOES NOT HAVE TO BE ON THE SAME PHYSICAL LINE — that is the mechanism
# again, for the THIRD time in this file's history. This matched `exit 1` within the single
# line carrying the refusal text, which held only while the refusal was one
# `|| { echo …; exit 1; }`. It grew into a block: re-running cannot get past preflight once
# this host has been promoted and restored, so the message now names the one action left
# instead of offering two that both die. The guarantee was untouched and the assertion failed
# anyway. What matters is that nothing between the refusal and the RESET can fall through, so
# look for the exit anywhere in that span.
chk "  and that refusal exits non-zero" yes \
    "$(awk -v a="$FENCELINE" -v b="$RESETLINE" \
         'NR>=a && NR<b && /exit 1/ {f=1} END{print (f ? "yes" : "no")}' "$S")"
# It must use PGOPTIONS, not the SET form section 2 proved broken. Matched on the SETTING
# rather than the whole literal string — the option list grows (see below), and an
# exact-match grep turns every legitimate addition into a failure that says nothing.
chk "restore uses PGOPTIONS"   yes \
    "$(grep -qE "^PGOPT='[^']*default_transaction_read_only=off" "$S" && echo yes || echo no)"
# One option list, and the restore of every path passes it: compose as `-e PGOPTIONS=`, native
# through su, Kubernetes through `env`. A path left on its own list is how one of them loses
# an option the others gained.
chk "  ... on every path"       3 \
    "$(sed -n '/^restore_stdin()/,/^}/p' "$S" | grep -cE 'PGOPTIONS="\$(PGOPT|1)"')"
# ⚠️ AND session_replication_role=replica, OR A MESHED NODE CANNOT BE RESTORED AT ALL.
# `certs_dc_range` refuses any leaf whose serial does not carry THIS node's prefix — correct
# for a local mint, and an ORIGIN trigger so replicated rows bypass it. A restore is neither:
# it is a local INSERT of rows this node never minted, and a converged node's `certs` table
# is mostly its peers'. With ON_ERROR_STOP and --single-transaction the first one aborts
# everything. Measured against a live data center 1 node: a peer-prefix row and a pre-mesh
# prefix-less row are both refused, and both insert cleanly under this setting. The skip-dup
# and last-writer-wins triggers are ENABLE REPLICA, so they still fire and still resolve
# duplicates; only the origin-only guard steps aside, which is exactly its purpose.
chk "  ... and steps aside for the per-data-center serial guard" yes \
    "$(grep -qE "^PGOPT='[^']*session_replication_role=replica" "$S" && echo yes || echo no)"
# Mesh dumps carry DROP SUBSCRIPTION, which cannot run inside a transaction block —
# the restore aborted on the lab at the first line until this filter was added.
chk "strips replication topology DDL" yes "$(grep -q 'SUBSCRIPTION|PUBLICATION' "$S" && echo yes || echo no)"
chk "...with grep, not BSD-broken sed //Id" yes "$(grep -q "grep -viE" "$S" && echo yes || echo no)"
FILTERED=$(printf 'DROP SUBSCRIPTION IF EXISTS s;\nCREATE PUBLICATION p;\nCREATE TABLE keep(x int);\n' \
  | grep -viE '^[[:space:]]*(DROP|CREATE|ALTER)[[:space:]]+(SUBSCRIPTION|PUBLICATION)([[:space:]]|$)')
chk "filter drops topology, keeps data" "CREATE TABLE keep(x int);" "$FILTERED"
chk "no Helm anywhere near it" yes "$(grep -qi helm "$S" && echo no || echo yes)"

echo "=== 6. every deployment path, not only compose ==="
# ⚠️ IT WAS COMPOSE-ONLY, and the same operation on a native, cloud or Kubernetes pair was a
# manual procedure. Each database operation the procedure needs is one function, with a
# branch per path, so a step cannot exist on one path and silently not on another.
for _f in q qp su_exec promote restore_stdin; do
    chk "  $_f() has a compose, a native and a kubernetes branch" 3 \
        "$(sed -n "/^$_f()/,/^}/p" "$S" | grep -cE '^ +(compose|native|k8s)\)')"
done
chk "  the native build installs it" yes \
    "$(grep -q 'deploy/db-restore-online.sh" /usr/share/fastpki/db-restore-online.sh' "$ROOT/deploy/native/build-native.sh" && echo yes || echo no)"
# The promoted server is a primary from here on. pg-promote.sh clears two things a promoted
# standby keeps, and this promotes a standby too: the inherited synchronized_standby_slots,
# which stalls every logical walsender of a mesh, and the standby mark, which stops a compose
# or native server's Postgres at its next restart.
# ⚠️ AND A PROMOTED SERVER NEEDS WHAT pg-promote.sh DOES AFTER A PROMOTION. On a live native
# pair the restored server's own applications could not connect: their conninfo still verified
# it against its former primary's anchor. The restore hands it to pg-promote.sh
# --already-promoted, which takes every step after the promotion itself.
P="$ROOT/deploy/pg-promote.sh"
chk "  hands the promoted server to pg-promote.sh --already-promoted" yes \
    "$(grep -qE 'pg-promote.sh.*--already-promoted|"\$_pp" .*--already-promoted' "$S" && echo yes || echo no)"
chk "  after lifting the guard" yes \
    "$([ "$(grep -n -- '--already-promoted; then' "$S" | head -1 | cut -d: -f1)" -gt "$RESETLINE" ] && echo yes || echo no)"
chk "  pg-promote.sh --already-promoted skips the promotion" yes \
    "$(awk '/^if \[ "\$AFTER" = 1 \]; then/{f=1} f&&/^else/{e=1} e&&/^pg_promote_now/{print "yes"; exit}' "$P")"
chk "  and refuses a server that is not already a primary" yes \
    "$(grep -q -- '--already-promoted, but \$SVC is not a read-write primary' "$P" && echo yes || echo no)"
# Kubernetes: the script stops the old primary itself, and only rebuilds it once the guard is
# lifted — a copy taken while the guard was on would carry default_transaction_read_only into
# the new standby, and on to whatever it is promoted to later.
STOPLINE=$(grep -n 'pg_ctl -D /var/lib/postgresql/data stop' "$S" | head -1 | cut -d: -f1)
PVCLINE=$(grep -n 'kubectl delete pvc' "$S" | head -1 | cut -d: -f1)
chk "  kubernetes: stops the old primary before lifting the guard" yes \
    "$([ -n "$STOPLINE" ] && [ -n "$RESETLINE" ] && [ "$STOPLINE" -lt "$RESETLINE" ] && echo yes || echo no)"
chk "  kubernetes: rebuilds it only after the guard is lifted" yes \
    "$([ -n "$PVCLINE" ] && [ -n "$RESETLINE" ] && [ "$RESETLINE" -lt "$PVCLINE" ] && echo yes || echo no)"
# ⚠️ INTO AN EMPTY DATABASE. The standby holds every table already, and the plain `pg_dump`
# docs/postgres.md gives carries no DROP statements, so loading one on top stopped at its first
# CREATE TABLE ("relation "accounts" already exists", measured on a Kubernetes pair). Only a
# --clean dump loaded at all.
chk "  recreates an empty database before loading the dump" yes \
    "$([ "$(grep -n '^recreate_db$' "$S" | cut -d: -f1)" -lt "$(grep -n '| restore_stdin' "$S" | cut -d: -f1)" ] && echo yes || echo no)"
chk "  refuses a data center in a mesh (docs/postgres.md 6.3)" yes \
    "$(grep -q 'part of a mesh' "$S" && grep -q 'FROM pg_subscription' "$S" && echo yes || echo no)"
chk "  kubernetes: a pod that is not a server is refused" 2 \
    "$(: > "$W/d.sql"; FASTPKI_RESTORE_MODE=k8s bash "$S" "$W/d.sql" web-0 >/dev/null 2>&1; echo $?)"

rm -rf "$W"
echo
echo "=== ONLINE RESTORE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ] || echo "RESULT: FAIL"
exit 0
