#!/usr/bin/env bash
# Postgres test helpers for the FastPKI regression harness.
# Source this file from each test script:
#   source "$ROOT/tests/pg_helpers.sh"
#
# Requires: psql, a running Postgres (Docker or local).
# Environment:
#   PGHOST  (default 127.0.0.1)
#   PGPORT  (default 5432)
#   PGUSER  (default fastpki)
#   PGPASSWORD (default fastpki)
#   PGDATABASE — set automatically per-test (ephemeral DB)
#   PG_CONNINFO — set automatically per-test

# seed_ca_from_conf registers a token-held CA key and needs hsm_conf_lines,
# so depend on it explicitly rather than assuming every caller sourced it too.
source "$(dirname "${BASH_SOURCE[0]}")/hsm_helpers.sh"
# pg_ensure_server() below starts a throwaway cluster when nothing answers on
# $PGPORT, and initdb/pg_ctl refuse to run as root. In the lab tier that branch is
# never reached — deploy/lab-test.sh starts a cluster via `su postgres` before
# run_all.sh — so this is the fallback, not today's path. It is wrapped anyway
# because if that pre-start ever fails, the whole PG tier would fail with a root
# refusal reported as "no usable Postgres".
source "$(dirname "${BASH_SOURCE[0]}")/pg_priv.sh"

PGHOST="${PGHOST:-127.0.0.1}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-fastpki}"
export PGPASSWORD="${PGPASSWORD:-fastpki}"
# Default the database too. pg_setup() overrides this with a per-test ephemeral DB, but
# the fixed-database suites (mesh, pqc, web_keygen_der, web_p12) call pg_exec WITHOUT
# pg_setup — with `set -u` that made every one of them die on "PGDATABASE: unbound
# variable", so the whole PG tier could not run.
#
# ⚠️ This list USED to name pg_smoke, pg_store_* and replication. All five of those call
# pg_setup today and have for a while; the comment was stale and was read as evidence
# while scoping the demo probe. Re-derive it, never quote it:
#     for f in tests/*.sh; do grep -q pg_helpers.sh "$f" && ! grep -qE '^[^#]*pg_setup' "$f" && echo "$f"; done
PGDATABASE="${PGDATABASE:-fastpki}"

# Set this to 0 BEFORE sourcing to suppress the source-time pg_ensure_server call
# at the bottom of this file. It exists for demo/pki-demo.sh and demo/pki-bench.sh, which
# source these helpers for pg_setup/pg_exec but, in `--target` mode, drive a live
# deployment and never touch a local database at all. Merely sourcing this file used to
# probe 127.0.0.1:5432, create/upgrade the `fastpki` and `pki` databases on whatever
# Postgres the operator happens to run, and print the five-line role warning at
# someone who had not asked for a local Postgres in the first place. pg_setup() ensures a
# server itself, so a suite that suppresses this still gets one the moment it asks for a
# database.
FASTPKI_PG_AUTOSTART="${FASTPKI_PG_AUTOSTART:-1}"

# psql from Homebrew libpq (macOS) or system PATH
_PSQL_BIN="${PSQL_BIN:-psql}"
if ! command -v "$_PSQL_BIN" >/dev/null 2>&1 && [ -x /opt/homebrew/opt/libpq/bin/psql ]; then
    _PSQL_BIN="/opt/homebrew/opt/libpq/bin/psql"
fi
export PATH="$(dirname "$_PSQL_BIN"):$PATH"
PSQL_BIN="$_PSQL_BIN"

# ⚠️ pg_dump REFUSES a server newer than itself. psql does not — it connects to a PG17
# server quite happily — so a box with several PostgreSQL versions installed can look
# entirely healthy right up to the moment a suite dumps:
#
#     pg_dump: error: aborting because of server version mismatch
#     pg_dump: detail: server version: 17.10 (Homebrew); pg_dump version: 16.14 (Homebrew)
#
# Measured here after the server moved 16 -> 17: Homebrew kept postgresql@16's
# bin first on PATH, and ca_no_fk, db_restore and backup_encrypted all went red at once.
# Every one of them reported it as its own product assertion failing ("dump is a real
# pg_dump", "pg_dump succeeds"), which is three misleading bug reports from one
# environment fact.
#
# So ask the SERVER what major it is and put matching dump tools — and ONLY those, see
# below — in front. This is the same shape as the libpq fallback above, and it is what
# §3d means by platform-agnostic: the suite must work on whatever the box has, not on the
# box being tidy. If nothing matching is installed, say so loudly ONCE rather than letting
# each suite discover it as an assertion failure.
_pg_align_client_version() {
    command -v pg_dump >/dev/null 2>&1 || return 0
    local srv dumpv d probe_t0 probe_secs
    probe_secs="${PG_PROBE_TIMEOUT:-10}"
    # ⚠️ THIS IS A NETWORK CALL AND IT RUNS AT SOURCE TIME. Nothing bounded it and its
    # stderr went to /dev/null, so a host that ACCEPTS the connection and then never
    # answers left every caller blocked forever with no output to attribute it to. The
    # last line on screen was whatever the caller printed before sourcing -- for the
    # clients demo, "loading helpers..." -- which reads as the demo doing nothing at all.
    #
    # A published container port whose server is still starting is exactly this shape:
    # the port is held and accepts immediately, the startup packet is never answered.
    # An ordinary "no server" is a REFUSAL, which returns instantly and always did.
    #
    # PGCONNECT_TIMEOUT bounds the whole connection sequence including authentication,
    # not just the TCP handshake, so it covers both. -w removes the other silent block:
    # libpq writes a password prompt to /dev/tty, which this call's discarded stderr
    # would not have shown either.
    probe_t0=$SECONDS
    srv=$(PGCONNECT_TIMEOUT="$probe_secs" "$PSQL_BIN" -w \
          -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAc \
          'SHOW server_version' 2>/dev/null | cut -d. -f1 | tr -d ' ')
    if [ -z "$srv" ]; then
        # Silence here is right for a refusal -- most suites source this with no server
        # yet, and alignment is an optimisation. Hitting the DEADLINE is different: it
        # means something held the port without answering, and staying quiet about that
        # is indistinguishable from a client version that already matched.
        if [ $((SECONDS - probe_t0)) -ge "$probe_secs" ]; then
            echo "pg_helpers: WARNING $PGHOST:$PGPORT accepted a connection but did not answer" >&2
            echo "pg_helpers:   within ${probe_secs}s. Continuing WITHOUT client-version alignment," >&2
            echo "pg_helpers:   so dump/restore suites may report a server version mismatch." >&2
            echo "pg_helpers:   A published container port whose server is still starting looks" >&2
            echo "pg_helpers:   like this; so does a firewall that drops instead of refusing." >&2
        fi
        return 0                                   # no server yet: nothing to match
    fi
    dumpv=$(pg_dump --version 2>/dev/null | sed -n 's/.*) \([0-9]*\).*/\1/p')
    [ -n "$dumpv" ] && [ "$dumpv" = "$srv" ] && return 0
    for d in "/opt/homebrew/opt/postgresql@$srv/bin" \
             "/usr/local/opt/postgresql@$srv/bin" \
             "/usr/lib/postgresql/$srv/bin" \
             "/usr/pgsql-$srv/bin"; do
        [ -x "$d/pg_dump" ] || continue
        # ⚠️ WHICH TOOLS GO IN THE SHIM IS THE WHOLE DESIGN, and every exclusion below
        # was learned by breaking something.
        #
        # IN — only the three tools that REFUSE a newer server:
        #   pg_dump, pg_dumpall, pg_restore
        #
        # OUT — everything else:
        #
        # NOT initdb / pg_ctl / postgres. Substituting a whole other PostgreSQL
        # installation through symlinks does not work: these binaries locate their
        # `share/` directory relative to the resolved executable, so a symlinked initdb
        # looks for it beside the SHIM and the cluster never starts. Tried it; the result
        # was replication_stream turning from 34 red assertions into a silent
        # "SKIP: could not start the throwaway clusters", which is worse.
        #
        # NOT pg_basebackup. The suites that run it build their own cluster with the
        # initdb on PATH, so their client and server match BY CONSTRUCTION; shimming it
        # put a PG17 client against those PG16 clusters and invented the very mismatch
        # this function exists to remove (replication_stream 54/0 -> 12/34).
        #
        # NOT the libpq CLIENTS: psql, createdb, dropdb, pg_isready.
        # An older client talks to a newer server quite happily, so they never needed
        # fixing, and swapping them is actively harmful. A keg binary finds libpq through
        # the dynamic loader, and demo/pki-demo.sh puts a Homebrew lib directory first on
        # DYLD_LIBRARY_PATH for OpenSSL. A PG17 psql then loads the LINKED keg's libpq,
        # which here is 16's:
        #
        #   dyld: Symbol not found: _PQchangePassword
        #     Referenced from: .../postgresql@17/17.10/bin/psql
        #     Expected in:     .../postgresql@16/16.14/lib/libpq.5.dylib
        #
        # The process dies with "Abort trap: 6", and because the demo sends psql's output
        # to /dev/null the dyld line never reaches the log — demo_clients and bench_smoke
        # went red with nothing but "could not create Postgres database … is Postgres
        # running?", which sends the reader to look at Postgres, which is fine.
        # Prepending the keg's own lib does not help: the demo prepends after us.
        local shim="${TMPDIR:-/tmp}/fastpki-pgshim-$srv-$(id -u)"
        rm -rf "$shim"
        mkdir -p "$shim"
        for t in pg_dump pg_dumpall pg_restore; do
            [ -x "$d/$t" ] && ln -sf "$d/$t" "$shim/$t"
        done
        export PATH="$shim:$PATH"
        return 0
    done
    echo "pg_helpers: WARNING the server is PostgreSQL $srv but pg_dump here is ${dumpv:-unknown}," >&2
    echo "pg_helpers:   and no matching client was found. Every dump/restore suite will fail" >&2
    echo "pg_helpers:   with 'aborting because of server version mismatch' — install" >&2
    echo "pg_helpers:   postgresql@$srv, or point PATH at its bin directory." >&2
}
_pg_align_client_version

# Registry of ephemeral databases: one "<owning-pid> <dbname>" line each.
#
# WHY THIS EXISTS. pg_setup's caller arms `trap 'pg_cleanup; …' EXIT`, and then most
# suites arm a SECOND `trap 'kill $SRV' EXIT` once the daemon is up. Bash does not
# stack EXIT traps — the second REPLACES the first — so pg_cleanup silently stopped
# running in 85 of them and every PG-tier run leaked its databases (measured: 1329
# databases / 11GB). Suites that call pg_setup twice leaked the first one regardless,
# since pg_cleanup only ever sees the last $PGDATABASE.
#
# Fixing 85 traps would fix today and rot again the next time someone re-arms one, so
# the drop is made to not depend on the trap at all: every database is recorded here
# and reaped by the next pg_setup once its owning process is gone.
_PG_REGISTRY="${TMPDIR:-/tmp}/fastpki-testdbs-$(id -u)"

# Drop every registered database whose owning suite has exited.
_pg_reap() {
    [ -s "$_PG_REGISTRY" ] || return 0
    local keep pid db
    keep="$(mktemp)"
    while read -r pid db; do
        [ -z "${db:-}" ] && continue
        # A live owner means that suite is still running — leave its database alone.
        # A recycled PID can only make this MISS a dead entry (dropped next time), it
        # can never drop a live suite's database, because a suite whose PID is gone
        # cannot still be connected.
        if kill -0 "$pid" 2>/dev/null; then
            printf '%s %s\n' "$pid" "$db" >> "$keep"
            continue
        fi
        "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres \
            -c "DROP DATABASE IF EXISTS \"$db\";" >/dev/null 2>&1 \
            || printf '%s %s\n' "$pid" "$db" >> "$keep"   # still busy — try again later
    done < "$_PG_REGISTRY"
    mv -f "$keep" "$_PG_REGISTRY" 2>/dev/null || rm -f "$keep"
}

# Create an ephemeral test database and load the schema.
# Call as: pg_setup <test-name>
# Sets PGDATABASE and PG_CONNINFO for use by the test.
pg_setup() {
    local test_name="${1:-test}"
    # Ensure a cluster HERE rather than relying only on the source-time call, so
    # suppressing that call (FASTPKI_PG_AUTOSTART=0) costs a caller nothing. Idempotent —
    # it returns immediately when pg_isready answers or $FASTPKI_PG_STARTED is set, which
    # is every case in the test tier.
    #
    # ⚠️ NOT redirected. Swallowing its stderr would swallow the role warning — which
    # _pg_role_usable prints ONCE per process — and the `_pg_role_usable` call below would
    # then exit 1 having said nothing at all. The whole point of that message is that the
    # misconfiguration gets named.
    pg_ensure_server || true
    PGDATABASE="fpki_${test_name}_$$"
    export PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE

    _pg_reap
    printf '%s %s\n' "$$" "$PGDATABASE" >> "$_PG_REGISTRY" 2>/dev/null

    _pg_role_usable; case $? in
        2) exit 1 ;;   # server up, role unusable: a misconfiguration, stop and say so
    esac

    "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres \
        -c "DROP DATABASE IF EXISTS $PGDATABASE;" 2>/dev/null
    "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres \
        -c "CREATE DATABASE $PGDATABASE;" 2>/dev/null
    "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
        -f "$ROOT/sql/createdb.sql" 2>/dev/null

    PG_CONNINFO="host=$PGHOST port=$PGPORT dbname=$PGDATABASE user=$PGUSER password=$PGPASSWORD"
}

# ⚠️ The harness must not connect with a role it has not checked, and must not do it
# silently. Every psql call above discards stderr, so a $PGUSER that cannot authenticate
# produced NO output here at all — the suite ran on, the product binaries failed to connect
# for the same reason, and the only visible trace was a FATAL in the SERVER's log:
#
#   pki@fpki_ocsp_abuse_59356 172.18.0.1 FATAL: password authentication failed for user "pki"
#
# Multiplied by ~30 PG-tier suites, that is the "postgres log is full" report. $PGUSER is
# taken from the environment (line 21) and nothing in this tree sets it to `pki`, so a stale
# export outside the repo is enough to do it — and the harness gave the operator nothing to
# go on. It now says so once, names the role, and stops.
#
# Distinguish the two cases deliberately, and that is the whole design:
#   0  the role works
#   1  NO SERVER — an absent optional dependency. Quiet: the suites SKIP on it (§3d), and
#      turning a laptop with no Postgres into 30 failures would be the worse bug.
#   2  server UP, role unusable — a misconfiguration. Printed once, and pg_setup exits.
#      A silent skip here would hide it, which is exactly how it stayed hidden.
_pg_role_usable() {
    "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAc 'select 1' \
        >/dev/null 2>&1 && return 0
    [ -x "$_PG_BINDIR/pg_isready" ] || return 1
    "$_PG_BINDIR/pg_isready" -h "$PGHOST" -p "$PGPORT" >/dev/null 2>&1 || return 1
    # Once per process. Two callers reach here — source time and pg_setup — and a fix for a
    # log flood that repeats its own message is not much of a fix.
    [ -n "${_PG_ROLE_WARNED:-}" ] && return 2
    _PG_ROLE_WARNED=1
    cat >&2 <<EOF
pg_helpers: Postgres at $PGHOST:$PGPORT is UP, but role "$PGUSER" cannot connect.
pg_helpers: PGUSER comes from the environment (default: fastpki). Every connection this
pg_helpers: suite makes — psql AND the fastpki binaries — will fail the same way and fill
pg_helpers: the server log with authentication FATALs. Unset PGUSER/PGPASSWORD, or point
pg_helpers: them at a role that exists.
EOF
    return 2
}

# Drop the ephemeral test database.
#
# ⚠️ ONLY a database pg_setup CREATED. Without this check pg_cleanup drops whatever
# $PGDATABASE happens to name, and $PGDATABASE defaults to the DEVELOPER'S OWN `fastpki`
# (line 27) for the five suites that never call pg_setup — pg_smoke, pg_store_hash,
# pg_store_uri, pg_store_hash_selectors, replication.
#
# That is not theoretical. `ca_in_token`'s SKIP path (tests/hsm_helpers.sh) calls
# pg_cleanup unconditionally, so on any box whose PKCS#11 toolchain is incomplete —
# a fresh dev machine, CI without SoftHSM — running tests/pg_smoke.sh DROPPED the
# developer's database. Reproduced against a throwaway `victim_probe`: present before,
# gone after, no error printed.
#
# The name is the evidence: pg_setup builds `fpki_<test>_<pid>` (line 161) and nothing
# else does. Anything not matching that shape was not ours to drop.
pg_cleanup() {
    case "${PGDATABASE:-}" in
        fpki_*_[0-9]*) ;;
        *) return 0 ;;
    esac
    if [ -n "${PGDATABASE:-}" ]; then
        # Terminate active connections before dropping
        "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres \
            -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$PGDATABASE';" 2>/dev/null
        "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres \
            -c "DROP DATABASE IF EXISTS $PGDATABASE;" 2>/dev/null
    fi
}

# Execute a SQL statement and return the result (trimmed, no headers/footer).
# Usage: val=$(pg_exec "SELECT count(*) FROM certs;")
pg_exec() {
    "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
        -tAq -c "$1"
}

# Seed the approved-domain allow-list into the `allowed_domains` table — the sole
# source (DOMAINS_FILE is gone; a file was only ever visible to a process
# sharing that filesystem, while the table replicates).
#
# Takes the same domains.txt the suite already writes, and imports it through the
# REAL path (`fastpki-config domains-import`) rather than a private INSERT, so the
# harness exercises what an operator runs.
#
# Call AFTER pg_setup and BEFORE the daemon starts: load_allowed_domains() reads the
# table once at daemon startup, exactly like seed_web_user's ordering constraint.
#
#   seed_domains <domains-file>
seed_domains() {
    local file="$1" cfg conninfo out rc
    [ -s "$file" ] || return 0          # nothing to import is not an error
    # The fixed-database PG-tier suites (pg_smoke, pg_store_*, replication) never call
    # pg_setup, so PG_CONNINFO is unset there. Build it from the PG* the helpers already
    # default, instead of making every such suite hand-roll the line.
    conninfo="${PG_CONNINFO:-host=$PGHOST port=$PGPORT dbname=$PGDATABASE user=$PGUSER password=$PGPASSWORD}"
    cfg="$(mktemp)"
    printf 'PG_CONNINFO=%s\n' "$conninfo" > "$cfg"
    out=$("$ROOT/build/fastpki-config" --config "$cfg" domains-import "$file" 2>&1); rc=$?
    rm -f "$cfg"
    [ "$rc" -eq 0 ] || echo "seed_domains: FAILED to import '$file': $out" >&2
    return $rc
}

# Store certificate profiles, from a JSON object {"<name>": {definition}, ...}, through the
# shipped `fastpki-config profiles-import`. Profiles are rows of the replicated
# `cert_profiles` table, not a config key, so a suite seeds them here before starting a
# service instead of writing them into a conf file. Same-named rows are replaced; a
# built-in given its shipped definition ends up with no row, exactly as in the console.
#
#   seed_cert_profiles '{"clientonly":{"allowed_eku":["clientAuth"]}}'
seed_cert_profiles() {
    local json="$1" cfg f conninfo out rc
    conninfo="${PG_CONNINFO:-host=$PGHOST port=$PGPORT dbname=$PGDATABASE user=$PGUSER password=$PGPASSWORD}"
    cfg="$(mktemp)"; f="$(mktemp)"
    printf 'PG_CONNINFO=%s\n' "$conninfo" > "$cfg"
    printf '%s' "$json" > "$f"
    out=$("$ROOT/build/fastpki-config" --config "$cfg" profiles-import "$f" 2>&1); rc=$?
    rm -f "$cfg" "$f"
    [ "$rc" -eq 0 ] || echo "seed_cert_profiles: FAILED: $out" >&2
    return $rc
}

# Execute a SQL file.
pg_exec_file() {
    "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
        -f "$1"
}

# SIGNING_CA_PEM/KEY/ID no longer bootstrap a CA (removed — CAs are ca_instances
# rows). This test helper reads those values from a config file and registers the CA as
# an active ca_instances row, exactly as the console / `fastpki-ca add` would — so a test
# that used to rely on the env-var seed only needs to call `seed_ca_from_conf <conf>`
# after pg_setup and after writing the conf, before starting the daemon.
# Abandon a suite cleanly from inside seed_ca_from_conf. The suite's EXIT trap is
# already armed and refers to a daemon PID it has not started yet ("P: unbound
# variable"), so tear the database down here and disarm the trap before leaving.
_seed_skip() {
    echo "SKIP: $1"
    pg_cleanup >/dev/null 2>&1 || true
    trap - EXIT
    exit 0
}

seed_ca_from_conf() {
    local conf="$1"
    local pem key id conninfo dbn
    pem=$(sed -n 's/^SIGNING_CA_PEM=//p' "$conf" | head -1)
    key=$(sed -n 's/^SIGNING_CA_KEY=//p' "$conf" | head -1)
    id=$(sed -n 's/^SIGNING_CA_ID=//p'  "$conf" | head -1)
    conninfo=$(sed -n 's/^PG_CONNINFO=//p' "$conf" | head -1)
    [ -z "$id" ] && id="ca_$(date +%s)_$$"
    [ -z "$pem" ] && return 0

    # The CA private key lives in a token, minted by ca_in_token at the
    # point the suite created its CA. Register THAT, not the conf's file path — a
    # file key is no longer a thing a CA can have.
    # Prefer what the conf actually names. $CA_KEY_URI is a convenience for the common
    # single-CA suite, but it holds the LAST key ca_in_token minted — so in a suite with
    # two CAs it would register CA-A under CA-B's key, and the certs would verify
    # against the wrong anchor while looking correct in every other respect.
    case "$key" in
        pkcs11:*) grep -q '^PKCS11_MODULE=' "$conf" || hsm_conf_lines >> "$conf" ;;
        *)  if [ -n "${CA_KEY_URI:-}" ]; then
                key="$CA_KEY_URI"
                grep -q '^PKCS11_MODULE=' "$conf" || hsm_conf_lines >> "$conf"
            fi ;;
    esac

    # Target the DB the daemon actually uses (dbname from the conf's PG_CONNINFO), so a
    # multi-database test seeds the right DB rather than the last pg_setup's $PGDATABASE.
    dbn=$(printf '%s\n' "$conninfo" | sed -n 's/.*dbname=\([^ ]*\).*/\1/p')
    [ -z "$dbn" ] && dbn="$PGDATABASE"

    # A CA IS a row of `certs` with is_ca — there is no registry table to seed.
    # So this writes the certificate itself, keyed on its own serial, with the CA's
    # identity on the same row. `$pem` is a FILE here because that is what a test has
    # on disk; what lands in the database is the certificate.
    local ossl ser der nb na cn
    ossl="${OSSL:-openssl}"
    command -v "$ossl" >/dev/null 2>&1 || ossl=openssl
    ser=$("$ossl" x509 -in "$pem" -noout -serial 2>/dev/null | sed 's/serial=//' \
          | tr 'A-F' 'a-f' | sed 's/^0*//')
    [ -n "$ser" ] || return 0
    der=$("$ossl" x509 -in "$pem" -outform DER 2>/dev/null | xxd -p | tr -d '\n')
    cn=$("$ossl" x509 -in "$pem" -noout -subject 2>/dev/null | sed 's/.*CN *= *//; s/,.*//')
    # The certificate's own validity, not a guess — `certs` holds bigint so a
    # long-lived or never-expiring CA fits.
    nb=$("$ossl" x509 -in "$pem" -noout -startdate 2>/dev/null | sed 's/notBefore=//')
    na=$("$ossl" x509 -in "$pem" -noout -enddate  2>/dev/null | sed 's/notAfter=//')
    # Register through the PRODUCT's own path rather than hand-written SQL.
    #
    # `fastpki-ca add` stores the certificate with insert_cert and then stamps the CA
    # identity onto that row — which is what the console and the servers do. Writing the
    # INSERT here instead meant the fixture had to know every column, and it got one
    # wrong in a way no assertion could see: `sHash`/`iHash` were left NULL, so a CA's
    # PARENT — derived by matching a parent's subject hash to this
    # certificate's issuer hash — could never be found for a seeded CA. A fixture that
    # builds state the product cannot build is a fixture that tests something else.
    #
    # NOT silenced. This used to end `>/dev/null 2>&1`, so a helper dozens of suites
    # depend on could fail and every one of them would test an empty database while
    # reporting whatever that produced.
    local out
    if out=$("${FASTPKI_CA_BIN:-$(dirname "${BASH_SOURCE[0]}")/../build/fastpki-ca}" \
                --config "$conf" add "$id" --name "$id" \
                --ca-pem "$pem" --ca-key "$key" 2>&1); then
        :
    else
        # ⚠️ Re-registering the SAME CA is a no-op, not a failure. Eleven suites call this
        # twice for one CA (a second config against the same instance) and every one of
        # them printed
        #     insert_cert: ERROR: duplicate key value violates unique constraint "certs_pkey"
        # on a PASSING run. That is the problem: a real seeding failure prints exactly the
        # same way, so the message everyone learned to ignore is the one that matters.
        #
        # Decide from what the DATABASE HOLDS, not from the message text: if the row for
        # this certificate is there and carries this CA id, the desired state exists and
        # there is nothing to report. Anything else is still reported, loudly.
        # `certs.id` is the CA identity column (folded ca_instances into certs);
        # there is no `ca_id` on this table. Getting that wrong made the check itself
        # error, which read as "not registered" and printed the noise anyway — the
        # failure mode this block exists to remove.
        local have
        have=$(PGDATABASE="$dbn" pg_exec \
            "SELECT count(*) FROM certs WHERE serial='$ser' AND id='$id';" 2>/dev/null | tr -d ' ')
        if [ "${have:-0}" != "1" ]; then
            printf '  seed_ca_from_conf: %s\n' "$out" >&2
        fi
    fi
}

# Seed a CA directly as the `certs` row it now is.
# Usage: pg_seed_ca_row <id> <pem-file> <key-uri> [enabled]
#
# Written straight into the table rather than through `fastpki-ca add`, for suites that
# need a CA the product would refuse to create — a disabled one, a file-keyed one, or
# several sharing a certificate. seed_ca_from_conf is the right helper when the CA is an
# ordinary one; this is the fixture escape hatch, and it exists so five suites stop each
# hand-writing the same INSERT and each getting a different subset of columns.
pg_seed_ca_row() {
    local id="$1" pem="$2" key="${3:-}" enabled="${4:-true}"
    local ossl ser der cn nb na
    ossl="${OSSL:-openssl}"
    command -v "$ossl" >/dev/null 2>&1 || ossl=openssl
    ser=$("$ossl" x509 -in "$pem" -noout -serial 2>/dev/null | sed 's/serial=//' \
          | tr 'A-F' 'a-f' | sed 's/^0*//')
    [ -n "$ser" ] || { echo "  pg_seed_ca_row: no serial in $pem" >&2; return 1; }
    der=$("$ossl" x509 -in "$pem" -outform DER 2>/dev/null | xxd -p | tr -d '\n')
    cn=$("$ossl" x509 -in "$pem" -noout -subject 2>/dev/null | sed 's/.*CN *= *//; s/,.*//')
    nb=$("$ossl" x509 -in "$pem" -noout -startdate 2>/dev/null | sed 's/notBefore=//')
    na=$("$ossl" x509 -in "$pem" -noout -enddate  2>/dev/null | sed 's/notAfter=//')
    pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,cn,cert,
                               id,name,ca_enabled,private_key,is_ca,ca_instance_id)
             VALUES('$ser',0,
                    extract(epoch from timestamptz '$nb')::bigint,
                    extract(epoch from timestamptz '$na')::bigint,
                    '$cn','$cn','\\x$der'::bytea,
                    '$id','$id',$enabled,'$key',true,'$id')
             ON CONFLICT (serial) DO UPDATE SET id=EXCLUDED.id, name=EXCLUDED.name,
               ca_enabled=EXCLUDED.ca_enabled, private_key=EXCLUDED.private_key,
               is_ca=true;"
}

# Insert a cert row from a PEM file.
# Usage: pg_insert_cert <pem-file> <status> [owner] [role]
#   status: 0=valid, 1=expired, -1=revoked, 2=on_hold
pg_insert_cert() {
    local pem="$1" status="${2:-0}" owner="${3:-test}" role="${4:-standard}"
    local ser der cn nb na
    ser=$("$OSSL" x509 -in "$pem" -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
    der=$("$OSSL" x509 -in "$pem" -outform DER | xxd -p | tr -d '\n')
    cn=$(basename "$pem" .pem)
    nb=$(date +%s)
    na=$((nb + 31536000))
    pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cert,cn,fingerprint)
             VALUES('$ser',$status,0,0,$nb,$na,'CN=$cn','$owner','\\x$der'::bytea,'$cn','')
             ON CONFLICT (serial) DO NOTHING;"
    echo "$ser"
}

# Insert a discovered cert row.
# Usage: pg_insert_discovered <target> <serial> <subject> <issuer> <algo> <bits> <sigalgo> <flags>
pg_insert_discovered() {
    local target="$1" serial="$2" subject="$3" issuer="$4" algo="$5" bits="$6" sigalgo="$7" flags="$8"
    local now
    now=$(date +%s)
    pg_exec "INSERT INTO discovered_certs(target,serial,subject,issuer,\"notBefore\",\"notAfter\",\"keyAlgo\",\"keyBits\",\"sigAlgo\",flags,\"discoveredAt\")
             VALUES('$target','$serial','$subject','$issuer',$((now-86400)),$((now+86400)),'$algo',$bits,'$sigalgo','$flags',$now);"
}

# ── A Postgres for the fixed-database suites (§3d) ───────────────────────────
# pg_setup() builds an ephemeral database per test, but several PG-tier suites
# (pg_smoke, pg_store_*, replication) target a FIXED database and so assumed a
# Postgres was already listening. That assumption is invisible until it is false —
# the suites then die with "connection refused", or pass on one machine and not
# another — and it breaks the rule that a test creates everything it needs.
#
# Starts a throwaway cluster ONLY if nothing already answers on $PGPORT, so a
# developer's own Postgres is used untouched. The cluster persists for the rest of
# the run (later suites reuse it), so it costs one initdb per run.
_PG_BINDIR="$(dirname "$_PSQL_BIN")"
# ⚠️ HIGHEST major wins, never first-match. This list used to name
# postgresql@16 FIRST and hardcode /usr/lib/postgresql/16, so on any machine with
# both majors installed the whole fixed-database PG tier silently ran on 16 — while
# the product ships 17 and failover slots do not exist before 17. A test
# helper that differs from the product IS the bug; and this one would have reported
# green forever. sort -V puts 17 above 16 (and 9.x below both, unlike plain sort).
[ -x "$_PG_BINDIR/initdb" ] || for d in \
        $(ls -d /opt/homebrew/opt/postgresql@*/bin /usr/lib/postgresql/*/bin \
                /usr/pgsql-*/bin 2>/dev/null | sort -V -r) /usr/bin; do
    [ -x "$d/initdb" ] && { _PG_BINDIR="$d"; break; }
done

# Create the fixed databases if absent. Runs whether or not this process started the
# server: an already-running cluster (a developer's own, or one a previous suite in
# this run started) will not have them, and returning early on "a server is up" left
# every fixed-database suite failing with 'database "fastpki" does not exist'.
_pg_ensure_databases() {
    local db i
    for i in $(seq 1 30); do
        "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAc "select 1" >/dev/null 2>&1 && break
        # ⚠️ This loop waits for a server that is STARTING. A server already up and
        # refusing this role will never become ready by waiting — it just makes 30 more
        # failed authentications, and this runs at source time in every PG suite. That
        # multiplication is most of the log flood the ticket reported.
        [ -x "$_PG_BINDIR/pg_isready" ] &&
            "$_PG_BINDIR/pg_isready" -h "$PGHOST" -p "$PGPORT" >/dev/null 2>&1 && break
        sleep 0.5
    done
    # Attribute it once, here, at the earliest point anything in the harness touches the
    # server — rather than leaving each suite to fail in its own way further down.
    _pg_role_usable || return 0
    local root; root="$(dirname "${BASH_SOURCE[0]}")/.."
    for db in "$PGDATABASE" pki; do
        [ -n "$db" ] || continue
        if ! "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAc \
                "select 1 from pg_database where datname='$db'" 2>/dev/null | grep -q 1; then
            "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c "CREATE DATABASE $db;" >/dev/null 2>&1
            "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$db" \
                -f "$root/sql/createdb.sql" >/dev/null 2>&1
            continue
        fi
        # The database ALREADY EXISTS — from an older createdb.sql, on this developer's
        # machine or a CI cache. Creating it was never the hard part; keeping it current
        # is, and skipping an existing database is exactly how it drifts. Schema versioning gave us
        # the mechanism, so use it here rather than inventing a second one: the binaries
        # now refuse to start against a stale schema, and without this every fixed-database
        # suite (pg_smoke, pg_store_*, replication) dies at startup with no obvious cause.
        PSQL="$_PSQL_BIN -h $PGHOST -p $PGPORT -U $PGUSER -d $db" \
            bash "$root/deploy/schema-apply.sh" >/dev/null 2>&1 || true
    done
}

pg_ensure_server() {
    if "$_PG_BINDIR/pg_isready" -h "$PGHOST" -p "$PGPORT" >/dev/null 2>&1; then
        _pg_ensure_databases; return 0
    fi
    [ -n "${FASTPKI_PG_STARTED:-}" ] && { _pg_ensure_databases; return 0; }
    [ -x "$_PG_BINDIR/initdb" ] || { echo "pg_helpers: no initdb found; PG suites need a Postgres on $PGPORT" >&2; return 1; }
    local d="${TMPDIR:-/tmp}/fastpki_pg_$$"
    rm -rf "$d"; mkdir -p "$d"; pg_own "$d"
    # LC_ALL=C: macOS initdb refuses under a multithreaded collation locale.
    LC_ALL=C pg_as "$_PG_BINDIR/initdb" -D "$d" -U "$PGUSER" --auth=trust >/dev/null 2>&1 \
        || { echo "pg_helpers: initdb failed — $(pg_priv_reason)" >&2; return 1; }
    # LC_ALL=C is needed for the SERVER too, not just initdb: macOS otherwise fails
    # with "postmaster became multithreaded during startup" and shuts straight down.
    LC_ALL=C pg_as "$_PG_BINDIR/pg_ctl" -D "$d" -o "-p $PGPORT -c listen_addresses=$PGHOST" -l "$d/log" start >/dev/null 2>&1
    local i; for i in $(seq 1 30); do
        "$_PG_BINDIR/pg_isready" -h "$PGHOST" -p "$PGPORT" >/dev/null 2>&1 && break; sleep 0.5
    done
    "$_PG_BINDIR/pg_isready" -h "$PGHOST" -p "$PGPORT" >/dev/null 2>&1 \
        || { echo "pg_helpers: cluster did not start; see $d/log" >&2; return 1; }
    export FASTPKI_PG_STARTED="$d"
    # Both names are in use: PGDATABASE is the configured default, and some suites
    # still hardcode dbname=pki in their conninfo.
    # pg_isready reports the listener before the server will accept a CREATE
    # DATABASE, so wait for a real query to succeed rather than trusting it.
    _pg_ensure_databases
    return 0
}

# Most PG-tier suites reach Postgres through this file, so ensure one exists the moment
# the helpers are sourced — pg_setup() does it too, but these suites use the FIXED
# `fastpki` database and never call pg_setup at all:
#
#     mesh.sh  pqc.sh  web_keygen_der.sh  web_p12.sh
#
# (acme_reconnect.sh, pg_reconnect.sh and replication_stream.sh also skip pg_setup, but
# each starts its own cluster explicitly through pg_as — see pg_priv.sh.)
#
# Skippable, because sourcing a test helper must not silently provision a database
# on the machine of someone running a DEMO against a live deployment.
[ "$FASTPKI_PG_AUTOSTART" = "0" ] || pg_ensure_server || true

# An openssl date ("Aug 13 11:56:56 2026 GMT", day space-padded for 1..9) as a
# sortable "YYYY-MM-DD HH:MM:SS". Reads stdin. Lets a suite assert that an artefact is
# stamped BEFORE a clock reading taken earlier, using plain string comparison — no
# date(1) arithmetic, which differs between BSD, GNU and busybox and would become its
# own portability bug inside a test.
#
# Shared rather than copied: the certificate, listener and CRL guards all need it, and
# three private copies is how one of them quietly stops matching.
ossl_date_iso() {
    awk 'BEGIN{ split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
                for (i = 1; i <= 12; i++) M[m[i]] = sprintf("%02d", i) }
         NF >= 4 { printf "%s-%s-%02d %s\n", $4, M[$1], $2, $3 }'
}

# ── wait for a listener instead of guessing how long it takes ────────────────────────
#
# ⚠️ A FIXED `sleep` AFTER LAUNCHING A SERVER IS BOTH TOO SLOW AND TOO FRAGILE. Too slow
# because a server that binds in 80ms still costs the suite a full second, and 529 seconds
# — 31% of a whole sequential run — was being spent waiting for ports that were already
# open. Too fragile because the same constant has to cover a loaded CI box, and when it
# does not the suite fails as though the PRODUCT were broken: the first request is refused,
# and the assertion that reports it is about certificates, not about timing.
#
# So poll the port and continue the moment it answers. /dev/tcp is a bash builtin — no nc,
# no curl, nothing to detect — and the harness already requires bash.
#
# ⚠️ THE PID ARGUMENT IS NOT OPTIONAL IN SPIRIT. Without it, a server that dies at startup
# is indistinguishable from one that is slow, and the suite burns the whole timeout before
# failing for the wrong reason. Given the pid, this returns the moment the process is gone,
# so the caller's own "did it die?" check reports the real story.
#
# Usage:  wait_port <port> [pid] [timeout_seconds]   (host is always 127.0.0.1)
# Returns 0 as soon as the port accepts a connection, 1 on timeout or if the pid exits.
wait_port() {
    local port="$1" pid="${2:-}" timeout="${3:-30}"
    local deadline=$(( $(date +%s) + timeout ))
    while :; do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            exec 3<&- 3>&- 2>/dev/null
            return 0
        fi
        # The process we are waiting for has gone: nothing will ever open this port.
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then return 1; fi
        [ "$(date +%s)" -ge "$deadline" ] && return 1
        sleep 0.05
    done
}

# ── wait for slapd to answer, never sleep a fixed time at it ─────────────────────────
#
# ⚠️ THIS IS THE SAME LESSON AS wait_port, AND IT WAS LEARNED TWICE. tests/ldap.sh carries
# a long comment about it: every server there used to be followed by `sleep 1`, and the
# suite's RESULT moved between runs on an unchanged binary — 6 failures one run, 11 the
# next, different assertions each time. A directory that has not finished binding and
# loading its LDIF answers every search with nothing, and "no entries" is indistinguishable
# from the policy result the assertion is actually about.
#
# ad_template_import.sh and directory_group_refresh.sh still slept, and it held right up
# until the harness started running six shards at once — then both failed with counts of 0
# ("the fixture directory loaded completely: expected 8 got 0"), which reads as a broken
# LDAP importer rather than a slapd that was still starting. Concurrency did not break
# them; it removed the slack that was hiding the bug.
#
# Lives here, beside wait_port, rather than being copied a third time: ldap.sh grew this
# implementation, the other two suites need the same thing, and three private copies is how
# one of them quietly stops matching.
#
# Usage:  wait_ldap <pid> <uri>
# Returns 0 as soon as the directory answers a base search, 1 if the pid exits or on timeout.
wait_ldap() {
    local pid="$1" uri="$2" i=0
    while [ "$i" -lt 150 ]; do
        kill -0 "$pid" 2>/dev/null || return 1
        ldapsearch -x -H "$uri" -b "" -s base -LLL >/dev/null 2>&1 && return 0
        i=$((i+1)); sleep 0.1
    done
    return 1
}

# ── wait on the port a server was actually configured with ──────────────────────────
#
# ⚠️ THE PORT IS READ FROM THE CONFIG AT RUNTIME, NOT GUESSED FROM THE SUITE'S VARIABLES.
# That is the whole reason this exists beside wait_port. Converting the first 37 suites was
# mechanical because each named its port in one obvious variable; the remaining ~70 start
# their servers through $WEB / $MS / $OCSP / $BIN with several configs and several ports in
# flight (web.conf, web2.conf, b.conf, stale.conf...), and there is no reliable way to tell
# from the surrounding text WHICH port a given launch will bind. Guessing wrong is worse
# than the sleep it replaces: wait_port would poll a port nobody opens and burn the whole
# timeout before the suite carried on anyway.
#
# The config file the server was just handed is the authority, it is already on disk, and
# it holds the answer as a literal. So read it.
#
# Usage:  wait_conf <config-file> <PORT_KEY> <pid> [timeout]
#   e.g.  wait_conf web.conf WEB_PORT "$P"
# Returns 0 once the port answers, 1 if the key is absent, the pid exits, or it times out.
wait_conf() {
    local conf="$1" key="$2" pid="$3" timeout="${4:-30}" port=""
    port=$(sed -n "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p" \
           "$conf" 2>/dev/null | tail -1)
    # ⚠️ NO SUCH KEY: FALL BACK TO THE OLD FIXED SLEEP, do not return immediately. Every
    # caller writes `wait_conf ... || true`, so a bare `return 1` here would leave the suite
    # with NO wait at all — strictly worse than the sleep this replaced, and silent. A
    # mistyped key must cost a second, never a race.
    [ -n "$port" ] || { sleep 1; return 1; }
    wait_port "$port" "$pid" "$timeout"
}

# ── is anything LISTENING on this port — without connecting to it ────────────────────
#
# ⚠️ wait_port CONNECTS, AND FOR SOME LISTENERS THAT IS DESTRUCTIVE. A `nc -l` serves one
# connection and exits, and `openssl s_server` answers a handshake; the readiness probe
# would BE that connection, and the suite's real request then finds nothing listening. The
# capture files those suites grep would come back empty and the failure would look like a
# broken notifier or a broken responder rather than a probe that ate the request.
#
# So ask the kernel instead of the socket. /proc/net/tcp lists every socket with its state;
# 0A is TCP_LISTEN, and the local address ends in the port as four hex digits. Nothing is
# opened, so a single-shot listener is left exactly as the suite set it up.
#
# Falls back to the old fixed sleep where /proc is not available (macOS), which is not a
# tier we run in — the harness refuses a full run outside the production image.
#
# Usage:  wait_listen <port> <pid> [timeout]
wait_listen() {
    # proto: "tcp" (default) or "any", which also scans /proc/net/udp. A KDC binds UDP as
    # well as TCP and a TCP-only probe would wait out its whole budget every run.
    local port="$1" pid="${2:-}" timeout="${3:-30}" proto="${4:-tcp}"
    if [ ! -r /proc/net/tcp ]; then sleep 1; return 0; fi
    local hex deadline
    hex=$(printf '%04X' "$port")
    deadline=$(( $(date +%s) + timeout ))
    while :; do
        if awk -v h=":$hex" '$4=="0A" && index($2,h)==length($2)-length(h)+1 {f=1}
                             END{exit !f}' /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
            return 0
        fi
        if [ "$proto" = any ] && awk -v h=":$hex" 'index($2,h)==length($2)-length(h)+1 {f=1}
                             END{exit !f}' /proc/net/udp /proc/net/udp6 2>/dev/null; then
            return 0
        fi
        [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null && return 1
        [ "$(date +%s)" -ge "$deadline" ] && return 1
        sleep 0.05
    done
}
