#!/bin/sh
# start-postgres.sh — this server pod's own PostgreSQL, in Kubernetes.
#
# Each fastpki-node pod is one whole server, the Kubernetes form of one Compose host: its own
# token, its own /var/pki and its own database. This is that database's entrypoint, and it
# decides which of three things this pod's Postgres is, from what is on its own claim and
# what its peers answer:
#
#   an empty data directory, and no peer answering    pod 0 of a new deployment: initialise
#                                                     a primary (createdb.sql)
#   an empty data directory, and a peer that is       seed from it with pg_basebackup and
#     read-write                                      stream — Compose's STANDBY_OF join
#   a data directory holding standby.signal           a standby: start as one
#   a data directory holding a primary's data         start as the primary — unless a peer is
#                                                     ALREADY one, below
#
# ⚠️ A RETURNING OLD PRIMARY MUST NOT START AS A SECOND ONE. On Compose an operator promotes
# the standby and is told not to restart the old host; here nothing asks — a node that comes
# back simply starts its pod, finds a primary's data directory and would come up read-write
# beside the promoted one, with every application's `target_session_attrs=read-write` free to
# land on either. So a populated primary data directory checks its peers first and REFUSES
# when one of them is read-write. The remedy is the one Compose documents: delete this pod's
# `pgdata` claim and it seeds from the new primary on its next start.
#
# ⚠️ AN EMPTY DIRECTORY BESIDE A LIVE STANDBY IS NOT A NEW DEPLOYMENT. Pod 0 initialises only
# when no peer answers at all. A standby that answers means this deployment already has data,
# and its primary is the thing that is missing — so this waits for a primary to seed from
# (promote the standby) rather than creating an empty second history.
#
# Placed in the ConfigMap rather than inline in the manifest because apply.sh renders manifests
# through envsubst, which would substitute every shell variable below.
set -eu

SRC=/pki/tls/pg
TLS=/var/lib/postgresql/tls
DATA=/var/lib/postgresql/data
TRUST=$SRC/trust.crt
USER_="${POSTGRES_USER:-fastpki}"
DB_="${POSTGRES_DB:-fastpki}"
SELF="${PG_BIND:?PG_BIND names this pod and is set by the manifest}"
POD="${POD_NAME:?}"
SET="${POD%-*}"
ORD="${POD##*-}"
SVC="${NODE_SERVICE:-$SET}"
COUNT="${NODE_COUNT:-1}"
# One physical slot per standby, so a second standby or a rebuilt one never takes over
# another's position in the WAL. ⚠️ ONE NAME ON EVERY PATH: fastpki_ and this server's own
# PG_BIND, lowercased, each character outside a-z and 0-9 as _, at most 63 characters (the
# Postgres limit) — deploy/ha-join.sh and deploy/docker-compose.yml derive it the same way.
SLOT="$(printf 'fastpki_%s' "$SELF" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9\n' '_' | cut -c1-63)"
AS="$(command -v gosu || command -v su-exec || true)"
export PGPASSWORD="${POSTGRES_PASSWORD:-}"

peers() {
    _i=0
    while [ "$_i" -lt "$COUNT" ]; do
        [ "$_i" = "$ORD" ] || printf '%s\n' "$SET-$_i.$SVC"
        _i=$((_i + 1))
    done
}
conn() {
    printf 'host=%s port=5432 user=%s dbname=%s sslmode=verify-full sslrootcert=%s connect_timeout=3' \
        "$1" "$USER_" "$DB_" "$TRUST"
}
# The trust bundle is rebuilt here too, not only by the renewal loop: a pod waiting to seed has
# no database connection and no loop of its own yet, and the anchor it needs arrives through
# the ConfigMap while it waits.
refresh_trust() { sh /scripts/pg-trust.sh --dir "$SRC" >/dev/null 2>&1 || true; }
# The first peer that is a read-write primary, verified. An unverifiable certificate reads as
# "no primary" rather than as one, which is the safe direction.
primary_peer() {
    for _p in $(peers); do
        _r=$(${AS:+$AS postgres} psql -d "$(conn "$_p")" -tAc 'SELECT pg_is_in_recovery()' 2>/dev/null \
             | tr -d '[:space:]') || true
        [ "$_r" = f ] && { printf '%s' "$_p"; return 0; }
    done
    return 1
}
any_peer_answers() {
    for _p in $(peers); do
        pg_isready -q -h "$_p" -p 5432 -t 2 >/dev/null 2>&1 && return 0
    done
    return 1
}

# Returns 0 only when it copied something new. Writes .new + mv so the server never reads a
# half-copied PEM. Postgres refuses a key file it does not own, so the delivery point on the
# claim is copied into a directory this container owns.
sync_tls() {
    [ -f "$SRC/server.crt" ] && [ -f "$SRC/server.key" ] || return 1
    if [ -f "$TLS/server.crt" ] && cmp -s "$SRC/server.crt" "$TLS/server.crt" \
       && cmp -s "$SRC/server.key" "$TLS/server.key"; then return 1; fi
    mkdir -p "$TLS"
    cp "$SRC/server.crt" "$TLS/server.crt.new" || return 1
    cp "$SRC/server.key" "$TLS/server.key.new" || return 1
    chown 70:70 "$TLS/server.crt.new" "$TLS/server.key.new"
    chmod 644 "$TLS/server.crt.new"
    chmod 600 "$TLS/server.key.new"
    mv "$TLS/server.crt.new" "$TLS/server.crt"
    mv "$TLS/server.key.new" "$TLS/server.key"
    return 0
}

sync_tls || true
refresh_trust

# ⚠️ FAIL CLOSED. Every application dials this server with sslmode=verify-full, so a plaintext
# server can serve nobody — and `ssl` is a command-line option, the highest precedence, so a
# server that starts plaintext stays plaintext for the life of the process.
if [ ! -f "$TLS/server.key" ]; then
    echo "postgres: FATAL - no $SRC/server.key, so this server cannot serve TLS." >&2
    echo "postgres: it is written by the init container (certgen) of this pod." >&2
    exit 1
fi
SSL="-c ssl=on -c ssl_cert_file=$TLS/server.crt -c ssl_key_file=$TLS/server.key"

if [ ! -s "$DATA/PG_VERSION" ]; then
    if [ "$ORD" = 0 ] && ! any_peer_answers; then
        echo "postgres: $POD has no data and no peer answers — initialising this deployment's primary"
        rm -f /pki/standby_of
    else
        [ "$ORD" = 0 ] && echo "postgres: $POD has no data, but a peer answers — this deployment" \
            "already exists, so waiting for a read-write primary to seed from rather than" \
            "creating a second history (promote the surviving standby if it has none)"
        echo "postgres: $POD is waiting for a read-write primary among: $(peers | tr '\n' ' ')"
        until P=$(primary_peer); do refresh_trust; sleep 5; done
        echo "postgres: seeding $POD from $P (pg_basebackup, slot=$SLOT)"
        ${AS:+$AS postgres} psql -d "$(conn "$P")" -v ON_ERROR_STOP=0 -tAc \
            "SELECT pg_drop_replication_slot('$SLOT') FROM pg_replication_slots
              WHERE slot_name='$SLOT' AND NOT active;" >/dev/null 2>&1 || true
        rm -rf "$DATA"/* "$DATA"/.[!.]* 2>/dev/null || true
        chown 70:70 "$DATA"; chmod 700 "$DATA"
        if ! ${AS:+$AS postgres} pg_basebackup -h "$P" -p 5432 -U "$USER_" \
                -D "$DATA" -Fp -Xs -R -P -C -S "$SLOT" -d "$(conn "$P")"; then
            echo "postgres: seeding from $P FAILED (trust bundle: $TRUST)." >&2
            exit 1
        fi
        # The Kubernetes form of Compose's STANDBY_OF line in .env: per pod, on this pod's own
        # claim, read by the console and the renewal loop, removed when this pod is promoted.
        printf '%s\n' "$P" > /pki/standby_of
        chmod 644 /pki/standby_of
        echo "postgres: seeded; $POD is a streaming standby of $P"
    fi
elif [ -f "$DATA/standby.signal" ]; then
    echo "postgres: $POD is a standby (standby.signal present) — starting as one"
else
    if P=$(primary_peer); then
        echo "postgres: REFUSING to start $POD as a primary — $P is already read-write." >&2
        echo "postgres: this pod's data is the old primary's history, which diverged when $P" >&2
        echo "postgres: was promoted. Starting it would give applications two read-write" >&2
        echo "postgres: databases to land on. Rebuild this pod as a standby of $P instead:" >&2
        echo "postgres:     kubectl -n <namespace> delete pvc pgdata-$POD --wait=false" >&2
        echo "postgres:     kubectl -n <namespace> delete pod $POD" >&2
        echo "postgres: It then seeds from $P on its next start." >&2
        exit 1
    fi
    rm -f /pki/standby_of
fi

# ⚠️ A STANDBY NEEDS SETTINGS A PRIMARY DOES NOT, and their absence is silent: PG17 synchronises
# a primary's logical (failover) slots only with sync_replication_slots and hot_standby_feedback
# on, primary_slot_name set and a real dbname in primary_conninfo — pg_basebackup -R writes the
# last two. Without the first two a standby of a mesh member synchronises nothing, and promoting
# it takes the data center out of the mesh while everything looks healthy.
SBY=""
if [ -f "$DATA/standby.signal" ]; then
    SBY="-c hot_standby=on -c sync_replication_slots=on -c hot_standby_feedback=on"
    # And the primary's half: hold its logical subscribers back until this standby has the WAL.
    # Named from here because naming a slot that does not exist stalls every logical walsender.
    if [ -r /pki/standby_of ]; then
        P="$(cat /pki/standby_of)"
        (
            until ${AS:+$AS postgres} psql -d "$(conn "$P")" -tAc 'SELECT 1' >/dev/null 2>&1; do
                refresh_trust; sleep 5
            done
            if ${AS:+$AS postgres} psql -d "$(conn "$P")" -v ON_ERROR_STOP=1 \
                   -c "ALTER SYSTEM SET synchronized_standby_slots = '$SLOT'" \
                   -c "SELECT pg_reload_conf()" >/dev/null 2>&1; then
                echo "postgres: $P now waits for slot $SLOT before confirming to peers"
            else
                echo "postgres: WARNING could not set synchronized_standby_slots on $P —" \
                     "a mesh peer can consume past this standby, so a promotion may diverge"
            fi
        ) &
    fi
fi

# ⚠️ A STANDBY CANNOT AUTHENTICATE WITHOUT THIS. pg_basebackup opens a replication connection,
# which is a separate pg_hba database column from everything the applications use, and the
# image's default pg_hba says nothing about it. Added on every pod, primary or not, because a
# standby becomes the primary at a promotion and its peer then has to be able to seed from it.
(
    until pg_isready -q -U "$USER_" -d "$DB_"; do sleep 1; done
    HBA="$DATA/pg_hba.conf"
    if [ -f "$HBA" ] && ! grep -q 'FASTPKI-HA-STANDBY' "$HBA"; then
        printf '# FASTPKI-HA-STANDBY: streaming standby\nhostssl replication %s all scram-sha-256\n' \
            "$USER_" >> "$HBA"
        psql -U "$USER_" -d "$DB_" -c 'SELECT pg_reload_conf()' >/dev/null 2>&1 || true
        echo "postgres: enabled the replication pg_hba rule for a streaming standby"
    fi
) &

# Adopt a certificate the renewal sweep issued while running, and keep the trust bundle current
# for this server's own outbound connections (a standby's walreceiver verifies its primary).
(
    until pg_isready -q -U "$USER_" -d "$DB_"; do sleep 2; done
    while :; do
        sleep 30
        refresh_trust
        if sync_tls; then
            if psql -U "$USER_" -d "$DB_" -c 'SELECT pg_reload_conf()' >/dev/null 2>&1; then
                echo "postgres: adopted a new TLS certificate from $SRC and reloaded"
            else
                echo "postgres: WARNING copied a new TLS certificate from $SRC but could not reload —" \
                     "it will be served after the next restart"
            fi
        fi
    done
) &

# Same flags as the Compose server. max_slot_wal_keep_size caps what an unconsumed slot can pin,
# so a standby or a mesh peer that is gone for good invalidates its slot instead of filling
# the claim. synchronized_standby_slots is deliberately NOT a flag here: it is set by a standby
# through ALTER SYSTEM, and a command-line flag would outrank that and make it a no-op.
exec docker-entrypoint.sh postgres \
    -c log_line_prefix='%m [%p] %q%u@%d %h ' \
    -c wal_level=logical -c max_wal_senders=10 -c max_replication_slots=10 \
    -c max_slot_wal_keep_size=8GB $SSL $SBY
