#!/bin/sh
# deploy/native/pg-tls-sync.sh — keep the PostgreSQL server's TLS material in step with
# what FastPKI publishes, on a native install. Installed as /usr/libexec/fastpki/pg-tls-sync.
#
#   pg-tls-sync once      copy if changed and exit (the installer runs this before
#                         PostgreSQL is first started)
#   pg-tls-sync follow    the same check every 30s, reloading the server on a change
#                         (the fastpki-pgtls OpenRC service)
#
# ── WHY POSTGRES DOES NOT SIMPLY READ THE FILE IN PLACE ────────────────────────────────
#
# PostgreSQL refuses a private key file it does not own ("private key file has
# non-root/non-owner ownership"). The obvious fix — chown the published pair to the
# postgres user — cannot work, because of WHO WRITES IT:
#
#   phase 1  deploy/certgen.sh, as root, self-signs the transport certificate at deploy
#            time, before any CA exists.
#   phase 2  `fastpki-ca pg-tls <ca-id>` or the console replaces it with a CA-issued
#            certificate carrying the interconnect SANs — and
#            fastpki-web runs as the unprivileged fastpki user. It cannot chown to
#            postgres, and creating a file needs write on the DIRECTORY.
#
# So /var/pki/tls/pg is the DELIVERY point, owned by the runtime user, and the server
# reads a COPY it owns. That is exactly the arrangement the compose stack uses, expressed
# there as a shell loop inside the postgres service's command.
#
# ⚠️ THE COPY IS DELIBERATELY NOT INSIDE PGDATA. pg_basebackup copies the whole data
# directory, so a standby seeded from this node would inherit the primary's copy and then
# fight its own sync over it.
#
# The copy is also what lets the certificate change without a restart: a SIGHUP re-runs
# secure_initialize(), which re-reads ssl_cert_file/ssl_key_file from disk, and the paths
# never move. Existing sessions keep the old certificate until they reconnect, which is
# normal TLS rotation, not a defect.
set -eu

SRC="${PG_TLS_SRC:-/var/pki/tls/pg}"
DST="${PG_TLS_DST:-/var/lib/postgresql/tls}"
INTERVAL="${PG_TLS_INTERVAL:-30}"
MODE="${1:-once}"

# Copies only when the source really differs, so the return value means "something
# changed" and the follow loop does not reload every 30 seconds forever. Writes .new and
# renames, so the server never reads a half-copied PEM.
sync_one() {   # sync_one <name> <mode>
    _n="$1"; _m="$2"
    [ -f "$SRC/$_n" ] || return 1
    if [ -f "$DST/$_n" ] && cmp -s "$SRC/$_n" "$DST/$_n"; then
        return 1
    fi
    cp "$SRC/$_n" "$DST/$_n.new"
    chown postgres:postgres "$DST/$_n.new"
    chmod "$_m" "$DST/$_n.new"
    mv -f "$DST/$_n.new" "$DST/$_n"
    return 0
}

sync_tls() {
    changed=1
    install -d -m 0700 -o postgres -g postgres "$DST"
    sync_one server.crt 0644 && changed=0
    sync_one server.key 0600 && changed=0
    # ca.crt is the anchor the apps verify against, not something the server reads; it is
    # copied so a standby rebuild and a psql run from this host have it in one place.
    sync_one ca.crt     0644 && changed=0
    # primary-ca.crt is a standby's copy of its PRIMARY's anchor, placed by the operator
    # (docs/high-availability.md section 4). The standby's own server dials the primary with
    # it — pg_basebackup, then primary_conninfo — and runs as postgres, which cannot enter
    # /var/pki. Its own ca.crt cannot stand in: until this host is issued a certificate by
    # the pair's CA, that file holds its own self-signed certificate. One file placed in the
    # same spot as on compose, where ha-join.sh puts it and the postgres container reads it.
    sync_one primary-ca.crt 0644 && changed=0
    return $changed
}

case "$MODE" in
  once)
    if [ ! -f "$SRC/server.crt" ] || [ ! -f "$SRC/server.key" ]; then
        echo "pg-tls-sync: $SRC has no server certificate — run certgen.sh first." >&2
        exit 1
    fi
    sync_tls || true
    exit 0 ;;
  follow)
    while :; do
        sleep "$INTERVAL"
        if sync_tls; then
            if su postgres -s /bin/sh -c "psql -q -d fastpki -c 'SELECT pg_reload_conf()'" >/dev/null 2>&1; then
                echo "pg-tls-sync: adopted a new TLS certificate from $SRC and reloaded"
            else
                echo "pg-tls-sync: WARNING copied a new TLS certificate from $SRC but could" \
                     "not reload — it will be served after the next restart" >&2
            fi
        fi
    done ;;
  *)
    echo "usage: pg-tls-sync once|follow" >&2; exit 2 ;;
esac
