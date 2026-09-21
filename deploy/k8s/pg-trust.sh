#!/bin/sh
# pg-trust.sh — build this server pod's PostgreSQL trust bundle.
#
#   sh /scripts/pg-trust.sh                         # from what is on disk and in the ConfigMap
#   sh /scripts/pg-trust.sh --refresh-roots         # and re-read the root CAs from the database
#   sh /scripts/pg-trust.sh --dir /pki/tls/pg       # the Postgres container mounts the claim at /pki
#
# ── WHY A BUNDLE, AND WHAT GOES IN IT ─────────────────────────────────────────────────
#
# Every pod is a whole server with its own Postgres, and every application connects with
# `host=127.0.0.1,fastpki-node-0.fastpki-node,fastpki-node-1.fastpki-node … sslmode=verify-full sslrootcert=trust.crt`. libpq
# stops at the first host whose certificate it cannot verify and never tries the next one, so
# each pod has to be able to verify EVERY pod's database — including one that is serving the
# self-signed pair certgen wrote at first start, before any CA exists. On Compose the join
# script carries the primary's anchor across by hand (`primary-ca.crt`); here three sources
# are concatenated instead, and the result is rebuilt every minute:
#
#   ca.crt                this pod's own anchor: its self-signed certificate, plus the root
#                         `fastpki-ca pg-tls` appends once the database certificate is issued
#   the fastpki-pg-anchors     every pod's ca.crt, published by apply.sh — how a pod that has never
#     ConfigMap           reached the database can verify the one it is about to seed from
#   roots.pem             every self-signed CA certificate registered in the database, re-read
#                         while the connection still works
#
# ⚠️ THE ROOTS ARE WHAT MAKES THE SWITCH TO CA-ISSUED CERTIFICATES SAFE. When the renewal sweep
# replaces a pod's self-signed database certificate with one from PG_TLS_CA_ID, every OTHER
# pod has to trust that CA's root already — the moment it does not, its connections to the
# switched pod fail, and so does this very refresh, which needs the database to learn the root.
# A root exists long before any database certificate chains to it (the CAs are created first,
# PG_TLS_CA_ID is set after), and this runs every minute, so by the time a sweep switches a
# pod every pod has the root cached on its own claim. Trusting this PKI's roots is the same
# reach Compose has: its ca.crt gains the issuing root the same way.
#
# ⚠️ A FAILED READ KEEPS WHAT WAS CACHED. An empty answer from an unreachable database would
# otherwise empty roots.pem, and the next rebuild would drop the very root that lets the pod
# reconnect. roots.pem is replaced only by a read that returned at least one certificate.
set -u

DIR=/var/pki/tls/pg
ANCHORS=/etc/fastpki/pg-anchors
REFRESH=0
CONF=/app/config/bootstrap.conf
while [ $# -gt 0 ]; do
    case "$1" in
        --refresh-roots) REFRESH=1; shift ;;
        --dir) DIR="${2:?--dir needs a path}"; shift 2 ;;
        *) echo "pg-trust: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -d "$DIR" ] || exit 0

if [ "$REFRESH" = 1 ] && command -v fastpki-ca >/dev/null 2>&1; then
    _roots="$DIR/.roots.pem.$$"
    : > "$_roots"
    if _ids=$(fastpki-ca --config "$CONF" list 2>/dev/null | cut -f1); then
        for _id in $_ids; do
            _pem=$(fastpki-ca --config "$CONF" show "$_id" --pem 2>/dev/null) || continue
            _s=$(printf '%s\n' "$_pem" | openssl x509 -noout -subject 2>/dev/null | sed 's/^subject=//')
            _i=$(printf '%s\n' "$_pem" | openssl x509 -noout -issuer 2>/dev/null | sed 's/^issuer=//')
            [ -n "$_s" ] && [ "$_s" = "$_i" ] || continue
            printf '%s\n' "$_pem" >> "$_roots"
        done
    fi
    if grep -q 'BEGIN CERTIFICATE' "$_roots" 2>/dev/null; then
        cmp -s "$_roots" "$DIR/roots.pem" 2>/dev/null || mv -f "$_roots" "$DIR/roots.pem"
    fi
    rm -f "$_roots"
fi

_tmp="$DIR/.trust.crt.$$"
{
    cat "$DIR/ca.crt" 2>/dev/null
    for _f in "$ANCHORS"/*.pem; do [ -f "$_f" ] && cat "$_f"; done
    cat "$DIR/roots.pem" 2>/dev/null
} > "$_tmp"
if ! grep -q 'BEGIN CERTIFICATE' "$_tmp" 2>/dev/null; then
    rm -f "$_tmp"
    exit 0
fi
chmod 644 "$_tmp"
if cmp -s "$_tmp" "$DIR/trust.crt" 2>/dev/null; then
    rm -f "$_tmp"
else
    mv -f "$_tmp" "$DIR/trust.crt"
fi
exit 0
