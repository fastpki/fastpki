#!/bin/sh
# deployment-path: operator — runs on the operator's machine; native and cloud (ssh + doas), compose (ssh + docker compose); a Kubernetes pair is built by apply.sh (HA_ENABLED)
# deploy/ha-join-pair.sh — make one server the streaming standby of another, from the
# operator's machine, in one command.
#
#   deploy/ha-join-pair.sh --primary <server> --standby <server> [-i <ssh key>]
#                          [--replace-local-database]
#
# Servers are named as in deploy/node-access.sh: alpine@<address> for a native or cloud
# server, admin@<host>[:/path/to/deploy] for compose. Both must be the same kind, and both
# installed for a pair (HA_ENABLED=yes).
#
# It runs ha-join.sh on both hosts: on the standby to copy the primary's database and point
# its services at both hosts, on the primary to point its own services at both. Then it copies
# the CA keys between the two tokens, on each host, until both hold every key they need.
#
# The three things only the primary has — its database CA certificate, its database password
# and its token PIN — travel from one host to the other through this script's memory, on
# stdin. Nothing secret is typed, and nothing secret is written on this machine.
set -eu

case "$0" in */*) HERE=${0%/*} ;; *) HERE=. ;; esac
. "$HERE/node-access.sh"
NA_PROG=ha-join-pair
say() { echo "ha-join-pair: $*"; }
die() { echo "ha-join-pair: $*" >&2; exit 1; }
usage() { sed -n '4,11p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

REPLACE="" A="" B=""
while [ $# -gt 0 ]; do
    case "$1" in
        --primary) A=${2:?}; shift 2 ;;
        --standby) B=${2:?}; shift 2 ;;
        -i) NA_SSH_KEY=${2:?}; shift 2 ;;
        --replace-local-database) REPLACE=--replace-local-database; shift ;;
        -h|--help) usage ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "$A" ] && [ -n "$B" ] || usage

na_resolve "$A"; KA=$NA_KIND
na_resolve "$B"; KB=$NA_KIND
[ "$KA" = "$KB" ] || die "$A is a $KA server and $B a $KB one: a pair is one data center twice, on one deployment path"
case "$KA" in
    k8s) die "a Kubernetes pair is built by deploy/k8s/apply.sh with HA_ENABLED=true" ;;
    native) JOIN=/usr/share/fastpki/ha-join.sh
            KEYS="/etc/periodic/daily/fastpki-certrenew" ;;
    compose) JOIN=./ha-join.sh
            # In the certrenew container, which has this host's PG_BIND from .env and the pair's
            # PG_CONNINFO from the override — the same as its own renewal loop runs it.
            KEYS='docker compose exec -T certrenew sh -c '"'"'p=""; [ -f /var/pki/tls/srcpin ] && p="--source-pin-file /var/pki/tls/srcpin"; fastpki-ca --config /app/config/bootstrap.conf key sync --from-peers $p'"'" ;;
esac
for h in "$A" "$B"; do
    na_run "$h" "test -x $JOIN" || die "$h has no $JOIN: update it to a release that includes it"
done

FA=$(na_facts "$A") || die "cannot read $A"
FB=$(na_facts "$B") || die "cannot read $B"
A_BIND=$(na_fact "$FA" BIND); B_BIND=$(na_fact "$FB" BIND)
[ "$(na_fact "$FA" DCID)" = "$(na_fact "$FB" DCID)" ] \
    || die "$A is data center $(na_fact "$FA" DCID) and $B is $(na_fact "$FB" DCID): a standby takes its primary's DATACENTER_ID"
say "primary $A answers on $A_BIND; standby $B on $B_BIND"

ANCHOR=$(na_anchor_pem "$A")
PW=$(na_fact "$FA" PASSWORD); APIN=$(na_fact "$FA" PIN); BPIN=$(na_fact "$FB" PIN)
[ -n "$ANCHOR" ] && [ -n "$PW" ] && [ -n "$APIN" ] && [ -n "$BPIN" ] \
    || die "could not read the primary's anchor, password or PIN, or the standby's PIN"

# Put a secret into a private temporary directory on a host, through stdin.
put() {   # put <server> <dir> <name> <value>
    printf '%s\n' "$4" | na_run "$1" "umask 077; cat > $2/$3"
}

# ── the standby ───────────────────────────────────────────────────────────────────────
# Run twice: now, to copy the database, and at the end, once the pair's CA has issued the
# standby its own database certificate, when the same command lists the standby first.
join_standby() {
    T=$(na_run "$B" 'umask 077; mktemp -d')
    put "$B" "$T" primary-ca.crt "$ANCHOR"
    put "$B" "$T" pw "$PW"
    PINOPT=""
    if [ "$APIN" != "$BPIN" ]; then put "$B" "$T" pin "$APIN"; PINOPT="--primary-pin-file $T/pin"; fi
    na_run "$B" "FASTPKI_JOIN_BY_PAIR=1 $JOIN $A_BIND $T/primary-ca.crt --primary-password-file $T/pw $PINOPT $REPLACE; rc=\$?; rm -rf $T; exit \$rc"
}
say "joining the standby: its checks first, then its database is replaced by a copy of the primary's"
join_standby || die "the standby's join stopped; its message is above. Nothing was changed on the primary."

# ── the primary ───────────────────────────────────────────────────────────────────────
PINOPT=""
T=$(na_run "$A" 'umask 077; mktemp -d')
if [ "$APIN" != "$BPIN" ]; then put "$A" "$T" pin "$BPIN"; PINOPT="--standby-pin-file $T/pin"; fi
na_run "$A" "FASTPKI_JOIN_BY_PAIR=1 $JOIN --on-primary $B_BIND $PINOPT; rc=\$?; rm -rf $T; exit \$rc" \
    || die "the primary's half stopped; its message is above"

# ── the keys ──────────────────────────────────────────────────────────────────────────
# Standby first, so it takes what the primary holds; then the primary, for anything that
# exists only on the standby. Each host's tunnel learns the other's certificate within a
# minute, so the first attempts can find no peer yet: they are retried, not reported.
for pair in "standby|$B" "primary|$A"; do
    role=${pair%%|*}; h=${pair#*|}
    n=0
    while :; do
        n=$((n+1))
        out=$(na_run "$h" "$KEYS" 2>&1 || true)
        if printf '%s' "$out" | grep -q 'holds every key it needs to serve'; then
            say "$role: holds every key it needs to serve"; break
        fi
        [ "$n" -lt 6 ] || { printf '%s\n' "$out" | tail -5 >&2; die "$role: the keys were still incomplete after $n attempts; the last lines are above"; }
        say "$role: keys not complete yet, retrying in 30 seconds"
        sleep 30
    done
done

# ── the standby's own database certificate, and the steady order ──────────────────────
# With the CA key now in its token, the standby can be issued its own database certificate
# from the pair's CA. Postgres takes it up within 30 seconds; the standby's half, run again,
# then finds it verifies and lists the standby first in its own services' PG_CONNINFO, so a
# primary being rebuilt cannot take the standby's services down with it.
out=$(na_cli "$B" fastpki-ca pg-tls --if-needed 2>&1) || die "standby: its database certificate could not be issued: $out"
case "$out" in *serial:*) say "standby: database certificate issued from the pair's CA" ;; esac
# The standby's half turns the order round only once Postgres SERVES a certificate the pair's
# CA issued, which is up to 30 seconds after it is written — whether this command issued it
# or the renewal job run by the key step above already had.
n=0
while :; do
    n=$((n+1))
    out=$(join_standby 2>&1) || { printf '%s\n' "$out" >&2; die "the standby's second pass stopped; its message is above"; }
    case "$out" in *"$B_BIND,$A_BIND"*) say "standby: its services now reach the standby first, then the primary"; break ;; esac
    [ "$n" -lt 4 ] || { say "standby: its services still reach the primary first: its own certificate is not being served yet; run this command again in a minute"; break; }
    sleep 30
done

say "done: $B streams from $A and holds the CA keys."
say "test a failover before relying on it: docs/high-availability.md, the failover drill."
