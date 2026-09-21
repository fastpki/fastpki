#!/bin/sh
# deployment-path: operator — runs on the operator's machine; reaches each server the way its path allows (deploy/node-access.sh)
# deploy/mesh-join.sh — connect data centers into a mesh, from the operator's machine.
#
#   deploy/mesh-join.sh [-i <ssh key>] <server> <server> [<server>...]
#
# One server per data center, named as in deploy/node-access.sh:
#   alpine@2001:db8::10            a native or cloud server
#   admin@192.0.2.20               a compose server in ~/FastPKI/deploy
#   admin@192.0.2.20:/opt/fastpki  a compose server in that directory
#   k8s:dc3-cluster/fastpki         a Kubernetes cluster, through kubectl
# A data center with a standby is written <primary>+<standby>; its peers then dial both.
#
# What it does, the same on every path, and safe to run again at any point:
#   1. reads each server's data center id, address, public name and database password
#   2. pass 1 on every server: the map of data centers, then the publication
#   3. stops if a data center has no issuing CA of its own, and says which. Creating the CAs
#      is the operator's decision (one sub CA per data center, or a shared one); run this
#      again once they exist
#   4. sets PG_TLS_CA_ID where it is unset and issues each database certificate from it
#   5. pass 2 on every server: its subscriptions to every peer
#   6. waits until every data center holds the same number of certificates
#
# Each server is given its own copy of the topology, with sslrootcert= naming the file ITS
# Postgres verifies peers with, because that path differs by deployment path. The topology
# holds every database password; it exists only in this script's memory and, briefly, mode
# 600 on each server while fastpki-mesh reads it.
set -eu

case "$0" in */*) HERE=${0%/*} ;; *) HERE=. ;; esac
. "$HERE/node-access.sh"
NA_PROG=mesh-join
say() { echo "mesh-join: $*"; }
die() { echo "mesh-join: $*" >&2; exit 1; }
# 1..n, and nothing for n = 0. Not `seq`: on macOS, where an operator may well run this,
# `seq 1 0` counts DOWN and prints 1 and 0.
upto() { _u=1; while [ "$_u" -le "$1" ]; do echo "$_u"; _u=$((_u+1)); done; }
usage() { sed -n '4,13p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

DCS=""
while [ $# -gt 0 ]; do
    case "$1" in
        -i) NA_SSH_KEY=${2:?}; shift 2 ;;
        -h|--help) usage ;;
        -*) die "unknown option: $1" ;;
        *) DCS="$DCS $1"; shift ;;
    esac
done
set -- $DCS
[ $# -ge 2 ] || usage
N=$#

# ── 1. what each data center is ───────────────────────────────────────────────────────
# Numbered variables, one set per data center: P_i (primary), ID_i, BIND_i, PW_i, DNS_i,
# ANCHOR_i. POSIX sh has no arrays.
i=0
for dc in "$@"; do
    i=$((i+1))
    p=${dc%%+*}; s=""; [ "$p" = "$dc" ] || s=${dc#*+}
    na_resolve "$p"; [ -z "$s" ] || na_resolve "$s"
    F=$(na_facts "$p") || die "cannot read $p"
    id=$(na_fact "$F" DCID); bind=$(na_fact "$F" BIND)
    case "$id" in ''|*[!0-9]*) die "$p has no numeric DATACENTER_ID ('$id')" ;; esac
    case "$bind" in ""|127.*|localhost|::1) die "$p's database address is '$bind': peers cannot reach it. Install it with its own routable PG_BIND" ;; esac
    if [ -n "$s" ]; then
        FS=$(na_facts "$s") || die "cannot read $s"
        [ "$(na_fact "$FS" DCID)" = "$id" ] || die "$s is data center $(na_fact "$FS" DCID), not $id like its primary $p"
        bind="$bind,$(na_fact "$FS" BIND)"
    fi
    for j in $(upto $((i-1))); do
        eval "[ \"\$ID_$j\" != \"$id\" ]" || die "two servers are data center $id: each needs its own DATACENTER_ID"
    done
    eval "P_$i=\$p ID_$i=\$id BIND_$i=\$bind"
    eval "PW_$i=\$(na_fact \"\$F\" PASSWORD) DNS_$i=\$(na_fact \"\$F\" PKI_DNS) ANCHOR_$i=\$(na_fact \"\$F\" ANCHOR)"
    say "data center $id: $dc ($(na_fact "$F" KIND)), database at $bind"
done

# ── 1a. the local accounts two data centers each hold ─────────────────────────────────
#
# ⚠️ `admin` IS ONE ACCOUNT ACROSS A MESH, AND JOINING DOES NOT MERGE THE TWO ROWS. Every
# installer on every path seeds its own admin/admin row into its own database, so before the
# join there are N rows for one username, each written independently. web_users replicates
# with last-writer-wins on the username alone, so exactly one survives and nothing on either
# side records which. The symptom is that the console accepts the password on one data center
# and answers 401 on another while the databases are otherwise in step, which reads as a
# replication fault rather than an account one.
#
# This is the tool that triggers it, so this is where it gets said. It is a WARNING and not a
# refusal: the join is not wrong, the password is simply about to be decided by write order,
# and it is set again in one command afterwards.
#
# The fingerprint is the first 8 characters of an md5 of the stored PBKDF2 hash. It exists to
# answer "is this the same row?" and nothing else - it is never compared against a password,
# and a short digest of an already-hashed value is not a credential. It is what lets step 6
# say which data center's password survived.
# ⚠️ auth_provider = 'local' IS THE FILTER, AND '' IS NOT. A row's auth_provider says where
# its password lives: 'local' is a real PBKDF2 hash in this table, 'dn' is derived from an
# EST client certificate, a provider's name means the password is in that directory, and
# empty or 'external' is a stub a directory has yet to claim. Only a 'local' row holds a
# password that two data centers can each have written a different version of, which is the
# whole subject here.
#
# This was written as `auth_provider = ''` and matched NOTHING on a real deployment, so the
# check below silently did nothing while looking like it worked — found by running it against
# a live two-data-center mesh, where fastpki-config had seeded every row 'local'.
LOCAL_ACCOUNTS_SQL="select username || '|' || must_reset || '|' || substr(md5(hash), 1, 8)
  from web_users where auth_provider = 'local' order by username"
ACCTS=""
for i in $(upto $N); do
    eval "id=\$ID_$i p=\$P_$i"
    _rows=$(printf '%s\n' "$LOCAL_ACCOUNTS_SQL" | na_sql "$p") || _rows=""
    [ -z "$_rows" ] || ACCTS="$ACCTS$(printf '%s\n' "$_rows" | sed "s/^/$id|/")
"
done
# One line per username held by more than one data center with differing rows:
#   <username>|<how many have a password SET>|<the data centers that do>
SHARED=$(printf '%s\n' "$ACCTS" | awk -F'|' '
    $1 != "" && $2 != "" {
        u = $2
        if (!(u in fp))      fp[u] = $4
        else if (fp[u] != $4) differ[u] = 1
        held[u] = held[u] " " $1
        if ($3 == "0") { set[u]++; setdc[u] = setdc[u] " " $1 }
    }
    END { for (u in differ) print u "|" (set[u] + 0) "|" substr(setdc[u], 2) }' | sort)
if [ -n "$SHARED" ]; then
    printf '%s\n' "$SHARED" | while IFS='|' read -r u nset setdc; do
        [ -n "$u" ] || continue
        if [ "$nset" -ge 2 ]; then
            say "WARNING: '$u' has a password set in more than one data center ($setdc)."
            say "  These are separate rows for one account. The join keeps one, chosen by write"
            say "  order, and the other password stops working. Set it again afterwards, once."
        elif [ "$nset" = 1 ]; then
            say "note: '$u' has a password set only in data center $setdc; the others still hold"
            say "  the seeded row. Step 6 reports which one the mesh kept."
        fi
    done
fi

# The topology as server $1 must see it: every data center's line, with sslrootcert= naming
# the anchor path on THAT server.
topology_for() {
    _a=$1
    for j in $(upto $N); do
        eval "_id=\$ID_$j _b=\$BIND_$j _pw=\$PW_$j _dns=\$DNS_$j"
        _n=$(printf '%s' "$_b" | tr ',' '\n' | grep -c .)
        _ports=$(for _k in $(upto "$_n"); do printf '5432,'; done | sed 's/,$//')
        _tsa=""; [ "$_n" -gt 1 ] && _tsa=" target_session_attrs=read-write"
        printf '%s|host=%s port=%s dbname=fastpki user=fastpki password=%s sslmode=verify-full sslrootcert=%s%s|%s|http://%s:8080\n' \
            "$_id" "$_b" "$_ports" "$_pw" "$_a" "$_tsa" "$_id" "$_dns"
    done
}

# Generate on server i, apply on server i. NOTICEs from idempotent DDL ("already exists,
# skipping") say nothing an operator can act on, so they are not shown.
#
# One WARNING is filtered too: every subscription after the first says it "requested
# copy_data with origin = NONE but might copy data that had a different origin". That is the
# mesh's design — every subscription copies, and a row that arrives twice is dropped by the
# certs_skip_dup trigger — so it is not something to act on.
apply_on() {   # apply_on <i> <fastpki-mesh args...>
    _i=$1; shift
    eval "_p=\$P_$_i _a=\$ANCHOR_$_i"
    _sql=$(topology_for "$_a" | na_mesh "$_p" "$@") || return 1
    _err=$(mktemp)
    printf 'SET client_min_messages = warning;\n%s\n' "$_sql" | na_sql "$_p" >/dev/null 2>"$_err"
    _rc=$?
    awk '/^WARNING: +subscription ".*" requested copy_data with origin = NONE/ {skip=2; next}
         skip > 0 && /^(DETAIL|HINT):/ {skip--; next} {skip=0; print}' "$_err" >&2
    rm -f "$_err"
    return $_rc
}

# ── 2. pass 1 ─────────────────────────────────────────────────────────────────────────
for i in $(upto $N); do
    eval "id=\$ID_$i p=\$P_$i"
    apply_on "$i" --map         || die "pass 1 (--map) failed on data center $id ($p)"
    apply_on "$i" --publication || die "pass 1 (--publication) failed on data center $id ($p)"
done
say "pass 1 done: every data center knows the others and publishes"

# ── 3. a CA of its own in every data center ───────────────────────────────────────────
# An issuing CA whose key this server holds: `fastpki-ca list` shows a replicated peer CA
# with an empty ca_key=.
MISSING=""
for i in $(upto $N); do
    eval "id=\$ID_$i p=\$P_$i"
    own=$(na_cli "$p" fastpki-ca list 2>/dev/null | awk -F'\t' '$2 == "active" && $3 == "intermediate" && $5 ~ /ca_key=pkcs11:/ {print $1}')
    eval "OWN_$i=\$own"
    [ -n "$own" ] || MISSING="$MISSING $id"
done
if [ -n "$MISSING" ]; then
    say "stopped: these data centers have no issuing CA of their own yet:$MISSING"
    say "create them: the root once, and a sub CA per data center or one shared by all"
    say "(docs/deployment.md 9.0 steps 5 to 7; on AWS, 12 steps 7 and 8; on Kubernetes, 9.3)."
    say "Then run this command again. It picks up from here."
    exit 3
fi

# ── 4. each database certificate from its data center's CA ────────────────────────────
WAIT=0
for i in $(upto $N); do
    eval "id=\$ID_$i p=\$P_$i own=\$OWN_$i"
    cur=$(echo "select value from config where key = 'PG_TLS_CA_ID'" | na_sql "$p")
    if [ -z "$cur" ]; then
        [ "$(printf '%s\n' "$own" | grep -c .)" = 1 ] \
            || die "data center $id has several issuing CAs ($(echo $own)); set PG_TLS_CA_ID to the one that issues its database certificate, then run this again"
        na_cli "$p" fastpki-config set PG_TLS_CA_ID "$own" >/dev/null
        say "data center $id: PG_TLS_CA_ID=$own"
    fi
    out=$(na_cli "$p" fastpki-ca pg-tls --if-needed 2>&1) || die "data center $id: pg-tls failed: $out"
    case "$out" in *serial:*) WAIT=1; say "data center $id: database certificate issued" ;; esac
done
# Postgres takes a new certificate up within 30 seconds (a minute on Kubernetes), and a peer
# that still serves the old one fails verify-full in pass 2.
[ "$WAIT" = 0 ] || { say "waiting 65 seconds for Postgres to take up the new certificates"; sleep 65; }

# ── 5. pass 2 ─────────────────────────────────────────────────────────────────────────
for i in $(upto $N); do
    eval "id=\$ID_$i p=\$P_$i"
    n=0
    until apply_on "$i" --node "$id"; do
        n=$((n+1)); [ "$n" -lt 4 ] || die "pass 2 failed on data center $id ($p); its error is above"
        say "data center $id: pass 2 did not complete, retrying in 30 seconds"; sleep 30
    done
done
say "pass 2 done: every data center subscribes to every other"

# ── 6. converged ──────────────────────────────────────────────────────────────────────
# The verdict is the certificate count, not the subscription views, which report healthy
# while a node is still short of rows (docs/deployment.md 9.2).
n=0
while :; do
    counts=""; workers_ok=1
    for i in $(upto $N); do
        eval "p=\$P_$i id=\$ID_$i"
        c=$(echo "select count(*) from certs" | na_sql "$p")
        w=$(echo "select count(*) from pg_stat_subscription where pid is not null and relid is null" | na_sql "$p")
        [ "$w" = $((N-1)) ] || workers_ok=0
        counts="$counts $id:$c"
    done
    distinct=$(printf '%s\n' $counts | cut -d: -f2 | sort -u | grep -c .)
    [ "$distinct" = 1 ] && [ "$workers_ok" = 1 ] && break
    n=$((n+1)); [ "$n" -lt 12 ] || die "the data centers do not hold the same data after 2 minutes (data center:certificates =$counts); docs/deployment.md 9.6"
    sleep 10
done
if [ "$N" = 2 ]; then peers="to the other"; else peers="to all $((N-1)) others"; fi
say "done: every data center holds $(printf '%s\n' $counts | head -1 | cut -d: -f2) certificates, and each is subscribed $peers"

# ── 7. which account row the mesh kept ────────────────────────────────────────────────
#
# ⚠️ THIS IS THE FACT NOBODY COULD GET BEFORE. Two independently seeded rows for one
# username collapse to one on join, and last-writer-wins is decided by write order, which
# is not visible from either console. An operator whose password stopped working could see
# only that it worked here and not there. Now the tool that merged them says which one it
# kept, by matching the converged row against the fingerprints taken before pass 1.
if [ -n "$SHARED" ]; then
    eval "p=\$P_1"
    NOW=$(printf '%s\n' "$LOCAL_ACCOUNTS_SQL" | na_sql "$p") || NOW=""
    printf '%s\n' "$SHARED" | while IFS='|' read -r u nset setdc; do
        [ -n "$u" ] || continue
        # An account nobody has set a password on yet is still seeded everywhere and must be
        # changed at first sign-in whichever row survived, so which one it was is not a fact
        # anyone can act on.
        [ "$nset" -ge 1 ] || continue
        fpnow=$(printf '%s\n' "$NOW" | awk -F'|' -v u="$u" '$1 == u {print $3}')
        if [ -z "$fpnow" ]; then
            say "'$u' is no longer in the mesh's accounts"
            continue
        fi
        from=$(printf '%s\n' "$ACCTS" | awk -F'|' -v u="$u" -v f="$fpnow" '$2 == u && $4 == f {print $1}' | sort -u | tr '\n' ' ')
        from=${from% }
        if [ -n "$from" ]; then
            say "'$u': the mesh kept the row from data center $from — that password is now the one"
            say "  in force everywhere."
        fi
        if [ "$nset" -ge 2 ]; then
            say "  Set it again now if that is not the one you want. docs/deployment.md 9.0 step 2"
            say "  has the command for every deployment path."
        fi
    done
fi
