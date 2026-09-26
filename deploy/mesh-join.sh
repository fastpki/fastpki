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
#   4. sets PG_TLS_CA_ID where it is unset and issues each database certificate from it,
#      and picks one row for each local account the data centers hold differently
#   5. pass 2 on every server: its subscriptions to every peer
#   6. waits until every data center holds the same number of certificates
#   7. reads those accounts back from every data center and says which password works where
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

# The port a peer dials at each address of <bind>: <ports> as a server reported it, or 5432 at
# every address when it reported none (native and Compose publish 5432). A Kubernetes server
# publishes each of its databases on its own port, and one it cannot name fails the join here:
# a topology that dials the wrong port subscribes to nothing.
db_ports() {   # db_ports <bind> <ports>
    _dn=$(printf '%s' "$1" | tr ',' '\n' | grep -c .)
    if [ -z "$2" ]; then
        for _dk in $(upto "$_dn"); do printf '5432,'; done | sed 's/,$//'
        return 0
    fi
    [ "$(printf '%s' "$2" | tr ',' '\n' | grep -c '^[0-9][0-9]*$')" = "$_dn" ] || return 1
    printf '%s\n' "$2"
}

# ── 1. what each data center is ───────────────────────────────────────────────────────
# Numbered variables, one set per data center: P_i (primary), ID_i, BIND_i, PORTS_i, PW_i,
# DNS_i, ANCHOR_i. POSIX sh has no arrays.
i=0
for dc in "$@"; do
    i=$((i+1))
    p=${dc%%+*}; s=""; [ "$p" = "$dc" ] || s=${dc#*+}
    na_resolve "$p"; [ -z "$s" ] || na_resolve "$s"
    F=$(na_facts "$p") || die "cannot read $p"
    id=$(na_fact "$F" DCID); bind=$(na_fact "$F" BIND)
    case "$id" in ''|*[!0-9]*) die "$p has no numeric DATACENTER_ID ('$id')" ;; esac
    case "$bind" in ""|127.*|localhost|::1) die "$p's database address is '$bind': peers cannot reach it. Install it with its own routable PG_BIND" ;; esac
    ports=$(db_ports "$bind" "$(na_fact "$F" PORTS)") || die "$p publishes no database port for every address in '$bind'. On Kubernetes, set PG_EXTERNAL_TYPE and run apply.sh again"
    if [ -n "$s" ]; then
        FS=$(na_facts "$s") || die "cannot read $s"
        [ "$(na_fact "$FS" DCID)" = "$id" ] || die "$s is data center $(na_fact "$FS" DCID), not $id like its primary $p"
        _sb=$(na_fact "$FS" BIND)
        _sp=$(db_ports "$_sb" "$(na_fact "$FS" PORTS)") || die "$s publishes no database port for every address in '$_sb'"
        bind="$bind,$_sb"; ports="$ports,$_sp"
    fi
    for j in $(upto $((i-1))); do
        eval "[ \"\$ID_$j\" != \"$id\" ]" || die "two servers are data center $id: each needs its own DATACENTER_ID"
    done
    eval "P_$i=\$p ID_$i=\$id BIND_$i=\$bind PORTS_$i=\$ports"
    eval "PW_$i=\$(na_fact \"\$F\" PASSWORD) DNS_$i=\$(na_fact \"\$F\" PKI_DNS) ANCHOR_$i=\$(na_fact \"\$F\" ANCHOR)"
    say "data center $id: $dc ($(na_fact "$F" KIND)), database at $bind (ports $ports)"
done

# ── 1a. the local accounts two data centers each hold ─────────────────────────────────
#
# ⚠️ `admin` IS ONE ACCOUNT ACROSS A MESH, AND JOINING DOES NOT MERGE THE TWO ROWS. Every
# installer on every path seeds its own admin/admin row into its own database, so before the
# join there are N rows for one username, each written independently, and the join does not
# merge them on its own (see KEEP below). The symptom is that the console accepts the password
# on one data center and answers 401 on another while the databases are otherwise in step,
# which reads as a replication fault rather than an account one.
#
# This is the tool that triggers it, so this is where it gets said. It is a WARNING and not a
# refusal: the join is not wrong, one row is about to be chosen (KEEP below), and where more
# than one data center had set a password, the next sign-in asks for a new one.
#
# The fingerprint is the first 8 characters of an md5 of the stored PBKDF2 hash. It exists to
# answer "is this the same row?" and nothing else - it is never compared against a password,
# and a short digest of an already-hashed value is not a credential. It is what lets step 7
# say which data center's password each data center now holds.
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
            say "  These are separate rows for one account. The join keeps the password of the"
            say "  first of them given on this command line, everywhere, and the next sign-in on"
            say "  any data center asks for a new one."
        elif [ "$nset" = 1 ]; then
            say "note: '$u' has a password set only in data center $setdc; the others still hold"
            say "  the seeded row. That row is the one the mesh keeps."
        fi
    done
fi
# Which data center's row each of those accounts keeps, one
# "<username>|<data center>|<how many had a password set>" line each: the first data center
# (in the order given) that has a password set, or failing that the first data center. Step 4
# makes that row the newest, so the join keeps it everywhere.
#
# ⚠️ WITHOUT A CHOICE, NEITHER ROW WINS. Both rows were written before the mesh existed, and
# only the mesh installs the triggers that stamp `updated`, so both carry 0. Last-writer-wins
# on a tie keeps the local row, so each data center kept its own: two passwords for one
# account, each accepted on one side only, for good.
KEEP=$( { printf '%s\n' "$SHARED" | sed 's/^/S|/'; printf '%s\n' "$ACCTS" | sed 's/^/A|/'; } | awk -F'|' '
    $1 == "S" && $2 != "" { want[$2] = 1; nset[$2] = $3; next }
    $1 == "A" && ($3 in want) {
        if (!($3 in keep) || (!($3 in isset) && $4 == "0")) {
            keep[$3] = $2
            if ($4 == "0") isset[$3] = 1
        }
    }
    END { for (u in keep) print u "|" keep[u] "|" nset[u] }' | sort)

# The topology as server $1 must see it: every data center's line, with sslrootcert= naming
# the anchor path on THAT server.
topology_for() {
    _a=$1
    for j in $(upto $N); do
        eval "_id=\$ID_$j _b=\$BIND_$j _ports=\$PORTS_$j _pw=\$PW_$j _dns=\$DNS_$j"
        _n=$(printf '%s' "$_b" | tr ',' '\n' | grep -c .)
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

# ── 4a. one row for each account the data centers hold differently ────────────────────
# The chosen row is given a real `updated` on its own data center, so every other data center
# replaces its row with it when pass 2 copies. --triggers first: it adds the column and the
# trigger that stamps it, which pass 2 would otherwise add only later. The username goes to
# SQL as hex, so no character in it can end the string.
#
# ⚠️ AND WHERE MORE THAN ONE DATA CENTER HAD SET A PASSWORD, THE KEPT ROW MUST BE CHANGED AT
# THE NEXT SIGN-IN. Keeping one of them silently drops the others: whoever set a password on
# data center 2 finds it refused everywhere, with nothing saying why. Forcing the change makes
# the result the same every time — one password, chosen by the operator after the join — and
# the change replicates like any other.
if [ -n "$KEEP" ]; then
    printf '%s\n' "$KEEP" | while IFS='|' read -r u kdc nset; do
        [ -n "$u" ] || continue
        for i in $(upto $N); do eval "[ \"\$ID_$i\" = \"\$kdc\" ]" && break; done
        eval "p=\$P_$i"
        apply_on "$i" --triggers || die "data center $kdc: could not install the account triggers"
        uhex=$(printf '%s' "$u" | od -An -tx1 | tr -d ' \n')
        force=must_reset; [ "${nset:-0}" -ge 2 ] && force=1
        echo "update web_users set updated = (extract(epoch from clock_timestamp()) * 1000000)::bigint,
                                   must_reset = $force
                where auth_provider = 'local' and username = convert_from(decode('$uhex', 'hex'), 'UTF8')" \
            | na_sql "$p" >/dev/null || die "data center $kdc: could not mark the row for '$u'"
        say "'$u': keeping the row from data center $kdc"
    done
fi

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

# ── 7. which account row each data center now holds ───────────────────────────────────
#
# ⚠️ READ EVERY DATA CENTER, NOT ONE. This read data center 1 alone, found its own row there,
# and reported that row "in force everywhere" while data center 2 still held and accepted a
# different one. Each account's fingerprint is read from every data center, until they agree
# or a minute has passed, and matched against the fingerprints taken before pass 1.
if [ -n "$SHARED" ]; then
    n=0
    while :; do
        NOW=""
        for i in $(upto $N); do
            eval "id=\$ID_$i p=\$P_$i"
            _rows=$(printf '%s\n' "$LOCAL_ACCOUNTS_SQL" | na_sql "$p") || _rows=""
            [ -z "$_rows" ] || NOW="$NOW$(printf '%s\n' "$_rows" | sed "s/^/$id|/")
"
        done
        # usernames among the shared ones whose rows still differ between data centers
        DIFFER=$( { printf '%s\n' "$SHARED" | sed 's/^/S|/'; printf '%s\n' "$NOW" | sed 's/^/A|/'; } | awk -F'|' '
            $1 == "S" && $2 != "" { want[$2] = 1; next }
            $1 == "A" && ($3 in want) { if (!($3 in fp)) fp[$3] = $5; else if (fp[$3] != $5) d[$3] = 1 }
            END { for (u in d) print u }')
        [ -n "$DIFFER" ] || break
        n=$((n+1)); [ "$n" -lt 12 ] || break
        sleep 5
    done
    # The data center(s) whose row, before the join, had this fingerprint.
    origin() { printf '%s\n' "$ACCTS" | awk -F'|' -v u="$1" -v f="$2" '$2 == u && $4 == f {print $1}' | sort -u | tr '\n' ' ' | sed 's/ $//'; }
    printf '%s\n' "$SHARED" | while IFS='|' read -r u nset setdc; do
        [ -n "$u" ] || continue
        fps=$(printf '%s\n' "$NOW" | awk -F'|' -v u="$u" '$2 == u {print $1 "|" $4}')
        if printf '%s\n' "$DIFFER" | grep -qxF -- "$u"; then
            say "WARNING: '$u' is still a different row on different data centers:"
            printf '%s\n' "$fps" | while IFS='|' read -r dc f; do
                [ -n "$dc" ] || continue
                o=$(origin "$u" "$f")
                if [ -n "$o" ]; then say "  data center $dc accepts the password set on data center $o"
                else say "  data center $dc accepts a password changed since this command started"; fi
            done
            say "  Set it once, on any data center, and it replicates to all of them."
            say "  The command is fastpki-config web-user; docs/admin-guide.md §1.4 shows how to run it."
            continue
        fi
        # An account nobody has set a password on yet is still seeded everywhere and must be
        # changed at first sign-in, so which row it kept is not a fact anyone can act on.
        [ "$nset" -ge 1 ] || continue
        f=$(printf '%s\n' "$fps" | head -1 | cut -d'|' -f2)
        if [ -z "$f" ]; then
            say "'$u' is no longer in the mesh's accounts"
            continue
        fi
        o=$(origin "$u" "$f")
        if [ -z "$o" ]; then
            say "'$u': every data center holds the same row, with a password changed since this"
            say "  command started."
        elif [ "$nset" -ge 2 ]; then
            say "'$u': every data center now uses the password set on data center $o. You will"
            say "  be asked to choose a new one at your next sign-in, on any data center."
        else
            say "'$u': every data center now uses the password set on data center $o; it works"
            say "  on all of them."
        fi
    done
fi
