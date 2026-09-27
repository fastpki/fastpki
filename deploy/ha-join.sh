#!/bin/sh
# Join THIS host to an existing FastPKI deployment as its Postgres standby: compose, and a
# native or cloud host (see NATIVE AND CLOUD HOSTS below; deploy/ha-join-pair.sh
# runs both halves of a native join from the operator's machine).
#
# ⚠️ WHY THIS SCRIPT EXISTS AT ALL, because setting STANDBY_OF by hand looks like it
# should be enough and is not. certgen mints a SELF-SIGNED transport certificate on every
# host and copies it over /var/pki/tls/pg/ca.crt on every `up` — cert_good() compares the
# two byte-for-byte, and a joining host has no server.crt of its own, so it regenerates
# unconditionally. Seeding then dials the primary with sslmode=verify-full against that
# freshly-minted local anchor, which the primary was of course not issued by, and the node
# restart-loops on
#     pg_basebackup: error: connection to server at "<primary>", port 5432 failed:
#     SSL error: certificate verify failed
# The message names the primary, so it reads as a fault at the far end. It is not: the
# joining host simply has no way to know who the primary is.
#
# The anchor therefore has to arrive OUT OF BAND, at a path certgen never writes. That is
# /var/pki/tls/pg/primary-ca.crt, and putting it there is this script's whole job.
#
#   ./ha-join.sh <primary-address> [primary-ca.crt] [--primary-pin-file <path>]
#
# With no file, the served chain's top certificate is offered and its fingerprint printed
# for you to confirm against the primary — trust-on-first-use, made explicit rather than
# assumed. Pass the file whenever you can copy it across; it is the only form that does not
# ask you to compare a hash by eye.
set -eu

usage() {
    cat >&2 <<EOF
usage: $0 <primary-address> [path-to-primary-ca.crt]

  <primary-address>   host or IP of the primary's Postgres, as this host reaches it.
                      It must match a SAN in the primary's certificate: verify-full
                      checks the name, so the address you use here is not free choice.
                      On the primary, PG_TLS_SANS + \`fastpki-ca pg-tls\` put it there.

  [primary-ca.crt]    the primary's /var/pki/tls/pg/ca.crt, copied across. Omit to be
                      offered the certificate the primary serves, with its fingerprint.

  --primary-pin-file <path>
                      the primary's token PIN (its FASTPKI_PIN), needed only if the two
                      hosts were given different ones. This host replicates the CA keys
                      out of the primary's token, and the wrap happens inside THAT token,
                      so it logs in there. With a shared PIN, omit this.

Then bring the node up:  docker compose up -d

On a native or cloud host, as root:
  on the standby:  $0 <primary-address> <primary-ca.crt> --primary-password-file <f>
                       [--primary-pin-file <f>] [--replace-local-database]
  on the primary:  $0 --on-primary <standby-address> [--standby-pin-file <f>]
  or both at once, from the operator's machine:  deploy/ha-join-pair.sh
EOF
    exit 2
}

PRIMARY=""; ANCHOR=""; PRIMARY_PIN=""
PRIMARY_PW=""; ON_PRIMARY=""; STANDBY_PIN=""; REPLACE_DB=0
while [ $# -gt 0 ]; do
    case "$1" in
        --primary-pin-file) [ $# -ge 2 ] || usage; PRIMARY_PIN=$2; shift 2 ;;
        --primary-password-file) [ $# -ge 2 ] || usage; PRIMARY_PW=$2; shift 2 ;;
        --on-primary)       [ $# -ge 2 ] || usage; ON_PRIMARY=$2; shift 2 ;;
        --standby-pin-file) [ $# -ge 2 ] || usage; STANDBY_PIN=$2; shift 2 ;;
        --replace-local-database) REPLACE_DB=1; shift ;;
        -h|--help)          usage ;;
        -*)                 echo "$0: unknown option $1" >&2; usage ;;
        *)  if   [ -z "$PRIMARY" ]; then PRIMARY=$1
            elif [ -z "$ANCHOR" ];  then ANCHOR=$1
            else echo "$0: unexpected argument $1" >&2; usage
            fi
            shift ;;
    esac
done
# ══ NATIVE AND CLOUD HOSTS ═══════════════════════════════════════════════════════════
#
# A native host (install-native.sh, and every cloud node, which is one) has no compose
# file, no containers and no .env. The pair used to be built there by hand, from
# docs/high-availability.md section 4, and following it on a two-node AWS deployment
# produced four separate failures: a primary left on the wrong database password by a
# retyped PG_CONNINFO, a key tunnel "enabled" by editing a file the installer owns, a
# standby whose certificate sync had silently stopped with Postgres, and file edits that
# could not work as the login user. This does the same steps, in order, and checks each one.
#
#   on the standby:  ha-join.sh <primary-address> <primary-ca.crt> \
#                        --primary-password-file <f> [--primary-pin-file <f>]
#   on the primary:  ha-join.sh --on-primary <standby-address> [--standby-pin-file <f>]
#
# deploy/ha-join-pair.sh runs both from the operator's machine over SSH, carrying the
# primary's anchor, password and PIN across on stdin, so none of them is typed or copied.
N_CONF=/etc/fastpki/bootstrap.conf
N_ENV=/etc/conf.d/fastpki
N_TLS=/var/pki/tls/pg
N_PGTLS=/var/lib/postgresql/tls
N_STANDBY_CONF=/etc/fastpki/postgresql.conf.d/standby.conf

nsay() { echo "ha-join: $*"; }
ndie() { echo "ha-join: $*" >&2; exit 1; }

# SQL on this host's own database, as postgres over the local socket. Fed on stdin, so a
# statement's quotes never meet a shell's.
npq_local() { printf '%s\n' "$1" | su postgres -s /bin/sh -c 'psql -X -q -At -d fastpki' 2>/dev/null || true; }

# Every FastPKI service that reads PG_CONNINFO, as this host's runlevel lists them. The token,
# the certificate sync and the stale-connection sweep do not connect as fastpki.
nservices() {
    rc-update show default 2>/dev/null \
        | awk '$1 ~ /^fastpki-/ && $1 !~ /^fastpki-(token|pgtls|pgstale)$/ {print $1}'
}

# Rewrite this host's PG_CONNINFO in place. sed -i keeps the file's 0640 root:fastpki,
# and editing rather than retyping keeps every field this step does not mean to change.
nset_conninfo() {   # nset_conninfo <host-list> [<password> <anchor>]
    _h=$1; _pw=${2:-}; _a=${3:-}
    _e="s/host=[^ ]*/host=$_h/; s/port=[^ ]*/port=5432,5432/; s/ target_session_attrs=[^ ]*//; s/ connect_timeout=/ target_session_attrs=read-write connect_timeout=/"
    [ -n "$_pw" ] && _e="$_e; s/password=[^ ]*/password=$_pw/"
    [ -n "$_a" ]  && _e="$_e; s#sslrootcert=[^ ]*#sslrootcert=$_a#"
    sed -i "/^PG_CONNINFO=/{$_e}" "$N_CONF"
    grep -q "^PG_CONNINFO=host=$_h " "$N_CONF" || ndie "could not rewrite PG_CONNINFO in $N_CONF"
}

# ⚠️ ONE NAME FOR A STANDBY'S SLOT ON EVERY PATH: fastpki_ and the standby's own PG_BIND,
# lowercased, each character outside a-z and 0-9 as _, at most 63 characters (the Postgres
# limit). deploy/docker-compose.yml and deploy/k8s/start-postgres.sh derive it the same way,
# so a rebuilt standby reclaims its own slot and a second one never takes another's.
slot_for() { printf 'fastpki_%s' "$1" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9\n' '_' | cut -c1-63; }

nset_env() {   # nset_env KEY VALUE — in /etc/conf.d/fastpki, replaced or appended
    if grep -q "^$1=" "$N_ENV"; then sed -i "s|^$1=.*|$1=$2|" "$N_ENV"
    else printf '%s=%s\n' "$1" "$2" >> "$N_ENV"; fi
}

ninstall_pin() {   # ninstall_pin <file> — the OTHER host's token PIN, as this host's srcpin
    tr -d '\r\n' < "$1" > /var/pki/tls/srcpin.new
    chown fastpki:fastpki /var/pki/tls/srcpin.new; chmod 600 /var/pki/tls/srcpin.new
    mv -f /var/pki/tls/srcpin.new /var/pki/tls/srcpin
    nsay "installed the other host's token PIN as /var/pki/tls/srcpin"
}

nrestart_services() {
    for _s in $(nservices); do rc-service "$_s" restart >/dev/null 2>&1 || true; done
}

# Checked on both hosts, before anything is changed. Each is fixed only by the installer,
# so finding it after the database has been replaced means doing the join twice.
ncheck_host() {
    [ "$(id -u)" = 0 ] || ndie "run as root: doas $0 ..."
    [ -r "$N_CONF" ] && [ -r "$N_ENV" ] || ndie "no $N_CONF or $N_ENV: this is not a native FastPKI host"
    SELF=$(sed -n 's/^PG_BIND=//p' "$N_ENV" | head -1)
    case "$SELF" in
        ""|127.*|localhost|::1)
            ndie "PG_BIND is '${SELF:-unset}' in $N_ENV. A pair needs each host's own routable
  address there: Postgres listens on it and the host publishes its key-transport
  certificates under it. Re-run the installer with the right answer." ;;
    esac
    grep -q '^P11_TLS=on$' "$N_ENV" && rc-service fastpki-p11-tls status >/dev/null 2>&1 \
        || ndie "the key tunnel is not running here (P11_TLS=on and fastpki-p11-tls started).
  Without it the CA keys cannot be copied to the standby, and a promoted standby cannot
  issue anything. Adding P11_TLS=on to $N_ENV by hand is not enough: the installer creates
  the tunnel's certificate in the token and enables the service. Re-run the installer with
  P11_TLS=on. On AWS, list the data center in standby_dcs."
}

native_standby() {
    ncheck_host
    [ -n "$ANCHOR" ] && [ -f "$ANCHOR" ] || ndie "name the primary's anchor: its $N_TLS/ca.crt, copied to this host"
    [ -n "$PRIMARY_PW" ] && [ -f "$PRIMARY_PW" ] || ndie "--primary-password-file <f> is required: the primary's database password, from its $N_CONF"
    openssl x509 -in "$ANCHOR" -noout >/dev/null 2>&1 || ndie "$ANCHOR is not a PEM certificate"
    PW=$(tr -d '\r\n' < "$PRIMARY_PW")
    case "$PW" in *[!A-Za-z0-9]*|"") ndie "the password in $PRIMARY_PW is empty or not the installer's letters-and-digits form" ;; esac

    # ── the anchor verifies the primary, by the address used here ─────────────────────
    _vf=$(mktemp)
    case "$PRIMARY" in *[a-zA-Z]*) _vn="-verify_hostname $PRIMARY" ;; *) _vn="-verify_ip $PRIMARY" ;; esac
    if ! openssl s_client -connect "$PRIMARY:5432" -starttls postgres -CAfile "$ANCHOR" \
            -verify_return_error $_vn </dev/null >"$_vf" 2>&1; then
        grep -qE "connect:errno|Connection refused|no route|timed out" "$_vf" \
            && ndie "nothing answered at $PRIMARY:5432 — check the address, and that the primary's PG_BIND is it"
        ndie "the anchor does not verify $PRIMARY: $(grep -m1 -E 'verify error|Verify return code' "$_vf")"
    fi
    rm -f "$_vf"
    install -m 0644 -o fastpki -g fastpki "$ANCHOR" "$N_TLS/primary-ca.crt"
    /usr/libexec/fastpki/pg-tls-sync once >/dev/null 2>&1 || true
    [ -r "$N_PGTLS/primary-ca.crt" ] || ndie "pg-tls-sync did not place $N_PGTLS/primary-ca.crt"
    nsay "installed the primary's anchor; it verifies $PRIMARY"

    CONN="host=$PRIMARY port=5432 dbname=fastpki user=fastpki sslmode=verify-full sslrootcert=$N_PGTLS/primary-ca.crt connect_timeout=5"
    npq_primary() { printf '%s\n' "$1" | PGPASSWORD="$PW" su postgres -s /bin/sh -c "psql -X -q -At '$CONN'" 2>&1 || true; }
    _one=$(npq_primary 'select 1')
    [ "$_one" = 1 ] || ndie "cannot log in to the primary as fastpki: $_one"

    # ── one data center twice ─────────────────────────────────────────────────────────
    _dc=$(sed -n 's/^DATACENTER_ID=//p' "$N_CONF" | head -1)
    _rows=$(npq_primary 'select dc_id from datacenters order by dc_id')
    if [ -n "$_rows" ] && ! printf '%s\n' "$_rows" | grep -Fqx "${_dc:-}"; then
        ndie "DATACENTER_ID=${_dc:-unset} here, but the primary's data centers are: $(echo $_rows).
  A standby takes its primary's id: a pair is one data center twice."
    fi

    # ── this host's own database ──────────────────────────────────────────────────────
    ALREADY=0
    if [ "$(npq_local 'select pg_is_in_recovery()')" = t ]; then
        _pc=$(npq_local 'show primary_conninfo')
        case "$_pc" in
            *"host=$PRIMARY "*) ALREADY=1; nsay "already streaming from $PRIMARY; not copying the database again" ;;
            *) ndie "this host is already a standby of another primary: $(printf '%s' "$_pc" | sed 's/password=[^ ]*/password=.../')" ;;
        esac
    elif [ "$(npq_local 'select 1')" != 1 ]; then
        # ⚠️ NO ANSWER IS NOT "NO CA". A stopped Postgres answers nothing, which the count below
        # read as zero, so the database of a stopped host was replaced without the flag. It is
        # not started to ask either: the usual stopped host is a failed primary being rebuilt,
        # and started it is a second read-write primary its peers' subscriptions can reach.
        [ "$REPLACE_DB" = 1 ] || ndie "this host's Postgres is not running, so what its database holds
  cannot be checked. Joining replaces it with a copy of the primary's. If nothing on this host is
  needed (a failed primary being rebuilt as the standby of the host that took over), re-run with
  --replace-local-database."
    else
        _cas=$(npq_local 'select count(*) from certs where is_ca')
        if [ "${_cas:-0}" -gt 0 ] && [ "$REPLACE_DB" != 1 ]; then
            ndie "this host's own database holds $_cas CA certificate(s). Joining replaces it with a
  copy of the primary's. If nothing on this host is needed, re-run with --replace-local-database."
        fi
    fi

    if [ "$ALREADY" = 0 ]; then
        SLOT=$(slot_for "$SELF")
        case "$(npq_primary "select active from pg_replication_slots where slot_name = '$SLOT'")" in
            t) ndie "the primary already has a standby streaming on slot $SLOT" ;;
            f) npq_primary "select pg_drop_replication_slot('$SLOT')" >/dev/null
               nsay "dropped the primary's unused slot $SLOT, left by an earlier standby" ;;
        esac
        DATA=$(npq_local 'show data_directory')
        # A stopped Postgres cannot say where its data is: then it is the one data directory
        # the package made, /var/lib/postgresql/<major>/data, and only if there is exactly one.
        if [ -z "$DATA" ]; then
            _n=0
            for _d in /var/lib/postgresql/*/data; do [ -d "$_d" ] && { _n=$((_n+1)); DATA=$_d; }; done
            [ "$_n" = 1 ] || DATA=""
        fi
        case "$DATA" in /var/lib/postgresql/*/data) ;; *) ndie "unexpected data directory '$DATA'" ;; esac
        nsay "stopping this host's services and Postgres; replacing $DATA with a copy of $PRIMARY"
        for _s in $(nservices); do rc-service -s "$_s" stop >/dev/null 2>&1 || true; done
        # A host being rebuilt usually has it stopped already, and OpenRC then warns
        # "already stopped" and succeeds; only a real failure to stop matters here.
        rc-service postgresql stop >/dev/null 2>&1 || ndie "could not stop Postgres; nothing was removed"
        rm -rf "$DATA"
        install -d -m 0700 -o postgres -g postgres "$DATA"
        # -R writes primary_conninfo from this conninfo, password and dbname included, and
        # the slot name; dbname is what the slot-sync worker needs.
        # Alpine links pg_hba.conf, postgresql.conf and pg_ident.conf into the data directory
        # from /etc/postgresql, and pg_basebackup warns "skipping special file" for each. Each
        # host keeps its own settings there, so skipping them is right, and the warning is
        # not something to act on.
        _bb=$(mktemp)
        if ! PGPASSWORD="$PW" su postgres -s /bin/sh -c \
                "pg_basebackup -D '$DATA' -R -X stream -c fast -C -S $SLOT -d '$CONN'" 2>"$_bb"; then
            grep -v 'skipping special file' "$_bb" >&2 || true; rm -f "$_bb"
            ndie "pg_basebackup failed; this host's Postgres is stopped with an empty data directory"
        fi
        grep -v 'skipping special file' "$_bb" >&2 || true; rm -f "$_bb"
        printf '# Written by ha-join.sh: this host is a streaming standby.\nsync_replication_slots = on\nhot_standby_feedback = on\n' > "$N_STANDBY_CONF"
        chown root:postgres "$N_STANDBY_CONF"; chmod 640 "$N_STANDBY_CONF"
        rc-service postgresql start >/dev/null
        _i=0; until [ "$(npq_local 'select pg_is_in_recovery()')" = t ]; do
            _i=$((_i+1)); [ "$_i" -le 30 ] || ndie "Postgres did not come back as a standby; see /var/log/postgresql/postmaster.log"
            sleep 1
        done
        nsay "streaming from $PRIMARY"
    fi
    # fastpki-pgtls depends on postgresql, so stopping Postgres stopped it, and starting
    # Postgres does not bring it back. It is what hands Postgres a new certificate.
    rc-service fastpki-pgtls start >/dev/null 2>&1 || true

    # ── services: the primary first, its password, its anchor ─────────────────────────
    # Which host first. libpq stops at the first host whose certificate it cannot verify and
    # never tries the next, so this host goes first only once its OWN database certificate
    # verifies against the pair's CA — its self-signed one never does. Until then the primary
    # is first; a re-run after the pair CA has issued this host's certificate turns it round,
    # so a primary being rebuilt cannot take this host's services down with it.
    # The certificate Postgres SERVES, not the file: a new certificate is written first and
    # taken up to 30 seconds later, and the services would dial the old one meanwhile.
    if openssl s_client -connect 127.0.0.1:5432 -starttls postgres -CAfile "$N_TLS/primary-ca.crt" \
            -verify_return_error </dev/null >/dev/null 2>&1; then
        HOSTS="$SELF,$PRIMARY"
    else
        HOSTS="$PRIMARY,$SELF"
    fi
    nset_conninfo "$HOSTS" "$PW" "$N_TLS/primary-ca.crt"
    nset_env STANDBY_OF "$PRIMARY"
    [ -n "$PRIMARY_PIN" ] && ninstall_pin "$PRIMARY_PIN"
    nrestart_services
    su -s /bin/sh fastpki -c "fastpki-config --config $N_CONF list" >/dev/null 2>&1 \
        || ndie "the services here cannot reach the database with the new PG_CONNINFO"
    nsay "services restarted, reaching the database at $HOSTS in that order; STANDBY_OF=$PRIMARY"
    [ -n "${FASTPKI_JOIN_BY_PAIR:-}" ] || cat <<EOF

Next, on the primary:   doas $0 --on-primary $SELF [--standby-pin-file <this host's PIN>]
Then copy the keys, on this host and then the primary, until it says "this node holds every
key it needs to serve":   doas /etc/periodic/daily/fastpki-certrenew
EOF
}

native_primary() {
    ncheck_host
    STANDBY=$ON_PRIMARY
    nset_conninfo "$SELF,$STANDBY"
    [ -n "$STANDBY_PIN" ] && ninstall_pin "$STANDBY_PIN"
    nrestart_services
    nsay "services restarted: this host first, then $STANDBY"

    # A peer data center must not receive a change the standby has not, or a promotion
    # loses it for good. Only once the standby's slot exists: naming an absent slot makes
    # every logical walsender wait forever.
    SLOT=$(slot_for "$STANDBY")
    if [ "$(npq_local "select count(*) from pg_replication_slots where slot_name = '$SLOT'")" = 1 ]; then
        if [ "$(npq_local "select count(*) from pg_replication_slots where slot_type = 'logical'")" -gt 0 ]; then
            npq_local "ALTER SYSTEM SET synchronized_standby_slots = '$SLOT'" >/dev/null
            npq_local 'select pg_reload_conf()' >/dev/null
            nsay "peer data centers now wait for the standby: synchronized_standby_slots = $SLOT"
        fi
    else
        nsay "WARNING: no slot $SLOT yet — run this again after the standby has joined"
    fi

    # The CA that issues the database certificates. The standby needs one from the pair's
    # CA, and the nightly job issues it only when this is set.
    # The CA that issued this host's current certificate, or else the data center's one
    # issuing CA — the same choice deploy/mesh-join.sh makes. Then this host's own
    # certificate from it, which the standby's services verify it with.
    if [ -z "$(npq_local "select value from config where key = 'PG_TLS_CA_ID'")" ]; then
        _list=$(su -s /bin/sh fastpki -c "fastpki-ca --config $N_CONF list" 2>/dev/null)
        _iss=$(openssl x509 -in "$N_TLS/server.crt" -noout -issuer 2>/dev/null | sed -n 's/^issuer= *CN *= *//p')
        _id=$(printf '%s\n' "$_list" | awk -F'\t' -v s="$_iss" '$4 == s {print $1; exit}')
        [ -n "$_id" ] || _id=$(printf '%s\n' "$_list" \
            | awk -F'\t' '$2 == "active" && $3 == "intermediate" && $5 ~ /ca_key=pkcs11:/ {n++; id=$1} END {if (n == 1) print id}')
        if [ -n "$_id" ]; then
            su -s /bin/sh fastpki -c "fastpki-config --config $N_CONF set PG_TLS_CA_ID $_id" >/dev/null
            nsay "PG_TLS_CA_ID=$_id: it issues both hosts' database certificates"
        else
            nsay "WARNING: PG_TLS_CA_ID is not set, and this data center has no single issuing CA
  to use. Set it to the CA that should issue both hosts' database certificates:
    doas su -s /bin/sh fastpki -c 'fastpki-config --config $N_CONF set PG_TLS_CA_ID <ca-id>'"
        fi
    fi
    su -s /bin/sh fastpki -c "fastpki-ca --config $N_CONF pg-tls --if-needed" 2>&1 | sed -n 's/^/ha-join: /;/serial:/p;/already/p' || true
    [ -n "${FASTPKI_JOIN_BY_PAIR:-}" ] || cat <<EOF

Now copy the keys, on the standby and then here, until it says "this node holds every key it
needs to serve":   doas /etc/periodic/daily/fastpki-certrenew
EOF
}

# ── WHICH DEPLOYMENT IS THIS ──────────────────────────────────────────────────────────
# Detected the way deploy/pg-promote.sh detects it: a compose file beside the script is the
# packaged path; /etc/fastpki/bootstrap.conf with OpenRC is a native or cloud host, where
# this script is installed as /usr/share/fastpki/ha-join.sh. FASTPKI_JOIN_MODE overrides.
MODE="${FASTPKI_JOIN_MODE:-}"
if [ -z "$MODE" ]; then
    if [ -f "$(dirname "$0")/docker-compose.yml" ]; then MODE=compose
    elif [ -f /etc/fastpki/bootstrap.conf ] && command -v rc-service >/dev/null 2>&1; then MODE=native
    else MODE=compose; fi
fi
if [ "$MODE" = native ]; then
    if [ -n "$ON_PRIMARY" ]; then native_primary; else [ -n "$PRIMARY" ] || usage; native_standby; fi
    exit 0
fi
# ══ COMPOSE ══════════════════════════════════════════════════════════════════════════
# The same two halves as native, with the same checks and the same result: both hosts
# installed the same way (install.sh with HA_ENABLED=yes), then the standby's database
# replaced by a copy of the primary's.
cd "$(dirname "$0")"
[ -f docker-compose.yml ] || { echo "$0: no docker-compose.yml beside this script" >&2; exit 1; }
envv() { sed -n "s/^$1=//p" .env 2>/dev/null | head -1; }
set_env() {   # set_env KEY VALUE — in .env, replaced or appended
    touch .env
    if grep -q "^$1=" .env; then sed -i.bak "s|^$1=.*|$1=$2|" .env && rm -f .env.bak
    else printf '%s=%s\n' "$1" "$2" >> .env; fi
}
# ⚠️ ASK COMPOSE FOR THE PROJECT NAME, DO NOT GUESS. docker-compose.yml sets `name: fastpki`,
# which outranks the directory basename, so deriving it from $PWD picks the wrong volumes —
# and the wrong volume means writing into a DIFFERENT deployment on the same host.
PROJ=$(docker compose config 2>/dev/null | sed -n "s/^name: *//p" | head -1)
[ -n "${PROJ:-}" ] || { echo "$0: cannot determine the compose project name" >&2; exit 1; }
cpq() { docker compose exec -T postgres psql -X -q -At -U fastpki -d fastpki -c "$1" 2>/dev/null || true; }

# Both hosts, before anything changes: installed for a pair. The same check as native's.
compose_check_host() {
    SELF=$(envv PG_BIND)
    case "$SELF" in
        ""|127.*|localhost|::1)
            echo "$0: PG_BIND is '${SELF:-unset}' in .env. A pair needs each host's own routable address" >&2
            echo "  there: Postgres is published on it and the host publishes its key-transport" >&2
            echo "  certificates under it. Re-run ./install.sh with the right answer." >&2
            exit 1 ;;
    esac
    if [ "$(envv P11_TLS)" != on ] || [ "$(envv SERVICE_KEYS_REPLICABLE)" != true ] \
       || ! printf ',%s,' "$(envv COMPOSE_PROFILES)" | grep -q ',p11tls,'; then
        echo "$0: this host was not installed for a pair. Its .env needs P11_TLS=on," >&2
        echo "  SERVICE_KEYS_REPLICABLE=true and p11tls in COMPOSE_PROFILES: without them the CA" >&2
        echo "  keys cannot reach the standby, and a promoted standby cannot issue anything." >&2
        echo "  Re-run ./install.sh with HA_ENABLED=yes (it writes all three) before any CA exists." >&2
        exit 1
    fi
}

compose_install_pin() {   # compose_install_pin <file> — the OTHER host's PIN as srcpin
    _pin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")   # docker run -v needs an absolute path
    docker compose --progress quiet run --rm --no-deps --user 0:0 --entrypoint sh \
        -v "$_pin":/in/srcpin:ro certgen -ec '
            mkdir -p /var/pki/tls
            tr -d "\r\n" < /in/srcpin > /var/pki/tls/srcpin
            chown fastpki:fastpki /var/pki/tls/srcpin 2>/dev/null || true
            chmod 600 /var/pki/tls/srcpin
        ' >/dev/null
    echo "Installed the other host's token PIN at /var/pki/tls/srcpin (0600)."
}

# The services' PG_CONNINFO names both hosts. Written by this script and rewritten by it on
# a re-run; an override somebody wrote by hand is left alone and named.
compose_write_override() {   # compose_write_override <host-list> <password> <anchor>
    if [ -e docker-compose.override.yml ] && ! head -1 docker-compose.override.yml | grep -q 'Written by ha-join.sh'; then
        echo "$0: docker-compose.override.yml exists and was not written by this script; leaving it" >&2
        echo "  alone. Its PG_CONNINFO must name $1, with sslrootcert=$3." >&2
        return 0
    fi
    _conn="host=$1 port=5432,5432 dbname=fastpki user=fastpki password=$2 sslmode=verify-full sslrootcert=$3 target_session_attrs=read-write connect_timeout=5"
    { echo "# Written by ha-join.sh. Every service that reaches the database, not only the"
      echo "# protocol listeners — a service left out keeps pointing at one host only."
      echo "services:"
      for _s in web est acme cmp ms scep ocsp store certrenew p11-tls; do
          printf '  %s:\n    environment:\n      PG_CONNINFO: "%s"\n' "$_s" "$_conn"
      done
    } > docker-compose.override.yml
    chmod 600 docker-compose.override.yml
    echo "Wrote docker-compose.override.yml: PG_CONNINFO names $1."
}

compose_primary() {
    compose_check_host
    compose_write_override "$SELF,$ON_PRIMARY" "$(envv POSTGRES_PASSWORD)" /var/pki/tls/pg/ca.crt
    [ -z "$STANDBY_PIN" ] || compose_install_pin "$STANDBY_PIN"
    # The CA that issues the database certificates: the standby needs one from the pair's
    # CA, and the renewal job issues it only when this is set.
    # The CA that issued this host's current certificate, or else the data center's one
    # issuing CA — the same choice as native's half and deploy/mesh-join.sh. Then this host's
    # own certificate from it.
    if [ -z "$(cpq "select value from config where key = 'PG_TLS_CA_ID'")" ]; then
        _list=$(docker compose exec -T web fastpki-ca --config /app/config/bootstrap.conf list 2>/dev/null)
        _iss=$(docker compose exec -T postgres cat /pki/tls/pg/server.crt 2>/dev/null \
                 | openssl x509 -noout -issuer 2>/dev/null | sed -n 's/^issuer= *CN *= *//p')
        _id=$(printf '%s\n' "$_list" | awk -F'\t' -v s="$_iss" '$4 == s {print $1; exit}')
        [ -n "$_id" ] || _id=$(printf '%s\n' "$_list" \
            | awk -F'\t' '$2 == "active" && $3 == "intermediate" && $5 ~ /ca_key=pkcs11:/ {n++; id=$1} END {if (n == 1) print id}')
        if [ -n "$_id" ]; then
            docker compose exec -T web fastpki-config --config /app/config/bootstrap.conf set PG_TLS_CA_ID "$_id" >/dev/null
            echo "PG_TLS_CA_ID=$_id: it issues both hosts' database certificates."
        else
            echo "WARNING: PG_TLS_CA_ID is not set, and this data center has no single issuing CA to"
            echo "  use. Set it to the CA that should issue both hosts' database certificates:"
            echo "    docker compose exec web fastpki-config --config /app/config/bootstrap.conf set PG_TLS_CA_ID <ca-id>"
        fi
    fi
    docker compose exec -T web fastpki-ca --config /app/config/bootstrap.conf pg-tls --if-needed 2>&1 \
        | sed -n '/serial:/p;/already/p' || true
    docker compose up -d >/dev/null 2>&1
    echo "Services restarted: this host first, then $ON_PRIMARY."
    [ -n "${FASTPKI_JOIN_BY_PAIR:-}" ] || cat <<EOF

Now copy the keys, on the standby and then here, until it says "this node holds every key it
needs to serve":
    docker compose exec certrenew fastpki-ca --config /app/config/bootstrap.conf key sync --from-peers
EOF
}

if [ -n "$ON_PRIMARY" ]; then compose_primary; exit 0; fi
[ -n "$PRIMARY" ] || usage
[ -z "$PRIMARY_PIN" ] || [ -f "$PRIMARY_PIN" ] || { echo "$0: no such file: $PRIMARY_PIN" >&2; exit 1; }
compose_check_host

# The primary's database password. Joining makes this host's database a copy of the
# primary's, so the password its own install generated stops existing.
if [ -n "$PRIMARY_PW" ]; then
    [ -f "$PRIMARY_PW" ] || { echo "$0: no such file: $PRIMARY_PW" >&2; exit 1; }
    set_env POSTGRES_PASSWORD "$(tr -d '\r\n' < "$PRIMARY_PW")"
fi

# ── This host's own database ──────────────────────────────────────────────────────────
# The same rule as native: a standby already streaming from this primary is left as it is;
# a database holding a CA is replaced only when asked, because joining replaces it with a
# copy of the primary's.
ALREADY=0; NEED_WIPE=0
VOL=$(docker volume ls -q -f "name=^${PROJ}_pgdata$" | head -1 || true)
if [ -n "$VOL" ]; then
    if [ "$(cpq 'select pg_is_in_recovery()')" = t ]; then
        case "$(cpq 'show primary_conninfo')" in
            *"host=$PRIMARY "*) ALREADY=1; echo "Already streaming from $PRIMARY; not copying the database again." ;;
            *) echo "$0: this host is already a standby of another primary." >&2; exit 1 ;;
        esac
    elif [ "$(cpq 'select 1')" != 1 ]; then
        # No answer is not "no CA": the same rule as native, for the same reason.
        if [ "$REPLACE_DB" != 1 ]; then
            echo "$0: this host's Postgres is not running, so what its database holds cannot be" >&2
            echo "  checked. Joining replaces it with a copy of the primary's. If nothing on this host" >&2
            echo "  is needed (a failed primary being rebuilt as the standby of the host that took" >&2
            echo "  over), re-run with --replace-local-database." >&2
            exit 1
        fi
        NEED_WIPE=1
    else
        _cas=$(cpq 'select count(*) from certs where is_ca')
        if [ "${_cas:-0}" -gt 0 ] && [ "$REPLACE_DB" != 1 ]; then
            echo "$0: this host's own database holds $_cas CA certificate(s). Joining replaces it with" >&2
            echo "  a copy of the primary's. If nothing on this host is needed, re-run with" >&2
            echo "  --replace-local-database." >&2
            exit 1
        fi
        NEED_WIPE=1
    fi
fi

# ── Obtain the anchor ──────────────────────────────────────────────────────────────────
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT INT TERM

if [ -n "$ANCHOR" ]; then
    [ -f "$ANCHOR" ] || { echo "$0: no such file: $ANCHOR" >&2; exit 1; }
    cp "$ANCHOR" "$TMP/primary-ca.crt"
else
    echo "Fetching the certificate $PRIMARY serves on 5432..."
    # -starttls postgres speaks the SSLRequest handshake; without it the server closes.
    if ! openssl s_client -connect "$PRIMARY:5432" -starttls postgres -showcerts \
            </dev/null 2>/dev/null | awk '/BEGIN CERT/,/END CERT/' > "$TMP/chain.pem" \
       || ! [ -s "$TMP/chain.pem" ]; then
        echo "$0: could not read a certificate from $PRIMARY:5432." >&2
        echo "$0: check the address and that PG_BIND on the primary is not loopback." >&2
        exit 1
    fi
    # The LAST certificate in the chain is the one to anchor on: a self-signed primary
    # serves exactly one (itself), a CA-issued one serves leaf-then-issuers.
    awk '/BEGIN CERT/{n++} {print > "'"$TMP"'/c" n ".pem"}' "$TMP/chain.pem"
    LAST=$(ls "$TMP"/c*.pem | sort -V | tail -1)
    cp "$LAST" "$TMP/primary-ca.crt"
    echo
    echo "  subject:     $(openssl x509 -in "$TMP/primary-ca.crt" -noout -subject | sed 's/^subject=//')"
    echo "  issuer:      $(openssl x509 -in "$TMP/primary-ca.crt" -noout -issuer  | sed 's/^issuer=//')"
    echo "  SHA256:      $(openssl x509 -in "$TMP/primary-ca.crt" -noout -fingerprint -sha256 | sed 's/.*=//')"
    echo
    echo "⚠️  Nothing has verified this — it is whatever answered on $PRIMARY:5432. Compare the"
    echo "    fingerprint against the primary before continuing:"
    echo "      openssl x509 -in /var/pki/tls/pg/ca.crt -noout -fingerprint -sha256"
    printf "Accept this certificate as the anchor? [y/N] "
    read -r reply
    case "$reply" in [yY]*) ;; *) echo "aborted."; exit 1 ;; esac
fi

openssl x509 -in "$TMP/primary-ca.crt" -noout >/dev/null 2>&1 \
    || { echo "$0: that is not a PEM certificate." >&2; exit 1; }

# ── Prove it actually verifies the primary, BEFORE anything is brought up ──────────────
# ⚠️ TWO SEPARATE THINGS HAVE TO HOLD, and a failed seed reports neither. The anchor must
# chain to the primary's certificate, AND that certificate must carry a SAN for the exact
# address used here, because seeding uses sslmode=verify-full. The second one is easy to
# miss: certgen's self-signed cert covers only the compose-internal names (postgres,
# localhost, 127.0.0.1), so a primary that has NOT yet been given a
# CA-issued transport cert cannot be joined by address at all. `fastpki-ca pg-tls` with
# PG_TLS_SANS is what puts the routable address in, and install.sh runs it whenever PG_BIND
# is not loopback. Checking here turns a restart loop into one sentence.
case "$PRIMARY" in
    *[a-zA-Z]*) VERIFY_NAME="-verify_hostname $PRIMARY" ;;
    *)          VERIFY_NAME="-verify_ip $PRIMARY" ;;
esac
if ! openssl s_client -connect "$PRIMARY:5432" -starttls postgres \
        -CAfile "$TMP/primary-ca.crt" -verify_return_error $VERIFY_NAME \
        </dev/null >"$TMP/verify.out" 2>&1; then
    # ⚠️ "could not verify" and "could not connect" are different problems with different
    # fixes, and s_client fails the same way for both. Saying the wrong one sends the
    # operator to look at certificates when the address or PG_BIND is what is wrong.
    if grep -qE "connect:errno|Connection refused|no route|timed out|socket" "$TMP/verify.out"; then
        echo "$0: nothing answered at $PRIMARY:5432." >&2
        echo "$0: check the address, and that PG_BIND on the primary is a routable one" >&2
        echo "$0: rather than 127.0.0.1 — a loopback-bound primary cannot be joined." >&2
        exit 1
    fi
    echo "$0: this anchor does NOT verify $PRIMARY, so seeding would fail. openssl says:" >&2
    sed -n 's/^\(verify error\|.*alert\|.*Verify return code\)/  &/p' "$TMP/verify.out" | head -4 >&2
    grep -q "Hostname mismatch\|IP address mismatch" "$TMP/verify.out" && cat >&2 <<EOF

  The chain is fine; the ADDRESS is not in the certificate. Fix it ON THE PRIMARY: PG_BIND in
  its deploy/.env has to be the address this standby dials ($PRIMARY) rather than loopback.
  pg-tls reads PG_BIND from that host's environment, so there is no config key to set, and
  each host then certifies its OWN address. Re-issue, naming the CA:

      docker compose exec web fastpki-ca pg-tls <ca-id>

  Postgres adopts the new pair within ~30s; no restart is needed. Then re-run this script.
  verify-full checks the name, so it has to be the same address.

  Do NOT put an interconnect address in PG_TLS_SANS on a pair. Its two hosts replicate the
  whole database, so they read ONE config table and ONE PG_TLS_SANS row: the standby would
  later be issued a certificate naming the PRIMARY's address instead of its own, and that
  fails verify-full at the moment of promotion, against a database that is up.
EOF
    exit 1
fi
echo "Verified: this anchor validates $PRIMARY and the certificate covers that address."

# ── Refuse a host still holding a PREVIOUS deployment's TLS material ───────────────────
# ⚠️ TWO VOLUMES MATTER ON A REUSED HOST, AND THE GUARD ABOVE NAMES ONLY ONE. `pgdata`
# holds the database; `pki-data` holds the CA material and the Postgres certificate. An
# operator told "remove it first" removes the data directory, re-runs this, and it passes
# — while pki-data still carries the root the old deployment made and the server.crt
# issued under it. Nothing replaces that certificate afterwards, because Postgres is the
# one credential that cannot adopt a CA-issued one by itself (libpq needs a key FILE and
# cannot reference the token). So the node joins, streams perfectly, and serves a
# certificate signed by a root that no longer exists anywhere in this deployment.
#
# It surfaces only at promotion, as `certificate verify failed` from every application at
# once, against a database that is up and read-write — and the CLIs share that conninfo,
# so the deployment cannot be repaired with its own tools. Catch it here instead.
PKIVOL=$(docker volume ls -q -f "name=^${PROJ}_pki-data$" | head -1 || true)
if [ -n "${PKIVOL:-}" ]; then
    # ⚠️ IN THIS DEPLOYMENT'S certgen, AS ROOT, AND ONLY A CLEAR ANSWER PASSES. It ran a bare
    # `docker run` of fastpki:local as the image's own user, which went wrong both ways on a
    # lab pair: that user could not read the anchor (0600, the login user's), so a host whose
    # certificate verified was refused as stale; and on a host with no image of that name the
    # container never started, the output was empty, and empty meant "nothing stale".
    _chk=$(docker compose --progress quiet run --rm --no-deps --user 0:0 \
             -v "$TMP/primary-ca.crt":/in/ca.crt:ro --entrypoint sh certgen -c '
        c=/var/pki/tls/pg/server.crt
        [ -f "$c" ] || { echo none; exit 0; }
        # Its own self-signed certificate, from its own install, is not a previous
        # deployment: the pair CA issues it a proper one after the join.
        [ "$(openssl x509 -in "$c" -noout -subject | sed "s/^subject=//")" != \
          "$(openssl x509 -in "$c" -noout -issuer  | sed "s/^issuer=//")" ] || { echo own; exit 0; }
        openssl verify -CAfile /in/ca.crt -untrusted "$c" "$c" >/dev/null 2>&1 && { echo ok; exit 0; }
        echo "stale:$(openssl x509 -in "$c" -noout -issuer | sed "s/^issuer=//")"
    ' 2>/dev/null | tr -d '\r')
    case "$_chk" in
        none|own|ok) STALE="" ;;
        stale:*)     STALE=${_chk#stale:} ;;
        *) echo "$0: could not check this host's TLS material ($PKIVOL): the certgen service did not run." >&2
           echo "  Run it to see why: docker compose run --rm --no-deps certgen true" >&2
           exit 1 ;;
    esac
    if [ -n "${STALE:-}" ]; then
        echo "$0: this host still holds a previous deployment's TLS material ($PKIVOL)." >&2
        echo "$0: its Postgres certificate is issued by" >&2
        echo "$0:     $STALE" >&2
        echo "$0: which $PRIMARY's anchor cannot verify. Joining would leave this node" >&2
        echo "$0: serving a certificate under a root this deployment does not have — and" >&2
        echo "$0: nothing re-issues it, so it would surface only when you promote here," >&2
        echo "$0: as 'certificate verify failed' from every application at once." >&2
        echo "$0:" >&2
        echo "$0: A reused host needs BOTH volumes cleared, not just the data directory:" >&2
        echo "$0:     docker volume rm ${PROJ}_pgdata $PKIVOL" >&2
        echo "$0: Be certain neither holds a CA key you still need." >&2
        exit 1
    fi
fi

# ── Install it where certgen will not overwrite it ─────────────────────────────────────
# certgen writes server.crt, server.key and ca.crt only; primary-ca.crt is untouched by it
# and by the console, which is the entire reason for the separate name.
docker compose --progress quiet run --rm --no-deps --user 0:0 --entrypoint sh \
    -v "$TMP/primary-ca.crt":/in/primary-ca.crt:ro certgen -ec '
        mkdir -p /var/pki/tls/pg
        cp /in/primary-ca.crt /var/pki/tls/pg/primary-ca.crt
        chmod 644 /var/pki/tls/pg/primary-ca.crt
    ' >/dev/null
echo "Installed the primary's anchor at /var/pki/tls/pg/primary-ca.crt."

# ── The primary's token PIN, when the two hosts do not share one ───────────────────────
# This host replicates the CA keys out of the primary's token, and the wrap happens INSIDE
# that token, so it logs in there. Each installer generates its node's FASTPKI_PIN
# independently, so the two need not match — and when they do not, nothing else on this
# host knows the primary's. Placed here for the same reason as the anchor: out of band,
# once, at the only moment an operator has both hosts in front of them.
[ -z "$PRIMARY_PIN" ] || compose_install_pin "$PRIMARY_PIN"

# ── DATACENTER_ID: a pair is ONE data center twice ─────────────────────────────────────
#
# ⚠️ NOTHING ELSE ENFORCES THIS, AND EVERY WAY OF GETTING IT WRONG IS QUIET UNTIL A
# PROMOTION. DATACENTER_ID is the high 15 bits of every serial this node mints and the key
# into `datacenters`. Three mistakes are possible at exactly this moment:
#
#   unset            set_random_serial() mints FULL-WIDTH serials with no prefix, so from
#                    the moment this host is promoted everything it issues sits outside the
#                    data center's partition. Permanently — a serial cannot be changed after
#                    issuance — and silently: the certificates are valid and enrolment
#                    succeeds. It surfaces on a local restore, which certs_dc_range refuses
#                    for a prefix-less row, and on any later expansion into a mesh.
#   no matching row  every issuing service refuses to start with "has no row in
#                    `datacenters`". `dc1` is the usual form: the lookup is
#                    WHERE dc_id=$1 against the literal value, and the installers write the
#                    bare index, so `dc1` parses fine and matches nothing.
#   another DC's id  this host mints into a different data center's serial range, and shares
#                    that data center's per-node ids rather than its primary's.
#
# The primary states its own id rather than the operator being asked to repeat it: every
# host publishes a p11_transport row under the dc_id it runs as. The anchor installed above
# is what makes reading it verifiable rather than trust-on-first-use.
_dcid=$(sed -n 's/^DATACENTER_ID=//p' .env 2>/dev/null | head -1)
_pgpw=$(sed -n 's/^POSTGRES_PASSWORD=//p' .env 2>/dev/null | head -1)

if [ -z "$_dcid" ]; then
    echo "$0: DATACENTER_ID is not set in .env." >&2
    echo "  A standby carries the SAME id as its primary — a pair is one data center twice." >&2
    echo "  Left unset, this host assigns full-width serials with no data center prefix from" >&2
    echo "  the moment it is promoted. That cannot be corrected afterwards: a serial is" >&2
    echo "  fixed at issuance, and nothing warns because the certificates are valid." >&2
    echo "  Set DATACENTER_ID to the primary's value in .env and re-run. See docs/high-availability.md." >&2
    exit 1
fi

# Ask the primary. Failure to reach it is NOT fatal here — the join itself has already
# proved the address and the anchor, and refusing on an unreadable table would block a
# legitimate join over a detail this script cannot always determine.
_pq() {
    docker compose --progress quiet run --rm --no-deps -e PGPASSWORD="$_pgpw" --entrypoint psql postgres \
        "host=$PRIMARY port=5432 dbname=fastpki user=fastpki sslmode=verify-full sslrootcert=/pki/tls/pg/primary-ca.crt connect_timeout=5" \
        -tAc "$1" 2>/dev/null | tr -d '\r' | sed '/^[[:space:]]*$/d'
}

_rows=$(_pq "SELECT dc_id FROM datacenters ORDER BY dc_id;" || true)
if [ -n "$_rows" ]; then
    if ! printf '%s\n' "$_rows" | grep -Fqx "$_dcid"; then
        echo "$0: DATACENTER_ID=$_dcid has no row in the primary's \`datacenters\` table." >&2
        echo "  Ids that do:" >&2
        printf '%s\n' "$_rows" | sed 's/^/    /' >&2
        echo "  The lookup is exact, and the installers write the bare index — so \`dc1\`" >&2
        echo "  never matches a topology whose dc_id is \`1\`. Every issuing service on this" >&2
        echo "  host would refuse to start with \"has no row in \\\`datacenters\\\`\"." >&2
        exit 1
    fi
    # The primary's own id, when the deployment states it unambiguously. A single distinct
    # dc_id is a single data center — the shape a pair is being built in. With several
    # (a mesh) this cannot name the primary's from here, so it is left alone rather than
    # guessed at.
    _pdc=$(_pq "SELECT DISTINCT dc_id FROM p11_transport WHERE dc_id IS NOT NULL AND dc_id <> '';" || true)
    if [ "$(printf '%s\n' "$_pdc" | grep -c .)" = "1" ] && [ "$_pdc" != "$_dcid" ]; then
        echo "$0: DATACENTER_ID=$_dcid, but the primary runs as data center '$_pdc'." >&2
        echo "  A standby takes its primary's id — a pair is one data center twice, and the" >&2
        echo "  id names the data center, not the host. With a different id this host assigns" >&2
        echo "  serials in another data center's range." >&2
        echo "  Set DATACENTER_ID=$_pdc in .env and re-run. See docs/high-availability.md." >&2
        exit 1
    fi
    echo "DATACENTER_ID=$_dcid matches the primary's data center."
fi

# ── Record the primary ─────────────────────────────────────────────────────────────────
touch .env
if grep -q '^STANDBY_OF=' .env; then
    sed -i.bak "s|^STANDBY_OF=.*|STANDBY_OF=$PRIMARY|" .env && rm -f .env.bak
else
    printf 'STANDBY_OF=%s\n' "$PRIMARY" >> .env
fi
echo "Recorded STANDBY_OF=$PRIMARY in .env."

# ── Write this host's PG_CONNINFO override ────────────────────────────────────────────
#
# ⚠️ NOT `fastpki-config set PG_CONNINFO`, which this script used to advise. PG_CONNINFO is
# the one key is_bootstrap_config_key() returns true for, so the database overlay is
# deliberately skipped for it — a deployment must not be able to reconfigure how it reaches
# its own database from a row inside that database. `set` leaves `get` reporting
# "not set: PG_CONNINFO" and every app keeps the value it started with, so the advice read
# as a command that ran and did nothing.
#
# ⚠️ THE PRIMARY IS LISTED FIRST HERE, AND THAT IS THE OPPOSITE OF THE STEADY STATE. libpq
# fails over past a peer that is DOWN or read-only, and NOT past one that ANSWERS with a
# certificate it cannot verify: it stops there and never tries the second host.
#
# At THIS moment — the join — the unverifiable host is THIS one. Its Postgres is serving the
# self-signed pair certgen wrote, and the anchor placed above is the PRIMARY's chain, which
# cannot verify it. So listing this host first makes every service here dial a certificate the
# anchor rejects and never reach the primary at all: measured on a fresh pair, web, est, acme,
# cmp, ms, scep and store all restart-loop, and p11-tls logs "could not publish this node's
# client certificate" so the token tunnel never comes up either. The host cannot escape on its
# own, because issuing its own database certificate needs a CA key that arrives by `key sync`,
# which needs the tunnel, which needs the database.
#
# Once this host HAS a database certificate from the pair's CA, the order should be reversed —
# then a peer being rebuilt cannot take this host's tooling down with it, which is what the
# steady-state rule is for. The message below says so, because nothing else will.
# Measured both ways: host=<unverifiable>,<good> fails, host=<good>,<unverifiable> succeeds.
# Which host first, by the same rule as native: this host first only once its own database
# certificate verifies against the pair's CA, which a self-signed one never does. A re-run
# after the pair CA has issued this host's certificate turns the order round.
# The certificate Postgres SERVES, not the file, as on native: it is taken up after it is
# written, and the services would dial the old one meanwhile.
if docker compose --progress quiet run --rm --no-deps --user 0:0 --entrypoint sh certgen -c \
     'openssl s_client -connect postgres:5432 -starttls postgres -CAfile /var/pki/tls/pg/primary-ca.crt -verify_return_error </dev/null' \
     >/dev/null 2>&1; then
    HOSTS="$SELF,$PRIMARY"
else
    HOSTS="$PRIMARY,$SELF"
fi
compose_write_override "$HOSTS" "$(envv POSTGRES_PASSWORD)" /var/pki/tls/pg/primary-ca.crt

# ── Bring it up as the primary's standby ──────────────────────────────────────────────
# With STANDBY_OF set and an empty data directory, the postgres service copies the
# primary's database itself (pg_basebackup), so replacing a database is: stop this host,
# remove its data volume, start it again.
if [ "$NEED_WIPE" = 1 ]; then
    echo "Stopping this host and replacing its database with a copy of $PRIMARY's."
    docker compose down >/dev/null 2>&1
    docker volume rm "$VOL" >/dev/null
fi
docker compose up -d >/dev/null 2>&1 || { echo "$0: docker compose up -d failed; run it to see why" >&2; exit 1; }
_i=0
until [ "$(cpq 'select pg_is_in_recovery()')" = t ]; do
    _i=$((_i+1))
    [ "$_i" -le 90 ] || { echo "$0: Postgres did not come back as a standby within 3 minutes: docker compose logs postgres" >&2; exit 1; }
    sleep 2
done
echo "Streaming from $PRIMARY."
[ -n "${FASTPKI_JOIN_BY_PAIR:-}" ] || cat <<EOF

Next, on the primary:   ./ha-join.sh --on-primary $SELF [--standby-pin-file <this host's PIN>]
Then copy the keys, on this host and then the primary, until it says "this node holds every
key it needs to serve":
    docker compose exec certrenew fastpki-ca --config /app/config/bootstrap.conf key sync --from-peers
deploy/ha-join-pair.sh does all of it from your own machine, in one command.

Every CA must have been created copyable (--replicable), the root included: a key is
copyable or not from the moment it is generated, and one that is not can never reach this
host, which then cannot sign under it.
EOF
