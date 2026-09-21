#!/bin/sh
# deployment-path: operator — runs on the operator's machine; reaches a server over ssh+doas (native, cloud), ssh+docker compose, or kubectl
# deploy/node-access.sh — reach one FastPKI server the way its deployment path allows.
#
# Sourced, not run, by the commands an operator runs from their OWN machine against several
# servers at once: deploy/mesh-join.sh and deploy/ha-join-pair.sh. Each of those does the same
# steps on every deployment path; this file is the only place the paths differ.
#
# A server is named by one string:
#
#   user@host                   native or cloud (Alpine + OpenRC, root through doas), or
#                               compose in ~/FastPKI/deploy — told apart by looking
#   user@host:/path/to/deploy   compose, in that directory
#   k8s:<context>[/<namespace>] Kubernetes, through kubectl (namespace default: fastpki)
#
# NA_SSH_KEY names an SSH identity file. Secrets travel on stdin, never on a command line,
# so they do not appear in the other host's process list.
#
# ⚠️ WHY THIS RUNS ON THE OPERATOR'S MACHINE: it needs to log in to every server as root.
# A node that could do that to its peers would hand an intruder on one host every other
# host's CA keys.

na_die() { echo "${NA_PROG:-node-access}: $*" >&2; exit 1; }

# NA_SSH_JUMP=user@host reaches servers through that host, for networks the operator's machine
# cannot reach directly. The same key is used for both hops. A host seen for the first time is
# added to known_hosts; one whose key has CHANGED is refused, as ssh always does.
na_ssh() {   # na_ssh <user@host> <remote command>
    _i=""; [ -z "${NA_SSH_KEY:-}" ] || _i="-i $NA_SSH_KEY"
    _o="-o ConnectTimeout=15 -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
    if [ -n "${NA_SSH_JUMP:-}" ]; then
        ssh $_o $_i -o "ProxyCommand=ssh $_o $_i -W %h:%p $NA_SSH_JUMP" "$1" "$2"
    else
        ssh $_o $_i "$1" "$2"
    fi
}

# Split a server's name into NA_KIND (native|compose|k8s), NA_HOST, NA_DIR, NA_CTX, NA_NS.
# "user@host" is resolved by looking at the host, and remembered in NA_SEEN, so call this
# once per server in the main shell before any $(...) that uses it.
NA_SEEN=""
na_resolve() {
    NA_HOST="" NA_DIR="" NA_CTX="" NA_NS="fastpki"
    case "$1" in
        k8s:*)
            NA_KIND=k8s; _r=${1#k8s:}
            case "$_r" in */*) NA_CTX=${_r%%/*}; NA_NS=${_r#*/} ;; *) NA_CTX=$_r ;; esac
            return 0 ;;
        *:/*) NA_KIND=compose; NA_HOST=${1%%:/*}; NA_DIR=/${1#*:/}; return 0 ;;
        *:~*) NA_KIND=compose; NA_HOST=${1%%:~*}; NA_DIR=~${1#*:~}; return 0 ;;
    esac
    NA_HOST=$1
    _hit=$(printf '%s\n' "$NA_SEEN" | awk -F'|' -v s="$1" '$1 == s {print $2 "|" $3; exit}')
    if [ -n "$_hit" ]; then NA_KIND=${_hit%%|*}; NA_DIR=${_hit#*|}; return 0; fi
    # </dev/null: ssh forwards stdin to the far command, so without it this look would swallow
    # whatever the CALLER is feeding — the SQL for na_sql, a secret for na_run — and the
    # command after it would run on empty input and print nothing.
    _k=$(na_ssh "$NA_HOST" 'if [ -f /etc/fastpki/bootstrap.conf ]; then echo native;
        elif [ -f "$HOME/FastPKI/deploy/docker-compose.yml" ]; then echo compose;
        else echo none; fi' </dev/null) || na_die "cannot log in to $NA_HOST"
    case "$_k" in
        native)  NA_KIND=native ;;
        compose) NA_KIND=compose; NA_DIR='~/FastPKI/deploy' ;;
        *) na_die "$NA_HOST is neither a native install (/etc/fastpki/bootstrap.conf) nor a compose one (~/FastPKI/deploy); name the directory: $NA_HOST:/path/to/deploy" ;;
    esac
    NA_SEEN="$NA_SEEN
$1|$NA_KIND|$NA_DIR"
}

na_kubectl() { kubectl --context "$NA_CTX" -n "$NA_NS" "$@"; }

# The Kubernetes server pod whose database is read-write: fastpki-node-0 unless it was promoted
# away from.
na_k8s_primary() {
    for _p in $(na_kubectl get pods -l app.kubernetes.io/component=node -o name 2>/dev/null | sed 's|^pod/||'); do
        [ "$(na_kubectl exec "$_p" -c postgres -- psql -X -At -U fastpki -d fastpki -c 'select pg_is_in_recovery()' 2>/dev/null)" = f ] \
            && { echo "$_p"; return 0; }
    done
    echo fastpki-node-0
}

# Run a shell script on the server's HOST with the privilege its path needs: root on native,
# the SSH user (a member of the docker group) in the deploy directory on compose. The script
# travels base64-encoded in the command line and must hold no secret; stdin stays free for
# data, which is where secrets go.
na_run() {   # na_run <server> <script>
    na_resolve "$1"
    _b=$(printf '%s' "$2" | openssl base64 -A)
    case "$NA_KIND" in
        native)  na_ssh "$NA_HOST" "echo $_b | base64 -d > /tmp/.na.\$\$; if [ \"\$(id -u)\" = 0 ]; then sh /tmp/.na.\$\$; else doas sh /tmp/.na.\$\$; fi; rc=\$?; rm -f /tmp/.na.\$\$; exit \$rc" ;;
        compose) na_ssh "$NA_HOST" "cd $NA_DIR && echo $_b | base64 -d > /tmp/.na.\$\$ && sh /tmp/.na.\$\$; rc=\$?; rm -f /tmp/.na.\$\$; exit \$rc" ;;
        k8s)     na_die "na_run: a Kubernetes server has no host shell" ;;
    esac
}

# SQL on stdin, run in the server's own database as the fastpki role. -At output.
na_sql() {   # na_sql <server>
    na_resolve "$1"
    _psql='psql -X -q -At -v ON_ERROR_STOP=1 -U fastpki -d fastpki'
    case "$NA_KIND" in
        native)  na_ssh "$NA_HOST" "if [ \"\$(id -u)\" = 0 ]; then su postgres -s /bin/sh -c '$_psql'; else doas su postgres -s /bin/sh -c '$_psql'; fi" ;;
        compose) na_ssh "$NA_HOST" "cd $NA_DIR && docker compose exec -T postgres $_psql" ;;
        k8s)     na_kubectl exec -i "$(na_k8s_primary)" -c postgres -- $_psql ;;
    esac
}

# A FastPKI CLI, as the service user, with the server's own config. Arguments are plain
# words (ids, flags); anything secret goes on stdin.
na_cli() {   # na_cli <server> <tool> [args...]
    _s=$1; _t=$2; shift 2
    na_resolve "$_s"
    case "$NA_KIND" in
        native)  na_ssh "$NA_HOST" "c='$_t --config /etc/fastpki/bootstrap.conf $*'; if [ \"\$(id -u)\" = 0 ]; then su -s /bin/sh fastpki -c \"\$c\"; else doas su -s /bin/sh fastpki -c \"\$c\"; fi" ;;
        compose) na_ssh "$NA_HOST" "cd $NA_DIR && docker compose exec -T web $_t --config /app/config/bootstrap.conf $*" ;;
        k8s)     na_kubectl exec -i "$(na_k8s_primary)" -c web -- $_t --config /app/config/bootstrap.conf "$@" ;;
    esac
}

# fastpki-mesh with a topology given on stdin, where the server can reach its peers. The
# topology holds every peer's database password, so it is written mode 600 to a temporary
# file and removed afterwards. The generated SQL goes to stdout.
na_mesh() {   # na_mesh <server> [fastpki-mesh args...]   (topology on stdin)
    _s=$1; shift
    na_resolve "$_s"
    # No single quote inside, so it can be wrapped in one for the far shell; kubectl passes
    # it to sh as it is.
    # --check-anchor: fastpki-mesh checks every peer before it emits anything, from where it
    # runs, and the topology's sslrootcert= is the path on the SUBSCRIBING Postgres. Where it
    # runs here — root on a native host, a web container on compose and Kubernetes — the CA
    # file is /var/pki/tls/pg/ca.crt on every path.
    _m='umask 077; t=$(mktemp); cat > "$t"; fastpki-mesh --topology "$t" --check-anchor /var/pki/tls/pg/ca.crt '"$*"'; rc=$?; rm -f "$t"; exit $rc'
    case "$NA_KIND" in
        native)  na_ssh "$NA_HOST" "if [ \"\$(id -u)\" = 0 ]; then sh -c '$_m'; else doas sh -c '$_m'; fi" ;;
        # --progress quiet: without it compose prints "Container ... Creating/Created" for
        # every one-off container, which tells an operator nothing.
        compose) na_ssh "$NA_HOST" "cd $NA_DIR && docker compose --progress quiet run --rm --no-deps -T --user 0:0 --entrypoint sh web -c '$_m'" ;;
        k8s)     na_kubectl exec -i "$(na_k8s_primary)" -c web -- sh -c "$_m" ;;
    esac
}

# What the orchestrators need to know about a server, as KEY=value lines on stdout:
#   KIND      native | compose | k8s
#   DCID      its DATACENTER_ID
#   PKI_DNS   its public name
#   BIND      the address(es) a peer dials for its database, comma-separated
#   PASSWORD  its database password (the fastpki role)
#   PIN       its token PIN
#   ANCHOR    the path of the CA file ITS OWN Postgres verifies a peer with — which is what
#             sslrootcert= must name in the topology it is given
na_facts() {   # na_facts <server>
    na_resolve "$1"
    case "$NA_KIND" in
        native) na_run "$1" '
            c=/etc/fastpki/bootstrap.conf; e=/etc/conf.d/fastpki
            echo KIND=native
            echo "DCID=$(sed -n "s/^DATACENTER_ID=//p" $c | head -1)"
            echo "PKI_DNS=$(sed -n "s/^PKI_DNS=//p" $c | head -1)"
            echo "BIND=$(sed -n "s/^PG_BIND=//p" $e | head -1)"
            echo "PASSWORD=$(sed -n "s/^PG_CONNINFO=.*password=\([^ ]*\).*/\1/p" $c | head -1)"
            echo "PIN=$(cat /var/pki/tls/pin 2>/dev/null)"
            echo ANCHOR=/var/lib/postgresql/tls/ca.crt' ;;
        compose) na_run "$1" '
            v() { sed -n "s/^$1=//p" .env 2>/dev/null | head -1; }
            echo KIND=compose
            echo "DCID=$(v DATACENTER_ID)"
            echo "PKI_DNS=$(v PKI_DNS)"
            echo "BIND=$(v PG_BIND)"
            echo "PASSWORD=$(v POSTGRES_PASSWORD)"
            echo "PIN=$(v FASTPKI_PIN)"
            echo ANCHOR=/pki/tls/pg/ca.crt' ;;
        k8s)
            _conf=$(na_kubectl get configmap fastpki-bootstrap -o jsonpath='{.data.bootstrap\.conf}' 2>/dev/null)
            _sec() { na_kubectl get secret fastpki-secret -o "jsonpath={.data.$1}" 2>/dev/null | openssl base64 -d -A; }
            echo KIND=k8s
            echo "DCID=$(printf '%s\n' "$_conf" | sed -n 's/^DATACENTER_ID=//p' | head -1)"
            echo "PKI_DNS=$(printf '%s\n' "$_conf" | sed -n 's/^PKI_DNS=//p' | head -1)"
            echo "BIND=$(printf '%s\n' "$_conf" | sed -n 's/^PG_TLS_SANS=//p' | head -1)"
            echo "PASSWORD=$(_sec pgPassword)"
            echo "PIN=$(_sec fastpkiPin)"
            echo ANCHOR=/pki/tls/pg/ca.crt ;;
    esac
}

# The PEM of the CA the server's database certificate chains to: what a joining standby
# verifies its primary with.
na_anchor_pem() {   # na_anchor_pem <server>
    na_resolve "$1"
    case "$NA_KIND" in
        native)  na_run "$1" 'cat /var/pki/tls/pg/ca.crt' ;;
        compose) na_run "$1" 'docker compose exec -T postgres cat /pki/tls/pg/ca.crt' ;;
        k8s)     na_kubectl exec "$(na_k8s_primary)" -c postgres -- cat /pki/tls/pg/ca.crt ;;
    esac
}

# One field out of na_facts output.
na_fact() { printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -1; }
