#!/bin/sh
# apply.sh — deploy FastPKI to Kubernetes using kubectl + envsubst.
# No Helm required. Source env.sh (or env.local) before running.
#
# Usage:
#   . deploy/k8s/env.sh                # or env.local
#   deploy/k8s/apply.sh
#   deploy/k8s/apply.sh --render       # print the StatefulSet and the protocol Services this run
#                                      # would apply, and stop; no cluster is touched
#
# ── THE SHAPE ─────────────────────────────────────────────────────────────────────────
#
# Every FastPKI server is one pod of the `fastpki-node` StatefulSet, carrying its own token, its own
# /var/pki and its own Postgres — the Kubernetes form of one Compose host (manifests/
# node-statefulset.yaml says why each piece is where it is). HA_ENABLED is two of them on two
# nodes: the Compose pair, with pod 1's database streaming from pod 0's and each pod's renewal
# loop replicating into its own token every key the other pod holds. apply.sh is also the update path: every step below
# is idempotent, and a re-run with a new IMAGE rolls the servers onto it.
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd "$DEPLOY_DIR/.." && pwd)"
MANIFESTS="$SCRIPT_DIR/manifests"

RENDER_ONLY=0
case "${1:-}" in
    --render) RENDER_ONLY=1 ;;
    "") ;;
    *) echo "usage: apply.sh [--render]" >&2; exit 2 ;;
esac

# ── 1. Load env ────────────────────────────────────────────────────────────
[ -f "$SCRIPT_DIR/env.local" ] && . "$SCRIPT_DIR/env.local"
# Whether anyone CHOSE an image, noted before env.sh fills in its default; see 1c.
IMAGE_CHOSEN="${IMAGE:-}${FASTPKI_RELEASE_IMAGE:-}"
. "$SCRIPT_DIR/env.sh"
[ -f "$SCRIPT_DIR/env.local" ] && . "$SCRIPT_DIR/env.local"

command -v envsubst >/dev/null 2>&1 || { echo "ERROR: envsubst not found (install gettext)" >&2; exit 1; }
[ "$RENDER_ONLY" = 1 ] || command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl not found" >&2; exit 1; }

# ⚠️ ONLY true OR false. A protocol flag is a manifest switch, and anything else — `yes`, `no`, a
# typo — would be read as off by render() and silently drop that protocol's container.
for _p in EST ACME CMP SCEP MS STORE; do
    eval "_v=\${${_p}_INSTALLED:-true}"
    case "$_v" in
        true|false) ;;
        *) echo "ERROR: ${_p}_INSTALLED must be true or false (got '$_v')" >&2; exit 1 ;;
    esac
done

# ── 1a. How many servers ──────────────────────────────────────────────────────────
#
# ⚠️ A PAIR IS TWO SERVERS WITH KEY REPLICATION, OR IT IS NOT A PAIR. The second server's token
# receives the CA keys only over P11_TLS (`key sync`, run by its renewal loop), so HA_ENABLED
# with the transport off builds a standby database beside a token that can never sign — the
# one-token failure, reached by a different road. It is switched on with HA_ENABLED
# rather than required as a second setting, and refused if it was explicitly turned off.
if [ "${HA_ENABLED:-false}" = "true" ]; then
    NODE_COUNT=2
    if [ "${P11_TLS:-}" = "off" ]; then
        echo "ERROR: HA_ENABLED=true with P11_TLS=off. The second server receives the CA keys" >&2
        echo "       only over the token transport; without it a promotion gives you a database" >&2
        echo "       and no issuer. Leave P11_TLS unset (HA_ENABLED turns it on) or set it to on." >&2
        exit 1
    fi
    P11_TLS=on
else
    NODE_COUNT=1
    P11_TLS="${P11_TLS:-off}"
    [ -n "$P11_TLS" ] || P11_TLS=off
fi

# ── 1b. Multi-data-center preconditions ─────────────────────────────────────
# ⚠️ REFUSE, DO NOT WARN. A cluster deployed as one data center of several with no interconnect
# address comes up looking healthy and can never be meshed: the peers have no host to dial, and
# this cluster's database certificates cannot carry a SAN nobody supplied, so every peer's
# sslmode=verify-full refuses them later, after the CAs exist.
#
# ⚠️ DC_INDEX IS NOT THE SWITCH, BECAUSE IT IS ALWAYS SET. env.sh defaults it to 1 on purpose — a
# single cluster is data center 1, not "no data center", so a later expansion does not leave
# every certificate issued before it outside this cluster's serial partition. PG_INTERCONNECT is
# the honest discriminator: a cluster is part of a mesh exactly when peers have an address to
# dial it on, and it has no default.
case "$DC_INDEX" in
    *[!0-9]*) echo "ERROR: DC_INDEX must be a positive integer (it IS this cluster's serial prefix)" >&2; exit 1 ;;
esac
# The real bound: a DER integer is signed, so a prefix with the high bit set pushes the serial
# past the RFC 5280 4.1.2.2 limit.
if [ "$DC_INDEX" -lt 1 ] || [ "$DC_INDEX" -gt 32767 ]; then
    echo "ERROR: DC_INDEX must be in 1..32767 (serial prefix is 2 octets, high bit reserved)" >&2; exit 1
fi
if [ "$DC_INDEX" != "1" ] && [ -z "${PG_INTERCONNECT:-}" ]; then
    echo "ERROR: DC_INDEX=$DC_INDEX requires PG_INTERCONNECT — the address the OTHER" >&2
    echo "       clusters dial to reach this cluster's Postgres. It goes into the" >&2
    echo "       topology file's host= AND into this cluster's database certificates as a" >&2
    echo "       SAN; without it the peers cannot connect and could not verify it if" >&2
    echo "       they could. See docs/deployment.md 9.3." >&2
    exit 1
fi
# ⚠️ ONE INTERCONNECT ADDRESS PER SERVER. A peer data center subscribes to this one's primary,
# and after a promotion the primary is the other pod — so, exactly as a Compose pair's peers name
# both hosts, the peers name both servers, and each needs an address of its own.
if [ -n "${PG_INTERCONNECT:-}" ]; then
    _ic_count=$(printf '%s' "$PG_INTERCONNECT" | tr ',' '\n' | grep -c '[^[:space:]]' || true)
    if [ "$_ic_count" -ne "$NODE_COUNT" ]; then
        echo "ERROR: PG_INTERCONNECT names $_ic_count address(es) for $NODE_COUNT server(s)." >&2
        echo "       Give one per server, in pod order, comma-separated: the first is fastpki-node-0's," >&2
        echo "       the second fastpki-node-1's. The peers dial each of them, since either can be" >&2
        echo "       the primary. See docs/deployment.md 9.3." >&2
        exit 1
    fi
fi

# ── 2. Generate bootstrap.conf ──────────────────────────────────────────────────
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# ⚠️ THE CONNINFO NAMES EVERY SERVER. libpq takes the first host that is read-write
# (target_session_attrs), so a promotion re-homes every application on its next statement with
# no restart. A single-server deployment names its one pod.
#
# ⚠️ sslrootcert IS THE TRUST BUNDLE, NOT A SINGLE ANCHOR. libpq stops at the first host whose
# certificate it cannot verify and never tries the next, so every pod has to verify every pod's
# database — including a peer still serving its self-signed first-start pair. pg-trust.sh builds
# the bundle from this pod's own anchor, every pod's anchor (the fastpki-pg-anchors ConfigMap) and
# this PKI's root CAs.
#
# ⚠️ AND THIS POD'S OWN DATABASE FIRST, AT 127.0.0.1, SO A PROMOTED SERVER NEEDS NO DNS. Every other
# host is a pod name that cluster DNS answers, and cluster DNS is usually one CoreDNS replica on
# one node. Measured on a three-node k3d cluster: the node lost was the one CoreDNS ran on, and for
# the minutes until Kubernetes rescheduled it the survivor could resolve neither pod name — its
# own promoted database included — so every service failed with "could not translate host name".
# 127.0.0.1 is the pod's own Postgres whatever its role: a standby's is skipped by
# target_session_attrs, a primary's is used without a lookup. Both database certificates carry the
# address (certgen and `fastpki-ca pg-tls` add it), which is what a Compose host's `postgres` is.
_hosts="127.0.0.1"; _ports="5432"; _i=0
while [ "$_i" -lt "$NODE_COUNT" ]; do
    _hosts="${_hosts:+$_hosts,}fastpki-node-$_i.fastpki-node"
    _ports="${_ports:+$_ports,}5432"
    _i=$((_i + 1))
done

PKI_CONF="$TMPDIR/bootstrap.conf"
cat "$DEPLOY_DIR/bootstrap.compose.conf" > "$PKI_CONF"
cat >> "$PKI_CONF" <<EOF

# ── Kubernetes overrides (apply.sh generated) ──
PKI_DNS=$PKI_DNS
# ⚠️ NO PASSWORD IN THIS STRING. bootstrap.conf becomes the fastpki-bootstrap ConfigMap, which is
# cleartext to anyone who can read ConfigMaps in the namespace. Every process takes the password
# from the fastpki-secret Secret as PGPASSWORD, which libpq applies when the conninfo omits it.
PG_CONNINFO=host=$_hosts port=$_ports dbname=$PG_DB user=$PG_USER sslmode=verify-full sslrootcert=/var/pki/tls/pg/trust.crt target_session_attrs=read-write connect_timeout=5
# ⚠️ WEB_PORT HAS TO REACH THE BINARY, not only the manifests. It is a real config key
# (Config::web_port), and the Service, the container port and the readiness probe all follow it.
WEB_PORT=$WEB_PORT
EOF

# ⚠️ DATACENTER_ID IS UNCONDITIONAL — a single cluster is data center 1. Without it the servers
# mint full-width serials carrying no prefix, and every certificate issued before a later
# expansion sits outside this cluster's partition for ever. Both servers of a pair carry the
# same id: a pair is one data center twice.
cat >> "$PKI_CONF" <<EOF
DATACENTER_ID=$DC_INDEX
EOF
# ⚠️ A PAIR'S SERVICE KEYS MUST BE REPLICABLE FROM THE FIRST ONE MINTED. Each server's renewal loop
# runs `renew-service-certs --create-missing`, and the OCSP, CMP and SCEP credential keys it mints
# are extractable only if this says so — CKA_EXTRACTABLE is fixed when a key is generated, so a
# credential minted without it can never reach the other server's token, and nothing can repair
# it afterwards. Set with HA_ENABLED rather than left for an operator to remember; the Config page
# still wins over it.
if [ "$NODE_COUNT" -gt 1 ]; then
    cat >> "$PKI_CONF" <<EOF
SERVICE_KEYS_REPLICABLE=true
EOF
fi
# ⚠️ EACH SERVER'S OWN NAME IS NOT IN HERE, AND MUST NOT BE. fastpki-node-N.fastpki-node reaches its
# database certificate from that pod's PG_BIND, which certgen and `fastpki-ca pg-tls` read from
# the environment. PG_TLS_SANS is one config row that every server of the data center reads, so
# it carries only what they share: the interconnect addresses peers dial.
PG_TLS_SANS="${PG_INTERCONNECT:-}"
if [ -n "$PG_TLS_SANS" ]; then
    cat >> "$PKI_CONF" <<EOF
PG_TLS_SANS=$PG_TLS_SANS
EOF
fi

# ── the service key specs, written only where the operator chose one ──────────────────
#
# ⚠️ ONLY NON-EMPTY VALUES. Config::load() applies every key it finds, so `WEB_KEY_ALGO=` would
# set the algorithm to the empty string rather than leaving the compiled default alone.
# ⚠️ KEY_MD IS A LISTENER-ONLY KEY. The parser knows WEB/EST/ACME/MS_KEY_MD and no
# OCSP_RESPONDER_KEY_MD or CMP_RA_KEY_MD, and an unknown key is silently ignored.
for _svc in WEB EST ACME MS OCSP_RESPONDER CMP_RA; do
    case "$_svc" in
        WEB|EST|ACME|MS) _fields="KEY_ALGO KEY_BITS KEY_CURVE KEY_MD" ;;
        *)               _fields="KEY_ALGO KEY_BITS KEY_CURVE" ;;
    esac
    for _f in $_fields; do
        eval "_v=\${${_svc}_${_f}:-}"
        [ -n "$_v" ] || continue
        printf '%s_%s=%s\n' "$_svc" "$_f" "$_v" >> "$PKI_CONF"
    done
done
# SCEP has a size and no algorithm — RFC 8894 fixes the envelope on RSA key transport.
[ -n "${SCEP_RA_KEY_BITS:-}" ] && printf 'SCEP_RA_KEY_BITS=%s\n' "$SCEP_RA_KEY_BITS" >> "$PKI_CONF"
true

# ── 3. Prepare optional YAML blocks ────────────────────────────────────────
# Active Directory is found by NAME, and the cluster resolver does not know your domain. LDAP
# login, user and group import, MS template import and Kerberos all resolve the DC first, and
# cluster DNS answers NXDOMAIN for the AD zone ("Can't contact LDAP server"). dnsPolicy stays
# ClusterFirst, so these nameservers are APPENDED and Service names keep resolving.
DIRECTORY_DNS_BLOCK=""
if [ -n "${DIRECTORY_DNS:-}" ]; then
    # No leading whitespace on the FIRST line — the use site indents the placeholder — and full
    # indentation on every continuation line. See the warning below.
    DIRECTORY_DNS_BLOCK="dnsConfig:"
    DIRECTORY_DNS_BLOCK="$DIRECTORY_DNS_BLOCK
        nameservers:"
    for ns in $(printf '%s' "$DIRECTORY_DNS" | tr ',' ' '); do
        DIRECTORY_DNS_BLOCK="$DIRECTORY_DNS_BLOCK
          - $ns"
    done
    if [ -n "${DIRECTORY_DNS_SEARCH:-}" ]; then
        DIRECTORY_DNS_BLOCK="$DIRECTORY_DNS_BLOCK
        searches:"
        for sd in $(printf '%s' "$DIRECTORY_DNS_SEARCH" | tr ',' ' '); do
            DIRECTORY_DNS_BLOCK="$DIRECTORY_DNS_BLOCK
          - $sd"
        done
    fi
fi
export DIRECTORY_DNS_BLOCK

# ⚠️ NO LEADING WHITESPACE IN ANY OF THESE. Every use site already indents the placeholder to the
# depth its key belongs at, and envsubst substitutes in place, so spaces here put the key one
# level too deep:
#
#   PersistentVolumeClaim ... strict decoding error: unknown field "spec.resources.storageClassName"
#
# — measured against a real cluster. It was invisible because these are EMPTY by default, and an
# empty value renders a whitespace-only line that YAML ignores.
if [ -n "$STORAGE_CLASS" ]; then
    STORAGE_CLASS_BLOCK="storageClassName: \"$STORAGE_CLASS\""
else
    STORAGE_CLASS_BLOCK=""
fi

if [ -n "$INGRESS_CLASS" ]; then
    INGRESS_CLASS_BLOCK="ingressClassName: $INGRESS_CLASS"
else
    INGRESS_CLASS_BLOCK=""
fi

if [ "$INGRESS_TLS" = "true" ]; then
    INGRESS_TLS_BLOCK="$(printf 'tls:\n    - hosts: ["%s"]\n      secretName: fastpki-web-tls' "$INGRESS_HOST")"
else
    INGRESS_TLS_BLOCK=""
fi

# ⚠️ HASH THE RENDERED CONFIG INTO THE POD TEMPLATE. bootstrap.conf reaches the pods through a
# subPath ConfigMap mount, and Kubernetes never updates a subPath mount — so updating the
# ConfigMap changed nothing a running process could see. Measured on a real cluster:
# DATACENTER_ID and PG_TLS_SANS were right in the ConfigMap and absent from the pod, and the
# database certificate was issued without the interconnect SAN.
# ⚠️ AND THE SCRIPTS THE PODS RUN FROM THE SAME ConfigMap. Those mount as a directory, so the files
# do change — but each container read its script once, when it started, so a changed script
# reached no running process either.
_hashed() {
    cat "$PKI_CONF" "$DEPLOY_DIR/certgen.sh" "$SCRIPT_DIR"/token.sh "$SCRIPT_DIR"/node-init.sh \
        "$SCRIPT_DIR"/node-run.sh "$SCRIPT_DIR"/pg-trust.sh "$SCRIPT_DIR"/start-postgres.sh \
        "$SCRIPT_DIR"/p11-tls.sh "$SCRIPT_DIR"/renew-loop.sh
}
CONFIG_HASH="$( (_hashed | sha256sum 2>/dev/null || _hashed | shasum -a 256 2>/dev/null || _hashed | cksum) | cut -d" " -f1 )"
[ -n "$CONFIG_HASH" ] || { echo "ERROR: could not hash $PKI_CONF" >&2; exit 1; }
export CONFIG_HASH

# ⚠️ THE TOKEN PIN. certgen refuses to fall back to a well-known PIN, because the token holds
# every CA private key. Every server's token is initialised with this one value, so a key
# replicated between them needs no second PIN.
#
# ⚠️ AN EXISTING DEPLOYMENT ALREADY HAS A PIN, AND MINTING A SECOND ONE BRICKS IT. SoftHSM keeps
# the PIN a token was INITIALISED with; a re-apply that generated a fresh one wrote a PIN into
# the Secret that opened nothing — "The specified PIN is invalid" from every issuing service,
# measured on a real cluster. So it is read back from the cluster, and generated only for a
# deployment that has none.
if [ "$RENDER_ONLY" = 0 ] && [ -z "${FASTPKI_PIN:-}" ]; then
    EXISTING_PIN="$(kubectl -n "$NAMESPACE" get secret fastpki-secret \
                      -o jsonpath='{.data.fastpkiPin}' 2>/dev/null | base64 -d 2>/dev/null || true)"
    if [ -n "$EXISTING_PIN" ]; then
        FASTPKI_PIN="$EXISTING_PIN"
        echo "==> Reusing the token PIN already held in namespace '$NAMESPACE'."
    else
        FASTPKI_PIN="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 32)"
        [ -n "$FASTPKI_PIN" ] || { echo "ERROR: could not generate FASTPKI_PIN" >&2; exit 1; }
        echo "==> Generated a token PIN for this deployment."
        echo "    Save it if you will ever deploy this namespace from scratch again:"
        echo "      echo 'export FASTPKI_PIN=$FASTPKI_PIN' >> $SCRIPT_DIR/env.local"
    fi
fi

# The database password, on exactly the same terms and for the same reason: Postgres keeps the
# password the role was CREATED with, so a fresh one would merely stop matching.
if [ "$RENDER_ONLY" = 0 ] && [ -z "${PG_PASSWORD:-}" ]; then
    EXISTING_PG="$(kubectl -n "$NAMESPACE" get secret fastpki-secret \
                     -o jsonpath='{.data.pgPassword}' 2>/dev/null | base64 -d 2>/dev/null || true)"
    if [ -n "$EXISTING_PG" ]; then
        PG_PASSWORD="$EXISTING_PG"
        echo "==> Reusing the database password already held in namespace '$NAMESPACE'."
    else
        PG_PASSWORD="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 32)"
        [ -n "$PG_PASSWORD" ] || { echo "ERROR: could not generate PG_PASSWORD" >&2; exit 1; }
        echo "==> Generated a database password for this deployment."
        echo "    Save it if you will ever deploy this namespace from scratch again:"
        echo "      echo 'export PG_PASSWORD=$PG_PASSWORD' >> $SCRIPT_DIR/env.local"
    fi
fi

# The image, on the same terms: a deployment that exists keeps the image it runs unless one
# is chosen. install.sh names the release image for the run it starts and saves it nowhere,
# so without this every later apply.sh fell back to env.sh's `fastpki:latest`, which no
# registry holds, and the servers could not restart (ErrImagePull).
if [ "$RENDER_ONLY" = 0 ] && [ -z "$IMAGE_CHOSEN" ]; then
    RUNNING_IMAGE="$(kubectl -n "$NAMESPACE" get statefulset fastpki-node \
        -o jsonpath='{.spec.template.spec.containers[?(@.name=="web")].image}' 2>/dev/null || true)"
    if [ -n "$RUNNING_IMAGE" ]; then
        IMAGE="$RUNNING_IMAGE"
        echo "==> Keeping the image this deployment runs: $IMAGE (set IMAGE to change it)."
    fi
fi

export STORAGE_CLASS_BLOCK INGRESS_CLASS_BLOCK INGRESS_TLS_BLOCK
export NAMESPACE IMAGE IMAGE_PULL_POLICY PKI_DNS
export PG_IMAGE PG_USER PG_DB PG_PASSWORD PG_DATA_SIZE
export PKI_DATA_SIZE
export WEB_SERVICE_TYPE WEB_PORT FASTPKI_PIN
export SOFTHSM_ENABLED SOFTHSM_SO_PIN SOFTHSM_TOKEN_SIZE
export PROTO_SERVICE_TYPE
export PKCS11_MODULE P11_KIT_SERVER_ADDRESS PKCS11_PIN_FILE PKCS11_TOKEN
export HA_ENABLED AUDITFWD_ENABLED NODE_COUNT P11_TLS
export PG_TLS_SANS

# Render a manifest, dropping every `# @if FLAG` … `# @end` section whose flag is off. The
# sections are optional containers and claims inside one StatefulSet, which envsubst alone has no
# way to leave out.
render() {
    _on=""
    [ "${SOFTHSM_ENABLED:-true}" = "true" ]      && _on="$_on SOFTHSM"
    [ "$P11_TLS" = "on" ]                        && _on="$_on P11_TLS"
    [ "${AUDITFWD_ENABLED:-false}" = "true" ]    && _on="$_on AUDITFWD"
    for _p in EST ACME CMP SCEP MS STORE; do
        eval "_v=\${${_p}_INSTALLED:-true}"
        [ "$_v" = true ] && _on="$_on $_p"
    done
    # ⚠️ AN UNKNOWN FLAG IS DROPPED, NOT KEPT. A section whose flag nobody sets here is a typo, and
    # rendering it by default would ship an optional container that was never switched on.
    envsubst < "$1" | awk -v on="$_on " '
        /^[[:space:]]*# @if [A-Z_0-9]+[[:space:]]*$/ { skip = (index(on, " " $3 " ") == 0); next }
        /^[[:space:]]*# @end[[:space:]]*$/          { skip = 0; next }
        !skip'
}

# One pod's container, for an exec. `kubectl exec sts/...` would pick a pod for us, and the right
# pod matters: the primary for the schema, a particular server for its own files.
kx() {   # kx <pod> <container> <command...>
    _pod=$1; _c=$2; shift 2
    kubectl exec -n "$NAMESPACE" "$_pod" -c "$_c" -- "$@"
}
# The pod whose database is read-write, or nothing. Asked of every pod rather than assumed to be
# pod 0: after a promotion it is not.
primary_pod() {
    _i=0
    while [ "$_i" -lt "$NODE_COUNT" ]; do
        _r=$(kx "fastpki-node-$_i" postgres psql -U "$PG_USER" -d "$PG_DB" -tAc 'SELECT pg_is_in_recovery()' 2>/dev/null \
             | tr -d '[:space:]' || true)
        [ "$_r" = f ] && { printf 'fastpki-node-%s' "$_i"; return 0; }
        _i=$((_i + 1))
    done
    return 1
}

# The interconnect Services, one per server: what 7b applies and what --render prints.
# ⚠️ ONE SERVICE PER POD, SELECTED BY POD NAME. A Service across both servers would spread a peer's
# subscription between the primary and a standby that cannot accept a replication slot; a peer
# names both addresses with target_session_attrs=read-write instead, as it names both hosts of a
# Compose pair.
#
# ⚠️ AND ONE PORT PER POD: 5432 for fastpki-node-0, 5433 for fastpki-node-1 (12345, 12346 for the
# token transport). A load balancer that publishes a Service on the machines' own addresses —
# k3s's, for one — claims the port on every machine. With both Services on 5432 the first took
# the port on both machines and the second never got an address, so every peer address led to
# fastpki-node-0: fine until a promotion, after which no peer could reach the new primary and
# replication from this data center stopped. mesh-join reads each Service's port back.
interconnect_services() {
    _i=0
    while [ "$_i" -lt "$NODE_COUNT" ]; do
        NODE_ORDINAL=$_i
        PG_EXTERNAL_PORT=$((5432 + _i))
        P11_TLS_EXTERNAL_PORT=$((12345 + _i))
        export NODE_ORDINAL PG_EXTERNAL_PORT P11_TLS_EXTERNAL_PORT
        if [ "${PG_EXTERNAL_TYPE:-none}" != "none" ]; then
            if [ "$PG_EXTERNAL_TYPE" = "NodePort" ]; then
                PG_NODEPORT_BLOCK="nodePort: $((PG_NODEPORT + _i))"
            else
                PG_NODEPORT_BLOCK=""
            fi
            export PG_NODEPORT_BLOCK
            echo "---"
            envsubst < "$MANIFESTS/postgres-external.yaml"
        fi
        if [ "$P11_TLS" = "on" ] && [ "${P11_TLS_SERVICE_TYPE:-ClusterIP}" != "ClusterIP" ]; then
            export P11_TLS_SERVICE_TYPE
            echo "---"
            envsubst < "$MANIFESTS/p11-tls-external.yaml"
        fi
        _i=$((_i + 1))
    done
}

# ── 4. Apply core resources ───────────────────────────────────────────────
if [ "$RENDER_ONLY" = 1 ]; then
    render "$MANIFESTS/node-statefulset.yaml"
    echo "---"
    render "$MANIFESTS/service-protocols.yaml"
    interconnect_services
    exit 0
fi

echo "==> Creating namespace $NAMESPACE"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

echo "==> Applying Secret"
envsubst < "$MANIFESTS/secret.yaml" | kubectl apply -n "$NAMESPACE" -f -

echo "==> Creating ConfigMap (bootstrap.conf + scripts)"
# ⚠️ THE DATA CENTER'S ROW IS WRITTEN BY initdb, AFTER THE SCHEMA. Every container of a server pod
# starts at once, and est, acme, cmp, scep, ms and web exit fatally while `datacenters` has no row
# for DATACENTER_ID — so a row written by this script once the primary answered came after the
# listeners had already died, and a new deployment converged only through restarts. initdb runs
# before the server accepts a connection from anything outside it. The upsert further down stays,
# for a deployment whose database already exists.
DC_SQL="$TMPDIR/datacenter.sql"
printf "INSERT INTO datacenters(dc_id, serial_prefix) VALUES('%s', %s)\n    ON CONFLICT (dc_id) DO UPDATE SET serial_prefix=EXCLUDED.serial_prefix;\n" \
    "$DC_INDEX" "$DC_INDEX" > "$DC_SQL"
kubectl create configmap fastpki-bootstrap \
    --from-file=bootstrap.conf="$PKI_CONF" \
    --from-file=certgen.sh="$DEPLOY_DIR/certgen.sh" \
    --from-file=token.sh="$SCRIPT_DIR/token.sh" \
    --from-file=node-init.sh="$SCRIPT_DIR/node-init.sh" \
    --from-file=node-run.sh="$SCRIPT_DIR/node-run.sh" \
    --from-file=pg-trust.sh="$SCRIPT_DIR/pg-trust.sh" \
    --from-file=start-postgres.sh="$SCRIPT_DIR/start-postgres.sh" \
    --from-file=p11-tls.sh="$SCRIPT_DIR/p11-tls.sh" \
    --from-file=renew-loop.sh="$SCRIPT_DIR/renew-loop.sh" \
    --from-file=createdb.sql="$REPO_DIR/sql/createdb.sql" \
    --from-file=datacenter.sql="$DC_SQL" \
    -n "$NAMESPACE" \
    --dry-run=client -o yaml | kubectl apply -f -

# The servers' database anchors. Created empty the first time, so the mount exists; filled in
# below once each server has minted its first certificate. Never overwritten with an empty one
# on a re-apply, which would take away the anchor a standby verifies its primary with.
if ! kubectl get configmap fastpki-pg-anchors -n "$NAMESPACE" >/dev/null 2>&1; then
    # --save-config, because the fill below is a `kubectl apply`, and apply prints a warning
    # about a missing annotation on an object `create` made without it.
    kubectl create configmap fastpki-pg-anchors -n "$NAMESPACE" --save-config >/dev/null
fi

# ── Schema steps, before anything runs the new image ─────────────────────────────
# apply.sh is the update path too, so this is the same ordering guarantee deploy/rolling-update.sh
# gives compose: the schema first, then every server on the new image. A fresh database is
# already current and this is a no-op.
#
# ⚠️ THE TRIGGER GENERATOR IS A ONE-SHOT POD OF $IMAGE, NOT AN EXEC INTO A RUNNING POD. The
# running servers hold the image being rolled AWAY from, whose generator writes the old key map.
apply_schema() {
    _prim="$1"
    echo "==> Applying schema steps (on $_prim)"
    PSQL="kubectl exec -i -n $NAMESPACE $_prim -c postgres -- psql -U $PG_USER -d $PG_DB"
    MESH_BIN="kubectl run fastpki-mesh-triggers -n $NAMESPACE --rm -i --quiet --restart=Never --pod-running-timeout=5m --image=$IMAGE --image-pull-policy=$IMAGE_PULL_POLICY --command -- fastpki-mesh"
    export PSQL MESH_BIN
    kubectl delete pod fastpki-mesh-triggers -n "$NAMESPACE" --ignore-not-found --wait >/dev/null 2>&1 || true
    _rc=0
    bash "$DEPLOY_DIR/schema-apply.sh" || _rc=$?
    kubectl delete pod fastpki-mesh-triggers -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
    if [ "$_rc" -ne 0 ]; then
        echo "FAIL: the schema step did not complete — nothing was updated to the new image." >&2
        exit 1
    fi
}

SCHEMA_DONE=""
if kubectl get statefulset fastpki-node -n "$NAMESPACE" >/dev/null 2>&1; then
    if _p=$(primary_pod); then
        apply_schema "$_p"
        SCHEMA_DONE=1
    fi
fi

# ── 5. The servers ─────────────────────────────────────────────────────────
echo "==> Applying $NODE_COUNT server(s): the fastpki-node StatefulSet and its headless Service"
render "$MANIFESTS/node-statefulset.yaml" | kubectl apply -n "$NAMESPACE" -f -

# ⚠️ THE STANDBY CANNOT VERIFY THE PRIMARY UNTIL IT HAS THE PRIMARY'S ANCHOR. Before any CA exists
# each server's database serves the pair certgen self-signed in its init container, and no pod
# can derive another's. Compose carries the anchor across by hand (ha-join.sh); here each
# server's /var/pki/tls/pg/ca.crt is collected into fastpki-pg-anchors, which every pod mounts, and the
# standby — waiting to seed — verifies its primary within about a minute of this running.
publish_anchors() {
    _dir="$TMPDIR/anchors"; rm -rf "$_dir"; mkdir -p "$_dir"
    _i=0; _got=0
    while [ "$_i" -lt "$NODE_COUNT" ]; do
        if kx "fastpki-node-$_i" postgres cat /pki/tls/pg/ca.crt > "$_dir/fastpki-node-$_i.pem" 2>/dev/null \
           && grep -q 'BEGIN CERTIFICATE' "$_dir/fastpki-node-$_i.pem"; then
            _got=$((_got + 1))
        else
            rm -f "$_dir/fastpki-node-$_i.pem"
        fi
        _i=$((_i + 1))
    done
    [ "$_got" -gt 0 ] || return 1
    # ⚠️ AND THIS PKI'S ROOTS, ONCE ANY SERVER HAS CACHED THEM. A server rebuilt later — its /var/pki
    # claim deleted with its node — starts with no cached roots and only these anchors, and has to
    # verify a peer that has long since moved to a CA-issued database certificate. Its peer's
    # ca.crt carries that root only if the peer re-issued before this last ran; the roots file
    # does not depend on that.
    _i=0
    while [ "$_i" -lt "$NODE_COUNT" ]; do
        if kx "fastpki-node-$_i" postgres cat /pki/tls/pg/roots.pem > "$_dir/roots.pem" 2>/dev/null \
           && grep -q 'BEGIN CERTIFICATE' "$_dir/roots.pem"; then
            break
        fi
        rm -f "$_dir/roots.pem"
        _i=$((_i + 1))
    done
    kubectl create configmap fastpki-pg-anchors -n "$NAMESPACE" --from-file="$_dir" \
        --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    [ "$_got" -eq "$NODE_COUNT" ]
}

echo "    Waiting for every server's database certificate (the init containers)..."
_n=0
until publish_anchors; do
    _n=$((_n + 1))
    if [ "$_n" -ge 60 ]; then
        echo "FAIL: not every server produced its database certificate within 5 minutes." >&2
        kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/component=node -o wide >&2 || true
        # ⚠️ SAY WHY EACH SERVER IS STUCK, NOT ONLY fastpki-node-0'S LOG. A server the scheduler never
        # placed has no log at all, and the reason is in its events: measured with HA_ENABLED=true
        # on a one-node cluster, fastpki-node-1 sat Pending on "didn't match pod anti-affinity rules"
        # while this printed fastpki-node-0's healthy init log.
        _ready=$(kubectl get nodes --no-headers 2>/dev/null | grep -c ' Ready' || true)
        _i=0
        while [ "$_i" -lt "$NODE_COUNT" ]; do
            if [ "$(kubectl get pod -n "$NAMESPACE" "fastpki-node-$_i" -o jsonpath='{.status.phase}' 2>/dev/null)" = Pending ]; then
                _why=$(kubectl get events -n "$NAMESPACE" \
                         --field-selector "involvedObject.name=fastpki-node-$_i,reason=FailedScheduling" \
                         -o jsonpath='{.items[-1:].message}' 2>/dev/null || true)
                echo "  fastpki-node-$_i was never scheduled: ${_why:-no reason recorded}" >&2
                case "$_why" in *anti-affinity*)
                    echo "  Each server runs on a node of its own, and this cluster has $_ready ready node(s)" >&2
                    echo "  for $NODE_COUNT server(s). Join another machine to the cluster (docs/deployment.md" >&2
                    echo "  8.0b), or set HA_ENABLED=false for one server." >&2 ;;
                esac
            else
                echo "  fastpki-node-$_i, the last lines of its init container:" >&2
                kubectl logs -n "$NAMESPACE" "fastpki-node-$_i" -c init --tail=30 >&2 || true
            fi
            _i=$((_i + 1))
        done
        exit 1
    fi
    sleep 5
done
echo "    Published $NODE_COUNT database anchor(s) to fastpki-pg-anchors."

echo "==> Waiting for the primary database"
_n=0
until PRIMARY=$(primary_pod); do
    _n=$((_n + 1))
    if [ "$_n" -ge 60 ]; then
        echo "FAIL: no server has a read-write database after 5 minutes. Logs of fastpki-node-0:" >&2
        kubectl logs -n "$NAMESPACE" fastpki-node-0 -c postgres --tail=30 >&2 || true
        exit 1
    fi
    sleep 5
done
echo "    $PRIMARY is the primary."

# A first deploy's schema step, now that there is a database.
[ -n "$SCHEMA_DONE" ] || apply_schema "$PRIMARY"

# ⚠️ REGISTER THIS DATA CENTER'S ROW, again. A new database already has it from initdb (above, at
# the ConfigMap); this covers one that predates a change of DC_INDEX. Without it est, acme, cmp,
# scep, ms and web refuse to start ("DATACENTER_ID=N has no row in `datacenters`") while ocsp and
# store, which do not issue, run happily. This cluster's index IS its serial prefix, so the row
# needs no topology file.
echo "==> Registering this cluster as data center '$DC_INDEX' (its serial prefix)"
kx "$PRIMARY" postgres psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 -q -c \
    "INSERT INTO datacenters(dc_id, serial_prefix) VALUES('$DC_INDEX', $DC_INDEX)
       ON CONFLICT (dc_id) DO UPDATE SET serial_prefix=EXCLUDED.serial_prefix;" \
  || { echo "FAIL: could not register the datacenters row — the issuing services would not start." >&2; exit 1; }

# ── 6. The console admin ──────────────────────────────────────────────────
# The database half of bootstrap.sh, once for the deployment (the file half runs in every pod's
# init container). admin/admin, forced to change at first sign-in; --if-absent never resets an
# admin whose password has already been changed.
echo "==> Seeding the console admin (admin/admin, must be changed at first sign-in)"
_n=0
until kx "$PRIMARY" renew fastpki-config --config /app/config/bootstrap.conf \
        web-user admin admin --role admin --must-reset --if-absent >/dev/null 2>&1; do
    _n=$((_n + 1))
    if [ "$_n" -ge 40 ]; then
        echo "FAIL: could not seed the console admin — the renew container of $PRIMARY never reached the database." >&2
        kubectl logs -n "$NAMESPACE" "$PRIMARY" -c renew --tail=20 >&2 || true
        exit 1
    fi
    sleep 3
done

# Which protocols this deployment runs, recorded where the console reads it — the same row the
# compose path's bootstrap.sh writes, so the console tells "not installed" from "switched off".
echo "==> Recording which protocols this deployment runs"
for _p in EST ACME CMP SCEP MS STORE; do
    eval "_v=\${${_p}_INSTALLED:-true}"
    kx "$PRIMARY" renew fastpki-config --config /app/config/bootstrap.conf set "${_p}_INSTALLED" "$_v" \
        >/dev/null 2>&1 || echo "    WARNING: could not record ${_p}_INSTALLED" >&2
done

# ── 7. Services ───────────────────────────────────────────────────────────
echo "==> Applying the protocol Services and the web Service"
render "$MANIFESTS/service-protocols.yaml" | kubectl apply -n "$NAMESPACE" -f -
# ⚠️ A PROTOCOL SWITCHED OFF LOSES ITS SERVICE TOO. `kubectl apply` only adds and updates, so a
# Service left over from when the protocol was on would keep its address and answer nothing.
for _p in est acme cmp scep ms store; do
    eval "_v=\${$(printf '%s' "$_p" | tr '[:lower:]' '[:upper:]')_INSTALLED:-true}"
    [ "$_v" = true ] || kubectl delete service "fastpki-$_p" -n "$NAMESPACE" --ignore-not-found >/dev/null
done
envsubst < "$MANIFESTS/service-web.yaml" | kubectl apply -n "$NAMESPACE" -f -

# ── 7b. The interconnect, one address per server ───────────────────────────
_ic=$(interconnect_services)
[ -z "$_ic" ] || printf '%s\n' "$_ic" | kubectl apply -n "$NAMESPACE" -f -

# ── 8. Ingress (optional) ─────────────────────────────────────────────────
if [ "$INGRESS_ENABLED" = "true" ]; then
    echo "==> Applying Ingress"
    envsubst < "$MANIFESTS/ingress.yaml" | kubectl apply -n "$NAMESPACE" -f -
fi

if [ "${AUDITFWD_ENABLED:-false}" = "true" ] && \
   ! grep -qE '^AUDIT_FORWARD[[:space:]]*=[[:space:]]*(syslog|hec)' "$PKI_CONF"; then
    # ⚠️ SAY IT HERE, NOT VIA A CRASHLOOP. With no sink configured the forwarder exits, and that
    # arrives as a container restarting every few seconds long before anyone reads its log.
    echo "    NOTE: AUDIT_FORWARD is not set to syslog or hec, so the forwarder has no sink and"
    echo "          will exit on start. Set it in the config before enabling AUDITFWD_ENABLED."
fi

echo "==> Waiting for every server to be ready"
kubectl rollout status statefulset/fastpki-node -n "$NAMESPACE" --timeout=600s || {
    echo "WARNING: not every server became ready within 10 minutes:" >&2
    kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/component=node -o wide >&2 || true
}

# ── 9. Service credentials, now rather than tonight ─────────────────────────────
#
# ⚠️ THE LISTENERS REFUSE EVERY TRANSACTION UNTIL THESE EXIST. The OCSP responder, CMP RA and SCEP
# RA credentials can only be minted once a signing CA exists, and on a fresh cluster the CAs are
# created in the console AFTER this script runs. Each server's renewal loop creates them on its
# next pass; running the sweep here means a re-apply after creating the CAs fixes it at once.
#
# Every server's trust bundle is refreshed FIRST: the sweep may switch a database to a CA-issued
# certificate, and the other server has to trust that CA's root before it does (pg-trust.sh).
echo "==> Creating any missing service credentials"
_i=0
while [ "$_i" -lt "$NODE_COUNT" ]; do
    kx "fastpki-node-$_i" renew sh /scripts/pg-trust.sh --refresh-roots >/dev/null 2>&1 || true
    _i=$((_i + 1))
done
# ⚠️ ON EVERY SERVER, THE PRIMARY FIRST. The credentials and listener certificates are rows the
# first run creates for the whole deployment, but each server's DATABASE certificate names that
# server (PG_BIND) and is issued only by a sweep running in its own pod — so a sweep on the
# primary alone left the other server on its self-signed pair until its renewal loop came round,
# up to a day later. The primary goes first because only it can mint what the others then find.
# ⚠️ AND STRIP kubectl's TRANSPORT NOISE. On a first apply no signing CA exists, the command exits
# non-zero by design, and "command terminated with exit code 1" would read as a failed step.
_order="$PRIMARY"
_i=0
while [ "$_i" -lt "$NODE_COUNT" ]; do
    [ "fastpki-node-$_i" = "$PRIMARY" ] || _order="$_order fastpki-node-$_i"
    _i=$((_i + 1))
done
SVC_ALL=""
for _p in $_order; do
    # ⚠️ KEYS FIRST, EXACTLY AS renew-loop.sh ORDERS IT. A credential whose row exists and whose key
    # is not in this server's token is re-minted by --create-missing, taking it away from the
    # server that made it a moment ago — so the key is copied first, and the sweep may mint only
    # when no retry of the copy could help (renew-loop.sh has the exit codes).
    _create=--create-missing
    if [ "$P11_TLS" = "on" ]; then
        _ks=0
        kx "$_p" renew fastpki-ca --config /app/config/bootstrap.conf key sync --from-peers \
            >/dev/null 2>&1 || _ks=$?
        case "$_ks" in 0|2|3) ;; *) _create="" ;; esac
    fi
    SVC_OUT=$(kx "$_p" renew fastpki-ca --config /app/config/bootstrap.conf \
                renew-service-certs $_create --re-issue-self-signed 2>&1) && SVC_RC=0 || SVC_RC=$?
    SVC_OUT=$(printf '%s\n' "$SVC_OUT" | grep -v '^command terminated with exit code ')
    if [ "${SVC_RC:-0}" -ne 0 ] && printf '%s' "$SVC_OUT" | grep -q 'no issuing CA'; then
        echo "    no signing CA yet, so there are no service credentials to create."
        echo "    Create the root and issuing CAs (docs/deployment.md §4.3), then re-run"
        echo "    apply.sh — each server's renewal loop does the same thing nightly."
        break
    fi
    [ "$NODE_COUNT" -gt 1 ] && echo "    on $_p:"
    printf '%s\n' "$SVC_OUT" | sed 's/^/    /'
    SVC_ALL="$SVC_ALL
$SVC_OUT"
done
# ⚠️ AND RESTART THE LISTENERS, SO THE CHECKS AN OPERATOR RUNS NEXT DO NOT RACE A RELOAD. Every
# listener picks a re-issued certificate up by itself within 30s, and ocsp and cmp a new
# credential within 20s, so this is not what makes them work — it is what makes them work NOW.
# Only the listener containers are restarted, on every server — never the pod, which would take
# its database down with it.
if printf '%s' "$SVC_ALL" | grep -qE '^(created|renewed|re-issued) '; then
    _i=0
    while [ "$_i" -lt "$NODE_COUNT" ]; do
        for _c in web est acme ms ocsp cmp scep; do
            kx "fastpki-node-$_i" "$_c" kill 1 >/dev/null 2>&1 || true
        done
        _i=$((_i + 1))
    done
    echo "    restarted the listeners on every server to pick up their new certificates"
    # And wait for them, so the summary below reports servers that are up rather than a
    # container caught mid-restart as `Error`.
    kubectl wait --for=condition=Ready pod -n "$NAMESPACE" -l app.kubernetes.io/component=node \
        --timeout=180s >/dev/null 2>&1 || true
fi
# ⚠️ REPUBLISH THE ANCHORS AFTER THE SWEEP. It may just have issued a server's CA-signed database
# certificate and appended the root to that server's ca.crt, and the copy published at the start
# of this run predates both — so a server rebuilt from here on would be handed anchors that
# cannot verify the certificate its peer now serves.
_i=0
while [ "$_i" -lt "$NODE_COUNT" ]; do
    kx "fastpki-node-$_i" renew sh /scripts/pg-trust.sh --refresh-roots >/dev/null 2>&1 || true
    _i=$((_i + 1))
done
publish_anchors >/dev/null 2>&1 || true

echo ""
echo "FastPKI deployed to namespace '$NAMESPACE': $NODE_COUNT server(s)."
_list="web($WEB_PORT) ocsp(8080)"
for _pp in est:8443 acme:8444 cmp:8445 ms:8446 store:8447 scep:8448; do
    eval "_v=\${$(printf '%s' "${_pp%%:*}" | tr '[:lower:]' '[:upper:]')_INSTALLED:-true}"
    [ "$_v" = true ] && _list="$_list ${_pp%%:*}(${_pp##*:})"
done
echo "Protocols: $_list"
kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/component=node -o wide 2>/dev/null \
    | sed 's/^/  /' || true
echo "  $PRIMARY holds the read-write database."
echo ""
echo "Reach the web console:"
if [ "$INGRESS_ENABLED" = "true" ]; then
    echo "  https://$INGRESS_HOST/"
elif [ "$WEB_SERVICE_TYPE" = "NodePort" ]; then
    echo "  kubectl -n $NAMESPACE get svc fastpki-web   # note the nodePort"
elif [ "$WEB_SERVICE_TYPE" = "LoadBalancer" ]; then
    echo "  kubectl -n $NAMESPACE get svc fastpki-web -w   # wait for EXTERNAL-IP"
else
    echo "  kubectl -n $NAMESPACE port-forward svc/fastpki-web $WEB_PORT:$WEB_PORT"
    echo "  # then https://localhost:$WEB_PORT/"
fi
# ⚠️ A RE-APPLY IS NOT A FIRST APPLY. Section 8 tells an operator to re-run this once the CAs
# exist, so ask the deployment rather than assuming there is nothing in it.
_cas=$(kx "$PRIMARY" renew fastpki-ca --config /app/config/bootstrap.conf list 2>/dev/null \
       | grep -c "	" || true)
if [ "${_cas:-0}" -eq 0 ]; then
    echo "  log in as admin / admin and change it at first login."
    echo "No CA yet — create the root and the issuing CAs in the console (CAs -> + New CA)."
    if [ "$NODE_COUNT" -gt 1 ]; then
        echo "  Tick 'replicable key' on EVERY CA, the root included: the second server can only"
        echo "  sign under a CA whose key can be copied into its own token."
    fi
else
    echo "  log in as admin."
    echo "$_cas CA instance(s) present; service credentials are created above."
fi

# ⚠️ IDENTITY AND POINTERS ONLY — DO NOT REPRINT THE MESH WALKTHROUGH HERE. It is in
# docs/deployment.md §9, and a printed copy is one that diverges from the docs nobody re-tests.
# Gated on PG_INTERCONNECT, the honest discriminator (see the top of this file).
if [ -n "${PG_INTERCONNECT:-}" ]; then
    echo ""
    echo "This cluster: data center $DC_INDEX — that index IS its certificate-serial prefix."
    echo "  Peers reach its servers' databases at $PG_INTERCONNECT (port 5432), already recorded"
    echo "  as PG_TLS_SANS."
    # ⚠️ A RE-APPLY IS ALSO AN UPGRADE, so ask the database whether this cluster is already
    # meshed. Printed unconditionally, "it does not replicate yet" told the operator of a working
    # mesh to connect it again on every upgrade. A database that knows more than one data center
    # is meshed: that row set replicates, so the answer is the same on every pod. The same test
    # as the native installer's closing text.
    _dcs=$(kx "$PRIMARY" postgres psql -U "$PG_USER" -d "$PG_DB" -tAqc 'SELECT count(*) FROM datacenters' \
           2>/dev/null | tr -d '[:space:]' || true)
    if [ "${_dcs:-0}" -gt 1 ] 2>/dev/null; then
        echo "It is already part of a mesh of $_dcs data centers and keeps replicating; there is"
        echo "  nothing to connect. docs/deployment.md 9.2 is the check."
    else
        # The topology, its anchor path inside the postgres container (/pki, not the apps'
        # /var/pki) and both passes are deploy/mesh-join.sh's job, the same command on every
        # deployment path.
        echo "It does not replicate yet. Connect it from a machine with kubectl access to every"
        echo "cluster, one context each:"
        echo "  deploy/mesh-join.sh k8s:<this cluster's context>/$NAMESPACE k8s:<peer's context>/<namespace> ..."
        echo "  Its first run stops until each cluster has a sub CA under one root; run it again after."
        echo "  docs/deployment.md 9.0 is the sequence, 9.3 the Kubernetes specifics, 9.2 the check."
    fi
fi
