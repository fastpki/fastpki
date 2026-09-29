#!/bin/sh
# Publish a dns-01 challenge TXT record through CoreDNS, and be the ONE way the demo does
# that.
#
# Two callers, one mechanism:
#   * certbot, as --manual-auth-hook. It supplies CERTBOT_DOMAIN and CERTBOT_VALIDATION in
#     the environment and passes no arguments.
#   * tests/acme_jws.sh's shell ACME client, via ACME_DNS_PUBLISH_HOOK, which calls
#     `dns-auth.sh <owner-name> <txt-value>` with the owner already fully qualified.
#
# It used to be the first only, and the wildcard cell ran build/dnsstub instead — two
# resolvers for one job. CoreDNS is the one a real deployment would actually meet, so it is
# the one both cells use; dnsstub stays where the suites already depend on it.
#
# ── WHERE CoreDNS RUNS ────────────────────────────────────────────────────────────────
#
# On the machine that hosts the ACME server, always. Not on the machine running the demo.
#
# ⚠️ THAT IS THE POINT, and the first version got it backwards. Running the resolver here
# and pointing the deployment at it requires the DEPLOYMENT to reach BACK to this machine
# on a UDP port — which needs inbound reachability, a published port, and Docker on the
# operator's laptop, none of which is a safe assumption. Running it beside the ACME service
# needs none of that: the demo only has to reach the deployment, which it already does, and
# the query never leaves that host. DNS_SSH_TARGET selects it.
set -u

DOMAIN_ARGS=$#
if [ $# -ge 2 ]; then
    OWNER="$1"; VALUE="$2"
else
    OWNER="_acme-challenge.${CERTBOT_DOMAIN:-acme-demo.internal}"
    VALUE="${CERTBOT_VALIDATION:-placeholder}"
fi
: "$DOMAIN_ARGS"
# The zone is the owner minus the _acme-challenge label; CoreDNS needs a zone to serve.
ZONE=${OWNER#_acme-challenge.}

COREFILE_BODY="$ZONE.:15353 {
    log
    template IN TXT $OWNER {
        answer \"{{ .Name }} 60 IN TXT \\\"$VALUE\\\"\"
    }
}"

if [ -n "${DNS_K8S_NAMESPACE:-}" ]; then
    # ── in the cluster ─────────────────────────────────────────────────────────────────
    # Same shape as the SSH branch below and for the same reason: CoreDNS runs BESIDE the
    # deployment, so fastpki-acme reaches it by Service name and the query never leaves the
    # cluster. Pointing the ACME server at the machine running the demo would need inbound
    # reachability and a published UDP port — assumptions that do not hold for a cluster.
    _ns="$DNS_K8S_NAMESPACE"
    kubectl -n "$_ns" delete configmap fastpki-dns >/dev/null 2>&1 || true
    kubectl -n "$_ns" create configmap fastpki-dns --from-literal=Corefile="$COREFILE_BODY" >/dev/null
    # Applied every call: the ConfigMap changes per challenge, and a subPath-free mount plus
    # a rollout restart is what makes CoreDNS actually re-read it.
    kubectl -n "$_ns" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastpki-dns
spec:
  replicas: 1
  selector: { matchLabels: { app: fastpki-dns } }
  template:
    metadata:
      labels: { app: fastpki-dns }
    spec:
      containers:
        - name: coredns
          image: coredns/coredns
          args: ["-conf", "/config/Corefile"]
          ports: [{ containerPort: 15353, protocol: UDP }]
          volumeMounts: [{ name: cfg, mountPath: /config }]
      volumes:
        - name: cfg
          configMap: { name: fastpki-dns }
---
apiVersion: v1
kind: Service
metadata:
  name: fastpki-dns
spec:
  selector: { app: fastpki-dns }
  ports: [{ port: 15353, targetPort: 15353, protocol: UDP }]
YAML
    # ⚠️ THE POD MUST BE REPLACED, NOT MERELY NUDGED, and the new one must be serving
    # before this returns. The zone changes per challenge — one cell asks for
    # acme-demo.internal and the next for wild-demo.internal — and CoreDNS's template
    # plugin is static, so an old pod keeps answering the previous zone and the server
    # reports "dns-01 TXT record missing or mismatched", which reads as a challenge fault
    # rather than a stale resolver. Deleting the pod outright is deterministic where a
    # rollout restart races the caller.
    kubectl -n "$_ns" delete pod -l app=fastpki-dns --ignore-not-found --wait >/dev/null 2>&1 || true
    kubectl -n "$_ns" rollout status deploy/fastpki-dns --timeout=120s >/dev/null 2>&1 || true
    kubectl -n "$_ns" wait --for=condition=Ready pod -l app=fastpki-dns --timeout=60s >/dev/null 2>&1 || true
    sleep 2   # the listener binds a moment after the pod reports Ready
    exit 0
fi
if [ -n "${DNS_SSH_TARGET:-}" ]; then
    # ── on the deployment ──────────────────────────────────────────────────────────────
    # Join whatever network the acme service is on, so it can be reached by container name
    # (fastpki-dns:15353) with nothing exposed to the outside world.
    # ⚠️ THE SCRIPT AND THE DATA NEED SEPARATE CHANNELS. The first version piped the
    # Corefile into an ssh whose stdin was ALREADY a heredoc carrying the script; the
    # heredoc wins, the remote `cat` read an exhausted stdin, and CoreDNS started on an
    # empty config, exited, and was removed by --rm. The visible symptom was two cells
    # failing with "dns-01 TXT record missing or mismatched" and no container to inspect.
    # Script over stdin, Corefile as a base64 argument.
    _b64=$(printf '%s\n' "$COREFILE_BODY" | base64 | tr -d '\n')
    ssh ${DNS_SSH_OPTS:-} "$DNS_SSH_TARGET" "sh -s -- $_b64" <<'RSH' >/dev/null 2>&1
set -u
d=/tmp/fastpki-demo-dns
mkdir -p "$d"
printf '%s' "$1" | base64 -d > "$d/Corefile"
a=$(docker ps --format "{{.Names}}" | grep -m1 -iE "acme")
[ -n "$a" ] || exit 3
net=$(docker inspect "$a" --format "{{range \$k,\$v := .NetworkSettings.Networks}}{{\$k}} {{end}}" | awk '{print $1}')
[ -n "$net" ] || exit 4
docker rm -f fastpki-dns >/dev/null 2>&1 || true
docker run -d --rm --name fastpki-dns --network "$net" \
    -v "$d:/config" coredns/coredns -conf /config/Corefile >/dev/null 2>&1
sleep 2
docker ps --format "{{.Names}}" | grep -qx fastpki-dns
RSH
    exit $?
fi

# ── beside a LOCAL compose stack ───────────────────────────────────────────────────────
# CoreDNS's file-plugin reload is not reliable across Docker on macOS (mtime is not
# propagated), so the container is recreated on each challenge — about a second.
CONFIG_DIR="${ZONE_DIR:-${ROOT:-/tmp}/demo/coredns}"
DNS_NET="${DNS_NET:-fastpki_default}"
mkdir -p "$CONFIG_DIR"
printf '%s\n' "$COREFILE_BODY" > "$CONFIG_DIR/Corefile"

docker stop fastpki-dns 2>/dev/null || true
docker rm -f fastpki-dns 2>/dev/null || true
# ⚠️ PUBLISH THE PORT WHEN THE TARGET CANNOT HOST THE RESOLVER. A native or cloud node has
# no docker to start a sibling container in and no cluster to make a Service in, so it
# reaches THIS container instead — which it can only do if the port is bound on this host
# rather than reachable solely on a private docker network.
#
# ⚠️ /udp, EXPLICITLY. A DNS query is a datagram and `-p a:b` publishes TCP only, so the
# server's lookup is dropped with nothing listening and the challenge is reported as
# "dns-01 TXT record missing or mismatched" — a record fault for what is a transport one.
# ⚠️ AND NO COMPOSE NETWORK WHEN THE POINT IS THE PUBLISHED PORT. DNS_NET names the network
# the LOCAL acme container sits on, so a sibling can be reached by name. A native target has
# no such network on this host, and `docker run --network <missing>` fails outright — the
# hook then exits 1 and certbot reports only "All authorizations were not finalized", which
# says nothing about a missing network. With the port published, the default bridge is what
# is wanted anyway.
if [ -n "${DNS_PUBLISH:-}" ]; then _net_arg=""; else _net_arg="--network $DNS_NET"; fi
docker run -d --rm --name fastpki-dns $_net_arg \
    ${DNS_PUBLISH:+-p ${DNS_PORT:-15353}:${DNS_PORT:-15353}/udp} \
    -v "$CONFIG_DIR:/config" \
    coredns/coredns -conf /config/Corefile >/dev/null 2>&1
sleep 2
# Report failure to the caller rather than leaving it to discover a pending authz later.
docker ps --format '{{.Names}}' 2>/dev/null | grep -qx fastpki-dns
