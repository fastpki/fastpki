#!/usr/bin/env bash
# Provision a FastPKI deployment for the demo and emit a target
# descriptor that demo/pki-demo.sh --target consumes.
#
# ONE PATH, THE CONSOLE API. Everything this needs is public over HTTPS: the API creates the
# demo user, names the CA, mints the per-user CMP, ACME and SCEP credentials, and reports the
# listener ports. So it works the same against docker compose, Kubernetes and a native or
# cloud node, from any machine that can reach the console — no ssh, no docker, no kubectl.
#
# ⚠️ IT USED TO HAVE FOUR MODES, and they were provisioning plumbing pretending to be
# different tests. `--k8s` read each listener's port from its Service with kubectl; the
# console reports them (GET /api/config returns EFFECTIVE values, so a port nobody set is
# still in the reply), and --web-url and --k8s were measured emitting identical ports against
# the same cluster. A bare ssh target read config and created the user through `docker exec`
# on the node; the API does that from here. Both are gone.
#
#   Local (no arguments)
#     A docker compose deployment on this machine, at https://localhost:8090 on the
#     shipped ports.
#
#   Any deployment (--web-url URL)
#     compose, Kubernetes or native, anywhere the console is reachable. The ports are read
#     back from the console rather than assumed.
#
# Two flags describe the DEPLOYMENT rather than how this script reaches it, because the demo
# needs them later and cannot infer either:
#
#   --namespace NS      Kubernetes. The demo creates the CoreDNS that answers the dns-01
#                       challenge beside the ACME service, and a Service that publishes this
#                       host for http-01 and tls-alpn-01. Both need the namespace.
#   --ssh-target U@H    A NATIVE node, for dns-01 only. There the resolver runs HERE and the
#                       deployment is told to ask it, which needs a login on the node. The
#                       other challenge types and every other protocol need nothing.
#                       With --namespace: a login on a machine where kubectl reaches the
#                       cluster, such as a k3s node. The demo runs every kubectl there, so
#                       this machine needs no kubeconfig of its own.
#
# ⚠️ NodePort IS NOT SUPPORTED. The cluster allocates the external port and the pod cannot
# know it, so the console reports the port the listener binds INSIDE the cluster. That is the
# same reason docs/deployment.md 8.6 tells operators not to use it: certificates' AIA and CRL
# DP URLs name the listener's port too, so under NodePort they advertise a port nothing
# outside answers on. Use LoadBalancer.
#
# Usage:
#   demo/provision-target.sh [--web-url URL] [--proto-host HOST] [--out FILE]
#                            [--namespace NS] [--challenge-fqdn NAME]
#                            [--user NAME] [--pass PASS]
#                            [--admin-user NAME] [--admin-pass PASS]
#                            [--admin-new-pass PASS] [--ssh-target USER@HOST]
#
# Examples:
#   demo/provision-target.sh                                          # local docker compose
#   demo/provision-target.sh --web-url https://pki.example.org        # native or cloud node
#   demo/provision-target.sh --web-url https://10.0.0.5:8090 --namespace fastpki   # a cluster
#   demo/provision-target.sh --web-url https://10.0.0.5:8090 --namespace fastpki \
#                            --ssh-target admin@10.0.0.5                           # ...over SSH
#   demo/pki-demo.sh --target demo/.target.env
set -u

SSH_TARGET=""; PROTO_HOST=""; OUT=""; USER="demo"; PASS="demo@Pass123"; WEBC=""; ADMIN_PASS="admin"
ADMIN_NEW_PASS=""
K8S=0; K8S_NS="fastpki"; K8S_NODE=""
# ⚠️ DEFAULTED FOR EVERY MODE, not just the one that discovers it. Only the remote path
# learns a challenge FQDN (from $SSH_CLIENT on the node); emit_descriptor tests it
# unconditionally, so under `set -u` any other mode aborts there — after provisioning has
# already succeeded, which is the worst place to stop.
#
# ⚠️ ACME http-01 AND tls-alpn-01 CANNOT WORK WITHOUT ONE. The server validates a challenge
# by connecting BACK to the identifier being claimed, so it has to be a name the deployment
# resolves to the machine running the demo. A cluster cannot guess that, and there is no
# $SSH_CLIENT to read it from — so --challenge-fqdn supplies it, and without it the ACME
# cells skip rather than failing in a way that looks like a server fault.
CHALLENGE_FQDN=""
# The administrative channel for a NATIVE deployment: a host with no container runtime, so
# neither `docker exec` nor kubectl reaches its CLI. Optional, and only dns-01 needs it.
NATIVE_SSH=""
# The console account this script signs in AS. It was hardcoded to `admin`, which is
# right for a fresh deployment (bootstrap seeds admin/admin) and wrong for every
# long-lived one: on the lab that password is not `admin` and is not ours to reset —
# it is a shared credential. Overridable so an operator can provision with their own
# admin, or a throwaway one, instead of changing a login other people use.
ADMIN_USER="admin"
SSH_OPTS=(-o StrictHostKeyChecking=no -o ConnectTimeout=10)
[ -f "$HOME/.ssh/fastpki_lab_ed25519" ] && SSH_OPTS+=(-i "$HOME/.ssh/fastpki_lab_ed25519")

while [ $# -gt 0 ]; do
  case "$1" in
    --proto-host) PROTO_HOST="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --user) USER="$2"; shift 2;;
    --pass) PASS="$2"; shift 2;;
    --web-container) WEBC="$2"; shift 2;;
    --admin-pass) ADMIN_PASS="$2"; shift 2;;
    --admin-new-pass) ADMIN_NEW_PASS="$2"; shift 2;;
    --admin-user) ADMIN_USER="$2"; shift 2;;
    # ⚠️ GONE: --k8s. It existed to read each listener's port from its Service with kubectl.
    # The console answers that now — GET /api/config carries EFFECTIVE values, so a port
    # nobody set is in the reply as the built-in default — and --web-url reads them from any
    # platform. Measured: --web-url and --k8s emitted identical ports against the same
    # cluster. What remains of "this is Kubernetes" is --namespace, which the demo needs to
    # create CoreDNS beside the ACME service; that is a fact about the deployment, not a mode.
    --k8s) echo "--k8s is gone: use --web-url https://<console> --namespace <ns>" >&2; exit 2;;
    --web-url) WEB_URL_IN="$2"; shift 2;;
    --challenge-fqdn) CHALLENGE_FQDN="$2"; shift 2;;
    --ssh-target) NATIVE_SSH="$2"; shift 2;;
    # ⚠️ RECORDED IN THE DESCRIPTOR FROM EVERY MODE, not only from --k8s. The namespace is
    # not how this script reaches the deployment — that is the console API — it is how the
    # DEMO creates the CoreDNS that answers the dns-01 challenge, which has to run next to
    # the ACME service and cannot be conjured over an API. Setting it only inside the --k8s
    # branch meant provisioning a cluster through --web-url produced a descriptor that did
    # not say it was a cluster, and every dns-01 cell skipped with "descriptor has no
    # SSH_TARGET or K8S_NAMESPACE" — about a deployment where kubectl was available and
    # working. Given explicitly, it belongs in the descriptor whatever mode found the ports.
    --namespace) K8S_NS="$2"; K8S_NS_OUT="$2"; shift 2;;
    --node) K8S_NODE="$2"; shift 2;;
    --compose-dir) shift 2;;
    -h|--help) sed -n '2,57p' "$0"; exit 0;;
    -*) echo "unknown arg: $1" >&2; exit 2;;
    # ⚠️ GONE: the bare <ssh-target> positional, which selected an SSH mode that read the
    # config and created the demo user through `docker exec` on the node. Everything it did
    # is done over the console API now, which needs no login on the deployment and works the
    # same against compose, Kubernetes and a native node. --ssh-target still exists, for the
    # one thing the API cannot do: dns-01 on a NATIVE node, where the resolver runs here and
    # the deployment has to be told to ask it.
    *) echo "provision-target: '$1' — the SSH provisioning mode is gone." >&2
       echo "  Use: --web-url https://<console-host>:<port>   (works for compose," >&2
       echo "       Kubernetes and native; add --namespace <ns> on a cluster)" >&2
       echo "  --ssh-target is still accepted, for dns-01 against a native node." >&2
       exit 2;;
  esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[ -n "$OUT" ]        || OUT="$ROOT/demo/.target.env"
[ -n "$PASS" ]       || PASS="demo"

# ── mode gate ──────────────────────────────────────────────────────────────────
if [ -n "${WEB_URL_IN:-}" ]; then
  # ⚠️ THE MODE FOR A DEPLOYMENT WITH NO CONTAINER RUNTIME. compose and Kubernetes are both
  # reached by asking their orchestrator — `docker compose ps`, `kubectl get deploy` — and a
  # node installed by deploy/native/install-native.sh has neither. That is what the cloud
  # image produces, so without this the demo and the benchmark cannot be pointed at a cloud
  # deployment at all: local mode stops at "docker compose not running" on a host that is
  # running FastPKI perfectly well under OpenRC.
  #
  # Everything it needs is already public over HTTPS — the console API provisions the user
  # and names the CA — so this mode asks the deployment rather than the machine, and works
  # equally against compose, Kubernetes or bare metal from anywhere that can reach 8090.
  MODE=native
  # ⚠️ AND THE ADMINISTRATIVE CHANNEL, IF ONE WAS OFFERED. Everything above is done over
  # the console API, which is why this mode needs no SSH — but dns-01 is not: the server
  # has to be told to ask a resolver this demo controls, and that means writing
  # ACME_DNS_RESOLVER and restarting fastpki-acme, which the demo user cannot do. On
  # compose that goes through `docker exec` and on Kubernetes through kubectl; a native
  # node has neither, so it is plain ssh to the host's own CLI. Recorded only when
  # --ssh-target was given, so the no-SSH promise still holds for everyone who does not
  # need dns-01.
  #
  # Set AFTER the mode is decided: a non-empty SSH_TARGET is what selects `remote` above.
  SSH_TARGET="$NATIVE_SSH"
  # ⚠️ --web-url SAYS HOW THIS SCRIPT REACHES THE CONSOLE, NOT WHAT THE DEPLOYMENT RUNS ON.
  # It is the API-only path, and a cluster can be provisioned through it perfectly well —
  # which is the point of reading the ports from /api/config rather than from an
  # orchestrator. But DEPLOY_MODE=native tells pki-demo.sh to use the NATIVE dns-01 wiring:
  # keep CoreDNS on the client and have the deployment reach BACK to it, which needs a name
  # that resolves here. On a cluster that is both wrong and unnecessary — CoreDNS belongs
  # beside the ACME service, where the query never leaves the cluster — and the cell skipped
  # asking for a CHALLENGE_FQDN it had no reason to need.
  #
  # A namespace is the operator saying "this is a cluster", so it decides the wiring.
  #
  # ⚠️ AND THERE IS A THIRD SHAPE: DOCKER COMPOSE REACHED REMOTELY. Treating every
  # non-Kubernetes --web-url target as native is the very mistake the paragraph above
  # warns about, applied one shape further down. It made pki-demo.sh reach for the native
  # administrative channel — `doas -u fastpki fastpki-config --config
  # /etc/fastpki/bootstrap.conf` — on a node that has neither doas nor that file, so
  # writing ACME_DNS_RESOLVER failed and BOTH dns-01 cells skipped with "could not write
  # ACME_DNS_RESOLVER on the target". The deployment was healthy; only the channel was
  # wrong. Measured against a compose deployment driven from another host.
  #
  # Ask the node instead of inferring from how we reached it. A running web container
  # means compose, which also selects the correct dns-01 wiring downstream (CoreDNS beside
  # the deployment, rather than on the client with the deployment reaching back). Probed
  # only when --ssh-target was given, so the no-SSH promise still holds for everyone else;
  # without a target the answer cannot be checked and native stays the assumption.
  if [ -n "${K8S_NS_OUT:-}" ]; then
    DEPLOY_MODE_OUT=""
    # ⚠️ ON A CLUSTER THE LOGIN IS FOR kubectl, NOT FOR THE COMPOSE OR NATIVE CHANNEL. Kept
    # out of SSH_TARGET, because every consumer of that key reaches for `docker exec` or the
    # native CLI, and a k3s node has neither.
    K8S_SSH_OUT="$SSH_TARGET"; SSH_TARGET=""
  elif [ -n "$SSH_TARGET" ] && ssh "${SSH_OPTS[@]}" -o BatchMode=yes "$SSH_TARGET" \
         'docker ps --format "{{.Names}}" 2>/dev/null | grep -qiE "web"' 2>/dev/null; then
    DEPLOY_MODE_OUT=""
  else
    DEPLOY_MODE_OUT=native
  fi
else
  MODE=local
fi

# ⚠️ A NAMESPACE IS A PROMISE THAT THE DEMO CAN REACH THE CLUSTER, so check it now. Every
# ACME cell on a cluster runs kubectl, and without access they did not fail: they skipped,
# after every other protocol had run, with advice to re-run this script. Measured from a Mac
# with no kubeconfig against a k3s deployment: 4 of 4 ACME cells skipped.
if [ -n "${K8S_NS_OUT:-}" ]; then
  if [ -n "${K8S_SSH_OUT:-}" ]; then
    _kc=(ssh "${SSH_OPTS[@]}" -o BatchMode=yes "$K8S_SSH_OUT" kubectl)
  else
    _kc=(kubectl)
  fi
  if ! "${_kc[@]}" -n "$K8S_NS_OUT" get statefulset fastpki-node -o name >/dev/null 2>&1; then
    echo "ERR: --namespace $K8S_NS_OUT, but kubectl ${K8S_SSH_OUT:+on $K8S_SSH_OUT }cannot see" >&2
    echo "     statefulset/fastpki-node in it. The demo's ACME steps need kubectl access." >&2
    if [ -z "${K8S_SSH_OUT:-}" ]; then
      echo "     Add --ssh-target USER@NODE, a login on a machine where kubectl works, and" >&2
      echo "     the demo runs kubectl there." >&2
    fi
    exit 1
  fi
fi
mkdir -p "$(dirname "$OUT")"
COOKIE="$(dirname "$OUT")/.provision-cookies"

# ── the ONE descriptor writer, for both modes ──────────────────────────────────
#
# ⚠️ THERE USED TO BE TWO, AND THEY HAD DRIFTED. Each mode ended in its own
# `{ ... } > "$OUT"` block, and the remote one emitted 15 keys where the local one emitted
# 17: no CA_ID and no DEMO_DOMAIN. CA_ID is not optional — `pki-bench.sh --target` stops
# at `CA_ID: target file missing CA_ID`, so provisioning a real deployment over SSH
# produced a descriptor that could not drive either demo, while the script exited 0 and
# printed "✓ wrote". The remote block had also never picked up the checked write that the
# local one carries, so it had exactly the silent-stale-descriptor failure the comment
# below was written about.
#
# The drift was the defect, not either missing key. So there is one writer now, it takes
# its values from variables both modes set, and tests/demo_target_descriptor.sh diffs the
# key sets the two modes produce so they cannot separate again.
#
# Callers set: TARGET_HOST, MODE_NOTE, CA_ID, DEMO_DOMAIN and the twelve port/path vars.
emit_descriptor() {
  {
    echo "# FastPKI demo target — generated by provision-target.sh $(date -u +%FT%TZ)"
    echo "# $MODE_NOTE"
    echo "TARGET_HOST=$TARGET_HOST"
    echo "DEMO_USER=$USER"
    echo "DEMO_PASS=$PASS"
    # Written only when discovered. An empty CA_ID= would satisfy pki-bench.sh's
    # `${CA_ID:?}` check and then build `/.well-known/est//cacerts`, turning a clear
    # "missing CA_ID" into a 404 halfway through a run.
    [ -n "$CA_ID" ]      && echo "CA_ID=$CA_ID"
    [ -n "$DEMO_DOMAIN" ] && echo "DEMO_DOMAIN=$DEMO_DOMAIN"
    # ⚠️ THE CONSOLE PORT IS PART OF THE DESCRIPTOR. pki-bench.sh and pki-demo.sh both
    # read WEB_PORT (defaulting to 8090) to reach /api/login and /api/enrolment-credentials
    # — where the CMP secret, ACME EAB and per-user SCEP challenge come from. Omitting it
    # is invisible on compose, where 8090 is right, and silently wrong anywhere the console
    # is published elsewhere: the credential fetch fails, and every CMP and SCEP cell then
    # enrols with no secret and is refused.
    # ⚠️ THE DESCRIPTOR HAS TO SAY WHICH KIND OF DEPLOYMENT THIS IS. The demo needs
    # administrative access for one thing only — repointing ACME_DNS_RESOLVER at a resolver
    # it controls, and putting it back — and how to get it differs: SSH_TARGET plus
    # `docker exec` for compose, kubectl for a cluster. Without this the dns-01 cells skip
    # with "descriptor has no SSH_TARGET", which is true and unhelpful on Kubernetes.
    [ -n "${K8S_NS_OUT:-}" ] && echo "K8S_NAMESPACE=$K8S_NS_OUT"
    # Where the demo runs kubectl, when it is not on this machine.
    [ -n "${K8S_SSH_OUT:-}" ] && echo "K8S_SSH_TARGET=$K8S_SSH_OUT"
    # ⚠️ AND THE THIRD KIND. A native node has no container runtime and no cluster, so the
    # demo reaches its CLI over plain ssh — a different command for the same job, which it
    # cannot infer from SSH_TARGET alone because compose targets carry one too.
    [ -n "${DEPLOY_MODE_OUT:-}" ] && echo "DEPLOY_MODE=$DEPLOY_MODE_OUT"
    echo "WEB_PORT=${WEB_PORT:-8090}"
    echo "EST_PORT=$EST_PORT";     echo "EST_BASE_PATH=$EST_BASE_PATH"
    echo "CMP_PORT=$CMP_PORT";     echo "CMP_PATH=$CMP_PATH"
    echo "OCSP_PORT=$OCSP_PORT";   echo "OCSP_PATH=$OCSP_PATH"
    echo "STORE_PORT=$STORE_PORT"; echo "STORE_PATH=$STORE_PATH"
    echo "SCEP_PORT=$SCEP_PORT";   echo "SCEP_PATH=$SCEP_PATH"
    echo "ACME_PORT=$ACME_PORT";   echo "ACME_BASE_PATH=$ACME_BASE_PATH"
    # ⚠️ MS TOO, WHICH WAS MISSING IN EVERY MODE. pki-demo.sh's TLS probe reads
    # ${MS_PORT:-8446}, so on compose the default happened to be right and nothing showed.
    # On Kubernetes it is a nodePort or a LoadBalancer port, and the probe then reported
    # "MS TLS on :8446 ... skipped (nothing listening)" about a listener that was serving
    # perfectly — the one protocol of eight whose port the descriptor never carried.
    echo "MS_PORT=$MS_PORT"
    # ⚠️ THE ACME SERVER VALIDATES BY CONNECTING BACK TO THE CLIENT, so the http-01 and
    # tls-alpn-01 cells need a name THIS deployment can resolve to the machine running the
    # demo. Against a local compose stack the demo teaches the container a route; against a
    # remote one it cannot, and the server rightly answers "the identifier does not
    # resolve". Detected on the node from $SSH_CLIENT rather than asked of the operator,
    # who would have to know what the deployment's resolver calls their own machine.
    if [ -n "$CHALLENGE_FQDN" ]; then
      echo "CHALLENGE_FQDN=$CHALLENGE_FQDN"
      # ⚠️ dns-01 needs MORE than a name: the server has to be told to ask THIS host for the
      # challenge TXT, which means writing ACME_DNS_RESOLVER on the deployment and putting
      # it back afterwards. That is administrative access, which the demo user does not
      # have — so record the SSH target we already used here. Without it the dns-01 cells
      # skip; with it they repoint the resolver, run, and restore.
      echo "SSH_TARGET=$SSH_TARGET"
    elif [ -z "${K8S_NS_OUT:-}" ]; then
      # A cluster needs neither key: the demo publishes this host to it as a Service.
      # ⚠️ NAME BOTH KEYS, because setting only the obvious one still skips. Two different
      # cells need two different things: http-01 and tls-alpn-01 need CHALLENGE_FQDN, while
      # dns-01 needs that AND an SSH target, which is how ACME_DNS_RESOLVER gets repointed at
      # this host and put back. An operator who fills in just the name gets the dns-01 cells
      # skipping with a message advising a re-run of this script — which reverse-resolves no
      # better the second time. Measured on a load-balanced pair, where the deployment could
      # not name the machine driving the demo.
      echo "# CHALLENGE_FQDN=   # the target could not reverse-resolve this host; set it by"
      echo "#                   # hand to a name it resolves here, or the two privileged"
      echo "#                   # ACME challenges will skip"
      echo "# SSH_TARGET=$SSH_TARGET   # uncomment this as well, or dns-01 still skips: it"
      echo "#                   # needs admin access to repoint ACME_DNS_RESOLVER and restore it"
    fi
    # The enrolment credentials are deliberately NOT here. The demos read them at run
    # time from /api/enrolment-credentials as the demo user, because an admin no longer
    # receives another user's secrets back and a descriptor on disk is the wrong place
    # for an authentication secret that can be rotated.
  # ⚠️ CHECK THE WRITE. There is no `set -e` here, so a failed redirect printed bash's
  # "Permission denied" and then this script printed "✓ wrote $OUT" on the next line and
  # exited 0. Measured: a root-owned /tmp/demo.target.env from a previous run made a fresh
  # provision silently leave a TWO-DAY-OLD descriptor in place, and the demo then drove the
  # wrong ports and the wrong CA — failures that read as product bugs and are not.
  #
  # A descriptor is the demo's entire idea of what it is talking to. Getting a stale one is
  # worse than getting none, because none stops.
  } > "$OUT" || { printf 'ERR: could not write %s\n' "$OUT" >&2; exit 1; }
  [ -s "$OUT" ] || { printf 'ERR: %s is empty after writing\n' "$OUT" >&2; exit 1; }
  chmod 600 "$OUT" || { printf 'ERR: could not chmod %s\n' "$OUT" >&2; exit 1; }

  echo "✓ wrote $OUT"
  if [ -z "$CA_ID" ]; then
    echo "  ⚠️ no CA_ID — pki-bench.sh --target will refuse, and pki-demo.sh will skip" >&2
    echo "     every enrolment step. No CA on this deployment served EST /cacerts." >&2
  fi
  echo
  echo "  Run the demo against it:"
  echo "    demo/pki-demo.sh --target $OUT"
}

# ── where the deployment answers ───────────────────────────────────────────────
#
# ⚠️ COMPOSE PORTS ARE FIXED; KUBERNETES PORTS ARE ASSIGNED. On compose every listener is
# published on its well-known port, so they can be written down. On Kubernetes a Service of
# type NodePort gets a port from the cluster's range at creation time, different on every
# deployment — so they have to be READ BACK, not assumed. Both modes end with the same
# variables set, which is what lets the provisioning flow below be shared.
discover_endpoints() {
    if [ "$MODE" = native ]; then
        # Ports are the shipped defaults, as on compose: install-native.sh binds each
        # listener on its well-known port and nothing reassigns them. --proto-host wins for
        # the protocol endpoints, so a deployment whose console is reached by one name and
        # whose protocols are advertised under another still produces a usable descriptor.
        WEB_URL="${WEB_URL_IN%/}"
        _wu="${WEB_URL#*://}"; _wh="${_wu%%/*}"
        # ⚠️ AN IPv6 LITERAL IS ALL COLONS, so "the port is after the last colon" is wrong
        # for exactly the addresses our own cloud module hands out. Splitting
        # https://[2600:1f18:7c6e:5102::d6e9] on ':' produced TARGET_HOST=[2600 and
        # WEB_PORT=d6e9], every probe then went nowhere, and the visible symptom was
        # "no CA on this deployment serves EST /cacerts" — a CA problem, on a deployment
        # whose CAs were fine. Brackets are what RFC 3986 uses to make the authority
        # parseable, so match on them first and only then fall back to host:port.
        case "$_wh" in
            \[*\]:*) _host="${_wh%]:*}]";     WEB_PORT="${_wh##*]:}" ;;   # [v6]:port
            \[*\])   _host="$_wh";            WEB_PORT=443 ;;             # [v6]
            *:*)     _host="${_wh%%:*}";      WEB_PORT="${_wh##*:}" ;;    # host:port
            *)       _host="$_wh";            WEB_PORT=443 ;;             # host
        esac
        TARGET_HOST="${PROTO_HOST:-$_host}"
        MODE_NOTE="mode: native deployment at $WEB_URL"
        EST_PORT=8443;   EST_BASE_PATH=/.well-known/est
        CMP_PORT=8445;   CMP_PATH=/cmp
        OCSP_PORT=8080;  OCSP_PATH=/ocsp
        STORE_PORT=8447; STORE_PATH=/certificates/search
        SCEP_PORT=8448;  SCEP_PATH=/scep
        ACME_PORT=8444;  ACME_BASE_PATH=/acme
        MS_PORT=8446
        return 0
    fi
    # ⚠️ THE ONLY SHAPE LEFT HERE: a local docker compose deployment on well-known ports.
    # Kubernetes used to be a branch of its own, reading each listener's port from its Service
    # with kubectl. The console answers that now — refine_ports_from_api() below asks
    # /api/config, whose values are EFFECTIVE, so a port nobody set is still in the reply — and
    # --web-url reaches any platform. These are the defaults for "no --web-url given", which
    # means compose on this machine.
    WEB_URL="https://localhost:8090"
    TARGET_HOST=localhost
    WEB_PORT=8090
    MODE_NOTE="mode: local docker compose"
    EST_PORT=8443;   EST_BASE_PATH=/.well-known/est
    CMP_PORT=8445;   CMP_PATH=/cmp
    OCSP_PORT=8080;  OCSP_PATH=/ocsp
    STORE_PORT=8447; STORE_PATH=/certificates/search
    SCEP_PORT=8448;  SCEP_PATH=/scep
    ACME_PORT=8444;  ACME_BASE_PATH=/acme
    MS_PORT=8446
}

# ⚠️ THE PORTS THE DEPLOYMENT ACTUALLY SERVES, ASKED OF THE DEPLOYMENT ITSELF.
#
# discover_endpoints() sets the shipped defaults, because this script has no session yet
# when it runs. Those are right on compose and on a native install, where install-native.sh
# binds every listener on its well-known port and nothing reassigns them — but they are
# assumptions, and reading the real ones used to mean asking the ORCHESTRATOR: kubectl for
# each Service's port, which is most of why a Kubernetes run needed a mode of its own.
#
# The console already knows. GET /api/config is config_json(effective_cfg()), so it carries
# EFFECTIVE values: a port nobody ever set is still in the answer, as the built-in default.
# One authenticated call, over the session this script already holds, replaces the
# orchestrator on every platform.
#
# ⚠️ IT DOES NOT MAKE NodePort WORK, and nothing here should pretend otherwise. Under
# NodePort the cluster allocates the external port and the pod cannot know it, so the answer
# is the port the listener binds INSIDE the cluster, not the one a client dials. That is the
# same reason docs/deployment.md 8.6 tells operators not to use NodePort: certificates' AIA
# and CRL DP URLs are built from the listener's port too, so they name a port nothing outside
# answers on. LoadBalancer keeps the real port, and then this answer is the right one.
#
# Best effort by design: a deployment that cannot be asked keeps the defaults rather than
# failing, because the defaults are what it almost certainly uses.
refine_ports_from_api() {
    _cfg=$(curl -sk -b "$COOKIE" --max-time 15 "$WEB_URL/api/config" 2>/dev/null) || return 0
    case "$_cfg" in *'"key":"'*) : ;; *) return 0 ;; esac
    _set_port() {   # <shell var> <config key>
        _v=$(printf '%s' "$_cfg" | tr '{' '\n' \
               | sed -n 's/.*"key":"'"$2"'","value":"\([^"]*\)".*/\1/p' | head -1)
        case "$_v" in ''|*[!0-9]*) return 0 ;; esac
        eval "$1=\$_v"
    }
    _set_port EST_PORT   EST_PORT
    _set_port CMP_PORT   CMP_PORT
    _set_port OCSP_PORT  OCSP_PORT
    _set_port STORE_PORT STORE_PORT
    _set_port SCEP_PORT  SCEP_PORT
    _set_port ACME_PORT  ACME_PORT
    _set_port MS_PORT    MS_PORT
    echo "    listener ports read from the console: est=$EST_PORT cmp=$CMP_PORT ocsp=$OCSP_PORT store=$STORE_PORT scep=$SCEP_PORT acme=$ACME_PORT ms=$MS_PORT"
}

# ── local mode ─────────────────────────────────────────────────────────────────
# Both remaining shapes provision the same way; only the readiness check differs.
if [ "$MODE" = local ] || [ "$MODE" = native ]; then
  discover_endpoints

  echo "→ provisioning against $WEB_URL ($MODE_NOTE) ..."

  # Is the console actually there? The useful error names the thing to start rather than the
  # request that failed. The kubectl branch that used to live here — checking the fastpki-node
  # StatefulSet and its rollout — is gone with --k8s: a cluster is reached through --web-url
  # now, and the console either answers or it does not, which is the same question.
  if [ "$MODE" = native ]; then
    # Nothing to ask but the deployment itself: no orchestrator, and the console is the
    # only thing this mode needs to be up.
    if ! curl -sk -o /dev/null --max-time 10 "$WEB_URL/" 2>/dev/null; then
      echo "  ERR: no console at $WEB_URL — is the deployment up and reachable from here?" >&2
      echo "    On the node: rc-service fastpki-web status" >&2
      exit 2
    fi
  else
    if ! docker compose -f "$ROOT/deploy/docker-compose.yml" ps --status running 2>/dev/null | grep -q web; then
      echo "  ERR: docker compose not running (no 'web' service up). Run:" >&2
      echo "    cd deploy && docker compose up -d" >&2
      exit 2
    fi
  fi

  # The global SCEP_CHALLENGE is gone — the challenge is per user now. This block
  # used to hunt the deployment-wide value through four locations —
  # the scep container's environment, the web container's, the running bootstrap.conf, then two
  # files — because the bug was that it looked in the two places the value was NOT.
  #
  # There is no such value any more, so there is nothing to find. The SCEP challengePassword
  # comes from /api/enrolment-credentials below, minted for THIS user with their role, on
  # the same session that already fetches the CMP and ACME credentials. That endpoint
  # had already become the preferred source anyway: the shared secret named no user, so
  # fastpki-scep resolved it to the role-less `scep` identity and refused the enrolment.

  # Step 1: login as admin, create the demo requester.
  echo "  creating demo user '$USER'..."
  curl -sk -c "$COOKIE" -X POST \
    -d "username=$ADMIN_USER&password=$ADMIN_PASS" \
    "$WEB_URL/api/login" -o /dev/null 2>/dev/null

  # ⚠️ A FRESH DEPLOYMENT REFUSES EVERYTHING ELSE UNTIL admin's PASSWORD IS CHANGED, which
  # is the one deployment this script exists to provision. bootstrap seeds admin/admin with
  # must_reset on purpose — a permanent well-known credential on a PKI is the weak-default
  # class that draws a CVE — and the console then allows that session only /api/me,
  # /api/password and /api/logout. So the very next call returned
  #     {"error":"password reset required"}
  # and provisioning died. Complete the change rather than reporting it: an operator who
  # ran this against a brand-new deployment has not skipped a step.
  ME=$(curl -sk -b "$COOKIE" --max-time 10 "$WEB_URL/api/me" 2>/dev/null)
  if printf '%s' "$ME" | grep -q '"mustReset":true'; then
    if [ -z "$ADMIN_NEW_PASS" ]; then
      ADMIN_NEW_PASS=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 20)
    fi
    PW_RESP=$(curl -sk -b "$COOKIE" -X POST \
      --data-urlencode "old=$ADMIN_PASS" \
      --data-urlencode "new=$ADMIN_NEW_PASS" \
      "$WEB_URL/api/password" 2>/dev/null)
    if printf '%s' "$PW_RESP" | grep -q '"error"'; then
      echo "  ERR: this deployment requires a first-login password change, and it failed:" >&2
      echo "       ${PW_RESP:0:160}" >&2
      exit 3
    fi
    ADMIN_PASS="$ADMIN_NEW_PASS"
    echo "    the console required a first-login password change — done."
    echo "    admin's password is now: $ADMIN_NEW_PASS"
    echo "    (pass it as --admin-pass on later runs against this deployment)"
  fi

  # The session is good from here, so ask the deployment what it actually serves rather than
  # keeping the defaults discover_endpoints() assumed.
  refine_ports_from_api

  CREATE_RESP=$(curl -sk -b "$COOKIE" -X POST \
    --data-urlencode "username=$USER" \
    --data-urlencode "password=$PASS" \
    --data-urlencode "role=requester" \
    --data-urlencode "create=1" \
    "$WEB_URL/api/users" 2>/dev/null)
  if printf '%s' "$CREATE_RESP" | grep -q 'already exists'; then
    echo "    user exists — updating password..."
    CREATE_RESP=$(curl -sk -b "$COOKIE" -X POST \
      --data-urlencode "username=$USER" \
      --data-urlencode "password=$PASS" \
      --data-urlencode "role=requester" \
      "$WEB_URL/api/users" 2>/dev/null)
  fi
  if printf '%s' "$CREATE_RESP" | grep -q '"error"'; then
    echo "  ERR: could not create/update user '$USER' (response: ${CREATE_RESP:0:200})" >&2
    exit 3
  fi
  echo "    user ready"

  # (The demo user's CMP secret is read further down, from the DEMO session — see step 3b.)

  # Step 2: discover CA ID (admin session — requires ca:read permission).
  echo "  discovering CA from /api/ca-instances..."
  # ⚠️ ASK THE TARGET WHICH DOMAIN IT WILL ISSUE FOR, AND DO IT WHILE STILL ADMIN.
  # The demo used to hardcode `*.internal` names, so on any deployment whose allowed_domains
  # does not happen to include `internal` EVERY issuance step failed on policy. Measured on
  # dc3, which approves cloud / test.com / unjam-proof:
  #
  #   PKIStatus: rejection; PKIFailureInfo: badRequest;
  #   StatusString: "policy: CN 'cmp-client.internal' is not in the approved domains"
  #
  # The refusal was correct and clearly worded — the demo was asking for a name this
  # deployment does not serve. allowed_domains is the OPERATOR's policy and the demo must
  # not write to it (the rule is: revert whatever you change), so it reads instead.
  #
  # ⚠️ HERE, not later: the session is re-logged in as the demo user further down to read
  # enrolment credentials, and /api/domains needs config:manage. Run against that session it
  # returns {"error":...} — and my first version's loose grep happily took the word `error`
  # as the domain name and announced it. Parse the ARRAY shape or take nothing.
  DEMO_DOMAIN=""
  _dom_json="$(curl -sk -b "$COOKIE" --max-time 10 "$WEB_URL/api/domains" 2>/dev/null)"
  case "$_dom_json" in
    \[*\])  DEMO_DOMAIN="$(printf '%s' "$_dom_json" \
                | sed 's/^\[//; s/\]$//' | tr ',' '\n' | tr -d '"' \
                | grep -E '^[A-Za-z0-9][A-Za-z0-9.-]*$' | head -1)" ;;
  esac
  if [ -n "$DEMO_DOMAIN" ]; then
    echo "  demo names will use the approved domain '$DEMO_DOMAIN'"
  else
    echo "  no approved domain readable from /api/domains — the demo will use 'internal'"
  fi

  INSTANCES=$(curl -sk -b "$COOKIE" --max-time 10 "$WEB_URL/api/ca-instances" 2>/dev/null)
  # ⚠️ TWO BUGS LIVED IN THE THREE LINES THIS REPLACES, and both produced a
  # target file that looked complete and failed at the first request.
  #
  # 1. The patterns were `.*"parentId"...*"id":"([^"]+)".*` against the WHOLE array on one
  #    line. `.*` does not stop at an object boundary, so it happily pairs a parentId from
  #    one CA with an id from another, or runs to the last "id" on the line. Split the
  #    array into one object per line first, and the pairing becomes impossible.
  #
  # 2. It picked a CA that cannot ISSUE. The lab registers its offline root (key on
  #    another machine entirely) so chains can be built; that row is a perfectly good CA
  #    to a chooser that only reads JSON, and EST answers 503 for it. The demo then died
  #    at "could not fetch CA chain" naming the CA but not the reason.
  #
  # So: ask the DEPLOYMENT which CA it will serve, rather than inferring it from a field.
  # /cacerts answering 200 is the same question the demo's very next step asks.
  # ⚠️ AND A ROOT IS NOT A CANDIDATE WHILE AN ISSUING CA EXISTS. /cacerts answering 200 is
  # necessary, not sufficient: a root serves its own chain perfectly well, and the very
  # next thing the demo does is enrol — which nothing does against a root. The product says
  # so itself, refusing to mint the credentials that would be needed:
  #
  #   skipped cmp-ra-root — CA 'root' is a root, and nothing enrols against a root
  #
  # So the CMP and SCEP steps fail on a deployment that is perfectly healthy, and the
  # failure names the protocol rather than the choice made here. Measured on a fresh
  # single-node install whose CA list is root + signing: iteration order put root first and
  # it was taken. Order the candidates by KIND and the question does not arise.
  _objs=$(printf '%s' "$INSTANCES" | tr '{' '\n')
  _issuing=$(printf '%s\n' "$_objs" | grep -v '"kind"[[:space:]]*:[[:space:]]*"root"' \
             | sed -nE 's/.*"id" *: *"([^"]+)".*/\1/p')
  _roots=$(printf '%s\n' "$_objs" | grep '"kind"[[:space:]]*:[[:space:]]*"root"' \
           | sed -nE 's/.*"id" *: *"([^"]+)".*/\1/p')
  CA_ID=""; _picked_root=no
  for _c in $_issuing $_roots; do
    if [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 \
              "https://$TARGET_HOST:${EST_PORT:-8443}/.well-known/est/$_c/cacerts")" = 200 ]; then
      CA_ID=$_c
      case " $_roots " in *" $_c "*) _picked_root=yes ;; esac
      break
    fi
    echo "    skipping '$_c' — EST does not serve it (no signing key on this node?)"
  done
  if [ -n "$CA_ID" ] && [ "$_picked_root" = no ]; then
    echo "    found: $CA_ID"
  elif [ -n "$CA_ID" ]; then
    # Chosen deliberately and said out loud, because the enrolment steps will fail and the
    # reason is this deployment's CA hierarchy rather than anything the demo did.
    echo "    WARN: '$CA_ID' is a ROOT and the only CA serving EST here. Nothing enrols" >&2
    echo "          against a root, so the CMP and SCEP steps will fail. Create an issuing" >&2
    echo "          CA beneath it (docs/deployment.md 4.3) and re-run this." >&2
  else
    echo "    WARN: no CA on this deployment serves EST /cacerts — the demo's enrolment steps will skip" >&2
  fi

  # Step 3: login as demo user and download the CMP client config.
  # The console substitutes the downloading user's own secrets into the config
  # body, so this MUST be the demo session, not admin.
  curl -sk -c "$COOKIE" -X POST \
    -d "username=$USER&password=$PASS" \
    "$WEB_URL/api/login" -o /dev/null 2>/dev/null

  # Step 3b: the demo user reads its OWN enrolment credentials.
  #
  # ⚠️ The rule under this script changed: an admin may still ROTATE another user's
  # credentials but no longer receives the values back — they are that user's
  # authentication secrets, and an admin holding them can enrol as them with the audit
  # trail naming the wrong actor. So the old `POST ?username=demo` as admin now returns an
  # empty cmp_secret and the CMP step of the demo fails with no obvious cause. Self-service
  # returns the real values, and this session is already open for exactly that reason.
  #
  # (Re-applied after 4d32cad, which rewrote this file to drop Python and restored the
  #  admin-read along the way. Same extraction style as the rest of the file — sed, no
  #  python3 — so the CoreDNS/no-Python work stands.)
  echo "  reading enrolment credentials for '$USER' (as '$USER')..."
  CREDS_RESP=$(curl -sk -b "$COOKIE" "$WEB_URL/api/enrolment-credentials" 2>/dev/null)
  CMP_SECRET=$(printf '%s' "$CREDS_RESP" | sed -nE 's/.*"cmp_secret" *: *"([^"]+)".*/\1/p')
  # The SCEP challengePassword is this user's OWN credential, and there is nothing
  # else it could be — the deployment-wide SCEP_CHALLENGE is gone.
  #
  # ⚠️ The shared value is why the SCEP step failed on a live deployment. It named no
  # user, so fastpki-scep resolved it to the shared `scep` identity, which holds no role
  # and therefore no profile — and an empty profile union is a refusal:
  #
  #   ERR  SCEP PKCSReq refused by policy: policy: this identity holds no profile
  #        permission, so no certificate profile applies.
  #
  # The per-user form is "<user>:<secret>"; the server splits on that ':' and
  # resolves the profile for THAT user, exactly as EST and CMP already do.
  SCEP_CH=$(printf '%s' "$CREDS_RESP" | sed -nE 's/.*"scep_challenge" *: *"([^"]+)".*/\1/p')
  if [ -n "$SCEP_CH" ]; then
    echo "    SCEP challenge: this user's own (per-user)"
  else
    echo "    note: '$USER' has no SCEP credential — grant its role enrol:scep so one is"
    echo "      minted, or the SCEP step will be skipped"
  fi
  if [ -n "$CMP_SECRET" ]; then
    echo "    CMP secret available (${#CMP_SECRET} chars)"
  else
    echo "    note: credentials response: ${CREDS_RESP:0:200}"
  fi

  CMP_CNF="$(dirname "$OUT")/fastpki-cmp.cnf"
  if [ -n "$CA_ID" ]; then
    echo "  downloading CMP client config for CA '$CA_ID'..."
    curl -sk -b "$COOKIE" --max-time 10 \
      "$WEB_URL/api/client-config/cmp?ca=$CA_ID" \
      -o "$CMP_CNF" 2>/dev/null
    if [ -s "$CMP_CNF" ] && ! head -1 "$CMP_CNF" | grep -q '{"error"'; then
      echo "    saved to $(basename "$CMP_CNF")"
    else
      rm -f "$CMP_CNF"
      echo "    note: could not download CMP config (will use CLI flags)"
    fi
  fi

  rm -f "$COOKIE"

  # Endpoints came from discover_endpoints() at the top of this block — fixed for compose,
  # read back from the Services for Kubernetes. Postgres is not among them: it is reached
  # over TLS on its own address, and if that connection fails the demo skips ACME
  # gracefully rather than failing the suite.
  emit_descriptor
  exit 0
fi

# The SSH provisioning path that used to live here is gone: everything it did through
# `docker exec` on the node — reading bootstrap.conf, creating the demo user, finding the
# CA — the console API does over HTTPS, from anywhere, for every platform. The argument
# parser above refuses a bare ssh target and names --web-url.
