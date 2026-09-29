#!/bin/sh
# FastPKI install wizard for Kubernetes. It asks the compose wizard's questions, in the same
# order and under the same answers-file keys, writes deploy/k8s/env.local, and then runs
# apply.sh. install.sh --k8s runs it; so can you, from this directory.
#
# Usage:
#   deploy/k8s/k8s-install.sh                     # interactive
#   deploy/k8s/k8s-install.sh --answers ans.env   # non-interactive (CI / scripted / next data center)
#   deploy/k8s/k8s-install.sh --non-interactive   # every question takes its default
#   deploy/k8s/k8s-install.sh --print-env         # write nothing; print env.local to stdout
#   deploy/k8s/k8s-install.sh --no-deploy         # write env.local and STOP; apply.sh is yours
#
# Answers file keys: the compose wizard's, so one file serves both paths:
#   DEPLOYMENT=single|cluster   FASTPKI_IMAGE=  PKI_DNS=
#   DC_INDEX=<i>   PG_BIND=<addr>[,<addr>]      (cluster only: this data center's address,
#                                                one per server, first machine first)
#   HA_ENABLED=yes|no            a second server on a second machine of this cluster
#   PG_PASSWORD=  PKCS11_PIN=    (blank = keep the deployment's, or generate one)
#   KEY_BACKEND=softhsm|hsm      PKCS11_MODULE=<abs path>  PKCS11_TOKEN=  (when KEY_BACKEND=hsm)
#   WANT_EST= WANT_ACME= WANT_CMP= WANT_SCEP= WANT_MS= WANT_STORE=   yes|no per protocol
#   <SVC>_KEY_ALGO / _KEY_BITS / _KEY_CURVE / _KEY_MD, SCEP_RA_KEY_BITS
#   KEEP_DB=yes|no               reuse an existing env.local and skip the questions
#
# What differs from compose is what Kubernetes itself decides:
#   - a single data center asks no database address: its servers reach each other inside the
#     cluster. In a mesh, PG_BIND is the address the OTHER clusters dial (PG_INTERCONNECT here),
#     one per server, and the database is published on it (PG_EXTERNAL_TYPE=LoadBalancer).
#   - the console and the protocols are published as LoadBalancer Services without a question,
#     the counterpart of compose publishing its ports.
#   - a blank password or PIN is left out of env.local, so apply.sh reuses the one the
#     deployment already holds, or generates one for a new deployment.
set -eu
( set -o pipefail ) 2>/dev/null && set -o pipefail || true

case "$0" in
    */*) HERE="$(cd "${0%/*}" && pwd)" ;;
    *)   HERE="$(pwd)" ;;
esac
ENV_OUT="$HERE/env.local"

ANSWERS=""; PRINT_ONLY=0; DO_DEPLOY=1; NONINTERACTIVE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --answers) ANSWERS="${2:?--answers needs a file}"; shift 2 ;;
    --print-env) PRINT_ONLY=1; shift ;;
    --no-deploy) DO_DEPLOY=0; shift ;;
    --non-interactive) NONINTERACTIVE=1; shift ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "k8s-install: unknown arg: $1" >&2; exit 2 ;;
  esac
done
if [ -n "$ANSWERS" ]; then
  [ -r "$ANSWERS" ] || { echo "k8s-install: cannot read answers file: $ANSWERS" >&2; exit 2; }
fi
if [ "$NONINTERACTIVE" -eq 0 ] && [ -z "$ANSWERS" ] && [ ! -t 0 ]; then
  echo "k8s-install: stdin is not a terminal — use --answers <file> or --non-interactive." >&2
  exit 2
fi

ansval() { [ -n "$ANSWERS" ] && sed -n "s/^$1=//p" "$ANSWERS" | head -1 || true; }
interactive() { [ "$NONINTERACTIVE" -eq 0 ] && [ -z "$ANSWERS" ] && [ -t 0 ]; }

# ⚠️ A CLUSTER FIRST, QUESTIONS SECOND. Every answer below is spent on apply.sh, and apply.sh
# needs a cluster kubectl can reach. Run before Kubernetes is installed, the wizard would take
# ten answers and then fail on the first kubectl call. --print-env writes nothing and needs none.
if [ "$PRINT_ONLY" = 0 ] && [ "$DO_DEPLOY" = 1 ]; then
  if ! command -v kubectl >/dev/null 2>&1 || ! kubectl get nodes --request-timeout=10s >/dev/null 2>&1; then
    echo "k8s-install: kubectl cannot reach a Kubernetes cluster from here." >&2
    echo "  Install Kubernetes first and check that 'kubectl get nodes' lists your machines as" >&2
    echo "  Ready (docs/deployment.md 8.0, step 1). Then run this again." >&2
    exit 1
  fi
fi

# ── Existing settings ─────────────────────────────────────────────────────
# The compose wizard offers to keep an existing database and skip the questions. Here the
# settings are env.local, and the database, token PIN and password live in the cluster, which
# apply.sh reuses by itself — so keeping env.local is the whole of "keep what is there".
KEEP_DB="no"
if [ -f "$ENV_OUT" ] && [ "$PRINT_ONLY" = 0 ]; then
  echo "Found existing settings in $ENV_OUT." >&2
  if interactive; then
    printf '%s' "Reuse them and skip configuration? (yes/no) [yes]: " >&2
    read -r ans || true
    case "${ans:-yes}" in y|Y|yes|YES|Yes) KEEP_DB="yes" ;; *) KEEP_DB="no" ;; esac
  else
    KEEP_DB="$(ansval KEEP_DB)"
    [ -z "$KEEP_DB" ] && KEEP_DB="no"
  fi
fi
if [ "$KEEP_DB" = yes ]; then
  echo "Reusing $ENV_OUT — skipping the wizard." >&2
  if [ "$DO_DEPLOY" = 1 ]; then exec sh "$HERE/apply.sh"; fi
  echo "Next step: sh $HERE/apply.sh" >&2
  exit 0
fi

ask() { # ask VAR "prompt" "default"
  _var="$1"; _prompt="$2"; _def="${3:-}"
  _cur="$(ansval "$1")"
  [ -n "$_cur" ] && _def="$_cur"
  if interactive; then
    printf '%s' "$_prompt [${_def}]: " >&2
    read -r _ans || true
    eval "$_var=\${_ans:-\$_def}"
  else
    eval "$_var=\$_def"
  fi
}
yesno() {   # yesno <VAR> <prompt> <default yes|no>
  ask "$1" "$2 (yes/no)" "$3"
  eval "_v=\$$1"
  case "$_v" in
    y|Y|yes|YES|Yes|true|TRUE|True)  eval "$1=yes" ;;
    n|N|no|NO|No|false|FALSE|False)  eval "$1=no"  ;;
    *) echo "k8s-install: $1 must be yes or no (got '$_v')" >&2; exit 1 ;;
  esac
}

if interactive; then
  echo "── FastPKI install wizard (Kubernetes) ────────────────────────────────" >&2
  echo "  single  - ONE data center: one server, or a pair on two machines of this" >&2
  echo "            cluster (the standby question below)." >&2
  echo "  cluster - SEVERAL data centers replicating active-active, each its own" >&2
  echo "            Kubernetes cluster with its own serial prefix." >&2
fi
ask DEPLOYMENT   "Deployment type (single / cluster)" "single"
case "$DEPLOYMENT" in single|cluster) ;; *) echo "k8s-install: DEPLOYMENT must be 'single' or 'cluster'" >&2; exit 1 ;; esac
# From a release, install.sh names the release's own image. A checkout has none: name the image
# the cluster can pull.
ask FASTPKI_IMAGE "Container image (a registry tag; the cluster downloads it)" \
    "${FASTPKI_RELEASE_IMAGE:-fastpki:latest}"
ask PKI_DNS       "Public FQDN of this deployment" "pki.example.org"
PG_BIND=""
if [ "$DEPLOYMENT" = cluster ]; then
  ask DC_INDEX "This data center's index — it IS its certificate-serial prefix" "1"
  ask PG_BIND  "This data center's mesh-reachable address, one per server, comma-separated, first machine first (peers subscribe to Postgres here)" ""
  case "$DC_INDEX" in ''|*[!0-9]*) echo "k8s-install: DC_INDEX must be a positive integer" >&2; exit 1 ;; esac
  [ "$DC_INDEX" -ge 1 ] || { echo "k8s-install: DC_INDEX must be >= 1" >&2; exit 1; }
  [ "$DC_INDEX" -le 32767 ] || { echo "k8s-install: DC_INDEX must be <= 32767 (serial prefix is 2 octets, high bit reserved)" >&2; exit 1; }
else
  DC_INDEX=1
fi
yesno HA_ENABLED "Will this data center have a standby server that takes over if this one is lost" no

# ⚠️ ONE ADDRESS PER SERVER, AND A REAL ONE. The peers dial each address, since either server of
# a pair can be the primary; apply.sh refuses a count that does not match, and a loopback
# address can never be reached from another cluster. Checked here, before anything is written.
if [ "$DEPLOYMENT" = cluster ]; then
  _want=1; [ "$HA_ENABLED" = yes ] && _want=2
  _got=$(printf '%s' "$PG_BIND" | tr ',' '\n' | grep -c '[^[:space:]]' || true)
  if [ "$_got" -ne "$_want" ]; then
    echo "k8s-install: PG_BIND needs $_want address(es) for $_want server(s), comma-separated, first" >&2
    echo "  machine first (kubectl get nodes -o wide shows them under INTERNAL-IP). Got '$PG_BIND'." >&2
    exit 1
  fi
  for _a in $(printf '%s' "$PG_BIND" | tr ',' ' '); do
    case "$_a" in 127.*|localhost|::1)
      echo "k8s-install: '$_a' is a loopback address; the other clusters cannot reach it." >&2; exit 1 ;;
    esac
  done
fi

ask PG_PASSWORD "Postgres password (blank = keep the deployment's, or generate one)" ""
ask PKCS11_PIN "Token PIN (blank = keep the deployment's, or generate one)" ""
ask KEY_BACKEND "Key storage (softhsm = bundled token container, dev/test; hsm = your own PKCS#11 module)" "softhsm"

ask_service_key() {   # ask_service_key <PREFIX> <human name> <allowed algorithms> [ask digest: yes|no]
  _p="$1"; _n="$2"; _allowed="$3"; _want_md="${4:-no}"
  _list="$(printf '%s' "$_allowed" | sed 's/ /, /g')"
  ask "${_p}_KEY_ALGO" "Key type for the ${_n} key (${_list})" ec
  eval "_a=\$${_p}_KEY_ALGO"
  case " $_allowed " in
    *" $_a "*) ;;
    *) echo "k8s-install: ${_p}_KEY_ALGO must be one of: ${_list} (got '$_a')" >&2; exit 1 ;;
  esac
  eval "${_p}_KEY_BITS=''; ${_p}_KEY_CURVE=''; ${_p}_KEY_MD=''"
  case "$_a" in
    ec)
      ask "${_p}_KEY_CURVE" "  EC curve for the ${_n} key (P-256, P-384, P-521)" P-256
      eval "_c=\$${_p}_KEY_CURVE"
      case "$_c" in
        P-256|P-384|P-521) ;;
        *) echo "k8s-install: ${_p}_KEY_CURVE must be P-256, P-384 or P-521 (got '$_c')" >&2; exit 1 ;;
      esac ;;
    rsa|rsa-pss)
      ask "${_p}_KEY_BITS" "  RSA size for the ${_n} key (2048, 3072, 4096)" 3072
      eval "_b=\$${_p}_KEY_BITS"
      case "$_b" in
        2048|3072|4096) ;;
        *) echo "k8s-install: ${_p}_KEY_BITS must be 2048, 3072 or 4096 (got '$_b')" >&2; exit 1 ;;
      esac ;;
  esac
  if [ "$_want_md" = yes ]; then
    case "$_a" in
      rsa|rsa-pss)
        ask "${_p}_KEY_MD" "  Signature digest for the ${_n} certificate (blank = auto; sha256, sha384, sha512, sha3-256, sha3-384, sha3-512)" ''
        eval "_m=\$${_p}_KEY_MD"
        case "$_m" in
          ''|sha256|sha384|sha512|sha3-256|sha3-384|sha3-512) ;;
          *) echo "k8s-install: ${_p}_KEY_MD must be blank or one of sha256, sha384, sha512, sha3-256, sha3-384, sha3-512 (got '$_m')" >&2; exit 1 ;;
        esac ;;
    esac
  fi
}
TLS_KEY_ALGOS='ec rsa rsa-pss'
CMP_KEY_ALGOS='ec rsa rsa-pss ed25519 ed448 ML-DSA-44 ML-DSA-65 ML-DSA-87'

if interactive; then
  echo >&2
  echo "Which protocols should this deployment run? Anything you decline gets no container and" >&2
  echo "no Service — you can add it later by setting <PROTO>_INSTALLED=true in env.local and" >&2
  echo "running apply.sh again." >&2
fi
yesno WANT_EST   "  EST (RFC 7030)"                       yes
yesno WANT_ACME  "  ACME (RFC 8555)"                      yes
yesno WANT_CMP   "  CMP (RFC 4210/9483)"                  yes
yesno WANT_SCEP  "  SCEP (RFC 8894)"                      yes
yesno WANT_MS    "  MS-XCEP/WSTEP (Windows auto-enrol)"   yes
yesno WANT_STORE "  Certificate store (RFC 4387)"         yes

if interactive; then
  echo "FastPKI generates one key per service inside the token at first start." >&2
  echo "Answer per service, or press Enter for the default (ec / P-256)." >&2
fi
ask_service_key WEB    "web console TLS"           "$TLS_KEY_ALGOS" yes
[ "$WANT_EST"  = yes ] && ask_service_key EST  "EST listener TLS"  "$TLS_KEY_ALGOS" yes
[ "$WANT_ACME" = yes ] && ask_service_key ACME "ACME listener TLS" "$TLS_KEY_ALGOS" yes
[ "$WANT_MS"   = yes ] && ask_service_key MS   "MS-XCEP/WSTEP listener TLS" "$TLS_KEY_ALGOS" yes
ask_service_key OCSP_RESPONDER "OCSP responder" "$TLS_KEY_ALGOS"
[ "$WANT_CMP" = yes ] && ask_service_key CMP_RA "CMP RA" "$CMP_KEY_ALGOS"
if [ "$WANT_SCEP" = yes ]; then
  ask SCEP_RA_KEY_BITS "RSA size for the SCEP RA key (2048, 3072, 4096) — SCEP requires RSA" 3072
  case "$SCEP_RA_KEY_BITS" in
    2048|3072|4096) ;;
    *) echo "k8s-install: SCEP_RA_KEY_BITS must be 2048, 3072 or 4096 (got '$SCEP_RA_KEY_BITS')" >&2; exit 1 ;;
  esac
fi

PKCS11_MODULE_OUT=""
case "$KEY_BACKEND" in
  softhsm) : ;;
  hsm)
    ask PKCS11_MODULE "Absolute path to the vendor PKCS#11 module inside the container" ""
    case "${PKCS11_MODULE:-}" in
      /*) ;;
      "") echo "k8s-install: KEY_BACKEND=hsm needs PKCS11_MODULE=<absolute path to the vendor .so>" >&2; exit 1 ;;
      *)  echo "k8s-install: PKCS11_MODULE must be an ABSOLUTE path (got '$PKCS11_MODULE')" >&2; exit 1 ;;
    esac
    PKCS11_MODULE_OUT="$PKCS11_MODULE"
    # The bundled token is always labelled `fastpki`; somebody else's HSM is labelled
    # whatever they labelled it, and every key URI names the token.
    ask PKCS11_TOKEN "Token label on that module" "fastpki" ;;
  *) echo "k8s-install: KEY_BACKEND must be 'softhsm' or 'hsm'" >&2; exit 1 ;;
esac

tf() { [ "$1" = yes ] && echo true || echo false; }
ENV_BODY=$(
  echo "# Written by deploy/k8s/k8s-install.sh. Change a setting here and run apply.sh again,"
  echo "# or run the wizard again. Every other setting takes its default from env.sh."
  printf 'IMAGE=%s\nPKI_DNS=%s\n' "$FASTPKI_IMAGE" "$PKI_DNS"
  printf 'WEB_SERVICE_TYPE=LoadBalancer\nPROTO_SERVICE_TYPE=LoadBalancer\n'
  if [ "$DEPLOYMENT" = cluster ]; then
    printf 'DC_INDEX=%s\nPG_INTERCONNECT=%s\nPG_EXTERNAL_TYPE=LoadBalancer\n' "$DC_INDEX" "$PG_BIND"
  fi
  [ "$HA_ENABLED" = yes ] && printf 'HA_ENABLED=true\n'
  [ -n "$PG_PASSWORD" ] && printf 'PG_PASSWORD=%s\n' "$PG_PASSWORD"
  [ -n "$PKCS11_PIN" ] && printf 'FASTPKI_PIN=%s\n' "$PKCS11_PIN"
  if [ -n "$PKCS11_MODULE_OUT" ]; then
    printf 'SOFTHSM_ENABLED=false\nPKCS11_MODULE=%s\nPKCS11_TOKEN=%s\n' "$PKCS11_MODULE_OUT" "${PKCS11_TOKEN:-fastpki}"
  fi
  printf 'EST_INSTALLED=%s\nACME_INSTALLED=%s\nCMP_INSTALLED=%s\n' \
      "$(tf "$WANT_EST")" "$(tf "$WANT_ACME")" "$(tf "$WANT_CMP")"
  printf 'SCEP_INSTALLED=%s\nMS_INSTALLED=%s\nSTORE_INSTALLED=%s\n' \
      "$(tf "$WANT_SCEP")" "$(tf "$WANT_MS")" "$(tf "$WANT_STORE")"
  for _p in WEB $([ "$WANT_EST" = yes ] && echo EST) $([ "$WANT_ACME" = yes ] && echo ACME) \
            $([ "$WANT_MS" = yes ] && echo MS) OCSP_RESPONDER \
            $([ "$WANT_CMP" = yes ] && echo CMP_RA); do
    eval "_a=\$${_p}_KEY_ALGO; _b=\${${_p}_KEY_BITS:-}; _c=\${${_p}_KEY_CURVE:-}; _m=\${${_p}_KEY_MD:-}"
    printf '%s_KEY_ALGO=%s\n' "$_p" "$_a"
    [ -n "$_b" ] && printf '%s_KEY_BITS=%s\n'  "$_p" "$_b"
    [ -n "$_c" ] && printf '%s_KEY_CURVE=%s\n' "$_p" "$_c"
    [ -n "$_m" ] && printf '%s_KEY_MD=%s\n'    "$_p" "$_m"
    true
  done
  [ "$WANT_SCEP" = yes ] && printf 'SCEP_RA_KEY_BITS=%s\n' "$SCEP_RA_KEY_BITS"
  true                     # keep the subshell's exit status 0 under set -e
)

if [ "$PRINT_ONLY" = 1 ]; then
  printf '%s\n' "$ENV_BODY"
  exit 0
fi

# ⚠️ KEEP WHAT WAS THERE. env.local is also where settings the wizard does not ask for live, so an
# existing file is set aside rather than lost.
#
# ⚠️ AND WRITE A NEW FILE, NOT OVER THE OLD ONE. It can hold the database password and the token
# PIN, and a redirect onto an existing file keeps that file's mode, so the umask below would
# protect only a first install.
if [ -f "$ENV_OUT" ]; then
  cp -p "$ENV_OUT" "$ENV_OUT.bak"
  rm -f "$ENV_OUT"
  echo "  previous settings kept in $ENV_OUT.bak" >&2
fi
( umask 077; printf '%s\n' "$ENV_BODY" > "$ENV_OUT" ) || { echo "k8s-install: could not write $ENV_OUT" >&2; exit 1; }
echo "Wrote $ENV_OUT" >&2

if [ "$DO_DEPLOY" = 1 ]; then
  exec sh "$HERE/apply.sh"
fi
echo "Next step: sh $HERE/apply.sh" >&2
