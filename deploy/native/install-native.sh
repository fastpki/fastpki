#!/usr/bin/env bash
# deploy/native/install-native.sh — FastPKI install wizard for a NATIVE Alpine host.
#
# The sibling of deploy/install.sh. That one configures a docker-compose deployment; this
# one configures the same deployment with no Docker at all: OpenRC services, a host
# Postgres, and the binaries build-native.sh installed under /usr/local/bin.
#
# It is a separate script rather than a --native flag on install.sh, because past the
# shared list of QUESTIONS the two have almost nothing in common: one writes a .env for
# compose to inject, the other writes /etc/fastpki/bootstrap.conf, /etc/conf.d/fastpki,
# a Postgres cluster and a set of rc-update lines. The questions are deliberately the
# same, in the same order, with the same defaults, so an answers file written for one
# works with the other.
#
#   ./install-native.sh                      # interactive
#   ./install-native.sh --answers ans.env    # non-interactive (cloud-init, CI, next node)
#   ./install-native.sh --answers ans.env --print-conf   # write nothing; print the config
#   ./install-native.sh --no-start           # configure everything, start nothing
#
# Answers file / env keys (all optional; sensible defaults) — a superset of install.sh's:
#   DEPLOYMENT=single|cluster   PKI_DNS=  PG_BIND=  CMP_CLIENT_CA_ID=
#   DC_COUNT=<N>  DC_INDEX=<i>          (cluster only; i in 1..N)
#   KEY_BACKEND=softhsm|hsm             PKCS11_MODULE=<abs path>  (required when hsm)
#   PG_PASSWORD=  PKCS11_PIN=           (blank = generate)
#   WANT_EST/WANT_ACME/WANT_CMP/WANT_SCEP/WANT_MS/WANT_STORE=yes|no
#   WEB_KEY_ALGO/…_BITS/…_CURVE/…_MD, and the same for EST_/ACME_/MS_
#   OCSP_RESPONDER_KEY_ALGO/…_BITS/…_CURVE, CMP_RA_KEY_ALGO/…, SCEP_RA_KEY_BITS
#   PG_LOCAL=yes|no                     native-only: is Postgres on THIS host?
#   P11_TLS=on|off  P11_TLS_PORT=<n>    publish this host's token over mTLS, so a peer can
#                                       replicate a CA key out of it (docs/deployment.md 8.3)
#   HA_ENABLED=yes|no                   this data center will have a standby: forces P11_TLS
#                                       on and creates service keys copyable. Same switch as
#                                       install.sh and Kubernetes; the standby is joined
#                                       later with deploy/ha-join-pair.sh.
#   PG_HOST=  PG_PORT=  PG_SSLROOTCERT= native-only: used when PG_LOCAL=no
set -euo pipefail

# ⚠️ NO `dirname`. It is an external command, and on a PATH without it the substitution is
# empty and this becomes `cd ""` — which Alpine treats as fatal and macOS treats as a
# successful no-op, so the bug hides on the dev box. Parameter expansion needs no PATH.
case "$0" in
    */*) HERE="$(cd "${0%/*}" && pwd)" ;;
    *)   HERE="$(pwd)" ;;
esac

# Where the deployment assets live. build-native.sh stages them under /usr/share/fastpki
# so a booted cloud image has them without the source tree; a run from a git checkout
# finds them beside this script instead. Checked in that order because the checkout is
# the newer of the two when both exist.
if [ -f "$HERE/../certgen.sh" ]; then
    ASSETS="$(cd "$HERE/.." && pwd)"
    SQLDIR="$(cd "$HERE/../../sql" && pwd)"
else
    ASSETS=/usr/share/fastpki
    SQLDIR=/usr/share/fastpki/sql
fi

CONF_DIR=/etc/fastpki
CONF="$CONF_DIR/bootstrap.conf"
PG_CONF_D="$CONF_DIR/postgresql.conf.d"
CONFD=/etc/conf.d/fastpki
PKI_DIR=/var/pki
BINDIR=/usr/local/bin
SVC_USER=fastpki

ANSWERS=""; PRINT_ONLY=0; DO_START=1
while [ $# -gt 0 ]; do
  case "$1" in
    --answers) ANSWERS="${2:?--answers needs a file}"; shift 2 ;;
    --print-conf) PRINT_ONLY=1; shift ;;
    --no-start) DO_START=0; shift ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

die() { echo "install-native: $*" >&2; exit 1; }

if [ "$PRINT_ONLY" = 0 ]; then
  [ "$(id -u)" = 0 ] || die "must run as root (it creates users, services and a database cluster)"
  command -v apk        >/dev/null 2>&1 || die "not an Alpine host — Alpine is the only native platform FastPKI supports (see docs/deployment.md)"
  command -v rc-update  >/dev/null 2>&1 || die "OpenRC is not installed; the native services are OpenRC services"
  [ -x "$BINDIR/fastpki-web" ] || die "$BINDIR/fastpki-web is missing — run deploy/native/build-native.sh first"
  # A package unpacked on a node (docs/admin-guide.md §14.4) brings files, not the Alpine
  # packages they link against. If this release needs one the node does not have, say
  # which, here — not as a service that fails to load a library after the restart.
  # ⚠️ THE ALPINE RELEASE THE PACKAGE WAS BUILT ON, BEFORE ANYTHING ELSE. docs/admin-guide.md
  # 14.4's update path unpacks the package by hand and runs this script, so it never passes
  # through install.sh's copy of this check. Alpine moves sonames between releases: a 3.24
  # package on 3.23 unpacks cleanly, this script reports success, every service reports
  # "started", and every binary then dies at exec for want of libxmlsec1-openssl.so.10311.
  # Measured on a stock Alpine 3.23 image.
  if [ -r /usr/share/fastpki/alpine-release ] && [ -r /etc/alpine-release ]; then
    _built=$(cat /usr/share/fastpki/alpine-release)
    _host=$(cut -d. -f1,2 /etc/alpine-release)
    [ "$_built" = "$_host" ] || die "these programs were built for Alpine $_built and this host is $_host — Alpine moves shared-library versions between releases, so they would install and then fail to start. Use an Alpine $_built host, or a package built for $_host"
    unset _built _host
  fi
  if [ -r /usr/share/fastpki/runtime-packages ]; then
    _missing=""
    for _p in $(cat /usr/share/fastpki/runtime-packages); do
      apk info -e "$_p" >/dev/null 2>&1 || _missing="$_missing $_p"
    done
    [ -z "$_missing" ] || die "this release needs Alpine packages the host does not have:$_missing — apk add them, then run this again"
    unset _missing _p
  fi
  # Hold Alpine's p11-kit packages at the installed version, so `apk upgrade` cannot put the
  # unpatched libraries back. The bake already does it; this covers a node baked before that.
  if [ -x /usr/libexec/fastpki/hold-p11-kit ]; then
    /usr/libexec/fastpki/hold-p11-kit || die "could not hold the p11-kit packages (see above)"
  fi
fi

[ -n "$ANSWERS" ] && { [ -r "$ANSWERS" ] || die "cannot read answers file: $ANSWERS"; }
# ⚠️ DEFINED BEFORE THE FIRST CALLER. In install.sh these helpers once sat below their
# first use, and the non-interactive path died with "ansval: command not found" and no
# config written — invisible interactively, because a tty takes the read -r branch.
ansval() { [ -n "$ANSWERS" ] && sed -n "s/^$1=//p" "$ANSWERS" | head -1 || true; }
interactive() { [ -z "$ANSWERS" ] && [ -t 0 ]; }
ask() {   # ask VAR "prompt" "default"
  local var="$1" prompt="$2" def="${3:-}" cur ans
  cur="$(ansval "$1")"
  [ -n "$cur" ] && def="$cur"
  if interactive; then
    read -r -p "$prompt [${def}]: " ans || true
    printf -v "$var" '%s' "${ans:-$def}"
  else
    printf -v "$var" '%s' "$def"
  fi
}
yesno() {   # yesno VAR "prompt" default
  ask "$1" "$2 (yes/no)" "$3"
  local v="${!1}"
  case "$v" in
    # true/false too: Kubernetes spells HA_ENABLED that way, and one name means one thing.
    y|Y|yes|YES|Yes|true|TRUE|True)  printf -v "$1" '%s' yes ;;
    n|N|no|NO|No|false|FALSE|False)  printf -v "$1" '%s' no ;;
    *) die "$1 must be yes or no (got '$v')" ;;
  esac
}
# Kernel CSPRNG, not $RANDOM — 15 bits of a seeded PRNG has no business near a token PIN
# or a database password. `head -c` comes FIRST so nothing dies of SIGPIPE under pipefail.
rand_secret() {
  local n="${1:-32}" s
  s=$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-"$n")
  [ "${#s}" -eq "$n" ] || die "could not generate $n random characters"
  printf '%s' "$s"
}

echo "── FastPKI native install wizard (Alpine + OpenRC) ────────────────────" >&2
ask DEPLOYMENT "Deployment type (single / cluster)" "single"
case "$DEPLOYMENT" in single|cluster) ;; *) die "DEPLOYMENT must be 'single' or 'cluster'" ;; esac

ask PKI_DNS "Public FQDN of this deployment" "pki.example.org"

DATACENTER_ID=""
if [ "$DEPLOYMENT" = cluster ]; then
  ask DC_COUNT "Number of data centers in the mesh (N)" "3"
  ask DC_INDEX "This node's data center index (1..$DC_COUNT)" "1"
  ask PG_BIND  "This node's mesh-reachable IP (peers subscribe to Postgres here)" "127.0.0.1"
  case "$DC_COUNT" in ''|*[!0-9]*) die "DC_COUNT must be a positive integer" ;; esac
  case "$DC_INDEX" in ''|*[!0-9]*) die "DC_INDEX must be a positive integer" ;; esac
  [ "$DC_COUNT" -ge 1 ] || die "DC_COUNT must be >= 1"
  { [ "$DC_INDEX" -ge 1 ] && [ "$DC_INDEX" -le "$DC_COUNT" ]; } || die "DC_INDEX must be in 1..$DC_COUNT"
  # 32767 is the ceiling because a DER integer is SIGNED: a prefix with its high bit set
  # makes OpenSSL pad the serial to 21 octets, past the RFC 5280 §4.1.2.2 limit.
  [ "$DC_COUNT" -le 32767 ] || die "DC_COUNT must be <= 32767 (serial prefix is 2 octets, high bit reserved)"
  # ⚠️ The PREFIX is not written anywhere here, on purpose — only DATACENTER_ID. The
  # prefix lives in the `datacenters` table, which `fastpki-mesh --map` fills from the
  # topology file, and this node reads its own row at startup. One source of truth.
  DATACENTER_ID="$DC_INDEX"
else
  ask PG_BIND "Postgres listen address (127.0.0.1 for a single server; this server's own IP if you will add an HA standby)" "127.0.0.1"
  # ⚠️ A SINGLE NODE IS Data center 1, NOT "no data center" — same reasoning as
  # deploy/install.sh. Without an id, set_random_serial() mints full-width serials carrying
  # no prefix, and every certificate issued before a later expansion sits outside this
  # node's partition forever: the two-datacenters-cannot-collide guarantee holds only from
  # the conversion onward, and `certs_dc_range` refuses those historical rows on any LOCAL
  # insert, which is what a restore is. Setting it now costs 16 bits of a 160-bit serial —
  # 144 bits of entropy against a 64-bit floor — and nothing reads the prefix until a
  # second datacenter exists.
  DC_INDEX=1
  DATACENTER_ID=1
fi

# Native-only: compose always ran Postgres beside the apps, so install.sh never had to
# ask. A cloud deployment may point at a managed database (RDS, Cloud SQL) instead, and
# then this host initialises no cluster and enables no postgresql service.
yesno PG_LOCAL "Run PostgreSQL on this host (no = use an existing/managed server)" "yes"
PG_SSLROOTCERT="$PKI_DIR/tls/pg/ca.crt"
if [ "$PG_LOCAL" = no ]; then
  ask PG_HOST "PostgreSQL host" ""
  [ -n "$PG_HOST" ] || die "PG_LOCAL=no needs PG_HOST"
  ask PG_PORT "PostgreSQL port" "5432"
  # ⚠️ A MANAGED SERVER NEEDS ITS OWN ANCHOR, AND THE DEFAULT IS THE WRONG ONE.
  # Every FastPKI conninfo is sslmode=verify-full, and on a local install the anchor is
  # the certificate certgen self-signed for this node's own PostgreSQL. A managed server
  # (RDS, Cloud SQL) serves a certificate from the provider's CA, which that file knows
  # nothing about — so the very first connection fails with a certificate-verify error
  # that reads like a networking problem. Ask for the bundle rather than let the default
  # be silently wrong.
  ask PG_SSLROOTCERT "CA bundle that signs the managed server's certificate" \
      "/etc/fastpki/pg-ca.crt"
  case "$PG_SSLROOTCERT" in /*) ;; *) die "PG_SSLROOTCERT must be an absolute path" ;; esac
  if [ "$PRINT_ONLY" = 0 ] && [ ! -r "$PG_SSLROOTCERT" ]; then
      echo "install-native: $PG_SSLROOTCERT does not exist yet." >&2
      echo "  Download your provider's CA bundle to that path before continuing —" >&2
      echo "  sslmode=verify-full cannot be satisfied without it, and every service" >&2
      echo "  would fail its first database connection." >&2
      die "missing $PG_SSLROOTCERT"
  fi
  # The role and database are the operator's to create on a managed server; the schema
  # steps below still run against them.
  echo "  note: PG_LOCAL=no — create the 'fastpki' role and database on $PG_HOST yourself." >&2
  echo "        This installer loads the schema into them but does not create them." >&2
else
  PG_HOST="127.0.0.1"; PG_PORT=5432
fi

ask CMP_CLIENT_CA_ID "CMP client-cert trust anchor: a registered CA id (blank = PBM-secret auth only)" ""

# ⚠️ A RE-RUN MUST NOT INVENT NEW SECRETS. SoftHSM keeps the PIN its token was INITIALISED
# with and nothing here can change it, so generating a fresh one on a second run writes a
# PIN that cannot open the existing token: every issuing service then fails with "The
# specified PIN is invalid" and fastpki-ca reports "no private key found at pkcs11 URI" for
# CAs whose keys are sitting in that token, intact. Measured on Kubernetes, where apply.sh
# had the identical defect; this path would fail the same way, and recovering it means
# putting the original PIN back by hand. The database password is the same shape — a new one
# does not match the role that already exists.
#
# So both are read back from /etc/conf.d/fastpki and the DB conninfo this installer wrote
# last time, and offered as the default. Answering blank on a re-run then keeps what works
# rather than breaking it, and a genuinely fresh install still generates.
_prev_confd() {   # <VAR> — read a value out of the previous /etc/conf.d/fastpki
  [ -r "$CONFD" ] || return 0
  sed -n "s/^$1=//p" "$CONFD" 2>/dev/null | head -1
}
_PREV_PIN="$(_prev_confd FASTPKI_PIN)"
# Not a secret, but the same shape: a standby is made one by hand, after install (docs/high-
# availability.md §4), so a re-run that did not carry this over would quietly turn the host
# back into something that follows nobody.
_PREV_STANDBY_OF="$(_prev_confd STANDBY_OF)"
# ⚠️ THE CONSOLE'S PORT SURVIVES A RE-RUN, and it has to be carried from bootstrap.conf
# rather than from conf.d, because that is where it lives. This installer asks no port
# question: a cloud node's console is moved to 443 by the first-boot script AFTER the
# install, by editing bootstrap.conf. So an update — unpack the new package, run this
# script again, which is what docs/admin-guide.md §14.4 says to do — rewrote the file
# without the key and put the console back on 8090. Measured on a running node: after the
# documented update the console answered on 8090 and nothing at all on 443, while every
# published address and every bookmark still said 443.
_prev_bootstrap() {   # <VAR> — read a value out of the previous /etc/fastpki/bootstrap.conf
  [ -r /etc/fastpki/bootstrap.conf ] || return 0
  sed -n "s/^$1=//p" /etc/fastpki/bootstrap.conf 2>/dev/null | head -1
}
_PREV_WEB_PORT="$(_prev_bootstrap WEB_PORT)"
# ⚠️ GUARDED, AND NOT AN AND-LIST. `set -euo pipefail` is on: a bare `[ -n "$x" ] && echo`
# exits the whole script when the test is false, and a `sed` on a file that does not exist
# fails the pipeline even with stderr discarded. Both bite on a FIRST install, where neither
# file is there yet — which is every install this script is actually for.
_PREV_PW=""
if [ -r "$CONF" ]; then
  _PREV_PW="$(sed -n 's/.*[?&;[:space:]]password=\([^ &;]*\).*/\1/p' "$CONF" | head -1 || true)"
fi
if [ -n "$_PREV_PIN" ]; then
  echo "  found the token PIN from a previous install — blank keeps it" >&2
fi
ask PG_PASSWORD "Postgres password (blank = keep/generate)" "${_PREV_PW:-}"
[ -n "${PG_PASSWORD:-}" ] || { PG_PASSWORD="$(rand_secret 32)"; echo "  generated a 32-character password" >&2; }
ask PKCS11_PIN "Token PIN (blank = keep/generate)" "${_PREV_PIN:-}"
[ -n "${PKCS11_PIN:-}" ] || { PKCS11_PIN="$(rand_secret 32)"; echo "  generated a 32-character PIN" >&2; }

# ⚠️ THE TUNNEL IS AN ANSWER, NOT ONLY AN ENVIRONMENT VARIABLE. These were read from the
# environment alone, so an answers file naming them — which is the ONLY way cloud-init can
# configure anything — was silently ignored. The node then initialised its OWN token and
# served it locally, which looks entirely healthy: the services start, the console answers,
# and the only symptom is that every node has a different token serial and none of them can
# see the CA keys the token host holds. Measured on three cloud-image nodes.
# An answers file wins over the environment, matching every other key here.
# `|| true` on each: `set -e` is on, and `[ -n "$x" ] && VAR=…` exits non-zero whenever the
# key is ABSENT — which is the common case — so without it the installer would abort on
# every deployment that does not publish its token.
_a="$(ansval P11_TLS)"         || true; [ -n "$_a" ] && P11_TLS="$_a"                 || true; : "${P11_TLS:=off}"
_a="$(ansval P11_TLS_PORT)"    || true; [ -n "$_a" ] && P11_TLS_PORT="$_a"            || true; : "${P11_TLS_PORT:=12345}"

# ⚠️ ONE SWITCH FOR A PAIR, THE SAME ON EVERY DEPLOYMENT PATH (install.sh, Kubernetes'
# HA_ENABLED, the AWS module's standby_dcs). "This data center will have a standby" means the
# key tunnel on, so the standby can be given the CA keys, and the OCSP, CMP RA and SCEP RA
# keys created copyable. The second is decided NOW or never: a key is copyable or not from
# the moment it is generated, and those are generated as soon as a CA exists. A standby that
# cannot receive them cannot answer OCSP or CMP after a failover.
yesno HA_ENABLED "Will this data center have a standby server that takes over if this one is lost" "no"
if [ "$HA_ENABLED" = yes ]; then
  [ "$P11_TLS" != off ] || [ -z "$(ansval P11_TLS)" ] \
    || die "HA_ENABLED=yes with P11_TLS=off: the standby receives the CA keys only over the key tunnel. Leave P11_TLS unset (HA_ENABLED turns it on) or set it to on."
  P11_TLS=on
  case "${PG_BIND:-}" in
    ""|127.*|localhost|::1)
      die "a data center with a standby needs PG_BIND to be this server's own routable address, because the standby connects to Postgres there. Got '${PG_BIND:-}'." ;;
  esac
fi

# A private key lives in a token and never in a file, so the question is WHICH token, not
# whether — "file" is deliberately not on offer.
#   softhsm  the bundled token, served out of process by p11-kit over a unix socket so no
#            app loads SoftHSM in-process (that combination deadlocks). Dev/demo posture.
#   hsm      your own PKCS#11 module, loaded directly. The production default, and on a
#            cloud instance that means the provider's HSM client library (for example
#            AWS CloudHSM's /opt/cloudhsm/lib/libcloudhsm_pkcs11.so).
ask KEY_BACKEND "Key storage (softhsm = bundled token, dev/demo; hsm = your own PKCS#11 module)" "softhsm"
PKCS11_MODULE_OUT="/usr/lib/pkcs11/p11-kit-client.so"
case "$KEY_BACKEND" in
  softhsm) ;;
  hsm)
    ask PKCS11_MODULE "Absolute path to the vendor PKCS#11 module on this host" ""
    case "${PKCS11_MODULE:-}" in
      /*) ;;
      "") die "KEY_BACKEND=hsm needs PKCS11_MODULE=<absolute path to the vendor .so>" ;;
      *)  die "PKCS11_MODULE must be an ABSOLUTE path (got '$PKCS11_MODULE')" ;;
    esac
    PKCS11_MODULE_OUT="$PKCS11_MODULE"
    # The bundled token is always labelled `fastpki`; somebody else's HSM is labelled
    # whatever they labelled it, and every transport-key URI below names the token.
    ask PKCS11_TOKEN "Token label on that module" "fastpki" ;;
  *) die "KEY_BACKEND must be 'softhsm' or 'hsm'" ;;
esac
PKCS11_TOKEN="${PKCS11_TOKEN:-fastpki}"

echo >&2
echo "Which protocols should this deployment run? Anything you decline is not started" >&2
echo "and not monitored — its OpenRC service is simply not added to the default runlevel." >&2
yesno WANT_EST   "  EST (RFC 7030)"                     yes
yesno WANT_ACME  "  ACME (RFC 8555)"                    yes
yesno WANT_CMP   "  CMP (RFC 4210/9483)"                yes
yesno WANT_SCEP  "  SCEP (RFC 8894)"                    yes
yesno WANT_MS    "  MS-XCEP/WSTEP (Windows auto-enrol)" yes
yesno WANT_STORE "  Certificate store (RFC 4387)"       yes
# ⚠️ OCSP AND THE CONSOLE ARE NOT ASKED, exactly as in install.sh. fastpki-ocsp serves the
# CRL endpoints too, so a PKI without it issues certificates and publishes no revocation
# information at all; and without the console there is no way to create a CA. Neither is a
# smaller deployment — both are an incomplete one.

# FastPKI mints one key per service inside the token at first start. Asked PER SERVICE so
# a customer has full control, and only for the services this deployment will run: asking
# for a curve for a listener that was just declined is a form, not a conversation.
# ⚠️ THE ALLOWED SET IS PER SERVICE and passed in, not hardcoded — the four constraints
# differ and one list would be wrong for three of them (docs/compatibility.md §1). A TLS
# listener is limited to what a peer will negotiate; the OCSP responder gets the same reach
# because it answers Windows and libpq too; the CMP RA can use anything OpenSSL signs with,
# since the client IS OpenSSL; and a SCEP RA key must be plain RSA because it decrypts the
# PKIOperation envelope, so it is not asked here at all. Keep this in step with
# deploy/install.sh, which asks the same questions for the compose deployment.
ask_service_key() {   # ask_service_key <PREFIX> <human name> <allowed algorithms> [ask digest: yes|no]
  local p="$1" n="$2" allowed="$3" want_md="${4:-no}" a b c m list
  list="$(printf '%s' "$allowed" | sed 's/ /, /g')"
  ask "${p}_KEY_ALGO" "Key type for the ${n} key (${list})" ec
  a="$(eval "printf '%s' \"\${${p}_KEY_ALGO}\"")"
  case " $allowed " in
    *" $a "*) ;;
    *) die "${p}_KEY_ALGO must be one of: ${list} (got '$a')" ;;
  esac
  printf -v "${p}_KEY_BITS" '%s' ""; printf -v "${p}_KEY_CURVE" '%s' ""; printf -v "${p}_KEY_MD" '%s' ""
  case "$a" in
    ec)
      ask "${p}_KEY_CURVE" "  EC curve for the ${n} key (P-256, P-384, P-521)" P-256
      c="$(eval "printf '%s' \"\${${p}_KEY_CURVE}\"")"
      case "$c" in P-256|P-384|P-521) ;; *) die "${p}_KEY_CURVE must be P-256, P-384 or P-521 (got '$c')" ;; esac ;;
    rsa|rsa-pss)
      ask "${p}_KEY_BITS" "  RSA size for the ${n} key (2048, 3072, 4096)" 3072
      b="$(eval "printf '%s' \"\${${p}_KEY_BITS}\"")"
      case "$b" in 2048|3072|4096) ;; *) die "${p}_KEY_BITS must be 2048, 3072 or 4096 (got '$b')" ;; esac ;;
    # ed25519, ed448 and the ML-DSA parameter sets carry their size in the name — nothing
    # further to ask, and asking would imply a choice that does not exist.
  esac
  # The digest is a question only where a choice exists: EC, Ed and ML-DSA carry their own
  # or are one-shot. Blank means auto-match the key.
  if [ "$want_md" = yes ]; then
    case "$a" in
      rsa|rsa-pss)
        ask "${p}_KEY_MD" "  Signature digest for the ${n} certificate (blank = auto; sha256, sha384, sha512, sha3-256, sha3-384, sha3-512)" ""
        m="$(eval "printf '%s' \"\${${p}_KEY_MD}\"")"
        case "$m" in
          ''|sha256|sha384|sha512|sha3-256|sha3-384|sha3-512) ;;
          *) die "${p}_KEY_MD must be blank or one of sha256, sha384, sha512, sha3-256, sha3-384, sha3-512 (got '$m')" ;;
        esac ;;
    esac
  fi
}
TLS_KEY_ALGOS='ec rsa rsa-pss'
CMP_KEY_ALGOS='ec rsa rsa-pss ed25519 ed448 ML-DSA-44 ML-DSA-65 ML-DSA-87'
echo >&2
echo "FastPKI generates one key per service inside the token at first start." >&2
echo "Answer per service, or press Enter for the default (ec / P-256)." >&2
ask_service_key WEB "web console TLS" "$TLS_KEY_ALGOS" yes
[ "$WANT_EST"  = yes ] && ask_service_key EST  "EST listener TLS"  "$TLS_KEY_ALGOS" yes
[ "$WANT_ACME" = yes ] && ask_service_key ACME "ACME listener TLS" "$TLS_KEY_ALGOS" yes
[ "$WANT_MS"   = yes ] && ask_service_key MS   "MS-XCEP/WSTEP listener TLS" "$TLS_KEY_ALGOS" yes
# The RA and responder credentials: the answer is recorded now and acted on once a CA
# exists to certify them, since minting here would create token objects nothing could sign.
ask_service_key OCSP_RESPONDER "OCSP responder" "$TLS_KEY_ALGOS"
[ "$WANT_CMP" = yes ] && ask_service_key CMP_RA "CMP RA" "$CMP_KEY_ALGOS"
if [ "$WANT_SCEP" = yes ]; then
  ask SCEP_RA_KEY_BITS "RSA size for the SCEP RA key (2048, 3072, 4096) — SCEP requires RSA" 3072
  case "$SCEP_RA_KEY_BITS" in
    2048|3072|4096) ;;
    *) die "SCEP_RA_KEY_BITS must be 2048, 3072 or 4096 (got '$SCEP_RA_KEY_BITS')" ;;
  esac
fi
echo "  note: the CMP RA, SCEP RA and OCSP responder credentials are NOT created here." >&2
echo "        Those services start without them and leave the feature off until one exists;" >&2
echo "        issue them from the console once a CA is created. A SCEP RA key must be RSA." >&2

# ── the two files ─────────────────────────────────────────────────────────────────────
# /etc/fastpki/bootstrap.conf is the config the binaries read. Only keys the parser
# actually knows go in it: apply() in src/lib/config.cpp is an if/else-if chain with no
# final else, so an unrecognised key is silently ignored rather than rejected.
PG_CONNINFO="host=$PG_HOST port=$PG_PORT dbname=fastpki user=fastpki password=$PG_PASSWORD sslmode=verify-full sslrootcert=$PG_SSLROOTCERT connect_timeout=5"

conf_body() {
  printf '# FastPKI native config — generated by deploy/native/install-native.sh.\n'
  printf '# CONTAINS A SECRET (the database password in PG_CONNINFO). Mode 0640, root:%s.\n' "$SVC_USER"
  printf '#\n# Everything except PG_CONNINFO can also live in the `config` DB table, which\n'
  printf '# OVERRIDES this file. Manage it with fastpki-config or the console Config page.\n\n'
  printf 'PKI_DNS=%s\n' "$PKI_DNS"
  printf 'PG_CONNINFO=%s\n' "$PG_CONNINFO"
  # Only when the previous config had one: an install that never moved the console leaves
  # the key absent and the binary's own default applies, exactly as before.
  #
  # An `if`, not `[ -n … ] && printf`: `set -e` is on, and a false test as the last command
  # of this function would make it return non-zero and take the script down — which is the
  # trap the comment beside _PREV_STANDBY_OF describes.
  if [ -n "${_PREV_WEB_PORT:-}" ]; then
    printf 'WEB_PORT=%s\n' "$_PREV_WEB_PORT"
  fi
  printf 'PKCS11_MODULE=%s\n' "$PKCS11_MODULE_OUT"
  printf 'PKCS11_TOKEN=%s\n' "$PKCS11_TOKEN"
  # The services never receive the PIN in their environment — a value there is readable
  # in /proc/<pid>/environ for the life of the process. certgen.sh writes it to this
  # path, 0400 and owned by the runtime user, and they read it off disk.
  printf 'PKCS11_PIN_FILE=%s\n' "$PKI_DIR/tls/pin"
  [ -n "$DATACENTER_ID" ] && printf 'DATACENTER_ID=%s\n' "$DATACENTER_ID"
  # A pair's service keys, created copyable from the first one (HA_ENABLED, above).
  [ "${HA_ENABLED:-no}" = yes ] && printf 'SERVICE_KEYS_REPLICABLE=true\n'
  # ⚠️ PG_TLS_SANS IS DERIVED, NOT ASKED AGAIN. `fastpki-ca pg-tls` reads the names for the
  # database certificate out of CONFIG rather than its arguments, so a node whose config
  # omits its interconnect address gets a certificate without that SAN — and every peer
  # then refuses it under sslmode=verify-full, long after the CAs exist and the hard part
  # looks done. PG_BIND is that address; the installer already asked for it as "this node's
  # mesh-reachable IP (peers subscribe to Postgres here)", so asking twice would only give
  # an operator a way to disagree with themselves. k8s apply.sh derives it the same way.
  if [ "${DEPLOYMENT:-single}" = cluster ] && [ -n "${PG_BIND:-}" ] && [ "$PG_BIND" != "127.0.0.1" ]; then
    printf 'PG_TLS_SANS=%s\n' "$PG_BIND"
  fi
  [ -n "${CMP_CLIENT_CA_ID:-}" ] && printf 'CMP_CLIENT_CA_ID=%s\n' "$CMP_CLIENT_CA_ID"
  # ── EVERY LISTENER'S KEY IS A TOKEN HANDLE, AND IT MUST BE STATED ────────────────
  # These are the same settings deploy/bootstrap.compose.conf carries, and leaving them
  # out is not a smaller config — it is a different product. Measured on a native install
  # that omitted them: fastpki-web came up on PLAIN HTTP, silently, because the default
  # log level is `err` and falling back is not an error. The console needs a secure
  # context for in-browser key generation and the HSM slot picker, so "it started" and
  # "it works" were different answers, and nothing said so.
  #
  # The object names are per listener and fixed (web-tls, est-tls, …): each service mints
  # its own key inside the token on first start and self-signs against it, then adopts a
  # CA-issued certificate when one exists. pin-source points at the PIN file rather than
  # carrying the PIN, for the same reason nothing else does.
  #
  # ⚠️ OCSP_RESPONDER_KEY CARRIES pin-source, like every sibling URI. It did not, on the
  # grounds that bootstrap.compose.conf did not either — and that has since been corrected
  # there. docs/deployment.md 9.1 is explicit about why: a shortened pkcs11 URI resolves on some
  # nodes and not others, because without pin-source the provider falls back to
  # PKCS11_PIN_FILE and, when that fallback does not fire, prompts for a PIN nobody can type
  # and reports the misleading "The token was not present in its slot".
  # Mirrored rather than "improved" here: two files disagreeing about one deployment's
  # token URIs is worse than one oddity, and tests/native_deploy.sh asserts they agree.
  printf 'WEB_TLS_KEY=pkcs11:token=%s;object=web-tls;type=private?pin-source=%s\n' \
      "$PKCS11_TOKEN" "$PKI_DIR/tls/pin"
  printf 'WEB_CERT_ID=web\n'
  printf 'OCSP_RESPONDER_KEY=pkcs11:token=%s;object=ocsp-ra;type=private?pin-source=%s\n' "$PKCS11_TOKEN" "$PKI_DIR/tls/pin"
  [ "$WANT_EST"  = yes ] && { printf 'EST_KEY=pkcs11:token=%s;object=est-tls;type=private?pin-source=%s\n' "$PKCS11_TOKEN" "$PKI_DIR/tls/pin"; printf 'EST_CERT_ID=est\n'; }
  [ "$WANT_ACME" = yes ] && { printf 'ACME_KEY=pkcs11:token=%s;object=acme-tls;type=private?pin-source=%s\n' "$PKCS11_TOKEN" "$PKI_DIR/tls/pin"; printf 'ACME_CERT_ID=acme\n'; }
  [ "$WANT_MS"   = yes ] && { printf 'MS_KEY=pkcs11:token=%s;object=ms-tls;type=private?pin-source=%s\n' "$PKCS11_TOKEN" "$PKI_DIR/tls/pin"; printf 'MS_CERT_ID=ms\n'; }
  [ "$WANT_CMP"  = yes ] && printf 'CMP_RA_KEY=pkcs11:token=%s;object=cmp-ra;type=private?pin-source=%s\n' "$PKCS11_TOKEN" "$PKI_DIR/tls/pin"
  # ⚠️ SCEP NEEDS ITS RA KEY WRITTEN, AND ONLY THE COMPOSE FILE HAD IT. This asked for
  # SCEP_RA_KEY_BITS and wrote that, but never wrote SCEP_RA_KEY itself — so a native or
  # cloud install with SCEP enabled fell back to the CA's OWN key, which works only while
  # that CA happens to be RSA. It silently does not on an EC CA, which is the default the
  # console offers and what a shared-token mesh is likely to be using. Measured on a
  # three-node cloud deployment: zero SCEP_RA_KEY lines in bootstrap.conf, against an
  # EC P-256 sub CA. bootstrap.compose.conf:64-72 spells out the same trap for compose.
  [ "$WANT_SCEP" = yes ] && printf 'SCEP_RA_KEY=pkcs11:token=%s;object=scep-ra;type=private?pin-source=%s\n' "$PKCS11_TOKEN" "$PKI_DIR/tls/pin"

  local p a b c m
  # OCSP_RESPONDER and CMP_RA ride the same loop: their variables are named for the config
  # keys they become, so nothing here special-cases them.
  for p in WEB $([ "$WANT_EST" = yes ] && echo EST) $([ "$WANT_ACME" = yes ] && echo ACME) \
           $([ "$WANT_MS" = yes ] && echo MS) OCSP_RESPONDER \
           $([ "$WANT_CMP" = yes ] && echo CMP_RA); do
    a="$(eval "printf '%s' \"\${${p}_KEY_ALGO}\"")"
    b="$(eval "printf '%s' \"\${${p}_KEY_BITS:-}\"")"
    c="$(eval "printf '%s' \"\${${p}_KEY_CURVE:-}\"")"
    m="$(eval "printf '%s' \"\${${p}_KEY_MD:-}\"")"
    printf '%s_KEY_ALGO=%s\n' "$p" "$a"
    # Only the setting that APPLIES: an EC answer carries no _BITS and an RSA one no
    # _CURVE, so the file never states a value the algorithm ignores.
    [ -n "$b" ] && printf '%s_KEY_BITS=%s\n' "$p" "$b"
    [ -n "$c" ] && printf '%s_KEY_CURVE=%s\n' "$p" "$c"
    [ -n "$m" ] && printf '%s_KEY_MD=%s\n' "$p" "$m"
    true
  done
  # SCEP has no algorithm line — the RA key must be plain RSA, so only the size is an answer.
  [ "$WANT_SCEP" = yes ] && printf 'SCEP_RA_KEY_BITS=%s\n' "$SCEP_RA_KEY_BITS"
  true
}

# /etc/conf.d/fastpki is read by the OpenRC init scripts, and by nothing else. It is 0600
# root-owned because it carries FASTPKI_PIN, which fastpki-token needs to INITIALISE the
# token on first boot. Sourcing a file sets a shell variable without exporting it, so that
# PIN reaches the init script and stops there — it is never in a daemon's environment.
confd_body() {
  printf '# FastPKI OpenRC settings — generated by deploy/native/install-native.sh.\n'
  printf '# CONTAINS A SECRET (the token PIN, used only to initialise the token on first\n'
  printf '# boot). Mode 0600, root-owned. See deploy/native/openrc/fastpki.initd.\n\n'
  printf 'FASTPKI_USER=%s\n' "$SVC_USER"
  printf 'FASTPKI_CONF=%s\n' "$CONF"
  printf 'FASTPKI_BINDIR=%s\n' "$BINDIR"
  printf 'PKCS11_MODULE=%s\n' "$PKCS11_MODULE_OUT"
  printf 'PKCS11_TOKEN=%s\n' "$PKCS11_TOKEN"
  printf 'FASTPKI_PIN=%s\n' "$PKCS11_PIN"
  # P11_TLS decides whether the PUBLISHER half runs, and certgen mints the material under
  # it — so it has to persist too, or a reboot silently drops the transport.
  [ "${P11_TLS:-off}" = "on" ] && printf 'P11_TLS=on\n' || true
  [ -n "${P11_TLS_PORT:-}" ] && printf 'P11_TLS_PORT=%s\n' "$P11_TLS_PORT" || true
  # ⚠️ PG_BIND NAMES THIS MACHINE, AND THE SERVICES READ IT FROM THEIR ENVIRONMENT. It is
  # the host id under which this node publishes its token-transport certificates and its
  # Replication-page report, with PKI_DNS as the fallback — and the two hosts of an HA pair
  # share PKI_DNS by design. It used to go only into Postgres's listen_addresses and
  # PG_TLS_SANS, so both hosts of a native pair published under the shared name, the second
  # overwrote the first, and no key could be replicated between them. compose writes it to
  # .env for the same reason. fastpki.initd, fastpki-p11-tls and fastpki-certrenew hand it on.
  printf 'PG_BIND=%s\n' "$PG_BIND"
  [ -n "$_PREV_STANDBY_OF" ] && printf 'STANDBY_OF=%s\n' "$_PREV_STANDBY_OF" || true
  printf 'FASTPKI_SERVICES="%s"\n' "$SERVICES"
}

SERVICES="fastpki-web fastpki-ocsp"
for pair in "est:$WANT_EST" "acme:$WANT_ACME" "cmp:$WANT_CMP" "scep:$WANT_SCEP" \
            "ms:$WANT_MS" "store:$WANT_STORE"; do
  [ "${pair##*:}" = yes ] && SERVICES="$SERVICES fastpki-${pair%%:*}"
done

if [ "$PRINT_ONLY" = 1 ]; then
  echo "── $CONF ──"; conf_body
  echo; echo "── $CONFD ──"; confd_body
  exit 0
fi

run_step() {   # run_step <description> <cmd...>
  echo; echo "==> $1" >&2
  shift
  if ! "$@"; then
    echo >&2
    echo "FAILED: $*" >&2
    echo "  The configuration files are written and valid — fix the cause and re-run" >&2
    echo "  install-native.sh; every step below is idempotent." >&2
    exit 1
  fi
}

# ── 1. service user and directories ───────────────────────────────────────────────────
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
  addgroup -S "$SVC_USER"
  adduser -S -G "$SVC_USER" -H -s /sbin/nologin "$SVC_USER"
  echo "created the $SVC_USER system user" >&2
fi
install -d -m 0755 -o root -g root "$CONF_DIR"
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$PKI_DIR" "$PKI_DIR/tls" "$PKI_DIR/ca" /var/log/fastpki

# ── 2. the two configuration files ────────────────────────────────────────────────────
# 0600/0640 BEFORE the write, not after: between creating a world-readable file and
# chmod'ing it there is a window in which the password is readable, and it is exactly the
# sort of window nobody notices because nothing fails.
( umask 077; conf_body > "$CONF" )
chown "root:$SVC_USER" "$CONF"; chmod 0640 "$CONF"
( umask 077; confd_body > "$CONFD" )
chown root:root "$CONFD"; chmod 0600 "$CONFD"
echo "wrote $CONF (0640 root:$SVC_USER) and $CONFD (0600 root:root)" >&2

# ── 3. PostgreSQL ─────────────────────────────────────────────────────────────────────
# Everything compose expressed as `-c` flags on the postgres command line, expressed here
# as an include file. postgresql.auto.conf is still read LAST, so ALTER SYSTEM keeps
# winning — which matters because the HA standby sets synchronized_standby_slots that way
# and deploy/pg-promote.sh clears it. Putting these on the command line instead would make
# both of those silent no-ops, which is the same reasoning the compose file records.
# Alpine's postgresql init script keeps the path in /etc/conf.d/postgresql, and has
# spelled it both `data_dir` and `PGDATA` across releases. Sourcing the file in a subshell
# reads whichever it is without this script having to parse shell quoting; the versioned
# default is the fallback for a layout that declares neither.
pg_data_dir() {
  local d="" maj=""
  if [ -r /etc/conf.d/postgresql ]; then
    d="$( . /etc/conf.d/postgresql >/dev/null 2>&1; printf '%s' "${data_dir:-${PGDATA:-}}" )"
  fi
  if [ -z "$d" ]; then
    maj="$(ls -d /usr/libexec/postgresql[0-9]* 2>/dev/null | sed 's|.*/postgresql||' | sort -n | tail -1)"
    [ -n "$maj" ] && d="/var/lib/postgresql/$maj/data"
  fi
  printf '%s' "$d"
}

if [ "$PG_LOCAL" = yes ]; then
  command -v initdb >/dev/null 2>&1 || command -v pg_ctl >/dev/null 2>&1 \
    || die "PG_LOCAL=yes but PostgreSQL is not installed (apk add postgresql17)"
  PGDATA="$(pg_data_dir)"
  [ -n "$PGDATA" ] || die "could not determine the PostgreSQL data directory"

  if [ ! -f "$PGDATA/PG_VERSION" ]; then
    run_step "initialising the PostgreSQL cluster at $PGDATA" \
        rc-service postgresql setup
  else
    echo "PostgreSQL cluster already initialised at $PGDATA — leaving it alone" >&2
  fi

  # An include file rather than edits to postgresql.conf, so a re-run replaces one file
  # instead of accumulating duplicate settings at the end of another.
  #
  # ⚠️ AN ABSOLUTE include_dir, AND OUTSIDE $PGDATA. Both halves are load-bearing, and the
  # first one cost a boot:
  #
  #   Alpine's `rc-service postgresql setup` MOVES the configuration out of the data
  #   directory into $conf_dir (/etc/postgresql) and symlinks it back. So appending to
  #   "$PGDATA/postgresql.conf" follows that symlink and lands in /etc/postgresql — and a
  #   RELATIVE `include_dir '"'"'conf.d'"'"'` resolves against the directory holding the config
  #   file, i.e. /etc/postgresql/conf.d, not $PGDATA/conf.d. Measured: the server refused
  #   to start with `could not open configuration directory "/etc/postgresql/conf.d"`,
  #   which names a path this script never mentions.
  #
  #   And outside $PGDATA for the reason the compose file already records about the TLS
  #   pair: pg_basebackup copies the whole data directory, so a standby seeded from this
  #   node would inherit this node'"'"'s listen_addresses and fight its own installer over it.
  install -d -m 0750 -o root -g postgres "$PG_CONF_D"
  cat > "$PG_CONF_D/fastpki.conf" <<PGCONF
# Generated by deploy/native/install-native.sh — do not edit; re-run the installer.
#
# wal_level=logical is what makes the multi-data-center active-active mesh possible:
# without it CREATE SUBSCRIPTION cannot stream. It is negligible overhead on a single
# node, so it is set unconditionally rather than only for a cluster.
wal_level = logical
max_wal_senders = 10
max_replication_slots = 10
# CAPS what an unconsumed slot can pin. A cut interconnect pins WAL and xmin on both
# nodes for the length of the partition, and an uncapped slot fills the disk — which
# presents as a network outage rather than as a full volume. Past the cap the slot is
# INVALIDATED (wal_status='lost'), which is visible and recoverable.
max_slot_wal_keep_size = 8GB
# Name the client on every line. A bare prefix means an auth FATAL prints neither the
# user nor the address it came from. %q suppresses both for background processes that
# have no session, so startup and checkpointer lines stay clean.
log_line_prefix = '%m [%p] %q%u@%d %h '
listen_addresses = '${PG_BIND},127.0.0.1'
port = 5432
# TLS is unconditional here, unlike the compose service which turns it on only if a
# certificate happens to exist: the installer runs certgen and stages the pair BEFORE it
# ever starts the server, and that staging step fails loudly if it cannot. A deployment
# that reaches this point has a certificate, so "come up in plaintext instead" is not a
# fallback worth having — every FastPKI conninfo is sslmode=verify-full and would fail
# anyway, one layer further from the cause.
ssl = on
ssl_cert_file = '/var/lib/postgresql/tls/server.crt'
ssl_key_file = '/var/lib/postgresql/tls/server.key'
PGCONF
  chown root:postgres "$PG_CONF_D/fastpki.conf"
  chmod 0640 "$PG_CONF_D/fastpki.conf"
  # Appending to $PGDATA/postgresql.conf is right even though Alpine symlinks it: the
  # symlink is followed, so the line lands in whichever file the server actually reads.
  grep -q "include_dir '$PG_CONF_D'" "$PGDATA/postgresql.conf" \
    || printf "\ninclude_dir '%s'\n" "$PG_CONF_D" >> "$PGDATA/postgresql.conf"

  # pg_hba: the apps connect with sslmode=verify-full, so every FastPKI rule is hostssl.
  # A marker comment keeps the append idempotent across re-runs.
  HBA="$PGDATA/pg_hba.conf"
  if ! grep -q 'FASTPKI' "$HBA"; then
    cat >> "$HBA" <<'PGHBA'

# FASTPKI: the apps and the mesh. hostssl throughout — every FastPKI conninfo is
# sslmode=verify-full, and a `host` rule here would let a misconfigured client fall
# back to plaintext and still succeed, which is the failure you never notice.
hostssl all         fastpki 127.0.0.1/32  scram-sha-256
hostssl all         fastpki ::1/128       scram-sha-256
hostssl all         fastpki all           scram-sha-256
hostssl replication fastpki all           scram-sha-256
PGHBA
    chown postgres:postgres "$HBA"
  fi
fi

# ── 4. transport TLS (certgen) ────────────────────────────────────────────────────────
# The same script the compose stack runs, unchanged: a fresh deployment has no CA (CAs
# live in the DB), but the app<->Postgres link and the console must still be encrypted
# from first boot, so this self-signs one certificate for both. Idempotent — a
# still-valid certificate is a no-op — and it also writes the token PIN file the services
# read instead of receiving the PIN in their environment.
#
# Phase 2, replacing this with a CA-issued certificate carrying the interconnect SANs,
# happens once a CA exists: `fastpki-ca pg-tls <ca-id>` (scriptable, and what a mesh
# bootstrap uses) or the console, Endpoints -> PostgreSQL -> Issue certificate.
# ⚠️ PKI_DNS, and it must be passed EXPLICITLY. ask() assigns with `printf -v`, which makes
# a shell variable and not an exported one, so certgen.sh sees only what this `env` hands it.
# A name that does not arrive is not an error: certgen falls back to its `localhost`
# default and the install issues its transport certificate for the wrong name, silently,
# because a certificate for `localhost` still verifies against itself. PKI_DNS is the only
# name for it — never pass a second one beside it.
# ⚠️ THE PIN IS EXPORTED, NOT PASSED IN argv. `ps` shows a process's arguments to every user
# on the host, so `env FASTPKI_PIN=… sh certgen.sh` published the PIN protecting every CA
# private key for as long as certgen ran — the same rule `--bind-pw-file` follows for a
# directory password, and the HSM PIN deserves it at least as much. run_step also echoes
# "FAILED: $*" on error, which printed it a second time, to a log an operator would paste
# into a ticket.
# ⚠️ P11_TLS TOO, OR THE TUNNEL MATERIAL IS NEVER MINTED AND THE INSTALL FAILS AT THE LAST
# STEP. P11_TLS=on is what makes certgen mint the tunnel keypair in the token and write
# and this handed certgen only PKI_DNS — so the installer went on to start
# fastpki-p11-tls, which refuses to publish a token unauthenticated:
#     no transport keypair in /var/pki/tls/p11.
#     ERROR: fastpki-p11-tls failed to start
# and the whole install exited non-zero after everything else had succeeded. It stayed
# hidden while P11_TLS could only come from the environment, because nothing set it.
export FASTPKI_PIN="$PKCS11_PIN"
# ⚠️ THE NODE'S OWN TOKEN MUST BE SERVING BEFORE certgen RUNS, because certgen MINTS the
# tunnel's keypair inside it rather than writing a key file. Everything else in this section
# is pure openssl and needs no token, which is why certgen sat here at all; this one step
# does, so the token comes up first. Only under P11_TLS: with the transport off, certgen
# makes no PKCS#11 call. And only with the bundled SoftHSM — a vendor module is loaded
# directly by openssl and pkcs11-tool, with no p11-kit server in the path.
if [ "${P11_TLS:-off}" = "on" ] && [ "$PKCS11_MODULE_OUT" = "/usr/lib/pkcs11/p11-kit-client.so" ]; then
  rc-update add fastpki-token default >/dev/null 2>&1 || true
  run_step "starting the token server" rc-service fastpki-token start
fi
run_step "generating the self-signed transport certificate and the PIN file" \
    env PKI_DNS="$PKI_DNS" PG_BIND="${PG_BIND:-}" P11_TLS="${P11_TLS:-off}" \
        PKCS11_TOKEN="${PKCS11_TOKEN:-fastpki}" \
        PKCS11_MODULE="$PKCS11_MODULE_OUT" sh "$ASSETS/certgen.sh"
unset FASTPKI_PIN

if [ "$PG_LOCAL" = yes ]; then
  # Postgres refuses a key file it does not own, and the delivery point under /var/pki is
  # owned by the runtime user because the CONSOLE writes phase 2 there and runs as that
  # user. So the server reads a copy of its own, exactly as the compose service does.
  run_step "staging the Postgres server certificate" \
      sh /usr/libexec/fastpki/pg-tls-sync once
fi

# ── 5. start Postgres and create the database ─────────────────────────────────────────
# Declared before the block that decides it, because sections 6 and 7 read it too and an
# externally managed database never reaches the detection inside.
PG_STANDBY=no
if [ "$PG_LOCAL" = yes ]; then
  # ⚠️ CGROUPS V2, FOR THE TOKEN SERVER'S PROCESS CEILING. fastpki-token sets
  # rc_cgroup_settings="pids.max 128" so a client that leaks PKCS#11 sessions cannot fill
  # the machine with p11-kit-remote processes — measured at 516 and 616 on two nodes, which
  # exhausted them and got PostgreSQL OOM-killed. OpenRC applies that setting only when
  # cgroups v2 is mounted, and skips it in silence otherwise, so the mount is arranged here
  # rather than assumed. Both lines are idempotent.
  if ! grep -qE '^rc_cgroup_mode=' /etc/rc.conf 2>/dev/null; then
    printf 'rc_cgroup_mode="unified"\n' >> /etc/rc.conf
  fi
  rc-update add cgroups boot >/dev/null 2>&1 || true
  rc-service cgroups start >/dev/null 2>&1 || true

  rc-update add postgresql default >/dev/null 2>&1 || true
  # Ordered before postgresql by its own depend(). It clears a socket file left by a server
  # the kernel killed, which Alpine's init script otherwise reports as "a server is already
  # listening" — on a node where none is, and which then cannot start its database at all.
  rc-update add fastpki-pgstale default >/dev/null 2>&1 || true
  run_step "starting PostgreSQL" sh -c 'rc-service postgresql status >/dev/null 2>&1 || rc-service postgresql start'
  i=0; until su postgres -s /bin/sh -c 'pg_isready -q' || [ "$i" -ge 60 ]; do sleep 1; i=$((i+1)); done
  su postgres -s /bin/sh -c 'pg_isready -q' || die "PostgreSQL did not become ready"

  # ⚠️ A STANDBY OWNS NONE OF WHAT FOLLOWS, AND CANNOT WRITE IT ANYWAY. This script is also
  # the upgrade path — docs/admin-guide.md 14.4 says to run it again with the same answers —
  # so on an HA pair it runs on the standby too. Everything from here to the end of section 7
  # is a WRITE: the fastpki role, the database, the schema, the seeded admin and this node's
  # datacenters row. On a standby every one of them arrived by replication from the primary,
  # and the cluster is read-only, so the first of them stops the upgrade outright:
  #
  #     ERROR:  cannot execute ALTER ROLE in a read-only transaction
  #     FAILED: could not create the fastpki role/database
  #
  # That left the worst possible state: the new files were already unpacked, so the node had
  # the new release on disk while its services went on running the OLD programs, which the
  # upgrade never reached the point of restarting. `fastpki-web --version` reported the new
  # version while the process serving requests was the previous build.
  #
  # pg_is_in_recovery() is the authority and needs no fastpki role to ask, so it works before
  # section 5 has run even once. deploy/schema-apply.sh already declines a standby for the
  # same reason; this is the same rule, applied to the steps that run before it.
  if [ "$(su postgres -s /bin/sh -c "psql -tAqc 'select pg_is_in_recovery()'" 2>/dev/null)" = t ]; then
    PG_STANDBY=yes
    echo "==> this server is a standby — its database replicates from the primary, so the" >&2
    echo "    role, schema and seed steps are the primary's and are skipped here" >&2
  fi

  if [ "$PG_STANDBY" = no ]; then
    # CREATE ROLE / DATABASE are what the postgres:17-alpine entrypoint does from
    # POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB. Both are idempotent.
    #
    # ⚠️ THE PASSWORD IS NEVER IN argv. `psql -v pw=<secret>` would put it in the process
    # table for every user on the box to read, which is the same defect deploy/schema-apply.sh
    # repairs when it finds `psql -W <password>` in a caller's PSQL. It goes into a 0600
    # file owned by postgres instead, which is removed as soon as psql returns.
    #
    # CREATE DATABASE cannot run inside a DO block (it is not transaction-safe), hence the
    # \gexec for that one statement and a plain DO block for the role.
    #
    # ⚠️ WRITTEN FIRST, HANDED TO postgres AFTER. chown-then-write fails on any kernel with
    # fs.protected_regular set (systemd's default, so Debian and friends, and every container on
    # such a host): in a sticky world-writable directory like /tmp, even root may not O_CREAT-open
    # a file another user owns, and `cat >` is exactly that open. Measured in run-check on a
    # Debian 13 docker host: "line 748: /tmp/tmp.…: Permission denied", and the install stopped
    # before the database existed. mktemp already creates the file 0600 root.
    SQLTMP="$(mktemp)"
    chmod 0600 "$SQLTMP"
    # Double any single quote so a hand-supplied PG_PASSWORD cannot end the literal early.
    # Generated passwords are alphanumeric, but PG_PASSWORD may come from an answers file.
    _pw_esc="$(printf '%s' "$PG_PASSWORD" | sed "s/'/''/g")"
    # ⚠️ REPLICATION, OR THIS NODE CAN NEVER JOIN A MESH. Logical replication opens a WAL
    # sender, and only a role carrying that attribute may start one:
    #     FATAL: permission denied to start WAL sender
    #     DETAIL: Only roles with the REPLICATION attribute may start a WAL sender process.
    # The comment above is right that this mirrors what the postgres:17-alpine entrypoint does
    # from POSTGRES_USER — but that entrypoint creates a SUPERUSER, and a superuser bypasses
    # the check. So compose and Kubernetes replicate while a native node could not, and the
    # difference is invisible until CREATE SUBSCRIPTION on the third step of a mesh bootstrap,
    # long after the CAs and the certificates are done. Measured on three cloud-image nodes.
    #
    # ⚠️ AND pg_create_subscription, WHICH IS THE OTHER HALF AND FAILS ONE STEP LATER.
    # REPLICATION covers being a publication SOURCE. Creating a subscription is a separate
    # permission since PostgreSQL 16, which moved it off superuser onto a predefined role:
    #     ERROR: permission denied to create subscription
    #     DETAIL: Only roles with privileges of the "pg_create_subscription" role may
    #             create subscriptions.
    # A superuser passes both checks, so again compose and Kubernetes never meet this and a
    # native node meets it on pass 2 of docs/deployment.md 9.1 step 8 — with every CA, every
    # certificate and pass 1 already done. Granting REPLICATION alone moved the failure one
    # step later rather than removing it. Measured on three cloud-image nodes.
    #
    # Guarded on the role existing so this still runs against PostgreSQL 15 and older, where
    # the predefined role does not exist and superuser was the only way.
    #
    # And pg_read_all_stats, for the console's Replication page. pg_stat_replication hides a
    # standby's state, lag and address from a role that is neither a superuser nor that
    # standby's own replication user, so without it the page cannot say whether the standby
    # is streaming. Compose and Kubernetes see it because their role is a superuser. Narrower
    # than pg_monitor on purpose: that also grants reading every server setting, which the
    # page does not need.
    #
    # The attribute and the grants, not superuser: this role owns the database it needs and
    # nothing more.
    cat > "$SQLTMP" <<SQL
DO \$\$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fastpki') THEN
      ALTER ROLE fastpki LOGIN REPLICATION PASSWORD '$_pw_esc';
    ELSE
      CREATE ROLE fastpki LOGIN REPLICATION PASSWORD '$_pw_esc';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pg_create_subscription') THEN
      EXECUTE 'GRANT pg_create_subscription TO fastpki';
    END IF;
    EXECUTE 'GRANT pg_read_all_stats TO fastpki';
END
\$\$;
SELECT 'CREATE DATABASE fastpki OWNER fastpki'
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'fastpki') \gexec
SQL
    unset _pw_esc
    chown postgres "$SQLTMP"
    if ! su postgres -s /bin/sh -c "psql -q -v ON_ERROR_STOP=1 -f '$SQLTMP'"; then
        rm -f "$SQLTMP"
        echo "FAILED: could not create the fastpki role/database" >&2
        exit 1
    fi
    rm -f "$SQLTMP"
    echo "==> fastpki role and database ready" >&2
  fi
fi

# ── 6. schema ─────────────────────────────────────────────────────────────────────────
# The connection settings travel in the environment, not on the command line: the same
# invocations below then work whether the server is on this host or managed elsewhere,
# and the password stays out of every argv.
export PGPASSWORD="$PG_PASSWORD"
export PGSSLMODE=verify-full PGSSLROOTCERT="$PG_SSLROOTCERT"

schema_loaded() {
  psql -h "$PG_HOST" -p "$PG_PORT" -U fastpki -d fastpki -tAqc \
      "SELECT 1 FROM information_schema.tables WHERE table_name='schema_version'" 2>/dev/null | grep -q 1
}
if schema_loaded; then
  echo "schema already present — applying pending steps only" >&2
else
  run_step "loading the FastPKI schema" \
      sh -c "psql -h '$PG_HOST' -p '$PG_PORT' -U fastpki -d fastpki -v ON_ERROR_STOP=1 -q -f '$SQLDIR/createdb.sql'"
fi
# ⚠️ ALWAYS, AND BEFORE ANY BINARY READS THE SCHEMA. createdb.sql is born current, so on a
# fresh database every step is already recorded and this is a no-op. It runs anyway
# because this script is also the upgrade path, and a step that only runs on the branch
# someone remembered is the shape schema versioning exists to prevent. bootstrap below
# runs fastpki-config, which carries the schema-version startup guard — so going second
# would mean the install dies one step before the step that would have fixed it.
run_step "applying schema steps (expand/contract)" \
    env PSQL="psql -h $PG_HOST -p $PG_PORT -U fastpki -d fastpki" \
        SCHEMA_STEPS_DIR="$SQLDIR/steps" bash "$ASSETS/schema-apply.sh"

# ── 7. bootstrap ──────────────────────────────────────────────────────────────────────
# The same script the compose stack runs, pointed at the native paths it already accepts
# (PKI_DIR / PKI_CONF exist for exactly this). Seeds admin/admin as must_reset and records
# which protocols this deployment was BUILT with — a protocol that was never installed is
# a different state from one an admin switched off, and the console cannot tell them apart
# without this.
#
# ⚠️ BOTH STEPS IN THIS SECTION ARE THE PRIMARY'S. The seeded admin row and this node's
# datacenters row both arrive on a standby by replication, and a standby cannot write them
# anyway. Seeding here would also be wrong even if it worked: a second admin row written
# independently is the collision that makes one password stop working across a mesh.
if [ "$PG_STANDBY" = yes ]; then
  echo "==> standby: the seeded admin and this node's data center row come from the primary" >&2
else
run_step "bootstrapping the database and seeding admin/admin (change it at first login)" \
    env PKI_DIR="$PKI_DIR" PKI_CONF="$CONF" \
        EST_INSTALLED="$([ "$WANT_EST" = yes ] && echo true || echo false)" \
        ACME_INSTALLED="$([ "$WANT_ACME" = yes ] && echo true || echo false)" \
        CMP_INSTALLED="$([ "$WANT_CMP" = yes ] && echo true || echo false)" \
        SCEP_INSTALLED="$([ "$WANT_SCEP" = yes ] && echo true || echo false)" \
        MS_INSTALLED="$([ "$WANT_MS" = yes ] && echo true || echo false)" \
        STORE_INSTALLED="$([ "$WANT_STORE" = yes ] && echo true || echo false)" \
        sh "$ASSETS/bootstrap.sh"

# ⚠️ SEED THIS NODE'S OWN data centers ROW — the same fix deploy/install.sh carries.
#
# Every issuing binary refuses at startup while `datacenters` has no row for
# DATACENTER_ID, so a cluster install that only PRINTS the mesh commands at the end
# finishes with est, acme, cmp, scep, ms and web restarting forever while ocsp and store,
# which do not issue, run happily. The compose installer had exactly this and a warning
# was not enough — it was reported twice, the second time on the release that added the
# warning.
#
# This node's index IS its serial prefix, so the row needs no topology file, which would
# need every OTHER data center's conninfo and cannot exist yet on the first node. Same
# statement fastpki-mesh --map emits, so applying the real topology later just updates it.
# ⚠️ UNCONDITIONAL — a single node is data center 1, not "no data center". Registering the
# row here is what lets it mint prefixed serials from its FIRST certificate, so a later
# expansion leaves no pre-mesh history outside this node's own partition.
run_step "registering this node as data center '$DC_INDEX' (its serial prefix)" \
    sh -c "psql -h '$PG_HOST' -p '$PG_PORT' -U fastpki -d fastpki -v ON_ERROR_STOP=1 -q -c \
      \"INSERT INTO datacenters(dc_id, serial_prefix) VALUES('$DC_INDEX', $DC_INDEX)
         ON CONFLICT (dc_id) DO UPDATE SET serial_prefix=EXCLUDED.serial_prefix;\""
fi

# ── 8. services ───────────────────────────────────────────────────────────────────────
# The bundled token server is enabled ONLY for KEY_BACKEND=softhsm. With a vendor module
# the app loads it directly and p11-kit is out of the path entirely — enabling a sidecar
# nothing talks to would be a process to monitor for no reason.
if [ "$PKCS11_MODULE_OUT" = "/usr/lib/pkcs11/p11-kit-client.so" ]; then
  rc-update add fastpki-token default >/dev/null 2>&1 || true
  # The mTLS transport in front of that socket, enabled only when asked for — the same
  # opt-in compose expresses with the `p11tls` profile and k8s with P11_TLS=on. certgen
  # mints the keypair under the same flag, and the service refuses to start without it
  # rather than publishing the token unauthenticated.
  if [ "${P11_TLS:-off}" = "on" ]; then
    rc-update add fastpki-p11-tls default >/dev/null 2>&1 || true
  fi
fi
[ "$PG_LOCAL" = yes ] && { rc-update add fastpki-pgtls default >/dev/null 2>&1 || true; }
for s in $SERVICES; do
  rc-update add "$s" default >/dev/null 2>&1 || true
done
# A protocol the operator DECLINED must not linger in the runlevel from an earlier run
# with different answers. Removing it is the native equivalent of dropping it from
# COMPOSE_PROFILES: not started, not restarted, not listed.
for s in fastpki-est fastpki-acme fastpki-cmp fastpki-scep fastpki-ms fastpki-store; do
  case " $SERVICES " in
    *" $s "*) ;;
    *) rc-update del "$s" default >/dev/null 2>&1 || true
       rc-service "$s" status >/dev/null 2>&1 && rc-service "$s" stop >/dev/null 2>&1 || true ;;
  esac
done

if [ "$DO_START" = 1 ]; then
  # ⚠️ A RE-RUN RESTARTS, because a re-run is how a node is updated and reconfigured
  # (docs/admin-guide.md §14.4), and `rc-service start` on a running service does nothing:
  # the old binaries and the old bootstrap.conf would stay in memory while this script
  # reported the node installed. So every FastPKI service that is running stops here, as a
  # set, and the starts below bring them back on what is now on disk.
  # As a set rather than one `restart` each: every service that needs the token is
  # restarted by OpenRC in the background when the token is, and a restart issued meanwhile
  # fails on that service's lock — "Call to flock failed ... stopped by something else" —
  # while the service does come up. Measured on a cloud-image node.
  for s in $(rc-update show default 2>/dev/null | awk '/fastpki-/ {print $1}'); do
    rc-service --ifstarted "$s" stop >/dev/null 2>&1 || true
  done
  [ "$PKCS11_MODULE_OUT" = "/usr/lib/pkcs11/p11-kit-client.so" ] && \
    run_step "starting the token server" rc-service fastpki-token start
    [ "${P11_TLS:-off}" = "on" ] && \
      run_step "publishing the token over mTLS" rc-service fastpki-p11-tls start
  [ "$PG_LOCAL" = yes ] && rc-service fastpki-pgtls start >/dev/null 2>&1 || true
  for s in $SERVICES; do
    run_step "starting $s" rc-service "$s" start
  done
  echo; echo "Installed." >&2
else
  echo; echo "Configured. Services are enabled but not started (--no-start)." >&2
  echo "Start them with:  rc-service fastpki-token start; for s in $SERVICES; do rc-service \$s start; done" >&2
fi

# ── what the operator does next ───────────────────────────────────────────────────────
# ⚠️ IDENTITY AND POINTERS ONLY — DO NOT GROW A MANUAL BACK IN HERE. This closing block
# used to print ~90 lines: an essay on the key backend, a ready-to-paste answers file for
# "the next data center", the whole `fastpki-ca` trust-bootstrap sequence, the topology
# format and both mesh passes. All of it is in docs/deployment.md §7/§9.1 word for word, and it
# buried the handful of lines an operator has to act on. Reported against the compose
# installer as "the output at the end is too lengthy — all the lyrics and prose should go
# to docs/deployment.md"; this script carried the identical block.
#
# ⚠️ AND NO `fastpki-ca` SEQUENCE. Operators create the root, the sub CAs and the Postgres
# transport certificates in the WEB CONSOLE. A printed CLI walkthrough is a second copy of
# §7a that diverges from it silently, because nothing re-tests what a script echoes.
_keyline="key backend $KEY_BACKEND"
if [ "$KEY_BACKEND" != softhsm ]; then _keyline="$_keyline ($PKCS11_MODULE_OUT)"; fi
# ⚠️ MIRROR conf_body's CONDITION, do not restate its result. The cluster summary below
# announced "PG_TLS_SANS=$PG_BIND in $CONF" unconditionally, while conf_body writes that key
# only when PG_BIND is set AND is not loopback. Since ask() always assigns and the prompt's
# own default is 127.0.0.1, the `${PG_BIND:-...}` fallback was unreachable: a cluster node
# installed on the default — including any answers file that omits PG_BIND — was told its
# peer-facing SAN was recorded in a file that has no PG_TLS_SANS line at all. The cost is
# spelled out at lines 365-371 of this file: `fastpki-ca pg-tls` reads the SAN names from
# config, so the database certificate is issued without the interconnect SAN and every peer
# refuses it under sslmode=verify-full, long after the CAs exist.
if [ -n "${PG_BIND:-}" ] && [ "$PG_BIND" != "127.0.0.1" ]; then
  _sansline="PG_TLS_SANS=$PG_BIND in $CONF"
else
  _sansline="NO PG_TLS_SANS in $CONF — PG_BIND is loopback, so peers cannot verify this node"
fi
# ⚠️ THIS SCRIPT IS ALSO THE UPGRADE PATH, SO THE CLOSING TEXT MUST NOT ASSUME A FIRST
# INSTALL. Every line below was written for a node that has just been created, and on an
# upgrade two of them are simply false: the console does not take admin/admin on a
# deployment whose password was changed months ago, and "it does not replicate yet" told the
# operator of a working mesh to go and connect it again. Measured while upgrading a live
# two-data-center deployment, where the last thing the upgrade printed was an instruction to
# re-mesh a mesh that was already replicating in both directions.
#
# A node that already knows about more than one data center is meshed. That row set
# replicates, so it is correct on a standby as well, which counting subscriptions is not.
_meshed=no
if [ "$(psql -h "$PG_HOST" -p "$PG_PORT" -U fastpki -d fastpki -tAqc \
          'SELECT count(*) FROM datacenters' 2>/dev/null)" -gt 1 ] 2>/dev/null; then
  _meshed=yes
fi
cat <<EOF

Console: https://$PKI_DNS:8090
EOF
if [ "$_meshed" = no ]; then
  cat <<EOF
  Log in as admin / admin and change it immediately.
  (self-signed until you issue the console a certificate, so expect a browser warning)
EOF
fi
cat <<EOF
Services: rc-service fastpki-web status | restart, rc-status, and the logs are in
  /var/log/fastpki/.
EOF
if [ "$DEPLOYMENT" = cluster ] && [ "$_meshed" = yes ]; then
  cat <<EOF

This node: data center $DC_INDEX of $DC_COUNT — $_keyline, $_sansline.
It is already part of a mesh and keeps replicating; there is nothing to connect.
EOF
elif [ "$DEPLOYMENT" = cluster ]; then
  cat <<EOF

This node: data center $DC_INDEX of $DC_COUNT — that index IS its certificate-serial prefix
  — $_keyline, $_sansline.
  EVERY node installs the same way: same answers file, only DC_INDEX/PKI_DNS/PG_BIND differ.
It does not replicate yet. Once every node is installed, connect them from your own
  machine with deploy/mesh-join.sh (docs/deployment.md 9.0 step 3). Its first run stops for
  the CAs, created in the console (CAs -> + New CA); run it again and it finishes.
EOF
else
  cat <<EOF

This node: datacenter 1 (single), $_keyline. No CA exists yet — create the root and
  issuing CAs in the console (CAs -> + New CA); docs/deployment.md 4.3 walks through it.
EOF
fi
