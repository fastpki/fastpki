#!/usr/bin/env bash
# FastPKI clients demo. Drives a FastPKI deployment with REAL clients
# — openssl (EST/CMP/OCSP), scep-testclient (SCEP), curl (Store), certbot
# (ACME) — to showcase the certificate lifecycle a client performs against each
# protocol, with per-step timing:
#
#   EST   : enroll a certificate (RFC 7030 simpleenroll)
#   CMP   : enroll a certificate (RFC 4210 ir)
#   OCSP  : check a certificate's status (RFC 6960) — good
#   CMP   : revoke a certificate (rr)
#   OCSP  : check again — revoked
#   SCEP  : enroll a certificate (RFC 8894 PKCSReq)
#   Store : search for a certificate by attribute (RFC 4387)
#   ACME  : enroll a certificate (RFC 8555, real certbot)   [see note below]
#
# TWO MODES:
#
#   demo/pki-demo.sh                       # THROWAWAY: spin up a throwaway docker
#                                          # compose deployment (postgres+softhsm+
#                                          # every protocol container), demo it,
#                                          # tear it down.
#
#   demo/pki-demo.sh --target FILE         # LIVE: drive an already-running
#                                          # deployment as a remote client. FILE
#                                          # is a target descriptor produced by
#                                          # demo/provision-target.sh (host, ports,
#                                          # creds, CMP secret, CA chain).
#
# THE SERVER-CREDENTIAL AXIS (throwaway mode only):
#
#   --server-key SPEC    # mint the EST listener's own self-signed certificate with
#                        # this key instead of the default. SPEC is algo[:param] —
#                        # ec, ec:P-384, rsa:3072, rsa-pss:3072, ed25519.
#   --server-md DIGEST   # and sign it with this digest (RSA/RSA-PSS only; EC, Ed and
#                        # the one-shot schemes have no choice to make).
#   --server-keys "A B"  # EXTRA Sweep-B iterations: re-key the server credentials to
#                        # each spec in the list inside the same stack.
#
# Throwaway mode IS a key/hash matrix: five sweeps (CA keys, server credential
# keys, client keys per protocol, CSR hashes, response digests), each overridable
# with --ca-keys/--server-keys/--client-keys/--hashes/--response-mds, each
# trimmed by --quick.
#
# The point is what the clients do NOT have to know: the same openssl/curl/certbot
# sequence runs unchanged whatever key the server presents. A live deployment's
# listener keys are its own configuration, so these are refused with --target.
#
# ACME note: ACME's challenge validation is INBOUND to the client (the server
# connects back to prove domain control), so a purely remote client can't be
# validated over a one-way link. ACME is therefore run against a co-located
# fastpki-acme (identical binary) via a real RFC 8555 order over the dns-01
# challenge — privilege-free (no :80), driven in shell by tests/acme_jws.sh with
# CoreDNS (started by demo/dns-auth.sh) answering the challenge lookup. --no-acme skips it.
# EST/CMP/SCEP/OCSP/Store need no reach-back and run against the live target.
#
# MS-XCEP/WSTEP is proven separately against the real Windows enrollment client
# and is added here once a lab Windows VM is available.
#
# Honours $OSSL / $OPENSSL_LIBDIR like the test suite. Defaults: /opt/openssl-3.5
# on Linux, or the `openssl` on PATH (e.g. Homebrew openssl@3) on macOS.
set -u

# ⚠️ --help IS ANSWERED BEFORE ANYTHING ELSE HAPPENS. It used to be a case arm in the
# argument loop, ninety lines below five `source`s of the test helpers — so the answer to
# "how do I run this?" depended on the whole test harness loading first. On a machine
# where any of that is slow or unhappy, `--help` produces NOTHING and a bare run sits
# there silently, and they fail identically because neither reaches the loop. Nothing
# above this line does any work.
#
# It also prints REAL usage instead of sed-ing this file's own header comment, which made
# the help text whatever the comment block happened to contain, internal notes and all.
# The delimiter is not the word USAGE: this text HAS a "USAGE" heading, which ends the
# heredoc early and leaves the rest of it as shell syntax.
usage(){ cat <<'HELPTEXT'
demo/pki-demo.sh - drive a FastPKI deployment with REAL clients, end to end.

  EST enroll | CMP enroll | OCSP check | CMP revoke | OCSP re-check |
  SCEP enroll | Store search | ACME order (real certbot)

USAGE
  demo/pki-demo.sh [options]

MODE (pick one; the default is described below)
  --target FILE        run against a LIVE deployment described by FILE.
  --throwaway          spin up a throwaway docker compose deployment, demo it,
                       tear it down. Needs docker; builds the fastpki image on
                       first use. All keys stay inside the stack's SoftHSM.

  With neither: demo/.target.env is used when it exists, otherwise --throwaway.
  Create a descriptor with:  demo/provision-target.sh admin@<host>

THE MATRIX (--throwaway runs the sweeps by default; each varies ONE axis)
  --full-matrix        instead of the one-axis sweeps, run their full cross-
                       product: response-MD × server-key × CA-key × client-
                       key × CSR-hash. EVERY cell runs a complete lifecycle —
                       enroll, chain+strict+CRL validation, renew (serial
                       must differ), revoke via CMP rr signed by the leaf,
                       OCSP-flip check, and a re-validation that must FAIL as
                       revoked. SCEP (2 keys × hashes) and ACME run once per
                       CA instance. Tens of minutes; failures print one line
                       each with their combination.
  --ca-keys LIST       Sweep A / matrix CA axis: create+probe one CA per
                       type. Default: rsa:4096 rsa-pss:4096 ec:P-521 ed448
                       ml-dsa-87.
  --server-key SPEC    Sweep B baseline — the server credential provisioned
                       before any client runs (rsa[:bits], rsa-pss[:bits],
                       ec[:curve], ed25519, ed448, ml-dsa-44/65/87). SCEP's
                       RA stays RSA whatever you ask: RFC 8894 fixes its
                       envelope on RSA key transport.
  --server-md DIGEST   Sweep B baseline — signing digest for the listener
                       credentials.
  --server-keys LIST   Sweep B iterations after the baseline pass, each re-
                       keying the transport + RA credentials in the stack;
                       also the server axis of --full-matrix. Default:
                       rsa:3072 rsa-pss:3072 ec:P-256 ed25519 ml-dsa-44.
  --client-keys LIST   Sweep C — client key types for EST/CMP (SCEP/ACME take
                       their own supported subset); client axis of
                       --full-matrix. Default: rsa:3072 rsa-pss:3072 ec:P-256
                       ed25519 ml-dsa-44.
  --protocols LIST     protocols to exercise — Sweep C and --full-matrix alike.
                       Default: "est cmp scep acme".
  --hashes LIST        Sweep D, client half — CSR signature hashes for the
                       EST/SCEP enrolments (CMP's CRMF carries no CSR). Also
                       the hash axis of --full-matrix. Default: sha3-256
                       sha3-512 (shake256 is refused for RSA/EC signatures).
  --response-mds LIST  Sweep D, server half / matrix outermost loop — OCSP/
                       CMP response digests, set and restarted. Default:
                       sha3-256 sha3-512.
  --quick              one representative per family — what tests/ drives.

ACME
  --acme / --no-acme   force the ACME leg on or off (default: on when it can run).
                       --full-matrix includes an ACME cell per CA only when
                       ACME is enabled.

OTHER
  -h, --help           this text.

EXAMPLES
  demo/pki-demo.sh --throwaway                     # full matrix, fresh stack
  demo/pki-demo.sh --throwaway --quick             # trimmed matrix (test tier)
  demo/pki-demo.sh --throwaway --server-key rsa-pss:3072 --server-md sha3-256
  demo/pki-demo.sh --throwaway --no-acme --ca-keys "ec:P-256 ml-dsa-65"
  demo/pki-demo.sh --target demo/.target.env --no-acme

Note: the key SPEC separator is a COLON, not a dash - ec:P-384, not ec-384.
HELPTEXT
}
case "${1:-}" in -h|--help|help|-help) usage; exit 0;; esac

# ⚠️ THE FIRST THING A USER SEES, and it is deliberately here rather than with the
# banner further down. Everything between this line and that banner is setup — sourcing
# helpers, resolving openssl — and if any of it stalls, a terminal that has printed
# nothing at all leaves the user with nothing to report except that the script "sits
# and does nothing", which is not something anyone can act on. One line before the
# setup turns a blank screen into a located failure.
printf 'FastPKI clients demo: loading helpers...\n' >&2

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${FASTPKI_BIN:-$ROOT/build}"

# A driver with no build can still run the enrolment clients from the testtools image;
# without this, SCEP is the one protocol a deployment host cannot exercise. See the file.
[ -f "$ROOT/demo/testclient.sh" ] && . "$ROOT/demo/testclient.sh"
# ⚠️ KEEP THE REASON. ensure_testclient distinguishes its failures now, and the SCEP cells
# below skip with "no scep-testclient in $BIN" — true, and almost never the thing to fix. The
# reason is usually the runtime image named in deploy/.env not being on this host, which is one
# environment variable away and invisible from that message.
SCEP_TC_WHY=""
if command -v ensure_testclient >/dev/null 2>&1; then
  ensure_testclient scep-testclient "$BIN" || SCEP_TC_WHY="${TESTCLIENT_WHY:-}"
fi
# Handed to the JWS driver, which falls back to its own UDP stub when a caller publishes no
# TXT itself. Every dns-01 cell here DOES publish, through demo/dns-auth.sh and the CoreDNS
# container it starts on the deployment's own network, so the demo never reaches for the
# stub — the suites in tests/ still do, and this keeps one spelling of where it lives.
ACME_DNSSTUB="${ACME_DNSSTUB:-$BIN/dnsstub}"
# ⚠️ THE THROWAWAY STACK RUNS IN CONTAINERS, so the demo sources none of the test
# harness's server-side helpers any more: no hsm_helpers (the SoftHSM sidecar owns the
# token), no pg_helpers/cmp_helpers/service_cert_helpers (provisioning goes through the
# product's own CLI inside the web container and the console API from here). What is
# left on the host is CLIENT work only: openssl/curl/certbot driving the published
# ports, and acme_jws.sh for the RFC 8555 orders.
source "$ROOT/tests/acme_jws.sh"

# ── openssl selection (Linux 3.5 side-install vs macOS Homebrew) ─────────────
if [ -z "${OSSL:-}" ]; then
  if [ -x /opt/openssl-3.5/bin/openssl ]; then OSSL=/opt/openssl-3.5/bin/openssl
  else OSSL="$(command -v openssl)"; fi
fi
if [ -z "${OPENSSL_LIBDIR:-}" ] && [ -d /opt/openssl-3.5/lib64 ]; then
  export LD_LIBRARY_PATH=/opt/openssl-3.5/lib64
elif [ -n "${OPENSSL_LIBDIR:-}" ]; then
  export LD_LIBRARY_PATH=$OPENSSL_LIBDIR
fi
# macOS: help the Homebrew openssl find its dylibs when invoked by abs path.
case "$OSSL" in
  /opt/homebrew/*|/usr/local/*) export DYLD_LIBRARY_PATH="$(dirname "$(dirname "$OSSL")")/lib:${DYLD_LIBRARY_PATH:-}";;
esac
# ⚠️ NO OPENSSL_CONF ADOPTION ANY MORE, and that is not an oversight. The guard used to
# export /etc/ssl/openssl.cnf so host-side `openssl ... -provider pkcs11` calls could load
# the provider — the exact machinery that made throwaway mode fragile (a shadowing config,
# a provider built for a different openssl minor, an argument-order landmine). Every key
# now lives in the compose stack's SoftHSM and is driven from inside the containers; the
# host's openssl only decodes certificates and speaks TLS as a CLIENT, which needs no
# provider at all. Leaving the guard would keep adopting whatever the machine happens to
# have at /etc/ssl/openssl.cnf for no benefit.

# base64 helpers (openssl -A = no newlines in output)
b64d(){ openssl base64 -d -A 2>/dev/null; }
b64e(){ openssl base64 -A 2>/dev/null | tr -d '\n'; }

# ── pretty output ────────────────────────────────────────────────────────────
if [ -t 1 ]; then B=$'\e[1m'; DIM=$'\e[2m'; GRN=$'\e[32m'; CYN=$'\e[36m'; YEL=$'\e[33m'; RED=$'\e[31m'; RST=$'\e[0m'; else B=; DIM=; GRN=; CYN=; YEL=; RED=; RST=; fi
now(){ date +%s; }
T0=; DEMO_FAIL=0; MTX_OK=0; MTX_FAIL=0; MTX_SKIP=0; MTX_SEQ=0
# Counted so the closing line can say what actually ran — see the note there.
DEMO_SKIP=0
# DEMO_QUIET=1 silences the narrative printers (hdr/step/ok/info) but never fail/skip:
# the full-matrix loop reuses the enrolment helpers hundreds of times and prints one
# summary line per cell instead; a failure must still be loud inside that silence.
DEMO_QUIET=${DEMO_QUIET:-0}
step(){ [ "$DEMO_QUIET" = 1 ] && return 0; printf '  %s→%s %s... ' "$CYN" "$RST" "$1"; T0=$(now); }
ok(){   [ "$DEMO_QUIET" = 1 ] && return 0; local d; d=$(awk "BEGIN {printf \"%.2f\", $(now)-$T0}"); printf '%sdone%s %s(%ss)%s\n' "$GRN" "$RST" "$DIM" "$d" "$RST"; }
fail(){ printf '%sFAILED%s %s\n' "$RED" "$RST" "${1:-}"; DEMO_FAIL=$((DEMO_FAIL+1)); }
skip(){ DEMO_SKIP=$((DEMO_SKIP+1)); [ "$DEMO_QUIET" = 1 ] && return 0; printf '%sskipped%s %s%s%s\n' "$YEL" "$RST" "$DIM" "${1:-}" "$RST"; }
hdr(){  [ "$DEMO_QUIET" = 1 ] && return 0; printf '\n%s%s%s\n' "$B" "$1" "$RST"; }
info(){ [ "$DEMO_QUIET" = 1 ] && return 0; printf '     %s%s%s %s\n' "$DIM" "$1" "$RST" "$2"; }

# ── args ─────────────────────────────────────────────────────────────────────
# ⚠️ LIVE IS THE DEFAULT, THROWAWAY IS THE OPT-IN. The point of a demo is to exercise
# the live deployment; a throwaway database proves only that the demo can talk to
# something it built itself.
# So: if a target descriptor exists, use it without being asked. `--throwaway` is how you
# say you meant the disposable one — tests/demo_clients.sh passes it explicitly, because a
# test harness has no deployment to point at.
MODE=; TARGET_FILE=; RUN_ACME=auto
DEFAULT_TARGET="$ROOT/demo/.target.env"
# The server-credential axis. A demo pass drives the SAME client sequence against a
# deployment whose own listener key (and response digest) is of a given type — the point
# is that a client sees no difference, which is only demonstrated by running it.
SERVER_KEY=""; SERVER_MD=""; SERVER_KEYS=""
# The matrix sweeps. Empty means "the default list for this axis", resolved once MODE
# is known — a live target gets none of them, because none of them may edit someone
# else's deployment.
CA_KEYS="" CLIENT_KEYS="" HASHES="" RESPONSE_MDS="" PROTOCOLS=""
QUICK=0
FULL_MATRIX=0
EST_CLIENT_SKIP=""   # set by server_key_show when the local TLS client, not the server, is the limit
# Declared here so it always has a REAL default: cmp_ra_key_show and cmp_enroll read it
# to announce a skip when a cell's RA credential cannot exist. Empty = every CMP cell runs.
CMP_RA_SKIP=""
# Enrolment names are built as <thing>.$DEMO_DOMAIN from the very first provisioning
# call (the RA credentials), so the domain needs its default BEFORE any function runs —
# under set -u a use-before-assignment aborts mid-provisioning. A --target descriptor
# or the environment may still override; setup_throwaway pins it to internal.
DEMO_DOMAIN="${DEMO_DOMAIN:-internal}"
while [ $# -gt 0 ]; do
  case "$1" in
    --target) MODE=live; TARGET_FILE="${2:?--target needs a file}"; shift 2;;
    --target=*) MODE=live; TARGET_FILE="${1#*=}"; shift;;
    --throwaway) MODE=throwaway; shift;;
    --server-key)  SERVER_KEY="${2:?--server-key needs an algorithm}"; shift 2;;
    --server-key=*) SERVER_KEY="${1#*=}"; shift;;
    --server-md)   SERVER_MD="${2:?--server-md needs a digest}"; shift 2;;
    --server-md=*)  SERVER_MD="${1#*=}"; shift;;
    --server-keys) SERVER_KEYS="${2:?--server-keys needs a list}"; shift 2;;
    --server-keys=*) SERVER_KEYS="${1#*=}"; shift;;
    --ca-keys) CA_KEYS="${2:?--ca-keys needs a list}"; shift 2;;
    --ca-keys=*) CA_KEYS="${1#*=}"; shift;;
    --client-keys) CLIENT_KEYS="${2:?--client-keys needs a list}"; shift 2;;
    --client-keys=*) CLIENT_KEYS="${1#*=}"; shift;;
    --hashes) HASHES="${2:?--hashes needs a list}"; shift 2;;
    --hashes=*) HASHES="${1#*=}"; shift;;
    --response-mds) RESPONSE_MDS="${2:?--response-mds needs a list}"; shift 2;;
    --response-mds=*) RESPONSE_MDS="${1#*=}"; shift;;
    --protocols) PROTOCOLS="${2:?--protocols needs a list}"; shift 2;;
    --protocols=*) PROTOCOLS="${1#*=}"; shift;;
    --quick) QUICK=1; shift;;
    --full-matrix) FULL_MATRIX=1; shift;;
    --acme) RUN_ACME=yes; shift;;
    --no-acme) RUN_ACME=no; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown option: $1" >&2
       echo "run 'demo/pki-demo.sh --help' for the accepted options." >&2
       exit 2;;
  esac
done
if [ -z "$MODE" ]; then
  if [ -f "$DEFAULT_TARGET" ]; then
    MODE=live; TARGET_FILE="$DEFAULT_TARGET"
  else
    # No descriptor and none asked for. Say what the demo is FOR rather than quietly doing
    # the thing he was annoyed about — then still run, so a bare checkout is not a dead end.
    MODE=throwaway
    printf '%snote:%s no %s — running against a throwaway deployment.\n' \
      "${YEL:-}" "${RST:-}" "demo/.target.env" >&2
    printf '      the demo is meant for a LIVE deployment: %sdemo/provision-target.sh admin@<host>%s\n' \
      "${DIM:-}" "${RST:-}" >&2
  fi
fi
# ── the server-credential axis: refuse it where it cannot mean anything ──────
# Changing a listener's key means generating a new one and restarting the service. Against
# a LIVE deployment that is someone else's running system, and this demo does not edit it
# to make its own step pass (the ACME challenge steps already hold that line). So say so —
# a flag that quietly did nothing would read as "my deployment ignores this setting".
# ⚠️ AN UNRECOGNISED SPELLING MUST BE REFUSED, NOT HALF-APPLIED. `--server-key EC:P-256`
# (the OpenSSL spelling) used to be accepted silently: the algorithm went into the config
# as `EC`, the `case` that writes the curve matched only lowercase `ec` so EST_KEY_CURVE was
# never written at all, and the verification below maps the algorithm to an expected SPKI
# name — which for an unknown spelling is the empty string, so the comparison was skipped.
# The run passed having asked for a key it did not get and asserted nothing about it.
# Measured: a full green demo on `EC:P-256` with no EC anywhere near the listener.
#
# So normalise the case and refuse anything not in the supported set, naming it.
_normalise_server_key(){
  [ -n "$1" ] || { printf ''; return 0; }
  local algo="${1%%:*}" param=""
  case "$1" in *:*) param="${1#*:}";; esac
  # lower-case the algorithm only; a curve name like P-256 or prime256v1 is case-sensitive
  algo=$(printf '%s' "$algo" | tr 'A-Z' 'a-z')
  case "$algo" in
    rsa|rsa-pss|ec|ed25519|ed448|ml-dsa-44|ml-dsa-65|ml-dsa-87) ;;
    *) echo "--server-key: unknown algorithm '$algo'. Supported: rsa[:bits], rsa-pss[:bits], ec[:curve], ed25519, ed448, ml-dsa-44/65/87." >&2; exit 2;;
  esac
  if [ -n "$param" ]; then printf '%s:%s' "$algo" "$param"; else printf '%s' "$algo"; fi
}
SERVER_KEY=$(_normalise_server_key "$SERVER_KEY") || exit 2
if [ -n "$SERVER_KEYS" ]; then
  _nk=""
  for _s in $SERVER_KEYS; do _nk="$_nk $(_normalise_server_key "$_s")" || exit 2; done
  SERVER_KEYS="${_nk# }"
fi

if [ "$MODE" != throwaway ] && [ -n "$SERVER_KEY$SERVER_MD$SERVER_KEYS$CA_KEYS$CLIENT_KEYS$HASHES$RESPONSE_MDS" ]; then
  echo "the key/hash axes need --throwaway: a live deployment's keys are its own configuration, and this demo does not change them." >&2
  exit 2
fi

# ── the matrix, resolved ─────────────────────────────────────────────────────
# --throwaway IS the matrix: one fresh stack, then five sweeps over it, each varying
# ONE axis against defaults elsewhere (a full cross-product is thousands of cells;
# sequential sweeps cover every dimension in ~40). The lists below are what an empty
# flag resolves to; --quick trims each to one representative per family, which is what
# tests/demo_clients.sh drives so the suite stays minutes rather than hours.
if [ "$MODE" = throwaway ]; then
  # Five representatives per axis: one per family, sized for the job. The full
  # factorial (--full-matrix) runs CA×client×hash cells against each of these; the
  # OFAT sweeps (default) vary one axis at a time.
  [ -n "$CA_KEYS" ]      || CA_KEYS="rsa:4096 rsa-pss:4096 ec:P-521 ed448 ml-dsa-87"
  [ -n "$SERVER_KEYS" ]  || SERVER_KEYS="rsa:3072 rsa-pss:3072 ec:P-256 ed25519 ml-dsa-44"
  [ -n "$CLIENT_KEYS" ]  || CLIENT_KEYS="rsa:3072 rsa-pss:3072 ec:P-256 ed25519 ml-dsa-44"
  # ⚠️ NO shake256 IN THE DEFAULTS. Sweep D signs each hash over an RSA CSR key, and
  # OpenSSL refuses SHAKE for RSASSA outright ("digest not allowed", rsa_sig.c) — EC
  # refuses it too, and an Ed25519 "-shake256" silently IGNORES the flag (PureEdDSA has
  # no prehash), which would report coverage the wire never carried. Measured, then
  # dropped; pass --hashes explicitly if you want the attempt announced.
  [ -n "$HASHES" ]       || HASHES="sha3-256 sha3-512"
  # SHA-3 family only for responder/CMP response digests: sha384 measured fine but the
  # axis is meant to prove the SHA-3 path; two members cover short/long output.
  [ -n "$RESPONSE_MDS" ] || RESPONSE_MDS="sha3-256 sha3-512"
  [ -n "$PROTOCOLS" ]    || PROTOCOLS="est cmp scep acme"
  if [ "$QUICK" = 1 ]; then
    CA_KEYS="rsa:4096 ec:P-521 ml-dsa-87"; SERVER_KEYS="ec:P-256"; CLIENT_KEYS="ec:P-256"
    HASHES="sha3-256"; RESPONSE_MDS="sha3-256"; PROTOCOLS="est cmp scep acme"
  fi
  # --server-key/--server-md PIN the baseline credential. A Sweep-B list would then
  # re-key the listeners to something else and report it — the run's own summary line
  # ("the web console listener served id-ecPublicKey") contradicting the flag the
  # operator passed. The pinned value IS the server-axis cell, so the sweep is empty.
  [ -z "${SERVER_KEY}${SERVER_MD}" ] || SERVER_KEYS=""
else
  CA_KEYS="" SERVER_KEYS="" CLIENT_KEYS="" HASHES="" RESPONSE_MDS=""
fi

# Resolve the target descriptor to an absolute path before we cd into the tempdir.
if [ -n "$TARGET_FILE" ]; then
  case "$TARGET_FILE" in /*) ;; *) TARGET_FILE="$PWD/$TARGET_FILE";; esac
fi

# ⚠️ THE WORK DIR MUST SIT ON A DOCKER-SHARED PATH, and /var/folders (mktemp's home on
# macOS) is not one. Measured on Docker Desktop: a single-FILE bind mount whose host side
# lives outside the shared paths does not fail — it silently appears INSIDE the container
# as an EMPTY DIRECTORY. The staged compose project bind-mounts two files (the bootstrap
# config and sql/createdb.sql), so postgres init "ran" nothing and every base table was
# missing — schema-apply then failed at migration 0002 with `relation "certs" does not
# exist`, pointing at the schema instead of at the mount. Staging under build/ keeps it
# inside the repo's shared path and out of git (build/ is ignored); cleanup removes it.
# ⚠️ CREATE build/ FIRST — IT DOES NOT EXIST IN A RELEASE TARBALL. It is gitignored, and
# release.yml builds the tarball with `git archive` exactly so nothing ignored rides along,
# so a fresh unpack has no build/ and this mktemp fails. The failure was unchecked inside a
# command substitution, so WORK became EMPTY and every path derived from it turned into an
# absolute one: `$WORK/capath` became `/capath`, mkdir was refused at the filesystem root,
# and the demo reported "verify: Not a directory: /capath" from a dozen steps while the
# real fault was three lines up. Measured on a clean unpack of a release tarball — the demo has
# only ever worked from a checkout, which is where build/ already exists.
mkdir -p "$ROOT/build" || { echo "FATAL: cannot create $ROOT/build for the demo's work directory" >&2; exit 1; }
WORK="$(mktemp -d "$ROOT/build/.demo-XXXXXX")" || WORK=""
# And refuse an empty one rather than deriving paths from it. An unset WORK does not fail
# any single command here; it silently re-roots every path the demo builds.
[ -n "$WORK" ] && [ -d "$WORK" ] || {
  echo "FATAL: could not create a work directory under $ROOT/build" >&2; exit 1; }
cd "$WORK"
pids=()

# ── the demo cleans up after itself ───────────────────────────────────
# A demo run must clean up after itself — revoke the certificates it requested — so the
# next run does not hit the per-CN issuance cap.
#
# ⚠️ REVOKE THROUGH THE PRODUCT, NOT THROUGH psql. The previous cleanup UPDATEd certs rows
# directly, which (a) skipped the CRL, the OCSP answer and the audit trail, so the
# deployment ended up in a state its own API could never produce, and (b) assumed the demo
# runs ON the deployment host — `psql -h localhost` — which is the opposite of what live
# mode is for. It reads the console's own POST /api/certs/<serial>/revoke now.
#
# ⚠️ AND IT REVOKES ONLY WHAT THIS RUN ISSUED. Serials are recorded at the moment of
# issuance, not discovered by scanning $WORK for certificates — the chain and the CA cert
# live there too, and a cleanup that guesses which files are "ours" is one bad glob away
# from revoking the CA of a live deployment.
ISSUED_SERIALS="$WORK/.issued-serials"
record_issued(){ # <cert-file> [der]
  local f="$1" form="${2:-pem}" ser=
  [ -s "$f" ] || return 0
  if [ "$form" = der ]; then ser=$("$OSSL" x509 -inform DER -in "$f" -noout -serial 2>/dev/null)
  else                       ser=$("$OSSL" x509 -in "$f" -noout -serial 2>/dev/null); fi
  ser=${ser#serial=}
  [ -n "$ser" ] && printf '%s\n' "$ser" >> "$ISSUED_SERIALS"
  return 0
}
revoke_issued(){
  [ "$MODE" = live ] && [ -s "${ISSUED_SERIALS:-}" ] || return 0
  [ -n "${TARGET_HOST:-}" ] && [ -n "${DEMO_USER:-}" ] || return 0
  local api="https://$TARGET_HOST:${WEB_PORT:-8090}" jar="$WORK/.revoke.cj" n=0 done_=0 code
  curl -sk -c "$jar" --max-time 10 -X POST \
       -d "username=${DEMO_USER}&password=${DEMO_PASS:-}" "$api/api/login" -o /dev/null 2>/dev/null || return 0
  while read -r ser; do
    [ -n "$ser" ] || continue
    n=$((n+1))
    # reason 5 = cessationOfOperation: the certificate is finished with, not compromised.
    code=$(curl -sk -b "$jar" --max-time 10 -o /dev/null -w '%{http_code}' \
           -X POST "$api/api/certs/$ser/revoke?reason=5" 2>/dev/null)
    [ "$code" = 200 ] && done_=$((done_+1))
  done < "$ISSUED_SERIALS"
  printf '     %scleanup:%s revoked %s/%s certificate(s) this run issued\n' \
         "${DIM:-}" "${RST:-}" "$done_" "$n"
}
cleanup(){
  # Tear the throwaway compose stack down, volumes included — a throwaway leaves
  # nothing behind. `down` operates on the project's containers whatever their
  # profile, so no --profile flags are needed here. Guarded on the project name
  # being set (setup_throwaway ran) and on docker still being reachable; a failure
  # here must not mask the demo's own verdict, so every error is swallowed.
  #
  # FASTPKI_DEMO_KEEP_STACK=1 skips the teardown (and prints how to reach the stack)
  # so a failing matrix/sweep can be probed live instead of reconstructed by hand.
  if [ "${FASTPKI_DEMO_KEEP_STACK:-}" = 1 ] && [ -n "${DEMO_PROJ:-}" ]; then
    printf '  %sKEEP_STACK: leaving the stack up — docker compose -p %s -f %s <cmd>%s\n' \
           "${DIM:-}" "$DEMO_PROJ" "${DEMO_COMPOSE_FILE:-$ROOT/deploy/docker-compose.yml}" "${RST:-}" >&2
  elif [ -n "${DEMO_PROJ:-}" ] && command -v docker >/dev/null 2>&1; then
    docker compose -p "$DEMO_PROJ" \
      -f "${DEMO_COMPOSE_FILE:-$ROOT/deploy/docker-compose.yml}" \
      down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  # Hand the certificates this run issued back through the product's own revoke API, so
  # the next run does not walk into the per-requester cap. Live mode only: a throwaway
  # stack is destroyed whole, so there is nothing to clean up behind it.
  revoke_issued || true
  # Keep the work dir (client/server logs) when something failed, so the failure
  # is debuggable — otherwise the log a "FAILED" line points at is already gone.
  # KEEP_STACK keeps it too: the compose file lives there, and deleting it would
  # strand the stack we just promised to leave up with no handle to manage it by.
  # ⚠️ ONLY AT THE REAL END OF THE RUN. bash runs an inherited EXIT trap when a SUBSHELL
  # exits, so any subshell dying mid-run used to reach this line and delete the working
  # directory out from under the steps still to come. That is not hypothetical: an unset
  # array expanded under `set -u` (macOS bash 3.2 treats an EMPTY array as unset) killed
  # the ACME cell's shell, cleanup ran, $WORK was removed, and every later step failed for
  # a reason that looked nothing like the cause -- the endpoint TLS check reported "no CA
  # chain available", when the chain was fine and its whole directory was gone.
  #
  # DEMO_COMPLETE is set on the last line of the script, so an early trap keeps the
  # directory (which is also what you want for debugging) and only the real exit clears it.
  if [ "${DEMO_COMPLETE:-0}" != 1 ]; then
    printf '  %sexited early — work dir kept: %s%s\n' "${DIM:-}" "$WORK" "${RST:-}" >&2
  elif { [ "$DEMO_FAIL" -eq 0 ] && [ "${FASTPKI_DEMO_KEEP_STACK:-}" != 1 ]; }; then rm -rf "$WORK";
  else printf '  %slogs kept for debugging: %s%s\n' "${DIM:-}" "$WORK" "${RST:-}" >&2; fi
}
trap cleanup EXIT

# These are the "target" variables every protocol step below consumes; they are
# filled either by setup_throwaway (local services) or by the --target file.
EST_URL= CMP_URL= OCSP_URL= STORE_URL= STORE_PATH= SCEP_URL= ACME_DIR=
# ⚠️ ONE dns-stub port for the whole run. ACME_DNS_RESOLVER is read at STARTUP, so a cell
# that picks its own port is asking a server that is looking somewhere else -- the authz
# then sits at "pending" until the poll gives up, which reads as a broken challenge rather
# than a mismatched port. The cells run one at a time and each tears its stub down.
DEMO_DNSP=15353
# Same options provision-target.sh uses, so a lab key that works there works here: the
# dns-01 cells reach the target over SSH to repoint its resolver and put it back.
DEMO_SSH_OPTS=(-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes)
[ -f "$HOME/.ssh/fastpki_lab_ed25519" ] && DEMO_SSH_OPTS+=(-i "$HOME/.ssh/fastpki_lab_ed25519")
CHAIN=            # full CA chain PEM (root + issuing)
ISSUER=           # the issuing-CA cert PEM (signs leaves; OCSP -issuer)
EST_AUTH=         # curl -u value, or empty for none
CMP_RECIPIENT= CMP_SECRET= CMP_REF=demo
CMP_CONFIG=       # path to downloaded fastpki-cmp.cnf (provision-target.sh)
TLS_INSECURE=1    # curl -k / openssl -no-CApath; live self-signed TLS

printf '%s FastPKI clients demo %s  %sopenssl %s · mode=%s%s\n' \
  "$B" "$RST" "$DIM" "$("$OSSL" version 2>/dev/null | awk '{print $2}')" "$MODE" "$RST"

# ── throwaway deployment ─────────────────────────────────────────────────────
run_bounded(){   # <seconds> <cmd...>
  local secs=$1; shift
  "$@" & local p=$!
  ( sleep "$secs"; kill -TERM "$p" 2>/dev/null ) & local w=$!
  wait "$p"; local rc=$?
  kill -TERM "$w" 2>/dev/null; wait "$w" 2>/dev/null
  return $rc
}

# ── the throwaway stack is a STAGED COMPOSE PROJECT ──────────────────────────
# Never deploy/ itself: the project name there is fixed (`name: fastpki`) and its host
# ports are the production ones, so a demo would collide with a real deployment on the
# same host — or tear it down at exit. Instead the four files install.sh drives are
# copied into $WORK, the host ports are rewritten to high loopback ones, and everything
# runs under a per-run project name with -p. `down -v` then removes exactly what this
# run created and nothing else.
DEMO_PROJ=""                       # set by setup_throwaway; cleanup() keys on it
DEMO_WEB_PORT=19444 DEMO_OCSP_PORT=19080 DEMO_EST_PORT=19443 DEMO_ACME_PORT=19446
DEMO_CMP_PORT=19085 DEMO_MS_PORT=19445 DEMO_STORE_PORT=19047 DEMO_SCEP_PORT=19048
DEMO_PG_PORT=15432
DEMO_COMPOSE_FILE="$WORK/compose/docker-compose.yml"
CONF_IN_CONTAINER="/app/config/bootstrap.conf"
dcp(){ docker compose -p "$DEMO_PROJ" -f "$DEMO_COMPOSE_FILE" "$@"; }
compose_exec(){ dcp exec -T web "$@"; }   # every provisioning call rides the console container

rand_secret(){ head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-"${1:-24}"; }
wait_tcp(){ local p=$1 i
  for i in $(seq 1 "${2:-100}"); do
    (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
    sleep 0.3
  done; return 1; }
wait_http(){ local u=$1 i code
  for i in $(seq 1 "${2:-120}"); do
    code=$(curl_tls --max-time 3 -o /dev/null -w '%{http_code}' "$u" 2>/dev/null)
    [ -n "$code" ] && [ "$code" != 000 ] && return 0
    sleep 0.5
  done; return 1; }

compose_stage(){
  mkdir -p "$WORK/compose" "$WORK/sql" || return 1
  cp "$ROOT/deploy/docker-compose.yml" "$ROOT/deploy/bootstrap.compose.conf" \
     "$ROOT/deploy/certgen.sh" "$ROOT/deploy/bootstrap.sh" "$WORK/compose/" || return 1
  cp "$ROOT/sql/createdb.sql" "$WORK/sql/" || return 1
  # Host ports → high loopback ports (the yaml hardcodes the production ones). The
  # CONTAINER side of each mapping stays put: inside the network every service still
  # speaks its default port. EXCEPTION — ocsp: the staged .env moves OCSP_PORT itself
  # so the AIA/CRLDP URLs derived for certificates are true on BOTH sides of the
  # mapping (see the .env note below); its container side must move with it.
  sed -e "s/\"8090:8090\"/\"127.0.0.1:$DEMO_WEB_PORT:8090\"/" \
      -e "s/\"8080:8080\"/\"127.0.0.1:$DEMO_OCSP_PORT:$DEMO_OCSP_PORT\"/" \
      -e "s/\"8443:8443\"/\"127.0.0.1:$DEMO_EST_PORT:8443\"/" \
      -e "s/\"8444:8444\"/\"127.0.0.1:$DEMO_ACME_PORT:8444\"/" \
      -e "s/\"8445:8445\"/\"127.0.0.1:$DEMO_CMP_PORT:8445\"/" \
      -e "s/\"8446:8446\"/\"127.0.0.1:$DEMO_MS_PORT:8446\"/" \
      -e "s/\"8447:8447\"/\"127.0.0.1:$DEMO_STORE_PORT:8447\"/" \
      -e "s/\"8448:8448\"/\"127.0.0.1:$DEMO_SCEP_PORT:8448\"/" \
      -e "s/}:5432:5432\"/}:$DEMO_PG_PORT:5432\"/" \
      "$ROOT/deploy/docker-compose.yml" > "$DEMO_COMPOSE_FILE" || return 1
  # AIA/CRLDP baked into certificates issued LATER must be reachable from THIS HOST,
  # because crl_capath fetches the CRL from here before each check. Inside the containers
  # those URLs are dead either way (they name the host), and nothing container-side
  # fetches them during a demo run.
  sed -e "s|http://localhost:8080|http://127.0.0.1:$DEMO_OCSP_PORT|g" \
      "$ROOT/deploy/bootstrap.compose.conf" > "$WORK/compose/bootstrap.compose.conf" || return 1
  # Per-run secrets, mode 600 — the same shape install.sh writes, never committed.
  # WEB_ALLOW_REVOKE unlocks /api/certs/request-hsm AND the revoke API; without it the
  # console refuses every provisioning call this setup makes.
  local envf="$WORK/compose/.env"
  # Docker's magic resolver name, spelled once: it is Docker's fixed name for the
  # host, not a PKI enrolment name, and the descriptor suite counts `.internal`
  # literals on executable lines to catch pinned enrolment names.
  { printf 'POSTGRES_PASSWORD=%s\n' "$(rand_secret 24)"
    printf 'FASTPKI_PIN=%s\n'       "$(rand_secret 12)"
    printf 'PKI_DNS=localhost\n'
    printf 'FASTPKI_IMAGE=%s\n' "${FASTPKI_IMAGE:-fastpki:local}"
    printf 'COMPOSE_PROFILES=ocsp,est,acme,cmp,scep,ms,store\n'
    printf 'WEB_ALLOW_REVOKE=true\n'
    # ⚠️ THE URLS BAKED INTO CERTIFICATES MUST BE REACHABLE FROM THIS HOST. AIA/CRLDP are
    # derived from the BASE_URL host + OCSP_PORT — with the defaults that is
    # http://pki.example.org:8080/…, and the CRL fetch then spent its whole
    # bound in DNS timeouts (the run "hung" at tls_verify with no error anywhere).
    # derive_ca_urls strips BASE_URL's scheme/port and re-derives from OCSP_PORT below,
    # but fastpki-acme advertises directory/new-nonce links from BASE_URL VERBATIM when
    # it is set explicitly (g_req_base path in acme/main.cpp) — a portless value sent
    # certbot to :80, and an http:// value sent it speaking plain HTTP at a TLS socket
    # ("Remote end closed connection without response"): fastpki-acme IS an SSLServer
    # even when reached directly, so the scheme must be https here too.
    printf 'BASE_URL=https://localhost:%s\n' "$DEMO_ACME_PORT"
    printf 'OCSP_PORT=%s\n' "$DEMO_OCSP_PORT"
    # The dns-01 validator runs INSIDE the acme container, so its resolver must be the
    # one name every Docker environment provides for "the host running the containers".
    # With this set at STARTUP (it is read once), acme_wildcard needs no repoint dance —
    # which is what DEMO_LOCAL_ACME below tells it.
    # ⚠️ THE CoreDNS CONTAINER, NOT THIS HOST. dns-auth.sh starts CoreDNS on this project's
    # own compose network and publishes no port, so the acme container reaches it by name
    # through docker's embedded DNS. Naming the host instead needs a resolver listening on
    # the host AND a name that resolves from inside a container — `host.docker.internal`
    # exists on Docker Desktop and NOT on Linux without an extra_hosts entry, which this
    # compose file has none of. Read once at startup, so acme_wildcard needs no repoint.
    printf 'ACME_DNS_RESOLVER=fastpki-dns:%s\n' "$DEMO_DNSP"
    printf 'EST_INSTALLED=true\nACME_INSTALLED=true\nCMP_INSTALLED=true\n'
    printf 'SCEP_INSTALLED=true\nMS_INSTALLED=true\nSTORE_INSTALLED=true\n'
    # No CRL cache: every CRL crl_capath stages for validate_cert must show
    # the revocation state AS OF the request — with the 300 s default, a
    # revoke-then-verify inside one cell would read a stale list and pass vacuously.
    printf 'CRL_CACHE_TTL_SEC=0\n'
    # RFC 8894 renewal: scep_renew signs its PKCSReq with the previously ISSUED cert;
    # without this the server rejects renewal and the cell would report a product gap.
    printf 'SCEP_RENEWAL=true\n'
    # The server-credential axis, as startup config for all four TLS listeners
    # (see server_key_env_lines — the WEB line is the one that actually matters).
    local _p
    for _p in WEB EST ACME MS; do server_key_env_lines "$_p"; done
  } > "$envf" && chmod 600 "$envf" || return 1
}

# ── the server-credential axis ───────────────────────────────────────────────
# The four HTTPS services mint their OWN self-signed listener certificate when no
# certificate exists yet, and the key type and signing digest of that certificate are
# configurable per service. A throwaway demo starts exactly one of them (EST), so that
# listener is where this axis is visible: --server-key changes the key FastPKI generates
# for it, and every client step then has to complete a real TLS handshake against it.
#
# The spec is "algo[:param]" — ec, ec:P-384, rsa:3072, rsa-pss:3072, ed25519 — matching
# the shape the install wizard asks for. `bits` applies to RSA, `curve` to EC; the other
# is ignored, exactly as on every other keygen path.
# ⚠️ ONE LISTENER IS NOT THE AXIS. This emitted EST_ only, so `--server-key` reached
# exactly one of the four services that speak TLS -- and the demo stood up only that one,
# which is why nobody noticed. The prefix is an argument now, and the three listeners this
# demo runs each get their own lines. (ACME is the fourth; the throwaway stack does not
# run it, and the ACME leg here drives a compose deployment instead.)
# Which key types a TLS listener can actually carry. The ticket draws this line itself:
# the four TLS services are "restricted to what TLS supports, today no ML-DSA keys", while
# the three non-TLS ones use RA certificates and should work with everything.
#
# ⚠️ MEASURED, NOT ASSUMED. `--server-key ml-dsa-65` used to configure ML-DSA on EST, the
# console and MS as well. All three then served NO certificate, the demo reported three
# FAILEDs, and every client step behind them failed too — five failures describing one
# thing the ticket already says is out of scope. The spec still has to be ACCEPTED, because
# OCSP and CMP are exactly where it belongs; it just must not reach a TLS listener.
tls_can_carry(){
  case "${SERVER_KEY%%:*}" in
    ml-dsa-44|ml-dsa-65|ml-dsa-87) return 1 ;;
    *) return 0 ;;
  esac
}
tls_skip_reason(){
  printf 'TLS has no code point for %s — RFC 8446 carries no ML-DSA signature algorithm, so the four TLS listeners keep their default key and this cell is measured on the RA credentials instead' "$SERVER_KEY"
}

# The server-credential axis reaches the containers as CONFIGURATION. The listeners
# mint their own transport key inside the stack's SoftHSM at startup and self-sign
# with it when no CA-issued certificate exists yet — exactly the behaviour the old
# native stack had — so the axis is <SVC>_KEY_ALGO/_BITS/_CURVE/_MD in the staged .env,
# read by every service through Config::from_env.
#
# ⚠️ THE CONSOLE IS A LISTENER TOO. est/acme/ms get their keys minted by the console
# API (keygen=true carries $SERVER_KEY), but web is ALREADY UP when credentials are
# issued and adopts its startup key (keygen=false) — without these lines that startup
# mint used the built-in default, and --server-key rsa:3072 produced a demo whose web
# console alone served ec/P-256. Measured. The lines also arm the other three as a
# correct fallback if their CA-issued row is missing at boot.
server_key_env_lines(){   # <prefix e.g. WEB> → append KEY_ALGO/_BITS/_CURVE/_MD lines
  local pfx="${1:?server_key_env_lines needs a config prefix, e.g. EST}"
  [ -n "$SERVER_KEY$SERVER_MD" ] || return 0
  # Leave the listener on its default rather than handing it a key it cannot serve.
  tls_can_carry || return 0
  local algo="${SERVER_KEY%%:*}" param=""
  case "$SERVER_KEY" in *:*) param="${SERVER_KEY#*:}";; esac
  printf '%s_KEY_ALGO=%s\n' "$pfx" "$algo"
  case "$algo" in
    rsa|rsa-pss) [ -n "$param" ] && printf '%s_KEY_BITS=%s\n' "$pfx" "$param";;
    ec)          [ -n "$param" ] && printf '%s_KEY_CURVE=%s\n' "$pfx" "$param";;
  esac
  [ -n "$SERVER_MD" ] && printf '%s_KEY_MD=%s\n' "$pfx" "$SERVER_MD"
  return 0
}

# The SPKI name this build of OpenSSL prints for a --server-key spec. Shared by every
# listener check, because a second copy is a second thing to fall out of step with the
# parser's accepted set.
#
# ⚠️ NO SILENT EMPTY. Every algorithm --server-key accepts must map to a name here, or the
# comparison at the call site is skipped and the whole step becomes decoration. The parser
# refuses anything outside this set, so a miss here is a bug in THIS list.
# The SIZE the spec asks for, as OpenSSL prints it inside "Public-Key: (N bit)". Empty
# when the spec names none (bare `ec`, or a fixed-size algorithm), which is the only case
# where skipping the comparison is honest.
#
# ⚠️ THE NAME ALONE IS NOT THE CELL, and this was measured, not theorised: with the config
# prefix deliberately wrong, a request for ec:P-384 got a listener serving
# id-ecPublicKey (256 bit) -- its own default curve -- and the step PASSED, because the
# comparison stopped at the algorithm name. Every curve and every bit-length cell of this
# axis was reporting coverage it did not have, EST's included.
#
# Both helpers take an optional SPEC argument so the sweeps can ask about a key that is
# not $SERVER_KEY (a CA key in Sweep A, a client key in Sweep C); the default stays the
# baseline server credential.
want_spki_bits(){
  local spec="${1:-$SERVER_KEY}"
  case "$spec" in
    rsa:*|rsa-pss:*) echo "${spec#*:}";;
    ec:P-256) echo 256;;
    ec:P-384) echo 384;;
    ec:P-521) echo 521;;
    *) echo "";;
  esac
}

want_spki_name(){
  local spec="${1:-$SERVER_KEY}"
  case "${spec%%:*}" in
    ec)         echo "id-ecPublicKey";;
    rsa)        echo "rsaEncryption";;
    rsa-pss)    echo "rsassaPss";;
    ed25519)    echo "ED25519";;
    ed448)      echo "ED448";;
    ml-dsa-44)  echo "ML-DSA-44";;
    ml-dsa-65)  echo "ML-DSA-65";;
    ml-dsa-87)  echo "ML-DSA-87";;
  esac
}


# Decode what a TLS listener actually presents and hold it to --server-key. Used for the
# console and MS; EST keeps its own copy below because it carries the client-library probe.
#   $1 label   $2 host:port   $3 file stem
tls_listener_show(){
  [ -n "$SERVER_KEY" ] || return 0
  step "$1 listener certificate"
  if ! tls_can_carry; then
    skip "($(tls_skip_reason))" 2>/dev/null || printf ' SKIPPED (%s)\n' "$(tls_skip_reason)"
    return 0
  fi
  if [ -z "$2" ]; then fail "(no $1 endpoint to inspect)"; return 1; fi
  local pem="$WORK/$3-served.pem" log="$WORK/$3-sclient.log"
  printf 'Q\n' | run_bounded 10 "$OSSL" s_client -connect "$2" -showcerts >"$log" 2>&1 || true
  sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "$log" | head -100 > "$pem"
  if [ ! -s "$pem" ]; then fail "(the $1 listener served no certificate — see $log)"; return 1; fi
  local txt pk sz want
  txt=$("$OSSL" x509 -in "$pem" -noout -text 2>/dev/null)
  pk=$(printf '%s' "$txt" | sed -nE 's/.*Public Key Algorithm: (.*)/\1/p' | head -1)
  sz=$(printf '%s' "$txt" | sed -nE 's/.*Public-Key: \((.*)\)/\1/p' | head -1)
  [ -n "$sz" ] && pk="$pk ($sz)"
  [ -n "$pk" ] || { fail "(could not decode the served certificate)"; return 1; }
  want=$(want_spki_name)
  if [ -z "$want" ]; then
    fail "(no expected SPKI name for '${SERVER_KEY%%:*}' — this check would pass without testing anything)"; return 1; fi
  if [ "${pk%% (*}" != "$want" ]; then
    fail "(asked for $SERVER_KEY, the $1 listener served $pk)"; return 1; fi
  local wantbits; wantbits=$(want_spki_bits)
  if [ -n "$wantbits" ] && [ "$sz" != "$wantbits bit" ]; then
    fail "(asked for $SERVER_KEY, the $1 listener served ${sz:-no size at all})"; return 1; fi
  ok
  info "key:" "$pk"
}

# What the listener ACTUALLY presents, decoded from the certificate it served. The point
# of the axis is that a client sees a working endpoint whatever the server key is, so the
# demo has to show the key it got — not the key it asked for.
server_key_show(){
  [ -n "$SERVER_KEY$SERVER_MD" ] || return 0
  step "EST listener certificate"
  if ! tls_can_carry; then
    skip "($(tls_skip_reason))" 2>/dev/null || printf ' SKIPPED (%s)\n' "$(tls_skip_reason)"
    return 0
  fi
  # ⚠️ Take the address from EST_URL, the same variable every client step below uses.
  # The port lives in a `local` inside the setup function, so reading it here found an
  # UNSET name and this whole step returned quietly — the flag looked honoured because
  # everything downstream passes either way. Nothing here may return 0 without asserting.
  local hostport="${EST_URL#*://}"; hostport="${hostport%%/*}"
  if [ -z "$hostport" ]; then fail "(no EST endpoint to inspect)"; return 1; fi
  local pem="$WORK/est-served.pem"
  # `Q` on stdin, not /dev/null: s_client holds the connection open after printing, so
  # closing stdin alone leaves it sitting there until the bound expires and every cell
  # pays that wall-clock. "Q" is s_client's own quit command.
  printf 'Q\n' | run_bounded 10 "$OSSL" s_client -connect "$hostport" -showcerts \
      >"$WORK/est-sclient.log" 2>&1 || true
  sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "$WORK/est-sclient.log" | head -100 > "$pem"
  if [ ! -s "$pem" ]; then
    fail "(the EST listener served no certificate — see $WORK/est-sclient.log)"; return 1
  fi
  local txt; txt=$("$OSSL" x509 -in "$pem" -noout -text 2>/dev/null)
  local pk sig
  pk=$(printf '%s' "$txt"  | sed -nE 's/.*Public Key Algorithm: (.*)/\1/p' | head -1)
  sig=$(printf '%s' "$txt" | sed -nE 's/.*Signature Algorithm: (.*)/\1/p'  | head -1)
  # ⚠️ The SIZE, not only the algorithm name. Without it "rsa:3072" and the RSA-2048
  # certificate this demo used to pre-generate print the identical line, so a check on
  # the algorithm alone cannot tell "the listener minted what I asked for" from "the
  # listener adopted a file that happened to be RSA too".
  local sz; sz=$(printf '%s' "$txt" | sed -nE 's/.*Public-Key: \((.*)\)/\1/p' | head -1)
  [ -n "$sz" ] && pk="$pk ($sz)"
  [ -n "$pk" ] || { fail "(could not decode the served certificate)"; return 1; }
  # ⚠️ Printing what it served is not a check. The whole flag is inert unless the served
  # key is the one that was ASKED for — and an inert flag reads exactly like a working
  # one, because every client step downstream passes either way. So name the expected
  # spelling and compare. Anything this build of OpenSSL prints differently fails here
  # rather than silently blessing the default key.
  # ⚠️ NO SILENT EMPTY. Every algorithm --server-key accepts must map to a name here, or
  # the comparison below is skipped and the whole step becomes decoration. The parser
  # refuses anything outside this set, so a miss here is a bug in THIS list, and it fails
  # loudly rather than passing quietly.
  local want; want=$(want_spki_name)
  if [ -z "$want" ]; then
    fail "(no expected SPKI name for '${SERVER_KEY%%:*}' — this check would pass without testing anything)"; return 1
  fi
  if [ "${pk%% (*}" != "$want" ]; then
    fail "(asked for $SERVER_KEY, the listener served $pk)"; return 1
  fi
  # ⚠️ AND THE SIZE. The comment above says the size is what separates "minted what I
  # asked for" from "adopted something that happened to match" -- but only the NAME was
  # ever compared, so ec:P-384 was satisfied by a P-256 listener. See want_spki_bits.
  local wantbits; wantbits=$(want_spki_bits)
  if [ -n "$wantbits" ] && [ "$sz" != "$wantbits bit" ]; then
    fail "(asked for $SERVER_KEY, the listener served ${sz:-no size at all})"; return 1
  fi
  ok
  info "key:" "$pk"
  info "signature:" "$sig"

  # ⚠️ THE SERVER SERVING IT AND THE CLIENT ACCEPTING IT ARE TWO DIFFERENT CLAIMS, and
  # the second one is about whatever TLS library the local curl was built against — not
  # about FastPKI. A curl linked to LibreSSL 3.3 cannot complete a handshake to an
  # Ed25519 server certificate AT ALL: it fails identically against a bare `openssl
  # s_server`, with no FastPKI in the picture. Reporting that as "EST enroll failed"
  # blames the product for the measuring instrument, which is how three wrong findings
  # got filed against this very axis once already.
  #
  # So probe it here, once, and say which of the two it is. openssl reached this listener
  # a moment ago, so if curl cannot, the difference IS the client library — and the EST
  # step below skips with that named as the cause, rather than failing.
  EST_CLIENT_SKIP=""
  curl_tls --max-time 10 -o /dev/null "$EST_URL/cacerts" 2>/dev/null
  if [ "$?" = 35 ]; then
    # The whole version line, not a guessed capture group: on macOS it names TWO stacks
    # (SecureTransport and LibreSSL) and picking one of them at random misattributes the
    # limit to the wrong library.
    local backend; backend=$(curl -V 2>/dev/null | head -1)
    EST_CLIENT_SKIP="this host's HTTPS client cannot complete a TLS handshake to a $pk server certificate, while openssl reached the SAME listener a moment ago — so the limit is the client's TLS library, not the server [${backend:-curl version unknown}]"
    info "note:" "the EST step will skip — see the reason on that step"
  fi
  return 0
}

# ⚠️ THESE FOUR WERE NESTED INSIDE server_key_show, because its closing brace was missing.
# Its body ran from its own first line to the end of the last definition below, so
# ocsp_key_show and cmp_ra_key_show did not EXIST until server_key_show had been CALLED.
# That stayed invisible for as long as the only callers were the three show steps, which
# run one after another in the one order that defines each just before it is needed.
#
# It stopped being invisible the moment setup_throwaway needed scep_ra_setup, two hundred
# lines before any show step runs: `line 834: scep_ra_setup: command not found`, after
# which the demo carried on and reported that SCEP was not in RA mode — a true statement
# about a cause it could not name. A definition whose availability depends on call ORDER
# is a landmine; guarded now by demo_functions_toplevel.sh.
  # The OCSP half of the same axis. OCSP has no TLS listener, so what varies on the server
# side is the DELEGATED RESPONDER credential — the key that signs status responses. Decode
# the CERTIFICATE the console issued for that key, for the same reason the EST step decodes
# the served certificate: asking for a key and getting one are different claims, and every
# client step downstream passes either way.
#
# ⚠️ THE KEY ITSELF IS NOT INSPECTABLE ANY MORE, and that is by design: it is minted inside
# the stack's SoftHSM and never leaves it, so there is no key file to `openssl pkey`. The
# certificate carries the public half, which asserts the same thing — the SPKI is what a
# client's response-verification actually sees.
ocsp_key_show(){
  [ -n "$SERVER_KEY" ] || return 0
  step "OCSP responder credential"
  local pem="$WORK/ocsp-ra.pem"
  if [ ! -s "$pem" ]; then fail "(no responder certificate was issued — nothing to inspect)"; return 1; fi
  local txt; txt=$("$OSSL" x509 -in "$pem" -noout -text 2>/dev/null)
  local pk sz want wantbits
  pk=$(printf '%s' "$txt" | sed -nE 's/.*Public Key Algorithm: (.*)/\1/p' | head -1)
  sz=$(printf '%s' "$txt" | sed -nE 's/.*Public-Key: \((.*)\)/\1/p' | head -1)
  [ -n "$sz" ] && pk="$pk ($sz)"
  [ -n "$pk" ] || { fail "(could not decode the responder certificate)"; return 1; }
  # ⚠️ NO SILENT EMPTY. Every algorithm --server-key accepts must map to a name here, or
  # the comparison below is skipped and the whole step becomes decoration. The parser
  # refuses anything outside this set, so a miss here is a bug in THIS list.
  want=$(want_spki_name)
  if [ -z "$want" ]; then
    fail "(no expected SPKI name for '${SERVER_KEY%%:*}' — this check would pass without testing anything)"; return 1; fi
  if [ "${pk%% (*}" != "$want" ]; then
    fail "(asked for $SERVER_KEY, the responder credential is $pk)"; return 1; fi
  wantbits=$(want_spki_bits)
  if [ -n "$wantbits" ] && [ "$sz" != "$wantbits bit" ]; then
    fail "(asked for $SERVER_KEY, the responder credential served ${sz:-no size at all})"; return 1; fi
  ok
  info "responder credential:" "$pk"
}

# CMP's server-side credential is the RA certificate, and it lives in the token. Decode
# what the RA cert actually certifies — hsm_expected_spki names what the certificate will
# say for a spec, which is the only trustworthy way to name a cell: a token listing cannot
# distinguish RSA-PSS from RSA, and reports an ML-DSA key by a numeric code.
cmp_ra_key_show(){
  [ -n "$SERVER_KEY" ] || return 0
  step "CMP RA credential key"
  # An announced skip, with its cause, is the only honest outcome for a cell the HARNESS
  # cannot reach. A silent pass here would report RSA coverage as if the axis had run.
  if [ -n "${CMP_RA_SKIP:-}" ]; then
    skip "($CMP_RA_SKIP)" 2>/dev/null || { printf ' SKIPPED (%s)\n' "$CMP_RA_SKIP"; }
    return 0
  fi
  local pem="$WORK/.cmpra.pem"
  if [ ! -s "$pem" ]; then fail "(no RA certificate was issued — nothing to inspect)"; return 1; fi
  local algo; algo=$("$OSSL" x509 -in "$pem" -noout -text 2>/dev/null \
                       | sed -n 's/.*Public Key Algorithm: //p' | head -1)
  # The certificate's SPKI is the assertion: it names the algorithm (and for EC the
  # curve is visible as the size), which is exactly what a CMP client verifies against.
  # want_spki_name/want_spki_bits are the same maps every other axis step uses — a
  # second copy of the mapping is a second thing to fall out of step with the parser.
  local want; want=$(want_spki_name)
  if [ -z "$want" ]; then
    fail "(no expected SPKI name for '${SERVER_KEY%%:*}' — this check would pass without testing anything)"; return 1; fi
  if [ "$algo" != "$want" ]; then
    fail "(asked for $SERVER_KEY, the RA credential is '${algo:-unreadable}', expected $want)"; return 1; fi
  ok
  info "RA credential:" "${algo:-unknown}"
}

# SCEP's server-side key, which is the third and last of the non-TLS three.
#
# ⚠️ WITHOUT AN RA CREDENTIAL SCEP SIGNS WITH THE CA KEY. msg_key() is
# `ra_mode ? ra_key : ca_key`, and ra_mode is on only when SCEP_RA_KEY is set. That is a
# designed path, not a bug — but it means the demo was standing SCEP up with NO server-side
# key of its own, so there was nothing for --server-key to vary and nothing to decode. CMP
# and OCSP were given their credentials for exactly this reason; SCEP was the one left.
#
# ⚠️ AND THE AXIS STOPS AT RSA, BY THE PROTOCOL. SCEP's message layer is CMS: the client
# ENCRYPTS the PKCSReq to the server's certificate, so the server key has to be able to
# unwrap a content-encryption key. RFC 8894 §3.1 fixes that on RSA. fastpki-scep refuses a
# non-RSA RA key at serve time and says so, so pushing an EC spec at it here would report a
# product limitation where there is a protocol one. Announced instead.
# ── provisioning the server-side credentials, through the product ────────────
# Every service credential (OCSP responder, CMP RA, SCEP RA) is issued the way an
# operator issues it: POST /api/certs/request-hsm, the route the console's
# "Inventory -> Request, key in HSM -> Serve as ..." button drives. The console mints
# the key INSIDE the stack's SoftHSM at the pkcs11: handle the service's config names,
# so no private material ever exists on this host — which is the point of running the
# throwaway stack in containers.
#
# ⚠️ cert_id MUST ARRIVE ALREADY QUALIFIED. The services resolve "<prefix>-<ca_id>";
# the console's own form appends the CA in the browser (`fd.set('cert_id', pfx + '-'
# + ca)`), and a raw POST must do the same or it writes a row nothing ever looks up.
#
# ⚠️ THE AXIS STOPS AT RSA FOR SCEP, BY THE PROTOCOL. SCEP's message layer is CMS: the
# client ENCRYPTS the PKCSReq to the server's certificate, so the server key has to be
# able to unwrap a content-encryption key. RFC 8894 §3.1 fixes that on RSA.
# fastpki-scep refuses a non-RSA RA key at serve time and says so, so pushing an EC
# spec at it here would report a product limitation where there is a protocol one.
# Announced instead.
scep_ra_gate(){   # sets SCEP_RA_SKIP when the axis asks for what SCEP cannot carry
  SCEP_RA_SKIP=""
  case "$(printf '%s' "${SERVER_KEY:-}" | tr 'A-Z' 'a-z')" in
    ''|rsa|rsa:*) : ;;
    *) SCEP_RA_SKIP="SCEP's CMS layer encrypts the request to the server's key, which RFC 8894 fixes on RSA; fastpki-scep refuses a non-RSA RA key at serve time, so ${SERVER_KEY} is not a cell this axis has" ;;
  esac
}

# Map a key SPEC onto the two arg shapes the product takes:
#   spec_cli_args  SPEC  → fastpki-ca create flags (--key/--bits/--curve)
#   spec_api_args  SPEC  → request-hsm form fields (key=/bits=/curve=)
# The spellings are the console form's own; generate_key_in_token lower-cases and maps
# them server-side, so this side only passes through what the parser already normalised.
spec_parts(){   # SPEC → sets SP_ALGO SP_PARAM
  SP_ALGO="${1%%:*}"; SP_PARAM=""
  case "$1" in *:*) SP_PARAM="${1#*:}";; esac
}
spec_cli_args(){
  local out=(); [ -n "$1" ] || { CLI_KEY_ARGS=(); return 0; }
  spec_parts "$1"
  out+=(--key "$SP_ALGO")
  case "$SP_ALGO" in
    rsa|rsa-pss) [ -n "$SP_PARAM" ] && out+=(--bits "$SP_PARAM");;
    ec)          [ -n "$SP_PARAM" ] && out+=(--curve "$SP_PARAM");;
  esac
  CLI_KEY_ARGS=("${out[@]}")
}
spec_api_args(){
  local out=(); [ -n "$1" ] || { API_KEY_ARGS=(); return 0; }
  spec_parts "$1"
  out+=(--data-urlencode "key=$SP_ALGO")
  case "$SP_ALGO" in
    rsa|rsa-pss) [ -n "$SP_PARAM" ] && out+=(--data-urlencode "bits=$SP_PARAM");;
    ec)          [ -n "$SP_PARAM" ] && out+=(--data-urlencode "curve=$SP_PARAM");;
  esac
  API_KEY_ARGS=("${out[@]}")
}

# Map the --server-key spec onto the issuance request's algorithm fields. The
# spellings are the console form's own ("key"=rsa|rsa-pss|ec|ed25519|ml-dsa-XX,
# "bits" for RSA, "curve" for EC) — generate_key_in_token lower-cases and maps them
# server-side, so this side only passes through what the parser already normalised.
api_key_args(){   # fills API_KEY_ARGS[] with the key/bits/curve form fields
  spec_api_args "${SERVER_KEY}"
}

#   $1 cert_id  $2 cn  $3 keyref  $4 ku  $5 eku  $6 out.pem  [$7+ extra form fields]
api_issue_hsm_cert(){
  [ -n "${WEB_HOSTPORT:-}" ] || { echo "no console"; return 1; }
  local cert_id="$1" cn="$2" keyref="$3" ku="$4" eku="$5" out="$6"
  shift 6
  local jar="$WORK/.console.cj"
  curl -sk -c "$jar" -d "username=demoadmin&password=DemoAdmin12345" \
       "https://$WEB_HOSTPORT/api/login" >/dev/null 2>&1
  local body
  # ⚠️ EXTRAS GO FIRST. cpp-httplib's get_param_value returns the FIRST occurrence of a
  # repeated form field, and curl sends --data-urlencode pairs in argv order — so had the
  # fixed defaults come first, every override below (`keygen=false` for web, `ca_instance`
  # in Sweep A) would have been silently swallowed by its own default.
  body=$(curl -sk -b "$jar" "https://$WEB_HOSTPORT/api/certs/request-hsm" \
      "$@" \
      --data-urlencode "ca_instance=${CA_ID:?CA_ID must be set}" \
      --data-urlencode "cn=$cn" \
      --data-urlencode "keyref=$keyref" \
      --data-urlencode "cert_id=$cert_id" \
      --data-urlencode "ku=$ku" \
      ${eku:+--data-urlencode "eku=$eku"} \
      --data-urlencode "keygen=true" \
      2>/dev/null)
  # The response carries the PEM; pull it out rather than going back to the database,
  # so what gets decoded is what the product actually handed back.
  # ⚠️ awk, not sed. The body is JSON with \n escapes, and BSD sed does not expand \n in a
  # replacement -- so the un-escaping silently did nothing and the first line came back as
  # `{"serial":"...","pem":"-----BEGIN CERTIFICATE-----`, which openssl reads as garbage and
  # the step reported as "the RA credential is 'unreadable'". awk's gsub replacement does
  # expand it. The leading JSON is then cut by starting the range at the marker itself.
  printf '%s' "$body" | awk '{ gsub(/\\n/, "\n"); print }' \
    | sed -n 's/.*\(-----BEGIN CERTIFICATE-----\)/\1/; /BEGIN CERTIFICATE/,/END CERTIFICATE/p' > "$out"
  if [ ! -s "$out" ]; then
    printf '%s' "$body" | head -c 300
    return 1
  fi
}

# What SCEP actually presents, asked of the SERVER over the wire rather than read back out
# of our own config. GetCACert is the question a real client asks, and RA mode changes its
# answer: RFC 8894 §4.2 says a certs-only PKCS#7 of RA-then-CA under
# application/x-x509-ca-ra-cert, instead of the bare CA certificate.
scep_key_show(){
  [ -n "$SERVER_KEY" ] || return 0
  step "SCEP RA credential key"
  if [ -n "${SCEP_RA_SKIP:-}" ]; then
    skip "($SCEP_RA_SKIP)" 2>/dev/null || printf ' SKIPPED (%s)\n' "$SCEP_RA_SKIP"
    return 0
  fi
  local ct; ct=$(curl -s --max-time 20 -D - "$SCEP_URL?operation=GetCACert" -o .scepca.p7 \
                 | grep -i '^content-type' | tr -d '\r' | sed 's/.*: *//')
  if [ "$ct" != "application/x-x509-ca-ra-cert" ]; then
    fail "(GetCACert answered '${ct:-nothing}' — RA mode is not on, so SCEP is signing with the CA key)"; return 1; fi
  local n; n=$("$OSSL" pkcs7 -inform DER -in .scepca.p7 -print_certs 2>/dev/null | grep -c 'BEGIN CERTIFICATE')
  [ "$n" = 2 ] || { fail "(GetCACert returned $n certificate(s), expected the RA and the CA)"; return 1; }
  # RA first, then CA — and the first is the one a client encrypts to, so decode THAT one.
  "$OSSL" pkcs7 -inform DER -in .scepca.p7 -print_certs 2>/dev/null \
    | "$OSSL" x509 -out .scepra-served.pem 2>/dev/null
  local algo ku
  algo=$("$OSSL" x509 -in .scepra-served.pem -noout -text 2>/dev/null \
         | grep -m1 -oE 'rsaEncryption|id-ecPublicKey|ED25519|ED448|ML-DSA-[0-9]+')
  [ "$algo" = "rsaEncryption" ] || { fail "(the served RA credential is '${algo:-unreadable}', and CMS needs RSA)"; return 1; }
  # keyEncipherment is the bit that makes the envelope openable. A credential without it
  # serves, enrols nothing, and fails inside CMS_decrypt with no attribution.
  ku=$("$OSSL" x509 -in .scepra-served.pem -noout -text 2>/dev/null \
       | grep -A1 'X509v3 Key Usage' | tail -1)
  case "$ku" in *"Key Encipherment"*) : ;;
    *) fail "(the served RA credential has no keyEncipherment: '$(printf '%s' "$ku" | sed 's/^ *//')')"; return 1 ;;
  esac
  ok
  info "RA credential:" "$algo, $(printf '%s' "$ku" | sed 's/^ *//')"
}

setup_throwaway(){
  # ⚠️ THIS IS AN INSTALL, NOT A TEST FIXTURE. The stack comes up exactly the way
  # deploy/install.sh brings one up — staged compose files, generated .env, certgen →
  # postgres → schema → bootstrap → console — and everything after that is provisioned
  # THROUGH THE PRODUCT: users and domains via fastpki-config inside the web container,
  # the CA via fastpki-ca, every service credential via POST /api/certs/request-hsm.
  # Nothing is INSERTed by hand, no key ever exists as a file on this host, and the
  # client steps below then run against it byte-for-byte the way --target runs against
  # a live deployment (setup_target_client is shared).
  hdr "Provisioning a throwaway FastPKI deployment (docker compose)"
  command -v docker >/dev/null 2>&1 || { fail "(docker not found — the throwaway stack runs in containers)"; return 1; }
  docker compose version >/dev/null 2>&1 || { fail "(docker compose plugin missing)"; return 1; }
  DEMO_PROJ="fpkidemo$$"    # per-run project name; cleanup() tears exactly this down

  step "staging an isolated compose project"
  compose_stage || { fail "(could not stage $WORK/compose)"; return 1; }
  ok
  info "project:" "$DEMO_PROJ  (web:$DEMO_WEB_PORT est:$DEMO_EST_PORT acme:$DEMO_ACME_PORT …)"

  step "transport image"
  local img="${FASTPKI_IMAGE:-fastpki:local}"
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    info "note:" "$img not found — building once (this takes a while)"
    ( cd "$ROOT/deploy" && FASTPKI_IMAGE="$img" bash build-image.sh ) >"$WORK/image-build.log" 2>&1 \
      || { fail "(image build failed — see $WORK/image-build.log)"; return 1; }
  fi
  ok; info "image:" "$img"

  step "starting postgres (certgen runs first, as in install.sh)"
  dcp up -d --quiet-pull postgres >"$WORK/compose-postgres.log" 2>&1 \
    || { fail "(docker compose up postgres failed — see $WORK/compose-postgres.log)"; return 1; }
  local i
  for i in $(seq 1 60); do
    dcp ps postgres 2>/dev/null | grep -q healthy && break
    sleep 1
  done
  dcp ps postgres 2>/dev/null | grep -q healthy || { fail "(postgres never went healthy)"; return 1; }
  ok

  step "applying the schema (deploy/schema-apply.sh)"
  ( cd "$ROOT/deploy" && PSQL="docker compose -p $DEMO_PROJ -f $DEMO_COMPOSE_FILE exec -T postgres psql -U fastpki -d fastpki" \
      bash schema-apply.sh ) >"$WORK/schema.log" 2>&1 \
    || { fail "(schema-apply failed — see $WORK/schema.log)"; return 1; }
  ok

  step "bootstrap (dirs + default admin)"
  dcp run --rm bootstrap >"$WORK/bootstrap.log" 2>&1 \
    || { fail "(bootstrap failed — see $WORK/bootstrap.log)"; return 1; }
  ok

  step "console up"
  dcp up -d --quiet-pull web >>"$WORK/compose-postgres.log" 2>&1 \
    || { fail "(web did not start)"; return 1; }
  WEB_HOSTPORT="localhost:$DEMO_WEB_PORT"
  wait_http "https://$WEB_HOSTPORT/api/me" 120 || { fail "(console never answered on :$DEMO_WEB_PORT)"; return 1; }
  ok

  # ── provisioning, through the product ────────────────────────────────────────
  step "users, domains, CA and config rows"
  compose_exec fastpki-config --config "$CONF_IN_CONTAINER" \
      web-user demoadmin DemoAdmin12345 --role admin >/dev/null 2>&1 || { fail "(demoadmin)"; return 1; }
  compose_exec fastpki-config --config "$CONF_IN_CONTAINER" \
      web-user demo demo --role requester >/dev/null 2>&1 || { fail "(demo user)"; return 1; }
  printf 'internal\nexample.org\n' | compose_exec sh -c \
      "cat >/tmp/domains.txt && fastpki-config --config $CONF_IN_CONTAINER domains-import /tmp/domains.txt" \
      >/dev/null 2>&1 || { fail "(domains-import)"; return 1; }
  CA_ID=demo-ca
  DEMO_CA_URI="pkcs11:token=fastpki;object=$CA_ID;type=private?pin-source=/var/pki/tls/pin"
  compose_exec fastpki-ca --config "$CONF_IN_CONTAINER" create "$CA_ID" \
      --name "$CA_ID" --subject "/CN=FastPKI Demo CA" \
      --ca-key "$DEMO_CA_URI" --keygen --out-dir /tmp --md sha3-512 >"$WORK/ca-create.log" 2>&1 \
    || { fail "(fastpki-ca create failed — see $WORK/ca-create.log)"; return 1; }
  # Rows the protocol services read at STARTUP must exist before they start:
  # SCEP's RA mode is decided from SCEP_RA_KEY at boot, and CMP needs its client-cert
  # anchor to accept signature-protected revocation.
  compose_exec fastpki-config --config "$CONF_IN_CONTAINER" set SCEP_RA_KEY \
      "pkcs11:token=fastpki;object=scep-ra;type=private?pin-source=/var/pki/tls/pin" >/dev/null 2>&1
  compose_exec fastpki-config --config "$CONF_IN_CONTAINER" set CMP_CLIENT_CA_ID "$CA_ID" >/dev/null 2>&1
  ok

  step "issuing service credentials through the console API"
  local pin_q="?pin-source=/var/pki/tls/pin"
  tok(){ printf 'pkcs11:token=fastpki;object=%s;type=private%s' "$1" "$pin_q"; }
  # OCSP responder: digitalSignature + OCSPSigning. The handler adds
  # id-pkix-ocsp-nocheck itself (RFC 6960 §4.2.2.2), and AIA/CRLDP are omitted —
  # a delegated responder pointing clients at itself is the loop the profile forbids.
  api_issue_hsm_cert "ocsp-ra-$CA_ID" "ocsp-ra.$DEMO_DOMAIN" "$(tok ocsp-ra)" \
      digitalSignature 1.3.6.1.5.5.7.3.9 "$WORK/ocsp-ra.pem" \
      --data-urlencode omit_aia=true --data-urlencode omit_crldp=true \
      || { fail "(ocsp-ra credential)"; return 1; }
  # CMP RA: id-kp-cmcRA (RFC 6402). bind_ra_cert resolves this row PER TRANSACTION,
  # so Sweep B can re-key it later without restarting anything.
  api_issue_hsm_cert "cmp-ra-$CA_ID" "cmp-ra.$DEMO_DOMAIN" "$(tok cmp-ra)" \
      digitalSignature 1.3.6.1.5.5.7.3.28 "$WORK/.cmpra.pem" \
      || { fail "(cmp-ra credential)"; return 1; }
  # SCEP RA: MUST be RSA (it decrypts the PKIOperation envelope), with
  # keyEncipherment for exactly that, plus Microsoft's Certificate Request Agent EKU.
  api_issue_hsm_cert "scep-ra-$CA_ID" "scep-ra.$DEMO_DOMAIN" "$(tok scep-ra)" \
      digitalSignature,keyEncipherment 1.3.6.1.4.1.311.20.2.1 "$WORK/.scepra.pem" \
      || { fail "(scep-ra credential)"; return 1; }
  # The four TLS listeners. est/acme/ms have never started, so keygen=true mints their
  # token keys NOW at the object names bootstrap.compose.conf points them at — their
  # first boot then finds a cert row (CERT_ID) and serves it instead of self-signing.
  # The console is already running and minted its own key at startup, so `web` adopts
  # the existing key (keygen=false): minting again would orphan the pair it loaded.
  spec_api_args "${SERVER_KEY}"   # baseline credential axis, usually empty = defaults
  api_issue_hsm_cert est localhost "$(tok est-tls)" \
      digitalSignature,keyEncipherment serverAuth \
          "$WORK/.est-tls.pem" \
          --data-urlencode "sans=localhost" \
      "${API_KEY_ARGS[@]+"${API_KEY_ARGS[@]}"}" || { fail "(est transport cert)"; return 1; }
  api_issue_hsm_cert acme localhost "$(tok acme-tls)" \
      digitalSignature,keyEncipherment serverAuth \
          "$WORK/.acme-tls.pem" \
          --data-urlencode "sans=localhost" \
      "${API_KEY_ARGS[@]+"${API_KEY_ARGS[@]}"}" || { fail "(acme transport cert)"; return 1; }
  api_issue_hsm_cert ms localhost "$(tok ms-tls)" \
      digitalSignature,keyEncipherment serverAuth \
          "$WORK/.ms-tls.pem" \
          --data-urlencode "sans=localhost" \
      "${API_KEY_ARGS[@]+"${API_KEY_ARGS[@]}"}" || { fail "(ms transport cert)"; return 1; }
  api_issue_hsm_cert web localhost "$(tok web-tls)" \
      digitalSignature,keyEncipherment serverAuth \
          "$WORK/.web-tls.pem" \
          --data-urlencode "sans=localhost" \
      --data-urlencode keygen=false \
      "${API_KEY_ARGS[@]+"${API_KEY_ARGS[@]}"}" || { fail "(web transport cert)"; return 1; }
  ok
  # ⚠️ THE CONSOLE LOADS ITS IDENTITY AT STARTUP — it was already running to drive the
  # API above, so it is still serving the self-signed pair it booted on. With Sweep B
  # in the plan nobody noticed: its restart list carried web, masking this. With the
  # sweep suppressed (--server-key pins the baseline), that mask is gone and the final
  # chain verification failed with num=18 self-signed certificate. Restart is the
  # adoption path; there is no hot-reload.
  step "reloading the console onto its CA-issued credential"
  dcp restart web >>"$WORK/compose-webrestart.log" 2>&1 \
    || { fail "(docker compose restart web failed — see $WORK/compose-webrestart.log)"; return 1; }
  wait_tcp "$DEMO_WEB_PORT" 100 || { fail "(console did not come back on :$DEMO_WEB_PORT)"; return 1; }
  ok

  step "starting the protocol services"
  dcp up -d --quiet-pull >"$WORK/compose-up.log" 2>&1 \
    || { fail "(docker compose up failed — see $WORK/compose-up.log)"; return 1; }
  for p in "$DEMO_OCSP_PORT" "$DEMO_CMP_PORT" "$DEMO_STORE_PORT" "$DEMO_SCEP_PORT" \
           "$DEMO_EST_PORT" "$DEMO_ACME_PORT" "$DEMO_MS_PORT"; do
    wait_tcp "$p" 100 || { fail "(service on :$p never came up — see $WORK/compose-up.log)"; return 1; }
  done
  MS_HOSTPORT="localhost:$DEMO_MS_PORT"
  ok

  # ── from here on this IS the live client path ────────────────────────────────
  # The same variables a target descriptor carries, then the SAME discovery code:
  # URLs, enrolment credentials from the API, chain bootstrap from EST /cacerts.
  TARGET_HOST=localhost
  WEB_PORT=$DEMO_WEB_PORT   EST_PORT=$DEMO_EST_PORT   CMP_PORT=$DEMO_CMP_PORT
  OCSP_PORT=$DEMO_OCSP_PORT STORE_PORT=$DEMO_STORE_PORT SCEP_PORT=$DEMO_SCEP_PORT
  ACME_PORT=$DEMO_ACME_PORT
  DEMO_USER=demo DEMO_PASS=demo DEMO_DOMAIN=internal
  # acme_wildcard keys on this: the throwaway stack already runs its validator pointed at
  # the host (ACME_DNS_RESOLVER in the staged .env), so there is nothing to repoint.
  DEMO_LOCAL_ACME=true
  setup_target_client
}
# ── live deployment (from a --target descriptor) ─────────────────────────────
setup_live(){
  hdr "Targeting a live FastPKI deployment"
  # The descriptor is plain KEY=VALUE lines (see demo/provision-target.sh).
  [ -f "$TARGET_FILE" ] || { echo "target file not found: $TARGET_FILE" >&2; exit 2; }
  # shellcheck disable=SC1090
  . "$TARGET_FILE"
  : "${TARGET_HOST:?target file missing TARGET_HOST}"
  # If provision-target.sh downloaded a CMP client config alongside the target
  # file, use it — it carries the authoritative ref/secret/server from the DB.
  cfg_dir="$(dirname "$TARGET_FILE")"
  CMP_CONFIG="${cfg_dir}/fastpki-cmp.cnf"
  [ -f "$CMP_CONFIG" ] || CMP_CONFIG=""
  setup_target_client
}

# ── the client path, shared by BOTH modes ────────────────────────────────────
# Everything from "which URLs" to "what do we trust" is identical whether the target
# was provisioned by setup_throwaway seconds ago or by an operator months ago. That
# sameness IS the point of throwaway mode: the client steps below cannot tell the two
# apart, so a green throwaway run is evidence about the live path, not about a fixture.
# Consumes: TARGET_HOST, the per-protocol ports, DEMO_USER/DEMO_PASS, optional CA_ID,
# EST_BASE_PATH/CMP_PATH/… overrides. Produces: every *_URL, CHAIN, ISSUER,
# CMP_RECIPIENT/REF/SECRET, EST_AUTH, ACME_EAB_*, SCEP_CHALLENGE.
setup_target_client(){
  local eP=${EST_PORT:-8443} cP=${CMP_PORT:-8445} oP=${OCSP_PORT:-8080}
  local sP=${STORE_PORT:-8447} scP=${SCEP_PORT:-8448} aP=${ACME_PORT:-8444}
  EST_URL="https://$TARGET_HOST:$eP${EST_BASE_PATH:-/.well-known/est}"
  CMP_URL="http://$TARGET_HOST:$cP${CMP_PATH:-/cmp}"
  OCSP_URL="http://$TARGET_HOST:$oP${OCSP_PATH:-/ocsp}"
  STORE_URL="http://$TARGET_HOST:$sP"; STORE_PATH="${STORE_PATH:-/certificates/search}"
  # SCEP is served at scep_path itself (default /scep); a deployment may still set the
  # old CGI-style path. Do NOT append anything — a further segment would match the
  # per-CA instance route /{scep_path}/{id}.
  SCEP_URL="http://$TARGET_HOST:$scP${SCEP_PATH:-/scep}"
  ACME_DIR="https://$TARGET_HOST:$aP${ACME_BASE_PATH:-/acme}/directory"
  EST_AUTH="${DEMO_USER:?DEMO_USER must be set}:${DEMO_PASS:?DEMO_PASS must be set}"
  # The global CMP_PBM_SECRET is gone. CMP PBM is per user, so the demo asks the
  # console for its OWN secret with the same session it already uses to discover the CA.
  # CMP_REF was already the username, so only the value changes — the wire format is
  # unchanged.
  CMP_REF="${DEMO_USER}"
  CMP_SECRET=""

  # Always ask the console for this user's enrolment credentials — a CA_ID in the
  # target file is just a hint and may be stale, but the user's secrets are only ever
  # returned by the API.  The session opened here is reused by the CA-discovery block
  # below so we don't log in twice.
  local wP=${WEB_PORT:-8090}
  local api_base="https://$TARGET_HOST:$wP"
  local cookie_jar="$WORK/.demo-cookies"
  curl -sk -c "$cookie_jar" -X POST \
    -d "username=${DEMO_USER}&password=${DEMO_PASS}" \
    "$api_base/api/login" -o /dev/null 2>/dev/null
  local creds
  creds=$(curl -sk -b "$cookie_jar" --max-time 10 "$api_base/api/enrolment-credentials" 2>/dev/null)
  CMP_SECRET=$(printf '%s' "$creds" | sed -nE 's/.*"cmp_secret" *: *"([^"]*)".*/\1/p')
  ACME_EAB_KID=$(printf '%s' "$creds" | sed -nE 's/.*"kid" *: *"([^"]*)".*/\1/p')
  ACME_EAB_HMAC=$(printf '%s' "$creds" | sed -nE 's/.*"acme_eab_hmac" *: *"([^"]*)".*/\1/p')
  # SCEP joins the other two. The deployment-wide SCEP_CHALLENGE is gone, so the
  # challengePassword is this user's own credential and comes from the same endpoint and
  # the same session — no longer scraped off the node's configuration by
  # provision-target.sh.
  SCEP_CHALLENGE=$(printf '%s' "$creds" | sed -nE 's/.*"scep_challenge" *: *"([^"]*)".*/\1/p')
  export SCEP_CHALLENGE
  if [ -z "$SCEP_CHALLENGE" ]; then
    info "note:" "no SCEP credential for ${DEMO_USER} — the SCEP step will be skipped. A role that enrols over SCEP (enrol:scep) gets one minted."
  fi
  if [ -z "$CMP_SECRET" ]; then
    info "note:" "no CMP secret for ${DEMO_USER} — the CMP steps will be skipped. A role that enrols (e.g. requester) gets one minted at first login."
  fi
  # EAB became the default, so a missing ACME credential is no longer a nuance — it is
  # the difference between the ACME step working and certbot being refused at register
  # with `externalAccountRequired`. CMP has said this all along; ACME did not, so the
  # step failed with the problem document buried in acme-cli.log and nothing on screen
  # naming the cause.
  if [ -z "$ACME_EAB_HMAC" ] || [ -z "$ACME_EAB_KID" ]; then
    info "note:" "no ACME EAB credential for ${DEMO_USER} — this deployment requires External Account Binding, so the ACME step will be refused at registration. Same fix as CMP: a role that enrols gets one minted at first login."
  fi

  # Auto-discover the primary CA ID from /api/ca-instances so per-CA routes
  # (EST/{id}, CMP/{id}) work without the user hard-coding a CA ID.
  #
  # ⚠️ NOT `local` ANY MORE. The discovery result has to survive this function: the
  # ACME cells build their directory URL from ${CA_ID:-sub-ca} long after setup has
  # returned, and a function-local silently reset it to that fallback on every live
  # run whose descriptor did not name a CA.
  if [ -z "${CA_ID:-}" ]; then
    step "discovering primary CA from /api/ca-instances"
    local instances
    instances=$(curl -sk -b "$cookie_jar" --max-time 10 "$api_base/api/ca-instances" 2>/dev/null)
    if [ -n "$instances" ]; then
      # ⚠️ THIS PICKED THE OFFLINE ROOT, and the demo then died at the first step.
      #
      # The old expression was
      #     sed -nE 's/.*"parentId" *: *"[^"]+".*"id" *: *"([^"]+)".*/\1/p'
      # which requires `parentId` to appear BEFORE `id`. The API emits `id` first:
      #     {"id":"issuing-dc2","name":...,"parentId":"labroot",...}
      # so it can never match inside one object — and because the body is one line and
      # `.*` is greedy, it matched across the WHOLE document and returned the LAST id in
      # it. On this lab that is `labroot`, the offline root, whose certificate cannot do
      # EST enrolment. Measured: "primary CA: labroot" then "could not fetch CA chain".
      #
      # ⚠️ AND "has a parent" IS NOT THE QUESTION ANYWAY. Every DC sees every CA, because
      # `certs` replicates — dc2 lists `issuing` (DC1's) and `issuing-dc3` too, and holds
      # the private key for neither. The question is "which CA can THIS node sign with",
      # and the API already answers it: `signable`. On dc2 exactly one CA is signable.
      #
      # Split on `{` so each CA is judged on its OWN fields; a document-wide regex is what
      # produced the bug. Order of preference: signable AND not a root, then signable,
      # then not a root, then whatever is first.
      local objs; objs=$(printf '%s' "$instances" | tr '{' '\n')
      local pick_id
      pick_id() { sed -nE 's/.*"id" *: *"([^"]+)".*/\1/p' | head -1; }
      CA_ID=$(printf '%s' "$objs" | grep '"signable" *: *true' | grep '"parentId" *: *"[^"]' | pick_id)
      [ -z "$CA_ID" ] && CA_ID=$(printf '%s' "$objs" | grep '"signable" *: *true' | pick_id)
      [ -z "$CA_ID" ] && CA_ID=$(printf '%s' "$objs" | grep '"parentId" *: *"[^"]' | pick_id)
      [ -z "$CA_ID" ] && CA_ID=$(printf '%s' "$objs" | grep '"id" *:' | pick_id)
    fi
    if [ -n "$CA_ID" ]; then ok; info "primary CA:" "$CA_ID"
    else ok; info "note:" "could not auto-detect CA_ID; set CA_ID in target file"
    fi
  fi
  # Per-CA EST/CMP/SCEP/ACME routes: the server 404s on the base path.
  if [ -n "$CA_ID" ]; then
    EST_URL="${EST_URL%/}/$CA_ID"
    CMP_URL="${CMP_URL%/}/$CA_ID"
    SCEP_URL="${SCEP_URL%/}/$CA_ID"
    # The ACME wildcard failed with "this endpoint is per-CA: use
    # /acme/{ca_id}/directory" even though CA_ID was written in the target descriptor.
    #
    # ⚠️ ACME was the one protocol this block forgot, and the reason it was forgotten is
    # that its id goes in the MIDDLE — /acme/{id}/directory — so the `${VAR%/}/$CA_ID`
    # suffix trick the other three use does not fit and nobody wrote the other line.
    # Rebuilt from its parts instead of patched, so there is one expression to read.
    #
    # It looked like only the wildcard was broken because the certbot step uses the
    # SERVER-generated certbot config, whose {{ACME_DIRECTORY}} is substituted with the
    # id already; only this locally-built URL was wrong.
    ACME_DIR="https://$TARGET_HOST:${ACME_PORT:-8444}${ACME_BASE_PATH:-/acme}/$CA_ID/directory"
  fi

  step "bootstrapping trust from EST /cacerts"
  curl -sk --max-time 20 "$EST_URL/cacerts" | b64d > cacerts.p7b 2>/dev/null
  "$OSSL" pkcs7 -inform DER -in cacerts.p7b -print_certs -out chain.pem 2>/dev/null
  if ! grep -q "BEGIN CERT" chain.pem 2>/dev/null; then fail "(could not fetch CA chain from $EST_URL/cacerts)"; exit 1; fi
  CHAIN="$WORK/chain.pem"
  # Split the chain and pick the issuing CA (the cert whose subject == other
  # certs' issuer, i.e. not the self-signed root) as OCSP -issuer / CMP recipient.
  awk 'BEGIN{n=0} /BEGIN CERT/{n++} {print > ("cc"n".pem")}' chain.pem
  ISSUER=""; local rootsubj=""
  for f in cc*.pem; do
    local s i; s=$("$OSSL" x509 -in "$f" -noout -subject 2>/dev/null | sed 's/^subject=//')
    i=$("$OSSL" x509 -in "$f" -noout -issuer  2>/dev/null | sed 's/^issuer=//')
    if [ "$s" = "$i" ]; then rootsubj="$s"; else ISSUER="$WORK/$f"; CMP_RECIPIENT="/${s//, //}"; fi
  done
  [ -z "$ISSUER" ] && ISSUER="$WORK/cc1.pem"   # single self-signed CA fallback
  # openssl -recipient wants slash-separated RDNs; build it from the issuer DN.
  CMP_RECIPIENT=$("$OSSL" x509 -in "$ISSUER" -noout -subject 2>/dev/null | sed 's/^subject=//; s/, /\//g; s/^/\//')
  ok
  info "target:" "$TARGET_HOST  ($("$OSSL" x509 -in "$ISSUER" -noout -subject 2>/dev/null | sed 's/^subject= *//'))"
}

# ── protocol steps (consume the target variables) ────────────────────────────
curl_tls(){ if [ "$TLS_INSECURE" = 1 ]; then curl -sk "$@"; else curl -s "$@"; fi; }

# Quietly fetch a cert for a CN from the RFC 4387 store into a PEM file (handles
# both a single DER cert and a PKCS7 bundle). 0 if a cert was written.
store_fetch(){ # <cn> <outfile.pem>
  local cn="$1" out="$2" p
  : > "$out"
  for p in "$STORE_PATH" /certificates/search /certs/search; do
    [ -n "$p" ] || continue
    curl -s --max-time 20 -o store-tmp.bin "$STORE_URL$p?cn=$cn" 2>/dev/null
    [ -s store-tmp.bin ] || continue
    "$OSSL" x509 -inform DER -in store-tmp.bin -out "$out" 2>/dev/null && [ -s "$out" ] && return 0
    "$OSSL" pkcs7 -inform DER -in store-tmp.bin -print_certs 2>/dev/null | "$OSSL" x509 -out "$out" 2>/dev/null
    [ -s "$out" ] && return 0
  done
  return 1
}

# ── CMP: every ir and kur asks for IMPLICIT CONFIRMATION ─────────────────────
#
# ⚠️ NOT a shortcut. It is the only way the Ed448 cells of the matrix run at all.
#
# Without it the client sends a separate certConf after the server has already issued.
# Building that message hashes the new certificate, and for an Ed448-signed cert
# OpenSSL's X509_digest_sig() picks SHAKE256 (the RFC 8419 CMS default) and hands that
# bare XOF EVP_MD to X509_digest, which fails because nothing ever sets an xoflen.
# cmp_msg.c's err: label raises nothing, so the client dies with a bare
#
#     error creating certconf
#
# AFTER the server issued the certificate — a CLIENT defect that reads exactly like a
# server one. Verified with an X509_digest_sig probe on the issued leaf (returns NULL,
# empty error queue); present in 3.5.x and 3.6.x alike. `ed448` is in the default
# CA_KEYS, so every Ed448 CMP cell was skipped on every run before this.
#
# ⚠️ AND IT COSTS NO COVERAGE, which is the only reason it is acceptable. Proving the
# certConf path is not this demo's job: tests/cmp_onhold.sh pins the whole truth table
# (implicit -> valid(0); -disable_confirm -> on-hold(2) + OCSP certificateHold; a plain
# ir -> on-hold then valid once certConf arrives) and tests/cmp_certconf.sh pins the
# full IR/IP/CERTCONF/PKICONF round trip on one keep-alive socket. The demo's job is the
# key and digest axes, and this is what lets it reach them.
#
# rr deliberately does NOT get the flag: a revocation has no certificate to confirm,
# which is why the shipped fastpki-cmp.cnf blanks implicit_confirm in [rr] and [genm].

# Ensure a CMP identity cert CN=$CMP_REF (the owner) exists, to authorize a
# signature-protected revocation (self-service authorization). 0 if available.
cmp_identity(){ # <outpem> <outkey>
  local pem="$1" key="$2"
  [ -s "$pem" ] && [ -s "$key" ] && return 0
  [ -n "$CMP_SECRET" ] || return 1
  "$OSSL" genrsa -out "$key" 2048 >/dev/null 2>&1
  local id_cfg=()
  if [ -n "$CMP_CONFIG" ] && [ -f "$CMP_CONFIG" ]; then
    # ⚠️ `-section cmp,ir` IS LOAD-BEARING, and leaving it out is why the failure came back.
    # The shipped fastpki-cmp.cnf has a section per command. Its [cmp] section
    # carries the SIGNATURE credentials — `cert = example.com.crt`, `key =
    # example.com.key`, and `secret =` to switch PBM off — because that is what an
    # already-enrolled client uses. The shared secret lives in [ir], which also blanks
    # cert/key again.
    #
    # `openssl cmp -config X` with no -section reads ONLY [cmp]. So this asked for
    # signature protection with two files that do not exist in the demo's workdir, and
    # died before sending anything:
    #
    #   Could not open file or uri for loading private key for CMP client certificate
    #     from example.com.key: No such file or directory
    #   cmp_main:apps/cmp.c:3867:CMP error: cannot set up CMP context
    #
    # -cmd ir on the command line overrides `cmd = cr` but pulls in NOTHING else from
    # the [ir] section, so it reads like the command was selected when the credentials
    # were not. cmp_enroll() below has had the -section for a while; this second call
    # site did not, which is the whole defect.
    # ⚠️ AND `-server` ON THE COMMAND LINE, overriding the config's own. The downloaded
    # fastpki-cmp.cnf carries the DEPLOYMENT's public URL — `{{CMP_URL}}` is substituted
    # from BASE_URL/PKI_DNS — while the demo reaches the target at TARGET_HOST, which is
    # whatever the operator pointed it at (localhost for a local stack, a lab FQDN for a
    # remote one). Measured on dc3, with the section fix already in place:
    #
    #   CMP info: will contact http://pki.example.org:8445/cmp/issuing-dc3
    #   CMP error: system lib:No address associated with hostname
    #
    # So the config got the client past setup and then sent it to a host the demo cannot
    # resolve. Same shape as the SCEP_CHALLENGE problem: a value read from the
    # deployment describes the deployment, not the route the demo is using.
    "$OSSL" cmp -cmd ir -implicit_confirm -section cmp,ir -config "$CMP_CONFIG" -server "$CMP_URL" \
      -trusted "$CHAIN" \
      -newkey "$key" -subject "/CN=$CMP_REF" -certout "$pem" >cmp-id.log 2>&1
  else
    "$OSSL" cmp -cmd ir -implicit_confirm -server "$CMP_URL" -recipient "$CMP_RECIPIENT" -trusted "$CHAIN" \
      -ref "$CMP_REF" -secret "pass:$CMP_SECRET" -keep_alive 0 \
      -newkey "$key" -subject "/CN=$CMP_REF" -certout "$pem" >cmp-id.log 2>&1
  fi
  grep -q "BEGIN CERTIFICATE" "$pem" 2>/dev/null || return 1
  # The identity cert counts against the same caps as everything else this run issued —
  # it is the one people forget, because it is enrolled to enable a REVOCATION.
  record_issued "$pem"
}

# Revoke a cert via CMP rr, signature-protected by the identity cert. The openssl
# client may exit non-zero validating the CA-signed response (the issuing-CA cert
# carries only keyCertSign/cRLSign — a cosmetic interop nit), so ignore its rc.
cmp_revoke_oldcert(){ # <oldcert.pem> <id.pem> <id.key> [reason=4]
  "$OSSL" cmp -cmd rr -server "$CMP_URL" -recipient "$CMP_RECIPIENT" -trusted "$CHAIN" \
    -cert "$2" -key "$3" -keep_alive 0 -oldcert "$1" -revreason "${4:-4}" >cmp-rr.log 2>&1 || true
}

# ── CRL staging for -crl_check_all ───────────────────────────────────────────
# ⚠️ DO NOT "SIMPLIFY" THIS BACK TO -crl_download. It was written that way and could
# not pass on the OpenSSL this script prefers.
#
# Under -crl_check_all, OpenSSL 3.5 demands a CRL for EVERY certificate in the chain,
# including the self-signed root at the top. A root carries no CRL DP of its own and
# must not — a trust anchor has no issuer to point at and is not revoked by anybody —
# so -crl_download has no URL to fetch for it and verification dies at the anchor's
# depth with "unable to get certificate CRL". Worse, -crl_download REPLACES the local
# CRL store rather than supplementing it, so supplying the root's CRL locally does not
# rescue the combination either. OpenSSL 3.6 dropped the demand (openssl/openssl#8439,
# open against 3.0-3.2 and master), which is the ONLY reason this ever passed: on a
# developer Mac $OSSL is Homebrew 3.6, while /opt/openssl-3.5 above and the shipped
# Alpine image are both 3.5 — where every validation here failed.
#
# So stage the CRLs instead of downloading them inline. Every CRL the chain needs is
# named by a CRL DP INSIDE the chain: the leaf's DP names the issuing CA's CRL (which
# covers depth 0), and the issuing CA's DP names the root's CRL (which covers depth 1
# AND the self-signed root at depth 2, whose issuer is itself). A single self-signed CA
# needs only the leaf's DP. Each is filed under its own issuer hash as <hash>.r0, which
# is what OpenSSL's on-disk lookup expects — and they stay OUT of the -CAfile, which
# carries trust anchors and nothing else.
#
# REBUILT ON EVERY CALL, never cached: a revoke-then-verify inside one cell must see
# the post-revocation list. That is the same reason CRL_CACHE_TTL_SEC=0 is set — with
# the responder's default 300 s cache a revoked certificate would still "pass" here,
# vacuously.
#
#   crl_capath <pem-file> [pem-file …]  -> prints the directory to pass to -CApath
# Each argument may hold one certificate or a bundle; every certificate found in any of
# them is harvested for CRL DPs. Silent by design: a CRL that cannot be fetched simply
# is not staged, and the verification that follows reports the resulting gap.
crl_capath(){
  local dir="$WORK/capath" src pem uris uri h n=0
  rm -rf "$dir"; mkdir -p "$dir"
  # ⚠️ ONE awk OVER EVERY FILE, never one per file. The split counter has to keep
  # incrementing across them: called once per file it restarts at 1, so the SECOND file's
  # first certificate overwrites the first file's. Passing (chain, leaf) that way kept the
  # leaf and the root and silently dropped the ISSUING CA — and with it the only CRL DP
  # naming the root's CRL, so every validation failed at the sub CA's depth with
  #     error 3 at 1 depth lookup: unable to get certificate CRL
  # while the leaf's own CRL staged perfectly. Measured against a live three-DC mesh.
  local srcs=""
  for src in "$@"; do [ -s "$src" ] && srcs="$srcs $src"; done
  [ -n "$srcs" ] || { printf '%s' "$dir"; return; }
  # shellcheck disable=SC2086
  awk -v d="$dir" '/BEGIN CERT/{n++} n{print > (d "/split" n ".pem")}' $srcs 2>/dev/null
  for pem in "$dir"/split*.pem; do
    [ -s "$pem" ] || continue
    uris=$("$OSSL" x509 -in "$pem" -noout -ext crlDistributionPoints 2>/dev/null \
           | sed -n 's/.*URI:\(http[^ ]*\).*/\1/p')
    [ -n "$uris" ] || continue
    # Several DPs mean several data centers serving the SAME list, not several lists —
    # take the first that answers and move on rather than fetching every copy.
    for uri in $uris; do
      curl -s --max-time 10 -o "$dir/.dl" "$uri" 2>/dev/null || continue
      [ -s "$dir/.dl" ] || continue
      if h=$("$OSSL" crl -in "$dir/.dl" -inform DER -noout -hash 2>/dev/null) && [ -n "$h" ]; then
        "$OSSL" crl -in "$dir/.dl" -inform DER -out "$dir/$h.r0" 2>/dev/null && { n=$((n+1)); break; }
      elif h=$("$OSSL" crl -in "$dir/.dl" -noout -hash 2>/dev/null) && [ -n "$h" ]; then
        cp "$dir/.dl" "$dir/$h.r0" && { n=$((n+1)); break; }
      fi
    done
  done
  rm -f "$dir"/.dl "$dir"/split*.pem
  printf '%s' "$dir"
}

# ── per-certificate validation ───────────────────────────────────────────────
# The SAME recipe the run's final tls_verify applies to endpoint chains, applied at
# ISSUANCE time: chain to the root, RFC 5280 strict parsing, and a live CRL check over
# every depth. The CRLs are fetched fresh through the certificates' own CRL DP pointers
# by crl_capath above; in throwaway those pointers are
# http://localhost:<ocsp port>/... served by fastpki-ocsp, so every check here still
# exercises the real responder.
#
#   validate_cert <leaf.pem> [ok|revoked]  -> 0 iff the outcome matches
# Prints nothing; callers present the result. `ok`  = verify exits 0.
# `revoked` = verify FAILS *and* names revocation — any other failure (chain break,
# unreachable CRL) must not masquerade as a correct revoked verdict.
validate_cert(){
  local pem="$1" expect="${2:-ok}" out rc cap
  [ -s "$pem" ] || return 1
  cap=$(crl_capath "${CHAIN:-$WORK/chain.pem}" "$pem")
  out=$("$OSSL" verify -CAfile "${CHAIN:-$WORK/chain.pem}" -CApath "$cap" \
        -x509_strict -crl_check_all "$pem" 2>&1); rc=$?
  if [ "$expect" = ok ]; then [ $rc -eq 0 ] && return 0; VALIDATE_WHY="$out"; return 1; fi
  [ $rc -ne 0 ] || { VALIDATE_WHY="verify unexpectedly succeeded"; return 1; }
  printf '%s\n' "$out" | grep -q 'certificate revoked' || { VALIDATE_WHY="failed but not as revoked:
$out"; return 1; }
}

vshow(){ # <label> <pem> <expect> — verbose presentation of a validate_cert result
  step "$1"
  if validate_cert "$2" "${3:-ok}"; then ok
  else fail "(${VALIDATE_WHY:-see above})"; fi
}
serial_of(){ "$OSSL" x509 -in "$1" -noout -serial 2>/dev/null | sed 's/^serial=//'; }

# ⚠️ SHA-3 IS NOT THE PROBLEM, AND OPENSSL SUPPORTS IT FINE. Say so up front, because
# "openssl cannot do sha3" is the wrong conclusion and the obvious one to jump to.
#
# What is missing is one specific encoding: an RSASSA-PSS-params AlgorithmIdentifier that
# names a SHA-3 hash. Everything around it works — measured on the shipped 3.5.7 and 3.6.3:
#
#   sha3 is present                openssl list -digest-algorithms -> 20 sha3 entries
#   PKCS#1 + sha3 encodes          a plain RSA CSR gets "Signature Algorithm: RSA-SHA3-256"
#   PSS + sha3 CRYPTO works        dgst -sha3-256 -sign with a PSS key, -verify -> Verified OK
#   PSS + sha3 AID does NOT        rsa_generate_signature_aid: internal error (rsa_sig.c:351)
#   nor a PSS KEY with them        genpkey rsa_pss_keygen_md:sha3-256 -> "Error writing key(s)"
#
# So the signature is computable AND verifiable; it cannot be DESCRIBED in the DER structure
# a CSR, certificate or CMP CertReq must carry. Note OpenSSL emits NOTHING here — it fails
# before writing output. It does not produce a malformed structure that a strict validator
# would later reject, so no bad artifact can escape; the failure is entirely local.
#
# Not an invocation error: six sigopt permutations were tried (rsa_padding_mode:pss,
# rsa_pss_saltlen:digest, rsa_pss_saltlen:-1, rsa_mgf1_md:sha3-256, digest:sha3-256, and
# the bare -sha3-256), all failed, while -sha256 and -sha512 passed on the same key. That
# key was verified UNRESTRICTED first ("No PSS parameter restrictions") — the question that
# mattered, since a key pinned to another digest refusing sha3 would be correct behaviour.
#
# ⚠️ AND FALLING BACK TO SHA-2 IS RIGHT ON INTEROP GROUNDS, NOT MERELY BECAUSE OPENSSL
# CANNOT. There is no PKIX profile for RSASSA-PSS with a FIXED-LENGTH SHA-3 in X.509:
# RFC 4055 profiles the params for SHA-1 and SHA-2 only, a decade before SHA-3, and
# RFC 8692 standardised the SHA-3 family for PSS only as the SHAKEs — parameterless OIDs
# id-RSASSA-PSS-SHAKE128/256 (1.3.6.1.5.5.7.6.30/.31). RFC 8017 defines RSASSA-PSS over any
# hash, so PSS+SHA3 is unprofiled rather than forbidden — but unprofiled is enough: even if
# OpenSSL emitted it, other stacks have no agreed encoding to validate against.
#
# The SHAKE route is not a workaround here either: this OpenSSL registers no
# RSASSA-PSS-SHAKE signature algorithm at all (every SHAKE entry in
# `list -signature-algorithms` is SLH-DSA) and does not know the names. Standardised,
# unimplemented.
#
# So the gap is detected from the client's own failure and never assumed from the pair: if
# a future OpenSSL closes the encoder these cells stop skipping by themselves, and the
# interop caveat above is then the reason to keep choosing SHA-2 for PSS certificates.
csr_local_gap(){ # <keyspec> <md> -> 0 iff THIS HOST cannot sign with this pair at all
  [ "${1%%:*}" = rsa-pss ] || return 1
  case "$2" in sha3-*|shake*) return 0;; esac
  return 1
}

# ── is the CSR-hash axis an axis at all for this client key? ─────────────────
# make_csr passes the digest straight to `openssl req`, and a ONE-SHOT signature scheme
# ignores it: PureEdDSA (RFC 8032) and ML-DSA (FIPS 204) prehash nothing, so -sha3-256
# and -sha3-512 produce BYTE-IDENTICAL CSRs and therefore byte-identical cells. At the
# default axes that is 2 of 5 client keys × 2 hashes per CA slice — roughly 200
# duplicated lifecycles reported as coverage the wire never carried. Same objection that
# keeps shake256 out of $HASHES by default; see the note at the axis defaults.
#
# ⚠️ EC IS DELIBERATELY NOT IN THIS LIST, and it looks like it belongs. The CSR really is
# signed ecdsa-with-SHA3-* — those OIDs exist and openssl emits them — so those cells do
# differ. What EC ignores is the digest of the ISSUED CERTIFICATE, which leaf_signing_md()
# auto-matches to the curve (src/lib/x509.cpp): a different claim, about a different
# signature, already pinned by tests/leaf_hash_choice.sh. Collapsing EC here would drop
# real coverage on the strength of a resemblance.
#
# rsa-pss × sha3 is NOT here either: csr_local_gap() handles it as a local TOOLING gap,
# detected on the actual failure rather than assumed.
hash_axis_applies(){   # <keyspec> -> 0 iff a requested digest changes what gets signed
  case "${1%%:*}" in
    ed25519|ed448|ml-dsa-44|ml-dsa-65|ml-dsa-87) return 1 ;;
    *) return 0 ;;
  esac
}
hash_axis_skip_reason(){   # <keyspec>
  printf '%s is a one-shot scheme with no prehash, so the CSR digest is ignored and every extra hash would repeat one cell — running only the first' "${1%%:*}"
}

# ── renewals ─────────────────────────────────────────────────────────────────
# A renewal is only proven when the NEW certificate differs from the old one, so every
# helper asserts serial != previous before validating.

est_renew(){ # <cn> -> est-ren.pem via POST /simplereenroll (RFC 7030 §4.2.2)
  local cn="$1"
  # ⚠️ CLEAR THE OUTPUTS FIRST, exactly as est_do_enroll and cmp_enroll already do.
  # Without this a cell that returns early — the HTTP 429 per-owner cap is the one that
  # bites, because mtx_est_cell CONTINUES past it — leaves the PREVIOUS cell's est-ren.pem
  # on disk beside a freshly generated ren.key. cmp_revoke_leaf is then handed a
  # certificate and a key that do not match, and the cell reports a spurious
  # "est-revoke2" failure that has nothing to do with the key or digest under test.
  rm -f est-ren.pem ren.key ren.csr ren.b64 ren.p7
  gen_client_key rsa:2048 ren.key || return 1
  make_csr ren.key "$cn" "" ren.csr || return 1
  "$OSSL" req -in ren.csr -outform DER 2>/dev/null | b64e > ren.b64
  local auth=(); [ -n "$EST_AUTH" ] && auth=(-u "$EST_AUTH")
  local code
  code=$(curl_tls --max-time 30 "${auth[@]+"${auth[@]}"}" --data-binary @ren.b64 \
    -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" \
    -o ren.p7 -w '%{http_code}' "$EST_URL/simplereenroll") || return 1
  [ "$code" = 200 ] || { EST_CODE=$code; return 1; }
  b64d < ren.p7 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs -out est-ren.pem 2>/dev/null
  grep -q "BEGIN CERTIFICATE" est-ren.pem 2>/dev/null || return 1
  [ "$(serial_of est-ren.pem)" != "$(serial_of est-leaf.pem)" ]
}

cmp_kur(){ # <cn> -> cmp-kur.pem: key update request signed by the EXISTING cert
  # Signature protection only: with -cert/-key present, PBM ref/secret would be dead
  # weight at best and an ambiguity at worst. The server resolves the signer's identity
  # from certs.owner via the extraCerts serial — the same rule rr uses.
  local cn="$1"
  gen_client_key ed25519 kur-new.key || return 1
  rm -f cmp-kur.pem
  "$OSSL" cmp -cmd kur -implicit_confirm -server "$CMP_URL" \
    -recipient "$CMP_RECIPIENT" -trusted "$CHAIN" -keep_alive 0 \
    -cert cmp-leaf.pem -key cmp-leaf.key -newkey kur-new.key \
    -certout cmp-kur.pem >cmp-kur.log 2>&1 || return 1
  grep -q "BEGIN CERTIFICATE" cmp-kur.pem 2>/dev/null || return 1
  [ "$(serial_of cmp-kur.pem)" != "$(serial_of cmp-leaf.pem)" ]
}

scep_renew(){ # <cn> <issued-leaf.key> [new-keyspec] — PKCSReq signed by the ISSUED pair.
  # scep-testclient build takes ANY signer cert+key pair; RFC 8894 renewal means
  # BOTH come from the previously issued certificate: the message is signed with ITS key,
  # while the wrapped CSR carries the NEW key the renewed cert will bind. Signing with the
  # fresh CSR key instead (an earlier draft passed -keyout's key here) leaves cert and key
  # mismatched — the client cannot even build the request, and the cell reports a mystery.
  # Requires SCEP_RENEWAL=true on the server (staged into throwaway .env); without it the
  # server answers pkiStatus rejection and the caller reports the cell honestly.
  local CN="$1" oldkey="$2" kspec="${3:-rsa:2048}" TC="$BIN/scep-testclient"
  "$OSSL" x509 -inform DER -in scep-issued.der -out scep-signer.pem 2>/dev/null || return 1
  printf '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=%s\n' "$CN" > screq.cnf
  gen_client_key "$kspec" scep-renew.key || return 1
  "$OSSL" req -new -key scep-renew.key -config screq.cnf \
      -outform DER -out scep-renew-csr.der >/dev/null 2>&1 || return 1
  "$TC" build scep-ca.pem scep-signer.pem "$oldkey" scep-renew-csr.der scep-renew-req.der >/dev/null 2>&1 || return 1
  rm -f scep-renew-res.bin scep-ren.der
  curl -s --max-time 30 -X POST --data-binary @scep-renew-req.der \
    -H "Content-Type: application/x-pki-message" \
    "$SCEP_URL?operation=PKIOperation" -o scep-renew-res.bin
  [ -s scep-renew-res.bin ] || return 1
  local ST; ST=$("$TC" parse scep-signer.pem "$oldkey" scep-renew-res.bin scep-ren.der 2>/dev/null)
  [ "$ST" = "pkiStatus=0" ] || { SCEP_ST="$ST"; return 1; }
  "$OSSL" x509 -inform DER -in scep-ren.der -out scep-ren.pem 2>/dev/null || return 1
  [ "$(serial_of scep-ren.pem)" != "$(serial_of scep-signer.pem)" ]
}

# ── revocation of an arbitrary leaf + proof ──────────────────────────────────
# rr REQUIRES signature protection server-side (PBM is refused for revocation), but
# the signer does not need a separate identity credential: authorization keys on
# certs.owner of the extraCerts signer, so a leaf may sign its OWN rr — owner==caller
# passes the ownership gate by construction. That makes revocation work for leaves
# issued under ANY CA instance, which the full matrix needs; the baseline's dedicated
# identity credential (cmp_identity + cmp_revoke_oldcert) stays for its own section.
# Proof is two-sided: OCSP must answer revoked AND chain validation must fail naming
# revocation — either alone could be stale or cosmetic.
cmp_revoke_leaf(){ # <leaf.pem> <leaf.key> [reason=4] -> 0 iff OCSP flips to revoked
  local leaf="$1" lkey="$2"
  "$OSSL" cmp -cmd rr -server "$CMP_URL" \
    -recipient "$CMP_RECIPIENT" -trusted "$CHAIN" -keep_alive 0 \
    -cert "$leaf" -key "$lkey" -oldcert "$leaf" -revreason "${3:-4}" >cmp-rr.log 2>&1 || true
  local i st=""
  for i in 1 2 3 4 5 6 7 8; do
    st=$(ocsp_status "$leaf"); [ "$st" = revoked ] && return 0
    sleep 1
  done
  REV_WHY="OCSP still says '${st:-unavailable}' after rr (see $WORK/cmp-rr.log)"
  return 1
}


# ── client keys by SPEC (Sweeps C/D) ─────────────────────────────────────────
# genpkey, not req -newkey: -newkey only knows rsa/ec spellings, while genpkey takes
# every algorithm by name — rsa-pss via -pkeyopt, ed25519/ed448 bare, ML-DSA-44/65/87
# as provider names (OpenSSL 3.5+). One code path for every cell of the axis.
gen_client_key(){   # <spec> <out.key> -> 0 iff the local openssl can make it
  local spec="$1" out="$2" algo param
  spec_parts "$spec"
  algo=$SP_ALGO; param=$SP_PARAM
  case "$algo" in
    rsa)      [ -n "$param" ] || param=2048
              "$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:"$param" -out "$out" >/dev/null 2>&1;;
    rsa-pss)  [ -n "$param" ] || param=2048
              # ⚠️ rsa_keygen_bits, NOT rsa_pss_keygen_bits. OpenSSL 3.x has no
              # rsa_pss_keygen_bits pkeyopt — "command not supported" in
              # ctrl_params_translate.c — which silently turned every RSA-PSS client
              # cell into a skip on hosts whose openssl is perfectly capable.
              #
              # ⚠️ AND UNRESTRICTED. Pinning rsa_pss_keygen_md/saltlen here bakes
              # those choices INTO the key's AlgorithmIdentifier, and from then on
              # the key refuses everything else — a KUR signed by such a key came
              # back from the server as rejection "digest not allowed", because the
              # signer cert's SPKI advertises sha256-only while the message
              # protection used another digest. An unrestricted PSS key lets the
              # signing operation pick parameters per signature, which is what the
              # hash axis assumes about every other key type.
              "$OSSL" genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:"$param" \
                             -out "$out" >/dev/null 2>&1;;
    ec)       [ -n "$param" ] || param=P-256
              "$OSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"$param" -out "$out" >/dev/null 2>&1;;
    ed25519|ed448|ml-dsa-44|ml-dsa-65|ml-dsa-87)
              "$OSSL" genpkey -algorithm "${algo}" -out "$out" >/dev/null 2>&1;;
    *) return 2;;
  esac
}

# A CSR signed with a given digest over a generated key. The digest is the loop-5
# variable; "pure" algorithms (Ed*, ML-DSA) take no digest and ignore it.
make_csr(){   # <key.pem> <cn> <md-or-empty> <out.csr>
  local mdargs=()
  [ -n "$3" ] && mdargs=(-"$3")
  "$OSSL" req -new -key "$1" -subj "/CN=$2" \
    "${mdargs[@]+"${mdargs[@]}"}" -out "$4" >/dev/null 2>&1
}

# Decode an issued certificate and hold its SPKI to a spec. Shared by Sweeps A/B/C:
# asking for a key type and being issued one are different claims.
assert_spki(){   # <cert.pem> <spec> <label> -> 0 iff it matches
  local pem="$1" spec="$2" label="$3"
  local txt pk sz want wantbits
  txt=$("$OSSL" x509 -in "$pem" -noout -text 2>/dev/null)
  pk=$(printf '%s' "$txt" | sed -nE 's/.*Public Key Algorithm: (.*)/\1/p' | head -1)
  sz=$(printf '%s' "$txt" | sed -nE 's/.*Public-Key: \((.*)\)/\1/p' | head -1)
  want=$(want_spki_name "$spec")
  if [ -z "$want" ]; then fail "($label: no expected SPKI name for '$spec')"; return 1; fi
  if [ "$pk" != "$want" ]; then
    fail "($label: asked for $spec, got '${pk:-unreadable}')"; return 1; fi
  wantbits=$(want_spki_bits "$spec")
  if [ -n "$wantbits" ] && [ "$sz" != "$wantbits bit" ]; then
    fail "($label: asked for $spec, got ${sz:-no size})"; return 1; fi
  return 0
}

# One EST simpleenroll with a fresh key; sets $EST_CODE; writes est-leaf.{key,pem}.
# 0 iff a certificate came back.
est_do_enroll(){ # <cn> [keyspec] [md]
  local cn="$1" kspec="${2:-rsa:2048}" md="${3:-}"
  # ⚠️ rm BEFORE, judge AFTER: the success test greps this file, so a leftover from an
  # earlier cell made a FAILED enroll look issued (the matrix hit exactly that — a 404
  # on a mis-built URL "succeeded" against the baseline cell's certificate).
  rm -f est-leaf.pem
  gen_client_key "$kspec" est-leaf.key || { EST_CODE=keygen; return 1; }
  make_csr est-leaf.key "$cn" "$md" est.csr || { EST_CODE=csr; return 1; }
  "$OSSL" req -in est.csr -outform DER 2>/dev/null | b64e > est.b64
  local auth=(); [ -n "$EST_AUTH" ] && auth=(-u "$EST_AUTH")
  EST_CODE=$(curl_tls --max-time 30 "${auth[@]+"${auth[@]}"}" --data-binary @est.b64 \
    -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" \
    -o est.p7 -w '%{http_code}' "$EST_URL/simpleenroll")
  b64d < est.p7 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs -out est-leaf.pem 2>/dev/null
  grep -q "BEGIN CERTIFICATE" est-leaf.pem 2>/dev/null
}
est_issued(){ record_issued est-leaf.pem; info "issued:" "$("$OSSL" x509 -in est-leaf.pem -noout -subject -serial 2>/dev/null | tr '\n' ' ')"; }

est_enroll(){ # $1=CN  -> writes est-leaf.{key,pem}
  hdr "EST (RFC 7030) — enroll a certificate"
  if [ -n "$EST_CLIENT_SKIP" ]; then
    step "EST enroll"; skip "($EST_CLIENT_SKIP)"; return 0
  fi
  local CN="$1"
  # ⚠️ WHAT USED TO BE HERE: `UPDATE certs SET status=-1 WHERE owner='admin' AND status=0`,
  # straight into Postgres, to clear the per-owner cap before enrolling. Against a throwaway
  # database that is merely rude. Against a LIVE deployment — which is now the default
  # — it revokes EVERY certificate the admin owns, silently, as a side effect of
  # running a demo. Deleted. The cap is handled the way he asked for instead: this run
  # revokes what this run issued, at exit, through the product's own API.
  step "requesting a cert via EST simpleenroll for $CN"
  if est_do_enroll "$CN"; then ok; est_issued
    vshow "validating est-leaf.pem (chain + strict + CRL)" est-leaf.pem ok
    return 0
  fi
  if [ "$EST_CODE" != 429 ]; then fail "(EST enroll — HTTP $EST_CODE)"; return 1; fi
  skip "(HTTP 429 — per-owner issuance cap reached, try running --no-acme again)"
}

cmp_enroll(){ # $1=CN [$2=keyspec] [$3=digest] -> writes cmp-leaf.{key,pem}
  # ⚠️ A SKIPPED PRECONDITION MUST NOT SURFACE AS A CLIENT FAILURE. When the RA credential
  # could not be provisioned -- and said so, with a measured reason -- CMP correctly refuses
  # every transaction, and the client reports "missing content type", which names nothing.
  # Measured with --server-key ml-dsa-65 on a host whose token has no ML-DSA: the axis cell
  # announced itself honestly and then the enrolment step FAILED underneath it, so one
  # environment fact produced one skip and one failure describing the same thing.
  if [ -n "${CMP_RA_SKIP:-}" ]; then
    hdr "CMP (RFC 4210) — enroll a certificate"
    step "CMP enroll for ${1:-}"
    skip "(no RA credential for this cell, so CMP refuses every transaction — $CMP_RA_SKIP)" \
      2>/dev/null || printf ' SKIPPED (no RA credential: %s)\n' "$CMP_RA_SKIP"
    return 0
  fi
  hdr "CMP (RFC 4210) — enroll a certificate"
  local CN="$1" kspec="${2:-rsa:2048}" md="${3:-}"
  # ⚠️ THE HASH AXIS REACHES CMP, and until now it did not. mtx_cmp_cell took no digest and
  # cmp_enroll had no way to accept one, so every CMP cell ran with openssl cmp's default
  # sha256 — while the matrix table printed it under sha3-256 AND sha3-512 as a PASS. That
  # is a coverage claim for a digest the wire never carried, and it ran the identical cell
  # twice per (CA, client key) to make it.
  #
  # `-digest` is what openssl cmp calls the digest for "message protection and POPO
  # signatures", so it is the CSR-signature analogue for this protocol.
  local _dg=(); [ -n "$md" ] && _dg=(-digest "$md")
  step "requesting a cert via the CMP client (ir) for $CN"
  # ⚠️ rm BEFORE the run. cmp -certout APPENDS nothing but the success check greps this
  # file — a leftover from a previous cell made a FAILED ir look issued, and the SPKI
  # assertion then judged the previous certificate.
  rm -f cmp-leaf.key cmp-leaf.pem
  gen_client_key "$kspec" cmp-leaf.key || { fail "(local keygen for $kspec failed)"; return 1; }
  if [ -n "$CMP_CONFIG" ] && [ -f "$CMP_CONFIG" ]; then
    # -server: see the note in cmp_identity() — the config names the deployment's public
    # URL, not the route this demo run is using.
    "$OSSL" cmp -cmd ir -implicit_confirm -section cmp,ir -config "$CMP_CONFIG" -server "$CMP_URL" "${_dg[@]+"${_dg[@]}"}" \
      -trusted "$CHAIN" \
      -newkey cmp-leaf.key -subject "/CN=$CN" -certout cmp-leaf.pem >cmp-cli.log 2>&1
  else
    "$OSSL" cmp -cmd ir -implicit_confirm -server "$CMP_URL" "${_dg[@]+"${_dg[@]}"}" \
      -recipient "$CMP_RECIPIENT" \
      -ref "${CMP_REF:-$CN}" -secret "pass:$CMP_SECRET" \
      -trusted "$CHAIN" -keep_alive 0 \
      -newkey cmp-leaf.key -subject "/CN=$CN" -certout cmp-leaf.pem >cmp-cli.log 2>&1
  fi
  if grep -q "BEGIN CERTIFICATE" cmp-leaf.pem 2>/dev/null; then ok
  else
    # One retry at max verbosity so the log names the exact failing step rather than
    # only the last error. The named example this used to give — "error creating
    # certconf" — is unreachable now that every ir asks for implicit confirmation, so
    # do not put it back: it would send a reader after a message this path cannot emit.
    if [ -n "$CMP_CONFIG" ] && [ -f "$CMP_CONFIG" ]; then
      "$OSSL" cmp -cmd ir -implicit_confirm -section cmp,ir -config "$CMP_CONFIG" -server "$CMP_URL" "${_dg[@]+"${_dg[@]}"}" \
        -trusted "$CHAIN" -verbosity 8 \
        -newkey cmp-leaf.key -subject "/CN=$CN" -certout cmp-leaf.pem >>cmp-cli.log 2>&1
    else
      "$OSSL" cmp -cmd ir -implicit_confirm -server "$CMP_URL" -recipient "$CMP_RECIPIENT" "${_dg[@]+"${_dg[@]}"}" \
        -ref "${CMP_REF:-$CN}" -secret "pass:$CMP_SECRET" -trusted "$CHAIN" -keep_alive 0 \
        -verbosity 8 \
        -newkey cmp-leaf.key -subject "/CN=$CN" -certout cmp-leaf.pem >>cmp-cli.log 2>&1
    fi
    # ⚠️ THE VERDICT BELONGS TO THE CALLER, as it already does for est_do_enroll, which sets
    # EST_CODE and returns non-zero without judging. cmp_enroll used to call fail() here, so
    # DEMO_FAIL was incremented before the caller could look — and the matrix, which turns a
    # known local PSS/SHA-3 gap into a SKIP, reported "failed: 0" while the run still exited
    # 1 on a failure it had just excused. Set the code; the three callers report.
    grep -q "BEGIN CERTIFICATE" cmp-leaf.pem 2>/dev/null && { ok; } || { CMP_CODE=ir; return 1; }
  fi
  record_issued cmp-leaf.pem
  info "issued:" "$("$OSSL" x509 -in "$WORK/cmp-leaf.pem" -noout -subject -serial 2>/dev/null | tr '\n' ' ')"
}

ocsp_status(){ # $1=leaf.pem -> prints the real OCSP status word (good/revoked/...)
  # A single query can come back empty on a transient blip (a dropped response, or
  # the responder momentarily busy — e.g. under EST rate-limiting), which would
  # otherwise be shown as a bogus "unknown". Retry briefly until we get a real
  # status word; only report "unavailable" if it genuinely never answers.
  local i st
  for i in 1 2 3 4 5 6; do
    st=$("$OSSL" ocsp -issuer "$ISSUER" -cert "$1" -url "$OCSP_URL" -resp_text -noverify 2>/dev/null \
         | sed -n 's/.*Cert Status: //p' | head -1)
    [ -n "$st" ] && { printf '%s\n' "$st"; return 0; }
    sleep 0.5
  done
  printf 'unavailable\n'
}
ocsp_check(){ # $1=leaf $2=colour $3=label
  hdr "OCSP (RFC 6960) — $3"
  step "checking the CMP certificate's status via OCSP"
  local S; S=$(ocsp_status "$1"); ok
  printf '     %sstatus:%s %s%s%s\n' "$DIM" "$RST" "$2" "$S" "$RST"
}

REVOKE_OK=no
cmp_revoke_and_confirm(){ # $1=CN of the cmp leaf
  hdr "CMP (RFC 4210) — revoke a certificate, then confirm via OCSP"
  # ⚠️ The "throwaway" branch that revoked over an UNPROTECTED request is gone, and
  # with it the last place this demo behaved differently from a real deployment. It only
  # worked because CMP_ACCEPT_UNPROTECTED=true ALSO switched off the rr authorization
  # block, so no owner was enforced. Both modes now take the signature-protected path.
  # Revocation requires SIGNATURE-based protection by a cert whose CN
  # equals the target's owner (self-service authorization). So enroll a
  # short-lived identity cert CN=<owner> (owner comes from -ref at enrollment)
  # and sign the rr with it. NOTE: the openssl client exits non-zero validating
  # the CA-signed response because FastPKI's issuing-CA cert carries only
  # keyCertSign/cRLSign (no digitalSignature) — a cosmetic interop nit — so we
  # judge success by the OCSP status flip, not the client's exit code.
  step "enrolling a CN=$CMP_REF identity cert and revoking (rr, signature-protected)"
  if cmp_identity cmp-id.pem cmp-id.key; then
    cat cmp-id.pem "$ISSUER" > "$WORK/cmp-id-with-chain.pem"
    "$OSSL" cmp -cmd rr -server "$CMP_URL" -recipient "$CMP_RECIPIENT" -trusted "$CHAIN" \
      -cert "$WORK/cmp-id-with-chain.pem" -key cmp-id.key -keep_alive 0 \
      -oldcert cmp-leaf.pem -revreason 1 >cmp-rr.log 2>&1 || true
    "$OSSL" cmp -cmd rr -server "$CMP_URL" -recipient "$CMP_RECIPIENT" -trusted "$CHAIN" \
      -cert "$WORK/cmp-id-with-chain.pem" -key cmp-id.key -keep_alive 0 \
      -oldcert cmp-id.pem -revreason 5 >/dev/null 2>&1 || true
  else
    # ⚠️ SAY WHY, do not guess. This used to report "deployment-gated: set
    # CMP_CLIENT_CA_ID" for EVERY failure of cmp_identity — and it was hit in practice with
    # CMP_CLIENT_CA_ID already set to `sub-ca`, so the demo named a cause that was not
    # true and hid the real one: a malformed `recipient` in the downloaded client
    # config. cmp_identity already writes cmp-id.log; it was simply thrown away.
    #
    # A refusal reported with the wrong cause is worse than an unexplained one: it sends
    # the reader to fix something that is not broken.
    local why=""
    [ -s cmp-id.log ] && why=$(grep -iE 'error|failed|status|unable|no recipient|denied' cmp-id.log \
                               | head -3 | tr '\n' ' ' | cut -c1-300)
    skip "(could not enrol the CN=$CMP_REF identity cert needed to sign the rr)"
    [ -n "$why" ] && info "client said:" "$why"
    info "note:" "cert remains valid. Check in this order: the CMP client config's"
    info ""      "  \`recipient\` is a DN (/CN=...); this user holds a role granting a"
    info ""      "  profile; CMP_CLIENT_CA_ID names a CA on the CMP service."
    info "log:"  "$WORK/cmp-id.log"
    return 0
  fi
  echo
  # ⚠️ DO NOT PRE-JUDGE THE OCSP ANSWER HERE. This used to compute the status and `fail
  # (OCSP status for revoked cert: good); return 1` before the branches below could run,
  # which made every one of them dead code — including the branch that names the actual
  # cause. The rr calls above are `|| true` on purpose (the client exits non-zero on a
  # cosmetic response-validation nit), so a REFUSED rr and a successful one look identical
  # until OCSP is asked, and the only thing that then distinguished them was the branch
  # this line pre-empted.
  #
  # Measured against a live deployment: CMP_CLIENT_CA_ID was unset, so the server refused
  # the signature-protected rr with `no suitable sender cert ... error validating
  # protection`, the certificate was never revoked, and OCSP correctly answered `good`.
  # The demo reported that as an OCSP failure — sending the reader after the one component
  # that was behaving properly, while cmp-rr.log sat unread with the real answer in it.
  step "confirming the CMP leaf was revoked via OCSP"
  if [ "$(ocsp_status cmp-leaf.pem)" = revoked ]; then
    REVOKE_OK=yes; ok
    step "re-checking the CMP certificate's status via OCSP"; local S; S=$(ocsp_status cmp-leaf.pem); ok
    printf '     %sstatus:%s %s%s%s\n' "$DIM" "$RST" "$YEL" "$S" "$RST"
  elif [ -n "$CMP_SECRET" ]; then
    # Live deployment that hasn't enabled self-service CMP revoke.
    skip "(deployment-gated: set CMP_CLIENT_CA_ID=<ca_id> on the CMP service for self-service rr)"
    info "note:" "cert remains valid; CMP self-service revoke is fully shown in --throwaway mode"
  else
    # SAY WHAT THE SERVER SAID. The log is right there and naming the first error line
    # turns "the certificate is still valid" into the reason it is.
    local why; why=$(grep -m1 -iE 'error|refus' "$WORK/cmp-rr.log" 2>/dev/null | cut -c1-90)
    fail "(CMP rr did not revoke${why:+ — $why} — see $WORK/cmp-rr.log)"
  fi
}

scep_enroll(){ # $1=CN [$2=keyspec]
  hdr "SCEP (RFC 8894) — enroll a certificate"
  local CN="$1" kspec="${2:-rsa:2048}" TC="$BIN/scep-testclient"
  if [ ! -x "$TC" ]; then step "SCEP enroll for $CN"; skip "(no scep-testclient in $BIN${SCEP_TC_WHY:+ — $SCEP_TC_WHY})"; return 0; fi
  step "GetCACert + PKCSReq via the SCEP client for $CN"
  curl -s --max-time 30 "$SCEP_URL?operation=GetCACert" -o scep-ca.der
  # RA mode returns a PKCS7 chain; single-CA mode returns a bare cert. Normalise.
  if ! "$OSSL" x509 -inform DER -in scep-ca.der -out scep-ca.pem 2>/dev/null; then
    "$OSSL" pkcs7 -inform DER -in scep-ca.der -print_certs 2>/dev/null | \
      "$OSSL" x509 -out scep-ca.pem 2>/dev/null
  fi
  # A multi-instance deployment may not serve the default CA over SCEP (the bare
  # path returns "unknown CA instance"). If we couldn't fetch a CA cert, the
  # endpoint isn't usable here — skip cleanly rather than fail.
  if ! grep -q "BEGIN CERTIFICATE" scep-ca.pem 2>/dev/null; then
    skip "(deployment-gated: no default CA served over SCEP at $SCEP_URL — register a SCEP CA instance)"
    return 0
  fi
  # Only carry a challengePassword attribute when the deployment sets one — an
  # empty challengePassword makes `openssl req` emit an empty CSR.
  if [ -n "${SCEP_CHALLENGE:-}" ]; then
    printf '[req]\ndistinguished_name=dn\nattributes=attrs\nprompt=no\n[dn]\nCN=%s\n[attrs]\nchallengePassword=%s\n' "$CN" "$SCEP_CHALLENGE" > screq.cnf
  else
    printf '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=%s\n' "$CN" > screq.cnf
  fi
  gen_client_key "$kspec" scep.key || { fail "(local keygen for $kspec failed)"; return 1; }
  "$OSSL" req -new -key scep.key -config screq.cnf -out scep.csr >/dev/null 2>&1
  "$OSSL" req -in scep.csr -outform DER -out scep-csr.der >/dev/null 2>&1
  "$OSSL" req -x509 -key scep.key -subj "/CN=$CN" -days 2 -out scep-self.pem >/dev/null 2>&1
  "$TC" build scep-ca.pem scep-self.pem scep.key scep-csr.der scep-req.der >/dev/null 2>&1
  rm -f scep-resp.der scep-issued.der   # stale pair would mask a failed transaction
  curl -s --max-time 30 -X POST --data-binary @scep-req.der \
    -H "Content-Type: application/x-pki-message" \
    "$SCEP_URL?operation=PKIOperation" -o scep-resp.der
  local ST; ST=$("$TC" parse scep-self.pem scep.key scep-resp.der scep-issued.der 2>/dev/null)
  if [ "$ST" = "pkiStatus=0" ] && "$OSSL" x509 -inform DER -in scep-issued.der -noout -subject >/dev/null 2>&1; then ok
  else fail "(SCEP $ST)"; return 1; fi
  record_issued scep-issued.der der
  info "issued:" "$("$OSSL" x509 -inform DER -in scep-issued.der -noout -subject -serial 2>/dev/null | tr '\n' ' ')"
  "$OSSL" x509 -inform DER -in scep-issued.der -out scep-leaf.pem 2>/dev/null
  vshow "validating scep-leaf.pem (chain + strict + CRL)" scep-leaf.pem ok
}

store_search(){ # $@ = candidate CNs issued this run; retrieves the first one present
  hdr "Certificate store (RFC 4387) — search for a certificate"
  # Try each candidate CN so the step doesn't depend on any single earlier step
  # having run — e.g. EST may be rate-limited (429) and skipped, so fall back to
  # the CMP/SCEP cert. A hit may be a single DER cert (one match) or a PKCS7
  # bundle (several); try the configured path first, then the known alternates.
  local cn p subj="" hit=""
  for cn in "$@"; do
    for p in "$STORE_PATH" /certificates/search /certs/search; do
      [ -n "$p" ] || continue
      curl -s --max-time 20 -o store-hit.bin "$STORE_URL$p?cn=$cn" 2>/dev/null
      [ -s store-hit.bin ] || continue
      subj=$("$OSSL" x509 -inform DER -in store-hit.bin -noout -subject 2>/dev/null | sed 's/^subject= *//')
      [ -z "$subj" ] && subj=$("$OSSL" pkcs7 -inform DER -in store-hit.bin -print_certs 2>/dev/null | sed -n 's/^subject= *//p' | head -1)
      [ -n "$subj" ] && { hit="$cn"; break; }
    done
    [ -n "$subj" ] && break
  done
  step "fetching a certificate from the store by CN=${hit:-$1}"
  if [ -n "$subj" ]; then ok; else fail "(no parseable cert from the store)"; return 1; fi
  info "retrieved:" "$subj"
}

acme_enroll(){ # [CN] [keyspec rsa|ec[:curve]] — certbot dns-01 against the running ACME
  hdr "ACME (RFC 8555) — enroll a certificate (certbot, dns-01)"
  local CN="${1:-acme-demo.internal}" kspec="${2:-}"
  if ! command -v certbot >/dev/null 2>&1; then
    step "ACME enroll for $CN"; skip "(certbot not found — brew install certbot)"; return 0
  fi
  # Which stack are we talking to? Live/compose deployments use the repo compose file on
  # its default project; throwaway runs stage their own file under their own project name
  # and publish the ACME port high. One resolution, used for every docker/curl below.
  local cfile="$ROOT/deploy/docker-compose.yml" proj_args=() net="fastpki_default"
  # ⚠️ TWO STATEMENTS, NOT ONE `local`. A `local a=$1 b=${a}` expands its arguments BEFORE
  # the builtin assigns any of them, so `${acme_port}` here is unbound — and under `set -u`
  # that aborts the whole demo, not just this cell. It only fires when ACME_DIR is unset,
  # because `${ACME_DIR:-...}` does not evaluate its default otherwise: --target descriptors
  # set it, so this survived every live run and killed every throwaway one.
  local acme_port="${ACME_PORT:-8444}"
  local acme_dir="${ACME_DIR:-https://localhost:${acme_port}/acme/${CA_ID:-sub-ca}/directory}"
  if [ -n "${DEMO_PROJ:-}" ]; then
    cfile="$DEMO_COMPOSE_FILE"; proj_args=(-p "$DEMO_PROJ"); net="${DEMO_PROJ}_default"
  fi
  # certbot's key-type axis: exactly two spellings exist (RFC 8555 leaves key choice to
  # the account/order; certbot exposes rsa|ecdsa). Its curve names are its own dialect —
  # secp256r1, NOT P-256 — and an unrecognised choice aborts at argparse before any
  # network traffic, which reads as "ACME broken" rather than "wrong flag spelling".
  local ktargs=()
  case "$kspec" in
    "") ;;
    rsa|rsa:*)   ktargs=(--key-type rsa);;
    ec|ec:*)     case "${kspec#*:}" in
                   P-384) ktargs=(--key-type ecdsa --elliptic-curve secp384r1);;
                   P-521) ktargs=(--key-type ecdsa --elliptic-curve secp521r1);;
                   *)     ktargs=(--key-type ecdsa --elliptic-curve secp256r1);;
                 esac;;
    *) step "ACME enroll with client key $kspec"; skip "(certbot offers only rsa|ecdsa client keys)"; return 0;;
  esac

  # ⚠️ REMOTE RUNS THE SAME RESOLVER IN THE SAME PLACE — beside the ACME service. Locally
  # that is a CoreDNS container on the compose network; remotely it is a CoreDNS container
  # on the deployment's network, started over SSH by dns-auth.sh. Neither expects anything
  # to reach back to this machine, which is why this needs no inbound port, no reachable
  # name for the demo host, and no Docker here. This cell used to skip outright, describing
  # the local wiring as if it were the challenge's limit.
  # ⚠️ WHERE THE RESOLVER RUNS IS NOT THE SAME QUESTION AS WHERE THE CONFIG IS WRITTEN.
  # dns-auth.sh starts CoreDNS ON the deployment when DNS_SSH_TARGET is set, which needs
  # docker there; a native node has none, so for that shape the resolver stays here and
  # DNS_PUBLISH exposes its port for the deployment to reach instead. The config write and
  # the acme restart still go over ssh either way — that is dns_remote, set below.
  local dns_ssh_t="" dns_pub=""
  local dns_remote=""
  if ! docker compose ${proj_args[@]+"${proj_args[@]}"} -f "$cfile" ps --status running 2>/dev/null | grep -q 'acme.*Up'; then
    # ⚠️ A CLUSTER HAS NO SSH TARGET AND STILL HAS AN ADMINISTRATIVE CHANNEL. This gate
    # asked only for SSH_TARGET, so every Kubernetes run skipped here describing the
    # compose wiring as if it were the challenge's limit — the same mistake the comment
    # above records, one layer up. K8S_NAMESPACE is the cluster's equivalent.
    # ⚠️ CHALLENGE_FQDN IS ONLY THE NATIVE SHAPE'S REQUIREMENT, and demanding it from every
    # shape made this cell skip on a cluster where the WILDCARD dns-01 cell — same mechanism,
    # a few lines down — succeeded. Compose and Kubernetes run CoreDNS BESIDE the ACME
    # service, so the query never leaves that machine and nothing has to reach back here.
    # Only a native target keeps the resolver on this host and has the deployment dial it,
    # which is what needs a name that resolves to here. demo_acme_dns_resolver_remote()
    # already gates it exactly that way; this gate did not, and the two disagreed.
    if { [ -n "${SSH_TARGET:-}" ] || [ -n "${K8S_NAMESPACE:-}" ]; } &&
       { [ "${DEPLOY_MODE:-}" != native ] || [ -n "${CHALLENGE_FQDN:-}" ]; }; then
      dns_remote=1
      # Native keeps the resolver here and publishes its port; the other two run it beside
      # the ACME service, where nothing has to reach back.
      if [ "${DEPLOY_MODE:-}" = native ]; then dns_pub=1; else dns_ssh_t="${SSH_TARGET:-}"; fi
    else
      step "ACME enroll for $CN"
      skip "(no local ACME stack, and the descriptor carries no SSH_TARGET/K8S_NAMESPACE + CHALLENGE_FQDN to repoint a remote one — re-run provision-target.sh)"
      return 0
    fi
  fi

  step "running certbot dns-01 against the ACME service for $CN${kspec:+ (client key $kspec)}"
  local dns_name="fastpki-dns" rc=0

  docker rm -f "$dns_name" 2>/dev/null || true

  # CoreDNS container on the compose network.  dns-auth.sh will restart it with
  # the certbot dns-01 TXT value each time (Corefile rewrite + docker restart).
  local coredns_dir="$ROOT/demo/coredns"
  mkdir -p "$coredns_dir"

  cat > "$coredns_dir/Corefile" <<COREDNS
$CN.:15353 {
    log
    template IN TXT _acme-challenge.$CN {
        answer "{{ .Name }} 60 IN TXT \\"placeholder\\""
    }
}
COREDNS

  if [ -n "$dns_remote" ]; then
    # Nothing to start HERE: dns-auth.sh runs CoreDNS on the deployment, beside the acme
    # service, when certbot calls it with the challenge value. All this does is tell that
    # service to ask it — the name resolves on the deployment's own docker network.
    if ! demo_acme_dns_resolver_remote "$DEMO_DNSP"; then return 0; fi
  else
    docker run -d --rm --name "$dns_name" --network "$net" \
      -v "$coredns_dir:/config" \
      coredns/coredns -conf /config/Corefile >/dev/null 2>&1
    sleep 3
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$dns_name" \
      || { fail "(CoreDNS did not start on $net)"; return 1; }

    # ⚠️ NAME THE CONTAINER, DO NOT CAPTURE ITS ADDRESS. dns-auth.sh REPLACES this
    # container on every challenge, and the replacement does not keep the address this one
    # holds — so an IP read here is a value that can stop being true before the server ever
    # uses it, and the query that goes to the old address is reported as
    #     dns-01 TXT record missing or mismatched
    # i.e. as a challenge fault rather than a resolver aimed at nothing. Docker's embedded
    # DNS resolves the name on this network at query time, which is what the remote and
    # wildcard paths already rely on.
    export ACME_DNS_RESOLVER="${dns_name}:$DEMO_DNSP"
    docker compose ${proj_args[@]+"${proj_args[@]}"} -f "$cfile" --profile acme up -d --no-deps acme >/dev/null 2>&1
    unset ACME_DNS_RESOLVER
  fi
  for _ in $(seq 1 20); do
    sleep 1
    curl -sk "$acme_dir" >/dev/null 2>&1 && break
  done

  local -a eab_args=()
  if [ -n "${ACME_EAB_KID:-}" ] && [ -n "${ACME_EAB_HMAC:-}" ]; then
    # ⚠️ `=` FORM, NOT A SEPARATE ARGUMENT. base64url maps '+' to '-', so about one
    # secret in 64 begins with one and certbot's argparse reads it as the next OPTION:
    # "argument --eab-hmac-key: expected one argument" -- the same message an EMPTY value
    # gives, which is why it does not read as a value problem. tests/acme_jws.sh re-rolls
    # to dodge it; the demo cannot, because this secret is the user's real credential.
    eab_args=(--eab-kid="$ACME_EAB_KID" --eab-hmac-key="$ACME_EAB_HMAC")
  fi
  # The hooks recreate the resolver container on the same network; DNS_NET is how a
  # throwaway project's network reaches them without hard-coding fastpki_default.
  # ⚠️ ACME_TLS_BUNDLE, not CHAIN. The TLS identity of the ACME LISTENER belongs to the
  # deployment's default CA and does not change when a matrix slice sweeps another CA;
  # the swept CA only changes the /acme/<ca_id>/ route. Verifying the listener against
  # the swept chain is what made every per-CA cell die with "unable to get local issuer
  # certificate" before any ACME traffic happened. The ISSUED cert is still validated
  # against the swept chain below (vshow → validate_cert), as everywhere else.
  REQUESTS_CA_BUNDLE="${ACME_TLS_BUNDLE:-$CHAIN}" ROOT="$ROOT" ZONE_DIR="$coredns_dir" \
    DNS_NET="$net" DNS_SSH_TARGET="$dns_ssh_t" DNS_PUBLISH="$dns_pub" \
    DNS_PORT="$DEMO_DNSP" DNS_K8S_NAMESPACE="${K8S_NAMESPACE:-}" \
    DNS_SSH_OPTS="${DEMO_SSH_OPTS[*]}" certbot certonly \
    --manual --preferred-challenges dns \
    --manual-auth-hook "$ROOT/demo/dns-auth.sh" \
    --manual-cleanup-hook "$ROOT/demo/dns-cleanup.sh" \
    --server "$acme_dir" \
    -d "$CN" --agree-tos --non-interactive --register-unsafely-without-email \
    ${ACME_FORCE:+--force-renewal} \
    "${eab_args[@]+"${eab_args[@]}"}" "${ktargs[@]+"${ktargs[@]}"}" \
    --work-dir "$WORK/certbot-work" --logs-dir "$WORK/certbot-logs" --config-dir "$WORK/certbot-config" \
    >acme-cli.log 2>&1
  certbot_rc=$?

  # Restore ACME without the DNS resolver — locally by recreating the service without the
  # override, remotely by putting the config key back and restarting over SSH. Both run
  # whatever certbot did, so a failed order cannot leave the deployment repointed.
  if [ -n "$dns_remote" ]; then
    demo_undo_remote_dns
  else
    docker compose ${proj_args[@]+"${proj_args[@]}"} -f "$cfile" --profile acme up -d --no-deps acme >/dev/null 2>&1
  fi
  docker stop "$dns_name" 2>/dev/null || true

  if [ $certbot_rc -eq 0 ]; then ok
    local cert_path="$WORK/certbot-config/live/$CN/cert.pem"
    if [ -f "$cert_path" ]; then
      record_issued "$cert_path"
      info "issued:" "$("$OSSL" x509 -in "$cert_path" -noout -subject -serial 2>/dev/null | tr '\n' ' ')"
      # An order completing is not a certificate being any good: check what the
      # other protocols are held to as well (chain + strict + CRL), or an ACME
      # section could pass all day while issuing something no client accepts.
      vshow "validating the ACME cert (chain + strict + CRL)" "$cert_path" ok
    fi
  else fail "(certbot — see $WORK/acme-cli.log)"; rc=1; fi
  return $rc
}

# Sweep C/D variants of the enrolments above. Same wire flows, but the caller has already
# made (or pre-digested) the client material, so these take files instead of specs.

scep_enroll_hashed(){ # <CN> <key.pem> <md> [keyspec] — PKCSReq over a CSR signed with $3
  hdr "SCEP (RFC 8894) — CSR signed with $3"
  local CN="$1" TC="$BIN/scep-testclient"
  # ⚠️ THE SAME GUARD scep_enroll() HAS. Without it a missing client is not a skip: `$TC
  # build` fails silently, curl is then handed a request file that was never written and
  # prints its own error into the transcript, and the failure path below reads an argument
  # the three-argument caller does not pass — aborting the whole run under `set -u`.
  [ -x "$TC" ] || { step "SCEP CSR signed with $3"; skip "(no scep-testclient in $BIN${SCEP_TC_WHY:+ — $SCEP_TC_WHY})"; return 0; }
  cp "$2" scep.key
  # The CSR is built HERE, not accepted from the caller, because the challengePassword
  # attribute must be present at req time — a CSR without it is rejected (pkiStatus=2)
  # no matter how it was signed. The digest applies to the SIGNATURE; the attribute
  # travels alongside it.
  if [ -n "${SCEP_CHALLENGE:-}" ]; then
    printf '[req]\ndistinguished_name=dn\nattributes=attrs\nprompt=no\n[dn]\nCN=%s\n[attrs]\nchallengePassword=%s\n' "$CN" "$SCEP_CHALLENGE" > screq.cnf
  else
    printf '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=%s\n' "$CN" > screq.cnf
  fi
  # skip, not fail: the EST/CMP cells of the same sweep degrade identically when the
  # local openssl cannot produce the requested signature (e.g. SHAKE on an RSA key),
  # and one protocol announcing FAIL for what is a host capability would read as a
  # server-side defect.
  "$OSSL" req -new -key scep.key -config screq.cnf "-$3" -out scep.csr >/dev/null 2>&1 \
    || { skip "(this openssl cannot sign a CSR with $3)"; return 1; }
  "$OSSL" req -in scep.csr -outform DER -out scep-csr.der >/dev/null 2>&1
  "$OSSL" req -x509 -key scep.key -subj "/CN=$CN" -days 2 -out scep-self.pem >/dev/null 2>&1
  curl -s --max-time 30 "$SCEP_URL?operation=GetCACert" -o scep-ca.der
  if ! "$OSSL" x509 -inform DER -in scep-ca.der -out scep-ca.pem 2>/dev/null; then
    "$OSSL" pkcs7 -inform DER -in scep-ca.der -print_certs 2>/dev/null | "$OSSL" x509 -out scep-ca.pem 2>/dev/null
  fi
  grep -q "BEGIN CERTIFICATE" scep-ca.pem 2>/dev/null || { skip "(no default CA served over SCEP at $SCEP_URL)"; return 0; }
  "$TC" build scep-ca.pem scep-self.pem scep.key scep-csr.der scep-req.der >/dev/null 2>&1
  rm -f scep-resp.der scep-issued.der   # stale pair would mask a failed transaction
  curl -s --max-time 30 -X POST --data-binary @scep-req.der \
    -H "Content-Type: application/x-pki-message" \
    "$SCEP_URL?operation=PKIOperation" -o scep-resp.der
  local ST; ST=$("$TC" parse scep-self.pem scep.key scep-resp.der scep-issued.der 2>/dev/null)
  if [ "$ST" = "pkiStatus=0" ]; then ok; record_issued scep-issued.der der
  else fail "(SCEP CSR/${4:-$3} → $ST)"; return 1; fi
}

acme_enroll_keyed(){ # <spec> — the dns-01 order with a chosen client key type
  acme_enroll "swac-${1//:/-}.$DEMO_DOMAIN" "$1"
}

# ── the five sweeps ──────────────────────────────────────────────────────────
# Throwaway mode IS the matrix: one fresh stack, then these sweeps over it, each varying
# ONE axis against defaults elsewhere. A full cross-product is thousands of cells;
# sequential sweeps cover every dimension in ~40 and keep a run inside minutes.
#
# Shared shape: every cell is step/ok/fail/skip like the baseline pass, so DEMO_FAIL
# counts them identically, and every issued certificate is recorded so cleanup revokes
# it — a sweep must not leave the deployment more provisioned than it found it.

# SWEEP A — CA signing keys. One CA per key type, created through fastpki-ca with the
# key minted in-token (--keygen), probed by issuing one certificate from it through the
# console and verifying that chain, then disabled. They are NOT deleted: delete refuses
# once a CA has signed anything (the anti-orphaning guard), which is the product's own
# rule about CA lifecycle and exactly what a demo should obey.
sweep_ca_keys(){
  [ -n "$CA_KEYS" ] || return 0
  hdr "Sweep A — CA signing keys"
  local spec n=0 idc crt probe
  for spec in $CA_KEYS; do
    n=$((n+1)); idc="demo-ca-a$n"
    step "CA $idc keyed $spec"
    spec_cli_args "$spec"
    # ⚠️ --out-dir /tmp, NOT THE DEFAULT. The container runs as the unprivileged fastpki
    # user and /app (the image's WORKDIR) is root-owned, so the default relative
    # ca-instances/ is unwritable and every create died on its last step with EACCES —
    # AFTER minting the token key. /tmp is world-writable and per-exec disposable.
    if ! compose_exec fastpki-ca --config "$CONF_IN_CONTAINER" create "$idc" \
          --name "$idc" --subject "/CN=FastPKI Sweep CA $n" \
          --ca-key "pkcs11:token=fastpki;object=$idc;type=private?pin-source=/var/pki/tls/pin" \
          --keygen --out-dir /tmp "${CLI_KEY_ARGS[@]+"${CLI_KEY_ARGS[@]}"}" >"$WORK/ca-a$n.log" 2>&1; then
      # The token refused to mint this key type (SoftHSM build without ML-DSA/Ed448,
      # say) is an environment fact about THAT cell, not a product failure — but it
      # must be announced as a skip naming the cause, never silently dropped.
      skip "(keygen refused: $(head -c 160 "$WORK/ca-a$n.log" | tr '\n' ' '))"
      continue
    fi
    ok
    crt="$WORK/$idc.crt"; compose_exec cat "/tmp/$idc.crt" > "$crt" 2>/dev/null
    step "$idc SPKI matches $spec"
    assert_spki "$crt" "$spec" "$idc" && ok || true
    # Probe issuance THROUGH the new CA: request-hsm mints the key in-token and signs
    # with the swept CA key, so this exercises the exact signing path a real deployment
    # would use with such a root.
    step "issuing a probe cert from $idc via the console API"
    probe="$WORK/probe-$n.pem"
    api_issue_hsm_cert "probe-$idc" "probe$n.$DEMO_DOMAIN" \
        "pkcs11:token=fastpki;object=probe-$idc;type=private?pin-source=/var/pki/tls/pin" \
        digitalSignature "" "$probe" --data-urlencode ca_instance="$idc" \
        && "$OSSL" verify -CAfile "$crt" "$probe" >/dev/null 2>&1 \
      && { ok; record_issued "$probe"; } \
      || fail "(console could not issue from $idc)"
    compose_exec fastpki-ca --config "$CONF_IN_CONTAINER" disable "$idc" >/dev/null 2>&1
  done
}

# SWEEP B — server credential keys. Re-keys the transport credentials (web/est/acme/ms)
# and the CMP/OCSP(/SCEP) RA credentials, then holds every served certificate to the
# spec. A re-key here means: mint a FRESH token object under a NEW label, issue the
# certificate on it, and let request-hsm's rekey=1 repoint the *_KEY setting — re-minting
# under the SAME label would leave two keypairs with one label, and token lookups are
# by label. Every protocol service restarts afterwards: listeners load key+cert at
# startup, and although CMP resolves its RA CERTIFICATE per transaction, its RA KEY URI
# is startup config like everyone else's. TLS cannot carry ML-DSA (no RFC 8446 code
# point) and SCEP's envelope is RSA-only: announced skips.
sweep_server_keys(){
  [ -n "$SERVER_KEYS" ] || return 0
  hdr "Sweep B — server credential keys"
  local spec saved_key="$SERVER_KEY" n=0 pin_q="?pin-source=/var/pki/tls/pin"
  tok(){ printf 'pkcs11:token=fastpki;object=%s;type=private%s' "$1" "$pin_q"; }
  for spec in $SERVER_KEYS; do
    n=$((n+1)); SERVER_KEY="$spec"   # every show/assert helper reads this global
    hdr "Sweep B iteration — server credentials keyed $spec"
    local svc
    spec_api_args "$spec"   # API_KEY_ARGS for every issuance in this iteration
    if tls_can_carry; then
      for svc in est acme ms web; do
        api_issue_hsm_cert "$svc" localhost "$(tok "$svc-tls-b$n")" \
            digitalSignature,keyEncipherment serverAuth \
            "$WORK/.rk-$svc.pem" \
          --data-urlencode "sans=localhost" \
            "${API_KEY_ARGS[@]+"${API_KEY_ARGS[@]}"}" --data-urlencode keygen=true --data-urlencode rekey=true \
          || { fail "(re-key of the $svc listener credential)"; SERVER_KEY="$saved_key"; return 1; }
      done
    else
      step "TLS listener credentials"
      skip "($(tls_skip_reason)) — measured on the RA credentials instead"
    fi
    # The RAs have no TLS restriction; this is where an ML-DSA axis cell is measured.
    api_issue_hsm_cert "cmp-ra-$CA_ID" "cmp-ra.$DEMO_DOMAIN" "$(tok "cmp-ra-b$n")" \
        digitalSignature 1.3.6.1.5.5.7.3.28 "$WORK/.cmpra.pem" \
        "${API_KEY_ARGS[@]+"${API_KEY_ARGS[@]}"}" --data-urlencode keygen=true --data-urlencode rekey=true \
      || { fail "(cmp-ra re-key)"; SERVER_KEY="$saved_key"; return 1; }
    api_issue_hsm_cert "ocsp-ra-$CA_ID" "ocsp-ra.$DEMO_DOMAIN" "$(tok "ocsp-ra-b$n")" \
        digitalSignature 1.3.6.1.5.5.7.3.9 "$WORK/ocsp-ra.pem" \
        "${API_KEY_ARGS[@]+"${API_KEY_ARGS[@]}"}" --data-urlencode keygen=true --data-urlencode rekey=true \
        --data-urlencode omit_aia=true --data-urlencode omit_crldp=true \
      || { fail "(ocsp-ra re-key)"; SERVER_KEY="$saved_key"; return 1; }
    scep_ra_gate   # sets SCEP_RA_SKIP when this spec is not RSA
    if [ -z "${SCEP_RA_SKIP:-}" ]; then
      api_issue_hsm_cert "scep-ra-$CA_ID" "scep-ra.$DEMO_DOMAIN" "$(tok "scep-ra-b$n")" \
          digitalSignature,keyEncipherment 1.3.6.1.4.1.311.20.2.1 "$WORK/.scepra.pem" \
          "${API_KEY_ARGS[@]+"${API_KEY_ARGS[@]}"}" --data-urlencode keygen=true --data-urlencode rekey=true \
        || { fail "(scep-ra re-key)"; SERVER_KEY="$saved_key"; return 1; }
    else
      step "SCEP RA credential"
      skip "($SCEP_RA_SKIP)"
    fi
    unset SCEP_RA_SKIP
    step "restarting the services that cache credentials at startup"
    # ⚠️ CMP IS ON THIS LIST. Only its CERTIFICATE row is resolved per transaction; the
    # KEY URI (CMP_RA_KEY) is config read at startup — so a re-key without a restart left
    # the process signing with the OLD token object while resolving the NEW certificate
    # row, every transaction 500'd, and the client saw "missing content type". Measured,
    # then healed by the next unrelated cmp restart — which is what made it look random.
    dcp restart ocsp scep cmp est acme ms web >>"$WORK/compose-restart.log" 2>&1 \
      || { fail "(docker compose restart failed — see $WORK/compose-restart.log)"; SERVER_KEY="$saved_key"; return 1; }
    local p
    for p in "$DEMO_OCSP_PORT" "$DEMO_CMP_PORT" "$DEMO_EST_PORT" "$DEMO_ACME_PORT" \
             "$DEMO_MS_PORT" "$DEMO_WEB_PORT"; do
      wait_tcp "$p" 100 || { fail "(listener on :$p did not come back)"; SERVER_KEY="$saved_key"; return 1; }
    done
    sleep 2   # TLS handshakes race the first accept after listen()
    ok
    # What each actually serves NOW — the same assertions the baseline pass makes, so a
    # green line here means exactly what it meant there.
    server_key_show
    tls_listener_show "web console" "${WEB_HOSTPORT:-}" web
    tls_listener_show "MS"          "${MS_HOSTPORT:-}"  ms
    ocsp_key_show
    cmp_ra_key_show
    scep_key_show
    # And a client still enrols against the re-keyed stack.
    step "EST smoke enroll against the re-keyed stack"
    if est_do_enroll "swpb$n.$DEMO_DOMAIN" rsa:2048; then ok; est_issued
    elif [ "${EST_CODE:-}" = 429 ]; then skip "(HTTP 429 — per-owner cap reached)"
    else fail "(EST HTTP ${EST_CODE:-?})"; fi
  done
  SERVER_KEY="$saved_key"
}

# SWEEP C — client key types per protocol. Purely client-side: no server state changes,
# so every cell is just an enrollment whose ISSUED certificate is held to the requested
# spec. EST/CMP take everything; SCEP's message layer and ACME/certbot are RSA/EC only,
# so their lists are filtered to what they can ask for.
sweep_client_keys(){
  [ -n "$CLIENT_KEYS$PROTOCOLS" ] || return 0
  hdr "Sweep C — client key types per protocol"
  local proto spec list cn pem
  for proto in $PROTOCOLS; do
    case "$proto" in
      est|cmp) list="$CLIENT_KEYS";;
      scep)    list="rsa ec";;
      acme)    list="rsa ec:P-256";;
      *) continue;;
    esac
    for spec in $list; do
      case "$proto" in
        est)  cn="swpc-$spec.$DEMO_DOMAIN"; cn=${cn//:/-}
              step "EST enroll with client key $spec"
              if gen_client_key "$spec" sw.key 2>/dev/null && make_csr sw.key "$cn" "" sw.csr; then
                if est_do_enroll "$cn" "$spec"; then
                  if assert_spki "$WORK/est-leaf.pem" "$spec" "est/$spec"; then ok; est_issued; fi
                elif [ "$EST_CODE" = 429 ]; then skip "(HTTP 429 — per-owner cap reached)"
                else fail "(EST $spec — HTTP ${EST_CODE:-?})"; fi
              else skip "(this openssl cannot generate $spec locally)"; fi;;
        cmp)  cn="cwpc-$spec.$DEMO_DOMAIN"; cn=${cn//:/-}
              step "CMP enroll with client key $spec"
              if ! gen_client_key "$spec" sw.key 2>/dev/null; then skip "(this openssl cannot generate $spec locally)"
              else
                if cmp_enroll "$cn" "$spec" && assert_spki "$WORK/cmp-leaf.pem" "$spec" "cmp/$spec"; then
                  vshow "validating cmp-leaf.pem (chain + strict + CRL)" cmp-leaf.pem ok
                elif [ "${CMP_CODE:-}" = ir ]; then
                  fail "(CMP ir with $spec — see $WORK/cmp-cli.log)"
                fi
              fi;;
        scep) cn="sspc-$spec.$DEMO_DOMAIN"
              step "SCEP enroll with client key $spec"
              if ! gen_client_key "$spec" sw.key 2>/dev/null; then
                skip "(this openssl cannot generate $spec locally)"
              elif ! scep_enroll "$cn" "$spec"; then :   # scep_enroll already reported it
              else
                "$OSSL" x509 -inform DER -in scep-issued.der -out sw-scep.pem 2>/dev/null \
                  && assert_spki sw-scep.pem "$spec" "scep/$spec" \
                  && vshow "validating sw-scep.pem (chain + strict + CRL)" sw-scep.pem ok || true
              fi;;
        acme) step "ACME enroll with client key $spec"
              acme_enroll_keyed "$spec" || true;;
      esac
    done
  done
}

# SWEEP D — hashes, both halves. Client half: CSRs for EST/CMP/SCEP signed under each
# digest (the CA re-signs the TBS at issuance, so the assertion is acceptance + issue).
# Server half: OCSP/CMP response digests via config rows + restart, verified by a real
# status query / transaction afterwards. Ed25519/ML-DSA have no digest choice ("pure"),
# so they appear only in Sweep C.
sweep_hashes(){
  [ -n "$HASHES$RESPONSE_MDS" ] || return 0
  hdr "Sweep D — signature digests"
  local md cn
  for md in $HASHES; do
    for cn_p in est cmp scep; do
      case "$PROTOCOLS" in *"$cn_p"*) ;; *) continue;; esac
      case "$cn_p" in
        est)  step "EST CSR signed with $md"
              if gen_client_key rsa:2048 sw.key && make_csr sw.key "sh-$md.$DEMO_DOMAIN" "$md" sw.csr; then
                if est_do_enroll "sh-$md.$DEMO_DOMAIN" rsa:2048 "$md"; then ok; est_issued
                elif [ "$EST_CODE" = 429 ]; then skip "(HTTP 429 — per-owner cap reached)"
                else fail "(EST $md — HTTP ${EST_CODE:-?})"; fi
              else skip "(this openssl cannot sign a CSR with $md)"; fi;;
        cmp)  step "CMP CSR signed with $md"
              if [ -z "${CMP_SECRET:-}" ]; then skip "(no CMP credential for ${DEMO_USER:-this user})"
              elif gen_client_key rsa:2048 sw.key && make_csr sw.key "shc-$md.$DEMO_DOMAIN" "$md" sw.csr; then
                "$OSSL" cmp -cmd ir -implicit_confirm -server "$CMP_URL" -recipient "$CMP_RECIPIENT" -digest "$md" \
                  -ref "${CMP_REF:-demo}" -secret "pass:$CMP_SECRET" -trusted "$CHAIN" -keep_alive 0 \
                  -newkey sw.key -subject "/CN=shc-$md.$DEMO_DOMAIN" -certout sh-md.pem >cmp-md.log 2>&1 \
                  && grep -q "BEGIN CERTIFICATE" sh-md.pem 2>/dev/null \
                  && { ok; record_issued "$WORK/sh-md.pem";
                       vshow "validating sh-md.pem (chain + strict + CRL)" "$WORK/sh-md.pem" ok; } \
                  || fail "(CMP ir with $md — see $WORK/cmp-md.log)"
              else skip "(this openssl cannot sign a CSR with $md)"; fi;;
        scep) step "SCEP CSR signed with $md"
              if gen_client_key rsa:2048 sw.key; then
                scep_enroll_hashed "shs-$md.$DEMO_DOMAIN" sw.key "$md" \
                  && { "$OSSL" x509 -inform DER -in scep-issued.der -out sh-scep.pem 2>/dev/null \
                       && vshow "validating sh-scep.pem (chain + strict + CRL)" sh-scep.pem ok; } || true
              else skip "(this openssl cannot generate a key locally)"; fi;;
      esac
    done
  done
  # Server response digests. The OCSP probe needs any certificate the run holds;
  # the CMP transaction needs an enrolment credential — without one, announce it.
  local probe=""
  [ -s "$WORK/cmp-leaf.pem" ] && probe="$WORK/cmp-leaf.pem"
  [ -z "$probe" ] && [ -s "$WORK/est-leaf.pem" ] && probe="$WORK/est-leaf.pem"
  for md in $RESPONSE_MDS; do
    step "OCSP responses under OCSP_RESPONSE_MD=$md"
    if [ -z "$probe" ]; then
      skip "(no client certificate from this run to query with)"
    else
      compose_exec fastpki-config --config "$CONF_IN_CONTAINER" set OCSP_RESPONSE_MD "$md" >/dev/null 2>&1 \
        && dcp restart ocsp >>"$WORK/compose-restart.log" 2>&1 && wait_tcp "$DEMO_OCSP_PORT" 100 \
        || { fail "(could not apply OCSP_RESPONSE_MD=$md)"; continue; }
      sleep 1
      local st; st=$(ocsp_status "$probe")
      case "$st" in good|revoked) ok;; *) fail "(no verifiable OCSP answer under $md: '$st')";; esac
    fi
    step "CMP transaction under CMP_RESPONSE_MD=$md"
    if [ -z "${CMP_SECRET:-}" ]; then
      skip "(no CMP credential for ${DEMO_USER:-this user} — a role that enrols gets one at first login)"
      continue
    fi
    compose_exec fastpki-config --config "$CONF_IN_CONTAINER" set CMP_RESPONSE_MD "$md" >/dev/null 2>&1 \
      && dcp restart cmp >>"$WORK/compose-restart.log" 2>&1 && wait_tcp "$DEMO_CMP_PORT" 100 \
      || { fail "(could not apply CMP_RESPONSE_MD=$md)"; continue; }
    sleep 1
    if cmp_identity "$WORK/sh-cmp-id.pem" "$WORK/sh-cmp-id.key"; then
      ok; record_issued "$WORK/sh-cmp-id.pem"
    else fail "(CMP ir refused under response MD $md — see $WORK/cmp-id.log)"; fi
  done
}

# ── a self-test hook, before anything is stood up ────────────────────────────
#
# Every definition above has now been executed, and nothing below this line has run. So
# this is the one point where "which functions does this script actually define" can be
# asked and answered honestly. tests/demo_functions_toplevel.sh asks it, because a
# definition nested inside another function still LOOKS top-level in the file and only
# exists once its host has been called -- see the ⚠️ above ocsp_key_show.
if [ -n "${FASTPKI_DEMO_DEFS_ONLY:-}" ]; then declare -F | awk '{print $3}'; exit 0; fi

# ── run ──────────────────────────────────────────────────────────────────────
if [ "$MODE" = throwaway ]; then setup_throwaway; else setup_live; fi

# ⚠️ THE DOMAIN COMES FROM THE TARGET, not from this script. These names used to be
# hardcoded `*.internal`, so on any deployment whose allowed_domains lacks `internal`
# every issuance step was refused on policy — correctly, and with a clear message, but
# the demo was asking for a name that deployment does not serve. provision-target.sh now
# reads /api/domains and writes DEMO_DOMAIN; `internal` remains the default because that
# is what the throwaway stack seeds for itself.
server_key_show   # what the EST listener actually presents, before any client touches it
tls_listener_show "web console" "${WEB_HOSTPORT:-}" web   # the second TLS service
tls_listener_show "MS"          "${MS_HOSTPORT:-}"  ms    # and the third
ocsp_key_show     # and what the OCSP responder was actually given — same axis, no TLS
cmp_ra_key_show   # and the CMP RA credential, which is CMP's server-side key
scep_key_show     # and SCEP's, asked of the server over the wire via GetCACert
DEMO_DOMAIN="${DEMO_DOMAIN:-internal}"
CN=est-client.$DEMO_DOMAIN
CCN=cmp-client.$DEMO_DOMAIN
est_enroll   "$CN"
cmp_enroll   "$CCN" || fail "(CMP ir — see $WORK/cmp-cli.log)"
vshow        "validating cmp-client cert (chain + strict + CRL)" cmp-leaf.pem ok
ocsp_check   cmp-leaf.pem "$GRN" "check certificate status (good)"
cmp_revoke_and_confirm "$CCN"
scep_enroll  scep-client.$DEMO_DOMAIN
# Retrieve whatever was reliably issued this run (SCEP first — issued and not
# revoked; then CMP, then EST which may be 429-skipped), so the store step never
# depends on a single earlier protocol having succeeded.
store_search scep-client.$DEMO_DOMAIN "$CCN" "$CN"

# ── Every TLS listener serves a CA-issued cert whose CRL actually checks ──────────
#
# The demo must verify the endpoints' TLS certificates with CRL checks:
#
#   openssl s_client -servername $PKI_DNS -CAfile <root.pem> -CApath <crl-dir> \
#           -x509_strict -crl_check_all $PKI_DNS:<ENDPOINT_PORT>
#
# where <crl-dir> is built by crl_capath from the CRL DPs in the served chain. See the
# block above that function for why the CRLs are staged rather than fetched inline with
# -crl_download: on OpenSSL 3.5 that combination cannot pass, because -crl_check_all
# demands a CRL for the self-signed root and a root has no CRL DP to fetch one from.
#
# This proves three separate things a plain enrolment step never touches:
#   * the listener is serving a CA-ISSUED certificate, not the temporary self-signed one
#     it boots with — a chain that verifies against the deployment's own root;
#   * -x509_strict holds the whole chain to strict RFC 5280, so a malformed extension on
#     the CA or the leaf fails here rather than in some customer's client;
#   * the staged CRLs come from the certificates' OWN CRLDP pointers and -crl_check_all
#     applies them to every element of the chain. That is an end-to-end test of the URL
#     we bake in at issuance: if the port or path in CRLDP is wrong, or the CRL is
#     unreachable, or it is signed by the wrong key, this fails. Nothing else in the demo
#     reads a CRLDP back out of a certificate and uses it.
#
# ⚠️ ONLY FOUR LISTENERS SPEAK TLS. EST, ACME and MS are HTTPS-only, and so is the console;
# OCSP, CMP, SCEP and the store are plain HTTP behind the operator's own proxy. Pointing s_client at the CMP port would fail on a correctly configured deployment
# and read as a product bug, so the plain-HTTP four are named and skipped, not probed.
# ── the full factorial ───────────────────────────────────────────────────────
# --full-matrix replaces the OFAT sweeps with the cross-product the sweeps only sample:
# response-MD × server-key × CA-key × client-key × CSR-hash, and inside every cell a
# FULL lifecycle — enroll, chain+strict+CRL validation, renew (serial must differ,
# revalidate), revoke via CMP rr signed by the leaf itself, OCSP-flip check, and a
# validation that must FAIL naming revocation. A cell is green only when its whole
# lifecycle is.
#
# Loop order minimises restarts: response-MD outermost restarts ocsp+cmp; server-key
# next restarts all seven; CAs are created lazily ONCE per run and reused across every
# inner slice. CMP exercises the key axes (CRMF carries no CSR, so no hash axis there);
# EST/SCEP CSRs carry the hash axis for real.
#
# ⚠️ PER-CA CMP RA ROWS SHARE ONE KEYPAIR. bind_ra_cert resolves the row
# "cmp-ra-<ca_id>", but the RESPONSE is signed by the CMP_RA_KEY config object — so a
# per-CA row whose certificate holds a DIFFERENT public key would be issued and then
# ignored as a mismatched pair (the console refuses exactly that shape). Every
# cmp-ra-<ca> row therefore certifies whichever key CMP_RA_KEY currently points at;
# MTX_CMPRA_OBJ tracks it across the server-axis re-keys.
MTX_SAVED_CHAIN="" MTX_SAVED_ISSUER="" MTX_SAVED_RCPT=""
MTX_SAVED_ESTURL="" MTX_SAVED_CMPURL="" MTX_SAVED_SCEPURL=""
MTX_CMPRA_OBJ="cmp-ra" MTX_OCSPRA_OBJ="ocsp-ra" MTX_SCEPRA_OBJ="scep-ra"
# The SCEP RA object only moves on RSA server specs (RFC 8894 pins its envelope to
# RSA); when a sweep skips the re-key the previous object stays current — and it is
# always an RSA pair, so per-CA rows can certify it on every slice.

mtx_line(){ printf '  %s[%s]%s %s\n' "$DIM" "$1" "$RST" "$2"; }
MTX_CTX=""   # "rmd=… srv=… ca=… cl=… h=…" — stamped by the innermost loop
mtx_fail(){ MTX_FAIL=$((MTX_FAIL+1)); DEMO_FAIL=$((DEMO_FAIL+1)); mtx_rec "$1" FAIL "${2:-}"; fail "(cell $1 $MTX_CTX: ${2:-})"; }
mtx_skip(){ MTX_SKIP=$((MTX_SKIP+1)); mtx_rec "$1" SKIP "${2:-}"; mtx_line SKIP "$1 $MTX_CTX — ${2:-}"; }

# ── the matrix REPORT ────────────────────────────────────────────────────────
# The run used to end with three numbers — "green cells: 20 skipped: 2 failed: 0" — which
# says how much happened and nothing about WHAT. The question a key/hash matrix exists to
# answer is per-combination: does an Ed448 CA issue to an ML-DSA client under sha3-512, and
# if not, why not. Three totals cannot answer it, and the skip lines that scrolled past an
# hour ago are not a table.
#
# So every cell records its axes and its verdict, and the run prints the grid at the end.
# A skip carries its reason: "TLS has no code point for ML-DSA", "openssl req cannot build
# an RSA-PSS SignatureAid over SHA-3", "one-shot scheme, digest ignored" are facts about
# the combination, and a reader needs them next to the cell rather than in the scrollback.
MTX_ROWS=()
_mtx_axis(){ printf '%s' "$MTX_CTX" | sed -n "s/.*$1=\([^ ]*\).*/\1/p"; }
mtx_rec(){   # <tag-or-protocol> <verdict> <reason>
    # ⚠️ THE TAG IS NOT THE PROTOCOL. mtx_fail/mtx_skip are called with a per-cell tag —
    # "m6 est-enroll", "fs3 scep-renew" — because that is what the inline message needs.
    # Dropped into the table verbatim it produced a PROTO column reading "m6 est-enroll",
    # which is unsortable and unreadable. Strip the sequence prefix and the step suffix so
    # the column is the protocol and nothing else; the reason still carries the step.
    local _p="$1"
    _p="${_p##* }"          # "m6 est-enroll" -> "est-enroll"
    _p="${_p%%-*}"          # "est-enroll"    -> "est"
    MTX_ROWS+=("$(_mtx_axis ca)|$(_mtx_axis cl)|$(_mtx_axis h)|$_p|$2|${3:-}")
}
mtx_ok(){    MTX_OK=$((MTX_OK+1)); mtx_rec "${1:-cell}" PASS ""; }

# One row per cell, widest-column aligned. Reasons are kept whole: a truncated reason is
# the same as no reason, and these are the payload.
mtx_report(){
    [ "${#MTX_ROWS[@]}" -gt 0 ] || return 0
    hdr "Matrix results — CA key × client key × CSR hash"
    printf '  %-14s %-14s %-10s %-6s %-6s %s\n' "CA KEY" "CLIENT KEY" "HASH" "PROTO" "" "REASON"
    printf '  %s\n' "--------------------------------------------------------------------------------"
    local r ca cl h p v why
    for r in "${MTX_ROWS[@]}"; do
        IFS='|' read -r ca cl h p v why <<<"$r"
        printf '  %-14s %-14s %-10s %-6s %-6s %s\n' \
            "${ca:--}" "${cl:--}" "${h:--}" "$p" "$v" "$why"
    done
    printf '  %s\n' "--------------------------------------------------------------------------------"
    printf '  %d cells: %d passed, %d skipped, %d failed\n' \
        "${#MTX_ROWS[@]}" "$MTX_OK" "$MTX_SKIP" "$MTX_FAIL"
}
# --protocols applies to the matrix too. It used to be read ONLY by Sweeps C and D, so
# `--full-matrix --protocols est` silently ran CMP, SCEP and ACME as well — the flag was
# accepted, documented, and ignored, which is worse than refusing it.
#
# Word-boundary match, not the loose `*"$p"*` the sweeps use: the sweeps get away with a
# substring test because no protocol name is a substring of another TODAY, and that is a
# property of the current list rather than of the check.
mtx_protocol_on(){ case " $PROTOCOLS " in *" $1 "*) return 0;; *) return 1;; esac; }

mtx_set_response_md(){ # <md> — responder + CMP response digest, then restart both
  compose_exec fastpki-config --config "$CONF_IN_CONTAINER" set OCSP_RESPONSE_MD "$1" >/dev/null 2>&1 || return 1
  compose_exec fastpki-config --config "$CONF_IN_CONTAINER" set CMP_RESPONSE_MD  "$1" >/dev/null 2>&1 || return 1
  dcp restart ocsp cmp >>"$WORK/compose-restart.log" 2>&1 || return 1
  wait_tcp "$DEMO_OCSP_PORT" 100 && wait_tcp "$DEMO_CMP_PORT" 100 && sleep 1
}

mtx_rekey_all(){ # <spec> — re-key every service credential at once, restart, wait
  local spec="$1" pin_q="?pin-source=/var/pki/tls/pin" svc
  tok(){ printf 'pkcs11:token=fastpki;object=%s;type=private%s' "$1" "$pin_q"; }
  SERVER_KEY="$spec"; spec_api_args "$spec"
  # TLS listeners first — unless this spec cannot front a TLS listener (ml-dsa), in
  # which case they keep their previous credential and the RA re-keys below still
  # measure the axis (identical to Sweep B's behaviour, minus the narrative).
  if tls_can_carry; then
    for svc in est acme ms web; do
      api_issue_hsm_cert "$svc" localhost "$(tok "$svc-tls-m$MTX_SEQ")" \
          digitalSignature,keyEncipherment serverAuth "$WORK/.rk-$svc.pem" \
          --data-urlencode "sans=localhost" \
          "${API_KEY_ARGS[@]+"${API_KEY_ARGS[@]}"}" \
          --data-urlencode keygen=true --data-urlencode rekey=true || return 1
    done
  fi
  api_issue_hsm_cert "cmp-ra-$CA_ID" "cmp-ra.$DEMO_DOMAIN" "$(tok "cmp-ra-m$MTX_SEQ")" \
      digitalSignature 1.3.6.1.5.5.7.3.28 "$WORK/.cmpra.pem" \
      "${API_KEY_ARGS[@]+"${API_KEY_ARGS[@]}"}" \
      --data-urlencode keygen=true --data-urlencode rekey=true \
    && MTX_CMPRA_OBJ="cmp-ra-m$MTX_SEQ" \
    || mtx_line NOTE "cmp-ra re-key refused for $spec — CMP cells keep the previous RA credential"
  api_issue_hsm_cert "ocsp-ra-$CA_ID" "ocsp-ra.$DEMO_DOMAIN" "$(tok "ocsp-ra-m$MTX_SEQ")" \
      digitalSignature 1.3.6.1.5.5.7.3.9 "$WORK/ocsp-ra.pem" \
      "${API_KEY_ARGS[@]+"${API_KEY_ARGS[@]}"}" \
      --data-urlencode keygen=true --data-urlencode rekey=true \
      --data-urlencode omit_aia=true --data-urlencode omit_crldp=true \
    && MTX_OCSPRA_OBJ="ocsp-ra-m$MTX_SEQ" \
    || mtx_line NOTE "ocsp-ra re-key refused for $spec — OCSP keeps the previous responder credential"
  scep_ra_gate   # sets SCEP_RA_SKIP for non-RSA specs; SCEP keeps its previous RA then
  if [ -z "${SCEP_RA_SKIP:-}" ]; then
    api_issue_hsm_cert "scep-ra-$CA_ID" "scep-ra.$DEMO_DOMAIN" "$(tok "scep-ra-m$MTX_SEQ")" \
        digitalSignature,keyEncipherment 1.3.6.1.4.1.311.20.2.1 "$WORK/.scepra.pem" \
        "${API_KEY_ARGS[@]+"${API_KEY_ARGS[@]}"}" \
        --data-urlencode keygen=true --data-urlencode rekey=true \
      && MTX_SCEPRA_OBJ="scep-ra-m$MTX_SEQ" \
      || { unset SCEP_RA_SKIP; return 1; }
  fi
  # else: the axis asked for a non-RSA server key, so the RA object was left as it was —
  # still the RSA pair it has always been, and still what per-CA rows must certify.
  unset SCEP_RA_SKIP
  dcp restart ocsp scep cmp est acme ms web >>"$WORK/compose-restart.log" 2>&1 || return 1
  local p
  for p in "$DEMO_OCSP_PORT" "$DEMO_CMP_PORT" "$DEMO_EST_PORT" "$DEMO_ACME_PORT" \
           "$DEMO_MS_PORT" "$DEMO_WEB_PORT"; do wait_tcp "$p" 100 || return 1; done
  sleep 2   # TLS handshakes race the first accept after listen()
}

mtx_ca_open(){ # <idc> <spec> <n> — create a root + its per-CA responder rows, retarget trust
  local idc="$1" spec="$2" n="$3" pin_q="?pin-source=/var/pki/tls/pin"
  MTX_CA_SPEC="$spec"
  tok(){ printf 'pkcs11:token=fastpki;object=%s;type=private%s' "$1" "$pin_q"; }
  spec_cli_args "$spec"
  # ⚠️ --md sha3-512 is for every CA EXCEPT RSA-PSS. An RFC 4055 restriction binds the
  # key to ONE digest, which must also be the signature digest, and OpenSSL cannot even
  # encode MGF1-with-SHA3 into the SPKI parameters — fastpki-ca now rejects the combo by
  # name. For a PSS CA let the product derive the ladder digest (4096 → sha384) so the
  # restriction and the self-signature agree by construction.
  local md_args=(--md sha3-512)
  case "$spec" in rsa-pss:*) md_args=();; esac
  compose_exec fastpki-ca --config "$CONF_IN_CONTAINER" create "$idc" \
      --name "$idc" --subject "/CN=FastPKI Matrix CA $n" \
      --ca-key "pkcs11:token=fastpki;object=$idc;type=private?pin-source=/var/pki/tls/pin" \
      --keygen --out-dir /tmp ${md_args[@]+"${md_args[@]}"} \
      "${CLI_KEY_ARGS[@]+"${CLI_KEY_ARGS[@]}"}" >"$WORK/$idc-create.log" 2>&1 || {
        mtx_line "SKIP" "CA $idc ($spec) refused: $(head -c 120 "$WORK/$idc-create.log" | tr '\n' ' ')"; return 1; }
  compose_exec cat "/tmp/$idc.crt" > "$WORK/$idc.crt" 2>/dev/null
  [ -s "$WORK/$idc.crt" ] || return 1
  # Every responder row is per CA: bind_ra_cert resolves "cmp-ra-<ca_id>", the OCSP
  # responder refuses to answer for a CA with no "ocsp-ra-<ca_id>", SCEP likewise.
  # Each response is signed by that service's CONFIG key object, so each new row must
  # certify the CURRENT object's public key (the console enforces the same handle
  # match) — certify, mint nothing. cmp-ra additionally demands its cert be issued BY
  # this very CA, which is exactly what ca_instance=$idc below arranges.
  api_issue_hsm_cert "cmp-ra-$idc" "cmp-ra-$n.$DEMO_DOMAIN" "$(tok "$MTX_CMPRA_OBJ")" \
      digitalSignature 1.3.6.1.5.5.7.3.28 "$WORK/.fm-cmpra-$n.pem" \
      --data-urlencode keygen=false --data-urlencode ca_instance="$idc" || return 1
  api_issue_hsm_cert "ocsp-ra-$idc" "ocsp-ra-m$n.$DEMO_DOMAIN" "$(tok "$MTX_OCSPRA_OBJ")" \
      digitalSignature 1.3.6.1.5.5.7.3.9 "$WORK/.fm-ocspra-$n.pem" \
      --data-urlencode keygen=false --data-urlencode omit_aia=true \
      --data-urlencode omit_crldp=true || return 1
  api_issue_hsm_cert "scep-ra-$idc" "scep-ra-m$n.$DEMO_DOMAIN" "$(tok "$MTX_SCEPRA_OBJ")" \
      digitalSignature,keyEncipherment 1.3.6.1.4.1.311.20.2.1 "$WORK/.fm-scepra-$n.pem" \
      --data-urlencode keygen=false || mtx_line NOTE "scep-ra row for $idc refused — SCEP cells will skip"
  # Signature-protected CMP (rr/kur signed by an enrolled client) validates the signer
  # against CMP_CLIENT_CA anchors, read at STARTUP: add this CA and restart cmp, or
  # every kur/rr under it dies with "no suitable sender cert".
  compose_exec fastpki-config --config "$CONF_IN_CONTAINER" set CMP_CLIENT_CA_ID \
      "demo-ca,$idc" >/dev/null 2>&1 || return 1
  dcp restart cmp >>"$WORK/compose-restart.log" 2>&1 && wait_tcp "$DEMO_CMP_PORT" 100 || return 1
  cp "$WORK/$idc.crt" "$WORK/$idc-chain.pem"    # swept CAs are self-signed roots
  # ⚠️ setup_target_client ALREADY appended /$CA_ID to every per-CA URL — appending a
  # second segment produced /cmp/demo-ca/fm-ca3 and a 404 on every matrix transaction.
  # The slice REPLACES that final segment instead; restore puts the default back.
  MTX_SAVED_CHAIN="$CHAIN"; MTX_SAVED_ISSUER="$ISSUER"; MTX_SAVED_RCPT="$CMP_RECIPIENT"
  MTX_SAVED_ESTURL="$EST_URL"; MTX_SAVED_CMPURL="$CMP_URL"; MTX_SAVED_SCEPURL="$SCEP_URL"
  CHAIN="$WORK/$idc-chain.pem"; ISSUER="$WORK/$idc.crt"
  CMP_RECIPIENT=$("$OSSL" x509 -in "$ISSUER" -noout -subject | sed 's/^subject=//; s/, /\//g; s/^/\//')
  EST_URL="${EST_URL%/$CA_ID}/$idc"; CMP_URL="${CMP_URL%/$CA_ID}/$idc"; SCEP_URL="${SCEP_URL%/$CA_ID}/$idc"
  rm -f cmp-id.pem cmp-id.key   # identity cache is only valid for one chain
}

mtx_ca_close(){ # <idc> — disable it and put the deployment's default back on the globals
  compose_exec fastpki-ca --config "$CONF_IN_CONTAINER" disable "$1" >/dev/null 2>&1
  CHAIN="$MTX_SAVED_CHAIN"; ISSUER="$MTX_SAVED_ISSUER"; CMP_RECIPIENT="$MTX_SAVED_RCPT"
  EST_URL="$MTX_SAVED_ESTURL"; CMP_URL="$MTX_SAVED_CMPURL"; SCEP_URL="$MTX_SAVED_SCEPURL"
}

mtx_est_cell(){ # <ca> <cl> <h> <rmd> <srv> — enroll → validate → renew → validate → revoke×2
  local ca="$1" cl="$2" h="$3" rmd="$4" srv="$5" CN tag
  MTX_SEQ=$((MTX_SEQ+1)); tag="m$MTX_SEQ"; CN="fm-$tag.$DEMO_DOMAIN"
  if ! est_do_enroll "$CN" "$cl" "$h"; then
    if [ "${EST_CODE:-}" = 429 ]; then mtx_skip "$tag est" "per-owner cap"; return; fi
    if [ "${EST_CODE:-}" = csr ] && csr_local_gap "$cl" "$h"; then
      mtx_skip "$tag est-enroll" "this openssl cannot sign a PSS CSR with $h"; return; fi
    mtx_fail "$tag est-enroll" "HTTP ${EST_CODE:-?} (key $cl)"; return
  fi
  if ! validate_cert est-leaf.pem ok; then mtx_fail "$tag est-validate" "enrolled cert: $VALIDATE_WHY"; return; fi
  if ! est_renew "$CN"; then
    if [ "${EST_CODE:-}" = 429 ]; then mtx_skip "$tag est-renew" "cap"; else mtx_fail "$tag est-renew" "HTTP ${EST_CODE:-?}"; return; fi
  elif ! validate_cert est-ren.pem ok; then mtx_fail "$tag est-revalidate" "renewed: $VALIDATE_WHY"; return
  fi
  if ! cmp_revoke_leaf est-leaf.pem est-leaf.key; then mtx_fail "$tag est-revoke1" "$REV_WHY"; return; fi
  if [ -s est-ren.pem ]; then
    if ! cmp_revoke_leaf est-ren.pem ren.key; then mtx_fail "$tag est-revoke2" "$REV_WHY"; return; fi
    if ! validate_cert est-ren.pem revoked; then mtx_fail "$tag est-revoked" "$VALIDATE_WHY"; return; fi
  fi
  mtx_ok est
}

mtx_cmp_cell(){ # <ca> <cl> <h> — enroll(ir) → validate → kur → validate → revoke×2
  local ca="$1" cl="$2" h="$3" CN tag
  MTX_SEQ=$((MTX_SEQ+1)); tag="m$MTX_SEQ"; CN="fc-$tag.$DEMO_DOMAIN"
  rm -f cmp-kur.pem kur-new.key
  if ! cmp_enroll "$CN" "$cl" "$h"; then
    [ -n "${CMP_RA_SKIP:-}" ] && { mtx_skip "$tag cmp" "$CMP_RA_SKIP"; unset CMP_RA_SKIP; return; }
    # ⚠️ THE SAME LOCAL GAP EST REPORTS, and CMP hits it for the same reason: the POPO
    # signature over the CertRequest needs an RSASSA-PSS AlgorithmIdentifier, which this
    # OpenSSL cannot build over SHA-3. It fails before any network I/O with "error creating
    # certreq", so the server never sees it and calling it a product failure would be wrong.
    # Judged on the client's own words AND the known pair — never on the pair alone, so a
    # host whose openssl manages the combination keeps full coverage.
    if csr_local_gap "$cl" "$h" && grep -q "error creating certreq" "$WORK/cmp-cli.log" 2>/dev/null; then
      mtx_skip "$tag cmp-enroll" "this openssl cannot build a PSS CertReq POPO with $h"; return
    fi
    mtx_fail "$tag cmp-enroll" "ir failed (key $cl)"; return
  fi
  if ! validate_cert cmp-leaf.pem ok; then mtx_fail "$tag cmp-validate" "enrolled: $VALIDATE_WHY"; return; fi
  if ! cmp_kur "$CN"; then mtx_fail "$tag cmp-kur" "(see $WORK/cmp-kur.log)"; return; fi
  if ! validate_cert cmp-kur.pem ok; then mtx_fail "$tag cmp-kur-validate" "$VALIDATE_WHY"; return; fi
  if ! cmp_revoke_leaf cmp-kur.pem kur-new.key; then mtx_fail "$tag cmp-revoke1" "$REV_WHY"; return; fi
  if ! cmp_revoke_leaf cmp-leaf.pem cmp-leaf.key; then mtx_fail "$tag cmp-revoke2" "$REV_WHY"; return; fi
  if ! validate_cert cmp-leaf.pem revoked; then mtx_fail "$tag cmp-revoked" "$VALIDATE_WHY"; return; fi
  mtx_ok cmp
}

mtx_scep_cell(){ # <ca-idc> — SCEP once per matrix CA: {rsa:3072, ec:P-256} × hashes + renewal
  local idc="$1" k h CN tag i=0
  for k in rsa:3072 ec:P-256; do
    for h in $HASHES; do
      i=$((i+1)); MTX_SEQ=$((MTX_SEQ+1)); tag="fs$i"; CN="fm-scep-$i.$DEMO_DOMAIN"
      MTX_CTX="ca=${MTX_CA_SPEC:-$idc} cl=$k h=$h"
      gen_client_key "$k" sw.key || { mtx_skip "$tag scep-keygen" "$k unsupported here"; continue; }
      rm -f scep-hashed-leaf.pem
      if ! scep_enroll_hashed "$CN" sw.key "$h" "$k"; then
        mtx_fail "$tag scep-enroll" "(see above)"; continue; fi
      "$OSSL" x509 -inform DER -in scep-issued.der -out scep-hashed-leaf.pem 2>/dev/null
      if ! validate_cert scep-hashed-leaf.pem ok; then mtx_fail "$tag scep-validate" "$VALIDATE_WHY"; continue; fi
      if scep_renew "$CN" sw.key "$k"; then
        if ! validate_cert scep-ren.pem ok; then mtx_fail "$tag scep-renew-validate" "$VALIDATE_WHY"; continue; fi
        mtx_ok scep
      elif [ -n "${SCEP_ST:-}" ]; then
        mtx_fail "$tag scep-renew" "pkiStatus $SCEP_ST (SCEP_RENEWAL?)"; unset SCEP_ST
      else
        mtx_fail "$tag scep-renew" "(see $WORK/cmp-rr.log)"; fi
    done
  done
}

run_full_matrix(){
  hdr "Full matrix — response-MD × server-key × CA-key × client-key × CSR-hash"
  local nrmd nsrv nca nh total
  nrmd=$(set -- $RESPONSE_MDS; echo $#); nsrv=$(set -- $SERVER_KEYS; echo $#)
  nca=$(set -- $CA_KEYS; echo $#)
  nh=$(set -- $HASHES; echo $#)
  # Count what will ACTUALLY run, not the raw cross-product: a client key that ignores
  # the CSR digest contributes ONE cell, not $nh (see hash_axis_applies). A plan line
  # that overstates by a third is the first thing a reader stops trusting.
  local percel=0
  for cl in $CLIENT_KEYS; do
    if hash_axis_applies "$cl"; then percel=$((percel+nh)); else percel=$((percel+1)); fi
  done
  total=$((nrmd*nsrv*nca*percel))
  info "plan:" "$total cells over [$PROTOCOLS] — expect tens of minutes"
  DEMO_QUIET=1   # one line per anomaly instead of the narrative
  local rmd srv cspec cl h idc cl_hashes n_ca=0
  MTX_SAVED_SRVKEY="$SERVER_KEY"   # the closing sections expect the operator's baseline back
  for rmd in $RESPONSE_MDS; do
    if ! mtx_set_response_md "$rmd"; then MTX_CTX=""; mtx_fail "rmd=$rmd" "could not apply response MD"; continue; fi
    for srv in $SERVER_KEYS; do
      MTX_SEQ=$((MTX_SEQ+1))
      if ! mtx_rekey_all "$srv"; then MTX_CTX=""; mtx_fail "rmd=$rmd srv=$srv" "re-key/restart failed"; continue; fi
      for cspec in $CA_KEYS; do
        n_ca=$((n_ca+1)); idc="fm-ca$n_ca"
        if ! mtx_ca_open "$idc" "$cspec" "$n_ca"; then
          MTX_CTX="srv=$srv rmd=$rmd"; mtx_skip "ca=$cspec" "unavailable under this stack"; continue; fi
        for cl in $CLIENT_KEYS; do
          # A key that ignores the digest runs the FIRST hash only, and SAYS so — the
          # report then distinguishes "not exercised here" from "exercised and passed",
          # instead of silently scoring one cell twice.
          cl_hashes="$HASHES"
          if ! hash_axis_applies "$cl"; then
            cl_hashes=$(set -- $HASHES; echo "${1:-}")
            MTX_CTX="rmd=$rmd srv=$srv ca=$cspec cl=$cl"
            mtx_skip "hash-axis" "$(hash_axis_skip_reason "$cl")"
          fi
          for h in $cl_hashes; do
            MTX_CTX="rmd=$rmd srv=$srv ca=$cspec cl=$cl h=$h"
            if mtx_protocol_on est; then mtx_est_cell "$idc" "$cl" "$h" "$rmd" "$srv"; fi
            if mtx_protocol_on cmp; then mtx_cmp_cell "$idc" "$cl" "$h"; fi
          done
        done
        MTX_CTX="rmd=$rmd srv=$srv ca=$cspec"
        if mtx_protocol_on scep; then mtx_scep_cell "$idc"; fi
        if mtx_protocol_on acme && [ "$RUN_ACME" != no ] && command -v certbot >/dev/null 2>&1; then
          MTX_SEQ=$((MTX_SEQ+1))
          rm -f "acme-cli.log"
          # The swept CA is selected by the DIRECTORY ROUTE (/acme/<ca_id>/directory),
          # not by trust: the listener keeps its default-CA service cert (see
          # ACME_TLS_BUNDLE above), while the issued cert must chain to the SWEPT root.
          local acme_ep="${ACME_DIR#*://}"; acme_ep="${acme_ep%%/*}"
          if ACME_TLS_BUNDLE="$MTX_SAVED_CHAIN" \
             ACME_DIR="https://${acme_ep}/acme/${idc}/directory" \
             ACME_FORCE=1 acme_enroll "fm-acme-$n_ca.$DEMO_DOMAIN" rsa >"$WORK/acme-$idc.log" 2>&1 \
             && validate_cert "$WORK/certbot-config/live/fm-acme-$n_ca.$DEMO_DOMAIN/cert.pem" ok; then
            mtx_ok acme
          else mtx_fail "acme ca=$cspec" "(see $WORK/acme-$idc.log)"; fi
        fi
        mtx_ca_close "$idc"
      done
    done
  done
  DEMO_QUIET=0
  hdr "Full matrix summary"
  info "green cells:" "$MTX_OK   skipped: $MTX_SKIP   failed: $MTX_FAIL"
  mtx_report
  # Leave the stack where the closing sections expect it: the operator's baseline creds.
  step "restoring baseline service credentials"
  SERVER_KEY="$MTX_SAVED_SRVKEY"
  # The matrix registered every swept root as a CMP client-auth anchor; drop them again
  # so the deployment is left exactly as it was found (mtx_rekey_all restarts cmp).
  compose_exec fastpki-config --config "$CONF_IN_CONTAINER" set CMP_CLIENT_CA_ID \
      demo-ca >/dev/null 2>&1 || true
  MTX_SEQ=$((MTX_SEQ+1))   # fresh token-object names — reusing a slice's would collide
  if mtx_rekey_all "${SERVER_KEY:-}"; then ok; else fail "(baseline restore — closing sections may report stale keys)"; fi
}

# ⚠️ BOUND ANY STEP THAT CAN BLOCK ON THE NETWORK. `timeout` is GNU coreutils and is
# absent on macOS (§3d: platform-agnostic), so this is the portable equivalent: run in the
# background, arm a watchdog, kill on expiry.
#
# It exists because the demo HUNG. The CRL fetch follows the URL named in the
# certificate's CRLDP, and that URL carries the DEPLOYMENT's BASE_URL — `pki.example.org`
# on the lab. openssl has no timeout of its own there, so the run stopped dead at
#
#     Connecting to ::1
#
# and never came back. A demo that cannot finish is worse than one that reports a failure.
tls_verify(){
  hdr "Verifying endpoint TLS certificates (chain + strict + CRL)"
  # ⚠️ LIVE ONLY, and it must say so rather than silently do nothing. `set -u` is on and
  # TARGET_HOST exists only in live mode — the first version dereferenced it unconditionally
  # and the whole demo exited 1 under --throwaway, which demo_clients.sh caught as "exit
  # status is 0 (got 1)" with nothing on screen explaining it.
  #
  # It is also the right scope on the merits: a throwaway run serves a self-signed cert it
  # generated seconds earlier, so "does the chain verify against the deployment root, and is
  # the CRL in it fetchable" has no meaning there. Those are questions about a REAL
  # deployment.
  if [ -z "${TARGET_HOST:-}" ]; then
    step "endpoint TLS verification"
    skip "(throwaway mode — the listeners serve a self-signed cert, so there is no chain or CRL to check)"
    return 0
  fi
  # ⚠️ REBUILD THE ANCHOR RATHER THAN GIVE UP, and say which file was missing if that
  # fails. This used to skip the whole step the moment $CHAIN did not point at a readable
  # file, reporting only "(no CA chain available to anchor against)" — which is what an
  # operator sees after the run has ALREADY validated EST, CMP and SCEP certificates
  # against that same trust. The anchors are one request away: EST /cacerts is where
  # setup_target_client got them in the first place, and re-fetching costs one round trip.
  # Naming the path matters as much: without it there is nothing to check by hand.
  local anchor="${CHAIN:-$WORK/chain.pem}"
  if [ ! -s "$anchor" ] && [ -n "${EST_URL:-}" ]; then
    curl -sk --max-time 20 "$EST_URL/cacerts" | b64d > "$WORK/tlsv-cacerts.p7b" 2>/dev/null
    "$OSSL" pkcs7 -inform DER -in "$WORK/tlsv-cacerts.p7b" -print_certs \
            -out "$WORK/tlsv-chain.pem" 2>/dev/null
    if grep -q "BEGIN CERT" "$WORK/tlsv-chain.pem" 2>/dev/null; then
      anchor="$WORK/tlsv-chain.pem"
      info "trust anchors:" "re-fetched from $EST_URL/cacerts"
    fi
  fi
  if [ ! -s "$anchor" ]; then
    step "endpoint TLS verification"
    skip "(no CA chain at $anchor, and $EST_URL/cacerts yielded none)"
    return 0
  fi
  local sni="${PKI_DNS:-$TARGET_HOST}"
  local wP=${WEB_PORT:-8090} eP=${EST_PORT:-8443} aP=${ACME_PORT:-8444} mP=${MS_PORT:-8446}
  # ⚠️ HOSTPORT FIRST, PORT AS FALLBACK. In throwaway the services publish on HIGH
  # loopback ports carried by WEB_HOSTPORT/EST_URL/…/MS_HOSTPORT; probing the bare
  # MS_PORT default found :8446 closed and reported "nothing listening" about a listener
  # that was very much up — one directory along.
  local hp_web="${WEB_HOSTPORT:-$TARGET_HOST:$wP}"
  local hp_est;  hp_est="$(printf '%s' "${EST_URL#*://}" | sed 's|/.*||')"
  local hp_acme; hp_acme="$(printf '%s' "${ACME_DIR#*://}" | sed 's|/.*||')"
  local hp_ms="${MS_HOSTPORT:-$TARGET_HOST:$mP}"
  [ -n "$hp_est" ]  || hp_est="$TARGET_HOST:$eP"
  [ -n "$hp_acme" ] || hp_acme="$TARGET_HOST:$aP"
  local any=0
  for pair in "console:$hp_web" "EST:$hp_est" "ACME:$hp_acme" "MS:$hp_ms"; do
    local name=${pair%%:*} hostport=${pair#*:}
    local port=${hostport##*:}
    # Only probe what is actually listening — a protocol the customer declined at install
    # has no container and no port, and reporting that as a TLS failure is wrong.
    # The liveness probe doubles as the fetch of what this listener actually serves:
    # crl_capath needs the LEAF to find the issuing CA's CRL (the leaf's own DP names
    # it), and the anchor alone cannot supply that. One handshake, both jobs.
    (run_bounded 8 "$OSSL" s_client -connect "$hostport" -servername "$sni" -showcerts \
        </dev/null >"$WORK/tlsv-$name-served.pem" 2>/dev/null) || {
        step "$name TLS on :$port"; skip "(nothing listening)"; continue; }
    any=1
    step "$name TLS on :$port"
    local cap; cap=$(crl_capath "$anchor" "$WORK/tlsv-$name-served.pem")
    # -verify_return_error makes a verification failure a NON-ZERO EXIT. Without it
    # s_client happily reports "Verify return code: 20" and exits 0, so the check would
    # pass on a chain that does not verify — the vacuous shape this repo keeps hitting.
    if run_bounded 25 "$OSSL" s_client -connect "$hostport" -servername "$sni" \
            -CAfile "$anchor" -CApath "$cap" -x509_strict -crl_check_all \
            -verify_return_error -brief </dev/null >"tls-$name.log" 2>&1; then
      ok
    else
      # Say WHICH of the three checks failed — "TLS verification failed" sends the reader
      # nowhere. The verify line names it.
      local why; why=$(grep -iE "verif|crl|error" "tls-$name.log" | head -3 | tr '\n' ' ')
      fail "(${why:-see $WORK/tls-$name.log})"
    fi
  done
  [ "$any" = 1 ] || info "note:" "no TLS listener answered on $TARGET_HOST — nothing verified."
  info "not probed:" "OCSP, CMP, SCEP and the store are plain HTTP by design."
}

# ── An ACME WILDCARD certificate, over dns-01 ────────────────────────────────────
#
# The demo must cover http-01, tls-alpn-01 and wildcard. This is the wildcard, and it
# is the one of the three that can run here. Saying why the other two cannot, because a
# silent omission is worse than a stated one:
#
#   http-01     RFC 8555 §8.3 fixes the validation port at 80 and the server honours that
#               (`httplib::Client cli(host, 80)`, src/acme/main.cpp:1170). Serving :80 on
#               the demo host under a name the ACME server resolves needs root, so the
#               demo cannot do it privilege-free. tests/acme_lifecycle.sh covers it with
#               real certbot and lives in ROOT_SUITES for exactly this reason.
#   tls-alpn-01 needs :443, or a deployment whose ACME_TLS_ALPN_PORT was changed — that is
#               server-side config we must not edit on someone's live target.
#               tests/acme_preauth_alpn.sh covers it unprivileged against its own server.
#
# The wildcard is worth showing on its own: the order keeps `*.`, the authorization does
# NOT (RFC 8555 §7.1.3), and the TXT record goes at the BASE name (§8.4). Getting any of
# those three wrong still produces a certificate for the non-wildcard name, which looks
# like success.
# ⚠️ INITIALISED HERE, not beside demo_need_sudo further down: the ACME steps are
# dispatched ABOVE that line, so under `set -u` the hoisted helpers below referenced an
# unset variable and died. Third instance of define-after-use in this session.
demo_sudo=""
# Give fastpki-acme a route back to this host for the duration of the demo, then
# take it away. Returns 1 (and prints its own skip) when it cannot.
DEMO_COMPOSE_OVERRIDE=""
# ── remote dns-01: repoint the deployment's resolver at this host, and put it back ─────
#
# dns-01 is the one challenge where the SERVER does the lookup, so nothing here needs a
# privileged port — but the server has to be told where to look. On a live deployment that
# means writing ACME_DNS_RESOLVER in its `config` table and restarting fastpki-acme, which
# reads the key at startup. That is administrative access the demo user does not have, so
# it goes over the SSH target provision-target.sh recorded in the descriptor.
#
# ⚠️ ALWAYS RESTORE. The previous value is captured before anything is written and put back
# in an EXIT/INT/TERM trap, so a Ctrl-C or a failed order cannot leave someone's ACME server
# pointed at a laptop that has gone home.
DEMO_REMOTE_DNS_PREV=""; DEMO_REMOTE_DNS_SET=""
demo_remote_cfg(){   # <target> <args...> — run fastpki-config against the deployment
  local t="$1"; shift
  # ⚠️ TWO WAYS TO REACH THE SAME CLI. A cluster has no SSH target and no `docker exec`;
  # kubectl is the equivalent administrative channel, and K8S_NAMESPACE in the descriptor
  # is what says which kind of deployment this is.
  if [ -n "${K8S_NAMESPACE:-}" ]; then
    # Any server will do: the config table is in the database every server reaches.
    kubectl -n "$K8S_NAMESPACE" exec statefulset/fastpki-node -c web -- \
      fastpki-config --config /app/config/bootstrap.conf "$@" 2>/dev/null
    return $?
  fi
  # ⚠️ AND A THIRD, WHERE THERE IS NO CONTAINER AT ALL. On a native or cloud node the CLI
  # is on the PATH and reads /etc/fastpki/bootstrap.conf, so neither branch above has
  # anything to exec into: `docker ps` finds nothing, this returned 3 for every call, and
  # the dns-01 cells skipped on the one deployment shape the cloud image produces.
  # Writing a config row is the fastpki user's to do, and Alpine ships doas, not sudo.
  if [ "${DEPLOY_MODE:-}" = native ]; then
    ssh "${DEMO_SSH_OPTS[@]}" "$t" \
        "doas -u fastpki fastpki-config --config /etc/fastpki/bootstrap.conf $*" 2>/dev/null
    return $?
  fi
  ssh "${DEMO_SSH_OPTS[@]}" "$t" "sh -s -- $*" <<'RSH' 2>/dev/null
webc=$(docker ps --format "{{.Names}}" 2>/dev/null | grep -m1 -iE "web")
[ -n "$webc" ] || exit 3
docker exec "$webc" fastpki-config --config /app/config/bootstrap.conf "$@"
RSH
}
# ⚠️ RESTARTING THE ACME LISTENER IS TWO DIFFERENT THINGS. ACME_DNS_RESOLVER is read at
# STARTUP, so writing it changes nothing until the process restarts — `docker restart` on
# compose, a restart of the acme container in every server pod on a cluster.
demo_restart_acme(){   # <target>
  if [ -n "${K8S_NAMESPACE:-}" ]; then
    # ⚠️ EVERY SERVER, BECAUSE THE SERVICE SPREADS ORDERS ACROSS THEM. Each fastpki-node pod runs its
    # own acme container, and one still holding the resolver from BEFORE this write makes an
    # order that lands on it fall back to cluster DNS for the challenge name — which finds
    # nothing and reports
    #     dns-01 TXT record missing or mismatched
    # about a record that is present and correct. Proven once by CoreDNS's own query log across
    # a failing order: it never saw a single TXT query.
    #
    # The container is restarted in place (its process is killed and the kubelet starts it
    # again), so, as with docker restart, no old process is left serving beside the new one.
    #
    # ⚠️ WAIT FOR THE RESTART TO BE COUNTED BEFORE WAITING FOR THE PORT. The kill returns at once
    # and the old process can still be listening on :8444 a moment later, so a port check alone
    # can pass on the very process this replaces.
    local _pods _p _i _rc0 _rc
    local _jp='{.status.containerStatuses[?(@.name=="acme")].restartCount}'
    _pods=$(kubectl -n "$K8S_NAMESPACE" get pods -l app.kubernetes.io/component=node -o name 2>/dev/null)
    [ -n "$_pods" ] || return 1
    for _p in $_pods; do
      _rc0=$(kubectl -n "$K8S_NAMESPACE" get "$_p" -o jsonpath="$_jp" 2>/dev/null)
      kubectl -n "$K8S_NAMESPACE" exec "$_p" -c acme -- kill 1 >/dev/null 2>&1 || return 1
      _i=0
      while :; do
        _rc=$(kubectl -n "$K8S_NAMESPACE" get "$_p" -o jsonpath="$_jp" 2>/dev/null)
        [ -n "$_rc" ] && [ "$_rc" -gt "${_rc0:-0}" ] && break
        _i=$((_i+1)); [ "$_i" -lt 120 ] || return 1; sleep 1
      done
    done
    for _p in $_pods; do
      _i=0
      until kubectl -n "$K8S_NAMESPACE" exec "$_p" -c acme -- \
              sh -c 'netstat -lnt 2>/dev/null | grep -q ":8444 "' >/dev/null 2>&1; do
        _i=$((_i+1)); [ "$_i" -lt 120 ] || return 1; sleep 1
      done
    done
    return 0
  fi
  # A native node's listener is an OpenRC service, so restarting it names the service and
  # needs no container to find first. ACME_DNS_RESOLVER is read at startup here exactly as
  # it is on compose, so this is what makes the write above take effect.
  if [ "${DEPLOY_MODE:-}" = native ]; then
    ssh "${DEMO_SSH_OPTS[@]}" "$1" 'doas rc-service fastpki-acme restart' >/dev/null 2>&1
    return $?
  fi
  ssh "${DEMO_SSH_OPTS[@]}" "$1" 'a=$(docker ps --format "{{.Names}}" | grep -m1 -iE "acme"); [ -n "$a" ] && docker restart "$a" >/dev/null' >/dev/null 2>&1
}
demo_undo_remote_dns(){
  [ -n "$DEMO_REMOTE_DNS_SET" ] || return 0
  local t="$DEMO_REMOTE_DNS_SET"; DEMO_REMOTE_DNS_SET=""   # first, so a second call cannot loop
  if [ -n "$DEMO_REMOTE_DNS_PREV" ]; then
    demo_remote_cfg "$t" set ACME_DNS_RESOLVER "$DEMO_REMOTE_DNS_PREV" >/dev/null 2>&1 || true
  else
    demo_remote_cfg "$t" unset ACME_DNS_RESOLVER >/dev/null 2>&1 || true
  fi
  # No restart on the way back either — the value is read where it is used, so clearing it
  # takes effect on its own. See the note at the set.
  sleep 6
  # ⚠️ AND WAIT FOR IT TO ANSWER AGAIN BEFORE THE NEXT CELL ASKS. Setting the resolver
  # already polls for readiness; reverting it did not, so the restart this triggers raced
  # whatever ran next — the http-01 cell fetched the directory into a listener that had not
  # rebound yet and reported `directory FAILED status=000`, which reads as an unreachable
  # deployment rather than as the previous cell's cleanup still finishing. Bounded, and
  # ignored on failure: this is teardown, and the cell that follows reports its own trouble.
  demo_acme_ready >/dev/null 2>&1 || true
  printf '  %sreverted the target ACME_DNS_RESOLVER%s\n' "$DIM" "$RST"
}
demo_acme_dns_resolver_remote(){   # <port> — point the deployment at the CoreDNS beside it
  local port=$1 t="${SSH_TARGET:-}"
  # A cluster is driven by kubectl and has no SSH target; K8S_NAMESPACE stands in for one.
  if [ -z "$t" ] && [ -n "${K8S_NAMESPACE:-}" ]; then t="k8s:$K8S_NAMESPACE"; fi
  [ -n "$t" ] || { skip "(descriptor has no SSH_TARGET or K8S_NAMESPACE — re-run provision-target.sh)"; return 1; }
  # ⚠️ THE RESOLVER IS A CONTAINER NAME, NOT THIS HOST. dns-auth.sh starts CoreDNS ON the
  # deployment, joined to the same network as the acme service, so the ACME server reaches
  # it by name and the query never leaves that machine. The first version ran CoreDNS here
  # and pointed the deployment back at this laptop, which needs inbound reachability, a
  # published UDP port and Docker on the operator's machine — three assumptions that hold
  # on a mesh VPN and almost nowhere else.
  local resolver="fastpki-dns:15353"
  # ⚠️ A NATIVE TARGET CANNOT HOST THE RESOLVER, so this is the one shape where it does run
  # beside the demo and the deployment reaches BACK. There is no docker on that node to
  # start a sibling container in, and no cluster to create a Service in — the two wirings
  # the comment above describes both assume one or the other. CHALLENGE_FQDN is already
  # defined as a name the deployment resolves to THIS host (it is what the http-01 and
  # tls-alpn-01 cells depend on), so it is exactly the address to hand back, and dns-auth.sh
  # publishes CoreDNS's port on this host for it to reach.
  if [ "${DEPLOY_MODE:-}" = native ]; then
    [ -n "${CHALLENGE_FQDN:-}" ] || {
      skip "(native target needs CHALLENGE_FQDN — a name it resolves to this host)"; return 1; }
    resolver="$CHALLENGE_FQDN:$port"
  fi
  if [ -n "${K8S_NAMESPACE:-}" ]; then
    # ⚠️ THE ClusterIP, NOT THE SERVICE NAME, AND THE DIFFERENCE IS 30 SECONDS OF CACHE.
    # dns-auth.sh creates the fastpki-dns Service and dns-cleanup.sh deletes it, once per
    # dns-01 cell, and every recreation gets a NEW ClusterIP — measured across consecutive
    # runs: 10.43.81.55, 10.43.1.96, 10.43.231.125, 10.43.91.8. k3s's cluster DNS caches A
    # records for 30s (`cache 30` in the kube-system Corefile), so fastpki-acme — which
    # resolves this at query time — got a PREVIOUS run's ClusterIP, with nothing behind it.
    # UDP to a dead ClusterIP is dropped silently, so the lookup returned no records and the
    # server reported "dns-01 TXT record missing or mismatched" about a record that was
    # present and correct. CoreDNS's own query log showed it never received the query.
    #
    # An address needs no resolving, so the cache cannot be wrong about it.
    #
    # ⚠️ WHICH MEANS THE SERVICE HAS TO EXIST BEFORE THE RESOLVER IS SET. dns-auth.sh
    # creates it at the first PUBLISH, which happens later — during the order, from the
    # challenge hook. Creating it here with a placeholder record is what makes the address
    # knowable now; the real publish replaces the ConfigMap and the pod, and `kubectl apply`
    # keeps the Service's ClusterIP, so the value set here stays correct for the whole cell.
    DNS_K8S_NAMESPACE="$K8S_NAMESPACE" "$ROOT/demo/dns-auth.sh" \
        _acme-challenge.placeholder.invalid placeholder >/dev/null 2>&1
    local cip
    cip=$(kubectl -n "$K8S_NAMESPACE" get svc fastpki-dns \
            -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
    if [ -z "$cip" ]; then
      skip "(could not create the CoreDNS service in namespace $K8S_NAMESPACE)"; return 1
    fi
    resolver="$cip:15353"
  fi
  DEMO_REMOTE_DNS_PREV=$(demo_remote_cfg "$t" get ACME_DNS_RESOLVER | tail -1 | tr -d '\r')
  case "$DEMO_REMOTE_DNS_PREV" in *"not set"*|*ERR*) DEMO_REMOTE_DNS_PREV="" ;; esac
  if ! demo_remote_cfg "$t" set ACME_DNS_RESOLVER "$resolver" >/dev/null 2>&1; then
    skip "(could not write ACME_DNS_RESOLVER on the target)"; return 1
  fi
  DEMO_REMOTE_DNS_SET="$t"
  # ⚠️ SUPERSET, INCLUDING cleanup. bash REPLACES traps, and this line used to install only
  # the override-revert -- silently displacing the cleanup handler set at startup, so a
  # run that reached a dns-01 cell never revoked the certificates it issued and never
  # removed its work directory. Name every handler the run still owes.
  trap 'demo_undo_all; cleanup' EXIT INT TERM
  # ⚠️ NO RESTART. fastpki-acme reads ACME_DNS_RESOLVER where it USES it — at dns-01
  # validation and at the CAA check — rather than once at startup, so the write above reaches
  # every server by itself within the value's few-second cache. Every pod reads the same
  # `config` table, which is what the restart was for: killing each acme container so none
  # kept a resolver from before the write.
  #
  # Restarting was not free. It killed PID 1 in the acme container of EVERY server, twice per
  # run, and the TLS probe that follows found "nothing listening" on the console, EST and MS
  # while they came back — three skips caused entirely by the demo disturbing the deployment
  # it was measuring. Measured on a k3s run: 6 container restarts, and three probes skipped.
  sleep 6
  # ⚠️ POLL, DO NOT SLEEP. This was `sleep 3`, which is a guess about how long a restart
  # takes on someone else's machine — and the very next thing the caller does is fetch the
  # ACME directory, so a slow restart surfaces as `directory FAILED status=000` rather than
  # as a timeout. demo_acme_ready() asks for the directory itself, which also covers a
  # listener that is bound but has not resolved its CA yet.
  if ! demo_acme_ready >&2; then
    demo_undo_remote_dns
    skip "(fastpki-acme did not answer its directory after the restart on the target)"; return 1
  fi
  # Name what changed and where, since two machines are involved. For compose and
  # Kubernetes the setting AND the nameserver are both on the deployment and nothing
  # reaches back here; for a native target the nameserver is here and the deployment
  # dials it. The line says which, because the difference decides where to look when a
  # challenge is not answered.
  if [ "${DEPLOY_MODE:-}" = native ]; then
    printf '  %sset ACME_DNS_RESOLVER=%s on %s, pointing it at a CoreDNS started HERE (both reverted at the end)%s\n' \
           "$DIM" "$resolver" "${t#*@}" "$RST"
  else
    printf '  %sset ACME_DNS_RESOLVER=%s on %s, alongside a CoreDNS started there (both reverted at the end)%s\n' \
           "$DIM" "$resolver" "${t#*@}" "$RST"
  fi
  return 0
}

# ⚠️ ONE RESTORE, because bash REPLACES traps rather than stacking them. Two mechanisms can
# be in play (a local compose override, a remote config key), and a later `trap
# demo_undo_compose` would silently drop the remote half -- leaving someone else's ACME
# server pointed at this laptop. Every trap and every early-return path uses this.
demo_undo_all(){ demo_undo_remote_dns; demo_undo_compose; demo_undo_k8s_client; }

# ⚠️ THE CLUSTER CAN MANUFACTURE THE NAME http-01 NEEDS, so the demo should not ask an
# operator for one.
#
# http-01 and tls-alpn-01 are the reverse of dns-01: the ACME server opens a connection TO
# the client, on port 80 or 443, at whatever name the order identifies. That is why those
# cells wanted CHALLENGE_FQDN — "a name this deployment already resolves to THIS host" —
# and skipped without it, on the reasoning that nothing here can teach a remote deployment
# to resolve a made-up name.
#
# On Kubernetes that reasoning does not hold. Cluster DNS gives every Service a name that
# every pod resolves, and a Service with hand-written endpoints can point anywhere — including
# back at the machine running the demo. So the name is not a precondition the environment has
# to satisfy; it is one object away. Measured: with the Service in place, the acme container
# fetched http://fastpki-client.fastpki.svc.cluster.local/ from this host and got the body.
#
# No selector, so nothing in the cluster is matched; the EndpointSlice names this host's
# address explicitly. Ports 80 and 443 because those are the two the protocol dials.
#
# ⚠️ SETS A GLOBAL, NEVER ECHOES THE NAME FOR $( ) TO CAPTURE. Called as
# `NAME=$(demo_k8s_client_publish)` this runs in a SUBSHELL, and two things go wrong at once:
# the EXIT trap it installs fires when that subshell ends — deleting the Service moments after
# creating it — and the teardown's own message lands on stdout, so the caller captures
#     fastpki-client.fastpki.svc.cluster.local  removed the temporary fastpki-client Service
# as the hostname. Both observed; the orders then went out against that string.
DEMO_K8S_CLIENT_SVC=""
DEMO_K8S_CLIENT_FQDN=""
demo_k8s_client_publish(){   # sets DEMO_K8S_CLIENT_FQDN; 0 on success
  DEMO_K8S_CLIENT_FQDN=""
  [ -n "${K8S_NAMESPACE:-}" ] || return 1
  command -v kubectl >/dev/null 2>&1 || return 1
  # This host's address AS THE CLUSTER WILL REACH IT. Taken from the route to the deployment
  # rather than from a guess like `hostname -I`, which on a multi-homed box hands back the
  # first of several and sends the challenge to an interface the cluster has no path to.
  local src
  src=$(ip -4 route get "${TARGET_HOST:-1.1.1.1}" 2>/dev/null \
          | sed -n 's/.* src \([0-9.]\{7,\}\).*/\1/p' | head -1)
  [ -n "$src" ] || return 1
  kubectl -n "$K8S_NAMESPACE" apply -f - >/dev/null 2>&1 <<YAML || return 1
apiVersion: v1
kind: Service
metadata: { name: fastpki-client }
spec:
  ports:
  - { name: http,  port: 80,  targetPort: 80 }
  - { name: https, port: 443, targetPort: 443 }
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: fastpki-client-1
  labels: { kubernetes.io/service-name: fastpki-client }
addressType: IPv4
ports:
- { name: http,  port: 80 }
- { name: https, port: 443 }
endpoints:
- addresses: ["$src"]
YAML
  DEMO_K8S_CLIENT_SVC="$K8S_NAMESPACE"
  DEMO_K8S_CLIENT_FQDN="fastpki-client.$K8S_NAMESPACE.svc.cluster.local"
  trap 'demo_undo_all; cleanup' EXIT INT TERM
  # ⚠️ WAIT FOR kube-proxy, OR THE FIRST CHALLENGE VALIDATES AGAINST NOTHING. `kubectl apply`
  # returns when the API server has the objects, not when every node's kube-proxy has
  # programmed the rules that make the ClusterIP reach this host. Measured: the http-01 cell
  # ran straight after this and the server reported
  #     http-01 validation failed: nothing answered on port 80 at the identifier
  # while the tls-alpn-01 cell, a few seconds later, passed against the SAME Service and the
  # same responder — the give-away that the address was right and simply not live yet.
  local _i
  for _i in 1 2 3 4 5 6 7 8 9 10; do
    kubectl -n "$K8S_NAMESPACE" get endpointslice fastpki-client-1 \
        -o jsonpath='{.endpoints[0].addresses[0]}' 2>/dev/null | grep -q '[0-9]' && break
    sleep 1
  done
  sleep 3
}

demo_undo_k8s_client(){
  [ -n "$DEMO_K8S_CLIENT_SVC" ] || return 0
  local ns="$DEMO_K8S_CLIENT_SVC"
  DEMO_K8S_CLIENT_SVC=""            # first, so a second call cannot loop
  kubectl -n "$ns" delete endpointslice fastpki-client-1 >/dev/null 2>&1 || true
  kubectl -n "$ns" delete service fastpki-client >/dev/null 2>&1 || true
  printf '  %sremoved the temporary fastpki-client Service%s\n' "$DIM" "$RST"
}

demo_undo_compose(){
  [ -n "$DEMO_COMPOSE_OVERRIDE" ] || return 0
  local cd_="${COMPOSE_DIR:-$ROOT/deploy}" f="$DEMO_COMPOSE_OVERRIDE"
  DEMO_COMPOSE_OVERRIDE=""          # first, so a second call cannot loop
  rm -f "$f"
  # Recreate acme WITHOUT the override so the service goes back to what it was.
  $demo_sudo docker compose -f "$cd_/docker-compose.yml" up -d --force-recreate acme \
      >/dev/null 2>&1 || true
  printf '  %sreverted the temporary acme override%s\n' "$DIM" "$RST"
}
# ⚠️ `up -d` RETURNS WHEN THE CONTAINER IS CREATED, NOT WHEN THE SERVER ANSWERS — and the
# very next thing this demo does is fetch the ACME directory. Measured on dc3: both challenge
# steps died on their FIRST request,
#
#     acme_order[http-01]: directory FAILED  status=000
#
# which is curl reporting "no response at all", not an ACME error. deploy/rolling-update.sh
# waits for each service's port for exactly this reason; this path recreated a service and
# then talked to it immediately.
#
# Separate from demo_acme_reachable() on purpose: that function's job is "write the override
# and recreate it", which is what tests/demo_acme_override.sh drives with a stubbed docker and
# no server at all. Folding the probe into it made that stub unsatisfiable.
#
# The probe asks for the directory itself rather than just opening the socket: a listener that
# is up but has not resolved its CA yet passes a bare connect and still fails the request.
# -k because the demo may be pointed at a self-signed deployment — this is a readiness check,
# not a trust decision; the order that follows uses the real chain.
demo_acme_ready(){
  local i code=000
  for i in $(seq 1 30); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "$ACME_DIR" 2>/dev/null || echo 000)
    [ "$code" = 200 ] && return 0
    sleep 1
  done
  printf '  %sfastpki-acme did not answer its directory after the restart (last: %s)%s\n' \
         "$DIM" "$code" "$RST"
  return 1
}


# Point the acme service at the CoreDNS that dns-auth.sh starts beside it, with the same
# override mechanism and the same revert as demo_acme_reachable below.
#
# ⚠️ THE RESOLVER IS A CONTAINER NAME, NOT THIS HOST — the same rule the remote variant
# states, and it is not interchangeable with the http-01 / tls-alpn-01 steps below, which
# DO name the host because their challenge servers run here. dns-auth.sh joins CoreDNS to
# the acme service's own compose network and publishes NOTHING ("with nothing exposed to
# the outside world", dns-auth.sh), so port 15353 on the docker host is closed. Naming the
# host — `host-gateway`, a bridge gateway, or any literal — sends the query where nothing
# is listening; the server gets no answer, cannot distinguish that from a name that has no
# records, and reports
#     dns-01 TXT record missing or mismatched
# which reads as a challenge fault rather than as a resolver never reached. Measured on the
# rc9 round-1 deployment, where the wildcard was the only failing step of the whole demo.
#
# Docker's embedded DNS resolves the container name on that network, so this needs no
# address, no `extra_hosts` and no platform knowledge. It is also why the acme service can
# be recreated here, BEFORE dns-auth.sh has started CoreDNS: src/acme/main.cpp resolves the
# configured name through getaddrinfo() at query time, not at startup, so the container
# that dns-auth.sh replaces per challenge is found at its new address every time.
demo_acme_dns_resolver(){   # <port> -> echoes the resolver value it configured
  local port=$1 cd_="${COMPOSE_DIR:-$ROOT/deploy}"
  local host=fastpki-dns
  local f="$cd_/docker-compose.demo-dns-$$.yml"
  cat > "$f" <<YML || { skip "(cannot write $f)"; return 1; }
# TEMPORARY — written by demo/pki-demo.sh and deleted when the demo ends.
services:
  acme:
    environment:
      ACME_DNS_RESOLVER: "$host:$port"
YML
  DEMO_COMPOSE_OVERRIDE="$f"
  # ⚠️ SUPERSET, INCLUDING cleanup. bash REPLACES traps, and this line used to install only
  # the override-revert -- silently displacing the cleanup handler set at startup, so a
  # run that reached a dns-01 cell never revoked the certificates it issued and never
  # removed its work directory. Name every handler the run still owes.
  trap 'demo_undo_all; cleanup' EXIT INT TERM
  if ! ${demo_sudo:-} docker compose -f "$cd_/docker-compose.yml" -f "$f" up -d --force-recreate acme >/dev/null 2>&1; then
    demo_undo_compose; skip "(could not restart fastpki-acme with the temporary resolver)"; return 1
  fi
  # ⚠️ THE READINESS PROBE BELONGS AT THE CALL SITE, NOT HERE. This function's job is
  # "write the override and recreate the service", which tests/demo_acme_override.sh drives
  # with a stubbed docker and no server at all — a probe in here makes that stub
  # unsatisfiable, which is why the http-01 path calls demo_acme_ready separately. The
  # wildcard cell does the same, immediately after this returns.
  # Same two-machine sentence as the remote variant: the setting changes on the acme
  # service, the nameserver it now queries is the CoreDNS container this demo started.
  printf '  %sset ACME_DNS_RESOLVER=%s:%s on the acme service, so it asks the CoreDNS this demo started (reverted at the end)%s\n' \
         "$DIM" "$host" "$port" "$RST"
  printf '%s' "$host:$port"
  return 0
}
acme_wildcard(){
  hdr "ACME (RFC 8555) — a WILDCARD certificate over dns-01"
  local base=wild-demo.internal DNSP=$DEMO_DNSP
  # ⚠️ THE GUARD DID NOT MATCH ITS OWN COMMENT. It said "ACME_DIR is the thing that says
  # so" and then also demanded TARGET_HOST -- which only a --target run sets. So once the
  # throwaway stack grew an ACME listener this cell still skipped, and it skipped saying
  # "no ACME directory", naming a cause that was no longer true. dns-01 needs nothing from
  # the host: the server resolves the challenge itself, which is exactly why this one is
  # not behind the sudo gate the other two challenges are.
  if [ -z "${ACME_DIR:-}" ]; then
    step "wildcard order"; skip "(no ACME directory for this target)"; return 0; fi
  if [ -z "${ACME_EAB_KID:-}" ] || [ -z "${ACME_EAB_HMAC:-}" ]; then
    step "wildcard order"
    skip "(no EAB credential for ${DEMO_USER:-this user} — a role that enrols gets one at first login)"
    return 0
  fi
  # ⚠️ CoreDNS, NOT build/dnsstub. This cell used to run our own resolver while the certbot
  # cell above drove the upstream coredns/coredns container — two resolvers for one job,
  # each with its own wiring and its own way of failing. The demo shows the product to a
  # person, so it should exercise the resolver a real deployment would actually meet;
  # dnsstub stays where the suites already depend on it. Both cells now publish through
  # demo/dns-auth.sh.
  if ! command -v docker >/dev/null 2>&1; then
    step "wildcard order"; skip "(docker is needed to run the CoreDNS resolver)"; return 0; fi
  # A stock deployment requires EAB, and the shell client can do it now.
  if [ -z "${ACME_EAB_KID:-}" ] || [ -z "${ACME_EAB_HMAC:-}" ]; then
    step "wildcard order"
    skip "(no EAB credential for ${DEMO_USER:-this user} — a role that enrols gets one at first login)"
    return 0
  fi
  # ⚠️ THE STEP THAT WAS MISSING, and the reason the wildcard run could never
  # go valid. This starts a dnsstub on THIS host while the ACME server is a CONTAINER: its
  # 127.0.0.1 is its own loopback, and with ACME_DNS_RESOLVER unset (the shipped default)
  # it queries its own /etc/resolv.conf, which has never heard of wild-demo.internal. The
  # authz stays pending until the order times out. Nothing about the wildcard logic was
  # wrong — the validator simply had no way to reach the answer.
  #
  # acme_enroll below has always done this dance for its own dns-01 run (it puts CoreDNS
  # on the compose network); this step never did.
  # ⚠️ THE RECONFIGURATION IS ONLY NEEDED WHEN THE SERVER IS SOMEONE ELSE'S. Against a
  # live target the validator is a container querying its own resolv.conf, so the demo has
  # to repoint it at this host's stub and put it back afterwards. The throwaway stack
  # starts fastpki-acme itself with ACME_DNS_RESOLVER already naming the stub, so there is
  # nothing to repoint -- and gating on a compose stack made this cell skip on the one
  # setup where dns-01 needs no dance at all.
  # How CoreDNS is reachable, decided once and handed to dns-auth.sh below:
  #   local  — join the compose network the ACME container is on, expose nothing
  #   remote — publish the port on this host, which is the only way another machine can ask
  local net_for_dns="${DEMO_PROJ:+${DEMO_PROJ}_default}"; : "${net_for_dns:=fastpki_default}"
  # Where CoreDNS should run: beside a LOCAL acme service on its compose network, on the
  # deployment itself over SSH, or — for a native target, which has no container runtime to
  # host it — here, with its port published so the deployment can reach back.
  local dns_ssh="" dns_pub_w=""
  if [ -z "${DEMO_LOCAL_ACME:-}" ]; then
    if docker compose -f "${COMPOSE_DIR:-$ROOT/deploy}/docker-compose.yml" ps --status running 2>/dev/null | grep -q 'acme.*Up'; then
      step "starting a CoreDNS beside the deployment for dns-01"
      if ! demo_acme_dns_resolver "$DNSP" >/dev/null; then return 0; fi
      ok
    else
      # A native target has no docker to host the resolver, so it stays here and the
      # deployment reaches back to it — see demo_acme_dns_resolver_remote.
      if [ "${DEPLOY_MODE:-}" = native ]; then dns_pub_w=1; else dns_ssh="${SSH_TARGET:-}"; fi
      # ⚠️ A REMOTE DEPLOYMENT CAN DO THIS TOO — it just cannot be done with a compose
      # override, because the compose file is on the other machine. ACME_DNS_RESOLVER is a
      # config-table key the server reads at startup, so writing it over SSH and restarting
      # fastpki-acme is the same manoeuvre by another route. This used to skip outright,
      # claiming dns-01 was "only possible against a compose stack this demo can
      # reconfigure", which was true of the MECHANISM and not of the challenge.
      step "starting a CoreDNS beside the deployment for dns-01"
      if ! demo_acme_dns_resolver_remote "$DNSP"; then return 0; fi
      ok
    fi
    # ⚠️ AND WAIT FOR THE SERVICE TO ANSWER BEFORE ORDERING. Both branches above RECREATE
    # fastpki-acme so it queries the CoreDNS this demo started, and `up -d` (or a remote
    # restart) returns when the container is created, not when the server is serving. The
    # very next act is fetching the ACME directory, so a restart slower than the guess
    # surfaced as
    #     acme_order[dns-01]: directory FAILED  status=000
    # — curl reporting no response at all, from a deployment that was healthy a second
    # later. Measured on the rc9 round-1 deployment, where the wildcard was the ONLY
    # failing step of the entire demo. The http-01 path already polls this way; this one
    # did not, and the remote branch guessed with `sleep 3`.
    if ! demo_acme_ready; then
      demo_undo_all
      step "wildcard order"; skip "(fastpki-acme did not answer its directory after the resolver was set)"
      return 0
    fi
  fi
  step "ordering *.$base"
  # The shell client asks dns-auth.sh to publish the TXT rather than starting a resolver of
  # its own; DNS_SSH_TARGET tells that script whether to start CoreDNS beside a local acme
  # service or on the deployment itself, which is where it belongs for a remote target.
  if ! ACME_DNS_PUBLISH_HOOK="$ROOT/demo/dns-auth.sh" \
       ZONE_DIR="$ROOT/demo/coredns" DNS_NET="$net_for_dns" \
       DNS_SSH_TARGET="$dns_ssh" DNS_PUBLISH="$dns_pub_w" DNS_PORT="$DNSP" DNS_K8S_NAMESPACE="${K8S_NAMESPACE:-}" DNS_SSH_OPTS="${DEMO_SSH_OPTS[*]}" \
       acme_dns01_order "$ACME_DIR" "*.$base" "0.0.0.0:$DNSP" wildcard.pem >wildcard-cli.log 2>&1; then
    fail "(see $WORK/wildcard-cli.log)"; demo_undo_all
    DNS_SSH_TARGET="$dns_ssh" DNS_PUBLISH="$dns_pub_w" DNS_PORT="$DNSP" DNS_K8S_NAMESPACE="${K8S_NAMESPACE:-}" DNS_SSH_OPTS="${DEMO_SSH_OPTS[*]}" "$ROOT/demo/dns-cleanup.sh" >/dev/null 2>&1
    return 1
  fi
  ok
  DNS_SSH_TARGET="$dns_ssh" DNS_PUBLISH="$dns_pub_w" DNS_PORT="$DNSP" DNS_K8S_NAMESPACE="${K8S_NAMESPACE:-}" DNS_SSH_OPTS="${DEMO_SSH_OPTS[*]}" \
    "$ROOT/demo/dns-cleanup.sh" >/dev/null 2>&1 || true
  # Decode the artifact — the whole point. A cert for the base name would satisfy "an
  # order completed", and that is the exact bug this step exists to catch.
  step "the issued certificate carries the wildcard SAN"
  local sans
  sans=$("$OSSL" x509 -in wildcard.pem -noout -ext subjectAltName 2>/dev/null | tr -d ' ')
  case "$sans" in
    *"DNS:*.$base"*) ok;;
    *) fail "(SAN is '$sans', expected DNS:*.$base)";;
  esac
  info "SAN:" "$sans"
  [ -z "${DEMO_LOCAL_ACME:-}" ] && demo_undo_all   # only if we changed it
}

case "$RUN_ACME" in
  no) ;;
  *)  acme_enroll;;   # dns-01 order — privilege-free, runs everywhere
esac
case "$RUN_ACME" in
  no) ;;
  *)  acme_wildcard;;
esac

# ── The other two RFC 8555 challenges ───────────────────────────────────────────
# Both challenge types should run, but only after establishing whether the user has sudo:
# if they do, the privileged commands run under sudo and the user is prompted for a
# password if one is required.
#
# Both need a privileged port on THIS host and neither can be moved:
#   http-01      RFC 8555 §8.3 fixes validation at port 80, and the server honours it.
#   tls-alpn-01  RFC 8737 validates over :443. The port is settable server-side
#                (ACME_TLS_ALPN_PORT), but that is the TARGET's config and this demo does
#                not edit someone's running deployment to make its own step pass.
#
# So the gate is the same for both: can we become root without a prompt we cannot answer?
# `sudo -n true` asks exactly that and never blocks. If it says no we do NOT give up — we
# try an interactive `sudo -v` once, which is the prompt we want, and only skip if
# that fails too.
have_sudo(){
  [ "$(id -u)" = 0 ] && { demo_sudo=""; return 0; }          # already root: no sudo needed
  command -v sudo >/dev/null 2>&1 || return 1
  sudo -n true 2>/dev/null && { demo_sudo="sudo"; return 0; }  # cached/NOPASSWD
  printf '  %sthese two ACME challenges need a privileged port — asking for sudo%s\n' "$DIM" "$RST"
  sudo -v 2>/dev/null && { demo_sudo="sudo"; return 0; }
  return 1
}

demo_acme_reachable(){   # <domain>
  local domain=$1 cd_="${COMPOSE_DIR:-$ROOT/deploy}"
  local f="$cd_/docker-compose.demo-$$.yml"
  # ⚠️ Written with the demo's OWN pid in the name. Two demos on one host must not delete
  # each other's override, and a leftover from a killed run must not be silently adopted.
  cat > "$f" <<YML || { skip "(cannot write $f)"; return 1; }
# TEMPORARY — written by demo/pki-demo.sh and deleted when the demo ends.
# If you are reading this in a running deployment, a demo was killed; deleting it and
# running \`docker compose up -d --force-recreate acme\` restores the original service.
services:
  acme:
    extra_hosts:
      - "$domain:host-gateway"
YML
  DEMO_COMPOSE_OVERRIDE="$f"
  # ⚠️ SUPERSET, INCLUDING cleanup. bash REPLACES traps, and this line used to install only
  # the override-revert -- silently displacing the cleanup handler set at startup, so a
  # run that reached a dns-01 cell never revoked the certificates it issued and never
  # removed its work directory. Name every handler the run still owes.
  trap 'demo_undo_all; cleanup' EXIT INT TERM
  if ! $demo_sudo docker compose -f "$cd_/docker-compose.yml" -f "$f" up -d --force-recreate acme >/dev/null 2>&1; then
    demo_undo_compose
    skip "(could not restart fastpki-acme with the temporary $domain route)"
    return 1
  fi
  printf '  %sadded a temporary %s route to the acme service (reverted at the end)%s\n' \
         "$DIM" "$domain" "$RST"
  return 0
}

acme_challenge_priv(){   # <label> <chtype> <port>
  # ⚠️ AGAINST A REMOTE TARGET, THE NAME MUST BE ONE THE SERVER CAN ALREADY RESOLVE TO US.
  # The compose-override path below teaches a LOCAL acme container to resolve
  # chal-demo.internal; a remote deployment has no such container here, so the override is
  # never applied and the server answered "the identifier does not resolve" — correctly,
  # because chal-demo.internal means nothing to it.
  #
  # The fix is not to reconfigure someone's deployment: it is to order a certificate for a
  # name that already points at this host. On a lab reachable over a mesh VPN that is this
  # machine's own peer name — CHALLENGE_FQDN=<this-host>.<mesh-domain> — which the server
  # resolves through its ordinary resolver and then connects back to on port 80/443.
  local label=$1 chtype=$2 port=$3 domain="${CHALLENGE_FQDN:-chal-demo.internal}"
  hdr "ACME (RFC 8555) — a certificate over $label"
  # These two cells reconfigure the COMPOSE deployment's acme service and take ports
  # 80/443 on this host. A throwaway stack lives under its own project name with its own
  # staged file, so "restart deploy/acme" targets nothing that exists here — and the
  # dns-01 cells above have already exercised the same order flow end to end.
  if [ "${MODE:-}" = "throwaway" ]; then
    step "$label order"
    skip "(throwaway run: dns-01 above covers the ACME order flow; this cell needs host ports 80/$([ "$port" = 80 ] || echo 443))"
    return 0
  fi
  if [ -z "${ACME_DIR:-}" ]; then
    step "$label order"; skip "(no ACME directory for this target)"; return 0; fi
  if [ -z "${ACME_EAB_KID:-}" ] || [ -z "${ACME_EAB_HMAC:-}" ]; then
    step "$label order"
    skip "(no EAB credential for ${DEMO_USER:-this user} — a role that enrols gets one at first login)"
    return 0
  fi
  if ! have_sudo; then
    step "$label order"
    skip "(needs port $port on this host and sudo is not available — the same flow is covered unprivileged by tests/acme_preauth_alpn.sh and tests/acme_lifecycle.sh)"
    return 0
  fi
  # ⚠️ THE SERVER VALIDATES, SO THE SERVER MUST REACH US — and in every deployment we
  # ship, fastpki-acme runs in a CONTAINER. A responder on this host's 127.0.0.1 and a
  # line in this host's /etc/hosts are both invisible to it: inside the container that
  # address is the container. Measured on a real DC, both challenges reached the authz
  # and then sat at "pending" until the poll gave up.
  #
  # dns-01 does not have this problem, which is why the two steps above work: the server
  # is pointed at a resolver, so the answer comes to IT rather than it coming to us.
  #
  # Making this work needs the ACME service to resolve $domain to the docker host.
  # Modifying the deployment for the demo is acceptable as long as the change is
  # reverted when the demo is done. So the demo adds it — and takes it
  # away again, in an EXIT trap so a Ctrl-C or a failed step cannot leave it behind.
  #
  # ⚠️ A SEPARATE OVERRIDE FILE, never an edit to docker-compose.yml. Reverting an edit
  # means reproducing the original text exactly, and a demo that half-restores someone's
  # compose file is worse than one that skips. Deleting a file we created cannot go
  # half-right, and `docker compose` merges `-f base -f override` natively.
  if [ -n "$(docker compose -f "${COMPOSE_DIR:-$ROOT/deploy}/docker-compose.yml" ps -q acme 2>/dev/null)" ]; then
    demo_acme_reachable "$domain" || { step "$label order"; return 0; }
    if ! demo_acme_ready; then
      demo_undo_compose
      step "$label order"; skip "(fastpki-acme did not come back after the $domain route was added)"
      return 0
    fi
  else
    # No local acme container: the deployment is remote, so nothing here can teach it to
    # resolve a made-up name. Refuse rather than order something that cannot validate.
    # On a cluster the name can be made rather than required — see demo_k8s_client_fqdn.
    if [ -z "${CHALLENGE_FQDN:-}" ] && [ -n "${K8S_NAMESPACE:-}" ]; then
      # No command substitution — see demo_k8s_client_publish.
      if demo_k8s_client_publish; then
        CHALLENGE_FQDN="$DEMO_K8S_CLIENT_FQDN"
        # ⚠️ AND THE DOMAIN THIS CELL IS ABOUT TO ORDER. `domain` was fixed at the top of the
        # function from CHALLENGE_FQDN, which was empty then — so without this the order goes
        # out for chal-demo.internal, the invented name meant for a LOCAL compose deployment,
        # and the cluster is asked to validate a name that resolves nowhere. Measured: the
        # first cell failed on chal-demo.internal while the second passed, because by then
        # this assignment's side effect on the global had reached it.
        domain="$CHALLENGE_FQDN"
        printf '  %spublished this host to the cluster as %s%s\n' \
            "$DIM" "$CHALLENGE_FQDN" "$RST" >&2
      fi
    fi
    if [ -z "${CHALLENGE_FQDN:-}" ]; then
      step "$label order"
      skip "(remote target: set CHALLENGE_FQDN to a name this deployment already resolves to THIS host — e.g. its mesh/VPN peer name — since the server connects back to it on port $port)"
      return 0
    fi
  fi
  # ⚠️ ONLY MAP IT LOCALLY WHEN IT IS OUR OWN INVENTED NAME. With CHALLENGE_FQDN the name
  # is real and already resolves — pinning it to 127.0.0.1 in this host's /etc/hosts would
  # be harmless for the responder but is a change to the operator's machine that buys
  # nothing, and it would outlive the run if the trap were missed.
  if [ -z "${CHALLENGE_FQDN:-}" ] && ! grep -q "$domain" /etc/hosts 2>/dev/null; then
    $demo_sudo sh -c "printf '127.0.0.1 %s\n' '$domain' >> /etc/hosts" 2>/dev/null \
      || { step "$label order"; skip "(could not add $domain to /etc/hosts)"; return 0; }
    DEMO_HOSTS_ADDED="$domain"
  fi
  step "ordering $domain over $label"
  rm -f "chal-$chtype.pem"
  # ⚠️ The two entry points do NOT take the same arguments — acme_alpn01_order carries the
  # responder port as $3 (RFC 8737 lets it move), acme_http01_order does not (RFC 8555 §8.3
  # pins it at 80). Calling them with one shared arg list put the output filename in the
  # port slot, which produced an order that failed for a reason unrelated to the challenge.
  local call
  case "$chtype" in
    tls-alpn-01) call="acme_alpn01_order '$ACME_DIR' '$domain' $port 'chal-$chtype.pem'";;
    http-01)     call="acme_http01_order '$ACME_DIR' '$domain' 'chal-$chtype.pem'";;
    *)           fail "(unknown challenge $chtype)"; return 1;;
  esac
  # ⚠️ CARRY THE EAB CREDENTIAL ACROSS THE sudo BOUNDARY. Without it acme_new_account
  # falls through to acme_seed_eab, which PROVISIONS one by writing a keys row — and that
  # needs pg_exec and a suite's seeded database, neither of which exists here. The failure
  # surfaced as "newAccount FAILED status=200" against a directory that plainly says
  # externalAccountRequired, which points at the server rather than at the missing env.
  # `sudo -E` does not help: sudo strips these by policy, so they are named explicitly.
  #
  # ⚠️ `-E` BELONGS TO sudo, SO IT ONLY EXISTS WHEN sudo DOES. have_sudo() sets
  # $demo_sudo to "" when we are ALREADY root — the correct thing, since no sudo is
  # needed — but the line then began with a bare `-E`, which the shell tried to run as a
  # command:
  #
  #     demo/pki-demo.sh: line 1194: -E: command not found
  #
  # Both privileged challenges failed, on every run as root, with the failure recorded in
  # chal-<type>.log where it looks like an ACME problem. Building the prefix as an array
  # is what makes the two cases actually differ instead of differing by one stray word.
  local runner=()
  [ -n "$demo_sudo" ] && runner=("$demo_sudo" -E)
  runner+=(env "PATH=$PATH" "OSSL=${OSSL:-openssl}"
           "ACME_DNSSTUB=${ACME_DNSSTUB:-}" "JWS_TMP=$WORK/jws-$chtype"
           "ACME_EAB_KID=${ACME_EAB_KID:-}" "ACME_EAB_HMAC=${ACME_EAB_HMAC:-}")
  local rc_priv=0
  "${runner[@]}" \
        bash -c "mkdir -p '$WORK/jws-$chtype'; cd '$WORK'; . '$ROOT/tests/acme_jws.sh'; $call" \
        >"chal-$chtype.log" 2>&1 || rc_priv=$?
  # ⚠️ GIVE THE FILES BACK BEFORE DOING ANYTHING ELSE. Everything the block above wrote —
  # jws-<type>/ and its request/response bodies — is owned by root when we went through
  # sudo, and cleanup() runs unprivileged. The run ended with a page of
  #     rm: .../jws-http-01/req.json: Permission denied
  #     rm: .../.demo-XXXXXX: Directory not empty
  # and a work directory left behind on a SUCCESSFUL run. Done on the failure path too,
  # which is exactly when those logs need to be readable.
  [ -n "$demo_sudo" ] && $demo_sudo chown -R "$(id -u):$(id -g)" "$WORK" 2>/dev/null || true
  if [ "$rc_priv" -ne 0 ]; then
    fail "(see $WORK/chal-$chtype.log)"; return 1
  fi
  ok
  # Decode it. "the order completed" is not the claim — the claim is that THIS CA issued a
  # certificate for THIS name over THIS challenge.
  step "the issued certificate is for $domain"
  local sans; sans=$("$OSSL" x509 -in "chal-$chtype.pem" -noout -ext subjectAltName 2>/dev/null | tr -d ' ')
  case "$sans" in *"DNS:$domain"*) ok;; *) fail "(SAN is '$sans')";; esac
  info "SAN:" "$sans"
}

case "$RUN_ACME" in
  no) ;;
  *)  acme_challenge_priv "http-01"     http-01     80
      acme_challenge_priv "tls-alpn-01" tls-alpn-01 443
      [ -n "${DEMO_HOSTS_ADDED:-}" ] && $demo_sudo sed -i.bak "/$DEMO_HOSTS_ADDED/d" /etc/hosts 2>/dev/null
      demo_undo_compose
      ;;
esac

# ── the matrix itself ────────────────────────────────────────────────────────
# Throwaway mode exists FOR these. On a live target they are skipped: re-keying
# someone's production credentials or creating ten CAs on it is not a demo.
if [ "${MODE:-}" = "throwaway" ]; then
  if [ "$FULL_MATRIX" = 1 ]; then
    run_full_matrix   # the whole cross-product, one full lifecycle per cell
  else
    sweep_ca_keys
    sweep_server_keys
    sweep_client_keys
    sweep_hashes
  fi
fi

tls_verify

# The run reached its end under its own power. Only now may cleanup() remove the working
# directory — see the guard there for why a subshell's inherited EXIT trap must not.
DEMO_COMPLETE=1

hdr "Demo complete"
# ⚠️ DO NOT NAME PROTOCOLS HERE. This line read "Real clients drove enroll
# (EST/CMP/SCEP), status + revoke (OCSP/CMP), and search (Store) end to end" and printed
# unconditionally — so a run where SCEP skipped for want of a client, and both ACME cells
# skipped for want of a challenge name, still ended by claiming all of them drove
# certificates end to end. The steps above already say which ran; this says how many did
# not, which is the part an operator would otherwise have to count by eye.
printf '  %sReal clients drove the enrolment, status, revocation and search steps above.%s\n' "$DIM" "$RST"
[ "$DEMO_SKIP" -eq 0 ] || printf '  %s%s step(s) skipped — each says why above.%s\n' "$YEL" "$DEMO_SKIP" "$RST"
printf '\n'
[ "$DEMO_FAIL" -eq 0 ] || { printf '  %s%s step(s) failed%s\n\n' "$RED" "$DEMO_FAIL" "$RST"; exit 1; }
