#!/usr/bin/env bash
# FastPKI throughput benchmark. Measures operations per second with
# REAL clients against EITHER a throwaway deployment it spins up and tears down,
# OR a live deployment pointed to via --target (same descriptor as pki-demo.sh):
#   enroll   est cmp scep   — certificates issued /s, per key type
#   status   ocsp           — OCSP status checks /s (against a pre-issued cert)
#   search   store          — RFC 4387 store searches /s
#   enroll   acme           — full RFC 8555 http-01 orders /s (certbot)
#
#   demo/pki-bench.sh [-n COUNT] [-k "keytypes"] [-p "protocols"] [--target FILE]
#     -n COUNT      operations per (protocol,keytype) cell         (default 50)
#     -k KEYTYPES   space-separated key types to test              (default all)
#     -p PROTOS     comma-separated protocols to test              (default all)
#     --target FILE target a live deployment (like pki-demo.sh)    (default throwaway)
#
# Available key types:
#   rsa2048 rsa3072 ec256 ec384 ed25519 rsapss2048 rsapss3072
#   mldsa44 mldsa65 mldsa87
#
# Available protocols:
#   est cmp scep ocsp store acme
#
# Examples:
#   demo/pki-bench.sh -n 100 -p "est,cmp"                          # throwaway, 100 ops
#   demo/pki-bench.sh --target demo/.target.env -p "est,cmp,acme"  # live deployment
#
# WHY est/scep look slower than cmp — it's the CLIENT, not the server. `openssl
# cmp` builds the request, does the HTTP round-trip and parses the response in ONE
# process. EST/SCEP have no single integrated CLI, so the client is orchestrated
# from several tools (curl + openssl/scep-testclient) and, for EST, runs over TLS
# (a handshake per enrollment — EST is HTTPS-only). To keep the number about the
# SERVER we exclude local key/CSR generation (pre-generated) and, for EST, use a
# single-process curl that just checks the HTTP status. The residual est>cmp gap
# is the TLS handshake, an architectural property of EST, not issuance cost.
#
# Honours $OSSL / $OPENSSL_LIBDIR like the rest of the suite.

set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# ⚠️ HELP IS ANSWERED BEFORE ANYTHING IS SOURCED, and it is real usage rather than a sed
# of this file's own header. There were TWO handlers printing two different ranges of the
# comment block — `2,/^$/p` here and `2,22p` in the argument loop — so the answer depended
# on which one you reached, and neither was a description of the flags.
usage(){ cat <<'HELPTEXT'
demo/pki-bench.sh - measure server-side throughput per protocol and key type.

  demo/pki-bench.sh [options]

  -n COUNT        iterations per cell (default 50).
  -k "A B"        client key types to sweep. Quote the list. Any of:
                    rsa2048 rsa3072 ec256 ec384 ed25519
                    rsapss2048 rsapss3072 mldsa44 mldsa65 mldsa87
                  (all ten by default; NO separator - rsa2048, not rsa:2048,
                   which is the demo's spelling, not the bench's)
  -p "A B"        protocols to run, space- or comma-separated. Any of:
                    est cmp scep ocsp store acme
  --target FILE   bench a LIVE deployment described by FILE, instead of a
                  throwaway one. Create one with demo/provision-target.sh.
  -h, --help      this text.

  Rates are server-side throughput; local key and CSR generation are excluded.
  ⚠️ That holds for a throwaway run, where the server is on this machine. With
  --target every operation crosses the network to the deployment, so the rate
  includes the round trip and is not comparable with a local run.

EXAMPLES
  demo/pki-bench.sh -n 10
  demo/pki-bench.sh -n 50 -p "est cmp" -k "rsa2048 ec256"
  demo/pki-bench.sh --target demo/.target.env -p acme
HELPTEXT
}
for a; do case "$a" in -h|--help|help) usage; exit 0;; esac; done

# The first thing a user sees. Everything between here and the banner further down is
# setup, and a stall in it would otherwise show a terminal that has printed nothing at
# all — which leaves nobody anything to report but "it sits there". Same reason, and the
# same line, as the clients demo.
printf 'FastPKI throughput benchmark: loading helpers...\n' >&2

BIN="${FASTPKI_BIN:-$ROOT/build}"
source "$ROOT/tests/hsm_helpers.sh"
# ⚠️ pg_helpers.sh ends in pg_ensure_server, so SOURCING it probed 127.0.0.1:5432,
# created or upgraded the `fastpki` and `pki` databases on whatever Postgres the operator
# had running, and printed five lines of harness diagnostics — at someone who had typed
# `pki-bench.sh --target`, which drives a LIVE deployment and never opens a local database.
# pg_setup() (the throwaway branch, below) ensures a cluster itself.
FASTPKI_PG_AUTOSTART=0
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
# scep_challenge_for lives here. cmp_helpers sources it only on a branch, so take
# the dependency explicitly rather than relying on which branch ran.
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"
[ -f "$ROOT/demo/testclient.sh" ] && . "$ROOT/demo/testclient.sh"   # run the enrolment clients from the image when this host has no build
if [ -z "${OSSL:-}" ]; then
  if [ -x /opt/openssl-3.5/bin/openssl ]; then OSSL=/opt/openssl-3.5/bin/openssl
  else OSSL="$(command -v openssl)"; fi
fi
if [ -z "${OPENSSL_LIBDIR:-}" ] && [ -d /opt/openssl-3.5/lib64 ]; then export LD_LIBRARY_PATH=/opt/openssl-3.5/lib64
elif [ -n "${OPENSSL_LIBDIR:-}" ]; then export LD_LIBRARY_PATH=$OPENSSL_LIBDIR; fi
case "$OSSL" in /opt/homebrew/*|/usr/local/*) export DYLD_LIBRARY_PATH="$(dirname "$(dirname "$OSSL")")/lib:${DYLD_LIBRARY_PATH:-}";; esac
# ⚠️ Only adopt the system openssl.cnf where it really IS one. On macOS this path is a
# stub that defines no providers, and exporting it breaks every pkcs11 load — the CA key
# then cannot be minted and this script fails for a reason that looks nothing like
# "wrong openssl.cnf". Every suite in tests/ already guards it this way (§3d); these two
# did not, which is the same portability bug one directory along.
if [ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null; then
  export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
fi
export PGPASSWORD="${PGPASSWORD:-fastpki}"
if ! command -v psql >/dev/null 2>&1; then
  _psql_hint=$(ls /opt/homebrew/Cellar/libpq/*/bin/psql 2>/dev/null | tail -1)
  if [ -n "$_psql_hint" ]; then export PATH="$(dirname "$_psql_hint"):$PATH"; fi
fi

COUNT=50; KEYTYPES="rsa2048 rsa3072 ec256 ec384 ed25519 rsapss2048 rsapss3072 mldsa44 mldsa65 mldsa87"
PROTOS="est cmp scep ocsp store acme"; TARGET_FILE=""; COUNT_SET=""
while [ $# -gt 0 ]; do
  case "$1" in
    -n) COUNT="$2"; COUNT_SET=1; shift 2;;  -k) KEYTYPES="$2"; shift 2;;  -p) PROTOS="${2//,/ }"; shift 2;;
    --target) TARGET_FILE="$2"; shift 2;
      case "$TARGET_FILE" in /*) ;; *) TARGET_FILE="$PWD/$TARGET_FILE";; esac  # resolve before cd
      ;;
    -h|--help) usage; exit 0;;
    *) echo "unknown option: $1" >&2
       echo "run 'demo/pki-bench.sh --help' for the accepted options." >&2
       exit 2;;
  esac
done

if [ -t 1 ]; then B=$'\e[1m'; DIM=$'\e[2m'; CYN=$'\e[36m'; RST=$'\e[0m'; else B=; DIM=; CYN=; RST=; fi
# ⚠️ NO perl. The Alpine runtime image does not ship it — the Dockerfile says as much where
# it uses `openssl rehash` rather than `c_rehash` — so running the bench ON a FastPKI node
# printed "perl: command not found" for every measurement, fed the empty result to awk
# ("awk: cmd. line:1: Unexpected token"), and produced a table with a correct issued count
# and BLANK rates. A benchmark that silently reports no numbers is worse than one that
# refuses, because the count beside the blank looks like a successful run.
#
# bash 5 has microsecond time built in and costs no process. The decimal separator follows
# the locale, so a comma is normalised to a dot before awk sees it.
now(){
  if [ -n "${EPOCHREALTIME:-}" ]; then
    printf '%s\n' "${EPOCHREALTIME/,/.}"
    return
  fi
  # Both GNU and busybox date understand %N; a shell with neither yields a literal "N", so
  # fall back to whole seconds rather than emitting something awk will read as garbage.
  _t=$(date +%s.%N 2>/dev/null)
  case "$_t" in *N*|'') date +%s ;; *) printf '%s\n' "$_t" ;; esac
}

WORK="$(mktemp -d)"; cd "$WORK"; pids=(); KEEP_WORK=0
# ⚠️ EVERY NAME THIS RUN ENROLS CARRIES THIS TOKEN, so the cleanup below revokes
# exactly what this run issued. Without it the CN pattern matched every bench-shaped
# certificate the account owned: the count claimed "this run issued" about earlier
# runs' certificates, and two people benchmarking one deployment at the same time
# revoked each other's.
BENCH_RUN=$(od -An -N3 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
[ -n "$BENCH_RUN" ] || BENCH_RUN=$$

# ── the bench cleans up after itself in LIVE mode ─────────────────────
# A demo run must clean up after itself — revoke the certificates it requested — so the
# next run does not hit the per-CN issuance cap.
#
# The bench is the one that MATTERS for this: a run issues COUNT certificates per protocol
# per key type — the default is 50 x 3 x 10 — and left every one of them active. The second
# run then walks into the per-requester cap and measures
# refusals instead of issuance.
#
# ⚠️ REVOKE BY THE CNs THIS RUN USED, and nothing else. Every certificate the bench mints is
# `b-<keytype>-<n>.$DEMO_DOMAIN`, plus the two fixed ones below — so the filter is narrow and
# cannot reach a certificate a human created. It goes through the console's own revoke API,
# not a psql UPDATE, so the CRL, OCSP and the audit trail all follow (the same correction
# pki-demo.sh needed).
revoke_bench_certs(){
  [ "${MODE:-}" = live ] && [ -n "${TARGET_HOST:-}" ] && [ -n "${DEMO_USER:-}" ] || return 0
  local api="https://$TARGET_HOST:${WEB_PORT:-8090}" jar="$WORK/.bench.cj" n=0 gone=0 code
  curl -sk -c "$jar" --max-time 10 -X POST \
       -d "username=${DEMO_USER}&password=${DEMO_PASS:-}" "$api/api/login" -o /dev/null 2>/dev/null || return 0
  curl -sk -b "$jar" --max-time 30 "$api/api/certs" -o "$WORK/inv.json" 2>/dev/null || return 0
  # ⚠️ ONE RECORD PER LINE, and NOT with `tr`. `tr '}' '}\n'` truncates SET2 to SET1's
  # length, so it maps } to } — a no-op. It silently left the whole inventory on one line,
  # the CN filter then matched that single line once, and the cleanup reported
  # "revoked 1/1" after a run that issued three. The counter counts what it FOUND, so a
  # broken extractor reads as a clean success. Split between records with sed.
  #
  # Matching serial and cn on the SAME line is the point: grepping the whole blob for
  # serials would collect every certificate this account owns, ignoring the CN filter.
  sed 's/},{/}\n{/g' "$WORK/inv.json" \
    | grep -E '"cn"[[:space:]]*:[[:space:]]*"(b-'"$BENCH_RUN"'-[a-z0-9]+-[0-9]+|ocsp-bench-'"$BENCH_RUN"'|store-bench-'"$BENCH_RUN"')\.'"$(printf '%s' "$DEMO_DOMAIN" | sed 's/\./\\./g')"'"' \
    | sed -nE 's/.*"serial"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' > "$WORK/bench-serials.txt"
  [ -s "$WORK/bench-serials.txt" ] || return 0
  while read -r ser; do
    [ -n "$ser" ] || continue
    n=$((n+1))
    code=$(curl -sk -b "$jar" --max-time 10 -o /dev/null -w '%{http_code}' \
           -X POST "$api/api/certs/$ser/revoke?reason=5" 2>/dev/null)
    [ "$code" = 200 ] && gone=$((gone+1))
  done < "$WORK/bench-serials.txt"
  printf '  %scleanup:%s revoked %s/%s certificate(s) this run issued\n' "${DIM:-}" "${RST:-}" "$gone" "$n"
}

cleanup(){
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
  docker rm -f fastpki-bench-http >/dev/null 2>&1 || true
  # The webroot is not always under $WORK — see acme_pick_webroot. Whatever it chose
  # outside $WORK is ours, and rm -rf "$WORK" would never touch it.
  [ -n "${ACME_WEBROOT_TMP:-}" ] && rm -rf "$ACME_WEBROOT_TMP"
  revoke_bench_certs || true
  if [ -n "${PGDB:-}" ]; then psql -h localhost -U "$PGUSER" -d postgres -c "DROP DATABASE IF EXISTS $PGDB" >/dev/null 2>&1 || true; fi
  if [ -n "${ACDB:-}" ]; then psql -h localhost -U "$PGUSER" -d postgres -c "DROP DATABASE IF EXISTS $ACDB" >/dev/null 2>&1 || true; fi
  [ "$KEEP_WORK" = 1 ] && { echo "  logs kept: $WORK" >&2; return; }
  rm -rf "$WORK"
}
trap cleanup EXIT

genkey(){ # <type> <outfile>
  case "$1" in
    rsa2048)   "$OSSL" genrsa -out "$2" 2048 >/dev/null 2>&1;;
    rsa3072)   "$OSSL" genrsa -out "$2" 3072 >/dev/null 2>&1;;
    ec256)     "$OSSL" ecparam -name prime256v1 -genkey -noout -out "$2" >/dev/null 2>&1;;
    ec384)     "$OSSL" ecparam -name secp384r1  -genkey -noout -out "$2" >/dev/null 2>&1;;
    ed25519)   "$OSSL" genpkey -algorithm Ed25519 -out "$2" >/dev/null 2>&1;;
    rsapss2048) "$OSSL" genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha256 -out "$2" >/dev/null 2>&1;;
    rsapss3072) "$OSSL" genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:3072 -pkeyopt rsa_pss_keygen_md:sha256 -out "$2" >/dev/null 2>&1;;
    mldsa44)   "$OSSL" genpkey -algorithm ML-DSA-44 -out "$2" >/dev/null 2>&1;;
    mldsa65)   "$OSSL" genpkey -algorithm ML-DSA-65 -out "$2" >/dev/null 2>&1;;
    mldsa87)   "$OSSL" genpkey -algorithm ML-DSA-87 -out "$2" >/dev/null 2>&1;;
    *) echo "unknown key type $1" >&2; return 1;;
  esac
}
keylabel(){ case "$1" in rsa2048) echo "RSA-2048";; rsa3072) echo "RSA-3072";; ec256) echo "EC P-256";; ec384) echo "EC P-384";; ed25519) echo "Ed25519";; rsapss2048) echo "RSA-PSS-2048";; rsapss3072) echo "RSA-PSS-3072";; mldsa44) echo "ML-DSA-44";; mldsa65) echo "ML-DSA-65";; mldsa87) echo "ML-DSA-87";; esac; }
port_up(){ (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&- 3<&-; return 0; }; return 1; }
need(){ case " $PROTOS " in *" $1 "*) return 0;; *) return 1;; esac; }

# ⚠️ THE BANNER PRINTS AFTER THE MODE IS KNOWN. It used to print here, before the target
# file was read — so a live run announced "n=50/cell" and then benched 10, which is the
# kind of small lie that makes someone distrust the numbers underneath it.
bench_banner(){
  printf '%s FastPKI throughput benchmark %s  %sopenssl %s · n=%s/cell%s\n' \
    "$B" "$RST" "$DIM" "$("$OSSL" version 2>/dev/null | awk '{print $2}')" "$COUNT" "$RST"
  # Name the measurement before the numbers, not only after them. Against a remote target
  # the client is here and the server is there, so each operation pays a round trip and the
  # rate is this link as much as that deployment.
  [ "$MODE" = live ] && printf '%s  measuring over the network to %s — rates include the round trip%s\n' \
    "$DIM" "${TARGET_HOST:-the target}" "$RST"
  return 0
}

# ── mode dispatch ─────────────────────────────────────────────────────────────
if [ -n "$TARGET_FILE" ]; then
  MODE=live
  # ⚠️ FEWER ITERATIONS AGAINST A LIVE TARGET, unless the operator asked for a number. A
  # remote deployment answers over the network, and every enrolment is a round trip plus a
  # signature on someone else's hardware: 50 iterations across ten key types is a long wait
  # and a lot of certificates to issue and revoke on a machine that is not ours. Ten is
  # enough to compare key types, which is what this is for. -n still wins.
  [ -n "$COUNT_SET" ] || COUNT=10
  bench_banner
  printf '  %sTargeting live deployment: %s%s\n' "$DIM" "$TARGET_FILE" "$RST"
  [ -f "$TARGET_FILE" ] || { echo "target file not found: $TARGET_FILE" >&2; exit 2; }
  source "$TARGET_FILE"
  : "${TARGET_HOST:?target file missing TARGET_HOST}"
  : "${DEMO_USER:?target file missing DEMO_USER}"
  : "${DEMO_PASS:?target file missing DEMO_PASS}"
  : "${CA_ID:?target file missing CA_ID}"
  # Reaching the deployment to stand a CoreDNS beside it for dns-01. Same key and options
  # provision-target.sh used, flattened to a string because the hooks are separate
  # processes and cannot inherit a bash array.
  BENCH_SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes"
  [ -f "$HOME/.ssh/fastpki_lab_ed25519" ] && BENCH_SSH_OPTS="$BENCH_SSH_OPTS -i $HOME/.ssh/fastpki_lab_ed25519"
  BENCH_DNS_PREV=""; BENCH_DNS_SET=""
  # Where CoreDNS runs for this target: beside the deployment over ssh (compose), or here
  # with its port published (native, which has no docker of its own to host it).
  BENCH_DNS_SSH=""; BENCH_DNS_PUB=""
  # ⚠️ A NATIVE TARGET HAS NO CONTAINER TO EXEC INTO, and no cluster either. Its CLI is on
  # the PATH and reads /etc/fastpki/bootstrap.conf, so the docker form below finds nothing,
  # exits 3, and the whole ACME leg skips with "could not set the resolver on the target".
  # DEPLOY_MODE comes from the descriptor; provision-target.sh writes it for that shape.
  # Kept beside the demo's demo_remote_cfg deliberately — same three shapes, same order.
  bench_native_cfg(){   # <args...>
    ssh $BENCH_SSH_OPTS "$SSH_TARGET" \
        "doas -u fastpki fastpki-config --config /etc/fastpki/bootstrap.conf $*" 2>/dev/null
  }
  bench_restart_acme(){
    if [ -n "${K8S_NAMESPACE:-}" ]; then
      # Every server's acme container, restarted in place — the Service spreads orders across
      # the servers, and one still holding the old resolver answers dns-01 from cluster DNS.
      # The restart is counted before the port is checked: the old process can still be
      # listening a moment after the kill, and a port check alone would pass on it.
      _jp='{.status.containerStatuses[?(@.name=="acme")].restartCount}'
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
    if [ "${DEPLOY_MODE:-}" = native ]; then
      ssh $BENCH_SSH_OPTS "$SSH_TARGET" 'doas rc-service fastpki-acme restart' >/dev/null 2>&1
      return $?
    fi
    ssh $BENCH_SSH_OPTS "$SSH_TARGET" 'a=$(docker ps --format "{{.Names}}" | grep -m1 -iE "acme"); [ -n "$a" ] && docker restart "$a" >/dev/null 2>&1' >/dev/null 2>&1
  }
  bench_remote_cfg(){   # <args...> — fastpki-config inside the target's web container
    if [ -n "${K8S_NAMESPACE:-}" ]; then
      kubectl -n "$K8S_NAMESPACE" exec statefulset/fastpki-node -c web -- \
        fastpki-config --config /app/config/bootstrap.conf "$@" 2>/dev/null
      return $?
    fi
    if [ "${DEPLOY_MODE:-}" = native ]; then bench_native_cfg "$@"; return $?; fi
    ssh $BENCH_SSH_OPTS "$SSH_TARGET" "sh -s -- $*" <<'RSH' 2>/dev/null
w=$(docker ps --format "{{.Names}}" 2>/dev/null | grep -m1 -iE "web")
[ -n "$w" ] || exit 3
docker exec "$w" fastpki-config --config /app/config/bootstrap.conf "$@"
RSH
  }
  bench_undo_remote_dns(){
    [ -n "$BENCH_DNS_SET" ] || return 0
    BENCH_DNS_SET=""
    if [ -n "$BENCH_DNS_PREV" ]; then bench_remote_cfg set ACME_DNS_RESOLVER "$BENCH_DNS_PREV" >/dev/null 2>&1 || true
    else bench_remote_cfg unset ACME_DNS_RESOLVER >/dev/null 2>&1 || true; fi
    bench_restart_acme || true
    DNS_SSH_TARGET="$BENCH_DNS_SSH" DNS_PUBLISH="$BENCH_DNS_PUB" DNS_PORT=15353 \
      DNS_K8S_NAMESPACE="${K8S_NAMESPACE:-}" \
      DNS_SSH_OPTS="$BENCH_SSH_OPTS" "$ROOT/demo/dns-cleanup.sh" >/dev/null 2>&1 || true
  }
  eP=${EST_PORT:-8443}; cP=${CMP_PORT:-8445}; oP=${OCSP_PORT:-8080}
  sP=${STORE_PORT:-8447}; scP=${SCEP_PORT:-8448}; aP=${ACME_PORT:-8444}; wP=${WEB_PORT:-8090}

  EST_URL="https://$TARGET_HOST:$eP${EST_BASE_PATH:-/.well-known/est}/$CA_ID"
  CMP_URL="http://$TARGET_HOST:$cP${CMP_PATH:-/cmp}/$CA_ID"
  OCSP_URL="http://$TARGET_HOST:$oP${OCSP_PATH:-/ocsp}"
  STORE_URL="http://$TARGET_HOST:$sP${STORE_PATH:-/certificates/search}"
  SCEP_URL="http://$TARGET_HOST:$scP${SCEP_PATH:-/scep}/$CA_ID"
  ACME_DIR="https://$TARGET_HOST:$aP${ACME_BASE_PATH:-/acme}/$CA_ID/directory"
  EST_AUTH="${DEMO_USER}:${DEMO_PASS}"
  api_base="https://$TARGET_HOST:$wP"

  # Fetch enrolment credentials (CMP secret + ACME EAB)
  cookie_jar="$WORK/.bench-cookies"
  curl -sk -c "$cookie_jar" -X POST \
    -d "username=${DEMO_USER}&password=${DEMO_PASS}" \
    "$api_base/api/login" -o /dev/null 2>/dev/null
  creds=$(curl -sk -b "$cookie_jar" --max-time 10 "$api_base/api/enrolment-credentials" 2>/dev/null)
  CMP_SECRET=$(printf '%s' "$creds" | sed -nE 's/.*"cmp_secret" *: *"([^"]*)".*/\1/p')
  CMP_REF="$DEMO_USER"
  ACME_EAB_KID=$(printf '%s' "$creds" | sed -nE 's/.*"kid" *: *"([^"]*)".*/\1/p')
  ACME_EAB_HMAC=$(printf '%s' "$creds" | sed -nE 's/.*"acme_eab_hmac" *: *"([^"]*)".*/\1/p')
  # ⚠️ SCEP was the one protocol this never asked for, and its credential moved: the
  # challengePassword became a PER-USER value, and that removed the deployment-wide
  # SCEP_CHALLENGE outright. pki-demo.sh was taught to read it from the same endpoint and
  # the same session; the bench was not, so every SCEP cell POSTed a CSR with no
  # challengePassword at all and the server refused all of them — "scep RSA-2048 0/50",
  # for RSA and EC alike, which is why the key type looked like the variable.
  SCEP_CHALLENGE=$(printf '%s' "$creds" | sed -nE 's/.*"scep_challenge" *: *"([^"]*)".*/\1/p')
  echo "  credentials: CMP=${CMP_SECRET:+yes} ACME_EAB=${ACME_EAB_HMAC:+yes} SCEP=${SCEP_CHALLENGE:+yes}"

  # Bootstrap trust from EST /cacerts (base64-encoded PKCS7)
  curl -sk --max-time 20 -u "$EST_AUTH" "$EST_URL/cacerts" 2>/dev/null | \
    "$OSSL" base64 -d -A > cacerts.p7b
  "$OSSL" pkcs7 -inform DER -in cacerts.p7b -print_certs -out chain.pem 2>/dev/null
  if ! grep -q "BEGIN CERT" chain.pem 2>/dev/null; then
    echo "could not fetch CA chain from $EST_URL/cacerts" >&2; exit 1
  fi
  awk 'BEGIN{n=0} /BEGIN CERT/{n++} {print > ("cc"n".pem")}' chain.pem
  ISSUER=""; for f in cc*.pem; do
    s=$("$OSSL" x509 -in "$f" -noout -subject 2>/dev/null | sed 's/^subject=//')
    i=$("$OSSL" x509 -in "$f" -noout -issuer  2>/dev/null | sed 's/^issuer=//')
    if [ "$s" != "$i" ]; then ISSUER="$WORK/$f"; CMP_RECIPIENT="/${s//, //}"; fi
  done
  [ -z "$ISSUER" ] && ISSUER="$WORK/cc1.pem"
  CMP_RECIPIENT=${CMP_RECIPIENT:-$("$OSSL" x509 -in "$ISSUER" -noout -subject 2>/dev/null | sed 's/^subject=//; s/, /\//g; s/^/\//')}
  EST_TRUST="--cacert chain.pem"
  CERTBOT_CA="$WORK/chain.pem"
else
  MODE=throwaway
  bench_banner
  printf '  %sThrowaway deployment (no external DB touched)%s\n' "$DIM" "$RST"

  EST_LPORT=19543; CMP_LPORT=19585; SCEP_LPORT=19548; OCSP_LPORT=19580; STORE_LPORT=19547
  "$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.pem.key -out est.pem -days 3650 -subj "/CN=localhost" >/dev/null 2>&1

  # ⚠️ pg_setup, not a hand-rolled CREATE DATABASE. This file sources pg_helpers.sh and then
  # used to reimplement it — with a name (`fastpki_bench_<pid>`) outside the `fpki_*_<pid>`
  # shape `_pg_reap` collects. So a run killed past the EXIT trap left its database behind
  # for ever, the same leak again in the one directory that was not converted. pg_setup also
  # carries the role probe, so a $PGUSER that cannot connect now says so here instead of
  # failing as "Postgres not available".
  # pg_setup's CREATE/DROP DATABASE and the schema load are harness plumbing, and
  # they are STDOUT. A demo run showed 70 lines of "CREATE TABLE" before its first result.
  # stderr is deliberately left alone — that is where the role diagnostic goes.
  pg_setup bench >/dev/null
  PGDB="$PGDATABASE"; PGINFO="$PG_CONNINFO"
  psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDB" -tAc 'select 1' >/dev/null 2>&1 \
    || { printf '\n  %sPostgres not available — run a local pki database first%s\n' "$B" "$RST" >&2; exit 1; }

  hsm_available || { printf '\n  SoftHSM/PKCS#11 toolchain incomplete — %s\n' "$(hsm_skip_reason)" >&2; exit 1; }
  hsm_server_start || { printf '\n  could not start a p11-kit server\n' >&2; exit 1; }
  BENCH_TOKEN="bench_$$"
  "$HSM_UTIL" --module "$HSM_SOFTHSM" --init-token --free --label "$BENCH_TOKEN" \
      --pin 1234 --so-pin 12345678 >/dev/null 2>&1 \
      || { printf '\n  could not initialise the bench SoftHSM token\n' >&2; exit 1; }
  BENCH_CA_KEY="pkcs11:token=$BENCH_TOKEN;object=ca;type=private?pin-value=1234"
  { printf 'PG_CONNINFO=%s\n' "$PGINFO"; hsm_conf_lines; } > "$WORK/ca.conf"
  "$BIN/fastpki-ca" --config "$WORK/ca.conf" create ca --name "Bench CA" \
      --subject "/CN=FastPKI Bench CA" --ca-key "$BENCH_CA_KEY" --keygen \
      --out-dir "$WORK" >"$WORK/ca-create.log" 2>&1 \
      || { printf '\n  fastpki-ca create failed — see %s/ca-create.log\n' "$WORK" >&2; exit 1; }
  cp "$WORK/ca.crt" ca.pem && cp ca.pem root.pem
  common="ROOT_CA_PEM=$WORK/root.pem
$(hsm_conf_lines)
PG_CONNINFO=$PGINFO
AUTH_BACKEND=local
CERT_VALIDITY_DAYS=365
MIN_EC_BITS=256
LOG_LEVEL=err"
  printf "%s\nEST_CERT=%s/est.pem\nEST_KEY=%s/est.pem.key\nEST_BIND=127.0.0.1\nEST_PORT=%s\n" "$common" "$WORK" "$WORK" "$EST_LPORT" > est.conf
  printf "%s\nCMP_BIND=127.0.0.1\nCMP_PORT=%s\nCMP_PATH=/cmp\n" "$common" "$CMP_LPORT" > cmp.conf
  cmp_ra_issue ca.pem "$BENCH_CA_KEY" && cmp_ra_publish && cmp_ra_conf_lines >> cmp.conf
  printf "%s\nSCEP_BIND=127.0.0.1\nSCEP_PORT=%s\n" "$common" "$SCEP_LPORT" > scep.conf
  printf "%s\nOCSP_BIND=127.0.0.1\nOCSP_PORT=%s\n" "$common" "$OCSP_LPORT" > ocsp.conf
  printf 'OCSP_RESPONDER_KEY=%s\n' \
    "$(ocsp_responder_key "$WORK/ca.pem" "$BENCH_CA_KEY" ca "$WORK")" >> ocsp.conf
  printf "%s\nSTORE_BIND=127.0.0.1\nSTORE_PORT=%s\n" "$common" "$STORE_LPORT" > store.conf
  printf "internal\n" > domains.txt
  "$BIN/fastpki-config" --config est.conf domains-import "$WORK/domains.txt" >/dev/null 2>&1
  # Same as the demo — EST_AUTH is "bench:bench" and now needs a row behind it.
  "$BIN/fastpki-config" --config est.conf web-user bench bench --role requester >/dev/null 2>&1

  # Start services
  starts=""
  add_start(){ case " $starts " in *" $1 "*) ;; *) starts="$starts $1";; esac; }
  started(){ case " $starts " in *" $1 "*) return 0;; *) return 1;; esac; }
  need est   && add_start est
  need cmp   && add_start cmp
  need scep  && add_start scep
  need ocsp  && { add_start ocsp; add_start cmp; }
  need store && { add_start store; add_start cmp; }
  expect=""
  for s in est cmp scep ocsp store; do
    started "$s" || continue
    "$BIN/fastpki-$s" --config "$s.conf" >"$s.log" 2>&1 & pids+=($!)
    eval "case \$s in est) expect=\"\$expect \$EST_LPORT\";; cmp) expect=\"\$expect \$CMP_LPORT\";; scep) expect=\"\$expect \$SCEP_LPORT\";; ocsp) expect=\"\$expect \$OCSP_LPORT\";; store) expect=\"\$expect \$STORE_LPORT\";; esac"
  done
  disown -a 2>/dev/null || true
  for _ in $(seq 1 40); do
    n=0; for p in $expect; do port_up "$p" && n=$((n+1)); done
    [ "$n" -eq "$(echo $expect | wc -w)" ] && break; sleep 0.2
  done
  down=""; for p in $expect; do port_up "$p" || down="$down $p"; done
  if [ -n "$down" ]; then
    KEEP_WORK=1
    printf '\n  %sbench servers did not start (ports:%s).%s\n' "$B" "$down" "$RST" >&2
    for s in est cmp scep ocsp store; do started "$s" && printf '    %s: %s\n' "$s" "$(tail -n 2 "$s.log" 2>/dev/null | tr '\n' ' ')" >&2; done
    exit 1
  fi

  EST_URL="https://127.0.0.1:$EST_LPORT/.well-known/est/ca"
  CMP_URL="http://127.0.0.1:$CMP_LPORT/cmp/ca"
  OCSP_URL="http://127.0.0.1:$OCSP_LPORT/ocsp"
  STORE_URL="http://127.0.0.1:$STORE_LPORT/certificates/search"
  SCEP_URL="http://127.0.0.1:$SCEP_LPORT/scep/ca"
  EST_AUTH="bench:bench"
  CMP_RECIPIENT="/CN=FastPKI Bench CA"
  # No unprotected CMP any more — the bench mints its own PBM credential so the CMP
  # leg measures the shipped posture rather than a mode the product no longer has.
  cmp_seed_pbm benchcmp 2>/dev/null
  CMP_REF="$CMP_PBM_REF"; CMP_SECRET="$CMP_PBM_SECRET"
  # Throwaway half: the same per-user challengePassword, read from the row the
  # product reads. The `bench` user above is a `requester`, and that role holds
  # `enrol:scep`, so `fastpki-config web-user` minted one for it.
  SCEP_CHALLENGE=$(scep_challenge_for bench)
  ACME_EAB_KID=""; ACME_EAB_HMAC=""
  EST_TRUST=""
  ISSUER="$WORK/ca.pem"
  CERTBOT_CA="$WORK/root.pem"
fi

# ⚠️ ISSUE FOR A NAME THE DEPLOYMENT ACTUALLY APPROVES. Every CN here was hardcoded under
# `.internal`, so against any live deployment whose allowed_domains does not include it,
# every single cell reported 0/N — a full table of plausible-looking zero-throughput rows
# for a server that was correctly refusing a name it does not serve:
#
#   policy: CN 'b-rsa2048-1.internal' is not in the approved domains
#
# provision-target.sh already reads /api/domains and writes DEMO_DOMAIN into the
# descriptor for exactly this, and pki-demo.sh already honours it; this did not. The
# throwaway local deployment below seeds `internal` itself, so that stays the default.
DEMO_DOMAIN="${DEMO_DOMAIN:-internal}"

# ── per-operation clients ────────────────────────────────────────────────────
est_one(){ # <prebuilt-b64-csr-file>
  [ "$(curl -sk --max-time 30 -u "$EST_AUTH" --data-binary @"$1" \
        -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" \
        -o /dev/null -w '%{http_code}' "$EST_URL/simpleenroll")" = 200 ]
}
# ⚠️ -implicit_confirm, LIKE pki-demo.sh AND LIKE THE CONFIG THE CONSOLE HANDS OUT. Without
# it a CMP transaction is IR → IP then certConf → pkiConf, and the second message is a
# separate HTTP request. Against a deployment behind ONE round-robin name that request lands
# on a different node, which has never heard of the transaction — so the cell reported 5/10
# on a mesh where every node was healthy and CMP worked perfectly when addressed directly.
# Measured: 5/10 without it, 10/10 with it, spread 4/3/3 across three nodes. The console
# writes implicit_confirm = 1 into the client config it generates, so this measures what a
# real client actually does rather than inventing a slower shape nothing uses.
cmp_one(){ # <key> <cn>
  "$OSSL" cmp -cmd ir -implicit_confirm -server "$CMP_URL" -recipient "$CMP_RECIPIENT" \
    -trusted "$ISSUER" -ref "$CMP_REF" -secret "pass:$CMP_SECRET" -keep_alive 0 \
    -newkey "$1" -subject "/CN=$2" -certout /dev/null >/dev/null 2>&1
}
scep_one(){ # <prebuilt-req-der> <self-pem> <key>
  curl -s --max-time 30 -X POST --data-binary @"$1" -H "Content-Type: application/x-pki-message" \
    "$SCEP_URL?operation=PKIOperation" -o sc-resp.der 2>/dev/null
  [ "$("$SCEPTC" parse "$2" "$3" sc-resp.der sc-issued.der 2>/dev/null)" = "pkiStatus=0" ]
}

printf '\n%s%-8s %-10s %10s %12s %11s%s\n' "$B" "proto" "key/op" "count" "seconds" "ops/s" "$RST"
printf '%s%s%s\n' "$DIM" "------------------------------------------------------------" "$RST"
FAILS=0
row(){ # <proto> <label> <ok> <count> <t0> <t1>
  local rate secs
  secs=$(awk "BEGIN { printf \"%.2f\", $6 - $5 }")
  rate=$(awk "BEGIN { printf \"%.1f\", $3 / ($6 - $5) }")
  # ⚠️ A FAILING CELL KEEPS ITS LOGS. The work directory is a mktemp that cleanup() removes
  # on exit, and KEEP_WORK was set only when the servers failed to START — so a cell that
  # ran and scored 0/N deleted the one file saying why, leaving a bare "0/5" and nothing to
  # read. The rate line tells you a cell failed; it can never tell you what failed.
  [ "$3" -eq "$4" ] || { FAILS=$((FAILS+1)); KEEP_WORK=1; }
  printf '%-8s %-10s %10s %12s %s%11s%s\n' "$1" "$2" "$3/$4" "$secs" "$CYN" "$rate" "$RST"
}

# ── a self-test hook, before anything is measured ────────────────────────────
#
# Same hook and same reason as pki-demo.sh: at this point every definition above has run
# and nothing below has. tests/demo_functions_toplevel.sh asks bash what it actually
# holds, because a definition nested inside another function still reads as top-level.
if [ -n "${FASTPKI_DEMO_DEFS_ONLY:-}" ]; then declare -F | awk '{print $3}'; exit 0; fi

# enroll: est / cmp / scep — per key type
for proto in est cmp scep; do
  need "$proto" || continue
  if [ "$proto" = scep ]; then
    SCEPTC="$BIN/scep-testclient"
    command -v ensure_testclient >/dev/null 2>&1 && ensure_testclient scep-testclient "$BIN" || true
    [ -x "$SCEPTC" ] || { printf '%-8s %-10s %10s\n' scep "(skip)" "no testclient"; continue; }
    # ⚠️ SAY WHY, rather than benchmarking a refusal. Without a challengePassword
    # every cell reports 0/N at a plausible-looking ops/s, which reads as a throughput
    # result for a server that never issued anything. The user this run authenticates as
    # needs a role holding `enrol:scep` for one to be minted.
    if [ -z "${SCEP_CHALLENGE:-}" ]; then
      printf '%-8s %-10s %10s  %s\n' scep "(skip)" "no cred" \
        "the user has no SCEP challengePassword — grant a role with enrol:scep"
      continue
    fi
    curl -s --max-time 20 "$SCEP_URL?operation=GetCACert" -o scep-ca.der 2>/dev/null
    "$OSSL" x509 -inform DER -in scep-ca.der -out scep-ca.pem 2>/dev/null || \
      "$OSSL" pkcs7 -inform DER -in scep-ca.der -print_certs 2>/dev/null | "$OSSL" x509 -out scep-ca.pem 2>/dev/null
  fi
  for kt in $KEYTYPES; do
    if [ "$proto" = scep ] && { [ "$kt" = ed25519 ] || [ "${kt#rsapss}" != "$kt" ] || [ "${kt#mldsa}" != "$kt" ]; }; then
      printf '%-8s %-10s %10s\n' scep "$(keylabel "$kt")" "(skip CMS)"; continue
    fi
    keys=(); reqs=()
    for i in $(seq 1 "$COUNT"); do
      k="k_${proto}_${kt}_$i.pem"; genkey "$kt" "$k"; keys+=("$k")
      if [ "$proto" = est ]; then
        "$OSSL" req -new -key "$k" -subj "/CN=b-$BENCH_RUN-$kt-$i.$DEMO_DOMAIN" -outform DER 2>/dev/null | "$OSSL" base64 -A > "r_$i.b64"
        reqs+=("r_$i.b64")
      elif [ "$proto" = scep ]; then
        # ⚠️ The challengePassword is a PKCS#9 ATTRIBUTE inside the CSR, so it has to
        # go in at `req -new` time — there is no flag to add it to a finished request. Same
        # shape pki-demo.sh uses; `-subj` cannot express attributes, hence the config file.
        printf '[req]\ndistinguished_name=dn\nattributes=attrs\nprompt=no\n[dn]\nCN=b-%s-%s-%s.%s\n[attrs]\nchallengePassword=%s\n' \
          "$BENCH_RUN" "$kt" "$i" "$DEMO_DOMAIN" "$SCEP_CHALLENGE" > "screq_$i.cnf"
        "$OSSL" req -new -key "$k" -config "screq_$i.cnf" -outform DER -out "csr_$i.der" >/dev/null 2>&1
        "$OSSL" req -x509 -key "$k" -subj "/CN=b-$BENCH_RUN-$kt-$i.$DEMO_DOMAIN" -days 2 -out "self_$i.pem" >/dev/null 2>&1
        "$SCEPTC" build scep-ca.pem "self_$i.pem" "$k" "csr_$i.der" "req_$i.der" >/dev/null 2>&1
        reqs+=("req_$i.der")
      fi
    done
    ok=0; t0=$(now)
    for i in $(seq 1 "$COUNT"); do
      case "$proto" in
        est)  est_one "${reqs[$((i-1))]}" && ok=$((ok+1));;
        cmp)  cmp_one "${keys[$((i-1))]}" "b-$BENCH_RUN-$kt-$i.$DEMO_DOMAIN" && ok=$((ok+1));;
        scep) scep_one "${reqs[$((i-1))]}" "self_$i.pem" "${keys[$((i-1))]}" && ok=$((ok+1));;
      esac
    done
    t1=$(now)
    row "$proto" "$(keylabel "$kt")" "$ok" "$COUNT" "$t0" "$t1"
    rm -f k_${proto}_${kt}_*.pem r_*.b64 req_*.der csr_*.der self_*.pem screq_*.cnf 2>/dev/null
  done
done

# status: OCSP — pre-issue one cert, then time status checks
if need ocsp; then
  "$OSSL" genrsa -out oc.key 2048 >/dev/null 2>&1
  "$OSSL" cmp -cmd ir -implicit_confirm -server "$CMP_URL" -recipient "$CMP_RECIPIENT" \
    -trusted "$ISSUER" -ref "$CMP_REF" -secret "pass:$CMP_SECRET" -keep_alive 0 \
    -newkey oc.key -subject "/CN=ocsp-bench-$BENCH_RUN.$DEMO_DOMAIN" -certout oc.pem >/dev/null 2>&1
  if [ -s oc.pem ]; then
    ok=0; t0=$(now)
    for i in $(seq 1 "$COUNT"); do
      "$OSSL" ocsp -issuer "$ISSUER" -cert oc.pem -url "$OCSP_URL" -resp_text -noverify 2>/dev/null | grep -q "Cert Status: good" && ok=$((ok+1))
    done
    t1=$(now); row ocsp "status" "$ok" "$COUNT" "$t0" "$t1"
  else printf '%-8s %-10s %10s\n' ocsp "(skip)" "no pre-issued cert"; fi
fi

# search: RFC 4387 store — pre-issue one cert, then time searches by CN
if need store; then
  "$OSSL" genrsa -out sk.key 2048 >/dev/null 2>&1
  "$OSSL" cmp -cmd ir -implicit_confirm -server "$CMP_URL" -recipient "$CMP_RECIPIENT" \
    -trusted "$ISSUER" -ref "$CMP_REF" -secret "pass:$CMP_SECRET" -keep_alive 0 \
    -newkey sk.key -subject "/CN=store-bench-$BENCH_RUN.$DEMO_DOMAIN" -certout sk.pem >/dev/null 2>&1
  if [ -s sk.pem ]; then
    ok=0; t0=$(now)
    for i in $(seq 1 "$COUNT"); do
      [ "$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' "$STORE_URL?cn=store-bench-$BENCH_RUN.$DEMO_DOMAIN")" = 200 ] && ok=$((ok+1))
    done
    t1=$(now); row store "search" "$ok" "$COUNT" "$t0" "$t1"
  else printf '%-8s %-10s %10s\n' store "(skip)" "no pre-issued cert"; fi
fi

# ── http-01, not dns-01 ────────────────────────────────────────────────
#
# ACME takes roughly 30 seconds per order, so running it COUNT times is unreasonable.
#
# ⚠️ THE COST WAS NEVER PROPAGATION DELAY, so swapping challenge types for its own
# sake would have missed it. Two things were paying it, both container churn:
#
#   * the demo RESTARTED THE WHOLE ACME SERVICE per run, because ACME_DNS_RESOLVER is
#     startup config and CoreDNS's container IP is not known until it is running;
#   * this bench destroyed and recreated CoreDNS for EVERY CERTIFICATE in its auth
#     hook — measured at 2.289 s/cert, against 0.003 s to write a webroot file.
#
# http-01 removes both. nginx starts ONCE and never restarts; a challenge is a file
# appearing in a directory it already serves. Nothing is reconfigured mid-run, so
# neither mode restarts fastpki-acme any more.
#
# ⚠️ THE IDENTIFIER IS `localhost` ON PURPOSE. fetch_http01() (src/acme/main.cpp) is
# `httplib::Client cli(host, 80)` — it resolves through the SYSTEM resolver, not
# ACME_DNS_RESOLVER, which feeds dns-01 only. So the name has to resolve for the ACME
# *server*. `localhost` does, everywhere, with no /etc/hosts edit and no root — which
# is exactly what acme_lifecycle.sh needs root for, and why it sits in ROOT_SUITES.
# A per-iteration name would need either root or a resolver the server never consults.
#
# ⚠️ AND `localhost` MEANS A DIFFERENT MACHINE IN EACH MODE, which is the whole reason
# nginx is placed two different ways below: throwaway runs fastpki-acme as a HOST
# process (its localhost is the host's → publish :80), live runs it in a CONTAINER
# (its localhost is that container's → join the same network namespace). Publishing
# :80 in live mode would put nginx somewhere the server cannot reach and every
# challenge would fail with a plain "missing or mismatched".
# ⚠️ DO NOT ASSUME DOCKER CAN SEE THE WORK DIRECTORY. The webroot is bind-mounted into
# nginx, and Docker Desktop mounts a path outside its file-sharing list as an EMPTY
# directory rather than refusing — so nginx starts, answers 404 for every challenge,
# and the cell skips blaming the network. `mktemp -d` on a Mac is exactly such a path
# (/var/folders/...), which is why this cell could not run there at all while the same
# code was fine on the lab. Measured, not assumed: mount each candidate into a
# throwaway container and keep the first one the container can actually read.
ACME_WEBROOT=; ACME_WEBROOT_TMP=
acme_pick_webroot(){
    local c
    for c in "$WORK/webroot" "${HOME:-/root}/.cache/fastpki-bench/webroot" "$ROOT/.bench-webroot"; do
        mkdir -p "$c/.well-known/acme-challenge" 2>/dev/null || continue
        # nginx workers are not root, and the container reads the mount point itself —
        # host ancestors above it are never traversed, so this is the tree that matters.
        chmod o+x "$c" 2>/dev/null; chmod -R o+rX "$c" 2>/dev/null
        echo probe > "$c/.well-known/acme-challenge/ping" 2>/dev/null || continue
        if docker run --rm -v "$c:/w:ro" nginx:alpine \
             test -f /w/.well-known/acme-challenge/ping >/dev/null 2>&1; then
            rm -f "$c/.well-known/acme-challenge/ping"
            ACME_WEBROOT="$c"
            # Anything outside $WORK is ours to remove; cleanup() only owns $WORK.
            [ "$c" = "$WORK/webroot" ] || ACME_WEBROOT_TMP="$c"
            return 0
        fi
        rm -f "$c/.well-known/acme-challenge/ping"
        [ "$c" = "$WORK/webroot" ] || rm -rf "$c"
    done
    return 1
}

# enroll: ACME — http-01 orders via certbot --webroot + one long-lived nginx
if need acme; then
  skipacme=""
  command -v certbot >/dev/null 2>&1 || skipacme="certbot not found"
  if [ -n "$skipacme" ]; then
    printf '%-8s %-10s %10s\n' acme "(skip)" "$skipacme"
  else

    # ⚠️ The `continue`s below abort the ACME leg on a setup failure — but nothing here is
    # a loop, so in bash they were error-printing no-ops that fell through to certbot and
    # reported a 0/N row for the wrong reason. One iteration makes them mean what they say.
    for _acme_once in 1; do
    # ⚠️ NO DOCKER AT ALL IS A DIFFERENT DIAGNOSIS. acme_pick_webroot() probes the
    # candidates by reading each from inside a container, so a machine with no docker
    # daemon fails every probe and used to be told to fix its File sharing settings —
    # a setting that cannot help, in a dialog belonging to software that is not running.
    if ! docker info >/dev/null 2>&1; then
      printf '%-8s %-10s %10s\n' acme "(skip)" "no docker"
      printf '  %sthe ACME leg drives certbot in a container, and no docker daemon%s\n' "$DIM" "$RST"
      printf '  %sis reachable here. Start one, or run this leg from a host that has it.%s\n' "$DIM" "$RST"
      continue
    fi
    if ! acme_pick_webroot; then
      printf '%-8s %-10s %10s\n' acme "(skip)" "no shareable webroot"
      printf '  %sdocker could not read ANY of these from inside a container:%s\n' "$DIM" "$RST"
      printf '  %s  %s%s\n' "$DIM" "$WORK/webroot" "$RST"
      printf '  %s  %s%s\n' "$DIM" "${HOME:-/root}/.cache/fastpki-bench/webroot" "$RST"
      printf '  %s  %s%s\n' "$DIM" "$ROOT/.bench-webroot" "$RST"
      printf '  %son Docker Desktop, add one of them under Settings > Resources > File sharing%s\n' \
             "$DIM" "$RST"
      continue
    fi
    if [ "$MODE" = throwaway ]; then
      LAPORT=19544
      "$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme-tls.key -out acme-tls.pem -days 3650 \
        -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
      # ⚠️ The throwaway ACME server's TLS identity is THIS self-signed cert, not anything
      # the bench CA signed — so certbot has to anchor on it. It was pointed at root.pem
      # and every order died in the TLS handshake ("self-signed certificate"), the second
      # reason this leg has never run.
      CERTBOT_CA="$WORK/acme-tls.pem"
      # Second throwaway database, same reasoning as the first. ⚠️ pg_setup overwrites
      # PGDATABASE/PG_CONNINFO, so capture them and put PGDATABASE back — everything after
      # this point still talks to the main bench database, and leaving it pointed at the
      # ACME one would send the rest of the run somewhere it did not mean to go.
      pg_setup acmebench
      ACDB="$PGDATABASE"; ACINFO="$PG_CONNINFO"
      export PGDATABASE="$PGDB"
      psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$ACDB" -tAc 'select 1' >/dev/null 2>&1 || continue
      # EAB is mandatory, so mint a kid + HMAC in the throwaway DB. certbot
      # picks these up through $eab_args below, exactly as the --target path does with the
      # credentials the console hands out.
      ACME_EAB_KID=benchbot
      ACME_EAB_HMAC=$(openssl rand 32 | openssl base64 -A | tr '+/' '-_' | tr -d '=')
      psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$ACDB" -tAc \
          "CREATE TABLE IF NOT EXISTS keys(kid TEXT PRIMARY KEY, key TEXT);
           INSERT INTO keys(kid,protocol,key) VALUES('$ACME_EAB_KID','eab','$ACME_EAB_HMAC')
           ON CONFLICT (kid,protocol) DO UPDATE SET key=EXCLUDED.key;" >/dev/null 2>&1 || continue
      { printf 'PG_CONNINFO=%s\n' "$ACINFO"; hsm_conf_lines; } > "$WORK/acme-ca.conf"
      "$BIN/fastpki-ca" --config "$WORK/acme-ca.conf" add bench-ca --name "Bench CA" \
          --ca-pem "$WORK/ca.pem" --ca-key "$BENCH_CA_KEY" >"$WORK/acme-ca.log" 2>&1 || continue
      # ⚠️ THE EAB CREDENTIAL PROVES WHO YOU ARE; IT GRANTS NOTHING. The server authorizes an
      # order with may_enrol(kid, "enrol:acme", <ca>) — the ACCOUNT KID is the identity — so
      # without a user row holding that permission every order is refused with "this account
      # may not enrol over ACME against CA 'bench-ca'" and the cell scores 0/N. That reads as
      # a dead ACME server; it is a permission the harness never granted. `requester` already
      # carries enrol:acme, so the row is all that is missing.
      #
      # This is the same shape one layer down from the EAB provisioning above: registration
      # was refused until this script minted a kid, and issuance is refused until the kid is
      # a principal. The password is random and unused — the EAB HMAC is the credential.
      "$BIN/fastpki-config" --config "$WORK/acme-ca.conf" web-user "$ACME_EAB_KID" \
          "$(openssl rand -hex 16)" --role requester >>"$WORK/acme-ca.log" 2>&1 || continue
      cat > acme.conf <<EOC
BASE_URL=https://localhost:$LAPORT
ROOT_CA_PEM=$WORK/root.pem
ACME_CERT=$WORK/acme-tls.pem
ACME_KEY=$WORK/acme-tls.key
PG_CONNINFO=$ACINFO
ACME_BIND=127.0.0.1
ACME_PORT=$LAPORT
ACME_BASE_PATH=/acme
# ⚠️ ACME_EAB_REQUIRED was removed. This throwaway server used to pin it false because
# throwaway mode has no enrolment credentials to bind with, and without that certbot
# register was refused and every iteration of the leg failed — a 0/N row that reads like a
# dead ACME server rather than a refused registration. It now PROVISIONS its own kid + HMAC
# in the throwaway database (below), so the leg measures issuance against the posture we
# ship. The live target is unaffected: it takes real EAB credentials from
# /api/enrolment-credentials.
CERT_VALIDITY_DAYS=90
LOG_LEVEL=err
EOC
      "$BIN/fastpki-acme" --config acme.conf >acme.log 2>&1 & pids+=($!); disown -a 2>/dev/null || true
      up=0; for _ in $(seq 1 40); do port_up "$LAPORT" && { up=1; break; }; sleep 0.2; done
      [ "$up" = 1 ] || { printf '%-8s %-10s %10s\n' acme "(skip)" "server down"; continue; }
      # ⚠️ Only the --target branch set ACME_DIR, so under `set -u` the throwaway ACME leg
      # died on "ACME_DIR: unbound variable" before it ever reached certbot — it has never
      # run. Every path is per-CA (§4a), and the CA registered above is `bench-ca`.
      ACME_DIR="https://localhost:$LAPORT/acme/bench-ca/directory"
      # Host process -> its localhost is the host's, so publish :80 and order `localhost`.
      acme_ident=localhost
      nginx_net=(-p 80:80)
      probe_what="http://localhost/.well-known/acme-challenge/ on this host — port 80 must be free"
      # Same reasoning as the live branch below: report the STATUS, because 404 (serving,
      # empty webroot) and 000 (nothing listening) need different fixes.
      challenge_reachable(){
          local c
          c=$(curl -s --max-time 2 -o /dev/null -w '%{http_code}' \
              "http://localhost/.well-known/acme-challenge/$1" 2>/dev/null)
          [ "$c" = 200 ] && { PROBE_WHY=""; return 0; }
          PROBE_WHY="HTTP $c from the host probe"
          return 1
      }
    else
      compose_dir="$ROOT/deploy"
      acme_ctr=$(docker compose -f "$compose_dir/docker-compose.yml" ps -q acme 2>/dev/null | head -1)
      # ⚠️ A REMOTE DEPLOYMENT HAS NO CONTAINER HERE, and http-01 cannot help it: certbot
      # writes the challenge file on THIS machine and the server fetches it over HTTP, so
      # serving it would need the deployment to reach back here. dns-01 has no such
      # requirement — the server does the lookup, and demo/dns-auth.sh runs CoreDNS beside
      # it over the SSH target the descriptor carries. So the remote bench benches dns-01.
      # ⚠️ A KUBERNETES DESCRIPTOR CARRIES K8S_NAMESPACE, NOT SSH_TARGET. pki-demo.sh has
      # accepted either for its dns-01 cells since the k8s target mode existed; this one
      # asked for SSH_TARGET alone, so the whole ACME leg skipped on every cluster — a
      # (skip) row that reads like a missing prerequisite rather than a gap here.
      if [ -z "$acme_ctr" ] && { [ -n "${SSH_TARGET:-}" ] || [ -n "${K8S_NAMESPACE:-}" ]; }; then
        acme_remote_dns=1
        # ⚠️ $DEMO_DOMAIN, NOT a hardcoded `.internal`. Every other enrolment CN in this
        # script follows the descriptor's domain; a literal here means the dns-01 leg asks a
        # live deployment for a name outside its allowed_domains and every iteration is
        # refused — a tidy 0/N row that reads like a slow server.
        acme_ident="bench-demo.$DEMO_DOMAIN"   # a dns-01 identifier, not an nginx alias
        # Where the resolver will live, and therefore what address to hand the server.
        # A native target cannot host it, so it runs here and is named by CHALLENGE_FQDN —
        # already defined as a name that deployment resolves back to this host.
        _bres="fastpki-dns:15353"
        if [ "${DEPLOY_MODE:-}" = native ]; then
          if [ -z "${CHALLENGE_FQDN:-}" ]; then
            printf '%-8s %-10s %10s\n' acme "(skip)" "native target without CHALLENGE_FQDN"
            continue
          fi
          BENCH_DNS_PUB=1; _bres="$CHALLENGE_FQDN:15353"
        else
          # Empty on a Kubernetes descriptor, which has no SSH target: dns-auth.sh then
          # starts CoreDNS through kubectl from DNS_K8S_NAMESPACE instead.
          BENCH_DNS_SSH="${SSH_TARGET:-}"
        fi
        BENCH_DNS_PREV=$(bench_remote_cfg get ACME_DNS_RESOLVER | tail -1 | tr -d '\r')
        case "$BENCH_DNS_PREV" in *"not set"*|*ERR*) BENCH_DNS_PREV="" ;; esac
        if ! bench_remote_cfg set ACME_DNS_RESOLVER "$_bres" >/dev/null 2>&1; then
          printf '%-8s %-10s %10s\n' acme "(skip)" "could not set the resolver on the target"
          continue
        fi
        BENCH_DNS_SET=1
        trap 'bench_undo_remote_dns; cleanup' EXIT INT TERM
        bench_restart_acme
        sleep 3
        printf '  %sACME_DNS_RESOLVER=%s set on %s (reverted at the end)%s\n' \
               "$DIM" "$_bres" "${SSH_TARGET:-k8s:${K8S_NAMESPACE:-}}" "$RST"
      elif [ -z "$acme_ctr" ]; then
        printf '%-8s %-10s %10s\n' acme "(skip)" "no ACME container, no SSH_TARGET, no K8S_NAMESPACE"
        continue
      fi
      if [ -n "${acme_remote_dns:-}" ]; then
        : # dns-01 needs no nginx, no webroot and no docker network here
      else
      # The ACME server is a container, so its resolver is docker's embedded one and it can
      # reach a sibling by container name. Ask which network it is actually on rather than
      # hardcoding `fastpki_default` — the name follows the compose project, which follows
      # the directory, so a checkout in ~/FastPKI and one in ~/fastpki disagree.
      acme_net=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' \
                   "$acme_ctr" 2>/dev/null | awk '{print $1}')
      [ -n "$acme_net" ] || { printf '%-8s %-10s %10s\n' acme "(skip)" "no docker network"; continue; }
      acme_ident=fastpki-bench-http
      nginx_net=(--network "$acme_net" --network-alias "$acme_ident")
      probe_what="http://$acme_ident/.well-known/acme-challenge/ from a container on $acme_net"
      # Probe from a sibling on the same network — the host cannot see this name.
      #
      # ⚠️ KEEP THE CLIENT'S OWN MESSAGE. Discarding stderr collapses two different faults
      # into one silence: nginx unreachable (bad address, connection refused) and nginx
      # answering 404 because the webroot bind mount is empty. Only the second is a mount
      # problem, and "no answer" reads as the first. busybox wget names which it is.
      challenge_reachable(){
          PROBE_WHY=$(docker run --rm --network "$acme_net" nginx:alpine \
              wget -q -O /dev/null "http://$acme_ident/.well-known/acme-challenge/$1" 2>&1) \
          && { PROBE_WHY=""; return 0; }
          return 1
      }
      fi
    fi

    # ⚠️ EVERYTHING FROM HERE TO THE ORDER LOOP IS THE http-01 RIG. dns-01 against a remote
    # deployment needs none of it: no nginx, no webroot, no reachable alias — the server
    # does the lookup and CoreDNS answers beside it.
    if [ -z "${acme_remote_dns:-}" ]; then
    docker rm -f fastpki-bench-http >/dev/null 2>&1 || true
    # ⚠️ NO `--rm`, AND THE OUTPUT IS KEPT. Three different faults used to arrive at one
    # "webroot unreachable" line ten seconds later — the container never started (port 80
    # already held on this host, image missing, network gone), it started and died, or it
    # is serving and the probe cannot reach it. Only the third is about the webroot, and
    # they need three different fixes. `--rm` would delete the one thing that can say
    # which; the EXIT trap removes the container instead.
    if ! docker run -d --name fastpki-bench-http "${nginx_net[@]}" \
           -v "$ACME_WEBROOT:/usr/share/nginx/html:ro" nginx:alpine \
           >"$WORK/bench-http.log" 2>&1; then
      printf '%-8s %-10s %10s\n' acme "(skip)" "nginx did not start"
      # ⚠️ THE CAUSE IS THE FIRST LINE, NOT THE LAST. docker prints the reason and then
      # "Run 'docker run --help' for more information", so a tail here reports the help
      # banner and drops the sentence naming the missing network or the held port.
      why=$(grep -m1 -i error "$WORK/bench-http.log" || true)
      [ -n "$why" ] || why=$(head -1 "$WORK/bench-http.log")
      printf '  %s%s%s\n' "$DIM" "$why" "$RST"
      continue
    fi
    echo up > "$ACME_WEBROOT/.well-known/acme-challenge/ping"
    # ⚠️ ASK THE CONTAINER WHETHER IT CAN SEE THE FILE, BEFORE PROBING OVER HTTP. The bind
    # mount and the network are two independent things that both end in "the challenge did
    # not load", and a probe from a sibling container cannot tell them apart. This one can:
    # if the file the host just wrote is not visible INSIDE nginx, the mount is the fault
    # and no amount of network debugging will help. Docker Desktop is the usual reason —
    # a path it is not sharing mounts as an empty directory rather than failing.
    if ! docker exec fastpki-bench-http \
         test -f /usr/share/nginx/html/.well-known/acme-challenge/ping 2>/dev/null; then
      printf '%-8s %-10s %10s\n' acme "(skip)" "webroot not mounted"
      printf '  %sthe file written to %s is not visible inside the container%s\n' \
             "$DIM" "$ACME_WEBROOT" "$RST"
      printf '  %sif this is Docker Desktop, add that path under Settings > Resources > File sharing%s\n' \
             "$DIM" "$RST"
      rm -f "$ACME_WEBROOT/.well-known/acme-challenge/ping"
      continue
    fi
    nginx_up=0
    for _ in $(seq 1 40); do challenge_reachable ping && { nginx_up=1; break; }; sleep 0.25; done
    rm -f "$ACME_WEBROOT/.well-known/acme-challenge/ping"
    if [ "$nginx_up" != 1 ]; then
      if [ "$(docker inspect -f '{{.State.Running}}' fastpki-bench-http 2>/dev/null)" = true ]; then
        # Serving, but the probe never got a 200 — a reachability problem on the probe's
        # side, so name the address that was actually tried rather than the directory.
        printf '%-8s %-10s %10s\n' acme "(skip)" "webroot unreachable"
        printf '  %snginx is running; %s did not serve the challenge%s\n' "$DIM" "$probe_what" "$RST"
        [ -n "${PROBE_WHY:-}" ] && printf '  %s  the probe said: %s%s\n' "$DIM" "$PROBE_WHY" "$RST"
        printf '  %s  a 404 here means the container is up but the webroot mount is empty%s\n' "$DIM" "$RST"
      else
        printf '%-8s %-10s %10s\n' acme "(skip)" "nginx exited"
        printf '  %s%s%s\n' "$DIM" "$(docker logs fastpki-bench-http 2>&1 | tail -2 | tr '\n' ' ')" "$RST"
      fi
      continue
    fi
    fi   # end of the http-01 rig

    for _ in $(seq 1 30); do
      sleep 1; curl -sk "$ACME_DIR" >/dev/null 2>&1 && break
    done

    eab_args=""
    [ -n "${ACME_EAB_KID:-}" ] && [ -n "${ACME_EAB_HMAC:-}" ] && eab_args="--eab-kid $ACME_EAB_KID --eab-hmac-key $ACME_EAB_HMAC"
    # ⚠️ certbot must trust whatever the ACME PORT presents, which is not always the CA
    # chain. Until a CA exists, every service mints itself a self-signed transport cert
    # and keeps it while it is still valid — so on a deployment whose CA was created
    # after first boot, the EST-fetched chain does not verify the ACME endpoint and every
    # order dies in the handshake. Test it rather than assume it, and say so when it is the
    # bootstrap cert: a silent append would hide a genuinely misconfigured endpoint.
    if [ "$MODE" = live ] && [ -f "$CERTBOT_CA" ]; then
      "$OSSL" s_client -connect "$TARGET_HOST:$aP" </dev/null 2>/dev/null \
        | "$OSSL" x509 -out acme-served.pem 2>/dev/null || true
      if [ -s acme-served.pem ] && \
         ! "$OSSL" verify -CAfile "$CERTBOT_CA" acme-served.pem >/dev/null 2>&1; then
        cat "$CERTBOT_CA" acme-served.pem > acme-trust.pem
        CERTBOT_CA="$WORK/acme-trust.pem"
        printf '  %sACME port serves a cert the CA chain does not cover (bootstrap cert) — trusting it for this run%s\n' "$DIM" "$RST"
      fi
    fi
    [ -f "$CERTBOT_CA" ] && cafile="REQUESTS_CA_BUNDLE=$CERTBOT_CA" || cafile=""

    # Register the ACME account once (saves ~1s per iteration)
    env $cafile certbot register \
      --server "$ACME_DIR" --agree-tos --non-interactive --register-unsafely-without-email \
      $eab_args \
      --work-dir "$WORK/certbot-work" --logs-dir "$WORK/certbot-logs" \
      --config-dir "$WORK/certbot-config" \
      >/dev/null 2>&1 || true   # succeeds or reuses existing

    # ⚠️ --force-renewal is what makes this a benchmark. Every iteration asks for the same
    # identifier, and without it certbot answers the 2nd..Nth from its own store
    # ("not yet due for renewal") without contacting the server at all — a very fast row
    # measuring nothing. With it, each iteration is a full new order + challenge + finalize.
    ok=0; t0=$(now)
    for i in $(seq 1 "$COUNT"); do
      if [ -n "${acme_remote_dns:-}" ]; then
        # dns-01 against a remote deployment: demo/dns-auth.sh publishes the TXT through a
        # CoreDNS it starts BESIDE that deployment for compose, or HERE with its port
        # published for a native target, which has no container runtime to host one.
        env $cafile ROOT="$ROOT" \
          DNS_SSH_TARGET="$BENCH_DNS_SSH" DNS_PUBLISH="$BENCH_DNS_PUB" DNS_PORT=15353 \
          DNS_K8S_NAMESPACE="${K8S_NAMESPACE:-}" \
          DNS_SSH_OPTS="$BENCH_SSH_OPTS" \
          certbot certonly --manual --preferred-challenges dns \
          --manual-auth-hook "$ROOT/demo/dns-auth.sh" \
          --manual-cleanup-hook "$ROOT/demo/dns-cleanup.sh" \
          --cert-name bench --force-renewal \
          --server "$ACME_DIR" -d "$acme_ident" \
          $eab_args --non-interactive --agree-tos --register-unsafely-without-email \
          --work-dir "$WORK/certbot-work" --logs-dir "$WORK/certbot-logs" \
          --config-dir "$WORK/certbot-config" \
          >>"$WORK/acme.log" 2>&1 && ok=$((ok+1))
      else
        env $cafile certbot certonly --webroot -w "$ACME_WEBROOT" \
          --cert-name bench --force-renewal \
          --server "$ACME_DIR" -d "$acme_ident" \
          $eab_args --non-interactive \
          --work-dir "$WORK/certbot-work" --logs-dir "$WORK/certbot-logs" \
          --config-dir "$WORK/certbot-config" \
          >>"$WORK/acme.log" 2>&1 && ok=$((ok+1))
      fi
    done
    t1=$(now)

    docker rm -f fastpki-bench-http >/dev/null 2>&1 || true
    if [ -n "${acme_remote_dns:-}" ]; then
      bench_undo_remote_dns
      row acme "dns-01" "$ok" "$COUNT" "$t0" "$t1"
    else
      row acme "http-01" "$ok" "$COUNT" "$t0" "$t1"
    fi
    done
  fi
fi

printf '%s%s%s\n' "$DIM" "------------------------------------------------------------" "$RST"
echo
if [ "$FAILS" -ne 0 ]; then echo "  ${FAILS} cell(s) had failures"; exit 1; fi
# ⚠️ SAY WHICH MEASUREMENT THIS RUN ACTUALLY MADE. The rates are server-side throughput
# only when the server is local. Against --target the client runs here, the server runs
# there, and every operation pays a network round trip — on a WAN link that dominates the
# server's own time, so a number read as "FastPKI does N/s" is mostly a latency
# measurement. Printing the same sentence in both modes invited exactly that reading.
if [ "$MODE" = live ]; then
  echo "  Rates INCLUDE the network round trip to the target (local key/CSR generation"
  echo "  excluded). They measure this client against that deployment over this link —"
  echo "  not server-side throughput, and not comparable with a throwaway run."
else
  echo "  Rates are server-side throughput (local key/CSR generation excluded)."
fi
echo "  ${DIM}est/scep use multi-tool clients (+TLS for est); cmp is one integrated"
echo "  process — so client overhead differs. See the header for details.${RST}"
