#!/usr/bin/env bash
# pg_promote_finishes.sh — a promotion has to leave the node able to RESTART and to SERVE.
#
# THE TWO DEFECTS THIS GUARDS, both found by promoting a real pair and both invisible at
# the moment they are created:
#
#   1. STANDBY_OF was left in .env. The node is a primary now and that variable says it is
#      not, so the entrypoint reads it on the next start and refuses:
#        postgres: STANDBY_OF=<addr> but the data directory is already PG17 — refusing to start.
#      The refusal is correct — re-seeding would destroy a freshly promoted primary — but
#      nothing restarts a container on purpose the day it is promoted, so this surfaces
#      weeks later on an unrelated reboot, to someone who does not know a promotion happened.
#
#   2. The node kept serving the self-signed pair certgen made. While it was a standby it
#      could not issue anything, because issuing is a write. Its applications verify against
#      the PRIMARY's anchor, which does not certify that, so every one of them fails the
#      instant it is promoted — and `fastpki-ca pg-tls`, which would replace the pair, needs
#      the very connection that is broken. The node is wedged.
#
# ⚠️ NO POSTGRES AND NO COMPOSE HERE, DELIBERATELY. tests/ha_failover.sh already proves the
# database mechanism against a real pair it builds itself; what regressed here is what the
# SCRIPT does around the promotion, which is file manipulation and one carefully shaped
# `compose run`. A stub docker answers the probes and records the calls, so this asserts the
# script's contract in about a second and cannot be flaky.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
mkdir -p "$W/bin" "$W/deploy"

# A stub `docker` that answers the three probes pg-promote.sh makes and logs every call.
# The answers are the ones a healthy single-node promotion produces: no mesh peers, and a
# database that leaves recovery.
# ⚠️ THE CA QUERY ANSWERS WITH A REAL CERTIFICATE, because the check parses one. It carries a
# CRLDP naming a host that is NOT this node — the state a pair is in when its hierarchy was
# minted on the primary, and the state the warning exists to report.
cat > "$W/bin/docker" <<'STUB'
#!/bin/sh
echo "$*" >> "$DOCKER_STUB_LOG"
case "$*" in
  *pg_subscription*)      echo 0 ;;   # PEERS: no mesh, so the slot pre-flight does not apply
  *pg_replication_slots*) echo 0 ;;   # READY
  *pg_is_in_recovery*)    echo f ;;   # promoted
  *encode*cert*)          cat "$FAKE_CA_B64" 2>/dev/null ;;
  *openssl*)              cat "$FAKE_CA_TXT" 2>/dev/null ;;
esac
exit 0
STUB
chmod +x "$W/bin/docker"

cp "$ROOT/deploy/pg-promote.sh" "$W/deploy/"
: > "$W/deploy/docker-compose.yml"
cat > "$W/deploy/.env" <<EOF
POSTGRES_PASSWORD=s3cr3t
FASTPKI_IMAGE=fastpki:local
STANDBY_OF=10.0.0.1
PKI_DNS=b.example.org
EOF
chmod 600 "$W/deploy/.env"


# ── a CA certificate whose CRLDP names ANOTHER host ────────────────────────────────────
# ⚠️ GENERATED, NOT PASTED. A fixture certificate checked in would expire and turn a real
# assertion into an annual mystery failure; minting one per run costs milliseconds.
FAKE_CA_B64="$W/ca.b64"; FAKE_CA_TXT="$W/ca.txt"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/ca.key" -out "$W/ca.pem" \
    -subj /CN=promote-fixture -days 2 \
    -addext "crlDistributionPoints=URI:http://other-host.example:8080/root.crl" >/dev/null 2>&1
openssl x509 -in "$W/ca.pem" -outform DER 2>/dev/null | base64 | tr -d '\n' > "$FAKE_CA_B64"
openssl x509 -in "$W/ca.pem" -noout -text > "$FAKE_CA_TXT" 2>/dev/null
export FAKE_CA_B64 FAKE_CA_TXT

DOCKER_STUB_LOG="$W/log"; : > "$DOCKER_STUB_LOG"
( cd "$W/deploy" && DOCKER_STUB_LOG="$DOCKER_STUB_LOG" PATH="$W/bin:$PATH" \
    sh ./pg-promote.sh >"$W/out" 2>&1 ) || true

echo "=== 1. the promotion itself still happens ==="
chk "it promoted the standby" yes \
    "$(grep -q 'pg_ctl' "$W/log" && echo yes || echo no)"
chk "  and reported a read-write primary" yes \
    "$(grep -q 'read-write primary' "$W/out" && echo yes || echo no)"

echo "=== 2. STANDBY_OF is gone, so the node can restart ==="
chk "STANDBY_OF removed from .env" no \
    "$(grep -q '^STANDBY_OF=' "$W/deploy/.env" && echo yes || echo no)"
chk "  and it said so" yes \
    "$(grep -q 'removed STANDBY_OF' "$W/out" && echo yes || echo no)"
# ⚠️ THE REST OF .env HAS TO SURVIVE. This rewrites the file, and a rewrite that drops the
# database password or the image tag would break the node far more thoroughly than the
# variable it removed.
chk "  the other settings survive" yes \
    "$(grep -q '^POSTGRES_PASSWORD=s3cr3t$' "$W/deploy/.env" &&
       grep -q '^FASTPKI_IMAGE=fastpki:local$' "$W/deploy/.env" && echo yes || echo no)"
# ⚠️ AND THE MODE. .env carries the database password; a rewrite that leaves it at the
# umask's default publishes it to every account on the host.
chk "  and it is still 0600" 600 \
    "$(stat -c %a "$W/deploy/.env" 2>/dev/null || stat -f %Lp "$W/deploy/.env" 2>/dev/null)"

echo "=== 3. the node issues a database certificate its own apps will accept ==="
chk "pg-tls was run" yes \
    "$(grep -q 'pg-tls' "$W/log" && echo yes || echo no)"
# ⚠️ sslmode=require IS THE POINT, not an oversight. It is the one-shot escape from the
# deadlock: the node's own certificate is still the self-signed one, so a verifying
# connection cannot be made, and it is exactly that connection pg-tls needs in order to
# replace it. Nothing is left configured this way.
chk "  over a connection that does not verify" yes \
    "$(grep 'pg-tls' "$W/log" | grep -q 'sslmode=require' && echo yes || echo no)"
# ⚠️ NOT 127.0.0.1. A one-shot `compose run` container has its own network namespace, where
# loopback is the container itself and the connection is refused.
chk "  naming the compose service, not loopback" yes \
    "$(grep 'pg-tls' "$W/log" | grep -q 'host=postgres' && echo yes || echo no)"
chk "  and not 127.0.0.1" no \
    "$(grep 'pg-tls' "$W/log" | grep -q 'host=127.0.0.1' && echo yes || echo no)"
# ⚠️ NO ca-id. PG_TLS_CA_ID is a row in the `config` TABLE, not a .env key, so passing one
# read from .env would be wrong on every deployment that set it the documented way. pg-tls
# resolves it itself and says so when it is unset.
chk "  letting pg-tls resolve PG_TLS_CA_ID itself" yes \
    "$(grep 'pg-tls' "$W/log" | grep -q 'pg-tls --if-needed' && echo yes || echo no)"


echo "=== 5. a promoted node says when its CA certificates name a host that is gone ==="
# ⚠️ THIS IS THE HALF THAT IS NOT AUTOMATIC. CRLDP and AIA are baked when a CA certificate
# is minted, from BASE_URL or PKI_DNS, so a pair whose hierarchy was created on the primary
# carries the PRIMARY's name in every CA certificate — and a promotion leaves those URLs
# pointing at the host that just died. Leaves are unaffected, so nothing fails until a
# relying party does strict validation. The promotion cannot fix it; it can say so.
chk "it warns that the CA URLs name another host" yes \
    "$(grep -q 'CHECK THE CA URLs' "$W/out" && echo yes || echo no)"
chk "  and names the repair rather than only the symptom" yes \
    "$(grep -q 're-issue the CA' "$W/out" && echo yes || echo no)"
echo "=== 4. PRECONDITION: the stub is what answered ==="
# An empty log would make every assertion above pass by never having run anything.
chk "the stub docker was invoked" yes \
    "$([ -s "$W/log" ] && echo yes || echo no)"


echo "=== 6. --already-promoted on Kubernetes: after a restore's promotion, and protocols switched off ==="
# db-restore-online.sh promotes the standby itself and hands it here for the steps after a
# promotion. The pod below runs no EST, ACME, CMP, SCEP, MS or store container
# (<PROTO>_INSTALLED=false): restarting a fixed list of eight reported six restarts that
# "failed" for containers that do not exist, measured on a live pair.
cat > "$W/bin/kubectl" <<'STUB'
#!/bin/sh
echo "$*" >> "$KUBECTL_STUB_LOG"
case "$*" in
  *"get pods"*)                    echo "pod/fastpki-node-0"; echo "pod/fastpki-node-1" ;;
  *"get pod"*containers*)          echo "postgres web ocsp renew p11tls pgtls" ;;
  *fastpki-node-0*pg_is_in_recovery*) echo t ;;
  *pg_is_in_recovery*)             echo "$FAKE_RECOVERY" ;;
  *pg_subscription*|*pg_replication_slots*) echo 0 ;;
esac
exit 0
STUB
chmod +x "$W/bin/kubectl"
KUBECTL_STUB_LOG="$W/klog"; : > "$KUBECTL_STUB_LOG"
( cd "$W/deploy" && KUBECTL_STUB_LOG="$KUBECTL_STUB_LOG" FAKE_RECOVERY=f PATH="$W/bin:$PATH" \
    FASTPKI_PROMOTE_MODE=k8s NAMESPACE=t sh ./pg-promote.sh fastpki-node-1 --already-promoted >"$W/kout" 2>&1 ) || true
chk "PRECONDITION: the stub kubectl answered"            yes "$([ -s "$W/klog" ] && echo yes || echo no)"
chk "it does not promote again"                          no  "$(grep -q 'pg_ctl.*promote' "$W/klog" && echo yes || echo no)"
chk "it restarts the containers the pod has"             yes "$(grep -q 'fastpki-node-1 -c web -- kill 1' "$W/klog" && grep -q 'fastpki-node-1 -c renew -- kill 1' "$W/klog" && echo yes || echo no)"
chk "  and skips the ones it does not"                   0   "$(grep -cE -- '-c (est|acme|cmp|scep|ms|store) -- kill 1' "$W/klog")"
chk "  without reporting a failed restart"               0   "$(grep -c 'did not restart' "$W/kout")"
: > "$KUBECTL_STUB_LOG"
( cd "$W/deploy" && KUBECTL_STUB_LOG="$KUBECTL_STUB_LOG" FAKE_RECOVERY=t PATH="$W/bin:$PATH" \
    FASTPKI_PROMOTE_MODE=k8s NAMESPACE=t sh ./pg-promote.sh fastpki-node-1 --already-promoted >"$W/kout2" 2>&1 ); _rc=$?
chk "it refuses a server that is still a standby"        1   "$_rc"
chk "  and says why"                                     yes "$(grep -q 'is not a read-write primary' "$W/kout2" && echo yes || echo no)"
echo
echo "=== PG PROMOTE FINISHES: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
