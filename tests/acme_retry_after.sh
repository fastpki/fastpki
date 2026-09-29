#!/usr/bin/env bash
# ACME Retry-After (RFC 8555 §7.1.3, §7.5.1, §8.2). Drives a full dns-01 order
# and asserts the poll responses carry Retry-After while the server is still
# working (pending authz, triggered challenge) and drop it once the order is
# valid. No privileges needed (no :80). Guards the Retry-After follow-up.
# ⚠️ THIS SUITE REGISTERS WITH A REAL EAB BINDING, and that is the point. It used to
# pin ACME_EAB_REQUIRED=false because it tests ACME PROTOCOL mechanics and not deployment
# policy — but the switch is gone, and pinning it meant fourteen suites exercised a
# configuration FastPKI does not ship. acme_new_account (acme_jws.sh) provisions a kid +
# HMAC in the `keys` table and signs the RFC 8555 §7.3.4 binding, so registration here now
# takes exactly the path a real client takes.
# The DEFAULT itself is still exercised by acme_default_eab.sh, which provisions NOTHING.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/acme_jws.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"   # macOS
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
W="$(mktemp -d)"; cd "$W"; PORT=18466; DNSP=15363; DOMAIN=retry.example.org
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Retry CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_retry_after
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > bootstrap.conf <<EOF
BASE_URL=https://localhost:$PORT
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
ACME_CERT=$W/acme.pem
ACME_KEY=$W/acme.key
PG_CONNINFO=$PG_CONNINFO
ACME_BIND=127.0.0.1
ACME_PORT=$PORT
ACME_BASE_PATH=/acme
ACME_DNS_RESOLVER=127.0.0.1:$DNSP
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
SRV=; DNSPID=
# ONE trap. A later `trap ... EXIT` REPLACES an earlier one rather than adding to it, and
# the version of this line that only killed $SRV silently dropped pg_cleanup — which is how
# the harness used to leak a database per run.
trap 'kill $DNSPID $SRV 2>/dev/null; pg_cleanup' EXIT
"$ROOT/build/fastpki-acme" --config bootstrap.conf > srv.log 2>&1 & SRV=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$SRV" || true
if ! kill -0 $SRV 2>/dev/null; then echo "fastpki-acme died:"; cat srv.log; exit 1; fi

# §3e: was tests/acme_retry_after.py. The header is the whole subject here, and
# acme_jws.sh exposes $ACME_HEADERS after every call, so this is shell now.
retry_after() { printf '%s' "$ACME_HEADERS" | sed -n 's/^[Rr]etry-[Aa]fter: *//p' | tr -d '\r' | tail -1; }

echo "=== ACME Retry-After ==="
acme_dir "https://127.0.0.1:$PORT/acme/ca/directory"
jws_newkey acct.pem
acme_new_account acct.pem
KID=$ACME_LOCATION
acme_post_kid acct.pem "$KID" "$ACME_NEW_ORDER" \
    "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"$DOMAIN\"}]}"
chk "newOrder -> 201" 201 "$ACME_STATUS"
ORDER_URL=$ACME_LOCATION
AUTHZ=$(printf '%s' "$ACME_BODY" | sed -n 's/.*"authorizations":\["\([^"]*\)".*/\1/p')

# 1) a PENDING authorization is still being worked on -> Retry-After (RFC 8555 §7.1.3)
acme_post_kid acct.pem "$KID" "$AUTHZ" ""
chk "the authorization is pending" pending "$(json_str "$ACME_BODY" status)"
chk "pending authorization carries Retry-After" yes \
    "$([ -n "$(retry_after)" ] && echo yes || echo no)"

CH=$(printf '%s' "$ACME_BODY" | tr '{' '\n' | grep 'dns-01')
CH_URL=$(json_str "$CH" url); TOKEN=$(json_str "$CH" token)
TXTVAL=$(printf '%s' "$TOKEN.$(jws_thumbprint acct.pem)" | "$OSSL" dgst -sha256 -binary | b64url)
"$ROOT/build/dnsstub" "$DNSP" "TXT:_acme-challenge.$DOMAIN=$TXTVAL" > dns.log 2>&1 &
DNSPID=$!
for _ in $(seq 1 40); do grep -q READY dns.log 2>/dev/null && break; sleep 0.1; done

# 2) a JUST-TRIGGERED challenge is processing -> Retry-After, and a usable one
acme_post_kid acct.pem "$KID" "$CH_URL" '{}'
chk "challenge triggered -> 200" 200 "$ACME_STATUS"
CHST=$(json_str "$ACME_BODY" status)
chk "the triggered challenge is being worked on" yes \
    "$([ "$CHST" = pending ] || [ "$CHST" = processing ] && echo yes || echo no)"
RA=$(retry_after)
chk "triggered challenge carries Retry-After" yes "$([ -n "$RA" ] && echo yes || echo no)"
# A header a client cannot act on is no better than a missing one.
chk "  and it is a positive integer" yes \
    "$(printf '%s' "$RA" | grep -qE '^[0-9]+$' && [ "${RA:-0}" -gt 0 ] && echo yes || echo no)"
# A client that sleeps exactly Retry-After and reuses its connection (certbot) must find
# it still open: a hint at the idle timeout races the server's close, and a POST that
# meets a closed connection is not retried.
KA=$(printf '%s' "$ACME_HEADERS" | sed -n 's/^[Kk]eep-[Aa]live:.*timeout=\([0-9]*\).*/\1/p' | tail -1)
chk "  and it leaves half the keep-alive window (Retry-After $RA, timeout ${KA:-none})" yes \
    "$([ -n "$KA" ] && [ $((2 * ${RA:-0})) -lt "$KA" ] && echo yes || echo no)"

acme_poll_status acct.pem "$KID" "$AUTHZ" valid && r=valid || r="$(json_str "$ACME_BODY" status)"
chk "the authorization validated" valid "$r"

"$OSSL" ecparam -name prime256v1 -genkey -noout -out leaf.key 2>/dev/null
printf '[req]\ndistinguished_name=dn\nreq_extensions=v3\nprompt=no\n[dn]\n[v3]\nsubjectAltName=DNS:%s\n' \
       "$DOMAIN" > csr.cnf
"$OSSL" req -new -key leaf.key -subj "/CN=$DOMAIN" -config csr.cnf -outform DER -out leaf.csr 2>/dev/null
acme_post_kid acct.pem "$KID" "$ORDER_URL" ""
FIN=$(printf '%s' "$ACME_BODY" | sed -n 's/.*"finalize":"\([^"]*\)".*/\1/p')
acme_post_kid acct.pem "$KID" "$FIN" "{\"csr\":\"$(b64url < leaf.csr)\"}"
chk "finalize -> 200" 200 "$ACME_STATUS"

# 3) a VALID order has nothing left to poll -> NO Retry-After (§7.5.1). This is the half
# that makes the others meaningful: a server that always sent the header would pass 1 and 2.
acme_poll_status acct.pem "$KID" "$ORDER_URL" valid && r=valid || r="$(json_str "$ACME_BODY" status)"
chk "the order became valid" valid "$r"
chk "a valid order does NOT carry Retry-After" yes \
    "$([ -z "$(retry_after)" ] && echo yes || echo no)"

echo
echo "=== ACME RETRY-AFTER: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
