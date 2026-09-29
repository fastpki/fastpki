#!/usr/bin/env bash
# ACME directory base-URL handling (regression for: server listens on :8444 but
# advertised endpoints on :443 because BASE_URL defaulted to https://<PKI_DNS>).
#   1. No BASE_URL  -> directory reflects the request Host header (host:port).
#   2. BASE_URL set -> directory uses it verbatim (production behind a TLS proxy).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
# Only adopt the system openssl.cnf where it really is one. On macOS this path is a
# stub that defines no providers, and exporting it breaks every pkcs11 load — the
# CA key then cannot be minted and the suite SKIPs for a reason that looks nothing
# like "wrong openssl.cnf". Tests must not assume a Linux layout (§3d).
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; PORT=18458
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=BU CA" 3650
cp ca.pem root.pem
# ACME is HTTPS-only — give the server its own TLS cert.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_baseurl
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT

common="SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
ACME_CERT=$W/acme.pem
ACME_KEY=$W/acme.key
PG_CONNINFO=$PG_CONNINFO
ACME_BIND=127.0.0.1
ACME_PORT=$PORT
LOG_LEVEL=err"

start() { "$ROOT/build/fastpki-acme" --config "$1" >srv.log 2>&1 & echo $!; }
nonce_field() { curl -sk "https://127.0.0.1:$PORT/acme/ca/directory" | tr ',' '\n' | sed -n 's/.*"newNonce":"\([^"]*\)".*/\1/p'; }

echo "=== 1. no BASE_URL (PKI_DNS=localhost) — reflect request host ==="
printf "PKI_DNS=localhost\n%s\n" "$common" > reflect.conf
seed_ca_from_conf reflect.conf   # register the CA (SIGNING_CA_* no longer seed it)
P=$(start reflect.conf); sleep 1
N=$(nonce_field); echo "  newNonce = $N"
kill $P 2>/dev/null
chk "newNonce uses the request host:port" "https://127.0.0.1:$PORT/acme/ca/new-nonce" "$N"

echo "=== 2. explicit BASE_URL — used verbatim ==="
printf "BASE_URL=https://pki.example.org\n%s\n" "$common" > explicit.conf
P=$(start explicit.conf); sleep 1
N=$(nonce_field); echo "  newNonce = $N"
kill $P 2>/dev/null
chk "newNonce uses the configured BASE_URL" "https://pki.example.org/acme/ca/new-nonce" "$N"

echo
echo "=== ACME BASEURL: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
