#!/usr/bin/env bash
# EST smoke test (RFC 7030):
#   1. GET  /.well-known/est/ca/cacerts      -> PKCS#7 with signing CA + root
#   2. POST /.well-known/est/ca/simpleenroll -> base64 PKCS#10 -> issued cert
# Auth is HTTP Basic; server runs in test mode (LDAP_AUTH=false accepts any
# non-empty user/pass).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"   # real credentials, not AUTH_BACKEND=none
source "$ROOT/tests/hsm_helpers.sh"
BIN="$ROOT/build/fastpki-est"
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
WORK="$(mktemp -d)"; cd "$WORK"
echo "workdir: $WORK"
PORT=18443

# --- CA (acts as both signing + root here) + root ---------------------------
ca_in_token signing_ca.pem "/CN=Test Signing CA" 3650
ca_in_token root_ca.pem "/CN=Test Root CA" 3650
# EST is HTTPS-only (RFC 7030); the server needs its own TLS cert.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key \
    -out est.pem -days 3650 -subj "/CN=localhost" >/dev/null 2>&1

pg_setup smoke_est
# AUTH_BACKEND=none is gone, so this suite authenticates for real.
seed_web_user tester secret requester
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "example.org\ninternal\nlocal\n" > domains.txt
seed_domains $WORK/domains.txt   # allowed_domains is the sole source

cat > bootstrap.conf <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$WORK/signing_ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$WORK/root_ca.pem
EST_CERT=$WORK/est.pem
EST_KEY=$WORK/est.key
PG_CONNINFO=$PG_CONNINFO
EST_BIND=127.0.0.1
EST_PORT=$PORT
AUTH_BACKEND=local
CERT_VALIDITY_DAYS=365
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)

"$BIN" --config "$WORK/bootstrap.conf" > "$WORK/srv.log" 2>&1 &
SRV=$!; sleep 1
trap 'pg_cleanup; kill "$SRV" 2>/dev/null' EXIT

# --- 1. cacerts -------------------------------------------------------------
echo "=== cacerts (expect 2 certs: signing CA + root) ==="
curl -sk "https://127.0.0.1:$PORT/.well-known/est/ca/cacerts" \
    | "$OSSL" base64 -d -A | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null \
    | grep -E "subject=" | sed 's/^/  /'

# --- 2. simpleenroll --------------------------------------------------------
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout client.key \
    -subj "/CN=est-client.example.org" -out client.csr >/dev/null 2>&1
# RFC 7030: body is base64-encoded DER PKCS#10.
"$OSSL" req -in client.csr -outform DER | "$OSSL" base64 > client.b64

echo "=== simpleenroll (expect issued cert) ==="
curl -sk -u tester:secret --data-binary @client.b64 \
    -H "Content-Type: application/pkcs10" \
    "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll" \
    | "$OSSL" base64 -d -A | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null \
    | grep -E "subject=|issuer=" | sed 's/^/  /'

echo "=== server log ==="; cat "$WORK/srv.log"
echo "rows in certs.db: $(pg_exec 'select count(*) from certs;')"
