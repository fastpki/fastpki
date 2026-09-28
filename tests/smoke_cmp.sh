#!/usr/bin/env bash
# CMP smoke test: issue a cert via an `ir` (initialization request) using the
# OpenSSL 3.3 cmp client against fastpki-cmp.
#
# CMP_ACCEPT_UNPROTECTED is GONE, so this authenticates like the shipped posture
# requires — a per-user PBM secret from `keys`. The old note here said request
# protection validation was "a documented TODO"; it has not been one for a long time, and the
# -unprotected_requests it justified meant this smoke test proved the server would issue to
# ANYONE, which is not what we ship.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
BIN="$ROOT/build/fastpki-cmp"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
# The from-source OpenSSL install (install_sw) ships no openssl.cnf; point the
# CLI at the system one so `req`/`cmp` can initialize.
# Only adopt the system openssl.cnf where it really is one. On macOS this path is a
# stub that defines no providers, and exporting it breaks every pkcs11 load — the
# CA key then cannot be minted and the suite SKIPs for a reason that looks nothing
# like "wrong openssl.cnf". Tests must not assume a Linux layout (§3d).
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
WORK="$(mktemp -d)"
cd "$WORK"
echo "workdir: $WORK"

# --- signing CA (server signs PKIMessage + issued certs with this) ----------
ca_in_token signing_ca.pem "/CN=Test Signing CA" 3650

# --- empty certs.db with schema --------------------------------------------
pg_setup smoke_cmp
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "example.org\ninternal\nlocal\n" > domains.txt
seed_domains $WORK/domains.txt   # allowed_domains is the sole source
# CMP protects responses with a per-CA RA credential and has NO CA-key fallback,
# so this is required setup, not decoration — without it every exchange below is a 503.
cmp_ra_setup signing_ca.pem "$CA_KEY_URI" \
    || { echo "SKIP: could not provision the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }

cat > bootstrap.conf <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$WORK/signing_ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$WORK/signing_ca.pem
PG_CONNINFO=$PG_CONNINFO
CMP_BIND=127.0.0.1
CMP_PORT=18085
CMP_PATH=/cmp
CERT_VALIDITY_DAYS=365
LOG_LEVEL=debug
EOF
cmp_ra_conf_lines >> bootstrap.conf
cmp_seed_pbm smoke-cmp
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)

"$BIN" --config "$WORK/bootstrap.conf" > "$WORK/srv.log" 2>&1 &
SRV=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "$WORK/bootstrap.conf" CMP_PORT "$SRV" || true
trap 'pg_cleanup; kill "$SRV" 2>/dev/null' EXIT

# --- client key + ir request ------------------------------------------------
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client.key >/dev/null 2>&1

echo "=== CMP ir request ==="
"$OSSL" cmp -cmd ir \
    -server http://127.0.0.1:18085/cmp/ca \
    -recipient "/CN=Test Signing CA" \
    -trusted signing_ca.pem -expect_sender "/CN=cmp-ra.test" \
    -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
    -newkey client.key -subject "/CN=cmp-client.example.org" \
    -certout issued.pem 2>&1 | tail -20

echo "=== server log ==="
cat "$WORK/srv.log"

echo "=== issued cert ==="
if [ -f issued.pem ]; then
    "$OSSL" x509 -in issued.pem -noout -subject -issuer -serial 2>&1
    echo "rows in certs.db: $(pg_exec 'select count(*) from certs;')"
    echo "RESULT: PASS"
else
    echo "RESULT: FAIL (no cert issued)"
fi
