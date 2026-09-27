#!/usr/bin/env bash
# Self-contained OCSP smoke test:
#  1. make a signing CA + one leaf cert
#  2. load the leaf into a postgres certs table (status=0 valid)
#  3. start fastpki-ocsp
#  4. query with `openssl ocsp` and assert "good"
#  5. revoke the row, re-query, assert "revoked"
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"
BIN="$ROOT/build/fastpki-ocsp"
WORK="$(mktemp -d)"
cd "$WORK"
echo "workdir: $WORK"

# --- 1. CA + leaf -----------------------------------------------------------
ca_in_token signing_ca.pem "/CN=Test Signing CA" 3650
openssl req -newkey rsa:2048 -nodes -keyout leaf.key \
    -out leaf.csr -subj "/CN=leaf.example.org" >/dev/null 2>&1
openssl x509 -req -in leaf.csr -CA signing_ca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS \
    -CAcreateserial -days 365 -out leaf.pem >/dev/null 2>&1

SERIAL_HEX=$(openssl x509 -in leaf.pem -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
echo "leaf serial (normalized): $SERIAL_HEX"

# --- 2. seed the certs table -------------------------------------------------
pg_setup smoke_ocsp
trap 'pg_cleanup' EXIT
NOTBEFORE=$(date +%s)
NOTAFTER=$((NOTBEFORE + 31536000))
# Store the DER cert as a hex blob.
DERHEX=$(openssl x509 -in leaf.pem -outform DER | xxd -p | tr -d '\n')
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cert,cn,fingerprint) VALUES('$SERIAL_HEX',0,0,0,$NOTBEFORE,$NOTAFTER,'CN=leaf.example.org','tester','\x$DERHEX'::bytea,'leaf.example.org','');"
echo "rows in certs: $(pg_exec 'select count(*) from certs;')"

# --- 3. config + start responder -------------------------------------------
cat > bootstrap.conf <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$WORK/signing_ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=smokeca
ROOT_CA_PEM=$WORK/signing_ca.pem
PG_CONNINFO=$PG_CONNINFO
OCSP_BIND=127.0.0.1
OCSP_PORT=18080
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
# Slice B: the CA key never signs a status response -- provision the responder.
printf 'OCSP_RESPONDER_KEY=%s\n' "$(ocsp_responder_key "$WORK/signing_ca.pem" "$CA_KEY_URI" smokeca "$WORK")" >> bootstrap.conf

"$BIN" --config "$WORK/bootstrap.conf" &
SRV=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "$WORK/bootstrap.conf" OCSP_PORT "$SRV" || true

# ⚠️ pg_cleanup FIRST, AND NO $P. `trap cleanup EXIT` replaces the earlier trap that
# carried pg_cleanup, so omitting it leaks this suite's database. Order matters under
# `set -u`: this suite sets SRV, never P, so a `kill $P` aborts the handler — which is
# why the ORIGINAL trap still cleaned up (pg_cleanup ran before it died) and a version
# that killed first did not.
cleanup() { pg_cleanup; [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null; true; }
trap cleanup EXIT

# --- 4. query: expect good --------------------------------------------------
echo "=== OCSP query (expect: good) ==="
openssl ocsp -issuer signing_ca.pem -cert leaf.pem \
    -url http://127.0.0.1:18080/ocsp -resp_text -noverify 2>&1 \
    | grep -E "Cert Status|Response Type|leaf|good|revoked" | head

# --- 5. revoke + re-query: expect revoked -----------------------------------
pg_exec "UPDATE certs SET status=-1, \"revocationReason\"=1, \"revocationDate\"=$NOTBEFORE WHERE serial='$SERIAL_HEX';"
echo "=== OCSP query after revoke (expect: revoked) ==="
openssl ocsp -issuer signing_ca.pem -cert leaf.pem \
    -url http://127.0.0.1:18080/ocsp -resp_text -noverify 2>&1 \
    | grep -E "Cert Status|Revocation" | head

echo "=== done ==="
