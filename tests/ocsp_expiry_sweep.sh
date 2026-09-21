#!/usr/bin/env bash
# Regression: OCSP marks expired certs in a periodic BACKGROUND
# thread (OCSP_EXPIRY_SWEEP_SEC), not on the request path.
#   Phase 1 (long interval): an OCSP request does NOT flip an expired cert.
#   Phase 2 (short interval): the background thread DOES flip it.
# mark_expired_now() sets status 0 -> 1 for certs whose "notAfter" is in the past.
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
W="$(mktemp -d)"; cd "$W"; PORT=18103
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Sweep CA" 3650
cp ca.pem root.pem
"$OSSL" req -newkey rsa:2048 -nodes -keyout e.key -out e.csr -subj "/CN=expired.internal" >/dev/null 2>&1
"$OSSL" x509 -req -in e.csr -CA ca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS -CAcreateserial -days 365 -out e.pem >/dev/null 2>&1
pg_setup ocsp_expiry_sweep
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
SER=$("$OSSL" x509 -in e.pem -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
DER=$("$OSSL" x509 -in e.pem -outform DER | xxd -p | tr -d '\n')
PAST=$(( $(date +%s) - 86400 ))   # "notAfter" 1 day in the past
ins() { pg_exec "DELETE FROM certs; INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cert,cn,fingerprint) VALUES('$SER',0,0,0,$((PAST-100)),$PAST,'CN=expired','t','\x$DER'::bytea,'expired.internal','');"; }
status() { pg_exec "select status from certs where serial='$SER';"; }

mk_conf() { cat > "$1.conf" <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
OCSP_EXPIRY_SWEEP_SEC=$2
LOG_LEVEL=err
EOF
}

echo "=== Phase 1: OCSP request must NOT sweep (long interval) ==="
ins; mk_conf p1 60
"$ROOT/build/fastpki-ocsp" --config p1.conf >p1.log 2>&1 & P=$!; sleep 1
"$OSSL" ocsp -issuer ca.pem -cert e.pem -url "http://127.0.0.1:$PORT/ocsp" -noverify >/dev/null 2>&1
chk "expired cert still status 0 after an OCSP request" 0 "$(status)"
kill $P 2>/dev/null; wait $P 2>/dev/null

# wait for the port to clear (httplib has no SO_REUSEADDR drama here, but be safe)
for i in $(seq 1 20); do ss -tan 2>/dev/null | grep -q ":$PORT " || break; sleep 0.5; done

echo "=== Phase 2: background thread SWEEPS (short interval, no requests) ==="
ins; mk_conf p2 2
"$ROOT/build/fastpki-ocsp" --config p2.conf >p2.log 2>&1 & P=$!
sleep 4   # > one sweep interval, no OCSP requests made
chk "expired cert flipped to status 1 by the sweep" 1 "$(status)"
kill $P 2>/dev/null

echo
echo "=== OCSP EXPIRY SWEEP: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
