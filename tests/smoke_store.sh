#!/usr/bin/env bash
# RFC 4387 cert store smoke test:
#   GET /certificates/search?<attr>=<value>  (cn, serial, certHash)
#   single match -> application/pkix-cert (DER); miss -> 404
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
BIN="$ROOT/build/fastpki-store"
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
PORT=18447

# --- CA + leaf --------------------------------------------------------------
ca_in_token ca.pem "/CN=Store Test CA" 3650
"$OSSL" req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr \
    -subj "/CN=store-leaf.example.org" >/dev/null 2>&1
"$OSSL" x509 -req -in leaf.csr -CA ca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS -CAcreateserial \
    -days 365 -out leaf.pem >/dev/null 2>&1

SERIAL=$("$OSSL" x509 -in leaf.pem -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
FPR=$("$OSSL" x509 -in leaf.pem -outform DER | "$OSSL" dgst -sha256 | sed 's/^.*= *//')
DERHEX=$("$OSSL" x509 -in leaf.pem -outform DER | xxd -p | tr -d '\n')
echo "serial=$SERIAL"
echo "certHash=$FPR"

# --- certs.db ---------------------------------------------------------------
pg_setup smoke_store
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
NB=$(date +%s); NA=$((NB + 31536000))
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cert,cn,fingerprint) VALUES('$SERIAL',0,0,0,$NB,$NA,'CN=store-leaf.example.org','tester','\x$DERHEX'::bytea,'store-leaf.example.org','$FPR');"

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
STORE_BIND=127.0.0.1
STORE_PORT=$PORT
LOG_LEVEL=info
EOF

"$BIN" --config "$WORK/bootstrap.conf" > srv.log 2>&1 &
SRV=$!; sleep 1
trap 'pg_cleanup; kill "$SRV" 2>/dev/null' EXIT

check() { # label  query  expect_subject
    local out; out=$(curl -s "http://127.0.0.1:$PORT/certificates/search?$2" \
        | "$OSSL" x509 -inform DER -noout -subject 2>/dev/null)
    echo "  [$1] $out"
}

echo "=== search by cn / serial / certHash (expect store-leaf.example.org) ==="
check "cn"       "cn=store-leaf.example.org"
check "serial"   "serial=$SERIAL"
check "certHash" "certHash=$FPR"

echo "=== miss (expect HTTP 404) ==="
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/certificates/search?cn=nope.example.org")
echo "  HTTP $code"
