#!/usr/bin/env bash
# CMP RA mode: CMP responses are protected (signed) by a Registration
# Authority credential instead of the CA key, so the CA key can stay offline / HSM.
# Issuance still uses the CA. Verifies: the RA (not the CA) is the response signer; and the
# client accepts it via the CA trust anchor, by chaining RA -> CA.
#
# The RA CERTIFICATE lives in the DB under cert_id "<CMP_RA_CERT_ID_PREFIX>-<ca_id>", one per
# CA, issued BY that CA. The old CMP_RA_CERT PEM-file branch is GONE — a file cannot express
# "one per CA", and §3f says delete the old path rather than keep it as a fallback. This
# suite therefore drives the same properties through the shipped DB path.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
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
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
W="$(mktemp -d)"; cd "$W"; PORT=18150
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Test CA" 3650
CA_URI_HERE="$CA_KEY_URI"
pg_setup cmp_ra
# The RA credential for CA id "ca": key minted in the token, certificate issued BY that CA
# and published as cert_id "cmp-ra-ca" — exactly what a deployment does.
cmp_ra_setup ca.pem "$CA_URI_HERE" \
    || { echo "SKIP: could not provision the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "example.org\ninternal\nlocal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source

mkconf(){ # cakey  -> writes bootstrap.conf
cat > bootstrap.conf <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$1
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
CMP_RA_CERT_ID_PREFIX=cmp-ra
CMP_RA_KEY=$CMP_RA_KEY_URI
PG_CONNINFO=$PG_CONNINFO
CMP_BIND=127.0.0.1
CMP_PORT=$PORT
CMP_PATH=/cmp
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
cmp_seed_pbm cmp-ra
}

echo "=== RA mode with a local CA key ==="
mkconf "$CA_KEY_URI"
"$BIN" --config bootstrap.conf >srv.log 2>&1 & SRV=$!
sleep 1; trap 'pg_cleanup; kill $SRV 2>/dev/null' EXIT
if ! kill -0 $SRV 2>/dev/null; then echo "fastpki-cmp died:"; cat srv.log; exit 1; fi
U="http://127.0.0.1:$PORT/cmp/ca"
ENR=(-recipient "/CN=Test CA" -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0)
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client.key >/dev/null 2>&1

# Client trusts the CA; the RA-protected response must verify by chaining RA -> CA.
"$OSSL" cmp -cmd ir -server "$U" "${ENR[@]}" -trusted ca.pem \
    -newkey client.key -subject "/CN=ra-client.example.org" -certout issued.pem >ir.log 2>&1
chk "ir issues a cert (RA-protected response accepted via CA trust)" yes "$([ -f issued.pem ] && echo yes || echo no)"
chk "issued cert chains to the CA" "issued.pem: OK" "$("$OSSL" verify -CAfile ca.pem issued.pem 2>/dev/null | sed 's#.*/##')"

# The RA — not the CA — is the protection signer: pinning the RA as -srvcert
# succeeds, pinning the CA fails.
"$OSSL" cmp -cmd ir -server "$U" "${ENR[@]}" -srvcert "$CMP_RA_PEM" \
    -newkey client.key -subject "/CN=ra-pin.example.org" -certout pin_ra.pem >pinra.log 2>&1
chk "response verifies when pinning the RA cert itself" yes "$([ -f pin_ra.pem ] && echo yes || echo no)"
"$OSSL" cmp -cmd ir -server "$U" "${ENR[@]}" -srvcert ca.pem \
    -newkey client.key -subject "/CN=ca-pin.example.org" -certout pin_ca.pem >pinca.log 2>&1
chk "response FAILS when pinning the CA cert (RA is the real signer)" yes "$([ ! -f pin_ca.pem ] && echo yes || echo no)"
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null

echo
echo "=== CMP RA: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
