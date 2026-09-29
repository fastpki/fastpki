#!/usr/bin/env bash
# Diagnostic: trace a CMP ir -> rr -> OCSP revocation to find where it breaks.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
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
W="$(mktemp -d)"; cd "$W"; CMP_PORT=18085; OCSP_PORT=18080

ca_in_token ca.pem "/CN=Diag CA" 3650
pg_setup diag_cmp_rr
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "example.org\ninternal\nlocal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source

common="SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
LOG_LEVEL=debug"
printf "%s\nCMP_BIND=127.0.0.1\nCMP_PORT=%s\nCMP_PATH=/cmp\nCMP_CLIENT_CA_ID=ca\n" "$common" "$CMP_PORT" > cmp.conf
printf "%s\nOCSP_BIND=127.0.0.1\nOCSP_PORT=%s\n" "$common" "$OCSP_PORT" > ocsp.conf
# Slice B: the CA key never signs a status response, so the responder needs its
# own certificate issued BY this CA -- otherwise fastpki-ocsp refuses every query.
# ⚠️ Mandatory, and missing here ever since — without it fastpki-cmp refuses
# every transaction and the client reports only a transfer error, which is exactly the
# symptom this diagnostic exists to investigate.
# ⚠️ And the CA itself was never registered. The SIGNING_CA_* startup seed is gone —
# a CA exists only as a `certs` row — so every /cmp/ca request 404s. Together with the
# missing RA credential above, this diagnostic has not been able to complete an
# enrolment for a long time; it just printed transfer errors.
seed_ca_from_conf cmp.conf
cmp_ra_setup ca.pem "$CA_KEY_URI" || { echo "SKIP: no CMP RA credential"; exit 0; }
cmp_ra_conf_lines >> cmp.conf
cmp_seed_pbm owner.example.org
printf 'OCSP_RESPONDER_KEY=%s
' "$(ocsp_responder_key "$W/ca.pem" "$CA_KEY_URI" ca "$W")" >> ocsp.conf


"$ROOT/build/fastpki-cmp"  --config cmp.conf  >cmp.log  2>&1 & C=$!
"$ROOT/build/fastpki-ocsp" --config ocsp.conf >ocsp.log 2>&1 & O=$!
sleep 1; trap 'pg_cleanup; kill $C $O 2>/dev/null' EXIT

"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out c.key >/dev/null 2>&1
"$OSSL" cmp -cmd ir -server "http://127.0.0.1:$CMP_PORT/cmp/ca" -recipient "/CN=Diag CA" \
    -trusted ca.pem -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
    -newkey c.key -subject "/CN=diag.example.org" -certout cert.pem >/dev/null 2>&1

CERT_SERIAL=$("$OSSL" x509 -in cert.pem -noout -serial | sed 's/serial=//')
echo "issued cert serial (openssl, upper):   $CERT_SERIAL"
echo "DB rows after ir:"
pg_exec "select serial,status from certs;"

# ⚠️ rr is SIGNATURE-protected: PBM is enrolment-only and unprotected is refused.
# Mint an identity cert whose CN equals the enrolment reference — that reference is the
# `owner` recorded on cert.pem, and ownership is what authorizes the revocation.
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out id.key >/dev/null 2>&1
"$OSSL" cmp -cmd ir -server "http://127.0.0.1:$CMP_PORT/cmp/ca" -recipient "/CN=Diag CA" \
    -trusted ca.pem -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
    -newkey id.key -subject "/CN=$CMP_PBM_REF" -certout id.pem >id.log 2>&1
echo "identity cert for the owner: $( [ -f id.pem ] && echo issued || echo MISSING )"
[ -f id.pem ] || { echo "--- client:"; tail -4 id.log; echo "--- server:"; grep -iE "polic|refus|denied|error" cmp.log | tail -4; }

echo "--- sending rr ---"
"$OSSL" cmp -cmd rr -server "http://127.0.0.1:$CMP_PORT/cmp/ca" -recipient "/CN=Diag CA" \
    -trusted ca.pem -cert id.pem -key id.key -keep_alive 0 -oldcert cert.pem 2>&1 | tail -8

echo "DB rows after rr:"
pg_exec "select serial,status,\"revocationReason\" from certs;"

echo "--- CMP server log (issued/revoked) ---"
grep -iE "issued|revok|error" cmp.log

echo "--- OCSP query ---"
"$OSSL" ocsp -issuer ca.pem -cert cert.pem -url "http://127.0.0.1:$OCSP_PORT/ocsp" -noverify 2>&1 | grep -E "Cert Status|Revocation"
