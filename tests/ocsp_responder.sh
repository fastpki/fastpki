#!/usr/bin/env bash
# Delegated OCSP responder (RFC 6960). With OCSP_RESPONDER_CERT/KEY set,
# fastpki-ocsp signs responses with a dedicated responder cert (issued by the CA,
# EKU id-kp-OCSPSigning) instead of the CA key — so the CA key can stay offline /
# in an HSM. Verifies: delegated signing is accepted by clients; and backward
# compatibility when no responder cert is configured.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OCSP="$ROOT/build/fastpki-ocsp"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
W="$(mktemp -d)"; cd "$W"; PORT=18140
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Test CA" 3650
# Delegated responder cert: issued by the CA, with OCSPSigning EKU + id-pkix-ocsp-nocheck.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout resp.key -subj "/CN=OCSP Test Responder" -out resp.csr >/dev/null 2>&1
cat > resp.ext <<EOF
[v3_resp]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = OCSPSigning
1.3.6.1.5.5.7.48.1.5 = critical,ASN1:NULL
EOF
"$OSSL" x509 -req -in resp.csr -CA ca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS -CAcreateserial -days 365 -extfile resp.ext -extensions v3_resp -out resp.pem >/dev/null 2>&1
chk "responder cert has OCSPSigning EKU" yes "$("$OSSL" x509 -in resp.pem -noout -ext extendedKeyUsage 2>/dev/null | grep -q 'OCSP Signing' && echo yes || echo no)"

pg_setup ocsp_responder
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
NOW=$(date +%s)
# ⚠️ ca_instance_id IS REQUIRED on a seeded row. OCSP now refuses to answer for a
# certificate no CA of ours issued: a row with no ca_instance_id is self-signed — since
# A listener's own TLS certificate is exactly such a row — and answering `good` for
# one would be this CA vouching for something it never issued. Measured on the lab: 0 of
# 1504 real issued leaf certificates lack this column, so a fixture without it was
# seeding a shape issuance never produces.
pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,ca_instance_id) VALUES('bb',0,$((NOW-100)),$((NOW+86400)),'CN=good','x','good','f1','ca');"
pg_exec "INSERT INTO certs(serial,status,\"revocationDate\",\"revocationReason\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,ca_instance_id) VALUES('aa',-1,$((NOW-50)),1,$((NOW-100)),$((NOW+86400)),'CN=rev','x','rev','f2','ca');"

start_ocsp(){ # configfile
  "$OCSP" --config "$1" >srv.log 2>&1 & echo $!
}
ocsp_q(){ # serial outfile  -> prints client output (with verify result)
  "$OSSL" ocsp -issuer ca.pem -serial "0x$1" -url "http://127.0.0.1:$PORT/ocsp" \
      -CAfile ca.pem -resp_text -respout "$2" 2>&1
}

echo "=== delegated responder, local CA key ==="
cat > local.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
OCSP_RESPONDER_KEY=$W/resp.key
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
LOG_LEVEL=err
EOF
seed_ca_from_conf local.conf   # register the CA (SIGNING_CA_* no longer seed it)
# The responder certificate is DB-resident and PER CA — cert_id "ocsp-ra-<ca_id>",
# not a PEM path. OCSP_RESPONDER_CERT is gone; only the key is still configured.
service_cert_publish resp.pem ca-global
P=$(start_ocsp local.conf); trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
sleep 1
if ! kill -0 $P 2>/dev/null; then echo "fastpki-ocsp died:"; cat srv.log; exit 1; fi
OUT=$(ocsp_q aa rev.der)
chk "response verifies (delegated responder accepted)" yes "$(echo "$OUT" | grep -q 'Response verify OK' && echo yes || echo no)"
chk "revoked serial reported revoked" yes "$(echo "$OUT" | grep -qiE '0x?aa: revoked' && echo yes || echo no)"
chk "responder cert is the signer (in the response)" yes \
    "$("$OSSL" ocsp -respin rev.der -resp_text -noverify 2>/dev/null | grep -q 'OCSP Test Responder' && echo yes || echo no)"
chk "response is NOT signed directly by the CA" no \
    "$("$OSSL" ocsp -respin rev.der -resp_text -noverify 2>/dev/null | grep -q 'Responder Id:.*Test CA' && echo yes || echo no)"
OUTG=$(ocsp_q bb good.der)
chk "valid serial reported good" yes "$(echo "$OUTG" | grep -qiE '0x?bb: good' && echo yes || echo no)"
chk "CRL still served with a local CA key" 200 "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/pki/signing_ca.crl/ca-global")"

echo "=== ⚠️ a DISABLED CA still ANSWERS status queries ==="
# The CRL side was reported first (`/root-ca.crl` -> "CA instance disabled"); the
# status answer went through the same gate. An offline root is the recommended posture,
# so this refusal fires exactly when the CA is most locked down — and refusing turns
# "revoked" into "cannot determine", which is the one outcome revocation exists to
# prevent. Disabling stops ISSUANCE; publishing what was already decided continues.
#
# The assertions above are this section's baseline: the same query on the same responder
# has just answered `revoked` and `good`, so the ONLY thing changing here is the flag.
pg_exec "UPDATE certs SET ca_enabled=false WHERE id='ca-global';"
DOUT=$(ocsp_q aa rev_dis.der)
chk "revoked serial still reported revoked" yes "$(echo "$DOUT" | grep -qiE '0x?aa: revoked' && echo yes || echo no)"
chk "  the response still verifies"          yes "$(echo "$DOUT" | grep -q 'Response verify OK' && echo yes || echo no)"
DGOOD=$(ocsp_q bb good_dis.der)
chk "good serial still reported good"        yes "$(echo "$DGOOD" | grep -qiE '0x?bb: good' && echo yes || echo no)"
chk "  and the CRL is served too"            200 \
    "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/pki/signing_ca.crl/ca-global")"
chk "  the CA really is disabled meanwhile"  f \
    "$(pg_exec "SELECT ca_enabled FROM certs WHERE id='ca-global';" | tr -d ' ')"
pg_exec "UPDATE certs SET ca_enabled=true WHERE id='ca-global';"
kill $P 2>/dev/null; wait $P 2>/dev/null

# ⚠️ Slice B: THE CA KEY NEVER SIGNS A STATUS RESPONSE.
#
# This section used to be titled "backward compat: no responder cert -> CA signs
# directly" and asserted that the CA signed. That is the behaviour the ticket removes
# -- an OCSP response must never be signed with the CA certificate, and each CA needs its
# own responder certificate -- and section 3f forbids
# keeping the old path as a fallback. So the assertion is inverted: a CA with no
# responder credential must REFUSE, not quietly sign with the CA key.
#
# A silent CA-signed answer is the dangerous outcome: it verifies, so nothing looks
# wrong, and the property "the CA key is only reached for issuance" is lost without a
# single error anywhere.
echo "=== a CA with NO responder credential refuses, it does not fall back to the CA key ==="
cat > plain.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
LOG_LEVEL=err
EOF
seed_ca_from_conf plain.conf   # register the CA (SIGNING_CA_* no longer seed it)
P=$(start_ocsp plain.conf); sleep 1
OUT=$(ocsp_q bb good2.der)
chk "no responder credential -> the response does NOT verify" no \
    "$(echo "$OUT" | grep -q 'Response verify OK' && echo yes || echo no)"
# And it must be an explicit internal error, not a malformed reply or a hang.
chk "  it is an explicit error response" yes \
    "$(echo "$OUT" | grep -qiE 'internalerror|Responder Error' && echo yes || echo no)"
# The log must name the remedy — a refusal nobody can act on is its own defect.
chk "  and the log names the cert_id to issue" yes \
    "$(grep -q 'ocsp-ra-ca-global' srv.log && echo yes || echo no)"
kill $P 2>/dev/null; wait $P 2>/dev/null

echo
echo "=== OCSP RESPONDER: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
