#!/usr/bin/env bash
# Microsoft Intune SCEP validation, end to end against tests/tools/intune_stub.cpp, which
# plays Entra, Graph and Intune on one HTTPS port and CHECKS the credential: every token
# request must carry a PS256 assertion signed by a certificate registered on the app, and
# every addKey/removeKey a proof signed by one.
#
# What it proves:
#   * `fastpki-ca intune add` creates the connection, the `intune` key in the token and the
#     CA's credential certificate, and Entra refuses it until it is uploaded;
#   * a device enrols at <SCEP_PATH>/intune/<id> only with a challenge Intune accepts, the
#     certificate is owned by intune\<id>, and Intune is told its serial and thumbprint;
#   * every refusal after validation is reported back to Intune, and a success notification
#     Intune refuses leaves the certificate revoked, not issued;
#   * the ordinary per-CA route never asks Intune;
#   * fastpki-scep collects revocation requests on its own, and `intune sync` revokes only
#     what the connection issued;
#   * a renewed credential registers itself with proof of the old one, and the replaced
#     certificate is then removed from the app.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF

W="$(mktemp -d)"; cd "$W"
PORT=18491; MS_PORT=18492
TC="$ROOT/build/scep-testclient"; CA="$ROOT/build/fastpki-ca"; STUB="$ROOT/build/intune-stub"
pass=0; fail=0; P=; SP=
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token root.pem "/CN=Intune Test Root" 3650 introot \
    || { echo "SKIP: could not mint a CA key in a token"; exit 0; }
ROOT_URI="$CA_KEY_URI"
ca_in_token sub.pem "/CN=Intune Test Issuing CA" 3650 intsub root.pem "$ROOT_URI" \
    || { echo "SKIP: could not mint the sub CA key"; exit 0; }
SUB_TOKEN=$(printf '%s' "$CA_KEY_URI" | sed -n 's/.*token=\([^;?]*\).*/\1/p')
pg_setup intune_scep
trap 'pg_cleanup; kill ${P:-} ${SP:-} 2>/dev/null' EXIT
printf "internal\n" > domains.txt; seed_domains "$W/domains.txt"
printf '1234' > pin

cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/sub.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=intsub
PG_CONNINFO=$PG_CONNINFO
PKCS11_TOKEN=$SUB_TOKEN
PKCS11_PIN_FILE=$W/pin
SCEP_BIND=127.0.0.1
SCEP_PORT=$PORT
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf

# ── the stand-in for Microsoft ──────────────────────────────────────────────────────────
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout ms.key -out ms.pem -days 2 \
    -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
# The only trust the product is given for it — the system store, as for the real endpoints.
export SSL_CERT_FILE="$W/ms.pem"
mkdir -p ms
"$STUB" "$MS_PORT" ms.pem ms.key "$W/ms" > stub.log 2>&1 & SP=$!
wait_port "$MS_PORT" "$SP" || true
chk "PRECONDITION: the Microsoft stand-in is up" yes "$(kill -0 $SP 2>/dev/null && echo yes || echo no)"
MS="https://127.0.0.1:$MS_PORT"
TENANT=aaaaaaaa-1111-2222-3333-444444444444; APP=bbbbbbbb-1111-2222-3333-444444444444
ev(){ cat "$W/ms/events.log" 2>/dev/null; }

echo "=== intune add creates the connection and the credential ==="
OUT=$("$CA" --config bootstrap.conf intune add c1 --tenant "$TENANT" --app "$APP" --ca intsub \
      --role requester --login-url "$MS" --graph-url "$MS" --intune-resource "$MS/" 2>&1); RC=$?
chk "intune add succeeds" 0 "$RC"
[ "$RC" = 0 ] || echo "$OUT" | sed 's/^/    /'
chk "  the connection is stored" 1 "$(pg_exec "select count(*) from intune_connections where id='c1';")"
chk "  its subject holds the role" 1 \
    "$(pg_exec "select count(*) from subject_roles where selector_value='intune\\c1' and role='requester';")"
chk "  the CA has an Intune credential certificate" 1 \
    "$(pg_exec "select count(*) from certs where cert_id='intune-intsub' and status=0;")"
"$CA" --config bootstrap.conf intune cert c1 --out cred.pem >/dev/null 2>&1
chk "  intune cert writes it" yes "$([ -s cred.pem ] && echo yes || echo no)"
chk "  it is an RSA certificate for client authentication" yes \
    "$("$OSSL" x509 -in cred.pem -noout -text 2>/dev/null | grep -q 'rsaEncryption' &&
       "$OSSL" x509 -in cred.pem -noout -ext extendedKeyUsage 2>/dev/null | grep -q 'Client Authentication' &&
       echo yes || echo no)"
chk "  issued by the connection's CA" yes \
    "$("$OSSL" verify -partial_chain -CAfile sub.pem cred.pem >/dev/null 2>&1 && echo yes || echo no)"
chk "  a second connection on the same CA reuses the credential" 0 \
    "$("$CA" --config bootstrap.conf intune add c2 --tenant "$TENANT" --app "$APP" --ca intsub \
        --login-url "$MS" --graph-url "$MS" --intune-resource "$MS/" >/dev/null 2>&1; echo $?)"
chk "  (still one credential certificate)" 1 \
    "$(pg_exec "select count(*) from certs where cert_id='intune-intsub';")"
"$CA" --config bootstrap.conf add introot --name "Intune Test Root" --ca-pem root.pem \
    --ca-key "$ROOT_URI" >/dev/null 2>&1
chk "PRECONDITION: the root is registered with its key" 1 \
    "$(pg_exec "select count(*) from certs where id='introot' and is_ca;")"
OUT=$("$CA" --config bootstrap.conf intune add c3 --tenant "$TENANT" --app "$APP" --ca introot 2>&1); RC=$?
chk "  a root CA is refused" "1|yes" "$RC|$(echo "$OUT" | grep -q 'is a root' && echo yes || echo no)"
chk "  an app id that is not a GUID is refused" 1 \
    "$("$CA" --config bootstrap.conf intune add c4 --tenant "$TENANT" --app not-a-guid --ca intsub >/dev/null 2>&1; echo $?)"

echo "=== Entra refuses the certificate until the administrator uploads it ==="
chk "intune test fails before the upload" 1 "$("$CA" --config bootstrap.conf intune test c1 >/dev/null 2>&1; echo $?)"
chk "  because the stand-in could not match the assertion to a registered certificate" yes \
    "$(ev | grep -q 'token refused: AADSTS700027' && echo yes || echo no)"
"$OSSL" x509 -in cred.pem -outform DER -out cred.der
CRED_SHA1=$("$OSSL" x509 -in cred.pem -noout -fingerprint -sha1 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')
cp cred.der "ms/registered/$CRED_SHA1.der"     # the administrator's upload
chk "intune test passes after it" 0 "$("$CA" --config bootstrap.conf intune test c1 >/dev/null 2>&1; echo $?)"
chk "  the token came from a PS256 assertion signed by that certificate" yes \
    "$(ev | grep -q "token scope=https://127.0.0.1:$MS_PORT/.default cert=$CRED_SHA1" && echo yes || echo no)"

echo "=== a device enrols through the Intune route ==="
"$ROOT/build/fastpki-scep" --config bootstrap.conf >srv.log 2>&1 & P=$!
wait_port "$PORT" "$P" || true
chk "PRECONDITION: the SCEP server is up" yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"
IURL="http://127.0.0.1:$PORT/scep/intune/c1"
curl -s "$IURL?operation=GetCACert" -o ca_dl.der
"$OSSL" x509 -inform DER -in ca_dl.der -out ca_dl.pem 2>/dev/null \
    || "$OSSL" pkcs7 -inform DER -in ca_dl.der -print_certs -out ca_dl.pem 2>/dev/null
chk "GetCACert answers on the Intune route" yes "$([ -s ca_dl.pem ] && echo yes || echo no)"

# enrol <n> <cn> <challenge> [url] -> pkiStatus=N ; leaves dev<n>.key, issued<n>.der
enrol(){
    local n="$1" cn="$2" ch="$3" url="${4:-$IURL}"
    printf '[req]\ndistinguished_name=dn\nattributes=at\nprompt=no\n[dn]\nCN=%s\n[at]\nchallengePassword=%s\n' \
        "$cn" "$ch" > "r$n.cnf"
    "$OSSL" req -new -newkey rsa:2048 -nodes -keyout "dev$n.key" -config "r$n.cnf" \
        -outform DER -out "csr$n.der" >/dev/null 2>&1
    "$OSSL" req -x509 -key "dev$n.key" -subj "/CN=$cn" -days 2 -out "client$n.pem" >/dev/null 2>&1
    "$TC" build ca_dl.pem "client$n.pem" "dev$n.key" "csr$n.der" "req$n.der" >/dev/null 2>&1
    curl -s -o "resp$n.der" -X POST --data-binary @"req$n.der" \
        -H "Content-Type: application/x-pki-message" "$url?operation=PKIOperation"
    "$TC" parse "client$n.pem" "dev$n.key" "resp$n.der" "issued$n.der" 2>/dev/null
}

chk "a challenge Intune accepts enrols" "pkiStatus=0" "$(enrol 1 device1.internal intune-good)"
kill -0 "$P" 2>/dev/null || { echo "  --- fastpki-scep exited; its log ---"; tail -20 srv.log; }
chk "  the certificate is owned by the connection's subject" 'intune\c1' \
    "$(pg_exec "select owner from certs where cn='device1.internal';")"
SER1=$(pg_exec "select serial from certs where cn='device1.internal';")
"$OSSL" x509 -inform DER -in issued1.der -out issued1.pem 2>/dev/null
TH1=$("$OSSL" x509 -in issued1.pem -noout -fingerprint -sha1 2>/dev/null | sed 's/.*=//; s/://g')
chk "  Intune was asked to validate it" yes "$(ev | grep -q 'validate .*challenge=intune-good caller=FastPKI' && echo yes || echo no)"
chk "  and told its serial and thumbprint" yes \
    "$(ev | grep -q "success .*serial=$SER1 thumbprint=$TH1 .*issuer=Intune Test Issuing CA" && echo yes || echo no)"

chk "a challenge Intune refuses does not enrol" "pkiStatus=2" "$(enrol 2 device2.internal intune-expired)"
chk "  and nothing was issued" 0 "$(pg_exec "select count(*) from certs where cn='device2.internal';")"

chk "a refused success notification means no certificate" "pkiStatus=2" "$(enrol 3 device3.internal intune-notifyfail)"
chk "  the certificate it signed is revoked" "-1" "$(pg_exec "select status from certs where cn='device3.internal';")"

chk "a CSR the profile refuses after Intune accepted it" "pkiStatus=2" "$(enrol 4 device4.example.com intune-good)"
chk "  is reported to Intune as a failure" yes \
    "$(ev | grep -q 'failure .*hresult=13' && echo yes || echo no)"

pg_exec "delete from subject_roles where selector_value='intune\\c1';" >/dev/null
chk "without scep:enrol for the connection's subject" "pkiStatus=2" "$(enrol 5 device5.internal intune-good)"
chk "  Intune is told access was denied" yes "$(ev | grep -q 'failure .*hresult=5 ' && echo yes || echo no)"
pg_exec "insert into subject_roles(selector_type,selector_value,role,created) values('user','intune\\c1','requester',0);" >/dev/null

BEFORE=$(ev | grep -c '^validate')
chk "the CA's own route does not accept an Intune challenge" "pkiStatus=2" \
    "$(enrol 6 device6.internal intune-good "http://127.0.0.1:$PORT/scep/intsub")"
chk "  and never asked Intune" "$BEFORE" "$(ev | grep -c '^validate')"

chk "an unknown connection is 404" 404 \
    "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/scep/intune/nope?operation=GetCACaps")"
pg_exec "update intune_connections set enabled=false where id='c2';" >/dev/null
chk "a disabled connection is 503" 503 \
    "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/scep/intune/c2?operation=GetCACaps")"

echo "=== fastpki-scep collects revocation requests by itself ==="
got=no
for _ in $(seq 1 60); do
    ev | grep -q '^download issuer=Intune Test Issuing CA' && { got=yes; break; }
    sleep 1
done
chk "the SCEP service asked Intune for this CA's revocation requests" yes "$got"
kill $P 2>/dev/null; wait $P 2>/dev/null; P=

echo "=== intune sync revokes only what the connection issued ==="
CRED_SER=$(pg_exec "select serial from certs where cert_id='intune-intsub' and status=0;")
printf '%s\ndeadbeef\n%s\n' "$SER1" "$CRED_SER" > ms/revoke
"$CA" --config bootstrap.conf intune sync c1 >sync0.out 2>&1
chk "the device's certificate is revoked" "-1" "$(pg_exec "select status from certs where serial='$SER1';")"
chk "  and reported as revoked" yes "$(ev | grep -q '^upload ctx-1 succeeded=true' && echo yes || echo no)"
chk "an unknown serial is reported as not found" yes \
    "$(ev | grep -q '^upload ctx-2 succeeded=false code=CertificateNotFoundError' && echo yes || echo no)"
chk "a certificate the connection did not issue is refused" yes \
    "$(ev | grep -q '^upload ctx-3 succeeded=false code=NotSupportedError' && echo yes || echo no)"
chk "  and stays valid" 0 "$(pg_exec "select status from certs where serial='$CRED_SER';")"

echo "=== a renewed credential registers itself ==="
"$CA" --config bootstrap.conf renew-service-certs --ca intsub --force >renew.out 2>&1
NEW_SHA1=$(pg_exec "select lower(fp_sha1) from certs where cert_id='intune-intsub' and status=0;")
chk "PRECONDITION: the credential was renewed" yes \
    "$([ -n "$NEW_SHA1" ] && [ "$NEW_SHA1" != "$CRED_SHA1" ] && echo yes || echo no)"
chk "  intune test says the renewal is not registered yet" 1 \
    "$("$CA" --config bootstrap.conf intune test c1 >/dev/null 2>&1; echo $?)"
"$CA" --config bootstrap.conf intune sync c1 >sync1.out 2>&1
chk "intune sync registers it with proof of the old certificate" yes \
    "$(ev | grep -q "^addKey $NEW_SHA1" && echo yes || echo no)"
"$CA" --config bootstrap.conf intune sync c1 >sync2.out 2>&1
chk "the next sync removes the certificate it replaced" yes \
    "$(ev | grep -q "^removeKey $CRED_SHA1" && echo yes || echo no)"
chk "  the app now holds only the current certificate" "$NEW_SHA1.der" "$(ls ms/registered)"
chk "  and Entra accepts it" 0 "$("$CA" --config bootstrap.conf intune test c1 >/dev/null 2>&1; echo $?)"

echo "=== a device still enrols after the rollover ==="
"$ROOT/build/fastpki-scep" --config bootstrap.conf >srv2.log 2>&1 & P=$!
wait_port "$PORT" "$P" || true
chk "a challenge Intune accepts enrols" "pkiStatus=0" "$(enrol 7 device7.internal intune-good)"
chk "  with a token from the renewed certificate" yes \
    "$(ev | grep -q "token scope=https://127.0.0.1:$MS_PORT//.default cert=$NEW_SHA1" && echo yes || echo no)"
kill $P 2>/dev/null; wait $P 2>/dev/null; P=
kill $SP 2>/dev/null; wait $SP 2>/dev/null; SP=

echo "=== removing a connection removes its subject's roles ==="
chk "intune remove succeeds" 0 "$("$CA" --config bootstrap.conf intune remove c1 >/dev/null 2>&1; echo $?)"
chk "  the connection is gone" 0 "$(pg_exec "select count(*) from intune_connections where id='c1';")"
chk "  and so is the role granted to intune\\c1" 0 \
    "$(pg_exec "select count(*) from subject_roles where selector_value='intune\\c1';")"
chk "  what it issued stays valid" 0 "$(pg_exec "select status from certs where cn='device7.internal';")"

echo
echo "=== INTUNE SCEP: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
