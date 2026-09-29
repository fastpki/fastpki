#!/usr/bin/env bash
# ONE certificate serial, written one way and read four.
#
# `certs.serial` is written by pki::x509_serial_hex(): lowercase hex, leading zeros
# stripped. Every reader looks the row up by EXACT STRING MATCH, so a reader that spells
# the value differently finds nothing — and "nothing" is indistinguishable from "you are
# not allowed", which is why this survived so long.
#
# The rule had been hand-written four times. Two copies had drifted:
#
#   src/est/main.cpp      self-renewal        lowercased only  ← WRONG
#   src/web/main.cpp      GET  /api/certs/<serial>   lowercased only  ← WRONG
#   src/web/main.cpp      POST /api/certs/<serial>/revoke  lowercased only  ← WRONG
#   src/scep/main.cpp     asn1_int_to_serial_hex   correct
#   src/cmp/main.cpp      rr handler               correct
#
# httplib's PeerCert::serial() returns BN_bn2hex output verbatim — UPPERCASE and padded
# to an even number of digits — and `openssl x509 -noout -serial` prints the same padded
# form. So a certificate whose top nibble is zero (one in sixteen) read back as `09ab…`
# against a stored `9ab…`:
#
#   * its own issuer told it "client certificate 096e06b9… was not issued here";
#   * the console 404'd on its detail page;
#   * and an operator could not REVOKE it.
#
# ⚠️ THIS SUITE DOES NOT WAIT FOR A 1-IN-16 DRAW. est_mtls_role.sh found the bug that way
# — two failures in nine runs — and a guard that only fires 6% of the time is not a guard.
# The serial here is CHOSEN: a certificate is minted with -set_serial 0x09… and imported
# through the product, so the row is written by the real writer and every read below is
# deterministic.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
unset OPENSSL_CONF
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; WPORT=18601; EPORT=18602
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ grep -q "$2" <<<"$1" && echo yes || echo no; }

pg_setup serial_canonical_form
P=; E=
trap 'pg_cleanup; kill ${P:-} ${E:-} 2>/dev/null' EXIT
ca_in_token ca.pem "/CN=Serial Form CA" 3650 serialca \
    || { echo "SKIP: could not mint a CA key in a token"; exit 0; }
cp ca.pem root.pem
seed_web_user boss bosspw admin
printf "internal\n" > domains.txt; seed_domains "$W/domains.txt"
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3 \
        -subj "/CN=localhost" >/dev/null 2>&1

cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=serialca
WEB_BIND=127.0.0.1
WEB_PORT=$WPORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
seed_ca_from_conf web.conf
"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat web.log; exit 1; }
U="http://127.0.0.1:$WPORT"
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null

# ── the chosen serial ────────────────────────────────────────────────────────────────
# 0x09ab… — 20 bytes, top nibble zero, which is exactly the shape that broke. The PADDED
# form is what BN_bn2hex and `openssl x509 -serial` emit; the CANONICAL form is what
# x509_serial_hex() stores. They differ by one character, and that is the whole bug.
PADDED=09ab1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d
CANON=${PADDED#0}

echo "=== 1. the WRITER's form: leading zeros are stripped on the way in ==="
# Registered through POST /api/ca-instances (import), so the `certs` row is written by the
# product's own writer rather than by an INSERT this script composes. A row this suite
# wrote itself would prove nothing about the form the product actually stores.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout dev.key -out dev.csr \
        -subj "/CN=device-zero.internal" >/dev/null 2>&1
# CA:TRUE because the registration path this suite uses to create the row is CA import,
# which refuses anything else; digitalSignature because section 4 then presents the very
# same certificate as a TLS CLIENT certificate, and without it the handshake never
# happens — curl reports 000 and the section blames EST for a connection it never made.
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyCertSign,cRLSign\n' > ext.cnf
"$OSSL" x509 -req -in dev.csr -CA ca.pem -CAkey "$CA_KEY_URI" \
        -set_serial "0x$PADDED" -days 3 -extfile ext.cnf -out dev.pem \
        ${CA_KEY_ENGINE_ARGS:-} >/dev/null 2>&1 \
  || "$OSSL" x509 -req -in dev.csr -CA ca.pem -CAkey "$CA_KEY_URI" -provider pkcs11 \
        -provider default -set_serial "0x$PADDED" -days 3 -extfile ext.cnf \
        -out dev.pem >/dev/null 2>&1
chk "PRECONDITION: a certificate was minted with the chosen serial" yes \
    "$(grep -q 'BEGIN CERTIFICATE' dev.pem 2>/dev/null && echo yes || echo no)"
# ⚠️ Assert the SERIAL, not just that a file exists. -set_serial silently accepting a
# different value would make every assertion below vacuous while they all still passed.
chk "  and openssl prints it in the PADDED form"    "$PADDED" \
    "$("$OSSL" x509 -in dev.pem -noout -serial 2>/dev/null | sed 's/serial=//' | tr 'A-Z' 'a-z')"
IMP=$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj -X POST "$U/api/ca-instances" \
      --data-urlencode 'id=devzero' --data-urlencode 'cert_pem@dev.pem' \
      --data-urlencode "key=$CA_KEY_URI")
chk "the certificate is registered through the product" 201 "$IMP"
chk "  and the row stores the CANONICAL form (no leading zero)" "$CANON" \
    "$(pg_exec "select serial from certs where cn='device-zero.internal';" | tr -d ' ')"

echo "=== 2. the console finds it by the form an operator would paste ==="
# `openssl x509 -noout -serial` prints PADDED. Anyone reading a serial off a certificate,
# a browser, or a log line has the padded form in their hand — it is not an exotic input.
D=$(curl -s -b boss.cj -w '|%{http_code}' "$U/api/certs/$PADDED")
chk "GET /api/certs/<padded> -> 200"        200 "${D##*|}"
chk "  and it is the right certificate"     yes "$(has "${D%|*}" 'device-zero.internal')"
# Uppercase is the other half of the same input: BN_bn2hex emits A-F.
UP=$(printf '%s' "$PADDED" | tr 'a-f' 'A-F')
chk "GET /api/certs/<PADDED UPPERCASE> -> 200" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj "$U/api/certs/$UP")"
chk "and the canonical form still works (no regression)" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj "$U/api/certs/$CANON")"

echo "=== 3. ...and it can be REVOKED by that same form ==="
# ⚠️ THE ASSERTION THAT MATTERS MOST. A detail page that 404s is an annoyance; a
# revocation that 404s means a compromised key stays trusted because the console cannot
# find the certificate it is looking straight at.
RV=$(curl -s -b boss.cj -w '|%{http_code}' -X POST "$U/api/certs/$PADDED/revoke")
chk "POST /api/certs/<padded>/revoke -> 200"  200 "${RV##*|}"
chk "  and the DB row really is revoked"      -1 \
    "$(pg_exec "select status from certs where cn='device-zero.internal';" | tr -d ' ')"

echo "=== 4. EST self-renewal resolves the same certificate ==="
# The device presents the certificate above as its client certificate. EST reads the
# serial from the TLS peer — PeerCert::serial(), i.e. the PADDED form — and looks up the
# row, so this is the same mismatch reached through a completely different door.
#
# ⚠️ It is REVOKED by section 3, which would refuse it for an unrelated and correct
# reason and hide whatever this section is testing. Un-revoke it first, and assert that
# the un-revoke landed rather than assuming it did.
pg_exec "update certs set status=0 where cn='device-zero.internal';" >/dev/null
chk "PRECONDITION: the device certificate is live again" 0 \
    "$(pg_exec "select status from certs where cn='device-zero.internal';" | tr -d ' ')"
cat > est.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=serialca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$EPORT
EST_CLIENT_CA_ID=serialca
CERT_VALIDITY_DAYS=365
LOG_LEVEL=info
EOF
"$ROOT/build/fastpki-est" --config est.conf >est.log 2>&1 & E=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "est.conf" EST_PORT "$E" || true
kill -0 $E 2>/dev/null || { echo "fastpki-est died:"; cat est.log; }
"$OSSL" req -new -subj "/CN=device-zero.internal" -newkey rsa:2048 -nodes \
        -keyout r.key -out r.csr >/dev/null 2>&1
"$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
RC=$(curl -sSk -o renew.p7 -w '%{http_code}' --cert dev.pem --key dev.key \
     --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
     "https://127.0.0.1:$EPORT/.well-known/est/serialca/simpleenroll" 2>curl.err)
chk "the device renews itself -> 200"        200 "$RC"
# A transport failure reports as 000 and says nothing; without this the suite blames the
# product for a handshake the client never completed.
[ "$RC" = 200 ] || { echo "      curl: $(tr -d '\n' < curl.err)"; }
"$OSSL" base64 -d -A -in renew.p7 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs \
        -out renew.pem 2>/dev/null
chk "  and a real certificate came back"     yes \
    "$(grep -q 'BEGIN CERTIFICATE' renew.pem 2>/dev/null && echo yes || echo no)"
chk "  for the same identity"                yes \
    "$("$OSSL" x509 -in renew.pem -noout -subject 2>/dev/null | grep -q 'device-zero.internal' \
       && echo yes || echo no)"
# ⚠️ And say WHY if it failed — "was not issued here" is the bug's fingerprint, and
# without it a reader cannot tell this apart from an ordinary authorization refusal.
grep -q 'was not issued here' est.log 2>/dev/null \
    && echo "      est.log says: $(grep 'was not issued here' est.log | tail -1)"

echo
echo "=== SERIAL CANONICAL FORM: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
