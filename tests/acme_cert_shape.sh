#!/usr/bin/env bash
# ACME issued-certificate SHAPE acceptance test. Mimics real certbot
# (EC key + empty-subject CSR with SAN), then inspects the issued cert to catch
# the defects reported: illegal keyEncipherment on an EC key, empty subject /
# no CN, non-critical SAN, missing DV policy, missing owner SDA.
# ⚠️ THIS SUITE REGISTERS WITH A REAL EAB BINDING, and that is the point. It used to
# pin ACME_EAB_REQUIRED=false because it tests ACME PROTOCOL mechanics and not deployment
# policy — but the switch is gone, and pinning it meant fourteen suites exercised a
# configuration FastPKI does not ship. acme_new_account (acme_jws.sh) provisions a kid +
# HMAC in the `keys` table and signs the RFC 8555 §7.3.4 binding, so registration here now
# takes exactly the path a real client takes.
# The DEFAULT itself is still exercised by acme_default_eab.sh, which provisions NOTHING.
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
W="$(mktemp -d)"; cd "$W"; PORT=18470; ALPN=14446
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }
has() { echo "$1" | grep -qiE "$2" && echo yes || echo no; }
source "$ROOT/tests/acme_jws.sh"

# CA with a G1-style name; ACME needs its own TLS cert.
ca_in_token ca.pem "/CN=FastPKI Signing CA G1" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_cert_shape
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > bootstrap.conf <<EOF
BASE_URL=https://localhost:$PORT
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
ACME_CERT=$W/acme.pem
ACME_KEY=$W/acme.key
PG_CONNINFO=$PG_CONNINFO
ACME_BIND=127.0.0.1
ACME_PORT=$PORT
ACME_BASE_PATH=/acme
ACME_TLS_ALPN_PORT=$ALPN
CERT_VALIDITY_DAYS=90
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-acme" --config bootstrap.conf > srv.log 2>&1 & SRV=$!
sleep 1; trap 'kill $SRV 2>/dev/null' EXIT
if ! kill -0 $SRV 2>/dev/null; then echo "fastpki-acme died:"; cat srv.log; exit 1; fi

echo "=== issue a cert like certbot does (EC key, empty-subject CSR) ==="
JWS_TMP="$W/jws"; mkdir -p "$JWS_TMP"
DOMAIN=localhost
acme_dir "https://127.0.0.1:$PORT/acme/ca/directory"
jws_newkey acct.pem
acme_new_account acct.pem
KID=$ACME_LOCATION
chk "account registered" yes "$([ -n "$KID" ] && echo yes || echo no)"

acme_post_kid acct.pem "$KID" "$ACME_NEW_ORDER" \
    "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"$DOMAIN\"}]}"
chk "newOrder -> 201" 201 "$ACME_STATUS"
ORDER_URL=$ACME_LOCATION
AUTHZ=$(printf '%s' "$ACME_BODY" | sed -n 's/.*"authorizations":\["\([^"]*\)".*/\1/p')

acme_post_kid acct.pem "$KID" "$AUTHZ" ""
# The challenge list is an array of objects, so pick the tls-alpn-01 record first and
# read its token out of THAT — reading "token" from the whole body would take whichever
# challenge happened to come first.
CH=$(printf '%s' "$ACME_BODY" | tr '{' '\n' | grep 'tls-alpn-01')
CH_URL=$(json_str "$CH" url)
TOKEN=$(json_str "$CH" token)
chk "the authz offers tls-alpn-01" yes "$([ -n "$CH_URL" ] && [ -n "$TOKEN" ] && echo yes || echo no)"

# RFC 8737: self-signed for the identifier, with a critical acmeIdentifier extension
# holding SHA-256 of the key authorization, served under ALPN "acme-tls/1".
alpn_cert "$DOMAIN" "$TOKEN" acct.pem val
chk "the validation cert carries acmeIdentifier" yes \
    "$("$OSSL" x509 -in val.pem -noout -text | grep -q '1.3.6.1.5.5.7.1.31' && echo yes || echo no)"
alpn_serve "$ALPN" val
trap 'alpn_stop; pg_cleanup; kill $SRV 2>/dev/null' EXIT

acme_post_kid acct.pem "$KID" "$CH_URL" '{}'
chk "challenge triggered -> 200" 200 "$ACME_STATUS"
acme_poll_status acct.pem "$KID" "$AUTHZ" valid && r=valid || r="$(json_str "$ACME_BODY" status)"
chk "the authorization validated over tls-alpn-01" valid "$r"
alpn_stop

# certbot's shape exactly: an EC key and a CSR with an EMPTY subject, carrying only a SAN.
"$OSSL" ecparam -name prime256v1 -genkey -noout -out leaf.key 2>/dev/null
cat > csr.cnf <<CNF
[req]
distinguished_name = dn
req_extensions = v3
prompt = no
[dn]
[v3]
subjectAltName = DNS:$DOMAIN
CNF
"$OSSL" req -new -key leaf.key -subj "/" -config csr.cnf -outform DER -out leaf.csr 2>/dev/null
chk "an empty-subject CSR was built" yes "$([ -s leaf.csr ] && echo yes || echo no)"

FIN=$(printf '%s' "$(acme_post_kid acct.pem "$KID" "$ORDER_URL" ""; printf '%s' "$ACME_BODY")" | \
      sed -n 's/.*"finalize":"\([^"]*\)".*/\1/p')
# ── a CSR may not smuggle in a name the order never validated ────────────────────
# ⚠️ REGRESSION GUARD. finalize compared only the dNSName entries of the CSR's SAN
# against the order's identifiers; every OTHER GeneralName type was collected by nothing
# and so compared against nothing. newOrder accepts `dns` identifiers and only those, so
# a solved challenge proves control of a DOMAIN — yet a CSR carrying the validated domain
# PLUS an `email:`, `IP:` or `URI:` entry was issued with those names in it.
# The profile layer is not a backstop: the default allowed_san_types is {dns,ip,email,uri},
# email has NO content restriction at all, and IP is bounded only by ALLOWED_IPS_REGEX,
# whose default is 10.0.0.0/8. One validated domain therefore bought a certificate
# asserting an arbitrary mailbox — CA mis-issuance, and no suite looked.
# Refused rather than stripped: silently dropping a requested name hands back a
# certificate that is not the one asked for, and the client learns that much later.
# The refusal happens before any state change, which is why the real CSR below is
# finalized on this SAME order — a rejected CSR must not wedge it.
for smuggle in "email:evil@victim.example" "IP:10.0.0.1" "URI:https://victim.example/"; do
    sed "s|^subjectAltName = .*|subjectAltName = DNS:$DOMAIN,$smuggle|" csr.cnf > bad.cnf
    "$OSSL" req -new -key leaf.key -subj "/" -config bad.cnf -outform DER -out bad.csr 2>/dev/null
    acme_post_kid acct.pem "$KID" "$FIN" "{\"csr\":\"$(b64url < bad.csr)\"}"
    chk "finalize refuses a CSR smuggling $smuggle" 400 "$ACME_STATUS"
    chk "  ...naming badCSR"                        yes "$(has "$ACME_BODY" 'badCSR')"
done

acme_post_kid acct.pem "$KID" "$FIN" "{\"csr\":\"$(b64url < leaf.csr)\"}"
chk "finalize -> 200" 200 "$ACME_STATUS"
acme_poll_status acct.pem "$KID" "$ORDER_URL" valid && r=valid || r="$(json_str "$ACME_BODY" status)"
chk "the order became valid" valid "$r"
CERT_URL=$(json_str "$ACME_BODY" certificate)
acme_post_kid acct.pem "$KID" "$CERT_URL" ""
printf '%s' "$ACME_BODY" > leaf.pem
chk "cert issued" yes "$([ -s leaf.pem ] && echo yes || echo no)"
[ -s leaf.pem ] || { echo "no cert; server log:"; tail -5 srv.log; echo "=== FAIL ==="; exit 1; }

T=$("$OSSL" x509 -in leaf.pem -text -noout 2>/dev/null)
echo "=== inspect the issued cert (RFC 5280 correctness) ==="
chk "key is EC (P-256)"                         yes "$(has "$T" 'id-ecPublicKey|ASN1 OID: prime256v1')"
chk "KeyUsage present"                          yes "$(has "$T" 'Key Usage')"
chk "KeyUsage has Digital Signature"            yes "$(has "$T" 'Digital Signature')"
chk "KeyUsage does NOT have Key Encipherment (illegal for EC)" no "$(has "$T" 'Key Encipherment')"
chk "Subject has a CN (synthesized from SAN)"   yes "$(has "$T" 'Subject:.*CN *= *localhost')"
chk "SubjectAltName present with the domain"    yes "$(has "$T" 'DNS:localhost')"
chk "DV certificate policy (2.23.140.1.2.1)"    yes "$(has "$T" '2.23.140.1.2.1')"
chk "owner recorded in Subject Directory Attributes" yes "$(has "$T" 'Subject Directory Attributes|X509v3 Subject Directory')"
# the leaf must verify against the CA
"$OSSL" verify -CAfile ca.pem leaf.pem >/dev/null 2>&1 && v=ok || v=bad
chk "leaf verifies against the CA" ok "$v"

echo
echo "=== ACME CERT SHAPE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
