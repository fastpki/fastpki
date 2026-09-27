#!/usr/bin/env bash
# EST /csrattrs (RFC 7030 §4.5). With EST_CSRATTRS set, GET /csrattrs returns a
# base64 DER SEQUENCE OF OBJECT IDENTIFIER listing those OIDs; with it unset the
# endpoint answers 204 No Content (the RFC's empty-response form).
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
W="$(mktemp -d)"; cd "$W"; PORT=18463
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }
has() { echo "$1" | grep -qi "$2" && echo yes || echo no; }

ca_in_token ca.pem "/CN=CSRAttrs CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3650 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup est_csrattrs
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT

mkconf() { # $1 = EST_CSRATTRS value (may be empty)
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
EST_BIND=127.0.0.1
EST_PORT=$PORT
EST_CSRATTRS=$1
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
}
start() { "$ROOT/build/fastpki-est" --config bootstrap.conf >srv.log 2>&1 & P=$!; sleep 1; }
stop()  { kill $P 2>/dev/null; wait $P 2>/dev/null; }
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
URL="https://127.0.0.1:$PORT/.well-known/est/ca/csrattrs"

echo "=== configured OIDs -> SEQUENCE OF OID ==="
# challengePassword (1.2.840.113549.1.9.7) + id-ecPublicKey (1.2.840.10045.2.1)
mkconf "1.2.840.113549.1.9.7, 1.2.840.10045.2.1"; start
CODE=$(curl -sk -o body.b64 -w '%{http_code}' -H 'Accept: application/csrattrs' "$URL")
CT=$(curl -sk -o /dev/null -w '%{content_type}' "$URL")
chk "csrattrs returns 200"                200 "$CODE"
chk "content-type is application/csrattrs" yes "$(has "$CT" 'application/csrattrs')"
PARSE=$("$OSSL" base64 -d -A < body.b64 2>/dev/null | "$OSSL" asn1parse -inform DER 2>&1)
echo "$PARSE" | sed 's/^/    /'
chk "body is a SEQUENCE"                   yes "$(has "$PARSE" 'SEQUENCE')"
chk "challengePassword OID present"        yes "$(has "$PARSE" 'challengePassword')"
chk "id-ecPublicKey OID present"           yes "$(has "$PARSE" 'id-ecPublicKey')"
stop

echo "=== profile csr_attrs -> AttrOrOID incl. the Attribute form ==="
# A profile whose csr_attrs mixes a bare OID (challengePassword) and an Attribute
# (id-ecPublicKey with a value SET naming secp384r1). EST_DEFAULT_PROFILE makes an
# anonymous /csrattrs advertise it (authenticated clients resolve their own).
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
# ⚠️ SIGNING_CA_ID must be here too. Without it seed_ca_from_conf falls back to a
# GENERATED id and tries to insert the same certificate under a different CA, which
# fails on the serial primary key — so this second seed had never registered anything.
# It was invisible because the duplicate-key line looked like the harmless one every
# other suite printed.
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
EST_BIND=127.0.0.1
EST_PORT=$PORT
EST_CSRATTRS=
EST_DEFAULT_PROFILE=estp
LOG_LEVEL=err
EOF
seed_cert_profiles '{"estp":{"csr_attrs":["1.2.840.113549.1.9.7",{"oid":"1.2.840.10045.2.1","values":["1.3.132.0.34"]}]}}'
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
start
CODE=$(curl -sk -o body.b64 -w '%{http_code}' "$URL")
chk "profile csrattrs returns 200" 200 "$CODE"
PARSE=$("$OSSL" base64 -d -A < body.b64 2>/dev/null | "$OSSL" asn1parse -inform DER 2>&1)
echo "$PARSE" | sed 's/^/    /'
chk "outer SEQUENCE"                    yes "$(has "$PARSE" 'SEQUENCE')"
chk "bare challengePassword OID"        yes "$(has "$PARSE" 'challengePassword')"
chk "Attribute type id-ecPublicKey"     yes "$(has "$PARSE" 'id-ecPublicKey')"
chk "Attribute value SET present"       yes "$(has "$PARSE" 'SET')"
chk "value names secp384r1"             yes "$(has "$PARSE" 'secp384r1')"
stop

echo "=== unset -> 204 No Content ==="
mkconf ""; start
CODE=$(curl -sk -o /dev/null -w '%{http_code}' "$URL")
chk "empty csrattrs returns 204" 204 "$CODE"
stop

echo
echo "=== EST CSRATTRS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
