#!/usr/bin/env bash
# Virtualized per-CA SCEP. One fastpki-scep serves multiple CA
# hierarchies under <scep_path>/{ca_instance_id}: GetCACert returns the
# instance's CA cert, and a PKCSReq enrolled against a per-CA endpoint is issued
# by THAT instance's CA (decrypt/sign use the instance key) and tagged with its
# ca_instance_id. SCEP secures the message, so plain HTTP is fine.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"   # grant_profile
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
TC="$ROOT/build/scep-testclient"; CA="$ROOT/build/fastpki-ca"
W="$(mktemp -d)"; cd "$W"; PORT=18460
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Global SCEP CA" 3650
GLOBAL_KEY_URI="$CA_KEY_URI"
cp ca.pem root.pem
# The second CA's key is token-born too — a CA private key is never a file.
ca_in_token depta.pem "/CN=Dept A CA" 3650 depta
DEPTA_KEY_URI="$CA_KEY_URI"
pg_setup scep_perca
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$GLOBAL_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
SCEP_BIND=127.0.0.1
SCEP_PORT=$PORT
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$CA" --config bootstrap.conf add dept-a --name "Dept A" --ca-pem "$W/depta.pem" --ca-key "$DEPTA_KEY_URI" >/dev/null

"$ROOT/build/fastpki-scep" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-scep died:"; cat srv.log; exit 1; fi
B="http://127.0.0.1:$PORT"

make_csr() {  # <cn> ; writes csr.der + dev.key + client.pem
    cat > req.cnf <<EOF
[req]
distinguished_name = dn
attributes = attrs
prompt = no
[dn]
CN = $1
[attrs]
challengePassword = $SCEP_CH
EOF
    "$OSSL" req -new -newkey rsa:2048 -nodes -keyout dev.key -config req.cnf -out dev.csr >/dev/null 2>&1
    "$OSSL" req -in dev.csr -outform DER -out csr.der >/dev/null 2>&1
    "$OSSL" req -x509 -key dev.key -subj "/CN=$1" -days 2 -out client.pem >/dev/null 2>&1
}
enroll() {  # <instance> <cn> -> echoes the issued cert's issuer CN
    local u="$B/scep/$1"
    curl -s "$u?operation=GetCACert" -o cacert.der
    "$OSSL" x509 -inform DER -in cacert.der -out ca_dl.pem >/dev/null 2>&1
    make_csr "$2"
    "$TC" build ca_dl.pem client.pem dev.key csr.der req.der >/dev/null 2>&1
    curl -s -X POST --data-binary @req.der -H "Content-Type: application/x-pki-message" \
        "$u?operation=PKIOperation" -o resp.der
    "$TC" parse client.pem dev.key resp.der issued.der >/dev/null 2>&1
    "$OSSL" x509 -inform DER -in issued.der -noout -issuer 2>/dev/null | sed -n 's/.*CN *= *//p'
}
code() { curl -s -o /dev/null -w '%{http_code}' "$B/scep/$1?operation=GetCACert"; }
cacn() { curl -s "$B/scep/$1?operation=GetCACert" -o c.der; "$OSSL" x509 -inform DER -in c.der -noout -subject 2>/dev/null | sed -n 's/.*CN *= *//p'; }

# ⚠️ The SHARED-challenge SCEP path resolves an identity (`owner='scep'`) and
# that identity now needs a profile grant, or the union is empty and every enrolment is
# refused. Granted before the first PKIOperation for that reason.
grant_profile scep requester
# The deployment-wide SCEP_CHALLENGE is gone, so every CSR below carries the
# PER-USER credential minted for the `scep` user. Seeding it as a real web_users row keeps
# the identity the rest of this suite already assumes: scep_kid_user("scep:scep") == "scep".
seed_web_user scep scepPW123456 requester >/dev/null 2>&1
SCEP_CH=$(scep_challenge_for scep)
chk "PRECONDITION: the scep user has a per-user challengePassword" yes \
    "$(printf '%s' "$SCEP_CH" | grep -q '^scep:.' && echo yes || echo no)"

echo "=== per-CA GetCACert ==="
chk "ca GetCACert returns the SIGNING_CA" "Global SCEP CA" "$(cacn ca)"
chk "dept-a GetCACert returns its own CA"     "Dept A CA"      "$(cacn dept-a)"
chk "unknown instance -> 404" 404 "$(code nope)"
"$CA" --config bootstrap.conf disable dept-a >/dev/null
chk "disabled instance -> 503" 503 "$(code dept-a)"
"$CA" --config bootstrap.conf enable dept-a >/dev/null

echo "=== per-CA enrollment ==="
chk "ca-issued cert signed by the SIGNING_CA" "Global SCEP CA" "$(enroll ca dev-ca.internal)"
chk "ca cert tagged ca_instance_id=ca" ca \
    "$(pg_exec "SELECT ca_instance_id FROM certs WHERE cn='dev-ca.internal';")"
chk "dept-a-issued cert signed by Dept A CA" "Dept A CA" "$(enroll dept-a dev-depta.internal)"
chk "dept-a cert tagged ca_instance_id=dept-a" dept-a \
    "$(pg_exec "SELECT ca_instance_id FROM certs WHERE cn='dev-depta.internal';")"

echo
echo "=== SCEP PER-CA: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
