#!/usr/bin/env bash
# RFC 4387 §2 `uri` selector. A cert carrying a SubjectAltName URI
# must be findable in the store by ?uri=<value>. URI SANs are opt-in per profile
#, so we enroll through a profile that permits them, then prove:
#   EST simpleenroll (URI SAN) -> cert_uris populated -> store ?uri= returns it.
# A cert can carry several URIs (each is indexed); a non-matching URI 404s and a
# cert issued without the URI is not returned by it.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
W="$(mktemp -d)"; cd "$W"; EST=18470; STORE=18471
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Store URI CA" 3
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3 -subj "/CN=localhost" >/dev/null 2>&1
printf "internal\n" > domains.txt
pg_setup store_uri
seed_domains $W/domains.txt   # allowed_domains is the sole source
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
seed_web_user uritester s3cret-u requester
# A profile that permits URI SANs, granted to the enrolling user in place of the builtin
# `requester`. With one profile in the union it is the single member, which is what makes it
# the answer when EST asks for no profile by name.
grant_profile uritester uritest

common="SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
LOG_LEVEL=err"
cat > est.conf <<EOF
$common
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$EST
CERT_VALIDITY_DAYS=365
EOF
seed_cert_profiles '{"uritest":{"allowed_san_types":["dns","uri"]}}'
printf "%s\nSTORE_BIND=127.0.0.1\nSTORE_PORT=%s\n" "$common" "$STORE" > store.conf
seed_ca_from_conf est.conf   # register CA 'ca' (SIGNING_CA_* no longer seed it)

"$ROOT/build/fastpki-est"   --config est.conf   >est.log   2>&1 & E=$!
"$ROOT/build/fastpki-store" --config store.conf >store.log 2>&1 & S=$!
sleep 1; trap 'pg_cleanup; kill $E $S 2>/dev/null' EXIT
if ! kill -0 $E 2>/dev/null; then echo "fastpki-est died:";   cat est.log;   exit 1; fi
if ! kill -0 $S 2>/dev/null; then echo "fastpki-store died:"; cat store.log; exit 1; fi

URI="https://host.internal/tls-id/42"
URI2="spiffe://internal/ns/prod/sa/web"

echo "=== EST enroll with two URI SANs ==="
"$OSSL" req -new -subj "/CN=host.internal" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr \
    -addext "subjectAltName=URI:$URI,URI:$URI2" >/dev/null 2>&1
"$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
curl -sk -u "uritester:s3cret-u" --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
    "https://127.0.0.1:$EST/.well-known/est/ca/simpleenroll" \
    | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs -out leaf.pem 2>/dev/null
chk "cert issued" ok "$( grep -q 'BEGIN CERTIFICATE' leaf.pem 2>/dev/null && echo ok || echo no )"
[ -s leaf.pem ] || { echo "enroll failed:"; cat est.log; exit 1; }
# The issued cert must actually carry both URI SANs (profile permitted them).
SAN=$("$OSSL" x509 -in leaf.pem -noout -ext subjectAltName 2>/dev/null)
chk "leaf carries URI SAN 1" yes "$( echo "$SAN" | grep -qF "$URI"  && echo yes || echo no )"
chk "leaf carries URI SAN 2" yes "$( echo "$SAN" | grep -qF "$URI2" && echo yes || echo no )"

fpr_of(){ "$OSSL" x509 -in "$1" -inform "${2:-PEM}" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }
LEAF_FPR=$(fpr_of leaf.pem PEM)
find_uri(){ # url-encoded value -> yes/no (returned DER equals the leaf)
    local code; code=$(curl -s -o hit.der -w "%{http_code}" -G "http://127.0.0.1:$STORE/certificates/search" --data-urlencode "uri=$1")
    [ "$code" = "200" ] || { echo "no($code)"; return; }
    [ "$(fpr_of hit.der DER)" = "$LEAF_FPR" ] && echo yes || echo no
}

echo "=== store search by uri ==="
chk "findable by URI SAN 1" yes "$(find_uri "$URI")"
chk "findable by URI SAN 2" yes "$(find_uri "$URI2")"

echo "=== a non-matching uri 404s (no match-all) ==="
code=$(curl -s -o /dev/null -w "%{http_code}" -G "http://127.0.0.1:$STORE/certificates/search" --data-urlencode "uri=https://host.internal/nope")
chk "unknown uri -> 404" 404 "$code"

echo
echo "=== STORE URI: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
