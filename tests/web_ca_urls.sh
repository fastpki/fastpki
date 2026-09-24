#!/usr/bin/env bash
# Web CA-create read-only AIA/CRLDP pre-fill. GET
# /api/ca-instances/derived-urls?id=<new-id> returns the URLs a NEW CA would carry,
# derived from the request's tenant + the CA id so the operator can't mistype them.
# Every CA has a real id, so the URLs always name it: /{ca_id}.crt (caIssuers, DER
# non-TLS) and /{ca_id}.crl (CRL DP); OCSP is the shared per-tenant /ocsp.
# (The full apex/subdomain matrix is covered by ca_urls.sh; this is the API wiring.)
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
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18096
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
# ⚠️ THE ENDPOINT RETURNS ARRAYS — one entry per data center — so this reads the FIRST,
# which is always this node's. An accessor still looking for a bare string would return
# empty for every key, and each comparison below would quietly compare "" with "".
jget(){ echo "$1" | tr ',' '\n' | grep -o "\"$2\":\\[\"[^\"]*\"" | head -1 | sed 's/.*\["//;s/"$//'; }

pg_setup web_ca_urls
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
ca_in_token ca.pem "/CN=Issuing CA" 3650
cp ca.pem root.pem
source "$ROOT/tests/user_helpers.sh"
seed_web_user boss bosspw admin
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
BASE_URL=https://pki.example.org
BASE_DOMAIN=example.org
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat srv.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null

echo "=== derived-urls previews the URLs a new CA 'extra' would carry ==="
# ⚠️ All three of these are served by fastpki-ocsp — a PLAIN HTTP listener on
# OCSP_PORT — so the URL must be http://<host>:<OCSP_PORT>/…, and BASE_URL's own scheme
# (https, here) must NOT carry over.
#   Https pointed a validator at a TLS port that serves none of these paths, and
#         AIA/CRLDP must not require the PKI they are used to validate (RFC 5280 §4.2.2.1).
#   and the product must not rely on a load balancer redirecting requests to the correct
#         ports, because a load balancer is out of scope.
# This suite previously asserted the https, port-less form: it pinned the bug in place.
R=$(curl -s -b boss.cj "$U/api/ca-instances/derived-urls?id=extra")
chk "CRL DP names the id (.crl)"    "http://pki.example.org:8080/extra.crl" "$(jget "$R" crl)"
chk "caIssuers names the id (.crt)" "http://pki.example.org:8080/extra.crt" "$(jget "$R" ca_issuers)"
chk "AIA OCSP is the shared path"   "http://pki.example.org:8080/ocsp"      "$(jget "$R" ocsp)"
# ⚠️ AND THE SHAPE ITSELF. jget reads the first element, so it would go on passing if the
# endpoint quietly went back to a bare string — and the console renders these by joining
# an array, which would then show one character per line.
chk "  the three are JSON arrays, not strings" yes \
    "$(printf '%s' "$R" | grep -q '"crl":\[' \
       && printf '%s' "$R" | grep -q '"ocsp":\[' \
       && printf '%s' "$R" | grep -q '"ca_issuers":\[' && echo yes || echo no)"
# ⚠️ THE THREE ABOVE ARE A PREVIEW FOR A CA THAT DOES NOT EXIST — 'extra' was never
# registered — so there is no key generation to name and the flat form is the honest
# answer. That also means they say NOTHING about generation-qualified URLs, which is why the pair below exists.
#
# For a CA that DOES exist, the console must show what issuance will actually bake in
# — <base>/{ca_id}/{ski}.p7c. The comment on the endpoint says display and issuance must not
# drift; they would have, with the console advertising a flat URL while every
# certificate named a generation. `ca` is the registered CA in this fixture.
REAL=$(curl -s -b boss.cj "$U/api/ca-instances/derived-urls?id=ca")
CA_SKI=$("$OSSL" x509 -in ca.pem -noout -text 2>/dev/null \
          | awk '/X509v3 Subject Key Identifier/{getline; gsub(/[ :]/,""); print tolower($0); exit}')
chk "PRECONDITION: the registered CA has an SKI" yes "$([ -n "$CA_SKI" ] && echo yes || echo no)"
# ⚠️ .p7c: the qualified target is a BUNDLE (a certs-only PKCS#7), because the lone
# generation leaves an AIA-walking client one hop short after a rekey. The extension is
# part of the contract — RFC 5280 §4.2.2.1 pairs a collection with application/pkcs7-mime.
chk "a REGISTERED CA's caIssuers names its generation, as a .p7c bundle" \
    "http://pki.example.org:8080/ca/$CA_SKI.p7c" "$(jget "$REAL" ca_issuers)"
# BASE_URL is https AND could carry its own port; neither may leak into these.
chk "no https anywhere in the three" no \
    "$(printf '%s' "$R" | grep -q 'https://' && echo yes || echo no)"

echo "=== A port BASE_URL carries is the CONSOLE's, not the OCSP listener's ==="
# An operator whose console is behind a non-default port writes BASE_URL=https://host:8443.
# Carrying that port into the CRL/AIA URLs would send every validator to the console.
# Restarted with a BASE_URL that has a port and a non-default OCSP_PORT, so a single
# hardcoded ":8080" cannot pass this.
kill $P 2>/dev/null; wait $P 2>/dev/null
sed -e 's|^BASE_URL=.*|BASE_URL=https://pki.example.org:8443|' bootstrap.conf > pki2.conf
echo "OCSP_PORT=9999" >> pki2.conf
"$WEB" --config pki2.conf >srv2.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
curl -s -c boss2.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null
R2=$(curl -s -b boss2.cj "$U/api/ca-instances/derived-urls?id=extra")
chk "the console port is replaced by OCSP_PORT" "http://pki.example.org:9999/extra.crl" "$(jget "$R2" crl)"
chk "  and OCSP too"                            "http://pki.example.org:9999/ocsp"      "$(jget "$R2" ocsp)"

echo "=== unauthenticated request is refused ==="
chk "no cookie -> 401/403" yes "$(c=$(curl -s -o /dev/null -w '%{http_code}' "$U/api/ca-instances/derived-urls?id=extra"); { [ "$c" = 401 ] || [ "$c" = 403 ]; } && echo yes || echo no)"

echo
echo "=== WEB CA URLS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
