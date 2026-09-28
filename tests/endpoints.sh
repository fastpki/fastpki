#!/usr/bin/env bash
# Endpoint-configuration engine. GET /api/endpoints returns a
# per-protocol map: the listener bind/path, the effective external URL (base +
# path), and the URL advertised in issued certs (AIA OCSP, CRL DP). The map is
# computed from the running config — including DB overlay keys (Task 1.1) — so
# editing an endpoint key in the overlay shows up here on restart.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"; CFG="$ROOT/build/fastpki-config"
W="$(mktemp -d)"; cd "$W"; PORT=18190
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
seg(){ echo "$1" | grep -o "\"protocol\":\"$2\"[^}]*"; }   # one protocol's JSON object

pg_setup endpoints
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
# Endpoint settings live in the DB overlay; the web server applies them at startup.
"$CFG" --config bootstrap.conf set BASE_URL https://pki.test >/dev/null
"$CFG" --config bootstrap.conf set CMP_PATH /pkix >/dev/null
"$CFG" --config bootstrap.conf set CRL_DPS http://crl.test/ca.crl >/dev/null
"$CFG" --config bootstrap.conf set AIA_OCSP http://ocsp.test >/dev/null
"$CFG" --config bootstrap.conf set ACME_BASE_PATH /acme2 >/dev/null

"$WEB" --config bootstrap.conf >web.log 2>&1 & P=$!
sleep 1; trap 'kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"
EP=$(curl -s "$U/api/endpoints")

echo "=== the endpoint map exposes every protocol ==="
for proto in EST ACME CMP SCEP OCSP CRL MS-XCEP MS-WSTEP Store; do
  chk "$proto is listed" yes "$(has "$EP" "\"protocol\":\"$proto\"")"
done

echo "=== effective external URLs are composed from BASE_URL + path ==="
chk "EST external URL"  yes "$(has "$(seg "$EP" EST)"  '"url":"https://pki.test/.well-known/est"')"
# ACME external URL is the DIRECTORY URL clients need, under the overlaid base path.
chk "ACME shows the directory URL under the overlaid base path" yes "$(has "$(seg "$EP" ACME)" '"url":"https://pki.test/acme2/directory"')"
chk "CMP path reflects the overlaid CMP_PATH" yes "$(has "$(seg "$EP" CMP)" '"path":"/pkix"')"
# CMP is a management protocol with no cert-borne locator, so "advertised" must
# be blank — nothing embeds a CMP URL in a cert. The /.well-known/cmp
# alias is a served path, not something advertised in certificates.
chk "CMP advertises nothing in certs" yes "$(has "$(seg "$EP" CMP)" '"advertised":""')"

echo "=== cert-advertised URLs (AIA / CRL DP) ==="
# These used to assert that the column echoed AIA_OCSP / CRL_DPS. It does not any more,
# and it should never have: issuance derives per-CA URLs from BASE_URL + the CA id and
# never reads those settings, so the page was reporting a URL that is in no certificate
# and that the server does not serve (the id-less shape 404s since §4a). Both settings
# are deliberately set to nonsense above and must NOT appear.
#
# endpoints_advertised.sh is the suite that checks the value against a decoded
# certificate; here we pin that the dead settings are gone and the shape is right.
chk "OCSP advertised is derived from BASE_URL" yes \
    "$(has "$(seg "$EP" OCSP)" '"advertised":"http://pki.test:8080/ocsp"')"
chk "CRL advertised is the per-CA shape"       yes \
    "$(has "$(seg "$EP" CRL)" '"advertised":"http://pki.test:8080/<ca_id>.crl"')"
chk "neither echoes the config setting"        no \
    "$(has "$EP" 'crl.test\|ocsp.test')"

echo "=== each row carries the config keys that drive it ==="
chk "EST row lists EST_PORT key"  yes "$(has "$(seg "$EP" EST)" 'EST_PORT')"
# CRL_DPS is no longer one of the keys that drives this row — BASE_URL is.
chk "CRL row lists BASE_URL key"  yes "$(has "$(seg "$EP" CRL)" 'BASE_URL')"

echo "=== Without an explicit BASE_URL, defaults reflect the real listener ==="
# Only PKI_DNS is set, so base_url is auto-derived (https://localhost, not a real
# proxy front). Plain-HTTP protocols (SCEP/OCSP/CMP/CRL/Store) must then be shown
# as http://<dns>:<port>/... — not https, and never dropping the listener port —
# while the HTTPS-native ones (EST/ACME/MS) keep https but still carry the port.
pg_setup endpoints2
PORT2=18191
cat > pki2.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT2
LOG_LEVEL=err
EOF
"$CFG" --config pki2.conf set PKI_DNS localhost >/dev/null
"$WEB" --config pki2.conf >web2.log 2>&1 & P2=$!
sleep 1; trap 'pg_cleanup; kill $P $P2 2>/dev/null' EXIT
if ! kill -0 $P2 2>/dev/null; then echo "fastpki-web(2) died:"; cat web2.log; exit 1; fi
EP2=$(curl -s "http://127.0.0.1:$PORT2/api/endpoints")
chk "SCEP default URL is http + port" yes "$(has "$(seg "$EP2" SCEP)"  '"url":"http://localhost:8448/scep"')"
chk "OCSP default URL is http + port"             yes "$(has "$(seg "$EP2" OCSP)"  '"url":"http://localhost:8080/ocsp"')"
chk "Store default URL is http + port"            yes "$(has "$(seg "$EP2" Store)" '"url":"http://localhost:8447/certs/search"')"
chk "EST default URL keeps https + port"          yes "$(has "$(seg "$EP2" EST)"   '"url":"https://localhost:8443/.well-known/est"')"

echo "=== Downloadable client configs from the live settings ==="
# On the BASE_URL=https://pki.test server (explicit front + overlaid CMP_PATH/ACME_BASE_PATH).
CMPC=$(curl -s "$U/api/client-config/cmp")
chk "CMP config carries the live CMP URL"        yes "$(has "$CMPC" 'server = https://pki.test/pkix')"
chk "CMP config is served as a named .cnf attachment" yes "$(curl -s -D - -o /dev/null "$U/api/client-config/cmp" | grep -qi 'filename="fastpki-cmp.cnf"' && echo yes || echo no)"
chk "ACME config carries the directory URL"      yes "$(has "$(curl -s "$U/api/client-config/acme")" 'server = https://pki.test/acme2/directory')"
chk "MS .inf carries the XCEP PolicyServer URL"  yes "$(has "$(curl -s "$U/api/client-config/ms")" 'PolicyServer "https://pki.test/msxcep"')"
chk "unknown client-config kind -> 404"          404 "$(curl -s -o /dev/null -w '%{http_code}' "$U/api/client-config/bogus")"
# On the default-URL server (PKI_DNS=localhost, no explicit BASE_URL): the SCEP
# helper must carry the reachable http+port URL, mirroring the endpoint fix.
chk "SCEP config uses the default http+port URL" yes "$(has "$(curl -s "http://127.0.0.1:$PORT2/api/client-config/scep")" 'URL="http://localhost:8448/scep"')"

echo
echo "=== ENDPOINTS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
