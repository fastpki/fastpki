#!/usr/bin/env bash
# The Endpoints page's "Advertised in certs" column must say what issuance actually
# bakes — checked against a DECODED CERTIFICATE, not against another config read.
#
# ── What this found ──────────────────────────────────────────────────────────────
#
# The column reported `AIA_OCSP` and `CRL_DPS` from the config. Issuance does not read
# them: every protocol calls ca_urls_for_instance() and bakes per-CA URLs derived from
# BASE_URL/PKI_DNS + the CA id (§4a). The global settings are a fallback taken only when
# the caller passes no URLs, which no caller does.
#
# Measured on the lab, console versus a real leaf out of the database:
#
#   console said  http://localhost:8080/pki/signing_ca.crl
#   cert carried  https://pki.example.org/issuing.crl
#
# Different scheme, host, port and path shape — and the shape shown was the id-less form
# that 404s since §4a. An operator reading that page to find out where clients fetch the
# CRL was told a URL that is in no certificate and that the server does not serve.
#
# Comparing the page against the config would have "passed" — both sides would have been
# reading the same dead setting. The only assertion that can catch this is against the
# artifact, so that is what this does: issue a certificate, decode its AIA and CRL DP,
# and require the page to agree.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18232
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
row(){ printf '%s' "$1" | sed 's/},{/}\n{/g' | grep "\"protocol\":\"$2\""; }
field(){ printf '%s' "$1" | sed -n 's/.*"'"$2"'":"\([^"]*\)".*/\1/p'; }

ca_in_token ca.pem "/CN=Advertised CA" 3650
pg_setup endpoints_advertised
source "$ROOT/tests/user_helpers.sh"
seed_web_user admin testpw admin
printf "internal\n" > domains.txt
seed_domains $W/domains.txt
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT

# A BASE_URL that shares nothing with the stale defaults, so a value copied from the
# config cannot accidentally match the derived one.
BASE="https://pki.advertised.test"
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
BASE_URL=$BASE
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
AIA_OCSP=http://stale.example/ocsp/
CRL_DPS=http://stale.example/pki/signing_ca.crl
AIA_CA_ISSUERS=http://stale.example/pki/signing_ca.crt
LOG_LEVEL=err
EOF
hsm_conf_lines >> web.conf
printf 'SIGNING_CA_PEM=%s\nSIGNING_CA_KEY=%s\nSIGNING_CA_ID=issuing\n' "$W/ca.pem" "$CA_KEY_URI" >> web.conf
seed_ca_from_conf web.conf
sed -i.bak '/^SIGNING_CA_/d' web.conf && rm -f web.conf.bak

"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c cj.txt -d 'username=admin&password=testpw' "$U/api/login" >/dev/null
CAID=$(curl -s -b cj.txt "$U/api/ca-instances" | tr '{' '\n' | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
chk "a CA is registered" yes "$([ -n "$CAID" ] && echo yes || echo no)"

echo "=== issue a certificate and read the URLs out of the DER ==="
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout leaf.key -subj "/CN=host.internal" -out leaf.csr >/dev/null 2>&1
curl -s -b cj.txt -X POST --data-binary @leaf.csr "$U/api/certs/request?ca_instance=$CAID" > iss.json
SER=$(sed -n 's/.*"serial":"\([^"]*\)".*/\1/p' iss.json)
chk "the certificate issued" yes "$([ -n "$SER" ] && echo yes || echo no)"
[ -n "$SER" ] || { echo "  response: $(cat iss.json)"; echo "=== ENDPOINTS ADVERTISED: PASS=$pass FAIL=$((fail+1)) ==="; exit 1; }
curl -s -b cj.txt "$U/api/certs/$SER" | sed -n 's/.*"pem":"\(.*\)","text".*/\1/p' | sed 's/\\n/\n/g' > leaf.pem
chk "and it decodes" yes "$("$OSSL" x509 -in leaf.pem -noout -subject >/dev/null 2>&1 && echo yes || echo no)"

T=$("$OSSL" x509 -in leaf.pem -noout -text 2>/dev/null)
CERT_OCSP=$(printf '%s' "$T" | sed -n 's/.*OCSP - URI:\([^ ]*\).*/\1/p' | head -1 | tr -d '\r')
CERT_CRL=$(printf '%s' "$T"  | grep -A 3 "CRL Distribution" | sed -n 's/.*URI:\([^ ]*\).*/\1/p' | head -1 | tr -d '\r')
chk "the cert carries an OCSP URI"  yes "$([ -n "$CERT_OCSP" ] && echo yes || echo no)"
chk "the cert carries a CRL DP"     yes "$([ -n "$CERT_CRL" ] && echo yes || echo no)"
# It must be derived from BASE_URL, not from the stale settings — otherwise the rest of
# this suite would be comparing two wrong things and agreeing.
# BASE_URL supplies the HOST only. The scheme is http and the port is the OCSP
# listener's, because that is the process serving this URI — see derive_ca_urls().
BASE_HOST=${BASE#*://}
chk "the OCSP URI comes from BASE_URL's host" yes \
    "$(printf '%s' "$CERT_OCSP" | grep -q "^http://$BASE_HOST:" && echo yes || echo no)"
chk "  and is not https"                       no \
    "$(printf '%s' "$CERT_OCSP" | grep -q '^https://' && echo yes || echo no)"
chk "the CRL DP names the CA id"       yes \
    "$(printf '%s' "$CERT_CRL" | grep -q "/$CAID\.crl$" && echo yes || echo no)"
chk "neither came from the stale config" no \
    "$(printf '%s%s' "$CERT_OCSP" "$CERT_CRL" | grep -q 'stale.example' && echo yes || echo no)"

echo "=== the Endpoints page must agree with the certificate ==="
EP=$(curl -s -b cj.txt "$U/api/endpoints")
ADV_OCSP=$(field "$(row "$EP" OCSP)" advertised)
ADV_CRL=$(field "$(row "$EP" CRL)" advertised)
# The page shows the shape with <ca_id> because an instance hosts several CAs; substitute
# this CA's id and the two must be identical strings.
chk "advertised OCSP == the cert's OCSP URI" "$CERT_OCSP" "$ADV_OCSP"
chk "advertised CRL  == the cert's CRL DP"   "$CERT_CRL" \
    "$(printf '%s' "$ADV_CRL" | sed "s/<ca_id>/$CAID/")"
# And the regression itself, stated directly.
chk "the page no longer quotes the dead settings" no \
    "$(printf '%s' "$EP" | grep -q 'stale.example' && echo yes || echo no)"

echo
echo "=== ENDPOINTS ADVERTISED: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
