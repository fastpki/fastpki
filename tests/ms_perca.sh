#!/usr/bin/env bash
# Per-CA MS-XCEP/WSTEP routing. MS is id-based like the other enrolment
# protocols: <xcep_path>/{ca_id} and <wstep_path>/{ca_id} resolve the named CA and
# issue from THAT CA's material, so a Windows client can enrol against any CA the
# single instance hosts — not only the globally-configured one.
#
#   - /msxcep/{id}  advertises that CA's cert AND its own /mswstep/{id} enrolment URI
#                   (this is how the Windows client discovers the per-CA URL — only
#                   the XCEP URL need be configured in GPO).
#   - /mswstep/{id} issues from that CA, tags the cert ca_instance_id={id}, bakes
#                   that CA's AIA/CRLDP.
#   - The base (no-id) paths 404 — MS is id-based like EST/CMP/ACME/SCEP.
#
# Single-tenant / multi-CA (one instance hosts several CAs) — the tenant dimension
# has been removed. NOT Windows-proven here (that rig is Windows-only) — this
# drives the real SOAP over curl and decodes the issued certs.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/ms_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
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
CA="$ROOT/build/fastpki-ca"
W="$(mktemp -d)"; cd "$W"; PORT=18449
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# The bootstrap SIGNING_CA (id 'ca'), a second CA 'dept-a' with its own backing, and
# the MS TLS cert. Both CAs live in the one single-tenant instance.
ca_in_token ca.pem "/CN=Global MS CA" 3650
# ⚠️ CAPTURE IT NOW. ca_in_token exports CA_KEY_URI, so the `depta` call below OVERWRITES it.
# SIGNING_CA_KEY was set from $CA_KEY_URI *after* that call, which paired Global MS CA's
# CERTIFICATE with Dept A's KEY: every certificate this suite issued from `ca` was signed by
# a key the published CA certificate does not certify, and would verify against nothing.
# Nothing caught it until resolve_ca_instance() began checking the pair.
GLOBAL_KEY_URI="$CA_KEY_URI"
cp ca.pem root.pem
ca_in_token depta.pem "/CN=Dept A CA" 3650 depta
DEPTA_KEY_URI="$CA_KEY_URI"
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout ms.key -out ms.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup ms_perca
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
seed_web_user tester s3cret-ms requester

cat > bootstrap.conf <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$GLOBAL_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
MS_CERT=$W/ms.pem
MS_KEY=$W/ms.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
MS_BIND=127.0.0.1
MS_PORT=$PORT
XCEP_PATH=/msxcep
WSTEP_PATH=/mswstep
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)

# A second CA registered as its own instance with its own crypto backing.
"$CA" --config bootstrap.conf add dept-a --name "Dept A" --ca-pem "$W/depta.pem" --ca-key "$DEPTA_KEY_URI" >/dev/null

"$ROOT/build/fastpki-ms" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-ms died:"; cat srv.log; exit 1; fi
U="https://127.0.0.1:$PORT"
HOST="localhost"

XCEP_REQ='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"><client><lastUpdate xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/><preferredLanguage xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/></client></GetPolicies></s:Body></s:Envelope>'
# XCEP authenticates like WSTEP now; `tester` is the user this suite already seeds.
xcep() { curl -sk -u tester:s3cret-ms -H "Host: $HOST" -H "Content-Type: application/soap+xml; charset=utf-8" --data "$XCEP_REQ" "$U$1"; }
xcep_code() { curl -sk -o /dev/null -w '%{http_code}' -u tester:s3cret-ms -H "Host: $HOST" \
    -H "Content-Type: application/soap+xml; charset=utf-8" --data "$XCEP_REQ" "$U$1"; }
xcep_ca_cn() {
    xcep "$1" | grep -o '<certificate>[^<]*' | sed 's/<certificate>//' \
        | "$OSSL" base64 -d -A 2>/dev/null \
        | "$OSSL" x509 -inform DER -noout -subject 2>/dev/null | sed 's/.*CN *= *//'
}
xcep_uri() { xcep "$1" | grep -o '<uri>[^<]*' | sed 's/<uri>//' | head -1; }

enroll() { # <path> <cn> <out.der> -> HTTP status
    ms_csr "$2" GenericUser "k_$2.key" "c_$2.csr"        # the template selects the policy
    local b64; b64=$("$OSSL" req -in "c_$2.csr" -outform DER 2>/dev/null | "$OSSL" base64 -A)
    local body='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><s:Header><wsse:Security><wsse:UsernameToken><wsse:Username>tester</wsse:Username><wsse:Password>s3cret-ms</wsse:Password></wsse:UsernameToken></wsse:Security></s:Header><s:Body><wst:RequestSecurityToken><wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType><wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10">'"$b64"'</wsse:BinarySecurityToken></wst:RequestSecurityToken></s:Body></s:Envelope>'
    local code; code=$(curl -sk -H "Host: $HOST" -H "Content-Type: application/soap+xml; charset=utf-8" \
        -o resp.xml -w '%{http_code}' --data "$body" "$U$1")
    local issued; issued=$(sed 's/.*<wst:RequestedSecurityToken>//' resp.xml \
        | grep -o 'base64binary">[^<]*' | head -1 | sed 's/.*base64binary">//')
    [ -n "$issued" ] && echo "$issued" | "$OSSL" base64 -d -A > "$3" 2>/dev/null
    echo "$code"
}
issuer_of(){ "$OSSL" x509 -in "$1" -inform DER -noout -issuer 2>/dev/null | sed 's/.*CN *= *//'; }
uri_of(){ "$OSSL" x509 -in "$1" -inform DER -noout -text 2>/dev/null \
    | grep -E "$2" | grep -oE 'URI:[^ ]+' | sed 's/URI://' | head -1; }

echo "=== per-CA XCEP policy advertises that CA + its own WSTEP URI ==="
chk "/msxcep/ca advertises the SIGNING_CA"      "Global MS CA" "$(xcep_ca_cn /msxcep/ca)"
chk "/msxcep/dept-a advertises the Dept A CA"   "Dept A CA"    "$(xcep_ca_cn /msxcep/dept-a)"
# The client learns the per-CA enrolment URL from the policy — no per-box GPO edit.
# Assert the WHOLE uri (host + per-CA path); with no BASE_URL the host is mirrored
# from the request Host.
chk "policy advertises the per-CA WSTEP uri"    "https://localhost/mswstep/dept-a" "$(xcep_uri /msxcep/dept-a)"

echo "=== Following the advertised uri actually enrols ==="
FOLLOW_PATH=$(xcep_uri /msxcep/dept-a | sed -E 's#^https?://[^/]+##')
chk "following the advertised uri enrols (-> 200)" 200 "$(enroll "$FOLLOW_PATH" followed.internal followed.der)"
chk "the cert is signed by the advertised CA"      "Dept A CA" "$(issuer_of followed.der)"

echo "=== per-CA WSTEP issues from the named CA ==="
chk "/mswstep/ca -> 200"               200 "$(enroll /mswstep/ca apex.internal apex.der)"
chk "issued by the SIGNING_CA"         "Global MS CA" "$(issuer_of apex.der)"
chk "cert tagged ca_instance_id=ca"    ca "$(pg_exec "SELECT ca_instance_id FROM certs WHERE cn='apex.internal';")"
chk "/mswstep/dept-a -> 200"           200 "$(enroll /mswstep/dept-a depta.internal depta.der)"
chk "issued by the Dept A CA"          "Dept A CA" "$(issuer_of depta.der)"
chk "cert tagged ca_instance_id=dept-a" dept-a "$(pg_exec "SELECT ca_instance_id FROM certs WHERE cn='depta.internal';")"
# Cryptographic check, not just the issuer name.
"$OSSL" x509 -in depta.der -inform DER -out depta_leaf.pem >/dev/null 2>&1
chk "dept-a cert verifies under the Dept A CA" OK \
    "$("$OSSL" verify -CAfile depta.pem depta_leaf.pem 2>/dev/null | grep -oE 'OK')"

echo "=== Issued certs carry the ISSUING CA's AIA/CRLDP (named by id) ==="
# Plain http on the OCSP listener's port — these three are served by
# fastpki-ocsp, not by any TLS listener, and no load balancer is shipped to redirect.
chk "dept-a CRLDP names dept-a"     "http://localhost:8080/dept-a.crl" "$(uri_of depta.der '\.crl')"
# caIssuers names the signing key GENERATION — <base>/{ca_id}/{ski}.p7c. The SKI is
# derived from the CA certificate, never pasted: a literal would pin this fixture's key
# rather than test that the product named the certificate that actually signs.
DEPTA_SKI=$("$OSSL" x509 -in depta.pem -noout -text 2>/dev/null \
             | awk '/X509v3 Subject Key Identifier/{getline; gsub(/[ :]/,""); print tolower($0); exit}')
chk "PRECONDITION: the dept-a CA cert has an SKI" yes "$([ -n "$DEPTA_SKI" ] && echo yes || echo no)"
chk "dept-a caIssuers names dept-a AND its generation" "http://localhost:8080/dept-a/$DEPTA_SKI.p7c" "$(uri_of depta.der 'CA Issuers')"
chk "dept-a AIA OCSP is the shared /ocsp" "http://localhost:8080/ocsp" "$(uri_of depta.der 'OCSP')"
chk "ca CRLDP names ca"             "http://localhost:8080/ca.crl" "$(uri_of apex.der '\.crl')"

echo "=== instance validation ==="
chk "unknown CA instance -> 404 (XCEP)"  404 "$(xcep_code /msxcep/nope)"
chk "unknown CA instance -> 404 (WSTEP)" 404 "$(enroll /mswstep/nope y1.internal y1.der)"
"$CA" --config bootstrap.conf disable dept-a >/dev/null
chk "disabled CA instance -> 503 (XCEP)"  503 "$(xcep_code /msxcep/dept-a)"
chk "disabled CA instance -> 503 (WSTEP)" 503 "$(enroll /mswstep/dept-a y2.internal y2.der)"
"$CA" --config bootstrap.conf enable dept-a >/dev/null
chk "re-enabled instance serves again" "Dept A CA" "$(xcep_ca_cn /msxcep/dept-a)"

echo "=== base (no-id) paths 404 — MS is id-based like every other protocol ==="
# Removed the default CA, and there is no "primary" CA either: the
# XCEP URL Windows is configured with carries the /{ca_id}, and GetPolicies then hands
# the client that CA's own id-bearing WSTEP URI. Nothing ever hits the base path.
chk "base /msxcep -> 404"  404 "$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/soap+xml' --data '<x/>' "$U/msxcep")"
chk "base /mswstep -> 404" 404 "$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/soap+xml' --data '<x/>' "$U/mswstep")"

echo
echo "=== MS-PERCA: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
