#!/usr/bin/env bash
# MS-XCEP / MS-WSTEP XML abuse (§4, rewritten for the real parser). The SOAP endpoints take
# untrusted XML, so they must resist the XML-specific attacks the other protocols don't
# face: XXE (external-entity file disclosure / SSRF) and entity-expansion DoS.
#
# ⚠️ WHY THE ASSERTIONS CHANGED. These used to pass for a reason that no longer holds:
# FastPKI read this XML with a hand-rolled byte scanner, which cannot expand an entity
# because it does not understand them. It was replaced with libxml2 — and a real parser
# is only safer if it is CONFIGURED to be. So "the canary did not appear" is no longer
# enough evidence; these now assert the request is REFUSED, fail-closed, at parse time.
#
# The refusal must also be the RIGHT refusal. Every abuse body below would ALSO have been
# 400-ed by the old code for the unrelated reason "missing BinarySecurityToken", so a bare
# status check proves nothing. We assert on the distinct message, and the last case sends a
# clean DOCTYPE-free body that must still produce the OLD message — otherwise a blanket
# 400-everything bug would read as a pass.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
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
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
W="$(mktemp -d)"; cd "$W"; PORT=18448
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

ca_in_token ca.pem "/CN=MS CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout ms.key -out ms.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup ms_xxe
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
seed_web_user tester s3cret-ms requester
cat > bootstrap.conf <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
ROOT_CA_PEM=$W/root.pem
MS_CERT=$W/ms.pem
MS_KEY=$W/ms.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
MS_BIND=127.0.0.1
MS_PORT=$PORT
XCEP_PATH=/msxcep
WSTEP_PATH=/mswstep
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-ms" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-ms died:"; cat srv.log; exit 1; fi
MS="https://127.0.0.1:$PORT"
SECRET="this-is-a-canary-secret-not-on-disk"
printf 'root:x:0:0:CANARY-PASSWD:/root:/bin/sh\n' > secret.txt

echo "=== XXE: an external entity must not be resolved (no file disclosure / SSRF) ==="
cat > xxe.xml <<XML
<?xml version="1.0"?>
<!DOCTYPE s:Envelope [ <!ENTITY xxe SYSTEM "file://$W/secret.txt"> ]>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
<s:Header><wsse:Security><wsse:UsernameToken><wsse:Username>&xxe;</wsse:Username><wsse:Password>x</wsse:Password></wsse:UsernameToken></wsse:Security></s:Header>
<s:Body><wst:RequestSecurityToken><wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType></wst:RequestSecurityToken></s:Body></s:Envelope>
XML
post(){ curl -sk -m 10 -o body.out -w '%{http_code}' -H "Content-Type: application/soap+xml" \
             --data-binary @"$1" "$MS/mswstep/ca-global"; }
SC=$(post xxe.xml); R=$(cat body.out)
chk "XXE request is REFUSED (400)"                400  "$SC"
chk "  refused AT PARSE, not later for a missing field" yes "$(has "$R" 'malformed SOAP request')"
chk "  response does not leak the file's contents" no  "$(has "$R" 'CANARY-PASSWD')"
chk "  MS server survives the XXE request"        yes  "$(kill -0 $P 2>/dev/null && echo yes || echo no)"

echo "=== XXE via a PARAMETER entity in an EXTERNAL DTD (the subset the loader must refuse) ==="
printf '<!ENTITY xxe SYSTEM "file://%s/secret.txt">\n' "$W" > ext.dtd
cat > extdtd.xml <<XML
<?xml version="1.0"?>
<!DOCTYPE s:Envelope SYSTEM "file://$W/ext.dtd">
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<s:Header><wsse:Security><wsse:UsernameToken><wsse:Username>&xxe;</wsse:Username><wsse:Password>x</wsse:Password></wsse:UsernameToken></wsse:Security></s:Header>
<s:Body/></s:Envelope>
XML
SC=$(post extdtd.xml); R=$(cat body.out)
chk "external-DTD request is REFUSED (400)"       400  "$SC"
chk "  refused at parse"                          yes  "$(has "$R" 'malformed SOAP request')"
chk "  no file contents in the response"          no   "$(has "$R" 'CANARY-PASSWD')"


echo "=== billion laughs: entity expansion must not blow up CPU/RAM ==="
cat > lol.xml <<'XML'
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<s:Header><wsse:Security><wsse:UsernameToken><wsse:Username>&lol9;</wsse:Username><wsse:Password>x</wsse:Password></wsse:UsernameToken></wsse:Security></s:Header>
<s:Body/></s:Envelope>
XML
T0=$(date +%s)
SC=$(post lol.xml); RC=$?
T1=$(date +%s)
R=$(cat body.out)
chk "billion-laughs request is REFUSED (400)"    400  "$SC"
chk "  refused at parse (DOCTYPE), not expanded" yes  "$(has "$R" 'malformed SOAP request')"
chk "billion-laughs request returns promptly (no expansion DoS)" yes "$([ $((T1-T0)) -lt 8 ] && echo yes || echo no)"
chk "request was not killed by the curl timeout" yes "$([ "$RC" != 28 ] && echo yes || echo no)"
chk "MS server survives the billion-laughs request" yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"

echo "=== ⚠️ the refusal must be SPECIFIC: a clean body still fails for its own reason ==="
# Without this, a bug that 400s every request would pass every assertion above. Same shape,
# no DOCTYPE, still no BinarySecurityToken -> the OLD message, from the OLD code path.
cat > clean.xml <<'XML'
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<s:Header><wsse:Security><wsse:UsernameToken><wsse:Username>tester</wsse:Username><wsse:Password>x</wsse:Password></wsse:UsernameToken></wsse:Security></s:Header>
<s:Body/></s:Envelope>
XML
SC=$(post clean.xml); R=$(cat body.out)
chk "well-formed body is NOT rejected as malformed" no  "$(has "$R" 'malformed SOAP request')"
chk "  it fails on its own missing field instead"   yes "$(has "$R" 'missing BinarySecurityToken')"

echo "=== character references in the BinarySecurityToken are DECODED, not stripped ==="
# The WCF client line-wraps base64 with &#xD;. The old code stripped four exact spellings
# by hand, so &#x0D; (leading zero) or &#xd; (lowercase) survived and corrupted the base64.
# libxml2 decodes all of them; assert the odd spellings now work.
ms_csr wrap.internal GenericUser w.key w.csr             # the template selects the policy
B64=$("$OSSL" req -in w.csr -outform DER 2>/dev/null | "$OSSL" base64 -A)
for ent in '&#xD;' '&#x0D;' '&#xd;'; do
  cat > wrap.xml <<XML
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
<s:Header><wsse:Security><wsse:UsernameToken><wsse:Username>tester</wsse:Username><wsse:Password>s3cret-ms</wsse:Password></wsse:UsernameToken></wsse:Security></s:Header>
<s:Body><wst:RequestSecurityToken><wst:TokenType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/PKCS10</wst:TokenType><wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType><wsse:BinarySecurityToken ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#PKCS10">${B64}${ent}${ent}</wsse:BinarySecurityToken></wst:RequestSecurityToken></s:Body></s:Envelope>
XML
  SC=$(post wrap.xml); R=$(cat body.out)
  # Assert SUCCESS positively. An earlier version of this checked only that the response
  # lacked the words "bad CSR/invalid/malformed" — which passed under the OLD stripper for
  # &#x0D; and &#xd;, because those failed with different wording. A guard that cannot tell
  # a success from a differently-worded failure is not a guard.
  chk "base64 wrapped with $ent is ACCEPTED (200)" 200 "$SC"
  chk "  ...and an actual certificate comes back"  yes \
      "$(has "$R" 'RequestSecurityTokenResponse')"
done

echo "=== the endpoint still serves normal SOAP afterwards ==="
XCEP='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"><client/></GetPolicies></s:Body></s:Envelope>'
chk "GetPolicies still answers after the abuse" yes \
    "$(has "$(curl -sk -m 10 -u tester:s3cret-ms -H 'Content-Type: application/soap+xml' --data "$XCEP" "$MS/msxcep/ca-global")" 'GetPoliciesResponse')"

echo
echo "=== MS XXE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
