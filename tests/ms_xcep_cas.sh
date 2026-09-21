#!/usr/bin/env bash
# The MS-XCEP <cAs> block and the two template attributes that were hardcoded.
# Everything a GetPoliciesResponse says about a CA's enrolment
# endpoints is per-CA data now:
#
#   <cAs><cA><uris><cAURI>  clientAuthentication / uri / priority / renewalOnly
#                           — one row per URI in ca_xcep_uris, 1..n per xcep.xsd
#   <cAs><cA><enrollPermission>          — ca_instances.ms_enroll_permission
#   <privateKeyAttributes><cryptoProviders>  — EVERY provider, not just the first
#   <privateKeyAttributes><permissions>      — ms_templates.private_key_permissions
#
# Before the fix these were the literals 4 / derived / 1 / false / true, a single
# <provider>, and a hardcoded xsi:nil — so every assertion below that reads back a
# non-default value fails without it.
#
# Writes go through the real console API (POST /api/ca-instances/{id}/xcep) and
# reads decode the actual SOAP fastpki-ms serves.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
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
CA="$ROOT/build/fastpki-ca"; WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18451; WPORT=18452
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=XCEP CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout ms.key -out ms.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup ms_xcep_cas
trap 'pg_cleanup; kill $P $PW 2>/dev/null' EXIT
seed_web_user boss bosspw admin

cat > bootstrap.conf <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
MS_CERT=$W/ms.pem
MS_KEY=$W/ms.key
PG_CONNINFO=$PG_CONNINFO
MS_BIND=127.0.0.1
MS_PORT=$PORT
XCEP_PATH=/msxcep
WSTEP_PATH=/mswstep
WEB_BIND=127.0.0.1
WEB_PORT=$WPORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)

"$WEB" --config bootstrap.conf >web.log 2>&1 & PW=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" WEB_PORT "$PW" || true
if ! kill -0 $PW 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="https://127.0.0.1:$PORT"; UW="http://127.0.0.1:$WPORT"
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$UW/api/login" >/dev/null

# fastpki-ms loads ms_templates ONCE at startup, so the templates this suite
# inspects have to exist before it boots. Two of them: one carrying several crypto
# providers and an SDDL, one carrying neither (to prove the nillable form survives).
curl -s -o /dev/null -b boss.cj -X POST \
  --data-urlencode 'name=XcepProv' --data-urlencode 'oid=1.3.6.1.4.1.311.21.8.9.1' \
  --data-urlencode 'crypto_providers=Microsoft Software Key Storage Provider|Microsoft Smart Card Key Storage Provider' \
  --data-urlencode 'private_key_permissions=O:COG:CGD:(A;;GASDWOKA;;;CO)' \
  "$UW/api/templates"
curl -s -o /dev/null -b boss.cj -X POST \
  --data-urlencode 'name=XcepNoSddl' --data-urlencode 'oid=1.3.6.1.4.1.311.21.8.9.2' \
  --data-urlencode 'crypto_providers=Microsoft Base Cryptographic Provider v1.0' \
  --data-urlencode 'private_key_permissions=' "$UW/api/templates"

"$ROOT/build/fastpki-ms" --config bootstrap.conf >ms.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" MS_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-ms died:"; cat ms.log; exit 1; fi

XCEP_REQ='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"><client><lastUpdate xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/><preferredLanguage xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/></client></GetPolicies></s:Body></s:Envelope>'
# XCEP now authenticates like WSTEP. `boss` is the admin this suite already seeds.
xcep(){ curl -sk -u boss:bosspw -H "Host: localhost:$PORT" -H "Content-Type: application/soap+xml; charset=utf-8" \
        --data "$XCEP_REQ" "$U/msxcep/ca"; }
# The <cAs> block only (so <policies> can't satisfy a match by accident).
cas(){ xcep | sed 's/.*<cAs>//; s|</cAs>.*||'; }
# n-th occurrence of a tag inside <cAs>. (busybox/BSD sed: no \? — two plain subs.)
nth(){ cas | grep -o "<$1>[^<]*</$1>" | sed -n "${2}p" | sed "s|<$1>||; s|</$1>||"; }
# The whole envelope is one line, so count occurrences (grep -c counts LINES).
count(){ cas | grep -o "<$1>" | wc -l | tr -d ' '; }
setxcep(){ curl -s -o /dev/null -w '%{http_code}' -b boss.cj -X POST \
           --data-urlencode "uris=$1" --data-urlencode "enrollPermission=$2" \
           "$UW/api/ca-instances/ca/xcep"; }

echo "=== a CA with no rows advertises this server's own endpoint, with the MS defaults ==="
# The fallback must reproduce exactly what the old literals emitted, or every
# existing deployment changes behaviour on upgrade.
chk "one <cAURI>"                  1     "$(count cAURI)"
chk "clientAuthentication = 4"     4     "$(nth clientAuthentication 1)"
chk "uri = this server's WSTEP"    "https://localhost:$PORT/mswstep/ca" "$(nth uri 1)"
chk "priority = 1"                 1     "$(nth priority 1)"
chk "renewalOnly = false"          false "$(nth renewalOnly 1)"
chk "enrollPermission = true"      true  "$(nth enrollPermission 1)"

echo
echo "=== per-CA URIs come from the DB, in order, with their own attributes ==="
# Three endpoints: an explicit X.509-auth primary, a Kerberos backup at priority 2,
# and an anonymous renewal-only one whose priority is nil.
chk "POST .../xcep -> 200" 200 "$(setxcep \
  'https://ms1.example.test/mswstep/ca|8|1|false
https://ms2.example.test/mswstep/ca|2|2|false
|1|-1|true' false)"
chk "three <cAURI>"                3     "$(count cAURI)"
chk "uri 1 as configured"          https://ms1.example.test/mswstep/ca "$(nth uri 1)"
chk "uri 1 clientAuth = 8 (X.509)" 8     "$(nth clientAuthentication 1)"
chk "uri 2 as configured"          https://ms2.example.test/mswstep/ca "$(nth uri 2)"
chk "uri 2 clientAuth = 2 (Krb)"   2     "$(nth clientAuthentication 2)"
chk "uri 2 priority = 2"           2     "$(nth priority 2)"
chk "uri 3 blank -> derived"       "https://localhost:$PORT/mswstep/ca" "$(nth uri 3)"
chk "uri 3 clientAuth = 1 (anon)"  1     "$(nth clientAuthentication 3)"
chk "uri 3 renewalOnly = true"     true  "$(nth renewalOnly 3)"
# priority is nillable in xcep.xsd; -1 must serialize as xsi:nil, not as "-1".
chk "uri 3 priority is xsi:nil"    yes   "$(cas | grep -q '<priority xsi:nil="true"/>' && echo yes || echo no)"
chk "no literal -1 priority"       no    "$(cas | grep -q '<priority>-1</priority>' && echo yes || echo no)"
chk "enrollPermission now false"   false "$(nth enrollPermission 1)"

echo
echo "=== the CA cert still comes from the CA's own material ==="
chk "certificate is the CA" "XCEP CA" \
  "$(cas | grep -o '<certificate>[^<]*' | sed 's/<certificate>//' \
     | "$OSSL" base64 -d -A 2>/dev/null \
     | "$OSSL" x509 -inform DER -noout -subject 2>/dev/null | sed 's/.*CN *= *//')"

echo
echo "=== a bogus clientAuthentication is rejected, and nothing changes ==="
chk "clientAuth 7 -> 400" 400 "$(setxcep 'https://x.test/mswstep/ca|7|1|false' true)"
chk "still three <cAURI>"  3  "$(count cAURI)"

echo
echo "=== GET .../xcep round-trips what was stored ==="
GX="$(curl -s -b boss.cj "$UW/api/ca-instances/ca/xcep")"
chk "GET reports 3 uris"       3     "$(echo "$GX" | grep -o '"uri":' | wc -l | tr -d ' ')"
chk "GET reports enrollPerm"   false "$(echo "$GX" | grep -o '"enrollPermission":[a-z]*' | sed 's/.*://')"

echo
echo "=== clearing the list falls back to the derived endpoint ==="
chk "POST empty uris -> 200" 200 "$(setxcep '' true)"
chk "back to one <cAURI>"    1   "$(count cAURI)"
chk "uri derived again"      "https://localhost:$PORT/mswstep/ca" "$(nth uri 1)"

echo
echo "=== template: EVERY cryptoProvider is advertised, not just the first ==="
# XcepProv carries two providers; the old code emitted crypto_providers[0] only.
POL="$(xcep | sed 's/.*<policies>//; s|</policies>.*||')"
chk "the two DB templates are served" 2 \
  "$(echo "$POL" | grep -o '<commonName>Xcep[^<]*' | wc -l | tr -d ' ')"
chk "both <provider> entries emitted" 2 \
  "$(echo "$POL" | grep -o '<provider>Microsoft S[^<]*Key Storage Provider</provider>' | wc -l | tr -d ' ')"
chk "provider order preserved" "Microsoft Software Key Storage Provider" \
  "$(echo "$POL" | grep -o '<provider>Microsoft S[^<]*' | sed -n 1p | sed 's/<provider>//')"

echo
echo "=== template: the SDDL private-key permissions are emitted ==="
chk "permissions carries the SDDL" 'O:COG:CGD:(A;;GASDWOKA;;;CO)' \
  "$(echo "$POL" | grep -o '<permissions>[^<]*</permissions>' | sed 's|<permissions>||; s|</permissions>||' | head -1)"
# XcepNoSddl sets none, so the nillable form must still appear.
chk "an unset SDDL stays xsi:nil" yes \
  "$(echo "$POL" | grep -q '<permissions xsi:nil="true"/>' && echo yes || echo no)"

echo
echo "=== Revert: the MS base paths 404 like every other protocol ==="
b(){ curl -sk -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/soap+xml' \
     --data '<x/>' "$U$1"; }
chk "base /msxcep -> 404"  404 "$(b /msxcep)"
chk "base /mswstep -> 404" 404 "$(b /mswstep)"

echo
echo "=== MS-XCEP-CAS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
