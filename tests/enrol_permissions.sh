#!/usr/bin/env bash
# The `enrol:*` verbs are ENFORCED by the protocol daemons.
#
# Since step 1 the schema has granted `est:enrol`, `acme:enrol`, `cmp:enrol`, `ms:enrol`
# and `scep:enrol`; step 3 made them editable in the console. No enrolment binary read
# them, so narrowing a role's protocols in the UI changed exactly nothing — the operator
# saw a saved setting and got no enforcement. This is the reader.
#
# ── What each section is really testing ──────────────────────────────────────────
#
# 1. The DEFAULT must not change. `admin` and `requester` hold all five verbs in the
#    schema, so every deployment that worked before still works. A gate that breaks
#    existing enrolment is not a feature, and this is the assertion that says it doesn't.
#
# 2. Removing ONE verb removes ONE protocol. That is the whole point: a role that may
#    enrol over EST but not MS is the thing an operator can now express.
#
# 3. Scope applies to protocols too. A grant reading `est:enrol|dept-a` permits EST
#    against dept-a and refuses it against another CA, so the per-CA confinement from
#    step 2b reaches the enrolment surface rather than stopping at the console.
#
# 4. **403, not 401.** The credentials were ACCEPTED; the account simply may not do this.
#    A 401 would send a client into a retry loop over a decision that will never change,
#    and would report the wrong problem to whoever reads the log.
#
# 5. A refusal is AUDITED as `authz_fail`, distinct from `auth_fail`. "Wrong password" and
#    "not allowed" are different incidents and an operator has to be able to tell them
#    apart.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/ms_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; ESTP=18480; MSP=18481; CMPP=18482
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup enrol_perms
PE=; PM=; PC=
trap 'pg_cleanup; kill $PE $PM $PC 2>/dev/null' EXIT

ca_in_token ca.pem "/CN=Enrol Gate CA" 3650 enrolca || { echo "SKIP: no token"; exit 0; }
CA_URI="$CA_KEY_URI"
ca_in_token depta.pem "/CN=Dept A CA" 3650 enroldepta
DEPTA_URI="$CA_KEY_URI"
# CMP needs a per-CA RA credential, issued BY the CA the endpoint signs with —
# which here is CA_URI (the FIRST mint, id "ca"), NOT whatever ca_in_token left in
# CA_KEY_URI after minting dept-a. Pairing ca.pem with dept-a's key would not even sign.
# Two traps in one line: the insert must come after ca_in_token (CA_KEY_URI is unset
# before it) and must name the CA the config actually uses.
cmp_ra_setup ca.pem "$CA_URI" \
    || { echo "SKIP: could not provision the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout srv.key -out srv.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

printf "internal\n" > domains.txt
seed_domains $W/domains.txt

cat > bootstrap.conf <<EOF
PKI_DNS=localhost
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_URI
SIGNING_CA_ID=ca
AUTH_BACKEND=local
EST_CERT=$W/srv.pem
EST_KEY=$W/srv.key
EST_BIND=127.0.0.1
EST_PORT=$ESTP
MS_CERT=$W/srv.pem
MS_KEY=$W/srv.key
MS_BIND=127.0.0.1
MS_PORT=$MSP
XCEP_PATH=/msxcep
WSTEP_PATH=/mswstep
CMP_BIND=127.0.0.1
CMP_PORT=$CMPP
CMP_PATH=/cmp
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf
"$ROOT/build/fastpki-ca" --config bootstrap.conf add dept-a --name "Dept A" \
    --ca-pem "$W/depta.pem" --ca-key "$DEPTA_URI" >/dev/null

# Three subjects: a plain requester (all five verbs, from the schema), one whose role
# grants EST only, and one whose EST grant names a single CA.
seed_web_user plain  plainpw  requester
pg_exec "INSERT INTO roles(name, description, builtin) VALUES
           ('est-only','test: EST but not MS',false),
           ('est-depta','test: EST, dept-a only',false) ON CONFLICT DO NOTHING;" >/dev/null
# ⚠️ Each custom role carries a PROFILE grant as well as its protocol verbs. Now
# removed the defaults, a role that names no profile may use none, and issuance stops at
# resolve_profile with 400 rather than at the gate with 403 — a different failure that
# reads like a broken CSR. Granting `profile:use|requester` is what "everything is set in
# roles, profiles and templates" means in practice.
pg_exec "INSERT INTO role_permissions(role, permission, scope) VALUES
           ('est-only','cert:request','*'), ('est-only','est:enrol','*'),
           ('est-only','profile:use','requester'),
           ('est-depta','cert:request','*'), ('est-depta','est:enrol','dept-a'),
           ('est-depta','profile:use','requester')
         ON CONFLICT DO NOTHING;" >/dev/null
seed_web_user issuer  issuerpw  standard    # the ISSUANCE namespace, not a console role
seed_web_user estonly estonlypw est-only
seed_web_user estdept estdeptpw est-depta

"$ROOT/build/fastpki-est" --config bootstrap.conf >est.log 2>&1 & PE=$!
"$ROOT/build/fastpki-ms"  --config bootstrap.conf >ms.log  2>&1 & PM=$!
cmp_ra_conf_lines >> bootstrap.conf   # CMP_RA_CERT_ID_PREFIX + CMP_RA_KEY
"$ROOT/build/fastpki-cmp" --config bootstrap.conf >cmp.log 2>&1 & PC=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" MS_PORT "$PM" || true
kill -0 $PE 2>/dev/null || { echo "fastpki-est died:"; cat est.log; exit 1; }
kill -0 $PM 2>/dev/null || { echo "fastpki-ms died:";  cat ms.log;  exit 1; }
kill -0 $PC 2>/dev/null || { echo "fastpki-cmp died:"; cat cmp.log; exit 1; }

est(){ # <user> <pw> <ca> <cn> -> HTTP status
    "$OSSL" req -new -newkey rsa:2048 -nodes -keyout "k$4.key" -subj "/CN=$4" \
        -out "c$4.csr" >/dev/null 2>&1
    "$OSSL" req -in "c$4.csr" -outform DER 2>/dev/null | "$OSSL" base64 -A > "b$4.txt"
    curl -sk -o "r$4.txt" -w '%{http_code}' -u "$1:$2" \
        -H "Content-Type: application/pkcs10" --data-binary "@b$4.txt" \
        "https://127.0.0.1:$ESTP/.well-known/est/$3/simpleenroll"
}
ms(){ # <user> <pw> <ca> <cn> -> HTTP status
    ms_csr "$4" GenericUser "m$4.key" "m$4.csr"          # the template selects the policy
    local b64; b64=$("$OSSL" req -in "m$4.csr" -outform DER 2>/dev/null | "$OSSL" base64 -A)
    local body='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><s:Header><wsse:Security><wsse:UsernameToken><wsse:Username>'"$1"'</wsse:Username><wsse:Password>'"$2"'</wsse:Password></wsse:UsernameToken></wsse:Security></s:Header><s:Body><wst:RequestSecurityToken><wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType><wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10">'"$b64"'</wsse:BinarySecurityToken></wst:RequestSecurityToken></s:Body></s:Envelope>'
    curl -sk -o "mr$4.xml" -w '%{http_code}' -H "Content-Type: application/soap+xml; charset=utf-8" \
        --data "$body" "https://127.0.0.1:$MSP/mswstep/$3"
}
n(){ pg_exec "$1" | tr -d ' '; }

echo "=== 1. the builtin default still enrols — a gate that breaks everything is not a feature ==="
chk "requester over EST -> 200" 200 "$(est plain plainpw ca one.internal)"
chk "  it really issued a cert" 1 "$(n "SELECT count(*) FROM certs WHERE cn='one.internal';")"
chk "requester over MS  -> 200" 200 "$(ms plain plainpw ca two.internal)"
chk "  and that one too"        1 "$(n "SELECT count(*) FROM certs WHERE cn='two.internal';")"

echo "=== 1b. a role that matches no row in `roles` grants NOTHING (no defaults) ==="
# ⚠️ THIS ASSERTION IS INVERTED FROM WHAT IT SAID, and the history is the reason to keep
# reading rather than to flip it back.
#
# `web_users.role` carried two namespaces: console RBAC roles (admin | requester | …) and
# the old issuance words (`standard`, `master`). The first version of this gate refused
# every unknown role; 18 suites failed, so it was changed to let them through and this
# suite pinned that. The escape then became permanent — it is what let AUTH_BACKEND=none
# hand a certificate to a username in no table (role defaulted to `requester`), and what
# Found letting an mTLS client with no web_users row enrol on its certificate alone.
#
# Removes it. The 18 suites were failing because their FIXTURES named a role that did
# not exist, not because refusing is wrong — the fix was always to give those accounts a
# real role, which is what they now have.
chk "'standard' is NOT an RBAC role"  0 "$(n "SELECT count(*) FROM roles WHERE name='standard';")"
chk "a 'standard' account is REFUSED over EST" 403 "$(est issuer issuerpw ca eight.internal)"
chk "  and over MS"                            500 "$(ms issuer issuerpw ca nine.internal)"
chk "  and NEITHER issued anything"              0 \
    "$(n "SELECT count(*) FROM certs WHERE cn IN ('eight.internal','nine.internal');")"
# …and the same account works the moment it holds a role that exists. Without this the
# assertions above would also pass against a server that refused everything.
pg_exec "UPDATE web_users SET role='requester' WHERE username='issuer';" >/dev/null
chk "  the SAME account enrols once its role is real" 200 "$(est issuer issuerpw ca nine-b.internal)"
pg_exec "UPDATE web_users SET role='standard' WHERE username='issuer';" >/dev/null

echo "=== 2. removing ONE verb removes ONE protocol ==="
# est-only holds est:enrol and NOT ms:enrol. That distinction is the feature.
chk "est-only over EST -> 200" 200 "$(est estonly estonlypw ca three.internal)"
chk "est-only over MS  -> 500 (WS-Trust fault, not a 401 challenge)" 500 \
    "$(ms estonly estonlypw ca four.internal)"
chk "  the fault says authentication/authorization" yes \
    "$(grep -q 'FailedAuthentication' mrfour.internal.xml 2>/dev/null || grep -q 'not permitted' mrfour.internal.xml 2>/dev/null && echo yes || echo no)"
chk "  and NO cert was issued" 0 "$(n "SELECT count(*) FROM certs WHERE cn='four.internal';")"

echo "=== 3. scope reaches the enrolment surface, not just the console ==="
# est-depta's grant reads `est:enrol|dept-a`.
chk "est-depta against dept-a -> 200" 200 "$(est estdept estdeptpw dept-a five.internal)"
chk "est-depta against ca     -> 403" 403 "$(est estdept estdeptpw ca six.internal)"
chk "  no cert from the refused CA"    0 "$(n "SELECT count(*) FROM certs WHERE cn='six.internal';")"
chk "  and the allowed one was issued BY dept-a" dept-a \
    "$(n "SELECT ca_instance_id FROM certs WHERE cn='five.internal';")"

echo "=== 4. 403, never 401 — the credentials were accepted ==="
# A 401 would make a client retry the same credentials forever against a decision that
# will never change, and would tell whoever reads the log the wrong thing.
chk "the refusal is 403"        403 "$(est estdept estdeptpw ca seven.internal)"
chk "  and says what is missing" yes \
    "$(grep -qi 'may not enrol' rseven.internal.txt 2>/dev/null || grep -qi 'forbidden' rseven.internal.txt 2>/dev/null && echo yes || echo no)"
# Contrast: a genuinely bad password is still a 401 with a challenge.
BADPW=$(curl -sk -o bad.txt -w '%{http_code}' -u 'estdept:wrongpassword' \
    -H "Content-Type: application/pkcs10" --data-binary "@bsix.internal.txt" \
    "https://127.0.0.1:$ESTP/.well-known/est/dept-a/simpleenroll" 2>/dev/null || true)
chk "a WRONG PASSWORD is still 401" 401 "$BADPW"

echo "=== 4b. CMP refuses in its OWN language, not an HTTP status ==="
# The identity is the senderKID reference, minted AS the username. The refusal is
# THROWN so OpenSSL's CMP server turns it into a PKIStatusInfo rejection — answering 403 at
# the transport would have a CMP client reporting a network problem for an authorization
# decision. estonly holds est:enrol and NOT cmp:enrol.
pg_exec "INSERT INTO keys(kid,protocol,key) VALUES('estonly','cmp','cmpsecret1234'),('plain','cmp','cmpsecret1234')
         ON CONFLICT (kid,protocol) DO UPDATE SET key=EXCLUDED.key;" >/dev/null
cmp_ir(){ # <ref> <tag> -> the client's own output
    rm -f "cmp$2.pem"
    "$OSSL" cmp -cmd ir -server "http://127.0.0.1:$CMPP/cmp/ca" -recipient "/CN=Enrol Gate CA" \
        -secret "pass:cmpsecret1234" -ref "$1" -trusted ca.pem -expect_sender "/CN=cmp-ra.test" -keep_alive 0 \
        -newkey scratch.key -subject "/CN=$2.internal" -certout "cmp$2.pem" 2>&1 | tail -4
}
cmp_ir plain ok >/dev/null
chk "a requester CAN enrol over CMP" yes "$([ -s cmpok.pem ] && echo yes || echo no)"
OUT_NO=$(cmp_ir estonly no)
chk "est-only CANNOT"                no  "$([ -s cmpno.pem ] && echo yes || echo no)"
chk "  and the client is told why"   yes \
    "$(printf '%s' "$OUT_NO" | grep -qi 'may not enrol over CMP' && echo yes || echo no)"
chk "  no cert was issued"           0 "$(n "SELECT count(*) FROM certs WHERE cn='no.internal';")"

echo "=== 4c. a CUSTOM role that grants a protocol also gets its credential ==="
# Mints the CMP secret / ACME EAB key from the role. That decision was a hardcoded
# `role == "admin" || role == "requester"`, so a custom role granting `cmp:enrol` minted
# NOTHING — the holder could not enrol with the access they had just been given, and the
# console said nothing. It now asks role_permissions, like everything else.
#
# Caught on the lab, not here: the first CMP smoke reported "no cert issued" and I nearly
# recorded it as the gate working. It was PBM failing on an empty secret.
pg_exec "INSERT INTO roles(name, description, builtin) VALUES('cmp-only','test: CMP only',false)
         ON CONFLICT DO NOTHING;" >/dev/null
pg_exec "INSERT INTO role_permissions(role, permission, scope) VALUES
           ('cmp-only','cert:request','*'), ('cmp-only','cmp:enrol','*')
         ON CONFLICT DO NOTHING;" >/dev/null
chk "the custom role counts as enrolling" 1 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='cmp-only' AND permission LIKE '%:enrol';")"
# Assigning it through the console is what triggers the mint.
seed_web_user cmponly cmponlypw cmp-only
CJ=$(mktemp)
chk "a CMP secret was minted for them" 1 "$(n "SELECT count(*) FROM keys WHERE kid='cmponly' AND protocol='cmp';")"
# ...and a role granting NO protocol mints nothing, so the credential really does follow
# the grant rather than existing for everyone.
pg_exec "INSERT INTO roles(name, description, builtin) VALUES('no-enrol','test: no protocols',false)
         ON CONFLICT DO NOTHING;" >/dev/null
pg_exec "INSERT INTO role_permissions(role, permission, scope) VALUES('no-enrol','ca:read','*')
         ON CONFLICT DO NOTHING;" >/dev/null
seed_web_user noenrol noenrolpw no-enrol
chk "a non-enrolling role mints nothing" 0 "$(n "SELECT count(*) FROM keys WHERE kid='noenrol';")"

echo "=== 5. a refusal is audited, and distinguishable from a failed login ==="
chk "authz_fail was recorded"      yes \
    "$([ "$(n "SELECT count(*) FROM audit_log WHERE action='authz_fail';")" -ge 1 ] && echo yes || echo no)"
chk "  naming the account"         estdept \
    "$(n "SELECT DISTINCT actor FROM audit_log WHERE action='authz_fail' AND detail LIKE '%EST%' LIMIT 1;")"
chk "  and the capability needed"  yes \
    "$(n "SELECT count(*) FROM audit_log WHERE action='authz_fail' AND detail LIKE '%est:enrol%';" | grep -qv '^0$' && echo yes || echo no)"
chk "CMP records its own refusal"   yes \
    "$([ "$(n "SELECT count(*) FROM audit_log WHERE action='authz_fail' AND detail LIKE '%CMP%';")" -ge 1 ] && echo yes || echo no)"
chk "auth_fail is a DIFFERENT action" yes \
    "$([ "$(n "SELECT count(*) FROM audit_log WHERE action='auth_fail';")" -ge 1 ] && echo yes || echo no)"

echo "=== 6. the per-requester cap fires on EVERY protocol, in that protocol's language ==="
# `roles.max_certs` sits immediately after the enrol gate in est/cmp/msxcep, which is why it
# is asserted HERE: this is the one fixture that drives all three against one database, so a
# protocol that forgot to call it stands out against the two that did.
#
# ⚠️ THE REFUSAL ENCODING IS THE POINT, not just the refusal. Each of these three answers in
# a different shape because its clients read a different shape — a bare 429 to a WCF client
# is reported as "server requires basic auth", and a transport-level status to a CMP
# client is reported as a network problem rather than a decision. Copying EST's 429 into all
# three would "work" and tell two of the three client families the wrong thing.
#
# `plain` holds the builtin `requester` role and has already enrolled successfully above, so
# the cap is what changes — not some pre-existing refusal.
HELD=$(n "SELECT count(*) FROM certs WHERE owner='plain' AND status IN (0,2) AND cert_id IS NULL;")
chk "the fixture user already holds certificates" yes "$([ "$HELD" -ge 1 ] && echo yes || echo no)"

# Cap the role BELOW what he holds: every protocol must now refuse. Set it after those
# certificates exist, so this cannot pass because issuance was broken all along.
pg_exec "UPDATE roles SET max_certs=1 WHERE name='requester';" >/dev/null
[ "$HELD" -ge 2 ] || pg_exec "UPDATE roles SET max_certs=$HELD WHERE name='requester';" >/dev/null

chk "EST refuses with 429"          429 "$(est plain plainpw ca capped-est.internal)"
chk "  and issued nothing"            0 "$(n "SELECT count(*) FROM certs WHERE cn='capped-est.internal';")"
# MS: a UsernameToken caller gets a soap:Fault, not a status a WCF client would mis-report.
chk "MS refuses with a soap:Fault"  500 "$(ms plain plainpw ca capped-ms.internal)"
chk "  the fault says what happened" yes \
    "$(grep -qi 'issuance limit' mrcapped-ms.internal.xml && echo yes || echo no)"
chk "  and issued nothing"            0 "$(n "SELECT count(*) FROM certs WHERE cn='capped-ms.internal';")"
# CMP: thrown, so OpenSSL renders it as a PKIStatusInfo the client can print.
OUT_CAP=$(cmp_ir plain capped)
chk "CMP refuses"                    no  "$([ -s cmpcapped.pem ] && echo yes || echo no)"
chk "  and the client is told why"  yes \
    "$(printf '%s' "$OUT_CAP" | grep -qi 'issuance limit' && echo yes || echo no)"

# ⚠️ THE ANTI-VACUITY HALF. Lift the cap and all three must issue again. Without this, a
# build that refused every enrolment for any reason would pass everything above.
pg_exec "UPDATE roles SET max_certs=NULL WHERE name='requester';" >/dev/null
chk "lift the cap and EST issues again" 200 "$(est plain plainpw ca uncapped-est.internal)"
chk "  MS too"                          200 "$(ms plain plainpw ca uncapped-ms.internal)"
chk "  and CMP"                         yes \
    "$(cmp_ir plain uncapped >/dev/null; [ -s cmpuncapped.pem ] && echo yes || echo no)"

echo
echo "=== ENROL PERMISSIONS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
