#!/usr/bin/env bash
# The MS certificate template IS the issuance policy for MS-WSTEP.
#
# Profiles and templates are treated identically as resources, because semantically they
# are the same thing. Profiles apply to every protocol except MS-WSTEP; templates apply
# only to MS-WSTEP. Whatever a template allows must be honoured in the CSR, and a CSR that
# does not match its template is denied.
#
# Before this, `template:use|<name>` gated exactly one thing — the console's template
# catalogue — and WSTEP resolved a PROFILE with the requested template hardcoded empty. So
# a client asking for `GenericComputer` got whatever shape a profile tiebreak picked, and
# the certificate then carried the template name it had never honoured. Granting a template
# changed nothing; granting a profile was what actually mattered, which is what produced
#
#   ERR  WSTEP error: policy: this identity holds no profile permission ...
#
# on a request that had named its template perfectly well.
#
# ⚠️ WHAT MAKES THIS SUITE WORTH HAVING is that every assertion below is about a DECISION,
# not a shape: which template applied, whether a grant was seen, whether a mismatch was
# refused. The one shape assertion (key usage) is here precisely because it is the evidence
# that the template — and not a profile — chose it.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/ms_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; PORT=18462
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=MS Tmpl Policy CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout ms.key -out ms.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup ms_tmpl_policy
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt

cat > bootstrap.conf <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=tca
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
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf

# ── the cast ──────────────────────────────────────────────────────────────────
# Three identities, each holding a DIFFERENT amount of template permission, so the
# resolution rules are told apart by what they refuse rather than by what they allow.
seed_web_user many   pw-many   requester    # the seed: ro on all three built-ins
seed_web_user single pw-single tmpl-one     # exactly one template
seed_web_user viagrp pw-viagrp nogrant      # ms:enrol, but no template at all

pg_exec "INSERT INTO roles(name,description) VALUES
           ('tmpl-one','one template'),('nogrant','nothing'),('grp-role','via a group')
         ON CONFLICT DO NOTHING;"
pg_exec "INSERT INTO role_permissions(role,permission,scope) VALUES
           ('tmpl-one','ms:enrol','*'), ('tmpl-one','template:use','GenericComputer'),
           ('nogrant','ms:enrol','*'),
           ('grp-role','ms:enrol','*'),  ('grp-role','template:use','Email')
         ON CONFLICT DO NOTHING;"
# ⚠️ THE GROUP PATH IS THE ONE THAT KEEPS BREAKING. The single most repeated defect in this
# codebase is a permission lookup that takes the username and drops the caller's GROUPS, and
# it fails looking like a missing grant rather than a dropped one. So one identity here holds
# its template ONLY through a group.
pg_exec "INSERT INTO subject_roles(selector_type,selector_value,role)
         VALUES('group','TmplAdmins','grp-role') ON CONFLICT DO NOTHING;"
# ⚠️ NOT SWALLOWED. The first version of this line named columns that do not exist and
# ended in `2>/dev/null || true`, so the INSERT failed, `viagrp` was in no group, and the
# group assertion below failed for a fixture reason while reading as a product defect. A
# fixture that can fail silently makes the assertion it feeds measure nothing.
pg_exec "INSERT INTO directory_group_members(grp,username) VALUES('TmplAdmins','viagrp')
         ON CONFLICT DO NOTHING;"
chk "PRECONDITION: the group membership fixture really landed" 1 \
    "$(pg_exec "SELECT count(*) FROM directory_group_members
                 WHERE grp='TmplAdmins' AND username='viagrp';" | tr -d ' ')"

"$ROOT/build/fastpki-ms" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-ms died:"; cat srv.log; exit 1; }

wstep(){ # <user> <pw> <csr_b64> -> raw response
    local body='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><s:Header><wsse:Security><wsse:UsernameToken><wsse:Username>'"$1"'</wsse:Username><wsse:Password>'"$2"'</wsse:Password></wsse:UsernameToken></wsse:Security></s:Header><s:Body><wst:RequestSecurityToken><wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType><wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10">'"$3"'</wsse:BinarySecurityToken></wst:RequestSecurityToken></s:Body></s:Envelope>'
    curl -sk -H "Content-Type: application/soap+xml; charset=utf-8" --data "$body" \
         "https://127.0.0.1:$PORT/mswstep/tca"
}
# ⚠️ THE RSTR CARRIES TWO BinarySecurityTokens — the PKCS#7 chain first, then the issued
# X509v3 certificate inside <wst:RequestedSecurityToken>. Grabbing "the first one" gets the
# chain, which decodes to something that is not the leaf, and every assertion about the
# issued certificate then measures the wrong object. Isolate RequestedSecurityToken first.
# (busybox grep has no -P/\K, so this is sed + grep -o, same as ms_smoke.sh.)
cert_of(){
    local b64; b64=$(printf '%s' "$1" | sed 's/.*<wst:RequestedSecurityToken>//' \
                     | grep -o 'base64binary">[^<]*' | head -1 | sed 's/.*base64binary">//')
    [ -n "$b64" ] || { echo ""; return; }
    printf '%s' "$b64" | "$OSSL" base64 -d -A > got.der 2>/dev/null || { echo ""; return; }
    "$OSSL" x509 -inform DER -in got.der 2>/dev/null
}
issued(){ [ -n "$(cert_of "$1")" ] && echo yes || echo no; }

echo "=== 1. a request that NAMES a permitted template is issued under it ==="
R=$(wstep single pw-single "$(ms_csr_b64 one.internal GenericComputer k1.key)")
chk "single-template identity enrols naming its template" yes "$(issued "$R")"
cert_of "$R" > c1.pem
TXT=$("$OSSL" x509 -in c1.pem -noout -text 2>/dev/null)
# ⚠️ THE EVIDENCE THAT THE TEMPLATE CHOSE THE SHAPE. GenericComputer's key_usage bitmap is
# 0xA000 = digitalSignature + keyEncipherment. A profile tiebreak would have produced the
# profile's key usage instead, and that is exactly what used to happen.
chk "  key usage comes from the TEMPLATE (digitalSignature)" yes \
    "$(printf '%s' "$TXT" | grep -A1 'X509v3 Key Usage' | grep -q 'Digital Signature' && echo yes || echo no)"
chk "  and keyEncipherment, the other bit of 0xA000" yes \
    "$(printf '%s' "$TXT" | grep -A1 'X509v3 Key Usage' | grep -q 'Key Encipherment' && echo yes || echo no)"
chk "  the template identity is stamped on the cert" yes \
    "$(printf '%s' "$TXT" | grep -q '1.3.6.1.4.1.311.20.2' && echo yes || echo no)"

# ⚠️ THE CASE THE HARNESS NEVER BUILT. Every other MS CSR here is made WITHOUT an EKU, so
# issuance takes the default_eku branch and the template's long names are only ever
# compared against themselves. Windows does not behave that way: CertEnroll copies the
# EKU out of the template it enrolled under, so a real request carries one — and it was
# then dropped, because the CSR yields OpenSSL SHORT names ("serverAuth") and the
# template holds LONG ones ("TLS Web Server Authentication"). The certificate came back
# with NO EKU extension at all, under a template announcing that EKU as critical.
R=$(wstep single pw-single "$(ms_csr_b64 eku.internal GenericComputer keku.key \
                             'serverAuth,clientAuth')")
chk "a request that CARRIES an EKU is issued" yes "$(issued "$R")"
cert_of "$R" > ceku.pem
ETXT=$("$OSSL" x509 -in ceku.pem -noout -text 2>/dev/null)
chk "  and the certificate actually HAS an EKU extension" yes \
    "$(printf '%s' "$ETXT" | grep -q 'X509v3 Extended Key Usage' && echo yes || echo no)"
chk "  carrying serverAuth, which the template announced" yes \
    "$(printf '%s' "$ETXT" | grep -A1 'Extended Key Usage' | grep -q 'TLS Web Server Authentication' && echo yes || echo no)"
chk "  and clientAuth, the other half of 0xA000's purpose set" yes \
    "$(printf '%s' "$ETXT" | grep -A1 'Extended Key Usage' | grep -q 'TLS Web Client Authentication' && echo yes || echo no)"

echo "=== 2. a template the identity may NOT use is refused ==="
# GenericUser exists and is perfectly valid — this identity simply holds no grant on it.
R=$(wstep single pw-single "$(ms_csr_b64 two.internal GenericUser k2.key)")
chk "naming an unpermitted template does not issue" no "$(issued "$R")"
chk "  and the refusal names the template" yes \
    "$(printf '%s' "$R" | grep -q "GenericUser" && echo yes || echo no)"
chk "  as a soap:Fault, which is what a WCF client can read" yes \
    "$(printf '%s' "$R" | grep -qi 'Fault' && echo yes || echo no)"

echo "=== 3. no template permission at all is a REFUSAL, never a fallback ==="
# ⚠️ "An empty permitted set means the feature is not adopted yet, so honour the request"
# is the exact shape that handed out `master` and wildcards on the profile side before it
# was deleted. It must refuse.
R=$(wstep viagrp pw-viagrp "$(ms_csr_b64 three.internal GenericUser k3.key)")
chk "an identity with no grant on the named template is refused" no "$(issued "$R")"

# ⚠️ AND THE SERVER SAYS SO LOUDLY, because the CLIENT will not. An identity with no
# template grant gets a valid 200 carrying an EMPTY <policies> list, and Windows turns that
# into an error naming nothing about permissions: Add-CertificateEnrollmentPolicyServer
# reports WS_E_INVALID_FORMAT and certreq reports ERROR_INVALID_PARAMETER (0x80070057).
# Both read as a malformed policy document. That cost six disproved hypotheses -- template
# schema, keySpec, crypto provider, the cAURI list, the WS-Addressing headers and XSD
# validity -- while this one log line, then at INFO among startup chatter, said exactly what
# was wrong. Zero is the case an operator never intends, so it is logged as a failure.
XCEP_GP='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"><client><lastUpdate xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/><preferredLanguage xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/></client></GetPolicies></s:Body></s:Envelope>'
XCEP_EMPTY=$(curl -sk -u viagrp:pw-viagrp -H 'Content-Type: application/soap+xml' \
    --data "$XCEP_GP" "https://127.0.0.1:$PORT/msxcep/tca" 2>/dev/null)
chk "  a zero-template policy really is served (the shape that misleads)" 0 \
    "$(printf '%s' "$XCEP_EMPTY" | grep -o '<policy>' | wc -l | tr -d ' ')"
chk "  and the log says so at ERROR, not INFO" yes \
    "$(grep -qE 'ERR.*XCEP offering 0 of' srv.log && echo yes || echo no)"
chk "  naming the grant that is missing" yes \
    "$(grep -q 'template:use' srv.log && echo yes || echo no)"

echo "=== 4. the two places a caller\'s GROUPS get dropped ==="
# ⚠️ THIS IS A CENSUS, NOT AN END-TO-END TEST, AND THE REASON MATTERS.
#
# The first version of this section granted a template to a group, put `viagrp` in that
# group via directory_group_members, and asserted the enrolment succeeded. It failed — and
# the product was right. Groups reach an authenticated identity from LDAP only
# (`ldap_groups_for_user`); directory_group_members is a cache the CONSOLE reads. Under
# AUTH_BACKEND=local a user simply has no groups, so that fixture could never have worked
# and the red assertion was measuring my test, not the code.
#
# The behaviour IS covered where it can be true: ldap.sh drives a real slapd and asserts
# that a role granted to an LDAP GROUP authorizes its members, through the same
# subject_roles() call templates_for_identity() makes.
#
# What is left worth guarding is the specific defect this codebase repeats: a permission
# lookup that takes the username and DROPS the groups. It fails looking like a missing
# grant rather than a dropped one, which is why a shape check earns its place here.
POL="$ROOT/src/lib/ms_template_policy.cpp"; MS="$ROOT/src/msxcep/main.cpp"
chk "templates_for_identity passes the caller\'s groups to subject_roles" yes \
    "$(grep -q 'subject_roles(db, id.username, id.role, id.groups)' "$POL" && echo yes || echo no)"
chk "  and WSTEP puts groups into the identity it resolves with" yes \
    "$(grep -q 'ProfileIdentity{auth_user, role, groups}' "$MS" && echo yes || echo no)"
# Anti-vacuity: both greps above must be looking at real files, or both pass over nothing.
chk "  and both files were actually read" yes \
    "$([ -s "$POL" ] && [ -s "$MS" ] && echo yes || echo no)"

echo "=== 5. several permitted and none named is ambiguous, so it is refused ==="
# The seed gives `requester` template:use on GenericUser, Email AND GenericComputer. Their
# key usages differ, so picking one would make the issued certificate depend on something
# nobody chose. A real Windows client always names a template.
R=$(wstep many pw-many "$(ms_csr_b64 five.internal '' k5.key)")
chk "a bare CSR with three permitted templates does not issue" no "$(issued "$R")"
chk "  and the refusal lists the choice" yes \
    "$(printf '%s' "$R" | grep -q 'GenericUser' && echo yes || echo no)"
# ...but naming one of them works, so the refusal above is about ambiguity and not about
# the identity being unable to enrol at all.
R=$(wstep many pw-many "$(ms_csr_b64 six.internal Email k6.key)")
chk "  naming one of the three DOES issue" yes "$(issued "$R")"

echo "=== 6. the CSR is validated AGAINST the template ==="
# "whatever is allowed in template, should be honored in CSR. If CSR does not match the
# template, the request should be denied." GenericComputer's bitmap has no cRLSign, so a
# CSR asking for it exceeds the template.
printf '[req]\ndistinguished_name=dn\nreq_extensions=v3\nprompt=no\n[dn]\nCN=seven.internal\n[v3]\nkeyUsage=cRLSign\n1.3.6.1.4.1.311.20.2=ASN1:BMPSTRING:GenericComputer\n' > bad.cnf
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout k7.key -out bad.csr -config bad.cnf >/dev/null 2>&1
BAD=$("$OSSL" req -in bad.csr -outform DER 2>/dev/null | "$OSSL" base64 -A)
R=$(wstep single pw-single "$BAD")
chk "a CSR asking beyond the template's key usage is denied" no "$(issued "$R")"

echo "=== 7. min_key_size is the one rule a profile cannot carry ==="
pg_exec "INSERT INTO ms_templates(name,oid,min_key_size,key_usage,validity_days)
         VALUES('BigKeyOnly','1.3.6.1.4.1.99999.7.1',4096,40960,365)
         ON CONFLICT (name) DO UPDATE SET min_key_size=4096;"
pg_exec "INSERT INTO role_permissions(role,permission,scope)
         VALUES('tmpl-one','template:use','BigKeyOnly') ON CONFLICT DO NOTHING;"
kill $P 2>/dev/null; wait $P 2>/dev/null       # the catalogue is read at startup
"$ROOT/build/fastpki-ms" --config bootstrap.conf >srv2.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
R=$(wstep single pw-single "$(ms_csr_b64 eight.internal BigKeyOnly k8.key)")   # 2048-bit
chk "a 2048-bit key under a 4096-bit template is refused" no "$(issued "$R")"
chk "  and the refusal says both numbers" yes \
    "$(printf '%s' "$R" | grep -q '2048' && printf '%s' "$R" | grep -q '4096' && echo yes || echo no)"

echo "=== 8. WHO the certificate is for is the template's decision, not the requester's ==="
# ⚠️ THE SUBJECT WAS NEVER SET ON THIS PATH. Every certificate this endpoint issued carried
# the CSR's name verbatim, so anyone who could enrol under a template could obtain a
# client-auth certificate in somebody else's name. The name flags carry an
# enrollee-supplies-subject grant and it was advertised in the policy document and enforced
# nowhere.
#
# 0xA6000000 is a REAL directory value (top bit set, so it arrives as a negative decimal)
# and its low bit — the grant — is CLEAR. Seeded as the signed form on purpose: a helper
# that compared the value instead of testing the bit would read this as "granted".
pg_exec "INSERT INTO ms_templates(name,oid,min_key_size,key_usage,validity_days,subject_name_flags)
         VALUES('DirectoryNamed','1.3.6.1.4.1.99999.8.1',2048,40960,365,-1509949440)
         ON CONFLICT (name) DO UPDATE SET subject_name_flags=-1509949440;"
pg_exec "INSERT INTO role_permissions(role,permission,scope)
         VALUES('tmpl-one','template:use','DirectoryNamed') ON CONFLICT DO NOTHING;"
# ⚠️ THE CONTROL NEEDS A **DB** TEMPLATE, NOT A BUILT-IN. The built-in defaults are served
# only while `ms_templates` is EMPTY, and this section fills it — so a control naming
# GenericComputer would fail for a fixture reason and read exactly like the fix having
# broken every template that does grant the subject. 0x9 is the built-in's own flag value,
# low bit SET.
pg_exec "INSERT INTO ms_templates(name,oid,min_key_size,key_usage,validity_days,subject_name_flags)
         VALUES('EnrolleeNamed','1.3.6.1.4.1.99999.8.2',2048,40960,365,9)
         ON CONFLICT (name) DO UPDATE SET subject_name_flags=9;"
pg_exec "INSERT INTO role_permissions(role,permission,scope)
         VALUES('tmpl-one','template:use','EnrolleeNamed') ON CONFLICT DO NOTHING;"
chk "PRECONDITION: the template really carries the negative flag" -1509949440 \
    "$(pg_exec "SELECT subject_name_flags FROM ms_templates WHERE name='DirectoryNamed';" | tr -d ' ')"
kill $P 2>/dev/null; wait $P 2>/dev/null       # the catalogue is read at startup
"$ROOT/build/fastpki-ms" --config bootstrap.conf >srv3.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true

# The impersonation attempt: `single` asks for a certificate naming somebody else, and
# carries a victim address in the SAN as well — the half that actually impersonates in a
# client-auth certificate.
printf '[req]\ndistinguished_name=dn\nreq_extensions=v3\nprompt=no\n[dn]\nCN=Administrator\nemailAddress=victim@example.com\n[v3]\nsubjectAltName=email:victim@example.com,DNS:victim.internal\n1.3.6.1.4.1.311.20.2=ASN1:BMPSTRING:DirectoryNamed\n' > imp.cnf
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout k9.key -out imp.csr -config imp.cnf >/dev/null 2>&1
IMP=$("$OSSL" req -in imp.csr -outform DER 2>/dev/null | "$OSSL" base64 -A)
# Anti-vacuity: the request must really be asking for the other name, or the assertions
# below pass against a CSR that never attempted anything.
chk "  fixture: the CSR really asks for another name" yes \
    "$("$OSSL" req -in imp.csr -noout -subject 2>/dev/null | grep -q 'Administrator' && echo yes || echo no)"
chk "  fixture: and really carries the victim SAN" yes \
    "$("$OSSL" req -in imp.csr -noout -text 2>/dev/null | grep -q 'victim@example.com' && echo yes || echo no)"

R=$(wstep single pw-single "$IMP")
# It is ISSUED, not refused — the template grants enrolment, it just does not grant naming.
# That is what a directory-authoritative template does: the CA builds the name.
chk "the request is still issued under the template" yes "$(issued "$R")"
cert_of "$R" > imp.pem
ITXT=$("$OSSL" x509 -in imp.pem -noout -text 2>/dev/null)
chk "  but the subject is the AUTHENTICATED principal" yes \
    "$("$OSSL" x509 -in imp.pem -noout -subject 2>/dev/null | grep -q 'CN *= *single' && echo yes || echo no)"
chk "  the requested common name is gone"        no \
    "$("$OSSL" x509 -in imp.pem -noout -subject 2>/dev/null | grep -q 'Administrator' && echo yes || echo no)"
# ⚠️ AND THE OTHER RDNs. Dropping only the CN would leave `emailAddress=victim@…` standing,
# which names the victim just as well in a mail-protection certificate.
chk "  the requested emailAddress RDN is gone"   no \
    "$("$OSSL" x509 -in imp.pem -noout -subject 2>/dev/null | grep -q 'victim@example.com' && echo yes || echo no)"
chk "  and no requested SAN survived"            no \
    "$(printf '%s' "$ITXT" | grep -q 'victim' && echo yes || echo no)"

# ⚠️ THE POSITIVE CONTROL. Every assertion above would also pass if this endpoint had simply
# stopped honouring requested names altogether, which would break every template that DOES
# grant the subject. EnrolleeNamed's flags are 0x9 — low bit SET — so its requested name
# must still come through untouched.
R=$(wstep single pw-single "$(ms_csr_b64 nine.internal EnrolleeNamed k10.key)")
chk "CONTROL: a template that GRANTS the subject still honours it" yes \
    "$(cert_of "$R" > ctl.pem 2>/dev/null; "$OSSL" x509 -in ctl.pem -noout -subject 2>/dev/null | grep -q 'nine.internal' && echo yes || echo no)"

# A refusal here is a POLICY decision the server explains in its log. Without this, a red
# assertion says only "no certificate came back" and the reason has to be reproduced by hand.
[ "$fail" -eq 0 ] || { echo "--- fastpki-ms log (last 25 policy lines) ---"
                       grep -iE "wstep|policy|template" srv*.log | tail -25; }
echo "=== 9. every suite that drives WSTEP names a template ==="
# ⚠️ I HUNTED THESE BY HAND AND MISSED TWO. Four suites were patched, the full run then
# failed on `ca_rollover_chain.sh` and `ms_kerberos.sh`, which drive WSTEP too. A bare CSR
# is no longer a valid MS-WSTEP request, so any suite that posts a RequestSecurityToken and
# builds its own CSR is a suite that will start refusing the day someone re-runs it.
#
# So: a suite that posts a RequestSecurityToken must put a certificate template in the
# request it builds. Nothing here needs updating when a new MS suite is added — it is caught
# on the day it lands.
#
# ⚠️ READ CODE, AND ASK FOR THE TEMPLATE RATHER THAN FOR THE HELPER'S NAME. A bare
# `grep -q ms_csr` over the whole file was satisfied by ad_template_import.sh's comment
# explaining why it does NOT use ms_csr_b64 (that template's imported minimum is 3072 and
# the helper is fixed at rsa:2048) — so the one suite that hand-rolls its WSTEP request
# cleared the census it is the counter-example to. What the CA needs is szOID_ENROLL_CERTTYPE
# in the request, so either the helper or the OID written out satisfies it, and both are read
# with comments stripped. What this still cannot see is a suite that builds one templated
# request and one bare one; that second request is refused when the suite runs.
MSTMPL='1\.3\.6\.1\.4\.1\.311\.20\.2|1\.3\.6\.1\.4\.1\.311\.21\.7'
cd "$ROOT"
drivers=$(grep -l 'RequestSecurityToken' tests/*.sh | grep -v 'tests/ms_template_policy.sh')
missing=""
for f in $drivers; do
    # comments cannot satisfy either half: whole-line ones go, then a trailing ` #…`
    code=$(grep -v "^[[:space:]]*#" "$f" | sed "s/[[:space:]]#.*//")
    # Only suites that build their OWN csr for it — one that reuses a fixture is fine.
    printf '%s\n' "$code" | grep -qE 'req -new' || continue
    printf '%s\n' "$code" | grep -qE "ms_csr|$MSTMPL" || missing="$missing $(basename "$f")"
done
chk "every WSTEP-driving suite names a template in the CSR it builds" "" "$missing"
# Anti-vacuity: the driver list must be non-empty, or the loop above proves nothing.
chk "  and the driver list is not empty" yes \
    "$([ "$(printf '%s\n' $drivers | grep -c .)" -ge 5 ] && echo yes || echo no)"

echo "=== MS TEMPLATE POLICY: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
