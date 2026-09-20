#!/usr/bin/env bash
# EST client-certificate authentication: WHERE the identity comes from, and
# (what part of it may be believed).
#
# ── the identity source ─────────────────────────────────────────────────────────
# fastpki-est used to take the caller's identity from two REQUEST HEADERS:
#
#     CLIENT_CERT_VERIFY: SUCCESS
#     SUBJECT_DN:         CN=alice
#
# written by a reverse proxy that had verified a client certificate. Nothing restricted
# where they came from — no trusted-proxy list, no source check, no shared secret — and
# the shipped compose publishes est on :8443 directly. Anyone who could reach the port
# could enrol as any identity, and auto-onboarding let them invent identities.
#
# EST now verifies the certificate itself, against EST_CLIENT_CA_ID / EST_CLIENT_CA_BUNDLE,
# and the identity is the CN of the VERIFIED peer certificate. This suite drives a real
# client certificate over a real TLS handshake, which is the only way to test that.
#
# ── the role RDN ────────────────────────────────────────────────────────────────
# The subject is trusted for the NAME and nothing else. `parse_subject_dn()` used to read
# `role=` out of it too, so that RDN became the caller's authenticated role — and a client
# can put it there itself: issue_cert() keeps every RDN the CSR asked for and replaces only
# the CN, and `role` is a standard X.520 attribute (OID 2.5.4.72) so OpenSSL accepts it.
# Measured before that fix:
#
#     CSR subject:         CN=probe.internal, role=master
#     ISSUED cert subject: CN=probe.internal, role=master
#
# What it bought: a certificate row and an audit line recording a role the caller was never
# granted. Every client certificate below carries role=master in its subject for exactly
# this reason — moving to real mTLS did not make that RDN trustworthy, it is still written
# by whoever asked for the certificate.
#
# ⚠️ This was originally reported as also lifting the per-CN cap. That part is WRONG and
# writing this suite is what showed it — `count_active_for_cn()` counts certificates whose
# CN equals the USERNAME. Tracked separately; this suite sets neither cap key so it
# cannot depend on that behaviour.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF

W="$(mktemp -d)"; cd "$W"; PORT=18499
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=mTLS Role CA" 3 || { echo "SKIP: could not mint a CA key in a token"; exit 0; }
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3 -subj "/CN=localhost" >/dev/null 2>&1
# A SECOND, unrelated CA. Its certificates are perfectly valid — they are simply not
# issued by an anchor EST was given, which is the case that has to be refused.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout rogue-ca.key -out rogue-ca.pem -days 3 \
        -subj "/CN=Rogue CA" >/dev/null 2>&1

pg_setup est_mtls_role
SRV=
trap 'pg_cleanup; kill ${SRV:-} 2>/dev/null' EXIT
printf "internal\n" > domains.txt; seed_domains "$W/domains.txt"

# alice is a STANDARD user. Everything below asks whether she can talk her way up.
# `requester`, not `standard`: a role matching no `roles` row grants
# nothing, so alice would be refused before the assertions below could measure anything.
# The suite's point is unchanged — her CSR claims role=master, her STORED role is what
# the issued certificate must carry, and it is now `requester`.
seed_web_user alice alicepw12 requester
# ⚠️ AND THE SAME PERSON AS A CERTIFICATE IDENTITY, QUALIFIED. A client certificate is not a
# local account: EST issues the CSR's subject verbatim, so a bare CN would let anyone who can
# enrol mint /CN=admin and wear it. mkclient below signs with ca.pem but never records the
# result in `certs`, so these certificates take the foreign-anchor path and authorize as
# `dn\<CN>`. The Basic-auth cases further down still use the unqualified `alice`, which is
# the point of the distinction.
seed_web_user 'dn\alice' alicepw12 requester

cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$PORT
EST_CLIENT_CA_ID=ca
CERT_VALIDITY_DAYS=365
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf
"$ROOT/build/fastpki-est" --config bootstrap.conf >srv.log 2>&1 & SRV=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$SRV" || true
kill -0 $SRV 2>/dev/null || { echo "fastpki-est died:"; cat srv.log; exit 1; }

# ⚠️ Assert the server actually turned mTLS ON. Without this every "refused" below is
# also what an EST that never asked for a certificate would produce, and the suite would
# pass just as happily against a build with no client-cert support at all.
# ⚠️ WAIT for the line rather than trusting the sleep above. Measured: this assertion
# failed once in three runs on a loaded box — the server was up and every later assertion
# passed, but the startup line had not been flushed when the grep ran. A guard that goes
# red for a reason unrelated to what it guards is worse than no guard, because the next
# person spends their time on the wrong thing.
for _ in $(seq 1 40); do
    grep -q 'client-certificate authentication enabled' srv.log && break
    sleep 0.25
done
chk "EST enabled client-certificate auth" yes \
    "$(grep -q 'client-certificate authentication enabled' srv.log && echo yes || echo no)"

# mkclient <cn> <out-prefix> [rogue] — a client certificate whose subject carries
# role=master, signed by the EST trust anchor (or by the rogue CA).
mkclient() {
    "$OSSL" req -new -subj "/CN=$1/role=master" -newkey rsa:2048 -nodes \
            -keyout "$2.key" -out "$2.csr" >/dev/null 2>&1
    if [ "${3:-}" = rogue ]; then
        "$OSSL" x509 -req -in "$2.csr" -CA rogue-ca.pem -CAkey rogue-ca.key \
                -CAcreateserial -days 2 -out "$2.pem" >/dev/null 2>&1
    else
        "$OSSL" x509 -req -in "$2.csr" -CA ca.pem -CAkey "$CA_KEY_URI" ${CA_OSSL_ARGS:-} \
                -CAcreateserial -days 2 -out "$2.pem" >/dev/null 2>&1
    fi
    [ -s "$2.pem" ]
}

# enrol_cert <client-prefix> <csr-cn> -> HTTP status (or 000 if the handshake was refused)
enrol_cert() {
    "$OSSL" req -new -subj "/CN=$2" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr >/dev/null 2>&1
    "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
    curl -sk -o body.out -w '%{http_code}' \
        --cert "$1.pem" --key "$1.key" \
        --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll"
}

mkclient alice   c_alice   || { echo "FAIL: could not issue the alice client cert"; exit 1; }
mkclient mallory c_mallory || { echo "FAIL: could not issue the mallory client cert"; exit 1; }
mkclient alice   c_rogue rogue || { echo "FAIL: could not issue the rogue client cert"; exit 1; }

echo "=== The HEADERS are not an identity any more ==="
# THE assertion for mTLS identity. Exactly the request that used to enrol as anyone: the two
# headers, no client certificate at all, no credentials. It must now authenticate nobody.
"$OSSL" req -new -subj "/CN=hdr.internal" -newkey rsa:2048 -keyout hk.pem -nodes -out hr.csr >/dev/null 2>&1
"$OSSL" req -in hr.csr -outform DER 2>/dev/null | "$OSSL" base64 > hr.b64
HDR=$(curl -sk -o hdr.out -w '%{http_code}' \
        -H "CLIENT_CERT_VERIFY: SUCCESS" -H "SUBJECT_DN: CN=alice,role=master" \
        --data-binary @hr.b64 -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll")
chk "CLIENT_CERT_VERIFY + SUBJECT_DN authenticate NOBODY" 401 "$HDR"
chk "  and no certificate was issued from them"           0 \
    "$(pg_exec "select count(*) from certs where cn='hdr.internal';" | tr -d ' ')"
# ⚠️ And the headers must not work as a SIDE CHANNEL either: a real certificate present,
# headers naming somebody else. If the header were still read first, this would enrol as
# mallory while holding alice's key.
HDR2=$(curl -sk -o hdr2.out -w '%{http_code}' \
        --cert c_alice.pem --key c_alice.key \
        -H "CLIENT_CERT_VERIFY: SUCCESS" -H "SUBJECT_DN: CN=mallory,role=master" \
        --data-binary @hr.b64 -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll")
chk "a header cannot override the certificate presented"  200 "$HDR2"
chk "  the row belongs to the CERTIFICATE holder"         1 \
    "$(pg_exec "select count(*) from certs where cn='hdr.internal' and owner='dn\\alice';" | tr -d ' ')"
chk "  and not to the name in the header"                 0 \
    "$(pg_exec "select count(*) from certs where cn='hdr.internal' and owner='mallory';" | tr -d ' ')"

echo "=== A certificate from an untrusted CA is refused at the handshake ==="
# curl reports 000 when the server terminates the handshake — SSL_VERIFY_PEER without
# SSL_VERIFY_FAIL_IF_NO_PEER_CERT means "you may send nothing, but what you send must
# verify". The rogue certificate is well-formed and correctly signed; it is simply not
# signed by an anchor this EST was given.
ROGUE=$(enrol_cert c_rogue "rogue.internal")
chk "an untrusted client certificate does not get in"  000 "$ROGUE"
chk "  and issued nothing"                             0 \
    "$(pg_exec "select count(*) from certs where cn='rogue.internal';" | tr -d ' ')"

echo "=== the certificate is trusted for the NAME, and the name alone ==="
c1=$(enrol_cert c_alice "one.internal")
chk "a verified mTLS caller enrols"                200 "$c1"
chk "  the certificate is recorded against alice"  1 \
    "$(pg_exec "select count(*) from certs where owner='dn\\alice' and cn='one.internal';" | tr -d ' ')"
# ⚠️ The two assertions that used to read certs.role are GONE, not relaxed: that column
# that column, so `select ... where role='master'` now errors and returns empty — which
# compares equal to the 0 one of them expected, i.e. it would have kept "passing" while
# testing nothing. The property they guarded is unchanged and is asserted immediately
# below against the AUDIT TRAIL, which is the stronger witness anyway: a row can only say
# what it stored, while the audit line is what an investigator actually reads. "no audit
# line claims master" fails loudly if a claimed role ever gets believed again.

echo "=== the audit trail records the real role, not the claimed one ==="
# The audit line is what an investigator reads afterwards. It used to say the
# enrolment was made under a role the caller was never granted.
# ⚠️ Not "== 1". alice enrols more than once above (the header-override case issues one
# too), so pinning the count makes this assertion a bookkeeping check on the fixture
# rather than a statement about the audit trail — and it would go red every time a case
# is added, which trains you to edit the number instead of reading the failure.
chk "every alice enrolment is audited as requester" yes \
    "$([ "$(pg_exec "select count(*) from audit_log where action='cert_issued' and detail like '%role=requester%';" | tr -d ' ')" -ge 1 ] && echo yes || echo no)"
chk "  and no audit line claims master"      0 \
    "$(pg_exec "select count(*) from audit_log where detail like '%role=master%';" | tr -d ' ')"

echo "=== an identity with no database row is REFUSED and ONBOARDED as 'none' ==="
# ⚠️ THIS ASSERTION WAS INVERTED once. It used to say "an unknown mTLS subject still
# enrols (documented)" and called that deliberate. That was overruled:
#
#   'no role' is NOT allowed to proceed. It is treated exactly
#    like role 'none' - no access except an entry should be created in web_users table
#    with role 'none', so that admin can assign a proper role if needed for external
#    users (LDAP, SAML, OIDC)."
#
# He was right, and the hole was bigger than a default. AuthInfo::role is initialised to
# "standard", which is an ISSUANCE role, not a console one — and may_enrol() used to enforce
# for roles it recognises as console roles (`if (known.empty()) return true`). So the
# unknown caller was not merely defaulted, it was waved straight through the gate on the
# strength of a client certificate, with no row anywhere and nothing to revoke.
c3=$(enrol_cert c_mallory "three.internal")
chk "an unknown mTLS subject is REFUSED"     403 "$c3"
chk "  and no certificate was issued to it"  0 \
    "$(pg_exec "select count(*) from certs where owner='dn\\mallory';" | tr -d ' ')"
# The other half: a refusal alone would leave the admin with an invisible caller. The row
# is what makes the identity assignable, mirroring what OIDC/SAML already do.
chk "  but it IS onboarded into web_users"   1 \
    "$(pg_exec "select count(*) from web_users where username='dn\\mallory';" | tr -d ' ')"
chk "    with role none, not the claimed one" "none" \
    "$(pg_exec "select role from web_users where username='dn\\mallory';" | tr -d ' ')"
chk "    and no password hash (cert auth only)" "" \
    "$(pg_exec "select coalesce(hash,'') from web_users where username='dn\\mallory';" | tr -d ' ')"
# ⚠️ Dropped certs.role, so the old "nothing is recorded as master" check here would
# have kept passing while querying a column that does not exist — its healthy answer was 0
# and a failed query also returns empty. The claim is made against the audit trail instead,
# where a wrongly-believed role would actually show up.
chk "  and no audit line anywhere claims master" 0 \
    "$(pg_exec "select count(*) from audit_log where detail like '%role=master%';" | tr -d ' ')"

# ⚠️ THE POINT OF ONBOARDING, not just of refusing. If assigning a role did not then let
# the same identity in, the row would be decoration and the feature would be a plain deny.
pg_exec "update web_users set role='requester' where username='dn\\mallory';" >/dev/null
c3b=$(enrol_cert c_mallory "three-b.internal")
chk "once an admin grants a role, the SAME subject enrols" 200 "$c3b"
chk "  and it is AUDITED with the GRANTED role, not the claimed one" yes \
    "$([ "$(pg_exec "select count(*) from audit_log where action='cert_issued' and actor='dn\\mallory' and detail like '%role=requester%';" | tr -d ' ')" -ge 1 ] && echo yes || echo no)"

echo "=== HTTP Basic still works alongside it (RFC 7030 §3.2.3) ==="
# ⚠️ The fallback is the reason install_client_trust() sets SSL_VERIFY_PEER WITHOUT
# SSL_VERIFY_FAIL_IF_NO_PEER_CERT. Get that wrong and every password client is killed at
# the handshake the moment an operator sets EST_CLIENT_CA_ID — a change that looks like it
# only ADDS an authentication method. Exactly this fallback was required.
"$OSSL" req -new -subj "/CN=basic.internal" -newkey rsa:2048 -keyout bk.pem -nodes -out br.csr >/dev/null 2>&1
"$OSSL" req -in br.csr -outform DER 2>/dev/null | "$OSSL" base64 > br.b64
BAS=$(curl -sk -o basic.out -w '%{http_code}' -u alice:alicepw12 \
        --data-binary @br.b64 -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll")
chk "a password client enrols with NO certificate" 200 "$BAS"
chk "  and it is recorded against alice"           1 \
    "$(pg_exec "select count(*) from certs where cn='basic.internal' and owner='alice';" | tr -d ' ')"
# And an unauthenticated caller is still refused, so the above is not "everything gets in".
NOA=$(curl -sk -o /dev/null -w '%{http_code}' \
        --data-binary @br.b64 -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll")
chk "  an anonymous caller is still refused"       401 "$NOA"

echo "=== A device may renew ITS OWN certificate, and nothing else ==="
# The exact report: get a certificate with username+password, then present THAT
# certificate as the client cert and try again. It was refused — the CN had no
# web_users row, so it onboarded with role 'none'. The ruling:
#
#   "allow these entities to request/renew/revoke this cert by default. The owner may
#    still revoke a device cert and this will essentially removes a permission from the
#    device to continue renewing its cert."
#
# ⚠️ The certificate has to be one the PRODUCT issued, not one openssl signed here.
# mkclient() above signs with the CA key directly and writes no `certs` row, and a row is
# what makes the grant revocable — the whole lever this relies on. So this enrols for
# real over Basic first, exactly as the report did.
"$OSSL" req -new -subj "/CN=device.internal" -newkey rsa:2048 -nodes \
        -keyout dev.key -out dev.csr >/dev/null 2>&1
"$OSSL" req -in dev.csr -outform DER 2>/dev/null | "$OSSL" base64 > dev.b64
curl -sk -o dev.p7 -u alice:alicepw12 --data-binary @dev.b64 \
     -H "Content-Type: application/pkcs10" \
     "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll" >/dev/null 2>&1
"$OSSL" base64 -d -A -in dev.p7 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs \
        -out dev.pem 2>/dev/null
chk "PRECONDITION: the device holds a real issued certificate" yes \
    "$(grep -q 'BEGIN CERTIFICATE' dev.pem 2>/dev/null && echo yes || echo no)"
DEVSER=$("$OSSL" x509 -in dev.pem -noout -serial 2>/dev/null | sed 's/serial=//')
chk "  and it is recorded in certs"                            1 \
    "$(pg_exec "select count(*) from certs where cn='device.internal';" | tr -d ' ')"
# device.internal has NO web_users row and therefore no role — that is the bug's setup.
chk "  and the device identity holds no role"                  0 \
    "$(pg_exec "select count(*) from web_users where username='device.internal' and role<>'none';" | tr -d ' ')"

# 1. THE FIX: same identity, authenticated by its own certificate -> issued.
enrol_with() {   # <cert-prefix> <csr-cn> -> status
    "$OSSL" req -new -subj "/CN=$2" -newkey rsa:2048 -keyout r2.key -nodes -out r2.csr >/dev/null 2>&1
    "$OSSL" req -in r2.csr -outform DER 2>/dev/null | "$OSSL" base64 > r2.b64
    curl -sk -o /dev/null -w '%{http_code}' --cert "$1.pem" --key "$1.key" \
        --data-binary @r2.b64 -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll"
}
cp dev.key dev_c.key; cp dev.pem dev_c.pem
# ⚠️ A 200 AND A CERTIFICATE, not just an authorization decision. Slice 2 got the gate to
# say yes and issuance still refused at 400, because device.internal holds no role, holds
# no profile, and an empty profile union is a refusal. Three options were proposed
# ways to give it one; all three were rejected in favour of:
#
#   "it's kind of a virtual profile if you wish, it only allows the same attributes on CSR
#    as in the provided cert, and validity should not be longer than existing one. Another
#    words, allow to renew with existing set of attributes and revoke and nothing else."
#   "which profile? The requester's role profile? It will be too broad for a particular
#    device. … A human requester would normally have more allowed attributes than a
#    particular device has."
#
# So the policy is read OFF the held certificate (pki::profile_from_cert). Nothing is
# stored, nothing is granted, and the ceiling is that device's own certificate.
enrol_body() {   # <cert-prefix> <csr-cn> -> PEM on stdout
    "$OSSL" req -new -subj "/CN=$2" -newkey rsa:2048 -keyout r3.key -nodes -out r3.csr >/dev/null 2>&1
    "$OSSL" req -in r3.csr -outform DER 2>/dev/null | "$OSSL" base64 > r3.b64
    curl -sk --cert "$1.pem" --key "$1.key" --data-binary @r3.b64 \
        -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll" 2>/dev/null \
      | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null
}
DEVSTAT=$(enrol_with dev_c device.internal)
chk "the enrol GATE allows self-renewal (was 403)" yes \
    "$(grep -q 'allowing self-renewal' srv.log && echo yes || echo no)"
chk "  it issues under the VIRTUAL profile, not a stored one" yes \
    "$(grep -q 'virtual profile read off its own certificate' srv.log && echo yes || echo no)"
chk "  and the device gets a certificate -> 200" 200 "$DEVSTAT"
# Decode it. A 200 says the request was accepted; only the bytes say what was issued.
enrol_body dev_c device.internal > renewed.pem 2>/dev/null
chk "  the response really carries a certificate" yes \
    "$(grep -q 'BEGIN CERTIFICATE' renewed.pem && echo yes || echo no)"
chk "  issued for the SAME subject" yes \
    "$("$OSSL" x509 -in renewed.pem -noout -subject 2>/dev/null | grep -q 'CN *= *device.internal' && echo yes || echo no)"
RENEWED_TEXT=$("$OSSL" x509 -in renewed.pem -noout -text 2>/dev/null)

# ⚠️ THE CEILING, and it is the half that makes this safe. The virtual profile is built
# from the held certificate, so a renewal can only ever NARROW. Without these the two
# assertions above would pass just as well against a permissive stored profile — which is
# precisely the outcome that was rejected as too broad for a particular device.
#
# ⚠️ NO `date` ARITHMETIC. `date -j -f` is BSD-only and `date -d` is GNU-only; §3d says a
# suite runs unchanged on any box, and this one has to pass on the Mac AND in the Alpine
# image. `openssl x509 -checkend` answers the same question with no parsing: it exits
# non-zero when the certificate expires within N seconds.
SPAN=$(( 365 * 86400 ))          # CERT_VALIDITY_DAYS in the config above
"$OSSL" x509 -in renewed.pem -noout -checkend $(( SPAN + 3600 )) >/dev/null 2>&1
chk "  the renewal does not outlive the certificate it renews" 1 "$?"

# ⚠️ THE UPPER BOUND HERE IS THE CA, NOT CERT_VALIDITY_DAYS, and that is a real behaviour
# change rather than a weakened assertion. This suite's CA is deliberately minted for THREE
# DAYS, and a leaf may no longer outlive its issuer — so a 365-day request is clamped to the
# CA's own notAfter. The check that used to sit here asserted the renewal still had at least
# half of 365 days left, which could only ever have passed while a leaf was allowed to
# outlive its 3-day issuer by a year. That is exactly the defect the clamp removed: a
# certificate valid on its face and chainable by nobody.
#
# So assert the clamp itself — the leaf ends exactly when the CA does — which is a stronger
# statement than any "long enough" bound, and cannot be satisfied by a degenerate value.
CA_END=$("$OSSL" x509 -in ca.pem      -noout -enddate 2>/dev/null | cut -d= -f2)
RN_END=$("$OSSL" x509 -in renewed.pem -noout -enddate 2>/dev/null | cut -d= -f2)
chk "  ...and is clamped to the issuer's own notAfter" "$CA_END" "$RN_END"
# Anti-vacuity: if the fixture CA were long-lived the line above would pass with no
# clamping happening at all, and it would be a decoration.
"$OSSL" x509 -in ca.pem -noout -checkend $(( SPAN / 2 )) >/dev/null 2>&1
chk "  fixture: the CA really is shorter than the requested validity" 1 "$?"

# The device certificate carries serverAuth+clientAuth. Ask for an EKU it does NOT hold
# and the virtual profile must not grant it.
#
# ⚠️ ASSERT THE BYTES, NOT THE STATUS — I got this wrong first and the assertion went red
# against working code. evaluate_profile_extensions() is DROP-not-deny for KU/EKU: a
# requested purpose outside the allow-list is silently left off the certificate, not
# refused, so the request still returns 200. Testing for a 400 tests a refusal the product
# deliberately does not make; the question is what the issued certificate CARRIES.
eku_enrol() {   # <eku> -> issued PEM on stdout
    "$OSSL" req -new -subj "/CN=device.internal" -newkey rsa:2048 -nodes \
            -addext "extendedKeyUsage=$1" -keyout r4.key -out r4.csr >/dev/null 2>&1
    "$OSSL" req -in r4.csr -outform DER 2>/dev/null | "$OSSL" base64 > r4.b64
    curl -sk --cert dev_c.pem --key dev_c.key --data-binary @r4.b64 \
        -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll" 2>/dev/null \
      | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null \
      | "$OSSL" x509 -noout -text 2>/dev/null
}
# ⚠️ DATA-DRIVEN off the held certificate, not against names I expect to be there. My
# first version asserted serverAuth survives, and it went red against correct code: the
# slice 3 removed ServerAuth/ClientAuth from `requester`'s default EKU, so device.internal's
# certificate carries NO extended key usage at all — and a ceiling read off a certificate
# with no EKU correctly grants none. Hardcoding the expectation tested the CA's default
# profile, which is the exact thing this feature is supposed to stop mattering.
ekus_of() { "$OSSL" x509 -noout -text 2>/dev/null \
            | awk '/X509v3 Extended Key Usage/{getline; gsub(/^ +| +$/,""); print}'; }
EKU_HELD=$("$OSSL" x509 -in dev.pem -noout -text 2>/dev/null \
           | awk '/X509v3 Extended Key Usage/{getline; gsub(/^ +| +$/,""); print}')
EKU_REN=$(echo "$RENEWED_TEXT" | awk '/X509v3 Extended Key Usage/{getline; gsub(/^ +| +$/,""); print}')
chk "  the renewal carries EXACTLY the held certificate's EKU" "[$EKU_HELD]" "[$EKU_REN]"
EKU_NO=$(eku_enrol codeSigning)
chk "  asking for an EKU the held cert lacks does not add it" no \
    "$(echo "$EKU_NO" | grep -q 'Code Signing' && echo yes || echo no)"
chk "  ...and that request still produced a certificate" yes \
    "$(echo "$EKU_NO" | grep -q 'Subject:' && echo yes || echo no)"

# 2. THE LIMIT that makes it safe. The same certificate asking for a DIFFERENT name is
#    still refused — otherwise a compromised device certificate becomes a general
#    enrolment credential, which is the escalation the owner-role idea was rejected for.
chk "  but it may NOT enrol a different identity -> 403" 403 "$(enrol_with dev_c other.internal)"

# 3. THE LEVER. Revoking the device certificate ends the permission — the certs row is
#    exactly why this works, and why a certificate with no row must never qualify.
pg_exec "update certs set status=-1 where cn='device.internal';" >/dev/null
chk "  and once REVOKED it cannot renew either -> 403" 403 "$(enrol_with dev_c device.internal)"
pg_exec "update certs set status=0 where cn='device.internal';" >/dev/null

kill $SRV 2>/dev/null; wait $SRV 2>/dev/null

echo "=== Without anchors, EST does not ask for a certificate at all ==="
# The default posture, and it has to keep working: an operator who never sets
# EST_CLIENT_CA_ID gets Basic-over-TLS, not a broken listener.
grep -v '^EST_CLIENT_CA_ID=' bootstrap.conf > pki2.conf
"$ROOT/build/fastpki-est" --config pki2.conf >srv2.log 2>&1 & SRV=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$SRV" || true
kill -0 $SRV 2>/dev/null || { echo "fastpki-est died with no client CA:"; cat srv2.log; }
chk "it says so in the log"            yes \
    "$(grep -q 'authenticate with HTTP Basic over TLS' srv2.log && echo yes || echo no)"
"$OSSL" req -new -subj "/CN=nomtls.internal" -newkey rsa:2048 -keyout nk.pem -nodes -out nr.csr >/dev/null 2>&1
"$OSSL" req -in nr.csr -outform DER 2>/dev/null | "$OSSL" base64 > nr.b64
NM=$(curl -sk -o /dev/null -w '%{http_code}' -u alice:alicepw12 \
        --data-binary @nr.b64 -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll")
chk "  and Basic enrolment still works" 200 "$NM"
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null

echo
echo "=== EST mTLS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
