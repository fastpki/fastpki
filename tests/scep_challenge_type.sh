#!/usr/bin/env bash
# (HIGH, unauthenticated remote DoS): the SCEP challengePassword was read out of an
# ASN1_TYPE union WITHOUT checking the tag.
#
#     ASN1_TYPE* t = X509_ATTRIBUTE_get0_type(attr, 0);
#     if (!t || !t->value.asn1_string) return {};      // passes for a BOOLEAN
#     ASN1_STRING* s = t->value.asn1_string;           // reads value.boolean as a pointer
#
# Attribute parsing does not coerce a value to whatever the attribute's NID implies, so a
# challengePassword encoded as BOOLEAN puts an int (0xFF) where a pointer is expected. The
# non-null guard passes and ASN1_STRING_get0_data() dereferences it.
#
# ⚠️ IT IS PRE-AUTH. require_challenge is unconditional for a non-renewal PKCSReq, the CMS
# signer is self-signed and verified with CMS_NO_SIGNER_CERT_VERIFY, and GetCACert publishes
# the certificate to encrypt to. So anyone who could reach the port could restart the
# process at will, with no credential of any kind.
#
# ⚠️ THE CSR MUST BE VALIDLY SIGNED. `parse_csr` verifies the POP BEFORE the handler reads
# the attribute, so a CSR mutated after signing is rejected one step too early and proves
# nothing. `scep-testclient badcsr` builds the odd type and then signs normally —
# which is exactly the capability a real attacker has, since it is their own key.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
# seed_web_user / grant_profile / scep_challenge_for: the positive control at the end needs
# a per-user challengePassword the PRODUCT minted.
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF

W="$(mktemp -d)"; cd "$W"; PORT=18471
TC="$ROOT/build/scep-testclient"
pass=0; fail=0; P=
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=SCEP Type Confusion CA" 3650 sceptc \
    || { echo "SKIP: could not mint a CA key in a token"; exit 0; }
pg_setup scep_challenge_type
trap 'pg_cleanup; kill ${P:-} 2>/dev/null' EXIT
printf "internal\n" > domains.txt; seed_domains "$W/domains.txt"

cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=sceptc
PG_CONNINFO=$PG_CONNINFO
SCEP_BIND=127.0.0.1
SCEP_PORT=$PORT
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf
"$ROOT/build/fastpki-scep" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
chk "PRECONDITION: the SCEP server is up" yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"

# ⚠️ THE CA ID IN THE PATH MUST BE THE ONE THIS SUITE CREATED. Pointing at a CA that does
# not exist returns 404 — and a 404 arrives without the request ever reaching the parser,
# so "the server survived" would be true of a server that never looked at the payload. The
# first version of this suite did exactly that and scored 10/13 while proving nothing.
URL="http://127.0.0.1:$PORT/scep/sceptc"
# GetCACert is public — this is the step that hands an attacker what it needs.
curl -s "$URL?operation=GetCACert" -o ca_dl.der
"$OSSL" x509 -inform DER -in ca_dl.der -out ca_dl.pem 2>/dev/null || cp ca.pem ca_dl.pem
chk "PRECONDITION: GetCACert is reachable with no credential" yes \
    "$([ -s ca_dl.pem ] && echo yes || echo no)"

# The CMS signer: self-signed, never verified against anything.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout dev.key -subj "/CN=attacker.internal" \
        -x509 -days 2 -out client.pem >/dev/null 2>&1
chk "PRECONDITION: a self-signed CMS signer (no credential) exists" yes \
    "$([ -s client.pem ] && echo yes || echo no)"

"$TC" badcsr dev.key device.internal bad.der >/dev/null 2>&1
chk "PRECONDITION: a CSR with a BOOLEAN challengePassword was built" yes \
    "$([ -s bad.der ] && echo yes || echo no)"
# ⚠️ Prove it really carries a BOOLEAN, decoded from the bytes. Without this the suite
# would still pass if badcsr silently produced an ordinary string CSR — and it would then
# be asserting nothing at all.
chk "  and it decodes as a BOOLEAN, not a string" yes \
    "$("$OSSL" asn1parse -inform DER -in bad.der 2>/dev/null | grep -A3 ':challengePassword' \
       | grep -q 'BOOLEAN' && echo yes || echo no)"
# And that it is a VALID CSR — a broken POP would be refused before the parse we care about.
chk "  and its POP signature verifies" yes \
    "$("$OSSL" req -inform DER -in bad.der -verify -noout 2>&1 | grep -qi 'verify OK\|self-signature verify OK' && echo yes || echo no)"

# ⚠️ PROVE THE ROUTE EXISTS FIRST. Everything below is worthless against a 404.
chk "PRECONDITION: the PKIOperation route for this CA exists" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' "$URL?operation=GetCACaps")"

echo "=== the malformed challengePassword must NOT take the server down ==="
"$TC" build ca_dl.pem client.pem dev.key bad.der req.der >/dev/null 2>&1
CODE=$(curl -s -o resp.der -w '%{http_code}' -X POST --data-binary @req.der \
       -H "Content-Type: application/x-pki-message" "$URL?operation=PKIOperation")
# ⚠️ THE ASSERTION THAT MATTERS. Before the fix the process segfaults here, curl reports
# 000 (empty reply) and the server is gone.
chk "the server SURVIVES the request" yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"
chk "  and answered rather than dropping the connection" 200 "$CODE"
# It must refuse, not enrol: a value we cannot read as a password is not a password.
chk "  the CertRep says FAILURE" "pkiStatus=2" \
    "$("$TC" parse client.pem dev.key resp.der issued.der 2>/dev/null)"
chk "  and no certificate was issued for it" 0 \
    "$(pg_exec "select count(*) from certs where cn='device.internal';" | tr -d ' ')"

echo "=== and it still survives a SECOND one (not merely a lucky first) ==="
"$TC" build ca_dl.pem client.pem dev.key bad.der req2.der >/dev/null 2>&1
curl -s -o resp2.der -X POST --data-binary @req2.der \
     -H "Content-Type: application/x-pki-message" "$URL?operation=PKIOperation"
chk "the server is still up after a repeat" yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"

# ⚠️ ANTI-VACUITY. Everything above passes for a server that refuses EVERY PKCSReq, and it
# also passes for one that throws a STRING challengePassword away at the attribute parse —
# which is the failure this suite exists to prevent, in the other direction. So the string
# path is proved end to end, by VALUE:
#
#   a string the credential store does not know  -> CertRep FAILURE, and
#   a string that IS a per-user credential       -> CertRep SUCCESS, with a certificate.
#
# ⚠️ NOT BY GREPPING srv.log. That log is the server's whole stderr since startup, and the
# two BOOLEAN requests above already wrote "bad challengePassword" into it — so a grep for
# challenge/credential matched before this section ran at all, and passed even if this
# request never left the client. Worse, a parse refusal and a credential refusal log the
# SAME line, so no grep can tell the two apart. The pkiStatus and the certs row can.
echo "=== a normal string challengePassword still reaches the credential check ==="
printf '[req]\ndistinguished_name=dn\nattributes=at\nprompt=no\n[dn]\nCN=device.internal\n[at]\nchallengePassword=nosuchsecret\n' > good.cnf
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout dev2.key -config good.cnf -outform DER -out good.der >/dev/null 2>&1
"$OSSL" req -x509 -key dev2.key -subj "/CN=attacker2.internal" -days 2 -out client2.pem >/dev/null 2>&1
"$TC" build ca_dl.pem client2.pem dev2.key good.der req3.der >/dev/null 2>&1
curl -s -o resp3.der -X POST --data-binary @req3.der \
     -H "Content-Type: application/x-pki-message" "$URL?operation=PKIOperation"
chk "the server is up" yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"
chk "  an unknown string credential is refused (FAILURE, not a crash)" "pkiStatus=2" \
    "$("$TC" parse client2.pem dev2.key resp3.der issued3.der 2>/dev/null)"

# ...and the SAME string shape, carrying a credential the product itself minted, ENROLS.
# This is the half no refusal can fake: it can only pass if the challengePassword was read
# as a STRING and checked against the credential store. A server that type-filtered strings
# away, or that refused every PKCSReq, fails here.
# The credential is minted BY the product for a real web_users row holding an enrolling
# role — there is no deployment-wide SCEP challenge to set. Same two calls, in the same
# order, as tests/scep.sh and tests/scep_renewal.sh, which enrol successfully this way.
grant_profile scepdev requester
seed_web_user scepdev scepdevPW123456 requester >/dev/null 2>&1
SCEP_CH=$(scep_challenge_for scepdev)
chk "PRECONDITION: a per-user challengePassword was minted for scepdev" yes \
    "$(printf '%s' "$SCEP_CH" | grep -q '^scepdev:.' && echo yes || echo no)"
printf '[req]\ndistinguished_name=dn\nattributes=at\nprompt=no\n[dn]\nCN=good.internal\n[at]\nchallengePassword=%s\n' \
    "$SCEP_CH" > ok.cnf
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout dev3.key -config ok.cnf -outform DER -out ok.der >/dev/null 2>&1
"$OSSL" req -x509 -key dev3.key -subj "/CN=good.internal" -days 2 -out client3.pem >/dev/null 2>&1
"$TC" build ca_dl.pem client3.pem dev3.key ok.der req4.der >/dev/null 2>&1
curl -s -o resp4.der -X POST --data-binary @req4.der \
     -H "Content-Type: application/x-pki-message" "$URL?operation=PKIOperation"
chk "  a VALID string credential still enrols (so strings reach the credential check)" \
    "pkiStatus=0" "$("$TC" parse client3.pem dev3.key resp4.der issued4.der 2>/dev/null)"
chk "  and the certificate it asked for was issued" 1 \
    "$(pg_exec "select count(*) from certs where cn='good.internal';" | tr -d ' ')"

kill $P 2>/dev/null; wait $P 2>/dev/null; P=
echo
echo "=== SCEP CHALLENGE TYPE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
