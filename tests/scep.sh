#!/usr/bin/env bash
# SCEP (RFC 8894) server — fastpki-scep — end to end.
#   GetCACaps / GetCACert            -> caps + CA cert (DER)
#   PKIOperation (PKCSReq) good      -> CertRep pkiStatus=SUCCESS, issued cert
#   PKIOperation wrong challenge     -> CertRep pkiStatus=FAILURE
# The request/response CMS is built/parsed by scep-testclient; curl does
# the HTTP. Confirms the full SignedData(EnvelopedData(CSR)) round-trip and that
# issuance shares the pki_lib path (cert lands in certs.db, audited).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"   # per-CA RA cert into the DB
source "$ROOT/tests/user_helpers.sh"            # grant_profile
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
TC="$ROOT/build/scep-testclient"
W="$(mktemp -d)"; cd "$W"; PORT=18448
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=SCEP CA" 3650
cp ca.pem root.pem
pg_setup scep
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
SCEP_BIND=127.0.0.1
SCEP_PORT=$PORT
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-scep" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-scep died:"; cat srv.log; exit 1; fi
URL="http://127.0.0.1:$PORT/scep/ca"

echo "=== GetCACaps / GetCACert ==="
CAPS=$(curl -s "$URL?operation=GetCACaps")
echo "$CAPS" | grep -q "POSTPKIOperation" && a=yes || a=no
chk "advertises POSTPKIOperation" yes "$a"
echo "$CAPS" | grep -q "SHA-1" && a=yes || a=no
chk "SHA-1 gated off by default" no "$a"
echo "$CAPS" | grep -q "DES3" && a=yes || a=no
chk "DES3 gated off by default" no "$a"
CT=$(curl -s -D - "$URL?operation=GetCACert" -o cacert.der | grep -i "content-type" | tr -d '\r' | sed 's/.*: //')
chk "GetCACert content-type" "application/x-x509-ca-cert" "$CT"
"$OSSL" x509 -inform DER -in cacert.der -out ca_dl.pem >/dev/null 2>&1   # CA cert for the client
SUBJ=$("$OSSL" x509 -in ca_dl.pem -noout -subject 2>/dev/null | sed -n 's/.*CN *= *//p')
chk "GetCACert returns the CA cert" "SCEP CA" "${SUBJ:-none}"

# Build a device key + a CSR carrying challengePassword + a self-signed signer cert.
make_csr() { # $1 = challenge, $2 = CN (default device.internal) -> csr.der,
             # plus the shared dev.key + client.pem
    local cn=${2:-device.internal}
    cat > req.cnf <<EOF
[req]
distinguished_name = dn
attributes = attrs
prompt = no
[dn]
CN = $cn
[attrs]
challengePassword = $1
EOF
    "$OSSL" req -new -newkey rsa:2048 -nodes -keyout dev.key -config req.cnf -out dev.csr >/dev/null 2>&1
    "$OSSL" req -in dev.csr -outform DER -out csr.der >/dev/null 2>&1
    # The SIGNER cert keeps a fixed name — it authenticates the CMS envelope and has
    # nothing to do with what the CSR asks for. Putting a wildcard here instead would
    # make `openssl req -x509` produce something no client would ever hold.
    "$OSSL" req -x509 -key dev.key -subj "/CN=device.internal" -days 2 -out client.pem >/dev/null 2>&1
}

# ⚠️ The SHARED-challenge path still resolves an identity (`owner='scep'`),
# and that identity now needs a profile grant — an empty union refuses. The grant used to
# appear only at the dynamic-token section further down, so every enrolment before it was
# refused. It is idempotent, so the later grant_profile calls still do their job.
grant_profile scep requester
# There is no deployment-wide SCEP_CHALLENGE any more, so the value every CSR below
# carries is the PER-USER credential minted for the `scep` user. Seeding it as a real
# web_users row is also what keeps the `owner='scep'` assertions below meaning what they
# always meant: scep_kid_user("scep:scep") is "scep".
seed_web_user scep scepPW123456 requester >/dev/null 2>&1
SCEP_CH=$(scep_challenge_for scep)
# ⚠️ PRECONDITION, because an empty challenge would be refused and every assertion below
# would then be measuring "SCEP refuses an empty secret" while claiming to measure
# issuance, RA mode, manual approval and weak-algorithm opt-in.
chk "PRECONDITION: the scep user has a per-user challengePassword" yes \
    "$(printf '%s' "$SCEP_CH" | grep -q '^scep:.' && echo yes || echo no)"

echo "=== PKIOperation: PKCSReq with correct challenge ==="
make_csr "$SCEP_CH"
"$TC" build ca_dl.pem client.pem dev.key csr.der req.der
RC=$?; chk "client built request" 0 "$RC"
curl -s -X POST --data-binary @req.der -H "Content-Type: application/x-pki-message" \
    "$URL?operation=PKIOperation" -o resp.der
ST=$("$TC" parse client.pem dev.key resp.der issued.der); RC=$?
chk "CertRep pkiStatus=SUCCESS" "pkiStatus=0" "$ST"
chk "parse exit 0" 0 "$RC"
ISUBJ=$("$OSSL" x509 -inform DER -in issued.der -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')
chk "issued cert CN = device.internal" "device.internal" "${ISUBJ:-none}"
IISS=$("$OSSL" x509 -inform DER -in issued.der -noout -issuer 2>/dev/null | sed -n 's/.*CN *= *//p')
chk "issued by SCEP CA" "SCEP CA" "${IISS:-none}"
NDB=$(pg_exec "SELECT COUNT(*) FROM certs WHERE owner='scep';")
chk "issued cert persisted in certs.db" 1 "$NDB"
# The row must NOT claim a role the caller never held. A SCEP client authenticates
# with a challenge, not a console user, so there was no role to record -- and the value it
# used to write, "standard", was a CERT PROFILE name, a different vocabulary from the
# console roles this same column carried on the EST path.
#
# ⚠️ The assertion that used to stand here is GONE, not moved: certs.role was dropped
# entirely, so `SELECT role FROM certs` now errors and returns empty — which compares equal
# to the empty string it expected and would have gone on "passing" while testing nothing.
# The mismatch it guarded cannot recur, because there is no column to disagree about.
NAUD=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='cert_issued' AND detail LIKE '%SCEP%';")
chk "issuance audited" 1 "$NAUD"

echo "=== EC devices enrol over SCEP — P-256 AND P-384 ==="
# EC P-256 and EC P-384 are skipped for the same reason the other key types are
# skipped for SCEP — CMS. Only RSA keys can be used for encryption.
#
# ⚠️ MEASURED, NOT REASONED — and it does not hold. In SCEP the requester's key never does
# key transport: it SIGNS the pkiMessage, and the CertRep comes back enveloped TO the
# requester's certificate, which OpenSSL's CMS layer opens with ECDH key AGREEMENT
# (RFC 5753). Key transport is the RSA-only mechanism and it is on the CA's side of the
# request envelope, not the client's. Ed25519 and ML-DSA are skipped because they can
# neither sign CMS the way SCEP needs nor agree a key — that gap is real, and EC is not
# in it.
#
# P-384 was covered NOWHERE until this loop: this suite did P-256 only, and the bench
# reported 0/50 for every key type for an unrelated reason (no
# challengePassword at all). So the one place the claim could have been checked was
# reporting a failure with a different cause.
for eccurve in prime256v1 secp384r1; do
  eclabel=$(echo "$eccurve" | sed 's/prime256v1/P-256/; s/secp384r1/P-384/')
  cat > ecreq.cnf <<EOF
[req]
distinguished_name = dn
attributes = attrs
prompt = no
[dn]
CN = ecdev-$eccurve.internal
[attrs]
challengePassword = $SCEP_CH
EOF
  "$OSSL" ecparam -name "$eccurve" -genkey -noout -out ecdev.key >/dev/null 2>&1
  "$OSSL" req -new -key ecdev.key -config ecreq.cnf -out ecdev.csr >/dev/null 2>&1
  "$OSSL" req -in ecdev.csr -outform DER -out eccsr.der >/dev/null 2>&1
  "$OSSL" req -x509 -key ecdev.key -subj "/CN=ecdev-$eccurve.internal" -days 2 -out ecclient.pem >/dev/null 2>&1
  "$TC" build ca_dl.pem ecclient.pem ecdev.key eccsr.der ecreq.der >/dev/null 2>&1
  curl -s -X POST --data-binary @ecreq.der -H "Content-Type: application/x-pki-message" \
      "$URL?operation=PKIOperation" -o ecresp.der
  rm -f ecissued.der
  ECST=$("$TC" parse ecclient.pem ecdev.key ecresp.der ecissued.der 2>/dev/null)
  ECT=$("$OSSL" x509 -inform DER -in ecissued.der -text -noout 2>/dev/null)
  # The CertRep status is asserted separately from the certificate: "no cert" and "a cert
  # that decoded wrong" are different failures and used to collapse into one.
  chk "EC $eclabel: the CertRep says SUCCESS"        "pkiStatus=0" "$ECST"
  chk "EC $eclabel: device cert issued"              yes "$(echo "$ECT" | grep -qi 'id-ecPublicKey' && echo yes || echo no)"
  # ⚠️ NAME THE CURVE. Without this, a server that silently issued a P-256 cert for a
  # P-384 request would pass every other line here — "id-ecPublicKey" is true of both.
  chk "EC $eclabel: the issued SPKI really is $eclabel" yes \
      "$(echo "$ECT" | grep -qi "NIST CURVE: $eclabel" && echo yes || echo no)"
  chk "EC $eclabel: KeyUsage has no Key Encipherment" yes "$(echo "$ECT" | grep -qi 'Key Encipherment' && echo no || echo yes)"
done

echo "=== PKIOperation: wrong challenge -> FAILURE ==="
make_csr WRONGpw
"$TC" build ca_dl.pem client.pem dev.key csr.der req2.der >/dev/null
curl -s -X POST --data-binary @req2.der -H "Content-Type: application/x-pki-message" \
    "$URL?operation=PKIOperation" -o resp2.der
ST2=$("$TC" parse client.pem dev.key resp2.der issued2.der); RC2=$?
chk "wrong challenge -> pkiStatus=FAILURE" "pkiStatus=2" "$ST2"
chk "parse exit 2 (non-success)" 2 "$RC2"

echo "=== A request with NO challengePassword is refused ==="
# ⚠️ THIS SECTION USED TO NEED ITS OWN SERVER, started from a config with the shared
# challenge stripped out — because the dangerous combination was "no shared challenge and
# no dynamic tokens", which turned out to set require_challenge=false and enrol ANYONE.
#
# Deleted the shared challenge outright, so that configuration is no longer something
# an operator can reach: it is simply what every deployment is. The second server is gone
# with it and the assertion runs against the instance above, which is now exactly the
# configuration that used to be the hole.
#
# What is left to prove is the rule itself: an empty challengePassword is refused, and
# refused as POLICY — a CertRep with pkiStatus=FAILURE — not by crashing or by issuing.
make_csr ""
"$TC" build ca_dl.pem client.pem dev.key csr.der req_nc.der >/dev/null
curl -s -X POST --data-binary @req_nc.der -H "Content-Type: application/x-pki-message" \
    "$URL?operation=PKIOperation" -o resp_nc.der
rm -f issued_nc.der
STNC=$("$TC" parse client.pem dev.key resp_nc.der issued_nc.der)
chk "an empty challengePassword -> FAILURE" "pkiStatus=2" "$STNC"
chk "  and NO certificate was issued"       no \
    "$([ -s issued_nc.der ] && echo yes || echo no)"
# ⚠️ ANTI-VACUITY. "refused" is also what a broken request, a dead server or a bad client
# produces. The SAME client and the SAME CSR machinery with a REAL credential must still
# enrol, or this section proves nothing about the challenge rule.
make_csr "$SCEP_CH" control-empty-chal.internal
"$TC" build ca_dl.pem client.pem dev.key csr.der req_ctl.der >/dev/null
curl -s -X POST --data-binary @req_ctl.der -H "Content-Type: application/x-pki-message" \
    "$URL?operation=PKIOperation" -o resp_ctl.der
chk "  CONTROL: the same client WITH a credential still enrols" "pkiStatus=0" \
    "$("$TC" parse client.pem dev.key resp_ctl.der issued_ctl.der 2>/dev/null)"

echo "=== dynamic one-time challenge tokens ==="
PORT2=18449
cat > dyn.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
SCEP_BIND=127.0.0.1
SCEP_PORT=$PORT2
SCEP_DYNAMIC_CHALLENGE=true
LOG_LEVEL=err
EOF
seed_ca_from_conf dyn.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-scep" --config dyn.conf >dyn.log 2>&1 & P2=$!
sleep 1; trap 'kill $P $P2 2>/dev/null' EXIT
URL2="http://127.0.0.1:$PORT2/scep/ca"

# ⚠️ The profile on a token is now USED, so it has to be one the SCEP identity
# is actually entitled to. This used to ask for the profile `webvpn` — a name no profile has — and
# it passed because the value was read from the database and then discarded at the call
# site. It is granted here, which is what makes the assertions below mean anything.
# TWO profiles in the union (the priority-ordered assignment table was replaced with the
# set of `profile:use` grants the identity's roles carry). Two is the point, not padding:
# with a single member, `resolve_profile` would answer it implicitly and the token could
# never differ from the no-token answer, so an assertion could not tell the fix from the
# bug. With two, there IS no implicit answer and only the token can choose.
grant_profile scep requester
grant_profile scep admin
UNION=$(pg_exec "SELECT count(*) FROM role_permissions p JOIN subject_roles s ON s.role=p.role
                  WHERE s.selector_value='scep' AND p.permission='profile:use';")
chk "PRECONDITION: the scep identity's profile union has 2 members" 2 "$UNION"
TOKEN=$("$ROOT/build/fastpki-scep" --config dyn.conf --issue-challenge admin --ttl 3600 2>/dev/null)
chk "minted a challenge token" yes "$([ -n "$TOKEN" ] && echo yes || echo no)"
# Minting for a profile the identity cannot use must fail HERE, not at enrolment time
# three weeks later on a device nobody is watching.
# ⚠️ The precondition above is what stops this passing vacuously: an EMPTY union refuses
# every name, so the refusal below would hold without the check it is about.
BADTOK=$("$ROOT/build/fastpki-scep" --config dyn.conf --issue-challenge no-such-profile --ttl 3600 2>/dev/null)
chk "  a profile the identity cannot use is REFUSED at mint" "" "${BADTOK}"
enroll_dyn() { # challenge outfile -> pkiStatus line
    make_csr "$1"
    "$TC" build ca_dl.pem client.pem dev.key csr.der "$2.der" >/dev/null
    curl -s -X POST --data-binary @"$2.der" -H "Content-Type: application/x-pki-message" \
        "$URL2?operation=PKIOperation" -o "$2.resp" 2>/dev/null
    "$TC" parse client.pem dev.key "$2.resp" "$2.issued" 2>/dev/null
}
chk "valid dynamic token -> SUCCESS" "pkiStatus=0" "$(enroll_dyn "$TOKEN" d1)"
chk "reused token -> FAILURE (one-time)" "pkiStatus=2" "$(enroll_dyn "$TOKEN" d2)"
ETOKEN=$("$ROOT/build/fastpki-scep" --config dyn.conf --issue-challenge expired --ttl -10 2>/dev/null)
chk "expired token -> FAILURE" "pkiStatus=2" "$(enroll_dyn "$ETOKEN" d3)"
chk "unknown token -> FAILURE" "pkiStatus=2" "$(enroll_dyn "never-minted" d4)"
# the used token is marked consumed in the DB
USED=$(pg_exec "SELECT used FROM scep_challenges WHERE token='$TOKEN';")
chk "consumed token flagged used=1" 1 "$USED"

echo "=== the profile a token was minted for actually reaches issuance ==="
# The profile was written by --issue-challenge, returned by consume_scep_challenge(), and then
# DISCARDED at the call site — `.has_value()` and nothing else. A reader with no writer,
# in the direction that matters: a one-time token could not constrain what it issued,
# which is the only thing that made it different from the shared secret.
#
# `admin` allows wildcards, `requester` does not (cert_profile.cpp: allow_wildcard is
# is_admin). So a wildcard CN is a visible, decoded difference between the two —
# not a log line or a status code.
WTOKEN=$("$ROOT/build/fastpki-scep" --config dyn.conf --issue-challenge admin --ttl 3600 2>/dev/null)
chk "minted an admin token" yes "$([ -n "$WTOKEN" ] && echo yes || echo no)"
make_csr "$WTOKEN" '*.internal'
"$TC" build ca_dl.pem client.pem dev.key csr.der w1.der >/dev/null
curl -s -X POST --data-binary @w1.der -H "Content-Type: application/x-pki-message" \
    "$URL2?operation=PKIOperation" -o w1.resp 2>/dev/null
chk "an admin token issues a WILDCARD" "pkiStatus=0" \
    "$("$TC" parse client.pem dev.key w1.resp w1.issued 2>/dev/null)"
chk "  and the issued cert really is the wildcard" yes \
    "$("$OSSL" x509 -inform DER -in w1.issued -noout -subject 2>/dev/null | grep -q '\*.internal' && echo yes || echo no)"
# ⚠️ THE CONTRAST. A token minted for `requester`, which forbids wildcards, from the same
# identity. Without this the assertion above would pass just as well against a build that
# ignores the token's profile. (A token minted with NO profile is no contrast any more: the
# identity holds both, so a request naming none gets their merge, and `admin` allows
# wildcards.)
NTOKEN=$("$ROOT/build/fastpki-scep" --config dyn.conf --issue-challenge requester --ttl 3600 2>/dev/null)
make_csr "$NTOKEN" '*.internal'
"$TC" build ca_dl.pem client.pem dev.key csr.der w2.der >/dev/null
W2=$(curl -s -o w2.resp -w '%{http_code}' -X POST --data-binary @w2.der \
     -H "Content-Type: application/x-pki-message" "$URL2?operation=PKIOperation" 2>/dev/null)
# (FIXED): this used to assert HTTP 400. A policy refusal was thrown as pki::Error(1)
# and rendered as a transport status, so a SCEP client reported a network problem for a
# decision this CA made deliberately — and the two refusal paths in the same handler
# disagreed, since a bad challengePassword already returned a signed CertRep. It is now a
# CertRep with pkiStatus=2 and a failInfo, so the transport is 200.
chk "a requester token does NOT" 200 "$W2"
chk "  the refusal is a signed CertRep, pkiStatus=2" "pkiStatus=2" \
    "$("$TC" parse client.pem dev.key w2.resp w2.issued 2>/dev/null)"
# ⚠️ pkiStatus=2 alone is what the bad-challenge path already returned, so it cannot tell a
# policy refusal from any other failure. The failInfo is the part that matters: decode the
# attribute out of the CMS rather than trusting the status. 2.16.840.1.113733.1.9.4 is
# id-scep-failInfo; the value is a PrintableString "2" = badRequest (RFC 8894 3.2.1.4).
chk "  ...carrying failInfo=2 (badRequest)" yes \
    "$("$OSSL" asn1parse -inform DER -in w2.resp 2>/dev/null |
       grep -A 3 '2.16.840.1.113733.1.9.4' | grep -q ':2$' && echo yes || echo no)"
chk "  and nothing wildcard was issued" 0 \
    "$(pg_exec "select count(*) from certs where cn like '%*%' and serial <> (select serial from certs where cn like '%*%' order by \"notBefore\" desc limit 1);" | tr -d ' ')"

# ⚠️ Give the union back its single member before anything else runs. The two grants above
# exist so the token has something to CHOOSE; with both in place every later section here
# — manual approval, GetCertInitial, the no-identity path — enrols without naming a profile
# and gets the MERGE of `requester` and `admin`, whose default key usages differ with no
# primary-role member to decide, so a CSR that asks for none is refused. That is the product
# behaving as designed, and worth knowing: SCEP has no field to name a profile outside a
# dynamic token, so a SCEP identity holding two profiles that disagree on a default needs its
# devices to ask for their key usages.
ungrant_profile scep admin

echo "=== A PER-USER challengePassword, gated by scep:enrol ==="
# SCEP had one shared SCEP_CHALLENGE for the whole deployment, so the downloadable
# client config could carry no credential at all without handing every user the
# deployment secret. Per-user credentials were chosen over substituting the shared value,
# as the more secure option that still does not break the SCEP RFC.
#
# Nothing about RFC 8894 changes — the challengePassword is a PKCS#9 attribute in the
# CSR and the RFC never said its value had to be shared. What changes is that the value
# now NAMES someone, which is the identity SCEP has never had, and is what makes
# scep:enrol enforceable instead of decorative (it was deleted in step 0009 for exactly
# that reason).
SU_SECRET='dGVzdC1zY2VwLXNlY3JldC1mb3ItMjM3LWFzc2VydGlvbnM'
# ⚠️ `hash` is NOT NULL with no default. My first version omitted it, the INSERT failed
# silently behind >/dev/null, and bob had NO web_users row — so may_enrol saw an empty
# role, took its "not a console role" bypass (`if (known.empty()) return true`), and the
# gate assertion below passed for a build with no gate at all. An empty string is a legal
# hash here: this identity authenticates with a challengePassword, and an empty hash
# cannot verify, so the row does not become a second way in.
pg_exec "INSERT INTO web_users(username,role,hash,created) VALUES('bob','requester','',0) ON CONFLICT (username) DO UPDATE SET role='requester';" >/dev/null
pg_exec "INSERT INTO keys(kid,protocol,key) VALUES('bob','scep','$SU_SECRET') ON CONFLICT (kid,protocol) DO UPDATE SET key='$SU_SECRET';" >/dev/null
# Assert the whole fixture TOOK. Each of these three is something whose absence makes the
# gate inert rather than failing, which is the only way this block can lie.
chk "bob has a web_users row"                1 \
    "$(pg_exec "select count(*) from web_users where username='bob' and role='requester';" | tr -d ' ')"
chk "bob has a SCEP credential"              1 \
    "$(pg_exec "select count(*) from keys where kid='bob' and protocol='scep';" | tr -d ' ')"
chk "bob holds scep:enrol through requester" 1 \
    "$(pg_exec "select count(*) from role_permissions where role='requester' and permission='scep:enrol';" | tr -d ' ')"
make_csr "bob:$SU_SECRET" bob-device.internal
"$TC" build ca_dl.pem client.pem dev.key csr.der pu1.der >/dev/null
curl -s -X POST --data-binary @pu1.der -H "Content-Type: application/x-pki-message" \
    "$URL?operation=PKIOperation" -o pu1.resp 2>/dev/null
chk "a per-user challenge enrols" "pkiStatus=0" \
    "$("$TC" parse client.pem dev.key pu1.resp pu1.issued 2>/dev/null)"
# ⚠️ THE POINT of an identity: the row records WHO, not the literal string "scep".
# Without this the credential would be a second password with no accountability.
chk "  and the certificate is recorded against bob" 1 \
    "$(pg_exec "select count(*) from certs where cn='bob-device.internal' and owner='bob';" | tr -d ' ')"
chk "  not against the anonymous scep identity"     0 \
    "$(pg_exec "select count(*) from certs where cn='bob-device.internal' and owner='scep';" | tr -d ' ')"

# THE GATE. Revoke scep:enrol from requester and the same credential stops working.
pg_exec "DELETE FROM role_permissions WHERE role='requester' AND permission='scep:enrol';" >/dev/null
make_csr "bob:$SU_SECRET" bob-device2.internal
"$TC" build ca_dl.pem client.pem dev.key csr.der pu2.der >/dev/null
curl -s -X POST --data-binary @pu2.der -H "Content-Type: application/x-pki-message" \
    "$URL?operation=PKIOperation" -o pu2.resp 2>/dev/null
chk "revoking scep:enrol stops that user" "pkiStatus=2" \
    "$("$TC" parse client.pem dev.key pu2.resp pu2.issued 2>/dev/null)"
chk "  and nothing was issued"            0 \
    "$(pg_exec "select count(*) from certs where cn='bob-device2.internal';" | tr -d ' ')"
# ⚠️ ANTI-VACUITY, and it is the half that matters most here. The ruling is that SCEP stays open
# for DEVICES, and the gate must not have quietly closed that. This used to be asserted
# with the shared SCEP_CHALLENGE, which named nobody and so had nothing to authorize.
# Removed that value, so the no-user path is now the one-time dynamic token — and it
# is asserted in the no-identity section below, which needs a server that accepts tokens.
# A wrong secret under a real kid must fail, or the kid alone would be the credential.
make_csr "bob:wrong-secret-entirely" bob-device3.internal
"$TC" build ca_dl.pem client.pem dev.key csr.der pu4.der >/dev/null
curl -s -X POST --data-binary @pu4.der -H "Content-Type: application/x-pki-message" \
    "$URL?operation=PKIOperation" -o pu4.resp 2>/dev/null
chk "a wrong secret under a real kid fails" "pkiStatus=2" \
    "$("$TC" parse client.pem dev.key pu4.resp pu4.issued 2>/dev/null)"
pg_exec "INSERT INTO role_permissions(role, permission, scope) VALUES('requester','scep:enrol','*') ON CONFLICT DO NOTHING;" >/dev/null

echo "=== GetCert: fetch an issued cert by issuer+serial ==="
# Reuse the cert issued by the very first PKCSReq (device.internal, on $URL).
SER=$("$OSSL" x509 -inform DER -in issued.der -noout -serial | sed 's/serial=//')
"$TC" getcert ca_dl.pem client.pem dev.key ca_dl.pem "$SER" gc.der
curl -s -X POST --data-binary @gc.der -H "Content-Type: application/x-pki-message" \
    "$URL?operation=PKIOperation" -o gc.resp
GST=$("$TC" parse client.pem dev.key gc.resp gc.out); GRC=$?
chk "GetCert known serial -> SUCCESS" "pkiStatus=0" "$GST"
GCN=$("$OSSL" x509 -inform DER -in gc.out -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')
chk "GetCert returns the right cert" "device.internal" "${GCN:-none}"
"$TC" getcert ca_dl.pem client.pem dev.key ca_dl.pem deadbeef gcm.der
curl -s -X POST --data-binary @gcm.der -H "Content-Type: application/x-pki-message" \
    "$URL?operation=PKIOperation" -o gcm.resp
chk "GetCert unknown serial -> FAILURE" "pkiStatus=2" "$("$TC" parse client.pem dev.key gcm.resp gcm.out)"

echo "=== GetCRL: fetch the CA CRL ==="
# Revoke the issued cert, then the CRL must list its serial.
SERLC=$(printf '%s' "$SER" | tr 'A-Z' 'a-z' | sed 's/^0*//')
pg_exec "UPDATE certs SET status=-1, \"revocationReason\"=0, \"revocationDate\"=$(date +%s) WHERE serial='$SERLC';"
"$TC" getcrl ca_dl.pem client.pem dev.key ca_dl.pem crl.req
curl -s -X POST --data-binary @crl.req -H "Content-Type: application/x-pki-message" \
    "$URL?operation=PKIOperation" -o crl.resp
CST=$("$TC" parsecrl client.pem dev.key crl.resp out.crl);
chk "GetCRL -> SUCCESS" "pkiStatus=0" "$CST"
"$OSSL" crl -inform DER -in out.crl -CAfile ca_dl.pem -noout 2>crlverify.txt && cv=ok || cv=bad
chk "CRL is CA-signed" "ok" "$cv"
"$OSSL" crl -inform DER -in out.crl -noout -text 2>/dev/null | grep -qi "$SERLC" && lst=yes || lst=no
chk "revoked serial listed in CRL" yes "$lst"

echo "=== manual approval: PENDING -> approve -> GetCertInitial ==="
PORT3=18450
cat > man.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
SCEP_BIND=127.0.0.1
SCEP_PORT=$PORT3
SCEP_MANUAL_APPROVAL=true
LOG_LEVEL=err
EOF
seed_ca_from_conf man.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-scep" --config man.conf >man.log 2>&1 & P3=$!
sleep 1; trap 'kill $P $P2 $P3 2>/dev/null' EXIT
URL3="http://127.0.0.1:$PORT3/scep/ca"

make_csr "$SCEP_CH"
MTXID=$("$TC" build ca_dl.pem client.pem dev.key csr.der m1.der)
curl -s -X POST --data-binary @m1.der -H "Content-Type: application/x-pki-message" \
    "$URL3?operation=PKIOperation" -o m1.resp
chk "PKCSReq under manual approval -> PENDING" "pkiStatus=3" "$("$TC" parse client.pem dev.key m1.resp m1.out)"
NPEND=$(pg_exec "SELECT COUNT(*) FROM scep_pending WHERE txid='$MTXID' AND status=0;")
chk "request parked pending in DB" 1 "$NPEND"
# poll before approval -> still PENDING
"$TC" getcertinitial ca_dl.pem client.pem dev.key "$MTXID" gci1.der
curl -s -X POST --data-binary @gci1.der -H "Content-Type: application/x-pki-message" \
    "$URL3?operation=PKIOperation" -o gci1.resp
chk "GetCertInitial before approval -> PENDING" "pkiStatus=3" "$("$TC" parse client.pem dev.key gci1.resp gci1.out)"
# operator lists + approves
LISTED=$("$ROOT/build/fastpki-scep" --config man.conf --list-pending 2>/dev/null | grep -c "$MTXID")
chk "operator sees it in --list-pending" 1 "$LISTED"
ASER=$("$ROOT/build/fastpki-scep" --config man.conf --ca ca --approve "$MTXID" 2>/dev/null)
chk "approve mints a serial" yes "$([ -n "$ASER" ] && echo yes || echo no)"
# poll after approval -> SUCCESS with the issued cert
"$TC" getcertinitial ca_dl.pem client.pem dev.key "$MTXID" gci2.der
curl -s -X POST --data-binary @gci2.der -H "Content-Type: application/x-pki-message" \
    "$URL3?operation=PKIOperation" -o gci2.resp
GIST=$("$TC" parse client.pem dev.key gci2.resp gci2.out);
chk "GetCertInitial after approval -> SUCCESS" "pkiStatus=0" "$GIST"
GICN=$("$OSSL" x509 -inform DER -in gci2.out -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')
chk "issued cert delivered on poll" "device.internal" "${GICN:-none}"

echo "=== manual approval: reject path ==="
make_csr "$SCEP_CH"
RTXID=$("$TC" build ca_dl.pem client.pem dev.key csr.der r1.der)
curl -s -X POST --data-binary @r1.der -H "Content-Type: application/x-pki-message" \
    "$URL3?operation=PKIOperation" -o r1.resp >/dev/null
"$TC" parse client.pem dev.key r1.resp r1.out >/dev/null
"$ROOT/build/fastpki-scep" --config man.conf --reject "$RTXID" 2>/dev/null
"$TC" getcertinitial ca_dl.pem client.pem dev.key "$RTXID" rgci.der
curl -s -X POST --data-binary @rgci.der -H "Content-Type: application/x-pki-message" \
    "$URL3?operation=PKIOperation" -o rgci.resp
chk "GetCertInitial on rejected txid -> FAILURE" "pkiStatus=2" "$("$TC" parse client.pem dev.key rgci.resp rgci.out)"
RSTATUS=$(pg_exec "SELECT status FROM scep_pending WHERE txid='$RTXID';")
chk "rejected request flagged status=2" 2 "$RSTATUS"

echo "=== RA mode: separate RA cert + x-x509-ca-ra-cert chain ==="
# RA cert signed by the CA. The shape here must be the shape the CONSOLE issues, or this
# suite proves SCEP works with *a* certificate rather than with *the* one an operator gets.
# Two properties, both deliberate:
#
#   keyEncipherment — a SCEP client ENCRYPTS the PKIOperation envelope to the RA, and
#     fastpki-scep calls CMS_decrypt with this key. That is also why the key is RSA:
#     key_can_encipher() accepts RSA/RSA-PSS only, so an EC RA would be issued happily
#     and then fail at the first enrolment.
#   CEP (1.3.6.1.4.1.311.20.2.1) — SCEP carries the CEP EKU,
#     NOT id-kp-cmcRA (that OID is CMP's, RFC 9810 §8.6) and NOT clientAuth, which this
#     suite used to mint and the console has never offered for this role.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout ra.key -subj "/CN=SCEP RA" -out ra.csr >/dev/null 2>&1
cat > ra.ext <<EOF
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = 1.3.6.1.4.1.311.20.2.1
EOF
"$OSSL" x509 -req -in ra.csr -CA ca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS -CAcreateserial -days 365 \
    -extfile ra.ext -out ra.pem >/dev/null 2>&1
# ⚠️ Assert what was just minted, so test and product cannot drift apart again silently.
# The previous value (clientAuth) passed for years against a shape the console never
# produced — a suite that agrees with itself rather than with the product.
RAT=$("$OSSL" x509 -in ra.pem -noout -text 2>/dev/null)
chk "the RA cert carries the CEP EKU the console issues" yes \
    "$(printf '%s' "$RAT" | grep -qE '1\.3\.6\.1\.4\.1\.311\.20\.2\.1|Certificate Request Agent' && echo yes || echo no)"
chk "  and NOT clientAuth, which this role never had" no \
    "$(printf '%s' "$RAT" | grep -q 'TLS Web Client Authentication' && echo yes || echo no)"
chk "  and keeps keyEncipherment (it decrypts the envelope)" yes \
    "$(printf '%s' "$RAT" | grep -q 'Key Encipherment' && echo yes || echo no)"

PORT4=18451
cat > ra.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
SCEP_BIND=127.0.0.1
SCEP_PORT=$PORT4
SCEP_RA_KEY=$W/ra.key
LOG_LEVEL=err
EOF
seed_ca_from_conf ra.conf   # register the CA (SIGNING_CA_* no longer seed it)
# SCEP_RA_CERT is gone. The RA certificate is PER CA and lives in the DB under
# cert_id "<SCEP_RA_CERT_ID_PREFIX>-<ca_id>" — same shape as the CMP RA and the OCSP
# responder, because an RA fronting CA 'ca' must be certified by 'ca'.
service_cert_publish "$W/ra.pem" ca scep-ra
"$ROOT/build/fastpki-scep" --config ra.conf >ra.log 2>&1 & P4=$!
sleep 1; trap 'kill $P $P2 $P3 $P4 2>/dev/null' EXIT
URL4="http://127.0.0.1:$PORT4/scep/ca"

RACT=$(curl -s -D - "$URL4?operation=GetCACert" -o raca.p7 | grep -i "content-type" | tr -d '\r' | sed 's/.*: //')
chk "GetCACert RA content-type" "application/x-x509-ca-ra-cert" "$RACT"
NCERTS=$("$OSSL" pkcs7 -inform DER -in raca.p7 -print_certs 2>/dev/null | grep -c "BEGIN CERTIFICATE")
chk "GetCACert returns RA+CA chain (2 certs)" 2 "$NCERTS"
"$OSSL" pkcs7 -inform DER -in raca.p7 -print_certs 2>/dev/null | grep -q "CN *= *SCEP RA" && hasra=yes || hasra=no
chk "chain includes the RA cert" yes "$hasra"
# Enrol: the client encrypts the PKIOperation envelope to the RA cert.
make_csr "$SCEP_CH"
"$TC" build ra.pem client.pem dev.key csr.der rareq.der >/dev/null
curl -s -X POST --data-binary @rareq.der -H "Content-Type: application/x-pki-message" \
    "$URL4?operation=PKIOperation" -o raresp.der
RAST=$("$TC" parse client.pem dev.key raresp.der raissued.der)
chk "RA-mode enrollment -> SUCCESS" "pkiStatus=0" "$RAST"
RAISS=$("$OSSL" x509 -inform DER -in raissued.der -noout -issuer 2>/dev/null | sed -n 's/.*CN *= *//p')
chk "RA-mode cert issued by the CA" "SCEP CA" "${RAISS:-none}"

echo "=== The RA credential is PER CA, from the DB — not a config file ==="
# ⚠️ THE POINT. SCEP_RA_CERT named ONE PEM file for the whole instance. An RA fronting
# CA 'a' must be certified by 'a', so on a multi-CA instance one file is right for at
# most one of them — the same argument RFC 6960 §4.2.2.2 makes for the OCSP responder
# and that the CMP RA made. The certificate now lives in `certs` under
# cert_id "<SCEP_RA_CERT_ID_PREFIX>-<ca_id>" and is resolved PER REQUEST.
chk "SCEP_RA_CERT is no longer a config key the parser accepts" no \
    "$(grep -q 'SCEP_RA_CERT[^_]' "$ROOT/src/lib/config.cpp" && echo yes || echo no)"

# Revoking the row must take the RA offline WITHOUT a restart — that is what "resolved
# per request" buys, and it is the half that a startup-load design cannot do.
pg_exec "UPDATE certs SET status=1 WHERE cert_id='scep-ra-ca' AND status=0;" >/dev/null 2>&1
RC=$(curl -s -o /dev/null -w '%{http_code}' "$URL4?operation=GetCACert")
chk "a revoked RA certificate takes SCEP down, no restart" 503 "$RC"
grep -qi "scep-ra-ca" ra.log && named=yes || named=no
chk "  and the log names the cert_id to fix" yes "$named"
# Restore it and prove recovery is equally live — a refusal that never clears would be
# just as broken as one that never fires.
service_cert_publish "$W/ra.pem" ca scep-ra
RC=$(curl -s -o /dev/null -w '%{http_code}' "$URL4?operation=GetCACert")
chk "republishing brings it straight back, no restart" 200 "$RC"

echo "=== the RA key can live IN THE TOKEN, not only in a file ==="
# ⚠️ THE POINT OF THIS SECTION. fastpki-scep loaded its RA key with load_privkey_pem(),
# which is PEM_read_bio_PrivateKey on a FILE and has no pkcs11 branch — so a pkcs11: URI in
# SCEP_RA_KEY was handed to a PEM reader and rejected, and SCEP could not hold a token key
# AT ALL. CMP and OCSP moved to the token-capable loader; SCEP was missed.
# The reported symptom was that SCEP does not notice an HSM restart because it
# holds no keys; this is the cause, and §3f says a private key belongs in the HSM.
#
# Fails before the fix: fastpki-scep dies at startup on the PEM read.
PORT6=18459
RAURI=$(hsm_new_key_uri scepra 2>/dev/null || echo "")
if [ -z "$RAURI" ]; then
    echo "  [SKIP] no token for the SCEP RA key"
else
    TOKN=$(sed -n 's/.*token=\([^;?]*\).*/\1/p' <<<"$CA_KEY_URI")
    # The SCEP RA credential's key type is a variable, so this section becomes one
    # ROW of the server-side matrix instead of needing a second script:
    #
    #     RA_KEY_SPEC=ML-DSA-65 bash tests/scep.sh
    #
    # Minted through hsm_mint_key, which routes by spec — see the ⚠️ on that helper for why
    # asking pkcs11-tool for anything outside its table silently measures the wrong key.
    # ⚠️ --id matters for anything but RSA: without CKA_ID the provider cannot associate
    # private with public and dies with "No CKA_ID in source object".
    # ⚠️ A FAILED MINT MUST STOP HERE. This used to set a variable nothing read, so the
    # run carried on and failed at the CSR with "Could not find private key" — a missing
    # key reported as a certification problem, three steps from the cause.
    if ! hsm_mint_key "$TOKN" scepra D0 "${RA_KEY_SPEC:-rsa:2048}"; then
        echo "  [SKIP] could not mint a ${RA_KEY_SPEC:-rsa:2048} RA key in the token"
        echo "         via ${HSM_MINT_VIA:-?}: ${HSM_MINT_ERR:-no error captured}"
        if [ -z "${RA_KEY_SPEC:-}" ] || [ "$RA_KEY_SPEC" = "rsa:2048" ]; then
            chk "the default RA key can be minted in the token" yes no
        else
            echo "         ⚠️ NOTHING was measured for RA_KEY_SPEC=$RA_KEY_SPEC."
        fi
        SCEPRA_MINT_FAILED=1
    fi
    if [ -z "${SCEPRA_MINT_FAILED:-}" ]; then
    # The RA certificate is issued BY the CA, for the key that now lives in the token.
    # ⚠️ KEEP THE STDERR. Both of these used to discard it, so when a key type could not be
    # certified the row reported "could not issue an RA certificate" and named nothing —
    # leaving it indistinguishable from a product limitation. Two separate commands can
    # fail here, and which one it is matters: the CSR is SELF-signed by the RA key, while
    # the certificate is signed by the CA key.
    "$OSSL" req -new -subj "/CN=SCEP RA Token" -key "$RAURI" $CA_OSSL_ARGS -out ratok.csr 2>racsr.log
    "$OSSL" x509 -req -in ratok.csr -CA ca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS \
        -CAcreateserial -days 365 -extfile ra.ext -out ratok.pem 2>rasign.log
    if [ ! -s ratok.pem ]; then
        echo "  [SKIP] could not issue an RA certificate for the token key"
        echo "         CSR step  ($([ -s ratok.csr ] && echo OK || echo FAILED)): $(grep -viE '^$' racsr.log 2>/dev/null | head -1)"
        echo "         sign step ($([ -s ratok.pem ] && echo OK || echo FAILED)): $(grep -viE '^$' rasign.log 2>/dev/null | head -1)"
        # ⚠️ A MATRIX ROW THAT SKIPPED IS NOT A ROW THAT PASSED. Without this the run still
        # prints a clean "SCEP: PASS=93 FAIL=0" and a pasted transcript reads as though the
        # key type worked — the exact way two demo cells were reported as product facts when
        # nothing had been measured. macOS cannot sign with an EC SoftHSM key through the
        # pkcs11 provider while Linux can, so this is expected HERE and the
        # row has to be run in the shipped image.
        if [ -n "${RA_KEY_SPEC:-}" ] && [ "$RA_KEY_SPEC" != "rsa:2048" ]; then
            echo "         ⚠️ NOTHING was measured for RA_KEY_SPEC=$RA_KEY_SPEC on this host."
            echo "         Minted via: ${HSM_MINT_VIA:-?}${HSM_MINT_ERR:+ — $HSM_MINT_ERR}"
            echo "         Run this row in the image: FASTPKI_TEST_SUITE=scep.sh \\"
            echo "           FASTPKI_TEST_ENV=\"RA_KEY_SPEC=$RA_KEY_SPEC\" \\"
            echo "           FASTPKI_IMAGE=fastpki:local tests/run-in-container.sh"
        fi
    else
        cat > ratok.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
SCEP_BIND=127.0.0.1
SCEP_PORT=$PORT6
SCEP_RA_KEY=$RAURI
LOG_LEVEL=err
EOF
        hsm_conf_lines >> ratok.conf
        # Publish THIS token key's certificate as the RA credential for CA 'ca'.
        # It replaces the file-backed one published above, so the RA key the server now
        # holds and the certificate it resolves are the token pair — which is what
        # X509_check_private_key is there to enforce.
        # THE MATRIX CELL, named by the certificate this deployment issued for the RA
        # key and is about to serve SCEP with. A token listing cannot name these keys —
        # SoftHSM stores RSA-PSS as plain CKK_RSA and pkcs11-tool calls an ML-DSA key
        # "unknown key algorithm 74" — so the SPKI is the only honest answer.
        if [ -n "${RA_KEY_SPEC:-}" ]; then
            WANT_SPKI=$(hsm_expected_spki "$RA_KEY_SPEC")
            SPKI_SAW=$("$OSSL" x509 -in ratok.pem -noout -text 2>/dev/null \
                       | sed -n 's/.*Public Key Algorithm: *//p' | head -1)
            if [ -n "$WANT_SPKI" ]; then
                chk "the SCEP RA certificate's key is $WANT_SPKI (matrix cell)" yes \
                    "$(printf '%s' "$SPKI_SAW" | grep -qiF "$WANT_SPKI" && echo yes || echo no)"
                printf '%s' "$SPKI_SAW" | grep -qiF "$WANT_SPKI" || echo "      SPKI says: '$SPKI_SAW'"
            else
                chk "the SCEP RA key was minted through the PROVIDER" provider "$HSM_MINT_VIA"
            fi
        fi
        service_cert_publish "$W/ratok.pem" ca scep-ra
        "$ROOT/build/fastpki-scep" --config ratok.conf >ratok.log 2>&1 & P6=$!
        # Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
        wait_conf "ratok.conf" SCEP_PORT "$P6" || true
        chk "fastpki-scep starts with a pkcs11: RA key" yes \
            "$(kill -0 $P6 2>/dev/null && echo yes || echo no)"
        chk "  and does not complain about a PEM read" no \
            "$(grep -qiE 'PEM_read|PEM routines' ratok.log && echo yes || echo no)"
        # Starting is not enough — the RA key is used to SIGN the response, so enrol.
        URL6="http://127.0.0.1:$PORT6/scep/ca"
        make_csr "$SCEP_CH"
        # ⚠️ CAPTURE the builder's stderr. It used to be thrown away, so when the client
        # could not build a request at all the next line failed as
        # `curl: option --data-binary: error encountered when reading a file` — a protocol
        # fact reported as a curl usage error, with nothing naming the cause.
        #
        # SCEP wraps the request in CMS EnvelopedData encrypted TO THE RA CERTIFICATE
        # (src/scep/client.cpp: CMS_encrypt). A recipient key must therefore support key
        # transport or key agreement. That is a property of the key type, not of FastPKI.
        "$TC" build ratok.pem client.pem dev.key csr.der tokreq.der >tokbuild.log 2>&1
        if [ ! -s tokreq.der ]; then
            # The row's answer IS this refusal — record it with the reason rather than
            # letting it read as a broken test.
            echo "  [INFO] the SCEP client cannot build a request for RA_KEY_SPEC=${RA_KEY_SPEC:-rsa:2048}"
            echo "         reason: $(grep -viE '^$' tokbuild.log | head -2 | tr '\n' ' ')"
            chk "  and the reason is the CMS recipient, not something else" yes \
                "$(grep -qiE 'CMS_encrypt|recipient|envelop' tokbuild.log && echo yes || echo no)"
            # ⚠️ The DEFAULT key type may NOT take this path. rsa:2048 is what every gate
            # runs; if IT cannot build a request that is a real fault and must be loud.
            if [ -z "${RA_KEY_SPEC:-}" ] || [ "$RA_KEY_SPEC" = "rsa:2048" ]; then
                chk "the default RA key can build a SCEP request" yes no
            fi
        else
        curl -s -X POST --data-binary @tokreq.der -H "Content-Type: application/x-pki-message" \
            "$URL6?operation=PKIOperation" -o tokresp.der
        TOKSTATUS=$("$TC" parse client.pem dev.key tokresp.der tokissued.der 2>&1)
        TOKPKI=$(printf '%s' "$TOKSTATUS" | grep -o 'pkiStatus=[0-9]*' | head -1)
        # ⚠️ EVERY KEY TYPE HAS A DEFINED CORRECT OUTCOME HERE, and for most of them it is
        # a REFUSAL. SCEP's PKIOperation envelope is CMS encrypted TO the RA certificate and
        # the RA must DECRYPT it, which needs RSA key transport. So:
        #
        #   RSA        enrols.
        #   EC         fastpki-scep refuses, naming RSA key transport — measured:
        #              "SCEP RA key is EC, but the RA decrypts the PKIOperation envelope
        #               and that needs RSA key transport."
        #   RSA-PSS    signature-only, so the same refusal.
        #   ML-DSA     the CLIENT cannot even build the request (handled above).
        #
        # Asserting "enrolment succeeds" for all of them would mark FastPKI's own correct,
        # actionable refusal as a defect. SCEP is the CMS-related exception that works
        # with RSA keys only.
        if [ -z "${RA_KEY_SPEC:-}" ] || [ "$RA_KEY_SPEC" = "rsa:2048" ]; then
            chk "enrolment through a token-held RA key -> SUCCESS" "pkiStatus=0" "$TOKPKI"
        elif [ "$TOKPKI" = "pkiStatus=0" ]; then
            chk "enrolment through a token-held $RA_KEY_SPEC RA key -> SUCCESS" "pkiStatus=0" "$TOKPKI"
        else
            chk "SCEP REFUSES a $RA_KEY_SPEC RA key, and the server says why" yes \
                "$(grep -qiE 'needs RSA key transport|requires RSA' ratok.log && echo yes || echo no)"
            chk "  and the refusal names the config key to fix it" yes \
                "$(grep -qi 'SCEP_RA_KEY' ratok.log && echo yes || echo no)"
        fi
        # ⚠️ READ THE SERVER LOG BEFORE THE CLIENT RESULT. An empty pkiStatus says only
        # "no parsable response"; it does not say whether the server refused, crashed, or
        # could not use its own key. Without this the EC row looked identical to the ML-DSA
        # row, and they are NOT the same failure: ML-DSA cannot be a CMS recipient at all,
        # while EC builds the request fine (ECDH) and fails later.
        if ! printf '%s' "$TOKSTATUS" | grep -q 'pkiStatus=0'; then
            echo "      client said: $(printf '%s' "$TOKSTATUS" | head -2 | tr '\n' ' ')"
            echo "      response bytes: $(wc -c < tokresp.der 2>/dev/null | tr -d ' ')"
            echo "      server log (last 6):"
            tail -6 ratok.log 2>/dev/null | sed 's/^/        /'
        fi
        fi
        kill $P6 2>/dev/null
    fi
    fi
fi

echo "=== Weak-algorithm opt-in: SHA-1 + DES3 advertised when enabled ==="
PORT5=18458
cat > weak.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
SCEP_BIND=127.0.0.1
SCEP_PORT=$PORT5
SCEP_ALLOW_SHA1=true
SCEP_ALLOW_DES3=true
LOG_LEVEL=err
EOF
seed_ca_from_conf weak.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-scep" --config weak.conf >weak.log 2>&1 & P5=$!
sleep 1; trap 'pg_cleanup; kill $P $P2 $P3 $P4 $P5 2>/dev/null' EXIT
if ! kill -0 $P5 2>/dev/null; then echo "fastpki-scep (weak) died:"; cat weak.log; exit 1; fi
WURL="http://127.0.0.1:$PORT5/scep/ca"   # SCEP is id-based
WCAPS=$(curl -s "$WURL?operation=GetCACaps")
echo "$WCAPS" | grep -q "SHA-1" && a=yes || a=no
chk "SHA-1 advertised when SCEP_ALLOW_SHA1=true" yes "$a"
echo "$WCAPS" | grep -q "DES3" && a=yes || a=no
chk "DES3 advertised when SCEP_ALLOW_DES3=true" yes "$a"

# ⚠️ THIS BLOCK MUST STAY AHEAD OF THE NO-IDENTITY SECTION BELOW, which deletes every
# `enrol:*` permission from every role to prove the ungated device path. I first appended
# it at the end of the file and every assertion measured that instead:
#
#     SCEP rejected: 'scep' holds no scep:enrol for CA 'ca'
#
# The cap-refusal assertion PASSED anyway — a refusal for the wrong reason is
# indistinguishable from the right one when you only read the status code.
echo "=== The issuance limits apply to SCEP too, now that it has a subject ==="
# It is per-user now, and it is capped as well — yes to both.
#
# ⚠️ SCEP WAS THE ONLY ENROLMENT PROTOCOL WITH NO CAP. EST, CMP, ACME, MS-WSTEP and the
# console each call role_limit_refusal(); scep/main.cpp called it zero times. That was
# CORRECT when the limits shipped — the only credential was a deployment-wide secret
# naming nobody — and stopped being correct when the per-user challenge arrived and
# Deleted the shared one. A rule that outlived its reason.
#
# ⚠️ DRIVEN WITH THE `scep` USER THIS SUITE ALREADY USES, not a purpose-built one. My first
# version created its own role and the server answered
#
#     SCEP rejected: 'capped' holds no scep:enrol for CA 'ca'
#
# — the cell was measuring a role I had failed to construct, not the cap. The existing user
# is proven to enrol by every section above, so the only variable left is the number.
CAPN=$(pg_exec "SELECT COUNT(*) FROM certs WHERE owner='scep' AND status=0;" | tr -d ' ')
chk "PRECONDITION: the scep user already holds certificates" yes \
    "$([ "${CAPN:-0}" -ge 1 ] && echo yes || echo no)"

scep_enrol_status() {   # <challenge> <cn> -> prints pkiStatus=N
    make_csr "$1" "$2" >/dev/null 2>&1
    "$TC" build ca_dl.pem client.pem dev.key csr.der req.der >/dev/null 2>&1
    curl -s -X POST --data-binary @req.der -H "Content-Type: application/x-pki-message" \
        "$URL?operation=PKIOperation" -o resp.der
    "$TC" parse client.pem dev.key resp.der issued.der 2>/dev/null
}

# ⚠️ ASK WHICH ROLE THE USER ACTUALLY HOLDS. Earlier sections reassign it — by this point
# `scep` is on a scoped role (`prof@scep`), not the `requester` it was seeded with. Capping
# `requester` therefore capped a role nobody held, the request sailed through, and the cell
# reported the cap broken when it was the test that was wrong.
CAPROLE=$(pg_exec "SELECT role FROM web_users WHERE username='scep';" | tr -d ' ')
chk "PRECONDITION: the scep user's role is known" yes \
    "$([ -n "$CAPROLE" ] && echo yes || echo no)"
# Cap it at exactly what it already holds, so the very next request is one over.
pg_exec "UPDATE roles SET max_certs=$CAPN WHERE name='$CAPROLE';" >/dev/null 2>&1
chk "PRECONDITION: the cap is really set on that role" "$CAPN" \
    "$(pg_exec "SELECT max_certs FROM roles WHERE name='$CAPROLE';" | tr -d ' ')"
chk "at the cap, SCEP refuses"                "pkiStatus=2" "$(scep_enrol_status "$SCEP_CH" over.internal)"
chk "  and no certificate was written for it" "$CAPN" \
    "$(pg_exec "SELECT COUNT(*) FROM certs WHERE owner='scep' AND status=0;" | tr -d ' ')"
chk "  the refusal is audited as a limit"     yes \
    "$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='authz_fail' AND detail LIKE '%issuance-limit%';" \
       | tr -d ' ' | grep -qE '^[1-9]' && echo yes || echo no)"
# ⚠️ THE NEGATIVE CONTROL. With the number removed the SAME request goes through. Without
# it this block passes just as well when the refusal comes from something unrelated — which
# is exactly how the first version fooled me.
pg_exec "UPDATE roles SET max_certs=NULL WHERE name='$CAPROLE';" >/dev/null 2>&1
chk "  with the cap removed the same request issues" "pkiStatus=0" \
    "$(scep_enrol_status "$SCEP_CH" under.internal)"
chk "  and the count grew by one"             "$((CAPN+1))" \
    "$(pg_exec "SELECT COUNT(*) FROM certs WHERE owner='scep' AND status=0;" | tr -d ' ')"

echo "=== The device path with NO identity is still UNGATED ==="
# EST, ACME, CMP and MS authorize enrolment against the caller's RBAC role. A SCEP request
# that carries no identity does not, by decision: SCEP is left untagged, since it
# is used by devices in most cases rather than humans.
#
# ⚠️ CHANGED WHICH PATH THAT IS, and this block is where the difference is pinned.
# It used to be the shared SCEP_CHALLENGE: no user, nothing to authorize, always issued.
# That value is gone, so the remaining credentials that name nobody are a ONE-TIME DYNAMIC
# TOKEN and a renewal. The per-user challengePassword does name someone and IS gated by
# scep:enrol — asserted in the per-user section above.
#
# So this asserts the ABSENCE of a gate on the token path, which needs care: "it enrolled"
# is also true of a server that has a gate the caller happens to satisfy. Strip every
# enrolment permission from every role first — that would refuse EST/ACME/CMP/MS outright.
PORT_UG=18456
sed -e "s/^SCEP_PORT=.*/SCEP_PORT=$PORT_UG/" bootstrap.conf > ungated.conf
printf 'SCEP_DYNAMIC_CHALLENGE=true\n' >> ungated.conf
chk "PRECONDITION: the token-accepting config was written" yes \
    "$(grep -q "^SCEP_PORT=$PORT_UG" ungated.conf 2>/dev/null && echo yes || echo no)"
"$ROOT/build/fastpki-scep" --config ungated.conf >ungated.log 2>&1 & PUG=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "ungated.conf" SCEP_PORT "$PUG" || true
chk "  the server starts" yes "$(kill -0 $PUG 2>/dev/null && echo yes || echo no)"
URLUG="http://127.0.0.1:$PORT_UG/scep/ca"
TOKUG=$("$ROOT/build/fastpki-scep" --config ungated.conf --issue-challenge 2>/dev/null | tail -1)
chk "  a one-time token was minted" yes "$([ -n "$TOKUG" ] && echo yes || echo no)"
pg_exec "DELETE FROM role_permissions WHERE permission LIKE '%:enrol';" >/dev/null
make_csr "$TOKUG" ungated-device.internal
"$TC" build ca_dl.pem client.pem dev.key csr.der req2.der >/dev/null 2>&1
curl -s -X POST --data-binary @req2.der -H "Content-Type: application/x-pki-message" \
    "$URLUG?operation=PKIOperation" -o resp2.der
ST2=$("$TC" parse client.pem dev.key resp2.der issued2.der 2>/dev/null)
chk "a dynamic token issues with every enrol:* permission revoked" "pkiStatus=0" "$ST2"
# ⚠️ THE OTHER HALF. With the same permissions revoked, the PER-USER path must be refused
# — otherwise "ungated" would mean SCEP has no gate at all, and the grant would be decorative.
SCEP_CH_UG=$(scep_challenge_for scep)
make_csr "$SCEP_CH_UG" gated-user.internal
"$TC" build ca_dl.pem client.pem dev.key csr.der req3.der >/dev/null 2>&1
curl -s -X POST --data-binary @req3.der -H "Content-Type: application/x-pki-message" \
    "$URLUG?operation=PKIOperation" -o resp3.der
chk "  ...while the per-user path IS refused" "pkiStatus=2" \
    "$("$TC" parse client.pem dev.key resp3.der issued3.der 2>/dev/null)"
kill $PUG 2>/dev/null; wait $PUG 2>/dev/null
# ⚠️ And the permission MUST be offered in the console now. Seeding a grant the role
# editor cannot save is the half-removal shape this repo has been bitten by: it made an
# admin who opened the admin role and pressed Save get a 400, unable to restore their own
# grants. Step 0009 took it out of both places; step 0016 puts it back in both.
chk "scep:enrol IS a grantable permission" yes \
    "$(grep -q '"scep:enrol"' "$ROOT/src/web/main.cpp" && echo yes || echo no)"

echo "=== A non-RSA SCEP RA key is REFUSED at serve time, not at first enrolment ==="
# ⚠️ The RA key DECRYPTS the PKIOperation envelope (CMS_decrypt), which is RSA key
# transport. An EC key satisfies every other check — it loads, it certifies, its cert
# resolves and X509_check_private_key passes — and then fails only when a real client
# enrols, as an opaque 400 "could not decrypt EnvelopedData" that names neither the key nor
# the reason. Refusing on both ends is the rule; the console refuses at issuance
# and this is the serving end.
# Only the KEY changes. No RA certificate is published for it on purpose: the algorithm
# check runs before resolve_ra_cert(), so reaching it proves the ordering as well as the
# refusal — and the assertions below key on the algorithm message, not on the bare 503,
# so a refusal arriving for any other reason would fail them.
"$OSSL" ecparam -name prime256v1 -genkey -noout -out raec.key >/dev/null 2>&1
kill $P4 2>/dev/null; wait $P4 2>/dev/null
sed 's#^SCEP_RA_KEY=.*#SCEP_RA_KEY='"$W"'/raec.key#' ra.conf > raec.conf
"$ROOT/build/fastpki-scep" --config raec.conf >raec.log 2>&1 & P5=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "raec.conf" SCEP_PORT "$P5" || true
EC_CODE=$(curl -s -o raec.out -w '%{http_code}' "http://127.0.0.1:$PORT4/scep/ca?operation=GetCACert")
chk "an EC SCEP RA key is refused (503)"          503 "$EC_CODE"
chk "  and the refusal says RSA is required"      yes "$(grep -q 'needs RSA key transport' raec.out && echo yes || echo no)"
chk "  and it NAMES the key type it found"        yes "$(grep -qi 'SCEP RA key is EC' raec.out && echo yes || echo no)"
chk "  ...the server logs it too, not only the client" yes \
    "$(grep -q 'needs RSA key transport' raec.log && echo yes || echo no)"
chk "  the server stays up (a refusal, not a crash)"   yes \
    "$(kill -0 $P5 2>/dev/null && echo yes || echo no)"
kill $P5 2>/dev/null; wait $P5 2>/dev/null

echo "=== SCEP_RESPONSE_MD — the digest the CertRep is SIGNED with ==="
# The key AND hash matrix was required on the three services that use an RA
# credential rather than TLS. For SCEP the hash half did not exist: CMS_sign takes no
# digest argument, so the CertRep was signed with whatever OpenSSL calls the key default
# and SCEP_ALLOW_SHA1 only ever governed what a CLIENT was allowed to send.
#
# ⚠️ DECODED FROM THE RESPONSE BYTES. `openssl cms -cmsout -print` prints the SignedData
# digestAlgorithm, which is the field that actually changes; asserting on the config value
# or on "the enrolment succeeded" would pass for a build that ignored the setting entirely.
PORT5=18452
# ⚠️ DRIVEN BY A ONE-TIME DYNAMIC TOKEN, NOT THE PER-USER CHALLENGE. By this point the
# Section above has deleted every enrol:* grant from every role and does not put
# them back, so a per-user enrolment here is refused on PERMISSIONS — a correct refusal
# that has nothing to do with digests. Worse, it would not have been visible: a FAILURE
# CertRep is signed with the same key, so the digest assertion below passes either way and
# only the SUCCESS assertion catches it. The token path is the one this suite has just
# proven works with those grants revoked, so it measures the digest and nothing else.
scep_md_run() {   # <md> <label> <expected digestAlgorithm name>
    local md="$1" label="$2" expect="$3"
    # ⚠️ LOG_LEVEL=info, not the suite default of err. A SCEP refusal is logged at info, so
    # at err the server log is EMPTY and a failing row says only "pkiStatus=2" with no
    # reason at all — which is exactly how the permissions cause above stayed hidden.
    sed -e "s#^SCEP_PORT=.*#SCEP_PORT=$PORT5#" -e "s#^LOG_LEVEL=.*#LOG_LEVEL=info#" \
        bootstrap.conf > "md-$label.conf"
    printf 'SCEP_DYNAMIC_CHALLENGE=true\n' >> "md-$label.conf"
    [ -n "$md" ] && printf 'SCEP_RESPONSE_MD=%s\n' "$md" >> "md-$label.conf"
    "$ROOT/build/fastpki-scep" --config "md-$label.conf" >"md-$label.log" 2>&1 & local PM=$!
    sleep 1
    if ! kill -0 $PM 2>/dev/null; then
        chk "$label: the SCEP server starts" yes no
        return 0
    fi
    local ch; ch=$("$ROOT/build/fastpki-scep" --config "md-$label.conf" --issue-challenge 2>/dev/null | tail -1)
    chk "$label: a one-time token was minted" yes "$([ -n "$ch" ] && echo yes || echo no)"
    make_csr "$ch" "md-$label.internal"
    "$TC" build ca_dl.pem client.pem dev.key csr.der "mdreq-$label.der" >/dev/null 2>&1
    curl -s -X POST --data-binary "@mdreq-$label.der" \
         -H "Content-Type: application/x-pki-message" \
         "http://127.0.0.1:$PORT5/scep/ca?operation=PKIOperation" \
         -o "mdresp-$label.der"
    # The CertRep must still be a real SUCCESS -- a digest change that broke issuance would
    # otherwise show up only as an unread response file.
    local st; st=$("$TC" parse client.pem dev.key "mdresp-$label.der" "mdissued-$label.der" 2>/dev/null)
    chk "$label: CertRep is still SUCCESS" "pkiStatus=0" "$st"
    [ "$st" = "pkiStatus=0" ] || sed -n '/SCEP/p' "md-$label.log" | tail -5
    local alg
    alg=$("$OSSL" cms -inform DER -in "mdresp-$label.der" -cmsout -print 2>/dev/null \
          | grep -A2 'digestAlgorithm' | grep -m1 'algorithm:' | sed 's/.*algorithm: *//; s/ *(.*//')
    chk "  $label: SignedData digest is '$expect'" yes \
        "$(printf '%s' "$alg" | grep -qi -- "$expect" && echo yes || echo no)"
    echo "      digestAlgorithm: ${alg:-<unreadable>}"
    kill $PM 2>/dev/null; wait $PM 2>/dev/null
}
# The baseline first: without it a later row could pass because the server emits one thing
# whatever it is asked for.
scep_md_run ""          default sha256
scep_md_run "sha512"    sha512  sha512
# An unknown name must not stop SCEP answering. Falling back beats refusing every
# enrolment over a digest label.
scep_md_run "sha42"     unknown sha256

echo
echo "=== SCEP: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
