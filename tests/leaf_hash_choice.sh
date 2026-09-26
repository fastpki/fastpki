#!/usr/bin/env bash
# Regression: the console may choose the SIGNATURE DIGEST for a leaf when
# the CA key is RSA, and may not when the key type fixes it.
#
# The requirement, restated:
#   auto-match does not hold for all key types. RSA keys are flexible, so when requesting
#   a certificate — a leaf one included — the hash function must be selectable in the web
#   console. The exception is modern keys that support only one hash; EC keys may
#   auto-match.
#
# Replaced the control with auto-match everywhere. For EC that is right — the digest
# must match the curve's security level or CKM_ECDSA is handed a raw digest of the wrong
# length. For RSA it enforced a DEFAULT (SHA-256 to 3072 bits, SHA-384 from 4096) as
# though it were a property of the key, which it is not.
#
# Asserted by DECODING the issued certificate's signatureAlgorithm, never by the API's
# status code — a 201 says a certificate was made, not what signed it. That distinction
# is the whole of this ticket.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF

W="$(mktemp -d)"; cd "$W"; PORT=18486
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

# ── An RSA CA and an EC CA, so both halves of the rule are exercised ───────────────
ca_in_token rsaca.pem "/CN=Hash Choice RSA CA" 3650 hashrsa
RSA_KEY_URI="$CA_KEY_URI"
# ⚠️ THE EC HALF IN A SUBSHELL, ON PURPOSE. ca_in_token `exit 0`s the whole script when a
# token key cannot self-sign, and on macOS an EC key cannot: the pkcs11 provider signs EC
# on Linux and not here (measured). Called directly it would take the RSA
# assertions down with it and the suite would SKIP entirely — a suite that asserts nothing
# is not a pass. So the EC CA is attempted in a subshell and its absence is REPORTED,
# never silent: the RSA half is platform-independent and runs everywhere.
EC_KEY_URI=""
( CA_KEY_SPEC="EC:prime256v1" ca_in_token ecca.pem "/CN=Hash Choice EC CA" 3650 hashec \
  && printf '%s' "$CA_KEY_URI" > ec.uri ) >/dev/null 2>&1
[ -s ec.uri ] && [ -s ecca.pem ] && EC_KEY_URI="$(cat ec.uri)"

chk "fixture: the RSA CA really is RSA" yes \
    "$("$OSSL" x509 -in rsaca.pem -noout -text 2>/dev/null | grep -qi 'Public Key Algorithm: rsa' && echo yes || echo no)"
if [ -n "$EC_KEY_URI" ]; then
  chk "fixture: the EC CA really is EC" yes \
      "$("$OSSL" x509 -in ecca.pem -noout -text 2>/dev/null | grep -qi 'Public Key Algorithm: id-ecPublicKey' && echo yes || echo no)"
else
  echo "  [note] no EC token CA on this host — the EC auto-match half is NOT measured here."
  echo "         (the pkcs11 provider signs EC on Linux, not on macOS; the in-image tier covers it)"
fi

pg_setup leaf_hash_choice
WP=
trap 'pg_cleanup; kill $WP 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains "$W/domains.txt"
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/rsaca.pem
SIGNING_CA_KEY=$RSA_KEY_URI
SIGNING_CA_ID=hashrsa
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
# The console's HSM route mints the SUBJECT key inside the token, so the server needs
# to know which token and how to log into it. Derived from the CA key URI rather than
# hardcoded — hsm_helpers gives every suite its own token label so parallel runs cannot
# collide.
HSM_TOKEN=$(printf '%s' "$RSA_KEY_URI" | sed -n 's/.*token=\([^;?]*\).*/\1/p')
printf '1234' > "$W/hsmpin"
printf 'PKCS11_TOKEN=%s\nPKCS11_PIN_FILE=%s\n' "$HSM_TOKEN" "$W/hsmpin" >> bootstrap.conf
seed_ca_from_conf bootstrap.conf
[ -n "$EC_KEY_URI" ] && "$ROOT/build/fastpki-ca" --config bootstrap.conf add hashec --name "Hash Choice EC" \
      --ca-pem "$W/ecca.pem" --ca-key "$EC_KEY_URI" >/dev/null 2>&1
# Bootstrap the first admin through the API, the way every other web suite does — the
# first POST /api/users on an empty table is the console's own bootstrap path.
"$ROOT/build/fastpki-web" --config bootstrap.conf >web.log 2>&1 & WP=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$WP" || true
kill -0 $WP 2>/dev/null || { echo "fastpki-web died:"; tail -20 web.log; echo "PASS=$pass FAIL=$((fail+1))"; exit 1; }

# Bootstrap the first admin through the API, the way every other web suite does — the
# first POST /api/users on an empty table is the console's own bootstrap path.
curl -s -o /dev/null -X POST "http://127.0.0.1:$PORT/api/users" \
     -d 'username=hadmin&password=hadminpw12&role=admin' 2>/dev/null

JAR="$W/cookies.txt"
curl -s -c "$JAR" -o /dev/null -X POST "http://127.0.0.1:$PORT/api/login" \
     -d 'username=hadmin&password=hadminpw12' 2>/dev/null

# Issue through the console with an explicit digest, then ask the CERTIFICATE what signed
# it. `openssl x509 -text` prints the signatureAlgorithm from the TBS and the outer one.
issue_with() {  # <ca_id> <md> <cn> -> prints the signature algorithm, lowercased
    "$OSSL" req -new -newkey rsa:2048 -nodes -keyout "k_$3.key" -out "c_$3.csr" \
        -subj "/CN=$3.internal" >/dev/null 2>&1
    # The CSR is the raw BODY and everything else is a query parameter — that is the
    # shape of /api/certs/request, and `md` rides alongside ca_instance rather than in a
    # form field.
    local body
    body=$(curl -s -b "$JAR" -X POST --data-binary "@c_$3.csr" \
        "http://127.0.0.1:$PORT/api/certs/request?ca_instance=$1&md=$2" 2>/dev/null)
    printf '%s' "$body" | sed -n 's/.*"pem":"\(.*\)".*/\1/p' | sed 's/\\n/\n/g' > "out_$3.pem"
    [ -s "out_$3.pem" ] || { echo "(no cert: $(printf '%s' "$body" | head -c 140))"; return; }
    "$OSSL" x509 -in "out_$3.pem" -noout -text 2>/dev/null \
        | sed -n 's/ *Signature Algorithm: *//p' | head -1 | tr 'A-Z' 'a-z'
}

echo "=== An RSA CA honours the requested digest ==="
chk "sha512 requested -> sha512WithRSAEncryption" sha512withrsaencryption "$(issue_with hashrsa sha512 a)"
chk "sha3-256 requested -> RSA-SHA3-256"          rsa-sha3-256            "$(issue_with hashrsa sha3-256 b)"
# The ladder is still the default when nothing is asked for: this CA is rsa:2048, so
# SHA-256. If this ever comes back sha512 the picker is leaking into the default.
chk "no digest requested -> the CA default (sha256)" sha256withrsaencryption "$(issue_with hashrsa '' c)"

if [ -n "$EC_KEY_URI" ]; then
echo "=== An EC CA auto-matches and IGNORES the request ==="
# ⚠️ THE POINT OF THIS HALF. P-256 must sign with SHA-256; asking for sha512 must change
# nothing. If it does, CKM_ECDSA gets a 64-byte digest where it expects 32 — which is the
# true half of the report and the reason the control is not simply restored for everyone.
chk "sha512 requested on P-256 -> still ecdsa-with-SHA256" ecdsa-with-sha256 "$(issue_with hashec sha512 d)"
chk "sha3-512 requested on P-256 -> still ecdsa-with-SHA256" ecdsa-with-sha256 "$(issue_with hashec sha3-512 e)"
fi

echo "=== An unknown digest name falls back, it does not fail the issuance ==="
# Refusing to issue over a cosmetic field would be the wrong trade — the request named a
# digest this build of OpenSSL does not have.
chk "garbage digest -> the CA default, still issued" sha256withrsaencryption "$(issue_with hashrsa not-a-digest f)"

echo "=== the CONSOLE's HSM route honours the digest too ==="
# ⚠️ EVERY ASSERTION ABOVE DRIVES /api/certs/request — the CSR path. 19c5126 wired
# `requested_md` there, gave the console's "Request (key in HSM)" form a digest picker, and
# I reported the control was back. It was not connected at either end:
#
#   * the browser builds its body as an explicit URLSearchParams list, and 'md' was not in
#     it, so the value never left the page;
#   * LeafRequest had no field to carry it and the request-hsm handler never read it, so
#     even a hand-written POST was ignored.
#
# The certificate came out signed with the CA default and looked entirely correct. This
# section drives THAT route, because a picker on a form nobody tested is how it shipped.
hsm_issue() {   # <ca_id> <md> <cn> -> the issued cert's signatureAlgorithm, lower-cased
    local body
    body=$(curl -s -b "$JAR" -X POST "http://127.0.0.1:$PORT/api/certs/request-hsm" \
        --data-urlencode "ca_instance=$1" --data-urlencode "md=$2" \
        --data-urlencode "cn=$3" \
        --data-urlencode "key=rsa" --data-urlencode "bits=2048" \
        --data-urlencode "keyref=pkcs11:token=$HSM_TOKEN;object=$3;type=private?pin-value=1234" 2>/dev/null)
    printf '%s' "$body" | sed -n 's/.*"pem":"\(.*\)".*/\1/p' | sed 's/\\n/\n/g' > "hsm_$3.pem"
    [ -s "hsm_$3.pem" ] || { printf 'NO-CERT(%s)' "$(printf '%s' "$body" | head -c 90)"; return; }
    "$OSSL" x509 -in "hsm_$3.pem" -noout -text 2>/dev/null \
        | sed -n 's/.*Signature Algorithm: *//p' | head -1 | tr 'A-Z' 'a-z'
}
chk "HSM route: sha512 requested -> sha512WithRSAEncryption" sha512withrsaencryption \
    "$(hsm_issue hashrsa sha512 hsha)"
chk "HSM route: sha3-256 requested -> RSA-SHA3-256"          rsa-sha3-256 \
    "$(hsm_issue hashrsa sha3-256 hsh3)"
# The control case: with no digest asked for, the CA default must still win — otherwise the
# two assertions above could pass on a route that simply always uses what was sent.
chk "HSM route: no digest requested -> the CA default (sha256)" sha256withrsaencryption \
    "$(hsm_issue hashrsa '' hdef)"

echo "=== the SIGNATURE FLOOR: a requested digest may be strong or absent, never broken ==="
# The picker above is a real choice, and "any digest OpenSSL can name" included sha1 and
# md5. Nothing refused them: the server resolved the name with EVP_get_digestbyname and
# signed. The console only ever OFFERS strong names, which is why this was invisible — the
# API takes whatever is sent, and the form is not the boundary.
#
# Asserted as a REFUSAL with a status code, and then as a real certificate under the
# opt-in. Checking only that sha1 does not come back would pass on a server that ignores
# the field entirely.
status_of() {   # <ca_id> <md> <cn> -> HTTP status from the CSR route
    "$OSSL" req -new -newkey rsa:2048 -nodes -keyout "k_$3.key" -out "c_$3.csr" \
        -subj "/CN=$3.internal" >/dev/null 2>&1
    curl -s -o "body_$3" -w '%{http_code}' -b "$JAR" -X POST --data-binary "@c_$3.csr" \
        "http://127.0.0.1:$PORT/api/certs/request?ca_instance=$1&md=$2" 2>/dev/null
}
chk "md=sha1 is refused"       400 "$(status_of hashrsa sha1 w1)"
chk "md=md5 is refused"        400 "$(status_of hashrsa md5  w2)"
# Spelling must not be a way past it. EVP_get_digestbyname resolves all of these to the
# same digest, so a filter written against name strings would honour whichever spelling
# whoever wrote it did not think of.
chk "md=SHA1 (other spelling) is refused"     400 "$(status_of hashrsa SHA1 w3)"
chk "md=RSA-SHA1 (another spelling) refused"  400 "$(status_of hashrsa RSA-SHA1 w4)"
# And the floor must not have swallowed the ordinary case.
chk "md=sha384 still issues"   201 "$(status_of hashrsa sha384 w5)"
chk "the refusal says why"     yes \
    "$(grep -qi 'signature floor' body_w1 && echo yes || echo no)"

echo "  -- and the HSM route has the same floor (two routes, one rule) --"
hsm_status() {  # <ca_id> <md> <cn>
    curl -s -o "hbody_$3" -w '%{http_code}' -b "$JAR" \
        -X POST "http://127.0.0.1:$PORT/api/certs/request-hsm" \
        --data-urlencode "ca_instance=$1" --data-urlencode "md=$2" --data-urlencode "cn=$3" \
        --data-urlencode "key=rsa" --data-urlencode "bits=2048" \
        --data-urlencode "keyref=pkcs11:token=$HSM_TOKEN;object=$3;type=private?pin-value=1234" 2>/dev/null
}
chk "HSM route: md=sha1 is refused" 400 "$(hsm_status hashrsa sha1 wh1)"

echo "  -- and a CA certificate cannot be created under a broken digest either --"
# Worse than a leaf: this is the anchor everything beneath it chains through, and it lives
# for years.
#
# ⚠️ WITH A CONTROL, because a refusal that fires for the wrong reason reads exactly like
# one that fires for the right reason. The first cut of this assertion passed against the
# UNFIXED server — the request was being rejected on its own shape, and the digest never
# came into it. The control below issues the identical request with a strong digest: if
# that does not succeed, the refusal above is measuring nothing and both rows say so.
ca_create() {   # <id> <md> -> HTTP status
    curl -s -o "cabody_$1" -w '%{http_code}' -b "$JAR" -X POST \
        "http://127.0.0.1:$PORT/api/ca-instances" \
        --data-urlencode "id=$1" --data-urlencode "name=Floor Test $1" \
        --data-urlencode "subject=/CN=Floor Test $1" --data-urlencode "md=$2" \
        --data-urlencode 'keyloc=pkcs11' --data-urlencode 'key=rsa' \
        --data-urlencode 'keygen=true' \
        --data-urlencode "keyref=pkcs11:token=$HSM_TOKEN;object=$1;type=private?pin-value=1234" \
        --data-urlencode 'bits=2048' --data-urlencode 'days=365' 2>/dev/null
}
CA_OK="$(ca_create floorok sha384)"
chk "control: the same CA request with a strong digest succeeds" 201 "$CA_OK"
if [ "$CA_OK" = "201" ]; then
    chk "CA creation with md=sha1 is refused" 400 "$(ca_create weakca sha1)"
else
    echo "  [note] the CA-creation request shape is not accepted here ($CA_OK) — the CA half"
    echo "         of the floor is NOT measured by this suite. The server said:"
    echo "         $(head -c 200 cabody_floorok)"
fi

echo "  -- the opt-in is real: with it set, sha1 is honoured and DECODES as sha1 --"
# ⚠️ This half is what makes the four refusals above meaningful. Without it they would
# equally pass on a server that had simply broken the `md` parameter, or on one that
# rejects every digest it does not recognise. Restarting with the key set and getting a
# certificate that genuinely says sha1WithRSAEncryption proves the floor is the ONLY thing
# refusing, and that an operator stuck with old equipment has a way through.
kill $WP 2>/dev/null; wait $WP 2>/dev/null
cp bootstrap.conf weak.conf
printf 'ALLOW_WEAK_SIGNATURE_DIGEST=true\n' >> weak.conf
"$ROOT/build/fastpki-web" --config weak.conf >web2.log 2>&1 & WP=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$WP" || true
JAR2="$W/cookies2.txt"
curl -s -c "$JAR2" -o /dev/null -X POST "http://127.0.0.1:$PORT/api/login" \
     -d 'username=hadmin&password=hadminpw12' 2>/dev/null
JAR="$JAR2"
chk "with the opt-in, md=sha1 is accepted"       201 "$(status_of hashrsa sha1 w6)"
chk "  and the certificate really is sha1-signed" sha1withrsaencryption "$(issue_with hashrsa sha1 w7)"

kill $WP 2>/dev/null; wait $WP 2>/dev/null
echo
echo "=== LEAF HASH CHOICE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
