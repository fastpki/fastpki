#!/usr/bin/env bash
# The `admin` built-in profile must ALLOW keyCertSign and cRLSign, and must allow
# EVERY ExtendedKeyUsage. Without keyCertSign and cRLSign, `admin` cannot issue CA
# certificates at all, and every EKU has to be allowed on that profile.
#
# ⚠️ WHY THIS SUITE ASSERTS BEHAVIOUR AND NOT THE PROFILE JSON. Adding the two bits to
# `allowed_ku` alone changed NOTHING: evaluate_profile_extensions() refused every CA-only
# bit from a blanket `is_ca_only_ku()` check that ran BEFORE the allow-list was consulted,
# so the new entry sat behind a branch that could never be reached. A test that read the
# profile back from /api/profiles would have gone green over exactly that bug. So every
# assertion here drives a real EST enrolment and DECODES the issued certificate.
#
# The other half is the one that keeps this from being a widening: `requester` must still
# refuse both. Each permit assertion below is paired with the refusal that proves the gate
# is still a gate and not a formality.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and is absent on the Mac. Without this the
# suite still RUNS and every assertion compares empty strings, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
W="$(mktemp -d)"; cd "$W"; PORT=18274
P=
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

ca_in_token ca.pem "/CN=Profile CA KU" 3
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup profile_ca_ku
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt
# `boss` holds the console role `admin`, which the shipped seed grants profile:use|admin —
# so the `admin` cert profile is the one that resolves for it. `hand` holds `requester`,
# which holds profile:use|requester.
seed_web_user boss s3cret-b admin
seed_web_user hand s3cret-h requester

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
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf
"$ROOT/build/fastpki-est" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "est died:"; cat srv.log; exit 1; fi

# enroll USER PASS SUBJECT [openssl-req-args...] -> the issued PEM (empty on refusal)
enroll(){ local u=$1 p=$2 s=$3; shift 3
  "$OSSL" req -new -subj "/CN=$s" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr "$@" >/dev/null 2>&1
  "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
  curl -sk -u "$u:$p" --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
    "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll" \
    | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null
}
issued(){ has "$1" "BEGIN CERTIFICATE"; }
ext(){ echo "$1" | "$OSSL" x509 -noout -ext "$2" 2>/dev/null; }

echo "=== 0. control: both identities can enrol at all ==="
# ⚠️ Without this, every "refused" assertion below could be passing because the identity
# is broken, the CA is missing or the server is wedged — a refusal for the WRONG reason
# reads exactly like the refusal we want to see.
chk "admin-role identity enrols an ordinary cert"     yes "$(issued "$(enroll boss s3cret-b a.internal)")"
chk "requester-role identity enrols an ordinary cert" yes "$(issued "$(enroll hand s3cret-h b.internal)")"

echo "=== 1. the admin profile PERMITS keyCertSign + cRLSign ==="
C=$(enroll boss s3cret-b ca-ish.internal -addext "keyUsage=critical,keyCertSign,cRLSign")
chk "issued"                       yes "$(issued "$C")"
KU=$(ext "$C" keyUsage)
# Decode the BITS, not the request. openssl prints the named bits of the KeyUsage
# extension, so this is the certificate saying what it holds.
chk "  the cert carries Certificate Sign" yes "$(has "$KU" 'Certificate Sign')"
chk "  the cert carries CRL Sign"         yes "$(has "$KU" 'CRL Sign')"

echo "=== 2. ...and requester STILL refuses them (the gate is still a gate) ==="
chk "requester + keyCertSign -> refused" no \
    "$(issued "$(enroll hand s3cret-h nope.internal -addext "keyUsage=critical,keyCertSign")")"
chk "requester + cRLSign -> refused"     no \
    "$(issued "$(enroll hand s3cret-h nope2.internal -addext "keyUsage=critical,cRLSign")")"

echo "=== 3. the admin profile allows EVERY EKU (the '*' wildcard) ==="
# An OID under a private arc no allow-list could ever have enumerated. That is the point:
# "all EKUs" cannot be expressed as a longer list, only as a wildcard.
ODD=1.3.6.1.4.1.99999.7.1
C=$(enroll boss s3cret-b odd.internal -addext "extendedKeyUsage=$ODD")
chk "issued"                          yes "$(issued "$C")"
chk "  the cert carries $ODD"         yes "$(has "$(ext "$C" extendedKeyUsage)" "$ODD")"

echo "=== 4. ...and requester DROPS an EKU outside its named list ==="
# By design, an attribute the profile does not allow is dropped rather than refused.
# So the request succeeds — and the assertion that matters is the second one,
# that the OID did not survive. Asserting only "issued" would pass on a cert carrying it.
C4=$(enroll hand s3cret-h odd2.internal -addext "extendedKeyUsage=$ODD")
chk "requester + $ODD -> issued"     yes "$(issued "$C4")"
chk "  ...but $ODD is NOT in the cert" no \
    "$(has "$(ext "$C4" extendedKeyUsage)" "$ODD")"

echo "=== 5. the refusal in section 2 is a POLICY refusal, named in the server log ==="
# ⚠️ Asserting the REASON. A 4xx with any other cause would satisfy section 2 equally
# well, and then this suite would be guarding the wrong thing.
#
# Both requests there ask for exactly one CA-only bit, so the profile keeps NOTHING —
# and an empty KeyUsage extension is not a certificate we may issue (RFC 5280 4.2.1.3):
# it would carry no key-usage restriction at all, which is the opposite of the ask.
# That is the refusal, and it names the bit so the operator can see which one to grant.
chk "log names the KeyUsage policy refusal" yes \
    "$(grep -q "permits none of the requested KeyUsage bits (keyCertSign)" srv.log && echo yes || echo no)"
chk "log says WHY an empty KeyUsage is not an option" yes \
    "$(grep -q "RFC 5280 4.2.1.3" srv.log && echo yes || echo no)"
chk "log points at the CA-only bit as the fix" yes \
    "$(grep -q "One of them is a CA-only bit" srv.log && echo yes || echo no)"

echo
echo "profile_ca_ku: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
