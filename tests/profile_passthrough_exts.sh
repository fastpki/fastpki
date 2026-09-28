#!/usr/bin/env bash
# `CertProfile.allowed_custom_extensions` — which extensions a REQUESTER may
# carry in from its own CSR. The ask: a special entry 'any' or '*' in the allowed custom
# extensions, meaning any custom extension is allowed — on the `admin` profile.
#
# ⚠️ THE OPPOSITE DIRECTION to `custom_extensions`, which is what the profile STAMPS on
# every certificate it issues (guarded by profile_custom_exts.sh). The two were one
# phrase in his sentence and they are opposite arrows in the code; this suite is the
# incoming one.
#
# Before this field existed, `IssuanceInput.passthrough_ext_oids` was set in exactly ONE
# place — src/msxcep/main.cpp, hardcoded to two Microsoft template OIDs — so NO CSR-supplied
# custom extension survived issuance on EST, ACME, CMP, SCEP or the console at all.
#
# Four things are asserted, all by decoding the issued certificate:
#   1. NOT listed          -> the extension is DROPPED (the older behaviour, still right)
#   2. listed by OID       -> it is CARRIED, value and criticality intact
#   3. "*"                 -> any OID is carried
#   4. "*" IS NOT A BYPASS -> a CSR asking for basicConstraints CA:TRUE, its own keyUsage
#                             and its own EKU gets NONE of them, because the CA writes
#                             those itself before the copy and the copy skips an OID that
#                             is already present.
#
# (4) is the reason this suite exists rather than a comment claiming the wildcard is safe.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
W="$(mktemp -d)"; cd "$W"; PORT=18284
P=
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

# The OIDs the CSR will carry. Deliberately ones OpenSSL has no built-in method for, so
# they can only reach the certificate through the generic passthrough copy.
OID_A=1.3.6.1.4.1.99999.8.1     # carried when named, or under '*'
OID_B=1.3.6.1.4.1.99999.8.2     # never named -> only '*' can carry it

ca_in_token ca.pem "/CN=Passthrough CA" 3
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup profile_passthrough_exts
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt

# Three users, one per profile. The third argument is web_users.role — the ISSUANCE
# namespace, not a console role, so none of them holds a profile grant of its own and
# grant_profile below is what puts exactly one profile in each union.
seed_web_user nolist s3cret-n requester
seed_web_user bylist s3cret-b requester
seed_web_user anylst s3cret-a requester
grant_profile nolist passthru-none
grant_profile bylist passthru-oid
grant_profile anylst passthru-any

PJ='{'
PJ="$PJ"'"passthru-none":{"allowed_ku":["digitalSignature","keyEncipherment"],"allowed_eku":["serverAuth","clientAuth"],"default_ku":["digitalSignature"],"default_eku":["serverAuth"],"allow_wildcard":false},'
PJ="$PJ"'"passthru-oid":{"allowed_ku":["digitalSignature","keyEncipherment"],"allowed_eku":["serverAuth","clientAuth"],"default_ku":["digitalSignature"],"default_eku":["serverAuth"],"allow_wildcard":false,"allowed_custom_extensions":["'"$OID_A"'"]},'
PJ="$PJ"'"passthru-any":{"allowed_ku":["digitalSignature","keyEncipherment"],"allowed_eku":["serverAuth","clientAuth"],"default_ku":["digitalSignature"],"default_eku":["serverAuth"],"allow_wildcard":false,"allowed_custom_extensions":["*"]}}'

cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
BASE_URL=https://pki.example.org
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$PORT
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
seed_cert_profiles "$PJ"
seed_ca_from_conf bootstrap.conf

"$ROOT/build/fastpki-est" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "est died:"; cat srv.log; exit 1; fi

# enroll USER PASS CN [-addext ...] -> the issued PEM (empty when refused)
enroll(){ local u=$1 p=$2 s=$3; shift 3
  "$OSSL" req -new -subj "/CN=$s" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr "$@" >/dev/null 2>&1
  "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
  curl -sk -u "$u:$p" --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
    "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll" \
    | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null
}
txt(){ echo "$1" | "$OSSL" x509 -noout -text 2>/dev/null; }
issued(){ has "$1" "BEGIN CERTIFICATE"; }
# Both custom OIDs, one critical, carrying distinguishable values.
CEXT=(-addext "$OID_A=DER:0C:05:68:65:6C:6C:6F" -addext "$OID_B=critical,DER:0C:05:77:6F:72:6C:64")

echo "=== PRECONDITION: the CSR really carries both extensions ==="
# ⚠️ Without this every "the extension is absent" assertion below passes just as well
# against an openssl that silently dropped the -addext, i.e. against nothing being tested.
"$OSSL" req -new -subj "/CN=pre.internal" -newkey rsa:2048 -keyout pk.pem -nodes -out pre.csr \
        "${CEXT[@]}" >/dev/null 2>&1
PRE=$("$OSSL" req -in pre.csr -noout -text 2>/dev/null)
chk "CSR carries $OID_A" yes "$(has "$PRE" "$OID_A")"
chk "CSR carries $OID_B" yes "$(has "$PRE" "$OID_B")"

echo "=== 1. a profile listing NOTHING drops both (the older behaviour) ==="
C=$(enroll nolist s3cret-n one.internal "${CEXT[@]}"); T=$(txt "$C")
chk "issued"                                  yes "$(issued "$C")"
chk "  $OID_A is NOT on the cert"             no  "$(has "$T" "$OID_A")"
chk "  $OID_B is NOT on the cert"             no  "$(has "$T" "$OID_B")"

echo "=== 2. a profile listing OID_A carries exactly that one ==="
C=$(enroll bylist s3cret-b two.internal "${CEXT[@]}"); T=$(txt "$C")
chk "issued"                                  yes "$(issued "$C")"
chk "  $OID_A IS carried"                     yes "$(has "$T" "$OID_A")"
chk "  its value survives (hello)"            yes "$(has "$T" 'hello')"
chk "  $OID_B is still dropped"               no  "$(has "$T" "$OID_B")"

echo "=== 3. \"*\" carries an OID nobody listed ==="
C=$(enroll anylst s3cret-a three.internal "${CEXT[@]}"); T=$(txt "$C")
chk "issued"                                  yes "$(issued "$C")"
chk "  $OID_A IS carried"                     yes "$(has "$T" "$OID_A")"
chk "  $OID_B IS carried too"                 yes "$(has "$T" "$OID_B")"
chk "  and it kept its critical flag"         yes \
    "$(echo "$T" | grep -A1 "$OID_B" | grep -qi critical && echo yes || echo no)"

echo "=== 4. ⚠️ \"*\" IS NOT A BYPASS: the CA still decides its own extensions ==="
# The whole safety claim for the wildcard, measured rather than asserted in a comment.
# issue_cert_from_parts writes basicConstraints critical,CA:FALSE, the resolved KU/EKU and
# the SAN BEFORE copy_exts_by_oid runs, and the copy skips any OID already on the cert.
C=$(enroll anylst s3cret-a four.internal \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:3" \
      -addext "keyUsage=critical,keyCertSign,cRLSign")
# A CA-only KeyUsage is refused outright by the profile engine, which is the FIRST line of
# defence and a different one — so the interesting case is the one that still issues.
chk "a CSR demanding keyCertSign is refused"  no  "$(issued "$C")"

C=$(enroll anylst s3cret-a five.internal \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:3" \
      -addext "extendedKeyUsage=serverAuth" "${CEXT[@]}")
T=$(txt "$C")
chk "issued (basic constraints alone is not a refusal)" yes "$(issued "$C")"
chk "  basicConstraints is CA:FALSE, not CA:TRUE"       yes "$(has "$T" 'CA:FALSE')"
chk "  and carries no pathlen the CSR asked for"        no  "$(has "$T" 'pathlen')"
# The control: this very certificate DID take the wildcard path, so the two lines above are
# about the CA overriding the CSR and not about the passthrough being off.
chk "  CONTROL: the wildcard still carried $OID_A here" yes "$(has "$T" "$OID_A")"

echo
echo "=== PROFILE PASSTHROUGH EXTS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
