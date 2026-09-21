#!/usr/bin/env bash
# Custom certificate extensions + suppress-default-extension flags on a cert
# profile. Drives EST enrollment to prove a profile can (a) stamp
# arbitrary custom extensions on issued certs — a known-NID one (id-pkix-ocsp-
# nocheck, 1.3.6.1.5.5.7.48.1.5) and an unknown critical OID — and (b) suppress
# the CA-added AIA / CRL DP, so an authorized OCSP-responder cert carries
# ocsp-nocheck and neither AIA nor CRLDP. A control profile ('requester', from an
# unassigned user) still gets AIA/CRLDP and no custom ext, proving the flags are
# per-profile. Asserts by decoding the real issued cert (openssl x509 -text).
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
W="$(mktemp -d)"; cd "$W"; PORT=18272
P=
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

ca_in_token ca.pem "/CN=CustExt CA" 3
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup profile_custom_exts
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
seed_web_user ctl s3cret-c requester
seed_web_user ocsp s3cret-o requester
# Grant the OCSP-responder profile to user 'ocsp'; 'ctl' gets no grant at all -> an empty
# union -> the CA default ('requester'), which keeps AIA/CRLDP and stamps no custom ext.
grant_profile ocsp ocspresp
# Split what used to be one profile's job in two. 'mayomit' is the same shape —
# custom extension, manage_aia/manage_crldp both true — but WITHOUT id-pkix-ocsp-nocheck,
# so it is the one that still shows the rule: permission to omit is not omission, and
# EST has no field to ask with. The nocheck profile can no longer carry that assertion.
seed_web_user omit s3cret-m requester
grant_profile omit mayomit

# The custom profile: two custom extensions (known-NID id-pkix-ocsp-nocheck with a
# NULL value + an unknown critical OID carrying a UTF8String) and both AIA/CRLDP
# suppress flags set — the authorized-OCSP-responder shape.
PJSON='{"ocspresp":{"allowed_ku":["digitalSignature","keyEncipherment"],"allowed_eku":["OCSPSigning","clientAuth"],"default_ku":["digitalSignature"],"default_eku":["OCSPSigning"],"allow_wildcard":false,"custom_extensions":[{"oid":"1.3.6.1.5.5.7.48.1.5","value":"DER:05:00","critical":false},{"oid":"1.2.3.4.5.6.7","value":"ASN1:UTF8:hello","critical":true}],"manage_aia":true,"manage_crldp":true},"mayomit":{"allowed_ku":["digitalSignature","keyEncipherment"],"allowed_eku":["serverAuth","clientAuth"],"default_ku":["digitalSignature"],"default_eku":["serverAuth"],"allow_wildcard":false,"custom_extensions":[{"oid":"1.2.3.4.5.6.8","value":"ASN1:UTF8:world","critical":false}],"manage_aia":true,"manage_crldp":true}}'

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
seed_cert_profiles "$PJSON"
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)

"$ROOT/build/fastpki-est" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "est died:"; cat srv.log; exit 1; fi

# enroll USER PASS CN [openssl-req-args...] -> prints the issued PEM (empty on reject)
enroll(){ local u=$1 p=$2 s=$3; shift 3
  "$OSSL" req -new -subj "/CN=$s" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr "$@" >/dev/null 2>&1
  "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
  curl -sk -u "$u:$p" --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
    "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll" \
    | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null
}
txt(){ echo "$1" | "$OSSL" x509 -noout -text 2>/dev/null; }
issued(){ has "$1" "BEGIN CERTIFICATE"; }

echo "=== control profile 'requester' (unassigned user): AIA/CRLDP present, no custom ext ==="
C=$(enroll ctl s3cret-c host.internal); T=$(txt "$C")
chk "control cert issued"                     yes "$(issued "$C")"
chk "control has AIA"                          yes "$(has "$T" 'Authority Information Access')"
chk "control has CRL Distribution Points"      yes "$(has "$T" 'CRL Distribution Points')"
chk "control has NO OCSP No Check"             no  "$(has "$T" 'OCSP No Check')"
chk "control has NO custom OID 1.2.3.4.5.6.7"  no  "$(has "$T" '1.2.3.4.5.6.7')"

echo "=== 'ocspresp' profile: custom extensions stamped, AIA/CRLDP suppressed ==="
C=$(enroll ocsp s3cret-o resp.internal); T=$(txt "$C")
chk "responder cert issued"                    yes "$(issued "$C")"
chk "has OCSP No Check (id-pkix-ocsp-nocheck)"  yes "$(has "$T" 'OCSP No Check')"
chk "has unknown custom OID 1.2.3.4.5.6.7"      yes "$(has "$T" '1.2.3.4.5.6.7')"
chk "unknown custom OID marked critical"        yes "$(has "$T" '1.2.3.4.5.6.7: critical')"
chk "custom OID value 'hello' present"          yes "$(has "$T" 'hello')"
# ⚠️ A NOCHECK CERTIFICATE HAS NO AIA AND NO CRLDP, whoever asked and however.
#
# These two assertions used to expect them PRESENT, on the reasoning that `manage_aia` means
# "the requester MAY omit", EST has no field to ask with, so permission is not omission.
# The reasoning is right and still applies — but not to this certificate. id-pkix-ocsp-nocheck
# says "do not check this certificate's revocation status" and AIA(OCSP)/CRLDP say "check it,
# here"; a certificate carrying both gives a relying party two opposite instructions, and
# `fastpki-ocsp` logged an ERR for each on every request it answered. There is no request that
# makes that combination correct, so it is not a request-level choice any more.
#
# The property is still asserted, on 'mayomit' below — same manage_* flags, no nocheck.
chk "no AIA — nocheck forbids it"               no  "$(has "$T" 'Authority Information Access')"
chk "no CRL DP — same reason"                   no  "$(has "$T" 'CRL Distribution Points')"

echo "=== 'mayomit' profile: may omit, but EST cannot ask — so both stay ==="
C=$(enroll omit s3cret-m may.internal); T=$(txt "$C")
chk "mayomit cert issued"                      yes "$(issued "$C")"
# The control that keeps the assertion above honest: this profile sets exactly the same
# manage_aia/manage_crldp, so if suppression were coming from those flags rather than from
# nocheck, this certificate would have lost them too.
chk "its custom OID 1.2.3.4.5.6.8 is stamped"  yes "$(has "$T" '1.2.3.4.5.6.8')"
chk "AIA present — EST cannot ask to omit it"  yes "$(has "$T" 'Authority Information Access')"
chk "CRL DP present — same reason"             yes "$(has "$T" 'CRL Distribution Points')"

echo
echo "=== CUSTOM EXT PROFILE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
