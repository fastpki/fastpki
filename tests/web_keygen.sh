#!/usr/bin/env bash
# Browser-side keygen + client-built CSR. The console's "Request a
# certificate using Web Crypto API" form generates the key in the browser (Web Crypto)
# and hand-builds a PKCS#10 CSR — CN + subjectAltName via the extensionRequest
# attribute, EC P-256 (ecdsa-with-SHA256) or RSA — then POSTs it to the unchanged
# /api/certs/request. The JS DER builder is verified in the browser harness; this
# guards the SERVER contract that path depends on: a SAN-bearing EC CSR (the exact
# shape the JS emits) is issued and the SANs are preserved in the cert, and the
# profile/domain policy still governs the requested SANs.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/json_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
unset OPENSSL_CONF
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18225
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

ca_in_token ca.pem "/CN=Keygen CA" 3
cp ca.pem root.pem
printf "internal\n" > domains.txt
pg_setup web_keygen
seed_domains $W/domains.txt   # allowed_domains is the sole source
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > web.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
WEB_SELFSERVICE_IDENTITY_SUBJECT=false
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
seed_ca_from_conf web.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$WEB" --config web.conf >web.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"

code -X POST "$U/api/users" -d 'username=boss&password=bosspw12&role=admin' >/dev/null
curl -s -c boss.cj -X POST "$U/api/login" -d 'username=boss&password=bosspw12' >/dev/null
code -b boss.cj -X POST "$U/api/users" -d 'username=alice&password=alicepw12&role=requester' >/dev/null
curl -s -c alice.cj -X POST "$U/api/login" -d 'username=alice&password=alicepw12' >/dev/null

# An EC P-256 CSR carrying a subjectAltName via extensionRequest — the shape the
# browser form emits (CN in the SAN too, per modern CA practice).
cat > san.cnf <<EOF
[req]
distinguished_name = dn
req_extensions = ext
prompt = no
[dn]
CN = svc.internal
[ext]
subjectAltName = DNS:svc.internal, DNS:alt.internal
EOF
"$OSSL" ecparam -name prime256v1 -genkey -noout -out ec.key >/dev/null 2>&1
"$OSSL" req -new -key ec.key -out ec.csr -config san.cnf >/dev/null 2>&1

echo "=== an EC P-256 CSR with SANs issues, and the SANs are preserved ==="
chk "SAN CSR issue -> 201" 201 "$(code -b alice.cj -X POST --data-binary @ec.csr "$U/api/certs/request?ca_instance=ca-global")"
RESP=$(curl -s -b alice.cj -X POST --data-binary @ec.csr "$U/api/certs/request?ca_instance=ca-global")
chk "response carries a PEM" yes "$(has "$RESP" 'BEGIN CERTIFICATE')"
json_pem "$RESP" pem issued.pem
T=$("$OSSL" x509 -in issued.pem -noout -text 2>/dev/null)
chk "issued cert CN = svc.internal"  yes "$(echo "$T" | grep -Eq 'CN *= *svc.internal' && echo yes || echo no)"
chk "issued cert is EC (P-256)"      yes "$(echo "$T" | grep -q 'id-ecPublicKey' && echo yes || echo no)"
chk "issued cert SAN keeps svc.internal" yes "$(echo "$T" | grep -A1 'Subject Alternative Name' | grep -q 'DNS:svc.internal' && echo yes || echo no)"
chk "issued cert SAN keeps alt.internal" yes "$(echo "$T" | grep -A1 'Subject Alternative Name' | grep -q 'DNS:alt.internal' && echo yes || echo no)"

# The full-attribute form can now emit Ed25519 keys — assert the
# issuance policy accepts an EdDSA subject key (it previously rejected it as an
# "unsupported key algorithm") and the issued leaf is genuinely Ed25519.
echo "=== an Ed25519 CSR is accepted and issued (key-type expansion) ==="
"$OSSL" genpkey -algorithm ED25519 -out ed.key >/dev/null 2>&1
"$OSSL" req -new -key ed.key -out ed.csr -config san.cnf >/dev/null 2>&1
chk "Ed25519 CSR issue -> 201" 201 "$(code -b alice.cj -X POST --data-binary @ed.csr "$U/api/certs/request?ca_instance=ca-global")"
json_pem "$(curl -s -b alice.cj -X POST --data-binary @ed.csr "$U/api/certs/request?ca_instance=ca-global")" pem ed.pem
chk "issued cert is Ed25519" yes "$("$OSSL" x509 -in ed.pem -noout -text 2>/dev/null | grep -qi 'Public Key Algorithm: ED25519' && echo yes || echo no)"

# ⚠️ AND THE Ed448 TWIN. check_key_size() has accepted EVP_PKEY_ED448 alongside Ed25519 all
# along — but the console listed Ed25519 in every key-algorithm dropdown and Ed448 in none,
# so a capability the product had was one no operator could reach from the UI. Asserted
# here rather than in the served HTML: what matters is that the issuance policy really does
# accept an Ed448 subject key, not that a particular <option> string is present.
echo "=== an Ed448 CSR is accepted and issued ==="
"$OSSL" genpkey -algorithm ED448 -out ed448.key >/dev/null 2>&1
"$OSSL" req -new -key ed448.key -out ed448.csr -config san.cnf >/dev/null 2>&1
chk "Ed448 CSR issue -> 201" 201 "$(code -b alice.cj -X POST --data-binary @ed448.csr "$U/api/certs/request?ca_instance=ca-global")"
json_pem "$(curl -s -b alice.cj -X POST --data-binary @ed448.csr "$U/api/certs/request?ca_instance=ca-global")" pem ed448.pem
chk "issued cert is Ed448" yes "$("$OSSL" x509 -in ed448.pem -noout -text 2>/dev/null | grep -qi 'Public Key Algorithm: ED448' && echo yes || echo no)"

echo "=== policy still governs a SAN outside the domain allowlist ==="
cat > bad.cnf <<EOF
[req]
distinguished_name = dn
req_extensions = ext
prompt = no
[dn]
CN = svc.internal
[ext]
subjectAltName = DNS:svc.internal, DNS:leak.example.com
EOF
"$OSSL" req -new -key ec.key -out bad.csr -config bad.cnf >/dev/null 2>&1
chk "SAN outside the allowlist -> 400" 400 "$(code -b alice.cj -X POST --data-binary @bad.csr "$U/api/certs/request?ca_instance=ca-global")"

echo "=== The form does NOT auto-populate the SAN from CN or email ==="
# The CN is not necessarily a DNS name (e.g. a client-identity profile forbids DNS
# SANs), so force-adding it to the SAN made those requests fail policy
# ('DNS SAN not permitted by profile'). generateCert() must send only the SANs the
# user typed. Guard against re-introducing the auto-population.
SRC="$ROOT/src/web/main.cpp"
chk "no auto 'sans.unshift(cn)' in the form"   "" "$(grep -F 'sans.unshift(cn)' "$SRC")"
chk "no auto 'sans.push(email)' in the form"   "" "$(grep -F 'sans.push(email)' "$SRC")"
chk "form renamed to 'Web Crypto API'"        yes "$(grep -q 'Request a certificate using Web Crypto API' "$SRC" && echo yes || echo no)"

echo "=== RSASSA-PSS: an RSA-PSS CSR issues correctly (RFC 4055 §3) ==="
# Generate an RSA-PSS key (genpkey handles the PSS params; -sha256 at req time
# sets the hash for the CSR signature). The key type is rsassaPss per the
# SubjectPublicKeyInfo OID — verify the server accepts it.
"$OSSL" genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out pss.key 2>/dev/null
"$OSSL" req -new -key pss.key -out pss.csr -sha256 -subj "/CN=pss.internal" 2>/dev/null
chk "RSA-PSS CSR issue -> 201" 201 "$(code -b alice.cj -X POST --data-binary @pss.csr "$U/api/certs/request?ca_instance=ca-global")"
json_pem "$(curl -s -b alice.cj -X POST --data-binary @pss.csr "$U/api/certs/request?ca_instance=ca-global")" pem pss.pem
PSS_T=$("$OSSL" x509 -in pss.pem -noout -text 2>/dev/null)
chk "issued cert public key is rsassaPss" yes "$(echo "$PSS_T" | grep -q 'Public Key Algorithm: rsassaPss' && echo yes || echo no)"
# The issued cert's signature is sha256WithRSAEncryption because the CA key is
# RSA (not RSA-PSS); the PSS signature is in the CSR, not the cert.
chk "issued cert CN = pss.internal" yes "$(echo "$PSS_T" | grep -Eq 'CN *= *pss.internal' && echo yes || echo no)"

echo "=== The key panel comes BEFORE key usage, under SAN ==="
# The ask: the key panel belongs above the key-usage panel and under the SAN panel — it
# is logical to select the key type first and then select what it is for.
#
# ⚠️ Asserted as ORDER, by byte offset in the served page — not by presence. All three
# panels existed before and after, so any "is the Key panel there?" check passes against
# the bug. This is one of the few UI properties a shell suite can judge honestly.
PAGE=$(curl -s -b boss.cj "$U/" | tr '\n' ' ')
# ⚠️ NOT `grep -bo` — busybox grep has NO -b, so on the image we ship it printed a usage
# dump instead of an offset, every position came back unusable, and all three checks failed
# as though the console had stopped emitting the panels. Measured on the lab tier:
#   grep -bo '<fieldset><legend>Key</legend>' -> "BusyBox ... -A N Print N lines of ..."
# while the shipped page really does contain all three <fieldset><legend> markers.
#
# ⚠️ THIS IS THE THIRD SITE. web_hsm_leaf.sh:447 and web_endpoint_controls.sh:203 already
# carry this same warning; the panel-order guard was written afterwards with the bug they document,
# so the check has never once run on the platform we ship. awk's index() is literal (not a
# regex) and exists on busybox and GNU alike. Flatten first — awk is line-oriented, so on
# multi-line HTML a per-line index() yields one mostly-empty result per line.
off(){ printf '%s' "$PAGE" | awk -v n="<fieldset><legend>$1</legend>" \
         '{i=index($0,n); if (i) {print i-1; exit}}'; }
O_SAN=$(off 'Subject alternative names'); O_KEY=$(off 'Key'); O_KU=$(off 'Key usage')
chk "PRECONDITION: all three panels are on the page" yes \
    "$([ -n "$O_SAN" ] && [ -n "$O_KEY" ] && [ -n "$O_KU" ] && echo yes || echo no)"
chk "Key comes after Subject alternative names" yes \
    "$([ -n "$O_SAN" ] && [ -n "$O_KEY" ] && [ "$O_KEY" -gt "$O_SAN" ] && echo yes || echo no)"
chk "  and BEFORE Key usage"                    yes \
    "$([ -n "$O_KEY" ] && [ -n "$O_KU" ] && [ "$O_KEY" -lt "$O_KU" ] && echo yes || echo no)"

echo
echo "=== WEB KEYGEN: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
