#!/usr/bin/env bash
# The CAs page, cross-node sub-CA round trip.
#
# A subordinate CA whose key must stay inside its OWN node's token cannot be made by the
# ordinary create path: that mints the key and signs it in one request, which needs the
# parent's key to be local. So the operation splits in two, with a PKCS#10 request
# carrying the public half across the gap:
#
#     POST /api/ca-instances/csr        key minted here, request out
#     POST /api/ca-instances/sign-csr   somebody else's request, certificate out
#     POST /api/ca-instances            the existing import, on the requesting node
#
# Both halves are driven here against real token keys and every artifact is DECODED —
# a certificate whose public half does not match the key in the token is issued, stored
# and reported successful, and is inert. Section 6 is the assertion that would catch it:
# the imported sub-CA has to actually sign a leaf.
#
# Skips cleanly where SoftHSM / the pkcs11 provider are not installed.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/json_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: that default path is a Linux convention and is absent on some dev boxes. Without
# this the suite still RUNS, every "$OSSL" call fails silently, and each assertion compares
# against an empty string — which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"   # macOS
unset OPENSSL_CONF 2>/dev/null; export OPENSSL_CONF=""
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18131
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
skipout(){ echo "  [SKIP] $1"; echo; echo "=== WEB CA CSR: PASS=$pass FAIL=$fail SKIP=1 ==="; exit 0; }

pg_setup web_ca_csr
trap 'pg_cleanup; kill ${P:-} 2>/dev/null' EXIT
# One token directory, owned by the harness — ca_in_token starts the shared p11-kit server
# in this shell and exports SOFTHSM2_CONF for it (§3d: a suite must run standalone).
ca_in_token ca.pem "/CN=Bootstrap CA" 3650
URI=$(hsm_ca_key csrca) || skipout "could not mint a CA key in a token"
TOK=$(sed -n 's/.*token=\([^;?]*\).*/\1/p' <<<"$URI")
intoken(){ "$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$TOK" --list-objects \
    --login --pin 1234 2>/dev/null | grep -q "$1" && echo yes || echo no; }
# How MANY objects carry this label. `intoken` answers presence, which cannot see the
# failure this guards against: minting a second key beside the first leaves the label
# present either way, so only a count distinguishes "refused" from "refused, but minted
# anyway".
objcount(){ "$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$TOK" --list-objects \
    --login --pin 1234 2>/dev/null | grep -c "$1" || true; }
source "$ROOT/tests/user_helpers.sh"
seed_web_user boss bosspw admin
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
PKI_DNS=pki.example.org
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf
"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat srv.log; skipout "fastpki-web could not start"; fi
U="http://127.0.0.1:$PORT"
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null
code(){ curl -s -o /dev/null -w '%{http_code}' -b boss.cj "$@"; }
body(){ curl -s -b boss.cj "$@"; }
# PEM comes back as a JSON string with literal \n two-character sequences. json_pem()
# decodes it with printf %b, which is POSIX. The sed this replaces (s/\\n/\n/g) has a
# GNU-only replacement side and did NOTHING on macOS — it only looked correct because
# python had already decoded the escapes before sed ever saw them. Dropping python without
# this would have written PEM full of literal "n". Its second arm (\/ -> /) was dead too:
# json_escape() in src/web/main.cpp escapes no forward slash, so that sequence never
# arrives, and it is not carried over.
#
# ca_field(): one CA record's field, or "?" when there is no such record. The distinction
# is kept deliberately — an absent record and a present-but-blank field are different
# failures, and the python this replaces reported them differently too.
ca_field(){ # <json> <ca-id> <field>
    # json_elems + an explicit match rather than json_rec(): json_rec greps -F for
    # "id":"x" with NO whitespace between the colon and the value, so it silently finds
    # nothing against pretty-printed JSON — while json_str, one function above it, is
    # deliberately whitespace-tolerant for exactly that reason. The console emits compact
    # JSON today so json_rec would work, but an assertion that reads "?" the day an
    # encoder adds a space is the failure this file was written to stop.
    local _rec
    _rec=$(json_elems "$1" | grep -E "\"id\"[[:space:]]*:[[:space:]]*\"$2\"" | head -1)
    [ -n "$_rec" ] || { echo "?"; return; }
    json_str "$_rec" "$3"
}

echo "=== 1. the parent CA, key in this node's token ==="
ROOTURI="pkcs11:token=$TOK;object=rootk;id=%11;type=private?pin-value=1234"
C=$(code "$U/api/ca-instances" --data-urlencode 'id=parent-ca' --data-urlencode 'name=Parent CA' \
    --data-urlencode 'subject=/CN=Parent CA/O=FastPKI' --data-urlencode 'keyloc=pkcs11' \
    --data-urlencode "keyref=$ROOTURI" --data-urlencode 'keygen=true' \
    --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' --data-urlencode 'pathlen=2')
if [ "$C" != 201 ]; then echo "parent create failed ($C):"; tail -8 srv.log; skipout "could not create the parent CA (provider ABI?)"; fi
chk "create parent-ca -> 201" 201 "$C"
body "$U/api/ca-instances/parent-ca/cert-pem" > parent.pem
chk "parent cert is served"  yes "$(grep -qc 'BEGIN CERTIFICATE' parent.pem >/dev/null && echo yes || echo no)"

echo "=== 2. POST /api/ca-instances/csr — key minted in the token, request returned ==="
SUBURI="pkcs11:token=$TOK;object=subk;id=%12;type=private?pin-value=1234"
R=$(body "$U/api/ca-instances/csr" \
    --data-urlencode 'subject=/CN=Sub CA DC2/O=FastPKI' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$SUBURI" \
    --data-urlencode 'keygen=true' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
    --data-urlencode 'md=sha256' --data-urlencode 'pathlen=0' \
    --data-urlencode 'ncPermitted=DNS:dc2.example.com')
json_pem "$R" csr sub.csr
if ! grep -q 'BEGIN CERTIFICATE REQUEST' sub.csr; then
    echo "csr endpoint said: $R"; tail -8 srv.log; skipout "the CSR endpoint returned no request"; fi
chk "a PEM PKCS#10 request came back" yes "$(grep -q 'BEGIN CERTIFICATE REQUEST' sub.csr && echo yes || echo no)"
chk "the key really is in the token"  yes "$(intoken subk)"
CT=$("$OSSL" req -in sub.csr -noout -text 2>/dev/null)
chk "request subject is what was asked for" yes \
    "$(echo "$CT" | grep -Eq 'Subject:.*CN *= *Sub CA DC2' && echo yes || echo no)"
# ⚠️ THE SIGNATURE IS THE PROOF OF POSSESSION, and it is made by the TOKEN key. A request
# whose signature does not verify is one the signer must refuse, so if this is wrong the
# whole round trip is dead at the second step — and `openssl req` prints the request
# happily either way, which is why this is asserted rather than eyeballed.
chk "the request is self-signed by the token key (POP verifies)" \
    "Certificate request self-signature verify OK" \
    "$("$OSSL" req -in sub.csr -noout -verify 2>&1 | tail -1)"
chk "the request asks for basicConstraints CA:TRUE" yes \
    "$(echo "$CT" | grep -q 'CA:TRUE' && echo yes || echo no)"
chk "  with the pathlen it asked for"               yes \
    "$(echo "$CT" | grep -q 'pathlen:0' && echo yes || echo no)"
chk "the request asks for keyCertSign + cRLSign"    yes \
    "$(echo "$CT" | grep -q 'Certificate Sign, CRL Sign' && echo yes || echo no)"
chk "  and the name constraint it asked for"        yes \
    "$(echo "$CT" | grep -q 'DNS:dc2.example.com' && echo yes || echo no)"
# ⚠️ AIA/CRLDP NAME THE ISSUER, so a REQUEST cannot carry them — the requester does not
# know who will sign it. build_ca_csr drops them; this is what says so.
chk "the request carries NO AIA"  no "$(echo "$CT" | grep -q 'Authority Information Access' && echo yes || echo no)"
chk "the request carries NO CRLDP" no "$(echo "$CT" | grep -q 'CRL Distribution' && echo yes || echo no)"
# ⚠️ NOTHING IS REGISTERED YET. A keypair and a request are not a CA, and a row here would
# claim this node holds a CA it has no certificate for.
chk "no CA row was written for it" 0 "$(pg_exec "SELECT count(*) FROM certs WHERE id IS NOT NULL AND cn LIKE 'Sub CA DC2%';")"

echo "=== 2b. FIPS 186-5: an EC key may be paired with a SHA-3 digest ==="
# The prehash path computes the hash in SOFTWARE and sends only the raw signature to the
# token, so the token's mechanism list has no say in which digest is used. The only real
# constraint is whether an OID exists to name the pair. FIPS 186-5 approves ECDSA with the
# whole SHA-2 and SHA-3 families; refusing SHA-3 was our own table being short, not a limit
# of the standard or of the hardware.
ECURI="pkcs11:token=$TOK;object=subkec;id=%13;type=private?pin-value=1234"
R3=$(body "$U/api/ca-instances/csr" \
    --data-urlencode 'subject=/CN=Sub CA EC SHA3/O=FastPKI' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$ECURI" \
    --data-urlencode 'keygen=true' --data-urlencode 'key=ec' --data-urlencode 'curve=P-521' \
    --data-urlencode 'md=sha3-512')
json_pem "$R3" csr ec.csr
if ! grep -q 'BEGIN CERTIFICATE REQUEST' ec.csr; then
    echo "  [note] EC+SHA3 CSR endpoint said: $(echo "$R3" | head -c 200)"
fi
chk "an EC P-521 key with SHA3-512 produces a request" yes \
    "$(grep -q 'BEGIN CERTIFICATE REQUEST' ec.csr && echo yes || echo no)"
ECT=$("$OSSL" req -in ec.csr -noout -text 2>/dev/null)
chk "  the key really is EC P-521"        yes "$(echo "$ECT" | grep -qi 'P-521\|secp521r1' && echo yes || echo no)"
# ⚠️ DECODE THE SIGNATURE ALGORITHM, do not settle for "it produced something". A request
# signed under a silently-substituted SHA-256 would still parse, still verify, and still
# look like success -- and would mean the digest the operator asked for was ignored.
chk "  and it is signed ecdsa-with-SHA3-512" yes \
    "$(echo "$ECT" | grep -qiE 'ecdsa.with.SHA3.512' && echo yes || echo no)"
chk "  the request's own signature verifies" "Certificate request self-signature verify OK" \
    "$("$OSSL" req -in ec.csr -noout -verify 2>&1 | tail -1)"

echo "=== 3. POST /api/ca-instances/sign-csr — the certificate, from the parent ==="
# ⚠️ THE PARENT NEEDS A RESPONDER CREDENTIAL for an AIA OCSP URI to be emitted at all. We
# only advertise a responder the ISSUER can actually answer with — an offline root normally
# has none and publishes a CRL instead. `parent-ca` is a fixture, so it gets one here: what
# section 3 is about is that the three extensions name the PARENT, which needs them present.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout wcc.key -out ocsp-ra-parent-ca.pem \
    -subj "/CN=Responder For parent-ca" -days 365 >/dev/null 2>&1
pg_insert_cert ocsp-ra-parent-ca.pem 0 test standard >/dev/null 2>&1
pg_exec "UPDATE certs SET cert_id='ocsp-ra-parent-ca' WHERE cn='ocsp-ra-parent-ca';" >/dev/null 2>&1
R=$(body "$U/api/ca-instances/sign-csr" --data-urlencode "csr@sub.csr" \
    --data-urlencode 'parent=parent-ca' --data-urlencode 'days=1825' \
    --data-urlencode 'pathlen=0' --data-urlencode 'aiaIssuers=true' \
    --data-urlencode 'crldp=true' --data-urlencode 'aiaOcsp=true')
json_pem "$R" cert sub.pem
if ! grep -q 'BEGIN CERTIFICATE' sub.pem; then
    echo "sign-csr said: $R"; tail -8 srv.log; skipout "the sign-csr endpoint returned no certificate"; fi
chk "a PEM certificate came back" yes "$(grep -q 'BEGIN CERTIFICATE' sub.pem && echo yes || echo no)"
ST=$("$OSSL" x509 -in sub.pem -noout -text 2>/dev/null)
chk "it is a CA (CA:TRUE)"            yes "$(echo "$ST" | grep -q 'CA:TRUE' && echo yes || echo no)"
chk "subject came from the REQUEST"   yes "$(echo "$ST" | grep -Eq 'Subject:.*CN *= *Sub CA DC2' && echo yes || echo no)"
chk "issued by the parent"            yes "$(echo "$ST" | grep -Eq 'Issuer:.*CN *= *Parent CA' && echo yes || echo no)"
chk "openssl VERIFIES it against the parent" "sub.pem: OK" \
    "$("$OSSL" verify -CAfile parent.pem sub.pem 2>/dev/null)"
# ⚠️ THE PUBLIC KEY MUST BE THE ONE IN THE TOKEN. If the signer certified a different key
# the certificate still decodes, still verifies against the parent, still imports and is
# completely inert — the sub-CA cannot sign anything, and nothing anywhere reports an
# error. Comparing the SPKI of the request and the certificate is what rules that out.
chk "the certified key is the request's key" \
    "$("$OSSL" req -in sub.csr -noout -pubkey 2>/dev/null | "$OSSL" sha256 2>/dev/null)" \
    "$("$OSSL" x509 -in sub.pem -noout -pubkey 2>/dev/null | "$OSSL" sha256 2>/dev/null)"
# All three URLs are DERIVED from the signing CA. The form sends booleans, so there is
# nothing to mistype — and nothing a hand-built POST could bake in.
chk "AIA caIssuers is the PARENT's cert"  yes \
    "$(echo "$ST" | grep -Eq 'CA Issuers - URI:http://pki\.example\.org:8080/parent-ca/[0-9A-Fa-f]+\.p7c' && echo yes || echo no)"
chk "CRL DP is the PARENT's CRL"          yes \
    "$(echo "$ST" | grep -q 'URI:http://pki.example.org:8080/parent-ca.crl' && echo yes || echo no)"
chk "AIA OCSP is the PARENT's responder"  yes \
    "$(echo "$ST" | grep -q 'OCSP - URI:http://pki.example.org:8080/ocsp' && echo yes || echo no)"
chk "  and none of them names the SUBJECT" no \
    "$(echo "$ST" | grep -q 'sub-ca-dc2' && echo yes || echo no)"
# ⚠️ SIGNING RECORDS THE CERTIFICATE AND REGISTERS NO CA. A CA that kept no record of a CA
# certificate it signed could neither list nor revoke it. The record is the certificate of a
# CA this node holds no key for — no id, no key, the signer as ca_instance_id — and the CA
# itself belongs to the node holding the key, which registers it on this row at import.
SERIAL=$(json_str "$R" serial)
chk "the response names the serial"  yes "$([ -n "$SERIAL" ] && echo yes || echo no)"
chk "signing recorded the certificate: a CA certificate, no id, no key, under its signer" \
    "true||parent-ca|" \
    "$(pg_exec "SELECT is_ca||'|'||coalesce(id,'')||'|'||ca_instance_id||'|'||coalesce(private_key,'') FROM certs WHERE serial='$SERIAL';" | tr -d ' ')"
chk "signing registered NO CA"        0  "$(pg_exec "SELECT count(*) FROM certs WHERE id='sub-ca-dc2';")"

echo "=== 4. refusals ==="
chk "no parent -> 400"        400 "$(code "$U/api/ca-instances/sign-csr" --data-urlencode "csr@sub.csr")"
chk "no csr -> 400"           400 "$(code "$U/api/ca-instances/sign-csr" --data-urlencode 'parent=parent-ca')"
chk "garbage csr -> 400"      400 "$(code "$U/api/ca-instances/sign-csr" --data-urlencode 'parent=parent-ca' --data-urlencode 'csr=-----BEGIN CERTIFICATE REQUEST-----
bm90IGEgY3Ny
-----END CERTIFICATE REQUEST-----')"
chk "unknown parent -> 404"   404 "$(code "$U/api/ca-instances/sign-csr" --data-urlencode "csr@sub.csr" --data-urlencode 'parent=nope')"
# The key floor CA creation and import apply: signing a CA request is creating a CA.
"$OSSL" req -new -newkey rsa:1024 -nodes -keyout weak.key -out weak.csr -subj '/CN=Weak Sub CA' >/dev/null 2>&1
chk "fixture: a 1024-bit CA request" yes "$([ -s weak.csr ] && echo yes || echo no)"
chk "a CA request below the key floor -> 400" 400 \
    "$(code "$U/api/ca-instances/sign-csr" --data-urlencode "csr@weak.csr" --data-urlencode 'parent=parent-ca')"
chk "csr: no subject -> 400"  400 "$(code "$U/api/ca-instances/csr" --data-urlencode "keyref=$SUBURI")"
chk "csr: a file path is not a token handle -> 400" 400 \
    "$(code "$U/api/ca-instances/csr" --data-urlencode 'subject=/CN=x' --data-urlencode 'keyref=/tmp/k.pem')"
# The refusal must land BEFORE anything is minted: a keypair orphaned in hardware by a
# rejected request is invisible and permanent.
chk "  and nothing was minted for it" no "$(intoken 'k.pem')"

# ⚠️ THE COLLISION THIS FORM NEVER CHECKED. $SUBURI already holds the key minted in
# section 2, so asking to GENERATE there again used to mint a SECOND object with the same
# label — after which a pkcs11: URI naming that label cannot say which key it means, and
# neither can anything that later loads the CA. The Inventory form has refused this for a
# long time via /api/certs/request-hsm; this route went straight to generate_key_in_token().
SUBOBJ=$(printf '%s' "$SUBURI" | sed -n 's/.*object=\([^;?]*\).*/\1/p')
COLL_BEFORE=$(objcount "$SUBOBJ")
chk "csr: generating over an occupied handle -> 409" 409 \
    "$(code "$U/api/ca-instances/csr" --data-urlencode 'subject=/CN=collide' \
       --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$SUBURI" \
       --data-urlencode 'keygen=true')"
# The refusal must be FREE: no second object, or the guard merely relocated the problem.
chk "  and no second object was minted" "$COLL_BEFORE" "$(objcount "$SUBOBJ")"
chk "  and it is machine-readable, so the console can offer to replace" yes \
    "$(body "$U/api/ca-instances/csr" --data-urlencode 'subject=/CN=collide2' \
       --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$SUBURI" \
       --data-urlencode 'keygen=true' | grep -q '"handleTaken":true' && echo yes || echo no)"
# Ticking "use an existing key" is the way through, and it builds a request.
chk "  building the request over the existing key -> 201" 201 \
    "$(code "$U/api/ca-instances/csr" --data-urlencode 'subject=/CN=adopted' \
       --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$SUBURI" \
       --data-urlencode 'keygen=false')"

echo "=== 5. import on the requesting node — the existing form, unchanged ==="
C=$(code "$U/api/ca-instances" --data-urlencode 'id=sub-ca-dc2' --data-urlencode 'name=Sub CA DC2' \
    --data-urlencode "cert_pem@sub.pem" --data-urlencode 'keyloc=pkcs11' --data-urlencode "key=$SUBURI")
chk "import the signed sub-CA -> 201" 201 "$C"
chk "it is registered now"             1  "$(pg_exec "SELECT count(*) FROM certs WHERE id='sub-ca-dc2' AND is_ca;")"
# The signer's record was ADOPTED, not duplicated or refused: still one row for the serial,
# now carrying the CA's own id.
chk "  on the signer's record: one row for the serial, the CA's own id" "1|sub-ca-dc2|sub-ca-dc2" \
    "$(pg_exec "SELECT count(*)||'|'||max(id)||'|'||max(ca_instance_id) FROM certs WHERE serial='$SERIAL';" | tr -d ' ')"
chk "  and importing it again is refused (409)" 409 \
    "$(code "$U/api/ca-instances" --data-urlencode 'id=sub-ca-dc2b' --data-urlencode "cert_pem@sub.pem" \
            --data-urlencode 'keyloc=pkcs11' --data-urlencode "key=$SUBURI")"
chk "  against the key that made the request" "$SUBURI" \
    "$(pg_exec "SELECT coalesce(private_key,'') FROM certs WHERE id='sub-ca-dc2' AND is_ca;")"
chk "  and the parent is derived from the issuer" parent-ca \
    "$(ca_field "$(body "$U/api/ca-instances")" sub-ca-dc2 parentId)"

body "$U/" > page.html
echo "=== 5b. an import does not depend on its signer being online ==="
# ⚠️ THE OFFLINE ROOT IS THE NORMAL CASE, not an edge case: a root that signs a
# per-data-center sub-CA and is then disabled is the recommended posture. The import used to
# run the CREATION parent checks, so naming that root refused the import with "parent CA
# instance is disabled" -- a correctly signed certificate rejected for a property of a CA
# that is not being asked to do anything. The form no longer offers the field; this asserts
# the server does not require it either, which is the half a hand-built POST could bypass.
# A DISTINCT certificate: importing the same one twice would collide on certs.serial,
# which is the primary key, and a 500 from that would look like this fix failing.
# TWO distinct certificates, both signed while the parent is still active: importing the
# same one twice would collide on certs.serial (the primary key) and a 500 from that would
# read as this fix failing.
for n in 1 2; do
    json_pem "$(body "$U/api/ca-instances/sign-csr" --data-urlencode "csr@ec.csr" \
         --data-urlencode 'parent=parent-ca' --data-urlencode 'days=1825')" cert "ec-sub$n.pem"
done
chk "two distinct sub-CA certificates to import" yes \
    "$([ -s ec-sub1.pem ] && [ -s ec-sub2.pem ] && \
       [ "$("$OSSL" x509 -in ec-sub1.pem -noout -serial 2>/dev/null)" != \
         "$("$OSSL" x509 -in ec-sub2.pem -noout -serial 2>/dev/null)" ] && echo yes || echo no)"
curl -s -o /dev/null -b boss.cj "$U/api/ca-instances/parent-ca/status?status=disabled" -X POST
chk "the signer is now disabled" disabled \
    "$(ca_field "$(body "$U/api/ca-instances")" parent-ca status)"
C=$(code "$U/api/ca-instances" --data-urlencode 'id=sub-offline' --data-urlencode 'name=Sub Offline' \
    --data-urlencode "cert_pem@ec-sub1.pem" --data-urlencode 'keyloc=pkcs11' --data-urlencode "key=$ECURI")
# A CONTROL, not the guard: this one sends no `parent` at all, so it passed before the fix
# too. It is here to show that a parentless import was never the broken case -- the refusal
# needed the field to be present, which is exactly what the form was supplying.
chk "importing under a DISABLED signer still works -> 201" 201 "$C"
# And a stale `parent` on the wire is ignored rather than re-introducing the refusal.
# ⚠️ A HAND-BUILT POST CAN STILL SEND `parent`, so the server must ignore it rather than
# rely on the form having dropped the field. A FRESH id and a FRESH certificate: reusing
# either would return 409 for being a duplicate, and this assertion could not tell that
# apart from the parent refusal it exists to rule out.
C=$(code "$U/api/ca-instances" --data-urlencode 'id=sub-offline-b' --data-urlencode 'name=Sub Offline B' \
    --data-urlencode "cert_pem@ec-sub2.pem" --data-urlencode 'keyloc=pkcs11' --data-urlencode "key=$ECURI" \
    --data-urlencode 'parent=parent-ca')
chk "  an explicitly sent parent is ignored, not refused -> 201" 201 "$C"
chk "  the parent is still derived from the certificate" parent-ca \
    "$(ca_field "$(body "$U/api/ca-instances")" sub-offline parentId)"
chk "the import form offers no parent picker" no \
    "$(grep -q 'caimportform' page.html && grep -A12 'ca-importform' page.html | grep -q 'name=\"parent\"' && echo yes || echo no)"
curl -s -o /dev/null -b boss.cj "$U/api/ca-instances/parent-ca/status?status=active" -X POST

echo "=== 6. ⚠️ the round trip is only real if the sub-CA can SIGN ==="
# Everything above passes for a certificate over the WRONG key: it decodes, it verifies
# against the parent, it imports and the console lists it. This is the assertion that
# separates a working sub-CA from an inert one — the product loads the key named in the
# row and signs with it.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr \
    -subj "/CN=host.dc2.example.com" >/dev/null 2>&1
ISS=$(curl -s -o leaf.json -w '%{http_code}' -b boss.cj -X POST --data-binary @leaf.csr \
      "$U/api/certs/request?ca_instance=sub-ca-dc2")
if [ "$ISS" != 201 ]; then echo "  leaf issuance said $ISS:"; head -c 300 leaf.json; echo; tail -6 srv.log; fi
chk "the imported sub-CA issues a leaf -> 201" 201 "$ISS"
json_pem "$(cat leaf.json)" pem leaf.pem
chk "the leaf decodes"                 yes "$("$OSSL" x509 -in leaf.pem -noout -subject >/dev/null 2>&1 && echo yes || echo no)"
cat sub.pem parent.pem > chain.pem
chk "and it CHAINS to the parent through the sub-CA" "leaf.pem: OK" \
    "$("$OSSL" verify -CAfile parent.pem -untrusted sub.pem leaf.pem 2>/dev/null)"

echo "=== 6b. renewing a sub CA whose parent's key is elsewhere: the CSR route ==="
# A sub CA's renewal is signed by its parent. When the parent's key is on another node — a
# root on one node and a sub CA per node — renew refuses and names the route: a CSR here,
# signed there, imported here under the SAME id as the CA's next certificate. The parent is
# an anchor registered with no key, which is exactly how a mesh peer holds the root.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout rroot.key -out rroot.pem -days 3650 \
    -subj "/CN=Remote Root/O=FastPKI" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > caext.cnf
chk "fixture: the remote root, registered with no key -> 201" 201 \
    "$(code "$U/api/ca-instances" --data-urlencode 'id=remote-root' --data-urlencode "cert_pem@rroot.pem")"
RSUBURI="pkcs11:token=$TOK;object=rsubk;id=%14;type=private?pin-value=1234"
json_pem "$(body "$U/api/ca-instances/csr" --data-urlencode 'subject=/CN=Remote Sub CA/O=FastPKI' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$RSUBURI" \
    --data-urlencode 'keygen=true' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048')" csr rsub.csr
"$OSSL" x509 -req -in rsub.csr -CA rroot.pem -CAkey rroot.key -set_serial 0x5101 -days 30 \
    -extfile caext.cnf -out rsub1.pem >/dev/null 2>&1
chk "fixture: a 30-day sub CA under it, imported with its token key -> 201" 201 \
    "$(code "$U/api/ca-instances" --data-urlencode 'id=remote-sub' --data-urlencode 'name=Remote Sub' \
       --data-urlencode "cert_pem@rsub1.pem" --data-urlencode 'keyloc=pkcs11' --data-urlencode "key=$RSUBURI")"
chk "  its parent is the remote root" remote-root "$(ca_field "$(body "$U/api/ca-instances")" remote-sub parentId)"
R=$(curl -s -o renew.json -w '%{http_code}' -b boss.cj -X POST "$U/api/ca-instances/remote-sub/renew" \
    --data-urlencode 'samekey=true')
chk "renew, with the parent's key not on this node -> 409" 409 "$R"
chk "  and it names the CSR route" yes "$(grep -q '"csrRoute":true' renew.json && echo yes || echo no)"
chk "  and wrote nothing" 1 "$(pg_exec "SELECT count(*) FROM certs WHERE id='remote-sub' AND is_ca;" | tr -d ' ')"

# The route: a request over the SAME key, signed where the parent's key is (openssl stands in
# for that node), imported here under the CA's own id.
json_pem "$(body "$U/api/ca-instances/csr" --data-urlencode 'subject=/CN=Remote Sub CA/O=FastPKI' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$RSUBURI" --data-urlencode 'keygen=false')" csr rsub2.csr
"$OSSL" x509 -req -in rsub2.csr -CA rroot.pem -CAkey rroot.key -set_serial 0x5102 -days 1000 \
    -extfile caext.cnf -out rsub2.pem >/dev/null 2>&1
sleep 1   # a later whole-second notBefore than generation 1
R=$(curl -s -o imp.json -w '%{http_code}' -b boss.cj "$U/api/ca-instances" --data-urlencode 'id=remote-sub' \
    --data-urlencode "cert_pem@rsub2.pem" --data-urlencode 'keyloc=pkcs11' --data-urlencode "key=$RSUBURI")
[ "$R" = 201 ] || echo "  (import said: $(head -c 200 imp.json))"
chk "import the renewal under the SAME id -> 201" 201 "$R"
chk "  reported as a renewal" yes "$(grep -q '"renewal":true' imp.json && echo yes || echo no)"
chk "  both generations are kept" 2 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='remote-sub' AND is_ca;" | tr -d ' ')"
chk "  the renewal is the one that signs" 5102 \
    "$(pg_exec "SELECT serial FROM certs WHERE id='remote-sub' AND is_ca
                ORDER BY \"notBefore\" DESC, ins_seq DESC NULLS LAST, serial DESC LIMIT 1;" | tr -d ' ')"
chk "  and the CA kept its name" "Remote Sub" "$(ca_field "$(body "$U/api/ca-instances")" remote-sub name)"
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout rleaf.key -out rleaf.csr \
    -subj "/CN=host.remote.example.com" >/dev/null 2>&1
ISS=$(curl -s -o rleaf.json -w '%{http_code}' -b boss.cj -X POST --data-binary @rleaf.csr \
      "$U/api/certs/request?ca_instance=remote-sub")
chk "the renewed sub CA issues a leaf -> 201" 201 "$ISS"
json_pem "$(cat rleaf.json)" pem rleaf.pem
# The leaf is cut to its signer's notAfter, so running past generation 1's 30 days is the
# proof that generation 2 signed it.
RLEAF_NA=$(pg_exec "SELECT \"notAfter\" FROM certs WHERE serial='$(json_str "$(cat rleaf.json)" serial)';" | tr -d ' ')
RSUB1_NA=$(pg_exec "SELECT \"notAfter\" FROM certs WHERE serial='5101';" | tr -d ' ')
chk "  which runs past the OLD certificate's end — the renewal signed it" yes \
    "$([ -n "$RLEAF_NA" ] && [ -n "$RSUB1_NA" ] && [ "$RLEAF_NA" -gt "$RSUB1_NA" ] && echo yes || echo no)"
chk "  and chains to the remote root through the renewal" "rleaf.pem: OK" \
    "$("$OSSL" verify -CAfile rroot.pem -untrusted rsub2.pem rleaf.pem 2>/dev/null)"

# ⚠️ ONLY A RENEWAL may take a registered id. Anything else under it is a different CA
# shadowing every lookup for the id.
R=$(curl -s -o imp.json -w '%{http_code}' -b boss.cj "$U/api/ca-instances" --data-urlencode 'id=remote-sub' \
    --data-urlencode "cert_pem@sub.pem" --data-urlencode 'keyloc=pkcs11' --data-urlencode "key=$SUBURI")
chk "a DIFFERENT CA's certificate under the id -> 409" 409 "$R"
chk "  because its subject is different" yes "$(grep -q 'not a renewal of it: its subject is different' imp.json && echo yes || echo no)"
json_pem "$(body "$U/api/ca-instances/sign-csr" --data-urlencode "csr@rsub2.csr" \
    --data-urlencode 'parent=parent-ca' --data-urlencode 'days=365')" cert rsub-wrongparent.pem
R=$(curl -s -o imp.json -w '%{http_code}' -b boss.cj "$U/api/ca-instances" --data-urlencode 'id=remote-sub' \
    --data-urlencode "cert_pem@rsub-wrongparent.pem" --data-urlencode 'keyloc=pkcs11' --data-urlencode "key=$RSUBURI")
chk "the same subject signed by ANOTHER CA -> 409" 409 "$R"
chk "  because the parent is not this CA's" yes "$(grep -q "not signed by this CA's parent" imp.json && echo yes || echo no)"
chk "  and neither refusal wrote a generation" 2 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='remote-sub' AND is_ca;" | tr -d ' ')"

echo "=== 7. the console offers both forms ==="
# Matching on the WIRING, not on prose: the served page carries these comments too, so a
# grep for anything explanatory would pass whether or not the button exists.
chk "the CSR button is on the toolbar"   yes "$(grep -q "id=\"cacsr\">+ Create CSR (key in HSM)" page.html && echo yes || echo no)"
chk "the sign button is on the toolbar"  yes "$(grep -q "id=\"casign\">Request from a CSR" page.html && echo yes || echo no)"
chk "the CSR form submits to createCaCsr"  yes \
    "$(grep -q "getElementById('cacsrform').onsubmit = createCaCsr" page.html && echo yes || echo no)"
chk "the sign form submits to signCaCsr"   yes \
    "$(grep -q "getElementById('casignform').onsubmit = signCaCsr" page.html && echo yes || echo no)"
# ⚠️ apiFetch, NOT fetch, and that is the assertion. This form generates a key in the token,
# which can take minutes and can also never answer — issuing the console's own certificate
# makes the browser distrust the connection the answer would arrive on. A bare fetch() then
# sits on "generating the key in the token…" for ever, with nothing in the server log because
# nothing is wrong there. apiFetch gives up and answers response-shaped, so the form's own
# `if (!r.ok)` path reports it. Every call that mints a key in the token goes through it.
chk "the CSR form posts to the CSR endpoint, through the timeout wrapper" yes \
    "$(grep -q "apiFetch('/api/ca-instances/csr'" page.html && echo yes || echo no)"
chk "the sign form posts to the sign endpoint" yes \
    "$(grep -q "fetch('/api/ca-instances/sign-csr'" page.html && echo yes || echo no)"
# ⚠️ `.card.wide2` DOES NOT WIDEN ANYTHING — width comes from the max-width list, and a
# modal left out of it silently renders at the 520px base with a full CA form inside.
chk "both modals are in the max-width list" yes \
    "$(tr -d ' \n' < page.html | grep -q '#cacsrmodal>.card,#casignmodal>.card' && echo yes || echo no)"


# ── the same exchange from the CLI, which is what a multi-datacenter bootstrap needs ──────
# ⚠️ WHY THIS EXISTS. A mesh needs one root and one sub CA per node, because POST
# /api/pg-tls signs with a CA whose key THAT node's own token provides.
# Until now the csr/sign-csr exchange existed ONLY as console endpoints, so every node
# needed an admin session and the bootstrap could not be scripted — which is why the
# procedure was never written down. The CLI pair must produce the same result as the API
# pair above, or the documented multi-DC install is a second, untested path.
CA="$ROOT/build/fastpki-ca"
echo "=== 9. fastpki-ca csr / sign-csr: the same exchange without a console ==="
CLI_KEY="$(hsm_new_key_uri clisub)"
"$CA" --config bootstrap.conf csr cli-sub --subject "/CN=CLI Sub" \
      --ca-key "$CLI_KEY" --keygen --out cli.csr >/dev/null 2>cli-csr.err
chk "csr wrote a PKCS#10 request" yes \
    "$(grep -q 'BEGIN CERTIFICATE REQUEST' cli.csr && echo yes || echo no)"
chk "  and told the operator how to sign it" yes \
    "$(grep -q 'sign-csr' cli-csr.err && echo yes || echo no)"

"$CA" --config bootstrap.conf sign-csr parent-ca --csr cli.csr --out cli-sub.crt >/dev/null 2>cli-sign.err
chk "sign-csr produced a certificate" yes \
    "$(grep -q 'BEGIN CERTIFICATE' cli-sub.crt && echo yes || echo no)"
# The meaningful check is that the issuer IS the parent's subject — not a substring of
# the instance id, which is a different string entirely (id `parent-ca`, subject
# `/CN=Parent CA/O=FastPKI`).
chk "  issued by the parent, not self-signed" yes \
    "$([ "$("$OSSL" x509 -in cli-sub.crt -noout -issuer 2>/dev/null | sed s/^issuer=//)" \
        = "$("$OSSL" x509 -in parent.pem -noout -subject 2>/dev/null | sed s/^subject=//)" ] \
       && echo yes || echo no)"
chk "  and it is a CA certificate" yes \
    "$("$OSSL" x509 -in cli-sub.crt -noout -text 2>/dev/null | grep -q 'CA:TRUE' && echo yes || echo no)"
chk "  the subject is the one the CSR asked for" yes \
    "$("$OSSL" x509 -in cli-sub.crt -noout -subject 2>/dev/null | grep -q 'CLI Sub' && echo yes || echo no)"
CLI_SER=$("$OSSL" x509 -in cli-sub.crt -noout -serial 2>/dev/null | sed 's/serial=//' | tr 'A-Z' 'a-z' | sed 's/^0*//')
chk "  and the signer recorded it (no id, under parent-ca)" "|parent-ca" \
    "$(pg_exec "SELECT coalesce(id,'')||'|'||ca_instance_id FROM certs WHERE serial='$CLI_SER';" | tr -d ' ')"
"$CA" --config bootstrap.conf add cli-sub --name "CLI Sub" --ca-pem cli-sub.crt --ca-key "$CLI_KEY" \
      >cli-add.out 2>cli-add.err
chk "fastpki-ca add registers the CA on that record" "1|cli-sub" \
    "$(pg_exec "SELECT count(*)||'|'||max(id) FROM certs WHERE serial='$CLI_SER';" | tr -d ' ')"
# A record that is NOT a CA-less copy of the same certificate is still refused: registering
# the same certificate a second time under another id.
"$CA" --config bootstrap.conf add cli-sub2 --ca-pem cli-sub.crt --ca-key "$CLI_KEY" >/dev/null 2>cli-add2.err
chk "  and adding it again is refused, naming the CA" yes \
    "$(grep -q "already registered as CA 'cli-sub'" cli-add2.err && echo yes || echo no)"

# The CSR route's last step from the CLI: a renewal of remote-sub (section 6b) added under its id.
"$OSSL" x509 -req -in rsub2.csr -CA rroot.pem -CAkey rroot.key -set_serial 0x5103 -days 1200 \
    -extfile caext.cnf -out rsub3.pem >/dev/null 2>&1
sleep 1
"$CA" --config bootstrap.conf add remote-sub --ca-pem rsub3.pem --ca-key "$RSUBURI" >cli-renew.out 2>cli-renew.err
chk "fastpki-ca add registers a renewal under the CA's id" yes \
    "$(grep -q 'added the renewed certificate of CA instance remote-sub' cli-renew.out && echo yes || echo no)"
chk "  as its third generation, keeping its name" "3|Remote Sub" \
    "$(pg_exec "SELECT count(*)||'|'||max(name) FROM certs WHERE id='remote-sub' AND is_ca;" | sed 's/^ *//;s/ *$//')"
"$CA" --config bootstrap.conf add remote-sub --ca-pem cli-sub.crt --ca-key "$CLI_KEY" >/dev/null 2>cli-renew2.err
chk "  and refuses a certificate that is not a renewal of it" yes \
    "$(grep -q 'not a renewal of it' cli-renew2.err && echo yes || echo no)"

# ⚠️ THE POINT OF THE RECORD: a CA certificate this node signed and that nobody imports can
# still be REVOKED here. (get_revoked_certs puts a CA row with no id on its issuer's CRL.)
"$CA" --config bootstrap.conf csr orphan-sub --subject "/CN=Orphan Sub" \
      --ca-key "$(hsm_new_key_uri orphansub)" --keygen --out orphan.csr >/dev/null 2>&1
"$CA" --config bootstrap.conf sign-csr parent-ca --csr orphan.csr --out orphan.crt >/dev/null 2>&1
ORPH_SER=$("$OSSL" x509 -in orphan.crt -noout -serial 2>/dev/null | sed 's/serial=//' | tr 'A-Z' 'a-z' | sed 's/^0*//')
chk "an unimported signed CA certificate is revocable from the console" 200 \
    "$(code "$U/api/certs/$ORPH_SER/revoke" -X POST --data-urlencode 'reason=1')"
chk "  and is revoked" "-1" "$(pg_exec "SELECT status FROM certs WHERE serial='$ORPH_SER';" | tr -d ' ')"

# ⚠️ ANTI-VACUITY: signing with a CA this node cannot sign for must be refused, not
# silently produce something. A mesh peer replicates every CA row but holds one key.
"$CA" --config bootstrap.conf sign-csr no-such-ca --csr cli.csr --out bogus.crt >/dev/null 2>bogus.err || true
chk "signing with an unknown CA is refused" yes \
    "$([ ! -s bogus.crt ] && grep -q 'no CA instance' bogus.err && echo yes || echo no)"

# ⚠️ WHY THIS EXISTS. Steps 4 and 5 of the multi-DC bootstrap (docs/deployment.md §9.1) are
# `show --pem` — the only way to get a root's certificate to the other nodes — and
# `pg-tls`, which issues the database's own certificate from the sub CA that node holds.
# Both existed only as console endpoints before, so the documented procedure silently
# required an admin session on every node with WEB_ALLOW_REVOKE=true, i.e. relaxing a
# security control to run a deploy step.
echo "=== 10. fastpki-ca show --pem / pg-tls: the rest of the bootstrap, scripted ==="
CFG="$ROOT/build/fastpki-config"
"$CA" --config bootstrap.conf show parent-ca --pem --out shown.pem >/dev/null 2>show.err
chk "show --pem wrote a certificate" yes \
    "$(grep -q 'BEGIN CERTIFICATE' shown.pem && echo yes || echo no)"
# The meaningful check: it is the SAME certificate the console serves, not merely a PEM.
chk "  and it is the one the console serves" yes \
    "$([ "$("$OSSL" x509 -in shown.pem -noout -fingerprint -sha256 2>/dev/null)" \
        = "$("$OSSL" x509 -in parent.pem -noout -fingerprint -sha256 2>/dev/null)" ] \
       && echo yes || echo no)"

# ⚠️ THE SANs COME FROM THE DB OVERLAY, NOT THE FILE. fastpki-ca did not apply
# overlay_config() at all, so `fastpki-config set PG_TLS_SANS` had no effect on it and
# pg-tls issued a certificate WITHOUT the interconnect address — exactly the certificate
# a mesh peer cannot verify. Measured on a 3-DC lab. This assertion is the regression.
"$CFG" --config bootstrap.conf set PG_TLS_SANS 10.10.10.99 >/dev/null 2>&1
mkdir -p pgtls
"$CA" --config bootstrap.conf pg-tls parent-ca --key ec --curve P-256 --dir pgtls >pgtls.out 2>pgtls.err
chk "pg-tls issued a server certificate" yes \
    "$([ -s pgtls/server.crt ] && [ -s pgtls/server.key ] && echo yes || echo no)"
chk "  and wrote the anchor bundle" yes \
    "$([ -s pgtls/ca.crt ] && echo yes || echo no)"
SANS=$("$OSSL" x509 -in pgtls/server.crt -noout -text 2>/dev/null | grep -A1 'Subject Alternative Name' | tail -1)
chk "  the interconnect address from the DB overlay is a SAN" yes \
    "$(echo "$SANS" | grep -q '10.10.10.99' && echo yes || echo no)"
chk "  and so are the service names every app dials" yes \
    "$(echo "$SANS" | grep -q 'postgres' && echo "$SANS" | grep -q '127.0.0.1' && echo yes || echo no)"
chk "  it chains to the anchor it wrote" yes \
    "$("$OSSL" verify -CAfile pgtls/ca.crt pgtls/server.crt >/dev/null 2>&1 && echo yes || echo no)"
chk "  serverAuth, and no CA bit" yes \
    "$("$OSSL" x509 -in pgtls/server.crt -noout -text 2>/dev/null \
        | grep -q 'TLS Web Server Authentication' \
       && ! "$OSSL" x509 -in pgtls/server.crt -noout -text 2>/dev/null | grep -q 'CA:TRUE' \
       && echo yes || echo no)"
# The row must be in the DB, because certificates live in Postgres and this one is no
# exception — a file-only pg certificate would be invisible to the console inventory.
chk "  the certificate is recorded in the DB" yes \
    "$(pg_exec "select count(*) from certs where cert_id='postgres'" 2>/dev/null | tr -d ' ' \
       | grep -qE '^[1-9]' && echo yes || echo no)"

# ⚠️ ANTI-VACUITY: a CA this node cannot sign with, or that reaches no anchor, must be
# refused with nothing written — half-applying takes every app off the database.
rm -rf pgtls2; mkdir -p pgtls2
"$CA" --config bootstrap.conf pg-tls no-such-ca --dir pgtls2 >/dev/null 2>nopg.err || true
chk "pg-tls with an unknown CA is refused, writing nothing" yes \
    "$([ ! -e pgtls2/server.crt ] && grep -q 'no CA instance' nopg.err && echo yes || echo no)"
echo
echo "=== WEB CA CSR: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
