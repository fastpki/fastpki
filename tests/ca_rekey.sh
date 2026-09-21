#!/usr/bin/env bash
# Renewing a CA — a new certificate with its OWN validity, on a new key or the current one.
#
# ── What has to be true ───────────────────────────────────────────────────────────
#
# Renewal ADDS certificates and keeps the old row live. What it adds depends on who signs:
#
#   a ROOT, new key       the new self-signed certificate (the CA's signer from now on)
#                         + the NEW key signed by the OLD root  (the bridge, an id row)
#                         + the OLD key signed by the NEW root  (the cross, a plain row)
#   a ROOT, current key   the new self-signed certificate alone
#   a SUB CA, either key  the new certificate, signed by its PARENT
#
# The renewal has to OUTLIVE the certificate it renews — that is what renewing is for, and
# a certificate signed by the CA's own previous generation never can. So the assertions
# that matter are `openssl verify` against the right anchor, including at a time AFTER the
# old certificate has expired, and against the OPPOSITE anchor through each bridge. A
# certificate that does not chain is worse than none, and only decoding the bytes can tell.
#
# ── The subject trap this guards ─────────────────────────────────────────────────
#
# A cross-certificate must carry the SAME subject as the CA it re-certifies, and "same"
# means byte-identical DER. cross_sign_ca copies the Name structurally instead of
# re-parsing params.subject_dn, because a one-line DN put back through build_name() can
# return different ASN.1 string types — the encoded Name changes, its sHash changes, and
# a relying party stops matching it against the issuer field of everything the CA signed.
# Section 4 compares the encoded subjects, not their text.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18118
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup ca_rekey
trap 'pg_cleanup; kill ${P:-} 2>/dev/null' EXIT

# A real token-held CA — rekeying is a token operation and there is no software path.
# ⚠️ 30 DAYS, deliberately short: the renewal below asks for ten years, and "it outlives the
# certificate it renews" can only fail if the two lives are far apart.
ca_in_token ca.pem "/CN=Rekey CA/O=FastPKI Test" 30 rekeyca || { echo "SKIP: no token"; exit 0; }
OLD_URI="$CA_KEY_URI"

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$OLD_URI
SIGNING_CA_ID=rekey
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf

# Cascade: give this CA a service credential to cascade ONTO. It must exist, and
# OCSP_RESPONDER_KEY must be in the config, before fastpki-web starts — the renew handler
# reads the credentials from the config it loaded at startup.
RKEY=$(ocsp_responder_key "$W/ca.pem" "$OLD_URI" rekey "$W" 2>/dev/null) || RKEY=""
[ -n "$RKEY" ] && printf 'OCSP_RESPONDER_KEY=%s\n' "$RKEY" >> bootstrap.conf
R_ORIG=$(pg_exec "SELECT serial FROM certs WHERE cert_id='ocsp-ra-rekey' AND status=0;" | tr -d ' ')

seed_web_user boss bosspw admin

"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
# ⚠️ THIS SLEEP IS NOT A READINESS WAIT — DO NOT REPLACE IT WITH wait_conf/wait_port.
# It advances the CLOCK. The rekey below asserts "the newest is the one that signs" with
# `ORDER BY "notBefore" DESC LIMIT 1`, and notBefore has one-second resolution, so the
# original CA and its rekeyed successor must not land in the same second or the ordering
# is a coin toss. Converting this to a port poll returned in ~50ms and the suite failed
# with the two serials swapped, which reads as a rekey bug and is a clock artefact.
sleep 1
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat srv.log; exit 1; }
U="http://127.0.0.1:$PORT"
curl -s -c cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null

OLD_SERIAL=$("$OSSL" x509 -in ca.pem -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')

echo "=== 1. refusals come before anything is minted ==="
# The lesson: a failure AFTER generate_key_in_token orphans a keypair in hardware.
code(){ curl -s -o r.json -w '%{http_code}' -b cj -X POST "$@"; }
chk "a file key is refused" 400 \
    "$(code "$U/api/ca-instances/rekey/renew" --data-urlencode "keyref=/tmp/new.key")"
chk "the current key as a NEW key is refused"  400 \
    "$(code "$U/api/ca-instances/rekey/renew" --data-urlencode "keyref=$OLD_URI")"
chk "  and it names the way to renew with it" yes \
    "$(grep -q 'samekey=true' r.json && echo yes || echo no)"
chk "an unknown CA is 404" 404 \
    "$(code "$U/api/ca-instances/nosuch/renew" --data-urlencode "keyref=pkcs11:token=x;object=y;type=private")"
chk "no second CA row was created by any of that" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='rekey' AND is_ca;" | tr -d ' ')"

echo "=== 2. renewing the root with a new key ==="
NEW_URI=$(hsm_new_key_uri rekeyca-new)
RC=$(code "$U/api/ca-instances/rekey/renew" --data-urlencode "keyref=$NEW_URI" \
        --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' --data-urlencode 'days=3650')
echo "  (renew said: $(cut -c1-160 r.json))"
chk "renew -> 201" 201 "$RC"
NEW_SERIAL=$(sed -n 's/.*"serial":"\([^"]*\)".*/\1/p' r.json)
B_SERIAL=$(sed -n 's/.*"bridgeSerial":"\([^"]*\)".*/\1/p' r.json)
X_SERIAL=$(sed -n 's/.*"crossSerial":"\([^"]*\)".*/\1/p' r.json)
chk "it returned a new serial"   yes "$([ -n "$NEW_SERIAL" ] && echo yes || echo no)"
chk "and a bridge serial"        yes "$([ -n "$B_SERIAL" ] && echo yes || echo no)"
chk "and a cross-cert serial"    yes "$([ -n "$X_SERIAL" ] && echo yes || echo no)"
chk "which are three different rows" 3 \
    "$(printf '%s\n' "$NEW_SERIAL" "$B_SERIAL" "$X_SERIAL" | sort -u | grep -c .)"
chk "none reuses the old serial" yes \
    "$([ "$NEW_SERIAL" != "$OLD_SERIAL" ] && [ "$B_SERIAL" != "$OLD_SERIAL" ] && [ "$X_SERIAL" != "$OLD_SERIAL" ] && echo yes || echo no)"
chk "a root signs its own renewal" rekey "$(sed -n 's/.*"signer":"\([^"]*\)".*/\1/p' r.json)"
chk "  and it was not a same-key renewal" false "$(sed -n 's/.*"sameKey":\([a-z]*\).*/\1/p' r.json)"

echo "=== 3. the old certificate is still there and still live ==="
# The design: the old row is untouched and stays live until its own notAfter.
chk "the old row survives"            1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE serial='$OLD_SERIAL';" | tr -d ' ')"
chk "three CA rows now share the id (old, bridge, renewed)" 3 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='rekey' AND is_ca;" | tr -d ' ')"
chk "all of them are live"            3 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='rekey' AND is_ca AND \"notAfter\" > $(date +%s);" | tr -d ' ')"
chk "the CA now points at the NEW key" "$NEW_URI" \
    "$(pg_exec "SELECT private_key FROM certs WHERE serial='$NEW_SERIAL';")"
chk "  and so does the bridge, which certifies it" "$NEW_URI" \
    "$(pg_exec "SELECT private_key FROM certs WHERE serial='$B_SERIAL';")"

echo "=== ⚠️ a RE-KEYED CA IS NOT ITS OWN PARENT ==="
# The re-key is self-ISSUED — subject == issuer — so `p."sHash" = c."iHash"` matched the CA's
# OTHER generations, and every one of them carries the SAME id. The only exclusion was
# `p.serial <> c.serial`, i.e. the row itself, so the derived parent came back as the CA's own
# id. Measured on the lab before the fix: `issuing` -> parent `issuing`.
#
# ⚠️ THIS IS NOT A COSMETIC FIELD. ca_instance.cpp seeds `seen{id}` and walks
#     while (!parent_id.empty() && seen.insert(parent_id).second)
# so parent == id makes the insert fail and THE BODY NEVER RUNS ONCE. The CMP/EST client-auth
# trust store is then built from the re-keyed CA alone with nothing above it, while
# `anchors > 0` keeps the startup log claiming success — client mTLS stops validating and
# nothing says so. Re-keying a CA was enough to cause it.
#
# This fixture is a re-keyed ROOT, so the right answer is EMPTY: it has no parent. The bug
# does not care about root-vs-intermediate — it is the shared id that does the damage — and a
# root is what this suite already builds honestly.
PARENT=$(curl -s -b cj "$U/api/ca-instances" | tr '{' '\n' | grep '"id":"rekey"' \
           | grep -o '"parentId":"[^"]*"' | head -1 | cut -d'"' -f4)
chk "the re-keyed CA does not name ITSELF as its parent" yes \
    "$([ "$PARENT" != "rekey" ] && echo yes || echo no)"
chk "  and a re-keyed ROOT has no parent at all" "" "$PARENT"
# The consumer, asserted separately: a self-parent made the ancestor walk exit before its
# first iteration, so the count is the assertion that would go red on a revert even if the
# field above were merely cosmetic.
chk "PRECONDITION: several generations share the id (the fixture is a real re-key)" 3 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='rekey' AND is_ca;" | tr -d ' ')"
chk "the old row kept the OLD key"     "$OLD_URI" \
    "$(pg_exec "SELECT private_key FROM certs WHERE serial='$OLD_SERIAL';")"
# The cross-certificate is a certificate, not a CA identity: it must not be addressable
# as this CA, or "which cert signs" would have three candidates instead of two.
chk "the cross-cert carries no id"     "" \
    "$(pg_exec "SELECT coalesce(id,'') FROM certs WHERE serial='$X_SERIAL';")"

echo "=== 4. THE POINT: the renewal stands on its own, and each bridge reaches the other anchor ==="
getpem(){ pg_exec "SELECT '-----BEGIN CERTIFICATE-----'||chr(10)||
                          rtrim(encode(cert,'base64'),chr(10))||chr(10)||
                          '-----END CERTIFICATE-----' FROM certs WHERE serial='$1';" > "$2"; }
pubhash(){ "$OSSL" x509 -in "$1" -noout -pubkey 2>/dev/null | "$OSSL" sha256 | sed 's/.*= *//'; }
epoch(){ pg_exec "SELECT \"notAfter\" FROM certs WHERE serial='$1';" | tr -d ' '; }
getpem "$NEW_SERIAL" new.pem
getpem "$B_SERIAL"   bridge.pem
getpem "$X_SERIAL"   cross.pem
chk "the new cert decodes"    yes "$("$OSSL" x509 -in new.pem    -noout -subject >/dev/null 2>&1 && echo yes || echo no)"
chk "the bridge cert decodes" yes "$("$OSSL" x509 -in bridge.pem -noout -subject >/dev/null 2>&1 && echo yes || echo no)"
chk "the cross cert decodes"  yes "$("$OSSL" x509 -in cross.pem  -noout -subject >/dev/null 2>&1 && echo yes || echo no)"
# The renewal is a real anchor: it verifies with its OWN key, no -partial_chain.
chk "the renewed root is self-signed" "new.pem: OK" \
    "$("$OSSL" verify -CAfile new.pem new.pem 2>/dev/null)"
OLD_NA=$(epoch "$OLD_SERIAL"); NEW_NA=$(epoch "$NEW_SERIAL"); B_NA=$(epoch "$B_SERIAL")
chk "⚠️ the renewal OUTLIVES the certificate it renews" yes \
    "$([ -n "$NEW_NA" ] && [ -n "$OLD_NA" ] && [ "$NEW_NA" -gt "$((OLD_NA + 3000*86400))" ] && echo yes || echo no)"
chk "  and still verifies after the old one has expired" yes \
    "$("$OSSL" verify -attime "$((OLD_NA + 86400))" -CAfile new.pem new.pem >/dev/null 2>&1 && echo yes || echo no)"
# Bridge: the NEW key under the OLD root — a relying party still anchored there reaches it.
chk "the bridge verifies against the OLD anchor" "bridge.pem: OK" \
    "$("$OSSL" verify -CAfile ca.pem bridge.pem 2>/dev/null)"
chk "  and ends no later than the old root" yes \
    "$([ -n "$B_NA" ] && [ "$B_NA" -le "$OLD_NA" ] && echo yes || echo no)"
# Cross: the OLD key under the NEW root — everything the old key signed stays reachable.
chk "the cross cert verifies against the NEW anchor" "cross.pem: OK" \
    "$("$OSSL" verify -CAfile new.pem cross.pem 2>/dev/null)"
# And the keys really did change hands.
NEWPUB=$(pubhash new.pem); OLDPUB=$(pubhash ca.pem)
chk "the new cert carries a DIFFERENT key" yes "$([ "$NEWPUB" != "$OLDPUB" ] && echo yes || echo no)"
chk "the bridge carries the NEW key"       "$NEWPUB" "$(pubhash bridge.pem)"
chk "the cross cert carries the OLD key"   "$OLDPUB" "$(pubhash cross.pem)"

echo "=== 4b. ⚠️ the rekey CASCADED onto the service credentials ==="
# ⚠️ THE RULE: if a CA certificate is re-keyed, the dependent certificates must be re-signed, so
# it should be automatic". Without the cascade the OCSP responder credential is still
# signed by the OLD key: it reaches the new CA only via the cross-certificate. That is
# not theoretical — it is exactly why the lab's DC1 responder returned "Response Verify
# Failure" until the intermediate was passed by hand.
if [ -z "$R_ORIG" ]; then
  echo "  [SKIP] no responder credential was provisioned"
else
  chk "the rekey reports re-signing it" 1 \
      "$(sed -n 's/.*"serviceCertsRenewed":\([0-9]*\).*/\1/p' r.json)"
  chk "  with nothing failed" 0 \
      "$(sed -n 's/.*"serviceCertsFailed":\([0-9]*\).*/\1/p' r.json)"
  R_NEW=$(pg_exec "SELECT serial FROM certs WHERE cert_id='ocsp-ra-rekey' AND status=0;" | tr -d ' ')
  chk "  the credential was actually replaced" yes \
      "$([ -n "$R_NEW" ] && [ "$R_NEW" != "$R_ORIG" ] && echo yes || echo no)"
  # The accumulation hazard again: two live rows under one cert_id make fastpki-ocsp
  # resolve an arbitrary one, and if it is not the one matching the held key every
  # response fails to verify.
  chk "  exactly ONE stays active for the cert_id" 1 \
      "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='ocsp-ra-rekey' AND status=0;" | tr -d ' ')"
  chk "  the old one is superseded, not deleted" 1 \
      "$(pg_exec "SELECT count(*) FROM certs WHERE serial='$R_ORIG' AND status<>0;" | tr -d ' ')"

  getpem "$R_NEW"  resp_new.pem
  getpem "$R_ORIG" resp_old.pem
  # THE assertion: the renewed credential chains DIRECTLY to the rekeyed CA...
  chk "  it now verifies DIRECTLY under the new CA cert" yes \
      "$("$OSSL" verify -CAfile new.pem -partial_chain resp_new.pem >/dev/null 2>&1 && echo yes || echo no)"
  # ...and the pre-rekey one does not, which is the whole reason the cascade exists.
  chk "  (the pre-rekey one does not — that IS the gap)" no \
      "$("$OSSL" verify -CAfile new.pem -partial_chain resp_old.pem >/dev/null 2>&1 && echo yes || echo no)"
  RT=$("$OSSL" x509 -in resp_new.pem -noout -text 2>/dev/null)
  chk "  it kept OCSPSigning" yes "$(echo "$RT" | grep -q 'OCSP Signing' && echo yes || echo no)"
  chk "  it kept id-pkix-ocsp-nocheck" yes \
      "$(echo "$RT" | grep -qiE 'OCSP No Check|1\.3\.6\.1\.5\.5\.7\.48\.1\.5' && echo yes || echo no)"
  # One key, N certificates: a cascade that minted a fresh key would leave the running
  # responder holding a key its certificate no longer matches.
  chk "  and it certifies the SAME key the responder holds" yes \
      "$([ "$("$OSSL" x509 -in resp_new.pem -noout -modulus 2>/dev/null)" = \
           "$("$OSSL" rsa  -in "$RKEY"      -noout -modulus 2>/dev/null | sed 's/^Modulus=/Modulus=/')" ] \
        && echo yes || echo no)"
fi

echo "=== 5. the subject is byte-identical, not merely similar ==="
# Compared as encoded DER. Re-parsing a one-line DN can change the ASN.1 string types,
# which changes the Name, its sHash, and whether anything still chains to it.
chk "new cert subject == old cert subject (text)" \
    "$("$OSSL" x509 -in ca.pem -noout -subject)" "$("$OSSL" x509 -in new.pem -noout -subject)"
chk "cross cert subject == old cert subject (text)" \
    "$("$OSSL" x509 -in ca.pem -noout -subject)" "$("$OSSL" x509 -in cross.pem -noout -subject)"
chk "bridge subject == old cert subject (text)" \
    "$("$OSSL" x509 -in ca.pem -noout -subject)" "$("$OSSL" x509 -in bridge.pem -noout -subject)"
# The DB's own subject hash is the encoded form, so equal sHash means equal DER Name.
chk "and their stored sHash matches the old one" yes \
    "$([ "$(pg_exec "SELECT encode(\"sHash\",'hex') FROM certs WHERE serial='$NEW_SERIAL';")" = \
        "$(pg_exec "SELECT encode(\"sHash\",'hex') FROM certs WHERE serial='$OLD_SERIAL';")" ] \
       && echo yes || echo no)"

echo "=== 6. issuance continues, now under the new key ==="
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout leaf.key -subj "/CN=after-rekey.internal" -out leaf.csr >/dev/null 2>&1
IC=$(curl -s -o iss.json -w '%{http_code}' -b cj -X POST --data-binary @leaf.csr \
        "$U/api/certs/request?ca_instance=rekey")
chk "a leaf still issues after the rekey" 201 "$IC"
LS=$(sed -n 's/.*"serial":"\([^"]*\)".*/\1/p' iss.json | head -1)
getpem "$LS" leaf.pem
chk "and it verifies under the RENEWED root, a full chain" "leaf.pem: OK" \
    "$("$OSSL" verify -CAfile new.pem leaf.pem 2>/dev/null)"
# ⚠️ A relying party that has NOT installed the new root reaches the leaf through the bridge.
chk "and under the OLD root, through the bridge" "leaf.pem: OK" \
    "$("$OSSL" verify -CAfile ca.pem -untrusted bridge.pem leaf.pem 2>/dev/null)"
chk "  but not without the bridge (the control)" no \
    "$("$OSSL" verify -CAfile ca.pem leaf.pem >/dev/null 2>&1 && echo yes || echo no)"
LEAF_NA=$(epoch "$LS")
if [ -n "$LEAF_NA" ] && [ "$LEAF_NA" -gt "$((OLD_NA + 86400))" ]; then
    chk "and it keeps verifying after the OLD root has expired" "leaf.pem: OK" \
        "$("$OSSL" verify -attime "$((OLD_NA + 86400))" -CAfile new.pem leaf.pem 2>/dev/null)"
else
    chk "PRECONDITION: the leaf outlives the old root by a day" yes no
fi

echo "=== 7. the CA serves EVERY live certificate ==="
# The reason for bridging rather than swapping: a client anchored on the OLD root and one
# anchored on the NEW must each be able to build a path from what the server gives them.
# Sending only the newest strands everyone who has not moved.
#
# This suite's fastpki-web has no EST listener, so the assertion is made where the
# decision is: resolve_ca_instance's chain, which is what handle_cacerts_for_instance
# serves. ca_rollover_chain.sh asserts what the protocols hand over.
CHAIN=$(pg_exec "SELECT count(*) FROM certs WHERE id='rekey' AND is_ca AND status=0
                   AND \"notAfter\" > $(date +%s);" | tr -d ' ')
chk "the CA has three live certificates to serve" 3 "$CHAIN"
# The bridge carries the same key and the same whole-second notBefore as the renewal; the
# renewal is inserted last so that it, not the bridge, is the one that signs. If the bridge
# signed, every certificate issued from here on would be cut to the OLD root's end date.
chk "the renewal is the one that signs, not the bridge" "$NEW_SERIAL" \
    "$(pg_exec "SELECT serial FROM certs WHERE id='rekey' AND is_ca AND status=0
                  AND \"notAfter\" > $(date +%s)
                ORDER BY \"notBefore\" DESC, ins_seq DESC NULLS LAST, serial DESC LIMIT 1;" | tr -d ' ')"
chk "  and the leaf issued after it runs past the bridge's end date" yes \
    "$([ -n "$LEAF_NA" ] && [ "$LEAF_NA" -gt "$B_NA" ] && echo yes || echo no)"
# Both orderings must chain: the leaf issued after the rekey under the new cert, and the
# pre-rekey world under the old one. Together that is the rollover working.
cat new.pem ca.pem > bundle.pem
chk "a client trusting the BUNDLE validates the new leaf" yes \
    "$("$OSSL" verify -CAfile bundle.pem -partial_chain leaf.pem >/dev/null 2>&1 && echo yes || echo no)"

echo "=== 8. the console actually offers it ==="
# A rekey endpoint nobody can reach from the UI is a rekey nobody performs. The shell
# harness cannot run the page's JS, so these are grep-proxies on the served source (§3e):
# weak on their own, but they catch the button or the wiring being dropped.
JS=$(curl -s -b cj "$U/")
chk "the CAs table renders a Renew button" yes \
    "$(echo "$JS" | grep -q 'data-renew=' && echo yes || echo no)"
chk "  only for an ACTIVE CA" yes \
    "$(echo "$JS" | grep -q "o.status === 'active' && !o.expired) ? ' <button data-renew=" && echo yes || echo no)"
# ⚠️ AND NOT FOR AN EXPIRED ONE. `status` is the ca_enabled switch, which still reads
# 'active' when the certificate has merely run out — but a rollover is signed BY this CA,
# so an expired signer only mints another dead certificate and resolve_ca_instance refuses
# it. Offering the button would point the operator at a remedy that cannot work; the pill
# tells them to create a replacement CA instead.
chk "  and never for an EXPIRED one" yes \
    "$(echo "$JS" | grep -q '!o.expired' && echo yes || echo no)"
chk "the button opens the CA detail's renew form" yes \
    "$(echo "$JS" | grep -q "getElementById('rekeybox')" && echo yes || echo no)"
chk "the form POSTs to this CA's /renew" yes \
    "$(echo "$JS" | grep -q "encodeURIComponent(o.id) + '/renew'" && echo yes || echo no)"
chk "it sends the token key reference it built" yes \
    "$(echo "$JS" | grep -q "fd.set('keyref', ref)" && echo yes || echo no)"
chk "it offers renewing with the current key" yes \
    "$(echo "$JS" | grep -q 'id="rk_samekey"' && echo "$JS" | grep -q "fd.set('samekey', 'true')" && echo yes || echo no)"

echo "=== 9. renewing with the CURRENT key ==="
# A new validity for the key the CA already has: nothing is minted, nothing is bridged (the
# key did not change), and nothing it signed needs re-signing.
sleep 1   # a later whole-second notBefore than the renewal above, so ordering is not a tie
KEYS_BEFORE=$(pg_exec "SELECT count(DISTINCT private_key) FROM certs WHERE id='rekey' AND is_ca;" | tr -d ' ')
RC=$(code "$U/api/ca-instances/rekey/renew" --data-urlencode 'samekey=true' --data-urlencode 'days=3650')
echo "  (renew said: $(cut -c1-160 r.json))"
chk "same-key renew -> 201" 201 "$RC"
SK_SERIAL=$(sed -n 's/.*"serial":"\([^"]*\)".*/\1/p' r.json)
chk "  it says so"                    true "$(sed -n 's/.*"sameKey":\([a-z]*\).*/\1/p' r.json)"
chk "  no bridge"                     ""   "$(sed -n 's/.*"bridgeSerial":"\([^"]*\)".*/\1/p' r.json)"
chk "  no cross-certificate"          ""   "$(sed -n 's/.*"crossSerial":"\([^"]*\)".*/\1/p' r.json)"
chk "  nothing re-signed"             0    "$(sed -n 's/.*"serviceCertsRenewed":\([0-9]*\).*/\1/p' r.json)"
chk "  no key was added"              "$KEYS_BEFORE" \
    "$(pg_exec "SELECT count(DISTINCT private_key) FROM certs WHERE id='rekey' AND is_ca;" | tr -d ' ')"
chk "  and the row keeps the current key" "$NEW_URI" \
    "$(pg_exec "SELECT private_key FROM certs WHERE serial='$SK_SERIAL';")"
getpem "$SK_SERIAL" samekey.pem
chk "the certificate carries the SAME key" "$NEWPUB" "$(pubhash samekey.pem)"
chk "  it is self-signed"             "samekey.pem: OK" "$("$OSSL" verify -CAfile samekey.pem samekey.pem 2>/dev/null)"
chk "  and what that key already signed verifies under it" "leaf.pem: OK" \
    "$("$OSSL" verify -CAfile samekey.pem leaf.pem 2>/dev/null)"
chk "  and it is the one that signs now" "$SK_SERIAL" \
    "$(pg_exec "SELECT serial FROM certs WHERE id='rekey' AND is_ca AND status=0
                  AND \"notAfter\" > $(date +%s)
                ORDER BY \"notBefore\" DESC, ins_seq DESC NULLS LAST, serial DESC LIMIT 1;" | tr -d ' ')"

echo "=== 10. renewing a SUB CA: signed by its parent, outliving its old certificate ==="
SUB_URI=$(hsm_new_key_uri rekeysub)
C=$(code "$U/api/ca-instances" --data-urlencode 'id=rsub' --data-urlencode 'name=Renew Sub' \
      --data-urlencode 'subject=/CN=Renew Sub CA/O=FastPKI Test' --data-urlencode 'parent=rekey' \
      --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$SUB_URI" --data-urlencode 'keygen=true' \
      --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' --data-urlencode 'days=10')
[ "$C" = 201 ] || echo "  (create said: $C $(cut -c1-160 r.json))"
chk "a 10-day sub CA under the root -> 201" 201 "$C"
SUB1=$(pg_exec "SELECT serial FROM certs WHERE id='rsub' AND is_ca;" | tr -d ' ')
getpem "$SUB1" sub1.pem
SUB1_NA=$(epoch "$SUB1")
sleep 1
for mode in samekey newkey; do
    if [ "$mode" = samekey ]; then
        RC=$(code "$U/api/ca-instances/rsub/renew" --data-urlencode 'samekey=true' --data-urlencode 'days=365')
    else
        RC=$(code "$U/api/ca-instances/rsub/renew" --data-urlencode "keyref=$(hsm_new_key_uri rekeysub2)" \
                --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' --data-urlencode 'days=365')
    fi
    echo "  ($mode renew said: $(cut -c1-160 r.json))"
    chk "$mode: sub CA renew -> 201" 201 "$RC"
    S=$(sed -n 's/.*"serial":"\([^"]*\)".*/\1/p' r.json)
    getpem "$S" "sub-$mode.pem"
    chk "  the parent signed it"         rekey "$(sed -n 's/.*"signer":"\([^"]*\)".*/\1/p' r.json)"
    chk "  no bridge or cross for a sub CA" "|" \
        "$(sed -n 's/.*"bridgeSerial":"\([^"]*\)".*/\1/p' r.json)|$(sed -n 's/.*"crossSerial":"\([^"]*\)".*/\1/p' r.json)"
    chk "  issued by the root's subject" \
        "$("$OSSL" x509 -in samekey.pem -noout -subject | sed 's/^subject=//')" \
        "$("$OSSL" x509 -in "sub-$mode.pem" -noout -issuer | sed 's/^issuer=//')"
    chk "  it chains to the root, a full chain" "sub-$mode.pem: OK" \
        "$("$OSSL" verify -CAfile samekey.pem "sub-$mode.pem" 2>/dev/null)"
    chk "  ⚠️ it outlives the old sub CA certificate" yes \
        "$([ "$(epoch "$S")" -gt "$((SUB1_NA + 300*86400))" ] && echo yes || echo no)"
    chk "  and verifies after the old one has expired" "sub-$mode.pem: OK" \
        "$("$OSSL" verify -attime "$((SUB1_NA + 86400))" -CAfile samekey.pem "sub-$mode.pem" 2>/dev/null)"
    chk "  its subject is the sub CA's, byte for byte" \
        "$(pg_exec "SELECT encode(\"sHash\",'hex') FROM certs WHERE serial='$SUB1';")" \
        "$(pg_exec "SELECT encode(\"sHash\",'hex') FROM certs WHERE serial='$S';")"
    sleep 1
done
chk "same-key: the renewal certifies the sub CA's own key" "$(pubhash sub1.pem)" "$(pubhash sub-samekey.pem)"
chk "new key: the renewal certifies a different key" yes \
    "$([ "$(pubhash sub-newkey.pem)" != "$(pubhash sub1.pem)" ] && echo yes || echo no)"
chk "the sub CA's parent is still the root" rekey \
    "$(curl -s -b cj "$U/api/ca-instances" | tr '{' '\n' | grep '"id":"rsub"' \
         | grep -o '"parentId":"[^"]*"' | head -1 | cut -d'"' -f4)"
chk "all three sub CA generations are kept" 3 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='rsub' AND is_ca;" | tr -d ' ')"


echo "=== a CA put ON HOLD holds every generation, and releasing it restores every one ==="
# rsub has three generations (section 10). A hold is posted against ONE serial, as the console
# does, and has to reach them all — or relying parties keep building a path through the others.
SUB_NEWEST=$(pg_exec "SELECT serial FROM certs WHERE id='rsub' AND is_ca AND status=0
                      ORDER BY \"notBefore\" DESC, ins_seq DESC NULLS LAST, serial DESC LIMIT 1;" | tr -d ' ')
chk "hold the sub CA (certificateHold) -> 200" 200 \
    "$(curl -s -o hold.json -w '%{http_code}' -b cj -X POST "$U/api/certs/$SUB_NEWEST/revoke?reason=6")"
chk "  every generation is on hold" "3|0" \
    "$(pg_exec "SELECT count(*) FILTER (WHERE status=-1 AND \"revocationReason\"=6)||'|'||count(*) FILTER (WHERE status=0)
                FROM certs WHERE id='rsub' AND is_ca;" | tr -d ' ')"
CAS=$(curl -s -b cj "$U/api/ca-instances")
chk "  the CA list says onHold" yes \
    "$(echo "$CAS" | tr '{' '\n' | grep '"id":"rsub"' | grep -q '"onHold":true' && echo yes || echo no)"
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout held.key -subj "/CN=while-held.internal" -out held.csr >/dev/null 2>&1
HC=$(curl -s -o held-iss.json -w '%{http_code}' -b cj -X POST --data-binary @held.csr "$U/api/certs/request?ca_instance=rsub")
chk "  and it does not sign" yes "$([ "$HC" != 201 ] && echo yes || echo no)"
chk "  saying it is on hold" yes "$(grep -q 'on hold' held-iss.json && echo yes || echo no)"
chk "release the hold -> 200" 200 \
    "$(curl -s -o rel.json -w '%{http_code}' -b cj -X POST "$U/api/certs/$SUB_NEWEST/release")"
chk "  it names the other generations it released" 2 \
    "$(grep -o '"alsoReleased":\[[^]]*\]' rel.json | grep -o '"[0-9a-f]*"' | grep -vc alsoReleased)"
chk "  every generation is valid again" "0|3" \
    "$(pg_exec "SELECT count(*) FILTER (WHERE status=-1)||'|'||count(*) FILTER (WHERE status=0)
                FROM certs WHERE id='rsub' AND is_ca;" | tr -d ' ')"
HC=$(curl -s -o held-iss.json -w '%{http_code}' -b cj -X POST --data-binary @held.csr "$U/api/certs/request?ca_instance=rsub")
chk "  and it signs again" 201 "$HC"

echo "=== the CLI renews the same way the console does ==="
# ⚠️ ASSERTED HERE RATHER THAN IN A SUITE OF ITS OWN, because what matters is that the two
# paths agree. Renewing lived only in the console handler, so a CA could be renewed only from
# a browser — and the operators who need it most are on nodes reached over SSH. Both callers
# now ask pki::renew_ca(), and the way to keep that true is to exercise them side by side
# against one database: the console renewed `rsub` above, the CLI renews it again below, and
# the result has to be another live generation of the same CA under the same key.
CA="$ROOT/build/fastpki-ca"
SUB_BEFORE=$(pg_exec "SELECT count(*) FROM certs WHERE id='rsub' AND is_ca AND status=0;" | tr -d ' ')
SUB_KEY_BEFORE=$(pg_exec "SELECT private_key FROM certs WHERE id='rsub' AND is_ca AND status=0
                          ORDER BY \"notBefore\" DESC, ins_seq DESC NULLS LAST LIMIT 1;" | tr -d ' ')

# The key options shape a key. With no key being minted they would do nothing at all, and a
# silently dropped --replicable is how an HA pair finds out at its first promotion that a key
# was never extractable — so they are refused, not ignored.
OUT=$("$CA" --config bootstrap.conf renew rsub --replicable 2>&1); RC=$?
chk "--replicable without a new key is refused" 1 "$RC"
chk "  and it says how to ask for either" yes \
    "$(echo "$OUT" | grep -q -- '--new-key' && echo yes || echo no)"
chk "  and nothing was issued" "$SUB_BEFORE" \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='rsub' AND is_ca AND status=0;" | tr -d ' ')"

OUT=$("$CA" --config bootstrap.conf renew rsub --days 400 2>&1); RC=$?
[ "$RC" = 0 ] || echo "  --- renew output ---
$OUT"
chk "a same-key renewal from the CLI succeeds" 0 "$RC"
chk "  and it added a generation" "$((SUB_BEFORE + 1))" \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='rsub' AND is_ca AND status=0;" | tr -d ' ')"
SUB_CLI=$(pg_exec "SELECT serial FROM certs WHERE id='rsub' AND is_ca AND status=0
                   ORDER BY \"notBefore\" DESC, ins_seq DESC NULLS LAST LIMIT 1;" | tr -d ' ')
chk "  which is the CA's newest certificate" yes \
    "$([ -n "$SUB_CLI" ] && [ "$SUB_CLI" != "$SUB_NEWEST" ] && echo yes || echo no)"
chk "  on the SAME key, because no new one was asked for" "$SUB_KEY_BEFORE" \
    "$(pg_exec "SELECT private_key FROM certs WHERE id='rsub' AND is_ca AND status=0
                ORDER BY \"notBefore\" DESC, ins_seq DESC NULLS LAST LIMIT 1;" | tr -d ' ')"
# The CLI audits where it previously recorded nothing at all, and under its own interface name
# so an auditor can tell a renewal run over SSH from one done in a browser.
chk "  and the run is audited as a CLI renewal" yes \
    "$(pg_exec "SELECT count(*) FROM audit_log WHERE action='cli_ca_renewed' AND target='rsub';" \
       | tr -d ' ' | grep -qE '^[1-9]' && echo yes || echo no)"

# The refusal an operator meets most often, because the deployment guide tells them to disable
# the root once the issuing CAs are signed. A refusal that does not name the remedy costs a
# round trip to find out that the parent has to be enabled for the renewal.
"$CA" --config bootstrap.conf disable rekey >/dev/null 2>&1
OUT=$("$CA" --config bootstrap.conf renew rsub 2>&1); RC=$?
chk "a disabled parent refuses the renewal" 1 "$RC"
chk "  and the refusal names enabling it" yes \
    "$(echo "$OUT" | grep -q 'enable' && echo yes || echo no)"
"$CA" --config bootstrap.conf enable rekey >/dev/null 2>&1
chk "  and re-enabling it lets the renewal through" 0 \
    "$("$CA" --config bootstrap.conf renew rsub >/dev/null 2>&1; echo $?)"

echo "=== ⚠️ revoking a RE-KEYED CA revokes EVERY generation, through the console route ==="
# This assertion exists because its absence hid a dead control twice over. The console can
# only post ONE serial — list_ca_instances is DISTINCT ON (id) and hands back the newest — so
# revoking a re-keyed CA left the PARENT-SIGNED generation valid, and relying parties went on
# building leaf -> old generation -> parent with nothing revoked on the parent's CRL. The
# cascade that fixes it then shipped INERT, because get_cert() did not SELECT is_ca and the
# guard `row->is_ca && !row->ca_id.empty()` could never be true.
#
# ⚠️ DRIVEN THROUGH THE HTTP ROUTE, NOT pg_exec. tests/crl.sh revokes with a direct UPDATE,
# which is exactly why a green suite said nothing about either defect: SQL cannot exercise a
# guard that lives in the handler.
GENS=$(pg_exec "SELECT count(*) FROM certs WHERE id='rekey' AND is_ca AND status=0;" | tr -d ' ')
chk "PRECONDITION: the re-keyed CA has more than one live generation" yes \
    "$([ "${GENS:-0}" -ge 2 ] && echo yes || echo no)"
NEWEST=$(pg_exec "SELECT serial FROM certs WHERE id='rekey' AND is_ca AND status=0 ORDER BY \"notBefore\" DESC, ins_seq DESC NULLS LAST, serial DESC LIMIT 1;" | tr -d ' ')
chk "console revoke of the newest generation -> 200" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b cj -X POST "$U/api/certs/$NEWEST/revoke")"
chk "  and EVERY generation is now revoked" 0 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='rekey' AND is_ca AND status=0;" | tr -d ' ')"
# The audit row must name what it actually did, or an operator reading it later is misled.
chk "  and the audit entry names the extra serials" yes \
    "$(pg_exec "SELECT count(*) FROM audit_log WHERE action='web_cert_revoked' AND detail LIKE '%also_revoked=%';" | tr -d ' ' | grep -qE '^[1-9]' && echo yes || echo no)"
echo
echo "=== CA REKEY: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
