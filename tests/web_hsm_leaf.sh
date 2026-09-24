#!/usr/bin/env bash
# Request a leaf certificate whose private key is generated INSIDE the
# HSM and never leaves it.
#
# The console's other self-service form makes the keypair in the browser with
# Web Crypto and hands the user a PKCS#8 — the right shape for a certificate on a
# laptop, the wrong one for a service identity that should hold a non-exportable
# key. POST /api/certs/request-hsm mints into a caller-named pkcs11: object instead
# and returns only the certificate.
#
# What this asserts, by decoding real artifacts rather than trusting status codes:
#   * the handle is REQUIRED — no server-side guess at the operator's token layout
#   * the certificate's public key is BYTE-IDENTICAL to the one in the token, which
#     is the only real proof the key it certifies is the key the HSM holds
#   * the private key object exists in the token and the response carries no key
#   * SANs typed the same way the in-browser encoder types them (DNS/IP/email/URI/UPN)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
unset OPENSSL_CONF
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18131
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

pg_setup web_hsm_leaf
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
ca_in_token ca.pem "/CN=Leaf Issuing CA" 3650 leafca
source "$ROOT/tests/user_helpers.sh"
seed_web_user boss bosspw admin
# ⚠️ PIN boss TO `requester` EXPLICITLY. This fixture makes ONE identity play two
# parts: it is seeded as an `admin` (it needs hsm:manage) and it also customises the
# `requester` profile and then checks the customisation applied to what it issued. Since the
# fallback became role-derived — it is logical for the master profile to be
# associated with the admin user by default — so an admin with no assignment
# resolves to `admin`, so those five assertions started measuring the wrong profile.
#
# The product behaviour is what he asked for; the fixture was conflating two roles. An
# explicit grant is the documented way to hold an admin on a restricted profile, and it is
# exactly what a deployment would do — so asserting through one is more honest than
# asserting through a default that happens to be `requester`.
# ⚠️ It used to be a raw INSERT into profile_assignments, and my first version got the
# column names wrong with `2>/dev/null || true` on the end: the INSERT errored silently and
# the five assertions stayed red while the comment above claimed they were fixed. The
# helper is not just tidier — it cannot fail quietly.
grant_profile boss requester
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=leafca
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
# The Serve-As key-name auto-fill is driven by the SERVER's transportKeys map,
# which is keyed by each role's cert-id setting. All three now default (the re-key path gave
# cmp_ra_cert_id_prefix the "cmp-ra" default its siblings already had); this line is kept
# so the suite states the id it asserts on rather than depending on a default.
CMP_RA_CERT_ID_PREFIX=cmp-ra
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
# The deployment names its token and PIN file, so the console can offer them as
# defaults instead of asking an operator to retype what the config already says.
PINFILE="$W/pin"; printf '1234' > "$PINFILE"; chmod 400 "$PINFILE"
CFG_TOKEN=$(echo "${CA_KEY_URI:-}" | sed -n 's/.*token=\([^;?]*\).*/\1/p')
printf 'PKCS11_TOKEN=%s\nPKCS11_PIN_FILE=%s\n' "$CFG_TOKEN" "$PINFILE" >> bootstrap.conf
# The three per-CA RA roles need their KEYS configured too, or transport_key_for
# has nothing to return and the assertions below cannot tell "correctly empty" from
# "empty because the lookup is broken" — which is exactly the bug they guard.
printf 'CMP_RA_KEY=pkcs11:token=%s;object=svc-cmpra;type=private?pin-value=1234\n' "$CFG_TOKEN" >> bootstrap.conf
printf 'OCSP_RESPONDER_KEY=pkcs11:token=%s;object=svc-ocspra;type=private?pin-value=1234\n' "$CFG_TOKEN" >> bootstrap.conf
printf 'SCEP_RA_KEY=pkcs11:token=%s;object=svc-scepra;type=private?pin-value=1234\n' "$CFG_TOKEN" >> bootstrap.conf
# A listener whose transport id AND key are configured, so the mismatch
# guard has a pair to compare. Without these the check has nothing to say.
printf 'EST_CERT_ID=est\nEST_KEY=pkcs11:token=%s;object=svc-est;type=private?pin-value=1234\n' \
       "$CFG_TOKEN" >> bootstrap.conf
seed_ca_from_conf bootstrap.conf
CA_ID=$(sed -n 's/^SIGNING_CA_ID=//p' bootstrap.conf | head -1)
[ -z "$CA_ID" ] && CA_ID=leafca

"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat srv.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null

# The leaf key goes into the SAME token the CA lives in — one token holding several
# objects is the ordinary deployment shape, and it keeps the suite to one token.
TOKEN=$(echo "$CA_KEY_URI" | sed -n 's/.*token=\([^;]*\).*/\1/p')
LEAF_URI="pkcs11:token=$TOKEN;object=svc-web;type=private?pin-value=1234"

post(){ curl -s -b boss.cj "$U/api/certs/request-hsm" "$@"; }
code(){ curl -s -o /dev/null -w '%{http_code}' -b boss.cj "$U/api/certs/request-hsm" "$@"; }

echo "=== 1. the pkcs11 handle is required — the server never guesses a token ==="
chk "no keyref -> 400" 400 "$(code --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=nope')"
chk "a file path is not a handle -> 400" 400 \
    "$(code --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=nope' \
            --data-urlencode 'keyref=/var/pki/svc.key')"
chk "no ca_instance -> 400" 400 \
    "$(code --data-urlencode 'cn=nope' --data-urlencode "keyref=$LEAF_URI")"

echo "=== 2. issue a leaf with the key minted in the token ==="
R=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode "keyref=$LEAF_URI" \
         --data-urlencode 'cn=svc.example.org' --data-urlencode 'o=FastPKI' \
         --data-urlencode 'ou=Platform' --data-urlencode 'c=US' \
         --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
         --data-urlencode 'sans=svc.example.org
10.0.0.7
ops@example.org' \
         --data-urlencode 'ku=digitalSignature,keyEncipherment' \
         --data-urlencode 'eku=serverAuth,clientAuth')
chk "issued (response carries a serial)" yes "$(has "$R" '"serial"')"
chk "response echoes the pkcs11 handle"  yes "$(has "$R" 'pkcs11:token=')"

# The point of the whole form: there is no private key to hand back.
chk "response carries NO private key"    no  "$(has "$R" 'BEGIN.*PRIVATE KEY')"
chk "response has no \"key\" field"      no  "$(has "$R" '"key"[[:space:]]*:')"

# Pull the PEM out of the JSON in shell (§3e): the value has no embedded quotes,
# only \n escapes, so a cut at the quotes and an unescape is exact here.
echo "$R" | sed -n 's/.*"pem":"\([^"]*\)".*/\1/p' | sed 's/\\n/\
/g' > leaf.pem
chk "a certificate came back" yes "$([ -s leaf.pem ] && "$OSSL" x509 -in leaf.pem -noout -subject >/dev/null 2>&1 && echo yes || echo no)"
T=$("$OSSL" x509 -in leaf.pem -noout -text 2>/dev/null)

echo "=== 3. the certified key IS the key in the token ==="
# Read the public half straight out of the token and compare it with the public key
# the CA certified. Equal bytes means the certificate belongs to the HSM key — the
# assertion the whole feature rests on.
"$OSSL" pkey $CA_OSSL_ARGS -pubin \
    -in "pkcs11:token=$TOKEN;object=svc-web;type=public" -pubout -out token_pub.pem 2>/dev/null
# Compare the modulus, not the PEM: the provider hands back a PKCS#1 RSAPublicKey
# while the certificate carries an SPKI, so the same key has two different wrappers
# and a byte compare of the files would fail on identical keys.
MOD_T=$("$OSSL" rsa -pubin -RSAPublicKey_in -in token_pub.pem -noout -modulus 2>/dev/null)
[ -z "$MOD_T" ] && MOD_T=$("$OSSL" rsa -pubin -in token_pub.pem -noout -modulus 2>/dev/null)
MOD_C=$("$OSSL" x509 -in leaf.pem -noout -modulus 2>/dev/null)
chk "the token's public key was readable" yes "$([ -n "$MOD_T" ] && echo yes || echo no)"
chk "cert public key == token public key" yes \
    "$([ -n "$MOD_T" ] && [ "$MOD_T" = "$MOD_C" ] && echo yes || echo no)"
# And the PRIVATE half is a token object — it was created in the HSM, not imported.
OBJS=$("$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$TOKEN" --login --pin 1234 \
       --list-objects --type privkey 2>/dev/null)
chk "private key object 'svc-web' lives in the token" yes "$(has "$OBJS" 'svc-web')"

echo "=== 4. the issued cert carries what was asked for ==="
# ⚠️ THE CN IS ALSO THE NO-ROLE GUARD, so state that here or the next person deletes it as a
# duplicate of the DN assertions below. WEB_SELFSERVICE_IDENTITY_SUBJECT rewrites CN to the
# caller's own username for a self-service request; both issuance handlers used to decide
# that with `role != "admin"`, a hardcoded builtin name. `boss` now holds the CUSTOM role
# grant_profile builds — full admin capabilities, a name that is not "admin" — which under
# the old test issued CN=boss: right key, right SANs, right KU/EKU, wrong subject, 201.
# The precondition is what makes this a guard rather than a coincidence: assert the role
# string really is not "admin", or a fixture change quietly restores the old pass.
chk "PRECONDITION: boss's role is NOT the literal 'admin'" no \
    "$(pg_exec "SELECT role FROM web_users WHERE username='boss';" | grep -qx 'admin' && echo yes || echo no)"
# ⚠️ CHANGED THIS ONE LINE'S EXPECTATION, and only this one. Whether issuance
# rewrites the CN is now decided by the PROFILE alone: the `!issues_for_others(req)`
# capability term is gone, because it short-circuited for anyone holding
# *:*/cert:read and made the profile's "do not override subject" checkbox dead
# for exactly those callers — the chosen behaviour. boss holds the
# `requester` profile, which does NOT preserve subjects, so the CN is now boss.
#
# The guard above is untouched and still does its job: it asserts the ROLE string is
# not the literal "admin", and no code path consults a role string for this decision.
# ⚠️ Do NOT "fix" this by moving boss to the `admin` profile — I tried, and it silently
# disabled four assertions below, because `requester` is what refuses the otherName SAN
# and empties the KU. The profile is load-bearing for the rest of this suite.
# ⚠️ DECODE THE SUBJECT, not the -text dump. `has "$T" 'CN *= *boss'` passes even with
# the fix reverted, because the Subject Directory Attributes extension carries
# `owner: CN=boss` in that same dump — I wrote exactly that and the control caught it
# staying green both ways. A guard that cannot fail is worse than no guard.
chk "CN is the caller (requester profile does not preserve the subject)" "boss" \
    "$("$OSSL" x509 -in leaf.pem -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')"
chk "O"                     yes "$(has "$T" 'O *= *FastPKI')"
chk "RSA 2048"              yes "$(has "$T" 'Public-Key: (2048 bit)')"
chk "not a CA"              yes "$(has "$T" 'CA:FALSE')"
chk "SAN DNS"               yes "$(has "$T" 'DNS:svc.example.org')"
chk "SAN IP typed as IP"    yes "$(has "$T" 'IP Address:10.0.0.7')"
chk "SAN email typed"       yes "$(has "$T" 'email:ops@example.org')"
chk "KU digitalSignature"   yes "$(has "$T" 'Digital Signature')"
chk "EKU serverAuth"        yes "$(has "$T" 'TLS Web Server Authentication')"
chk "EKU clientAuth"        yes "$(has "$T" 'TLS Web Client Authentication')"

echo "=== 5. an HSM key is not a way around the issuance policy ==="
# The same profile rules the CSR path obeys. Minting the key inside the token
# changes where the key lives, and nothing about what may be certified — worth
# asserting explicitly, because a second issuance entry point is exactly where a
# policy bypass would hide.
deny(){ post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=t.example.org' \
             --data-urlencode "keyref=pkcs11:token=$TOKEN;object=$1;type=private?pin-value=1234" \
             --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
             --data-urlencode "sans=$2"; }
# ⚠️ URI is NOT the example any more. It was added to `requester`'s allowed SAN
# types as required (URI added to the allowed SAN types), so the request
# that used to be refused here now issues — and the whole point of this block is a REFUSAL,
# so it has to name a type the profile still declines. `othername` is that type, and the
# control below proves URI really does issue rather than the assertion having been dropped
# because it became inconvenient.
chk "otherName/upn SAN refused by profile"        yes "$(has "$(deny d1 'upn:svc@corp.example')"      'not permitted by profile')"
chk "  a second otherName is refused too"         yes "$(has "$(deny d2 'upn:other@corp.example')"    'not permitted by profile')"
chk "out-of-range IP SAN refused"                 yes "$(has "$(deny d3 '2001:db8::1')"               'not in the approved range')"
chk "CONTROL: a URI SAN now ISSUES" no \
    "$(has "$(deny ok1 'https://svc.example.org/id')" 'not permitted by profile')"
# …and a refusal costs nothing. Every one of those three named a token object; if the
# policy check ran after key generation, three keypairs would now be sitting in the
# HSM that no certificate will ever name and no operator will ever know about.
DENIED=$("$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$TOKEN" --login --pin 1234 \
         --list-objects --type privkey 2>/dev/null)
chk "a refused request minted NO key"             0 \
    "$(echo "$DENIED" | grep -c 'label:.*d[123]$' | tr -d ' ')"

echo "=== 6. it landed in the inventory, issued by this CA ==="
SER=$("$OSSL" x509 -in leaf.pem -noout -serial 2>/dev/null | sed 's/serial=//' | tr 'A-Z' 'a-z' | sed 's/^0*//')
INV=$(curl -s -b boss.cj "$U/api/certs?limit=100")
chk "the serial was read back" yes "$([ -n "$SER" ] && echo yes || echo no)"
chk "serial is in the inventory" yes "$([ -n "$SER" ] && has "$INV" "$SER" || echo no)"
chk "chains to the issuing CA"   yes \
    "$("$OSSL" verify -CAfile ca.pem leaf.pem >/dev/null 2>&1 && echo yes || echo no)"

echo "=== 7. a second object in the same token does not collide ==="
R2=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=svc2.example.org' \
          --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-two;type=private?pin-value=1234" \
          --data-urlencode 'key=rsa' --data-urlencode 'bits=2048')
chk "second leaf issued" yes "$(has "$R2" '"serial"')"
OBJS2=$("$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$TOKEN" --login --pin 1234 \
        --list-objects --type privkey 2>/dev/null)
chk "both key objects present" yes \
    "$([ "$(echo "$OBJS2" | grep -c 'svc-web\|svc-two')" -ge 2 ] && echo yes || echo no)"

echo "=== 8. a custom EKU OID: issued when the profile permits it, refused when not ==="
# A follow-up: the form takes an EKU that has no friendly name. The rule is
# the same one the named purposes obey — `allowed_eku` is an ALLOW-LIST, so an OID is
# issuable exactly when an admin has listed it. There is no OID special case, and no
# way to slip an arbitrary purpose past a profile.
kill $P 2>/dev/null; wait $P 2>/dev/null
cp bootstrap.conf pki2.conf
# 1.3.6.1.4.1.99999.7.1 is in a private arc OpenSSL has no name for, so it travels as
# a dotted OID all the way through — which is the case worth proving.
seed_cert_profiles '{"requester":{"allowed_ku":["digitalSignature","keyEncipherment","nonRepudiation"],"allowed_eku":["serverAuth","clientAuth","1.3.6.1.4.1.99999.7.1"],"default_ku":["digitalSignature","keyEncipherment"],"default_eku":["serverAuth","clientAuth"],"allow_wildcard":false}}'
"$WEB" --config pki2.conf >srv2.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "pki2.conf" WEB_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died on the profile override:"; cat srv2.log; fi
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null

R3=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=svc3.example.org' \
          --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-three;type=private?pin-value=1234" \
          --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
          --data-urlencode 'eku=clientAuth,1.3.6.1.4.1.99999.7.1')
echo "$R3" | sed -n 's/.*"pem":"\([^"]*\)".*/\1/p' | sed 's/\\n/\
/g' > leaf3.pem
T3=$("$OSSL" x509 -in leaf3.pem -noout -text 2>/dev/null)
chk "leaf with a permitted custom EKU issued" yes "$(has "$R3" '"serial"')"
[ "$(has "$R3" '"serial"')" = no ] && echo "      server said: $(echo "$R3" | head -c 300)"
chk "the custom OID is IN the cert"  yes "$(has "$T3" '1.3.6.1.4.1.99999.7.1')"
chk "...alongside the named purpose" yes "$(has "$T3" 'TLS Web Client Authentication')"

# Everything below must be refused BEFORE the key is minted. This is the whole reason
# the pre-flight exists: the key is created INSIDE a token, so a request rejected on
# the way out leaves a keypair in hardware that no certificate names, that nothing
# tracks, and that no later run can tell apart from a real one.
orphan(){ post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=svc4.example.org' \
               --data-urlencode "keyref=pkcs11:token=$TOKEN;object=$1;type=private?pin-value=1234" \
               --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
               --data-urlencode "$2"; }
# ⚠️ An EKU the profile forbids is no longer a refusal — it is DROPPED. So the
# refusals that still exist are the two below, and they are what keeps this pre-flight
# ordering honest. Picking a case that no longer refuses would leave the whole section
# asserting nothing while still reading green.
chk "KU that the profile empties -> refused" yes \
    "$(has "$(orphan orph-1 'ku=keyCertSign,cRLSign')" 'EMPTY KeyUsage')"
chk "a string that is not an OID -> refused" yes \
    "$(has "$(orphan orph-2 'eku=clientAuth,not-an-oid')" 'bad extendedKeyUsage')"
ORPH=$("$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$TOKEN" --login --pin 1234 \
       --list-objects --type privkey 2>/dev/null)
chk "NO orphan key was left in the token" no "$(has "$ORPH" 'orph-')"

# ...and the case that USED to sit above: a forbidden EKU now issues, minus the OID.
# The key it mints is a real one, so it is deliberately NOT named orph-*: naming it
# that way would make the sweep above fail on a legitimate key.
R5=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=svc5.example.org' \
          --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-five;type=private?pin-value=1234" \
          --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
          --data-urlencode 'eku=clientAuth,1.3.6.1.4.1.99999.7.2')
echo "$R5" | sed -n 's/.*"pem":"\([^"]*\)".*/\1/p' | sed 's/\\n/\
/g' > leaf5.pem
T5=$("$OSSL" x509 -in leaf5.pem -noout -text 2>/dev/null)
chk "an OID the profile forbids -> issued (dropped)" yes "$(has "$R5" '"serial"')"
chk "  the forbidden OID is NOT in the cert" no  "$(has "$T5" '1.3.6.1.4.1.99999.7.2')"
chk "  the permitted purpose survived"       yes "$(has "$T5" 'TLS Web Client Authentication')"

echo "=== 8b. CA creation obeys the same rule: refuse first, mint second ==="
# `keygen=true` on POST /api/ca-instances mints in the token exactly as the leaf path
# does, so it needs the same ordering. This one is already correct — the parent
# check runs before the key is created — and the point of the assertion is to KEEP it
# that way, because the failure would be silent: a mistyped parent id would still
# return a tidy error while leaving a keypair behind in the HSM.
# (Asserted here rather than in web_ca_hsm.sh because that suite skips wherever the
# pkcs11 provider ABI is unavailable — an assertion that never runs proves nothing.)
#
# ⚠️ NOT AS `boss`. The CA-creation page consults the acting admin's profile,
# and this fixture deliberately pins `boss` to `requester`, which does not permit
# basicConstraints CA:TRUE. Driven as boss the request is refused at the PROFILE — a 403
# that never reaches the parent check, so the two assertions below would both pass while
# measuring nothing about ordering. A refusal firing for the wrong reason reads exactly
# like a pass. `caboss` is an admin with no profile pin, so it resolves to `admin`.
seed_web_user caboss cabosspw admin
curl -s -c caboss.cj -d 'username=caboss&password=cabosspw' "$U/api/login" >/dev/null
# ...and while we are here, assert the basicConstraints refusal itself, since this fixture already
# holds the one identity that must NOT be able to create a CA.
PROFBODY=$(curl -s -b boss.cj -X POST "$U/api/ca-instances" \
      --data-urlencode 'id=ca-byrequester' --data-urlencode 'subject=/CN=Requester CA' \
      --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' -w '|%{http_code}')
chk "the requester profile may not create a CA" 403 "${PROFBODY##*|}"
chk "  and it says why (basicConstraints CA:TRUE)"    yes \
    "$(has "${PROFBODY%|*}" 'basicConstraints CA:TRUE')"
CABODY=$(curl -s -b caboss.cj -X POST "$U/api/ca-instances" \
      --data-urlencode 'id=ca-badparent' --data-urlencode 'subject=/CN=Bad Parent CA' \
      --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
      --data-urlencode 'parent=no-such-ca' --data-urlencode 'keyloc=pkcs11' \
      --data-urlencode 'keygen=true' \
      --data-urlencode "keyref=pkcs11:token=$TOKEN;object=ca-orphan;type=private?pin-value=1234" \
      -w '|%{http_code}')
CAJ=${CABODY##*|}
chk "unknown parent is refused"      400 "$CAJ"
[ "$CAJ" = 400 ] || echo "      server said: ${CABODY%|*}"
CAOBJ=$("$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$TOKEN" --login --pin 1234 \
        --list-objects --type privkey 2>/dev/null)
chk "...and NO CA key was minted"    no  "$(has "$CAOBJ" 'ca-orphan')"

echo "=== 9. the slot list carries this deployment's defaults, never the PIN ==="
SLOTS=$(curl -s -b boss.cj "$U/api/pkcs11/slots")
chk "the configured token is offered"  yes "$(has "$SLOTS" "\"token\":\"$CFG_TOKEN\"")"
chk "the PIN FILE PATH is offered"     yes "$(has "$SLOTS" "\"pinFile\":\"$PINFILE\"")"
# Match the PIN as a JSON *value* (quoted) and the URI form, never the bare digits.
# `"slot":<id>` is an UNQUOTED number and SoftHSM assigns slot ids at random, so a bare
# grep for 1234 false-fails whenever an id happens to contain those digits — which it
# did, once, in a full-suite run where enough tokens existed to make it likely. An
# assertion that fails for a reason unrelated to what it is testing is worse than none.
chk "the PIN VALUE is never served"    no  "$(has "$SLOTS" '"1234"')"
chk "no pin-value= is served either"   no  "$(has "$SLOTS" 'pin-value')"
chk "the real slot is enumerated"      yes "$(has "$SLOTS" "\"slot\":")"

echo "=== 10. the console actually wires the form (served JS, not just markup) ==="
# Grep-proxies are weak, but they catch a reintroduction — and the shell harness
# cannot run JS, so the runtime behaviour is checked in a browser before deploy.
# These assert the wiring the browser pass exercised.
SRC="$ROOT/src/web/main.cpp"
# -F: every pattern below is a literal snippet of the served page, and BSD and GNU
# grep disagree about enough BRE metacharacters that a regex here would silently
# match nothing on one of the two platforms.
inpage(){ grep -qF "$1" "$SRC" && echo yes || echo no; }
chk "Inventory has a toolbar, not stacked <details>" yes "$(inpage 'class="toolbar"')"
chk "the three request routes are buttons"           yes "$(inpage 'id="reqhsm"')"
chk "the HSM modal uses the shared shell"            yes "$(inpage 'id="hsmmodal" class="modal"')"
chk "the form posts to /api/certs/request-hsm"       yes "$(inpage '/api/certs/request-hsm')"
# Follow-up: the handle is PICKED, not typed. A raw pkcs11: URI in a text box asks
# an operator to know a syntax the console already knows.
chk "the handle comes from a slot dropdown"          yes "$(inpage 'id="inv_hsm_slot"')"
chk "...and keyref is assembled, not typed"          yes "$(inpage 'type="hidden" name="keyref" id="inv_keyref"')"
chk "a custom EKU OID field exists"                  yes "$(inpage 'name="ekucustom"')"
chk "the HSM form applies the KU/EKU rules"          yes "$(inpage 'syncKuEku(f, HSM_KU_NAMES)')"
# The CA form had a dropdown of slots (partitions), a textbox for the object name
# and another for the pin file name, and the same shape was required for the
# "Request key in HSM" form. The dropdown was
# already asserted above; the other two boxes were not, so a regression could remove
# either and still pass. Named here so the next reader knows these are his asks.
chk "...a Key name box"                              yes "$(inpage 'id="inv_hsm_obj"')"
chk "...and a PIN file box"                          yes "$(inpage 'id="inv_hsm_pinsrc"')"
# The KU-validity table is what makes the rule above depend on the KEY TYPE — the
# actual ask. Without it syncKuEku still runs and enforces nothing algorithm-specific.
chk "KU validity is keyed by algorithm"              yes "$(inpage 'const KEY_KU_VALID')"
chk "...RSA-only bits are denied to EC"              yes \
    "$(sed -n '/const KEY_KU_VALID/,/};/p' "$SRC" | grep -q "ec: *\['digitalSignature','nonRepudiation'\]" && echo yes || echo no)"
chk "...and to Ed25519"                              yes \
    "$(sed -n '/const KEY_KU_VALID/,/};/p' "$SRC" | grep -q "ed25519:\['digitalSignature','nonRepudiation'\]" && echo yes || echo no)"
# The first ask was the CAs page: File offered, HSM not. That was fixed, but the
# guard belongs next to the others so the pair cannot drift apart again.
chk "the New CA form picks a slot too"        yes "$(inpage 'id="ca_hsm_slot"')"
chk "...and always sends keyloc=pkcs11"              yes "$(inpage "fd.set('keyloc', 'pkcs11')")"
# One URI builder for EVERY form that needs a token key. Two would be two chances to
# write a slightly different one and mint a key into the wrong token.
chk "exactly one pkcs11 URI builder"                 yes \
    "$([ "$(grep -c "let uri = 'pkcs11:'" "$SRC")" -eq 1 ] && echo yes || echo no)"
# The list grows as forms are added — the cross-node sub-CA request form is the third
# here. Pinning the whole call is deliberate: a form added WITHOUT its prefix gets no slot
# picker and no assembled handle, and its hidden keyref field then submits empty.
chk "the CA forms use that same builder"             yes "$(inpage "hsmLoadSlots(['ca','imp','cacsr'])")"
chk "so does the Inventory form"                     yes "$(inpage "hsmLoadSlots(['inv'])")"
# One KU/EKU rule table, likewise — the browser-keygen form and this one must agree.
chk "one EKU->KU rule table"                         yes \
    "$([ "$(grep -c '^const EKU_KU_REQUIRED' "$SRC")" -eq 1 ] && echo yes || echo no)"
# The whole point: this path must never hand back a private key. The Web Crypto
# form calls dl() with o.key; this one must only ever download the certificate.
# `o.key` exactly: the response's `keyref` (the token handle, which the success message
# names) is not a private key, and matching it as one made this pass or fail on wording.
chk "the HSM path downloads only the certificate"    no  \
    "$(sed -n '/async function requestHsmCert/,/^}/p' "$SRC" | grep -qE 'o\.key([^A-Za-z0-9_]|$)' && echo yes || echo no)"
chk "one modal shell, not one per modal"             yes \
    "$([ "$(grep -c '^\.modal{position:fixed' "$SRC")" -eq 1 ] && echo yes || echo no)"

echo "=== 10. one name, one key — and adopting one already there ==="
# PKCS#11 does not require a token to reject a second object with the same label, and
# SoftHSM does not: you get TWO keys with one name and an unspecified answer to "which
# one?". That is a certificate nobody can rely on and a key nobody can safely delete, so
# the collision has to be refused BEFORE minting — the same discipline as the CA form's
# algorithm pre-flight, and for the same reason: afterwards costs a keypair in hardware.
COLL="pkcs11:token=$CFG_TOKEN;object=collide;type=private?pin-source=$PINFILE"
C1=$(code --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=collide.internal' \
     --data-urlencode "keyref=$COLL" --data-urlencode 'key=rsa' --data-urlencode 'bits=2048')
chk "first request at a free handle -> 201"      201 "$C1"
objs(){ "$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$CFG_TOKEN" --login --pin 1234 \
        --list-objects 2>/dev/null | grep -c "$1" | tr -d ' '; }
BEFORE=$(objs collide)
C2=$(code --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=collide2.internal' \
     --data-urlencode "keyref=$COLL" --data-urlencode 'key=rsa' --data-urlencode 'bits=2048')
chk "generating over an occupied handle -> 409"  409 "$C2"
# The refusal must be FREE: no second object, or the guard merely relocated the problem.
chk "and no second object was minted"  "$BEFORE" "$(objs collide)"
chk "the refusal explains the choice"  yes \
    "$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=c3.internal' \
        --data-urlencode "keyref=$COLL" --data-urlencode 'key=rsa' \
        | grep -q 'existing key' && echo yes || echo no)"
# Adopting the key that IS there is the way through, and it issues.
chk "certifying the existing key -> 201"         201 \
    "$(code --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=adopted.internal' \
        --data-urlencode "keyref=$COLL" --data-urlencode 'keygen=false')"
# ...and asking to adopt a key that is not there is a 404, not a silent mint.
GHOST="pkcs11:token=$CFG_TOKEN;object=nothing-here;type=private?pin-source=$PINFILE"
chk "adopting a handle with no key -> 404"       404 \
    "$(code --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=ghost.internal' \
        --data-urlencode "keyref=$GHOST" --data-urlencode 'keygen=false')"
chk "and nothing was minted at it"                 0 "$(objs nothing-here)"

echo "=== 11. the form asks for the key before the usage it constrains ==="
IDX2=$(curl -s -b boss.cj "$U/")
# The algorithm decides which KU/EKU combinations are legal (syncKuEku reads it), so
# asking for usage first and changing the algorithm underneath it is the wrong order.
# ⚠️ NOT `grep -bo` — busybox grep has no -b, so on the shipped image both positions came
# back EMPTY and this read as "the console emits them in the wrong order". awk's index()
# is literal and works on busybox and GNU alike.
# ⚠️ FLATTEN FIRST. awk works line by line, so on multi-line HTML this printed one result
# per LINE (mostly empty) and the caller compared a multi-line string numerically — my own
# first version of this fix did exactly that and changed nothing. `tr` makes it one record;
# `exit` takes the first hit only.
byteof(){ printf '%s' "$2" | tr '\n' ' ' \
          | awk -v n="$1" '{i=index($0,n); if (i) {print i-1; exit}}'; }
APOS=$(byteof 'id="hsmalgo"'     "$IDX2")
KPOS=$(byteof 'id="hsm-keynote"' "$IDX2")
chk "algorithm appears before Key usage" yes \
    "$([ -n "$APOS" ] && [ -n "$KPOS" ] && [ "$APOS" -lt "$KPOS" ] && echo yes || echo no)"
chk "the existing-key option is offered"  yes "$(inpage 'id="hsm_existingkey"')"
chk "the submit says whether to generate" yes "$(inpage "fd.set('keygen'")"
# The advertised-mechanism filter now drives THIS form too, not just the CA one.
chk "the form is in the algorithm filter" yes "$(inpage "inv: 'hsmalgo'")"
chk "ML-DSA is offered at all"            yes "$(inpage 'ML-DSA-87')"

echo "=== 12. issue a TRANSPORT cert an endpoint actually picks up ==="
# WEB_CERT_ID / EST_CERT_ID / ACME_CERT_ID / MS_CERT_ID / CMP_RA_CERT_ID_PREFIX were readable
# settings with NO writer: every listener self-signed its own transport cert and there
# was no supported way to hand it a CA-issued one. Reported from the other end: it was
# not clear how to create new certificates for endpoints at all. So the
# assertion is not that a field exists, it is that the row a listener READS is the row
# this request WROTE.
TR_URI="pkcs11:token=$TOKEN;object=svc-est;type=private?pin-value=1234"
R12=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode "keyref=$TR_URI" \
           --data-urlencode 'cn=est.example.org' \
           --data-urlencode 'sans=est.example.org' \
           --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
           --data-urlencode 'cert_id=est')
chk "issued for a transport id"          yes "$(has "$R12" '"serial"')"
chk "the response names the id"          yes "$(has "$R12" '"cert_id":"est"')"
TR_SERIAL=$(echo "$R12" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')

# The row itself. A transport cert is a TAGGED ROW in `certs` — that is what
# resolve_transport_cert() reads at startup, so this is the assertion that the endpoint
# will serve this certificate.
chk "an ACTIVE certs row tagged 'est' exists" 1 "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='est' AND status=0;" | tr -d ' ')"
chk "...bound to the issuing CA"     "$CA_ID" "$(pg_exec "SELECT ca_instance_id FROM certs WHERE cert_id='est' AND status=0;" | tr -d ' ')"

# Decode the stored DER and prove it is the certificate that was just issued — not a
# stale row, not the CA, not something the self-signer left behind.
pg_exec "SELECT encode(cert,'hex') FROM certs WHERE cert_id='est' AND status=0;" | tr -d ' \n' > tr.hex
[ -s tr.hex ] && "$OSSL" asn1parse -genstr "FORMAT:HEX,OCTETSTRING:$(cat tr.hex)" -noout -out tr.der 2>/dev/null
# asn1parse wraps it; the DER is the octet-string payload, so strip the 4-byte header.
tail -c +5 tr.der > tr2.der 2>/dev/null || true
"$OSSL" x509 -inform DER -in tr2.der -noout -text > tr.txt 2>/dev/null
chk "the stored bytes decode as a certificate" yes "$([ -s tr.txt ] && echo yes || echo no)"
STORED_SER=$("$OSSL" x509 -inform DER -in tr2.der -noout -serial 2>/dev/null | sed 's/serial=//' | tr 'A-Z' 'a-z')
chk "and it is the cert just issued" "$(echo "$TR_SERIAL" | tr 'A-Z' 'a-z' | sed 's/^0*//')" \
    "$(echo "$STORED_SER" | sed 's/^0*//')"
chk "it carries the SAN a TLS client needs" yes "$(grep -c 'DNS:est.example.org' tr.txt | grep -q '^[1-9]' && echo yes || echo no)"
chk "it is NOT a CA certificate"            yes "$(grep -q 'CA:FALSE' tr.txt && echo yes || echo no)"

# Re-issuing the same id must REPLACE the row, not accumulate one per attempt — the
# listener reads a single row and two would make which-one-wins unspecified.
# Renewal is a NEW CERTIFICATE ON THE SAME KEY: the handle is fixed by the listener's
# config (§13), so re-certify what is already at it rather than minting beside it.
R12b=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode "keyref=$TR_URI" \
            --data-urlencode 'cn=est.example.org' --data-urlencode 'sans=est.example.org' \
            --data-urlencode 'keygen=false' \
            --data-urlencode 'cert_id=est')
chk "re-issuing the id succeeds"         yes "$(has "$R12b" '"serial"')"
# ⚠️ ONE *ACTIVE* row, not one row. Transport certs are keyed on serial inside `certs`,
# so re-issuing ADDS a row rather than replacing one — asserting a bare count of 1 would
# now be false by design. What still holds, and what this test was really about, is the
# "one cert_id, one active certificate" invariant: the console retires the previous
# holder to status=3 before inserting the new one.
chk "...and there is still ONE ACTIVE row"  1 "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='est' AND status=0;" | tr -d ' ')"
chk "...the previous one was retired, not dropped" 1 "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='est' AND status=3;" | tr -d ' ')"
NEW_SER=$(echo "$R12b" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')
chk "...holding the NEW certificate"     yes "$([ "$NEW_SER" != "$TR_SERIAL" ] && echo yes || echo no)"

# ⚠️ AN HA PAIR PUBLISHES BOTH HOSTS' LISTENER CERTIFICATES UNDER ONE ID, each for its own key.
# Re-issuing on this host must retire THIS host's previous certificate and never the peer's:
# retired, the peer's listener has no row certifying its key and falls back to self-signed.
# The peer's row is given the LATEST notAfter, so a lookup that ignores whose key a row
# certifies (get_cert_by_cert_id: newest live row) picks it — the fixture discriminates.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout peer-est.key -out peer-est.crt \
    -subj /CN=est.example.org -days 30 >/dev/null 2>&1
PEER_SER=$("$OSSL" x509 -in peer-est.crt -noout -serial | sed 's/serial=//' | tr 'A-Z' 'a-z')
NOWP=$(date +%s)
pg_exec "INSERT INTO certs(serial,status,cert,cert_id,ca_instance_id,cn,subject,\"notBefore\",\"notAfter\")
         VALUES('$PEER_SER',0, decode('$("$OSSL" x509 -in peer-est.crt -outform DER | od -An -tx1 | tr -d ' \n')','hex'),
                'est','$CA_ID','est.example.org','CN=est.example.org', $NOWP, $((NOWP+315360000)));" >/dev/null
chk "fixture: the peer's row is live under the same id" 2 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='est' AND status=0;" | tr -d ' ')"
R12c=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode "keyref=$TR_URI" \
            --data-urlencode 'cn=est.example.org' --data-urlencode 'sans=est.example.org' \
            --data-urlencode 'keygen=false' \
            --data-urlencode 'cert_id=est')
chk "re-issuing beside a peer's certificate succeeds" yes "$(has "$R12c" '"serial"')"
chk "  the peer's certificate is still live" 0 \
    "$(pg_exec "SELECT status FROM certs WHERE serial='$PEER_SER';" | tr -d ' ')"
chk "  and this host's previous one is retired" 3 \
    "$(pg_exec "SELECT status FROM certs WHERE serial='$(echo "$NEW_SER" | tr 'A-Z' 'a-z')' OR serial='$NEW_SER' LIMIT 1;" | tr -d ' ')"
pg_exec "DELETE FROM certs WHERE serial='$PEER_SER';" >/dev/null

# Omitting the id must publish NOTHING. An ordinary certificate that silently became a
# listener's TLS identity would be a very bad surprise.
post --data-urlencode "ca_instance=$CA_ID" \
     --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-plain;type=private?pin-value=1234" \
     --data-urlencode 'cn=plain.example.org' --data-urlencode 'key=rsa' \
     --data-urlencode 'bits=2048' >/dev/null
chk "no cert_id publishes nothing new"     1 "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id IS NOT NULL AND status=0;" | tr -d ' ')"

# And the form has to offer it, or the API is unreachable from the console.
chk "the form offers the id"             yes "$(inpage 'id="inv_cert_id"')"
chk "...and the submit sends it"         yes "$(inpage "'curve','cert_id'")"

echo "=== 13. the key must be the one that listener loads ==="
# The failure this prevents, measured on the lab: issue to cert_id=est with the key at
# `est-tls-141` while EST_KEY names `est-tls`. Everything reports success — 201, a tagged
# row in `certs`, "issued" in the console — and then EST finds a certificate whose public
# half is not its key, refuses the mismatched pair (rightly) and keeps serving self-signed.
# The only evidence was one log line inside the container. Refusing up front also matters
# because a late refusal would orphan a keypair in the token.
WRONG="pkcs11:token=$TOKEN;object=not-the-est-key;type=private?pin-value=1234"
chk "a mismatched key is refused" 400 \
    "$(code --data-urlencode "ca_instance=$CA_ID" --data-urlencode "keyref=$WRONG" \
             --data-urlencode 'cn=est.example.org' --data-urlencode 'key=rsa' \
             --data-urlencode 'bits=2048' --data-urlencode 'cert_id=est')"
RW=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode "keyref=$WRONG" \
          --data-urlencode 'cn=est.example.org' --data-urlencode 'key=rsa' \
          --data-urlencode 'bits=2048' --data-urlencode 'cert_id=est')
# The message has to name the handle to use, or it just says no.
chk "...and names the expected key" yes "$(has "$RW" 'object=svc-est')"
# Refused BEFORE minting: a keypair left in hardware that no certificate names is exactly
# what this page is about.
chk "...without minting anything"     0 "$(objs not-the-est-key)"
# An id with no configured key (nothing in the map) must NOT be blocked — the check only
# applies where there is something to disagree with.
chk "an unconfigured id is allowed" 201 \
    "$(code --data-urlencode "ca_instance=$CA_ID" \
             --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-free;type=private?pin-value=1234" \
             --data-urlencode 'cn=free.example.org' --data-urlencode 'key=rsa' \
             --data-urlencode 'bits=2048' --data-urlencode 'cert_id=some-other-id')"
# And the console is told each listener's key, so the form can fill it in rather than
# leaving the operator to match two settings by hand.
SLOTS=$(curl -s -b boss.cj "$U/api/pkcs11/slots")
chk "hsm-slots carries transportKeys" yes "$(has "$SLOTS" '"transportKeys"')"
chk "...naming EST's key"             yes "$(has "$SLOTS" 'object=svc-est')"
chk "the form wires Serve-as -> key"  yes "$(inpage "_cert_id')")"

echo "=== 14. the certificate is SAVED, not downloaded ==="
# "When I submit the form, the certificate gets downloaded! This is wrong - it should be
# saved in DB instead!" It was in fact doing both — insert_cert ran and the browser was
# ALSO handed a .pem. For an HSM key there is no private half to pair that file with, so
# it is a copy of something the deployment already holds. The download is gone; the row
# is the artifact.
SER14=$(post --data-urlencode "ca_instance=$CA_ID" \
             --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-saved;type=private?pin-value=1234" \
             --data-urlencode 'cn=saved.example.org' --data-urlencode 'key=rsa' \
             --data-urlencode 'bits=2048' | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')
chk "it is in the certs table"           1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE serial='$SER14';" | tr -d ' ')"
# Looked up by SERIAL, not by the requested CN. The `requester` profile now binds
# the subject to the caller, so the row's cn is `boss` and a search for the CN that was
# asked for finds nothing — which says nothing about whether the API can read the
# certificate back. The serial is the identity that does not move.
chk "...and readable back over the API" yes \
    "$(curl -s -b boss.cj "$U/api/certs?q=$SER14" | grep -q "$SER14" && echo yes || echo no)"
# Scoped to the HSM handler, not the whole page: the CSR and browser-keygen forms still
# download, and rightly so — the caller there holds a private key that exists nowhere
# else, so the certificate file is the half they are missing. A page-wide grep for `dl(`
# would have called that a failure.
HSMFN=$(curl -s -b boss.cj "$U/" | awk '/request-hsm./{f=1} f{print; n++} n>18{exit}')
chk "the HSM submit does not download"   no \
    "$(printf '%s' "$HSMFN" | grep -q 'dl(' && echo yes || echo no)"
chk "...but the CSR form still does"    yes "$(inpage 'dl((o.cn || o.serial)')"

echo "=== Serve as is the FIRST field in the form ==="
# It decides what the certificate IS — a listener's transport credential or an ordinary
# leaf — and that answer changes what belongs in every field below it, most of all the
# SANs. Asserted by POSITION, because "present somewhere" was already true when it sat
# two thirds of the way down the form.
curl -s -b boss.cj "$U/" -o form.html 2>/dev/null
lineof(){ grep -n "$1" form.html | head -1 | cut -d: -f1; }
SA=$(lineof '<label>Serve as</label>'); IF=$(lineof '<label>Issue from</label>')
chk "both fields were found in the served form" yes \
    "$([ -n "$SA" ] && [ -n "$IF" ] && echo yes || echo no)"
chk "  ... and Serve as comes before Issue from" yes \
    "$([ -n "$SA" ] && [ -n "$IF" ] && [ "$SA" -lt "$IF" ] && echo yes || echo no)"

echo
echo "=== 15. overwrite an occupied handle — but never one in use ==="
# The refusal in section 10 is now a CHOICE rather than a dead end: confirm, and the
# existing object is destroyed and a fresh key minted. Three things have to hold, and
# the third is the one that matters most.

# (a) the 409 must be machine-readable, or the console cannot know to offer the prompt.
chk "the refusal carries handleTaken so the UI can offer to replace" yes \
    "$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=ht.internal' \
        --data-urlencode "keyref=$COLL" --data-urlencode 'key=rsa' \
        | grep -q '"handleTaken":true' && echo yes || echo no)"

# (b) confirmed overwrite replaces rather than duplicates. The object count must stay
#     at one: a "replace" that leaves two keys with one name is the very bug section 10
#     exists to prevent, wearing a friendlier label.
OW_BEFORE=$(objs collide)
C_OW=$(code --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=overwritten.internal' \
       --data-urlencode "keyref=$COLL" --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
       --data-urlencode 'overwrite=true')
chk "confirmed overwrite -> 201"                 201 "$C_OW"
chk "and the handle still holds ONE key, not two" "$OW_BEFORE" "$(objs collide)"

# (c) ⚠️ THE GUARD. The key name is free text, so it can name the signing key of a
#     registered CA. Destroying that is unrecoverable — the CA is gone and every
#     certificate it issued becomes unverifiable against any replacement. Overwrite must
#     refuse, and must refuse WITHOUT destroying anything: a guard that reports the error
#     after the damage is no guard. $CA_KEY_URI is this suite's own CA, so this asserts
#     against a real registered CA rather than a hypothetical one.
CA_OBJ=$(printf '%s' "$CA_KEY_URI" | sed -n 's/.*object=\([^;?]*\).*/\1/p')
CAK_BEFORE=$(objs "$CA_OBJ")
C_CA=$(code --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=steal-ca-key.internal' \
       --data-urlencode "keyref=$CA_KEY_URI" --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
       --data-urlencode 'overwrite=true')
chk "overwriting a REGISTERED CA's signing key -> 409" 409 "$C_CA"
chk "and that CA key is still in the token"   "$CAK_BEFORE" "$(objs "$CA_OBJ")"
chk "the refusal names what is using it"      yes \
    "$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=steal2.internal' \
        --data-urlencode "keyref=$CA_KEY_URI" --data-urlencode 'key=rsa' \
        --data-urlencode 'overwrite=true' \
        | grep -qi 'in use\|signing key of CA' && echo yes || echo no)"
# The CA must still work afterwards — proving the refusal cost nothing.
chk "the CA still issues after the refused overwrite" 201 \
    "$(code --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=still-alive.internal' \
        --data-urlencode "keyref=pkcs11:token=$CFG_TOKEN;object=alive;type=private?pin-source=$PINFILE" \
        --data-urlencode 'key=rsa' --data-urlencode 'bits=2048')"

echo "=== 11. an OCSP-signing cert gets id-pkix-ocsp-nocheck, without being asked ==="
# Object names carry $$ because this suite runs against a token that can outlive one
# invocation: a fixed label collides with the key a previous run minted, and the request
# is then refused for key management rather than for anything this section is about.
#
# ⚠️ THE BUG THIS EXISTS FOR. fastpki-ocsp REFUSES a non-CA responder certificate that
# lacks id-pkix-ocsp-nocheck (RFC 6960 §2.1.2, enforced in responder.cpp) —
# and this form has ku/eku/ekucustom and NO field for an extension. So "Serve as → OCSP
# responder" issued a certificate, reported success, and the responder then rejected it:
# there was no combination of console inputs that produced a usable credential.
#
# It is NOT fixable by putting the OID in Custom EKU (the literal reading of the ask):
# ekucustom feeds extendedKeyUsage, so the OID would become an EKU purpose and the
# EXTENSION would still be absent. The server adds the extension itself.
# ⚠️ Section 8 left the server on a profile whose allowed_eku is an ALLOW-LIST without
# OCSPSigning, so a responder request there is refused for an unrelated reason and this
# section would "fail" without ever reaching the extension. Restart on a profile that
# permits it — the allow-list behaviour is section 8's subject, not this one's.
kill $P 2>/dev/null; wait $P 2>/dev/null
cp bootstrap.conf pki11.conf
seed_cert_profiles '{"requester":{"allowed_ku":["digitalSignature","keyEncipherment"],"allowed_eku":["serverAuth","clientAuth","OCSPSigning"],"default_ku":["digitalSignature"],"default_eku":["serverAuth"],"allow_wildcard":false}}'
"$WEB" --config pki11.conf >srv11.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "pki11.conf" WEB_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died on the responder profile:"; cat srv11.log; }
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null

R11=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=responder.example.org' \
           --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-nocheck-ra;type=private?pin-value=1234" \
           --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
           --data-urlencode 'ku=digitalSignature' --data-urlencode 'eku=serverAuth,OCSPSigning')
# A request that does not issue must say WHY — otherwise a refused-for-an-unrelated-reason
# run and a genuinely broken extension look identical, which is exactly what happened here.
printf '%s' "$R11" | grep -q '"error"' && echo "    --- server said: $(printf '%s' "$R11" | head -c 220)"
echo "$R11" | sed -n 's/.*"pem":"\([^"]*\)".*/\1/p' | sed 's/\\n/\
/g' > ocspleaf.pem
chk "the OCSP-signing cert issues" yes \
    "$([ -s ocspleaf.pem ] && "$OSSL" x509 -in ocspleaf.pem -noout -subject >/dev/null 2>&1 && echo yes || echo no)"
if [ -s ocspleaf.pem ]; then
  T11=$("$OSSL" x509 -in ocspleaf.pem -noout -text 2>/dev/null)
  chk "  it carries id-kp-OCSPSigning" yes \
      "$(printf '%s' "$T11" | grep -qi 'OCSP Signing' && echo yes || echo no)"
  # THE assertion: the EXTENSION, decoded — not an EKU entry that merely looks like it.
  chk "  and the ocsp-nocheck EXTENSION (not an EKU entry)" yes \
      "$(printf '%s' "$T11" | grep -qiE 'OCSP No Check|1\.3\.6\.1\.5\.5\.7\.48\.1\.5' && echo yes || echo no)"
  # It must not have leaked into extendedKeyUsage, which is what the ticket's literal
  # wording would have produced.
  chk "  the nocheck OID is NOT in extendedKeyUsage" yes \
      "$(printf '%s' "$T11" | sed -n '/Extended Key Usage/,+2p' | grep -q '48\.1\.5' && echo no || echo yes)"
fi
# A certificate with no OCSPSigning must NOT collect the extension — the rule is "when
# OCSP signing is requested", not "always".
R11b=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=plain.example.org' \
            --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-nocheck-ctl;type=private?pin-value=1234" \
            --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
            --data-urlencode 'ku=digitalSignature' --data-urlencode 'eku=serverAuth')
echo "$R11b" | sed -n 's/.*"pem":"\([^"]*\)".*/\1/p' | sed 's/\\n/\
/g' > plainleaf.pem
# Distinguish "issued without nocheck" (what we want) from "never issued" (a broken test
# that would otherwise read as a pass on the negative).
chk "  the control cert issues at all" yes \
    "$([ -s plainleaf.pem ] && "$OSSL" x509 -in plainleaf.pem -noout -subject >/dev/null 2>&1 && echo yes || echo no)"
[ -s plainleaf.pem ] || echo "    --- server said: $(printf '%s' "$R11b" | head -c 220)"
if [ -s plainleaf.pem ]; then
  chk "  an ordinary server cert does NOT get ocsp-nocheck" yes \
      "$("$OSSL" x509 -in plainleaf.pem -noout -text 2>/dev/null \
          | grep -qiE 'OCSP No Check|1\.3\.6\.1\.5\.5\.7\.48\.1\.5' && echo no || echo yes)"
fi

echo "=== 14. a cert_id names ONE active certificate ==="
# ⚠️ Found on the lab, not here: re-issuing an OCSP responder left TWO live rows under
# ocsp-ra-<ca_id>. get_cert_by_cert_id() selects status=0 and breaks ties on
# notAfter/serial, so the service resolved an arbitrary one — and signed with a key that
# did not match the certificate it presented, producing "Response Verify Failure" from a
# responder that looked healthy. The test helper service_cert_publish() has always
# replaced; the product's request-hsm path did not, so only the tests were safe.
R12a=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=dup.example.org' \
            --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-dup-a;type=private?pin-value=1234" \
            --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
            --data-urlencode 'cert_id=dup-tag' --data-urlencode 'eku=serverAuth')
S1=$(printf '%s' "$R12a" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')
R12b=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=dup.example.org' \
            --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-dup-b;type=private?pin-value=1234" \
            --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
            --data-urlencode 'cert_id=dup-tag' --data-urlencode 'eku=serverAuth')
S2=$(printf '%s' "$R12b" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')
chk "both issuances succeeded" yes "$([ -n "$S1" ] && [ -n "$S2" ] && [ "$S1" != "$S2" ] && echo yes || echo no)"
# THE assertion: exactly one row for that cert_id is still active.
chk "  exactly ONE active certificate for the cert_id" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='dup-tag' AND status=0;" | tr -d ' ')"
chk "  and it is the NEWEST one" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='dup-tag' AND status=0 AND serial='$S2';" | tr -d ' ')"
# The superseded one is retired, not deleted — it stays auditable.
chk "  the previous one is retired, not removed" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='dup-tag' AND serial='$S1' AND status<>0;" | tr -d ' ')"

echo "=== ⚠️ every Serve-As option must reach ALL THREE lists ==="
# The dropdown is backed by three independent lists that have to agree:
#   1. the <option> values in the form            (what the operator can pick)
#   2. PURPOSE_EXT in the page JS                 (fills KU / EKU / custom OIDs)
#   3. the transportKeys map from the SERVER      (fills the Key name + token slot)
# And a later change added ocsp-ra and scep-ra to (1) and (2) and forgot (3), so those two
# options half-worked: the usage boxes changed and the Key-name field stayed blank. That
# field is `required`, so the form silently refused to submit and nothing said why —
# which is exactly what was hit in practice. Grep-proxies are weak, but three lists
# drifting apart is precisely what a grep CAN see.
PAGE=$(curl -s -b boss.cj "$U/" 2>/dev/null)
OPTS=$(printf '%s' "$PAGE" | sed -n "s/.*<select name=\"cert_id\" id=\"inv_cert_id\">\(.*\)/\1/p" \
       | grep -o "value=\"[a-z-]*\"" | sed 's/value="//;s/"//' | grep -v '^$' | sort -u)
[ -n "$OPTS" ] || OPTS=$(printf '%s' "$PAGE" | grep -o "'\(web\|est\|acme\|ms\|cmp-ra\|ocsp-ra\|scep-ra\)':  *{ ku:" | sed "s/'//g;s/: *{ ku://" | sort -u)
chk "found the Serve-As options to check" yes "$([ -n "$OPTS" ] && echo yes || echo no)"
for o in $OPTS; do
    case "$PAGE" in *"'$o':"*) HIT=yes ;; *) HIT=no ;; esac
    chk "  '$o' has a KU/EKU preset" yes "$HIT"
done
# (3) is served by /api/pkcs11/slots. Assert the two roles that were missing are now
# emitted whenever their cert-id setting is set — the map is keyed by that VALUE.
SLOTS=$(curl -s -b boss.cj "$U/api/pkcs11/slots" 2>/dev/null)
case "$SLOTS" in *'"transportKeys"'*) TK=yes ;; *) TK=no ;; esac
chk "the slots API carries a transportKeys map" yes "$TK"
for role in ocsp-ra scep-ra cmp-ra; do
    case "$SLOTS" in *"\"$role\""*) HIT=yes ;; *) HIT=no ;; esac
    chk "  transportKeys names '$role'" yes "$HIT"
done
# ⚠️ Round 2: WHICH name ends up in the box when the operator changes their mind.
# My first fix filled the field only when it was EMPTY, so: pick a role that HAS a key
# (the box fills with that key's name), then switch to SCEP RA (which has none) and the
# box keeps the OTHER listener's key name. That is worse than the blank field it replaced
# — blank is obviously unfinished, whereas a plausible wrong name gets submitted. The
# rule is: a name WE filled is ours to replace; a name the operator typed is theirs.
PAGE2=$(curl -s -b boss.cj "$U/" 2>/dev/null)
chk "role change may replace an auto-filled key name" yes \
    "$(printf '%s' "$PAGE2" | grep -q "obj.dataset.auto !== '1'" && echo yes || echo no)"
chk "  typing in the box makes the name the operator's" yes \
    "$(printf '%s' "$PAGE2" | grep -q "obj.dataset.auto = ''" && echo yes || echo no)"
chk "  and the empty-box guard is GONE (it is what caused this)" no \
    "$(printf '%s' "$PAGE2" | grep -q 'if (obj && !obj.value) obj.value = cid.value' && echo yes || echo no)"

echo "=== ⚠️ SCEP RA forces an RSA key, or it loses keyEncipherment ==="
# Reported: selecting SCEP RA from the dropdown left only digitalSignature ticked. The
# key-type selection is locked to RSA only, and the message has to explain why.
#
# The preset DID tick keyEncipherment; syncKuEku then unticked it, because KEY_KU_VALID
# allows that bit for RSA only and this form defaults to EC. Two correct rules disagreed
# and the key type silently won — producing a SCEP RA that cannot decrypt the
# PKIOperation envelope, which fails at the first enrolment rather than at issuance.
PG178=$(curl -s -b boss.cj "$U/" 2>/dev/null)
chk "the key type is locked for an RSA-only purpose" yes \
    "$(printf '%s' "$PG178" | grep -q "function lockKeyTypeForPurpose" && echo yes || echo no)"
# ORDER IS THE BUG. Locking after syncKuEku would leave the bit unticked exactly as before.
chk "  and it runs BEFORE syncKuEku, not after"      yes \
    "$(printf '%s' "$PG178" | tr '\n' ' ' \
       | grep -q "lockKeyTypeForPurpose(f, want);[[:space:]]*syncKuEku" && echo yes || echo no)"
# Derived from KEY_KU_VALID, not a second hand-kept list of which purposes need RSA.
chk "  the RSA requirement is DERIVED from KEY_KU_VALID" yes \
    "$(printf '%s' "$PG178" | grep -q "KEY_KU_VALID.rsa.includes(k) && !KEY_KU_VALID.ec.includes(k)" && echo yes || echo no)"
chk "  the lock is RELEASED for a non-RA purpose"    yes \
    "$(printf '%s' "$PG178" | grep -q "lockKeyTypeForPurpose(f, null)" && echo yes || echo no)"
chk "  and there is somewhere to explain why"        yes \
    "$(printf '%s' "$PG178" | grep -q 'id="hsm-algonote"' && echo yes || echo no)"
chk "  the explanation names the reason, not just the rule" yes \
    "$(printf '%s' "$PG178" | grep -q "decrypts the PKIOperation envelope with this key" && echo yes || echo no)"
# The preset itself must still ASK for both bits — the lock only makes them survivable.
chk "  scep-ra still requests keyEncipherment"       yes \
    "$(printf '%s' "$PG178" | grep -q "'scep-ra': { ku: \['digitalSignature', 'keyEncipherment'\]" && echo yes || echo no)"

echo "=== The Custom EKU box refuses id-pkix-ocsp-nocheck ==="
# It is an EXTENSION, not an EKU purpose. This box is the only free-text OID field on the
# form, so it is where an operator puts the OID — and doing so produced the
# policy error. A not-permitted EKU is DROPPED instead now, so the mistake
# would now be silent: a certificate comes back and the extension is just missing. This
# form-side refusal is the only feedback left, which is why it is asserted here.
JS=$(curl -s -b boss.cj "$U/")
chk "the form knows the nocheck OID" yes \
    "$(printf '%s' "$JS" | grep -c "1\.3\.6\.1\.5\.5\.7\.48\.1\.5" | grep -qv '^0$' && echo yes || echo no)"
chk "  and refuses it BEFORE building the eku list" yes \
    "$(printf '%s' "$JS" | grep -q "custom.indexOf(NOCHECK)" && echo yes || echo no)"
chk "  explaining it is an EXTENSION, not an EKU" yes \
    "$(printf '%s' "$JS" | grep -q "is an EXTENSION, not an" && echo yes || echo no)"
# And the server still does the right thing on its own: OCSPSigning alone yields nocheck.
chk "  the server adds nocheck for an OCSPSigning request" yes \
    "$(printf '%s' "$JS" | grep -q "the SERVER adds the extension itself" && echo yes || echo no)"

echo "=== 'no key there' and 'key unreadable' are DIFFERENT answers ==="
# The console said "no key at that handle to certify" about a handle whose
# key the ACME service was loading successfully at the same moment. The probe caught every
# exception and reported absence as fact. Absence and unreadable-for-some-other-reason
# must not collapse into one message — the second invites the operator to generate OVER a
# key that is really there.
#
# A handle in a token that does not exist is genuinely absent -> 404.
# A handle whose key is genuinely not in the token IS an absence -> 404, asserted
# earlier in this suite ("adopting a handle with no key -> 404"). What must NOT be called
# an absence is a keyref the loader could not read for some OTHER reason. A non-token
# keyref is the deterministic case: there is no handle here at all, so "no key at that
# handle to certify. Untick 'use an existing key' to generate one there" would be false
# advice — following it would generate a token key the operator never asked for.
BODY=$(post --data-urlencode 'keyref=pkcs11:token=leafhsm;object=nosuch;type=private?pin-source=/nonexistent/pin' \
            --data-urlencode 'keygen=false' --data-urlencode 'cn=absent.test' \
            --data-urlencode 'ca_instance=leafca' \
            --data-urlencode 'ku=digitalSignature' --data-urlencode 'eku=serverAuth')
RC=probe
chk "an unloadable handle is NOT reported as a plain absence" no \
    "$(printf '%s' "$BODY" | grep -q "no key at that handle" && echo yes || echo no)"
chk "  the operator is told it could not be READ" yes \
    "$(printf '%s' "$BODY" | grep -q "could not be read" && echo yes || echo no)"
chk "  and warned not to generate over it" yes \
    "$(printf '%s' "$BODY" | grep -q "do NOT generate over it" && echo yes || echo no)"
chk "  with the underlying reason included, not swallowed" yes \
    "$(printf '%s' "$BODY" | grep -qiE "OSSL_STORE|pkcs11|error" && echo yes || echo no)"
echo "  (body: $(printf '%s' "$BODY" | head -c 220))"

echo "=== The PROFILE grants the choice, the REQUEST makes it ==="
# The case: an admin needs ONE profile that issues ordinary certificates AND
# can issue an OCSP responder with no AIA and no CRLDP. The old profile flag was
# "always omit", which cannot do both — so it became manage_aia / manage_crldp, meaning
# "the requester may omit". Neither half alone suppresses anything; that is the assertion.
kill $P 2>/dev/null; wait $P 2>/dev/null
cp bootstrap.conf pki163.conf
seed_cert_profiles '{"requester":{"allowed_ku":["digitalSignature","keyEncipherment"],"allowed_eku":["serverAuth","clientAuth","OCSPSigning"],"default_ku":["digitalSignature"],"default_eku":["serverAuth"],"allow_wildcard":false,"manage_aia":true,"manage_crldp":true},"strict":{"allowed_ku":["digitalSignature"],"allowed_eku":["serverAuth"],"default_ku":["digitalSignature"],"default_eku":["serverAuth"],"allow_wildcard":false}}'
"$WEB" --config pki163.conf >srv163.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "pki163.conf" WEB_PORT "$P" || true
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null 2>&1
mk(){ # mk <object> <extra curl args...>
  local obj="$1"; shift
  post --data-urlencode "keyref=pkcs11:token=$HSMTOK;object=$obj;type=private" \
       --data-urlencode 'ca_instance=leafca' --data-urlencode "cn=$obj.163.test" \
       --data-urlencode 'ku=digitalSignature' --data-urlencode 'eku=serverAuth' "$@"
}
HSMTOK=$(printf '%s' "${CA_KEY_URI:-}" | sed -n 's/.*token=\([^;?]*\).*/\1/p')
if [ -z "$HSMTOK" ]; then
  echo "  [SKIP] no token in CA_KEY_URI — cannot mint request keys for this case"
else
  # 1. profile ALLOWS + request ASKS -> gone. This is the case that was impossible before.
  C1=$(mk om163a --data-urlencode 'omit_aia=true' --data-urlencode 'omit_crldp=true')
  T1=$(printf '%s' "$C1" | sed -n 's/.*"pem":"\(.*\)".*/\1/p' | sed 's/\\n/\n/g' | "$OSSL" x509 -noout -text 2>/dev/null)
  chk "profile allows + request asks: AIA gone"    no "$(has "$T1" 'Authority Information Access')"
  chk "  ...and CRL DP gone"                       no "$(has "$T1" 'CRL Distribution Points')"
  # 2. profile ALLOWS, request stays silent -> present. Permission is not omission; this
  #    is what lets ONE profile serve ordinary certificates too.
  C2=$(mk om163b)
  T2=$(printf '%s' "$C2" | sed -n 's/.*"pem":"\(.*\)".*/\1/p' | sed 's/\\n/\n/g' | "$OSSL" x509 -noout -text 2>/dev/null)
  chk "profile allows, request silent: AIA present" yes "$(has "$T2" 'Authority Information Access')"
  chk "  ...and CRL DP present"                     yes "$(has "$T2" 'CRL Distribution Points')"
  # 3. ⚠️ THE ONE THAT MATTERS FOR POLICY: the profile does NOT allow it and the request
  #    asks anyway. A hand-crafted POST must not be able to drop AIA from a certificate
  #    whose profile forbids it — the checkbox in the form is a convenience, not the gate.
  kill $P 2>/dev/null; wait $P 2>/dev/null
  cp bootstrap.conf pki163b.conf
  seed_cert_profiles '{"requester":{"allowed_ku":["digitalSignature","keyEncipherment"],"allowed_eku":["serverAuth","clientAuth"],"default_ku":["digitalSignature"],"default_eku":["serverAuth"],"allow_wildcard":false}}'
  "$WEB" --config pki163b.conf >srv163b.log 2>&1 & P=$!
  # Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
  wait_conf "pki163b.conf" WEB_PORT "$P" || true
  curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null 2>&1
  C3=$(mk om163c --data-urlencode 'omit_aia=true' --data-urlencode 'omit_crldp=true')
  T3=$(printf '%s' "$C3" | sed -n 's/.*"pem":"\(.*\)".*/\1/p' | sed 's/\\n/\n/g' | "$OSSL" x509 -noout -text 2>/dev/null)
  chk "profile FORBIDS + request asks: AIA still present" yes \
      "$(has "$T3" 'Authority Information Access')"
  chk "  ...and CRL DP still present"                     yes \
      "$(has "$T3" 'CRL Distribution Points')"

  # 4. Both requester-facing forms must be able to ASK. The API contract above is the real
  #    guard; this is the §3e grep-proxy that catches one form losing the ticks — which is
  #    exactly how a capability becomes unreachable from the console while the API still
  #    honours it. The HSM form gets OMIT_ROW; the browser-generate form gets its own
  #    fieldset; both draw from the shared omitTicks().
  JS=$(curl -s "$U/")
  # Shell pattern matching, not `printf | grep -q`: grep closes the pipe on its first hit
  # and printf then dies with EPIPE, printing "write error" noise on every passing check.
  hasjs(){ case "$JS" in *"$1"*) echo yes;; *) echo no;; esac; }
  chk "console defines the shared omitTicks() helper" yes "$(hasjs 'function omitTicks()')"
  # ⚠️ CHANGED WHERE THE HSM FORM'S ANSWER COMES FROM, and this assertion changed with
  # it rather than being deleted. omitTicks() reads PROFILES, which the Profiles page loads
  # behind `profile:edit` — so on the HSM form the ticks were invisible to every plain
  # requester (the people a profile granting them is written for) and visible to an admin
  # whenever ANY profile anywhere granted the flag, applicable or not. The form has to
  # DISPLAY the resolved profile rather than ask, so the HSM form now asks the
  # SERVER which profile applies and what it permits. The browser-generate form still uses
  # omitTicks(), which is why the helper must still exist.
  chk "  HSM form has the omit row"                  yes "$(hasjs 'id="hsm_omit"')"
  chk "  ...driven by the RESOLVED profile"          yes "$(hasjs 'async function refreshHsmProfile()')"
  chk "  ...and it still carries both boxes"         yes \
      "$(hasjs 'name="omit_crldp" value="true"> omit CRL DP')"
  chk "  generate-in-browser form renders it too"    yes \
      "$(hasjs '${omitTicks() ? `<fieldset><legend>Omit</legend>')"
  chk "  ...and PUTS the answer on the request"      yes "$(hasjs "'omit_aia=true'")"
fi
kill $P 2>/dev/null; wait $P 2>/dev/null
"$WEB" --config bootstrap.conf >>srv.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" WEB_PORT "$P" || true
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null 2>&1

echo "=== keyRef for a PER-CA RA credential (the Re-key button's precondition) ==="
# ⚠️ WHY THIS EXISTS. transport_key_for() compared a whole certs.cert_id against settings
# that are PREFIXES: a real row is "<prefix>-<ca_id>", so `cert_id == prefix` was false for
# every credential that can exist. OCSP RA and SCEP RA were not in the function at all.
# keyRef therefore came back empty for all three, and an empty keyRef is precisely what
# hides the Re-key / Renew button — so the console offered no way to re-key any
# service credential, and nothing anywhere reported an error.
detail_keyref() {   # detail_keyref <serial> -> the keyRef the detail view would show
  curl -s -b boss.cj "$U/api/certs/$1" | sed -n 's/.*"keyRef":"\([^"]*\)".*/\1/p'
}
mkra() {            # mkra <prefix> <key-object>
  post --data-urlencode "ca_instance=$CA_ID" \
       --data-urlencode "keyref=pkcs11:token=$TOKEN;object=$2;type=private?pin-value=1234" \
       --data-urlencode "cn=$1.168.test" --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
       --data-urlencode "cert_id=$1-$CA_ID"
}
for spec in "cmp-ra:svc-cmpra" "ocsp-ra:svc-ocspra" "scep-ra:svc-scepra"; do
  PFX="${spec%%:*}"; OBJ="${spec##*:}"
  R=$(mkra "$PFX" "$OBJ")
  SER=$(echo "$R" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')
  chk "$PFX-<ca> issued"                       yes "$([ -n "$SER" ] && echo yes || echo no)"
  KR=$(detail_keyref "$SER")
  chk "  its keyRef is NOT empty"              yes "$([ -n "$KR" ] && echo yes || echo no)"
  chk "  ...and names the configured key"      yes "$(printf '%s' "$KR" | grep -q "object=$OBJ" && echo yes || echo no)"
done

# The prefix match must not be greedy: an ordinary leaf has no listener key, and claiming
# one would offer a Re-key button that re-keys nothing.
# ⚠️ Each of these needs its OWN free handle. They used to share `svc-two`, which an
# earlier section had already minted — so the second request 409'd, produced no serial, and
# the "empty keyRef" assertion below passed because there was no certificate to ask about.
# It was green and testing nothing; the re-key dialog exposed it by making a real answer non-empty.
RL=$(post --data-urlencode "ca_instance=$CA_ID" \
          --data-urlencode "keyref=pkcs11:token=$TOKEN;object=plain168a;type=private?pin-value=1234" \
          --data-urlencode 'cn=plain.168.test' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048')
LSER=$(echo "$RL" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')
# ⚠️ CHANGED WHAT "no listener key" LOOKS LIKE, and the assertion changed with it.
# This used to demand an EMPTY keyRef, because that was the only way to say "the prefix did
# not match". A leaf now reports its OWN token handle, so emptiness no longer distinguishes
# the two — but the thing that matters is unchanged and is now stated directly: the leaf
# must report the key it was actually minted at, NEVER the CMP RA's configured key.
chk "an ordinary leaf was issued at all"         yes "$([ -n "$LSER" ] && echo yes || echo no)"
chk "an ordinary leaf reports its OWN key"       yes "$(has "$(detail_keyref "$LSER")" 'object=plain168a')"
chk "  ...and NOT the listener's"                no  "$(has "$(detail_keyref "$LSER")" 'object=svc-cmpra')"
# ...and the prefix must not swallow an id that merely starts with the same bytes.
RN=$(post --data-urlencode "ca_instance=$CA_ID" \
          --data-urlencode "keyref=pkcs11:token=$TOKEN;object=plain168b;type=private?pin-value=1234" \
          --data-urlencode 'cn=nearmiss.168.test' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
          --data-urlencode "cert_id=cmp-radar")
NSER=$(echo "$RN" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')
chk "the near-miss id was issued at all"              yes "$([ -n "$NSER" ] && echo yes || echo no)"
chk "'cmp-radar' is NOT treated as the cmp-ra prefix" no \
    "$(has "$(detail_keyref "$NSER")" 'object=svc-cmpra')"
chk "  ...it reports its own key instead"             yes "$(has "$(detail_keyref "$NSER")" 'object=plain168b')"

echo "=== Fixing keyRef also switches ON the mismatched-pair refusal for RA ids ==="
# Before the fix transport_key_for() returned "" for these ids, so the guard had
# nothing to compare and silently allowed ANY key. That is the same silent failure class
# as the RA credentials — issued, stored, reported successful, then ignored by the server.
chk "wrong key for cmp-ra-<ca> is REFUSED (400)" 400 \
    "$(code --data-urlencode "ca_instance=$CA_ID" \
            --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-two;type=private?pin-value=1234" \
            --data-urlencode 'cn=wrong.168.test' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
            --data-urlencode "cert_id=cmp-ra-$CA_ID")"
# ...and it must name the key the operator should have used, not just say no.
WR=$(post --data-urlencode "ca_instance=$CA_ID" \
          --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-two;type=private?pin-value=1234" \
          --data-urlencode 'cn=wrong2.168.test' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
          --data-urlencode "cert_id=cmp-ra-$CA_ID")
chk "  and the refusal names the expected key"  yes "$(has "$WR" 'svc-cmpra')"

echo "=== Re-key mints a new key AND repoints the setting, in one operation ==="
# ⚠️ Making keyRef correct UNHID a button whose path had never run — and it did not work,
# for anything, ever (measured: the `est` listener, whose button has been visible since
# Behaved identically). Two guards each gave correct-sounding advice pointing at
# the other:
#
#   same handle      -> 409 handleTaken -> retry with overwrite -> "refusing to overwrite
#                       the live CMP_RA_KEY ... issue this under a different key name"
#   different handle -> 400 "that key is not the one 'cmp-ra-<ca>' loads ..."
#
# The cause was structural: the configuration names ONE key, re-key means a NEW key, and
# nothing moved the setting. Option 1 was settled on: the setting is repointed in the
# same operation. So a re-key now says so, and the
# handle guard stands for everything that does not.
RK_SAME=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'keygen=true' \
          --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-cmpra;type=private?pin-value=1234" \
          --data-urlencode 'cn=cmp-ra.168.test' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
          --data-urlencode "cert_id=cmp-ra-$CA_ID")
chk "re-key at the SAME handle prompts (handleTaken)" yes "$(has "$RK_SAME" 'handleTaken')"
# ⚠️ The guard MUST still fire without the re-key marker. Repointing a live listener
# because someone mistyped a handle is not a friendlier outcome than a 400 — it is the
# Silent-failure class with a config write attached.
RK_NEW=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'keygen=true' \
          --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-cmpra-v2;type=private?pin-value=1234" \
          --data-urlencode 'cn=cmp-ra.168.test' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
          --data-urlencode "cert_id=cmp-ra-$CA_ID")
chk "a NEW handle WITHOUT rekey still hits the guard" yes "$(has "$RK_NEW" 'mismatched pair')"
chk "  ...and that guard names the configured key"    yes "$(has "$RK_NEW" 'svc-cmpra')"
chk "  ...and now names the way through (re-key)"     yes "$(has "$RK_NEW" 'repoints CMP_RA_KEY')"

# The real thing: rekey=1 at a new handle. Assert the SETTING moved, not merely that a
# certificate came back — a 201 alone is exactly what the old silent-mismatch bug produced.
CMPRA_BEFORE=$(pg_exec "select value from config where key='CMP_RA_KEY';" 2>/dev/null)
RK_OK=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'keygen=true' \
          --data-urlencode 'rekey=1' \
          --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-cmpra-v2;type=private?pin-value=1234" \
          --data-urlencode 'cn=cmp-ra.168.test' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
          --data-urlencode "cert_id=cmp-ra-$CA_ID")
chk "RE-KEY at a new handle is issued"                yes "$(has "$RK_OK" '"serial"')"
chk "  and the response names the setting it moved"   yes "$(has "$RK_OK" '"repointed":"CMP_RA_KEY"')"
# And says this WAS a re-key, so the console can word the toast for what happened.
# Reported: a confusing re-keying message appeared after a certificate was issued, when
# no SCEP key existed in the HSM at all. Two different events shared one
# sentence — a setting being FILLED IN for the first time was announced as "Re-keyed",
# which sends the operator looking for a key that never existed. CMP_RA_KEY was set here,
# so this one is a genuine replacement.
chk "  ...and marks it a real re-key, not a first assignment" yes \
    "$(has "$RK_OK" '"repointWasUnset":false')"
CMPRA_AFTER=$(pg_exec "select value from config where key='CMP_RA_KEY';" 2>/dev/null)
chk "  and CMP_RA_KEY now names the NEW object"       yes "$(has "$CMPRA_AFTER" 'object=svc-cmpra-v2')"
chk "  ...which it did not before"                    no  "$(has "$CMPRA_BEFORE" 'object=svc-cmpra-v2')"
# The certificate really is on the new key: its public half must match the token object
# the setting now names. Same modulus comparison as section 3 — the provider hands back a
# PKCS#1 RSAPublicKey while the certificate carries an SPKI, so identical keys have
# different bytes and only the modulus can be compared.
printf '%s' "$RK_OK" | sed -n 's/.*"pem":"\(.*\)".*/\1/p' | sed 's/\\n/\n/g' > rk_cert.pem
"$OSSL" pkey $CA_OSSL_ARGS -pubin \
    -in "pkcs11:token=$TOKEN;object=svc-cmpra-v2;type=public" -pubout -out rk_tok.pem 2>/dev/null
RK_MT=$("$OSSL" rsa -pubin -RSAPublicKey_in -in rk_tok.pem -noout -modulus 2>/dev/null)
[ -z "$RK_MT" ] && RK_MT=$("$OSSL" rsa -pubin -in rk_tok.pem -noout -modulus 2>/dev/null)
RK_MC=$("$OSSL" x509 -in rk_cert.pem -noout -modulus 2>/dev/null)
chk "  and the cert's key IS the new token object"    yes \
    "$([ -n "$RK_MT" ] && [ "$RK_MT" = "$RK_MC" ] && echo yes || echo no)"
# ⚠️ rekey is not a way around the OTHER refusals. A re-key onto a handle that is already
# taken must still stop: minting there would destroy whatever is at it.
RK_TAKEN=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'keygen=true' \
          --data-urlencode 'rekey=1' \
          --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-cmpra;type=private?pin-value=1234" \
          --data-urlencode 'cn=cmp-ra.168.test' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
          --data-urlencode "cert_id=cmp-ra-$CA_ID")
chk "re-key onto an OCCUPIED handle still refuses"    yes "$(has "$RK_TAKEN" 'handleTaken')"
# ...and it is not a way to repoint a setting without minting: adopt-an-existing-key plus
# rekey must not move the config, or "re-key" would become a config editor with a
# certificate attached.
RK_ADOPT=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'keygen=false' \
          --data-urlencode 'rekey=1' \
          --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-est;type=private?pin-value=1234" \
          --data-urlencode 'cn=cmp-ra.168.test' --data-urlencode "cert_id=cmp-ra-$CA_ID")
chk "rekey+adopt does NOT bypass the handle guard"    yes "$(has "$RK_ADOPT" 'mismatched pair')"
# Put the setting back so the sections after this one still describe the world they expect.
# ⚠️ effective_cfg() re-reads the DB overlay on every request, so this really does take
# effect immediately — which is also why the assertions above are meaningful.
pg_exec "update config set value='pkcs11:token=$TOKEN;object=svc-cmpra;type=private?pin-value=1234' where key='CMP_RA_KEY';" >/dev/null 2>&1 || :
# Renew — same key, fresh certificate — is the path that DOES work, and it is what the
# button's own hint text promises for the "keeps the key already in the token" case.
RN2=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'keygen=false' \
          --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-cmpra;type=private?pin-value=1234" \
          --data-urlencode 'cn=cmp-ra.168.test' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
          --data-urlencode "cert_id=cmp-ra-$CA_ID")
chk "RENEW (same key, new cert) on an RA id works"    yes "$(has "$RN2" '"serial"')"
chk "  and it stays bound to the same cert_id"        yes "$(has "$RN2" "\"cert_id\":\"cmp-ra-$CA_ID\"")"

echo "=== An ORDINARY HSM certificate reports its key, so it can be re-keyed ==="
# Reported: certificates whose private keys are in the HSM offer a Re-key option that
# gives no key selection, unlike CA re-keying. Driving the console showed something
# narrower and worse: such a certificate
# had NO re-key option at all. `keyRef` was answered only by transport_key_for(), which
# knows four listener ids and three RA prefixes and returns "" for everything else — and an
# empty keyRef is exactly what hides the button.
#
# The fix records the handle on the row. `certs.private_key` already means "where this
# row's key lives, in THIS node's token" for a CA and is already excluded from mesh
# publication, which is precisely what a leaf's handle needs — so no new column.
L161="pkcs11:token=$TOKEN;object=leaf161;type=private?pin-value=1234"
R161=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode "keyref=$L161" \
        --data-urlencode 'cn=leaf161.test' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048')
S161=$(printf '%s' "$R161" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')
chk "an ordinary HSM leaf is issued"                  yes "$([ -n "$S161" ] && echo yes || echo no)"
D161=$(curl -s -b boss.cj "$U/api/certs/$S161")
chk "  and its detail now carries a keyRef"           yes "$(has "$D161" '"keyRef":"pkcs11:')"
chk "  naming the token object it was minted at"      yes "$(has "$D161" 'object=leaf161')"
# The re-key itself: a new handle, and NOTHING is repointed — a leaf has no configuration.
RK161=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'keygen=true' \
        --data-urlencode 'rekey=1' \
        --data-urlencode "keyref=pkcs11:token=$TOKEN;object=leaf161-2;type=private?pin-value=1234" \
        --data-urlencode 'cn=leaf161.test' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048')
RS161=$(printf '%s' "$RK161" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')
chk "re-key of an ordinary leaf is issued"            yes "$([ -n "$RS161" ] && echo yes || echo no)"
chk "  and NO config setting was repointed"           no  "$(has "$RK161" 'repointed')"
chk "  and the new row names the NEW token object"    yes \
    "$(curl -s -b boss.cj "$U/api/certs/$RS161" | grep -q 'object=leaf161-2' && echo yes || echo no)"
# Decode, do not trust the echo: the certificate must really be on the new key.
printf '%s' "$RK161" | sed -n 's/.*"pem":"\(.*\)".*/\1/p' | sed 's/\\n/\n/g' > rk161.pem
"$OSSL" pkey $CA_OSSL_ARGS -pubin \
    -in "pkcs11:token=$TOKEN;object=leaf161-2;type=public" -pubout -out rk161tok.pem 2>/dev/null
M161T=$("$OSSL" rsa -pubin -RSAPublicKey_in -in rk161tok.pem -noout -modulus 2>/dev/null)
[ -z "$M161T" ] && M161T=$("$OSSL" rsa -pubin -in rk161tok.pem -noout -modulus 2>/dev/null)
chk "  and the certificate IS on that new key"        yes \
    "$([ -n "$M161T" ] && [ "$M161T" = "$("$OSSL" x509 -in rk161.pem -noout -modulus 2>/dev/null)" ] && echo yes || echo no)"
# The OLD certificate stays valid — re-key does not revoke, by design.
chk "  and the old certificate is still valid"        yes \
    "$(curl -s -b boss.cj "$U/api/certs/$S161" | grep -q '"status":0' && echo yes || echo no)"

echo "=== A role whose key setting is UNSET gets it assigned, not silently ignored ==="
# Reported: SCEP_RA_KEY is unset in Config and install generates no key for it in the
# HSM. That is deliberate — only web/EST/ACME/MS keys are created at
# install — so this is the NORMAL state of a fresh deployment, not a misconfiguration.
#
# ⚠️ WHAT IT USED TO DO. transport_key_for() returned "" for the role, so the handle
# guard had nothing to compare, the certificate was issued, the row was written, the
# console said done — and the service never loaded the key, because nothing recorded where
# the key is. Issued, stored, reported successful, inert: the RA-credential shape again.
#
# This suite configures all three RA keys at the top, so blank one out first — that is the
# state under test, and it must be produced deliberately rather than assumed.
pg_exec "DELETE FROM config WHERE key='SCEP_RA_KEY';" >/dev/null 2>&1 || :
pg_exec "INSERT INTO config(key,value) VALUES('SCEP_RA_KEY','') ON CONFLICT (key) DO UPDATE SET value='';" >/dev/null 2>&1 || :
U167=$(pg_exec "select coalesce(value,'') from config where key='SCEP_RA_KEY';" 2>/dev/null)
chk "precondition: SCEP_RA_KEY is empty"              yes "$([ -z "$U167" ] && echo yes || echo no)"
R167=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'keygen=true' \
        --data-urlencode "keyref=pkcs11:token=$TOKEN;object=scep-ra-first;type=private?pin-value=1234" \
        --data-urlencode 'cn=scep167.test' --data-urlencode "cert_id=scep-ra-$CA_ID" \
        --data-urlencode 'key=rsa' --data-urlencode 'bits=2048')
chk "the first SCEP RA credential is issued"          yes "$(has "$R167" '"serial"')"
chk "  and the response says the setting was set"     yes "$(has "$R167" '"repointed":"SCEP_RA_KEY"')"
# And marks it a FIRST ASSIGNMENT, not a re-key. This is the very case
# What was hit: the key had just been created under exactly the name in Config, with no
# existing SCEP key in the HSM — and the console announced it as "Re-keyed",
# which claims a key was replaced when SCEP_RA_KEY was simply empty. Same response, two
# very different events; the flag is what lets the toast tell them apart.
chk "  ...and marks it a FIRST assignment, not a re-key" yes \
    "$(has "$R167" '"repointWasUnset":true')"

echo "=== Choosing a purpose that locks RSA must re-sync the key options ==="
# Reported: selecting SCEP RA from the dropdown in the request (key in HSM) form locks
# the RSA key type but leaves other key options cached from previous usage. For
# example, if I requested EC key for OCSP, the page will still show EC-256 curve for RSA
# key type."
#
# ⚠️ A SHELL SUITE CANNOT RUN THE JS, so these are grep-proxies on the served page — weak
# on their own, but they catch the exact reintroduction, because the defect WAS the wiring:
# lockKeyTypeForPurpose ended with `if (typeof syncAlgo === 'function') syncAlgo();` and
# `syncAlgo` is a local const inside another function, never a global. The typeof test is
# 'undefined' at that scope, so the call never ran — silently, because a typeof guard on an
# undeclared identifier cannot throw. That is why it survived: the code reads as defensive
# and is in fact dead.
chk "the visibility sync is a TOP-LEVEL function"      yes "$(has "$PAGE" 'function syncHsmKeyOptions')"
chk "  and the purpose lock actually calls it"         yes "$(has "$PAGE" 'syncHsmKeyOptions();')"
chk "  and no dead 'typeof syncAlgo' guard remains"    no  "$(has "$PAGE" "typeof syncAlgo")"
A167=$(pg_exec "select value from config where key='SCEP_RA_KEY';" 2>/dev/null)
chk "  and SCEP_RA_KEY now NAMES that key"            yes "$(has "$A167" 'object=scep-ra-first')"
# Put the suite's own value back for the sections that follow.
pg_exec "UPDATE config SET value='pkcs11:token=$TOKEN;object=svc-scepra;type=private?pin-value=1234' WHERE key='SCEP_RA_KEY';" >/dev/null 2>&1 || :

echo "=== A SCEP RA credential must be RSA — refused at ISSUANCE ==="
# ⚠️ The RA key DECRYPTS the PKIOperation envelope, so it needs RSA key transport. Nothing
# refused before: an EC choice was issued, stored and reported successful, then failed only
# when a real client enrolled, as an opaque 400 naming neither the key nor the reason.
# Refusing on both ends is the rule; this is the issuance end.
for algo in ec ed25519 rsa-pss; do
  EXTRA='--data-urlencode key='"$algo"
  case "$algo" in ec) EXTRA="$EXTRA --data-urlencode curve=P-256";; rsa-pss) EXTRA="$EXTRA --data-urlencode bits=2048";; esac
  R170=$(post --data-urlencode "ca_instance=$CA_ID" \
         --data-urlencode "keyref=pkcs11:token=$TOKEN;object=scep170-$algo;type=private?pin-value=1234" \
         --data-urlencode "cn=scep170-$algo.test" --data-urlencode "cert_id=scep-ra-$CA_ID" $EXTRA)
  chk "SCEP RA with $algo is refused"        yes "$(has "$R170" 'must use an RSA key')"
  chk "  ...and the reason names decryption" yes "$(has "$R170" 'PKIOperation envelope')"
done
# The refusal must be SPECIFIC: RSA still works, and a non-SCEP id with EC is untouched.
# Uses the CONFIGURED SCEP RA handle: any other would be refused by the handle guard
# first, and then this would pass for the wrong reason.
ROK=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'keygen=false' \
      --data-urlencode "keyref=pkcs11:token=$TOKEN;object=svc-scepra;type=private?pin-value=1234" \
      --data-urlencode 'cn=scep170-ok.test' --data-urlencode "cert_id=scep-ra-$CA_ID" \
      --data-urlencode 'key=rsa' --data-urlencode 'bits=2048')
chk "SCEP RA with RSA is still issued"        yes "$(has "$ROK" '"serial"')"
REC=$(post --data-urlencode "ca_instance=$CA_ID" \
      --data-urlencode "keyref=pkcs11:token=$TOKEN;object=plain170-ec;type=private?pin-value=1234" \
      --data-urlencode 'cn=plain170.test' --data-urlencode 'key=ec' --data-urlencode 'curve=P-256')
chk "an ORDINARY leaf with EC is unaffected"  yes "$(has "$REC" '"serial"')"

echo "=== keyEncipherment is no longer stamped on an rsa-pss certificate ==="
# key_can_encipher() accepted RSA-PSS, so the server would put keyEncipherment on a key
# that cannot perform it — measured: OpenSSL refuses both encrypt and decrypt for RSA-PSS
# at context-init. The console's own KEY_KU_VALID map already excluded it; the server was
# the one that disagreed.
RPSS=$(post --data-urlencode "ca_instance=$CA_ID" \
       --data-urlencode "keyref=pkcs11:token=$TOKEN;object=pss170;type=private?pin-value=1234" \
       --data-urlencode 'cn=pss170.test' --data-urlencode 'key=rsa-pss' --data-urlencode 'bits=2048' \
       --data-urlencode 'ku=digitalSignature,keyEncipherment')
PSSTXT=$(printf '%s' "$RPSS" | sed -n 's/.*"pem":"\(.*\)".*/\1/p' | sed 's/\\n/\n/g' | "$OSSL" x509 -noout -text 2>/dev/null)
chk "an rsa-pss cert is still issued"            yes "$([ -n "$PSSTXT" ] && echo yes || echo no)"
chk "  and does NOT carry Key Encipherment"      no  "$(printf '%s' "$PSSTXT" | grep -q 'Key Encipherment' && echo yes || echo no)"
chk "  but keeps Digital Signature"              yes "$(printf '%s' "$PSSTXT" | grep -q 'Digital Signature' && echo yes || echo no)"

echo "=== 'use existing key' must SHOW the key's facts, not just lock the controls ==="
# Reported: the key-type selection is locked but the key info shown does not match the
# existing key, which is confusing for an end user.
#
# Disabled Algorithm / Key size / Curve at whatever they happened to hold. Nothing
# ever read the key. So the form sat locked on "RSA 3072" over an EC P-384 key and
# asserted it — a form that lies is worse than one that lets you pick. The fix reads
# /api/pkcs11/keys and sets the controls from the TOKEN.
#
# §3e: the shell harness runs no JS, so assert the wiring. Two of these are ORDERING
# checks, and ordering is the whole bug: read the facts before locking, and read them
# after the key NAME is known.
PG3=$(curl -s -b boss.cj "$U/" 2>/dev/null)
inpg(){ printf '%s' "$PG3" | grep -qF "$1" && echo yes || echo no; }
chk "the form reads the adopted key from the token" yes "$(inpg 'async function hsmAdoptKeyFacts()')"
# NOT "does the page mention /api/pkcs11/keys" — renderHsmKeys has always fetched it, so
# that string is present with or without this fix and the check could never fail. The
# distinguishing fact is the cache this function fills.
chk "  it caches the token's key facts"             yes "$(inpg 'HSM.keysLoaded = true;')"
chk "  and only private keys are candidates"        yes "$(inpg "filter(o => o.class === 'private')")"
chk "  RSA size comes from the token's bits"        yes "$(inpg "bsel.value = String(bits)")"
chk "  EC curve is derived from them too"           yes "$(inpg "bits === 256 ? 'P-256'")"
# ⚠️ ORDER 1: facts first, THEN disable. Reversed, syncAlgo() would show bits-vs-curve for
# the stale value and the operator could not correct it.
chk "  facts are read BEFORE the controls lock"     yes "$(inpg 'if (adopt) await hsmAdoptKeyFacts();')"
# ⚠️ ORDER 2: the re-key path fills the key NAME after ticking the box. Firing the change
# event at the old place looked up "" and reported "no key named ''" over a good renewal.
chk "  the re-key path fires the toggle after the name is set" yes \
    "$(inpg "if (box) box.dispatchEvent(new Event('change'));")"
chk "  and no longer fires it while the name is blank" no \
    "$(inpg "box.checked = !!sameKey; box.dispatchEvent(new Event('change'));")"
# A name that names nothing must SAY so rather than leave a wrong algorithm locked.
chk "  an unknown key name is reported, not ignored" yes "$(inpg 'No key named')"
# The token cannot tell PKCS#1 v1.5 from PSS (one CKK_RSA), so an explicit rsa-pss choice
# must survive — the server probes the key's allowed mechanisms at signing time.
chk "  an explicit rsa-pss choice is not overwritten" yes "$(inpg "if (algo.value !== 'rsa-pss') algo.value = 'rsa';")"

echo "=== The Serve As form gains Custom extensions, and drives the omit ticks ==="
# The five items. 1 needs a real field AND a server that accepts it; 2-5 are
# behaviours of the picker. The shell harness cannot run the page's JS (§3e), so item 1 is
# proven END TO END against the API and by decoding the issued certificate, and 2-5 are
# proven by asserting what the served JS actually wires — not merely that a symbol exists.

# ── 1. the field exists, reaches the server, and lands on the certificate ──────────
PG246=$(curl -s -b boss.cj "$U/" 2>/dev/null)
in246(){ grep -qF "$1" <<<"$PG246" && echo yes || echo no; }
# Newline-flattened copy, for the assertions that pin the ORDER of two statements.
PG246_1L=$(tr '\n' ' ' <<<"$PG246")
chk "the HSM form has a Custom extensions box" yes "$(in246 'name="custom_exts" id="hsm_cexts"')"
chk "  and the submit path serialises it"      yes "$(in246 "fd.set('custom_extensions', JSON.stringify(cexts))")"
# The end-to-end half. An OID under a private arc, so nothing in the product could be
# adding it for its own reasons — if it is on the certificate, the form put it there.
CE246='1.3.6.1.4.1.99999.8.1'
R246=$(post --data-urlencode "ca_instance=$CA_ID" --data-urlencode 'cn=cext.leaf.test' \
            --data-urlencode "keyref=pkcs11:token=$TOKEN;object=cext-key;type=private?pin-value=1234" \
            --data-urlencode 'keygen=true' --data-urlencode 'key=ec' \
            --data-urlencode 'ku=digitalSignature' --data-urlencode 'eku=serverAuth' \
            --data-urlencode "custom_extensions=[{\"oid\":\"$CE246\",\"value\":\"DER:05:00\",\"critical\":false}]")
T246=$(printf '%s' "$R246" | sed -n 's/.*"pem":"\(.*\)".*/\1/p' | sed 's/\\n/\n/g' | "$OSSL" x509 -noout -text 2>/dev/null)
chk "a certificate came back"                        yes "$([ -n "$T246" ] && echo yes || echo no)"
chk "  and it CARRIES the requested custom extension" yes \
    "$(grep -qF "$CE246" <<<"$T246" && echo yes || echo no)"

# ── 2/4. picking OCSP Responder sets omit AIA + omit CRL DP and the nocheck OID ────
chk "ocsp-ra asks for the omit ticks"          yes "$(in246 'omit: true')"
chk "  and carries the nocheck OID as an EXTENSION, not an EKU" yes \
    "$(in246 "exts: '1.3.6.1.5.5.7.48.1.5 DER:05:00'")"
# ⚠️ The point of item 4 is that the OID appears in the CUSTOM EXTENSIONS box. The old
# `oids:` key on the same map feeds Custom EKU — the box the form REFUSES nocheck in —
# so asserting the OID is "somewhere in the ocsp-ra entry" would pass on the wrong field.
chk "  and NOT in the Custom EKU field for that purpose" yes \
    "$(grep -q "'ocsp-ra':[^}]*oids: ''" <<<"$PG246_1L" && echo yes || echo no)"

# ── 3/5. any other pick CLEARS both, including "an ordinary certificate" ───────────
chk "the side effects are applied from one place" yes "$(in246 'const applyPurposeSideEffects =')"
# The empty pick returns early from the handler, so the call has to come BEFORE that
# return or "ordinary certificate" would keep the previous purpose's omit ticks.
chk "  and run BEFORE the early return for an ordinary certificate" yes \
    "$(grep -q "applyPurposeSideEffects(want);[[:space:]]*if (!want)" <<<"$PG246_1L" && echo yes || echo no)"
chk "  clearing the box is the no-purpose case"   yes "$(in246 "cx.value = (want && want.exts) || ''")"
chk "  and the ticks follow the purpose, not the previous state" yes \
    "$(in246 'cb.checked = !!(want && want.omit) && permitted')"
# ⚠️ A profile that does not permit omitting must still win over the preset. Ticking a
# box the server will discard tells the operator something untrue about their request.
chk "  a box the profile forbids is never ticked" yes \
    "$(in246 "const permitted = cb.closest('label') && !cb.closest('label').hidden;")"

echo
echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] || echo "RESULT: FAIL"
exit 0
