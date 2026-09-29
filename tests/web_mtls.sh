#!/usr/bin/env bash
# mTLS / certificate-based login for the console.
#
# ⚠️ THE CN IS NOT THE IDENTITY. It used to be: the cert's CN was matched straight to a
# web_users row, which made the console trust a name it had not issued. EST issues the CSR's
# subject verbatim and check_cn() accepts any dotless name when allowed_domains is empty, so
# a caller holding only `requester` could enrol /CN=admin and present it here as admin.
# The identity is now `certs.owner` — what this deployment recorded at issuance — and a
# certificate from a foreign anchor, which has no row, is qualified `dn\<CN>` so it can
# never collide with a local account. Revocation is honoured here too, as it already was in
# EST, CMP and SCEP.
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
# Only adopt the system openssl.cnf where it really is one. On macOS this path is a
# stub that defines no providers, and exporting it breaks every pkcs11 load — the
# CA key then cannot be minted and the suite SKIPs for a reason that looks nothing
# like "wrong openssl.cnf". Tests must not assume a Linux layout (§3d).
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18094
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

pg_setup web_mtls
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
NOW=$(date +%s)
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint) VALUES('a1',0,0,0,$((NOW-86400)),$((NOW+86400)),'CN=web.host','alice','web.host','ff11');"

# server TLS cert + a client CA, then client certs whose CN = the web username
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout srv.key -out srv.pem -days 3650 -subj "/CN=localhost" >/dev/null 2>&1
ca_in_token clientca.pem "/CN=FastPKI Client CA" 3650
gen() { # CN file
    "$OSSL" req -newkey rsa:2048 -nodes -keyout "$2.key" -subj "/CN=$1" -out "$2.csr" >/dev/null 2>&1
    "$OSSL" x509 -req -in "$2.csr" -CA clientca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS -CAcreateserial -days 365 -out "$2.pem" >/dev/null 2>&1
}
gen admin   adm          # CN=admin, but NOT issued by us -> foreign anchor -> dn\admin
gen auditor  aud
gen stranger str
gen admin   esc          # ALSO CN=admin -- the escalation probe, with a row owned by mallory
gen alice   okc          # a certificate we "issued" TO alice: owner == CN
gen svc.example svc      # a SERVICE certificate: owner=alice but CN is a hostname
gen alice   revc         # issued to alice, then revoked
# A directory person's own certificate, as self-service issuance writes it: the name in the CN
# and the provider in a domainComponent. And two that only look like it.
gen 'bob/DC=corp'  dirc   # CN=bob, DC=corp, owner corp\bob -> corp\bob
gen bob            dirn   # CN=bob, no DC,   owner corp\bob -> not a login
gen 'bob/DC=other' diro   # CN=bob, DC=other, owner corp\bob -> not a login

source "$ROOT/tests/user_helpers.sh"
# Foreign-anchor identities are qualified. An unqualified name would be the LOCAL account.
seed_web_user 'dn\admin'   x admin
seed_web_user 'dn\auditor' x auditor
# Local accounts that certificates will resolve to through certs.owner.
seed_web_user alice   x auditor
seed_web_user mallory x requester
# Rows this deployment recorded at issuance. The escalation probe carries CN=admin and is
# owned by mallory: the row must win over the subject.
pg_insert_cert esc.pem  0 mallory >/dev/null   # CN=admin but owned by mallory -> mismatch
pg_insert_cert okc.pem  0 alice   >/dev/null   # CN=alice owned by alice   -> alice
pg_insert_cert svc.pem  0 alice   >/dev/null   # CN=svc.example owned by alice -> not a login
pg_insert_cert revc.pem -1 alice  >/dev/null
seed_web_user 'corp\bob' x auditor
pg_insert_cert dirc.pem 0 'corp\bob' >/dev/null
pg_insert_cert dirn.pem 0 'corp\bob' >/dev/null
pg_insert_cert diro.pem 0 'corp\bob' >/dev/null

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_TLS_CERT=$W/srv.pem
WEB_TLS_KEY=$W/srv.key
WEB_CLIENT_CA=$W/clientca.pem
LOG_LEVEL=err
EOF
"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat srv.log; exit 1; fi
U="https://127.0.0.1:$PORT"
cadm=(--cert adm.pem --key adm.key)
caud=(--cert aud.pem --key aud.key)
cstr=(--cert str.pem --key str.key)
cesc=(--cert esc.pem --key esc.key)
cokc=(--cert okc.pem --key okc.key)
csvc=(--cert svc.pem --key svc.key)
crev=(--cert revc.pem --key revc.key)

echo "=== a client WITHOUT a certificate still reaches the console ==="
# ⚠️ THIS CASE USED TO ASSERT THE BUG. It read "no client cert -> handshake refused (no
# 200)" and only tested that the code was not 200 -- which is true whether the handshake
# was refused (000) or the request was answered and rejected (401). So it passed while
# WEB_CLIENT_CA_ID set SSL_VERIFY_FAIL_IF_NO_PEER_CERT and locked every browser out of the
# console at the handshake, before the login page: Firefox reported
# SSL_ERROR_RX_CERTIFICATE_REQUIRED_ALERT and the server logged nothing.
#
# mTLS is ONE console authentication method beside local passwords, LDAP, OIDC and SAML --
# role_of() tries the certificate, then the session cookie, then the bearer token. So the
# requirement is: no certificate completes the handshake and is UNAUTHENTICATED, and only
# a certificate that cannot be verified is killed at the handshake.
code=$(curl -sk -o /dev/null -w '%{http_code}' "$U/api/me" 2>/dev/null || echo "000")
chk "no client cert -> the handshake still completes" yes \
    "$( [ "$code" != "000" ] && echo yes || echo no )"
chk "  and the caller is unauthenticated, not served" 401 "$code"

echo "=== a foreign-anchor certificate is a QUALIFIED identity, never a local one ==="
ME=$(curl -sk "${cadm[@]}" "$U/api/me")
echo "$ME" | grep -q '"user":"dn\\\\admin"' && a=yes || a=no
chk "admin cert -> user=dn\\admin (not the local 'admin')" yes "$a"
echo "$ME" | grep -q '"role":"admin"' && a=yes || a=no
chk "admin cert -> role=admin" yes "$a"
chk "admin cert authorizes /api/certs" 200 "$(curl -sk -o /dev/null -w '%{http_code}' "${cadm[@]}" "$U/api/certs")"

echo "=== a certificate we issued TO that person is that person ==="
ME=$(curl -sk "${cokc[@]}" "$U/api/me")
echo "$ME" | grep -q '"user":"alice"' && a=yes || a=no
chk "issued cert (CN=alice, owner=alice) -> user=alice" yes "$a"
echo "$ME" | grep -q '"role":"auditor"' && a=yes || a=no
chk "  and carries alice's role" yes "$a"

echo "=== a directory person's certificate (CN=user, DC=provider) is that person ==="
# Self-service issuance keeps the provider out of the CN, so CN never equalled `corp\bob` and
# every directory or SSO user's certificate was refused as a service credential.
chk "CN=bob DC=corp owned by corp\\bob -> corp\\bob" yes \
    "$(curl -sk --cert dirc.pem --key dirc.key "$U/api/me" | grep -qF '"user":"corp\\bob"' && echo yes || echo no)"
chk "  CN=bob with no DC -> 401" 401 \
    "$(curl -sk -o /dev/null -w '%{http_code}' --cert dirn.pem --key dirn.key "$U/api/certs")"
chk "  CN=bob with another provider's DC -> 401" 401 \
    "$(curl -sk -o /dev/null -w '%{http_code}' --cert diro.pem --key diro.key "$U/api/certs")"

echo "=== ESCALATION: a subject we did not issue to that name is refused ==="
# The whole finding: EST issues the CSR's subject verbatim, so mallory can mint /CN=admin.
# owner != CN is the server's own evidence that the subject is not who it claims.
chk "cert with CN=admin owned by mallory -> 401" 401 \
    "$(curl -sk -o /dev/null -w '%{http_code}' "${cesc[@]}" "$U/api/certs")"
curl -sk "${cesc[@]}" "$U/api/me" | grep -q '"role":"admin"' && a=no || a=yes
chk "  and is not admin by virtue of its CN" yes "$a"

echo "=== a SERVICE certificate is not a console login ==="
# CN=svc.example owned by alice: the private key lives on that host, so anyone holding it
# would otherwise sign in as alice.
chk "service cert (CN=svc.example, owner=alice) -> 401" 401 \
    "$(curl -sk -o /dev/null -w '%{http_code}' "${csvc[@]}" "$U/api/certs")"
curl -sk "${csvc[@]}" "$U/api/me" | grep -q '"user":"alice"' && a=no || a=yes
chk "  and does not become its owner" yes "$a"

echo "=== REVOCATION is honoured, as it is in EST/CMP/SCEP ==="
chk "a revoked client certificate is refused" 401 \
    "$(curl -sk -o /dev/null -w '%{http_code}' "${crev[@]}" "$U/api/certs")"
curl -sk "${crev[@]}" "$U/api/me" | grep -q '"user":"alice"' && a=no || a=yes
chk "  and does not authenticate as its owner" yes "$a"

echo "=== RBAC still applies to the cert role ==="
curl -sk "${caud[@]}" "$U/api/me" | grep -q '"role":"auditor"' && a=yes || a=no
chk "auditor cert -> role=auditor" yes "$a"
chk "auditor cert may read the audit log" 200 "$(curl -sk -o /dev/null -w '%{http_code}' "${caud[@]}" "$U/api/audit")"
chk "auditor cert is denied the inventory (403)" 403 "$(curl -sk -o /dev/null -w '%{http_code}' "${caud[@]}" "$U/api/certs")"

echo "=== an unmapped cert CN is unauthorized ==="
chk "valid-but-unknown cert CN -> 401" 401 "$(curl -sk -o /dev/null -w '%{http_code}' "${cstr[@]}" "$U/api/certs")"

echo

echo "=== ⚠️ A FORGED SERIAL CANNOT BORROW ANOTHER CERTIFICATE'S IDENTITY ==="
# Every mTLS path resolves a presented certificate to a local account BY SERIAL, and
# `certs.serial` is a deployment-global primary key with no issuer scoping — so a row found
# that way is "some certificate with this serial", not "this certificate". Serial and CN are
# both fields the ISSUER chooses. Any anchor an operator trusts for client auth can therefore
# mint a certificate carrying a serial we issued and a CN equal to that row's owner, and the
# owner==CN test would pass on a certificate we never issued.
#
# Here the attacker's certificate copies okc.pem's serial and its CN. Before the binding, it
# authenticated as alice. cpp-httplib exposes no way to reach the presented bytes, so the
# check lives in the TLS verify callback where the leaf is in hand.
OKSER=$("$OSSL" x509 -in okc.pem -noout -serial | cut -d= -f2)
"$OSSL" req -newkey rsa:2048 -nodes -keyout forge.key -subj "/CN=alice" -out forge.csr >/dev/null 2>&1
"$OSSL" x509 -req -in forge.csr -CA clientca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS \
    -set_serial "0x$OKSER" -days 365 -out forge.pem >/dev/null 2>&1
chk "PRECONDITION: the forgery copies a real serial" "$OKSER" \
    "$("$OSSL" x509 -in forge.pem -noout -serial | cut -d= -f2)"
chk "  and is a DIFFERENT certificate"           yes \
    "$(cmp -s forge.pem okc.pem && echo no || echo yes)"
chk "  PRECONDITION: the genuine one still logs in as alice" alice \
    "$(curl -sk --cert okc.pem --key okc.key "$U/api/me" | sed -n 's/.*"user":"\([^"]*\)".*/\1/p')"
FORGED=$(curl -sk --cert forge.pem --key forge.key "$U/api/me" 2>/dev/null \
         | sed -n 's/.*"user":"\([^"]*\)".*/\1/p')
chk "the forgery does NOT become alice"          "" "$FORGED"
chk "  and the server says why it refused"       yes \
    "$(grep -q 'whose bytes do not' srv.log && echo yes || echo no)"

# ── the same thing, anchored from the DATABASE rather than a file ──────────────────────
# ⚠️ WHY THIS CASE EXISTS. WEB_CLIENT_CA was a FILE PATH and the only way to anchor console
# mTLS, while every other protocol names a registered CA through <PROTO>_CLIENT_CA_ID. So
# setting WEB_CLIENT_CA to a CA id was the obvious reading, and it failed the listener with
# NOTHING logged: SSL_CTX_load_verify_locations returned an unchecked error and the console
# printed "TLS setup failed (check WEB_TLS_KEY)" — a setting that path never reads. Reported
# from a release candidate, where the operator had set it to `sub-ca`.
kill $P 2>/dev/null; wait $P 2>/dev/null

echo "=== a CA id in WEB_CLIENT_CA is refused, and says why ==="
sed 's|^WEB_CLIENT_CA=.*|WEB_CLIENT_CA=sub-ca|' bootstrap.conf > idpath.conf
"$WEB" --config idpath.conf >idpath.log 2>&1
chk "a CA id in the FILE key does not start the listener" no \
    "$(grep -q 'listening' idpath.log && echo yes || echo no)"
chk "  and the error names WEB_CLIENT_CA, not WEB_TLS_KEY" yes \
    "$(grep -q 'WEB_CLIENT_CA could not be loaded' idpath.log && echo yes || echo no)"
chk "  and says it is a file path, not a CA id" yes \
    "$(grep -qi 'FILE PATH, not a' idpath.log && echo yes || echo no)"
echo "=== WEB_CLIENT_CA_BUNDLE anchors console mTLS from the DB ==="
# ⚠️ THROUGH THE DB OVERLAY, NOT A CONFIG LINE. A PEM is multi-line and a config file holds
# one value per line — which is the whole reason this source exists. The console sets it,
# and cmp_client_ca_db.sh sets CMP_CLIENT_CA_BUNDLE the same way.
CFG="$ROOT/build/fastpki-config"
sed -e 's|^WEB_CLIENT_CA=.*||' idpath.conf > bundle.conf
"$CFG" --config bundle.conf set WEB_CLIENT_CA_BUNDLE "$(cat "$W/clientca.pem")" >/dev/null
"$WEB" --config bundle.conf >bundle.log 2>&1 & P2=$!
sleep 2
chk "the listener starts with a DB-held trust bundle" yes \
    "$(kill -0 $P2 2>/dev/null && echo yes || echo no)"
if kill -0 $P2 2>/dev/null; then
  chk "  and the admin client cert still authenticates" yes \
      "$(curl -sk "${cadm[@]}" "https://127.0.0.1:$PORT/api/me" 2>/dev/null | grep -q '"role":"admin"' && echo yes || echo no)"
fi
kill $P2 2>/dev/null

# ── An attested device certificate plus a PIN (WEB_SIGNIN_METHODS=device-certificate) ──
# The phone is a smartcard: the TLS handshake proves its key, the PIN proves the person.
# device_certs is what ACME writes when it issues through an Apple-attested order; no Apple
# device is available here, so the rows are seeded exactly as ACME writes them.
spki_hex() { "$OSSL" x509 -in "$1" -pubkey -noout | "$OSSL" pkey -pubin -outform DER | xxd -p | tr -d '\n'; }
dev_row() { # pem owner spki-hex
    local ser; ser=$(pg_insert_cert "$1" 0 "$2")
    pg_exec "INSERT INTO device_certs(serial,owner,ca_instance_id,device_serial,spki,created)
             VALUES('$ser','$2','sub-ca','C02TEST$RANDOM','\\x$3'::bytea,$NOW);"
    echo "$ser"
}
gen Alice-iPhone devn     # a device certificate as the Apple profile names it
gen alice        devs     # a device someone NAMED alice: CN equals the owner
gen Alice-iPad   devbad   # recorded with a public key that is not the one it carries
gen Alice-old    devrev   # revoked after its session began
dev_row devn.pem alice "$(spki_hex devn.pem)" >/dev/null
dev_row devs.pem alice "$(spki_hex devs.pem)" >/dev/null
dev_row devbad.pem alice "$(spki_hex okc.pem)" >/dev/null
DEVREV=$(dev_row devrev.pem alice "$(spki_hex devrev.pem)")
cdevn=(--cert devn.pem --key devn.key)
cdevs=(--cert devs.pem --key devs.key)
cdevbad=(--cert devbad.pem --key devbad.key)
cdevrev=(--cert devrev.pem --key devrev.key)

DPORT=$((PORT+2))
sed "s/^WEB_PORT=.*/WEB_PORT=$DPORT/" bootstrap.conf > dev.conf
echo "WEB_SIGNIN_METHODS=password, certificate ,device-certificate" >> dev.conf
PD=; PB=; PX=
"$WEB" --config dev.conf >dev.log 2>&1 & PD=$!
trap 'pg_cleanup; kill $P $PD $PB $PX 2>/dev/null' EXIT
sleep 2
D="https://127.0.0.1:$DPORT"

echo "=== a device certificate is never a sign-in on its own ==="
chk "device cert CN=alice owned by alice -> 401 (the CN matching is not enough)" 401 \
    "$(curl -sk -o /dev/null -w '%{http_code}' "${cdevs[@]}" "$D/api/me")"
chk "device cert CN=Alice-iPhone -> 401" 401 \
    "$(curl -sk -o /dev/null -w '%{http_code}' "${cdevn[@]}" "$D/api/me")"
chk "  PRECONDITION: alice's user certificate still signs in alone" alice \
    "$(curl -sk "${cokc[@]}" "$D/api/me" | sed -n 's/.*"user":"\([^"]*\)".*/\1/p')"

echo "=== the sign-in page learns what it may offer ==="
M=$(curl -sk "${cdevn[@]}" "$D/api/signin/methods")
chk "methods are the normalised policy" '"methods":["password","certificate","device-certificate"]' \
    "$(echo "$M" | grep -o '"methods":\[[^]]*\]')"
chk "the device certificate names its owner" yes \
    "$(echo "$M" | grep -q '"device":{"owner":"alice","pinSet":false}' && echo yes || echo no)"
chk "a user certificate is not a device" yes \
    "$(curl -sk "${cokc[@]}" "$D/api/signin/methods" | grep -q '"device":null' && echo yes || echo no)"
chk "a device record whose key differs from the certificate's is not a device" yes \
    "$(curl -sk "${cdevbad[@]}" "$D/api/signin/methods" | grep -q '"device":null' && echo yes || echo no)"
chk "no PIN set yet -> 403" 403 \
    "$(curl -sk -o /dev/null -w '%{http_code}' "${cdevn[@]}" -d pin=246810 "$D/api/signin/device")"

echo "=== a person sets their PIN after signing in another way ==="
curl -sk -c alice.jar -d username=alice -d password=x "$D/api/login" >/dev/null
chk "a PIN shorter than 6 characters is refused" 400 \
    "$(curl -sk -b alice.jar -o /dev/null -w '%{http_code}' -d pin=12345 "$D/api/me/pin")"
chk "alice sets her PIN" 200 \
    "$(curl -sk -b alice.jar -o /dev/null -w '%{http_code}' -d pin=246810 "$D/api/me/pin")"
chk "  and it reads back as set" '{"set":true}' "$(curl -sk -b alice.jar "$D/api/me/pin")"
chk "  and is stored hashed" no \
    "$(pg_exec "SELECT hash FROM console_pins WHERE subject='alice';" | grep -q 246810 && echo yes || echo no)"
chk "a certificate-only caller has no session to set a PIN with" 401 \
    "$(curl -sk "${cokc[@]}" -o /dev/null -w '%{http_code}' -d pin=999999 "$D/api/me/pin")"
pg_exec "UPDATE web_sessions SET created = created - 3600 WHERE lower(username)='alice';" >/dev/null
chk "a sign-in older than 10 minutes may not change the PIN" 403 \
    "$(curl -sk -b alice.jar -o /dev/null -w '%{http_code}' -d pin=135790 "$D/api/me/pin")"

echo "=== the device certificate plus the PIN signs in ==="
chk "wrong PIN -> 401" 401 \
    "$(curl -sk -o /dev/null -w '%{http_code}' "${cdevn[@]}" -d pin=000000 "$D/api/signin/device")"
chk "a PIN without a device certificate -> 401" 401 \
    "$(curl -sk -o /dev/null -w '%{http_code}' -d pin=246810 "$D/api/signin/device")"
chk "a PIN with a user certificate -> 401" 401 \
    "$(curl -sk -o /dev/null -w '%{http_code}' "${cokc[@]}" -d pin=246810 "$D/api/signin/device")"
chk "right PIN -> 200" 200 \
    "$(curl -sk -c dev.jar -o /dev/null -w '%{http_code}' "${cdevn[@]}" -d pin=246810 "$D/api/signin/device")"
chk "  the session is alice's, with her role" yes \
    "$(curl -sk -b dev.jar "${cdevn[@]}" "$D/api/me" | grep -q '"user":"alice","role":"auditor"' && echo yes || echo no)"
chk "  and the audit log names the device" yes \
    "$(pg_exec "SELECT detail FROM audit_log WHERE action='web_login' AND actor='alice';" | grep -q 'auth=device-certificate device_serial=C02TEST' && echo yes || echo no)"

echo "=== the session goes with the certificate, not the cookie ==="
chk "the cookie without the certificate -> 401" 401 \
    "$(curl -sk -b dev.jar -o /dev/null -w '%{http_code}' "$D/api/audit")"
chk "the cookie with another of alice's certificates -> 401" 401 \
    "$(curl -sk -b dev.jar "${cdevs[@]}" -o /dev/null -w '%{http_code}' "$D/api/audit")"
curl -sk -c rev.jar -o /dev/null "${cdevrev[@]}" -d pin=246810 "$D/api/signin/device"
chk "  PRECONDITION: a second device's session works" 200 \
    "$(curl -sk -b rev.jar "${cdevrev[@]}" -o /dev/null -w '%{http_code}' "$D/api/audit")"
pg_exec "UPDATE certs SET status=-1 WHERE serial='$DEVREV';" >/dev/null
chk "revoking that device's certificate ends its session at the next request" 401 \
    "$(curl -sk -b rev.jar "${cdevrev[@]}" -o /dev/null -w '%{http_code}' "$D/api/audit")"
chk "  and the first device is unaffected" 200 \
    "$(curl -sk -b dev.jar "${cdevn[@]}" -o /dev/null -w '%{http_code}' "$D/api/audit")"

echo "=== an administrator clears a forgotten PIN ==="
chk "a user without user:manage cannot clear someone's PIN" 403 \
    "$(curl -sk "${caud[@]}" -o /dev/null -w '%{http_code}' -X DELETE "$D/api/users/pin?username=alice")"
chk "an admin clears alice's PIN" 200 \
    "$(curl -sk "${cadm[@]}" -o /dev/null -w '%{http_code}' -X DELETE "$D/api/users/pin?username=alice")"
chk "  and the device no longer signs in" 403 \
    "$(curl -sk -o /dev/null -w '%{http_code}' "${cdevn[@]}" -d pin=246810 "$D/api/signin/device")"

echo "=== the policy is enforced at sign-in and on every request ==="
# A second console on the same database whose policy leaves out password and certificate:
# sessions are shared, so a password session made on the first is presented to the second.
BPORT=$((PORT+3))
sed -e "s/^WEB_PORT=.*/WEB_PORT=$BPORT/" -e "s/^WEB_SIGNIN_METHODS=.*/WEB_SIGNIN_METHODS=device-certificate/" \
    dev.conf > only.conf
"$WEB" --config only.conf >only.log 2>&1 & PB=$!
sleep 2
B="https://127.0.0.1:$BPORT"
curl -sk -c pw.jar -d username=alice -d password=x "$D/api/login" >/dev/null
chk "  PRECONDITION: the password session works where password is allowed" 200 \
    "$(curl -sk -b pw.jar -o /dev/null -w '%{http_code}' "$D/api/audit")"
chk "the same session is refused where password is not" 401 \
    "$(curl -sk -b pw.jar -o /dev/null -w '%{http_code}' "$B/api/audit")"
chk "password sign-in is refused -> 403" 403 \
    "$(curl -sk -o /dev/null -w '%{http_code}' -d username=alice -d password=x "$B/api/login")"
chk "a user certificate alone is refused" 401 \
    "$(curl -sk "${cokc[@]}" -o /dev/null -w '%{http_code}' "$B/api/me")"
chk "the page is told only the device method" '"methods":["device-certificate"]' \
    "$(curl -sk "$B/api/signin/methods" | grep -o '"methods":\[[^]]*\]')"
kill $PB $PD 2>/dev/null; wait $PB $PD 2>/dev/null

echo "=== an unusable policy stops the console with a reason ==="
sed "s/^WEB_SIGNIN_METHODS=.*/WEB_SIGNIN_METHODS=password,smartcard/" only.conf > bad.conf
# In the background and killed after, so a console that wrongly starts cannot hang the suite.
"$WEB" --config bad.conf >bad.log 2>&1 & PX=$!; sleep 2; kill $PX 2>/dev/null; wait $PX 2>/dev/null
chk "an unknown method is refused by name" yes \
    "$(grep -q "unknown method 'smartcard'" bad.log && echo yes || echo no)"
sed "s/^WEB_SIGNIN_METHODS=.*/WEB_SIGNIN_METHODS= , /" only.conf > empty.conf
"$WEB" --config empty.conf >empty.log 2>&1 & PX=$!; sleep 2; kill $PX 2>/dev/null; wait $PX 2>/dev/null
chk "an empty list is refused" yes \
    "$(grep -q "must name at least one sign-in method" empty.log && echo yes || echo no)"

echo "=== WEB-mTLS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
