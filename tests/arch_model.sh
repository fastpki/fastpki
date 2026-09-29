#!/usr/bin/env bash
# The secure architecture model: an initial login via a
# traditional method (password / OIDC / SAML / PSK) lets the user request a client
# certificate; subsequent logins use that certificate (mTLS), whose subject DN
# identifies the user. This test proves the loop closes end-to-end with the pieces
# already shipped — self-service issuance, identity-bound subject
# + the owner DN in Subject Directory Attributes, and mTLS console login
# a password user requests a cert and then re-authenticates with it,
# no password.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/json_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORTA=18290; PORTB=18291
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

# One CA acts as both the issuing CA and the console's client-cert trust anchor.
ca_in_token ca.pem "/CN=Arch CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout srv.key -out srv.pem -days 3650 -subj "/CN=localhost" >/dev/null 2>&1
printf "internal\n" > domains.txt
pg_setup arch_model
seed_domains $W/domains.txt   # allowed_domains is the sole source
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
# alice is a normal console user (password); role requester (self-service).
source "$ROOT/tests/user_helpers.sh"
seed_web_user alice alicepw12 requester

echo "=== phase 1: password login → request a client certificate ==="
cat > a.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
ROOT_CA_PEM=$W/root.pem
WEB_BIND=127.0.0.1
WEB_PORT=$PORTA
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
seed_ca_from_conf a.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$WEB" --config a.conf >a.log 2>&1 & PA=$!
sleep 1; trap 'pg_cleanup; kill $PA $PB 2>/dev/null' EXIT
if ! kill -0 $PA 2>/dev/null; then echo "web A died:"; cat a.log; exit 1; fi
UA="http://127.0.0.1:$PORTA"
chk "alice logs in with her password" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -c alice.cj -X POST "$UA/api/login" -d 'username=alice&password=alicepw12')"
# She generates a keypair locally and asks for a cert (CN in the CSR is ignored —
# the server binds it to her identity).
#
# ⚠️ She REQUESTS clientAuth, and now she has to. The `requester` profile's default EKU was
# emptied deliberately — serverAuth and clientAuth are no longer handed out by default — so a
# bare CSR now yields a certificate with no ExtendedKeyUsage at all. That is not
# a broken certificate — RFC 5280 §4.2.1.12 says an absent EKU constrains nothing — but it
# means the EKU has to come from the CSR, which is the honour-what-is-asked path the profile
# still permits. Asking for it is what a real client does, and it tests strictly more than
# reading back a default the CA stamped by itself.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout alice.key -out alice.csr -subj "/CN=ignored" \
        -addext "extendedKeyUsage=clientAuth" >/dev/null 2>&1
curl -s -b alice.cj -X POST --data-binary @alice.csr "$UA/api/certs/request?ca_instance=ca-global" > resp.json
json_pem "$(cat resp.json)" pem alice.pem
chk "she receives an issued certificate" yes "$(has "$(cat alice.pem)" 'BEGIN CERTIFICATE')"
chk "the cert is bound to her identity (CN=alice)" yes \
    "$(has "$("$OSSL" x509 -in alice.pem -noout -subject -nameopt RFC2253 2>/dev/null)" 'CN=alice')"
chk "the cert carries clientAuth EKU (usable for mTLS)" yes \
    "$("$OSSL" x509 -in alice.pem -noout -ext extendedKeyUsage 2>/dev/null | grep -q 'Web Client' && echo yes || echo no)"
# The control for the line above: the profile HONOURED a request rather than stamping a
# default, so it must not also have added serverAuth, which the CSR did not ask for.
chk "  and only that — no serverAuth the CSR never asked for" no \
    "$("$OSSL" x509 -in alice.pem -noout -ext extendedKeyUsage 2>/dev/null | grep -q 'Web Server' && echo yes || echo no)"
chk "the owner DN rides in the Subject Directory Attributes ext" yes \
    "$("$OSSL" x509 -in alice.pem -noout -text 2>/dev/null | grep -q 'Subject Directory Attributes' && echo yes || echo no)"
kill $PA 2>/dev/null; wait $PA 2>/dev/null

echo "=== phase 2: re-authenticate with that certificate (mTLS, no password) ==="
cat > b.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORTB
WEB_TLS_CERT=$W/srv.pem
WEB_TLS_KEY=$W/srv.key
WEB_CLIENT_CA=$W/ca.pem
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
"$WEB" --config b.conf >b.log 2>&1 & PB=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "b.conf" WEB_PORT "$PB" || true
if ! kill -0 $PB 2>/dev/null; then echo "web B died:"; cat b.log; exit 1; fi
UB="https://127.0.0.1:$PORTB"
chk "the mTLS console rejects a request with no client cert" no \
    "$([ "$(curl -sk -o /dev/null -w '%{http_code}' "$UB/api/me" 2>/dev/null || echo 000)" = "200" ] && echo yes || echo no)"
ME=$(curl -sk --cert alice.pem --key alice.key "$UB/api/me")
chk "her self-service cert authenticates her (no password)" yes "$(has "$ME" '"user":"alice"')"
chk "the cert maps to her role"                              yes "$(has "$ME" '"role":"requester"')"
chk "she can reach her own inventory over mTLS"              200 \
    "$(curl -sk -o /dev/null -w '%{http_code}' --cert alice.pem --key alice.key "$UB/api/certs")"

echo
echo "=== ARCH MODEL: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
