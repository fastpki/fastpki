#!/usr/bin/env bash
# ACME key roll-over (RFC 8555 §7.3.5). Starts fastpki-acme and drives the protocol with
# the shell JWS client in tests/acme_jws.sh — certbot has no key-change command, so the
# could not convert this one to certbot the way it converted the others.
#
# ⚠️ This header used to say "drives the protocol with tests/acme_keychange.py", a file
# §3e had already deleted. suite_exit_honest.sh now fails on any suite that claims to use
# a tests/*.py which is not there.
# No privileges needed (no :80 / challenge).
# ⚠️ THIS SUITE REGISTERS WITH A REAL EAB BINDING, and that is the point. It used to
# pin ACME_EAB_REQUIRED=false because it tests ACME PROTOCOL mechanics and not deployment
# policy — but the switch is gone, and pinning it meant fourteen suites exercised a
# configuration FastPKI does not ship. acme_new_account (acme_jws.sh) provisions a kid +
# HMAC in the `keys` table and signs the RFC 8555 §7.3.4 binding, so registration here now
# takes exactly the path a real client takes.
# The DEFAULT itself is still exercised by acme_default_eab.sh, which provisions NOTHING.
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
W="$(mktemp -d)"; cd "$W"; PORT=18455
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

source "$ROOT/tests/acme_jws.sh"
ca_in_token ca.pem "/CN=KC CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_keychange
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > bootstrap.conf <<EOF
BASE_URL=https://localhost:$PORT
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
ACME_CERT=$W/acme.pem
ACME_KEY=$W/acme.key
PG_CONNINFO=$PG_CONNINFO
ACME_BIND=127.0.0.1
ACME_PORT=$PORT
ACME_BASE_PATH=/acme
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-acme" --config bootstrap.conf > srv.log 2>&1 & SRV=$!
sleep 1; trap 'pg_cleanup; kill $SRV 2>/dev/null' EXIT
if ! kill -0 $SRV 2>/dev/null; then echo "fastpki-acme died:"; cat srv.log; exit 1; fi

echo "=== ACME key roll-over (RFC 8555 §7.3.5) ==="
JWS_TMP="$W/jws"; mkdir -p "$JWS_TMP"
acme_dir "https://127.0.0.1:$PORT/acme/ca/directory"
chk "directory advertises keyChange" yes "$([ -n "$ACME_KEYCHANGE" ] && echo yes || echo no)"

jws_newkey old.pem
jws_newkey new.pem
acme_new_account old.pem
chk "registered with the old key" yes \
    "$([ "$ACME_STATUS" = 200 ] || [ "$ACME_STATUS" = 201 ] && echo yes || echo no)"
KID=$ACME_LOCATION

# The inner JWS proves possession of the NEW key and carries no nonce — §7.3.5 is explicit
# that it is not an independent request, and a server that demanded one would reject every
# correct client. It is signed by the new key and becomes the outer request's PAYLOAD.
INNER_PROT=$(printf '{"alg":"ES256","jwk":%s,"url":"%s"}' "$(jws_jwk new.pem)" "$ACME_KEYCHANGE")
INNER_PAY=$(printf '{"account":"%s","oldKey":%s}' "$KID" "$(jws_jwk old.pem)")
INNER=$(jws_sign new.pem "$INNER_PROT" "$INNER_PAY")
chk "the inner JWS was built" yes "$(printf '%s' "$INNER" | grep -q '"signature"' && echo yes || echo no)"

acme_post_kid old.pem "$KID" "$ACME_KEYCHANGE" "$INNER"
chk "keyChange -> 200" 200 "$ACME_STATUS"

# What the roll-over MEANS, in both directions. Either half alone would pass against a
# server that ignored the request entirely.
acme_post_kid new.pem "$KID" "$KID" ""
chk "the new key now authenticates the account" 200 "$ACME_STATUS"
acme_post_kid old.pem "$KID" "$KID" ""
chk "the old key no longer does" yes \
    "$([ "$ACME_STATUS" -ge 400 ] && [ "$ACME_STATUS" -lt 500 ] && echo yes || echo no)"

# server-side audit log line
grep -q "ACME key-change for account" srv.log && a=yes || a=no
chk "server logged the key-change" yes "$a"

echo
echo "=== ACME KEYCHANGE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
