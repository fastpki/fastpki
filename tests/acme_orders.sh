#!/usr/bin/env bash
# ACME account orders list (RFC 8555 §7.1.2.1). Registers an account, creates two orders,
# POST-as-GETs the account `orders` URL and asserts both are listed and that a DIFFERENT
# account is refused. No privileges needed (no :80).
#
# §3e: pure shell. This was the first ACME suite off Python — the JWS signing that kept
# all seven of them there lives in tests/acme_jws.sh now. The assertions also went from
# one ("the driver printed PASS") to one per protocol fact, which is the real gain: when
# the driver failed, the suite could only say that something in eighty lines of Python
# went wrong.
# ⚠️ THIS SUITE USED TO PIN ACME_EAB_REQUIRED=false. The key is gone — an ACME server
# that accepts any self-generated account key is exactly the class of setting that ticket
# deletes — so the suite now provisions a real EAB credential and binds with it. It still
# exercises ACME PROTOCOL mechanics; it just does so against the posture we ship, which is
# the posture it should have been testing all along.
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
W="$(mktemp -d)"; cd "$W"; PORT=18458
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

source "$ROOT/tests/acme_jws.sh"
ca_in_token ca.pem "/CN=Orders CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_orders
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

echo "=== ACME orders list (RFC 8555 §7.1.2.1) ==="
JWS_TMP="$W/jws"; mkdir -p "$JWS_TMP"
acme_dir "https://127.0.0.1:$PORT/acme/ca/directory"
chk "directory advertises newAccount" yes "$([ -n "$ACME_NEW_ACCT" ] && echo yes || echo no)"
# EAB is mandatory now — provision the credential these accounts bind with.
acme_seed_eab acme-orders
chk "directory advertises newOrder"   yes "$([ -n "$ACME_NEW_ORDER" ] && echo yes || echo no)"

# ── account 1 ───────────────────────────────────────────────────────────────────
jws_newkey k1.pem
acme_new_account k1.pem
chk "newAccount accepted the ES256 JWS" yes \
    "$([ "$ACME_STATUS" = 200 ] || [ "$ACME_STATUS" = 201 ] && echo yes || echo no)"
KID1=$ACME_LOCATION
ORDERS=$(json_str "$ACME_BODY" orders)
chk "account has a Location (kid)" yes "$([ -n "$KID1" ] && echo yes || echo no)"
chk "account advertises an orders URL" yes "$([ -n "$ORDERS" ] && echo yes || echo no)"

new_order() {   # <domain> -> echoes the order URL
    acme_post_kid k1.pem "$KID1" "$ACME_NEW_ORDER" \
        "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"$1\"}]}"
    [ "$ACME_STATUS" = 201 ] || { echo ""; return; }
    printf '%s' "$ACME_LOCATION"
}
O1=$(new_order a.orders.test); chk "newOrder a.orders.test -> 201" yes "$([ -n "$O1" ] && echo yes || echo no)"
O2=$(new_order b.orders.test); chk "newOrder b.orders.test -> 201" yes "$([ -n "$O2" ] && echo yes || echo no)"
chk "the two orders have distinct URLs" yes "$([ -n "$O1" ] && [ "$O1" != "$O2" ] && echo yes || echo no)"

# ── the list ────────────────────────────────────────────────────────────────────
# POST-as-GET: an empty payload, signed. Not a GET — RFC 8555 §7.1.2.1 makes the orders
# list an authenticated resource, which is the point of the cross-account check below.
acme_post_kid k1.pem "$KID1" "$ORDERS" ""
chk "POST-as-GET the orders list -> 200" 200 "$ACME_STATUS"
LISTED=$ACME_BODY
chk "the list contains the first order"  yes "$(printf '%s' "$LISTED" | grep -qF "$O1" && echo yes || echo no)"
chk "the list contains the second order" yes "$(printf '%s' "$LISTED" | grep -qF "$O2" && echo yes || echo no)"
# Exactly two: a list that returned every order on the server would also contain both.
N=$(printf '%s' "$LISTED" | tr ',' '\n' | grep -c '/acme/[^"]*order')
chk "and nothing else (exactly 2)" 2 "$N"
[ "$N" = 2 ] || echo "  (orders body was: $LISTED)"

# ── the signature is really checked ──────────────────────────────────────────────
# This suite hand-builds the JWS, so it has to prove the server VERIFIES it. Without
# this, a client emitting a malformed ES256 signature — DER instead of the raw R||S RFC
# 7518 wants, say — would pass every assertion above against a server that never looked.
# Flip one character of a valid signature and the same request must now fail.
acme_post_kid k1.pem "$KID1" "$ORDERS" ""
GOOD=$(cat "$JWS_TMP/req.json")
SIG=$(printf '%s' "$GOOD" | sed -n 's/.*"signature":"\([^"]*\)".*/\1/p')
FLIP=$([ "${SIG:0:1}" = "A" ] && echo "B${SIG:1}" || echo "A${SIG:1}")
printf '%s' "$GOOD" | sed "s|\"signature\":\"$SIG\"|\"signature\":\"$FLIP\"|" > "$JWS_TMP/bad.json"
acme_http "$ORDERS" "$JWS_TMP/bad.json"
chk "a tampered signature is refused" yes \
    "$([ "$ACME_STATUS" -ge 400 ] && echo yes || echo no)"

# ── another account must not read it ─────────────────────────────────────────────
jws_newkey k2.pem
acme_new_account k2.pem
KID2=$ACME_LOCATION
chk "a second account registered" yes "$([ -n "$KID2" ] && [ "$KID2" != "$KID1" ] && echo yes || echo no)"
acme_post_kid k2.pem "$KID2" "$ORDERS" ""
chk "cross-account read of the orders list -> 401" 401 "$ACME_STATUS"

# ── an identifier must be a DNS NAME, not just a string ─────────────────────────
# ⚠️ THE VALUE WAS NEVER LOOKED AT. `type` was checked and `value` was taken as given —
# and it becomes the authz name, then the SAN the CSR must match at finalize, then the
# dNSName in the certificate. policy.cpp deliberately skips the domain allowlist for ACME
# because an ACME name is proven by challenge instead, so on this path NOTHING inspected
# the bytes.
#
# The sharp case is the embedded NUL. DNS splits on '.', so evil.example\0.attacker.example
# is an ordinary name inside a zone the caller controls — its dns-01 challenge SOLVES — and
# the certificate then carries a dNSName that a client reading the SAN as a C string sees as
# `evil.example`. The rest are names no resolver could answer for, and a CA has no business
# certifying them either way.
#
# Refused at newOrder, which is the point: at finalize the client has already solved every
# challenge, and policy.cpp's refusal would arrive after all that work.
bad_ident() {   # <json string body> <label>
    acme_post_kid k1.pem "$KID1" "$ACME_NEW_ORDER" \
        "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"$1\"}]}"
    chk "newOrder refuses $2" 400 "$ACME_STATUS"
    chk "  as rejectedIdentifier" yes \
        "$(printf '%s' "$ACME_BODY" | grep -q rejectedIdentifier && echo yes || echo no)"
}
bad_ident 'evil.example\u0000.attacker.example' "an embedded NUL"
bad_ident 'has space.example'                    "a space"
bad_ident 'a..b.example'                         "an empty label"
bad_ident '-lead.example'                        "a label starting with a hyphen"
bad_ident 'tab\there.example'                   "a control character"
# Anti-vacuity: the check must not be refusing everything. A wildcard is syntactically
# legal here on purpose — whether it may be ISSUED is the profile's question, and this
# check must not quietly answer it.
O3=$(new_order 'c.orders.test'); chk "an ordinary name still -> 201" yes "$([ -n "$O3" ] && echo yes || echo no)"
O4=$(new_order '*.orders.test'); chk "a wildcard is still accepted"  yes "$([ -n "$O4" ] && echo yes || echo no)"

echo
echo "=== ACME ORDERS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
