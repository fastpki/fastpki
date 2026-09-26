#!/usr/bin/env bash
# ACME TLS-ALPN-01 (RFC 8737) + newAuthz pre-authorization (RFC 8555 §7.4.1).
# Starts fastpki-acme with ACME_NEW_AUTHZ + a test ACME_TLS_ALPN_PORT, then runs
# both flows are driven here against an `openssl s_server` ALPN responder (§3e: pure
# shell; the JWS and the responder live in tests/acme_jws.sh).
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
W="$(mktemp -d)"; cd "$W"; PORT=18466; ALPN=14443
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }
source "$ROOT/tests/acme_jws.sh"

ca_in_token ca.pem "/CN=ALPN CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_preauth_alpn
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
ACME_NEW_AUTHZ=true
ACME_TLS_ALPN_PORT=$ALPN
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-acme" --config bootstrap.conf > srv.log 2>&1 & SRV=$!
sleep 1; trap 'kill $SRV 2>/dev/null' EXIT
if ! kill -0 $SRV 2>/dev/null; then echo "fastpki-acme died:"; cat srv.log; exit 1; fi

echo "=== ACME TLS-ALPN-01 + newAuthz ==="
JWS_TMP="$W/jws"; mkdir -p "$JWS_TMP"
acme_dir "https://127.0.0.1:$PORT/acme/ca/directory"
NEW_AUTHZ=$(json_str "$ACME_BODY" newAuthz)
chk "directory advertises newAuthz (ACME_NEW_AUTHZ=true)" yes \
    "$([ -n "$NEW_AUTHZ" ] && echo yes || echo no)"
jws_newkey acct.pem
acme_new_account acct.pem
KID=$ACME_LOCATION
chk "account registered" yes "$([ -n "$KID" ] && echo yes || echo no)"

# Validate one authorization over tls-alpn-01. Returns 0 only if it reaches "valid".
complete_via_alpn() {   # <identifier> <authz-url>
    local id=$1 az=$2 ch ch_url token
    acme_post_kid acct.pem "$KID" "$az" ""
    ch=$(printf '%s' "$ACME_BODY" | tr '{' '\n' | grep 'tls-alpn-01')
    ch_url=$(json_str "$ch" url); token=$(json_str "$ch" token)
    [ -n "$ch_url" ] && [ -n "$token" ] || return 1
    alpn_cert "$id" "$token" acct.pem "val_$id"
    alpn_serve "$ALPN" "val_$id"
    acme_post_kid acct.pem "$KID" "$ch_url" '{}'
    [ "$ACME_STATUS" = 200 ] || { alpn_stop; return 1; }
    acme_poll_status acct.pem "$KID" "$az" valid; local r=$?
    alpn_stop
    return $r
}
trap 'alpn_stop; pg_cleanup; kill $SRV 2>/dev/null' EXIT

# ── flow 1: an ordinary order validated over tls-alpn-01 ────────────────────────
ID1=localhost
acme_post_kid acct.pem "$KID" "$ACME_NEW_ORDER" \
    "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"$ID1\"}]}"
chk "newOrder($ID1) -> 201" 201 "$ACME_STATUS"
ORDER1=$ACME_LOCATION
AZ1=$(printf '%s' "$ACME_BODY" | sed -n 's/.*"authorizations":\["\([^"]*\)".*/\1/p')
complete_via_alpn "$ID1" "$AZ1" && r=ok || r=no
chk "tls-alpn-01 validated the authorization" ok "$r"

# ── the refusal must name WHICH of six things went wrong ────────────────────────
# ⚠️ ONE FALSE, SIX CAUSES. fetch_tlsalpn01 returns false when the host does not resolve,
# the connect fails, the handshake fails, the peer speaks a different ALPN, it sends no
# certificate, the certificate has no acmeIdentifier extension, or the digest differs. All
# were rendered as "validation certificate missing or mismatched", which sends the reader
# to their responder's certificate when the usual cause is an ordinary web server holding
# the port: it completes the handshake and simply does not speak acme-tls/1, so the
# certificate is never the problem.
#
# Each case drives the REAL validator and reads the error the server stored, so these
# assert behaviour rather than wording in the source.
# ⚠️ THE IDENTIFIER MUST RESOLVE. A made-up name makes every case fail at getaddrinfo, so
# all three return "the identifier does not resolve" and the discriminator looks broken when
# it is working — it was the first thing this very assertion caught, against itself. Vary
# ONLY what is listening on the port.
alpn_error_for() {   # <identifier>  -> echoes the challenge error detail
    local id=$1 az ch ch_url
    acme_post_kid acct.pem "$KID" "$NEW_AUTHZ" "{\"identifier\":{\"type\":\"dns\",\"value\":\"$id\"}}"
    az=$ACME_LOCATION
    acme_post_kid acct.pem "$KID" "$az" ""
    ch=$(printf '%s' "$ACME_BODY" | tr '{' '\n' | grep 'tls-alpn-01')
    ch_url=$(json_str "$ch" url)
    acme_post_kid acct.pem "$KID" "$ch_url" '{}'
    local i
    for i in $(seq 1 25); do
        acme_post_kid acct.pem "$KID" "$az" ""
        printf '%s' "$ACME_BODY" | grep -q '"status":"invalid"' && break
        sleep 0.3
    done
    printf '%s' "$ACME_BODY" | sed -nE 's/.*"detail":"([^"]*)".*/\1/p' | head -1
}

echo "=== a failed tls-alpn-01 names WHICH of the six causes it was ==="

# (a) NOTHING LISTENING.
alpn_stop
E1=$(alpn_error_for 127.0.0.1)
chk "a closed port is named as such"                   yes \
    "$(printf '%s' "$E1" | grep -qi 'nothing accepted' && echo yes || echo no)"

# (b) A PLAIN TLS SERVER ON THE PORT — the reported shape. The handshake succeeds and only
#     the ALPN differs, so blaming the certificate here would blame the one correct thing.
alpn_cert 127.0.0.1 tok-b acct.pem val_b
"$OSSL" s_server -accept "$ALPN" -cert val_b.pem -key val_b.key -quiet -no_ticket \
    >/dev/null 2>&1 & ALPN_PID=$!; disown "$ALPN_PID" 2>/dev/null || true; sleep 0.5
E2=$(alpn_error_for 127.0.0.1)
alpn_stop
# ⚠️ NOT a grep for "alpn" — the OLD message was "tls-alpn-01 validation certificate
# missing or mismatched", which contains the challenge type and so matched that pattern
# happily. The revert-and-watch step caught this assertion passing against the very code it
# is meant to reject. Match a word only the new message can produce.
chk "a server not speaking acme-tls/1 is named"        yes \
    "$(printf '%s' "$E2" | grep -qi 'negotiated' && echo yes || echo no)"
chk "  and it points at the port, not the certificate" yes \
    "$(printf '%s' "$E2" | grep -qi 'listening on this port' && echo yes || echo no)"
chk "  it does NOT blame the digest"                   no \
    "$(printf '%s' "$E2" | grep -qi 'digest does not match' && echo yes || echo no)"

# (c) CORRECT ALPN, WRONG DIGEST — the case the old wording actually described. It must stay
#     distinguishable from (b), or the discriminator has only moved the ambiguity.
alpn_cert 127.0.0.1 not-the-real-token acct.pem val_c
alpn_serve "$ALPN" val_c
E3=$(alpn_error_for 127.0.0.1)
alpn_stop
chk "a wrong digest is named as a digest mismatch"     yes \
    "$(printf '%s' "$E3" | grep -qi 'digest does not match' && echo yes || echo no)"
chk "  the three causes give three DIFFERENT messages" yes \
    "$([ -n "$E1" ] && [ "$E1" != "$E2" ] && [ "$E2" != "$E3" ] && [ "$E1" != "$E3" ] && echo yes || echo no)"
acme_post_kid acct.pem "$KID" "$ORDER1" ""
chk "the order reached ready" ready "$(json_str "$ACME_BODY" status)"

# ── the validation is a real check, not a handshake ─────────────────────────────
# tls-alpn-01's whole security property is that the responder proves it holds the key
# authorization. A server that merely completed the handshake would validate any
# identifier for anyone who can answer on port 443 — so serve a certificate whose
# acmeIdentifier digest is for a DIFFERENT token and require the challenge to fail.
ID_BAD=bad.alpn.test
acme_post_kid acct.pem "$KID" "$ACME_NEW_ORDER" \
    "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"$ID_BAD\"}]}"
AZ_BAD=$(printf '%s' "$ACME_BODY" | sed -n 's/.*"authorizations":\["\([^"]*\)".*/\1/p')
acme_post_kid acct.pem "$KID" "$AZ_BAD" ""
CHB=$(printf '%s' "$ACME_BODY" | tr '{' '\n' | grep 'tls-alpn-01')
CHB_URL=$(json_str "$CHB" url)
# The wrong token: a valid-looking cert for the right name, keyed to something else.
alpn_cert "$ID_BAD" "not-the-real-token" acct.pem valbad
alpn_serve "$ALPN" valbad
acme_post_kid acct.pem "$KID" "$CHB_URL" '{}'
acme_poll_status acct.pem "$KID" "$AZ_BAD" valid 8 && r=valid || r="$(json_str "$ACME_BODY" status)"
alpn_stop
chk "a wrong key authorization does NOT validate" no "$([ "$r" = valid ] && echo yes || echo no)"

# ── flow 2: pre-authorize, then reuse it ────────────────────────────────────────
# The point of newAuthz is that the NEXT order for the same identifier needs no
# challenge at all. Asserting only that the pre-authorization validated would not show
# the reuse — the order below must be `ready` on creation, without a second validation.
ID2=127.0.0.1
acme_post_kid acct.pem "$KID" "$NEW_AUTHZ" \
    "{\"identifier\":{\"type\":\"dns\",\"value\":\"$ID2\"}}"
chk "newAuthz($ID2) -> 201" 201 "$ACME_STATUS"
PREAUTHZ=$ACME_LOCATION
complete_via_alpn "$ID2" "$PREAUTHZ" && r=ok || r=no
chk "the pre-authorization validated over tls-alpn-01" ok "$r"

acme_post_kid acct.pem "$KID" "$ACME_NEW_ORDER" \
    "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"$ID2\"}]}"
chk "newOrder($ID2) after pre-auth -> 201" 201 "$ACME_STATUS"
ORDER2=$ACME_LOCATION
acme_post_kid acct.pem "$KID" "$ORDER2" ""
chk "and it is ready IMMEDIATELY (the pre-auth was reused)" ready "$(json_str "$ACME_BODY" status)"

echo "=== A WHOLE order over tls-alpn-01, through the shared client ==="
# Everything above drives the challenge by hand. This drives the same validation through
# `acme_alpn01_order` — the shared entry point demo/pki-demo.sh will use — so the helper
# is proven here rather than first discovered to be broken in the demo.
#
# It also covers ground the hand-driven flows do not: newOrder -> authz -> challenge ->
# finalize -> download, ending in a certificate that must verify against the CA. The
# sections above stop at "authz is valid".
rm -f alpn-chain.pem
if acme_alpn01_order "https://127.0.0.1:$PORT/acme/ca/directory" localhost "$ALPN" alpn-chain.pem \
        >order.log 2>&1; then O=ok; else O="failed — $(tail -2 order.log | tr '\n' ' ')"; fi
chk "acme_alpn01_order completes a full order" ok "$O"
chk "  and it returned a certificate"          yes \
    "$(grep -q 'BEGIN CERTIFICATE' alpn-chain.pem 2>/dev/null && echo yes || echo no)"
# ⚠️ Decoded, not grepped for success: a chain that is not signed by this CA would still
# contain BEGIN CERTIFICATE and pass the line above.
chk "  the leaf verifies against the CA"       yes \
    "$("$OSSL" verify -CAfile ca.pem alpn-chain.pem >/dev/null 2>&1 && echo yes || echo no)"
chk "  and it is for the identifier we ordered" yes \
    "$("$OSSL" x509 -in alpn-chain.pem -noout -text 2>/dev/null | grep -q 'DNS:localhost' && echo yes || echo no)"

echo
echo "=== ACME PREAUTH+ALPN: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
