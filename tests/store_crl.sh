#!/usr/bin/env bash
# Regression: RFC 4387 store GET /crls/search serves the CA CRL.
# Insert a revoked cert, fetch the CRL from fastpki-store, and assert it is valid
# (CA-signed) and lists the revoked serial. (Previously /crls/search returned 501.)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/x509_der.sh"
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
W="$(mktemp -d)"; cd "$W"; PORT=18102
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Store CRL CA" 3650
cp ca.pem root.pem
# one revoked leaf
"$OSSL" req -newkey rsa:2048 -nodes -keyout r.key -out r.csr -subj "/CN=revoked.internal" >/dev/null 2>&1
"$OSSL" x509 -req -in r.csr -CA ca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS -CAcreateserial -days 365 -out r.pem >/dev/null 2>&1
pg_setup store_crl
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
# NOTE: the ca_instances INSERT that used to sit here is gone. That table was dropped --
# a CA is a row of `certs` with is_ca now -- so the statement had been failing silently
# (pg_exec does not check psql's exit status, and nothing here did either). The suite
# passed regardless because seed_ca_from_conf does the real registration. Left in place
# it reads like the thing that seeds the CA, which is exactly how the next person loses
# an afternoon.
NB=$(date +%s); NA=$((NB+31536000))
SER=$("$OSSL" x509 -in r.pem -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
DER=$("$OSSL" x509 -in r.pem -outform DER | xxd -p | tr -d '\n')
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cert,cn,fingerprint,ca_instance_id) VALUES('$SER',-1,1,$NB,$NB,$NA,'CN=revoked','t','\x$DER'::bytea,'revoked.internal','','ca-global');"

cat > store.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
STORE_BIND=127.0.0.1
STORE_PORT=$PORT
LOG_LEVEL=err
EOF
seed_ca_from_conf store.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-store" --config store.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-store died:"; cat srv.log; exit 1; fi

# No default CA — the store requires an RFC 4387 selector (iHash) to name the CA
# whose CRL to serve. iHash = SHA-1 of the DER-encoded issuer (CA subject) Name.
# Field 1 of x509_selectors is SHA-1 over the DER subject Name, which for the CA
# IS the issuer Name every CRL from it carries. Reusing the one implementation
# rather than writing a second: two ways to compute the same hash is how they
# drift, and the drift would look like a server bug.
IHASH=$(x509_selectors "$W/ca.pem" | cut -d' ' -f1)
echo "=== GET /crls/search?iHash=<ca> ==="
code=$(curl -s -o crl.der -w "%{http_code}" "http://127.0.0.1:$PORT/crls/search?iHash=$IHASH")
chk "HTTP 200" 200 "$code"
"$OSSL" crl -inform DER -in crl.der -noout -CAfile ca.pem >/dev/null 2>&1 && v=ok || v=bad
chk "CRL signature valid (signed by CA)" ok "$v"
LIST=$("$OSSL" crl -inform DER -in crl.der -noout -text 2>/dev/null | grep -A1 "Serial Number" | tr 'A-F' 'a-f' | tr -d ' :')
echo "$LIST" | grep -qi "$SER" && f=yes || f=no
chk "revoked serial listed in CRL" yes "$f"

echo "=== RFC 4387 §3 CRL selectors (\"iHash\") ==="
CODE(){ curl -s -o /dev/null -w '%{http_code}' "$1"; }
U="http://127.0.0.1:$PORT/crls/search"
    # No interpreter guard any more: the selector is computed in shell, so these two
    # assertions run everywhere instead of skipping on a machine without python.
    IHASH=$(x509_selectors "$W/ca.pem" | cut -d' ' -f1)
    chk "matching \"iHash\" -> 200"        200 "$(CODE "$U?"iHash"=$IHASH")"
    chk "wrong \"iHash\" -> 404"           404 "$(CODE "$U?"iHash"=deadbeef")"
chk "unknown CRL attribute -> 400"    400 "$(CODE "$U?bogus=x")"
chk "no selector -> 400 (must name a CA)"  400 "$(CODE "$U")"

echo "=== ⚠️ A PEER SERVES A REPLICATED CRL FOR A CA IT CANNOT SIGN FOR ==="
# This is the whole reason a signed CRL is stored and replicated: when the node holding a
# CA's key goes down, its peers must still answer for that CA. A peer is exactly a node where
# resolve_ca_instance() finds no local key — and it therefore marks the CA INACTIVE, so
# CaMaterialCache::get() FAILS. The stored-CRL fallback sat below that failure and could
# never run: a node with valid, unexpired CRL bytes in its own database answered "revocation
# status cannot be determined" while they sat there.
#
# Simulated the way the product sees it: point the CA row's key at a handle this node does
# not have, which is precisely what a mesh peer's row looks like.
STORED=$(curl -s "$U?iHash=$IHASH" --output - | wc -c | tr -d ' ')
chk "PRECONDITION: the CRL is served while the key is here" yes \
    "$([ "${STORED:-0}" -gt 0 ] && echo yes || echo no)"
# Publish it, so there is something for a peer to serve.
chk "  and it was stored for the peers"      1 \
    "$(pg_exec "SELECT count(*) FROM crls WHERE ca_id='ca-global' AND NOT is_delta;" | tr -d ' ')"

pg_exec "UPDATE certs SET private_key='pkcs11:token=nosuchtoken;object=nope;type=private'
         WHERE id='ca-global' AND is_ca;" >/dev/null
kill $P 2>/dev/null; wait $P 2>/dev/null
# The fallback announces itself at info — which every shipped config sets, though the
# compiled default is err and the rest of this suite runs at err on purpose. Asserting a
# line the daemon was configured not to print would be a test that can only fail.
sed 's/^LOG_LEVEL=.*/LOG_LEVEL=info/' store.conf > peer.conf
"$ROOT/build/fastpki-store" --config peer.conf >peer.log 2>&1 & P=$!
wait_port "$PORT" "$P" || true
chk "a peer still serves that CA's CRL"      200 "$(CODE "$U?iHash=$IHASH")"
chk "  and the bytes are a real CRL"         yes \
    "$(curl -s "$U?iHash=$IHASH" -o peer.crl && "$OSSL" crl -in peer.crl -inform DER -noout \
       >/dev/null 2>&1 && echo yes || echo no)"
chk "  and it says why it fell back"         yes \
    "$(grep -q 'serving the stored CRL instead' peer.log && echo yes || echo no)"

echo
echo "=== ⚠️ AND A DISABLED CA STILL ANSWERS FOR WHAT IT ALREADY ISSUED ==="
# Disabling a CA stops it ISSUING. It does not retract the certificates already out
# there, and those are exactly the ones whose revocation status a relying party still
# needs — more so after a disable, since one reason to disable a CA is that something
# went wrong with it. The lookup above filtered on ci.status != "active", so a disabled
# CA never resolved to a ca_id and the handler 404d BEFORE the stored-CRL fallback this
# suite just proved could run. "Revoked" silently became "unknown".
pg_exec "UPDATE certs SET ca_enabled=false WHERE id='ca-global' AND is_ca;" >/dev/null
chk "PRECONDITION: the CA now reads as disabled" disabled \
    "$(pg_exec "SELECT CASE WHEN coalesce(ca_enabled,true) THEN 'active' ELSE 'disabled' END
                  FROM certs WHERE id='ca-global' AND is_ca LIMIT 1;" | tr -d ' ')"
kill $P 2>/dev/null; wait $P 2>/dev/null
"$ROOT/build/fastpki-store" --config peer.conf >disabled.log 2>&1 & P=$!
wait_port "$PORT" "$P" || true
chk "a disabled CA still serves its CRL"     200 "$(CODE "$U?iHash=$IHASH")"
chk "  and the bytes are a real CRL"         yes \
    "$(curl -s "$U?iHash=$IHASH" -o disabled.crl && "$OSSL" crl -in disabled.crl -inform DER \
       -noout >/dev/null 2>&1 && echo yes || echo no)"
# The CA it cannot match must still 404, or the assertion above would pass on a server
# that had simply stopped checking which CA was asked for.
chk "  and an unknown iHash is still 404"    404 "$(CODE "$U?iHash=deadbeef")"

echo "=== STORE CRL: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
