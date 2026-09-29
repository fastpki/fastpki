#!/usr/bin/env bash
# EST server-side key generation (RFC 7030 §4.4) + reenroll semantics (§4.2.2).
#  - /serverkeygen: server generates the key, issues, returns multipart/mixed
#    { application/pkcs8 private key, application/pkcs7-mime certs-only }; the
#    returned key must match the issued cert. Off by default -> 404 when disabled.
#  - /simplereenroll: renews an existing subject; a subject with no active cert
#    is refused (403).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"   # real credentials, not AUTH_BACKEND=none
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
W="$(mktemp -d)"; cd "$W"; PORT=18464; PORT2=18465
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=SKG CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3650 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup est_serverkeygen
# AUTH_BACKEND=none is gone, so this suite authenticates for real.
seed_web_user u p requester
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$PORT
EST_SERVERKEYGEN=true
EST_SERVERKEYGEN_BITS=2048
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-est" --config bootstrap.conf >srv.log 2>&1 & P=$!
# a second server WITHOUT serverkeygen to prove the route is opt-in
sed "s/EST_PORT=$PORT/EST_PORT=$PORT2/;s/EST_SERVERKEYGEN=true/EST_SERVERKEYGEN=false/" bootstrap.conf > off.conf
"$ROOT/build/fastpki-est" --config off.conf >off.log 2>&1 & P2=$!
# a third server with encryption DISABLED (plaintext PKCS#8)
PORT3=18468
sed "s/EST_PORT=$PORT/EST_PORT=$PORT3/" bootstrap.conf > plain.conf
echo "EST_SERVERKEYGEN_ENCRYPT=false" >> plain.conf
"$ROOT/build/fastpki-est" --config plain.conf >plain.log 2>&1 & P3=$!
sleep 1; trap 'pg_cleanup; kill $P $P2 $P3 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-est died:"; cat srv.log; exit 1; fi
BASE="https://127.0.0.1:$PORT/.well-known/est/ca"

# The CSR is signed by csr.key; the encrypted reply is decrypted with that key.
"$OSSL" req -new -subj "/CN=skg.internal" -newkey rsa:2048 -nodes -keyout csr.key -out c.csr >/dev/null 2>&1
"$OSSL" req -in c.csr -outform DER | "$OSSL" base64 > c.b64
parts() { tr -d '\r' < "$1" | grep -E '^[A-Za-z0-9+/=]{40,}$'; }

echo "=== /serverkeygen (default): key is ENCRYPTED to the CSR key + never stored ==="
curl -sk -u u:p --data-binary @c.b64 -H "Content-Type: application/pkcs10" "$BASE/serverkeygen" -o resp.txt
# Portable array collection (bash 3 compat — no mapfile)
B64=(); while IFS= read -r _b; do B64+=("$_b"); done < <(parts resp.txt)
chk "response has two base64 parts (key + cert)" 2 "${#B64[@]}"
chk "key part is CMS (server-generated-key), not plaintext pkcs8" yes \
    "$(tr -d '\r' < resp.txt | grep -qi 'smime-type=server-generated-key' && echo yes || echo no)"
chk "no plaintext application/pkcs8 part" 0 "$(tr -d '\r' < resp.txt | grep -c 'Content-Type: application/pkcs8')"
# decrypt the CMS EnvelopedData with the CSR private key -> PKCS#8
printf '%s' "${B64[0]:-}" | "$OSSL" base64 -d -A > enc.der 2>/dev/null
"$OSSL" cms -decrypt -inform DER -in enc.der -inkey csr.key -out key.der -binary >/dev/null 2>&1 && dok=ok || dok=bad
chk "client decrypts the key with its CSR key" ok "$dok"
"$OSSL" pkey -inform DER -in key.der -pubout -out keypub.pem >/dev/null 2>&1
printf '%s' "${B64[1]:-}" | "$OSSL" base64 -d -A | "$OSSL" pkcs7 -inform DER -print_certs -out cert.pem >/dev/null 2>&1
CN=$("$OSSL" x509 -in cert.pem -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')
chk "issued cert CN = skg.internal" "skg.internal" "${CN:-none}"
"$OSSL" x509 -in cert.pem -pubkey -noout > certpub.pem 2>/dev/null
if diff -q keypub.pem certpub.pem >/dev/null 2>&1; then m=match; else m=nomatch; fi
chk "the decrypted server-generated key matches the issued cert" match "$m"
chk "issued cert persisted" 1 "$(pg_exec "SELECT COUNT(*) FROM certs WHERE cn='skg.internal';")"
# the private key must NEVER be stored. The stored blob is the CERTIFICATE...
pg_exec "SELECT encode(cert, 'hex') FROM certs WHERE cn='skg.internal';" | xxd -r -p 2>/dev/null \
    | "$OSSL" x509 -inform DER -noout >/dev/null 2>&1 && sc=cert || sc=other
chk "stored artifact is the issued certificate, not a key" cert "$sc"
# ...and the generated private key's bytes appear nowhere in the cert blob.
# (Postgres: compare the cert DER — it must NOT be a private key.)
ks_cert=$("$OSSL" pkey -inform DER -in <(pg_exec "SELECT encode(cert,'hex') FROM certs WHERE cn='skg.internal';" | xxd -r -p) -pubout >/dev/null 2>&1 && echo key || echo cert)
chk "stored artifact is a certificate, not a private key" cert "$ks_cert"

echo "=== /serverkeygen with encryption disabled -> plaintext application/pkcs8 ==="
curl -sk -u u:p --data-binary @c.b64 -H "Content-Type: application/pkcs10" \
    "https://127.0.0.1:$PORT3/.well-known/est/ca/serverkeygen" -o presp.txt
chk "plaintext mode advertises application/pkcs8" 1 "$(tr -d '\r' < presp.txt | grep -c 'Content-Type: application/pkcs8')"
PB64=(); while IFS= read -r _b; do PB64+=("$_b"); done < <(parts presp.txt)
printf '%s' "${PB64[0]:-}" | "$OSSL" base64 -d -A | "$OSSL" pkey -inform DER -pubout >/dev/null 2>&1 && pok=ok || pok=bad
chk "plaintext part 1 is a usable private key" ok "$pok"

echo "=== /serverkeygen is opt-in (404 when disabled) ==="
CODE=$(curl -sk -o /dev/null -w '%{http_code}' -u u:p --data-binary @c.b64 \
    -H "Content-Type: application/pkcs10" "https://127.0.0.1:$PORT2/.well-known/est/ca/serverkeygen")
chk "disabled server -> 404" 404 "$CODE"

echo "=== /simplereenroll semantics (RFC 7030 §4.2.2) ==="
enroll_code() { # endpoint CN -> http_code
    "$OSSL" req -new -subj "/CN=$2" -newkey rsa:2048 -nodes -keyout k.key -out r.csr >/dev/null 2>&1
    "$OSSL" req -in r.csr -outform DER | "$OSSL" base64 > r.b64
    curl -sk -o /dev/null -w '%{http_code}' -u u:p --data-binary @r.b64 \
        -H "Content-Type: application/pkcs10" "$BASE/$1"
}
chk "initial simpleenroll host.internal -> 200"      200 "$(enroll_code simpleenroll host.internal)"
chk "simplereenroll same subject -> 200 (renew)"     200 "$(enroll_code simplereenroll host.internal)"
chk "simplereenroll a never-enrolled subject -> 403" 403 "$(enroll_code simplereenroll fresh.internal)"

echo
echo "=== EST SERVERKEYGEN + REENROLL: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
