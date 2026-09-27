#!/usr/bin/env bash
# Browser PKCS#12 export — the JS-P12 slice. The console can bundle
# an issued cert + the browser-generated key into one password-protected .p12,
# built entirely client-side (PBES2-shrouded key bag + cleartext cert bag +
# traditional RFC 7292 PKCS#12 MAC over HMAC-SHA-256). This guards that builder by
# running the ACTUAL shipped code (extracted from src/web/main.cpp between the
# BUILDER sentinels) under Node's WebCrypto and proving openssl imports the
# result: MAC verifies with the password (and fails with a wrong one), and the
# extracted key matches the cert. Needs only node + openssl -> CORE tier.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
NODE=$(command -v node || true)
SRC="$ROOT/src/web/main.cpp"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
PW='P12-secret_123'
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

if [ -z "$NODE" ]; then echo "SKIP: node not found (browser PKCS#12 unit test needs Node WebCrypto)"; exit 0; fi

# 1. browser: EC P-384 keypair + CSR (writes the plaintext key too)
"$NODE" "$ROOT/tests/web_p12.mjs" "$SRC" csr "$W/leaf.csr" "$W/leaf.key.pem" 2>"$W/n1.err" \
  || { echo "csr mode failed:"; cat "$W/n1.err"; exit 1; }

# 2. a throwaway CA signs the CSR into a leaf cert
ca_in_token "$W/ca.pem" "/CN=P12 CA" 3
"$OSSL" x509 -req -in "$W/leaf.csr" -CA "$W/ca.pem" -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS -days 1 -out "$W/leaf.pem" >/dev/null 2>&1
chk "leaf cert signed" yes "$([ -s "$W/leaf.pem" ] && echo yes || echo no)"

# 3. browser: bundle leaf + key into a password-protected .p12
"$NODE" "$ROOT/tests/web_p12.mjs" "$SRC" p12 "$W/leaf.pem" "$W/leaf.key.pem" "$PW" "p12.internal" "$W/out.p12" 2>"$W/n2.err" \
  || { echo "p12 mode failed:"; cat "$W/n2.err"; exit 1; }
chk "p12 emitted (non-empty DER)" yes "$([ -s "$W/out.p12" ] && echo yes || echo no)"
chk "p12 parses as a PFX (asn1)" yes "$("$OSSL" asn1parse -in "$W/out.p12" -inform DER >/dev/null 2>&1 && echo yes || echo no)"

echo "=== openssl imports the .p12 and verifies the MAC with the password ==="
INFO=$("$OSSL" pkcs12 -in "$W/out.p12" -passin pass:"$PW" -info -nodes -out "$W/dump.pem" 2>&1)
chk "MAC verified / import ok"        yes "$([ $? -eq 0 ] && echo yes || echo no)"
chk "reports the SHA-256 PKCS#12 MAC" yes "$(echo "$INFO" | grep -qi 'MAC: *sha256' && echo yes || echo no)"
chk "dump carries the private key"    yes "$(grep -q 'PRIVATE KEY' "$W/dump.pem" 2>/dev/null && echo yes || echo no)"
chk "dump carries the certificate"    yes "$(grep -q 'BEGIN CERTIFICATE' "$W/dump.pem" 2>/dev/null && echo yes || echo no)"

echo "=== the wrong password is rejected (MAC verify fails) ==="
chk "wrong password -> failure" yes "$("$OSSL" pkcs12 -in "$W/out.p12" -passin pass:nope -info -nodes >/dev/null 2>&1 && echo no || echo yes)"

echo "=== the packaged key matches the packaged certificate ==="
"$OSSL" pkcs12 -in "$W/out.p12" -passin pass:"$PW" -nokeys  -out "$W/c.pem" >/dev/null 2>&1
"$OSSL" pkcs12 -in "$W/out.p12" -passin pass:"$PW" -nocerts -nodes -out "$W/k.pem" >/dev/null 2>&1
CPUB=$("$OSSL" x509 -in "$W/c.pem" -noout -pubkey 2>/dev/null)
KPUB=$("$OSSL" pkey -in "$W/k.pem" -pubout 2>/dev/null)
chk "cert public key == key public key" yes "$([ -n "$CPUB" ] && [ "$CPUB" = "$KPUB" ] && echo yes || echo no)"
# With -out, openssl writes the per-bag attribute headers (friendlyName/localKeyID)
# into the dump file, not to stdout — assert against the file.
chk "friendlyName preserved"            yes "$(grep -qi 'friendlyName: *p12.internal' "$W/dump.pem" 2>/dev/null && echo yes || echo no)"
chk "localKeyID pairs key and cert"     yes "$([ "$(grep -ci 'localKeyID' "$W/dump.pem" 2>/dev/null)" -ge 2 ] && echo yes || echo no)"

echo
echo "=== WEB P12: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
