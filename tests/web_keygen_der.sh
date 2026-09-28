#!/usr/bin/env bash
# Browser CSR builder — full-attribute request form. The console's
# "Generate a certificate for a hostname" form hand-builds a PKCS#10 CSR in the
# browser (Web Crypto). This guards that hand-rolled DER by running the ACTUAL
# shipped builder (extracted verbatim from src/web/main.cpp between the
# BUILDER sentinels) under Node's WebCrypto, then decoding the emitted CSRs
# with openssl to prove: (1) each self-signature verifies, (2) the full RFC 5280
# subject DN (CN/O/OU/C/ST/L/emailAddress) is present, (3) every SAN kind
# (DNS/IPv4/IPv6/rfc822/URI) is encoded, (4) each key type — EC P-256/384/521,
# Ed25519, RSA-2048/3072/4096 (PKCS#1 v1.5), RSA-PSS-2048/3072/4096 (RFC 4055 §3)
# — round-trips, and (5) the PBES2-encrypted key
# decrypts. Needs only node + openssl (no server bind) -> CORE tier.
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
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fi; [ "$2" = "$3" ] || fail=$((fail+1)); }

if [ -z "$NODE" ]; then echo "SKIP: node not found (browser CSR builder unit test needs Node WebCrypto)"; exit 0; fi

MAN=$("$NODE" "$ROOT/tests/web_keygen_der.mjs" "$SRC" "$W" 2>"$W/node.err")
if [ $? -ne 0 ] || [ -z "$MAN" ]; then echo "harness failed:"; cat "$W/node.err"; exit 1; fi
echo "manifest: $MAN"

txt(){ "$OSSL" req -in "$1" -noout -text -verify 2>&1; }
yn(){ [ -n "$1" ] && echo yes || echo no; }

echo "=== full subject DN + every SAN kind (EC P-384 case) ==="
T=$(txt "$W/EC384.csr.pem")
chk "CSR self-signature verifies"       yes "$(echo "$T" | grep -qi 'verify OK' && echo yes)"
for pair in 'CN=svc.internal' 'O=Example Ltd' 'OU=Platform' 'C=US' 'ST=California' 'L=San Francisco' 'emailAddress=admin@example.org'; do
  chk "subject has $pair" yes "$(echo "$T" | grep -q "Subject:.*$pair" && echo yes)"
done
SAN=$(echo "$T" | grep -A1 'Subject Alternative Name' | tail -1)
chk "SAN has DNS"   yes "$(echo "$SAN" | grep -q 'DNS:svc.internal' && echo yes)"
chk "SAN has IPv4"  yes "$(echo "$SAN" | grep -q 'IP Address:10.0.0.5' && echo yes)"
chk "SAN has IPv6"  yes "$(echo "$SAN" | grep -qi 'IP Address:2001:DB8' && echo yes)"
chk "SAN has email" yes "$(echo "$SAN" | grep -q 'email:admin@example.org' && echo yes)"
chk "SAN has URI"   yes "$(echo "$SAN" | grep -q 'URI:spiffe://example.org' && echo yes)"

echo "=== every key type verifies with the right algorithm ==="
declare -a CASES=(
  "EC256|id-ecPublicKey|P-256|ecdsa-with-SHA256"
  "EC384|id-ecPublicKey|P-384|ecdsa-with-SHA384"
  "EC521|id-ecPublicKey|P-521|ecdsa-with-SHA512"
  "ED25519|ED25519||ED25519"
  "RSA2048|rsaEncryption|2048 bit|sha256WithRSAEncryption"
  "RSA3072|rsaEncryption|3072 bit|sha256WithRSAEncryption"
  "RSA4096|rsaEncryption|4096 bit|sha256WithRSAEncryption"
  "RSA-PSS2048|id-RSASSA-PSS|2048 bit|id-RSASSA-PSS"
  "RSA-PSS3072|id-RSASSA-PSS|3072 bit|id-RSASSA-PSS"
  "RSA-PSS4096|id-RSASSA-PSS|4096 bit|id-RSASSA-PSS"
)
for c in "${CASES[@]}"; do
  IFS='|' read -r kt _alg curve sig <<<"$c"
  f="$W/$kt.csr.pem"
  if [ ! -s "$f" ]; then chk "$kt CSR emitted" yes ""; continue; fi
  T=$(txt "$f")
  chk "$kt verifies"        yes "$(echo "$T" | grep -qi 'verify OK' && echo yes)"
  # OpenSSL spells the RSA-PSS algorithm differently by version — "id-RSASSA-PSS"
  # up to 3.5, "rsassaPss" from 3.6 — so match either. The OID is identical; only
  # the display string moved, and pinning one spelling fails on half the toolchains.
  sigre="$sig"
  [ "$sig" = "id-RSASSA-PSS" ] && sigre="(id-RSASSA-PSS|rsassaPss)"
  chk "$kt sig = $sig"      yes "$(echo "$T" | grep -qiE "Signature Algorithm: $sigre" && echo yes)"
  [ -n "$curve" ] && chk "$kt key marker '$curve'" yes "$(echo "$T" | grep -qi "$curve" && echo yes)"
done

echo "=== PBES2-encrypted private key decrypts under openssl ==="
if [ -s "$W/EC384.key.enc.pem" ]; then
  # </dev/null so a failed decrypt FAILS instead of falling back to prompting. Without
  # it openssl reaches for a console, and under run_all.sh there is none — the error then
  # reads "UI routines:open_console:unknown ttyget", which describes the terminal rather
  # than the key and sends you looking in the wrong place. (It cost exactly that here.)
  D=$("$OSSL" pkey -in "$W/EC384.key.enc.pem" -passin pass:demo-pass-123 -noout -text </dev/null 2>&1)
  chk "decrypts with the passphrase"     yes "$(echo "$D" | grep -qi 'Private-Key' && echo yes)"
  # If it did not decrypt, say WHY here and keep the artefact. This assertion failed six
  # times in a row and then passed 15 times with no change to the builder or
  # the binary, and the cause was lost each time because all the failure said was
  # "expected 'yes' got ''". The openssl error turned out to be a UI/ttyget one — openssl
  # PROMPTING, i.e. the supplied passphrase did not open the file — which is a fact about
  # the encryption, not about the test. Next occurrence should arrive with the evidence.
  if ! echo "$D" | grep -qi 'Private-Key'; then
      echo "    openssl said: $(echo "$D" | head -2 | tr '\n' ' ')"
      cp "$W/EC384.key.enc.pem" "${TMPDIR:-/tmp}/fastpki-pbes2-failed-$$.pem" 2>/dev/null &&
        echo "    kept the artefact at ${TMPDIR:-/tmp}/fastpki-pbes2-failed-$$.pem"
      echo "    PBES2 params: $("$OSSL" asn1parse -in "$W/EC384.key.enc.pem" 2>/dev/null |
                                 grep -oE ':(PBES2|PBKDF2|hmacWith[A-Za-z0-9]+|aes-[0-9]+-cbc)' |
                                 tr -d ':' | tr '\n' ' ')"
  fi
  chk "wrong passphrase is rejected"     yes "$("$OSSL" pkey -in "$W/EC384.key.enc.pem" -passin pass:wrong -noout 2>&1 | grep -qi 'bad decrypt\|error\|could not' && echo yes)"
fi

echo "=== Requested KeyUsage / ExtKeyUsage / otherName SANs encode in the CSR ==="
E=$(txt "$W/EXT.csr.pem")
chk "EXT CSR verifies"                 yes "$(echo "$E" | grep -qi 'verify OK' && echo yes)"
chk "KeyUsage: Digital Signature"      yes "$(echo "$E" | grep -q 'Digital Signature' && echo yes)"
chk "KeyUsage: Key Encipherment"       yes "$(echo "$E" | grep -q 'Key Encipherment' && echo yes)"
chk "EKU: TLS Web Server Auth"         yes "$(echo "$E" | grep -q 'TLS Web Server Authentication' && echo yes)"
chk "EKU: TLS Web Client Auth"         yes "$(echo "$E" | grep -q 'TLS Web Client Authentication' && echo yes)"
chk "EKU: custom OID present"          yes "$(echo "$E" | grep -qE 'SSH Client|1\.3\.6\.1\.5\.5\.7\.3\.21' && echo yes)"
chk "otherName UPN encoded"            yes "$(echo "$E" | grep -qi 'UPN:alice@corp.example' && echo yes)"
chk "otherName generic OID encoded"    yes "$(echo "$E" | grep -q '1.3.6.1.4.1.99999.1:custom-value' && echo yes)"

echo
echo "=== WEB KEYGEN DER: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
