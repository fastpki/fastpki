#!/usr/bin/env bash
# PQC readiness. Proves the OpenSSL toolchain we build against
# exposes the post-quantum primitives — ML-DSA (FIPS 204) signatures and ML-KEM
# (FIPS 203) — so the PQC cert work has a working foundation. Does an
# ML-DSA-65 keygen -> sign -> verify -> tamper-reject round-trip, plus a keygen
# spot check of ML-DSA-44/87 and ML-KEM-768.
#
# Self-skips on OpenSSL < 3.5 (the first release with native ML-DSA), so older
# dev boxes stay green; CI (Alpine 3.24 / OpenSSL 3.5.x) runs it for real.
# Busybox-safe (no GNU-only flags) since it executes in the Alpine CI image.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=openssl

VER=$("$OSSL" version 2>/dev/null | awk '{print $2}')
major=$(echo "$VER" | cut -d. -f1); minor=$(echo "$VER" | cut -d. -f2)
case "$major$minor" in ''|*[!0-9]*) major=0; minor=0;; esac
if [ "${major:-0}" -lt 3 ] || { [ "$major" -eq 3 ] && [ "${minor:-0}" -lt 5 ]; }; then
    echo "SKIP: OpenSSL ${VER:-unknown} < 3.5 — no native ML-DSA (PQC features disabled)"; exit 0
fi

W="$(mktemp -d)"; cd "$W"
trap 'rm -rf "$W"' EXIT
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

echo "=== OpenSSL $VER: ML-DSA (FIPS 204) EVP round-trip ==="
printf 'fastpki post-quantum readiness probe\n' > msg.txt

"$OSSL" genpkey -algorithm ML-DSA-65 -out mldsa65.key >/dev/null 2>&1
chk "ML-DSA-65 keygen" 0 "$?"
"$OSSL" pkey -in mldsa65.key -pubout -out mldsa65.pub >/dev/null 2>&1
chk "ML-DSA-65 extract public key" 0 "$?"

# ML-DSA is a pure (non-prehashed) signature -> one-shot DigestSign via -rawin.
"$OSSL" pkeyutl -sign -rawin -inkey mldsa65.key -in msg.txt -out sig.bin >/dev/null 2>&1
chk "ML-DSA-65 sign" 0 "$?"
"$OSSL" pkeyutl -verify -rawin -pubin -inkey mldsa65.pub -sigfile sig.bin -in msg.txt >/dev/null 2>&1
chk "ML-DSA-65 verify (good signature)" 0 "$?"

# Tamper: append a byte so the signature no longer matches; verify MUST reject.
cp sig.bin sigbad.bin; printf '\xAA' >> sigbad.bin
"$OSSL" pkeyutl -verify -rawin -pubin -inkey mldsa65.pub -sigfile sigbad.bin -in msg.txt >/dev/null 2>&1
rc=$?; [ "$rc" -ne 0 ] && t=reject || t=accept
chk "ML-DSA-65 verify rejects tampered signature" reject "$t"

echo "=== SLH-DSA (FIPS 205) EVP round-trip ==="
"$OSSL" genpkey -algorithm SLH-DSA-SHA2-128s -out slhdsa.key >/dev/null 2>&1
chk "SLH-DSA-SHA2-128s keygen" 0 "$?"
"$OSSL" pkey -in slhdsa.key -pubout -out slhdsa.pub >/dev/null 2>&1
chk "SLH-DSA extract public key" 0 "$?"
"$OSSL" pkeyutl -sign -rawin -inkey slhdsa.key -in msg.txt -out slhsig.bin >/dev/null 2>&1
chk "SLH-DSA sign" 0 "$?"
"$OSSL" pkeyutl -verify -rawin -pubin -inkey slhdsa.pub -sigfile slhsig.bin -in msg.txt >/dev/null 2>&1
chk "SLH-DSA verify (good signature)" 0 "$?"
cp slhsig.bin slhbad.bin; printf '\xAA' >> slhbad.bin
"$OSSL" pkeyutl -verify -rawin -pubin -inkey slhdsa.pub -sigfile slhbad.bin -in msg.txt >/dev/null 2>&1
rc=$?; [ "$rc" -ne 0 ] && t=reject || t=accept
chk "SLH-DSA verify rejects tampered signature" reject "$t"

echo "=== algorithm-support matrix: FIPS 204/205/186-5 + FIPS 203 KEM ==="
for alg in ML-DSA-44 ML-DSA-87 SLH-DSA-SHAKE-256f ED25519 ED448 ML-KEM-768; do
    "$OSSL" genpkey -algorithm "$alg" -out "k.key" >/dev/null 2>&1
    chk "$alg keygen" 0 "$?"
done
# classical NIST curves + RSA (FIPS 186-5 / SP 800-56B)
"$OSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out ec.key >/dev/null 2>&1
chk "ECDSA P-384 keygen" 0 "$?"
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out rsa.key >/dev/null 2>&1
chk "RSA-3072 keygen" 0 "$?"

echo
echo "=== PQC: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
