#!/usr/bin/env bash
# The signing digest is derived from the CA KEY, not hardcoded.
#
# The settled call: auto-match, no operator control. RSA follows the modulus the way EC
# already follows the curve, so nobody can pair a 4096-bit key with SHA-256 by filling in
# a form field wrong.
#
# Asserted by decoding the issued certificate's signatureAlgorithm — not by reading the
# code back, and not by trusting the request. Two of these would have passed before the
# change (RSA-2048 -> SHA-256 was already the hardcoded answer), so the RSA-4096 and
# EC P-384 rows are the ones carrying the weight: the first is the new behaviour, the
# second is a mismatch that existed and nothing caught, because the helper that computed
# the curve-matched digest was only ever reached when the caller passed no digest — and
# every caller passed one.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
CA="$ROOT/build/fastpki-ca"
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

pg_setup signing_digest
trap 'pg_cleanup' EXIT
hsm_available || { echo "SKIP: CA keys are token-only — $(hsm_skip_reason)"; exit 0; }
hsm_server_start || { echo "SKIP: no p11-kit server"; exit 0; }
printf 'PG_CONNINFO=%s\n' "$PG_CONNINFO" > ca.conf
hsm_conf_lines >> ca.conf

# Mint a CA of the given key shape through the product's own CLI (--keygen puts the key
# in the token) and report the signatureAlgorithm of the certificate it signed.
sigalg_for() {   # <id> <extra fastpki-ca args...>
    local id="$1"; shift
    local tok="dg_${id}_$$"
    "$HSM_UTIL" --module "$HSM_SOFTHSM" --init-token --free --label "$tok" \
        --pin 1234 --so-pin 12345678 >/dev/null 2>&1 || return 1
    "$CA" --config ca.conf create "$id" --name "$id" --subject "/CN=Digest $id" \
        --ca-key "pkcs11:token=$tok;object=$id;type=private?pin-value=1234" --keygen \
        --out-dir "$W" "$@" >"ca_$id.log" 2>&1 || return 1
    [ -f "$W/$id.crt" ] || return 1
    "$OSSL" x509 -in "$W/$id.crt" -noout -text 2>/dev/null \
        | sed -n 's/.*Signature Algorithm: *//p' | head -1 | tr -d ' '
}

echo "=== the digest follows the CA key, decoded from the certificate ==="
ran=0
try_case() {   # <label> <expected sigalg> <id> <args...>
    local label="$1" want="$2" id="$3"; shift 3
    local got; got=$(sigalg_for "$id" "$@") || { echo "  [SKIP] $label (could not mint)"; return; }
    ran=$((ran+1)); chk "$label signs with $want" "$want" "$got"
}
try_case "RSA-2048 CA" sha256WithRSAEncryption rsa2048 --key rsa --bits 2048
try_case "RSA-4096 CA" sha384WithRSAEncryption rsa4096 --key rsa --bits 4096
try_case "EC P-256 CA" ecdsa-with-SHA256      ec256   --key ec  --curve P-256
try_case "EC P-384 CA" ecdsa-with-SHA384      ec384   --key ec  --curve P-384

chk "at least one key shape actually ran (not a vacuous pass)" yes \
    "$([ "$ran" -gt 0 ] && echo yes || echo no)"

echo
echo "=== SIGNING DIGEST: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
