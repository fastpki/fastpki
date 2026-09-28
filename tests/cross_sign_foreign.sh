#!/usr/bin/env bash
# Cross-signing a FOREIGN CA, with the agreed safety envelope.
#
# The refusals are the point of this suite, not decoration. A cross-certificate without
# name constraints lets the foreign CA certify ANY name under our trust, and one without
# an explicit pathlen lets it mint further CAs. Both are refused rather than defaulted,
# because a default there is a silent grant — and the whole reason cross-signing is an
# explicit operator action is that the grant should never be implicit.
#
# Every refusal is checked for the RIGHT REASON: a command that fails because the id was
# wrong, or the file missing, looks identical to one that fails because the guard fired.
# So each negative case asserts the message names the thing it is refusing.
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

pg_setup cross_sign_foreign
trap 'pg_cleanup' EXIT
hsm_available || { echo "SKIP: CA keys are token-only — $(hsm_skip_reason)"; exit 0; }

# Ours: a real registered CA that will do the vouching.
ca_in_token ours.pem "/CN=Our Issuing CA" 3650 ourca
OUR_KEY="$CA_KEY_URI"
printf 'PG_CONNINFO=%s\n' "$PG_CONNINFO" > bootstrap.conf
hsm_conf_lines >> bootstrap.conf
"$CA" --config bootstrap.conf add ourca --name "Ours" --ca-pem "$W/ours.pem" --ca-key "$OUR_KEY" >/dev/null 2>&1

# Theirs: a foreign root we do NOT control — a plain self-signed CA is exactly that.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout foreign.key -out foreign.pem -days 3650 \
    -subj "/O=Partner Inc/CN=Partner Root CA" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
# And a non-CA, to prove we refuse to hand out CA:TRUE over a leaf's key.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.pem -days 365 \
    -subj "/CN=not-a-ca.partner.example" -addext "basicConstraints=critical,CA:FALSE" >/dev/null 2>&1

xs() { "$CA" --config bootstrap.conf cross-sign ourca --foreign-pem "$W/foreign.pem" "$@" 2>&1; }

echo "=== the envelope is refused, not defaulted ==="
out=$(xs --pathlen 0)
chk "no --permitted is refused" 1 "$([ -n "$out" ] && echo 1 || echo 0)"
chk "  ... and the message says why (name constraints)" yes \
    "$(printf '%s' "$out" | grep -qi 'name constraints' && echo yes || echo no)"

out=$(xs --permitted DNS:partner.example)
chk "no --pathlen is refused" 1 "$([ -n "$out" ] && echo 1 || echo 0)"
chk "  ... and the message says why (explicit depth)" yes \
    "$(printf '%s' "$out" | grep -qi 'pathlen' && echo yes || echo no)"

out=$("$CA" --config bootstrap.conf cross-sign ourca --foreign-pem "$W/leaf.pem" \
        --permitted DNS:partner.example --pathlen 0 2>&1)
chk "cross-signing a NON-CA is refused" yes \
    "$(printf '%s' "$out" | grep -qi 'not a CA' && echo yes || echo no)"

echo "=== a real cross-certificate, decoded ==="
xs --permitted DNS:partner.example --pathlen 0 --out-dir "$W" >xs.log 2>&1
chk "cross-sign succeeds with the envelope supplied" yes \
    "$([ -f "$W/ourca-crosssigned.crt" ] && echo yes || echo no)"
if [ -f "$W/ourca-crosssigned.crt" ]; then
    T=$("$OSSL" x509 -in "$W/ourca-crosssigned.crt" -noout -text 2>/dev/null)
    # THEIR subject, OUR issuer — that is what a cross-certificate is.
    chk "subject is the FOREIGN CA's" yes \
        "$(printf '%s' "$T" | grep -A1 'Subject:' | grep -q 'Partner Root CA' && echo yes || echo no)"
    chk "issuer is OURS" yes \
        "$(printf '%s' "$T" | grep 'Issuer:' | grep -q 'Our Issuing CA' && echo yes || echo no)"
    chk "carries the name constraints" yes \
        "$(printf '%s' "$T" | grep -q 'partner.example' && echo yes || echo no)"
    chk "carries pathlen 0" yes \
        "$(printf '%s' "$T" | grep -qi 'pathlen:0' && echo yes || echo no)"
    # The subject DER must be byte-identical to theirs, or it chains to nothing they
    # issued — the same trap the rekey path documents.
    chk "subject DER matches the foreign certificate exactly" yes \
        "$([ "$("$OSSL" x509 -in "$W/ourca-crosssigned.crt" -noout -subject -nameopt RFC2253)" \
           = "$("$OSSL" x509 -in "$W/foreign.pem" -noout -subject -nameopt RFC2253)" ] \
           && echo yes || echo no)"
    chk "it verifies against OUR CA" yes \
        "$("$OSSL" verify -CAfile "$W/ours.pem" -partial_chain "$W/ourca-crosssigned.crt" \
           >/dev/null 2>&1 && echo yes || echo no)"
fi

echo
echo "=== CROSS-SIGN FOREIGN: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
