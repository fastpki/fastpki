#!/usr/bin/env bash
# certgen.sh must write the PKCS#11 PIN file on EVERY run, including the runs where it
# decides the transport certificate needs no work.
#
# ── The outage this comes from ───────────────────────────────────────────────────
#
# `deploy/certgen.sh` has two "nothing to do" exits — a CA-issued Postgres certificate is
# already in place (the console owns it), or the self-signed one is still valid. The PIN
# file was written at the END of the script, after both of them.
#
# On the lab, once a CA-issued Postgres certificate had been installed, certgen
# took the first exit on every subsequent deploy and `/var/pki/tls/pin` was never written
# again. Every `*_KEY` in the shipped config names it as `pin-source`, so no service could
# mint a token key:
#
#     CMP: could not mint the RA key: pkcs11 keygen params (uri/bits/group) rejected:
#          error:80000002:system library::No such file or directory
#
# That is the "est-tls and cmp-ra keys were missing in token" failure. The keys that did
# exist (acme, ms, web) had been minted before it took over. Nothing announced the
# cause: the symptom is a BIO error from OpenSSL, several layers away, and only for the
# key ids created after the change.
#
# The PIN has nothing to do with any certificate. It is coupled to them only by position
# in the file, which is exactly the kind of coupling a test should pin down.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
CG="$ROOT/deploy/certgen.sh"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

[ -f "$CG" ] || { echo "  [SKIP] no deploy/certgen.sh"; echo "=== CERTGEN PIN: PASS=0 FAIL=0 SKIP=1 ==="; exit 0; }

echo "=== the PIN write precedes every early exit ==="
# Line numbers, because this is a question about ORDER and nothing else can answer it.
PIN_LINE=$(grep -n '> */var/pki/tls/pin' "$CG" | head -1 | cut -d: -f1)
chk "certgen writes the PIN file" yes "$([ -n "$PIN_LINE" ] && echo yes || echo no)"
[ -n "$PIN_LINE" ] || { echo "=== CERTGEN PIN: PASS=$pass FAIL=$((fail+1)) ==="; exit 1; }

BAD=""
for L in $(grep -n '^[[:space:]]*exit 0' "$CG" | cut -d: -f1); do
    [ "$L" -lt "$PIN_LINE" ] && BAD="$BAD $L"
done
chk "no 'exit 0' comes before it" "" "$(echo $BAD)"

echo "=== and it survives the paths that take those exits ==="
# Run the real script against a fake root for each shape. It runs as root in the image
# and writes to absolute paths, so drive it through a container-less stand-in: a copy
# with /var/pki rewritten to a temp tree. Rewriting the PATH is the only edit — the
# control flow under test is untouched.
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)

run_certgen() {   # <label> — leaves $W/root/var/pki/tls populated per the setup done by caller
    sed -e "s#/var/pki#$W/root/var/pki#g" \
        -e "s#^chown #: chown #" -e "s#^ *chown #: chown #" \
        -e "s#chown fastpki#: chown fastpki#" \
        "$CG" > "$W/cg.sh"
    ( cd "$W" && FASTPKI_PIN=s3cr3t PKI_DNS=pki.test sh "$W/cg.sh" >"$W/$1.log" 2>&1 )
    return 0
}

# 1. Fresh: nothing exists. The full path runs.
rm -rf "$W/root"; mkdir -p "$W/root/var/pki/tls/pg"
run_certgen fresh
chk "fresh deploy writes the PIN" "s3cr3t" "$(cat "$W/root/var/pki/tls/pin" 2>/dev/null)"

# 2. A CA-ISSUED Postgres cert is present — the exit that broke the lab. Build a real
#    two-cert chain so is_self_signed() answers no for the right reason.
rm -rf "$W/root"; mkdir -p "$W/root/var/pki/tls/pg"
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout "$W/ca.key" -out "$W/ca.crt" -days 30 \
    -subj "/CN=Test Root" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout "$W/root/var/pki/tls/pg/server.key" \
    -out "$W/s.csr" -subj "/CN=postgres" >/dev/null 2>&1
"$OSSL" x509 -req -in "$W/s.csr" -CA "$W/ca.crt" -CAkey "$W/ca.key" -CAcreateserial \
    -days 30 -out "$W/root/var/pki/tls/pg/server.crt" >/dev/null 2>&1
run_certgen caissued
chk "it took the CA-issued-cert exit" yes \
    "$(grep -q "phase 2, the console, owns it" "$W/caissued.log" && echo yes || echo no)"
chk "and STILL wrote the PIN" "s3cr3t" "$(cat "$W/root/var/pki/tls/pin" 2>/dev/null)"

# 3. A still-valid self-signed cert — the other exit.
rm -rf "$W/root"; mkdir -p "$W/root/var/pki/tls/pg"
run_certgen seed1 >/dev/null 2>&1        # generate a valid self-signed pair
rm -f "$W/root/var/pki/tls/pin"          # then remove the PIN, as a redeploy would find it
run_certgen selfsigned
chk "it took the already-valid exit" yes \
    "$(grep -q "already valid" "$W/selfsigned.log" && echo yes || echo no)"
chk "and STILL wrote the PIN" "s3cr3t" "$(cat "$W/root/var/pki/tls/pin" 2>/dev/null)"

# 4. The freshness gate decides re-issue, and it has to be right in BOTH directions.
#
# ⚠️ A GATE THAT NEVER SKIPS AND A GATE THAT NEVER FIRES ARE BOTH SILENT. Neither breaks a
# deployment loudly: one re-issues the Postgres certificate on every `compose up` and every
# pod start, churning the anchor pg/ca.crt that every app and every replication peer
# verifies against; the other reports "already valid" while a newly added PG_TLS_SANS
# address never reaches the certificate, and the failure then appears at the FAR end as a
# verify error naming a host this side considers perfectly configured. Both shipped: the
# first because `openssl x509 -text` prints `IP Address:` where the -addext input spelling
# is `IP:`, the second because a `while read` fed by a pipeline cannot fail its caller.
echo "=== the freshness gate skips when nothing changed, and re-issues when it did ==="
rm -rf "$W/root"; mkdir -p "$W/root/var/pki/tls/pg"
run_certgen gate1 >/dev/null 2>&1
chk "a first run generates"            yes \
    "$(grep -q 'generated self-signed' "$W/gate1.log" && echo yes || echo no)"
chmod 600 "$W/root/var/pki/tls/pin" 2>/dev/null || true
run_certgen gate2
chk "  an unchanged re-run SKIPS"      yes \
    "$(grep -q 'already valid' "$W/gate2.log" && echo yes || echo no)"
chmod 600 "$W/root/var/pki/tls/pin" 2>/dev/null || true
( export PG_TLS_SANS=10.9.9.9; run_certgen gate3 )
chk "  adding a SAN re-issues"         yes \
    "$(grep -q 'generated self-signed' "$W/gate3.log" && echo yes || echo no)"
chk "  and the new address is IN the certificate" yes \
    "$("$OSSL" x509 -in "$W/root/var/pki/tls/pg/server.crt" -noout -text 2>/dev/null \
       | grep -q '10\.9\.9\.9' && echo yes || echo no)"

echo
echo "=== CERTGEN PIN: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
