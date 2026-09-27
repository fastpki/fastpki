#!/usr/bin/env bash
# The trust anchor comes from the DATABASE, not ROOT_CA_PEM.
#
# A root is a row of `certs` like any other CA certificate, so a service can
# walk from an issuing CA up to its root instead of being handed a file path. This proves
# the walk, because nothing else does: every other EST suite builds a SELF-SIGNED CA, and
# against one of those the ancestor walk correctly returns nothing — so those suites pass
# whether the walk works or does nothing at all. Only a real two-level hierarchy tells
# them apart.
#
# Asserted here:
#   1. /cacerts for a SUB-CA returns the sub AND its root (the walk found the parent).
#   2. /cacerts for the ROOT returns exactly one certificate — a self-signed CA's subject
#      hash IS its issuer hash, so an unguarded walk matches itself and either duplicates
#      the root forever or never terminates.
#   3. No service config names ROOT_CA_PEM.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
EST="$ROOT/build/fastpki-est"; CA="$ROOT/build/fastpki-ca"
W="$(mktemp -d)"; cd "$W"; PORT=18452
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

# Root, then a sub-CA the root actually signs. Capture the root's key URI BEFORE minting
# the sub: $CA_KEY_URI holds the LAST key ca_in_token minted, so reading it afterwards
# would sign the sub with its own key and quietly produce a second self-signed root.
ca_in_token rootca.pem "/CN=Ancestry Root CA" 3650 ancroot
ROOT_KEY_URI="$CA_KEY_URI"
ca_in_token subca.pem "/CN=Ancestry Issuing CA" 3650 ancsub rootca.pem "$ROOT_KEY_URI"
SUB_KEY_URI="$CA_KEY_URI"
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3650 \
    -subj "/CN=localhost" >/dev/null 2>&1

# Prove the fixture really is a hierarchy before trusting anything built on it.
chk "fixture: sub-CA is signed by the root" yes \
    "$("$OSSL" verify -CAfile rootca.pem -partial_chain subca.pem >/dev/null 2>&1 && echo yes || echo no)"
chk "fixture: sub-CA is NOT self-signed" yes \
    "$([ "$("$OSSL" x509 -in subca.pem -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')" \
      != "$("$OSSL" x509 -in subca.pem -noout -issuer -nameopt RFC2253 2>/dev/null | sed 's/^issuer=//')" ] \
      && echo yes || echo no)"

pg_setup ca_ancestors
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains "$W/domains.txt"
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/subca.pem
SIGNING_CA_KEY=$SUB_KEY_URI
SIGNING_CA_ID=ancsub
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$PORT
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf
"$CA" --config bootstrap.conf add ancroot --name "Ancestry Root" \
      --ca-pem "$W/rootca.pem" --ca-key "$ROOT_KEY_URI" >/dev/null 2>&1

"$EST" --config bootstrap.conf >est.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" EST_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-est died:"; cat est.log; exit 1; }

# Count the certificates a /cacerts response actually carries, by decoding it.
cacerts_count() {
    curl -sk "https://127.0.0.1:$PORT/.well-known/est/$1/cacerts" -o "p7_$1.b64" 2>/dev/null
    openssl base64 -d -A -in "p7_$1.b64" -out "p7_$1.der" 2>/dev/null || return 1
    "$OSSL" pkcs7 -inform DER -in "p7_$1.der" -print_certs -noout 2>/dev/null \
        | grep -c '^subject=' || true
}
subject_list() {
    "$OSSL" pkcs7 -inform DER -in "p7_$1.der" -print_certs -noout 2>/dev/null \
        | sed -n 's/^subject=//p' | tr -d ' ' | sort | tr '\n' ' '
}

echo "=== the sub-CA's chain reaches its root, with no ROOT_CA_PEM anywhere ==="
n=$(cacerts_count ancsub)
chk "sub-CA /cacerts carries 2 certificates" 2 "$n"
chk "  ... the issuing CA is present" yes \
    "$(subject_list ancsub | grep -q 'AncestryIssuingCA' && echo yes || echo no)"
chk "  ... and so is the ROOT (this is the walk)" yes \
    "$(subject_list ancsub | grep -q 'AncestryRootCA' && echo yes || echo no)"

echo "=== a self-signed root does not walk into itself ==="
nr=$(cacerts_count ancroot)
chk "root /cacerts carries exactly 1 certificate" 1 "$nr"

echo "=== the file path is gone, and so is the CA it invented ==="
chk "bootstrap.conf names no ROOT_CA_PEM" 0 "$(grep -c '^ROOT_CA_PEM=' bootstrap.conf || true)"
# ROOT_CA_PEM also synthesised a CA row called `root` — listed as `active`, with a
# file PATH where its signing key should be, resolvable by no service. An id-less or
# invented CA has been removed twice before; this asserts it stays removed.
# Asserted with the key SET, and pointed at a real self-signed root — otherwise this
# passes on the old code too and proves nothing. The old build read this path, found a
# genuine root, and printed a `root` row; the new build does not parse the key at all.
# A separate conf file, so the "bootstrap.conf names no ROOT_CA_PEM" check above stays true.
sed 's/^SIGNING_CA_ID=.*/SIGNING_CA_ID=ancsub/' bootstrap.conf > rootkey.conf
printf 'ROOT_CA_PEM=%s\nROOT_CA_KEY=%s\n' "$W/rootca.pem" "$W/nonexistent.key" >> rootkey.conf
chk "fixture: the anchor file really is a self-signed root" yes \
    "$("$OSSL" verify -CAfile rootca.pem -partial_chain rootca.pem >/dev/null 2>&1 && echo yes || echo no)"
chk "fastpki-ca list invents no 'root' row" 0 \
    "$("$CA" --config rootkey.conf list 2>/dev/null | grep -c '^root' || true)"
chk "fastpki-ca show root is a plain not-found" 1 \
    "$("$CA" --config rootkey.conf show root >/dev/null 2>&1; echo $?)"

echo
echo "=== CA ANCESTORS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
