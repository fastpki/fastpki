#!/usr/bin/env bash
# RFC 4387 store selector hashes populated at issuance. A cert issued
# through FastPKI must be findable in the store by "sHash" / "iAndSHash" / "sKIDHash",
# not just certHash. Before the fix insert_cert never wrote those columns, so the
# store 404'd every hash query for a FastPKI-issued cert.
#   CMP issue -> PostgreSQL ("sHash"/"iAndSHash"/"sKIDHash" filled) -> store search each hash
# The expected hash values are recomputed independently by tests/x509_der.sh:
#   "sHash"      = SHA-1(DER subject Name)
#   "iAndSHash"  = SHA-1(DER IssuerAndSerialNumber)
#   "sKIDHash"   = SHA-1(subjectKeyIdentifier value)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/x509_der.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
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
W="$(mktemp -d)"; cd "$W"; CMP=18110; STORE=18111
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Store Hash CA" 3650
printf "internal\n" > domains.txt
pg_setup store_hash
# CMP protects responses with a per-CA RA credential and has NO CA-key
# fallback, so this is required setup — without it every exchange below is a 503.
cmp_ra_setup ca.pem "$CA_KEY_URI" \
    || { echo "SKIP: could not provision the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
seed_domains $W/domains.txt   # allowed_domains is the sole source
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
common="SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
LOG_LEVEL=err"
printf "%s\nCMP_BIND=127.0.0.1\nCMP_PORT=%s\nCMP_PATH=/cmp\n" "$common" "$CMP" > cmp.conf
printf "%s\nSTORE_BIND=127.0.0.1\nSTORE_PORT=%s\n" "$common" "$STORE" > store.conf
seed_ca_from_conf cmp.conf   # register CA 'ca' (SIGNING_CA_* no longer seed it)
cmp_seed_pbm store-hash
cmp_ra_conf_lines >> cmp.conf   # CMP_RA_CERT_ID_PREFIX + CMP_RA_KEY
"$ROOT/build/fastpki-cmp"   --config cmp.conf   >cmp.log   2>&1 & C=$!
"$ROOT/build/fastpki-store" --config store.conf >store.log 2>&1 & S=$!
sleep 1; trap 'pg_cleanup; kill $C $S 2>/dev/null' EXIT
if ! kill -0 $C 2>/dev/null; then echo "fastpki-cmp died:";   cat cmp.log;   exit 1; fi
if ! kill -0 $S 2>/dev/null; then echo "fastpki-store died:"; cat store.log; exit 1; fi

echo "=== CMP issue -> PostgreSQL ==="
"$OSSL" cmp -cmd ir -server "http://127.0.0.1:$CMP/cmp/ca" -recipient "/CN=Store Hash CA" \
    -trusted ca.pem -expect_sender "/CN=cmp-ra.test" -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
    -newkey scratch.key -subject "/CN=host.internal" -certout leaf.pem >/dev/null 2>&1
chk "cert issued" ok "$( [ -f leaf.pem ] && echo ok || echo no )"
[ -f leaf.pem ] || { echo "issue failed:"; cat cmp.log; exit 1; }

# Independently recompute the three RFC 4387 selector hashes from the leaf.
read -r SHASH IHASH IANDS SKID < <(x509_selectors "$W/leaf.pem")
echo "  \"sHash\"=$SHASH"
echo "  \"iHash\"=$IHASH"
echo "  \"iAndSHash\"=$IANDS"
echo "  \"sKIDHash\"=$SKID"

fpr_of() { "$OSSL" x509 -in "$1" -inform "${2:-PEM}" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }
LEAF_FPR=$(fpr_of leaf.pem PEM)

search_matches() { # attr value -> yes/no (the leaf is among the certificates returned)
    # RFC 4387 §3.3: a selector may match several certificates, and the store answers a
    # single match with application/pkix-cert and several with a certs-only PKCS#7. Both
    # are correct, so accept either and ask the real question — is the leaf in there?
    #
    # This used to assume a bare certificate, which held only while a CA's certificate
    # was NOT in `certs`. It is now, and a SELF-SIGNED CA has the same iHash as
    # the leaves it issued (its issuer is itself), so an iHash search legitimately
    # returns two. That is the store gaining the ability to serve a CA certificate, not
    # a regression — but it made the old helper report "no" for the leaf that was right
    # there in the bundle.
    local code; code=$(curl -s -o hit.der -w "%{http_code}" "http://127.0.0.1:$STORE/certificates/search?$1=$2")
    [ "$code" = "200" ] || { echo "no($code)"; return; }
    if [ "$(fpr_of hit.der DER)" = "$LEAF_FPR" ]; then echo yes; return; fi
    # Not a bare certificate — try it as a PKCS#7 bundle and look for the leaf inside.
    if "$OSSL" pkcs7 -inform DER -in hit.der -print_certs -out hit.pem 2>/dev/null; then
        "$OSSL" crl2pkcs7 -nocrl -certfile hit.pem 2>/dev/null >/dev/null   # sanity: parses
        awk 'BEGIN{n=0} /BEGIN CERT/{n++} {print > ("c" n ".pem")}' hit.pem
        for f in c*.pem; do
            [ -s "$f" ] || continue
            [ "$(fpr_of "$f" PEM)" = "$LEAF_FPR" ] && { rm -f c*.pem; echo yes; return; }
        done
        rm -f c*.pem
    fi
    echo no
}

echo "=== store search by each selector hash ==="
chk "findable by sHash"     yes "$(search_matches sHash "$SHASH")"
chk "findable by iHash"     yes "$(search_matches iHash "$IHASH")"
chk "findable by iAndSHash" yes "$(search_matches iAndSHash "$IANDS")"
chk "findable by sKIDHash"  yes "$(search_matches sKIDHash "$SKID")"

echo "=== a wrong hash still 404s (no accidental match-all) ==="
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$STORE/certificates/search?sHash=deadbeef")
chk "unknown sHash -> 404" 404 "$code"

echo
echo "=== STORE HASH: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
