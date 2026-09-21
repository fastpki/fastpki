#!/usr/bin/env bash
# RFC 4387 store selector hashes on the PostgreSQL backend. Companion
# to store_hash.sh and pg_store_hash.sh (certHash only): proves a cert
# issued through FastPKI into Postgres is findable by "sHash" / "iAndSHash" / "sKIDHash",
# where those columns are bytea storing the raw digest (insert_cert wraps the hex
# as "\x…", search wraps the query as decode($1,'hex')).
# Requires a running Postgres with the `pki` db loaded from sql/createdb.sql.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/x509_der.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
BIN=${BIN:-$ROOT/build}
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
# Follow the helper's settings rather than hardcoding: 33bc9df moved the default
# role/database to fastpki for Docker compose, which left every suite that pinned
# user=pki failing with 'role "pki" does not exist'.
# ⚠️ A THROWAWAY database, not the developer's own. This suite used to run against
# $PGDATABASE, which defaults to `fastpki` -- so it truncated the developer's tables, and on
# any box with an incomplete PKCS#11 toolchain `ca_in_token`'s SKIP path called pg_cleanup
# and DROPPED that database outright. pg_setup gives it an `fpki_<name>_<pid>` of its own.
pg_setup pg_store_hash_selectors
PGCONN="$PG_CONNINFO"
W="$(mktemp -d)"; cd "$W"; CMP=18120; STORE=18121
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fi; [ "$2" = "$3" ] || fail=$((fail+1)); }

pg_exec "TRUNCATE certs;" >/dev/null
ca_in_token ca.pem "/CN=PG Sel CA" 3650
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
common="SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PGCONN
LOG_LEVEL=err"
printf "%s\nCMP_BIND=127.0.0.1\nCMP_PORT=%s\nCMP_PATH=/cmp\n" "$common" "$CMP" > cmp.conf
printf "%s\nSTORE_BIND=127.0.0.1\nSTORE_PORT=%s\n" "$common" "$STORE" > store.conf
# A CA exists only as a ca_instances row; the SIGNING_CA_* env seed is gone.
# CMP protects its responses with a dedicated RA credential — the CA-key fallback
# is gone — so this suite must provision one before it starts fastpki-cmp, and the client
# must anchor with -trusted rather than pin with -srvcert (the CA is no longer the sender).
cmp_ra_issue ca.pem "$CA_KEY_URI" \
    || { echo "SKIP: could not provision the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
cmp_ra_publish
cmp_ra_conf_lines >> cmp.conf
seed_ca_from_conf cmp.conf
cmp_seed_pbm pg-store-hash-selectors

"$BIN/fastpki-cmp"   --config cmp.conf   >cmp.log   2>&1 & C=$!
"$BIN/fastpki-store" --config store.conf >store.log 2>&1 & S=$!
sleep 1; trap 'kill $C $S 2>/dev/null; pg_cleanup' EXIT
if ! kill -0 $C 2>/dev/null; then echo "fastpki-cmp died:";   cat cmp.log;   exit 1; fi
if ! kill -0 $S 2>/dev/null; then echo "fastpki-store died:"; cat store.log; exit 1; fi

echo "=== CMP issue -> Postgres ==="
"$OSSL" cmp -cmd ir -server "http://127.0.0.1:$CMP/cmp/ca" -recipient "/CN=PG Sel CA" \
    -trusted ca.pem -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
    -newkey scratch.key -subject "/CN=pg.internal" -certout leaf.pem >/dev/null 2>&1
chk "cert issued" ok "$( [ -f leaf.pem ] && echo ok || echo no )"
[ -f leaf.pem ] || { echo "issue failed:"; cat cmp.log; exit 1; }

# The bytea columns must hold the raw digest (16..20 bytes), not the hex text.
# Scoped to non-CA rows: with ca_instances gone the CA is a row of `certs`
# too, and it carries selector hashes like any other certificate.
chk "sHash column is non-null in the row" 1 "$(pg_exec "SELECT count(*) FROM certs WHERE \"sHash\" IS NOT NULL AND NOT is_ca;")"

read -r SHASH IHASH IANDS SKID < <(x509_selectors "$W/leaf.pem")
echo "  \"sHash\"=$SHASH  \"iHash\"=$IHASH  \"iAndSHash\"=$IANDS  \"sKIDHash\"=$SKID"

fpr_of() { "$OSSL" x509 -in "$1" -inform "${2:-PEM}" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }
LEAF_FPR=$(fpr_of leaf.pem PEM)
search_matches() {   # the selector identifies exactly one certificate
    local code; code=$(curl -s -o hit.der -w "%{http_code}" "http://127.0.0.1:$STORE/certificates/search?$1=$2")
    [ "$code" = "200" ] || { echo "no($code)"; return; }
    [ "$(fpr_of hit.der DER)" = "$LEAF_FPR" ] && echo yes || echo no
}

# iHash is the one selector that is legitimately NOT unique to the leaf. The leaf's issuer
# is the CA's subject, and the CA is self-signed -- so the CA's own iHash is that same
# value, and with the CA a row of `certs` a search by iHash correctly returns
# both. RFC 4387 agrees: the CA's self-signed certificate IS a certificate issued by that
# name. So assert the leaf is AMONG the answers, not that it is the only one; the response
# may be a bare DER or a certs-only PKCS#7 depending on the count.
search_contains() {
    local code; code=$(curl -s -o hit.bin -w "%{http_code}" "http://127.0.0.1:$STORE/certificates/search?$1=$2")
    [ "$code" = "200" ] || { echo "no($code)"; return; }
    if [ "$(fpr_of hit.bin DER)" = "$LEAF_FPR" ]; then echo yes; return; fi
    "$OSSL" pkcs7 -inform DER -in hit.bin -print_certs -out hits.pem 2>/dev/null || \
        "$OSSL" pkcs7 -inform PEM -in hit.bin -print_certs -out hits.pem 2>/dev/null
    # Split with awk, not `csplit ... '{*}'`: the repeat-count form is a GNU extension and
    # BSD/macOS csplit rejects it, which would leave the loop below with nothing to read
    # and turn a real match into a silent "no" (§3d -- the suites run on macOS too).
    if [ -s hits.pem ]; then
        rm -f bundle_*.pem
        awk '/-----BEGIN CERTIFICATE-----/{n++; f=sprintf("bundle_%02d.pem", n)}
             f {print > f}
             /-----END CERTIFICATE-----/{f=""}' hits.pem
        for f in bundle_*.pem; do
            [ -e "$f" ] || continue
            [ "$(fpr_of "$f" PEM)" = "$LEAF_FPR" ] && { rm -f bundle_*.pem; echo yes; return; }
        done
        rm -f bundle_*.pem
    fi
    echo no
}

echo "=== store search by each selector hash (bytea decode) ==="
chk "findable by sHash"     yes "$(search_matches sHash "$SHASH")"
chk "findable by iHash"     yes "$(search_contains iHash "$IHASH")"
chk "findable by iAndSHash" yes "$(search_matches iAndSHash "$IANDS")"
chk "findable by sKIDHash"  yes "$(search_matches sKIDHash "$SKID")"
echo "=== uppercase hex also matches (decode is case-insensitive) ==="
chk "findable by uppercase sHash" yes "$(search_matches sHash "$(echo "$SHASH" | tr 'a-f' 'A-F')")"

echo
echo "=== PG STORE HASH SELECTORS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
