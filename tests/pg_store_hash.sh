#!/usr/bin/env bash
# Regression: RFC 4387 cert-store search over the bytea hash
# columns (certHash -> fingerprint) on the PostgreSQL backend. Before the fix,
# the store compared a hex query value against a bytea column and matched
# nothing; now search_certs wraps it as decode($1,'hex').
#   CMP issue -> Postgres (fingerprint bytea) -> store certHash=<hex> -> the cert
# Requires a running Postgres with the `pki` db loaded from sql/createdb.sql.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
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
# Follow the helper's settings rather than hardcoding: 33bc9df moved the default
# role/database to fastpki for Docker compose, which left every suite that pinned
# user=pki failing with 'role "pki" does not exist'.
# ⚠️ A THROWAWAY database, not the developer's own. This suite used to run against
# $PGDATABASE, which defaults to `fastpki` -- so it truncated the developer's tables, and on
# any box with an incomplete PKCS#11 toolchain `ca_in_token`'s SKIP path called pg_cleanup
# and DROPPED that database outright. pg_setup gives it an `fpki_<name>_<pid>` of its own.
pg_setup pg_store_hash
PGCONN="$PG_CONNINFO"
W="$(mktemp -d)"; cd "$W"; CMP=18100; STORE=18101
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

pg_exec "TRUNCATE certs;" >/dev/null
ca_in_token ca.pem "/CN=PG Store CA" 3650
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
cmp_seed_pbm pg-store-hash

"$ROOT/build/fastpki-cmp"   --config cmp.conf   >cmp.log   2>&1 & C=$!
"$ROOT/build/fastpki-store" --config store.conf >store.log 2>&1 & S=$!
sleep 1; trap 'kill $C $S 2>/dev/null; pg_cleanup' EXIT
if ! kill -0 $C 2>/dev/null; then echo "fastpki-cmp died:";   cat cmp.log;   exit 1; fi
if ! kill -0 $S 2>/dev/null; then echo "fastpki-store died:"; cat store.log; exit 1; fi

echo "=== CMP issue -> Postgres ==="
"$OSSL" cmp -cmd ir -server "http://127.0.0.1:$CMP/cmp/ca" -recipient "/CN=PG Store CA" \
    -trusted ca.pem -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
    -newkey scratch.key -subject "/CN=store.internal" -certout leaf.pem >/dev/null 2>&1
chk "cert issued" ok "$( [ -f leaf.pem ] && echo ok || echo no )"

# SHA-256 fingerprint as stored (lowercase hex, no colons) == certHash query value.
FPR=$("$OSSL" x509 -in leaf.pem -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')
echo "  certHash=$FPR"

echo "=== store certHash search (bytea decode) ==="
code=$(curl -s -o out.der -w "%{http_code}" "http://127.0.0.1:$STORE/certificates/search?certHash=$FPR")
chk "HTTP 200 for certHash" 200 "$code"
GOT=$("$OSSL" x509 -in out.der -inform DER -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')
chk "returned cert matches the requested certHash" "$FPR" "${GOT:-none}"

echo "=== uppercase hex also matches (decode is case-insensitive) ==="
UP=$(echo "$FPR" | tr 'a-f' 'A-F')
code=$(curl -s -o up.der -w "%{http_code}" "http://127.0.0.1:$STORE/certificates/search?certHash=$UP")
chk "HTTP 200 for uppercase certHash" 200 "$code"

echo "=== unknown certHash -> 404 ==="
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$STORE/certificates/search?certHash=deadbeef")
chk "unknown certHash -> 404" 404 "$code"

echo
echo "=== PG STORE HASH: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
