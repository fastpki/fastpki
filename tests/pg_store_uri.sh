#!/usr/bin/env bash
# RFC 4387 §2 `uri` selector on the PostgreSQL backend. Companion to
# store_uri.sh: proves a cert issued through FastPKI into Postgres with a
# SubjectAltName URI is indexed in cert_uris (insert_cert) and found by the store's
# ?uri=<value> (search_certs JOIN). URI SANs are opt-in per profile.
# Requires a running Postgres with the `pki` db loaded from sql/createdb.sql.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
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
pg_setup pg_store_uri
PGCONN="$PG_CONNINFO"
W="$(mktemp -d)"; cd "$W"; EST=18472; STORE=18473
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fi; [ "$2" = "$3" ] || fail=$((fail+1)); }

pg_exec "TRUNCATE certs;" >/dev/null
pg_exec "TRUNCATE cert_uris;" >/dev/null
ca_in_token ca.pem "/CN=PG URI CA" 3
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3 -subj "/CN=localhost" >/dev/null 2>&1
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
PG_CONNINFO="$PGCONN"   # this suite targets the fixed DB, so it never ran pg_setup
seed_web_user uritester s3cret-u requester
# This suite targets a FIXED database, so a previous run's grant is still there — clear the
# carrier role's membership before re-granting rather than assuming a clean table.
pg_exec "DELETE FROM subject_roles WHERE selector_value='uritester';" >/dev/null
grant_profile uritester uritest

common="SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PGCONN
LOG_LEVEL=err"
cat > est.conf <<EOF
$common
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$EST
CERT_VALIDITY_DAYS=365
EOF
seed_cert_profiles '{"uritest":{"allowed_san_types":["dns","uri"]}}'
printf "%s\nSTORE_BIND=127.0.0.1\nSTORE_PORT=%s\n" "$common" "$STORE" > store.conf
# A CA exists only as a ca_instances row; the SIGNING_CA_* env seed is gone.
seed_ca_from_conf est.conf


"$BIN/fastpki-est"   --config est.conf   >est.log   2>&1 & E=$!
"$BIN/fastpki-store" --config store.conf >store.log 2>&1 & S=$!
sleep 1; trap 'kill $E $S 2>/dev/null; pg_cleanup' EXIT
if ! kill -0 $E 2>/dev/null; then echo "fastpki-est died:";   cat est.log;   exit 1; fi
if ! kill -0 $S 2>/dev/null; then echo "fastpki-store died:"; cat store.log; exit 1; fi

URI="https://pg.internal/tls-id/7"
echo "=== EST enroll with a URI SAN -> Postgres ==="
"$OSSL" req -new -subj "/CN=pg.internal" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr \
    -addext "subjectAltName=URI:$URI" >/dev/null 2>&1
"$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
curl -sk -u "uritester:s3cret-u" --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
    "https://127.0.0.1:$EST/.well-known/est/ca/simpleenroll" \
    | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs -out leaf.pem 2>/dev/null
chk "cert issued" ok "$( grep -q 'BEGIN CERTIFICATE' leaf.pem 2>/dev/null && echo ok || echo no )"
[ -s leaf.pem ] || { echo "enroll failed:"; cat est.log; exit 1; }

# insert_cert must have written the URI into cert_uris.
chk "cert_uris row present" "$URI" "$(pg_exec "SELECT uri FROM cert_uris LIMIT 1;")"

fpr_of() { "$OSSL" x509 -in "$1" -inform "${2:-PEM}" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }
LEAF_FPR=$(fpr_of leaf.pem PEM)
find_uri() {
    local code; code=$(curl -s -o hit.der -w "%{http_code}" -G "http://127.0.0.1:$STORE/certificates/search" --data-urlencode "uri=$1")
    [ "$code" = "200" ] || { echo "no($code)"; return; }
    [ "$(fpr_of hit.der DER)" = "$LEAF_FPR" ] && echo yes || echo no
}

echo "=== store search by uri (JOIN cert_uris) ==="
chk "findable by URI SAN" yes "$(find_uri "$URI")"
echo "=== a non-matching uri 404s ==="
code=$(curl -s -o /dev/null -w "%{http_code}" -G "http://127.0.0.1:$STORE/certificates/search" --data-urlencode "uri=https://pg.internal/nope")
chk "unknown uri -> 404" 404 "$code"

echo
echo "=== PG STORE URI: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
