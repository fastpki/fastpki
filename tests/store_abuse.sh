#!/usr/bin/env bash
# RFC 4387 cert store abuse (§4). The store answers
# GET /certificates/search?<attr>=<value> straight out of the DB, so the surface
# is injection, not path traversal (it never touches the filesystem). The column
# is double-allowlisted (handler + DB layer) and the value is a bound parameter,
# so neither attribute-injection nor SQL-injection should work — this proves it.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
W="$(mktemp -d)"; cd "$W"; PORT=18104
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
code(){ curl -s -G -o /dev/null -w '%{http_code}' "$@"; }

ca_in_token ca.pem "/CN=Store Abuse CA" 3650
cp ca.pem root.pem
"$OSSL" req -newkey rsa:2048 -nodes -keyout c.key -out c.csr -subj "/CN=host.internal" >/dev/null 2>&1
"$OSSL" x509 -req -in c.csr -CA ca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS -CAcreateserial -days 365 -out c.pem >/dev/null 2>&1
pg_setup store_abuse
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
NB=$(date +%s); NA=$((NB+31536000)); FP="deadbeefcafe0001"
DER=$("$OSSL" x509 -in c.pem -outform DER | xxd -p | tr -d '\n')
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cert,cn,fingerprint) VALUES('aa',0,0,0,$NB,$NA,'CN=host.internal','t','\x$DER'::bytea,'host.internal','\x$FP'::bytea);"
cat > store.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
STORE_BIND=127.0.0.1
STORE_PORT=$PORT
LOG_LEVEL=err
EOF
seed_ca_from_conf store.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-store" --config store.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-store died:"; cat srv.log; exit 1; fi
U="http://127.0.0.1:$PORT/certificates/search"

echo "=== a legitimate lookup works (baseline) ==="
chk "exact fingerprint match -> 200" 200 "$(code "$U" --data-urlencode "certHash=$FP")"

echo "=== SQL injection in the value is neutralized (bound parameter) ==="
chk "tautology ' OR '1'='1 does NOT match-all -> 404" 404 \
    "$(code "$U" --data-urlencode "certHash=' OR '1'='1")"
chk "UNION/quote-break payload -> 404" 404 \
    "$(code "$U" --data-urlencode "certHash=' UNION SELECT cert FROM certs --")"
# Destructive payload must not execute — the table (and its row) survive.
code "$U" --data-urlencode "certHash=x'; DROP TABLE certs; --" >/dev/null
# The seeded LEAF, not every row: the CA's own certificate is a row in
# `certs` too, so a bare count answers "how many certificates exist" when the question
# is "did the table and its contents survive".
chk "DROP TABLE payload did not drop the table" "1" \
    "$(pg_exec "SELECT count(*) FROM certs WHERE NOT is_ca;" 2>/dev/null)"
chk "the store still answers a real lookup after the injection attempts" 200 \
    "$(code "$U" --data-urlencode "certHash=$FP")"

echo "=== attribute-injection + RFC 4387 shape are rejected ==="
chk "unsupported attribute -> 400" 400 "$(code "$U" --data-urlencode "filename=../../../etc/passwd")"
chk "a non-allowlisted column name -> 400" 400 "$(code "$U" --data-urlencode "cert=1")"
chk "two attributes (RFC 4387: exactly one) -> 400" 400 \
    "$(code "$U" --data-urlencode "serial=aa" --data-urlencode "cn=host.internal")"
chk "no attribute -> 400" 400 "$(code "$U")"

echo "=== server survived all of it ==="
chk "fastpki-store still alive" yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"

echo
echo "=== STORE ABUSE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
