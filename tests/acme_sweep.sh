#!/usr/bin/env bash
# Regression: a background thread reaps expired ACME nonces and
# orders without any triggering request (ACME_SWEEP_SEC). Previously
# delete_expired_nonces/orders were never called, so they accumulated forever.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
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
W="$(mktemp -d)"; cd "$W"; PORT=18105
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Sweep CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_sweep
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
ROOT_CA_PEM=$W/root.pem
ACME_CERT=$W/acme.pem
ACME_KEY=$W/acme.key
PG_CONNINFO=$PG_CONNINFO
ACME_BIND=127.0.0.1
ACME_PORT=$PORT
ACME_SWEEP_SEC=2
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-acme" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-acme died:"; cat srv.log; exit 1; fi

# The background sweeper (ACME_SWEEP_SEC=2) briefly write-locks acme.db every 2s.
# Read through a busy-timeout so a query that lands during a sweep waits for the
# lock instead of returning empty ("database is locked"), which otherwise makes
# this test flaky under CI load (e.g. a spurious "survivor" mismatch).
adb(){ psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -tAq -c "$@"; }

PAST=$(( $(date +%s) - 100 ))
FUT=$(( $(date +%s) + 86400 ))
# expired + future nonces and orders (no HTTP requests involved)
adb "INSERT INTO nonces(nonce,ip,expires) VALUES('old-n','127.0.0.1',$PAST),('new-n','127.0.0.1',$FUT);"
adb "INSERT INTO orders(id,status,expires) VALUES('111',0,$PAST),('222',0,$FUT);"
chk "2 nonces before sweep" 2 "$(adb 'select count(*) from nonces;')"
chk "2 orders before sweep" 2 "$(adb 'select count(*) from orders;')"

echo "=== wait for background sweep (no requests) ==="
sleep 3
chk "expired nonce reaped, future kept" 1 "$(adb 'select count(*) from nonces;')"
chk "the survivor is the future nonce" new-n "$(adb 'select nonce from nonces;')"
chk "expired order reaped, future kept" 1 "$(adb 'select count(*) from orders;')"
chk "the survivor is the future order" 222 "$(adb 'select id from orders;')"

echo
echo "=== ACME SWEEP: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
