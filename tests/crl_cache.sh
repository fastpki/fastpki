#!/usr/bin/env bash
# Regression: CRL caching + RFC 5280 extensions.
#   - the CRL carries X509v3 CRL Number and Authority Key Identifier
#   - within CRL_CACHE_TTL_SEC the CRL is served from cache (not regenerated)
#   - after the TTL it is regenerated (new crlNumber, reflects new revocations)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
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
W="$(mktemp -d)"; cd "$W"; PORT=18104; CRLP=/pki/signing_ca.crl
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

# CA with a SubjectKeyIdentifier so the CRL's AKI (keyid:always) can be derived.
ca_in_token ca.pem "/CN=CRL Ext CA" 3650
cp ca.pem root.pem
pg_setup crl_cache
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
# NOTE: the ca_instances INSERT that used to sit here is gone. That table was dropped --
# a CA is a row of `certs` with is_ca now -- so the statement had been failing silently
# (pg_exec does not check psql's exit status, and nothing here did either). The suite
# passed regardless because seed_ca_from_conf does the real registration. Left in place
# it reads like the thing that seeds the CA, which is exactly how the next person loses
# an afternoon.
NB=$(date +%s); NA=$((NB+31536000))
mkrev() { # cn status -> serial
    "$OSSL" req -newkey rsa:2048 -nodes -keyout $1.key -out $1.csr -subj "/CN=$1" >/dev/null 2>&1
    "$OSSL" x509 -req -in $1.csr -CA ca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS -CAcreateserial -days 365 -out $1.pem >/dev/null 2>&1
    local ser der; ser=$("$OSSL" x509 -in $1.pem -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
    der=$("$OSSL" x509 -in $1.pem -outform DER | xxd -p | tr -d '\n')
    pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cert,cn,fingerprint,ca_instance_id) VALUES('$ser',$2,1,$NB,$NB,$NA,'CN=$1','t','\x$der'::bytea,'$1','','ca-global');"
    echo "$ser"
}
S1=$(mkrev rev1 -1)   # already revoked
S2=$(mkrev rev2 0)    # valid for now; revoked mid-test

cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
CRL_PATH=$CRLP
CRL_CACHE_TTL_SEC=2
OCSP_EXPIRY_SWEEP_SEC=0
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-ocsp" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT

crlnum() { "$OSSL" crl -inform DER -in "$1" -noout -text 2>/dev/null | grep -A1 "CRL Number" | tail -1 | tr -dc '0-9'; }
has_serial() { "$OSSL" crl -inform DER -in "$1" -noout -text 2>/dev/null | grep -A1 "Serial Number" | tr 'A-F' 'a-f' | tr -d ' :' | grep -qi "$2" && echo yes || echo no; }

echo "=== extensions present ==="
curl -s "http://127.0.0.1:$PORT$CRLP/ca-global" -o c1.der
TXT=$("$OSSL" crl -inform DER -in c1.der -noout -text 2>/dev/null)
echo "$TXT" | grep -q "CRL Number" && a=yes || a=no
chk "CRL has X509v3 CRL Number" yes "$a"
echo "$TXT" | grep -q "Authority Key Identifier" && b=yes || b=no
chk "CRL has Authority Key Identifier" yes "$b"
N1=$(crlnum c1.der); echo "  crlNumber #1 = $N1"

echo "=== caching within TTL ==="
pg_exec "UPDATE certs SET status=-1, \"revocationDate\"=$NB WHERE serial='$S2';"  # revoke rev2 now
curl -s "http://127.0.0.1:$PORT$CRLP/ca-global" -o c2.der
chk "crlNumber unchanged within TTL (cached)" "$N1" "$(crlnum c2.der)"
chk "newly-revoked serial NOT yet in cached CRL" no "$(has_serial c2.der "$S2")"

echo "=== regenerated after TTL ==="
sleep 3
curl -s "http://127.0.0.1:$PORT$CRLP/ca-global" -o c3.der
N3=$(crlnum c3.der); echo "  crlNumber #3 = $N3"
[ -n "$N3" ] && [ "$N3" != "$N1" ] && c=yes || c=no
chk "crlNumber changed after TTL (regenerated)" yes "$c"
chk "newly-revoked serial now in CRL" yes "$(has_serial c3.der "$S2")"

echo
echo "=== CRL CACHE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
