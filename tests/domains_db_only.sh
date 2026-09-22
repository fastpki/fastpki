#!/usr/bin/env bash
# The approved-domain allow-list is the `allowed_domains` TABLE and nothing else.
#
# `load_allowed_domains()` used to merge a DOMAINS_FILE on top of the table — its own
# comment called that a "backward compat / migration source". Two things were wrong with
# it. It is a file, so the effective ISSUANCE POLICY differed per node while the table
# replicates: the same CSR could be signed on DC1 and refused on DC2, which is the worst
# kind of PKI bug because both answers look correct locally. And a stale file silently
# widened the allow-list — a domain nobody could see in the console was still issuable.
#
# "Removed" therefore has to mean INERT, not merely unused. So this suite points
# DOMAINS_FILE at a well-formed file naming a domain that is NOT in the table, and proves
# the CA refuses to sign for it. Before this change that name was issuable.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
# Only adopt the system openssl.cnf where it really is one (§3d): on macOS that path is
# a stub with no providers and exporting it breaks every pkcs11 load.
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; PORT=18482
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ grep -q "$2" <<<"$1" && echo yes || echo no; }

ca_in_token ca.pem "/CN=Domains CA" 3
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup domains_db_only
trap 'pg_cleanup; kill ${SRV:-} 2>/dev/null' EXIT

# In the TABLE: allowed.example. In the FILE ONLY: fromfile.example.
printf 'allowed.example\n' > indb.txt
printf 'fromfile.example\n' > domains.txt
seed_domains "$W/indb.txt"
seed_web_user tester s3cret-d requester

cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
DOMAINS_FILE=$W/domains.txt
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$PORT
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf

"$ROOT/build/fastpki-est" --config bootstrap.conf >srv.log 2>&1 & SRV=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$SRV" || true
kill -0 $SRV 2>/dev/null || { echo "est died:"; cat srv.log; exit 1; }

# enroll <cn> -> issued PEM on stdout (empty when the policy refuses)
enroll(){
  "$OSSL" req -new -subj "/CN=$1" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr >/dev/null 2>&1
  "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
  curl -sk -u tester:s3cret-d --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
    "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll" \
    | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null
}
issued(){ has "$1" "BEGIN CERTIFICATE"; }

echo "=== the table IS the allow-list ==="
N=$(pg_exec "SELECT COUNT(*) FROM allowed_domains WHERE domain='allowed.example';" | tr -d ' ')
chk "seed_domains wrote the table"            1   "$N"
chk "a domain in the table is issuable"       yes "$(issued "$(enroll host.allowed.example)")"

echo "=== a well-formed DOMAINS_FILE is inert ==="
chk "the file exists and names a domain"      yes "$(has "$(cat domains.txt)" 'fromfile.example')"
chk "the file's domain is NOT in the table"   0   "$(pg_exec "SELECT COUNT(*) FROM allowed_domains WHERE domain='fromfile.example';" | tr -d ' ')"
chk "a file-only domain is REFUSED"           no  "$(issued "$(enroll host.fromfile.example)")"
chk "an unlisted domain is refused too"       no  "$(issued "$(enroll host.nowhere.example)")"

# Had the file been read, the cert would exist. Assert on the DB, not just the response.
chk "no certificate was issued for it"        0 \
    "$(pg_exec "SELECT COUNT(*) FROM certs WHERE cn LIKE '%fromfile.example';" | tr -d ' ')"

echo "=== the list is live: adding to the table takes effect on restart ==="
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
pg_exec "INSERT INTO allowed_domains(domain) VALUES('fromfile.example') ON CONFLICT DO NOTHING;" >/dev/null
"$ROOT/build/fastpki-est" --config bootstrap.conf >srv2.log 2>&1 & SRV=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$SRV" || true
chk "same name issuable once the TABLE has it" yes "$(issued "$(enroll host.fromfile.example)")"
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null

echo "=== the config key is gone ==="
chk "DOMAINS_FILE is not a parsed key" no "$(grep -q '"DOMAINS_FILE"' "$ROOT/src/lib/config.cpp" && echo yes || echo no)"

echo
echo "=== DOMAINS DB-ONLY: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
