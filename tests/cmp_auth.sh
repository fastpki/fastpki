#!/usr/bin/env bash
# CMP authentication: with accept_unprotected=false (fail closed), prove that
#   - unprotected requests are REJECTED
#   - PBM with the correct shared secret is ACCEPTED
#   - PBM with a wrong secret is REJECTED
#   - a client cert signed by the trusted client-CA is ACCEPTED
#   - a client cert NOT under the trusted CA is REJECTED
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
# These suites use -trusted, not -srvcert. Responses are protected by the RA
# credential now, so pinning the CA as the exact server cert can never match; the
# client validates the chain RA -> CA against that anchor instead.
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
W="$(mktemp -d)"; cd "$W"; PORT=18095
SECRET=topsecret123
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

# CA (signs responses + issued certs), client-CA (trust anchor for client certs)
ca_in_token ca.pem "/CN=Auth CA" 3650
# CMP has no CA-key fallback — issue the RA credential from THIS CA
# while CA_KEY_URI still names it, and publish it once the DB exists.
cmp_ra_issue ca.pem "$CA_KEY_URI" || { echo "SKIP: no CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
SERVER_CA_KEY_URI="$CA_KEY_URI"
ca_in_token clientca.pem "/CN=Client CA" 3650
# a client cert under the trusted client-CA
"$OSSL" req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=tester" >/dev/null 2>&1
"$OSSL" x509 -req -in client.csr -CA clientca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS -CAcreateserial -days 365 -out client.pem >/dev/null 2>&1
# a rogue self-signed client cert (not under the trusted CA)
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout rogue.key -out rogue.pem -days 365 -subj "/CN=rogue" >/dev/null 2>&1

pg_setup cmp_auth
cmp_ra_publish || { echo "SKIP: could not publish the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
cat > cmp.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$SERVER_CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
CMP_BIND=127.0.0.1
CMP_PORT=$PORT
CMP_PATH=/cmp
CMP_CLIENT_CA_ID=clientca
LOG_LEVEL=err
EOF
seed_ca_from_conf cmp.conf
# CMP PBM is PER USER — the global CMP_PBM_SECRET is gone. Every reference the
# client sends below needs its own `keys` row, or the server installs no secret and the
# MAC cannot verify. That is the point of the change: there is nothing to fall back to.
pg_exec "INSERT INTO keys(kid,protocol,key) VALUES('1','cmp','$SECRET') ON CONFLICT (kid,protocol) DO UPDATE SET key=EXCLUDED.key;" >/dev/null
pg_exec "INSERT INTO keys(kid,protocol,key) VALUES('tester','cmp','$SECRET') ON CONFLICT (kid,protocol) DO UPDATE SET key=EXCLUDED.key;" >/dev/null
# The credential needs an IDENTITY holding a profile grant, or
# resolve_profile refuses. seed_enrolling_identity leaves an existing role alone.
seed_enrolling_identity 1
seed_enrolling_identity tester
# The client-auth anchor is a ca_instances row, not a PEM file path.
"$ROOT/build/fastpki-ca" --config cmp.conf add clientca --name "Client Anchor" \
    --ca-pem "$W/clientca.pem" >/dev/null   # no key: FastPKI never signs with an anchor,
    # it only VERIFIES client certs against it. Registering the test's own
    # signing key here would be claiming this instance can issue, which it cannot.
cmp_ra_conf_lines >> cmp.conf
"$ROOT/build/fastpki-cmp" --config cmp.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT

base=( -cmd ir -server "http://127.0.0.1:$PORT/cmp/ca" -recipient "/CN=Auth CA" -trusted ca.pem
       -subject "/CN=auth.example.internal" )
issued() { [ -f "$1" ] && echo issue || echo reject; }

echo "=== CMP authentication (accept_unprotected=false) ==="

rm -f u.pem
"$OSSL" cmp "${base[@]}" -unprotected_requests -keep_alive 0 -ref 1 -newkey scratch.key -certout u.pem >/dev/null 2>&1
chk "unprotected request rejected" reject "$(issued u.pem)"

rm -f pbm.pem
"$OSSL" cmp "${base[@]}" -secret "pass:$SECRET" -ref tester -keep_alive 0 -newkey scratch.key -certout pbm.pem >/dev/null 2>&1
chk "PBM correct secret accepted" issue "$(issued pbm.pem)"

rm -f bad.pem
"$OSSL" cmp "${base[@]}" -secret "pass:wrongsecret" -ref tester -keep_alive 0 -newkey scratch.key -certout bad.pem >/dev/null 2>&1
chk "PBM wrong secret rejected" reject "$(issued bad.pem)"

rm -f sig.pem
"$OSSL" cmp "${base[@]}" -cert client.pem -key client.key -keep_alive 0 -newkey scratch.key -certout sig.pem >/dev/null 2>&1
chk "trusted client-cert signature accepted" issue "$(issued sig.pem)"

rm -f rogue_out.pem
"$OSSL" cmp "${base[@]}" -cert rogue.pem -key rogue.key -keep_alive 0 -newkey scratch.key -certout rogue_out.pem >/dev/null 2>&1
chk "untrusted client-cert rejected" reject "$(issued rogue_out.pem)"

echo
echo "=== CMP AUTH: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
