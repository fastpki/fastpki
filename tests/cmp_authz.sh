#!/usr/bin/env bash
# CMP per-user authorization + client-supplied revocation reason,
# both over signature-protected requests in the fail-closed posture
# (unprotected CMP has been removed — the server always refuses it).
#
# fastpki-cmp recovers the authenticated signer from the raw PKIMessage
# (pki::parse_cmp_request: header sender CN, bound to a cert in extraCerts after
# OpenSSL validates the protection) and enforces:
#   a) a caller may revoke a cert it OWNS (+ the client's CRLReason is recorded)
#   b) a caller may NOT revoke a cert owned by someone else
#   c) a caller whose role grants cert:revoke may revoke ANY cert
#   d) PBM-protected rr is refused (PBM is for enrollment only)
#   e) unprotected rr is refused
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"
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
W="$(mktemp -d)"; cd "$W"; PORT=18100; OPORT=18101
GLOBAL=globalpbm123
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }
ocsp() { "$OSSL" ocsp -issuer ca.pem -cert "$1" -url "http://127.0.0.1:$OPORT/ocsp" -noverify 2>/dev/null | grep -oE "good|revoked" | head -1; }

# CA (signs issued certs) + client-CA (trust anchor for the callers' certs).
ca_in_token ca.pem "/CN=Authz CA" 3650
# CMP has no CA-key fallback — issue the RA credential from THIS CA
# while CA_KEY_URI still names it, and publish it once the DB exists.
cmp_ra_issue ca.pem "$CA_KEY_URI" || { echo "SKIP: no CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
SERVER_CA_KEY_URI="$CA_KEY_URI"
ca_in_token cca.pem "/CN=Client CA" 3650
# Caller auth certs under the client-CA: alice, bob (plain), boss (revoke-any).
mkcaller() {
  "$OSSL" req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$1" >/dev/null 2>&1
  "$OSSL" x509 -req -in "$1.csr" -CA cca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS -CAcreateserial -days 365 -out "$1.pem" >/dev/null 2>&1
}
mkcaller alice; mkcaller bob; mkcaller boss
"$OSSL" genrsa -out lk.pem 2048 >/dev/null 2>&1

pg_setup cmp_authz
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
CMP_CLIENT_CA_ID=cca
LOG_LEVEL=info
EOF
seed_ca_from_conf cmp.conf
# Revoke-any used to be `MASTER_USERS=boss` in the config file above. It is now a
# GRANT, which is the whole point — an admin can see it in the console, it replicates, and
# it can name one CA instead of the whole deployment.
#
# boss gets a role of his own rather than `admin`: this must prove the CAPABILITY is what
# CMP reads, not a builtin's name. Four earlier bugs in this repo were a builtin name
# deciding an outcome, and each was invisible until a custom role existed.
pg_exec "INSERT INTO roles(name,description,builtin) VALUES('cert-revoker','revoke any cert',false) ON CONFLICT (name) DO NOTHING;" >/dev/null
pg_exec "INSERT INTO role_permissions(role,permission,scope) VALUES('cert-revoker','cert:revoke','*') ON CONFLICT DO NOTHING;" >/dev/null
pg_exec "INSERT INTO web_users(username,hash,role) VALUES('boss','x','cert-revoker') ON CONFLICT (username) DO UPDATE SET role=EXCLUDED.role;" >/dev/null
# CMP PBM is PER USER — the global CMP_PBM_SECRET is gone. Every reference the
# client sends below needs its own `keys` row, or the server installs no secret and the
# MAC cannot verify. That is the point of the change: there is nothing to fall back to.
pg_exec "INSERT INTO keys(kid,protocol,key) VALUES('1','cmp','$GLOBAL') ON CONFLICT (kid,protocol) DO UPDATE SET key=EXCLUDED.key;" >/dev/null
pg_exec "INSERT INTO keys(kid,protocol,key) VALUES('alice','cmp','$GLOBAL') ON CONFLICT (kid,protocol) DO UPDATE SET key=EXCLUDED.key;" >/dev/null
# The credential needs an IDENTITY holding a profile grant, or
# resolve_profile refuses. seed_enrolling_identity leaves an existing role alone.
seed_enrolling_identity alice
seed_enrolling_identity bob
seed_enrolling_identity boss
# The client-auth anchor is a ca_instances row, not a PEM file path.
"$ROOT/build/fastpki-ca" --config cmp.conf add cca --name "Client Anchor" \
    --ca-pem "$W/cca.pem" >/dev/null   # no key: FastPKI never signs with an anchor,
    # it only VERIFIES client certs against it. Registering the test's own
    # signing key here would be claiming this instance can issue, which it cannot.
cat > ocsp.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$SERVER_CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
OCSP_BIND=127.0.0.1
OCSP_PORT=$OPORT
LOG_LEVEL=err
EOF
seed_ca_from_conf ocsp.conf   # register the CA (SIGNING_CA_* no longer seed it)
# Slice B: the CA key never signs a status response, so the responder needs its
# own certificate issued BY this CA -- otherwise fastpki-ocsp refuses every query.
printf 'OCSP_RESPONDER_KEY=%s\n' "$(ocsp_responder_key "$W/ca.pem" "$SERVER_CA_KEY_URI" ca "$W")" >> ocsp.conf

cmp_ra_conf_lines >> cmp.conf
"$ROOT/build/fastpki-cmp"  --config cmp.conf  >srv.log  2>&1 & P=$!
"$ROOT/build/fastpki-ocsp" --config ocsp.conf >ocsp.log 2>&1 & O=$!
sleep 1; trap 'pg_cleanup; kill $P $O 2>/dev/null' EXIT

SRV=( -server "http://127.0.0.1:$PORT/cmp/ca" -recipient "/CN=Authz CA" -trusted ca.pem -keep_alive 0 )
# Issue a leaf via signature as $1 (caller name); leaf owner becomes the sender CN.
issue() { # issue <caller> <leafcn> <outfile>
  # The sender (hence the cert owner) is taken from the -cert subject by openssl.
  "$OSSL" cmp -cmd ir "${SRV[@]}" -cert "$1.pem" -key "$1.key" \
      -subject "/CN=$2" -newkey lk.pem -implicit_confirm -certout "$3" >/dev/null 2>&1
}

echo "=== Per-user revocation authorization (signature-protected) ==="

# a) owner revokes own cert, with reason
issue alice alice-leaf-1 al1.pem
chk "owner's cert issued valid" good "$(ocsp al1.pem)"
"$OSSL" cmp -cmd rr "${SRV[@]}" -cert alice.pem -key alice.key \
    -oldcert al1.pem -revreason 1 >/dev/null 2>&1
chk "owner may revoke own cert" revoked "$(ocsp al1.pem)"
al1s=$("$OSSL" x509 -in al1.pem -serial -noout | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
chk "revocation reason recorded = 1" 1 "$(pg_exec "SELECT \"revocationReason\" FROM certs WHERE serial='$al1s';")"

# b) a different standard user may NOT revoke alice's cert
issue alice alice-leaf-2 al2.pem
"$OSSL" cmp -cmd rr "${SRV[@]}" -cert bob.pem -key bob.key \
    -oldcert al2.pem -revreason 1 >/dev/null 2>&1
chk "non-owner standard user refused" good "$(ocsp al2.pem)"

# c) a caller holding cert:revoke may revoke anyone's cert
issue bob bob-leaf-1 bo1.pem
"$OSSL" cmp -cmd rr "${SRV[@]}" -cert boss.pem -key boss.key \
    -oldcert bo1.pem -revreason 1 >/dev/null 2>&1
chk "cert:revoke holder may revoke another's cert" revoked "$(ocsp bo1.pem)"

# d) PBM-protected rr refused (PBM is for enrollment only)
"$OSSL" cmp -cmd rr "${SRV[@]}" -secret "pass:$GLOBAL" -ref alice \
    -oldcert al2.pem -revreason 1 >/dev/null 2>&1
chk "PBM-protected revocation refused" good "$(ocsp al2.pem)"

# e) unprotected rr refused
"$OSSL" cmp -cmd rr "${SRV[@]}" -unprotected_requests -ref 1 \
    -oldcert al2.pem -revreason 1 >/dev/null 2>&1
chk "unprotected revocation refused" good "$(ocsp al2.pem)"

echo
echo "=== CMP AUTHZ: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
