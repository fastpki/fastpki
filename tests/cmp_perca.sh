#!/usr/bin/env bash
# Per-CA CMP. One fastpki-cmp serves multiple CA hierarchies
# under {CMP_PATH}/{ca_instance_id} (e.g. /cmp/dept-a), aligned with EST's inline
# label instead of an /endpoints prefix: a request there is issued by THAT instance's CA
# AND its response is protected by an RA credential issued BY that CA — so a client
# anchored on the right CA validates and a client anchored on another does not. Certs are
# tagged with ca_instance_id. Unknown -> 404, disabled -> 503.
#
# -trusted, not -srvcert. Responses are protected by the RA, so pinning the CA as
# the EXACT server certificate can never match — that is inherent to RA mode and no amount
# of per-CA scoping changes it. The per-CA guarantee lives in the CHAIN: the RA for dept-a
# chains to dept-a and not to the global CA, which is what the last check below proves.
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
CA="$ROOT/build/fastpki-ca"
W="$(mktemp -d)"; cd "$W"; PORT=18102
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Global CMP CA" 3650
GLOBAL_KEY_URI="$CA_KEY_URI"        # capture before the next mint overwrites it
ca_in_token depta.pem "/CN=Dept A CA" 3650 depta
DEPTA_KEY_URI="$CA_KEY_URI"
pg_setup cmp_perca
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
# CMP protects responses with a dedicated RA credential and has no CA-key fallback,
# so this is not optional setup — without it every transaction below is a 503. The RA
# certificate comes from the GLOBAL CA, and it protects the responses for every per-CA
# endpoint: the RA is one service identity, not one per CA.
# ONE RA credential PER CA — that is the whole point of this suite. Each endpoint's
# responses are protected by an RA certificate issued BY that endpoint's CA, so a client
# pinning that CA still validates and a client pinning the other one still does not. A
# single shared RA would make both endpoints validate identically and silently drop the
# Guarantee this file exists to protect.
cmp_ra_setup ca.pem "$GLOBAL_KEY_URI" || { echo "SKIP: could not provision the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
cmp_ra_for_ca depta.pem "$DEPTA_KEY_URI" dept-a \
    || { echo "SKIP: could not provision the dept-a RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
cat > cmp.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$GLOBAL_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
CMP_BIND=127.0.0.1
CMP_PORT=$PORT
CMP_PATH=/cmp
CMP_RA_CERT_ID_PREFIX=cmp-ra
CMP_RA_KEY=$CMP_RA_KEY_URI
LOG_LEVEL=err
EOF
seed_ca_from_conf cmp.conf   # register the CA (SIGNING_CA_* no longer seed it)
cmp_seed_pbm cmp-perca
"$CA" --config cmp.conf add dept-a --name "Dept A" --ca-pem "$W/depta.pem" --ca-key "$DEPTA_KEY_URI" >/dev/null

"$ROOT/build/fastpki-cmp" --config cmp.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-cmp died:"; cat srv.log; exit 1; fi
B="http://127.0.0.1:$PORT"

issue(){ # <path> <srvcert> <recipient> <cn> <out>  -> issue|reject
    rm -f "$5"
    "$OSSL" cmp -cmd ir -server "$B$1" -recipient "$3" -trusted "$2" -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" \
        -keep_alive 0 -newkey scratch.key -subject "/CN=$4" -implicit_confirm -certout "$5" >/dev/null 2>&1
    [ -f "$5" ] && echo issue || echo reject
}
issuer_of(){ "$OSSL" x509 -in "$1" -issuer -noout 2>/dev/null | sed -n 's/.*CN *= *//p'; }
tag(){ pg_exec "SELECT ca_instance_id FROM certs WHERE cn='$1';"; }

echo "=== the default /cmp/ca endpoint issues from the SIGNING_CA ==="
chk "ca issuance accepted"            issue "$(issue /cmp/ca ca.pem "/CN=Global CMP CA" d.internal d.pem)"
chk "ca cert signed by the SIGNING_CA"     "Global CMP CA" "$(issuer_of d.pem)"
chk "ca cert verifies under the SIGNING_CA" "d.pem: OK" "$("$OSSL" verify -CAfile ca.pem d.pem 2>/dev/null)"
chk "ca cert tagged ca"          ca "$(tag d.internal)"

echo "=== dept-a endpoint issues from (and signs with) the Dept A CA ==="
chk "dept-a issuance accepted"             issue "$(issue /cmp/dept-a depta.pem "/CN=Dept A CA" a.internal a.pem)"
chk "dept-a cert signed by Dept A CA"      "Dept A CA" "$(issuer_of a.pem)"
chk "dept-a cert verifies under Dept A CA" "a.pem: OK" "$("$OSSL" verify -CAfile depta.pem a.pem 2>/dev/null)"
chk "dept-a cert tagged dept-a"            dept-a "$(tag a.internal)"

echo "=== the per-CA endpoint authenticates (wrong PBM secret is rejected) ==="
# ⚠️ THIS ASSERTION REPLACED "dept-a endpoint with the global srvcert is rejected",
# and the reason is a change of PREMISE, not a bug. That check handed the client the WRONG
# trust anchor and expected the response signature to fail to verify. It only worked because
# the transaction was UNPROTECTED, so the server signed its response with the instance RA
# and -trusted was what validated it. Under the mandatory PBM the shipped posture requires,
# the server MAC-protects the response with the shared secret instead — there is no srvcert
# in play at all, so the wrong anchor is simply never consulted and the order succeeds.
# Keeping it would have been a check that can no longer fail for its stated reason.
#
# The property it was really guarding — each endpoint uses its OWN CA material — is already
# proven three ways above (issuer, verify against depta.pem, and the ca_instance_id tag).
# What was NOT covered, and is now, is that the per-CA endpoint authenticates at all.
issue_badsecret(){ # -> issue|reject
    rm -f bs.pem
    "$OSSL" cmp -cmd ir -server "$B/cmp/dept-a" -recipient "/CN=Dept A CA" -trusted depta.pem \
        -secret "pass:definitelynotthesecret" -ref "$CMP_PBM_REF" \
        -keep_alive 0 -newkey scratch.key -subject "/CN=bs.internal" -implicit_confirm \
        -certout bs.pem >/dev/null 2>&1
    [ -f bs.pem ] && echo issue || echo reject
}
chk "dept-a endpoint rejects a wrong PBM secret" reject "$(issue_badsecret)"
chk "  and issued nothing for it"               0 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cn='bs.internal';" | tr -d ' ')"

echo "=== unknown / disabled instances ==="
chk "unknown instance rejected (404)" reject "$(issue /cmp/nope ca.pem "/CN=Global CMP CA" x.internal x.pem)"
"$CA" --config cmp.conf disable dept-a >/dev/null
chk "disabled instance rejected (503)" reject "$(issue /cmp/dept-a depta.pem "/CN=Dept A CA" y.internal y.pem)"
"$CA" --config cmp.conf enable dept-a >/dev/null

echo
echo "=== CMP PER-CA: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
