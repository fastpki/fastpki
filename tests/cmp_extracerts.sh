#!/usr/bin/env bash
# ⚠️ SCOPE, because deleting this key was once proposed on the belief that the chain work had made it
# inert, and that was agreed before I found the premise was wrong. This suite
# runs the server in DIRECT CA mode, with no RA credential, and there the key governs
# extraCerts completely — measured 3/0. What became unconditional is the PROTECTION
# chain (the RA credential's issuer), which is a different field's worth of certificates
# and is pinned by tests/cmp_ra_chain.sh — that suite deliberately leaves this key OFF and
# still requires the RA's issuer to arrive. The two coincide only when the RA and the leaf
# share an issuer, which is why one looked like the other.
#
# Regression: with CMP_EXTRACERTS_CA=true the CMP server returns
# the signing CA in the response's extraCerts (chainOut), so a bootstrapping
# client can build the chain; with =false it does not.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
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
W="$(mktemp -d)"; cd "$W"; PORT=18108
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Extra CA" 3650
# CMP has no CA-key fallback — issue the RA credential from THIS CA
# while CA_KEY_URI still names it, and publish it once the DB exists.
cmp_ra_issue ca.pem "$CA_KEY_URI" || { echo "SKIP: no CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
cp ca.pem root.pem
pg_setup cmp_extracerts
cmp_ra_publish || { echo "SKIP: could not publish the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
seed_domains $W/domains.txt   # allowed_domains is the sole source
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt

run_ir() { # extracerts_flag  outfile  -> writes extracerts to $2
    local flag="$1" out="$2"
    # Reset the issued certs between cases, but NOT the RA credential — that row is
    # infrastructure, not test data, and wiping it leaves fastpki-cmp with no identity to
    # protect responses with, so every case below 503s.
    pg_exec "DELETE FROM certs WHERE cert_id IS DISTINCT FROM 'cmp-ra-ca';"
    printf "SIGNING_CA_PEM=%s/ca.pem\nSIGNING_CA_KEY=$CA_KEY_URI\nSIGNING_CA_ID=ca\nROOT_CA_PEM=%s/root.pem\nPG_CONNINFO=%s\nCMP_BIND=127.0.0.1\nCMP_PORT=%s\nCMP_PATH=/cmp\nCMP_EXTRACERTS_CA=%s\nLOG_LEVEL=err\n" \
        "$W" "$W" "$PG_CONNINFO" "$PORT" "$flag" > cmp.conf
    seed_ca_from_conf cmp.conf   # register CA 'ca' (SIGNING_CA_* no longer seed it)
    cmp_seed_pbm cmp-extracerts
    cmp_ra_conf_lines >> cmp.conf
    "$ROOT/build/fastpki-cmp" --config cmp.conf >srv.log 2>&1 & local C=$!
    # Wait for the listener instead of sleeping at it. A server still binding answers
    # nothing, and an ir that never happened writes no extracerts file at all — which the
    # =false leg below would otherwise read as "the signing CA was not sent".
    wait_port "$PORT" "$C" || true
    # leaf.pem goes with it: it is this run's proof that a transaction completed, and left
    # over from the previous leg it would vouch for a run that never reached the server.
    rm -f "$out" leaf.pem "ir_$flag.log"
    "$OSSL" cmp -cmd ir -server "http://127.0.0.1:$PORT/cmp/ca" -recipient "/CN=Extra CA" \
        -trusted ca.pem -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
        -newkey scratch.key -subject "/CN=host.internal" -certout leaf.pem -extracertsout "$out" \
        >"ir_$flag.log" 2>&1
    kill $C 2>/dev/null; wait $C 2>/dev/null
    for i in $(seq 1 20); do ss -tan 2>/dev/null | grep -q ":$PORT " || break; sleep 0.5; done
}
ca_in() { # file -> yes if it contains a cert whose subject is the signing CA
    [ -f "$1" ] || { echo no; return; }
    "$OSSL" crl2pkcs7 -nocrl -certfile "$1" 2>/dev/null | "$OSSL" pkcs7 -print_certs -noout 2>/dev/null \
        | grep -q "subject=CN *= *Extra CA" && echo yes || echo no
}

echo "=== CMP_EXTRACERTS_CA=true ==="
run_ir true extra_true.pem
chk "issued a cert" ok "$( [ -s leaf.pem ] && echo ok || echo no )"
chk "signing CA returned in extraCerts" yes "$(ca_in extra_true.pem)"

echo "=== CMP_EXTRACERTS_CA=false ==="
run_ir false extra_false.pem
# ⚠️ THE CONTROL CARRIES THIS LEG, and it is not decoration. ca_in reports "no" for a file
# that was never written, and openssl writes no extracerts file unless a response arrived —
# so on its own "the signing CA is NOT in extraCerts" is equally what a server that failed
# to start, 503'd for a missing RA credential, or rejected the rotated PBM secret produces.
# The negative leg then passed with the flag never exercised. run_ir deletes leaf.pem first,
# so this certificate can only be the one THIS run issued.
# The control has to be the certificate rather than a non-empty extracerts file: with the RA
# issued straight off the self-signed Extra CA the RA's issuer chain is empty, and OpenSSL
# moves the validated protection signer out of extraCertsIn (tests/cmp_ra_chain.sh measures
# that), so a correct =false response legitimately leaves nothing to dump.
chk "issued a cert (so this leg's transaction really happened)" ok "$( [ -s leaf.pem ] && echo ok || echo no )"
chk "signing CA NOT in extraCerts" no "$(ca_in extra_false.pem)"
[ -s leaf.pem ] || { echo "  --- ir_false.log ---"; tail -8 ir_false.log 2>/dev/null; \
                     echo "  --- srv.log ---"; tail -8 srv.log 2>/dev/null; }

echo
echo "=== CMP EXTRACERTS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
