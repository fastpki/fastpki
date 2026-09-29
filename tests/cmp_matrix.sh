#!/usr/bin/env bash
# CMP coverage matrix — reworks the use-cases of cmp_client/tests.php into our
# environment (not a literal port). Covers:
#   commands : ir (bootstrap), cr, kur, rr, genm, p10cr
#   profiles : key types (rsa2048/rsa1024/ec256/ec384) x SAN profiles
#              (none / DNS / multi-DNS / 10.x IP / mixed / public / 192.168 /
#              wildcard) — collapsing the 35 redundant ext sections into the
#              distinct behaviours they exercise
#   integration: every issued cert -> `openssl verify` (chain) -> `openssl ocsp`
#                (status), mirroring the PHP cross-protocol check.
# Verdicts: PASS / GAP (should-reject but issued) / FAIL (should-issue but rejected).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
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
W="$(mktemp -d)"; cd "$W"; CMP_PORT=18085; OCSP_PORT=18080

pass=0; gap=0; fail=0; integ_ok=0; integ_bad=0
verdict() { # name expect got
    local v
    if [ "$2" = "$3" ]; then v=PASS; pass=$((pass+1))
    elif [ "$2" = reject ] && [ "$3" = issue ]; then v=GAP; gap=$((gap+1))
    else v=FAIL; fail=$((fail+1)); fi
    printf "  %-34s expect=%-6s got=%-6s [%s]\n" "$1" "$2" "$3" "$v"
}

# CA fixture must be marked as a CA (basicConstraints CA:TRUE): the CMP client's
# genm-caCerts check and `openssl verify` both reject a non-CA issuer. macOS `req
# -x509` doesn't add it from its openssl.cnf the way Alpine/CI does, so set it here.
ca_in_token ca.pem "/CN=Matrix CA" 3650
# CMP has no CA-key fallback — issue the RA credential from THIS CA
# while CA_KEY_URI still names it, and publish it once the DB exists.
cmp_ra_issue ca.pem "$CA_KEY_URI" || { echo "SKIP: no CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
pg_setup cmp_matrix
cmp_ra_publish || { echo "SKIP: could not publish the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\nlocal\nexample.org\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source

common="SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
LOG_LEVEL=err"
printf "%s
CMP_BIND=127.0.0.1
CMP_PORT=%s
CMP_PATH=/cmp
CMP_CLIENT_CA_ID=ca
" "$common" "$CMP_PORT" > cmp.conf
printf "%s\nOCSP_BIND=127.0.0.1\nOCSP_PORT=%s\n" "$common" "$OCSP_PORT" > ocsp.conf
seed_ca_from_conf cmp.conf   # register CA 'ca' (SIGNING_CA_* no longer seed it)
# The reference doubles as the `owner`, and the ownership rule wants an identity cert
# whose CN equals it — so it has to be a name policy will issue.
cmp_seed_pbm owner.example.internal
# Slice B: the CA key never signs a status response, so the responder needs its
# own certificate issued BY this CA -- otherwise fastpki-ocsp refuses every query.
printf 'OCSP_RESPONDER_KEY=%s\n' "$(ocsp_responder_key "$W/ca.pem" "$CA_KEY_URI" ca "$W")" >> ocsp.conf

cmp_ra_conf_lines >> cmp.conf
"$ROOT/build/fastpki-cmp"  --config cmp.conf  >cmp.log  2>&1 & C=$!
"$ROOT/build/fastpki-ocsp" --config ocsp.conf >ocsp.log 2>&1 & O=$!
sleep 1; trap 'pg_cleanup; kill $C $O 2>/dev/null' EXIT

# keys
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out k_rsa2048.pem >/dev/null 2>&1
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out k_rsa1024.pem >/dev/null 2>&1
"$OSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out k_ec256.pem >/dev/null 2>&1
"$OSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out k_ec384.pem >/dev/null 2>&1

cmp_cr() { # cmd subject sans keyfile outfile
    local cmd="$1" subj="$2" sans="$3" kf="$4" out="$5"; rm -f "$out"
    local sanopt=""; [ -n "$sans" ] && sanopt="-sans $sans"
    "$OSSL" cmp -cmd "$cmd" -server "http://127.0.0.1:$CMP_PORT/cmp/ca" -recipient "/CN=Matrix CA" \
        -trusted ca.pem -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
        -newkey "$kf" -subject "/CN=$subj" $sanopt -certout "$out" >/dev/null 2>&1
    [ -f "$out" ] && echo issue || echo reject
}
integ() { # issued.pem  -> verify chain + OCSP good
    "$OSSL" verify -CAfile ca.pem "$1" >/dev/null 2>&1 && local v=ok || local v=bad
    local st; st=$("$OSSL" ocsp -issuer ca.pem -cert "$1" -url "http://127.0.0.1:$OCSP_PORT/ocsp" -noverify 2>/dev/null | grep -oE "good|revoked" | head -1)
    if [ "$v" = ok ] && [ "$st" = good ]; then integ_ok=$((integ_ok+1)); else integ_bad=$((integ_bad+1)); echo "      integration FAIL: verify=$v ocsp=$st"; fi
}

echo "=== CMP cr profile matrix (key x SAN) ==="
run() { # name subject sans keyfile expect
    local got; got=$(cmp_cr cr "$2" "$3" "$4" out.pem)
    verdict "$1" "$5" "$got"
    [ "$got" = issue ] && integ out.pem
}
run "cn-only rsa2048"      test.example.internal ""                                 k_rsa2048.pem issue
run "dns SAN rsa2048"      test.example.internal "test2.example.internal"           k_rsa2048.pem issue
run "multi-DNS rsa2048"    test.example.internal "a.example.internal,b.example.internal" k_rsa2048.pem issue
run "10.x IP SAN"          test.example.internal "10.2.3.4"                         k_rsa2048.pem issue
run "DNS+10.x mixed"       test.example.internal "test2.example.internal,10.2.3.4"  k_rsa2048.pem issue
run "ec256"                test.example.internal ""                                 k_ec256.pem   issue
run "ec384"                test.example.internal ""                                 k_ec384.pem   issue
run "public CN (google)"   test.google.com       ""                                 k_rsa2048.pem reject
run "public SAN"           test.example.internal "evil.google.com"                  k_rsa2048.pem reject
run "192.168 IP SAN"       test.example.internal "192.168.1.1"                      k_rsa2048.pem reject
run "wildcard (standard)"  '\*.example.internal' ""                                 k_rsa2048.pem reject
run "rsa1024 (min size)"   test.example.internal ""                                 k_rsa1024.pem reject

echo "=== CMP other commands ==="
# ir bootstrap (issue) — also used as the cert to update/revoke
ir=$(cmp_cr ir boot.example.internal "" k_rsa2048.pem boot.pem); verdict "ir bootstrap" issue "$ir"
# kur: key update of an existing cert
kur=reject
if [ -f boot.pem ]; then
    "$OSSL" cmp -cmd kur -server "http://127.0.0.1:$CMP_PORT/cmp/ca" -recipient "/CN=Matrix CA" \
        -trusted ca.pem -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
        -oldcert boot.pem -newkey k_ec256.pem -certout kur.pem >/dev/null 2>&1
    [ -f kur.pem ] && kur=issue
fi
verdict "kur (key update)" issue "$kur"
# p10cr: PKCS#10-based request
"$OSSL" req -new -key k_rsa2048.pem -subj "/CN=p10.example.internal" -out p10.csr >/dev/null 2>&1
"$OSSL" cmp -cmd p10cr -server "http://127.0.0.1:$CMP_PORT/cmp/ca" -recipient "/CN=Matrix CA" \
    -trusted ca.pem -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 -csr p10.csr -certout p10.pem >/dev/null 2>&1
verdict "p10cr" issue "$( [ -f p10.pem ] && echo issue || echo reject )"
# rr: revoke the bootstrap cert, confirm via OCSP
# ⚠️ REVOCATION IS SIGNATURE-PROTECTED. PBM is enrolment-only, so an rr sent over
# PBM is refused by design — this suite used to get away with it because
# CMP_ACCEPT_UNPROTECTED=true ALSO switched off the whole rr authorization block (PBM
# refusal, signer identity, ownership). Mint an identity certificate whose CN equals the
# enrolment reference — that reference is the `owner` recorded on what we are revoking —
# and sign the rr with it, which is what a real client does.
if [ -f boot.pem ]; then
    "$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out id.key >/dev/null 2>&1
    "$OSSL" cmp -cmd ir -server "http://127.0.0.1:$CMP_PORT/cmp/ca" -recipient "/CN=Matrix CA" \
        -trusted ca.pem -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
        -newkey id.key -subject "/CN=$CMP_PBM_REF" -certout id.pem >/dev/null 2>&1
    "$OSSL" cmp -cmd rr -server "http://127.0.0.1:$CMP_PORT/cmp/ca" -recipient "/CN=Matrix CA" \
        -trusted ca.pem -cert id.pem -key id.key -keep_alive 0 -oldcert boot.pem >/dev/null 2>&1
    st=$("$OSSL" ocsp -issuer ca.pem -cert boot.pem -url "http://127.0.0.1:$OCSP_PORT/ocsp" -noverify 2>/dev/null | grep -oE "good|revoked" | head -1)
    verdict "rr -> OCSP revoked" revoked "${st:-good}"
fi
# genm: get CA certs — assert the CA cert content actually comes back
# (client saves it via -cacertsout).
rm -f gm_ca.pem
"$OSSL" cmp -cmd genm -infotype caCerts -server "http://127.0.0.1:$CMP_PORT/cmp/ca" \
    -recipient "/CN=Matrix CA" -trusted ca.pem -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
    -cacertsout gm_ca.pem >/dev/null 2>&1 || true
gm=reject
{ [ -s gm_ca.pem ] && "$OSSL" x509 -in gm_ca.pem -noout -subject 2>/dev/null | grep -q "Matrix CA"; } && gm=issue
verdict "genm (get CA certs)" issue "$gm"

# Audit producers: CMP issuance + revocation must be logged.
AISS=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='cert_issued'  AND detail LIKE '%CMP%';")
AREV=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='cert_revoked' AND detail LIKE '%CMP%';")
[ "${AISS:-0}" -ge 1 ] && verdict "CMP issuance audited"   issue "issue" || verdict "CMP issuance audited"   issue "reject"
[ "${AREV:-0}" -ge 1 ] && verdict "CMP revocation audited" issue "issue" || verdict "CMP revocation audited" issue "reject"

echo
echo "=== SUMMARY: PASS=$pass  GAP=$gap  FAIL=$fail | integration(verify+OCSP): ok=$integ_ok bad=$integ_bad ==="
[ "$fail" -eq 0 ]
