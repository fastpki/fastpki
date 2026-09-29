#!/usr/bin/env bash
# RFC 9810 (CMPv3) conformance slice for fastpki-cmp:
#   * the standardized /.well-known/cmp HTTP endpoint (RFC 6712 / RFC 9483 §6)
#   * Content-Type matched per RFC 7231 (case-insensitive, parameters ignored)
#   * genm support messages: id-it-caCerts AND id-it-rootCaCert (RFC 9810 §5.3.19)
#
# Note: the OpenSSL `cmp` client's `-infotype rootCaCert` actually expects an
# id-it-rootCaKeyUpdate ITAV back, so we verify the (correct) id-it-rootCaCert
# response by replaying the captured request and decoding the GENP ourselves.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
# These suites use -trusted, not -srvcert. Responses are protected by the RA
# credential now, so pinning the CA as the exact server cert can never match; the
# client validates the chain RA -> CA against that anchor instead.
BIN="$ROOT/build/fastpki-cmp"
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
W="$(mktemp -d)"; cd "$W"; PORT=18096
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# Distinct root + signing CA so a rootCaCert response is distinguishable.
# CA fixtures must be marked as CAs (basicConstraints CA:TRUE) — the CMP client's
# genm-caCerts validation rejects a returned cert that isn't a CA. macOS `req -x509`
# does not add it from its openssl.cnf the way Alpine/CI does, so set it explicitly.
# (No explicit keyUsage: the CMP server SIGNS responses with the signing-CA key, so
# the cert must not forbid digitalSignature — an unrestricted KU is correct here.)
# The signing CA is ACTUALLY SIGNED BY the root. It used to be a second,
# unrelated self-signed CA, with ROOT_CA_PEM simply pointing at the other file — which
# worked only because the old id-it-rootCaCert answer was "whatever file was configured",
# related to the signing CA or not. The anchor now comes from the certificates
# themselves, so the fixture has to be a real hierarchy, which is also what a deployment
# looks like. Capture the root's key URI before minting the sub: $CA_KEY_URI holds the
# LAST key ca_in_token minted.
ca_in_token root_ca.pem "/CN=Test Root CA" 3650 rfc9810root
RFC9810_ROOT_KEY="$CA_KEY_URI"
ca_in_token signing_ca.pem "/CN=Test Signing CA" 3650 ca root_ca.pem "$RFC9810_ROOT_KEY"
# CMP has no CA-key fallback, so it needs an RA credential — and it must be issued
# by the SIGNING CA, not the root. The client anchors on signing_ca.pem (-trusted below),
# so a root-issued RA would chain past that anchor and every exchange would fail
# validation. Publish once the DB exists.
cmp_ra_issue signing_ca.pem "$CA_KEY_URI" || { echo "SKIP: no CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
pg_setup cmp_rfc9810
cmp_ra_publish || { echo "SKIP: could not publish the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "example.org\ninternal\nlocal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
cat > bootstrap.conf <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$W/signing_ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root_ca.pem
PG_CONNINFO=$PG_CONNINFO
CMP_BIND=127.0.0.1
CMP_PORT=$PORT
CMP_PATH=/cmp
CERT_VALIDITY_DAYS=365
LOG_LEVEL=er
EOF
cmp_ra_conf_lines >> bootstrap.conf   # CMP protects responses with the RA credential
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
# ⚠️ THE ROOT HAS TO BE A REGISTERED CA TOO, or the hierarchy exists only as files. The
# id-it-rootCaCert answer walks get_ca_ancestor_ders(), which matches a parent's subject hash
# to this certificate's issuer hash among rows that are is_ca with a non-null id. With the root
# absent the walk returns nothing, the server correctly falls back to "this CA IS the root" and
# answers with the SIGNING CA — so the two-tier fixture this suite builds above was never
# actually exercised, and the old assertion could not tell because it only checked that SOME
# certificate came back.
#
# Registered through `fastpki-ca add`, not a hand-written INSERT: insert_cert is what computes
# sHash/iHash, and a row seeded without them can never have a parent found for it. That is the
# trap pg_helpers.sh records at seed_ca_from_conf.
"${FASTPKI_CA_BIN:-$ROOT/build/fastpki-ca}" --config "$W/bootstrap.conf" \
    add rfc9810root --name rfc9810root \
    --ca-pem "$W/root_ca.pem" --ca-key "$RFC9810_ROOT_KEY" >/dev/null 2>&1 \
  || { echo "SKIP: could not register the root CA"; echo "PASS=0 FAIL=0"; exit 0; }
cmp_seed_pbm cmp-rfc9810
"$BIN" --config "$W/bootstrap.conf" >srv.log 2>&1 & SRV=$!
sleep 1; trap 'pg_cleanup; kill "$SRV" 2>/dev/null' EXIT
if ! kill -0 "$SRV" 2>/dev/null; then echo "fastpki-cmp died:"; cat srv.log; exit 1; fi

WK="http://127.0.0.1:$PORT/.well-known/cmp/ca"
LEG="http://127.0.0.1:$PORT/cmp/ca"
# -expect_sender names the RA, because that is what RA mode MEANS — the response
# is protected by the RA credential, not by the CA the request was addressed to. Without it
# the client issues the certificate, then throws the response away with "no suitable sender
# cert: for msg sender name = /CN=cmp-ra.test", which reads like a server fault and is not.
# -trusted still anchors on the signing CA, so the RA is validated by chaining to it.
# Two changes, both forced by RA mode rather than by this suite's subject matter.
#   -expect_sender names the RA, because that is what RA mode MEANS: the response is
#     protected by the RA credential, not by the CA the request was addressed to.
#   -trusted must reach a SELF-SIGNED anchor. signing_ca.pem is issued by the root, so it
#     cannot be a bare trust anchor — the RA chain is RA -> signing CA -> root, and
#     OpenSSL reported the RA as "potentially invalid certificate" when handed only the
#     intermediate. Anchor on the root and supply the intermediate as untrusted.
cat root_ca.pem signing_ca.pem > ra_trust.pem
ENR=(-recipient "/CN=Test Signing CA" -trusted ra_trust.pem -expect_sender "/CN=cmp-ra.test" \
     -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0)
# ⚠️ GEN used to append `-ref genmclient`, needed only because these were UNPROTECTED
# requests with no subject to identify the sender. Now that genm is PBM-protected
# that second -ref OVERRIDES the seeded one, so the server looks up a kid with no `keys`
# row, installs no secret, and the MAC fails — five assertions red for a reason none of
# them is testing. genm authenticates as the same reference as everything else.
GEN=("${ENR[@]}")

echo "=== ir over the standardized /.well-known/cmp endpoint ==="
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client.key >/dev/null 2>&1
"$OSSL" cmp -cmd ir -server "$WK" "${ENR[@]}" \
    -newkey client.key -subject "/CN=wk.example.org" -certout wk.pem >ir.log 2>&1
chk "ir over /.well-known/cmp issues a cert" yes "$([ -f wk.pem ] && echo yes || echo no)"
chk "issued cert subject correct" "subject=CN=wk.example.org" \
    "$([ -f wk.pem ] && "$OSSL" x509 -in wk.pem -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/ //g')"

echo "=== genm id-it-caCerts (well-known) ==="
"$OSSL" cmp -cmd genm -infotype caCerts -server "$WK" "${GEN[@]}" \
    -cacertsout cacerts.pem >genm_ca.log 2>&1; rc=$?
chk "genm caCerts succeeds" 0 "$rc"
chk "genm caCerts returns the signing CA" yes \
    "$([ -f cacerts.pem ] && "$OSSL" x509 -in cacerts.pem -noout -subject 2>/dev/null | grep -q 'Test Signing CA' && echo yes || echo no)"

echo "=== genm id-it-rootCaCert (RFC 9810) ==="
# Capture the request, replay it, and decode the GENP — the server returns the
# (correct) id-it-rootCaCert ITAV carrying the configured root CA.
"$OSSL" cmp -cmd genm -infotype rootCaCert -server "$LEG" "${GEN[@]}" -newwithnew nw.pem -reqout rootreq.der >/dev/null 2>&1
chk "captured a rootCaCert genm request" yes "$([ -s rootreq.der ] && echo yes || echo no)"
curl -s -o rootresp.der -H 'Content-Type: application/pkixcmp' --data-binary @rootreq.der "$LEG"  # replay genp
# ⚠️ READ THE ITAV, DO NOT GREP THE DUMP. Every response carries the RA credential's issuer
# chain in extraCerts, and here that is the signing CA — whose ISSUER RDN is CN=Test Root CA
# and which asn1parse prints verbatim. So "Test Root CA appears somewhere in the recursive
# dump" was true of a GENP with no rootCaCert ITAV at all, of one answering with the signing
# CA instead of the root, and of an error PKIMessage. Locate the id-it-rootCaCert ITAV by its
# own OID, lift the certificate that follows it out of the response with the dump's
# offset/header/length columns, and name the subject it turns out to hold.
itav_cert() {   # <oid-regex> <out.der> -> cuts that ITAV's certificate out of rootresp.der
    local oid="$1" out="$2" off hl len line
    line=$("$OSSL" asn1parse -inform DER -in rootresp.der 2>/dev/null \
           | awk -v oid="$oid" '$0 ~ ("OBJECT  *: *" oid "$") { seen=1; next }
                                seen && /cons: *SEQUENCE/ { print; exit }' \
           | sed -n 's/^ *\([0-9][0-9]*\):d=[0-9][0-9]* *hl=\([0-9][0-9]*\) *l= *\([0-9][0-9]*\).*/\1 \2 \3/p')
    [ -n "$line" ] || return 1
    set -- $line; off="$1"; hl="$2"; len="$3"
    rm -f "$out"
    dd if=rootresp.der of="$out" bs=1 skip="$off" count=$((hl + len)) 2>/dev/null
    [ -s "$out" ]
}
# Both spellings: $OSSL knows the name, a build that does not prints the dotted OID.
ROOTITAV_SUBJ=$(itav_cert '(id-it-rootCaCert|1.3.6.1.5.5.7.4.20)' rootitav.der \
                && "$OSSL" x509 -inform DER -in rootitav.der -noout -subject -nameopt RFC2253 \
                   2>/dev/null | sed 's/^subject= *//')
chk "rootCaCert ITAV carries the root CA" "CN=Test Root CA" "$ROOTITAV_SUBJ"
# Cross-check the two support messages return different material: the caCerts
# response (saved above) carries the signing CA only, not the root. (The root
# only appears in the rootCaCert ITAV; the signing CA shows in both responses'
# extraCerts because it signs them — so we compare the ITAV payloads.)
chk "caCerts response excludes the root CA" no \
    "$("$OSSL" x509 -in cacerts.pem -noout -subject 2>/dev/null | grep -q 'Test Root CA' && echo yes || echo no)"

echo "=== Content-Type tolerance (RFC 7231) ==="
"$OSSL" cmp -cmd genm -infotype caCerts -server "$LEG" "${GEN[@]}" -cacertsout /dev/null -reqout genm.der >/dev/null 2>&1
chk "captured a genm request" yes "$([ -s genm.der ] && echo yes || echo no)"
ct(){ curl -s -o /dev/null -w '%{http_code}' -H "Content-Type: $1" --data-binary @genm.der "$LEG"; }
chk "exact application/pkixcmp -> 200"   200 "$(ct 'application/pkixcmp')"
chk "with charset parameter -> 200"      200 "$(ct 'application/pkixcmp; charset=utf-8')"
chk "uppercase media type -> 200"        200 "$(ct 'APPLICATION/PKIXCMP')"
chk "wrong media type -> 415"            415 "$(ct 'application/json')"
chk "missing Content-Type -> 415"        415 "$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type:' --data-binary @genm.der "$LEG")"

echo "=== genm id-it-crlStatusList -> id-it-crls (RFC 9483 §4.3.4, OpenSSL >= 3.5) ==="
# The server answers a crlStatusList genm with this CA instance's current CRL.
"$OSSL" cmp -cmd genm -infotype crlStatusList -server "$WK" "${GEN[@]}" \
    -crlcert wk.pem -crlout received.crl -crlform PEM >genm_crl.log 2>&1; rc=$?
chk "genm crlStatusList succeeds" 0 "$rc"
chk "received a CA-signed CRL over CMP" yes \
    "$([ -s received.crl ] && "$OSSL" crl -in received.crl -noout -issuer 2>/dev/null | grep -q 'Test Signing CA' && echo yes || echo no)"

echo "=== central key generation is refused (RFC 9483: no server-side keygen) ==="
"$OSSL" cmp -cmd cr -server "$WK" "${ENR[@]}" -subject "/CN=ckg.example.org" \
    -centralkeygen -newkeyout ckg.key -certout ckg.pem >ckg.log 2>&1; rc=$?
chk "central-keygen request fails (non-zero exit)" yes "$([ "$rc" -ne 0 ] && echo yes || echo no)"
chk "no cert issued for central-keygen request" yes "$([ ! -s ckg.pem ] && echo yes || echo no)"

echo "=== RFC 9483 certProfile: honored only if authorized ==="
# A certProfile that matches the identity's effective profile (here the role
# default 'requester') is honored.
"$OSSL" cmp -cmd ir -server "$WK" "${ENR[@]}" -newkey client.key \
    -subject "/CN=prof-ok.example.org" -profile requester -certout prof_ok.pem >prof_ok.log 2>&1
chk "ir -profile requester (matches default) issues" yes "$([ -f prof_ok.pem ] && echo yes || echo no)"
# Requesting a more permissive profile the identity is NOT assigned is refused
# (no escalation): 'admin' allows wildcards, 'requester' does not.
"$OSSL" cmp -cmd ir -server "$WK" "${ENR[@]}" -newkey client.key \
    -subject "/CN=prof-esc.example.org" -profile admin -certout prof_esc.pem >prof_esc.log 2>&1; rc=$?
chk "ir -profile admin (escalation) is refused" yes "$([ "$rc" -ne 0 ] && echo yes || echo no)"
chk "no cert issued for the unauthorized profile" yes "$([ ! -s prof_esc.pem ] && echo yes || echo no)"

echo "=== legacy /cmp path still works (regression) ==="
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client2.key >/dev/null 2>&1
"$OSSL" cmp -cmd ir -server "$LEG" "${ENR[@]}" \
    -newkey client2.key -subject "/CN=legacy.example.org" -certout leg.pem >ir2.log 2>&1
chk "ir over legacy /cmp still issues" yes "$([ -f leg.pem ] && echo yes || echo no)"

echo
echo "=== CMP RFC9810: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
