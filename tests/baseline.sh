#!/usr/bin/env bash
# Consolidated "baseline" acceptance run, distilled from the PHP repo's
# functional suites (cmp_client/tests.php, est_client/tests.php). It focuses on
# the POLICY / negative checks those suites encode, run against the current
# fastpki binaries. Verdicts:
#   PASS  expected behaviour matched
#   GAP   server accepted something the policy should reject (missing policy)
#   FAIL  server rejected something it should accept (regression)
#
# Shares one certs.db across est + ocsp + cmp, mirroring the PHP cross-protocol
# checks (issue -> verify -> OCSP).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"   # real credentials, not AUTH_BACKEND=none
source "$ROOT/tests/service_cert_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"      # cmp_ra_issue / _publish / _conf_lines
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
W="$(mktemp -d)"; cd "$W"
EST_PORT=18443; OCSP_PORT=18080; CMP_PORT=18085

pass=0; gap=0; fail=0
verdict() { # name  expected(issue|reject|good|revoked)  actual
    local v
    if   [ "$2" = "$3" ]; then v=PASS; pass=$((pass+1))
    elif { [ "$2" = reject ] && [ "$3" = issue ]; } || \
         { [ "$2" = revoked ] && [ "$3" = good ]; }; then v=GAP; gap=$((gap+1))
    else v=FAIL; fail=$((fail+1)); fi
    printf "  %-46s expect=%-7s got=%-7s [%s]\n" "$1" "$2" "$3" "$v"
}

# --- CA + shared DB ---------------------------------------------------------
ca_in_token ca.pem "/CN=Baseline CA" 3650
cp ca.pem root.pem
# CMP has no CA-key fallback — it signs with its own RA credential or refuses every
# request. Issue it here, while CA_KEY_URI still names this CA; it is published below, once
# the database exists. Without it every CMP row of the matrix reads `reject`.
CMP_RA_OK=1
cmp_ra_issue ca.pem "$CA_KEY_URI" || CMP_RA_OK=
# EST is HTTPS-only (RFC 7030); the server needs its own TLS cert.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem \
    -days 3650 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup baseline
# AUTH_BACKEND=none is gone, so this suite authenticates for real.
seed_web_user tester secret requester
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "example.org\ninternal\nlocal\n" > "$W/domains.txt"
seed_domains $W/domains.txt   # allowed_domains is the sole source

mk_conf() { cat > "$W/$1.conf" <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
CERT_VALIDITY_DAYS=365
EST_BIND=127.0.0.1
EST_PORT=$EST_PORT
OCSP_BIND=127.0.0.1
OCSP_PORT=$OCSP_PORT
CMP_BIND=127.0.0.1
CMP_PORT=$CMP_PORT
CMP_PATH=/cmp
# Signature-protected revocation needs a client-cert anchor to validate against.
CMP_CLIENT_CA_ID=ca
LOG_LEVEL=err
EOF
}
mk_conf est; mk_conf ocsp; mk_conf cmp
# ⚠️ REGISTER THE CA. The implicit "a config key names a CA" path is gone: every CA is a
# row, and an enrolment request for /est/ca/... resolves that row or refuses. Without this
# line the SIGNING_CA_* keys above are just text in a file, no CA exists, and EST and CMP
# reject EVERYTHING.
#
# That is what this suite had been doing. It scored PASS=5 GAP=0 FAIL=6, and every one of
# the 5 passes was an "expect=reject" case passing because enrolment was broken, not because
# any policy fired. It is not in run_all.sh, so nothing noticed. One call, not three: the
# three configs share one database and the CA lives there.
seed_ca_from_conf "$W/est.conf"
cmp_seed_pbm owner.example.org
# Slice B: the CA key never signs a status response, so the responder needs its
# own certificate issued BY this CA -- otherwise fastpki-ocsp refuses every query.
printf 'OCSP_RESPONDER_KEY=%s\n' "$(ocsp_responder_key "$W/ca.pem" "$CA_KEY_URI" ca "$W")" >> "$W/ocsp.conf"
[ -n "$CMP_RA_OK" ] && cmp_ra_publish || CMP_RA_OK=
[ -n "$CMP_RA_OK" ] && cmp_ra_conf_lines >> "$W/cmp.conf"


"$ROOT/build/fastpki-est"  --config "$W/est.conf"  >est.log  2>&1 & E=$!
"$ROOT/build/fastpki-ocsp" --config "$W/ocsp.conf" >ocsp.log 2>&1 & O=$!
"$ROOT/build/fastpki-cmp"  --config "$W/cmp.conf"  >cmp.log  2>&1 & C=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "$W/est.conf" EST_PORT "$E" || true
trap 'pg_cleanup; kill $E $O $C 2>/dev/null' EXIT

# --- helper: EST enroll -> returns "issue" or "reject" ----------------------
est_enroll() { # subject  keyargs  [extargs]
    local subj="$1" kargs="$2" ext="${3:-}"
    "$OSSL" req -new -subj "/CN=$subj" $kargs $ext -keyout k.pem -nodes -out r.csr >/dev/null 2>&1 || { echo reject; return; }
    "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
    local out; out=$(curl -sk -u tester:secret --data-binary @r.b64 \
        -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$EST_PORT/.well-known/est/ca/simpleenroll" \
        | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null)
    if echo "$out" | grep -q "BEGIN CERTIFICATE"; then echo issue; else echo reject; fi
}

echo "=== EST policy matrix (from est_client/tests.php) ==="
verdict "EST rsa2048 internal"          issue  "$(est_enroll internal.example.org '-newkey rsa:2048')"
verdict "EST ec P-256 internal"         issue  "$(est_enroll internal.example.org '-newkey ec -pkeyopt ec_paramgen_curve:P-256')"
verdict "EST ec P-384 internal"         issue  "$(est_enroll internal.example.org '-newkey ec -pkeyopt ec_paramgen_curve:P-384')"
verdict "EST rsa1024 (below min size)"  reject "$(est_enroll internal.example.org '-newkey rsa:1024')"
verdict "EST public domain google.com"  reject "$(est_enroll test.google.com    '-newkey rsa:2048')"
verdict "EST wildcard *.example.org"    reject "$(est_enroll '*.example.org'     '-newkey rsa:2048')"
verdict "EST bad-domain SAN .com"       reject "$(est_enroll internal.example.org '-newkey rsa:2048' '-addext subjectAltName=DNS:evil.attacker.com')"
verdict "EST non-10.x IP SAN"           reject "$(est_enroll internal.example.org '-newkey rsa:2048' '-addext subjectAltName=IP:192.168.1.1')"
verdict "EST allowed 10.x IP SAN"       issue  "$(est_enroll internal.example.org '-newkey rsa:2048' '-addext subjectAltName=IP:10.2.3.4')"

echo "=== CMP commands (from cmp_client/tests.php) ==="
# ⚠️ `-trusted`, NOT `-srvcert`. The CMP server protects its responses with its
# own RA credential, not the CA key, so pinning the CA certificate as THE expected signer
# rejects every reply — the client fails before it ever looks at the certificate it was
# issued. The other seven CMP suites already moved to -trusted; this one was left behind.
cmp_run() { # cmd  extra...
    "$OSSL" cmp -cmd "$1" -server "http://127.0.0.1:$CMP_PORT/cmp/ca" \
        -recipient "/CN=Baseline CA" -trusted ca.pem -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" \
        -keep_alive 0 "${@:2}" 2>&1
}
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out cmpc.key >/dev/null 2>&1
ir=$(cmp_run ir -newkey cmpc.key -subject "/CN=cmp.example.org" -certout cmp.pem)
verdict "CMP ir (issue)"  issue  "$( [ -f cmp.pem ] && echo issue || echo reject )"

# rr: revoke the just-issued cert, then confirm via OCSP it reads 'revoked'
if [ -f cmp.pem ]; then
    # ⚠️ REVOCATION IS SIGNATURE-PROTECTED. PBM is enrolment-only, so an rr sent over
    # PBM is refused by design — this suite used to get away with it because
    # CMP_ACCEPT_UNPROTECTED=true ALSO switched off the whole rr authorization block (PBM
    # refusal, signer identity, ownership). Mint an identity certificate whose CN equals the
    # enrolment reference — that reference is the `owner` recorded on what we are revoking —
    # and sign the rr with it, which is what a real client does.
    "$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out bid.key >/dev/null 2>&1
    cmp_run ir -newkey bid.key -subject "/CN=$CMP_PBM_REF" -certout bid.pem >/dev/null 2>&1
    "$OSSL" cmp -cmd rr -server "http://127.0.0.1:$CMP_PORT/cmp/ca" \
        -recipient "/CN=Baseline CA" -trusted ca.pem -cert bid.pem -key bid.key \
        -keep_alive 0 -oldcert cmp.pem >/dev/null 2>&1
    st=$("$OSSL" ocsp -issuer ca.pem -cert cmp.pem -url "http://127.0.0.1:$OCSP_PORT/ocsp" -noverify 2>/dev/null | grep -oE "good|revoked" | head -1)
    verdict "CMP rr -> OCSP status"  revoked  "${st:-good}"
fi

# genm: returns the CA cert(s); assert content lands via -cacertsout
rm -f gm_ca.pem
cmp_run genm -infotype caCerts -cacertsout gm_ca.pem >/dev/null 2>&1
gmv=reject; { [ -s gm_ca.pem ] && "$OSSL" x509 -in gm_ca.pem -noout -subject 2>/dev/null | grep -q "Baseline CA"; } && gmv=issue
verdict "CMP genm (get CA certs)"  issue  "$gmv"

echo
echo "=== SUMMARY: PASS=$pass  GAP=$gap  FAIL=$fail ==="
echo "(GAP = policy the PHP suite enforces but our port does not yet; FAIL = regression)"
[ "$fail" -eq 0 ]
