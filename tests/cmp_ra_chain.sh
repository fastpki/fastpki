#!/usr/bin/env bash
# Regression: the RA certificate's ISSUER CHAIN must travel in the
# response's extraCerts, so a client holding only the ROOT can verify the protection.
#
# The report:
#   "When I only add root CA in trusted file and omit untrusted file with issuing CA in
#    fastpki-cmp.cnf, then the signature verification fails because signing CA cert is
#    missing."
#
# OpenSSL puts the protection signer — the RA leaf — into extraCerts by itself. That is
# not enough to verify anything. The client's own log shows how close it gets before
# failing, which is why this reads as a client problem rather than a server one:
#
#     CMP info:  cert subject matches sender field: /CN=FastPKI CMP
#     CMP info:  cert seems acceptable
#     CMP error: certificate verification failed:... error = 20
#                (unable to get local issuer certificate)
#
# ⚠️ WHY THIS SUITE NEEDS A REAL TWO-LEVEL HIERARCHY, AND WHY EVERY OTHER CMP SUITE
# PASSES WITHOUT THE FIX. Every one of them builds a SELF-SIGNED CA and hands the client
# `-trusted ca.pem` — the anchor and the RA's issuer are the same certificate, so the
# client already holds the missing link and the chain closes with nothing on the wire.
# Only root -> sub -> RA tells a server that sends its chain apart from one that does not.
#
# ⚠️ AND WHY CMP_EXTRACERTS_CA IS LEFT OFF. That option adds the chain of the
# ISSUED certificate to a certificate response, and here the RA and the leaf share an
# issuer — so turning it on would put the sub-CA in extraCerts for a completely different
# reason and this suite could not fail. They are different things: the extraCerts option is
# about the payload and is optional, this is about the PROTECTION and is not, which the genm
# case below makes concrete — a genm response carries no certificate at all, so that option
# can ever help it.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
# Only adopt the system openssl.cnf where it really is one — on macOS this path is a stub
# that defines no providers, and exporting it breaks every pkcs11 load.
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF

W="$(mktemp -d)"; cd "$W"; PORT=18485
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

# ── Fixture: a root that signs a sub-CA ─────────────────────────────────────────────
# Capture the root's key URI BEFORE minting the sub: $CA_KEY_URI holds the LAST key
# ca_in_token minted, so reading it afterwards signs the sub with its own key and
# silently produces a second self-signed root — which would make every assertion below
# pass for the wrong reason.
ca_in_token rootca.pem "/CN=CMP Chain Root CA" 3650 cmpchainroot
ROOT_KEY_URI="$CA_KEY_URI"
ca_in_token subca.pem "/CN=CMP Chain Issuing CA" 3650 cmpchainsub rootca.pem "$ROOT_KEY_URI"
SUB_KEY_URI="$CA_KEY_URI"

chk "fixture: the sub-CA is signed by the root" yes \
    "$("$OSSL" verify -CAfile rootca.pem -partial_chain subca.pem >/dev/null 2>&1 && echo yes || echo no)"
# The failure mode this guards is ca_in_token falling back to SELF-SIGNING the sub (it
# does exactly that when handed an empty parent), which would make the anchor and the
# RA's issuer the same certificate again and quietly restore the blind spot described
# above. A self-sign there produces subject == issuer, so comparing the two names catches
# it. ⚠️ The obvious `verify -CAfile subca.pem -partial_chain subca.pem` does NOT: the
# certificate under test IS the anchor, so OpenSSL matches it by identity and answers OK
# whoever signed it — it cannot fail, and it reported this fixture as self-signed when it
# is not. (Name equality is not a general self-signed test either — a REKEYED CA has
# subject == issuer and is signed by its previous key — but no rekey happens here.)
chk "fixture: the sub-CA is not self-signed (subject differs from issuer)" yes \
    "$([ "$("$OSSL" x509 -in subca.pem -noout -subject -nameopt RFC2253 | sed 's/^subject=//')" \
       != "$("$OSSL" x509 -in subca.pem -noout -issuer  -nameopt RFC2253 | sed 's/^issuer=//')" ] \
       && echo yes || echo no)"

# The RA credential is issued by the SUB-CA, so RA -> sub -> root is a real three-link path.
cmp_ra_issue subca.pem "$SUB_KEY_URI" \
    || { echo "SKIP: no CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }

pg_setup cmp_ra_chain
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cmp_ra_publish cmp-ra-cmpchainsub \
    || { echo "SKIP: could not publish the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
printf "internal\n" > domains.txt
seed_domains "$W/domains.txt"

cat > cmp.conf <<EOF
SIGNING_CA_PEM=$W/subca.pem
SIGNING_CA_KEY=$SUB_KEY_URI
SIGNING_CA_ID=cmpchainsub
PG_CONNINFO=$PG_CONNINFO
CMP_BIND=127.0.0.1
CMP_PORT=$PORT
CMP_PATH=/cmp
CMP_CLIENT_CA_ID=cmpchainsub
LOG_LEVEL=err
EOF
seed_ca_from_conf cmp.conf
# Register the ROOT too. build_issuer_chain() walks ca_instances by AKI, so a root that
# is not a row is a root the walk cannot reach — the server would send nothing and the
# failure would look exactly like the bug this suite guards.
"$ROOT/build/fastpki-ca" --config cmp.conf add cmpchainroot --name "CMP Chain Root" \
      --ca-pem "$W/rootca.pem" --ca-key "$ROOT_KEY_URI" >/dev/null 2>&1
cmp_seed_pbm cmp-chain
cmp_ra_conf_lines >> cmp.conf

"$ROOT/build/fastpki-cmp" --config cmp.conf >srv.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-cmp died:"; cat srv.log; echo "PASS=$pass FAIL=$((fail+1))"; exit 1; }

# ── 1. ir, anchored on the ROOT ONLY, with no -untrusted ────────────────────────────
# This is the exact reported invocation. -untrusted is deliberately absent: handing
# the client the intermediate is the WORKAROUND, and a suite that uses it proves nothing.
"$OSSL" cmp -cmd ir -server "http://127.0.0.1:$PORT/cmp/cmpchainsub" \
    -recipient "/CN=CMP Chain Issuing CA" -trusted rootca.pem \
    -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
    -newkey scratch.key -subject "/CN=host.internal" \
    -certout leaf.pem -extracertsout extra.pem >ir.log 2>&1
IR_RC=$?

chk "ir succeeds with only the root trusted" 0 "$IR_RC"
chk "  and a certificate came back" ok "$( [ -s leaf.pem ] && echo ok || echo no )"
# The precise error the ticket reports, by name — so a future failure says whether it is
# THIS regression or some other breakage.
chk "  no 'unable to get local issuer certificate'" no \
    "$(grep -q 'unable to get local issuer certificate' ir.log && echo yes || echo no)"

# ── 2. the sub-CA is really on the wire (decode it, do not infer it) ────────────────
certs_in() {   # <pem-bundle> <subject-CN> -> yes|no
    [ -s "$1" ] || { echo no; return; }
    "$OSSL" crl2pkcs7 -nocrl -certfile "$1" 2>/dev/null \
        | "$OSSL" pkcs7 -print_certs -noout 2>/dev/null \
        | grep -q "subject=CN *= *$2" && echo yes || echo no
}
# ⚠️ `-extracertsout` saves the extraCerts of the LAST message received, which for an ir
# without -implicit_confirm is the PKIConf closing the transaction, not the ip carrying
# the certificate. The RA leaf is absent there — OpenSSL sends the protection signer once
# per transaction — so asserting it here would be asserting OpenSSL's behaviour against
# the wrong message. It is asserted on the single-round-trip genm below instead, and its
# presence in the ip is already proven by the fact that the ir verified at all.
chk "extraCerts carries the RA's ISSUER (the sub-CA)" yes "$(certs_in extra.pem 'CMP Chain Issuing CA')"
# RFC 8446 §4.4.2 posture, and build_issuer_chain stops at the self-signed root: the
# anchor is the client's to hold. Sending it invites a client to trust it off the wire.
chk "extraCerts does NOT carry the root" no "$(certs_in extra.pem 'CMP Chain Root CA')"

# ── 3. kur — the exact reported repro, and the one that actually FAILS ─────────────
# ⚠️ READ THIS BEFORE TRUSTING THE ir CASE ABOVE. Measured with the fix reverted: the ir
# still SUCCEEDS. It is PBM-protected (-secret), and OpenSSL accepts the response on the
# shared secret without ever needing to build a path to the RA. So those three assertions
# do not discriminate — only the extraCerts content ones do, and only this kur case
# reproduces the client-visible failure the ticket reports.
#
# kur is signature-protected: the client authenticates with the certificate it just got,
# and the response protection must therefore be verified by PATH, against the root alone.
# That is `-section cmp,kur` from the ticket.
# -newkey names an EXISTING key file; it is not a "generate one" switch. Left to fend for
# itself the client dies with "cannot set up CMP context" before a single byte reaches the
# server, which reads exactly like the recipient failure and has nothing to do with this.
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out kur.key >/dev/null 2>&1
"$OSSL" cmp -cmd kur -server "http://127.0.0.1:$PORT/cmp/cmpchainsub" \
    -recipient "/CN=CMP Chain Issuing CA" -trusted rootca.pem \
    -cert leaf.pem -key scratch.key -keep_alive 0 \
    -newkey kur.key -certout kur.pem >kur.log 2>&1
KUR_RC=$?
chk "kur succeeds with only the root trusted" 0 "$KUR_RC"
chk "  kur returned a certificate" ok "$( [ -s kur.pem ] && echo ok || echo no )"
chk "  no 'unable to get local issuer certificate' on kur" no \
    "$(grep -q 'unable to get local issuer certificate' kur.log && echo yes || echo no)"
[ "$KUR_RC" -eq 0 ] || { echo "  --- kur.log ---"; tail -20 kur.log; echo "  --- srv.log ---"; tail -10 srv.log; }

# ── 4. genm — a response with no certificate payload at all ─────────────────────────
# CMP_EXTRACERTS_CA can never help here: there is no issued certificate whose
# chain it could attach. If genm verifies against the root alone, the chain came from the
# protection path, which is the whole claim here.
"$OSSL" cmp -cmd genm -server "http://127.0.0.1:$PORT/cmp/cmpchainsub" \
    -recipient "/CN=CMP Chain Issuing CA" -trusted rootca.pem \
    -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
    -extracertsout genm_extra.pem >genm.log 2>&1
GENM_RC=$?
chk "genm verifies with only the root trusted" 0 "$GENM_RC"
chk "  no issuer-certificate error on genm" no \
    "$(grep -q 'unable to get local issuer certificate' genm.log && echo yes || echo no)"
chk "  genp extraCerts carries the RA's issuer" yes "$(certs_in genm_extra.pem 'CMP Chain Issuing CA')"
# ⚠️ NOTHING HERE ASSERTS THE RA LEAF, AND THAT IS DELIBERATE — it is not ours to assert.
# Measured on both flows: the client's -extracertsout dump lists the sub-CA and NOT the
# signer, on the single-round-trip genm as well as on the ir. That is OpenSSL's own
# bookkeeping — a validated server certificate moves to validatedSrvCert and does not
# come back out of get1_extraCertsIn — not something the server chose. It cannot be
# absent from the wire: without it the client has nothing to check the protection
# signature with, and both exchanges above verified against the root alone.

echo "  (extraCerts held: $("$OSSL" crl2pkcs7 -nocrl -certfile extra.pem 2>/dev/null | "$OSSL" pkcs7 -print_certs -noout 2>/dev/null | sed -n 's/^subject=//p' | tr '\n' '|'))"
kill $P 2>/dev/null; wait $P 2>/dev/null

echo
echo "=== CMP RA CHAIN: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
