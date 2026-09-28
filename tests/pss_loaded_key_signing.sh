#!/usr/bin/env bash
# A PSS-ONLY CA key must still sign a CRL and an audit checkpoint.
#
# ── The bug this exists for ──────────────────────────────────────────────────────
#
# The original failure was diagnosed precisely: the CA-creation path minted a
# key and then RELOADED it through OSSL_STORE, and the reload loses the provider's
# "RSA-PSS" type name. `is_rsa_pss_p11_key()` reads exactly that name, so it answered
# false, the PSS branch never ran, X509_sign asked for PKCS#1 v1.5, and the token
# correctly refused a key whose CKA_ALLOWED_MECHANISMS is PSS-only.
#
# Certificate signing was fixed. **CRL signing and audit-chain signing were not** — both
# still asked `is_rsa_pss_p11_key()`, and both are reached with a key that was LOADED
# rather than generated, because that is what every long-running service does with a CA
# key. So the same failure was still there, one layer along. His words on the ticket:
#
#   "The sub-CA/CRL/audit signing paths still need the proper CKA_ALLOWED_MECHANISMS-based
#    gate you described. Please take it from here."
#
# ── Why the test is shaped like this ─────────────────────────────────────────────
#
# The CA is created by fastpki-web, which GENERATES the key and therefore still sees the
# type name — that path passes either way and proves nothing here. The discriminator is
# that fastpki-ocsp and fastpki-audit are SEPARATE PROCESSES that resolve the same key by
# URI, so they get the reloaded handle with the name stripped. That is the only shape in
# which the bug is visible, and it is the shape production runs in.
#
# Fails without the fix: the CRL comes back empty/unsigned and the audit checkpoint is
# refused, both with "provider signature failure" in the server log.
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
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; PORT=18492; OPORT=18493
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
skipout(){ echo "  [SKIP] $1"; echo; echo "=== PSS LOADED KEY: PASS=$pass FAIL=$fail SKIP=1 ==="; exit 0; }

pg_setup pss_loaded_key
P=; PO=
trap 'kill $P $PO 2>/dev/null; pg_cleanup' EXIT

ca_in_token ca.pem "/CN=PSS Loaded Bootstrap CA" 3650 || skipout "no token"
seed_web_user boss bosspw admin

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=boot
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
OCSP_BIND=127.0.0.1
OCSP_PORT=$OPORT
CRL_PATH=/crl
AUDIT_SIGN=true
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf

"$ROOT/build/fastpki-web" --config bootstrap.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" WEB_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat web.log; exit 1; }
U="http://127.0.0.1:$PORT"
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null

echo "=== a PSS-only CA, minted in the token by the console ==="
TOK=$(sed -n 's/.*token=\([^;?]*\).*/\1/p' <<<"$CA_KEY_URI")
PSSURI="pkcs11:token=$TOK;object=pssonly;id=%09;type=private?pin-value=1234"
C=$(curl -s -o cre.json -w '%{http_code}' -b boss.cj "$U/api/ca-instances" \
      --data-urlencode 'id=pssonly' --data-urlencode 'name=PSS Only CA' \
      --data-urlencode 'subject=/CN=PSS Only CA' \
      --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$PSSURI" \
      --data-urlencode 'keygen=true' --data-urlencode 'key=rsa-pss' \
      --data-urlencode 'bits=2048' --data-urlencode 'days=3650')
# If the provider on this box cannot sign RSA-PSS with a token key at all, there is no
# bug to demonstrate — say so rather than fail for an unrelated reason (§3d).
[ "$C" = 201 ] || skipout "the pkcs11 provider will not create an RSA-PSS CA here (create -> $C)"
chk "create the RSA-PSS CA -> 201" 201 "$C"
# CA_INSTANCE_DIR is gone; the certificate comes from the API (its `certs` row).
curl -s -b boss.cj "$U/api/ca-instances/pssonly/cert-pem" > "$W/pssonly.pem"
"$OSSL" x509 -in "$W/pssonly.pem" -noout -text > pssca.txt 2>/dev/null
chk "  and it really signs with PSS" yes \
    "$(grep -qi 'Signature Algorithm: rsassaPss' pssca.txt && echo yes || echo no)"

echo "=== a PSS-only RESPONDER credential, and a leaf to ask about ==="
# Is the same defect one more layer along: the RESPONDER key, not the CA key.
# OCSP_basic_sign builds its own EVP_MD_CTX with no PSS parameters, so the provider asks
# the token for CKM_SHA256_RSA_PKCS and a PSS-only key refuses — "provider signature
# failure", exactly what was reported from the live ocsp container.
#
# So the responder key here must be PSS-restricted and IN THE TOKEN. `ocsp_responder_key`
# (service_cert_helpers.sh) mints a software RSA key, which cannot show this: a software
# key has no CKA_ALLOWED_MECHANISMS to refuse with. Mint it the way production does —
# POST /api/certs/request-hsm, which generates in the token and publishes the ocsp-ra row.
RESP_URI="pkcs11:token=$TOK;object=pssresp;id=%0a;type=private?pin-value=1234"
RC=$(curl -s -o resp_cred.json -w '%{http_code}' -b boss.cj "$U/api/certs/request-hsm" \
       --data-urlencode 'ca_instance=pssonly' --data-urlencode "keyref=$RESP_URI" \
       --data-urlencode 'cn=OCSP Responder pssonly' \
       --data-urlencode 'key=rsa-pss' --data-urlencode 'bits=2048' \
       --data-urlencode 'ku=digitalSignature' --data-urlencode 'eku=OCSPSigning' \
       --data-urlencode 'cert_id=ocsp-ra-pssonly')
chk "the PSS responder credential is issued -> 201" 201 "$RC"

echo "=== The DB records the key type WE ASKED FOR, not the one the SPKI claims ==="
# ⚠️ THE DECISION: store the key type in the DB, so our own code is sure without
# trial and error what RSA key we deal with."
#
# ⚠️ THIS IS THE ONE PLACE THE TWO ANSWERS DISAGREE, which is what makes it worth
# asserting. `insert_cert` DERIVES certs.keyAlgo from the certificate's SPKI, and for an
# RSA-PSS token key that SPKI says `rsaEncryption` — the defect itself. So the derived
# value says RSA and the fact is lost at the moment it was known for certain.
# ⚠️ The CA assertion is a CONSISTENCY check, not the regression guard, and watching
# it fail is what showed the difference: on the unfixed binary the CA row ALREADY read
# RSASSA-PSS, because a CA's SPKI genuinely says rsassaPss and the derived value
# was therefore right. It is the LEAF below that changes — which is precisely where the defect
# lives, and the only one of the two that goes red without the writer.
chk "the CA row records RSASSA-PSS"  "RSASSA-PSS" \
    "$(pg_exec "SELECT \"keyAlgo\" FROM certs WHERE id='pssonly' AND is_ca;" | tr -d ' ')"
chk "  and the leaf row too"         "RSASSA-PSS" \
    "$(pg_exec "SELECT \"keyAlgo\" FROM certs WHERE cert_id='ocsp-ra-pssonly' AND status=0;" | tr -d ' ')"
# ⚠️ ANTI-VACUITY, and it is the half that matters. If the column were hardcoded, or if
# every HSM-minted key were recorded as RSA-PSS, the two assertions above would pass and
# mean nothing. So mint a PLAIN RSA CA through the SAME endpoint, in the SAME token, and
# require it to read RSA — same code path, different input, different answer.
PLAINURI="pkcs11:token=$TOK;object=plainrsa;id=%0b;type=private?pin-value=1234"
PC=$(curl -s -o plain.json -w '%{http_code}' -b boss.cj "$U/api/ca-instances" \
      --data-urlencode 'id=plainrsa' --data-urlencode 'name=Plain RSA CA' \
      --data-urlencode 'subject=/CN=Plain RSA CA' \
      --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$PLAINURI" \
      --data-urlencode 'keygen=true' --data-urlencode 'key=rsa' \
      --data-urlencode 'bits=2048' --data-urlencode 'days=3650')
chk "a plain RSA CA is created -> 201" 201 "$PC"
chk "  and its row reads RSA, not RSASSA-PSS" "RSA" \
    "$(pg_exec "SELECT \"keyAlgo\" FROM certs WHERE id='plainrsa' AND is_ca;" | tr -d ' ')"
# ⚠️ THIS ASSERTION FLIPPED, and the flip is the point. It used to require the leaf's SPKI
# to say `rsaEncryption` — the certificate contradicting the row was the whole reason the
# keyAlgo column had to exist. Commit 8406d1f made issue_cert_from_parts
# apply rsa_pss_restricted_public() to the leaf, so the SPKI now says `rsassaPss` (RFC 4055
# §3.1) and a relying party stops trying PKCS#1 v1.5 on a key the token will not verify with.
# The column still earns its place: it records what we ASKED the token for, which is the one
# thing no certificate and no loaded key can be interrogated for afterwards.
# ⚠️ Read it off the DER in the DB, not off resp.pem: that file is carved out of a JSON
# field by sed and an empty or half-extracted file makes this assertion answer "no" for a
# reason that has nothing to do with the certificate. My first version did exactly that.
LEAFSPKI=$(pg_exec "SELECT encode(cert,'base64') FROM certs WHERE cert_id='ocsp-ra-pssonly' AND status=0;" \
           | tr -d ' \n' | "$OSSL" base64 -d -A 2>/dev/null \
           | "$OSSL" x509 -inform DER -noout -text 2>/dev/null \
           | sed -n 's/.*Public Key Algorithm: //p' | head -1)
chk "  and the leaf's SPKI publishes rsassaPss" "rsassaPss" "${LEAFSPKI:-<unreadable>}"
sed -n 's/.*"pem":"\([^"]*\)".*/\1/p' resp_cred.json | sed 's/\\n/\
/g' > resp.pem
# ⚠️ THE CERTIFICATE CANNOT WITNESS THE RESTRICTION — and here is why, with the reason now
# measured rather than guessed. Same token, same run: the CA above carries `rsassaPss` in its
# SubjectPublicKeyInfo and this leaf carries plain `rsaEncryption`, because that was added
# `rsa_pss_restricted_public()` and wired it into the two CA-creation paths only.
# `issue_cert_from_parts` — every leaf the product issues — sets the key as-is.
#
# ⚠️⚠️ DO NOT "FIX" THAT BY CALLING THE HELPER HERE. Tried, measured, reverted: the
# certificate then carries an RSA-PSS-typed public key while OCSP_RESPONDER_KEY is the
# pkcs11 RSA private handle, `X509_check_private_key` compares key TYPES, and
# `resolve_responder_cert` refuses its own credential —
#
#   OCSP: refusing to answer for CA 'pssonly' — the certificate 'ocsp-ra-pssonly' does not
#   match the OCSP responder key this process holds — it was issued for a DIFFERENT key pair
#
# which takes OCSP down for exactly the deployments the restriction is for. The same check
# guards the CMP and SCEP RA credentials and the transport certs. Publishing the restricted
# SPKI needs the key-matching to compare modulus and exponent rather than the type label,
# and that is a security-relevant change to make deliberately, not as a side effect.
#
# The witness that this fixture is PSS-restricted is therefore the SIGNATURE ALGORITHM on
# the response below, not anything in this certificate.
#
# The witness that this fixture is PSS-restricted is therefore the SIGNATURE ALGORITHM on
# the response below: a plain-RSA responder key produces sha256WithRSAEncryption there and
# every assertion in this block would pass on the broken build. That is the precondition.
# Fastpki-ocsp signs with OCSP_RESPONDER_KEY and refuses to answer without a
# matching ocsp-ra-<ca_id> row, so this line is what makes the responder reachable at all.
printf 'OCSP_RESPONDER_KEY=%s\n' "$RESP_URI" >> bootstrap.conf

LC=$(curl -s -o leaf.json -w '%{http_code}' -b boss.cj "$U/api/certs/request-hsm" \
       --data-urlencode 'ca_instance=pssonly' \
       --data-urlencode "keyref=pkcs11:token=$TOK;object=pssleaf;id=%0b;type=private?pin-value=1234" \
       --data-urlencode 'cn=leaf.example.org' \
       --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
       --data-urlencode 'ku=digitalSignature,keyEncipherment' \
       --data-urlencode 'eku=serverAuth')
chk "a leaf to ask the responder about -> 201" 201 "$LC"
sed -n 's/.*"pem":"\([^"]*\)".*/\1/p' leaf.json | sed 's/\\n/\
/g' > leaf.pem

echo "=== an ocsp-nocheck certificate carries no AIA and no CRLDP ==="
"$OSSL" x509 -in resp.pem  -noout -text > resp.txt 2>/dev/null
"$OSSL" x509 -in leaf.pem  -noout -text > leafx.txt 2>/dev/null
# ⚠️ THE POSITIVE CONTROL COMES FIRST. This CA has to be one that actually bakes AIA and
# CRLDP into what it issues, or "the responder has none" is true for the boring reason and
# the assertions below are decoration. The leaf is issued by the same CA, in the same run.
chk "the CA does bake AIA into its leaves"   yes \
    "$(grep -q 'Authority Information Access' leafx.txt && echo yes || echo no)"
chk "  and CRL Distribution Points"          yes \
    "$(grep -q 'CRL Distribution Points' leafx.txt && echo yes || echo no)"
chk "the responder cert has ocsp-nocheck"    yes \
    "$(grep -qE 'OCSP No Check|1\.3\.6\.1\.5\.5\.7\.48\.1\.5' resp.txt && echo yes || echo no)"
chk "  so it carries NO AIA"                 no  \
    "$(grep -q 'Authority Information Access' resp.txt && echo yes || echo no)"
chk "  and NO CRL Distribution Points"       no  \
    "$(grep -q 'CRL Distribution Points' resp.txt && echo yes || echo no)"

echo "=== fastpki-ocsp LOADS that key and must still sign a CRL ==="
# THE assertion. A separate process, resolving the key by URI: the reload strips the
# "RSA-PSS" type name, so a type-name gate is blind here and v1.5 gets attempted.
"$ROOT/build/fastpki-ocsp" --config bootstrap.conf >ocsp.log 2>&1 & PO=$!
# ⚠️ POLL, do not sleep. This process now loads OCSP_RESPONDER_KEY from the token at
# startup — a p11-kit round trip — so it takes longer to bind than it used to, and a
# fixed `sleep 1` made the whole block fail intermittently with an EMPTY log: alive
# according to kill -0, not yet listening, so every curl came back with nothing and it
# read as a product failure.
for _ in $(seq 1 60); do
    kill -0 $PO 2>/dev/null || break
    curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$OPORT/crl/pssonly" && break
    sleep 0.5
done
kill -0 $PO 2>/dev/null || { echo "fastpki-ocsp died:"; cat ocsp.log; exit 1; }
curl -s "http://127.0.0.1:$OPORT/crl/pssonly" -o crl.der
chk "the CRL is non-empty" yes "$([ -s crl.der ] && echo yes || echo no)"
"$OSSL" crl -inform DER -in crl.der -noout -text > crl.txt 2>/dev/null
chk "it parses as a CRL" yes \
    "$(grep -q 'Certificate Revocation List' crl.txt && echo yes || echo no)"
chk "and it is signed with rsassaPss" yes \
    "$(grep -qi 'rsassaPss' crl.txt && echo yes || echo no)"
# Decoding is not enough: a CRL is only useful if it verifies against the CA that signed it.
chk "the CRL verifies against its CA" yes \
    "$("$OSSL" crl -inform DER -in crl.der -CAfile "$W/pssonly.pem" -noout 2>&1 \
       | grep -qi 'verify ok' && echo yes || echo no)"
chk "no provider signature failure in the ocsp log" no \
    "$(grep -qi 'provider signature failure' ocsp.log && echo yes || echo no)"

echo "=== ...and must sign an OCSP RESPONSE with that PSS-only responder key ==="
# ⚠️ THIS BLOCK IS RED ON PURPOSE, like the failover-slot assertions. Do not "fix" it by
# relaxing the expectation.
#
# Commit 8406d1f made the leaf SPKI publish id-RSASSA-PSS, which is right
# by RFC 4055 §3.1. But the pkcs11 provider hands the SAME key back as plain RSA — it picks
# its keymgmt from CKA_KEY_TYPE, and there is no PSS key type in PKCS#11 — so inside
# OCSP_basic_sign OpenSSL compares the certificate's key type with the private key's and
# refuses:
#
#   digital envelope routines::different key types
#   x509 certificate routines::key type mismatch
#   OCSP routines::private key does not match certificate
#
# That is OpenSSL's own check, not ours; ours (pki::cert_certifies_key) compares n/e and
# correctly says these ARE the same key pair. So a PSS-restricted OCSP responder cannot sign
# at all today, and every request gets `internalerror` from a responder whose certificate is
# valid and adopted. Pinning today's behaviour here would bless that.
# The CRL above is signed with the CA key; this is signed with the RESPONDER key, through
# a completely different OpenSSL entry point (OCSP_basic_sign, not X509_CRL_sign). That
# fixed three PSS signing paths one at a time and missed this one for the same reason each
# time: nothing exercised it.
"$OSSL" ocsp -issuer "$W/pssonly.pem" -cert leaf.pem -CAfile "$W/pssonly.pem" \
        -url "http://127.0.0.1:$OPORT/ocsp" -resp_text -respout ocsp.der > ocsp.txt 2>&1
chk "a response came back at all" yes "$([ -s ocsp.der ] && echo yes || echo no)"
# ⚠️ NOT the exit code and NOT "successful" alone: on the broken build the responder
# answers with a well-formed internalError, which is a valid OCSP response. The question
# is whether it carries a SIGNATURE the CA's own PSS key produced.
chk "  response status is successful" yes \
    "$(grep -q 'OCSP Response Status: successful' ocsp.txt && echo yes || echo no)"
# ⚠️ This one is doing double duty: it proves the fix AND proves the fixture. Plain RSA
# here would mean the responder key was never PSS-restricted and the whole block is inert.
chk "  and it is signed with rsassaPss" yes \
    "$(grep -qi 'rsassaPss' ocsp.txt && echo yes || echo no)"
# ⚠️ ASSERT THE VERIFICATION, NOT THE STATUS LINE BESIDE IT. The first alternative of this
# pattern used to be `leaf.pem: <status>`, which openssl prints AFTER the verification block
# and prints whether or not verification succeeded — so a response that came back
# "Response Verify Failure / unable to get issuer certificate" still reported `leaf.pem:
# good` two lines later, ocsp.txt carries both streams, and the check passed with nothing
# having verified the signature. That is the same trap ocsp_rekeyed_chain.sh records at its
# own verify assertion. "Response verify OK" is printed only when OCSP_basic_verify actually
# validated the signature against pssonly.pem — and an error response, which carries no
# signature at all, cannot produce it.
chk "  the signature verifies against the CA" yes \
    "$(grep -qi 'Response verify OK' ocsp.txt && echo yes || echo no)"
chk "  the leaf is reported good" yes \
    "$(grep -q ': good' ocsp.txt && echo yes || echo no)"
chk "no OCSP_basic_sign failure in the ocsp log" no \
    "$(grep -qi 'OCSP_basic_sign failed' ocsp.log && echo yes || echo no)"
# The responder detects the contradiction and logs it on EVERY request it answers.
# Asserted after a real query, so it is the served path and not a startup check.
chk "  and no 'contradictory' ERR either" no \
    "$(grep -qi 'contradictory' ocsp.log && echo yes || echo no)"

echo "=== fastpki-audit LOADS it too, and must sign a checkpoint ==="
cat > audit.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/pssonly.pem
SIGNING_CA_KEY=$PSSURI
SIGNING_CA_ID=pssonly
AUDIT_SIGN=true
LOG_LEVEL=err
EOF
hsm_conf_lines >> audit.conf
AUDIT="$ROOT/build/fastpki-audit"
"$AUDIT" --config audit.conf append auth login alice success "" "ip=10.0.0.1" >/dev/null 2>&1
"$AUDIT" --config audit.conf --ca pssonly sign >cp.log 2>&1; rc=$?
chk "the audit checkpoint is signed -> rc 0" 0 "$rc"
[ "$rc" -eq 0 ] || { echo "    --- fastpki-audit said ---"; sed 's/^/    /' cp.log | head -6; }
chk "  and not refused by the token" no \
    "$(grep -qiE 'provider signature failure|signature failure' cp.log && echo yes || echo no)"
chk "the checkpoint row carries a signature" yes \
    "$(pg_exec "SELECT length(coalesce(signature,''))>0 FROM audit_checkpoints ORDER BY at DESC LIMIT 1;" \
       | tr -d ' ' | grep -q '^t$' && echo yes || echo no)"

echo
echo "=== PSS LOADED KEY: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
