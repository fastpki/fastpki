#!/usr/bin/env bash
# CMP_RESPONSE_MD — which digest protects a SIGNED CMP response.
#
# ── Why this exists ──────────────────────────────────────────────────────────────
#
# OCSP and SCEP both let the operator choose the digest their signed responses are
# protected with, through one shared helper that knows the per-key rule: honour the
# choice for RSA/RSA-PSS, auto-match for EC, and leave the one-shot schemes
# (Ed25519/Ed448/ML-DSA) alone because they carry their own hash. CMP had no such
# control at all — it never set the protection digest, so every signed response went out
# under whatever OpenSSL's built-in default happened to be, with no way to raise it.
#
# ⚠️ THE SETTING GOVERNS SIGNATURE PROTECTION ONLY, AND THAT IS NOT A GAP IN THE TEST.
# When a client authenticates with a shared secret, the response comes back protected by
# a password-based MAC, whose parameters are a different axis entirely (a one-way function
# and a MAC, not a signature digest). So a suite that drove the usual PBM client would
# decode `password based MAC` for every configuration and could never tell any of them
# apart — which is exactly what the first version of this file did. The client here
# authenticates with a CERTIFICATE, which is what makes the response signed.
#
# ⚠️ AND IT IS SELF-CONTAINED ON PURPOSE. The obvious shortcut is to append these checks
# to the existing CMP RA suite, which already builds a working RA credential. By the point
# that suite ends it has DELIBERATELY repointed the RA cert_id at a certificate whose key
# does not match the configured RA key — it is testing the mismatched-pair refusal. Both
# servers then correctly refuse every transaction and produce no response to decode, while
# the control assertion ("with no setting the digest is NOT sha512") still passes, because
# an empty string is not sha512 either. Every section below therefore asserts that a
# response was actually captured before saying anything about what is inside it.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# The default path is a Linux convention and is absent on some dev boxes. Without this
# every "$OSSL" call fails silently and each assertion compares against an empty string,
# which reads exactly like a product that emits no digest at all.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"
# Only adopt the system openssl.cnf where it really is one; on macOS this path is a stub
# that defines no providers, and exporting it breaks every pkcs11 load.
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; CPORT=18235
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

echo "=== fixture: a CA, its RA credential, and a client CA to authenticate against ==="
ca_in_token ca.pem "/CN=CMP Digest CA" 3650
# The RA credential must be issued while this CA's key URI is still current — the second
# ca_in_token below overwrites CA_KEY_URI. Published once the database exists.
cmp_ra_issue ca.pem "$CA_KEY_URI" || { echo "SKIP: no CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
SERVER_CA_KEY_URI="$CA_KEY_URI"
ca_in_token clientca.pem "/CN=CMP Digest Client CA" 3650
"$OSSL" req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=tester" >/dev/null 2>&1
"$OSSL" x509 -req -in client.csr -CA clientca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS \
    -CAcreateserial -days 365 -out client.pem >/dev/null 2>&1
chk "the client certificate was issued" yes "$([ -s client.pem ] && echo yes || echo no)"

pg_setup cmp_response_digest
C=
trap 'pg_cleanup; kill $C 2>/dev/null' EXIT
cmp_ra_publish || { echo "SKIP: could not publish the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
printf "internal\n" > domains.txt
seed_domains $W/domains.txt
seed_enrolling_identity tester

# One config template. Each run below appends its own CMP_RESPONSE_MD (or nothing) — the
# setting is read from the config, so telling two settings apart needs two servers.
cat > cmp.base <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$SERVER_CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
CMP_BIND=127.0.0.1
CMP_PORT=$CPORT
CMP_PATH=/cmp
CMP_CLIENT_CA_ID=clientca
LOG_LEVEL=info
EOF
cmp_ra_conf_lines >> cmp.base
seed_ca_from_conf cmp.base
# The client-auth anchor is a registered row, not a PEM path. No key: FastPKI never signs
# with an anchor, it only verifies client certificates against it.
"$ROOT/build/fastpki-ca" --config cmp.base add clientca --name "Client Anchor" \
    --ca-pem "$W/clientca.pem" >/dev/null

# ── the instrument ───────────────────────────────────────────────────────────────
# ⚠️ THE MESSAGE CARRIES SEVERAL SIGNATURE-ALGORITHM OIDs AND ONLY ONE OF THEM IS THE
# ANSWER. Alongside protectionAlg the response holds the issued certificate and the RA's
# own chain in extraCerts, each with its own signatureAlgorithm — so grepping the whole
# dump for a digest name measures whatever the CA signed with, not what protected the
# message. protectionAlg is field [1] of PKIHeader, and PKIHeader is the first member of
# PKIMessage: it is the `cont [ 1 ]` at depth 2, and nothing else in the message is. Take
# the OBJECT immediately inside it and stop.
protection_alg(){   # <response.der> -> e.g. sha512WithRSAEncryption
    [ -s "$1" ] || { echo ""; return; }
    "$OSSL" asn1parse -inform DER -in "$1" 2>/dev/null | awk '
        /d=2 / && /cont \[ 1 \]/ { inalg=1; next }
        inalg && /OBJECT/        { sub(/.*:/, ""); print; exit }'
}

# <extra-config-line-or-empty> <tag> [auth-args…] — starts a server with that setting,
# runs one ir, leaves <tag>.der (the response) and <tag>.pem (the issued certificate).
run_ir(){
    local extra="$1" tag="$2"; shift 2
    rm -f "$tag.der" "$tag.pem"
    cp cmp.base "cmp-$tag.conf"
    [ -n "$extra" ] && echo "$extra" >> "cmp-$tag.conf"
    "$ROOT/build/fastpki-cmp" --config "cmp-$tag.conf" > "cmp-$tag.log" 2>&1 & C=$!
    # Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
  wait_port "$CPORT" "$C" || true
    "$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tag.key" >/dev/null 2>&1
    "$OSSL" cmp -cmd ir -server "http://127.0.0.1:$CPORT/cmp/ca" \
        -recipient "/CN=CMP Digest CA" -trusted ca.pem -expect_sender "/CN=cmp-ra.test" \
        -keep_alive 0 "$@" \
        -newkey "$tag.key" -subject "/CN=$tag.internal" \
        -certout "$tag.pem" -rspout "$tag.der" > "ir-$tag.log" 2>&1 || true
    kill $C 2>/dev/null; wait $C 2>/dev/null; C=
}
SIGAUTH=( -cert client.pem -key client.key )

echo "=== 1. with nothing configured the response keeps OpenSSL's own default ==="
run_ir "" default "${SIGAUTH[@]}"
# ⚠️ THE FIXTURE CHECKS COME FIRST, and they are the ones the first attempt was missing.
# Every assertion below compares a decoded OID name; if no exchange happened at all that
# name is the empty string, and "the empty string is not sha512" passes a control while
# proving nothing whatsoever.
chk "fixture: a response was captured"  yes "$([ -s default.der ] && echo yes || echo no)"
chk "fixture: and a certificate issued" yes "$([ -s default.pem ] && echo yes || echo no)"
DEFAULT_ALG="$(protection_alg default.der)"
chk "the protection algorithm decodes to something" yes \
    "$([ -n "$DEFAULT_ALG" ] && echo yes || echo no)"
# ⚠️ AND IT IS A SIGNATURE, NOT A MAC. If this ever reads "password based MAC" the client
# stopped authenticating by certificate, and every comparison below would be between two
# identical MAC names — the failure that made the first version of this suite worthless.
chk "  and it is a SIGNATURE, so the setting can apply at all" yes \
    "$(printf '%s' "$DEFAULT_ALG" | grep -qi 'MAC' && echo no || echo yes)"
echo "         (default protectionAlg: ${DEFAULT_ALG:-<none>})"

echo "=== 2. the configured digest is what protects the response ==="
run_ir "CMP_RESPONSE_MD=sha512" sha512 "${SIGAUTH[@]}"
chk "fixture: a response was captured"  yes "$([ -s sha512.der ] && echo yes || echo no)"
chk "fixture: and a certificate issued" yes "$([ -s sha512.pem ] && echo yes || echo no)"
SHA512_ALG="$(protection_alg sha512.der)"
chk "the response is protected with sha512" "sha512WithRSAEncryption" "$SHA512_ALG"
# The control: setting it must CHANGE something. Without this, a build that hardcoded
# sha512 — or one where the default already was sha512 — would look identical.
chk "  and that differs from the default" yes \
    "$([ -n "$DEFAULT_ALG" ] && [ "$DEFAULT_ALG" != "$SHA512_ALG" ] && echo yes || echo no)"

echo "=== 3. a second value, so the setting is read rather than hardcoded ==="
run_ir "CMP_RESPONSE_MD=sha384" sha384 "${SIGAUTH[@]}"
chk "fixture: a response was captured"  yes "$([ -s sha384.der ] && echo yes || echo no)"
chk "the response is protected with sha384" "sha384WithRSAEncryption" \
    "$(protection_alg sha384.der)"

echo "=== 4. an unusable value falls back — it never fails the message ==="
# ⚠️ THE TRADE THAT MATTERS. A digest name this build of OpenSSL does not have is a
# cosmetic mistake in a config file; refusing to serve CMP over it would turn a typo into
# an outage. The shared helper falls back to the key's own default, and the enrolment must
# still complete — which is why the issued certificate is asserted here too.
run_ir "CMP_RESPONSE_MD=nosuchdigest" bogus "${SIGAUTH[@]}"
chk "an unknown digest still issues a certificate" yes \
    "$([ -s bogus.pem ] && echo yes || echo no)"
chk "  and the response falls back to the default" "$DEFAULT_ALG" \
    "$(protection_alg bogus.der)"
# A weak digest is a different refusal from an unknown one: the name resolves perfectly
# well, it is the signature floor that rejects it. Both must land on the same fallback.
run_ir "CMP_RESPONSE_MD=md5" weak "${SIGAUTH[@]}"
chk "a digest below the signature floor still issues" yes \
    "$([ -s weak.pem ] && echo yes || echo no)"
chk "  and is not what protects the response" no \
    "$(protection_alg weak.der | grep -qi md5 && echo yes || echo no)"
chk "  falling back to the default instead" "$DEFAULT_ALG" \
    "$(protection_alg weak.der)"

echo "=== 5. the boundary: a shared-secret client gets a MAC, which this does not govern ==="
# ⚠️ ASSERTED, NOT ASSUMED. A password-based MAC has its own one-way function and MAC
# algorithm; the signature digest plays no part. Stating that here stops a later reader
# from "fixing" section 2 to expect sha512 everywhere, and pins the fact that setting this
# key does NOT quietly change how a PBM client is answered.
cmp_seed_pbm digestpbm
run_ir "CMP_RESPONSE_MD=sha512" pbm -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF"
chk "fixture: the shared-secret client also enrolled" yes \
    "$([ -s pbm.pem ] && echo yes || echo no)"
chk "its response is MAC-protected, not signed" yes \
    "$(protection_alg pbm.der | grep -qi 'MAC' && echo yes || echo no)"

echo "=== 6. the key is one the parser knows ==="
# A shipped setting the parser silently ignores is the failure mode this whole axis is
# vulnerable to: the config file looks right, the server starts, and nothing changes.
chk "CMP_RESPONSE_MD is a recognised config key" yes \
    "$(grep -q '"CMP_RESPONSE_MD"' "$ROOT/src/lib/config.cpp" && echo yes || echo no)"

# A refusal here is a decision the server explains in its log; without this a red
# assertion says only "no certificate came back" and the reason has to be reproduced.
[ "$fail" -eq 0 ] || { echo "--- fastpki-cmp (digest + refusal lines) ---"
                       grep -ihE "digest|refus" cmp-*.log 2>/dev/null | tail -12
                       echo "--- openssl cmp (last client run) ---"
                       tail -5 ir-*.log 2>/dev/null | tail -20; }
echo
echo "=== CMP RESPONSE DIGEST: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
