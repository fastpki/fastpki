#!/usr/bin/env bash
# PKCS#11 HSM-backed CA key. Proves a CA signing key that lives in a
# PKCS#11 token (here SoftHSM) drives real issuance: fastpki-ocsp loads the key
# via the pkcs11 provider + OSSL_STORE and signs a CRL with it, which we then
# verify against the CA cert. Skips cleanly (not fails) where SoftHSM / the
# pkcs11 OpenSSL provider aren't installed, so CI stays green either way.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"   # macOS
# Overridable: on macOS the system /etc/ssl/openssl.cnf is minimal (no v3_ca),
# which yields a self-signed CA with no basicConstraints; point at a full cnf
# (e.g. brew's /opt/homebrew/etc/openssl@3/openssl.cnf) there.
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
W="$(mktemp -d)"; cd "$W"; PORT=18092; CRLP=/pki/signing_ca.crl
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }
skipout() { echo "  [SKIP] $1"; echo; echo "=== PKCS11: PASS=$pass FAIL=$fail SKIP=1 ==="; exit 0; }

findfirst() { for x in "$@"; do [ -e "$x" ] && { echo "$x"; return 0; }; done; return 1; }
P11PFX="${P11_PREFIX:-$HOME/p11local/usr}"
SOFTHSM_MOD=$(findfirst "${SOFTHSM_MODULE:-}" "$P11PFX/lib/softhsm/libsofthsm2.so" \
    /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib64/softhsm/libsofthsm2.so \
    /opt/homebrew/lib/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so || true)
UTIL=$(findfirst "$P11PFX/bin/softhsm2-util" || true); [ -z "$UTIL" ] && UTIL=$(command -v softhsm2-util || true)
PKTOOL=$(findfirst "$P11PFX/bin/pkcs11-tool" || true); [ -z "$PKTOOL" ] && PKTOOL=$(command -v pkcs11-tool || true)
# $P11_PROVIDER lets a caller point straight at a built provider module (e.g. a
# from-source pkcs11.dylib on macOS); otherwise probe the usual install dirs (.so on
# Linux, .dylib under a brew openssl@3 on macOS).
# Homebrew Cellar may hold pkcs11.dylib under a version dir that the opt/ symlink doesn't reach
CELLAR_PROV=$(ls /opt/homebrew/Cellar/openssl@3/*/lib/ossl-modules/pkcs11.dylib 2>/dev/null | head -1)
PROV=$(findfirst "${P11_PROVIDER:-}" "$P11PFX/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so" \
    /usr/lib/ossl-modules/pkcs11.so /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so \
    /usr/lib64/ossl-modules/pkcs11.so \
    /opt/homebrew/opt/openssl@3/lib/ossl-modules/pkcs11.dylib \
    /opt/homebrew/lib/ossl-modules/pkcs11.dylib \
    $CELLAR_PROV || true)
[ -n "$SOFTHSM_MOD" ] && [ -n "$UTIL" ] && [ -n "$PKTOOL" ] && [ -n "$PROV" ] || \
    skipout "SoftHSM / pkcs11 provider not installed (SOFTHSM_MOD=$SOFTHSM_MOD PROV=$PROV)"
PROVDIR=$(dirname "$PROV")
# The setup tools (softhsm2-util / pkcs11-tool) may need the prefix's own libs.
TOOL_LD="$LD_LIBRARY_PATH"
case "$SOFTHSM_MOD" in "$P11PFX"/*) TOOL_LD="$P11PFX/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH";; esac
echo "using SoftHSM=$SOFTHSM_MOD provider=$PROVDIR"

# 1) SoftHSM token + a CA keypair generated IN the token (never exported)
mkdir -p tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$W" > softhsm2.conf
export SOFTHSM2_CONF="$W/softhsm2.conf"
LD_LIBRARY_PATH="$TOOL_LD" "$UTIL" --module "$SOFTHSM_MOD" --init-token --free --label PKITEST --pin 1234 --so-pin 12345678 >/dev/null 2>&1
LD_LIBRARY_PATH="$TOOL_LD" "$PKTOOL" --module "$SOFTHSM_MOD" --keypairgen --key-type rsa:2048 \
    --label cakey --id 0102 --login --pin 1234 >/dev/null 2>&1
URI="pkcs11:token=PKITEST;object=cakey;type=private?pin-value=1234"

# The module fastpki/openssl SIGN with: the p11-kit proxy (out-of-process, so
# SoftHSM can't re-enter our libcrypto and deadlock) where p11-kit is available,
# else the direct module. Token setup above stays on the direct module.
. "$ROOT/tests/p11kit_lib.sh"
# NOT $( ) — see p11kit_lib.sh: the subshell would swallow the server address.
p11_setup_signing "$SOFTHSM_MOD" || skipout "no safe out-of-process PKCS#11 route"
SIGN_MOD="$P11_SIGN_MODULE"
echo "signing module: $SIGN_MOD"

# 2) Self-sign the CA cert with the token key (via the pkcs11 provider)
PKCS11_PROVIDER_MODULE="$SIGN_MOD" "$OSSL" req -x509 -new -key "$URI" -sha256 -days 3650 \
    -subj "/CN=HSM CA" -out ca.pem \
    -provider-path "$PROVDIR" -provider pkcs11 -provider default >/dev/null 2>&1
[ -s ca.pem ] || skipout "could not self-sign CA with the token key (provider/softhsm ABI?)"
chk "CA cert self-signed by the HSM key" ok "$( [ -s ca.pem ] && echo ok || echo no )"

# 3) A DB with one revoked cert so the generated CRL has content
pg_setup pkcs11
trap 'p11_cleanup; pg_cleanup; kill $P 2>/dev/null' EXIT
NOW=$(date +%s)
pg_seed_ca_row hsm-rsa "$W/ca.pem" "$URI"   # a CA is a `certs` row
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,ca_instance_id) VALUES('dead01',-1,1,$NOW,$((NOW-86400)),$((NOW+86400)),'CN=gone.host','x','gone.host','ab','hsm-rsa');"

cat > ocsp.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$URI
SIGNING_CA_ID=hsm-rsa
PKCS11_MODULE=$SIGN_MOD
PKCS11_PROVIDER_PATH=$PROVDIR
PG_CONNINFO=$PG_CONNINFO
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
CRL_PATH=$CRLP
LOG_LEVEL=info
EOF

# 4) fastpki-ocsp signs the CRL with the HSM key; verify it
"$ROOT/build/fastpki-ocsp" --config ocsp.conf >srv.log 2>&1 & P=$!
# ⚠️ This REPLACES the trap set above — bash traps do not stack — so it has to repeat
# every handler, not just the new one. It used to name `kill $P` alone, which silently
# dropped pg_cleanup and leaked a database on every run of this suite.
sleep 1; trap 'p11_cleanup; pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-ocsp died:"; cat srv.log; skipout "fastpki-ocsp could not load the HSM key"; fi
curl -s "http://127.0.0.1:$PORT$CRLP/hsm-rsa" -o crl.der
chk "CRL retrieved" ok "$( [ -s crl.der ] && echo ok || echo no )"
"$OSSL" crl -inform DER -in crl.der -CAfile ca.pem -noout 2>crlverr.txt && a=yes || a=no
chk "CRL signature verifies against the HSM CA" yes "$a"
"$OSSL" crl -inform DER -in crl.der -noout -text 2>/dev/null | tr 'A-F' 'a-f' | tr -d ' :' | grep -qi dead01 && SER=y || SER=n
chk "revoked serial present in the HSM-signed CRL" "y" "$SER"

kill $P 2>/dev/null; wait $P 2>/dev/null; sleep 0.5

# === 5. EC (P-256) CRL signing via SoftHSM ===
echo "=== 5. EC (P-256) CRL signing via SoftHSM ==="
LD_LIBRARY_PATH="$TOOL_LD" "$PKTOOL" --module "$SOFTHSM_MOD" --keypairgen \
    --key-type ec:prime256v1 --label ec-ca --id 0103 --login --pin 1234 >/dev/null 2>&1
EC_URI="pkcs11:token=PKITEST;object=ec-ca;type=private?pin-value=1234"
# ⚠️ THIS WORKAROUND IS PROBABLY NO LONGER NEEDED — MEASURE BEFORE TRUSTING IT.
# It was justified as "ECDSA digest_sign_update is broken in the pkcs11 provider on
# SoftHSM". Measured on the shipped image (OpenSSL 3.5.8), that is not what happens:
#
#   provider -> p11-kit-client.so, EC:prime256v1 WITH --id   : self-signs, ecdsa-with-SHA256
#   provider -> p11-kit-client.so, EC:prime256v1 WITHOUT --id: fails, p11prov_obj_find_associated
#   provider -> libsofthsm2.so direct, EC *and* RSA          : HANGS or fails, non-deterministic
#
# The last row is the re-entrant deadlock the whole p11-kit arrangement exists to avoid,
# and it is not algorithm-specific — RSA hangs there too. The key below is minted with
# `--id 0103`, and $SIGN_MOD is the p11-kit shim (p11kit_lib.sh:78), so a direct self-sign
# should now work. Left as-is only because changing it needs a container run to prove;
# the pubkey route is still correct, just no longer forced.
# Extract the public key and build a CA cert around it; CRL verification only needs it.
LD_LIBRARY_PATH="$TOOL_LD" "$PKTOOL" --module "$SOFTHSM_MOD" --read-object \
    --type pubkey --id 0103 --login --pin 1234 -o ec-pub.der >/dev/null 2>&1
if [ -s ec-pub.der ]; then
    "$OSSL" ecparam -genkey -name prime256v1 -out ec-tmp.key 2>/dev/null
    "$OSSL" req -x509 -new -key ec-tmp.key -sha256 -days 3650 \
        -subj "/CN=HSM EC CA" -out ec-tmp.pem 2>/dev/null
    "$OSSL" x509 -in ec-tmp.pem -force_pubkey ec-pub.der -out ec-ca.pem 2>/dev/null
fi
if [ -s ec-ca.pem ]; then
    echo "  EC CA cert built with the HSM public key"
    pg_seed_ca_row hsm-ec "$W/ec-ca.pem" "$EC_URI"   # a CA is a `certs` row
    pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,ca_instance_id) VALUES('dead02',-1,1,$NOW,$((NOW-86400)),$((NOW+86400)),'CN=gone.host','x','gone.host','ab','hsm-ec');"
    cat > ec-ocsp.conf <<EOF
SIGNING_CA_PEM=$W/ec-ca.pem
SIGNING_CA_KEY=$EC_URI
SIGNING_CA_ID=hsm-ec
PKCS11_MODULE=$SIGN_MOD
PKCS11_PROVIDER_PATH=$PROVDIR
PG_CONNINFO=$PG_CONNINFO
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
CRL_PATH=$CRLP
LOG_LEVEL=info
EOF
    "$ROOT/build/fastpki-ocsp" --config ec-ocsp.conf >srv.log 2>&1 & P=$!
    # Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
    wait_port "$PORT" "$P" || true
    if kill -0 $P 2>/dev/null; then
        curl -s "http://127.0.0.1:$PORT$CRLP/hsm-ec" -o ec-crl.der
        chk "EC CRL retrieved" ok "$( [ -s ec-crl.der ] && echo ok || echo no )"
        "$OSSL" crl -inform DER -in ec-crl.der -CAfile ec-ca.pem -noout 2>ec-verr.txt && a=yes || a=no
        chk "EC CRL signature verifies against the HSM CA" yes "$a"
        "$OSSL" crl -inform DER -in ec-crl.der -noout -text 2>/dev/null | tr 'A-F' 'a-f' | tr -d ' :' | grep -qi dead02 && SER=y || SER=n
        chk "revoked serial present in the EC HSM-signed CRL" "y" "$SER"
        kill $P 2>/dev/null; wait $P 2>/dev/null; sleep 0.3
    else
        echo "  [SKIP] fastpki-ocsp could not start with the EC HSM key"
    fi
else
    echo "  [SKIP] no EC (ec:prime256v1) key in the token — keygen or read-object failed here"
fi

# === 6. Ed25519 CRL signing via SoftHSM ===
echo "=== 6. Ed25519 CRL signing via SoftHSM ==="
# ⚠️ THE CURVE NAME IS `edwards25519`, NOT `ED25519`, AND THE DIFFERENCE COST THIS
# SECTION ITS ENTIRE LIFE. OpenSC answers EC:ED25519 with
#
#     error: Unknown EC key parameter 'ED25519'
#
# so no key was ever made, ed-pub.der stayed empty, and the else branch below announced
# that SoftHSM "does not support Ed25519 key generation". It supports it fine: the token
# advertises EC-EDWARDS-KEY-PAIR-GEN and EDDSA at keySize={255,448}, and the same command
# with the right spelling creates the key immediately. A wrong parameter was reported as a
# missing capability, and believed.
#
# tests/hsm_helpers.sh:hsm_token_spec() is the canonical mapping (ed25519 -> ec:edwards25519).
# This suite talks to SoftHSM directly and does not source those helpers, so the spelling is
# repeated here rather than derived — keep the two in step.
LD_LIBRARY_PATH="$TOOL_LD" "$PKTOOL" --module "$SOFTHSM_MOD" --keypairgen \
    --key-type EC:edwards25519 --label ed-ca --id 0104 --login --pin 1234 >ed-keygen.log 2>&1
ED_URI="pkcs11:token=PKITEST;object=ed-ca;type=private?pin-value=1234"
LD_LIBRARY_PATH="$TOOL_LD" "$PKTOOL" --module "$SOFTHSM_MOD" --read-object \
    --type pubkey --id 0104 --login --pin 1234 -o ed-pub.der >/dev/null 2>&1
if [ -s ed-pub.der ]; then
    "$OSSL" genpkey -algorithm ED25519 -out ed-tmp.key 2>/dev/null
    "$OSSL" req -x509 -new -key ed-tmp.key -days 3650 \
        -subj "/CN=HSM EdDSA CA" -out ed-tmp.pem 2>/dev/null
    "$OSSL" x509 -in ed-tmp.pem -force_pubkey ed-pub.der -out ed-ca.pem 2>/dev/null
fi
if [ -s ed-ca.pem ]; then
    echo "  Ed25519 CA cert built with the HSM public key"
    pg_seed_ca_row hsm-ed "$W/ed-ca.pem" "$ED_URI"   # a CA is a `certs` row
    pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,ca_instance_id) VALUES('dead03',-1,1,$NOW,$((NOW-86400)),$((NOW+86400)),'CN=gone.host','x','gone.host','ab','hsm-ed');"
    cat > ed-ocsp.conf <<EOF
SIGNING_CA_PEM=$W/ed-ca.pem
SIGNING_CA_KEY=$ED_URI
SIGNING_CA_ID=hsm-ed
PKCS11_MODULE=$SIGN_MOD
PKCS11_PROVIDER_PATH=$PROVDIR
PG_CONNINFO=$PG_CONNINFO
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
CRL_PATH=$CRLP
LOG_LEVEL=info
EOF
    "$ROOT/build/fastpki-ocsp" --config ed-ocsp.conf >srv.log 2>&1 & P=$!
    # Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
    wait_port "$PORT" "$P" || true
    if kill -0 $P 2>/dev/null; then
        curl -s "http://127.0.0.1:$PORT$CRLP/hsm-ed" -o ed-crl.der
        chk "Ed25519 CRL retrieved" ok "$( [ -s ed-crl.der ] && echo ok || echo no )"
        "$OSSL" crl -inform DER -in ed-crl.der -CAfile ed-ca.pem -noout 2>ed-verr.txt && a=yes || a=no
        chk "Ed25519 CRL signature verifies against the HSM CA" yes "$a"
        "$OSSL" crl -inform DER -in ed-crl.der -noout -text 2>/dev/null | tr 'A-F' 'a-f' | tr -d ' :' | grep -qi dead03 && SER=y || SER=n
        chk "revoked serial present in the Ed25519 HSM-signed CRL" "y" "$SER"
        kill $P 2>/dev/null; wait $P 2>/dev/null; sleep 0.3
    else
        echo "  [SKIP] fastpki-ocsp could not start with the Ed25519 HSM key"
    fi
else
    # Report the tool's own words. The previous text asserted a SoftHSM limitation from a
    # failed command, which is how a wrong curve name passed as a product fact.
    echo "  [SKIP] no Ed25519 key in the token; pkcs11-tool said:"
    sed 's/^/         /' ed-keygen.log 2>/dev/null | tail -3
fi

# === 7. RSA-PSS CRL signing via SoftHSM ===
echo "=== 7. RSA-PSS CRL signing via SoftHSM ==="
LD_LIBRARY_PATH="$TOOL_LD" "$PKTOOL" --module "$SOFTHSM_MOD" --keypairgen \
    --key-type rsa:2048 --label rsapss-ca --id 0105 --login --pin 1234 >/dev/null 2>&1
RSA_URI="pkcs11:token=PKITEST;object=rsapss-ca;type=private?pin-value=1234"
PKCS11_PROVIDER_MODULE="$SIGN_MOD" "$OSSL" req -x509 -new -key "$RSA_URI" -sha256 -days 3650 \
    -subj "/CN=HSM RSA-PSS CA" -out rsapss-ca.pem \
    -provider-path "$PROVDIR" -provider pkcs11 -provider default >/dev/null 2>&1
if [ -s rsapss-ca.pem ]; then
    echo "  RSA-PSS CA cert self-signed by the HSM key"
    pg_seed_ca_row hsm-rsapss "$W/rsapss-ca.pem" "$RSA_URI"   # a CA is a `certs` row
    pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,ca_instance_id) VALUES('dead04',-1,1,$NOW,$((NOW-86400)),$((NOW+86400)),'CN=gone.host','x','gone.host','ab','hsm-rsapss');"
    cat > rsapss-ocsp.conf <<EOF
SIGNING_CA_PEM=$W/rsapss-ca.pem
SIGNING_CA_KEY=$RSA_URI
SIGNING_CA_ID=hsm-rsapss
PKCS11_MODULE=$SIGN_MOD
PKCS11_PROVIDER_PATH=$PROVDIR
PG_CONNINFO=$PG_CONNINFO
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
CRL_PATH=$CRLP
LOG_LEVEL=info
EOF
    "$ROOT/build/fastpki-ocsp" --config rsapss-ocsp.conf >srv.log 2>&1 & P=$!
    # Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
    wait_port "$PORT" "$P" || true
    if kill -0 $P 2>/dev/null; then
        curl -s "http://127.0.0.1:$PORT$CRLP/hsm-rsapss" -o rsapss-crl.der
        chk "RSA-PSS CRL retrieved" ok "$( [ -s rsapss-crl.der ] && echo ok || echo no )"
        "$OSSL" crl -inform DER -in rsapss-crl.der -CAfile rsapss-ca.pem -noout 2>rsapss-verr.txt && a=yes || a=no
        chk "RSA-PSS CRL signature verifies against the HSM CA" yes "$a"
        "$OSSL" crl -inform DER -in rsapss-crl.der -noout -text 2>/dev/null | tr 'A-F' 'a-f' | tr -d ' :' | grep -qi dead04 && SER=y || SER=n
        chk "revoked serial present in the RSA-PSS HSM-signed CRL" "y" "$SER"
        kill $P 2>/dev/null; wait $P 2>/dev/null; sleep 0.3
    else
        echo "  [SKIP] fastpki-ocsp could not start with the RSA-PSS HSM key"
    fi
else
    echo "  [SKIP] SoftHSM could not self-sign RSA-PSS CA cert (provider ABI?)"
fi

echo
echo "=== PKCS11: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
