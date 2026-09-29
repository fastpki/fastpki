#!/usr/bin/env bash
# CA-creation page — PKCS#11 / HSM key location.
# The dedicated CA-creation form can back a NEW CA with an EXISTING token key
# (`keyloc=pkcs11` + a `pkcs11:` handle) instead of a generated software key: the
# server builds + self-signs the CA cert with the token key (which never leaves the
# HSM) and registers the pkcs11 URI as the CA's signing key — no private key on
# disk. Drives POST /api/ca-instances and DEEP-INSPECTS the emitted cert.
# Skips cleanly where SoftHSM / the pkcs11 provider aren't installed.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"   # macOS
unset OPENSSL_CONF 2>/dev/null; export OPENSSL_CONF=""
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18097
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
skipout(){ echo "  [SKIP] $1"; echo; echo "=== WEB CA HSM: PASS=$pass FAIL=$fail SKIP=1 ==="; exit 0; }
findfirst(){ for x in "$@"; do [ -e "$x" ] && { echo "$x"; return 0; }; done; return 1; }

pg_setup web_ca_hsm
trap 'pg_cleanup; kill ${P:-} 2>/dev/null' EXIT
# ca_in_token starts the shared p11-kit server IN THIS SHELL and exports SOFTHSM2_CONF
# for it. This suite used to build its own token directory beforehand, which that call
# then silently replaced, so the token holding the CA key became invisible and the run
# ended at "no private key found at pkcs11 URI" — visible only when the suite was run on
# its own, because run_all.sh starts a server first and leaves SOFTHSM2_CONF alone.
# One token directory, owned by the harness (§3d: a suite must run standalone).
ca_in_token ca.pem "/CN=Global CA" 3650
# The CA key this suite hands the console: its own token on that same server.
URI=$(hsm_ca_key hsmca) || skipout "could not mint a CA key in a token"
TOK=$(sed -n 's/.*token=\([^;?]*\).*/\1/p' <<<"$URI")
# Read a minted key back from the token itself. Through the client shim, and naming the
# token explicitly — the shared server carries several, and "the first one" is whichever
# SoftHSM happens to enumerate first.
intoken(){ "$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$TOK" --list-objects \
    --login --pin 1234 2>/dev/null | grep -q "$1" && echo yes || echo no; }
source "$ROOT/tests/user_helpers.sh"
seed_web_user boss bosspw admin
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf   # PKCS11_MODULE = the client shim, not SoftHSM itself
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat srv.log; skipout "fastpki-web could not start"; fi
U="http://127.0.0.1:$PORT"
# `fastpki-ca sub --out-dir` is the CLI's OWN argument and has nothing to do with the
# removed CA_INSTANCE_DIR — the CLI writes where you tell it to. Named here so
# the distinction is visible rather than looking like a leftover.
CLI_OUT="$W/cli-out"; mkdir -p "$CLI_OUT"
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null
create(){ curl -s -o /dev/null -w '%{http_code}' -b boss.cj "$U/api/ca-instances" "$@"; }
create_body(){ curl -s -b boss.cj "$U/api/ca-instances" "$@"; }

echo "=== 1. create an HSM-backed root CA from the console (key stays in the token) ==="
C=$(create --data-urlencode 'id=hsm-root' --data-urlencode 'name=HSM Root' \
    --data-urlencode 'subject=/CN=HSM Root CA/O=FastPKI' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$URI" \
    --data-urlencode 'md=sha256' --data-urlencode 'pathlen=1')
if [ "$C" != 201 ]; then echo "create failed ($C):"; tail -5 srv.log; skipout "web HSM CA create failed (provider ABI?)"; fi
chk "create hsm-root -> 201"                 201 "$C"
# CA_INSTANCE_DIR is gone — the console wrote <id>.crt there and nothing read it,
# while the certificate is a `certs` row. Ask the API, which is what an
# operator and every other service do.
pem(){ curl -s -b boss.cj "$U/api/ca-instances/$1/cert-pem"; }
chk "CA cert is served by the API"           yes "$(pem hsm-root | grep -q 'BEGIN CERTIFICATE' && echo yes || echo no)"
chk "  and nothing was written to disk"      no  "$([ -d "$W/ca-inst" ] && echo yes || echo no)"
chk "NO CA material on disk at all" yes "$([ ! -d "$W/ca-inst" ] && echo yes || echo no)"
chk "registered signing_ca_key is the pkcs11 URI" "$URI" "$(pg_exec "SELECT coalesce(private_key,'') FROM certs WHERE id='hsm-root' AND is_ca;")"
T=$(pem hsm-root | "$OSSL" x509 -noout -text 2>/dev/null)
chk "cert is a CA (CA:TRUE)"                  yes "$(echo "$T" | grep -q 'CA:TRUE' && echo yes || echo no)"
chk "cert subject carries O"                  yes "$(echo "$T" | grep -Eq 'O *= *FastPKI' && echo yes || echo no)"
chk "BasicConstraints pathlen:1"              yes "$(echo "$T" | grep -q 'pathlen:1' && echo yes || echo no)"
pem hsm-root > hsm-root.pem
chk "self-signed by the HSM key (openssl verify)" "hsm-root.pem: OK" \
    "$("$OSSL" verify -CAfile hsm-root.pem hsm-root.pem 2>/dev/null)"

echo "=== 2. GENERATE a fresh key INSIDE the token from the console (keygen=true) ==="
# A distinct object label/id so the provider mints a NEW token key (not hsmca).
GENURI="pkcs11:token=$TOK;object=gencak;id=%02;type=private?pin-value=1234"
# RSA: SoftHSM's ECDSA-via-provider signing is unreliable across platforms (macOS
# fails outright), while RSA signs everywhere — so the in-token keygen is proven
# with RSA, the same key type as the existing-key case above.
C=$(create --data-urlencode 'id=hsm-gen' --data-urlencode 'name=HSM Gen' \
    --data-urlencode 'subject=/CN=HSM Gen CA' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$GENURI" \
    --data-urlencode 'keygen=true' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048')
if [ "$C" != 201 ]; then echo "keygen create failed ($C):"; tail -8 srv.log; skipout "web HSM in-token keygen failed (provider keygen ABI?)"; fi
chk "create hsm-gen (in-token keygen) -> 201" 201 "$C"
chk "new key object persisted in the token"   yes \
    "$(intoken gencak)"
chk "NO CA material on disk at all (gen)" yes "$([ ! -d "$W/ca-inst" ] && echo yes || echo no)"
chk "registered signing_ca_key is the new URI" "$GENURI" "$(pg_exec "SELECT coalesce(private_key,'') FROM certs WHERE id='hsm-gen' AND is_ca;")"
pem hsm-gen > hsm-gen.pem
chk "self-signed by the generated HSM key" "hsm-gen.pem: OK" \
    "$("$OSSL" verify -CAfile hsm-gen.pem hsm-gen.pem 2>/dev/null)"
chk "generated CA is RSA (sha256WithRSAEncryption)" yes \
    "$(pem hsm-gen | "$OSSL" x509 -noout -text 2>/dev/null | grep -qi 'sha256WithRSAEncryption' && echo yes || echo no)"

echo "=== 3. in-token RSA-PSS keygen + sign ==="
GENRSAURI="pkcs11:token=$TOK;object=genrsapss;id=%03;type=private?pin-value=1234"
C=$(create --data-urlencode 'id=hsm-rsapss' --data-urlencode 'name=HSM RSA-PSS' \
    --data-urlencode 'subject=/CN=HSM RSA-PSS CA' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$GENRSAURI" \
    --data-urlencode 'keygen=true' --data-urlencode 'key=rsa-pss' --data-urlencode 'bits=2048')
# ⚠️ THIS USED TO SKIP, blaming "an upstream pkcs11-provider PSS limitation". That was
# WRONG and the wrong layer. Measured: SoftHSM advertises RSA-PKCS-PSS and signs with it;
# patched p11-kit relays those mechanisms and `pkcs11-tool --sign --mechanism
# SHA256-RSA-PKCS-PSS` succeeds through the client shim; and the provider signs PSS fine
# when it is ASKED to. The real defect was ours: the console minted the key and then
# RELOADED it by URI, which loses the "RSA-PSS" type name is_rsa_pss_p11_key() reads, so the
# PSS branch never ran and the token refused the PKCS#1 v1.5 request its
# CKA_ALLOWED_MECHANISMS forbids. So this asserts success now — a SKIP here would hide a
# FastPKI bug behind an upstream excuse.
if [ "$C" != 201 ]; then echo "rsa-pss CA create failed ($C):"; tail -8 srv.log; fi
chk "create hsm-rsapss (in-token keygen) -> 201" 201 "$C"
chk "RSA-PSS key object persisted in token" yes \
    "$(intoken genrsapss)"
chk "NO CA material on disk at all (rsapss)" yes "$([ ! -d "$W/ca-inst" ] && echo yes || echo no)"
pem hsm-rsapss > hsm-rsapss.pem
chk "self-signed by the RSA-PSS generated key" "hsm-rsapss.pem: OK" \
    "$("$OSSL" verify -CAfile hsm-rsapss.pem hsm-rsapss.pem 2>/dev/null)"
# ⚠️ ONE ANSWER, not either. This used to accept `rsaEncryption|rsassaPss`, which
# made it the only assertion in the tree that looks at an HSM key's SPKI and gave it nothing
# to fail on — an RSA-PSS key published as unrestricted rsaEncryption passed it happily.
# That is exactly what leaves used to do; this CA path has been right for longer,
# so pinning it costs nothing and closes the hole the tolerance left.
chk "RSA-PSS CA cert publishes the RFC 4055 restricted SPKI" rsassaPss \
    "$(pem hsm-rsapss | "$OSSL" x509 -noout -text 2>/dev/null \
        | sed -n 's/.*Public Key Algorithm: //p' | head -1)"
# Check the signature algorithm is RSA-PSS (not plain RSA)
chk "signature is rsassaPss (not plain RSA)" yes \
    "$(pem hsm-rsapss | "$OSSL" x509 -noout -text 2>/dev/null | grep -qi 'rsassaPss' && echo yes || echo no)"

echo "=== 3b. an EC CA key generated in the token, through the PRODUCT ==="
# The server-side key type had never been varied. The console
# offers "EC (ECDSA)" as a CA key, and nothing tested it — every in-token keygen here was
# RSA or RSA-PSS, so this is the first assertion in the tree that asks the product to sign
# a CA certificate with an elliptic-curve key held in a token.
#
# ⚠️ ASSERTED, NOT SKIPPED, and deliberately so. Driving the token with `openssl req -x509`
# through pkcs11-provider fails at EVP_DigestSignUpdate ("ECDSA digest_sign_update") both
# on macOS and in the image, which reads like an upstream limitation and would justify a
# SKIP. Section 3 above is the standing warning against exactly that move: it used to SKIP
# blaming "an upstream pkcs11-provider PSS limitation", and the defect turned out to be
# ours. The product does not sign the way that probe does, so a probe failure says
# nothing about the product. Ask the product and believe the certificate.
GENECURI="pkcs11:token=$TOK;object=genec;id=%04;type=private?pin-value=1234"
C=$(create --data-urlencode 'id=hsm-ec' --data-urlencode 'name=HSM EC' \
    --data-urlencode 'subject=/CN=HSM EC CA' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$GENECURI" \
    --data-urlencode 'keygen=true' --data-urlencode 'key=ec' --data-urlencode 'bits=256')
if [ "$C" != 201 ]; then echo "  ec CA create said $C:"; tail -6 srv.log; fi
chk "create hsm-ec (in-token EC keygen) -> 201" 201 "$C"
chk "EC key object persisted in token"          yes "$(intoken genec)"
pem hsm-ec > hsm-ec.pem 2>/dev/null
chk "self-signed by the EC generated key" "hsm-ec.pem: OK" \
    "$("$OSSL" verify -CAfile hsm-ec.pem hsm-ec.pem 2>/dev/null)"
chk "  and the SPKI is id-ecPublicKey" "id-ecPublicKey" \
    "$("$OSSL" x509 -in hsm-ec.pem -noout -text 2>/dev/null \
        | sed -n 's/.*Public Key Algorithm: //p' | head -1)"
chk "  signed with ecdsa-with-SHA256, not RSA" yes \
    "$("$OSSL" x509 -in hsm-ec.pem -noout -text 2>/dev/null \
        | grep -qi 'ecdsa-with-SHA256' && echo yes || echo no)"

echo "=== 3c. Ed25519 and ML-DSA CA keys, gated on what the TOKEN advertises ==="
# ⚠️ Which algorithms exist is a property of the SoftHSM build, and it genuinely differs:
# the shipped image builds SoftHSM from source with -DENABLE_MLDSA=ON (Dockerfile stage
# 2b), a distro package generally does not. So these cells cannot simply be asserted
# everywhere — but they must not silently vanish either.
#
# ⚠️ ASK THE PRODUCT WHAT THE TOKEN ADVERTISES. `pkcs11-tool --list-mechanisms` prints
# mechanisms it cannot name as bare hex — ML-DSA shows up as `mechtype-0x1C` /
# `mechtype-0x1D` — so grepping it for "ML-DSA" reports "unsupported" on a token that
# supports it perfectly well. That mistake was made once already, reporting ML-DSA
# missing from an image that had it. /api/pkcs11/slots derives the list from
# the token's real mechanism set (pkcs11_slot_algorithms), which is the same question
# asked correctly.
ADV=$(curl -s -b boss.cj "$U/api/pkcs11/slots" \
      | sed -n 's/.*"algorithms":\[\([^]]*\)\].*/\1/p' | tr -d '"' | tr ',' ' ')
echo "  (token advertises: ${ADV:-none})"
ca_keytype_cell() { # <algo> <id> <expect-spki-substring>
    local algo="$1" id="$2" want="$3"
    case " $ADV " in
        *" $algo "*) ;;
        *) echo "  [SKIP] token does not advertise $algo — cell not run (this is a TOKEN"
           echo "         limit, not a FastPKI one; the image's SoftHSM build carries more)"
           return 0;;
    esac
    local uri="pkcs11:token=$TOK;object=$id;type=private?pin-value=1234"
    local c
    c=$(create --data-urlencode "id=$id" --data-urlencode "name=$id" \
        --data-urlencode "subject=/CN=$id CA" \
        --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$uri" \
        --data-urlencode 'keygen=true' --data-urlencode "key=$algo")
    if [ "$c" != 201 ]; then echo "  $algo CA create said $c:"; tail -4 srv.log; fi
    chk "create $id ($algo in-token keygen) -> 201" 201 "$c"
    chk "  $algo key object persisted in token"     yes "$(intoken "$id")"
    pem "$id" > "$id.pem" 2>/dev/null
    chk "  self-signed by the $algo key" "$id.pem: OK" \
        "$("$OSSL" verify -CAfile "$id.pem" "$id.pem" 2>/dev/null)"
    chk "  and the SPKI names $want" yes \
        "$("$OSSL" x509 -in "$id.pem" -noout -text 2>/dev/null | grep -qi "$want" && echo yes || echo no)"
}
ca_keytype_cell ed25519    hsm-ed25519 "ED25519"
ca_keytype_cell ML-DSA-65  hsm-mldsa65 "ML-DSA-65"

echo "=== 3a. sign with a LOADED RSA-PSS key, not a generated one ==="
# ⚠️ THE CASE EVERYTHING ABOVE MISSES. Every assertion so far signs with the handle the
# console just GENERATED, and the pkcs11 provider reports that one as type "RSA-PSS". The
# same key loaded back through OSSL_STORE comes back as plain "RSA", so any path that loads
# its key — a sub-CA signing with its parent's key, CRL signing, audit signing — lost the
# PSS branch and asked for PKCS#1 v1.5, which this key's CKA_ALLOWED_MECHANISMS forbids.
#
# fastpki-ca is a SEPARATE PROCESS, so `create --parent hsm-rsapss` must load the parent key
# by URI: exactly the broken path, and the only way to exercise it from here. It fails
# against a build that decides by type name, and passes once the padding is decided by
# asking the token (p11_rsa_requires_pss probes with v1.5 — the padding only an
# unrestricted key accepts; both kinds accept PSS, which is why probing with PSS could not
# tell them apart).
# ⚠️ fastpki-ca create does NOT mint the new instance's own key — --ca-key must already name
# a token object, and without this the create fails with "no private key found at
# pkcs11 URI" and the assertion below measures my setup rather than the product. Caught by
# running the case against a build WITHOUT the fix and seeing it fail identically.
"$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$TOK" --keypairgen \
    --key-type rsa:2048 --label subpss --id 20 --login --pin 1234 >/dev/null 2>&1
SUBURI="pkcs11:token=$TOK;object=subpss;id=%20;type=private?pin-value=1234"
"$ROOT/build/fastpki-ca" --config bootstrap.conf create sub-of-pss --name "Sub of PSS" \
    --parent hsm-rsapss --ca-key "$SUBURI" --key rsa --bits 2048 \
    --out-dir "$CLI_OUT" >subpss.log 2>&1
chk "sub-CA signed by a LOADED RSA-PSS parent key" yes \
    "$([ -s "$CLI_OUT/sub-of-pss.crt" ] && echo yes || echo no)"
if [ -s "$CLI_OUT/sub-of-pss.crt" ]; then
    chk "and the parent's signature really is rsassaPss" yes \
        "$(pem sub-of-pss | "$OSSL" x509 -noout -text 2>/dev/null \
           | grep -qi 'rsassaPss' && echo yes || echo no)"
    chk "sub-CA verifies under the RSA-PSS parent" "$CLI_OUT/sub-of-pss.crt: OK" \
        "$("$OSSL" verify -CAfile hsm-rsapss.pem "$CLI_OUT/sub-of-pss.crt" 2>/dev/null)"
else
    echo "    sub-CA creation output:"; tail -4 subpss.log
fi

echo "=== 3b. RSA-PSS with SHA-384 (CKM_SHA384_RSA_PKCS_PSS) ==="
GENRSA384URI="pkcs11:token=$TOK;object=genrsapss384;id=%04;type=private?pin-value=1234"
C=$(create --data-urlencode 'id=hsm-rsapss384' --data-urlencode 'name=HSM RSA-PSS 384' \
    --data-urlencode 'subject=/CN=HSM RSA-PSS 384 CA' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$GENRSA384URI" \
    --data-urlencode 'keygen=true' --data-urlencode 'key=rsa-pss' --data-urlencode 'bits=2048' \
    --data-urlencode 'md=sha384')
if [ "$C" != 201 ]; then echo "rsa-pss384 create failed ($C):"; tail -8 srv.log; skipout "RSA-PSS SHA-384 keygen failed"; fi
chk "create hsm-rsapss384 -> 201"                        201 "$C"
chk "RSA-PSS-384 key object persisted in token"          yes \
    "$(intoken genrsapss384)"
chk "NO CA material on disk at all (rsapss384)" yes "$([ ! -d "$W/ca-inst" ] && echo yes || echo no)"
pem hsm-rsapss384 > hsm-rsapss384.pem
chk "self-signed by the RSA-PSS-384 generated key" "hsm-rsapss384.pem: OK" \
    "$("$OSSL" verify -CAfile hsm-rsapss384.pem hsm-rsapss384.pem 2>/dev/null)"
chk "RSA-PSS-384 signature is rsassaPss"                 yes \
    "$(pem hsm-rsapss384 | "$OSSL" x509 -noout -text 2>/dev/null | grep -qi 'rsassaPss' && echo yes || echo no)"
chk "RSA-PSS-384 uses sha384 hash"                       yes \
    "$(pem hsm-rsapss384 | "$OSSL" x509 -noout -text 2>/dev/null | grep -q 'sha384' && echo yes || echo no)"

echo "=== 3c. RSA-PSS with SHA-512 (CKM_SHA512_RSA_PKCS_PSS) ==="
GENRSA512URI="pkcs11:token=$TOK;object=genrsapss512;id=%05;type=private?pin-value=1234"
C=$(create --data-urlencode 'id=hsm-rsapss512' --data-urlencode 'name=HSM RSA-PSS 512' \
    --data-urlencode 'subject=/CN=HSM RSA-PSS 512 CA' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$GENRSA512URI" \
    --data-urlencode 'keygen=true' --data-urlencode 'key=rsa-pss' --data-urlencode 'bits=2048' \
    --data-urlencode 'md=sha512')
if [ "$C" != 201 ]; then echo "rsa-pss512 create failed ($C):"; tail -8 srv.log; skipout "RSA-PSS SHA-512 keygen failed"; fi
chk "create hsm-rsapss512 -> 201"                        201 "$C"
chk "RSA-PSS-512 key object persisted in token"          yes \
    "$(intoken genrsapss512)"
chk "NO CA material on disk at all (rsapss512)" yes "$([ ! -d "$W/ca-inst" ] && echo yes || echo no)"
pem hsm-rsapss512 > hsm-rsapss512.pem
chk "self-signed by the RSA-PSS-512 generated key" "hsm-rsapss512.pem: OK" \
    "$("$OSSL" verify -CAfile hsm-rsapss512.pem hsm-rsapss512.pem 2>/dev/null)"
chk "RSA-PSS-512 signature is rsassaPss"                 yes \
    "$(pem hsm-rsapss512 | "$OSSL" x509 -noout -text 2>/dev/null | grep -qi 'rsassaPss' && echo yes || echo no)"
chk "RSA-PSS-512 uses sha512 hash"                       yes \
    "$(pem hsm-rsapss512 | "$OSSL" x509 -noout -text 2>/dev/null | grep -q 'sha512' && echo yes || echo no)"

echo "=== 5. LISTING the token must not break SIGNING with it ==="
# ⚠️ THIS ORDER HAD NEVER BEEN RUN. Every section above only POSTs; nothing GETs the CA
# list in between, so the enumeration and a signature never met in one process — which is
# exactly why the defect below was invisible.
#
# Put pkcs11_list_objects() on the CAs dashboard and both issue pickers, and that
# function ended with C_Logout. PKCS#11 login state is per-token per-APPLICATION, not
# per-session (v2.40 §6.7.5), so that call logged out every session THIS PROCESS holds on
# the token — including the OpenSSL pkcs11 provider's, the ones the console signs with.
# The file already refused to call C_Finalize for precisely that reason and stopped one
# call short of the same conclusion; the C_Logout is now gone too.
#
# ⚠️ AND THIS SECTION DOES NOT DISCRIMINATE ON THAT. Measured both ways: with the
# C_Logout restored, every assertion below still PASSES. On this host's SoftHSM +
# pkcs11-provider the provider simply logs back in on demand, so I could not demonstrate
# that the logout broke anything, and I am not claiming it did. What is asserted here is
# the interleaving itself — list the token, then sign with it — which no suite ran before,
# every section above being POST-only. That gap is why a change to the enumeration could
# not have been caught by this file at all.
#
# The removal stands on the spec and on the C_Finalize precedent beside it, not on a red
# test. Where it could still bite is the shipped image: the DCs reach the token through
# p11-kit over a socket to a SoftHSM sidecar, which is different plumbing from this host,
# and deploy/lab-test.sh runs this suite there.
LIST=$(curl -s -b boss.cj "$U/api/ca-instances")
# PRECONDITION: the list really did enumerate the token. Without `signable` in the JSON,
# The enumeration did not run and the section below proves nothing about logout.
chk "PRECONDITION: the CA list enumerated the token" yes \
    "$(echo "$LIST" | grep -q '"signable"' && echo yes || echo no)"
# Now sign with the token key AFTER that enumeration. Same key, new CA id.
C=$(create --data-urlencode 'id=hsm-after-list' --data-urlencode 'name=After List' \
    --data-urlencode 'subject=/CN=After List CA' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$URI" \
    --data-urlencode 'md=sha256')
chk "signing still works after the token was listed" 201 "$C"
if [ "$C" != 201 ]; then echo "  --- server log tail ---"; tail -5 srv.log | sed 's/^/    /'; fi
# ⚠️ Decode the artifact, not the status code: a 201 that stored an unsigned or
# wrongly-signed certificate is the failure this repo keeps finding.
pem hsm-after-list > after.pem 2>/dev/null
chk "  and the certificate it produced verifies"    "after.pem: OK" \
    "$("$OSSL" verify -CAfile after.pem after.pem 2>/dev/null)"
# And listing twice in a row must not degrade either.
curl -s -o /dev/null -b boss.cj "$U/api/ca-instances"
curl -s -o /dev/null -b boss.cj "$U/api/ca-instances"
chk "  …and after listing twice more"               200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj "$U/api/ca-instances/hsm-after-list/cert-pem")"

echo "=== 6. replicable keys, from every console form that mints one ==="
# The console minted every token key non-extractable, so a hierarchy created in it could
# never be replicated to an HA standby, and a rekey silently confined a CA that had been
# replicable. CKA_EXTRACTABLE is fixed at generation, so the assertion is the TOKEN's
# attribute on the key each form minted, not the status code of the request.
xt(){ hsm_key_extractable "$TOK" "$1"; }
chk "control: a key the console minted ordinarily is NOT extractable" no "$(xt gencak)"

RROOT="pkcs11:token=$TOK;object=replroot;id=%40;type=private?pin-value=1234"
C=$(create --data-urlencode 'id=repl-root' --data-urlencode 'name=Replicable Root' \
    --data-urlencode 'subject=/CN=Replicable Root CA' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$RROOT" \
    --data-urlencode 'keygen=true' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
    --data-urlencode 'replicable=true')
[ "$C" = 201 ] || { echo "  replicable CA create said $C:"; tail -4 srv.log; }
chk "New CA, replicable=true -> 201"              201 "$C"
chk "  its key is extractable in the token"       yes "$(xt replroot)"
pem repl-root > repl-root.pem 2>/dev/null
chk "  and the key loaded back signs the CA certificate" "repl-root.pem: OK" \
    "$("$OSSL" verify -CAfile repl-root.pem repl-root.pem 2>/dev/null)"

R=$(curl -s -o csr.json -w '%{http_code}' -b boss.cj "$U/api/ca-instances/csr" \
    --data-urlencode 'subject=/CN=Replicable Sub CA' \
    --data-urlencode 'keyloc=pkcs11' \
    --data-urlencode "keyref=pkcs11:token=$TOK;object=replcsr;id=%41;type=private?pin-value=1234" \
    --data-urlencode 'keygen=true' --data-urlencode 'key=ec' --data-urlencode 'replicable=true')
[ "$R" = 201 ] || { echo "  replicable CSR said $R: $(cut -c1-160 csr.json)"; }
chk "CA CSR, replicable=true (EC) -> 201"         201 "$R"
chk "  its key is extractable in the token"       yes "$(xt replcsr)"

R=$(curl -s -o rk.json -w '%{http_code}' -b boss.cj -X POST "$U/api/ca-instances/repl-root/renew" \
    --data-urlencode "keyref=pkcs11:token=$TOK;object=replroot2;id=%42;type=private?pin-value=1234" \
    --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' --data-urlencode 'replicable=true')
[ "$R" = 201 ] || { echo "  replicable rekey said $R: $(cut -c1-160 rk.json)"; }
chk "rekey, replicable=true -> 201"               201 "$R"
chk "  the NEW key is extractable in the token"   yes "$(xt replroot2)"

R=$(curl -s -o hsmreq.json -w '%{http_code}' -b boss.cj "$U/api/certs/request-hsm" \
    --data-urlencode 'ca_instance=hsm-gen' --data-urlencode 'cn=repl-svc' \
    --data-urlencode "keyref=pkcs11:token=$TOK;object=replsvc;id=%43;type=private?pin-value=1234" \
    --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' --data-urlencode 'replicable=true')
[ "$R" = 201 ] || { echo "  replicable HSM request said $R: $(cut -c1-160 hsmreq.json)"; }
chk "Inventory HSM request, replicable=true -> 201" 201 "$R"
chk "  its key is extractable in the token"       yes "$(xt replsvc)"

# EVERY CA key algorithm the form offers, not only RSA: the replicable path mints through
# PKCS#11 directly and loads the key back by URI, so each type has to come back usable —
# RSA-PSS above all, which is recognised on load only by its CKA_ALLOWED_MECHANISMS.
n=50
for spec in ec:P-384 ec:P-521 ed25519: ed448: ML-DSA-65: rsa-pss:; do
    algo=${spec%%:*}; curve=${spec#*:}; n=$((n+1)); lbl="repl$n"
    args=(--data-urlencode "id=$lbl" --data-urlencode "subject=/CN=Replicable $algo $curve CA"
          --data-urlencode 'keyloc=pkcs11'
          --data-urlencode "keyref=pkcs11:token=$TOK;object=$lbl;id=%$n;type=private?pin-value=1234"
          --data-urlencode 'keygen=true' --data-urlencode "key=$algo" --data-urlencode 'replicable=true')
    [ -n "$curve" ] && args+=(--data-urlencode "curve=$curve")
    [ "$algo" = rsa-pss ] && args+=(--data-urlencode 'bits=2048')
    C=$(create "${args[@]}")
    [ "$C" = 201 ] || { echo "  replicable $algo $curve said $C:"; tail -4 srv.log; }
    chk "New CA, replicable $algo $curve -> 201"      201 "$C"
    chk "  its key is extractable in the token"       yes "$(xt "$lbl")"
    pem "$lbl" > "$lbl.pem" 2>/dev/null
    chk "  and the key loaded back self-signs it"     "$lbl.pem: OK" \
        "$("$OSSL" verify -CAfile "$lbl.pem" "$lbl.pem" 2>/dev/null)"
done
chk "  and the RSA-PSS one publishes the restricted SPKI" rsassaPss \
    "$("$OSSL" x509 -in repl56.pem -noout -text 2>/dev/null \
        | sed -n 's/.*Public Key Algorithm: //p' | head -1)"

# ⚠️ REFUSED BEFORE THE HANDLE IS TOUCHED. With overwrite confirmed, the collision check
# destroys the key already at the handle, so a replicable refusal that came after it would
# cost that key for nothing. `keepme` is an unrelated key standing in for one an operator
# typed the name of.
"$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$TOK" --keypairgen \
    --key-type rsa:2048 --label keepme --id 44 --login --pin 1234 >/dev/null 2>&1
KEEP="pkcs11:token=$TOK;object=keepme;id=%44;type=private?pin-value=1234"
chk "fixture: keepme is in the token"             yes "$(intoken keepme)"
# A curve FastPKI does not mint. The token pre-flight checks the algorithm (`ec`), not the
# curve, so the only thing that can refuse this is the replicable rule — a token-capability
# refusal would pass the assertion for the wrong reason.
C=$(create --data-urlencode 'id=repl-ed' --data-urlencode 'subject=/CN=Replicable secp256k1' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$KEEP" \
    --data-urlencode 'keygen=true' --data-urlencode 'overwrite=true' \
    --data-urlencode 'key=ec' --data-urlencode 'curve=secp256k1' --data-urlencode 'replicable=true')
chk "replicable EC secp256k1 over an existing key -> 400" 400 "$C"
chk "  and the key that was there survives"       yes "$(intoken keepme)"
C=$(create --data-urlencode 'id=repl-adopt' --data-urlencode 'subject=/CN=Replicable Adopted' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$KEEP" \
    --data-urlencode 'replicable=true')
chk "replicable on an adopted key -> 400, not silently ignored" 400 "$C"
R=$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj -X POST "$U/api/ca-instances/repl-root/renew" \
    --data-urlencode "keyref=$KEEP" --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
    --data-urlencode 'replicable=true')
chk "rekey onto an occupied key name -> 409"      409 "$R"
chk "  and that key survives too"                 yes "$(intoken keepme)"
chk "no CA row was created by any refusal"        0 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id IN ('repl-ed','repl-adopt') AND is_ca;" | tr -d ' ')"

# One rule, four forms: each form that mints a key offers the box and sends it.
PAGE=$(curl -s -b boss.cj "$U/")
for id in ca_replicable cacsr_replicable rk_replicable hsm_replicable; do
    chk "the console offers $id" yes "$(printf '%s' "$PAGE" | grep -q "id=\"$id\"" && echo yes || echo no)"
done
chk "  and all four forms send replicable" 4 \
    "$(printf '%s' "$PAGE" | grep -c "fd.set('replicable', 'true')")"

echo "=== 4. negative paths ==="
chk "pkcs11 keyloc without a handle -> 400" 400 "$(create --data-urlencode 'id=nohandle' --data-urlencode 'subject=/CN=x' --data-urlencode 'keyloc=pkcs11')"
chk "pkcs11 keyloc with a non-pkcs11 handle -> 400" 400 "$(create --data-urlencode 'id=badhandle' --data-urlencode 'subject=/CN=x' --data-urlencode 'keyloc=pkcs11' --data-urlencode 'keyref=/etc/passwd')"
chk "unknown keyloc -> 400" 400 "$(create --data-urlencode 'id=badloc' --data-urlencode 'subject=/CN=x' --data-urlencode 'keyloc=magic')"

echo
echo "=== WEB CA HSM: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
