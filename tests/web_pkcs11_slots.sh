#!/usr/bin/env bash
# PKCS#11 slot enumeration API + HSM form fields.
#   1. GET /api/pkcs11/slots returns correct structure.
#   2. Without PKCS11_MODULE configured: empty slots, HSM option hidden.
#   3. With PKCS11_MODULE + SoftHSM: slot with token is listed.
#   4. CA create with assembled pkcs11 URI still succeeds.
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
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18098
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
skipout(){ echo "  [SKIP] $1"; echo; echo "=== PKCS11 SLOTS: PASS=$pass FAIL=$fail SKIP=1 ==="; exit 0; }
# A here-string, not a pipe: `grep -q` exits on the first match and SIGPIPEs the
# writer, which bash reports as "write error: Broken pipe" beside a passing assertion.
has(){ grep -q "$2" <<<"$1" && echo yes || echo no; }
findfirst(){ for x in "$@"; do [ -e "$x" ] && { echo "$x"; return 0; }; done; return 1; }

P11PFX="${P11_PREFIX:-$HOME/p11local/usr}"
SOFTHSM_MOD=$(findfirst "${SOFTHSM_MODULE:-}" "$P11PFX/lib/softhsm/libsofthsm2.so" /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so /usr/lib64/softhsm/libsofthsm2.so \
    /opt/homebrew/lib/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so || true)
UTIL=$(findfirst "$P11PFX/bin/softhsm2-util" || true); [ -z "$UTIL" ] && UTIL=$(command -v softhsm2-util || true)
PKTOOL=$(findfirst "$P11PFX/bin/pkcs11-tool" || true); [ -z "$PKTOOL" ] && PKTOOL=$(command -v pkcs11-tool || true)
# Homebrew Cellar may hold pkcs11.dylib under a version dir that the opt/ symlink doesn't reach
CELLAR_PROV=$(ls /opt/homebrew/Cellar/openssl@3/*/lib/ossl-modules/pkcs11.dylib 2>/dev/null | head -1)
PROV=$(findfirst "${P11_PROVIDER:-}" "$P11PFX/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so" /usr/lib/ossl-modules/pkcs11.so \
    /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so /usr/lib64/ossl-modules/pkcs11.so \
    /opt/homebrew/opt/openssl@3/lib/ossl-modules/pkcs11.dylib /opt/homebrew/lib/ossl-modules/pkcs11.dylib \
    $CELLAR_PROV || true)
[ -n "$SOFTHSM_MOD" ] && [ -n "$UTIL" ] && [ -n "$PKTOOL" ] && [ -n "$PROV" ] || \
    skipout "SoftHSM / pkcs11 provider not installed"
PROVDIR=$(dirname "$PROV")
TOOL_LD="$LD_LIBRARY_PATH"; case "$SOFTHSM_MOD" in "$P11PFX"/*) TOOL_LD="$P11PFX/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH";; esac

# ── Part 1: no PKCS#11 configured — slots should be empty ──────────────────
ca_in_token ca.pem "/CN=Test CA" 3650
pg_setup pkcs11_slots_no_hsm
source "$ROOT/tests/user_helpers.sh"
seed_web_user admin testpw admin
trap 'pg_cleanup; kill $P11 $P12 2>/dev/null' EXIT

cat > pki_nohsm.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
LOG_LEVEL=err
EOF
seed_ca_from_conf pki_nohsm.conf   # register the CA (SIGNING_CA_* no longer seed it)
# This phase is specifically "the operator has NOT configured an HSM", so strip the
# PKCS11 keys seeding added. The CA key is still token-held — what is being
# asserted here is the slots API's behaviour when this BINARY has no module
# configured to enumerate, which is a different thing from where the CA key lives.
sed -i.bak '/^PKCS11_MODULE=/d; /^PKCS11_PROVIDER_PATH=/d' pki_nohsm.conf && rm -f pki_nohsm.conf.bak

"$WEB" --config pki_nohsm.conf >srv1.log 2>&1 & P11=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "pki_nohsm.conf" WEB_PORT "$P11" || true
if ! kill -0 $P11 2>/dev/null; then echo "fastpki-web (no-hsm) died:"; cat srv1.log; skipout "web failed to start"; fi
U="http://127.0.0.1:$PORT"
curl -s -c cj1.txt -d 'username=admin&password=testpw' "$U/api/login" >/dev/null

echo "=== 1. no HSM configured: slots API returns empty ==="
SLOTS=$(curl -s -b cj1.txt "$U/api/pkcs11/slots")
chk "slots array is empty"      yes "$(echo "$SLOTS" | grep -q '\"slots\":\[\]' && echo yes || echo no)"
chk "module is empty"           yes "$(echo "$SLOTS" | grep -q '\"module\":\"\"' && echo yes || echo no)"

kill $P11 2>/dev/null; wait $P11 2>/dev/null

# ── Part 2: HSM configured — slots should list the SoftHSM token ──────────
mkdir -p tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$W" > softhsm2.conf
export SOFTHSM2_CONF="$W/softhsm2.conf"
LD_LIBRARY_PATH="$TOOL_LD" "$UTIL" --module "$SOFTHSM_MOD" --init-token --free --label PKISLOTS --pin 1234 --so-pin 12345678 >/dev/null 2>&1

. "$ROOT/tests/p11kit_lib.sh"
# NOT $( ) — see p11kit_lib.sh: the subshell would swallow the server address.
p11_setup_signing "$SOFTHSM_MOD" || skipout "no safe out-of-process PKCS#11 route"
SIGN_MOD="$P11_SIGN_MODULE"

pg_cleanup
pg_setup pkcs11_slots_hsm

cat > pki_hsm.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
WEB_BIND=127.0.0.1
WEB_PORT=$((PORT+1))
PKCS11_MODULE=$SIGN_MOD
PKCS11_PROVIDER_PATH=$PROVDIR
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
seed_ca_from_conf pki_hsm.conf   # register the CA (SIGNING_CA_* no longer seed it)

U2="http://127.0.0.1:$((PORT+1))"
"$WEB" --config pki_hsm.conf >srv2.log 2>&1 & P12=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "pki_hsm.conf" WEB_PORT "$P12" || true
if ! kill -0 $P12 2>/dev/null; then echo "fastpki-web (hsm) died:"; cat srv2.log; skipout "web (hsm) failed to start"; fi
curl -s -c cj2.txt -d 'username=admin&password=testpw' "$U2/api/login" >/dev/null

echo "=== 2. HSM configured: slots API lists token ==="
SLOTS2=$(curl -s -b cj2.txt "$U2/api/pkcs11/slots")
# ⚠️ COMPARE THE VALUE, NOT THE KEY. This matched '"module"' — the KEY, which the handler
# emits unconditionally — so an EMPTY module_path satisfied a check titled "module path is
# set": PKCS11_MODULE dropped from the conf, misspelled, or never reaching the effective
# config all read as a pass. Phase 1 asserts '"module":""' against the same body shape, so
# one response could satisfy both claims. The module this binary was CONFIGURED with is the
# only right answer, and a misspelling now reports itself by name.
MODVAL=$(echo "$SLOTS2" | sed -n 's/.*"module":"\([^"]*\)".*/\1/p')
chk "module path is the configured module" "$SIGN_MOD" "$MODVAL"
# ⚠️ AND THE ARRAY HAS TO HOLD A SLOT. `,"slots":[` is appended before the loop over
# info.slots runs, so '"slots":\[' is present for the EMPTY array too — the very state
# phase 1 asserts with '"slots":[]', which matches that pattern as well. A slot entry opens
# `[{"slot":`, so requiring the brace is what separates "listed a slot" from "enumerated
# nothing" — the two cases this phase exists to tell apart.
chk "slots array is non-empty"  yes "$(echo "$SLOTS2" | grep -q '"slots":\[{' && echo yes || echo no)"
chk "PKISLOTS token found"      yes "$(echo "$SLOTS2" | grep -q 'PKISLOTS' && echo yes || echo no)"
chk "slot id present"           yes "$(echo "$SLOTS2" | grep -q '"slot":' && echo yes || echo no)"
# The algorithms a slot will actually mint, from the token's own
# C_GetMechanismList. The console had been offering a STATIC list of seven while the
# reachable token could do three, and the other four failed as CKR_TOKEN_NOT_PRESENT —
# an error about slots for a problem about algorithms.
chk "slot reports its algorithms" yes "$(echo "$SLOTS2" | grep -q '"algorithms":\[' && echo yes || echo no)"
# SoftHSM advertises RSA and EC keygen on any initialised token, so an empty array here
# means the enumeration silently failed rather than the token being limited — which is
# exactly the confusion this field exists to remove.
chk "RSA is advertised"           yes "$(echo "$SLOTS2" | grep -q '"rsa"' && echo yes || echo no)"
chk "EC is advertised"            yes "$(echo "$SLOTS2" | grep -q '"ec"' && echo yes || echo no)"
# Only slots whose token is actually INITIALIZED may be listed. SoftHSM always
# exposes a spare uninitialized slot alongside the one we just initialized; if it
# leaks into the API the console's slot dropdown shows a blank, unusable entry
# that fails at CA-create time. (CKF_TOKEN_PRESENT is a CK_SLOT_INFO flag — on
# CK_TOKEN_INFO.flags bit 0x1 is CKF_RNG, so filtering on it lets the spare slot
# through; the right gate is CKF_TOKEN_INITIALIZED 0x400.)
chk "no blank-label (uninitialized) slot listed" yes \
    "$(echo "$SLOTS2" | grep -q '"token":""' && echo no || echo yes)"
chk "exactly one slot listed"   1 \
    "$(echo "$SLOTS2" | grep -o '"slot":' | wc -l | tr -d ' ')"

echo "=== 3. CA create with assembled pkcs11 URI still works ==="
# Build the URI from parts the same way the form would.
# pin-source= points to a server-side file containing the PIN.
echo -n "1234" > "$W/pin.txt"
GENURI="pkcs11:token=PKISLOTS;object=slotkey;type=private?pin-source=$W/pin.txt"
R0=$(curl -s -w '\n%{http_code}' -b cj2.txt "$U2/api/ca-instances" \
    --data-urlencode 'id=slot-test' --data-urlencode 'name=Slot Test' \
    --data-urlencode 'subject=/CN=Slot Test' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$GENURI" \
    --data-urlencode 'keygen=true' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048')
C=$(echo "$R0" | tail -1)
# Print the SERVER's reason, not just the status. "create failed (500)" with the body
# thrown away is a line that costs an hour to act on.
if [ "$C" != 201 ]; then echo "  create failed ($C): $(echo "$R0" | sed '$d')"; tail -5 srv2.log; skipout "CA create with pkcs11 URI failed"; fi
chk "create slot-test -> 201"                    201 "$C"
chk "registered key is the assembled URI" "$GENURI" "$(pg_exec "SELECT coalesce(private_key,'') FROM certs WHERE id='slot-test' AND is_ca;")"

# ── Part 4: pre-flight — the token's own answer, before anything is minted ──────
echo
echo "=== 4. unsupported algorithm is refused BEFORE a key is generated ==="
# Every algorithm the CA form offers, against what this token actually advertises.
# The unsupported one is DERIVED from the token rather than hardcoded, because which
# algorithms a given SoftHSM build carries is exactly what differs between machines —
# and deriving it is the same thing the feature itself does.
ADV=$(echo "$SLOTS2" | sed -n 's/.*"algorithms":\[\([^]]*\)\].*/\1/p' | tr -d '"' | tr ',' ' ')
chk "token advertised at least one algorithm" yes "$([ -n "$ADV" ] && echo yes || echo no)"
MISSING=""
for a in rsa rsa-pss ec ed25519 ML-DSA-44 ML-DSA-65 ML-DSA-87; do
    case " $ADV " in *" $a "*) ;; *) MISSING="$a"; break;; esac
done
if [ -z "$MISSING" ]; then
    # ⚠️ NOT A SKIP. In the production image the token is patched to carry every algorithm
    # the form offers, so there is no refusal to provoke -- and that is a fact about a
    # CORRECTLY built image, not a gap. The complement is what matters here and it is
    # perfectly assertable: the pre-flight must not refuse anything the token DOES
    # advertise. A gate that rejects supported algorithms is the same bug pointing the other
    # way, and it is the one this environment can actually catch.
    echo "  (token advertises everything the form offers: $ADV — asserting no FALSE refusal)"
    OK_ALG=$(echo "$ADV" | tr ' ' '\n' | grep -x 'ec' || echo "$ADV" | awk '{print $1}')
    PFURI="pkcs11:token=PKISLOTS;object=pfyes;type=private?pin-source=$W/pin.txt"
    R=$(curl -s -w '\n%{http_code}' -b cj2.txt "$U2/api/ca-instances" \
        --data-urlencode 'id=preflight-yes' --data-urlencode 'name=PreflightOK' \
        --data-urlencode 'subject=/CN=PreflightOK' \
        --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$PFURI" \
        --data-urlencode 'keygen=true' --data-urlencode "key=$OK_ALG" --data-urlencode 'bits=2048')
    PFCODE=$(echo "$R" | tail -1); PFMSG=$(echo "$R" | sed '$d')
    chk "a SUPPORTED algorithm ($OK_ALG) is not refused by the pre-flight" no \
        "$([ "$PFCODE" = 400 ] && echo yes || echo no)"
    chk "  and the refusal text does not name it"  no \
        "$(echo "$PFMSG" | grep -qE "does not support|unsupported" && echo yes || echo no)"
    pg_exec "DELETE FROM certs WHERE id='preflight-yes';" >/dev/null 2>&1 || true
else
    echo "  (token advertises: $ADV — asking for '$MISSING')"
    PFURI="pkcs11:token=PKISLOTS;object=pfkey;type=private?pin-source=$W/pin.txt"
    R=$(curl -s -w '\n%{http_code}' -b cj2.txt "$U2/api/ca-instances" \
        --data-urlencode 'id=preflight-no' --data-urlencode 'name=Preflight' \
        --data-urlencode 'subject=/CN=Preflight' \
        --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$PFURI" \
        --data-urlencode 'keygen=true' --data-urlencode "key=$MISSING" --data-urlencode 'bits=2048')
    PFCODE=$(echo "$R" | tail -1); PFMSG=$(echo "$R" | sed '$d')
    chk "unsupported algorithm -> 400"     400 "$PFCODE"
    chk "refusal names the algorithm"      yes "$(echo "$PFMSG" | grep -qF "$MISSING" && echo yes || echo no)"
    chk "refusal names the token"          yes "$(has "$PFMSG" PKISLOTS)"
    # The error this replaces named the SLOT for a problem about the ALGORITHM, and only
    # surfaced from inside the provider after a keypair already existed in hardware.
    chk "refusal is not CKR_TOKEN_NOT_PRESENT" yes \
        "$(echo "$PFMSG" | grep -q 'CKR_TOKEN_NOT_PRESENT' && echo no || echo yes)"
    chk "no CA row created"                0 "$(pg_exec "SELECT count(*) FROM certs WHERE id='preflight-no' AND is_ca;")"
    # The whole point of a pre-flight: a refusal costs nothing. A failure raised after
    # generate_key_in_token leaves a keypair in the token that no certificate names and
    # nothing ever collects.
    ORPH=$(LD_LIBRARY_PATH="$TOOL_LD" "$PKTOOL" --module "$SOFTHSM_MOD" --token-label PKISLOTS \
        --pin 1234 --list-objects 2>/dev/null | grep -c 'pfkey' || true)
    chk "no orphaned keypair left in the token" 0 "$(echo "$ORPH" | tr -d ' ')"

    echo "=== 5. the pre-flight refuses only on a positive 'no' from the token ==="
    # A URI naming a token this process never enumerated must NOT be pre-refused. The
    # check exists to replace a confusing error, not to invent a new class of them:
    # an unreadable module or an unknown token has said nothing, and silence is consent.
    R2=$(curl -s -w '\n%{http_code}' -b cj2.txt "$U2/api/ca-instances" \
        --data-urlencode 'id=preflight-unknown' --data-urlencode 'name=Preflight U' \
        --data-urlencode 'subject=/CN=Preflight U' --data-urlencode 'keyloc=pkcs11' \
        --data-urlencode "keyref=pkcs11:token=NOSUCHTOKEN;object=pfkey2;type=private" \
        --data-urlencode 'keygen=true' --data-urlencode "key=$MISSING" --data-urlencode 'bits=2048')
    chk "unknown token is not pre-refused" yes \
        "$(echo "$R2" | sed '$d' | grep -q 'does not generate' && echo no || echo yes)"
fi

# ── Part 6: the console consumes the field it is served ────────────────────────
echo
echo "=== 6. the CA form filters its algorithm dropdown from the slot ==="
# A field the API emits and no form reads is the same as no field at all, so assert the
# WIRING (hsmSyncSlot calling it), not merely that the function is defined somewhere.
PAGE=$(curl -s -b cj2.txt "$U2/")
chk "console defines the algorithm filter"  yes "$(has "$PAGE" 'function hsmAlgoSync')"
chk "slot changes drive it"                 yes \
    "$(echo "$PAGE" | grep -A6 'function hsmSyncSlot' | grep -q 'hsmAlgoSync(prefix)' && echo yes || echo no)"
# Disabled, not removed: an option that vanishes is indistinguishable from a feature
# that was taken away — which is how it was reported in the first place.
chk "unavailable algorithms are disabled, not removed" yes "$(has "$PAGE" 'o.disabled = !ok')"

echo "=== The form reads the EFFECTIVE config, not the startup snapshot ==="
# /api/config overlays the DB config; /api/pkcs11/slots did not. So an operator who changed
# MS_KEY in the console saw the new value on the Config page while the HSM request form
# kept offering the value the process booted with — the form "insisting on" a key name they
# had already replaced, with the Config page apparently agreeing with them.
#
# NOTE the server used here: this suite drops and recreates its database partway through,
# so server 1's DB no longer exists by this point and pg_exec talks to server 2's. Writing
# the config row against one and reading it from the other asserts nothing.
#
# Two readers of one setting must not disagree. This changes the DB config UNDER a running
# server and requires both endpoints to move together, with no restart.
pg_exec "INSERT INTO config(key,value) VALUES('MS_KEY','pkcs11:token=fastpki;object=ms-tls-rsa;type=private')
         ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value;" >/dev/null
CFG=$(curl -s -b cj2.txt "$U2/api/config")
SLOTS=$(curl -s -b cj2.txt "$U2/api/pkcs11/slots")
chk "the Config page shows the new key"      yes \
    "$(echo "$CFG"   | grep -q 'ms-tls-rsa' && echo yes || echo no)"
chk "and so does the HSM form's key map"     yes \
    "$(echo "$SLOTS" | grep -q 'ms-tls-rsa' && echo yes || echo no)"
# ...and reverting is picked up too, so this is a live read rather than a one-shot cache.
pg_exec "DELETE FROM config WHERE key='MS_KEY';" >/dev/null
chk "reverting drops it from both"           no \
    "$(curl -s -b cj2.txt "$U2/api/pkcs11/slots" | grep -q 'ms-tls-rsa' && echo yes || echo no)"

echo
echo "=== PKCS11 SLOTS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
