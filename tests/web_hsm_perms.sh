#!/usr/bin/env bash
# Minting a key inside the HSM is its own permission, and what the token holds
# is finally readable from the console.
#
# ⚠️ THE GAP: there were no such permissions, meaning a requester
# could create keys in HSM. Like hsm:manage given to admin by default and hsm:read might be
# given to auditor, for example. We would then also need a page with HSM keys list. As of
# now, HSM keys are hidden from anyone."
#
# ⚠️ The gap was not one forgotten route. required_caps() matches by PREFIX, so
# `/api/certs/request-hsm` inherited `cert:request` from `/api/certs/request` — the same
# permission self-service enrolment uses. A `requester` could therefore create a
# hardware-resident object that nobody can enumerate from the console and only someone with
# token access can remove.
#
# What this asserts, by driving the real API rather than reading the page:
#   * a requester is REFUSED the HSM route and an admin is not — the server is the gate
#   * the refusal is a permission refusal (403), not a 400 that would pass for the wrong
#     reason if the request were malformed
#   * an auditor can LIST the token and cannot mint into it
#   * the listing names an object we put there ourselves, decoded from the token
#   * the resolved profile is served to the form, so it can display what will apply
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
unset OPENSSL_CONF
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18137
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

pg_setup web_hsm_perms
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
ca_in_token ca.pem "/CN=HSM Perms CA" 3650 permca
seed_web_user boss  bosspw  admin
seed_web_user reqr  reqrpw  requester
seed_web_user audit auditpw auditor

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=permca
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
PINFILE="$W/pin"; printf '1234' > "$PINFILE"; chmod 400 "$PINFILE"
CFG_TOKEN=$(echo "${CA_KEY_URI:-}" | sed -n 's/.*token=\([^;?]*\).*/\1/p')
printf 'PKCS11_TOKEN=%s\nPKCS11_PIN_FILE=%s\n' "$CFG_TOKEN" "$PINFILE" >> bootstrap.conf
seed_ca_from_conf bootstrap.conf
CA_ID=permca

"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" WEB_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat srv.log; exit 1; }
U="http://127.0.0.1:$PORT"
for u in boss:bosspw reqr:reqrpw audit:auditpw; do
  curl -s -c "${u%%:*}.cj" -d "username=${u%%:*}&password=${u##*:}" "$U/api/login" >/dev/null
done
# ⚠️ Prove every login actually worked before asserting on refusals. A cookie jar for a
# failed login produces 401/403 on everything, which reads exactly like a permission
# refusal and would make this whole suite pass while testing nothing.
for u in boss reqr audit; do
  chk "$u is logged in" yes "$(curl -s -b "$u.cj" "$U/api/me" | grep -q '"user"' && echo yes || echo no)"
done

LEAF="pkcs11:token=$CFG_TOKEN;object=perm-leaf;type=private?pin-value=1234"
hsmpost(){ local jar="$1"; shift; curl -s -o /dev/null -w '%{http_code}' -b "$jar" \
             "$U/api/certs/request-hsm" "$@"; }
mkargs(){ echo --data-urlencode "ca_instance=$CA_ID" --data-urlencode "keyref=$1" \
               --data-urlencode "cn=$2" --data-urlencode 'key=rsa' --data-urlencode 'bits=2048'; }

echo "=== 1. hsm:manage exists as a grantable capability ==="
PERMS=$(curl -s -b boss.cj "$U/api/permissions")
chk "the served vocabulary offers hsm:manage" yes "$(has "$PERMS" '"hsm:manage"')"
chk "  ...and hsm:read"                       yes "$(has "$PERMS" '"hsm:read"')"

echo "=== 2. a requester may NOT mint inside the token ==="
# The whole point of the ticket. Before this the same request succeeded.
RC=$(hsmpost reqr.cj $(mkargs "pkcs11:token=$CFG_TOKEN;object=perm-req;type=private?pin-value=1234" reqr.perm.test))
chk "requester -> /api/certs/request-hsm 403" 403 "$RC"
# ⚠️ A 403 for the WRONG reason would look identical. The same identity must still be able
# to use the ORDINARY request route, or this would be measuring a broken login.
RCO=$(curl -s -o /dev/null -w '%{http_code}' -b reqr.cj "$U/api/my-profiles")
chk "  and the same requester still reads its own profiles (not a dead session)" 200 "$RCO"
# And nothing was created in the token by the refused request.
OBJS=$("$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$CFG_TOKEN" --login --pin 1234 \
       --list-objects --type privkey 2>/dev/null)
chk "  and no key was minted by the refused request" no "$(has "$OBJS" 'perm-req')"

echo "=== 3. an admin still can ==="
chk "admin -> /api/certs/request-hsm 201" 201 "$(hsmpost boss.cj $(mkargs "$LEAF" leaf.perm.test))"

echo "=== 4. the token is readable — and only by someone granted hsm:read ==="
KEYS_A=$(curl -s -b audit.cj "$U/api/pkcs11/keys")
chk "auditor -> /api/pkcs11/keys 200" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b audit.cj "$U/api/pkcs11/keys")"
chk "requester -> /api/pkcs11/keys 403" 403 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b reqr.cj "$U/api/pkcs11/keys")"
# Decoded fact, not a shape: the listing must contain the key section 3 just minted and the
# CA key this suite created. A list that is merely well-formed proves nothing.
chk "the listing names the leaf key we just minted" yes "$(has "$KEYS_A" 'perm-leaf')"
chk "  and the CA key that was already there"       yes "$(has "$KEYS_A" 'permca')"
# The CA's signing key says which CA signs with it — it showed an empty "Serves" cell, the
# same as an unused key — and an ordinary leaf key names no CA.
CA_OBJ=$(echo "${CA_KEY_URI:-}" | sed -n 's/.*object=\([^;?]*\).*/\1/p')
CA_PRIV=$(echo "$KEYS_A" | tr '}' '\n' | grep "\"label\":\"$CA_OBJ\"" | grep '"class":"private"')
chk "  and marks the CA key with its CA"            yes "$(echo "$CA_PRIV" | grep -qF "\"cas\":[\"$CA_ID\"]" && echo yes || echo no)"
LEAF_PRIV=$(echo "$KEYS_A" | tr '}' '\n' | grep '"label":"perm-leaf"' | grep '"class":"private"')
chk "  and a leaf key with none"                    yes "$(echo "$LEAF_PRIV" | grep -qF '"cas":[]' && echo yes || echo no)"
chk "  and says which are PRIVATE keys"             yes "$(has "$KEYS_A" '"class":"private"')"
chk "  and names the key type"                      yes "$(has "$KEYS_A" '"keyType":"RSA"')"
# ⚠️ Round 2 — ML keys were displayed with '-' in the type column.
# CKK_ML_DSA was set to 0x1C, which is CKM_ML_DSA_KEY_PAIR_GEN's value; in CKK space 0x1C
# is CKK_BATON. A real ML-DSA key reports 0x4A, matched no branch, and fell to an empty
# string that the page renders as "-".
#
# The shipped image's patched SoftHSM mints ML-DSA, so section 4b asserts that type directly.
# This asserts the property that made the wrong constant invisible: an unrecognised type must
# never come back EMPTY. It reports its number ("type 0x4a"), so the next algorithm we have
# not named is still identifiable instead of blank. The exact constants are pinned by a
# static_assert in pkcs11_helpers.cpp, which no token is needed to check.
chk "  no object reports an EMPTY key type"         no  "$(has "$KEYS_A" '"keyType":""')"
# ⚠️ The listing must never carry key material. It cannot — a token private key has no
# exportable half — but the assertion is cheap and the day it stops being true matters.
chk "the listing carries NO private key material"   no  "$(has "$KEYS_A" 'PRIVATE KEY')"

echo "=== 4b. the listing reports an EC key's CURVE and bit length ==="
# ⚠️ THE REPORT: selecting 'Serve As' and ticking 'Use existing key' gave ... 'From
# the token: EC, size unknown'". The console reads THIS endpoint and filters to
# class=="private" — and CKA_EC_PARAMS / CKA_MODULUS_BITS live on the PUBLIC half of the
# keypair, which is why the private object came back with bits=0 and no curve at all.
#
# ⚠️ Mint a P-384 key, not P-256. 256 is the one size the console's old bit-count guess
# could still name, so a P-256 key would pass this section without the fix.
EC_KEY="pkcs11:token=$CFG_TOKEN;object=perm-ec;type=private?pin-value=1234"
chk "admin mints an EC P-384 key in the token" 201 \
    "$(hsmpost boss.cj --data-urlencode "ca_instance=$CA_ID" --data-urlencode "keyref=$EC_KEY" \
                       --data-urlencode 'cn=ec.perm.test' --data-urlencode 'key=ec' \
                       --data-urlencode 'curve=P-384')"
KEYS_EC=$(curl -s -b audit.cj "$U/api/pkcs11/keys")
# Pull out the PRIVATE object for that label specifically. Asserting against the whole
# body would pass on the PUBLIC half — which always had these facts, and whose absence
# from the console is the entire bug.
EC_PRIV=$(echo "$KEYS_EC" | tr '}' '\n' | grep 'perm-ec' | grep '"class":"private"')
chk "the private EC object is listed"     yes "$([ -n "$EC_PRIV" ] && echo yes || echo no)"
chk "  and it names the curve P-384"      yes "$(has "$EC_PRIV" '"curve":"P-384"')"
chk "  and reports 384 bits, not 0"       yes "$(has "$EC_PRIV" '"bits":384')"
# The control: RSA must not have regressed, and must not have acquired a curve.
RSA_PRIV=$(echo "$KEYS_EC" | tr '}' '\n' | grep 'perm-leaf' | grep '"class":"private"')
chk "the RSA private key still reports its size" yes "$(has "$RSA_PRIV" '"bits":2048')"
chk "  and carries no curve"                     yes "$(has "$RSA_PRIV" '"curve":""')"
# ⚠️ CKK_EC_EDWARDS is BOTH EdDSA curves, and every Ed448 key was listed as Ed25519: the key
# type was mapped without reading CKA_EC_PARAMS. And ML-DSA by name, not by number.
ED_KEY="pkcs11:token=$CFG_TOKEN;object=perm-ed448;type=private?pin-value=1234"
chk "admin mints an Ed448 key in the token" 201 \
    "$(hsmpost boss.cj --data-urlencode "ca_instance=$CA_ID" --data-urlencode "keyref=$ED_KEY" \
                       --data-urlencode 'cn=ed448.perm.test' --data-urlencode 'key=ed448')"
ML_KEY="pkcs11:token=$CFG_TOKEN;object=perm-mldsa;type=private?pin-value=1234"
chk "admin mints an ML-DSA-65 key in the token" 201 \
    "$(hsmpost boss.cj --data-urlencode "ca_instance=$CA_ID" --data-urlencode "keyref=$ML_KEY" \
                       --data-urlencode 'cn=mldsa.perm.test' --data-urlencode 'key=ML-DSA-65')"
KEYS_PQ=$(curl -s -b audit.cj "$U/api/pkcs11/keys")
ED_PRIV=$(echo "$KEYS_PQ" | tr '}' '\n' | grep 'perm-ed448' | grep '"class":"private"')
chk "the Ed448 key is listed as Ed448, not Ed25519" yes "$(has "$ED_PRIV" '"keyType":"Ed448"')"
ED25519_ROWS=$(echo "$KEYS_PQ" | tr '}' '\n' | grep 'perm-ed448' | grep -c '"keyType":"Ed25519"')
chk "  and neither half of it says Ed25519" 0 "$ED25519_ROWS"
ML_PRIV=$(echo "$KEYS_PQ" | tr '}' '\n' | grep 'perm-mldsa' | grep '"class":"private"')
chk "the ML-DSA key is listed as ML-DSA" yes "$(has "$ML_PRIV" '"keyType":"ML-DSA"')"

echo "=== 5. an auditor reads the token and cannot mint into it ==="
chk "auditor -> /api/certs/request-hsm 403" 403 \
    "$(hsmpost audit.cj $(mkargs "pkcs11:token=$CFG_TOKEN;object=perm-aud;type=private?pin-value=1234" aud.perm.test))"

echo "=== 6. the request form is told which profile will apply ==="
# ⚠️ FOR (3): display the resolved profile, do not ask. The form has no
# picker by design — the server resolves — so it has to be TOLD, and /api/my-profiles is
# the one endpoint a plain requester may read.
MP=$(curl -s -b reqr.cj "$U/api/my-profiles")
chk "my-profiles names the resolved profile"  yes "$(has "$MP" '"default"')"
chk "  and whether it permits omitting AIA"   yes "$(has "$MP" '"manageAia"')"
chk "  and CRL DP"                            yes "$(has "$MP" '"manageCrldp"')"
# The page is large, so match it in the shell rather than through a pipe grep -q closes
# early — the SIGPIPE that produces is harmless but prints noise into the suite output.
JS=$(curl -s -b boss.cj "$U/")
inpage(){ case "$JS" in *"$1"*) echo yes;; *) echo no;; esac; }
chk "the page displays the resolved profile"  yes "$(inpage 'hsm_profile')"
chk "  and asks the server which one applies" yes "$(inpage 'refreshHsmProfile')"
# It must remain a DISPLAY, not a picker — the server resolves the profile, and a control
# here would say otherwise.
#
# ⚠️ ASSERT THE SHAPE OF THE ROW, NOT ONE LITERAL ADJACENCY. This searched the whole page
# for 'id="hsm_profile"><select', which nothing plausible emits: a picker renders as
# <select id="hsm_profile" …>, with the id AFTER the tag name, and a select added beside the
# pill is not adjacent to the id at all. So the form could grow exactly the picker this
# forbids and the search would still come back empty.
#
# Scoped to renderHsmForm()'s own markup, with the JS comments stripped: "profile" appears
# all over the rest of the page (the Profiles page IS a picker, by definition), so a
# page-wide search cannot tell the two apart, and a comment saying the form has no picker
# must not satisfy a check that the form has no picker.
printf '%s' "$JS" > page.html
sed -n '/^function renderHsmForm()/,/^}/p' page.html | grep -v '^[[:space:]]*//' > hsmform.js
chk "  the HSM form's own markup was found"            yes \
    "$(grep -q 'id="hsm_profile"' hsmform.js && echo yes || echo no)"
chk "  the resolved profile is rendered as a <span>"   yes \
    "$(grep -q '<span id="hsm_profile"' hsmform.js && echo yes || echo no)"
chk "  and offers no profile control on the HSM form"  no \
    "$(grep -qE '<(select|input|textarea)[^>]*(id|name)="[^"]*[Pp]rof' hsmform.js && echo yes || echo no)"
# The page itself.
chk "the console has an HSM keys page"        yes "$(inpage 'renderHsmKeys')"
chk "  gated on hsm:read"                     yes "$(inpage "hsm: ['hsm:read']")"

# The Serves column vanished after a logout+login. The page loads its own copy of
# the transportKeys map when nothing else has, but the guard was `if (!HSM.transportKeys)`
# and HSM initialises that field to `{}` — TRUTHY, so the branch was unreachable and the
# fetch never happened. The column was populated only when the user had first opened the
# Inventory request panel (which calls hsmLoadSlots). Land straight on HSM keys and it was
# blank. Assert the guard is a real load-flag and that the dead test is gone: an
# unreachable branch is wrong code, not dormant code.
chk "  the slots fetch is gated on a load FLAG"      yes "$(inpage 'if (!HSM.loaded)')"
chk "  HSM carries that flag, starting false"        yes "$(inpage 'transportKeys: {}, loaded: false')"
chk "  the always-true {} guard is gone"             no  "$(inpage 'if (!HSM.transportKeys)')"

echo
echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] || echo "RESULT: FAIL"
exit 0
