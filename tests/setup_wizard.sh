#!/usr/bin/env bash
# Setup state + CA creation. GET /api/setup reports whether a signing CA exists yet;
# POST /api/ca-instances creates or imports one. Covers the state transition, the
# import path, and its refusals.
#
# The first-run WIZARD is gone. It prompted for the first CA on a CA-less
# instance, but a root alone is never the finished job — the operator still has to go to
# the CAs page and issue a signing CA under it, so the overlay saved no step while
# implying setup was complete. This suite kept the endpoint coverage and now also pins
# that the overlay does not come back: a hidden `#setup` div reappearing would be
# invisible to a markup grep looking only for what it contains.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18180
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

pg_setup setup_wizard
P=; P2=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
# An existing external CA (for the import path) and a plain leaf (a non-CA cert).
# Its key is token-born like every other CA key. The old comment here claimed
# importing somebody else's CA is "exactly the case where the key arrives as a file";
# that is no longer a case FastPKI can serve — an imported CA whose key is a path
# registers cleanly and then cannot sign, so the import endpoint refuses it outright.
# ca_in_token also supplies the explicit basicConstraints/keyUsage this needs: the
# stub openssl.cnf supplies neither, and import correctly rejects a non-CA cert.
ca_in_token ext.pem "/CN=Imported Root" 3650 extca
EXT_KEY_URI="$CA_KEY_URI"
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout leaf.key -subj "/CN=leaf" -out leaf.csr >/dev/null 2>&1
"$OSSL" x509 -req -in leaf.csr -CA ext.pem -CAkey "$EXT_KEY_URI" $CA_OSSL_ARGS -CAcreateserial -days 365 -out leaf.pem >/dev/null 2>&1
# A SECOND, distinct CA certificate for the anchor-only import below. Its key is a plain
# software key that is never registered — that is the whole point of a trust anchor: this
# node verifies chains up to it and can never sign with it. It must not be ext.pem, because
# `certs.serial` is the primary key and a CA's certificate IS its row, so re-importing the
# same bytes under a second id is a duplicate row rather than a second CA.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout anchor.key -out anchor.pem \
    -subj "/CN=Anchor Only Root" -days 3650 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1

echo "=== fresh deployment: no signing CA yet ==="
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/nonexistent.pem
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
hsm_conf_lines >> web.conf
# Phase 1 is a FRESH, CA-less deployment — do NOT register a CA here; the wizard
# below creates the first one. (Registering a CA would make /api/setup report initialized.)
"$WEB" --config web.conf >web.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P $P2 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"
chk "setup reports not initialized" yes "$(has "$(curl -s "$U/api/setup")" '"initialized":false')"

# The console still has to work on a CA-less instance — that is the state a fresh
# deployment starts in, and it is now the ONLY state, since nothing prompts for a CA any
# more. init() renders the console for the signed-in admin and stops.
curl -s "$U/" -o index.html
oneline="$(tr '\n' ' ' < index.html | tr -s ' ')"
chk "console still renders on a CA-less instance" yes \
    "$(printf '%s' "$oneline" | grep -qF 'applyRole(me);' && echo yes || echo no)"

echo "=== The first-run wizard is GONE, not hidden ==="
# Every one of these is a piece of the overlay. Asserting the container alone would pass
# against a half-removed form whose fields still ship.
chk "no setup overlay"          no "$(grep -q 'id="setup"' index.html && echo yes || echo no)"
chk "no setup form"             no "$(grep -q 'id="setupform"' index.html && echo yes || echo no)"
chk "no welcome copy"           no "$(grep -qi "let's set up your PKI" index.html && echo yes || echo no)"
chk "no wizard slot picker"     no "$(grep -q 'id="wiz_hsm_slot"' index.html && echo yes || echo no)"
chk "no wizard submit handler"  no "$(printf '%s' "$oneline" | grep -qF 'maybeWizard' && echo yes || echo no)"
# The endpoint stays: a deployment script can still ask whether this instance has a CA.
chk "the setup STATE endpoint still answers" yes "$(has "$(curl -s "$U/api/setup")" '"initialized":false')"

echo "=== the CAs page creates the first Root CA ==="
# The console mints the key in the token, so the create names WHERE it goes.
ROOTREF=$(hsm_new_key_uri wizroot "$EXT_KEY_URI")
chk "create root -> 201" 201 "$(curl -s -o /dev/null -w '%{http_code}' \
    --data-urlencode 'id=root' --data-urlencode 'name=Root' --data-urlencode 'key=ec' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$ROOTREF" \
    --data-urlencode 'keygen=true' "$U/api/ca-instances")"
chk "setup now initialized" yes "$(has "$(curl -s "$U/api/setup")" '"initialized":true')"
chk "setup counts the managed CA" yes "$(has "$(curl -s "$U/api/setup")" '"managedCas":1')"

echo "=== importing an existing CA ==="
C=$(curl -s -o /dev/null -w '%{http_code}' --data-urlencode "id=imp" --data-urlencode "name=Imported" \
       --data-urlencode "cert_pem@ext.pem" --data-urlencode "key=$EXT_KEY_URI" "$U/api/ca-instances")
chk "import existing CA -> 201" 201 "$C"
chk "imported CA is listed" yes "$(has "$(curl -s "$U/api/ca-instances")" '"id":"imp"')"
# A non-CA cert must be rejected; a missing key reference too.
chk "import a non-CA cert -> 400" 400 "$(curl -s -o /dev/null -w '%{http_code}' --data-urlencode 'id=bad' --data-urlencode 'cert_pem@leaf.pem' --data-urlencode "key=$EXT_KEY_URI" "$U/api/ca-instances")"
# ⚠️ THE KEY FLOOR ON IMPORT. This route checked basicConstraints CA:TRUE and nothing else
# — no algorithm, no size — so a CA weaker than the leaves it would go on to sign
# registered cleanly and became a trust anchor everything beneath it inherits. Every
# ISSUED certificate has always had to clear MIN_RSA_BITS (default 2048); the CA that
# signs them did not.
"$OSSL" req -x509 -newkey rsa:1024 -nodes -keyout weak.key -out weak.pem -days 3650 \
    -subj "/CN=Weak Root" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
chk "fixture: the weak CA really is 1024-bit" yes \
    "$("$OSSL" x509 -in weak.pem -noout -text 2>/dev/null | grep -q '1024 bit' && echo yes || echo no)"
chk "import a CA below MIN_RSA_BITS -> 400" 400 \
    "$(curl -s -o /dev/null -w '%{http_code}' --data-urlencode 'id=weakca' \
       --data-urlencode 'cert_pem@weak.pem' "$U/api/ca-instances")"
chk "  and it was not registered" no \
    "$(has "$(curl -s "$U/api/ca-instances")" '"id":"weakca"')"
# ⚠️ NO KEY IS A VALID IMPORT: it registers a verify-only trust anchor. This asserted 400
# for a long time, which is what blocked the documented multi-datacenter bootstrap from the
# console — `fastpki-ca add <id> --ca-pem <f>` has always accepted a keyless registration,
# and a peer node that cannot register the shared root cannot get a Postgres certificate
# either, because `fastpki-ca pg-tls` refuses to write unless the chain reaches a
# REGISTERED anchor.
chk "import without a key -> 201 (a verify-only trust anchor)" 201 \
    "$(curl -s -o /dev/null -w '%{http_code}' --data-urlencode 'id=nokey' \
       --data-urlencode 'cert_pem@anchor.pem' "$U/api/ca-instances")"
chk "  and the anchor is listed" yes \
    "$(has "$(curl -s "$U/api/ca-instances")" '"id":"nokey"')"
# And the same certificate twice is a clean refusal, not a 500. Reachable only now that the
# key gate no longer rejects this shape first.
chk "re-importing the SAME certificate -> 409, not 500" 409 \
    "$(curl -s -o /dev/null -w '%{http_code}' --data-urlencode 'id=dup' \
       --data-urlencode 'cert_pem@ext.pem' --data-urlencode "key=$EXT_KEY_URI" "$U/api/ca-instances")"
kill $P 2>/dev/null; wait $P 2>/dev/null

echo "=== a deployment with a pre-registered CA in the DB is already initialized ==="
pg_setup setup_wizard2
cat > web2.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ext.pem
SIGNING_CA_KEY=$EXT_KEY_URI
WEB_BIND=127.0.0.1
WEB_PORT=$((PORT+1))
LOG_LEVEL=err
EOF
hsm_conf_lines >> web2.conf
seed_ca_from_conf web2.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$WEB" --config web2.conf >web2.log 2>&1 & P2=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web2.conf" WEB_PORT "$P2" || true
U2="http://127.0.0.1:$((PORT+1))"
chk "global CA -> initialized" yes "$(has "$(curl -s "$U2/api/setup")" '"initialized":true')"
# The "global signing CA" concept is retired — /api/setup always reports
# hasGlobalCa:false; a pre-registered CA counts as a managed CA instead.
chk "pre-registered CA counted (managedCas:1)" yes "$(has "$(curl -s "$U2/api/setup")" '"managedCas":1')"
chk "no global-CA concept (hasGlobalCa:false)"  yes "$(has "$(curl -s "$U2/api/setup")" '"hasGlobalCa":false')"

echo
echo "=== SETUP WIZARD: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
