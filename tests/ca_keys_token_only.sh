#!/usr/bin/env bash
# A CA private key lives in a token. There is no software CA key — not as a
# default, not as a fallback, not as an option an operator can still reach.
#
# This asserts the REMOVED path is inert, not that the kept one works (the kept one is
# covered by web_ca_hsm / ca_create_hsm / web_ca_create). Every check below is a way
# somebody could still end up with a file-backed CA key, and each must fail closed:
#
#   1. fastpki-ca create --ca-key <path>          refused, nothing registered, no file
#   2. fastpki-ca add    --ca-key <path>          refused
#   3. POST /api/ca-instances keyloc=software     400, nothing registered
#   4. POST /api/ca-instances with no handle      400
#   5. import whose key reference is a path       400
#   6. a row ALREADY holding a path               cannot sign, and says why
#   7. a real token-backed create                 leaves no .key anywhere
#
# 6 is the one that matters most: it is the only check that proves load_signing_key
# genuinely lost its on-disk branch rather than the console merely stopping offering it.
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
unset OPENSSL_CONF
WEB="$ROOT/build/fastpki-web"; CA="$ROOT/build/fastpki-ca"
W="$(mktemp -d)"; cd "$W"; PORT=18099
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup ca_keys_token_only
trap 'pg_cleanup; kill ${P:-} 2>/dev/null' EXIT
ca_in_token ca.pem "/CN=Token Only CA" 3650 tokonly
source "$ROOT/tests/user_helpers.sh"
seed_web_user boss bosspw admin
# A perfectly good CA key AND its matching self-signed certificate, both in files.
# Nothing here is malformed and the pair genuinely matches — the point is that the key's
# SHAPE is refused, not its contents. The cert has to be the key's own: registering a
# file key against somebody else's certificate would fail on the mismatch, and section 6
# would then pass for a reason that has nothing to do with what it claims to test.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout ondisk.key -out ondisk.pem -days 3650 \
    -subj "/CN=Legacy File CA" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign" >/dev/null 2>&1
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=tokonly
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf

echo "=== 1. fastpki-ca create with a key PATH ==="
"$CA" --config bootstrap.conf create cli-soft --name "CLI Soft" --subject "/CN=CLI Soft" \
    --ca-key "$W/ondisk.key" --out-dir cas >/dev/null 2>cli.err
chk "create exits non-zero"            1 "$?"
chk "the error names the reason"     yes "$(grep -q 'pkcs11' cli.err && echo yes || echo no)"
chk "no CA registered"                 0 "$(pg_exec "SELECT count(*) FROM certs WHERE id='cli-soft' AND is_ca;")"
chk "no key file written"             no "$([ -f cas/cli-soft.key ] && echo yes || echo no)"

echo "=== 2. fastpki-ca add with a key PATH ==="
"$CA" --config bootstrap.conf add add-soft --name "Add Soft" --ca-pem "$W/ca.pem" \
    --ca-key "$W/ondisk.key" >/dev/null 2>add.err
chk "add exits non-zero"               1 "$?"
chk "no CA registered"                 0 "$(pg_exec "SELECT count(*) FROM certs WHERE id='add-soft' AND is_ca;")"

"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" WEB_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat srv.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null
code(){ curl -s -o /dev/null -w '%{http_code}' -b boss.cj "$U/api/ca-instances" "$@"; }
body(){ curl -s -b boss.cj "$U/api/ca-instances" "$@"; }

echo "=== 3. POST keyloc=software ==="
chk "keyloc=software -> 400"         400 "$(code --data-urlencode 'id=api-soft' \
    --data-urlencode 'subject=/CN=API Soft' --data-urlencode 'key=ec' \
    --data-urlencode 'keyloc=software')"
chk "the error names the reason"     yes "$(body --data-urlencode 'id=api-soft2' \
    --data-urlencode 'subject=/CN=API Soft' --data-urlencode 'key=ec' \
    --data-urlencode 'keyloc=software' | grep -q 'token' && echo yes || echo no)"
chk "no CA registered"                 0 "$(pg_exec "SELECT count(*) FROM certs WHERE id LIKE 'api-soft%' AND is_ca;")"

echo "=== 4. POST with no key handle at all ==="
chk "no keyref -> 400"               400 "$(code --data-urlencode 'id=api-nokey' \
    --data-urlencode 'subject=/CN=API NoKey' --data-urlencode 'key=ec')"
chk "no CA material directory appeared" no "$([ -d "$W/ca-inst" ] && echo yes || echo no)"

echo "=== 5. import whose key reference is a PATH ==="
chk "import with a path -> 400"      400 "$(code --data-urlencode 'id=imp-path' \
    --data-urlencode "cert_pem@ca.pem" --data-urlencode "key=$W/ondisk.key")"
chk "no CA registered"                 0 "$(pg_exec "SELECT count(*) FROM certs WHERE id='imp-path' AND is_ca;")"

echo "=== 6. a row that ALREADY names a path cannot sign ==="
# Written straight into the table, bypassing every check above — the only way to get
# this state now, and exactly the state an older database would be in. Issuance must
# refuse it. If load_signing_key still had its on-disk branch this CA would happily
# issue, which is the regression this whole guard exists to catch.
# A CA IS a `certs` row, so that older state is a row whose private_key is a
# FILE PATH. Written straight into the table on purpose — no product path will create
# one, which is exactly what makes it the right shape to prove the door is shut.
# (An earlier version of this fixture used parent_id='' against the old self-FK; the
# INSERT was rejected, the row never existed, and section 6 "passed" by asking about a
# CA that was not there. An assertion that holds for the wrong reason is worse than none
# — hence the existence check on the line below.)
LEGACY_DER=$("$OSSL" x509 -in ondisk.pem -outform DER | xxd -p | tr -d '\n')
LEGACY_SER=$("$OSSL" x509 -in ondisk.pem -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,cn,cert,
                           id,name,ca_enabled,private_key,is_ca,ca_instance_id)
         VALUES('$LEGACY_SER',0,$(date +%s),$(( $(date +%s) + 315360000 )),
                'CN=Legacy File CA','Legacy File CA','\\x$LEGACY_DER'::bytea,
                'legacy-file','Legacy',true,'$W/ondisk.key',true,'legacy-file');"
chk "the legacy row really exists"       1 "$(pg_exec "SELECT count(*) FROM certs WHERE id='legacy-file' AND is_ca;")"
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout leaf.key -subj "/CN=leaf.internal" -out leaf.csr >/dev/null 2>&1
ISSB=$(curl -s -w '\n%{http_code}' -b boss.cj -X POST --data-binary @leaf.csr \
    "$U/api/certs/request?ca_instance=legacy-file")
ISS=$(echo "$ISSB" | tail -1)
# Measured against the previous binary this CA issued a REAL certificate
# (Issuer: Legacy File CA), so this is the check that would catch the branch coming back.
echo "  (issuance said: $(echo "$ISSB" | sed '$d' | cut -c1-90))"
chk "issuance under a file-key CA fails" no "$([ "$ISS" = 201 ] && echo yes || echo no)"
# NOT is_ca: the CA's own certificate is a row carrying its ca_instance_id
# too, so counting them all would count the CA itself as something it issued.
chk "and nothing was issued"             0 "$(pg_exec "SELECT count(*) FROM certs WHERE ca_instance_id='legacy-file' AND NOT is_ca;")"

echo "=== 7. a real token-backed create leaves nothing on disk ==="
GOOD=$(hsm_new_key_uri tokonly-new)
chk "token-backed create -> 201"     201 "$(code --data-urlencode 'id=tok-good' \
    --data-urlencode 'subject=/CN=Tok Good' --data-urlencode 'key=ec' \
    --data-urlencode 'curve=P-256' --data-urlencode 'keyloc=pkcs11' \
    --data-urlencode 'keygen=true' --data-urlencode "keyref=$GOOD")"
# CA_INSTANCE_DIR is gone. The console used to write <id>.crt there and nothing
# ever read it — the certificate is a `certs` row — so these now assert
# the API answer and the ABSENCE of any directory. Inverting an assertion that encoded
# the removed behaviour is the honest update; leaving it would pin what the ticket
# removed.
chk "its cert is served by the API" yes \
  "$(curl -s -b boss.cj "$U/api/ca-instances/tok-good/cert-pem" | grep -q "BEGIN CERTIFICATE" && echo yes || echo no)"
chk "the registered key is a handle" yes "$(pg_exec "SELECT coalesce(private_key,'') FROM certs WHERE id='tok-good' AND is_ca;" | grep -q '^pkcs11:' && echo yes || echo no)"
# The sweeping one, and it sweeps wider now: not "no tok-good.key", and not even
# "no .key in the instance directory" — no CA material file ANYWHERE under /var/pki's
# stand-in for this run. The console writes nothing to disk for a CA at all now.
#
# ⚠️ IT IS NOT NARROWED BY `-path '*ca-inst*'` ANY MORE, and that filter is why this check
# could not fail: it is the old --out-dir default, a directory no product path creates —
# section 4 above asserts $W/ca-inst is absent — so the find matched nothing by
# construction and the count was 0 however the CA had been written. The three files the
# FIXTURE itself makes are excluded BY NAME instead (ondisk.key is the path key section 1
# offers, leaf.key the client key section 6 enrols with, scratch.key the throwaway keypair
# ca_in_token leaves beside the certificate), so a CA key or certificate written anywhere
# under $W under any other name — tok-good.key, cas/tok-good.crt — now counts.
STRAY=$(find "$W" \( -name '*.key' -o -name '*.crt' \) \
        ! -name ondisk.key ! -name leaf.key ! -name scratch.key 2>/dev/null)
chk "no CA cert or key file anywhere" 0 "$(printf '%s' "$STRAY" | grep -c . | tr -d ' ')"
# Name them when there are any: a bare count tells an operator nothing about what leaked.
[ -n "$STRAY" ] && echo "  (on disk: $(printf '%s' "$STRAY" | tr '\n' ' '))"

echo
echo "=== CA KEYS TOKEN ONLY: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
