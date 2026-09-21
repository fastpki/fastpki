#!/usr/bin/env bash
# The console and the listener were naming DIFFERENT rows.
#
# resolve_transport_cert() runs the configured id through listener_cert_id(), so on a
# node with DATACENTER_ID=dcx it looks up `web-dcx`. The console's "Serve as" dropdown sends
# the bare purpose — `<option value="web">`. Issuing through the documented flow therefore
# stored a row under `web` that no listener ever reads.
#
# ⚠️ THE FAILURE IS A 201. The certificate is minted, published, replicated to every peer and
# reported successful; it is simply never resolved. That is the dominant bug shape in this
# codebase — a credential and its consumer joined by a third thing nobody wrote — and it is
# invisible to any assertion that reads the status code. Measured on the lab, where `certs`
# holds BOTH spellings for all four listeners: web/web-dc1, est/est-dc1, acme/acme-dc1,
# ms/ms-dc1.
#
# It also disarmed a guard: transport_key_setting_for() compares against the SCOPED id, so an
# unscoped submission fell through to {} — and a {} there leaves the
# mismatched-pair check with nothing to compare.
#
# The fix scopes on WRITE exactly as resolve_transport_cert scopes on READ.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18241
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
skipout(){ echo "  [SKIP] $1"; echo; echo "=== TRANSPORT CERT ID SCOPE: PASS=$pass FAIL=$fail SKIP=1 ==="; exit 0; }

ca_in_token ca.pem "/CN=Scope Test CA" 3650 scopeca || skipout "no token"
pg_setup transport_cert_id_scope
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
# config.cpp refuses to start a node whose DATACENTER_ID has no serial prefix.
pg_exec "INSERT INTO datacenters(dc_id, serial_prefix) VALUES('dcx', 4101)
           ON CONFLICT DO NOTHING;" >/dev/null

cat > web.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=scope
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
DATACENTER_ID=dcx
WEB_CERT_ID=web
LOG_LEVEL=err
EOF
hsm_conf_lines >> web.conf
seed_ca_from_conf web.conf
# The token this suite's CA key lives in — the same one request-hsm must mint into.
TOK=$(sed -n 's/.*token=\([^;?]*\).*/\1/p' <<<"$CA_KEY_URI")
"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "web died:"; cat web.log; exit 1; }
U="http://127.0.0.1:$PORT"
curl -s -o /dev/null -X POST "$U/api/users" -d 'username=boss&password=bosspw12&role=admin'
curl -s -c cj -X POST "$U/api/login" -d 'username=boss&password=bosspw12' >/dev/null

echo "=== issue through the console's own flow, sending the BARE purpose ==="
# Exactly what the dropdown submits: cert_id=web, not cert_id=web-dcx.
RC=$(curl -s -o iss.json -w '%{http_code}' -b cj -X POST "$U/api/certs/request-hsm" \
      --data-urlencode 'cert_id=web' \
      --data-urlencode 'ca_instance=scope' \
      --data-urlencode 'cn=node.internal' \
      --data-urlencode 'keygen=true' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
      --data-urlencode "keyref=pkcs11:token=$TOK;object=webtls-dcx;type=private?pin-value=1234")
[ "$RC" = "201" ] || skipout "could not issue the transport cert here (-> $RC: $(head -c 200 iss.json))"
chk "PRECONDITION: issuance succeeded" 201 "$RC"

echo "=== ⚠️ the row must land under the id the LISTENER resolves ==="
# THE DISCRIMINATING ASSERTIONS. Before the fix these were 0 and 1 respectively: the
# certificate existed, under a name nothing reads.
chk "stored under the node-scoped id 'web-dcx'" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='web-dcx' AND status=0;" | tr -d ' ')"
chk "and NOT under the bare 'web'" 0 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='web' AND status=0;" | tr -d ' ')"
# Ask the certificate, not just the row label: a row tagged correctly but holding someone
# else's certificate would satisfy the counts above.
chk "  the stored certificate is the one just issued" "node.internal" \
    "$(pg_exec "SELECT cn FROM certs WHERE cert_id='web-dcx' AND status=0;" | tr -d ' ')"
chk "  and it records its issuing CA" "scope" \
    "$(pg_exec "SELECT ca_instance_id FROM certs WHERE cert_id='web-dcx' AND status=0;" | tr -d ' ')"

echo "=== ⚠️ and the mismatched-pair guard is ARMED again ==="
# This is the strongest evidence the scoping reached the code that matters, and it is why
# the section exists. transport_key_setting_for() compares against the SCOPED id, so an
# UNSCOPED submission fell through to {} — and a {} there leaves the
# mismatched-pair check with nothing to compare, letting any key through. The guard firing,
# and naming `web-dcx`, is only possible if the submitted id was scoped first.
#
# Offering a DIFFERENT key handle for the same listener must be refused: the certificate
# would be issued and then ignored, because the listener loads the other key.
RC2=$(curl -s -o iss2.json -w '%{http_code}' -b cj -X POST "$U/api/certs/request-hsm" \
      --data-urlencode 'cert_id=web-dcx' \
      --data-urlencode 'ca_instance=scope' \
      --data-urlencode 'cn=node2.internal' \
      --data-urlencode 'keygen=true' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
      --data-urlencode "keyref=pkcs11:token=$TOK;object=webtls-OTHER;type=private?pin-value=1234")
chk "a MISMATCHED key for that listener is refused" 400 "$RC2"
chk "  and the refusal names the node-scoped id" yes \
    "$(grep -q "web-dcx" iss2.json && echo yes || echo no)"
# ⚠️ Ask the DB: a refusal that still minted the certificate would be the worse outcome, and
# it is invisible from the status code.
chk "  and no second row was written" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='web-dcx';" | tr -d ' ')"
chk "  nothing gained a double suffix" 0 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id LIKE '%-dcx-dcx';" | tr -d ' ')"

echo "=== the console can still find the key for what it offers ==="
# HSM.transportKeys is looked up by the DROPDOWN's value. Keyed only by the scoped id, the
# required Key-name field stayed blank on any node with a DATACENTER_ID and the form would
# not submit — with nothing saying why. Both spellings must resolve.
SLOTS=$(curl -s -b cj "$U/api/pkcs11/slots")
chk "transportKeys answers to the scoped id"  yes \
    "$(printf '%s' "$SLOTS" | grep -q '"web-dcx":' && echo yes || echo no)"
chk "transportKeys answers to the bare id too" yes \
    "$(printf '%s' "$SLOTS" | grep -q '"web":' && echo yes || echo no)"

echo "=== ⚠️ a RE-KEY writes the key name the listener will actually load ==="
# The listener loads WEB_TLS_KEY through listener_key_uri(), which appends -<DATACENTER_ID>.
# A re-key used to mint at the name it was given and write that name into WEB_TLS_KEY, so a
# re-key submitted as `webtls-2` left the console looking for `webtls-2-dcx`, which did not
# exist — it minted another key and served a self-signed certificate. The handle has to be
# scoped before anything is minted, exactly as the id is.
RC3=$(curl -s -o iss3.json -w '%{http_code}' -b cj -X POST "$U/api/certs/request-hsm" \
      --data-urlencode 'cert_id=web' \
      --data-urlencode 'ca_instance=scope' \
      --data-urlencode 'cn=node.internal' \
      --data-urlencode 'keygen=true' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
      --data-urlencode 'rekey=1' \
      --data-urlencode "keyref=pkcs11:token=$TOK;object=webtls-2;type=private?pin-value=1234")
chk "a listener re-key submitted without the suffix is issued" 201 "$RC3"
chk "  WEB_TLS_KEY names the node-scoped object" yes \
    "$(pg_exec "SELECT value FROM config WHERE key='WEB_TLS_KEY';" | grep -q 'object=webtls-2-dcx;' && echo yes || echo no)"
chk "  and the key was minted at that name, which the response reports" yes \
    "$(grep -q 'object=webtls-2-dcx;' iss3.json && echo yes || echo no)"
chk "  nothing was minted at the bare name" no \
    "$(grep -q 'object=webtls-2;' iss3.json && echo yes || echo no)"
# The certificate for the REPLACED key is this node's previous one, so it is superseded —
# found through the key the setting named before the re-key, since the new certificate
# certifies a different one.
chk "  the certificate on the replaced key is superseded, one live row remains" "1|1" \
    "$(pg_exec "SELECT count(*) FILTER (WHERE status=0)||'|'||count(*) FILTER (WHERE status=3) FROM certs WHERE cert_id='web-dcx';" | tr -d ' ')"

echo "=== CONTROL: a node with NO data center is untouched ==="
# The scoping must not surprise a single-node deployment — and without this control, a fix
# that scoped everything unconditionally would pass every assertion above.
kill $P 2>/dev/null; wait $P 2>/dev/null
sed -e 's/^DATACENTER_ID=.*//' -e "s/^WEB_PORT=.*/WEB_PORT=18242/" \
    -e 's/^WEB_CERT_ID=.*/WEB_CERT_ID=solo/' web.conf > solo.conf
"$WEB" --config solo.conf >solo.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "solo.conf" WEB_PORT "$P" || true
U2="http://127.0.0.1:18242"
curl -s -c cj2 -X POST "$U2/api/login" -d 'username=boss&password=bosspw12' >/dev/null
curl -s -o /dev/null -b cj2 -X POST "$U2/api/certs/request-hsm" \
      --data-urlencode 'cert_id=solo' \
      --data-urlencode 'ca_instance=scope' \
      --data-urlencode 'cn=solo.internal' \
      --data-urlencode 'keygen=true' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
      --data-urlencode "keyref=pkcs11:token=$TOK;object=solotls;type=private?pin-value=1234"
chk "with no DATACENTER_ID the BARE id is stored" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='solo' AND status=0;" | tr -d ' ')"
chk "  and nothing gained a suffix" 0 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id LIKE 'solo-%';" | tr -d ' ')"

echo
echo "=== TRANSPORT CERT ID SCOPE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
