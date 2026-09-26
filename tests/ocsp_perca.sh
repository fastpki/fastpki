#!/usr/bin/env bash
# Virtualized per-CA OCSP + the shared per-CA responder.
# One fastpki-ocsp answers for multiple CA instances under /ocsp/{ca_instance_id}
# (trailing segment), each response signed by THAT instance's CA — so a client
# verifies it with its own CA.
#
# The SHARED /ocsp endpoint now answers for every CA of every CA too — it picks
# the signing CA from the REQUESTED cert's issuer — a single fastpki-ocsp signing every
# response with the OCSP signing cert selected from the host header and the requested
# certificate. That is why every issued cert's AIA can point at the same /ocsp path.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
# Only adopt the system openssl.cnf where it really is one. On macOS this path is a
# stub that defines no providers, and exporting it breaks every pkcs11 load — the
# CA key then cannot be minted and the suite SKIPs for a reason that looks nothing
# like "wrong openssl.cnf". Tests must not assume a Linux layout (§3d).
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
CA="$ROOT/build/fastpki-ca"
W="$(mktemp -d)"; cd "$W"; PORT=18103
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Global OCSP CA" 3650
GLOBAL_KEY_URI="$CA_KEY_URI"
# The second CA's key is token-born too — a CA private key is never a file.
ca_in_token depta.pem "/CN=Dept A CA" 3650 depta
DEPTA_KEY_URI="$CA_KEY_URI"
# A leaf under each CA, with controlled serials so we can seed the DB rows.
mkleaf(){ # <cakey> <cacert> <serial-dec> <cn> <out>
    "$OSSL" req -newkey rsa:2048 -nodes -keyout "$5.key" -subj "/CN=$4" -out "$5.csr" >/dev/null 2>&1
    # $1 is always a pkcs11: URI now — both CAs are token-born — so the
    # provider args are always required.
    "$OSSL" x509 -req -in "$5.csr" -CA "$2" -CAkey "$1" ${CA_OSSL_ARGS:-} -set_serial "$3" -days 365 -out "$5.pem" >/dev/null 2>&1
}
mkleaf "$DEPTA_KEY_URI" depta.pem 4660  dev.dept-a.internal deptleaf   # serial 0x1234 -> '1234'
mkleaf "$GLOBAL_KEY_URI" ca.pem 22136 dev.default.internal defleaf    # serial 0x5678 -> '5678'

pg_setup ocsp_perca
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$GLOBAL_KEY_URI
SIGNING_CA_ID=ca-global
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
CRL_PATH=/crl
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$CA" --config bootstrap.conf add dept-a --name "Dept A" --ca-pem "$W/depta.pem" --ca-key "$DEPTA_KEY_URI" >/dev/null
# Slice B: the CA key never signs a status response, so BOTH CAs this responder
# answers for need their own responder certificate — same key, one certificate each,
# which is exactly the per-CA binding RFC 6960 §4.2.2.2 requires.
RKEY=$(ocsp_responder_key "$W/ca.pem"    "$GLOBAL_KEY_URI" ca-global "$W")
        ocsp_responder_key "$W/depta.pem" "$DEPTA_KEY_URI"  dept-a    "$W" >/dev/null
printf 'OCSP_RESPONDER_KEY=%s\n' "$RKEY" >> bootstrap.conf
pg_exec "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('1234',0,'dev.dept-a.internal','dept-a');"
pg_exec "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('5678',0,'dev.default.internal','ca-global');"

"$ROOT/build/fastpki-ocsp" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-ocsp died:"; cat srv.log; exit 1; fi
B="http://127.0.0.1:$PORT"

q(){ "$OSSL" ocsp -issuer "$2" -cert "$3" -url "$1" -CAfile "$4" -resp_text -no_nonce 2>&1; }
stat(){ echo "$1" | grep -oE "Cert Status: (good|revoked|unknown)" | sed 's/Cert Status: //' | head -1; }
ver(){ echo "$1" | grep -q "Response verify OK" && echo ok || echo no; }

echo "=== per-CA OCSP, response signed by the instance CA ==="
O=$(q "$B/ocsp/dept-a" depta.pem deptleaf.pem depta.pem)
chk "dept-a cert status good"            good "$(stat "$O")"
chk "dept-a response verifies under Dept A CA" ok "$(ver "$O")"

O=$(q "$B/ocsp" ca.pem defleaf.pem ca.pem)
chk "default cert status good"           good "$(stat "$O")"
chk "default response verifies under global CA" ok "$(ver "$O")"

# The shared /ocsp picks its signer from the requested cert, so a dept-a cert
# queried there is answered by dept-a's CA and verifies under it — one endpoint serves
# every CA of the instance. (This endpoint could once only sign with the global CA.)
echo "=== the shared /ocsp answers a per-CA cert with THAT secondary CA's signature ==="
O=$(q "$B/ocsp" depta.pem deptleaf.pem depta.pem)
chk "dept-a cert at the shared /ocsp reports its status" good "$(stat "$O")"
chk "dept-a cert at the shared /ocsp verifies under Dept A CA" ok "$(ver "$O")"

echo "=== a superseded certificate is not revoked, so OCSP answers good ==="
# Renewal marks the certificate it replaces as superseded (status 3): FastPKI stops using it,
# but nobody revoked it and the CRL does not list it. The responder answered "unknown", which
# in RFC 6960 §2.2 means it does not know the certificate at all — about one this CA issued,
# and while the CRL said the opposite.
pg_exec "UPDATE certs SET status=3 WHERE serial='1234';"
O=$(q "$B/ocsp/dept-a" depta.pem deptleaf.pem depta.pem)
chk "superseded dept-a cert status good" good "$(stat "$O")"
chk "  and the response verifies under Dept A CA" ok "$(ver "$O")"

echo "=== revocation reflected per instance ==="
REVDATE=$(date +%s)
pg_exec "UPDATE certs SET status=-1, \"revocationReason\"=1, \"revocationDate\"=$REVDATE WHERE serial='1234';"
O=$(q "$B/ocsp/dept-a" depta.pem deptleaf.pem depta.pem)
chk "revoked dept-a cert status revoked" revoked "$(stat "$O")"

echo "=== OCSP over GET answers what POST answers, whatever the base64 contains ==="
# ⚠️ WHY THIS SECTION EXISTS. A GET carries the request as URL-encoded base64 (RFC 6960 A.1),
# so a '/' in it arrives as %2F, and httplib decodes the path before routing. The request then
# looked like /ocsp/{id}/{rest}, with a slice of the base64 taken for a CA id, and got 404. The
# issuer-hash half of a CertID is fixed per CA, so on the lab every GET to two CAs failed
# (110 of 110) while POST worked — and no suite sent a GET at all. Each request below is made
# with a fresh nonce until its base64 carries a '/', so the case that failed is the one tested.
b64req(){ "$OSSL" base64 -A -in "$1"; }
escaped(){ b64req "$1" | sed 's/%/%25/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g'; }
mkslashreq(){ # <issuer> <cert> <out>: a request whose base64 contains '/'
    for _i in $(seq 1 80); do
        "$OSSL" ocsp -issuer "$1" -cert "$2" -nonce -reqout "$3" >/dev/null 2>&1
        b64req "$3" | grep -q / && return 0
    done; return 1; }
gstat(){ # <url> <req.der> <issuer> -> "<http code> <status> <verify>"
    _c=$(curl -s -o g.der -w '%{http_code}' "$1")
    _t=$("$OSSL" ocsp -respin g.der -reqin "$2" -issuer "$3" -CAfile "$3" -resp_text 2>&1)
    echo "$_c $(stat "$_t") $(ver "$_t")"; }
pstat(){ # <url> <req.der> <issuer>
    curl -s -o p.der -H "Content-Type: application/ocsp-request" --data-binary @"$2" "$1"
    _t=$("$OSSL" ocsp -respin p.der -reqin "$2" -issuer "$3" -CAfile "$3" -resp_text 2>&1)
    echo "200 $(stat "$_t") $(ver "$_t")"; }
mkslashreq ca.pem defleaf.pem qd.der; mkslashreq depta.pem deptleaf.pem qa.der
chk "PRECONDITION: both requests' base64 contains '/'" yes \
    "$(b64req qd.der | grep -q / && b64req qa.der | grep -q / && echo yes || echo no)"
chk "shared /ocsp: GET, escaped, answers as POST does (good)" "$(pstat "$B/ocsp" qd.der ca.pem)" \
    "$(gstat "$B/ocsp/$(escaped qd.der)" qd.der ca.pem)"
chk "  and it is a verified good"                     "200 good ok" "$(gstat "$B/ocsp/$(escaped qd.der)" qd.der ca.pem)"
chk "per-CA /ocsp/{id}: GET, escaped (revoked)"       "200 revoked ok" "$(gstat "$B/ocsp/dept-a/$(escaped qa.der)" qa.der depta.pem)"
chk "shared /ocsp: GET for the other CA's cert"       "200 revoked ok" "$(gstat "$B/ocsp/$(escaped qa.der)" qa.der depta.pem)"
chk "a client that does not escape '/' is answered"   "200 good ok" "$(gstat "$B/ocsp/$(b64req qd.der)" qd.der ca.pem)"
chk "  also on the per-CA form"                       "200 revoked ok" "$(gstat "$B/ocsp/dept-a/$(b64req qa.der)" qa.der depta.pem)"
chk "base64 that decodes to nothing -> 400"           400 "$(curl -s -o /dev/null -w '%{http_code}' "$B/ocsp/%25zz%21%21")"
chk "  and the responder still answers after it"      "200 good ok" "$(gstat "$B/ocsp/$(escaped qd.der)" qd.der ca.pem)"

echo "=== per-CA CRL (scoped revoked list, signed by the instance CA) ==="
# dept-a cert 1234 is revoked (above); also revoke the default cert 5678.
REVDATE2=$(date +%s)
pg_exec "UPDATE certs SET status=-1, \"revocationReason\"=1, \"revocationDate\"=$REVDATE2 WHERE serial='5678';"
crl_text(){ curl -s "$1" -o c.der; "$OSSL" crl -inform DER -in c.der -text -noout 2>/dev/null; }
crl_verify(){ curl -s "$1" -o c.der; "$OSSL" crl -inform DER -in c.der -CAfile "$2" -noout 2>&1; }
has_serial(){ echo "$1" | grep -qE "Serial Number: *$2( |$)" && echo yes || echo no; }

DA=$(crl_text "$B/crl/dept-a")
chk "dept-a CRL verifies under the Dept A CA" "verify OK" "$(crl_verify "$B/crl/dept-a" depta.pem)"
chk "dept-a CRL lists the dept-a revoked serial (1234)" yes "$(has_serial "$DA" 1234)"
chk "dept-a CRL does NOT list the default serial (5678)" no  "$(has_serial "$DA" 5678)"
# No default CA — the id-less /crl alias 404s; CRLs are per-CA at /crl/{ca_id}.
chk "base (id-less) /crl -> 404" 404 "$(curl -s -o /dev/null -w '%{http_code}' "$B/crl")"

echo "=== unknown / disabled instances ==="
code(){ curl -s -o /dev/null -w '%{http_code}' -H "Content-Type: application/ocsp-request" --data-binary @"$W/req.der" "$1"; }
"$OSSL" ocsp -issuer depta.pem -cert deptleaf.pem -reqout req.der -no_nonce >/dev/null 2>&1
chk "unknown instance -> 404" 404 "$(code "$B/ocsp/nope")"
"$CA" --config bootstrap.conf disable dept-a >/dev/null
# ⚠️ THIS USED TO ASSERT 503 AND THAT WAS THE BUG.
# As reported: `curl -k http://localhost:8080/root-ca.crl` -> "CA instance disabled".
# Disabling a CA stops ISSUANCE; it does not withdraw the revocation information already
# published. An offline root is the recommended posture, so the refusal fired exactly when
# the CA was most locked down, and for a REVOKED certificate it turns "revoked" into
# "cannot determine" — the one answer revocation exists to prevent.
# Refusing to issue is enforced in CaMaterialCache, which this route does not touch.
chk "disabled instance still ANSWERS" 200 "$(code "$B/ocsp/dept-a")"
chk "  and still serves its CRL"      200 \
    "$(curl -s -o /dev/null -w '%{http_code}' "$B/crl/dept-a")"
"$CA" --config bootstrap.conf enable dept-a >/dev/null

echo "=== A CA whose key is in ANOTHER node's token answers 503, not 500 ==="
# On the mesh every DC holds a row for every CA, and only the node whose token holds the
# key can sign. Asking dc3 for dc2's CRL is routine, not a server fault — but the pkcs11
# URI throws inside the Responder constructor, pick_responder caught it, and the client got
# 500 "CA material unavailable". 500 says "I broke", which sends whoever is debugging at
# the server rather than at their URL. Measured on the lab while live-smoking the chain:
#
#   test-03  issuing.crl      500   <- key in another node's token
#   test-03  labroot.crl      503   <- offline root, no key at all
#
# Two names for one fact ("this node cannot produce that CRL"), and the useful answer is
# the one that names the CA.
#
# Simulated the way it really happens: point the row at a pkcs11 URI for an object that
# does not exist in THIS token. That is exactly what a peer's key looks like from here.
# ⚠️ The column is `private_key`. It is NOT `signing_ca_key` — that name belongs to the
# CaInstance struct and the backup JSON; the CA attributes were merged onto `certs` and the
# column there has always been `private_key`. My first version updated the struct's name,
# matched nothing, and the CRL came back 200 from a perfectly good key.
pg_exec "UPDATE certs SET private_key='pkcs11:token=fastpki;object=not-in-this-token;type=private'
         WHERE id='dept-a' AND is_ca;" >/dev/null
# Assert the setup TOOK. An UPDATE that matches no row is silent, and every assertion
# below then measures the unmodified product and reports it broken (or, worse, healthy).
chk "  the CA row now names an unreachable key" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='dept-a' AND is_ca AND private_key LIKE '%not-in-this-token%';" | tr -d ' ')"
# ⚠️ RESTART THE LISTENER, or this proves nothing. pick_responder caches one Responder per
# CA id for the process lifetime, so after the assertions above dept-a already has a live
# one built from the WORKING key — the row change never reaches the constructor and the
# CRL is served 200 from the cache. The first version of this block asserted 503 against
# exactly that and reported the product broken when it was the test.
#
# A restart is also the honest reproduction: on the lab the 500 happened on the FIRST
# request a fresh process saw for a CA whose key lives elsewhere.
kill $P 2>/dev/null; wait $P 2>/dev/null
# LOG_LEVEL=info for this half. The fallback below is announced at info — which every
# shipped config sets, though the compiled default is err — and the rest of this suite runs
# at err on purpose. Asserting a log line the daemon was configured not to print would be a
# test that can only fail.
sed 's/^LOG_LEVEL=.*/LOG_LEVEL=info/' bootstrap.conf > remote.conf
"$ROOT/build/fastpki-ocsp" --config remote.conf >srv2.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-ocsp died on restart:"; tail -5 srv2.log; }
# ⚠️ TWO DIFFERENT STATES, AND THE ANSWER IS NOT THE SAME IN BOTH.
#
# This node served dept-a's CRL above, which PUBLISHED it to the `crls` table. So when the
# key handle goes unreachable there are now signed bytes in hand, and serving them is
# right: a CA that cannot sign should still publish the last CRL it did sign. Answering 503
# while holding a valid CRL fails revocation closed for no reason — the opposite of what a
# relying party needs.
#
# But a 200 here is indistinguishable from a healthy CA, and this endpoint used to be the
# only place a mistyped pkcs11: handle showed up. So the LOG has to say it, and that is
# asserted rather than assumed.
CODE=$(curl -s -o crl_remote.out -w '%{http_code}' "$B/crl/dept-a")
chk "a stored CRL is served when the key is unreachable" 200 "$CODE"
chk "  and the bytes are a CRL, not an error page" yes \
    "$("$OSSL" crl -in crl_remote.out -inform DER -noout >/dev/null 2>&1 && echo yes || echo no)"
chk "  and the log says the key is not usable here" yes \
    "$(grep -q "signing key is not usable here" srv2.log && echo yes || echo no)"
chk "  naming the CA"                 yes \
    "$(grep -q "CRL for CA 'dept-a'" srv2.log && echo yes || echo no)"
chk "the {ca_id}.crl route agrees"    200 \
    "$(curl -s -o /dev/null -w '%{http_code}' "$B/dept-a.crl")"

# With NOTHING stored, the refusal is still the right answer and must still be actionable.
pg_exec "DELETE FROM crls WHERE ca_id='dept-a';" >/dev/null
chk "  PRECONDITION: nothing is stored for dept-a now" 0 \
    "$(pg_exec "SELECT count(*) FROM crls WHERE ca_id='dept-a';" | tr -d ' ')"
CODE=$(curl -s -o crl_none.out -w '%{http_code}' "$B/crl/dept-a")
chk "with no stored CRL: 503, not 500" 503 "$CODE"
[ "$CODE" = 503 ] || echo "  body: $(head -c 200 crl_none.out)"
# ⚠️ Assert the BODY names the CA. A bare 503 is also what a disabled CA used to return
# and what an unrelated outage returns; without the name the operator learns
# nothing they did not already know from the URL they typed.
chk "  and the body names the CA"     yes \
    "$(grep -q "dept-a" crl_none.out && echo yes || echo no)"
chk "  and says the key is elsewhere" yes \
    "$(grep -qi "not available on this node" crl_none.out && echo yes || echo no)"
# The OTHER CRL route, because patching one of two is how this got half-fixed the first time.
chk "the {ca_id}.crl route agrees"    503 \
    "$(curl -s -o /dev/null -w '%{http_code}' "$B/dept-a.crl")"
# ⚠️ And the node must still answer OCSP for that CA: responses are signed by the
# DELEGATED responder credential, never by the CA key, so a remote CA key does not
# stop status answers. Refusing them would turn "revoked" into "cannot determine" — the
# same mistake already fixed for disabled CAs.
chk "  OCSP for that CA still answers" 200 "$(code "$B/ocsp/dept-a")"

echo "=== (second half): an unloadable RESPONDER key must not take out the CRL ==="
# Found live-smoking the fix on the lab, which is the only reason it was found at
# all: the fix above was only half of it.
#
#   test-03  /issuing-dc3.crl   200   <- this node's own CA
#   test-03  /issuing.crl       500   <- SAME process, same code path
#
# Both CAs' rows were fine. The difference was OCSP_RESPONDER_KEY: loading it THREW out
# of the Responder constructor, pick_responder caught the throw, and every route that
# responder serves became 500 "CA material unavailable" — including /{ca_id}.crl, which
# is signed by the CA key and never touches the responder key at all.
#
# So: two independent credentials, and one being absent must not disable the other. The
# CRL is a CA-key artifact; the status response is a responder-key artifact.
#
# Restore a WORKING CA key first, or this block measures the previous one's damage
# instead of its own.
pg_exec "UPDATE certs SET private_key='$DEPTA_KEY_URI' WHERE id='dept-a' AND is_ca;" >/dev/null
chk "  the CA key is reachable again" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='dept-a' AND is_ca AND private_key NOT LIKE '%not-in-this-token%';" | tr -d ' ')"
# Now break ONLY the responder key, the way a mesh peer's looks from here.
sed -i.bak 's|^OCSP_RESPONDER_KEY=.*|OCSP_RESPONDER_KEY=pkcs11:token=fastpki;object=no-such-responder;type=private|' bootstrap.conf
chk "  the config now names an unreachable responder key" 1 \
    "$(grep -c 'object=no-such-responder' bootstrap.conf)"
kill $P 2>/dev/null; wait $P 2>/dev/null
"$ROOT/build/fastpki-ocsp" --config bootstrap.conf >srv3.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-ocsp died on restart:"; tail -5 srv3.log; }
# THE assertion. 500 here on the old binary; the CRL needs the CA key, which is present.
CODE=$(curl -s -o crl_rk.out -w '%{http_code}' "$B/dept-a.crl")
chk "the CRL is served anyway (200, not 500)" 200 "$CODE"
[ "$CODE" = 200 ] || echo "  body: $(head -c 200 crl_rk.out)"
# ⚠️ Decode it — a 200 carrying an error page would pass a status-only check. This is the
# artifact assertion the whole suite is built on.
chk "  and it is a real CRL"          yes \
    "$("$OSSL" crl -in crl_rk.out -inform DER -noout -text 2>/dev/null | grep -q 'Certificate Revocation List' && echo yes || echo no)"
chk "  issued by the right CA"        yes \
    "$("$OSSL" crl -in crl_rk.out -inform DER -noout -issuer 2>/dev/null | grep -q 'Dept A CA' && echo yes || echo no)"
# The other CRL route, same reasoning as above.
chk "  the /crl/{id} route agrees"    200 \
    "$(curl -s -o /dev/null -w '%{http_code}' "$B/crl/dept-a")"
# OCSP itself must refuse — it genuinely has no signing credential — but it must say WHY,
# and "not set" would be a lie: it IS set, it just is not here.
RK=$(curl -s -o ocsp_rk.out -w '%{http_code}' -H 'Content-Type: application/ocsp-request' \
        --data-binary @/dev/null "$B/ocsp/dept-a")
chk "OCSP refuses rather than 500"    yes \
    "$([ "$RK" != 500 ] && echo yes || echo no)"
chk "  and the log names the reason"  yes \
    "$(grep -qi 'no-such-responder' srv3.log && echo yes || echo no)"
chk "  not the 'is not set' message"  yes \
    "$(grep -qi 'OCSP_RESPONDER_KEY is not set' srv3.log && echo no || echo yes)"

echo
echo "=== OCSP PER-CA: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
