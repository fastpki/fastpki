#!/usr/bin/env bash
# Multi-CA dashboard. The console can list, create, and
# enable/disable CA instances, and pivot the inventory by tenant. Creation is an
# unscoped-admin act gated behind WEB_ALLOW_REVOKE; a scoped admin sees and can
# toggle only its own CA. Mirrors the fastpki-ca control plane over HTTP.
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
# Only adopt the system openssl.cnf where it really is one. On macOS this path is a
# stub that defines no providers, and exporting it breaks every pkcs11 load — the
# CA key then cannot be minted and the suite SKIPs for a reason that looks nothing
# like "wrong openssl.cnf". Tests must not assume a Linux layout (§3d).
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
WEB="$ROOT/build/fastpki-web";CA="$ROOT/build/fastpki-ca"
W="$(mktemp -d)"; cd "$W"; PORT=18094
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
field(){ echo "$1" | grep -o "\"$2\":[0-9]*" | head -1 | grep -o '[0-9]*'; }

pg_setup web_cas
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
NOW=$(date +%s)
# One cert in the global CA, one in tenant dept-a (so the dashboard can count).
# (Pre-create 'ca' instance row for FK; dept-a is created via API below.)
# NOTE: the ca_instances INSERT that used to sit here is gone. That table was dropped --
# a CA is a row of `certs` with is_ca now -- so the statement had been failing silently
# (pg_exec does not check psql's exit status, and nothing here did either). The suite
# passed regardless because seed_ca_from_conf does the real registration. Left in place
# it reads like the thing that seeds the CA, which is exactly how the next person loses
# an afternoon.
# Seed the 'ca' cert now; dept-a cert is seeded after the API creates the instance.
pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,ca_instance_id) VALUES('aa',0,$((NOW-86400)),$((NOW+86400)),'CN=def.host','x','def.host','f1','ca');"

# A real 2-level hierarchy: a self-signed root, and an intermediate signing CA
# issued by it. This makes the signing CA a genuine
# intermediate (issuer != subject) so the dashboard must classify it as such,
# and gives ROOT_CA_PEM a trust anchor to surface as its own row.
ca_in_token root.pem "/CN=Global Root CA" 3650 rootca
ROOT_KEY_URI="$CA_KEY_URI"
ca_in_token ca.pem "/CN=Global Issuing CA" 3650 issuingca root.pem "$ROOT_KEY_URI"
source "$ROOT/tests/user_helpers.sh"
seed_web_user boss bosspw admin
seed_web_user alice alicepw admin dept-a
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat srv.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c boss.cj  -d 'username=boss&password=bosspw'   "$U/api/login" >/dev/null
curl -s -c alice.cj -d 'username=alice&password=alicepw' "$U/api/login" >/dev/null
# A CA key is minted in the token, so every create that is MEANT to succeed names
# a handle. The validation cases below still post raw, because they must be refused
# before any key is involved.
mkca(){  # <id> <extra curl args...>
    local id="$1"; shift
    curl -s -o /dev/null -w '%{http_code}' -b boss.cj "$U/api/ca-instances" \
        --data-urlencode "id=$id" "$@" \
        --data-urlencode 'keyloc=pkcs11' --data-urlencode 'keygen=true' \
        --data-urlencode "keyref=$(hsm_new_key_uri "k-$id")"
}
jboss(){ curl -s -b boss.cj "$@"; }

echo "=== dashboard lists the registered signing CA (SIGNING_CA_ID) ==="
L=$(jboss "$U/api/ca-instances")
chk "ca CA is listed"                   yes "$(has "$L" '"id":"ca"')"
chk "ca CA labelled by its id"          yes "$(has "$(echo "$L" | grep -o '"id":"ca"[^}]*')" '"name":"ca"')"
chk "ca CA is a managed instance"           yes "$(has "$(echo "$L" | grep -o '"id":"ca"[^}]*')" '"managed":true')"
chk "ca CA counts its 1 issued cert" 1 "$(echo "$L" | grep -o '"id":"ca"[^}]*' | grep -o '"certs":[0-9]*' | head -1 | grep -o '[0-9]*')"
# The global signing CA is issued by the root, so it must be classified
# from the CERT (issuer != subject => intermediate), not from parent_id.
DEF0=$(echo "$L" | grep -o '"id":"ca"[^}]*')
chk "ca is intermediate (from cert, not parent_id)"      yes "$(has "$DEF0" '"kind":"intermediate"')"
chk "ca is NOT mislabelled root"                         no  "$(has "$DEF0" '"kind":"root"')"
chk "ca keyType is not the opaque 'inherited'"           no  "$(has "$DEF0" '"keyType":"inherited"')"
chk "ca exposes a serial number"                         yes "$(has "$DEF0" '"serial":"[0-9A-F]')"
# REPLACES an assertion that said the opposite. ROOT_CA_PEM used to synthesise a CA
# row called `root` out of a file on this host: listed as `active`, with a file PATH where
# its signing key belongs, and resolvable by no service — load_signing_key has refused a
# path since CA keys became token-only, so the row could never sign anything it claimed to.
# The call was to remove the key outright, which removes the row with it.
#
# This config still SETS ROOT_CA_PEM (line ~55) and points it at a real self-signed root,
# which is what makes these assertions worth anything: on the old build that file produced
# the row, so a config with the key absent would pass either way.
chk "no synthetic 'root' row is invented" no "$(has "$L" '"id":"root"')"
# NOT "the subject string appears nowhere" — that was the first version and it failed
# correctly: a registered sub-CA's `issuer` field legitimately names its root, so the
# string is there for an honest reason. The precise facts are that no row IS the anchor
# and nothing carries the key location only the synthetic row ever had.
chk "  ... nor the offline/external key location it carried" no \
    "$(has "$L" '"keyType":"offline / external"')"
chk "  ... and the anchor is not a row under any id" no "$(has "$L" '"name":"Root CA"')"
# The registered CAs are untouched by the removal — this is the half that must NOT change.
chk "the registered CA is still listed"   yes "$(has "$L" '"id":"ca"')"

echo "=== Full decoded certificate text (openssl x509 -text) ==="
DT=$(jboss "$U/api/ca-instances/ca/cert-text")
chk "ca cert-text is a full X509 dump"  yes "$(has "$DT" 'Certificate:')"
chk "ca cert-text shows the signature"  yes "$(has "$DT" 'Signature Algorithm')"
chk "ca cert-text decodes v3 extensions" yes "$(has "$DT" 'X509v3')"
# `root` is not a CA any more, so it answers exactly like any other unknown id.
chk "root cert-text -> 404" 404 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj "$U/api/ca-instances/root/cert-text")"
chk "unknown CA cert-text -> 404" 404 "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj "$U/api/ca-instances/nope/cert-text")"

echo "=== Copyable CA certificate PEM ==="
DP=$(curl -s -b boss.cj "$U/api/ca-instances/ca/cert-pem")
chk "ca cert-pem begins with a PEM header" yes "$(has "$DP" 'BEGIN CERTIFICATE')"
chk "ca cert-pem parses as an X509 cert"   yes \
    "$(echo "$DP" | "$OSSL" x509 -noout -subject >/dev/null 2>&1 && echo yes || echo no)"
chk "root cert-pem -> 404"             404 "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj "$U/api/ca-instances/root/cert-pem")"
chk "unknown CA cert-pem -> 404"       404 "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj "$U/api/ca-instances/nope/cert-pem")"

echo "=== A NON-ADMIN can download the CA certificate ==="
# ⚠️ THE REPORT: CA certs were not available for download from the console CAs page for
# non-admin users." Every assertion above used `boss`, an admin — which is exactly why the
# bug shipped. The route table gated the whole /api/ca-instances/ PREFIX on `ca:manage`,
# so a requester (who holds `ca:read`) got 403 on the trust anchor its own certificate
# chains to — material fastpki-ocsp already serves unauthenticated at /{ca_id}.crt.
seed_web_user hand handpw requester
curl -s -c hand.cj -d 'username=hand&password=handpw' "$U/api/login" >/dev/null
# ⚠️ Control first. Without it a 403 below could mean "the login failed", and a refusal
# for the wrong reason reads exactly like the refusal we are testing for.
chk "the requester is really logged in" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b hand.cj "$U/api/me")"
chk "requester CAN list CAs (ca:read, unchanged)" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b hand.cj "$U/api/ca-instances")"
HP=$(curl -s -b hand.cj "$U/api/ca-instances/ca/cert-pem")
chk "requester cert-pem -> 200"            200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b hand.cj "$U/api/ca-instances/ca/cert-pem")"
# Decode it: a 200 carrying an error page would satisfy the status check.
chk "  and it is a real X509 certificate"  yes \
    "$(echo "$HP" | "$OSSL" x509 -noout -subject >/dev/null 2>&1 && echo yes || echo no)"
chk "  and it is the SAME cert the admin gets" yes \
    "$([ "$(echo "$HP" | "$OSSL" x509 -noout -fingerprint 2>/dev/null)" = \
        "$(echo "$DP" | "$OSSL" x509 -noout -fingerprint 2>/dev/null)" ] && echo yes || echo no)"
chk "requester cert-text -> 200"           200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b hand.cj "$U/api/ca-instances/ca/cert-text")"
# ⚠️ THE OTHER HALF. Reading a CA certificate is public; ADMINISTERING a CA is not, and
# the fix must not have widened the prefix it sits inside. Both of these still 403.
chk "requester still CANNOT create a CA"   403 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b hand.cj -d 'id=sneaky&key=ec' "$U/api/ca-instances")"
chk "requester still CANNOT change CA status" 403 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b hand.cj -X POST "$U/api/ca-instances/ca/status?status=disabled")"

echo "=== create a root CA over HTTP (key minted in the token) ==="
C=$(mkca dept-a --data-urlencode 'name=Dept A' --data-urlencode 'key=ec')
chk "create dept-a -> 201" 201 "$C"
# Now that dept-a exists, seed the tenant cert for inventory-pivot tests.
pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,ca_instance_id) VALUES('bb',0,$((NOW-86400)),$((NOW+86400)),'CN=depta.host','x','depta.host','f2','dept-a');"
# The CA certificate is a `certs` row, not a file — CA_INSTANCE_DIR is gone and
# the console wrote <id>.crt there for no reader. Ask the API, which is what everything
# else does, and assert the directory never appears.
chk "dept-a cert is served by the API" yes \
    "$(curl -s -b boss.cj "$U/api/ca-instances/dept-a/cert-pem" | grep -q 'BEGIN CERTIFICATE' && echo yes || echo no)"
chk "  and no CA material directory exists" no "$([ -d "$W/ca-inst" ] && echo yes || echo no)"
# The inverse of what this used to assert. No <id>.key is written, because the
# private half was made inside the token and has no on-disk form.
chk "NO dept-a key file on disk" no "$([ -f "$W/ca-inst/dept-a.key" ] && echo yes || echo no)"
L=$(jboss "$U/api/ca-instances")
chk "dept-a now listed as a managed root" yes "$(has "$L" '"id":"dept-a"')"
chk "dept-a kind=root"     yes "$(has "$(echo "$L" | grep -o '"id":"dept-a"[^}]*')" '"kind":"root"')"
chk "dept-a keyType=HSM" yes "$(has "$(echo "$L" | grep -o '"id":"dept-a"[^}]*')" '"keyType":"HSM"')"
chk "dept-a counts its 1 cert" 1 "$(echo "$L" | grep -o '"id":"dept-a"[^}]*' | grep -o '"certs":[0-9]*' | grep -o '[0-9]*')"
chk "dept-a registered in control plane" yes "$("$CA" --config bootstrap.conf list 2>/dev/null | grep -q '^dept-a' && echo yes || echo no)"

echo "=== create a Sub-CA under the signing CA (parent=ca) ==="
C=$(mkca sub-glob --data-urlencode 'name=Sub under global' --data-urlencode 'key=ec' --data-urlencode 'parent=ca')
chk "create sub-glob under parent=ca -> 201" 201 "$C"
L=$(jboss "$U/api/ca-instances")
SUBG=$(echo "$L" | grep -o '"id":"sub-glob"[^}]*')
chk "sub-glob is listed"        yes "$(has "$SUBG" '"id":"sub-glob"')"
chk "sub-glob kind=intermediate (issued, not self-signed)" yes "$(has "$SUBG" '"kind":"intermediate"')"
chk "sub-glob parentId=ca" yes "$(has "$SUBG" '"parentId":"ca"')"
# It must actually be signed BY the global signing CA (issuer = the demo CA subject).
SUBT=$(jboss "$U/api/ca-instances/sub-glob/cert-text")
chk "sub-glob issued by the ca CA" yes "$(echo "$SUBT" | grep -A2 'Issuer:' | grep -q 'Global Issuing CA' && echo yes || echo no)"
# A bogus parent is still rejected.
chk "unknown parent still rejected (400)" 400 "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj -d 'id=sub-bad&key=ec&parent=nope' "$U/api/ca-instances")"

echo "=== CAs page data is enriched (issuer / key algo+size / sig algo / location) ==="
DEPTA=$(echo "$L" | grep -o '"id":"dept-a"[^}]*')
chk "dept-a exposes issuer"          yes "$(has "$DEPTA" '"issuer":"[^"]')"
chk "dept-a key is EC P-256"         yes "$(has "$DEPTA" '"keyDesc":"EC P-256"')"
chk "dept-a exposes \"keyAlgo\"=EC"      yes "$(has "$DEPTA" '"keyAlgo":"EC"')"
chk "dept-a exposes a signature algo" yes "$(has "$DEPTA" '"sigAlgo":"[^"]')"
chk "dept-a exposes keyLocation"     yes "$(has "$DEPTA" '"keyLocation":"HSM"')"
chk "dept-a exposes a serial number" yes "$(has "$DEPTA" '"serial":"[0-9A-F]')"
chk "dept-a exposes notBefore"       yes "$(has "$DEPTA" '"notBefore":"[0-9]')"
DEF=$(echo "$L" | grep -o '"id":"ca"[^}]*')
chk "ca CA exposes its key (RSA/EC)" yes "$(has "$DEF" '"keyDesc":"\(RSA\|EC\)')"

echo "=== create a Sub-CA under dept-a ==="
C=$(mkca dept-a-sub --data-urlencode 'parent=dept-a' --data-urlencode 'key=ec')
chk "create sub -> 201" 201 "$C"
L=$(jboss "$U/api/ca-instances")
# A sub-CA is signed by its parent (issuer != subject) => intermediate.
SUB=$(echo "$L" | grep -o '"id":"dept-a-sub"[^}]*')
chk "sub kind=intermediate (signed by parent)" yes "$(has "$SUB" '"kind":"intermediate"')"
chk "sub is NOT mislabelled root"              no  "$(has "$SUB" '"kind":"root"')"

echo "=== create validation ==="
chk "reserved id 'default' -> 400" 400 "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj -d 'id=default' "$U/api/ca-instances")"
chk "duplicate id -> 409"          409 "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj -d 'id=dept-a&key=ec' "$U/api/ca-instances")"
chk "bad id chars -> 400"          400 "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj -d 'id=a/b&key=ec' "$U/api/ca-instances")"
chk "unknown parent -> 400"        400 "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj -d 'id=orphan&parent=nope&key=ec' "$U/api/ca-instances")"

echo "=== enable / disable ==="
chk "disable dept-a -> 200" 200 "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj -X POST "$U/api/ca-instances/dept-a/status?status=disabled")"
chk "dept-a now disabled" disabled "$("$CA" --config bootstrap.conf show dept-a 2>/dev/null | cut -f2)"
chk "enable dept-a -> 200" 200 "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj -X POST "$U/api/ca-instances/dept-a/status?status=active")"
chk "dept-a active again" active "$("$CA" --config bootstrap.conf show dept-a 2>/dev/null | cut -f2)"
chk "bad status value -> 400"   400 "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj -X POST "$U/api/ca-instances/dept-a/status?status=bogus")"
chk "status on 'default' -> 404" 404 "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj -X POST "$U/api/ca-instances/default/status?status=disabled")"

echo "=== inventory pivots by CA (?ca=) ==="
chk "?ca=ca shows the ca cert"           yes "$(has "$(jboss "$U/api/certs?ca=ca")" def.host)"
chk "?ca=ca hides the tenant cert"       no  "$(has "$(jboss "$U/api/certs?ca=ca")" depta.host)"
chk "?ca=dept-a shows the tenant cert"   yes "$(has "$(jboss "$U/api/certs?ca=dept-a")" depta.host)"
chk "?ca=dept-a hides the ca cert"       no  "$(has "$(jboss "$U/api/certs?ca=dept-a")" def.host)"

echo "=== tenant RBAC on the dashboard ==="
AL=$(curl -s -b alice.cj "$U/api/ca-instances")
chk "scoped alice sees her dept-a CA"     yes "$(has "$AL" '"id":"dept-a"')"
chk "scoped alice does NOT see ca"        no  "$(has "$AL" '"id":"ca"')"
chk "scoped alice does NOT see dept-a-sub" no "$(has "$AL" '"id":"dept-a-sub"')"
chk "scoped alice CANNOT create a CA -> 403" 403 "$(curl -s -o /dev/null -w '%{http_code}' -b alice.cj -d 'id=sneaky&key=ec' "$U/api/ca-instances")"
chk "scoped alice may toggle her own CA -> 200" 200 "$(curl -s -o /dev/null -w '%{http_code}' -b alice.cj -X POST "$U/api/ca-instances/dept-a/status?status=disabled")"
chk "scoped alice CANNOT toggle out-of-scope CA -> 404" 404 "$(curl -s -o /dev/null -w '%{http_code}' -b alice.cj -X POST "$U/api/ca-instances/dept-a-sub/status?status=disabled")"
"$CA" --config bootstrap.conf enable dept-a >/dev/null 2>&1   # restore

echo "=== writes are gated behind WEB_ALLOW_REVOKE ==="
# A second instance with writes off: create/toggle must be refused.
#
# ⚠️ TURNED OFF EXPLICITLY, NOT LEFT OUT. Writes are enabled by default — a console that
# silently refuses to do its job is not what anyone installs — so OMITTING this key no
# longer disables anything. This block used to rely on the omission, and the day the
# default flipped it stopped testing the gate and started testing nothing.
cat > pki2.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
WEB_BIND=127.0.0.1
WEB_PORT=$((PORT+1))
WEB_ALLOW_REVOKE=false
LOG_LEVEL=err
EOF
seed_ca_from_conf pki2.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$WEB" --config pki2.conf >srv2.log 2>&1 & P2=$!
sleep 1; trap 'pg_cleanup; kill $P $P2 2>/dev/null' EXIT
U2="http://127.0.0.1:$((PORT+1))"
curl -s -c boss2.cj -d 'username=boss&password=bosspw' "$U2/api/login" >/dev/null
chk "create refused when writes off -> 403" 403 "$(curl -s -o /dev/null -w '%{http_code}' -b boss2.cj -d 'id=nope&key=ec' "$U2/api/ca-instances")"
chk "toggle refused when writes off -> 403" 403 "$(curl -s -o /dev/null -w '%{http_code}' -b boss2.cj -X POST "$U2/api/ca-instances/dept-a/status?status=disabled")"
chk "listing still allowed (read-only) -> ok" yes "$(has "$(curl -s -b boss2.cj "$U2/api/ca-instances")" '"id":"dept-a"')"

echo "=== The CAs page is a toolbar + modals, like Users and Inventory ==="
# The runtime behaviour (form moves into the modal card, caFormInit and the
# derived-URL wiring still bind) is exercised in a browser before deploy — the
# shell harness cannot run JS. These catch a reintroduction of the old shape.
curl -s "$U/" -o index.html
inpage(){ grep -qF "$1" index.html && echo yes || echo no; }
chk "no <details> disclosure for New CA"  no  "$(inpage '<details id="cadetails"')"
chk "New CA is a toolbar button"          yes "$(inpage 'id="canew"')"
chk "Import is a toolbar button"          yes "$(inpage 'id="caimport"')"
chk "the CA modals use the shared shell"  yes "$(inpage 'id="camodal" class="modal"')"
chk "the import modal too"                yes "$(inpage 'id="caimpmodal" class="modal"')"

echo "=== the long forms do not scroll inside their own window ==="
# A form you cannot see at once is a form you fill in blind, with the Submit button below
# the fold. The fix is to stop making them tall — above 1000px the field grid runs in two
# label/field column pairs — rather than to grow the window past the screen.
curl -s -b boss.cj "$U/" -o page.html 2>/dev/null
hasq(){ grep -qF "$1" page.html && echo yes || echo no; }
chk "the tall forms opt into the two-column grid" yes \
    "$([ "$(grep -c 'class="card wide2"' page.html)" -ge 4 ] && echo yes || echo no)"
chk "  ... which is four column tracks, not two" yes \
    "$(hasq '130px minmax(0,1fr) 130px minmax(0,1fr)')"
chk "  ... only above a width where that fits" yes "$(hasq '@media (min-width: 1000px)')"
# Full-width rows must stay full-width: a textarea or checkbox row squeezed into one pair
# reads as belonging to the field beside it, which is worse than the scrolling.
chk "  ... with hints spanning both pairs" yes "$(hasq '.fgrid .hint{grid-column:1 / -1')"
chk "  ... and textareas/checkbox rows too"  yes "$(hasq '.fgrid .cbrow,')"
# Short modals are deliberately NOT widened: a confirm dialog in two columns is just wider.
chk "short modals keep the single-column grid" yes \
    "$([ "$(grep -c 'class="card wide2"' page.html)" -lt "$(grep -c 'class="modal"' page.html)" ] && echo yes || echo no)"

echo
echo "=== The MS-XCEP editor is a data table, not a key/value form ==="
# The report was vertical labels and a stray EnrolPermission checkbox. Both came
# from markup, so both are greppable. `kvform` reserves a fixed 210px label column for
# key/value pairs — using it for a five-column grid is what squeezed the fields into
# stacked, vertical-looking cells. And the columns had no header at all, so the priority
# box and the auth picker were unlabelled.
chk "the endpoint table is dtable, not kvform" yes \
    "$(sed -n '/renderCaXcep/,/^}/p' page.html | grep -q 'table class="dtable"' && echo yes || echo no)"
# Assert the MARKUP, not the word: the console JS lives in a C++ raw string, so the
# comment explaining why kvform is wrong here is itself served. Grepping for the word
# matches that prose and fails on a correct page.
chk "no kvform TABLE remains in the XCEP editor" yes \
    "$(sed -n '/renderCaXcep/,/^}/p' page.html | grep -q 'table class="kvform"' && echo no || echo yes)"
chk "every column is labelled by a header row" yes \
    "$(sed -n '/renderCaXcep/,/^}/p' page.html | grep -q '<th>Endpoint URI</th>' && echo yes || echo no)"
# The CA-level enrollPermission is a property of the CA, not of an endpoint row, and it
# was rendered as a bare checkbox carrying its raw XML name next to the buttons.
chk "enrollPermission reads as English, not an XML tag name" yes \
    "$(sed -n '/renderCaXcep/,/^}/p' page.html | grep -q 'Clients may enrol against this CA' && echo yes || echo no)"

echo "=== The CAs page carries fingerprints, and they are the real digests ==="
# Fingerprints are useful for comparing certs. The CAs detail modal
# had none at all, so there was nothing to compare with.
#
# ⚠️ COMPARED AGAINST openssl's OWN DIGEST OF THE SAME FILE, not merely "a 64-hex string
# is present". A hash of the wrong certificate is the exact failure this feature would
# cause and it looks perfectly healthy — the field is populated, the format is right, and
# the operator concludes two certificates differ when they do not.
CAJSON=$(jboss "$U/api/ca-instances")
# The suite minted this CA itself, so ca.pem IS the certificate the row must describe.
REAL256=$("$OSSL" x509 -in ca.pem -noout -fingerprint -sha256 2>/dev/null \
          | sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z')
REAL1=$("$OSSL" x509 -in ca.pem -noout -fingerprint -sha1 2>/dev/null \
        | sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z')
chk "PRECONDITION: openssl produced both digests of ca.pem" yes \
    "$([ ${#REAL256} -eq 64 ] && [ ${#REAL1} -eq 40 ] && echo yes || echo no)"
chk "the CA row carries the real SHA-256" yes "$(has "$CAJSON" "$REAL256")"
chk "the CA row carries the real SHA-1"   yes "$(has "$CAJSON" "$REAL1")"
# And the modal renders them, below Status where the ticket asked for them.
chk "the CA detail modal renders the SHA-256 row" yes \
    "$(sed -n '/function showCADetail/,/^}/p' page.html | grep -q "SHA-256 fingerprint" && echo yes || echo no)"
chk "  and the SHA-1 row" yes \
    "$(sed -n '/function showCADetail/,/^}/p' page.html | grep -q "SHA-1 fingerprint" && echo yes || echo no)"
# ⚠️ ORDER, not just presence: "below Status" is the whole of the request. Presence alone
# passes with the rows left at the bottom, which is where the Inventory one already was
# and why the ticket was raised.
CABODY=$(sed -n '/function showCADetail/,/^}/p' page.html)
chk "  and they sit below Status, not at the end" yes \
    "$([ "$(echo "$CABODY" | grep -n "row('Status'" | head -1 | cut -d: -f1)" -lt \
          "$(echo "$CABODY" | grep -n "SHA-256 fingerprint" | head -1 | cut -d: -f1)" ] \
       && echo yes || echo no)"
# Inventory's modal: SHA-256 used to be the LAST field, under Signature.
chk "the Inventory modal lists SHA-256 immediately after Status" yes \
    "$(grep -q "\['statusText','Status'\]," page.html && \
       grep -q "\['fingerprint','SHA-256'\],\['fingerprintSha1','SHA-1'\]" page.html \
       && echo yes || echo no)"
chk "  and no longer trails it after Signature" no \
    "$(grep -q "\['sigAlgo','Signature'\],\['fingerprint','SHA-256'\]" page.html && echo yes || echo no)"

echo "=== Only CAs THIS node can sign with are offered ==="
# Reported: all four CAs — two peer DCs and the offline root — appeared in the
# "Issue from" dropdown under the label "Only CAs you can access with a locally-available
# signing key are listed", and picking one failed.
#
# ⚠️ The filter was `!/offline|external/i.test(c.keyLocation)`, and the server emits only
# "none" or "HSM" — it tested for two strings that are never produced, so it excluded
# nothing. Reader with no writer, in a control whose own label promised the opposite.
#
# Two distinct reasons a CA cannot sign here, and both are invisible in a display string.
# `certs.private_key` is where the key reference lives.
# An OFFLINE ROOT: registered, active, and holding no key reference at all. Built by
# clearing the key on a registered instance, because `dept-a` IS one of the ids this suite
# already registers — inventing a new id here would test a row the console never lists.
pg_exec "UPDATE certs SET private_key=NULL WHERE id='dept-a' AND is_ca;" >/dev/null 2>&1
# A PEER DC's CA: a perfectly good pkcs11 URI naming an object that is in ANOTHER node's
# token. Token LABELS are identical on every DC (replicates ca_instances), so only the
# OBJECT distinguishes them — which is why this cannot be judged from keyLocation.
# A PEER DC's CA: a perfectly good pkcs11 URI naming an object that lives in ANOTHER
# node's token. ca_instances replicates across the mesh, so every peer's CA arrives
# here complete with its own URI, and token LABELS are identical on every DC — only the
# OBJECT distinguishes them, which is exactly why this cannot be judged from keyLocation.
#
# ⚠️ Registered with the REAL key and then repointed in the DB, because `fastpki-ca add`
# validates the handle and refuses one it cannot load. That refusal is correct — it is why
# a peer's CA can only arrive here by REPLICATION, never by an operator adding it — so the
# fixture has to reproduce replication's result rather than fight the CLI.
PEER_TOKEN=$(printf '%s' "$CA_KEY_URI" | sed -n 's/.*token=\([^;?]*\).*/\1/p')
# ⚠️ THE SERVER NEEDS TO BE ABLE TO READ THE TOKEN, or ca_signable_here() cannot tell a
# peer's key from a local one and correctly answers "unknown" — which is fail-OPEN, so
# every CA stays listed and this section would pass against the bug. The shipped compose
# sets both of these (deploy/bootstrap.compose.conf); this suite's conf did not, because its
# URIs carry pin-value= inline and nothing else had needed the enumeration.
printf '1234' > "$W/tokenpin"
printf 'PKCS11_TOKEN=%s\nPKCS11_PIN_FILE=%s\n' "$PEER_TOKEN" "$W/tokenpin" >> bootstrap.conf
kill $P 2>/dev/null; wait $P 2>/dev/null
"$WEB" --config bootstrap.conf >srv2.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" WEB_PORT "$P" || true
# ⚠️ root.pem, not ca.pem: a certificate is keyed by its own serial (folded
# ca_instances into certs), so re-registering the cert `ca` already holds is a duplicate
# and silently registers nothing.
"$CA" --config bootstrap.conf add peerdc --name "Peer DC CA" \
      --ca-pem "$W/root.pem" --ca-key "$ROOT_KEY_URI" >/dev/null 2>&1
chk "  (fixture) the peer CA registered"          yes \
    "$("$CA" --config bootstrap.conf list 2>/dev/null | grep -q '^peerdc' && echo yes || echo no)"
pg_exec "UPDATE certs SET private_key='pkcs11:token=$PEER_TOKEN;object=not-in-this-token;type=private' \
         WHERE id='peerdc' AND is_ca;" >/dev/null 2>&1
CAJ=$(jboss "$U/api/ca-instances")
chk "the local issuing CA is signable"            yes \
    "$(echo "$CAJ" | grep -o '{[^{]*"id":"ca"[^}]*}' | grep -q '"signable":true' && echo yes || echo no)"
chk "  a key-less (offline) CA is NOT"            yes \
    "$(echo "$CAJ" | grep -o '{[^{]*"id":"dept-a"[^}]*}' | grep -q '"signable":false' && echo yes || echo no)"
chk "  and a peer DC's CA is NOT"                 yes \
    "$(echo "$CAJ" | grep -o '{[^{]*"id":"peerdc"[^}]*}' | grep -q '"signable":false' && echo yes || echo no)"
# The console must FILTER on that answer, not on a display string it invented.
PG2=$(curl -s -b boss.cj "$U/" 2>/dev/null)
chk "  the pickers filter on the server's answer" yes \
    "$(echo "$PG2" | grep -q 'c.signable !== false' && echo yes || echo no)"
# ⚠️ THE SECOND HALF OF WHAT WAS REPORTED, which the first cut left alone:
# "The request fails for obvious reason 'CA instance disabled' but CAs page displays all
# 4 CAs as active (not disabled!)". The page was RIGHT — those CAs genuinely are active,
# and their CRLs and OCSP answers are still served from here. The 503 was wrong: one
# branch answered "CA instance disabled" both for a CA an operator disabled and for one
# whose key simply lives on another node, which is the ordinary state of two thirds of a
# mesh. Two outcomes, one sentence, and the sentence contradicted the page.
CASJ=$(jboss "$U/api/ca-instances")
# The id the fixture registers is `peerdc`. Read its object out of the array rather than
# grepping near it: `"status":"active"` appears for every other CA too, so a loose grep
# would pass whatever this row said.
chk "the peer CA is still reported ACTIVE (the page was right)" yes \
    "$(printf '%s' "$CASJ" | tr '{' '\n' | grep '"id":"peerdc"' | grep -q '"status":"active"' && echo yes || echo no)"
# The console must now SAY why it cannot be used, where he was looking.
PAGE=$(curl -s -b boss.cj "$U/")
chk "  the CAs page marks an active CA it cannot sign with" yes \
    "$(printf '%s' "$PAGE" | grep -q "no key here" && echo yes || echo no)"
chk "  and the detail modal says it in words"     yes \
    "$(printf '%s' "$PAGE" | grep -q "no signing key for this CA on this node" && echo yes || echo no)"
# ⚠️ And the REFUSAL must stop saying "disabled" about it. This is the half that is
# reachable by CA id from every enrolment protocol even after the picker stopped
# offering it, so it is the one an operator still meets.
chk "the 503 no longer calls a key-less CA 'disabled'" yes \
    "$(grep -rq 'no signing key for this CA on this node' "$ROOT/src/lib/ca_instance.cpp" && echo yes || echo no)"
# ⚠️ ASSERTED AS "routes through the shared helper", not "contains the string". The three
# binaries used to carry their own copy of a two-way ternary, which is what this counted.
# There are now FOUR reasons a CA cannot sign — disabled, revoked, expired, and no local key
# — and duplicating a four-way message three times is how they drift, so they all call
# pki::ca_unavailable_reason(). Counting the literal here would now enforce the duplication
# this removed.
chk "  and every protocol routes its 503 through the shared reason" 3 \
    "$(grep -rl 'ca_unavailable_reason' "$ROOT/src/acme" "$ROOT/src/est" "$ROOT/src/ocsp" | wc -l | tr -d ' ')"
chk "  and none of them still hardcodes the old two-way message" 0 \
    "$(grep -rl 'CA instance disabled\" : \"no signing key' "$ROOT/src/acme" "$ROOT/src/est" "$ROOT/src/ocsp" | wc -l | tr -d ' ')"

chk "  and the dead keyLocation regex is gone"    no \
    "$(echo "$PG2" | grep -q 'offline|external' && echo yes || echo no)"

echo
echo "=== WEB CAS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
