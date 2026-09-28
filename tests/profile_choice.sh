#!/usr/bin/env bash
# An identity may CHOOSE among the profiles assigned to it — and the built-in
# profiles are editable.
#
# ── The bug ──────────────────────────────────────────────────────────────────────
#
# resolve_profile() has always taken a `requested` profile and honoured it when
# identity_allows_profile() says the identity is entitled to it. Both issuance handlers
# passed /*requested=*/"" — hardcoded, no parameter read — so only the PRIORITY WINNER
# could ever apply. This was hit trying to issue an OCSP responder
# certificate: admin holds `admin` at priority 100 for everyday work, so an `ocsp`
# profile assigned at a lower precedence could never be reached, and admin must keep
# `admin` to issue anything else.
#
# It also made his second question unanswerable — "why do we even need priorities if only
# the lowest applies?" Because with `requested` discarded, priority WAS the only selector
# and every other assignment was inert. The machinery to choose existed and nothing
# called it: the same reader-with-no-writer shape as certs.cert_id and the fuzz harnesses.
#
# ── What is asserted ─────────────────────────────────────────────────────────────
#
# By decoding the ISSUED CERTIFICATE, not by trusting a status code: choosing the
# restrictive profile must actually change the bytes (no AIA, no CRLDP), and choosing a
# profile you are NOT assigned must be refused rather than silently downgraded to the
# default — a refusal that quietly issued the default certificate would look like success.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"
unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; PORT=18499
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup profile_choice
P=
trap 'kill $P 2>/dev/null; pg_cleanup' EXIT

# ⚠️ The CA key must live in a TOKEN: load_signing_key() has no on-disk branch,
# so a file-backed SIGNING_CA_KEY leaves the CA unloadable and every issuance in this suite
# fails for a reason that has nothing to do with profiles.
skipout(){ echo "  [SKIP] $1"; echo; echo "=== PROFILE CHOICE: PASS=$pass FAIL=$fail SKIP=1 ==="; exit 0; }
ca_in_token ca.pem "/CN=Profile Choice CA" 3650 || skipout "no token"
seed_web_user boss bosspw admin

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=pc
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf

"$ROOT/build/fastpki-web" --config bootstrap.conf >web.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat web.log; exit 1; }
U="http://127.0.0.1:$PORT"
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null

echo "=== two profiles held by one identity, neither implied ==="
# `restricted` is the shape an OCSP responder needs: the profile GRANTS
# the requester the right to omit AIA/CRLDP — it does not omit them by itself.
curl -s -o /dev/null -b boss.cj "$U/api/profiles" \
     --data-urlencode 'name=restricted' --data-urlencode 'allowed_ku=digitalSignature' \
     --data-urlencode 'allowed_eku=serverAuth,OCSPSigning' \
     --data-urlencode 'default_ku=digitalSignature' --data-urlencode 'default_eku=OCSPSigning' \
     --data-urlencode 'manage_aia=true' --data-urlencode 'manage_crldp=true'
# The two profiles are held as GRANTS on the caller's role, not rows in an assignment
# table, and there are no priorities. `boss` is an admin, and admin
# ships holding `profile:use|admin` — so only `restricted` has to be added to reach the
# two-profile state this suite is about.
# `boss` is an admin, and admin ships holding `profile:use|admin`. Add `restricted` as a
# SECOND role boss also holds — additive on purpose, which is the state this suite is
# about. (grant_profile in user_helpers.sh does the opposite, replacing the builtin's
# profile, because that is what "use THIS one instead" needs.) Raw SQL rather than the
# roles API: /api/roles/<r>/permissions REPLACES a role's whole grant list, so adding one
# line through it means reading back and re-sending the other twenty-odd — noise in a suite
# whose subject is resolution. profiles_web.sh covers that route.
pg_exec "INSERT INTO roles(name,description,builtin) VALUES('extra-profile','holds restricted',false)
           ON CONFLICT DO NOTHING;
         INSERT INTO role_permissions(role,permission,scope)
           VALUES('extra-profile','profile:use','restricted') ON CONFLICT DO NOTHING;
         INSERT INTO subject_roles(selector_type,selector_value,role,created)
           VALUES('user','boss','extra-profile',0) ON CONFLICT DO NOTHING;" >/dev/null

MY=$(curl -s -b boss.cj "$U/api/my-profiles")
chk "/api/my-profiles lists BOTH entitled profiles" yes \
    "$(echo "$MY" | grep -q '"admin"' && echo "$MY" | grep -q 'restricted' && echo yes || echo no)"
# Two profiles and no name in the request: the request is issued under their MERGE —
# what either allows, with the defaults of the profile named after the PRIMARY role where
# the two disagree. `boss`'s primary role is `admin`, a member, so the merge is decided.
chk "  and the default is their merge, 'admin+restricted'" yes \
    "$(echo "$MY" | grep -q '"default":"admin+restricted"' && echo yes || echo no)"

echo "=== two profiles, primary role a member: its defaults decide ==="
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout l.key -out l.csr -subj "/CN=a.test" >/dev/null 2>&1
iss(){ curl -s -b boss.cj -X POST --data-binary @l.csr "$U/api/certs/request?ca_instance=pc${1:-}"; }
pem_of(){ sed -n 's/.*"pem":"\([^"]*\)".*/\1/p' | sed 's/\\n/\
/g'; }
# `restricted` defaults its EKU to OCSPSigning and `admin` to none. A bare CSR from boss
# must get admin's answer — an OCSP-signing certificate nobody asked for is exactly what
# picking the wrong member's default would hand out.
iss | pem_of > boss-bare.pem
chk "a bare CSR from boss issues" yes \
    "$([ -s boss-bare.pem ] && "$OSSL" x509 -in boss-bare.pem -noout >/dev/null 2>&1 && echo yes || echo no)"
chk "  without restricted's default EKU (OCSPSigning)" no \
    "$("$OSSL" x509 -in boss-bare.pem -noout -text 2>/dev/null | grep -q 'OCSP Signing' && echo yes || echo no)"

echo "=== two profiles, no primary-role member: the union decides what the CSR asks for ==="
# `amb` holds a custom role that carries admin's console access WITHOUT its profile grant
# (the restricted-admin shape), plus two profiles neither of which is called `ambiguous`.
pg_exec "INSERT INTO roles(name,description,builtin) VALUES('ambiguous','two profiles, no name match',false)
           ON CONFLICT DO NOTHING;
         INSERT INTO role_permissions(role,permission,scope)
           SELECT 'ambiguous', permission, scope FROM role_permissions
            WHERE role='admin' AND permission NOT LIKE 'profile:%' ON CONFLICT DO NOTHING;
         INSERT INTO role_permissions(role,permission,scope) VALUES
           ('ambiguous','profile:use','restricted'),('ambiguous','profile:use','requester')
           ON CONFLICT DO NOTHING;
         INSERT INTO web_users(username, role, hash, must_reset)
           SELECT 'amb','ambiguous',hash,0 FROM web_users WHERE username='boss'
           ON CONFLICT (username) DO UPDATE SET role='ambiguous';" >/dev/null
curl -s -c amb.cj -X POST "$U/api/login" -d 'username=amb&password=bosspw' >/dev/null
# ⚠️ PRECONDITION. Without it every assertion below passes just as well against a login
# that failed or a union that came back empty — both of which also issue nothing.
AMY=$(curl -s -b amb.cj "$U/api/my-profiles")
chk "PRECONDITION: 'amb' is entitled to exactly two, neither named 'ambiguous'" yes \
    "$(echo "$AMY" | grep -q 'restricted' && echo "$AMY" | grep -q 'requester' \
       && ! echo "$AMY" | grep -q '"ambiguous"' && echo yes || echo no)"
chk "  and it reports their merge" yes \
    "$(echo "$AMY" | grep -q '"default":"requester+restricted"' && echo yes || echo no)"
# ⚠️ THE UNION ITSELF. clientAuth is permitted by `requester` and NOT by `restricted`, so
# under either profile alone one of these two cells would differ: `restricted` would drop
# clientAuth. The merge honours it because a member allows it.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout c.key -out c.csr -subj "/CN=a.test" \
    -addext "extendedKeyUsage=clientAuth" >/dev/null 2>&1
curl -s -b amb.cj -X POST --data-binary @c.csr "$U/api/certs/request?ca_instance=pc" | pem_of > amb-client.pem
chk "a CSR asking for clientAuth issues with no profile named" yes \
    "$([ -s amb-client.pem ] && "$OSSL" x509 -in amb-client.pem -noout >/dev/null 2>&1 && echo yes || echo no)"
chk "  and carries clientAuth, which only one member allows" yes \
    "$("$OSSL" x509 -in amb-client.pem -noout -text 2>/dev/null | grep -q 'TLS Web Client Authentication' && echo yes || echo no)"
# A CSR that asks for NO EKU relies on a default, and the members' default EKUs differ
# (none vs OCSPSigning) with no primary-role member to decide: refused, naming what differs.
D=$(curl -s -b amb.cj -X POST --data-binary @l.csr "$U/api/certs/request?ca_instance=pc")
chk "a bare CSR, relying on the default EKU they disagree on, is not issued" no \
    "$(echo "$D" | grep -q '"pem"' && echo yes || echo no)"
chk "  and the refusal names the extended key usage and both profiles" yes \
    "$(echo "$D" | grep -q 'extended key usage' && echo "$D" | grep -q 'requester+restricted' && echo yes || echo no)"
# The control: naming one of them issues, so the refusal above is about the undecided
# default and not about `amb` being unable to issue at all.
chk "  naming one of them issues" yes \
    "$(curl -s -b amb.cj -X POST --data-binary @l.csr "$U/api/certs/request?ca_instance=pc&profile=requester" \
       | grep -q '"pem"' && echo yes || echo no)"

echo "=== ⚠️ THE ASSERTION: naming the OTHER assigned profile changes the bytes ==="
echo "$(iss '&profile=restricted&omit_aia=true&omit_crldp=true')" | sed -n 's/.*"pem":"\([^"]*\)".*/\1/p' | sed 's/\\n/\
/g' > res.pem
chk "issued when naming 'restricted'" yes \
    "$([ -s res.pem ] && "$OSSL" x509 -in res.pem -noout -subject >/dev/null 2>&1 && echo yes || echo no)"
RT=$("$OSSL" x509 -in res.pem -noout -text 2>/dev/null)
chk "  NO AIA — profile grants + request asks" no \
    "$(echo "$RT" | grep -q 'Authority Information Access' && echo yes || echo no)"
chk "  and NO CRL Distribution Points" no \
    "$(echo "$RT" | grep -q 'CRL Distribution Points' && echo yes || echo no)"
chk "  EKU is the chosen profile's default (OCSPSigning)" yes \
    "$(echo "$RT" | grep -q 'OCSP Signing' && echo yes || echo no)"

echo "=== a profile you are NOT assigned is REFUSED, not silently downgraded ==="
curl -s -o /dev/null -b boss.cj "$U/api/profiles" \
     --data-urlencode 'name=forbidden' --data-urlencode 'allowed_ku=digitalSignature' \
     --data-urlencode 'allowed_eku=serverAuth' --data-urlencode 'default_eku=serverAuth'
R=$(iss '&profile=forbidden')
chk "naming an unassigned profile does not issue" no \
    "$(echo "$R" | grep -q '"pem"' && echo yes || echo no)"
# A refusal that quietly issued the DEFAULT certificate would read as success to a client.
chk "  and it says the profile is not permitted" yes \
    "$(echo "$R" | grep -qi 'not permitted' && echo yes || echo no)"

echo "=== An identity entitled to NOTHING cannot name its way to a profile ==="
# ⚠️ THE ESCALATION THIS ALMOST SHIPPED WITH. resolve_profile briefly honoured any named
# profile when the union was EMPTY, reasoning that a deployment which has granted nothing
# must keep working. But an empty union is the NORMAL state for the callers that matter:
# CMP authenticates with a PBM secret and ACME with an account key, so neither holds a
# console role and neither has a grant — the rule handed both of them `admin`, wildcards
# and all.
pg_exec "INSERT INTO web_users(username, role, hash, must_reset)
           VALUES('nobody','requester','x',0) ON CONFLICT (username) DO NOTHING;
         DELETE FROM role_permissions WHERE role='requester' AND permission LIKE 'profile:%';"  >/dev/null
NG=$(pg_exec "SELECT count(*) FROM role_permissions p
               LEFT JOIN subject_roles s ON s.role = p.role AND s.selector_value='nobody'
              WHERE p.permission LIKE 'profile:%' AND (s.role IS NOT NULL OR p.role='requester');")
chk "PRECONDITION: 'nobody' has an EMPTY profile union" 0 "$(echo "$NG" | tr -d ' ')"
# Driven through the CONSOLE as that user, so it is the product's own resolution path and
# not a unit test of the helper.
pg_exec "UPDATE web_users SET hash=(SELECT hash FROM web_users WHERE username='boss') WHERE username='nobody';" >/dev/null
curl -s -c nb.cj -X POST "$U/api/login" -d 'username=nobody&password=bosspw' >/dev/null
NR=$(curl -s -b nb.cj -X POST --data-binary @l.csr "$U/api/certs/request?ca_instance=pc&profile=admin")
chk "an empty union does NOT honour a named profile" no \
    "$(echo "$NR" | grep -q '"pem"' && echo yes || echo no)"
chk "  and it says the identity holds no profile permission" yes \
    "$(echo "$NR" | grep -qi 'no profile permission' && echo yes || echo no)"
# The request forms offer /api/my-profiles as choices, so a caller holding none must be
# offered none — not the built-in default the list used to be padded with.
NMY=$(curl -s -b nb.cj "$U/api/my-profiles")
chk "  /api/my-profiles offers it no profile and no default" yes \
    "$(echo "$NMY" | grep -q '"profiles":\[\]' && echo "$NMY" | grep -q '"default":""' && echo yes || echo no)"
# ⚠️ INVERTED BY THE NO-DEFAULTS RULE, and the reason is worth keeping. There used to be ONE
# exception here — naming the CA default was honoured even with an empty union, "because
# that is the profile the request would have been given anyway". That was true only while
# an empty union silently fell back to the CA default. Slice 5 made an empty union refuse,
# so there is no longer a profile the request would have been given, and honouring the name
# would grant something nobody granted. The `ca_default` parameter is gone with it.
ND=$(curl -s -b nb.cj -X POST --data-binary @l.csr "$U/api/certs/request?ca_instance=pc&profile=requester")
chk "  and naming the former CA default is refused too" no \
    "$(echo "$ND" | grep -q '"pem"' && echo yes || echo no)"
# THE CONTROL: the same user, same route, issues the moment a grant exists — so the two
# refusals above are about the empty union and not about this account being broken.
pg_exec "INSERT INTO role_permissions(role,permission,scope)
           VALUES('requester','profile:use','requester') ON CONFLICT DO NOTHING;" >/dev/null
NY=$(curl -s -b nb.cj -X POST --data-binary @l.csr "$U/api/certs/request?ca_instance=pc&profile=requester")
chk "  ...and issues once the grant is put back" yes \
    "$(echo "$NY" | grep -q '"pem"' && echo yes || echo no)"

echo "=== the key-in-browser and CSR forms can name a profile; the key-in-HSM form cannot ==="
# The server has honoured `profile=` on these routes all along; the forms had no way to send
# it. Read from each form's own function in the served page, so a picker present on one
# form and forgotten on the other fails here.
curl -s -b boss.cj "$U/" > page.html
chk "the browser-key form has a Profile list"     yes "$(grep -q 'name="gprofile"' page.html && echo yes || echo no)"
chk "  and generateCert() sends it"               yes \
    "$(sed -n '/^async function generateCert(/,/^}/p' page.html | grep -q "profile=' + encodeURIComponent(f.gprofile.value)" && echo yes || echo no)"
chk "the CSR form has a Profile list"             yes "$(grep -q 'name="rprofile"' page.html && echo yes || echo no)"
chk "  and requestCert() sends it"                yes \
    "$(sed -n '/^async function requestCert(/,/^}/p' page.html | grep -q "profile=' + encodeURIComponent(prof)" && echo yes || echo no)"
chk "  both are filled from /api/my-profiles"     yes \
    "$(sed -n '/^async function populateProfilePickers(/,/^}/p' page.html | grep -q "/api/my-profiles" && echo yes || echo no)"
# Decided for the key-in-HSM form: it displays the resolved profile and does not ask for one.
chk "the key-in-HSM form still has no profile list" no \
    "$(sed -n '/^function renderHsmForm()/,/^}/p' page.html | grep -v '^[[:space:]]*//' \
       | grep -qE '<(select|input)[^>]*(id|name)="[^"]*[Pp]rof' && echo yes || echo no)"

echo "=== built-in profiles are editable, and still undeletable ==="
C=$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj "$U/api/profiles" \
     --data-urlencode 'name=requester' --data-urlencode 'allowed_ku=digitalSignature' \
     --data-urlencode 'allowed_eku=serverAuth' --data-urlencode 'default_eku=serverAuth' \
     --data-urlencode 'max_validity_days=42')
chk "editing 'requester' is accepted" yes "$([ "$C" = 200 ] || [ "$C" = 201 ] && echo yes || echo no)"
# ⚠️ The half that a 200 does not prove: it must SURVIVE, or the edit was accepted and
# dropped by the serialiser that skips built-ins. Read it back from the API.
chk "  and the edit PERSISTS (not skipped on save)" yes \
    "$(curl -s -b boss.cj "$U/api/profiles" | grep -q '"max_validity_days":42' && echo yes || echo no)"
chk "deleting a built-in is still refused" 400 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj -X DELETE "$U/api/profiles?name=requester")"

echo
echo "=== PROFILE CHOICE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
