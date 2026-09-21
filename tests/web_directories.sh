#!/usr/bin/env bash
# The console manages the directories this deployment authenticates against.
#
# Until this page existed a directory could only be added with `fastpki-config` on a shell
# on ONE node — which is not a deployment surface for a thing that is replicated to every
# node precisely so an admin does not have to visit all of them. The tables landed first;
# this is the operator's way in.
#
# What this suite is really guarding is the bind password. It is the directory's own
# service-account credential, and two ways of getting it wrong are both silent:
#
#   * RETURNING it in the provider list hands a domain credential to anyone who can open
#     one screen — the same defect the Users page once had with enrolment credentials.
#   * OVERWRITING it with the form's empty field wipes the service account the moment an
#     admin edits anything else, leaving a directory that authenticates nobody and an
#     error that points at the directory rather than at us.
#
# Both are asserted against the DATABASE, not against the API's own account of itself.
#
# Self-contained (§3d) + shell-only (§3e): ephemeral Postgres, own port, temp dir,
# SKIPs cleanly with no Postgres.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18296
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi

pg_setup web_directories
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c admin.cj -X POST "$U/api/users" -d 'username=admin&password=adminpw12&role=admin' >/dev/null
curl -s -c admin.cj -X POST "$U/api/login" -d 'username=admin&password=adminpw12' >/dev/null

# ⚠️ PRECONDITION. Every assertion below reads an authenticated endpoint, and an
# unauthenticated body carries no providers at all — so a broken login would make every
# "the password is absent" check pass for the wrong reason. Measured, on the lab: a JSON
# POST to /api/login returns 401 and the whole check goes vacuous.
ME=$(curl -s -b admin.cj "$U/api/me")
chk "PRECONDITION: the admin session is real" yes \
    "$(echo "$ME" | grep -q '"user":"admin"' && echo yes || echo no)"

echo "=== 1. the page is reachable, not merely present in the markup ==="
# ⚠️ TO A FILE, NOT A VARIABLE. `echo "$IDX" | grep -q` makes grep exit on the first
# match and close the pipe under echo, which prints "write error: Broken pipe" into the
# middle of the results. Noise in a suite's output is how a real error gets read past.
curl -s "$U/" > index.html
chk "the nav offers a Directories tab" yes \
    "$(grep -q 'data-tab="directories"' index.html && echo yes || echo no)"
chk "  and the tab has a panel to render into" yes \
    "$(grep -q 'id="dirpanel"' index.html && echo yes || echo no)"
# ⚠️ A TAB IN THE MARKUP IS NOT A TAB A USER CAN OPEN. The console hides any tab whose
# capability is not in the caller's set, and a tab absent from that map is invisible to
# everyone — which is exactly how the Roles tab once shipped: present in the HTML,
# unreachable in the product.
chk "  and it is in the capability map, so it is not invisible to everyone" yes \
    "$(grep -q "directories: \['config:manage'\]" index.html && echo yes || echo no)"

echo "=== 2. creating a directory through the API ==="
C=$(curl -s -o body.json -w '%{http_code}' -b admin.cj -X POST "$U/api/auth-providers" \
      --data-urlencode 'id=corp' --data-urlencode 'display_name=Corp AD' \
      --data-urlencode 'uris=ldaps://dc1.corp,ldaps://dc2.corp' \
      --data-urlencode 'base_dns=ou=people,dc=corp,dc=example' \
      --data-urlencode 'bind_dn=cn=fastpki,dc=corp,dc=example' \
      --data-urlencode 'bind_pw=s3rvicepw' \
      --data-urlencode 'netbios_name=CORP' --data-urlencode 'dns_root=corp.example.com')
chk "POST creates it" 201 "$C"
L=$(curl -s -b admin.cj "$U/api/auth-providers")
chk "  and it comes back in the list" yes "$(echo "$L" | grep -q '"id":"corp"' && echo yes || echo no)"
chk "  with its NetBIOS name"          yes "$(echo "$L" | grep -q '"netbios_name":"CORP"' && echo yes || echo no)"
chk "  and its DNS root"               yes "$(echo "$L" | grep -q '"dns_root":"corp.example.com"' && echo yes || echo no)"
chk "  the row really reached the database" 1 \
    "$(pg_exec "SELECT COUNT(*) FROM ldap_providers WHERE provider_id='corp';")"
chk "  and its provider row too"            1 \
    "$(pg_exec "SELECT COUNT(*) FROM auth_providers WHERE id='corp' AND kind='ldap';")"

echo "=== 3. the bind password is WRITE-ONLY ==="
# The API's own list must not carry it in any field, under any name.
chk "the stored password is NOT in the provider list" no \
    "$(echo "$L" | grep -q 's3rvicepw' && echo yes || echo no)"
chk "  the list says only WHETHER one is stored"      yes \
    "$(echo "$L" | grep -q '"bind_pw_set":true' && echo yes || echo no)"
# ⚠️ THE CONTROL THAT STOPS THE LINE ABOVE BEING VACUOUS. "The password is not in the
# response" also passes when nothing was stored, when the request failed, or when the
# endpoint returns an empty list. So prove the password IS in the database — the API is
# withholding something that exists.
chk "  PRECONDITION: it really is stored, so withholding it means something" s3rvicepw \
    "$(pg_exec "SELECT bind_pw FROM ldap_providers WHERE provider_id='corp';")"

echo "=== 4. editing without a password KEEPS it, and does not wipe the service account ==="
C=$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X POST "$U/api/auth-providers" \
      --data-urlencode 'id=corp' --data-urlencode 'display_name=Corp Active Directory' \
      --data-urlencode 'uris=ldaps://dc1.corp,ldaps://dc2.corp' \
      --data-urlencode 'base_dns=ou=people,dc=corp,dc=example' \
      --data-urlencode 'bind_dn=cn=fastpki,dc=corp,dc=example' \
      --data-urlencode 'netbios_name=CORP' --data-urlencode 'dns_root=corp.example.com')
chk "an edit with a blank password field is accepted" 201 "$C"
chk "  the edit took"                    "Corp Active Directory" \
    "$(pg_exec "SELECT display_name FROM auth_providers WHERE id='corp';")"
chk "  and the stored password SURVIVED it" s3rvicepw \
    "$(pg_exec "SELECT bind_pw FROM ldap_providers WHERE provider_id='corp';")"

echo "=== 5. clearing it is possible, but only by asking ==="
curl -s -o /dev/null -b admin.cj -X POST "$U/api/auth-providers" \
      --data-urlencode 'id=corp' --data-urlencode 'display_name=Corp Active Directory' \
      --data-urlencode 'uris=ldaps://dc1.corp' \
      --data-urlencode 'base_dns=ou=people,dc=corp,dc=example' \
      --data-urlencode 'bind_pw_clear=true'
chk "bind_pw_clear=true removes it" "" \
    "$(pg_exec "SELECT bind_pw FROM ldap_providers WHERE provider_id='corp';")"
chk "  and the list now reports none stored" yes \
    "$(curl -s -b admin.cj "$U/api/auth-providers" | grep -q '"bind_pw_set":false' && echo yes || echo no)"

echo "=== 6. an id that would break the qualified subject is refused ==="
# A subject is `<id>\<user>`, so an id carrying a backslash or an @ makes the qualified
# name ambiguous with the very forms it is supposed to disambiguate.
for bad in 'a\b' 'a@b' 'a b'; do
  C=$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X POST "$U/api/auth-providers" \
        --data-urlencode "id=$bad" --data-urlencode 'uris=ldaps://x' --data-urlencode 'base_dns=dc=x')
  chk "  id '$bad' is refused" 400 "$C"
done
C=$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X POST "$U/api/auth-providers" \
      --data-urlencode 'id=nouris')
chk "  a directory with no URIs or base DNs is refused" 400 "$C"

echo "=== 6b. one id is one kind, and a login name answers to one directory ==="
# Saving `corp` as SAML over the LDAP `corp` answered 201 and left SAML settings under an
# LDAP provider row.
C=$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X POST "$U/api/auth-providers" \
      --data-urlencode 'id=corp' --data-urlencode 'kind=saml' --data-urlencode 'idp_sso_url=https://idp/sso' \
      --data-urlencode 'idp_cert=/tmp/x.pem' --data-urlencode 'sp_entity_id=urn:sp')
chk "  reusing an LDAP id for SAML -> 409" 409 "$C"
chk "  and no SAML settings were written under it" 0 \
    "$(pg_exec "SELECT COUNT(*) FROM saml_providers WHERE provider_id='corp';")"
# `CORP\alice` resolves CORP against every directory's names in priority order, so a second
# directory answering to CORP was unreachable by it.
C=$(curl -s -o body2.json -w '%{http_code}' -b admin.cj -X POST "$U/api/auth-providers" \
      --data-urlencode 'id=corp2' --data-urlencode 'uris=ldaps://dc9.corp' \
      --data-urlencode 'base_dns=dc=corp2' --data-urlencode 'netbios_name=corp')
chk "  a NetBIOS name equal to another directory's id -> 409" 409 "$C"
chk "  and says which directory already answers to it" yes "$(grep -q "directory 'corp'" body2.json && echo yes || echo no)"
C=$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X POST "$U/api/auth-providers" \
      --data-urlencode 'id=corp3' --data-urlencode 'uris=ldaps://dc9.corp' \
      --data-urlencode 'base_dns=dc=corp3' --data-urlencode 'dns_root=CORP')
# (corp's own DNS root was cleared by the edits in sections 4-5, so its id is the name to hit.)
chk "  a DNS root equal to another's id, in any case -> 409" 409 "$C"
# A SAML provider without sp_entity_id saved and signed nobody in — and, first in line, stopped
# SAML for every provider.
C=$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X POST "$U/api/auth-providers" \
      --data-urlencode 'id=idp1' --data-urlencode 'kind=saml' --data-urlencode 'idp_sso_url=https://idp/sso' \
      --data-urlencode 'idp_cert=/tmp/x.pem')
chk "  a SAML provider without sp_entity_id -> 400" 400 "$C"

echo "=== 7. removing one says what it orphans ==="
pg_exec "INSERT INTO subject_roles(selector_type,selector_value,role) VALUES('user','corp\\alice','admin'),('user','corp\\bob','admin'),('user','other\\carol','admin'),('group','corp\\PKI Admins','admin');" >/dev/null
D=$(curl -s -b admin.cj -X DELETE "$U/api/auth-providers?id=corp")
chk "DELETE removes the directory" 0 \
    "$(pg_exec "SELECT COUNT(*) FROM ldap_providers WHERE provider_id='corp';")"
chk "  and the provider row with it" 0 \
    "$(pg_exec "SELECT COUNT(*) FROM auth_providers WHERE id='corp';")"
# Three of the four grants are qualified by `corp` — two users AND a group, which is granted
# qualified just the same; the fourth belongs to another directory and must not be counted,
# or the number an operator is shown is not about this decision.
chk "  it counts the grants it orphans, groups included"  yes \
    "$(echo "$D" | grep -q '"orphaned_grants":3' && echo yes || echo no)"
chk "  and does NOT delete them — they are grants, not garbage" 4 \
    "$(pg_exec "SELECT COUNT(*) FROM subject_roles WHERE selector_type IN ('user','group');")"

echo "=== 7b. the sign-in page can offer the domain, so nobody has to know the spelling ==="
# The rule: an operator picks a domain and the product does not guess. An unqualified name
# is a LOCAL account and is never tried against a directory -- with one configured or with
# ten -- so the picker is how a person chooses without typing `DOMAIN\user`.
curl -s -o /dev/null -b admin.cj -X POST "$U/api/auth-providers" \
      --data-urlencode 'id=corp' --data-urlencode 'display_name=Corp AD' \
      --data-urlencode 'uris=ldaps://dc1.corp' --data-urlencode 'base_dns=dc=corp,dc=example' \
      --data-urlencode 'bind_pw=s3rvicepw'
curl -s -o /dev/null -b admin.cj -X POST "$U/api/auth-providers" \
      --data-urlencode 'id=partner' --data-urlencode 'display_name=Partner AD' \
      --data-urlencode 'uris=ldaps://dc1.partner' --data-urlencode 'base_dns=dc=partner,dc=example' \
      --data-urlencode 'enabled=false'
# ⚠️ UNAUTHENTICATED ON PURPOSE — the sign-in page reads it before anyone has signed in.
D=$(curl -s "$U/api/auth-domains")
chk "the domain list is readable without a session" yes \
    "$(echo "$D" | grep -q '"id":"corp"' && echo yes || echo no)"
chk "  it carries the display name"                 yes \
    "$(echo "$D" | grep -q '"display_name":"Corp AD"' && echo yes || echo no)"
chk "  a DISABLED directory is not offered as a choice" no \
    "$(echo "$D" | grep -q 'partner' && echo yes || echo no)"
# ⚠️ AND IT MUST NOT PUBLISH THE DIRECTORY ITSELF. This endpoint is pre-auth; the URIs,
# the service account and the base DNs live behind config:manage and must not leak here.
chk "  it does NOT leak the bind password"  no "$(echo "$D" | grep -q 's3rvicepw' && echo yes || echo no)"
chk "  nor the directory URIs"              no "$(echo "$D" | grep -q 'ldaps://' && echo yes || echo no)"
chk "  nor the base DNs"                    no "$(echo "$D" | grep -q 'dc=corp' && echo yes || echo no)"
# The picker exists in the page AND is called — a loader nobody invokes is a control that
# renders empty forever, which looks exactly like a deployment with no directories.
chk "the sign-in form has a domain control" yes \
    "$(grep -q 'id="logindomain"' index.html && echo yes || echo no)"
# ⚠️ MATCH THE CALL, NOT THE DEFINITION. `grep 'loadLoginDomains()'` also matches
# `async function loadLoginDomains() {`, so it passes whether or not anything ever invokes
# it — a guard that cannot tell a definition from a use is decoration. Watched: deleting
# the call site left the loose pattern green and this one red. The call site is a
# statement on its own line; the definition is preceded by `function`.
chk "  and something actually CALLS it (not just defines it)" yes \
    "$(grep -qE '^[[:space:]]*loadLoginDomains\(\);' index.html && echo yes || echo no)"
# ⚠️ THE FIRST OPTION IS THE SAFE ONE. A <select> that cannot show its intended value
# submits option 1; here option 1 must be the choice that changes nothing.
chk "  and its first option is the local account, not a directory" yes \
    "$(grep -q '<option value=\"\">local account</option>' index.html && echo yes || echo no)"
curl -s -o /dev/null -b admin.cj -X DELETE "$U/api/auth-providers?id=partner"

echo "=== 7c. the Kerberos keytab is uploaded, not typed, and never served back ==="
# MS_KERBEROS_KEYTAB is a PATH, and a path only helps someone who can already put a file
# there — on a container deployment, someone with a shell inside the container. The keytab
# is binary (it holds the service's long-term key), so it cannot be pasted like a PEM.
KT="$W/svc.keytab"
# A well-formed MIT keytab starts 0x05 0x02.
printf '\x05\x02FAKEKEYTABBYTES' > good.kt
printf 'not a keytab at all'      > bad.kt
# ⚠️ PER DIRECTORY NOW. A keytab holds ONE realm's service key, so a deployment-wide
# setting could serve exactly one domain and left every other domain's clients failing
# SPNEGO against a key the acceptor did not hold. The endpoint names the directory, and
# the old global MS_KERBEROS_KEYTAB config key is gone rather than kept as a fallback.
K=$(curl -s -b admin.cj "$U/api/ms-keytab?provider=corp")
chk "with nothing uploaded the console says so" no \
    "$(echo "$K" | grep -q '"present":true' && echo yes || echo no)"
C=$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X POST "$U/api/ms-keytab" --data-binary @good.kt)
chk "  an upload that names no directory is refused" 400 "$C"
C=$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X POST "$U/api/ms-keytab?provider=nosuchdir" --data-binary @good.kt)
chk "  and one naming a directory that does not exist is refused" 404 "$C"
# Give this directory a path of its own and retry — same request, different configuration.
pg_exec "UPDATE ldap_providers SET krb_keytab='$KT' WHERE provider_id='corp';" >/dev/null
# `wait` after the kill, or the shell prints its own "Terminated" line into the middle
# of the results — noise in a suite's output is how a real error gets read past.
kill $P 2>/dev/null; wait $P 2>/dev/null || true
"$WEB" --config web.conf >web2.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
curl -s -c admin.cj -X POST "$U/api/login" -d 'username=admin&password=adminpw12' >/dev/null
C=$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X POST "$U/api/ms-keytab?provider=corp" --data-binary @bad.kt)
chk "a file that is not a keytab is refused BEFORE the good one is replaced" 400 "$C"
chk "  and nothing was written"  no "$([ -f "$KT" ] && echo yes || echo no)"
C=$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X POST "$U/api/ms-keytab?provider=corp" --data-binary @good.kt)
chk "a real keytab uploads" 200 "$C"
chk "  and the bytes landed on disk byte-for-byte" yes \
    "$(cmp -s good.kt "$KT" && echo yes || echo no)"
# ⚠️ GNU FIRST, AND JUDGE THE OUTPUT, NOT THE EXIT STATUS. `stat -f` is the BSD/macOS
# spelling for a format string; on GNU coreutils `-f` means "display FILESYSTEM status",
# which SUCCEEDS on a regular file -- exit 0, printing `  File: "/tmp/.../svc.keytab"`. So
# the `||` fallback never fired and the assertion compared 600 against a block of
# filesystem prose. Green on this Mac, red on Linux, and invisible until the suite ran
# there: `[FAIL] readable only by its owner (expected '600' got '  File: ...')`.
#
# A fallback chained on exit status is only as good as the first command's willingness to
# fail. This one asks for the answer in both dialects and keeps whichever LOOKS like a mode.
file_mode(){
    local m
    for m in "$(stat -c '%a' "$1" 2>/dev/null)" "$(stat -f '%Lp' "$1" 2>/dev/null)"; do
        case "$m" in [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) printf '%s' "$m"; return 0;; esac
    done
    printf 'no-mode-from-stat'
}
chk "  readable only by its owner" 600 "$(file_mode "$KT")"
K=$(curl -s -b admin.cj "$U/api/ms-keytab?provider=corp")
chk "  the console reports it present" yes "$(echo "$K" | grep -q '"present":true' && echo yes || echo no)"
# ⚠️ IT IS A KEY. The status endpoint must report on it, never return it.
chk "  and does NOT serve the keytab back" no \
    "$(echo "$K" | grep -q 'FAKEKEYTABBYTES' && echo yes || echo no)"
chk "  the upload is audited without the bytes" yes \
    "$(pg_exec "SELECT action||' '||coalesce(detail,'') FROM audit_log WHERE action='ms_keytab_uploaded';" | grep -q 'provider=corp bytes=17' && echo yes || echo no)"
chk "the page offers the upload control" yes \
    "$(curl -s "$U/" | grep -q 'id=\"ktform\"' && echo yes || echo no)"

echo "=== 8. every write is audited, and the password is not in the audit either ==="
A=$(pg_exec "SELECT action||' '||coalesce(detail,'') FROM audit_log WHERE action LIKE 'auth_provider%' ORDER BY seq;")
# ⚠️ PRECONDITION, AND IT IS NOT A FORMALITY. The first version of this block queried a
# table called `audit` that does not exist. Four assertions went red, which is how it was
# caught — but the FIFTH, "no audit row carries the password", went GREEN, because an
# errored query returns nothing and nothing contains no password. An assertion whose
# healthy answer is "absent" passes for free the moment its input is empty.
chk "PRECONDITION: the audit query returned rows at all" yes \
    "$(echo "$A" | grep -q 'auth_provider' && echo yes || echo no)"
chk "the create is audited"  yes "$(echo "$A" | grep -q 'auth_provider_saved.*bind_pw=set' && echo yes || echo no)"
chk "  the keep is audited as a keep" yes "$(echo "$A" | grep -q 'auth_provider_saved.*bind_pw=kept' && echo yes || echo no)"
chk "  the clear is audited as a clear" yes "$(echo "$A" | grep -q 'auth_provider_saved.*bind_pw=cleared' && echo yes || echo no)"
chk "  the removal is audited"          yes "$(echo "$A" | grep -q 'auth_provider_removed' && echo yes || echo no)"
chk "  and no audit row carries the password" no "$(echo "$A" | grep -q 's3rvicepw' && echo yes || echo no)"

echo
echo "=== WEB DIRECTORIES: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
