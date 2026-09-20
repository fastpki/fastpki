#!/usr/bin/env bash
# Console API for cert policy profiles. Profile CRUD against
# the cert_profiles table, admin-gated and write-gated.
#
# Removed /api/profile-assignments: who may USE a profile is now a `profile:use|rw`
# grant on a role, set through /api/roles/<role>/permissions. The sections that drove the
# old table are rewritten onto that route rather than deleted — the behaviour they pinned
# (a second profile ADDS rather than replaces; an unknown profile is refused) still has to
# hold, and it now has to hold somewhere else.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/json_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18290; PORT2=18291
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

pg_setup profiles_web; pg_setup profiles_web2
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
seed_cert_profiles '{"clientonly":{"allowed_ku":["digitalSignature"],"allowed_eku":["clientAuth"],"default_ku":["digitalSignature"],"default_eku":["clientAuth"],"allow_wildcard":false}}'
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
"$WEB" --config web.conf >web.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P $P2 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"

echo "=== profiles list (built-ins + the cert_profiles table) ==="
PJ=$(curl -s "$U/api/profiles")
chk "requester listed (builtin)" yes "$(has "$PJ" '"name":"requester"')"
chk "admin listed" yes "$(has "$PJ" '"name":"admin"')"
chk "custom clientonly listed" yes "$(has "$PJ" '"name":"clientonly"')"
# Only the custom profile is non-builtin, so a single "builtin":false marks it.
chk "a non-builtin (custom) profile present" yes "$(has "$PJ" '"builtin":false')"
chk "built-ins marked builtin:true" yes "$(has "$PJ" '"builtin":true')"

echo "=== profile definition CRUD ==="
chk "create custom profile 'devs' (201)" 201 \
    "$(code -X POST "$U/api/profiles" -d 'name=devs&allowed_eku=clientAuth&default_eku=clientAuth&allowed_ku=digitalSignature&default_ku=digitalSignature')"
chk "devs now listed" yes "$(has "$(curl -s "$U/api/profiles")" '"name":"devs"')"
chk "edit devs (allow wildcards) (201)" 201 \
    "$(code -X POST "$U/api/profiles" -d 'name=devs&allowed_eku=clientAuth&default_eku=clientAuth&allow_wildcard=true')"
# validity_days is not on the console's form, and the save built the profile from scratch,
# so every console save reset it to 0.
code -X POST "$U/api/profiles" -d 'name=devs&allowed_eku=clientAuth&default_eku=clientAuth&validity_days=400' >/dev/null
code -X POST "$U/api/profiles" -d 'name=devs&allowed_eku=clientAuth&default_eku=clientAuth&allow_wildcard=true' >/dev/null
chk "a save that does not send validity_days keeps it" yes \
    "$(curl -s "$U/api/profiles" | tr '}' '\n' | grep -q '"name":"devs".*"validity_days":400\|"validity_days":400.*"name":"devs"' && echo yes || echo no)"
# The built-ins ARE editable now — an operator forbidden from editing them
# cannot fix their own defaults. They remain UNDELETABLE (asserted below), because
# issuance falls back to kDefaultProfile by name.
chk "editing a built-in profile is now accepted (201)" 201 \
    "$(code -X POST "$U/api/profiles" -d 'name=requester&allowed_eku=clientAuth&default_eku=clientAuth')"
code -X POST "$U/api/roles" --data-urlencode 'name=devrole' >/dev/null
chk "now grantable to a role (200)" 200 \
    "$(code -X POST "$U/api/roles/devrole/permissions" --data-urlencode 'grants=profile:use|devs')"
# Drop it again: `devs` is deleted two lines down and a grant naming a gone profile is
# exactly what the validation below refuses, so leaving it would poison every later save.
code -X POST "$U/api/roles/devrole/permissions" --data-urlencode 'grants=' >/dev/null
chk "delete a built-in profile is refused (400)" 400 "$(code -X DELETE "$U/api/profiles?name=admin")"
# ⚠️ The API accepting an edit is only HALF of "editable" — the built-ins were asked for
# twice to be editable, and the backend allows it. What was still
# missing is the console EDIT BUTTON, hidden behind `!p.builtin` while
# clone was rendered for every profile. A markup grep is a weak proxy, but it is the one
# that catches the gate being put back: `data-editprof` must NOT sit inside a builtin test.
JS=$(curl -s "$U/")
# The edit control is now the shared gear, so the pattern moved with the markup. What it
# pins has not: `data-editprof` must NOT sit inside a builtin test.
chk "console renders Edit for every profile, built-ins included" yes \
    "$(echo "$JS" | grep -qF "'<button class=\"gearbtn\" data-editprof=\"' + esc(p.name)" && echo yes || echo no)"
# The undeletable-built-in rule MOVED rather than went: the per-row delete button is gone,
# a row is selected for bulk delete by a checkbox, and a built-in is the one row that does
# not get one.
chk "  and only DELETE is still gated on the built-in flag" yes \
    "$(echo "$JS" | grep -qF "'<td class=\"cbcol\">' + (p.builtin ? '' :" && echo yes || echo no)"
chk "  the page no longer calls the built-ins read-only" no \
    "$(echo "$JS" | grep -q 'are read-only but can be cloned' && echo yes || echo no)"
# The new profile field must be on the form AND submitted, or an operator
# can never grant a passthrough OID from the console.
chk "the allowed-custom-extensions field is on the form" yes \
    "$(echo "$JS" | grep -q "name=\"allowed_custom_extensions\"" && echo yes || echo no)"
chk "  and the form actually SENDS it" yes \
    "$(echo "$JS" | grep -q "fd.set('allowed_custom_extensions'" && echo yes || echo no)"
# The API half, asserted by round-trip rather than by the 201.
code -X POST "$U/api/profiles" -d 'name=passthru&allowed_ku=digitalSignature&default_ku=digitalSignature&allowed_custom_extensions=1.2.3.4,*' >/dev/null
PP=$(curl -s "$U/api/profiles")
chk "allowed_custom_extensions round-trips through the API" yes \
    "$(echo "$PP" | tr ',' '\n' | grep -q '1.2.3.4' && echo "$PP" | grep -q '"allowed_custom_extensions"' && echo yes || echo no)"
code -X DELETE "$U/api/profiles?name=passthru" >/dev/null
chk "'devs' is stored as its own cert_profiles row" 1 \
    "$(pg_exec "SELECT count(*) FROM cert_profiles WHERE name='devs';" | tr -d ' ')"
chk "delete custom profile 'devs' ok" 200 "$(code -X DELETE "$U/api/profiles?name=devs")"
chk "devs gone" no "$(has "$(curl -s "$U/api/profiles")" '"name":"devs"')"
chk "  and so is its row" 0 "$(pg_exec "SELECT count(*) FROM cert_profiles WHERE name='devs';" | tr -d ' ')"

echo "=== profiles are a replicated TABLE: the console follows writes it did not make ==="
# The table replicates and fastpki-config writes it, so a running console must see a profile
# that arrived from elsewhere without a restart — and must not list one deleted elsewhere.
printf 'PG_CONNINFO=%s\n' "$PG_CONNINFO" > cli.conf
seed_cert_profiles '{"outside":{"allowed_ku":["digitalSignature"],"default_ku":["digitalSignature"]}}'
chk "a profile imported with fastpki-config is listed at once" yes \
    "$(has "$(curl -s "$U/api/profiles")" '"name":"outside"')"
chk "profiles-export prints the stored profiles as one object" yes \
    "$("$ROOT/build/fastpki-config" --config cli.conf profiles-export | grep -q '"outside":{' && echo yes || echo no)"
chk "profiles-delete removes it" yes \
    "$("$ROOT/build/fastpki-config" --config cli.conf profiles-delete outside | grep -q 'deleted profile outside' && echo yes || echo no)"
chk "  and the console stops listing it" no "$(has "$(curl -s "$U/api/profiles")" '"name":"outside"')"
chk "profiles-delete of a built-in with no row says it is already at its default" yes \
    "$("$ROOT/build/fastpki-config" --config cli.conf profiles-delete admin 2>&1 | grep -q 'already at its default' && echo yes || echo no)"
# One malformed row costs that profile, not the catalogue.
pg_exec "INSERT INTO cert_profiles(name, definition) VALUES('broken','not json');" >/dev/null
BJ=$(curl -s "$U/api/profiles")
chk "a malformed row is not listed" no "$(has "$BJ" '"name":"broken"')"
chk "  and every other profile still is" yes "$(has "$BJ" '"name":"clientonly"')"
chk "  and the console says which row it skipped" yes \
    "$(grep -q "profile 'broken' is stored malformed" web.log && echo yes || echo no)"
pg_exec "DELETE FROM cert_profiles WHERE name='broken';" >/dev/null

echo "=== Per-profile csr_attrs round-trip (editor -> config -> API) ==="
# AttrOrOID JSON as the Profiles editor submits it: an id-ecPublicKey Attribute
# with a P-384 value, a bare challengePassword OID, and a bare id-ad-ocsp OID.
CA='[{"oid":"1.2.840.10045.2.1","values":["1.3.132.0.34"]},"1.2.840.113549.1.9.7","1.3.6.1.5.5.7.48.1"]'
chk "create profile 'estp' with csr_attrs (201)" 201 \
    "$(code -X POST "$U/api/profiles" --data-urlencode 'name=estp' --data-urlencode 'allowed_ku=digitalSignature' --data-urlencode 'default_ku=digitalSignature' --data-urlencode "csr_attrs=$CA")"
PJC=$(curl -s "$U/api/profiles")
chk "csr_attrs: EC pubkey Attribute + P-384 value persisted" yes "$(echo "$PJC" | grep -q '1.3.132.0.34' && echo yes)"
chk "csr_attrs: challengePassword bare OID persisted"        yes "$(echo "$PJC" | grep -q '1.2.840.113549.1.9.7' && echo yes)"
# A save that omits csr_attrs must not carry the old ones over (fresh set each save).
chk "re-save without csr_attrs clears them (201)" 201 \
    "$(code -X POST "$U/api/profiles" --data-urlencode 'name=estp' --data-urlencode 'allowed_ku=digitalSignature' --data-urlencode 'csr_attrs=[]')"
chk "csr_attrs now empty for estp" '[]' \
    "$(json_rec "$(curl -s "$U/api/profiles")" name estp | grep -o '"csr_attrs":\[[^]]*\]' | sed 's/.*://')"
curl -s -X DELETE "$U/api/profiles?name=estp" >/dev/null

echo "=== custom extensions + manage-AIA/CRLDP flags round-trip ==="
CE='[{"oid":"1.3.6.1.5.5.7.48.1.5","value":"DER:05:00","critical":false},{"oid":"1.2.3.4.5.6.7","value":"ASN1:UTF8:hi","critical":true}]'
chk "create profile 'ocspr' with custom_extensions + manage flags (201)" 201 \
    "$(code -X POST "$U/api/profiles" --data-urlencode 'name=ocspr' --data-urlencode 'allowed_ku=digitalSignature' --data-urlencode 'default_ku=digitalSignature' --data-urlencode "custom_extensions=$CE" --data-urlencode 'manage_aia=true' --data-urlencode 'manage_crldp=true')"
PJE=$(curl -s "$U/api/profiles")
chk "custom ext ocsp-nocheck OID persisted"  yes "$(echo "$PJE" | grep -q '1.3.6.1.5.5.7.48.1.5' && echo yes)"
OCSPR=$(json_rec "$PJE" name ocspr)
OCSPR_CE=$(printf '%s' "$OCSPR" | sed 's/.*"custom_extensions":\(\[[^]]*\]\).*/\1/')
chk "custom ext critical flag persisted"     yes "$(json_elems "$OCSPR_CE" | grep -F '"oid":"1.2.3.4.5.6.7"' | grep -q '"critical":true' && echo yes || echo no)"
chk "manage_aia persisted"                   yes "$([ "$(json_num "$OCSPR" manage_aia)" = true ] && echo yes || echo no)"
chk "manage_crldp persisted"                 yes "$([ "$(json_num "$OCSPR" manage_crldp)" = true ] && echo yes || echo no)"
# A save that omits them must not carry the old ones over (fresh set each save).
chk "re-save without custom exts clears them (201)" 201 \
    "$(code -X POST "$U/api/profiles" --data-urlencode 'name=ocspr' --data-urlencode 'allowed_ku=digitalSignature' --data-urlencode 'custom_extensions=[]')"
OCSPR2=$(json_rec "$(curl -s "$U/api/profiles")" name ocspr)
chk "custom_extensions now empty + manage flags reset" yes \
    "$(printf '%s' "$OCSPR2" | grep -q '"custom_extensions":\[\]' && \
       [ "$(json_num "$OCSPR2" manage_aia)" != true ] && \
       [ "$(json_num "$OCSPR2" manage_crldp)" != true ] && echo yes || echo no)"
curl -s -X DELETE "$U/api/profiles?name=ocspr" >/dev/null

echo "=== profile grants live on ROLES ==="
# Grants come back inside GET /api/roles — there is no per-role permissions GET — so read
# the role's own record out of the list rather than grepping the whole document, or a
# grant on a DIFFERENT role would satisfy every assertion below.
grants(){ json_rec "$(curl -s "$U/api/roles")" name devrole | sed 's/.*"grants":\[//;s/\].*//'; }
chk "devrole holds no profile grant yet" no "$(has "$(grants)" 'clientonly')"
chk "grant user role -> clientonly (200)" 200 \
    "$(code -X POST "$U/api/roles/devrole/permissions" --data-urlencode 'grants=profile:use|clientonly')"
chk "grant listed on the role" yes "$(has "$(grants)" '"permission":"profile:use","scope":"clientonly"')"
# ⚠️ Asserted this against the old table, where assigning a SECOND profile silently
# REPLACED the first through ON CONFLICT ... DO UPDATE on a two-column key — success
# returned, previous row gone. The union has no key to collide on, but the property still
# has to be measured: a role may hold several profiles at once.
chk "a second profile for the same role is ADDED (200)" 200 \
    "$(code -X POST "$U/api/roles/devrole/permissions" --data-urlencode 'grants=profile:use|clientonly
profile:use|admin')"
GJ=$(grants)
chk "  the new one is there"      yes "$(has "$GJ" '"scope":"admin"')"
chk "  and the FIRST one survived" yes "$(has "$GJ" '"scope":"clientonly"')"

echo "=== validation ==="
# The old /api/profile-assignments refused an unknown profile with a 400. This route
# replaced it, so it has to refuse one too — a grant naming a profile that does not exist
# would sit in the table looking effective and simply never resolve.
chk "unknown profile in a profile: scope rejected (400)" 400 \
    "$(code -X POST "$U/api/roles/devrole/permissions" --data-urlencode 'grants=profile:use|nope')"
chk "unknown permission verb rejected (400)" 400 \
    "$(code -X POST "$U/api/roles/devrole/permissions" --data-urlencode 'grants=banana:ro|admin')"
# A CA-scoped verb is deliberately NOT checked against existing CAs — ids come and go
# independently of the roles that name them — so this must still be accepted.
chk "a CA scope naming no existing CA is still accepted (200)" 200 \
    "$(code -X POST "$U/api/roles/devrole/permissions" --data-urlencode 'grants=est:enrol|no-such-ca')"

echo "=== removing a grant ==="
# set_role_grants REPLACES the list, so "delete" is a save without the line. That is the
# whole delete story now: there is no per-grant DELETE route to get wrong.
chk "save without the profile line drops it (200)" 200 \
    "$(code -X POST "$U/api/roles/devrole/permissions" --data-urlencode 'grants=profile:use|admin')"
GJ2=$(grants)
chk "  clientonly is gone"        no  "$(has "$GJ2" '"scope":"clientonly"')"
chk "  admin survived the save"   yes "$(has "$GJ2" '"scope":"admin"')"

echo "=== the list carries the same controls as every other list page ==="
# A checkbox on the left of each DELETABLE row, one bulk-delete button at the top, a gear
# to edit, and the row itself opens the read-only detail view — the shape the subjects,
# templates and domains lists already use. The three per-row buttons went with it, and
# Clone moved into the detail view.
#
# ⚠️ EXPRESSIONS ONLY, NEVER PROSE. The served page embeds the console's own source
# comments, so grepping for a phrase would match the explanation whether or not the wiring
# exists. Every pattern below is a code expression.
curl -s "$U/" -o page.html
pg(){ grep -qF -- "$1" page.html && echo yes || echo no; }
chk "fixture: the console page was served"       yes "$(pg 'id="profilepanel"')"
chk "each deletable row carries a checkbox"      yes "$(pg "'<input type=\"checkbox\" data-sel=\"' + esc(p.name) + '\"'")"
chk "the header carries a select-all"            yes "$(pg 'id="profall"')"
chk "the toolbar carries one bulk delete"        yes "$(pg "Delete selected (' + profSel.size + ')")"
# .dtable is load-bearing: the checkbox and gear column widths are declared as
# table.dtable th.cbcol / td.gearcol and match nothing on a bare <table>.
chk "the list is the shared card/dtable"         yes \
    "$(grep -B1 -F 'id="profall"' page.html | grep -qF '<table class="dtable">' && echo yes || echo no)"
# ⚠️ AN ABSENCE ASSERTION IS ONLY WORTH ANYTHING IF THE PATTERN USED TO BE PRESENT. Each of
# these matched the previous revision of the console exactly twice — the markup and its
# handler — and no other page has ever used these names, so a hit anywhere in the served
# document would belong to this page.
chk "the per-row delete button is gone"          no  "$(pg 'data-delprof')"
chk "the per-row clone button is gone"           no  "$(pg 'data-cloneprof')"
chk "  and the single-row delete path with it"   no  "$(pg 'deleteProfile')"
# One request PER profile, and failures named. One refusal must never read as "all deleted".
chk "bulk delete issues a request per name"      yes \
    "$(pg "'/api/profiles?name=' + encodeURIComponent(n), { method:'DELETE', headers: H }")"
# ⚠️ ANCHORED TO THIS PAGE'S REQUEST. The bare failed.push(...) line is byte-identical to
# the templates page's, so grepping for it alone passed against the previous revision of
# the console, where this page had no bulk delete at all — a decoration, not a guard.
chk "  and reports the failures BY NAME"         yes \
    "$(grep -A2 -F "'/api/profiles?name=' + encodeURIComponent(n), { method:'DELETE', headers: H }" page.html | \
       grep -qF "failed.push(n + ': '" && echo yes || echo no)"
# ⚠️ The console's own confirm, never the browser's: a browser told to prevent additional
# dialogs makes window.confirm() return false for the rest of the page, turning every
# action behind one into a silent no-op that reports success.
chk "  behind the console's own confirm"         yes \
    "$(pg "await askConfirm('Delete ' + names.length + ' profile(s)?")"
# The gesture that replaced the buttons, and the guard that stops it firing on the controls
# sitting inside the same row.
chk "a row click opens the detail view"          yes "$(pg 'showProfDetail(PROFILES[+tr.dataset.row].name)')"
chk "  but not when the click was a control"     yes \
    "$(grep -B1 -F 'showProfDetail(PROFILES[+tr.dataset.row].name);' page.html | \
       grep -qF "if (e.target.closest('input, button')) return;" && echo yes || echo no)"
chk "the detail view is a modal, not an inline pane" yes "$(pg "document.querySelector('#profdetmodal .card')")"
chk "  rendered as the same grid the cert detail uses" yes \
    "$(pg "'<span class=\"x\" id=\"profdetx\">&times;</span><h3>' + esc(p.name) + '</h3><dl class=\"kvdl\">'")"
# Clone is not a request of its own — it opens the editor pre-filled under a new name — so
# moving it needs no new route: it calls the same function the row button called. It is
# offered only when that form is on the page, which is the precondition the function it
# calls already has, so the button and the function cannot drift apart.
chk "Clone moved into the detail view"           yes "$(pg 'id="profdetclone"')"
chk "  and still opens the pre-filled editor"    yes "$(pg 'close(); fillProfileForm(p.name, true);')"
chk "  only when the editor form exists"         yes \
    "$(pg "const canClone = !!document.getElementById('profform');")"
# ⚠️ THE WIDTH COMES FROM THE RULE, NOT FROM THE CLASS. `.card.wide2` re-columns a form grid
# and widens nothing, so a modal left out of this selector list silently renders at the
# 520px base with a seventeen-row definition list squeezed into it. The list is multi-line
# and grows, so match the id inside the block: `[^{}]*` cannot cross a rule boundary.
tr '\n' ' ' < page.html > page.flat
chk "the detail modal is in the wide list"       yes \
    "$(grep -qE '#profdetmodal > \.card[^{}]*\{max-width:1100px;\}' page.flat && echo yes || echo no)"
# ⚠️ TICKING A BOX UPDATES THE TOOLBAR IN PLACE — it must NOT re-render the page. A
# re-render here re-FETCHES the profile list and rewrites the whole panel (and the editor
# modal's card) on every single click: the checkbox just ticked is destroyed and rebuilt,
# so it loses focus and keyboard selection restarts at the top of the tab order, and a
# long list pays a network round trip per tick. This is the same defect that was fixed in
# the AD import picker, where it showed up as the list jumping back to the top.
#
# Anchored to the handler: `renderProfiles()` is legitimately called elsewhere (after a
# bulk delete), so its mere presence on the page proves nothing.
chk "ticking a box updates in place"            yes \
    "$(grep -A2 -F "cb.checked ? profSel.add(cb.dataset.sel) : profSel.delete(cb.dataset.sel);" page.html | \
       grep -qF 'syncProfSel();' && echo yes || echo no)"
chk "  and does not re-render the page"         no  \
    "$(grep -A2 -F "cb.checked ? profSel.add(cb.dataset.sel) : profSel.delete(cb.dataset.sel);" page.html | \
       grep -qF 'renderProfiles();' && echo yes || echo no)"
chk "  select-all repaints the boxes in place"  yes \
    "$(pg "panel.querySelectorAll('input[type=checkbox][data-sel]')")"

echo "=== writes gated by WEB_ALLOW_REVOKE ==="
# ⚠️ SET false EXPLICITLY. Writes are on by default now, so omitting the key — which is
# what this block used to do — disables nothing and the two refusals below would quietly
# stop being refusals.
cat > web2.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT2
WEB_ALLOW_REVOKE=false
LOG_LEVEL=err
EOF
"$WEB" --config web2.conf >web2.log 2>&1 & P2=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web2.conf" WEB_PORT "$P2" || true
U2="http://127.0.0.1:$PORT2"
chk "read still works" yes "$(has "$(curl -s "$U2/api/profiles")" '"name":"clientonly"')"
chk "profile write refused when the write switch is off (403)" 403 \
    "$(code -X POST "$U2/api/profiles" -d 'name=gated&allowed_ku=digitalSignature')"
chk "grant write refused when the write switch is off (403)" 403 \
    "$(code -X POST "$U2/api/roles/devrole/permissions" --data-urlencode 'grants=profile:use|clientonly')"

echo
echo "=== PROFILES WEB: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
