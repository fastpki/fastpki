#!/usr/bin/env bash
# The console can WRITE roles, so a scoped role no longer needs SQL.
#
# Step 2b made scope a property of the role. That left the mechanism real but
# unreachable: an admin could confine someone to one CA only by hand-inserting rows.
# This is the editor — roles, their grants, and the `scope` on each grant, which is the
# whole of option (a) expressed through the UI.
#
# ── The two refusals that matter more than the writes ────────────────────────────
#
# 1. **The lockout guard.** An admin may edit `admin`. Stripping `role:manage` from the
#    only role that has it leaves the console unadministrable with no way back except
#    SQL — the exact hazard `roles_permissions_schema.sh` was written to worry about, now
#    enforced rather than merely noted. Sections 4 and 5 attack it from both directions:
#    editing the grants away, and deleting the role outright.
#
# 2. **An unknown permission is refused, not stored.** A typo'd verb would sit in
#    `role_permissions` looking effective while granting nothing, and the person who typed
#    it would believe access had been given. The gate's vocabulary is served at
#    /api/permissions for exactly this reason.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18476
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup web_role_editor
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
NOW=$(date +%s)

mk(){ "$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.pem" -days 3650 \
        -subj "/CN=$2" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1; }
mk depta "Dept A CA"
mk deptb "Dept B CA"
pg_seed_ca_row dept-a depta.pem "" true
pg_seed_ca_row dept-b deptb.pem "" true
pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,ca_instance_id)
         VALUES('a1',0,$((NOW-86400)),$((NOW+86400)),'CN=a.host','x','a.host','fa','dept-a'),
               ('b1',0,$((NOW-86400)),$((NOW+86400)),'CN=b.host','x','b.host','fb','dept-b');" >/dev/null

seed_web_user boss bosspw admin

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" WEB_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat srv.log; exit 1; }
U="http://127.0.0.1:$PORT"
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null

get(){ curl -s -b boss.cj "$U$1"; }
code(){ curl -s -o r.json -w '%{http_code}' -b boss.cj "$@"; }
n(){ pg_exec "$1" | tr -d ' '; }

echo "=== 1. the vocabulary is served, not hardcoded in the page ==="
PERMS=$(get /api/permissions)
chk "GET /api/permissions -> a list"  yes "$(echo "$PERMS" | grep -q '"role:manage"' && echo yes || echo no)"
chk "  it carries the enrol verbs"    yes "$(echo "$PERMS" | grep -q '"est:enrol"' && echo yes || echo no)"
chk "  and the per-CA ones"           yes "$(echo "$PERMS" | grep -q '"ca:manage"' && echo yes || echo no)"

echo "=== 2. roles read back with their grants, scope included ==="
ROLES=$(get /api/roles)
# Kept for section 5: an admin who trims their own role must be able to put it back.
ADMIN_GRANTS=$(pg_exec "SELECT string_agg(permission||chr(124)||scope, chr(10)) FROM role_permissions WHERE role='admin';")
ADMIN_N=$(n "SELECT count(*) FROM role_permissions WHERE role='admin';")
chk "the four builtins are listed"    4 "$(echo "$ROLES" | grep -o '"builtin":true' | wc -l | tr -d ' ')"
chk "admin is marked builtin"         yes \
    "$(echo "$ROLES" | grep -o '"name":"admin","description":"[^"]*","builtin":true' | grep -q . && echo yes || echo no)"
chk "grants carry a scope"            yes "$(echo "$ROLES" | grep -q '"scope":"\*"' && echo yes || echo no)"
# ⚠️ And NOT the old field name. Emitting both would let a stale page keep reading
# caId while the server had moved on, which is the half-rename this slice exists to avoid.
chk "  and not the old caId field"    no  "$(echo "$ROLES" | grep -q '"caId"' && echo yes || echo no)"

echo "=== 3. creating a SCOPED role through the API — the point of step 3 ==="
chk "create the role -> 201" 201 \
    "$(code -X POST "$U/api/roles" --data-urlencode 'name=ca-admin-dept-a' \
        --data-urlencode 'description=admin over dept-a only')"
chk "  it exists" 1 "$(n "SELECT count(*) FROM roles WHERE name='ca-admin-dept-a';")"
chk "  and is NOT builtin" f "$(n "SELECT builtin FROM roles WHERE name='ca-admin-dept-a';")"
# The grants: the same verbs an admin holds, but named at ONE CA.
chk "set its grants -> 200" 200 \
    "$(code -X POST "$U/api/roles/ca-admin-dept-a/permissions" \
        --data-urlencode 'grants=ca:read|dept-a
ca:manage|dept-a
cert:read|dept-a
cert:request|dept-a')"
chk "  four grants stored"  4 "$(n "SELECT count(*) FROM role_permissions WHERE role='ca-admin-dept-a';")"
chk "  every one names dept-a" 0 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='ca-admin-dept-a' AND scope<>'dept-a';")"
# A bare permission with no bar means every CA — the default has to be explicit somewhere,
# and this is where.
chk "a bar-less line means '*'" 200 \
    "$(code -X POST "$U/api/roles/ca-admin-dept-a/permissions" \
        --data-urlencode 'grants=ca:read|dept-a
audit:read')"
chk "  and stores the star" 1 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='ca-admin-dept-a' AND permission='audit:read' AND scope='*';")"
chk "  replacing REPLACES: the old four are gone" 2 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='ca-admin-dept-a';")"

echo "=== 4. a typo'd permission is refused, not stored ==="
chk "unknown verb -> 400" 400 \
    "$(code -X POST "$U/api/roles/ca-admin-dept-a/permissions" --data-urlencode 'grants=ca:mange|dept-a')"
chk "  and says which one" yes "$(grep -q 'ca:mange' r.json && echo yes || echo no)"
chk "  the role is untouched" 2 "$(n "SELECT count(*) FROM role_permissions WHERE role='ca-admin-dept-a';")"
chk "an invalid role name -> 400" 400 \
    "$(code -X POST "$U/api/roles" --data-urlencode 'name=bad name/../x')"
chk "an unknown role's grants -> 404" 404 \
    "$(code -X POST "$U/api/roles/nosuchrole/permissions" --data-urlencode 'grants=ca:read')"
# The scope column's typos: `own` means nothing off a cert verb, and a verb with no
# instances has nothing a name could confine. Both used to be stored and restrict nothing.
chk "scope 'own' on a non-cert verb -> 400" 400 \
    "$(code -X POST "$U/api/roles/ca-admin-dept-a/permissions" --data-urlencode 'grants=audit:read|own')"
chk "a named scope on a verb with none -> 400" 400 \
    "$(code -X POST "$U/api/roles/ca-admin-dept-a/permissions" --data-urlencode 'grants=audit:read|dept-a')"
chk "  while cert:read|own is accepted" 200 \
    "$(code -X POST "$U/api/roles/ca-admin-dept-a/permissions" --data-urlencode 'grants=ca:read|dept-a
audit:read
cert:read|own')"
code -X POST "$U/api/roles/ca-admin-dept-a/permissions" --data-urlencode 'grants=ca:read|dept-a
audit:read' >/dev/null
# "create role" upserted: an existing name — a built-in included — lost its description and limits.
pg_exec "UPDATE roles SET max_certs=7 WHERE name='auditor';" >/dev/null
chk "create=1 on an existing role -> 409" 409 \
    "$(code -X POST "$U/api/roles" --data-urlencode 'name=auditor' --data-urlencode 'description=x' --data-urlencode 'create=1')"
chk "  and the role keeps its limit" 7 "$(n "SELECT max_certs FROM roles WHERE name='auditor';")"
pg_exec "UPDATE roles SET max_certs=NULL WHERE name='auditor';" >/dev/null
chk "the vocabulary lists each permission once" 1 "$(get /api/permissions | grep -o '"profile:edit"' | wc -l | tr -d ' ')"

echo "=== 5. the lockout guard: the console cannot be locked from the inside ==="
# `admin` is the only role granting role:manage, and an admin is allowed to edit it —
# so this is reachable in one click from the UI, not a theoretical path.
chk "exactly one role grants role:manage" 1 "$(n "SELECT count(DISTINCT role) FROM role_permissions WHERE permission='role:manage';")"
chk "editing it away -> 409" 409 \
    "$(code -X POST "$U/api/roles/admin/permissions" --data-urlencode 'grants=ca:read|*')"
chk "  and explains why" yes "$(grep -q 'unadministrable' r.json && echo yes || echo no)"
chk "  admin still holds it" 1 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='admin' AND permission='role:manage';")"
# With a SECOND holder the same edit is allowed — the guard is "the last one", not
# "never", or an admin could never reorganize their own roles.
code -X POST "$U/api/roles" --data-urlencode 'name=second-admin' >/dev/null
code -X POST "$U/api/roles/second-admin/permissions" --data-urlencode 'grants=role:manage|*' >/dev/null
chk "two roles grant it now" 2 "$(n "SELECT count(DISTINCT role) FROM role_permissions WHERE permission='role:manage';")"
chk "now the edit is allowed" 200 \
    "$(code -X POST "$U/api/roles/admin/permissions" --data-urlencode 'grants=ca:read|*
role:manage|*')"
# ...and that edit really did take effect, which is why the next call would 403: admin no
# longer holds user:manage. Put it back from what section 2 read, so the round-trip
# read-grants -> write-them-unchanged is exercised too.
chk "the trimmed admin lost user:manage" 0 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='admin' AND permission='user:manage';")"
chk "restoring the original grants -> 200" 200 \
    "$(code -X POST "$U/api/roles/admin/permissions" --data-urlencode "grants=$ADMIN_GRANTS")"
chk "  admin is whole again" "$ADMIN_N" \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='admin';")"

echo "=== 6. deletion: builtins are not customizations ==="
chk "deleting a builtin -> 409" 409 "$(code -X DELETE "$U/api/roles/requester")"
chk "  it survives" 1 "$(n "SELECT count(*) FROM roles WHERE name='requester';")"
chk "deleting an unknown role -> 404" 404 "$(code -X DELETE "$U/api/roles/nope")"
# A custom role goes, and takes its grants AND its assignments with it — a subject_roles
# row pointing at a role that no longer exists is a grant nobody can see or revoke.
code -X POST "$U/api/subject-roles" --data-urlencode 'selector_type=user' \
    --data-urlencode 'selector_value=boss' --data-urlencode 'role=ca-admin-dept-a' >/dev/null
chk "the role is assigned to someone" 1 \
    "$(n "SELECT count(*) FROM subject_roles WHERE role='ca-admin-dept-a';")"
chk "delete the custom role -> 200" 200 "$(code -X DELETE "$U/api/roles/ca-admin-dept-a")"
chk "  its grants went with it"     0 "$(n "SELECT count(*) FROM role_permissions WHERE role='ca-admin-dept-a';")"
chk "  and its assignments too"     0 "$(n "SELECT count(*) FROM subject_roles WHERE role='ca-admin-dept-a';")"

echo "=== 7. every role write is audited ==="
# An access grant nobody can reconstruct afterwards is worse than one nobody made.
for a in role_upsert role_permissions_set role_delete; do
    chk "audit records $a" yes \
        "$([ "$(n "SELECT count(*) FROM audit_log WHERE action='$a';")" -ge 1 ] && echo yes || echo no)"
done
chk "the actor is recorded" boss \
    "$(n "SELECT DISTINCT actor FROM audit_log WHERE action='role_delete';")"

echo "=== 8. the console page wires it ==="
# §3e: the shell harness cannot run the page's JS, so these are greps on the served
# source — weak alone, but they catch the editor or its scope field being dropped.
JS=$(get /)
chk "a Roles tab exists"                yes "$(echo "$JS" | grep -q 'data-tab="roles"' && echo yes || echo no)"
chk "it reads /api/roles"               yes "$(echo "$JS" | grep -q "fetch('/api/roles'" && echo yes || echo no)"
chk "it offers the served vocabulary"   yes "$(echo "$JS" | grep -q "/api/permissions" && echo yes || echo no)"
chk "the grant editor has a CA field"   yes "$(echo "$JS" | grep -q 'data-g="ca"' && echo yes || echo no)"
chk "it POSTs grants as permission|scope" yes "$(echo "$JS" | grep -q "g.permission+'|'+g.scope" && echo yes || echo no)"
# The scope dropdown's CONTENTS follow the permission beside it. Offering CA ids for
# a profile:use grant stores something that looks effective and grants nothing — which is
# precisely what the two-dropdown design exists to prevent.
# The lookup moved into scopeSel() when the "unshowable scope" fix landed (section 8d), so
# ask the two halves that actually carry the behaviour: the row passes the verb's kind in,
# and the helper indexes the option table by it.
chk "  the scope list follows the verb" yes \
    "$(echo "$JS" | grep -q 'scopeSel(scopeKind(g.permission), g.scope, g.permission)' && \
       echo "$JS" | grep -q 'SCOPE_OPTS\[kind\] || SCOPE_OPTS.ca' && echo yes || echo no)"
chk "  and scopeKind knows the three"   yes \
    "$(echo "$JS" | grep -q "indexOf('profile:')" && echo "$JS" | grep -q "indexOf('template:')" && echo yes || echo no)"
chk "  and a verb with no instances gets no scope list" yes "$(echo "$JS" | grep -q "return 'none';" && echo yes || echo no)"
chk "a new grant row starts on a placeholder, not *:*" yes \
    "$(echo "$JS" | grep -q "draw(read().concat(\[{permission: '', scope: '\*'}\]))" && echo yes || echo no)"
chk "and it can delete a custom role"   yes "$(echo "$JS" | grep -q "method:'DELETE'" && echo yes || echo no)"

echo "=== 8b. the list carries the same controls as every other list page ==="
# A checkbox on the left of each DELETABLE row, one bulk-delete button at the top, a gear
# that opens ONE editor, and the row itself opens a read-only detail view. What went: two
# per-row edit buttons that painted two different editors into the SAME div, so opening
# one destroyed the other, and a per-row delete.
#
# ⚠️ EXPRESSIONS ONLY, NEVER PROSE — the served page embeds the console's own comments, so
# a phrase match proves nothing. Every pattern below is a code expression.
get / > page.html
pg(){ grep -qF -- "$1" page.html && echo yes || echo no; }
chk "fixture: the console page was served"      yes "$(pg 'data-tab="roles"')"
chk "each deletable row carries a checkbox"     yes "$(pg "'<input type=\"checkbox\" data-sel=\"'+esc(r.name)+'\"'")"
# ⚠️ A built-in is NOT DELETABLE but IS EDITABLE, and those are two different rules. Copying
# the templates page — where a built-in is a code-defined fallback and gets neither control
# — would silently remove the ability to edit the built-in roles' grants and limits.
chk "  a built-in row gets no checkbox"         yes "$(pg "'<td class=\"cbcol\">'+(r.builtin ? '' :")"
chk "  but keeps its gear"                      yes \
    "$(pg "'<td class=\"gearcol\"><button class=\"gearbtn\" data-edit=\"'+esc(r.name)+'\" title=\"Edit\">")"
chk "the header carries a select-all"           yes "$(pg 'id="roleall"')"
chk "the toolbar carries one bulk delete"       yes "$(pg "Delete selected ('+roleSel.size+')")"
# .dtable is load-bearing: the checkbox and gear column widths are declared as
# table.dtable th.cbcol / td.gearcol and match nothing on a bare <table>.
chk "the list is the shared card/dtable"        yes \
    "$(grep -B1 -F 'id="roleall"' page.html | grep -qF '<table class="dtable">' && echo yes || echo no)"
# ⚠️ AN ABSENCE ASSERTION IS ONLY WORTH ANYTHING IF THE PATTERN USED TO BE PRESENT. Each of
# these matched the previous revision of the console — the markup and its handler — and no
# other page has ever used these names, so a hit anywhere in the document would be this one.
chk "the two per-row edit buttons are gone"     no  "$(pg 'data-redit')"
chk "  both of them"                            no  "$(pg 'data-rlim')"
chk "the per-row delete button is gone"         no  "$(pg 'data-rdel')"
chk "the shared editor div is gone with them"   no  "$(pg 'id="rgrants"')"
# One request PER role, failures named. The server refuses to delete the last role granting
# role:manage, so a refusal among several is the ORDINARY case here — reporting the first
# status would read as "all deleted".
chk "bulk delete issues a request per role"     yes \
    "$(pg "'/api/roles/'+encodeURIComponent(n), { method:'DELETE', headers: H }")"
chk "  and reports the failures BY NAME"        yes \
    "$(pg "failed.push(n + ': ' + (e.error || ('HTTP '+s.status)))")"
# ⚠️ The console's own confirm, never the browser's: a browser told to prevent additional
# dialogs makes window.confirm() return false for the rest of the page, turning every
# action behind one into a silent no-op that reports success.
chk "  behind the console's own confirm"        yes \
    "$(pg "await askConfirm('Delete ' + names.length + ' role(s)?")"
# The gesture that replaced the buttons, and the guard that stops it firing on the controls
# sitting inside the same row.
chk "a row click opens the detail view"         yes "$(pg 'showRoleDetail(roles[+tr.dataset.row].name)')"
chk "  but not when the click was a control"    yes \
    "$(grep -B1 -F 'showRoleDetail(roles[+tr.dataset.row].name);' page.html | \
       grep -qF "if (e.target.closest('input, button')) return;" && echo yes || echo no)"
chk "the detail view is a modal, not an inline pane" yes "$(pg "document.querySelector('#roledetmodal .card')")"
chk "  and its lookup keeps the FULL list"      yes "$(pg 'window.ROLES = roles;')"
# ⚠️ THE WIDTH COMES FROM THE RULE, NOT FROM THE CLASS. `.card.wide2` re-columns a form grid
# and widens nothing, so a modal left out of this selector list renders at the 520px base —
# with a grants table inside it. The list is multi-line and grows as pages gain detail
# views, so match the id inside the block: `[^{}]*` cannot cross a rule boundary.
tr '\n' ' ' < page.html > page.flat
chk "the detail modal is in the wide list"      yes \
    "$(grep -qE '#roledetmodal > \.card[^{}]*\{max-width:1100px;\}' page.flat && echo yes || echo no)"

echo "=== 8c. one gear, one editor, and a save that cannot drop half the form ==="
# The two buttons opened two editors for the one role, so "edit this role" had two answers.
# They are two SECTIONS of one form now — description, the three issuance limits, and the
# grant rows.
# ⚠️ THE LIMIT FIELD IDS ARE DELIBERATELY REUSED, so asking whether the page contains one
# proves nothing — it did before the merge too. Ask whether it is inside the ONE editor.
awk '/^function editRole\(role\) \{/,/^\}/' page.html > editrole.js
er(){ grep -qF -- "$1" editrole.js && echo yes || echo no; }
chk "fixture: the editor function was extracted" yes "$([ -s editrole.js ] && echo yes || echo no)"
chk "the editor carries the description"        yes "$(er 'id="roleDesc"')"
chk "  the three issuance limits"               yes "$(er 'id="limCerts"')"
chk "  and the grant rows"                      yes "$(er 'id="rgrantrows"')"
chk "one Save, not one per section"             yes "$(pg 'id="rolesave"')"
chk "  and the old per-section Saves are gone"  no  "$(pg 'id="limsave"')"
chk "  neither of them"                         no  "$(pg 'id="gsave"')"
# The operator-facing heading the config reference points at by name.
chk "the Issuance limits heading survives"      yes "$(pg "'<h4>Issuance limits</h4>'")"
# ⚠️ THE GRANT REDRAW MUST NOT OWN THE WHOLE EDITOR. Changing a permission redraws only the
# grant rows; rewriting the box — which is what the grant editor did when it owned it —
# would discard the description and limits just typed, and the save would then post what
# was reloaded rather than what was on screen.
chk "  a permission change redraws only the rows" yes "$(pg 'rows.innerHTML =')"
# ⚠️ TWO REQUESTS, AND THE ORDER IS LOAD-BEARING. Neither route can express the other's
# half, so one request would silently drop one. The grants go FIRST because they are the
# refusable half — unknown verb, unknown scope, and the last-role-granting-role:manage
# guard — so a refusal writes nothing at all. Row-first would leave new limits stored
# against grants the server rejected: a role that reads as saved and is not the one sent.
EG=$(grep -n -F "/permissions'," editrole.js | head -1 | cut -d: -f1)
ER=$(grep -n -F "fetch('/api/roles', { method:'POST'" editrole.js | head -1 | cut -d: -f1)
chk "fixture: both requests were found in it"    yes \
    "$([ -n "$EG" ] && [ -n "$ER" ] && echo yes || echo no)"
chk "  the grants POST runs BEFORE the row POST" yes \
    "$([ -n "$EG" ] && [ -n "$ER" ] && [ "$EG" -lt "$ER" ] && echo yes || echo no)"
# ⚠️ A HALF-WRITE IS POSSIBLE BY DESIGN and must not be reported as either a clean save or
# a clean failure. It says which half landed, keeps the editor open with the typed numbers
# still in it, and repeats it in a toast, which lives outside the panel a re-render wipes.
chk "  a half-write is reported as a half-write" yes \
    "$(pg "'grants saved; the description and limits were not: '")"
chk "  in a toast as well as inline"             yes "$(pg 'notify(half);')"

echo "=== 8c-2. the gear opens a MODAL, like every other page's editor ==="
# It used to paint into a div under the table, so pressing the gear appended the form to
# the BOTTOM of the page instead of opening it over the list — on a long list that reads as
# a gear that does nothing. ⚠️ Nothing in this suite pinned that: every assertion above is
# about the editor's CONTENT, so the whole stage→modal move passed unchanged. These four
# are what makes the shape itself an invariant.
chk "the editor has a modal of its own"         yes "$(pg 'id="roleeditmodal"')"
chk "  and editRole paints into it"             yes "$(er "const modal = document.getElementById('roleeditmodal');")"
chk "  and shows it"                            yes "$(er "modal.style.display = 'flex';")"
# The stage is gone, not merely bypassed — a leftover div is how a second, invisible copy
# of an editor survives and gets written into by the next change.
chk "the under-the-table stage is gone"         no  "$(pg 'id="roleedit"')"
# ⚠️ THE WIDTH COMES FROM THE RULE, NOT THE CLASS. `.card.wide2` re-columns a form grid and
# widens nothing, so a modal left out of this list renders at the 520px base — with the
# grant table inside it.
chk "the editor modal is in the wide list"      yes \
    "$(grep -qE '#roleeditmodal > \.card[^{}]*\{max-width:1100px;\}' page.flat && echo yes || echo no)"

echo "=== 8d. a scope the dropdown cannot show must never be saved as '*' ==="
# ⚠️ THIS IS A PRIVILEGE-WIDENING GUARD, NOT A COSMETIC ONE.
#
# The scope <select> is built from lists that hold only what the CALLER may see: the CA
# list is scope-filtered server-side, and the profile and template lists are served under
# their own permissions and degrade to EMPTY when the caller lacks them. So a stored scope
# is routinely absent from the list. Marking it selected by a plain string match then does
# nothing, and a <select> with no selected option submits its FIRST — which is '*', every
# resource. The server cannot catch it: it skips the existence checks precisely for '*',
# and does not validate CA scopes at all.
#
# It is worse than a display bug because ONE Save now covers the whole role, so an admin
# editing a description or a limit would re-post the widened grants without ever having
# opened the grant rows.
chk "an unshowable scope is carried as its own option" yes \
    "$(er "return '<option '+tag+' selected>'+esc(scope)+' (outside your view)</option>'+list;")"
chk "  and the row's scope select goes through it"     yes \
    "$(er 'scopeSel(scopeKind(g.permission), g.scope, g.permission)')"
# ⚠️ ABSENCE, AND IT WAS PRESENT BEFORE — this exact expression is what silently dropped
# the selection: verified 1 occurrence in the previous revision of the console, 0 now.
chk "  the bare unconditional replace is gone"         no  "$(pg "'value=\"'+esc(g.scope)+'\" selected'")"
# The match is anchored by the CLOSING QUOTE, so ca-dc1 cannot match inside ca-dc10.
chk "  the option match is quote-anchored"             yes \
    "$(er "const tag = 'value=\"'+esc(scope)+'\"';")"

echo "=== 8e. editing a limit must not re-post the grant list ==="
# REPLACE is wholesale, so re-posting grants is never a no-op at the server. This one form
# is also how a description and the three limits are edited, and those must not rewrite
# permissions as a side effect. The baseline is the list the editor was OPENED with.
chk "the editor remembers the grants it opened with"   yes "$(er 'const grantsAsOpened =')"
chk "  and posts permissions only when they differ"    yes "$(er 'const grantsChanged = wanted !== grantsAsOpened;')"
# ⚠️ ANCHORED: asking whether the page merely CONTAINS `if (grantsChanged)` would pass with
# the POST sitting outside it. Ask whether the POST is inside the gate.
chk "  the permissions POST sits INSIDE that gate"     yes \
    "$(awk '/^function editRole\(role\) \{/,/^\}/' page.html > er2.js
       grep -A6 -F 'if (grantsChanged) {' er2.js | grep -qF "/permissions'," && echo yes || echo no)"
# And the half-write message must not claim a write that never happened.
chk "  a row-only failure does not claim grants saved" yes \
    "$(er "'the description and limits were not saved: '")"

# The client-side skip above is a correctness fix, not the security boundary. Pin the
# server contract it relies on: the role-row upsert must not touch grants, or the skip
# would stop protecting anything the next time someone edits that handler.
R8=rolescope-guard
code -X POST "$U/api/roles" --data-urlencode "name=$R8" --data-urlencode 'description=before' >/dev/null
code -X POST "$U/api/roles/$R8/permissions" --data-urlencode 'grants=est:enrol|scoped-ca-x' >/dev/null
chk "fixture: the role holds a NAMED scope"            scoped-ca-x \
    "$(n "SELECT scope FROM role_permissions WHERE role='$R8';")"
code -X POST "$U/api/roles" --data-urlencode "name=$R8" --data-urlencode 'description=after' \
     --data-urlencode 'maxCerts=5' >/dev/null
chk "the row upsert leaves the named scope alone"      scoped-ca-x \
    "$(n "SELECT scope FROM role_permissions WHERE role='$R8';")"
chk "  and it stored the limit it was called for"      5 \
    "$(n "SELECT COALESCE(max_certs::text,'') FROM roles WHERE name='$R8';")"
code -X DELETE "$U/api/roles/$R8" >/dev/null

echo "=== 9. the tab is VISIBLE to a real admin, not just present in the markup ==="
# Caught by clicking, not by grepping: the tab existed in the nav and disappeared the
# moment anyone logged in, because visibility came from a hardcoded map of the five
# builtin ROLE NAMES and `roles` was not in it. Every assertion in section 8 passed while
# the page was unusable — the lesson exactly (§3e: a markup grep cannot see
# behaviour). Visibility now follows the caller's capabilities, which /api/me reports.
MEJ=$(get /api/me)
chk "/api/me reports the caller's capabilities" yes \
    "$(echo "$MEJ" | grep -q '"capabilities":\[' && echo yes || echo no)"
chk "  admin holds role:manage"                 yes \
    "$(echo "$MEJ" | grep -q '"role:manage"' && echo yes || echo no)"
# The mapping itself, so a tab added later cannot be invisible for the same reason twice.
chk "the Roles tab is gated on role:manage"     yes \
    "$(echo "$JS" | grep -q "roles: \['role:manage'\]" && echo yes || echo no)"
chk "visibility reads capabilities, not a role-name map" yes \
    "$(echo "$JS" | grep -q 'me.capabilities' && echo yes || echo no)"
chk "  and the old hardcoded map is gone"       no \
    "$(echo "$JS" | grep -q "const allowed = { admin:" && echo yes || echo no)"
# An unknown tab hides rather than shows: a nav entry nobody mapped must not leak a page
# whose API calls would 403 anyway.
chk "an unmapped tab is hidden, not shown"      yes \
    "$(echo "$JS" | grep -q 'if (!need) return false;' && echo yes || echo no)"

echo
echo "=== 10. a CUSTOM role is offered everywhere a role can be assigned ==="
# ⚠️ THE REPORT: a custom role called 'computer' was created with two grants
# 'ms:enrol'='*' and 'profile:use'=requester. When I try to assign this role to a user or
# computer in Users page, it's not visible in any dropdown lists."
#
# ⚠️ THE DEFECT WAS A HARDCODED VOCABULARY, NOT A MISSING NAME. The console carried
# USER_ROLES and ASSIGNABLE_ROLES as literal arrays of the four builtins, feeding FIVE
# pickers: the user modal, the new group/DN modal, the LDAP group import, the LDAP user
# import, and the per-subject role editor. Roles are DATA, so EVERY custom
# role was invisible in all five. This is the fifth hardcoded-builtins bug here, so the
# assertions pin the SHAPE — the client states no role names at all — not the one name
# that happened to be tried.
chk "create the custom role -> 201" 201 \
    "$(code -X POST "$U/api/roles" -d 'name=computer&description=domain computers')"
chk "  set its two grants -> 200" 200 \
    "$(code -X POST "$U/api/roles/computer/permissions" --data-urlencode 'grants=ms:enrol|*
profile:use|requester')"
chk "  both stored" 2 "$(n "SELECT count(*) FROM role_permissions WHERE role='computer';")"

VOCAB=$(get /api/assignable-roles)
chk "the role vocabulary lists the custom role" yes \
    "$(echo "$VOCAB" | grep -q '"name":"computer"' && echo yes || echo no)"
chk "  and still lists the builtins"           yes \
    "$(echo "$VOCAB" | grep -q '"name":"auditor"' && echo yes || echo no)"
# ⚠️ The SERVER states which roles may be an EXTRA grant. `none` means "onboarded, no
# access" and POST /api/subject-roles rejects it, so it must not be offered there — a rule
# the client used to encode as a second hardcoded array.
chk "  none is NOT assignable as an extra role" yes \
    "$(echo "$VOCAB" | tr '{' '\n' | grep '"name":"none"' | grep -q '"assignable":false' && echo yes || echo no)"
chk "  while the custom role IS assignable"     yes \
    "$(echo "$VOCAB" | tr '{' '\n' | grep '"name":"computer"' | grep -q '"assignable":true' && echo yes || echo no)"

# END TO END: the thing the ticket actually asks for — assigning it.
chk "the custom role can be GRANTED to a subject -> 201" 201 \
    "$(code -X POST "$U/api/subject-roles" -d 'selector_type=user&selector_value=boss&role=computer')"
chk "  and it is stored" 1 \
    "$(n "SELECT count(*) FROM subject_roles WHERE role='computer' AND selector_value='boss';")"

echo "=== 10b. the console states NO role names of its own ==="
JS=$(get /)
# ⚠️ GUARD THE SHAPE, NOT THE SITE. Asserting "computer appears" would pass again the day
# someone re-adds a literal list that happens to contain it. What must stay true is that
# the client holds no role vocabulary at all.
chk "no hardcoded builtin-role array remains" no \
    "$(printf '%s' "$JS" | grep -qE "\['requester'," && echo yes || echo no)"
chk "  every picker is built from the server's list" yes \
    "$(printf '%s' "$JS" | grep -q 'roleOptions(' && echo yes || echo no)"
chk "  which it fetches"                             yes \
    "$(printf '%s' "$JS" | grep -q '/api/assignable-roles' && echo yes || echo no)"
# ⚠️ A picker that silently lost its options is how this stayed unreported: four builtins
# looked like the whole truth. An empty list must SAY so.
chk "  and an unloadable list renders visibly"       yes \
    "$(printf '%s' "$JS" | grep -q 'could not load the role list' && echo yes || echo no)"

echo "=== 10c. reading the vocabulary needs user:manage, NOT role:manage ==="
# Gating the NAMES behind role:manage is what pushed the console into hardcoding them:
# whoever may ASSIGN a role must be able to learn what the roles are called. The editor's
# payload — every role's grants and caps — stays at role:manage.
pg_exec "INSERT INTO roles(name,description,builtin) VALUES('useradm','test',false) ON CONFLICT DO NOTHING;" >/dev/null
pg_exec "INSERT INTO role_permissions(role,permission,scope) VALUES('useradm','user:manage','*') ON CONFLICT DO NOTHING;" >/dev/null
chk "PRECONDITION: the user-admin role holds user:manage" 1 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='useradm' AND permission='user:manage';")"
seed_web_user ua uapw12345 useradm
curl -s -c ua.cj -d 'username=ua&password=uapw12345' "$U/api/login" >/dev/null
uacode(){ curl -s -o /dev/null -w '%{http_code}' -b ua.cj "$@"; }
chk "PRECONDITION: that login works at all" 200 "$(uacode "$U/api/me")"
chk "a user-admin CAN read the role vocabulary"       200 "$(uacode "$U/api/assignable-roles")"
chk "  but CANNOT read the role editor's payload"     403 "$(uacode "$U/api/roles")"
chk "  and cannot create a role"                      403 "$(uacode -X POST "$U/api/roles" -d 'name=sneaky')"

echo "=== 10d. user:manage is a CEILING, not a route to admin ==="
# `user:manage` used to be indistinguishable from `*:*`: POST /api/users took the
# role straight from the request and checked only role_exists(), and /api/assignable-roles
# offers every role to anyone who can read it. So a "helpdesk" role could promote itself, or
# mint a fresh admin and log in as it. A caller may now assign only a role whose grants it
# already holds, and may never change its OWN role.
chk "a user-admin CANNOT promote ITSELF to admin" 403 \
    "$(uacode -X POST "$U/api/users" -d 'username=ua&role=admin&password=uapw12345')"
chk "  and its stored role is untouched" useradm \
    "$(n "SELECT role FROM web_users WHERE username='ua';")"
chk "  CANNOT mint a NEW admin to log in as" 403 \
    "$(uacode -X POST "$U/api/users" -d 'username=puppet&role=admin&password=puppetpw123&create=1')"
chk "  and no such account was created" 0 \
    "$(n "SELECT count(*) FROM web_users WHERE username='puppet';")"
# The other door onto the same escalation: bind `admin` to a group and pick it up as an
# effective role on the next request. Guarding only /api/users would be worth nothing.
chk "  CANNOT bind admin to a group either" 403 \
    "$(uacode -X POST "$U/api/subject-roles" -d 'selector_type=group&selector_value=helpdesk&role=admin')"
chk "  and no such grant was stored" 0 \
    "$(n "SELECT count(*) FROM subject_roles WHERE role='admin' AND selector_value='helpdesk';")"
# The positive half — the ceiling must not be a wall. `useradm` grants exactly what `ua`
# holds, so handing it out is within the ceiling and must still work.
chk "  but CAN assign a role it fully holds" 201 \
    "$(uacode -X POST "$U/api/users" -d 'username=peer&role=useradm&password=peerpw12345&create=1')"
chk "    and that account exists with that role" useradm \
    "$(n "SELECT role FROM web_users WHERE username='peer';")"
# And a real admin is unaffected.
chk "an admin CAN still assign admin" 201 \
    "$(code -X POST "$U/api/users" -d 'username=admin2&role=admin&password=admin2pw123&create=1')"
chk "  and CANNOT change its own role either" 403 \
    "$(code -X POST "$U/api/users" -d 'username=boss&role=useradm&password=bosspw')"
chk "    boss is still admin" admin \
    "$(n "SELECT role FROM web_users WHERE username='boss';")"

echo "=== 10e. a stronger verb answers for a weaker one — at GATES only ==="
# There is no implication between permissions except within one resource's verb ordering.
# Two resources order theirs: ca (manage > read) and hsm (manage > read). Before this, a role
# granted only ca:manage could create, renew and delete a CA and still be refused its
# CERTIFICATE, because that route asks for ca:read.
pg_exec "INSERT INTO roles(name,description,builtin) VALUES('camgr','test: ca:manage only',false)
         ON CONFLICT DO NOTHING;" >/dev/null
pg_exec "INSERT INTO role_permissions(role,permission,scope) VALUES
           ('camgr','ca:manage','*'), ('camgr','self:manage','*') ON CONFLICT DO NOTHING;" >/dev/null
seed_web_user cam campw123456 camgr
curl -s -c cam.cj -d 'username=cam&password=campw123456' "$U/api/login" >/dev/null
camcode(){ curl -s -o /dev/null -w '%{http_code}' -b cam.cj "$@"; }
chk "PRECONDITION: camgr holds ca:manage and NOT ca:read" 0 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='camgr' AND permission='ca:read';")"
chk "ca:manage reaches a ca:read route"          200 "$(camcode "$U/api/ca-instances")"

# The ordering is one-way. A reader is not a manager.
pg_exec "INSERT INTO roles(name,description,builtin) VALUES('cardr','test: ca:read only',false)
         ON CONFLICT DO NOTHING;" >/dev/null
pg_exec "INSERT INTO role_permissions(role,permission,scope) VALUES
           ('cardr','ca:read','*'), ('cardr','self:manage','*') ON CONFLICT DO NOTHING;" >/dev/null
seed_web_user car carpw1234567 cardr
curl -s -c car.cj -d 'username=car&password=carpw1234567' "$U/api/login" >/dev/null
chk "  but ca:read does NOT reach a ca:manage route" 403 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b car.cj -X POST "$U/api/ca-instances" -d 'id=x')"

# ⚠️ AND THE ORDERING STOPS AT THE GATE. may_assign_role asks whether a caller may GIVE a
# grant to somebody else, and there the match is literal: holding the stronger verb is not
# holding the weaker one, and what is handed over is a row whose effect depends on the
# recipient's other grants rather than on the entitlement that justified the implication.
pg_exec "INSERT INTO roles(name,description,builtin) VALUES('camgr2','test: ca:manage + user:manage',false)
         ON CONFLICT DO NOTHING;" >/dev/null
pg_exec "INSERT INTO role_permissions(role,permission,scope) VALUES
           ('camgr2','ca:manage','*'), ('camgr2','user:manage','*'), ('camgr2','self:manage','*')
         ON CONFLICT DO NOTHING;" >/dev/null
seed_web_user cam2 cam2pw123456 camgr2
curl -s -c cam2.cj -d 'username=cam2&password=cam2pw123456' "$U/api/login" >/dev/null
chk "  and cannot ASSIGN a role holding the weaker verb" 403 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b cam2.cj -X POST "$U/api/users" \
        -d 'username=newreader&role=cardr&password=newreaderpw1&create=1')"
chk "    so no such account exists"                      0 \
    "$(n "SELECT count(*) FROM web_users WHERE username='newreader';")"

# The two deliberate ABSENCES. profile/template do not order their verbs, because `use` is
# issuance entitlement: an administrator who may edit every profile must not thereby be
# entitled to issue under every profile.
chk "profile does not order use/edit — admin holds both explicitly" 1 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='admin' AND permission='profile:use';")"
chk "template does not order use/edit either"                       1 \
    "$(n "SELECT count(*) FROM role_permissions WHERE role='admin' AND permission='template:edit' AND scope='*';")"

echo "=== WEB ROLE EDITOR: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
