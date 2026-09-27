#!/usr/bin/env bash
# Users page redesign: the console Users tab is table-centric with a
# modal editor — a checkbox column for bulk delete, a per-row gear that opens a
# create/edit modal, Source/Must-reset pill badges, and the console role-assignment
# editor NESTED inside the modal (no standalone inline form / section on the page).
#
# This is a frontend change (the /api/users + /api/subject-roles contracts are
# unchanged and covered by web_users.sh / web_subject_roles_api.sh). So this suite
# guards the *served markup*: it asserts the new structure is shipped and the old
# inline-form scaffolding (#userform / #srform / #srtable + their handlers) is gone,
# which would otherwise regress silently (the HTML is one big embedded string).
#
# Self-contained (§3d): ephemeral Postgres via pg_helpers, own port, temp dir,
# SKIPs cleanly when no Postgres is reachable. Asserts on the real bytes served by
# a running fastpki-web, not on source.
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
W="$(mktemp -d)"; cd "$W"; PORT=18260
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
present(){ grep -qF -- "$1" index.html && echo yes || echo no; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

# Need a reachable Postgres; SKIP (not FAIL) when absent so the suite is portable.
if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT (set PGHOST/PGPORT/PGUSER/PGPASSWORD)"; exit 0
fi

pg_setup web_users_ui
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
curl -s "$U/" -o index.html
chk "index page served" yes "$([ -s index.html ] && echo yes || echo no)"

echo "=== the redesigned table-centric structure is shipped ==="
chk "user modal overlay present"        yes "$(present 'id="usermodal"')"
chk "openUserModal() builder present"   yes "$(present 'function openUserModal')"
chk "bulk-delete handler present"       yes "$(present 'function bulkDeleteSubjects')"
chk "users grid table class present"    yes "$(present 'class="dtable"')"
chk "per-row gear button present"       yes "$(present 'class="gearbtn"')"
chk "+ New user action present"         yes "$(present '+ New user')"
chk "Delete selected action present"    yes "$(present 'Delete selected')"
chk "checkbox select-all present"       yes "$(present 'id="uall"')"
chk "role assignments nested in modal"  yes "$(present 'function renderModalRoles')"
chk "modal-scoped role add form"        yes "$(present 'id="umraddf"')"

echo "=== the subject role editor is locked to its subject (type + name read-only) ==="
chk "role add-row selector is read-only" yes "$(present 'readonly title="Assignments in this dialog apply to this subject"')"
chk "role editor scoped to the subject"  yes "$(present 'Extra console roles granted to')"

echo "=== the Role column shows extra console roles, and Source IS a column ==="
# ⚠️ THIS ASSERTION USED TO READ "no Source column header", pinning the very state
# reported: the field was served and the table never showed it. A test that asserts the
# absence of a thing we later decide to add will quietly defend the gap — it did here.
chk "the subjects table HAS a Source header" yes "$(present '<th>Source</th>')"
chk "role cell includes extra roles"      yes "$(present 'EXTRA console roles granted')"

echo "=== groups / DNs are first-class subjects (follow-up) ==="
chk "subjects are merged (users + roles)" yes "$(present 'function mergeSubjects')"
chk "Type column in the subject grid"     yes "$(present 'Type</th>')"
# `dn` is gone as a selector type, so the button says what it creates. The old label
# outlived the feature by two tickets, which is what needed cleaning up:
# "One cosmetic thing to fix is to remove DN from the label on 'New group / DN' button".
chk "New group action present"           yes "$(present '+ New group<')"
chk "New group/DN modal builder"          yes "$(present 'function openNewGroupModal')"
chk "role-only subject modal builder"     yes "$(present 'function openSubjectRolesModal')"
chk "edit modal looks users up by .name"  yes "$(present 'u.type === ')"
# There are TWO directory imports now, and the labels must say which is which —
# "Import from LDAP" beside a second import button is the ambiguity the ticket is about
# (group mapping is the wrong granularity for one administrator or a break-glass account).
chk "Import GROUPS from LDAP action present"  yes "$(present 'Import groups from LDAP')"
chk "Import USER from LDAP action present"    yes "$(present 'Import user from LDAP')"
chk "LDAP import modal builder"           yes "$(present 'function openLdapImport')"

echo "=== assignable roles exclude 'none' (the subject-roles API rejects it) ==="
# ⚠️ MOVED THIS RULE FROM THE CLIENT TO THE SERVER. It used to grep for a literal
# `ASSIGNABLE_ROLES = [...]` array — which was exactly the bug: the console stated the role
# vocabulary itself, so no CUSTOM role ever appeared in any picker. The rule is unchanged
# (`none` is a primary role only) but it is now `assignable:false` from
# /api/assignable-roles, so this asserts the SAME intent against the mechanism that carries
# it. Asserting the old const again would re-demand the defect.
chk "the console fetches the role vocabulary" yes "$(present '/api/assignable-roles')"
chk "  and filters the extra-role pickers by it" yes \
    "$(present 'filter(r => !assignableOnly || r.assignable)')"
# The server contract this protects: subject-roles must 400 on role=none.
curl -s -c admin.cj -X POST "$U/api/users" -d 'username=root1&password=root1pass&role=admin' >/dev/null
curl -s -c admin.cj -X POST "$U/api/login" -d 'username=root1&password=root1pass' >/dev/null
# ⚠️ AFTER the login, deliberately. Placed before it, the request 401s, the grep finds
# nothing, and "none is not assignable" passes without the server ever being asked — a
# vacuous guard whose healthy and broken answers are identical.
VOC=$(curl -s -b admin.cj "$U/api/assignable-roles")
chk "PRECONDITION: the vocabulary endpoint answered" yes \
    "$(echo "$VOC" | grep -q '"name":"admin"' && echo yes || echo no)"
chk "assignable roles exclude 'none'"        no  \
    "$(echo "$VOC" | tr '{' '\n' | grep '"name":"none"' | grep -q '"assignable":true' && echo yes || echo no)"
chk "POST subject-roles role=none -> 400" 400 "$(code -b admin.cj -X POST "$U/api/subject-roles" -d 'selector_type=group&selector_value=g1&role=none')"
chk "POST subject-roles role=admin -> 201" 201 "$(code -b admin.cj -X POST "$U/api/subject-roles" -d 'selector_type=group&selector_value=g1&role=admin')"

echo "=== usernames are unique case-insensitively on create (follow-up) ==="
chk "create 'alpha' -> 201"                201 "$(code -b admin.cj -X POST "$U/api/users" -d 'create=1&username=alpha&password=alphapw12&role=requester')"
chk "create 'Alpha' (case dup) -> 409"     409 "$(code -b admin.cj -X POST "$U/api/users" -d 'create=1&username=Alpha&password=alphapw12&role=requester')"
chk "create 'alpha' (exact dup) -> 409"    409 "$(code -b admin.cj -X POST "$U/api/users" -d 'create=1&username=alpha&password=alphapw12&role=requester')"
chk "edit 'alpha' (no create) upserts 200" 200 "$(code -b admin.cj -X POST "$U/api/users" -d 'username=alpha&role=auditor')"


# ⚠️ AND THE DATABASE ENFORCES IT, NOT ONLY THIS ROUTE. The 409s above come from a check
# inside /api/users, and three callers reach upsert_web_user without it: EST auto-onboards
# an unknown mTLS client-certificate identity (src/est/main.cpp), MS-WSTEP does the same
# (src/msxcep/main.cpp), and restore writes rows straight in (src/lib/backup.cpp). A
# second row differing only in case makes get_web_user's
# `lower(username)=lower($1) ORDER BY username LIMIT 1` decide by COLLATION which of the
# two authenticates — so the constraint has to live where every path meets it.
pg_exec "INSERT INTO web_users(username,role,hash,must_reset,created,auth_provider)
         VALUES('ALPHA','admin','x',0,0,'dn');" >/dev/null 2>&1 \
  && r=inserted || r=refused
chk "a direct INSERT of a case-variant is refused" refused "$r"
chk "  so exactly one alpha row exists"           1 \
    "$(pg_exec "SELECT count(*) FROM web_users WHERE lower(username)='alpha';" | tr -d ' ')"
# CONTROL: a genuinely different name still inserts, so the refusal above is the
# case-collision and not a broken table or a rejected statement.
pg_exec "INSERT INTO web_users(username,role,hash,must_reset,created,auth_provider)
         VALUES('beta','auditor','x',0,0,'dn');" >/dev/null 2>&1 \
  && r=inserted || r=refused
chk "  a distinct username still inserts"         inserted "$r"
echo "=== the LDAP group endpoint answers (enabled flag) ==="
chk "/api/ldap/groups reports enabled flag" yes "$(echo "$(curl -s -b admin.cj "$U/api/ldap/groups")" | grep -q '"enabled"' && echo yes || echo no)"

echo "=== the old inline form + standalone section are gone ==="
chk "no inline #userform"               no  "$(present 'id="userform"')"
chk "no inline #srform"                 no  "$(present 'id="srform"')"
chk "no standalone #srtable"            no  "$(present 'id="srtable"')"
chk "no old createUser()"               no  "$(present 'function createUser')"
chk "no old loadRoleAssignments()"      no  "$(present 'function loadRoleAssignments')"

echo "=== No window.confirm() anywhere — the browser can switch it off ==="
# ⚠️ THE REPORT: the prompt asks not to do it again, and ticking the checkbox leaves you
# no longer able to revoke any certs."
#
# That is the browser's own "prevent this page from creating additional dialogs". Ticked,
# window.confirm() returns FALSE for the rest of the page's life, so every
# `if (!confirm(...)) return;` becomes `return;` — the action silently does nothing.
#
# ⚠️ The suppression is per PAGE, not per dialog: ticking it on the delete-template prompt
# disables revoke too. So this asserts ZERO call sites remain, not "revoke was fixed".
# One survivor is enough to poison all the others again.
chk "no 'if (!confirm(' call site"      no  "$(present 'if (!confirm(')"
chk "no 'if (confirm(' call site"       no  "$(present 'if (confirm(')"
chk "no '&& !confirm(' call site"       no  "$(present '&& !confirm(')"
# ⚠️ AND window.alert() FOR THE SAME REASON — a rule that lived in a comment with
# nothing enforcing it, and was then broken by the AD-template import. The browser checkbox
# that suppresses confirm() suppresses alert() too, for the life of the page, and every
# alert() in this console carried an ERROR: suppression does not hide a dialog, it throws
# away the only explanation an operator gets.
#
# ⚠️ MATCHED ON A CALL WITH AN ARGUMENT, and that shape is the whole trick. The served page
# CONTAINS the comments that explain this rule, and they say "window.alert()" — so a check
# for the word matches its own documentation and can never pass. The first version of this
# assertion did exactly that, against a page with zero real calls left. Prose always writes
# the empty parens; a real call never does.
chk "no window.alert() call site"       0   "$(grep -cE 'alert\([^)]' index.html | tr -d ' ')"
# Anti-vacuity: notify() is what replaced them, so it has to be there — otherwise deleting
# the error reporting entirely would satisfy the assertion above.
chk "  and notify() is what reports instead" yes "$(present 'function notify(')"
chk "the in-page replacement exists"    yes "$(present 'function askConfirm(message, okLabel')"
chk "  it is a Promise, so it can be awaited" yes "$(present 'return new Promise(resolve =>')"
chk "  and has its own modal shell"     yes "$(present 'id="confirmmodal"')"
# Esc and the backdrop must mean NO — these gate destructive operations, so the ambiguous
# ways out have to resolve to the safe answer rather than falling through as "yes".
chk "  Escape resolves false"           yes "$(present "if (ev.key === 'Escape') finish(false);")"
chk "  clicking the backdrop resolves false" yes "$(present 'if (ev.target === modal) finish(false);')"
# Revocation is the one on the ticket; assert it by name so a future edit cannot quietly
# put window.confirm() back on exactly this path.
# Read from the function's own body: the prompt text depends on the reason (hold or revoke),
# so matching one literal message would pin the wording rather than the dialog.
chk "revoke() awaits the in-page dialog" yes \
    "$(sed -n '/^async function revoke(serial/,/^}/p' index.html | grep -qF 'if (!await askConfirm(' && echo yes || echo no)"

echo "=== No window.alert() either — the same checkbox kills it ==="
# alert() is suppressed by the identical browser setting. Every alert() in this console
# reported an ERROR ("revoke failed: HTTP 500", "failed to delete: x"), so suppression
# threw away the only explanation the operator gets — the button appears to do nothing,
# exactly that symptom. Assert ZERO call sites, same reasoning as above.
chk "no window.alert() call sites remain" 0 \
    "$(printf '%s' "$JS" | grep -o '[^k.]alert(' | wc -l | tr -d ' ')"
chk "the in-page replacement exists"      yes "$(present 'function notify(message, kind)')"
chk "  it has a host container"           yes "$(present 'id="toasts"')"
# Errors must NOT vanish on a timer: an operator who looked away still has to be able to
# read why the action failed. Only the info style auto-dismisses.
chk "  errors are sticky, info times out" yes "$(present 'if (!err) setTimeout(kill, 8000);')"
# Server error text is not ours — it must not be able to inject markup.
chk "  message text is set as textContent" yes "$(present "el.querySelector('.msg').textContent = String(message);")"

echo "=== The Source column is actually RENDERED, not just served ==="
# ⚠️ Added `source` to /api/users and the console never displayed it — a field with
# a writer and no reader. The column map at the top of the page listed it, but the
# subjects table builds its own <th> list and subjectRow() emits its own cells, so the
# map is not what an operator sees. Assert the TABLE, not the map.
chk "the subjects table has a Source header" yes \
    "$(present '<th>Source</th>')"
chk "  subjectRow emits a source cell"       yes \
    "$(present 'srcCell')"
chk "  and mergeSubjects carries it through" yes \
    "$(present 'source:u.source')"
# ⚠️ AND THE COUNTS MUST AGREE. `Scope` sat in the header with no matching <td>, so every
# value after Role rendered one column to the left — Must-reset under Scope, the gear
# under Must reset. A column list that is one longer than its row is invisible until
# someone reads a value off the wrong heading.
# ⚠️ SCOPED TO THE SUBJECTS ROW, because <th>Scope</th> is legitimate elsewhere — the
# role-permissions table is Permission/Scope. Asserting it globally failed on a correct
# table, which is a guard blaming the wrong code.
chk "the subjects header no longer carries a cell-less Scope" no \
    "$(grep -o "<th>Type</th>[^+]*" index.html 2>/dev/null | grep -q "Scope" && echo yes || echo no)"

echo "=== A machine account must READ as a computer, not just be tagged one ==="
# ⚠️ ALSO: the user table should say 'computer' instead of 'user' for computer accounts.
#
# ⚠️ WE REPORTED THIS DONE AND IT WAS NOT. The server half shipped — principal_kind()
# derives user|computer from the `$` suffix and the `/` of a service principal, and
# /api/users serialises it — but mergeSubjects() hardcoded `type:'user'` on every account
# row and the pill rendered o.type, so the field was computed, sent, and thrown away.
# A WRITER WITH NO READER, and the API-only assertion below would have passed the whole
# time. That is why both halves are asserted here: the contract AND the consumption.
curl -s -b admin.cj -X POST "$U/api/users" \
     -d 'create=1&username=labbox$&password=labboxpw12&role=requester' >/dev/null
USERS_JSON=$(curl -s -b admin.cj "$U/api/users")
chk "a \$-suffixed account is reported as kind=computer" yes \
    "$(printf '%s' "$USERS_JSON" | grep -q '"username":"labbox\$"[^}]*"kind":"computer"' && echo yes || echo no)"
chk "  and an ordinary account is still kind=user" yes \
    "$(printf '%s' "$USERS_JSON" | grep -q '"username":"alpha"[^}]*"kind":"user"' && echo yes || echo no)"
# The consumption half. The harness cannot run JS (§3e), so assert the two lines that
# carry the value from the payload to the cell — a grep proxy, but one that fails the
# moment either is reverted to the hardcoded form.
chk "mergeSubjects carries kind onto the row" yes \
    "$(grep -q "kind: u.kind || 'user'" index.html && echo yes || echo no)"
chk "  and the Type pill renders it" yes \
    "$(grep -q "esc(o.kind || o.type)" index.html && echo yes || echo no)"
# ⚠️ `type` MUST stay the selector. rolesFor('user', …) and the `o.type==='user' &&
# o.account` gates gate the edit modal, delete, role cell and source cell — relabelling
# type would silently strip a machine account of all four.
chk "  while type stays the subject_roles selector" yes \
    "$(grep -q "type:'user', kind: u.kind" index.html && echo yes || echo no)"

echo
echo "=== WEB USERS UI: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
