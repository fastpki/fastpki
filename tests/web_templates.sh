#!/usr/bin/env bash
# MS certificate templates — web console, and a template is
# a PERMISSIONED RESOURCE rather than something one named role owns wholesale.
#
# The `template-editor` role is gone — it only ever meant "holds template:use on
# everything", which is a grant. Its
# replacement is a custom role carrying `template:use` scoped to the templates it may touch,
# and that scoping is what this suite exists to prove.
#
# ⚠️ THE SCOPE WAS NEVER CHECKED before slice 4. path_allowed() answers with capability
# NAMES and permissions_for_roles() SELECTs DISTINCT permission, so scope never reached the
# gate: any template:use holder could edit, import over, or delete EVERY template. All three
# write paths are asserted here, because the import is the obvious way around a per-name
# grant and the delete is the destructive one.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18280
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

pg_setup web_templates
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
"$WEB" --config web.conf >web.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"

echo "=== bootstrap: an admin, a SCOPED template editor, and a requester ==="
chk "create admin -> 201" 201 "$(code -X POST "$U/api/users" -d 'username=boss&password=bosspw12&role=admin')"
curl -s -c boss.cj -X POST "$U/api/login" -d 'username=boss&password=bosspw12' >/dev/null
# `tpl-one` is what template-editor becomes: template:use on ONE template, plus self:manage
# so the /api/users narrowing below still has something to narrow.
pg_exec "INSERT INTO roles(name,description,builtin) VALUES('tpl-one','writes EdTpl only',false)
           ON CONFLICT DO NOTHING;
         INSERT INTO role_permissions(role,permission,scope) VALUES
           ('tpl-one','template:use','EdTpl'), ('tpl-one','template:edit','EdTpl'),('tpl-one','self:manage','*')
           ON CONFLICT DO NOTHING;" >/dev/null
chk "create scoped editor -> 201"  201 "$(code -b boss.cj -X POST "$U/api/users" -d 'username=ed&password=edpw12345&role=tpl-one')"
chk "create requester user -> 201" 201 "$(code -b boss.cj -X POST "$U/api/users" -d 'username=al&password=alpw123456&role=requester')"
curl -s -c ed.cj -X POST "$U/api/login" -d 'username=ed&password=edpw12345' >/dev/null
curl -s -c al.cj -X POST "$U/api/login" -d 'username=al&password=alpw123456' >/dev/null
chk "template-editor no longer exists as a role" 0 \
    "$(pg_exec "SELECT count(*) FROM roles WHERE name='template-editor';" | tr -d ' \r\n')"

echo "=== admin CRUD on templates ==="
# With no custom templates, the API lists the read-only built-in defaults that
# fastpki-ms actually serves, each flagged builtin:true.
chk "empty DB lists read-only built-ins" yes "$(has "$(curl -s -b boss.cj "$U/api/templates")" '"builtin":true')"
chk "create a template -> 200" 200 "$(code -b boss.cj -X POST "$U/api/templates" \
    --data-urlencode 'name=WebTpl' --data-urlencode 'oid=1.3.6.1.4.1.311.21.8.99.1' \
    --data-urlencode 'validity_days=365' --data-urlencode 'key_usage=0xA000' \
    --data-urlencode 'ekus=TLS Web Server Authentication' --data-urlencode 'enabled=true')"
chk "list now shows WebTpl" yes "$(has "$(curl -s -b boss.cj "$U/api/templates")" 'WebTpl')"
# The console sends flag/key-usage bitmaps as 0x.. hex (checkbox groups OR the bits);
# the API must parse them and echo the numeric value the JS then expands to
# "Digital Signature (0x8000) | Key Encipherment (0x2000)". 0xA000=40960.
chk "key_usage 0xA000 round-trips to 40960" yes "$(has "$(curl -s -b boss.cj "$U/api/templates")" '"key_usage":40960')"

echo "=== CSV import from the console ==="
printf 'name,oid,ekus\nImpA,1.3.6.1.4.1.311.21.8.99.10,TLS Web Server Authentication\nImpB,1.3.6.1.4.1.311.21.8.99.11,TLS Web Client Authentication\n' > imp.csv
R=$(curl -s -b boss.cj -X POST --data-binary @imp.csv "$U/api/templates/import")
chk "CSV import reports 2" yes "$(has "$R" '"imported":2')"
LIST=$(curl -s -b boss.cj "$U/api/templates")
chk "imported ImpA present" yes "$(has "$LIST" 'ImpA')"
chk "imported ImpB present" yes "$(has "$LIST" 'ImpB')"
# a malformed CSV is rejected
chk "CSV missing oid -> 400" 400 "$(printf 'name,oid\nX,\n' | code -b boss.cj -X POST --data-binary @- "$U/api/templates/import")"

# The downloadable CSV template must actually import.
#
# ⚠️ TAKEN OUT OF THE SERVED PAGE, NOT RETYPED HERE — and that is the whole point of this
# block. It used to be a copy pasted into this file, and the copy had already drifted: the
# console's button emitted a column this file's version did not have, so what was checked
# was that *a* CSV imports, not that *the shipped one* does. An operator downloading it and
# pasting it back is the only path this guards, and a second copy cannot see that path.
PAGE=$(curl -s -b boss.cj "$U/")
awk '/const csv = \[/,/\]\.join/' <<<"$PAGE" | sed -n "s/^ *'\(.*\)',\{0,1\}\$/\1/p" > tmpl.csv
# ⚠️ FIXTURE FIRST. If the extraction missed, the import below gets an empty body, the
# server says so, and a bare "did it import" assertion would report a product failure for
# what is really this awk not matching any more.
chk "fixture: the console's CSV template was extracted" yes \
    "$(grep -q '^name,oid,schema' tmpl.csv && echo yes || echo no)"
# ⚠️ AND THE COLUMN SET IS COMPARED, not just "it parsed". A CSV missing a column still
# imports cleanly — every column is optional — so importing successfully proves nothing
# about completeness. The header the parser publishes is the contract; the button must
# offer exactly it. Sorted, because the two orders legitimately differ.
LIBHDR=$(awk '/std::string ms_templates_csv_header/,/^}/' "$ROOT/src/lib/ms_template.cpp" \
         | grep -o '"[^"]*"' | tr -d '"\n')
CONHDR=$(grep -m1 '^name,oid,schema' tmpl.csv)
cols(){ printf '%s' "$1" | tr ',' '\n' | sort | tr '\n' ' '; }
chk "fixture: the parser's published header was read from source" yes \
    "$(printf '%s' "$LIBHDR" | grep -q '^name,oid,' && echo yes || echo no)"
chk "the console offers exactly the columns the parser publishes" "$(cols "$LIBHDR")" "$(cols "$CONHDR")"
RT=$(curl -s -b boss.cj -X POST --data-binary @tmpl.csv "$U/api/templates/import")
chk "downloadable template imports 2" yes "$(has "$RT" '"imported":2')"
LT=$(curl -s -b boss.cj "$U/api/templates")
chk "template row FastKPIWebServer present" yes "$(has "$LT" 'FastKPIWebServer')"
chk "pipe-separated ekus parsed (client EKU present)" yes "$(has "$LT" '1.3.6.1.4.1.311.10.3.4')"
# The renewal overlap makes the whole round trip — CSV cell, parser, DB column, JSON — and
# the two rows carry DIFFERENT values on purpose, so a reader that returns a constant
# (or the struct default for both) cannot pass.
tplfield(){ printf '%s' "$LT" | tr '{' '\n' | grep "\"name\":\"$1\"" | grep -o "\"$2\":-\{0,1\}[0-9]*" | head -1 | sed 's/.*://'; }
chk "a configured overlap survives the import" 3628800 "$(tplfield FastKPIUser overlap_seconds)"
chk "  and a blank one stays 'derive'"         -1      "$(tplfield FastKPIWebServer overlap_seconds)"

echo "=== a disabled template stays listed, editable and in the backup ==="
# The list read enabled rows only, so a template saved disabled — which "+ New template"
# did by default — vanished from the page, from templates-list and from the backup.
chk "disable WebTpl -> 200" 200 "$(code -b boss.cj -X POST "$U/api/templates" \
    --data-urlencode 'name=WebTpl' --data-urlencode 'oid=1.3.6.1.4.1.311.21.8.99.1' --data-urlencode 'enabled=false')"
LD=$(curl -s -b boss.cj "$U/api/templates")
chk "  it is still listed, as disabled" yes \
    "$(printf '%s' "$LD" | tr '{' '\n' | grep '"name":"WebTpl"' | grep -q '"enabled":false' && echo yes || echo no)"
chk "  and its fields survived the save (validity 365, not the default)" 365 "$(printf '%s' "$LD" | tr '{' '\n' | grep '"name":"WebTpl"' | grep -o '"validity_days":[0-9]*' | sed 's/.*://')"
chk "  and the config backup carries it" yes \
    "$(curl -s -b boss.cj "$U/api/backup" | grep -q '"WebTpl"' && echo yes || echo no)"
# An empty text field clears the stored value; the form sends it rather than leaving it out.
code -b boss.cj -X POST "$U/api/templates" --data-urlencode 'name=WebTpl' \
    --data-urlencode 'oid=1.3.6.1.4.1.311.21.8.99.1' --data-urlencode 'ekus=' >/dev/null
chk "an empty EKU field clears the EKUs" '"ekus":[]' \
    "$(curl -s -b boss.cj "$U/api/templates" | tr '{' '\n' | grep '"name":"WebTpl"' | grep -o '"ekus":\[\]')"
# -1 is "not specified" and must stay that; the top flag bit must survive as a value.
code -b boss.cj -X POST "$U/api/templates" --data-urlencode 'name=WebTpl' --data-urlencode 'oid=1.3.6.1.4.1.311.21.8.99.1' \
    --data-urlencode 'enrollment_flags=-1' --data-urlencode 'subject_name_flags=0x80000001' >/dev/null
LF=$(curl -s -b boss.cj "$U/api/templates" | tr '{' '\n' | grep '"name":"WebTpl"')
chk "an absent flag field saves as absent (-1)" yes "$(has "$LF" '"enrollment_flags":-1')"
chk "the top subject-name bit round-trips" yes "$(printf '%s' "$LF" | grep -qE '"subject_name_flags":(-2147483647|2147483649)' && echo yes || echo no)"
PAGE=$(curl -s -b boss.cj "$U/")
chk "the editor starts a new template from the defaults, enabled" yes \
    "$(printf '%s' "$PAGE" | grep -q "setForm(TPL_NEW, false)" && printf '%s' "$PAGE" | grep -q 'enabled:true };' && echo yes || echo no)"
chk "the editor locks Name on an edit" yes "$(printf '%s' "$PAGE" | grep -q 'f.elements.name.readOnly = !!editing' && echo yes || echo no)"
chk "the hash list uses the stored spelling (sha256)" yes "$(printf '%s' "$PAGE" | grep -q "\['sha256','2.16.840.1.101.3.4.2.1'\]" && echo yes || echo no)"

echo "=== delete ==="
chk "delete WebTpl -> 200" 200 "$(code -b boss.cj -X DELETE "$U/api/templates/WebTpl")"
chk "WebTpl is gone" no "$(has "$(curl -s -b boss.cj "$U/api/templates")" 'WebTpl')"

echo "=== ⚠️ THE SCOPE: template:use|EdTpl writes EdTpl and NOTHING else ==="
chk "editor can list templates"  200 "$(code -b ed.cj "$U/api/templates")"
chk "editor writes the template it is scoped to" 200 \
    "$(code -b ed.cj -X POST "$U/api/templates" --data-urlencode 'name=EdTpl' --data-urlencode 'oid=1.3.6.1.4.1.311.21.8.99.2')"
# The one that used to pass. Same verb, same role, a name outside the grant.
chk "  but NOT one outside its scope (403)" 403 \
    "$(code -b ed.cj -X POST "$U/api/templates" --data-urlencode 'name=OtherTpl' --data-urlencode 'oid=1.3.6.1.4.1.311.21.8.99.7')"
chk "  and nothing was written"  no \
    "$(has "$(curl -s -b boss.cj "$U/api/templates")" 'OtherTpl')"
# A bulk import is how you would drive around a per-name grant, so it checks every row
# BEFORE writing any of them.
chk "  a CSV import outside its scope is refused (403)" 403 \
    "$(code -b ed.cj -X POST "$U/api/templates/import" --data-binary 'name,oid
Imported,1.3.6.1.4.1.311.21.8.99.8')"
chk "  and imported nothing"     no \
    "$(has "$(curl -s -b boss.cj "$U/api/templates")" 'Imported')"
# …and the destructive one.
chk "  deleting outside its scope is refused (403)" 403 \
    "$(code -b ed.cj -X DELETE "$U/api/templates/GenericUser")"
chk "  deleting its OWN template is allowed"        200 \
    "$(code -b ed.cj -X DELETE "$U/api/templates/EdTpl")"
# ⚠️ THE CONTROL. Every refusal above would also fire if `ed` simply could not reach the
# route at all, which is a different bug wearing the same status code.
chk "CONTROL: admin CAN write the name ed was refused" 200 \
    "$(code -b boss.cj -X POST "$U/api/templates" --data-urlencode 'name=OtherTpl' --data-urlencode 'oid=1.3.6.1.4.1.311.21.8.99.7')"
# The role holds self:manage, so /api/users is reachable — narrowed by the
# handler to the editor's own row. "Nothing else" now means "nobody else": assert the
# BODY, since the status code alone can no longer tell the two outcomes apart.
chk "editor reaches /api/users (200)"       200 "$(code -b ed.cj "$U/api/users")"
chk "  but sees only themselves"            "ed" \
    "$(curl -s -b ed.cj "$U/api/users" | grep -o '"username":"[^"]*"' | sed 's/.*:"//; s/"$//' | tr '\n' ' ' | sed 's/ $//')"
chk "editor CANNOT reach /api/subject-roles (403)" 403 "$(code -b ed.cj "$U/api/subject-roles")"
chk "editor CANNOT reach /api/certs (403)"  403 "$(code -b ed.cj "$U/api/certs")"

echo "=== the shared search box filters THIS page, not the inventory ==="
# The topbar search is one control shared by every page. render() bails out on any tab
# with no column set, so on the template list typing filtered nothing at all while the
# placeholder still advertised certificates — the box looked like it belonged elsewhere.
#
# ⚠️ MATCHED ON CODE, NOT ON PROSE. The served page carries the source comments that
# explain this, so grepping for a phrase like "search" or "template names" would match the
# explanation whether or not the wiring exists. Every pattern below is an expression.
curl -s -b boss.cj "$U/" -o page.html
pg(){ grep -qF -- "$1" page.html && echo yes || echo no; }
chk "the search box repaints the template list" yes "$(pg "if (tab === 'templates') return renderTemplates();")"
chk "  and the list filters on the name"        yes "$(pg "(t.name || '').toLowerCase().includes(q)")"
chk "  on the OID"                              yes "$(pg "(t.oid  || '').toLowerCase().includes(q)")"
chk "  and on the EKUs"                         yes "$(pg "(t.ekus || []).some(e => (e || '').toLowerCase().includes(q))")"
# The row count has to follow the filter, or a filtered page still claims the full total.
chk "the count reports the filtered subset"     yes "$(pg "shown.length + ' of ' + list.length")"
# ⚠️ The detail view resolves a template by NAME out of TPLS. Filtering that would break
# "details" on the very row the operator just searched for, so the full set is kept.
chk "the detail lookup keeps the FULL set"      yes "$(pg 'window.TPLS = list;')"
# The placeholder moved into the one table that decides which pages get a search box at
# all, so the wording lives there now. What it pins is unchanged: this page's box must
# name TEMPLATES — reading "Search certs…" here is what made it look like the inventory's.
chk "the placeholder names templates"           yes "$(pg "  templates:  'Search templates")"
# Anti-vacuity: if the page had not been fetched at all, every check above would read 'no'
# and this suite would report a clean failure rather than a silent one.
chk "  fixture: the console page was served"    yes "$(pg 'data-tab="templates"')"

echo "=== the list carries the same controls as every other list page ==="
# A checkbox on the left of each row, one bulk-delete button at the top, a gear to edit,
# and the row itself opens the detail view — the shape the subjects, roles, profiles and
# domains lists use. Three per-row buttons (details / edit / delete) went with it.
#
# ⚠️ EXPRESSIONS ONLY, for the reason stated above: the served page carries these comments.
chk "each row carries a selection checkbox"     yes "$(pg "'<input type=\"checkbox\" data-sel=\"'+esc(t.name)+'\"'")"
chk "the header carries a select-all"           yes "$(pg "id=\"tplall\"")"
chk "the toolbar carries one bulk delete"       yes "$(pg "Delete selected ('+tplSel.size+')")"
chk "the edit control is the shared gear"       yes "$(pg "<button class=\"gearbtn\" data-edit=\"'+esc(t.name)+'\" title=\"Edit\">")"
# ⚠️ THE ABSENCES ARE THE ASK, AND AN ABSENCE ASSERTION IS ONLY WORTH ANYTHING IF THE
# PATTERN USED TO BE PRESENT. Both of these were checked against the previous revision of
# the console and matched it exactly once; the first version of this block wrapped the
# delete pattern in a leading `'<button ` that had never appeared in the old markup either,
# so it would have passed for ever without testing anything. `data-view` was the per-row
# "details" button and no other page ever used the attribute, so its disappearance from the
# whole document is an exact fact rather than a guess about which page a hit belongs to.
chk "the per-row details button is gone"        no  "$(pg 'data-view=')"
chk "the per-row delete button is gone"         no  "$(pg "data-del=\"'+esc(t.name)+'\"")"
# The gesture that replaced it, and the guard that keeps it from firing on the controls
# that sit inside the same row.
chk "a row click opens the detail view"         yes "$(pg "showTplDetail(shown[+tr.dataset.row].name)")"
chk "  but not when the click was a control"    yes "$(pg "if (e.target.closest('input, button')) return;")"
chk "the detail view is a modal, not an inline pane" yes "$(pg "document.querySelector('#tpldetmodal .card')")"
chk "  rendered as the same grid the cert detail uses" yes "$(pg '<dl class="kvdl">')"

echo "=== the directory import is a picker, not an all-or-nothing button ==="
# The apply posts NAMES, and the server re-reads the directory to get the bodies. Posting
# template content back would let anyone who can reach the route write a template of their
# own composition under the name of an import.
chk "the apply posts the ticked names"          yes "$(pg "sel.forEach(n => body.append('name', n));")"
# ⚠️ NOTHING TICKED TO BEGIN WITH. Defaulting to all-selected puts the old bulk import one
# click away, which is the behaviour the picker exists to replace.
chk "  and nothing starts ticked"               yes "$(pg 'const sel = new Set();')"
chk "  the Import button is dead until one is" yes "$(pg "(sel.size?'':' disabled')")"
chk "a row that would be overwritten says so"   yes "$(pg "have.has(t.name) ? '<span class=\"pill flag\">overwrites</span>'")"
# The picker scrolls vertically only — a modal that scrolls sideways to reach a checkbox is
# the complaint this fixes — and the EKU cell wraps rather than forcing that width.
chk "the picker scrolls vertically only"        yes "$(pg 'overflow-y:auto;overflow-x:hidden')"
# ⚠️ THE PICKER MUST BE IN THE WIDE LIST, and this is the assertion that would have caught
# the original complaint. `.card.wide2` re-columns a form grid and widens nothing, so a
# modal absent from this rule silently renders at the 520px base — which is what made a
# multi-column table unreadable and what "its width should be larger" was about.
# The rule is ONE multi-line selector list that every new detail view is appended to, so
# matching the whole line breaks the next time another page gains one. Ask the only
# question that matters instead: does this id sit in a block whose declaration is the wide
# max-width? `[^{}]*` cannot cross a rule boundary, so a hit is this rule and no other.
tr '\n' ' ' < page.html > page.flat
widemodal(){ grep -qE "#$1 > \.card[^{}]*\{max-width:1100px;\}" page.flat && echo yes || echo no; }
chk "the picker modal is widened, not left at the base" yes "$(widemodal tpladmodal)"
chk "  and so is the detail view it sits beside"        yes "$(widemodal tpldetmodal)"
# The OID column is the widest and the least useful for choosing; an operator picks by
# name. Asserted as the picker's OWN header, positively — the first version of this checked
# for the ABSENCE of `<th>Name</th><th>OID</th>`, which also matches the main Templates
# table, where an OID column is entirely correct. It failed for the right reason and would
# have been impossible to satisfy without breaking the other table.
chk "the picker shows name, schema and version" yes \
    "$(pg "'<th>Name</th><th>Schema</th><th>Version</th><th></th>'")"
chk "  and the EKU cell wraps"                  yes "$(pg 'word-break:break-word')"
# ⚠️ TICKING A BOX MUST NOT REBUILD THE CARD. Rebuilding resets the scroll position, so
# every choice below the fold threw the operator back to the top. The handler updates the
# count in place instead; `sync()` existing at all is what distinguishes the two.
chk "ticking updates in place, not by redraw"   yes "$(pg 'cb.checked ? sel.add(n) : sel.delete(n); sync();')"

echo "=== RBAC: other roles cannot touch templates ==="
chk "requester GET /api/templates -> 403"  403 "$(code -b al.cj "$U/api/templates")"
chk "requester POST /api/templates -> 403" 403 "$(code -b al.cj -X POST "$U/api/templates" --data-urlencode 'name=Nope' --data-urlencode 'oid=1.2.3')"

echo
echo "=== WEB TEMPLATES: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
