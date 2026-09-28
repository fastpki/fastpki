#!/usr/bin/env bash
# Users and Computers as two pages, groups first, with the members of the selected group
# beside them and the subjects that belong to no group last.
#
# THE PROBLEM. One table called "Users" held people, machines, directory groups and DN
# grants together. The name stopped being true the day machine accounts arrived, and in a
# company of any size the table grows past being readable — "which of these is a person?"
# and "who does this group actually grant access to?" both required scrolling and guessing.
#
# ⚠️ THE PARTITION IS NOT RE-DERIVED IN THE PAGE. Which side a subject belongs on comes
# from `kind` on the row, computed once by pki::principal_kind(). A second copy of that rule
# in JavaScript would be a second answer to "is this a person?", and this console has
# already shipped a bug of exactly that shape. So the strongest thing this suite can assert
# from shell is the CONTRACT the page depends on: that the API says `computer` for a machine
# and `user` for a person. If that ever regresses, the pages silently sort people into the
# wrong one, and nothing else here would notice.
#
# ⚠️ AND WHY THE MARKUP CHECKS ARE SHAPED THE WAY THEY ARE. The served page carries this
# file's sibling comments in web/main.cpp, so a grep for a PHRASE matches the prose that
# explains the feature rather than the code that implements it — the console has produced
# that exact false pass before. Every assertion below matches either real markup
# (`data-tab="computers"`) or a code expression prose cannot contain.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
WEB="${FASTPKI_BUILD:-$ROOT/build}/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18303
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
present(){ grep -qF -- "$1" index.html && echo yes || echo no; }

[ -x "$WEB" ] || { echo "SKIP: no fastpki-web built"; exit 0; }
if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi

pg_setup web_subject_pages
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
# A person and a machine. The trailing '$' is what makes the second one a computer, and it
# is the SERVER that decides that — this suite only checks it still says so.
seed_web_user padmin padminpw12345 admin
seed_web_user 'WS01$' machinepw12345 requester
"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; tail -20 web.log; echo "RESULT: FAIL"; exit 1; }
JAR="$W/c.jar"
curl -s -c "$JAR" -o /dev/null -X POST "http://127.0.0.1:$PORT/api/login" -d 'username=padmin&password=padminpw12345'
curl -s -b "$JAR" "http://127.0.0.1:$PORT/" -o index.html
U="$(curl -s -b "$JAR" "http://127.0.0.1:$PORT/api/users")"

echo "=== the contract the split rests on: the SERVER classifies the subject ==="
kindof(){ printf '%s' "$U" | tr '{' '\n' | grep -F "\"username\":\"$1\"" | sed -n 's/.*"kind":"\([a-z]*\)".*/\1/p'; }
chk "a person is reported as a user"      user     "$(kindof 'padmin')"
chk "a machine account is a computer"     computer "$(kindof 'WS01$')"
# Anti-vacuity: if the response were empty both lookups would return '' and the two
# assertions above would be comparing nothing to nothing.
chk "  and both rows are actually there"  2 \
    "$(printf '%s' "$U" | grep -o '"username"' | wc -l | tr -d ' ')"

echo "=== two pages, not one table ==="
chk "the Users tab is still there"        yes "$(present 'data-tab="users"')"
chk "a Computers tab exists"              yes "$(present 'data-tab="computers"')"
# Both tabs must load the subject data; a tab that renders nothing is worse than no tab.
chk "both tabs drive the subject loader"  yes "$(present "SUBJECT_TABS = ['users', 'computers']")"

echo "=== groups first, members beside them ==="
chk "the two-pane renderer exists"        yes "$(present 'function subjectPanes(')"
chk "the left pane lists groups"          yes "$(present 'filter(x => subjIsGroup(x.o))')"

# A group row carries the same two controls every other subject row has. It had neither, so
# a group added from the console could only be removed by editing the database.
# ⚠️ Both address the row by its rowsView INDEX, exactly like the member pane — a left pane
# that renumbered would wire the delete checkbox to somebody else's subject.
chk "group rows carry the rowsView index" yes "$(present 'groupsIdx.map(x => {')"
chk "a group row has a delete checkbox"   yes "$(present 'userSel.has(subjKey(g))')"
# ⚠️ Matched on the entity the GROUP pane emits, not on `gearbtn data-idx`: the member rows
# carry that too, so it would pass whether or not the group row ever grew one.
chk "a group row has an edit gear"        yes "$(present '&#9881;</button>')"
# The row's own click selects the group; without this the checkbox would also swing the
# member pane onto the group being deleted.
chk "clicking a control does not select"  yes "$(present "e.target.closest('input, button')")"
chk "selecting a group drives the right pane" yes "$(present 'GROUPSEL = tr.dataset.grp')"
chk "the right pane is the members of it" yes "$(present 'subjVia(x.o).includes(GROUPSEL)')"

echo "=== ⚠️ the member pane must address rows by their ORIGINAL index ==="
# Every gear and every delete checkbox is wired by index INTO rowsView. A pane that
# renumbered its rows would point them at other people's subjects — silently, and worst on
# the destructive one. This is the assertion that would catch that.
chk "members carry the rowsView index"    yes "$(present 'subjectRow(x.o, x.i, canWrite)')"

echo "=== a group appears where it actually reaches somebody ==="
# First shape of this screen put EVERY group on BOTH pages, which showed user groups on
# Computers with an empty member list — a row that can only be read as broken. A group
# holding both people and machines still appears on both; that is the case worth keeping.
chk "the page decides per group, not per kind" yes "$(present 'subjIsGroup(o) ? groupOnPage(o) : subjKind(o) === wantKind')"
chk "a group shows where it has that kind"     yes "$(present 'groupHasKind(g.name, wantKind)')"
# ⚠️ THE ZERO-MEMBER CASE IS THE ONE THAT MATTERS. Hiding a group that reaches nobody would
# leave no row to select, edit or delete — a grant nobody can see is a grant nobody can
# remove. It is also exactly what a directory whose search base misses its members produces,
# and that has to stay visible rather than vanish off the page the operator is looking at.
chk "a group reaching nobody stays on both"    yes \
    "$(present 'subjVia(o).includes(g.name))')"

echo "=== and the ungrouped subjects come last ==="
chk "the bottom table excludes grouped rows" yes "$(present 'subjVia(o).length || subjIsGroup(o)')"

kill $P 2>/dev/null; wait $P 2>/dev/null
echo
echo "=== WEB SUBJECT PAGES: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
