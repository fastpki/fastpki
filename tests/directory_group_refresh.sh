#!/usr/bin/env bash
# The member list of a granted directory group is STORED, refreshed on a timer, and
# refreshable per group from the console.
#
# The scope is repopulating membership, and it is not session revocation:
#
#   a group can be updated, so the stored member list has to be repopulated from the
#   directory. Someone who has already logged in but was removed at that same moment
#   keeps access until they log in again, and that is acceptable. So the member list of
#   every granted group is refreshed from time to time, 12h by default, and can also be
#   refreshed manually from the UI for one specific group.
#
# So `web_sessions` is untouched; what this suite measures is the store, its two refresh
# paths, and the three states it has to keep apart:
#
#   never resolved   no directory_groups row      -> "membership not resolved yet"
#   resolved, empty  refreshed > 0, 0 members     -> the group really has nobody in it
#   refresh refused  attempted > 0, err set       -> the PREVIOUS members are still true
#
# ⚠️ THE ASSERTION THAT MATTERS MOST IS THE FAILURE ONE (section 6). Collapsing a refused
# search into "0 members" is the lie told about a group instead of a search, and it is
# the one way this feature could make things worse than the live-search it replaces: a
# directory blip would empty every group at once. `ldap_group_members` reports a refusal
# through its error out-param — including the subtle case where it DID answer from one URI
# and was refused on another, so the list it returned is SHORT — and the writer only
# replaces the stored rows when that string is empty.
#
# Without the fix this suite cannot pass at all: there is no directory_groups table, no
# refresh endpoint, and /api/directory-subjects searched the directory live on every call
# (so section 5 — "the stored list does not move until something refreshes it" — measures
# the change itself).
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
# FASTPKI_BUILD names the build directory to test: LDAP is an OPTIONAL cmake feature and a
# tree's default build/ may have FASTPKI_WITH_LDAP=OFF, in which case fastpki-web cannot
# talk to a directory at all and this suite has nothing to measure.
BUILD="${FASTPKI_BUILD:-$ROOT/build}"
WEB="$BUILD/fastpki-web"
SLAPD=""
for c in "$(command -v slapd 2>/dev/null)" /usr/sbin/slapd /usr/local/libexec/slapd \
         /opt/homebrew/opt/openldap/libexec/slapd /usr/local/opt/openldap/libexec/slapd; do
  [ -n "$c" ] && [ -x "$c" ] && { SLAPD="$c"; break; }
done
[ -n "$SLAPD" ] || { echo "SKIP: openldap (slapd) not installed"; exit 0; }
case "$SLAPD" in */libexec/slapd) PATH="${SLAPD%/libexec/slapd}/bin:${SLAPD%/libexec/slapd}/sbin:$PATH"; export PATH;; esac
command -v ldapadd >/dev/null 2>&1 || { echo "SKIP: ldap-utils not installed"; exit 0; }
# `ldd` does not exist on macOS; asking neither would make an LDAP-less build look like a
# product failure rather than a build without the feature.
linked_ldap(){ { ldd "$1" 2>/dev/null || otool -L "$1" 2>/dev/null; } | grep -qiE "libldap|LDAP\.framework"; }
linked_ldap "$WEB" || { echo "SKIP: $WEB built without FASTPKI_WITH_LDAP"; exit 0; }
SCH=""
for d in /etc/ldap/schema /etc/openldap/schema \
         /opt/homebrew/etc/openldap/schema /usr/local/etc/openldap/schema; do
  [ -d "$d" ] && SCH="$d"
done
[ -n "$SCH" ] || { echo "SKIP: openldap schema dir not found"; exit 0; }
MODP=""; for d in /usr/lib/ldap /usr/lib/openldap /usr/lib/x86_64-linux-gnu/openldap \
                  /opt/homebrew/opt/openldap/libexec/openldap; do
  [ -e "$d/back_mdb.so" ] && MODP="$d"
done

W="$(mktemp -d)"; cd "$W"; LPORT=13891; WPORT=18471
# ⚠️ ONE trap for every child: bash EXIT traps DO NOT STACK, the second replaces the first.
# A second `trap ... EXIT` here would silently drop slapd from the cleanup and leak a
# listening directory server, which makes the NEXT run fail at "slapd failed to start".
LP=""; P=""
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

echo "=== 1. a throwaway directory: PKI-Team = alice + bob ==="
mkdir -p ldap/data
cat > slapd.conf <<EOF
include $SCH/core.schema
include $SCH/cosine.schema
include $SCH/inetorgperson.schema
${MODP:+modulepath $MODP}
${MODP:+moduleload back_mdb}
pidfile $W/ldap/slapd.pid
argsfile $W/ldap/slapd.args
database mdb
maxsize 33554432
suffix "dc=fastpki,dc=test"
rootdn "cn=admin,dc=fastpki,dc=test"
rootpw adminpass
directory $W/ldap/data
EOF
LURI="ldap://127.0.0.1:$LPORT"
# ⚠️ POLL, DO NOT SLEEP AT IT. `sleep 1` held only while suites ran one at a time. Under
# six parallel shards slapd had not finished binding and loading its LDIF, so every search
# returned nothing and this suite failed with "the directory holds PKI-Team with 2 members:
# expected 2 got 0" — which reads as a broken group importer rather than a directory that
# was still starting. wait_ldap (pg_helpers.sh) also returns the moment slapd DIES, so a
# genuine startup failure is reported in a fraction of a second.
start_slapd(){ "$SLAPD" -h "$LURI/" -f slapd.conf -d 0 >>slapd.log 2>&1 & LP=$!
               wait_ldap "$LP" "$LURI" || { echo "slapd did not come up:"; tail -20 slapd.log; return 1; }; }
# ⚠️ Armed BEFORE the first child is backgrounded. It used to be installed on the line
# AFTER start_slapd, so an interrupt in that window left a directory server listening on
# 13891 — and the NEXT run then failed at "slapd failed to start" with an empty log, which
# reads as a product failure.
trap 'kill $P $LP 2>/dev/null; pg_cleanup' EXIT
start_slapd
if ! kill -0 $LP 2>/dev/null; then echo "slapd failed to start:"; cat slapd.log; exit 1; fi
ldapadd -x -H "$LURI" -D "cn=admin,dc=fastpki,dc=test" -w adminpass >add.log 2>&1 <<'LDIF'
dn: dc=fastpki,dc=test
objectClass: top
objectClass: dcObject
objectClass: organization
o: FastPKI Test
dc: fastpki

dn: cn=alice,dc=fastpki,dc=test
objectClass: inetOrgPerson
cn: alice
sn: Alice
mail: alice@directory.test
userPassword: alicepass

dn: cn=bob,dc=fastpki,dc=test
objectClass: inetOrgPerson
cn: bob
sn: Bob
userPassword: bobpass

dn: cn=carol,dc=fastpki,dc=test
objectClass: inetOrgPerson
cn: carol
sn: Carol
userPassword: carolpass

dn: cn=PKI-Team,dc=fastpki,dc=test
objectClass: groupOfNames
cn: PKI-Team
member: cn=alice,dc=fastpki,dc=test
member: cn=bob,dc=fastpki,dc=test
LDIF
chk "PRECONDITION: the directory holds PKI-Team with 2 members" 2 \
    "$(ldapsearch -x -LLL -H "$LURI" -b 'dc=fastpki,dc=test' '(cn=PKI-Team)' member 2>/dev/null \
       | grep -c '^member:')"

pg_setup dir_group_refresh
# ⚠️ THE DIRECTORY IS A ROW, AND THE CONF NO LONGER MENTIONS IT AT ALL. Leaving the LDAP_*
# keys in a fixture after the reader stopped consulting them masks bugs: the console gated
# its directory endpoints on cfg.ldap_uris, and the fixture kept satisfying that gate with
# a value nothing else read. This row is the only thing that makes a directory exist.
# Group selectors are provider-qualified: a grant names the directory it belongs to, so
# another directory's identically-named group is a different selector entirely.
Q_PKI_TEAM='default\PKI-Team'; Q_GHOST_TEAM='default\Ghost-Team'
Q_DARK_TEAM='default\Dark-Team'; Q_NOT_GRANTED='default\Not-Granted'
seed_ldap_provider default "$LURI" "dc=fastpki,dc=test" || {
    echo "cannot seed the directory — the assertions below would measure a deployment"
    echo "with no directories at all."; exit 1; }
mkconf(){ # $1 = DIRECTORY_GROUP_REFRESH_SEC, or "" to leave the key OUT of bootstrap.conf (§10)
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$WPORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
[ -n "${1:-}" ] && printf 'DIRECTORY_GROUP_REFRESH_SEC=%s\n' "$1" >> bootstrap.conf
return 0
}
start_web(){ "$WEB" --config bootstrap.conf >>web.log 2>&1 & P=$!; sleep 1; }
stop_web(){ kill $P 2>/dev/null; wait $P 2>/dev/null; P=""; }
U="http://127.0.0.1:$WPORT"

# The sweep is OFF for sections 2-6: every change to the store there must be the result of
# an action under test, not of a timer that could have fired at any moment.
mkconf 0
start_web
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
seed_web_user boss bosspw12 admin
curl -s -c boss.cj -X POST "$U/api/login" -d 'username=boss&password=bosspw12' >/dev/null
API(){ curl -s -b boss.cj "$@"; }

echo "=== 2. granting a role to a group resolves it THERE AND THEN ==="
# "if a grant names a group the lookup returns nothing for, saying so
# explicitly would have caught the Domain Users primary-group problem at the moment
# the grant was created." So the POST answers with what the directory said.
GR=$(API -X POST "$U/api/subject-roles" -d 'selector_type=group&selector_value=default%5CPKI-Team&role=requester')
chk "the grant reports the directory resolved it" yes \
    "$(printf '%s' "$GR" | grep -q '"resolved":true' && echo yes || echo no)"
chk "  and names the member count it found"       yes \
    "$(printf '%s' "$GR" | grep -q '"members":2' && echo yes || echo no)"
chk "the members are STORED, not just reported" 2 \
    "$(pg_exec "SELECT count(*) FROM directory_group_members WHERE grp='$Q_PKI_TEAM';" | tr -d ' ')"
chk "  and the group carries a successful refresh stamp" yes \
    "$(pg_exec "SELECT refreshed > 0 AND err = '' FROM directory_groups WHERE grp='$Q_PKI_TEAM';" \
       | tr -d ' ' | grep -q '^t$' && echo yes || echo no)"

echo "=== 3. the Subjects tab reads the store ==="
DS=$(API "$U/api/directory-subjects")
chk "alice is listed via PKI-Team" yes \
    "$(printf '%s' "$DS" | tr '{' '\n' | grep '"username":"alice"' | grep -q '"via":"default\\\\PKI-Team"' && echo yes || echo no)"
chk "  and bob"                    yes \
    "$(printf '%s' "$DS" | tr '{' '\n' | grep '"username":"bob"' | grep -q '"via":"default\\\\PKI-Team"' && echo yes || echo no)"
chk "  and NOT carol, who is not in the group" no \
    "$(printf '%s' "$DS" | grep -q '"username":"carol"' && echo yes || echo no)"
chk "the per-group state says 2 members" yes \
    "$(printf '%s' "$DS" | tr '{' '\n' | grep '"name":"default\\\\PKI-Team"' | grep -q '"members":2' && echo yes || echo no)"
chk "  with a refresh timestamp the console can date it by" no \
    "$(printf '%s' "$DS" | tr '{' '\n' | grep '"name":"default\\\\PKI-Team"' | grep -q '"refreshed":0' && echo yes || echo no)"

echo "=== 4. ⚠️ RESOLVED-AND-EMPTY is a real answer, and it is not a failure ==="
# A grant that arrived without going through this console — replicated in from a peer DC,
# or written by SQL as here — has no stored membership yet. The console has to be able to
# say that, because "0 members" is a claim about the directory it has not earned.
pg_exec "INSERT INTO subject_roles(selector_type,selector_value,role)
         VALUES('group','$Q_GHOST_TEAM','requester') ON CONFLICT DO NOTHING;" >/dev/null
DS=$(API "$U/api/directory-subjects")
chk "a granted group the directory lacks still appears in the group list" yes \
    "$(printf '%s' "$DS" | grep -q '"name":"default\\\\Ghost-Team"' && echo yes || echo no)"
# ⚠️ RESOLVED, not unresolved. The lazy first fill asks the directory on this very read,
# the search SUCCEEDS, and it finds no such group — so the honest record is "we asked, the
# answer was nobody", with a timestamp and no error. That is a different fact from "we have
# not asked" and from "we asked and were refused"; section 6 covers the third.
chk "  it is RESOLVED (the search worked), not left unresolved" no \
    "$(printf '%s' "$DS" | tr '{' '\n' | grep '"name":"default\\\\Ghost-Team"' | grep -q '"refreshed":0' && echo yes || echo no)"
chk "  with no error recorded, because nothing failed" yes \
    "$(pg_exec "SELECT err = '' FROM directory_groups WHERE grp='$Q_GHOST_TEAM';" \
       | tr -d ' ' | grep -q '^t$' && echo yes || echo no)"
chk "  and no member rows invented for it" 0 \
    "$(pg_exec "SELECT count(*) FROM directory_group_members WHERE grp='$Q_GHOST_TEAM';" | tr -d ' ')"

echo "=== 5. a directory change is NOT picked up until something refreshes ==="
# This is the change itself: the endpoint used to search the directory on every request.
ldapmodify -x -H "$LURI" -D "cn=admin,dc=fastpki,dc=test" -w adminpass >>add.log 2>&1 <<'LDIF'
dn: cn=PKI-Team,dc=fastpki,dc=test
changetype: modify
add: member
member: cn=carol,dc=fastpki,dc=test
LDIF
chk "PRECONDITION: carol really is in the group now" 3 \
    "$(ldapsearch -x -LLL -H "$LURI" -b 'dc=fastpki,dc=test' '(cn=PKI-Team)' member 2>/dev/null \
       | grep -c '^member:')"
DS=$(API "$U/api/directory-subjects")
chk "the stored list still says 2 — it is a store, not a live search" yes \
    "$(printf '%s' "$DS" | tr '{' '\n' | grep '"name":"default\\\\PKI-Team"' | grep -q '"members":2' && echo yes || echo no)"
# "trigger update group manually from ui for a specific group."
RF=$(API -X POST "$U/api/directory-groups/default%5CPKI-Team/refresh")
chk "the manual refresh reports ok"      yes "$(printf '%s' "$RF" | grep -q '"ok":true' && echo yes || echo no)"
chk "  and hands back carol immediately" yes "$(printf '%s' "$RF" | grep -q '"username":"carol"' && echo yes || echo no)"
chk "the store now holds 3"              3 \
    "$(pg_exec "SELECT count(*) FROM directory_group_members WHERE grp='$Q_PKI_TEAM';" | tr -d ' ')"
DS=$(API "$U/api/directory-subjects")
chk "  and the Subjects tab lists carol" yes \
    "$(printf '%s' "$DS" | tr '{' '\n' | grep '"username":"carol"' | grep -q '"via":"default\\\\PKI-Team"' && echo yes || echo no)"
# Pinned here so section 6 can assert the FAILED refresh left it exactly alone.
OKSTAMP=$(pg_exec "SELECT refreshed FROM directory_groups WHERE grp='$Q_PKI_TEAM';" | tr -d ' ')

echo "=== 6. ⚠️ A REFUSED REFRESH KEEPS THE PREVIOUS MEMBERS ==="
# The whole safety argument for this feature. Take the directory away and ask again: the
# answer must be an error that says the old list still stands, NOT an empty group.
kill $LP 2>/dev/null; wait $LP 2>/dev/null; LP=""
CODE=$(curl -s -b boss.cj -o rf2.json -w '%{http_code}' -X POST "$U/api/directory-groups/default%5CPKI-Team/refresh")
chk "an unreachable directory refuses the refresh (502)" 502 "$CODE"
chk "  and says the previous members were KEPT" yes \
    "$(grep -q '"kept":true' rf2.json && echo yes || echo no)"
chk "⚠️ the stored members are UNTOUCHED — a blip must not empty a group" 3 \
    "$(pg_exec "SELECT count(*) FROM directory_group_members WHERE grp='$Q_PKI_TEAM';" | tr -d ' ')"
chk "  the attempt is recorded with its reason" yes \
    "$(pg_exec "SELECT attempted > 0 AND err <> '' FROM directory_groups WHERE grp='$Q_PKI_TEAM';" \
       | tr -d ' ' | grep -q '^t$' && echo yes || echo no)"
# ⚠️ NOT "refreshed > 0" — that was vacuous, since a successful refresh in section 5 had
# already set it and nothing here could clear it. The real claim is that the FAILURE did
# not move it: refreshed must still date the stored list, while attempted moved on.
# ⚠️ `attempted >=`, not `>`: both stamps are whole seconds and a fast failure lands in
# the same one. The load-bearing half is that `refreshed` still equals what the SUCCESSFUL
# refresh wrote — the failure must not have moved it.
chk "  refreshed still dates the STORED list — the failure did not touch it" yes \
    "$(pg_exec "SELECT refreshed = $OKSTAMP AND attempted >= refreshed
                  FROM directory_groups WHERE grp='$Q_PKI_TEAM';" \
       | tr -d ' ' | grep -q '^t$' && echo yes || echo no)"
# ⚠️ THE THIRD STATE, and the only way to reach it now that the lazy fill exists: a group
# first seen while the directory is unreachable. refreshed stays 0 AND a reason is recorded
# — "we asked and could not be told" — which the console must render differently from
# "nobody has asked yet". Those two shared one string until this was fixed.
pg_exec "INSERT INTO subject_roles(selector_type,selector_value,role)
         VALUES('group','$Q_DARK_TEAM','requester') ON CONFLICT DO NOTHING;" >/dev/null
API "$U/api/directory-subjects" >/dev/null
chk "a group first seen while the directory is DOWN records the reason" yes \
    "$(pg_exec "SELECT refreshed = 0 AND err <> '' FROM directory_groups WHERE grp='$Q_DARK_TEAM';" \
       | tr -d ' ' | grep -q '^t$' && echo yes || echo no)"
chk "  and claims no members for it" 0 \
    "$(pg_exec "SELECT count(*) FROM directory_group_members WHERE grp='$Q_DARK_TEAM';" | tr -d ' ')"
# ⚠️ ONE attempt, not one per request. The lazy fill is gated on `attempted == 0`, so a
# directory that is down costs a blocking LDAP timeout ONCE per group — not on every page
# load, which is what would turn a directory outage into an unusable console.
A1=$(pg_exec "SELECT attempted FROM directory_groups WHERE grp='$Q_DARK_TEAM';" | tr -d ' ')
API "$U/api/directory-subjects" >/dev/null
chk "  and the next read does NOT retry it" "$A1" \
    "$(pg_exec "SELECT attempted FROM directory_groups WHERE grp='$Q_DARK_TEAM';" | tr -d ' ')"
pg_exec "DELETE FROM subject_roles WHERE selector_value='$Q_DARK_TEAM';" >/dev/null
DS=$(API "$U/api/directory-subjects")
chk "the Subjects tab still lists all three people" yes \
    "$(printf '%s' "$DS" | grep -q '"username":"carol"' && echo yes || echo no)"
chk "  and surfaces the failure rather than showing a clean stale list" yes \
    "$(printf '%s' "$DS" | grep -q '"searchError"' && echo yes || echo no)"

echo "=== 7. the SWEEP: a directory change is picked up with nobody acting ==="
# 12h in production (DIRECTORY_GROUP_REFRESH_SEC), 3s here. Same code path.
start_slapd
if ! kill -0 $LP 2>/dev/null; then echo "slapd failed to restart:"; cat slapd.log; exit 1; fi
ldapmodify -x -H "$LURI" -D "cn=admin,dc=fastpki,dc=test" -w adminpass >>add.log 2>&1 <<'LDIF'
dn: cn=PKI-Team,dc=fastpki,dc=test
changetype: modify
delete: member
member: cn=carol,dc=fastpki,dc=test
LDIF
stop_web
mkconf 3
start_web
# Wait for the sweeper rather than sleeping a fixed amount: a fixed sleep either flakes or
# is slower than it needs to be, and it cannot tell "not yet" from "never".
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
  [ "$(pg_exec "SELECT count(*) FROM directory_group_members WHERE grp='$Q_PKI_TEAM';" | tr -d ' ')" = "2" ] && break
  sleep 1
done
chk "the sweeper dropped carol with no operator action" 2 \
    "$(pg_exec "SELECT count(*) FROM directory_group_members WHERE grp='$Q_PKI_TEAM';" | tr -d ' ')"
chk "  alice and bob are still there (it re-resolved, not just cleared)" 2 \
    "$(pg_exec "SELECT count(*) FROM directory_group_members
                 WHERE grp='$Q_PKI_TEAM' AND username IN ('alice','bob');" | tr -d ' ')"
chk "  and the error from section 6 is cleared by the successful refresh" yes \
    "$(pg_exec "SELECT err = '' FROM directory_groups WHERE grp='$Q_PKI_TEAM';" \
       | tr -d ' ' | grep -q '^t$' && echo yes || echo no)"
# ⚠️ THE OTHER HALF OF SECTION 4. Ghost-Team is granted but absent from the directory: the
# search SUCCEEDS and finds no entry, which is a real answer of "nobody". It must end up
# distinguishable from the never-resolved state it was in before the sweep ran.
chk "a granted group the directory does not have resolves to EMPTY, not to an error" yes \
    "$(pg_exec "SELECT refreshed > 0 AND err = '' FROM directory_groups WHERE grp='$Q_GHOST_TEAM';" \
       | tr -d ' ' | grep -q '^t$' && echo yes || echo no)"
chk "  with no members" 0 \
    "$(pg_exec "SELECT count(*) FROM directory_group_members WHERE grp='$Q_GHOST_TEAM';" | tr -d ' ')"

echo "=== 7b. LAZY FIRST FILL: a grant this console never served is populated on read ==="
# ⚠️ THIS IS WHAT KEEPS THE ENDPOINT'S ANSWER THE SAME AS BEFORE THE STORE EXISTED.
# subject_roles REPLICATES between DCs; directory_groups does not. So a grant made on dc1
# arrives on dc2 with no local write, and without a lazy fill dc2's Subjects tab would show
# nobody until its next sweep — forever, if the sweep is disabled. tests/ldap.sh seeds its
# grants by SQL for exactly this reason and asserts the members ARE listed; before the lazy
# fill it passed only because the sweeper happened to win a race.
#
# Simulated by inserting the grant directly (the same shape a replicated row arrives in)
# and reading the endpoint ONCE.
pg_exec "INSERT INTO subject_roles(selector_type,selector_value,role)
         VALUES('group','$Q_PKI_TEAM','auditor') ON CONFLICT DO NOTHING;" >/dev/null
pg_exec "DELETE FROM directory_group_members WHERE grp='$Q_PKI_TEAM';
         DELETE FROM directory_groups WHERE grp='$Q_PKI_TEAM';" >/dev/null
chk "PRECONDITION: the store really is empty for a granted group" 0 \
    "$(pg_exec "SELECT count(*) FROM directory_groups WHERE grp='$Q_PKI_TEAM';" | tr -d ' ')"
DS=$(API "$U/api/directory-subjects")
chk "the FIRST read resolves it — members are listed, not 'nobody'" yes \
    "$(printf '%s' "$DS" | tr '{' '\n' | grep '"username":"alice"' | grep -q '"via":"default\\\\PKI-Team"' && echo yes || echo no)"
chk "  and it is now stored, so the next read costs no directory search" 2 \
    "$(pg_exec "SELECT count(*) FROM directory_group_members WHERE grp='$Q_PKI_TEAM';" | tr -d ' ')"

echo "=== 7c. the store is bounded by the GRANT table ==="
# ⚠️ Without this the refresh endpoint mints rows for any string an admin types, and
# NOTHING reaps them: the sweep only visits granted groups, the DELETE reaper only fires
# when a grant goes away, and the Subjects tab only lists granted groups — invisible and
# immortal at the same time.
CODE=$(curl -s -b boss.cj -o rf3.json -w '%{http_code}' -X POST "$U/api/directory-groups/default%5CNot-Granted/refresh")
chk "refreshing a group that holds no role is refused (404)" 404 "$CODE"
chk "  and no rows were created for it" 0 \
    "$(pg_exec "SELECT count(*) FROM directory_groups WHERE grp='$Q_NOT_GRANTED';" | tr -d ' ')"
# The peer-DC case: the grant row vanishes (it replicated away) but the store does not.
# Only the sweeper's reap collects that, so plant one and wait for a tick.
pg_exec "INSERT INTO directory_groups(grp,refreshed,attempted,err) VALUES('Orphan-Team',1,1,'');
         INSERT INTO directory_group_members(grp,username,display) VALUES('Orphan-Team','ghost','ghost');" >/dev/null
chk "PRECONDITION: an orphaned store row exists" 1 \
    "$(pg_exec "SELECT count(*) FROM directory_groups WHERE grp='Orphan-Team';" | tr -d ' ')"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
  [ "$(pg_exec "SELECT count(*) FROM directory_groups WHERE grp='Orphan-Team';" | tr -d ' ')" = "0" ] && break
  sleep 1
done
chk "the sweeper reaps a store row no grant justifies" 0 \
    "$(pg_exec "SELECT count(*) FROM directory_groups WHERE grp='Orphan-Team';" | tr -d ' ')"
chk "  members and all" 0 \
    "$(pg_exec "SELECT count(*) FROM directory_group_members WHERE grp='Orphan-Team';" | tr -d ' ')"

echo "=== 8. the store follows the grant ==="
# ⚠️ THE "LAST grant, not THIS grant" BRANCH. 7b gave PKI-Team a SECOND role, so removing
# the first one must leave the store alone. Without this assertion the comment claiming the
# distinction was the only thing asserting it, and a reaper that fired on every revoke
# would have passed the suite while silently emptying groups that still hold a role.
API -X DELETE "$U/api/subject-roles?selector_type=group&selector_value=default%5CPKI-Team&role=requester" >/dev/null
chk "removing ONE of two grants keeps the stored members" 2 \
    "$(pg_exec "SELECT count(*) FROM directory_group_members WHERE grp='$Q_PKI_TEAM';" | tr -d ' ')"
API -X DELETE "$U/api/subject-roles?selector_type=group&selector_value=default%5CPKI-Team&role=auditor" >/dev/null
chk "removing the LAST grant drops the stored members" 0 \
    "$(pg_exec "SELECT count(*) FROM directory_group_members WHERE grp='$Q_PKI_TEAM';" | tr -d ' ')"
chk "  and the group's refresh state"                 0 \
    "$(pg_exec "SELECT count(*) FROM directory_groups WHERE grp='$Q_PKI_TEAM';" | tr -d ' ')"

echo "=== 9. the console renders the three states ==="
PAGE=$(API "$U/")
chk "the group row offers a per-group refresh" yes \
    "$(grep -q 'data-refresh=' <<<"$PAGE" && echo yes || echo no)"
chk "  wired to the refresh endpoint"          yes \
    "$(grep -qF "api/directory-groups/' + encodeURIComponent(name) + '/refresh" <<<"$PAGE" && echo yes || echo no)"
chk "  and says so when a group has never been resolved" yes \
    "$(grep -q 'membership not resolved yet' <<<"$PAGE" && echo yes || echo no)"
chk "a failed manual refresh tells the operator the list is the OLD one" yes \
    "$(grep -q 'previously stored members are still shown' <<<"$PAGE" && echo yes || echo no)"
# ⚠️ A SUCCESS TOAST MUST NOT RENDER AS A FAILURE. notify(msg, kind) treats any kind other
# than the literal 'info' as an error: red border, role=alert, and no auto-dismiss. The
# success path omitted it, so a refresh that worked looked exactly like one that did not.
INFOPAT="member(s)', 'info')"
chk "  while a SUCCESSFUL refresh reports as info, not as a red sticky alert" yes \
    "$(printf '%s' "$PAGE" | grep -qF "$INFOPAT" && echo yes || echo no)"
# The three states must be three different strings; two of them shared one before.
chk "a first refresh that FAILED says so, instead of 'not resolved yet'" yes \
    "$(grep -q 'membership could not be read' <<<"$PAGE" && echo yes || echo no)"
# The grant-time answer had no reader — the server computed it and the
# console dropped it, which is the writer-with-no-reader shape this project keeps hitting.
chk "a group granted with ZERO directory members says so at grant time" yes \
    "$(grep -q 'returned NO members for it' <<<"$PAGE" && echo yes || echo no)"
# BOTH group-grant paths must report it: the New-group modal and the LDAP bulk import.
# One call site would leave the other silently back at the empty-group screen.
chk "  and both group-grant paths call it" 2 \
    "$(grep 'noteGrantedGroup(' <<<"$PAGE" | grep -vc 'function ')"

echo "=== 10. the interval lives in the DB config TABLE, and the table beats bootstrap.conf ==="
# The project rule: config settings are not stored in a file, they are stored in a DB
# table unless that is absolutely unavoidable.
#
# DIRECTORY_GROUP_REFRESH_SEC was once described as global and living in the config file.
# That was wrong. It is an ordinary config
# key, which under §3f means the `config` TABLE is where it belongs and where it WINS —
# lib/config.cpp's apply() accepts it, so overlay_config() lays the DB row over whatever
# bootstrap.conf said, at startup, before the sweeper ever reads it; and the Config page writes it
# with PUT /api/config/db like every other setting. Nothing ships it in a file: it appears in
# no deploy/ file and in no compose environment.
#
# ⚠️ EVERY SECTION ABOVE SET IT IN bootstrap.conf, and that is the artefact that made the claim
# look true. A guard has to run the DB path with the file saying the OPPOSITE, or "the table
# wins" stays an assertion about the source rather than about the product. So: file says 0
# (sweep off), table says 3, and the assertion is that the SWEEP RUNS.
API -X POST "$U/api/subject-roles" \
    -d 'selector_type=group&selector_value=default%5CPKI-Team&role=requester' >/dev/null
chk "PRECONDITION: PKI-Team is granted again and stored with 2 members" 2 \
    "$(pg_exec "SELECT count(*) FROM directory_group_members WHERE grp='$Q_PKI_TEAM';" | tr -d ' ')"

# The path an admin actually takes: the Config page's editor is PUT /api/config/db.
CODE=$(curl -s -b boss.cj -o cfgset.json -w '%{http_code}' -X PUT "$U/api/config/db" \
        -d 'key=DIRECTORY_GROUP_REFRESH_SEC&value=3')
chk "the console stores the interval in the config table" 200 "$CODE"
chk "  and it is a real row, not a file line" 3 \
    "$(pg_exec "SELECT value FROM config WHERE key='DIRECTORY_GROUP_REFRESH_SEC';" | tr -d ' ')"
chk "  which the Config page lists as an override" yes \
    "$(API "$U/api/config/db" | tr '{' '\n' | grep -q '"key":"DIRECTORY_GROUP_REFRESH_SEC","value":"3"' \
       && echo yes || echo no)"

stop_web
mkconf 0          # bootstrap.conf now says the sweep is OFF
start_web
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
chk "PRECONDITION: bootstrap.conf really says 0" 1 \
    "$(grep -c '^DIRECTORY_GROUP_REFRESH_SEC=0$' bootstrap.conf | tr -d ' ')"
chk "the EFFECTIVE value is the table's, not the file's" yes \
    "$(API "$U/api/config" | tr '{' '\n' \
       | grep -q '"key":"DIRECTORY_GROUP_REFRESH_SEC","value":"3"' && echo yes || echo no)"

# ...and the sweeper is really running on it. carol was removed from PKI-Team in section 7;
# put her back and watch the store follow, with nobody touching the console.
ldapmodify -x -H "$LURI" -D "cn=admin,dc=fastpki,dc=test" -w adminpass >>add.log 2>&1 <<'LDIF'
dn: cn=PKI-Team,dc=fastpki,dc=test
changetype: modify
add: member
member: cn=carol,dc=fastpki,dc=test
LDIF
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
  [ "$(pg_exec "SELECT count(*) FROM directory_group_members WHERE grp='$Q_PKI_TEAM';" | tr -d ' ')" = "3" ] && break
  sleep 1
done
chk "the sweep RAN on the table's interval, with the file saying it was off" 3 \
    "$(pg_exec "SELECT count(*) FROM directory_group_members WHERE grp='$Q_PKI_TEAM';" | tr -d ' ')"

# And unsetting the override hands the key back to bootstrap.conf rather than to a hardcoded
# default — otherwise "stored in the DB" would be a one-way door.
CODE=$(curl -s -b boss.cj -o cfgunset.json -w '%{http_code}' \
        -X DELETE "$U/api/config/db?key=DIRECTORY_GROUP_REFRESH_SEC")
chk "the override can be removed from the table" 200 "$CODE"
stop_web
start_web
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
chk "  after which the effective value is bootstrap.conf's 0 again" yes \
    "$(API "$U/api/config" | tr '{' '\n' \
       | grep -q '"key":"DIRECTORY_GROUP_REFRESH_SEC","value":"0"' && echo yes || echo no)"
# The shipped default, for a deployment that sets it in neither place. 12h — the required
# value — and it must come from the code, not from any file we ship.
chk "and nothing in deploy/ writes this key to a file" 0 \
    "$(grep -rl 'DIRECTORY_GROUP_REFRESH_SEC' "$ROOT/deploy" 2>/dev/null | wc -l | tr -d ' ')"

echo "=== 11. an expiry email goes to the address the directory holds ==="
# The same directory, asked the other question the notifier has: where does this owner read
# mail? alice's directory entry has an address and her account row a different one — the
# directory's wins. carol's entry has none, so her account's field is used. bob has neither.
NOW=$(date +%s)
for o in alice carol bob; do
  pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint) VALUES('m$o',0,0,0,$((NOW-86400)),$((NOW+3*86400)),'CN=$o.mail.test','default\\$o','$o.mail.test','');" >/dev/null
done
printf 'PG_CONNINFO=%s\nLOG_LEVEL=err\nSMTP_SERVER=localhost:1\nSMTP_FROM=pki@example.test\n' "$PG_CONNINFO" > notify.conf
"$BUILD/fastpki-config" --config notify.conf web-user 'default\alice' pw-alice-123 --role requester --email alice.account@example.test >/dev/null
"$BUILD/fastpki-config" --config notify.conf web-user 'default\carol' pw-carol-123 --role requester --email carol.account@example.test >/dev/null
DRY=$("$BUILD/fastpki-notify" --config notify.conf --dry-run 2>&1)
chk "a directory owner is emailed at the directory's mail" yes \
    "$(echo "$DRY" | grep -q 'email (dry run) -> alice@directory.test: 1 certificate' && echo yes || echo no)"
chk "  not at the address on the account row" no \
    "$(echo "$DRY" | grep -q 'alice.account@example.test' && echo yes || echo no)"
chk "one the directory has no mail for falls back to the account's field" yes \
    "$(echo "$DRY" | grep -q 'email (dry run) -> carol.account@example.test: 1 certificate' && echo yes || echo no)"
chk "and one with neither is reported as having no address" yes \
    "$(echo "$DRY" | grep -qF 'no address for owner default\bob' && echo yes || echo no)"

echo
echo "=== DIRECTORY GROUP REFRESH: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
