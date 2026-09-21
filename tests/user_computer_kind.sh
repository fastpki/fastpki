#!/usr/bin/env bash
# ⚠️ THE REQUIREMENT: the user/computer distinction is needed everywhere.
#
# The ticket opened as a WSTEP 403 for FASTPKI-WIN$, and the first thing it exposed was
# that this product had no concept of a machine at all: the console refused the name
# outright ("invalid username"), and once that was fixed only ONE endpoint said what kind
# of principal it was. `everywhere` is the ask, so this suite is the list of places that
# must agree, and the census that stops a second implementation of the rule appearing.
#
# What is asserted, and why each one is here rather than implied by the others:
#
#   1. /api/users              — the account row (already shipped; kept as the control)
#   2. /api/subject-roles      — a `user` GRANT naming a machine. This is the shape from
#                                the ticket: FASTPKI-WIN$ has no account, so a grant row is
#                                the only place the console can name it.
#   3. /api/certs + detail     — a GenericComputer certificate is OWNED by a machine.
#   4. /api/audit              — the line the failure was READ in.
#   5. the served console      — every one of the above has a reader. The first fix
#                                shipped `kind` server-side and threw it away in
#                                mergeSubjects(), so "the endpoint emits it" is NOT the
#                                assertion that matters.
#   6. a census                — no file outside src/lib/auth.cpp may spell the rule out.
#                                It was in TWO places before this change (web/main.cpp had
#                                the `/` rule, ldap_auth.cpp did not) which is how the two
#                                sites came to disagree.
#   7. the realm-qualified form — FASTPKI-WIN$@REALM and FASTPKI-WIN$ must classify the
#                                same, or a grant an operator types does not match the row
#                                the machine writes when it enrols.
#
# ⚠️ ANTI-VACUITY. Almost every assertion has the form "does X say computer?", and every
# one of them would pass for free against a build that called EVERYTHING a computer. Each
# section therefore carries the opposite assertion on an ordinary account in the same
# response — see the `an ordinary …` lines.
#
# The directory half — a machine reaching the console only as a member of a granted group,
# which is the case actually meant — needs a live directory and lives in
# tests/ldap.sh (the FASTPKI_WITH_LDAP build); this suite asserts the console CONSUMES it.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18233
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
# ⚠️ A here-string, not `echo | grep -q`. The console page is ~700 kB and grep -q exits at
# the first match, which closes the pipe under the still-writing echo — every assertion
# below section 5 printed "write error: Broken pipe" beside its PASS.
has(){ grep -q "$2" <<<"$1" && echo yes || echo no; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

# The three principals under test, and the ordinary one that keeps them honest.
MACH='WS-BOX$'                    # AD machine account: sAMAccountName MUST end in `$`
SVC='host/node1.example.org'      # Kerberos service form: never a person
HUMAN='dora'

pg_setup user_computer_kind
trap 'pg_cleanup; kill ${P:-} 2>/dev/null' EXIT

# A real token-held CA, so section 3 issues a certificate rather than inventing a row.
# Sections 1/2/4/5/6/7 do not need it and run either way — see HAVE_CA below.
HAVE_CA=no
if ca_in_token ca.pem "/CN=Kind Test CA/O=FastPKI Test" 3650 kindca >/dev/null 2>&1; then
    HAVE_CA=yes
fi

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
if [ "$HAVE_CA" = yes ]; then
cat >> bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=kindca
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf
fi

seed_web_user boss    bosspw12    admin
seed_web_user "$HUMAN" dorapw12   requester
seed_web_user "$MACH" machinepw1  requester
seed_web_user "$SVC"  servicepw1  requester

"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" WEB_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat srv.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c boss.cj -X POST "$U/api/login" -d 'username=boss&password=bosspw12' >/dev/null
chk "PRECONDITION: the admin session works" 200 "$(code -b boss.cj "$U/api/users")"

echo "=== 1. /api/users — the account row ==="
UL=$(curl -s -b boss.cj "$U/api/users")
chk "the machine account is kind=computer"      yes "$(has "$UL" "\"username\":\"WS-BOX\\\$\",\"role\":\"requester\",\"mustReset\":false,\"kind\":\"computer\"")"
chk "the service principal is kind=computer"    yes "$(has "$UL" "\"username\":\"host/node1.example.org\",\"role\":\"requester\",\"mustReset\":false,\"kind\":\"computer\"")"
# ⚠️ THE CONTROL. Without it every assertion in this file passes against a build that
# hardcodes "computer".
chk "an ordinary account is kind=user"          yes "$(has "$UL" "\"username\":\"dora\",\"role\":\"requester\",\"mustReset\":false,\"kind\":\"user\"")"

echo "=== 2. /api/subject-roles — the GRANT row, which is how the machine appears ==="
# FASTPKI-WIN$ had role `none` and no way to be given one; once it holds a grant, that row
# is what the Users tab renders. Before this change it carried no kind at all, so the tab
# fell back to the SELECTOR type — which is the literal string `user`.
for s in "$MACH" "$SVC" "$HUMAN"; do
  curl -s -o /dev/null -b boss.cj -X POST "$U/api/subject-roles" \
       --data-urlencode "selector_type=user" --data-urlencode "selector_value=$s" \
       --data-urlencode "role=requester"
done
curl -s -o /dev/null -b boss.cj -X POST "$U/api/subject-roles" \
     --data-urlencode "selector_type=group" --data-urlencode "selector_value=Domain Computers" \
     --data-urlencode "role=requester"
SR=$(curl -s -b boss.cj "$U/api/subject-roles")
chk "PRECONDITION: all four grants were written" 4 \
    "$(pg_exec "SELECT count(*) FROM subject_roles WHERE role='requester';" | tr -d ' ')"
chk "a user grant naming a machine is kind=computer" yes \
    "$(has "$SR" "\"selector_value\":\"WS-BOX\\\$\",\"role\":\"requester\",\"kind\":\"computer\"")"
chk "a user grant naming a service principal is kind=computer" yes \
    "$(has "$SR" "\"selector_value\":\"host/node1.example.org\",\"role\":\"requester\",\"kind\":\"computer\"")"
chk "a user grant naming a person is kind=user" yes \
    "$(has "$SR" "\"selector_value\":\"dora\",\"role\":\"requester\",\"kind\":\"user\"")"
# ⚠️ A GROUP IS NEITHER, and must not be classified. "Domain Computers" is the group an
# admin grants the machine role TO — asking whether that NAME is a computer is a category
# error, and answering `user` (which a blanket `kind` on every row would) is worse than
# saying nothing, because the Type pill would then read `user` for a group.
chk "a GROUP grant carries no kind at all" no \
    "$(has "$SR" '"selector_type":"group","selector_value":"Domain Computers","role":"requester","kind"')"

echo "=== 7. the realm-qualified spelling classifies identically ==="
# msxcep stores the realm-stripped name; an operator writing a grant, and
# directory_groups_for(), can both produce the qualified one. If they classified
# differently the console would say `computer` for the row the machine wrote and `user`
# for the row the operator typed, for the same machine.
curl -s -o /dev/null -b boss.cj -X POST "$U/api/subject-roles" \
     --data-urlencode "selector_type=user" --data-urlencode 'selector_value=WS-BOX$@FASTPKI.LAB' \
     --data-urlencode "role=requester"
curl -s -o /dev/null -b boss.cj -X POST "$U/api/subject-roles" \
     --data-urlencode "selector_type=user" --data-urlencode 'selector_value=dora@example.test' \
     --data-urlencode "role=requester"
SR=$(curl -s -b boss.cj "$U/api/subject-roles")
chk "WS-BOX\$@REALM is a computer, like WS-BOX\$" yes \
    "$(has "$SR" "\"selector_value\":\"WS-BOX\\\$@FASTPKI.LAB\",\"role\":\"requester\",\"kind\":\"computer\"")"
# The control for the realm strip: an ordinary UPN must not become a computer just because
# it contains an `@`.
chk "dora@example.test is still a user" yes \
    "$(has "$SR" "\"selector_value\":\"dora@example.test\",\"role\":\"requester\",\"kind\":\"user\"")"

echo "=== 3. a certificate OWNED by a machine ==="
if [ "$HAVE_CA" = yes ]; then
  issue_as(){   # $1 user  $2 password  $3 cn  -> echoes the serial ("" on refusal)
    # ⚠️ --data-binary with the raw PEM. The route takes the CSR as the BODY, not as a
    # multipart field; a -F upload 400s with "body must be a PEM PKCS#10 CSR", which reads
    # as an authorization refusal if you only look at the empty serial.
    local jar; jar="$W/j.cj"
    curl -s -c "$jar" -X POST "$U/api/login" \
         --data-urlencode "username=$1" --data-urlencode "password=$2" >/dev/null
    "$OSSL" req -new -newkey rsa:2048 -nodes -keyout "$W/k.pem" -out "$W/c.csr" \
            -subj "/CN=$3" >/dev/null 2>&1
    curl -s -b "$jar" -o "$W/iss.json" -X POST --data-binary "@$W/c.csr" \
         "$U/api/certs/request?ca_instance=kindca" >/dev/null
    sed -n 's/.*"serial":"\([^"]*\)".*/\1/p' "$W/iss.json" | head -1
  }
  MS=$(issue_as "$MACH" machinepw1 ws-box.example.org)
  HS=$(issue_as "$HUMAN" dorapw12  dora.example.org)
  chk "PRECONDITION: the machine's request issued a certificate" yes \
      "$([ -n "$MS" ] && echo yes || echo no)"
  chk "PRECONDITION: the person's request issued one too"        yes \
      "$([ -n "$HS" ] && echo yes || echo no)"
  # ⚠️ Read back from the LIST, which is what the Inventory table paints.
  LIST=$(curl -s -b boss.cj "$U/api/certs?limit=500")
  chk "the machine's cert reports ownerKind=computer" yes \
      "$(has "$LIST" "\"owner\":\"WS-BOX\\\$\",\"ownerKind\":\"computer\"")"
  chk "the person's cert reports ownerKind=user"      yes \
      "$(has "$LIST" "\"owner\":\"dora\",\"ownerKind\":\"user\"")"
  # And from the DETAIL route, which the modal reads. Two producers, one answer — the
  # column and the modal sitting side by side disagreeing is the drift shape.
  chk "the detail route agrees: computer" yes \
      "$(has "$(curl -s -b boss.cj "$U/api/certs/$MS")" '"ownerKind":"computer"')"
  chk "the detail route agrees: user"     yes \
      "$(has "$(curl -s -b boss.cj "$U/api/certs/$HS")" '"ownerKind":"user"')"
  # ⚠️ AN UNOWNED ROW IS NOT A PERSON, and this is not hypothetical — the lab holds ~1700
  # certificates with owner='' (issued before ownership was recorded, plus the CA rows
  # themselves) and the first version of this field said `user` about every one of them.
  # principal_kind("") answers User, so the omission has to be at the emitter.
  pg_exec "INSERT INTO certs(serial,status,owner,\"notBefore\",\"notAfter\")
           VALUES('deadbeef01',0,'',1,2000000000);" >/dev/null 2>&1
  UNOWNED=$(curl -s -b boss.cj "$U/api/certs?limit=500" | grep -o '{"serial":"deadbeef01"[^}]*}')
  chk "PRECONDITION: the unowned row is listed"   yes "$([ -n "$UNOWNED" ] && echo yes || echo no)"
  chk "  it reports an empty owner"               yes "$(has "$UNOWNED" '"owner":""')"
  chk "  and carries NO ownerKind at all"         no  "$(has "$UNOWNED" 'ownerKind')"

  echo "=== 4. /api/audit — the line the failure is READ in ==="
  # It was diagnosed from `545 … auth authz_fail FASTPKI-WIN$ failure issuing`.
  # Issuance writes an audit row with the requester as actor, so the same principals appear
  # here without inventing an event.
  AU=$(curl -s -b boss.cj "$U/api/audit?limit=200")
  chk "an audit row actored by a machine says actorKind=computer" yes \
      "$(has "$AU" "\"actor\":\"WS-BOX\\\$\",\"actorKind\":\"computer\"")"
  chk "an audit row actored by a person says actorKind=user"      yes \
      "$(has "$AU" "\"actor\":\"dora\",\"actorKind\":\"user\"")"
  # Same rule as the unowned certificate: a system-generated event (the expiry sweep, the
  # reissue cron) has no actor and is not a person.
  # ⚠️ prev_hash is NOT NULL — omitting it makes the INSERT fail silently and the
  # PRECONDITION below then reads as "the endpoint dropped the row", which is a claim
  # about the product rather than about the fixture.
  pg_exec "INSERT INTO audit_log(ts,category,action,actor,actor_ip,target,status,detail,prev_hash,hash)
           VALUES(1,'system','kind_probe','','','','success','','x','y');" >/dev/null 2>&1
  SYSROW=$(curl -s -b boss.cj "$U/api/audit?limit=500" | grep -o '{"seq":[0-9]*,[^}]*kind_probe[^}]*}')
  chk "PRECONDITION: the actorless row is listed" yes "$([ -n "$SYSROW" ] && echo yes || echo no)"
  chk "  and it carries NO actorKind"             no  "$(has "$SYSROW" 'actorKind')"
else
  # ⚠️ A PROBED skip with its reason printed, not a silent one. A harness skip and an
  # environment skip read identically in a run summary otherwise.
  echo "  [SKIP] sections 3-4 need a PKCS#11 token for the CA — ca_in_token failed here"
fi

echo "=== 5. the console READS every one of them ==="
# ⚠️ COMMENTS STRIPPED FIRST. The served page carries this file's sibling prose, and a
# grep guard that matches its own comment passes forever — that is a defect this tree has
# already shipped once. Everything below is matched against CODE only.
PAGE=$(curl -s -b boss.cj "$U/" | sed -e 's|//.*$||' -e 's|/\*.*\*/||g')
chk "PRECONDITION: the console page was served" yes \
    "$(has "$PAGE" 'function mergeSubjects')"
chk "there is a principal renderer at all"               yes "$(has "$PAGE" 'function principalCell')"
chk "the Audit Actor column uses it"                     yes "$(has "$PAGE" "tab === 'audit' && k === 'actor'")"
chk "  and passes the SERVER's actorKind, not its own guess" yes "$(has "$PAGE" 'row.actorKind')"
chk "the Inventory Owner column uses it"                 yes "$(has "$PAGE" "tab === 'certs' && k === 'owner'")"
chk "  and passes the server's ownerKind"                yes "$(has "$PAGE" 'row.ownerKind')"
chk "the cert detail modal uses it"                      yes "$(has "$PAGE" "principalCell(v, c.ownerKind)")"
chk "an account row carries kind into the table"         yes "$(has "$PAGE" 'kind: u.kind')"
chk "a GRANT row carries kind into the table"            yes "$(has "$PAGE" 'kind:a.kind')"
chk "a DIRECTORY row carries kind into the table"        yes "$(has "$PAGE" 'kind: d.kind')"
# The pill already prefers `kind` over `type`; assert it, because that line is what turns
# every field above into something visible.
chk "the Type pill renders kind in preference to type"   yes "$(has "$PAGE" 'esc(o.kind || o.type)')"
# ⚠️ AND THE RENDERER MUST NOT RE-DERIVE. If principalCell tested the name itself, every
# `kind` field above would be decoration and the console could drift from the gate.
chk "principalCell does NOT test the name itself" no \
    "$(echo "$PAGE" | sed -n '/function principalCell/,/^}/p' | grep -qE "endsWith\('\\\$'\)|indexOf\('/'\)" && echo yes || echo no)"

echo "=== 6. census: exactly ONE implementation of the rule ==="
# The rule was in two places before this change, and they had already diverged: web/main.cpp
# carried the `/` service-form test that was asked for and ldap_auth.cpp did not. A
# comment saying "keep these in sync" is what a census replaces.
cd "$ROOT"
# ⚠️ NO GIT. There is none in the shipped image — the harness mounts the tree at /src but
# the container has no `git` binary at all. `git ls-files` there returns NOTHING, the loop
# below runs zero times, `$impl` is empty, and "no file re-implements the rule" PASSES
# having examined no files. That is the worse of the two failure modes: the sibling check
# using `git grep` at least went RED and said so. Both are plain grep/find now, so this
# suite measures the same thing on a dev box and on what we ship.
SRCS=$(find src include -type f \( -name '*.cpp' -o -name '*.hpp' \) | sort)
# ...and prove the file list is not empty, or every census below is vacuous again.
chk "the census has source files to scan" yes \
    "$([ "$(printf '%s\n' "$SRCS" | grep -c .)" -gt 50 ] && echo yes || echo no)"
# Files that spell out a trailing-`$` or embedded-`/` principal test. auth.cpp is the one
# legal site. Comments are stripped so a file that only DESCRIBES the rule is not counted.
impl=$(for f in $SRCS; do
         [ "$f" = "src/lib/auth.cpp" ] && continue
         sed -e 's|//.*$||' "$f" | grep -qE "back\(\) *== *'\\\$'|ends_with\(\"\\\$\"\)" && echo "$f"
       done)
chk "no file outside src/lib/auth.cpp re-implements the \$ test" "" "$impl"
# ⚠️ AND THE CENSUS MUST NOT BE VACUOUS. If the pattern matched nothing anywhere — a
# refactor renaming the idiom, say — the assertion above would pass while the rule was
# reimplemented three times under a new spelling. Prove the pattern still finds the ONE
# site it is supposed to.
chk "  and the census pattern still finds auth.cpp itself" yes \
    "$(sed -e 's|//.*$||' src/lib/auth.cpp | grep -qE "back\(\) *== *'\\\$'" && echo yes || echo no)"
# Every consumer must go through the shared entry points. Count them so a site added later
# without them is visible as a drop rather than as nothing.
users=" $(grep -rlE 'principal_kind|is_computer_principal' src include | sort | tr '\n' ' ')"
missing=""
for f in src/web/main.cpp src/msxcep/main.cpp src/est/main.cpp src/lib/ldap_auth.cpp; do
    [[ "$users" == *" $f "* ]] || missing="$missing $f"
done
chk "the shared classifier has readers in web, msxcep, est and ldap_auth" "" "$missing"

echo
echo "user_computer_kind: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
