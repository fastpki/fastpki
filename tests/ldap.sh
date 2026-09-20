#!/usr/bin/env bash
# LDAP auth backend. Validates AUTH_BACKEND=ldap against a REAL
# OpenLDAP server — a throwaway slapd this test provisions on a high port — to
# close the "not validated against a directory" test-gap. Our backend does a
# simple bind as CN=<user>,<base> (ldap_auth.cpp); slapd reproduces that exactly.
# Self-skips when openldap or the FASTPKI_WITH_LDAP build is absent.
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
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
# ⚠️ THIS SUITE USED TO SKIP ON EVERY MAC AND NOBODY NOTICED (see the SKIP lines below).
# A skip counts as `ok` in run_all.sh, so "full suite green" from a Mac silently excluded
# LDAP entirely — it hid three real failures once already. Homebrew DOES ship slapd
# and the schemas, just not where a Linux distribution puts them, so every probe here is a
# LIST of the known locations rather than one Linux path. Each SKIP below is a real absence,
# not a spelling difference.
#
# FASTPKI_BUILD names the build directory to test. It exists because LDAP is an OPTIONAL
# cmake feature: a tree's default `build/` may have FASTPKI_WITH_LDAP=OFF, in which case
# these binaries cannot speak to a directory at all and the suite has nothing to measure.
BUILD="${FASTPKI_BUILD:-$ROOT/build}"
EST="$BUILD/fastpki-est"
SLAPD=""
for c in "$(command -v slapd 2>/dev/null)" /usr/sbin/slapd /usr/local/libexec/slapd \
         /opt/homebrew/opt/openldap/libexec/slapd /usr/local/opt/openldap/libexec/slapd; do
  [ -n "$c" ] && [ -x "$c" ] && { SLAPD="$c"; break; }
done
[ -n "$SLAPD" ] || { echo "SKIP: openldap (slapd) not installed"; exit 0; }
# The client tools may live beside slapd rather than on PATH (Homebrew keeps openldap
# keg-only, precisely so it does not shadow the system LDAP.framework).
case "$SLAPD" in */libexec/slapd) PATH="${SLAPD%/libexec/slapd}/bin:${SLAPD%/libexec/slapd}/sbin:$PATH"; export PATH;; esac
command -v ldapadd >/dev/null 2>&1 || { echo "SKIP: ldap-utils not installed"; exit 0; }
# `ldd` does not exist on macOS; `otool -L` is the equivalent. Asking neither would make
# the FASTPKI_WITH_LDAP=OFF build look like a product failure instead of a build without
# the feature.
linked_ldap(){ { ldd "$1" 2>/dev/null || otool -L "$1" 2>/dev/null; } | grep -qiE "libldap|LDAP\.framework"; }
linked_ldap "$EST" || { echo "SKIP: $EST built without FASTPKI_WITH_LDAP"; exit 0; }
SCH=""
for d in /etc/ldap/schema /etc/openldap/schema \
         /opt/homebrew/etc/openldap/schema /usr/local/etc/openldap/schema; do
  [ -d "$d" ] && SCH="$d"
done
[ -n "$SCH" ] || { echo "SKIP: openldap schema dir not found"; exit 0; }
# back_mdb may be a loadable module (Debian) or compiled in (Homebrew). Empty MODP means
# "compiled in" and the conf simply omits the moduleload lines.
MODP=""; for d in /usr/lib/ldap /usr/lib/openldap /usr/lib/x86_64-linux-gnu/openldap \
                  /opt/homebrew/opt/openldap/libexec/openldap; do
  [ -e "$d/back_mdb.so" ] && MODP="$d"
done
W="$(mktemp -d)"; cd "$W"; LPORT=13890; EPORT=18460; WPORT=18461
# ⚠️ EVERY child goes in ONE variable list, because bash EXIT TRAPS DO NOT STACK: the
# second `trap ... EXIT` REPLACES the first. This suite used to set one trap for slapd and
# then a second for Postgres, which silently dropped slapd from the cleanup — it leaked a
# listening directory server on port 13890 on every run, and the NEXT run then failed at
# "slapd failed to start" with an empty log, which reads as a broken product.
# ⚠️ EVERY server this suite starts belongs in this list, not only the ones that existed
# when the trap was written. The two extra consoles below are killed on their own happy
# path, which is exactly why they were never added here — and an early `exit` between the
# start and that kill leaves a console listening on a fixed port, so the NEXT run of the
# suite fails to bind and reports it as a product fault.
P=""; LP=""; WP=""; BP=""; RWP=""
cleanup(){ kill $LP $P $WP $BP $RWP 2>/dev/null; }
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# ⚠️ WAIT FOR THE SERVICE TO ANSWER — NEVER SLEEP A FIXED TIME AT IT. Every server in this
# suite used to be followed by `sleep 1` (or 2), and the suite's RESULT moved between runs
# on an unchanged binary: repeated runs gave 6 and 11 failures with different assertions in
# each set. A server that has not finished binding turns every request in its section into
# a connection refusal, and at this level a refusal is indistinguishable from the policy
# denial the assertion is actually about — so the flake reads as a product bug, and worse,
# the NEGATIVE assertions all pass while it is happening.
#
# Both helpers also give up the moment the child DIES, so a server that cannot start is
# reported in a fraction of a second instead of after the whole retry budget. The budget is
# generous on purpose: waiting a little longer costs a second, answering early costs a
# wrong result nobody can reproduce.
wait_ldap(){ # pid uri
  local i=0
  while [ $i -lt 150 ]; do
    kill -0 "$1" 2>/dev/null || return 1
    ldapsearch -x -H "$2" -b "" -s base -LLL >/dev/null 2>&1 && return 0
    i=$((i+1)); sleep 0.1
  done
  return 1
}
wait_http(){ # pid url
  local i=0
  while [ $i -lt 150 ]; do
    kill -0 "$1" 2>/dev/null || return 1
    # Any HTTP answer means the listener is serving; the STATUS is what the assertions
    # below are for, so 401/404 is "up" here and only `000` (no response) is not.
    [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "$2" 2>/dev/null)" != "000" ] && return 0
    i=$((i+1)); sleep 0.1
  done
  return 1
}

echo "=== provision a throwaway slapd (dc=fastpki,dc=test) ==="
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
# ⚠️ `-d 0` KEEPS SLAPD IN THE FOREGROUND BUT LOGS NOTHING TO STDERR — it sends its
# diagnostics to syslog instead. So the failure branch below used to print an always-empty
# file, and "slapd failed to start:" followed by a blank line is a message that cannot tell
# you a port was busy from a schema file that would not parse. `-d 256` (stats) is the
# quietest level that still puts startup errors where this suite can read them.
"$SLAPD" -h "$LURI/" -f slapd.conf -d 256 >slapd.log 2>&1 & LP=$!
trap cleanup EXIT
if ! wait_ldap $LP "$LURI"; then echo "slapd failed to start:"; cat slapd.log; exit 1; fi
ldapadd -x -H "$LURI" -D "cn=admin,dc=fastpki,dc=test" -w adminpass >add.log 2>&1 <<LDIF
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

dn: cn=PKI-Nested,dc=fastpki,dc=test
objectClass: groupOfNames
cn: PKI-Nested
member: cn=alice,dc=fastpki,dc=test

dn: cn=Field\+Ops,dc=fastpki,dc=test
objectClass: groupOfNames
cn: Field+Ops
member: cn=alice,dc=fastpki,dc=test

dn: cn=WS-BOX$,dc=fastpki,dc=test
objectClass: inetOrgPerson
cn: WS-BOX$
sn: Machine
userPassword: machinepass

dn: cn=PKI-Enrollers,dc=fastpki,dc=test
objectClass: groupOfNames
cn: PKI-Enrollers
member: cn=carol,dc=fastpki,dc=test
member: cn=WS-BOX$,dc=fastpki,dc=test
member: cn=PKI-Nested,dc=fastpki,dc=test

dn: cn=PKI-Bystanders,dc=fastpki,dc=test
objectClass: groupOfNames
cn: PKI-Bystanders
member: cn=bob,dc=fastpki,dc=test
LDIF
chk "directory seeded (alice can bind)" yes \
    "$(ldapwhoami -x -H "$LURI" -D 'cn=alice,dc=fastpki,dc=test' -w alicepass >/dev/null 2>&1 && echo yes || echo no)"
# bob is a SECOND bindable identity. The profile-assignment section below needs a user who
# authenticates fine but holds no assignment — without him, "unassigned subject is refused"
# would pass because the user cannot log in at all, which proves nothing about profiles.
chk "directory seeded (bob can bind too)"  yes \
    "$(ldapwhoami -x -H "$LURI" -D 'cn=bob,dc=fastpki,dc=test' -w bobpass >/dev/null 2>&1 && echo yes || echo no)"

echo "=== EST enrollment with AUTH_BACKEND=ldap ==="
ca_in_token ca.pem "/CN=LDAP Auth CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3650 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup ldap
# ⚠️ THE DIRECTORY IS A ROW, NOT A CONFIG KEY, AND THE CONF NO LONGER NAMES ONE. A flat
# key-value config describes exactly one directory, which is why several domains were never
# expressible. AUTH_BACKEND=ldap is still read from the file — that is a choice of backend,
# not a directory — but every SETTING comes from this row, whose id `default` is what
# qualifies every subject as `default\<user>`.
#
# The LDAP_* lines were deliberately removed from the fixtures: leaving them after the
# reader stopped consulting them masked a real bug, because the console gated its directory
# endpoints on cfg.ldap_uris and the fixture kept that gate satisfied.
seed_ldap_provider default "$LURI" "dc=fastpki,dc=test" || {
    echo "cannot seed the directory — every assertion below would measure a deployment"
    echo "with no directories at all, which is not what this suite is about."; exit 1; }
trap 'pg_cleanup; cleanup' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
mkconf(){ # extra-lines -> bootstrap.conf
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=ldap
EST_BIND=127.0.0.1
EST_PORT=$EPORT
CERT_VALIDITY_DAYS=365
$1
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
}
start_est(){
  "$EST" --config bootstrap.conf >srv.log 2>&1 & P=$!
  # `cacerts` needs no credentials and no CSR, so it answers as soon as the listener is
  # serving — the cheapest question that proves the server is ready to be asked a real one.
  wait_http $P "https://127.0.0.1:$EPORT/.well-known/est/ca/cacerts" \
    || { echo "fastpki-est did not come up:"; tail -20 srv.log; }
}
  # ⚠️ THE CREDENTIAL CARRIES ITS DIRECTORY. An unqualified name is a LOCAL account -- it is
  # never tried against a directory -- so every caller below, all of whom are directory users,
  # must present `<directory>\user`. Qualified here rather than at seventeen call sites, and
  # only when the caller did not already name one, which is the rule the sign-in page's domain
  # picker applies too.
  qual(){ case "$1" in *\\*|*@*) printf '%s' "$1";; *) printf '%s\\%s' "${DIR_ID:-default}" "$1";; esac; }
  enroll(){ # user pass subject -> issue|reject
    set -- "$(qual "$1")" "$2" "$3"
  "$OSSL" req -new -subj "/CN=$3" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr >/dev/null 2>&1
  "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
  local out; out=$(curl -sk -u "$1:$2" --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
      "https://127.0.0.1:$EPORT/.well-known/est/ca/simpleenroll" \
      | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null)
  echo "$out" | grep -q "BEGIN CERTIFICATE" && echo issue || echo reject
}

# ⚠️ An LDAP subject needs an EXPLICIT grant now, and this suite used to assume it
# did not. `AuthResult::role` defaults to empty on purpose:
#
#   "A default role is a grant nobody made. Empty means 'this subject claims nothing',
#    and the gate decides from the tables."
#
# It used to default to `requester` — a seeded console role holding est:enrol|*, so any
# username that bound successfully got an enrolment-capable role nobody had granted it.
# A role with permissions to no profile simply has its request denied. So
# authenticating is no longer the same thing as being allowed to enrol,
# and every assertion below that expects issuance has to say which grant carries it.
# ⚠️ A DIRECTORY IDENTITY IS AUTHORIZED UNDER `<provider>\<user>`, NOT THE BARE NAME.
# The login name is split before the bind and the directory that accepted it qualifies the
# subject, so a grant keyed on `alice` is a grant nobody can match: the subject arriving at
# the gate is `default\alice`. A config-derived directory carries the id `default`.
# Group selectors are NOT qualified — they are spelled as the directory spells them.
DIR_ID='default'
Q_ALICE="$DIR_ID"'\alice'
# Groups are provider-qualified too now, exactly like subjects: a grant names the
# directory it belongs to, so a same-named group in another directory is a different
# selector and carries none of its authority.
Q_ENROLLERS="$DIR_ID"'\PKI-Enrollers'
Q_BOB="$DIR_ID"'\bob'
Q_CAROL="$DIR_ID"'\carol'
pg_exec "INSERT INTO subject_roles(selector_type,selector_value,role)
         VALUES('user','$Q_ALICE','requester') ON CONFLICT DO NOTHING;" >/dev/null
mkconf ""; start_est
if ! kill -0 $P 2>/dev/null; then echo "fastpki-est died:"; cat srv.log; exit 1; fi
chk "valid LDAP credentials + a role grant -> issue" issue "$(enroll alice alicepass host.internal)"
# ⚠️ The discriminator. Without this, EVERY assertion in the auth block below is satisfied
# by a blanket refusal — which is exactly how this suite read 12/3 while LDAP enrolment
# was entirely broken, since its negative cases cannot tell "wrong password" from
# "nothing works at all".
chk "  same credentials, NO grant -> reject"        reject "$(enroll bob bobpass host2.internal)"
chk "wrong LDAP password -> reject (401)" reject "$(enroll alice wrongpass host.internal)"
chk "unknown LDAP user -> reject (401)"   reject "$(enroll ghost whatever  host.internal)"
chk "empty password -> reject"            reject "$(enroll alice ''        host.internal)"
AF=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='auth_fail' AND detail LIKE '%EST%';")
chk "LDAP auth failures are audited (>=3)" yes "$([ "${AF:-0}" -ge 3 ] && echo yes || echo no)"
kill $P 2>/dev/null; wait $P 2>/dev/null

echo "=== An LDAP subject gets the wildcard from a ROLE GRANT — there is no config list ==="
# ⚠️ This section has now been wrong in BOTH directions, so read the history before editing.
#
# Originally it asserted "a master LDAP user may request a wildcard". Removing
# the role->profile shim made that false, which is what was reported. The assertion
# was then inverted to "MASTER_USERS alone does NOT grant a wildcard".
#
# Removed MASTER_USERS outright — no master users, no globals — which settles the
# question: an LDAP subject has no web_users row, so the ONLY
# thing that can carry a role for it is a `subject_roles` grant. auth.cpp assigns no role
# from any config key any more.
#
# The chain being pinned: subject_roles(user=alice) -> `admin` -> `profile:use|admin` ->
# alice's profile union contains `admin` -> that profile allows a wildcard. Every link is a
# row an operator can see and edit; asserting only "it issues" would not distinguish that
# from a hardcoded list.
pg_exec "UPDATE subject_roles SET role='admin' WHERE selector_type='user' AND selector_value='$Q_ALICE';" >/dev/null
# bob holds `requester`, so the contrast below is PROFILE scope and nothing else: both
# subjects authenticate, both carry a grant, and only the profile differs. Without a grant
# bob would be refused for lacking a role, and the wildcard assertion would pass for the
# wrong reason — the failure mode this is about.
pg_exec "INSERT INTO subject_roles(selector_type,selector_value,role)
         VALUES('user','$Q_BOB','requester') ON CONFLICT DO NOTHING;" >/dev/null
mkconf ""; start_est
chk "an LDAP subject granted 'admin' CAN request a wildcard" issue "$(enroll alice alicepass '*.internal')"
chk "  a subject granted only 'requester' cannot"            reject "$(enroll bob bobpass '*.internal')"
chk "  ...and that subject still enrols a plain CN"          issue  "$(enroll bob bobpass 'plain.internal')"
kill $P 2>/dev/null; wait $P 2>/dev/null

# THE MECHANISM, measured twice over.
# (1) Take the profile grant off the `admin` role: the same subject, same config, loses it.
pg_exec "DELETE FROM role_permissions WHERE role='admin' AND permission='profile:use' AND scope='admin';" >/dev/null
mkconf ""; start_est
chk "revoke admin's profile grant -> the SAME user is refused" reject "$(enroll alice alicepass '*.internal')"
kill $P 2>/dev/null; wait $P 2>/dev/null
pg_exec "INSERT INTO role_permissions(role,permission,scope) VALUES('admin','profile:use','admin'), ('admin','profile:edit','admin')
         ON CONFLICT DO NOTHING;" >/dev/null
# (2) Take the SUBJECT grant away instead: same result, from the other end of the chain.
pg_exec "DELETE FROM subject_roles WHERE selector_type='user' AND selector_value='$Q_ALICE';" >/dev/null
mkconf ""; start_est
chk "revoke alice's subject_roles grant -> refused again"      reject "$(enroll alice alicepass '*.internal')"
kill $P 2>/dev/null; wait $P 2>/dev/null
pg_exec "INSERT INTO subject_roles(selector_type,selector_value,role)
         VALUES('user','$Q_ALICE','admin') ON CONFLICT DO NOTHING;" >/dev/null

echo "=== an LDAP subject moves profile by EDITING ITS ROLE, which is the only lever ==="
# ⚠️ An LDAP subject claims NO role of its own. auth.cpp's ldap branch returns AuthResult
# with `role` empty (a default role is a grant nobody made), and there is no config
# key that could fill it — DEFAULT_ROLE is gone. So an LDAP subject's roles are
# exactly what `subject_roles` grants it, and adding one only ADDS to the union, leaving
# two members and nothing to choose between.
#
# What an operator actually does is edit the builtin in the Roles editor, which the model makes
# a supported act. Re-scope `requester`'s profile grant and every LDAP subject moves with
# it — no second table, no priority, one row.
pg_exec "UPDATE role_permissions SET scope='admin'
          WHERE role='requester' AND permission='profile:use';" >/dev/null
U=$(pg_exec "SELECT count(*) FROM role_permissions WHERE role='requester' AND permission LIKE 'profile:%';" | tr -d ' ')
chk "PRECONDITION: requester still holds exactly ONE profile grant" 1 "$U"
mkconf ""; start_est
chk "re-scoped to 'admin', an ordinary LDAP subject CAN request a wildcard" issue \
    "$(enroll bob bobpass '*.internal')"
kill $P 2>/dev/null; wait $P 2>/dev/null
pg_exec "UPDATE role_permissions SET scope='requester'
          WHERE role='requester' AND permission='profile:use';" >/dev/null
mkconf ""; start_est
chk "put back, the same subject is refused again" reject "$(enroll bob bobpass '*.internal')"
kill $P 2>/dev/null; wait $P 2>/dev/null

echo "=== A role granted to an LDAP GROUP authorizes its members ==="
# ⚠️ WHAT THIS PINS, AND WHY IT COULD BE BELIEVED FOR MONTHS WITHOUT BEING TRUE.
#
# `subject_roles` has long had a `group` selector kind, and the console has imported
# LDAP group names into it — an admin could open the Roles page, pick a real
# directory group out of a real picker, grant it a role, and see the row saved. Nothing
# ever resolved a user's memberships, so `roles_for_subject` was only ever asked about
# `user`, and every one of those group rows was a grant that could not match anything.
#
# It fails SILENTLY and in the safe direction: the subject is simply refused, which looks
# exactly like a subject who was never granted anything. There is no error, no log line,
# nothing in the console to say the grant is inert. So the assertion below is deliberately
# about a user who has NO `user` grant at all — carol's only path to a role is her group.
# If group resolution regresses, she loses enrolment and this goes red.
pg_exec "DELETE FROM subject_roles WHERE selector_value='$Q_CAROL';" >/dev/null
# ⚠️ bob carries a `user` grant from the section above, which would authorize him no matter
# what his GROUP holds — measured: without this delete he enrols and the negative case below
# passes for the wrong reason. Both subjects must reach the gate with their group as their
# ONLY possible source of a role, or the comparison says nothing about groups.
pg_exec "DELETE FROM subject_roles WHERE selector_type='user' AND selector_value='$Q_BOB';" >/dev/null
pg_exec "INSERT INTO subject_roles(selector_type,selector_value,role)
         VALUES('group','$Q_ENROLLERS','requester') ON CONFLICT DO NOTHING;" >/dev/null
mkconf ""; start_est
chk "PRECONDITION: neither carol nor bob holds a 'user' grant" 0 \
    "$(pg_exec "SELECT count(*) FROM subject_roles WHERE selector_type='user'
                 AND selector_value IN ('$Q_CAROL','$Q_BOB');" | tr -d ' ')"
chk "carol enrols on her GROUP's grant alone" issue "$(enroll carol carolpass grouped.internal)"
# ⚠️ The discriminator for the discriminator. bob is in a DIFFERENT group, one that holds
# no grant. Without him, "carol can enrol" would also pass if group membership were being
# ignored and every authenticated LDAP user let through — the failure shape where a
# blanket answer satisfies the positive case.
chk "  bob, in a group with NO grant, is still refused" reject \
    "$(enroll bob bobpass bystander.internal)"
kill $P 2>/dev/null; wait $P 2>/dev/null

# The mechanism from the other end: take the GROUP's grant away and the same user, same
# directory, same config, loses enrolment. This is the positive control — it is what makes
# the assertion above evidence rather than a coincidence.
pg_exec "DELETE FROM subject_roles WHERE selector_type='group' AND selector_value='$Q_ENROLLERS';" >/dev/null
mkconf ""; start_est
chk "revoke the GROUP grant -> carol is refused" reject "$(enroll carol carolpass grouped2.internal)"
kill $P 2>/dev/null; wait $P 2>/dev/null
pg_exec "INSERT INTO subject_roles(selector_type,selector_value,role)
         VALUES('group','$Q_ENROLLERS','requester') ON CONFLICT DO NOTHING;" >/dev/null

  # ⚠️ A SAME-NAMED GROUP IN ANOTHER DIRECTORY CARRIES NO AUTHORITY. This is the defect the
  # qualification exists for: group selectors were bare CNs matched by plain string
  # equality, so a role granted to one domain's `PKI-Enrollers` authorized every other
  # domain's identically-named group the moment a second directory was configured — a
  # silent privilege widening that no page in the console would show.
  #
  # The grant here names a directory this deployment does not even have. Under the old
  # bare-name matching it would have authorized carol regardless, because only the CN was
  # compared; qualified, it is simply a different selector and she is refused.
  pg_exec "DELETE FROM subject_roles WHERE selector_type='group' AND selector_value='$Q_ENROLLERS';" >/dev/null
  pg_exec "INSERT INTO subject_roles(selector_type,selector_value,role)
           VALUES('group','other-dir\\PKI-Enrollers','requester') ON CONFLICT DO NOTHING;" >/dev/null
  mkconf ""; start_est
  chk "a grant to ANOTHER directory's same-named group does not authorize" reject \
      "$(enroll carol carolpass crossdir.internal)"
  kill $P 2>/dev/null; wait $P 2>/dev/null
  pg_exec "DELETE FROM subject_roles WHERE selector_type='group' AND selector_value='other-dir\\PKI-Enrollers';" >/dev/null
  pg_exec "INSERT INTO subject_roles(selector_type,selector_value,role)
           VALUES('group','$Q_ENROLLERS','requester') ON CONFLICT DO NOTHING;" >/dev/null

echo "=== The audit names the role that GRANTED, not the one that was carried ==="
# Point 3 of the ticket. A subject carrying a word that is not a console role — `standard`,
# the issuance-namespace name every older account holds, and until this change the
# hardcoded default of MsAuth — used to be recorded verbatim as `role=standard` while the
# request was authorized by something else entirely. An audit line that names a value the
# decision did not use is worse than one that names nothing, because it reads as an answer.
#
# `certs.role` used to disagree the same way; that column is gone, so the audit detail
# is the whole of what remains.
# ⚠️ THE ROW IS KEYED ON THE QUALIFIED SUBJECT, not on the name typed at the prompt. An
# onboarded directory account is stored under `<provider>\<user>`, so seeding it bare
# would leave the login finding nothing and arriving with no role at all — which is not
# the case this section is about.
pg_exec "INSERT INTO web_users(username,role,hash,must_reset,created)
         VALUES('$Q_CAROL','standard','!external',0,0)
         ON CONFLICT (username) DO UPDATE SET role='standard', hash='!external';" >/dev/null
mkconf ""; start_est
chk "a user row with no local password still authenticates via LDAP" issue \
    "$(enroll carol carolpass audited.internal)"
# Scoped to THIS certificate's CN: carol has enrolled before in this run, so an unscoped
# count measures the whole suite's history rather than the row under test.
chk "  the audit records the GRANTING role" 1 \
    "$(pg_exec "SELECT count(*) FROM audit_log WHERE actor='$Q_CAROL' AND action='cert_issued'
                 AND detail LIKE '%cn=audited.internal%' AND detail LIKE '%role=requester%';" | tr -d ' ')"
chk "  and never the carried placeholder" 0 \
    "$(pg_exec "SELECT count(*) FROM audit_log WHERE actor='$Q_CAROL' AND action='cert_issued'
                 AND detail LIKE '%role=standard%';" | tr -d ' ')"
kill $P 2>/dev/null; wait $P 2>/dev/null

echo "=== The CONSOLE honours AUTH_BACKEND (it used to ignore it entirely) ==="
# /api/login did its own find_user + verify_password and never called pki::authenticate(),
# so AUTH_BACKEND=ldap applied to EST and MS-XCEP and not to the console: measured on a
# live deployment, a directory account got 200 from `/msxcep/{ca}` and 401 from the console
# with the same credential.
WEB="$BUILD/fastpki-web"
if [ ! -x "$WEB" ]; then
  echo "  [SKIP] fastpki-web not built"
else
  cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$WPORT
AUTH_BACKEND=ldap
LOG_LEVEL=err
EOF
  "$WEB" --config web.conf >web.log 2>&1 & WP=$!
  wait_http $WP "http://127.0.0.1:$WPORT/api/me" || { echo "fastpki-web did not come up:"; tail -20 web.log; }
  chk "fastpki-web started" yes "$(kill -0 $WP 2>/dev/null && echo yes || echo no)"
  # ⚠️ A PRECONDITION, not decoration. `000` from curl is "no HTTP response at all", and it
  # compares unequal to 200 AND to 401 — so a console that never came up would fail every
  # assertion below and read exactly like a broken login. This one distinguishes them.
  chk "  and serves its index"        200 \
      "$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$WPORT/" 2>/dev/null)"
  # The session cookie is kept: /api/me and /api/config below are authenticated, and
  # without a jar every one of them would 401 and read as a broken endpoint.
  WORK_JAR="$W/cookies.txt"
  # Same rule as `enroll` above: a directory login says which directory.
  login(){ curl -s -c "$WORK_JAR" -o /dev/null -w "%{http_code}" -X POST \
             --data-urlencode "username=$(qual "$1")" --data-urlencode "password=$2" \
             "http://127.0.0.1:$WPORT/api/login" 2>/dev/null; }
  chk "a directory identity can log in to the console" 200 "$(login carol carolpass)"
  chk "  wrong directory password is still 401"        401 "$(login carol wrongpass)"
  chk "  a username in neither store is still 401"     401 "$(login ghost whatever)"
  # ⚠️ NOT a formality — this is the half of the fix that is easy to leave out. carol
  # already carries a `!external` row (seeded above, and federated_role() writes exactly
  # that shape when it onboards someone). Without the fallthrough added to authenticate(),
  # a row like that is authoritative and can only ever say no: the console fix alone would
  # let each directory user in exactly once, persist their row, and lock them out forever
  # after. Logging in twice is what distinguishes the two.
  chk "  and can log in AGAIN once a row exists for them" 200 "$(login carol carolpass)"

  # ── the four spellings that name one directory ────────────────────────────────────
  # A Windows domain is known by a NetBIOS short name, a DNS root and a Kerberos realm
  # (the root upper-cased), and there is no string conversion between the short name and
  # the FQDN — AD keeps a crossRef object mapping one to the other. With only the provider
  # id to match, a deployment accepted ONE of these and refused the rest as an unknown
  # domain. Re-seeded here with both names, and every spelling must reach the same
  # directory and authenticate the same person against a real slapd.
  seed_ldap_provider default "$LURI" "dc=fastpki,dc=test" "" "" \
                     --netbios CORP --dns-root corp.contoso.com
  # ⚠️ ITS OWN COOKIE JAR. `login()` writes the SHARED $WORK_JAR, and this section ends
  # with two deliberate 401s — which would leave that jar holding no session and fail
  # every later assertion in the suite that reuses it. Measured: six of them, and they
  # read as group-membership and ownership bugs rather than as a clobbered cookie.
  SPELL_JAR="$W/spelling-cookies.txt"
  slogin(){ curl -s -c "$SPELL_JAR" -o /dev/null -w "%{http_code}" -X POST \
              --data-urlencode "username=$1" --data-urlencode "password=$2" \
              "http://127.0.0.1:$WPORT/api/login" 2>/dev/null; }
  # ⚠️ UNQUALIFIED IS LOCAL, SO IT IS REFUSED HERE. `carol` exists in the directory and the
  # password is right, and it still must not authenticate: a name with no qualifier means the
  # web_users table, which holds no such row. Binding a bare name against each directory in
  # turn until one accepted let the PASSWORD choose the authority when two domains held the
  # same username, and sent that password to every directory on the way. There is no "how
  # many directories are configured" case -- this is what the name MEANS.
  chk "an UNQUALIFIED name is refused (it means a local account)" 401 "$(slogin carol carolpass)"
  chk "  by provider id"                             200 "$(slogin 'default\carol' carolpass)"
  chk "  by NetBIOS short name"                      200 "$(slogin 'CORP\carol' carolpass)"
  chk "  by NetBIOS short name, other case"          200 "$(slogin 'corp\carol' carolpass)"
  chk "  by DNS root"                                200 "$(slogin 'carol@corp.contoso.com' carolpass)"
  chk "  by Kerberos realm (the root upper-cased)"   200 "$(slogin 'carol@CORP.CONTOSO.COM' carolpass)"
  # ⚠️ THE HALF THAT STOPS THE FIVE ABOVE BEING VACUOUS. If the domain part were simply
  # ignored — stripped and thrown away — every spelling above would pass while naming
  # nothing. A domain that matches no directory must still be refused, and the right
  # password must not rescue it.
  chk "  a domain that names NO directory is refused" 401 "$(slogin 'NOPE\carol' carolpass)"
  chk "  and neither is an unknown DNS root"          401 "$(slogin 'carol@nosuch.example' carolpass)"
  # And the stored names come back out, so an operator can see what a directory answers to.
  PLIST=$("$ROOT/build/fastpki-config" --config <(printf 'PG_CONNINFO=%s\n' "$PG_CONNINFO") \
            auth-providers-list 2>/dev/null)
  chk "  the CLI shows the NetBIOS name"  yes "$(echo "$PLIST" | grep -q 'netbios=CORP' && echo yes || echo no)"
  chk "  and the DNS root"                yes "$(echo "$PLIST" | grep -q 'dns-root=corp.contoso.com' && echo yes || echo no)"
  # The two names stay on the row: they are additional spellings, and the rest of the suite
  # logs in unqualified or by id, both of which still resolve. Re-seeding to "restore" it
  # would REPLACE the row (auth-providers-add is an upsert over both tables), which is a
  # bigger side effect than the one it would be undoing.

  echo "=== The console lists every LDAP key the parser accepts ==="
  # The console listed 5 of 9. The 4 it omitted include BOTH settings the console's own
  # "Import groups from LDAP" button needs, so an operator working from the UI could not
  # fix that feature — and the error it printed blamed the directory.
  #
  # ⚠️ Asserted against the SET the parser accepts, not a hand-written list, so a key added
  # to config.cpp and forgotten in the console fails here instead of shipping invisible.
  # ⚠️ An ADMIN session. carol holds `requester` at most, and /api/config is gated on
  # `config:manage` — asked as carol every key reads as "missing" and the assertion
  # blames the console for what is a correct refusal.
  seed_web_user cfgadmin cfgpass admin
  AJAR="$W/cookies-admin.txt"
  curl -s -c "$AJAR" -o /dev/null -X POST --data-urlencode "username=cfgadmin" \
       --data-urlencode "password=cfgpass" "http://127.0.0.1:$WPORT/api/login" 2>/dev/null
  CFG=$(curl -s -b "$AJAR" "http://127.0.0.1:$WPORT/api/config" 2>/dev/null)
  chk "PRECONDITION: the admin session can read /api/config" yes \
      "$(echo "$CFG" | grep -q 'AUTH_BACKEND' && echo yes || echo no)"
  PARSED=$(grep -oE '"LDAP_[A-Z_]+"' "$ROOT/src/lib/config.cpp" | tr -d '"' | sort -u)
  MISSING=""
  for k in $PARSED; do
    echo "$CFG" | grep -q "\"$k\"" || MISSING="$MISSING $k"
  done
  chk "every LDAP_* key config.cpp accepts is shown in the console" "" "$MISSING"
  chk "  LDAP_BIND_PW is present but REDACTED" no \
      "$(echo "$CFG" | grep -q 'adminpass' && echo yes || echo no)"

  echo "=== /api/me reports the roles that actually apply ==="
  # carol's web_users row says `standard`; her enrolment role comes from the PKI-Enrollers
  # GROUP grant. Before this, /api/me reported the row's word alone, so a directory user
  # holding real capability was displayed as holding none.
  ME=$(curl -s -b "$WORK_JAR" "http://127.0.0.1:$WPORT/api/me" 2>/dev/null)
  chk "the session's effective roles include the GROUP-granted one" yes \
      "$(echo "$ME" | grep -q '"roles":\[[^]]*"requester"' && echo yes || echo no)"
  chk "  and the group that conferred it is named" yes \
      "$(echo "$ME" | grep -q "\"groups\":\[[^]]*\"$DIR_ID\\\\\\\\PKI-Enrollers\"" && echo yes || echo no)"
  # ⚠️ REGRESSION GUARD, and the reason it lives here rather than in an AD-only test.
  # Added two AD-specific searches beside the portable one: a primary-group lookup by
  # objectSid, and nested membership via LDAP_MATCHING_RULE_IN_CHAIN
  # (1.2.840.113556.1.4.1941). OpenLDAP has neither, so what this pins is that they stay
  # ADDITIVE — the portable answer must be unchanged, with nothing extra leaking in.
  #
  # ⚠️ Two honest limits on this assertion. It does NOT go red if the primary-group support is reverted (with no
  # extra searches the set is still exactly PKI-Enrollers) — it is a portability guard, not
  # a guard for the AD behaviour, which is measured against the live domain instead. And
  # the control I ran for it was NOT a revert but the design alternative: folding the
  # matching rule into the single portable filter. That stayed 48/0, so the claim that it
  # "would break OpenLDAP" is false for this slapd and is not made anywhere.
  chk "  the group set is EXACTLY the directory's answer (no AD-only search leaked in)" yes \
      "$(echo "$ME" | sed -n 's/.*"groups":\[\([^]]*\)\].*/\1/p' \
         | tr -d ' "' | tr ',' '\n' | sort | tr '\n' ',' | grep -qxF "$(printf '%s\\\\PKI-Enrollers,' "$DIR_ID")" && echo yes || echo no)"
  # ⚠️ NOT ASSERTED HERE, deliberately: that the AD-only searches log nothing on OpenLDAP.
  # This suite runs the console at LOG_LEVEL=err and the line in question is log::info, so
  # a grep for it CANNOT FAIL either way — it would pass against a build that shouted on
  # every login. An assertion whose healthy and broken answers are identical is a
  # decoration; the quiet flag is visible in the code and belongs to a suite that runs at
  # info if we ever want it measured.
  echo "=== The directory's users and a group's MEMBERS are readable from the console ==="
  # An operator granting a role to one person had to hand-create the
  # web_users row and get the username exactly right — and a row that does not match what
  # the directory presents at sign-in never applies, with nothing reporting the mismatch.
  # And at import "`Admins` and `Auditors` are indistinguishable in a list; membership is
  # precisely what differs. In this lab the two were mapped to each other'"'"'s roles for a
  # while and nothing on screen could have revealed it."
  LU=$(curl -s -b "$AJAR" "http://127.0.0.1:$WPORT/api/ldap/users" 2>/dev/null)
  chk "the user picker is enabled"                yes "$(echo "$LU" | grep -q '"enabled":true' && echo yes || echo no)"
  # ⚠️ QUALIFIED, LIKE THE GROUP PICKER. Whatever this list offers is what the import flow
  # stores as a `user` selector -- and an UNQUALIFIED selector means the LOCAL web_users
  # table, so a grant made from a bare listing landed on a local account of the same name and
  # never on the directory identity it was made for. Two directories' `alice` also rendered
  # identically here, which is the group-name collision one table over.
  # -F with a literal two-character backslash pair: the qualifier is `default\alice` in the
  # value, and JSON escapes it, so the BODY carries `default\\alice`. A regex here would
  # need four backslashes to say that and reads as a typo either way.
  for who in alice bob carol; do
    WANT="\"username\":\"$DIR_ID\\\\$who\""
    chk "  it lists $who, qualified by its directory" yes \
        "$(echo "$LU" | grep -qF "$WANT" && echo yes || echo no)"
  done
  chk "  and offers NO bare username at all"      no  \
      "$(echo "$LU" | grep -qE '"username":"(alice|bob|carol)"' && echo yes || echo no)"
  # The GROUPS must not come back as users: groupOfNames has a cn too, and a picker that
  # offered PKI-Enrollers as a person would create a web_users row that can never log in.
  chk "  and does NOT offer a group as a user"    no  "$(echo "$LU" | grep -q '"username":"PKI-Enrollers"' && echo yes || echo no)"
  LUQ=$(curl -s -b "$AJAR" "http://127.0.0.1:$WPORT/api/ldap/users?q=car" 2>/dev/null)
  # ⚠️ PIN THE `username` KEY, not a bare substring. Matching just `carol"` would also be
  # satisfied by a display name or a DN fragment ending in that value, so the cell would stop
  # testing the field it is named for.
  chk "  the q filter narrows to carol"           yes \
      "$(echo "$LUQ" | grep -qF "\"username\":\"$DIR_ID\\\\carol\"" && echo yes || echo no)"
  chk "  and excludes the others"                 no  \
      "$(echo "$LUQ" | grep -qF "\"username\":\"$DIR_ID\\\\bob\"" && echo yes || echo no)"

  # ⚠️ THE DISCRIMINATING PAIR. Both groups exist and both have exactly one member; only
  # the MEMBER differs. A members endpoint that returned the same thing for both — or the
  # group's own name, or nothing — would pass a "did it answer?" check and be useless for
  # the confusion the ticket describes.
  # ⚠️ THE GROUP IS NAMED AS THE PICKER OFFERS IT: `<directory>\<group>`, percent-encoded.
  # The endpoint asks ONE directory -- the one the qualifier names -- so a bare name is not a
  # directory group at all and is refused rather than broadcast to every directory and merged.
  # Members come back qualified for the same reason the user picker's do: they are the same
  # people, and a bare name here would be a LOCAL one by the naming rule.
  ENC="$DIR_ID%5C"
  M1=$(curl -s -b "$AJAR" "http://127.0.0.1:$WPORT/api/ldap/groups/${ENC}PKI-Enrollers/members" 2>/dev/null)
  M2=$(curl -s -b "$AJAR" "http://127.0.0.1:$WPORT/api/ldap/groups/${ENC}PKI-Bystanders/members" 2>/dev/null)
  QC="\"username\":\"$DIR_ID\\\\carol\""
  QB="\"username\":\"$DIR_ID\\\\bob\""
  chk "PKI-Enrollers lists carol"                 yes "$(echo "$M1" | grep -qF "$QC" && echo yes || echo no)"
  chk "  and NOT bob"                             no  "$(echo "$M1" | grep -qF "$QB" && echo yes || echo no)"
  chk "PKI-Bystanders lists bob"                  yes "$(echo "$M2" | grep -qF "$QB" && echo yes || echo no)"
  # An UNQUALIFIED group is refused outright -- it is the shape that used to be asked of every
  # directory at once, which is how two domains' identically-named groups became one answer.
  MU=$(curl -s -b "$AJAR" "http://127.0.0.1:$WPORT/api/ldap/groups/PKI-Enrollers/members" 2>/dev/null)
  chk "  an UNqualified group name is refused"    yes \
      "$(echo "$MU" | grep -q 'not a directory group' && echo yes || echo no)"
  chk "  and it lists nobody"                     no  "$(echo "$MU" | grep -q '"username"' && echo yes || echo no)"
  chk "  and NOT carol"                           no  "$(echo "$M2" | grep -q '"username":"carol"' && echo yes || echo no)"

  # ⚠️ A NESTED GROUP IS NOT A PERSON. PKI-Enrollers also has cn=PKI-Nested in its member
  # list. Resolving a member DN used a bare (objectClass=*) BASE search and handed the
  # entry to read_user_entry, which accepts anything carrying a `cn` — and every group has
  # one. So the group came back as a member named "PKI-Nested": an account offered for
  # import that can never log in. ldap_list_users has always applied user_object_filter()
  # and the assertion right below pins that for ITS endpoint; this path skipped it.
  chk "  and NOT the nested GROUP in its member list" no \
      "$(echo "$M1" | grep -q '"username":"PKI-Nested"' && echo yes || echo no)"
  # …and the person reached only through that nested group is not silently promoted either:
  # nested expansion is a separate feature, and inventing it here would be worse than not
  # having it. alice is in PKI-Nested and in no other group under PKI-Enrollers.
  chk "  nor alice, who is only in the nested group"  no \
      "$(echo "$M1" | grep -q '"username":"alice"' && echo yes || echo no)"

  # ⚠️ THE PATH SEGMENT IS ALREADY DECODED. cpp-httplib decodes req.path before routing
  # and deliberately does NOT map '+' to space there. The handler decoded a SECOND time
  # and did map it, so a group whose name legally contains '+' was looked up as one
  # containing a space and found nothing — reported as "no members". Only names containing
  # spaces and nothing else were ever tried, which is why it looked right.
  MP=$(curl -s -b "$AJAR" "http://127.0.0.1:$WPORT/api/ldap/groups/${ENC}Field%2BOps/members" 2>/dev/null)
  QA="\"username\":\"$DIR_ID\\\\alice\""
  chk "a group whose name contains '+' resolves"  yes \
      "$(echo "$MP" | grep -qF "$QA" && echo yes || echo no)"
  chk "  and it is echoed back unmangled"         yes \
      "$(echo "$MP" | grep -qF "\"group\":\"$DIR_ID\\\\Field+Ops\"" && echo yes || echo no)"

  # ⚠️ A REFUSED SEARCH IS NOT AN EMPTY GROUP, again. Only a failed BIND reached the
  # error field, so a directory that authenticated us and then failed the search answered
  # `{"members":[]}` with HTTP 200 and no searchError — and the console rendered "this
  # group has no members". A base DN that does not exist makes the server return
  # LDAP_NO_SUCH_OBJECT for the SEARCH while the BIND still succeeds, which is exactly the
  # shape being guarded and needs no second directory.
  BPORT=$((WPORT+40))
  # ⚠️ THE BASE DN IS A ROW, so breaking it means REWRITING THE PROVIDER, not sed-ing the
  # config. This block used to substitute LDAP_BASE_DNS in the conf file; nothing reads a
  # directory's settings from a file any more, so that edit changed nothing, the search
  # succeeded, and the two assertions below failed against a working directory — a fixture
  # that had quietly stopped setting up the condition it was testing.
  #
  # Repointed and then put back, because the provider is global: every server sharing this
  # database sees it. Nothing else is asserted between these two calls.
  seed_ldap_provider default "$LURI" "dc=nosuch,dc=place" \
    || { echo "cannot repoint the directory at a bad base"; }
  sed -e "s|^WEB_PORT=.*|WEB_PORT=$BPORT|" web.conf > badbase.conf
  "$WEB" --config badbase.conf >badweb.log 2>&1 & BP=$!
  wait_http $BP "http://127.0.0.1:$BPORT/api/me" || { echo "fastpki-web (bad base) did not come up:"; tail -20 badweb.log; }
  # The same admin account — it lives in the shared Postgres, not in the directory, so a
  # broken LDAP base does not stop the console session that asks the question.
  curl -s -c "$W/bad.cj" -o /dev/null -X POST --data-urlencode "username=cfgadmin" \
       --data-urlencode "password=cfgpass" "http://127.0.0.1:$BPORT/api/login" 2>/dev/null
  MB=$(curl -s -b "$W/bad.cj" "http://127.0.0.1:$BPORT/api/ldap/groups/PKI-Enrollers/members" 2>/dev/null)
  kill $BP 2>/dev/null; wait $BP 2>/dev/null
  # Put the real base back before anything else asks the directory a question.
  seed_ldap_provider default "$LURI" "dc=fastpki,dc=test" \
    || { echo "cannot restore the directory base — later assertions are unsafe"; exit 1; }
  # ⚠️ PRECONDITION: prove the request was actually served. `{}` from a dead console would
  # satisfy "members is empty" and fail "searchError present" — reading as the bug when it
  # is really a harness failure.
  chk "PRECONDITION: the bad-base console answered"  yes \
      "$(echo "$MB" | grep -q '"enabled":true' && echo yes || echo no)"
  chk "a FAILED search reports searchError, not zero members" yes \
      "$(echo "$MB" | grep -q '"searchError"' && echo yes || echo no)"
  chk "  and the member list is genuinely empty"  yes \
      "$(echo "$MB" | grep -q '"members":\[\]' && echo yes || echo no)"

  echo "=== The Users tab can answer 'who does this grant actually reach?' ==="
  # Once a group is mapped there was no way to answer "who does this actually grant
  # access to?" without going to a domain controller — and for a PKI that is the first
  # question an auditor asks.
  #
  # carol is a member of PKI-Enrollers and that group carries a grant, so she must appear
  # WITH the group named. Asserted through the API, which is the part a shell suite can
  # actually judge; the rendering is grep-proxied below.
  DS=$(curl -s -b "$AJAR" "http://127.0.0.1:$WPORT/api/directory-subjects" 2>/dev/null)
  chk "the directory-subjects endpoint is enabled"  yes \
      "$(echo "$DS" | grep -q '"enabled":true' && echo yes || echo no)"
  chk "  carol appears as a group-derived subject"  yes \
      "$(echo "$DS" | grep -q '"username":"carol"' && echo yes || echo no)"
  chk "  and the CONFERRING group is named"         yes \
      "$(echo "$DS" | grep -q "\"via\":\"$DIR_ID\\\\\\\\PKI-Enrollers\"" && echo yes || echo no)"
  # ⚠️ THE DISCRIMINATOR. bob is in PKI-Bystanders, which carries NO grant — so he must be
  # absent. An endpoint that listed every directory user, or every member of every group,
  # would satisfy the two assertions above and be useless: the question is who the GRANTS
  # reach, not who exists.
  # ⚠️ This one does NOT go red on a revert — with the endpoint gone nothing is listed at
  # all. It guards a different wrong answer, and the more likely one: an endpoint that
  # returned every directory user, or every member of every group, would satisfy both
  # assertions above and be useless. The question is who the GRANTS reach, not who exists.
  chk "  bob, whose group has no grant, is NOT listed" no \
      "$(echo "$DS" | grep -q '"username":"bob"' && echo yes || echo no)"

  # ⚠️ THE CASE the user/computer distinction is really about. A domain computer
  # has NO account of its own — it reaches the console only
  # as a member of a granted group — so this endpoint is the ONLY one that will ever name
  # it, and until this change it was also the only producer with no `kind` at all. The
  # console then rendered `user` beside a machine, which is what he had already flagged
  # once on the account row.
  #
  # WS-BOX$ is a member of PKI-Enrollers, exactly like carol, so the two rows differ ONLY
  # in the name — which is the whole input to pki::principal_kind().
  chk "  a machine in a granted group is listed at all"  yes \
      "$(echo "$DS" | grep -q '"username":"WS-BOX\$"' && echo yes || echo no)"
  chk "  and it is reported kind=computer"               yes \
      "$(echo "$DS" | grep -q '"username":"WS-BOX\$","display":"[^"]*","kind":"computer"' && echo yes || echo no)"
  # ⚠️ THE CONTROL. carol comes through the identical code path in the identical group; if
  # she were also `computer` the assertion above would be worthless.
  chk "  while carol, same group, is kind=user"          yes \
      "$(echo "$DS" | grep -q '"username":"carol","display":"[^"]*","kind":"user"' && echo yes || echo no)"
  # And the other half of the same rule: the "import a user" picker must still EXCLUDE the
  # machine. That exclusion used to spell `back() == '$'` out for itself; it asks the
  # shared classifier now, so this is what proves the shared one still refuses it.
  chk "  the user-import picker does NOT offer the machine" no \
      "$(curl -s -b "$AJAR" "http://127.0.0.1:$WPORT/api/ldap/users" 2>/dev/null \
         | grep -q '"username":"WS-BOX\$"' && echo yes || echo no)"

  # ⚠️ Grep-proxies on the served page — a shell suite cannot run the JS (§3e). They catch
  # the reintroduction that matters: the API landing with nothing calling it. The
  # first half was exactly that shape (`source` shipped server-side and the console
  # never rendered it), so "endpoint exists" is not the thing to assert.
  UPAGE=$(curl -s -b "$AJAR" "http://127.0.0.1:$WPORT/" 2>/dev/null)
  chk "the console offers a USER import, not only groups" yes \
      "$(echo "$UPAGE" | grep -q 'Import user from LDAP' && echo yes || echo no)"
  chk "  and it calls /api/ldap/users"            yes \
      "$(echo "$UPAGE" | grep -q "/api/ldap/users" && echo yes || echo no)"
  chk "  writing a 'user' selector, like groups write 'group'" yes \
      "$(echo "$UPAGE" | grep -q "selector_type', 'user'" && echo yes || echo no)"
  chk "the import dialog can expand a group's members" yes \
      "$(echo "$UPAGE" | grep -q "/api/ldap/groups/' + encodeURIComponent" && echo yes || echo no)"
  chk "the Subjects tab merges directory-derived rows" yes \
      "$(echo "$UPAGE" | grep -q "/api/directory-subjects" && echo yes || echo no)"
  # ⚠️ NOT a grep for "via '" — that string already occurs elsewhere in the page, so it
  # passed against the unmodified build. Match the row builder's own markup instead.
  chk "  and renders which group conferred the role"  yes \
      "$(echo "$UPAGE" | grep -q "o.via||\[\]).length ? '<span class=\"muted\"" && echo yes || echo no)"
  # ⚠️ A WRITER WITH NO READER. DIRSUBJ_ERR was assigned from the endpoint's searchError
  # and rendered NOWHERE, so a refused membership search showed the local rows alone with
  # nothing to say the directory half was missing — the same screen, again. The commit
  # message for 92b1e1f claimed it was "carried and shown"; only the carrying was true.
  # Asserted as a READ of the variable, since assigning it is what already existed.
  # ⚠️ Two assertions, because the READ and the RENDER are separate failures: a page can
  # compute the banner and never concatenate it. (And not `\|` alternation — BSD grep does
  # not read that as alternation, so a single combined pattern silently never matches.)
  chk "  and a refused directory search is SHOWN, not just carried" yes \
      "$(echo "$UPAGE" | grep -qF 'const dirWarn = DIRSUBJ_ERR' && echo yes || echo no)"
  chk "    …and the banner reaches the panel"       yes \
      "$(echo "$UPAGE" | grep -qF 'dirWarn +' && echo yes || echo no)"
  chk "    …with the message naming what is missing" yes \
      "$(echo "$UPAGE" | grep -q 'directory members are NOT listed' && echo yes || echo no)"

  echo "=== A group-granted enrolment role mints credentials ==="
  # Reported: LDAP/SAML users had no CMP or ACME credentials shown on the Dashboard and
  # could not download client config files.
  #
  # mint_enrol_creds asked roles_for_subject with the USER selector alone, so carol — whose
  # enrolment role comes from the PKI-Enrollers GROUP — looked like she held no enrolling
  # role: nothing was minted, the Dashboard had nothing to show, and the client configs had
  # no credential to substitute. Meanwhile the RBAC gate, which DOES union the groups, was
  # letting her enrol. Asserted in the DATABASE and then through the download, because a
  # config file served with an unsubstituted {{...}} is the same failure wearing a 200.
  CRED=$(pg_exec "SELECT count(*) FROM keys WHERE kid='$Q_CAROL';" 2>/dev/null | tr -d ' ')
  chk "carol has enrolment credentials minted"  yes "$([ "${CRED:-0}" -gt 0 ] && echo yes || echo no)"
  curl -s -b "$WORK_JAR" "http://127.0.0.1:$WPORT/api/client-config/acme" -o carol-acme.ini 2>/dev/null
  # ⚠️ THIS ONE DOES NOT DISCRIMINATE, and the fact that it cannot is the finding. Measured
  # both ways: the download SUCCEEDS with or without the fix. The ticket says "cannot
  # download client config files", but nothing 404s or 500s — the file arrives, and the
  # credential line in it is EMPTY. Kept as the control that says so out loud.
  chk "  her ACME config downloads (control: passes either way)" yes \
      "$([ -s carol-acme.ini ] && echo yes || echo no)"
  # ⚠️ COMPARE THE VALUE, DO NOT GREP FOR IT. The kid IS the subject, so it now carries a
  # backslash — and a backslash inside a grep pattern is an escape, not a character, so a
  # pattern built from the expected name would quietly mean something else. Extracting the
  # field and comparing it also puts the wrong value in the failure message instead of a
  # bare `no`.
  chk "  and carries a real EAB kid, not a token" "$Q_CAROL" \
      "$(grep '^eab-kid' carol-acme.ini 2>/dev/null | head -1 | sed 's/^eab-kid[[:space:]]*=[[:space:]]*//')"
  # Also non-discriminating, for the same reason: the substitution replaces the token with
  # an EMPTY STRING rather than leaving `{{ACME_EAB_KID}}` behind, so a file with no
  # credential in it still passes a "nothing unsubstituted" check. That is why the
  # assertion above names the VALUE — an empty setting wearing a 200 is the actual bug.
  chk "  with nothing left unsubstituted (control: passes either way)" no \
      "$(grep -q '{{' carol-acme.ini && echo yes || echo no)"

  echo "=== The rest of the credential path resolves the SAME identity ==="
  # Taught mint_enrol_creds to union the group selectors and left three siblings on
  # the user selector alone, so they each disagreed with it about who carol is.
  #
  # ⚠️ ITS OWN CONSOLE, because this section needs WRITES. The shared web.conf above does
  # not set WEB_ALLOW_REVOKE, so every console write returns 403 "console writes disabled"
  # — measured. Asserting against that instance would have made both checks below pass
  # without reaching the code at all: the role write is refused, so nothing deletes the
  # credentials, and "they survived" reads as a fix. A decoration, not a guard.
  RWPORT=$((WPORT+41))
  sed -e "s|^WEB_PORT=.*|WEB_PORT=$RWPORT|" web.conf > rw.conf
  echo "WEB_ALLOW_REVOKE=true" >> rw.conf
  "$WEB" --config rw.conf >rwweb.log 2>&1 & RWP=$!
  wait_http $RWP "http://127.0.0.1:$RWPORT/api/me" || { echo "fastpki-web (revoke) did not come up:"; tail -20 rwweb.log; }
  RWA="$W/rw-admin.txt"; RWC="$W/rw-carol.txt"
  curl -s -c "$RWA" -o /dev/null -X POST --data-urlencode "username=cfgadmin" \
       --data-urlencode "password=cfgpass" "http://127.0.0.1:$RWPORT/api/login" 2>/dev/null
  curl -s -c "$RWC" -o /dev/null -X POST --data-urlencode "username=$(qual carol)" \
       --data-urlencode "password=carolpass" "http://127.0.0.1:$RWPORT/api/login" 2>/dev/null
  # ⚠️ PRECONDITIONS. Without these a 403 from a dead console, an unauthenticated admin or
  # a still-read-only instance is indistinguishable from the bug.
  chk "PRECONDITION: the writable console answers as admin" 200 \
      "$(curl -s -o /dev/null -w '%{http_code}' -b "$RWA" "http://127.0.0.1:$RWPORT/api/me" 2>/dev/null)"
  chk "PRECONDITION: carol has a session on it"             200 \
      "$(curl -s -o /dev/null -w '%{http_code}' -b "$RWC" "http://127.0.0.1:$RWPORT/api/me" 2>/dev/null)"

  # ⚠️ THE DESTRUCTIVE ONE. sync_enrolment_creds runs on every write that could change a
  # subject's roles and DELETES the credentials when the answer holds no enrolling role.
  # carol's web_users row says `standard`; her enrolment role is the PKI-Enrollers grant.
  # So an unrelated grant written against her name made the console revoke, on the spot,
  # the credentials just minted.
  WROTE=$(curl -s -o /dev/null -w '%{http_code}' -b "$RWA" -X POST \
       "http://127.0.0.1:$RWPORT/api/subject-roles" \
       --data-urlencode "selector_type=user" --data-urlencode "selector_value=$Q_CAROL" \
       --data-urlencode "role=auditor" 2>/dev/null)
  chk "PRECONDITION: the role write was ACCEPTED, not refused" 201 "$WROTE"
  CRED2=$(pg_exec "SELECT count(*) FROM keys WHERE kid='$Q_CAROL';" 2>/dev/null | tr -d ' ')
  chk "…and it does NOT delete her group-granted credentials" yes \
      "$([ "${CRED2:-0}" -gt 0 ] && echo yes || echo no)"

  # The rotation handler, which refuses 409 "holds no role that permits enrolment" when it
  # cannot see the group — for a user the RBAC gate is admitting on that very group.
  RC=$(curl -s -o /dev/null -w '%{http_code}' -b "$RWC" -X POST \
       "http://127.0.0.1:$RWPORT/api/enrolment-credentials" 2>/dev/null)
  chk "she can rotate her own credentials (not 409)" 200 "$RC"
  # ⚠️ Decode what the DB HOLDS: a 200 that rotated nothing would pass the line above.
  CRED3=$(pg_exec "SELECT count(*) FROM keys WHERE kid='$Q_CAROL';" 2>/dev/null | tr -d ' ')
  chk "  and a credential is still there afterwards" yes \
      "$([ "${CRED3:-0}" -gt 0 ] && echo yes || echo no)"
  kill $RWP 2>/dev/null; wait $RWP 2>/dev/null

  echo "=== A directory user with a group-granted requester role sees ONLY their own ==="
  # Reported: an LDAP user with the requester role saw certificates under My Certificates
  # that they do not own — and the same for SAML users.
  #
  # ⚠️ WHY THIS CANNOT LIVE IN web_selfservice.sh, which already covers self-service. That
  # suite creates a LOCAL user whose stored role is the literal word `requester`, and the
  # old code scoped on exactly that string — so it passed against the bug. What was broken
  # is the case where the EFFECTIVE role is requester but the stored word is not, which is
  # every directory user whose role arrives through a group grant. Same shape as its siblings and
  # A gate reading the role STRING instead of the permission table.
  #
  # Two certificates go in directly, because what is under test is the read path'"'"'s owner
  # filter, not issuance.
  LEAFDER=$("$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -days 2 \
            -subj "/CN=scoping.test" -outform DER 2>/dev/null | od -An -v -tx1 | tr -d ' \n')
  NOW=$(date +%s); LATER=$((NOW + 86400))
  # ⚠️ THE OWNER IS THE QUALIFIED SUBJECT, THE CN IS JUST A LABEL. They were one field
  # here, which cannot survive qualification: the owner filter matches `default\carol`
  # while the assertion below greps for a hostname. Keeping them separate also stops a
  # backslash reaching a DNS name it has no business being in.
  for row in "aa287:$Q_CAROL:carol" "bb287:someone-else:someone-else"; do
    ser="${row%%:*}"; rest="${row#*:}"; own="${rest%:*}"; label="${rest##*:}"
    pg_exec "INSERT INTO certs(serial,status,cert,subject,cn,owner,is_ca,\"notBefore\",\"notAfter\") \
             VALUES('$ser',0,decode('$LEAFDER','hex'),'/CN=$label.scoping.test','$label.scoping.test', \
                    '$own',false,$NOW,$LATER) ON CONFLICT (serial) DO UPDATE SET owner='$own';" >/dev/null 2>&1
  done
  CERTS=$(curl -s -b "$WORK_JAR" "http://127.0.0.1:$WPORT/api/certs?limit=1000" 2>/dev/null)
  chk "carol sees the certificate she owns"            yes \
      "$(echo "$CERTS" | grep -q 'carol.scoping.test' && echo yes || echo no)"
  # THE assertion. Before the fix this came back yes: role_of() returned her stored word,
  # which is not "requester", so no owner filter was applied at all and she saw the estate.
  chk "  and NOT one owned by somebody else"           no  \
      "$(echo "$CERTS" | grep -q 'someone-else.scoping.test' && echo yes || echo no)"
  # The same filter guards the detail route, so a serial guessed by hand is refused too —
  # a list that hides a row while /api/certs/<serial> still serves it is not scoping.
  chk "  and the detail route refuses the other one"   no  \
      "$(curl -s -o /dev/null -w '%{http_code}' -b "$WORK_JAR" \
         "http://127.0.0.1:$WPORT/api/certs/bb287" 2>/dev/null | grep -q '^200$' && echo yes || echo no)"

  # ⚠️ The discriminator: `capabilities` was ALREADY correct before this change, so an
  # assertion on capabilities alone would have passed against the bug. What was wrong is
  # the SUMMARY beside them, which is what an operator reads.
  chk "  capabilities agree (they always did — this is the control)" yes \
      "$(echo "$ME" | grep -q '"capabilities":\[[^]]*"est:enrol"' && echo yes || echo no)"
  echo "=== The Users tab distinguishes a local account from a directory one ==="
  # The Source column existed and said "db" for every row, which distinguishes nothing.
  # carol was onboarded with the `!external` sentinel; cfgadmin has a real PBKDF2 hash.
  U=$(curl -s -b "$AJAR" "http://127.0.0.1:$WPORT/api/users" 2>/dev/null)
  chk "a password account reports source=local" yes \
      "$(echo "$U" | grep -o '{[^}]*cfgadmin[^}]*}' | grep -q '"source":"local"' && echo yes || echo no)"
  chk "  a directory-backed account reports the BACKEND" yes \
      "$(echo "$U" | grep -o '{[^}]*carol[^}]*}' | grep -q '"source":"ldap"' && echo yes || echo no)"
  chk "  and no row still says the meaningless 'db'" 0 \
      "$(echo "$U" | grep -o '"source":"db"' | wc -l | tr -d ' ')"
  echo "=== The profile gate sees the same identity the RBAC gate did ==="
  # ⚠️ AUTHORIZED, THEN REFUSED. The RBAC gate unions the session's directory groups in via
  # roles_of(), so a user holding `admin` through a group grant PASSES the permission
  # check — and the console then built ProfileIdentity{owner, role_of(req)} with NO groups,
  # so profiles_for_identity() saw only the stored role (`none` for an onboarded directory
  # user), matched no profile grant, and resolve_profile threw:
  #
  #   "policy: this identity holds no profile permission, so no certificate profile applies"
  #
  # Two gates disagreeing about who the caller is, in one request. Both go through
  # subject_roles(); the bug was handing them different identities.
  # ⚠️ carol's STORED role must contribute NOTHING, or this proves nothing. She was given
  # `standard` earlier in this suite; `standard` is not a console role but the profile
  # union is computed from what subject_roles() returns, and leaving any second source in
  # place made the assertion pass with the fix REVERTED — measured. `none` is also what an
  # onboarded directory user actually has, which is the case the ticket reports.
  pg_exec "UPDATE web_users SET role='none' WHERE username='$Q_CAROL';" >/dev/null
  pg_exec "DELETE FROM subject_roles WHERE selector_type='user' AND selector_value='$Q_CAROL';" >/dev/null
  pg_exec "INSERT INTO subject_roles(selector_type,selector_value,role)
           VALUES('group','$Q_ENROLLERS','admin') ON CONFLICT DO NOTHING;" >/dev/null
  curl -s -c "$WORK_JAR" -o /dev/null -X POST --data-urlencode "username=$(qual carol)" \
       --data-urlencode "password=carolpass" "http://127.0.0.1:$WPORT/api/login" 2>/dev/null
  # ⚠️ /api/my-profiles, NOT /api/profiles. The latter returns every configured profile
  # from cfg and never looks at the caller — asking it proved nothing, and it passed with
  # the fix reverted (measured twice before I read the handler).
  PROF=$(curl -s -b "$WORK_JAR" "http://127.0.0.1:$WPORT/api/my-profiles" 2>/dev/null)
  chk "PRECONDITION: the group grant reaches the RBAC gate" yes \
      "$(curl -s -b "$WORK_JAR" "http://127.0.0.1:$WPORT/api/me" 2>/dev/null \
         | grep -q '"roles":\[[^]]*"admin"' && echo yes || echo no)"
  # The profile list is what the profile gate computes for this identity. Empty is the bug.
  chk "  and her ONLY role source is the group" none \
      "$(pg_exec "SELECT role FROM web_users WHERE username='$Q_CAROL';" | tr -d ' ')"
  # ⚠️ AND WHICH PROFILE, not merely "non-empty": `admin` is reachable only through the
  # profile:use|admin grant that carol holds via her GROUP, so it is the discriminator even
  # if the list were ever padded again.
  chk "the profile union contains the GROUP-granted profile" yes \
      "$(echo "$PROF" | grep -q '"admin"' && echo yes || echo no)"
  echo "=== The auth provider is RECORDED per identity, not derived from a config key ==="
  # The Source value used to be computed at read time from AUTH_BACKEND, whose only legal
  # values are `local` and `ldap`. So SAML and OIDC identities — written with the same
  # `!external` sentinel — rendered as `ldap` on any deployment configured that way, and
  # changing the key retroactively relabelled every existing external row.
  #
  # ⚠️ ASSERTED IN THE DATABASE, not just the API: the point is that the fact is
  # STORED. A reader that still computed the right answer from config would satisfy an
  # API-only check while leaving the bug in place.
  chk "a directory login records auth_provider=ldap" ldap \
      "$(pg_exec "SELECT auth_provider FROM web_users WHERE username='$Q_CAROL';" | tr -d ' ')"
  chk "  a password account records 'local'"         local \
      "$(pg_exec "SELECT auth_provider FROM web_users WHERE username='cfgadmin';" | tr -d ' ')"
  # ⚠️ The discriminator for "recorded, not derived": change AUTH_BACKEND and the stored
  # value must NOT move. Under the old scheme every external row's label followed this key.
  pg_exec "UPDATE web_users SET role=role WHERE username='$Q_CAROL';" >/dev/null
  chk "  and a later UPDATE does not erase it"       ldap \
      "$(pg_exec "SELECT auth_provider FROM web_users WHERE username='$Q_CAROL';" | tr -d ' ')"
  chk "  the API reports the stored value"           yes \
      "$(curl -s -b "$AJAR" "http://127.0.0.1:$WPORT/api/users" 2>/dev/null \
         | grep -o '{[^}]*carol[^}]*}' | grep -q '"source":"ldap"' && echo yes || echo no)"

  # ⚠️ THE PLACEHOLDER MUST BE REFINABLE. Step 0027 backfills a pre-0027 row from its
  # password hash, which can only say "not a local password" — so it writes `external`,
  # meaning "we do not know which directory yet". If a login treats that as a settled
  # answer, such a row reads `external` forever while authenticating against LDAP every
  # day. Measured in exactly that state on all three lab DCs after 27052ba, where admin1
  # and audit1 came out of the backfill as `external`. Reproduced here by putting the
  # placeholder back and logging in again.
  pg_exec "UPDATE web_users SET auth_provider='external' WHERE username='$Q_CAROL';" >/dev/null
  chk "  the 0027 placeholder is in place"          external \
      "$(pg_exec "SELECT auth_provider FROM web_users WHERE username='$Q_CAROL';" | tr -d ' ')"
  curl -s -c "$WORK_JAR" -o /dev/null -X POST --data-urlencode "username=$(qual carol)" \
       --data-urlencode "password=carolpass" "http://127.0.0.1:$WPORT/api/login" 2>/dev/null
  chk "  a login REFINES 'external' to the real provider" ldap \
      "$(pg_exec "SELECT auth_provider FROM web_users WHERE username='$Q_CAROL';" | tr -d ' ')"
  kill $WP 2>/dev/null; wait $WP 2>/dev/null
fi

echo
echo "=== LDAP AUTH: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
