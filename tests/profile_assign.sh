#!/usr/bin/env bash
# Which certificate policy profile an identity issues under (reshaped so that
# slice 2). A profile is no longer SELECTED for a subject by a `profile_assignments` row —
# it is a RESOURCE a ROLE holds `profile:use`/`profile:use` on, and the profiles a subject's
# roles hold form a UNION with no priority.
#
# Driven through EST end to end: the same user enrols before and after the grant, and the
# issued cert's EKU reflects it; revoking the last grant REFUSES issuance (slice 5 —
# there is no CA-default fallback any more). A grant to
# a role this user does NOT hold must not affect them.
#
# ⚠️ The subject needs a CONSOLE role for any of this to apply. `subject_roles.known` is
# the subset of a subject's roles that are rows in `roles`, so a user holding only an
# ISSUANCE role (`master`/`standard`) has no grants, an EMPTY union, and keeps the CA
# default — the same inert case `may_enrol` has, and the reason this suite gives tester a
# real role.
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
W="$(mktemp -d)"; cd "$W"; PORT=18270
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

ca_in_token ca.pem "/CN=Assign CA" 3
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup profile_assign
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
# ⚠️ A CLONE OF `requester`, NOT THE BUILTIN. This suite's last section grants a SECOND
# profile to a role tester holds, and two profiles with none named in the request are
# MERGED — `requester`'s allowances would then still apply, and the narrowing this suite
# measures would not show. Holding the builtin made that unavoidable, because its
# `profile:use|requester` grant cannot be dropped for one user without changing the builtin
# for everyone.
# (tester used to hold the issuance name `standard`; that is not a roles row, so it
# carried no profile at all and the question never arose.)
pg_exec "INSERT INTO roles(name,description,builtin) VALUES('testerrole','test: tester base',false)
         ON CONFLICT (name) DO NOTHING;" >/dev/null
pg_exec "INSERT INTO role_permissions(role,permission,scope)
           SELECT 'testerrole', permission, scope FROM role_permissions WHERE role='requester'
         ON CONFLICT DO NOTHING;" >/dev/null
seed_web_user tester s3cret-t testerrole

# A custom profile that only permits clientAuth, so it is distinguishable from the CA
# default. ⚠️ The discriminator is NOT "serverAuth present" any more: the rename emptied
# `requester`'s default EKU by design, so a certificate issued under
# the CA default now carries NO ExtendedKeyUsage extension at all. Asserting its ABSENCE
# is the stronger test anyway — "no serverAuth" is also true of a cert that was never
# issued, and `dflt` below rejects an empty PEM for exactly that reason.
PJSON='{"clientonly":{"allowed_ku":["digitalSignature"],"allowed_eku":["clientAuth"],"default_ku":["digitalSignature"],"default_eku":["clientAuth"],"allow_wildcard":false}}'
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$PORT
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
seed_cert_profiles "$PJSON"
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)

start(){ "$ROOT/build/fastpki-est" --config bootstrap.conf >srv.log 2>&1 & SRV=$!; sleep 1; }
stop(){ kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; }
trap 'pg_cleanup; kill $SRV 2>/dev/null' EXIT
# grant <role> <profile>  /  revoke <role> <profile>
grant(){  pg_exec "INSERT INTO roles(name) VALUES('$1') ON CONFLICT DO NOTHING;
                   INSERT INTO role_permissions(role,permission,scope) VALUES('$1','profile:use','$2')
                   ON CONFLICT DO NOTHING;"; }
revoke(){ pg_exec "DELETE FROM role_permissions WHERE role='$1' AND permission='profile:use' AND scope='$2';"; }
# Give a user an extra console role, the many-to-many way the console does (slice 2b).
#
# ⚠️ THE ROLE MUST ALSO GRANT est:enrol, and this cost me a debugging pass. Before the role
# is held, tester's only role is the ISSUANCE role `standard`, which is not a `roles` row —
# so may_enrol's `known.empty()` case makes the gate INERT and the request goes through.
# Holding a real console role ends that: the gate now recognises the subject and refuses
# them unless the role grants the protocol. Giving a user a console role to carry a profile
# grant therefore ALSO subjects them to the enrolment gate, which is correct and is exactly
# the composition the union relies on — but it means a fixture that grants only
# `profile:use` produces no certificate at all, and every EKU assertion then reads "no" in
# both directions.
hold(){   pg_exec "INSERT INTO roles(name) VALUES('$2') ON CONFLICT DO NOTHING;
                   INSERT INTO role_permissions(role,permission,scope) VALUES('$2','est:enrol','*')
                   ON CONFLICT DO NOTHING;
                   INSERT INTO subject_roles(selector_type,selector_value,role,created) VALUES('user','$1','$2',0) ON CONFLICT DO NOTHING;"; }
unhold(){ pg_exec "DELETE FROM subject_roles WHERE selector_type='user' AND selector_value='$1' AND role='$2';"; }
enroll(){ # -> issued PEM
  "$OSSL" req -new -subj "/CN=host.internal" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr >/dev/null 2>&1
  "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
  curl -sk -u tester:s3cret-t --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
    "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll" \
    | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null
}
eku(){ echo "$1" | "$OSSL" x509 -noout -ext extendedKeyUsage 2>/dev/null; }
# "this cert was issued AND carries no EKU" — the CA default now. Both
# halves matter: without the first, a failed enrolment passes as a default-profile cert.
dflt(){ [ -n "$(echo "$1" | grep "BEGIN CERTIFICATE")" ] \
        && [ -z "$(echo "$2" | grep -i "Extended Key Usage")" ] && echo yes || echo no; }

echo "=== no profile grant: the CA default (issued, no EKU) ==="
start
C=$(enroll); E=$(eku "$C")
chk "issued under the CA default" yes "$(dflt "$C" "$E")"

echo "=== a grant on a role the user does NOT hold does not reach them ==="
grant other-role clientonly
C=$(enroll); E=$(eku "$C")
chk "tester still gets the CA default" yes "$(dflt "$C" "$E")"

echo "=== granting profile:use to a role tester HOLDS changes what they issue under ==="
# Two steps, and both are load-bearing: the grant alone reaches nobody, and the role alone
# grants nothing. Asserting after each is what tells the two apart when this goes red.
hold tester dept-a
C=$(enroll); E=$(eku "$C")
chk "the role alone changes nothing"  yes "$(dflt "$C" "$E")"
grant dept-a clientonly
# ...and drop the base profile, so the union is exactly the granted one. Otherwise this
# measures ambiguity rather than the grant.
pg_exec "DELETE FROM role_permissions WHERE role='testerrole' AND permission='profile:use';" >/dev/null
C=$(enroll); E=$(eku "$C")
chk "now clientAuth only (granted profile)" yes "$([ "$(has "$E" 'Client')" = yes ] && [ "$(has "$E" 'Server')" = no ] && echo yes || echo no)"
# ⚠️ An empty $C makes every EKU assertion answer "no" in BOTH directions, which reads as
# "the profile did not apply" when the truth is "nothing was issued". Say which it is.
[ -n "$C" ] || { echo "    --- enrolment produced NO cert; server said ---"; tail -8 srv.log | sed 's/^/    /'; }

echo "=== revoking the LAST grant refuses issuance — there is no CA default to fall back to ==="
# ⚠️ THIS ASSERTION CHANGED SIDES, and that is the point of the no-defaults rule. It used to expect
# the CA default: revoke the only profile grant and the subject still got a certificate,
# just an unprofiled one. That is ruled out: a role with no permission to any profile
# denies the request, so an empty union now refuses.
#
# Asserting the REFUSAL rather than deleting the section is what keeps the revoke path
# covered: a grant you cannot take away is not a permission.
revoke dept-a clientonly
C=$(enroll)
chk "no certificate is issued at all" "" "$(printf '%s' "$C" | grep -c 'BEGIN CERTIFICATE' | sed 's/^0$//')"
chk "  and the server says why"       yes \
    "$(tail -20 srv.log | grep -q 'holds no profile permission' && echo yes || echo no)"
stop

echo
echo "=== PROFILE ASSIGN: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
