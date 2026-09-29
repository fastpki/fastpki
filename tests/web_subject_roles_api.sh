#!/usr/bin/env bash
# Console role-assignment CRUD API (slice 2b). Admin manages the
# many-to-many subject_roles map over /api/subject-roles; a granted role takes
# effect immediately via the union RBAC gate. Drives the whole flow through the
# API (no direct DB writes) — assign, list, see the union take effect, delete,
# see it revoked — plus input validation.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
# Only adopt the system openssl.cnf where it really is one. On macOS this path is a
# stub that defines no providers, and exporting it breaks every pkcs11 load — the
# CA key then cannot be minted and the suite SKIPs for a reason that looks nothing
# like "wrong openssl.cnf". Tests must not assume a Linux layout (§3d).
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18095
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
acode(){ curl -s -o /dev/null -w '%{http_code}' -b admin.cj "$@"; }   # as admin
ccode(){ curl -s -o /dev/null -w '%{http_code}' -b carol.cj "$U$1"; } # as carol

pg_setup web_subject_roles_api
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
ca_in_token ca.pem "/CN=Web CA" 3650
source "$ROOT/tests/user_helpers.sh"
seed_web_user admin adminpw admin
seed_web_user carol carolpw auditor
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat srv.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c admin.cj -d 'username=admin&password=adminpw' "$U/api/login" >/dev/null
curl -s -c carol.cj -d 'username=carol&password=carolpw' "$U/api/login" >/dev/null

echo "=== RBAC: only admin may reach the role-assignment API ==="
chk "admin GET /api/subject-roles (200)"      200 "$(acode "$U/api/subject-roles")"
chk "auditor GET /api/subject-roles (403)"    403 "$(ccode /api/subject-roles)"

echo "=== validation ==="
chk "bad role rejected (400)"          400 "$(acode -X POST "$U/api/subject-roles?selector_type=user&selector_value=carol&role=superuser")"
chk "bad selector_type rejected (400)" 400 "$(acode -X POST "$U/api/subject-roles?selector_type=box&selector_value=carol&role=tpl-writer")"

echo "=== carol (auditor) cannot reach templates before the grant ==="
chk "templates denied (403)" 403 "$(ccode /api/templates)"

# `template-editor` is gone, so the EXTRA role carol is granted has to be a
# real one that actually unlocks templates — otherwise this whole section asserts nothing.
pg_exec "INSERT INTO roles(name,description,builtin) VALUES('tpl-writer','writes templates',false)
           ON CONFLICT DO NOTHING;
         INSERT INTO role_permissions(role,permission,scope) VALUES('tpl-writer','template:use','*'), ('tpl-writer','template:edit','*')
           ON CONFLICT DO NOTHING;" >/dev/null
echo "=== admin grants tpl-writer to carol via the API ==="
chk "POST grant (201)" 201 "$(acode -X POST "$U/api/subject-roles?selector_type=user&selector_value=carol&role=tpl-writer")"
chk "GET lists the mapping" yes "$(curl -s -b admin.cj "$U/api/subject-roles" | grep -q '"selector_value":"carol"' && grep -q '"role":"tpl-writer"' <<<"$(curl -s -b admin.cj "$U/api/subject-roles")" && echo yes || echo no)"

echo "=== union now in effect for carol (via API grant) ==="
chk "templates now allowed (200)"        200 "$(ccode /api/templates)"
chk "still holds base auditor (200)"     200 "$(ccode /api/audit)"
chk "no admin escalation: config (403)"  403 "$(ccode /api/config)"

echo "=== admin revokes the grant via the API ==="
chk "DELETE grant (200)" 200 "$(acode -X DELETE "$U/api/subject-roles?selector_type=user&selector_value=carol&role=tpl-writer")"
chk "templates denied again (403)" 403 "$(ccode /api/templates)"
chk "base auditor intact (200)"    200 "$(ccode /api/audit)"

echo "=== ⚠️ a client-certificate DN is NOT a role subject ==="
# The rule: x509 certificates are about authentication, not authorization — in the PKI
# model authorization lives externally, not inside the certificate. "Users, groups and
# DNs" means the user table, not the certificate subject: a role stays outside the DN, in
# a table column, and is never part of the DN itself.
#
# ⚠️ WHY REFUSING MATTERS MORE THAN IT LOOKS. `dn` was never a working feature now being
# withdrawn: the console offered it, POST stored it and mesh.cpp replicated the row to
# every DC — and NOTHING read it. Every selector list is built from ("user",user) and
# ("group",g) only, so the grant matched nobody, on any node. An operator granted console
# access, watched the row appear in the Subjects tab and replicate, and access was never
# configured. A 400 is the difference between "you cannot do that" and a promise silently
# unkept. This section is ~vacuous on the old binary in the honest direction: it returns
# 201 and writes the row, so all three of the first assertions go red.
chk "selector_type=dn rejected (400)" 400 \
    "$(acode -X POST "$U/api/subject-roles?selector_type=dn&selector_value=CN=box.internal&role=tpl-writer")"
# ⚠️ Ask the DB, not the status code — a refusal that still wrote the row is exactly the
# shape this ticket is about, and it would be invisible from the response alone.
chk "  and no dn row was written" 0 \
    "$(pg_exec "SELECT count(*) FROM subject_roles WHERE selector_type='dn';" | tr -d ' ')"
# CONTROL: the two surviving types must still be accepted, or a handler that 400s on
# everything would satisfy the assertion above for entirely the wrong reason.
chk "CONTROL: selector_type=group still accepted (201)" 201 \
    "$(acode -X POST "$U/api/subject-roles?selector_type=group&selector_value=pki-admins&role=tpl-writer")"
chk "CONTROL: selector_type=user still accepted (201)" 201 \
    "$(acode -X POST "$U/api/subject-roles?selector_type=user&selector_value=carol&role=tpl-writer")"
acode -X DELETE "$U/api/subject-roles?selector_type=group&selector_value=pki-admins&role=tpl-writer" >/dev/null
acode -X DELETE "$U/api/subject-roles?selector_type=user&selector_value=carol&role=tpl-writer"      >/dev/null
# The console must not offer what the API refuses. The shape: two halves of one rule
# disagreeing, with only the visible half noticed.
chk "the served console offers no dn option" yes \
    "$(curl -s -b admin.cj "$U/" | grep -q '<option value="dn">' && echo no || echo yes)"

echo
echo "=== WEB SUBJECT-ROLES API: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
