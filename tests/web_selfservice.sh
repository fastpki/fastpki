#!/usr/bin/env bash
# Self-service "My certs" portal. A standard web user can
# see and revoke ONLY the certs they own, and cannot reach any admin surface.
# Ownership is enforced server-side (the session user), not by a client param.
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
W="$(mktemp -d)"; cd "$W"; PORT=18205
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

pg_setup web_selfservice
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
# Seed: alice owns aa01 + aa03; bob owns bb02.
NOW=$(date +%s)
pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,owner,cn) VALUES
 ('aa01',0,$NOW,$((NOW+86400)),'/CN=a1.internal','alice','a1.internal'),
 ('aa03',0,$NOW,$((NOW+86400)),'/CN=a3.internal','alice','a3.internal'),
 ('bb02',0,$NOW,$((NOW+86400)),'/CN=b2.internal','bob','b2.internal');"
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

echo "=== bootstrap admin + two requester users ==="
chk "create first admin -> 201" 201 "$(code -X POST "$U/api/users" -d 'username=boss&password=bosspw12&role=admin')"
curl -s -c boss.cj -X POST "$U/api/login" -d 'username=boss&password=bosspw12' >/dev/null
chk "create alice (requester) -> 201" 201 "$(code -b boss.cj -X POST "$U/api/users" -d 'username=alice&password=alicepw12&role=requester')"
chk "create bob (requester) -> 201" 201 "$(code -b boss.cj -X POST "$U/api/users" -d 'username=bob&password=bobpw12345&role=requester')"
curl -s -c alice.cj -X POST "$U/api/login" -d 'username=alice&password=alicepw12' >/dev/null

echo "=== alice sees only her own certs ==="
chk "me reports requester role" yes "$(has "$(curl -s -b alice.cj "$U/api/me")" '"role":"requester"')"
LIST=$(curl -s -b alice.cj "$U/api/certs")
chk "list includes alice's aa01" yes "$(has "$LIST" 'aa01')"
chk "list includes alice's aa03" yes "$(has "$LIST" 'aa03')"
chk "list EXCLUDES bob's bb02"   no  "$(has "$LIST" 'bb02')"
# search must not let her widen scope to bob's certs
chk "search can't reach bob's cert" no "$(has "$(curl -s -b alice.cj "$U/api/certs?q=b2.internal")" 'bb02')"

echo "=== per-cert detail + revoke are owner-scoped ==="
chk "alice can read her own cert detail" 200 "$(code -b alice.cj "$U/api/certs/aa01")"
chk "alice cannot see bob's cert (404)" 404 "$(code -b alice.cj "$U/api/certs/bb02")"
chk "alice can revoke her own cert" 200 "$(code -b alice.cj -X POST "$U/api/certs/aa01/revoke?reason=4")"
chk "alice cannot revoke bob's cert (404)" 404 "$(code -b alice.cj -X POST "$U/api/certs/bb02/revoke?reason=4")"
chk "bob's cert still valid in the DB" "0" "$(pg_exec "SELECT status FROM certs WHERE serial='bb02';")"

echo "=== admin surfaces are forbidden to a requester user ==="
# Alice reaches /api/users — but sees ONE row, hers. The status code alone would
# not tell the two outcomes apart, so read the body.
chk "GET /api/users -> 200 (self:manage)" 200 "$(code -b alice.cj "$U/api/users")"
chk "…and it lists only alice" "alice" \
    "$(curl -s -b alice.cj "$U/api/users" | grep -o '"username":"[^"]*"' | sed 's/.*:"//; s/"$//' | tr '\n' ' ' | sed 's/ $//')"
chk "GET /api/audit -> 403"      403 "$(code -b alice.cj "$U/api/audit")"
chk "GET /api/summary -> 403"    403 "$(code -b alice.cj "$U/api/summary")"
chk "GET /api/config/db -> 403"  403 "$(code -b alice.cj "$U/api/config/db")"
chk "GET /api/profiles -> 403"   403 "$(code -b alice.cj "$U/api/profiles")"

echo "=== REVOKING IS NOT READING — the owner check asks cert:revoke ==="
# ⚠️ The two roles below are the whole point, and neither is exotic: they are what the
# union model tells an operator to build. The first cut gated the revoke handler on
# `cert:read`, which gets BOTH of them wrong in the direction that matters.
#
#   auditplus  — reads the whole estate, revokes only its own. Under the old code the
#                read grant skipped the ownership check and it could revoke ANYTHING.
#   revoker    — revokes the whole estate, reads only its own. Under the old code the
#                missing read grant bound it to its own certs and cert:revoke did
#                nothing at all.
#
# alice/bob above cannot see this: a plain requester holds NEITHER capability, so the
# two predicates agree on it and every assertion passes against the bug. That is exactly
# the blind spot that commit message named for this file.
# ⚠️ role_permissions.role is a FK onto roles(name) — seed the role FIRST, or every insert
# below is rejected, the users 400, every request 401s and the section fails for a reason
# that has nothing to do with the bug. That is a broken instrument, not a control.
pg_exec "INSERT INTO roles(name,description,builtin) VALUES
 ('auditplus','reads the estate, revokes only its own',false),
 ('revoker','revokes the estate, reads only its own',false)
 ON CONFLICT (name) DO NOTHING;" >/dev/null
pg_exec "INSERT INTO role_permissions(role,permission,scope) VALUES
 ('auditplus','cert:read','*'),('auditplus','cert:revoke','own'),('auditplus','self:manage','*'),
 ('revoker','cert:revoke','*'),('revoker','cert:read','own'),('revoker','self:manage','*')
 ON CONFLICT DO NOTHING;" >/dev/null
chk "create auditplus user -> 201" 201 "$(code -b boss.cj -X POST "$U/api/users" -d 'username=ap&password=appw123456&role=auditplus')"
chk "create revoker user   -> 201" 201 "$(code -b boss.cj -X POST "$U/api/users" -d 'username=rv&password=rvpw123456&role=revoker')"
curl -s -c ap.cj -X POST "$U/api/login" -d 'username=ap&password=appw123456' >/dev/null
curl -s -c rv.cj -X POST "$U/api/login" -d 'username=rv&password=rvpw123456' >/dev/null

# aa03 is alice's and still valid (aa01 was revoked above).
chk "auditplus CAN read another owner's cert"  200 "$(code -b ap.cj "$U/api/certs/aa03")"
chk "…but CANNOT revoke it (403, not 200)"     403 "$(code -b ap.cj -X POST "$U/api/certs/aa03/revoke?reason=4")"
# ⚠️ Decode what the DATABASE holds, not the status code — a refusal that still revoked
# would report 403 and be the worse bug (memory: issued, stored, reported, and inert).
chk "…and aa03 is STILL VALID in the DB"       "0" "$(pg_exec "SELECT status FROM certs WHERE serial='aa03';")"
# The error must name the capability, so an operator knows which grant to add.
chk "…the refusal names cert:revoke"       yes \
    "$(has "$(curl -s -b ap.cj -X POST "$U/api/certs/aa03/revoke?reason=4")" 'cert:revoke')"

# The converse half, which the old code also got wrong: revoke:all without read:all.
chk "revoker CANNOT read another owner's cert" 404 "$(code -b rv.cj "$U/api/certs/aa03")"
chk "…but CAN revoke it (cert:revoke)"     200 "$(code -b rv.cj -X POST "$U/api/certs/aa03/revoke?reason=4")"
chk "…and the DB now shows it revoked"         "-1" "$(pg_exec "SELECT status FROM certs WHERE serial='aa03';")"

echo
echo "=== WEB SELF-SERVICE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
