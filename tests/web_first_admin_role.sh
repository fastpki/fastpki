#!/usr/bin/env bash
# The FIRST console user must be an admin.
#
# The requirement: user `admin` holds role `admin` by default.
#
# ⚠️ Why this is a LOCKOUT and not a cosmetic wrong value. The documented bootstrap
# (docs/deployment.md §4.5, and tests/web_openmode.sh) is: start `fastpki-web` with no users
# and no WEB_TOKEN — it serves /api/* unauthenticated — then `POST /api/users` to "create
# the first admin". Open mode CLOSES the moment user #1 exists. `POST /api/users` used to
# default `role` to `requester`, and `docs/api-reference.md` documented that default, so
# following the documentation exactly produced a first user who:
#   * holds no `user:manage`, so cannot create anybody,
#   * is the reason open mode is now shut,
# and there is no console route left that can mint an admin. A fresh install, bricked, by
# doing what the manual said.
#
# Asserts the ROLE THAT WAS STORED, not the 201 — a create that succeeds with the wrong
# role is exactly the bug.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
W="$(mktemp -d)"; cd "$W"; PORT=18296
P=
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=First Admin CA" 3
cp ca.pem root.pem
pg_setup first_admin_role
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT

cat > web.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_TLS=false
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
seed_ca_from_conf web.conf
# ⚠️ NO web-user is seeded and NO WEB_TOKEN is set. That is the whole fixture: this suite
# is about the console in OPEN MODE, the state a fresh deployment starts in.
"$ROOT/build/fastpki-web" --config web.conf >web.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"
role_of(){ pg_exec "SELECT role FROM web_users WHERE username='$1';" | tr -d ' \r\n'; }

echo "=== PRECONDITION: the console really is in open mode ==="
# Without this the create below could be succeeding for some other reason, and every
# assertion would be measuring a console that was never open.
chk "no users yet"                 0   "$(pg_exec 'SELECT count(*) FROM web_users;' | tr -d ' \r\n')"
chk "/api/users is unauthenticated" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' "$U/api/users")"

echo "=== the first user, created the way docs/deployment.md §4.5 documents (no role named) ==="
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$U/api/users" \
      -d 'username=firstadmin&password=firstadminpw1&create=1')
chk "created (201)" 201 "$C"
chk "⚠️ THE ASSERTION: the first user is an admin" admin "$(role_of firstadmin)"

echo "=== and that user can actually administer — the point of the role ==="
curl -s -c fa.cj -o /dev/null -X POST "$U/api/login" -d 'username=firstadmin&password=firstadminpw1'
chk "can create a second user (201)" 201 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b fa.cj -X POST "$U/api/users" \
        -d 'username=second&password=secondpw123&create=1&role=requester')"
chk "  and that one is a requester, as asked" requester "$(role_of second)"

echo "=== open mode is CLOSED now, which is why the role above had to be right ==="
chk "anonymous is refused" yes \
    "$(c=$(curl -s -o /dev/null -w '%{http_code}' "$U/api/users"); [ "$c" != 200 ] && echo yes || echo no)"

echo "=== with the console closed, a create must NAME a role (no defaults) ==="
C=$(curl -s -o /dev/null -w '%{http_code}' -b fa.cj -X POST "$U/api/users" \
      -d 'username=third&password=thirdpw12345&create=1')
chk "omitting role is refused (400)" 400 "$C"
chk "  and nothing was written" 0 "$(pg_exec "SELECT count(*) FROM web_users WHERE username='third';" | tr -d ' \r\n')"

echo "=== a self-service password change still needs no role, and keeps its own ==="
# The self:manage path reads the role from the stored row, so requiring the parameter
# above must not break it. Without this, the 400 rule silently locks every non-admin out
# of changing their own password.
curl -s -c s2.cj -o /dev/null -X POST "$U/api/login" -d 'username=second&password=secondpw123'
chk "second changes own password (200)" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b s2.cj -X POST "$U/api/users" \
        -d 'username=second&password=brandnewpw99&old=secondpw123')"
chk "  and is STILL a requester (no self-promotion, no demotion)" requester "$(role_of second)"

echo
echo "=== FIRST ADMIN ROLE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
