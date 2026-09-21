#!/usr/bin/env bash
# (RELEASE BLOCKER): the deployed default admin must change its password before
# the account can be used for anything.
#
# Deployment seeds `admin` / `admin`. A permanent, well-known credential on a PKI
# product is the weak-default class that draws a CVE, so the seed now carries
# `--must-reset` and both doors are shut until the owner sets a new password:
#
#   console (fastpki-web)  — the pre-routing gate lets a must_reset session reach only
#                            /api/me, /api/password and /api/logout.
#   enrolment (EST/MS/...) — pki::authenticate() refuses the row outright.
#
# ⚠️ THE SECOND DOOR IS THE POINT, and it is why this suite starts an EST server as
# well as the console. web_users is ONE table serving both, but fastpki-web does
# its own lookup (`find_user` + `verify_password`) and never calls pki::authenticate().
# So flipping the seed alone would gate the console and leave admin/admin live on the
# path that actually mints certificates — the more dangerous half. Assert both, or this
# suite blesses a half-fix.
#
# Self-contained (§3d): ephemeral Postgres, own ports, temp dir, token-minted CA.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF

W="$(mktemp -d)"; cd "$W"; WP=18492; EP=18493
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

pg_setup default_admin_reset
WEBP=""; SRV=""
trap 'pg_cleanup; kill ${WEBP:-} ${SRV:-} 2>/dev/null' EXIT

# ── the seed, exactly as deploy/bootstrap.sh writes it ────────────────────────
CFG=$(mktemp); printf 'PG_CONNINFO=%s\n' "$PG_CONNINFO" > "$CFG"
"$ROOT/build/fastpki-config" --config "$CFG" web-user admin admin --role admin --must-reset --if-absent >/dev/null 2>&1
chk "the seeded admin is flagged must_reset" 1 \
    "$(pg_exec "select must_reset::int from web_users where username='admin';" | tr -d ' ')"

echo "=== console: admin/admin logs in, and can do NOTHING but change its password ==="
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$WP
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
"$ROOT/build/fastpki-web" --config web.conf >web.log 2>&1 & WEBP=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$WEBP" || true
kill -0 $WEBP 2>/dev/null || { echo "fastpki-web died:"; cat web.log; exit 1; }
U="http://127.0.0.1:$WP"

LOGIN=$(curl -s -c a.cj -X POST "$U/api/login" -d 'username=admin&password=admin')
chk "the default password still logs in"      yes "$(has "$LOGIN" '"user":"admin"')"
chk "  and the reply says a reset is required" yes "$(has "$LOGIN" '"mustReset":true')"

# The three the gate deliberately allows — an account that cannot see its own session or
# reach the password form could never complete the reset.
chk "/api/me is reachable"        200 "$(code -b a.cj "$U/api/me")"
# ...and everything else is refused. These are the ones that matter: an admin session
# that can still administer is not gated at all.
chk "/api/users is refused"       403 "$(code -b a.cj "$U/api/users")"
chk "/api/ca-instances is refused" 403 "$(code -b a.cj "$U/api/ca-instances")"
chk "/api/certs is refused"       403 "$(code -b a.cj "$U/api/certs")"
chk "creating a user is refused"  403 "$(code -b a.cj -X POST "$U/api/users" -d 'create=1&username=x&password=xpass12345&role=admin')"
chk "  and no user was created"   0 "$(pg_exec "select count(*) from web_users where username='x';" | tr -d ' ')"

echo "=== enrolment: the same row cannot mint a certificate either (the second door) ==="
ca_in_token ca.pem "/CN=Reset CA" 3 || { echo "SKIP: could not mint a CA key in a token"; exit 0; }
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3 -subj "/CN=localhost" >/dev/null 2>&1
printf "internal\n" > domains.txt; seed_domains "$W/domains.txt"
cat > est.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$EP
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
seed_ca_from_conf est.conf
"$ROOT/build/fastpki-est" --config est.conf >est.log 2>&1 & SRV=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "est.conf" EST_PORT "$SRV" || true
kill -0 $SRV 2>/dev/null || { echo "fastpki-est died:"; cat est.log; exit 1; }

enroll(){
  "$OSSL" req -new -subj "/CN=$3.internal" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr >/dev/null 2>&1
  "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
  curl -sk -u "$1:$2" --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
    "https://127.0.0.1:$EP/.well-known/est/ca/simpleenroll" \
    | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null
}
chk "an un-reset admin cannot enrol over EST" no "$(has "$(enroll admin admin before)" 'BEGIN CERTIFICATE')"
chk "  and no certificate reached the database" 0 \
    "$(pg_exec "select count(*) from certs where cn='before.internal';" | tr -d ' ')"

echo "=== after the owner sets a password, both doors open and the old one is dead ==="
chk "changing the password succeeds" 200 \
    "$(code -b a.cj -X POST "$U/api/password" -d 'old=admin&new=Str0ngNewAdminPw')"
chk "must_reset is cleared in the database" 0 \
    "$(pg_exec "select must_reset::int from web_users where username='admin';" | tr -d ' ')"
chk "the session can now administer"  200 "$(code -b a.cj "$U/api/users")"
# The whole promise of the ticket: the well-known credential stops working.
chk "the OLD password no longer logs in" 401 \
    "$(code -c b.cj -X POST "$U/api/login" -d 'username=admin&password=admin')"
chk "the NEW password logs in"           200 \
    "$(code -c c.cj -X POST "$U/api/login" -d 'username=admin&password=Str0ngNewAdminPw')"
chk "the OLD password cannot enrol"   no  "$(has "$(enroll admin admin old)" 'BEGIN CERTIFICATE')"
chk "the NEW password CAN enrol"      yes "$(has "$(enroll admin Str0ngNewAdminPw new)" 'BEGIN CERTIFICATE')"

echo "=== the shipped deployment actually asks for this ==="
# The gate above is worth nothing if bootstrap.sh seeds without the flag — that is the
# shipped-vs-tested gap: every assertion so far set --must-reset itself.
chk "deploy/bootstrap.sh seeds with --must-reset" yes \
    "$(grep -q 'web-user admin admin --role admin --must-reset' "$ROOT/deploy/bootstrap.sh" && echo yes || echo no)"

rm -f "$CFG"
echo
echo "=== DEFAULT ADMIN RESET: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
