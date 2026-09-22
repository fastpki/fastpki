#!/usr/bin/env bash
# "no globals": the SHIPPED deployment must not accept any password from anyone.
#
# ⚠️ WHAT WAS MEASURED. `deploy/bootstrap.compose.conf` shipped `AUTH_BACKEND=none`.
# auth.cpp's `none` branch returns ok=true for any username with no `web_users` row, with
# any non-empty password, and `AuthResult.role` defaults to `requester` — a SEEDED console
# role holding `est:enrol|*`, `ms:enrol|*` and `cert:request|*`. So on a fresh deployment:
#
#     curl -u mallory:whatever ... /simpleenroll   ->  HTTP 200
#     certs row: cn=pwned.internal owner=mallory role=requester
#
# mallory exists in no table. Every lab DC and every deployment built from our own compose
# file ran that way. The binary logs "WARNING: AUTH_BACKEND=none — EST accepts any
# username/password" at startup, which made the log line the only thing between a published
# port and free issuance.
#
# THIS SUITE HAS TWO HALVES AND BOTH ARE LOAD-BEARING:
#   1. the SHIPPED FILE does not select the dangerous mode — a plain text assertion, which
#      is the one that would have caught it;
#   2. the two modes really do differ at runtime — otherwise (1) is a lint rule about a
#      string, and a future change that made `local` behave like `none` would pass it.
#
# Related: tests/config_keys.sh (a shipped file must not set a key the parser ignores).
# This is the mirror — a shipped file must not set a key to a value that disables auth.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF

pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

echo "=== 1. THE SHIPPED FILES: no deployment we hand out may select AUTH_BACKEND=none ==="
# Scanned by VALUE, not by key name: the key is legitimate, one of its values is not.
#
# ⚠️ DISCOVERED, NOT LISTED. This began as `for f in deploy/bootstrap.compose.conf
# config/bootstrap.conf.example`, and a hardcoded list is the pattern that has already produced
# four separate bugs in this repo (the builtin-role lists): it is correct on the day it is
# written and silently misses the sixth file somebody adds later. So the set is every file
# under deploy/ and config/ that assigns ANY config-shaped key.
#
# ⚠️ NOT `git ls-files`. It returns NOTHING inside the shipped image — there is no git
# checkout in there — which would make this whole section pass over an empty list on the
# one tier that runs closest to production.
#
# deploy/.env is deliberately in scope when present: it is untracked and per-deployment,
# so it is exactly where somebody would paste `AUTH_BACKEND=none` to unblock themselves.
shipped=$(grep -rlE '^[[:space:]]*[A-Z][A-Z0-9_]{3,}=' "$ROOT/deploy" "$ROOT/config" 2>/dev/null \
          | grep -vE '\.md$|\.sh$' | sort)
for f in $shipped; do
    # ⚠️ NO `|| echo 0` here: grep -c already prints 0 when it matches nothing, and the
    # fallback would fire on its exit-1 and make the value "0\n0".
    n=$(grep -c '^[[:space:]]*AUTH_BACKEND[[:space:]]*=[[:space:]]*none' "$f" 2>/dev/null)
    chk "${f#$ROOT/} does not ship AUTH_BACKEND=none" 0 "$n"
done
# The vacuity guard: if deploy/ moved or the grep shape changed, the loop above would run
# zero times and this section would pass having examined nothing.
chk "  ... and the scan found the shipped config files" yes \
    "$([ "$(echo "$shipped" | grep -c .)" -ge 3 ] && echo yes || echo "no ($shipped)")"
# …and it must actually SET it. Leaving the key out entirely would satisfy the check above
# while letting the code default decide, which is not the same guarantee.
n=$(grep -c '^[[:space:]]*AUTH_BACKEND[[:space:]]*=[[:space:]]*local' "$ROOT/deploy/bootstrap.compose.conf" 2>/dev/null)
chk "deploy/bootstrap.compose.conf pins AUTH_BACKEND=local" 1 "$n"

echo
echo "=== 2. and the two modes really are different at runtime ==="
W="$(mktemp -d)"; cd "$W"; PORT=18613
ca_in_token ca.pem "/CN=Auth Backend CA" 3 || { echo "SKIP: could not mint a CA key in a token"; echo "PASS=$pass FAIL=$fail"; exit 0; }
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup auth_backend_shipped
SRV=
trap 'pg_cleanup; kill ${SRV:-} 2>/dev/null' EXIT
printf "internal\n" > domains.txt; seed_domains "$W/domains.txt"

mkconf() {
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=$1
EST_BIND=127.0.0.1
EST_PORT=$PORT
CERT_VALIDITY_DAYS=365
LOG_LEVEL=info
EOF
hsm_conf_lines >> bootstrap.conf
}
start() { "$ROOT/build/fastpki-est" --config bootstrap.conf >srv.log 2>&1 & SRV=$!; sleep 2
          kill -0 $SRV 2>/dev/null || { echo "fastpki-est died:"; cat srv.log; exit 1; }; }
stop()  { kill ${SRV:-} 2>/dev/null; wait ${SRV:-} 2>/dev/null; SRV=; }
# enrol <user> <pw> <cn> -> HTTP status
enrol() {
    "$OSSL" req -new -subj "/CN=$3" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr >/dev/null 2>&1
    "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
    curl -sk -o body.out -w '%{http_code}' -u "$1:$2" \
        --data-binary @r.b64 -H 'Content-Type: application/pkcs10' \
        "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll"
}
mkconf local
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)

echo "--- PRECONDITIONS: the gate is armed and mallory is a stranger ---"
# Without these the refusal below could be an unconfigured deployment refusing everything,
# which would prove nothing about AUTH_BACKEND.
chk "roles ARE defined (may_enrol is not inert)" yes \
    "$([ "$(pg_exec 'SELECT count(*) FROM roles;' | tr -d ' \r\n')" -gt 0 ] && echo yes || echo no)"
chk "the default role 'requester' really can enrol over EST" 1 \
    "$(pg_exec "SELECT count(*) FROM role_permissions WHERE role='requester' AND permission='est:enrol';" | tr -d ' \r\n')"
chk "mallory is in no table" 0 \
    "$(pg_exec "SELECT count(*) FROM web_users WHERE username='mallory';" | tr -d ' \r\n')"

echo "--- AUTH_BACKEND=local (what we ship): a stranger is refused ---"
mkconf local; start
C=$(enrol mallory whatever stranger-local.internal)
chk "unknown username is refused" yes "$([ "$C" != 200 ] && echo yes || echo no)"
chk "  and NO certificate was written" 0 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cn='stranger-local.internal';" | tr -d ' \r\n')"
stop

echo "--- AUTH_BACKEND=none no longer EXISTS: the server refuses to start ---"
# ⚠️ THIS SECTION USED TO ASSERT THE DANGEROUS BEHAVIOUR ON PURPOSE — that `none` really
# did let `mallory` in — because that is what made section 1 a guard rather than a string
# check. The value was removed deliberately (no AUTH_BACKEND=none, and
# any other similar settings"), so there is no longer a dangerous behaviour to demonstrate:
# the config parser rejects the value.
#
# The replacement has to be just as strong, so it asserts the REFUSAL, not merely that the
# process exited. A binary that died for an unrelated reason — a missing CA, a bad port —
# would satisfy "it did not start" and leave a reintroduced `none` completely unguarded.
mkconf none
"$ROOT/build/fastpki-est" --config bootstrap.conf >none.log 2>&1 &
SRV=$!; sleep 2
chk "fastpki-est refuses to start with AUTH_BACKEND=none" no \
    "$(kill -0 $SRV 2>/dev/null && echo yes || echo no)"
stop
chk "  and the refusal NAMES the key"        yes \
    "$(grep -q 'AUTH_BACKEND' none.log && echo yes || echo no)"
chk "  and says which values are valid"      yes \
    "$(grep -qE "local.*ldap|'local' or 'ldap'" none.log && echo yes || echo no)"
# The point of the whole ticket: an operator who still has the old value gets told, rather
# than getting a server that starts and issues certificates to anyone.
chk "  no certificate was issued to a stranger" 0 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cn='stranger-none.internal';" | tr -d ' \r\n')"

echo
echo "=== AUTH BACKEND SHIPPED: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
