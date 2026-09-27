#!/usr/bin/env bash
# AUTH_BACKEND=local means the `web_users` TABLE and nothing else.
#
# The file backend (USERS_FILE + fastpki-passwd) is gone. "Gone" has to mean inert,
# not merely unused: the dangerous shape of this removal is a leftover fallthrough
# that still reads a users file for names the DB does not know — that would be an
# authentication bypass wearing a compatibility hat, and no other suite would see it
# because every other suite only ever seeds users the DB *does* know.
#
# So this suite plants a syntactically PERFECT legacy users file — real PBKDF2 hash,
# lifted straight out of web_users so it cannot be dismissed as a malformed line —
# naming a user who exists nowhere in the database, points USERS_FILE at it, and
# proves EST refuses that user. The same file would once have authenticated
# 'mallory' AND handed them the 'master' issuance role.
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
# Only adopt the system openssl.cnf where it really is one (§3d): on macOS that path
# is a stub with no providers and exporting it breaks every pkcs11 load.
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; PORT=18478
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

ca_in_token ca.pem "/CN=DB Auth CA" 3
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup auth_db_only
trap 'pg_cleanup; kill ${SRV:-} 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source

# `requester`, not `standard`: with the defaults gone, a role that matches no
# row in `roles` grants nothing and enrolment is refused. This suite is about the
# USERS_FILE being inert, not about roles, so it needs a role that actually works.
seed_web_user alice alicepw12 requester

# A legacy users file that is correct in every respect EXCEPT that its user is not in
# the database. The hash is alice's own, so 'mallory:alicepw12' would verify if any
# code still read this file — and the role field would even promote them to 'master'.
HASH=$(pg_exec "SELECT hash FROM web_users WHERE username='alice';" | tr -d ' ')
chk "seeded user has a PBKDF2 hash in web_users" yes "$(has "$HASH" '^pbkdf2\$')"
printf 'mallory:master:%s\n' "$HASH" > users.txt

cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
USERS_FILE=$W/users.txt
EST_BIND=127.0.0.1
EST_PORT=$PORT
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf

"$ROOT/build/fastpki-est" --config bootstrap.conf >srv.log 2>&1 & SRV=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$SRV" || true
kill -0 $SRV 2>/dev/null || { echo "est died:"; cat srv.log; exit 1; }

# enroll USER PASS -> issued PEM on stdout (empty when refused)
enroll(){
  "$OSSL" req -new -subj "/CN=host.internal" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr >/dev/null 2>&1
  "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
  curl -sk -u "$1:$2" --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
    "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll" \
    | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null
}
issued(){ has "$1" "BEGIN CERTIFICATE"; }

echo "=== the web_users row IS the EST credential ==="
chk "DB user enrolls over EST Basic auth"       yes "$(issued "$(enroll alice alicepw12)")"
chk "DB user with a wrong password is refused"  no  "$(issued "$(enroll alice wrongpw123)")"

echo "=== a perfectly-formed legacy users file is inert ==="
chk "users file exists and is well-formed" yes "$(has "$(cat users.txt)" '^mallory:master:pbkdf2\$')"
chk "user present ONLY in the file is refused" no "$(issued "$(enroll mallory alicepw12)")"
chk "...and unknown users generally are refused" no "$(issued "$(enroll nobody alicepw12)")"

# The file's role field said 'master'. Had it been read, the cap would have come from
# MAX_CERTS_MASTER — assert the identity never appeared at all, in the DB or the log.
N=$(pg_exec "SELECT COUNT(*) FROM certs WHERE owner='mallory';" | tr -d ' ')
chk "no certificate was ever issued to the file-only user" 0 "$N"

echo "=== the tool that wrote that file is gone ==="
chk "src/tools/passwd.cpp removed"       no "$([ -f "$ROOT/src/tools/passwd.cpp" ] && echo yes || echo no)"
chk "no fastpki-passwd CMake target"     no "$(grep -q 'fastpki-passwd' "$ROOT/CMakeLists.txt" && echo yes || echo no)"

kill $SRV 2>/dev/null; wait $SRV 2>/dev/null

echo
echo "=== AUTH DB-ONLY: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
