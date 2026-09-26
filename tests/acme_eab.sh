#!/usr/bin/env bash
# ACME External Account Binding (RFC 8555 §7.3.4):
#   - the server requires EAB, which is the only behaviour there is
#   - a per-kid HMAC key is provisioned in the `keys` table
#   - certbot with the correct kid+key registers, the account is bound, and a
#     cert issues
#   - certbot with a WRONG key is rejected
# Requires root (binds :80, edits /etc/hosts).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
BIN="$ROOT/build/fastpki-acme"
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
WORK="$(mktemp -d)"; cd "$WORK"; PORT=18444; DOMAIN=acmetest.local
grep -q "$DOMAIN" /etc/hosts || echo "127.0.0.1 $DOMAIN" >> /etc/hosts
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=EAB CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
export REQUESTS_CA_BUNDLE="$WORK/acme.pem"
pg_setup acme_eab
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
pg_exec "CREATE TABLE IF NOT EXISTS keys(kid TEXT PRIMARY KEY, key TEXT);"

# Provision an EAB HMAC key (base64url) for kid 'tester'.
KID=tester
# ⚠️ AND AN IDENTITY, not just a secret. This suite tests EAB *authentication* — does the
# right HMAC bind an account and the wrong one not — but binding an account is only the
# first half of issuing a certificate. The second half is authorization,
# and a kid with no `web_users` row holds no role, so `acme:enrol` refuses:
#
#   urn:ietf:params:acme:error:unauthorized ::
#     this account may not enrol over ACME against CA 'ca'
#
# The suite then reported "correct EAB key -> cert issued: no" — which reads as the EAB
# check rejecting a valid key, i.e. the exact opposite of what actually happened.
#
# `acme_jws.sh`'s acme_seed_eab() seeds the identity; its own comment notes
# that acme_eab.sh "provisions its own kid and never calls this", and that is precisely how
# this suite was left behind. Same helper, called directly.
#
# ⚠️ INVISIBLE TO THE LOCAL TIER. This suite binds :80, so it is a ROOT_SUITES entry and
# skips on a dev box — it has only ever failed in-image, which is the point.
source "$ROOT/tests/user_helpers.sh"
# ⚠️ THE SHARED HELPER, NOT A SECOND GENERATOR. This suite used to roll its own secret
# here, and that copy lacked the one thing the helper exists for: base64url maps '+' to
# '-', so roughly 1 in 64 secrets STARTS with '-', certbot's argparse then reads it as the
# next option and dies with
#     certbot: error: argument --eab-hmac-key: expected one argument
# The comment above already claimed this suite called the helper; the code below it did
# not, so the re-roll protected six suites and not this one. Caught on a lab gate with
# key=-pNaNKjMiDWd...: "correct EAB key -> cert issued" failed while every NEGATIVE case
# passed vacuously, because no certificate was issued at all.
source "$ROOT/tests/acme_jws.sh"
acme_seed_eab "$KID"
EABKEY="$ACME_EAB_HMAC"
# The identity has to actually exist, or every assertion below measures a refusal for a
# reason the suite is not about.
chk "PRECONDITION: the EAB kid has an enrolling identity" 1 \
    "$(pg_exec "SELECT count(*) FROM web_users WHERE username='$KID';" | tr -d ' ')"
echo "provisioned EAB kid=$KID key=${EABKEY:0:12}..."

cat > bootstrap.conf <<EOF
BASE_URL=https://localhost:$PORT
SIGNING_CA_PEM=$WORK/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$WORK/root.pem
ACME_CERT=$WORK/acme.pem
ACME_KEY=$WORK/acme.key
PG_CONNINFO=$PG_CONNINFO
ACME_BIND=0.0.0.0
ACME_PORT=$PORT
ACME_BASE_PATH=/acme
CERT_VALIDITY_DAYS=90
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$BIN" --config bootstrap.conf > srv.log 2>&1 & SRV=$!
sleep 1; trap 'pg_cleanup; kill $SRV 2>/dev/null' EXIT

echo "directory externalAccountRequired: $(curl -sk https://localhost:$PORT/acme/ca/directory | grep -o 'externalAccountRequired":[a-z]*')"

run_certbot() { # cfgdir  eabkey  -> exit handled by caller
    certbot certonly --standalone -d "$DOMAIN" --http-01-port 80 \
        --server "https://localhost:$PORT/acme/ca/directory" \
        --eab-kid "$KID" --eab-hmac-key "$2" \
        --register-unsafely-without-email --agree-tos -n \
        --config-dir "$1" --work-dir "$1/w" --logs-dir "$1/l" >/dev/null 2>&1
}

echo "=== EAB enabled ==="
run_certbot "$WORK/good" "$EABKEY"
[ -f "$WORK/good/live/$DOMAIN/cert.pem" ] && g=ok || g=no
chk "correct EAB key -> cert issued" ok "$g"
chk "account bound to kid"           "$KID" "$(pg_exec 'select kid from accounts limit 1;')"

WRONG=$("$OSSL" rand 32 | "$OSSL" base64 -A | tr '+/' '-_' | tr -d '=')
run_certbot "$WORK/bad" "$WRONG"
[ -f "$WORK/bad/live/$DOMAIN/cert.pem" ] && b=ok || b=no
chk "wrong EAB key -> rejected (no cert)" no "$b"

echo "=== The PRODUCTION kid shape IS the username, and it is what gets RECORDED ==="
# WHY THIS CELL EXISTS. Everything above uses KID=tester, chosen by the suite. The product
# does not choose kids -- `ensure_enrolment_creds` mints one per user, and it is the
# plain username (it was `<user>:eab`, a suffix that existed only to keep a user's three
# secrets apart in a table keyed by kid alone).
#
# The suffix caused two measured defects, and both are asserted here:
#   * newOrder stripped it and finalize did not, so an EAB-bound account validated
#     and then got 400 "this identity holds no profile permission" from a lookup for a
#     subject literally called `demo:eab`. Measured on dc3 over http-01 and tls-alpn-01.
#   * ACME RECORDED that kid as `certs.owner`, so one person appeared in the
#     inventory under two names: `demo` from EST/CMP, `demo:eab` from ACME.
PUSER=prod-eab
seed_enrolling_identity "$PUSER"
PKEY=$("$OSSL" rand 32 | "$OSSL" base64 -A | tr '+/' '-_' | tr -d '=')
pg_exec "INSERT INTO keys(kid,protocol,key) VALUES('$PUSER','eab','$PKEY')
         ON CONFLICT (kid,protocol) DO UPDATE SET key=EXCLUDED.key;" >/dev/null
# PRECONDITIONS. The kid must be exactly the username, and the row must be the EAB one --
# seeded as a `cmp` row instead, ACME would find nothing and the issuance below would fail
# for a reason that has nothing to do with what is being measured.
chk "PRECONDITION: the kid IS the web_users row" 1 \
    "$(pg_exec "SELECT count(*) FROM web_users WHERE username='$PUSER';" | tr -d ' ')"
chk "PRECONDITION: its secret is stored under protocol=eab" 1 \
    "$(pg_exec "SELECT count(*) FROM keys WHERE kid='$PUSER' AND protocol='eab';" | tr -d ' ')"
# AND NO SUFFIXED KID SURVIVES ANYWHERE. This is one of the two assertions that fail on the
# old code: `ensure_enrolment_creds` wrote `<user>:eab` and `<user>:scep`, so a single row
# with a colon in its kid means the suffix is still being minted somewhere.
chk "PRECONDITION: no kid in the whole table carries a suffix" 0 \
    "$(pg_exec "SELECT count(*) FROM keys WHERE kid LIKE '%:%';" | tr -d ' ')"
certbot certonly --standalone -d "$DOMAIN" --http-01-port 80 \
    --server "https://localhost:$PORT/acme/ca/directory" \
    --eab-kid "$PUSER" --eab-hmac-key "$PKEY" \
    --register-unsafely-without-email --agree-tos -n \
    --config-dir "$WORK/prod" --work-dir "$WORK/prod/w" --logs-dir "$WORK/prod/l" \
    >"$WORK/prod.log" 2>&1
[ -f "$WORK/prod/live/$DOMAIN/cert.pem" ] && pg_ok=ok || pg_ok=no
chk "a username-kid account issues a certificate" ok "$pg_ok"
if [ "$pg_ok" = ok ]; then
    # Decode it rather than trusting the file's existence (3d).
    chk "  and it is for the requested name" yes \
        "$("$OSSL" x509 -in "$WORK/prod/live/$DOMAIN/cert.pem" -noout -subject 2>/dev/null \
           | grep -q "$DOMAIN" && echo yes || echo no)"
    # THE OWNER ASSERTION, and the reason this cell decodes the DATABASE and not just the
    # file. The certificate issuing proves the lookup works; it says nothing about the name
    # the certificate was filed under. On the old code this row read `prod-eab:eab`.
    # Counted, not ORDER BY ... LIMIT 1: earlier cells in this suite issue for the same
    # name, and picking "the latest" out of several rows needs a tiebreak that certs does
    # not reliably have (`notBefore` has one-second granularity).
    chk "  and ACME filed it under the USERNAME, not a suffixed kid" 1 \
        "$(pg_exec "SELECT count(*) FROM certs WHERE cn='$DOMAIN' AND owner='$PUSER';" | tr -d ' ')"
    chk "  and no certificate anywhere is owned by a suffixed kid" 0 \
        "$(pg_exec "SELECT count(*) FROM certs WHERE owner LIKE '%:%';" | tr -d ' ')"
else
    echo "      certbot said: $(grep -oE '"detail":"[^"]*"' "$WORK/prod.log" | head -1)"
fi

echo
echo "=== the seeded secret is safe to hand to a CLI ==="
# ⚠️ base64url maps '+' to '-', so ~1 raw secret in 64 STARTS with one, and certbot's
# argparse then reads it as the next option instead of this option's value:
#     certbot: error: argument --eab-hmac-key: expected one argument
# That is the same message an EMPTY secret gives, which is what made it hard to place.
# Seven suites feed this to certbot; it took out acme_caa.sh on a lab gate at PASS=8
# FAIL=11 — and the 8 were the NEGATIVE cases passing because nothing was issued at all.
#
# ⚠️ STRUCTURAL ONLY, AND DELIBERATELY SO. Sampling was the obvious way to check this and
# it is the wrong one twice over: each acme_seed_eab writes to the database, so enough
# draws to make a 1-in-64 event reliable costs hundreds of round trips (a 400-draw version
# blew the suite's time budget), and — the part that actually bit — every draw REPLACES
# ACME_EAB_KID/ACME_EAB_HMAC, which the assertions above are still using. A 25-draw
# version took this suite from green to FAILED in the lab gate: it clobbered the seeded
# credential and then read the variable under `set -u`. Requiring the re-roll to still be
# in the helper costs nothing and mutates nothing, and it is what actually holds.
chk "acme_seed_eab still re-rolls a leading '-'" yes \
    "$(sed -n '/^acme_seed_eab()/,/^}/p' "$ROOT/tests/acme_jws.sh" \
       | grep -q 'ACME_EAB_HMAC#-' && echo yes || echo no)"
# ⚠️ AND THAT THIS SUITE ACTUALLY USES IT. The assertion above passed for a long time while
# this suite quietly rolled its own secret a few lines up, so the helper was verified and
# then not called — which is precisely how the leading-'-' failure reached a gate here and
# nowhere else. Checking the guard exists is worth nothing without checking it is on the
# path this suite takes, so this asserts the suite takes its secret FROM the helper and
# generates none of its own.
chk "  and this suite takes its secret from that helper" yes \
    "$(grep -q '^EABKEY="\$ACME_EAB_HMAC"' "$ROOT/tests/acme_eab.sh" && echo yes || echo no)"
chk "  and rolls no EAB secret of its own" yes \
    "$(grep -qE '^EABKEY=\$\("\$OSSL" rand' "$ROOT/tests/acme_eab.sh" && echo no || echo yes)"

echo
echo "=== ACME EAB: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
