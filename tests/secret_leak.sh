#!/usr/bin/env bash
# Secret-in-logs leak test (§5). PKI servers handle private keys,
# shared secrets, tokens and passwords; a classic failure is logging them on an
# error path. Run the secret-bearing servers at the most verbose log level with
# canary secrets, exercise normal + bad-auth + malformed paths, and assert no
# canary — and no PEM private key — ever lands in the captured logs.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
W="$(mktemp -d)"; cd "$W"; WP=18270; SP=18271
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
# absent F S -> "yes" if string S does NOT appear (case-insensitively) in file F.
absent(){ grep -qiF "$2" "$1" 2>/dev/null && echo no || echo yes; }

# Canary secrets — deliberately unique so a single grep is conclusive.
TOKEN="CANARYtok_4f1c9e2b7a"
PASSWD="CANARYpw_8d3e6f0a1c"
HSMPIN="Pin-CanaryDoNotLog-4711"
CHAL="CANARYchal_2b9f7e4d6a"

ca_in_token ca.pem "/CN=Leak CA" 3650
cp ca.pem root.pem; printf "internal\n" > domains.txt
echo "=== fastpki-web: token, password and CA key must not be logged ==="
pg_setup secret_leak
seed_domains $W/domains.txt   # allowed_domains is the sole source
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
WEB_BIND=127.0.0.1
WEB_PORT=$WP
WEB_TOKEN=$TOKEN
WEB_ALLOW_REVOKE=true
MS_KEY=pkcs11:token=fastpki;object=leaky-key;type=private?pin-value=$HSMPIN
LOG_LEVEL=debug
EOF
seed_ca_from_conf web.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-web" --config web.conf >web.log 2>&1 & WPID=$!
sleep 1; trap 'pg_cleanup; kill $WPID $SPID 2>/dev/null' EXIT
if ! kill -0 $WPID 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
UW="http://127.0.0.1:$WP"
AUTH="Authorization: Bearer $TOKEN"
# Token auth (success) + create a user carrying the canary password.
curl -s -o /dev/null -H "$AUTH" "$UW/api/me"
curl -s -o /dev/null -H "$AUTH" -X POST "$UW/api/users" -d "username=boss&password=$PASSWD&role=admin"
# A failed login that submits the canary password (must not be echoed to the log).
curl -s -o /dev/null -X POST "$UW/api/login" -d "username=boss&password=$PASSWD-WRONG"
# A request with a bogus token + the effective-config dump (must redact the token).
curl -s -o /dev/null -H "Authorization: Bearer $TOKEN-BOGUS" "$UW/api/me"
CFG=$(curl -s -H "$AUTH" "$UW/api/config")
chk "config endpoint redacts WEB_TOKEN (not the value)" yes "$(echo "$CFG" | grep -qF "$TOKEN" && echo no || echo yes)"
chk "WEB_TOKEN value never written to the log"   yes "$(absent web.log "$TOKEN")"
chk "submitted password never written to the log" yes "$(absent web.log "$PASSWD")"
chk "no PEM private key block in the web log"     yes "$(absent web.log 'PRIVATE KEY')"

# §5 asks for a leak test covering PINs, and the HSM PIN had no coverage. A
# `pkcs11:` URI is a HANDLE — token and object name are meant to be visible, and are
# what makes the Config page useful. But RFC 7512 also allows `pin-value=<the PIN>`
# inside the URI, and the page returned that verbatim to anyone who could read the
# config. The shipped deployment uses `pin-source=<path>`, so this bites the operator
# who hand-writes a URI with the PIN inline — a natural thing to do, and exactly what
# this harness does everywhere.
chk "config endpoint redacts an inline pin-value"  yes "$(echo "$CFG" | grep -q "$HSMPIN" && echo no || echo yes)"
chk "  and says it redacted rather than truncating" yes "$(echo "$CFG" | grep -q 'pin-value=(redacted)' && echo yes || echo no)"
# Over-redaction would be its own bug: the handle is the reason the value is shown.
chk "  while still showing the key handle"          yes "$(echo "$CFG" | grep -q 'object=leaky-key' && echo yes || echo no)"
chk "the PIN is never written to the log"           yes "$(absent web.log "$HSMPIN")"

echo "=== fastpki-scep: challenge secret + CA key must not be logged ==="
pg_setup secret_leak2
seed_domains $W/domains.txt   # this instance has its own database
cat > scep.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
SCEP_BIND=127.0.0.1
SCEP_PORT=$SP
SCEP_CHALLENGE=$CHAL
LOG_LEVEL=debug
EOF
seed_ca_from_conf scep.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-scep" --config scep.conf >scep.log 2>&1 & SPID=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "scep.conf" SCEP_PORT "$SPID" || true
if ! kill -0 $SPID 2>/dev/null; then echo "fastpki-scep died:"; cat scep.log; exit 1; fi
US="http://127.0.0.1:$SP/scep/ca"
curl -s -o /dev/null "$US?operation=GetCACaps"
curl -s -o /dev/null "$US?operation=GetCACert"
# Malformed PKIOperation (garbage CMS) to drive the error path.
head -c 128 /dev/urandom | curl -s -o /dev/null --data-binary @- -H 'Content-Type: application/x-pki-message' "$US?operation=PKIOperation"
chk "SCEP_CHALLENGE secret never written to the log" yes "$(absent scep.log "$CHAL")"
chk "no PEM private key block in the SCEP log"       yes "$(absent scep.log 'PRIVATE KEY')"
chk "both servers still alive after the probes" yes \
    "$(kill -0 $WPID 2>/dev/null && kill -0 $SPID 2>/dev/null && echo yes || echo no)"

# ⚠️ THE CLIs LEAK TOO, AND NOTHING HERE LOOKED AT THEM. Every assertion above reads a
# SERVICE log. The fastpki-* tools handle the same handles — a listener key URI may carry its
# PIN inline as ?pin-value=, which this product reads — and their stderr is captured by the
# nightly renewal job on both the compose and the OpenRC paths, so it lands in exactly the
# same place a service log does.
#
# Measured: renew_service_certs_for_ca printed "could not load the listener key <uri>" with
# the handle verbatim, on the path a cron job runs every night, and this suite passed it.
#
# The handle is made UNLOADABLE on purpose (no such object in the token), because the leak
# lives on the failure path — the success path never prints the handle at all.
echo "=== fastpki-ca must not print a PIN when a key handle fails to load ==="
cat > ca.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
MS_KEY=pkcs11:token=fastpki;object=no-such-object-here;type=private?pin-value=$HSMPIN
LOG_LEVEL=debug
EOF
# ⚠️ A ROW MUST EXIST UNDER THE ID, or the loop skips with "nothing published yet" BEFORE it
# ever touches the key, and every assertion below passes without exercising the leak path.
# The contents do not matter — the key load happens first — so the CA's own certificate under
# a made-up serial is enough to make the id non-empty.
pg_exec "INSERT INTO certs(serial,status,cert,cert_id,ca_instance_id,cn,subject,\"notBefore\",\"notAfter\")
         VALUES('7e5701',0, decode('$("$OSSL" x509 -in ca.pem -outform DER | od -An -tx1 | tr -d ' \n')','hex'),
                'ms', NULL, 'leak-probe','CN=leak-probe',
                $(( $(date +%s) - 3600 )), $(( $(date +%s) + 86400 )))
         ON CONFLICT (serial) DO NOTHING;" >/dev/null 2>&1
chk "the leak-path fixture is in place (a row under the id)" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='ms' AND status=0;" | tr -d ' ')"
"$ROOT/build/fastpki-ca" --config ca.conf renew-service-certs --re-issue-self-signed --ca ca \
    >ca-cli.log 2>&1 || true
chk "the CLI reported the failure at all" yes \
    "$(grep -qi 'could not load the listener key' ca-cli.log && echo yes || echo no)"
chk "  the PIN is not in the CLI output"   yes "$(absent ca-cli.log "$HSMPIN")"
chk "  and it redacted rather than hiding the handle" yes \
    "$(grep -q 'pin-value=(redacted)' ca-cli.log && echo yes || echo no)"
# ⚠️ THE PEM ARMOUR, NOT THE PHRASE. The two service-log checks above get away with grepping
# for "PRIVATE KEY" because those servers never say it in prose; this path does — the token
# error is "no private key found at pkcs11 URI: …", which is the correct message and matched a
# case-insensitive search for the phrase. What must never appear is an actual key BLOCK, so
# look for the armour that only a real PEM has.
chk "  no PEM private key block in the CLI output" yes \
    "$(grep -qiE '\-\-\-\-\-BEGIN ([A-Z]+ )?PRIVATE KEY' ca-cli.log 2>/dev/null && echo no || echo yes)"

echo
echo "=== SECRET LEAK: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
