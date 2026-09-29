#!/usr/bin/env bash
# EST authenticates DB users (web_users table). Creates a user via the
# fastpki-web console API, then enrolls via fastpki-est against the same DB.
#   correct password  -> issue
#   wrong password    -> reject (401)
#   unknown user      -> reject (401)
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
W="$(mktemp -d)"; cd "$W"; WPORT=18471; EPORT=18472
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=DBAuth CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.pem.key -out est.pem -days 3650 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup est_dbauth
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source

# --- fastpki-web: create a DB user via the console ---
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$WPORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
"$ROOT/build/fastpki-web" --config web.conf >web.log 2>&1 & WP=$!
sleep 1; trap 'pg_cleanup; kill $WP ${EP:-0} 2>/dev/null' EXIT
WU="http://127.0.0.1:$WPORT"
# first user (admin) needs no auth; then log in and create the requester DB user
curl -s -o /dev/null -X POST "$WU/api/users" -d 'username=admin&password=adminpw12&role=admin'
curl -s -c adm.cj -X POST "$WU/api/login" -d 'username=admin&password=adminpw12' >/dev/null
curl -s -o /dev/null -b adm.cj -X POST "$WU/api/users" -d 'username=dbuser&password=dbpw-12345&role=requester'
NDB=$(pg_exec "SELECT COUNT(*) FROM web_users WHERE username='dbuser';")
chk "dbuser created in web_users table" 1 "$NDB"

# --- fastpki-est on the same DB ---
# One source of truth for the backoff numbers: the config below and the assertion at the
# end of this suite must agree, or the precondition there measures a different threshold
# from the one the server is running.
LOGIN_FAILURE_THRESHOLD=3
LOGIN_LOCKOUT_SEC=120
cat > est.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.pem.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$EPORT
# The shipped guessing-backoff policy, wound down so the suite can watch the lockout both
# start and expire instead of waiting out the production ceiling. Setting them here also
# proves the keys are read at all — a hardcoded policy would ignore both and the timing
# below would not line up.
LOGIN_FAILURE_THRESHOLD=$LOGIN_FAILURE_THRESHOLD
LOGIN_LOCKOUT_SEC=$LOGIN_LOCKOUT_SEC
LOG_LEVEL=err
EOF
seed_ca_from_conf est.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-est" --config est.conf >est.log 2>&1 & EP=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "est.conf" EST_PORT "$EP" || true

enroll() { # user pass -> issue|reject
    "$OSSL" req -new -subj "/CN=host.internal" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr >/dev/null 2>&1
    "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
    local o; o=$(curl -sk -u "$1:$2" --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$EPORT/.well-known/est/ca/simpleenroll" \
        | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null)
    echo "$o" | grep -q "BEGIN CERTIFICATE" && echo issue || echo reject
}

echo "=== EST authenticates DB users ==="
chk "DB user, correct password -> issue"  issue  "$(enroll dbuser dbpw-12345)"
chk "DB user, wrong password -> reject"   reject "$(enroll dbuser wrongpass)"
chk "unknown user -> reject"              reject "$(enroll ghost whatever)"

# ⚠️ THE SUBJECT IS THE CANONICAL ROW NAME, NOT WHAT WAS TYPED. get_web_user() matches
# case-insensitively and returns the stored row, so DBUSER authenticates — but authenticate()
# then handed the CALLER'S spelling on as the authorization subject. Everything downstream
# compares it exactly: roles_for_subject() matches selector_value with no lower(), so a grant
# bound to `dbuser` was invisible to a caller who typed `DBUSER`, and the certificate landed
# with owner=DBUSER, which the console's mTLS path now compares against a certificate CN.
chk "an uppercase login still enrols"     issue  "$(enroll DBUSER dbpw-12345)"
# Not "== 1": earlier cases in this suite enrol as `dbuser` too, so pinning the count would
# make this a bookkeeping check on the fixture rather than a statement about the subject.
chk "  and the cert is owned by the CANONICAL name" yes \
    "$([ "$(pg_exec "SELECT count(*) FROM certs WHERE owner='dbuser';" | tr -d ' ' | head -1)" -ge 1 ] && echo yes || echo no)"
chk "  not by the spelling that was typed"          0 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE owner='DBUSER';" | tr -d ' ' | head -1)"

echo "=== Guard: EC-key enrollment gets valid KeyUsage (no keyEncipherment) ==="
"$OSSL" ecparam -name prime256v1 -genkey -noout -out ec.key >/dev/null 2>&1
"$OSSL" req -new -key ec.key -subj "/CN=ec.internal" -out ec.csr >/dev/null 2>&1
"$OSSL" req -in ec.csr -outform DER | "$OSSL" base64 > ec.b64
curl -sk -u dbuser:dbpw-12345 --data-binary @ec.b64 -H "Content-Type: application/pkcs10" \
    "https://127.0.0.1:$EPORT/.well-known/est/ca/simpleenroll" \
    | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs -out ecleaf.pem 2>/dev/null
ECT=$("$OSSL" x509 -in ecleaf.pem -text -noout 2>/dev/null)
chk "EC leaf issued"                          yes "$(echo "$ECT" | grep -qi 'id-ecPublicKey' && echo yes || echo no)"
chk "EC KeyUsage has Digital Signature"       yes "$(echo "$ECT" | grep -qi 'Digital Signature' && echo yes || echo no)"
chk "EC KeyUsage has NO Key Encipherment"     yes "$(echo "$ECT" | grep -qi 'Key Encipherment' && echo no || echo yes)"

echo "=== the SECOND password door is throttled too ==="
# ⚠️ WHY THIS IS GUARDED HERE. Basic auth in front of EST reaches the shared
# authenticate(), while the console does its own local check first and only falls through
# to it for directory logins. Two independent doors onto the same password, and a backoff
# wired into one of them is not a control — an attacker simply picks the other. The console
# side has its own suite; this is the half that guards THIS door.
#
# ⚠️ AND IT RUNS LAST, DELIBERATELY. The throttle counts the client ADDRESS as well as the
# account, and every request in this suite comes from one address — so locking it out
# mid-file would make every later assertion fail for a reason that has nothing to do with
# what it is testing.
#
# ⚠️ THE WINDOW IS LONG ON PURPOSE. The first version set the ceiling to 2 seconds so the
# expiry could be watched, and each attempt here generates a fresh RSA-2048 key and does a
# TLS round trip — which on the Mac took under two seconds and in the shipped image did
# not. The lockout had expired before the assertion ran, and the suite reported a product
# failure that was really a stopwatch. Expiry is measured in the console suite, where an
# attempt costs a single HTTP request; here the only claim is that the door shuts.
# ⚠️ THE WRONG-PASSWORD ATTEMPTS MUST ACTUALLY REACH THE SERVER, and nothing checked that.
# `enroll` reports "reject" for a TRANSPORT failure exactly as it does for a refusal, so a
# run where these six never landed — a busy host, a slow TLS handshake, a connection reset
# — leaves the counter below the threshold, the correct password still works, and this
# suite reports a PRODUCT failure that is really a lost fixture. That is the shape of the
# intermittent red it produced in the full in-image run while passing alone: nothing here
# could tell "the throttle did not engage" from "the attempts never arrived".
#
# So count the server's own refusals, and require at least the threshold before judging.
bad_status() {   # user pass -> the HTTP status of one enrolment attempt
    "$OSSL" req -new -subj "/CN=host.internal" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr >/dev/null 2>&1
    "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
    curl -sk -o /dev/null -w '%{http_code}' -u "$1:$2" --data-binary @r.b64 \
        -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$EPORT/.well-known/est/ca/simpleenroll" 2>/dev/null
}
# ⚠️ THE LOCKOUT IS SHORT-LIVED, AND THAT IS THE OTHER HALF OF THE INTERMITTENT RED.
# It is not the LOGIN_LOCKOUT_SEC ceiling above — that only caps the delay. The backoff is
# computed from the failure count and measured from the LAST failure, so what decides this
# assertion is the WALL-CLOCK GAP between the final wrong attempt and the judged one.
#
# MEASURED, not derived: with a 10-second stall injected before the judged request, the
# correct password is accepted again — so the lockout at this point expires in under ten
# seconds. (My first reading of wait_for() said the window here was 32s. The experiment
# says otherwise, and the experiment wins; the exact curve is not what this suite is
# entitled to depend on.)
#
# So the suite must not put slow work inside that gap. The final CSR is generated BEFORE
# the wrong-password loop, leaving one HTTP round trip between the last failure and the
# judged request — where it used to generate an RSA-2048 key there, on a host running a
# couple of hundred suites. The extra attempts are belt-and-braces, not the mechanism.
"$OSSL" req -new -subj "/CN=host.internal" -newkey rsa:2048 -keyout klast.pem -nodes \
        -out rlast.csr >/dev/null 2>&1
"$OSSL" req -in rlast.csr -outform DER 2>/dev/null | "$OSSL" base64 > rlast.b64

# ⚠️ THE GAP IS THE EXPERIMENT, SO MEASURE IT AND RETRY WHEN IT IS LOST. The backoff is
# stamped from the LAST failure, and the window here expires in under ten seconds, so what
# decides the assertion below is the wall-clock distance between the final wrong attempt
# and the judged request. On a build node running a couple of hundred suites one HTTPS
# round trip can exceed it, and the judged request then legitimately succeeds — which this
# suite reported as "the throttle does not engage", a PRODUCT claim built on a stopwatch.
# It went red exactly that way in a full in-image run while passing alone.
#
# Hardening it by making the gap smaller has already been done (the CSR is pre-generated
# above) and was not enough. So: time the gap, and if the run lost the race, redo the
# wrong-password loop and judge again rather than blaming the product. Three tries, then
# report the LOSS as what it is — a harness failure with the measured gap in the message,
# not a verdict about the throttle.
# ⚠️ THE WINDOW IS ONE SECOND, AND NINE RAPID ATTEMPTS SPEND IT.
#
# authenticate() asks retry_after() BEFORE checking the password and returns early when it
# is non-zero -- and record_failure(), the only writer of the counter, sits after that
# return. So an attempt made while already in backoff is refused WITHOUT extending it.
# That is deliberate and right: otherwise anyone could keep a victim locked out forever
# just by attacking continuously.
#
# The consequence for a test is that `failures` cannot climb past threshold+1 by hammering:
#
#     attempts 1..threshold+1   retry_after = 0   password checked, failure RECORDED
#     everything after          retry_after > 0   refused early, NOTHING recorded
#
# so the window stays at `1 << 0` = ONE SECOND, measured from the last recorded failure,
# and every further attempt only spends it. The old loop fired nine, then judged against a
# GAP_BUDGET of 5s -- five times the real window -- so under load the window had legitimately
# expired, the correct password was legitimately accepted, and both guards still reported
# the request had landed inside a window it had not. Idle hosts finished the extra attempts
# inside the second, which is why it only ever failed under a full gate.
#
# ESCALATE ON PURPOSE INSTEAD. Each further failure has to be RECORDED to count, which
# means waiting out the current window before making it. Four paced attempts take the
# window 1 -> 2 -> 4 -> 8 seconds, and 8s is wide enough that the judged request lands
# inside it even on a loaded machine. The cost is a few seconds of sleeping, paid once.
verdict=""; gap=0; refused=0; fails=0
window_now(){ echo $(( 1 << (fails - LOGIN_FAILURE_THRESHOLD - 1) )); }

# 1. Reach threshold+1 as fast as possible: every one of these IS recorded.
for _ in $(seq 1 $((LOGIN_FAILURE_THRESHOLD + 1))); do
    case "$(bad_status dbuser stillwrongpassword)" in 401|403) refused=$((refused + 1));; esac
    fails=$((fails + 1))
done
# 2. Escalate. Sleeping the current window + 1 guarantees the next attempt is COUNTED
#    rather than refused early, which is the only way the counter moves at all.
for _ in 1 2 3; do
    sleep $(( $(window_now) + 1 ))
    case "$(bad_status dbuser stillwrongpassword)" in 401|403) refused=$((refused + 1));; esac
    fails=$((fails + 1))
done
GAP_BUDGET=$(window_now)          # the window the code actually produces, not an assumed 10
t0=$(date +%s)
code=$(curl -sk -o /dev/null -w '%{http_code}' -u 'dbuser:dbpw-12345' --data-binary @rlast.b64 \
       -H 'Content-Type: application/pkcs10' \
       "https://127.0.0.1:$EPORT/.well-known/est/ca/simpleenroll" 2>/dev/null)
gap=$(( $(date +%s) - t0 ))
case "$code" in 401|403|429) verdict=reject ;; *) verdict=issue ;; esac

chk "PRECONDITION: every attempt that had to be recorded was" "$((LOGIN_FAILURE_THRESHOLD + 4))" "$refused"
# The gap is measured from the LAST RECORDED failure, which is where the window starts --
# not from the end of a batch that recorded nothing.
chk "PRECONDITION: the judged request landed inside the ${GAP_BUDGET}s window" yes \
    "$([ "$verdict" = reject ] || [ "$gap" -le "$GAP_BUDGET" ] && echo yes || echo no)"
[ "$verdict" = reject ] || [ "$gap" -le "$GAP_BUDGET" ] || \
    echo "         the judged request took ${gap}s against a ${GAP_BUDGET}s window, so the" \
         "lockout had expired before it arrived — this is the harness losing a race, not the throttle"
# Measured as "the CORRECT password stops working" — the one observable that cannot mean
# anything except a real refusal.
chk "after repeated failures the right password is refused too" reject "$verdict"

echo
echo "=== EST DB AUTH: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
