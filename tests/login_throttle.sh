#!/usr/bin/env bash
# Online password-guessing backoff on the console login.
#
# THE DEFECT THIS GUARDS. Every password door in this product answered as fast as it
# could, forever — no counter, no delay, no lockout anywhere. `POST /api/login` would take
# an unlimited number of attempts per second, and so would the HTTP Basic auth in front of
# EST and MS-WSTEP. A weak console password is minutes of work against that, and the
# console admin is the identity that can register a CA.
#
# ⚠️ AND THERE ARE TWO DOORS. The console does its OWN user lookup and password check and
# only calls the shared authenticate() when that fails AND a directory backend is
# configured — so a throttle living only inside authenticate() would leave local console
# password guessing completely unthrottled, which is the commonest deployment. This suite
# drives the LOCAL path deliberately (AUTH_BACKEND=local, a real web_users row) because
# that is the path a throttle is most likely to be built past. The EST/Basic door is
# guarded where that door is already driven, in the EST DB-auth suite.
#
# Self-contained (§3d) + shell-only (§3e): ephemeral Postgres, own port, temp dir, SKIPs
# cleanly when no Postgres is reachable. The lockout ceiling is configured down from the
# shipped default so the expiry can be measured rather than assumed.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18291
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
U="http://127.0.0.1:$PORT"
bad(){  code -X POST "$U/api/login" -d 'username=tuser&password=wrongwrongwrong'; }
good(){ code -X POST "$U/api/login" -d 'username=tuser&password=tuserpw12345'; }

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi

pg_setup login_throttle
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
# THRESHOLD=3 and a 10s ceiling: the same policy the product ships, wound down so a suite
# can watch the lockout start AND expire. Both are configuration, so pinning them here also
# proves the keys are read at all — a hardcoded policy would ignore these and the timing
# assertions below would not line up.
#
# ⚠️ NOT WOUND DOWN FURTHER, and the margin is the point. A 2s ceiling was enough on a fast
# machine and not enough in the shipped image, where the assertions in between took longer
# than the window and the lockout expired before it was checked — a suite reporting a
# product failure that was really a stopwatch. The window has to be comfortably longer than
# the requests that run inside it, on the SLOWEST machine this runs on, not the fastest.
# ⚠️ ONE SOURCE FOR THE POLICY THE ASSERTIONS BELOW DO ARITHMETIC ON. These are shell
# variables interpolated into the config, not literals written twice: the backoff the
# suite computes has to be the backoff the server was configured with, and two hand-kept
# copies are how a test ends up judging against a window the product never had.
THRESHOLD=3
LOCKOUT=10
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
LOGIN_FAILURE_THRESHOLD=$THRESHOLD
LOGIN_LOCKOUT_SEC=$LOCKOUT
LOG_LEVEL=err
EOF
seed_web_user tuser tuserpw12345 admin
"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat web.log; echo "RESULT: FAIL"; exit 1; }

echo "=== a correct password works, and typing it wrong a few times is not punished ==="
# People mistype passwords. A control that locks out on the third attempt is a control
# somebody switches off, so the first few failures must cost nothing.
# ⚠️ COUNT WHAT THE SERVER RECORDED; DO NOT ASSUME IT LATER. The escalation block further
# down used to open with `fails=4`, reasoning that the four 401s here were recorded and that
# the 429 and the Retry-After probe were not. That reasoning holds only while the assertion
# above it holds. When "refused outright" came back 401 instead, the attempt HAD been
# recorded, `fails` was short, every sleep derived from it was short, the escalation attempts
# were refused early — and one failed assertion became two, with the second pointing at the
# wrong thing entirely.
fails=0
attempt(){          # one wrong password. ATT is the status; it counts only if it was recorded
    ATT="$(bad)"
    [ "$ATT" = "401" ] && fails=$((fails + 1))
    return 0
}
window_now(){       # the backoff the code produces for the failures recorded so far
    local w=$(( 1 << (fails - THRESHOLD - 1) ))
    [ "$w" -gt "$LOCKOUT" ] && w=$LOCKOUT
    echo "$w"
}

chk "the fixture password is right" 200 "$(good)"
attempt; chk "1st wrong password -> 401" 401 "$ATT"
attempt; chk "2nd wrong password -> 401" 401 "$ATT"
attempt; chk "3rd wrong password -> 401" 401 "$ATT"

echo "=== past the threshold the door closes ==="
attempt; chk "4th wrong password -> 401" 401 "$ATT"

# ⚠️ "THE VERY NEXT ATTEMPT IS REFUSED" IS NOT A TESTABLE CLAIM, and asserting it is what
# broke this suite on a sanitizer runner while it passed everywhere else. login_throttle.cpp
# reads a steady_clock in WHOLE SECONDS and refuses only while `elapsed < window`; four
# recorded failures give 1 << 0 = ONE second. So the instant the fourth and fifth requests
# straddle a tick boundary, elapsed is 1, the window reads as already expired, and the fifth
# is COUNTED instead of refused. That is a coin flip weighted by machine speed — and a single
# `sleep 1` in front of it reproduces the sanitizer failure exactly, on an ordinary build.
# A one-second window cannot be judged by a one-second clock, and no budget repairs that;
# widening one is how this suite was "fixed" three times before.
#
# So escalate to a window second granularity CAN judge, which is what the section below
# already does. Two more recorded failures take it 1s -> 2s -> 4s. The claim under test is
# unchanged: past the threshold, attempts are refused with 429 and a Retry-After.
escalated=0
for _ in 1 2; do
    sleep $(( $(window_now) + 1 ))
    attempt
    [ "$ATT" = "401" ] && escalated=$((escalated + 1))
done
# ⚠️ ANTI-VACUITY: an escalation attempt refused early was never recorded, so the window is
# not the one window_now claims and everything judged against it proves nothing.
chk "PRECONDITION: both escalation attempts were recorded" 2 "$escalated"
W=$(window_now)
chk "inside the ${W}s window the door is shut (429)" 429 "$(bad)"
chk "  and it says how long to wait"        yes \
    "$(curl -s -D h1 -o /dev/null -X POST "$U/api/login" -d 'username=tuser&password=wrongwrongwrong' 2>/dev/null; \
       grep -qi '^retry-after: *[1-9]' h1 && echo yes || echo no)"

echo "=== ⚠️ the CORRECT password is refused too, while the backoff holds ==="
# This is the assertion that separates a real throttle from a cosmetic one. If the right
# password still gets in, an attacker's guesses are being counted but not blocked — the
# check has to run BEFORE the password is looked at, which also stops a locked-out attempt
# ⚠️ A ONE-SECOND WINDOW IS WHY THIS ASSERTION KEPT FLAKING — three times, each "fixed" by
# widening a budget rather than by measuring the right thing. The backoff is
# 1 << (failures - threshold - 1) seconds from the LAST RECORDED failure, and a refused
# attempt answers 429 BEFORE record_failure runs, so neither a 429 nor the Retry-After probe
# re-stamps it. Judged straight after the threshold that window is one second, which a loaded
# machine cannot promise to land inside — and the clock ticks in whole seconds anyway, so it
# could not be judged even if it did.
#
# The previous shape timed the judged request's own DURATION against a budget of 5. That is
# not the deciding interval — a fast request that arrived seconds late measured small and
# the precondition passed anyway, so the guard reported "the throttle is cosmetic" while
# proving nothing. A budget wider than the window it guards can only ever be vacuous.
#
# So ESCALATE first, the way the EST-side twin does. Sleeping the current window + 1 makes
# the next attempt land after the window and therefore be COUNTED rather than refused early,
# and every counted failure doubles the window. Three escalations take it from 1s to 8s,
# which second granularity can judge honestly, and the budget is then derived from the
# code's own formula instead of assumed.
# `fails` and window_now() are maintained from the top of this suite now, counting what the
# server actually recorded rather than assuming which attempts were refused.
counted=0
for _ in 1 2 3; do
    sleep $(( $(window_now) + 1 ))
    attempt
    [ "$ATT" = "401" ] && counted=$((counted + 1))
done
GAP_BUDGET=$(window_now)          # the window the code actually produces, not an assumed one
t0=$(date +%s); verdict="$(good)"; gap=$(( $(date +%s) - t0 ))

# ⚠️ ANTI-VACUITY. If an escalation attempt came back 429 the sleep was short, that failure
# was never recorded, and the window is not the one GAP_BUDGET now claims — judging against
# a window that does not exist is exactly how this assertion passed while proving nothing.
chk "PRECONDITION: every escalation attempt was recorded (401, not refused early)" 3 "$counted"
chk "PRECONDITION: the judged request landed inside the ${GAP_BUDGET}s window" yes \
    "$([ "$verdict" = "429" ] || [ "$gap" -le "$GAP_BUDGET" ] && echo yes || echo no)"
[ "$verdict" = "429" ] || [ "$gap" -le "$GAP_BUDGET" ] || \
    echo "         the judged request took ${gap}s against a ${GAP_BUDGET}s window, so the" \
         "lockout had expired before it arrived — the harness lost a race, not the throttle"
chk "correct password during backoff -> 429" 429 "$verdict"

echo "=== it EXPIRES — this is a delay, not a permanent lockout ==="
# A control that locks a real user out until an administrator intervenes is one that gets
# removed after the first support call.
sleep 12
chk "after the window, the correct password works again" 200 "$(good)"

echo "=== and success clears the count, so the next mistake starts from zero ==="
# Otherwise a user who mistypes twice a day would be permanently near the threshold.
chk "1st wrong after a success -> 401" 401 "$(bad)"
chk "2nd wrong after a success -> 401" 401 "$(bad)"
chk "3rd wrong after a success -> 401" 401 "$(bad)"
chk "still not locked out"             401 "$(bad)"

echo "=== a DIFFERENT account is not locked out by this one's failures ==="
# The account key and the address key are counted separately for a reason, but a suite
# running from one host cannot vary the address — so this asserts the half it can see:
# hammering one account must not deny another. (Both keys apply and the LONGER wait wins,
# so the sleep above has to outlast the address key too — otherwise this would fail for the
# address rather than the account and say nothing about the distinction it is testing.)
seed_web_user other otherpw12345 admin
sleep 12
chk "the other account can still sign in" 200 \
    "$(code -X POST "$U/api/login" -d 'username=other&password=otherpw12345')"

echo "=== a refused attempt is auditable ==="
# A lockout nobody can see is a support ticket with no evidence behind it.
chk "the throttled attempt is in the audit trail" 1 \
    "$("$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -tAc \
        "select least(count(*),1) from audit_log where action='web_login_throttled'" 2>/dev/null)"

kill $P 2>/dev/null; wait $P 2>/dev/null
echo
echo "=== LOGIN THROTTLE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
