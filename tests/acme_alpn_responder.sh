#!/usr/bin/env bash
# The tls-alpn-01 responder helper in tests/acme_jws.sh (RFC 8737).
#
# ⚠️ THIS SUITE GUARDS THE INSTRUMENT, NOT THE PRODUCT — deliberately. The helper used to
# background `openssl s_server`, sleep, and return success unconditionally. On a port that
# was already held it therefore reported a responder it had not started, and the ACME
# server dutifully validated against whatever else was listening.
#
# The worst version of that is a responder LEAKED by an earlier run: it negotiates
# acme-tls/1 correctly and presents a real acmeIdentifier extension, just for the previous
# challenge's token. The server then answers, entirely correctly, that the digest does not
# match the key authorization — and the report reads as a broken CA when the cause is a
# listener nobody killed. Every assertion here is about making that distinction impossible
# to miss, so no server and no database are needed.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and is absent on a Mac. Without this the
# suite still RUNS and every assertion compares empty strings, which reads as a real fault.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
W="$(mktemp -d)"; cd "$W"
# ⚠️ EVERY REAL CALLER ALREADY HAS ONE — acme_dir() sets it. Leaving it unset here made
# the helper die on `set -u` before it reached the code under test, so the suite
# measured a missing variable and reported it as the defect.
export JWS_TMP="$W/jws"; mkdir -p "$JWS_TMP"
PORT=14457; HTTPPORT=14458
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }
has() { echo "$1" | grep -qF "$2" && echo yes || echo no; }
source "$ROOT/tests/acme_jws.sh"
SQUAT=; HTTPSQUAT=
trap 'alpn_stop; _acme_respond_stop 2>/dev/null; for p in $SQUAT $HTTPSQUAT; do kill $p 2>/dev/null; done; rm -rf "$W"' EXIT

jws_newkey acct.pem

echo "=== 1. a free port: the responder starts and serves its own certificate ==="
alpn_cert localhost tok-good acct.pem val_good
chk "alpn_cert reports the certificate it wrote" 0 $?
alpn_serve "$PORT" val_good; rc=$?
chk "alpn_serve succeeds on a free port" 0 "$rc"
chk "and it left a live listener" yes "$(kill -0 ${ALPN_PID:-0} 2>/dev/null && echo yes || echo no)"
# ⚠️ The helper now makes its own probe connection to check the certificate. `s_server`
# accepts in a loop, but if that ever changed the probe would eat the ONE accept the real
# validation needs and every challenge would time out — with the helper reporting success.
served=$("$OSSL" s_client -connect "127.0.0.1:$PORT" -alpn acme-tls/1 </dev/null 2>/dev/null \
         | "$OSSL" x509 -noout -fingerprint -sha256 2>/dev/null)
ours=$("$OSSL" x509 -in val_good.pem -noout -fingerprint -sha256)
chk "a SECOND connection is still served (the self-check did not consume the accept)" "$ours" "$served"
alpn_stop; sleep 0.4

echo
echo "=== 2. a leaked responder holds the port, carrying an EARLIER token's digest ==="
alpn_cert localhost tok-stale acct.pem val_stale
"$OSSL" s_server -accept "$PORT" -cert val_stale.pem -key val_stale.key \
    -alpn acme-tls/1 -quiet -no_ticket >squat.log 2>&1 &
SQUAT=$!
# wait_listen, not wait_port: this listener serves ONE connection, so a probe that
# connects would BE the request the assertion is about (pg_helpers.sh).
wait_listen "$PORT" "$SQUAT" || true
chk "the squatter really is holding the port" yes \
    "$(kill -0 $SQUAT 2>/dev/null && echo yes || echo no)"
alpn_cert localhost tok-fresh acct.pem val_fresh
# ⚠️ A FILE, NOT `$( )`. Command substitution runs the helper in a SUBSHELL, so ALPN_PID
# never reaches this shell and the assertion below compared the value section 1 had already
# cleared — passing identically with and without the fix.
alpn_serve "$PORT" val_fresh 2>refuse.log; rc=$?
why=$(cat refuse.log)
chk "alpn_serve REFUSES the held port" 1 "$rc"
chk "and it hands back no pid, so nothing later kills a stranger" "" "${ALPN_PID:-}"
# ⚠️ MATCH A PHRASE ONLY THE REFUSAL CAN PRODUCE. Grepping for "alpn" or "port" would also
# match the old success path's own output, so the assertion would pass against the very
# code it exists to reject.
chk "and says plainly this is not a product failure" yes "$(has "$why" "NOT a product failure")"
# ⚠️ ONE VERDICT, NOT TWO ASSERTIONS. "the message does not mention the digest" is true of
# an EMPTY message too, so as a standalone check it passed against the unfixed helper —
# which says nothing at all. Presence and content have to be judged together.
verdict=$([ -z "$why" ] && echo no-message \
          || { [ "$(has "$why" "digest")" = yes ] && echo blames-digest \
               || { [ "$(has "$why" "ALREADY IN USE")" = yes ] && echo names-the-port || echo says-something-else; }; })
chk "the refusal names the held port rather than the certificate" names-the-port "$verdict"

echo
echo "=== 3. a refusal that cannot be heard (the http-01 responder had this branch all along) ==="
# ⚠️ `exec 3<&- 3>&- 2>/dev/null` WITH NO COMMAND redirects THIS SHELL's stderr permanently,
# so every line the branch exists to print went to /dev/null. The http-01 responder has
# carried that refusal since long before tls-alpn-01 got one, and it has been mute the
# whole time: the suite must assert the explanation is HEARD, not merely written.
if command -v nc >/dev/null 2>&1; then
    # ⚠️ HOLD THE PORT WITH s_server, NOT `nc`. The listen flag is not portable — BSD takes
    # `nc -l PORT`, GNU and busybox want `nc -l -p PORT` — so `nc -l "$PORT"` binds on a Mac
    # and silently does NOT bind on Linux. That difference alone turned this section into
    # the exact hang it exists to test for (see below), and it wedged a whole lab gate.
    "$OSSL" s_server -accept "$HTTPPORT" -cert val_good.pem -key val_good.key \
        -quiet -no_ticket >/dev/null 2>&1 &
    HTTPSQUAT=$!
    held=no
    for i in $(seq 1 40); do
        if (exec 3<>/dev/tcp/127.0.0.1/"$HTTPPORT") 2>/dev/null; then
            { exec 3<&- 3>&-; } 2>/dev/null; held=yes; break
        fi
        sleep 0.25
    done
    # Without this the two assertions below would pass or fail for a reason that has
    # nothing to do with the refusal.
    chk "the port really is held before the refusal is asked for" yes "$held"

    # ⚠️ A FILE, NOT `$( )`. On a free port _acme_http_serve BACKGROUNDS a responder that
    # inherits the captured stderr, and a command substitution waits for EOF on that pipe —
    # which never comes while the responder lives. It hung forever. On this Mac the squatter
    # always bound, so the refusal returned before anything was backgrounded and the hang
    # could not appear; on Linux the port stayed free and the same line stalled the suite.
    _acme_http_serve "$HTTPPORT" keyauth 2>httprefuse.log >/dev/null; hrc=$?
    # Nothing to stop when it refused, everything to stop when it did not.
    _acme_respond_stop
    hwhy=$(cat httprefuse.log 2>/dev/null)
    chk "the http-01 responder refuses a port it does not own" 1 "$hrc"
    chk "and the refusal is actually printed, not swallowed" yes "$(has "$hwhy" "ALREADY IN USE")"
    kill $HTTPSQUAT 2>/dev/null; wait $HTTPSQUAT 2>/dev/null; HTTPSQUAT=
else
    echo "  [SKIP] nc is not installed — the http-01 refusal path cannot be driven here"
fi

echo
echo "=== 4. _acme_respond propagates the refusal instead of reporting a responder ==="
# Without this the order driver walks on and the failure surfaces as a digest mismatch
# three steps later, against a certificate that was never served.
_ACME_ALPN_PORT="$PORT" _acme_respond tls-alpn-01 localhost tok-fresh "tok-fresh.$(jws_thumbprint acct.pem)" \
    >/dev/null 2>&1; rc=$?
chk "_acme_respond fails when the responder could not bind" 1 "$rc"
kill $SQUAT 2>/dev/null; wait $SQUAT 2>/dev/null; SQUAT=

echo
echo "=== 5. a certificate that could not be written is reported, not assumed ==="
# ⚠️ A DIRECTORY THAT DOES NOT EXIST, NOT ONE MADE UNWRITABLE. `chmod 500` proves nothing
# when the suite runs as root, which it does in the in-image tier — root writes anyway, so
# this assertion passed on a Mac and failed in the container for a reason that has nothing
# to do with the code. A missing path cannot be written by any uid.
alpn_cert localhost tok-x acct.pem "$W/nosuchdir/val_x" >/dev/null 2>&1
chk "alpn_cert fails when it cannot write the certificate" 1 $?

echo
echo "=== ACME TLS-ALPN-01 RESPONDER: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
