#!/usr/bin/env bash
# Who the audit log says a client was, when a proxy is in front.
#
# THE DEFECT THIS GUARDS. Behind a load balancer or a reverse proxy — the shape
# docs/high-availability.md documents for an HA pair — every request arrives from the
# proxy's address. The audit log then stamps every issuance, revocation and configuration
# change with one address and cannot attribute any of them, and the per-address half of the
# sign-in backoff becomes a deployment-wide delay, so one person's mistyped password slows
# everybody down. Nothing in the tree read X-Forwarded-For at all.
#
# ⚠️ AND THE FIX IS ITSELF A WAY IN IF IT TRUSTS TOO EASILY. X-Forwarded-For is written by
# whoever sends it. A server that believes it unconditionally lets any caller choose what
# the audit log records about them and slip the backoff with a fresh address per attempt —
# strictly worse than recording the proxy honestly. So trust is explicit, TRUSTED_PROXIES
# has no default, and the cases below drive BOTH directions: honoured from a configured
# proxy, ignored from anything else.
#
# Self-contained: ephemeral Postgres, own port, temp dir, SKIPs cleanly when no Postgres is
# reachable. TRUSTED_PROXIES is pending-restart, so each case restarts the console.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18297
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
U="http://127.0.0.1:$PORT"

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi

pg_setup trusted_proxies
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
seed_web_user tuser tuserpw12345 admin

# Restart the console with one TRUSTED_PROXIES value. Empty means the key is absent
# altogether, which is the shipped default and must behave as it always did.
restart(){                       # restart <trusted-proxies value, or empty for unset>
    [ -n "${P:-}" ] && { kill "$P" 2>/dev/null; wait "$P" 2>/dev/null; }
    { echo "PG_CONNINFO=$PG_CONNINFO"
      echo "AUTH_BACKEND=local"
      echo "WEB_BIND=127.0.0.1"
      echo "WEB_PORT=$PORT"
      echo "LOG_LEVEL=err"
      [ -n "$1" ] && echo "TRUSTED_PROXIES=$1"
    } > web.conf
    "$WEB" --config web.conf >web.log 2>&1 & P=$!
    wait_conf "web.conf" WEB_PORT "$P" || true
    kill -0 "$P" 2>/dev/null || { echo "fastpki-web died:"; cat web.log; echo "RESULT: FAIL"; exit 1; }
}

# One failed sign-in carrying the given X-Forwarded-For, and the address the server recorded
# for it. A wrong password is used deliberately: web_login_fail is written on every attempt
# with no other state to disturb, and the actor_ip on it is the value under test.
#
# ⚠️ READ BACK THE ROW THIS ATTEMPT WROTE, not the newest row of that action. The suite
# restarts the server between cases and every case writes the same action, so matching on
# the action alone would happily assert against a previous case's row and pass while the
# current one recorded nothing at all.
recorded_ip(){                   # recorded_ip <x-forwarded-for value, or empty for none>
    local marker="probe-$RANDOM-$RANDOM"
    if [ -n "$1" ]; then
        curl -s -o /dev/null -X POST "$U/api/login" \
             -H "X-Forwarded-For: $1" -d "username=$marker&password=wrongwrongwrong"
    else
        curl -s -o /dev/null -X POST "$U/api/login" \
             -d "username=$marker&password=wrongwrongwrong"
    fi
    pg_exec "select coalesce(max(actor_ip),'NONE') from audit_log where actor='$marker'"
}

echo "=== with TRUSTED_PROXIES unset, the header is ignored ==="
# The shipped default. A deployment with nothing in front must behave exactly as before,
# and a client that invents a header must not be able to change what is recorded.
restart ""
chk "no header: the connection address is recorded" 127.0.0.1 "$(recorded_ip '')"
chk "a forged header changes nothing"               127.0.0.1 "$(recorded_ip '203.0.113.9')"

echo "=== from a configured proxy, the header is believed ==="
# The test client IS the proxy here: it connects from 127.0.0.1, which is what the config
# names, so its X-Forwarded-For is the one a real proxy would have written.
restart "127.0.0.1"
chk "the client's own address is recorded" 203.0.113.9 "$(recorded_ip '203.0.113.9')"
chk "with no header, the connection address stands" 127.0.0.1 "$(recorded_ip '')"

echo "=== the header is read right to left ==="
# Each proxy APPENDS what it saw, so the rightmost entries are the ones our own proxies
# wrote and the leftmost is whatever the caller put there before any proxy saw it. Reading
# left to right — the obvious implementation, and the wrong one — would return 198.51.100.7
# here, which is precisely the value an attacker controls.
chk "the rightmost untrusted hop wins, not the first" 203.0.113.9 \
    "$(recorded_ip '198.51.100.7, 203.0.113.9')"

echo "=== a proxy that is not ours is not believed ==="
# Same header, same client, but the configured proxy is somebody else's address. The
# connection is not from a trusted proxy, so the header is worth nothing.
restart "10.99.99.99"
chk "an untrusted peer's header is ignored" 127.0.0.1 "$(recorded_ip '203.0.113.9')"

echo "=== an IPv4 prefix matches a client on a dual-stack listener ==="
# ⚠️ THE CASE MOST LIKELY TO LOOK CONFIGURED AND DO NOTHING. Every listener binds the IPv6
# wildcard with V6ONLY off, so an IPv4 client can arrive as ::ffff:127.0.0.1. Compared
# literally against 127.0.0.0/8 that never matches, the header is silently ignored, and the
# operator sees a setting that is present and has no effect.
restart "127.0.0.0/8"
chk "a CIDR prefix matches the client" 203.0.113.9 "$(recorded_ip '203.0.113.9')"
restart "::1/128, 127.0.0.0/8"
chk "a mixed v4/v6 list still matches" 203.0.113.9 "$(recorded_ip '203.0.113.9')"

echo "=== a prefix wide enough to contain the client still finds the client ==="
# ⚠️ THE CASE A REAL PROXY FOUND AND THIS SUITE DID NOT. Naming one internal prefix rather
# than listing each proxy is normal, and then the CLIENT is inside the trusted range too.
# Walking right to left past every trusted hop runs out of entries, and the obvious reading
# of that — "no untrusted hop, so use the peer" — records the PROXY, which is the whole
# defect this exists to remove. With every hop trusted, the leftmost is still what the
# outermost proxy saw, so it is the client.
#
# Measured with nginx in front of the console and the prefix covering both: every request was
# attributed to nginx until this was fixed. The cases above could not see it, because there
# the forwarded address sat outside the trusted range.
restart "127.0.0.0/8, 203.0.113.0/24"
chk "a client inside the trusted range is still the client" 203.0.113.9 \
    "$(recorded_ip '203.0.113.9')"
chk "  and with a chain, the outermost hop wins" 203.0.113.9 \
    "$(recorded_ip '203.0.113.9, 127.0.0.9')"

echo "=== a prefix that does not contain the client does not match ==="
# The partial-byte case: 127.0.0.1 is not in 127.128.0.0/9, and a matcher that compared
# whole bytes only would say it is.
restart "127.128.0.0/9"
chk "a near-miss prefix is still a miss" 127.0.0.1 "$(recorded_ip '203.0.113.9')"

echo "=== every protocol records a source address, and all of them the same way ==="
# ⚠️ THE POINT IS UNIFORMITY, NOT THAT SOME SERVICE SOMEWHERE DOES IT. CMP recorded an empty
# address for every enrolment, revocation and authorization refusal while the other five
# recorded one, because its audit events are written from OpenSSL's callbacks, which get no
# request. An operator reading the log saw CMP transactions that came from nowhere. It now
# stashes the address at the HTTP layer for the duration of the request.
#
# The live cases above drive the console, which is the door with the throttle. These are
# source assertions, because driving all six protocols to check one field would cost far
# more than it proves — and what actually regresses is a NEW audit site written with the raw
# socket address, which is exactly what the third check catches.
for svc in web acme est scep msxcep cmp; do
    f="$ROOT/src/$svc/main.cpp"
    chk "  $svc resolves the client through pki::real_client_ip" yes \
        "$(grep -q 'pki::real_client_ip' "$f" && echo yes || echo no)"
    chk "    and stamps its audit events with the result" yes \
        "$(grep -qE 'actor_ip = (client_ip\(req\)|g_client_ip)' "$f" && echo yes || echo no)"
    # The regression this guards: a new audit site added with the raw socket address, which
    # behind a proxy records the proxy and looks perfectly correct in a direct test.
    chk "    and no audit site uses the socket address directly" 0 \
        "$(grep -c 'actor_ip = req\.remote_addr' "$f")"
done
# If one of these starts writing audit events, it needs the same treatment and this suite
# needs a row for it. OCSP answers status and the store answers searches; neither
# authenticates a caller, so neither has anything to attribute.
for svc in ocsp certstore; do
    chk "  $svc still writes no audit events, so it needs no address" 0 \
        "$(cat "$ROOT"/src/$svc/*.cpp 2>/dev/null | grep -c 'append_audit')"
done

echo
echo "=== TRUSTED PROXIES: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ] || echo "RESULT: FAIL"
exit $(( fail > 0 ))
