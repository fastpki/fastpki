#!/usr/bin/env bash
# The console session cookie must carry `Secure` when — and only when — the console is
# actually serving TLS.
#
# THE DEFECT THIS GUARDS. The cookie carried HttpOnly and SameSite and nothing else. Those
# two stop script access and cross-site sends; neither stops the browser attaching the
# token to a plaintext same-host request, which is the case `Secure` exists for. It was
# missing at all four Set-Cookie sites, so there was not even an inconsistency to notice.
#
# ⚠️ AND THE OTHER DIRECTION IS AN ASSERTION TOO, not a leftover. `Secure` on a cookie sent
# over plain HTTP makes the browser DISCARD it. Hardcoding the flag would therefore break
# every non-TLS console into a shape that looks like it works — the login returns 200 and a
# cookie, and every request after it is anonymous, with nothing in any log to say why. So
# the flag is gated on TLS being configured, and a guard that only checked the TLS case
# would bless exactly that failure.
#
# Both halves run the SAME binary with the same login, differing only in whether a TLS key
# is configured. That is what makes this a test of the gate rather than of two unrelated
# code paths.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18297
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi

pg_setup session_cookie_secure
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
seed_web_user cuser cuserpw12345 admin

"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout srv.key -out srv.pem -days 3650 \
    -subj "/CN=localhost" >/dev/null 2>&1

base_conf(){
    cat > "$1" <<EOF
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
LOG_LEVEL=err
EOF
}

# Log in and return the raw Set-Cookie line. Reading the HEADER, not a cookie jar: curl's
# jar format drops the attributes, so a jar could never show whether the flag was sent —
# the thing being asserted would be invisible to the instrument.
login_cookie(){   # <scheme>
    curl -sk -D "$W/h.$$" -o /dev/null -X POST "$1://127.0.0.1:$PORT/api/login" \
        -d 'username=cuser&password=cuserpw12345' 2>/dev/null
    grep -i '^set-cookie:' "$W/h.$$" | tr -d '\r'
}

start(){ "$WEB" --config "$1" >"$2" 2>&1 & P=$!; sleep 1;
         kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat "$2"; echo "RESULT: FAIL"; exit 1; }; }
stop(){ kill $P 2>/dev/null; wait $P 2>/dev/null; P=; sleep 1; }

echo "=== plain HTTP console: the flag must be ABSENT ==="
base_conf plain.conf
start plain.conf plain.log
CK_PLAIN="$(login_cookie http)"
chk "the login sets a session cookie"  yes \
    "$(printf '%s' "$CK_PLAIN" | grep -q 'fastpki_session=' && echo yes || echo no)"
chk "it is HttpOnly"                   yes \
    "$(printf '%s' "$CK_PLAIN" | grep -q 'HttpOnly' && echo yes || echo no)"
chk "it sets SameSite"                 yes \
    "$(printf '%s' "$CK_PLAIN" | grep -qi 'SameSite=' && echo yes || echo no)"
# The load-bearing negative: with Secure here the browser would drop the cookie outright.
chk "and it is NOT marked Secure"      no \
    "$(printf '%s' "$CK_PLAIN" | grep -qi 'Secure' && echo yes || echo no)"
# Control: the session this cookie names must actually work, or "no Secure" above would be
# true of a login that failed for some entirely different reason.
chk "  control: that cookie authenticates" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: $(printf '%s' "$CK_PLAIN" | sed 's/^[Ss]et-[Cc]ookie: *//; s/;.*//')" \
        "http://127.0.0.1:$PORT/api/me" 2>/dev/null)"
stop

echo "=== TLS console: the flag must be PRESENT ==="
base_conf tls.conf
printf 'WEB_TLS_CERT=%s/srv.pem\nWEB_TLS_KEY=%s/srv.key\n' "$W" "$W" >> tls.conf
start tls.conf tls.log
CK_TLS="$(login_cookie https)"
chk "the login sets a session cookie"  yes \
    "$(printf '%s' "$CK_TLS" | grep -q 'fastpki_session=' && echo yes || echo no)"
chk "it IS marked Secure"              yes \
    "$(printf '%s' "$CK_TLS" | grep -qi 'Secure' && echo yes || echo no)"
chk "  and still HttpOnly"             yes \
    "$(printf '%s' "$CK_TLS" | grep -q 'HttpOnly' && echo yes || echo no)"
chk "  control: that cookie authenticates" 200 \
    "$(curl -sk -o /dev/null -w '%{http_code}' -H "Cookie: $(printf '%s' "$CK_TLS" | sed 's/^[Ss]et-[Cc]ookie: *//; s/;.*//')" \
        "https://127.0.0.1:$PORT/api/me" 2>/dev/null)"
stop

echo
echo "=== SESSION COOKIE SECURE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
