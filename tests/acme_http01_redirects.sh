#!/usr/bin/env bash
# ACME http-01: which redirects the CA follows while validating, and which it refuses.
#
# ⚠️ WHY THIS IS A TEST. Validation followed every redirect a challenge response gave, to any
# host, port and scheme, so an ACME account could make the CA send a GET to an internal
# service on any port or to the cloud metadata endpoint (169.254.169.254). RFC 8555 §8.3
# says redirects SHOULD be followed, and http -> https is the everyday case, so they still
# are, within rules asserted here:
#   - http and https only, on ports 80 and 443;
#   - at most 10 redirects;
#   - every hop's address is checked before it is dialled: link-local, unspecified,
#     multicast and reserved addresses are refused;
#   - loopback and private ranges are ALLOWED: a private CA validates names that resolve
#     to private addresses, and a single-host install validates over loopback.
#
# The challenge responder is replaced by one that answers with a scripted redirect, so each
# rule is driven by a real order against a real fastpki-acme. Needs ports 80 and 443: root on
# Linux (the ROOT tier), any user on macOS.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; PORT=18471; OTHER=18081
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
source "$ROOT/tests/acme_jws.sh"
command -v nc >/dev/null 2>&1 || { echo "FAIL: nc is needed for the challenge responder"; exit 1; }
# The listen flag differs: GNU and busybox take `nc -l -p PORT`, BSD and macOS `nc -l PORT`.
# ⚠️ ASK WHETHER nc IS STILL LISTENING, not whether `kill` succeeded: `kill %%` also succeeds
# on a job that has already exited, so macOS's nc, which rejects `-l -p` at once, was taken
# for one that accepts it, and no responder ever listened.
nc -l -p "$OTHER" </dev/null >/dev/null 2>&1 & _p=$!; sleep 0.3
if kill -0 $_p 2>/dev/null; then NCL="-l -p"; kill $_p 2>/dev/null; else NCL="-l"; fi
wait $_p 2>/dev/null
if [ "$(uname)" != Darwin ] && [ "$(id -u)" != 0 ]; then
    echo "SKIP: http-01 validation dials port 80, which only root can bind here"; exit 0
fi

ca_in_token ca.pem "/CN=HTTP01 Redirect CA" 3650
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_http01_redirects
SRV=; SPID=; OPID=
cleanup(){ _acme_respond_stop 2>/dev/null; kill $SPID $OPID $SRV 2>/dev/null; pg_cleanup; }
trap cleanup EXIT
cat > bootstrap.conf <<EOF
BASE_URL=https://localhost:$PORT
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ACME_CERT=$W/acme.pem
ACME_KEY=$W/acme.key
PG_CONNINFO=$PG_CONNINFO
ACME_BIND=127.0.0.1
ACME_PORT=$PORT
ACME_BASE_PATH=/acme
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf
"$ROOT/build/fastpki-acme" --config bootstrap.conf > srv.log 2>&1 & SRV=$!
wait_port "$PORT" "$SRV" || true
kill -0 $SRV 2>/dev/null || { echo "fastpki-acme died:"; tail -20 srv.log; exit 1; }
DIR="https://127.0.0.1:$PORT/acme/ca/directory"

# ── the scripted responder ──────────────────────────────────────────────────────────────
# Port 80 is a one-shot nc per connection, so it can answer only the FIRST request of a
# validation: the next one arrives before the next nc listens. It answers with
# "Location: $FIRST" when FIRST is set, or with the key authorization when it is not.
#
# Every later hop goes to https on 443, where `openssl s_server -HTTP` answers any number of
# requests, each with the complete HTTP response stored in the file its path names:
#   /ka    200 with this challenge's key authorization
#   /rel   302 to the relative Location "/ka"
#   /loop  302 to itself
FIRST=""
HTTPS_ROOT="$W/webroot"; mkdir -p "$HTTPS_ROOT"
_acme_http_serve() {   # <port> <key-authorization>   (replaces acme_jws.sh's)
    local port=$1 ka=$2 resp
    printf 'HTTP/1.1 200 OK\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' "${#ka}" "$ka" > "$HTTPS_ROOT/ka"
    printf 'HTTP/1.1 302 Found\r\nLocation: /ka\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' > "$HTTPS_ROOT/rel"
    printf 'HTTP/1.1 302 Found\r\nLocation: https://localhost/loop\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' > "$HTTPS_ROOT/loop"
    if [ -n "$FIRST" ]; then resp="HTTP/1.1 302 Found\r\nLocation: $FIRST\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    else resp="HTTP/1.1 200 OK\r\nContent-Length: ${#ka}\r\nConnection: close\r\n\r\n$ka"; fi
    ( ncpid=
      trap 'kill $ncpid 2>/dev/null; exit 0' TERM INT
      while :; do
          printf "$resp" | nc $NCL "$port" >/dev/null 2>&1 &
          ncpid=$!
          wait "$ncpid" || break
      done ) &
    _ACME_RESP_PID=$!
    wait_listen "$port" "$_ACME_RESP_PID" 10 || true
    return 0
}
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout tls.key -out tls.pem -days 1 -subj "/CN=localhost" >/dev/null 2>&1
( cd "$HTTPS_ROOT" && exec "$OSSL" s_server -accept 443 -HTTP -cert "$W/tls.pem" -key "$W/tls.key" -quiet ) > s_server.log 2>&1 & SPID=$!
wait_listen 443 "$SPID" 10 || true
chk "PRECONDITION: the https responder is listening on 443" yes "$(kill -0 $SPID 2>/dev/null && echo yes || echo no)"

# Run one http-01 order for localhost; prints "valid" or the server's reason.
order() {
    local out
    acme_http01_order "$DIR" localhost > order.out 2> order.err && { echo valid; return; }
    out=$(sed -n 's/.*the server said: .*"detail":"\([^"]*\)".*/\1/p' order.err | head -1)
    echo "${out:-<no reason: $(head -c 200 order.err | tr '\n' ' ')>}"
}

echo "=== allowed ==="
FIRST="";                                    chk "no redirect: valid"                              valid "$(order)"
FIRST="https://localhost/ka";                chk "http -> https on 443 (self-signed): valid"       valid "$(order)"
FIRST="https://127.0.0.1/ka";                chk "to a loopback address: valid"                    valid "$(order)"
FIRST="https://localhost/rel";               chk "then a relative Location: valid"                 valid "$(order)"
PRIV=$( { ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1; ifconfig 2>/dev/null | awk '/inet /{print $2}'; } \
        | grep -E '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' | head -1)
if [ -n "$PRIV" ]; then
    FIRST="https://$PRIV/ka";                chk "to a private address ($PRIV): valid"             valid "$(order)"
else
    chk "PRECONDITION: this host has a private (RFC 1918) address to redirect to" yes no
fi

echo "=== refused ==="
r=$(FIRST="http://169.254.169.254/latest/meta-data/" order)
chk "to the metadata address: refused as link-local"  yes "$(printf '%s' "$r" | grep -q 'link-local' && echo yes || echo "no: $r")"
r=$(FIRST="http://[fe80::1]/x" order)
chk "to an IPv6 link-local address: refused"           yes "$(printf '%s' "$r" | grep -q 'link-local' && echo yes || echo "no: $r")"
# A listener on the refused port records whether the CA dialled it anyway.
: > other.log
( nc $NCL "$OTHER" > other.log 2>/dev/null ) & OPID=$!
wait_listen "$OTHER" "$OPID" 5 || true
r=$(FIRST="http://127.0.0.1:$OTHER/x" order)
chk "to another port: refused, naming the port"        yes "$(printf '%s' "$r" | grep -q "port $OTHER" && echo yes || echo "no: $r")"
chk "  and that port was never dialled"                0   "$(wc -c < other.log | tr -d ' ')"
kill $OPID 2>/dev/null; wait $OPID 2>/dev/null; OPID=
r=$(FIRST="ftp://127.0.0.1/x" order)
chk "to an ftp URL: refused, naming the scheme"        yes "$(printf '%s' "$r" | grep -q "'ftp'" && echo yes || echo "no: $r")"
r=$(FIRST="https://localhost/loop" order)
chk "a redirect loop: refused after 10"                yes "$(printf '%s' "$r" | grep -q 'more than 10 times' && echo yes || echo "no: $r")"
r=$(FIRST="http://user:pw@127.0.0.1/x" order)
chk "a URL carrying credentials: refused"              yes "$(printf '%s' "$r" | grep -q 'credentials' && echo yes || echo "no: $r")"

echo
echo "=== ACME HTTP-01 REDIRECTS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
