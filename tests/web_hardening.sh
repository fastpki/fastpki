#!/usr/bin/env bash
# Console hardening: request-body limits, the API bearer token, session eviction on a
# password change, the leaf validity clamp, and the browser-hardening headers.
#
# Five separate defects, one suite, because they need the same expensive fixture — a token
# CA, a console and a logged-in session — and standing four of those up separately would
# quadruple the runtime for nothing.
#
#   1. NO REQUEST BODY LIMIT. Every other listener capped its bodies; the console did not,
#      so httplib's 100 MB default applied and the whole body is buffered before any
#      handler runs — on endpoints that are pre-auth by design. Unauthenticated memory
#      exhaustion, one request at a time.
#   2. THE API BEARER TOKEN was compared with `std::string ==`, which stops at the first
#      differing byte. The timing of that leaks how much of an admin-equivalent token a
#      guess got right. ⚠️ The timing property itself is NOT shell-testable and this suite
#      does not pretend to measure it — what is asserted here is that the constant-time
#      comparison still accepts the right token and rejects wrong ones, including the
#      prefix and length cases a hand-rolled compare gets wrong.
#   3. A PASSWORD CHANGE LEFT EVERY OTHER SESSION ALIVE. Changing a password under
#      suspicion is meant to evict whoever might be using the old one; it did nothing to a
#      session already established, so the attacker simply kept the cookie they had.
#   4. A LEAF COULD OUTLIVE ITS ISSUER. Only the CA re-key path clamped notAfter. An
#      issuing CA in its last year handed out certificates running years past its own
#      expiry — valid on their face, chainable by nobody.
#   5. NOTHING STOPPED ANOTHER SITE FRAMING THE CONSOLE. SameSite=Strict keeps a cross-site
#      request from carrying the session, but not the signed-in user from being walked
#      through a framed console (clickjacking), where CAs are deleted and certificates
#      revoked. And no answer said nosniff, so a JSON or PEM body could be sniffed into a
#      script. ⚠️ HSTS is asserted ABSENT: it binds the whole host name, every port, and the
#      same name serves OCSP, CRLs and AIA over plain http.
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
W="$(mktemp -d)"; cd "$W"; PORT=18299
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
U="http://127.0.0.1:$PORT"

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi

# A CA whose own validity is SHORT, so the clamp has something to clamp against.
ca_in_token shortca.pem "/CN=Short Lived CA" 30 shortca
CA_KEY="$CA_KEY_URI"

pg_setup web_hardening
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains "$W/domains.txt"
TOKEN="tok-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/shortca.pem
SIGNING_CA_KEY=$CA_KEY
SIGNING_CA_ID=shortca
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
WEB_TOKEN=$TOKEN
CERT_VALIDITY_DAYS=730
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf
seed_web_user hadmin hadminpw12345 admin
"$ROOT/build/fastpki-web" --config bootstrap.conf >web.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; tail -20 web.log; echo "RESULT: FAIL"; exit 1; }

echo "=== 1. request bodies are capped, and the cap applies BEFORE authentication ==="
head -c 2000000 /dev/zero | tr '\0' 'a' > big.txt          # 2 MB, over the 1 MiB API limit
printf 'username=x&password=y' > small.txt
# ⚠️ THE CONTENT TYPE IS PART OF THE TEST, and getting it wrong made the first version of
# this assertion pass against the UNFIXED server. httplib caps FORM-urlencoded bodies at
# 8 KB of its own accord, so a `curl --data-binary` (which sends that content type) was
# already answered 413 by the library and the assertion measured nothing of ours. The
# uncapped surface was always the routes that take a NON-form body — a CSR, a backup — so
# that is what has to be sent here.
BIN_CT='Content-Type: application/octet-stream'
chk "an oversized NON-form body, pre-auth route -> 413" 413 \
    "$(curl -s -o /dev/null -w '%{http_code}' -H "$BIN_CT" -X POST --data-binary @big.txt "$U/api/login")"
# Control: the same endpoint with an ordinary body still behaves normally, so the 413
# above is the size limit and not the endpoint being broken.
chk "  control: an ordinary body still reaches the handler" 401 \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST --data-binary @small.txt "$U/api/login")"
chk "an oversized NON-form body, authenticated route -> 413" 413 \
    "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H "$BIN_CT" \
        -X POST --data-binary @big.txt "$U/api/certs/request?ca_instance=shortca")"
# The library's own 8 KB form limit still stands underneath ours — asserted so that if a
# future httplib drops it, this suite says so rather than going quietly weaker.
chk "  and httplib still caps form bodies on its own" 413 \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST --data-binary @big.txt "$U/api/login")"

echo "=== 2. the API bearer token: right one in, wrong ones out ==="
# ⚠️ NOT a timing measurement — see the header. These assert the constant-time compare did
# not change WHICH tokens are accepted, including the two shapes a hand-rolled loop most
# easily gets wrong: a correct prefix, and a correct value with something appended.
chk "the correct token authenticates"            200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$U/api/me")"
chk "a wrong token is refused"                   401 \
    "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer wrongwrongwrong" "$U/api/me")"
chk "a correct PREFIX of the token is refused"   401 \
    "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${TOKEN%??}" "$U/api/me")"
chk "the token with a suffix appended is refused" 401 \
    "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${TOKEN}x" "$U/api/me")"
chk "an empty bearer is refused"                 401 \
    "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer " "$U/api/me")"

echo "=== 3. changing a password ends the user's OTHER sessions ==="
curl -s -c a.cj -o /dev/null -X POST "$U/api/login" -d 'username=hadmin&password=hadminpw12345'
curl -s -c b.cj -o /dev/null -X POST "$U/api/login" -d 'username=hadmin&password=hadminpw12345'
chk "both sessions start authenticated (A)" 200 "$(curl -s -o /dev/null -w '%{http_code}' -b a.cj "$U/api/me")"
chk "both sessions start authenticated (B)" 200 "$(curl -s -o /dev/null -w '%{http_code}' -b b.cj "$U/api/me")"
chk "the password change succeeds"          200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b a.cj -X POST "$U/api/password" \
        -d 'old=hadminpw12345&new=hadminpw54321')"
# The other session is the whole point.
chk "the OTHER session is now dead"         401 "$(curl -s -o /dev/null -w '%{http_code}' -b b.cj "$U/api/me")"
# And the one that made the change survives — signing the user out of the browser they
# just used would make a successful change look like a failure.
chk "  and the changing session survives"   200 "$(curl -s -o /dev/null -w '%{http_code}' -b a.cj "$U/api/me")"
# Decode what the system HOLDS, not just the status codes: the row must be gone too, or a
# peer node reading web_sessions would still honour the evicted cookie.
chk "  exactly one session row remains"     1 \
    "$("$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -tAc \
        "select count(*) from web_sessions where lower(username)='hadmin'" 2>/dev/null)"

echo "=== 4. a leaf may not outlive the CA that signs it ==="
# CERT_VALIDITY_DAYS is 730 and this CA has 30 days left, so an unclamped issuance would
# hand back a certificate valid two years past its own issuer's expiry.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr \
    -subj "/CN=clamped.internal" >/dev/null 2>&1
curl -s -b a.cj -X POST --data-binary @leaf.csr "$U/api/certs/request?ca_instance=shortca" \
    | sed -n 's/.*"pem":"\(.*\)".*/\1/p' | sed 's/\\n/\n/g' > leaf.pem
chk "the leaf was issued"           yes "$([ -s leaf.pem ] && echo yes || echo no)"
CA_END=$("$OSSL" x509 -in shortca.pem -noout -enddate 2>/dev/null | cut -d= -f2)
LF_END=$("$OSSL" x509 -in leaf.pem    -noout -enddate 2>/dev/null | cut -d= -f2)
chk "its notAfter equals the CA's"  "$CA_END" "$LF_END"
# Anti-vacuity: if the fixture CA were long-lived the assertion above would pass without
# any clamping happening at all, and this suite would be a decoration.
chk "  fixture: the CA really is short-lived (< 730d)" yes \
    "$("$OSSL" x509 -in shortca.pem -noout -checkend $((700*86400)) >/dev/null 2>&1 && echo no || echo yes)"

echo "=== 5. no console answer may be framed or sniffed ==="
hdr(){ curl -s -o /dev/null -D - "${@:2}" | tr -d '\r' | sed -n "s/^$1: //Ip" | head -1; }
chk "PRECONDITION: the session is signed in"      200 "$(curl -s -o /dev/null -w '%{http_code}' -b a.cj "$U/api/me")"
chk "PRECONDITION: the gate refuses no session"   401 "$(curl -s -o /dev/null -w '%{http_code}' "$U/api/users")"
for _w in "the page|$U/" "an API answer|-b a.cj $U/api/me" "the gate's 401|$U/api/users" "a 404|$U/no-such-page"; do
    _n=${_w%%|*}; _a=${_w#*|}
    # shellcheck disable=SC2086  # _a is a curl argument list on purpose
    chk "$_n: X-Frame-Options: DENY"                   DENY                    "$(hdr X-Frame-Options $_a)"
    # shellcheck disable=SC2086
    chk "$_n: CSP frame-ancestors 'none'"              "frame-ancestors 'none'" "$(hdr Content-Security-Policy $_a)"
    # shellcheck disable=SC2086
    chk "$_n: X-Content-Type-Options: nosniff"         nosniff                 "$(hdr X-Content-Type-Options $_a)"
    # shellcheck disable=SC2086
    chk "$_n: no Strict-Transport-Security"            ""                      "$(hdr Strict-Transport-Security $_a)"
done

kill $P 2>/dev/null; wait $P 2>/dev/null
echo
echo "=== WEB HARDENING: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
