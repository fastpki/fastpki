#!/usr/bin/env bash
# ACME CAA re-checking (RFC 8555 §8.1.1, RFC 8659), driven by REAL certbot.
#
# ⚠️ A HOME-MADE ACME CLIENT IS NOT ACCEPTED FOR ACME TESTS. Compliance is a claim about
# what real clients do, so it has to be proved with one: this suite used to drive the shell
# JWS client in tests/acme_jws.sh, and now runs `certbot certonly` and asserts on what
# certbot and the database say. certbot's own Python is fine — the no-Python rule covers OUR
# tests, not third-party tools.
#
# dns-01 on purpose: it needs no privileged port, so this stays a CORE suite that runs on
# any dev box. http-01 would drag it into the root tier for nothing (RFC 8555 pins http-01
# validation to port 80).
#
# ⚠️ One assertion genuinely changed shape. The old test read the literal HTTP status of
# the finalize POST (200 / 403). certbot cannot report that: acme/client.py's
# `_check_response` branches on `response.ok`, so every 2xx looks alike and no status code
# reaches the caller. The CAA refusal is therefore asserted three ways certbot CAN see —
# the command fails, no certificate is written, and the problem document it received is
# typed `caa`. That type is read out of certbot's own HTTP trace, because certbot renders a
# problem document as its `detail` alone and the RFC 8555 type never reaches the terminal.
# The database assertions are unchanged and are the strongest of the set.
# â ï¸ THIS SUITE REGISTERS WITH A REAL EAB BINDING, and that is the point. It used to
# pin ACME_EAB_REQUIRED=false because it tests ACME PROTOCOL mechanics and not deployment
# policy â but the switch is gone, and pinning it meant fourteen suites exercised a
# configuration FastPKI does not ship. The binding is now provisioned the way a real
# deployment provisions one: acme_seed_eab writes a kid + HMAC to the `keys` table and
# certbot presents them with --eab-kid/--eab-hmac-key.
# The DEFAULT itself is still exercised by acme_default_eab.sh, which provisions NOTHING.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/acme_jws.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
[ -n "$OSSL" ] || { echo "SKIP: no openssl on PATH"; exit 0; }
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
command -v certbot >/dev/null 2>&1 || { echo "SKIP: certbot not installed (needs the real client)"; exit 0; }
[ -x "$ROOT/build/dnsstub" ] || { echo "SKIP: build/dnsstub not built"; exit 0; }

W="$(mktemp -d)"; cd "$W"; PORT=18457; DNSP=15354; BASE=caa.example.org; IDENTITY=fastpki.test
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=CAA CA" 3650 || { echo "SKIP: could not mint a CA key in a token"; exit 0; }
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_caa
cat > bootstrap.conf <<EOF
BASE_URL=https://localhost:$PORT
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
ACME_CERT=$W/acme.pem
ACME_KEY=$W/acme.key
PG_CONNINFO=$PG_CONNINFO
ACME_BIND=127.0.0.1
ACME_PORT=$PORT
ACME_BASE_PATH=/acme
ACME_DNS_RESOLVER=127.0.0.1:$DNSP
ACME_CAA_IDENTITY=$IDENTITY
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
SRV=
# ONE trap: a later `trap ... EXIT` REPLACES rather than adds, and a $SRV-only version
# would drop pg_cleanup and leak a database per run.
trap 'kill $SRV 2>/dev/null; pkill -f "dnsstub $DNSP" 2>/dev/null; pg_cleanup' EXIT
"$ROOT/build/fastpki-acme" --config bootstrap.conf > srv.log 2>&1 & SRV=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$SRV" || true
if ! kill -0 $SRV 2>/dev/null; then echo "fastpki-acme died:"; cat srv.log; exit 1; fi

# certbot (python-requests) trusts the ACME server's self-signed cert through this.
export REQUESTS_CA_BUNDLE="$W/acme.pem"
acme_seed_eab caa
CB=(--server "https://localhost:$PORT/acme/ca/directory"
    --config-dir "$W/cb" --work-dir "$W/cbw" --logs-dir "$W/cbl" -n
    --eab-kid "$ACME_EAB_KID" --eab-hmac-key "$ACME_EAB_HMAC")

# dnsstub takes its records on the command line and has no runtime update, so the auth
# hook restarts it carrying this domain's challenge TXT. That is the same
# one-stub-per-order shape the suite always had; certbot only inverts WHEN the value is
# known — the hook is handed $CERTBOT_VALIDATION instead of the test deriving it from the
# token and the account thumbprint itself.
cat > authhook.sh <<'HOOK'
#!/usr/bin/env bash
set -u
pkill -f "dnsstub $DNSP" 2>/dev/null; sleep 0.2
recs=("TXT:_acme-challenge.$CERTBOT_DOMAIN=$CERTBOT_VALIDATION")
[ -n "${CAA_ISSUER:-}" ] && recs+=("CAA:$CERTBOT_DOMAIN=$CAA_ISSUER")
# An RCODE entry makes the CAA query at $CERTBOT_DOMAIN fail while the TXT at
# _acme-challenge.$CERTBOT_DOMAIN keeps working — which is the only way to reach the CAA
# re-check at finalize at all. A stub that failed every query would fail the challenge
# first and the order would never get that far.
[ -n "${CAA_RCODE:-}" ] && recs+=("RCODE:$CERTBOT_DOMAIN=$CAA_RCODE")
# Same shape and the same reason as RCODE above: forged at $CERTBOT_DOMAIN only, so the
# challenge TXT at _acme-challenge.$CERTBOT_DOMAIN still validates and the order actually
# reaches the finalize-time CAA re-check.
[ -n "${CAA_FORGE:-}" ] && recs+=("FORGE:$CERTBOT_DOMAIN=$CAA_FORGE")
rm -f "$W/dns.log"
"$ROOT/build/dnsstub" "$DNSP" "${recs[@]}" > "$W/dns.log" 2>&1 &
for i in $(seq 1 40); do grep -q READY "$W/dns.log" 2>/dev/null && break; sleep 0.1; done
HOOK
# ⚠️ The cleanup hook must NOT stop the DNS server, and this is the whole reason CAA needs
# care with a real client. certbot runs cleanup as soon as the CHALLENGE validates, which
# is BEFORE finalize — and CAA is re-checked at finalize (RFC 8555 §8.1.1). Tearing the
# stub down here left no CAA record at the moment the server looked, and RFC 8659 says
# absence is not denial, so the DENIED domain was issued a certificate. Measured: that is
# exactly what happened on the first run, and the DB assertion caught it.
# The next auth hook replaces the stub; the EXIT trap kills the last one.
cat > cleanhook.sh <<'HOOK'
#!/usr/bin/env bash
set -u
# The one case that needs the stub GONE. certbot runs cleanup after the challenge
# validates and BEFORE finalize, so killing the resolver here is exactly "the resolver went
# away between validation and the CAA re-check" — the timeout/no-route half of the ticket,
# which no amount of RCODE fiddling can produce.
[ -n "${KILL_DNS:-}" ] && pkill -f "dnsstub $DNSP" 2>/dev/null
exit 0
HOOK
chmod +x authhook.sh cleanhook.sh
export ROOT W DNSP

# ⚠️ `case` cannot go inline in $( ): the ")" closing a pattern also closes the command
# substitution, so the assertion ends up comparing against shell fragments. The suite
# always had this helper for that reason; I removed it in the certbot rewrite and
# immediately hit it again.
begins() { case "$1" in "$2"*) echo yes;; *) echo no;; esac; }

# <domain> [caa-issuer] -> "ok:" when certbot wrote a certificate, else "fail:<acme error code>"
run_caa_order() {
    local domain="$1"
    export CAA_ISSUER="${2:-}"
    export CAA_RCODE="${3:-}"
    export KILL_DNS="${4:-}"
    export CAA_FORGE="${5:-}"
    rm -rf "$W/cb/live/$domain"
    local out
    out=$(certbot certonly --manual --preferred-challenges dns "${CB[@]}" \
            --manual-auth-hook "$W/authhook.sh" --manual-cleanup-hook "$W/cleanhook.sh" \
            --register-unsafely-without-email --agree-tos \
            --cert-name "$domain" -d "$domain" 2>&1)
    printf '%s\n' "$out" > "certbot_$domain.log"
    # ⚠️ THE PROBLEM TYPE COMES FROM CERTBOT'S HTTP TRACE, NOT FROM ITS CONSOLE TEXT, and
    # that is the whole weight behind the "typed caa" assertions below. This used to be
    # `grep -o caa` over the console output: every domain the suite orders is under
    # caa.example.org and certbot echoes the domain on every run, so ANY refusal whatsoever
    # — unauthorized, a rate limit, a 500 at finalize — came back as "fail:caa" and the
    # assertion could not go red. certbot prints a problem document as its `detail` alone
    # (certbot/_internal/display/util.py, describe_acme_error), so the RFC 8555 error type is
    # not on the terminal at all. It IS in the response body, which certbot logs at DEBUG in
    # letsencrypt.log, and that file is rotated on every invocation, so it carries this
    # order's exchange and no other. The last type in it is the one that refused issuance.
    if [ -f "$W/cb/live/$domain/cert.pem" ]; then echo "ok:"
    else echo "fail:$(grep -o 'urn:ietf:params:acme:error:[A-Za-z]*' \
                          "$W/cbl/letsencrypt.log" 2>/dev/null | tail -1 | sed 's/.*://')"; fi
}

echo "=== ACME CAA re-check via real certbot (allow / deny / none) ==="
# 1) CAA authorizes our identity -> issuance allowed
R1=$(run_caa_order "allow.$BASE" "$IDENTITY")
chk "CAA naming us -> certbot issued"             "ok:" "$R1"
# 2) CAA names a DIFFERENT CA -> refused, and specifically as a CAA problem. The old test
#    read a literal 403; certbot never exposes the status, so the refusal is asserted as
#    "no certificate" plus the RFC 8555 error type in the problem document certbot got.
R2=$(run_caa_order "deny.$BASE" "otherca.example")
chk "CAA naming another CA -> certbot got no cert" yes "$(begins "$R2" fail:)"
chk "  and the problem it got is typed caa"        caa "${R2#fail:}"
# 3) no CAA at all -> issuance allowed (absence is not denial, RFC 8659)
R3=$(run_caa_order "none.$BASE" "")
chk "no CAA record -> certbot issued"             "ok:" "$R3"

echo "=== A CAA lookup that FAILS refuses, it does not fall back to permissive ==="
# Confirmed as wanted, and it needed fixing.
#
# query_caa() returned one empty vector for all three outcomes — records, genuinely no
# records, and "the lookup did not work" — and caa_allows() reads empty as "climb to the
# parent", so running out of parents meant unrestricted. A SERVFAIL, a REFUSED, a dead
# resolver or a 3s timeout therefore switched the CAA policy OFF and issuance proceeded,
# silently. RFC 8659 §3 and CA/B Forum BR 3.2.2.8 both say a failed lookup must refuse.
#
# ⚠️ THE RCODE WAS NEVER READ AT ALL: the parser went straight to ANCOUNT, which is 0 in an
# error response, so a resolver explicitly saying "I failed" was read as a clean empty
# answer. That is why these three domains carry no CAA record — under the old code every
# one of them would have been ISSUED, which is the same result as a healthy pass.
R4=$(run_caa_order "servfail.$BASE" "" 2)
chk "SERVFAIL -> refused"                          yes "$(begins "$R4" fail:)"
chk "  and the problem is typed caa"               caa "${R4#fail:}"
R5=$(run_caa_order "refused.$BASE" "" 5)
chk "REFUSED -> refused"                           yes "$(begins "$R5" fail:)"
R6=$(run_caa_order "deadres.$BASE" "" "" kill)
chk "resolver gone at finalize -> refused"         yes "$(begins "$R6" fail:)"
# ⚠️ NXDOMAIN IS THE ONE NON-ZERO RCODE THAT IS A REAL ANSWER — the name does not exist, so
# it has no CAA RRset and the climb continues. Refusing on it would break every ordinary
# domain, so this is the anti-vacuity control for the three above: without it, "refuse on
# any rcode" would pass them all and quietly break issuance everywhere.
R7=$(run_caa_order "nxd.$BASE" "" 3)
chk "NXDOMAIN stays permissive -> issued"          "ok:" "$R7"

echo "=== a reply that does not answer OUR question is not an answer ==="
# ⚠️ THE QUERY ID WAS DRAWN AND THEN NEVER COMPARED. Both DNS queries in
# src/acme/main.cpp built a header with a RAND_bytes transaction id and then parsed
# whatever datagram came back, without ever checking that id, the QR bit, or the question
# echoed in the reply. recv() on a connected UDP socket already refuses datagrams from any
# source but the resolver, so a forger has to spoof the resolver's address either way —
# but with the id unchecked, the FIRST spoofed datagram to arrive is believed, instead of
# having to match a 16-bit value it cannot see.
#
# The stub could not show this because it echoed both fields verbatim, so an honest
# resolver and a spoofer were byte-identical from the product's side. FORGE:<name>=id and
# FORGE:<name>=qname make it lie in each of the two ways that matter.
#
# CAA is the sharper of the two directions to assert: a forged reply carrying no records
# reads as "this name publishes no CAA", which is PERMISSIVE — so believing a forgery does
# not merely mishandle an error, it switches the issuer restriction off. It must come back
# as a failed lookup and refuse, exactly like SERVFAIL above.
R8=$(run_caa_order "forgeid.$BASE" "" "" "" id)
chk "a forged transaction id -> refused"           yes "$(begins "$R8" fail:)"
chk "  and the problem is typed caa"               caa "${R8#fail:}"
R9=$(run_caa_order "forgeqn.$BASE" "" "" "" qname)
chk "an answer about a different name -> refused"  yes "$(begins "$R9" fail:)"
# The ticket's other half: nothing said the check had not run.
chk "the server log names the failed lookup"       yes \
    "$(grep -q 'CAA lookup for servfail' srv.log && echo yes || echo no)"
chk "  and says it refused rather than treating it as no policy" yes \
    "$(grep -q 'refusing rather than treating it as no policy' srv.log && echo yes || echo no)"

# The strongest assertions, and unchanged by the client swap: what the SERVER stored.
chk "no cert issued for the CAA-denied domain"  0 "$(pg_exec "select count(*) from certs where cn='deny.$BASE';")"
chk "cert issued for the CAA-authorized domain" 1 "$(pg_exec "select count(*) from certs where cn='allow.$BASE';")"
chk "cert issued for the no-CAA domain"         1 "$(pg_exec "select count(*) from certs where cn='none.$BASE';")"
# From the SERVER's side: three broken-lookup domains, zero certificates between them.
chk "no cert for the SERVFAIL domain"           0 "$(pg_exec "select count(*) from certs where cn='servfail.$BASE';")"
chk "no cert for the REFUSED domain"            0 "$(pg_exec "select count(*) from certs where cn='refused.$BASE';")"
chk "no cert for the dead-resolver domain"      0 "$(pg_exec "select count(*) from certs where cn='deadres.$BASE';")"
chk "cert issued for the NXDOMAIN domain"       1 "$(pg_exec "select count(*) from certs where cn='nxd.$BASE';")"
chk "no cert for the forged-id domain"          0 "$(pg_exec "select count(*) from certs where cn='forgeid.$BASE';")"
chk "no cert for the forged-question domain"    0 "$(pg_exec "select count(*) from certs where cn='forgeqn.$BASE';")"
# ...and the issued artifact is decoded, not trusted (§3d).
chk "the issued leaf really carries the SAN" yes \
    "$("$OSSL" x509 -in "$W/cb/live/allow.$BASE/cert.pem" -noout -text 2>/dev/null \
       | grep -q "DNS:allow.$BASE" && echo yes || echo no)"

[ "$fail" -eq 0 ] || { echo "--- certbot said (allow):"; tail -25 "certbot_allow.$BASE.log" 2>/dev/null; }

echo
echo "=== ACME CAA: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
