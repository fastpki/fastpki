#!/usr/bin/env bash
# (CRITICAL): a certificate CN is attacker-chosen, and the console rendered it into
# innerHTML unescaped. Anyone who could enrol could plant script that ran in the session of
# whichever admin or auditor opened Inventory — same-origin injected script, so HttpOnly
# and SameSite do nothing about it.
#
# ⚠️ THE SERVER IS NOT THE PLACE THE BUG LIVED, and that shapes this whole suite.
# `json_escape()` is CORRECT: JSON must carry the CN verbatim, because the CN is what the
# certificate actually says and mangling it server-side would corrupt the inventory to work
# around a rendering fault. So there is no server response to assert "is escaped" — the API
# is supposed to return the payload intact. What must hold is:
#
#   1. the API still returns the value VERBATIM (we did not "fix" this by damaging data);
#   2. the shipped renderer escapes it (census over the served page, comments stripped);
#   3. the one place a value is stored rather than issued -- selector_value -- refuses
#      characters that can be markup at all.
#
# ⚠️ NO node/DOM DEPENDENCY. The shipped image has no node, and a suite whose real
# assertions live behind `command -v node` would SKIP there — which reads exactly like a
# pass. Every assertion below runs with curl, psql and awk.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF

W="$(mktemp -d)"; cd "$W"; PORT=18470
pass=0; fail=0; P=
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# ⚠️ SHELL-ONLY — every suite here is bash plus curl/openssl/psql, with no interpreter
# driver. "Still valid JSON" is asserted for exactly one failure mode, which is the only
# one these responses can produce: a backslash that does not open a legal escape. JSON
# permits \" \\ \/ \b \f \n \r \t and \uXXXX, and `grep -o` consumes a correct `\\` as a
# single match, so what remains can only be a separator the serialiser forgot to escape.
json_escapes_ok(){
  bad=$(grep -o '\\.' "$1" 2>/dev/null | grep -vc '\\["\\/bfnrtu]' || true)
  if [ "${bad:-0}" = "0" ]; then echo yes; else echo no; fi
}

SRC="$ROOT/src/web/main.cpp"

# ── 1. the console SOURCE, with comments stripped ────────────────────────────
# ⚠️ STRIP `//` COMMENTS BEFORE GREPPING. The served console page embeds this file's
# prose, and a previous guard in this tree passed forever because it matched its OWN
# comment (the comment named the thing it was checking for). Everything below reads
# code only.
code() { sed 's#//.*##' "$SRC"; }

echo "=== the table renderer escapes by DEFAULT, not per column ==="
# The default branch is what rendered cn / role / caInstance / notAfter.
chk "cell()'s default branch escapes" yes \
    "$(code | grep -qE "return \(v===null\|\|v===undefined\)\?''\:esc\(String\(v\)\)" && echo yes || echo no)"
# ⚠️ ANTI-VACUITY: prove the OLD form is gone, not merely that a new one appeared. A
# grep for the fix passes just as well if both forms are present.
chk "  the unescaped default is GONE" yes \
    "$(code | grep -qE "return \(v===null\|\|v===undefined\)\?''\:String\(v\)" && echo no || echo yes)"
chk "serial/target go through esc()" yes \
    "$(code | grep -q "k === 'serial' || k === 'target') return '<code>'+esc(v)" && echo yes || echo no)"
chk "flags tokens go through esc()" yes \
    "$(code | grep -q "'<span class=\"pill flag\">'+esc(f)+'</span>'" && echo yes || echo no)"

echo "=== a value used as a CSS CLASS is whitelisted, not merely escaped ==="
# A class attribute is a TOKEN LIST: a value with a space becomes extra classes even when
# escaped, so esc() is the wrong tool and cls() exists for it.
chk "cls() is defined" yes \
    "$(code | grep -q 'function cls(s){' && echo yes || echo no)"
chk "  and drops everything outside [A-Za-z0-9_-]" yes \
    "$(code | grep -q "replace(/\[^A-Za-z0-9_-\]/g, '')" && echo yes || echo no)"
chk "statusText no longer interpolates v raw" yes \
    "$(code | grep -qE "class=\"pill '\+v\+'\"" && echo no || echo yes)"

echo "=== the certificate DETAIL modal escapes every field it did not build ==="
# This was the worse half and the ticket does not list it: the Inventory column leaks one
# field, the modal rendered subject, issuer, SANs, CN and role into innerHTML raw.
chk "the modal escapes unless a branch flagged markup" yes \
    "$(code | grep -q "(markup ? v : esc(String(v)))" && echo yes || echo no)"
chk "  the raw '<dd>'+v+'</dd>' form is GONE" yes \
    "$(code | grep -qE "'</dt><dd>'\+v\+'</dd>'|'<dd>'\+v\+'</dd>'" && echo no || echo yes)"

# ── 2. behaviour: the API must still carry the payload VERBATIM ──────────────
ca_in_token ca.pem "/CN=XSS Guard CA" 3650 xssguard \
    || { echo "SKIP: could not mint a CA key in a token"; exit 0; }

echo "=== ⚠️ no backtick may appear in an HTML comment inside the console source ==="
# THE BUG THIS EXISTS FOR. The console is one <script> that builds its HTML from JS TEMPLATE
# LITERALS, so a backtick inside an HTML comment that sits within a template CLOSES the
# template, and whatever follows is parsed as JavaScript. rc6 shipped
#
#     data center, and `fastpki-ca pg-tls` refuses to write until it has been. -->
#
# inside caCreateForm()'s template. `fastpki-ca pg-tls` is not valid JS, so the ENTIRE console
# script failed to parse: a blank page, every control dead, and NOTHING in the server log
# because the backend served the page correctly.
#
# ⚠️ IT PASSED EVERYTHING. 251/251 in the container and a green CI including the ASan/UBSan
# lane, because no suite EXECUTES the console JS — web.sh and this file fetch the page and
# grep it. It was found by an operator deploying the release candidate.
#
# ⚠️ AND BALANCE IS NOT THE TEST. The two backticks balanced, so a brace/paren/quote scan
# matched the previous release exactly. What matters is whether the text BETWEEN them is
# valid JavaScript — `wide2` happened to be (an identifier), `fastpki-ca pg-tls` was not.
# Both are latent; the rule is simply that backticks do not belong in these comments.
BTICK=$(awk 'BEGIN{BT=sprintf("%c",96)} /<!--/,/-->/ { if (index($0,BT)) c++ } END{print c+0}' "$SRC")
chk "no HTML comment in the console carries a backtick" 0 "$BTICK"
pg_setup console_xss
trap 'pg_cleanup; kill ${P:-} 2>/dev/null' EXIT

PAYLOAD='<img src=x onerror="fetch(1)">'
pg_exec "INSERT INTO certs(serial,status,cn,ca_instance_id,\"notAfter\") \
         VALUES('beef',0,'$PAYLOAD','xssguard', extract(epoch from now())::bigint + 86400);" >/dev/null
chk "PRECONDITION: a certificate with a script CN is in the DB" 1 \
    "$(pg_exec "select count(*) from certs where serial='beef';" | tr -d ' ')"

cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=xssguard
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_TLS=false
WEB_ALLOW_REVOKE=true
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf
seed_web_user xssadmin xssPW123456 admin >/dev/null 2>&1
"$ROOT/build/fastpki-web" --config bootstrap.conf >web.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
chk "the console starts" yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"

# ⚠️ THE CONSOLE IS SESSION-COOKIE AUTH, NOT BASIC. A `-u user:pass` call gets a clean
# 401, and every assertion after it then measures "the console refused me" while claiming
# to measure escaping — the 401 is indistinguishable from a real refusal in the result
# line. Log in once and carry the jar, like the other console suites.
curl -s -c adm.cj -d "username=xssadmin&password=xssPW123456" \
     "http://127.0.0.1:$PORT/api/login" >/dev/null
chk "PRECONDITION: the admin session is established" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b adm.cj "http://127.0.0.1:$PORT/api/me")"
curl -s -b adm.cj "http://127.0.0.1:$PORT/api/certs?limit=50" -o certs.json
# ⚠️ The API MUST return it intact. Escaping here would be the wrong fix — the inventory
# would then show a CN that is not the CN in the certificate.
chk "the JSON carries the CN verbatim (server must NOT mangle it)" yes \
    "$(grep -q 'onerror' certs.json && echo yes || echo no)"
chk "  and the response is still valid JSON" yes \
    "$(json_escapes_ok certs.json)"

# ── 3. behaviour: selector_value refuses what can be markup ──────────────────
echo "=== POST /api/subject-roles refuses a selector_value that can be markup ==="
CODE=$(curl -s -o sr.out -w '%{http_code}' -b adm.cj -X POST \
       --data-urlencode "selector_type=group" \
       --data-urlencode "selector_value=$PAYLOAD" \
       --data-urlencode "role=requester" \
       "http://127.0.0.1:$PORT/api/subject-roles")
chk "a script selector_value is refused (400)" 400 "$CODE"
chk "  and NOTHING was stored for it" 0 \
    "$(pg_exec "select count(*) from subject_roles where selector_value like '%onerror%';" | tr -d ' ')"
# ⚠️ ANTI-VACUITY. A validator that refuses everything satisfies the assertion above and
# breaks every real directory group. AD group names carry spaces, commas and parentheses.
CODE2=$(curl -s -o sr2.out -w '%{http_code}' -b adm.cj -X POST \
        --data-urlencode "selector_type=group" \
        --data-urlencode "selector_value=CN=FastPKI Users (EU),OU=Groups" \
        --data-urlencode "role=requester" \
        "http://127.0.0.1:$PORT/api/subject-roles")
# 201 Created — the grant is a new row. Asserted as the exact code rather than "not 4xx",
# so a future change to the response is noticed rather than absorbed.
chk "a REAL directory group name is still accepted" 201 "$CODE2"
chk "  and it was stored" 1 \
    "$(pg_exec "select count(*) from subject_roles where selector_value='CN=FastPKI Users (EU),OU=Groups';" | tr -d ' ')"

# ⚠️ BACKSLASH IS DELIBERATELY ALLOWED, and this is the assertion that says so on purpose
# rather than by omission. A directory identity is authorized under `<provider>\<user>`,
# so refusing the separator refuses a role grant to EVERY directory user — the console can
# list a directory subject and then 400 on any attempt to give it a role. It was refused
# here once, alongside the characters that can actually end an attribute or open a tag, and
# a backslash can do neither.
#
# What makes it safe is not that claim but the two assertions below: the value must come
# back BYTE-IDENTICAL, and the response must still parse as JSON — which it only does if
# the serialiser escaped the backslash. A blanket refusal would satisfy the markup
# assertion above while breaking the product, so this is the anti-vacuity pair for it.
QUAL='default\alice'
CODE3=$(curl -s -o sr3.out -w '%{http_code}' -b adm.cj -X POST \
        --data-urlencode "selector_type=user" \
        --data-urlencode "selector_value=$QUAL" \
        --data-urlencode "role=requester" \
        "http://127.0.0.1:$PORT/api/subject-roles")
chk "a provider-qualified subject is accepted" 201 "$CODE3"
chk "  and stored with the separator intact" 1 \
    "$(pg_exec "select count(*) from subject_roles where selector_value='$QUAL';" | tr -d ' ')"
curl -s -b adm.cj "http://127.0.0.1:$PORT/api/subject-roles" -o sr_list.json
chk "  and the listing is still valid JSON" yes \
    "$(json_escapes_ok sr_list.json)"
# ⚠️ MATCH THE WIRE BYTES, NOT THE STORED VALUE. JSON escapes a backslash as two, so the
# response carries `default\\alice` where the database holds `default\alice` — grepping for
# the stored spelling reports a broken round-trip on a correct one. Spelled out as a fixed
# string so the difference is visible instead of hidden inside an escape.
WIRE='"selector_value":"default\\alice"'
chk "  and it round-trips through the API unchanged" yes \
    "$(grep -qF "$WIRE" sr_list.json && echo yes || echo no)"

echo "=== the served script parses, and a form cannot wait for ever ==="
# ⚠️ NOTHING PARSES THE CONSOLE'S JAVASCRIPT. It is a 10k-line string literal inside a C++
# file: the compiler checks the quoting and no test checks the code, so a typo ships and is
# found by whoever opens the page. node is here for the WebCrypto unit tests; asking it to
# parse the served bytes costs one call and closes that gap.
curl -s -b adm.cj "http://127.0.0.1:$PORT/" -o page.html
if command -v node >/dev/null 2>&1; then
    awk '/^<script>$/{f=1;next} /^<\/script>$/{f=0} f' page.html > page.js
    chk "the page's script was extracted" yes \
        "$([ -s page.js ] && echo yes || echo no)"
    node --check page.js > nodecheck.txt 2>&1
    chk "  and it parses"                 0 "$?"
    [ -s nodecheck.txt ] && head -3 nodecheck.txt
else
    echo "  [FAIL] node is not installed in this image — the script cannot be parsed"
    fail=$((fail+1))
fi
# A request that cannot be delivered must end in an error, not a spinner. The console can cut
# its own connection by issuing its own TLS certificate: the browser refuses the new one and
# every later fetch() from that page hangs. Both key-generating forms go through the wrapper
# that gives up and answers response-shaped, so their ordinary error path reports it.
chk "the timeout wrapper is served"                yes \
    "$(grep -qF 'async function apiFetch(url, opts, ms)' page.html && echo yes || echo no)"
chk "  the HSM request form uses it"               yes \
    "$(grep -qF "apiFetch('/api/certs/request-hsm'" page.html && echo yes || echo no)"
chk "  the CA CSR form uses it"                    yes \
    "$(grep -qF "apiFetch('/api/ca-instances/csr'" page.html && echo yes || echo no)"
chk "  and issuing the console's own certificate warns first" yes \
    "$(grep -qF "This certificate is the console\\'s own TLS certificate." page.html && echo yes || echo no)"

kill $P 2>/dev/null; wait $P 2>/dev/null; P=
echo
echo "=== CONSOLE XSS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
