#!/usr/bin/env bash
# MS certificate template import. An admin imports templates exported
# from Active Directory (as CSV) with `fastpki-config templates-import`; they land
# in the ms_templates table and fastpki-ms serves them to Windows clients via
# MS-XCEP GetPolicies, replacing the three built-in defaults. With no templates
# configured, the built-in defaults are served (back-compat).
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
# XCEP authenticates now, so this suite needs an identity to present.
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
CFG="$ROOT/build/fastpki-config"; MS="$ROOT/build/fastpki-ms"
W="$(mktemp -d)"; cd "$W"; PORT=18450; PORT2=18451
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

ca_in_token ca.pem "/CN=MS Tpl CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout ms.key -out ms.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
printf "internal\n" > domains.txt
pg_setup ms_templates; PG_CONNINFO1="$PG_CONNINFO"; PGDATABASE1="$PGDATABASE"
seed_domains $W/domains.txt   # allowed_domains is the sole source
seed_web_user tester s3cret-ms requester   # XCEP authenticates now
pg_setup ms_templates2
seed_domains $W/domains.txt   # the second instance has its own database
seed_web_user tester s3cret-ms requester   # ...and this instance has its own database
P=; P2=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
mkconf(){ cat > "$1" <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
ROOT_CA_PEM=$W/root.pem
MS_CERT=$W/ms.pem
MS_KEY=$W/ms.key
PG_CONNINFO=$2
AUTH_BACKEND=local
MS_BIND=127.0.0.1
MS_PORT=$3
XCEP_PATH=/msxcep
WSTEP_PATH=/mswstep
LOG_LEVEL=err
EOF
}
mkconf bootstrap.conf "$PG_CONNINFO1" "$PORT"
mkconf empty.conf "$PG_CONNINFO" "$PORT2"
seed_ca_from_conf bootstrap.conf; seed_ca_from_conf empty.conf   # register the CA in each DB

# A CSV "exported from AD": header + two custom templates (other columns default).
cat > templates.csv <<EOF
name,oid,validity_days,key_usage,ekus
WebServerTpl,1.3.6.1.4.1.311.21.8.99.1,365,0xA000,TLS Web Server Authentication
ClientAuthTpl,1.3.6.1.4.1.311.21.8.99.2,365,0x8000,TLS Web Client Authentication
EOF

echo "=== CSV import via fastpki-config ==="
OUT=$("$CFG" --config bootstrap.conf templates-import templates.csv 2>&1)
chk "import reports 2 templates" yes "$(has "$OUT" 'imported 2 MS template')"
LIST=$("$CFG" --config bootstrap.conf templates-list 2>&1)
chk "templates-list shows WebServerTpl"  yes "$(has "$LIST" 'WebServerTpl')"
chk "templates-list shows ClientAuthTpl" yes "$(has "$LIST" 'ClientAuthTpl')"
# A bad CSV (missing required oid) must be rejected without importing.
printf 'name,oid\nNoOid,\n' > bad.csv
chk "a row missing oid is rejected (non-zero)" no \
    "$("$CFG" --config bootstrap.conf templates-import bad.csv >/dev/null 2>&1 && echo yes || echo no)"

# ⚠️ A REAL DIRECTORY'S FLAG VALUES HAVE THE TOP BIT SET, and that broke the client
# outright. msPKI-Certificate-Name-Flag is a 32-bit BITMASK; a directory hands back
# 0xA6000000 as the signed decimal -1509949440, and xcep types these unsignedInt — so
# emitting the negative made Windows refuse the WHOLE policy response with
# WS_E_NUMERIC_OVERFLOW (0x803d0002) and the policy server could not be added at all.
#
# It hid because the built-in templates use small positive values (0x9, 0x10) — it appears
# only once real directory templates are imported. Measured on one directory: 12 of its 33
# templates carry a negative value in this attribute.
#
# Set BEFORE the server starts: the catalogue is read once at startup.
"$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE1" -qc \
  "UPDATE ms_templates SET subject_name_flags = -1509949440 WHERE name = 'WebServerTpl'" >/dev/null 2>&1
chk "fixture: a top-bit-set flag is stored" -1509949440 \
    "$("$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE1" -tAc \
        "select subject_name_flags from ms_templates where name='WebServerTpl'" 2>/dev/null | tr -d ' ')"

echo "=== fastpki-ms GetPolicies serves the imported templates ==="
"$MS" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P $P2 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-ms died:"; cat srv.log; exit 1; fi
REQ='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"><client/></GetPolicies></s:Body></s:Envelope>'
XR=$(curl -sk -u tester:s3cret-ms -H "Content-Type: application/soap+xml" --data "$REQ" "https://127.0.0.1:$PORT/msxcep/ca-global")
chk "GetPoliciesResponse returned"          yes "$(has "$XR" 'GetPoliciesResponse')"
# ⚠️ THE CATALOGUE IS FILTERED TO WHAT THE CALLER MAY ENROL UNDER, which is what a real AD
# returns — a domain client is offered the templates it holds Enroll on and nothing else.
# `tester` is a `requester`, and the shipped grants give that role template:use on the three
# BUILT-INS only. These two were freshly imported and nobody has granted them, so they must
# NOT appear. Before the filter every authenticated caller saw the whole catalogue and then
# had WSTEP refuse it — an autoenrolling client would chase a template it could never get.
chk "an ungranted imported template is NOT offered (WebServerTpl)"  no "$(has "$XR" 'WebServerTpl')"
chk "an ungranted imported template is NOT offered (ClientAuthTpl)" no "$(has "$XR" 'ClientAuthTpl')"
chk "and a built-in the caller cannot enrol is gone too" no "$(has "$XR" 'GenericUser')"

# ⚠️ PGDATABASE1, NOT PGDATABASE. This suite calls pg_setup TWICE and the second call
# overwrites PGDATABASE, so the obvious spelling writes the grant into the OTHER database
# while the server under test reads the first one. The grant row then exists, the fixture
# check passes, and the template still does not appear — which reads exactly like a broken
# product. Measured: that is precisely what happened here.
#
# THE POSITIVE CONTROL, and without it the three assertions above are worthless: an empty
# response satisfies every one of them, so a server that had simply stopped emitting
# templates — or a broken request — would read as the feature working. Grant the template
# and it must appear.
"$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE1" -qc \
  "INSERT INTO role_permissions(role,permission,scope) VALUES ('requester','template:use','WebServerTpl') ON CONFLICT DO NOTHING" >/dev/null 2>&1
# ⚠️ Assert the GRANT landed before asserting what it changes. A silent INSERT failure
# would leave the next check red and send the reader looking at the server.
chk "  fixture: the grant row exists" 1 \
    "$("$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE1" -tAc \
        "select count(*) from role_permissions where role='requester' and permission='template:use' and scope='WebServerTpl'" 2>/dev/null | tr -d ' ')"
XG=$(curl -sk -u tester:s3cret-ms -H "Content-Type: application/soap+xml" --data "$REQ" "https://127.0.0.1:$PORT/msxcep/ca-global")
chk "  once granted, WebServerTpl IS offered"        yes "$(has "$XG" 'WebServerTpl')"
# ⚠️ THE FLAG MUST REACH THE WIRE UNSIGNED. 0xA6000000 stored as -1509949440 must serialise
# as 2785017856; the negative form is what Windows rejects with WS_E_NUMERIC_OVERFLOW.
chk "  its subjectNameFlags is unsigned on the wire" yes \
    "$(printf '%s' "$XG" | grep -qF '<subjectNameFlags>2785017856</subjectNameFlags>' && echo yes || echo no)"
# Anti-vacuity paired with it: the negative rendering must be absent. Asserting only the
# positive would pass against a response that somehow carried both.
chk "  and no negative flag appears anywhere"        yes \
    "$(printf '%s' "$XG" | grep -qE '<(subjectName|enrollment|general|privateKey)Flags>-' && echo no || echo yes)"
chk "  and the still-ungranted one stays hidden"     no  "$(has "$XG" 'ClientAuthTpl')"
kill $P 2>/dev/null; wait $P 2>/dev/null

echo "=== empty table falls back to the built-in defaults ==="
"$MS" --config empty.conf >srv2.log 2>&1 & P2=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "empty.conf" MS_PORT "$P2" || true
XR2=$(curl -sk -u tester:s3cret-ms -H "Content-Type: application/soap+xml" --data "$REQ" "https://127.0.0.1:$PORT2/msxcep/ca-global")
chk "default GenericUser served when table is empty" yes "$(has "$XR2" 'GenericUser')"
kill $P2 2>/dev/null; wait $P2 2>/dev/null

echo "=== delete a template ==="
"$CFG" --config bootstrap.conf templates-delete WebServerTpl >/dev/null 2>&1
chk "deleted template is gone from the list" no "$(has "$("$CFG" --config bootstrap.conf templates-list 2>&1)" 'WebServerTpl')"

# ── the console's flag decoder, run against the REAL dictionaries ────────────────────
# ⚠️ THE DECODER IS WHERE FOUR SEPARATE DEFECTS LIVED AT ONCE, and none of them was
# reachable by any other suite: the flag semantics are MS-CRTD's, so they belong to this
# suite, but the code that renders them is JavaScript embedded in src/web/main.cpp and
# nothing executed it.
#
#   * kMsNil (-1) means "the directory did not say" and is the honest value for a template
#     IMPORTED from AD. `(-1) >>> 0` is 0xFFFFFFFF, so the decoder matched every bit and
#     reported a template as carrying all eighteen enrollment flags.
#   * JS bitwise operators return a SIGNED int32, so `(val & 0x80000000) === 0x80000000` is
#     false however the flag is set. CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH is that bit and
#     could never be named.
#   * CT_FLAG_REQUIRE_V2_ATTESTATION (0x8000) was absent from the private-key dictionary, so
#     a real flag rendered as an unknown bit.
#   * three general flags MS-CRTD marks "Reserved. All protocols MUST ignore this flag"
#     were labelled as though they worked, two of them sharing a name with a flag that does.
#
# Inspection would have caught none of them; EXECUTION caught all four. So this extracts the
# five dictionaries and the function from the source and runs them, rather than grepping for
# a shape. node is in the test image on purpose (deploy/Dockerfile.test installs nodejs).
echo "=== the console decodes MS-CRTD template flags correctly ==="
if command -v node >/dev/null 2>&1; then
    awk '/^const (KU|SNF|EF|PKF|GF)_BITS = \[/,/\];[[:space:]]*$/' "$ROOT/src/web/main.cpp" > tpl.js
    awk '/^function tplExpand\(val, dict\) \{/,/^\}$/'             "$ROOT/src/web/main.cpp" >> tpl.js
    cat >> tpl.js <<'JS'
const t = (n,a,b) => console.log((a === b ? 'OK|' : 'NO|') + n + '|' + a + '|' + b);
t('kMsNil is not a bitmask',        tplExpand(-1, EF_BITS), 'not specified');
t('null is not a bitmask',          tplExpand(null, GF_BITS), 'not specified');
t('zero is none, not absent',       tplExpand(0, EF_BITS), 'none (0x0)');
t('the top bit names itself',       tplExpand(0x80000000, SNF_BITS), 'Subject require directory path (0x80000000)');
t('V2 attestation is a known flag', tplExpand(0x8000, PKF_BITS), 'Require V2 attestation (0x8000)');
t('an unknown bit is reserved',     tplExpand(0x40000000, EF_BITS), 'reserved (0x40000000)');
t('reserved general flags say so',  tplExpand(0x2, GF_BITS), 'Add email (reserved — ignored) (0x2)');
JS
    node tpl.js > tpl.out 2>tpl.err || { echo "  [FAIL] the decoder did not run: $(head -2 tpl.err)"; fail=$((fail+1)); }
    # Every dictionary must have survived extraction, or the checks below pass over nothing.
    chk "all five flag dictionaries extracted" 5 "$(grep -c '^const .*_BITS = \[' tpl.js)"
    while IFS='|' read -r st name got want; do
        [ -n "$st" ] || continue
        chk "$name" "$want" "$got"
    done < tpl.out
else
    echo "  [SKIP] node is not on this host (it is in the test image, where the verdict is taken)"
fi

echo
echo "=== MS TEMPLATES: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
