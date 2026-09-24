#!/usr/bin/env bash
# Editable / persisted client-config files: an
# admin can pre-edit and store the per-protocol client config (CMP openssl.cnf, ACME
# certbot, SCEP sscep, MS certreq .inf) so users download the CURATED version instead
# of the generated default. The stored body may carry {{TOKENS}} that the download
# substitutes from live settings, so a curated file stays correct as settings change.
#
# Endpoints (admin-only, writes gated by WEB_ALLOW_REVOKE):
#   GET  /api/client-config/<kind>        download (stored+substituted, else generated)
#   GET  /api/client-config/<kind>/edit   editor payload (stored body or tokenized default + token legend)
#   PUT  /api/client-config/<kind>        store an override
#   DELETE /api/client-config/<kind>      revert to generated
#
# Self-contained (§3d): ephemeral Postgres via pg_helpers, own port, temp dir; SKIPs
# cleanly when no Postgres. Shell-only — JSON checked with grep, no interpreter.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18265
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
has(){ grep -qF -- "$2" <<<"$1" && echo yes || echo no; }

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi

pg_setup client_config_store
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
PKI_DNS=ca.example.com
BASE_URL=https://ca.example.com
LOG_LEVEL=err
EOF
"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c admin.cj -X POST "$U/api/users" -d 'username=admin&password=adminpw12&role=admin' >/dev/null
curl -s -c admin.cj -X POST "$U/api/login" -d 'username=admin&password=adminpw12' >/dev/null

echo "=== generated default + tokenized editor template ==="
DEF="$(curl -s -b admin.cj "$U/api/client-config/cmp")"
chk "default download carries the live URL" yes "$(has "$DEF" 'server = https://ca.example.com/cmp')"
ED="$(curl -s -b admin.cj "$U/api/client-config/cmp/edit")"
chk "editor reports no override yet"    yes "$(has "$ED" '"stored":false')"
chk "editor body is tokenized"          yes "$(has "$ED" 'server = {{CMP_URL}}')"
chk "editor returns the token legend"   yes "$(has "$ED" '{{CMP_URL}}')"
chk "editor names the download file"    yes "$(has "$ED" 'fastpki-cmp.cnf')"

echo "=== The default CMP config is the supplied file ==="
# It is a full working config with a section per command, so
# `openssl cmp -config fastpki-cmp.cnf -section cmp,kur` runs without hand-editing.
for sect in "[cmp]" "[ir]" "[p10cr]" "[cr]" "[kur]" "[rr]" "[genm]"; do
  chk "the default carries the $sect section" yes "$(has "$DEF" "$sect")"
done
chk "kur renews the cert cmp issued"  yes "$(has "$DEF" 'oldcert = $cmp::certout')"
chk "ir carries the per-user senderKID" yes "$(has "$ED" 'ref = {{CMP_KID}}')"
chk "the editor template exposes {{CMP_RA_CN}}" yes "$(has "$ED" 'recipient = {{CMP_RA_CN}}')"
# ⚠️ THIS DEPLOYMENT HAS NO CA, so there is no RA certificate to name. The token must
# still be SUBSTITUTED (to empty) rather than shipped literally — handing an operator a
# file containing `recipient = {{CMP_RA_CN}}` is the hand-editing this exists to remove,
# and openssl cmp would take the braces as the recipient DN.
chk "with no RA cert the token is not shipped raw" no  "$(has "$DEF" '{{CMP_RA_CN}}')"
chk "  the recipient line is present but empty"    yes "$(has "$DEF" 'recipient = ')"

echo "=== store a curated override; download serves it with tokens substituted ==="
chk "PUT override -> ok" 200 "$(code -b admin.cj -X PUT "$U/api/client-config/cmp" --data-urlencode $'body=# Curated\n[cmp]\nserver = {{CMP_URL}}\nref = acme-corp')"
CUR="$(curl -s -b admin.cj "$U/api/client-config/cmp")"
chk "download serves the curated body"      yes "$(has "$CUR" 'ref = acme-corp')"
chk "download substitutes {{CMP_URL}}"      yes "$(has "$CUR" 'server = https://ca.example.com/cmp')"
chk "download leaves no raw token"          no  "$(has "$CUR" '{{CMP_URL}}')"
chk "editor now reports stored override"    yes "$(has "$(curl -s -b admin.cj "$U/api/client-config/cmp/edit")" '"stored":true')"

# "Download preview" fetched the STORED version, so it previewed nothing typed in the editor.
PRV="$(curl -s -b admin.cj -X POST "$U/api/client-config/cmp/preview" --data-urlencode $'body=[cmp]\nserver = {{CMP_URL}}\nref = typed-not-saved')"
chk "preview substitutes the TYPED text"      yes "$(has "$PRV" 'ref = typed-not-saved')"
chk "  with its tokens filled in"             yes "$(has "$PRV" 'server = https://ca.example.com/cmp')"
chk "  and saves nothing"                     yes "$(has "$(curl -s -b admin.cj "$U/api/client-config/cmp")" 'ref = acme-corp')"

echo "=== the token keeps the curated file correct when settings change ==="
curl -s -b admin.cj -X PUT "$U/api/config/db" -d 'key=BASE_URL&value=https://pki.newhost.net' >/dev/null
chk "curated download reflects the new BASE_URL" yes "$(has "$(curl -s -b admin.cj "$U/api/client-config/cmp")" 'server = https://pki.newhost.net/cmp')"

echo "=== revert (DELETE) restores the generated config ==="
chk "DELETE override -> ok" 200 "$(code -b admin.cj -X DELETE "$U/api/client-config/cmp")"
chk "download is generated again" yes "$(has "$(curl -s -b admin.cj "$U/api/client-config/cmp")" 'server = https://pki.newhost.net/cmp')"
chk "editor reports no override after revert" yes "$(has "$(curl -s -b admin.cj "$U/api/client-config/cmp/edit")" '"stored":false')"

echo "=== unknown kind + RBAC (admin-only) ==="
chk "PUT unknown kind -> 404"  404 "$(code -b admin.cj -X PUT "$U/api/client-config/bogus" --data-urlencode 'body=x')"
chk "GET edit unknown kind -> 404" 404 "$(code -b admin.cj "$U/api/client-config/bogus/edit")"
seed_web_user aud audpw123 auditor
curl -s -c aud.cj -X POST "$U/api/login" -d 'username=aud&password=audpw123' >/dev/null
chk "auditor GET edit -> 403" 403 "$(code -b aud.cj "$U/api/client-config/cmp/edit")"
chk "auditor PUT -> 403"      403 "$(code -b aud.cj -X PUT "$U/api/client-config/cmp" --data-urlencode 'body=x')"
chk "auditor DELETE -> 403"   403 "$(code -b aud.cj -X DELETE "$U/api/client-config/cmp")"
chk "auditor preview -> 403"  403 "$(code -b aud.cj -X POST "$U/api/client-config/cmp/preview" --data-urlencode 'body=x')"

echo "=== the editor UI is shipped in the served console ==="
curl -s "$U/" -o index.html
chk "client-config editor builder present" yes "$(grep -qF 'function openClientConfigModal' index.html && echo yes || echo no)"
chk "per-kind Edit button present"         yes "$(grep -qF 'ccfgedit' index.html && echo yes || echo no)"

echo "=== ⚠️ a REQUESTER can reach their own protocol credentials ==="
# The protocol configs were unavailable to a user holding the requester role, so that
# user could not learn their own CMP secret or ACME EAB key.
#
# The SERVER was already right — required_caps() gives GET /api/client-config/* and
# /api/enrolment-credentials to `cert:request`, and its own comment says "a requester is
# precisely the person who enrols". What was missing was a SURFACE: those endpoints were
# reachable only from the Users modal (user:manage) and the Endpoints tab
# (config:manage), so the one role that needs the credentials was the one role that could
# not see them. A requester could enrol in principle and never learn their own secret.
curl -s -b admin.cj -X POST "$U/api/users" -d 'username=req1&password=req1pw12345&role=requester' >/dev/null
curl -s -c req.cj -X POST "$U/api/login" -d 'username=req1&password=req1pw12345' >/dev/null
MYC="$(curl -s -b req.cj "$U/api/enrolment-credentials")"
chk "requester reads their own credentials"   yes "$(has "$MYC" '"enrolment":true')"
chk "  and they carry a CMP secret"           yes "$(has "$MYC" '"cmp_secret":"')"
chk "  and an ACME EAB key"                   yes "$(has "$MYC" '"acme_eab_hmac":"')"
chk "requester can download a client config"  200     "$(curl -s -o /dev/null -w '%{http_code}' -b req.cj "$U/api/client-config/cmp")"
# ⚠️ Self-service must stay SELF. ?username= is honoured for admins only; for anyone else
# creds_subject() falls back to the caller, so asking for admin's must return req1's own.
OTHER="$(curl -s -b req.cj "$U/api/enrolment-credentials?username=admin")"
chk "  a requester cannot read ANOTHER user's" yes "$(has "$OTHER" '"username":"req1"')"
# The panel that shows it is on the dashboard, the one tab every authenticated user sees.
chk "the dashboard renders a credentials panel" yes     "$(grep -qF 'renderMyCreds' index.html && echo yes || echo no)"
chk "  it reads the REAL field names"           yes     "$(grep -qF 'c.acme_eab_hmac' index.html && echo yes || echo no)"

echo "=== Every kind a button offers must be one the server serves ==="
# ⚠️ THE BUG THIS EXISTS FOR. The dashboard panel listed ['cmp','acme','est','scep'] — it
# invented an `est` kind the server has never had and dropped `ms`, which the server DOES
# have. Reported: four configs showed — CMP, ACME, EST, SCEP — with no MS config, and
# the EST one was "not found" on click. Both symptoms, one literal.
#
# A button with no handler is the mirror of this project's usual "reader with no writer",
# and there were TWO hand-maintained button lists against one server-side branch chain, so
# nothing made them agree. This asserts them against the SERVER rather than against each
# other: cross-checking the two lists would have passed happily while both were wrong.
# ⚠️ SCOPE THE GREP TO THE GENERATOR, or it answers a different question. `kind` is not a
# reserved word: the auth-provider endpoint dispatches on `kind == "saml"` / `kind == "oidc"`
# too, in a namespace that has nothing to do with client configs. A file-wide grep picked
# those up and reported that the server "serves" two kinds it has never had a branch for —
# a red suite naming a product bug that did not exist, which is the same failure this suite
# was written to catch, pointed the other way.
#
# So read the ONE function that decides this, from its signature to its closing brace.
CCFN=$(awk '/^ClientConfig client_config\(const pki::Config&/{f=1} f{print} f&&/^\}/{exit}' \
         "$ROOT/src/web/main.cpp")
chk "PRECONDITION: the generator function was located" yes \
    "$([ "$(printf '%s' "$CCFN" | wc -l)" -gt 50 ] && echo yes || echo no)"
SRVKINDS=$(printf '%s' "$CCFN" | grep -oE 'kind == "[a-z]+"' | sed 's/.*"\(.*\)"/\1/' | sort -u | tr '\n' ' ')
chk "the server serves exactly cmp/acme/scep/ms and the two Apple profiles" "acme appleacme applescep cmp ms scep " "$SRVKINDS"
for k in $SRVKINDS; do
    chk "  '$k' is offered by a button"  yes \
        "$(grep -qF "data-kind=\"'+k[0]+'\"" index.html && grep -qF "'$k'," index.html && echo yes || echo no)"
    case "$k" in
        apple*)  # no CA exists yet, and an Apple profile needs its root: a readable refusal
            chk "  '$k' with no CA -> 403 with a reason a person can read" "403 yes" \
                "$(curl -s -o body.txt -w '%{http_code}' -b req.cj "$U/api/client-config/$k") $(grep -q 'cannot be made for you: no CA' body.txt && echo yes || echo no)" ;;
        *)  chk "  '$k' really downloads (200)"  200 \
                "$(curl -s -o /dev/null -w '%{http_code}' -b req.cj "$U/api/client-config/$k")" ;;
    esac
done
# And the other direction — the one that actually broke. Every kind a button names must be
# one of the server's; an `est` button 404s the moment anyone clicks it.
#
# ⚠️ EXCLUDE COMMENT LINES. The console is one raw-string literal, so its JS comments are
# SERVED, and the follow-up note at src/web/main.cpp:7337 literally contains
# ['cmp','acme','est','scep'] — the wrong list it exists to warn about. Scanning prose means
# a comment can keep this check alive after the code it describes is gone.
BTNKINDS=$(grep -v '^[[:space:]]*//' index.html \
           | grep -oE "\['(cmp|acme|scep|ms|est|appleacme|applescep)'," | sed "s/\['//; s/',//" | sort -u | tr '\n' ' ')
# ⚠️ AND ASSERT THE INPUT IS NON-EMPTY FIRST. The check below is satisfied by the empty
# string, so a scan that matches NOTHING — every button gone, or the array reshaped so the
# regex misses it — reads exactly like "no bad kinds". A guard whose healthy answer is
# "zero" proves nothing until you know it looked at something.
chk "  the button-kind scan actually found buttons" yes \
    "$([ -n "$BTNKINDS" ] && echo yes || echo no)"
chk "no button names a kind the server lacks" "" \
    "$(for b in $BTNKINDS; do echo "$SRVKINDS" | grep -qw "$b" || printf '%s ' "$b"; done)"

echo "=== Apple profiles: a device installs them and enrols by itself ==="
# The ACME profile carries a NEW one-time device ticket on every download, issued to the
# downloading user; the SCEP profile carries that user's own challenge. Both carry the CA's
# root. A profile that could not work is refused in plain text, because a phone shows it.
ca_in_token ca1.pem "/CN=Profile Test Root" 30 ca1
printf 'SIGNING_CA_PEM=%s\nSIGNING_CA_KEY=%s\nSIGNING_CA_ID=ca1\nPG_CONNINFO=%s\n' \
    "$W/ca1.pem" "$CA_KEY_URI" "$PG_CONNINFO" > ca1.conf
seed_ca_from_conf ca1.conf
chk "PRECONDITION: the CA is registered" 1 "$(pg_exec "SELECT count(*) FROM certs WHERE ca_instance_id='ca1' AND is_ca;")"
tickets() { pg_exec "SELECT count(*) FROM acme_device_tickets;"; }
T0=$(tickets)
HDR="$W/apple.hdr"
A1="$(curl -s -D "$HDR" -b req.cj "$U/api/client-config/appleacme?ca=ca1")"
chk "the ACME profile downloads (200)" yes "$(grep -q '^HTTP/1.1 200' "$HDR" && echo yes || echo no)"
chk "  as application/x-apple-aspen-config" yes "$(grep -qi '^Content-Type: application/x-apple-aspen-config' "$HDR" && echo yes || echo no)"
chk "  named fastpki-acme.mobileconfig" yes "$(grep -qi 'filename="fastpki-acme.mobileconfig"' "$HDR" && echo yes || echo no)"
TK1=$(printf '%s' "$A1" | sed -n 's|.*<key>ClientIdentifier</key><string>\([0-9a-f]\{32\}\)</string>.*|\1|p')
chk "  with a 32-hex ticket as ClientIdentifier" yes "$([ -n "$TK1" ] && echo yes || echo no)"
chk "  the ticket is issued to the downloading user, for that CA" "req1|ca1" \
    "$(pg_exec "SELECT owner||'|'||ca_instance_id FROM acme_device_tickets WHERE ticket='$TK1';")"
chk "  attestation and a Secure Enclave key are asked for" yes \
    "$(has "$A1" '<key>Attest</key><true/>' | grep -q yes && has "$A1" '<key>HardwareBound</key><true/>')"
# BASE_URL was changed to pki.newhost.net above, and the profile follows it.
chk "  the directory is this CA's" yes "$(has "$A1" '<key>DirectoryURL</key><string>https://pki.newhost.net')"
chk "  ... at /acme/ca1/directory" yes "$(has "$A1" '/acme/ca1/directory</string>')"
chk "  the device is named after the user" yes "$(has "$A1" '<string>req1-device</string>')"
chk "  no token is left unfilled" no "$(has "$A1" '{{')"
ROOT_B64=$(printf '%s' "$A1" | sed -n 's|.*<data>\(.*\)</data>.*|\1|p')
chk "  the root payload is the CA's certificate" "$("$OSSL" x509 -in ca1.pem -noout -fingerprint -sha256)" \
    "$(printf '%s' "$ROOT_B64" | "$OSSL" base64 -d -A | "$OSSL" x509 -inform DER -noout -fingerprint -sha256 2>/dev/null)"
if command -v xmllint >/dev/null 2>&1; then
    chk "  the profile is well-formed XML" 0 "$(printf '%s' "$A1" | xmllint --noout - >/dev/null 2>&1; echo $?)"
fi
A2="$(curl -s -b req.cj "$U/api/client-config/appleacme?ca=ca1")"
TK2=$(printf '%s' "$A2" | sed -n 's|.*<key>ClientIdentifier</key><string>\([0-9a-f]\{32\}\)</string>.*|\1|p')
chk "every download carries a NEW ticket" yes "$([ -n "$TK2" ] && [ "$TK2" != "$TK1" ] && echo yes || echo no)"
chk "  and new payload UUIDs" yes \
    "$([ "$(printf '%s' "$A1" | grep -o 'PayloadUUID</key><string>[^<]*' | head -1)" != \
         "$(printf '%s' "$A2" | grep -o 'PayloadUUID</key><string>[^<]*' | head -1)" ] && echo yes || echo no)"
chk "  and each is audited" 2 "$(pg_exec "SELECT count(*) FROM audit_log WHERE action='acme_device_ticket_issued' AND actor='req1';")"

S1="$(curl -s -b req.cj "$U/api/client-config/applescep?ca=ca1")"
chk "the SCEP profile carries the user's own challenge" yes "$(has "$S1" '<key>Challenge</key><string>req1:')"
chk "  the SCEP URL and the CA name" yes \
    "$(has "$S1" '/scep/ca1</string>' | grep -q yes && has "$S1" '<key>Name</key><string>ca1</string>')"
chk "  and issues no ticket" "$(( T0 + 2 ))" "$(tickets)"

chk "a user who may not request certificates gets a refusal, not a profile" "403 yes" \
    "$(curl -s -o body.txt -w '%{http_code}' -b aud.cj "$U/api/client-config/appleacme?ca=ca1") $(grep -q 'lack cert:request' body.txt && echo yes || echo no)"
chk "  and no ticket is issued" "$(( T0 + 2 ))" "$(tickets)"
PV="$(curl -s -b admin.cj -X POST "$U/api/client-config/appleacme/preview?ca=ca1" \
      --data-urlencode $'body=<string>{{DEVICE_TICKET}}</string>')"
chk "a preview shows a placeholder ticket" yes "$(has "$PV" 'PREVIEW-NO-TICKET-ISSUED')"
chk "  and issues none" "$(( T0 + 2 ))" "$(tickets)"

echo "=== The Enrolment codes page: tickets, device serials, SCEP one-time challenges ==="
# user:manage, like another user's enrolment credentials: these decide who may enrol.
chk "a requester cannot list device tickets (403)" 403 "$(code -b req.cj "$U/api/device-tickets")"
chk "  nor issue one" 403 "$(code -b req.cj -X POST "$U/api/device-tickets" -d 'ca=ca1&owner=req1')"
TJ="$(curl -s -b admin.cj -X POST "$U/api/device-tickets" -d 'ca=ca1&owner=req1&ttl=3600')"
TA=$(printf '%s' "$TJ" | sed -n 's/.*"ticket":"\([0-9a-f]\{32\}\)".*/\1/p')
chk "an admin issues a ticket for another user" yes "$([ -n "$TA" ] && echo yes || echo no)"
chk "  it is owned by that user" "req1|ca1" "$(pg_exec "SELECT owner||'|'||ca_instance_id FROM acme_device_tickets WHERE ticket='$TA';")"
chk "  and listed in full while unused" yes "$(has "$(curl -s -b admin.cj "$U/api/device-tickets")" "\"ticket\":\"$TA\"")"
chk "  and audited" 1 "$(pg_exec "SELECT count(*) FROM audit_log WHERE action='acme_device_ticket_issued' AND actor='admin';")"
chk "a ticket for an owner without acme:enrol is refused (400)" 400 \
    "$(code -b admin.cj -X POST "$U/api/device-tickets" -d 'ca=ca1&owner=aud')"
chk "cancelling an unused ticket -> 200" 200 "$(code -b admin.cj -X DELETE "$U/api/device-tickets/$TA")"
chk "  it is gone" 0 "$(pg_exec "SELECT count(*) FROM acme_device_tickets WHERE ticket='$TA';")"
chk "  and cancelling it again -> 404" 404 "$(code -b admin.cj -X DELETE "$U/api/device-tickets/$TA")"
PF="$(curl -s -b admin.cj -X POST "$U/api/device-tickets" -d 'ca=ca1&owner=req1&format=mobileconfig')"
chk "'Issue and download' gives the finished profile" yes "$(has "$PF" '<string>com.apple.security.acme</string>')"
chk "  named for the owner's device" yes "$(has "$PF" '<string>req1-device</string>')"
chk "  carrying a ticket that exists" 1 \
    "$(pg_exec "SELECT count(*) FROM acme_device_tickets WHERE ticket='$(printf '%s' "$PF" | sed -n 's|.*<key>ClientIdentifier</key><string>\([0-9a-f]\{32\}\)</string>.*|\1|p')';")"

chk "a device serial is registered" 200 \
    "$(code -b admin.cj -X POST "$U/api/device-serials" -d 'ca=ca1&owner=req1&serial=C02ABCDEF123')"
chk "  and listed" yes "$(has "$(curl -s -b admin.cj "$U/api/device-serials")" '"serial":"C02ABCDEF123"')"
chk "a serial with other characters is refused (400)" 400 \
    "$(code -b admin.cj -X POST "$U/api/device-serials" -d 'ca=ca1&owner=req1&serial=C02-ABC')"
IMP="$(curl -s -b admin.cj -X POST "$U/api/device-serials" --data-urlencode 'ca=ca1' \
       --data-urlencode 'owner=req1' --data-urlencode $'csv=# from the MDM\nC02IMPORT001\nC02IMPORT002,aud\nbad-serial\n\nC02IMPORT003,req1')"
chk "a CSV import adds the good lines" yes "$(has "$IMP" '"added":2')"
chk "  and reports the refused ones by line" yes \
    "$(has "$IMP" '"line":3' | grep -q yes && has "$IMP" '"line":4')"
chk "  the owner's refusal names the reason" yes "$(has "$IMP" 'acme:enrol')"
chk "removing a serial -> 200" 200 "$(code -b admin.cj -X DELETE "$U/api/device-serials/C02IMPORT001?ca=ca1")"
chk "  and it is gone" 0 "$(pg_exec "SELECT count(*) FROM acme_device_serials WHERE serial='C02IMPORT001';")"

chk "a SCEP challenge is refused while the scep identity has no profile (400)" 400 \
    "$(code -b admin.cj -X POST "$U/api/scep-challenges" -d 'ttl=600')"
seed_enrolling_identity scep >/dev/null 2>&1
SJ="$(curl -s -b admin.cj -X POST "$U/api/scep-challenges" -d 'ttl=600')"
SC=$(printf '%s' "$SJ" | sed -n 's/.*"token":"\([0-9a-f]\{32\}\)".*/\1/p')
chk "  and issued once it has one" yes "$([ -n "$SC" ] && echo yes || echo no)"
chk "  with a warning while SCEP_DYNAMIC_CHALLENGE is off" yes "$(has "$SJ" '"accepted":false')"
chk "  listed while unused" yes "$(has "$(curl -s -b admin.cj "$U/api/scep-challenges")" "\"token\":\"$SC\"")"
chk "  and cancelled" 200 "$(code -b admin.cj -X DELETE "$U/api/scep-challenges/$SC")"

curl -s "$U/" -o index.html
chk "the console serves an Enrolment codes tab" yes \
    "$(grep -qF '<button data-tab="enrolcodes">Enrolment codes</button>' index.html && echo yes || echo no)"
chk "  which TAB_CAPS gates on user:manage" yes \
    "$(grep -qE "enrolcodes: *\['user:manage'\]" index.html && echo yes || echo no)"
chk "  and load() renders" yes \
    "$(grep -qF "tab === 'enrolcodes') { await renderEnrolCodes(); return; }" index.html && echo yes || echo no)"

echo "=== Client configs have their OWN page, between Config and Backup ==="
# Editable client configs do not belong on the Endpoints page: they move to their own
# page, 'Client Configs', between Config and Backup.
#
# Asserted on the SERVED console rather than the source: this is markup the browser gets,
# and the shell harness cannot run the JS (§3e), so every check below is about what is
# actually delivered.
chk "a Client Configs tab is served" yes \
    "$(grep -qF 'data-tab="clientcfg"' index.html && echo yes || echo no)"
chk "  labelled 'Client Configs'" yes \
    "$(grep -qF '<button data-tab="clientcfg">Client Configs</button>' index.html && echo yes || echo no)"
# The POSITION is the literal request, so assert the order rather than mere presence.
NAVORDER=$(grep -oE 'data-tab="[a-z]+"' index.html | sed 's/data-tab="//; s/"//' | awk '!seen[$0]++' | tr '\n' ' ')
chk "  it sits between Config and Backup" yes \
    "$(echo "$NAVORDER" | grep -q 'config clientcfg backup' && echo yes || echo no)"

# ⚠️ THE WIRING THAT FAILS SILENTLY. tabAllowed() returns FALSE for a tab missing from
# TAB_CAPS ("an unknown tab is hidden, not shown"), so without this entry the button is
# served, passes every markup grep above, and is invisible to everyone except *:* —
# a nav item that exists in the HTML and not on the screen.
chk "  and TAB_CAPS knows it, or it renders for nobody" yes \
    "$(grep -qE 'clientcfg: *\[' index.html && echo yes || echo no)"
chk "  gated on config:manage, the capability it had on Endpoints" yes \
    "$(grep -qE "clientcfg: *\['config:manage'\]" index.html && echo yes || echo no)"

chk "the page has a renderer" yes \
    "$(grep -qF 'function renderClientConfigs' index.html && echo yes || echo no)"
chk "  and load() dispatches to it" yes \
    "$(grep -qF "tab === 'clientcfg') { renderClientConfigs(); return; }" index.html && echo yes || echo no)"
chk "  with its own panel container" yes \
    "$(grep -qF 'id="ccpanel"' index.html && echo yes || echo no)"
chk "  which updateChrome hides on every other tab" yes \
    "$(grep -qF "tab !== 'clientcfg') document.getElementById('ccpanel').hidden = true" index.html && echo yes || echo no)"

# ⚠️ A MOVE, NOT A COPY. Every assertion above passes just as well if the block was
# duplicated onto a new page and left on Endpoints — which is the likeliest way to "fix"
# this and not fix it. Read renderEpEdit's own body and require the client-config markup to
# be GONE from it.
EPBODY=$(awk '/^function renderEpEdit\(\)/{f=1} f{print} f&&/^}/{exit}' index.html)
chk "the Endpoints page no longer builds client-config buttons" no \
    "$(echo "$EPBODY" | grep -q 'ccfg' && echo yes || echo no)"
chk "  and no longer carries the 'Client configs' heading" no \
    "$(echo "$EPBODY" | grep -q 'Client configs' && echo yes || echo no)"
# The other half of the move: Endpoints keeps what it is actually for.
chk "  while keeping its endpoint-health control" yes \
    "$(echo "$EPBODY" | grep -q 'ephcheck' && echo yes || echo no)"

echo "=== A caller of this file must select a SECTION, and the demo must ==="
# ⚠️ WHY THIS IS HERE RATHER THAN IN A DEMO SUITE. The defect is a mismatch between the
# file this endpoint SERVES and the way a caller drives it, so the assertion needs the
# real served bytes — which this suite already holds in $DEF — not a copy of them.
#
# Replaced the single-[cmp] config with the section-per-command file.
# Its [cmp] section carries the SIGNATURE credentials (cert/key, and `secret =` to switch
# PBM off), because that is what an already-enrolled client uses; the shared secret lives
# in [ir]. `openssl cmp -config X` with no -section reads ONLY [cmp], so it asks for two
# files that a first enrolment does not have yet and dies before sending anything:
#
#     cmp_main:apps/cmp.c:3867:CMP error: cannot set up CMP context
#
# That is exactly what was hit after the recipient bug was fixed, and `-cmd ir` on
# the command line does not help: it overrides `cmd = cr` and pulls in nothing else, so
# the command looks selected while the credentials are not.
printf '%s' "$DEF" > served-cmp.cnf
# Point it at a port nothing listens on. This is deliberate: context setup happens BEFORE
# any I/O, so a connect failure is PROOF that setup succeeded, and the suite needs no CMP
# server to decide the question it is actually asking.
sed -i.bak "s|^server = .*|server = 127.0.0.1:9/cmp|" served-cmp.cnf
sed -i.bak "s|^ref = .*|ref = demo:cmp|; s|^secret = pass:.*|secret = pass:notasecret|" served-cmp.cnf
"$OSSL" genrsa -out cc-id.key 2048 >/dev/null 2>&1
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout cc-anchor.key -out cc-anchor.pem \
        -subj "/CN=cc-anchor" -days 1 >/dev/null 2>&1
cmp_try(){  # extra args -> prints "setup-failed" or "reached-transport"
    "$OSSL" cmp -config served-cmp.cnf "$@" -trusted cc-anchor.pem \
            -newkey cc-id.key -subject "/CN=demo" -certout cc-out.pem >cc.log 2>&1
    grep -q "cannot set up CMP context" cc.log && { echo "setup-failed"; return; }
    echo "reached-transport"
}
# ⚠️ THE NEGATIVE FIRST, so this cannot pass vacuously. If the served file ever stops
# requiring a section, the positive assertion below would hold for a config that never
# needed one and the guard would be worth nothing.
chk "without -section the served config cannot even set up a context" \
    setup-failed "$(cmp_try -cmd ir)"
chk "  with -section cmp,ir it gets past setup to the transport" \
    reached-transport "$(cmp_try -cmd ir -section cmp,ir)"

# And the call sites. The functional pair above proves the contract; this proves the demo
# HONOURS it — cmp_enroll() has long carried the -section and cmp_identity() did
# not, which is the whole defect. A third call site added later fails here.
DEMO="$ROOT/demo/pki-demo.sh"
CFG_CALLS=$(grep -c 'cmp .*-config "\$CMP_CONFIG"' "$DEMO" 2>/dev/null || echo 0)
SECT_CALLS=$(grep -c 'cmp .*-section cmp,ir -config "\$CMP_CONFIG"' "$DEMO" 2>/dev/null || echo 0)
SRV_CALLS=$(grep -c 'cmp .*-config "\$CMP_CONFIG" -server "\$CMP_URL"' "$DEMO" 2>/dev/null || echo 0)
chk "the demo has more than one -config call site" yes \
    "$([ "${CFG_CALLS:-0}" -gt 1 ] && echo yes || echo no)"
chk "  and every one of them selects a section" "$CFG_CALLS" "$SECT_CALLS"
# ⚠️ AND OVERRIDES THE SERVER. `server =` in this file is the DEPLOYMENT's public URL
# ({{CMP_URL}} from BASE_URL/PKI_DNS); the demo reaches the target at TARGET_HOST, which
# is whatever the operator pointed it at. Measured on dc3 once the section fix was in:
#
#   CMP info: will contact http://pki.example.org:8445/cmp/issuing-dc3
#   CMP error: system lib:No address associated with hostname
#
# i.e. the config got the client past setup and then sent it somewhere the demo cannot
# resolve — the SAME class as the SCEP_CHALLENGE problem: a value read from the deployment
# describes the deployment, not the route in use.
chk "  and every one overrides the config's server" "$CFG_CALLS" "$SRV_CALLS"
# The served file really does carry a server line, so the assertion above is about
# something that exists rather than a precaution against nothing.
chk "  (the served config does name a server)" yes \
    "$(printf '%s' "$DEF" | grep -q '^server = ' && echo yes || echo no)"

echo
echo "=== CLIENT CONFIG STORE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
