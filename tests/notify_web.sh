#!/usr/bin/env bash
# Notification-dispatcher panel. The console exposes a
# read-only preview of what the cron fastpki-notify would alert on (GET
# /api/notify: configured windows + expiry buckets), the windows/webhook live in
# the DB config overlay, and fastpki-notify falls back to them when its flags are
# omitted.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
WEB="$ROOT/build/fastpki-web"; NOTIFY="$ROOT/build/fastpki-notify"
W="$(mktemp -d)"; cd "$W"; P1=18230; P2=18231
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

pg_setup notify_web; PG_CONNINFO1="$PG_CONNINFO"; DB1="$PGDATABASE"
NOW=$(date +%s)
seed(){ pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,owner,cn) VALUES
 ('aa',0,$((NOW-86400)),$((NOW-86400)),'/CN=expired.host','alice','expired.host'),
 ('bb',0,$((NOW-86400)),$((NOW+5*86400)),'/CN=critical.host','bob','critical.host'),
 ('cc',0,$((NOW-86400)),$((NOW+10*86400)),'/CN=warning.host','carol','warning.host'),
 ('dd',0,$((NOW-86400)),$((NOW+25*86400)),'/CN=info.host','dave','info.host'),
 ('ee',0,$((NOW-86400)),$((NOW+100*86400)),'/CN=far.host','erin','far.host');"; }
seed
pg_setup notify_web2
seed
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT

cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO1
WEB_BIND=127.0.0.1
WEB_PORT=$P1
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
"$WEB" --config web.conf >web.log 2>&1 & P=$!
PID2=
sleep 1; trap 'pg_cleanup; kill $P $PID2 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$P1"
code -X POST "$U/api/users" -d 'username=boss&password=bosspw12&role=admin' >/dev/null
curl -s -c boss.cj -X POST "$U/api/login" -d 'username=boss&password=bosspw12' >/dev/null
code -b boss.cj -X POST "$U/api/users" -d 'username=al&password=alicepw12&role=requester' >/dev/null
curl -s -c al.cj -X POST "$U/api/login" -d 'username=al&password=alicepw12' >/dev/null

echo "=== /api/notify preview with the default 30,14,7 windows ==="
N=$(curl -s -b boss.cj "$U/api/notify")
chk "default windows reported"        yes "$(has "$N" '"days":\[30,14,7\]')"
chk "expired bucket counts 1"         yes "$(has "$N" '"expired":1')"
chk "critical bucket counts 1"        yes "$(has "$N" '"critical":1')"
chk "warning bucket counts 1"         yes "$(has "$N" '"warning":1')"
chk "info bucket counts 1"            yes "$(has "$N" '"info":1')"
chk "the cert beyond the window is excluded" no "$(has "$N" 'far.host')"
chk "a soon-to-expire cert is listed" yes "$(has "$N" 'critical.host')"

echo "=== RBAC + persistence ==="
chk "requester cannot read /api/notify (403)" 403 "$(code -b al.cj "$U/api/notify")"
chk "admin persists NOTIFY_DAYS to the overlay (200)" 200 \
    "$(code -b boss.cj -X PUT "$U/api/config/db" --data 'key=NOTIFY_DAYS&value=14,7')"
chk "the overlay round-trips the new value" yes \
    "$(has "$(curl -s -b boss.cj "$U/api/config/db")" 'NOTIFY_DAYS')"

echo "=== the webhook: its format, never its address, and a way to remove it ==="
chk "the preview reports the format (json by default)" yes "$(has "$(curl -s -b boss.cj "$U/api/notify")" '"webhookFormat":"json"')"
chk "a webhook is stored (200)" 200 \
    "$(code -b boss.cj -X PUT "$U/api/config/db" --data-urlencode 'key=NOTIFY_WEBHOOK' --data-urlencode 'value=https://hooks.example.test/T000/B000/secretpart')"
chk "a format is stored (200)" 200 \
    "$(code -b boss.cj -X PUT "$U/api/config/db" --data 'key=NOTIFY_WEBHOOK_FORMAT&value=teams')"
chk "an unknown format is refused (400)" 400 \
    "$(code -b boss.cj -X PUT "$U/api/config/db" --data 'key=NOTIFY_WEBHOOK_FORMAT&value=markdown')"
NP=$(curl -s -b boss.cj "$U/api/notify")
chk "the preview says the webhook is set"   yes "$(has "$NP" '"webhook":"(set)"')"
chk "  and reports the stored format"      yes "$(has "$NP" '"webhookFormat":"teams"')"
# A Slack or Teams webhook URL is a bearer token. The Notifications page masked it; the Config
# page printed it.
chk "the Config page does not print the webhook address" no \
    "$(has "$(curl -s -b boss.cj "$U/api/config")" 'secretpart')"
chk "  nor does the stored-overrides list" no \
    "$(has "$(curl -s -b boss.cj "$U/api/config/db")" 'secretpart')"
PAGE=$(curl -s -b boss.cj "$U/")
# The LABEL markup, not the words: the page's own comment explaining the rename quotes the old
# label, and a check for the bare phrase matched it.
chk "the form says Webhook, not Default webhook" yes \
    "$([ "$(has "$PAGE" '<label>Webhook <input name="webhook"')" = yes ] && [ "$(has "$PAGE" '<label>Default webhook')" = no ] && echo yes || echo no)"
chk "  offers the Slack and Teams formats"      yes "$(has "$PAGE" "\['teams','Microsoft Teams'\]")"
chk "  and a Remove webhook control"            yes "$(has "$PAGE" 'id="notifyclear">Remove webhook')"
chk "removing the webhook (the control's request) succeeds" 200 \
    "$(code -b boss.cj -X DELETE "$U/api/config/db?key=NOTIFY_WEBHOOK")"
chk "  and the preview no longer reports one" yes "$(has "$(curl -s -b boss.cj "$U/api/notify")" '"webhook":""')"

echo "=== email: the relay, the template, a test message and each user's address ==="
hasf(){ echo "$1" | grep -qF "$2" && echo yes || echo no; }
N=$(curl -s -b boss.cj "$U/api/notify")
chk "the preview carries the relay settings, none set"   yes "$(hasf "$N" '"email":{"server":"","tls":"starttls","user":"","password":""')"
chk "  and the built-in template"                          yes "$(hasf "$N" '"template":{"subject":"FastPKI: {{count}} certificate(s)')"
chk "  marked as not edited"                               yes "$(hasf "$N" '"custom":false')"
for kv in 'SMTP_SERVER=mail.example.test:587' 'SMTP_USER=mailer' 'SMTP_PASSWORD=relaypw-secretpart' \
          'SMTP_FROM=pki@example.test' 'NOTIFY_EMAIL_FALLBACK=pki-team@example.test'; do
    chk "stores ${kv%%=*}" 200 "$(code -b boss.cj -X PUT "$U/api/config/db" --data-urlencode "key=${kv%%=*}" --data-urlencode "value=${kv#*=}")"
done
chk "an unknown SMTP_TLS value is refused (400)" 400 \
    "$(code -b boss.cj -X PUT "$U/api/config/db" --data 'key=SMTP_TLS&value=plain')"
N=$(curl -s -b boss.cj "$U/api/notify")
chk "the preview shows the relay"                          yes "$(hasf "$N" '"server":"mail.example.test:587"')"
chk "  the password only as set"                           yes "$(hasf "$N" '"password":"(set)"')"
chk "  and the fallback address"                           yes "$(hasf "$N" '"fallback":"pki-team@example.test"')"
chk "neither the preview nor the Config page prints the password" no \
    "$(hasf "$N$(curl -s -b boss.cj "$U/api/config")$(curl -s -b boss.cj "$U/api/config/db")" 'relaypw-secretpart')"
chk "a template without {{certificates}} is refused (400)" 400 \
    "$(code -b boss.cj -X PUT "$U/api/notify/template" --data-urlencode 'subject=S' --data-urlencode 'line=L' --data-urlencode 'body=no list here')"
chk "a template missing a part is refused (400)" 400 \
    "$(code -b boss.cj -X PUT "$U/api/notify/template" --data-urlencode 'subject=' --data-urlencode 'line=L' --data-urlencode 'body={{certificates}}')"
chk "a complete template is stored (200)" 200 \
    "$(code -b boss.cj -X PUT "$U/api/notify/template" --data-urlencode 'subject=Expiring: {{count}}' --data-urlencode 'line=- {{name}}' --data-urlencode 'body=Hi {{owner}}
{{certificates}}')"
N=$(curl -s -b boss.cj "$U/api/notify")
chk "  and the page edits the stored one"                  yes "$(hasf "$N" '"subject":"Expiring: {{count}}"' )"
chk "  marked as edited"                                   yes "$(hasf "$N" '"custom":true')"
chk "the template replicates: it is a row, not a config key" 1 \
    "$(PGDATABASE="$DB1" pg_exec "SELECT count(*) FROM notify_templates WHERE name='expiry';" | tr -d ' ')"
chk "resetting returns to the built-in template (200)" 200 "$(code -b boss.cj -X DELETE "$U/api/notify/template")"
chk "  which the preview then shows" yes "$(hasf "$(curl -s -b boss.cj "$U/api/notify")" '"custom":false')"
chk "a requester cannot edit the template (403)" 403 \
    "$(code -b al.cj -X PUT "$U/api/notify/template" --data-urlencode 'subject=x' --data-urlencode 'line=x' --data-urlencode 'body={{certificates}}')"
chk "a test email needs one address (400)" 400 \
    "$(code -b boss.cj -X POST "$U/api/notify/test-email" --data-urlencode 'to=not an address')"
# A relay that does not answer: the error comes back to the page instead of a hang or a 200.
chk "a test email to a relay that is not there reports the failure (502)" 502 \
    "$(code -b boss.cj -X POST "$U/api/notify/test-email" --data-urlencode 'to=boss@example.test' --max-time 60)"
chk "a requester cannot send a test email (403)" 403 \
    "$(code -b al.cj -X POST "$U/api/notify/test-email" --data-urlencode 'to=al@example.test')"
code -b boss.cj -X DELETE "$U/api/config/db?key=SMTP_SERVER" >/dev/null
chk "with no relay set the test email says so (400)" 400 \
    "$(code -b boss.cj -X POST "$U/api/notify/test-email" --data-urlencode 'to=boss@example.test')"
PAGE=$(curl -s -b boss.cj "$U/")
chk "the page has the relay form"                         yes "$(hasf "$PAGE" "'<form id=\"notifymail\"")"
chk "  a Send test email control"                          yes "$(hasf "$PAGE" 'id="notifytest">Send test email')"
chk "  and the template editor"                            yes "$(hasf "$PAGE" "'<form id=\"notifytpl\"")"
chk "  offering STARTTLS, TLS and none"                    yes "$(hasf "$PAGE" "['none','None: a relay without TLS (port 25 by default)']")"
chk "  and refusing none beside a user at the form"        yes "$(hasf "$PAGE" "if (f.tls.value === 'none' && f.user.value.trim())")"
chk "none is a value the settings accept (200)" 200 \
    "$(code -b boss.cj -X PUT "$U/api/config/db" --data 'key=SMTP_TLS&value=none')"
code -b boss.cj -X DELETE "$U/api/config/db?key=SMTP_TLS" >/dev/null
chk "the user form has an Email field"                     yes "$(hasf "$PAGE" '<label>Email</label>')"

# Each account's own address, set by an administrator or by the account itself.
chk "an administrator sets a user's email (200)" 200 \
    "$(code -b boss.cj -X POST "$U/api/users" --data-urlencode 'username=al' --data-urlencode 'email=al@example.test')"
chk "  which the users list shows" yes "$(hasf "$(curl -s -b boss.cj "$U/api/users")" '"username":"al","role":"requester"')"
chk "  with the address" yes "$(hasf "$(curl -s -b boss.cj "$U/api/users")" '"email":"al@example.test"')"
chk "  and the role is untouched by an email-only edit" requester \
    "$(PGDATABASE="$DB1" pg_exec "SELECT role FROM web_users WHERE username='al';" | tr -d ' ')"
chk "a user sets their own email without their password (200)" 200 \
    "$(code -b al.cj -X POST "$U/api/users" --data-urlencode 'username=al' --data-urlencode 'email=al.home@example.test')"
chk "  and it is stored" al.home@example.test "$(PGDATABASE="$DB1" pg_exec "SELECT email FROM web_users WHERE username='al';" | tr -d ' ')"
chk "  but still cannot change their password without it (401)" 401 \
    "$(code -b al.cj -X POST "$U/api/users" --data-urlencode 'username=al' --data-urlencode 'password=newpass123')"
chk "an address that is not one is refused (400)" 400 \
    "$(code -b boss.cj -X POST "$U/api/users" --data-urlencode 'username=al' --data-urlencode 'email=al@@example')"
for k in SMTP_USER SMTP_PASSWORD SMTP_FROM NOTIFY_EMAIL_FALLBACK; do
    code -b boss.cj -X DELETE "$U/api/config/db?key=$k" >/dev/null
done

echo "=== a fresh instance honors the configured window (NOTIFY_DAYS=7) ==="
cat > web2.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$P2
WEB_ALLOW_REVOKE=true
NOTIFY_DAYS=7
LOG_LEVEL=err
EOF
"$WEB" --config web2.conf >web2.log 2>&1 & PID2=$!
sleep 1; U2="http://127.0.0.1:$P2"
code -X POST "$U2/api/users" -d 'username=boss&password=bosspw12&role=admin' >/dev/null
curl -s -c b2.cj -X POST "$U2/api/login" -d 'username=boss&password=bosspw12' >/dev/null
N2=$(curl -s -b b2.cj "$U2/api/notify")
chk "7-day window reported"                    yes "$(has "$N2" '"days":\[7\]')"
chk "only certs within 7d (warning excluded)"  no  "$(has "$N2" 'warning.host')"
chk "the critical cert is still in-window"      yes "$(has "$N2" 'critical.host')"

echo "=== fastpki-notify falls back to NOTIFY_DAYS from config ==="
cat > cli.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
NOTIFY_DAYS=7
LOG_LEVEL=err
EOF
REP=$("$NOTIFY" --config cli.conf)
chk "cron notify uses the 7-day default window" yes "$(has "$REP" 'expiring within 7 days')"
chk "cron notify excludes the 25-day cert"      no  "$(has "$REP" 'info.host')"

echo
echo "=== NOTIFY WEB: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
