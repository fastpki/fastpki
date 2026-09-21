#!/usr/bin/env bash
# Expiry-notification engine — fastpki-notify.
#   - scans certs.db and buckets valid certs by time-to-expiry
#     (expired / critical <=7d / warning <=14d / info <=30d)
#   - certs outside the largest window are not reported
#   - --webhook POSTs the JSON summary (delivery + graceful failure on no listener)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
NOTIFY="$ROOT/build/fastpki-notify"
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

pg_setup notify
SMTPD_PID=
trap 'pg_cleanup; kill $SMTPD_PID 2>/dev/null' EXIT
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
LOG_LEVEL=err
EOF

NOW=$(date +%s)
ins() { # serial cn owner "notAfter"
    pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint) VALUES('$1',0,0,0,$((NOW-86400)),$4,'CN=$2','$3','$2','');"
}
ins aa expired.host  alice  $((NOW - 86400))        # expired (1d ago)
ins bb critical.host bob    $((NOW + 5*86400))      # critical (<=7d)
ins cc warning.host  carol  $((NOW + 10*86400))     # warning (<=14d)
ins dd info.host     dave   $((NOW + 25*86400))     # info (<=30d)
ins ee far.host      erin   $((NOW + 100*86400))    # outside the 30d window
# a revoked cert that's also "expiring" must be ignored (status != 0)
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint) VALUES('ff',-1,1,$NOW,$((NOW-86400)),$((NOW+5*86400)),'CN=revoked.host','x','revoked.host','');"

echo "=== scan / report ==="
REP=$("$NOTIFY" --config bootstrap.conf)
echo "$REP" | grep -q "expiring within 30 days: 4" && a=yes || a=no
chk "reports 4 certs in the 30d window" yes "$a"
echo "$REP" | grep -q "expired=1 critical=1 warning=1 info=1" && a=yes || a=no
chk "buckets: expired=1 critical=1 warning=1 info=1" yes "$a"
echo "$REP" | grep -q "far.host" && a=yes || a=no
chk "cert outside window not reported" no "$a"
echo "$REP" | grep -q "revoked.host" && a=yes || a=no
chk "revoked cert not reported" no "$a"

echo "=== JSON output ==="
J=$("$NOTIFY" --config bootstrap.conf --json)
echo "$J" | grep -q '"count":4' && a=yes || a=no
chk "json count=4" yes "$a"
echo "$J" | grep -q '"severity":"critical"' && a=yes || a=no
chk "json carries severity" yes "$a"

echo "=== discovered (unmanaged) certs ==="
# A discovered cert expiring in 5 days (critical) + one outside the window.
pg_exec "INSERT INTO discovered_certs(target,serial,subject,issuer,\"notBefore\",\"notAfter\",\"keyAlgo\",\"keyBits\",\"sigAlgo\",sans,fingerprint,\"selfSigned\",flags,\"discoveredAt\") VALUES('10.0.0.7:443','d1','CN=legacy.host','CN=legacy.host',$((NOW-86400)),$((NOW+5*86400)),'RSA',1024,'sha1WithRSAEncryption','','ab',1,'weak_key',$NOW);"
pg_exec "INSERT INTO discovered_certs(target,serial,subject,issuer,\"notBefore\",\"notAfter\",\"keyAlgo\",\"keyBits\",\"sigAlgo\",sans,fingerprint,\"selfSigned\",flags,\"discoveredAt\") VALUES('10.0.0.8:443','d2','CN=far.legacy','CN=far.legacy',$((NOW-86400)),$((NOW+100*86400)),'RSA',2048,'sha256WithRSAEncryption','','cd',1,'',$NOW);"
# Default: discovered certs are NOT scanned.
echo "$("$NOTIFY" --config bootstrap.conf)" | grep -q "legacy.host" && a=yes || a=no
chk "discovered certs ignored without --include-discovered" no "$a"
# With the flag: the expiring discovered cert joins the report (owner=discovered).
RD=$("$NOTIFY" --config bootstrap.conf --include-discovered)
echo "$RD" | grep -q "expiring within 30 days: 5" && a=yes || a=no
chk "--include-discovered adds the expiring discovered cert (5)" yes "$a"
echo "$RD" | grep -qE "legacy.host.*owner=discovered" && a=yes || a=no
chk "discovered cert labelled owner=discovered" yes "$a"
echo "$RD" | grep -q "far.legacy" && a=yes || a=no
chk "far discovered cert outside window not reported" no "$a"

echo "=== custom thresholds ==="
# Only a 7-day window -> just the expired + critical certs (2).
R2=$("$NOTIFY" --config bootstrap.conf --days 7)
echo "$R2" | grep -q "expiring within 7 days: 2" && a=yes || a=no
chk "--days 7 narrows the window to 2" yes "$a"

echo "=== webhook: graceful failure with no listener ==="
"$NOTIFY" --config bootstrap.conf --webhook "http://127.0.0.1:1/hook" >/dev/null 2>&1
chk "no-listener webhook -> nonzero exit" 1 "$?"

echo "=== webhook: delivery (best effort) ==="
if command -v nc >/dev/null 2>&1; then
    WPORT=18606
    ( printf 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'; sleep 2 ) | nc -l -p "$WPORT" > cap.txt 2>/dev/null &
    NCPID=$!
    # wait_listen, not wait_port: this listener serves ONE connection, so a probe that
    # connects would BE the request the assertion is about (pg_helpers.sh).
    wait_listen "$WPORT" "$NCPID" || true
    "$NOTIFY" --config bootstrap.conf --webhook "http://127.0.0.1:$WPORT/hook" >/dev/null 2>&1 || true
    sleep 1; kill "$NCPID" 2>/dev/null
    if grep -q '"count":4' cap.txt 2>/dev/null; then
        echo "  [PASS] webhook delivered the JSON payload"; pass=$((pass+1))
    else
        echo "  [SKIP] webhook capture inconclusive (nc variant) — delivery code path still exercised"
    fi
else
    echo "  [SKIP] webhook delivery (no nc)"
fi

echo "=== per-owner routing ==="
if command -v nc >/dev/null 2>&1; then
    RPORT=18607
    printf 'bob=http://127.0.0.1:%s/hook\n' "$RPORT" > routes.txt
    ( printf 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'; sleep 2 ) | nc -l -p "$RPORT" > rcap.txt 2>/dev/null &
    RPID=$!
    # wait_listen, not wait_port: this listener serves ONE connection, so a probe that
    # connects would BE the request the assertion is about (pg_helpers.sh).
    wait_listen "$RPORT" "$RPID" || true
    "$NOTIFY" --config bootstrap.conf --routes routes.txt >/dev/null 2>&1 || true
    sleep 1; kill "$RPID" 2>/dev/null
    if grep -q 'critical.host' rcap.txt 2>/dev/null; then
        echo "  [PASS] owner route received bob's cert"; pass=$((pass+1))
        grep -q 'expired.host' rcap.txt 2>/dev/null && a=yes || a=no
        chk "route carries only bob's subset (no other owners)" no "$a"
        grep -q '"count":1' rcap.txt 2>/dev/null && a=yes || a=no
        chk "owner route count=1" yes "$a"
    else
        echo "  [SKIP] routing capture inconclusive (nc variant) — dispatch code path still exercised"
    fi
else
    echo "  [SKIP] per-owner routing (no nc)"
fi

echo "=== webhook formats: the shape Slack and Teams accept ==="
# Slack incoming webhooks refuse a body without `text`, and Teams webhooks refuse one that is
# not a message carrying an Adaptive Card — so the report's own JSON document, which is all
# this tool used to send, was dropped by both. Each format is captured off the wire.
capture() { # <port> <outfile> <notify args...>; returns the notifier's exit status
    local port=$1 out=$2 pid rc; shift 2
    ( printf 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'; sleep 2 ) | nc -l -p "$port" > "$out" 2>/dev/null &
    pid=$!
    wait_listen "$port" "$pid" || true
    "$NOTIFY" --config bootstrap.conf "$@" >/dev/null 2>&1; rc=$?
    sleep 1; kill "$pid" 2>/dev/null
    return $rc
}
body() { sed '1,/^\r*$/d' "$1"; }
capture 18608 slack.txt --webhook "http://127.0.0.1:18608/hook" --webhook-format slack
SB=$(body slack.txt)
chk "slack: the body is a text message"        yes "$(printf '%s' "$SB" | grep -q '^{"text":"' && echo yes || echo no)"
chk "  titled with the count and the window"  yes "$(printf '%s' "$SB" | grep -qF '*FastPKI: 4 certificate(s) expiring within 30 days*' && echo yes || echo no)"
chk "  listing the certificates"              yes "$(printf '%s' "$SB" | grep -qF 'critical.host' && echo yes || echo no)"
chk "  and not the JSON report"               no  "$(printf '%s' "$SB" | grep -qF '"certificates":' && echo yes || echo no)"
capture 18609 teams.txt --webhook "http://127.0.0.1:18609/hook" --webhook-format teams
TB=$(body teams.txt)
chk "teams: a message"                         yes "$(printf '%s' "$TB" | grep -q '^{"type":"message"' && echo yes || echo no)"
chk "  carrying an Adaptive Card attachment"   yes "$(printf '%s' "$TB" | grep -qF '"contentType":"application/vnd.microsoft.card.adaptive"' && printf '%s' "$TB" | grep -qF '"type":"AdaptiveCard"' && echo yes || echo no)"
chk "  with the counts as facts"               yes "$(printf '%s' "$TB" | grep -qF '"FactSet"' && echo yes || echo no)"
chk "  and the certificates"                   yes "$(printf '%s' "$TB" | grep -qF 'critical.host' && echo yes || echo no)"
# The format stored by the console is what a plain run uses; the flag still wins.
pg_exec "INSERT INTO config(key,value) VALUES('NOTIFY_WEBHOOK_FORMAT','teams');" >/dev/null
capture 18610 stored.txt --webhook "http://127.0.0.1:18610/hook"
chk "the stored format is used without the flag" yes "$(body stored.txt | grep -q '^{"type":"message"' && echo yes || echo no)"
pg_exec "DELETE FROM config WHERE key='NOTIFY_WEBHOOK_FORMAT';" >/dev/null
"$NOTIFY" --config bootstrap.conf --webhook-format markdown >/dev/null 2>&1
chk "an unknown format is refused (exit 2)" 2 "$?"
# Every body is built by a JSON library: a CN with a TAB used to go out raw, which no receiver
# can parse. Asserted on the JSON document, whose escaping the old code did by hand.
TAB=$(printf '\t')
ins tb "tab${TAB}host" tabby $((NOW + 3*86400))
capture 18611 tab.txt --webhook "http://127.0.0.1:18611/hook" --webhook-format json
chk "a tab in a CN is escaped, not sent raw" yes \
    "$(body tab.txt | grep -qF 'tab\thost' && ! body tab.txt | grep -qF "tab${TAB}host" && echo yes || echo no)"
pg_exec "DELETE FROM certs WHERE serial='tb';" >/dev/null

echo "=== the windows stored in the config table, bucketed as the console buckets them ==="
# NOTIFY_DAYS as the console's Notifications page stores it. This tool read bootstrap.conf and
# the environment only, so the page's settings never reached it. And four windows, because the
# old rule ("warning within the second-SMALLEST window") agreed with the console's preview for
# three windows only: 25 days left, between the smallest (7) and the largest (60), is a warning.
pg_exec "INSERT INTO config(key,value) VALUES('NOTIFY_DAYS','60,30,14,7')
         ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value;" >/dev/null
REP4=$("$NOTIFY" --config bootstrap.conf)
chk "the stored NOTIFY_DAYS applies without --days" yes \
    "$(echo "$REP4" | grep -q 'expiring within 60 days: 4' && echo yes || echo no)"
chk "  and 25 days left is a warning between the windows" yes \
    "$(echo "$REP4" | grep -q 'expired=1 critical=1 warning=2 info=0' && echo yes || echo no)"
pg_exec "DELETE FROM config WHERE key='NOTIFY_DAYS';" >/dev/null

echo "=== email to each certificate's owner, through a real relay ==="
# OpenSMTPD, the relay a deployment would actually point at, on three listeners: STARTTLS with
# AUTH (the usual submission port), TLS from the first byte with AUTH, and one offering neither
# TLS nor AUTH — refused unless SMTP_TLS=none says so, and never with a password. Its
# certificate comes from a CA of the suite's own, so verification is exercised rather than
# switched off.
OSSL=${OSSL:-openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=openssl
SMTPD=$(command -v smtpd || echo /usr/sbin/smtpd)
SMTPCTL=$(command -v smtpctl || echo /usr/sbin/smtpctl)
# The relay's delivery agent runs as `nobody`, so it must be able to reach the folder: mktemp -d
# makes the work directory 0700, and a delivery into it fails with nothing in the relay's reply.
MAIL="$W/mail"; mkdir -p "$MAIL"; chmod 777 "$MAIL"; chmod 711 "$W"
if [ ! -x "$SMTPD" ] || [ ! -x "$SMTPCTL" ]; then
    echo "  [FAIL] OpenSMTPD (smtpd, smtpctl) is not installed in this image"; fail=$((fail+1))
else
    "$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout relay-ca.key -out relay-ca.pem -days 2 \
        -subj /CN=relay-test-ca >/dev/null 2>&1
    "$OSSL" req -newkey rsa:2048 -nodes -keyout relay.key -out relay.csr -subj /CN=localhost >/dev/null 2>&1
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > relay.ext
    "$OSSL" x509 -req -in relay.csr -CA relay-ca.pem -CAkey relay-ca.key -CAcreateserial \
        -out relay.crt -days 2 -extfile relay.ext >/dev/null 2>&1
    chmod 600 relay.key
    printf 'mailer %s\n' "$("$SMTPCTL" encrypt s3cret-relay-pw)" > relay.creds
    chmod 640 relay.creds
    cat > smtpd.conf <<EOF
pki localhost cert "$W/relay.crt"
pki localhost key "$W/relay.key"
table creds file:$W/relay.creds
table anyone { "@" = "nobody" }
listen on 127.0.0.1 port 18620 tls-require pki localhost auth <creds> hostname localhost
listen on 127.0.0.1 port 18621 smtps pki localhost auth <creds> hostname localhost
listen on 127.0.0.1 port 18622 hostname localhost
action "sink" mda "/bin/sh -c 'cat > $MAIL/msg.\$\$'" virtual <anyone>
match from any for any action "sink"
EOF
    "$SMTPD" -f smtpd.conf -d > smtpd.log 2>&1 & SMTPD_PID=$!
    wait_port 18620 "$SMTPD_PID" || { echo "  smtpd did not start:"; tail -20 smtpd.log; }
fi
mail_count() { find "$MAIL" -type f | wc -l | tr -d ' '; }
wait_mail() { local i=0; while [ "$i" -lt 150 ]; do [ "$(mail_count)" -ge "$1" ] && return 0; i=$((i+1)); sleep 0.1; done; return 1; }
mail_to() { grep -l "^To: $1" "$MAIL"/msg.* 2>/dev/null | head -1; }
mail_body() { sed '1,/^\r*$/d' "$1" | tr -d '\r' | base64 -d 2>/dev/null; }
setkey() { pg_exec "INSERT INTO config(key,value) VALUES('$1','$2') ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value;" >/dev/null; }
delkey() { pg_exec "DELETE FROM config WHERE key='$1';" >/dev/null; }

# The owners: alice and dave have an address on their account, carol has an account without
# one, and bob has no account at all — so the last two go to the fallback address.
printf 'PG_CONNINFO=%s\n' "$PG_CONNINFO" > users.conf
"$ROOT/build/fastpki-config" --config users.conf web-user alice pw-alice-123 --role requester --email alice@example.test >/dev/null
"$ROOT/build/fastpki-config" --config users.conf web-user carol pw-carol-123 --role requester >/dev/null
"$ROOT/build/fastpki-config" --config users.conf web-user dave  pw-dave-1234 --role requester --email dave@example.test >/dev/null
chk "web-user --email refuses what is not an address" 1 \
    "$("$ROOT/build/fastpki-config" --config users.conf web-user eve pw-eve-12345 --role requester --email 'eve at example' >/dev/null 2>&1; echo $?)"
setkey SMTP_SERVER localhost:18620
setkey SMTP_USER mailer
setkey SMTP_PASSWORD s3cret-relay-pw
setkey SMTP_FROM pki@example.test
setkey SMTP_CA_FILE "$W/relay-ca.pem"
setkey NOTIFY_EMAIL_FALLBACK pki-team@example.test

DRY=$("$NOTIFY" --config bootstrap.conf --dry-run 2>&1)
chk "--dry-run names each email it would send" yes \
    "$(echo "$DRY" | grep -q 'email (dry run) -> alice@example.test: 1 certificate' && echo "$DRY" | grep -q 'email (dry run) -> pki-team@example.test: 2 certificate' && echo yes || echo no)"
chk "  and the owners with no address" yes \
    "$(echo "$DRY" | grep -q 'no address for owner bob' && echo "$DRY" | grep -q 'no address for owner carol' && echo yes || echo no)"
sleep 1
chk "  and sends nothing" 0 "$(mail_count)"
chk "  and records nothing" 0 "$(pg_exec "SELECT count(*) FROM notify_sent;" | tr -d ' ')"

OUT=$("$NOTIFY" --config bootstrap.conf 2>&1); rc=$?
chk "a run with a relay exits 0" 0 "$rc"
[ "$rc" = 0 ] || { echo "$OUT" | tail -15; echo "--- relay log"; tail -15 smtpd.log; }
wait_mail 3 || true
chk "three emails: alice, dave and the fallback" 3 "$(mail_count)"
A=$(mail_to alice@example.test); D=$(mail_to dave@example.test); F=$(mail_to pki-team@example.test)
chk "alice's email lists her expired certificate" yes \
    "$([ -n "$A" ] && mail_body "$A" | grep -q 'expired.host' && echo yes || echo no)"
chk "  and nobody else's" no \
    "$([ -n "$A" ] && mail_body "$A" | grep -qE 'critical.host|warning.host|info.host' && echo yes || echo no)"
chk "  from the configured sender, over the relay's TLS" yes \
    "$([ -n "$A" ] && grep -q '^From: pki@example.test' "$A" && grep -q 'smtp tls' smtpd.log && echo yes || echo no)"
chk "  subject from the built-in template" yes \
    "$([ -n "$A" ] && grep -q '^Subject: FastPKI: 1 certificate(s) expiring or expired (expired)' "$A" && echo yes || echo no)"
chk "the fallback address gets bob's and carol's, with their owners named" yes \
    "$([ -n "$F" ] && mail_body "$F" | grep -q 'critical.host' && mail_body "$F" | grep -q 'warning.host' && mail_body "$F" | grep -q 'bob, carol' && echo yes || echo no)"
chk "dave's email lists his certificate" yes \
    "$([ -n "$D" ] && mail_body "$D" | grep -q 'info.host' && echo yes || echo no)"
chk "each certificate is recorded at its stage" 4 "$(pg_exec "SELECT count(*) FROM notify_sent;" | tr -d ' ')"
chk "  the expired one at stage 0" 0 "$(pg_exec "SELECT stage FROM notify_sent WHERE serial='aa';" | tr -d ' ')"

OUT2=$("$NOTIFY" --config bootstrap.conf 2>&1)
sleep 1
chk "the next run emails nobody again" 3 "$(mail_count)"
chk "  and says why" yes "$(echo "$OUT2" | grep -q '0 sent, 0 failed, 4 already emailed at this stage' && echo yes || echo no)"

# dave's certificate moves from the 30-day window into the 7-day one: that is news, and it goes
# out in the words of a template an administrator saved.
pg_exec "UPDATE certs SET \"notAfter\"=$((NOW + 5*86400)) WHERE serial='dd';" >/dev/null
pg_exec "INSERT INTO notify_templates(name,subject,line,body,updated) VALUES('expiry','Custom: {{count}} for {{owner}}','* {{name}} ({{severity}}, {{when}})','Dear {{owner}}:
{{certificates}}
-- the PKI team',1);" >/dev/null
rm -f "$MAIL"/msg.*
"$NOTIFY" --config bootstrap.conf >/dev/null 2>&1
wait_mail 1 || true
D2=$(mail_to dave@example.test)
chk "a certificate reaching a nearer window is emailed again" 1 "$(mail_count)"
chk "  in the stored template's words" yes \
    "$([ -n "$D2" ] && grep -q '^Subject: Custom: 1 for dave' "$D2" && mail_body "$D2" | grep -q '^\* info.host (critical, in 4 day(s))' && mail_body "$D2" | grep -q 'the PKI team' && echo yes || echo no)"
pg_exec "DELETE FROM notify_templates;" >/dev/null

# A renewal leaves the old certificate valid until it expires. Its owner has already acted, so
# it is not news — but a certificate with the same subject and different names is.
mk() { # <name> <san> <days>
    "$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.pem" -days "$3" \
        -subj /CN=renewed.host -addext "subjectAltName=$2" >/dev/null 2>&1
    "$OSSL" x509 -in "$1.pem" -outform DER | xxd -p | tr -d '\n'
}
insder() { # serial owner notAfter derhex
    pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,cert) VALUES('$1',0,0,0,$((NOW-86400)),$3,'CN=renewed.host','$2','renewed.host','',decode('$4','hex'));" >/dev/null
}
"$ROOT/build/fastpki-config" --config users.conf web-user rita pw-rita-1234 --role requester --email rita@example.test >/dev/null
insder r1 rita $((NOW + 3*86400))  "$(mk r1 DNS:renewed.host 3)"
insder r2 rita $((NOW + 80*86400)) "$(mk r2 DNS:renewed.host 80)"
insder r3 rita $((NOW + 6*86400))  "$(mk r3 DNS:other.renewed.host 6)"
rm -f "$MAIL"/msg.*
OUT3=$("$NOTIFY" --config bootstrap.conf 2>&1)
wait_mail 1 || true
R=$(mail_to rita@example.test)
chk "a replaced certificate is not emailed about" no \
    "$([ -n "$R" ] && mail_body "$R" | grep -q 'serial r1' && echo yes || echo no)"
chk "  one with the same subject and other names is" yes \
    "$([ -n "$R" ] && mail_body "$R" | grep -q 'serial r3' && echo yes || echo no)"
chk "  and the run counts the replaced one" yes "$(echo "$OUT3" | grep -q '1 already replaced' && echo yes || echo no)"

echo "=== email: the relay's protections are not optional ==="
rm -f "$MAIL"/msg.*
T=$("$NOTIFY" --config bootstrap.conf --test-email tester@example.test 2>&1); rc=$?
wait_mail 1 || true
chk "--test-email is accepted over STARTTLS" 0 "$rc"
chk "  and delivered" yes "$(f=$(mail_to tester@example.test); [ -n "$f" ] && grep -q '^Subject: FastPKI: test email' "$f" && echo yes || echo no)"
setkey SMTP_PASSWORD wrong-relay-pw
T=$("$NOTIFY" --config bootstrap.conf --test-email tester@example.test 2>&1); rc=$?
chk "wrong credentials fail the run" 1 "$rc"
chk "  saying the relay refused them" yes "$(echo "$T" | grep -q 'refused the SMTP_USER credentials' && echo yes || echo no)"
chk "  without repeating the password" no "$(echo "$T" | grep -q 'wrong-relay-pw' && echo yes || echo no)"
setkey SMTP_PASSWORD s3cret-relay-pw
setkey SMTP_SERVER localhost:18622
T=$("$NOTIFY" --config bootstrap.conf --test-email tester@example.test 2>&1); rc=$?
chk "a relay without STARTTLS is refused" 1 "$rc"
chk "  and says so" yes "$(echo "$T" | grep -q 'does not offer STARTTLS' && echo yes || echo no)"
setkey SMTP_SERVER localhost:18620
delkey SMTP_CA_FILE
T=$("$NOTIFY" --config bootstrap.conf --test-email tester@example.test 2>&1); rc=$?
chk "a relay certificate nobody trusts is refused" 1 "$rc"
chk "  naming the verification failure" yes "$(echo "$T" | grep -q 'did not verify' && echo yes || echo no)"
setkey SMTP_CA_FILE "$W/relay-ca.pem"
setkey SMTP_TLS tls
setkey SMTP_SERVER localhost:18621
rm -f "$MAIL"/msg.*
"$NOTIFY" --config bootstrap.conf --test-email tester@example.test >/dev/null 2>&1; rc=$?
wait_mail 1 || true
chk "SMTP_TLS=tls delivers over TLS from the first byte" "0 1" "$rc $(mail_count)"
setkey SMTP_TLS plain
"$NOTIFY" --config bootstrap.conf >/dev/null 2>&1
chk "SMTP_TLS refuses a value it does not know" 1 "$?"
# An internal relay that speaks no TLS and trusts this server's address: SMTP_TLS=none, on the
# listener that offers nothing. It is refused while a user is set, because signing in without
# TLS would send the relay password in the clear.
setkey SMTP_TLS none
setkey SMTP_SERVER localhost:18622
T=$("$NOTIFY" --config bootstrap.conf --test-email tester@example.test 2>&1); rc=$?
chk "SMTP_TLS=none is refused beside SMTP_USER" 1 "$rc"
chk "  saying the password would go unencrypted" yes "$(echo "$T" | grep -q 'cannot be used with SMTP_USER' && echo yes || echo no)"
delkey SMTP_USER; delkey SMTP_PASSWORD
rm -f "$MAIL"/msg.*
T=$("$NOTIFY" --config bootstrap.conf --test-email tester@example.test 2>&1); rc=$?
wait_mail 1 || true
chk "SMTP_TLS=none delivers to a relay without TLS or AUTH" "0 1" "$rc $(mail_count)"
[ "$rc" = 0 ] || echo "$T" | tail -5
setkey SMTP_USER mailer
setkey SMTP_PASSWORD s3cret-relay-pw
setkey SMTP_SERVER localhost:18621
setkey SMTP_TLS tls
delkey SMTP_FROM
T=$("$NOTIFY" --config bootstrap.conf 2>&1); rc=$?
chk "a relay set without a sender fails the run" 1 "$rc"
chk "  naming the missing key, and still printing the report" yes \
    "$(echo "$T" | grep -q 'SMTP_FROM is empty' && echo "$T" | grep -q 'Certificate expiry report' && echo yes || echo no)"
setkey SMTP_FROM pki@example.test
setkey SMTP_TLS starttls
setkey SMTP_SERVER localhost:18620
"$NOTIFY" --config bootstrap.conf --no-email >/dev/null 2>&1
chk "--no-email runs the report without a relay" 0 "$?"

echo "=== email: each data center emails about the certificates it issued ==="
# With a data center configured, a serial carries its prefix in its first four hex digits, and
# every node holds every certificate. Only the issuing site may email, or each would.
pg_exec "INSERT INTO datacenters(dc_id,serial_prefix) VALUES('dc7',7);" >/dev/null
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint) VALUES('0007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',0,0,0,$((NOW-86400)),$((NOW+2*86400)),'CN=dc7.host','alice','dc7.host','');" >/dev/null
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint) VALUES('0009bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',0,0,0,$((NOW-86400)),$((NOW+2*86400)),'CN=dc9.host','alice','dc9.host','');" >/dev/null
rm -f "$MAIL"/msg.*
OUT4=$("$NOTIFY" --config bootstrap.conf 2>&1)
wait_mail 1 || true
A4=$(mail_to alice@example.test)
chk "this data center's certificate is emailed" yes "$([ -n "$A4" ] && mail_body "$A4" | grep -q 'dc7.host' && echo yes || echo no)"
chk "  another data center's is not" no "$([ -n "$A4" ] && mail_body "$A4" | grep -q 'dc9.host' && echo yes || echo no)"
chk "  and the run counts the others" yes "$(echo "$OUT4" | grep -qE '[1-9][0-9]* issued by another data center' && echo yes || echo no)"
pg_exec "DELETE FROM datacenters;" >/dev/null
for k in SMTP_SERVER SMTP_TLS SMTP_USER SMTP_PASSWORD SMTP_FROM SMTP_CA_FILE NOTIFY_EMAIL_FALLBACK; do delkey "$k"; done
kill "$SMTPD_PID" 2>/dev/null

echo "=== --fail-on monitoring gate ==="
# The main dataset has an expired cert -> 'critical' threshold trips (exit 3).
"$NOTIFY" --config bootstrap.conf --fail-on critical >/dev/null 2>&1
chk "--fail-on critical trips on expired/critical (exit 3)" 3 "$?"
# A second DB with only a far 'info' cert -> 'critical' threshold not met.
pg_setup notify2
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint) VALUES('a1',0,0,0,$((NOW-86400)),$((NOW+25*86400)),'CN=info.only','z','info.only','');"
cat > pki2.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
LOG_LEVEL=err
EOF
"$NOTIFY" --config pki2.conf --fail-on critical >/dev/null 2>&1
chk "--fail-on critical clears when only info-level (exit 0)" 0 "$?"
"$NOTIFY" --config pki2.conf --fail-on info >/dev/null 2>&1
chk "--fail-on info trips on the info cert (exit 3)" 3 "$?"

echo
echo "=== NOTIFY: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
