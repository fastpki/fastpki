#!/usr/bin/env bash
# A config row the parser cannot read must produce a VISIBLE failure, not a plausible
# wrong answer.
#
# ⚠️ ONE BAD ROW DISCARDS EVERY OVERRIDE. overlay_config applies the config table key by
# key and throws where it trips, so a single unparseable value aborts the whole overlay.
# The console used to swallow that exception and answer with built-in defaults for every
# setting, presented as the live configuration — while the listener half REFUSED TO START
# on the identical input. The two halves disagreed about whether the configuration was
# usable, and only one of them said so. That refusal is deliberate and stays; what changes
# is that the console can no longer serve defaults in silence.
#
# The bad row is written straight to the table on purpose. validate_config_value() already
# refuses one through the console, so the console is not the way in; a row that predates
# the validator, or one written by any other means, is.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18492
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
# ⚠️ NO PIPE. `echo "$page" | grep -q` makes grep exit on the first match and leaves echo
# writing into a closed pipe, so a PASSING assertion prints "write error: Broken pipe"
# beside itself — noise that reads exactly like a failure.
has(){ grep -qF -- "$2" <<<"$1" && echo yes || echo no; }
# one key's value, as the running server reports it
effval(){ curl -s -b admin.cj "$U/api/config" | tr '{' '\n' | grep "\"key\":\"$1\"," \
          | sed -n 's/.*"value":"\(.*\)","desc".*/\1/p'; }
sql(){ "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -tAc "$1"; }

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi
pg_setup config_malformed_row
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
LOG_LEVEL=info
EOF
# ⚠️ LOG_LEVEL=info, NOT err. The visibility this suite is about is a log line, and at
# LOG_LEVEL=err no suite can see a log claim at all.
"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat web.log; exit 1; }
U="http://127.0.0.1:$PORT"
curl -s -c admin.cj -X POST "$U/api/users" -d 'username=admin&password=adminpw12&role=admin' >/dev/null
curl -s -c admin.cj -X POST "$U/api/login" -d 'username=admin&password=adminpw12' >/dev/null

echo "=== 1. a healthy overlay: the override is live and the page says so ==="
curl -s -b admin.cj -X PUT "$U/api/config/db" -d 'key=CRL_NEXT_UPDATE_DAYS&value=37' >/dev/null
chk "the override is what the server reports" 37 "$(effval CRL_NEXT_UPDATE_DAYS)"
st=$(curl -s -b admin.cj "$U/api/config/status")
chk "and the configuration reports itself LIVE" yes "$(has "$st" '"live":true')"
chk "with no error to name" no "$(has "$st" '"error"')"

echo
echo "=== 2. one malformed row, written the way the validator cannot intercept ==="
sql "INSERT INTO config(key,value) VALUES ('AUDIT_FORWARD','sylsog')
     ON CONFLICT (key) DO UPDATE SET value=excluded.value" >/dev/null
# The value is legal-looking and the key is one the console never reads, which is what
# made this so quiet: nothing on the page relates to AUDIT_FORWARD.
chk "the bad row really is in the table" sylsog "$(sql "SELECT value FROM config WHERE key='AUDIT_FORWARD'")"

st=$(curl -s -b admin.cj "$U/api/config/status")
chk "the configuration now reports itself NOT live" yes "$(has "$st" '"live":false')"
# ⚠️ NAME THE KEY. "configuration failed" sends an operator to read every setting; the
# parser already knows which one, and that is the whole value of the message.
chk "and names the offending key" yes "$(has "$st" 'AUDIT_FORWARD')"
chk "and quotes the value it could not parse" yes "$(has "$st" 'sylsog')"

echo
echo "=== 3. the served values are defaults, and are no longer claimed to be live ==="
# This is the defect exactly: an override that is in the table, applied a moment earlier,
# read back as the built-in default with nothing saying so.
chk "the override has indeed been discarded (the built-in default is served)" 30 \
    "$(effval CRL_NEXT_UPDATE_DAYS)"
# ⚠️ THE PAIRING IS THE POINT. Serving 30 is tolerable; serving 30 while reporting the
# configuration as live is the bug. Judge them together so neither can pass alone.
verdict=$([ "$(effval CRL_NEXT_UPDATE_DAYS)" = 30 ] \
          && { [ "$(has "$st" '"live":false')" = yes ] && echo "default-and-declared" \
               || echo "DEFAULT-SERVED-AS-LIVE"; } || echo "override-still-applied")
chk "a default is served AND declared as such" default-and-declared "$verdict"

echo
echo "=== 4. it is visible without the console, in the log ==="
grep -q "stored configuration is NOT in use" web.log
chk "the server said so in its own log" 0 $?
chk "and the log names the key too" yes "$(has "$(cat web.log)" 'AUDIT_FORWARD')"
# A line per request would bury the deployment's own logs; the state changed once.
for _ in 1 2 3 4 5; do curl -s -b admin.cj "$U/api/config" >/dev/null; done
chk "and said it ONCE, not once per request" 1 \
    "$(grep -c 'stored configuration is NOT in use' web.log)"

echo
echo "=== 5. the console renders the banner, for every viewer ==="
page=$(curl -s -b admin.cj "$U/")
chk "the page carries the banner element" yes "$(has "$page" 'id="cfgstale"')"
chk "and asks the server whether the configuration is live" yes "$(has "$page" '/api/config/status')"
# ⚠️ `hidden` LOSES TO AN AUTHOR `display`. A rule setting display on this element would
# show the banner on a healthy config, which is worse than having no banner at all.
chk "no author display rule can defeat the hidden attribute" no \
    "$(has "$(echo "$page" | tr '}' '\n' | grep '#cfgstale{')" 'display:')"
# The message quotes the offending value back, and that value came from whoever wrote the
# row — so it must go through the escaper.
chk "the parser's message is escaped before it is rendered" yes \
    "$(has "$page" 'esc(String(st.error')"

echo
echo "=== 6. fix the row and the verdict goes back on its own ==="
sql "DELETE FROM config WHERE key='AUDIT_FORWARD'" >/dev/null
st=$(curl -s -b admin.cj "$U/api/config/status")
chk "the configuration reports itself live again" yes "$(has "$st" '"live":true')"
chk "and the override is back" 37 "$(effval CRL_NEXT_UPDATE_DAYS)"
chk "the recovery is in the log too" yes "$(has "$(cat web.log)" 'parses again')"

echo
echo "=== CONFIG MALFORMED ROW: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
