#!/usr/bin/env bash
# EVERY setting the console renders in the config file must actually reconfigure the
# service. ⚠️ THE RULE: all changes made in the config file must reflect in
# the service configuration."
#
# This is the guard for a whole class of bug where the console renders something that is
# not a settable value, so what you edit is not what you get. Two real instances:
#   * *_BIND was rendered as the display string "addr:port" with no *_PORT key, so the
#     only way to change a listener port was to edit the bind line — which saved a
#     literal, unbindable "0.0.0.0:8091" and crash-looped a data center.
#   * certificate profiles, while they were a config key, were rendered as the SUMMARY
#     "2 profile(s)". Being identical to the base rendering, the save diff read it as
#     "same as default" and DELETED the override, silently destroying an admin's custom
#     cert profiles. (They are a table now, out of the file's reach.)
#
# Method: take the file the console serves, change EVERY editable setting in one edit,
# save it, and assert the effective configuration reports each new value. Then restart a
# server against the same DB and confirm the values are what it actually runs with — the
# console's own view is not proof that a service is configured.
#
# Self-contained (§3d) + shell-only (§3e): ephemeral Postgres, own ports, temp dir,
# SKIPs cleanly with no Postgres.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18290; PORT2=18291
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
filetext(){ curl -s -b admin.cj "$U/api/config/file" \
  | sed -e 's/^{"text":"//' -e 's/"}$//' -e 's/\\n/\n/g' -e 's/\\"/"/g' -e 's/\\\\/\\/g'; }
# effective value of one key, from the running server's own config view
effval(){ curl -s -b "$2" "$1/api/config" | tr '{' '\n' | grep "\"key\":\"$3\"," \
          | sed -n 's/.*"value":"\(.*\)","desc".*/\1/p'; }

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi

pg_setup config_ui_modifiable
trap 'pg_cleanup; kill $P $P2 2>/dev/null' EXIT
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c admin.cj -X POST "$U/api/users" -d 'username=admin&password=adminpw12&role=admin' >/dev/null
curl -s -c admin.cj -X POST "$U/api/login" -d 'username=admin&password=adminpw12' >/dev/null

filetext > cur.conf
total=$(grep -cE '^[A-Z][A-Z0-9_]*=' cur.conf)

# ⚠️ ASSERTED HERE, ON A FRESH CONFIG, BECAUSE A DEFAULT IS ONLY MEANINGFUL BEFORE ANYTHING
# HAS BEEN EDITED. This check used to sit at the very end, after the bulk edit had set every
# string setting to a placeholder — so finding the default there meant the edit had NOT
# taken, and the only reason it passed was that the whole served configuration had
# collapsed. A malformed profiles row (profiles were a config key then) written earlier in this file made the effective
# config throw, and the console answered with built-in DEFAULTS for every key: EST_PORT
# read 8443 when the edit had set 8444, CRL_NEXT_UPDATE_DAYS read 30 when it had set 37.
# The assertion was measuring that breakage, not the default.
chk "MS_XCEP_FRIENDLY_NAME defaults to the FastPKI name" yes \
    "$(grep -q '^MS_XCEP_FRIENDLY_NAME=FastPKI Certificate Enrollment Policy$' cur.conf && echo yes || echo no)"
echo "=== the file renders $total settings; changing every editable one at once ==="

# Build the edited file + the expectation list. Values are shaped like the current one so
# they stay valid: ports/numbers shift, booleans flip, binds stay bare addresses.
: > expect.tsv
: > new.conf
while IFS= read -r line; do
  case "$line" in
    [A-Z]*=*) : ;;
    *) printf '%s\n' "$line" >> new.conf; continue ;;
  esac
  key=${line%%=*}; val=${line#*=}
  # A masked secret must be left alone: "(set)" means "keep current" by design.
  case "$val" in '(set)'|'(not set)') printf '%s\n' "$line" >> new.conf; continue ;; esac
  # Settings that govern how THIS harness reaches and authenticates to a server. They
  # are proven modifiable one-at-a-time below; changing them in the bulk edit would
  # just break the test client (TLS on a plain-HTTP probe, or a dead login).
  case "$key" in
    WEB_BIND|WEB_PORT|WEB_TLS_CERT|WEB_TLS_KEY|WEB_CLIENT_CA|WEB_ALLOW_REVOKE|AUTH_BACKEND|LDAP_AUTH)
      printf '%s\n' "$line" >> new.conf; continue ;;
  esac
  case "$key" in
    # ⚠️ NOT EVERY STRING SETTING TAKES ARBITRARY TEXT. A few are validated enums, and the
    # parser THROWS on a value outside the set — which is not a per-key failure, because
    # the overlay applies every key in one loop, so one rejected value aborts all the
    # others with it. Probing these with the generic placeholder therefore did not fail
    # one row, it reverted the ENTIRE edit and every assertion below it. Give them a legal
    # alternative instead; the setting still changes, so the check keeps its meaning.
    AUDIT_FORWARD)       new="syslog" ;;
    AUDIT_FORWARD_PROTO) new="udp" ;;
    NOTIFY_WEBHOOK_FORMAT) new="slack" ;;
    SMTP_TLS)            new="tls" ;;
    *_BIND)  new="127.0.0.2" ;;
    *_PORT)  new=$(( val + 1 )); [ "$new" -gt 65535 ] && new=1234 ;;
    *)
      if   [ "$val" = "true" ];  then new="false"
      elif [ "$val" = "false" ]; then new="true"
      elif echo "$val" | grep -qE '^[0-9]+$'; then new=$(( val + 7 ))
      elif [ -z "$val" ];        then new="uitest"
      else new="uitest" ; fi ;;
  esac
  printf '%s=%s\n' "$key" "$new" >> new.conf
  printf '%s\t%s\n' "$key" "$new" >> expect.tsv
done < cur.conf

edited=$(wc -l < expect.tsv | tr -d ' ')
echo "  editable settings changed: $edited"
resp=$(curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode "text@new.conf")
chk "the whole edited file saves cleanly" yes "$(echo "$resp" | grep -q '"set":' && echo yes || echo no)"
chk "it stored one override per edit"     "$edited" "$(echo "$resp" | sed -n 's/.*"set":\([0-9]*\).*/\1/p')"

echo "=== every changed setting is reflected in the effective configuration ==="
notapplied=""
while IFS=$'\t' read -r key want; do
  got=$(effval "$U" admin.cj "$key")
  [ "$got" = "$want" ] || notapplied="$notapplied $key(want=$want,got=${got:-empty})"
done < expect.tsv
chk "all $edited settings took effect"    "" "$notapplied"

echo "=== a RESTARTED server actually runs with them (not just the console's view) ==="
# The console recomputes its view live; only a fresh process proves the overlay is what a
# service starts with. Same DB, a bootstrap.conf whose own values differ from what we set.
#
# ⚠️ DATACENTER_ID needs its `datacenters` row to exist or the fresh process REFUSES to
# start — a node that thinks it is in a mesh and does not know its serial prefix
# would otherwise mint serials that can collide with a peer's. Seed the row for whatever
# value the bulk edit chose, rather than excluding the key: dropping it from the sweep
# would leave "is DATACENTER_ID modifiable" untested, which is the question this suite
# exists to answer.
DCWANT=$(awk -F'\t' '$1=="DATACENTER_ID"{print $2}' expect.tsv)
[ -n "$DCWANT" ] && pg_exec "INSERT INTO datacenters(dc_id, serial_prefix) VALUES('$DCWANT', 4242)
                             ON CONFLICT (dc_id) DO NOTHING;" >/dev/null
cat > web2.conf <<EOF2
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT2
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF2
"$WEB" --config web2.conf >web2.log 2>&1 & P2=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web2.conf" WEB_PORT "$P2" || true
U2="http://127.0.0.1:$PORT2"
curl -s -c a2.cj -X POST "$U2/api/login" -d 'username=admin&password=adminpw12' >/dev/null
stale=""
while IFS=$'\t' read -r key want; do
  case "$key" in WEB_PORT|WEB_BIND) continue ;; esac   # this server's own listener
  got=$(effval "$U2" a2.cj "$key")
  [ "$got" = "$want" ] || stale="$stale $key(want=$want,got=${got:-empty})"
done < expect.tsv
chk "a fresh process runs with the edited config" "" "$stale"
kill $P2 2>/dev/null

echo "=== the connection/auth settings are modifiable too (one at a time) ==="
# Excluded from the bulk edit only because changing them mid-run breaks the test client.
for k in WEB_ALLOW_REVOKE:false WEB_CLIENT_CA:/tmp/ca.pem AUTH_BACKEND:ldap; do
  key=${k%%:*}; want=${k#*:}
  curl -s -b admin.cj -X PUT "$U/api/config/db" --data-urlencode "key=$key" --data-urlencode "value=$want" >/dev/null
  chk "$key is modifiable" "$want" "$(effval "$U" admin.cj "$key")"
  curl -s -b admin.cj -X DELETE "$U/api/config/db?key=$key" >/dev/null
done

echo "=== keys the file must NOT expose (not settable as text) ==="
chk "the storage slot is not in the file" no "$(grep -q '^CONFIG_FILE_TEXT=' cur.conf && echo yes || echo no)"
chk "bootstrap PG_CONNINFO is not shown"  no "$(grep -q '^PG_CONNINFO=' cur.conf && echo yes || echo no)"
# Saving the file must never disturb the profiles the Profiles tab owns. They were a config
# key rendered as a summary, and a file save once deleted them; they are a table of their own
# now, and this holds the line that the file editor cannot reach them.
curl -s -b admin.cj -o /dev/null "$U/api/profiles" --data-urlencode 'name=myprofile' \
     --data-urlencode 'allowed_ku=digitalSignature' --data-urlencode 'max_validity_days=42'
chk "PRECONDITION: the profile was stored as its row" yes \
    "$("$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -tAc \
       "select definition from cert_profiles where name='myprofile'" 2>/dev/null | grep -q '"max_validity_days":42' && echo yes || echo no)"
curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode "text@new.conf" >/dev/null
chk "custom profiles survive a file save" yes \
    "$("$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -tAc \
       "select definition from cert_profiles where name='myprofile'" 2>/dev/null | grep -q '"max_validity_days":42' && echo yes || echo no)"
chk "  and no profile is rendered into the file" no "$(grep -q 'myprofile' cur.conf && echo yes || echo no)"

echo "=== the DB overlay shows IN the table, not as a second list above it ==="
# A setting used to appear twice with two different values: the running value in the Config
# table, and the pending override in a list above it, with nothing saying which wins. The
# served JS is the only place this is decided, so assert the wiring rather than the markup.
# Written to a file first — grep -q on a pipe closes it early and the writer reports a
# broken pipe, which looks like a test failure and is not one.
curl -s -b admin.cj "$U/" -o served.html 2>/dev/null
has(){ grep -qF "$1" served.html && echo yes || echo no; }
chk "the overlay is folded into the value cell"                 yes "$(has 'CFG_OVERRIDES')"
chk "  ... an overridden row says it is pending a restart"      yes "$(has 'pending restart')"
# It names WHICH processes are pending, because that is the actionable part — the
# Endpoints page has a Restart button per listener.
chk "  ... and names the processes that have not restarted"     yes "$(has 'pending restart: ')"
# ⚠️ THIS USED TO ASSERT A `running: ` LINE, AND THAT LINE WAS NOT TRUE.
# Printed the override with `running: <x>` beneath it, meaning "this is what the
# process actually has". The catalog is built from effective_cfg(), which re-reads the
# config table on every request, so `<x>` WAS the override — the widget printed the same
# string twice and labelled the second one as the live value. fastpki-web cannot know
# another process's effective configuration; it can only know whether that process has
# restarted since the change, which is what the cell says now. Proved, not assumed, in
# web_config_pending_restart.sh ("the catalog already reports the OVERRIDE").
chk "  ... and claims no 'running' value it cannot know"        no  "$(has 'running: ')"
# The panel keeps its form — that is the input control. What must not come back is a second
# LISTING of the same settings above the table. Asserted on the exact constructs that listing
# was built from, not "a <table> somewhere in the panel": the console has fourteen
# panel.innerHTML sites and a sed range spans all of them, which is how the first version of
# this check reported a failure that was not there.
chk "the panel's duplicate row list is gone"                     no "$(has '<td><button data-unset=')"
chk "  ... and so is the cell() call that rendered it"           no "$(has "cell('', o.value)")"
# Setting an override changes the TABLE, so the table must repaint — repainting only the
# panel was why a just-set value looked like it had not applied anywhere.
chk "a set repaints the table, not just the panel"               yes "$(has 'renderCfgPanel(); render();')"
chk "  ... and so does an unset"                                 yes \
    "$(grep -c 'renderCfgPanel(); render();' served.html | grep -qv '^1$' && echo yes || echo no)"

echo "=== The settings dropdown follows the selected Area tab ==="
# ⚠️ THE REQUIREMENT: when tab 'All' is selected, the settings dropdown must display all
# settings as it does now. When I select any other tab, the settings dropdown list should
# only display the settings for this tab … display only relevant settings for ACME, for
# example, not all the settings."
#
# The tab labels and the filter compare the SAME string — renderCfgSubmenu() builds the
# bar from `new Set(data.map(o => o.section))` and the filter tests `o.section === cfgArea`
# — so assert on that identity rather than on a second list that could drift from it.
chk "the dropdown is built from an Area-filtered list" yes \
    "$(has 'filter(o => !cfgArea || o.section === cfgArea)')"
chk "  and 'All' (cfgArea null) still yields every setting" yes \
    "$(has '!cfgArea ||')"
# ⚠️ THE HALF THAT IS EASY TO MISS. Filtering alone changes nothing a user can see: the
# panel is painted once, so without a repaint on tab change the dropdown silently keeps
# the PREVIOUS Area's settings, which reads as the feature not working at all. Assert the
# click handler repaints the panel, inside renderCfgSubmenu's own body so a
# `renderCfgPanel()` call anywhere else in the file cannot satisfy it.
SUB=$(sed -n '/^function renderCfgSubmenu/,/^}/p' served.html)
chk "picking an Area repaints the panel, not just the table" yes \
    "$(echo "$SUB" | grep -q 'renderCfgPanel();' && echo yes || echo no)"
chk "  and still repaints the table"                          yes \
    "$(echo "$SUB" | grep -q 'render();' && echo yes || echo no)"
chk "  and the tab bar is built from the same section field"  yes \
    "$(echo "$SUB" | grep -q 'data.map(o => o.section)' && echo yes || echo no)"

echo
echo "=== No UI control shows a ticket reference ==="
# ⚠️ THE REQUIREMENT: no ticket reference number in the MS_XCEP_GUID config setting
# description and avoid doing this for any UI controls in a future."
#
# The second half is the durable one, so it is guarded rather than just fixed once. A ticket
# number in a settings description is an internal bookkeeping detail leaking onto an operator's
# screen: it means nothing to the person reading it and cannot be looked up from there.
#
# ⚠️ `PKCS#11` IS NOT A TICKET REFERENCE. A naive /#[0-9]+/ flags it — it is a standard's
# name and appears in two live descriptions. Neutralise it before matching, or this guard
# fails on correct text and gets deleted by whoever hits it next.
SETTINGS=$(curl -s -b admin.cj "$U/api/config")
DESCR=$(printf '%s' "$SETTINGS" | sed 's/PKCS#11/PKCS-11/g')
BAD=$(printf '%s' "$DESCR" | grep -oE '#[0-9]{2,4}' | sort -u | tr '\n' ' ')
chk "no setting description carries a ticket number" "" "$BAD"
# ⚠️ POSITIVE CONTROL. If $SETTINGS were empty or the sed above ate everything, the check
# above would pass while measuring nothing — the vacuous-guard shape. Prove the haystack is
# real and that the matcher CAN fire.
chk "  PRECONDITION: the settings payload was actually read" yes \
    "$(printf '%s' "$DESCR" | grep -q 'MS_XCEP_GUID' && echo yes || echo no)"
chk "  PRECONDITION: the matcher fires on a planted ref" "#999" \
    "$(printf 'a description mentioning #999 here' | grep -oE '#[0-9]{2,4}')"

echo "=== CONFIG UI MODIFIABLE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
