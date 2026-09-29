#!/usr/bin/env bash
# "pending restart" must be answered by the process that READS the setting.
#
# The report: once a service is restarted with new settings, the Config page still shows
# "pending restart" — seen on the CMP service after changing the settings a second time.
#
# ── THE DEFECT ──────────────────────────────────────────────────────────────────
#
# The Config page decided it with ONE number: the console's own start time.
#
#     if (e.u <= SERVER_START && e.v === running) return esc(running);
#
# `SERVER_START` is fastpki-web's start. That is the right process for WEB_PORT and the
# wrong one for every setting the console does not itself read. Change a CMP setting and
# restart CMP and the row stays "pending restart" until fastpki-web happens to restart —
# which is the report. It also fails the other way, and that direction is worse: restart
# nothing but the console and every row clears while CMP still runs the old value.
#
# Why the first change after a deployment looked fine: a fresh deployment restarts
# everything, so the console's start was newer than every override and the arithmetic
# came out right by accident.
#
# ── WHAT THIS ASSERTS ───────────────────────────────────────────────────────────
#
# Each listener now stamps <PROTO>_STARTED_AT for itself when its gate opens, and the
# catalog says which process owns each setting. Both halves are checked here against real
# processes rather than hand-written markers — a marker this suite wrote itself would
# prove only that the suite can write to a table.
#
#   1. a real fastpki-ocsp stamps OCSP_STARTED_AT when it starts;
#   2. restarting it moves the stamp past an override written in between, WHILE the
#      console's own start time is still behind that override — that combination is
#      exactly the state the old code got wrong, and this suite fails on the old binary
#      because nothing writes the stamp at all;
#   3. a listener that is switched OFF stamps nothing (it is not running, so it cannot be
#      running a stale setting);
#   4. /api/config names the owning process per setting, including the two that are easy
#      to get wrong: DATACENTER_ID is SHARED (it is the per-DC serial prefix, read
#      by every issuer) and LOG_LEVEL is shared;
#   5. the served JS decides from the owner's start marker. The shell harness cannot run
#      JS (§3e), so the browser half is a grep — weak on its own, which is why 1-3 drive
#      real processes.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"
WEB="$ROOT/build/fastpki-web"
OCSP="$ROOT/build/fastpki-ocsp"
[ -x "$WEB" ] && [ -x "$OCSP" ] || { echo "SKIP: build fastpki-web and fastpki-ocsp first"; exit 0; }
W="$(mktemp -d)"; cd "$W"; PORT=18477; OPORT=18478
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup web_config_pending_restart
source "$ROOT/tests/user_helpers.sh"
seed_web_user admin testpw admin
P=; PO=
trap 'kill ${P:-} ${PO:-} 2>/dev/null; pg_cleanup' EXIT

cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
OCSP_BIND=127.0.0.1
OCSP_PORT=$OPORT
LOG_LEVEL=err
EOF

# The console starts FIRST and is never restarted after this point. Every override below
# is therefore newer than SERVER_START — the state in which the old code says "pending"
# for everything, forever.
"$WEB" --config web.conf > web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat web.log; exit 1; }
U="http://127.0.0.1:$PORT"
curl -s -c cj.txt -X POST "$U/api/login" -d 'username=admin&password=testpw' >/dev/null
# ⚠️ /api/start-time is behind the session gate like every other /api route. Without the
# cookie it 401s and the parse yields an empty string, which every later [ -gt ] then
# reports as a product failure. (The console fetches it in init(); on the login screen
# that call really does 401, and the reload after a successful login re-runs init() with
# the cookie — which is why the page ends up with a real value.)
WEB_START=$(curl -s -b cj.txt "$U/api/start-time" | sed -nE 's/.*"time":([0-9]+).*/\1/p')
chk "the console reports its start time" yes "$([ -n "$WEB_START" ] && [ "$WEB_START" -gt 0 ] && echo yes || echo no)"

# The value of one config-table row, straight from the database. Read from the DB rather
# than the API so the assertion cannot be satisfied by the console's own bookkeeping.
cfgval(){ pg_exec "SELECT value FROM config WHERE key='$1';" | tr -d ' '; }
cfgupd(){ pg_exec "SELECT updated FROM config WHERE key='$1';" | tr -d ' '; }

echo "=== 1. a listener stamps its own start ==="
chk "no OCSP_STARTED_AT before anything runs"  "" "$(cfgval OCSP_STARTED_AT)"
BEFORE=$(date +%s)
"$OCSP" --config web.conf > ocsp1.log 2>&1 & PO=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" OCSP_PORT "$PO" || true
kill -0 $PO 2>/dev/null || { echo "fastpki-ocsp died:"; cat ocsp1.log; }
S1=$(cfgval OCSP_STARTED_AT)
chk "fastpki-ocsp stamped OCSP_STARTED_AT"     yes "$([ -n "$S1" ] && echo yes || echo no)"
chk "  and it is its OWN start, not older"     yes \
    "$([ -n "$S1" ] && [ "$S1" -ge "$BEFORE" ] && echo yes || echo no)"

echo "=== 2. the exact state the old code got wrong ==="
# Stop it, change one of ITS settings, start it again. The console has not restarted, so
# SERVER_START is still older than the change: the old rule reports "pending restart" on
# a process that is demonstrably running the new value.
kill $PO 2>/dev/null; wait $PO 2>/dev/null; PO=
sleep 1
curl -s -b cj.txt -X PUT "$U/api/config/db" -d 'key=CRL_NEXT_UPDATE_DAYS&value=9' >/dev/null
CHANGED=$(cfgupd CRL_NEXT_UPDATE_DAYS)
chk "the override records when it was written" yes \
    "$([ -n "$CHANGED" ] && [ "$CHANGED" -gt 0 ] && echo yes || echo no)"
chk "  it is NEWER than the console's start"   yes \
    "$([ "$CHANGED" -ge "$WEB_START" ] && echo yes || echo no)"
# ⚠️ WHY THE CELL NO LONGER PRINTS A "running:" LINE, PROVED RATHER THAN ASSERTED.
#
# Rendered the override over a second line reading `running: <x>`, meaning "and
# this is what the process actually has". It could never mean that. The catalog is built
# from effective_cfg(), which re-reads the config table on EVERY request — so the value it
# reports is the override itself, and the widget printed the same string twice with the
# second one labelled as the live one. The console cannot know another process's effective
# value; it can only know whether that process has restarted, which is what it says now.
CATV=$(curl -s -b cj.txt "$U/api/config" | tr '{' '\n' | grep '"key":"CRL_NEXT_UPDATE_DAYS"' \
       | sed -nE 's/.*"value":"([^"]*)".*/\1/p')
chk "the catalog already reports the OVERRIDE" 9 "$CATV"
chk "  so 'running' would have been the same string" yes \
    "$([ "$CATV" = "$(cfgval CRL_NEXT_UPDATE_DAYS)" ] && echo yes || echo no)"

sleep 1
"$OCSP" --config web.conf > ocsp2.log 2>&1 & PO=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" OCSP_PORT "$PO" || true
S2=$(cfgval OCSP_STARTED_AT)
chk "restarting the listener moves its stamp"  yes \
    "$([ -n "$S2" ] && [ -n "$S1" ] && [ "$S2" -gt "$S1" ] && echo yes || echo no)"
# THE assertion. Same two numbers the page now compares: the OWNER's start against the
# moment the override was written.
chk "the owner started AFTER the change"       yes \
    "$([ -n "$S2" ] && [ "$S2" -ge "$CHANGED" ] && echo yes || echo no)"
kill $PO 2>/dev/null; wait $PO 2>/dev/null; PO=

echo "=== 3. a switched-off listener claims nothing ==="
# It blocks before the gate opens, so it must not stamp. A marker written while blocked
# would tell the console a stale setting is live in a process that is not even listening.
pg_exec "DELETE FROM config WHERE key='OCSP_STARTED_AT';" >/dev/null
curl -s -b cj.txt -X POST "$U/api/endpoints/ocsp/enabled?enabled=false" >/dev/null
"$OCSP" --config web.conf > ocsp3.log 2>&1 & PO=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" OCSP_PORT "$PO" || true
chk "switched off -> no start marker"          "" "$(cfgval OCSP_STARTED_AT)"
# Prove it is genuinely blocked rather than merely quiet: the port must not answer.
# (The "switched off" line it logs is info-level, and this suite runs at LOG_LEVEL=err,
# so grepping the log would assert nothing here.)
chk "  and its port is not listening"          no \
    "$(curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$OPORT/" && echo yes || echo no)"
chk "  the process is still alive, just idle"  yes \
    "$(kill -0 $PO 2>/dev/null && echo yes || echo no)"
kill $PO 2>/dev/null; wait $PO 2>/dev/null; PO=
curl -s -b cj.txt -X POST "$U/api/endpoints/ocsp/enabled?enabled=true" >/dev/null

echo "=== 4. the catalog names the owning process ==="
CAT=$(curl -s -b cj.txt "$U/api/config")
# One record per line so a per-key lookup cannot accidentally match a neighbour's owner.
owner_of(){ printf '%s' "$CAT" | tr '{' '\n' | grep "\"key\":\"$1\"" \
            | sed -nE 's/.*"owner":"([^"]*)".*/\1/p'; }
chk "CMP_PATH             -> cmp"    cmp   "$(owner_of CMP_PATH)"
chk "ACME_DNS_RESOLVER    -> acme"   acme  "$(owner_of ACME_DNS_RESOLVER)"
chk "EST_PORT             -> est"    est   "$(owner_of EST_PORT)"
chk "SCEP_BIND            -> scep"   scep  "$(owner_of SCEP_BIND)"
chk "MS_PORT              -> ms"     ms    "$(owner_of MS_PORT)"
chk "OCSP_BIND            -> ocsp"   ocsp  "$(owner_of OCSP_BIND)"
chk "WEB_ALLOW_REVOKE     -> web"    web   "$(owner_of WEB_ALLOW_REVOKE)"
# ⚠️ The two that are easy to get wrong. DATACENTER_ID reads like console metadata and is
# actually the per-DC serial prefix that every issuing binary applies — calling it
# console-owned would report the change live while six issuers still minted the old
# prefix. LOG_LEVEL is the obvious shared one and is here so the empty string is proved to
# be a real answer rather than a key the catalog simply forgot.
# ⚠️ These two were asserted as ocsp/scep-owned in the first version of this suite, and
# BOTH claims were wrong — which means my own assertions blessed the defect rather than
# catching it. CRL_NEXT_UPDATE_DAYS is read through src/lib/crl.cpp and SCEP_PATH by
# fastpki-ocsp as well, so restarting one service would have cleared a row that other
# processes were still stale on. They are pinned here as SHARED so the correction cannot
# quietly revert; 4b below is what derives the answer instead of asserting it.
chk "CRL_NEXT_UPDATE_DAYS -> shared" ""    "$(owner_of CRL_NEXT_UPDATE_DAYS)"
chk "SCEP_PATH            -> shared" ""    "$(owner_of SCEP_PATH)"
chk "OCSP_PORT            -> shared" ""    "$(owner_of OCSP_PORT)"
chk "DATACENTER_ID        -> shared" ""    "$(owner_of DATACENTER_ID)"
chk "LOG_LEVEL            -> shared" ""    "$(owner_of LOG_LEVEL)"
# The audit shipper is a separate process, not a listener, and it is the ONLY reader of
# these keys. Its section is Logging, whose default is shared — and shared is wrong in the
# dangerous direction here: it clears the pending mark once the eight LISTENERS have
# restarted, while the shipper may still be running the previous collector address. So the
# owner is pinned, and pinned against "" specifically, because "" is what the section
# would answer if this override were ever removed.
for k in AUDIT_FORWARD AUDIT_FORWARD_TARGET AUDIT_FORWARD_PROTO AUDIT_FORWARD_TLS \
         AUDIT_FORWARD_TOKEN AUDIT_FORWARD_CA_ID AUDIT_FORWARD_INTERVAL_SEC AUDIT_FORWARD_BATCH; do
  chk "$k -> auditfwd" auditfwd "$(owner_of "$k")"
done

# The settings must be ON the Config page at all: they were parsed and applied from the
# `config` table from the start, but the console never listed them, so the only practical
# way to set them was a file on each node — which is the complaint. Assert the section as
# well as the presence, because a key in the catalog under the wrong heading is not
# findable.
sec_of(){ printf '%s' "$CAT" | tr '{' '\n' | grep "\"key\":\"$1\"" \
          | sed -nE 's/.*"section":"([^"]*)".*/\1/p'; }
chk "AUDIT_FORWARD is under Logging"        Logging "$(sec_of AUDIT_FORWARD)"
chk "AUDIT_FORWARD_TARGET is under Logging" Logging "$(sec_of AUDIT_FORWARD_TARGET)"

# ⚠️ The collector token is a credential. The catalog masks any key whose NAME contains
# TOKEN, so this passes for free — which is exactly why it is asserted: the value must
# never be the thing on the wire, and a future rename that drops the word would silently
# start publishing it.
curl -s -b cj.txt -X PUT "$U/api/config/db" -d 'key=AUDIT_FORWARD_TOKEN&value=s3cr3t-hec-value' >/dev/null
CAT=$(curl -s -b cj.txt "$U/api/config")
val_of(){ printf '%s' "$CAT" | tr '{' '\n' | grep "\"key\":\"$1\"" \
          | sed -nE 's/.*"value":"([^"]*)".*/\1/p'; }
chk "the collector token is masked"      "(set)" "$(val_of AUDIT_FORWARD_TOKEN)"
chk "and its value never reaches the API" no \
    "$(printf '%s' "$CAT" | grep -q 's3cr3t-hec-value' && echo yes || echo no)"

# The other half of the complaint: a value written through the console reaches the
# effective configuration, so a collector is repointed by editing a row and not a file.
curl -s -b cj.txt -X PUT "$U/api/config/db" -d 'key=AUDIT_FORWARD_TARGET&value=collector.example:6514' >/dev/null
CAT=$(curl -s -b cj.txt "$U/api/config")
chk "a target set from the console is effective" "collector.example:6514" "$(val_of AUDIT_FORWARD_TARGET)"

# ⚠️ A VALUE THE PARSER REFUSES MUST BE REFUSED HERE, WHERE THE OPERATOR CAN SEE IT.
# Several settings are validated enums, and the parser throws rather than falling back —
# correctly, because a deployment must not believe it forwards its audit trail while
# shipping nothing. But the overlay applies every key in ONE loop, so a throw takes the
# whole configuration with it: measured, a listener given a config table containing
# AUDIT_FORWARD='sylsog' exits with "fatal: config: AUDIT_FORWARD must be 'off', 'syslog'
# or 'hec'" and does not come up — over a key it never reads. Accepting the typo here
# would hide it until the next restart and then stop the listeners.
BADRC=$(curl -s -o badcfg.json -w '%{http_code}' -b cj.txt -X PUT "$U/api/config/db" \
        -d 'key=AUDIT_FORWARD&value=sylsog')
chk "a misspelled enum is refused at the console"  400 "$BADRC"
chk "  and the error names the allowed values"     yes \
    "$(grep -q "syslog" badcfg.json && echo yes || echo no)"
CAT=$(curl -s -b cj.txt "$U/api/config")
chk "  and nothing was stored"                     off "$(val_of AUDIT_FORWARD)"
# The same guard must not reject a LEGAL value — a validator that refuses everything
# would pass the assertion above and break the feature.
OKRC=$(curl -s -o /dev/null -w '%{http_code}' -b cj.txt -X PUT "$U/api/config/db" \
       -d 'key=AUDIT_FORWARD&value=syslog')
chk "  a legal value is still accepted"            200 "$OKRC"
chk "  ... and 'shared' is not just a missing field" yes \
    "$(printf '%s' "$CAT" | tr '{' '\n' | grep '"key":"LOG_LEVEL"' | grep -q '"owner":"' && echo yes || echo no)"

echo "=== 4b. no key CLAIMS one owner while the code reads it more widely ==="
# ⚠️ THIS IS THE ASSERTION I NEEDED AND DID NOT HAVE.
#
# The first version of section_owner() mapped whole SECTIONS, and a section groups
# settings by subject matter rather than by who reads them. Fifteen keys were wrong, all
# in the dangerous direction: the row would clear after restarting one service while five
# other processes still ran the old value. OCSP_PORT is the clearest — it lives in the
# "OCSP & CRL" section and is read by src/lib/x509.cpp, which bakes it into the AIA URL of
# every certificate ANY issuer mints.
#
# So do not check a list against a list. Derive the answer from the code the same way the
# reviewer did, and hold the API's claim to it:
#
#   key -> Config field      from apply() in src/lib/config.cpp
#   field read in src/lib/   -> shared, because pki_lib is linked into every binary
#   field read in another    -> shared
#     protocol's main.cpp
#
# fastpki-web is excluded from "another binary": the console reads every setting in order
# to DISPLAY it, which says nothing about who runs on it.
claimed_wrong=""; checked=0
for k in $(printf '%s' "$CAT" | tr '{' '\n' | sed -nE 's/.*"key":"([A-Z0-9_]+)".*/\1/p'); do
    own=$(owner_of "$k"); [ -n "$own" ] || continue      # already shared: nothing to check
    [ "$own" = web ] && continue                          # console-only, same reasoning
    fld=$(sed -nE 's/.*key *== *"'"$k"'" *\) *\{? *c\.([a-z0-9_]+).*/\1/p' "$ROOT/src/lib/config.cpp" | head -1)
    [ -n "$fld" ] || continue
    checked=$((checked+1))
    # src/lib is linked into everything, so a read there means every binary reads it.
    #
    # ⚠️ EXCEPT A READ THAT IS MAINTENANCE RATHER THAN SERVING, which the source marks. The
    # listener table in renew_service_certs_for_ca() reads EST_KEY/ACME_KEY/MS_KEY in order
    # to RE-ISSUE those certificates, and is reachable only from `fastpki-ca` and the
    # console's rekey cascade — both already excluded above. Counting it made this suite
    # demand that three correctly-owned keys be relabelled shared, which would have told an
    # operator to restart every service because the EST listener's key changed.
    #
    # The exemption is a marker at the READ, not a function name here: a name in this file
    # goes stale silently, while a new read on the serving path cannot inherit a comment it
    # was not given.
    if grep -nw "$fld" "$ROOT"/src/lib/*.cpp 2>/dev/null \
         | grep -v '/config\.cpp:' \
         | grep -qv 'pending-restart: maintenance read'; then
        claimed_wrong="$claimed_wrong $k(lib)"; continue
    fi
    for d in est acme cmp scep msxcep ocsp certstore mcp; do
        case "$d:$own" in est:est|acme:acme|cmp:cmp|scep:scep|msxcep:ms|ocsp:ocsp|certstore:store) continue;; esac
        [ -f "$ROOT/src/$d/main.cpp" ] || continue
        grep -qw "$fld" "$ROOT/src/$d/main.cpp" && { claimed_wrong="$claimed_wrong $k($d)"; break; }
    done
done
chk "every claimed owner is the only reader" "" "$claimed_wrong"
# The loop must have examined real keys. If the API stopped emitting `owner`, or apply()
# were restructured so no field could be resolved, `checked` would be 0 and the assertion
# above would pass having tested nothing.
chk "  ... and it checked a real number of keys" yes \
    "$([ "$checked" -ge 20 ] && echo yes || echo "no (only $checked)")"

echo "=== 5. the served page decides from the owner's marker ==="
curl -s -b cj.txt "$U/" > page.html
chk "the page harvests <PROTO>_STARTED_AT"     yes \
    "$(grep -q '_STARTED_AT\$/' page.html && echo yes || echo no)"
chk "  it keys the decision on the row's owner" yes \
    "$(grep -q 'pendingOn(row.key, row.owner, e.u)' page.html && echo yes || echo no)"
chk "  a shared setting waits for every listener" yes \
    "$(grep -q "ALL_LISTENERS = \['web','est','acme','cmp','scep','ms','ocsp','store'\]" page.html && echo yes || echo no)"
# The defect itself, pinned: the console's own start time must no longer be what decides
# a row. SERVER_START survives as SVC_START.web — that is the console's OWN entry and is
# correct — so match the comparison, not the name.
#
# ⚠️ NAME THE FILE. An earlier version of this line read `grep -q '…' && echo no || echo
# yes` with no file: grep then reads STDIN, finds nothing, and the assertion answers "yes"
# forever. It sailed through the run with the fix deliberately reverted — the one run
# whose entire purpose was to make it red — while its four neighbours went red correctly.
chk "  the old console-start rule is gone"     yes \
    "$(grep -q 'e.u <= SERVER_START' page.html && echo no || echo yes)"
chk "  the marker is not offered as a setting" yes \
    "$(grep -q "!/\^\[A-Z\]+_STARTED_AT\$/.test(o.key)" page.html && echo yes || echo no)"

echo "=== 6. UNSETTING an override is a pending change too ==="
# CRL_NEXT_UPDATE_DAYS is still overridden to 9 from section 2, and fastpki-ocsp restarted
# after that, so it is running 9 and shows no marker. Remove the override and the row goes
# back to the default — which no running process has yet — while the page said nothing:
# CFG_OVERRIDES is built from the rows that EXIST, so the key simply dropped out of the map
# and rendered as an ordinary, unmarked value.
#
#   set    CRL_NEXT_UPDATE_DAYS=9   -> row shows 9,  "pending restart: ocsp"   correct
#   unset  CRL_NEXT_UPDATE_DAYS     -> row shows 30, no marker                 wrong
#
# ⚠️ The listener must NOT be restarted after the unset, or there is nothing pending and
# the whole block passes against the unfixed page.
chk "the override is in force before we unset it" 9 "$(cfgval CRL_NEXT_UPDATE_DAYS)"
curl -s -b cj.txt -X DELETE "$U/api/config/db?key=CRL_NEXT_UPDATE_DAYS" >/dev/null
chk "the override row is gone"        "" "$(cfgval CRL_NEXT_UPDATE_DAYS)"
# THE FIX: a tombstone carrying the removal's own write time, because the row that used to
# carry one no longer exists.
chk "a tombstone records the removal" yes \
    "$([ -n "$(cfgval __UNSET__CRL_NEXT_UPDATE_DAYS)" ] && echo yes || echo no)"
UNSET_AT=$(cfgupd __UNSET__CRL_NEXT_UPDATE_DAYS)
chk "  and it is stamped with a time" yes \
    "$([ -n "$UNSET_AT" ] && [ "$UNSET_AT" -gt 0 ] && echo yes || echo no)"
DBJSON=$(curl -s -b cj.txt "$U/api/config/db")
chk "the API reports it against the REAL key" yes \
    "$(echo "$DBJSON" | grep -q '"key":"CRL_NEXT_UPDATE_DAYS","unset":true' && echo yes || echo no)"
# ⚠️ And NOT as a row of its own. A tombstone rendered as an ordinary entry would put a
# key nothing parses onto the Config page and read as a setting somebody could edit.
chk "  and never as a settable key"          yes \
    "$(echo "$DBJSON" | grep -q '"key":"__UNSET__' && echo no || echo yes)"
curl -s -b cj.txt "$U/" > page2.html
chk "the page marks an unset as pending"     yes \
    "$(grep -q 'pending restart (unset)' page2.html && echo yes || echo no)"
chk "  keyed on the same start markers"      yes \
    "$(grep -q 'if (e.unset)' page2.html && echo yes || echo no)"
# ⚠️ ANTI-VACUITY: setting it again must END the unset, or a set/unset/set leaves the row
# marked forever — which reads exactly like the bug this fixes.
curl -s -b cj.txt -X PUT "$U/api/config/db" -d 'key=CRL_NEXT_UPDATE_DAYS&value=7' >/dev/null
chk "setting it again clears the tombstone"  "" "$(cfgval __UNSET__CRL_NEXT_UPDATE_DAYS)"
chk "  and the override is back"             7  "$(cfgval CRL_NEXT_UPDATE_DAYS)"

[ "$fail" -eq 0 ] || { echo "--- web log:"; tail -15 web.log; echo "--- ocsp log:"; tail -15 ocsp2.log; }
echo
echo "=== CONFIG PENDING RESTART: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
