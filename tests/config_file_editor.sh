#!/usr/bin/env bash
# Full config-file editor + Restart: instead of editing the DB config
# overlay one key at a time, an admin can edit the WHOLE configuration as a single
# .conf file and Restart to apply. GET /api/config/file returns the operator's own saved
# text verbatim when there is one (comments and ordering survive, each value refreshed to
# the live one), else renders every setting as a live KEY=value line (secrets masked,
# bootstrap keys omitted); PUT /api/config/file diffs it against the bootstrap.conf base, applies
# the result to this data center's overlay and stores the text as typed; POST /api/restart
# exits so the container restarts. A bind/port typo is rejected rather than bricking the DC.
#
# This guards the real API behaviour (not just markup): the render shape, the diff
# semantics (set / unset), the secret round-trip (no clear-text leak, "(set)" is a
# no-op), input validation, and the admin-only RBAC gate. The modal was also driven
# in a real browser before deploy (§3e); this suite additionally asserts the modal
# builder is shipped in the served bytes.
#
# Self-contained (§3d): ephemeral Postgres via pg_helpers, own port, temp dir,
# SKIPs cleanly when no Postgres is reachable. Shell-only (no Python interpreter is
# required — jq-free JSON field extraction via sed/grep).
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18264
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
# Pull the "text" string field out of {"text":"..."} and unescape \n and \" so we
# can grep it line by line. Shell-only.
filetext(){ curl -s -b admin.cj "$U/api/config/file" \
  | sed -e 's/^{"text":"//' -e 's/"}$//' -e 's/\\n/\n/g' -e 's/\\"/"/g' -e 's/\\\\/\\/g'; }

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi

pg_setup config_file_editor
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
CERT_VALIDITY_DAYS=411
LOG_LEVEL=err
EOF
"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"
# Open mode (no users yet): create the admin, then log in.
curl -s -c admin.cj -X POST "$U/api/users" -d 'username=admin&password=adminpw12&role=admin' >/dev/null
curl -s -c admin.cj -X POST "$U/api/login" -d 'username=admin&password=adminpw12' >/dev/null

echo "=== GET /api/config/file renders the FULL effective config as live KEY=value lines ==="
chk "GET answers 200" 200 "$(code -b admin.cj "$U/api/config/file")"
T="$(filetext)"
chk "has the data-center-scoped header"    yes "$(echo "$T" | grep -q 'FastPKI configuration (this data center)' && echo yes || echo no)"
chk "has an Area section comment"         yes "$(echo "$T" | grep -q 'Identity' && echo yes || echo no)"
# Every setting is a LIVE (uncommented) line — reads like a real config file, not a
# mostly-commented stub. A bootstrap.conf value shows uncommented with its actual value.
chk "setting shows as a live line"        yes "$(echo "$T" | grep -q '^CERT_VALIDITY_DAYS=411' && echo yes || echo no)"
chk "no all-commented '# KEY=' refs"      no  "$(echo "$T" | grep -qE '^# [A-Z_]+=' && echo yes || echo no)"
chk "bootstrap PG_CONNINFO is omitted"    yes "$(echo "$T" | grep -q 'PG_CONNINFO' && echo no || echo yes)"
chk "bootstrap SQL_DB is omitted"         yes "$(echo "$T" | grep -q 'SQL_DB' && echo no || echo yes)"
# ⚠️ Driven with WEB_TOKEN, since SCEP_CHALLENGE is gone. The subject is the MASKING,
# not the key — but it has to be a key the parser still knows, or this asserts that an
# unknown key is absent, which every build satisfies.
chk "secret WEB_TOKEN is masked"          yes "$(echo "$T" | grep -qE '^WEB_TOKEN=\((set|not set)\)' && echo yes || echo no)"

# An override created OUTSIDE the file editor (per-key form) is annotated with the
# bootstrap.conf default it shadows. Must run BEFORE any file PUT: once the operator saves a
# file we hand back THEIR text verbatim and never re-inject generated annotations.
curl -s -b admin.cj -X PUT "$U/api/config/db" -d 'key=CERT_VALIDITY_DAYS&value=555' >/dev/null
chk "overridden key is annotated vs bootstrap.conf" yes "$(filetext | grep -q '# (overrides bootstrap.conf default: 411)' && echo yes || echo no)"
curl -s -b admin.cj -X DELETE "$U/api/config/db?key=CERT_VALIDITY_DAYS" >/dev/null

echo "=== every rendered line is a VALID config value (round-trips unchanged) ==="
# The root cause of a bricked lab DC: the catalog rendered WEB_BIND as "addr:port"
# (display-only) and emitted no WEB_PORT, so the only place to change the console port
# was the bind line — and saving that wrote a literal, unbindable "0.0.0.0:8091".
# BIND and PORT are now separate keys, both valid config values.
T="$(filetext)"
chk "WEB_BIND is an address, no port"    yes "$(echo "$T" | grep -qE '^WEB_BIND=[^:]*$' && echo yes || echo no)"
chk "WEB_PORT is emitted separately"     yes "$(echo "$T" | grep -qE '^WEB_PORT=[0-9]+$' && echo yes || echo no)"
chk "listener binds carry no port either" no "$(echo "$T" | grep -qE '^[A-Z_]+_BIND=[^ ]*:[0-9]+$' && echo yes || echo no)"
chk "every listener has a *_PORT line"   yes "$(for k in EST ACME CMP SCEP MS OCSP STORE; do echo "$T" | grep -qE "^${k}_PORT=[0-9]+$" || { echo no; exit; }; done; echo yes)"
# Saving the file back untouched must be a clean no-op. This is the guard that would
# have caught the regression where validation rejected the console's own rendering.
filetext > rt.conf
chk "unchanged file round-trips (no 400)" '{"set":0,"unset":0}' "$(curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode "text@rt.conf")"
# And the port can now be changed the natural way, via WEB_PORT.
sed 's/^WEB_PORT=.*/WEB_PORT=8091/' rt.conf > rt2.conf
chk "WEB_PORT is editable via the file"  '{"set":1,"unset":0}' "$(curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode "text@rt2.conf")"
curl -s -b admin.cj -X DELETE "$U/api/config/db?key=WEB_PORT" >/dev/null


echo "=== PUT applies the diff (set / unset) to the overlay ==="
chk "set two keys -> set:2"  '{"set":2,"unset":0}' "$(curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode $'text=CERT_VALIDITY_DAYS=730\nLOG_LEVEL=info')"
T="$(filetext)"
chk "override now shows live (uncommented)" yes "$(echo "$T" | grep -q '^CERT_VALIDITY_DAYS=730' && echo yes || echo no)"
chk "overlay endpoint reflects the set"     yes "$(curl -s -b admin.cj "$U/api/config/db" | grep -q '"CERT_VALIDITY_DAYS"' && echo yes || echo no)"
chk "drop a line -> unset:1"  '{"set":0,"unset":1}' "$(curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode $'text=CERT_VALIDITY_DAYS=730')"

echo "=== a value edited via the file ACTUALLY configures a server (not just stored) ==="
# Set a distinctive validity through the file editor, then start a FRESH server against
# the SAME DB: its startup applies the overlay over bootstrap.conf, so it must report 3, not
# the bootstrap.conf default (411). This proves the file edit changes real server config.
curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode $'text=CERT_VALIDITY_DAYS=3' >/dev/null
PORT2=18274
cat > web2.conf <<EOF2
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT2
WEB_ALLOW_REVOKE=true
CERT_VALIDITY_DAYS=411
LOG_LEVEL=err
EOF2
"$WEB" --config web2.conf >web2.log 2>&1 & P2=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web2.conf" WEB_PORT "$P2" || true
U2="http://127.0.0.1:$PORT2"
curl -s -c a2.cj -X POST "$U2/api/login" -d 'username=admin&password=adminpw12' >/dev/null
chk "fresh server honours the file-edited value (3, not bootstrap.conf 411)" yes "$(curl -s -b a2.cj "$U2/api/config" | grep -q '"key":"CERT_VALIDITY_DAYS","value":"3"' && echo yes || echo no)"
kill $P2 2>/dev/null
# Setting a value back to the bootstrap.conf default drops the override entirely.
chk "value == bootstrap.conf default -> override dropped (unset:1)" '{"set":0,"unset":1}' "$(curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode $'text=CERT_VALIDITY_DAYS=411')"
# ⚠️ The OVERRIDE row, not the key. The API also reports the key with
# "unset":true — a tombstone recording that the removal is itself a pending change no
# process has picked up yet — so a bare grep for the key name now matches the marker and
# reads as "the override is still there". Match the override's shape instead.
chk "overlay no longer holds the reverted key" yes \
    "$(curl -s -b admin.cj "$U/api/config/db" | grep -q '"key":"CERT_VALIDITY_DAYS","value"' && echo no || echo yes)"
# Second call site: reverting through the WHOLE-FILE editor is the same change as
# DELETE /api/config/db and was equally invisible. Both go through one helper now.
chk "  and the revert leaves a tombstone"      yes \
    "$(curl -s -b admin.cj "$U/api/config/db" | grep -q '"key":"CERT_VALIDITY_DAYS","unset":true' && echo yes || echo no)"

echo "=== secret round-trip: no clear-text leak, and (set) is a no-op ==="
curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode $'text=CERT_VALIDITY_DAYS=730\nWEB_TOKEN=topsecret123' >/dev/null
T="$(filetext)"
chk "secret shows masked in the file"      yes "$(echo "$T" | grep -q '^WEB_TOKEN=(set)' && echo yes || echo no)"
chk "secret value NOT leaked in the file"  yes "$(echo "$T" | grep -q 'topsecret123' && echo no || echo yes)"
chk "leaving (set) is a no-op (set:0)"  '{"set":0,"unset":0}' "$(curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode $'text=CERT_VALIDITY_DAYS=730\nWEB_TOKEN=(set)')"
chk "/api/config/db masks the secret"      yes "$(curl -s -b admin.cj "$U/api/config/db" | grep -q '"WEB_TOKEN","value":"(set)"' && echo yes || echo no)"
# The TEXT is stored in the config table too, and `fastpki-config list` prints that table:
# a secret typed into the file was readable there verbatim.
curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode $'text=CERT_VALIDITY_DAYS=730\nWEB_TOKEN=anothersecret456' >/dev/null
chk "the stored file text holds no secret" no \
    "$(pg_exec "SELECT value FROM config WHERE key='CONFIG_FILE_TEXT';" | grep -q 'anothersecret456' && echo yes || echo no)"
chk "  while the secret itself was stored" yes \
    "$(pg_exec "SELECT value FROM config WHERE key='WEB_TOKEN';" | grep -q 'anothersecret456' && echo yes || echo no)"
printf 'PG_CONNINFO=%s\nLOG_LEVEL=err\n' "$PG_CONNINFO" > cli.conf
chk "fastpki-config list names the file text, not its lines" yes \
    "$("$ROOT/build/fastpki-config" --config cli.conf list | grep -q "^CONFIG_FILE_TEXT=(the console's config file" && echo yes || echo no)"
chk "  and export leaves it out, so export -> import round-trips" no \
    "$("$ROOT/build/fastpki-config" --config cli.conf export | grep -q '^CONFIG_FILE_TEXT=' && echo yes || echo no)"
# A key the catalog does not know, typed into the file and later deleted from it, stayed set:
# only catalog keys were unset. The previous text says which keys the file offered.
curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode $'text=CERT_VALIDITY_DAYS=730\nWEB_TOKEN=(set)\nSITE_NOTE_KEY=hello' >/dev/null
chk "fixture: a non-catalog key typed into the file is stored" 1 \
    "$(pg_exec "SELECT count(*) FROM config WHERE key='SITE_NOTE_KEY';")"
curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode $'text=CERT_VALIDITY_DAYS=730\nWEB_TOKEN=(set)' >/dev/null
chk "  and deleting its line unsets it" 0 \
    "$(pg_exec "SELECT count(*) FROM config WHERE key='SITE_NOTE_KEY';")"

echo "=== input validation -> 400 ==="
chk "malformed line -> 400"  400 "$(code -b admin.cj -X PUT "$U/api/config/file" --data-urlencode 'text=this is not valid')"
chk "bootstrap key -> 400"   400 "$(code -b admin.cj -X PUT "$U/api/config/file" --data-urlencode 'text=PG_CONNINFO=host=evil')"
chk "bad key chars -> 400"   400 "$(code -b admin.cj -X PUT "$U/api/config/file" --data-urlencode 'text=bad-key=1')"

echo "=== RBAC: the editor + restart are admin-only ==="
seed_web_user aud audpw123 auditor
curl -s -c aud.cj -X POST "$U/api/login" -d 'username=aud&password=audpw123' >/dev/null
chk "auditor GET file -> 403"      403 "$(code -b aud.cj "$U/api/config/file")"
chk "auditor PUT file -> 403"      403 "$(code -b aud.cj -X PUT "$U/api/config/file" --data-urlencode 'text=LOG_LEVEL=info')"
chk "auditor POST restart -> 403"  403 "$(code -b aud.cj -X POST "$U/api/restart")"

echo "=== the file round-trips VERBATIM: comments and custom text survive a save ==="
# The reported bug: a '# test save' line was added, Save & Restart pressed, and it was
# gone by the next login. The editor re-rendered the file from the config catalog every open, so anything
# that wasn't a KEY=value override (comments, blank lines, ordering, notes) was dropped.
# The saved text is now stored verbatim and handed back as authored.
curl -s -b admin.cj -X PUT "$U/api/config/file" \
  --data-urlencode $'text=# test save\n# my notes about this DC\nCERT_VALIDITY_DAYS=99\n' >/dev/null
T="$(filetext)"
chk "author's comment survives the save"   yes "$(echo "$T" | grep -qF '# test save' && echo yes || echo no)"
chk "a second custom comment survives"     yes "$(echo "$T" | grep -qF '# my notes about this DC' && echo yes || echo no)"
chk "the edited value survives"            yes "$(echo "$T" | grep -q '^CERT_VALIDITY_DAYS=99' && echo yes || echo no)"
chk "settings left out are still listed"   yes "$(echo "$T" | grep -q '^LOG_LEVEL=' && echo yes || echo no)"
# The storage slot is an internal blob, never a setting the operator can see or clobber.
chk "internal key is not a config line"    no  "$(echo "$T" | grep -q '^CONFIG_FILE_TEXT=' && echo yes || echo no)"
chk "internal key survives a later save"   yes "$(curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode $'text=# test save\nCERT_VALIDITY_DAYS=99\n' >/dev/null; filetext | grep -qF '# test save' && echo yes || echo no)"
# Values stay truthful: a change made elsewhere is reflected in the authored file.
curl -s -b admin.cj -X PUT "$U/api/config/db" -d 'key=CERT_VALIDITY_DAYS&value=77' >/dev/null
chk "value refreshed to the live one"      yes "$(filetext | grep -q '^CERT_VALIDITY_DAYS=77' && echo yes || echo no)"
chk "comment still intact after refresh"   yes "$(filetext | grep -qF '# test save' && echo yes || echo no)"

echo "=== a setting missing from a saved file comes back IN ITS SECTION ==="
# A file saved before a setting existed (or before *_PORT was split out of *_BIND) does
# not mention it. Re-adding those at the END of the file made it look like every port
# configuration had disappeared from the Web Console section. They belong in their own
# section, where the operator expects to find them.
filetext | grep -vE '^(WEB|EST|ACME|CMP|SCEP|MS|OCSP|STORE)_PORT=' > old.conf
curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode "text@old.conf" >/dev/null
T="$(filetext)"
websec=$(echo "$T" | awk '/── Web Console ──/{f=1;next} /── /{if(f)exit} f{print}')
chk "WEB_PORT is back in the Web Console section" yes "$(echo "$websec" | grep -q '^WEB_PORT=' && echo yes || echo no)"
ocspsec=$(echo "$T" | awk '/── OCSP & CRL ──/{f=1;next} /── /{if(f)exit} f{print}')
chk "OCSP_PORT is back in the OCSP section"       yes "$(echo "$ocspsec" | grep -q '^OCSP_PORT=' && echo yes || echo no)"
chk "no catch-all dump at the end of the file"    no  "$(echo "$T" | grep -q 'settings not listed above' && echo yes || echo no)"
chk "all 8 listener ports are present"            8   "$(echo "$T" | grep -cE '^(WEB|EST|ACME|CMP|SCEP|MS|OCSP|STORE)_PORT=')"
# Restoring them must not silently create overrides.
chk "restored settings create no overrides" '{"set":0,"unset":0}' "$(filetext > back.conf; curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode "text@back.conf")"

echo "=== a bind/port typo cannot brick a data center ==="
# WEB_BIND=0.0.0.0:8091 was set on a lab DC (the port belongs in WEB_PORT; a bind key
# takes an address only). The server tried to bind host "0.0.0.0:8091", failed, and
# crash-looped — so BOTH ports were dead and the console, the only tool that could undo
# the override, was gone with it. Recovery needed shell + psql on the box.
chk "WEB_BIND=host:port -> 400 (per-key)"  400 "$(code -b admin.cj -X PUT "$U/api/config/db" -d 'key=WEB_BIND&value=0.0.0.0:8091')"
chk "WEB_BIND=host:port -> 400 (file)"     400 "$(code -b admin.cj -X PUT "$U/api/config/file" --data-urlencode $'text=WEB_BIND=0.0.0.0:8091\n')"
chk "the error says to use WEB_PORT"       yes "$(curl -s -b admin.cj -X PUT "$U/api/config/db" -d 'key=WEB_BIND&value=0.0.0.0:8091' | grep -q 'set WEB_PORT=8091' && echo yes || echo no)"
chk "WEB_PORT out of range -> 400"         400 "$(code -b admin.cj -X PUT "$U/api/config/db" -d 'key=WEB_PORT&value=99999')"
chk "WEB_PORT non-numeric -> 400"          400 "$(code -b admin.cj -X PUT "$U/api/config/db" -d 'key=WEB_PORT&value=eighty')"
chk "any *_BIND is guarded, not just web"  400 "$(code -b admin.cj -X PUT "$U/api/config/db" -d 'key=OCSP_BIND&value=0.0.0.0:8080')"
# Legitimate values must still be accepted, and an IPv6 address is full of colons — so
# "contains a colon" was never the test. The count is: host:port has exactly one, an IPv6
# literal has two or more. Every listener now DEFAULTS to `::`, so a guard that rejected
# these would reject the shipped configuration and break the round-trip of a file nobody
# had edited.
chk "a plain address is accepted"          200 "$(code -b admin.cj -X PUT "$U/api/config/db" -d 'key=OCSP_BIND&value=127.0.0.1')"
chk "the IPv6 wildcard is accepted"        200 "$(code -b admin.cj -X PUT "$U/api/config/db" -d 'key=OCSP_BIND&value=::')"
chk "an IPv6 literal is accepted"          200 "$(code -b admin.cj -X PUT "$U/api/config/db" -d 'key=OCSP_BIND&value=2001:db8::1')"
# ⚠️ AND THE BRACKETED FORM IS REFUSED, which this suite used to require be ACCEPTED.
# Measured in the shipped image: `getent ahosts "[::1]"` returns nothing while `getent
# ahosts "::1"` resolves — getaddrinfo() takes the bare form, and brackets are a URI
# convention. So a saved `[::1]` is a value that cannot bind, which is precisely the typo
# the guard above exists to catch, and accepting it bricked the listener at the next
# restart rather than at the save.
chk "a bracketed literal is refused"       400 "$(code -b admin.cj -X PUT "$U/api/config/db" -d 'key=OCSP_BIND&value=[::1]')"
chk "  and the error says to drop them"    yes \
    "$(curl -s -b admin.cj -X PUT "$U/api/config/db" -d 'key=OCSP_BIND&value=[::1]' | grep -q 'without brackets' && echo yes || echo no)"
curl -s -b admin.cj -X DELETE "$U/api/config/db?key=OCSP_BIND" >/dev/null

# Defence in depth: an override written straight to the table (predating validation, as
# on the lab) must not stop the console starting — it is dropped with a loud log and the
# bootstrap.conf value is kept, so the operator can remove it from the console itself.
"$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
  -c "insert into config(key,value,updated) values('WEB_BIND','0.0.0.0:8091',0) on conflict(key) do update set value='0.0.0.0:8091'" >/dev/null 2>&1
PORT3=18278
sed "s/^WEB_PORT=.*/WEB_PORT=$PORT3/" web.conf > web3.conf
"$WEB" --config web3.conf >web3.log 2>&1 & P3=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web3.conf" WEB_PORT "$P3" || true
chk "starts despite an invalid stored override" 200 "$(code "http://127.0.0.1:$PORT3/")"
chk "and says why it ignored it"            yes "$(grep -q 'ignoring invalid DB config override' web3.log && echo yes || echo no)"
chk "still running (no crash loop)"         yes "$(kill -0 $P3 2>/dev/null && echo yes || echo no)"
kill $P3 2>/dev/null
"$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -c "delete from config where key='WEB_BIND'" >/dev/null 2>&1

echo "=== the modal editor is shipped in the served console ==="
curl -s "$U/" -o index.html
chk "config-file modal builder present" yes "$(grep -qF 'function openConfigFileModal' index.html && echo yes || echo no)"
chk "config-file modal container present" yes "$(grep -qF 'id="cfgfilemodal"' index.html && echo yes || echo no)"
chk "Edit-full-config button present"   yes "$(grep -qF 'cfgfilebtn' index.html && echo yes || echo no)"

echo "=== saving the file must not delete keys the file cannot express ==="
# ⚠️ THE DANGEROUS ONE, and it is not about the file editor's own settings.
#
# GET renders the file from config_catalog() only. Four families of config-table key are
# therefore NEVER in the text: <PROTO>_ENABLED (the on/off switch), <PROTO>_INSTALLED
#, <PROTO>_RESTART_AT and <PROTO>_STARTED_AT. PUT's delete pass
# unset everything in the overlay that the submitted text did not mention — so every save
# silently wiped all four.
#
# The worst is <PROTO>_ENABLED. Its absence means ENABLED (endpoint_enabled(): "it ==
# cfg.end() || truthy"), so an admin who switched EST off in the console and later saved
# the config file — a completely unrelated action — turned EST back on, with nothing said
# anywhere. That is a listener coming back up on a box where someone decided it should
# not be listening.
#
# Assert through the API, on real state, not by grepping the served text.
curl -s -b admin.cj -X POST "$U/api/endpoints/est/enabled?enabled=false" >/dev/null
curl -s -b admin.cj -X POST "$U/api/endpoints/cmp/restart" >/dev/null
before_en=$(curl -s -b admin.cj "$U/api/config/db" | grep -c 'EST_ENABLED')
chk "EST_ENABLED is set before the save"        1 "$before_en"
# Save the file EXACTLY as served — a no-op edit. Nothing about this should change state.
filetext > roundtrip.conf
curl -s -b admin.cj -X PUT "$U/api/config/file" --data-urlencode "text@roundtrip.conf" >/dev/null
chk "  ... and survives an unchanged save"      1 \
    "$(curl -s -b admin.cj "$U/api/config/db" | grep -c 'EST_ENABLED')"
chk "  ... still switched OFF, not silently on" no \
    "$(curl -s -b admin.cj "$U/api/endpoints" | tr '{' '\n' | grep '"gate":"est"' \
       | grep -q '"enabled":true' && echo yes || echo no)"
chk "  the restart marker survives too"         1 \
    "$(curl -s -b admin.cj "$U/api/config/db" | grep -c 'CMP_RESTART_AT')"

# ── an out-of-band edit to bootstrap.conf must not be silently overwritten ─────────────────
#
# The dialog edits the authored text stored in the `config` table and renders values from
# the in-memory struct, so a file edited behind the console's back is invisible — and Save
# persists the stale rendering back over it, succeeding while reverting the change. The
# chosen design is option 2: the DB stays authoritative, the disagreement is made
# visible, and nothing overwrites without being told to.
echo "=== Drift between bootstrap.conf on disk and the console's copy ==="
DRIFT(){ curl -s -b admin.cj "$U/api/config/file/drift" | grep -o '"drift":[a-z]*' | cut -d: -f2; }
# ⚠️ A SEPARATE endpoint on purpose: GET /api/config/file must keep returning exactly
# {"text":"..."} — filetext() above takes everything between `{"text":"` and the trailing
# `"}`, so any extra field lands inside the config body and every later PUT 400s with
# "line is not KEY=value". Adding a field to a response is an interface change.
chk "PRECONDITION: no drift before anyone touches the file" false "$(DRIFT)"

# A PUT is accepted while the two agree — otherwise the refusal below proves nothing.
BODY=$(filetext)
code=$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X PUT \
        --data-urlencode "text=$BODY" "$U/api/config/file")
chk "  a Save is accepted while they agree" 200 "$code"

# Now edit the file the way an operator would, out of band.
sleep 1                     # mtime has 1-second granularity; without this the edit can
                            # land in the same second as the load and look like no change
echo "# edited out of band at $(date +%s)" >> web.conf
chk "the console notices the file changed on disk" true "$(DRIFT)"

code=$(curl -s -o resp275.json -w '%{http_code}' -b admin.cj -X PUT \
        --data-urlencode "text=$BODY" "$U/api/config/file")
chk "  and REFUSES the Save that would revert it" 409 "$code"
chk "  naming the file and what to do" yes \
    "$(grep -qi "changed on disk" resp275.json && grep -qi "force=true" resp275.json && echo yes || echo no)"
# ⚠️ The override must still exist: refusing forever would make the editor unusable after
# any file edit, which is a worse failure than the one being fixed.
code=$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X PUT \
        --data-urlencode "text=$BODY" --data-urlencode "force=true" "$U/api/config/file")
chk "  but an explicit force=true is honoured" 200 "$code"

echo "=== POST /api/restart returns, then the server exits (Docker restarts it) ==="
chk "admin restart -> 200 restarting" '{"restarting":true}' "$(curl -s -b admin.cj -X POST "$U/api/restart")"
gone=no
for i in 1 2 3 4 5 6; do
  if ! curl -s -o /dev/null --max-time 1 "$U/api/me" 2>/dev/null; then gone=yes; break; fi
  sleep 1
done
chk "server process exited after restart" yes "$gone"

echo
echo "=== CONFIG FILE EDITOR: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
