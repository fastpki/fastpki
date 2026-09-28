#!/usr/bin/env bash
# — the controls the Endpoints page and the certificate
# detail view offer an operator.
#
# ── MS had no on/off switch ─────────────────────────────────────────────────────
#
# Every listener can be gated by a config key its own process reads. The console
# derived that key from the row's DISPLAY name by lowercasing it, which works for six
# rows and not for the two that are named after their protocol rather than their process:
# `MS-XCEP` and `MS-WSTEP` lowercased to "ms-xcep"/"ms-wstep", matched no gate, and both
# rows rendered a dash. So MS was the one protocol an operator could not switch off — and
# nothing said why, because a dash is also what CRL correctly shows.
#
# The gate id is now carried explicitly, so the display name and the key can differ. Both
# MS rows gate on the one `MS_ENABLED` key, which is the truth: one process, one port — and
# so only the MS-XCEP row draws the switch, as only the OCSP row does for OCSP and the CRL.
#
# ── the console was absent from its own endpoints page ──────────────────────────
#
# And could not be restarted from itself, which is what an operator needs right after
# issuing the console's TLS certificate: the certificate is resolved at startup, so until
# the process comes back the new one sits in the database unserved.
#
# ── form order, and re-issuing a transport certificate ─────────────────────────
#
# The HSM request form asked for the algorithm before asking whether the key already
# exists — the answer that decides whether an algorithm may be chosen at all. And the
# detail view could revoke a certificate but not renew one, for exactly the certificates
# the console CAN re-issue unaided: those whose private key is in the token.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18212
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ grep -q "$2" <<<"$1" && echo yes || echo no; }
# One endpoint object out of the /api/endpoints array, by its protocol name. The array is
# one line of JSON, so cut on the record separator rather than trying to parse it.
row(){ printf '%s' "$1" | tr '{' '\n' | grep "\"protocol\":\"$2\""; }

ca_in_token ca.pem "/CN=Endpoint Controls CA" 3650
pg_setup web_endpoint_controls
source "$ROOT/tests/user_helpers.sh"
seed_web_user admin testpw admin
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT

cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
hsm_conf_lines >> web.conf
printf 'SIGNING_CA_PEM=%s\nSIGNING_CA_KEY=%s\n' "$W/ca.pem" "$CA_KEY_URI" >> web.conf
seed_ca_from_conf web.conf
sed -i.bak '/^SIGNING_CA_/d' web.conf && rm -f web.conf.bak

"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c cj.txt -d 'username=admin&password=testpw' "$U/api/login" >/dev/null
EP=$(curl -s -b cj.txt "$U/api/endpoints")

echo "=== MS can be switched off like every other listener, with ONE switch ==="
# One process serves both MS addresses, so it gets one switch: on the MS-XCEP row. The
# MS-WSTEP row keeps the gate — it follows the service's state — but names the row that
# holds the switch instead of drawing a second one that flips the same key.
chk "MS-XCEP is gateable"               yes "$(has "$(row "$EP" MS-XCEP)" '"gateable":true')"
chk "  and it gates on the ms key"      yes "$(has "$(row "$EP" MS-XCEP)" '"gate":"ms"')"
chk "MS-WSTEP draws no switch of its own" yes "$(has "$(row "$EP" MS-WSTEP)" '"gateable":false')"
chk "  it names MS-XCEP as its switch"  yes "$(has "$(row "$EP" MS-WSTEP)" '"switchedWith":"MS-XCEP"')"
chk "  and still follows the ms key"    yes "$(has "$(row "$EP" MS-WSTEP)" '"gate":"ms"')"
# The regression in one assertion: the gate id must not be the lowercased display name,
# because that is the value that matched nothing.
chk "the gate is not the lowercased label" no "$(has "$EP" '"gate":"ms-xcep"')"
# CRL is the same shape: served by the OCSP process, so no switch of its own, and it says so.
chk "CRL is still not gateable" yes "$(has "$(row "$EP" CRL)" '"gateable":false')"
chk "  it names OCSP as its switch" yes "$(has "$(row "$EP" CRL)" '"switchedWith":"OCSP"')"
# The page draws the dash with the note for such a row, before the plain dash.
PAGE=$(curl -s -b cj.txt "$U/")
chk "the On column explains a switched-with row" yes \
    "$(printf '%s' "$PAGE" | grep -q 'switched and restarted on that row' && echo yes || echo no)"
for p in EST ACME CMP SCEP OCSP Store; do
    chk "$p is still gateable" yes "$(has "$(row "$EP" "$p")" '"gateable":true')"
done

echo "=== and the switch actually reaches MS_ENABLED ==="
C=$(curl -s -b cj.txt -o /dev/null -w '%{http_code}' -X POST "$U/api/endpoints/ms/enabled?enabled=false")
chk "POST ms/enabled=false -> 200" 200 "$C"
chk "the config row is written" "false" \
    "$(pg_exec "SELECT value FROM config WHERE key='MS_ENABLED';" | tr -d ' ')"
EP2=$(curl -s -b cj.txt "$U/api/endpoints")
# BOTH rows must follow, or the page shows one MS path on and the other off while one
# process serves both.
chk "MS-XCEP now reads disabled"  yes "$(has "$(row "$EP2" MS-XCEP)"  '"enabled":false')"
chk "MS-WSTEP now reads disabled" yes "$(has "$(row "$EP2" MS-WSTEP)" '"enabled":false')"
chk "EST is unaffected"           yes "$(has "$(row "$EP2" EST)" '"enabled":true')"
curl -s -b cj.txt -o /dev/null -X POST "$U/api/endpoints/ms/enabled?enabled=true"

echo "=== The console is on its own endpoints page, with Restart ==="
chk "there is a Web Console row" yes "$(has "$EP" '"protocol":"Web Console"')"
chk "it is restartable"          yes "$(has "$(row "$EP" "Web Console")" '"restartable":true')"
# Not an on/off switch: switching the console off from the console is a lockout whose
# only cure is a shell and psql on the box.
chk "it is NOT gateable"         yes "$(has "$(row "$EP" "Web Console")" '"gateable":false')"
# The console is no longer the ONLY restartable row — every listener with a
# watcher is. What stays unique to the console is `selfRestart`: it re-execs itself,
# because a console that exits waiting for a restart policy is a console that may not
# come back. Everything else stops and is brought back by that policy.
chk "the console is the only SELF-restarting row" 1 \
    "$(printf '%s' "$EP" | grep -o '\"selfRestart\":true' | wc -l | tr -d ' ')"
chk "  ... and the other listeners are restartable too" yes \
    "$([ "$(printf '%s' "$EP" | grep -o '\"restartable\":true' | wc -l | tr -d ' ')" -gt 1 ] && echo yes || echo no)"
curl -s -b cj.txt "$U/" -o index.html
oneline="$(tr '\n' ' ' < index.html | tr -s ' ')"
chk "the page renders a restart button" yes \
    "$(printf '%s' "$oneline" | grep -qF 'data-restart' && echo yes || echo no)"
# The URL is built from the button rather than hardcoded, because one handler now
# serves the console and every protocol. So assert the two halves that make it correct:
# the console's button carries `web`, and the fetch composes the path from that value.
chk "  the console button targets web"  yes \
    "$(printf '%s' "$oneline" | grep -qF "data-restart=\"web\"" && echo yes || echo no)"
chk "  wired to the restart endpoint"   yes \
    "$(printf '%s' "$oneline" | grep -qF "'/api/endpoints/' + encodeURIComponent(who) + '/restart'" && echo yes || echo no)"
# Only the console reloads the page: the others are served by a different process, so this
# page keeps working and freezing it would be a lie.
chk "  only a self-restart reloads the page" yes \
    "$(printf '%s' "$oneline" | grep -qF "const isSelf = (who === 'web')" && echo yes || echo no)"
# The toggle must post the gate, not the label — the served JS is the only place this can
# be checked without a browser (§3e).
chk "the toggle posts the gate id" yes \
    "$(printf '%s' "$oneline" | grep -qF 'row.gate || row.protocol' && echo yes || echo no)"

echo "=== the restart endpoint restarts the process ==="
# The strongest available proof in shell: the pid changes, the port comes back, and the
# same session still works — a re-exec, not a crash and not a no-op.
OLD_PID=$P
BEFORE=$(curl -s -b cj.txt "$U/api/me")
chk "the session works before" yes "$(has "$BEFORE" '"user":"admin"')"
C=$(curl -s -b cj.txt -o restart.json -w '%{http_code}' -X POST "$U/api/endpoints/web/restart")
chk "POST web/restart -> 200" 200 "$C"
chk "  and it says so" yes "$(has "$(cat restart.json)" '"restarting":true')"
# execv replaces the image, so the pid is KEPT. That is the point: no supervisor is
# needed. Wait for the listener to come back.
up=no
for i in $(seq 1 60); do
    sleep 1
    curl -s -o /dev/null --max-time 2 "$U/api/setup" 2>/dev/null && { up=yes; break; }
done
chk "the console is serving again" yes "$up"
chk "the process is the same pid (re-exec, not respawn)" yes \
    "$(kill -0 $OLD_PID 2>/dev/null && echo yes || echo no)"
# A restart is a config reload, so a value written while it was down must now be live.
chk "it came back on a fresh config read" yes \
    "$(has "$(curl -s -b cj.txt "$U/api/endpoints")" '"protocol":"Web Console"')"
# Sessions live in `web_sessions`, so they survive the restart (that is what makes this
# usable at all — an operator is not logged out by pressing the button).
chk "the session survived" yes "$(has "$(curl -s -b cj.txt "$U/api/me")" '"user":"admin"')"

echo "=== and it re-execs even when argv[0] is a bare name ==="
# The lab found this and the suite had not: there the console is PID 1 with argv[0]
# "fastpki-web", and execv does not search PATH — so the re-exec failed with ENOENT and
# the restart quietly became "exit and let the container be recreated". That works only
# where something is supervising, which is the dependency re-exec exists to remove. Run
# it the way a container does and require the pid to survive.
kill $P 2>/dev/null; wait $P 2>/dev/null
BIN="$W/bin"; mkdir -p "$BIN"; cp "$WEB" "$BIN/fastpki-web"
# NOT a subshell and NOT pgrep: `( … ) &` makes $! the subshell, and pgrep by name picks
# up any other run's leftovers — which is how the first version of this assertion passed
# against the pre-fix build, matching an unrelated process while the one under test had
# already exited. Backgrounding the command directly makes $! the server itself.
PATH="$BIN:$PATH" fastpki-web --config web.conf >web2.log 2>&1 &
BARE_PID=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$BARE_PID" || true
P=$BARE_PID
chk "the bare-name console started" yes "$(kill -0 $BARE_PID 2>/dev/null && echo yes || echo no)"
curl -s -c cj2.txt -d 'username=admin&password=testpw' "$U/api/login" >/dev/null
C=$(curl -s -b cj2.txt -o /dev/null -w '%{http_code}' -X POST "$U/api/endpoints/web/restart")
chk "POST web/restart -> 200 (bare argv[0])" 200 "$C"
up=no
for i in $(seq 1 60); do
    sleep 1
    # Require the PROCESS to still be there as well as the port to answer: a stale
    # listener from another run would satisfy the port on its own.
    kill -0 $BARE_PID 2>/dev/null || break
    curl -s -o /dev/null --max-time 2 "$U/api/setup" 2>/dev/null && { up=yes; break; }
done
chk "it is serving again" yes "$up"
# THE assertion: a re-exec keeps the pid. A crash-and-be-restarted would not — and here
# there is no supervisor at all, so nothing would bring it back.
chk "the pid survived (execvp found it on PATH)" yes \
    "$([ -n "$BARE_PID" ] && kill -0 "$BARE_PID" 2>/dev/null && echo yes || echo no)"

echo "=== The HSM form asks its questions in the order they are decided ==="
curl -s -b cj2.txt "$U/" -o index.html
# Positions in the served document. A grep can only say a field EXISTS; the complaint was
# about order, so compare where they are.
# ⚠️ NOT `grep -bo`. busybox grep has no -b, so on the image we ship this printed a usage
# dump, every position came back EMPTY, and all four order checks failed — looking exactly
# like the console had stopped emitting the fields. awk's index() is literal (not a regex)
# and present on busybox and GNU alike.
posn(){ printf '%s' "$oneline" | awk -v n="$1" '{i=index($0,n); print (i ? i-1 : "")}'; }
oneline="$(tr '\n' ' ' < index.html | tr -s ' ')"
P_SLOT=$(posn 'id="inv_hsm_slot"')
P_EXIST=$(posn 'id="hsm_existingkey"')
P_ALGO=$(posn 'id="hsmalgo"')
P_CN=$(posn 'name="cn" required')
chk "all four fields are present" yes \
    "$([ -n "$P_SLOT" ] && [ -n "$P_EXIST" ] && [ -n "$P_ALGO" ] && [ -n "$P_CN" ] && echo yes || echo no)"
chk "Existing key comes after Token slot" yes "$([ "$P_EXIST" -gt "$P_SLOT" ] && echo yes || echo no)"
chk "Algorithm comes after Existing key"  yes "$([ "$P_ALGO" -gt "$P_EXIST" ] && echo yes || echo no)"
chk "the key block comes before the subject" yes "$([ "$P_CN" -gt "$P_ALGO" ] && echo yes || echo no)"

echo "=== Renew / Re-key on a certificate whose key is in the token ==="
# Issue one through the HSM path so the row is genuine — its key really is in the token
# and it really is tagged as a listener's transport certificate.
cp cj2.txt cj.txt
KEYREF=$(hsm_new_key_uri ep-web-tls "$CA_KEY_URI")
# WEB_CERT_ID's key must be the one the console loads, or request-hsm refuses.
curl -s -b cj.txt -o /dev/null -X PUT "$U/api/config/db?key=WEB_TLS_KEY&value=$(printf '%s' "$KEYREF" | sed 's/;/%3B/g;s/=/%3D/g;s/:/%3A/g')"
CAID=$(curl -s -b cj.txt "$U/api/ca-instances" | tr '{' '\n' | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
ISS=$(curl -s -b cj.txt -X POST "$U/api/certs/request-hsm" \
        --data-urlencode "ca_instance=$CAID" \
        --data-urlencode "keyref=$KEYREF" --data-urlencode 'cn=console.example.org' \
        --data-urlencode 'sans=console.example.org' --data-urlencode 'cert_id=web' \
        --data-urlencode 'key=ec' --data-urlencode 'curve=P-256')
chk "an HSM-keyed transport cert was issued" yes "$(has "$ISS" '"serial"')"
SER=$(printf '%s' "$ISS" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')
DET=$(curl -s -b cj.txt "$U/api/certs/$SER")
# These three fields ARE the Renew button: without them it cannot reopen the form on this
# certificate, and offering it would produce a request the server refuses.
chk "the detail names its transport role" yes "$(has "$DET" '"certId":"web"')"
chk "the detail names the issuing CA"     yes "$(has "$DET" '"caInstanceId":"')"
chk "the detail names the token key"      yes "$(has "$DET" "\"keyRef\":\"pkcs11:")"
chk "  and it is the key the console loads" yes \
    "$(printf '%s' "$DET" | grep -q "ep-web-tls" && echo yes || echo no)"

# The Serves column must resolve a PER-CA CMP RA id. The map behind it is keyed
# on exact ids, and 'cmp-ra' gained a '-<ca_id>' suffix when the RA credential went
# per-CA — so an exact lookup silently stopped matching and the column fell back to
# printing the raw id. A missing entry degrades to something that still looks plausible,
# which is why this needs an assertion and not an eyeball. The console renders client
# side, so this greps the served script (§3e): weak as proxies go, but it does catch the
# reintroduction, which is the failure mode here.
# ⚠️ Match the CODE, not prose. The console JS lives in a C++ raw string, so the comments
# above this branch are served to the browser as well — greping "CMP RA for" matched the
# COMMENT and passed with the branch deleted. Anchor on the expression itself, which only
# the implementation can contain.
# The two hardcoded prefix checks became ONE list, PER_CA_SERVES, because the
# display side and the input side had drifted apart twice and produced a real bug each
# time (a cert_id='cmp-ra' that no CA ever looked up). Assert the list and its
# members, not a particular expression — the whole point is that there is now one place.
chk "the Serves column resolves per-CA ids from a single list" yes \
    "$(grep -qF "const PER_CA_SERVES" index.html && echo yes || echo no)"
chk "  the list covers the CMP RA" yes \
    "$(grep -qF "'cmp-ra': 'CMP RA'" index.html && echo yes || echo no)"
chk "  and the OCSP responder" yes \
    "$(grep -qF "'ocsp-ra': 'OCSP responder'" index.html && echo yes || echo no)"
chk "  and the SCEP RA" yes \
    "$(grep -qF "'scep-ra': 'SCEP RA'" index.html && echo yes || echo no)"
chk "  and derives the CA id from the suffix" yes \
    "$(grep -qF "id.slice(pfx.length + 1)" index.html && echo yes || echo no)"

# ⚠️ AND THE INPUT SIDE, which the display fix above did NOT cover and which mattered more.
# "Serve as -> CMP RA" posted the bare id, so the console wrote cert_id='cmp-ra' while
# fastpki-cmp resolves '<CMP_RA_CERT_ID_PREFIX>-<ca_id>'. The certificate was issued, the row was
# written, the console said done — and CMP went on refusing every transaction, because the
# credential it needed did not exist under the name it looks up. The console could not
# produce a working CMP RA credential at all from the moment it shipped.
#
# Anchored on the expression, for the reason spelled out above: the comments around it are
# served to the browser too, so prose matches prose.
# Turned this into a list, because the OCSP responder id is per CA for the same
# reason. Anchored on the assignment and on the list containing both prefixes, so dropping
# either one fails.
chk "the console posts a PER-CA cert_id for these purposes" yes \
    "$(grep -qF "fd.set('cert_id', pfx + '-' + f.ca.value)" index.html && echo yes || echo no)"
# ⚠️ The strongest assertion here: the input side must read the SAME list the display
# side does. Two independent lists is what produced that bug, and it was missed
# twice more after that — so this pins the sharing, not the contents.
chk "  and the input side reads the SAME list as the display side" yes \
    "$(grep -qF "for (const pfx in PER_CA_SERVES)" index.html && echo yes || echo no)"

# The purpose must also drive KU/EKU. Left alone, the form's TLS defaults (serverAuth +
# clientAuth) went onto an RA certificate, and RFC 9810 §8.6 wants id-kp-cmcRA there.
chk "picking a purpose presets its extensions" yes \
    "$(grep -qF "PURPOSE_EXT" index.html && echo yes || echo no)"
chk "  and CMP RA asks for id-kp-cmcRA" yes \
    "$(grep -qF "1.3.6.1.5.5.7.3.28" index.html && echo yes || echo no)"

echo "=== an ordinary leaf offers no Renew — the console has no key for it ==="
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout leaf.key -subj "/CN=plain.example.org" -out leaf.csr >/dev/null 2>&1
# The CSR body is the raw PEM, and the CA is named in the QUERY (there is no
# default CA) — not a form field.
PLAIN=$(curl -s -b cj.txt -X POST --data-binary @leaf.csr "$U/api/certs/request?ca_instance=$CAID")
PSER=$(printf '%s' "$PLAIN" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')
if [ -n "$PSER" ]; then
    PDET=$(curl -s -b cj.txt "$U/api/certs/$PSER")
    chk "a plain leaf reports no transport role" yes "$(has "$PDET" '"certId":""')"
    chk "  and no key handle"                    yes "$(has "$PDET" '"keyRef":""')"
else
    # Not a skip: this pair of assertions is the whole negative case — without a plain
    # leaf to compare against, "the tag is set" proves nothing about when it is NOT.
    chk "an ordinary leaf was issued for the negative case" yes "no ($PLAIN)"
fi
chk "the button is gated on the key handle, not the name" yes \
    "$(printf '%s' "$oneline" | grep -qF '!!c.keyRef' && echo yes || echo no)"
# And on being allowed to create keys in the token — Renew and Re-key both go through
# /api/certs/request-hsm, which requires hsm:manage. This replaced a bare isAdmin(), which
# is why the assertion above no longer names it: an `admin` still passes, via *:*.
chk "  ...and on hsm:manage, not on being admin"  yes \
    "$(printf '%s' "$oneline" | grep -qF "x === 'hsm:manage'" && echo yes || echo no)"
chk "Renew keeps the existing key"  yes "$(printf '%s' "$oneline" | grep -qF 'reissue(c, true)'  && echo yes || echo no)"
chk "Re-key generates a new one"    yes "$(printf '%s' "$oneline" | grep -qF 'reissue(c, false)' && echo yes || echo no)"

echo "=== Restarting an endpoint that is not the console ==="
# The console's own restart is a LITERAL route; the per-protocol one is a regex that also
# matches "web". httplib matches in REGISTRATION order, so the regex registered first
# shadows the literal, refuses "web" as not-a-protocol, and 404s the console's own restart
# button. That is a regression this suite exists to catch — assert the literal still wins.
code=$(curl -s -b cj.txt -o /dev/null -w '%{http_code}' -X POST "$U/api/endpoints/web/restart" \
        --max-time 3 || echo 000)
chk "the console's own restart route still answers" yes \
    "$([ "$code" = 200 ] || [ "$code" = 000 ] && echo yes || echo no)"

# A protocol restart writes a timestamp its OWN watcher reads — the console never touches
# another container. Asserted on the config table, which is the contract between them.
before=$(curl -s -b cj.txt "$U/api/config/db" | grep -c 'EST_RESTART_AT' || true)
code=$(curl -s -b cj.txt -o rr.json -w '%{http_code}' -X POST "$U/api/endpoints/est/restart")
chk "POST /api/endpoints/est/restart -> 200" 200 "$code"
chk "  ... and it stamps EST_RESTART_AT" yes \
    "$(curl -s -b cj.txt "$U/api/config/db" | grep -q 'EST_RESTART_AT' && echo yes || echo no)"
chk "  ... with an epoch second, not a flag" yes \
    "$(grep -qE '\"restartAt\":[0-9]{10}' rr.json && echo yes || echo no)"
# The key the console writes must be the key the binaries read. Two spellings is how a
# feature ships inert.
chk "  ... the same key endpoint_restart_key() builds" yes \
    "$(grep -q 'return k + \"_RESTART_AT\";' "$ROOT/src/lib/endpoint_gate.cpp" && echo yes || echo no)"
code=$(curl -s -b cj.txt -o /dev/null -w '%{http_code}' -X POST "$U/api/endpoints/nosuch/restart")
chk "an unknown protocol -> 404" 404 "$code"

echo
echo "=== ENDPOINT CONTROLS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
