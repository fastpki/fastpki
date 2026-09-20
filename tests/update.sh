#!/usr/bin/env bash
# Software update check + release-signature verification.
# Exercises fastpki-update: version reporting, the update check against a local
# mock feed (UPDATE_FEED_URL override), and detached release-signature verify
# (accept good / reject tampered / reject wrong key). Self-skips without python3.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
UPD="$ROOT/build/fastpki-update"; PY=$(command -v python3 || true)
[ -n "$PY" ] || { echo "SKIP: python3 not available (mock feed needs it)"; exit 0; }
W="$(mktemp -d)"; cd "$W"; PORT=18310
# Clean stale processes on our ports.
#
# ⚠️ NEVER AN UNBOUNDED `lsof` HERE. In a --network host container it blocks forever, and
# it wedged the whole DC run TWICE at exactly this line — before the suite's first echo, so
# the log showed ">>> update.sh" and then nothing, for hours. Nothing timed it out because
# run_all has no per-suite limit; the first run was killed by hand, the second stalled the
# same way.
#
# This suite had never run anywhere before: it self-skips without python3, and the shipped
# image had none until certbot (a Python application) pulled one in. So a convenience line
# nobody had executed became a total stall the first time it was reached.
#
# Bounded, and skipped entirely where it cannot be bounded — macOS has no `timeout`, and a
# missing cleanup only risks a loud port-in-use failure, while a hang costs the whole run.
kill_stale_port(){
    command -v lsof    >/dev/null 2>&1 || return 0
    command -v timeout >/dev/null 2>&1 || return 0
    timeout 5 lsof -ti :"$1" 2>/dev/null | while read -r p; do
        [ -n "$p" ] && kill "$p" 2>/dev/null
    done
    return 0
}
kill_stale_port "$PORT"
kill_stale_port 18311
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

echo "=== version ==="
CUR=$("$UPD" version)
chk "version is reported (non-empty)" yes "$([ -n "$CUR" ] && echo yes || echo no)"
chk "--version matches the subcommand" "$CUR" "$("$UPD" --version)"
BASE=$(echo "$CUR" | sed 's/-.*//')   # strip any -dev / -gNNN suffix

echo "=== update check against a mock feed (UPDATE_FEED_URL) ==="
WP=""
mkdir feed; "$PY" -m http.server "$PORT" --bind 127.0.0.1 --directory feed >/dev/null 2>&1 & SRV=$!
sleep 1; trap 'kill $SRV $WP 2>/dev/null' EXIT
printf 'UPDATE_FEED_URL=http://127.0.0.1:%s/feed.json\nLOG_LEVEL=err\n' "$PORT" > bootstrap.conf
# A newer release is offered.
printf '{"version":"99.9.0","notes":"big release","url":"https://example/fastpki-99.9.0.tgz"}' > feed/feed.json
OUT=$("$UPD" --config bootstrap.conf check); RC=$?
chk "newer version is reported available" yes "$(has "$OUT" 'UPDATE AVAILABLE: 99.9.0')"
chk "check exits 10 when an update is available" 10 "$RC"
chk "the download URL is surfaced" yes "$(has "$OUT" 'fastpki-99.9.0.tgz')"
# The same version → up to date.
printf '{"version":"%s"}' "$BASE" > feed/feed.json
OUT=$("$UPD" --config bootstrap.conf check); RC=$?
chk "same version → up to date" yes "$(has "$OUT" 'up to date')"
chk "check exits 0 when up to date" 0 "$RC"
# A malformed feed is a clean failure, not a crash.
printf 'not json' > feed/feed.json
"$UPD" --config bootstrap.conf check >/dev/null 2>&1
chk "malformed feed fails cleanly (non-zero, no crash)" yes "$([ $? -ne 0 ] && echo yes || echo no)"

echo "=== release-signature verification ==="
"$OSSL" ecparam -genkey -name prime256v1 -out rel.key >/dev/null 2>&1
"$OSSL" ec -in rel.key -pubout -out rel.pub >/dev/null 2>&1
"$OSSL" ecparam -genkey -name prime256v1 -out other.key >/dev/null 2>&1
"$OSSL" ec -in other.key -pubout -out other.pub >/dev/null 2>&1
head -c 4096 /dev/urandom > artifact.bin
"$OSSL" dgst -sha256 -sign rel.key -out artifact.sig artifact.bin
chk "valid signature is accepted" 0 "$("$UPD" verify artifact.bin artifact.sig --pubkey rel.pub >/dev/null 2>&1; echo $?)"
# Tamper with the artifact → reject.
cp artifact.bin tampered.bin; printf 'x' >> tampered.bin
chk "a tampered artifact is rejected" 1 "$("$UPD" verify tampered.bin artifact.sig --pubkey rel.pub >/dev/null 2>&1; echo $?)"
# Wrong key → reject.
chk "a wrong public key is rejected" 1 "$("$UPD" verify artifact.bin artifact.sig --pubkey other.pub >/dev/null 2>&1; echo $?)"
# Pinned key via RELEASE_PUBKEY in the config.
printf 'RELEASE_PUBKEY=%s\nLOG_LEVEL=err\n' "$W/rel.pub" > verify.conf
chk "pinned RELEASE_PUBKEY verifies" 0 "$("$UPD" --config verify.conf verify artifact.bin artifact.sig >/dev/null 2>&1; echo $?)"

echo "=== web Updates panel (/api/version) ==="
WEB="$ROOT/build/fastpki-web"
pg_setup update
trap 'pg_cleanup; kill $SRV "${WP:-}" 2>/dev/null' EXIT
printf '{"version":"99.9.0","notes":"web check"}' > feed/feed.json
printf 'WEB_BIND=127.0.0.1\nWEB_PORT=18311\nWEB_ALLOW_REVOKE=true\nUPDATE_FEED_URL=http://127.0.0.1:%s/feed.json\nLOG_LEVEL=err\n' "$PORT" > web.conf
"$WEB" --config web.conf >web.log 2>&1 & WP=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$WP" || true
UU="http://127.0.0.1:18311"
# Updating replaces binaries shared by every tenant, so the Updates surface is
# admin (update is the shared deployment, single-tenant).
curl -s -o /dev/null -X POST "$UU/api/users" -d 'username=boss&password=bosspw12&role=admin'
curl -s -c b.cj -X POST "$UU/api/login" -d 'username=boss&password=bosspw12' >/dev/null
curl -s -o /dev/null -b b.cj -X POST "$UU/api/users" -d 'username=al&password=alpw123456&role=requester'
curl -s -c al.cj -X POST "$UU/api/login" -d 'username=al&password=alpw123456' >/dev/null
chk "GET /api/version reports the running version" yes "$(has "$(curl -s -b b.cj "$UU/api/version")" '"version"')"
chk "GET /api/version?check=1 finds the update"    yes "$(has "$(curl -s -b b.cj "$UU/api/version?check=1")" '"available":true')"
chk "requester cannot read /api/version (403)" 403 "$(curl -s -o /dev/null -w '%{http_code}' -b al.cj "$UU/api/version")"

echo
echo "=== UPDATE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
