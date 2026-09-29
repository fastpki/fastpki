#!/usr/bin/env bash
# Full-database backup AND one-click restore from the web console. An admin
# downloads a pg_dump (POST /api/db-backup) and restores it in one click
# (POST /api/db-backup/restore). The restore is ATOMIC — psql --single-transaction
# -v ON_ERROR_STOP=1 — so a valid dump applies wholesale and a corrupt / wrong-format
# file rolls back with the database untouched. Both endpoints are admin-only.
#
# Self-contained (§3d/§3e): ephemeral DB via pg_helpers, one web instance, pure shell.
# SKIPs cleanly when Postgres / pg_dump / psql / the binary are absent.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
WEB="$ROOT/build/fastpki-web"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

command -v pg_dump >/dev/null 2>&1 || { echo "SKIP: pg_dump not installed"; exit 0; }
command -v psql    >/dev/null 2>&1 || { echo "SKIP: psql not installed"; exit 0; }
[ -x "$WEB" ] || { echo "SKIP: fastpki-web not built"; exit 0; }

W="$(mktemp -d)"; cd "$W"; PORT=18320
pg_setup db_restore
# Config-agnostic: SKIP (not fail) when no Postgres is reachable.
if [ "$(pg_exec 'SELECT 1;' 2>/dev/null)" != "1" ]; then echo "SKIP: no Postgres available"; exit 0; fi
trap 'pg_cleanup; kill $PID 2>/dev/null' EXIT
printf 'PG_CONNINFO=%s\nWEB_BIND=127.0.0.1\nWEB_PORT=%s\nWEB_ALLOW_REVOKE=true\nLOG_LEVEL=err\n' \
    "$PG_CONNINFO" "$PORT" > web.conf
"$WEB" --config web.conf >web.log 2>&1 & PID=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$PID" || true
U="http://127.0.0.1:$PORT"

echo "=== seed admin + requester, log in, plant a marker ==="
code -X POST "$U/api/users" -d 'username=boss&password=bosspw12&role=admin' >/dev/null
curl -s -c a.cj  -X POST "$U/api/login" -d 'username=boss&password=bosspw12' >/dev/null
code -b a.cj -X POST "$U/api/users" -d 'username=al&password=alpw123456&role=requester' >/dev/null
curl -s -c al.cj -X POST "$U/api/login" -d 'username=al&password=alpw123456' >/dev/null
# a distinctive config value we can track across dump/mutate/restore
curl -s -b a.cj -X PUT "$U/api/config/db" --data 'key=NOTIFY_DAYS&value=91,17' >/dev/null
chk "marker planted (NOTIFY_DAYS=91,17)" yes "$(has "$(curl -s -b a.cj "$U/api/config/db")" '91,17')"

echo "=== RBAC: db backup + restore are admin-only ==="
chk "requester cannot db-backup (403)"        403 "$(code -b al.cj -X POST "$U/api/db-backup")"
chk "requester cannot db-restore (403)"       403 "$(code -b al.cj -X POST "$U/api/db-backup/restore" -F 'file=@web.conf')"
chk "unauthenticated cannot db-backup (401)"  401 "$(code -X POST "$U/api/db-backup")"
chk "unauthenticated cannot db-restore (401)" 401 "$(code -X POST "$U/api/db-backup/restore" -F 'file=@web.conf')"

echo "=== admin downloads a full DB backup ==="
curl -s -b a.cj -X POST "$U/api/db-backup" -o db.sql
chk "dump is non-empty"                    yes "$([ -s db.sql ] && echo yes || echo no)"
chk "dump is a real pg_dump"               yes "$(has "$(cat db.sql)" 'PostgreSQL database dump')"

echo "=== mutate the DB, then restore the backup over it ==="
curl -s -b a.cj -X PUT "$U/api/config/db" --data 'key=NOTIFY_DAYS&value=3,2' >/dev/null
chk "marker mutated (91,17 gone)"          no  "$(has "$(curl -s -b a.cj "$U/api/config/db")" '91,17')"
R=$(curl -s -b a.cj -X POST "$U/api/db-backup/restore" -F 'file=@db.sql')
chk "restore reports success"              yes "$(has "$R" 'restored')"
chk "marker restored (91,17 back)"         yes "$(has "$(curl -s -b a.cj "$U/api/config/db")" '91,17')"
chk "requester al still logs in post-restore (user round-tripped)" 200 \
    "$(code -c al2.cj -X POST "$U/api/login" -d 'username=al&password=alpw123456')"

echo "=== ATOMIC: a partially-valid, then-erroring file rolls back (DB untouched) ==="
# Without --single-transaction the DROP would commit; with it, the later syntax error
# aborts the whole transaction and certs survives.
printf 'DROP TABLE IF EXISTS certs CASCADE;\nthis is not valid sql;\n' > bad.sql
chk "a bad restore is rejected (500)"      500 "$(code -b a.cj -X POST "$U/api/db-backup/restore" -F 'file=@bad.sql')"
chk "certs table survived (rolled back)"   200 "$(code -b a.cj "$U/api/certs")"
chk "marker intact after failed restore"   yes "$(has "$(curl -s -b a.cj "$U/api/config/db")" '91,17')"

echo "=== ENCRYPTED round-trip ==="
# NB: /api/db-backup reads the passphrase as a urlencoded param (as the console's
# URLSearchParams POST does), not a multipart field — send it the same way.
curl -s -b a.cj -X POST "$U/api/db-backup" --data 'passphrase=secretpw123' -o db.enc
chk "encrypted dump carries the FPKIBAK magic" yes "$(head -c 8 db.enc | grep -q 'FPKIBAK' && echo yes || echo no)"
curl -s -b a.cj -X PUT "$U/api/config/db" --data 'key=NOTIFY_DAYS&value=5,4' >/dev/null
RE=$(curl -s -b a.cj -X POST "$U/api/db-backup/restore" -F 'file=@db.enc' -F 'passphrase=secretpw123')
chk "encrypted restore succeeds"               yes "$(has "$RE" 'restored')"
chk "marker restored from encrypted dump"      yes "$(has "$(curl -s -b a.cj "$U/api/config/db")" '91,17')"
chk "wrong passphrase is rejected (400)"       400 \
    "$(code -b a.cj -X POST "$U/api/db-backup/restore" -F 'file=@db.enc' -F 'passphrase=wrongpw')"

echo "=== REFUSED on a node that replicates ==="
# A mesh node's dump holds rows its peers have since changed; replacing its database brings
# the old ones back (a certificate revoked elsewhere reads valid again). The publication
# fastpki-mesh creates is what marks a replicating node.
curl -s -b a.cj -X PUT "$U/api/config/db" --data 'key=NOTIFY_DAYS&value=6,5' >/dev/null
pg_exec "CREATE PUBLICATION fastpki_pub;" >/dev/null
RM=$(curl -s -o rm.json -w '%{http_code}' -b a.cj -X POST "$U/api/db-backup/restore" -F 'file=@db.sql')
chk "a restore on a replicating node is refused (409)" 409 "$RM"
chk "  and the refusal names the procedure to use"   yes "$(has "$(cat rm.json)" 'fastpki-mesh --restore')"
chk "  and nothing was restored"                     no  "$(has "$(curl -s -b a.cj "$U/api/config/db")" '91,17')"
pg_exec "DROP PUBLICATION fastpki_pub;" >/dev/null
chk "without the publication the same restore runs"  yes \
    "$(has "$(curl -s -b a.cj -X POST "$U/api/db-backup/restore" -F 'file=@db.sql')" 'restored')"

echo
echo "=== DB RESTORE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
