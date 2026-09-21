#!/usr/bin/env bash
# Config backup & restore from the web console. An admin downloads a
# JSON backup (GET /api/backup) and restores it into another instance
# (POST /api/backup/restore). Other roles can't; restore needs WEB_ALLOW_REVOKE.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PA=18300; PB=18301
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

pg_setup web_backup; PG_CONNINFO_A="$PG_CONNINFO"
pg_setup web_backup2
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
mkweb(){ printf 'PG_CONNINFO=%s\nWEB_BIND=127.0.0.1\nWEB_PORT=%s\nWEB_ALLOW_REVOKE=true\nLOG_LEVEL=err\n' "$1" "$2"; }
mkweb "$PG_CONNINFO_A" "$PA" > a.conf; mkweb "$PG_CONNINFO" "$PB" > b.conf
"$WEB" --config a.conf >a.log 2>&1 & PIDA=$!
"$WEB" --config b.conf >b.log 2>&1 & PIDB=$!
sleep 1; trap 'pg_cleanup; kill $PIDA $PIDB 2>/dev/null' EXIT
UA="http://127.0.0.1:$PA"; UB="http://127.0.0.1:$PB"

echo "=== seed source instance A ==="
# Backup/restore dumps and upserts EVERY tenant's users + CAs, so it is a
# admin surface (backup is the instance DB, single-tenant).
code -X POST "$UA/api/users" -d 'username=boss&password=bosspw12&role=admin' >/dev/null
curl -s -c a.cj -X POST "$UA/api/login" -d 'username=boss&password=bosspw12' >/dev/null
code -b a.cj -X POST "$UA/api/users" -d 'username=al&password=alpw123456&role=requester' >/dev/null
curl -s -c al.cj -X POST "$UA/api/login" -d 'username=al&password=alpw123456' >/dev/null
curl -s -b a.cj -X PUT "$UA/api/config/db" --data 'key=NOTIFY_DAYS&value=21,7' >/dev/null
printf 'name,oid,validity_days,ekus\nBkUiTpl,1.3.6.1.4.1.311.21.8.88.1,500,TLS Web Server Authentication\n' > t.csv
curl -s -b a.cj -X POST --data-binary @t.csv "$UA/api/templates/import" >/dev/null

echo "=== admin downloads a backup from A ==="
BK=$(curl -s -b a.cj "$UA/api/backup")
chk "backup has the marker"            yes "$(has "$BK" 'fastpki_backup')"
chk "backup carries the config key"    yes "$(has "$BK" 'NOTIFY_DAYS')"
chk "backup carries the user"          yes "$(has "$BK" '"username": "al"')"
chk "backup carries the MS template"   yes "$(has "$BK" 'BkUiTpl')"
curl -s -b a.cj "$UA/api/backup" -o backup.json

echo "=== RBAC on /api/backup ==="
chk "requester cannot download a backup (403)" 403 "$(code -b al.cj "$UA/api/backup")"
chk "unauthenticated cannot download a backup"     401 "$(code "$UA/api/backup")"

echo "=== restore the backup into the fresh instance B ==="
code -X POST "$UB/api/users" -d 'username=boss2&password=boss2pw12&role=admin' >/dev/null
curl -s -c b.cj -X POST "$UB/api/login" -d 'username=boss2&password=boss2pw12' >/dev/null
# /api/templates falls back to the built-in defaults when the DB is empty,
# so assert B lacks the *imported* template rather than an empty list.
chk "B lacks the imported template before restore" no "$(has "$(curl -s -b b.cj "$UB/api/templates")" 'BkUiTpl')"
R=$(curl -s -b b.cj -X POST --data-binary @backup.json "$UB/api/backup/restore")
chk "restore reports success" yes "$(has "$R" 'restored:')"
chk "B now serves the imported template" yes "$(has "$(curl -s -b b.cj "$UB/api/templates")" 'BkUiTpl')"
chk "B restored the config key" yes "$(has "$(curl -s -b b.cj "$UB/api/config/db")" 'NOTIFY_DAYS')"
chk "B restored the user al (can log in with A's password)" 200 \
    "$(code -c bal.cj -X POST "$UB/api/login" -d 'username=al&password=alpw123456')"
# a malformed restore body is rejected
chk "a non-backup restore body -> 400" 400 "$(code -b b.cj -X POST --data 'not json' "$UB/api/backup/restore")"

echo
echo "=== WEB BACKUP: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
