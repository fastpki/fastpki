#!/usr/bin/env bash
# Encrypted config backup + file upload/download.
#
# A backup carries console password hashes and the tokens kept in settings, so it must
# be safe to hand to backup storage. The console can encrypt it with a passphrase given
# at backup time and demanded again at restore time; the passphrase is never stored
# server-side. This suite guards the real bytes and the real failure modes:
#   * an encrypted backup must not leak any plaintext secret,
#   * the right passphrase restores, a wrong one is refused with a clear message,
#   * a TAMPERED file is refused rather than half-restored (AES-GCM tag),
#   * the passphrase never travels in a URL (POST, not GET),
#   * unencrypted files and raw-JSON bodies keep working (console + CLI compat),
#   * a non-admin cannot back up or restore.
#
# Self-contained (§3d) + shell-only (§3e): ephemeral Postgres, own port, temp dir,
# SKIPs cleanly when no Postgres is reachable.
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
W="$(mktemp -d)"; cd "$W"; PORT=18296
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
roleof(){ curl -s -b admin.cj "$U/api/users" | tr '{' '\n' | grep "\"$1\"" | sed -n 's/.*"role":"\([^"]*\)".*/\1/p'; }

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi

pg_setup backup_encrypted
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
seed_web_user admin adminpw12 admin
seed_web_user alice alicepw123 auditor
"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c admin.cj -X POST "$U/api/login" -d 'username=admin&password=adminpw12' >/dev/null
curl -s -c alice.cj -X POST "$U/api/login" -d 'username=alice&password=alicepw123' >/dev/null

PASSPHRASE='correct horse battery staple'

echo "=== an unencrypted backup is still plain JSON (GET and POST agree) ==="
curl -s -b admin.cj -X POST "$U/api/backup" -d 'passphrase=' -o plain.json -D h.plain
chk "POST with no passphrase returns JSON"  '{' "$(head -c1 plain.json)"
chk "it is named .json"                     yes "$(grep -qi 'filename="fastpki-backup.json"' h.plain && echo yes || echo no)"
chk "GET /api/backup still works"           200 "$(code -b admin.cj "$U/api/backup")"
# The plaintext backup really does carry secrets — that is why encryption matters.
chk "plain backup contains a password hash" yes "$(grep -q 'pbkdf2' plain.json && echo yes || echo no)"
# The plaintext download is the one that most needs a trace, and it was the one without.
chk "an unencrypted download is audited (POST and GET)" 2 \
    "$(pg_exec "SELECT count(*) FROM audit_log WHERE action='web_backup_downloaded' AND detail LIKE '%encrypted=0%';")"

echo "=== an encrypted backup leaks nothing in cleartext ==="
curl -s -b admin.cj -X POST "$U/api/backup" --data-urlencode "passphrase=$PASSPHRASE" -o enc.fpkibak -D h.enc
chk "carries the FPKIBAK1 magic"        FPKIBAK1 "$(head -c8 enc.fpkibak)"
chk "it is named .fpkibak"              yes "$(grep -qi 'filename="fastpki-backup.fpkibak"' h.enc && echo yes || echo no)"
chk "no password hash in the ciphertext" no  "$(grep -qa 'pbkdf2' enc.fpkibak && echo yes || echo no)"
chk "no username in the ciphertext"      no  "$(grep -qa 'alice' enc.fpkibak && echo yes || echo no)"
chk "no backup marker in the ciphertext" no  "$(grep -qa 'fastpki_backup' enc.fpkibak && echo yes || echo no)"
# Two encryptions of the same data must differ (random salt+IV), or the file would leak
# equality between backups.
curl -s -b admin.cj -X POST "$U/api/backup" --data-urlencode "passphrase=$PASSPHRASE" -o enc2.fpkibak
chk "two encryptions are not identical"  no  "$(cmp -s enc.fpkibak enc2.fpkibak && echo yes || echo no)"

echo "=== the passphrase never travels in a URL ==="
# GET has no way to pass one: it is POST-only, so it cannot land in an access log.
chk "GET ignores a ?passphrase= query" '{' "$(curl -s -b admin.cj "$U/api/backup?passphrase=hunter2" | head -c1)"

echo "=== restore: right passphrase brings the data back ==="
# Change alice out from under the backup, then restore and prove she is put back.
curl -s -b admin.cj -X POST "$U/api/users" -d 'username=alice&role=requester' >/dev/null
chk "alice was changed to requester" requester "$(roleof alice)"
out=$(curl -s -b admin.cj -X POST "$U/api/backup/restore" -F "file=@enc.fpkibak" -F "passphrase=$PASSPHRASE")
chk "encrypted restore reports success" yes "$(echo "$out" | grep -q '"restored"' && echo yes || echo no)"
chk "alice is back to auditor"          auditor "$(roleof alice)"

echo "=== restore: the ways it must fail ==="
curl -s -b admin.cj -X POST "$U/api/users" -d 'username=alice&role=requester' >/dev/null
chk "wrong passphrase -> 400"    400 "$(code -b admin.cj -X POST "$U/api/backup/restore" -F "file=@enc.fpkibak" -F 'passphrase=wrong')"
chk "  and says the passphrase is wrong" yes "$(curl -s -b admin.cj -X POST "$U/api/backup/restore" -F "file=@enc.fpkibak" -F 'passphrase=wrong' | grep -q 'wrong passphrase' && echo yes || echo no)"
chk "missing passphrase -> 400"  400 "$(code -b admin.cj -X POST "$U/api/backup/restore" -F "file=@enc.fpkibak")"
chk "  and says it is encrypted"         yes "$(curl -s -b admin.cj -X POST "$U/api/backup/restore" -F "file=@enc.fpkibak" | grep -q 'encrypted' && echo yes || echo no)"
chk "no file at all -> 400"      400 "$(code -b admin.cj -X POST "$U/api/backup/restore" -F 'passphrase=x')"
# A failed restore must not have applied anything.
chk "a failed restore changed nothing" requester "$(roleof alice)"

echo "=== a tampered file is refused, not half-restored (AES-GCM tag) ==="
cp enc.fpkibak tamper.fpkibak
# XOR the byte rather than overwriting it with \x00: the ciphertext is random, so one
# run in 256 that byte ALREADY was \x00, the "tampered" file was byte-identical to the
# original, it decrypted cleanly and this suite failed for no reason. Flipping always
# changes it.
tb=$(dd if=tamper.fpkibak bs=1 skip=100 count=1 2>/dev/null | od -An -tu1 | tr -d ' \n')
printf "$(printf '\\x%02x' $(( tb ^ 0xFF )))" | dd of=tamper.fpkibak bs=1 seek=100 conv=notrunc 2>/dev/null
chk "flipped ciphertext byte -> 400" 400 "$(code -b admin.cj -X POST "$U/api/backup/restore" -F "file=@tamper.fpkibak" -F "passphrase=$PASSPHRASE")"
chk "tampering left the data alone"  requester "$(roleof alice)"
head -c 40 enc.fpkibak > trunc.fpkibak
chk "truncated file -> 400"          400 "$(code -b admin.cj -X POST "$U/api/backup/restore" -F "file=@trunc.fpkibak" -F "passphrase=$PASSPHRASE")"

echo "=== unencrypted + CLI paths keep working ==="
chk "plain .json upload restores"  200 "$(code -b admin.cj -X POST "$U/api/backup/restore" -F "file=@plain.json")"
chk "  and it restored alice"      auditor "$(roleof alice)"
curl -s -b admin.cj -X POST "$U/api/users" -d 'username=alice&role=requester' >/dev/null
chk "raw JSON body still restores" 200 "$(code -b admin.cj -X POST "$U/api/backup/restore" --data-binary @plain.json)"
chk "  and it restored alice"      auditor "$(roleof alice)"
chk "garbage upload -> 400"        400 "$(printf 'not a backup' > junk.json; code -b admin.cj -X POST "$U/api/backup/restore" -F "file=@junk.json")"

echo "=== backup/restore is admin-only ==="
chk "auditor cannot POST a backup"  403 "$(code -b alice.cj -X POST "$U/api/backup" -d 'passphrase=x')"
chk "auditor cannot GET a backup"   403 "$(code -b alice.cj "$U/api/backup")"
chk "auditor cannot restore"        403 "$(code -b alice.cj -X POST "$U/api/backup/restore" -F "file=@plain.json")"

echo "=== full database backup: pg_dump, download-only ==="
if ! command -v pg_dump >/dev/null 2>&1; then
  echo "  SKIP: pg_dump not on this host (it IS installed in the runtime image)"
else
  curl -s -b admin.cj -X POST "$U/api/db-backup" -d 'passphrase=' -o db.sql -D h.db
  chk "dump downloads as .sql"          yes "$(grep -qi 'filename="fastpki-db.sql"' h.db && echo yes || echo no)"
  chk "it contains schema"              yes "$([ "$(grep -c '^CREATE TABLE' db.sql)" -gt 5 ] && echo yes || echo no)"
  chk "it contains data"                yes "$([ "$(grep -c '^COPY ' db.sql)" -gt 5 ] && echo yes || echo no)"
  chk "it carries the console users"    yes "$(grep -qa 'alice' db.sql && echo yes || echo no)"
  # Replication subscriptions must be excluded. pg_dump writes CREATE SUBSCRIPTION with
  # the peer connection string INCLUDING the replication password, and restoring one
  # would have the restored database start replicating from its peers immediately. Found
  # on the lab, invisible here: a single-node test DB has no mesh, so only an assertion
  # about the pg_dump invocation catches it on every host.
  chk "no CREATE SUBSCRIPTION in the dump" no "$(grep -qa 'CREATE SUBSCRIPTION' db.sql && echo yes || echo no)"
  chk "dump asks pg_dump for --no-subscriptions" yes "$(grep -qa 'no-subscriptions' "$ROOT/src/web/main.cpp" && echo yes || echo no)"
  # NOTE: a full dump legitimately contains whatever is stored, and on a mesh node the
  # `datacenters` rows hold peer conninfo with the replication password. That is why
  # the console warns to encrypt it rather than pretending the dump is secret-free.
  chk "the console warns the dump holds credentials" yes "$(curl -s "$U/" | grep -qF 'including the replication' && echo yes || echo no)"

  # THE test that matters: a backup is only a backup if it restores. Load it into a
  # fresh database and prove the rows come back.
  RDB="${PGDATABASE}_restore"
  "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c "DROP DATABASE IF EXISTS $RDB" >/dev/null 2>&1
  "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c "CREATE DATABASE $RDB" >/dev/null 2>&1
  "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$RDB" -q -f db.sql >restore.log 2>&1
  chk "restores into a fresh database"  yes "$([ "$("$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$RDB" -tAc "select count(*) from information_schema.tables where table_schema='public'" 2>/dev/null)" -gt 5 ] && echo yes || echo no)"
  chk "and alice survives the restore"  auditor "$("$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$RDB" -tAc "select role from web_users where username='alice'" 2>/dev/null)"
  "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c "DROP DATABASE $RDB" >/dev/null 2>&1

  curl -s -b admin.cj -X POST "$U/api/db-backup" --data-urlencode "passphrase=$PASSPHRASE" -o db.enc -D h.dbe
  chk "encrypted dump is .sql.fpkibak"  yes "$(grep -qi 'filename="fastpki-db.sql.fpkibak"' h.dbe && echo yes || echo no)"
  chk "encrypted dump has the magic"    FPKIBAK1 "$(head -c8 db.enc)"
  chk "encrypted dump leaks no schema"  no  "$(grep -qa 'CREATE TABLE' db.enc && echo yes || echo no)"
  chk "encrypted dump leaks no user"    no  "$(grep -qa 'alice' db.enc && echo yes || echo no)"
  # Restoring it from the command line needs it decrypted first, and nothing could do that.
  printf '%s\n' "$PASSPHRASE" > pass.txt
  "$ROOT/build/fastpki-config" decrypt-backup db.enc --passphrase-file pass.txt --out db.dec.sql 2>/dev/null
  chk "fastpki-config decrypts the dump to SQL" yes \
      "$([ "$(grep -c '^CREATE TABLE' db.dec.sql 2>/dev/null)" -gt 5 ] && echo yes || echo no)"
  chk "auditor cannot dump the database" 403 "$(code -b alice.cj -X POST "$U/api/db-backup" -d 'passphrase=')"
fi
# Exposed DB restore (POST /api/db-backup/restore): atomic (psql --single-transaction),
# encrypted-backup + passphrase, rolls back on error. It takes the backup as an uploaded
# file (multipart 'file', like the UI); a non-file request (a stray urlencoded field) is
# malformed -> 400, not raw SQL fed to psql -> 500.
chk "DB-restore rejects a non-file request (400)"   400 "$(code -b admin.cj -X POST "$U/api/db-backup/restore" -d 'x=1')"

echo "=== the Backup page is action-buttons + modals, like the Users page ==="
curl -s "$U/" -o index.html
chk "no paste-JSON textarea"          no  "$(grep -qF 'placeholder="{&quot;fastpki_backup&quot;:1' index.html && echo yes || echo no)"
chk "a backup modal container ships"  yes "$(grep -qF 'id="bkmodal"' index.html && echo yes || echo no)"
# It used to assert the selector `#usermodal,#bkmodal{` — i.e. that the two
# modals were styled by one shared RULE. They now share the one .modal CLASS, so
# the styling is common by construction and there is no per-modal selector to grep.
chk "it reuses the shared modal shell"  yes "$(grep -qF 'id="bkmodal" class="modal"' index.html && echo yes || echo no)"
# One toolbar button per action, each opening a modal to configure and submit.
chk "Config backup action"            yes "$(grep -qF 'id="bknew"' index.html && echo yes || echo no)"
chk "Restore config action"           yes "$(grep -qF 'id="bkrestore"' index.html && echo yes || echo no)"
chk "Database backup action"          yes "$(grep -qF 'id="bkdb"' index.html && echo yes || echo no)"
chk "Restore-instructions action"     yes "$(grep -qF 'id="bkhelp"' index.html && echo yes || echo no)"
chk "create-backup modal builder"     yes "$(grep -qF 'function openBackupCreateModal' index.html && echo yes || echo no)"
chk "restore modal builder"           yes "$(grep -qF 'function openBackupRestoreModal' index.html && echo yes || echo no)"
chk "db-backup modal builder"         yes "$(grep -qF 'function openDbBackupModal' index.html && echo yes || echo no)"
chk "restore-help modal builder"      yes "$(grep -qF 'function openRestoreHelpModal' index.html && echo yes || echo no)"
# The fields live in the modals now, not inline on the page.
chk "a file picker is shipped"        yes "$(grep -qF 'id="bkfile"' index.html && echo yes || echo no)"
chk "a backup passphrase field"       yes "$(grep -qF 'id="bkpass"' index.html && echo yes || echo no)"
chk "a restore passphrase field"      yes "$(grep -qF 'id="bkrpass"' index.html && echo yes || echo no)"
chk "a DB passphrase field"           yes "$(grep -qF 'id="dbpass"' index.html && echo yes || echo no)"
chk "download POSTs the passphrase"   yes "$(grep -qF "fetch('/api/backup', { method:'POST'" index.html && echo yes || echo no)"
chk "the offline restore recipe ships" yes "$(grep -qF 'How to restore a database backup' index.html && echo yes || echo no)"
chk "the recipe names the decrypt step" yes "$(grep -qF 'fastpki-config decrypt-backup' index.html && echo yes || echo no)"
chk "a too-large file gets a reason, not HTTP 413" yes "$(grep -qF 'function bkTooLarge' index.html && echo yes || echo no)"
# Found in a browser, invisible to markup greps: the restore handler used to re-render on
# success, which rebuilt the panel and wiped the summary — the only confirmation there is.
chk "restore keeps its success message" yes "$(grep -qF 'the summary is the only' index.html && echo yes || echo no)"
chk "success is marked with a tick"     yes "$(grep -qF "(o.restored || 'restored')" index.html && echo yes || echo no)"

echo
echo "=== ENCRYPTED BACKUP: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
