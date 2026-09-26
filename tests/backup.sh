#!/usr/bin/env bash
# Config backup & restore. fastpki-config backup writes a JSON dump of
# the management/config tables (config overlay, web_users, ca_instances, roles +
# their grants, subject_roles, ms_templates); restore upserts them into another DB. This
# seeds a source DB, backs it up, restores into a fresh DB, and asserts every
# section round-trips.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: this suite mints its own fixture CA with openssl but never set OSSL — under
# `set -u` that is an immediate "unbound variable" on any box that does not export it.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
CFG="$ROOT/build/fastpki-config"
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup backup; PG_CONNINFO_SRC="$PG_CONNINFO"; SRC_DB="$PGDATABASE"
P=
trap 'PGDATABASE="$DST_DB"; pg_cleanup; PGDATABASE="$SRC_DB"; pg_cleanup; kill $P 2>/dev/null' EXIT
printf 'PG_CONNINFO=%s\nLOG_LEVEL=err\n' "$PG_CONNINFO" > src.conf

echo "=== seed the source DB ==="
"$CFG" --config src.conf set CERT_VALIDITY_DAYS 365 >/dev/null
"$CFG" --config src.conf set WEB_ALLOW_REVOKE true >/dev/null
pg_exec "INSERT INTO web_users(username,role,hash,must_reset,created) VALUES('alice','admin','pbkdf2\$1\$aa\$bb',1,0);"
# A directory-onboarded account: its sign-in provider is part of what a restore must bring back.
pg_exec "INSERT INTO web_users(username,role,hash,must_reset,created,auth_provider)
         VALUES('corp\\carol','none','!external',0,0,'ldap');"
# A CA is a `certs` row carrying its own certificate, so the fixture needs a real
# one — and that is what makes the round-trip meaningful: restore has to rebuild the row
# from the PEM the backup carries, not just copy a registry entry.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout depta.key -out depta.pem -days 3650 \
    -subj "/CN=Dept A CA" >/dev/null 2>&1
DEPTA_DER=$("$OSSL" x509 -in depta.pem -outform DER | xxd -p | tr -d '\n')
DEPTA_SER=$("$OSSL" x509 -in depta.pem -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,cn,cert,
                           id,name,ca_enabled,private_key,is_ca,ca_instance_id)
         VALUES('$DEPTA_SER',0,$(date +%s),$(( $(date +%s) + 315360000 )),
                'CN=Dept A CA','Dept A CA','\\x$DEPTA_DER'::bytea,
                'dept-a','Dept A CA',true,'pkcs11:token=t;object=dept-a;type=private',
                true,'dept-a')
         ON CONFLICT (serial) DO NOTHING;"
# A subject's issuance profile is a `profile:use` grant on a role it holds, so what
# has to survive the round-trip is a CUSTOM role, its grants, and the membership — three
# tables where there used to be one row. The role is deliberately non-builtin: a builtin
# would be seeded by createdb.sql in the destination too, so it could round-trip
# vacuously while the backup carried nothing at all.
pg_exec "INSERT INTO roles(name,description,builtin,max_certs,max_cn,max_san) VALUES('fieldops','Field ops',false,5,2,3);"
pg_exec "INSERT INTO role_permissions(role,permission,scope) VALUES
           ('fieldops','profile:use','admin'),('fieldops','est:enrol','*');"
pg_exec "INSERT INTO subject_roles(selector_type,selector_value,role,created)
         VALUES('user','bob','fieldops',0);"
printf 'name,oid,validity_days,ekus\nBackupTpl,1.3.6.1.4.1.311.21.8.77.1,400,TLS Web Server Authentication\n' > t.csv
"$CFG" --config src.conf templates-import t.csv >/dev/null
# A certificate profile: its own table since profiles left `config`, so the role grant
# above could otherwise come back naming a profile the destination does not have.
printf '{"fieldprof":{"allowed_ku":["digitalSignature"],"allowed_eku":["clientAuth"],"max_validity_days":77}}' > p.json
"$CFG" --config src.conf profiles-import p.json >/dev/null

echo "=== backup → restore into a fresh DB ==="
"$CFG" --config src.conf backup --out backup.json 2>/dev/null
chk "backup file is valid JSON with a marker" yes "$(grep -q '"fastpki_backup"' backup.json && echo yes || echo no)"
pg_setup backup2; DST_DB="$PGDATABASE"
printf 'PG_CONNINFO=%s\nLOG_LEVEL=err\n' "$PG_CONNINFO" > dst.conf
chk "destination starts empty (no users)" "0" "$(pg_exec 'SELECT count(*) FROM web_users;')"
R=$("$CFG" --config dst.conf restore backup.json 2>&1)
echo "    $R"

echo "=== every section round-trips into the destination ==="
chk "config key restored (CERT_VALIDITY_DAYS=365)" "365" "$("$CFG" --config dst.conf get CERT_VALIDITY_DAYS)"
chk "config key restored (WEB_ALLOW_REVOKE=true)"  "true" "$("$CFG" --config dst.conf get WEB_ALLOW_REVOKE)"
chk "web user restored (alice=admin)"   "admin"     "$(pg_exec "SELECT role FROM web_users WHERE username='alice';")"
chk "web user role + must_reset kept"   "admin|1"   "$(pg_exec "SELECT role||'|'||must_reset FROM web_users WHERE username='alice';")"
chk "CA instance restored (dept-a)"     "Dept A CA" "$(pg_exec "SELECT coalesce(name,'') FROM certs WHERE id='dept-a' AND is_ca;")"
chk "custom role restored (fieldops)"   "Field ops" "$(pg_exec "SELECT description FROM roles WHERE name='fieldops';")"
# The GRANTS are the point: a role restored with no permissions is a role that grants
# nothing, which reads as present in the console and denies every request underneath it.
chk "its grants restored (2, incl. the profile)" "est:enrol=*,profile:use=admin" \
    "$(pg_exec "SELECT string_agg(permission||'='||scope, ',' ORDER BY permission) FROM role_permissions WHERE role='fieldops';")"
chk "role membership restored (bob→fieldops)" "fieldops" "$(pg_exec "SELECT role FROM subject_roles WHERE selector_value='bob';")"
# ALL THREE issuance limits. Only max_certs was carried, and the restore's upsert wrote the
# other two as NULL — a restore quietly lifted every per-name and SAN limit it touched.
chk "all three issuance limits restored (5|2|3)" "5|2|3" \
    "$(pg_exec "SELECT max_certs||'|'||max_cn||'|'||max_san FROM roles WHERE name='fieldops';")"
chk "a directory account keeps its sign-in provider" "ldap" \
    "$(pg_exec "SELECT coalesce(auth_provider,'') FROM web_users WHERE username='corp\\carol';")"
chk "builtin roles are not duplicated"  "1" "$(pg_exec "SELECT count(*) FROM roles WHERE name='admin';")"
chk "MS template restored (BackupTpl)"  "1.3.6.1.4.1.311.21.8.77.1" "$(pg_exec "SELECT oid FROM ms_templates WHERE name='BackupTpl';")"
chk "template detail kept (validity 400)" "400" "$(pg_exec "SELECT validity_days FROM ms_templates WHERE name='BackupTpl';")"
chk "certificate profile restored (fieldprof, max validity 77)" yes \
    "$(pg_exec "SELECT definition FROM cert_profiles WHERE name='fieldprof';" | grep -q '"max_validity_days":77' && echo yes || echo no)"

echo "=== restore is idempotent (re-running changes nothing) ==="
"$CFG" --config dst.conf restore backup.json >/dev/null 2>&1
chk "still exactly one alice after a second restore" "1" "$(pg_exec "SELECT count(*) FROM web_users WHERE username='alice';")"
chk "a non-backup file is rejected" no "$(echo '{}' > nb.json; "$CFG" --config dst.conf restore nb.json >/dev/null 2>&1 && echo yes || echo no)"

echo "=== the command line writes and reads the console's ENCRYPTED format ==="
# The CLI had no way to encrypt a backup, and `restore` fed a .fpkibak straight to the JSON
# parser — so a file downloaded from the Backup page could not be restored without a browser.
printf 'correct horse battery staple\n' > pw.txt
"$CFG" --config src.conf backup --out backup.fpkibak --passphrase-file pw.txt 2>/dev/null
chk "the encrypted file carries the FPKIBAK1 magic" yes \
    "$(head -c 8 backup.fpkibak | grep -q 'FPKIBAK1' && echo yes || echo no)"
chk "  and no cleartext of the backup" no \
    "$(grep -q 'fastpki_backup\|alice' backup.fpkibak && echo yes || echo no)"
chk "restoring it without a passphrase is refused" no \
    "$("$CFG" --config dst.conf restore backup.fpkibak >/dev/null 2>&1 && echo yes || echo no)"
printf 'wrong\n' > bad.txt
chk "  and with the wrong one" no \
    "$("$CFG" --config dst.conf restore backup.fpkibak --passphrase-file bad.txt >/dev/null 2>&1 && echo yes || echo no)"
pg_exec "DELETE FROM subject_roles WHERE selector_value='bob';" >/dev/null
chk "with the right one it restores" yes \
    "$("$CFG" --config dst.conf restore backup.fpkibak --passphrase-file pw.txt >/dev/null 2>&1 && echo yes || echo no)"
chk "  and the data is back" "fieldops" "$(pg_exec "SELECT role FROM subject_roles WHERE selector_value='bob';")"
# decrypt-backup is the disaster-recovery step, so it must work with NO database: the
# --config here names a file that does not exist.
"$CFG" --config /nonexistent.conf decrypt-backup backup.fpkibak --passphrase-file pw.txt --out plain.json 2>/dev/null
chk "decrypt-backup needs no database and yields the JSON" yes \
    "$(grep -q '"fastpki_backup"' plain.json 2>/dev/null && echo yes || echo no)"
chk "  written owner-only" 600 "$(stat -c %a plain.json 2>/dev/null || stat -f %Lp plain.json)"
chk "  a wrong passphrase writes nothing" no \
    "$("$CFG" --config /nonexistent.conf decrypt-backup backup.fpkibak --passphrase-file bad.txt --out never.json >/dev/null 2>&1; [ -e never.json ] && echo yes || echo no)"

echo
echo "=== BACKUP: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
