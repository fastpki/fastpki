#!/usr/bin/env bash
# Expand: the three columns that let `certs` hold CA rows, and the one column
# of the three that must NOT leave this node.
#
# `certs` and `ca_instances` hold the same thing — an X.509 object with metadata — and
# keeping them apart meant keeping them in sync, which on the lab they were not: test-03
# held 1361 certs whose `ca_instances` row had never arrived, and a node in that state can
# be neither dumped nor restored. This is the expand half: the columns arrive nullable and
# unread, so an old binary sharing the database during a rollout neither sees nor cares.
#
# What this asserts:
#   1. a fresh createdb.sql database HAS the columns and indexes, and says version 2;
#   2. step 0002 brings an OLDER database to the same place, and is re-runnable;
#   3. the mesh publication ships `id` and `is_ca` and does NOT ship `private_key`;
#   4. the binaries still start — this is an expand, so kSchemaVersion must NOT have moved.
#
# 3 is the one with teeth. `certs` was published BARE, so the moment `private_key` existed
# a bare publication would have started replicating it and nothing would have said so. It
# names a pkcs11 object in THIS node's token: a peer receiving it gets a row claiming a
# signing capability it does not have, and the lie only surfaces at issuance, from inside
# the provider. The assertion is made against the REAL generated SQL, not a grep of the
# source, because the source is not what Postgres reads.
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
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup certs_ca_columns
trap 'pg_cleanup; kill ${P:-} 2>/dev/null' EXIT

col(){ pg_exec "SELECT data_type FROM information_schema.columns WHERE table_name='certs' AND column_name='$1';" | tr -d ' '; }
idx(){ pg_exec "SELECT count(*) FROM pg_indexes WHERE tablename='certs' AND indexname='$1';" | tr -d ' '; }
# Apply a step file the way deploy/schema-apply.sh does — one transaction, so the
# change and its schema_version row commit together or not at all.
apply_step(){ "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
    --single-transaction -q -v ON_ERROR_STOP=1 -f "$1" >/dev/null; }

echo "=== 1. a fresh database is born with the columns ==="
chk "certs.id is text"               text    "$(col id)"
chk "certs.private_key is text"      text    "$(col private_key)"
chk "certs.is_ca is boolean"         boolean "$(col is_ca)"
chk "is_ca has a NOT NULL default"   "false" "$(pg_exec "SELECT column_default FROM information_schema.columns WHERE table_name='certs' AND column_name='is_ca';" | tr -d ' ')"
chk "certs_id_idx exists"            1 "$(idx certs_id_idx)"
chk "certs_is_ca_idx exists"         1 "$(idx certs_is_ca_idx)"
# ⚠️ EQUALITY NOW, and that is the whole point. createdb.sql is the ONLY definition of the
# schema — the 39 steps that carried already-deployed databases forward were collapsed into
# it — so a fresh database must be born at exactly the version the binary requires. Any
# other number and the startup guard tells a brand-new install to run a migration that does
# not exist. This used to be `>= 2` because the head version moved every time a step landed.
NEED=$(sed -n 's/^constexpr int kSchemaVersion = \([0-9]*\);.*/\1/p' "$ROOT/include/pki/schema.hpp" | head -1)
chk "a fresh schema is born at exactly kSchemaVersion" "$NEED" \
    "$(pg_exec "SELECT COALESCE(MAX(version),0) FROM schema_version;" | tr -d ' ')"

# Needs TWO live rows sharing one id for the length of a CA rollover, so a unique
# index on `id` would make the renewal INSERT fail. Prove it is not unique by doing the
# thing a rekey will do.
echo "=== 2. the id column is indexed but NOT unique — a rollover needs that ==="
pg_exec "INSERT INTO certs(serial,status,id,is_ca,\"notBefore\") VALUES('aa',0,'issuing',true,1),('bb',0,'issuing',true,2);" >/dev/null 2>&1
chk "two live CA rows may share an id" 2 "$(pg_exec "SELECT count(*) FROM certs WHERE id='issuing';" | tr -d ' ')"
chk "the newest is selectable"      bb "$(pg_exec "SELECT serial FROM certs WHERE id='issuing' AND is_ca ORDER BY \"notBefore\" DESC LIMIT 1;" | tr -d ' ')"
pg_exec "DELETE FROM certs WHERE id='issuing';" >/dev/null 2>&1

echo "=== 5. and what a FRESH mesh setup emits agrees with it ==="
printf 'dc1|host=127.0.0.1 dbname=a sslmode=disable|1|http://dc1.example\ndc2|host=127.0.0.1 dbname=b sslmode=disable|2|http://dc2.example\n' > topo.txt
# --allow-plaintext-transport because this is a rendering check, not a deployment;
# mesh otherwise refuses sslmode=disable, and it is right to (the link carries password
# hashes). Rendering the SQL is all we need.
PUB=$("$ROOT/build/fastpki-mesh" --topology topo.txt --publication --allow-plaintext-transport 2>/dev/null)
chk "a publication was generated"    yes "$(echo "$PUB" | grep -q 'CREATE PUBLICATION' && echo yes || echo no)"
# The column list belongs to `certs` specifically, so cut it out rather than searching the
# whole statement — `private_key` must be absent from THIS list, not merely from the file.
CERTCOLS=$(echo "$PUB" | sed -n 's/.*FOR TABLE certs (\([^)]*\)).*/\1/p')
chk "certs is published by column list" yes "$([ -n "$CERTCOLS" ] && echo yes || echo no)"
chk "id replicates"        yes "$(echo "$CERTCOLS" | tr ',' '\n' | grep -qx ' *id' && echo yes || echo no)"
chk "is_ca replicates"     yes "$(echo "$CERTCOLS" | tr ',' '\n' | grep -qx ' *is_ca' && echo yes || echo no)"
chk "private_key does NOT" yes "$(echo "$CERTCOLS" | grep -q 'private_key' && echo no || echo yes)"
# The PK must be in any column list or logical replication cannot locate a row.
chk "serial (the PK) is listed" yes "$(echo "$CERTCOLS" | tr ',' '\n' | grep -qx 'serial' && echo yes || echo no)"

echo "=== 6. migrate: a CA's own cert row carries its identity ==="
# The columns are useless until something fills them. A CA created now must land in
# `certs` with its id, its key location and is_ca — and the leaves it issues must not.
ca_in_token ca.pem "/CN=Merge CA" 3650 mergeca
source "$ROOT/tests/user_helpers.sh"
seed_web_user boss bosspw admin
PORT=18101
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=mergeca
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf
"$ROOT/build/fastpki-web" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
U="http://127.0.0.1:$PORT"
curl -s -c cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null
NEWREF=$(hsm_new_key_uri mergedca)
C=$(curl -s -o /dev/null -w '%{http_code}' -b cj "$U/api/ca-instances" \
    --data-urlencode 'id=merged' --data-urlencode 'subject=/CN=Merged CA' \
    --data-urlencode 'key=ec' --data-urlencode 'curve=P-256' \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode 'keygen=true' \
    --data-urlencode "keyref=$NEWREF")
chk "console created a CA"        201 "$C"
q1(){ pg_exec "SELECT COALESCE($1,'<null>') FROM certs WHERE ca_instance_id='merged' AND is_ca;" | tr -d ' '; }
chk "its cert row is flagged is_ca" 1 "$(pg_exec "SELECT count(*) FROM certs WHERE ca_instance_id='merged' AND is_ca;" | tr -d ' ')"
chk "...carries the CA id"     merged "$(q1 id)"
chk "...carries the key handle"   yes "$(q1 private_key | grep -q '^pkcs11:' && echo yes || echo no)"

# A leaf under that CA must NOT look like one.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout leaf.key -subj "/CN=leaf.internal" -out leaf.csr >/dev/null 2>&1
curl -s -o /dev/null -b cj -X POST --data-binary @leaf.csr "$U/api/certs/request?ca_instance=merged"
# Count the leaf ROW and require is_ca=false on it, rather than counting rows matching
# `NOT is_ca AND is_ca` — a contradiction no row can satisfy, so that count was 0 however
# issuance flagged the leaf. Expecting 1 also refuses a leaf that was never stored.
chk "the leaf is NOT flagged is_ca" 1 "$(pg_exec "SELECT count(*) FROM certs WHERE ca_instance_id='merged' AND cn='leaf.internal' AND NOT is_ca;" | tr -d ' ')"
chk "exactly one is_ca row for that CA" 1 "$(pg_exec "SELECT count(*) FROM certs WHERE ca_instance_id='merged' AND is_ca;" | tr -d ' ')"
chk "the leaf has no CA id"    "<null>" "$(pg_exec "SELECT COALESCE(id,'<null>') FROM certs WHERE ca_instance_id='merged' AND NOT is_ca LIMIT 1;" | tr -d ' ')"

# Sections 7 and 8 tested `fastpki-ca backfill-ca-columns`, which is gone: it
# migrated the old `ca_instances` rows into `certs`, and since the contract half the
# CA IS the certs row — there is nothing to migrate from. What those sections really
# proved (a CA registered with an INLINE PEM, and a CA whose row was absent entirely)
# is now covered where it belongs: tests/ca_no_fk.sh builds both shapes against the
# live schema.

echo "=== 9. the mesh range guard must EXEMPT a CA's own certificate ==="
# A multi-DC node refuses any cert whose serial is outside its slice, so two DCs can never
# mint the same one. But a CA's own certificate is a row in `certs` too and this DC did not
# necessarily mint it — a sub CA signed by another node's root carries that root's serial,
# outside every DC's range. The guard refused the CA row on DC2 and DC3, and only a real
# mesh could show that.
#
# ⚠️ ASSERTED AGAINST THE GENERATOR, which is the only thing that creates this trigger.
# It used to be asserted by rewinding a database and applying step 0002 — but a step only
# ever repaired an ALREADY-DEPLOYED node, and with the steps collapsed into createdb.sql
# the generator is the whole story for every deployment that now exists.
TRG=$("$ROOT/build/fastpki-mesh" --topology topo.txt --all --allow-plaintext-transport 2>/dev/null)
chk "the generator emits the range guard" yes \
    "$(echo "$TRG" | grep -q 'fastpki_dc_range_guard' && echo yes || echo no)"
chk "  it exempts a CA row"               yes \
    "$(echo "$TRG" | grep -q 'NEW.is_ca' && echo yes || echo no)"
chk "  and a service certificate"         yes \
    "$(echo "$TRG" | grep -q 'NEW.cert_id IS NOT NULL' && echo yes || echo no)"
# Anti-vacuity: exempting those two must not have disarmed the guard for everything else.
chk "  while still refusing a foreign serial" yes \
    "$(echo "$TRG" | grep -q "does not carry this data center" && echo yes || echo no)"

echo

# ── schema-apply refuses a database missing a table createdb.sql declares ────────────────
#
# ⚠️ THE GAP THAT ONLY SHOWS AS A CRASH LOOP. createdb.sql runs against an empty database
# only, and a table reaches an existing deployment only through a step. A table added without
# one never reaches it, and schema_version does not move either, so nothing detects it: schema-apply said "nothing to apply", the roll proceeded,
# and the first service to read the missing table died part-way through, leaving the
# deployment on two different images. Measured on a deployment a few days old, with five
# tables absent.
#
# Refusing BEFORE anything rolls turns that into a list of names.
echo "=== schema-apply refuses a database that is missing a declared table ==="
pg_exec "DROP TABLE IF EXISTS notify_sent;" >/dev/null 2>&1
SA_PSQL="$_PSQL_BIN -h $PGHOST -p $PGPORT -U $PGUSER -d $PGDATABASE"
OUT=$(PSQL="$SA_PSQL" MESH_BIN=true bash "$ROOT/deploy/schema-apply.sh" 2>&1); SA_RC=$?
chk "it refuses rather than reporting nothing to apply" 1 "$SA_RC"
chk "  and names the missing table" yes \
    "$(echo "$OUT" | grep -q 'notify_sent' && echo yes || echo no)"
chk "  and says nothing was rolled" yes \
    "$(echo "$OUT" | grep -q 'NOTHING has been rolled' && echo yes || echo no)"
[ "$SA_RC" = 1 ] || { echo "  --- schema-apply output ---"; echo "$OUT" | tail -6; }

# CONTROL: with the table back, the same call succeeds — so the refusal is the missing table
# and not schema-apply being broken in this fixture.
pg_exec "CREATE TABLE IF NOT EXISTS notify_sent(serial text NOT NULL, kind text NOT NULL, sent_at bigint NOT NULL, PRIMARY KEY(serial, kind));" >/dev/null 2>&1
OUT=$(PSQL="$SA_PSQL" MESH_BIN=true bash "$ROOT/deploy/schema-apply.sh" 2>&1); SA_RC=$?
chk "a complete database is applied without complaint" 0 "$SA_RC"
[ "$SA_RC" = 0 ] || { echo "  --- schema-apply output ---"; echo "$OUT" | tail -6; }

# ── an upgrade: a database from the previous release is carried forward by the steps ──
# Releases are public, so an existing deployment upgrades with the documented two steps:
# schema-apply.sh, then the new binaries. Make this database look like v0.2.3's — version 1,
# without the tables step 0002 creates — and the first step must bring it to version 2.
echo "=== schema-apply carries a v0.2.3 database to v0.3.0's schema ==="
pg_exec "DROP TABLE IF EXISTS acme_device_tickets; DROP TABLE IF EXISTS acme_device_serials;
         DELETE FROM schema_version; INSERT INTO schema_version(version,name,applied) VALUES (1,'baseline',0);" >/dev/null 2>&1
chk "PRECONDITION: the database is at version 1 without the new tables" "1|0" \
    "$(pg_exec "SELECT max(version) FROM schema_version;")|$(pg_exec "SELECT count(*) FROM pg_tables WHERE tablename IN ('acme_device_tickets','acme_device_serials');")"
OUT=$(PSQL="$SA_PSQL" MESH_BIN=true bash "$ROOT/deploy/schema-apply.sh" 2>&1); SA_RC=$?
chk "schema-apply succeeds" 0 "$SA_RC"
[ "$SA_RC" = 0 ] || { echo "  --- schema-apply output ---"; echo "$OUT" | tail -8; }
chk "  it applied step 0002" yes "$(echo "$OUT" | grep -q 'applying 0002-acme-device-attestation.sql' && echo yes || echo no)"
chk "  the database is now at version 2" 2 "$(pg_exec "SELECT max(version) FROM schema_version;")"
chk "  with both new tables" 2 \
    "$(pg_exec "SELECT count(*) FROM pg_tables WHERE tablename IN ('acme_device_tickets','acme_device_serials');")"
OUT=$(PSQL="$SA_PSQL" MESH_BIN=true bash "$ROOT/deploy/schema-apply.sh" 2>&1); SA_RC=$?
chk "  and a second run has nothing left to do" yes \
    "$([ "$SA_RC" = 0 ] && echo "$OUT" | grep -q 'up to date' && echo yes || echo no)"
echo "=== CERTS CA COLUMNS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
