#!/usr/bin/env bash
# Multi-data-center active-active replication against real Postgres.
# Validates the pieces that ARE checkable on a single node:
#   - serial-prefix minting: a node reads its prefix from its own `datacenters`
#     row and every serial it issues carries it (Task 1.6.1), so the certs PK never
#     collides across data centers;
#   - the generated guard trigger accepts this node's prefix and rejects a peer's;
#   - the public-only PUBLICATION and the `datacenters` map apply cleanly.
# Live cross-data-center streaming needs N clusters and is out of CI scope.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
# Only adopt the system openssl.cnf where it really is one. On macOS this path is a
# stub that defines no providers, and exporting it breaks every pkcs11 load — the
# CA key then cannot be minted and the suite SKIPs for a reason that looks nothing
# like "wrong openssl.cnf". Tests must not assume a Linux layout (§3d).
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
# NB --allow-plaintext-transport: fastpki-mesh refuses a topology whose conninfo
# does not request TLS, because inter-DC replication carries web_users (incl. the
# pbkdf2 password hash) and the conninfo embeds the replication password. These
# suites drive throwaway clusters on 127.0.0.1 — a genuinely closed link — so they
# take the documented override rather than weakening the guard. See mesh_tls.sh.
MESH="$ROOT/build/fastpki-mesh"
# Follow the helper's settings rather than hardcoding: 33bc9df moved the default
# role/database to fastpki for Docker compose, which left every suite that pinned
# user=pki failing with 'role "pki" does not exist'.
# ⚠️ A THROWAWAY database, not the developer's own. This suite used to run against
# $PGDATABASE, which defaults to `fastpki` -- so it truncated the developer's tables, and on
# any box with an incomplete PKCS#11 toolchain `ca_in_token`'s SKIP path called pg_cleanup
# and DROPPED that database outright. pg_setup gives it an `fpki_<name>_<pid>` of its own.
pg_setup replication
PGCONN="$PG_CONNINFO"
W="$(mktemp -d)"; cd "$W"; CMP=18101
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

PFX=5                                            # this node's serial prefix
PFXHEX=0005                                      # ...as the serial's top two octets
FOREIGN=00060000000000000000000000000000000000ab  # a peer's prefix, same width

# ⚠️ THIS SUITE SHARES THE DEVELOPER'S DATABASE — it has no pg_setup, and neither do
# pg_smoke.sh, pg_store_hash.sh, pg_store_uri.sh or pg_store_hash_selectors.sh. So every
# mesh object it installs is installed on THEIR database too, and the guard trigger it
# creates decides whether their INSERTs are allowed.
#
# That was survivable while the guard was a RANGE: this suite used [0000…, 8000…), so a
# random serial passed about half the time and the leak looked like flakiness. The prefix made
# the guard an exact 4-character prefix match, so a leaked trigger fails those four suites
# every single run — which is how the leak was finally found. The trap below therefore
# removes the FUNCTION and the TRIGGER, not just the publication and a CHECK constraint
# that was never created in the first place.
mesh_teardown() {
    pg_exec "DROP TRIGGER IF EXISTS certs_dc_range ON certs;"     >/dev/null 2>&1
    pg_exec "DROP FUNCTION IF EXISTS fastpki_dc_range_guard() CASCADE;" >/dev/null 2>&1
    pg_exec "ALTER TABLE certs DROP CONSTRAINT IF EXISTS certs_dc_range;" >/dev/null 2>&1
    pg_exec "DROP PUBLICATION IF EXISTS fastpki_pub;"             >/dev/null 2>&1
    pg_exec "DELETE FROM datacenters;"                            >/dev/null 2>&1
}

# clean slate (a previous run's objects may linger)
mesh_teardown
pg_exec "TRUNCATE certs;" >/dev/null

cat > topo.txt <<EOF
dc1|$PGCONN|$PFX|http://dc1.example
EOF

echo "=== apply generated DDL to Postgres ==="
# Per-node serial-prefix guard (single-DC topology -> no subscriptions emitted).
# It's a TRIGGER, not a CHECK, so replicated certs from other DCs' ranges don't
# stall the apply (see tests/replication_stream.sh for the live proof).
"$MESH" --allow-plaintext-transport --topology topo.txt --node dc1 | PGPASSWORD="$PGPASSWORD" "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" >/dev/null 2>&1
chk "certs_dc_range INSERT trigger created" 1 "$(pg_exec "select count(*) from pg_trigger where tgname='certs_dc_range' and not tgisinternal;")"
chk "no legacy prefix CHECK constraint remains" 0 "$(pg_exec "select count(*) from pg_constraint where conname='certs_dc_range';")"
# Public-only publication.
"$MESH" --allow-plaintext-transport --topology topo.txt --publication | PGPASSWORD="$PGPASSWORD" "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" >/dev/null 2>&1
chk "fastpki_pub publication created" 1 "$(pg_exec "select count(*) from pg_publication where pubname='fastpki_pub';")"
# `keys` IS published: it holds the per-user CMP/ACME enrolment secrets,
# which are minted by a role grant that itself replicates via web_users. A credential
# stranded on the DC that created it would make a downloaded client config enrol
# against one node out of three. The private key material that must never replicate
# is a CA's signing key, excluded by the `certs` published COLUMN LIST.
chk "publication includes keys (per-user enrolment secrets)" 1 "$(pg_exec "select count(*) from pg_publication_tables where pubname='fastpki_pub' and tablename='keys';")"
chk "publication includes certs"      1 "$(pg_exec "select count(*) from pg_publication_tables where pubname='fastpki_pub' and tablename='certs';")"

# Removed `ca_instances`: a CA is now a row of `certs` carrying is_ca, with its key
# reference in certs.private_key. The property under test is unchanged -- every DC gets
# every CA CERTIFICATE, no DC gets another's KEY -- but it now lives on one table, so
# these assertions had to move with it. They asserted against the dropped table until
# now, which is why this suite has been red.
chk "certs replicates the certificate bytes (every DC holds every CA cert)" 1 \
    "$(pg_exec "select count(*) from pg_publication_tables where pubname='fastpki_pub' and tablename='certs' and 'cert' = any(attnames);")"
chk "certs replicates is_ca (a peer can tell a CA from a leaf)" 1 \
    "$(pg_exec "select count(*) from pg_publication_tables where pubname='fastpki_pub' and tablename='certs' and 'is_ca' = any(attnames);")"

# The negative below is only worth anything if the column still EXISTS -- otherwise it
# passes because there is nothing to find, which is exactly how the ca_instances version
# of this check kept passing after the table it named was dropped. Prove the column is
# real first, then prove it is excluded.
chk "private_key is still a real column on certs" 1 \
    "$(pg_exec "select count(*) from information_schema.columns where table_name='certs' and column_name='private_key';")"
chk "certs does NOT replicate private_key (keys stay node-local)" 0 \
    "$(pg_exec "select count(*) from pg_publication_tables where pubname='fastpki_pub' and tablename='certs' and 'private_key' = any(attnames);")"
# The data center map. ⚠️ THIS MUST LAND BEFORE fastpki-cmp STARTS: the server reads
# its own row at startup to learn its prefix, and with no row it refuses to issue at all.
"$MESH" --allow-plaintext-transport --topology topo.txt --map | PGPASSWORD="$PGPASSWORD" "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" >/dev/null 2>&1
chk "datacenters map seeded"          1 "$(pg_exec "select count(*) from datacenters where dc_id='dc1';")"
chk "  with this node's prefix"       "$PFX" "$(pg_exec "select serial_prefix from datacenters where dc_id='dc1';")"

echo "=== serial-prefix minting via CMP issuance ==="
ca_in_token ca.pem "/CN=DC CA" 3650
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
cat > cmp.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PGCONN
DATACENTER_ID=dc1
CMP_BIND=127.0.0.1
CMP_PORT=$CMP
CMP_PATH=/cmp
LOG_LEVEL=err
EOF
# CMP protects with a dedicated RA credential now, so it must exist before the
# server starts; and the client anchors with -trusted, because the CA is not the sender.
cmp_ra_issue ca.pem "$CA_KEY_URI" \
    || { echo "SKIP: could not provision the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
cmp_ra_publish
cmp_ra_conf_lines >> cmp.conf
seed_ca_from_conf cmp.conf   # register the CA (SIGNING_CA_* no longer seed it)
cmp_seed_pbm replication
"$ROOT/build/fastpki-cmp" --config cmp.conf >cmp.log 2>&1 & C=$!
sleep 1; trap 'kill $C 2>/dev/null; mesh_teardown; pg_cleanup' EXIT
if ! kill -0 $C 2>/dev/null; then echo "fastpki-cmp died:"; cat cmp.log; exit 1; fi

# Issue several certs; each minted serial must satisfy the CHECK (else the
# INSERT — hence issuance — fails and the row count stays 0).
for i in 1 2 3 4 5; do
  "$OSSL" cmp -cmd ir -server "http://127.0.0.1:$CMP/cmp/ca" -recipient "/CN=DC CA" \
      -trusted ca.pem -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
      -newkey scratch.key -subject "/CN=node$i.internal" -certout "leaf$i.pem" >/dev/null 2>&1
done
# NOT is_ca: the CA is a row of `certs` and its self-signed certificate was
# never minted from the datacenter range.
#
# cert_id IS NULL as well: the CMP RA credential is also a non-CA row, and it
# is inserted directly rather than minted through the data center range — so counting every
# leaf turned "5 issued" into 6 and the range assertion into a false alarm. cert_id is the
# discriminator: minted certificates have none, provisioned credentials are tagged.
MINTED="not is_ca and cert_id is null"
chk "5 certs issued under the prefix guard" 5 "$(pg_exec "select count(*) from certs where $MINTED;")"
chk "every minted serial carries prefix $PFXHEX" 5 \
    "$(pg_exec "select count(*) from certs where $MINTED and left(lpad(lower(serial),40,'0'),4) = '$PFXHEX';")"

# ⚠️ The serial must still be a legal DER INTEGER — this is the property the 1..32767
# prefix bound exists to preserve, and nothing else in the suite would notice if a prefix
# ever set the high bit: OpenSSL would quietly prepend a 0x00 pad, the serial would become
# 21 octets, and the certificate would leave RFC 5280 §4.1.2.2 while verifying perfectly.
# Read it off the ISSUED CERTIFICATE, not the database column, because the padding lives
# in the encoding and the column stores the value.
#
# ⚠️ Read the SERIAL's INTEGER, which is the one at depth 2. The first INTEGER in the
# output is the VERSION, nested at depth 3 inside the [0] tag, and it is always 1 octet —
# a checker that grabs it reports 1 for every certificate ever made and can never fail.
der_serial_len() {
  "$OSSL" asn1parse -in "$1" 2>/dev/null \
    | awk '/d=2/ && /prim: INTEGER/ {sub(/.*hl=[0-9]+ +l= */,""); sub(/ .*/,""); print; exit}'
}
# The POSITIVE CONTROL, and this suite is worthless without it: mint a certificate whose
# serial deliberately has the high bit set and prove the checker above reports 21. Then a
# green result below means the product's serials really are conformant, rather than the
# measurement being blind.
"$OSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /dev/null \
    -out highbit.pem -subj /CN=highbit -days 1 \
    -set_serial 0xFF00000000000000000000000000000000000001 >/dev/null 2>&1
chk "the DER-length check can SEE a high-bit serial (control)" 21 "$(der_serial_len highbit.pem)"

bad=0
for i in 1 2 3 4 5; do
  [ -s "leaf$i.pem" ] || { bad=$((bad+1)); continue; }
  len=$(der_serial_len "leaf$i.pem")
  [ -n "$len" ] && [ "$len" -ge 1 ] && [ "$len" -le 20 ] || bad=$((bad+1))
done
chk "every issued DER serial is 1..20 octets (positive, RFC 5280 §4.1.2.2)" 0 "$bad"

echo "=== the guard rejects a write carrying ANOTHER data center's prefix ==="
pg_exec "INSERT INTO certs(serial,status) VALUES('$FOREIGN',0);" >/dev/null 2>&1 && rc=0 || rc=1
chk "a foreign-prefix serial is rejected" 1 "$rc"
chk "rejected row not stored"             0 "$(pg_exec "select count(*) from certs where serial='$FOREIGN';")"
# ⚠️ And the same serial WITH our prefix must go in, or the assertion above proves only
# that the trigger rejects things — which a guard that rejects everything also does.
MINE="00050000000000000000000000000000000000ab"
pg_exec "INSERT INTO certs(serial,status) VALUES('$MINE',0);" >/dev/null 2>&1 && rc=0 || rc=1
chk "  while the same serial under OUR prefix is accepted" 0 "$rc"

echo
echo "=== REPLICATION: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
