#!/usr/bin/env bash
# Multi-data-center replication topology generator — fastpki-mesh.
# Pure DDL text generation, no DB: validates the loop-free full-mesh output
# (Task 1.6.2), the per-node serial-range CHECK (Task 1.6.1), the public-only
# publication, and the input validation (overlap / bad hex rejection).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
# NB --allow-plaintext-transport: fastpki-mesh refuses a topology whose conninfo
# does not request TLS, because inter-DC replication carries web_users (incl. the
# pbkdf2 password hash) and the conninfo embeds the replication password. These
# suites drive throwaway clusters on 127.0.0.1 — a genuinely closed link — so they
# take the documented override rather than weakening the guard. See mesh_tls.sh.
MESH="$ROOT/build/fastpki-mesh"
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

cat > topo.txt <<EOF
# dc_id|conninfo|serial_prefix
dc1|host=10.1.0.1 dbname=pki user=repl|1|http://dc1.example
dc2|host=10.2.0.1 dbname=pki user=repl|258|http://dc2.example
dc3|host=10.3.0.1 dbname=pki user=repl|32767|http://dc3.example
EOF

echo "=== full mesh (3 data centers) ==="
ALL=$("$MESH" --allow-plaintext-transport --topology topo.txt --all)
chk "N*(N-1) = 6 subscriptions"      6 "$(echo "$ALL" | grep -c 'CREATE SUBSCRIPTION')"
# Every subscription must carry origin = none (loop-free). Count the WITH lines.
chk "every subscription is origin=none" 6 "$(echo "$ALL" | grep -c 'origin = none, failover = true, copy_data')"
# ⚠️ EVERY subscription seeds (copy_data = true), and both other settings are broken:
#   all false     -> a node joining a mesh that already has history never backfills, which
#                    is how lab dc1 sat at 86 certs against its peers' ~1456
#   one per node  -> right only if the ONE designated peer is already converged. On a
#                    first-time bootstrap none is and none can be: the mesh needs
#                    verify-full, which needs each node's database certificate, which needs
#                    that node's own sub CA — so every node holds local rows before any
#                    subscription can exist. Measured on a 3-node lab: node 1 seeded from
#                    node 2 and node 2 from node 1, so node 3's rows reached neither and
#                    the mesh sat at 13 of 19 certs with every health signal green.
# Seeding from every peer presents duplicates, and that is safe BY CONSTRUCTION rather than
# by luck: certs has certs_skip_dup, kSkipDupTables covers four more and kMgmtTables carries
# last-writer-wins — 1 + 4 + 12 = the 17 published tables, all ENABLE REPLICA TRIGGER and
# all installed before any subscription exists. Verified on PG17: re-seeding a node holding
# 13 of 19 rows presented all 13 as duplicates with zero apply errors.
#
# Asserted on the copy_data VALUE. The origin check above greps
# 'origin = none, copy_data' and matches either way, so it pinned nothing here — which is
# why the blanket-false bug was invisible to this suite.
chk "every subscription seeds, so a bootstrap converges"  6 \
    "$(echo "$ALL" | grep -c 'origin = none, failover = true, copy_data = true')"
chk "  and none is stream-only"                           0 \
    "$(echo "$ALL" | grep -c 'origin = none, failover = true, copy_data = false')"

echo "$ALL" | grep -q "CREATE PUBLICATION fastpki_pub FOR TABLE certs" && a=yes || a=no
chk "publication covers certs"       yes "$a"
# `keys` holds the per-user CMP/ACME enrolment secrets, and it IS
# published. It was excluded when nothing wrote it — the secrets were hand-inserted
# per node. Now a role grant mints them, web_users replicates that grant, and a
# credential stranded on its creating DC would make a downloaded client config enrol
# against one node out of three. The genuinely private key material is a CA's own
# signing key, and that is still excluded — by the `certs` column list asserted just
# below, which is the real guard.
echo "$ALL" | grep 'CREATE PUBLICATION' | grep -qw keys && a=yes || a=no
chk "publication includes keys (per-user enrolment secrets)" yes "$a"
# There is no registry table. A CA is a row of `certs`, so it replicates through
# the certs column list — carrying what a CA IS (id, name, enabled, enrolment
# permission) and NOT its key handle, which names an object in one node's token.
echo "$ALL" | grep 'CREATE PUBLICATION' | grep -q 'ca_instances' && a=yes || a=no
chk "publication no longer names ca_instances (it is gone)" no "$a"
CERTCOLS=$(echo "$ALL" | sed -n 's/.*FOR TABLE certs (\([^)]*\)).*/\1/p')
chk "certs is published by an explicit column list" yes "$([ -n "$CERTCOLS" ] && echo yes || echo no)"
for c in id is_ca name ca_enabled ms_enroll_permission; do
    echo "$CERTCOLS" | tr ',' '\n' | sed 's/^ *//' | grep -qx "$c" && a=yes || a=no
    chk "the CA attribute $c replicates" yes "$a"
done
# The real guard, and the reason the list is explicit at all: a bare publication would
# have started shipping private_key the moment it was added, silently.
echo "$CERTCOLS" | grep -q 'private_key' && a=yes || a=no
chk "certs does NOT publish private_key (keys stay node-local)" no "$a"
echo "$ALL" | grep -q 'origin = none' && a=yes || a=no
chk "header advertises origin=none"  yes "$a"
# The emitted SQL must CONVERGE, not merely create. It used to be a bare
# CREATE PUBLICATION, which fails on any cluster that already has one — so every table
# added to the list AFTER the initial setup silently never replicated, with nothing in a
# log to say so. `roles`/`role_permissions` were added and were dead on the lab until this
# was found by hand. Re-running setup is now how the live list is corrected.
echo "$ALL" | grep -q 'ALTER PUBLICATION fastpki_pub SET TABLE' && a=yes || a=no
chk "an EXISTING publication is corrected, not skipped"  yes "$a"
echo "$ALL" | grep -q 'FROM pg_publication WHERE pubname' && a=yes || a=no
chk "  and the create is the else-branch"                yes "$a"
# Same for subscriptions: a newly published table does not start streaming until the
# subscriber refreshes, so a converging publication alone would still leave it stalled.
#
# copy_data must be TRUE on the refresh, and this is not a detail. REFRESH copies only the
# tables NEW to the subscription, so it costs nothing for data already replicating — but
# with copy_data=false a newly published table arrives EMPTY and stays empty forever. That
# is exactly how foreign_anchors reached every node's schema and no node's data.
chk "every existing subscription is REFRESHed"           6 \
    "$(echo "$ALL" | grep -c 'REFRESH PUBLICATION WITH (copy_data = true)')"
chk "  ... and no refresh suppresses the copy of a NEW table" 0 \
    "$(echo "$ALL" | grep -c 'REFRESH PUBLICATION WITH (copy_data = false)')"

# ---- the transport-cert TAG has to replicate with the row --------------------------
# `certs` is published with an EXPLICIT column list, and mesh.cpp notes that such a list
# does not pick up columns added later. A listener's TLS certificate IS a
# certs row identified by cert_id, so if the tag is missing from the publication a peer
# receives the row with cert_id NULL — the cert is there and nothing can find it.
# Both spellings — the generator emits CREATE for a new cluster and ALTER ... SET TABLE
# for an existing one, and the column list has to be right in BOTH or a converging node
# silently loses the tag. Count the PUBLICATION statements naming cert_id, not every
# mention of it (the skip-dup triggers name it too).
chk "both publication forms carry certs.cert_id" 2 \
    "$(echo "$ALL" | grep -cE '(CREATE|ALTER) PUBLICATION .*certs \(.*[ (]cert_id[,)]')"

# ---- every slot the mesh creates must be a FAILOVER slot ----------------------------
# COUNT, not presence. A grep -q passes when a single subscription carries the flag,
# which is exactly the bug shape copy_data had — the seeding peer set and the
# rest not. Six subscriptions in a 3-DC mesh, six flags.
chk "every CREATE SUBSCRIPTION marks the slot failover"  6 \
    "$(echo "$ALL" | grep -c 'WITH (origin = none, failover = true, copy_data = ')"
chk "  ... and no CREATE omits it"                       0 \
    "$(echo "$ALL" | grep -c 'WITH (origin = none, copy_data = ')"
# The converge trio. REFRESH PUBLICATION does not touch subscription OPTIONS, so an
# already-meshed cluster would keep failover=false forever — the fix would work on a
# fresh cluster only and silently no-op on every live node. PG17 refuses
# ALTER SUBSCRIPTION ... SET (failover) on an ENABLED subscription, hence three
# statements rather than one.
chk "an existing subscription is DISABLEd before the flag is set" 6 \
    "$(echo "$ALL" | grep -c "ALTER SUBSCRIPTION %I DISABLE")"
chk "  ... the flag is then SET"                                 6 \
    "$(echo "$ALL" | grep -c "ALTER SUBSCRIPTION %I SET (failover = true)")"
chk "  ... and it is ENABLEd again"                              6 \
    "$(echo "$ALL" | grep -c "ALTER SUBSCRIPTION %I ENABLE")"
# ⚠️ THE ORDERING BUG THIS EXISTS TO CATCH. The ENABLE must be guarded on NOT subenabled.
# Guard it on NOT subfailover and it can never fire — the SET above has already flipped
# subfailover to true — so every subscription is left permanently DISABLED and the mesh
# converges itself into silence. Match the whole predicate, not a fragment.
chk "the ENABLE is guarded on subenabled, NOT on subfailover"    6 \
    "$(echo "$ALL" | grep -c "AND subname = '[^']*' AND NOT subenabled)")"
# An existing subscription must also take the topology's CONNECTION. CREATE runs once, so
# without this a subscription keeps the conninfo it was born with for ever: when each server
# of a Kubernetes pair moved to its own port, every peer already meshed kept dialling the old
# one. Set on every run (subconninfo is superuser-only to read), only where it exists, before
# the REFRESH that connects to the publisher, and with the same conninfo the CREATE carries.
chk "every existing subscription takes the topology's connection"  6 \
    "$(echo "$ALL" | grep -c "ALTER SUBSCRIPTION %I CONNECTION %L")"
chk "  only where the subscription exists"                          6 \
    "$(echo "$ALL" | grep -A2 "ALTER SUBSCRIPTION %I CONNECTION %L" | grep -c 'WHERE EXISTS (SELECT 1 FROM pg_subscription WHERE subdbid')"
chk "  with the publisher's own conninfo (dc2 is subscribed to twice)" 2 \
    "$(echo "$ALL" | grep -A1 "ALTER SUBSCRIPTION %I CONNECTION %L" | grep -c "'host=10.2.0.1 dbname=pki user=repl'")"
_c=$(echo "$ALL" | grep -n "ALTER SUBSCRIPTION %I CONNECTION %L" | head -1 | cut -d: -f1)
_r=$(echo "$ALL" | grep -n "REFRESH PUBLICATION WITH (copy_data = true)" | head -1 | cut -d: -f1)
chk "  before the REFRESH, which dials the publisher"             yes \
    "$([ -n "$_c" ] && [ -n "$_r" ] && [ "$_c" -lt "$_r" ] && echo yes || echo no)"
# Assert BOTH properties, not just that some guard exists: it must key on subname AND be
# scoped to the current database. pg_subscription is a cluster-wide catalog, so an
# unscoped match sees another database's subscriptions and would skip a CREATE this one
# still needs. Matching the whole predicate rather than a fragment also means a future
# narrowing of the guard fails here loudly instead of silently still matching.
echo "$ALL" | grep -qE 'FROM pg_subscription WHERE subdbid = .*AND subname = ' && a=yes || a=no
chk "  guarded on the subscription already existing, scoped to this database" yes "$a"
# No `;` may end the SELECT that a \gexec runs. With one, psql runs the SELECT at once and
# prints its result — for CREATE SUBSCRIPTION that is the whole statement, the peer's
# password included — and \gexec then runs it again from the history buffer. Checked on
# the --restore plan too, because its detach steps are generated by separate code.
semi_gexec() { awk '/^\\gexec$/ { g++; if (prev ~ /;[[:space:]]*$/) s++ } { prev = $0 }
                    END { print (g ? s + 0 : "no-gexec") }'; }
chk "no \\gexec follows a statement ended by ';' (--all)" 0 "$(echo "$ALL" | semi_gexec)"
chk "  ... nor in the --restore plan" 0 \
    "$("$MESH" --allow-plaintext-transport --topology topo.txt --node dc1 --restore --no-preflight 2>/dev/null | semi_gexec)"
# The role tables themselves — admin-managed data exactly like subject_roles, which has
# always replicated. A role that exists on one DC and not another means the same user
# gets different access per DC, and assigning it there is refused outright.
for t in roles role_permissions; do
    echo "$ALL" | grep 'SET TABLE' | grep -qw "$t" && a=yes || a=no
    chk "publication includes $t" yes "$a"
done

echo "=== single node (--node dc1) ==="
# NB --no-preflight: --node normally asks every peer whether it is on the same release
# before emitting anything (exercised in its own section at the end). The conninfos in this
# topology name addresses nothing answers on, so the check would spend a connect timeout per
# peer to reach the same "could not be read, skipped" note every time. These assertions are
# about the generated SQL, so they ask nobody.
N1=$("$MESH" --allow-plaintext-transport --topology topo.txt --no-preflight --node dc1)
chk "node dc1 has N-1 = 2 subscriptions" 2 "$(echo "$N1" | grep -c 'CREATE SUBSCRIPTION')"
echo "$N1" | grep -q 'sub_dc1_from_dc2' && a=yes || a=no
chk "node dc1 subscribes to dc2"     yes "$a"
echo "$N1" | grep -q 'sub_dc1_from_dc3' && a=yes || a=no
chk "node dc1 subscribes to dc3"     yes "$a"
# ⚠️ BOTH peers seed. A single designated seeder — dc2, the lowest id — was the previous
# rule, and it converges a node only if that one peer already holds everything. At bootstrap
# it does not: every node has its own sub CA and certificates before the mesh can start, so
# dc3's rows reached nobody and the lab sat at 13 of 19 certs, silently.
# Match on the CREATE form specifically. A bare 'copy_data = true' also appears on every
# REFRESH line, and the subscription NAME is on the next line of the format(...) call, so
# a line-based grep can neither isolate the creates nor tell which peer each names.
chk "dc1 seeds from BOTH peers" 2 \
    "$(echo "$N1" | grep -c 'origin = none, failover = true, copy_data = true')"
# Named, not just counted: a count of 2 would also pass if the same peer were emitted twice.
SEEDERS=$(echo "$N1" | grep -A1 'origin = none, failover = true, copy_data = true' \
         | grep -oE 'sub_dc1_from_dc[0-9]' | sort -u | tr '\n' ' ' | sed 's/ $//')
chk "  and they are dc2 and dc3"      "sub_dc1_from_dc2 sub_dc1_from_dc3" "$SEEDERS"
chk "no subscription is stream-only"  0 \
    "$(echo "$N1" | grep -c 'origin = none, failover = true, copy_data = false')"
# The serial-prefix guard is a TRIGGER, not a CHECK — a CHECK would also reject
# certs replicated from other DCs' partitions and stall the mesh (verified live).
echo "$N1" | grep -q "CREATE TRIGGER certs_dc_range BEFORE INSERT ON certs" && a=yes || a=no
chk "node dc1 gets a serial-prefix INSERT trigger (not a CHECK)" yes "$a"
echo "$N1" | grep -q "ADD CONSTRAINT certs_dc_range CHECK" && a=yes || a=no
chk "no prefix CHECK constraint is emitted (would stall replication)" no "$a"
# Dc1's prefix is 1, which is '0001' as the top two octets of a 40-hex serial.
# ⚠️ The comparison must be POSITIONAL — left(...,4) — and not a LIKE or a range. A
# substring match anywhere in the serial would accept a peer's cert whose random tail
# happens to contain these four characters, roughly one in 16^4 of everything replicated.
echo "$N1" | grep -q "left(lpad(lower(NEW.serial),40,'0'),4) <> '0001'" && a=yes || a=no
chk "dc1's guard compares the top two octets against its own prefix" yes "$a"
# The guard is generated per node, so dc2's must differ. 258 = 0x0102.
N2=$("$MESH" --allow-plaintext-transport --topology topo.txt --no-preflight --node dc2)
echo "$N2" | grep -q "left(lpad(lower(NEW.serial),40,'0'),4) <> '0102'" && a=yes || a=no
chk "dc2's guard carries ITS prefix (0102), not dc1's" yes "$a"
# ⚠️ 32767 = 0x7fff is the largest legal prefix, and the reason for the bound: 0x8000
# would set the high bit of the leading octet, and DER integers are signed, so OpenSSL
# would prepend a 0x00 pad and push the serial to 21 octets — outside RFC 5280 §4.1.2.2.
N3=$("$MESH" --allow-plaintext-transport --topology topo.txt --no-preflight --node dc3)
echo "$N3" | grep -q "left(lpad(lower(NEW.serial),40,'0'),4) <> '7fff'" && a=yes || a=no
chk "the 32767 ceiling renders as 7fff (high bit clear)" yes "$a"

echo "=== publication / map preamble modes ==="
chk "--publication prints one CREATE PUBLICATION" 1 "$("$MESH" --allow-plaintext-transport --topology topo.txt --publication | grep -c 'CREATE PUBLICATION')"
chk "--map upserts 3 datacenter rows" 3 "$("$MESH" --allow-plaintext-transport --topology topo.txt --map | grep -c 'INSERT INTO datacenters')"
chk "  ... each carrying its own prefix" 3 \
    "$("$MESH" --allow-plaintext-transport --topology topo.txt --map | grep -cE "VALUES\\('dc[123]', (1|258|32767),")"

echo "=== input validation ==="
# Two data centers sharing a prefix is the whole failure this mechanism prevents, so it
# must not be expressible in a topology file. (`datacenters.serial_prefix` is UNIQUE too,
# but a topology is authored long before it reaches any database.)
cat > dup.txt <<EOF
dcA|host=a dbname=pki|7|http://dcx.example
dcB|host=b dbname=pki|7|http://dcx.example
EOF
"$MESH" --allow-plaintext-transport --topology dup.txt --all >/dev/null 2>&1 && rc=0 || rc=1
chk "two data centers sharing a prefix are rejected" 1 "$rc"
cat > badnum.txt <<EOF
dcA|host=a dbname=pki|abc|http://dcx.example
EOF
"$MESH" --allow-plaintext-transport --topology badnum.txt --all >/dev/null 2>&1 && rc=0 || rc=1
chk "a non-numeric prefix is rejected" 1 "$rc"
# ⚠️ 32768 sets the high bit, which DER would pad to a 21-octet serial. The bound is a
# correctness requirement, not a style choice, so prove BOTH sides of it.
cat > big.txt <<EOF
dcA|host=a dbname=pki|32768|http://dcx.example
EOF
"$MESH" --allow-plaintext-transport --topology big.txt --all >/dev/null 2>&1 && rc=0 || rc=1
chk "prefix 32768 is rejected (high bit would pad the serial to 21 octets)" 1 "$rc"
cat > ok.txt <<EOF
dcA|host=a dbname=pki|32767|http://dcx.example
EOF
"$MESH" --allow-plaintext-transport --topology ok.txt --all >/dev/null 2>&1 && rc=0 || rc=1
chk "  ... and 32767 is accepted" 0 "$rc"
cat > zero.txt <<EOF
dcA|host=a dbname=pki|0|http://dcx.example
EOF
"$MESH" --allow-plaintext-transport --topology zero.txt --all >/dev/null 2>&1 && rc=0 || rc=1
chk "prefix 0 is rejected (0 means 'no prefix' to the minter)" 1 "$rc"
# A prefix wide enough to overflow atoi must be caught BEFORE the conversion, or it wraps
# into a small number that looks perfectly valid.
cat > huge.txt <<EOF
dcA|host=a dbname=pki|99999999999999999999|http://dcx.example
EOF
"$MESH" --allow-plaintext-transport --topology huge.txt --all >/dev/null 2>&1 && rc=0 || rc=1
chk "an overflowing prefix is rejected, not wrapped" 1 "$rc"
cat > badid.txt <<EOF
dc-1|host=a dbname=pki|1
EOF
"$MESH" --allow-plaintext-transport --topology badid.txt --all >/dev/null 2>&1 && rc=0 || rc=1
chk "invalid data center id is rejected" 1 "$rc"
"$MESH" --allow-plaintext-transport --topology topo.txt --no-preflight --node nope >/dev/null 2>&1 && rc=0 || rc=1
chk "unknown --node is rejected"     1 "$rc"

# ⚠️ THE RELEASE CHECK IS THE ONLY THING THAT NAMES THE REAL FAULT. A peer on a different
# release fails at `CREATE SUBSCRIPTION ... copy_data = true`, which reads the PEER's
# publication and so reports `relation "public.<table>" does not exist` — an error that
# names a healthy node's database and blames it for a table the OTHER side invented or
# dropped. schema_version says 1 on both, because what differs is what the binaries publish.
# So --node asks each peer first, against real databases: these cells stand two of them up
# and make them disagree in each direction.
echo "=== release preflight (two live databases) ==="
pg_setup mesh_preflight
SELF="$PG_CONNINFO"
PEER_DB="${PGDATABASE}_peer"
psql_() { "$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$1" -tAq -c "$2"; }
# The last EXIT trap has to be a superset of every earlier one — there is no earlier one
# here, so this is the whole cleanup: the peer database this section creates, the database
# pg_setup created, and the temp directory.
trap 'psql_ postgres "DROP DATABASE IF EXISTS $PEER_DB;" >/dev/null 2>&1; pg_cleanup; rm -rf "$W"' EXIT
psql_ postgres "DROP DATABASE IF EXISTS $PEER_DB;" >/dev/null 2>&1
psql_ postgres "CREATE DATABASE $PEER_DB;" >/dev/null 2>&1
"$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PEER_DB" \
    -f "$ROOT/sql/createdb.sql" >/dev/null 2>&1
PEER="host=$PGHOST port=$PGPORT dbname=$PEER_DB user=$PGUSER password=$PGPASSWORD"
# dc3 is deliberately unreachable: a generator whose job is offline SQL must not turn a peer
# it cannot contact into an error, because the subscription it emits will report the
# connection failure itself, with the address in it.
cat > live.txt <<EOF
dc1|$SELF|1|http://dc1.example
dc2|$PEER|258|http://dc2.example
dc3|host=10.1.0.1 dbname=pki user=repl connect_timeout=1|32767|http://dc3.example
EOF
# The peer publishes a subset it and this node both have, which is the matching case.
psql_ "$PEER_DB" "CREATE PUBLICATION fastpki_pub FOR TABLE certs;" >/dev/null 2>&1
OUT=$("$MESH" --allow-plaintext-transport --topology live.txt --node dc1 2>err.txt) && rc=0 || rc=1
chk "a matching peer passes the check and the SQL is emitted" 0 "$rc"
chk "  and dc1 still gets its N-1 = 2 subscriptions" 2 "$(echo "$OUT" | grep -c 'CREATE SUBSCRIPTION')"
grep -q "data center 'dc3' could not be read" err.txt && a=yes || a=no
chk "an unreachable peer is a note, not a failure" yes "$a"

# OLDER peer: this node would publish a table the peer's schema does not have, so the
# peer's subscription to this node is what would break. Drop it there.
psql_ "$PEER_DB" "DROP TABLE notify_templates;" >/dev/null 2>&1
OUT=$("$MESH" --allow-plaintext-transport --topology live.txt --node dc1 2>err.txt) && rc=0 || rc=1
chk "a peer missing a table we publish is refused" 1 "$rc"
grep -q "does not have: notify_templates" err.txt && a=yes || a=no
chk "  and the message names the table" yes "$a"
grep -q 'OLDER release' err.txt && a=yes || a=no
chk "  and says which side is behind"   yes "$a"
chk "  and nothing was emitted"          0 "$(echo "$OUT" | grep -c 'CREATE SUBSCRIPTION')"
OUT=$("$MESH" --allow-plaintext-transport --topology live.txt --no-preflight --node dc1 2>/dev/null) \
    && rc=0 || rc=1
chk "--no-preflight asks nobody and emits anyway" 2 "$(echo "$OUT" | grep -c 'CREATE SUBSCRIPTION')"

# NEWER peer: the peer publishes a table this node has never heard of, so it is OUR
# subscription that would break, with an error naming our own database.
psql_ "$PEER_DB" "ALTER PUBLICATION fastpki_pub ADD TABLE cert_profiles;" >/dev/null 2>&1
psql_ "$PGDATABASE" "DROP TABLE cert_profiles CASCADE;" >/dev/null 2>&1
"$MESH" --allow-plaintext-transport --topology live.txt --node dc1 >/dev/null 2>err.txt && rc=0 || rc=1
chk "a peer publishing a table we lack is refused" 1 "$rc"
grep -q 'NEWER release' err.txt && a=yes || a=no
chk "  and the peer is named as the newer one" yes "$a"

echo
echo "=== MESH: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
