#!/usr/bin/env bash
# Which of a re-keyed CA's two live generations signs, when both were minted in the
# same second.
#
# `certs.id` is deliberately NOT unique — rekeying adds a SECOND row beside the first
# and both stay live for the rollover. Several queries pick between them with
# `ORDER BY "notBefore" DESC LIMIT 1`, and "notBefore" is whole epoch SECONDS read out of
# the certificate. Two generations minted in the same second tie exactly, and the planner
# decides — differently on identical data.
#
# ⚠️ THE FAILURE THAT MATTERS IS NOT "the wrong certificate". The CERTIFICATE
# (get_ca_cert_der) and the private KEY (get_ca_instance) are chosen by two SEPARATE
# queries. On a tie they can land on DIFFERENT generations: the CA signs with one
# generation's key while presenting the other's certificate, and every certificate, CRL and
# OCSP response it produces then fails signature verification. Nothing logs anything.
#
# The chosen design is an insertion sequence. `certs.ins_seq` is written by
# insert_cert as (serial_prefix << 48) | nextval('certs_seq_local'), the same per-DC
# partitioning as the serial, and every consumer orders
#     "notBefore" DESC, ins_seq DESC NULLS LAST, serial DESC
#
# ⚠️ THE FIXTURE IS BUILT SO `serial DESC` ALONE GETS IT WRONG. The newer generation is
# given the LOWER serial. Without that, appending `serial DESC` would pass this suite while
# answering "which generation is new?" by coin-flip — serial is 18 bytes of RAND_bytes with
# no recency at all (x509.cpp set_random_serial).
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
CA="$ROOT/build/fastpki-ca"
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
skipout(){ echo "  [SKIP] $1"; echo; echo "=== CA PICK TIEBREAK: PASS=$pass FAIL=$fail SKIP=1 ==="; exit 0; }

ca_in_token ca.pem "/CN=Tiebreak CA" 3650 tbca || skipout "no token"
pg_setup ca_pick_tiebreak
trap 'pg_cleanup' EXIT

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=tb
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf

echo "=== 1. the WRITER: insert_cert stamps a prefixed ins_seq ==="
# The CA seeded above went through insert_cert, so its row must carry one.
SEQ=$(pg_exec "SELECT coalesce(ins_seq::text,'<null>') FROM certs WHERE id='tb' AND is_ca;" | tr -d ' ')
chk "the seeded CA row has an ins_seq" yes "$([ "$SEQ" != "<null>" ] && [ -n "$SEQ" ] && echo yes || echo no)"
# ⚠️ Decode the LAYOUT, not just non-nullness. A plain nextval would also be non-null and
# would be exactly the unsafe form this ticket rejected.
#   no DATACENTER_ID here -> prefix 0 -> the value is the low 48 bits alone.
chk "  and it lives in prefix-space 0 with no data center set" yes \
    "$(pg_exec "SELECT (ins_seq >> 48) = 0 FROM certs WHERE id='tb' AND is_ca;" | tr -d ' ' | grep -q '^t$' && echo yes || echo no)"

echo "=== 2. ⚠️ two generations, SAME second, newer has the LOWER serial ==="
# Both rows carry id='tb'. `aaaa…` sorts BELOW `ffff…`, so serial DESC prefers the OLDER
# one — which is what makes this fixture discriminating.
NOW=$(pg_exec "SELECT \"notBefore\" FROM certs WHERE id='tb' AND is_ca LIMIT 1;" | tr -d ' ')
pg_exec "UPDATE certs SET serial='ffff0000000000000000000000000000000000f1', ins_seq=100
           WHERE id='tb' AND is_ca;" >/dev/null
pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,cn,cert,
                           is_ca,id,private_key,ca_instance_id,ins_seq)
         SELECT 'aaaa0000000000000000000000000000000000a2', 0, $NOW, \"notAfter\", subject, cn, cert,
                true, 'tb', 'pkcs11:object=NEWGEN;type=private', ca_instance_id, 200
           FROM certs WHERE serial='ffff0000000000000000000000000000000000f1';" >/dev/null
chk "PRECONDITION: two live CA rows share the id" 2 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='tb' AND is_ca;" | tr -d ' ')"
chk "PRECONDITION: they tie on notBefore" 1 \
    "$(pg_exec "SELECT count(DISTINCT \"notBefore\") FROM certs WHERE id='tb' AND is_ca;" | tr -d ' ')"
chk "PRECONDITION: the NEWER one has the LOWER serial" yes \
    "$(pg_exec "SELECT (SELECT serial FROM certs WHERE id='tb' AND is_ca AND ins_seq=200)
                     < (SELECT serial FROM certs WHERE id='tb' AND is_ca AND ins_seq=100);" \
       | tr -d ' ' | grep -q '^t$' && echo yes || echo no)"

echo "=== 3. the PRODUCT picks the newer generation ==="
# ⚠️ Ask fastpki-ca, not the SQL — the SQL is what is under test. `show` reports the row
# get_ca_instance chose, and its ca_key names the generation, so this reads the CHOICE.
SHOWN=$("$CA" --config bootstrap.conf show tb 2>/dev/null | grep -o 'ca_key=[^]]*' | head -1)
chk "get_ca_instance chose the NEW generation's key" yes \
    "$(printf '%s' "$SHOWN" | grep -q 'NEWGEN' && echo yes || echo no)"

echo "=== 4. ⚠️ NULLS LAST: a pre-migration row must not win a tie ==="
# Postgres puts NULLs FIRST under DESC. Without NULLS LAST, a row from before step 0028
# sorts as the newest and inverts the whole fix — the single subtlest thing here.
pg_exec "UPDATE certs SET ins_seq=NULL WHERE id='tb' AND is_ca AND serial LIKE 'ffff%';" >/dev/null
SHOWN2=$("$CA" --config bootstrap.conf show tb 2>/dev/null | grep -o 'ca_key=[^]]*' | head -1)
chk "a NULL ins_seq loses to a real one on a tie" yes \
    "$(printf '%s' "$SHOWN2" | grep -q 'NEWGEN' && echo yes || echo no)"

echo "=== 5. the answer is STABLE — a query that flips on identical data is the bug ==="
S1=$("$CA" --config bootstrap.conf show tb 2>/dev/null | cut -f1,2)
for _ in 1 2 3 4 5; do
    SN=$("$CA" --config bootstrap.conf show tb 2>/dev/null | cut -f1,2)
    [ "$SN" = "$S1" ] || { chk "repeated lookups agree" "$S1" "$SN"; break; }
done
chk "repeated lookups agree" yes "$([ -n "$S1" ] && echo yes || echo no)"

echo
echo "=== CA PICK TIEBREAK: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
