#!/usr/bin/env bash
# No fake 'default' CA instance in the DB.  Transport certs use
# NULL ca_instance_id; the 'default' id is reserved but not seeded.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup no_default_ca
trap 'pg_cleanup' EXIT

# ── 1. Fresh DB must NOT contain a 'default' ca_instances row ───────────
DEFAULT_ROWS=$(pg_exec "SELECT count(*) FROM certs WHERE id='default' AND is_ca;")
chk "no 'default' row in fresh DB" "0" "$DEFAULT_ROWS"

# ── 2. ca_instances column defaults to NULL, not 'default' ──────────────
NOW=$(date +%s)
pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint)
         VALUES('aa',0,$((NOW-100)),$((NOW+86400)),'CN=transport','x','transport','')
         ON CONFLICT (serial) DO NOTHING;"
NULL_CI=$(pg_exec "SELECT ca_instance_id IS NULL FROM certs WHERE serial='aa';")
chk "cert without explicit ca_instance_id has NULL" "t" "$NULL_CI"

# ── 3. seed_ca_from_conf creates a REAL CA with id 'default' ───────────
ca_in_token ca.pem "/CN=Test CA" 3650
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=default
PG_CONNINFO=$PG_CONNINFO
EOF
seed_ca_from_conf bootstrap.conf
DEFAULT_ROWS=$(pg_exec "SELECT count(*) FROM certs WHERE id='default' AND is_ca;")
chk "'default' row exists after seed_ca_from_conf" "1" "$DEFAULT_ROWS"

# The CA's certificate IS its row, so "has a certificate" is a non-empty `cert`.
HAS_PEM=$(pg_exec "SELECT CASE WHEN cert IS NOT NULL AND length(cert)>0 THEN 'yes' ELSE 'no' END FROM certs WHERE id='default' AND is_ca;")
chk "seeded 'default' CA has a stored certificate" "yes" "$HAS_PEM"

# ── 4. Certs with a real ca_instance_id are stored correctly ────────────
pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,ca_instance_id)
         VALUES('bb',0,$((NOW-100)),$((NOW+86400)),'CN=issued','x','issued','','default')
         ON CONFLICT (serial) DO NOTHING;"
REAL_CERTS=$(pg_exec "SELECT count(*) FROM certs WHERE ca_instance_id='default' AND NOT is_ca;")
chk "certs with ca_instance_id='default' exist" "1" "$REAL_CERTS"

# ── 5. audit_log and discovered_certs also default to NULL ──────────────
pg_exec "INSERT INTO audit_log(ts,category,action,status,prev_hash,hash)
         VALUES($((NOW-100)),'test','insert',0,'','abc123')
         ON CONFLICT DO NOTHING;"
AUDIT_NULL=$(pg_exec "SELECT ca_instance_id IS NULL FROM audit_log WHERE category='test';")
chk "audit_log entry without ca_instance_id has NULL" "t" "$AUDIT_NULL"

echo ""
echo "=== NO DEFAULT CA: PASS=$pass FAIL=$fail ==="
if [ "$fail" -ne 0 ]; then exit 1; fi
