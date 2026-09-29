#!/usr/bin/env bash
# The MS-XCEP enrollment policy GUID is PER NODE.
#
# It used to be the literal {b7bf7cea-1991-42c2-8c4f-e222ee159701} compiled into
# config.hpp, so every deployment and every DC of one mesh advertised the same
# <policyID>. Windows keys its enrollment policy cache on that id: point a machine at a
# second DC and it believes it already holds that policy under that id, and the two
# servers collide over one cache entry.
#
# What makes the fix work is that the `config` table is NOT replicated — it is
# deliberately absent from the pinned publication in tests/lab_replication_mesh.sh — so a
# value written there stays on its own node. This suite stands in for two DCs with two
# independent databases, which is the same thing from the GUID's point of view.
#
# Asserted by decoding the real GetPolicies response and by reading the row the server
# wrote, never by grepping the source.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: that default path is a Linux convention and is absent on plenty of dev boxes.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
ne(){  if [ "$2" != "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (both were '$2')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=GUID CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout ms.key -out ms.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

XCEP_REQ='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"><client><lastUpdate xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/><preferredLanguage xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/></client></GetPolicies></s:Body></s:Envelope>'

# Bring up one "DC": its own database, its own fastpki-ms. Echoes the <policyID> the
# server advertises. $PORT and $PG_CONNINFO are per-node, which is the whole point.
MSPID=""
start_node() {   # <dbname> <port>
    pg_setup "$1"
    seed_domains /dev/null 2>/dev/null || true
    seed_web_user tester s3cret-guid requester >/dev/null 2>&1
    cat > "pki_$2.conf" <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
ROOT_CA_PEM=$W/root.pem
MS_CERT=$W/ms.pem
MS_KEY=$W/ms.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
MS_BIND=127.0.0.1
MS_PORT=$2
XCEP_PATH=/msxcep
WSTEP_PATH=/mswstep
LOG_LEVEL=info
EOF
    seed_ca_from_conf "pki_$2.conf"
    "$ROOT/build/fastpki-ms" --config "pki_$2.conf" >"srv_$2.log" 2>&1 & MSPID=$!
    for _ in $(seq 1 40); do
        curl -sk -o /dev/null "https://127.0.0.1:$2/msxcep/ca-global" 2>/dev/null && break
        # Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
        wait_conf "pki_$2.conf" MS_PORT "$MSPID" || true
    done
}
policy_id_of() {   # <port> -> the <policyID> the server advertises
    curl -sk -u tester:s3cret-guid -H "Content-Type: application/soap+xml; charset=utf-8" \
        --data "$XCEP_REQ" "https://127.0.0.1:$1/msxcep/ca-global" 2>/dev/null \
      | sed -n 's/.*<policyID>\([^<]*\)<\/policyID>.*/\1/p'
}

echo "=== node A mints its own policy GUID on first start ==="
start_node xcep_guid_a 18471
A1=$(policy_id_of 18471)
A_ROW=$(pg_exec "SELECT value FROM config WHERE key='MS_XCEP_GUID';" | tr -d ' ')
chk "GetPolicies advertises a policyID"        yes "$([ -n "$A1" ] && echo yes || echo no)"
chk "it is a braced v4 GUID"                   yes \
    "$(echo "$A1" | grep -qiE '^\{[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\}$' && echo yes || echo no)"
chk "the server persisted it to the config table" "$A1" "$A_ROW"
# ⚠️ The whole ticket. If this ever passes by matching, the hardcoded literal is back.
ne  "it is NOT the old hardcoded literal"      "{b7bf7cea-1991-42c2-8c4f-e222ee159701}" "$A1"

echo "=== and reuses it across a restart (a client's cache key must not move) ==="
kill $MSPID 2>/dev/null; wait $MSPID 2>/dev/null
"$ROOT/build/fastpki-ms" --config pki_18471.conf >>srv_18471.log 2>&1 & MSPID=$!
for _ in $(seq 1 40); do curl -sk -o /dev/null "https://127.0.0.1:18471/msxcep/ca-global" 2>/dev/null && break; sleep 0.25; done
A2=$(policy_id_of 18471)
chk "same policyID after restart" "$A1" "$A2"
chk "exactly one MS_XCEP_GUID row (it claimed, it did not re-mint)" 1 \
    "$(pg_exec "SELECT count(*) FROM config WHERE key='MS_XCEP_GUID';" | tr -d ' ')"
kill $MSPID 2>/dev/null; wait $MSPID 2>/dev/null
pg_cleanup

echo "=== node B — a SEPARATE database, standing in for a second DC ==="
start_node xcep_guid_b 18472
B1=$(policy_id_of 18472)
B_ROW=$(pg_exec "SELECT value FROM config WHERE key='MS_XCEP_GUID';" | tr -d ' ')
chk "node B also advertises a policyID"  yes "$([ -n "$B1" ] && echo yes || echo no)"
chk "node B persisted its own"           "$B1" "$B_ROW"
# PRECONDITION: without both values the inequality below is vacuously true.
chk "PRECONDITION: both nodes produced a GUID" yes \
    "$([ -n "$A1" ] && [ -n "$B1" ] && echo yes || echo no)"
ne  "the two nodes advertise DIFFERENT policy GUIDs" "$A1" "$B1"
kill $MSPID 2>/dev/null; wait $MSPID 2>/dev/null

echo "=== a value already stored is HONOURED, never re-minted over ==="
# ⚠️ Pin it in the DATABASE, not in the conf file. DB config overlays the file by design
# (Task 1.1, §3f: the database is the source of truth), so a file entry legitimately
# loses to a stored one — that is what the console writes when an operator sets a key.
# My first version of this assertion pinned it in bootstrap.conf and read the failure as a
# product bug; it was the test asserting the wrong contract.
PINNED='{11111111-2222-4333-8444-555555555555}'
pg_exec "UPDATE config SET value='$PINNED' WHERE key='MS_XCEP_GUID';" >/dev/null
chk "PRECONDITION: the pinned value is what the table now holds" "$PINNED" \
    "$(pg_exec "SELECT value FROM config WHERE key='MS_XCEP_GUID';" | tr -d ' ')"
"$ROOT/build/fastpki-ms" --config pki_18472.conf >>srv_18472.log 2>&1 & MSPID=$!
for _ in $(seq 1 40); do curl -sk -o /dev/null "https://127.0.0.1:18472/msxcep/ca-global" 2>/dev/null && break; sleep 0.25; done
chk "the stored GUID is advertised, not replaced" "$PINNED" "$(policy_id_of 18472)"
chk "  and the row still holds it after start"    "$PINNED" \
    "$(pg_exec "SELECT value FROM config WHERE key='MS_XCEP_GUID';" | tr -d ' ')"
kill $MSPID 2>/dev/null; wait $MSPID 2>/dev/null
pg_cleanup

echo
echo "=== MS XCEP GUID: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
