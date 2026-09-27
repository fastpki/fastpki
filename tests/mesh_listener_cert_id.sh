#!/usr/bin/env bash
# Two nodes, one MS_CERT_ID, and BOTH transport certificates stay active.
#
# ── The bug ────────────────────────────────────────────────────────────────────────
#
# `certs` is replicated, so a bare id like `ms` names the SAME ROW on every node in a mesh.
# publish_service_cert retires the previous holder of an id — by id alone, with no CA or
# node component — so three DCs each issuing `ms` against their own HSM key leave ONE
# active row and two `status=3` (superseded).
#
# ⚠️ THE REASON THIS SAT UNNOTICED FOR HOURS IS WHY THE ASSERTION IS SHAPED THIS WAY.
# Nothing fails at issuance: every call returns 200 with a PEM, and every listener carries
# on serving the certificate it loaded at startup. The damage only appears on the NEXT
# restart, when a node looks up its id, finds no active row, and falls back to a temporary
# self-signed certificate. Any check made right after issuing passes. So this suite does
# not assert "issuance succeeded" — it asserts what the DATABASE HOLDS afterwards, which is
# the only place the collision is visible before a restart.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"
MS="$ROOT/build/fastpki-ms"
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Mesh Listener CA" 3650
pg_setup mesh_listener_cert_id
trap 'pg_cleanup; kill ${P1:-} ${P2:-} ${P3:-} ${P4:-} ${P5:-} ${P6:-} 2>/dev/null' EXIT

# Two nodes of one mesh: same database (as replication would give them), same MS_CERT_ID,
# different DATACENTER_ID. A `datacenters` row is required — config.cpp refuses to start a
# node whose DATACENTER_ID has no serial prefix, which is itself a guard.
pg_exec "INSERT INTO datacenters(dc_id, serial_prefix) VALUES('dca', 4001)
         ON CONFLICT (dc_id) DO NOTHING;" >/dev/null
pg_exec "INSERT INTO datacenters(dc_id, serial_prefix) VALUES('dcb', 4002)
         ON CONFLICT (dc_id) DO NOTHING;" >/dev/null

# ⚠️ EACH NODE NEEDS ITS OWN KEY, or the whole scenario evaporates. Without MS_KEY there
# is nothing to sign with, resolve_transport_cert publishes nothing, and every assertion
# below reads an empty table — including "nothing under the bare id", which passes on
# nothing at all. The bug being tested is precisely that two nodes hold DIFFERENT private
# keys for one id, so distinct per-node keys are the scenario, not a detail.
KEY_A=$(hsm_new_key_uri mslistener_a)
KEY_B=$(hsm_new_key_uri mslistener_b)
KEY_S=$(hsm_new_key_uri mslistener_solo)

node_conf() {   # $1=dc_id  $2=port  $3=outfile  $4=key uri
cat > "$3" <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
PG_CONNINFO=$PG_CONNINFO
MS_BIND=127.0.0.1
MS_PORT=$2
MS_CERT_ID=ms
MS_KEY=$4
DATACENTER_ID=$1
PKI_DNS=$1.mesh.internal
LOG_LEVEL=info
EOF
hsm_conf_lines >> "$3"
}
node_conf dca 18761 a.conf "$KEY_A"
node_conf dcb 18762 b.conf "$KEY_B"
seed_ca_from_conf a.conf

echo "=== both nodes come up with the SAME MS_CERT_ID=ms ==="
"$MS" --config a.conf >a.log 2>&1 & P1=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "a.conf" MS_PORT "$P1" || true
chk "node A (DATACENTER_ID=dca) started" yes "$(kill -0 $P1 2>/dev/null && echo yes || echo no)"
"$MS" --config b.conf >b.log 2>&1 & P2=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "b.conf" MS_PORT "$P2" || true
chk "node B (DATACENTER_ID=dcb) started" yes "$(kill -0 $P2 2>/dev/null && echo yes || echo no)"
[ -s a.log ] && grep -iE "^ERR|fatal" a.log | head -2
[ -s b.log ] && grep -iE "^ERR|fatal" b.log | head -2

echo "=== each node published under its OWN id ==="
chk "node A's row is ms-dca" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='ms-dca';" | tr -d ' ')"
chk "node B's row is ms-dcb" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='ms-dcb';" | tr -d ' ')"
# ⚠️ And nothing is left under the BARE id. If this ever comes back it means one end of the
# change was missed — the listener resolving `ms-dca` while something else still publishes
# `ms` is the same disagreement in a new costume.
chk "PRECONDITION: something was published at all" yes \
    "$([ "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id LIKE 'ms%';" | tr -d ' ')" -gt 0 ] && echo yes || echo no)"
chk "  and nothing was published under the bare id" 0 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='ms';" | tr -d ' ')"

echo "=== THE ASSERTION: neither node superseded the other ==="
# status 3 = superseded. The second node to start used to set the first one's row to 3,
# and the first node then came up self-signed on its next restart.
chk "node A's certificate is still ACTIVE" 0 \
    "$(pg_exec "SELECT status FROM certs WHERE cert_id='ms-dca';" | tr -d ' ')"
chk "node B's certificate is still ACTIVE" 0 \
    "$(pg_exec "SELECT status FROM certs WHERE cert_id='ms-dcb';" | tr -d ' ')"
chk "  two active listener certificates, not one" 2 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id LIKE 'ms-dc%' AND status=0;" | tr -d ' ')"
chk "  and none was retired as superseded" 0 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id LIKE 'ms-dc%' AND status=3;" | tr -d ' ')"

echo "=== they are genuinely different certificates, not one row read twice ==="
SA=$(pg_exec "SELECT serial FROM certs WHERE cert_id='ms-dca';" | tr -d ' ')
SB=$(pg_exec "SELECT serial FROM certs WHERE cert_id='ms-dcb';" | tr -d ' ')
chk "different serials" yes "$([ -n "$SA" ] && [ -n "$SB" ] && [ "$SA" != "$SB" ] && echo yes || echo no)"
chk "  each names its own node in the subject" yes \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='ms-dca' AND cn LIKE '%dca%';" | tr -d ' ' \
       | grep -q 1 && echo yes || echo no)"

echo "=== a single-node deployment is UNCHANGED (no DATACENTER_ID) ==="
# The scoping must not surprise anyone who never joined a mesh: with DATACENTER_ID unset
# the id stays exactly what the operator configured.
sed -e 's/^DATACENTER_ID=.*//' -e 's/^MS_PORT=.*/MS_PORT=18763/' \
    -e 's/^MS_CERT_ID=.*/MS_CERT_ID=solo/' -e "s|^MS_KEY=.*|MS_KEY=$KEY_S|" a.conf > solo.conf
"$MS" --config solo.conf >solo.log 2>&1 & P3=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "solo.conf" MS_PORT "$P3" || true
chk "a node with no DATACENTER_ID publishes the BARE id" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='solo';" | tr -d ' ')"
chk "  and did not invent a suffix" 0 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id LIKE 'solo-%';" | tr -d ' ')"
kill $P3 2>/dev/null

echo "=== The issuing CA is read off the LAST certificate, not out of config ==="
# resolve_transport_cert used to have three paths — a published row, a cert adopted from
# disk, and self-sign — and none of them asked a CA. Every listener served a self-signed
# certificate; on the lab `ms` looked CA-issued only because a legacy ms.crt beside its key
# was being adopted.
#
# ⚠️ AND THE FIRST CUT NAMED THE CA IN CONFIG, via a TRANSPORT_CA_ID key. That setting was
# redundant: the issuing CA is known from the leaf certificate itself. The redundancy had
# a cause:
# publish_transport_cert hardcoded certs.ca_instance_id to NULL, so a CA-issued listener
# certificate was stored looking self-signed and the issuer had to be re-supplied from
# config on every start. The column is recorded now and the key is gone.
#
# THE FIXTURE IS THE REAL SCENARIO: a previous CA-issued listener certificate that has
# EXPIRED. It is not a candidate (the candidate query filters on notAfter), so the node
# must mint a new one — and the only thing telling it which CA to use is the expired row.
#
# ⚠️ SELF-SIGNED IS `subject == issuer`, NOT "no chain". Comparing the two names is the
# only honest test: a certificate can have an issuer field naming a CA and still be
# self-signed if that name is its own.
KEY_C=$(hsm_new_key_uri mslistener_ca)
sed -e 's/^DATACENTER_ID=.*/DATACENTER_ID=dcc/' -e 's/^MS_PORT=.*/MS_PORT=18764/' \
    -e 's/^MS_CERT_ID=.*/MS_CERT_ID=caissued/' -e "s|^MS_KEY=.*|MS_KEY=$KEY_C|" \
    a.conf > caissued.conf
pg_exec "INSERT INTO datacenters(dc_id, serial_prefix) VALUES('dcc', 4003)
         ON CONFLICT (dc_id) DO NOTHING;" >/dev/null
# The expired predecessor. Its DER is the CA's own certificate — this row exists to carry
# ca_instance_id and an expired notAfter, and nothing reads its bytes on this path.
CA_B64=$("$OSSL" x509 -in ca.pem -outform DER 2>/dev/null | "$OSSL" base64 -A)
pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,cn,cert_id,ca_instance_id,cert)
         VALUES('deadbeef01',0,1,2,'/CN=old listener','old listener','caissued-dcc','ca',
                decode('$CA_B64','base64'));" >/dev/null
chk "PRECONDITION: the expired predecessor records its issuing CA" "ca" \
    "$(pg_exec "SELECT ca_instance_id FROM certs WHERE serial='deadbeef01';" | tr -d ' ')"
chk "PRECONDITION: and no config key names a CA" 0 \
    "$(grep -c 'TRANSPORT_CA_ID' caissued.conf)"
"$MS" --config caissued.conf >caissued.log 2>&1 & P4=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "caissued.conf" MS_PORT "$P4" || true
chk "the node started" yes "$(kill -0 $P4 2>/dev/null && echo yes || echo no)"
CI_PEM=$(pg_exec "SELECT encode(cert,'base64') FROM certs WHERE cert_id='caissued-dcc' AND status=0 AND serial<>'deadbeef01';" | tr -d ' \n')
printf '%s' "$CI_PEM" | "$OSSL" base64 -d -A > caissued.der 2>/dev/null
SUBJ=$("$OSSL" x509 -inform DER -in caissued.der -noout -subject 2>/dev/null | sed 's/^subject=//')
ISSU=$("$OSSL" x509 -inform DER -in caissued.der -noout -issuer  2>/dev/null | sed 's/^issuer=//')
chk "a NEW certificate was published under caissued-dcc" yes \
    "$([ -s caissued.der ] && echo yes || echo no)"
chk "  it is NOT self-signed (subject != issuer)" yes \
    "$([ -n "$SUBJ" ] && [ "$SUBJ" != "$ISSU" ] && echo yes || echo no)"
chk "  and its issuer IS the CA the expired row named" yes \
    "$(echo "$ISSU" | grep -q 'Mesh Listener CA' && echo yes || echo no)"
# ⚠️ The discriminator. Without it, "issuer is the CA" could be satisfied by any code path
# that happens to name a CA; this says the SIGNATURE verifies against that CA's key.
chk "  and it VERIFIES against the CA" yes \
    "$("$OSSL" verify -CAfile ca.pem -purpose sslserver \
        <("$OSSL" x509 -inform DER -in caissued.der) >/dev/null 2>&1 && echo yes || echo no)"
# ⚠️ THE HALF THAT MAKES THE NEXT START WORK, and the actual bug behind the redundant key:
# the new row must RECORD its issuer, or the node forgets who signed it and self-signs on
# the following expiry — which is exactly the state it shipped in.
chk "  and the NEW row records its issuer too" "ca" \
    "$(pg_exec "SELECT ca_instance_id FROM certs WHERE cert_id='caissued-dcc' AND serial<>'deadbeef01';" | tr -d ' ')"
kill $P4 2>/dev/null

# And a node with no CA-issued predecessor is unchanged — self-sign is the first-boot case
# (a fresh deployment has no CA at all), not dead code this replaces. node A (ms-dca) never
# had a CA-issued row, so get_transport_ca_id answers "" for it and nothing re-issues.
SS=$(pg_exec "SELECT encode(cert,'base64') FROM certs WHERE cert_id='ms-dca' AND status=0;" | tr -d ' \n')
printf '%s' "$SS" | "$OSSL" base64 -d -A > ss.der 2>/dev/null
SS_S=$("$OSSL" x509 -inform DER -in ss.der -noout -subject 2>/dev/null | sed 's/^subject=//')
SS_I=$("$OSSL" x509 -inform DER -in ss.der -noout -issuer  2>/dev/null | sed 's/^issuer=//')
# ⚠️ PRECONDITION: without it, an unreadable row makes SS_S empty and the equality below
# compares "" to "" — which my own edit did, turning this guard into a decoration.
chk "PRECONDITION: node A's certificate is readable" yes \
    "$([ -n "$SS_S" ] && echo yes || echo no)"
chk "a node with no CA-issued predecessor still self-signs" yes \
    "$([ -n "$SS_S" ] && [ "$SS_S" = "$SS_I" ] && echo yes || echo no)"

echo

echo "=== two nodes, ONE configured MS_KEY: the token objects must not collide ==="
#
# ⚠️ THE SECTIONS ABOVE DELIBERATELY GIVE EACH NODE ITS OWN KEY URI, which is why they never
# caught this. A node with its own token has its own `ms-tls` and nothing collides. Under
# P11_TLS — or a network HSM — every node reaches ONE token while every node's config still
# says `object=ms-tls`, because that string is written by the installer and is identical
# everywhere. CKA_LABEL is free text and PKCS#11 permits duplicates, so both nodes mint a key
# under the SAME label and `object=ms-tls` then resolves to whichever the provider hands
# back. Measured on a three-node cloud mesh before listener_key_uri(): two objects each
# labelled web-tls, est-tls and acme-tls, and a listener refusing to start with
# "the token-resident private key was refused ... key values mismatch".
pg_exec "INSERT INTO datacenters(dc_id, serial_prefix) VALUES('dcd', 4004)
         ON CONFLICT (dc_id) DO NOTHING;" >/dev/null
pg_exec "INSERT INTO datacenters(dc_id, serial_prefix) VALUES('dce', 4005)
         ON CONFLICT (dc_id) DO NOTHING;" >/dev/null
KEY_SHARED=$(hsm_new_key_uri mslistener_shared)
node_conf dcd 18763 d.conf "$KEY_SHARED"
node_conf dce 18764 e.conf "$KEY_SHARED"
"$MS" --config d.conf >d.log 2>&1 & P5=$!
wait_conf "d.conf" MS_PORT "$P5" || true
"$MS" --config e.conf >e.log 2>&1 & P6=$!
wait_conf "e.conf" MS_PORT "$P6" || true
chk "node D started on the shared MS_KEY" yes "$(kill -0 ${P5:-0} 2>/dev/null && echo yes || echo no)"
chk "node E started on the shared MS_KEY" yes "$(kill -0 ${P6:-0} 2>/dev/null && echo yes || echo no)"
chk "node D published ms-dcd" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='ms-dcd' AND status=0;" | tr -d ' ')"
chk "node E published ms-dce" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='ms-dce' AND status=0;" | tr -d ' ')"

# The assertion that would have failed before: each node's certificate must certify a key of
# its OWN, not its peer's. Equal public keys mean both resolved the same token object.
pubkey_of() {   # $1=cert_id -> SPKI, or empty
    local b; b=$(pg_exec "SELECT encode(cert,'base64') FROM certs WHERE cert_id='$1' AND status=0;" | tr -d ' \n')
    [ -n "$b" ] || return 0
    printf '%s' "$b" | "$OSSL" base64 -d -A > "pk_$1.der" 2>/dev/null
    "$OSSL" x509 -inform DER -in "pk_$1.der" -noout -pubkey 2>/dev/null
}
PKD=$(pubkey_of ms-dcd); PKE=$(pubkey_of ms-dce)
chk "PRECONDITION: both certificates are readable" yes \
    "$([ -n "$PKD" ] && [ -n "$PKE" ] && echo yes || echo no)"
chk "the two nodes hold DIFFERENT keys under one configured MS_KEY" yes \
    "$([ -n "$PKD" ] && [ -n "$PKE" ] && [ "$PKD" != "$PKE" ] && echo yes || echo no)"
kill ${P5:-} ${P6:-} 2>/dev/null
echo "=== MESH LISTENER CERT ID: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
