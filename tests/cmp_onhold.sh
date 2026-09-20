#!/usr/bin/env bash
# CMP on-hold-until-certConf. fastpki-cmp now recovers the client's
# implicit-confirm request from the PKIHeader generalInfo (our own ASN.1,
# pki::parse_cmp_request) and persists accordingly:
#   - implicit confirm requested  -> VALID (0) at once (no certConf will come)
#   - not requested               -> ON-HOLD (2) until the client's certConf
#                                     flips it to valid (or rejects -> revoked)
#
#   A) -implicit_confirm            -> status 0 (valid)
#   B) -disable_confirm (no IC)     -> status 2 (on-hold, never confirmed) +
#                                      OCSP reports it revoked/certificateHold
#   C) normal ir (no IC, sends certConf) -> on-hold then status 0 (valid)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
# These suites use -trusted, not -srvcert. Responses are protected by the RA
# credential now, so pinning the CA as the exact server cert can never match; the
# client validates the chain RA -> CA against that anchor instead.
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
W="$(mktemp -d)"; cd "$W"; PORT=18098; OPORT=18099
SECRET=onholdsecret
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }
norm() { "$OSSL" x509 -in "$1" -serial -noout | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//'; }

ca_in_token ca.pem "/CN=OnHold CA" 3650
# CMP has no CA-key fallback — issue the RA credential from THIS CA
# while CA_KEY_URI still names it, and publish it once the DB exists.
cmp_ra_issue ca.pem "$CA_KEY_URI" || { echo "SKIP: no CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
pg_setup cmp_onhold
cmp_ra_publish || { echo "SKIP: could not publish the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
cat > cmp.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
CMP_BIND=127.0.0.1
CMP_PORT=$PORT
CMP_PATH=/cmp
LOG_LEVEL=info
EOF
seed_ca_from_conf cmp.conf   # register the CA (SIGNING_CA_* no longer seed it)
# CMP PBM is PER USER — the global CMP_PBM_SECRET is gone. Every reference the
# client sends below needs its own `keys` row, or the server installs no secret and the
# MAC cannot verify. That is the point of the change: there is nothing to fall back to.
pg_exec "INSERT INTO keys(kid,protocol,key) VALUES('tester','cmp','$SECRET') ON CONFLICT (kid,protocol) DO UPDATE SET key=EXCLUDED.key;" >/dev/null
# The credential needs an IDENTITY holding a profile grant, or
# resolve_profile refuses. seed_enrolling_identity leaves an existing role alone.
seed_enrolling_identity tester
cmp_ra_conf_lines >> cmp.conf
"$ROOT/build/fastpki-cmp" --config cmp.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null; kill ${O:-0} 2>/dev/null' EXIT

base=( -cmd ir -server "http://127.0.0.1:$PORT/cmp/ca" -recipient "/CN=OnHold CA" -trusted ca.pem
       -secret "pass:$SECRET" -ref tester -keep_alive 0 -newkey scratch.key )

echo "=== On-hold until certConf ==="

# A) implicit confirm -> valid immediately
"$OSSL" cmp "${base[@]}" -subject "/CN=a.example.internal" -implicit_confirm -certout a.pem >/dev/null 2>&1
sa=$(norm a.pem); stA=$(pg_exec "SELECT status FROM certs WHERE serial='$sa';")
chk "implicit-confirm cert persisted valid (0)" 0 "${stA:-none}"

# B) no implicit confirm, client skips certConf -> stays on-hold (2)
"$OSSL" cmp "${base[@]}" -subject "/CN=b.example.internal" -disable_confirm -certout b.pem >/dev/null 2>&1
sb=$(norm b.pem); stB=$(pg_exec "SELECT status FROM certs WHERE serial='$sb';")
chk "unconfirmed cert persisted on-hold (2)" 2 "${stB:-none}"

# C) no implicit confirm, client sends certConf -> on-hold then valid (0)
"$OSSL" cmp "${base[@]}" -subject "/CN=c.example.internal" -certout c.pem >/dev/null 2>&1
sc=$(norm c.pem); stC=$(pg_exec "SELECT status FROM certs WHERE serial='$sc';")
chk "confirmed cert flipped to valid (0)" 0 "${stC:-none}"
nconf=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='cert_confirmed';")
chk "certConf produced a cert_confirmed audit event" 1 "${nconf:-0}"

# OCSP: the on-hold cert (B) must report revoked / certificateHold.
cat > ocsp.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
# ⚠️ SIGNING_CA_ID is required here too — without it seed_ca_from_conf falls back to a
# GENERATED id and re-inserts the same certificate under a different CA, which fails on
# the serial primary key. This second seed had therefore never registered anything, and
# nobody noticed because the duplicate-key line looked like the harmless one that eleven
# other suites printed on a green run.
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
OCSP_BIND=127.0.0.1
OCSP_PORT=$OPORT
LOG_LEVEL=err
EOF
seed_ca_from_conf ocsp.conf   # register the CA (SIGNING_CA_* no longer seed it)
# Slice B: the CA key never signs a status response, so the responder needs its
# own certificate issued BY this CA -- otherwise fastpki-ocsp refuses every query.
printf 'OCSP_RESPONDER_KEY=%s\n' "$(ocsp_responder_key "$W/ca.pem" "$CA_KEY_URI" ca "$W")" >> ocsp.conf

"$ROOT/build/fastpki-ocsp" --config ocsp.conf >ocsp.log 2>&1 & O=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "ocsp.conf" OCSP_PORT "$O" || true
"$OSSL" ocsp -issuer ca.pem -cert b.pem -url "http://127.0.0.1:$OPORT/" -resp_text -noverify >ob.txt 2>&1
grep -qiE "Cert Status: revoked" ob.txt && st=hold || st=notheld
chk "OCSP reports on-hold cert as revoked (certificateHold)" hold "$st"
grep -qiE "certificateHold" ob.txt && rh=yes || rh=no
chk "OCSP revocation reason = certificateHold" yes "$rh"

echo
echo "=== CMP ON-HOLD: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
