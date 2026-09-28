#!/usr/bin/env bash
# CMP certConf over a DEFAULT keep-alive connection (regression for the bug where
# the IR/IP succeeded but the client's CERTCONF on the reused connection failed
# with "error sending"/"failed reading data", because the server dropped the
# keep-alive socket between messages).
#
# The other CMP suites all pass -keep_alive 0 (fresh connection per message), so
# they do NOT cover this path. Here we deliberately let `openssl cmp` use its
# default (keep_alive=1) and assert the full IR -> IP -> CERTCONF -> PKICONF flow.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
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
W="$(mktemp -d)"; cd "$W"; PORT=18454
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=CMP CA" 3650
# CMP has no CA-key fallback — issue the RA credential from THIS CA
# while CA_KEY_URI still names it, and publish it once the DB exists.
cmp_ra_issue ca.pem "$CA_KEY_URI" || { echo "SKIP: no CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
cp ca.pem root.pem
pg_setup cmp_certconf
cmp_ra_publish || { echo "SKIP: could not publish the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
cat > cmp.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
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
pg_exec "INSERT INTO keys(kid,protocol,key) VALUES('1234','cmp','0000') ON CONFLICT (kid,protocol) DO UPDATE SET key=EXCLUDED.key;" >/dev/null
# The credential needs an IDENTITY holding a profile grant, or
# resolve_profile refuses. seed_enrolling_identity leaves an existing role alone.
seed_enrolling_identity 1234
cmp_ra_conf_lines >> cmp.conf
"$ROOT/build/fastpki-cmp" --config cmp.conf > srv.log 2>&1 & C=$!
sleep 1; trap 'pg_cleanup; kill $C 2>/dev/null' EXIT

echo "=== CMP ir with default keep-alive (certConf round-trip) ==="
# NOTE: no -keep_alive 0 here — that's the whole point.
OUT=$("$OSSL" cmp -cmd ir -server "http://127.0.0.1:$PORT/cmp/ca" -recipient "/CN=CMP CA" \
    -trusted ca.pem -secret pass:0000 -ref 1234 \
    -newkey scratch.key -subject "/CN=host.internal" -certout leaf.pem 2>&1)

echo "$OUT" | grep -q "received PKICONF" && a=yes || a=no
chk "client received PKICONF"        yes "$a"
chk "leaf cert written"              ok  "$( [ -f leaf.pem ] && echo ok || echo no )"
grep -q "certConf confirmed" srv.log && b=yes || b=no
chk "server processed certConf"      yes "$b"
echo "$OUT" | grep -qiE "error (sending|receiving)|failed reading" && e=err || e=clean
chk "no transport error"             clean "$e"
# on-hold -> valid: the confirmed cert must be status 0 (valid) in the DB.
SER=$("$OSSL" x509 -in leaf.pem -noout -serial 2>/dev/null | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
STv=$(pg_exec "select status from certs where serial='$SER';" 2>/dev/null)
chk "confirmed cert is valid (status 0)" 0 "${STv:-none}"
# The accept is now distinguished from a reject and audited as
# cert_confirmed (a certConf carrying PKIStatus "rejection" would revoke instead).
AC=$(pg_exec "select count(*) from audit_log where action='cert_confirmed' and detail like '%CMP%';" 2>/dev/null)
chk "certConf accept audited (cert_confirmed)" 1 "${AC:-0}"
# ⚠️ AND IT CARRIES A SOURCE ADDRESS. CMP writes its audit events from OpenSSL's callbacks,
# which get no request, so every CMP row recorded an empty actor_ip while the other five
# protocols recorded one — an operator reading the log saw CMP transactions that came from
# nowhere. The address is taken at the HTTP layer and stashed for the request. Asserted
# non-empty rather than equal to a literal, because what the loopback client presents
# differs between a v4 and a dual-stack listener and the point is that it is recorded at all.
AIP=$(pg_exec "select count(*) from audit_log where action='cert_confirmed' and detail like '%CMP%' and coalesce(actor_ip,'') <> '';" 2>/dev/null)
chk "  and records where the client came from" 1 "${AIP:-0}"

echo
echo "=== CMP CERTCONF: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
