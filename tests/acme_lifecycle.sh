#!/usr/bin/env bash
# ACME full lifecycle (reworks certbot/tests.sh use-cases):
#   register -> issue (http-01) -> renew --force -> revoke -> unregister
# Asserts each step. Requires root (binds :80, edits /etc/hosts).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/acme_jws.sh"
BIN="$ROOT/build/fastpki-acme"
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
WORK="$(mktemp -d)"; cd "$WORK"; PORT=18444; DOMAIN=acmetest.local
grep -q "$DOMAIN" /etc/hosts || echo "127.0.0.1 $DOMAIN" >> /etc/hosts

ca_in_token ca.pem "/CN=ACME Life CA" 3650
cp ca.pem root.pem
# ACME is HTTPS-only; give the server a TLS cert certbot can trust (below).
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_lifecycle
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > bootstrap.conf <<EOF
BASE_URL=https://localhost:$PORT
SIGNING_CA_PEM=$WORK/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$WORK/root.pem
ACME_CERT=$WORK/acme.pem
ACME_KEY=$WORK/acme.key
PG_CONNINFO=$PG_CONNINFO
ACME_BIND=0.0.0.0
ACME_PORT=$PORT
# ⚠️ THIS SUITE REGISTERS WITH A REAL EAB BINDING. It drives REAL certbot through
# register -> issue -> renew -> revoke -> unregister, and it used to pin
# ACME_EAB_REQUIRED=false so certbot's very first step was not refused 400
# externalAccountRequired. That switch is gone; the binding is now provisioned the way a
# real deployment provisions one, and certbot presents it with --eab-kid/--eab-hmac-key.
#
# ⚠️ This suite is in ROOT_SUITES (it binds :80), so an ordinary unprivileged run does not
# execute it — the EAB regression that broke ca_rollover_chain.sh in plain sight would
# have sat here unseen until someone ran the suite as root.
ACME_BASE_PATH=/acme
CERT_VALIDITY_DAYS=90
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$BIN" --config bootstrap.conf > srv.log 2>&1 & SRV=$!
sleep 1; trap 'pg_cleanup; kill $SRV 2>/dev/null' EXIT

# certbot (python-requests) trusts the self-signed ACME server cert via this bundle.
export REQUESTS_CA_BUNDLE="$WORK/acme.pem"
acme_seed_eab lifecycle
CB=(--server "https://localhost:$PORT/acme/ca/directory" --config-dir "$WORK/cb" --work-dir "$WORK/cbw" --logs-dir "$WORK/cbl" -n \
    --eab-kid "$ACME_EAB_KID" --eab-hmac-key "$ACME_EAB_HMAC")
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2, got $3)"; fail=$((fail+1)); fi; }
# ⚠️ LEAVES ONLY. `count(*) from certs` counts the CA too: a CA instance IS a
# row in `certs`, and seed_ca_from_conf above inserts one, so every count came out +1
# (1->2, 2->3). The numbers here were written before that merge and nothing caught it,
# because this suite self-skips without certbot and had never run on any machine.
ncerts() { pg_exec 'select count(*) from certs where coalesce(is_ca,false)=false;'; }
acctstatus() { pg_exec 'select status from accounts limit 1;' 2>/dev/null; }

echo "=== 1. register + issue ==="
certbot certonly --standalone "${CB[@]}" -d "$DOMAIN" --http-01-port 80 \
    --register-unsafely-without-email --agree-tos >/dev/null 2>&1
[ -f "$WORK/cb/live/$DOMAIN/cert.pem" ] && r=ok || r=no
chk "issue produced a cert" ok "$r"
chk "1 cert in db"          1  "$(ncerts)"
chk "account registered"    0  "$(acctstatus)"

# ⚠️ The SHAPE of a certificate REAL certbot obtained.
#
# ⚠️ A HOME-MADE ACME CLIENT IS NOT ACCEPTED FOR ACME TESTS — compliance is a claim about
# what real clients do. tests/acme_cert_shape.sh already asserts these
# facts, but on a certificate our own shell JWS client fetched over tls-alpn-01 — which
# certbot cannot speak, so that suite cannot move. Asserting the same facts HERE, on the
# file certbot just wrote, is what actually satisfies the ticket: same properties, real
# client, and acme_cert_shape keeps its tls-alpn-01 coverage and its no-root tier.
#
# These are the reported findings — every one was a real defect found in an issued
# certificate, so they are worth pinning against the client operators will really use.
CBCERT="$WORK/cb/live/$DOMAIN/cert.pem"
T=$("$OSSL" x509 -in "$CBCERT" -noout -text 2>/dev/null)
hasx() { echo "$T" | grep -qE "$1" && echo yes || echo no; }
chk "  certbot's cert: KeyUsage present"                yes "$(hasx 'Key Usage')"
chk "  certbot's cert: has Digital Signature"           yes "$(hasx 'Digital Signature')"
# certbot defaults to ECDSA P-256 since 2.0; an EC key must NOT claim keyEncipherment
# (the same rule applies on the transport side).
if [ "$(hasx 'id-ecPublicKey')" = yes ]; then
    chk "  certbot's cert: EC key does NOT claim Key Encipherment" no "$(hasx 'Key Encipherment')"
else
    echo "  [note] certbot issued a non-EC key here; the keyEncipherment rule is EC-only"
fi
chk "  certbot's cert: Subject has a CN"                yes "$(hasx "Subject:.*CN *= *$DOMAIN")"
chk "  certbot's cert: SAN carries the domain"          yes "$(hasx "DNS:$DOMAIN")"
chk "  certbot's cert: DV policy 2.23.140.1.2.1"        yes "$(hasx '2\.23\.140\.1\.2\.1')"
chk "  certbot's cert: owner in Subject Dir Attributes" yes "$(hasx 'Subject Directory Attributes|X509v3 Subject Directory')"
# And it must chain to the ISSUING CA.
# ⚠️ $WORK/ca.pem, NOT acme.pem. This suite has two self-signed certs and they are not
# interchangeable: ca.pem is the issuing CA (ca_in_token, "/CN=ACME Life CA"), acme.pem is
# the ACME listener's own HTTPS cert (ACME_CERT). Verifying a leaf against the transport
# cert would fail for a reason that has nothing to do with issuance.
chk "  certbot's cert verifies against the issuing CA" ok \
    "$("$OSSL" verify -CAfile "$WORK/ca.pem" "$CBCERT" >/dev/null 2>&1 && echo ok || echo no)"

echo "=== 2. renew --force ==="
# ⚠️ --no-random-sleep-on-renew, OR THIS ONE LINE COSTS UP TO EIGHT MINUTES. `certbot renew`
# deliberately staggers itself so the world's cron jobs do not all hit Let's Encrypt at the
# same instant: renewal.py applies `random.uniform(1, 60 * 8)` — 1 to 480 seconds — whenever
# `not sys.stdin.isatty()`, which is always true under this harness. It is the right default
# for a real cron job and pure dead time for a test that forces the renewal itself.
#
# That single sleep WAS the whole variance of this suite: measured at 76s, 154s, 280s, 339s
# and 350s across five runs of identical code, while every other section of the suite takes
# about eleven seconds in total. It also made this the slowest suite in the tree and
# therefore the floor for the entire sharded run, and — worse than slow — it made the
# suite's recorded duration meaningless, so the shard scheduler could not balance around it.
certbot renew --cert-name "$DOMAIN" --force-renewal --no-random-sleep-on-renew "${CB[@]}" \
    --standalone --http-01-port 80 >/dev/null 2>&1
chk "2 certs in db after renew" 2 "$(ncerts)"

echo "=== 3. revoke (live cert) ==="
SER=$("$OSSL" x509 -in "$WORK/cb/live/$DOMAIN/cert.pem" -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
certbot revoke --cert-name "$DOMAIN" --no-delete-after-revoke "${CB[@]}" >/dev/null 2>&1
chk "live cert revoked (status -1)" -1 "$(pg_exec "select status from certs where serial='$SER';")"
# Audit producers: ACME issuance + revocation must be logged.
chk "ACME issuance audited"   1 "$([ "$(pg_exec "select count(*) from audit_log where action='cert_issued' and detail like '%ACME%';")" -ge 1 ] && echo 1 || echo 0)"
chk "ACME revocation audited" 1 "$([ "$(pg_exec "select count(*) from audit_log where action='cert_revoked' and detail like '%ACME%';")" -ge 1 ] && echo 1 || echo 0)"

echo "=== 4. unregister (deactivate account) ==="
certbot unregister "${CB[@]}" >/dev/null 2>&1
chk "account deactivated (status 1)" 1 "$(acctstatus)"

echo
echo "=== LIFECYCLE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
