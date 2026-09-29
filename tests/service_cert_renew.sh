#!/usr/bin/env bash
# `fastpki-ca renew-service-certs` — automatic reissue of the service credentials.
#
# ── The gap ──────────────────────────────────────────────────────────────────────
#
# FastPKI issues itself credentials that are neither CA certificates nor certificates a
# client asked for: the CMP RA, the OCSP responder and the SCEP RA.
# Nothing reissued them. They are short-lived by design — a delegated responder carries
# id-pkix-ocsp-nocheck precisely because clients are told not to check its revocation —
# so each one went dark, silently, on the day it expired.
#
# ── The settled answers, which this implements ────────────────────────────
#
#   trigger    cron is standard, k8s has it and it runs inside a docker container just
#              as well  -> a CLI subcommand, NOT a timer inside each service
#   threshold  3/4 of the lifetime
#   scope      OCSP has the urgency; automate the others too where practical
#
# ⚠️ Why the trigger MUST be one invoker: `certs` is logically replicated across every
# node. A per-process timer fires on all of them at once and they race to publish under
# the same cert_id — the two-certificates-one-cert_id state identified earlier and that
# Slice B found live on the lab, where it made a healthy responder return
# "Response Verify Failure" on one node and verify fine on the other two.
#
# Assertions decode real certificates and read the DB — not exit codes.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"
unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
skipout(){ echo "  [SKIP] $1"; echo; echo "=== SERVICE CERT RENEW: PASS=$pass FAIL=$fail SKIP=1 ==="; exit 0; }

pg_setup service_cert_renew
trap 'pg_cleanup' EXIT

ca_in_token ca.pem "/CN=Renew CA" 3650 renewca || skipout "no token"

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
# ⚠️ A PUBLIC NAME, because without one there are no addresses to put in a certificate.
# AIA and CRL DP are derived from BASE_URL, or PKI_DNS when that is unset, so a fixture
# with neither produces credentials carrying no revocation information — and a suite built
# on it cannot tell "the code does not add them" from "there was nothing to add". Every
# real deployment has one; the installers ask for it before anything else.
PKI_DNS=pki.test
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=renewca
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf

CA="$ROOT/build/fastpki-ca"

# Provision an OCSP responder credential the ordinary way, then point the config at it.
RKEY=$(ocsp_responder_key "$W/ca.pem" "$CA_KEY_URI" renewca "$W") || skipout "could not provision a responder"
printf 'OCSP_RESPONDER_KEY=%s\n' "$RKEY" >> bootstrap.conf
ORIG=$(pg_exec "SELECT serial FROM certs WHERE cert_id='ocsp-ra-renewca' AND status=0;" | tr -d ' ')
chk "a responder credential exists to renew" yes "$([ -n "$ORIG" ] && echo yes || echo no)"

echo "=== a FRESH certificate is not due — the run must be a no-op ==="
OUT=$("$CA" --config bootstrap.conf renew-service-certs 2>&1)
chk "the run succeeds" 0 "$?"
chk "  nothing was renewed" yes "$(echo "$OUT" | grep -q 'renewed 0' && echo yes || echo no)"
chk "  and the certificate is untouched" "$ORIG" \
    "$(pg_exec "SELECT serial FROM certs WHERE cert_id='ocsp-ra-renewca' AND status=0;" | tr -d ' ')"

echo "=== --dry-run with --force reports without changing anything ==="
OUT=$("$CA" --config bootstrap.conf renew-service-certs --force --dry-run 2>&1)
chk "dry run says it WOULD renew" yes "$(echo "$OUT" | grep -q 'would renew ocsp-ra-renewca' && echo yes || echo no)"
chk "  but the certificate did not change" "$ORIG" \
    "$(pg_exec "SELECT serial FROM certs WHERE cert_id='ocsp-ra-renewca' AND status=0;" | tr -d ' ')"

echo "=== ⚠️ THE RENEWAL: same key, new certificate, exactly one active ==="
OUT=$("$CA" --config bootstrap.conf renew-service-certs --force 2>&1)
NEW=$(pg_exec "SELECT serial FROM certs WHERE cert_id='ocsp-ra-renewca' AND status=0;" | tr -d ' ')
chk "a new certificate was issued" yes "$([ -n "$NEW" ] && [ "$NEW" != "$ORIG" ] && echo yes || echo no)"
# THE assertion this was broken by: two live rows make the service resolve an
# arbitrary one and sign with a key that may not match the certificate it presents.
chk "  exactly ONE active certificate for the cert_id" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='ocsp-ra-renewca' AND status=0;" | tr -d ' ')"
chk "  the previous one is RETIRED, not deleted" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='ocsp-ra-renewca' AND serial='$ORIG' AND status<>0;" | tr -d ' ')"

pg_exec "SELECT encode(cert,'base64') FROM certs WHERE serial='$NEW';" | tr -d ' \n' | base64 -d > new.der 2>/dev/null
"$OSSL" x509 -inform DER -in new.der -out new.pem 2>/dev/null
NT=$("$OSSL" x509 -in new.pem -noout -text 2>/dev/null)

# ⚠️ The renewal must not quietly drop what MAKES it a responder credential.
# fastpki-ocsp REFUSES a non-CA responder without id-pkix-ocsp-nocheck (RFC 6960 §2.1.2),
# so a renewal that lost it would produce a credential the responder rejects — a renewal
# that breaks the very thing it renewed, and only at the next query.
chk "  it still carries OCSPSigning" yes \
    "$(echo "$NT" | grep -q 'OCSP Signing' && echo yes || echo no)"
chk "  it still carries id-pkix-ocsp-nocheck" yes \
    "$(echo "$NT" | grep -qiE 'OCSP No Check|1\.3\.6\.1\.5\.5\.7\.48\.1\.5' && echo yes || echo no)"
chk "  and the subject is unchanged" yes \
    "$(echo "$NT" | grep -q 'OCSP Responder renewca' && echo yes || echo no)"

# ⚠️ serverAuth must NOT survive a renewal. It was retracted for these three credentials
# — the standards do not require it — and renewal
# copies the EKU off the certificate it replaces — so without an explicit drop, every
# credential already carrying serverAuth would keep it forever and fixing the console
# preset would change nothing on any running deployment.
chk "  serverAuth is GONE from the renewed certificate" no \
    "$(echo "$NT" | grep -q 'TLS Web Server Authentication' && echo yes || echo no)"
# ...and the drop is surgical: the purposes that MAKE it a responder are still there
# (asserted above), so this is not "renewal loses extensions".

# "One key, N certificates" — the renewal must certify the SAME key, not mint a new one.
"$OSSL" x509 -in new.pem -noout -modulus 2>/dev/null | sed 's/^Modulus=//' > new.mod
"$OSSL" rsa -in "$RKEY" -noout -modulus 2>/dev/null | sed 's/^Modulus=//' > key.mod
chk "  the renewed certificate certifies the SAME key" yes \
    "$([ -s new.mod ] && [ -s key.mod ] && cmp -s new.mod key.mod && echo yes || echo no)"
# And it is issued by the CA, not self-signed or issued by something else.
chk "  issued by the CA" yes \
    "$("$OSSL" verify -CAfile "$W/ca.pem" new.pem 2>&1 | grep -q ': OK' && echo yes || echo no)"

echo "=== ⚠️ a CA this node holds NO key for is SKIPPED, not failed ==="
# Found on the live lab, not here: in a mesh every node sees every CA — its own with a
# pkcs11 key, the others as keyless trust anchors it verifies against and never signs
# with. Counting those as failures made a perfectly healthy three-DC lab print
# "failed 4" on every node, which as a daily cron job is an alarm that fires forever for
# the normal state. The node that HOLDS the key renews that credential on its own tick.
# A genuinely separate CA: `certs.serial` is the primary key, so re-registering the same
# certificate under a second id collides rather than creating an anchor.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout anchor.key -out anchor.pem -days 365 \
        -subj "/CN=Anchor CA" -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
# No --ca-key: registered as a trust anchor this instance verifies against and never
# signs with — the same shape a peer DC's CA has when it replicates to this node.
"$CA" --config bootstrap.conf add anchorca --name "Anchor" --ca-pem "$W/anchor.pem" >/dev/null 2>&1
chk "a keyless trust-anchor CA is registered" yes \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='anchorca' AND is_ca;" | tr -d ' ' | grep -q '^1$' && echo yes || echo no)"
# Give it a credential to find, so the run reaches the no-signing-key branch.
# Give the anchor its own credential so the run REACHES the no-signing-key branch.
# It must be a distinct certificate: republishing an existing serial would move that row
# to the new cert_id instead of adding one.
( unset CA_OSSL_ARGS; ocsp_responder_key "$W/anchor.pem" "$W/anchor.key" anchorca "$W" ) >/dev/null 2>&1 || true
chk "  the anchor has a credential to find" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='ocsp-ra-anchorca' AND status=0;" | tr -d ' ')"
OUT=$("$CA" --config bootstrap.conf renew-service-certs --force 2>&1); RC=$?
chk "the run still exits 0" 0 "$RC"
chk "  it reports the CA as skipped, not failed" yes \
    "$(echo "$OUT" | grep -q 'skipped ocsp-ra-anchorca' && echo yes || echo no)"
chk "  and the failure count is zero" yes \
    "$(echo "$OUT" | grep -qE 'failed 0$' && echo yes || echo no)"

echo "=== ⚠️ one invoker at a time: a concurrent run STANDS DOWN, it does not race ==="
# `certs` is replicated, so cron on three DCs fires three simultaneous runs. Without
# mutual exclusion all three read the same certificate, all issue, and all insert —
# two live certificates under one cert_id, the state that made a healthy lab responder
# answer "Response Verify Failure". Deterministic here: another session HOLDS the lock,
# rather than hoping to win a real race.
LOCK=6221515358067838551
BEFORE=$(pg_exec "SELECT serial FROM certs WHERE cert_id='ocsp-ra-renewca' AND status=0;" | tr -d ' ')
"$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -tAq \
    -c "SELECT pg_advisory_lock($LOCK); SELECT pg_sleep(20);" >/dev/null 2>&1 &
HOLDER=$!
# Wait for the lock to actually be held — asserting against a lock that was never taken
# would pass for the wrong reason.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ "$(pg_exec "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND granted;" | tr -d ' ')" != "0" ] && break
    sleep 0.3
done
chk "the lock is genuinely held by the other session" 1 \
    "$(pg_exec "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND granted;" | tr -d ' ')"
OUT=$("$CA" --config bootstrap.conf renew-service-certs --force 2>&1); RC=$?
chk "the second invoker exits 0 — losing the race is not an error" 0 "$RC"
chk "  and says another node is doing it" yes \
    "$(echo "$OUT" | grep -q 'another node is already renewing' && echo yes || echo no)"
chk "  and issued NOTHING" "$BEFORE" \
    "$(pg_exec "SELECT serial FROM certs WHERE cert_id='ocsp-ra-renewca' AND status=0;" | tr -d ' ')"
# ⚠️ Killing the psql CLIENT does not release the lock: the backend sits in pg_sleep()
# and only notices the disconnect when it next writes. Terminate the BACKEND, which is
# also the honest model of a crashed job — the session dies and Postgres drops the lock.
kill $HOLDER 2>/dev/null; wait $HOLDER 2>/dev/null
pg_exec "SELECT pg_terminate_backend(pid) FROM pg_locks
         WHERE locktype='advisory' AND granted;" >/dev/null 2>&1
for _ in $(seq 1 40); do
    [ "$(pg_exec "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND granted;" | tr -d ' ')" = "0" ] && break
    sleep 0.25
done
chk "  a dead holder does not wedge the lock" 0 \
    "$(pg_exec "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND granted;" | tr -d ' ')"
OUT=$("$CA" --config bootstrap.conf renew-service-certs --force 2>&1)
chk "once the holder exits, the next run proceeds" yes \
    "$(echo "$OUT" | grep -q 'renewed ocsp-ra-renewca' && echo yes || echo no)"

echo "=== --ca scopes the run to one CA ==="
OUT=$("$CA" --config bootstrap.conf renew-service-certs --ca nosuchca --force 2>&1)
chk "an unknown --ca renews nothing" yes "$(echo "$OUT" | grep -q 'checked 0' && echo yes || echo no)"

# ⚠️ CREATION, which is a different operation from renewal: there is no previous
# certificate to copy a subject and purposes from, so they come from the built-in
# definition, and the KEY does not exist either and has to be minted in the token.
# This is the path an unattended install runs instead of opening the console.
# ⚠️ A ROOT GETS NOTHING. Nothing enrols against a root — a CMP or SCEP RA there would
# front a CA that issues sub CAs and nothing else — so iterating every CA must SKIP it
# rather than hand it three credentials it can never use. `renewca` is self-signed.
echo "=== --create-missing skips a ROOT ==="
CMPURI=$(hsm_new_key_uri cmp-ra-created) || skipout "no token for the create test"
printf 'CMP_RA_KEY=%s\nCMP_RA_KEY_ALGO=ec\nCMP_RA_KEY_CURVE=P-384\n' "$CMPURI" >> bootstrap.conf
cmpcount(){ pg_exec "SELECT count(*) FROM certs WHERE cert_id='cmp-ra-$1' AND status=0;" | tr -d ' '; }

OUT=$("$CA" --config bootstrap.conf renew-service-certs --create-missing 2>&1)
chk "the root is given no CMP RA" 0 "$(cmpcount renewca)"
chk "  and the run says why" yes "$(echo "$OUT" | grep -q 'is a root' && echo yes || echo no)"
# A skip, never a failure: this is the normal state of every root, not an error to alarm on.
chk "  and it counts as skipped, not failed" yes \
    "$(echo "$OUT" | grep -qE 'failed 0' && echo yes || echo no)"

echo "=== --create-missing creates the credential on an ISSUING CA, key and all ==="
SUBURI=$(hsm_new_key_uri renew-subca)
"$CA" --config bootstrap.conf create subca --name "Renew Sub" --parent renewca \
      --ca-key "$SUBURI" --keygen --key ec --curve P-256 >subca.log 2>&1 || true
SUBOK=$(pg_exec "SELECT count(*) FROM certs WHERE id='subca' AND is_ca;" | tr -d ' ')
chk "a sub CA exists to create credentials under" 1 "$SUBOK"
[ "${SUBOK:-0}" = 1 ] || { echo "  --- sub CA creation log ---"; tail -8 subca.log; }

# THE assertion that keeps the daily cron tick safe: a run without the flag must leave a
# missing credential missing. Minting keys and issuing certificates on a timer, for
# something nobody asked for, is precisely what this must never do.
OUT=$("$CA" --config bootstrap.conf renew-service-certs --force 2>&1)
chk "an ordinary run does NOT create it" 0 "$(cmpcount subca)"

OUT=$("$CA" --config bootstrap.conf renew-service-certs --create-missing --dry-run 2>&1)
chk "dry run says it WOULD create" yes \
    "$(echo "$OUT" | grep -q 'would create cmp-ra-subca' && echo yes || echo no)"
chk "  but created nothing" 0 "$(cmpcount subca)"

OUT=$("$CA" --config bootstrap.conf renew-service-certs --create-missing 2>&1)
chk "the credential is created" 1 "$(cmpcount subca)"
chk "  and the run says so" yes "$(echo "$OUT" | grep -q 'created cmp-ra-subca' && echo yes || echo no)"

pg_exec "SELECT encode(cert,'base64') FROM certs WHERE cert_id='cmp-ra-subca' AND status=0;" \
    | tr -d ' \n' | base64 -d > cmp.der 2>/dev/null
"$OSSL" x509 -inform DER -in cmp.der -out cmp.pem 2>/dev/null
chk "  the subject is the built-in name, not PKI_DNS" yes \
    "$("$OSSL" x509 -in cmp.pem -noout -subject 2>/dev/null | grep -q 'FastPKI CMP' && echo yes || echo no)"
# RFC 9810 §8.6: an RA protecting CMP messages is identified by id-kp-cmcRA. Both
# spellings, because whether OpenSSL prints a name or the OID depends on the build.
chk "  it carries id-kp-cmcRA" yes \
    "$("$OSSL" x509 -in cmp.pem -noout -text 2>/dev/null \
       | grep -qE '1\.3\.6\.1\.5\.5\.7\.3\.28|CMC Registration Authority' && echo yes || echo no)"
# The EKU must be exactly what the definition says. An empty purpose list would make
# issuance fall back to the profile default of serverAuth+clientAuth, so a credential
# that quietly gained serverAuth is the failure this catches.
chk "  and does NOT carry serverAuth" no \
    "$("$OSSL" x509 -in cmp.pem -noout -text 2>/dev/null \
       | grep -qE 'TLS Web Server Authentication' && echo yes || echo no)"
# The key was minted to the CONFIGURED type, not to a hardcoded default.
chk "  the key is the EC P-384 that was asked for" yes \
    "$("$OSSL" x509 -in cmp.pem -noout -text 2>/dev/null \
       | grep -qE 'secp384r1|P-384' && echo yes || echo no)"

# The key it just minted cannot leave this token — which is right for a single node, and is
# the whole of the problem on a pair: the scheduled job has no command line to put
# --replicable on, and CKA_EXTRACTABLE cannot be granted afterwards.
# The token these keys live in is the one ca_in_token made, named inside CA_KEY_URI.
TOKEN_LABEL=$(printf '%s' "${CA_KEY_URI:-}" | sed -n 's/.*token=\([^;?]*\).*/\1/p')
CMPLABEL=$(printf '%s' "$CMPURI" | sed -n 's/.*object=\([^;?]*\).*/\1/p')
chk "  the key it minted is NOT replicable" no \
    "$(hsm_key_extractable "$TOKEN_LABEL" "$CMPLABEL" 2>/dev/null)"

# Idempotent: the credential now exists, so a second create run is an ordinary
# not-due renewal and must not issue a second active certificate.
OUT=$("$CA" --config bootstrap.conf renew-service-certs --create-missing 2>&1)
chk "running it again creates nothing further" 1 "$(cmpcount subca)"

echo "=== SERVICE_KEYS_REPLICABLE carries the decision to a run with no command line ==="
# The scheduled job — Compose's certrenew, the Kubernetes renew container, the OpenRC periodic — runs
# `renew-service-certs --create-missing` and nothing else, so on an HA pair it decided for ever
# that these keys could not reach the standby: CKA_EXTRACTABLE is fixed at generation. The
# setting says it where a cron tick can read it, and the flag still wins for a single run.
#
# ⚠️ A FRESH HANDLE, because the RA key is ONE KEY PER PROCESS. Pointing CMP_RA_KEY at the
# key that already exists would mint nothing — the run would find it and renew the
# certificate — and the assertion would be about the key the previous section made.
sed 's|^CMP_RA_KEY=.*|CMP_RA_KEY='"$(hsm_new_key_uri cmp-ra-repl)"'|' bootstrap.conf > repl.conf
pg_exec "INSERT INTO config(key,value) VALUES('SERVICE_KEYS_REPLICABLE','true')
         ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value;" >/dev/null
OUT=$("$CA" --config repl.conf renew-service-certs --create-missing 2>&1)
chk "a run with no flag still creates the credential" yes \
    "$(echo "$OUT" | grep -qE 'created cmp-ra-subca' && echo yes || echo no)"
[ -n "$OUT" ] && echo "$OUT" | grep -qE 'created cmp-ra' || echo "  --- run output ---
$OUT"
chk "  and the setting made its key replicable" yes \
    "$(hsm_key_extractable "$TOKEN_LABEL" cmp-ra-repl 2>/dev/null)"
pg_exec "DELETE FROM config WHERE key='SERVICE_KEYS_REPLICABLE';" >/dev/null

# ── the credentials carry the signing CA's addresses ──────────────────────────────────────
#
# ⚠️ ASSERTED BECAUSE IT WAS MISSING FOR EVERY ONE OF THEM. Both minting paths passed a null
# CaUrls to issuance, so no service credential carried AIA or a CRL distribution point — and
# the OCSP responder, the one credential that is SUPPOSED to carry neither, looked right by
# accident. An operator found it on a running deployment: CMP and SCEP RA certificates that
# no relying party could check for revocation.
#
# The responder's absence is the deliberate half (RFC 6960 §4.2.2.2.1 — a responder pointing
# at itself for its own status is a loop), so both directions are asserted here: one
# credential that must have them, and one that must not.
cred_ext_count() {   # <cert_id> <extension> — how many URIs that extension holds
    pg_exec "SELECT encode(cert,'base64') FROM certs WHERE cert_id='$1' AND status=0;" \
        | tr -d ' \n' | base64 -d > "$W/cred.der" 2>/dev/null
    "$OSSL" x509 -inform DER -in "$W/cred.der" -noout -ext "$2" 2>/dev/null | grep -c 'URI:'
}
# What the credential actually came out with, printed only when an assertion below fails —
# "expected yes got no" cannot distinguish a certificate without the extension from a
# certificate this helper failed to read.
cred_dump_uris() {   # <cert_id> — every URI the certificate carries, one per line
    pg_exec "SELECT encode(cert,'base64') FROM certs WHERE cert_id='$1' AND status=0;" \
        | tr -d ' \n' | base64 -d > "$W/cred.der" 2>/dev/null
    "$OSSL" x509 -inform DER -in "$W/cred.der" -noout -text 2>/dev/null | grep -oE 'URI:[^ ]+'
}
cred_dump() {
    echo "  --- $1 as issued ---"
    pg_exec "SELECT encode(cert,'base64') FROM certs WHERE cert_id='$1' AND status=0;" \
        | tr -d ' \n' | base64 -d > "$W/cred.der" 2>/dev/null
    "$OSSL" x509 -inform DER -in "$W/cred.der" -noout -text 2>&1 \
        | grep -A3 -iE 'Authority Information|CRL Distribution' | head -12
}
CMP_CRLDP=$(cred_ext_count cmp-ra-subca crlDistributionPoints)
CMP_AIA=$(cred_ext_count cmp-ra-subca authorityInfoAccess)
chk "the CMP RA credential carries a CRL distribution point" yes \
    "$([ "${CMP_CRLDP:-0}" -ge 1 ] && echo yes || echo no)"
chk "  and an issuer address" yes \
    "$([ "${CMP_AIA:-0}" -ge 1 ] && echo yes || echo no)"
[ "${CMP_CRLDP:-0}" -ge 1 ] && [ "${CMP_AIA:-0}" -ge 1 ] || cred_dump cmp-ra-subca
chk "the OCSP responder carries neither, which is the rule for a responder" yes \
    "$([ "$(cred_ext_count ocsp-ra-renewca crlDistributionPoints)" -eq 0 ] &&
       [ "$(cred_ext_count ocsp-ra-renewca authorityInfoAccess)" -eq 0 ] && echo yes || echo no)"

# ── and they name THIS node only, however many data centers exist ─────────────────────────
#
# ⚠️ A SERVICE CREDENTIAL IS NOT AN END-ENTITY CERTIFICATE. A leaf outlives any particular
# node's availability, so naming every data center gives a relying party somewhere else to
# go. A CMP or SCEP RA credential is presented by the service running on THIS node: nothing
# validates it while this node is down, because the service that would have presented it is
# down too. A peer's address therefore buys nothing, and costs an address that is wrong
# whenever the peer does not replicate this CA — permanently, because a certificate's URLs
# are fixed when it is minted.
pg_exec "INSERT INTO datacenters(dc_id, serial_prefix, base_url) VALUES
           ('dc2', 2, 'https://peer-dc2.example'),
           ('dc3', 3, 'https://peer-dc3.example')
         ON CONFLICT (dc_id) DO NOTHING;" >/dev/null
# ⚠️ repl.conf, NOT bootstrap.conf. The live cmp-ra-subca certificate certifies the key the
# SERVICE_KEYS_REPLICABLE section minted, and bootstrap.conf still names the earlier one — so
# renewing with it is refused, correctly, as certifying the wrong key. Using the config whose
# key matches is what makes this assertion about URLs rather than about that refusal.
SER_BEFORE=$(pg_exec "SELECT serial FROM certs WHERE cert_id='cmp-ra-subca' AND status=0;" | tr -d ' ')
OUT=$("$CA" --config repl.conf renew-service-certs --ca subca --force 2>&1)
chk "a renewal with two peers present still succeeds" yes \
    "$(echo "$OUT" | grep -qE 'failed 0' && echo yes || echo no)"
echo "$OUT" | grep -qE 'failed 0' || { echo "  --- renewal output ---"; echo "$OUT" | tail -6; }
# ⚠️ PROVE IT WAS RE-ISSUED AFTER THE PEERS EXISTED. Without this the two assertions below
# would pass by reading the certificate minted earlier in the suite, when the table held one
# data center — a test that cannot fail is worse than no test.
SER_AFTER=$(pg_exec "SELECT serial FROM certs WHERE cert_id='cmp-ra-subca' AND status=0;" | tr -d ' ')
chk "  PRECONDITION: the credential really was re-issued" yes \
    "$([ -n "$SER_AFTER" ] && [ "$SER_AFTER" != "$SER_BEFORE" ] && echo yes || echo no)"
chk "  and the CMP RA still names ONE CRL distribution point" 1 \
    "$(cred_ext_count cmp-ra-subca crlDistributionPoints)"
chk "  and one issuer address, not the peers'" yes \
    "$(cred_dump_uris cmp-ra-subca | grep -qE 'peer-dc[23]\.example' && echo no || echo yes)"

echo
echo "=== SERVICE CERT RENEW: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
