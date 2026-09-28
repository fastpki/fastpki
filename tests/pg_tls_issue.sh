#!/usr/bin/env bash
# The console issues the PostgreSQL server's own TLS certificate.
#
# The requirement: issue CA-signed certificates for postgres the same way as for every
# other FastPKI service, then restart postgres. For that, the postgres endpoint has to be
# listed in the web console, and the certificate and its key have to be written to files
# in a volume mounted into the postgres container.
#
# What broke before this existed: `deploy/pg-tls.sh` was referenced nine times and was
# not in the tree. The lab was RUNNING a CA-issued Postgres certificate, so nothing was
# visibly wrong — what had been lost was the ability to produce one again. A fresh
# deployment, a re-key or a wiped volume left the mesh on a self-signed certificate with
# no path back.
#
# ⚠️ This is the ONE certificate in FastPKI whose private key is a file. PostgreSQL has
# no PKCS#11 support at all — ssl_key_file is a filesystem path — so the HSM route every
# other listener takes cannot serve it. §3f permits a file exactly here, and the test
# asserts the file pair is real and usable rather than trusting the 200.
#
# What it asserts, by decoding artifacts:
#   * the certificate is CA-ISSUED (issuer == the CA's subject), not self-signed
#   * server.key is 0600 and its public half matches the certificate's
#   * openssl verify against ca.crt succeeds — i.e. the anchor the applications are
#     pointed at really does validate what Postgres will serve
#   * SANs cover every name PG_CONNINFO can dial, plus the configured extras
#   * the row is tagged cert_id='postgres' and carries ca_instance_id
#   * re-issuing RETIRES the previous certificate: one cert_id, one active row
#   * ca.crt ACCUMULATES the anchor rather than replacing it, which is what stops
#     verify-full failing for the ~30s before Postgres reloads
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: that default path is a Linux convention and is absent on other dev boxes. Without
# this every "$OSSL" call fails silently and each assertion compares empty strings, which
# reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
unset OPENSSL_CONF
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18147
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

pg_setup pg_tls_issue
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
ca_in_token ca.pem "/CN=PG Issuing CA" 3650 pgca

source "$ROOT/tests/user_helpers.sh"
seed_web_user boss bosspw admin

PGTLS="$W/pgtls"
mkdir -p "$PGTLS"
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=pgca
PKI_DNS=pki.example.org
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
PG_TLS_DIR=$PGTLS
# The interconnect address a mesh node's peers subscribe over — the SAN that only the
# deployment knows. It is config and NOT a request parameter on purpose: see the handler.
PG_TLS_SANS=10.10.10.99,db.example.org
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf

# Phase 1, as certgen leaves it: a self-signed Postgres certificate that is its own
# anchor. The suite starts from this state because the interesting behaviour is the
# HANDOVER — an anchor swapped in one step is what takes every application off the
# database for as long as Postgres has not reloaded.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout "$PGTLS/server.key" \
    -out "$PGTLS/server.crt" -days 30 -subj "/CN=postgres" \
    -addext "subjectAltName=DNS:postgres,DNS:localhost,IP:127.0.0.1" \
    >/dev/null 2>&1
cp "$PGTLS/server.crt" "$PGTLS/ca.crt"
chmod 600 "$PGTLS/server.key"
SELFSIGNED_BEFORE=$("$OSSL" x509 -in "$PGTLS/server.crt" -noout -fingerprint -sha256 2>/dev/null)
SELFSIGNED_PEM=$(cat "$PGTLS/server.crt")

"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat srv.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null

echo "=== the database is listed as an endpoint (the first ask) ==="
EP=$(curl -s -b boss.cj "$U/api/endpoints")
chk "PostgreSQL has a row on the Endpoints page" yes "$(has "$EP" '"protocol":"PostgreSQL"')"
# ⚠️ THE ISSUE ACTION IS NOT ON THIS PAGE ANY MORE, and that is the point of the row's
# remaining fields. Issuing the database certificate moved to Inventory, beside the other
# certificate actions, because an "Endpoints" page is a strange home for issuance — and it
# cannot be Inventory's ordinary "Request (key in HSM)" either, since postgres reads its
# private key off DISK and can never hold it in a token. So the row is still LISTED here
# (it is an endpoint worth seeing) and carries no action flag at all.
chk "  and it carries no issue-certificate flag (that action moved to Inventory)" no \
    "$(has "$EP" '"pgTls"')"
# It must NOT be gateable or restartable: both write a config key that only a FastPKI
# binary reads, and this listener is the stock postgres image. A button that cannot work
# is worse than no button.
PGROW=$(echo "$EP" | tr '{' '\n' | grep '"protocol":"PostgreSQL"')
chk "  no on/off switch (nothing in that container reads the gate)"  yes "$(has "$PGROW" '"gateable":false')"
chk "  no restart button (same reason)"                              yes "$(has "$PGROW" '"restartable":false')"

echo "=== a CA is required — there is no default ==="
CODE=$(curl -s -o r.json -w '%{http_code}' -b boss.cj -X POST "$U/api/pg-tls" -d '')
chk "no ca_instance -> 400" 400 "$CODE"
CODE=$(curl -s -o r.json -w '%{http_code}' -b boss.cj -X POST "$U/api/pg-tls" -d 'ca_instance=nosuchca')
chk "unknown CA -> 404"     404 "$CODE"

echo "=== issue it ==="
CODE=$(curl -s -o iss.json -w '%{http_code}' -b boss.cj -X POST "$U/api/pg-tls" \
        -d 'ca_instance=pgca&key=rsa&bits=2048')
chk "POST /api/pg-tls -> 200" 200 "$CODE"
SER=$(sed -n 's/.*"serial":"\([^"]*\)".*/\1/p' iss.json)
chk "the response names a serial" yes "$([ -n "$SER" ] && echo yes || echo no)"

echo "=== the FILE pair Postgres will read ==="
chk "server.crt written" yes "$([ -f "$PGTLS/server.crt" ] && echo yes || echo no)"
chk "server.key written" yes "$([ -f "$PGTLS/server.key" ] && echo yes || echo no)"
# ⚠️ Postgres REFUSES to start on a key with group or world access — "private key file
# has group or world access" — so this is not a hygiene assertion, it is the difference
# between a database that starts and one that does not.
# ⚠️ GNU FORM FIRST. `stat -f` is the BSD/macOS spelling, but on busybox (which is what
# the shipped Alpine image has) -f means "filesystem status" — it SUCCEEDS, prints
# something else entirely, and the `||` fallback never runs. Measured in the image:
# expected '600', got a multi-line "File: ..." block. Probing with the form that ERRORS
# on the wrong platform is what makes the fallback work at all; -c errors on macOS.
MODE=$(stat -c '%a' "$PGTLS/server.key" 2>/dev/null || stat -f '%Lp' "$PGTLS/server.key" 2>/dev/null)
chk "server.key is 0600" 600 "$MODE"

SUBJ=$("$OSSL" x509 -in "$PGTLS/server.crt" -noout -subject | sed 's/^subject= *//')
ISS=$("$OSSL" x509 -in "$PGTLS/server.crt" -noout -issuer  | sed 's/^issuer= *//')
chk "it is CA-ISSUED, not self-signed (subject != issuer)" no "$([ "$SUBJ" = "$ISS" ] && echo yes || echo no)"
chk "  and the issuer is our CA" yes "$(has "$ISS" 'PG Issuing CA')"
chk "  the self-signed one is gone" no \
    "$([ "$("$OSSL" x509 -in "$PGTLS/server.crt" -noout -fingerprint -sha256)" = "$SELFSIGNED_BEFORE" ] && echo yes || echo no)"

TXT=$("$OSSL" x509 -in "$PGTLS/server.crt" -noout -text)
chk "EKU serverAuth"                 yes "$(has "$TXT" 'TLS Web Server Authentication')"
chk "SAN covers postgres"            yes "$(has "$TXT" 'DNS:postgres')"
chk "SAN covers localhost"           yes "$(has "$TXT" 'DNS:localhost')"
chk "SAN covers 127.0.0.1"           yes "$(has "$TXT" 'IP Address:127.0.0.1')"
# The two halves of PG_TLS_SANS, one typed as an IP and one as a DNS name by
# general_name_of(). A deployment that lists its interconnect address here and gets a
# DNS:10.10.10.99 back has a certificate no peer can verify.
chk "SAN covers the configured interconnect IP" yes "$(has "$TXT" 'IP Address:10.10.10.99')"
chk "SAN covers the configured extra DNS name"  yes "$(has "$TXT" 'DNS:db.example.org')"
chk "PKI_DNS is covered too"                    yes "$(has "$TXT" 'DNS:pki.example.org')"

# The only real proof the pair is usable: the certificate's public key and the key file's
# public half are the same bytes. A cert issued for a DIFFERENT key is issued, stored,
# reported successful — and Postgres refuses the pair at startup with the whole story in
# a log line inside the container.
CPUB=$("$OSSL" x509 -in "$PGTLS/server.crt" -noout -pubkey)
KPUB=$("$OSSL" pkey -in "$PGTLS/server.key" -pubout)
chk "the certificate certifies THIS key file" yes "$([ "$CPUB" = "$KPUB" ] && echo yes || echo no)"

echo "=== the anchor the applications verify against ==="
VOUT=$("$OSSL" verify -CAfile "$PGTLS/ca.crt" "$PGTLS/server.crt" 2>&1)
chk "openssl verify -CAfile ca.crt server.crt succeeds" yes "$(has "$VOUT" ': OK')"
# ⚠️ ACCUMULATES, does not replace. Postgres does not serve the new certificate until it
# reloads (up to ~30s). Replacing the anchor outright leaves the applications trusting
# only the new CA while the database still presents the old certificate — verify-full
# then refuses every new connection for the length of that window.
ANCHORS=$(grep -c 'BEGIN CERTIFICATE' "$PGTLS/ca.crt")
chk "ca.crt kept the previous anchor as well as the new one" 2 "$ANCHORS"
chk "  the phase-1 self-signed certificate is still in it" yes \
    "$(grep -qF "$(echo "$SELFSIGNED_PEM" | sed -n '2p')" "$PGTLS/ca.crt" && echo yes || echo no)"
chk "  the new CA anchor is FIRST, so it is the one a reader hits first" yes \
    "$(has "$("$OSSL" x509 -in "$PGTLS/ca.crt" -noout -subject)" 'PG Issuing CA')"

echo "=== the inventory row ==="
chk "tagged cert_id=postgres" "postgres" "$(pg_exec "SELECT coalesce(cert_id,'') FROM certs WHERE serial='$SER';")"
chk "carries ca_instance_id"  "pgca"     "$(pg_exec "SELECT coalesce(ca_instance_id,'') FROM certs WHERE serial='$SER';")"
chk "status is valid"         "0"        "$(pg_exec "SELECT status FROM certs WHERE serial='$SER';")"
# private_key means "the token object this certificate's key lives at". This key is a
# FILE, so claiming a handle would offer Re-key in the console on a certificate the
# console cannot re-key that way.
chk "no token handle claimed (the key is a file)" "" "$(pg_exec "SELECT coalesce(private_key,'') FROM certs WHERE serial='$SER';")"

echo "=== re-issuing retires the previous one: ONE cert_id, ONE active certificate ==="
# Two live rows under one cert_id is not cosmetic — the resolver breaks ties on
# notAfter/serial and would pick an arbitrary one. Measured on the lab for the OCSP
# responder credential, where it produced "Response Verify Failure" against an
# otherwise healthy responder.
sleep 1
CODE=$(curl -s -o iss2.json -w '%{http_code}' -b boss.cj -X POST "$U/api/pg-tls" \
        -d 'ca_instance=pgca&key=ec&curve=P-256')
chk "second issuance -> 200" 200 "$CODE"
SER2=$(sed -n 's/.*"serial":"\([^"]*\)".*/\1/p' iss2.json)
chk "a different certificate" no "$([ "$SER" = "$SER2" ] && echo yes || echo no)"
chk "the previous one is retired (status 3)" "3" "$(pg_exec "SELECT status FROM certs WHERE serial='$SER';")"
chk "exactly one ACTIVE row for cert_id=postgres" "1" \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='postgres' AND status=0;")"
# An EC key gets digitalSignature only. keyEncipherment means "this key wraps a session
# key", which is RSA key transport — an EC key cannot do it, and asserting the bit would
# claim a capability the key does not have.
TXT2=$("$OSSL" x509 -in "$PGTLS/server.crt" -noout -text)
chk "the EC certificate does NOT assert keyEncipherment" no "$(has "$TXT2" 'Key Encipherment')"
chk "  it does assert digitalSignature"                  yes "$(has "$TXT2" 'Digital Signature')"
CPUB2=$("$OSSL" x509 -in "$PGTLS/server.crt" -noout -pubkey)
KPUB2=$("$OSSL" pkey -in "$PGTLS/server.key" -pubout)
chk "the re-issued pair still matches" yes "$([ "$CPUB2" = "$KPUB2" ] && echo yes || echo no)"

echo "=== a REFUSED request leaves the running certificate exactly where it was ==="
# Everything that can fail is checked before anything is written — a half-applied
# issuance is worse than a refused one, because it takes every application off the
# database (verify-full against an anchor that no longer matches what Postgres serves).
BEFORE=$("$OSSL" x509 -in "$PGTLS/server.crt" -noout -serial)
BEFORE_KEY=$("$OSSL" pkey -in "$PGTLS/server.key" -pubout)
BEFORE_ANCHORS=$(grep -c 'BEGIN CERTIFICATE' "$PGTLS/ca.crt")
CODE=$(curl -s -o r3.json -w '%{http_code}' -b boss.cj -X POST "$U/api/pg-tls" -d 'ca_instance=pgca&key=nosuchalgo')
chk "an unknown key algorithm is refused" no "$([ "$CODE" = "200" ] && echo yes || echo no)"
chk "  the served certificate is untouched" "$BEFORE" "$("$OSSL" x509 -in "$PGTLS/server.crt" -noout -serial)"
chk "  the key file is untouched"           "$BEFORE_KEY" "$("$OSSL" pkey -in "$PGTLS/server.key" -pubout)"
chk "  the anchor file is untouched"        "$BEFORE_ANCHORS" "$(grep -c 'BEGIN CERTIFICATE' "$PGTLS/ca.crt")"

echo "=== the renewal SWEEP maintains it, with no command of its own ==="
# ⚠️ THIS REPLACED A REAL OUTAGE CLASS, so it is asserted by RUNNING the sweep rather than by
# grepping for a call. While the database's certificate was maintained only by `fastpki-ca
# pg-tls`, every scheduled renewer had to invoke that command for itself: the Kubernetes and
# native jobs never did, and compose's call sat inside `if P11_TLS = on`, which is off unless
# asked for. So on the default shape the certificate was issued once by hand and then expired
# with nothing to replace it — and every application fails sslmode=verify-full against a
# database that is up and read-write, the CLIs included, since they share that conninfo.
#
# renew_service_certs_for_ca now maintains it directly, which is why this suite can prove the
# property with the ordinary renewal command and no mention of pg-tls at all.
CA_CLI="$ROOT/build/fastpki-ca"
# A precondition, not a skip: this suite already requires build/fastpki-web, so the CLI beside it
# is equally present, and a silent skip here would report green while proving nothing.
chk "PRECONDITION: the CLI is built" yes "$([ -x "$CA_CLI" ] && echo yes || echo no)"
if [ -x "$CA_CLI" ]; then
    # Name the CA for the unattended path, as an operator does once. It is never guessed: a
    # database certificate quietly re-issued by an unintended CA is worse than one not yet
    # replaced, so with PG_TLS_CA_ID unset the sweep leaves the database alone.
    printf 'PG_TLS_CA_ID=pgca\n' >> "$W/bootstrap.conf"
    # Take the served pair away, as a wiped volume or a freshly seeded standby would.
    rm -f "$PGTLS/server.crt" "$PGTLS/server.key"
    SWEEP=$("$CA_CLI" --config "$W/bootstrap.conf" renew-service-certs 2>&1)
    chk "renew-service-certs alone restores the pair" yes \
        "$([ -s "$PGTLS/server.crt" ] && [ -s "$PGTLS/server.key" ] && echo yes || echo no)"
    # ⚠️ SAY WHY, not just that. Without this the failure is "the file is not there", and the
    # reason — which CA the sweep walked, whether PG_TLS_CA_ID matched it, what it refused — is
    # only visible by rerunning the command by hand inside a container that no longer exists.
    if [ ! -s "$PGTLS/server.crt" ]; then
        printf '    sweep output: %s\n' "$SWEEP" | head -12
        printf '    PG_TLS_CA_ID in conf: %s\n' "$(sed -n 's/^PG_TLS_CA_ID=//p' "$W/bootstrap.conf")"
        printf '    registered CAs: %s\n' \
            "$("$CA_CLI" --config "$W/bootstrap.conf" list 2>&1 | awk '{print $1}' | tr '\n' ' ')"
    fi
    chk "  the sweep reports it as a credential it handled" yes \
        "$(echo "$SWEEP" | grep -q 'PostgreSQL server TLS' && echo yes || echo no)"
    # ⚠️ GUARDED ON THE FILE EXISTING. Comparing two decodes of an absent file compares two empty
    # strings, which PASSES — so an earlier version of these two assertions reported green on
    # exactly the run where the certificate had not been written at all.
    if [ -s "$PGTLS/server.crt" ] && [ -s "$PGTLS/server.key" ]; then
        # CA-issued, not a self-signed stand-in: the issuer must be the CA's subject.
        CA_SUBJ=$("$OSSL" x509 -in "$W/ca.pem" -noout -subject | sed 's/^subject=//')
        NEW_ISS=$("$OSSL" x509 -in "$PGTLS/server.crt" -noout -issuer | sed 's/^issuer=//')
        chk "  and it is CA-issued, not self-signed" "$CA_SUBJ" "$NEW_ISS"
        CPUB3=$("$OSSL" x509 -in "$PGTLS/server.crt" -noout -pubkey)
        KPUB3=$("$OSSL" pkey -in "$PGTLS/server.key" -pubout)
        chk "  the pair matches" yes \
            "$([ -n "$CPUB3" ] && [ "$CPUB3" = "$KPUB3" ] && echo yes || echo no)"
    else
        chk "  and it is CA-issued, not self-signed" yes "no (nothing was written)"
        chk "  the pair matches"                     yes "no (nothing was written)"
    fi
    # ⚠️ AND A SECOND SWEEP MUST NOT CHURN IT. The sweep runs daily on every deployment; minting
    # a fresh certificate each time would burn serials, fill the inventory and replace a
    # perfectly good key for nothing. That is what the freshness check inside the sweep is for.
    SER_A=$("$OSSL" x509 -in "$PGTLS/server.crt" -noout -serial)
    "$CA_CLI" --config "$W/bootstrap.conf" renew-service-certs >/dev/null 2>&1
    # Guarded for the same reason: an absent file decodes to the empty string both times, so this
    # would report "unchanged" on a run that never produced a certificate.
    chk "  PRECONDITION: there is a serial to compare" yes \
        "$([ -n "$SER_A" ] && echo yes || echo no)"
    chk "  a second sweep leaves it alone" "$SER_A" \
        "$("$OSSL" x509 -in "$PGTLS/server.crt" -noout -serial 2>/dev/null)"

    echo "=== and it checks what a STANDBY would serve, the way a client does ==="
    # ⚠️ THE GAP THIS CLOSES. Applications dial the primary and replication makes the standby the
    # CLIENT of it, so the certificate the standby SERVES is verified by nobody until a failover
    # re-homes every application onto it. A deployment whose standby served certgen's self-signed
    # pair passed a full demo with zero failures and zero skips, then broke at the promotion.
    #
    # The addresses come from PG_CONNINFO, which already names both hosts of a pair, so a
    # single-host conninfo means no standby and nothing to probe. Asserted FIRST, because that is
    # what keeps this silent on every ordinary deployment.
    ONE=$("$CA_CLI" --config "$W/bootstrap.conf" renew-service-certs 2>&1)
    chk "silent when the conninfo names one host (no standby)" no \
        "$(echo "$ONE" | grep -qE 'could not reach the database|serves a certificate' \
           && echo yes || echo no)"

    # ⚠️ AND AN UNREACHABLE HOST IS NOT A CERTIFICATE FAULT. A standby stopped for maintenance
    # must not fail the nightly run, or the finding that matters is lost in an alarm nobody can
    # act on. A name that cannot resolve is the cheapest unreachable host there is.
    # ⚠️ APPEND TO THE host= VALUE, not to the end of the line. `s|^PG_CONNINFO=.*|&,host2|`
    # appends to whatever field comes LAST, which is the password — so the conninfo still named one
    # host, the probe was correctly silent, and the assertions below failed while the file
    # contained the string they were looking for.
    sed -i.bak "s|^\(PG_CONNINFO=.*host=[^ ]*\)|\1,no-such-standby.invalid|" "$W/bootstrap.conf"
    # And the precondition has to read the HOST LIST, not grep the file: the version that grepped
    # for the name anywhere in the file passed on exactly the broken edit above.
    PGHOSTS=$(sed -n 's/^PG_CONNINFO=.*host=\([^ ]*\).*/\1/p' "$W/bootstrap.conf" | head -1)
    chk "PRECONDITION: the conninfo's host list now names two hosts" yes \
        "$(printf '%s' "$PGHOSTS" | grep -q ',' && echo yes || echo no)"
    chk "  and the second of them is the unreachable one" yes \
        "$(printf '%s' "$PGHOSTS" | grep -q 'no-such-standby.invalid$' && echo yes || echo no)"
    TWO=$("$CA_CLI" --config "$W/bootstrap.conf" renew-service-certs 2>&1); TWO_RC=$?
    chk "an unreachable standby is reported" yes \
        "$(echo "$TWO" | grep -q 'no-such-standby.invalid' && echo yes || echo no)"
    chk "  as something other than a certificate fault" yes \
        "$(echo "$TWO" | grep -q 'not a certificate fault' && echo yes || echo no)"
    # The run must still succeed: an unreachable standby is availability, and failing here would
    # make the renewal job red every night on a deployment whose certificates are all correct.
    chk "  and the renewal still succeeds" 0 "$TWO_RC"
fi

echo
echo "=== PG TLS ISSUE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
