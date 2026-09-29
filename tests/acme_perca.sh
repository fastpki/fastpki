#!/usr/bin/env bash
# Virtualized per-CA ACME. One fastpki-acme serves multiple CA
# hierarchies under /acme/{ca_instance_id}/...: the directory advertises
# in-instance URLs, and a full DNS-01 order finalized under a per-CA endpoint is
# issued by THAT instance's CA and tagged with its ca_instance_id.
#
# The two full orders are driven by REAL certbot, one --server per CA directory,
# which is also the cleanest proof that the per-CA endpoints are a working ACME service
# and not just correctly-shaped JSON. The directory / 404 / 503 assertions below are plain
# curl and involve no client at all, so they are unchanged.
#
# dns-01, so no privileges (no :80) are needed and this stays a CORE suite.
# ⚠️ THIS SUITE REGISTERS WITH A REAL EAB BINDING, and that is the point. It used to
# pin ACME_EAB_REQUIRED=false because it tests ACME PROTOCOL mechanics and not deployment
# policy — but the switch is gone, and pinning it meant fourteen suites exercised a
# configuration FastPKI does not ship. The binding is now provisioned the way a real
# deployment provisions one: acme_seed_eab writes a kid + HMAC to the `keys` table and
# certbot presents them with --eab-kid/--eab-hmac-key.
# The DEFAULT itself is still exercised by acme_default_eab.sh, which provisions NOTHING.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/acme_jws.sh"
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
command -v certbot >/dev/null 2>&1 || { echo "SKIP: certbot not installed (needs the real client)"; exit 0; }
EST_CA="$ROOT/build/fastpki-ca"
W="$(mktemp -d)"; cd "$W"; PORT=18458; DNSP=15355
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Global CA" 3650
GLOBAL_KEY_URI="$CA_KEY_URI"
cp ca.pem root.pem
# The second CA's key is token-born too — a CA private key is never a file.
ca_in_token depta.pem "/CN=Dept A CA" 3650 depta
DEPTA_KEY_URI="$CA_KEY_URI"
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_perca
trap 'pg_cleanup; kill $P 2>/dev/null; pkill -f "dnsstub $DNSP" 2>/dev/null' EXIT
cat > bootstrap.conf <<EOF
BASE_URL=https://localhost:$PORT
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$GLOBAL_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
ACME_CERT=$W/acme.pem
ACME_KEY=$W/acme.key
PG_CONNINFO=$PG_CONNINFO
ACME_BIND=127.0.0.1
ACME_PORT=$PORT
ACME_BASE_PATH=/acme
ACME_DNS_RESOLVER=127.0.0.1:$DNSP
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)

# Register the secondary CA instance with its own signing material.
"$EST_CA" --config bootstrap.conf add dept-a --name "Dept A" --ca-pem "$W/depta.pem" --ca-key "$DEPTA_KEY_URI" >/dev/null

"$ROOT/build/fastpki-acme" --config bootstrap.conf > srv.log 2>&1 & SRV=$!
sleep 1; trap 'kill $SRV 2>/dev/null; pkill -f "dnsstub $DNSP" 2>/dev/null; pg_cleanup' EXIT
if ! kill -0 $SRV 2>/dev/null; then echo "fastpki-acme died:"; cat srv.log; exit 1; fi
U="https://127.0.0.1:$PORT"

echo "=== per-CA directory threading + validation ==="
dir=$(curl -sk "$U/acme/dept-a/directory")
echo "$dir" | grep -q '/acme/dept-a/new-order' && r=ok || r=no
chk "per-CA directory advertises in-instance URLs" ok "$r"
chk "unknown instance directory -> 404" 404 "$(curl -sk -o /dev/null -w '%{http_code}' "$U/acme/nope/directory")"
# ACME is an enrolment protocol, so it is id-based — the base (no-id) directory
# 404s (a CA is never guessed). 'default' is a real CA id (the bootstrap SIGNING_CA),
# but this config names it 'ca' via SIGNING_CA_ID, so /{default} is genuinely unknown.
chk "base (no-id) directory -> 404" 404 "$(curl -sk -o /dev/null -w '%{http_code}' "$U/acme/directory")"
chk "the configured CA's directory serves -> 200" 200 "$(curl -sk -o /dev/null -w '%{http_code}' "$U/acme/ca/directory")"
"$EST_CA" --config bootstrap.conf disable dept-a >/dev/null
chk "disabled instance directory -> 503" 503 "$(curl -sk -o /dev/null -w '%{http_code}' "$U/acme/dept-a/directory")"
"$EST_CA" --config bootstrap.conf enable dept-a >/dev/null

issuer_of_cn() {  # <cn> -> issuer CN of the stored cert
    pg_exec "select encode(cert, 'hex') from certs where cn='$1';" | xxd -r -p > leaf.der 2>/dev/null
    "$OSSL" x509 -inform DER -in leaf.der -issuer -noout 2>/dev/null | sed -n 's/.*CN *= *\(.*\)/\1/p'
}
# certbot (python-requests) trusts the ACME server's self-signed cert through this.
export REQUESTS_CA_BUNDLE="$W/acme.pem"
# The auth hook restarts build/dnsstub carrying this domain's challenge TXT — dnsstub takes
# its records only on the command line. The cleanup hook is a NO-OP on purpose: certbot
# runs it as soon as the challenge validates, i.e. BEFORE finalize, and tearing the
# resolver down there breaks anything the server still needs DNS for (acme_caa.sh was
# issued a certificate for a DENIED domain exactly that way).
cat > authhook.sh <<'HOOK'
#!/usr/bin/env bash
set -u
pkill -f "dnsstub $DNSP" 2>/dev/null; sleep 0.2
rm -f "$W/dns.log"
"$ROOT/build/dnsstub" "$DNSP" "TXT:_acme-challenge.$CERTBOT_DOMAIN=$CERTBOT_VALIDATION" > "$W/dns.log" 2>&1 &
for i in $(seq 1 40); do grep -q READY "$W/dns.log" 2>/dev/null && break; sleep 0.1; done
HOOK
printf '#!/usr/bin/env bash\nexit 0\n' > cleanhook.sh
chmod +x authhook.sh cleanhook.sh
export ROOT W DNSP

acme_seed_eab perca

run_order() {  # <instance> <domain> -> ok|no
    # A SEPARATE certbot config dir per instance: certbot keys its account store by
    # --server, and these are two different directories, so each CA gets its own account
    # exactly as a real deployment would.
    certbot certonly --manual --preferred-challenges dns \
        --server "$U/acme/$1/directory" \
        --config-dir "$W/cb_$1" --work-dir "$W/cbw_$1" --logs-dir "$W/cbl_$1" -n \
        --manual-auth-hook "$W/authhook.sh" --manual-cleanup-hook "$W/cleanhook.sh" \
        --eab-kid "$ACME_EAB_KID" --eab-hmac-key "$ACME_EAB_HMAC" \
        --register-unsafely-without-email --agree-tos \
        --cert-name "$2" -d "$2" > "certbot_$2.log" 2>&1
    [ -f "$W/cb_$1/live/$2/cert.pem" ] && echo ok || echo no
}

echo "=== full order issued by the secondary CA ==="
chk "ca order reached valid"  ok "$(run_order ca def.example.org)"
chk "ca cert signed by the SIGNING_CA"           "Global CA" "$(issuer_of_cn def.example.org)"
chk "ca cert tagged ca_instance_id=ca" ca \
    "$(pg_exec "select ca_instance_id from certs where cn='def.example.org';")"

chk "dept-a order reached valid"   ok "$(run_order dept-a depta.example.org)"
chk "dept-a cert signed by Dept A CA"            "Dept A CA" "$(issuer_of_cn depta.example.org)"
chk "dept-a cert tagged ca_instance_id=dept-a"   dept-a \
    "$(pg_exec "select ca_instance_id from certs where cn='depta.example.org';")"

echo
echo "=== ACME PER-CA: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
