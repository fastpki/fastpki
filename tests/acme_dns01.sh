#!/usr/bin/env bash
# ACME DNS-01 (RFC 8555 §8.4), driven by REAL certbot.
#
# ⚠️ A HOME-MADE ACME CLIENT IS NOT ACCEPTED FOR ACME TESTS. Compliance is a claim about
# what real clients do, so it has to be proved with one: this suite used to drive the shell
# JWS client in tests/acme_jws.sh, and now runs `certbot certonly --preferred-challenges dns`
# and asserts on what certbot and the database say. certbot's own Python is fine — the
# no-Python rule covers OUR tests, not third-party tools.
#
# dns-01 needs no privileged port, so this stays a CORE suite that runs on any dev box.
# build/dnsstub is a test-only binary (tests/tools/dnsstub.cpp explains why that one piece
# cannot be shell: shell variables cannot hold the NUL bytes a DNS packet is full of).
#
# ⚠️ TWO assertions genuinely changed shape, and both are WEAKER. Say so rather than let
# a green run imply the old coverage:
#
#   "newOrder -> 201" and "finalize -> 200" read the literal HTTP status. certbot cannot
#   report either: acme/client.py's `_check_response` branches on `response.ok`, so every
#   2xx looks alike and no status code reaches the caller. They become "the order reached
#   valid and a certificate exists", checked in OUR database — which is a statement about
#   the outcome rather than the wire.
#
# What did NOT weaken: the DB assertions and the decoded certificate. Those are the ones
# that would catch an issuance bug, and they are unchanged.
# â ï¸ THIS SUITE REGISTERS WITH A REAL EAB BINDING, and that is the point. It used to
# pin ACME_EAB_REQUIRED=false because it tests ACME PROTOCOL mechanics and not deployment
# policy â but the switch is gone, and pinning it meant fourteen suites exercised a
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
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
[ -n "$OSSL" ] || { echo "SKIP: no openssl on PATH"; exit 0; }
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
# Only adopt the system openssl.cnf where it really is one. On macOS this path is a stub
# that defines no providers, and exporting it breaks every pkcs11 load — the CA key then
# cannot be minted and the suite SKIPs for a reason that looks nothing like "wrong
# openssl.cnf". Tests must not assume a Linux layout (§3d).
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
command -v certbot >/dev/null 2>&1 || { echo "SKIP: certbot not installed (needs the real client)"; exit 0; }
[ -x "$ROOT/build/dnsstub" ] || { echo "SKIP: build/dnsstub not built"; exit 0; }

W="$(mktemp -d)"; cd "$W"; PORT=18456; DNSP=15353; DOMAIN=dns01.example.org
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=DNS01 CA" 3650 || { echo "SKIP: could not mint a CA key in a token"; exit 0; }
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_dns01
# ⚠️ ONE trap, set once. bash EXIT traps do NOT stack — a later `trap ... EXIT` REPLACES
# this one — and that is exactly what used to happen here: a second trap dropped
# pg_cleanup, so every run leaked its throwaway database.
SRV=
trap 'kill $SRV 2>/dev/null; pkill -f "dnsstub $DNSP" 2>/dev/null; pg_cleanup' EXIT
cat > bootstrap.conf <<EOF
BASE_URL=https://localhost:$PORT
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
ACME_CERT=$W/acme.pem
ACME_KEY=$W/acme.key
PG_CONNINFO=$PG_CONNINFO
ACME_BIND=127.0.0.1
ACME_PORT=$PORT
ACME_BASE_PATH=/acme
ACME_DNS_RESOLVER=127.0.0.1:$DNSP
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-acme" --config bootstrap.conf > srv.log 2>&1 & SRV=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$SRV" || true
if ! kill -0 $SRV 2>/dev/null; then echo "fastpki-acme died:"; cat srv.log; exit 1; fi

# certbot (python-requests) trusts the ACME server's self-signed cert through this.
export REQUESTS_CA_BUNDLE="$W/acme.pem"
acme_seed_eab dns01
CB=(--server "https://localhost:$PORT/acme/ca/directory"
    --config-dir "$W/cb" --work-dir "$W/cbw" --logs-dir "$W/cbl" -n
    --eab-kid "$ACME_EAB_KID" --eab-hmac-key "$ACME_EAB_HMAC")

# dnsstub takes its records on the command line and has no runtime update, so the auth
# hook restarts it carrying this domain's challenge TXT. certbot only inverts WHEN the
# value is known — the hook is handed $CERTBOT_VALIDATION instead of the test deriving it
# from the token and the account thumbprint itself.
cat > authhook.sh <<'HOOK'
#!/usr/bin/env bash
set -u
pkill -f "dnsstub $DNSP" 2>/dev/null; sleep 0.2
rm -f "$W/dns.log"
"$ROOT/build/dnsstub" "$DNSP" "TXT:_acme-challenge.$CERTBOT_DOMAIN=$CERTBOT_VALIDATION" > "$W/dns.log" 2>&1 &
for i in $(seq 1 40); do grep -q READY "$W/dns.log" 2>/dev/null && break; sleep 0.1; done
HOOK
# ⚠️ The cleanup hook must NOT stop the DNS server. certbot runs cleanup as soon as the
# CHALLENGE validates, which is BEFORE finalize — tearing the stub down there breaks
# anything the server re-checks at finalize. (acme_caa.sh learned this the hard way: the
# DENIED domain was issued a certificate.) The next auth hook replaces the stub; the EXIT
# trap kills the last one.
printf '#!/usr/bin/env bash\nexit 0\n' > cleanhook.sh
chmod +x authhook.sh cleanhook.sh
export ROOT W DNSP

echo "=== ACME DNS-01 order, driven by real certbot ==="
out=$(certbot certonly --manual --preferred-challenges dns "${CB[@]}" \
        --manual-auth-hook "$W/authhook.sh" --manual-cleanup-hook "$W/cleanhook.sh" \
        --register-unsafely-without-email --agree-tos \
        --cert-name "$DOMAIN" -d "$DOMAIN" 2>&1)
printf '%s\n' "$out" > certbot.log

chk "certbot completed the dns-01 order"  yes \
    "$([ -f "$W/cb/live/$DOMAIN/cert.pem" ] && echo yes || echo no)"
# The account exists because certbot registered one — the old suite asserted this from its
# own newAccount response; here it is the server's own record that says so.
chk "the server registered an ACME account" yes \
    "$([ "$(pg_exec "select count(*) from accounts;" | tr -d ' ')" -ge 1 ] && echo yes || echo no)"

echo "=== the server's own record of the order ==="
# Replaces the literal "newOrder -> 201" / "finalize -> 200": the outcome, not the wire.
#
# ⚠️ Two things here are not what they look like, and I got both wrong first:
#   status is an INTEGER, not the RFC's string. `status='valid'` gives
#     ERROR: invalid input syntax for type integer: "valid"
#     include/pki/acme_db.hpp:21-24 is the mapping — order 3=valid, challenge 2=valid.
#   identifiers / identifier are BYTEA holding JSON, so they print as \x5b7b… and no
#     LIKE on the raw column can ever match a hostname. convert_from() reads them.
# The table names have no acme_ prefix either. Every one of those errors returns an EMPTY
# string from pg_exec, which fails against 1 — loud. Against 0 it would have PASSED on a
# query that never ran, which is the trap worth remembering.
chk "the order reached valid"  1 \
    "$(pg_exec "select count(*) from orders
                where status=3 and convert_from(identifiers,'UTF8') like '%$DOMAIN%';" | tr -d ' ')"
chk "it was validated over dns-01" 1 \
    "$(pg_exec "select count(*) from authorizations a join challenges c on c.\"authorization\"=a.id
                where convert_from(a.identifier,'UTF8') like '%$DOMAIN%'
                  and c.type='dns-01' and c.status=2;" | tr -d ' ')"
chk "cert row in db" 1 "$(pg_exec "select count(*) from certs where cn='$DOMAIN';" | tr -d ' ')"

echo "=== the issued artifact is decoded, not trusted (§3d) ==="
chk "the issued leaf carries the SAN" yes \
    "$("$OSSL" x509 -in "$W/cb/live/$DOMAIN/cert.pem" -noout -text 2>/dev/null \
       | grep -q "DNS:$DOMAIN" && echo yes || echo no)"
chk "  and it chains to our CA" yes \
    "$("$OSSL" verify -CAfile "$W/root.pem" -untrusted "$W/cb/live/$DOMAIN/chain.pem" \
        "$W/cb/live/$DOMAIN/cert.pem" >/dev/null 2>&1 && echo yes || echo no)"

[ "$fail" -eq 0 ] || { echo "--- certbot said:"; tail -25 certbot.log; echo "--- server:"; tail -15 srv.log; }
echo
echo "=== ACME DNS01: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
