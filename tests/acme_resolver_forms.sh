#!/usr/bin/env bash
# ACME_DNS_RESOLVER: the three spellings an operator can legitimately write.
#
# The key used to be an IPv4 LITERAL and nothing else. Both DNS queries in
# src/acme/main.cpp ran inet_pton(AF_INET) over the configured string, so a HOSTNAME and
# an IPv6 LITERAL each failed the same silent way — query_txt() returned an empty vector,
# which the dns-01 validator reads as "that name has no TXT record". The authz then sat
# `pending` until the order timed out, with nothing anywhere naming the cause.
#
# ⚠️ WHY THIS IS NOT A THEORETICAL PORTABILITY NICETY. A real demo run could not
# complete a dns-01 order on macOS, and this is why. On Docker Desktop the compose bridge
# gateway is NOT the host — measured, a datagram sent there never arrives — so the only
# address a container can use to reach the host is `host-gateway`, and Docker Desktop
# resolves that to an **IPv6** address (fdc4:f303:9324::254). An IPv4-only resolver
# parser cannot be pointed at the host at all on that platform.
#
# The three cases below are the product's own dns-01 path, driven by real certbot,
# and each asserts on a decoded certificate rather than an exit code.
#
#   127.0.0.1:PORT   IPv4 literal — the one form that always worked; the regression guard.
#   localhost:PORT   a name. ⚠️ This one ALSO proves dns_exchange() asks EVERY address
#                    getaddrinfo returns: `localhost` gives ::1 first on most hosts, the
#                    stub is bound on 127.0.0.1 only, and connect() on a UDP socket
#                    performs no handshake — so it SUCCEEDS against ::1 where nothing is
#                    listening. Stopping at the first address would report "no records".
#   [::1]:PORT       IPv6 literal, with the stub bound on ::1 — the Docker Desktop shape.
#
# Self-contained per §3d: own CA in a token, own throwaway Postgres, own ports.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/acme_jws.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
[ -n "$OSSL" ] || { echo "SKIP: no openssl on PATH"; exit 0; }
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
command -v certbot >/dev/null 2>&1 || { echo "SKIP: certbot not installed (needs the real client)"; exit 0; }
[ -x "$ROOT/build/dnsstub" ] || { echo "SKIP: build/dnsstub not built"; exit 0; }

W="$(mktemp -d)"; cd "$W"; PORT=18471; DNSP=15371
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Resolver Forms CA" 3650 || { echo "SKIP: could not mint a CA key in a token"; exit 0; }
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_resolver_forms
# ⚠️ ONE trap, set once — bash EXIT traps do NOT stack, a second `trap … EXIT` REPLACES
# this one and the throwaway database leaks.
SRV=
trap 'kill $SRV 2>/dev/null; pkill -f "dnsstub .*:$DNSP" 2>/dev/null; pkill -f "dnsstub $DNSP" 2>/dev/null; pg_cleanup' EXIT

export REQUESTS_CA_BUNDLE="$W/acme.pem"
export ROOT W DNSP

# The auth hook restarts the stub carrying this domain's challenge TXT (dnsstub has no
# runtime update). STUB_BIND says which address to bind — that is what makes the IPv6 case
# a real IPv6 case rather than a differently-spelled loopback.
cat > authhook.sh <<'HOOK'
#!/usr/bin/env bash
set -u
pkill -f "dnsstub $STUB_BIND " 2>/dev/null; sleep 0.2
rm -f "$W/dns.log"
"$ROOT/build/dnsstub" "$STUB_BIND" "TXT:_acme-challenge.$CERTBOT_DOMAIN=$CERTBOT_VALIDATION" \
    > "$W/dns.log" 2>&1 &
for i in $(seq 1 40); do grep -q READY "$W/dns.log" 2>/dev/null && break; sleep 0.1; done
HOOK
# ⚠️ Cleanup must NOT stop the stub: certbot runs it as soon as the CHALLENGE validates,
# which is BEFORE finalize, and the server re-checks names at finalize (acme_caa.sh
# learned this by issuing a certificate for a DENIED domain).
printf '#!/usr/bin/env bash\nexit 0\n' > cleanhook.sh
chmod +x authhook.sh cleanhook.sh

# <label> <resolver-as-configured> <stub-bind-arg> <domain>
run_case() {
    local label=$1 resolver=$2 bind=$3 domain=$4
    echo "=== $label — ACME_DNS_RESOLVER=$resolver, stub on $bind ==="
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
ACME_DNS_RESOLVER=$resolver
LOG_LEVEL=info
EOF
    seed_ca_from_conf bootstrap.conf
    "$ROOT/build/fastpki-acme" --config bootstrap.conf > "srv-$domain.log" 2>&1 & SRV=$!
    # Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
  wait_port "$PORT" "$SRV" || true
    if ! kill -0 $SRV 2>/dev/null; then
        chk "fastpki-acme started with resolver '$resolver'" yes no
        sed -n '1,15p' "srv-$domain.log"; return
    fi
    acme_seed_eab "eab-$domain" >/dev/null 2>&1
    STUB_BIND="$bind" certbot certonly --manual --preferred-challenges dns \
        --server "https://localhost:$PORT/acme/ca/directory" \
        --config-dir "$W/cb-$domain" --work-dir "$W/cbw-$domain" --logs-dir "$W/cbl-$domain" -n \
        --eab-kid "$ACME_EAB_KID" --eab-hmac-key "$ACME_EAB_HMAC" \
        --manual-auth-hook "$W/authhook.sh" --manual-cleanup-hook "$W/cleanhook.sh" \
        --register-unsafely-without-email --agree-tos \
        --cert-name "$domain" -d "$domain" > "certbot-$domain.log" 2>&1

    chk "certbot completed the dns-01 order" yes \
        "$([ -f "$W/cb-$domain/live/$domain/cert.pem" ] && echo yes || echo no)"
    # The authz actually going valid is the assertion that distinguishes "the resolver was
    # reached" from "the order failed for some other reason".
    chk "  the dns-01 authz reached valid" 1 \
        "$(pg_exec "select count(*) from authorizations a join challenges c on c.\"authorization\"=a.id
                    where convert_from(a.identifier,'UTF8') like '%$domain%'
                      and c.type='dns-01' and c.status=2;" | tr -d ' ')"
    # Decode the artifact — a completed order is not the claim; THIS name, from THIS CA is.
    chk "  the issued leaf carries the SAN" yes \
        "$("$OSSL" x509 -in "$W/cb-$domain/live/$domain/cert.pem" -noout -text 2>/dev/null \
           | grep -q "DNS:$domain" && echo yes || echo no)"
    chk "  and it chains to our CA" yes \
        "$("$OSSL" verify -CAfile "$W/root.pem" -untrusted "$W/cb-$domain/live/$domain/chain.pem" \
            "$W/cb-$domain/live/$domain/cert.pem" >/dev/null 2>&1 && echo yes || echo no)"
    [ -f "$W/cb-$domain/live/$domain/cert.pem" ] || { echo "  --- certbot:"; tail -12 "certbot-$domain.log"; }
    kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; SRV=
    pkill -f "dnsstub $bind " 2>/dev/null
    sleep 0.3
}

run_case "IPv4 literal (regression guard)" "127.0.0.1:$DNSP" "127.0.0.1:$DNSP" v4lit.example.org
run_case "a HOSTNAME"                      "localhost:$DNSP"  "127.0.0.1:$DNSP" byname.example.org
run_case "an IPv6 literal"                 "[::1]:$DNSP"      "[::1]:$DNSP"     v6lit.example.org

echo
echo "=== ACME RESOLVER FORMS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
