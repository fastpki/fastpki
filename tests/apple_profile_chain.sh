#!/usr/bin/env bash
# A signed Apple profile carries the console's chain, so a device that trusts the root can
# verify it.
#
# ⚠️ WHY THIS IS A TEST. The console signs the .mobileconfig profiles it serves with its own TLS
# certificate. A device verifies that signature from the certificates the signature carries,
# up to a root it trusts; it does not fetch the issuers. The signature carried the signer
# alone, so on an iPhone that trusted the root the profile still showed as "Not Verified",
# while the console's own TLS handshake sent the issuing CA as it should. The chain was read
# from the certificate's own chain, and the console's transport certificate keeps its issuers
# in the SSL context's extra chain.
#
# The shipped shape: the console serves a certificate issued by an intermediate CA, published
# as its transport certificate, with the chain built from the CAs in the database. Asserted:
# the handshake sends the intermediate, the signature carries every certificate the handshake
# sends, and it verifies against the root alone. The key is a file here; the chain is the same
# for a token key, and a file key lets the suite run where the token cannot serve TLS.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; PORT=18296
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
[ -x "$ROOT/build/fastpki-web" ] || { echo "SKIP: fastpki-web not built"; exit 0; }
if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi

ca_in_token root.pem "/CN=Profile Chain Root" 3650 proot
ROOT_KEY="$CA_KEY_URI"
ca_in_token inter.pem "/CN=Profile Chain Issuing CA" 1825 pinter "$W/root.pem" "$ROOT_KEY"
INTER_KEY="$CA_KEY_URI"
pg_setup apple_profile_chain
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf 'SIGNING_CA_PEM=%s\nSIGNING_CA_KEY=%s\nSIGNING_CA_ID=proot\nPG_CONNINFO=%s\n' "$W/root.pem" "$ROOT_KEY" "$PG_CONNINFO" > root.conf
printf 'SIGNING_CA_PEM=%s\nSIGNING_CA_KEY=%s\nSIGNING_CA_ID=pinter\nPG_CONNINFO=%s\n' "$W/inter.pem" "$INTER_KEY" "$PG_CONNINFO" > inter.conf
seed_ca_from_conf root.conf
seed_ca_from_conf inter.conf
chk "PRECONDITION: the intermediate is issued by the root" \
    "$("$OSSL" x509 -in root.pem -noout -subject | sed 's/^subject=//')" \
    "$("$OSSL" x509 -in inter.pem -noout -issuer | sed 's/^issuer=//')"

# The console's certificate, from the intermediate.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout web.key -out web.csr -subj "/CN=localhost" >/dev/null 2>&1
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > web.ext
"$OSSL" x509 -req -in web.csr -CA inter.pem -CAkey "$INTER_KEY" ${CA_OSSL_ARGS:-} \
    -set_serial 0x5eed01 -days 30 -extfile web.ext -out web.crt >/dev/null 2>&1
chk "PRECONDITION: the console's certificate is issued by the intermediate" yes \
    "$("$OSSL" verify -CAfile root.pem -untrusted inter.pem web.crt >/dev/null 2>&1 && echo yes || echo no)"

seed_web_user admin adminpw12 admin
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_TLS_CERT=$W/web.crt
WEB_TLS_KEY=$W/web.key
WEB_CERT_ID=web
LOG_LEVEL=info
EOF
"$ROOT/build/fastpki-web" --config web.conf > web.log 2>&1 & P=$!
wait_conf "web.conf" WEB_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; tail -20 web.log; exit 1; }
U="https://127.0.0.1:$PORT"
curl -sk -c a.cj -o /dev/null -X POST "$U/api/login" -d 'username=admin&password=adminpw12'

# sha256 fingerprints of every certificate in a PEM stream on stdin, sorted.
fps(){ local d; d=$(mktemp -d); awk -v d="$d" '/BEGIN CERT/{n++} n{print > (d "/" n ".pem")}'
       for f in "$d"/*.pem; do [ -e "$f" ] && "$OSSL" x509 -in "$f" -noout -fingerprint -sha256 2>/dev/null; done | sort; rm -rf "$d"; }
HS=$(echo | "$OSSL" s_client -connect "127.0.0.1:$PORT" -showcerts 2>/dev/null | fps)
chk "PRECONDITION: the console serves its certificate from the intermediate" \
    "$("$OSSL" x509 -in web.crt -noout -fingerprint -sha256)" \
    "$(echo | "$OSSL" s_client -connect "127.0.0.1:$PORT" 2>/dev/null | "$OSSL" x509 -noout -fingerprint -sha256 2>/dev/null)"
chk "PRECONDITION: its handshake sends the intermediate too" yes \
    "$(printf '%s\n' "$HS" | grep -qxF "$("$OSSL" x509 -in inter.pem -noout -fingerprint -sha256)" && echo yes || echo no)"

for kind in applescep appleacme; do
    echo "=== the $kind profile ==="
    code=$(curl -sk -b a.cj -o "$kind.mobileconfig" -w '%{http_code}' "$U/api/client-config/$kind?ca=pinter")
    chk "it downloads (200)" 200 "$code"
    SG=$("$OSSL" pkcs7 -inform DER -in "$kind.mobileconfig" -print_certs 2>/dev/null | fps)
    chk "  it is a CMS signature whose content is the profile" yes \
        "$("$OSSL" cms -verify -noverify -inform DER -in "$kind.mobileconfig" -out "$kind.xml" >/dev/null 2>&1 \
           && grep -q '<key>PayloadContent</key>' "$kind.xml" && echo yes || echo no)"
    chk "  the signature carries every certificate the handshake sends" "" \
        "$(printf '%s\n' "$HS" | while read -r l; do [ -n "$l" ] || continue; printf '%s\n' "$SG" | grep -qxF -- "$l" || echo "missing: $l"; done)"
    # -purpose any: OpenSSL checks for an e-mail signing certificate by default; a TLS
    # certificate is what signs Apple profiles, and the device accepts it.
    chk "  it verifies against the root alone" yes \
        "$("$OSSL" cms -verify -purpose any -inform DER -in "$kind.mobileconfig" -CAfile root.pem -out /dev/null >/dev/null 2>&1 && echo yes || echo no)"
done

echo
echo "=== APPLE PROFILE CHAIN: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
