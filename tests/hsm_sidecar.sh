#!/usr/bin/env bash
# tests/hsm_sidecar.sh — SoftHSM served OUT-OF-PROCESS by `p11-kit server` (the
# compose/k8s `softhsm` sidecar). A FastPKI binary signs through the server SOCKET via
# p11-kit-client.so, so SoftHSM runs in the SERVER process and never re-enters the app's
# libcrypto (the re-entrant deadlock). This is the deployable "separate container"
# form the deployment calls for — the essential property is process isolation,
# which this shell test reproduces without docker (a server process + a signing process).
#
# Proves fastpki-ca self-signs an HSM-resident CA *through the socket*, the key never
# leaves the token, and the CA then issues over EST. SKIPs where SoftHSM / the pkcs11
# provider / p11-kit-server / p11-kit-client.so are absent (e.g. macOS).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"   # real credentials, not AUTH_BACKEND=none
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
CA="$ROOT/build/fastpki-ca"
W="$(mktemp -d)"; cd "$W"; PORT=18471
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
skipout(){ echo "  [SKIP] $1"; echo; echo "=== HSM SIDECAR: PASS=$pass FAIL=$fail SKIP=1 ==="; exit 0; }
findfirst(){ for x in "$@"; do [ -e "$x" ] && { echo "$x"; return 0; }; done; return 1; }

SOFTHSM_MOD=$(findfirst "${SOFTHSM_MODULE:-}" /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so /usr/lib64/softhsm/libsofthsm2.so \
    /opt/homebrew/lib/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so || true)
UTIL=$(command -v softhsm2-util || true); PKTOOL=$(command -v pkcs11-tool || true)
# Homebrew Cellar may hold pkcs11.dylib under a version dir that the opt/ symlink doesn't reach
CELLAR_PROV=$(ls /opt/homebrew/Cellar/openssl@3/*/lib/ossl-modules/pkcs11.dylib 2>/dev/null | head -1)
PROV=$(findfirst "${P11_PROVIDER:-}" /usr/lib/ossl-modules/pkcs11.so /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so /usr/lib64/ossl-modules/pkcs11.so \
    /opt/homebrew/opt/openssl@3/lib/ossl-modules/pkcs11.dylib /opt/homebrew/lib/ossl-modules/pkcs11.dylib \
    $CELLAR_PROV || true)
P11KIT=$(command -v p11-kit || true)
CLIENT=$(findfirst "${P11_CLIENT:-}" /usr/lib/pkcs11/p11-kit-client.so /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so /usr/lib64/pkcs11/p11-kit-client.so \
    /opt/homebrew/lib/pkcs11/p11-kit-client.so /usr/local/lib/pkcs11/p11-kit-client.so || true)
HAVE_SERVER=no; [ -n "$P11KIT" ] && "$P11KIT" server --help >/dev/null 2>&1 && HAVE_SERVER=yes
[ -n "$SOFTHSM_MOD" ] && [ -n "$UTIL" ] && [ -n "$PKTOOL" ] && [ -n "$PROV" ] && [ -n "$CLIENT" ] && [ "$HAVE_SERVER" = yes ] \
    || skipout "SoftHSM / provider / p11-kit-server / p11-kit-client.so not installed"
PROVDIR=$(dirname "$PROV")

# Token + a CA keypair generated IN it (direct module, own process — safe).
mkdir -p tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' "$W" > softhsm2.conf
export SOFTHSM2_CONF="$W/softhsm2.conf" XDG_RUNTIME_DIR="$W"
"$UTIL" --module "$SOFTHSM_MOD" --init-token --free --label PKITEST --pin 1234 --so-pin 12345678 >/dev/null 2>&1
"$PKTOOL" --module "$SOFTHSM_MOD" --keypairgen --key-type rsa:2048 --label hsmca --id 0103 --login --pin 1234 >/dev/null 2>&1
URI="pkcs11:token=PKITEST;object=hsmca;type=private?pin-value=1234"

echo "=== the sidecar: p11-kit server holds the token, serves it on a socket ==="
SOCK="$W/pkcs11.sock"
"$P11KIT" server -f -n "$SOCK" --provider "$SOFTHSM_MOD" "pkcs11:" >server.log 2>&1 & SRV=$!
for _ in $(seq 1 20); do [ -S "$SOCK" ] && break; sleep 0.5; done
chk "sidecar socket is serving" yes "$([ -S "$SOCK" ] && echo yes || echo no)"
export P11_KIT_SERVER_ADDRESS="unix:path=$SOCK"     # apps dial the sidecar via client.so

ca_in_token ca.pem "/CN=Global CA" 3650
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3650 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup hsm_sidecar
# AUTH_BACKEND=none is gone, so this suite authenticates for real.
seed_web_user t t requester
trap 'pg_cleanup; kill $SRV $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
ROOT_CA_PEM=$W/ca.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PKCS11_MODULE=$CLIENT
PKCS11_PROVIDER_PATH=$PROVDIR
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$PORT
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
field(){ "$OSSL" x509 -in "$1" -noout -"$2" 2>/dev/null | sed -n 's/.*CN *= *//p'; }

echo "=== fastpki-ca self-signs an HSM CA THROUGH the sidecar socket (client.so) ==="
"$CA" --config bootstrap.conf create hsm-s --name "HSM Sidecar" --subject "/CN=HSM Sidecar CA" --ca-key "$URI" --out-dir cas >/dev/null 2>cre.err \
  || { echo "create failed:"; cat cre.err; skipout "fastpki-ca create through the socket failed (provider/client ABI?)"; }
chk "CA cert written"                  yes "$([ -f cas/hsm-s.crt ] && echo yes || echo no)"
chk "no private key on disk"           yes "$([ ! -f cas/hsm-s.key ] && echo yes || echo no)"
chk "CA cert is a CA"                  yes "$("$OSSL" x509 -in cas/hsm-s.crt -noout -text 2>/dev/null | grep -q 'CA:TRUE' && echo yes || echo no)"
chk "self-signed by the tokened key via the socket" "cas/hsm-s.crt: OK" "$("$OSSL" verify -CAfile cas/hsm-s.crt cas/hsm-s.crt 2>/dev/null)"
kill -0 $SRV 2>/dev/null; chk "the sidecar server process handled the signing" 0 "$?"

echo "=== the sidecar-HSM CA issues over EST (off-process signing) ==="
"$ROOT/build/fastpki-est" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-est died:"; cat srv.log; skipout "fastpki-est could not start"; fi
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout k.pem -subj "/CN=host.internal" -out csr.pem >/dev/null 2>&1
b64=$("$OSSL" req -in csr.pem -outform DER 2>/dev/null | "$OSSL" base64 -A)
curl -sk -u t:t -H "Content-Type: application/pkcs10" --data-binary "$b64" \
    "https://127.0.0.1:$PORT/.well-known/est/hsm-s/simpleenroll" \
  | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs -out leaf.pem 2>/dev/null
chk "EST leaf issued by the sidecar-HSM CA" "HSM Sidecar CA" "$(field leaf.pem issuer)"

echo
echo "=== HSM SIDECAR: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
