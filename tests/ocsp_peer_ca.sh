#!/usr/bin/env bash
# OCSP for a CA this node does not serve: a mesh peer's CA gets `unauthorized`, quietly.
#
# ⚠️ WHY THIS IS A TEST. On a mesh every data center holds every CA's rows, including the
# responder certificate the CA's home data center issued for ITS OWN responder key. Asked
# about a peer's CA, a node found that certificate, saw it certify a key it does not hold,
# and answered internalError, with an ERR line per request telling the operator to reissue
# the certificate. All three were wrong:
#   - internalError says the server is broken; RFC 6960 §2.3 has `unauthorized` for "I am
#     not the responder for this certificate";
#   - reissuing it here would replace the home data center's credential mesh-wide;
#   - anyone could write an ERR line into the log per request, just by asking.
#
# One database stands in for the mesh: a second CA whose key reference names an object this
# node's token does not hold, and whose responder certificate certifies a different
# responder key from the one this process runs with. Also asserted, so the change cannot
# pass by answering `unauthorized` for everything: this node's own CA still answers `good`,
# and its own responder certificate issued for the wrong key is still internalError + ERR.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF

W="$(mktemp -d)"; cd "$W"; PORT=18113
pass=0; fail=0; P=
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token home.pem "/CN=OCSP Home CA" 3650 home \
    || { echo "SKIP: could not mint a CA key in a token"; exit 0; }
HOME_KEY="$CA_KEY_URI"
ca_in_token peer.pem "/CN=OCSP Peer CA" 3650 peer \
    || { echo "SKIP: could not mint a CA key in a token"; exit 0; }
PEER_KEY="$CA_KEY_URI"
pg_setup ocsp_peer_ca
trap 'pg_cleanup; kill ${P:-} 2>/dev/null' EXIT
printf "internal\n" > domains.txt; seed_domains "$W/domains.txt"

# One leaf per CA, with known serials so the rows can be seeded.
leaf() {   # <ca.pem> <ca key> <serial> <cn> <out.pem>
    "$OSSL" req -newkey rsa:2048 -nodes -keyout "$5.key" -subj "/CN=$4" -out "$5.csr" >/dev/null 2>&1
    "$OSSL" x509 -req -in "$5.csr" -CA "$1" -CAkey "$2" ${CA_OSSL_ARGS:-} \
            -set_serial "$3" -days 365 -out "$5" >/dev/null 2>&1
}
leaf home.pem "$HOME_KEY" 43981 home.internal home-leaf.pem   # 0xabcd
leaf peer.pem "$PEER_KEY" 48879 peer.internal peer-leaf.pem   # 0xbeef
chk "PRECONDITION: a leaf of each CA exists" yes \
    "$([ -s home-leaf.pem ] && [ -s peer-leaf.pem ] && echo yes || echo no)"

cat > home.conf <<EOF
SIGNING_CA_PEM=$W/home.pem
SIGNING_CA_KEY=$HOME_KEY
SIGNING_CA_ID=home
PG_CONNINFO=$PG_CONNINFO
EOF
cat > peer.conf <<EOF
SIGNING_CA_PEM=$W/peer.pem
SIGNING_CA_KEY=$PEER_KEY
SIGNING_CA_ID=peer
PG_CONNINFO=$PG_CONNINFO
EOF
seed_ca_from_conf home.conf
seed_ca_from_conf peer.conf
pg_exec "INSERT INTO certs(serial,status,cn,ca_instance_id,\"notAfter\") VALUES
           ('abcd',0,'home.internal','home', extract(epoch from now())::bigint + 86400),
           ('beef',0,'peer.internal','peer', extract(epoch from now())::bigint + 86400)
         ON CONFLICT (serial) DO NOTHING;" >/dev/null

# Each data center has its own responder key; the certificates for both replicate.
mkdir -p here there
HERE_KEY=$(ocsp_responder_key "$W/home.pem" "$HOME_KEY" home "$W/here" 2>/dev/null) || HERE_KEY=""
ocsp_responder_key "$W/peer.pem" "$PEER_KEY" peer "$W/there" >/dev/null 2>&1
chk "PRECONDITION: both responder certificates are stored" 2 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id IN ('ocsp-ra-home','ocsp-ra-peer')" | tr -d ' \n')"
chk "PRECONDITION: they certify two different keys" no \
    "$(cmp -s "$W/here/ocsp-responder.key" "$W/there/ocsp-responder.key" && echo yes || echo no)"
# The peer's key lives in the PEER's token: its row names an object this token does not hold.
pg_exec "UPDATE certs SET private_key = regexp_replace(private_key, 'object=[^;]*', 'object=held-by-a-peer')
          WHERE is_ca AND id = 'peer';" >/dev/null
chk "PRECONDITION: the peer CA's key reference points elsewhere" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE is_ca AND id='peer' AND private_key LIKE '%object=held-by-a-peer%'" | tr -d ' \n')"

cat home.conf > ocsp.conf
cat >> ocsp.conf <<EOF
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
OCSP_RESPONDER_KEY=$HERE_KEY
LOG_LEVEL=info
EOF
"$ROOT/build/fastpki-ocsp" --config ocsp.conf > ocsp.log 2>&1 & P=$!
wait_port "$PORT" "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-ocsp died:"; tail -20 ocsp.log; exit 1; }

# The answer: the leaf's status when the response is successful, else the response status
# ("unauthorized", "internalerror", ...).
ask() {   # <issuer.pem> <leaf.pem> <path>
    "$OSSL" ocsp -issuer "$1" -cert "$2" -url "http://127.0.0.1:$PORT$3" -resp_text -noverify \
            -respout ask.der > ask.out 2>&1
    # A status other than successful is printed as "Responder Error: <status> (<n>)".
    local st; st=$(sed -n 's/^Responder Error: \([a-zA-Z]*\).*/\1/p' ask.out | head -1)
    if [ -n "$st" ]; then printf '%s' "$st"; return; fi
    grep -oE 'Cert Status: [a-z]+' ask.out | head -1 | awk '{print $3}' | grep . || echo '<none>'

}

echo "=== this node's own CA answers ==="
chk "home CA, shared /ocsp: good"                       good "$(ask home.pem home-leaf.pem /ocsp)"
chk "home CA, /ocsp/home: good"                         good "$(ask home.pem home-leaf.pem /ocsp/home)"

echo "=== a CA served by another node: unauthorized, and no ERR ==="
for _i in 1 2 3; do
    chk "peer CA, shared /ocsp (request $_i): unauthorized" unauthorized "$(ask peer.pem peer-leaf.pem /ocsp)"
done
chk "peer CA, /ocsp/peer: unauthorized"                 unauthorized "$(ask peer.pem peer-leaf.pem /ocsp/peer)"
chk "no ERR line names the peer CA"                     0 "$(grep ' ERR ' ocsp.log | grep -c "'peer'")"
chk "no advice to reissue the peer's certificate"       0 "$(grep -c 'Reissue it' ocsp.log)"
chk "one info line says it is answered elsewhere"       1 "$(grep -c "CA 'peer' is answered by another node" ocsp.log)"

echo "=== this node's OWN responder certificate for the wrong key is still a fault ==="
pg_exec "DELETE FROM certs WHERE cert_id='ocsp-ra-home';" >/dev/null
mkdir -p wrong
ocsp_responder_key "$W/home.pem" "$HOME_KEY" home "$W/wrong" >/dev/null 2>&1
chk "PRECONDITION: the new certificate is for another key" no \
    "$(cmp -s "$W/here/ocsp-responder.key" "$W/wrong/ocsp-responder.key" && echo yes || echo no)"
chk "home CA, mismatched responder certificate: internalerror" internalerror "$(ask home.pem home-leaf.pem /ocsp/home)"
chk "  and an ERR line says to reissue it"              yes \
    "$(grep ' ERR ' ocsp.log | grep "'home'" | grep -q 'Reissue it' && echo yes || echo no)"
# The peer CA's key reference is a token URI carrying the PIN inline (RFC 7512 pin-value=),
# and the line saying that key is not here is logged on every mesh node.
chk "PRECONDITION: the peer CA's key reference carries a PIN" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE is_ca AND id='peer' AND private_key LIKE '%pin-value=%'" | tr -d ' \n')"
_pin=$(pg_exec "SELECT substring(private_key from 'pin-value=([^;&]*)') FROM certs WHERE is_ca AND id='peer'" | tr -d ' \n')
chk "the token PIN is not in the log"                   0 "$(grep -c "pin-value=$_pin" ocsp.log)"

kill $P 2>/dev/null; wait $P 2>/dev/null; P=
echo
echo "=== OCSP PEER CA: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
