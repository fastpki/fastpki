#!/usr/bin/env bash
# Virtualized per-CA protocol routing on EST cacerts.
# /.well-known/est/{ca_instance_id}/cacerts resolves the requested CA
# instance, validates it's active, and returns THAT instance's CA cert — so one
# fastpki-est serves multiple independent CA hierarchies.
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
EST="$ROOT/build/fastpki-est"; CA="$ROOT/build/fastpki-ca"
W="$(mktemp -d)"; cd "$W"; PORT=18444
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

# Global (default-instance) CA, a separate per-CA CA, and the EST TLS cert.
ca_in_token ca.pem "/CN=Global CA" 3650
GLOBAL_KEY_URI="$CA_KEY_URI"
cp ca.pem root.pem
# The second CA's key is token-born too — a CA private key is never a file.
ca_in_token depta.pem "/CN=Dept A CA" 3650 depta
DEPTA_KEY_URI="$CA_KEY_URI"
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3650 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup est_perca
# AUTH_BACKEND=none is gone, so this suite authenticates for real.
seed_web_user tester secret requester
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$GLOBAL_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$PORT
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)

# Register a secondary CA instance with its own crypto backing (its own CA cert).
"$CA" --config bootstrap.conf add dept-a --name "Dept A" --ca-pem "$W/depta.pem" --ca-key "$DEPTA_KEY_URI" >/dev/null

"$EST" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-est died:"; cat srv.log; exit 1; fi
U="https://127.0.0.1:$PORT"

cacert_cn() { # ca_instance_id -> the CN of the returned CA cert (or "")
    curl -sk "$U/.well-known/est/$1/cacerts" \
        | "$OSSL" base64 -d -A 2>/dev/null \
        | "$OSSL" pkcs7 -inform DER -print_certs -noout 2>/dev/null \
        | sed -n 's/.*subject=.*CN *= *\(.*\)/\1/p' | head -1
}
code() { curl -sk -o /dev/null -w '%{http_code}' "$U/.well-known/est/$1/cacerts"; }

echo "=== per-CA cacerts routing (enrolment is id-based) ==="
chk "the default 'ca' instance returns the (SIGNING_CA) CA" "Global CA" "$(cacert_cn ca)"
chk "dept-a instance returns its own CA"     "Dept A CA" "$(cacert_cn dept-a)"
# No id-less route — a CA is never guessed (with a root + subCA hierarchy "the
# first CA" is ambiguous), so the base path 404s.
chk "the base (no-id) route 404s — every request names a /{ca_id}" 404 \
    "$(curl -sk -o /dev/null -w '%{http_code}' "$U/.well-known/est/cacerts")"

echo "=== instance validation ==="
chk "unknown CA instance -> 404" 404 "$(code nope)"
"$CA" --config bootstrap.conf disable dept-a >/dev/null
chk "disabled CA instance -> 503" 503 "$(code dept-a)"
"$CA" --config bootstrap.conf enable dept-a >/dev/null
chk "re-enabled instance serves again (200)" 200 "$(code dept-a)"

echo "=== per-CA enrollment (simpleenroll) ==="
issuer_of() { "$OSSL" x509 -in "$1" -issuer -noout 2>/dev/null | sed -n 's/.*CN *= *\(.*\)/\1/p'; }
enroll() { # <instance> <cn> <leaf-out>  ; echoes the HTTP status code
    "$OSSL" req -new -newkey rsa:2048 -nodes -keyout k.pem -subj "/CN=$2" -out csr.pem >/dev/null 2>&1
    local b64; b64=$("$OSSL" req -in csr.pem -outform DER 2>/dev/null | "$OSSL" base64 -A)
    local code; code=$(curl -sk -u tester:secret -o p7.b64 -w '%{http_code}' -H "Content-Type: application/pkcs10" \
        --data-binary "$b64" "$U/.well-known/est/$1/simpleenroll")
    "$OSSL" base64 -d -A -in p7.b64 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs -out "$3" 2>/dev/null
    echo "$code"
}

chk "ca enroll -> 200" 200 "$(enroll ca ent-ca.internal leaf_d.pem)"
chk "ca-issued cert signed by the SIGNING_CA" "Global CA" "$(issuer_of leaf_d.pem)"
chk "ca cert tagged ca_instance_id=ca" ca \
    "$(pg_exec "SELECT ca_instance_id FROM certs WHERE cn='ent-ca.internal';")"

chk "dept-a enroll -> 200" 200 "$(enroll dept-a ent-depta.internal leaf_a.pem)"
chk "dept-a-issued cert signed by the Dept A CA" "Dept A CA" "$(issuer_of leaf_a.pem)"
chk "dept-a cert tagged ca_instance_id=dept-a" dept-a \
    "$(pg_exec "SELECT ca_instance_id FROM certs WHERE cn='ent-depta.internal';")"
# Cryptographic check (not just issuer name): the leaf must actually verify under
# the Dept A CA — a per-CA cert paired with the wrong key would fail here.
"$OSSL" x509 -in leaf_a.pem -out leaf_a.x.pem >/dev/null 2>&1
chk "dept-a cert verifies under the Dept A CA" OK \
    "$("$OSSL" verify -CAfile depta.pem leaf_a.x.pem 2>/dev/null | grep -oE 'OK')"
"$OSSL" x509 -in leaf_d.pem -out leaf_d.x.pem >/dev/null 2>&1
chk "ca cert verifies under the SIGNING_CA" OK \
    "$("$OSSL" verify -CAfile ca.pem leaf_d.x.pem 2>/dev/null | grep -oE 'OK')"

# The AIA/CRLDP baked into issued certs always NAME the issuing CA's id — the
# first CA ('ca') is no exception. OCSP is the shared per-CA path for every CA.
# (No BASE_URL set → https://pki.example.org.)
uri_of() { "$OSSL" x509 -in "$1" -noout -text 2>/dev/null | grep -E "$2" | grep -oE 'URI:[^ ]+' | sed 's/URI://' | head -1; }
echo "=== per-CA AIA/CRLDP baked into issued certs ==="
# Plain http + the OCSP port. These asserted the https, port-less form,
# which is the shape that was reported as broken — the suite pinned it in place.
chk "first CA 'ca' cert CRLDP names the id"   "http://pki.example.org:8080/ca.crl"     "$(uri_of leaf_d.pem '\.crl')"
# caIssuers names the SIGNING KEY GENERATION as a .p7c bundle, not just the CA id —
# <base>/{ca_id}/{ski}.p7c. The requirement: {ca_id} may not be used in cAIssuers and
# CRLDP links on its own — it is a prefix or path segment, with some unique piece next to
# it that uniquely identifies the CA key generation.
#
# ⚠️ These two CAs have ONE generation each and are qualified anyway, deliberately. If the
# token only appeared after a rekey, every certificate issued BEFORE the first rekey would
# carry a flat URL and break the moment that CA is re-keyed — the fix has to be in place
# before it is needed.
#
# The expected SKI is DERIVED from the CA certificate, never pasted: a literal would pin
# this fixture's key and say nothing about whether the product used the right one.
ski_of(){ "$OSSL" x509 -in "$1" -noout -text 2>/dev/null \
            | awk '/X509v3 Subject Key Identifier/{getline; gsub(/[ :]/,""); print tolower($0); exit}'; }
CA_SKI=$(ski_of ca.pem); DEPTA_SKI=$(ski_of depta.pem)
chk "PRECONDITION: both CA certs have an SKI" yes \
    "$([ -n "$CA_SKI" ] && [ -n "$DEPTA_SKI" ] && echo yes || echo no)"
chk "first CA 'ca' cert caIssuers (.p7c)"     "http://pki.example.org:8080/ca/$CA_SKI.p7c"     "$(uri_of leaf_d.pem 'CA Issuers')"
chk "first CA 'ca' cert AIA OCSP (shared)"    "http://pki.example.org:8080/ocsp"       "$(uri_of leaf_d.pem 'OCSP')"
chk "subsequent 'dept-a' CRLDP names the id"  "http://pki.example.org:8080/dept-a.crl" "$(uri_of leaf_a.pem '\.crl')"
chk "subsequent 'dept-a' caIssuers (.p7c)"    "http://pki.example.org:8080/dept-a/$DEPTA_SKI.p7c" "$(uri_of leaf_a.pem 'CA Issuers')"
chk "subsequent 'dept-a' AIA OCSP (shared)"   "http://pki.example.org:8080/ocsp"       "$(uri_of leaf_a.pem 'OCSP')"

echo "=== ⚠️ AND EVERY DATA CENTER'S ADDRESS, so a client has somewhere else to go ==="
# A certificate carries these for as long as it lives and cannot be told a new URL after
# it is issued, so naming only the node that issued it leaves a relying party with
# nowhere to go when that node is down — which also makes the CRLs every peer already
# replicates unreachable in exactly the outage they exist for.
uris_of(){ "$OSSL" x509 -in "$1" -noout -text 2>/dev/null | grep -E "$2" \
             | grep -oE 'URI:[^ ]+' | sed 's/URI://' | tr '\n' ' '; }
pg_exec "INSERT INTO datacenters(dc_id, serial_prefix, base_url) VALUES
           ('dc2', 2, 'https://pki-dc2.example'),
           ('dc3', 3, 'https://pki-dc3.example')
         ON CONFLICT (dc_id) DO NOTHING;" >/dev/null
enroll ca multi.internal leaf_m.pem >/dev/null
# ⚠️ ORDER MATTERS AND IS ASSERTED. This node comes first — a client tries them in order,
# and the local one is the one that cannot be a network hop away. The peers follow by
# dc_id, so two nodes issuing under the same CA produce identical extension bytes.
chk "CRLDP carries every data center, local first" \
    "http://pki.example.org:8080/ca.crl https://pki-dc2.example/ca.crl https://pki-dc3.example/ca.crl " \
    "$(uris_of leaf_m.pem '\.crl')"
# ⚠️ AIA OCSP DOES **NOT** FOLLOW BY DEFAULT, and the asymmetry is the point.
#
# A CRL and a CA certificate are signed once and the mesh replicates them, so any data center
# can serve a copy and naming them all costs nothing. An OCSP response is signed PER REQUEST
# with that CA's ocsp-ra-<ca_id> private key. A peer holds that key only if somebody chose to
# replicate it, and whether a private key may leave its token is the operator's decision — so
# issuance does not assume it. Measured on a two-data-center deployment before this was gated:
# every certificate named the peer's /ocsp and the peer answered 404, for the life of the
# certificate, because a certificate's URLs are fixed when it is issued.
chk "  but AIA OCSP names only the data center that holds the key" \
    "http://pki.example.org:8080/ocsp " \
    "$(uris_of leaf_m.pem 'OCSP')"
# And the operator can say otherwise. OCSP_RESPONDER_KEYS_REPLICATED asserts that every data
# center can answer for every CA; then the peers are advertised like the CRL. Asked through
# `ca urls`, which derives them exactly as issuance does, so this needs no server restart.
sed 's/^LOG_LEVEL=.*/LOG_LEVEL=err/' bootstrap.conf > repl-ocsp.conf
printf 'OCSP_RESPONDER_KEYS_REPLICATED=true\n' >> repl-ocsp.conf
chk "  with the keys declared replicated, every data center is offered" 3 \
    "$("$CA" --config repl-ocsp.conf urls ca 2>/dev/null | grep -c 'ocsp')"
chk "  and the default config still offers one" 1 \
    "$("$CA" --config bootstrap.conf urls ca 2>/dev/null | grep -c 'ocsp')"
# caIssuers is generation-qualified, and the qualification must reach the peers too —
# a certificate mixing a .p7c URL for this node with flat .crt URLs for its peers would
# hand an AIA-walking client two different shapes for the same thing.
chk "  and caIssuers is qualified on EVERY entry" 3 \
    "$(uris_of leaf_m.pem 'CA Issuers' | grep -oE '[^ ]+\.p7c' | wc -l | tr -d ' ')"
# CONTROL: a certificate issued before those rows existed still names one node, so the
# three above are the new rows taking effect and not a change in how URIs are counted.
chk "  a cert issued earlier still names one" 1 \
    "$(uris_of leaf_d.pem '\.crl' | wc -w | tr -d ' ')"

chk "unknown instance enroll -> 404" 404 "$(enroll nope x.internal j1.pem)"
"$CA" --config bootstrap.conf disable dept-a >/dev/null
chk "disabled instance enroll -> 503" 503 "$(enroll dept-a y.internal j2.pem)"
"$CA" --config bootstrap.conf enable dept-a >/dev/null

# 6b superseded the old fail-fast: a missing EST_CERT/KEY is no longer fatal
# (that was the crash-loop on a CA-less deploy) — EST now comes up on a TEMPORARY
# self-signed transport cert and adopts a real one later. So an EST_CERT pointing at
# a missing file falls back to self-signed and stays alive, rather than exiting.
echo "=== 6b: EST_CERT set but missing -> self-signed transport fallback (alive, not fatal) ==="
sed 's#^EST_CERT=.*#EST_CERT='"$W"'/nope.pem#; s#^EST_KEY=.*#EST_KEY='"$W"'/nope.key#; s#^LOG_LEVEL=.*#LOG_LEVEL=info#' bootstrap.conf > bad.conf
"$EST" --config bad.conf >bad.log 2>&1 & bad_pid=$!; sleep 2
chk "stays alive on the self-signed fallback (no crash-loop)" yes \
    "$(kill -0 $bad_pid 2>/dev/null && echo yes || echo no)"
chk "logs the TEMPORARY self-signed transport cert" yes \
    "$(grep -q 'TEMPORARY self-signed' bad.log && echo yes || echo no)"
kill "$bad_pid" 2>/dev/null; wait "$bad_pid" 2>/dev/null

echo
echo "=== EST-PERCA: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
