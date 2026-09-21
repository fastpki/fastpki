#!/usr/bin/env bash
# Import an existing CA from the console. The CAs page can register a
# CA from a pasted/uploaded certificate PEM plus a server-side key reference (a
# file path, or a pkcs11: URI) — the private key is never uploaded. Drives
# the backing POST /api/ca-instances import path and asserts registration + the
# key-location/reference validation. No HSM needed (import only stores the ref).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"   # macOS
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18098
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup web_ca_import
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
ca_in_token global.pem "/CN=Global CA" 3650 gca
# A genuine CA cert (CA:TRUE) to import, and a non-CA leaf for the negative path.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout imp.key -out imp.pem -days 3650 -subj "/CN=Imported Root CA/O=Acme" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:2" -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.pem -days 3650 -subj "/CN=not-a-ca.example" \
    -addext "basicConstraints=critical,CA:FALSE" >/dev/null 2>&1
source "$ROOT/tests/user_helpers.sh"
seed_web_user boss bosspw admin
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/global.pem
SIGNING_CA_KEY=$CA_KEY_URI
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat srv.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null
imp(){ curl -s -o /dev/null -w '%{http_code}' -b boss.cj "$U/api/ca-instances" "$@"; }
sk(){ pg_exec "SELECT coalesce(private_key,'') FROM certs WHERE id='$1' AND is_ca;"; }

echo "=== 1. a software key path is REFUSED, not imported ==="
# This used to be the happy path. An imported CA whose key is a file registers cleanly
# and then cannot sign — load_signing_key has no on-disk branch — so the refusal moved
# to the door, where the message can still name the cause. The guard asserts the removed
# path is INERT: refused AND nothing written.
C=$(imp --data-urlencode 'id=imp-soft' --data-urlencode 'name=Imported' \
    --data-urlencode "cert_pem@imp.pem" --data-urlencode 'keyloc=software' \
    --data-urlencode "key=$W/imp.key")
chk "import with a key PATH -> 400"     400 "$C"
chk "nothing registered, nothing written" no "$([ -d "$W/ca-inst" ] && echo yes || echo no)"
chk "no CA row registered"              ""  "$(sk imp-soft)"

echo "=== 2. import a CA whose key lives in an HSM (pkcs11: reference) ==="
URI="$CA_KEY_URI"
C=$(imp --data-urlencode 'id=imp-hsm' --data-urlencode "cert_pem@imp.pem" \
    --data-urlencode 'keyloc=pkcs11' --data-urlencode "key=$URI")
chk "import (pkcs11) -> 201"            201 "$C"
chk "registered signing_ca_key = the pkcs11 URI" "$URI" "$(sk imp-hsm)"
# CA_INSTANCE_DIR is gone. The console used to write <id>.crt there and nothing
# ever read it — the certificate is a `certs` row — so these now assert
# the API answer and the ABSENCE of any directory. Inverting an assertion that encoded
# the removed behaviour is the honest update; leaving it would pin what the ticket
# removed.
chk "the cert is readable from the API"  yes \
  "$(curl -s -b boss.cj "$U/api/ca-instances/imp-hsm/cert-pem" | grep -q "BEGIN CERTIFICATE" && echo yes || echo no)"
chk "  and NO file was written for it"    no  "$([ -d "$W/ca-inst" ] && echo yes || echo no)"
T=$(curl -s -b boss.cj "$U/api/ca-instances/imp-hsm/cert-text")
chk "cert-text shows Imported Root CA"  yes "$(echo "$T" | grep -q 'Imported Root CA' && echo yes || echo no)"
chk "cert-text shows CA:TRUE"           yes "$(echo "$T" | grep -q 'CA:TRUE' && echo yes || echo no)"

echo "=== 3. negative paths ==="
chk "non-CA leaf cert -> 400" 400 "$(imp --data-urlencode 'id=imp-leaf' --data-urlencode "cert_pem@leaf.pem" --data-urlencode 'keyloc=software' --data-urlencode "key=$W/leaf.key")"
chk "not a PEM cert -> 400"   400 "$(imp --data-urlencode 'id=imp-junk' --data-urlencode 'cert_pem=not a cert' --data-urlencode 'keyloc=software' --data-urlencode "key=$W/imp.key")"
# There is one rule now — the reference must be a handle — so "the location and
# the reference disagree" collapses into it. Both spellings of the old mismatch are still
# refused, which is what matters.
chk "a path reference -> 400" 400 "$(imp --data-urlencode 'id=imp-mm1' --data-urlencode "cert_pem@imp.pem" --data-urlencode 'keyloc=pkcs11' --data-urlencode "key=$W/imp.key")"
chk "keyloc=software with a handle -> 400" 400 "$(imp --data-urlencode 'id=imp-mm2' --data-urlencode "cert_pem@imp.pem" --data-urlencode 'keyloc=software' --data-urlencode "key=$URI")"
chk "missing key reference -> 400" 400 "$(imp --data-urlencode 'id=imp-nokey' --data-urlencode "cert_pem@imp.pem" --data-urlencode 'keyloc=software')"


# ⚠️ A FORM BODY OVER 8 KiB WAS REFUSED BY THE LIBRARY, BEFORE ANY HANDLER RAN.
# cpp-httplib's CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH defaults to 8192, and
# read_content() answers 413 for any application/x-www-form-urlencoded body above it —
# inside httplib, so nothing of ours logged a thing. set_payload_max_length() does NOT
# raise it: two separate limits, and that one is a compile-time constant.
#
# 8 KiB was fine while every posted PEM was RSA or EC. It is not fine for PQC: an ML-DSA-87
# certificate carries a 2592-byte public key and a 4627-byte signature, so its PEM is ~10 KiB
# before form-encoding expands it further. Importing one into the console failed with a bare
# 413 and an empty log — reported from a lab bringing up a mesh, where the sub CA that could
# not be imported WAS the exercise.
#
# Asserted with a body that is simply large, not with a real ML-DSA certificate: what broke
# is the SIZE check, it fires before any parsing, and requiring a PQC-capable build here
# would make the regression invisible on every platform that skips those.
echo "=== 4. a form body larger than httplib's 8 KiB default is not refused by the library ==="
BIG=$(head -c 60000 /dev/zero | tr '\0' 'A')
CODE=$(imp --data-urlencode 'id=imp-big' --data-urlencode "cert_pem=$BIG" \
           --data-urlencode 'keyloc=software' --data-urlencode "key=$W/imp.key")
# 400 is the RIGHT answer — it is not a certificate. 413 means the request never reached us.
chk "a ~60 KiB body reaches the handler (400, not 413)" 400 "$CODE"
# Anti-vacuity: prove the body really was over the old ceiling, or this passes on a typo.
chk "  PRECONDITION: the body was well over 8 KiB" yes \
    "$([ "${#BIG}" -gt 8192 ] && echo yes || echo no)"
echo
echo "=== WEB CA IMPORT: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
