#!/usr/bin/env bash
# SELF-ISSUED IS NOT SELF-SIGNED, and only self-SIGNED means "root".
#
#   self-ISSUED  subject == issuer. Says only that the certificate names itself as its own
#                issuer. A RE-KEYED CA is self-issued and signed by its PREVIOUS key: it
#                still has a parent, and it is not a trust anchor.
#   self-SIGNED  the signature verifies under the certificate's OWN public key.
#
# Both `fastpki-ca list/show` (kind_label) and the console's CAs page (kind_of) used to
# decide "root" with `X509_NAME_cmp(subject, issuer) == 0`. That is the first property, and
# they were claiming the second.
#
# ⚠️ THIS WAS LIVE ON THE LAB, not a theoretical case. `fastpki-ca show issuing` on all three
# DCs reported `(root)` for DC1's issuing CA — an ONLINE intermediate under
# `FastPKI Lab Root CA G3`. Measured on the real certificate:
#     g2 self-signature valid?   verification failed   <-- NOT self-signed
#     g2 signed by g1 (old key)? OK                    <-- signed by its own PREVIOUS key
# So the console drew it as a trust anchor and dropped its parent from the hierarchy.
#
# The fixture builds all three shapes explicitly with openssl rather than going through the
# re-key endpoint, because the point is the CLASSIFIER, and a fixture that depends on what
# the re-key path happens to emit would move if that path changed:
#   root      self-signed, subject == issuer          -> root
#   inter     signed by root, subject != issuer       -> intermediate
#   rekeyed   subject == issuer, signed by inter's OLD key, carrying a NEW key
#                                                     -> intermediate  (the whole ticket)
#
# `rekeyed` is the ONLY discriminating fixture: `root` and `inter` are classified the same
# either way and are here as controls, so a classifier that answered "intermediate" for
# everything could not pass.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: that default path is a Linux convention and is absent on plenty of dev boxes.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
CA="$ROOT/build/fastpki-ca"
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; # ⚠️ NOT 18231: that is inside saml.sh's contiguous 18230-18233 block (two mock IdPs and
# two web listeners). Both suites passed for as long as the sharding kept them apart; the
# moment they landed in the same shard this one got "listen failed" a minute after saml.sh
# had finished and reported ok — a failure that reads as a product fault and is not one.
PORT=18501
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup ca_kind_selfsigned
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF

cat > ext.cnf <<'EOF'
[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage         = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF

echo "=== build the three shapes ==="
# 1. a genuine self-signed root
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 3650 \
    -subj "/O=Kind Test/CN=Kind Root CA" -extensions ca_ext -config ext.cnf >/dev/null 2>&1

# 2. an ordinary intermediate, signed by the root
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout inter.key -out inter.csr \
    -subj "/O=Kind Test/CN=Kind Issuing CA" >/dev/null 2>&1
"$OSSL" x509 -req -in inter.csr -CA root.pem -CAkey root.key -CAcreateserial -days 3650 \
    -extfile ext.cnf -extensions ca_ext -out inter.pem >/dev/null 2>&1

# 3. THE TICKET: a re-key of the intermediate. Same subject, a NEW key, and signed by the
#    intermediate's OLD key — so issuer == subject while the self-signature cannot verify.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout rekeyed.key -out rekeyed.csr \
    -subj "/O=Kind Test/CN=Kind Issuing CA" >/dev/null 2>&1
"$OSSL" x509 -req -in rekeyed.csr -CA inter.pem -CAkey inter.key -CAcreateserial -days 3650 \
    -extfile ext.cnf -extensions ca_ext -out rekeyed.pem >/dev/null 2>&1

# ⚠️ PRECONDITIONS ON THE FIXTURE ITSELF. If `rekeyed` came out genuinely self-signed, or
# not self-issued at all, every assertion below would still "pass" while testing nothing —
# the vacuous-guard shape. Prove the shape with openssl before asking the product about it.
SI=$("$OSSL" x509 -in rekeyed.pem -noout -subject | sed 's/^subject=//')
IS=$("$OSSL" x509 -in rekeyed.pem -noout -issuer  | sed 's/^issuer=//')
chk "PRECONDITION: the re-keyed cert is SELF-ISSUED (subject == issuer)" yes \
    "$([ "$SI" = "$IS" ] && echo yes || echo no)"
"$OSSL" verify -CAfile rekeyed.pem -no-CApath rekeyed.pem >/dev/null 2>&1
chk "PRECONDITION: and its own signature does NOT verify (not self-signed)" yes \
    "$([ $? -ne 0 ] && echo yes || echo no)"
"$OSSL" verify -partial_chain -CAfile inter.pem -no-CApath rekeyed.pem >/dev/null 2>&1
chk "PRECONDITION: it verifies under the PREVIOUS key" yes \
    "$([ $? -eq 0 ] && echo yes || echo no)"
K1=$("$OSSL" x509 -in inter.pem   -noout -pubkey | "$OSSL" sha256 | sed 's/.*= *//')
K2=$("$OSSL" x509 -in rekeyed.pem -noout -pubkey | "$OSSL" sha256 | sed 's/.*= *//')
chk "PRECONDITION: the re-key really carries a DIFFERENT key" yes \
    "$([ "$K1" != "$K2" ] && echo yes || echo no)"
# The control fixture must be the opposite in exactly one respect.
"$OSSL" verify -CAfile root.pem -no-CApath root.pem >/dev/null 2>&1
chk "PRECONDITION: the root IS self-signed" yes "$([ $? -eq 0 ] && echo yes || echo no)"

echo "=== register all three (no --ca-key: a trust anchor we never sign with) ==="
for n in root inter rekeyed; do
    "$CA" --config bootstrap.conf add "$n" --name "$n" --ca-pem "$W/$n.pem" >/dev/null 2>&1
done
chk "PRECONDITION: three CA rows registered" 3 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE is_ca AND id IN ('root','inter','rekeyed');" | tr -d ' ')"

echo "=== fastpki-ca: kind_label ==="
kind_cli(){ "$CA" --config bootstrap.conf show "$1" 2>/dev/null | cut -f3; }
chk "CONTROL: a self-signed root is (root)"        "(root)"       "$(kind_cli root)"
chk "CONTROL: an ordinary sub-CA is intermediate"  "intermediate" "$(kind_cli inter)"
chk "⚠️ a RE-KEYED CA is intermediate, not a root" "intermediate" "$(kind_cli rekeyed)"

echo "=== the console CAs API: kind_of ==="
"$WEB" --config bootstrap.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" WEB_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "web died:"; cat web.log; fi
U="http://127.0.0.1:$PORT"
curl -s -o /dev/null -X POST "$U/api/users" -d 'username=boss&password=bosspw12&role=admin'
curl -s -c boss.cj -X POST "$U/api/login" -d 'username=boss&password=bosspw12' >/dev/null
CAS=$(curl -s -b boss.cj "$U/api/ca-instances")
# ⚠️ Decode the JSON per CA. A bare grep for '"kind":"root"' over the whole document would
# match the `root` control and pass while `rekeyed` was still wrong.
kind_api(){ printf '%s' "$CAS" | tr '{' '\n' | grep "\"id\":\"$1\"" \
              | grep -o '"kind":"[a-z]*"' | head -1 | cut -d'"' -f4; }
chk "PRECONDITION: the API listed the CAs" yes \
    "$([ -n "$(kind_api root)" ] && echo yes || echo no)"
chk "CONTROL: root -> root"               "root"         "$(kind_api root)"
chk "CONTROL: inter -> intermediate"      "intermediate" "$(kind_api inter)"
chk "⚠️ rekeyed -> intermediate, not root" "intermediate" "$(kind_api rekeyed)"

echo
echo "=== CA KIND SELF-SIGNED: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
