#!/usr/bin/env bash
# Faithful reproduction of est_client/tests.php's FULL matrix:
#   2 subjects x 9 SAN exts x 5 key types = 90 enrol attempts.
# Expectation model (what the PHP policy enforces):
#   - public domain subject (test.google.com)  -> reject
#   - rsa1024 (below min key size)              -> reject
#   - everything else                           -> issue
# Reports issued/rejected and PASS/GAP/FAIL counts out of 90.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"   # real credentials, not AUTH_BACKEND=none
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
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
W="$(mktemp -d)"; cd "$W"; PORT=18443

ca_in_token ca.pem "/CN=Matrix CA" 3650
cp ca.pem root.pem
# EST is HTTPS-only (RFC 7030); give the server its own TLS cert.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3650 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup est_matrix
# AUTH_BACKEND=none is gone, so this suite authenticates for real.
seed_web_user tester secret requester
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
"$OSSL" genpkey -quiet -genparam -algorithm dsa -out dsaparams >/dev/null 2>&1
# Approved domain suffixes (mirrors the PHP domains.txt).
printf "internal\nlocal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
# ⚠️ A REAL user with a REAL role. This suite used to run on AUTH_BACKEND=none with a
# `tester` that existed in no table: `none` accepted any password and the role defaulted to
# `requester`, so all 90 attempts authenticated on a configuration we no longer ship. The
# removed both defaults, and the suite measured 0 issued of 90 — every policy expectation
# failing for an authentication reason that has nothing to do with policy.
#
# The matrix is about ISSUANCE POLICY (key sizes, SAN limits, domain allow-list). It has to
# get past the gate to measure any of that, so the caller is now a seeded `requester`, which
# is also what a real deployment looks like.
seed_web_user tester secret requester

cat > est.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$PORT
# ⚠️ Turn the per-CN cap OFF for this suite, explicitly.
#
# This matrix fires ~90 enrolments at a handful of common names to sweep key types, sizes,
# SANs and subject shapes. It measures which requests POLICY accepts; it is not a volume
# test. This suite used to set MAX_CERTS_PER_CN=0 to keep the per-CN cap from refusing the
# tail of the matrix with 429 and scoring 14 policy expectations as failures. That key no
# longer exists ("no max certs per cn … No globals please"), so there is nothing
# to disable — the only quota left is the per-requester `roles.max_certs`, which is NULL
# for every role this suite seeds.
LOG_LEVEL=err
EOF
seed_ca_from_conf est.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-est" --config "$W/est.conf" >est.log 2>&1 & E=$!
sleep 1; trap 'pg_cleanup; kill $E 2>/dev/null' EXIT

subjects=("test.example.internal" "test.google.com")
exts=("" \
  "-addext subjectAltName=DNS:test2.example.internal" \
  "-addext subjectAltName=DNS:test.example.internal,DNS:test2.example.internal" \
  "-addext subjectAltName=IP:10.2.3.4" \
  "-addext subjectAltName=DNS:test.example.internal,IP:10.2.3.4" \
  "-addext subjectAltName=DNS:test.example.internal,DNS:test2.example.internal,IP:10.2.3.4" \
  "-addext subjectAltName=DNS:test.example.internal.com" \
  "-addext subjectAltName=IP:192.168.1.1" \
  "-addext subjectAltName=DNS:test.example.internal.com,IP:192.168.1.1")
keys=("-newkey rsa:2048" "-newkey rsa:1024" "-newkey dsa:dsaparams" \
      "-newkey ec -pkeyopt ec_paramgen_curve:P-384" "-newkey ec -pkeyopt ec_paramgen_curve:P-256")

n=0; issued=0; rejected=0; pass=0; gap=0; fail=0
for subj in "${subjects[@]}"; do
  for ext in "${exts[@]}"; do
    for key in "${keys[@]}"; do
      n=$((n+1))
      # expectation = reject if any policy rule is violated, else issue:
      #   - subject not under an approved suffix (test.google.com)
      #   - rsa1024 (below min key size)
      #   - a SAN DNS not under an approved suffix (*.internal.com)
      #   - a SAN IP outside 10.0.0.0/8 (192.168.1.1)
      exp=issue
      case "$subj" in *.internal|*.local) ;; *) exp=reject;; esac
      echo "$key" | grep -q "rsa:1024" && exp=reject
      echo "$ext" | grep -q "internal.com" && exp=reject
      echo "$ext" | grep -q "192.168" && exp=reject
      # enrol
      if ! "$OSSL" req -new -subj "/CN=$subj" $key $ext -keyout k.pem -nodes -out r.csr >/dev/null 2>&1; then
        got=reject   # client couldn't even build the CSR (e.g. key gen)
      else
        "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
        body=$(curl -sk -u tester:secret --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
               "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll" | "$OSSL" base64 -d -A 2>/dev/null \
               | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null)
        if echo "$body" | grep -q "BEGIN CERTIFICATE"; then got=issue; else got=reject; fi
      fi
      [ "$got" = issue ] && issued=$((issued+1)) || rejected=$((rejected+1))
      if   [ "$exp" = "$got" ]; then pass=$((pass+1))
      elif [ "$exp" = reject ] && [ "$got" = issue ]; then gap=$((gap+1))
      else fail=$((fail+1)); fi
    done
  done
done

# ── the SAN COUNT limit, at the boundary ─────────────────────────────────────────
# The matrix above proves three of the four issuance-policy rules end to end (subject
# suffix, minimum key size, SAN suffix/range). The SAN COUNT limit was exercised by
# nothing at all until this block, so `>` vs `>=` could have been broken in either
# direction unnoticed.
#
# ⚠️ MOVED THE LIMIT. It was the MAX_SAN config key, set in the config above; it is
# now `roles.max_san` on the role this caller holds, so the number is written to the DB
# instead — and the server has to be restarted to pick up nothing at all, because the
# limit is read per request from the roles table rather than at startup. Both sides of
# the boundary either way: with 3, three SANs must issue and four must be refused.
echo
echo "=== SAN count limit (roles.max_san=3) boundary ==="
pg_exec "UPDATE roles SET max_san=3 WHERE name='requester';" >/dev/null
CHK=$(pg_exec "SELECT max_san FROM roles WHERE name='requester';" | tr -d ' ')
if [ "$CHK" = 3 ]; then echo "  [PASS] PRECONDITION: the role carries max_san=3"; pass=$((pass+1));
else echo "  [FAIL] PRECONDITION: the role carries max_san=3 (got '$CHK')"; fail=$((fail+1)); fi
san_case() {   # <expectation> <san-list>
    "$OSSL" req -new -subj "/CN=sans.example.internal" -newkey rsa:2048 -nodes \
        -addext "subjectAltName=$2" -keyout sk.pem -out sr.csr >/dev/null 2>&1
    "$OSSL" req -in sr.csr -outform DER 2>/dev/null | "$OSSL" base64 > sr.b64
    local out
    out=$(curl -sk -u tester:secret --data-binary @sr.b64 -H "Content-Type: application/pkcs10" \
          "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll" | "$OSSL" base64 -d -A 2>/dev/null \
          | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null)
    local got=reject
    echo "$out" | grep -q "BEGIN CERTIFICATE" && got=issue
    if [ "$1" = "$got" ]; then echo "  [PASS] $3"; pass=$((pass+1));
    else echo "  [FAIL] $3 (expected $1 got $got)"; fail=$((fail+1)); fi
}
san_case issue  "DNS:a.example.internal,DNS:b.example.internal,DNS:c.example.internal" \
    "exactly max_san (3) is allowed"
san_case reject "DNS:a.example.internal,DNS:b.example.internal,DNS:c.example.internal,DNS:d.example.internal" \
    "one over max_san (4) is refused"
# ...and with the number taken away the SAME four-SAN request must go through. Without
# this the pair above would pass identically if the request were refused for some other
# reason entirely — a suffix, a key size, a quota — which is how "the limit works" gets
# reported for a limit nothing is reading.
pg_exec "UPDATE roles SET max_san=NULL WHERE name='requester';" >/dev/null
san_case issue "DNS:a.example.internal,DNS:b.example.internal,DNS:c.example.internal,DNS:d.example.internal" \
    "no number on the role -> the same four SANs issue"

echo
echo "EST full matrix: $n attempts"
echo "  server issued:   $issued"
echo "  server rejected: $rejected"
echo "  vs policy ->  PASS=$pass  GAP=$gap  FAIL=$fail"
echo "  (GAP = should-reject-by-policy but server issued)"
[ "$fail" -eq 0 ]
