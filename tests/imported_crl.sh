#!/usr/bin/env bash
# An OFFLINE root publishes a CRL it signed elsewhere.
#
# ── The gap this closes ────────────────────────────────────────────────────────────
#
# FastPKI generates every CRL from a local key. A CA whose key it does not hold — an
# offline root, which is the RECOMMENDED posture — therefore has no CRL at all, and every
# serving path refuses. Measured on dc1 before this landed:
#
#     GET /issuing.crl   200  (key in this node's token)
#     GET /labroot.crl   503  CRL unavailable: CA 'labroot' has no signing key configured
#
# The requirement: offline root CRL issuance and publishing must be supported.
#
# ── What this asserts ──────────────────────────────────────────────────────────────
#
# The whole operator story, in order, against a CA this deployment genuinely cannot sign
# for: it refuses, an import is REFUSED unless the bytes verify against that CA, a good
# import is accepted, and the same URL then serves those exact bytes back.
#
# ⚠️ The refusal comes FIRST and is asserted. Without it the publish assertion could pass
# on a build that was generating the CRL locally all along — which is precisely what every
# other CA in this suite's database does.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"
W="$(mktemp -d)"; cd "$W"; PORT=18271
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# An OFFLINE root: its key exists HERE, in the test's workdir, and is never given to the
# deployment. That is the whole scenario — the private key is somewhere FastPKI cannot
# reach, so it can publish a CRL but never produce one.
#
# ⚠️ basicConstraints IS PASSED EXPLICITLY. `openssl req -x509` adds CA:TRUE only when a
# config file supplies x509_extensions, so with the OPENSSL_CONF= the harness mandates
# these came out as ordinary end-entity certificates and `fastpki-ca add` refused them —
# correctly — with "that certificate is not a CA". Every assertion downstream then failed
# for a reason that has nothing to do with what this suite tests. -addext does not depend
# on the ambient config, which is the point.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 3650 \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -subj "/CN=Offline Root 269" >/dev/null 2>&1
# A second, unrelated CA — the wrong signer for the negative control below.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.pem -days 3650 \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -subj "/CN=Some Other CA" >/dev/null 2>&1
[ -s root.pem ] || { echo "SKIP: could not create the offline root"; echo "=== IMPORTED CRL: PASS=0 FAIL=0 SKIP=1 ==="; exit 0; }

pg_setup imported_crl
trap 'pg_cleanup; kill ${S:-} 2>/dev/null' EXIT

# ⚠️ fastpki-OCSP, not fastpki-store. `/{ca_id}.crl` is an OCSP-daemon route; the store
# serves `/crls/search`. My first version started the store and got 404 for every request —
# the daemon was answering correctly about a route it does not have.
cat > store.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
LOG_LEVEL=info
EOF

# Register the root as a CA instance with NO key — exactly what an offline root looks like
# in the database. `fastpki-ca add` is the operator path.
# --ca-pem, and deliberately NO --ca-key: "a trust anchor this instance only verifies
# against and never signs with" is exactly what an offline root is.
"$ROOT/build/fastpki-ca" --config store.conf add offlineroot \
    --name "Offline Root 269" --ca-pem root.pem >add.log 2>&1
[ -s add.log ] && head -2 add.log
chk "the offline root is registered" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='offlineroot' AND is_ca;" | tr -d ' ')"
chk "  and the deployment holds NO key for it" yes \
    "$([ -z "$(pg_exec "SELECT coalesce(private_key,'') FROM certs WHERE id='offlineroot';" | tr -d ' ')" ] && echo yes || echo no)"

"$ROOT/build/fastpki-ocsp" --config store.conf >store.log 2>&1 & S=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$S" || true
chk "the OCSP daemon started" yes "$(kill -0 $S 2>/dev/null && echo yes || echo no)"

echo "=== 1. with nothing imported, the CRL is REFUSED — and that is the bug ==="
C=$(curl -s -o r0.out -w '%{http_code}' "http://127.0.0.1:$PORT/offlineroot.crl")
chk "GET /offlineroot.crl -> 503" 503 "$C"
chk "  and it says the key is remote" yes \
    "$(grep -qi "remote\|no signing key" r0.out && echo yes || echo no)"

echo "=== 2. an import that does NOT verify against this CA is refused ==="
# The offline signer produces a real CRL — but signed by the WRONG CA. A name check alone
# would let this through, which is why the import verifies the SIGNATURE.
cat > o.cnf <<'EOF'
[ca]
default_ca = CA_default
[CA_default]
database = index.txt
crlnumber = crlnumber
default_md = sha256
default_crl_days = 30
EOF
: > index.txt; echo 1000 > crlnumber
"$OSSL" ca -config o.cnf -gencrl -cert other.pem -keyfile other.key -out wrong.crl >/dev/null 2>&1
chk "PRECONDITION: a CRL signed by the OTHER CA exists" yes \
    "$([ -s wrong.crl ] && echo yes || echo no)"
"$ROOT/build/fastpki-ca" --config store.conf import-crl offlineroot wrong.crl >wrong.log 2>&1
RC=$?
chk "importing it is REFUSED" no "$([ "$RC" -eq 0 ] && echo yes || echo no)"
chk "  and the refusal names the reason" yes \
    "$(grep -qiE "not signed by|issuer is not" wrong.log && echo yes || echo no)"
chk "  nothing was stored" 0 \
    "$(pg_exec "SELECT count(*) FROM crls WHERE ca_id='offlineroot';" | tr -d ' ')"

echo "=== 3. the root signs its own CRL offline, and the import is accepted ==="
: > index.txt; echo 2000 > crlnumber
"$OSSL" ca -config o.cnf -gencrl -cert root.pem -keyfile root.key -out root.crl >/dev/null 2>&1
chk "PRECONDITION: the offline root produced a CRL" yes \
    "$([ -s root.crl ] && echo yes || echo no)"
"$ROOT/build/fastpki-ca" --config store.conf import-crl offlineroot root.crl >imp.log 2>&1
chk "the import is accepted" 0 "$?"
chk "  it is stored for this CA" 1 \
    "$(pg_exec "SELECT count(*) FROM crls WHERE ca_id='offlineroot';" | tr -d ' ')"
# Decode what was recorded rather than trusting the command's own message (§3d) — and
# take the EXPECTED value from the CRL too. `openssl ca` reads its crlnumber file as HEX,
# so "echo 2000 > crlnumber" produces 8192; hardcoding 2000 asserted my arithmetic, not the
# product.
WANTNUM=$("$OSSL" crl -in root.crl -noout -text 2>/dev/null \
          | grep -A1 -i "CRL Number" | tail -1 | tr -dc '0-9')
chk "PRECONDITION: the CRL carries a crlNumber" yes "$([ -n "$WANTNUM" ] && echo yes || echo no)"
chk "  and it was decoded from the DER into the row" "$WANTNUM" \
    "$(pg_exec "SELECT coalesce(crl_number,0) FROM crls WHERE ca_id='offlineroot';" | tr -d ' ')"

echo "=== 4. the same URL now publishes it, byte for byte ==="
C=$(curl -s -o got.crl -w '%{http_code}' "http://127.0.0.1:$PORT/offlineroot.crl")
chk "GET /offlineroot.crl -> 200" 200 "$C"
# ⚠️ Decode it as a CRL and check it against the ROOT — "200 with a body" would pass on a
# server returning anything at all.
chk "  the body is a CRL issued by the offline root" yes \
    "$("$OSSL" crl -inform DER -in got.crl -noout -issuer 2>/dev/null \
       | grep -q 'Offline Root 269' && echo yes || echo no)"
chk "  and it verifies against the root's own key" yes \
    "$("$OSSL" crl -inform DER -in got.crl -noout -CAfile root.pem 2>&1 \
       | grep -qi 'verify OK' && echo yes || echo no)"
# The bytes must be the ones imported — not re-signed, not re-encoded.
"$OSSL" crl -in root.crl -outform DER -out want.crl 2>/dev/null
chk "  byte-identical to what was imported" yes \
    "$(cmp -s want.crl got.crl && echo yes || echo no)"

echo "=== 5. the point of the feature: a REVOKED sub-CA reaches clients ==="
# ⚠️ Sections 1-4 publish an EMPTY CRL. That proves the plumbing and nothing else — an
# offline root's CRL exists to say "this sub-CA is revoked", and a serving path that
# dropped or re-generated the entries would pass every assertion above.
#
# It also asserts what the schema comment CLAIMS and nothing tested: one row per
# (ca_id, is_delta), so a second import REPLACES the first. Only the current CRL is
# servable; an accumulating table would leave the stale one reachable.
mkdir -p newcerts; echo 01 > serial
cat > s.cnf <<'EOF'
[ca]
default_ca = CA_default
[CA_default]
dir              = .
database         = index.txt
new_certs_dir    = newcerts
certificate      = root.pem
private_key      = root.key
serial           = serial
crlnumber        = crlnumber
default_md       = sha256
default_days     = 365
default_crl_days = 30
policy           = pol
[pol]
commonName = supplied
EOF
: > index.txt
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout sub.key -out sub.csr \
    -subj "/CN=Sub CA Under 269" >/dev/null 2>&1
"$OSSL" ca -batch -config s.cnf -in sub.csr -out sub.pem >/dev/null 2>&1
SUBSER=$("$OSSL" x509 -in sub.pem -noout -serial 2>/dev/null | cut -d= -f2)
chk "PRECONDITION: the offline root issued a sub-CA" yes \
    "$([ -n "$SUBSER" ] && echo yes || echo no)"
# Revoked with the offline key, on the offline machine — FastPKI is never involved.
"$OSSL" ca -config s.cnf -revoke sub.pem -crl_reason keyCompromise >/dev/null 2>&1
"$OSSL" ca -config s.cnf -gencrl -out rev.crl >/dev/null 2>&1
chk "PRECONDITION: that CRL lists the sub-CA" yes \
    "$("$OSSL" crl -in rev.crl -noout -text 2>/dev/null | grep -qi "$SUBSER" && echo yes || echo no)"

"$ROOT/build/fastpki-ca" --config store.conf import-crl offlineroot rev.crl >rev.log 2>&1
chk "the second import is accepted" 0 "$?"
chk "  it REPLACED the first — still one row" 1 \
    "$(pg_exec "SELECT count(*) FROM crls WHERE ca_id='offlineroot';" | tr -d ' ')"

C=$(curl -s -o pub.crl -w '%{http_code}' "http://127.0.0.1:$PORT/offlineroot.crl")
chk "GET /offlineroot.crl -> 200" 200 "$C"
chk "  the PUBLISHED CRL names the revoked sub-CA" yes \
    "$("$OSSL" crl -inform DER -in pub.crl -noout -text 2>/dev/null \
       | grep -qi "$SUBSER" && echo yes || echo no)"
chk "  and carries the reason the offline signer set" yes \
    "$("$OSSL" crl -inform DER -in pub.crl -noout -text 2>/dev/null \
       | grep -qi "Key Compromise" && echo yes || echo no)"
chk "  it still verifies against the root" yes \
    "$("$OSSL" crl -inform DER -in pub.crl -noout -CAfile root.pem 2>&1 \
       | grep -qi 'verify OK' && echo yes || echo no)"
# The stale empty CRL must be gone, not merely shadowed.
chk "  the superseded CRL is no longer served" no \
    "$(cmp -s want.crl pub.crl && echo yes || echo no)"

echo
echo "=== IMPORTED CRL: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
