#!/usr/bin/env bash
# PostgreSQL backend validation. Drives the real DB code paths against Postgres:
#   insert_cert (CMP issue) -> get_cert/mark_expired (OCSP) -> revoke_cert
#   (CMP rr) -> get_revoked_certs (CRL).
# Requires a running Postgres with a `pki` db loaded from sql/createdb.sql.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
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
# Follow the helper's settings rather than hardcoding: 33bc9df moved the default
# role/database to fastpki for Docker compose, which left every suite that pinned
# user=pki failing with 'role "pki" does not exist'.
# ⚠️ A THROWAWAY database, not the developer's own. This suite used to run against
# $PGDATABASE, which defaults to `fastpki` -- so it truncated the developer's tables, and on
# any box with an incomplete PKCS#11 toolchain `ca_in_token`'s SKIP path called pg_cleanup
# and DROPPED that database outright. pg_setup gives it an `fpki_<name>_<pid>` of its own.
pg_setup pg_smoke
PGCONN="$PG_CONNINFO"
W="$(mktemp -d)"; cd "$W"; CMP=18098; OCSP=18099; CRLP=/pki/signing_ca.crl
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

# clean slate
pg_exec "TRUNCATE certs;" >/dev/null
ca_in_token ca.pem "/CN=PG CA" 3650
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
common="SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PGCONN
LOG_LEVEL=err"
printf "%s
CMP_BIND=127.0.0.1
CMP_PORT=%s
CMP_PATH=/cmp
CMP_CLIENT_CA_ID=ca
" "$common" "$CMP" > cmp.conf
printf "%s\nOCSP_BIND=127.0.0.1\nOCSP_PORT=%s\nCRL_PATH=%s\n" "$common" "$OCSP" "$CRLP" > ocsp.conf
# Removed the SIGNING_CA_* env seed: a CA only exists once it is a ca_instances
# row. Without this the daemons come up CA-less and every issuance is refused, which
# is why this suite reported "cert issued: no" with no other clue.
# CMP protects its responses with a dedicated RA credential — the CA-key fallback
# is gone — so this suite must provision one before it starts fastpki-cmp, and the client
# must anchor with -trusted rather than pin with -srvcert (the CA is no longer the sender).
cmp_ra_issue ca.pem "$CA_KEY_URI" \
    || { echo "SKIP: could not provision the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
cmp_ra_publish
cmp_ra_conf_lines >> cmp.conf
seed_ca_from_conf cmp.conf
# ⚠️ The reference doubles as the `owner` recorded on every cert it enrols, and the
# ownership rule wants an identity certificate whose CN equals it — so the ref has to be
# a name policy will actually issue. `pg-smoke` is not under allowed_domains (`internal`),
# so the identity cert was refused and the revocation had nothing to sign with.
cmp_seed_pbm owner.internal
# Slice B: the CA key never signs a status response, so the responder needs its
# own certificate issued BY this CA -- otherwise fastpki-ocsp refuses every query.
printf 'OCSP_RESPONDER_KEY=%s\n' "$(ocsp_responder_key "$W/ca.pem" "$CA_KEY_URI" ca "$W")" >> ocsp.conf

"$ROOT/build/fastpki-cmp"  --config cmp.conf  >cmp.log  2>&1 & C=$!
"$ROOT/build/fastpki-ocsp" --config ocsp.conf >ocsp.log 2>&1 & O=$!
sleep 1; trap 'kill $C $O 2>/dev/null; pg_cleanup' EXIT

# connectivity sanity (did the servers connect to PG, or crash?)
if ! kill -0 $C 2>/dev/null; then echo "fastpki-cmp died:"; cat cmp.log; exit 1; fi
if ! kill -0 $O 2>/dev/null; then echo "fastpki-ocsp died:"; cat ocsp.log; exit 1; fi

echo "=== CMP issue -> Postgres (insert_cert) ==="
"$OSSL" cmp -cmd ir -server "http://127.0.0.1:$CMP/cmp/ca" -recipient "/CN=PG CA" \
    -trusted ca.pem -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
    -newkey scratch.key -subject "/CN=pg.internal" -certout leaf.pem >/dev/null 2>&1
chk "cert issued"             ok "$( [ -f leaf.pem ] && echo ok || echo no )"
# NOT is_ca: the CA is a row of `certs` too, so an unscoped count is 2.
# Scoped to the cert under test: the RA credential is a leaf row too, and
# "how many leaves exist" was never the property this line cared about.
chk "1 row in pg certs"       1  "$(pg_exec "select count(*) from certs where cn='pg.internal';")"

ocsp_status() { "$OSSL" ocsp -issuer ca.pem -cert leaf.pem -url "http://127.0.0.1:$OCSP/ocsp" -noverify 2>/dev/null | grep -oE "good|revoked" | head -1; }
echo "=== OCSP get_cert (Postgres) ==="
chk "OCSP status = good"      good "$(ocsp_status)"

echo "=== CMP rr -> revoke_cert (Postgres) ==="
# ⚠️ REVOCATION IS SIGNATURE-PROTECTED, NOT PBM. This used to revoke over PBM, which
# only worked because the suite set CMP_ACCEPT_UNPROTECTED=true — that flag also switched
# off the whole rr authorization block (PBM-refusal, signer identity, ownership). With the
# flag gone, PBM rr is refused by design: "revocation requires signature-based protection
# (PBM is allowed for enrollment only)".
#
# So mint an identity certificate the way a real client would — over PBM, CN equal to the
# enrolment reference, which is the `owner` recorded on leaf.pem — and revoke with it. That
# also makes this suite exercise the ownership rule instead of bypassing it.
# ⚠️ `-newkey` LOADS a key file, it does not generate one (the suite makes scratch.key
# the same way above). Passing a path that does not exist fails in the client with
# "cannot set up CMP context", never reaching the server — cmp.log stays empty, which
# reads as the server silently refusing.
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out id.key >/dev/null 2>&1
"$OSSL" cmp -cmd ir -server "http://127.0.0.1:$CMP/cmp/ca" -recipient "/CN=PG CA" \
    -trusted ca.pem -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
    -newkey id.key -subject "/CN=$CMP_PBM_REF" -certout id.pem >id.log 2>&1
chk "identity cert for the owner issued" ok "$( [ -f id.pem ] && echo ok || echo no )"
[ -f id.pem ] || { echo "--- client said:"; tail -8 id.log; echo "--- fastpki-cmp said:"; tail -8 cmp.log; }
"$OSSL" cmp -cmd rr -server "http://127.0.0.1:$CMP/cmp/ca" -recipient "/CN=PG CA" \
    -trusted ca.pem -cert id.pem -key id.key -keep_alive 0 -oldcert leaf.pem >/dev/null 2>&1
chk "OCSP status = revoked"   revoked "$(ocsp_status)"
chk "pg row status = -1"      -1 "$(pg_exec "select status from certs where cn='pg.internal';")"

echo "=== CRL get_revoked_certs (Postgres) ==="
SER=$("$OSSL" x509 -in leaf.pem -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
# CRL_PATH is the CONFIGURED base; the CRL itself is served per-CA at /{ca_id}.crl.
# Fetching $CRLP hits the bare-path handler, which 404s with "use
# /{ca_id}.crl" — 16 bytes that openssl then cannot parse as a CRL.
curl -s "http://127.0.0.1:$OCSP/ca.crl" -o crl.der
LIST=$("$OSSL" crl -inform DER -in crl.der -noout -text 2>/dev/null | grep -A1 "Serial Number" | tr 'A-F' 'a-f' | tr -d ' :')
echo "$LIST" | grep -qi "$SER" && f=yes || f=no
chk "revoked serial in CRL"   yes "$f"

echo "=== cert store search_certs (Postgres, text column) ==="
chk "search by cn returns the cert" 1 "$(pg_exec "select count(*) from certs where cn='pg.internal';")"

echo
echo "=== PG SMOKE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
