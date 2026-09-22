#!/usr/bin/env bash
# Does CMP genm actually return the CA cert content?
set -u
# §3d: honour OSSL/OPENSSL_LIBDIR rather than a hardcoded path. This named an absolute
# path that does not exist on macOS, so the script failed with "No such file or directory"
# on any machine but the Linux box it was written on.
O=${OSSL:-/opt/openssl-3.5/bin/openssl}
[ -x "$O" ] || O=$(command -v openssl)
[ -n "$O" ] || { echo "SKIP: no openssl on PATH"; exit 0; }
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64} OPENSSL_CONF=/etc/ssl/openssl.cnf
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
W=$(mktemp -d); cd "$W"
ca_in_token ca.pem "/CN=GM CA" 3650
pg_setup diag_genm
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
# ⚠️ MISSING EVER SINCE, and invisible because this script is not wired into run_all.sh.
# CMP protects every response with a per-CA RA credential and has no CA-key fallback, so
# without this the server refuses every transaction with "no RA credential" and the client
# reports only "expected response: GENP" — which reads as a broken genm implementation
# rather than missing setup. genm itself is fine; cmp_rfc9810.sh and baseline.sh both
# exercise it green.
cmp_ra_setup ca.pem "$CA_KEY_URI" \
    || { echo "SKIP: could not provision the CMP RA credential"; exit 0; }
cat > cmp.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
CMP_BIND=127.0.0.1
CMP_PORT=18092
CMP_PATH=/cmp
LOG_LEVEL=debug
EOF
seed_ca_from_conf cmp.conf   # register the CA (SIGNING_CA_* no longer seed it)
cmp_ra_conf_lines >> cmp.conf
cmp_seed_pbm diag-genm
"$ROOT/build/fastpki-cmp" --config cmp.conf >srv.log 2>&1 &
P=$!; sleep 1
echo "=== genm caCerts -> cacertsout ==="
# ⚠️ -srvcert is GONE with the unprotected mode. It pins the certificate expected to
# SIGN the response; under PBM the server MAC-protects the response with the shared secret
# instead, so pinning a signer rejects a perfectly good GENP. Same premise change that
# retired cmp_perca's wrong-srvcert assertion.
#
# ⚠️ And this comment lives ABOVE the command, not inside it: a `#` line after a trailing
# backslash is joined to the continued line, which silently swallowed -secret and produced
# "must give -key or -secret" — an error that reads as a missing flag rather than a comment
# in the wrong place.
"$O" cmp -cmd genm -infotype caCerts -server http://127.0.0.1:18092/cmp/ca \
    -recipient "/CN=GM CA" -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 \
    -cacertsout cacerts.pem 2>&1 | tail -3
# A diagnostic that hides the server's reason is not a diagnostic. The client can only say
# "expected response: GENP"; the reason is always in srv.log.
echo "--- fastpki-cmp said ---"
tail -20 srv.log
echo "--- returned CA certs ---"
[ -s cacerts.pem ] && "$O" x509 -in cacerts.pem -noout -subject 2>/dev/null || echo "(no cacerts.pem)"
kill $P 2>/dev/null
