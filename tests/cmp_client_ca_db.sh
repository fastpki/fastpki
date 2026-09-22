#!/usr/bin/env bash
# CMP client-cert trust anchor without a deploy-time file. The trust store is
# assembled additively from (2) CMP_CLIENT_CA_ID — ca_instances rows the admin picks in
# the console — and (3) CMP_CLIENT_CA_BUNDLE — PEM for external CAs, held in the DB config.
# Proves each source authenticates the right client certs and rejects the rest, and that
# CMP stays fail-closed when nothing is configured. (The legacy file path is covered by
# cmp_auth.sh.)
#
# Self-contained (§3d/§3e): ephemeral Postgres + throwaway CAs, pure shell. SKIPs cleanly.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
# These suites use -trusted, not -srvcert. Responses are protected by the RA
# credential now, so pinning the CA as the exact server cert can never match; the
# client validates the chain RA -> CA against that anchor instead.
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
CMP="$ROOT/build/fastpki-cmp"; CA="$ROOT/build/fastpki-ca"; CFG="$ROOT/build/fastpki-config"
for b in "$CMP" "$CA" "$CFG"; do [ -x "$b" ] || { echo "SKIP: $(basename "$b") not built"; exit 0; }; done
W="$(mktemp -d)"; cd "$W"; PORT=18471
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# Signing CA (issues + protects responses); a client-anchor CA to register as a
# ca_instances row; an EXTERNAL CA (never registered) for the bundle; a rogue self-signed.
ca_in_token ca.pem "/CN=Sign CA" 3650
# CMP has no CA-key fallback — issue the RA credential from THIS CA
# while CA_KEY_URI still names it, and publish it once the DB exists.
cmp_ra_issue ca.pem "$CA_KEY_URI" || { echo "SKIP: no CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
SERVER_CA_KEY_URI="$CA_KEY_URI"
ca_in_token clientca.pem "/CN=Client Anchor CA" 3650
CLIENTCA_KEY_URI="$CA_KEY_URI"
ca_in_token extca.pem "/CN=External CA" 3650 extca
EXTCA_KEY_URI="$CA_KEY_URI"
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout rogue.key    -out rogue.pem    -days 365  -subj "/CN=rogue"            >/dev/null 2>&1
# a client cert under each trusted-issuer
mkcl(){ "$OSSL" req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$1" >/dev/null 2>&1
        "$OSSL" x509 -req -in "$1.csr" -CA "$2" -CAkey "$3" $CA_OSSL_ARGS -CAcreateserial -days 365 -out "$1.pem" >/dev/null 2>&1; }
mkcl cl  clientca.pem "$CLIENTCA_KEY_URI"   # signed by the ca_instances anchor
mkcl ext extca.pem    "$EXTCA_KEY_URI"      # signed by the external bundle CA

pg_setup cmp_client_ca_db
cmp_ra_publish || { echo "SKIP: could not publish the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
[ "$(pg_exec 'SELECT 1;' 2>/dev/null)" = "1" ] || { echo "SKIP: no Postgres available"; exit 0; }
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT

cat > base.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$SERVER_CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
CMP_BIND=127.0.0.1
CMP_PORT=$PORT
CMP_PATH=/cmp
LOG_LEVEL=info
EOF
# Into base.conf itself, because run1.conf/run4.conf are DERIVED from it
# (`{ cat base.conf; echo ...; } > run1.conf`) — appending per-start would leave the
# derived configs without an RA credential and every request would 503.
cmp_ra_conf_lines >> base.conf
# The issuing CA (formerly the SIGNING_CA_ID seed) is now a ca_instances row.
seed_ca_from_conf base.conf
# A signature-authenticated caller is identified by its cert CN, and that
# identity now needs a profile grant or resolve_profile refuses. `chcl` is minted later,
# inside the intermediate-anchor section, and is provisioned there.
seed_enrolling_identity cl
seed_enrolling_identity ext
# Register the client-anchor CAs as ca_instances rows (what the console does).
"$CA" --config base.conf add clientca  --name "Client Anchor" --ca-pem "$W/clientca.pem" --ca-key "$CLIENTCA_KEY_URI" >/dev/null
"$CA" --config base.conf add extanchor --name "Ext Anchor"    --ca-pem "$W/extca.pem"    --ca-key "$EXTCA_KEY_URI"    >/dev/null

start(){ "$CMP" --config "$1" >"$2" 2>&1 & P=$!; sleep 1; }
stop(){ kill $P 2>/dev/null; wait $P 2>/dev/null; P=; }
cbase=( -cmd ir -server "http://127.0.0.1:$PORT/cmp/ca" -recipient "/CN=Sign CA" -trusted ca.pem -subject "/CN=req.internal" )
req(){ # <cert> <key> <out> -> issue|reject
  rm -f "$3"
  "$OSSL" cmp "${cbase[@]}" -cert "$1" -key "$2" -keep_alive 0 -newkey scratch.key -certout "$3" >/dev/null 2>&1
  [ -f "$3" ] && echo issue || echo reject
}

echo "=== (2) CMP_CLIENT_CA_ID: a ca_instances row is the client-auth anchor ==="
{ cat base.conf; echo "CMP_CLIENT_CA_ID=clientca"; } > run1.conf
start run1.conf run1.log
chk "client under the ca_instances anchor -> issue"    issue  "$(req cl.pem   cl.key   o1.pem)"
chk "client under an external CA -> reject"            reject "$(req ext.pem  ext.key  o2.pem)"
chk "rogue self-signed client -> reject"               reject "$(req rogue.pem rogue.key o3.pem)"
chk "log: signature auth enabled with 1 anchor"        yes "$(grep -q 'signature authentication enabled (1 trust anchor' run1.log && echo yes || echo no)"
stop

echo "=== (3) CMP_CLIENT_CA_BUNDLE: external CA via the DB config (console-set) ==="
"$CFG" --config base.conf set CMP_CLIENT_CA_BUNDLE "$(cat extca.pem)" >/dev/null
start base.conf run2.log      # no CMP_CLIENT_CA_ID; the bundle comes from the DB overlay
chk "client under the DB bundle CA -> issue"           issue  "$(req ext.pem ext.key o4.pem)"
chk "client under the (non-anchored) clientca -> reject" reject "$(req cl.pem cl.key o5.pem)"
stop
"$CFG" --config base.conf unset CMP_CLIENT_CA_BUNDLE >/dev/null

echo "=== fail-closed: no anchor -> every SIGNATURE-protected request refused ==="
start base.conf run3.log
chk "no client anchor -> signature-protected request rejected" reject "$(req cl.pem cl.key o6.pem)"
# ⚠️ The warning changed wording, and so did what it can truthfully claim. It used
# to say "no auth configured", which was fair when a missing CMP_PBM_SECRET really did
# mean no PBM at all. PBM is per user now, so any provisioned user can still authenticate
# and the only thing a missing anchor costs is signature-protected operations —
# revocation among them. Assert what the operator needs to act on: the anchor.
chk "log: warns there is no client-CA trust anchor" yes \
    "$(grep -q 'no client-CA trust anchor' run3.log && echo yes || echo no)"
chk "  and names revocation as the consequence"     yes \
    "$(grep -q 'including revocation' run3.log && echo yes || echo no)"
stop

echo "=== hot-reload: a console anchor change takes effect without a CMP restart ==="
# Start with NO anchor and a fast (2s) refresh poll; a client under clientca is rejected.
{ cat base.conf; echo "CMP_CLIENT_CA_REFRESH_SEC=2"; } > run4.conf
start run4.conf run4.log
chk "before: client-cl rejected (no anchor yet)"       reject "$(req cl.pem cl.key h1.pem)"
# Designate clientca as the anchor in the DB (console-equivalent) WHILE cmp keeps running.
"$CFG" --config base.conf set CMP_CLIENT_CA_ID clientca >/dev/null
sleep 4                                                 # > the 2s refresh poll
chk "after set clientca: client-cl accepted (no restart)" issue  "$(req cl.pem cl.key h2.pem)"
chk "after set clientca: client-ext still rejected"    reject "$(req ext.pem ext.key h2b.pem)"
chk "log: anchors reloaded from the DB"                yes "$(grep -q 'trust anchors reloaded from DB' run4.log && echo yes || echo no)"
# Switch the anchor to extanchor -> trust genuinely changes (old client now rejected).
"$CFG" --config base.conf set CMP_CLIENT_CA_ID extanchor >/dev/null
sleep 4
chk "after switch to extanchor: client-ext now accepted" issue  "$(req ext.pem ext.key h3.pem)"
chk "after switch to extanchor: client-cl now rejected"  reject "$(req cl.pem cl.key h3b.pem)"
# Remove every anchor -> fail closed again (empty store rejects all).
"$CFG" --config base.conf unset CMP_CLIENT_CA_ID >/dev/null
sleep 4
chk "after removing all anchors: client-ext rejected"    reject "$(req ext.pem ext.key h4.pem)"
stop

echo "=== Naming an INTERMEDIATE anchor must pull in its root ==="
# OpenSSL validates identity -> sub-CA -> root and needs a SELF-SIGNED trust anchor to
# finish. X509_STORE_add_cert() adds an untrusted intermediate, so pointing
# CMP_CLIENT_CA_ID at a sub-CA left the chain unterminated and every signature-protected
# request failed with "no suitable sender cert". build_cmp_client_store() now walks up
# from the named CA, adding each generation until it reaches a self-signed one.
#
# ⚠️ Assert by ISSUING, not by the anchor count. A count of 2 only says two certificates
# went into a store; whether the chain actually validates is a different question, and it
# is the one the client asks.
ca_in_token chroot.pem "/CN=Chain Root" 3650 chroot
CHROOT_KEY_URI="$CA_KEY_URI"
ca_in_token chsub.pem "/CN=Chain Sub" 1800 chsub chroot.pem "$CHROOT_KEY_URI"
CHSUB_KEY_URI="$CA_KEY_URI"
if [ -s chsub.pem ] && [ -s chroot.pem ]; then
    mkcl chcl chsub.pem "$CHSUB_KEY_URI"          # client under the INTERMEDIATE
    seed_enrolling_identity chcl
    "$CA" --config base.conf add chroot --name "Chain Root" --ca-pem "$W/chroot.pem" --ca-key "$CHROOT_KEY_URI" >/dev/null
    "$CA" --config base.conf add chsub  --name "Chain Sub"  --ca-pem "$W/chsub.pem"  --ca-key "$CHSUB_KEY_URI"  >/dev/null
    # Sanity: the chain really is two deep and the sub-CA really is not self-signed —
    # otherwise this section would pass for the wrong reason.
    chk "the sub-CA is issued by the root, not itself" yes \
        "$([ "$("$OSSL" x509 -in chsub.pem -noout -issuer)" != "$("$OSSL" x509 -in chsub.pem -noout -subject | sed 's/^subject=/issuer=/')" ] && echo yes || echo no)"
    { cat base.conf; echo "CMP_CLIENT_CA_ID=chsub"; } > run5.conf
    start run5.conf run5.log
    chk "client under the INTERMEDIATE anchor -> issue"  issue  "$(req chcl.pem chcl.key o7.pem)"
    chk "  the root was walked in (2 anchors from 1 id)" yes \
        "$(grep -q 'signature authentication enabled (2 trust anchor' run5.log && echo yes || echo no)"
    # The walk must widen trust to this chain only — not to everything.
    chk "  a client under an unrelated CA still rejected" reject "$(req ext.pem ext.key o8.pem)"
    stop
else
    echo "  [SKIP] could not mint a token-backed root+sub chain"
fi

echo
echo "=== CMP CLIENT-CA FROM DB: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
