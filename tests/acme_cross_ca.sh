#!/usr/bin/env bash
# (HIGH): two ACME issuance-authorization gaps, both letting an account obtain a
# certificate it should not.
#
# H2 — finalize was not bound to the CA that authorized the order. new-order gates
# acme:enrol against the CA in ITS url; finalize picked the signing CA from ITS url and
# re-checked nothing, and the order carried no CA. So: new-order + solve on CA-A, then POST
# the finalize to CA-B, and be issued under CA-B — past CA-B's grant, profile and caps.
#
# H3 — the CSR commonName was never checked against the ordered identifiers (RFC 8555
# §7.4). Only SANs were compared, and policy.cpp skips the CN domain-allowlist for ACME. A
# CSR with SAN=controlled + CN=victim yielded a CA-signed cert asserting victim.
#
# ⚠️ THIS DRIVES THE REAL HANDLER WITH SIGNED JWS, not certbot — certbot will never send
# the malicious cross-CA finalize or the mismatched CN. The order is taken to `ready` the
# legitimate way (dns-01), and only the finalize is hostile.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/acme_jws.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF

W="$(mktemp -d)"; cd "$W"; PORT=18472; DNSP=15372
EST_CA="$ROOT/build/fastpki-ca"
pass=0; fail=0; SRV=
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=CA A" 3650 caa       || { echo "SKIP: no token CA"; exit 0; }
CAA_KEY="$CA_KEY_URI"; cp ca.pem root.pem
ca_in_token cab.pem "/CN=CA B" 3650 cab
CAB_KEY="$CA_KEY_URI"
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_cross_ca
trap 'pg_cleanup; kill ${SRV:-} 2>/dev/null; pkill -f "dnsstub $DNSP" 2>/dev/null' EXIT
# Both domains are approved — the point is authorization, not the allowlist.
printf 'controlled.test\nvictim.test\n' > domains.txt; seed_domains "$W/domains.txt"

cat > bootstrap.conf <<EOF
BASE_URL=https://localhost:$PORT
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CAA_KEY
SIGNING_CA_ID=caa
ROOT_CA_PEM=$W/root.pem
ACME_CERT=$W/acme.pem
ACME_KEY=$W/acme.key
PG_CONNINFO=$PG_CONNINFO
ACME_BIND=127.0.0.1
ACME_PORT=$PORT
ACME_BASE_PATH=/acme
ACME_DNS_RESOLVER=127.0.0.1:$DNSP
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf
"$EST_CA" --config bootstrap.conf add cab --name "CA B" --ca-pem "$W/cab.pem" --ca-key "$CAB_KEY" >/dev/null

"$ROOT/build/fastpki-acme" --config bootstrap.conf > srv.log 2>&1 & SRV=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$SRV" || true
kill -0 $SRV 2>/dev/null || { echo "acme died:"; cat srv.log; exit 1; }
U="https://127.0.0.1:$PORT"
export REQUESTS_CA_BUNDLE="$W/acme.pem"
# _acme_respond dns-01 reads the resolver port from _ACME_DNSPORT, and the server's
# ACME_DNS_RESOLVER points at the same one — they must agree or the challenge never
# validates (which reads as "authz never valid", not a config mismatch).
export _ACME_DNSPORT=$DNSP

# The account holds acme:enrol on BOTH CAs (scope '*') on purpose: it isolates H2. With the
# grant present on CA-B too, the ONLY thing that can stop a CA-B finalize of a CA-A order is
# the CA-binding check — not may_enrol. If the test instead relied on a missing grant it
# would pass even with H2 unfixed.
acme_seed_eab crossca
# acme_seed_eab maps the kid to a requester-role user; requester already holds acme:enrol *.

# ── drive a dns-01 order to `ready` on CA-A ──────────────────────────────────
DOMAIN=controlled.test
acme_dir "$U/acme/caa/directory" || { echo "FAIL: directory"; exit 1; }
jws_newkey acct.pem
acme_new_account acct.pem
KID=$ACME_LOCATION
chk "PRECONDITION: account registered on CA-A" yes "$([ -n "$KID" ] && echo yes || echo no)"

acme_post_kid acct.pem "$KID" "$ACME_NEW_ORDER" \
    "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"$DOMAIN\"}]}"
chk "PRECONDITION: new-order on CA-A -> 201" 201 "$ACME_STATUS"
ORDER=$ACME_LOCATION
AUTHZ=$(printf '%s' "$ACME_BODY" | sed -n 's/.*"authorizations":\["\([^"]*\)".*/\1/p')
FIN_A=$(printf '%s' "$ACME_BODY" | sed -n 's/.*"finalize":"\([^"]*\)".*/\1/p')
# The order stored the CA it was authorized under.
chk "PRECONDITION: order row remembers CA-A" caa \
    "$(pg_exec "select ca_instance_id from orders where id='$(basename "$ORDER")';" | tr -d ' ')"

# Solve dns-01.
acme_post_kid acct.pem "$KID" "$AUTHZ" ""
CH=$(printf '%s' "$ACME_BODY" | tr '{' '\n' | grep 'dns-01')
CHURL=$(json_str "$CH" url); TOKEN=$(json_str "$CH" token)
KEYAUTH="$TOKEN.$(jws_thumbprint acct.pem)"
_acme_respond dns-01 "$DOMAIN" "$TOKEN" "$KEYAUTH" || { echo "FAIL: dns responder"; exit 1; }
acme_post_kid acct.pem "$KID" "$CHURL" '{}'
acme_poll_status acct.pem "$KID" "$AUTHZ" valid || { echo "FAIL: authz never valid"; _acme_respond_stop; exit 1; }
# ⚠️ READ THE ORDER. This compared two literals (`yes yes`), so it announced a precondition
# nothing had looked at: the authz half is established by the `|| exit 1` above, and the
# order half by no code in the suite at all — a server that left the order `pending` after
# its only authorization went valid (RFC 8555 §7.1.6) still scored a PASS. Everything below
# is about a finalize, so the order being FINALIZABLE is the precondition that matters.
# Polled rather than read once: validation saves the authz before the order, so a single
# read can land in the microseconds between the two writes.
acme_poll_status acct.pem "$KID" "$ORDER" ready || true
chk "PRECONDITION: the authorized order is ready" ready "$(json_str "$ACME_BODY" status)"

# A correct CSR: empty subject, SAN = the ordered domain (certbot's shape).
"$OSSL" ecparam -name prime256v1 -genkey -noout -out leaf.key 2>/dev/null
printf '[req]\ndistinguished_name=dn\nreq_extensions=v3\nprompt=no\n[dn]\n[v3]\nsubjectAltName=DNS:%s\n' \
       "$DOMAIN" > csr.cnf
"$OSSL" req -new -key leaf.key -subj "/" -config csr.cnf -outform DER -out good.csr 2>/dev/null

echo "=== H2: finalizing the CA-A order under CA-B is refused ==="
# Rewrite the finalize URL from /acme/caa/... to /acme/cab/... — the cross-CA attack.
FIN_B=$(printf '%s' "$FIN_A" | sed 's#/acme/caa/#/acme/cab/#')
chk "  the two finalize URLs actually differ" yes \
    "$([ "$FIN_A" != "$FIN_B" ] && echo yes || echo no)"
acme_post_kid acct.pem "$KID" "$FIN_B" "{\"csr\":\"$(b64url < good.csr)\"}"
chk "cross-CA finalize is refused (403)" 403 "$ACME_STATUS"
chk "  the problem names an authorization failure" yes \
    "$(printf '%s' "$ACME_BODY" | grep -qi 'unauthorized\|different CA' && echo yes || echo no)"
chk "  and NO certificate was issued under CA-B" 0 \
    "$(pg_exec "select count(*) from certs where cn='$DOMAIN' and ca_instance_id='cab';" | tr -d ' ')"

echo "=== H2 control: finalizing under the CORRECT CA still works ==="
acme_post_kid acct.pem "$KID" "$FIN_A" "{\"csr\":\"$(b64url < good.csr)\"}"
chk "same-CA finalize -> 200" 200 "$ACME_STATUS"
acme_poll_status acct.pem "$KID" "$ORDER" valid || true
chk "  a certificate WAS issued under CA-A" 1 \
    "$(pg_exec "select count(*) from certs where cn='$DOMAIN' and ca_instance_id='caa';" | tr -d ' ')"
_acme_respond_stop

echo "=== H3: a CSR whose CN is not an ordered identifier is refused ==="
# A fresh order + solve, then a CSR SAN=controlled (validated) but CN=victim (never proven).
DOMAIN2=controlled.test
acme_post_kid acct.pem "$KID" "$ACME_NEW_ORDER" \
    "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"$DOMAIN2\"}]}"
ORDER2=$ACME_LOCATION
AUTHZ2=$(printf '%s' "$ACME_BODY" | sed -n 's/.*"authorizations":\["\([^"]*\)".*/\1/p')
FIN2=$(printf '%s' "$ACME_BODY" | sed -n 's/.*"finalize":"\([^"]*\)".*/\1/p')
acme_post_kid acct.pem "$KID" "$AUTHZ2" ""
CH2=$(printf '%s' "$ACME_BODY" | tr '{' '\n' | grep 'dns-01')
CHURL2=$(json_str "$CH2" url); TOKEN2=$(json_str "$CH2" token)
KEYAUTH2="$TOKEN2.$(jws_thumbprint acct.pem)"
_acme_respond dns-01 "$DOMAIN2" "$TOKEN2" "$KEYAUTH2" || { echo "FAIL: dns2"; exit 1; }
acme_post_kid acct.pem "$KID" "$CHURL2" '{}'
acme_poll_status acct.pem "$KID" "$AUTHZ2" valid || { echo "FAIL: authz2"; _acme_respond_stop; exit 1; }

# SAN matches the ordered domain (passes the SAN check); CN is a DIFFERENT name.
printf '[req]\ndistinguished_name=dn\nreq_extensions=v3\nprompt=no\n[dn]\nCN=victim.test\n[v3]\nsubjectAltName=DNS:%s\n' \
       "$DOMAIN2" > bad.cnf
"$OSSL" req -new -key leaf.key -config bad.cnf -outform DER -out bad.csr 2>/dev/null
chk "  PRECONDITION: the CSR really carries CN=victim.test" yes \
    "$("$OSSL" req -inform DER -in bad.csr -noout -subject 2>/dev/null | grep -q 'victim.test' && echo yes || echo no)"
acme_post_kid acct.pem "$KID" "$FIN2" "{\"csr\":\"$(b64url < bad.csr)\"}"
chk "CN-not-in-identifiers finalize is refused (400)" 400 "$ACME_STATUS"
chk "  the problem is a badCSR" yes \
    "$(printf '%s' "$ACME_BODY" | grep -qi 'badCSR\|CN' && echo yes || echo no)"
chk "  and no cert asserting victim.test was issued" 0 \
    "$(pg_exec "select count(*) from certs where cn='victim.test';" | tr -d ' ')"
_acme_respond_stop

kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; SRV=
echo
echo "=== ACME CROSS-CA: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
