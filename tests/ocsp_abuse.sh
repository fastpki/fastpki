#!/usr/bin/env bash
# OCSP abuse testing (§4). The security-critical property: a status
# request for a serial we NEVER issued must NOT come back "good" (a CA that says
# "good" for an unknown serial is forgeable). FastPKI follows RFC 6960 §2.2
# non-issued handling — unknown serials are reported revoked(certificateHold)
# with the ExtendedRevoke extension. Also: a malformed/oversized request must be
# rejected cleanly without crashing the responder.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OCSP="$ROOT/build/fastpki-ocsp"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
W="$(mktemp -d)"; cd "$W"; PORT=18142
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -qi "$2" && echo yes || echo no; }

ca_in_token ca.pem "/CN=Abuse CA" 3650
pg_setup ocsp_abuse
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
NOW=$(date +%s)
# Exactly ONE issued (good) serial. 'deadbeef' is deliberately never inserted.
# ⚠️ ca_instance_id IS REQUIRED on a seeded row. OCSP now refuses to answer for a
# certificate no CA of ours issued: a row with no ca_instance_id is self-signed — since
# A listener's own TLS certificate is exactly such a row — and answering `good` for
# one would be this CA vouching for something it never issued. Measured on the lab: 0 of
# 1504 real issued leaf certificates lack this column, so a fixture without it was
# seeding a shape issuance never produces.
pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,ca_instance_id) VALUES('bb',0,$((NOW-100)),$((NOW+86400)),'CN=good','x','good','f1','ca');"
cat > o.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
# ⚠️ ONE explicit id for every config here, because they all register the SAME ca.pem.
# Without it seed_ca_from_conf invents a time-based id per config, so the same certificate
# ends up registered several times, and the shared /ocsp — which picks its signer by
# matching the request's CertID issuer — resolves to whichever duplicate the DB lists
# first. That was always nondeterministic; it only became visible with the delegated responder, when the
# responder certificate started being looked up per ca_id.
SIGNING_CA_ID=ca-resp
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
LOG_LEVEL=err
EOF
seed_ca_from_conf o.conf   # register the CA (SIGNING_CA_* no longer seed it)
# Slice B: the CA key never signs a status response. Every section below queries
# this responder, so without a credential each one fails on the refusal rather than on
# the abuse case it is actually testing.
printf 'OCSP_RESPONDER_KEY=%s\n' "$(ocsp_responder_key "$W/ca.pem" "$CA_KEY_URI" ca-resp "$W")" >> o.conf
"$OCSP" --config o.conf >srv.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "o.conf" OCSP_PORT "$P" || true
# ⚠️ A SUPERSET OF THE TRAP IT REPLACES. bash does not stack EXIT traps -- this one
# overwrites the `pg_cleanup; kill $P` set above, and the version that only killed $P
# leaked this suite's database on every run. $SP2 is the sub-CA responder started near
# the end; naming it here rather than there keeps the LAST trap the complete one.
trap 'kill ${P:-} ${SP2:-} 2>/dev/null; pg_cleanup' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-ocsp died:"; cat srv.log; exit 1; fi
U="http://127.0.0.1:$PORT/ocsp"
deadline(){ local t=$1; shift; "$@" & local pid=$!; local c=0; while kill -0 $pid 2>/dev/null; do sleep 1; c=$((c+1)); if [ $c -ge $t ]; then kill $pid 2>/dev/null; return 124; fi; done; wait $pid 2>/dev/null; }
ocsp_q(){ deadline 5 "$OSSL" ocsp -issuer ca.pem -serial "0x$1" -url "$U" -CAfile ca.pem -resp_text 2>&1; }

echo "=== the critical property: an unissued serial is never 'good' ==="
UN=$(ocsp_q deadbeef)
chk "response for an unissued serial verifies"      yes "$(has "$UN" 'Response verify OK')"
chk "unissued serial is NOT reported good"          no  "$(has "$UN" '0x.*deadbeef: good')"
chk "unissued serial is reported revoked (non-issued)" yes "$(has "$UN" 'deadbeef: revoked')"
chk "non-issued uses the 1970 epoch revocationTime" yes "$(has "$UN" '1970')"

echo "=== a genuinely issued serial still resolves good (no false revoke) ==="
GD=$(ocsp_q bb)
chk "issued serial reported good" yes "$(has "$GD" '0x.*bb: good')"

# ── thisUpdate is BACKDATED, or a client whose clock lags refuses the response ──────
# ⚠️ THE RESPONSE IS GENERATED PER REQUEST, so it is stamped at exactly `now` — and a
# client even one second behind us then holds a response dated in its own future.
# OpenSSL hides this: OCSP_check_validity takes a 300s skew argument, so `openssl ocsp`
# says "Response verify OK" either way. Windows does not. Measured on a domain client
# whose clock was SIX SECONDS behind the responder:
#
#     certutil -urlfetch -verify   ->  Expired "OCSP"        (before)
#     certutil -urlfetch -verify   ->  Verified "OCSP"       (after)
#
# in the same run in which the CRL — which has been backdated all along — verified from
# the same host. Every certificate we sign backdates notBefore for this reason and the CRL
# backdates lastUpdate; OCSP was the one stamp that did not.
TU=$(printf '%s' "$UN" | sed -n 's/.*This Update: \(.*\)/\1/p' | head -1)
chk "PRECONDITION: the response carries a thisUpdate" yes "$([ -n "$TU" ] && echo yes || echo no)"
# 300s back, so it must be at least 60s in the past even allowing for a slow test host.
TU_EPOCH=$(date -u -d "$TU" +%s 2>/dev/null || date -u -j -f "%b %d %H:%M:%S %Y %Z" "$TU" +%s 2>/dev/null)
NOW_EPOCH=$(date -u +%s)
chk "  and it is backdated, not stamped at 'now'" yes \
    "$([ -n "$TU_EPOCH" ] && [ $((NOW_EPOCH - TU_EPOCH)) -ge 60 ] && echo yes || echo no)"

echo "=== the answer is bound to the CA the client ASKED about ==="
# ⚠️ THE SERIAL LOOKUP DOES NOT PROVE THE ISSUER. A CertID names the issuer -- a hash of
# its name and a hash of its public key -- precisely so the responder can confirm it is the
# right authority to answer. Only the serial was ever looked up, so on a multi-CA instance
# (the shipped model) this responder would answer for a certificate a DIFFERENT CA issued,
# with nothing tying the answer to the authority the client named.
#
# `unauthorized` is RFC 6960 §2.3's status for a question this responder is not the
# authority for -- deliberately NOT the non-issued path, which asserts something ABOUT this
# CA ("we never issued that serial") and would be a false statement here.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.pem \
    -subj "/CN=Some Other CA" -days 3650 >/dev/null 2>&1
# ⚠️ THE PER-CA URL IS THE ONE THAT MATTERS. The shared /ocsp already picked its signer by
# matching the CertID issuer against the hosted CAs and refused when none matched, so
# asserting only there would pass with the responder itself unguarded. /ocsp/<ca-id> names
# the CA in the PATH and did no such matching -- it is the route this fixes.
FOREIGN=$(deadline 5 "$OSSL" ocsp -issuer other.pem -serial 0xbb -url "$U/ca-resp" \
              -CAfile ca.pem -resp_text 2>&1)
chk "a CertID naming ANOTHER CA is refused on /ocsp/<ca-id>" yes "$(has "$FOREIGN" 'unauthorized')"
chk "  and is certainly not answered 'good'"                 no  "$(has "$FOREIGN" '0x.*bb: good')"
# Anti-vacuity: the same serial on the same route with the RIGHT issuer must still answer,
# or "refused" above would be indistinguishable from a route that is simply broken.
OK=$(deadline 5 "$OSSL" ocsp -issuer ca.pem -serial 0xbb -url "$U/ca-resp" \
         -CAfile ca.pem -resp_text 2>&1)
chk "  the SAME serial with the right issuer still answers good" yes "$(has "$OK" '0x.*bb: good')"
# The shared route keeps refusing too (it already did; this pins it).
SHARED=$(deadline 5 "$OSSL" ocsp -issuer other.pem -serial 0xbb -url "$U" \
             -CAfile ca.pem -resp_text 2>&1)
chk "  the shared /ocsp refuses a foreign issuer as well" yes "$(has "$SHARED" 'unauthorized')"

echo "=== a SIGNED request has its signature checked, or is refused ==="
# ⚠️ A SIGNATURE NOBODY VERIFIES IS WORSE THAN NO SIGNATURE. Request signing is optional in
# RFC 6960 §3.1 and rare, but this used to log "signer validation TODO" and answer anyway --
# so a deployment that enabled request signing to authenticate its requesters got no such
# property and was never told. The trust anchor is this CA's own chain; a signer it cannot
# chain to is refused.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout stranger.key -out stranger.pem \
    -subj "/CN=Unrelated Signer" -days 3650 >/dev/null 2>&1
SIGNED=$(deadline 5 "$OSSL" ocsp -issuer ca.pem -serial 0xbb -url "$U" -CAfile ca.pem \
             -signer stranger.pem -signkey stranger.key -resp_text 2>&1)
chk "a request signed by an unrelated key is refused" yes "$(has "$SIGNED" 'unauthorized')"
chk "  it is NOT answered good on an unchecked signature" no "$(has "$SIGNED" '0x.*bb: good')"
# And the common case is untouched: an UNSIGNED request is still answered normally.
chk "  unsigned requests are unaffected" yes "$(has "$(ocsp_q bb)" '0x.*bb: good')"
chk "  responder survived both refusals" yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"

echo "=== malformed / oversized requests are rejected cleanly (no crash) ==="
# Wrong content-type is refused outright (HTTP 415).
chk "wrong content-type -> 415" 415 \
    "$(curl -s -m 5 -o /dev/null -w '%{http_code}' --data-binary 'x' -H 'Content-Type: text/plain' "$U")"
# Random garbage with the OCSP content-type -> RFC 6960 malformedRequest response
# (HTTP 200 carrying responseStatus=malformedRequest is the correct behavior).
head -c 64 /dev/urandom > junk.bin
curl -s -m 5 --data-binary @junk.bin -H 'Content-Type: application/ocsp-request' "$U" -o junk.der
chk "garbage body yields an OCSP malformedRequest" yes \
    "$(has "$("$OSSL" ocsp -respin junk.der -resp_text -noverify 2>&1)" 'malformedrequest')"
# 1 MB oversized body must not crash or hang the responder.
head -c 1048576 /dev/zero > big.bin
curl -s -m 5 -o /dev/null --data-binary @big.bin -H 'Content-Type: application/ocsp-request' "$U" || true
chk "responder still alive after malformed + oversized input" yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"
# ...and a valid query right after still works (no state corruption).
chk "a valid query still works after abuse" yes "$(has "$(ocsp_q bb)" '0x.*bb: good')"

echo "=== RFC 8954 nonce handling ==="
# A normal (16-octet) nonce is echoed back so `openssl ocsp` reports no warning.
NRESP=$(ocsp_q bb)   # openssl's -serial path includes a nonce by default
chk "normal nonce request verifies OK"    yes "$(has "$NRESP" 'Response verify OK')"
chk "server does not warn of a missing nonce" no "$(has "$NRESP" 'no nonce in response')"
# ⚠️ THIS USED TO BE GATED ON `python3 -c 'import cryptography'`, AND THE GATE WAS DEAD.
# The DER these cells need is built by tests/ocsp_nonce_req.sh, which is pure shell and
# holds no Python at all — it was ported and the gate was never removed. So the cells
# skipped on any host without the cryptography module, to build a request that needed
# nothing of the kind. Unconditional now.
# An over-long (>32-octet) nonce must be refused with malformedRequest (RFC 8954 §2.1).
OSSL="$OSSL" bash "$ROOT/tests/ocsp_nonce_req.sh" ca.pem 40 > big_nonce.der 2>/dev/null
curl -s -m 5 --data-binary @big_nonce.der -H 'Content-Type: application/ocsp-request' "$U" -o bn.der
chk "40-octet nonce -> malformedRequest" yes \
    "$(has "$("$OSSL" ocsp -respin bn.der -resp_text -noverify 2>&1)" 'malformedrequest')"
# A 32-octet nonce (the upper bound) is still accepted and echoed.
OSSL="$OSSL" bash "$ROOT/tests/ocsp_nonce_req.sh" ca.pem 32 > ok_nonce.der 2>/dev/null
curl -s -m 5 --data-binary @ok_nonce.der -H 'Content-Type: application/ocsp-request' "$U" -o on.der
chk "32-octet nonce accepted (successful)" yes \
    "$(has "$("$OSSL" ocsp -respin on.der -resp_text -noverify 2>&1)" 'successful')"

echo "=== delegated responder cert: id-pkix-ocsp-nocheck validation (RFC 6960 §2.1.2) ==="
# Helper: generate delegated responder cert with given extension config + section.
# Args: outfile extfile extensions_section keyout
make_resp_cert() {
    "$OSSL" req -new -newkey rsa:2048 -nodes -keyout "$4" \
        -subj "/CN=Test Responder" -out "$W/rc.tmp" >/dev/null 2>&1
    "$OSSL" x509 -req -in "$W/rc.tmp" -CA ca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS -CAcreateserial \
        -days 365 -extfile "$2" -extensions "$3" -out "$1" >/dev/null 2>&1
}
TPORT=18199
# 1) Non-CA cert WITHOUT id-pkix-ocsp-nocheck -> server must refuse to start.
cat > "$W/ext_nocheck_miss.cfg" <<EOF
[v3_resp]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = OCSPSigning
EOF
make_resp_cert "$W/resp_nocheck_miss.pem" "$W/ext_nocheck_miss.cfg" v3_resp "$W/rk1.tmp"
cat > "$W/nocc.conf" <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-resp
OCSP_RESPONDER_KEY=$W/rk1.tmp
OCSP_BIND=127.0.0.1
OCSP_PORT=$TPORT
LOG_LEVEL=err
EOF
seed_ca_from_conf $W/nocc.conf   # register the CA (SIGNING_CA_* no longer seed it)
# The responder certificate is DB-resident and per CA now, not a config path.
# All three cases share ONE ca id on purpose — they also share a CA CERTIFICATE, and the
# shared /ocsp resolves its signer by matching the request's CertID issuer, which cannot
# tell three ids apart when the certificate behind them is the same. Each publish replaces
# the last, and the servers run one at a time.
service_cert_publish "$W/resp_nocheck_miss.pem" ca-resp
"$OCSP" --config "$W/nocc.conf" >"$W/nocc.log" 2>&1 &
NRP=$!; sleep 1
kill -0 $NRP 2>/dev/null && alive=yes || alive=no
chk "server starts (nocheck is validated lazily, not at startup)" yes "$alive"
kill $NRP 2>/dev/null; wait $NRP 2>/dev/null || true
# 2) Non-CA cert WITH nocheck + AIA-OCSP -> starts with warnings.
TPORT2=$((TPORT+1))
cat > "$W/ext_warn.cfg" <<EOF
[v3_resp]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = OCSPSigning
1.3.6.1.5.5.7.48.1.5 = critical,ASN1:NULL
authorityInfoAccess = OCSP;URI:http://127.0.0.1:9999
EOF
make_resp_cert "$W/resp_warn.pem" "$W/ext_warn.cfg" v3_resp "$W/rk2.tmp"
cat > "$W/warn.conf" <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-resp
OCSP_RESPONDER_KEY=$W/rk2.tmp
OCSP_BIND=127.0.0.1
OCSP_PORT=$TPORT2
LOG_LEVEL=err
EOF
seed_ca_from_conf $W/warn.conf   # register the CA (SIGNING_CA_* no longer seed it)
# The responder certificate is DB-resident and per CA now, not a config path.
# All three cases share ONE ca id on purpose — they also share a CA CERTIFICATE, and the
# shared /ocsp resolves its signer by matching the request's CertID issuer, which cannot
# tell three ids apart when the certificate behind them is the same. Each publish replaces
# the last, and the servers run one at a time.
service_cert_publish "$W/resp_warn.pem" ca-resp
"$OCSP" --config "$W/warn.conf" >"$W/warn.log" 2>&1 &
WRP=$!; sleep 1
kill -0 $WRP 2>/dev/null && walive=yes || walive=no
chk "server starts with nocheck + AIA (warnings only)" yes "$walive"
# Trigger lazy Responder construction so the AIA warning is emitted.
"$OSSL" ocsp -issuer ca.pem -serial 0xbb -reqout "$W/aia_req.der" 2>&1 || true
curl -s -m 5 --data-binary @"$W/aia_req.der" -H 'Content-Type: application/ocsp-request' \
    "http://127.0.0.1:${TPORT2}/ocsp" -o /dev/null 2>&1 || true
kill $WRP 2>/dev/null; wait $WRP 2>/dev/null || true
chk "warning about AIA present" yes "$([ -f "$W/warn.log" ] && grep -q 'Authority Information Access' "$W/warn.log" && echo yes || echo no)"
# 3) Non-CA cert WITH nocheck only -> starts cleanly, no warnings.
TPORT3=$((TPORT+2))
cat > "$W/ext_clean.cfg" <<EOF
[v3_resp]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = OCSPSigning
1.3.6.1.5.5.7.48.1.5 = critical,ASN1:NULL
EOF
make_resp_cert "$W/resp_clean.pem" "$W/ext_clean.cfg" v3_resp "$W/rk3.tmp"
cat > "$W/clean.conf" <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-resp
OCSP_RESPONDER_KEY=$W/rk3.tmp
OCSP_BIND=127.0.0.1
OCSP_PORT=$TPORT3
LOG_LEVEL=err
EOF
seed_ca_from_conf $W/clean.conf   # register the CA (SIGNING_CA_* no longer seed it)
# The responder certificate is DB-resident and per CA now, not a config path.
# All three cases share ONE ca id on purpose — they also share a CA CERTIFICATE, and the
# shared /ocsp resolves its signer by matching the request's CertID issuer, which cannot
# tell three ids apart when the certificate behind them is the same. Each publish replaces
# the last, and the servers run one at a time.
service_cert_publish "$W/resp_clean.pem" ca-resp
"$OCSP" --config "$W/clean.conf" >"$W/clean.log" 2>&1 &
CLP=$!; sleep 1
kill -0 $CLP 2>/dev/null && calive=yes || calive=no
chk "server starts cleanly with nocheck only" yes "$calive"
# ⚠️ A NEGATIVE CONTROL HAS TO RUN THE CHECK IT IS NEGATIVE ABOUT. The contradictory-
# extension warnings come out of resolve_responder_cert, which runs PER REQUEST — the
# responder certificate is DB-resident, so nothing reads it at startup. Starting the
# responder and killing it without sending anything left a log that COULD NOT hold that
# string whatever the code did, so "no warnings" passed for a responder that flags every
# nocheck certificate. Send one request, exactly as case 2 does, and prove it reached the
# signing path before reading anything into the absence of the warning.
"$OSSL" ocsp -issuer ca.pem -serial 0xbb -reqout "$W/clean_req.der" 2>&1 || true
curl -s -m 5 --data-binary @"$W/clean_req.der" -H 'Content-Type: application/ocsp-request' \
    "http://127.0.0.1:${TPORT3}/ocsp" -o "$W/clean_resp.der" 2>&1 || true
kill $CLP 2>/dev/null; wait $CLP 2>/dev/null || true
# A *successful* OCSPResponse carries a signed BasicOCSPResponse, and that exists only once
# resolve_responder_cert has returned a certificate — a refusal there answers internalerror
# instead. So this cell is the proof that the extension checks below actually executed.
chk "  the clean responder answered and signed (so the checks ran)" yes \
    "$(has "$("$OSSL" ocsp -respin "$W/clean_resp.der" -resp_text -noverify 2>&1)" 'successful')"
chk "no warnings for clean nocheck cert" no "$([ -f "$W/clean.log" ] && grep -q 'contradictory' "$W/clean.log" && echo yes || echo no)"


# ── ...and a signer this CA DID issue must be ACCEPTED, on a SUB-CA ─────────────────
# ⚠️ REFUSALS ALONE CANNOT TELL A CHECK FROM A WALL. Every cell above is satisfied by an
# implementation that refuses every signed request, which is a different (and much worse)
# product than one that validates them. This is the positive half.
#
# ⚠️ AND IT HAS TO BE A SUB-CA. OCSP_request_verify chains under X509_PURPOSE_OCSP_HELPER,
# whose trust model requires the path to end at a SELF-SIGNED certificate in the store. The
# CA above is a self-signed root, so a signer it issued verifies whether or not the code
# gets this right -- the defect only appears one level down, which is the shipped topology
# (`fastpki-ca create` builds root -> issuing). Measured against a real chain:
#
#     store={issuing CA}                  -> 0  certificate verify error
#     store={issuing CA} + PARTIAL_CHAIN  -> 1
#
# so without PARTIAL_CHAIN every correctly signed request on a sub-CA is answered
# `unauthorized`, and no cell above would notice.
SUBPORT=18143
ca_in_token sub.pem "/CN=Abuse Issuing" 1825 ca-sub ca.pem "$CA_KEY_URI"
SUB_KEY_URI="$CA_KEY_URI"
NOW2=$(date +%s)
pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,ca_instance_id) VALUES('cc',0,$((NOW2-100)),$((NOW2+86400)),'CN=subgood','x','subgood','f2','ca-sub');"
cat > sub.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/sub.pem
SIGNING_CA_KEY=$SUB_KEY_URI
SIGNING_CA_ID=ca-sub
OCSP_BIND=127.0.0.1
OCSP_PORT=$SUBPORT
LOG_LEVEL=err
OCSP_RESPONDER_KEY=$W/sub-responder.key
EOF
seed_ca_from_conf sub.conf
# The responder credential is ALSO a certificate this sub-CA issued, so it doubles as the
# request signer -- exactly the realistic case, a client holding a cert from this PKI.
SUBRESP=$(ocsp_responder_key "$W/sub.pem" "$SUB_KEY_URI" ca-sub "$W")
cp "$SUBRESP" sub-responder.key 2>/dev/null || true
service_cert_publish "$W/ocspresp-ca-sub.pem" ca-sub
"$OCSP" --config sub.conf >subsrv.log 2>&1 & SP2=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "sub.conf" OCSP_PORT "$SP2" || true
SUBU="http://127.0.0.1:$SUBPORT/ocsp/ca-sub"
chk "PRECONDITION: the sub-CA responder started" yes "$(kill -0 $SP2 2>/dev/null && echo yes || echo no)"
# unsigned first: proves the route and the seeded serial are sound, so a refusal below is
# about the SIGNATURE and not about the setup.
SUBOK=$(deadline 5 "$OSSL" ocsp -issuer sub.pem -serial 0xcc -url "$SUBU" -CAfile sub.pem -resp_text 2>&1)
chk "  an UNSIGNED request to the sub-CA answers good" yes "$(has "$SUBOK" '0x.*cc: good')"
SUBSIGNED=$(deadline 5 "$OSSL" ocsp -issuer sub.pem -serial 0xcc -url "$SUBU" -CAfile sub.pem \
                -signer "$W/ocspresp-ca-sub.pem" -signkey "$W/ocsp-responder.key" -resp_text 2>&1)
chk "a request signed by a cert THIS sub-CA issued is ACCEPTED" yes "$(has "$SUBSIGNED" '0x.*cc: good')"
chk "  and is NOT refused as unauthorized" no "$(has "$SUBSIGNED" 'unauthorized')"
# The stranger stays refused here too — the check narrowed, it did not open.
SUBBAD=$(deadline 5 "$OSSL" ocsp -issuer sub.pem -serial 0xcc -url "$SUBU" -CAfile sub.pem \
             -signer stranger.pem -signkey stranger.key -resp_text 2>&1)
chk "  an unrelated signer is still refused on the sub-CA" yes "$(has "$SUBBAD" 'unauthorized')"
kill $SP2 2>/dev/null; wait $SP2 2>/dev/null || true

echo
echo "=== OCSP ABUSE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
