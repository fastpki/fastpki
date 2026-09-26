#!/usr/bin/env bash
# SCEP renewal (RFC 8894 §3.3.2) + CA key rollover GetNextCACert (§3.5.3).
#   - GetCACaps advertises Renewal + GetNextCACert when enabled/configured
#   - GetNextCACert returns the rollover CA cert, CA-signed
#   - a PKCSReq signed by a currently-valid issued cert enrolls WITHOUT a
#     challengePassword (renewal); a self-signed request without one is refused
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"   # grant_profile
source "$ROOT/tests/hsm_helpers.sh"
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
TC="$ROOT/build/scep-testclient"
W="$(mktemp -d)"; cd "$W"; PORT=18452
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }
has() { echo "$1" | grep -qi "$2" && echo yes || echo no; }

ca_in_token ca.pem "/CN=SCEP Renew CA" 3650
cp ca.pem root.pem
# A distinct "next" CA cert for GetNextCACert.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout next.key -out nextca.pem -days 3650 -subj "/CN=SCEP Next CA" >/dev/null 2>&1
pg_setup scep_renewal
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
SCEP_BIND=127.0.0.1
SCEP_PORT=$PORT
SCEP_RENEWAL=true
SCEP_NEXT_CA_CERT=$W/nextca.pem
# The "not treated as a renewal" reasons are logged at INFO. At `err` no
# assertion can see them, which is how a log claim survives a whole suite.
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-scep" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-scep died:"; cat srv.log; exit 1; fi
URL="http://127.0.0.1:$PORT/scep/ca"
"$OSSL" x509 -inform DER -in <(curl -s "$URL?operation=GetCACert") -out ca_dl.pem >/dev/null 2>&1

# ⚠️ The SHARED-challenge SCEP path resolves an identity (`owner='scep'`) and
# that identity now needs a profile grant, or the union is empty and every enrolment is
# refused. Granted before the first PKIOperation for that reason.
grant_profile scep requester
# The deployment-wide SCEP_CHALLENGE is gone, so every CSR below carries the
# PER-USER credential minted for the `scep` user. Seeding it as a real web_users row keeps
# the identity the rest of this suite already assumes: scep_kid_user("scep:scep") == "scep".
seed_web_user scep scepPW123456 requester >/dev/null 2>&1
SCEP_CH=$(scep_challenge_for scep)
chk "PRECONDITION: the scep user has a per-user challengePassword" yes \
    "$(printf '%s' "$SCEP_CH" | grep -q '^scep:.' && echo yes || echo no)"

echo "=== GetCACaps advertises Renewal + GetNextCACert ==="
CAPS=$(curl -s "$URL?operation=GetCACaps")
chk "advertises Renewal"       yes "$(has "$CAPS" '^Renewal$')"
chk "advertises GetNextCACert" yes "$(has "$CAPS" '^GetNextCACert$')"

echo "=== GetNextCACert returns the rollover CA cert (CA-signed) ==="
CT=$(curl -s -D - "$URL?operation=GetNextCACert" -o next.p7 | grep -i '^content-type' | tr -d '\r' | sed 's/.*: //')
chk "content-type is x-x509-next-ca-cert" yes "$(has "$CT" 'application/x-x509-next-ca-cert')"
NEXTSUBJ=$("$OSSL" pkcs7 -inform DER -in next.p7 -print_certs 2>/dev/null | "$OSSL" x509 -noout -subject 2>/dev/null | sed -n 's/.*CN *= *//p')
chk "carries the Next CA cert" "SCEP Next CA" "${NEXTSUBJ:-none}"

# helper: make a CSR (challengePassword only when non-empty — an empty value makes
# `openssl req` error and silently keep the old CSR) + a self-signed signer cert.
make_csr() { # $1 = challenge ("" => no challengePassword attribute at all)
             # $2 = CN            (default device.internal)
             # $3 = SAN list      (e.g. "DNS:a,DNS:b")
    rm -f dev.key dev.csr csr.der client.pem
    local cn=${2:-device.internal}
    {
      echo "[req]"
      echo "distinguished_name = dn"
      [ -n "$1" ] && echo "attributes = attrs"
      [ -n "${3:-}" ] && echo "req_extensions = ext"
      echo "prompt = no"
      echo "[dn]"
      echo "CN = $cn"
      [ -n "$1" ] && { echo "[attrs]"; echo "challengePassword = $1"; }
      [ -n "${3:-}" ] && { echo "[ext]"; echo "subjectAltName = $3"; }
    } > req.cnf
    "$OSSL" req -new -newkey rsa:2048 -nodes -keyout dev.key -config req.cnf -out dev.csr >/dev/null 2>&1
    "$OSSL" req -in dev.csr -outform DER -out csr.der >/dev/null 2>&1
    "$OSSL" req -x509 -key dev.key -subj "/CN=$cn" -days 2 -out client.pem >/dev/null 2>&1
    # ⚠️ Assert the CSR really carries what was asked for. `openssl req` fails silently
    # on a malformed config and leaves the PREVIOUS csr.der in place, so every assertion
    # below would then measure the wrong request and the product would take the blame.
    [ -s csr.der ] || { echo "  [FAIL] make_csr produced no CSR"; fail=$((fail+1)); }
}
enroll() { # signer_cert signer_key req_out -> pkiStatus line, writes $3.issued
    "$TC" build ca_dl.pem "$1" "$2" csr.der "$3.der" >/dev/null 2>&1
    curl -s -X POST --data-binary @"$3.der" -H 'Content-Type: application/x-pki-message' \
        "$URL?operation=PKIOperation" -o "$3.resp" 2>/dev/null
    "$TC" parse "$1" "$2" "$3.resp" "$3.issued" 2>/dev/null
}

echo "=== initial enrollment (challenge) then renewal (signed by the issued cert) ==="
make_csr "$SCEP_CH"
chk "initial PKCSReq -> SUCCESS" "pkiStatus=0" "$(enroll client.pem dev.key e1)"
"$OSSL" x509 -inform DER -in e1.issued -out issued1.pem >/dev/null 2>&1
cp dev.key issued1.key   # the issued cert is for dev.key
# Renewal: NEW csr, NO challenge, signed by the previously-issued cert+key.
make_csr ""
chk "renewal without a challenge, signed by the issued cert -> SUCCESS" \
    "pkiStatus=0" "$(enroll issued1.pem issued1.key ren)"

echo "=== a self-signed request without a challenge is still refused ==="
make_csr ""
chk "self-signed, no challenge -> FAILURE" "pkiStatus=2" "$(enroll client.pem dev.key noch)"

echo "=== A renewal must ask for the identity it already holds ==="
# THE hole. Before this, "renewal" meant only "the CMS is signed by an unrevoked
# certificate this CA issued" and NOTHING afterwards compared the CSR to that
# certificate. So the holder of any such certificate could obtain one for any subject the
# shared SCEP profile permits, with no challengePassword — and it did not even have to be
# a certificate issued over SCEP.
#
# issued1.pem is a legitimate, unrevoked, currently-valid certificate for
# device.internal. That is exactly the credential the attacker in this scenario holds.
make_csr "" other.internal
chk "a DIFFERENT subject is NOT a renewal -> FAILURE" "pkiStatus=2" \
    "$(enroll issued1.pem issued1.key esc)"
chk "  and no certificate exists for it"  0 \
    "$(pg_exec "select count(*) from certs where cn='other.internal';" | tr -d ' ')"
# ⚠️ ANTI-VACUITY. If the refusal above were firing for some unrelated reason — a broken
# fixture, a dead server, a CSR that never got built — this next one would fail too, and
# the block would be worthless. The SAME signer, asking for the SAME identity, must still
# renew.
make_csr ""
chk "the same subject still renews"       "pkiStatus=0" \
    "$(enroll issued1.pem issued1.key ok2)"

echo "=== A renewal may DROP a name but never ADD one ==="
# ⚠️ This block needed its own enrolment. issued1 carries NO subjectAltName at all —
# issuance does not synthesise one from the CN — and my first version asserted it did.
# The assertion that caught it ("the issued cert has the SAN we think it has") is why
# this is written against a certificate that demonstrably HAS names rather than one I
# assumed had them; without it the subset case would have been testing an empty set
# against an empty set and passing for no reason.
make_csr "$SCEP_CH" san.internal "DNS:a.internal,DNS:b.internal"
chk "an enrolment WITH SANs succeeds"     "pkiStatus=0" "$(enroll client.pem dev.key s1)"
"$OSSL" x509 -inform DER -in s1.issued -out sans1.pem >/dev/null 2>&1
cp dev.key sans1.key
# The premise, measured, not assumed: issuance must have carried both names through.
chk "  and the issued cert carries both names" yes \
    "$("$OSSL" x509 -in sans1.pem -noout -text | grep -q 'DNS:a.internal' && \
       "$OSSL" x509 -in sans1.pem -noout -text | grep -q 'DNS:b.internal' && echo yes || echo no)"
# Dropping one is harmless and clients legitimately do it when a hostname is retired.
# Requiring EQUALITY here would refuse honest renewals for no security gain, which is why
# the check is a subset test.
make_csr "" san.internal "DNS:a.internal"
chk "dropping a name still renews"        "pkiStatus=0" "$(enroll sans1.pem sans1.key sub)"
# Adding one is the escalation.
make_csr "" san.internal "DNS:a.internal,DNS:evil.internal"
chk "adding a name -> FAILURE"            "pkiStatus=2" "$(enroll sans1.pem sans1.key add)"
chk "  and nothing was issued carrying it" 0 \
    "$(pg_exec "select count(*) from certs where cert is not null and position('evil.internal' in encode(cert,'escape')) > 0;" | tr -d ' ')"

echo "=== An EXPIRED signer is not a credential ==="
# Nothing checked notAfter, and expiry is the only thing that ever retires a certificate
# nobody revoked — so without this the renewal right was permanent.
#
# Built the way it really occurs: a certificate this CA genuinely signed, whose validity
# has passed, with an unrevoked row in `certs` (status 0) so the old status check passes.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout old.key -subj "/CN=device.internal" -out old.csr >/dev/null 2>&1
"$OSSL" x509 -req -in old.csr -CA ca.pem -CAkey "$CA_KEY_URI" ${CA_OSSL_ARGS:-} -CAcreateserial \
        -not_before 20200101000000Z -not_after 20200201000000Z -out old.pem >/dev/null 2>&1
chk "the fixture signer really is expired" yes \
    "$("$OSSL" x509 -in old.pem -noout -checkend 0 >/dev/null 2>&1 && echo no || echo yes)"
OLDSN=$("$OSSL" x509 -in old.pem -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
pg_exec "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('$OLDSN',0,'device.internal','ca');" >/dev/null
chk "  and its row is UNREVOKED (status 0)" 1 \
    "$(pg_exec "select count(*) from certs where serial='$OLDSN' and status=0;" | tr -d ' ')"
make_csr ""
chk "an expired signer cannot renew -> FAILURE" "pkiStatus=2" \
    "$(enroll old.pem old.key exp)"
chk "  and the log says why"               yes \
    "$(grep -q 'signer certificate has expired' srv.log && echo yes || echo no)"

echo
echo "=== SCEP RENEWAL: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
