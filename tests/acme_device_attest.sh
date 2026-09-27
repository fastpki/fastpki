#!/usr/bin/env bash
# ACME device attestation (device-attest-01, draft-ietf-acme-device-attest) — the path an
# Apple device takes with an ACME configuration profile and Attest=true.
#
# A device has no external account binding: its account is accepted only while a one-time
# ticket from `fastpki-acme --issue-device-ticket` is outstanding, and that account can do
# nothing but claim a ticket. The ticket is the device's ClientIdentifier and the order's
# permanent-identifier; the proof is a WebAuthn attestation object of format "apple" whose
# leaf certificate chains to an attestation root and carries the device serial and a
# freshness code equal to SHA-256 of the challenge token. Finalize issues only for a CSR
# carrying the attested key, to the ticket's owner, and revokes the same device's previous
# certificate as superseded.
#
# Apple's real root cannot sign test attestations, so a stand-in root is supplied through
# ACME_ATTESTATION_ROOTS — the setting that ADDS attestation roots, which is exactly what
# a deployment would use for a second attestor. Every check the server makes is the one a
# real device meets.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; PORT=18459
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

source "$ROOT/tests/acme_jws.sh"
JWS_TMP="$W/jws"; mkdir -p "$JWS_TMP"

# ── a stand-in attestation PKI: root (P-384, like Apple's) -> intermediate -> per-challenge leaf
"$OSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out att-root.key 2>/dev/null
"$OSSL" req -x509 -new -key att-root.key -subj "/CN=Test Attestation Root" -days 30 \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -out att-root.pem 2>/dev/null
"$OSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out att-int.key 2>/dev/null
"$OSSL" req -new -key att-int.key -subj "/CN=Test Attestation Sub CA" -out att-int.csr 2>/dev/null
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > int.ext
"$OSSL" x509 -req -in att-int.csr -CA att-root.pem -CAkey att-root.key -CAcreateserial \
    -days 30 -extfile int.ext -out att-int.pem 2>/dev/null
"$OSSL" x509 -in att-int.pem -outform DER -out att-int.der
# A second, untrusted root, for the chain check.
"$OSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out rogue.key 2>/dev/null
"$OSSL" req -x509 -new -key rogue.key -subj "/CN=Rogue Attestation Root" -days 30 \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -out rogue.pem 2>/dev/null
chk "PRECONDITION: the stand-in attestation PKI was built" yes \
    "$([ -s att-root.pem ] && [ -s att-int.der ] && [ -s rogue.pem ] && echo yes || echo no)"

hexof() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
# The attestation leaf for one challenge: <device-key> <serial> <token> <out.der> [issuer]
att_leaf() {
    local key=$1 serial=$2 token=$3 out=$4 issuer=${5:-int} fresh
    fresh=$(printf '%s' "$token" | "$OSSL" dgst -sha256 -binary | od -An -tx1 | tr -d ' \n')
    printf '1.2.840.113635.100.8.9.1=DER:%s\n1.2.840.113635.100.8.9.2=DER:%s\n1.2.840.113635.100.8.11.1=DER:%s\n' \
        "$(hexof "$serial")" "$(hexof "UDID-$serial")" "$fresh" > leaf.ext
    # Posture extensions for this one leaf, e.g. "OS=26.1 SIP=0": the OS version as text and
    # the SIP status as a DER INTEGER (0 = on). Absent unless asked for.
    for kv in ${ATT_EXTRA:-}; do
        case "$kv" in
            OS=*)  printf '1.2.840.113635.100.8.10.1=DER:%s\n' "$(hexof "${kv#OS=}")" >> leaf.ext ;;
            SIP=*) printf '1.2.840.113635.100.8.13.1=DER:0201%02x\n' "${kv#SIP=}" >> leaf.ext ;;
        esac
    done
    "$OSSL" req -new -key "$key" -subj "/CN=attested" -out leaf.csr 2>/dev/null
    if [ "$issuer" = rogue ]; then
        "$OSSL" x509 -req -in leaf.csr -CA rogue.pem -CAkey rogue.key -CAcreateserial -days 1 \
            -extfile leaf.ext -outform DER -out "$out" 2>/dev/null
    else
        "$OSSL" x509 -req -in leaf.csr -CA att-int.pem -CAkey att-int.key -CAcreateserial -days 1 \
            -extfile leaf.ext -outform DER -out "$out" 2>/dev/null
    fi
}
# CBOR (RFC 8949): {"fmt":"apple","attStmt":{"x5c":[leaf,intermediate]},"authData":h''}
cb() { printf "\\$(printf %03o "$1")"; }
cbor_head() {   # <major> <length>
    local m=$(( $1 << 5 )) n=$2
    if [ "$n" -lt 24 ]; then cb $((m | n))
    elif [ "$n" -lt 256 ]; then cb $((m | 24)); cb "$n"
    else cb $((m | 25)); cb $((n >> 8)); cb $((n & 255)); fi
}
cbor_tstr() { cbor_head 3 "${#1}"; printf '%s' "$1"; }
cbor_bstr() { cbor_head 2 "$(wc -c < "$1" | tr -d ' ')"; cat "$1"; }
att_obj() {   # <leaf.der> <fmt> -> base64url on stdout
    {
        cbor_head 5 3
        cbor_tstr fmt;      cbor_tstr "$2"
        cbor_tstr attStmt;  cbor_head 5 1; cbor_tstr x5c
                            cbor_head 4 2; cbor_bstr "$1"; cbor_bstr att-int.der
        cbor_tstr authData; cbor_head 2 0
    } > attobj.cbor
    b64url < attobj.cbor
}

# ── the deployment ───────────────────────────────────────────────────────────────────
ca_in_token ca.pem "/CN=Device CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_device_attest
P=""
trap 'pg_cleanup; [ -n "$P" ] && kill $P 2>/dev/null' EXIT
cat > bootstrap.conf <<EOF
BASE_URL=https://localhost:$PORT
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
ACME_CERT=$W/acme.pem
ACME_KEY=$W/acme.key
PG_CONNINFO=$PG_CONNINFO
ACME_BIND=127.0.0.1
ACME_PORT=$PORT
ACME_BASE_PATH=/acme
ACME_ATTESTATION_ROOTS=$("$OSSL" base64 -A < att-root.pem)
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf
seed_enrolling_identity alice
# A profile that puts the attested serial in the certificate (device_serial_san), granted to
# its own user: profiles a user holds are combined, so granting it to alice would put the
# serial into every device certificate of hers. Created before the service starts, which
# reads profiles once at startup.
cat > fleet.json <<'EOF'
{"fleet":{"allowed_ku":["digitalSignature"],"allowed_eku":["clientAuth"],
          "default_ku":["digitalSignature"],"default_eku":["clientAuth"],
          "allowed_san_types":["dns"],"device_serial_san":true}}
EOF
"$ROOT/build/fastpki-config" --config bootstrap.conf profiles-import fleet.json >/dev/null 2>&1
seed_enrolling_identity fleetuser
grant_profile fleetuser fleet
chk "PRECONDITION: the fleet profile is stored with the serial option" yes \
    "$(pg_exec "SELECT count(*) FROM cert_profiles WHERE name='fleet';" | grep -q 1 && echo yes || echo no)"
seed_web_user nobody nobodyPW12345 none >/dev/null 2>&1
ticket() { "$ROOT/build/fastpki-acme" --config bootstrap.conf --issue-device-ticket "$@" 2>ticket.err; }

"$ROOT/build/fastpki-acme" --config bootstrap.conf > srv.log 2>&1 & P=$!
wait_listen "$PORT" "$P" 30
if ! kill -0 "$P" 2>/dev/null; then echo "fastpki-acme died:"; cat srv.log; exit 1; fi
acme_dir "https://127.0.0.1:$PORT/acme/ca/directory"

echo "=== with no ticket outstanding, an account still needs a binding ==="
jws_newkey dev.pem
acme_post_jwk dev.pem "$ACME_NEW_ACCT" '{"termsOfServiceAgreed":true}'
chk "newAccount without a binding -> 400" 400 "$ACME_STATUS"
chk "  ... externalAccountRequired" yes \
    "$(printf '%s' "$ACME_BODY" | grep -q externalAccountRequired && echo yes || echo no)"

echo "=== issuing tickets: every enrolment check is made when the ticket is issued ==="
chk "a ticket for an owner with no acme:enrol is refused" "1" "$(ticket --ca ca --owner nobody >/dev/null; echo $?)"
chk "a ticket for a CA that does not exist is refused" "1" "$(ticket --ca nope --owner alice >/dev/null; echo $?)"
chk "a ticket without --owner is refused" "2" "$(ticket --ca ca >/dev/null; echo $?)"
T_BADNONCE=$(ticket --ca ca --owner alice)
T_ROGUE=$(ticket --ca ca --owner alice)
T_GOOD=$(ticket --ca ca --owner alice)
T_NEXT=$(ticket --ca ca --owner alice)
T_EXPIRED=$(ticket --ca ca --owner alice --ttl 1)
chk "tickets are issued, 32 hex characters each" yes \
    "$(for t in "$T_BADNONCE" "$T_ROGUE" "$T_GOOD" "$T_NEXT"; do printf '%s' "$t" | grep -qE '^[0-9a-f]{32}$' || echo no; done | grep -q no && echo no || echo yes)"

echo "=== an account without a binding can only prove a device ==="
acme_post_jwk dev.pem "$ACME_NEW_ACCT" '{"termsOfServiceAgreed":true}'
chk "newAccount without a binding, while tickets are outstanding -> 201" 201 "$ACME_STATUS"
KID=$ACME_LOCATION
acme_post_kid dev.pem "$KID" "$ACME_NEW_ORDER" '{"identifiers":[{"type":"dns","value":"device.example.org"}]}'
chk "  ... and its dns order is refused (403)" 403 "$ACME_STATUS"

order_for() {   # <ticket> -> sets ORDER, AUTHZ, CHALL, TOKEN, FINALIZE
    ORDER=""; AUTHZ=""; CHALL=""; TOKEN=""; FINALIZE=""
    acme_post_kid dev.pem "$KID" "$ACME_NEW_ORDER" \
        "{\"identifiers\":[{\"type\":\"permanent-identifier\",\"value\":\"$1\"}]}"
    [ "$ACME_STATUS" = 201 ] || return 1
    ORDER=$ACME_LOCATION
    FINALIZE=$(json_str "$ACME_BODY" finalize)
    AUTHZ=$(printf '%s' "$ACME_BODY" | sed -n 's/.*"authorizations":\["\([^"]*\)".*/\1/p')
    acme_post_kid dev.pem "$KID" "$AUTHZ" ""
    CHALL=$(json_str "$ACME_BODY" url)
    TOKEN=$(json_str "$ACME_BODY" token)
    AUTHZ_BODY=$ACME_BODY
}
answer() {   # <leaf.der> [fmt]
    acme_post_kid dev.pem "$KID" "$CHALL" "{\"attObj\":\"$(att_obj "$1" "${2:-apple}")\"}"
}

acme_post_kid dev.pem "$KID" "$ACME_NEW_ORDER" '{"identifiers":[{"type":"permanent-identifier","value":"0123456789abcdef0123456789abcdef"}]}'
chk "an order for an unknown ticket is refused (403)" 403 "$ACME_STATUS"
sleep 2
acme_post_kid dev.pem "$KID" "$ACME_NEW_ORDER" "{\"identifiers\":[{\"type\":\"permanent-identifier\",\"value\":\"$T_EXPIRED\"}]}"
chk "an order for an expired ticket is refused (403)" 403 "$ACME_STATUS"

echo "=== the attestation must be fresh ==="
order_for "$T_BADNONCE"
chk "a device order is created (201)" yes "$([ -n "$ORDER" ] && echo yes || echo no)"
chk "  ... offering device-attest-01 and nothing else" "device-attest-01" \
    "$(chs=${AUTHZ_BODY#*\"challenges\"}; printf '%s' "${chs%%]*}" | grep -oE '"type":"[a-z0-9-]+"' | sed 's/"type":"//;s/"//' | sort -u | tr '\n' ' ' | sed 's/ $//')"
acme_post_kid dev.pem "$KID" "$ACME_NEW_ORDER" "{\"identifiers\":[{\"type\":\"permanent-identifier\",\"value\":\"$T_BADNONCE\"}]}"
chk "the same ticket cannot back a second order (403)" 403 "$ACME_STATUS"
jws_newkey devkey1.pem
att_leaf devkey1.pem SERIAL-ONE "not-this-token" leaf.der
answer leaf.der
chk "an attestation for another token -> 400" 400 "$ACME_STATUS"
chk "  ... badAttestationStatement" yes \
    "$(printf '%s' "$ACME_BODY" | grep -q badAttestationStatement && echo yes || echo no)"

echo "=== the attestation must chain to an attestation root ==="
order_for "$T_ROGUE"
att_leaf devkey1.pem SERIAL-ONE "$TOKEN" leaf.der rogue
answer leaf.der
chk "a leaf from an untrusted root -> badAttestationStatement" yes \
    "$([ "$ACME_STATUS" = 400 ] && printf '%s' "$ACME_BODY" | grep -q badAttestationStatement && echo yes || echo no)"

echo "=== a genuine attestation, and a certificate for the attested key only ==="
order_for "$T_GOOD"
att_leaf devkey1.pem SERIAL-ONE "$TOKEN" leaf.der
answer leaf.der packed
chk "an attestation of another format is refused" 400 "$ACME_STATUS"
order_for "$T_NEXT"   # the refused format spent T_GOOD's challenge; carry on with the next
NEXT_ORDER=$ORDER NEXT_FINALIZE=$FINALIZE
att_leaf devkey1.pem SERIAL-ONE "$TOKEN" leaf.der
answer leaf.der
chk "a good attestation -> 200" 200 "$ACME_STATUS"
chk "  ... the challenge is valid" valid "$(json_str "$ACME_BODY" status)"
acme_post_kid dev.pem "$KID" "$NEXT_ORDER" ""
chk "  ... and the order is ready" ready "$(json_str "$ACME_BODY" status)"

csr_b64() { "$OSSL" req -new -key "$1" -subj "/CN=$2" -outform DER 2>/dev/null | b64url; }
jws_newkey otherkey.pem
acme_post_kid dev.pem "$KID" "$NEXT_FINALIZE" "{\"csr\":\"$(csr_b64 otherkey.pem device-one)\"}"
chk "a CSR for a key the device did not attest -> badCSR" yes \
    "$([ "$ACME_STATUS" = 400 ] && printf '%s' "$ACME_BODY" | grep -q badCSR && echo yes || echo no)"
acme_post_kid dev.pem "$KID" "$NEXT_FINALIZE" "{\"csr\":\"$(csr_b64 devkey1.pem device-one)\"}"
chk "the attested key's CSR -> 200" 200 "$ACME_STATUS"
chk "  ... the order is valid" valid "$(json_str "$ACME_BODY" status)"
# The certificate belongs to the ticket's owner, not to the account, and the device still has
# to be able to fetch it — on a real Mac this was refused 401 and the install failed.
CERT_URL=$(json_str "$ACME_BODY" certificate)
acme_post_kid dev.pem "$KID" "$CERT_URL" ""
chk "  ... and the device account can download it" 200 "$ACME_STATUS"
chk "  ... as a PEM chain" yes "$(printf '%s' "$ACME_BODY" | grep -q 'BEGIN CERTIFICATE' && echo yes || echo no)"
jws_newkey stranger.pem
acme_new_account stranger.pem
acme_post_kid stranger.pem "$ACME_LOCATION" "$CERT_URL" ""
chk "  ... while another account cannot (401)" 401 "$ACME_STATUS"
CERT1=$(pg_exec "SELECT serial FROM certs WHERE cn='device-one' AND status=0;" | head -1)
chk "  ... a certificate was recorded" yes "$([ -n "$CERT1" ] && echo yes || echo no)"
chk "  ... issued to the ticket's owner" alice "$(pg_exec "SELECT owner FROM certs WHERE serial='$CERT1';")"

echo "=== the same device again: its previous certificate is revoked as superseded ==="
T_AGAIN=$(ticket --ca ca --owner alice)
order_for "$T_AGAIN"
jws_newkey devkey2.pem
att_leaf devkey2.pem SERIAL-ONE "$TOKEN" leaf.der
answer leaf.der
acme_post_kid dev.pem "$KID" "$FINALIZE" "{\"csr\":\"$(csr_b64 devkey2.pem device-one-b)\"}"
chk "the device's next certificate is issued" 200 "$ACME_STATUS"
chk "  ... and the previous one is revoked" "-1" "$(pg_exec "SELECT status FROM certs WHERE serial='$CERT1';")"
chk "  ... as superseded (reason 4)" 4 "$(pg_exec "SELECT \"revocationReason\" FROM certs WHERE serial='$CERT1';")"

echo "=== an MDM fleet: a registered serial number enrols with no ticket ==="
# The profile's ClientIdentifier is the device's serial; the list names the CA, the owner and
# the profile. The attestation must prove exactly that serial — Apple signs it.
pg_exec "INSERT INTO acme_device_serials(serial,ca_instance_id,owner,profile,created,updated)
         VALUES('C02SERIAL001','ca','alice','',0,0);" >/dev/null
order_for C02SERIAL001
chk "an order for a registered serial -> 201, no ticket needed" yes "$([ -n "$ORDER" ] && echo yes || echo no)"
SER_FINALIZE=$FINALIZE
jws_newkey devkey3.pem
att_leaf devkey3.pem C02OTHER0001 "$TOKEN" leaf.der
answer leaf.der
chk "an attestation of ANOTHER serial is refused" yes \
    "$([ "$ACME_STATUS" = 400 ] && printf '%s' "$ACME_BODY" | grep -q 'not the one this order names' && echo yes || echo no)"
order_for C02SERIAL001
chk "the same serial may order again (it is not one-time)" yes "$([ -n "$ORDER" ] && echo yes || echo no)"
att_leaf devkey3.pem C02SERIAL001 "$TOKEN" leaf.der
answer leaf.der
chk "the device's own serial -> the challenge is valid" valid "$(json_str "$ACME_BODY" status)"
acme_post_kid dev.pem "$KID" "$FINALIZE" "{\"csr\":\"$(csr_b64 devkey3.pem fleet-mac-1)\"}"
chk "  ... and the certificate is issued" 200 "$ACME_STATUS"
chk "  ... to the serial's registered owner" alice "$(pg_exec "SELECT owner FROM certs WHERE cn='fleet-mac-1';")"
FLEET1=$(pg_exec "SELECT serial FROM certs WHERE cn='fleet-mac-1';")
order_for C02SERIAL001
jws_newkey devkey4.pem
att_leaf devkey4.pem C02SERIAL001 "$TOKEN" leaf.der
answer leaf.der
acme_post_kid dev.pem "$KID" "$FINALIZE" "{\"csr\":\"$(csr_b64 devkey4.pem fleet-mac-1b)\"}"
chk "the device enrolling again revokes its previous certificate" "-1" \
    "$(pg_exec "SELECT status FROM certs WHERE serial='$FLEET1';")"
acme_post_kid dev.pem "$KID" "$ACME_NEW_ORDER" '{"identifiers":[{"type":"permanent-identifier","value":"C02NOTLISTED"}]}'
chk "a serial that is not registered is refused (403)" 403 "$ACME_STATUS"
pg_exec "INSERT INTO acme_device_serials(serial,ca_instance_id,owner,profile,created,updated)
         VALUES('C02NOBODY001','ca','nobody','',0,0);" >/dev/null
acme_post_kid dev.pem "$KID" "$ACME_NEW_ORDER" '{"identifiers":[{"type":"permanent-identifier","value":"C02NOBODY001"}]}'
chk "a registered serial whose owner has no acme:enrol is refused (403)" 403 "$ACME_STATUS"

echo "=== the attested serial in the certificate, when the profile asks (RFC 4043) ==="
has_pid() { "$OSSL" x509 -inform DER -noout -ext subjectAltName 2>/dev/null | grep -c 'Permanent Identifier\|1.3.6.1.5.5.7.8.3'; }
certder() { pg_exec "SELECT encode(cert,'hex') FROM certs WHERE cn='$1';" | xxd -r -p; }
T_FLEET=$(ticket --ca ca --owner fleetuser --profile fleet)
order_for "$T_FLEET"
jws_newkey devkey5.pem
att_leaf devkey5.pem C02FLEETSAN1 "$TOKEN" leaf.der
answer leaf.der
acme_post_kid dev.pem "$KID" "$FINALIZE" "{\"csr\":\"$(csr_b64 devkey5.pem fleet-san-1)\"}"
chk "a device ticket under the fleet profile is issued" 200 "$ACME_STATUS"
chk "  its certificate carries a permanentIdentifier SAN" 1 "$(certder fleet-san-1 | has_pid)"
# OpenSSL 3.5 prints a permanentIdentifier as `othername: Permanent Identifier:<unsupported>`,
# so the value is read by parsing the SAN extension's own contents.
certder fleet-san-1 > fleet-san.der
SAN_OFF=$("$OSSL" asn1parse -inform DER -in fleet-san.der 2>/dev/null \
          | awk '/Subject Alternative Name/{f=1;next} f&&/OCTET STRING/{sub(/:.*/,"",$1);print $1;exit}')
SAN_ASN1=$("$OSSL" asn1parse -inform DER -in fleet-san.der -strparse "${SAN_OFF:-0}" 2>&1)
chk "  whose value is the attested serial" yes \
    "$(printf '%s' "$SAN_ASN1" | grep -q 'UTF8STRING *:C02FLEETSAN1' && echo yes || echo no)"
chk "the default profile puts no serial in the certificate" 0 "$(certder device-one-b | has_pid)"

echo "=== posture: a minimum OS version and SIP (ACME_ATTEST_MIN_OS, ACME_ATTEST_REQUIRE_SIP) ==="
# Settings are read at startup, so the service restarts with both checks on.
kill "$P" 2>/dev/null; wait "$P" 2>/dev/null
printf 'ACME_ATTEST_MIN_OS=26.0\nACME_ATTEST_REQUIRE_SIP=true\n' >> bootstrap.conf
"$ROOT/build/fastpki-acme" --config bootstrap.conf >> srv.log 2>&1 & P=$!
wait_listen "$PORT" "$P" 30
posture() {   # <ATT_EXTRA> -> the challenge response's HTTP status
    local tk; tk=$(ticket --ca ca --owner alice)
    order_for "$tk"
    jws_newkey pkey.pem
    ATT_EXTRA="$1" att_leaf pkey.pem C02POSTURE01 "$TOKEN" leaf.der
    answer leaf.der
}
posture 'OS=18.5 SIP=0'
chk "an attested OS version below the minimum is refused"    400 "$ACME_STATUS"
chk "  and the reason names the version"                    yes \
    "$(printf '%s' "$ACME_BODY" | grep -q 'below ACME_ATTEST_MIN_OS' && echo yes || echo no)"
posture 'SIP=0'
chk "an attestation with no OS version is refused"          400 "$ACME_STATUS"
posture 'OS=26.1 SIP=1'
chk "a Mac with SIP off is refused"                         400 "$ACME_STATUS"
chk "  and the reason says so" yes \
    "$(printf '%s' "$ACME_BODY" | grep -q 'System Integrity Protection is off' && echo yes || echo no)"
posture 'OS=26.0'
chk "an attestation with no SIP value (an iPhone) passes"   200 "$ACME_STATUS"
posture 'OS=26.1 SIP=0'
chk "a Mac on 26.1 with SIP on passes"                      200 "$ACME_STATUS"

echo "=== every refusal is in the server log ==="
chk "the log names badAttestationStatement" yes "$(grep -q 'refused 400 badAttestationStatement' srv.log && echo yes || echo no)"
chk "the log records the verified device" yes "$(grep -q 'device attestation verified' srv.log && echo yes || echo no)"
chk "no ticket value reaches the log" "" "$(for t in "$T_BADNONCE" "$T_ROGUE" "$T_GOOD" "$T_NEXT" "$T_AGAIN"; do grep -l "$t" srv.log; done)"

echo
echo "=== ACME DEVICE ATTEST: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ] || echo "RESULT: FAIL"
[ "$fail" -eq 0 ]
