#!/usr/bin/env bash
# MS-XCEP / MS-WSTEP best-effort validation with curl (NOT Windows-proven, but
# confirms the SOAP parses, authenticates, issues, and returns well-formed XML):
#   /msxcep  GetPolicies            -> GetPoliciesResponse with template names
#   /mswstep RequestSecurityToken   -> issued cert (correct creds)
#            wrong password         -> rejected
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/ms_helpers.sh"
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
W="$(mktemp -d)"; cd "$W"; PORT=18446
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=MS CA" 3650
cp ca.pem root.pem
# MS-XCEP/WSTEP is HTTPS-only (Windows enrollment clients require TLS).
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout ms.key -out ms.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup ms_smoke
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
seed_web_user tester s3cret-ms requester

cat > bootstrap.conf <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
ROOT_CA_PEM=$W/root.pem
MS_CERT=$W/ms.pem
MS_KEY=$W/ms.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
MS_BIND=127.0.0.1
MS_PORT=$PORT
XCEP_PATH=/msxcep
WSTEP_PATH=/mswstep
CERT_VALIDITY_DAYS=365
# info, not err: the CMC-vs-PKCS#10 assertions below read the request line the server
# logs at info. At err they would grep an empty log and fail no matter what the code did.
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-ms" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-ms died:"; cat srv.log; exit 1; fi

echo "=== MS-XCEP GetPolicies ==="
XCEP_REQ='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"><client><lastUpdate xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/><preferredLanguage xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/></client></GetPolicies></s:Body></s:Envelope>'
XR=$(curl -sk -u tester:s3cret-ms -H "Content-Type: application/soap+xml; charset=utf-8" --data "$XCEP_REQ" "https://127.0.0.1:$PORT/msxcep/ca-global")
echo "$XR" | grep -q "GetPoliciesResponse" && a=yes || a=no
chk "GetPoliciesResponse returned" yes "$a"
echo "$XR" | grep -q "GenericUser" && b=yes || b=no
chk "template names present (GenericUser)" yes "$b"

# ── how long the client is told to cache this policy ────────────────────────────────
#
# ⚠️ THIS NUMBER DECIDES WHETHER A TEMPLATE CHANGE CAN BE TESTED AT ALL, which is why it
# is asserted rather than left as a detail of the XML. A Windows client caches the
# enrolment policy for nextUpdateHours and will not re-read it before then, so with the
# old hardcoded 24 a template edit was invisible to a real client for up to a day —
# and INVISIBLE IS THE KIND WORD FOR IT. Two failure modes were measured on the lab
# client, and the second is the dangerous one:
#
#   - GenericComputer: the client never sends a CSR and reports "A certificate request
#     could not be created. Access denied" — a loud failure against a stale template.
#   - Email: the client enrols SUCCESSFULLY against the stale definition and is issued a
#     certificate with the wrong subject. Nothing anywhere reports an error.
#
# A whole afternoon was spent re-rolling the image against a client that had stopped
# asking. MS_XCEP_NEXT_UPDATE_HOURS exists so a template can be iterated on; 0 disables
# caching while developing one.
chk "the policy tells the client how long to cache it (default 24)" yes \
    "$(echo "$XR" | grep -q '<nextUpdateHours>24</nextUpdateHours>' && echo yes || echo no)"

echo "=== the built-in templates offer a provider a SILENT enrolment can use ==="
# ⚠️ A LEGACY CSP CANNOT ACQUIRE A SILENT CONTEXT, and silent is the normal case:
# autoenrolment, scheduled tasks and anything running as a service have no desktop to
# prompt on. Measured with the real Windows client against the old default:
#
#     certreq -q -enroll -machine ...
#       -> Provider could not perform the action since the context was acquired as silent.
#          0x80090022 (NTE_SILENT_CONTEXT)
#
# cryptoProviders is a LIST and the client takes the first it can use, so the assertion is
# about ORDER, not mere presence: a KSP listed after the legacy CSP would still be chosen
# second and change nothing.
FIRSTP=$(printf '%s' "$XR" | grep -oE '<provider>[^<]*' | head -1 | sed 's/.*>//')
chk "the first provider offered is a Key Storage Provider" yes \
    "$(printf '%s' "$FIRSTP" | grep -qi 'Key Storage Provider' && echo yes || echo no)"
# ⚠️ AND NO LEGACY CSP BEHIND IT, because the SCHEMA decides which providers Windows will
# consider at all: schema 1 and 2 are CryptoAPI and allow only legacy CSPs, a Key Storage
# Provider requires schema 3. The built-ins were briefly a KSP on a schema-1 template --
# two thirds of a CNG template -- which is not a combination Windows accepts. They are
# schema 3 now, and on a schema-3 template the legacy entry is unreachable: a client too
# old for CNG cannot read the template at all, so keeping it only made the set look
# self-contradictory.
chk "  and NO legacy CSP is offered beside it" no \
    "$(printf '%s' "$XR" | grep -qi 'Enhanced RSA and AES' && echo yes || echo no)"
chk "  and the template declares schema 3, which is what allows a KSP" 3 \
    "$(printf '%s' "$XR" | grep -oE '<policySchema>[0-9]+' | head -1 | sed 's/.*>//')"
# A template naming a KSP and then claiming AT_KEYEXCHANGE describes two different key
# stores at once; 0 is the CNG spelling.
chk "  and keySpec is the CNG spelling, not AT_KEYEXCHANGE" 0 \
    "$(printf '%s' "$XR" | grep -oE '<keySpec>[0-9]+' | head -1 | sed 's/.*>//')"
# XCEP recorded auth_fail and nothing else, so the trail could answer "who was turned
# away" but not "who successfully retrieved enrolment policy, and how did they
# authenticate?" — which is the one that establishes trust and the one an incident review
# needs. It also made the reporter read the server's silence as a routing failure.
chk "a successful XCEP auth is audited" 1 \
    "$(pg_exec "SELECT count(*) FROM audit_log
                 WHERE action='auth_ok' AND actor='tester'
                   AND detail LIKE '%protocol=MS-XCEP%';" | tr -d ' ')"
chk "  it records HOW they authenticated" 1 \
    "$(pg_exec "SELECT count(*) FROM audit_log
                 WHERE action='auth_ok' AND actor='tester' AND detail LIKE '%method=%';" | tr -d ' ')"
chk "  and which CA's policy they read" 1 \
    "$(pg_exec "SELECT count(*) FROM audit_log
                 WHERE action='auth_ok' AND actor='tester' AND detail LIKE '%ca=ca-global%';" | tr -d ' ')"
# ⚠️ The failure path must still be audited — a change that recorded successes by
# replacing the failure call would satisfy everything above and lose more than it gained.
curl -sk -o /dev/null -u tester:WRONGPASS -H "Content-Type: application/soap+xml; charset=utf-8" \
     --data "$XCEP_REQ" "https://127.0.0.1:$PORT/msxcep/ca-global" || true
chk "  and a REFUSED one is still audited as a failure" 1 \
    "$(pg_exec "SELECT count(*) FROM audit_log
                 WHERE action='auth_fail' AND detail LIKE '%protocol=MS-XCEP%';" | tr -d ' ')"

# WS-Trust enrollment helper: build an RST with the CSR + UsernameToken
wstep() { # username password csr_b64  -> raw response
    local body='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><s:Header><wsse:Security><wsse:UsernameToken><wsse:Username>'"$1"'</wsse:Username><wsse:Password>'"$2"'</wsse:Password></wsse:UsernameToken></wsse:Security></s:Header><s:Body><wst:RequestSecurityToken><wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType><wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10">'"$3"'</wsse:BinarySecurityToken></wst:RequestSecurityToken></s:Body></s:Envelope>'
    curl -sk -H "Content-Type: application/soap+xml; charset=utf-8" --data "$body" "https://127.0.0.1:$PORT/mswstep/ca-global"
}

# Name the template, like a real client. `requester` may use three of them, so a
# request naming none is ambiguous and is now refused — see ms_template_policy.sh.
ms_csr ms.internal GenericUser c.key c.csr
CSR_B64=$("$OSSL" req -in c.csr -outform DER | "$OSSL" base64 -A)

echo "=== MS-WSTEP enrollment (correct creds) ==="
# ⚠️ Sampled BEFORE the enrolment, so it is strictly earlier than the issuing
# instant. The assertion below needs that ordering and nothing else — no date(1)
# arithmetic, which differs between BSD and GNU and would be its own bug.
T0_ISO=$(date -u +'%Y-%m-%d %H:%M:%S')
RESP=$(wstep tester s3cret-ms "$CSR_B64")
# The RSTR carries two BinarySecurityTokens (PKCS7 chain, then the issued X509v3
# cert inside RequestedSecurityToken). Isolate RequestedSecurityToken first, then
# grab the base64 body (busybox grep has no -P/\K).
ISSUED=$(echo "$RESP" | sed 's/.*<wst:RequestedSecurityToken>//' | grep -o 'base64binary">[^<]*' | head -1 | sed 's/.*base64binary">//')
if [ -n "$ISSUED" ]; then echo "$ISSUED" | "$OSSL" base64 -d -A > issued.der 2>/dev/null; fi
# CN only — owner/role ride in a Subject Directory Attributes extension,
# not the subject DN.
SUBJ=$("$OSSL" x509 -in issued.der -inform DER -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')
chk "issued cert subject CN = ms.internal" "ms.internal" "${SUBJ:-none}"
ISS=$("$OSSL" x509 -in issued.der -inform DER -noout -issuer 2>/dev/null | sed 's/.*CN *= *//')
chk "issued by MS CA" "MS CA" "${ISS:-none}"
# Audit producer: WSTEP issuance must write a cert_issued row.
AUD=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='cert_issued' AND detail LIKE '%MS-WSTEP%';")
chk "WSTEP issuance audited (cert_issued)" 1 "$AUD"

# ⚠️ notBefore MUST be backdated, or the client rejects its own new certificate.
# A certificate stamped with the issuing instant is "not yet valid" on any client whose
# clock trails ours, and the client checks it milliseconds later — so the bad window is
# exactly the window of first use. The lab's Windows box measured 1.75s behind the DC
# and `certreq` answered CERT_E_EXPIRED (0x800B0101), "not within its validity period
# when verifying against the current system clock", for a certificate whose notAfter was
# two years out. CryptoAPI returns that code for BOTH ends of the window.
#
# Compared as zero-padded ISO strings, so this is a plain lexical test with no timezone
# or date-dialect arithmetic anywhere. notBefore must be strictly EARLIER than a clock
# reading taken before we even sent the request; unbackdated, it is necessarily later.
NB=$("$OSSL" x509 -in issued.der -inform DER -noout -startdate 2>/dev/null | sed 's/^notBefore=//' | ossl_date_iso)
# Precondition: without this an empty NB would satisfy "NB < T0_ISO" and the assertion
# would pass while decoding nothing at all.
chk "notBefore decoded from the issued cert" yes \
    "$([ -n "$NB" ] && echo yes || echo no)"
chk "notBefore is backdated (before the pre-request clock reading $T0_ISO)" yes \
    "$([ -n "$NB" ] && [ "$NB" \< "$T0_ISO" ] && echo yes || echo no)"

echo "=== MS-WSTEP carries the certificate-template extension ==="
# A real Windows client puts szOID_ENROLL_CERTTYPE_EXTENSION (1.3.6.1.4.1.311.20.2,
# the template name as a BMPString) in its CSR; the issued cert must keep it so it
# retains its template identity. Verified end-to-end against the Windows enrollment
# client; this locks the behaviour with a synthetic CSR carrying the same ext.
cat > tmpl.cnf <<EOF
[req]
distinguished_name = dn
req_extensions = ext
prompt = no
[dn]
CN = tmpl.internal
[ext]
1.3.6.1.4.1.311.20.2 = ASN1:BMP:GenericUser
EOF
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout t.key -out t.csr -config tmpl.cnf >/dev/null 2>&1
TCSR_B64=$("$OSSL" req -in t.csr -outform DER | "$OSSL" base64 -A)
TRESP=$(wstep tester s3cret-ms "$TCSR_B64")
TISSUED=$(echo "$TRESP" | sed 's/.*<wst:RequestedSecurityToken>//' | grep -o 'base64binary">[^<]*' | head -1 | sed 's/.*base64binary">//')
echo "$TISSUED" | "$OSSL" base64 -d -A > tissued.der 2>/dev/null
chk "issued cert keeps the template extension (1.3.6.1.4.1.311.20.2)" yes \
    "$("$OSSL" x509 -in tissued.der -inform DER -noout -text 2>/dev/null | grep -q '1.3.6.1.4.1.311.20.2' && echo yes || echo no)"
# The value is a BMPString (UTF-16BE), so openssl -text prints it byte-interleaved
# ("...G.e.n.e.r.i.c.U.s.e.r"); strip the non-letters before matching.
chk "template name value survives (GenericUser)" yes \
    "$("$OSSL" x509 -in tissued.der -inform DER -noout -text 2>/dev/null | grep -A1 '1.3.6.1.4.1.311.20.2' | tr -cd 'A-Za-z' | grep -qi 'GenericUser' && echo yes || echo no)"

echo "=== MS-WSTEP accepts a CMC full PKI request, which is what Windows sends ==="
# ⚠️ THIS IS THE SHAPE A REAL WINDOWS CLIENT SUBMITS, and until it was added nothing here
# ever sent one. A client enrolling through an XCEP policy wraps the PKCS#10 in a CMC full
# PKI request (RFC 5272) — a CMS SignedData whose encapsulated content is id-cct-PKIData —
# and handle_wstep base64-decoded the token and gave the bytes straight to parse_csr(). So
# every genuine Windows enrolment failed with "CSR is not valid PEM or DER: ... wrong tag",
# while this suite went green on the bare PKCS#10 that no Windows client sends. Measured
# against a domain-joined Server 2022 client; see the Windows enrolment ticket.
#
# The structure is built by hand rather than with `openssl asn1parse -genconf`, because the
# CertificationRequest has to be embedded as raw DER and genconf has no primitive that
# emits a blob verbatim — every wrapper it offers would add a tag we would then be testing.
hexlen() {   # <byte count> -> DER length octets, as hex
    if   [ "$1" -lt 128 ]; then printf '%02x' "$1"
    elif [ "$1" -lt 256 ]; then printf '81%02x' "$1"
    else                        printf '82%04x' "$1"; fi
}
ms_csr cmc.internal GenericUser cmc-leaf.key cmc-leaf.csr
"$OSSL" req -in cmc-leaf.csr -outform DER -out cmc-leaf.der
CSR_HEX=$(xxd -p -c 100000 cmc-leaf.der | tr -d '\n')
# TaggedCertificationRequest ::= SEQUENCE { bodyPartID INTEGER, certificationRequest }
# tagged [0] IMPLICIT, so the SEQUENCE tag is replaced by a constructed context-0 (0xa0).
TCR_BODY="020101${CSR_HEX}"
TCR="a0$(hexlen $(( ${#TCR_BODY} / 2 )))${TCR_BODY}"
REQSEQ="30$(hexlen $(( ${#TCR} / 2 )))${TCR}"
# PKIData ::= SEQUENCE { controlSequence, reqSequence, cmsSequence, otherMsgSequence }
PKI_BODY="3000${REQSEQ}30003000"
printf '%s' "30$(hexlen $(( ${#PKI_BODY} / 2 )))${PKI_BODY}" | xxd -r -p > pkidata.der
chk "the PKIData blob was built" yes "$([ -s pkidata.der ] && echo yes || echo no)"
# Any signer will do: the CMC signature is deliberately not verified — identity comes from
# the authenticated WSTEP session and proof of possession from the inner CSR's own
# self-signature, which parse_csr() checks. A self-signed throwaway is what a first
# enrolment uses anyway.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout cmc-signer.key -out cmc-signer.pem \
        -days 2 -subj "/CN=cmc-signer" >/dev/null 2>&1
"$OSSL" cms -sign -binary -nodetach -md sha256 -econtent_type 1.3.6.1.5.5.7.12.2 \
        -in pkidata.der -inform DER -signer cmc-signer.pem -inkey cmc-signer.key \
        -outform DER -out cmc.der >/dev/null 2>&1
chk "  and wrapped as a CMS with eContentType id-cct-PKIData" yes \
    "$([ -s cmc.der ] && "$OSSL" cms -cmsout -inform DER -in cmc.der -print 2>/dev/null \
       | grep -q '1.3.6.1.5.5.7.12.2' && echo yes || echo no)"

CMC_B64=$("$OSSL" base64 -A < cmc.der)
CRESP=$(wstep tester s3cret-ms "$CMC_B64")
CISSUED=$(echo "$CRESP" | sed 's/.*<wst:RequestedSecurityToken>//' | grep -o 'base64binary">[^<]*' | head -1 | sed 's/.*base64binary">//')
[ -n "$CISSUED" ] && echo "$CISSUED" | "$OSSL" base64 -d -A > cmcissued.der 2>/dev/null
chk "a CMC request is issued a certificate" yes "$([ -s cmcissued.der ] && echo yes || echo no)"
# ⚠️ THE SUBJECT MUST COME FROM THE INNER CSR, not from the CMS signer. Getting the
# unwrap subtly wrong — landing on the signer's certificate instead of the TaggedRequest —
# would still produce a certificate, and only the name says which one was read.
chk "  and it certifies the INNER CSR's subject, not the CMS signer" yes \
    "$("$OSSL" x509 -in cmcissued.der -inform DER -noout -subject 2>/dev/null \
       | grep -q 'cmc.internal' && echo yes || echo no)"
chk "  the server recorded it as a CMC request" yes \
    "$(grep -q 'WSTEP: CMC request' srv.log && echo yes || echo no)"
# Anti-vacuity: the bare PKCS#10 path must still be taken for a bare PKCS#10, or the
# detection is simply unwrapping everything.
chk "  and a bare PKCS#10 is still read as one" yes \
    "$(grep -q 'WSTEP: PKCS#10 request' srv.log && echo yes || echo no)"

echo "=== MS-WSTEP wrong password (WS-Trust soap:Fault, not a 401 Basic challenge) ==="
RESP2=$(wstep tester WRONGPW "$CSR_B64")
echo "$RESP2" | grep -qi "BinarySecurityToken" && c=issued || c=rejected
chk "wrong password -> no cert" rejected "$c"
# A bad WS-Security UsernameToken is a WS-Trust error → soap:Fault with a
# wsse:FailedAuthentication subcode, so the WCF client reports an auth failure
# rather than "server requires basic auth".
chk "wrong password -> soap:Fault"          yes "$(echo "$RESP2" | grep -q ':Fault' && echo yes || echo no)"
chk "fault subcode = FailedAuthentication"  yes "$(echo "$RESP2" | grep -q 'FailedAuthentication' && echo yes || echo no)"
# Audit producer: the failed WSTEP auth must be logged.
AF=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='auth_fail' AND detail LIKE '%MS-WSTEP%';")
chk "WSTEP auth failure audited" 1 "$AF"

echo "=== MS-XCEP authenticates, like every other MS endpoint ==="
# MS-XCEP is normally authenticated in Microsoft's own deployments, and there is no
# reason for this implementation not to follow that.
#
# GetPolicies used to read no credential at all: the POLICY endpoint was wide open while
# WSTEP, in the same binary and one lambda away, ran the full Kerberos → Basic →
# UsernameToken ladder. Windows fronts XCEP with IIS auth, so this follows it.
XU="https://127.0.0.1:$PORT/msxcep/ca-global"
xcode(){ curl -sk -o /dev/null -w '%{http_code}' "$@" \
         -H "Content-Type: application/soap+xml; charset=utf-8" --data "$XCEP_REQ" "$XU"; }
chk "anonymous GetPolicies -> 401" 401 "$(xcode)"
chk "  a wrong password -> 401"    401 "$(xcode -u tester:wrongpw)"
chk "  the right credential -> 200" 200 "$(xcode -u tester:s3cret-ms)"
# ⚠️ 401 WITH A CHALLENGE, not a bare refusal and not a soap:Fault. XCEP is the FIRST
# call a Windows autoenrolment client makes, before it holds any credential context: it
# expects to be challenged and to retry. A fault, or a 401 with no WWW-Authenticate, ends
# the flow instead of starting it — which is the one way this change could break a real
# domain client while every status-code assertion above still passed.
HDRS=$(curl -sk -D - -o /dev/null -H "Content-Type: application/soap+xml; charset=utf-8" \
       --data "$XCEP_REQ" "$XU")
chk "  the refusal CHALLENGES rather than just refusing" yes \
    "$(echo "$HDRS" | grep -qi '^WWW-Authenticate: *Basic' && echo yes || echo no)"
# And it must not leak the policy in the body it refuses with.
BODY=$(curl -sk -H "Content-Type: application/soap+xml; charset=utf-8" --data "$XCEP_REQ" "$XU")
chk "  and returns no policy to an anonymous caller" no \
    "$(echo "$BODY" | grep -q 'GetPoliciesResponse' && echo yes || echo no)"
XAF=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='auth_fail' AND detail LIKE '%MS-XCEP%';")
chk "  the refusal is audited" yes "$([ "${XAF:-0}" -ge 1 ] && echo yes || echo no)"
# ⚠️ AND IT MUST NOT BE A CA-ID ORACLE. My first version resolved the CA BEFORE
# authenticating, so an anonymous POST answered 401 for a real id and 404 for a made-up
# one — the status code alone enumerated every CA on the deployment. Measured that way on
# all three DCs before it was fixed. Both must now look identical to a caller with no
# credential; the difference may only appear once one is accepted.
XBOGUS="https://127.0.0.1:$PORT/msxcep/no-such-ca-anywhere"
anon_code(){ curl -sk -o /dev/null -w '%{http_code}' \
             -H "Content-Type: application/soap+xml; charset=utf-8" --data "$XCEP_REQ" "$1"; }
chk "anonymous cannot tell a real CA id from a made-up one" "$(anon_code "$XU")" \
    "$(anon_code "$XBOGUS")"
chk "  and once authenticated the made-up id is a 404"  404 \
    "$(curl -sk -o /dev/null -w '%{http_code}' -u tester:s3cret-ms \
       -H "Content-Type: application/soap+xml; charset=utf-8" --data "$XCEP_REQ" "$XBOGUS")"

# ── a DB-DEFINED template must still name its algorithms ───────────────────────────────
# ⚠️ AN ABSENT COLUMN MUST NOT ERASE A DEFAULT. pk_oid/pk_name/hash_oid/hash_name are
# nullable, and the DB reader assigned them unconditionally from `coalesce(col,'')` -- so
# every template defined in the DATABASE, which is the supported way to customise them,
# advertised `<oID><value></value>` for its algorithms while `algorithmOIDReference`
# pointed straight at it. A Windows client rejects that template with
# ERROR_INVALID_PARAMETER; the built-in templates were fine, so it only appeared once
# somebody used the feature. The text loader had guarded this all along -- two readers
# filling one struct and only one preserving the defaults.
#
# ⚠️ LAST IN THE FILE, and that is not tidiness. Seeding ANY row switches the catalogue
# from the built-in defaults to DB-only, so GenericUser disappears and every section
# after it fails on a template that no longer exists. Measured: 13 failures when this
# sat in the middle.
#
# Seeded with the MINIMAL column set on purpose: naming pk_oid here would configure the
# very thing under test away.
pg_exec "INSERT INTO ms_templates(name,oid,min_key_size,key_usage,validity_days)
         VALUES('DbDefined','1.3.6.1.4.1.99999.42.1',2048,40960,365)
         ON CONFLICT (name) DO NOTHING;" >/dev/null
# ⚠️ AND GRANT IT. The policy lists only templates the CALLER may use, so without this the
# document comes back with no templates at all and every assertion below reads as "the DB
# template did not load" when the real answer is "you were not allowed to see it".
pg_exec "INSERT INTO role_permissions(role,permission,scope)
         VALUES('requester','template:use','DbDefined') ON CONFLICT DO NOTHING;" >/dev/null
# ⚠️ ITS OWN PORT, NOT A RESTART. Killing the suite's server and rebinding the same port
# raced: two listeners ended up on it, curl reached the SURVIVING one -- still serving
# built-ins -- and the assertion read that as "the DB template did not load". Measured:
# `lsof -iTCP:$PORT` showed 2. A second instance on a free port answers the same question
# with nothing to race against.
PORT2=$((PORT + 7))
sed "s/^MS_PORT=.*/MS_PORT=$PORT2/" bootstrap.conf > pki-db.conf
grep -q "^MS_PORT=$PORT2" pki-db.conf || echo "MS_PORT=$PORT2" >> pki-db.conf
"$ROOT/build/fastpki-ms" --config pki-db.conf >srv-db.log 2>&1 & P2=$!
# Wait for it to ANSWER rather than sleeping a guess: a fixed sleep after a server start
# is how this suite would become load-dependent.
for _ in $(seq 1 40); do
    curl -sk --max-time 1 "https://127.0.0.1:$PORT2/msxcep/ca-global" >/dev/null 2>&1 && break
    kill -0 $P2 2>/dev/null || break
    sleep 0.25
done
kill -0 $P2 2>/dev/null || { echo "         second instance died: $(tail -3 srv-db.log 2>/dev/null | tr '\n' ' ')"; }
XR2=$(curl -sk -u tester:s3cret-ms -H "Content-Type: application/soap+xml; charset=utf-8" \
        --data "$XCEP_REQ" "https://127.0.0.1:$PORT2/msxcep/ca-global")
chk "PRECONDITION: the DB template reached the policy" yes \
    "$(printf '%s' "$XR2" | grep -q 'DbDefined' && echo yes || echo no)"
echo "         rows in ms_templates: $(pg_exec "SELECT count(*) FROM ms_templates;" | tr -d ' ') names=$(pg_exec "SELECT string_agg(name||':'||enabled,',') FROM ms_templates;" | tr -d ' ')"
echo "         policy bytes=${#XR2} commonNames=$(printf '%s' "$XR2" | grep -oE '<commonName>[^<]*' | sed 's/.*>//' | tr '\n' ',')"
echo "         server said: $(tail -3 srv-db.log 2>/dev/null | tr '\n' ' | ')"
printf '%s' "$XR2" | grep -q 'GetPoliciesResponse' || \
    echo "         no GetPoliciesResponse; server said: $(tail -2 srv-db.log 2>/dev/null | tr '\n' ' ')"
# ⚠️ THE EMPTINESS CHECK BELOW IS VACUOUS ON AN EMPTY BODY -- grep finds no
# `<value></value>` in nothing at all and reports success. Establish there IS a document
# first, or a dead server reads as a clean policy.
chk "PRECONDITION: a policy document came back" yes \
    "$(printf '%s' "$XR2" | grep -q 'GetPoliciesResponse' && echo yes || echo no)"
chk "no OID in the policy has an empty value" no \
    "$(printf '%s' "$XR2" | grep -q '<value></value>' && echo yes || echo no)"
chk "  the public-key algorithm is still named" yes \
    "$(printf '%s' "$XR2" | grep -q '1.2.840.113549.1.1.1' && echo yes || echo no)"
chk "  and so is the hash" yes \
    "$(printf '%s' "$XR2" | grep -q '2.16.840.1.101.3.4.2.1' && echo yes || echo no)"
kill $P2 2>/dev/null; wait $P2 2>/dev/null

# ── the SUCCESSFUL authentication is audited, not just the failures ─────────────────

echo
echo "=== MS SMOKE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
