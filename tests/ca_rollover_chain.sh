#!/usr/bin/env bash
# What each protocol actually HANDS A CLIENT while a root is renewed with a new key.
#
# ── Why this suite exists, stated plainly ────────────────────────────────────────
#
# `ca_rekey.sh` proves the renewal itself — the new self-signed root, the bridge (new key
# under the old root) and the cross (old key under the new root), each verifying against the
# right anchor. It does NOT prove that a client ever receives them, because it runs only
# fastpki-web, which has no enrolment
# listener. EST's chain was proven on the lab against a real rollover; ACME, CMP and MS
# were wired to the same `chain_ders` and shipped on the strength of "reads the same
# field", with the gap written down rather than closed. This closes it for the three
# protocols whose chain is decodable with shell + openssl:
#
#   EST   GET /cacerts                -> PKCS#7, straight out of resolve_ca_instance
#   CMP   ir response extraCerts      -> `openssl cmp -extracertsout`
#   MS    WSTEP RSTR PKCS#7 token     -> the CMS the WCF client builds its chain from
#
#   ACME  the order's certificate URL   -> POST-as-GET, so fetching it needs JWS signing
#
# ACME was excluded when this was written, for exactly that reason. tests/acme_jws.sh signs
# it now (§3e), so all four are covered and the exclusion note is gone rather than left to
# read as still true.
#
# ── The three states, and why the third one matters most ─────────────────────────
#
#   1. one live certificate          -> every protocol sends exactly ONE
#   2. after renewal, three live     -> every protocol sends ALL of them, no restart
#      (old root, bridge, renewed root)
#   3. the old root expires, and the -> every protocol is back to ONE, no restart
#      bridge with it
#
# State 1 is the control: without it, "sends 3" could just as well be a server that
# always sends everything it can find.
#
# State 3 is the one that found a real bug in the design of this change. The material
# cache invalidates on the SIGNING certificate's serial, and at the end of a rollover the
# signer does not change — the old certificate simply stops being live. A cache keyed on
# the signer alone would have gone on handing out an expired CA certificate until the
# process was restarted. That is why CaMaterialCache::Entry carries `chain_ref` (every
# live serial) as well as `cert_ref`, and section 4 is what holds it honest.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/ms_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
source "$ROOT/tests/acme_jws.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
# Only adopt the system openssl.cnf where it really is one. On macOS this path is a stub
# that defines no providers, and exporting it breaks every pkcs11 load (§3d).
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"
WEBP=18470; ESTP=18471; MSP=18472; CMPP=18473; ACMEP=18474; DNSP=15356
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

CA_CN="Rollover Chain CA"
pg_setup ca_rollover_chain
PW=; PE=; PM=; PC=; PA=
trap 'pg_cleanup; kill $PW $PE $PM $PC $PA 2>/dev/null' EXIT

ca_in_token ca.pem "/CN=$CA_CN" 3650 rollchain || { echo "SKIP: no token"; exit 0; }
OLD_URI="$CA_KEY_URI"
# The RA credential must come AFTER ca_in_token (which sets CA_KEY_URI) and must
# be tagged for THIS suite's CA id, which is "roll" — not the "ca" the default assumes.
# Two things the mechanical fix got wrong here: the ordering and the id.
cmp_ra_issue ca.pem "$OLD_URI" \
    || { echo "SKIP: could not provision the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
cmp_ra_publish cmp-ra-roll
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout srv.key -out srv.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

# ⚠️ `test` IS HERE FOR THE RA CREDENTIAL, not for the leaves. cmp_ra_issue gives the RA
# certificate CN=cmp-ra.test, and a rekey reissues that credential by copying its subject
# forward. Issuance policy still applies on that path, so without `test` approved the cascade
# fails with "CN 'cmp-ra.test' is not in the approved domains" and the credential silently
# stays on the old key. The shipped credentials carry names like "FastPKI CMP", which are not
# domain-shaped and never meet this check — which is why only a fixture runs into it.
printf "internal\ntest\n" > domains.txt
seed_domains $W/domains.txt
seed_web_user boss bosspw admin

cat > bootstrap.conf <<EOF
PKI_DNS=localhost
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$OLD_URI
SIGNING_CA_ID=roll
AUTH_BACKEND=local
WEB_BIND=127.0.0.1
WEB_PORT=$WEBP
WEB_ALLOW_REVOKE=true
EST_CERT=$W/srv.pem
EST_KEY=$W/srv.key
EST_BIND=127.0.0.1
EST_PORT=$ESTP
MS_CERT=$W/srv.pem
MS_KEY=$W/srv.key
MS_BIND=127.0.0.1
MS_PORT=$MSP
XCEP_PATH=/msxcep
WSTEP_PATH=/mswstep
CMP_BIND=127.0.0.1
CMP_PORT=$CMPP
CMP_PATH=/cmp
CMP_EXTRACERTS_CA=true
BASE_URL=https://localhost:$ACMEP
ACME_CERT=$W/srv.pem
ACME_KEY=$W/srv.key
ACME_BIND=127.0.0.1
ACME_PORT=$ACMEP
ACME_BASE_PATH=/acme
ACME_DNS_RESOLVER=127.0.0.1:$DNSP
# ⚠️ Removed ACME_EAB_REQUIRED, which this suite used to pin false. Section 3b tests
# what ACME hands a client mid-rollover, not who is allowed to ask — but the way to keep
# testing that is to REGISTER PROPERLY, not to switch the requirement off. acme_dns01_order
# provisions a kid + HMAC and signs the binding, so the four 3b assertions now run against
# the posture FastPKI actually ships. This was the ONE suite outside tests/acme_*.sh that
# drives a real account registration, and the nine pinned alongside it missed it.
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf
cmp_seed_pbm ca-rollover-chain

"$ROOT/build/fastpki-web" --config bootstrap.conf >web.log 2>&1 & PW=$!
"$ROOT/build/fastpki-est" --config bootstrap.conf >est.log 2>&1 & PE=$!
"$ROOT/build/fastpki-ms"  --config bootstrap.conf >ms.log  2>&1 & PM=$!
cmp_ra_conf_lines >> bootstrap.conf   # CMP_RA_CERT_ID_PREFIX + CMP_RA_KEY
"$ROOT/build/fastpki-cmp" --config bootstrap.conf >cmp.log 2>&1 & PC=$!
"$ROOT/build/fastpki-acme" --config bootstrap.conf >acme.log 2>&1 & PA=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" CMP_PORT "$PC" || true
for n in web:$PW est:$PE ms:$PM cmp:$PC acme:$PA; do
    kill -0 "${n#*:}" 2>/dev/null || { echo "fastpki-${n%%:*} died:"; cat "${n%%:*}.log"; exit 1; }
done
curl -s -c cj -d 'username=boss&password=bosspw' "http://127.0.0.1:$WEBP/api/login" >/dev/null

# ── decoding helpers: count and identify the CA certs in a bundle ────────────────
# Split a PEM stream into one file per certificate, then ask openssl about each. A
# `grep -c BEGIN CERTIFICATE` would count the leaf too, and counting "subject=" lines out
# of `-print_certs` cannot tell two distinct CA certs from the same one sent twice — the
# whole question here. Serials answer it.
ca_serials() { # <pem stream file> -> the CA's serials, sorted, space separated
    rm -rf parts; mkdir -p parts
    awk -v d=parts 'BEGIN{n=0} /BEGIN CERTIFICATE/{n++} {if(n>0) print > (d"/"n".pem")}' "$1" 2>/dev/null
    local out=""
    for f in parts/*.pem; do
        [ -e "$f" ] || continue
        "$OSSL" x509 -in "$f" -noout -subject 2>/dev/null | grep -q "CN *= *$CA_CN" || continue
        out="$out $("$OSSL" x509 -in "$f" -noout -serial 2>/dev/null | sed 's/serial=//' \
                    | tr 'A-F' 'a-f' | sed 's/^0*//')"
    done
    echo $(printf '%s\n' $out | sort -u)
}
n_of() { set -- $1; echo $#; }

est_chain() {  # -> serials of the CA certs in EST /cacerts
    curl -sk "https://127.0.0.1:$ESTP/.well-known/est/roll/cacerts" \
        | "$OSSL" base64 -d -A 2>/dev/null \
        | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null > est.pem
    ca_serials est.pem
}
cmp_chain() { # <n> <anchor.pem> [extra openssl args] -> the CA serials in extraCerts
    local n="$1" anchor="$2"; shift 2
    rm -f cmpx.pem
    # -trusted, not -srvcert. -trusted PINS -expect_sender "/CN=cmp-ra.test" one exact server certificate, which cannot
    # survive a rekey by construction and would make this suite prove nothing about the
    # rollover. -trusted makes the client do what a relying party actually does: take an
    # anchor and try to build a path to the signer out of what the server sent. So a call
    # that succeeds here has proven the extraCerts chain is USABLE, not merely present.
    "$OSSL" cmp -cmd ir -server "http://127.0.0.1:$CMPP/cmp/roll" -recipient "/CN=$CA_CN" \
        -trusted "$anchor" -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF" -keep_alive 0 "$@" \
        -newkey scratch.key -subject "/CN=cmp$n.internal" \
        -certout "cmp$n.pem" -extracertsout cmpx.pem >/dev/null 2>&1
    ca_serials cmpx.pem
}
ms_chain() {  # -> serials of the CA certs in the WSTEP RSTR's PKCS#7 token
    # WSTEP resolves a TEMPLATE now, so name one like a real client. (The console
    # request further down is a different route and stays a plain CSR.)
    ms_csr "ms$1.internal" GenericUser "ms$1.key" "ms$1.csr"
    local b64; b64=$("$OSSL" req -in "ms$1.csr" -outform DER 2>/dev/null | "$OSSL" base64 -A)
    local body='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><s:Header><wsse:Security><wsse:UsernameToken><wsse:Username>boss</wsse:Username><wsse:Password>bosspw</wsse:Password></wsse:UsernameToken></wsse:Security></s:Header><s:Body><wst:RequestSecurityToken><wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType><wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10">'"$b64"'</wsse:BinarySecurityToken></wst:RequestSecurityToken></s:Body></s:Envelope>'
    curl -sk -H "Host: localhost" -H "Content-Type: application/soap+xml; charset=utf-8" \
        -o "msr$1.xml" --data "$body" "https://127.0.0.1:$MSP/mswstep/roll" >/dev/null
    # The RSTR carries two base64 tokens — the PKCS#7 and the issued certificate. Pick
    # the one by its ValueType rather than by position: which comes first is an ordering
    # detail of build_wstep_response, and a test that silently starts decoding the leaf
    # would still "pass" every count in this file for the wrong reason.
    sed 's/.*#PKCS7"[^>]*>//; s#</wsse:BinarySecurityToken>.*##' "msr$1.xml" \
        | "$OSSL" base64 -d -A 2>/dev/null > "msp7$1.der"
    "$OSSL" pkcs7 -inform DER -in "msp7$1.der" -print_certs 2>/dev/null > "msp7$1.pem"
    ca_serials "msp7$1.pem"
}

OLD_SERIAL=$("$OSSL" x509 -in ca.pem -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')

# ACME needs JWS even to FETCH: RFC 8555's certificate URL is POST-as-GET, so a plain curl
# cannot download the chain. That is why this used to shell out to a Python driver.
# tests/acme_jws.sh signs it now, so every assertion below is shell over a real artifact
# (§3e) and the driver is gone.
acme_chain() {  # <domain> <out.pem> -> "ok" | "skip" | "no"
    # §3e: was tests/acme_dns01.py, which existed here only because RFC 8555's certificate
    # URL is POST-as-GET and a shell suite could not sign the fetch. acme_jws.sh can, and
    # build/dnsstub answers the challenge lookup.
    [ -x "$ACME_DNSSTUB" ] || { echo skip; return; }
    acme_dns01_order "https://127.0.0.1:$ACMEP/acme/roll/directory" "$1" "$DNSP" "$2" \
        >"acme_$1.log" 2>&1 && echo ok || echo no
}

echo "=== 1. the control: one live certificate, so every protocol sends exactly one ==="
E1=$(est_chain); C1=$(cmp_chain 1 ca.pem); M1=$(ms_chain 1)
chk "EST cacerts sends 1"      1 "$(n_of "$E1")"
chk "  and it is the CA"       "$OLD_SERIAL" "$E1"
chk "CMP extraCerts sends 1"   1 "$(n_of "$C1")"
chk "  and it is the CA"       "$OLD_SERIAL" "$C1"
chk "MS PKCS#7 sends 1"        1 "$(n_of "$M1")"
chk "  and it is the CA"       "$OLD_SERIAL" "$M1"

echo "=== 2. renew the root with a new key through the console ==="
NEW_URI=$(hsm_new_key_uri rollchain-new)
RC=$(curl -s -o r.json -w '%{http_code}' -b cj -X POST \
        "http://127.0.0.1:$WEBP/api/ca-instances/roll/renew" \
        --data-urlencode "keyref=$NEW_URI" --data-urlencode 'key=rsa' \
        --data-urlencode 'bits=2048' --data-urlencode 'days=3650')
chk "renew -> 201" 201 "$RC"
NEW_SERIAL=$(sed -n 's/.*"serial":"\([^"]*\)".*/\1/p' r.json)
BRIDGE_SERIAL=$(sed -n 's/.*"bridgeSerial":"\([^"]*\)".*/\1/p' r.json)
chk "three CA rows are live now (old, bridge, renewed)" 3 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='roll' AND is_ca AND \"notAfter\" > $(date +%s);" | tr -d ' ')"
# The rekeyed certificate has to be as usable as the one it succeeds. It was not: the
# product's CA key-usage default omitted digitalSignature, so the new certificate could
# not protect a CMP response and section 3's CMP call failed with "missing key usage
# digitalsignature" — a CA that had worked over CMP for its whole life stopped the moment
# it was rekeyed. The KU default is fixed; this is what keeps it fixed.
pg_exec "SELECT '-----BEGIN CERTIFICATE-----'||chr(10)||
                rtrim(encode(cert,'base64'),chr(10))||chr(10)||
                '-----END CERTIFICATE-----' FROM certs WHERE serial='$NEW_SERIAL';" > rekeyed.pem

# ⚠️ A REKEY REISSUES THE RA CREDENTIAL BY ITSELF, and this asserts that it did.
#
# After a rekey the RA certificate is still signed by the OLD key, so a client that has moved
# its anchor to the rekeyed CA cannot build a path to the protection signer, and CMP goes dark
# for it with no error that says so. That is why the rekey handler cascades: with a new key it
# calls renew_service_certs_for_ca(force=true), which reissues the OCSP responder, CMP RA and
# SCEP RA under the new key and publishes each through publish_service_cert().
#
# ⚠️ THIS SUITE USED TO DO THAT REISSUE BY HAND — cmp_ra_issue to build a certificate with
# openssl, then cmp_ra_publish to INSERT a row — and called it "the operator step". That was
# wrong twice over. It is not a step an operator performs, because the cascade already ran; and
# cmp_ra_publish only ever INSERTs (its ON CONFLICT is on *serial*, which a fresh certificate
# never collides with), so it left a SECOND live row under this cert_id on top of the one the
# cascade had correctly published. The read below then had two rows to choose between and its
# answer depended on the ordering rather than on the product. That is a state the product never
# produces, and it made this assertion fail about one run in seven.
#
# Asked against the product now: the rekey response reports what the cascade did, and the row
# fastpki-cmp will actually pick has to verify under the REKEYED certificate. The selection is
# get_cert_by_cert_id's — cert_id + status=0, newest "notAfter", serial DESC as the tie-break —
# so this is the same certificate the server would protect a response with.
chk "the rekey reissued the service credentials itself" yes \
    "$(sed -n 's/.*"serviceCertsRenewed":\([0-9]*\).*/\1/p' r.json | grep -qE '^[1-9]' && echo yes || echo no)"
chk "  and none of them failed" 0 \
    "$(sed -n 's/.*"serviceCertsFailed":\([0-9]*\).*/\1/p' r.json)"
chk "  leaving ONE live row for the credential, as publish_service_cert guarantees" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='cmp-ra-roll' AND status=0;" | tr -d ' ')"
[ "$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='cmp-ra-roll' AND status=0;" | tr -d ' ')" = 1 ] || {
    echo "  --- live rows for cmp-ra-roll ---"
    pg_exec "SELECT serial||' status='||status||' nb='||\"notBefore\"||' cn='||coalesce(cn,'')
               FROM certs WHERE cert_id='cmp-ra-roll' ORDER BY \"notBefore\";"; }
# The cascade reports a count, and a count cannot be acted on. The reason is in the console's
# log, so print it here rather than leaving whoever reads a red line to go and find it.
sed -n 's/.*"serviceCertsFailed":\([0-9]*\).*/\1/p' r.json | grep -qE '^0$' || {
    echo "  --- what the re-key said about re-issuing the credentials ---"; grep -i "re-issu" web.log | tail -3; }
pg_exec "SELECT '-----BEGIN CERTIFICATE-----'||chr(10)||
                rtrim(encode(cert,'base64'),chr(10))||chr(10)||
                '-----END CERTIFICATE-----'
           FROM certs WHERE cert_id='cmp-ra-roll' AND status=0
          ORDER BY \"notAfter\" DESC, serial DESC LIMIT 1;" > ra-now.pem
# No -partial_chain: the renewed certificate is a self-signed root, a real anchor.
chk "the RA credential is reissued under the renewed root" yes \
    "$("$OSSL" verify -CAfile rekeyed.pem ra-now.pem >/dev/null 2>&1 \
       && echo yes || echo no)"
# INVERTED. A rekeyed CA must NOT carry digitalSignature any more — CMP protects
# with a dedicated RA credential, so the CA signs certificates and CRLs and nothing else.
# This asserted the old contract, which is exactly what slice 3 removed.
chk "the rekeyed cert carries keyCertSign+cRLSign only (no digitalSignature)" yes \
    "$("$OSSL" x509 -in rekeyed.pem -noout -text 2>/dev/null | grep -A1 'Key Usage' \
       | grep -q 'Digital Signature' && echo no || echo yes)"

echo "=== 3. mid-rollover: every protocol hands over ALL of them, without a restart ==="
# No process was restarted between section 1 and here. Each daemon re-reads the row per
# request and reloads only on a material change, so this also proves the renewal propagates
# to separate processes by itself — which is the only way it can, since nothing can push
# to them.
ALL=$(printf '%s\n' "$OLD_SERIAL" "$BRIDGE_SERIAL" "$NEW_SERIAL" | sort -u | tr '\n' ' ' | sed 's/ $//')
# The CMP client is anchored on the OLD root here on purpose: this is the relying party
# that has NOT installed the new root, and the one the bridge exists for. It can only
# succeed by chaining the new signer through the bridge to the old anchor, using the
# certificates the server put in extraCerts.
E2=$(est_chain); C2=$(cmp_chain 2 ca.pem); M2=$(ms_chain 2)
chk "EST cacerts sends 3"      3 "$(n_of "$E2")"
chk "  old, bridge AND new"    "$ALL" "$E2"
chk "CMP succeeds for a client anchored on the OLD root" yes \
    "$([ -s cmp2.pem ] && echo yes || echo no)"
chk "  and extraCerts carries the bridge" yes \
    "$(printf ' %s ' "$C2" | grep -q " $BRIDGE_SERIAL " && echo yes || echo no)"
chk "MS PKCS#7 sends 3"        3 "$(n_of "$M2")"
chk "  old, bridge AND new"    "$ALL" "$M2"

echo "=== 3b. ACME serves the rollover chain too ==="
# The gap flagged when ACME and CMP were wired on the strength of "reads the same
# field". CMP got its assertion in section 3; this is ACME's.
A2=$(acme_chain after-rekey.internal acme2.pem)
if [ "$A2" = skip ]; then
    echo "  [SKIP] build/dnsstub not built — the ACME chain cannot be asserted without a"
    echo "         DNS responder for the dns-01 challenge"
else
    # ⚠️ SHOW THE CLIENT LOG WHEN THE ORDER FAILS. Without this the leg reported four
    # red lines and `grep: acme2.pem: No such file or directory`, which says the file is
    # missing and nothing about why the order never produced it — the reason was a
    # newAccount refusal three steps earlier, invisible from here.
    # acme_dns01_order names the step it died on (acme_jws.sh:_acme_why), so the client
    # log is worth showing now. It was not before: every failure path exited in silence
    # and this leg printed four red lines and an empty file.
    [ "$A2" = ok ] || { echo "--- ACME client log:"; tail -20 acme_*.log;
                        echo "--- fastpki-acme:"; tail -10 acme.log; }
    chk "an ACME order completes mid-rollover" ok "$A2"
    chk "  and its chain carries all three live CA certs" 3 "$(n_of "$(ca_serials acme2.pem)")"
    chk "  old, bridge AND new"                  "$ALL" "$(ca_serials acme2.pem)"
    # The leaf must be there too — a "chain" that is only CA certs would satisfy a count.
    chk "  plus the issued leaf" yes \
        "$(grep -c 'BEGIN CERTIFICATE' acme2.pem | awk '{print ($1>=3)?"yes":"no"}')"
fi

echo "=== 4. the rollover ends: the expired certificate stops being served ==="
# Nothing signs differently here — the newest certificate is unchanged, so a cache keyed
# on the signer would never notice. Only the live SET changed.
# The bridge was cut to the old root's end date when it was signed, so it expires in the
# same moment; both are aged here, as the clock would.
pg_exec "UPDATE certs SET \"notAfter\" = $(( $(date +%s) - 60 )) WHERE serial IN ('$OLD_SERIAL','$BRIDGE_SERIAL');" >/dev/null
chk "one CA row is live again" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='roll' AND is_ca AND \"notAfter\" > $(date +%s);" | tr -d ' ')"
# Past the deadline the old anchor is expired, so the client that can still work is
# the one that has installed the renewed root — which is what the deadline means.
pg_exec "SELECT '-----BEGIN CERTIFICATE-----'||chr(10)||
                rtrim(encode(cert,'base64'),chr(10))||chr(10)||
                '-----END CERTIFICATE-----' FROM certs WHERE serial='$NEW_SERIAL';" > new.pem
# No -partial_chain: the renewed root is self-signed, so a client that installed it holds
# a real anchor and needs nothing that expired.
E3=$(est_chain); C3=$(cmp_chain 3 new.pem); M3=$(ms_chain 3)
chk "EST cacerts is back to 1"     1 "$(n_of "$E3")"
chk "  and it is the NEW one"      "$NEW_SERIAL" "$E3"
# ⚠️ CMP's extraCerts carries the RA CREDENTIAL now, not the CA — OpenSSL puts the
# protection signer there so a client can build RA -> CA. So this no longer tracks the CA
# rollover at all, and the EST/MS assertions above are the ones that still do.
#
# A real operational consequence, worth stating: a CA REKEY does not reissue the RA
# certificate. The RA stays chained to the OLD key until an operator issues a new one, so
# a client that has moved its anchor to the new CA cannot validate the protection. Raised
# separately rather than papered over here.
# These two are UNCHANGED by the RA credential, and that is the interesting part. Under RA mode
# extraCerts carries the RA *and its chain*, so ca_serials() still finds exactly one CA
# certificate — and after the reissue above it is the rekeyed one.
#
# ⚠️ They did fail while I was building this, and neither the assertion nor the model was
# wrong: the RA had simply not been reissued, so the client could not build a path and got
# an empty extraCerts. The fix was the operator step, not the expectation. Do not "correct"
# these to 0 — I nearly did.
chk "CMP extraCerts is back to 1"  1 "$(n_of "$C3")"
chk "  and it is the NEW one"      "$NEW_SERIAL" "$C3"
chk "MS PKCS#7 is back to 1"       1 "$(n_of "$M3")"
chk "  and it is the NEW one"      "$NEW_SERIAL" "$M3"

echo "=== 5. the certificates a client got are usable as anchors ==="
# Counting serials proves they were sent; this proves they were sent intact and that the
# set really does span the rollover — a leaf issued after the renewal validates against a
# store built from what section 3 handed out.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout leaf.key -subj "/CN=after.internal" \
    -out leaf.csr >/dev/null 2>&1
IC=$(curl -s -o iss.json -w '%{http_code}' -b cj -X POST --data-binary @leaf.csr \
        "http://127.0.0.1:$WEBP/api/certs/request?ca_instance=roll")
chk "a leaf issues after the rekey" 201 "$IC"
LS=$(sed -n 's/.*"serial":"\([^"]*\)".*/\1/p' iss.json | head -1)
pg_exec "SELECT '-----BEGIN CERTIFICATE-----'||chr(10)||
                rtrim(encode(cert,'base64'),chr(10))||chr(10)||
                '-----END CERTIFICATE-----' FROM certs WHERE serial='$LS';" > leaf.pem
# Section 4's est.pem holds only the new certificate, so build the anchor store from
# EVERY CA row — which is exactly what section 3 handed out.
pg_exec "SELECT string_agg('-----BEGIN CERTIFICATE-----'||chr(10)||
                           rtrim(encode(cert,'base64'),chr(10))||chr(10)||
                           '-----END CERTIFICATE-----', chr(10))
           FROM certs WHERE id='roll' AND is_ca;" > bundle.pem
chk "it validates against the rollover bundle" yes \
    "$("$OSSL" verify -CAfile bundle.pem -partial_chain leaf.pem >/dev/null 2>&1 && echo yes || echo no)"

echo
echo "=== CA ROLLOVER CHAIN: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
