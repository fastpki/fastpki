#!/usr/bin/env bash
# CA-creation page. The console's dedicated CA-creation
# form exposes the full RFC 5280 CA attribute surface: key algorithm (incl. PQC),
# DN builder, explicit NotBefore/NotAfter (with never-expire), pathLen, KeyUsage,
# NameConstraints, AIA/CDP and certificatePolicies. This test drives the backing
# POST /api/ca-instances with those fields and DEEP-INSPECTS the emitted cert with
# openssl — asserting decoded extension contents, not just HTTP status.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"   # ocsp_responder_key / service_cert_publish
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
unset OPENSSL_CONF
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18095
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
# A here-string, not a pipe: `grep -q` exits on the first match, and against a whole
# served page that closes the pipe early — printing "Broken pipe" noise into a passing
# run, which is how a real failure ends up overlooked.
has(){ grep -q "$2" <<<"$1" && echo yes || echo no; }

pg_setup web_ca_create
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
ca_in_token ca.pem "/CN=Global CA" 3650
source "$ROOT/tests/user_helpers.sh"
seed_web_user boss bosspw admin
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat srv.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null
# Every CA key is minted inside the token, so the handle is part of every create.
# The helper adds it, named after the CA id (unique by construction), so each test below
# stays about the ATTRIBUTE it is testing rather than about PKCS#11 plumbing.
create(){
    local a id=""
    for a in "$@"; do case "$a" in id=*) id="${a#id=}";; esac; done
    curl -s -o /dev/null -w '%{http_code}' -b boss.cj "$U/api/ca-instances" "$@" \
        --data-urlencode 'keyloc=pkcs11' --data-urlencode 'keygen=true' \
        --data-urlencode "keyref=$(hsm_new_key_uri "k-$id")"
}
# The CA certificate comes from the API, not from a file. CA_INSTANCE_DIR is gone —
# the console wrote <id>.crt there and nothing ever read it back, while the certificate
# itself is a `certs` row. Asking the product for it is also the stronger
# test: it exercises the path an operator and every other service actually use.
pem(){ curl -s -b boss.cj "$U/api/ca-instances/$1/cert-pem"; }
txt(){ pem "$1" | "$OSSL" x509 -noout -text 2>/dev/null; }
der(){ pem "$1" | "$OSSL" x509 -outform DER 2>/dev/null; }

echo "=== 1. RSA-3072 self-signed root, DN builder, explicit hash + validity ==="
C=$(create --data-urlencode 'id=root-a' --data-urlencode 'name=Root A' \
    --data-urlencode 'subject=/CN=Root A/O=FastPKI/C=US' \
    --data-urlencode 'key=rsa' --data-urlencode 'bits=3072' --data-urlencode 'md=sha512' \
    --data-urlencode 'pathlen=1')
chk "create root-a -> 201" 201 "$C"
T=$(txt root-a)
chk "root-a is self-signed (issuer==subject)" yes "$(echo "$T" | grep -A1 Issuer: | grep -q 'Root A' && echo yes || echo no)"
chk "root-a subject carries O" yes "$(echo "$T" | grep -Eq 'O *= *FastPKI' && echo yes || echo no)"
chk "root-a subject carries C" yes "$(echo "$T" | grep -Eq 'C *= *US' && echo yes || echo no)"
chk "root-a key is RSA 3072"    yes "$(has "$T" 'Public-Key: (3072 bit)')"
chk "root-a signed with SHA-512" yes "$(has "$T" 'sha512WithRSAEncryption')"
chk "root-a BasicConstraints pathlen:1" yes "$(has "$T" 'pathlen:1')"
# ⚠️ INVERTED LATER, and the history is worth keeping because the reasoning below was
# accepted for months. It said a CA must carry digitalSignature so it can protect a CMP
# response. The real conclusion was the opposite one: a CA should not be a CMP protection
# signer at all. CMP now protects with a dedicated RA credential, so the CA signs
# certificates and CRLs and nothing else, and the widened default is gone.
chk "root-a KU is keyCertSign+cRLSign only (no digitalSignature)" no \
    "$(echo "$T" | grep -A1 'Key Usage' | grep -q 'Digital Signature' && echo yes || echo no)"
chk "root-a is still a CA (Certificate Sign)" yes \
    "$(echo "$T" | grep -A1 'Key Usage' | grep -q 'Certificate Sign' && echo yes || echo no)"
# The form is the other half: it POSTs whatever is ticked, so a box ticked by default
# would re-widen the CA from the console even with the C++ default narrowed (§3e — assert
# the served JS, not just the API).
chk "the CA form does NOT pre-tick digitalSignature" no \
    "$(curl -s -b boss.cj "$U/" | tr -d ' \n' \
       | grep -q "k==='digitalSignature'||k==='keyCertSign'||k==='cRLSign'" && echo yes || echo no)"

echo "=== 2. EC P-384 sub-CA: NameConstraints, KeyUsage, never-expire, AIA/CDP ==="
C=$(create --data-urlencode 'id=sub-a' --data-urlencode 'parent=root-a' \
    --data-urlencode 'subject=/CN=Sub A' \
    --data-urlencode 'key=ec' --data-urlencode 'curve=P-384' --data-urlencode 'md=sha384' \
    --data-urlencode 'pathlen=0' --data-urlencode 'ku=keyCertSign,cRLSign' \
    --data-urlencode 'neverExpire=true' \
    --data-urlencode 'ncPermitted=DNS:corp.example.com,email:.corp.example.com,IP:10.0.0.0/8' \
    --data-urlencode 'ncExcluded=DNS:secret.example.com' \
    --data-urlencode 'crldp=http://crl.example/sub-a.crl' \
    --data-urlencode 'aiaIssuers=http://crl.example/sub-a.crt' \
    --data-urlencode 'aiaOcsp=http://ocsp.example')
chk "create sub-a -> 201" 201 "$C"
T=$(txt sub-a)
chk "sub-a issued by Root A"          yes "$(echo "$T" | grep -q 'Issuer:.*Root A' && echo yes || echo no)"
chk "sub-a key is EC P-384"           yes "$(has "$T" 'NIST CURVE: P-384')"
chk "sub-a signed with SHA-384 (parent RSA)" yes "$(has "$T" 'sha384WithRSAEncryption')"
chk "sub-a pathlen:0"                 yes "$(has "$T" 'pathlen:0')"
chk "sub-a KeyUsage critical"         yes "$(echo "$T" | grep -A1 'Key Usage' | grep -q critical && echo yes || echo no)"
chk "sub-a KU = Certificate Sign + CRL Sign" yes "$(has "$T" 'Certificate Sign, CRL Sign')"
# Asked never to expire, under a root that does: a CA certificate may not outlive the one
# that signs it (nothing could chain it past that date), so its end date is the root's.
ROOT_NA=$(txt root-a | sed -n 's/.*Not After : //p')
chk "sub-a asked never-expire: its end date is Root A's, not 9999" "$ROOT_NA" \
    "$(echo "$T" | sed -n 's/.*Not After : //p')"
chk "sub-a NameConstraints critical"  yes "$(echo "$T" | grep -A1 'Name Constraints' | grep -q critical && echo yes || echo no)"
chk "sub-a NC permitted DNS"          yes "$(has "$T" 'DNS:corp.example.com')"
chk "sub-a NC permitted email"        yes "$(has "$T" 'email:.corp.example.com')"
# The IP entry is written the way THIS FORM'S OWN HINT tells an operator to write it —
# CIDR. RFC 5280 encodes an iPAddress constraint as address+mask and OpenSSL will not
# parse a prefix length, so the console's worked example produced `bad ip address` and
# refused to create the CA at all. Guarding the ADVERTISED form, not a form that happens
# to work: the whole defect was that those two were different.
chk "sub-a NC permitted IP (the CIDR the form advertises)" yes \
    "$(has "$T" '10.0.0.0/255.0.0.0')"
chk "sub-a NC excluded DNS"           yes "$(has "$T" 'DNS:secret.example.com')"
# ⚠️ AIA OCSP IS DERIVED FROM THE PARENT TOO — and this assertion used to pin the
# opposite, exactly the way the CRL DP one below did before it was fixed. It sent
# `aiaOcsp=http://ocsp.example` and checked the certificate carried it back, so it agreed
# with the defect and could never have caught it: the request value was baked in verbatim,
# and a caller passing `aiaOcsp=auto` got a certificate advertising `OCSP - URI:auto`.
#
# The responder that can answer about THIS certificate is the ISSUER's (RFC 6960 §2.2),
# which is the same reasoning that makes caIssuers and the CRL DP point up the chain. The
# request still sends a wrong URL on purpose.
# ⚠️ AND IT IS OMITTED ENTIRELY WHEN THE ISSUER CANNOT ANSWER. A CA serves OCSP only if a
# delegated responder certificate exists for it (cert_id "<prefix>-<ca_id>", issued BY that
# CA -- RFC 6960 §4.2.2.2). `root-a` has none, which is the ordinary shape for an offline
# root: it publishes a CRL and no responder. Advertising the URI anyway names an endpoint
# that cannot answer about this certificate -- measured against a real Windows client, which
# queries it and reports `Unsuccessful "OCSP"` for the intermediate, and a verifier
# configured to fail closed on an unreachable responder does worse than report. The CRL DP
# below is what carries revocation for a CA certificate.
chk "sub-a has NO AIA OCSP (its issuer has no responder)" no "$(has "$T" 'OCSP - URI:')"
chk "  and certainly not the one the request asked for"   no "$(has "$T" 'ocsp.example')"
# ⚠️ THE OTHER HALF, or the assertion above is satisfied by never emitting AIA OCSP at all.
# Give root-a a responder credential and the next CA under it must carry the URI -- derived
# from the PARENT, still not from what the request asked for.
# The rule turns on ONE fact: does a responder credential exist for the parent, i.e. is
# there a cert row with cert_id "<prefix>-<parent>"? Seeded directly rather than minted
# through the whole responder flow, because what is under test is the AIA decision, not
# credential issuance -- ocsp_responder_keys.sh covers that.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout rr.key -out ocsp-ra-root-a.pem \
    -subj "/CN=Responder For Root A" -days 365 >/dev/null 2>&1
pg_insert_cert ocsp-ra-root-a.pem 0 test standard >/dev/null 2>&1
pg_exec "UPDATE certs SET cert_id='ocsp-ra-root-a' WHERE cn='ocsp-ra-root-a';" >/dev/null 2>&1
HAVE_RESP=$(pg_exec "SELECT COUNT(*) FROM certs WHERE cert_id='ocsp-ra-root-a' AND status=0;")
if [ "$HAVE_RESP" = 1 ]; then
    C=$(create --data-urlencode 'id=sub-ocsp' --data-urlencode 'name=Sub OCSP' \
        --data-urlencode 'parent=root-a' --data-urlencode 'subject=/CN=Sub OCSP' \
        --data-urlencode 'days=1825' --data-urlencode 'aiaOcsp=http://ocsp.example')
    T2=$(txt sub-ocsp)
    chk "  with a responder present, the URI IS advertised" yes \
        "$(has "$T2" 'OCSP - URI:http://pki.example.org:8080/ocsp')"
else
    echo "  [FAIL] could not seed a responder credential for root-a — the positive half of"
    echo "         this rule went untested, so the assertion above proves only absence"
    fail=$((fail+1))
fi
# ⚠️ THE CRL DP NAMES THE ISSUER, NOT THIS CA.
# ⚠️ THE REPORT: an intermediate CA had its CRL link pointing to itself instead of
# issuing/signing CA CRL!" sub-a is signed by root-a, so the CRL that could revoke sub-a
# is root-a's (RFC 5280 §4.2.1.13). This assertion previously pinned the OPPOSITE: it
# passed the request `crldp=http://crl.example/sub-a.crl` and checked that it came back —
# so the test agreed with the bug and could never have caught it. A self-referential CRLDP
# fails silently in the worst way: the URL resolves, the CRL is valid and correctly
# signed, and it simply is not the list this certificate would ever appear on, so the
# intermediate is unrevokable and nothing reports an error.
#
# The request STILL sends the wrong URL on purpose — the server must derive its own and
# ignore it, or a hand-built POST could bake in a CRL DP that answers nothing.
chk "sub-a CRL DP is the PARENT's CRL"  yes "$(has "$T" 'URI:http://pki.example.org:8080/root-a.crl')"
chk "  and NOT its own"                 no  "$(has "$T" 'sub-a.crl')"
# On the same decoded certificate: plain http, and the OCSP listener's port.
chk "  scheme is http, not https"       no  "$(has "$T" 'URI:https://pki.example.org')"
# Qualified by the parent's signing generation (/<id>/<ski>.p7c), as every issuer names it and
# as the form's preview shows — the flat /root-a.crt was this path alone.
chk "  caIssuers is the parent's generation" yes \
    "$(printf '%s' "$T" | grep -Eq 'CA Issuers - URI:http://pki\.example\.org:8080/root-a/[0-9A-Fa-f]+\.p7c' && echo yes || echo no)"

echo "=== 3. Ed25519 root (one-shot signature, no prehash) ==="
# The key is minted in the token, so this now depends on the local PKCS#11 stack
# relaying CKM_EC_EDWARDS_KEY_PAIR_GEN. p11-kit 0.26.x drops it (our image ships a
# patched build); on a host with the packaged one, the algorithm is simply not
# reachable. SKIP rather than FAIL, and say WHICH algorithm, so the gap is legible
# instead of looking like a broken console.
C=$(create --data-urlencode 'id=ed-root' --data-urlencode 'subject=/CN=Ed Root' --data-urlencode 'key=ed25519')
if [ "$C" = "201" ]; then
  chk "create ed25519 root -> 201" 201 "$C"
  T=$(txt ed-root)
  chk "ed-root public key is ED25519"  yes "$(has "$T" 'ED25519')"
  chk "ed-root signature is ED25519"   yes "$(echo "$T" | grep -q 'Signature Algorithm: ED25519' && echo yes || echo no)"
else
  echo "  [SKIP] this token/p11-kit will not mint Ed25519 in-token (create -> $C)"
fi

echo "=== 3b. RSA-PSS root (RFC 4055 §3) ==="
# In-token RSA-PSS. The KEY mints fine (one RSA keygen mechanism serves both
# forms); what can fail is X509_sign through the OpenSSL pkcs11 provider — measured on
# macOS/SoftHSM, where p11-kit relays RSA-PKCS-PSS and pkcs11-tool signs with it happily,
# so the gap is the provider's PSS path rather than the token or the proxy.
C=$(create --data-urlencode 'id=pss-root' --data-urlencode 'subject=/CN=PSS Root' --data-urlencode 'key=rsa-pss' --data-urlencode 'bits=3072' --data-urlencode 'md=sha256')
if [ "$C" != "201" ]; then echo "  [SKIP] the pkcs11 provider will not sign RSA-PSS with a token key (create -> $C)"; fi
if [ "$C" = "201" ]; then
  chk "create RSA-PSS root -> 201" 201 "$C"
  T=$(txt pss-root)
  # RFC 4055 §3.1 — follow the RFC: the standards
  # exist for a reason." An RSA-PSS key's SubjectPublicKeyInfo carries id-RSASSA-PSS, which
  # is what RESTRICTS the key to PSS; publishing rsaEncryption (what we used to do) leaves a
  # relying party free to use it with PKCS#1 v1.5, so `key=rsa-pss` promised a restriction
  # it did not deliver — it differed from `key=rsa` only in signature algorithm, which `md`
  # already selects.
  #
  # ⚠️ This block had NEVER RUN before the signing path was fixed: `create` returned
  # non-201 and the SKIP above fired every time, so its assertions had never been evidence.
  ALG=$(echo "$T" | sed -n 's/.*Public Key Algorithm: *//p' | head -1)
  chk "pss-root SPKI is id-RSASSA-PSS (RFC 4055 §3.1)" "rsassaPss" "$ALG"
  # And the PARAMETERS must be explicit. RFC 4055's defaults are SHA-1 / MGF1-SHA1 /
  # salt 20, so an AlgorithmIdentifier with absent parameters would quietly mean SHA-1 on a
  # CA the operator asked to be SHA-256. Decode them rather than trust the OID.
  pem pss-root | "$OSSL" asn1parse 2>/dev/null > pss.asn1
  chk "  its params name the requested hash" yes \
      "$(awk '/:rsassaPss/{f=1} f&&/OBJECT.*:sha256/{n++} END{exit !(n>=2)}' pss.asn1 && echo yes || echo no)"
  chk "  and MGF1" yes \
      "$(awk '/:rsassaPss/{f=1} f&&/OBJECT.*:mgf1/{print;exit}' pss.asn1 | grep -q mgf1 && echo yes || echo no)"
  chk "pss-root key is 3072 bit"         yes "$(echo "$T" | grep -q '3072 bit' && echo yes || echo no)"
  chk "pss-root signature is rsassaPss"  yes "$(echo "$T" | grep -q 'Signature Algorithm: rsassaPss' && echo yes || echo no)"
  chk "pss-root is self-signed"          yes "$(echo "$T" | grep -A1 'Issuer:' | grep -q 'PSS Root' && echo yes || echo no)"
  chk "pss-root is a CA"                 yes "$(has "$T" 'CA:TRUE')"
fi

echo "=== 3c. RSA-PSS CSR issues under the RSA-PSS CA ==="
PSS_OK="$C"   # 3b's status: without that CA there is nothing to issue under
# Generate an RSA-PSS CSR and submit it to be signed by the pss-root CA instance.
"$OSSL" genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out pss-leaf.key 2>/dev/null
"$OSSL" req -new -key pss-leaf.key -out pss-leaf.csr -sha256 -subj "/CN=pss-leaf.example" 2>/dev/null
if [ "$PSS_OK" = "201" ]; then
  # ⚠️ THE PROVIDER'S PSS SIGNING PATH, NOT THE PRODUCT. Creating the CA signs with
  # RSA-PSS one way (X509_sign over an already-PSS key), but signing a leaf from a CSR
  # goes through EVP_DigestSign on foreign SPKI params — and on macOS/SoftHSM the
  # pkcs11 provider answers that with "provider signature failure" (the same gap 3b's
  # header documents). Announce the skip with the server's own reason; anything else
  # is a real regression and must fail.
  ISS=$(curl -s -o pss-body.txt -w '%{http_code}' -b boss.cj -X POST --data-binary @pss-leaf.csr "$U/api/certs/request?ca_instance=pss-root")
  if [ "$ISS" != "201" ] && grep -q 'provider signature failure' pss-body.txt 2>/dev/null; then
    echo "  [SKIP] the pkcs11 provider cannot sign a PSS leaf here ($(cat pss-body.txt))"
    rm -f pss-body.txt
  else
    chk "RSA-PSS CSR issued under pss-root -> 201" 201 "$ISS"
  fi
else
  echo "  [SKIP] no RSA-PSS CA to issue under (see 3b)"
fi

echo "=== 3d. a 4096-bit RSA-PSS CA must sign certificates it can VERIFY ==="
# ⚠️ THE REGRESSION THIS EXISTS FOR. An rsa-pss CA was given an RFC 4055 §3.1 SPKI that
# RESTRICTS the key to one digest. That restriction is BINDING: sign with anything else and
# OpenSSL refuses the signature outright —
#
#     rsa_check_padding:digest not allowed
#
# ca_signing_md() chose the digest from the key SIZE (SHA-384 from 4096 bits), while the
# restriction was written from the operator's `md`. At 3072 bits both say SHA-256, which is
# why section 3c above passed throughout and the bug shipped. At 4096 they disagree, and
# Every certificate the sub-CA issued was found to be unverifiable.
#
# The size is the whole point of this section: do not "simplify" it to 2048/3072.
C=$(create --data-urlencode 'id=pss4096' --data-urlencode 'subject=/CN=PSS 4096 CA' \
           --data-urlencode 'key=rsa-pss' --data-urlencode 'bits=4096' --data-urlencode 'md=sha256')
if [ "$C" != "201" ]; then
  echo "  [SKIP] could not create a 4096-bit RSA-PSS CA (create -> $C)"
else
  chk "create a 4096-bit RSA-PSS CA -> 201" 201 "$C"
  RESTRICT=$(txt pss4096 2>/dev/null \
             | sed -n '/PSS parameter restrictions/,/Trailer/p' | sed -n 's/.*Hash Algorithm: *//p' | head -1)
  chk "  its SPKI restricts the key to a digest" yes "$([ -n "$RESTRICT" ] && echo yes || echo no)"

  "$OSSL" req -new -newkey rsa:2048 -nodes -keyout l4096.key -out l4096.csr \
      -subj "/CN=leaf4096.example" >/dev/null 2>&1
  ISS=$(curl -s -o l4096.json -w '%{http_code}' -b boss.cj -X POST --data-binary @l4096.csr \
        "$U/api/certs/request?ca_instance=pss4096")
  # Same macOS pkcs11-provider PSS gap as 3c — the CA was CREATED (that signature path
  # works) but leaf issuance through EVP fails. Announce and skip the dependent cells;
  # on CI (patched provider) the assertions below still run.
  if [ "$ISS" != "201" ] && grep -q 'provider signature failure' l4096.json 2>/dev/null; then
    echo "  [SKIP] the pkcs11 provider cannot sign a PSS leaf here ($(cat l4096.json))"
  else
  chk "  it issues a leaf -> 201" 201 "$ISS"
  # The response carries the serial, not the certificate; read the DER back out of the DB
  # and decode it, the same way ca_rollover_chain.sh does.
  LS=$(sed -n 's/.*"serial":"\([^"]*\)".*/\1/p' l4096.json | head -1)
  pg_exec "SELECT '-----BEGIN CERTIFICATE-----'||chr(10)||
                  rtrim(encode(cert,'base64'),chr(10))||chr(10)||
                  '-----END CERTIFICATE-----' FROM certs WHERE serial='$LS';" > l4096.pem
  chk "  the issued leaf decodes" yes \
      "$("$OSSL" x509 -in l4096.pem -noout -subject >/dev/null 2>&1 && echo yes || echo no)"

  # THE assertion: the CA must be able to verify what it just signed. This is the exact
  # command from the ticket, and it failed with "certificate signature failure" before.
  pem pss4096 > pss4096.pem; VOUT=$("$OSSL" verify -trusted pss4096.pem l4096.pem 2>&1)
  chk "  and openssl VERIFIES that leaf against it" yes \
      "$(printf '%s' "$VOUT" | grep -q ': OK' && echo yes || echo no)"
  [ -n "$(printf '%s' "$VOUT" | grep -o 'digest not allowed')" ] && \
      echo "    --- the signature: $VOUT"

  # And say WHY, so a future failure is diagnosable rather than just red: the digest the
  # leaf was signed with has to be the one the CA's SPKI permits.
  # Compare the digest SIZE, so "SHA2-256" (how the restriction prints) and "sha256" (how
  # the signature prints) are recognised as the same thing.
  digitsof(){ printf '%s' "$1" | sed 's/.*[^0-9]\([0-9][0-9]*\)$/\1/'; }
  LEAFMD=$("$OSSL" x509 -in l4096.pem -noout -text 2>/dev/null \
           | sed -n '/Signature Algorithm: rsassaPss/,/Salt/p' | sed -n 's/.*Hash Algorithm: *//p' | head -1)
  chk "  the leaf's signature digest equals the CA's restriction ($RESTRICT vs ${LEAFMD:-none})" \
      "$(digitsof "$RESTRICT")" "$(digitsof "$LEAFMD")"
  fi
fi

echo "=== 4. ML-DSA-65 PQC root (OpenSSL >= 3.5) ==="
C=$(create --data-urlencode 'id=pq-root' --data-urlencode 'subject=/CN=PQ Root' --data-urlencode 'key=ML-DSA-65')
if [ "$C" = "201" ]; then
  T=$(txt pq-root)
  # ML-DSA-65: OpenSSL prints the name "ML-DSA-65" (or the OID 2.16.840.1.101.3.4.3.18).
  chk "pq-root uses ML-DSA-65" yes "$(echo "$T" | grep -Eq 'ML-DSA-65|2\.16\.840\.1\.101\.3\.4\.3\.18' && echo yes || echo no)"
  chk "pq-root is a CA"            yes "$(has "$T" 'CA:TRUE')"
else
  echo "  [SKIP] ML-DSA-65 not available in this OpenSSL build (create -> $C)"
fi

echo "=== 4b. the software key location is GONE, not merely hidden ==="
# This section used to prove the File location worked: the key landed at
# because a CA whose key is a file can be registered and cannot sign — load_signing_key
# has no on-disk branch. The guard asserts the removed path is INERT, not that the kept
# one works; a create that quietly succeeded here would be the real regression.
chk "keyloc=software -> 400"  400 "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj \
    "$U/api/ca-instances" -d 'id=fk-sw' --data-urlencode 'subject=/CN=FK SW' -d 'key=ec' \
    --data-urlencode 'keyloc=software')"
chk "no CA registered for it" 0 "$(pg_exec "SELECT count(*) FROM certs WHERE id='fk-sw' AND is_ca;")"
# No keyref at all is the same refusal: there is no default place to put a CA key.
chk "no key handle -> 400"    400 "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj \
    "$U/api/ca-instances" -d 'id=fk-nokey' --data-urlencode 'subject=/CN=FK NoKey' -d 'key=ec')"
# There is no per-CA directory left to write into at all — assert the absence of
# the DIRECTORY rather than of one file in it, which is the stronger statement and the one
# that stays true if someone reintroduces a different filename.
chk "and no CA material directory exists" no "$([ -d "$W/ca-inst" ] && echo yes || echo no)"
# `keypath` is not a parameter any more; naming one must not resurrect the file path.
KP="$W/customkeys/mine.key"
chk "keypath is ignored, not honoured" 201 "$(create --data-urlencode 'id=fk-kp' \
    --data-urlencode 'subject=/CN=FK KP' --data-urlencode 'key=ec' --data-urlencode 'curve=P-256' \
    --data-urlencode "keypath=$KP")"
chk "no key file at the named path"    no  "$([ -f "$KP" ] && echo yes || echo no)"
chk "still no CA material directory"   no  "$([ -d "$W/ca-inst" ] && echo yes || echo no)"
chk "the registered key is the token handle" yes \
    "$(pg_exec "SELECT coalesce(private_key,'') FROM certs WHERE id='fk-kp' AND is_ca;" | grep -q '^pkcs11:' && echo yes || echo no)"

# The New CA form no longer asks WHERE the key lives — a CA key lives in the
# token, so the dropdown was a question with one answer. What remains is which SLOT.
# (The API's keypath handling above is untouched; only the console stopped offering it.)
IDX=$(curl -s "$U/")
chk "no key-location dropdown in the form"   no  "$(has "$IDX" 'id="ca_keyloc"')"
chk "no key-file path box in the form"       no  "$(has "$IDX" 'id="ca_keypath"')"
chk "the form picks a token slot"            yes "$(has "$IDX" 'id="ca_hsm_slot"')"
# Generating is the common case, so it must need no click. The old checkbox was
# "generate a new key" (unchecked by default), which silently asked the server to load
# a key that was not there.
chk "the checkbox is now 'existing key'"     yes "$(has "$IDX" 'id="ca_existingkey"')"
chk "the old generate-key checkbox is gone"  no  "$(has "$IDX" 'id="ca_keygen"')"
chk "...and it is unchecked by default"      no  \
    "$(echo "$IDX" | grep -o 'id="ca_existingkey"[^>]*' | grep -q 'checked' && echo yes || echo no)"
chk "submit always names pkcs11"             yes "$(has "$IDX" "fd.set('keyloc', 'pkcs11')")"
chk "submit generates unless adopting"       yes \
    "$(echo "$IDX" | tr '\n' ' ' | grep -qF "if (!document.getElementById('ca_existingkey').checked) fd.set('keygen', 'true')" && echo yes || echo no)"

echo "=== 5. validation ==="
# 400, not 500. The token is asked whether it generates this algorithm before
# it is asked to, so an unknown name is a bad REQUEST answered up front — it used to
# surface as a 500 from inside the provider after the CA row had been half-built.
chk "unknown key algorithm is rejected" 400 "$(create --data-urlencode 'id=badkey' --data-urlencode 'subject=/CN=Bad' --data-urlencode 'key=bogus-algo')"
chk "unknown parent -> 400"             400 "$(create --data-urlencode 'id=orphan' --data-urlencode 'subject=/CN=Orphan' --data-urlencode 'parent=nope')"

echo "=== 6. the CA-creation page CONSULTS the cert profile ==="
# ⚠️ FOR CONSISTENCY: the CA-creation page should consult the profile and
# I guess this implies that we need to add basicConstraints to it."
#
# Until now this endpoint read no profile at all — it gated only on being an unscoped
# admin. So the KU allow-list gained in 7e84ab4 governed leaves and had nothing to say
# about the one path that actually mints a CA, which is the inconsistency he named.
#
# `allow_ca` is basicConstraints CA:TRUE as a profile property. `admin` ships true,
# `requester` false.
prof_get() { curl -s -b boss.cj "$U/api/profiles"; }
chk "PRECONDITION: the admin profile ships allow_ca=true" yes \
    "$(prof_get | tr '{' '\n' | grep '"name":"admin"' | grep -q '"allow_ca":true' && echo yes || echo no)"
chk "  and requester does NOT" yes \
    "$(prof_get | tr '{' '\n' | grep '"name":"requester"' | grep -q '"allow_ca":false' && echo yes || echo no)"

# ⚠️ Drive the REAL refusal: take CA:TRUE away from the profile this admin resolves to and
# ask for a CA. A 403 here can only be the new check — every other gate on this endpoint
# (unscoped admin, valid id, unique id) is already satisfied by the calls above.
#
# ⚠️ WRITE THE WHOLE PROFILE, do not string-replace. A first version string-replaced
# '"allow_ca":true' in the stored profiles — and on a fresh database a built-in has no stored
# definition at all (it is only persisted once somebody edits it), so the replace matched
# nothing, the profile kept its shipped allow_ca=true, and the "refused" assertion failed by
# ISSUING. The edit has to be one whose effect does not depend on what was already there.
#
# keyCertSign/cRLSign stay in the allow-list so the ONLY thing withdrawn is
# basicConstraints — otherwise a refusal could be the KU check instead.
set_admin_ca() {   # <true|false>
  seed_cert_profiles '{"admin":{"allowed_ku":["keyCertSign","cRLSign","digitalSignature"],"allowed_eku":["*"],"allow_ca":'"$1"'}}'
  # Prove the write landed before drawing any conclusion from what the server does next —
  # a row that silently was not written reads exactly like the product ignoring the profile.
  case "$(pg_exec "select definition from cert_profiles where name='admin';")" in
    *'"allow_ca":'"$1"*) : ;;
    *) echo "  [FAIL] set_admin_ca $1: the admin profile row was not written"; fail=$((fail+1));;
  esac
}
set_admin_ca false
kill $P 2>/dev/null; wait $P 2>/dev/null
"$WEB" --config bootstrap.conf >>srv.log 2>&1 & P=$!
for i in $(seq 1 40); do curl -s -o /dev/null "$U/api/me" && break; sleep 0.25; done
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null
chk "with allow_ca=false the CA is REFUSED -> 403" 403 \
    "$(create --data-urlencode 'id=noca' --data-urlencode 'subject=/CN=No CA' --data-urlencode 'key=ec')"
chk "  and no CA row was written for it" 0 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='noca' AND is_ca;")"
# ⚠️ THE REASON, not just the status. A 403 with any other cause would satisfy the line
# above equally well and this would be guarding the wrong thing.
# ⚠️ Fetch the BODY. `create` is built to print only the status code (-o /dev/null -w
# '%{http_code}'), so no redirection of its output can recover the message — my first
# version tried and asserted against an empty string.
NOCA_BODY=$(curl -s -b boss.cj "$U/api/ca-instances" \
    --data-urlencode 'id=noca2' --data-urlencode 'subject=/CN=No CA 2' \
    --data-urlencode 'key=ec' --data-urlencode 'keyloc=pkcs11' \
    --data-urlencode 'keygen=true' --data-urlencode "keyref=$(hsm_new_key_uri k-noca2)")
chk "  the message names basicConstraints" yes \
    "$(printf '%s' "$NOCA_BODY" | grep -q 'does not permit basicConstraints CA:TRUE' && echo yes || echo no)"

# Put it back and prove the SAME request now succeeds — without this the refusal above
# could be permanent for some unrelated reason and the suite would never notice.
set_admin_ca true
kill $P 2>/dev/null; wait $P 2>/dev/null
"$WEB" --config bootstrap.conf >>srv.log 2>&1 & P=$!
for i in $(seq 1 40); do curl -s -o /dev/null "$U/api/me" && break; sleep 0.25; done
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null
chk "restored, the same request is accepted -> 201" 201 \
    "$(create --data-urlencode 'id=yesca' --data-urlencode 'subject=/CN=Yes CA' --data-urlencode 'key=ec')"
chk "  and that CA really is a CA (basicConstraints CA:TRUE)" yes \
    "$(pem yesca | "$OSSL" x509 -noout -text 2>/dev/null | grep -A1 'Basic Constraints' | grep -q 'CA:TRUE' && echo yes || echo no)"

echo
echo "=== WEB CA CREATE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
