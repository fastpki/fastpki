#!/usr/bin/env bash
# A renewal must carry the CA's own identity forward — and must not outlive the
# certificate signing it, which for a sub CA is its PARENT's.
#
# ── What was measured ────────────────────────────────────────────────────────────
#
# `certutil -urlfetch -verify` was run against a leaf issued by the lab's DC1
# issuing CA. Both intermediate generations came back:
#
#     ----------------  Certificate AIA  ----------------
#     No URLs "None" Time: 0 (null)
#     ----------------  Certificate CDP  ----------------
#     No URLs "None" Time: 0 (null)
#     ----------------  Certificate OCSP  ----------------
#     No URLs "None" Time: 0 (null)
#
# and the chain therefore ended at CERT_TRUST_REVOCATION_STATUS_UNKNOWN (0x40) — Windows
# could not check whether the intermediate had been revoked, because the intermediate said
# nothing about where to look.
#
# The renew handler builds its CaCertParams with a subject, a validity and a digest, and
# NOTHING else. Every remaining field defaults empty, and in build_ca_certificate_ex empty
# means OMIT. So a re-key silently dropped:
#
#     authorityInfoAccess     caIssuers + OCSP  -> chain building and revocation both die
#     crlDistributionPoints                     -> ditto
#     certificatePolicies                       -> policy processing changes answer
#                                                  (NOT asserted here — the console cannot set
#                                                   one at all today, filed separately; the copy
#                                                   is by extension OID so it is covered anyway)
#     nameConstraints                           -> ⚠️ a CONSTRAINED CA came back OPEN
#     basicConstraints pathlen                  -> ⚠️ pathlen:0 came back UNLIMITED
#
# The last two are the reason this suite exists at all. Losing a URL is an outage; losing a
# nameConstraints or a pathLenConstraint is a re-key handing back a CA with strictly more
# authority than the one it replaced, and nothing anywhere reports an error.
#
# ── And the second defect in the same dump ───────────────────────────────────────
#
#     CertContext[0][1]  NotAfter: 7/25/2036   <- generation 2, self-issued, the re-key
#     CertContext[0][2]  NotAfter: 7/25/2031   <- generation 1, signed by the root
#
# Generation 2 outlived by five years the generation whose key signed it, so for those five
# years nobody could chain it. A renewal is now signed by the PARENT instead, so it may run
# past generation 1 — but never past the parent's own notAfter, which is where the clamp
# now applies. `days` defaults to 3650 in the renew handler, so the cut is the ordinary case.
#
# ── Why the fixture is shaped like the lab ───────────────────────────────────────
#
# root in a token -> sub-CA created through the console with real URLs, constraints and a
# 5-year life -> renew the sub-CA with a new key asking for the default 10 years. That is the
# lab's own hierarchy and the lab's own numbers, so a pass here is evidence about the rebuild
# rather than about a shape only this file builds.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18119
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup ca_rekey_ident
trap 'pg_cleanup; kill ${P:-} 2>/dev/null' EXIT

# The root lives in a token — re-keying is a token operation and there is no software path.
# ⚠️ 3000 DAYS, SHORTER THAN THE 3650 THE RENEWAL ASKS FOR. With both at 3650 the clamp in
# section 3 had nothing to cut whenever the root and the renewal were minted in the same
# second — a fast runner did exactly that, and the precondition failed on equality.
ca_in_token root.pem "/CN=Rekey Ident Root/O=FastPKI Test" 3000 rkiroot || { echo "SKIP: no token"; exit 0; }
ROOT_URI="$CA_KEY_URI"

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/root.pem
SIGNING_CA_KEY=$ROOT_URI
SIGNING_CA_ID=rkiroot
BASE_URL=http://pki.example.org:8080
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf
seed_web_user boss bosspw admin

"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" WEB_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat srv.log; exit 1; }
U="http://127.0.0.1:$PORT"
curl -s -c cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null

# ── the sub-CA: URLs, a policy, a name constraint, a pathlen, and FIVE years ──────
# keygen=true + a fresh object label/id, so the CONSOLE mints this key inside the token
# (the existing-key path would need the object to be there already). RSA, because
# SoftHSM's ECDSA-through-the-provider signing is unreliable across platforms and fails
# outright on macOS — see web_ca_hsm.sh §2 for the same choice and the same reason.
# Two policy OIDs, deliberately sent as "A, B" with a space — that is what an operator
# types into the console's comma-separated field, and the list splitter used to keep the
# trailing space on every token but the last, which OBJ_txt2obj then rejects.
POL_DV='2.23.140.1.2.1'                 # CA/Browser Forum domain-validated
POL_PRIV='1.3.6.1.4.1.99999.1'          # a private arc, the shape the console advertises
TOK=$(printf '%s' "$ROOT_URI" | sed -n 's/.*token=\([^;?]*\).*/\1/p')
SUB_URI="pkcs11:token=$TOK;object=rkisubg1;id=%30;type=private?pin-value=1234"
SUBDAYS=1825
# ⚠️ THE PARENT NEEDS A RESPONDER CREDENTIAL, or the AIA OCSP URI is not emitted at all and
# the precondition below fails. A CA certificate advertises its ISSUER's responder, and we
# only advertise one the issuer can actually answer with — an offline root normally has none
# and publishes a CRL instead. `rkiroot` is a fixture root, so it gets one here: what this
# suite is about is whether a REKEY carries the extension forward, which needs generation 1
# to have carried it in the first place.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout rkirr.key -out ocsp-ra-rkiroot.pem \
    -subj "/CN=Responder For rkiroot" -days 365 >/dev/null 2>&1
pg_insert_cert ocsp-ra-rkiroot.pem 0 test standard >/dev/null 2>&1
pg_exec "UPDATE certs SET cert_id='ocsp-ra-rkiroot' WHERE cn='ocsp-ra-rkiroot';" >/dev/null 2>&1

C=$(curl -s -o cr.json -w '%{http_code}' -b cj "$U/api/ca-instances" \
      --data-urlencode 'id=issuing' --data-urlencode 'name=Issuing' \
      --data-urlencode 'subject=/CN=Rekey Ident Issuing CA/O=FastPKI Test' \
      --data-urlencode 'parent=rkiroot' \
      --data-urlencode 'keyloc=pkcs11' --data-urlencode "keyref=$SUB_URI" \
      --data-urlencode 'keygen=true' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048' \
      --data-urlencode "days=$SUBDAYS" --data-urlencode 'pathlen=0' \
      --data-urlencode 'ncPermitted=DNS:lab.example' \
      --data-urlencode 'crldp=derive' --data-urlencode 'aiaIssuers=derive' \
      --data-urlencode 'aiaOcsp=http://pki.example.org:8080/ocsp' \
      --data-urlencode "policies=$POL_DV, $POL_PRIV")
echo "  (create said: $C $(cut -c1-140 cr.json))"
chk "sub-CA created" 201 "$C"
[ "$C" = 201 ] || { echo "cannot continue"; echo "=== CA REKEY IDENTITY: PASS=$pass FAIL=$((fail+1)) ==="; exit 1; }

pem(){ curl -s -b cj "$U/api/ca-instances/$1/cert-pem"; }
pem issuing > g1.pem
G1=$("$OSSL" x509 -in g1.pem -noout -text 2>/dev/null)

# ⚠️ PRECONDITIONS. Every assertion below asks "did generation 2 keep X?". If generation 1
# never had X, each of those passes for free and this file measures nothing. `grep -c` on
# an absent extension returns 0 and reads exactly like a healthy answer, which is the
# vacuity this block exists to rule out.
echo "=== 0. PRECONDITION: generation 1 really carries what generation 2 must keep ==="
has(){ printf '%s\n' "$G1" | grep -q "$1" && echo yes || echo no; }
chk "gen1 has an AIA caIssuers URI"   yes "$(has 'CA Issuers - URI:')"
chk "gen1 has an AIA OCSP URI"        yes "$(has 'OCSP - URI:')"
chk "gen1 has a CRL distribution URI" yes "$(has 'X509v3 CRL Distribution Points')"
chk "gen1 has nameConstraints"        yes "$(has 'X509v3 Name Constraints')"
chk "gen1 is constrained to pathlen:0" yes "$(has 'pathlen:0')"
# ⚠️ THIS IS THE ONE THAT WAS NEVER SENT. The block above has claimed "a policy" since the
# suite was written, and the request did not carry one — so certificatePolicies went
# through no code path here at all. Creating a CA with this field filled in returned 500:
# certificatePolicies is an `r2i` extension and OpenSSL refuses every r2i extension when
# the context has no config database, whatever the value is.
chk "gen1 has certificatePolicies"     yes "$(has 'X509v3 Certificate Policies')"
chk "  and it asserts the DV policy"   yes "$(has "Policy: $POL_DV")"
chk "  and the private arc, un-mangled by the space after the comma" yes \
    "$(has "Policy: $POL_PRIV")"
G1_CAISS=$(printf '%s\n' "$G1" | sed -n 's/.*CA Issuers - URI:\(.*\)/\1/p' | head -1 | tr -d ' \r')
G1_OCSP=$( printf '%s\n' "$G1" | sed -n 's/.*OCSP - URI:\(.*\)/\1/p'       | head -1 | tr -d ' \r')
G1_CRL=$(  printf '%s\n' "$G1" | sed -n 's/.*URI:\(http[^ ]*\.crl\).*/\1/p' | head -1 | tr -d ' \r')
chk "  and the caIssuers URI is readable" yes "$([ -n "$G1_CAISS" ] && echo yes || echo no)"
chk "  and the CRL URI is readable"       yes "$([ -n "$G1_CRL" ]   && echo yes || echo no)"
G1_SKI=$(printf '%s\n' "$G1" | awk '/X509v3 Subject Key Identifier/{getline; gsub(/[ :]/,""); print toupper($0); exit}')
G1_NA=$("$OSSL" x509 -in g1.pem -noout -enddate | sed 's/notAfter=//')
G1_NA_EPOCH=$(pg_exec "SELECT \"notAfter\" FROM certs WHERE id='issuing' AND is_ca;" | tr -d ' ')
chk "  and gen1 has an SKI"               yes "$([ -n "$G1_SKI" ] && echo yes || echo no)"

echo "=== 1. renew it with a new key, asking for the handler's default 3650 days ==="
# ⚠️ 3650 days runs PAST the root's own expiry (created a moment earlier for 3000 days), so
# the clamp assertion in section 3 has something to cut. It also runs past gen1's 1825, which
# a renewal is ALLOWED to do — that is the point of renewing.
NEW_URI="pkcs11:token=$TOK;object=rkisubg2;id=%31;type=private?pin-value=1234"
RC=$(curl -s -o r.json -w '%{http_code}' -b cj -X POST "$U/api/ca-instances/issuing/renew" \
      --data-urlencode "keyref=$NEW_URI" --data-urlencode 'key=rsa' \
      --data-urlencode 'bits=2048' --data-urlencode 'days=3650')
echo "  (renew said: $RC $(cut -c1-140 r.json))"
chk "renew -> 201" 201 "$RC"
G2_SERIAL=$(sed -n 's/.*"serial":"\([^"]*\)".*/\1/p' r.json)
chk "it returned a new serial"       yes "$([ -n "$G2_SERIAL" ] && echo yes || echo no)"
# A sub CA's old and new certificates both chain to the parent, so nothing is cross-signed.
chk "and made no cross-certificate"  "" "$(sed -n 's/.*"crossSerial":"\([^"]*\)".*/\1/p' r.json)"

getpem(){ pg_exec "SELECT '-----BEGIN CERTIFICATE-----'||chr(10)||
                          rtrim(encode(cert,'base64'),chr(10))||chr(10)||
                          '-----END CERTIFICATE-----' FROM certs WHERE serial='$1';" > "$2"; }
getpem "$G2_SERIAL" g2.pem
G2=$("$OSSL" x509 -in g2.pem    -noout -text 2>/dev/null)
chk "generation 2 decodes" yes "$([ -n "$G2" ] && echo yes || echo no)"

# CONTROL: this really is a re-key. If the SKI matched, generation 2 would be carrying the
# SAME key and every "it kept X" assertion below would be trivially true.
G2_SKI=$(printf '%s\n' "$G2" | awk '/X509v3 Subject Key Identifier/{getline; gsub(/[ :]/,""); print toupper($0); exit}')
G2_AKI=$(printf '%s\n' "$G2" | awk '/X509v3 Authority Key Identifier/{getline; gsub(/[ :]/,""); sub(/^keyid/,""); print toupper($0); exit}')
ROOT_SKI=$("$OSSL" x509 -in root.pem -noout -text 2>/dev/null \
    | awk '/X509v3 Subject Key Identifier/{getline; gsub(/[ :]/,""); print toupper($0); exit}')
chk "CONTROL: gen2 carries a DIFFERENT key (SKI changed)" yes \
    "$([ -n "$G2_SKI" ] && [ "$G2_SKI" != "$G1_SKI" ] && echo yes || echo no)"
chk "  and gen2's AKI names the ROOT — the parent signed it" "$ROOT_SKI" "$G2_AKI"

echo "=== 2. ⚠️ THE DEFECT: generation 2 carries the CA's identity forward ==="
hasg2(){ printf '%s\n' "$G2" | grep -q "$1" && echo yes || echo no; }
chk "gen2 has an AIA caIssuers URI"    yes "$(hasg2 'CA Issuers - URI:')"
chk "  and it is gen1's, byte for byte" "$G1_CAISS" \
    "$(printf '%s\n' "$G2" | sed -n 's/.*CA Issuers - URI:\(.*\)/\1/p' | head -1 | tr -d ' \r')"
chk "gen2 has an AIA OCSP URI"         yes "$(hasg2 'OCSP - URI:')"
chk "  and it is gen1's"                "$G1_OCSP" \
    "$(printf '%s\n' "$G2" | sed -n 's/.*OCSP - URI:\(.*\)/\1/p' | head -1 | tr -d ' \r')"
chk "gen2 has a CRL distribution point" yes "$(hasg2 'X509v3 CRL Distribution Points')"
chk "  and it is gen1's"                "$G1_CRL" \
    "$(printf '%s\n' "$G2" | sed -n 's/.*URI:\(http[^ ]*\.crl\).*/\1/p' | head -1 | tr -d ' \r')"
# ⚠️ The two that are a privilege escalation, not an outage.
chk "⚠️ gen2 is STILL name-constrained"  yes "$(hasg2 'X509v3 Name Constraints')"
chk "  to the same name"                 yes "$(hasg2 'DNS:lab.example')"
chk "⚠️ gen2 is STILL pathlen:0"         yes "$(hasg2 'pathlen:0')"
# Exactly one of each — a certificate carrying two basicConstraints is malformed, and
# "add the old one" without removing the default would produce precisely that.
chk "exactly one basicConstraints"  1 "$(printf '%s\n' "$G2" | grep -c 'X509v3 Basic Constraints')"
chk "exactly one keyUsage"          1 "$(printf '%s\n' "$G2" | grep -c 'X509v3 Key Usage')"
chk "exactly one AIA block"         1 "$(printf '%s\n' "$G2" | grep -c 'Authority Information Access')"
chk "exactly one nameConstraints"   1 "$(printf '%s\n' "$G2" | grep -c 'X509v3 Name Constraints')"
chk "gen2 still asserts the DV policy"      yes "$(hasg2 "Policy: $POL_DV")"
chk "gen2 still asserts the private policy" yes "$(hasg2 "Policy: $POL_PRIV")"
chk "exactly one certificatePolicies" 1 "$(printf '%s\n' "$G2" | grep -c 'X509v3 Certificate Policies')"

echo "=== 3. ⚠️ IT OUTLIVES GEN1, BUT NEVER THE PARENT THAT SIGNED IT ==="
G2_NA=$("$OSSL" x509 -in g2.pem -noout -enddate | sed 's/notAfter=//')
G2_NA_EPOCH=$(pg_exec "SELECT \"notAfter\" FROM certs WHERE serial='$G2_SERIAL';" | tr -d ' ')
ROOT_NA_EPOCH=$(pg_exec "SELECT \"notAfter\" FROM certs WHERE id='rkiroot' AND is_ca;" | tr -d ' ')
echo "  (gen1 notAfter: $G1_NA / gen2 notAfter: $G2_NA)"
chk "PRECONDITION: 3650 days really was past the root's expiry" yes \
    "$([ -n "$ROOT_NA_EPOCH" ] && [ "$((ROOT_NA_EPOCH))" -lt "$(( $(date +%s) + 3650*86400 ))" ] && echo yes || echo no)"
chk "gen2 expires exactly when the root does" "$ROOT_NA_EPOCH" "$G2_NA_EPOCH"
chk "  which is later than gen1 — the renewal extends the CA's life" yes \
    "$([ -n "$G1_NA_EPOCH" ] && [ "$((G2_NA_EPOCH))" -gt "$((G1_NA_EPOCH))" ] && echo yes || echo no)"

echo "=== 4. and none of that broke the chain ==="
# Re-asserted here because copying extensions rewrites the certificate between build and
# sign: if the copy ran after signing, the signature would no longer cover the bytes.
chk "gen2 verifies against the root, a full chain" "g2.pem: OK" \
    "$("$OSSL" verify -CAfile root.pem g2.pem 2>/dev/null)"
chk "  and still does after gen1 has expired" "g2.pem: OK" \
    "$("$OSSL" verify -attime "$((G1_NA_EPOCH + 86400))" -CAfile root.pem g2.pem 2>/dev/null)"
# And the subject is still byte-identical, which is what makes it the same CA at all.
chk "gen2 keeps gen1's exact subject DER" \
    "$("$OSSL" x509 -in g1.pem -noout -subject -nameopt RFC2253)" \
    "$("$OSSL" x509 -in g2.pem -noout -subject -nameopt RFC2253)"

echo
echo "=== CA REKEY IDENTITY: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
