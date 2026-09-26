#!/usr/bin/env bash
# After a CA rekey, can a relying party anchored at the ROOT still build a path?
#
# Measured on lab DC1 before the fix, against a perfectly good certificate:
#
#   Response Verify Failure
#     error:13800065:OCSP routines:ocsp_verify_signer:certificate verify error:
#     Verify error: unable to get issuer certificate
#   leaf.pem: good
#
# The answer was correct and signed. It simply could not be verified by anyone anchored at
# the root, because nothing the deployment PUBLISHED led there.
#
# ⚠️ A REKEY LEAVES THREE LIVE CA CERTIFICATES, and two of them are SELF-ISSUED:
#
#   sub1   subject=Sub CA  issuer=Root      <- the one the parent signed
#   sub2   subject=Sub CA  issuer=Sub CA    <- NewWithOld: new key certified by the old one
#
# `certs.cert_der` is the NEWEST, i.e. sub2. Two publication paths handed that out alone:
#   * /{ca_id}.crt — the AIA caIssuers target baked into every certificate this CA issues —
#     served sub2, which carries no AIA of its own, so a client had the new key certified by
#     the old key and no pointer any further up;
#   * the signed OCSP response pushed the responder cert + ca_cert_ (again sub2).
#
# ⚠️ AND THIS IS NOT THE NAME CONFUSION. sub2 is self-ISSUED but not self-SIGNED, and
# X509_self_signed correctly says so. The gap was in what gets published, not in how a root
# is recognised — which is why this suite asserts on bytes fetched over the wire rather than
# on any is-root predicate.
#
# No HSM: this is about chain publication, and file keys exercise it identically. That
# matters — the HSM suites skip on macOS, which is how a chain defect gets to be a lab-only
# discovery in the first place (the lesson chain_rekeyed_ca.sh was written for).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"   # ocsp_responder_key
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
[ -n "$OSSL" ] || { echo "FAIL: no openssl on PATH — set OSSL"; exit 1; }
W="$(mktemp -d)"; cd "$W"; PORT=18479
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > ca.ext
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > leaf.ext

"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 3650 \
    -subj "/CN=Rekey OCSP Root" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "subjectKeyIdentifier=hash" >/dev/null 2>&1
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout sub1.key -out sub1.csr \
    -subj "/CN=Rekey OCSP Sub CA" >/dev/null 2>&1
"$OSSL" x509 -req -in sub1.csr -CA root.pem -CAkey root.key -CAcreateserial -days 3000 \
    -extfile ca.ext -out sub1.pem >/dev/null 2>&1
# The rekey: same subject, new key, certified by generation 1.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout sub2.key -out sub2.csr \
    -subj "/CN=Rekey OCSP Sub CA" >/dev/null 2>&1
# ⚠️ 3001, NOT 3000. "Newest" is resolved by notAfter, which has ONE-SECOND granularity —
# two certificates minted in the same second by the same script are ordered arbitrarily, and
# the responder then computed its CertID from whichever won. That is not hypothetical: it is
# what made this suite answer "unauthorized" the first time I ran it. A real rekey always
# produces a longer-lived certificate, so making the fixture unambiguous also makes it true.
"$OSSL" x509 -req -in sub2.csr -CA sub1.pem -CAkey sub1.key -CAcreateserial -days 3001 \
    -extfile ca.ext -out sub2.pem >/dev/null 2>&1
# A leaf issued by the NEW key, which is what a client will be asking about.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr \
    -subj "/CN=host.internal" >/dev/null 2>&1
"$OSSL" x509 -req -in leaf.csr -CA sub2.pem -CAkey sub2.key -set_serial 4660 -days 825 \
    -extfile leaf.ext -out leaf.pem >/dev/null 2>&1

echo "=== 1. the fixture is a real rekey, not a second CA ==="
s=$("$OSSL" x509 -in sub2.pem -noout -subject | sed 's/subject=//')
i=$("$OSSL" x509 -in sub2.pem -noout -issuer  | sed 's/issuer=//')
chk "the newest CA cert is SELF-ISSUED"        yes "$([ "$s" = "$i" ] && echo yes || echo no)"
"$OSSL" verify -CAfile sub2.pem sub2.pem >/dev/null 2>&1 && ss=yes || ss=no
chk "  but NOT self-signed"             no  "$ss"
"$OSSL" verify -CAfile root.pem -untrusted sub1.pem leaf.pem >/dev/null 2>&1 && v1=yes || v1=no
chk "the leaf needs generation 1 to reach root" no "$v1"

echo "=== 2. seed both generations under one id and start the responder ==="
pg_setup ocsp_rekeyed
trap 'pg_cleanup; kill ${P:-} 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains "$W/domains.txt"
# ⚠️ NO private_key ON THE CA ROWS, AND THAT IS THE POINT TWICE OVER.
#   1. load_signing_key() refuses a file path outright — a CA signing key is a pkcs11:
#      handle or nothing — so a file-keyed CA row makes the responder throw at
#      construction and every query 500s. That is what this fixture did first.
#   2. It does not need one. The response is signed by the DELEGATED responder
#      credential, never by the CA key, so a CA whose key is not on this host still gets
#      served — which is exactly the offline-root posture required. Seeding no key
#      keeps the suite HSM-free AND tests the shape that matters.
pg_seed_ca_row root "$W/root.pem" ""
# certs.id is indexed, not unique, precisely so a rollover keeps two live certs.
pg_seed_ca_row sub  "$W/sub1.pem" ""
pg_seed_ca_row sub  "$W/sub2.pem" ""
# ⚠️ MAKE "NEWEST" UNAMBIGUOUS, AND ON THE COLUMNS THE PRODUCT ACTUALLY ORDERS BY.
#   resolve_ca_instance()  ORDER BY "notBefore" DESC LIMIT 1
#   list_ca_instances()    DISTINCT ON (id) ... ORDER BY id, created DESC,
#                          where kCaSelect aliases  coalesce(c."notBefore",0) AS created
# — so BOTH are notBefore. (There is no `created` column on certs; updating one silently
#   errored and my assertion came back empty, which is how I found that out.)
# Both generations are minted by this script within the same second, and both columns have
# one-second granularity, so which one counts as "the CA certificate" was a coin flip. That
# is not a hypothetical: it made the responder compute its CertID from generation 1 while
# the leaf was issued by generation 2, and every query came back `unauthorized`.
# It also meant the /sub.crt assertion below could pass by accident.
# A real rekey happens later than the certificate it replaces; say so explicitly.
S1=$("$OSSL" x509 -in sub1.pem -noout -serial | sed 's/serial=//' | tr 'A-Z' 'a-z' | sed 's/^0*//')
pg_exec "UPDATE certs SET \"notBefore\"=\"notBefore\"-86400 WHERE serial='$S1';" >/dev/null
chk "generation 2 is unambiguously the newest" 1 \
    "$(pg_exec "SELECT count(*) FROM (SELECT DISTINCT ON (id) serial FROM certs
                WHERE id='sub' ORDER BY id, \"notBefore\" DESC) q
                WHERE q.serial <> '$S1';" | tr -d ' ')"
cat > bootstrap.conf <<EOF
SIGNING_CA_ID=sub
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
CRL_PATH=/crl
LOG_LEVEL=err
EOF
# ⚠️ NOT `2>/dev/null || RKEY=""`. The delegated responder certificate is mandatory,
# so if this fails the responder answers `unauthorized` to everything and the suite blames
# the product for a fixture that never got built. Let it be loud, and stop if it breaks.
RKEY=$(ocsp_responder_key "$W/sub2.pem" "$W/sub2.key" sub "$W") \
  || { echo "FAIL: could not mint the OCSP responder credential"; exit 1; }
printf 'OCSP_RESPONDER_KEY=%s\n' "$RKEY" >> bootstrap.conf
pg_exec "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('1234',0,'host.internal','sub');" >/dev/null
"$ROOT/build/fastpki-ocsp" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-ocsp died:"; cat srv.log; exit 1; }
B="http://127.0.0.1:$PORT"

echo "=== 3. /{ca_id}.crt is the AIA caIssuers target — it must lead UPWARDS ==="
curl -s -o served.der -w '%{http_code}' "$B/sub.crt" > code.txt
chk "GET /sub.crt -> 200" 200 "$(cat code.txt)"
"$OSSL" x509 -inform DER -in served.der -out served.pem 2>/dev/null
ss=$("$OSSL" x509 -in served.pem -noout -subject 2>/dev/null | sed 's/subject=//')
si=$("$OSSL" x509 -in served.pem -noout -issuer  2>/dev/null | sed 's/issuer=//')
# ⚠️ THE ASSERTION IS "issued by someone else", NOT "is not a root". Serving the newest
# certificate gives a self-issued one whose issuer is itself, and that is the bug.
chk "  it is the certificate the PARENT signed" yes "$([ "$ss" != "$si" ] && echo yes || echo no)"
chk "  which is generation 1, byte for byte"    yes \
    "$([ "$("$OSSL" x509 -in served.pem -noout -fingerprint -sha256 | sed 's/.*=//')" \
       = "$("$OSSL" x509 -in sub1.pem   -noout -fingerprint -sha256 | sed 's/.*=//')" ] && echo yes || echo no)"
# ...and fetching it gets a client to the root, which is the entire point of caIssuers.
"$OSSL" verify -CAfile root.pem served.pem >/dev/null 2>&1 && vs=yes || vs=no
chk "  and it verifies straight to the root"    yes "$vs"

echo "=== 3b. the GENERATION-QUALIFIED caIssuers target ==="
# ⚠️ SECTION 3 ABOVE PINS THE OTHER HALF OF THE IMPOSSIBILITY, AND BOTH ARE RIGHT.
# /sub.crt must serve g1 (the new generation needs a path UP to the root); a client
# holding a leaf signed by g2 needs g2 (or the served cert cannot chain that leaf).
# One URL cannot do both, which is why the generation belongs IN
# the URL. These assertions are the qualified half; section 3 stays exactly as it was, because
# certificates issued before this shipped still point at the flat path.
SKI2=$("$OSSL" x509 -in sub2.pem -noout -text \
        | awk '/X509v3 Subject Key Identifier/{getline; gsub(/[ :]/,""); print tolower($0); exit}')
chk "PRECONDITION: generation 2 has a subjectKeyIdentifier" yes \
    "$([ -n "$SKI2" ] && echo yes || echo no)"
# ⚠️ AND IT MUST BE THE TOKEN A CLIENT ALREADY HOLDS. The leaf's AKI keyid is its signer's
# SKI — that equality is the whole reason the SKI was chosen over the serial, so assert it
# rather than trusting it.
AKI=$("$OSSL" x509 -in leaf.pem -noout -text \
        | awk '/X509v3 Authority Key Identifier/{getline; gsub(/[ :]/,""); sub(/^keyid/,""); print tolower($0); exit}')
chk "  and the LEAF's AKI keyid equals it (so a client can build the URL)" "$SKI2" "$AKI"

# ⚠️ .p7c AND A BUNDLE — this is the second half and it changed the route.
#
# Slice 1 served the lone generation at /sub/<ski>.crt, and measuring that on the live dc1
# showed it is not enough: a rekeyed generation is SELF-ISSUED but not self-signed, carries
# no AIA of its own, and is name-identical to the generation that signed it, so a client
# that follows the URL lands on g2 with nowhere to go. It has to be a bundle, and a bundle
# does not carry the extension or the MIME content type a single certificate does.
# RFC 5280 §4.2.2.1: a collection is a certs-only
# PKCS#7 — application/pkcs7-mime, .p7c.
curl -s -o q.p7c -D qhdr.txt -w '%{http_code}' "$B/sub/$SKI2.p7c" > qcode.txt
chk "GET /sub/<ski>.p7c -> 200" 200 "$(cat qcode.txt)"
chk "  served as application/pkcs7-mime, not pkix-cert" yes \
    "$(grep -qi '^content-type: *application/pkcs7-mime' qhdr.txt && echo yes || echo no)"
"$OSSL" pkcs7 -inform DER -in q.p7c -print_certs -out q.pem 2>/dev/null
chk "  it really is a parsable PKCS#7" yes \
    "$([ -s q.pem ] && echo yes || echo no)"
chk "  carrying BOTH live generations" 2 \
    "$(grep -c 'BEGIN CERTIFICATE' q.pem | tr -d ' ')"
# The generation asked for comes first — a bag has no required order, but what a client
# asked for should be on top of what it gets.
awk '/BEGIN CERT/{n++} n==1{print}' q.pem > q1.pem
chk "  and the one asked for is FIRST, byte for byte" yes \
    "$([ "$("$OSSL" x509 -in q1.pem   -noout -fingerprint -sha256 | sed 's/.*=//')" \
       = "$("$OSSL" x509 -in sub2.pem -noout -fingerprint -sha256 | sed 's/.*=//')" ] && echo yes || echo no)"
# ⚠️ THE ASSERTION THAT MATTERS, and it is the one slice 1 could not pass. Not "which file
# came back" but: anchored on the ROOT ALONE, with nothing but this fetch, does the leaf
# verify? No -partial_chain, no second -untrusted.
"$OSSL" verify -CAfile root.pem -untrusted q.pem leaf.pem >/dev/null 2>&1 && lv=yes || lv=no
chk "  ⚠️ root + this ONE fetch verifies the leaf — the actual defect" yes "$lv"
# ⚠️ THE CONTROL THAT MAKES THE LINE ABOVE MEAN SOMETHING. The lone generation — exactly
# what the qualified URL used to serve — leaves the walk one hop short. Measured on the lab
# before this changed: "root + g2 -> unable to get local issuer certificate".
"$OSSL" verify -CAfile root.pem -untrusted sub2.pem leaf.pem >/dev/null 2>&1 && sv=yes || sv=no
chk "  CONTROL: generation 2 ALONE does not — one hop short" no "$sv"
# ...and the flat URL's answer cannot verify that leaf either, which is why the qualified
# route exists at all.
"$OSSL" verify -partial_chain -CAfile served.pem -no-CApath leaf.pem >/dev/null 2>&1 && fv=yes || fv=no
chk "  CONTROL: the FLAT /sub.crt answer cannot verify that leaf" no "$fv"
# A generation nobody has must 404, not fall back to a substitute — handing over a different
# key is the exact substitution this ticket is about.
BOGUS=$(printf '%s' "$SKI2" | tr '0-9a-f' '1-9a-f0')
curl -s -o /dev/null -w '%{http_code}' "$B/sub/$BOGUS.p7c" > bcode.txt
chk "an unknown generation is 404, never a substitute" 404 "$(cat bcode.txt)"
# §3f: the single-certificate qualified route is GONE, not kept beside the bundle. Two
# answers at one meaning is how the wrong one gets fetched.
curl -s -o /dev/null -w '%{http_code}' "$B/sub/$SKI2.crt" > ocode.txt
chk "the old single-cert /sub/<ski>.crt is gone" 404 "$(cat ocode.txt)"

echo "=== 4. the symptom on the ticket: an OCSP answer a root-anchored client can verify ==="
OUT=$("$OSSL" ocsp -issuer sub2.pem -cert leaf.pem -url "$B/ocsp" \
        -CAfile root.pem -resp_text -no_nonce 2>&1)
printf '%s\n' "$OUT" > ocsp.out
chk "the status itself is good"                yes \
    "$(printf '%s' "$OUT" | grep -q 'leaf.pem: good' && echo yes || echo no)"
# THE assertion. Before the fix this said "Response Verify Failure / unable to get issuer
# certificate" while still reporting good — a correct answer nobody could trust.
#
# ⚠️ ASSERT THE POSITIVE, NOT THE ABSENCE OF THE ERROR STRING. My first version checked only
# that "Response Verify Failure" was missing, and it PASSED against a run that got
# "Responder Error: unauthorized" — an error response carries no signature, so there is
# nothing for the verify to fail on. Requiring "Response verify OK" cannot pass that way.
chk "the response VERIFIES against the root"   yes \
    "$(printf '%s' "$OUT" | grep -qi 'Response verify OK' && echo yes || echo no)"
chk "  and it is a real answer, not an error"  no \
    "$(printf '%s' "$OUT" | grep -q 'Responder Error' && echo yes || echo no)"
# It verifies because the response carries both generations, not because the client was
# handed them out of band: -CAfile is the root ALONE, no -untrusted.
#
# ⚠️ NAME-COUNTING IS NOT ENOUGH. My first version asserted that "Rekey OCSP Sub CA"
# appeared twice, and it PASSED on the unfixed binary — the responder certificate's own
# issuer line says that name, so two occurrences prove nothing. Look for generation 1's
# SERIAL, which appears only if that certificate is actually in the response.
# openssl renders a long serial as colon-separated hex on its own wrapped line, not as
# "Serial Number: N (0xN)" — build that form rather than guess at it.
S1COLON=$("$OSSL" x509 -in sub1.pem -noout -serial | sed 's/serial=//' \
          | tr 'A-Z' 'a-z' | sed 's/../&:/g; s/:$//')
chk "  and it carried generation 1 itself"     yes \
    "$(printf '%s' "$OUT" | tr -d ' \n' | grep -qF "$(printf '%s' "$S1COLON" | tr -d ' ')" \
       && echo yes || echo no)"

echo "=== the responder cache is keyed on the CA's MATERIAL, not just its id ==="
# ⚠️ A RESPONDER BUILT FROM GENERATION 1 MUST NOT OUTLIVE A REKEY. fastpki-ocsp caches one
# Responder per CA id for the process lifetime. Keyed on the id alone and never invalidated,
# it went on signing OCSP responses — and every CRL regenerated through it — with the OLD key
# and the old authorityKeyIdentifier, while the CA served the new certificate. A relying
# party then cannot match the signature to any published CA certificate.
#
# CaMaterialCache beside it already tracks cert_ref and chain_ref for exactly this and
# reloads when either moves; the responder cache did not.
#
# This is a SOURCE check, and it is weaker than it looks: it proves the invalidation exists,
# not that it fires. A behavioural test needs a rekey performed while the daemon is running,
# against a generation whose key this node holds — which this suite's fixture (two key-less
# generations seeded before start) cannot express. Worth building when a suite grows that
# shape; until then this at least cannot be deleted silently.
OM="$ROOT/src/ocsp/main.cpp"
chk "the responder cache records the material it was built from" yes \
    "$(grep -q 'inst_resp_ref' "$OM" && echo yes || echo no)"
chk "  and rebuilds when that reference moves"  yes \
    "$(grep -q 'rebuilding the responder' "$OM" && echo yes || echo no)"
chk "  keyed on the chain, not only the leaf serial" yes \
    "$(grep -q 'rc.cert_serial + "|" + rc.chain_ref' "$OM" && echo yes || echo no)"

echo
echo "=== OCSP REKEYED CHAIN: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
