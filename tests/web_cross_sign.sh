#!/usr/bin/env bash
# Cross-signing a foreign CA from the CONSOLE, and the registry that gates it.
#
# The CLI path is covered by cross_sign_foreign.sh. This suite exists for the thing the
# CLI does NOT have: an allowlist. The console signs a FINGERPRINT out of `foreign_anchors`
# and never a pasted certificate, so the certificate that gets vouched for cannot be one
# that was never vetted. The single most important assertion here is the 404 on an
# unregistered fingerprint — without it the registry is decoration, and a table nothing
# enforces is exactly the "reader with no writer" shape that has shipped inert three times
# on this project.
#
# Refusals are checked for the RIGHT REASON. A cross-sign that 400s because the CA id was
# wrong looks identical to one that 400s because the envelope guard fired, and a refusal
# firing for the wrong reason reads exactly like a pass.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/json_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"   # macOS
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18461
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
skipout(){ echo "  [SKIP] $1"; echo; echo "=== WEB CROSS-SIGN: PASS=$pass FAIL=$fail SKIP=1 ==="; exit 0; }

pg_setup web_cross_sign
trap 'pg_cleanup; kill ${P:-} 2>/dev/null' EXIT
hsm_available || skipout "CA keys are token-only — $(hsm_skip_reason)"

# Ours: the CA that does the vouching.
ca_in_token ours.pem "/CN=Our Issuing CA/O=FastPKI" 3650 ourca
OUR_KEY="$CA_KEY_URI"

source "$ROOT/tests/user_helpers.sh"
seed_web_user boss bosspw admin
seed_web_user rq   rqpw    requester
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
"$ROOT/build/fastpki-ca" --config bootstrap.conf add ourca --name "Ours" \
    --ca-pem "$W/ours.pem" --ca-key "$OUR_KEY" >/dev/null 2>&1

"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" WEB_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat srv.log; skipout "fastpki-web could not start"; }
U="http://127.0.0.1:$PORT"
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null
curl -s -c rq.cj   -d 'username=rq&password=rqpw'     "$U/api/login" >/dev/null

# Theirs: a foreign root we do not control, plus a leaf to prove non-CAs are refused.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout foreign.key -out foreign.pem -days 3650 \
    -subj "/O=Partner Inc/CN=Partner Root CA" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.pem -days 365 \
    -subj "/CN=not-a-ca.partner.example" -addext "basicConstraints=critical,CA:FALSE" >/dev/null 2>&1
# A second CA, registered but never signed — proves the list is a list, not one row.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.pem -days 3650 \
    -subj "/O=Other Ltd/CN=Other Root CA" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
FP_FOREIGN=$("$OSSL" x509 -in foreign.pem -noout -fingerprint -sha256 \
             | sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z')

reg(){ curl -s -o "$2" -w '%{http_code}' -b "${3:-boss.cj}" "$U/api/foreign-anchors" \
        --data-urlencode "pem@$1" --data-urlencode "note=vetted out of band"; }
xs(){ curl -s -o "$2" -w '%{http_code}' -b "${3:-boss.cj}" \
        "$U/api/ca-instances/ourca/cross-sign" "${@:4}"; }

echo "=== the registry refuses what it should ==="
C=$(reg leaf.pem r1.json)
chk "registering a NON-CA -> 400" 400 "$C"
chk "  ... and the message says why" yes \
    "$(grep -qi 'not a CA' r1.json && echo yes || echo no)"

cat foreign.pem other.pem > bundle.pem
C=$(reg bundle.pem r2.json)
chk "registering a BUNDLE -> 400" 400 "$C"
chk "  ... and the message says exactly one" yes \
    "$(grep -qi 'exactly one\|single PEM' r2.json && echo yes || echo no)"

C=$(reg foreign.pem r3.json rq.cj)
chk "a requester cannot register an anchor -> 403" 403 "$C"

echo "=== registering, and the fingerprint is the identity ==="
C=$(reg foreign.pem r4.json)
chk "admin registers the foreign CA -> 201" 201 "$C"
chk "  ... keyed on the SHA-256 of the DER, not the subject" "$FP_FOREIGN" \
    "$(json_str "$(cat r4.json)" fingerprint)"
C=$(reg other.pem r5.json)
chk "a second CA registers too -> 201" 201 "$C"
curl -s -b boss.cj "$U/api/foreign-anchors" -o list.json
chk "both are listed" 2 "$(grep -o '"fingerprint"' list.json | wc -l | tr -d ' ')"

echo "=== the allowlist is ENFORCED, not advisory ==="
# The point of the whole table. A fingerprint that is not a row must not sign, even
# though the certificate itself is a perfectly valid CA the operator holds.
FP_UNREG=$("$OSSL" x509 -in ours.pem -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z')
C=$(xs . u1.json boss.cj --data-urlencode "fingerprint=$FP_UNREG" \
      --data-urlencode 'permitted=DNS:partner.example' --data-urlencode 'pathlen=0')
chk "cross-signing an UNREGISTERED fingerprint -> 404" 404 "$C"
chk "  ... and the message names the registry" yes \
    "$(grep -qi 'registry\|register it first' u1.json && echo yes || echo no)"

echo "=== the envelope is refused, not defaulted ==="
C=$(xs . e1.json boss.cj --data-urlencode "fingerprint=$FP_FOREIGN" --data-urlencode 'pathlen=0')
chk "no permitted subtrees -> 400" 400 "$C"
chk "  ... and the message says why (any name at all)" yes \
    "$(grep -qi 'name constraints\|permitted subtrees' e1.json && echo yes || echo no)"

C=$(xs . e2.json boss.cj --data-urlencode "fingerprint=$FP_FOREIGN" \
      --data-urlencode 'permitted=DNS:partner.example')
chk "no pathlen -> 400" 400 "$C"
chk "  ... and the message says why (further CAs)" yes \
    "$(grep -qi 'pathlen' e2.json && echo yes || echo no)"

C=$(xs . e3.json rq.cj --data-urlencode "fingerprint=$FP_FOREIGN" \
      --data-urlencode 'permitted=DNS:partner.example' --data-urlencode 'pathlen=0')
chk "a requester cannot cross-sign -> 403" 403 "$C"

echo "=== a real cross-certificate, decoded ==="
C=$(xs . ok.json boss.cj --data-urlencode "fingerprint=$FP_FOREIGN" \
      --data-urlencode 'permitted=DNS:partner.example,IP:10.0.0.0/8' \
      --data-urlencode 'pathlen=0' --data-urlencode 'days=365')
chk "cross-sign with the envelope supplied -> 201" 201 "$C"
SERIAL=$(json_str "$(cat ok.json)" serial)
chk "  ... a serial came back" yes "$([ -n "$SERIAL" ] && echo yes || echo no)"
json_pem "$(cat ok.json)" pem xc.pem
if [ -s xc.pem ]; then
    T=$("$OSSL" x509 -in xc.pem -noout -text 2>/dev/null)
    chk "subject is the FOREIGN CA's" yes \
        "$(printf '%s' "$T" | grep -A1 'Subject:' | grep -q 'Partner Root CA' && echo yes || echo no)"
    chk "issuer is OURS" yes \
        "$(printf '%s' "$T" | grep 'Issuer:' | grep -q 'Our Issuing CA' && echo yes || echo no)"
    chk "carries the DNS permitted subtree" yes \
        "$(printf '%s' "$T" | grep -q 'partner.example' && echo yes || echo no)"
    # The console's own worked example is CIDR (`IP:10.0.0.0/8`). RFC 5280 encodes an
    # iPAddress constraint as address+mask and OpenSSL will not parse a prefix length, so
    # for months the hint the UI printed produced `bad ip address`. Assert the ADVERTISED
    # form reaches the certificate as a real constraint — the shipped-vs-tested question.
    chk "the CIDR the console advertises became a real IP constraint" yes \
        "$(printf '%s' "$T" | grep -q '10.0.0.0/255.0.0.0' && echo yes || echo no)"
    chk "carries pathlen 0" yes \
        "$(printf '%s' "$T" | grep -qi 'pathlen:0' && echo yes || echo no)"
    # Byte-identical subject, or it chains to nothing the foreign CA ever issued.
    chk "subject DER matches the registered certificate exactly" yes \
        "$([ "$("$OSSL" x509 -in xc.pem -noout -subject -nameopt RFC2253)" \
           = "$("$OSSL" x509 -in foreign.pem -noout -subject -nameopt RFC2253)" ] \
           && echo yes || echo no)"
    chk "it verifies against OUR CA" yes \
        "$("$OSSL" verify -CAfile "$W/ours.pem" -partial_chain xc.pem >/dev/null 2>&1 \
           && echo yes || echo no)"
else
    chk "the response carried a downloadable PEM" yes no
fi

echo "=== it is stored as someone else's CA, not one of ours ==="
q(){ psql "$PG_CONNINFO" -tAc "$1" 2>/dev/null | tr -d ' '; }
chk "the cross-certificate is a certs row" 1 \
    "$(q "SELECT count(*) FROM certs WHERE serial='$SERIAL'")"
# No id and no private key: we signed it, but the key behind it is theirs. An `id` would
# make it addressable as one of our CAs at /{ca_id}, and a private_key would be a lie.
chk "  ... with NO ca id (it is not one of our CAs)" 1 \
    "$(q "SELECT count(*) FROM certs WHERE serial='$SERIAL' AND id IS NULL")"
chk "  ... and NO private key (we do not hold theirs)" 1 \
    "$(q "SELECT count(*) FROM certs WHERE serial='$SERIAL' AND (private_key IS NULL OR private_key='')")"
chk "the audit log recorded who signed it" 1 \
    "$(q "SELECT count(*) FROM audit_log WHERE action='web_ca_cross_signed' AND actor='boss'")"
# CA:TRUE, but no CA of ours: the Inventory is where it can be found and revoked. Skipping
# every CA:TRUE row hid it from every page.
chk "  ... and the Inventory lists it, marked as a cross-certificate" yes \
    "$(curl -s -b boss.cj "$U/api/certs?limit=500" | tr '}' '\n' | grep "\"serial\":\"$SERIAL\"" | grep -q '"crossCert":true' && echo yes || echo no)"

echo "=== the Hash field is honoured (an RSA CA can sign under any digest) ==="
# cross_sign_foreign_ca signed with the key's default whatever was asked.
C=$(xs . md.json boss.cj --data-urlencode "fingerprint=$FP_FOREIGN" \
      --data-urlencode 'permitted=DNS:partner.example' --data-urlencode 'pathlen=0' \
      --data-urlencode 'days=30' --data-urlencode 'md=sha384')
chk "cross-sign with md=sha384 -> 201" 201 "$C"
json_pem "$(cat md.json)" pem xc384.pem
chk "  ... signed with SHA-384" yes \
    "$("$OSSL" x509 -in xc384.pem -noout -text 2>/dev/null | grep -m1 'Signature Algorithm' | grep -qi 'sha384' && echo yes || echo no)"

echo "=== removing an anchor stops new signatures, and says so ==="
C=$(curl -s -o rm.json -w '%{http_code}' -b boss.cj -X DELETE \
      "$U/api/foreign-anchors/$FP_FOREIGN")
chk "admin removes the anchor -> 200" 200 "$C"
chk "  ... and the response says the issued cert stays valid" yes \
    "$(grep -qi 'stays valid' rm.json && echo yes || echo no)"
C=$(xs . after.json boss.cj --data-urlencode "fingerprint=$FP_FOREIGN" \
      --data-urlencode 'permitted=DNS:partner.example' --data-urlencode 'pathlen=0')
chk "cross-signing the removed anchor -> 404" 404 "$C"
chk "the already-issued cross-certificate is still there" 1 \
    "$(q "SELECT count(*) FROM certs WHERE serial='$SERIAL'")"

echo
echo "=== WEB CROSS-SIGN: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
