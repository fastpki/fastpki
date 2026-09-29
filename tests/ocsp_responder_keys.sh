#!/usr/bin/env bash
# The OCSP responder's RA credential, across every key type FastPKI supports.
#
# Three other services — CMP, OCSP and SCEP — do not use TLS but RA certificates instead,
# which in theory should work with every key type and hash function FastPKI supports:
# RSA, RSA-PSS, EC, Ed and ML-DSA with shake.
#
# For OCSP the answer was NO, and the reason was ours. `basic_sign_compat()` always passed
# EVP_sha256(); EdDSA and ML-DSA are one-shot schemes that hash internally and OpenSSL
# rejects an explicit digest ("invalid digest"). So a responder holding an Ed25519 or
# ML-DSA credential could not sign a single response — every query came back empty and the
# suites read `status good (got '')`.
#
# src/lib/x509.cpp has long carried exactly this rule for certificates. The OCSP
# path, one file away, never got it.
#
# ⚠️ WHY THIS SUITE EXISTS AT ALL, rather than just `OCSP_KEY_SPEC=ED25519 ocsp_perca.sh`.
# That env var makes the key type a variable, which is what was asked for — but a variable
# nobody sets is coverage nobody has. The default run used rsa:2048 and every other cell
# was reachable only by remembering to type it. This suite walks the whole row on every
# run, so a regression in any key type fails the gate instead of waiting for someone to
# think of it.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF

W="$(mktemp -d)"; cd "$W"; PORT=18109
pass=0; fail=0; P=
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=OCSP Key Matrix CA" 3650 keymatrix \
    || { echo "SKIP: could not mint a CA key in a token"; exit 0; }
CA_KEY_URI_SAVED="$CA_KEY_URI"
pg_setup ocsp_responder_keys
trap 'pg_cleanup; kill ${P:-} 2>/dev/null' EXIT
printf "internal\n" > domains.txt; seed_domains "$W/domains.txt"

# One leaf to ask about, with a known serial so the DB row can be seeded.
"$OSSL" req -newkey rsa:2048 -nodes -keyout leaf.key -subj "/CN=probe.internal" \
        -out leaf.csr >/dev/null 2>&1
"$OSSL" x509 -req -in leaf.csr -CA ca.pem -CAkey "$CA_KEY_URI_SAVED" ${CA_OSSL_ARGS:-} \
        -set_serial 43981 -days 365 -out leaf.pem >/dev/null 2>&1   # 0xabcd
chk "PRECONDITION: a leaf to ask about exists" yes \
    "$([ -s leaf.pem ] && echo yes || echo no)"
pg_exec "INSERT INTO certs(serial,status,cn,ca_instance_id,\"notAfter\") \
         VALUES('abcd',0,'probe.internal','keymatrix', extract(epoch from now())::bigint + 86400) \
         ON CONFLICT (serial) DO NOTHING;" >/dev/null

cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI_SAVED
SIGNING_CA_ID=keymatrix
PG_CONNINFO=$PG_CONNINFO
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf

# The BasicOCSPResponse's OWN signatureAlgorithm.
#
# ⚠️ NEVER THE EMBEDDED CERTIFICATE'S. A signed response carries the responder certificate,
# and that certificate has "Signature Algorithm" lines of its own naming what the CA used
# to sign IT — a different key, a different choice, and one this suite never varies. A
# plain `grep -m1` over the whole print would therefore report the CA's digest and pass no
# matter what the responder did. The response's own field is printed before the first
# "Certificate:" block, so stop reading there.
resp_sigalg() {   # <resp.der> -> e.g. sha512WithRSAEncryption
    "$OSSL" ocsp -respin "$1" -resp_text -noverify 2>/dev/null \
        | awk '/^Certificate:/ {exit} /Signature Algorithm:/ {print $3; exit}'
}

# ⚠️ ONE SPEC PER RESPONDER PROCESS, restarted each time. The responder resolves its
# credential per request and caches it, and reusing one process across key types would
# measure the cache rather than the key.
one_key() {   # <keyspec> <label> [OCSP_RESPONSE_MD] [expected substring of the sig alg]
    local spec="$1" label="$2" md="${3:-}" expect="${4:-}"
    rm -rf "$W/$label" && mkdir -p "$W/$label"
    # Delete the previous credential, or resolve_ocsp_cert may pick the older row and the
    # next cell silently re-measures the last one.
    pg_exec "DELETE FROM certs WHERE cert_id='ocsp-ra-keymatrix';" >/dev/null 2>&1
    local key
    key=$(OCSP_KEY_SPEC="$spec" ocsp_responder_key "$W/ca.pem" "$CA_KEY_URI_SAVED" \
                                                    keymatrix "$W/$label" 2>/dev/null) || key=""
    if [ -z "$key" ] || [ ! -s "$key" ]; then
        # A key type this OpenSSL cannot generate is a real, visible outcome — not a pass.
        chk "$label: the responder credential was provisioned" yes no
        return 0
    fi
    printf 'OCSP_RESPONDER_KEY=%s\n' "$key" > "$W/$label.conf"
    [ -n "$md" ] && printf 'OCSP_RESPONSE_MD=%s\n' "$md" >> "$W/$label.conf"
    cat bootstrap.conf "$W/$label.conf" > "$W/$label.bootstrap.conf"
    "$ROOT/build/fastpki-ocsp" --config "$W/$label.bootstrap.conf" >"$W/$label.log" 2>&1 & P=$!
    # Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
  wait_port "$PORT" "$P" || true
    if ! kill -0 $P 2>/dev/null; then
        chk "$label: the responder starts" yes no
        return 0
    fi
    "$OSSL" ocsp -issuer ca.pem -cert leaf.pem -url "http://127.0.0.1:$PORT/ocsp/keymatrix" \
            -resp_text -noverify -respout "$W/$label.der" > "$W/$label.out" 2>&1
    local status
    status=$(grep -oE '^\s*Cert Status: [a-z]+' "$W/$label.out" | head -1 | awk '{print $3}')
    chk "$label: the responder answers with a status" good "${status:-<none>}"
    # ⚠️ AND THE SIGNATURE VERIFIES. "answers" alone would pass for a response signed with
    # the wrong parameters — which is exactly the shape where the bytes decoded
    # cleanly and only the signature was wrong.
    "$OSSL" ocsp -issuer ca.pem -cert leaf.pem -url "http://127.0.0.1:$PORT/ocsp/keymatrix" \
            -CAfile ca.pem -VAfile "$W/$label/ocspresp-keymatrix.pem" \
            > "$W/$label.verify" 2>&1
    chk "  $label: the response verifies" yes \
        "$(grep -q "Response verify OK" "$W/$label.verify" && echo yes || echo no)"
    # Name the algorithm actually used, so the cell cannot pass while quietly falling back.
    local sigalg
    sigalg=$("$OSSL" x509 -in "$W/$label/ocspresp-keymatrix.pem" -noout -text 2>/dev/null \
             | grep -m1 "Public Key Algorithm" | sed 's/.*: //')
    echo "      responder key algorithm: ${sigalg:-<unreadable>}"
    # Digest axis: name the algorithm the RESPONSE was signed with. Decoded from the
    # bytes, not inferred from the setting — the whole defect was that the setting did not
    # exist and every response came back sha256 regardless.
    if [ -n "$expect" ]; then
        local ralg; ralg=$(resp_sigalg "$W/$label.der")
        chk "  $label: response signed with '$expect'" yes \
            "$(printf '%s' "$ralg" | grep -qi -- "$expect" && echo yes || echo no)"
        echo "      response signatureAlgorithm: ${ralg:-<unreadable>}"
    fi
    kill $P 2>/dev/null; wait $P 2>/dev/null; P=
}

echo "=== every responder key type must sign a verifiable response ==="
one_key "rsa:2048"  rsa
one_key "EC:P-256"  ec
# ⚠️ THE TWO THAT WERE BROKEN. Both are one-shot schemes; both were handed EVP_sha256()
# and refused to sign at all. If either regresses, this is where it shows.
one_key "ED25519"   ed25519
one_key "ML-DSA-65" mldsa65

echo
echo "=== and the DIGEST axis: OCSP_RESPONSE_MD ==="
# The ask covers all the key types AND the hash functions (sha2, sha3). The key
# half is above. The hash half did not exist for OCSP at all: basic_sign_compat was called
# with a hardcoded EVP_sha256(), so every response on every deployment was sha256 and there
# was no setting to ask for anything else — while the TLS services had answered the same
# question through <SVC>_KEY_MD.
#
# ⚠️ THE BASELINE MUST BE MEASURED, NOT ASSUMED. Without this first row a later row could
# pass because the responder emits the same thing for every input.
one_key "rsa:2048"  md_default ""          "sha256WithRSAEncryption"
one_key "rsa:2048"  md_sha512  "sha512"    "sha512"
# sha3 on an RSA key — the half of the question that had never been asked of any FastPKI
# signature path. An RSA key can sign under it; nothing about the key restricts the digest.
one_key "rsa:2048"  md_sha3    "sha3-256"  "sha3-256"
# ⚠️ THE ANTI-VACUITY CELL. EC must IGNORE the setting: the digest has to match the curve's
# security level, and leaf_signing_md auto-matches for exactly that reason. An
# implementation that simply forwards OCSP_RESPONSE_MD to the signer passes every row above
# and fails this one — which is the difference between honouring a request where a choice
# exists and honouring it where there is none. (On a TOKEN key the same mistake hands
# CKM_ECDSA a digest of the wrong length; the file key used here cannot show that, so what
# is asserted is the policy that protects the token case.)
one_key "EC:P-256"  md_ec_ignored "sha512" "ecdsa-with-SHA256"
# A digest name this build of OpenSSL does not know must not take OCSP down. Refusing to
# answer any revocation query over an unrecognised label would be a far worse outcome than
# falling back, so the responder starts, answers, and signs with the key's default.
one_key "rsa:2048"  md_unknown "sha42"     "sha256WithRSAEncryption"

echo
echo "=== a responder key REPLACED under a running responder is used without a restart ==="
# The HA procedure deletes the responder key and renew-service-certs --create-missing makes a
# replicable one at the same reference, with a new certificate. A responder built before
# that held the old key and refused every request ("does not match the OCSP responder key
# this process holds") until restarted. Same key reference here, new key behind it.
pg_exec "DELETE FROM certs WHERE cert_id='ocsp-ra-keymatrix';" >/dev/null 2>&1
rm -rf "$W/repl1" "$W/repl2"; mkdir -p "$W/repl1" "$W/repl2"
K1=$(ocsp_responder_key "$W/ca.pem" "$CA_KEY_URI_SAVED" keymatrix "$W/repl1" 2>/dev/null) || K1=""
KP="$W/replaced.key"; cp "$K1" "$KP" 2>/dev/null
printf 'OCSP_RESPONDER_KEY=%s\n' "$KP" | cat bootstrap.conf - > "$W/repl.bootstrap.conf"
"$ROOT/build/fastpki-ocsp" --config "$W/repl.bootstrap.conf" >"$W/repl.log" 2>&1 & P=$!
wait_port "$PORT" "$P" || true
ask_status() {   # <verify-with.pem> -> "good yes" when answered good and the signature verifies
    "$OSSL" ocsp -issuer ca.pem -cert leaf.pem -url "http://127.0.0.1:$PORT/ocsp/keymatrix" \
            -CAfile ca.pem -VAfile "$1" > "$W/repl.out" 2>&1
    printf '%s %s' "$(grep -oE 'leaf.pem: [a-z]+' "$W/repl.out" | awk '{print $2}')" \
        "$(grep -q 'Response verify OK' "$W/repl.out" && echo yes || echo no)"
}
chk "before: the responder answers with the first key" "good yes" "$(ask_status "$W/repl1/ocspresp-keymatrix.pem")"
pg_exec "DELETE FROM certs WHERE cert_id='ocsp-ra-keymatrix';" >/dev/null 2>&1
K2=$(ocsp_responder_key "$W/ca.pem" "$CA_KEY_URI_SAVED" keymatrix "$W/repl2" 2>/dev/null) || K2=""
cp "$K2" "$KP" 2>/dev/null
chk "PRECONDITION: the key behind the reference really changed" no \
    "$(cmp -s "$K1" "$KP" && echo yes || echo no)"
chk "after: the same process answers with the new key and certificate" "good yes" \
    "$(ask_status "$W/repl2/ocspresp-keymatrix.pem")"
kill $P 2>/dev/null; wait $P 2>/dev/null; P=

echo "=== OCSP RESPONDER KEYS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
