#!/usr/bin/env bash
# CMP RA mode via CMP_RA_CERT_ID_PREFIX — the branch a real deployment actually takes.
#
# ── Why this exists ──────────────────────────────────────────────────────────────
#
# `fastpki-cmp` finds its RA certificate two different ways:
#
#   db.get_cert_by_cert_id(cmp_ra_cert_id_prefix + "-" + ca_id)      // PER CA
#
# `deploy/bootstrap.compose.conf` ships `CMP_RA_CERT_ID_PREFIX=cmp-ra`, so every real deployment takes
# that path. The CMP_RA_CERT PEM-file branch is GONE: a file cannot express one
# certificate per CA, so §3f says remove it rather than keep it as a fallback. And
# `get_cert_by_cert_id` reads `certs.cert_id` — a column that had a reader and NO WRITER
# until `2adbad6`. Nothing ever set it, so on a real deployment the lookup always came
# back empty and the server logged, every start:
#
#     CMP: refusing the transaction for CA 'ca' — no valid certificate for cert_id
#          'cmp-ra-ca' (missing, or revoked)
#
# RA mode could not be switched on, no matter what the operator issued. The suite stayed
# green throughout because it exercised the other branch — the same shape as the CA
# KeyUsage defect (`edb2b45`), where a test helper minted differently from the product.
# When a test must differ from the shipped configuration to pass, the difference is the
# bug.
#
# So this drives the SHIPPED branch end to end: the console issues an HSM-keyed
# certificate tagged `cmp-ra-ca`, and CMP picks it up. It fails against
# any build without the `certs.cert_id` writer.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; WPORT=18224; CPORT=18225
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=CMP RA CertId CA" 3650
cp ca.pem root.pem
pg_setup cmp_ra_cert_id
source "$ROOT/tests/user_helpers.sh"
seed_web_user admin testpw admin
printf "internal\n" > domains.txt
seed_domains $W/domains.txt
P=; C=
trap 'pg_cleanup; kill $P $C 2>/dev/null' EXIT

# The RA key handle, exactly as the deployment would name it. The console refuses to
# issue a transport certificate against a key the listener does not load, so
# both sides must name the same object — that check is part of what this proves.
TOKEN=$(echo "$CA_KEY_URI" | sed -n 's/.*token=\([^;]*\).*/\1/p')
RA_URI="pkcs11:token=$TOKEN;object=cmp-ra-key;type=private?pin-value=1234"

cat > cmp.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
CMP_BIND=127.0.0.1
CMP_PORT=$CPORT
CMP_PATH=/cmp
CMP_RA_CERT_ID_PREFIX=cmp-ra
CMP_RA_KEY=$RA_URI
LOG_LEVEL=info
EOF
hsm_conf_lines >> cmp.conf
seed_ca_from_conf cmp.conf
# CMP PBM is PER USER — the global CMP_PBM_SECRET is gone. Every reference the
# client sends below needs its own `keys` row, or the server installs no secret and the
# MAC cannot verify. That is the point of the change: there is nothing to fall back to.
pg_exec "INSERT INTO keys(kid,protocol,key) VALUES('1234','cmp','0000') ON CONFLICT (kid,protocol) DO UPDATE SET key=EXCLUDED.key;" >/dev/null
# The credential needs an IDENTITY holding a profile grant, or
# resolve_profile refuses. seed_enrolling_identity leaves an existing role alone.
seed_enrolling_identity 1234
CA_ID=ca

echo "=== 1. with no certificate for this CA, the TRANSACTION is refused and says so ==="
# ⚠️ THE HARNESS MINTS THE RA KEY NOW. cmp's startup mint is gone, so RA mode is only
# on when the key already exists — and this section is about having the KEY but no
# CERTIFICATE for the CA, which is precisely the state an operator is in between creating
# the credential and issuing it. Without this the section would test "no key at all", which
# is a different scenario (and is covered by the two assertions below).
# The RA credential's key type is a variable, so this whole suite — a real CMP ir
# and rr against a real RA — becomes one row of the server-side matrix
# rather than needing a second script:
#
#     RA_KEY_SPEC=EC:prime256v1 bash tests/cmp_ra_cert_id.sh
#
# Default unchanged. ⚠️ --id matters for anything but RSA: without CKA_ID the provider
# cannot associate private with public and dies with "No CKA_ID in source object".
#
# ⚠️ A FAILED MINT IS NOT A PRODUCT RESULT, AND THIS USED TO READ AS ONE. The mint failure
# was swallowed with a one-line note and the suite ran on regardless — so with
# RA_KEY_SPEC=ED25519 on a machine whose PKCS#11 stack cannot mint one, it reported
# `PASS=7 FAIL=4`. Those four are "there is no RA key at all", which is a DIFFERENT
# scenario the suite already covers on purpose; nothing in the counts says the key never
# existed. Reported as a matrix cell that would say "CMP does not work with Ed25519", which
# is a claim about this machine's SoftHSM, not about FastPKI.
#
# So: capture what the tool actually said, and for a NON-DEFAULT keyspec skip with that
# reason rather than measure a server that has nothing to sign with.
# ⚠️ TWO tools, because they answer different questions — and using only the first one is
# what left two cells of the key-type matrix unmeasured.
#
# `pkcs11-tool --keypairgen` has a hardcoded table of key-type spellings: rsa:N, EC:curve,
# ED25519. Ask it for anything else and it says `Unknown key pair type rsa-pss:2048` —
# which is the TOOL failing to name the type, not the token refusing to make it. I reported
# both of those refusals as "not results", and they were not.
#
# The PRODUCT never uses that tool. `generate_key_in_token()` hands the algorithm name
# straight to the pkcs11 provider (`EVP_PKEY_CTX_new_from_name(name, "?provider=pkcs11")`)
# precisely so a token that supports something is askable for it — the comment there says
# an allow-list "is exactly the thing that goes stale". So for a spec pkcs11-tool cannot
# spell, ask the provider the way the product does. Measured: RSA-PSS mints fine this way
# on a stack whose pkcs11-tool rejects the name outright.
#
# ⚠️ ROUTE BY SPEC — do NOT "try pkcs11-tool first and fall back". I wrote it that way and it
# was wrong in the most expensive direction: `pkcs11-tool --key-type rsa-pss` does not refuse,
# it SUCCEEDS and mints an ordinary RSA:2048 key with no CKA_ALLOWED_MECHANISMS at all. So the
# fallback never fired, the suite went 38/0, and the cell would have reported "RSA-PSS works"
# having tested plain RSA a second time. A tool that quietly accepts a spec it does not
# implement makes try-then-fallback pick the wrong tool every time.
# Minted by hsm_mint_key() in tests/hsm_helpers.sh — ONE implementation of "mint a key the
# way the product does", shared with scep.sh. It routes by spec and sends anything outside
# pkcs11-tool's table to the pkcs11 provider, exactly as generate_key_in_token() does; see
# the ⚠️ on that helper for why try-then-fallback across the two tools measures the wrong key.
# This suite used to carry its own copy, and the two drifted: the copy in hsm_helpers.sh was
# missing ec:edwards*, which cost an unmeasured Ed25519 SCEP row.
hsm_mint_key "$TOKEN" cmp-ra-key C0 "${RA_KEY_SPEC:-rsa:2048}" || MINT_FAILED=1
MINT_VIA="$HSM_MINT_VIA"; MINT_ERR="$HSM_MINT_ERR"


# ⚠️ A matrix cell must prove it tested the key type it NAMES. `RSA-PSS` is not a PKCS#11
# key type — the token stores it as CKK_RSA with `CKA_ALLOWED_MECHANISMS` restricted to the
# PSS set — so a provider that quietly ignored the request would leave an ordinary RSA key
# behind, the suite would go 38/0, and the cell would report "RSA-PSS works" having tested
# RSA twice. Ask the token what it actually holds.
if [ -z "${MINT_FAILED:-}" ] && [ -n "${RA_KEY_SPEC:-}" ]; then
    # ⚠️ -B2, not just -A6. pkcs11-tool prints the TYPE on the "Private Key Object; ..."
    # line ABOVE the label, so a block starting at `label:` structurally cannot contain the
    # thing this is about to assert — it reported "the token does not hold an ML-DSA key"
    # about a token that did. Same shape as reading a hex mechtype as an absent mechanism.
    KEYDESC=$("$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$TOKEN" --login --pin 1234 \
              -O --type privkey 2>/dev/null | grep -B2 -A6 'label:  *cmp-ra-key')
    case "$(printf '%s' "$RA_KEY_SPEC" | tr 'A-Z' 'a-z')" in
      rsa-pss)
        # ⚠️ What this pins is WHICH TOOL minted the key, and that is deliberate.
        #
        # The regression this exists to stop is real and already happened: asking
        # `pkcs11-tool --key-type rsa-pss` does not fail, it mints an ordinary RSA:2048 key
        # with no mechanism restriction, so the cell reported 38/0 having tested plain RSA a
        # second time. Routing by spec (above) removes that structurally; this asserts the
        # routing actually held.
        #
        # It deliberately does NOT try to confirm the key's CKA_ALLOWED_MECHANISMS here.
        # Both ways of asking break on THIS harness for reasons that have nothing to do with
        # FastPKI: through the p11-kit client the attribute read returns
        # `CKR_DEVICE_ERROR`, and a behavioural sign probe dies inside p11-kit itself
        # (`'bound != NULL' not true at fixed0_C_CloseSession`) on macOS. Read either as a
        # product answer and you publish a false one. Asked through the module directly, the
        # same key does list the PSS-only set — so the restriction is there; this harness
        # just cannot see it. Confirm the mechanism set in the image (deploy/lab-test.sh).
        chk "the RA key was minted through the PROVIDER, not pkcs11-tool" provider "$MINT_VIA" ;;
      ml-dsa*|slh-dsa*)
        # ⚠️ DO NOT ask pkcs11-tool to NAME this key. It cannot, and it does not pretend to:
        #
        #     Private Key Object; unknown key algorithm 74
        #
        # 74 is 0x4A, the PKCS#11 v3 PQC key-type range. The tool predates the name, so
        # "does it say ML-DSA" answers a question about the TOOL's vocabulary. That exact
        # confusion already produced one wrong report, where a hex mechtype was read
        # as an absent mechanism. What CAN be trusted here is the negative: it is not RSA
        # and not EC, so the provider did not quietly substitute a classic key.
        chk "the token holds a non-classic key type (not RSA, not EC)" yes \
            "$(printf '%s' "$KEYDESC" | grep -i 'Private Key Object' \
               | grep -qiE 'RSA|EC[; ]|EC$|ECDSA' && echo no || echo yes)"
        chk "  and it was minted through the PROVIDER" provider "$MINT_VIA"
        # The key type itself is asserted where the PRODUCT names it — on the certificate
        # fastpki actually issued and used (search: RA_KEY_SPEC_CHECK below).
        ;;
    esac
fi
if [ -n "${MINT_FAILED:-}" ]; then
    # ⚠️ The DEFAULT keyspec may NOT skip. A suite that can skip its own baseline stops
    # asserting the moment the environment drifts and still counts as ok in the run
    # totals — which is how four mesh suites asserted nothing for weeks. rsa:2048 is what
    # every gate runs, so a failure there is a real environment fault and must be loud.
    if [ -n "${RA_KEY_SPEC:-}" ] && [ "$RA_KEY_SPEC" != "rsa:2048" ]; then
        echo "  [SKIP] this PKCS#11 stack cannot mint an RA key of type '$RA_KEY_SPEC'"
        echo "         pkcs11-tool said: $(printf '%s' "$MINT_ERR" | head -2 | tr '\n' ' ')"
        echo "         Nothing about fastpki-cmp was measured. Run this cell in the shipped"
        echo "         image (deploy/lab-test.sh), where the patched p11-kit lives."
        echo
        echo "=== CMP RA CERT_ID: PASS=0 FAIL=0 SKIP=1 ==="
        exit 0
    fi
    echo "  [FAIL] the default RA key (rsa:2048) could not be minted: $(printf '%s' "$MINT_ERR" | head -1)"
    fail=$((fail+1))
fi
"$ROOT/build/fastpki-cmp" --config cmp.conf > cmp1.log 2>&1 & C=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "cmp.conf" CMP_PORT "$C" || true
chk "the server started" yes "$(kill -0 $C 2>/dev/null && echo yes || echo no)"
# ⚠️ CHANGED WHERE THIS SURFACES, and the assertion has to follow. The RA
# certificate is per CA now, so startup cannot say which CAs are missing one — it does not
# know which CA a request will name. The refusal therefore happens per TRANSACTION, which
# is also the better thing to assert: a log line is a proxy, a refused request is the
# behaviour. Ask for a certificate and expect to be turned away.
# ⚠️ PBM-PROTECTED, not -unprotected_requests. This config sets
# no unprotected mode exists, so such a request is turned away at AUTH and never
# reaches the RA binding at all — the "no cert issued" check would then pass for entirely
# the wrong reason and the log assertion below would (correctly) fail. Same credentials the
# working exchange in section 3 uses, so the only thing missing is the RA certificate.
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out scratch1.key >/dev/null 2>&1
# -recipient is now REQUIRED (strict, option (a)). Without it
# this request would be refused as wrongAuthority and the assertion below would pass for
# a reason that has nothing to do with the missing RA certificate it is testing.
"$OSSL" cmp -cmd ir -server "http://127.0.0.1:$CPORT/cmp/$CA_ID" \
    -recipient "/CN=CMP RA CertId CA" \
    -trusted ca.pem -secret pass:0000 -ref 1234 -keep_alive 0 -newkey scratch1.key \
    -subject "/CN=nora.internal" -certout nora.pem >ir0.log 2>&1 || true
chk "authenticated request, but no RA certificate -> no cert issued" yes \
    "$([ ! -f nora.pem ] && echo yes || echo no)"
chk "and the refusal names the per-CA id it wanted" yes \
    "$(grep -q "no valid certificate for cert_id 'cmp-ra-ca'" cmp1.log && echo yes || echo no)"
# ⚠️ REMOVED CMP's STARTUP MINT — OCSP, CMP and SCEP do not need one at startup;
# their keys are generated from the console once the CAs exist. This used to assert `minted the RA key inside the token`; that behaviour is
# gone, so it now asserts the state this section actually sets up — RA mode ON because the
# key exists, with no certificate for the CA yet.
chk "and RA mode is ON (the key exists, the certificate does not)" yes \
    "$(grep -q "CMP RA mode:" cmp1.log && echo yes || echo no)"
chk "and cmp is still running" yes "$(kill -0 $C 2>/dev/null && echo yes || echo no)"
kill $C 2>/dev/null; wait $C 2>/dev/null

echo "=== 2. the console certifies the RA key that already exists ==="
# keygen=false — "use a key already in the token". ⚠️ WHO put it there has changed:
# cmp used to mint it on first start, and now nothing does but an operator (via this same
# form, with keygen=true). Section 1 pre-mints it so this section can test the half it is
# about — certifying an existing token key and tagging the certificate `cmp-ra-<ca_id>`.
# Asking the console to generate over it here would (correctly) be refused as handleTaken.
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$WPORT
WEB_ALLOW_REVOKE=true
CMP_RA_CERT_ID_PREFIX=cmp-ra
CMP_RA_KEY=$RA_URI
LOG_LEVEL=err
EOF
hsm_conf_lines >> web.conf
"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$WPORT"
curl -s -c cj.txt -d 'username=admin&password=testpw' "$U/api/login" >/dev/null
# ku/eku exactly as the fixed "Serve as -> CMP RA" preset now posts them. The API has
# always accepted both; nothing drove them from the purpose control, so an RA certificate
# came out with the form's TLS defaults (serverAuth + clientAuth) and no id-kp-cmcRA.
# === the downloaded CMP config always names a recipient ===
# We ship a valid config with the recipient filled in, so a client following it should
# not fail. Right here is the state that used to break that: the CA exists, the
# console is up, and the RA certificate has NOT been issued yet. {{CMP_RA_CN}} resolved to
# empty, so the file went out with a bare `recipient = ` and openssl cmp sends a NULL-DN.
#
# ⚠️ Asserted BEFORE the issuance below on purpose. Afterwards the RA certificate exists
# and the fallback is never taken, so the same assertions would pass without the fix.
CFG0=$(curl -s -b cj.txt "$U/api/client-config/cmp?ca=$CA_ID")
CACN=$("$OSSL" x509 -in ca.pem -noout -subject 2>/dev/null | sed -n 's/.*CN *= *//p' | head -1)
chk "PRECONDITION: no RA certificate yet" "" \
    "$(pg_exec "select coalesce(cert_id,'') from certs where cert_id='cmp-ra-ca';" 2>/dev/null | tr -d ' ')"
case "$CFG0" in *'{{CMP_RA_CN}}'*) RAW=yes;; *) RAW=no;; esac
chk "the token is substituted, not shipped raw" no "$RAW"
# ⚠️ Read the LINE, do not grep for it. `grep -F` splits a pattern on newlines and treats
# the parts as alternatives, so a pattern ending in one carries an empty alternative that
# matches any input — the assertion would pass whatever the file said.
RCPT=$(printf '%s\n' "$CFG0" | sed -n 's/^recipient *= *//p' | head -1)
chk "recipient is NOT left empty" yes "$([ -n "$RCPT" ] && echo yes || echo no)"
chk "  it falls back to the CA's own subject CN" "\"/CN=$CACN\"" "$RCPT"

ISS=$(curl -s -b cj.txt -X POST "$U/api/certs/request-hsm" \
        --data-urlencode "ca_instance=$CA_ID" --data-urlencode "keyref=$RA_URI" \
        --data-urlencode 'cn=ra.internal' --data-urlencode 'cert_id=cmp-ra-ca' \
        --data-urlencode 'ku=digitalSignature' \
        --data-urlencode 'eku=1.3.6.1.5.5.7.3.28' \
        --data-urlencode 'keygen=false')
SER=$(printf '%s' "$ISS" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')
chk "the console issued it" yes "$([ -n "$SER" ] && echo yes || echo no)"
[ -n "$SER" ] || { echo "  response: $ISS"; echo "=== CMP RA CERT_ID: PASS=$pass FAIL=$((fail+1)) ==="; exit 1; }

# THE assertion this suite exists for. The cert row was always written; the tag on
# the certificate row is what CMP reads, and it is what was missing.
TAG=$(pg_exec "select coalesce(cert_id,'') from certs where serial='$SER';" 2>/dev/null | tr -d ' ')
chk "the certificate row carries the per-CA tag" "cmp-ra-ca" "$TAG"

# Decoded from the real certificate, not from what was posted. RFC 9810 §8.6 wants
# id-kp-cmcRA on an RA signer; fastpki-cmp only WARNS when it is missing and enrols anyway,
# so nothing failed and nothing looked wrong — the suite asserted the RA was USED and never
# what it carried.
pg_exec "select '-----BEGIN CERTIFICATE-----'||chr(10)||encode(cert,'base64')||chr(10)||'-----END CERTIFICATE-----' \
         from certs where serial='$SER';" > ra_issued.pem 2>/dev/null
chk "the issued RA certificate carries id-kp-cmcRA" yes \
    "$("$OSSL" x509 -in ra_issued.pem -noout -text 2>/dev/null \
       | grep -qE '1\.3\.6\.1\.5\.5\.7\.3\.28|CMC Registration Authority' && echo yes || echo no)"

# RA_KEY_SPEC_CHECK. THE MATRIX CELL IS NAMED HERE, by the product, on the artifact
# it minted and then used for a real CMP ir and rr. A token listing cannot do this: SoftHSM
# stores RSA-PSS as plain CKK_RSA, and pkcs11-tool calls ML-DSA "unknown key algorithm 74".
# The certificate's SubjectPublicKeyInfo is the one place the key type is stated in a
# vocabulary that is not a tool's guess — so a cell can never again claim to have tested a
# key type it did not.
if [ -n "${RA_KEY_SPEC:-}" ]; then
    SPKI=$("$OSSL" x509 -in ra_issued.pem -noout -text 2>/dev/null \
           | sed -n 's/.*Public Key Algorithm: *//p' | head -1)
    case "$(printf '%s' "$RA_KEY_SPEC" | tr 'A-Z' 'a-z')" in
      ml-dsa-65) WANT="ML-DSA-65" ;;
      ml-dsa-44) WANT="ML-DSA-44" ;;
      ml-dsa-87) WANT="ML-DSA-87" ;;
      # ⚠️ The edwards curves come FIRST. `EC:edwards25519` is how you ASK pkcs11 for it,
      # but the certificate says ED25519 — a generic ec:* arm matches it first and then
      # asserts the wrong answer about a cell that works.
      ed25519|ec:edwards25519) WANT="ED25519" ;;
      ed448|ec:edwards448)     WANT="ED448" ;;
      ec:*)      WANT="id-ecPublicKey" ;;
      # ⚠️ rsa-pss is certified rsaEncryption — the SPKI cannot distinguish it, which
      # is the whole reason certs.keyAlgo exists. Asserted at the mint instead.
      rsa-pss|rsa:*) WANT="" ;;
      *)         WANT="" ;;
    esac
    [ -n "$WANT" ] && chk "  the RA certificate's key is $WANT (this is the matrix cell)" yes \
        "$(printf '%s' "$SPKI" | grep -qiF "$WANT" && echo yes || echo no)"
    [ -n "$WANT" ] && [ -z "$(printf '%s' "$SPKI" | grep -iF "$WANT")" ] \
        && echo "      SPKI says: '$SPKI'"
fi

echo "=== The downloaded CMP config names THIS CA's RA as recipient ==="
# {{CMP_RA_CN}} is a substitution taken from the CMP RA certificate's subject CN. A
# missing recipient makes `openssl cmp` warn about setting it to a NULL-DN.
#
# This suite is where it can be proven: it has a console, a CA, and an RA credential
# PUBLISHED as cert_id "cmp-ra-$CA_ID" — the exact thing the token resolves through.
CFG250=$(curl -s -b cj.txt "$U/api/client-config/cmp?ca=$CA_ID")
chk "the config downloads"                    yes "$([ -n "$CFG250" ] && echo yes || echo no)"
chk "  it carries no raw {{CMP_RA_CN}} token" no  \
    "$(grep -qF '{{CMP_RA_CN}}' <<<"$CFG250" && echo yes || echo no)"
# The VALUE, decoded from the RA certificate this suite issued — not merely "non-empty".
# From the certificate the console ACTUALLY issued and published under cmp-ra-ca —
# ra_issued.pem is dumped from the `certs` row above — not from the `cn=` this suite
# posted. If the server ever resolved a different certificate, this catches it.
RACN=$("$OSSL" x509 -in ra_issued.pem -noout -subject -nameopt multiline 2>/dev/null \
       | sed -n 's/^ *commonName *= *//p' | head -1)
chk "  the RA cert really has a CN"           yes "$([ -n "$RACN" ] && echo yes || echo no)"
chk "  and the config names exactly that CN"  yes \
    "$(grep -qF "recipient = \"/CN=$RACN\"" <<<"$CFG250" && echo yes || echo no)"
# ⚠️ A DN, not a bare CN, and this is the assertion that would have caught both.
# `openssl cmp -recipient` parses the same syntax as -subject and -issuer —
# `/type=value/type=value` — so `"FastPKI Demo CA"` is not a name it can read. The config
# went out that way, demo/pki-demo.sh prefers the downloaded config when it exists, and the
# demo then reported the failure as "CMP_CLIENT_CA_ID unset" — a cause already ruled out
# by the operator having set it. One defect, filed as two.
#
# Asserted on the SHAPE, so it holds for any CA name: the value must begin `/CN=` inside
# the quotes, and must not be a bare CN.
chk "  the recipient is a DN, not a bare CN" yes \
    "$(sed -n 's/^recipient *= *//p' <<<"$CFG250" | head -1 | grep -q '^"/CN=' && echo yes || echo no)"
# And the client must actually accept it. A shape assertion cannot say that; openssl can.
#
# ⚠️ ASK THE NAME PARSER, AND CALIBRATE THE QUESTION FIRST. openssl reads -recipient with
# the same parse_name() as -subject/-issuer, and its refusal reads `recipient name is
# expected to be in the format /type0=value0/type1=value1/... This name is not in that
# format: '<value>'`. So a grep for "recipient.*(invalid|cannot|unable|bad)" matches nothing
# openssl ever prints, and `-newkey /dev/null` killed the client in context setup before it
# looked at -recipient at all: the answer was "no" whatever the config carried, including
# for the bare CN this exists to reject. scratch1.key is a real key (section 1 writes it),
# so setup now reaches the name, and the probe only ever looks for the parser's own verdict
# — never for a setup or transfer error, which must not be read as a bad recipient.
rcpt_rejected() {   # <value> <logfile> -> yes if openssl's name parser refuses it
    "$OSSL" cmp -cmd ir -server 127.0.0.1:1 -recipient "$1" -ref x -secret pass:x \
            -newkey scratch1.key -certout /dev/null >"$2" 2>&1
    grep -qE 'is not in that format|expected to be in the format' "$2" && echo yes || echo no
}
RCPT250=$(sed -n 's/^recipient *= *//p' <<<"$CFG250" | head -1 | tr -d '"')
# ⚠️ THE NEGATIVE FIRST, with the defect's own shape — the CN with no /CN= in front of it.
# Reading "no" here means the probe never reached the parser, and the assertion under it
# would then hold for any value at all.
chk "  openssl cmp refuses a bare CN as recipient" yes "$(rcpt_rejected "$RACN" rcpt_bare.log)"
chk "  and accepts the recipient this config carries" no "$(rcpt_rejected "$RCPT250" rcpt.log)"
# ⚠️ QUOTED. A CN routinely contains spaces ("FastPKI SubCA G1"); unquoted, openssl's
# config parser takes only the first word and the recipient is silently wrong.
chk "  the CN is quoted for the config parser" yes \
    "$(grep -qE 'recipient = "[^"]+"' <<<"$CFG250" && echo yes || echo no)"

chk "  and NOT the TLS defaults the form used to apply" no \
    "$("$OSSL" x509 -in ra_issued.pem -noout -text 2>/dev/null \
       | grep -q 'TLS Web Server Authentication' && echo yes || echo no)"
kill $P 2>/dev/null; wait $P 2>/dev/null

echo "=== 3. CMP now finds it and RA mode comes up ==="
"$ROOT/build/fastpki-cmp" --config cmp.conf > cmp2.log 2>&1 & C=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "cmp.conf" CMP_PORT "$C" || true
chk "the server started" yes "$(kill -0 $C 2>/dev/null && echo yes || echo no)"
chk "RA mode is no longer refused" no \
    "$(grep -q "no valid certificate for cert_id" cmp2.log && echo yes || echo no)"
# Positive, not merely the absence of the refusal: the server says RA mode is on.
chk "the server reports RA mode enabled" yes \
    "$(grep -qi "RA mode" cmp2.log && ! grep -qi "RA mode off" cmp2.log && echo yes || echo no)"

# And it still serves: an enrolment must work with RA mode on, or "enabled" would be a
# log line describing a broken server.
#
# The client is told to expect the RA as the sender, because that is what RA mode MEANS:
# the response is protected by the RA credential, not the CA key. With `-srvcert ca.pem`
# the same exchange gets as far as a successfully issued certificate and is then thrown
# away by the client with "unexpected sender:/CN=ra.internal" — which is the client being
# right. `-trusted` lets it validate the RA certificate up to the CA instead.
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client.key >/dev/null 2>&1
"$OSSL" cmp -cmd ir -server "http://127.0.0.1:$CPORT/cmp/ca" \
    -recipient "/CN=CMP RA CertId CA" \
    -trusted ca.pem -expect_sender "/CN=ra.internal" -secret pass:0000 -ref 1234 \
    -newkey client.key -subject "/CN=host.internal" -certout leaf.pem >client.log 2>&1
chk "a client can still enrol with RA mode on" yes "$([ -s leaf.pem ] && echo yes || echo no)"

echo "=== The recipient must name THIS authority (strict — his option (a)) ==="
# Of strict / lenient / log-only, (a) was chosen: we ship a valid config with the
# recipient filled in, so a client following it should not fail.
#
# By this point in the suite the CA has an RA credential (CN=ra.internal) and the CA
# itself is CN=CMP RA CertId CA, so both acceptable answers exist and can be told apart.
CMPSRV="http://127.0.0.1:$CPORT/cmp/ca"
try_recipient() {   # <args...> -> writes r.pem, echoes "yes"/"no" for issued
    rm -f r.pem
    "$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out r.key >/dev/null 2>&1
    "$OSSL" cmp -cmd ir -server "$CMPSRV" "$@" -trusted ca.pem \
        -secret pass:0000 -ref 1234 -keep_alive 0 -newkey r.key \
        -subject "/CN=recip-$RANDOM.internal" -certout r.pem >recip.log 2>&1 || true
    [ -s r.pem ] && echo yes || echo no
}
# ⚠️ THE POSITIVE CASE FIRST. Every refusal below is only meaningful if the same call
# shape issues when the recipient IS right — otherwise this section would pass just as
# well against a server that refuses everything.
chk "the RA's own CN is accepted"        yes "$(try_recipient -recipient "/CN=ra.internal")"
# The CA is the authority; the RA merely fronts it. A client naming the CA is not wrong
# under RFC 9810 §5.1.1, and our own generated config names the CA whenever a CA has no
# RA credential yet — so refusing it would refuse configs this deployment handed out.
chk "  and so is the issuing CA's CN"    yes "$(try_recipient -recipient "/CN=CMP RA CertId CA")"
chk "a recipient naming someone else is REFUSED" no \
    "$(try_recipient -recipient "/CN=Some Other CA")"
chk "  with failinfo wrongAuthority"     yes \
    "$(grep -qi 'wrongAuthority' recip.log && echo yes || echo no)"
chk "  and the message names both acceptable answers" yes \
    "$(grep -q 'neither this RA' recip.log && echo yes || echo no)"
# ⚠️ THIS is what makes it (a) rather than (b). `openssl cmp` with no -recipient and no
# -srvcert sends a NULL-DN, and that client — pointed at whatever host it was given — is
# exactly the one the rule exists to stop.
chk "NO recipient at all is REFUSED too" no  "$(try_recipient)"
chk "  and says to set it in the config" yes \
    "$(grep -q 'set .recipient. in fastpki-cmp.cnf' recip.log && echo yes || echo no)"
# Revocation is governed too — a rule that covered only issuance would be half a gate, and
# revoking against the wrong authority is the worse mistake.
"$OSSL" cmp -cmd rr -server "$CMPSRV" -recipient "/CN=Some Other CA" -trusted ca.pem \
    -secret pass:0000 -ref 1234 -oldcert leaf.pem -revreason 1 >recip_rr.log 2>&1 || true
chk "revocation is governed by the same rule" yes \
    "$(grep -qi 'wrongAuthority' recip_rr.log && echo yes || echo no)"

# The sharpest proof that the RA credential is the one in use: the response was signed
# by the certificate the console just issued, not by the CA.
chk "and the response was protected by the RA, not the CA" yes \
    "$(grep -q "unexpected sender" client.log && echo no || echo yes)"

echo "=== 4. an RA certificate issued for the WRONG key is refused, in words ==="
# ⚠️ THE REGRESSION CASE. The model is one RA key with one certificate per CA, and until
# now nothing checked it. Issue a certificate for a DIFFERENT key pair and the failure
# surfaced deep inside OpenSSL message protection as:
#
#     CMP error: key values mismatch
#     CMP error: cert and key do not match
#     CMP error: error protecting message
#
# — no certificate named, no CA named, no action implied, and a 500 at the client. This is
# not hypothetical: a CA rekey obliges an operator to reissue the RA credential, and
# reissuing is exactly when a fresh key pair gets minted by accident (I did it myself
# building ca_rollover_chain.sh, and the run was FLAKY rather than failing, because the two
# certificates could land in the same one-second "notAfter" and order arbitrarily).
RA2_URI=$(hsm_new_key_uri cmp-ra-wrong)
"$WEB" --config web.conf >web2.log 2>&1 & P2=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P2" || true
curl -s -c cj2.txt -d 'username=admin&password=testpw' "$U/api/login" >/dev/null

# ⚠️ The console API now REFUSES to do this directly. transport_key_for() used to
# return "" for a per-CA RA id (it compared a whole cert_id against a PREFIX), so the
# Mismatched-pair guard had nothing to compare and let any key through — the very
# hole that makes the state below reachable in the first place. Assert the refusal here,
# because this suite is where someone would notice if it ever stopped firing.
REF=$(curl -s -b cj2.txt -X POST "$U/api/certs/request-hsm" \
        --data-urlencode "ca_instance=$CA_ID" --data-urlencode "keyref=$RA2_URI" \
        --data-urlencode 'cn=ra-wrong.internal' --data-urlencode 'cert_id=cmp-ra-ca' \
        --data-urlencode 'keygen=true' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048')
chk "the console REFUSES a mismatched RA pair" yes \
    "$(printf '%s' "$REF" | grep -q 'mismatched pair' && echo yes || echo no)"

# The state is still reachable without the console — a restore, a hand-edited row, or a
# CMP_RA_KEY repointed after the certificate was issued — and fastpki-cmp must still fail
# with a message that NAMES the problem. So build it the way it can still arise: issue
# under a throwaway id the guard has no opinion on, then move the row onto the RA id.
ISS2=$(curl -s -b cj2.txt -X POST "$U/api/certs/request-hsm" \
        --data-urlencode "ca_instance=$CA_ID" --data-urlencode "keyref=$RA2_URI" \
        --data-urlencode 'cn=ra-wrong.internal' --data-urlencode 'cert_id=ra-wrong-staging' \
        --data-urlencode 'keygen=true' --data-urlencode 'key=rsa' --data-urlencode 'bits=2048')
SER2=$(printf '%s' "$ISS2" | sed -n 's/.*"serial":"\([^"]*\)".*/\1/p')
[ -n "$SER2" ] && pg_exec "UPDATE certs SET cert_id='cmp-ra-ca' WHERE serial='$SER2';" >/dev/null 2>&1
kill $P2 2>/dev/null; wait $P2 2>/dev/null
chk "a second RA certificate exists for a different key" yes \
    "$([ -n "$SER2" ] && echo yes || echo no)"

if [ -n "$SER2" ]; then
    # Make it win the lookup outright rather than relying on the tie-break, so this suite
    # tests the cert/key check and not the ordering.
    pg_exec "UPDATE certs SET \"notAfter\" = \"notAfter\" + 86400 WHERE serial='$SER2';" >/dev/null 2>&1
    : > cmp2.log
    # NO RESTART. The certificate is resolved per transaction, so the running server must
    # pick the new row up by itself — which is also what makes a reissue take effect
    # immediately instead of at the next restart.
    "$OSSL" cmp -cmd ir -server "http://127.0.0.1:$CPORT/cmp/ca" \
        -recipient "/CN=CMP RA CertId CA" \
        -trusted ca.pem -secret pass:0000 -ref 1234 \
        -newkey client.key -subject "/CN=wrongkey.internal" -certout bad.pem >bad.log 2>&1
    chk "the enrolment is refused" no "$([ -s bad.pem ] && echo yes || echo no)"
    chk "and the log NAMES the mismatch and the fix" yes \
        "$(grep -q "does not match the RA private key" cmp2.log && echo yes || echo no)"
    chk "  not the bare OpenSSL noise it used to be" no \
        "$(grep -q "cert and key do not match" cmp2.log && ! grep -q "does not match the RA private key" cmp2.log && echo yes || echo no)"
fi
kill $C 2>/dev/null; wait $C 2>/dev/null

echo
echo "=== CMP RA CERT_ID: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
