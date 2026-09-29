#!/usr/bin/env bash
# Provision the dedicated CMP RA credential a suite needs to talk CMP at all.
#
# CMP protects every response with the RA credential and has NO CA-key fallback: the CA
# signs certificates, the RA signs messages, and keeping those apart is what lets a CA
# carry only keyCertSign,cRLSign instead of dragging digitalSignature along for one
# protocol's benefit. A suite that starts fastpki-cmp without provisioning an RA
# credential therefore gets HTTP 503 on every transaction — by design, not by accident.
#
# ⚠️ Two things here must stay true to the product, because a helper that mints
# differently from the product is how the original bug hid for months (edb2b45):
#   * digitalSignature KU — the OpenSSL CMP *client* validates the message signer's key
#     usage and rejects the whole response with "srvcert does not validate msg" without it.
#   * id-kp-cmcRA EKU (1.3.6.1.5.5.7.3.28) — RFC 4210 RA operation, and fastpki-cmp logs a
#     warning when it is missing. Warned-about-but-accepted is still the wrong artifact to
#     assert against, so mint it correctly.
#
# Requires hsm_helpers.sh and pg_helpers.sh already sourced, and a CA already minted into
# a token by ca_in_token (which exports CA_OSSL_ARGS and the token URI).
#
# ⚠️ CA_OSSL_ARGS is NOT assumed to exist. The demo and benchmark scripts mint their CA
# with `fastpki-ca create --keygen` rather than ca_in_token, so the variable is never set
# there and `set -u` made this helper abort on the first line that used it — which read,
# from the caller's side, as the whole demo failing for no stated reason. Derive it when
# it is absent; it is the same provider argument list either way.
#
# Usage:  cmp_ra_setup <ca.pem> <ca-key-uri> [ra-key-label]
# Sets:   CMP_RA_KEY_URI — use it as CMP_RA_KEY in the config, with CMP_RA_CERT_ID_PREFIX=cmp-ra.

# Split in two on purpose. A suite that mints several CAs overwrites CA_KEY_URI with each
# one, so the RA certificate has to be issued while the FIRST CA's URI is still current —
# which is before pg_setup has run and there is anywhere to store it. So: issue early,
# publish once the database exists.
#   cmp_ra_issue <ca.pem> <ca-key-uri>   right after the first ca_in_token
#   cmp_ra_publish                        right after pg_setup
# cmp_ra_setup does both, for the single-CA suites where the order is not delicate.
cmp_ra_setup() { cmp_ra_issue "$1" "$2" "${3:-}" && cmp_ra_publish; }

cmp_ra_issue() {
    local ca_pem="$1" ca_uri="$2" label="${3:-cmp-ra-key}"
    : "${CA_OSSL_ARGS:=$(hsm_ossl_provider_args)}"
    [ -n "$label" ] || label=cmp-ra-key
    local token
    token=$(sed -n 's/.*token=\([^;?]*\).*/\1/p' <<<"$ca_uri")
    [ -n "$token" ] || { echo "cmp_ra_setup: no token= in '$ca_uri'" >&2; return 1; }

    # The RA key lives in the CA's own token: one p11-kit server, one token, so a suite
    # that kills or restarts the token affects both together the way a real sidecar does.
    #
    # ⚠️ REUSED IF IT ALREADY EXISTS, and that is the whole point of calling this twice.
    # The model is ONE RA key with one certificate per CA, so a REISSUE (after a CA rekey,
    # say) mints a new certificate for the SAME key. Minting a second key pair instead
    # produces a certificate the running server cannot use, and the server's own error for
    # that case is now explicit — see bind_ra_cert.
    if "$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$token" --list-objects \
           --type privkey --login --pin 1234 2>/dev/null | grep -q "label:[[:space:]]*$label\$"; then
        : # already provisioned — reissue against it
    else
        # ⚠️ THE RA CREDENTIAL IS A SERVER-SIDE KEY, so it is a row of the key-type matrix
        # like the OCSP responder — CMP has no TLS listener, and this is the key that
        # actually signs. It was hardcoded rsa:2048, which made every "server key" cell of
        # a matrix run identical here whatever was asked for.
        #
        # Mint through hsm_mint_key rather than calling pkcs11-tool directly: it already
        # knows which specs go to pkcs11-tool and which to the provider, and asks the TOKEN
        # whether the key appeared instead of trusting genpkey's exit code (which is always
        # non-zero for a token key, because -out cannot export it). hsm_token_spec first,
        # because the caller may hand us the OpenSSL spelling of a curve.
        local raspec; raspec=$(hsm_token_spec "${CMP_RA_KEY_SPEC:-rsa:2048}")
        hsm_mint_key "$token" "$label" "01" "$raspec" \
            || { echo "cmp_ra_setup: could not mint a $raspec RA key in $token${HSM_MINT_ERR:+ ($HSM_MINT_ERR)}" >&2; return 1; }
    fi
    CMP_RA_KEY_URI="pkcs11:token=$token;object=$label;type=private?pin-value=1234"
    export CMP_RA_KEY_URI

    local ext=".cmpra.ext" csr=".cmpra.csr" pem=".cmpra.pem"
    printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=1.3.6.1.5.5.7.3.28\n' > "$ext"
    "${OSSL:-openssl}" req -new -subj "/CN=cmp-ra.test" -key "$CMP_RA_KEY_URI" \
        $CA_OSSL_ARGS -out "$csr" 2>/dev/null
    # Judged by the artifact, not the exit code: p11-kit's teardown assertion makes openssl
    # exit non-zero after it has already written a good certificate (same trap as
    # ca_in_token).
    "${OSSL:-openssl}" x509 -req -in "$csr" -CA "$ca_pem" -CAkey "$ca_uri" \
        $CA_OSSL_ARGS -CAcreateserial -days 365 -extfile "$ext" -out "$pem" 2>/dev/null
    if ! [ -s "$pem" ] || ! "${OSSL:-openssl}" x509 -in "$pem" -noout -subject >/dev/null 2>&1; then
        echo "cmp_ra_issue: RA certificate issuance failed" >&2; return 1
    fi
    CMP_RA_PEM="$PWD/$pem"; export CMP_RA_PEM
}

# The RA certificate is PER CA — cert_id "<CMP_RA_CERT_ID_PREFIX>-<ca_id>" — because each
# endpoint's responses must chain to the CA the client addressed. One RA KEY serves them
# all (a key pair can be certified by several CAs), so this only issues another certificate.
#
# Usage: cmp_ra_for_ca <ca.pem> <ca-key-uri> <ca_id>     after cmp_ra_issue + cmp_ra_publish
cmp_ra_for_ca() {
    : "${CA_OSSL_ARGS:=$(hsm_ossl_provider_args)}"
    local ca_pem="$1" ca_uri="$2" ca_id="$3"
    [ -n "${CMP_RA_KEY_URI:-}" ] || { echo "cmp_ra_for_ca: call cmp_ra_issue first" >&2; return 1; }
    local ext=".cmpra-$ca_id.ext" csr=".cmpra-$ca_id.csr" pem=".cmpra-$ca_id.pem"
    printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=1.3.6.1.5.5.7.3.28\n' > "$ext"
    "${OSSL:-openssl}" req -new -subj "/CN=cmp-ra.$ca_id.test" -key "$CMP_RA_KEY_URI" \
        $CA_OSSL_ARGS -out "$csr" 2>/dev/null
    "${OSSL:-openssl}" x509 -req -in "$csr" -CA "$ca_pem" -CAkey "$ca_uri" \
        $CA_OSSL_ARGS -CAcreateserial -days 365 -extfile "$ext" -out "$pem" 2>/dev/null
    if ! [ -s "$pem" ] || ! "${OSSL:-openssl}" x509 -in "$pem" -noout -subject >/dev/null 2>&1; then
        echo "cmp_ra_for_ca: RA certificate issuance failed for '$ca_id'" >&2; return 1
    fi
    CMP_RA_PEM="$PWD/$pem"; export CMP_RA_PEM
    cmp_ra_publish "cmp-ra-$ca_id"
}

# The tag is per CA. Defaults to "cmp-ra-ca" because every single-CA suite here
# registers its CA as id "ca" (SIGNING_CA_ID=ca); a suite with more CAs calls
# cmp_ra_for_ca for each of the others.
cmp_ra_publish() {
    local tag="${1:-cmp-ra-ca}"
    local pem="${CMP_RA_PEM:-}"
    [ -s "$pem" ] || { echo "cmp_ra_publish: call cmp_ra_issue first" >&2; return 1; }
    # Tag the row `cmp-ra`: fastpki-cmp finds its RA certificate with
    # get_cert_by_cert_id -> "SELECT cert FROM certs WHERE cert_id=$1 AND status=0".
    # od (not xxd) for the hex — busybox on the Alpine CI image has no xxd.
    local der ser nb na
    der=$("${OSSL:-openssl}" x509 -in "$pem" -outform DER | od -An -v -tx1 | tr -d ' \n')
    # ⚠️ THE PRODUCT'S SERIAL FORM: lowercase, no leading zeros. x509_serial_hex() writes it
    # that way and every lookup keyed on a serial compares the string, so a row stored in
    # openssl's uppercase form is invisible to the product. publish_service_cert() then reads
    # the old certificate, computes the lowercase serial, calls set_cert_status() on it,
    # matches nothing, and leaves the row live — so a cert_id ends up with TWO active
    # certificates, which is the exact state that function exists to prevent.
    ser=$("${OSSL:-openssl}" x509 -in "$pem" -noout -serial | sed 's/serial=//' \
            | tr 'A-F' 'a-f' | sed 's/^0*//')
    nb=$(date +%s); na=$((nb + 365 * 86400))
    pg_exec "INSERT INTO certs(serial,status,cert,cert_id,subject,cn,\"notBefore\",\"notAfter\") \
             VALUES('$ser',0,decode('$der','hex'),'$tag','/CN=$tag.test','$tag.test',$nb,$na) \
             ON CONFLICT (serial) DO UPDATE SET cert_id='$tag', status=0;" >/dev/null 2>&1
    # Prove the row is readable the way CMP reads it, rather than trusting the INSERT.
    #
    # ⚠️ BY SERIAL, NOT BY TAG. Asking only "is there a live row for this cert_id" is answered
    # by any EARLIER row under the same tag, so an INSERT that failed — its output is discarded
    # above — was reported as success whenever the caller had published before. A suite then
    # went on to test the certificate it had just replaced. Asking for THIS certificate's serial
    # is the difference between "something is there" and "what I just published is there".
    local got
    got=$(pg_exec "SELECT count(*) FROM certs WHERE serial='$ser' AND cert_id='$tag' AND status=0;" 2>/dev/null | tr -d ' ')
    case "$got" in
        *[1-9]*) : ;;
        *) echo "cmp_ra_publish: the '$tag' row is not readable after insert" >&2; return 1 ;;
    esac
}

# The two config lines every CMP suite needs, so no suite has to remember both.
# Usage:  cmp_ra_conf_lines >> bootstrap.conf
cmp_ra_conf_lines() {
    printf 'CMP_RA_CERT_ID_PREFIX=cmp-ra\nCMP_RA_KEY=%s\n' "$CMP_RA_KEY_URI"
}

# ── PBM client authentication ────────────────────────────────────────────
#
# CMP_ACCEPT_UNPROTECTED is gone. Nine suites used to set it TRUE and send
# `-unprotected_requests`, which meant they exercised a configuration FastPKI has never
# shipped — our own deploy/bootstrap.compose.conf and config/bootstrap.conf.example both said `false`,
# and so did the compiled default. Worse, the flag did not only switch authentication off:
# it also switched off the REVOCATION OWNERSHIP CHECK in handle_rr (`if
# (!cfg.cmp_accept_unprotected)` wrapped the whole thing), so those suites could not have
# caught an ownership regression either.
#
# This provisions the per-user PBM secret the shipped posture requires. PBM is
# per-user: the senderKID the client sends (`-ref`) is looked up in `keys`, and there is no
# global secret to fall back to — an unknown ref installs no secret and the MAC cannot
# verify.
#
# Usage:
#   cmp_seed_pbm                 # or: cmp_seed_pbm myref
#   "$OSSL" cmp -cmd ir ... -secret "pass:$CMP_PBM_SECRET" -ref "$CMP_PBM_REF"
#
# ⚠️ A `keys` row is ENOUGH — no web_users row, no role grant. Measured, not assumed:
# cmp_auth.sh seeds exactly this and nothing else, and its PBM issuance is accepted.
cmp_seed_pbm() {   # [ref] -> sets CMP_PBM_REF / CMP_PBM_SECRET, seeds the keys row
    CMP_PBM_REF=${1:-cmptester}
    # Base64 minus the characters that would need quoting inside `pass:` or SQL.
    # ⚠️ Resolve openssl rather than assuming $OSSL: diag_genm.sh names its binary $O, so
    # `"$OSSL" rand` aborted under `set -u` with "OSSL: unbound variable" and the seed
    # silently produced nothing.
    local ossl=${OSSL:-$(command -v openssl)}
    CMP_PBM_SECRET=$("$ossl" rand 24 | "$ossl" base64 -A | tr -d '=+/')
    [ -n "$CMP_PBM_SECRET" ] || { echo "cmp_seed_pbm: could not generate a secret" >&2; return 1; }
    # Self-sufficient, like acme_seed_eab: `keys` is the only table this needs and a suite
    # may reach its first transaction before anything else has touched the schema.
    pg_exec "CREATE TABLE IF NOT EXISTS keys(kid TEXT PRIMARY KEY, key TEXT);" >/dev/null
    pg_exec "INSERT INTO keys(kid,protocol,key) VALUES('$CMP_PBM_REF','cmp','$CMP_PBM_SECRET')
             ON CONFLICT (kid,protocol) DO UPDATE SET key=EXCLUDED.key;" >/dev/null
    # ⚠️ AND AN IDENTITY, not just a secret — a bare credential issues
    # nothing now. Defined once in user_helpers.sh; sourced here so every suite that takes
    # a credential from this helper gets the identity too, without remembering to.
    command -v seed_enrolling_identity >/dev/null 2>&1 \
        || . "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/user_helpers.sh"
    seed_enrolling_identity "$CMP_PBM_REF"
}
