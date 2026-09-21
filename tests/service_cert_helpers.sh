# Shared helper for FastPKI's per-CA SERVICE credentials — the CMP RA, the OCSP
# responder and the SCEP RA.
#
# All three arrived at the same shape: ONE key for the process, N certificates — one per
# CA, each issued BY that CA and held in the database under cert_id "<prefix>-<ca_id>".
# The reason repeats: a credential that fronts CA 'a' must be certified by 'a' (RFC 6960
# §4.2.2.2 says so outright for the responder), so a single instance-wide PEM file can
# only ever be correct for one CA. Only the KEY is still configured, once.
#
# This was `ocsp_ra_publish` in ocsp_helpers.sh. It was never OCSP-specific — only its
# name was — and SCEP would have been the THIRD copy of the same INSERT (cmp_helpers.sh
# holds the other). Renamed rather than duplicated.
#
# Requires pg_helpers.sh already sourced (for pg_exec).
#
#   service_cert_publish <cert.pem> <ca_id> [prefix]     prefix: ocsp-ra | scep-ra | ...
#
# The suite builds the certificate however it likes — this only puts it where the server
# looks for it.

service_cert_publish() {
    local pem="${1:?service_cert_publish <responder.pem> <ca_id> [prefix]}"
    local ca_id="${2:?service_cert_publish <responder.pem> <ca_id> [prefix]}"
    local prefix="${3:-ocsp-ra}"
    [ -s "$pem" ] || { echo "service_cert_publish: no such certificate '$pem'" >&2; return 1; }

    local tag="$prefix-$ca_id" der ser nb na
    # ⚠️ REPLACE, do not accumulate. "Publish this certificate as the responder" means
    # exactly one is active: leave the previous row at status=0 and two certificates answer
    # to one cert_id, with the newest notAfter winning — which is a tie-break away from
    # nondeterministic (the bug hit on get_cert_by_cert_id).
    pg_exec "UPDATE certs SET status=1 WHERE cert_id='$tag' AND status=0;" >/dev/null 2>&1
    # od (not xxd) for the hex — busybox on the Alpine CI image has no xxd.
    der=$("${OSSL:-openssl}" x509 -in "$pem" -outform DER | od -An -v -tx1 | tr -d ' \n')
    # ⚠️ Normalise the serial the way the PRODUCT does, or nothing can find this row.
    # x509_serial_hex() lowercases and strips leading zeros; `openssl x509 -serial` gives
    # UPPERCASE with them intact. Insert the openssl form and every product lookup by
    # serial silently misses -- which is exactly how a renewal failed to retire the
    # certificate it replaced, leaving two active under one cert_id.
    ser=$("${OSSL:-openssl}" x509 -in "$pem" -noout -serial | sed 's/serial=//' \
          | tr 'A-Z' 'a-z' | sed 's/^0*//')
    [ -n "$ser" ] || ser=0
    nb=$(date +%s); na=$((nb + 365 * 86400))
    pg_exec "INSERT INTO certs(serial,status,cert,cert_id,subject,cn,\"notBefore\",\"notAfter\") \
             VALUES('$ser',0,decode('$der','hex'),'$tag','/CN=$tag.test','$tag.test',$nb,$na) \
             ON CONFLICT (serial) DO UPDATE SET cert_id=EXCLUDED.cert_id, status=0;" >/dev/null 2>&1

    # Read it back the way the product does. An INSERT that reports success and a row the
    # server cannot then resolve is the failure this catches — the same check cmp_ra_publish
    # earns its keep with.
    local n
    n=$(pg_exec "SELECT count(*) FROM certs WHERE cert_id='$tag' AND status=0;" 2>/dev/null | tr -d ' ')
    case "$n" in
        ''|0) echo "service_cert_publish: the '$tag' row is not readable after insert" >&2; return 1 ;;
    esac
    SERVICE_CERT_TAG="$tag"; export SERVICE_CERT_TAG
}

# ── mint AND publish an OCSP responder credential in one call ───────────────────────
#
# The CA key no longer signs status responses — there is no fallback — so EVERY suite
# that queries OCSP must provision a responder credential or the responder refuses. That
# is 11 suites, and without this helper it would be 11 copies of the same six openssl
# lines, each free to drift (the ocsp-nocheck extension is easy to forget, and
# fastpki-ocsp rejects a non-CA responder that lacks it — RFC 6960 §2.1.2).
#
#   ocsp_responder_key <ca.pem> <ca-key-or-uri> <ca_id> [outdir]
#
# Mints a key + certificate signed by that CA, publishes the certificate under
# cert_id "ocsp-ra-<ca_id>", and echoes the KEY PATH for OCSP_RESPONDER_KEY.
#
# $CA_OSSL_ARGS is honoured so a token-held CA key signs through the pkcs11 provider
# exactly as a file-held one does.
ocsp_responder_key() {
    local ca_pem="${1:?ocsp_responder_key <ca.pem> <ca_key> <ca_id> [outdir]}"
    local ca_key="${2:?}" ca_id="${3:?}" out="${4:-$(dirname "$ca_pem")}"
    # ⚠️ ONE key for the process, N certificates — the product's shape (OCSP_RESPONDER_KEY
    # is a single setting). So the key path is FIXED per directory and REUSED across CAs;
    # only the certificate is per-CA. Minting a fresh key per call would give each CA a
    # different key, and fastpki-ocsp would then reject every certificate but the last via
    # X509_check_private_key -- which is precisely the mismatch that check exists to catch.
    local key="$out/ocsp-responder.key"
    local csr="$out/ocspresp-$ca_id.csr"
    local pem="$out/ocspresp-$ca_id.pem" ext="$out/ocspresp-$ca_id.ext"
    # The responder's key type is a variable, so every suite that provisions an OCSP
    # responder becomes a row of the server-side matrix:
    #
    #     OCSP_KEY_SPEC=EC:P-256      OCSP_KEY_SPEC=ED25519      OCSP_KEY_SPEC=ML-DSA-65
    #
    # Default rsa:2048, unchanged. This one is a FILE key (OCSP_RESPONDER_KEY is a path),
    # so it sidesteps the token entirely — which is why ML-DSA is reachable here today:
    # OpenSSL 3.5 generates it natively, as tests/pqc.sh already proves.
    # ⚠️ ASSIGN THE DEFAULT FIRST. Writing `case "${OCSP_KEY_SPEC:-rsa:2048}"` for the test
    # but `${OCSP_KEY_SPEC#rsa:}` in the body reads the UNSET variable in the body, so the
    # default never reaches it and `rsa_keygen_bits:` gets an empty value. I did exactly
    # that and it took ocsp_abuse.sh from 18/0 to 11/7 — a broken key that still produced a
    # file, so every suite failed later at "status good (got '')" rather than here.
    local spec="${OCSP_KEY_SPEC:-rsa:2048}"
    # ⚠️ THE ALGORITHM HALF IS CASE-INSENSITIVE, the parameter half is not. This used to
    # match `rsa:*` and `EC:*` literally, so `ec:P-256` — the spelling the clients demo
    # normalises to — fell through to the catch-all and became `genpkey -algorithm ec:P-256`,
    # which fails. The caller then had a responder with no key, or (before the demo asserted
    # the key it actually got) silently kept the default rsa:2048 while the run reported the
    # EC cell green. A curve name like P-256 or prime256v1 IS case-sensitive, so only the
    # algorithm is folded.
    local _algo="${spec%%:*}" _param=""
    case "$spec" in *:*) _param="${spec#*:}";; esac
    _algo=$(printf '%s' "$_algo" | tr 'A-Z' 'a-z')
    if [ ! -s "$key" ]; then
        case "$_algo" in
            rsa)     "$OSSL" genpkey -algorithm RSA \
                        -pkeyopt "rsa_keygen_bits:${_param:-2048}" -out "$key" >/dev/null 2>&1 ;;
            rsa-pss) "$OSSL" genpkey -algorithm RSA-PSS \
                        -pkeyopt "rsa_keygen_bits:${_param:-2048}" -out "$key" >/dev/null 2>&1 ;;
            ec)      "$OSSL" genpkey -algorithm EC \
                        -pkeyopt "ec_paramgen_curve:${_param:-P-256}" -out "$key" >/dev/null 2>&1 ;;
            *)       "$OSSL" genpkey -algorithm "$_algo" -out "$key" >/dev/null 2>&1 ;;
        esac || { echo "ocsp_responder_key: cannot generate a $spec key" >&2; return 1; }
        [ -s "$key" ] || { echo "ocsp_responder_key: $spec produced no key" >&2; return 1; }
    fi
    "$OSSL" req -new -key "$key" -out "$csr" \
            -subj "/CN=OCSP Responder $ca_id" >/dev/null 2>&1 || return 1
    cat > "$ext" <<EXT
[v3_resp]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
# ⚠️ serverAuth ON PURPOSE, even though the product no longer puts it here.
# The renewal guard asserts it is DROPPED, and an assertion that the renewed cert lacks
# something the original never had would pass without testing anything.
extendedKeyUsage = OCSPSigning, serverAuth
1.3.6.1.5.5.7.48.1.5 = critical,ASN1:NULL
EXT
    "$OSSL" x509 -req -in "$csr" -CA "$ca_pem" -CAkey "$ca_key" ${CA_OSSL_ARGS:-} \
            -CAcreateserial -days 365 -extfile "$ext" -extensions v3_resp \
            -out "$pem" >/dev/null 2>"${TMPDIR:-/tmp}/ocsp_sign_debug.log"
    [ -s "$pem" ] || return 1
    service_cert_publish "$pem" "$ca_id" ocsp-ra || return 1
    echo "$key"
}
