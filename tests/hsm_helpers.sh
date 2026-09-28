#!/usr/bin/env bash
# One p11-kit server for the whole test run (option A).
#
# Private keys do not live in files any more, so a suite that needs a CA key needs
# a token. The obvious way — each test process loading SoftHSM through the pkcs11
# provider — is exactly the arrangement that DEADLOCKS: SoftHSM's OpenSSL backend
# re-enters libcrypto inside a process that is already using it. A deadlock
# in CI hangs rather than fails, which is far worse than a red suite.
#
# So SoftHSM runs in ONE separate process for the entire run, and every test reaches
# it through p11-kit-client.so. No test loads SoftHSM in-process, and the tests then
# exercise the same arrangement production uses (the sidecar).
#
# Each suite gets its OWN token on that shared socket. Tokens created after the
# server is running are visible through it — SoftHSM re-enumerates its token
# directory, verified before this was built.
#
#   source tests/hsm_helpers.sh
#   hsm_available || { echo "SKIP: no PKCS#11 toolchain"; exit 0; }
#   URI=$(hsm_ca_key myca)           # a fresh token + key, returns a pkcs11: URI
#   hsm_conf_lines >> bootstrap.conf       # PKCS11_MODULE / PKCS11_PROVIDER_PATH
#
# run_all.sh starts the server once and exports P11_KIT_SERVER_ADDRESS; a suite run
# on its own starts a private one on first use and tears it down at exit.

_hsm_findfirst(){ for x in "$@"; do [ -n "$x" ] && [ -e "$x" ] && { echo "$x"; return 0; }; done; return 1; }

# Locate the toolchain. Sets HSM_* on success; returns 1 if any piece is missing so
# callers can SKIP cleanly (§3d) rather than fail on a box without SoftHSM.
hsm_detect() {
    [ -n "${HSM_DETECTED:-}" ] && return "$HSM_DETECTED_RC"
    HSM_SOFTHSM=$(_hsm_findfirst "${SOFTHSM_MODULE:-}" \
        /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib64/softhsm/libsofthsm2.so /opt/homebrew/lib/softhsm/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so || true)
    HSM_UTIL=$(command -v softhsm2-util || true)
    HSM_PKTOOL=$(command -v pkcs11-tool || true)
    HSM_P11KIT=$(command -v p11-kit || true)
    HSM_CLIENT=$(_hsm_findfirst "${P11_CLIENT:-}" \
        /usr/lib/pkcs11/p11-kit-client.so /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so \
        /usr/lib64/pkcs11/p11-kit-client.so /opt/homebrew/lib/pkcs11/p11-kit-client.so \
        /usr/local/lib/pkcs11/p11-kit-client.so || true)
    # Homebrew keeps pkcs11.dylib under a versioned Cellar dir the opt/ symlink misses.
    local cellar; cellar=$(ls /opt/homebrew/Cellar/openssl@3/*/lib/ossl-modules/pkcs11.dylib 2>/dev/null | head -1)
    HSM_PROVIDER=$(_hsm_findfirst "${P11_PROVIDER:-}" \
        /usr/lib/ossl-modules/pkcs11.so /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so \
        /usr/lib64/ossl-modules/pkcs11.so /opt/homebrew/opt/openssl@3/lib/ossl-modules/pkcs11.dylib \
        /opt/homebrew/lib/ossl-modules/pkcs11.dylib "$cellar" || true)
    HSM_PROVIDER_DIR=$([ -n "$HSM_PROVIDER" ] && dirname "$HSM_PROVIDER" || echo "")

    HSM_DETECTED=1; HSM_DETECTED_RC=1
    [ -n "$HSM_SOFTHSM" ] && [ -n "$HSM_UTIL" ] && [ -n "$HSM_PKTOOL" ] && \
    [ -n "$HSM_CLIENT" ] && [ -n "$HSM_PROVIDER" ] && [ -n "$HSM_P11KIT" ] && \
    "$HSM_P11KIT" server --help >/dev/null 2>&1 && HSM_DETECTED_RC=0
    return "$HSM_DETECTED_RC"
}

hsm_available(){ hsm_detect; }

# Why a suite might SKIP — one line, so the reason is never a mystery in a CI log.
hsm_skip_reason() {
    hsm_detect && { echo "toolchain present"; return; }
    local m=""
    [ -z "${HSM_SOFTHSM:-}" ] && m="$m softhsm2-module"
    [ -z "${HSM_UTIL:-}" ]    && m="$m softhsm2-util"
    [ -z "${HSM_PKTOOL:-}" ]  && m="$m pkcs11-tool"
    [ -z "${HSM_CLIENT:-}" ]  && m="$m p11-kit-client.so"
    [ -z "${HSM_PROVIDER:-}" ]&& m="$m pkcs11-provider"
    [ -z "${HSM_P11KIT:-}" ]  && m="$m p11-kit(server)"
    echo "missing:$m"
}

# Start the shared server if nothing else has. run_all.sh calls this once up front;
# a lone suite gets its own and cleans it up. HSM_TOKENDIR is the token directory the
# server was started against — every later token must be created into that same dir,
# or the server will not see it.
hsm_server_start() {
    hsm_detect || return 1
    # Reuse a running server — but STILL export the provider's module variable. It is
    # per-process, not a property of the server, and returning early without it left
    # the provider unable to initialise ("Module initialization failed!"), whereupon
    # OpenSSL silently falls back to the file store and stats the pkcs11: URI as a
    # path. The suite then reports only "could not self-sign with the token key".
    # This is why a suite passed when a server had been started in the calling shell
    # (which exported it) and failed when run on its own.
    if [ -n "${P11_KIT_SERVER_ADDRESS:-}" ] && [ -S "${P11_KIT_SERVER_ADDRESS#unix:path=}" ]; then
        export PKCS11_PROVIDER_MODULE="$HSM_CLIENT"
        return 0
    fi
    HSM_RUNDIR="${HSM_RUNDIR:-$(mktemp -d)}"
    HSM_TOKENDIR="$HSM_RUNDIR/tokens"
    mkdir -p "$HSM_TOKENDIR"
    printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$HSM_TOKENDIR" \
        > "$HSM_RUNDIR/softhsm2.conf"
    export SOFTHSM2_CONF="$HSM_RUNDIR/softhsm2.conf"
    export XDG_RUNTIME_DIR="$HSM_RUNDIR"
    local sock="$HSM_RUNDIR/pkcs11.sock"
    "$HSM_P11KIT" server -f -n "$sock" --provider "$HSM_SOFTHSM" "pkcs11:" \
        > "$HSM_RUNDIR/server.log" 2>&1 &
    HSM_SERVER_PID=$!
    local i
    for i in $(seq 1 40); do [ -S "$sock" ] && break; sleep 0.25; done
    [ -S "$sock" ] || { echo "hsm_helpers: p11-kit server failed to start; see $HSM_RUNDIR/server.log" >&2; return 1; }
    export P11_KIT_SERVER_ADDRESS="unix:path=$sock"
    # The pkcs11 PROVIDER reads its own variable to decide which PKCS#11 module to
    # load, and it is NOT the same name as FastPKI's PKCS11_MODULE config key. Leave
    # it unset and the provider fails with "Module initialization failed!" while
    # OpenSSL quietly falls back to the file store and stats the pkcs11: URI as a
    # path. Point it at the client shim so direct `openssl` calls reach the server.
    export PKCS11_PROVIDER_MODULE="$HSM_CLIENT"
    export HSM_TOKENDIR HSM_RUNDIR
    return 0
}

hsm_server_stop() {
    # ⚠️ KILL THE PER-CONNECTION CHILDREN TOO. `p11-kit server` forks a child per
    # connected client, and killing only the listener stops NEW connections while every
    # process that ALREADY holds a session keeps a fully live token through its surviving
    # fork. So "the token is gone" was not true for exactly the services the test was
    # asking about, and a service that correctly kept running looked like a service that
    # failed to notice.
    #
    # This is why it reads as "fastpki-cmp does not exit when its PKCS#11 token dies":
    # the token did not die for cmp. Whether cmp has a real defect cannot be judged until
    # the instrument measures what it claims to — fix the teardown first, then look.
    #
    # Children before the parent: killing the listener first can leave a child reparented
    # to init with the socket still open, which is the state that produced the false
    # reading. hsm_token_reachable() below is the proof, and the suites assert it.
    if [ -n "${HSM_SERVER_PID:-}" ]; then
        local kids
        kids=$(pgrep -P "$HSM_SERVER_PID" 2>/dev/null | tr '\n' ' ')
        [ -n "$kids" ] && kill $kids 2>/dev/null
        kill "$HSM_SERVER_PID" 2>/dev/null
        # Reap before returning: an assertion that runs while the child is still dying
        # sees a reachable token and is a coin flip. Bounded so a stuck child cannot hang
        # the suite — hsm_token_reachable() is what actually decides, not this wait.
        local i=0
        while [ $i -lt 40 ]; do
            kill -0 "$HSM_SERVER_PID" 2>/dev/null || break
            sleep 0.1; i=$((i+1))
        done
        for k in $kids; do
            i=0
            while [ $i -lt 40 ]; do kill -0 "$k" 2>/dev/null || break; sleep 0.1; i=$((i+1)); done
        done
    fi
    HSM_SERVER_PID=""
    # ⚠️ REMOVE THE STALE SOCKET. p11-kit does not unlink it on SIGTERM, and
    # hsm_server_start early-returns whenever P11_KIT_SERVER_ADDRESS names a path that is
    # still a socket — without setting HSM_SERVER_PID. So a stop/start/stop sequence used
    # to leave the second stop a SILENT NO-OP: the suite believed it had killed the token,
    # the token was whatever state the first stop left it in, and the assertion that
    # followed measured nothing. Any suite that cycles the token more than once needs this.
    # :- on every expansion — token_key_liveness.sh deliberately `unset`s this to own its
    # token, and under `set -u` a bare ${VAR#...} on an unset name aborts the whole suite.
    local addr="${P11_KIT_SERVER_ADDRESS:-}" sock=""
    case "$addr" in unix:path=*) sock="${addr#unix:path=}" ;; esac
    [ -n "$sock" ] && rm -f "$sock" 2>/dev/null
    return 0
}

# Is the token actually reachable right now? A liveness test must be able to prove its own
# precondition: "the service did not notice the token die" is only meaningful if the token
# really died. Without this a broken teardown reads exactly like a product bug.
hsm_token_reachable() {
    [ -n "${HSM_PKTOOL:-}" ] && [ -n "${HSM_CLIENT:-}" ] || return 1
    "$HSM_PKTOOL" --module "$HSM_CLIENT" --list-slots >/dev/null 2>&1
}

# Mint a CA key in a token of this suite's own and echo its pkcs11: URI.
#   hsm_ca_key <label> [keyspec]
#
# This HARNESS self-signs its CA certificates with plain `openssl` driving the pkcs11
# provider, and that path signs with an EC token key perfectly well. Measured on the
# shipped image (OpenSSL 3.5.8, SoftHSM behind p11-kit, reached through the client shim):
#
#   EC:prime256v1                       -> ecdsa-with-SHA256
#   rsa:2048                            -> sha256WithRSAEncryption
#   rsa:2048 -sigopt rsa_padding_mode:pss -> rsassaPss
#   EC:edwards25519                     -> ED25519
#
# ⚠️ WHAT BREAKS EC IS A MISSING CKA_ID, AND ONLY EC NOTICES. Measured on the same token:
#
#                     with --id      without --id
#   EC:prime256v1     sign OK        sign FAIL (p11prov_obj_find_associated)
#   rsa:2048          sign OK        sign OK
#
# That asymmetry is the whole trap. Mint both WITHOUT `--id` and you observe exactly "RSA
# works, EC fails" and conclude the curve is unsupported — which is how this comment came
# to claim that, and how the claim then justified an RSA default. The keypairgen below
# passes `--id "$kid"`, so EC is available here: `hsm_ca_key ca EC:prime256v1` works.
#
# The rsa:2048 default is kept only so existing suites keep the key they were written
# against; nothing about the provider requires it.
# The token label is made unique per call so parallel suites on the shared server
# cannot collide, and the URI names the token explicitly so a lookup can never drift
# to a peer's key.
hsm_ca_key() {
    local label="${1:-ca}" keyspec="${2:-rsa:2048}"
    hsm_server_start || return 1
    local token="T_${label}_$$_${RANDOM}"
    # ⚠️ Create the token where the SERVER we are about to talk to is looking. Hardcoding
    # $HSM_RUNDIR here broke every caller that runs its OWN p11-kit server against its own
    # token directory: hsm_sidecar.sh exports SOFTHSM2_CONF and P11_KIT_SERVER_ADDRESS for
    # its private sidecar (hsm_sidecar.sh:49-50,60), but the token was still initialised in
    # $HSM_RUNDIR/tokens, so the keypairgen below asked a server that could not see it. The
    # suite SKIPped with "could not mint a CA key in a token" on EVERY machine — the Mac and
    # the lab both — which is why it could be listed as a lab-only suite while it
    # had in fact never run anywhere.
    SOFTHSM2_CONF="${SOFTHSM2_CONF:-$HSM_RUNDIR/softhsm2.conf}" "$HSM_UTIL" --module "$HSM_SOFTHSM" \
        --init-token --free --label "$token" --pin 1234 --so-pin 12345678 >/dev/null 2>&1 \
        || { echo "hsm_helpers: init-token failed for $token (SOFTHSM2_CONF=${SOFTHSM2_CONF:-$HSM_RUNDIR/softhsm2.conf})" >&2; return 1; }
    # Generate THROUGH the socket, so the key is created by the server process — the
    # same path production uses, and the one that must not deadlock.
    # ⚠️ --id is not decoration. Without CKA_ID the pkcs11 provider cannot associate the
    # private key with its public half, and the first non-RSA cell dies with
    #   p11prov_obj_find_associated: No CKA_ID in source object
    # RSA happened to survive without it, which is why this went unnoticed for as long as
    # every key here was rsa:2048. Derived from the label so it stays stable and unique
    # within the token.
    local kid
    kid=$(printf '%s' "$label" | od -An -tx1 | tr -d ' \n')
    "$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$token" \
        --keypairgen --key-type "$keyspec" --label "$label" --id "$kid" --login --pin 1234 >/dev/null 2>&1 \
        || { echo "hsm_helpers: keypairgen failed in $token (key-type $keyspec)" >&2; return 1; }
    echo "pkcs11:token=$token;object=$label;type=private?pin-value=1234"
}

# The two config keys a binary needs to reach the shared server. PKCS11_MODULE is the
# CLIENT shim (not SoftHSM itself) — that indirection is the whole point.
hsm_conf_lines() {
    hsm_detect || return 1
    printf 'PKCS11_MODULE=%s\nPKCS11_PROVIDER_PATH=%s\n' "$HSM_CLIENT" "$HSM_PROVIDER_DIR"
}

# A pkcs11: URI naming a NOT-YET-EXISTING object in the token this suite's CA key lives
# in. For a console or CLI create with keygen=true: the server mints the key at
# that handle itself, so all this has to do is name a free object — exactly what the
# console's slot picker assembles for an operator.
#
#   hsm_new_key_uri rootkey        # after ca_in_token, which set CA_KEY_URI
#   hsm_new_key_uri rootkey "$OTHER_KEY_URI"   # or name the token explicitly
#
# Deliberately NOT a token of its own: a suite that wants the console to mint into the
# same token it already uses should not have to know how tokens are named.
hsm_new_key_uri() {
    local label="${1:?hsm_new_key_uri <object-label> [uri-naming-the-token]}"
    local from="${2:-${CA_KEY_URI:-}}" tok
    tok=$(printf '%s' "$from" | sed -n 's/.*token=\([^;?]*\).*/\1/p')
    [ -n "$tok" ] || { echo "hsm_new_key_uri: no token in '$from' (call ca_in_token first)" >&2; return 1; }
    printf 'pkcs11:token=%s;object=%s;type=private?pin-value=1234\n' "$tok" "$label"
}

# Is the PRIVATE key labelled <object-label> in <token-label> marked extractable? Prints
# yes or no. Set P11_KIT_SERVER_ADDRESS on the call to pick a token server other than the
# shared one.
#
#   hsm_key_extractable fastpki repl-ca
#
# ⚠️ AN EXACT ATTRIBUTE, NOT A SUBSTRING. pkcs11-tool lists a key that can never leave its
# token as `Access: sensitive, always sensitive, never extractable, local`, so grepping
# that line for "extractable" answers yes about exactly the key the check exists to catch.
# The line is split on its commas and one item must be `extractable` by itself.
# ⚠️ AND THE PRIVATE HALF'S LINE. Both halves carry the label, and the public key's Access
# line says nothing about whether the private key can leave.
hsm_key_extractable() {
    local tok="${1:?hsm_key_extractable <token-label> <object-label>}"
    local label="${2:?hsm_key_extractable <token-label> <object-label>}"
    hsm_detect || { echo no; return 1; }
    "$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$tok" --list-objects \
        --login --pin 1234 2>/dev/null \
    | awk -v want="$label" '
        /^[^[:space:]].*Object/ { priv = ($0 ~ /^Private Key Object/); lbl = "" }
        priv && /^[[:space:]]*label:/ {
            lbl = $0; sub(/^[[:space:]]*label:[[:space:]]*/, "", lbl) }
        priv && /^[[:space:]]*Access:/ && lbl == want {
            acc = $0; sub(/^[[:space:]]*Access:[[:space:]]*/, "", acc)
            n = split(acc, item, /,[[:space:]]*/)
            for (i = 1; i <= n; i++) if (item[i] == "extractable") found = 1 }
        END { print (found ? "yes" : "no") }'
}

# For `openssl` invoked directly by a test against a token key.
hsm_ossl_provider_args() {
    hsm_detect || return 1
    printf -- '-provider pkcs11 -provider default -provider-path %s' "$HSM_PROVIDER_DIR"
}

# Create a CA whose private key exists only inside a token, and self-sign its
# certificate to <pem>. This replaces the
#   openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem ...
# idiom: no ca.key is written, because a CA private key in a file is the thing
# Removes.
#
# Called at the point the suite creates its CA — BEFORE it signs any fixtures — so
# $CA_KEY_URI is already set when those fixtures need it.
#
#   ca_in_token ca.pem "/CN=Some CA" [days] [id]
# Exports CA_KEY_URI and CA_OSSL_ARGS.
# With a parent, this mints a SUB-CA: its own key in its own token, certificate
# signed by the parent's token key. That is the real deployment shape (an issuing CA
# under an offline root), and several suites depend on issuer != subject to exercise
# chain handling — a self-signed stand-in would quietly not test it.
#
#   ca_in_token sub.pem "/CN=Issuing CA" 3650 subca root.pem "$ROOT_KEY_URI"
# The same backdate the product applies to every notBefore, as an absolute UTC
# stamp openssl will accept. BSD/macOS spells epoch conversion `-r`, GNU coreutils and
# busybox spell it `-d @` — both are tried because the suite runs on this Mac AND inside
# the Alpine image we ship, and a helper that works on only one of them is how a green
# local run stops meaning anything.
_hsm_backdated_stamp() {   # -> [CC]YYMMDDHHMMSSZ, 300 seconds ago, UTC
    local n; n=$(date -u +%s) || return 1
    date -u -r $((n - 300)) +%Y%m%d%H%M%SZ 2>/dev/null && return 0
    date -u -d "@$((n - 300))" +%Y%m%d%H%M%SZ 2>/dev/null && return 0
    return 1
}

ca_in_token() {
    local pem="${1:?ca_in_token <pem> <subj> [days] [id] [parent_pem] [parent_key_uri]}" \
          subj="${2:?}" days="${3:-3650}" id="${4:-}" parent_pem="${5:-}" parent_uri="${6:-}"
    [ -z "$id" ] && id="ca$$_${RANDOM}"
    if ! hsm_available; then
        echo "SKIP: CA keys are token-only; PKCS#11 toolchain incomplete — $(hsm_skip_reason)"
        type pg_cleanup >/dev/null 2>&1 && pg_cleanup >/dev/null 2>&1
        trap - EXIT
        exit 0
    fi
    # Start the server in THIS shell first. hsm_ca_key would start one itself, but it
    # is called in a command substitution, so the server would be a child of that
    # subshell and every variable it exports (P11_KIT_SERVER_ADDRESS,
    # PKCS11_PROVIDER_MODULE, HSM_PROVIDER_DIR) would die with it. The key gets minted
    # and the URI comes back looking perfectly good, then the very next openssl call
    # has no server to talk to and no module configured. That is the whole reason a
    # suite passed when a server happened to be running in the calling shell and
    # failed when run on its own.
    hsm_server_start || { echo "SKIP: no p11-kit server"; trap - EXIT; exit 0; }
    # The SERVER-side key type is a variable, not a constant. hsm_ca_key has always
    # taken a keyspec; ca_in_token simply never passed one, so every suite and the demo
    # minted rsa:2048 and no test anywhere exercised a non-RSA CA. That is the gap
    # this axis closes — our matrices vary the key on the CSR (the CLIENT side)
    # and nothing varies the key doing the signing.
    #
    # An environment variable rather than a 7th positional: the callers already pass up to
    # six, and a matrix driver wants to set this once per cell rather than at every call.
    # Values are pkcs11-tool --key-type spelling, e.g. rsa:2048, EC:prime256v1,
    # EC:edwards25519. Unsupported combinations fail at keypairgen, which is the honest
    # place — the token says what it can mint.
    CA_KEY_URI=$(hsm_ca_key "$id" "${CA_KEY_SPEC:-rsa:2048}") \
        || { echo "SKIP: could not mint a ${CA_KEY_SPEC:-rsa:2048} CA key in a token"; trap - EXIT; exit 0; }
    # ⚠️ -provider-path MUST PRECEDE -provider. The app processes these in order and loads
    # each provider the moment it parses it, so a trailing -provider-path arrives after the
    # lookup has already happened and openssl searches its DEFAULT modules directory. That
    # worked only for as long as HSM_PROVIDER_DIR happened to BE the default directory — a
    # Homebrew openssl@3 bump (3.6.2 to 3.6.3) moves the default and leaves the provider
    # behind in the old Cellar, and every token suite then SKIPs with "could not self-sign a
    # CA certificate with the token key" while the provider sits there working.
    CA_OSSL_ARGS="-provider-path $HSM_PROVIDER_DIR -provider pkcs11 -provider default"
    # Set the provider's own module variable HERE, at the point of use. It is
    # per-process and easy to lose: any path that reaches a token without having gone
    # through the full hsm_server_start body leaves it unset, the provider then fails
    # with "Module initialization failed!", and OpenSSL quietly falls back to the file
    # store and stats the pkcs11: URI as a filename. The only symptom a suite shows is
    # "could not self-sign with the token key", which points nowhere near the cause.
    export PKCS11_PROVIDER_MODULE="$HSM_CLIENT"
    export CA_KEY_URI CA_OSSL_ARGS
    # Judged by the artifact: p11-kit's teardown assertion makes openssl exit
    # non-zero after it has already written a good certificate.
    #
    # ⚠️ THIS MUST MATCH WHAT THE PRODUCT MINTS (build_ca_certificate_unsigned in
    # src/lib/x509.cpp). It did not, and that divergence hid a real defect for months:
    # the product minted every CA WITHOUT digitalSignature while this helper added it,
    # so every CMP exchange was dead in the field and green in the suite (edb2b45).
    # Removes the reason a CA ever needed digitalSignature — CMP now protects with
    # a dedicated RA credential — so the product default is keyCertSign,cRLSign and so is
    # this. When a helper must differ from the product, the difference IS the bug: change
    # this line only in lockstep with x509.cpp.
    local exts="basicConstraints=critical,CA:TRUE"
    local ku="keyUsage=critical,keyCertSign,cRLSign"
    # ⚠️ THE HELPER MUST BACKDATE THE WAY THE PRODUCT DOES. This mints with raw
    # openssl, so without the same 300s backdate the harness CA is stamped LATER than a
    # product-minted certificate created seconds after it. `ORDER BY "notBefore" DESC` is
    # how a rekeyed CA picks the certificate that SIGNS, so the old certificate
    # wins and the rollover silently signs with the superseded key. Measured: ca_rekey.sh
    # went 46/0 -> 43/3 the moment the product started backdating and this did not.
    # When a test helper has to differ from the product, the difference IS the bug.
    local nb; nb=$(_hsm_backdated_stamp) || nb=""
    local nbarg=""; [ -n "$nb" ] && nbarg="-not_before $nb"
    if [ -n "$parent_pem" ]; then
        "${OSSL:-openssl}" req -new -subj "$subj" -key "$CA_KEY_URI" $CA_OSSL_ARGS \
            -out "$pem.csr" 2>/dev/null
        "${OSSL:-openssl}" x509 -req -in "$pem.csr" -CA "$parent_pem" \
            -CAkey "$parent_uri" $CA_OSSL_ARGS -CAcreateserial -days "$days" $nbarg \
            -extfile <(printf '%s\n%s\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n' "$exts" "$ku") \
            -out "$pem" 2>/dev/null
        rm -f "$pem.csr"
    else
        "${OSSL:-openssl}" req -new -x509 -days "$days" -subj "$subj" -key "$CA_KEY_URI" \
            $CA_OSSL_ARGS $nbarg -addext "$exts" -addext "$ku" -out "$pem" 2>/dev/null
    fi
    if ! [ -s "$pem" ] || ! "${OSSL:-openssl}" x509 -in "$pem" -noout -subject >/dev/null 2>&1; then
        echo "SKIP: could not self-sign a CA certificate with the token key"
        type pg_cleanup >/dev/null 2>&1 && pg_cleanup >/dev/null 2>&1
        trap - EXIT; exit 0
    fi
    # Several suites reused the old ca.key as a throwaway keypair for a CLIENT
    # (openssl cmp -newkey, say). That is a legitimate file key — the client is not
    # FastPKI — but it must not be called ca.key, or a reader will conclude the CA
    # key survived. Emit it beside the certificate under an honest name.
    "${OSSL:-openssl}" genrsa -out "$(dirname "$pem")/scratch.key" 2048 >/dev/null 2>&1
    return 0
}

# ── hsm_mint_key <token> <label> <id-hex> <spec> ───────────────────────────────────
# Mint a keypair INSIDE a token, the way the PRODUCT does. Sets HSM_MINT_VIA to
# `pkcs11-tool` or `provider`, and HSM_MINT_ERR on failure. Returns non-zero if the key
# does not exist afterwards.
#
# ⚠️ ROUTE BY SPEC — never "try pkcs11-tool first and fall back".
# `pkcs11-tool --keypairgen` implements a fixed table of spellings: rsa:N, EC:curve,
# ED25519. Ask it for `rsa-pss` and it does NOT refuse — it mints an ordinary RSA:2048
# key with no CKA_ALLOWED_MECHANISMS. So a fallback never fires, and the caller measures
# plain RSA while believing it measured PSS. Ask it for ML-DSA-65 and it says
# `Unknown key pair type`, which is the TOOL lacking the name, not the token lacking
# the capability.
#
# generate_key_in_token() hands the algorithm name straight to the pkcs11 provider
# (`EVP_PKEY_CTX_new_from_name(name, "?provider=pkcs11")`) — its own comment says an
# allow-list "is exactly the thing that goes stale". Anything outside pkcs11-tool's table
# therefore goes to the provider, exactly as the product would.
hsm_mint_key() {
    _tok="$1"; _lbl="$2"; _id="$3"; _spec="$4"
    HSM_MINT_VIA=; HSM_MINT_ERR=
    case "$(printf '%s' "$_spec" | tr 'A-Z' 'a-z')" in
      # ⚠️ ec:edwards25519 BELONGS HERE. pkcs11-tool knows that spelling and mints it
      # correctly; the provider branch below would receive it verbatim as
      # `genpkey -algorithm EC:edwards25519`, which is not an OpenSSL algorithm name (it
      # wants ED25519). Leaving it out sent Ed25519 down the wrong path, the mint failed,
      # and the caller only found out three steps later as "Could not find private key".
      # The pkcs11 spelling and the OpenSSL spelling are different vocabularies — the
      # same trap as EC:edwards25519 vs an ED25519 SPKI in hsm_expected_spki().
      rsa:*|ec:prime*|ec:secp*|ec:brainpool*|ec:edwards*|ed25519|ed448)
        HSM_MINT_VIA=pkcs11-tool
        HSM_MINT_ERR=$("$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$_tok" \
            --keypairgen --key-type "$_spec" --label "$_lbl" --id "$_id" \
            --login --pin 1234 2>&1 >/dev/null) && return 0
        return 1 ;;
    esac
    # ⚠️ ASK THE TOKEN WHAT IT ADVERTISES, BEFORE ASKING IT TO GENERATE. The provider's
    # refusal for an algorithm the token does not implement is
    #
    #   p11prov_mldsa_gen: The token was not present in its slot when the function was invoked
    #
    # which is CKR_TOKEN_NOT_PRESENT — it names the SLOT, and the slot is fine. Passed up
    # verbatim it becomes an announced skip that says the wrong thing, and the next person
    # goes looking for a dead p11-kit session. Measured on this MacBook: its SoftHSM
    # advertises ZERO ML-DSA mechanisms, while the shipped image's advertises them as
    # mechtype-0x1C / 0x1D. Same shape as probing CKA_ALLOWED_MECHANISMS instead of
    # attempting a signature: the capability question has a direct answer, so ask it.
    case "$(printf '%s' "$_spec" | tr 'A-Z' 'a-z')" in
      ml-dsa-*)
        if ! "$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$_tok" --list-mechanisms \
               2>/dev/null | grep -qiE 'ml-dsa|mechtype-0x1[cd]'; then
            HSM_MINT_VIA=provider
            HSM_MINT_ERR="this host's PKCS#11 token advertises no ML-DSA mechanism (pkcs11-tool --list-mechanisms shows neither ML-DSA nor mechtype-0x1C/0x1D), so it cannot generate a $_spec key; the shipped image's SoftHSM does — run this cell there"
            return 1
        fi ;;
    esac
    HSM_MINT_VIA=provider
    _perr=$("${OSSL:-openssl}" genpkey -provider pkcs11 -provider default -algorithm "$_spec" \
        -pkeyopt "pkcs11_uri:pkcs11:token=$_tok;object=$_lbl;id=%$_id?pin-value=1234" \
        -out "${TMPDIR:-/tmp}/hsm_mint.discard" 2>&1)
    # ⚠️ genpkey's exit code is USELESS here and always non-zero: a token private key cannot
    # be exported, so `-out` fails AFTER the keypair was created in hardware. Ask the TOKEN.
    "$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$_tok" --login --pin 1234 \
        -O --type privkey 2>/dev/null | grep -q "$_lbl" && return 0
    HSM_MINT_ERR="provider: $(printf '%s' "$_perr" | grep -iE 'p11prov|pkcs11|unsupported|not present' | head -1)"
    return 1
}

# ── hsm_token_spec <spec> ──────────────────────────────────────────────────────────
# Translate an OpenSSL-flavoured key spec into the vocabulary hsm_mint_key expects.
#
# ⚠️ THE TWO VOCABULARIES DIFFER AND NEITHER ERRORS USEFULLY. OpenSSL names the curve
# `P-256` and the algorithm `ED25519`; pkcs11-tool names them `prime256v1` and
# `edwards25519`, and hands anything it does not recognise to the provider branch as
# `genpkey -algorithm ec:P-256`, which is not an algorithm name. The failure surfaces
# several steps later as "Could not find private key", pointing at the wrong thing.
#
# Anything already in the token vocabulary passes through unchanged, so this is safe to
# apply to a spec from either side.
hsm_token_spec() {
    case "$(printf '%s' "$1" | tr 'A-Z' 'a-z')" in
      ec:p-256|ec:prime256v1|ec:secp256r1) echo "ec:prime256v1" ;;
      ec:p-384|ec:secp384r1)               echo "ec:secp384r1" ;;
      ec:p-521|ec:secp521r1)               echo "ec:secp521r1" ;;
      ed25519|ec:edwards25519)             echo "ec:edwards25519" ;;
      ed448|ec:edwards448)                 echo "ec:edwards448" ;;
      *)                                   printf '%s\n' "$1" ;;
    esac
}

# ── hsm_expected_spki <spec> ───────────────────────────────────────────────────────
# What the CERTIFICATE's "Public Key Algorithm:" will say for a key of this spec, or
# empty when the SPKI genuinely cannot distinguish it.
#
# ⚠️ This is the only trustworthy way to name a key-type matrix cell. A token listing
# cannot: SoftHSM stores RSA-PSS as plain CKK_RSA, and pkcs11-tool reports an ML-DSA key
# as `unknown key algorithm 74` (0x4A, the PKCS#11 v3 PQC range) because it predates the
# name. The certificate the product issued and then used states the type in the product's
# own vocabulary.
hsm_expected_spki() {
    case "$(printf '%s' "$1" | tr 'A-Z' 'a-z')" in
      # The edwards curves come FIRST: you ASK for EC:edwards25519, the certificate says
      # ED25519, and a generic ec:* arm would match first and assert the wrong answer.
      ed25519|ec:edwards25519) echo "ED25519" ;;
      ed448|ec:edwards448)     echo "ED448" ;;
      ml-dsa-44) echo "ML-DSA-44" ;;
      ml-dsa-65) echo "ML-DSA-65" ;;
      ml-dsa-87) echo "ML-DSA-87" ;;
      ec:*)      echo "id-ecPublicKey" ;;
      # rsa-pss is certified rsaEncryption — the SPKI cannot distinguish it, which is
      # the whole reason certs.keyAlgo exists. Assert such a cell at the mint instead.
      *)         echo "" ;;
    esac
}
