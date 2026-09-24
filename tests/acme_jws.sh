# ACME JWS in shell — the piece that kept seven suites on Python.
#
# Every test is a self-contained shell script; the surviving Python
# drivers are legacy to migrate off. All seven that remain are ACME, and they are
# all Python for one reason: RFC 8555 signs every request as a JWS, and nothing in the
# harness could do that. This does it with `openssl` and shell built-ins only — no xxd, no
# python, no jq.
#
# The awkward part is ES256. RFC 7518 §3.4 wants the signature as the raw pair R||S, 32
# bytes each; `openssl dgst -sign` emits a DER SEQUENCE of two INTEGERs, which are
# variable-length and may carry a leading 0x00 sign byte. Handing the DER straight to the
# server produces a signature that verifies as garbage — a failure that looks like a
# server bug, not an encoding one. `der_to_raw_ecdsa` below is the conversion.
#
# Usage (see acme_orders.sh for a worked example):
#
#   . "$ROOT/tests/acme_jws.sh"
#   acme_dir "https://127.0.0.1:8444/acme/<ca>/directory"   # loads the endpoint URLs
#   jws_newkey k1.pem                                        # a fresh account key
#   acme_new_account k1.pem
#
# ⚠️ SELF-CONTAINED wait_listen. This file calls wait_listen(), which lives in
# tests/pg_helpers.sh — fine for a suite, which sources that first, and broken for
# demo/pki-demo.sh, which deliberately does not (it needs no database helpers). The
# result was `acme_jws.sh: line 509: wait_listen: command not found` followed by the
# server reporting "http-01 challenge response missing or mismatched": the responder had
# not come up yet and nothing waited for it. Define a fallback only when the real one is
# absent, so a suite that sources pg_helpers keeps its version.
#
# It must NOT connect to the port: the responder is a loop of one-shot `nc` listeners, and
# a probe that completes a connection eats the very response the challenge fetch needs.
if ! command -v wait_listen >/dev/null 2>&1; then
wait_listen() {   # <port> [pid] [timeout]
    local port="$1" pid="${2:-}" timeout="${3:-30}" deadline
    deadline=$(( $(date +%s) + timeout ))
    while :; do
        if [ -r /proc/net/tcp ]; then
            local hex; hex=$(printf '%04X' "$port")
            awk -v h=":$hex" '$4=="0A" && index($2,h)==length($2)-length(h)+1 {f=1}
                              END{exit !f}' /proc/net/tcp /proc/net/tcp6 2>/dev/null && return 0
        elif command -v lsof >/dev/null 2>&1; then
            # macOS: no /proc. lsof reports the LISTEN state without opening a connection.
            lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && return 0
        else
            sleep 1; return 0          # nothing to probe with — the old behaviour
        fi
        [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null && return 1
        [ "$(date +%s)" -ge "$deadline" ] && return 1
        sleep 0.05
    done
}
fi
#   KID=$ACME_LOCATION                                       # set by every acme_post_*
#   acme_post_kid k1.pem "$KID" "$ACME_NEW_ORDER" '{"identifiers":[...]}'
#   acme_post_kid k1.pem "$KID" "$SOMEURL" ""                # "" = POST-as-GET
#
# After each call: $ACME_STATUS, $ACME_BODY, $ACME_LOCATION, $ACME_HEADERS.

# ── encoding ────────────────────────────────────────────────────────────────────
b64url()      { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
b64url_str()  { printf '%s' "$1" | b64url; }
# Hex to raw bytes without xxd: busybox's xxd is not guaranteed and `xxd` is a vim package
# on several distros. printf '%b' understands \xNN in bash.
hex2bin()     { printf '%b' "$(printf '%s' "$1" | sed 's/../\\x&/g')"; }
b64url_hex()  { hex2bin "$1" | b64url; }

# ── keys ────────────────────────────────────────────────────────────────────────
# A P-256 account key. ACME accepts RS256 too, but ES256 is what every suite here used
# and it is the one that exercises the DER->raw conversion.
jws_newkey() { "$OSSL" ecparam -name prime256v1 -genkey -noout -out "$1" 2>/dev/null; }

# The JWK for a P-256 key, with members in the order RFC 7638 requires for a thumbprint
# (crv, kty, x, y — lexicographic) so the same string serves both uses.
#
# The public key in DER is an SPKI whose last 65 bytes are the uncompressed point
# 0x04 || X(32) || Y(32). Taking it from the tail avoids parsing the algorithm identifier.
jws_jwk() {
    local pt
    pt=$("$OSSL" ec -in "$1" -pubout -outform DER 2>/dev/null | \
         od -An -tx1 -v | tr -d ' \n' | tail -c 130)   # 65 bytes = 130 hex chars
    [ "${pt:0:2}" = "04" ] || { echo "jws_jwk: not an uncompressed P-256 point" >&2; return 1; }
    printf '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' \
        "$(b64url_hex "${pt:2:64}")" "$(b64url_hex "${pt:66:64}")"
}

# RFC 7638 JWK thumbprint — the account identifier a key authorization is built from.
jws_thumbprint() { jws_jwk "$1" | "$OSSL" dgst -sha256 -binary | b64url; }

# DER SEQUENCE{INTEGER r, INTEGER s} -> the 64 raw bytes RFC 7518 wants.
# asn1parse prints each INTEGER as ":<uppercase hex>"; a value may be 31 bytes (no
# padding) or 33 (a leading 00 so the DER integer stays positive), so each half is
# normalised to exactly 64 hex characters rather than assumed.
der_to_raw_ecdsa() {
    local ints r s
    ints=$("$OSSL" asn1parse -inform DER -in "$1" 2>/dev/null | sed -n 's/.*INTEGER *://p')
    r=$(printf '%s' "$ints" | sed -n 1p | tr 'A-F' 'a-f')
    s=$(printf '%s' "$ints" | sed -n 2p | tr 'A-F' 'a-f')
    [ -n "$r" ] && [ -n "$s" ] || { echo "der_to_raw_ecdsa: no INTEGERs in signature" >&2; return 1; }
    pad32() { local h=$1; while [ ${#h} -gt 64 ]; do h=${h#??}; done
              while [ ${#h} -lt 64 ]; do h="0$h"; done; printf '%s' "$h"; }
    printf '%s%s' "$(pad32 "$r")" "$(pad32 "$s")"
}

# The JWS Flattened JSON Serialization of <protected-json> over <payload-json>.
# An EMPTY payload is POST-as-GET (RFC 8555 §6.3) and must serialise as "", not as "{}"
# — the server verifies the signature over the empty string, so the two differ.
jws_sign() {
    local key=$1 protected=$2 payload=$3 p pl sig
    p=$(b64url_str "$protected")
    if [ -z "$payload" ]; then pl=""; else pl=$(b64url_str "$payload"); fi
    printf '%s' "$p.$pl" | "$OSSL" dgst -sha256 -sign "$key" -out "$JWS_TMP/sig.der" 2>/dev/null
    sig=$(b64url_hex "$(der_to_raw_ecdsa "$JWS_TMP/sig.der")") || return 1
    printf '{"protected":"%s","payload":"%s","signature":"%s"}' "$p" "$pl" "$sig"
}

# ── transport ───────────────────────────────────────────────────────────────────
# Every ACME response can carry a fresh nonce, and the suites talk to a self-signed
# listener, hence -k. Headers are kept because Location and Replay-Nonce are the protocol,
# not metadata.
acme_http() {   # <url> [body-file]
    local url=$1 body=${2:-}
    if [ -n "$body" ]; then
        ACME_STATUS=$(curl -sk -o "$JWS_TMP/body" -D "$JWS_TMP/hdr" -w '%{http_code}' \
            -H 'Content-Type: application/jose+json' --data-binary "@$body" "$url")
    else
        ACME_STATUS=$(curl -sk -o "$JWS_TMP/body" -D "$JWS_TMP/hdr" -w '%{http_code}' "$url")
    fi
    ACME_BODY=$(cat "$JWS_TMP/body")
    ACME_HEADERS=$(cat "$JWS_TMP/hdr")
    ACME_LOCATION=$(printf '%s' "$ACME_HEADERS" | sed -n 's/^[Ll]ocation: *//p' | tr -d '\r' | tail -1)
    local n
    n=$(printf '%s' "$ACME_HEADERS" | sed -n 's/^[Rr]eplay-[Nn]once: *//p' | tr -d '\r' | tail -1)
    [ -n "$n" ] && ACME_NONCE=$n
    return 0
}

# A value out of a flat JSON object. Deliberately narrow: it reads one string member by
# name and nothing else, so it cannot quietly match a similarly named member of a nested
# object the way a greedy pattern would.
json_str() { printf '%s' "$1" | sed -n 's/.*"'"$2"'":"\([^"]*\)".*/\1/p' | head -1; }

acme_dir() {    # <directory-url>
    JWS_TMP=${JWS_TMP:-$(mktemp -d)}
    ACME_DIRECTORY=$1
    acme_http "$1"
    ACME_NEW_ACCT=$(json_str "$ACME_BODY" newAccount)
    ACME_NEW_ORDER=$(json_str "$ACME_BODY" newOrder)
    ACME_NEW_NONCE=$(json_str "$ACME_BODY" newNonce)
    ACME_REVOKE=$(json_str "$ACME_BODY" revokeCert)
    ACME_KEYCHANGE=$(json_str "$ACME_BODY" keyChange)
    [ -n "$ACME_NEW_ACCT" ] && [ -n "$ACME_NEW_ORDER" ]
}

acme_nonce() { acme_http "$ACME_NEW_NONCE"; printf '%s' "$ACME_NONCE"; }

# First contact: the account key travels as a `jwk`, because the server has no account to
# look it up under yet.
acme_post_jwk() {   # <key> <url> <payload-json>
    local key=$1 url=$2 payload=$3 prot
    prot=$(printf '{"alg":"ES256","jwk":%s,"nonce":"%s","url":"%s"}' \
           "$(jws_jwk "$key")" "$(acme_nonce)" "$url")
    jws_sign "$key" "$prot" "$payload" > "$JWS_TMP/req.json" || return 1
    acme_http "$url" "$JWS_TMP/req.json"
}

# ── External Account Binding (RFC 8555 §7.3.4) ──────────────────────────────────
#
# Made EAB the DEFAULT, which means the shell client could not register an account
# on a stock deployment at all — only against a suite that switched EAB off.
# That is why demo/pki-demo.sh's live ACME leg had nothing to drive: certbot can do EAB,
# this client could not.
#
# The binding is an inner JWS carried in the newAccount payload:
#   protected = {"alg":"HS256","kid":<kid>,"url":<newAccount url>}
#   payload   = the ACCOUNT's public JWK  (not the thumbprint — the whole key)
#   signature = HMAC-SHA256 over "<protected>.<payload>" with the MAC key
#
# ⚠️ The MAC key is the base64url-DECODED secret, as raw bytes. `openssl dgst -hmac` takes
# a STRING key and would silently HMAC with the base64 text instead, producing a signature
# the server rejects with no clue why. `-mac HMAC -macopt hexkey:` is the form that takes
# binary. (FastPKI stores one base64url string and CMP uses it verbatim while ACME decodes
# it — see include/pki/enrol_creds.hpp.)
acme_eab_binding() {   # <account-key> <kid> <base64url-hmac> <newAccount-url> -> JSON
    local key=$1 kid=$2 secret=$3 url=$4
    # base64url -> base64 -> raw -> hex, for -macopt hexkey:
    local b64 hexkey
    b64=$(printf '%s' "$secret" | tr '\-_' '+/')
    case $(( ${#b64} % 4 )) in 2) b64="$b64==";; 3) b64="$b64=";; esac
    hexkey=$(printf '%s' "$b64" | "$OSSL" base64 -d -A 2>/dev/null | od -An -tx1 -v | tr -d ' \n')
    [ -n "$hexkey" ] || { echo "acme_eab_binding: could not decode the HMAC key" >&2; return 1; }
    local prot payload sig
    prot=$(b64url_str "$(printf '{"alg":"HS256","kid":"%s","url":"%s"}' "$kid" "$url")")
    payload=$(b64url_str "$(jws_jwk "$key")")
    sig=$(printf '%s.%s' "$prot" "$payload" \
          | "$OSSL" dgst -sha256 -mac HMAC -macopt "hexkey:$hexkey" -binary | b64url)
    printf '{"protected":"%s","payload":"%s","signature":"%s"}' "$prot" "$payload" "$sig"
}

# External Account Binding is MANDATORY — ACME_EAB_REQUIRED is gone, and with it the
# ability to run an ACME server that accepts any self-generated account key. These two are
# what every protocol suite now uses to get an account, so the plumbing lives in one place
# instead of being copied into fourteen files.
#
# ⚠️ The suites that call these test ACME PROTOCOL MECHANICS, not deployment policy, and
# they used to pin the removed ACME_EAB_REQUIRED=false for exactly that reason. That pin meant fourteen
# suites exercised a configuration FastPKI does not ship. Removing the switch also removes
# that gap: they now run against the shipped posture.
acme_seed_eab() {   # [kid] -> sets ACME_EAB_KID / ACME_EAB_HMAC, seeds the keys row
    ACME_EAB_KID=${1:-eabtester}
    # ⚠️ NEVER LET THE SECRET BEGIN WITH '-'. base64url maps '+' to '-', so ~1 in 64 of
    # these starts with one (measured: 5 in 400). certbot's argparse then reads it as the
    # NEXT OPTION rather than as this option's value and dies with
    #
    #     certbot: error: argument --eab-hmac-key: expected one argument
    #
    # — the same message an EMPTY secret produces, which is why the emptiness guard below
    # did not explain it. Seven suites pass this to certbot, so a full run hits it roughly
    # one time in twelve: it took out acme_caa.sh on a lab gate (PASS=8 FAIL=11, and the
    # 8 were the NEGATIVE cases passing vacuously because no certificate was issued at
    # all). Re-rolling costs nothing and keeps the value a normal base64url secret.
    ACME_EAB_HMAC=$("$OSSL" rand 32 | "$OSSL" base64 -A | tr '+/' '-_' | tr -d '=')
    _eab_tries=0
    while [ "${ACME_EAB_HMAC#-}" != "$ACME_EAB_HMAC" ] && [ "$_eab_tries" -lt 32 ]; do
        ACME_EAB_HMAC=$("$OSSL" rand 32 | "$OSSL" base64 -A | tr '+/' '-_' | tr -d '=')
        _eab_tries=$((_eab_tries+1))
    done
    # ⚠️ EXIT, not `return 1`. The check was right and the propagation was not —
    # all six callers (acme_caa, acme_dns01, acme_lifecycle, acme_orders, acme_perca,
    # acme_wildcard) invoke this bare, and with no `set -e` a non-zero return is simply
    # ignored. The suite then carried on with an empty $ACME_EAB_HMAC and certbot answered
    #
    #     certbot: error: argument --eab-hmac-key: expected one argument
    #
    # having eaten the next argument — seven red assertions pointing at certbot's parser
    # instead of at the generator. Failing here names the cause and cannot be forgotten by
    # the next caller, which a `return` provably was.
    #
    # And it FAILS rather than SKIPs on purpose: an openssl that cannot produce 32 random
    # bytes is a broken environment, not an absent optional dependency.
    [ -n "$ACME_EAB_HMAC" ] || {
        echo "acme_seed_eab: '$OSSL rand 32' produced nothing — cannot seed an EAB secret" >&2
        exit 1; }
    # Self-sufficient on purpose: a suite may reach newAccount before anything else has
    # touched the schema, and `keys` is the only table this helper needs. Same
    # CREATE-then-INSERT acme_eab.sh does.
    pg_exec "CREATE TABLE IF NOT EXISTS keys(kid TEXT PRIMARY KEY, key TEXT);" >/dev/null
    pg_exec "INSERT INTO keys(kid,protocol,key) VALUES('$ACME_EAB_KID','eab','$ACME_EAB_HMAC')
             ON CONFLICT (kid,protocol) DO UPDATE SET key=EXCLUDED.key;" >/dev/null
    # ⚠️ AND AN IDENTITY, not just a secret — a bare credential issues
    # nothing now. Defined once in user_helpers.sh; sourced here so every suite that takes
    # a credential from this helper gets the identity too, without remembering to.
    command -v seed_enrolling_identity >/dev/null 2>&1 \
        || . "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/user_helpers.sh"
    seed_enrolling_identity "$ACME_EAB_KID"
}

# Create an account with the mandatory binding. Replaces the bare
# `acme_post_jwk <key> "$ACME_NEW_ACCT" '{"termsOfServiceAgreed":true}'` those suites used.
#
# ⚠️ It SEEDS ON DEMAND rather than erroring "call acme_seed_eab first". The kid is an
# implementation detail of the test — no suite here is testing who may register — so making
# each call site remember an ordering step buys nothing and gives every future ACME suite a
# way to fail with a 400 that looks like a product bug. The suites that DO test the policy
# (acme_eab.sh, acme_default_eab.sh) provision their own kid and never call this.
acme_new_account() {   # <account-key>
    [ -n "${ACME_EAB_KID:-}" ] || acme_seed_eab || return 1
    acme_post_newacct_eab "$1" "$ACME_NEW_ACCT" "$ACME_EAB_KID" "$ACME_EAB_HMAC"
}

# newAccount WITH a binding. Same shape as acme_post_jwk; the payload gains the field.
acme_post_newacct_eab() {   # <key> <newAccount-url> <kid> <base64url-hmac>
    local key=$1 url=$2 kid=$3 secret=$4 eab
    eab=$(acme_eab_binding "$key" "$kid" "$secret" "$url") || return 1
    acme_post_jwk "$key" "$url" \
        "$(printf '{"termsOfServiceAgreed":true,"externalAccountBinding":%s}' "$eab")"
}

# Everything afterwards: `kid` is the account URL. An empty payload is POST-as-GET.
acme_post_kid() {   # <key> <kid> <url> <payload-json-or-empty>
    local key=$1 kid=$2 url=$3 payload=$4 prot
    prot=$(printf '{"alg":"ES256","kid":"%s","nonce":"%s","url":"%s"}' \
           "$kid" "$(acme_nonce)" "$url")
    jws_sign "$key" "$prot" "$payload" > "$JWS_TMP/req.json" || return 1
    acme_http "$url" "$JWS_TMP/req.json"
}

# ── tls-alpn-01 (RFC 8737) ──────────────────────────────────────────────────────
# A responder built out of `openssl s_server`, which is the only reason the two
# tls-alpn-01 suites can leave Python: it can advertise the ALPN protocol and serve an
# arbitrary certificate, which is the entire protocol.
#
# The validation certificate is self-signed for the identifier and carries the
# acmeIdentifier extension (1.3.6.1.5.5.7.1.31), critical, whose value is a DER OCTET
# STRING of SHA-256(key authorization) — hence the `0420` prefix, tag 04 length 0x20.
#
# The three suites that still use Python all need a UDP DNS responder for dns-01, which
# no standard tool provides and which shell cannot build without a new dependency (§3f).
# That is the honest boundary of this migration, not an oversight.
alpn_cert() {   # <domain> <token> <account-key> <out-prefix>
    local dom=$1 tok=$2 key=$3 out=$4 keyauth digest
    keyauth="$tok.$(jws_thumbprint "$key")"
    digest=$(printf '%s' "$keyauth" | "$OSSL" dgst -sha256 -binary | od -An -tx1 -v | tr -d ' \n')
    "$OSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$out.key" -out "$out.pem" -days 1 -subj "/CN=$dom" \
        -addext "subjectAltName=DNS:$dom" \
        -addext "1.3.6.1.5.5.7.1.31=critical,DER:0420$digest" >/dev/null 2>&1
    # The whole challenge rests on this certificate carrying THIS token's digest, and
    # openssl's own diagnostics are discarded just above — so a failure to write it would
    # otherwise surface two steps later as a validation error against a certificate that
    # was never created.
    [ -s "$out.pem" ] && [ -s "$out.key" ]
}

# Serve it until stopped. Sets ALPN_PID. Non-zero if this responder is not the thing
# actually answering on that port.
#
# ⚠️ A RESPONDER THAT FAILED TO BIND IMPERSONATES A PRODUCT BUG. This used to background
# s_server, sleep, and return 0 unconditionally. When the port was already held — by a
# responder some killed run leaked, or by an unrelated server — openssl wrote "Address
# already in use" into a log nobody reads, ALPN_PID named a process that had already
# exited, and the validating server connected to whatever else was there.
#
# When that squatter is a LEAKED responder from an earlier run, it is the worst case: it
# negotiates acme-tls/1 correctly and presents a certificate carrying a real acmeIdentifier
# extension — for the PREVIOUS challenge's token. So the server answers, entirely
# correctly:
#
#     the acmeIdentifier digest does not match this challenge's key authorization
#
# and that reads as a broken CA when it is a leaked listener. Refuse a held port, then
# prove the certificate on the wire is the one just generated, so the message names the
# cause instead of the symptom.
alpn_serve() {  # <port> <cert-prefix>
    local port=$1 pfx=$2 i served="" ours=""
    JWS_TMP=${JWS_TMP:-$(mktemp -d)}
    if (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
        # ⚠️ BRACES, NOT A BARE `exec`. `exec 3<&- 3>&- 2>/dev/null` with no command applies
        # that redirection to THIS SHELL, permanently — so every explanation below it, the
        # whole point of the branch, went to /dev/null and the refusal was silent.
        { exec 3<&- 3>&-; } 2>/dev/null || true
        echo "acme_jws: port $port is ALREADY IN USE — a previous run leaked a responder, or" >&2
        echo "          another server holds it. The tls-alpn-01 responder cannot bind, so a" >&2
        echo "          validation failure from here is NOT a product failure." >&2
        ALPN_PID=
        return 1
    fi
    "$OSSL" s_server -accept "$port" -cert "$pfx.pem" -key "$pfx.key" \
        -alpn acme-tls/1 -quiet -no_ticket >"$JWS_TMP/alpn.log" 2>&1 &
    ALPN_PID=$!
    # Detach it from job control, or bash prints "Terminated: 15" beside a passing
    # assertion when alpn_stop kills it — noise that reads like a failure.
    disown "$ALPN_PID" 2>/dev/null || true
    # ⚠️ ASK THE PORT WHICH CERTIFICATE IT SERVES rather than sleeping and hoping. Only the
    # certificate actually on the wire settles whether this challenge can validate at all.
    ours=$("$OSSL" x509 -in "$pfx.pem" -noout -fingerprint -sha256 2>/dev/null)
    for i in $(seq 1 40); do
        kill -0 "$ALPN_PID" 2>/dev/null || break
        served=$("$OSSL" s_client -connect "127.0.0.1:$port" -alpn acme-tls/1 </dev/null 2>/dev/null \
                 | "$OSSL" x509 -noout -fingerprint -sha256 2>/dev/null)
        [ -n "$served" ] && [ "$served" = "$ours" ] && return 0
        sleep 0.25
    done
    echo "acme_jws: the tls-alpn-01 responder is not serving on port $port." >&2
    sed -n '1,4p' "$JWS_TMP/alpn.log" 2>/dev/null >&2
    if [ -n "$served" ] && [ "$served" != "$ours" ]; then
        echo "acme_jws: something ELSE answers on $port — it served $served," >&2
        echo "          ours is $ours. Every digest comparison after this would be against" >&2
        echo "          the wrong certificate." >&2
    fi
    kill "$ALPN_PID" 2>/dev/null; ALPN_PID=
    return 1
}
alpn_stop() { [ -n "${ALPN_PID:-}" ] && kill "$ALPN_PID" 2>/dev/null; ALPN_PID=; }

# ── polling ─────────────────────────────────────────────────────────────────────
# Poll a resource with POST-as-GET until its "status" reaches <want>. Returns non-zero
# on timeout so a caller asserts on the outcome rather than on having waited.
acme_poll_status() {    # <key> <kid> <url> <want> [tries]
    local key=$1 kid=$2 url=$3 want=$4 tries=${5:-40} i=0
    while [ $i -lt "$tries" ]; do
        acme_post_kid "$key" "$kid" "$url" ""
        [ "$(json_str "$ACME_BODY" status)" = "$want" ] && return 0
        sleep 0.25; i=$((i+1))
    done
    return 1
}

# A complete dns-01 order, for suites that only need "did it work" rather than a per-step
# narrative. Returns 0 on a valid order.
#
#   acme_dns01_order <directory-url> <domain> <dns-port> [chain-out.pem]
#
# With a 4th argument the issued fullchain is written there — RFC 8555's certificate URL is
# POST-as-GET, so it cannot be fetched with plain curl; the JWS machinery is already here.
#
# tests/acme_dns01.sh deliberately does NOT use this: it is the dns-01 suite, so it inlines
# the same flow in order to assert each step separately and localise a failure. This exists
# for the suites where dns-01 is a means to an end (acme_perca).
#
# Needs build/dnsstub — see tests/tools/dnsstub.cpp for why one piece of this cannot be
# shell. Runs in a subshell-safe way: the stub is killed before returning.
# ⚠️ WHY THIS EXISTS. acme_post_jwk / acme_post_kid PRINT NOTHING — they put the response
# in $ACME_BODY and the code in $ACME_STATUS. So every `|| exit 1` in acme_dns01_order used
# to abandon the order in silence: ca_rollover_chain.sh reported four red assertions, a
# `grep: acme2.pem: No such file or directory`, and a completely EMPTY client log, with
# nothing anywhere naming the step that failed. The real cause was a newAccount refusal
# three steps earlier (EAB became the default and that suite never pinned it off).
#
# One line naming the step, the status and the body turns "the chain is empty" into "the
# server refused the account, and here is what it said".
_acme_why() {   # <step> [directory-url]
    # ⚠️ Name the challenge actually being driven. This said "acme_dns01_order" for every
    # failure, which was true when there was only one order driver and became a lie the
    # moment http-01 and tls-alpn-01 arrived — a tls-alpn-01 failure reported
    # itself as a dns-01 one, sending the reader to the wrong half of the system.
    echo "acme_order[${_ACME_CHTYPE:-dns-01}]: $1 FAILED  status=${ACME_STATUS:-<none>}" >&2
    # ⚠️ PULL THE PROBLEM DOCUMENT OUT BEFORE TRUNCATING THE BODY. RFC 8555 §6.7 puts the
    # reason in `type`/`detail`, and on a failed authz those sit on ONE challenge inside a
    # list — routinely past the 300-character cut. A tls-alpn-01 log from the lab on
    # Ended mid-word at `{"erro`, losing the only field that said why. Extract first,
    # then print the body, so truncation can no longer swallow the answer.
    if [ -n "${ACME_BODY:-}" ]; then
        local prob
        prob=$(printf '%s' "$ACME_BODY" | tr '{' '\n' \
               | grep -o '"type":"urn:ietf:params:acme:error:[^"]*"\|"detail":"[^"]*"' | head -4)
        [ -n "$prob" ] && printf '  the server said: %s\n' "$(printf '%s' "$prob" | tr '\n' ' ')" >&2
        echo "  body: $(printf '%s' "$ACME_BODY" | head -c 600)" >&2
    fi
    # A newAccount refusal is nearly always policy rather than a broken server, and the
    # directory says which: meta.externalAccountRequired. Fetch it so the answer is in the
    # same place as the question.
    if [ -n "${2:-}" ]; then
        local meta; meta=$(curl -sk --max-time 5 "$2" | tr ',' '\n' | grep -i 'externalAccountRequired')
        [ -n "$meta" ] && echo "  the directory says:$meta  ->  this deployment requires EAB." >&2
        [ -n "$meta" ] && echo "  register with acme_new_account (it provisions the binding); there is no switch to turn EAB off." >&2
    fi
    return 0
}
# ── challenge responders ────────────────────────────────────────────────────────
# One order driver, three challenge types. The RFC 8555 flow is identical for all
# of them — newAccount, newOrder, read the authz, satisfy ONE challenge, finalize — and
# only the "satisfy" step differs, so that is the only part that is per-type. Each
# responder starts a listener and sets _ACME_RESP_PID; _acme_respond_stop kills it.
#
# ⚠️ The type strings are the RFC 8555 §8 names and are matched against the authz body,
# so they must stay exactly "dns-01" / "http-01" / "tls-alpn-01".
_acme_respond() {   # <chtype> <domain> <token> <keyauth>
    local ty=$1 dom=$2 tok=$3 keyauth=$4
    case "$ty" in
      dns-01)
        local txt; txt=$(printf '%s' "$keyauth" | "${OSSL:-openssl}" dgst -sha256 -binary | b64url)
        # RFC 8555 §8.4: a WILDCARD identifier publishes its TXT at the BASE name —
        # `_acme-challenge.example.com`, never `_acme-challenge.*.example.com`, which is
        # not a legal DNS owner name.
        #
        # WHO PUBLISHES IT is the caller's choice. The suites use build/dnsstub, which needs
        # nothing but a port. demo/pki-demo.sh publishes through the upstream coredns/coredns
        # container instead, so the demo exercises the same resolver a real deployment would
        # meet rather than a tool that exists only in this repo — and so its two dns-01 cells
        # share one mechanism instead of having one each. ACME_DNS_PUBLISH_HOOK is how it
        # says so: called with <owner-name> <txt-value>, it must have the record answerable
        # by the time it returns.
        if [ -n "${ACME_DNS_PUBLISH_HOOK:-}" ]; then
            "$ACME_DNS_PUBLISH_HOOK" "_acme-challenge.${dom#\*.}" "$txt" >resp.log 2>&1 \
                || { _acme_why dns-publish "$ACME_DNS_PUBLISH_HOOK"; exit 1; }
        else
            "$ACME_DNSSTUB" "${_ACME_DNSPORT:?dns-01 needs _ACME_DNSPORT}" \
                "TXT:_acme-challenge.${dom#\*.}=$txt" > resp.log 2>&1 &
            _ACME_RESP_PID=$!
            local i; for i in $(seq 1 40); do grep -q READY resp.log 2>/dev/null && break; sleep 0.1; done
        fi
        ;;
      http-01)
        # RFC 8555 §8.3 fixes the validation port at 80 and the server honours it, so this
        # needs root. The caller gates on that; here we only serve.
        _acme_http_serve "${_ACME_HTTP_PORT:-80}" "$keyauth" || return 1
        ;;
      tls-alpn-01)
        alpn_cert "$dom" "$tok" acct.pem "val_$dom"       || return 1
        alpn_serve "${_ACME_ALPN_PORT:-443}" "val_$dom"   || return 1
        _ACME_RESP_PID=$ALPN_PID
        ;;
      *) return 1;;
    esac
    return 0
}
# ⚠️ KILL THE CHILD FIRST, or the listener outlives the suite and holds the port forever.
#
# The http-01 responder is a subshell looping on `nc`, and that subshell spends its whole
# life BLOCKED INSIDE nc. Killing only the subshell orphans the nc: it reparents to init
# and keeps :80 bound. Measured on test-01 — `nc -l -p 80`, PPID 1, still listening NINE
# HOURS after the run that started it, which is why acme_lifecycle.sh had been failing
# in-image with certbot unable to bind. Nothing named the cause; the suite simply could
# not get a certificate.
#
# pkill -P is not portable enough to rely on (busybox), so the responder traps TERM and
# kills its own nc — see _acme_http_serve. This also `wait`s, so the port is actually
# released before the next suite starts rather than a few milliseconds later.
_acme_respond_stop() {
    [ -n "${_ACME_RESP_PID:-}" ] || { _ACME_RESP_PID=; return 0; }
    kill "$_ACME_RESP_PID" 2>/dev/null
    wait "$_ACME_RESP_PID" 2>/dev/null
    _ACME_RESP_PID=
}

# A one-path HTTP responder. §3e keeps this shell-only, and an ACME server fetches
# exactly one URL per challenge, so a serial accept loop is enough — no second compiled
# stub beside dnsstub.
#
# It answers EVERY request with the key authorization rather than routing on the path.
# That is correct for a challenge responder (the server asks for
# /.well-known/acme-challenge/<token> and nothing else) and it avoids parsing HTTP in
# shell, which is where a hand-rolled listener usually goes wrong.
_acme_http_serve() {   # <port> <key-authorization>
    local port=$1 ka=$2 ncflags
    command -v nc >/dev/null 2>&1 || { echo "acme_jws: http-01 needs nc" >&2; return 1; }
    # ⚠️ `nc -l` is not portable: BSD/macOS takes `nc -l <port>`, GNU and busybox want
    # `nc -l -p <port>`. Probe once rather than assuming, or the listener silently never
    # binds and the challenge times out with nothing naming the cause.
    if nc -l -p "$port" </dev/null >/dev/null 2>&1 & sleep 0.2; kill %% 2>/dev/null; then
        ncflags="-l -p"
    else
        ncflags="-l"
    fi
    # ⚠️ REFUSE TO START ON A PORT SOMEONE ELSE HOLDS. A stale listener here does not
    # announce itself: nc simply fails to bind, the loop spins, the challenge times out,
    # and certbot reports a validation failure that reads exactly like a product bug. That
    # is how a leaked `nc -l -p 80` sat on test-01 for nine hours quietly failing
    # acme_lifecycle.sh in-image. Say it plainly instead.
    if (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
        # ⚠️ BRACES, NOT A BARE `exec`. `exec 3<&- 3>&- 2>/dev/null` with no command applies
        # that redirection to THIS SHELL, permanently — so every explanation below it, the
        # whole point of the branch, went to /dev/null and the refusal was silent.
        { exec 3<&- 3>&-; } 2>/dev/null || true
        echo "acme_jws: port $port is ALREADY IN USE — a previous run leaked a listener." >&2
        echo "          The http-01 challenge cannot bind, so this is not a product failure." >&2
        return 1
    fi
    # ⚠️ The loop's shell spends its life BLOCKED INSIDE nc, so a plain kill of the shell
    # orphans that nc and the port stays bound (see _acme_respond_stop). Backgrounding nc
    # and trapping TERM gives the shell something it can actually clean up.
    ( ncpid=
      trap 'kill $ncpid 2>/dev/null; exit 0' TERM INT
      while :; do
        printf 'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
               "${#ka}" "$ka" | nc $ncflags "$port" >/dev/null 2>&1 &
        ncpid=$!
        wait "$ncpid" || break
      done ) &
    _ACME_RESP_PID=$!
    disown "$_ACME_RESP_PID" 2>/dev/null || true
    # wait_listen, not wait_port: this is a loop of one-shot nc listeners, so a probe that
    # connects would consume the very response the challenge fetch needs (pg_helpers.sh).
    wait_listen "$port" "$_ACME_RESP_PID" 10 || true
    return 0
}

# tls-alpn-01 order (RFC 8737). _ACME_ALPN_PORT selects the port the responder binds;
# the ACME server's ACME_TLS_ALPN_PORT must agree, and defaults to 443 on both sides.
acme_alpn01_order() {   # <directory-url> <domain> <alpn-port> [chain-out]
    _ACME_ALPN_PORT="$3" _acme_order "$1" "$2" tls-alpn-01 "${4:-}"
}
# http-01 order (RFC 8555 §8.3). The port is fixed at 80 by the protocol, so this needs
# root; _ACME_HTTP_PORT exists only so a test can prove the refusal on another port.
acme_http01_order() {   # <directory-url> <domain> [chain-out]
    _ACME_HTTP_PORT="${_ACME_HTTP_PORT:-80}" _acme_order "$1" "$2" http-01 "${3:-}"
}

acme_dns01_order() {
    local dir="$1" domain="$2" dnsport="$3" chain_out="${4:-}"
    _ACME_DNSPORT="$dnsport" _acme_order "$dir" "$domain" dns-01 "$chain_out"
}

_acme_order() {
    local dir="$1" domain="$2" chtype="$3" chain_out="${4:-}" rc=1
    _ACME_CHTYPE="$chtype"          # so _acme_why names the right challenge
    # ⚠️ ABSOLUTE, resolved BEFORE the subshell cds into its own workdir. A relative path
    # would be written inside that temp dir and deleted with it, and the caller would see
    # an empty chain with every step reporting success — which is exactly what
    # ca_rollover_chain.sh got.
    case "$chain_out" in ''|/*) ;; *) chain_out="$PWD/$chain_out" ;; esac
    local wd; wd=$(mktemp -d)
    (
        cd "$wd" || exit 1
        acme_dir "$dir"                                     || { _acme_why directory ""; exit 1; }
        jws_newkey acct.pem
        # EAB is mandatory. acme_new_account reuses the caller's
        # ACME_EAB_KID/HMAC when it set them and provisions its own otherwise, so this one
        # call covers both — the branch that used to skip the binding is gone with the key.
        acme_new_account acct.pem
        local kid=$ACME_LOCATION
        [ -n "$kid" ]                                       || { _acme_why newAccount "$dir"; exit 1; }
        acme_post_kid acct.pem "$kid" "$ACME_NEW_ORDER" \
            "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"$domain\"}]}"
        [ "$ACME_STATUS" = 201 ]                            || { _acme_why newOrder ""; exit 1; }
        local order=$ACME_LOCATION
        local authz; authz=$(printf '%s' "$ACME_BODY" | sed -n 's/.*"authorizations":\["\([^"]*\)".*/\1/p')
        acme_post_kid acct.pem "$kid" "$authz" ""
        # ⚠️ Match the challenge by the type the CALLER asked for. Grepping for a fixed
        # 'dns-01' here is what limited this driver to one challenge type.
        local ch;   ch=$(printf '%s' "$ACME_BODY" | tr '{' '\n' | grep "$chtype")
        local churl; churl=$(json_str "$ch" url)
        local token; token=$(json_str "$ch" token)
        [ -n "$churl" ] && [ -n "$token" ]                  || { _acme_why "authz (no $chtype challenge)" ""; exit 1; }
        local keyauth="$token.$(jws_thumbprint acct.pem)"
        _acme_respond "$chtype" "$domain" "$token" "$keyauth" \
            || { _acme_why "could not stand up a $chtype responder" ""; exit 1; }
        acme_post_kid acct.pem "$kid" "$churl" '{}'
        if [ "$ACME_STATUS" != 200 ]; then _acme_why "challenge accept" ""; _acme_respond_stop; exit 1; fi
        acme_poll_status acct.pem "$kid" "$authz" valid || { _acme_why "authz never went valid ($chtype)" ""; _acme_respond_stop; exit 1; }
        "${OSSL:-openssl}" ecparam -name prime256v1 -genkey -noout -out leaf.key 2>/dev/null
        printf '[req]\ndistinguished_name=dn\nreq_extensions=v3\nprompt=no\n[dn]\n[v3]\nsubjectAltName=DNS:%s\n' \
               "$domain" > csr.cnf
        "${OSSL:-openssl}" req -new -key leaf.key -subj "/CN=$domain" -config csr.cnf \
               -outform DER -out leaf.csr 2>/dev/null
        acme_post_kid acct.pem "$kid" "$order" ""
        local fin; fin=$(printf '%s' "$ACME_BODY" | sed -n 's/.*"finalize":"\([^"]*\)".*/\1/p')
        acme_post_kid acct.pem "$kid" "$fin" "{\"csr\":\"$(b64url < leaf.csr)\"}"
        if [ "$ACME_STATUS" != 200 ]; then _acme_why finalize ""; _acme_respond_stop; exit 1; fi
        # ⚠️ THESE THREE EXITS USED TO BE COMPLETELY SILENT — the only failures in this
        # function that call no _acme_why. They are also the LAST three, so reaching them
        # means the challenge validated and the CA then declined to hand over a
        # certificate. The client log came out EMPTY, which is the worst possible report:
        # it says the order failed, refuses to say where, and reads like a broken harness
        # rather than a refused issuance. That is exactly what the reported http-01
        # run produced — an empty chal-http-01.log with nothing to go on.
        #
        # An order that finalizes and then never goes valid is the CA refusing to issue,
        # and RFC 8555 §7.1.6 puts the reason in the order's own `error`, which _acme_why
        # now prints.
        acme_poll_status acct.pem "$kid" "$order" valid; local r=$?
        if [ "$r" -ne 0 ]; then
            _acme_why "order never went valid after finalize" ""
        elif [ -n "$chain_out" ]; then
            local curl_; curl_=$(json_str "$ACME_BODY" certificate)
            if [ -z "$curl_" ]; then
                _acme_why "the order is valid but names no certificate URL" ""; r=1
            else
                acme_post_kid acct.pem "$kid" "$curl_" ""
                printf '%s' "$ACME_BODY" > "$chain_out"
                # A non-200 and a 200 with an empty body both land here, and both used to
                # become a bare r=1 with the chain file silently empty.
                if [ ! -s "$chain_out" ]; then
                    _acme_why "certificate fetch returned no PEM" ""; r=1
                fi
            fi
        fi
        _acme_respond_stop
        exit $r
    )
    rc=$?
    rm -rf "$wd"
    return $rc
}
# Where the stub lives. Overridable so a suite with a different layout can point at it.
ACME_DNSSTUB="${ACME_DNSSTUB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/build/dnsstub}"
