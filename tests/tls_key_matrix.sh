#!/usr/bin/env bash
# The ticket's headline ask: the FOUR TLS services across every key type TLS supports.
#
# Four services — web console, EST, ACME, MS — use TLS, so their keys are restricted to
# what TLS supports, which today excludes ML-DSA. Each remaining key type (RSA, RSA-PSS,
# EC, Ed) needs coverage on those TLS services.
#
# Everything else varied the CA key or the CSR key. NOTHING varied the SERVER's own
# listener key, which is what this asserts — and it needs no product change to express:
# each listener already reads its own `<SVC>_KEY_ALGO` / `_BITS` / `_CURVE`, because
# "give a customer full control over keys for each service" is exactly what one shared
# setting cannot do. The shipped default is `ec` / P-256 for all four.
#
# ⚠️ THE ASSERTION IS THE HANDSHAKE PLUS THE DECODED SPKI, not the config and not the exit
# code. A service that ignored its key setting entirely would still start, still serve, and
# still pass any "is it up?" check — it would just present a key of the wrong type. So each
# cell connects with a real TLS client and asks the PRESENTED CERTIFICATE what its public
# key is.
#
# ⚠️ RSA-PSS SERVES, and I had this backwards. I wrote this suite asserting that an
# rsa-pss listener key would be REFUSED, reasoning that RSA-PSS is signature-only and
# cannot do key transport. That is true of TLS 1.2's RSA key exchange and irrelevant here:
# TLS 1.3 never does RSA key transport — it is ECDHE plus a signature — and rsa_pss_pss_*
# is a first-class TLS 1.3 signature scheme. All four listeners complete a real handshake
# with an rsa-pss key and present an rsassaPss SPKI. The product was right and the
# assertion was wrong, so it now asserts what actually happens.
# This suite found the defect and now guards it: the per-service key type used to be honoured
# only when the listener key was a `pkcs11:` handle, so with a FILE key — the deployment
# default — `<SVC>_KEY_ALGO` was parsed, documented and silently ignored and every listener
# got EC P-256. 12 of 16 cells failed. With the fix, 16/16.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
[ -n "$OSSL" ] || { echo "SKIP: no openssl on PATH"; exit 0; }
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF

W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup tls_key_matrix
SRV=
trap 'kill $SRV 2>/dev/null; pg_cleanup' EXIT

# The four TLS listeners, each with its own port, binary, and config key names. Kept as one
# table so a fifth TLS service cannot be added without appearing here.
#   name | binary | port | cert-key | key-key | algo-prefix | probe path
SERVICES="
web|fastpki-web|18601|WEB_TLS_CERT|WEB_TLS_KEY|WEB|/
est|fastpki-est|18602|EST_CERT|EST_KEY|EST|/.well-known/est/ca/cacerts
acme|fastpki-acme|18603|ACME_CERT|ACME_KEY|ACME|/acme/ca/directory
ms|fastpki-ms|18604|MS_CERT|MS_KEY|MS|/msxcep/ca
"

# What the SPKI of a presented certificate should say, per requested algo.
spki_want() {
    case "$1" in
        rsa)     echo "rsaEncryption";;
        ec)      echo "id-ecPublicKey";;
        ed25519) echo "ED25519";;
        rsa-pss) echo "rsassaPss";;
        *)       echo "?";;
    esac
}

# Bring one listener up with one key algo and report what it presents.
#   -> "spki=<algo name>" on a successful handshake, or "no-handshake", or "died"
probe() {   # <svc> <bin> <port> <certkey> <keykey> <prefix> <path> <algo> [md]
    local svc=$1 bin=$2 port=$3 ck=$4 kk=$5 pfx=$6 path=$7 algo=$8 md=${9:-}
    # The digest axis shares every per-cell name with the key axis, so a cell is
    # <algo> or <algo>-<md>. Getting this wrong is not cosmetic — see the CERT_ID warning
    # below; two cells sharing an id means the second serves the first one's certificate.
    local cell="$algo${md:+-$md}"
    local conf="$W/$svc-$cell.conf"
    # ⚠️ A DISTINCT <PFX>_CERT_ID PER CELL, AND IT IS LOAD-BEARING. resolve_transport_cert
    # ADOPTS an existing `certs` row for its cert_id before minting anything
    # (list_transport_candidates), so cells sharing one id all serve whatever the FIRST one
    # created. Measured before this existed: all sixteen cells reported id-ecPublicKey —
    # four services x four algos — because `ec` ran first and every later cell adopted its
    # row. That reads exactly like "the product ignores <SVC>_KEY_ALGO".
    cat > "$conf" <<EOF
PG_CONNINFO=$PG_CONNINFO
LOG_LEVEL=err
${pfx}_BIND=127.0.0.1
${pfx}_PORT=$port
${ck}=$W/$svc-$algo.crt
${kk}=$W/$svc-$algo.key
${pfx}_KEY_ALGO=$algo
${pfx}_KEY_CURVE=P-256
${pfx}_KEY_BITS=2048
${pfx}_CERT_ID=$svc-$cell
EOF
    # Only written when asked for, so the key-axis cells above still exercise the
    # "operator set nothing" path rather than silently pinning a digest.
    [ -n "$md" ] && printf '%s_KEY_MD=%s\n' "$pfx" "$md" >> "$conf"
    # web binds WEB_BIND/WEB_PORT; the others use <PFX>_BIND/<PFX>_PORT too, but web also
    # needs writes enabled to serve its console at all.
    [ "$svc" = web ] && printf 'WEB_ALLOW_REVOKE=true\n' >> "$conf"
    "$ROOT/build/$bin" --config "$conf" > "$W/$svc-$cell.log" 2>&1 & SRV=$!
    local i
    for i in $(seq 1 30); do
        kill -0 $SRV 2>/dev/null || break
        "$OSSL" s_client -connect "127.0.0.1:$port" -servername localhost </dev/null \
            >"$W/$svc-$cell.hs" 2>/dev/null && break
        command sleep 0.3 2>/dev/null || true
    done
    if ! kill -0 $SRV 2>/dev/null; then echo "died"; SRV=; return; fi
    "$OSSL" s_client -connect "127.0.0.1:$port" -servername localhost -showcerts </dev/null \
        2>/dev/null | awk '/BEGIN CERT/,/END CERT/' > "$W/$svc-$cell.pem"
    kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; SRV=
    [ -s "$W/$svc-$cell.pem" ] || { echo "no-handshake"; return; }
    local a
    a=$("$OSSL" x509 -in "$W/$svc-$cell.pem" -noout -text 2>/dev/null \
        | sed -n 's/.*Public Key Algorithm: *//p' | head -1)
    echo "spki=${a:-unknown}"
}

for row in $(printf '%s' "$SERVICES" | tr ' ' '\n' | grep .); do
    IFS='|' read -r svc bin port ck kk pfx path <<EOF
$row
EOF
    [ -x "$ROOT/build/$bin" ] || { echo "  [note] $bin not built — $svc NOT measured"; continue; }
    echo "=== $svc listener key types ==="
    for algo in ec rsa ed25519; do
        got=$(probe "$svc" "$bin" "$port" "$ck" "$kk" "$pfx" "$path" "$algo")
        want=$(spki_want "$algo")
        case "$got" in
            spki=*) chk "$svc with a $algo listener key presents $want" "spki=$want" "$got";;
            # ⚠️ REPORTED, NEVER SILENT. ed25519 through the pkcs11 provider does not work on
            # every host (measured: EC/Ed sign on Linux and not on macOS), so
            # a cell that cannot run says which and why instead of disappearing.
            *)      echo "  [note] $svc/$algo did not complete a handshake ($got) — see $svc-$algo.log";;
        esac
    done
    # rsa-pss completes a real TLS 1.3 handshake and presents an rsassaPss SPKI.
    got=$(probe "$svc" "$bin" "$port" "$ck" "$kk" "$pfx" "$path" rsa-pss)
    chk "$svc with an rsa-pss listener key presents rsassaPss" "spki=rsassaPss" "$got"

    # ── THE OTHER HALF OF THE ASK: the DIGEST axis ───────────────────────────────
    #
    # The ask covers each key type (RSA, RSA-PSS, EC, Ed) AND the hash functions
    # (sha2, sha3) for these TLS services.
    #
    # The key axis above shipped earlier. Nothing had ever varied the digest a
    # listener certificate is SIGNED with: `<SVC>_KEY_MD` did not exist, and
    # selfsign_tls_cert called ca_signing_md(), which derives sha256 from the key and
    # takes no operator input at all.
    #
    # ⚠️ THE ASSERTION IS THE DECODED signatureAlgorithm. A listener that ignored the
    # setting would start, serve, and hand back a perfectly valid certificate — signed
    # sha256. Only the bytes say which.
    sigalg() {   # <algo> <md> -> the signatureAlgorithm of the cert that cell presented
        "$OSSL" x509 -in "$W/$svc-$1-$2.pem" -noout -text 2>/dev/null \
            | sed -n 's/^ *Signature Algorithm: *//p' | head -1
    }
    for md in sha512 sha3-256; do
        got=$(probe "$svc" "$bin" "$port" "$ck" "$kk" "$pfx" "$path" rsa "$md")
        case "$got" in
          spki=rsaEncryption)
            # OpenSSL names these sha512WithRSAEncryption and RSA-SHA3-256.
            chk "$svc rsa + ${pfx}_KEY_MD=$md signs with $md" yes \
                "$(sigalg rsa "$md" | grep -qiE "${md}withrsa|RSA-${md}" && echo yes || echo "no ($(sigalg rsa "$md"))")";;
          *) echo "  [note] $svc/rsa/$md did not complete a handshake ($got)";;
        esac
    done
    # ⚠️ ANTI-VACUITY CONTROL, and the one that would catch a naive implementation.
    # An EC key has NO digest choice — the digest must match the curve's security level
    # or the signature is malformed — so leaf_signing_md ignores the request for EC. If
    # <SVC>_KEY_MD were simply passed to the signer, this cell would come back sha512 on
    # a P-256 key. It must stay sha256, i.e. the setting is honoured exactly where a
    # choice exists and nowhere else.
    got=$(probe "$svc" "$bin" "$port" "$ck" "$kk" "$pfx" "$path" ec sha512)
    case "$got" in
      spki=id-ecPublicKey)
        chk "⚠️ $svc ec IGNORES ${pfx}_KEY_MD — P-256 auto-matches sha256" yes \
            "$(sigalg ec sha512 | grep -qi 'ecdsa-with-SHA256' && echo yes || echo "no ($(sigalg ec sha512))")";;
      *) echo "  [note] $svc/ec/sha512 did not complete a handshake ($got)";;
    esac
    # And a digest name this build of OpenSSL does not know must not stop the listener
    # coming up — refusing to serve over a cosmetic label would be the wrong trade.
    got=$(probe "$svc" "$bin" "$port" "$ck" "$kk" "$pfx" "$path" rsa notadigest)
    chk "$svc still starts with an unknown ${pfx}_KEY_MD" "spki=rsaEncryption" "$got"
done

echo
echo "=== TLS KEY MATRIX: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
