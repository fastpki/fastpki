#!/usr/bin/env bash
# Replicating a CA private key from one node's token into another's.
#
# ── Why this exists ────────────────────────────────────────────────────────────────────
#
# Every node has its own token. A CA whose key lives in only one of them dies with that
# node: the survivors cannot issue under it and — the part that cannot be repaired later —
# cannot renew or revoke anything it already signed. Replication is what makes losing a
# node survivable, and `docs/architecture.md` §5-§6 is the design record for it.
#
# ── What is asserted, and why each one matters ─────────────────────────────────────────
#
# ⚠️ THE ASSERTION IS THAT THE COPY IS THE SAME KEY, not that a transfer reported success.
# A wrapped blob that decodes to something is worth nothing: a derivation mismatch, a wrong
# source object or a stale blob all produce a handle that loads perfectly and signs
# certificates chaining to nothing. So the destination's copy SIGNS here, and the signature
# is verified against the CA certificate's public key — which came from the source.
#
# ⚠️ AND THAT THE KEY NEVER TOUCHES THE FILESYSTEM. Two tokens, two p11-kit servers, two
# separate token directories: the only path between them is the wrapped blob the CLI holds
# in memory. The negative half is the point — a CA created the ordinary way must REFUSE to
# be replicated, because CKA_EXTRACTABLE is fixed at generation and PKCS#11 does not allow
# granting it afterwards.
#
# The mTLS tunnel `--from` raises is NOT exercised end to end here; tests/hsm_tls_transport.sh
# already proves an authorised client reaches a published token through stunnel and a rogue
# one sees nothing. What this asserts about `--from` is that it refuses safely when this
# node has no material to dial with.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"
CA="$ROOT/build/fastpki-ca"

pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
skipout(){ echo "  [SKIP] $1"; echo; echo "=== KEY REPLICATION: PASS=$pass FAIL=$fail SKIP=1 ==="; exit 0; }

hsm_available || skipout "$(hsm_skip_reason)"
[ -x "$CA" ]   || skipout "build/fastpki-ca is not built"

W="$(mktemp -d)"; cd "$W"
# ⚠️ THE LAST TRAP MUST BE A SUPERSET OF EVERY EARLIER ONE — bash replaces traps rather
# than stacking them. Two p11-kit servers here, and each forks a child per connected
# client: killing only the listener leaves a fork holding a fully live token.
cleanup() {
    for p in ${SRV_A:-} ${SRV_B:-}; do
        pkill -P "$p" 2>/dev/null || true
        kill "$p" 2>/dev/null || true
    done
    pg_cleanup
    rm -rf "$W"
}
trap cleanup EXIT

# ── two nodes, two tokens, two servers ────────────────────────────────────────────────
#
# Both tokens are labelled `fastpki`, which is not laziness: every node in a real
# deployment labels its own token that way, and a transfer that only worked when the two
# labels differed would be testing an arrangement nobody deploys.
start_node() {   # start_node <name>  ->  sets NODE_SOCK
    # ⚠️ TWO STATEMENTS, NOT ONE. `local n="$1" d="$W/$n"` expands every word BEFORE it
    # assigns any of them, so $n is still unset when $d is built — and under `set -u` that
    # kills the suite at its first call rather than producing a wrong path.
    local n="$1"
    local d="$W/$n"
    mkdir -p "$d/tokens"
    printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
        "$d/tokens" > "$d/softhsm2.conf"
    SOFTHSM2_CONF="$d/softhsm2.conf" "$HSM_UTIL" --module "$HSM_SOFTHSM" \
        --init-token --free --label fastpki --pin 1234 --so-pin 12345678 >/dev/null 2>&1 \
        || return 1
    SOFTHSM2_CONF="$d/softhsm2.conf" "$HSM_P11KIT" server -f -n "$d/p11.sock" \
        --provider "$HSM_SOFTHSM" "pkcs11:" > "$d/server.log" 2>&1 &
    NODE_PID=$!
    local i; for i in $(seq 1 40); do [ -S "$d/p11.sock" ] && break; sleep 0.25; done
    [ -S "$d/p11.sock" ] || return 1
    NODE_SOCK="unix:path=$d/p11.sock"
    return 0
}

start_node a || skipout "could not start node A's token server"
SOCK_A="$NODE_SOCK"; SRV_A="$NODE_PID"
start_node b || skipout "could not start node B's token server"
SOCK_B="$NODE_SOCK"; SRV_B="$NODE_PID"

pg_setup key_replication
export PKCS11_PROVIDER_MODULE="$HSM_CLIENT"
cat > conf <<EOF
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
PKCS11_TOKEN=fastpki
LOG_LEVEL=err
EOF
hsm_conf_lines >> conf

URI_R='pkcs11:token=fastpki;object=repl-ca;type=private?pin-value=1234'
URI_N='pkcs11:token=fastpki;object=plain-ca;type=private?pin-value=1234'

echo "=== 1. a CA created --replicable, in node A's token ==="
# ⚠️ THROUGH PKCS#11 DIRECTLY, because the OpenSSL pkcs11 provider offers no parameter for
# CKA_EXTRACTABLE. That single attribute is the whole reason --replicable exists, and it
# can only be chosen here: PKCS#11 forbids granting it after generation.
P11_KIT_SERVER_ADDRESS="$SOCK_A" "$CA" --config conf create repl-ca \
    --name "Replicable CA" --subject "/CN=Replicable CA" --ca-key "$URI_R" \
    --keygen --key ec --replicable --out-dir cas >create_r.log 2>&1
chk "the CA is created" 0 "$?"
chk "  its certificate exists" yes "$([ -s cas/repl-ca.crt ] && echo yes || echo no)"
[ -s cas/repl-ca.crt ] || { cat create_r.log; echo; echo "=== KEY REPLICATION: PASS=$pass FAIL=$((fail+1)) ==="; exit 1; }
chk "  and no private key was written to disk" yes \
    "$([ ! -f cas/repl-ca.key ] && echo yes || echo no)"
chk "  node A's token holds it" yes \
    "$(P11_KIT_SERVER_ADDRESS="$SOCK_A" "$HSM_PKTOOL" --module "$HSM_CLIENT" \
        --token-label fastpki --list-objects --login --pin 1234 2>/dev/null \
        | grep -q 'repl-ca' && echo yes || echo no)"
chk "  and node B's token does NOT" yes \
    "$(P11_KIT_SERVER_ADDRESS="$SOCK_B" "$HSM_PKTOOL" --module "$HSM_CLIENT" \
        --token-label fastpki --list-objects --login --pin 1234 2>/dev/null \
        | grep -q 'repl-ca' && echo no || echo yes)"
# ⚠️ THE PRECONDITION FOR EVERYTHING BELOW, asserted directly rather than inferred from a
# later failure. CKA_EXTRACTABLE is fixed at generation, so if --replicable did not set it
# the replication cannot work and no other assertion here explains why. hsm_key_extractable
# reads the private half's Access line and matches the attribute exactly: a substring grep
# also matches `never extractable`, so it could not fail.
chk "  and the private half is marked extractable" yes \
    "$(P11_KIT_SERVER_ADDRESS="$SOCK_A" hsm_key_extractable fastpki repl-ca)"
# What an operator reads before a standby is joined: `key list` on each node, one line per key.
chk "  and key list on node A says it is here and replicable" yes \
    "$(P11_KIT_SERVER_ADDRESS="$SOCK_A" "$CA" --config conf key list repl-ca 2>/dev/null \
        | grep -q "in this node's token, replicable]" && echo yes || echo no)"
chk "  and key list on node B says it is not in node B's token" yes \
    "$(P11_KIT_SERVER_ADDRESS="$SOCK_B" "$CA" --config conf key list repl-ca 2>/dev/null \
        | grep -q "[not in this node's token]" && echo yes || echo no)"

echo "=== 2. node B replicates it into its own token ==="
P11_KIT_SERVER_ADDRESS="$SOCK_B" "$CA" --config conf key replicate repl-ca \
    --source-socket "$SOCK_A" --source-key "$URI_R" >repl.log 2>&1
RC=$?
chk "the replication succeeds" 0 "$RC"
[ "$RC" = 0 ] || cat repl.log
chk "  node B's token now holds the key" yes \
    "$(P11_KIT_SERVER_ADDRESS="$SOCK_B" "$HSM_PKTOOL" --module "$HSM_CLIENT" \
        --token-label fastpki --list-objects --login --pin 1234 2>/dev/null \
        | grep -q 'repl-ca' && echo yes || echo no)"
# ⚠️ AND NODE A STILL HAS ITS OWN. This is replication, not a move: a transfer that
# emptied the source would turn "survive losing a node" into "move the problem".
chk "  and node A still has its own" yes \
    "$(P11_KIT_SERVER_ADDRESS="$SOCK_A" "$HSM_PKTOOL" --module "$HSM_CLIENT" \
        --token-label fastpki --list-objects --login --pin 1234 2>/dev/null \
        | grep -q 'repl-ca' && echo yes || echo no)"

echo "=== 3. ⚠️ THE COPY IS THE SAME KEY — it signs, and the CA certificate verifies it ==="
# The only assertion that matters. A handle that loads proves nothing; this signs with
# node B's copy and verifies against the public key inside the certificate node A
# self-signed, so the two keys are the same key or this fails.
echo "replication proof $$" > msg.txt
# ⚠️ -rawin WITH -digest, not without. `-rawin` alone is the one-shot form EdDSA and ML-DSA
# take; an ECDSA key signs a digest, and omitting it makes openssl reject the operation
# rather than sign — which would read here as "the replicated key cannot sign".
P11_KIT_SERVER_ADDRESS="$SOCK_B" "$OSSL" pkeyutl -sign -inkey "$URI_R" \
    -provider pkcs11 -provider default -rawin -digest sha256 \
    -in msg.txt -out sig.bin >sign.log 2>&1
chk "node B's copy produces a signature" yes "$([ -s sig.bin ] && echo yes || echo no)"
[ -s sig.bin ] || cat sign.log
"$OSSL" x509 -in cas/repl-ca.crt -noout -pubkey > capub.pem 2>/dev/null
chk "  and the CA certificate's public key verifies it" yes \
    "$("$OSSL" pkeyutl -verify -pubin -inkey capub.pem -rawin -digest sha256 \
        -in msg.txt -sigfile sig.bin >/dev/null 2>&1 && echo yes || echo no)"

echo "=== 4. the key list node B registered names its OWN token ==="
# certs.private_key is node-local: it must name the object that now exists HERE, never a
# peer's. A URL pointing at another machine could not be opened anyway — every candidate
# is resolved through the one PKCS#11 module this process has.
# ⚠️ COUNT, DO NOT MATCH. Both "nodes" share one database here, so the row already carried
# the handle `create` registered — grepping for the object label passed whether or not the
# replication had done anything at all. What proves this step ran is a SECOND entry.
chk "node B added its own handle to the key list" 2 \
    "$(pg_exec "SELECT coalesce(private_key,'') FROM certs WHERE id='repl-ca' AND is_ca;" \
       | grep -c '^pkcs11:')"

echo "=== 5. ⚠️ AN ORDINARY CA REFUSES TO BE REPLICATED, and says why ==="
# The negative half, and the reason --replicable has to exist at all. CKA_EXTRACTABLE is
# set when a key is generated; a CA minted the ordinary way can never leave its token, and
# no retry or flag will change that afterwards. The message has to send the operator to
# CA creation rather than to the mechanism.
P11_KIT_SERVER_ADDRESS="$SOCK_A" "$CA" --config conf create plain-ca \
    --name "Plain CA" --subject "/CN=Plain CA" --ca-key "$URI_N" \
    --keygen --key ec --out-dir cas >create_n.log 2>&1
if [ -s cas/plain-ca.crt ]; then
    # The control for section 1's attribute check: without it, a check that answered yes
    # about every key would pass there unnoticed.
    chk "an ordinary CA key is NOT marked extractable" no \
        "$(P11_KIT_SERVER_ADDRESS="$SOCK_A" hsm_key_extractable fastpki plain-ca)"
    chk "  and key list says it can never be copied" yes \
        "$(P11_KIT_SERVER_ADDRESS="$SOCK_A" "$CA" --config conf key list plain-ca 2>/dev/null \
            | grep -q "NOT replicable: it can never be copied" && echo yes || echo no)"
    P11_KIT_SERVER_ADDRESS="$SOCK_B" "$CA" --config conf key replicate plain-ca \
        --source-socket "$SOCK_A" --source-key "$URI_N" >plain.log 2>&1
    chk "replicating a non-replicable CA fails" no \
        "$([ "$?" = 0 ] && echo yes || echo no)"
    chk "  and the message names the cause, not the mechanism" yes \
        "$(grep -qi 'non-extractable\|--replicable' plain.log && echo yes || echo no)"
    chk "  and node B's token was left without it" yes \
        "$(P11_KIT_SERVER_ADDRESS="$SOCK_B" "$HSM_PKTOOL" --module "$HSM_CLIENT" \
            --token-label fastpki --list-objects --login --pin 1234 2>/dev/null \
            | grep -q 'plain-ca' && echo no || echo yes)"
else
    echo "  [SKIP] the ordinary CA could not be created; see create_n.log"
fi

echo "=== 6. --from refuses safely when this node cannot dial ==="
# ⚠️ AN EMPTY TRUST DIRECTORY MUST BE A HARD STOP. C_Login crosses this tunnel carrying
# the PIN that protects every CA private key in the token, so dialling out with nothing to
# verify the far end against is the one failure the transport exists to prevent — it has
# to refuse, not warn.
mkdir -p empty/servers
: > empty/client.crt
P11_TLS_DIR="$W/empty" P11_KIT_SERVER_ADDRESS="$SOCK_B" "$CA" --config conf \
    key replicate repl-ca --from 127.0.0.1:1 --source-key "$URI_R" >from.log 2>&1
chk "an empty trust directory refuses" no "$([ "$?" = 0 ] && echo yes || echo no)"
chk "  naming the directory an operator must fill" yes \
    "$(grep -q 'servers' from.log && echo yes || echo no)"
P11_TLS_DIR="$W/nonexistent" P11_KIT_SERVER_ADDRESS="$SOCK_B" "$CA" --config conf \
    key replicate repl-ca --from 127.0.0.1:1 --source-key "$URI_R" >from2.log 2>&1
chk "a missing client certificate refuses" no "$([ "$?" = 0 ] && echo yes || echo no)"
chk "  naming certgen as what mints it" yes \
    "$(grep -q 'certgen' from2.log && echo yes || echo no)"


# ── 7. a SERVICE CREDENTIAL replicates too, not only the CAs ──────────────────────────
#
# ⚠️ THIS IS THE HALF THAT WAS MISSING AND THE ONE THAT LOOKS FINE WHEN IT IS BROKEN. An HA
# pair has to carry every private key the node needs in order to SERVE, and `key sync`
# walked CA instances only — so a promoted node issued perfectly over EST and ACME, which
# sign from the CA, while CMP refused every transaction, OCSP answered internalerror and
# SCEP served nothing. Measured on a lab pair before the fix: est 10/10, cmp 0/10, which
# reads as a CMP fault rather than a failover gap.
#
# A credential differs from a CA in two ways this exercises: its key URI is a CONFIG value
# rather than a `certs` row, so there is nothing to register afterwards, and its
# certificate is found by cert_id (`<prefix>-<ca_id>`) rather than read off that row.
echo "=== 7. a service credential replicates too, not only the CAs ==="
URI_OCSP='pkcs11:token=fastpki;object=ocsp-ra;type=private?pin-value=1234'
URI_SUB='pkcs11:token=fastpki;object=repl-sub;type=private?pin-value=1234'
printf 'OCSP_RESPONDER_KEY=%s\nOCSP_RESPONDER_KEY_ALGO=ec\n' "$URI_OCSP" >> conf
# ⚠️ key sync NEEDS THIS NODE'S OWN PIN AND HAS NO URI TO READ IT FROM. It names nothing, so
# unlike `key replicate --source-key <uri>` there is no inline pin-value to fall back on: it
# resolves the local PIN from PKCS11_PIN_FILE, which every real deployment sets in
# bootstrap.conf and this fixture had not needed until now. Without it every object fails
# identically — "no token PIN for this node" — CAs included.
printf '1234' > pin; chmod 600 pin
printf 'PKCS11_PIN_FILE=%s\n' "$W/pin" >> conf

# ⚠️ AN ISSUING CA, NOT THE ROOT. Service credentials are per-CA and roots are skipped —
# nothing enrols against a root — so a deployment whose only CA is self-signed mints none
# of them and this section would assert against an empty set.
P11_KIT_SERVER_ADDRESS="$SOCK_A" "$CA" --config conf create repl-sub --parent repl-ca \
    --name "Replicable Sub" --subject "/CN=Replicable Sub" --ca-key "$URI_SUB" \
    --keygen --key ec --replicable >sub.log 2>&1 || true
chk "an issuing CA exists to hang the credential on" yes \
    "$(grep -q 'created CA instance repl-sub' sub.log && echo yes || echo no)"

intoken(){  # <socket> <label> -> yes|no  (through the client shim, as every check here does)
    P11_KIT_SERVER_ADDRESS="$1" "$HSM_PKTOOL" --module "$HSM_CLIENT" \
        --token-label fastpki --list-objects --login --pin 1234 2>/dev/null \
      | grep -q "$2" && echo yes || echo no
}

# Mint it in node A's token, REPLICABLE. --create-missing is what mints; --replicable is
# what makes the key extractable, and that choice exists only at this moment.
P11_KIT_SERVER_ADDRESS="$SOCK_A" "$CA" --config conf \
    renew-service-certs --create-missing --replicable >cred.log 2>&1 || true
chk "the credential is minted replicable" yes \
    "$(grep -q 'generated a REPLICABLE' cred.log && echo yes || echo no)"
chk "  node A's token holds it"  yes "$(intoken "$SOCK_A" ocsp-ra)"
chk "  node B's token does NOT"  no  "$(intoken "$SOCK_B" ocsp-ra)"

# ⚠️ --from-peers ASKS THIS DATA CENTER'S OTHER HOSTS, AND SAYS SO WHEN THERE ARE NONE. It is what
# every nightly loop runs, so a node with no published peer — this fixture publishes no
# transport certificate — must name the missing key and the reason, not fail silently or reach
# for a host of another data center. And with exit 3, not 1: the nightly loops hold back
# `renew-service-certs --create-missing` after a 1, because a peer holding the key may only be
# restarting, and let it mint a replacement after a 3, because nobody can ever supply one.
_rc=0
P11_KIT_SERVER_ADDRESS="$SOCK_B" "$CA" --config conf \
    key sync --from-peers >peers.log 2>&1 || _rc=$?
chk "key sync --from-peers with no other host of the data center exits 3" 3 "$_rc"
chk "  naming why" yes \
    "$(grep -q 'no other host of data center' peers.log && echo yes || echo no)"
chk "  and copies nothing" no "$(intoken "$SOCK_B" ocsp-ra)"
chk "  and --from-peers with --from is refused" yes \
    "$("$CA" --config conf key sync --from-peers --from 127.0.0.1:1 2>&1 | grep -q 'exactly one of' && echo yes || echo no)"

# `key sync` names nothing: it replicates every key this node needs and does not have, so
# the assertion is that it reaches the CREDENTIAL and not merely the CA it already handled.
P11_KIT_SERVER_ADDRESS="$SOCK_B" "$CA" --config conf \
    key sync --source-socket "$SOCK_A" >sync.log 2>&1 || true
chk "key sync names the credential as missing" yes \
    "$(grep -q "ocsp-ra" sync.log && echo yes || echo no)"
chk "  and replicates it into node B's token" yes "$(intoken "$SOCK_B" ocsp-ra)"
[ "$(intoken "$SOCK_B" ocsp-ra)" = yes ] || { echo "    --- sync.log ---"; sed 's/^/    /' sync.log | tail -12; }
# ⚠️ AND NOT AS A KEY TO ISSUE UNDER. A credential's key URI is a config value, and an HA
# pair shares one config table, so the URI already names the object the unwrap created —
# there is no row to register, and the wording says which kind it was.
# ⚠️ IT MUST SAY WHEN THE CREDENTIAL BECOMES LIVE, WHICH IS THE HALF THAT WENT WRONG. The
# wording was "this node can now serve with <id>", and that was false when it printed:
# fastpki-ocsp and -cmp resolved their credential at startup and cached its ABSENCE, so a
# promoted standby was sent into production with protocols dead — measured, CMP still
# refusing with "no RA credential" seven minutes after a successful sync.
#
# They re-check now, so the key does become live on its own. The message therefore has to
# give the operator the one thing they cannot see: how long to wait, and that waiting is
# enough. Asserted scoped to ocsp-ra, because one sync run replicates both kinds and a CA
# key's line legitimately says "can now issue, renew and revoke" — that branch is correct
# and unchanged, so grepping the whole file for its absence would fail a correct run.
chk "  says when this credential becomes live" yes \
    "$(grep -q 'fastpki-ocsp picks it up within' sync.log && echo yes || echo no)"
chk "  and that a restart is not required" yes \
    "$(grep -q 'no restart is required' sync.log && echo yes || echo no)"
chk "  while still giving the command to apply it at once" yes \
    "$(grep -q 'restart ocsp' sync.log && echo yes || echo no)"

echo "=== 7c. a key under the right label that is not the certificate's ==="
# ⚠️ PRESENT MEANS THE CERTIFICATE'S KEY. Both tokens have an object called ocsp-ra, and when
# the two hosts of a pair each minted their own, one of them certifies nothing — measured on a
# Kubernetes pair, where `key sync` reported every key present on both hosts while one host's
# OCSP, CMP and SCEP signed with keys no certificate named. A stale key is planted in node B's
# token under the credential's label, and each thing that used to trust the label is checked.
pubhash(){  # <socket> <label> -> sha256 of the public key the token holds under that label
    P11_KIT_SERVER_ADDRESS="$1" "$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label fastpki \
        --read-object --type pubkey --label "$2" 2>/dev/null | "$OSSL" dgst -sha256 | awk '{print $NF}'
}
certhash(){  # <cert_id> -> sha256 of the public key the current certificate carries
    pg_exec "SELECT encode(cert,'base64') FROM certs WHERE cert_id='$1' ORDER BY ins_seq DESC NULLS LAST LIMIT 1;" \
      | tr -d ' \n' | "$OSSL" base64 -d -A 2>/dev/null \
      | "$OSSL" x509 -inform DER -noout -pubkey 2>/dev/null \
      | "$OSSL" pkey -pubin -outform DER 2>/dev/null | "$OSSL" dgst -sha256 | awk '{print $NF}'
}
plant_stale(){  # <socket>: replace ocsp-ra in that token with an unrelated EC keypair
    for t in privkey pubkey; do
        P11_KIT_SERVER_ADDRESS="$1" "$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label fastpki \
            --login --pin 1234 --delete-object --type "$t" --label ocsp-ra >/dev/null 2>&1
    done
    P11_KIT_SERVER_ADDRESS="$1" "$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label fastpki \
        --login --pin 1234 --keypairgen --key-type EC:prime256v1 --label ocsp-ra --id 7c \
        >/dev/null 2>&1
}
CRED_ID=ocsp-ra-repl-sub
A_KEY=$(pubhash "$SOCK_A" ocsp-ra)
chk "fixture: node B holds the certificate's key after the sync above" "$A_KEY" "$(pubhash "$SOCK_B" ocsp-ra)"
chk "  and the certificate certifies it" "$A_KEY" "$(certhash "$CRED_ID")"
plant_stale "$SOCK_B"
chk "fixture: node B now holds a different key under the same label" yes \
    "$([ -n "$(pubhash "$SOCK_B" ocsp-ra)" ] && [ "$(pubhash "$SOCK_B" ocsp-ra)" != "$A_KEY" ] && echo yes || echo no)"

# Renewal on the node with the stale key would certify it and move the breakage to node A.
P11_KIT_SERVER_ADDRESS="$SOCK_B" "$CA" --config conf \
    renew-service-certs --force >stale-renew.log 2>&1 || true
chk "renewal refuses to certify a key that does not match the certificate" yes \
    "$(grep -q 'does not match this certificate' stale-renew.log && echo yes || echo no)"
chk "  and the certificate still certifies node A's key" "$A_KEY" "$(certhash "$CRED_ID")"

P11_KIT_SERVER_ADDRESS="$SOCK_B" "$CA" --config conf \
    key sync --source-socket "$SOCK_A" >stale-sync.log 2>&1 || true
chk "key sync reports the key as not matching, not as present" yes \
    "$(grep -q "'ocsp-ra' (OCSP responder) has a key in this node's token that does NOT match" stale-sync.log && echo yes || echo no)"
chk "  and replaces it with node A's" "$A_KEY" "$(pubhash "$SOCK_B" ocsp-ra)"
chk "  leaving one private key under the label, not two" 1 \
    "$(P11_KIT_SERVER_ADDRESS="$SOCK_B" "$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label fastpki \
         --login --pin 1234 --list-objects --type privkey 2>/dev/null | grep -c 'label: *ocsp-ra$')"
[ "$(pubhash "$SOCK_B" ocsp-ra)" = "$A_KEY" ] || { echo "    --- stale-sync.log ---"; sed 's/^/    /' stale-sync.log | tail -12; }
P11_KIT_SERVER_ADDRESS="$SOCK_B" "$CA" --config conf \
    key sync --source-socket "$SOCK_A" >stale-sync2.log 2>&1 || true
chk "  and a second run finds nothing missing for it" no \
    "$(grep -q "'ocsp-ra'" stale-sync2.log && echo yes || echo no)"

# With --create-missing the node that cannot get the right key mints its own in place of the
# stale one, and the other node then replaces ITS key the same way — converging, where two
# label-only checks left each host with a different key for ever.
plant_stale "$SOCK_B"
P11_KIT_SERVER_ADDRESS="$SOCK_B" "$CA" --config conf \
    renew-service-certs --create-missing --replicable >stale-create.log 2>&1 || true
B_KEY=$(pubhash "$SOCK_B" ocsp-ra)
chk "the sweep removes a stale key before minting in its place" yes \
    "$(grep -q 'removed the key under' stale-create.log && echo yes || echo no)"
chk "  and the new certificate certifies node B's new key" "$B_KEY" "$(certhash "$CRED_ID")"
chk "  which is not node A's" yes "$([ "$B_KEY" != "$A_KEY" ] && echo yes || echo no)"
[ "$(certhash "$CRED_ID")" = "$B_KEY" ] || { echo "    --- stale-create.log ---"; sed 's/^/    /' stale-create.log | tail -12; }
P11_KIT_SERVER_ADDRESS="$SOCK_A" "$CA" --config conf \
    key sync --source-socket "$SOCK_B" >stale-back.log 2>&1 || true
chk "node A's key sync then replaces its own, now stale, key" "$B_KEY" "$(pubhash "$SOCK_A" ocsp-ra)"

echo "=== 7b. a CA whose key label is not its id ==="
# A CA renewed with a new key signs under a new label (object=<id>-2), and the console's key
# picker lets any key take any label. key sync asked the source token for object=<id>, so it
# fetched the wrong object — or the previous generation's key — and failed verification.
# Every label above equals its id, which is exactly how that went unnoticed.
URI_LBL='pkcs11:token=fastpki;object=lbl-ca-key-2;type=private?pin-value=1234'
P11_KIT_SERVER_ADDRESS="$SOCK_A" "$CA" --config conf create lbl-ca \
    --name "Labelled CA" --subject "/CN=Labelled CA" --ca-key "$URI_LBL" \
    --keygen --key ec --replicable >lbl.log 2>&1 || true
chk "fixture: a CA whose key is labelled lbl-ca-key-2" yes "$(intoken "$SOCK_A" lbl-ca-key-2)"
chk "  and node B does not hold it" no "$(intoken "$SOCK_B" lbl-ca-key-2)"
P11_KIT_SERVER_ADDRESS="$SOCK_B" "$CA" --config conf \
    key sync --source-socket "$SOCK_A" >sync2.log 2>&1 || true
chk "key sync replicates it, by the label its key reference names" yes "$(intoken "$SOCK_B" lbl-ca-key-2)"
# Not "0 failed": plain-ca from section 5 is non-replicable and fails every sync, correctly.
chk "  it reports lbl-ca replicated" yes "$(grep -q "replicated lbl-ca's" sync2.log && echo yes || echo no)"
chk "  and nothing arrived that failed verification" no \
    "$(grep -q 'does NOT match' sync2.log && echo yes || echo no)"
[ "$(intoken "$SOCK_B" lbl-ca-key-2)" = yes ] || { echo "    --- sync2.log ---"; sed 's/^/    /' sync2.log | tail -12; }

echo "=== 8. every CA key algorithm replicates, not only RSA and P-256 ==="
# ⚠️ WHAT WAS NEVER MEASURED WAS ASSUMED IMPOSSIBLE. Replicable keys were refused for every
# algorithm but RSA and P-256 because the probe behind them had only run where Ed25519,
# ML-DSA and PSS-restricted keys do not exist. The shipped token wraps all of them, so each
# goes through the same proof as section 3: minted replicable on node A, replicated by the
# product into node B's token, and a signature from B's copy verified against the public key
# in A's CA certificate.
n=0
for spec in ec:P-384 ec:P-521 ed25519: ed448: ML-DSA-65: rsa-pss:; do
    algo=${spec%%:*}; curve=${spec#*:}; n=$((n+1)); id="alg-$n"
    uri="pkcs11:token=fastpki;object=$id;type=private?pin-value=1234"
    extra=(); [ -n "$curve" ] && extra+=(--curve "$curve"); [ "$algo" = rsa-pss ] && extra+=(--bits 2048)
    P11_KIT_SERVER_ADDRESS="$SOCK_A" "$CA" --config conf create "$id" --name "$algo $curve" \
        --subject "/CN=Replicable $algo $curve" --ca-key "$uri" --keygen --key "$algo" \
        "${extra[@]}" --replicable --out-dir cas >"$id.create.log" 2>&1
    chk "$algo $curve: the replicable CA is created on node A" yes \
        "$([ -s "cas/$id.crt" ] && echo yes || echo no)"
    [ -s "cas/$id.crt" ] || { tail -4 "$id.create.log"; continue; }
    chk "  its key is extractable" yes "$(P11_KIT_SERVER_ADDRESS="$SOCK_A" hsm_key_extractable fastpki "$id")"

    P11_KIT_SERVER_ADDRESS="$SOCK_B" "$CA" --config conf key replicate "$id" \
        --source-socket "$SOCK_A" --source-key "$uri" >"$id.repl.log" 2>&1
    rc=$?
    chk "  node B replicates it" 0 "$rc"
    [ "$rc" = 0 ] || { tail -4 "$id.repl.log"; continue; }
    chk "  and B's copy is extractable in turn" yes \
        "$(P11_KIT_SERVER_ADDRESS="$SOCK_B" hsm_key_extractable fastpki "$id")"

    # ECDSA and RSA-PSS sign a digest; EdDSA and ML-DSA are one-shot over the message.
    case "$algo" in
        ec)      sopts=(-rawin -digest sha256) ;;
        rsa-pss) sopts=(-rawin -digest sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:digest) ;;
        *)       sopts=(-rawin) ;;
    esac
    rm -f "$id.sig"
    P11_KIT_SERVER_ADDRESS="$SOCK_B" "$OSSL" pkeyutl -sign -inkey "$uri" \
        -provider pkcs11 -provider default "${sopts[@]}" -in msg.txt -out "$id.sig" >"$id.sign.log" 2>&1
    chk "  B's copy signs" yes "$([ -s "$id.sig" ] && echo yes || echo no)"
    [ -s "$id.sig" ] || { tail -3 "$id.sign.log"; continue; }
    "$OSSL" x509 -in "cas/$id.crt" -noout -pubkey > "$id.pub" 2>/dev/null
    chk "  and A's CA certificate verifies that signature" yes \
        "$("$OSSL" pkeyutl -verify -pubin -inkey "$id.pub" "${sopts[@]}" \
            -in msg.txt -sigfile "$id.sig" >/dev/null 2>&1 && echo yes || echo no)"

    if [ "$algo" = rsa-pss ]; then
        # ⚠️ THE RESTRICTION HAS TO ARRIVE WITH THE KEY. Asked of the token directly, not of
        # OpenSSL, which would refuse PKCS#1 padding for an RSA-PSS key type on its own and so
        # pass this whether or not CKA_ALLOWED_MECHANISMS was carried across. The PSS signature
        # through the same tool is the control: without it, a wrong label or a failed login
        # would make the refusal below pass for nothing.
        # ⚠️ SELECT THE KEY BY CKA_ID. With --label alone, both checks failed at C_SignInit with
        # CKR_KEY_TYPE_INCONSISTENT — the key pkcs11-tool picked was not this RSA key, in a
        # token that also holds section 1's EC keys — while OpenSSL signed with it by URI.
        # pkcs11-tool derives the PSS parameters from SHA256-RSA-PKCS-PSS itself, and refuses
        # --hash-algorithm with it ("applicable only to RSA-PKCS-PSS").
        keyid=$(P11_KIT_SERVER_ADDRESS="$SOCK_B" "$HSM_PKTOOL" --module "$HSM_CLIENT" \
                  --token-label fastpki --list-objects --type privkey --login --pin 1234 2>/dev/null \
                | awk -v want="$id" '/^Private Key Object/ { l = "" }
                    /^[[:space:]]*label:/ { l = $0; sub(/^[[:space:]]*label:[[:space:]]*/, "", l) }
                    /^[[:space:]]*ID:/ && l == want { v = $0; sub(/^[[:space:]]*ID:[[:space:]]*/, "", v); print v; exit }')
        chk "  fixture: B's copy has a CKA_ID to select it by" yes "$([ -n "$keyid" ] && echo yes || echo no)"
        P11_KIT_SERVER_ADDRESS="$SOCK_B" "$HSM_PKTOOL" --module "$HSM_CLIENT" \
            --token-label fastpki --login --pin 1234 --sign --mechanism SHA256-RSA-PKCS-PSS \
            --id "$keyid" --input-file msg.txt --output-file "$id.pss" >"$id.pss.log" 2>&1
        rc=$?
        chk "  control: pkcs11-tool signs PSS with B's copy" 0 "$rc"
        [ "$rc" = 0 ] || sed 's/^/    /' "$id.pss.log" | tail -4
        P11_KIT_SERVER_ADDRESS="$SOCK_B" "$HSM_PKTOOL" --module "$HSM_CLIENT" \
            --token-label fastpki --login --pin 1234 --sign --mechanism SHA256-RSA-PKCS \
            --id "$keyid" --input-file msg.txt --output-file "$id.v15" >"$id.v15.log" 2>&1
        # The REASON, not merely a failure: CKR_MECHANISM_INVALID at C_SignInit is the token
        # applying CKA_ALLOWED_MECHANISMS, measured on a provider-minted PSS key.
        chk "  and B's RSA-PSS copy refuses PKCS#1 v1.5 at the token (CKR_MECHANISM_INVALID)" yes \
            "$(grep -q 'CKR_MECHANISM_INVALID' "$id.v15.log" && echo yes || echo no)"
        grep -q 'CKR_MECHANISM_INVALID' "$id.v15.log" || sed 's/^/    /' "$id.v15.log" | tail -4
    fi
done

echo
echo "=== KEY REPLICATION: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
