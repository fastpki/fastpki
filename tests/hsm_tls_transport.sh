#!/usr/bin/env bash
# The token socket, reached over mTLS instead of a shared filesystem.
#
# ── Why there is a tunnel at all ───────────────────────────────────────────────────────
#
# p11-kit speaks neither TLS nor TCP. Its client shim parses `unix:path=` and
# `vsock:cid=;port=` and links no bind/listen, so a token is reachable only by processes that
# can open one file on one host. The transport is therefore a PAIR OF PROXIES, not a p11-kit
# setting: an stunnel server beside the token, and a peer dialling in over TLS.
#
# ⚠️ WHAT IT IS FOR: REPLICATING A KEY OUT OF THIS TOKEN, not signing through it. Every node
# has its own token in every deployment shape, and after replication each signs from its own
# copy and needs no peer to issue, renew or revoke. A deployment in which every node signed
# through one host's token stops signing entirely when that host is lost, and certificates
# issued under its key can never afterwards be renewed or revoked.
#
# ── What this asserts, and why each one matters ────────────────────────────────────────
#
# The transport carries C_Login, and C_Login carries the PIN that protects every CA private
# key in the token. Today that PIN is a 0400 file that never crosses a machine boundary;
# through a tunnel it is on the wire, and the tunnel's authentication is the only thing
# between the network and every CA. So it is not enough to prove that PKCS#11 works through
# the tunnel — the refusal has to be proven too, in the same run, or a build that silently
# stopped verifying client certificates would pass on the first half alone.
#
# ⚠️ THE ROGUE CASE IS THE POINT. A wrong-certificate client must see NOTHING: no slot, no
# token label, no error that distinguishes an empty token from a refused connection.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
skipout(){ echo "  [SKIP] $1"; echo; echo "=== HSM TLS TRANSPORT: PASS=$pass FAIL=$fail SKIP=1 ==="; exit 0; }

command -v stunnel        >/dev/null 2>&1 || skipout "stunnel is not installed"
command -v softhsm2-util  >/dev/null 2>&1 || skipout "softhsm2-util is not installed"
command -v pkcs11-tool    >/dev/null 2>&1 || skipout "pkcs11-tool is not installed"
SHIM=/usr/lib/pkcs11/p11-kit-client.so
P11SRV=/usr/libexec/p11-kit/p11-kit-server
MODULE=/usr/lib/softhsm/libsofthsm2.so
for f in "$SHIM" "$P11SRV" "$MODULE"; do
    [ -e "$f" ] || skipout "$f is missing (not the shipped image)"
done

W="$(mktemp -d)"; cd "$W"
# ⚠️ A PORT NO OTHER SUITE CLAIMS. Suites pick fixed ports by hand and run_all.sh shards
# them, so two suites sharing one are fine until the sharding puts them in the same shard —
# then the second gets a bare "listen failed" that looks like a product fault. 18499 was
# already taken by est_mtls_role.sh and profile_choice.sh.
PORT=18500
# ⚠️ THE LAST TRAP MUST BE A SUPERSET OF EVERY EARLIER ONE — bash replaces traps rather
# than stacking them, and this suite leaves four processes and a token directory behind.
# Killing the p11-kit server also means killing its CHILDREN: it forks one per connected
# client, and a surviving fork keeps a fully live token behind a dead-looking listener.
cleanup() {
    for p in ${ROGUE_PID:-} ${CLI_PID:-} ${SRV_PID:-}; do kill "$p" 2>/dev/null || true; done
    if [ -n "${P11_PID:-}" ]; then
        pkill -P "$P11_PID" 2>/dev/null || true
        kill "$P11_PID" 2>/dev/null || true
    fi
    rm -rf "$W"
}
trap cleanup EXIT

export SOFTHSM2_CONF="$W/softhsm2.conf"
mkdir -p "$W/tokens" "$W/run"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' \
    "$W" > "$SOFTHSM2_CONF"
softhsm2-util --init-token --slot 0 --label fastpki --so-pin 1234 --pin t1234 >/dev/null 2>&1 \
    || skipout "could not initialise a token"

echo "=== 1. the material certgen mints for the tunnel ==="
# Generated the same way deploy/certgen.sh does under P11_TLS=on, rather than by running
# certgen itself: that script writes into /var/pki and wants root, and what is under test
# here is the TRANSPORT, not the file layout. The shapes must match, which is asserted.
D="$W/p11"; mkdir -p "$D/clients"
for n in server client; do
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$D/$n.key" -out "$D/$n.crt" \
        -days 1 -subj "/CN=fastpki-p11-$n" >/dev/null 2>&1
done
cp "$D/client.crt" "$D/clients/client.crt"
openssl rehash "$D/clients" >/dev/null 2>&1
# ⚠️ A SECOND NODE, WITH ITS OWN DIRECTORY. This is the whole point of the transport: a peer
# on another host reaching this token to replicate a key out of it. Both ends sharing a
# directory is the SAME-HOST case, which needs no tunnel at all — and testing that shape is
# how a tunnel that could never handshake between two hosts stayed green. $CD is the peer: it
# mints its own client pair, and has no access to anything under $D.
CD="$W/p11-consumer"; mkdir -p "$CD/servers"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$CD/client.key" -out "$CD/client.crt" \
    -days 1 -subj "/CN=fastpki-p11-client-dc2" >/dev/null 2>&1
# ⚠️ AND ITS OWN SERVER PAIR, BECAUSE certgen MINTS BOTH ON EVERY NODE. Seeding the
# consumer's server trust with the certificate IT generated is not an artificial setup —
# it is exactly the state a consumer host shipped in, and exactly why no two hosts could
# ever handshake: CAfile pointed at a certificate the remote end has never held. stunnel
# also refuses to start on an empty CApath, so this is what makes the negative case
# testable at all rather than merely absent.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$CD/server.key" -out "$CD/server.crt" \
    -days 1 -subj "/CN=fastpki-p11-server-dc2" >/dev/null 2>&1
cp "$CD/server.crt" "$CD/servers/server.crt"
openssl rehash "$CD/servers" >/dev/null 2>&1
chk "the client trust directory is indexed" yes \
    "$(ls "$D/clients" | grep -qE '^[0-9a-f]{8}\.0$' && echo yes || echo no)"
# certgen must keep minting what this proves. A rename there with no change here would
# leave the suite testing a shape the product no longer produces.
chk "  and certgen mints the same pair" yes \
    "$(grep -q 'p11_pair server' "$ROOT/deploy/certgen.sh" &&
       grep -q 'p11_pair client' "$ROOT/deploy/certgen.sh" && echo yes || echo no)"
chk "  gated on P11_TLS, so it is opt-in"  yes \
    "$(grep -q 'P11_TLS:-off' "$ROOT/deploy/certgen.sh" && echo yes || echo no)"

# ⚠️ AND THE PRIVATE HALVES ARE TOKEN OBJECTS, NOT FILES. FastPKI's rule is that a private
# key is generated in a token and never leaves it; this transport shipped two file-based keys
# on every node, which was a gap rather than a design. What must never come back is a
# `-keyout` here — it would put the one exception in the deployment right in front of the
# token it fronts.
chk "  minting them IN the token"                yes \
    "$(grep -qE 'pkcs11-tool ' "$ROOT/deploy/certgen.sh" && grep -qE '[-][-]keypairgen' "$ROOT/deploy/certgen.sh" && echo yes || echo no)"
chk "  and never writing a transport key file"   yes \
    "$(grep -qE '\-newkey rsa:[0-9]+ -nodes -keyout "\$_k' "$ROOT/deploy/certgen.sh" \
       && echo no || echo yes)"
# ⚠️ MATCH THE RULE, NOT THE SPELLING. Both greps below quoted certgen's exact characters,
# so routing its token calls through a privilege-dropping helper — which changed "$_uri" to
# '$_uri' inside the wrapper — failed them while the behaviour they describe was untouched.
# An assertion about source text has to tolerate the quoting, or it reports a refactor as a
# regression and is edited away rather than believed.
#
# ⚠️ RESOLVE BEFORE MINTING. Reaching the mint with the key already present is ordinary — an
# expired certificate, or one deleted by hand — and SoftHSM will create a SECOND object under
# the same label, after which `object=p11-server` selects whichever comes back first and the
# pinned certificate matches it only by luck.
chk "  resolving an existing key before minting" yes \
    "$(grep -qE 'if ! .*openssl pkey -in .\$_uri. -pubout' "$ROOT/deploy/certgen.sh" && echo yes || echo no)"
# ⚠️ ONLY EC NOTICES A MISSING CKA_ID, which is how "openssl cannot sign with an EC token key"
# came to be written down as a limitation of the curve. It is not: it is `--id`.
chk "  with a CKA_ID, which EC signing requires" yes \
    "$(grep -qE 'keypairgen --key-type EC:prime256v1 --label .\$3. --id .\$4.' "$ROOT/deploy/certgen.sh" \
       && echo yes || echo no)"

echo "=== 1b. every deploy path loads that key from the token ==="
# ⚠️ THREE PATHS, ONE RULE. compose, Kubernetes and OpenRC each write their own stunnel
# config, so a key file reintroduced in any one of them is a private key outside a token in
# that deployment shape alone — which is exactly the kind of divergence that survives review.
for f in "$ROOT/deploy/docker-compose.yml" "$ROOT/deploy/k8s/p11-tls.sh" \
         "$ROOT/deploy/native/openrc/fastpki-p11-tls.initd"; do
    chk "$(basename "$f"): stunnel key is a pkcs11 URI" yes \
        "$(grep -q 'key = pkcs11:token=' "$f" && echo yes || echo no)"
    # ⚠️ AND stunnel CANNOT SEE THE PROVIDER WITHOUT A CONFIG SAYING SO. It is a stock Alpine
    # binary reading the stock openssl.cnf, which activates nothing — so the URI alone would
    # fail at start with no hint that a provider was missing.
    chk "  and it is given an OPENSSL_CONF activating pkcs11" yes \
        "$(grep -q 'pkcs11-module-path' "$f" && echo yes || echo no)"
    # ⚠️ THE CLIENT SHIM, NEVER libsofthsm2.so. In-process SoftHSM re-enters libcrypto while
    # it holds a lock and DEADLOCKS — a hang, which is worse than a failure.
    #
    # ⚠️ SO CHECK THE VALUE, NOT ONE SPELLING OF A PATH. All three files write
    # `${PKCS11_MODULE:-…}` into that setting and compose emits the value as a printf argument
    # two lines under the key, so a grep for the text `pkcs11-module-path = /usr/lib/softhsm`
    # matched nothing whatever module was configured — swapping a default to libsofthsm2.so
    # passed. What is asserted now is the module each path actually hands stunnel: the setting's
    # line plus the two following it, comment lines dropped first because every one of these
    # settings is introduced by a ⚠️ block naming libsofthsm2.so that would otherwise answer
    # for it. Scoped to that window on purpose — docker-compose.yml gives libsofthsm2.so to the
    # p11-kit SERVER further up, which is correct and must keep passing.
    MODCFG="$(grep -v '^[[:space:]]*#' "$f" | grep -A2 'pkcs11-module-path')"
    chk "  and the module it names is the client shim"        yes \
        "$(printf '%s\n' "$MODCFG" | grep -q 'p11-kit-client\.so' && echo yes || echo no)"
    chk "  and is not libsofthsm2.so"                         no \
        "$(printf '%s\n' "$MODCFG" | grep -qi 'softhsm' && echo yes || echo no)"
done

# ⚠️ NO NODE EVER SIGNS THROUGH ANOTHER NODE'S TOKEN. Every node has its own token in every
# deployment shape; P11_TLS publishes THIS node's so a peer can replicate a CA key out of it.
# The arrangement that once existed here — a node whose /run/p11/pkcs11.sock was a tunnel to
# somebody else's token — stops every node signing when that host is lost, and certificates
# issued under its key can never afterwards be renewed or revoked. It must not come back.
for f in "$ROOT/deploy/docker-compose.yml" "$ROOT/deploy/k8s/token.sh" \
         "$ROOT/deploy/k8s/env.sh" "$ROOT/deploy/k8s/apply.sh" \
         "$ROOT/deploy/native/openrc/fastpki-token.initd" \
         "$ROOT/deploy/native/install-native.sh"; do
    chk "$(basename "$f") has no remote-token role" "" \
        "$(grep -l 'P11_TLS_CONNECT' "$f" 2>/dev/null | xargs -r basename)"
done

echo "=== 1c. and something renews them before they expire ==="
# ⚠️ NOTHING ELSE RENEWS THESE. `fastpki-ca renew-service-certs` renews what a CA issued;
# this pair is self-signed and PINNED, so it is not a `certs` row and that command never
# sees it. Their only renewal is certgen running again — which on a native or cloud node
# happened once, at install. At SELFSIGNED_DAYS the tunnel simply stops handshaking, and it
# reads like a trust failure rather than an expiry, so nothing points at the cause.
chk "certgen offers the renewal entry point" yes \
    "$(grep -q -- '--p11-only' "$ROOT/deploy/certgen.sh" && echo yes || echo no)"
# ⚠️ AND IT MUST NOT DEMAND FASTPKI_PIN. Renewal re-signs with the key already in the token
# and needs only the pin-source file; the daily job runs as the unprivileged runtime user,
# which cannot read /etc/conf.d/fastpki. Requiring the PIN here would make the renewal
# impossible on exactly the deployment shape that has no other trigger.
chk "  and minting, not renewing, is what needs the PIN" yes \
    "$(grep -q 'no .* key in the token and no FASTPKI_PIN' "$ROOT/deploy/certgen.sh" \
       && echo yes || echo no)"
# All three schedulers, because a renewal wired into one path is an expiry on the other two.
# ⚠️ THE KUBERNETES SCHEDULER IS A SCRIPT, NOT THE MANIFEST. It is the renew container of every
# server pod, deploy/k8s/renew-loop.sh, reaching the pod through the fastpki-bootstrap ConfigMap because
# apply.sh renders manifests through envsubst, which rewrote an inline script's own accumulated
# exit status to an empty string.
for f in "$ROOT/deploy/native/periodic/fastpki-certrenew" \
         "$ROOT/deploy/docker-compose.yml" \
         "$ROOT/deploy/k8s/renew-loop.sh"; do
    chk "$(basename "$f") renews the transport pair" yes \
        "$(grep -q -- '--p11-only' "$f" && echo yes || echo no)"
    # ⚠️ AND REPUBLISHES. Each end verifies the other against a trust directory built from
    # what peers published; renewing without publishing leaves every peer pinning the
    # certificate this node no longer presents, so the tunnel would break AT RENEWAL —
    # strictly worse than letting it expire, because it happens 90 days earlier.
    chk "  and publishes the result" yes \
        "$(grep -q 'p11-server-publish' "$f" && grep -q 'p11-client-publish' "$f" \
           && echo yes || echo no)"
done

# ⚠️ AND BOTH HALVES OF THE TRUST ARE PUBLISHED AT START, not only by the daily job. Every
# node with P11_TLS on publishes its own token AND may dial a peer to replicate a key out of
# one, so it needs its client certificate advertised and the peers' server certificates
# materialised before the first `key replicate --from`. When only the daily job did this, a
# freshly deployed node refused with "no peer token host can be verified" for up to a day —
# and that is the command docs/deployment.md tells an operator to run.
for f in "$ROOT/deploy/native/openrc/fastpki-p11-tls.initd" \
         "$ROOT/deploy/k8s/p11-tls.sh" "$ROOT/deploy/docker-compose.yml"; do
    for c in p11-server-publish p11-clients-sync p11-client-publish p11-servers-sync; do
        chk "$(basename "$f") runs $c at start" yes \
            "$(grep -q "$c" "$f" && echo yes || echo no)"
    done
done

echo "=== 2. a token behind a p11-kit server, as the sidecar runs it ==="
"$P11SRV" -f -n "$W/run/real.sock" --provider "$MODULE" "pkcs11:" >"$W/p11srv.log" 2>&1 &
P11_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$W/run/real.sock" ] && break; sleep 0.3; done
chk "the token socket is up" yes "$([ -S "$W/run/real.sock" ] && echo yes || echo no)"

echo "=== 2b. certgen RUNS: it mints into the token, and renews without re-keying ==="
# ⚠️ EXECUTED, NOT GREPPED. The assertions in 1c prove the renewal is wired into all three
# schedulers; they cannot prove it works. What this covers is the failure that would
# otherwise surface two years after a deployment, as a tunnel that stops handshaking.
#
# certgen writes under /var/pki and expects to be root, so the paths are rewritten into $W
# the same way tests/certgen_pin_always.sh does it.
CG="$W/cg.sh"
sed -e "s#/var/pki#$W/root/var/pki#g" \
    -e "s#^chown #: chown #" -e "s#^ *chown #: chown #" -e "s#chown fastpki#: chown fastpki#" \
    "$ROOT/deploy/certgen.sh" > "$CG"
mkdir -p "$W/root/var/pki/tls/pg"
# ⚠️ P11_RUN_USER, OR EVERY TOKEN CALL IS REFUSED HERE FOR THE OPPOSITE REASON IT WOULD BE
# IN PRODUCTION. p11-kit-server authorises by the connecting process's uid. In a deployment
# it runs as `fastpki` while certgen runs as root, so certgen drops to `fastpki` to reach
# it. This suite starts its OWN server, as whoever runs the suite — so that same drop is
# what gets rejected, and the mint fails with "Is this node's token server running?" about
# a server that is running perfectly. The override exists for exactly this.
CG_ENV="P11_TLS=on PKI_DNS=pki.test PKCS11_TOKEN=fastpki \
        PKCS11_MODULE=$SHIM P11_KIT_SERVER_ADDRESS=unix:path=$W/run/real.sock \
        P11_RUN_USER=$(id -un)"
env $CG_ENV FASTPKI_PIN=t1234 sh "$CG" >"$W/cg1.log" 2>&1
CGD="$W/root/var/pki/tls/p11"
chk "certgen mints the transport pair" yes \
    "$([ -s "$CGD/server.crt" ] && [ -s "$CGD/client.crt" ] && echo yes || echo no)"
[ -s "$CGD/server.crt" ] || sed -n '1,12p' "$W/cg1.log"
# ⚠️ THE PRIVATE HALVES ARE IN THE TOKEN AND NOWHERE ELSE. A .key beside them would be the
# one private key in the deployment living outside a token, in front of the token it fronts.
chk "  and writes no key file"                yes \
    "$([ ! -f "$CGD/server.key" ] && [ ! -f "$CGD/client.key" ] && echo yes || echo no)"
chk "  the token holds both objects"          yes \
    "$(P11_KIT_SERVER_ADDRESS="unix:path=$W/run/real.sock" pkcs11-tool --module "$SHIM" \
        --token-label fastpki --list-objects --login --pin t1234 2>/dev/null \
        | grep -c 'p11-server\|p11-client' | grep -qv '^0$' && echo yes || echo no)"

# A fresh certificate is left alone: the gate is a renewal threshold, not a rewrite.
# ⚠️ WITH FASTPKI_PIN EXPLICITLY EMPTY, because what the next two lines claim is that this run
# needed none: a PIN inherited from whoever runs the suite would satisfy the mint path and the
# claim would be untested. certgen tests the variable with `-z`, so empty reads as absent.
env $CG_ENV FASTPKI_PIN= sh "$CG" --p11-only >"$W/cg2.log" 2>&1
CG2_RC=$?   # certgen's OWN status, captured before any other command can overwrite $?
chk "--p11-only leaves a fresh certificate alone" yes \
    "$(grep -q 'keypair written\|key minted' "$W/cg2.log" && echo no || echo yes)"
# ⚠️ AND IT RUNS WITHOUT FASTPKI_PIN. The daily job runs as the unprivileged runtime user,
# which can read the pin FILE but not /etc/conf.d/fastpki. Renewal re-signs with the key
# already in the token; only minting needs the PIN.
#
# This used to read `$?` one command too late — the status of the chk above, whose last
# statement is an arithmetic assignment and so always 0, making the comparison 0 = 0. A run
# that refused for want of a PIN, or died, also wrote nothing for the grep above to find, so
# both lines printed PASS on a run that did nothing. Now the refusal is what fails it.
chk "  and needed no FASTPKI_PIN"             0 "$CG2_RC"

# Now force the renewal branch by making every certificate "within the renewal window",
# which is what the passage of time would do.
BEFORE=$(openssl x509 -in "$CGD/server.crt" -noout -pubkey 2>/dev/null)
env $CG_ENV SELFSIGNED_RENEW_DAYS=99999 sh "$CG" --p11-only >"$W/cg3.log" 2>&1
AFTER=$(openssl x509 -in "$CGD/server.crt" -noout -pubkey 2>/dev/null)
chk "a certificate inside the window IS re-issued" yes \
    "$([ -s "$CGD/server.crt" ] && grep -q 'certificate written' "$W/cg3.log" && echo yes || echo no)"
# ⚠️ THE ASSERTION THAT MATTERS. Renewal must re-sign with the SAME key: peers pin this
# node's certificate, and a re-minted key would break every one of them at renewal rather
# than at expiry — 90 days earlier, and for a reason no message would name.
chk "  and the key is NOT re-minted"          yes \
    "$([ -n "$BEFORE" ] && [ "$BEFORE" = "$AFTER" ] && echo yes || echo no)"

echo "=== 3. stunnel: TLS in front of it, a local socket in front of that ==="
cat > "$W/server.conf" <<EOF
foreground = yes
pid =
[p11]
accept = 127.0.0.1:$PORT
connect = $W/run/real.sock
cert = $D/server.crt
key = $D/server.key
CApath = $D/clients
verifyPeer = yes
verifyChain = yes
EOF
stunnel "$W/server.conf" >"$W/stunnel-server.log" 2>&1 & SRV_PID=$!
cat > "$W/client.conf" <<EOF
foreground = yes
pid =
[p11]
client = yes
accept = $W/run/tunnel.sock
connect = 127.0.0.1:$PORT
cert = $CD/client.crt
key = $CD/client.key
CApath = $CD/servers
verifyPeer = yes
verifyChain = yes
EOF
stunnel "$W/client.conf" >"$W/stunnel-client.log" 2>&1 & CLI_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$W/run/tunnel.sock" ] && break; sleep 0.3; done
chk "the tunnel's local socket is up" yes \
    "$([ -S "$W/run/tunnel.sock" ] && echo yes || echo no)"

echo "=== 3b. ⚠️ BEFORE TRUST IS DISTRIBUTED, THE TWO HOSTS CANNOT TALK ==="
# This is the assertion whose absence let a tunnel ship that could never handshake
# between two hosts. Each node has only what it generated itself: the consumer would be
# verifying the server against a certificate the server has never held, and the server
# would be checking a client certificate it has never seen. Both halves must fail, and
# section 4 must NOT be reachable until the publish/sync step below has run.
P11_KIT_SERVER_ADDRESS="unix:path=$W/run/tunnel.sock" \
    pkcs11-tool --module "$SHIM" -T >"$W/untrusted.out" 2>&1 || true
chk "the token is NOT reachable before trust is published" no \
    "$(grep -qi 'token label *: *fastpki' "$W/untrusted.out" && echo yes || echo no)"

echo "=== 3c. the mesh distributes both halves, and only then does it work ==="
# What `fastpki-config p11-client-publish` / `p11-servers-sync` do through the
# `datacenters` table, done here as the file movements they produce. The DB round trip
# itself is covered in section 6; what is under test here is that these two movements
# are what the handshake actually needs.
cp "$CD/client.crt" "$D/clients/dc-dc2.crt"
openssl rehash "$D/clients" >/dev/null 2>&1
cp "$D/server.crt" "$CD/servers/dc-dc1.crt"
openssl rehash "$CD/servers" >/dev/null 2>&1
# ⚠️ CONTENT, NOT COUNT. The directory is already non-empty — it holds the certificate this
# node generated for itself — so asserting it has "a" certificate would pass before the
# distribution step and prove nothing. What matters is that the SERVING node's certificate
# is now in it.
chk "  the consumer now holds the serving node's certificate" yes \
    "$(cmp -s "$CD/servers/dc-dc1.crt" "$D/server.crt" && echo yes || echo no)"
kill "$CLI_PID" "$SRV_PID" 2>/dev/null || true
wait "$CLI_PID" "$SRV_PID" 2>/dev/null || true
rm -f "$W/run/tunnel.sock"
stunnel "$W/server.conf" >"$W/stunnel-server.log" 2>&1 & SRV_PID=$!
stunnel "$W/client.conf" >"$W/stunnel-client.log" 2>&1 & CLI_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$W/run/tunnel.sock" ] && break; sleep 0.3; done

echo "=== 4. PKCS#11 works THROUGH the tunnel ==="
# ⚠️ unix:path=, still. If this ever has to become anything else, the transport has leaked
# into the client and every binary would need to know about it.
P11_KIT_SERVER_ADDRESS="unix:path=$W/run/tunnel.sock" \
    pkcs11-tool --module "$SHIM" -T >"$W/ok.out" 2>&1 || true
chk "the token is visible over the tunnel" yes \
    "$(grep -qi 'token label *: *fastpki' "$W/ok.out" && echo yes || echo no)"
chk "  and it reports as initialised, not a husk" yes \
    "$(grep -qi 'token initialized' "$W/ok.out" && echo yes || echo no)"

echo "=== 5. ⚠️ AND AN UNTRUSTED CLIENT SEES NOTHING ==="
# The PIN protecting every CA key crosses this link in C_Login. If client verification
# regressed, section 4 would still pass — this is the half that would notice.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/rogue.key" -out "$W/rogue.crt" \
    -days 1 -subj "/CN=rogue" >/dev/null 2>&1
sed -e "s|$CD/client.crt|$W/rogue.crt|" -e "s|$CD/client.key|$W/rogue.key|" \
    -e "s|$W/run/tunnel.sock|$W/run/rogue.sock|" "$W/client.conf" > "$W/rogue.conf"
stunnel "$W/rogue.conf" >"$W/stunnel-rogue.log" 2>&1 & ROGUE_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$W/run/rogue.sock" ] && break; sleep 0.3; done
P11_KIT_SERVER_ADDRESS="unix:path=$W/run/rogue.sock" \
    pkcs11-tool --module "$SHIM" -T >"$W/rogue.out" 2>&1 || true
chk "an untrusted client gets no token" yes \
    "$(grep -qi 'token label' "$W/rogue.out" && echo no || echo yes)"
chk "  and the server says why it refused" yes \
    "$(grep -qi 'certificate verify failed' "$W/stunnel-server.log" && echo yes || echo no)"
# PRECONDITION for the two above: a refusal proves nothing if the good client never worked.
chk "  PRECONDITION: the trusted client did get in" yes \
    "$(grep -qi 'token label' "$W/ok.out" && echo yes || echo no)"

echo "=== 6. the trust set converges through the mesh, not by copying files ==="
# ⚠️ THE LAST MANUAL STEP THIS REMOVES. The serving node trusts a DIRECTORY of client
# certificates, and filling it on a multi-node deployment meant an operator carrying each
# joining node's certificate across by hand. `datacenters` already replicates and is already
# keyed per node, so a node publishes its own certificate into its own row and the serving
# node materialises the directory from what it finds.
if command -v psql >/dev/null 2>&1 && [ -f "$ROOT/tests/pg_helpers.sh" ]; then
  # shellcheck source=/dev/null
  . "$ROOT/tests/pg_helpers.sh"
  if pg_setup p11trust >/dev/null 2>&1; then
    CFG="$ROOT/build/fastpki-config"
    cat > "$W/t.conf" <<EOF
PG_CONNINFO=$PG_CONNINFO
DATACENTER_ID=dc1
EOF
    pg_exec "INSERT INTO datacenters(dc_id, serial_prefix) VALUES('dc1', 1)
             ON CONFLICT (dc_id) DO NOTHING;" >/dev/null 2>&1
    pg_exec "INSERT INTO datacenters(dc_id, serial_prefix) VALUES('dc2', 2)
             ON CONFLICT (dc_id) DO NOTHING;" >/dev/null 2>&1

    # ⚠️ THE KEY MUST NEVER TRAVEL. Publishing client.key instead of client.crt would
    # replicate this node's transport key to every peer, so it is refused by content.
    "$CFG" --config "$W/t.conf" p11-client-publish "$D/client.key" >/dev/null 2>&1 && r=ok || r=refused
    chk "publishing a PRIVATE KEY is refused"    refused "$r"

    "$CFG" --config "$W/t.conf" p11-client-publish "$D/client.crt" >"$W/pub.out" 2>&1 && r=ok || r=failed
    chk "a node publishes its own certificate"   ok "$r"
    [ "$r" = ok ] || { echo "  --- why ---"; head -4 "$W/pub.out"; }
    chk "  into its own row, and only its own"   1 \
        "$(pg_exec "SELECT count(*) FROM p11_transport WHERE client_cert IS NOT NULL;" | tr -d ' ')"

    # A second node's certificate arrives the way every other replicated row does.
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/dc2.key" -out "$W/dc2.crt" \
        -days 1 -subj "/CN=fastpki-p11-client-dc2" >/dev/null 2>&1
    pg_exec "INSERT INTO p11_transport(host_id, dc_id, client_cert) VALUES('dc2-host','dc2',\$\$$(cat "$W/dc2.crt")\$\$) ON CONFLICT (host_id) DO UPDATE SET client_cert=EXCLUDED.client_cert;" >/dev/null 2>&1

    SYNC="$W/trust"; mkdir -p "$SYNC"
    # certgen puts THIS node's own client.crt in the same directory. A sync that swept every
    # *.crt would delete it, so a run before any peer had published would empty the trust set
    # and the tunnel would refuse everyone. Planted here so that can never come back.
    cp "$D/client.crt" "$SYNC/client.crt"
    "$CFG" --config "$W/t.conf" p11-clients-sync "$SYNC" >/dev/null 2>&1
    chk "  certgen's own client.crt survives a sync" yes \
        "$([ -f "$SYNC/client.crt" ] && echo yes || echo no)"
    chk "the serving node materialises both"     2 "$(ls "$SYNC"/host-*.crt 2>/dev/null | wc -l | tr -d ' ')"
    # ⚠️ A CApath IS LOOKED UP BY SUBJECT HASH. A .crt with no <hash>.N link beside it is
    # invisible to OpenSSL — the tunnel would refuse a node whose certificate is right there.
    chk "  with the hash links OpenSSL reads"    2 \
        "$(find "$SYNC" -type l 2>/dev/null | wc -l | tr -d ' ')"

    # Removing a row is how a node is locked out; a merge would keep trusting the old file.
    pg_exec "DELETE FROM p11_transport WHERE host_id='dc2-host';" >/dev/null 2>&1
    "$CFG" --config "$W/t.conf" p11-clients-sync "$SYNC" >/dev/null 2>&1
    chk "revoking a node drops its certificate"  1 "$(ls "$SYNC"/host-*.crt 2>/dev/null | wc -l | tr -d ' ')"
    chk "  and its stale hash link with it"      1 \
        "$(find "$SYNC" -type l 2>/dev/null | wc -l | tr -d ' ')"
    # ⚠️ AND THE SERVER HALF, WHICH IS WHAT MAKES A CROSS-HOST HANDSHAKE POSSIBLE. A
    # consumer verifies the token host it dials; with only the client half published it
    # would be left pinning a certificate it generated itself. The two columns are
    # independent, so publishing one must not disturb the other.
    "$CFG" --config "$W/t.conf" p11-server-publish "$D/server.key" >/dev/null 2>&1 && r=ok || r=refused
    chk "publishing a server PRIVATE KEY is refused" refused "$r"

    "$CFG" --config "$W/t.conf" p11-server-publish "$D/server.crt" >"$W/spub.out" 2>&1 && r=ok || r=failed
    chk "the token host publishes its server certificate" ok "$r"
    [ "$r" = ok ] || { echo "  --- why ---"; head -4 "$W/spub.out"; }
    chk "  without disturbing the client column" 1 \
        "$(pg_exec "SELECT count(*) FROM p11_transport WHERE client_cert IS NOT NULL;" | tr -d ' ')"

    SSYNC="$W/servers"; mkdir -p "$SSYNC"
    "$CFG" --config "$W/t.conf" p11-servers-sync "$SSYNC" >/dev/null 2>&1
    chk "a consumer materialises the hosts it may dial" 1 \
        "$(ls "$SSYNC"/host-*.crt 2>/dev/null | wc -l | tr -d ' ')"
    chk "  with the hash link OpenSSL reads" 1 \
        "$(find "$SSYNC" -type l 2>/dev/null | wc -l | tr -d ' ')"
    # The two syncs must not read each other's column: a consumer that pulled CLIENT
    # certificates into its server trust would verify the host it dials against the
    # identity of a peer, which is a different node entirely.
    chk "  and the two trust sets stay distinct" yes \
        "$(cmp -s "$(ls "$SSYNC"/host-*.crt | head -1)" "$D/server.crt" && echo yes || echo no)"

    pg_cleanup >/dev/null 2>&1 || true
  else
    echo "  [SKIP] no Postgres available for the trust-convergence section"
  fi
else
  echo "  [SKIP] psql not available for the trust-convergence section"
fi

echo
echo "=== HSM TLS TRANSPORT: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
