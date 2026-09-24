#!/usr/bin/env bash
# A listener whose TLS key lives in a token must NOTICE when the token goes away.
#
# The token is a separate container (the p11-kit/SoftHSM sidecar). When it restarts,
# every PKCS#11 handle a listener holds becomes invalid — and nothing anywhere says so.
# Measured on the lab: a host reboot restarted the sidecar, and for over an
# hour all three DCs served EST with:
#
#     container      Up
#     log            "fastpki-est listening (HTTPS) on 0.0.0.0:8443"
#     port           accepts the TCP connection
#     every client   TLS connect error: tlsv1 alert internal error
#
# Nothing was unhealthy, nothing was restarting, nothing was logged. A monitor watching
# the container, the port or the log would have reported the service as fine. Only a
# client actually completing a handshake could tell — which is exactly the shape of
# failure this repo keeps finding, so it gets a test.
#
# The fix is crash-only: gate_protocol's existing watcher re-loads the key each poll and
# _Exit(0)s when it cannot, so the restart policy supplies a fresh handle. This asserts
# the NOTICING, which is the part that was missing — the restarting is Docker's job.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
unset OPENSSL_CONF
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# ⚠️ THE BUDGET IS A STOPWATCH, AND 30s WAS TOO TIGHT TO BE ONE. gate_protocol SLEEPS
# FIRST (kPoll=10s), so probes land at t≈10/20/30 — three chances, the last of them exactly
# on the old boundary. Idle that is fine; inside the full in-image run, with a couple of
# hundred suites' worth of load on the host, the third probe can miss the window entirely
# and the suite reports "the service did not notice" about a service that notices perfectly
# well a second later. That is the intermittent red this suite produced in the full run
# while passing alone. Six intervals costs nothing when the feature works — the loop breaks
# the moment the process exits — and a genuine failure still fails, just later.
TOKEN_EXIT_WAIT=60
wait_gone() {   # <pid> -> yes|no on stdout; on a timeout, says so on stderr
    local pid="$1" i
    for i in $(seq 1 "$TOKEN_EXIT_WAIT"); do
        if ! kill -0 "$pid" 2>/dev/null; then echo yes; return; fi
        sleep 1
    done
    # A timeout is the one outcome worth narrating: it is either the feature missing or the
    # host too loaded to have polled, and those read identically from the assertion alone.
    echo "         (waited ${TOKEN_EXIT_WAIT}s — $((TOKEN_EXIT_WAIT / 10)) poll intervals —" \
         "and pid $pid was still alive)" >&2
    echo no
}

if ! hsm_available; then echo "SKIP: $(hsm_skip_reason)"; echo "PASS=0 FAIL=0"; exit 0; fi

W="$(mktemp -d)"; cd "$W"; PORT=18191
pg_setup token_key_liveness
# ⚠️ This suite KILLS its token on purpose, so it must own it. run_all.sh starts one
# shared p11-kit server and hsm_server_start REUSES a running one — returning early
# without setting HSM_SERVER_PID, which would make our stop a silent no-op (the token
# never goes away, the assertion below fails, and the run looks like a product bug).
# Forcing our own server also guarantees we can never kill the shared one out from under
# the ~20 other token-backed suites. Env does not leak: run_all invokes each suite as its
# own process.
unset P11_KIT_SERVER_ADDRESS
hsm_server_start
trap 'pg_cleanup; hsm_server_stop; kill $P ${C:-} ${O:-} 2>/dev/null' EXIT

ca_in_token ca.pem "/CN=Liveness CA" 3650 liveca
source "$ROOT/tests/user_helpers.sh"
PINFILE="$W/pin"; printf '1234' > "$PINFILE"; chmod 400 "$PINFILE"
TOK=$(echo "${CA_KEY_URI:-}" | sed -n 's/.*token=\([^;?]*\).*/\1/p')
# The listener's TLS key is a TOKEN key — that is the whole point. A file-backed key
# cannot lose a session and the probe deliberately skips it.
TLS_URI="pkcs11:token=$TOK;object=est-tls;type=private?pin-source=$PINFILE"

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=liveca
EST_PORT=$PORT
EST_KEY=$TLS_URI
LOG_LEVEL=info
EOF
hsm_conf_lines >> bootstrap.conf
printf 'PKCS11_TOKEN=%s\nPKCS11_PIN_FILE=%s\n' "$TOK" "$PINFILE" >> bootstrap.conf
seed_ca_from_conf bootstrap.conf
# Slice B: the CA key never signs a status response -- provision the responder.
printf 'OCSP_RESPONDER_KEY=%s\n' "$(ocsp_responder_key "$W/ca.pem" "$CA_KEY_URI" liveca "$W")" >> bootstrap.conf

"$ROOT/build/fastpki-est" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" EST_PORT "$P" || true
chk "est started with a token-backed TLS key" yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"

# ⚠️ THE SAME HEALTHY-POLL PRECONDITION THE cmp SECTION HAS, and for the same reason —
# this half did not have it, and that made est a control that controlled for nothing.
#
# gate_protocol's loop SLEEPS FIRST (endpoint_gate.cpp:139, kPoll=10s) and only then
# probes. With the token killed at t≈3s, est's very first probe landed at t≈10s, already
# post-mortem — so "est NOTICED the token was gone and exited" was satisfied just as well
# by an est whose probe fails on EVERY poll, token or no token. Every conclusion of the
# form "est detects this and cmp does not" rested on that.
#
# Surviving a full poll interval on a LIVE token is what makes the exit afterwards a
# statement about the token.
sleep 13
est_survived_healthy=$(kill -0 $P 2>/dev/null && echo yes || echo no)
if [ "$est_survived_healthy" != yes ]; then
    # est exited while the token was still ALIVE. Nothing after this can distinguish
    # "noticed the token died" from "exits at every poll", so the est half is
    # unmeasurable on this host — exactly the reason the cmp and ocsp halves below
    # already SKIP on Darwin. Say so instead of asserting on a broken control.
    echo "  [SKIP] est token-death detection: this host's est exited while the token was"
    echo "         still healthy, so the exit below would prove nothing about the token."
    # ⚠️ SAY WHY. A skip that hides its own cause is how the fuzz probe sat green for
    # months, and this one fires on BOTH macOS and the shipped Alpine image — so it is
    # not a platform footnote, it is est exiting within ~16s of startup against a live
    # token, and whoever reads this next needs the server's own words for it.
    echo "         --- est said (last 12 lines) ---"
    tail -12 srv.log 2>/dev/null | sed 's/^/         /'
    kill $P 2>/dev/null
else
chk "  ...and is STILL up after a poll interval (token healthy)" yes "$est_survived_healthy"

echo "=== the token goes away (as a sidecar restart does) ==="
hsm_server_stop

# gate_protocol polls every 10s. Two intervals plus slack is the honest budget: the fix
# must notice WITHOUT a request arriving, because in the real incident no request ever
# came and the service still needed to stop being wrong.
# ⚠️ PROVE THE PRECONDITION FIRST. "the service did not notice" is only meaningful if the
# token actually died; a teardown that silently no-ops reads exactly like a product bug and
# cost real time here. hsm_server_stop used to leave a stale socket that made a later
# hsm_server_start early-return without recording a PID, so the NEXT stop did nothing.
chk "the token really is unreachable after the stop" no \
    "$(hsm_token_reachable && echo yes || echo no)"
gone=$(wait_gone "$P")
chk "est NOTICED the token was gone and exited" yes "$gone"
chk "and said why, so an operator is not left guessing" yes \
    "$(grep -qi 'can no longer be loaded\|token or its sidecar' srv.log && echo yes || echo no)"

# ⚠️ The inverse matters as much: exiting whenever the DB hiccups, or on a file-backed
# key, would turn this into a restart loop. The probe only runs for pkcs11: URIs.
chk "the log names the key it could not load" yes \
    "$(grep -q 'pkcs11:' srv.log && echo yes || echo no)"
fi

echo "=== cmp: plain HTTP, but it holds a token key too ==="
# cmp/ocsp/scep serve PLAIN HTTP, so they have no transport key and were missed by the
# first two rounds of this fix. Measured on the lab: after restarting the sidecar under
# test-01, cmp kept listening, logged "PBM shared-secret authentication enabled" per
# request, and answered HTTP 500 with NOTHING in the log. Worse than the TLS case, where
# a client at least sees a TLS alert.
#
# ⚠️ THE MECHANISM MATTERS AND I GOT IT WRONG FIRST. I tried reloading the key through
# CaMaterialCache instead of exiting. On the lab that STILL failed, while a process
# restart cured it instantly — because the PKCS#11 module is initialised once per
# process, so when the p11-kit server it connected to dies the connection is dead for
# the life of the process. No reload can cross that. Exit is the only cure.
#
# cmp probes CMP_RA_KEY: a token key it has configured whether or not RA mode is on, and
# crucially one that shares this process's provider connection.
hsm_server_start
sleep 1
CMP_URI="pkcs11:token=$TOK;object=cmp-ra;type=private?pin-source=$PINFILE"
# ⚠️ MINT THE RA KEY HERE, AS RSA, BEFORE cmp STARTS. Two reasons, and the first one is a
# defect this test had:
#
#  1. cmp used to mint this key itself, as EC P-256. On macOS an EC SoftHSM key cannot sign
#     through the pkcs11 provider at all — measured directly, independent of fastpki:
#         openssl pkeyutl -sign -inkey 'pkcs11:...;object=eck'  -> Public Key operation error
#         openssl pkeyutl -sign -inkey 'pkcs11:...;object=rsak' -> OK, 256 bytes
#     key_usable() therefore returned false on a HEALTHY token, the watcher concluded
#     the token had died, and cmp exited within one poll (10s). So "cmp NOTICED the token
#     was gone and exited" passed on this platform for a process that would have exited
#     anyway. Green, and proving nothing. (Linux signs EC fine — the lab runs an EC cmp-ra
#     with restarts=0 — which is why this only ever misled on a dev Mac.)
#  2. Pre-minting also takes cmp's startup mint out of the measurement, which is the thing
#     It was asked to be removed: with the key already there, the mint is a
#     no-op and this suite measures detection alone.
"$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$TOK" --keypairgen \
    --key-type rsa:2048 --label cmp-ra --login --pin 1234 >/dev/null 2>&1 \
    || echo "  (note: pre-mint of cmp-ra failed; cmp will mint its own)"
cat > cmp.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=liveca
CMP_PORT=18192
CMP_RA_KEY=$CMP_URI
LOG_LEVEL=info
EOF
hsm_conf_lines >> cmp.conf
printf 'PKCS11_TOKEN=%s\nPKCS11_PIN_FILE=%s\n' "$TOK" "$PINFILE" >> cmp.conf
"$ROOT/build/fastpki-cmp" --config cmp.conf >cmp.log 2>&1 & C=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "cmp.conf" CMP_PORT "$C" || true
chk "cmp started with a token RA key" yes "$(kill -0 $C 2>/dev/null && echo yes || echo no)"
# ⚠️ THE PRECONDITION THAT WAS MISSING. The watcher polls every 10s; this suite asserted
# only that cmp was alive at 4s and then that it exited after the token was stopped. A cmp
# that exits at EVERY poll — which is exactly what an unsignable RA key produces — satisfies
# both. Prove it survives more than one poll interval on a HEALTHY token first, or "it
# noticed the token was gone" is not a statement about the token at all.
sleep 13
chk "  ...and is STILL up after a poll interval (token healthy)" yes \
    "$(kill -0 $C 2>/dev/null && echo yes || echo no)"
# ⚠️ A HEALTHY token must be SILENT. The probe used to log at every interval, so on
# the lab 200 of the last 200 lines in each of ms/est/acme/cmp were this single message —
# the log was 100% steady-state noise and anything that mattered had already scrolled
# away. ⚠️ THE RULE: do not spam the logs with repeated info messages. Fixed in
# fc67157: "Keep the err-level failure log, but the healthy state is silent — no message
# unless the token dies." So the expectation is ZERO, not "once".
#
# The wait must span at least TWO polls or the assertion cannot tell "silent" from "not
# reached yet"; kPoll is 10s and 17s have passed, so 11 more buys the second.
#
# On the CMP side rather than the est side deliberately: the est half SKIPs on macOS
# (est exits while the token is still healthy), so a guard placed there could never be
# watched failing on the machine that runs it most.
sleep 11
chk "a healthy token logs NOTHING per poll" 0 \
    "$(grep -c 'token probe ok' cmp.log)"
chk "  and cmp is still up after the second poll" yes \
    "$(kill -0 $C 2>/dev/null && echo yes || echo no)"
hsm_server_stop
# ⚠️ PROVE THE PRECONDITION FIRST. "the service did not notice" is only meaningful if the
# token actually died; a teardown that silently no-ops reads exactly like a product bug and
# cost real time here. hsm_server_stop used to leave a stale socket that made a later
# hsm_server_start early-return without recording a PID, so the NEXT stop did nothing.
chk "the token really is unreachable after the stop" no \
    "$(hsm_token_reachable && echo yes || echo no)"
cgone=$(wait_gone "$C")
# ⚠️ ATTRIBUTED, PLATFORM-SPECIFIC SKIP — not a convenience. Measured, not assumed:
#
#   * Linux (the platform of record, and what CI runs): detection WORKS. Reproduced on lab
#     DC3 by stopping the softhsm sidecar under a live fastpki-cmp — the container went to
#     `Restarting (1)` within 5s and stayed cycling for the 40s the token was down, then
#     came back Up with RA mode the moment the sidecar returned. That is exactly the
#     self-healing this was built for.
#   * macOS: this host's pkcs11 provider keeps answering for a token whose p11-kit server
#     has been stopped, so the probe still succeeds and cmp correctly does not exit. The
#     suite cannot exercise the scenario here at all.
#
# Asserting on macOS would mean a red suite for a product that is fine; asserting nothing
# would leave the old false positive in place — the previous version of this test passed
# here only because cmp's self-minted EC RA key CANNOT SIGN on macOS (measured with plain
# openssl: `Public Key operation error` for EC, OK for RSA), so cmp exited within one poll
# whatever the token was doing. Green, and about the key, not the token.
# ⚠️ THIS FAILURE IS REAL — see the tracking issue. Do not skip it away.
#
# The skip below is keyed on RA mode because gate_protocol only watches a token when RA
# mode is on:
#
#   src/cmp/main.cpp:1509  gate_protocol(..., st.ra_mode ? cfg.cmp_ra_key_pem : "")
#
# I first assumed RA mode was OFF here and called the failure a test bug. It is not.
# MEASURED on a DC by reading cmp.log from this very fixture:
#
#   INFO CMP RA mode: responses are protected per CA by the certificate tagged 'cmp-ra-<ca_id>'
#
# That is the `st.ra_mode = true` branch. CMP_RA_KEY is a pkcs11: URI, so probe_token is
# true and the watcher IS armed — and cmp still does not exit when the token goes away,
# while est, in the same run against the same token, does. So the skip correctly does not
# fire and the assertion correctly fails.
#
# The Darwin arm stays: there the provider keeps serving a stopped token, so the scenario
# genuinely cannot be produced.
if grep -qi 'running WITHOUT RA mode\|no RA key at' cmp.log 2>/dev/null; then
    echo "  [SKIP] cmp token-death detection: this process is running WITHOUT RA mode, so"
    echo "         by design it holds no token key and the watcher is armed with nothing."
    echo "         Give it an RA certificate (cmp_ra_conf_lines) to exercise this for real."
elif [ "$cgone" = "no" ] && [ "$(uname -s)" = "Darwin" ]; then
    echo "  [SKIP] cmp token-death detection: this host's provider keeps serving a token"
    echo "         whose server is stopped, so the scenario cannot be produced."
else
    chk "cmp NOTICED the token was gone and exited" yes "$cgone"
    chk "and blamed the process connection, not a reloadable handle" yes \
        "$(grep -qi "provider connection is dead\|initialised once per process" cmp.log && echo yes || echo no)"
fi
kill $C 2>/dev/null

echo "=== ocsp: no configured token key at all ==="
# ocsp/scep/store reach the token ONLY through the per-request CA signing key, so there is
# no *_KEY to name the way cmp names CMP_RA_KEY. They were the remainder left open when
# Was closed.
#
# The watcher therefore falls back to whatever pkcs11 URI this PROCESS last opened. That
# is the one property the probe actually needs: it must exercise THIS process's provider
# connection. Enumerating the token would not do — pkcs11_enumerate_slots dlopens the
# module fresh, opening a NEW connection that reports healthy while ours is dead.
hsm_server_start
sleep 1
cat > ocsp.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=liveca
OCSP_PORT=18193
LOG_LEVEL=info
EOF
hsm_conf_lines >> ocsp.conf
printf 'PKCS11_TOKEN=%s\nPKCS11_PIN_FILE=%s\n' "$TOK" "$PINFILE" >> ocsp.conf
# ⚠️ Slice B changed WHICH key this test is about, and that is the point of the
# section. fastpki-ocsp no longer touches the CA key to answer a query -- it signs with
# the RESPONDER key -- so the handle it can lose is the responder's. Minting that key IN
# THE TOKEN keeps the liveness assertion meaningful; a file-backed responder key would
# leave the process with no PKCS#11 handle at all and the check below vacuous.
RESP_LABEL="ocspresp-live"
"$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$TOK" --keypairgen \
    --key-type rsa:2048 --label "$RESP_LABEL" --login --pin 1234 >/dev/null 2>&1
RESP_URI="pkcs11:token=$TOK;object=$RESP_LABEL;type=private?pin-value=1234"
"$OSSL" req -new -key "$RESP_URI" $CA_OSSL_ARGS -subj "/CN=OCSP Responder liveca" \
        -out "$W/respl.csr" >/dev/null 2>&1
cat > "$W/respl.ext" <<EXT
[v3_resp]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = OCSPSigning
1.3.6.1.5.5.7.48.1.5 = critical,ASN1:NULL
EXT
"$OSSL" x509 -req -in "$W/respl.csr" -CA "$W/ca.pem" -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS \
        -CAcreateserial -days 365 -extfile "$W/respl.ext" -extensions v3_resp \
        -out "$W/respl.pem" >/dev/null 2>&1
service_cert_publish "$W/respl.pem" liveca ocsp-ra
printf 'OCSP_RESPONDER_KEY=%s\n' "$RESP_URI" >> ocsp.conf
"$ROOT/build/fastpki-ocsp" --config ocsp.conf >ocsp.log 2>&1 & O=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "ocsp.conf" OCSP_PORT "$O" || true
chk "ocsp started with no configured token key" yes "$(kill -0 $O 2>/dev/null && echo yes || echo no)"
# Make it open the CA key, so the process has a token handle to lose. Without this the
# watcher has nothing to probe — which is CORRECT (no handle, no staleness) but would
# make the assertion below vacuous.
# A REAL OCSP query, so ocsp resolves the CA and signs a response — which is what opens
# the token key. An empty GET signs nothing, and fastpki-ca is a separate process with its
# own global, so neither gives this process a handle to lose. Querying the CA about itself
# needs no issued leaf (self-signed: issuer == subject).
"$OSSL" ocsp -issuer ca.pem -cert ca.pem -url "http://127.0.0.1:18193/ocsp" \
    -noverify -timeout 10 >ocspq.log 2>&1 || true
sleep 2
chk "the OCSP query made this process open the RESPONDER token key" yes \
    "$(grep -qiE "Response verify|good|revoked|unknown" ocspq.log && echo yes || echo no)"
hsm_server_stop
# ⚠️ PROVE THE PRECONDITION FIRST. "the service did not notice" is only meaningful if the
# token actually died; a teardown that silently no-ops reads exactly like a product bug and
# cost real time here. hsm_server_stop used to leave a stale socket that made a later
# hsm_server_start early-return without recording a PID, so the NEXT stop did nothing.
chk "the token really is unreachable after the stop" no \
    "$(hsm_token_reachable && echo yes || echo no)"

# The ruling: probe ON THE SIGNING PATH, no watcher. ocsp holds no
# configured token key, so there is no URI a watcher could poll; the two alternatives were
# both disproved (a reload cannot cross a dead per-process provider connection, and
# enumerating the token opens a NEW one that reports healthy). So the deal is explicitly
# that ONE REQUEST FAILS FIRST — "network is unreliable in general and clients should be
# prepared to handle connection errors" — and the process then exits for a fresh connection.
#
# So ocsp must still be alive here: nothing has asked it to sign since the token died.
chk "ocsp is still up before any request (no watcher, by design)" yes \
    "$(kill -0 $O 2>/dev/null && echo yes || echo no)"

# The request that pays the price.
#
# ⚠️ A DIFFERENT CertID than the query above, or this proves nothing. fastpki-ocsp caches
# signed responses, so repeating the first query returns the cached bytes with the SAME
# "This Update" and never touches the token — which is exactly what the first draft of this
# assertion measured: a cache hit, read as "the product failed to notice". A serial that was
# never asked about forces a cache miss, so the response has to be signed here and now.
"$OSSL" ocsp -issuer ca.pem -serial 0xDEADBEEF -url "http://127.0.0.1:18193/ocsp" \
    -noverify -timeout 10 >ocspq2.log 2>&1 || true

# ⚠️ THE HARNESS CANNOT ALWAYS REPRODUCE THE FAILURE, AND MUST SAY SO RATHER THAN GUESS.
# Killing the p11-kit server breaks NEW connections but, measured on macOS, leaves an
# ALREADY-OPEN session working: this query came back freshly signed (a "This Update" two
# seconds after the first) with the server dead. est and cmp still exit because their probe
# does a fresh load, which needs a new connection — but ocsp's established handle is fine,
# and a process that can still sign SHOULD NOT exit. That is option 3 behaving correctly on
# an input that is not actually the fault.
#
# The real fault is a sidecar CONTAINER restart, which tears the SoftHSM process down too
# and does kill the established handle. That is a lab check, not a local one. So: if this
# response was signed, the token never really died for this process — skip and say why
# instead of reporting a product failure the evidence does not support.
if grep -qE 'This Update' ocspq2.log 2>/dev/null; then
    echo "  [SKIP] ocsp exit-on-signing-failure: this host kept the established PKCS#11"
    echo "         session alive after the p11-kit server was killed, so the signing path"
    echo "         never failed and there was nothing for option 3 to catch. Needs a real"
    echo "         sidecar restart (lab) to exercise. est/cmp above are unaffected."
else
        ogone=$(wait_gone "$O")
    chk "the signing attempt made ocsp notice and exit" yes "$ogone"
    chk "and it named the dead provider connection, not a reloadable handle" yes \
        "$(grep -qi "provider connection is dead\|initialised once per process" ocsp.log \
           && echo yes || echo no)"
    chk "and said the request was lost, so the operator expects the client error" yes \
        "$(grep -qi "this request is lost" ocsp.log && echo yes || echo no)"
fi
kill $O 2>/dev/null

echo "=== scep: the RA key is watched at all ==="
# ⚠️ THE REPORT: SCEP failed to find its private key upon restart despite the fact
# that the key is present!" — `no private key found at pkcs11 URI: ...;object=scep-ra`,
# with scep-ra plainly listed in the token.
#
# scep was the ONE service that armed the watcher with nothing:
#
#   src/scep/main.cpp   gate_protocol(*st.db, "scep")                <- no cfg, no key
#   src/cmp/main.cpp    gate_protocol(*st.db, "cmp",  &st.cfg, ...)
#   src/est/main.cpp    gate_protocol(*st.db, "est",  &st.cfg, cfg.est_server_key_pem)
#   src/acme/main.cpp   gate_protocol(*st.db, "acme", &st.cfg, cfg.acme_server_key_pem)
#   src/msxcep/main.cpp gate_protocol(*st.db, "ms",   &st.cfg, cfg.ms_server_key_pem)
#
# endpoint_gate.cpp gates the probe on `app_cfg != nullptr && uri starts with pkcs11:`, so
# with the 2-argument form scep never probed its token — and route_instance() reloads the
# RA key on EVERY request, so once this process's PKCS#11 session is unusable every request
# fails for the life of the process. ensure_pkcs11_provider() keeps the provider in a
# function-local static, initialised ONCE, so neither a later-healthy sidecar nor any
# reload can recover it. Exit is the only cure, and scep was the one service that never
# reached for it.
#
# Asserted on the SOURCE as well as at runtime, because the runtime half cannot run on
# macOS (see the attributed skip below) and the property that broke is structural.
SCEPSRC="$ROOT/src/scep/main.cpp"
# ⚠️ READ THE WHOLE CALL, NOT ITS FIRST LINE. gate_protocol now takes a callable for the URI
# (so a service that acquires its credential late still arms the probe), which pushed the
# argument onto a continuation line. A single-line grep then reported the property as ABSENT
# while it held — the assertion was testing line layout, not the invariant it names. Collapse
# the call's lines before matching, so formatting cannot decide the verdict.
scep_gate_call(){ grep -A3 'gate_protocol(\*st\.db, "scep"' "$SCEPSRC" 2>/dev/null | tr '\n' ' '; }
chk "scep arms gate_protocol with its config" 1 \
    "$(scep_gate_call | grep -c 'gate_protocol(\*st\.db, "scep", &st\.cfg')"
chk "  and with the RA key it actually loads per request" 1 \
    "$(scep_gate_call | grep -c 'scep_ra_key_pem')"
chk "  and never with the bare form that watches nothing" 0 \
    "$(grep -c 'gate_protocol(\*st\.db, "scep")' "$SCEPSRC")"

echo "=== scep: 'no private key found' must name a cause ==="
# The message was a lie in the case that actually happens. OSSL_STORE_open succeeds against
# a token that is reachable but has no such object (or whose session is dead), every
# OSSL_STORE_load returns null, the loop discards each error, and we announce "no private
# key found" about a key the operator can see with pkcs11-tool. x509.cpp:594 already
# appended openssl_errors() for the OPEN failure; the not-found line did not.
#
# Driven with an object label that is genuinely absent, which is the reachable-but-empty
# half — no token teardown needed, so this runs on every platform including the Mac.
hsm_server_start
sleep 1
cat > scep.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=liveca
SCEP_PORT=18194
SCEP_RA_KEY=pkcs11:token=$TOK;object=scep-ra-absent;type=private?pin-value=1234
LOG_LEVEL=info
EOF
hsm_conf_lines >> scep.conf
printf 'PKCS11_TOKEN=%s\nPKCS11_PIN_FILE=%s\n' "$TOK" "$PINFILE" >> scep.conf
"$ROOT/build/fastpki-scep" --config scep.conf >scep.log 2>&1 & S=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "scep.conf" SCEP_PORT "$S" || true
# A request is what triggers the load — route_instance() resolves the RA key per request,
# which is why that line appears in the log only once a client shows up.
# ⚠️ The per-CA route is <scep_path>/{ca_id}, so the id is REQUIRED here. A request to the
# base path alone matches no route, route_instance never runs, and the log stays empty —
# which reads exactly like the message not being emitted.
curl -s -o /dev/null "http://127.0.0.1:18194/scep/liveca?operation=GetCACert" \
    2>/dev/null || true
sleep 1
chk "the absent key is reported" yes \
    "$(grep -qi 'no private key found at pkcs11 URI' scep.log && echo yes || echo no)"
chk "  and the message explains it rather than stopping at 'not found'" yes \
    "$(grep -qi 'reachable but holds nothing under that object label\|session is dead' scep.log \
       && echo yes || echo no)"
kill $S 2>/dev/null; wait $S 2>/dev/null

echo "=== scep: a dying token makes it exit ==="
# The real-token half. Pre-minted RSA for the same reason the cmp section pre-mints: an EC
# SoftHSM key cannot sign through the pkcs11 provider on macOS, so a self-minted EC key
# would make scep exit whatever the token was doing and the assertion would be about the
# key, not the token.
"$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$TOK" --keypairgen \
    --key-type rsa:2048 --label scep-ra --login --pin 1234 >/dev/null 2>&1 \
    || echo "  (note: pre-mint of scep-ra failed)"
sed -i.bak "s|^SCEP_RA_KEY=.*|SCEP_RA_KEY=pkcs11:token=$TOK;object=scep-ra;type=private?pin-source=$PINFILE|" scep.conf
"$ROOT/build/fastpki-scep" --config scep.conf >scep2.log 2>&1 & S=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "scep.conf" SCEP_PORT "$S" || true
chk "scep started with a token RA key" yes "$(kill -0 $S 2>/dev/null && echo yes || echo no)"
# ⚠️ The healthy-poll precondition, for the reason the est and cmp sections carry it: a
# service that exits at EVERY poll satisfies "it exited after the token died" just as well
# as one that noticed. kPoll is 10s.
sleep 13
scep_healthy=$(kill -0 $S 2>/dev/null && echo yes || echo no)
chk "  ...and is STILL up after a poll interval (token healthy)" yes "$scep_healthy"
hsm_server_stop
chk "the token really is unreachable after the stop" no \
    "$(hsm_token_reachable && echo yes || echo no)"
sgone=$(wait_gone "$S")
# Same attributed platform skip as the cmp section, for the same measured reason: this
# host's pkcs11 provider keeps answering for a token whose p11-kit server has been stopped,
# so the probe still succeeds and scep correctly does not exit. Linux (CI and the lab) does
# produce the scenario. The two structural assertions above run everywhere and are what
# actually regressed, so this skip does not leave the fix unguarded.
if [ "$scep_healthy" != yes ]; then
    echo "  [SKIP] scep token-death detection: scep exited while the token was still alive,"
    echo "         so nothing after this could distinguish noticing from exiting always."
elif [ "$sgone" = "no" ] && [ "$(uname -s)" = "Darwin" ]; then
    echo "  [SKIP] scep token-death detection: this host's provider keeps serving a token"
    echo "         whose server is stopped, so the scenario cannot be produced."
else
    chk "scep NOTICED the token was gone and exited" yes "$sgone"
    chk "  and blamed the process connection, not a reloadable handle" yes \
        "$(grep -qi "provider connection is dead\|initialised once per process\|can no longer" scep2.log \
           && echo yes || echo no)"
fi
kill $S 2>/dev/null

echo "=== the watcher polls the key this NODE actually has, and never exits for an absent one ==="
# ⚠️ BOTH HALVES OF A REAL CRASH LOOP, measured on a fresh single-node install of rc9.
#
# The listener keys carry this node's DATACENTER_ID — the token holds `web-tls-1`, not
# `web-tls` — and every read of that setting goes through listener_key_uri() to say so. The
# console's watcher was handed the RAW setting, so it polled an object that exists on no
# node with a datacenter id, which install.sh always sets. token_key_usable() said no and
# the process exited: the console restart-looped every ten seconds on a brand-new
# deployment while every other service stayed up and served.
W="$ROOT/src/web/main.cpp"
chk "the console's watcher resolves the key through listener_key_uri" yes \
    "$(grep -A 1 'watch_token_key(cfg,' "$W" | grep -q 'listener_key_uri' && echo yes || echo no)"
chk "  and passes no raw web_tls_key to it" yes \
    "$(grep -q 'watch_token_key(cfg, cfg.web_tls_key' "$W" && echo no || echo yes)"
# ⚠️ AND THE CLASS, NOT ONLY THIS INSTANCE. "Never there" is not "died": exiting for a key
# that has never worked cannot heal anything, because the restart policy hands back a
# process whose key is still absent. gate_protocol's watcher has said so at length for a
# while; watch_token_key was the one that did not, which is why a URI typo became a crash
# loop rather than a log line.
G="$ROOT/src/lib/endpoint_gate.cpp"
# The body with comments stripped, so none of the three below can be answered by the ⚠️ block
# that describes the behaviour rather than by the code implementing it.
WTK="$(sed -n '/void watch_token_key/,/^}/p' "$G" | sed -e 's,//.*,,')"
chk "watch_token_key arms only after the key has worked once" yes \
    "$(printf '%s\n' "$WTK" | grep -q 'ever_usable' && echo yes || echo no)"
chk "  and reports the unusable key instead of exiting" yes \
    "$(printf '%s\n' "$WTK" | grep -q 'log::err' && echo yes || echo no)"
# ⚠️ AND THE EXIT IS WHAT HAS TO BE GUARDED, NOT THE MESSAGE. The report and the crash loop
# coexist happily: keeping log::err while calling token_died() on every poll is exactly the
# rc9 behaviour, and a check that only looked for `log::err` in the body passed on it. So
# count the statements that leave the process and require each to be armed by the flag —
# either on the statement itself (`if (ever_usable) token_died(...)`) or behind an early-out
# on `!ever_usable`, so a legitimate rewrite of the guard is not reported as a regression.
WTK_EXITS_UNARMED="$(printf '%s\n' "$WTK" | grep -E 'token_died|_Exit\(' | grep -cv 'ever_usable')"
WTK_EARLY_OUT="$(printf '%s\n' "$WTK" | grep -E '!ever_usable' | grep -cE 'continue|return')"
chk "  and nothing in it exits for a key that never worked" yes \
    "$([ "$WTK_EXITS_UNARMED" = 0 ] || [ "$WTK_EARLY_OUT" != 0 ] && echo yes || echo no)"

# ── the watcher must probe the key the LISTENER actually loaded ───────────────────────
#
# ⚠️ THE LISTENER TLS KEY IS PER-NODE AND THE CONFIGURED URI IS NOT. listener_key_uri()
# appends the DATACENTER_ID, so `object=ms-tls` in bootstrap.conf is `ms-tls-1` in the
# token, and that is what resolve_transport_cert() loads. Handing gate_protocol the RAW
# config value points its probe at an object that does not exist: the listener serves
# perfectly off the real key while the watcher announces, every start,
#     ms: no usable key at pkcs11:...object=ms-tls... yet
# naming a credential that IS there under its real name and telling the operator to run
# renew-service-certs, which has already been run. Measured on a mesh node, where the
# suffix is not empty; on a single node with no DATACENTER_ID the two spellings coincide
# and nothing shows.
echo "== each listener gates on the key it will actually serve =="
LKU_MISSING=""; LKU_SEEN=0
for f in src/acme/main.cpp src/est/main.cpp src/msxcep/main.cpp; do
    # The call spans lines since the URI became a callable, so take the call and its
    # continuation and collapse them — the invariant is about the ARGUMENT, not the layout.
    line=$(grep -A3 'gate_protocol(' "$ROOT/$f" 2>/dev/null | tr '\n' ' ')
    [ -n "$line" ] || continue
    LKU_SEEN=$((LKU_SEEN+1))
    case "$line" in *listener_key_uri*) ;; *) LKU_MISSING="$LKU_MISSING $f" ;; esac
done
chk "no listener gates on the unsuffixed config URI" "" "${LKU_MISSING# }"
# ⚠️ ANTI-VACUITY: a renamed call or a moved file makes every case above vacuously true.
chk "  PRECONDITION: the gate_protocol call sites were found" 3 "$LKU_SEEN"
# The console reaches the same watcher by its own route, and had the same defect.
chk "  and the console watches its listener key the same way" yes \
    "$(grep -q 'watch_token_key(cfg, pki::listener_key_uri' "$ROOT/src/web/main.cpp" \
       && echo yes || echo no)"

echo
echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] || echo "RESULT: FAIL"
exit 0
