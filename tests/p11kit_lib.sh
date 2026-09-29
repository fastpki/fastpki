# Sourced helper. SoftHSM uses OpenSSL as its own crypto backend, so
# loaded as a PKCS#11 module *into* an OpenSSL process (fastpki, `openssl req`) it
# re-enters libcrypto and can DEADLOCK — and it's racy (sometimes it completes,
# sometimes it hangs). The confirmed fix: run the token
# out-of-process. Token setup (softhsm2-util / pkcs11-tool) always talks to the
# direct module in its own process — safe.
#
# ⚠️ THE FALLBACK USED TO BE THE BUG. This returned the DIRECT module whenever it
# could not wire an out-of-process route, justified as "e.g. macOS, where the
# deadlock doesn't occur". Alpine is not macOS. The shipped image has `p11-kit` and
# a writable module dir but NO p11-kit-proxy.so anywhere — musl/Alpine does not
# package one — so on the platform we actually ship, this handed back the direct
# module and `openssl req -x509` wedged for 26 minutes in futex_wait_queue with no
# socket open: exactly the deadlock the helper exists to prevent. It only ever
# surfaced once the suite ran on a real DC.
#
# So the order is now: sidecar, then proxy, then FAIL — never silently pick the
# route we know hangs.
#
# p11_setup_signing <direct-softhsm-module> SETS $P11_SIGN_MODULE — it does not echo it.
# Call it AFTER exporting SOFTHSM2_CONF so the spawned server sees the same token.
# Returns non-zero (and explains) if there is no safe route.
#
# ⚠️ IT ASSIGNS RATHER THAN ECHOING FOR A REASON. The old shape was
# `SIGN_MOD=$(p11_sign_module ...)`, and command substitution is a SUBSHELL: the
# `export P11_KIT_SERVER_ADDRESS` died with it and the server became that subshell's
# child. The caller then held the right module path and no way to reach the server,
# so the pkcs11 provider failed "Module initialization failed!" and OpenSSL quietly
# fell back to the file store and ran stat() on the pkcs11: URI. The visible symptom
# was "could not self-sign with the token key" — nothing about a missing server.
# There is nothing to capture now, so the subshell cannot come back by accident.

# Start a p11-kit server for THIS suite's token and point the client shim at it.
#
# ⚠️ Always start our own, never reuse an inherited P11_KIT_SERVER_ADDRESS. run_all.sh
# exports one for the shared token (hsm_helpers.sh), and a suite that mints its own
# token in its own SOFTHSM2_CONF would then ask the WRONG server and find no key —
# which reads as "the token is broken", not as "you are talking to a different token".
p11_server_start() {
    local mod="$1" p11kit="$2" sock i
    sock="${TMPDIR:-/tmp}/p11sign-$$.sock"
    "$p11kit" server -f -n "$sock" --provider "$mod" "pkcs11:" > p11sign-server.log 2>&1 &
    P11_SIGN_SERVER_PID=$!
    for i in $(seq 1 40); do [ -S "$sock" ] && break; sleep 0.25; done
    [ -S "$sock" ] || return 1
    export P11_KIT_SERVER_ADDRESS="unix:path=$sock"
    export P11_SIGN_SERVER_PID
    return 0
}

# Call from the suite's EXIT trap. p11-kit does NOT unlink its socket on SIGTERM, so
# a leftover path keeps looking like a live server to anything that probes for one.
p11_cleanup() {
    [ -n "${P11_SIGN_SERVER_PID:-}" ] && kill "$P11_SIGN_SERVER_PID" 2>/dev/null
    P11_SIGN_SERVER_PID=""
    case "${P11_KIT_SERVER_ADDRESS:-}" in
        unix:path=*) rm -f "${P11_KIT_SERVER_ADDRESS#unix:path=}" 2>/dev/null ;;
    esac
    return 0
}

p11_setup_signing() {
    local direct="$1" p11kit="" proxy="" client="" modcfg="" d
    P11_SIGN_MODULE=""
    p11kit=$(command -v p11-kit 2>/dev/null) || true

    # 1) THE SIDECAR — p11-kit-client.so talking to `p11-kit server` over a unix socket.
    #    This is what the DEPLOYMENT runs, and on Alpine it is the only route that
    #    exists. Preferring it here means the suite exercises the same arrangement the
    #    product ships with, instead of a second mechanism that only works on Debian.
    if [ -n "$p11kit" ]; then
        for client in /usr/lib/pkcs11/p11-kit-client.so \
                      /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so \
                      /usr/lib64/pkcs11/p11-kit-client.so; do
            [ -e "$client" ] && break || client=""
        done
        if [ -n "$client" ] && p11_server_start "$direct" "$p11kit"; then
            P11_SIGN_MODULE="$client"; return 0
        fi
    fi

    # 2) The proxy + a `remote:` directive spawns the token as a child process. Debian
    #    and friends package p11-kit-proxy.so; Alpine does not.
    for proxy in /usr/lib/p11-kit-proxy.so /usr/lib/x86_64-linux-gnu/p11-kit-proxy.so \
                 /usr/lib64/p11-kit-proxy.so; do
        [ -e "$proxy" ] && break || proxy=""
    done
    if [ -n "$p11kit" ] && [ -n "$proxy" ]; then
        for d in /usr/share/p11-kit/modules /etc/pkcs11/modules; do
            if [ -d "$d" ] && [ -w "$d" ]; then modcfg="$d/softhsm2.module"; break; fi
        done
        if [ -n "$modcfg" ] &&
           printf 'module: %s\nremote: |%s remote %s\n' "$direct" "$p11kit" "$direct" > "$modcfg"; then
            P11_SIGN_MODULE="$proxy"; return 0
        fi
    fi

    # 3) Direct, in-process — ONLY where the deadlock does not occur. macOS has never
    #    reproduced it (SoftHSM there links its own libcrypto). Everywhere else this is
    #    the hanging path, and hanging is worse than failing: a wedged suite blocks the
    #    whole run and reports nothing at all.
    if [ "$(uname -s)" = "Darwin" ]; then P11_SIGN_MODULE="$direct"; return 0; fi
    echo "p11kit_lib: no out-of-process PKCS#11 route on $(uname -s)." >&2
    echo "  need p11-kit + p11-kit-client.so (sidecar) or p11-kit-proxy.so (proxy);" >&2
    echo "  refusing the direct module — in-process SoftHSM deadlocks here." >&2
    return 1
}
