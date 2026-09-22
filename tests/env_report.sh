# Which environment this is. Sourced by tests/run_all.sh.
#
# ⚠️ THIS IS DELIBERATELY SMALL. It used to print a capability report — which tools were
# present, which cells could not run here, what the run "cannot prove". That was written for
# a world where the suite ran on a developer's Mac and in CI and in the image, and someone
# had to be told which of the three they were reading. The policy removed that world: the
# full harness runs in the production image, everything it needs is installed there, and
# nothing may skip. A report describing per-host differences is a description of a problem
# that should not exist, so it is gone. What remains is the identity the two rules need.

# The tier, taken from the IMAGE rather than from a caller. deploy/Dockerfile.test writes
# "test-image" and the Dockerfile's build stage writes "build-image"; anything else is
# somebody's own machine. A run therefore cannot claim a tier it is not in — which matters,
# because "test-image" is what makes a skip fatal and what lifts the off-image refusal.
env_id() { cat /etc/fastpki-test-env 2>/dev/null || echo host; }

# Does openssl load a pkcs11 provider RIGHT NOW, in this environment?
#
# ⚠️ ASKED, NOT INFERRED FROM $OPENSSL_CONF, because the dangerous state is the variable
# being UNSET. Homebrew ships a default /opt/homebrew/etc/openssl@3/openssl.cnf that loads a
# pkcs11 provider pointed straight at libsofthsm2.so, bypassing p11-kit-client.so — the
# in-process SoftHSM load tests/hsm_helpers.sh says DEADLOCKS, and a deadlock hangs rather
# than fails. Measured: `openssl list -providers` prints default + pkcs11 with the variable
# unset, and default alone with OPENSSL_CONF= empty. "Unset or empty" was never equivalent.
#
# Kept even though the full harness no longer runs off-image, because running ONE suite
# there still is supported and this still bites it.
env_pkcs11_in_default_conf() {
    local o="${OSSL:-openssl}"
    command -v "$o" >/dev/null 2>&1 || return 1
    "$o" list -providers 2>/dev/null | grep -qE '^[[:space:]]+pkcs11$'
}

env_banner() {
    local o="${OSSL:-openssl}"
    echo "==================================================================="
    printf 'ENVIRONMENT: %s   openssl %s   %s %s\n' \
        "$(env_id)" \
        "$("$o" version 2>/dev/null | awk '{print $2}')" \
        "$(uname -m)" "$(uname -s)"
    if env_pkcs11_in_default_conf; then
        echo "  ⚠️ openssl loads a pkcs11 provider from its DEFAULT config, pointed straight"
        echo "     at libsofthsm2.so — the in-process load hsm_helpers.sh says deadlocks."
        echo "     Fix for this shell:  export OPENSSL_CONF="
        echo "     (UNSETTING it is not enough: unset falls back to that very file.)"
    fi
    echo "==================================================================="
}
