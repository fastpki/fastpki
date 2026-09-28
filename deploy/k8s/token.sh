#!/bin/sh
# The SoftHSM token server of ONE fastpki-node pod — deploy/docker-compose.yml's `token` service,
# in Kubernetes. It runs as a sidecar of the pod's init sequence, so the socket exists before
# certgen mints this pod's transport keypair in it and before any service opens it.
#
# ⚠️ ONE PER SERVER, AND NEVER ONE FOR THE WHOLE DEPLOYMENT. Every node has its own token, in
# every deployment shape (docs/architecture.md §4): a deployment whose keys live in one token
# loses every key with the node that holds it, however its storage is arranged. So each pod owns
# a token on its own claim, and a CA key reaches the other pods by being REPLICATED into their
# tokens over P11_TLS (`fastpki-ca key sync`, run by every server's renewal loop). The earlier
# manifests ran one token Deployment for the whole cluster, and that is the defect this shape removes.
#
# ⚠️ THE PKCS#11 MODULE MUST NOT RUN INSIDE THE APPLICATION PROCESS. p11-kit's SoftHSM provider
# re-enters libcrypto, and an in-process module deadlocks against the app's own OpenSSL. So the
# app links p11-kit-client.so and talks over a socket to THIS process, which owns the provider.
#
# The socket lives on an emptyDir that only this pod's containers mount. p11-kit's RPC has no
# TCP transport, and nothing outside the pod needs it: another server reaches this token only
# through the mutually authenticated p11-tls container, and only to replicate a key.
set -eu

SOCK=/run/p11/pkcs11.sock
TOK=/var/lib/softhsm/tokens
mkdir -p /run/p11 "$TOK"

export SOFTHSM2_CONF=/run/p11/softhsm2.conf
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$TOK" > "$SOFTHSM2_CONF"

# ⚠️ NEVER A DEFAULT PIN. The token holds every CA private key this server has, so initialising
# it under a guessable PIN would hand that decision to whoever knows the default.
: "${FASTPKI_PIN:?token: FASTPKI_PIN is not set — apply.sh generates one into the Secret}"

# Idempotent: a token that already exists is left alone, so a pod restart does not try to
# re-initialise a token that already holds keys.
if ! softhsm2-util --show-slots 2>/dev/null | grep -qi 'label:.*fastpki'; then
    softhsm2-util --init-token --free --label fastpki \
        --so-pin "${SOFTHSM_SO_PIN:-$FASTPKI_PIN}" --pin "$FASTPKI_PIN"
    echo "token: initialised token 'fastpki'"
else
    echo "token: token 'fastpki' already present"
fi

# A socket left by an unclean stop makes the bind fail and the sidecar restart into the same
# error for ever.
[ -S "$SOCK" ] && rm -f "$SOCK"
echo "token: serving the token on $SOCK (connectable by the fastpki user)"
exec /usr/libexec/p11-kit/p11-kit-server -f -n "$SOCK" -u fastpki \
    --provider /usr/lib/softhsm/libsofthsm2.so "pkcs11:"
