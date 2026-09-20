#!/usr/bin/env bash
# deploy/lab-test.sh — run the FULL suite on a lab DC, inside a container built from the
# SHIPPED image. This is the "does it work on what we ship?" run; the Mac run is the
# "is the logic right?" run. The block below says why both have to exist.
#
# ⚠️ WHY THIS IS NOT DUPLICATION OF THE MAC RUN.
#   this Mac : arm64, macOS, OpenSSL 3.6.3, no root, no p11-kit sidecar
#   we ship  : x86_64, musl/Alpine 3.24, OpenSSL 3.5.7, root, sidecar running
# A minor OpenSSL version apart on a product that is nothing but OpenSSL — and macOS
# genuinely cannot sign with an EC SoftHSM key through the pkcs11 provider while Linux can.
# Six suites (hsm_sidecar, ldap, saml, acme_lifecycle, acme_eab, lab_replication_mesh)
# never ran ANYWHERE before this: the Mac skips them and nothing else was running them.
#
#   ./lab-test.sh                       # on a DC, from deploy/
#   LAB_DC=<node-address> ./lab-test.sh    # or drive it over SSH from anywhere
#
# It builds a throwaway test image FROM the deployed one, adding only what the harness
# needs (postgres server binaries, softhsm2, openldap, xmlsec1). The product binaries,
# libc and OpenSSL are the shipped ones — that is the entire point, so never `apt install`
# a different OpenSSL here.
set -eu

HERE="$(cd "${0%/*}" && pwd)"
# The image comes from this node's own untracked .env (the same file compose reads), or
# from the per-site lab file when driving from a workstation. Neither is tracked, so the
# repository names no registry of ours — and the value the suite tests is the value the
# node actually runs, rather than a default in a script that can drift from it.
# ⚠️ DO NOT `.` THE COMPOSE .env — IT IS NOT A SHELL SCRIPT. Compose accepts an unquoted
# value containing spaces, which is ordinary in that file; the shell reads the same line as
# an assignment followed by a COMMAND. Measured on a DC: `PG_CONNINFO=host=db port=5432`
# made this script die with `email: command not found` before it ran a single suite, and the
# gate reported "no suite failed" against an EMPTY log — an environment change on one node
# silently disabling the whole in-image tier.
#
# Only one value is wanted here, so read that one key rather than executing the file. An
# explicit FASTPKI_IMAGE in the environment wins: the deploy passes the image it just rolled,
# and a stale line in .env must not override what the caller asked to test.
if [ -z "${FASTPKI_IMAGE:-}" ] && [ -r "$HERE/.env" ]; then
    FASTPKI_IMAGE="$(sed -n 's/^[[:space:]]*FASTPKI_IMAGE=//p' "$HERE/.env" | head -1)"
fi
# nodes.env is ours and shell-shaped by construction, so sourcing it is fine.
[ -r "$HERE/lab/nodes.env" ]   && . "$HERE/lab/nodes.env"
IMAGE="${FASTPKI_IMAGE:-${LAB_REGISTRY:+$LAB_REGISTRY/fastpki:latest}}"
if [ -z "$IMAGE" ]; then
    echo "ERR: no image to test. Set FASTPKI_IMAGE, or put it in deploy/.env," >&2
    echo "     or set LAB_REGISTRY in deploy/lab/nodes.env (see nodes.env.example)." >&2
    exit 2
fi
TESTIMG="fastpki-labtest:local"
LAB_USER="${LAB_SSH_USER:-admin}"

# Driving it from a workstation: re-exec the whole thing on the DC. Only THIS path needs
# to know the account and where its deploy tree sits.
if [ -n "${LAB_DC:-}" ]; then
    KEY="${LAB_SSH_KEY:-$HOME/.ssh/fastpki_lab_ed25519}"
    RREPO="${FASTPKI_REPO:-/home/$LAB_USER/FastPKI}"
    echo "== running the full suite on $LAB_DC, in the shipped image =="
    exec ssh -i "$KEY" -o StrictHostKeyChecking=no "$LAB_USER@$LAB_DC" \
        "cd $RREPO/deploy && sudo -E FASTPKI_IMAGE=$IMAGE bash ./lab-test.sh"
fi

# Running ON the node (this is how rolling-update.sh calls it): the tree is wherever this
# script is, whoever owns it. No path assumption to get wrong, so the deploy hook cannot
# break because someone keeps the checkout somewhere else.
REPO="${FASTPKI_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"

command -v docker >/dev/null 2>&1 || { echo "FAIL: docker is required (run this ON a DC)"; exit 2; }
[ -d "$REPO/tests" ] || { echo "FAIL: no test tree at $REPO/tests — set FASTPKI_REPO"; exit 2; }

# ⚠️ REFUSE TO BUILD ONTO A NEARLY-FULL DISK, AND SWEEP THE CACHE THAT FILLS IT.
#
# Measured: four image builds in one day left 12.94 GB of docker BUILD CACHE on the build
# node. `/` hit 100%, and PostgreSQL did not degrade — it PANICked mid-checkpoint:
#
#   PANIC: could not write to file "pg_logical/replorigin_checkpoint.tmp": No space left on device
#   checkpointer process was terminated by signal 6: Aborted
#   ... database system is in recovery mode        <- crash loop, DC effectively down
#
# Every build layer is regenerable, so the cache is the one thing here that is safe to
# delete and the only thing that grows without bound. `docker builder prune` touches build
# cache ONLY.
#
# ⚠️ NEVER `docker system prune --volumes` or `docker volume prune` on a DC: the volumes
# include softhsm-tokens, which holds every CA private key. There is no backup of a token.
BUILD_CACHE_KEEP="${BUILD_CACHE_KEEP:-4GB}"
_free_pct=$(df -P / | awk 'NR==2 {gsub(/%/,"",$5); print 100-$5}')
if [ "${_free_pct:-100}" -lt 25 ]; then
    echo "== only ${_free_pct}% of / is free — pruning docker build cache before building =="
    docker builder prune -af --filter "until=1h" >/dev/null 2>&1 || true
    _free_pct=$(df -P / | awk 'NR==2 {gsub(/%/,"",$5); print 100-$5}')
    echo "   ${_free_pct}% free after the prune"
fi
if [ "${_free_pct:-100}" -lt 10 ]; then
    echo "FAIL: only ${_free_pct}% of / is free even after pruning the build cache."
    echo "      Building now risks a Postgres PANIC mid-checkpoint and a crash-looping DC."
    df -h / | tail -1
    docker system df
    exit 2
fi

# ── hand over to the canonical runner ────────────────────────────────────────────────
# Everything above is what makes this a LAB script: the site's image name, the SSH re-exec
# onto a DC, and the disk guard for a node that runs Postgres beside the build. The run
# itself is not lab-specific and lives in tests/run-in-container.sh, so a developer gets
# the same environment with no lab configuration at all.
#
# The old LAB_TEST_SUITE / LAB_TEST_ENV names are gone rather than aliased: the mechanism
# was never lab-specific, and this repo does not keep compatibility shims.
if [ -n "${LAB_TEST_SUITE:-}${LAB_TEST_ENV:-}" ]; then
    echo "lab-test.sh: LAB_TEST_SUITE / LAB_TEST_ENV have been renamed." >&2
    echo "             Use FASTPKI_TEST_SUITE / FASTPKI_TEST_ENV instead." >&2
    exit 2
fi
# ⚠️ THE SUITE NEEDS A SECOND IMAGE, AND THE REGISTRY DOES NOT CARRY IT. The SCEP and CMP
# test clients were moved out of the shipped image into the `testtools` stage — a production
# image must not carry a client that can enrol — and run-in-container.sh refuses to start
# without `<name>-testtools:<tag>`. deploy/build-image.sh builds both, but a DC runs an image
# PULLED from the local registry, where only the runtime half was ever pushed. So build the
# companion here, from the checkout this script is already running out of.
_ti_name="$IMAGE" _ti_tag=""
case "${IMAGE##*/}" in
    *:*) _ti_tag="${IMAGE##*:}"; _ti_name="${IMAGE%:*}" ;;
esac
TOOLS_IMAGE="${FASTPKI_TOOLS_IMAGE:-${_ti_name}-testtools${_ti_tag:+:$_ti_tag}}"
if ! docker image inspect "$TOOLS_IMAGE" >/dev/null 2>&1; then
    echo "== building $TOOLS_IMAGE — the registry carries only the runtime image =="
    docker build --target testtools -t "$TOOLS_IMAGE" "$REPO" || {
        echo "FAIL: could not build the test-tools image $TOOLS_IMAGE" >&2
        echo "      The suite cannot run without it; see deploy/build-image.sh." >&2
        exit 2; }
fi

exec env FASTPKI_IMAGE="$IMAGE" bash "$REPO/tests/run-in-container.sh" "$@"
