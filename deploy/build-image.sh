#!/bin/sh
# Build the FastPKI image from a tree that has passed the public-repo hygiene gate.
#
# WHY THIS IS NOT A STEP INSIDE THE DOCKERFILE. The natural place to put a "check the tree,
# then build" gate is the build stage — install git, run the check, then cmake. It cannot
# go there, and the reason is a fact about the build CONTEXT rather than about git:
#
#   .dockerignore excludes .git/, so the tree the builder sees is NOT A REPOSITORY.
#
# The hygiene suite's claim is about the TRACKED file set — what a fresh clone would carry,
# which is precisely what "before the repo goes public" means. Without .git there is no
# tracked set: there is only "files that happened to be in the context", which is a
# different population in both directions. .dockerignore removes some, and any untracked
# scratch file sitting in a working tree would be scanned as though it shipped.
#
# Un-ignoring .git/ to fix that would put the whole history into the build context and into
# a builder layer, to answer a question the host can answer for free — the repository is
# right here.
#
# So the gate runs HERE, before docker is invoked, and the image cannot be built from a
# tree that fails it. The final image is unaffected either way: it is a separate stage that
# copies binaries, so no git and no history reach it.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
IMAGE="${IMAGE:-fastpki:local}"
# Overridable so the gate itself can be tested with a check that fails on purpose. Not a
# security control -- anyone who can set this can run `docker build` directly, which the
# note above already says is theirs to decide.
HYGIENE="${HYGIENE:-$ROOT/tests/public_repo_hygiene.sh}"

echo "==> public-repo hygiene (the tree, before it becomes an image)" >&2
if ! sh "$HYGIENE"; then
    echo "FAIL: the tree does not pass the public-repo hygiene gate — not building." >&2
    echo "      Fix the findings above, or build with docker directly if you know why." >&2
    exit 1
fi

# ⚠️ TWO IMAGES, and the second is not shipped anywhere. The `testtools` stage carries
# scep-testclient and cmp-testclient, which the suites need and a production image must not
# have. Built first so a failure there is not mistaken for a runtime-image failure; tagged
# from IMAGE so the pair always match.
# ⚠️ SPLIT ON THE TAG, NOT ON THE FIRST COLON — a registry-qualified name carries a port,
# and `${IMAGE%%:*}` turns `registry.example.org:5000/fastpki:latest` into
# `registry.example.org-testtools:5000/fastpki:latest`. Must match
# tests/run-in-container.sh, which derives the same name to look the image up.
_ti_name="$IMAGE" _ti_tag=""
case "${IMAGE##*/}" in
    *:*) _ti_tag="${IMAGE##*:}"; _ti_name="${IMAGE%:*}" ;;
esac
TOOLS_IMAGE="${TOOLS_IMAGE:-${_ti_name}-testtools${_ti_tag:+:$_ti_tag}}"
echo "==> docker build --target testtools -t $TOOLS_IMAGE" >&2
docker build --target testtools -t "$TOOLS_IMAGE" "$@" "$ROOT" || exit 1

echo "==> docker build -t $IMAGE" >&2
exec docker build -t "$IMAGE" "$@" "$ROOT"
