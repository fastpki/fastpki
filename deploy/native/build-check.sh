#!/bin/sh
# deploy/native/build-check.sh — run the cloud image's BAKE locally, in a throwaway
# container, and prove it works before spending anything in a cloud account.
#
#   ./build-check.sh                 # bake HEAD in a throwaway Alpine container
#   ./build-check.sh --ref v1.0.0    # bake a specific ref
#   ./build-check.sh --keep          # leave the container behind to poke at
#   ./build-check.sh --image fastpki-baked:local   # commit the result, for run-check.sh
#   ./build-check.sh --ref v1.0.0 --package fastpki-native-v1.0.0.tar.gz
#                                    # the files the bake installed, to update a cloud node
#
# ── WHY THIS EXISTS ───────────────────────────────────────────────────────────────────
#
# The AMI bake is a twenty-minute EC2 round trip, and nearly everything that can go wrong
# in it has nothing to do with EC2: a patch that stopped applying against a new upstream
# commit, p11-kit no longer relaying ML-DSA, a compile error, a binary that cannot print
# its own usage. Every one of those is answerable on a developer machine for free, and
# discovering them from a failed cloud build costs twenty minutes and an instance-hour
# each time.
#
# So the rule this supports is: build locally on every change, and build in the cloud only
# when there is a release to pin an image to.
#
# ⚠️ IT RUNS deploy/cloud/image/provision.sh — THE REAL ONE, NOT A COPY. A local check
# that asserts the same things through a second script is a check that can pass while the
# real bake fails, which is the drift problem the Dockerfile pin extraction already exists
# to prevent. provision.sh skips exactly two steps under FASTPKI_BAKE_LOCAL=1, both of
# them about a machine that boots (enabling crond in a runlevel, and asserting the base
# image can receive user-data). A container has no init and no cloud-init, so neither is
# answerable here; nothing else differs.
#
# ── WHAT IT CANNOT TELL YOU ───────────────────────────────────────────────────────────
#
# It does not boot anything. cloud-init, the bootloader and the OpenRC services actually
# starting under a real init are outside its reach — and outside the EC2 bake's reach too,
# because the bake never starts a service either. Those are asserted one step further on,
# locally: deploy/cloud/image/build-qemu.sh emits the same image as a bootable disk and
# deploy/cloud/boot-check.sh boots it. Only the AWS hardware surface — the ENA and NVMe
# drivers — and AMI registration genuinely need a running instance.
set -eu

case "$0" in
    */*) HERE="$(cd "${0%/*}" && pwd)" ;;
    *)   HERE="$(pwd)" ;;
esac
ROOT="$(cd "$HERE/../.." && pwd)"

REF=HEAD
KEEP=0
IMAGE=""
PACKAGE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --ref) REF="${2:?--ref needs a git ref}"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        # Commit the finished container as an image, so run-check.sh can BOOT it instead
        # of baking again. Same split as the cloud: bake once, configure many.
        --image) IMAGE="${2:?--image needs a tag}"; shift 2 ;;
        # Package what the bake installed, for a node that is already running: it has no
        # toolchain and often no internet, so it installs the result rather than building.
        --package) PACKAGE="${2:?--package needs an output file}"; shift 2 ;;
        -h|--help) sed -n '2,42p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

command -v docker >/dev/null 2>&1 || { echo "build-check: docker is not on PATH" >&2; exit 1; }
command -v git    >/dev/null 2>&1 || { echo "build-check: git is not on PATH" >&2; exit 1; }

# ⚠️ THE ALPINE VERSION COMES FROM THE DOCKERFILE, not from a constant here and not from
# the Packer template's default. The container image is the tested surface: baking against
# a different Alpine release would build the binaries against a different libc and a
# different OpenSSL from the ones the suite ran against, and the whole value of a local
# check is that it is the same build.
ALPINE="$(sed -n 's/^FROM alpine:\([0-9][0-9.]*\).*/\1/p' "$ROOT/Dockerfile" | head -1)"
[ -n "$ALPINE" ] || { echo "build-check: could not read the Alpine version from $ROOT/Dockerfile" >&2; exit 1; }

# ⚠️ PARALLELISM IS SIZED BY MEMORY, NOT BY CPU COUNT. Docker Desktop gives its VM a
# memory limit unrelated to the host's core count, and it is shared with every other
# container running at the time. Compiling FastPKI's console needs well over a gigabyte on
# its own, so -j<cores> on a small VM is an OOM kill twenty minutes in, reported as a
# compiler that "crashed" — the least informative way this can fail. One job per 1.5 GB,
# capped at the CPU count, and never below one.
DOCKER_MEM="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
DOCKER_CPU="$(docker info --format '{{.NCPU}}' 2>/dev/null || echo 2)"
if [ "$DOCKER_MEM" -gt 0 ] 2>/dev/null; then
    JOBS=$(( DOCKER_MEM / 1610612736 ))
    [ "$JOBS" -lt 1 ] && JOBS=1
    [ "$JOBS" -gt "$DOCKER_CPU" ] && JOBS="$DOCKER_CPU"
else
    JOBS=2
fi
[ -n "${FASTPKI_BUILD_JOBS:-}" ] && JOBS="$FASTPKI_BUILD_JOBS"

COMMIT="$(git -C "$ROOT" rev-parse --short "$REF")"
NAME="fastpki-bake-check-$COMMIT"
echo "==> baking $REF ($COMMIT) on alpine:$ALPINE" >&2
echo "    this compiles pkcs11-provider, p11-kit, SoftHSM and FastPKI — expect 15-30 min" >&2
echo "    -j$JOBS (docker: ${DOCKER_CPU} CPUs, $(( DOCKER_MEM / 1073741824 ))GB; override with FASTPKI_BUILD_JOBS)" >&2

# Same source delivery as the AMI bake: `git archive`, the tracked set and nothing a
# working directory happens to be carrying. Piped straight in rather than written to a
# file, so a failed run leaves nothing behind.
docker rm -f "$NAME" >/dev/null 2>&1 || true

# ⚠️ AN INTERRUPT MUST TAKE THE CONTAINER WITH IT. Without this, Ctrl-C (or anything that
# kills the parent shell) leaves a container compiling four C/C++ projects at full tilt
# with nobody left to read its result or commit its image — it cannot produce anything
# usable, and it holds CPU and gigabytes of RAM until someone notices. Observed exactly
# once, which is once more than it needs to be.
interrupted() {
    echo >&2
    echo "build-check: interrupted — removing $NAME" >&2
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    exit 130
}
trap interrupted INT TERM HUP

start=$(date +%s)
set +e
git -C "$ROOT" archive --format=tar "$REF" \
  | docker run -i --name "$NAME" \
        -e FASTPKI_BAKE_LOCAL=1 \
        -e "JOBS=$JOBS" \
        -e "FASTPKI_RELEASE=$COMMIT-local" \
        "alpine:$ALPINE" sh -ec '
            mkdir -p /tmp/fastpki-src
            tar x -C /tmp/fastpki-src
            # provision.sh expects the archive as a tarball at this path, exactly as the
            # file provisioner delivers it in the cloud build.
            tar czf /tmp/fastpki-src.tar.gz -C /tmp/fastpki-src .
            exec sh /tmp/fastpki-src/deploy/cloud/image/provision.sh
        '
rc=$?
set -e
end=$(date +%s)
mins=$(( (end - start) / 60 ))

if [ "$rc" -eq 0 ] && [ -n "$IMAGE" ]; then
    docker commit "$NAME" "$IMAGE" >/dev/null
    echo "==> committed the baked filesystem as $IMAGE" >&2
fi

# ⚠️ ONLY AFTER THE BAKE PASSED, AND ONLY WHAT IT INSTALLED. provision.sh has just proved
# these exact files — the patched stack relays ML-DSA and EdDSA, every binary prints its
# usage — so the package is the verified result, not a second build. The list is the
# manifest build-native.sh writes as it installs; the token store and /etc/softhsm2.conf
# are deliberately not in it, because on a node they are the node's own.
if [ "$rc" -eq 0 ] && [ -n "$PACKAGE" ]; then
    PKG_IMAGE="$NAME-package"
    docker commit "$NAME" "$PKG_IMAGE" >/dev/null
    if docker run --rm --entrypoint sh "$PKG_IMAGE" -ec \
           'cd / && tar czf - -T usr/share/fastpki/installed-files etc/fastpki-release' \
           > "$PACKAGE"; then
        echo "==> packaged $(docker run --rm --entrypoint sh "$PKG_IMAGE" -c 'wc -l < /usr/share/fastpki/installed-files') paths as $PACKAGE" >&2
    else
        rm -f "$PACKAGE"
        echo "build-check: packaging failed" >&2
        rc=1
    fi
    docker rmi "$PKG_IMAGE" >/dev/null 2>&1 || true
fi
if [ "$KEEP" = 1 ]; then
    echo "==> container kept as $NAME (docker exec -it $NAME sh)" >&2
else
    docker rm -f "$NAME" >/dev/null 2>&1 || true
fi

echo >&2
if [ "$rc" -eq 0 ]; then
    echo "BAKE CHECK: PASS ($COMMIT, ${mins}m)" >&2
    echo "  The patched PKCS#11 stack relays ML-DSA and EdDSA, every binary built and" >&2
    echo "  prints its usage without a database. What this did NOT test: booting —" >&2
    echo "  cloud-init and OpenRC supervising the services. For that, next:" >&2
    echo "    deploy/cloud/image/build-qemu.sh && deploy/cloud/boot-check.sh" >&2
else
    echo "BAKE CHECK: FAIL ($COMMIT, ${mins}m, exit $rc)" >&2
    echo "  Do not run 'packer build' — it would fail the same way, twenty minutes and an" >&2
    echo "  instance-hour later. Re-run with --keep to inspect the container." >&2
fi
exit "$rc"
