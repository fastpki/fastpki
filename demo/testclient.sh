# demo/testclient.sh — make the enrolment test clients usable on a driver that has no build.
#
# ⚠️ THEY CANNOT SIMPLY BE COPIED ONTO A HOST. `scep-testclient` and
# `cmp-testclient` live in the `-testtools` image stage, deliberately: a shipped runtime
# image must not carry a client that can enrol. They are musl binaries, so copying one onto
# a glibc host fails at exec with `cannot execute: required file not found` — which reads
# like a corrupt download rather than the wrong libc.
#
# That left no single driver able to exercise every protocol against a live deployment: a
# workstation has the build but no privileged ports for ACME's http-01/tls-alpn-01, and a
# deployment host has the ports but no build. So when the binary is absent and docker is
# there, run it FROM an image.
#
# ⚠️ THE `-testtools` IMAGE IS A CARRIER, NOT A RUNTIME. Its binaries are `COPY --from`'d
# into the test image by deploy/Dockerfile.test, which is where the shared libraries are;
# running one in the carrier itself fails with `Error loading shared library libldap.so.2`.
# So this builds a one-layer image — the deployment's own runtime, plus the client copied
# in — and caches it under a fixed tag. It is rebuilt only when that tag is absent.
#
# ⚠️ THE WORKING DIRECTORY IS MOUNTED AT THE SAME PATH INSIDE. Every argument these clients
# take is a path to a file the caller just wrote (scep-ca.pem, scep.key, scep-req.der …), so
# a container that sees them at a different path cannot open them, and `docker run` resolves
# a -v source on the HOST — mounting the caller's $PWD at $PWD is what makes both ends agree.

# _tc_runtime_image — the image whose libraries the client needs. The deployment's own.
_tc_runtime_image() {
    if [ -n "${FASTPKI_IMAGE:-}" ]; then printf '%s' "$FASTPKI_IMAGE"; return 0; fi
    local envf
    for envf in "${ROOT:-.}/deploy/.env" ./deploy/.env ../deploy/.env; do
        [ -f "$envf" ] || continue
        local v; v=$(sed -n 's/^FASTPKI_IMAGE=//p' "$envf" | head -1)
        [ -n "$v" ] && { printf '%s' "$v"; return 0; }
    done
    docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null \
      | grep -E '(^|/)fastpki(-[a-z]+)?:' | grep -v -- '-testtools:' | grep -v '<none>' | head -1
}

# ensure_testclient <name> [bin-dir]  -> 0 if $bin/<name> is runnable afterwards
#
# ⚠️ SAYS WHY IT COULD NOT, IN $TESTCLIENT_WHY. Every failure below used to be a bare
# `return 1`, and the caller reported all of them as "no <name> in <bin>" — which is true and
# useless, because the build directory is rarely the problem. Measured: a host with a
# -testtools image, a working democlients image and docker running was told to build a client,
# when the actual cause was `deploy/.env` naming a release image that host did not have.
# Setting FASTPKI_IMAGE fixed it in one line, and nothing in the output pointed there.
TESTCLIENT_WHY=""
ensure_testclient() {
    local name="$1" bin="${2:-${BIN:-}}"
    TESTCLIENT_WHY=""
    [ -n "$bin" ] || { TESTCLIENT_WHY="no bin directory was given"; return 1; }
    # ⚠️ A SHIM OUTLIVES THE IMAGE IT NAMES. The generated one below hard-codes a tag that is
    # a checksum of the (runtime, tools) pair, so it changes whenever either is rebuilt —
    # constantly, on a machine that runs the suites. build/ is not cleaned between runs, so
    # the stale shim is simply found and used: `docker run` fails on the missing image, the
    # client writes no output file, and the next step reports
    #     curl: option --data-binary: error encountered when reading a file
    # naming neither the shim nor the image. Validate it and regenerate instead.
    if [ -x "$bin/$name" ]; then
        local _img
        _img=$(sed -n 's/.*--entrypoint '"$name"' \([^ ]*\) .*/\1/p' "$bin/$name" 2>/dev/null | head -1)
        case "$_img" in
            '') return 0 ;;    # a real binary, not one of our shims
            *)  docker image inspect "$_img" >/dev/null 2>&1 && return 0
                echo "  the $name shim names $_img, which is gone — regenerating" >&2
                rm -f "$bin/$name" ;;
        esac
    fi
    command -v docker >/dev/null 2>&1 || {
        TESTCLIENT_WHY="docker is not on PATH, so the client cannot be run from an image"
        return 1; }
    docker info >/dev/null 2>&1 || {
        TESTCLIENT_WHY="docker is installed but not answering (is the daemon running?)"
        return 1; }

    local tools="${FASTPKI_TOOLS_IMAGE:-}"
    if [ -z "$tools" ]; then
        tools=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null \
                | grep -- '-testtools:' | grep -v '<none>' | head -1)
    fi
    [ -n "$tools" ] || {
        TESTCLIENT_WHY="no -testtools image on this host (the clients live in that stage; \
build it with FASTPKI_BUILD_IMAGE=1 tests/run-in-container.sh, or set FASTPKI_TOOLS_IMAGE)"
        return 1; }
    docker image inspect "$tools" >/dev/null 2>&1 || {
        TESTCLIENT_WHY="the tools image '$tools' is named but not present on this host"
        return 1; }

    local runtime; runtime=$(_tc_runtime_image)
    [ -n "$runtime" ] || {
        TESTCLIENT_WHY="could not tell which runtime image to build the client against \
(set FASTPKI_IMAGE, or put FASTPKI_IMAGE= in deploy/.env)"
        return 1; }
    # ⚠️ THE CASE THAT ACTUALLY HAPPENS. deploy/.env names a release image, the host has moved
    # to another release candidate, and the inspect fails — on a machine that has everything
    # else it needs. Name the image and the override, because the fix is one variable.
    docker image inspect "$runtime" >/dev/null 2>&1 || {
        TESTCLIENT_WHY="the runtime image '$runtime' is not on this host — it comes from \
FASTPKI_IMAGE or deploy/.env; set FASTPKI_IMAGE to one you have (docker images | grep fastpki)"
        return 1; }

    # One image per (runtime, tools) pair, so a re-run is free and a changed deployment
    # image rebuilds rather than silently reusing a client from the previous one.
    local tag="fastpki-democlients:$(printf '%s|%s' "$runtime" "$tools" | cksum | cut -d' ' -f1)"
    if ! docker image inspect "$tag" >/dev/null 2>&1; then
        printf 'FROM %s\nCOPY --from=%s /usr/local/bin/%s /usr/local/bin/%s\n' \
               "$runtime" "$tools" "$name" "$name" \
          | docker build -q -t "$tag" -f - . >/dev/null 2>&1 || {
            TESTCLIENT_WHY="could not build the client image from '$runtime' + '$tools'"
            return 1; }
    fi
    docker run --rm --entrypoint sh "$tag" -c "command -v $name" >/dev/null 2>&1 || {
        TESTCLIENT_WHY="'$name' is not in the tools image '$tools'"
        return 1; }

    mkdir -p "$bin" 2>/dev/null || return 1
    cat > "$bin/$name" <<SHIM
#!/bin/sh
# GENERATED by demo/testclient.sh — runs $name from $tag, because this host has no build.
# Delete it, or build the real binary over it, to go back to a local client.
exec docker run --rm -i --user "\$(id -u):\$(id -g)" -v "\$PWD:\$PWD" -w "\$PWD" --entrypoint $name $tag "\$@"
SHIM
    chmod +x "$bin/$name" 2>/dev/null || return 1
    echo "  using $name from $tag (no local build on this host)" >&2
    return 0
}
