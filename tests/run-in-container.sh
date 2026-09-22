#!/usr/bin/env bash
# Run the harness against the image we SHIP, which is the only place the patched PKCS#11
# stack exists.
#
#   tests/run-in-container.sh                      # needs FASTPKI_IMAGE, or:
#   FASTPKI_BUILD_IMAGE=1 tests/run-in-container.sh
#   FASTPKI_TEST_SUITE=web_ca_hsm.sh tests/run-in-container.sh
#
# ⚠️ WHY THIS EXISTS AT ALL. A macOS run and the CI fast lane both drive an UNPATCHED
# token: Alpine's p11-kit drops CKM_ML_DSA and CKM_EDDSA in its RPC relay, its SoftHSM has
# no ML-DSA, and neither honours CKA_ALLOWED_MECHANISMS on an RSA private key. Every cell
# that needs those SKIPS, and a skip still prints ALL GREEN. Only the runtime image carries
# all three patches, so only this run can prove those paths.
#
# It was deploy/lab-test.sh, which reads as a lab tool and is therefore not run. The lab
# specifics — the site's image name, the SSH re-exec, the DC disk guard — stayed there;
# everything a developer needs is here and needs no lab.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
TESTIMG="${FASTPKI_TEST_IMAGE:-fastpki-test:local}"

# ── which image is under test ────────────────────────────────────────────────────────
IMAGE="${FASTPKI_IMAGE:-}"
# ⚠️ BOTH SET IS A CONTRADICTION, AND IT USED TO RESOLVE SILENTLY. FASTPKI_IMAGE names an
# image that already exists; FASTPKI_BUILD_IMAGE asks for one to be built from this tree.
# With both, the build was skipped and whatever that tag pointed at was tested — which is
# how a run reported 248 passed against an image whose binaries predated the source by two
# hours: three suites failed for the only honest reason available to them, that the CLI
# subcommand they exercise did not exist in the image. A stale image is the one thing this
# harness must never test quietly, so say so and stop.
if [ -n "$IMAGE" ] && [ "${FASTPKI_BUILD_IMAGE:-0}" = "1" ]; then
    echo "run-in-container.sh: FASTPKI_IMAGE=$IMAGE and FASTPKI_BUILD_IMAGE=1 contradict." >&2
    echo "  FASTPKI_IMAGE tests an image that already exists; FASTPKI_BUILD_IMAGE builds one" >&2
    echo "  from this tree. Pass exactly one — otherwise the build is skipped and the run" >&2
    echo "  proves whatever that tag happens to point at, which may be older than your code." >&2
    exit 2
fi
if [ -z "$IMAGE" ]; then
    if [ "${FASTPKI_BUILD_IMAGE:-0}" = "1" ]; then
        IMAGE=fastpki:local
        # ⚠️ Through build-image.sh, NEVER a bare `docker build`. That wrapper runs the
        # public-repo hygiene gate on the HOST first, and the host is the only place it CAN
        # run: .dockerignore excludes .git/, so the build context is not a repository.
        # tests/build_image_gated.sh exists to stop exactly this being bypassed.
        echo "== building $IMAGE (via deploy/build-image.sh, so the hygiene gate runs) =="
        IMAGE="$IMAGE" sh "$ROOT/deploy/build-image.sh"
    else
        cat >&2 <<'EOF'
run-in-container.sh: no image to test against.

  This runs the harness against the image we SHIP — the patched p11-kit, the patched
  SoftHSM and the shipped libcrypto live there and nowhere else. It will not silently
  invent one: the runtime build takes 15-25 minutes.

    FASTPKI_BUILD_IMAGE=1 tests/run-in-container.sh   # build fastpki:local first
    FASTPKI_IMAGE=<ref>   tests/run-in-container.sh   # test an image you already have
    deploy/lab-test.sh                                # on a DC: read it from deploy/.env
EOF
        exit 2
    fi
fi

command -v docker >/dev/null 2>&1 || { echo "run-in-container.sh: docker is required" >&2; exit 2; }
[ -d "$ROOT/tests" ] || { echo "run-in-container.sh: no test tree at $ROOT/tests" >&2; exit 2; }

# ⚠️ PRE-FLIGHT ON THE HOST: does deploy/docker-compose.yml still parse?
#
# tests/install_wizard.sh used to ask `docker compose config` from inside the suite, which
# meant it skipped everywhere docker was absent — i.e. in the very image the harness runs
# in. Handing that container the host docker socket to fix it would give a large shell
# harness control of the host daemon, which for a PKI is not a trade worth making. So the
# check runs HERE, where docker already is, and refuses the run rather than skipping it.
# deploy/build-image.sh runs the public-repo hygiene gate on the host for the same reason.
if command -v docker >/dev/null 2>&1; then
    if ! docker compose -f "$ROOT/deploy/docker-compose.yml" config >/dev/null 2>&1; then
        echo "run-in-container.sh: deploy/docker-compose.yml does not parse." >&2
        docker compose -f "$ROOT/deploy/docker-compose.yml" config 2>&1 | tail -5 >&2
        exit 1
    fi
fi

echo "== building the test image from $IMAGE =="
# ⚠️ TOOLS is the image holding scep-testclient and cmp-testclient. They are deliberately
# NOT in the runtime image — a production image must not carry a client that can enrol — so
# the test image pulls them from the `testtools` stage that deploy/build-image.sh tags
# alongside it. Derived from IMAGE so the pair always match.
#
# ⚠️ SPLIT ON THE TAG, NOT ON THE FIRST COLON. A registry-qualified name carries a PORT —
# `registry.example.org:5000/fastpki:latest` is a shape a deployment really uses — and
# `${IMAGE%%:*}` takes the HOST, producing a name nothing can ever match.
# A colon is a tag separator only when it appears after the last slash.
_ti_name="$IMAGE" _ti_tag=""
case "${IMAGE##*/}" in
    *:*) _ti_tag="${IMAGE##*:}"; _ti_name="${IMAGE%:*}" ;;
esac
TOOLSIMG="${FASTPKI_TOOLS_IMAGE:-${_ti_name}-testtools${_ti_tag:+:$_ti_tag}}"
if ! docker image inspect "$TOOLSIMG" >/dev/null 2>&1; then
    echo "run-in-container.sh: no test-tools image \"$TOOLSIMG\"." >&2
    echo "  It is built beside the runtime image: FASTPKI_BUILD_IMAGE=1 tests/run-in-container.sh," >&2
    echo "  or IMAGE=$IMAGE sh deploy/build-image.sh. Override with FASTPKI_TOOLS_IMAGE." >&2
    exit 1
fi
docker build -q -t "$TESTIMG" --build-arg BASE="$IMAGE" --build-arg TOOLS="$TOOLSIMG" \
    -f "$ROOT/deploy/Dockerfile.test" "$ROOT" >/dev/null

# ── how many shards: sized to the machine unless told otherwise ──────────────────────
#
# The default is DERIVED, not a constant. A hardcoded 1 made every developer wait 29
# minutes on a machine that can do it in four, and a hardcoded 6 would oversubscribe the
# 2-core runner CI actually uses — each shard is a container running its own Postgres and
# p11-kit, so more shards than cores costs more than it saves.
#
#   cores - 2, clamped to [1, 8]
#
# The two reserved cores are for the Docker daemon and this driver, which are doing real
# work while the shards run. The floor of 1 matters: it means a 2-core CI runner gets
# EXACTLY the sequential behaviour it had before, so this change cannot turn that gate red.
# The cap of 8 is where extra shards stop paying — the longest single suite is ~128s
# against ~1400s of total work, so beyond about eight shards the run is bounded by that
# suite and not by the fleet.
#
# ⚠️ SHARDING IS ONLY SAFE BECAUSE NO SUITE SLEEPS AT A SERVER ANY MORE (1bc0511 removed
# the last 73). Fixed sleeps and contention are the combination that produces failures
# which read as product bugs; two LDAP suites proved that before they were converted. If
# a fixed sleep is ever reintroduced next to a background start, expect it to fail here
# first and fail on the slowest machine worst.
#
# FASTPKI_JOBS overrides, and FASTPKI_JOBS=1 forces the old single-container run.
if [ -n "${FASTPKI_JOBS:-}" ]; then
    JOBS="$FASTPKI_JOBS"
else
    # getconf is POSIX and works on both macOS and Linux; nproc is Linux-only and busybox
    # has it, so it is the fallback rather than the primary. Anything unparseable means we
    # do not know the machine, and not knowing means one shard.
    _cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1)
    case "$_cores" in ''|*[!0-9]*) _cores=1 ;; esac
    JOBS=$(( _cores - 2 ))
    [ "$JOBS" -lt 1 ] && JOBS=1
    [ "$JOBS" -gt 8 ] && JOBS=8
    [ "$JOBS" -gt 1 ] && echo "== $_cores cores detected: running $JOBS shards (FASTPKI_JOBS=1 for one container) =="
fi
case "$JOBS" in ''|*[!0-9]*) echo "FASTPKI_JOBS must be a number (got '$JOBS')" >&2; exit 2 ;; esac

# ── network ─────────────────────────────────────────────────────────────────────────
# host on Linux: a DC run must reach the node's own services, and it is what the lab has
# always used. bridge on Darwin: Docker Desktop's host networking is opt-in and off by
# default, and on a laptop bridge is BETTER anyway — every suite binds a FIXED port in the
# 18000-18300 range, so host mode collides with whatever the developer is already running.
# Nothing in CORE/SMOKE/ROOT/PG needs the host's network: Postgres, the mock IdPs and
# dnsstub all come up INSIDE the container, and the ACME suites bind :80 in the container's
# own namespace.
case "$(uname -s)" in Darwin) _net_default=bridge ;; *) _net_default=host ;; esac
NET="${FASTPKI_TEST_NETWORK:-$_net_default}"
# ⚠️ SHARDING REQUIRES A PRIVATE NETWORK NAMESPACE, AND ON LINUX THE DEFAULT IS NOT ONE.
# `host` is the right default for a single DC run, but it puts every container in the
# HOST's namespace — so N shards would share one loopback and the fixed ports the suites
# bind would collide exactly as they do today. Sharding on host networking does not fail
# cleanly either: the second binder gets EADDRINUSE, or worse, one shard's client reaches
# another shard's server and asserts against it. So force bridge whenever we shard, and
# say so rather than silently overriding what the operator asked for.
if [ "$JOBS" -gt 1 ] && [ "$NET" = host ]; then
    echo "== sharding: using bridge networking, not host (shards need separate loopbacks) =="
    NET=bridge
fi

# ── what to run ─────────────────────────────────────────────────────────────────────
RUNCMD='bash tests/run_all.sh'
if [ -n "${FASTPKI_TEST_SUITE:-}" ]; then
    [ -f "$ROOT/tests/$FASTPKI_TEST_SUITE" ] || {
        echo "run-in-container.sh: no such suite: tests/$FASTPKI_TEST_SUITE" >&2; exit 1; }
    RUNCMD="bash tests/$FASTPKI_TEST_SUITE"
    echo "== SINGLE SUITE: $FASTPKI_TEST_SUITE — a probe, NOT a release gate =="
fi

# ⚠️ AN ARRAY, not a bare `for kv in $FASTPKI_TEST_ENV`. The old loop word-split on IFS, so
# FASTPKI_TEST_ENV="X=a b" became two -e flags and the second was not a variable at all.
ENVARGS=()
for kv in ${FASTPKI_TEST_ENV:-}; do ENVARGS+=(-e "$kv"); done

echo "== running the suite (network=$NET) =="
# ⚠️ MOUNT THE WHOLE REPO, not just tests/ and sql/. Mounting those two made 8 suites fail
# with "grep: src/lib/config.cpp: No such file or directory" — a whole class of them
# (docs_accurate, schema_version, certs_ca_columns, roles_permissions_schema,
# deploy_defaults_exist, mesh_publication_complete, p11kit_patch, install_protocol_choice)
# reads the SOURCE TREE to check that docs, schema and deploy files agree with the code.
# Those are not product failures; they are a harness that was never given the files.
#
# ⚠️ AND SHADOW build/ WITH A TMPFS. The harness resolves binaries as $ROOT/build/fastpki-*,
# and the repo mount buries whatever the image put there — so this used to symlink the
# container's binaries into the HOST's build/. That works on a DC, whose checkout is
# reset --hard on every deploy, and it is destructive on a laptop: it leaves the developer
# with a build/ full of symlinks to /usr/local/bin/fastpki-*, which exist only inside the
# container. Measured — every local suite then fails, and `cmake --build` cannot even
# relink, because the linker follows the dangling symlink and gets EACCES. Running the gate
# once destroyed the fast inner loop.
#
# A tmpfs at /src/build layers over the bind mount (mounts apply in path order), so the
# symlinks are made INSIDE the container and the host's build/ is never touched. Verified
# safe: no suite writes into build/ — they only read $ROOT/build/fastpki-*.
# ── one container per shard ──────────────────────────────────────────────────────────
#
# Each shard runs in its OWN container, so it gets its own loopback, its own Postgres and
# its own p11-kit token stack. That is precisely what makes running them at the same time
# safe: the suites bind FIXED ports and 67 of those numbers are claimed by more than one
# suite, so they can only run concurrently if they cannot see one another's network.
run_one() {   # <shard-spec, e.g. "2/6", or "" for the whole run>
docker run --rm --network "$NET" \
    -e FASTPKI_SHARD="$1" \
    -v "$ROOT:/src" \
    --mount type=tmpfs,destination=/src/build \
    -e RUN_ROOT="${RUN_ROOT:-1}" -e RUN_PG="${RUN_PG:-1}" \
    -e OSSL=/usr/bin/openssl \
    -e FASTPKI_MS_KRB=/usr/local/bin/fastpki-ms \
    "${ENVARGS[@]+"${ENVARGS[@]}"}" \
    -e "FASTPKI_RUNCMD=$RUNCMD" \
    "$TESTIMG" bash -lc '
      set -e
      # ⚠️ GIT REFUSES A TREE IT DOES NOT OWN, AND THAT SILENTLY DISARMED A GATE. The bind
      # mount keeps the host uid, so on Linux /src belongs to the developer (1000) while this
      # container runs as root, and git answers "detected dubious ownership in repository at
      # /src" to every command. tests/public_repo_hygiene.sh asks `git rev-parse
      # --is-inside-work-tree` first and SKIPS when that fails -- so the suite that keeps lab
      # hostnames, and citations of files a clone will not have, out of a public repo has
      # never run on any Linux host: not in the lab, not in CI. (It caught this very comment
      # naming such a file, one minute after being re-armed.) It passes on macOS only because
      # Docker Desktop
      # presents the mount as owned by the container user, which is why nobody saw it.
      git config --global --add safe.directory /src 2>/dev/null || true

      # WARNING: REFUSE TO RUN IF THE TMPFS IS NOT ACTUALLY THERE. Everything below writes
      # symlinks into /src/build, and /src is the DEVELOPERS OWN REPOSITORY, bind-mounted.
      # The tmpfs above is the only thing between those symlinks and the real build/
      # directory. If it silently failed to mount, the loop below fills the real one with
      # links to /usr/local/bin/fastpki-*, which exist only inside a container that is
      # about to be removed.
      #
      # The damage is not noticed here. It is noticed an hour later, when every local suite
      # fails and cmake --build cannot even relink, because the linker follows a dangling
      # symlink and gets EACCES -- the exact failure the comment above this block already
      # describes. A shared working tree makes it worse: whoever loses their build/ is not
      # necessarily whoever ran this.
      #
      # One syscall turns "the build directory is mysteriously empty" into a refusal at the
      # point of the mistake. A mount that did not happen looks exactly like one that did,
      # right up until something writes.
      if ! mountpoint -q /src/build 2>/dev/null; then
          echo "run-in-container.sh: /src/build is NOT a tmpfs -- refusing to run." >&2
          echo "  Without it, the symlinks below land in the HOST repository build/" >&2
          echo "  directory and destroy it. Check the --mount flag on the docker run." >&2
          exit 1
      fi

      # The harness looks for build/fastpki-*; the shipped binaries are on PATH. Link them
      # in here, on the tmpfs, where it costs the host nothing.
      mkdir -p /src/build
      for b in /usr/local/bin/fastpki-* /usr/local/bin/dnsstub /usr/local/bin/spnego-post \
               /usr/local/bin/scep-testclient /usr/local/bin/cmp-testclient; do
          [ -e "$b" ] && ln -sf "$b" "/src/build/$(basename "$b")"
      done
      # A throwaway cluster for the PG tier, inside the container — nothing outside is
      # touched, so this never disturbs a deployment it is running next to.
      #
      # ⚠️ THROUGH tests/pg_priv.sh, NOT A HAND-ROLLED `su postgres`. Postgres refuses to
      # run as root, and that wrapper is where the knowledge of dropping privilege in THIS
      # image lives: it picks postgres or nobody, re-quotes with printf %q, carries PATH and
      # LC_ALL across, and bounds the probe — busybox setpriv has no user-switching options,
      # so `su -s /bin/sh` is the only thing that works here. tests/pg_priv_census.sh caught
      # this file duplicating that logic rather than reusing it, which is what it is for.
      . /src/tests/pg_priv.sh
      export PGDATA=/tmp/pg PGHOST=127.0.0.1 PGUSER=fastpki PGPASSWORD=fastpki PGDATABASE=fastpki
      # ⚠️ A PORT OF OUR OWN, NOT 5432. On Linux this runs with --network host, so the
      # container shares the loopback of the HOST rather than getting one of its own. A node
      # that runs a FastPKI deployment already has Postgres on 5432 there, so the throwaway
      # cluster cannot bind and the whole PG tier dies at startup with
      #   could not bind IPv4 address "127.0.0.1": Address in use
      #   FATAL: could not create any TCP/IP sockets  ->  pg_ctl: could not start server
      # which surfaces only as "the suite FAILED against the rolled image". That is the
      # post-roll gate failing 100% of the time on precisely the machines it exists for,
      # and it says nothing about the image being rolled.
      export PGPORT="${FASTPKI_TEST_PGPORT:-15432}"
      mkdir -p "$PGDATA"
      pg_own "$PGDATA"
      pg_as initdb -D "$PGDATA" -U fastpki --auth=trust >/dev/null
      pg_as pg_ctl -D "$PGDATA" -o "-c port=$PGPORT -c listen_addresses=127.0.0.1 -c wal_level=logical" -w start >/dev/null
      createdb -U fastpki fastpki 2>/dev/null || true
      psql -U fastpki -d fastpki -f sql/createdb.sql >/dev/null 2>&1 || true
      eval "$FASTPKI_RUNCMD"
    '
}

if [ "$JOBS" -le 1 ] || [ -n "${FASTPKI_TEST_SUITE:-}" ]; then
    run_one ""
    exit $?
fi

# ⚠️ A SHARD'S OUTPUT IS BUFFERED TO A FILE AND PRINTED WHOLE. Letting N containers write
# to the same terminal interleaves them line by line, and a suite's failure output then
# belongs to whichever shard happened to be mid-write — which is worse than useless when
# the whole point is to find out which suite failed.
_tmp="$(mktemp -d)"
# Keep the shard logs when something failed: they are the only record of WHICH suite
# broke, and deleting them on the way out is how a parallel run becomes unactionable.
trap '[ "${_rc:-1}" = 0 ] && rm -rf "$_tmp" || echo "shard logs kept in $_tmp"' EXIT
echo "== $JOBS shards in parallel, one container each =="
_pids=""
for k in $(seq 1 "$JOBS"); do
    ( run_one "$k/$JOBS" >"$_tmp/shard.$k" 2>&1; echo $? >"$_tmp/rc.$k" ) &
    _pids="$_pids $!"
done
# 'set -e' is on: bare `wait` returns the CHILD's status, so a shard that reports
# failures would kill this driver before it printed a single line of any shard's log --
# and the EXIT trap would then delete them. The rc files below carry the verdict.
for p in $_pids; do wait "$p" || true; done

# Aggregate. Each shard prints its own "SUITES: a passed, b failed, ..." line; sum them so
# the run ends with one honest total rather than N partial ones the reader must add up.
_p=0; _f=0; _s=0; _n=0; _rc=0; _failed=""
for k in $(seq 1 "$JOBS"); do
    echo "==================== shard $k/$JOBS ===================="
    cat "$_tmp/shard.$k"
    _line="$(grep -E '^SUITES: ' "$_tmp/shard.$k" | tail -1)"
    if [ -n "$_line" ]; then
        _p=$(( _p + $(echo "$_line" | sed -E 's/.*SUITES: ([0-9]+) passed.*/\1/') ))
        _f=$(( _f + $(echo "$_line" | sed -E 's/.*, ([0-9]+) failed.*/\1/') ))
        _s=$(( _s + $(echo "$_line" | sed -E 's/.*, ([0-9]+) skipped.*/\1/') ))
        _n=$(( _n + $(echo "$_line" | sed -E 's/.*\(of ([0-9]+)\).*/\1/') ))
    fi
    _failed="$_failed $(grep -E '^  FAILED: ' "$_tmp/shard.$k" | sed 's/^  FAILED: //' | tr '\n' ' ')"
    [ "$(cat "$_tmp/rc.$k" 2>/dev/null || echo 1)" -eq 0 ] || _rc=1
done
echo "==================================================================="
echo "PARALLEL TOTAL ($JOBS shards): $_p passed, $_f failed, $_s skipped  (of $_n)"
# ⚠️ A shard that died without printing totals must not read as green. rc is the authority.
if [ -n "$(echo "$_failed" | tr -d ' ')" ]; then echo "  FAILED:$_failed"; fi
if [ "$_rc" -eq 0 ] && [ "$_f" -eq 0 ]; then echo "ALL GREEN"; fi
exit $_rc
