#!/usr/bin/env bash
# deployment-path: compose-only — it validates the compose lab
# The MANDATORY sequence after every push of a new version to the lab.
#
# The rule this script implements: run the code suite on ONE dc (dc1), then a replication
# test and a local database failover, then validate that all three are healthy and in sync
# — and do all of it every time a new version is pushed to the lab.
#
# ⚠️ WHY THIS SCRIPT EXISTS. `lab-test.sh` passes RUN_ROOT=1 and RUN_PG=1 but NOT RUN_LAB=1,
# so every one of its runs prints
#
#     NOTE: skipping the lab tier (lab_replication_mesh.sh); set RUN_LAB=1 ...
#
# and carries on. A whole session was reported as "the full lab suite, 174/175" while the
# ONLY test that touches more than one DC had never run. A skip that reads as coverage —
# the same shape as bugs we have shipped in the product, here in the deploy flow.
#
# It cannot simply be added to lab-test.sh: lab_replication_mesh.sh drives the DCs over SSH
# from the WORKSTATION (tests/lab_replication_mesh.sh:34,51) and the test container has
# neither the key nor NetBird. So the tiers genuinely have to run from different places, and
# something has to run both. That is this.
#
#   bash deploy/lab-validate.sh            # the whole sequence
#   SKIP_SUITE=1 bash deploy/lab-validate.sh   # replication + failover + health only
#
# ⚠️ Step 2 CUTS the interconnect and promotes a standby for real. It restores both via an
# EXIT trap and asserts the restore, but it is shared infrastructure — do not start it while
# someone else is mid-test.
set -uo pipefail
HERE="$(cd "${0%/*}" && pwd)"        # no dirname, it is not on every PATH
ROOT="$(cd "$HERE/.." && pwd)"
KEY="${LAB_SSH_KEY:-$HOME/.ssh/fastpki_lab_ed25519}"
USER_="${LAB_SSH_USER:-admin}"

# Node addresses come from an untracked per-site file, never from this script. Nothing in
# the repository names our infrastructure, and a second lab is a file rather than a
# grep-and-replace. Format and overrides: deploy/lab/nodes.env.example.
LAB_ENV="${LAB_ENV:-$HERE/lab/nodes.env}"
# ⚠️ THE ENVIRONMENT MUST WIN, and it did not. Sourcing the file plainly OVERWROTE any
# variable already set in the environment, so the documented one-off override
# (`LAB_DC1_MGMT=… bash deploy/lab-validate.sh`) silently did nothing whenever nodes.env
# existed — which is always, on a machine set up to run this. It reads as though it worked:
# the run proceeds and validates the file's hosts, not the ones you named. Snapshot the
# environment first and re-apply it afterwards, so the file is the DEFAULT and the
# environment is the override, which is what its own documentation promises.
_env_dc1="${LAB_DC1_MGMT:-}"; _env_dc2="${LAB_DC2_MGMT:-}"; _env_dc3="${LAB_DC3_MGMT:-}"
_env_reg="${LAB_REGISTRY:-}"
[ -r "$LAB_ENV" ] && . "$LAB_ENV"
[ -n "$_env_dc1" ] && LAB_DC1_MGMT="$_env_dc1"
[ -n "$_env_dc2" ] && LAB_DC2_MGMT="$_env_dc2"
[ -n "$_env_dc3" ] && LAB_DC3_MGMT="$_env_dc3"
[ -n "$_env_reg" ] && LAB_REGISTRY="$_env_reg"
DC1="${LAB_DC1_MGMT:-}"; DC2="${LAB_DC2_MGMT:-}"; DC3="${LAB_DC3_MGMT:-}"
REGISTRY_IMAGE="${FASTPKI_IMAGE:-${LAB_REGISTRY:-}/fastpki:latest}"
# No default address. A guess would reach SOMETHING, and validating the wrong host reads
# exactly like validating the right one.
if [ -z "$DC1" ] || [ -z "$DC2" ] || [ -z "$DC3" ] || [ -z "${LAB_REGISTRY:-}${FASTPKI_IMAGE:-}" ]; then
    echo "ERR: no lab topology. Copy deploy/lab/nodes.env.example to $LAB_ENV and fill it in," >&2
    echo "     or set LAB_DC1_MGMT / LAB_DC2_MGMT / LAB_DC3_MGMT and LAB_REGISTRY." >&2
    exit 2
fi
SSHO="-i $KEY -o StrictHostKeyChecking=no -o ConnectTimeout=15"
on(){ ssh $SSHO "$USER_@$1" "$2" 2>/dev/null; }
fail=0
say(){ printf '\n=== %s ===\n' "$1"; }
# ⚠️ TWO EMPTY STRINGS ARE NOT A PASS. Several checks below compare one node's answer
# against another's, and `on()` returns "" for a node it cannot reach — so when NOTHING is
# reachable, "" = "" and every one of those checks reported PASS. That is the exact
# opposite of what this script exists for: step 1 is the only thing that has ever caught
# the stale-checkout case, and it was the check that failed open. An expected value of ""
# is a bug in the caller, never a result.
chk(){
    if [ -z "$2" ] && [ -z "$3" ]; then
        echo "  [FAIL] $1 (both sides empty — the probe returned nothing, so this compared nothing)"
        fail=$((fail+1)); return
    fi
    if [ "$2" = "$3" ]; then echo "  [PASS] $1"; else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi
}

# ⚠️ PREFLIGHT, and it aborts rather than degrading. Checking reachability once here covers
# every step at a stroke — the alternative is each individual check having to distinguish
# "the answer is wrong" from "there was no answer", which is precisely the distinction that
# was missed. A validation run that cannot reach the thing it validates has no useful
# partial result; it has no result.
[ -r "$KEY" ] || {
    echo "ERR: the lab SSH key '$KEY' is not readable." >&2
    echo "     Set LAB_SSH_KEY. Note \$HOME changes under sudo, so the default path may" >&2
    echo "     resolve somewhere the key is not." >&2
    exit 2
}
_unreachable=""
for spec in "$DC1:dc1" "$DC2:dc2" "$DC3:dc3"; do
    ip=${spec%%:*}; nm=${spec##*:}
    ssh $SSHO -o BatchMode=yes "$USER_@$ip" true >/dev/null 2>&1 || _unreachable="$_unreachable $nm($ip)"
done
[ -z "$_unreachable" ] || {
    echo "ERR: cannot reach:$_unreachable" >&2
    echo "     Every check below compares one node against another, so an unreachable node" >&2
    echo "     would make them compare nothing. Refusing to report on a lab we cannot see." >&2
    exit 2
}

# ---- 1. the code under test is the SAME everywhere -------------------------------------
# ⚠️ Checked FIRST and asserted, not assumed. The three checkouts drifted once because each
# deploy bundles from the last-deployed SHA and only the build node was re-synced before a
# lab run — same image, different test trees, so "the lab" was not one thing. And a
# `git bundle` whose ref does not match what the DC fetches fails SILENTLY, leaving the node
# behind with no error at all.
say "1. all three DCs on the same commit and the same image"
H1=$(on $DC1 'cd ~/FastPKI && git rev-parse --short HEAD')
for spec in "$DC2:dc2" "$DC3:dc3"; do
    ip=${spec%%:*}; nm=${spec##*:}
    chk "$nm git HEAD matches dc1 ($H1)" "$H1" "$(on $ip 'cd ~/FastPKI && git rev-parse --short HEAD')"
done
I1=$(on $DC1 'sudo docker inspect --format "{{.Image}}" fastpki-acme-1')
for spec in "$DC2:dc2" "$DC3:dc3"; do
    ip=${spec%%:*}; nm=${spec##*:}
    chk "$nm runs the same image as dc1" "$I1" "$(on $ip 'sudo docker inspect --format "{{.Image}}" fastpki-acme-1')"
done

# ⚠️ EVERY CONTAINER, AGAINST THE REGISTRY, BY DIGEST. The three assertions above compare
# the DCs to EACH OTHER and only via fastpki-acme-1, so all three being uniformly stale
# passes, and any service the deploy forgot passes too.
#
# Both happened on the serial-prefix deploy: the recreate named a hardcoded service list
# that left out `certrenew`, so it ran the previous binary for three hours on all three DCs.
# It would have minted unprefixed serials that its own DB guard then rejected. The tag was
# identical the whole time -- `docker compose up -d <list>` does not touch a service it was
# not named, and :latest on a stale container still reads ":latest". Only the DIGEST shows
# it, which is why this compares .Image (a digest) and not .Config.Image (the tag).
#
# Derived from `docker ps`, never a list: a service added to compose tomorrow is covered
# on the day it lands, which a hardcoded list is exactly what failed here.
say "1a. every service runs the image now in the registry (by digest, not tag)"
for spec in "$DC1:dc1" "$DC2:dc2" "$DC3:dc3"; do
    ip=${spec%%:*}; nm=${spec##*:}
    stale=$(on $ip 'W=$(sudo docker image inspect '"$REGISTRY_IMAGE"' --format "{{.Id}}" 2>/dev/null)
        [ -z "$W" ] && { echo "NO-REGISTRY-IMAGE"; exit 0; }
        n=0; bad=""
        for c in $(sudo docker ps --format "{{.Names}}" | grep "^fastpki-"); do
            case "$(sudo docker inspect "$c" --format "{{.Config.Image}}")" in postgres:*) continue ;; esac
            n=$((n+1))
            [ "$(sudo docker inspect "$c" --format "{{.Image}}")" = "$W" ] || bad="$bad $c"
        done
        [ "$n" -lt 5 ] && { echo "ONLY-$n-CONTAINERS"; exit 0; }   # not vacuous
        echo "${bad:-none}"')
    chk "$nm has no service on a stale image" "none" "$stale"
done

# ---- 1b. the MESH is fully applied, not just the half that happens to work --------------
# ⚠️ Added after finding the lab had been running for months with the data center map
# empty on all three DCs — the replicated view that lets a node see any partition but its
# own. The per-node half was applied and kept working perfectly, which is exactly why
# nobody noticed. A hand-applied mesh has no artifact to diff against; this re-asserts
# the whole thing from deploy/lab/topology on every push. An empty map also
# means a node that cannot issue at all: it reads its own serial prefix from that row.
say "1b. the mesh matches the topology file"
# deploy/lab/ is local-only (see .gitignore): it is this lab's operational plumbing, not
# product. A tracked script must not hard-depend on an untracked one, so SKIP loudly
# rather than fail when it is absent — and say so, because a silent skip is how coverage
# gets lost.
if [ ! -x "$ROOT/deploy/lab/lab-mesh.sh" ]; then
    echo "  [SKIP] deploy/lab/lab-mesh.sh is not present — mesh-vs-topology NOT checked"
elif bash "$ROOT/deploy/lab/lab-mesh.sh" verify > /tmp/lab-validate-mesh-cfg.log 2>&1; then
    echo "  [PASS] every node carries the whole mesh"
else
    echo "  [FAIL] the mesh does not match deploy/lab/topology — run: bash deploy/lab/lab-mesh.sh apply"
    grep '\[FAIL\]' /tmp/lab-validate-mesh-cfg.log | sed 's/^/    /'
    fail=$((fail+1))
fi

# ---- 2. the code check, on ONE node ------------------------------------------------------
say "2. full suite on DC1 only, in the SHIPPED image"
if [ "${SKIP_SUITE:-0}" = "1" ]; then
    echo "  [SKIP] SKIP_SUITE=1 — suite not run this time"
else
    on $DC1 "cd ~/FastPKI/deploy && sudo -E FASTPKI_IMAGE=$REGISTRY_IMAGE bash ./lab-test.sh" \
        > /tmp/lab-validate-suite.log 2>&1
    SUM=$(grep -E '^SUITES:' /tmp/lab-validate-suite.log | tail -1)
    # ⚠️ NO SUMMARY LINE IS NOT "ZERO FAILURES". The suite can die before it runs anything —
    # measured when a node's compose .env grew a value with spaces and lab-test.sh, which
    # sourced that file as shell, exited on `email: command not found`. The old check then
    # compared an empty string to "0" and reported a bare mismatch, so the visible result was
    # a failed assertion with no hint that the tier had not run at all. Say that outright and
    # show what the log DOES end with, because that line names the cause.
    if [ -z "$SUM" ]; then
        echo "  [FAIL] the in-image suite produced no summary — it did not run to completion"
        echo "         last lines of /tmp/lab-validate-suite.log:"
        tail -5 /tmp/lab-validate-suite.log 2>/dev/null | sed 's/^/           /'
        fail=$((fail+1))
    else
        echo "  $SUM"
        chk "no suite failed on dc1" "0" "$(printf '%s' "$SUM" | sed -n 's/.*, \([0-9]*\) failed.*/\1/p')"
    fi
    grep -E '^  FAILED:' /tmp/lab-validate-suite.log | sed 's/^/  /'
fi

# ---- 3+4. replication AND the local DB failover -----------------------------------------
# One suite covers both: section 7 promotes dc3's standby through the product's own
# deploy/pg-promote.sh, then restores it.
say "3+4. cross-DC replication and a REAL local DB failover"
RUN_LAB=1 bash "$ROOT/tests/lab_replication_mesh.sh" > /tmp/lab-validate-mesh.log 2>&1
MESH=$(grep -E 'PASS=[0-9]+ FAIL=' /tmp/lab-validate-mesh.log | tail -1)
echo "  ${MESH:-(no summary — see /tmp/lab-validate-mesh.log)}"
grep -E '\[FAIL\]' /tmp/lab-validate-mesh.log | sed 's/^/  /'
chk "replication + failover suite is green" "0" "$(printf '%s' "$MESH" | sed -n 's/.*FAIL=\([0-9]*\).*/\1/p')"
# ⚠️ AND IT MUST HAVE ASSERTED SOMETHING. "FAIL=0" is also what a suite that ran ZERO
# assertions reports, so the line above alone called a suite green after it had printed
# its own error and given up — measured: `PASS=0 FAIL=0` under a "bring the network up"
# message, reported as green. Any check whose healthy answer is "zero failures" goes
# vacuous the moment its input is empty, so the pass count is asserted beside it.
_mesh_pass=$(printf '%s' "$MESH" | sed -n 's/.*PASS=\([0-9]*\).*/\1/p')
chk "  and it actually ran assertions (PASS>0)" "yes" \
    "$([ -n "$_mesh_pass" ] && [ "$_mesh_pass" -gt 0 ] 2>/dev/null && echo yes || echo no)"

# ---- 5. the end state ------------------------------------------------------------------
say "5. all three DCs healthy AND in sync"
for spec in "$DC1:dc1" "$DC2:dc2" "$DC3:dc3"; do
    ip=${spec%%:*}; nm=${spec##*:}
    # ⚠️ ADDRESS THE CONTAINERS, NOT A DIRECTORY. These checks used to `cd ~/FastPKI/deploy`
    # and drive `docker compose` from there — the SSH user's BUILD checkout, not the running
    # deployment, which is installed from a release tarball under a different account
    # entirely. It only appeared to work because both directories are named `deploy`, so
    # compose derives the same project name and finds the same containers; the compose file
    # and .env it read were the wrong copies, and on a host where the deployment sits in a
    # directory by any other name these checks would have reported an empty stack as
    # healthy-looking zeroes. Container names are stable and belong to whoever started them.
    chk "$nm has 12 services running" "12" \
        "$(on $ip 'sudo docker ps --filter name=fastpki- --format "{{.State}}" | grep -c running')"
    # ⚠️ FILTER pg_subscription by current_database(). It is a SHARED catalog, so unfiltered
    # it reports leftover restore databases' disabled subscriptions and calls a healthy mesh
    # broken.
    chk "$nm has 2/2 enabled subscriptions" "2|2" \
        "$(on $ip 'printf "select count(*) filter (where subenabled), count(*) from pg_subscription s join pg_database d on d.oid=s.subdbid where d.datname=current_database();\n" | sudo docker exec -i "$(sudo docker ps --filter name=postgres --format "{{.Names}}" | head -1)" psql -U fastpki -d fastpki -tA -f -' | tr -d ' ')"
    # ⚠️ ENABLED IS NOT CARRYING TABLES, and the check above cannot tell them apart.
    # A subscription whose table set is EMPTY is enabled, connected, has a live apply
    # worker, a fresh last_msg_receipt_time and an active slot at near-zero lag — every
    # signal that normally means healthy — and replicates nothing at all. Measured on this
    # lab: three of the six subscriptions carried zero tables, so the mesh ran ONE WAY
    # (dc1 -> dc2 -> dc3) and the nodes silently diverged to 6 / 11 / 15 certificates while
    # this whole section passed. The cause was ordering: each node was applied in full,
    # subscriptions included, before the later nodes had published anything, so a node
    # could only subscribe to the nodes applied before it.
    #
    # Every other mesh check we own looks at the PUBLICATION side and all three publications
    # were correct throughout. This is the subscriber side, and it is the half nobody asked.
    #
    # ⚠️ If you rewrite this as a LEFT JOIN, count the JOINED COLUMN, not count(*) — over a
    # LEFT JOIN count(*) returns 1 for a subscription with no tables, which reads as "one
    # table" rather than none and sends you looking for which table it is. The correlated
    # subquery below does not have that trap; the warning is for the next person who
    # "simplifies" it.
    chk "$nm has no subscription replicating ZERO tables" "0" \
        "$(on $ip 'printf "select count(*) from (select s.oid from pg_subscription s join pg_database d on d.oid=s.subdbid where d.datname=current_database() and (select count(sr.srrelid) from pg_subscription_rel sr where sr.srsubid=s.oid)=0) q;\n" | sudo docker exec -i "$(sudo docker ps --filter name=postgres --format "{{.Names}}" | head -1)" psql -U fastpki -d fastpki -tA -f -' | tr -d ' ')"
    chk "$nm web answers" "200" "$(on $ip 'curl -sk -o /dev/null -w %{http_code} https://127.0.0.1:8090/')"
done

echo
if [ "$fail" -eq 0 ]; then echo "=== LAB VALIDATE: all steps passed ==="; else echo "=== LAB VALIDATE: $fail check(s) FAILED ==="; fi
[ "$fail" -eq 0 ]
