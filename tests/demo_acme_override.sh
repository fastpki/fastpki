#!/usr/bin/env bash
# The demo may modify a running deployment, on ONE condition.
#
# ⚠️ THE CONDITION: modifying the deployment for the demo is fine as long as we revert the
# changes back when the demo is done."
#
# So the thing worth guarding is not that the override works — it is that it GOES AWAY.
# A demo that leaves `extra_hosts` on someone's acme service has broken the condition the
# permission was granted under, and nothing about the deployment looks wrong afterwards:
# the service starts, serves, and quietly resolves a name it should not.
#
# ⚠️ This drives the REAL functions out of demo/pki-demo.sh with `docker` stubbed, rather
# than grepping the script for a `rm`. A grep proves the line exists; it does not prove the
# trap fires, that the file name is the one deleted, or that a killed demo cleans up.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# A `docker` that records what it was asked to do and always succeeds.
mkdir -p "$W/bin"
cat > "$W/bin/docker" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DOCKER_CALLS"
exit 0
STUB
chmod +x "$W/bin/docker"
export PATH="$W/bin:$PATH" DOCKER_CALLS="$W/calls.txt"
: > "$DOCKER_CALLS"

mkdir -p "$W/deploy"; : > "$W/deploy/docker-compose.yml"

# The harness the two functions expect from pki-demo.sh. Deliberately minimal: if either
# function grows a dependency on something else, this suite fails loudly rather than
# silently testing a different code path.
DIM=""; RST=""; demo_sudo=""; COMPOSE_DIR="$W/deploy"
skip(){ echo "    (skip: $*)"; }

# Extract the functions from the shipped demo and run THOSE. Sourcing the whole script would
# run a demo; this takes the definitions only, and fails if any is renamed away.
#
# ⚠️ EVERY DEFINITION IS NAMED. This began as a range from `^DEMO_COMPOSE_OVERRIDE=""` to the
# next `^}`, which worked only while demo_undo_compose happened to be the next thing in the
# file. A remote-dns block was later inserted between them, so the range stopped at a `}`
# inside an unrelated function, demo_undo_compose never reached fns.sh, and every call to it
# was a silent 127 — including the one inside the EXIT trap, which is why the SIGTERM case
# failed too. Ranges anchored on a neighbour break when a neighbour moves; names do not.
#
# The trap installed by demo_acme_reachable is `demo_undo_all`, so its two callees and the
# two state variables they clear have to come along. demo_undo_remote_dns returns early when
# DEMO_REMOTE_DNS_SET is empty, which it always is here, so demo_remote_cfg is not needed.
sed -n '/^DEMO_COMPOSE_OVERRIDE=""/p;
        /^DEMO_REMOTE_DNS_PREV=/p;
        /^demo_undo_remote_dns(){/,/^}$/p;
        /^demo_undo_all(){/p;
        /^demo_undo_compose(){/,/^}$/p;
        /^demo_acme_reachable(){/,/^}$/p;
        /^demo_acme_dns_resolver(){/,/^}$/p' \
    "$ROOT/demo/pki-demo.sh" > "$W/fns.sh"
# Assert every definition the cases below CALL is present. The old check named two of them,
# so an extraction that silently dropped the rest still passed here and failed later as a
# command-not-found, which reads as a product bug rather than a harness one.
missing=""
for fn in demo_acme_reachable demo_acme_dns_resolver demo_undo_all demo_undo_compose \
          demo_undo_remote_dns; do
    grep -q "^$fn(){" "$W/fns.sh" || missing="$missing $fn"
done
chk "every override function was found in demo/pki-demo.sh" "" "$missing"
# shellcheck disable=SC1090
. "$W/fns.sh"

echo "=== the override is created, and it is an OVERRIDE — not an edit ==="
BEFORE_SUM=$(cksum < "$W/deploy/docker-compose.yml")
demo_acme_reachable chal-demo.internal >/dev/null
OVR=$(ls "$W"/deploy/docker-compose.demo-*.yml 2>/dev/null | head -1)
chk "an override file was written"                 yes "$([ -n "$OVR" ] && echo yes || echo no)"
chk "  naming the domain as a host-gateway entry"  yes \
    "$(grep -q 'chal-demo.internal:host-gateway' "$OVR" 2>/dev/null && echo yes || echo no)"
chk "  scoped to the acme service ONLY"            1 \
    "$(grep -cE '^  [a-z]' "$OVR" 2>/dev/null | tr -d ' ')"
# ⚠️ THE ASSERTION THAT MATTERS MOST. The permission was for a reversible change; an edit
# to the shipped compose file is not reversible by deleting anything.
chk "  and docker-compose.yml is byte-for-byte untouched" "$BEFORE_SUM" \
    "$(cksum < "$W/deploy/docker-compose.yml")"
chk "  the service was recreated WITH the override" yes \
    "$(grep -q -- "-f $OVR up -d --force-recreate acme" "$DOCKER_CALLS" && echo yes || echo no)"

echo "=== ...and it is removed again ==="
demo_undo_compose >/dev/null
chk "the override file is gone"                    no  "$([ -f "$OVR" ] && echo yes || echo no)"
chk "  and acme was recreated WITHOUT it"          yes \
    "$(grep -qE -- "-f $W/deploy/docker-compose.yml up -d --force-recreate acme$" "$DOCKER_CALLS" \
       && echo yes || echo no)"
chk "  a second undo is a no-op, not an error"     0   "$(demo_undo_compose >/dev/null 2>&1; echo $?)"

echo "=== the dns-01 resolver override names the CoreDNS CONTAINER ==="
# ⚠️ THIS PATH HAD NO GUARD AT ALL, and both of its wrong answers named an ADDRESS OR A
# HOST when the thing to name is a container. dns-auth.sh runs CoreDNS on the acme
# service's own compose network and exposes no port, so every host-shaped answer — the
# compose network's IPAM gateway, or a host-gateway entry — reaches a closed port, and the
# server reports the silence as "dns-01 TXT record missing or mismatched".
#
# So the assertion is not "an address was written" — it is that the demo names the
# container and lets docker's embedded DNS resolve it.
DNSSUM_BEFORE=$(cksum < "$W/deploy/docker-compose.yml")
# ⚠️ REDIRECT TO A FILE — do NOT wrap this in $( ). Command substitution runs a SUBSHELL,
# and the function installs `trap demo_undo_compose EXIT`, so the trap fires the instant
# the substitution closes: the override is created and deleted again before the next line
# runs, and every assertion below then fails against the real, correct demo. The demo
# itself calls it as `demo_acme_dns_resolver "$DNSP" >/dev/null`, in the main shell, which
# is what keeps the trap alive for the length of the run.
demo_acme_dns_resolver 15353 > "$W/dnsres.txt" 2>/dev/null
RESOLVER=$(tail -1 "$W/dnsres.txt")
DOVR=$(ls "$W"/deploy/docker-compose.demo-dns-*.yml 2>/dev/null | head -1)
chk "an override file was written"                  yes "$([ -n "$DOVR" ] && echo yes || echo no)"
chk "  pointing ACME_DNS_RESOLVER at the container" yes \
    "$(grep -q 'ACME_DNS_RESOLVER: "fastpki-dns:15353"' "$DOVR" 2>/dev/null && echo yes || echo no)"
# ⚠️ AND NOT AT THIS HOST. dns-auth.sh publishes no port, so an extra_hosts/host-gateway
# entry aims the server at a closed port on the docker host and the order fails as
# "dns-01 TXT record missing or mismatched" — a resolver fault wearing a challenge fault's
# words. The http-01 step above legitimately maps host-gateway; this one must not.
chk "  and naming no host for the acme service"     no \
    "$(grep -qE 'extra_hosts|host-gateway' "$DOVR" 2>/dev/null && echo yes || echo no)"
# The regression this locks down: a hardcoded dotted-quad is the old, platform-dependent
# behaviour — an address this script guessed for a container docker itself can name.
chk "  no guessed IPv4 literal in the resolver"     no \
    "$(grep -qE 'ACME_DNS_RESOLVER: "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:' "$DOVR" 2>/dev/null && echo yes || echo no)"
chk "  it did not interrogate the docker network"   no \
    "$(grep -q 'network inspect' "$DOCKER_CALLS" && echo yes || echo no)"
chk "  scoped to the acme service ONLY"             1 \
    "$(grep -cE '^  [a-z]' "$DOVR" 2>/dev/null | tr -d ' ')"
chk "  docker-compose.yml still untouched" "$DNSSUM_BEFORE" \
    "$(cksum < "$W/deploy/docker-compose.yml")"
chk "  the function echoed the value it configured" "fastpki-dns:15353" "$RESOLVER"
demo_undo_compose >/dev/null
chk "  and the dns override is removed too"         no  "$([ -f "$DOVR" ] && echo yes || echo no)"

echo "=== a demo that DIES still reverts (the trap, not the happy path) ==="
# The condition is about the deployment afterwards, and "afterwards" includes
# Ctrl-C and a failed step. Run the create in a subshell that then kills itself.
( . "$W/fns.sh"; demo_acme_reachable chal-demo.internal >/dev/null; kill -TERM $$ ) >/dev/null 2>&1
LEFT=$(ls "$W"/deploy/docker-compose.demo-*.yml 2>/dev/null | wc -l | tr -d ' ')
chk "nothing left behind after a SIGTERM" 0 "$LEFT"

echo
echo "=== DEMO ACME OVERRIDE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
