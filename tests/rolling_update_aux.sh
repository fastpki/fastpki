#!/usr/bin/env bash
# rolling_update_aux.sh — a rolling update must leave the WHOLE deployment on one image.
#
# THE DEFECT THIS GUARDS. The updater rolled the eight protocol services and stopped.
# Every other container built from the same image — the token server, the periodic
# certificate-renewal job — was never recreated, so after each update it kept running the
# image from the update before. Nothing failed. The services were healthy, the tag they
# reported was identical (a stale container still says ":latest"), and only a digest
# comparison showed it. Measured across a three-node deployment where the post-deploy
# validator had been reporting exactly this and was correct.
#
# It matters because these containers are not inert. The renewal job runs issuance code
# on a timer; the token server is what every private-key operation goes through. "We only
# changed the protocol binaries" is never true either — they all share one image, so a
# change to the shared library lands in them too.
#
# HOW THIS IS TESTED WITHOUT DOCKER. The updater talks to the outside world through one
# command, overridable as DOCKER_COMPOSE. This substitutes a recorder for it and asserts
# on the command stream: which services get recreated, and in what order. That is the
# actual contract — a grep for a service name in the script would pass on a mention in a
# comment.
set -uo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UPD="$ROOT/deploy/rolling-update.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; PASS=$((PASS+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; FAIL=$((FAIL+1)); fi; }

# ── the recorder ────────────────────────────────────────────────────────────────────────
# Answers the four questions the updater asks and logs every call. The service list is a
# realistic deployment: the database, two one-shot provisioning steps that have already
# run and exited, two long-lived auxiliary containers, and the protocols.
#
# Protocol services deliberately report a state that is NOT `running`, so the updater's
# "is it answering yet?" wait times out instead of depending on whether some unrelated
# process on this machine happens to hold one of those ports. The run therefore ends in
# the protocol phase by design — everything asserted below happens before that.
cat > "$TMP/dc" <<'SHIM'
#!/bin/sh
echo "$*" >> "$LOG"
case "$1" in
  config)
    printf '%s\n' postgres token certgen bootstrap certrenew \
                  web ocsp est acme cmp ms store scep
    ;;
  ps)
    svc="$2"; fmt="$*"
    case "$svc" in
      token|certrenew)  st=running ;;   # long-lived sidecars
      certgen|bootstrap)  st=exited  ;;   # one-shots: already ran
      *)                  st=starting ;;  # protocols: never "answer" in this harness
    esac
    case "$fmt" in
      *Health*) [ "$svc" = token ] && echo healthy || echo "" ;;
      *)        echo "$st" ;;
    esac
    ;;
esac
exit 0
SHIM
chmod +x "$TMP/dc"

run_update(){                      # run_update <logfile> [service…]
  local log="$1"; shift
  : > "$log"
  ( cd "$ROOT/deploy" && LOG="$log" DOCKER_COMPOSE="$TMP/dc" \
      SKIP_SCHEMA=1 HEALTH_TIMEOUT=2 \
      bash "$UPD" "$@" ) > "$log.out" 2>&1
  echo $?
}

# line number of the first `up` naming $1; empty if it never happens
upline(){ grep -n "^up .*[ ]$1\$" "$2" | head -1 | cut -d: -f1; }

echo "=== 1. a full update recreates the auxiliary services too ==="
LOG="$TMP/full.log"
RC="$(run_update "$LOG")"

chk "the token server is recreated"      yes "$(grep -q '^up -d --force-recreate --no-deps token$'   "$LOG" && echo yes || echo no)"
chk "the renewal job is recreated"       yes "$(grep -q '^up -d --force-recreate --no-deps certrenew$' "$LOG" && echo yes || echo no)"
chk "both are pulled, not just rolled"   yes "$(grep '^pull ' "$LOG" | grep -q 'token' && grep '^pull ' "$LOG" | grep -q 'certrenew' && echo yes || echo no)"

echo "=== 2. what must NOT be recreated ==="
# The one-shots already ran. Recreating them would re-run provisioning — re-seeding the
# console admin, rewriting transport material — under what is supposed to be an update.
# They are excluded because they are not running, which needs no list and so cannot rot.
chk "the transport-cert one-shot is left alone" no "$(grep -q '^up .*certgen'   "$LOG" && echo yes || echo no)"
chk "the bootstrap one-shot is left alone"      no "$(grep -q '^up .*bootstrap' "$LOG" && echo yes || echo no)"
# Recreating the database is a failover, not an update.
chk "the database is left alone"                no "$(grep -qE '^up .*(^| )postgres($| )' "$LOG" && echo yes || echo no)"

echo "=== 3. ORDER: the token server goes before any protocol ==="
# Every protocol container reaches the token through the sidecar's socket, so recreating
# the sidecar invalidates the sessions it handed out. Before the roll that costs nothing —
# each protocol is replaced next and starts against a live socket. After the roll it would
# strand eight freshly started services with nothing left to restart them.
SH="$(upline token "$LOG")"
FIRSTPROTO="$(grep -n '^up -d --no-deps ' "$LOG" | head -1 | cut -d: -f1)"
chk "the token server is recreated first" yes \
    "$([ -n "$SH" ] && [ -n "$FIRSTPROTO" ] && [ "$SH" -lt "$FIRSTPROTO" ] && echo yes || echo no)"

echo "=== 4. a named service list is a TARGETED operation ==="
LOG2="$TMP/targeted.log"
RC2="$(run_update "$LOG2" web est)"
chk "no auxiliary service is touched" no \
    "$(grep -qE '^up .*(token|certrenew)' "$LOG2" && echo yes || echo no)"
chk "and it says so"                  yes \
    "$(grep -qi 'auxiliary services.*left alone' "$LOG2.out" && echo yes || echo no)"

echo "=== 5. the run is honest about stopping ==="
# The protocol phase cannot complete here (nothing answers a port), and it must FAIL
# rather than fall through — a rollout that reports success without verifying a service
# came back is the failure mode the one-at-a-time design exists to prevent.
chk "an unverifiable protocol stops the rollout" 1 "$RC"
chk "and the reason is stated"                   yes \
    "$(grep -q 'did not come back' "$LOG.out" && echo yes || echo no)"

echo
echo "RESULT: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
