#!/usr/bin/env bash
# deployment-path: compose-only — a native node is updated by installing a package, docs/admin-guide.md 14.4
# deploy/rolling-update.sh — update FastPKI one service at a time, verifying
# each before moving on, instead of recreating the whole stack at once.
#
#   ./rolling-update.sh                     # every protocol service
#   ./rolling-update.sh web est             # just these
#   FASTPKI_IMAGE=... ./rolling-update.sh   # pin the image being rolled to
#
# WHAT THIS DOES AND DOES NOT GIVE YOU. Read this before believing "zero downtime".
#
# Every protocol service publishes a FIXED host port (web 8090, est 8443, …). Two
# replicas of one service therefore cannot run on one host — the second fails to bind.
# So on a single host a service IS briefly unavailable while its container is replaced,
# typically a second or two. What this script buys is that
#
#   * only ONE protocol is down at a time, never the whole stack, and
#   * a service that fails to come back STOPS the rollout, so a bad image takes out one
#     protocol instead of all eight.
#
# `docker compose up -d` gives neither: it recreates everything at once and keeps going.
#
# Genuine zero-downtime needs a SECOND instance serving while the first is replaced,
# and something in front to move traffic between them. That something is a load
# balancer or reverse proxy, which is the operator's INFRASTRUCTURE — not part of a PKI
# product and deliberately not shipped or required here.
#
# What FastPKI owes that arrangement is only this, and it already holds:
#   * no session state in any binary — console sessions live in web_sessions, so any
#     instance can serve any request (guarded by no_sticky_sessions.sh);
#   * every instance reaches the database through the same multi-host conninfo, so they
#     agree on which node is primary without coordinating with each other;
#   * a port that answers as soon as the instance is ready to serve, which is what this
#     script probes.
#
# An operator who wants zero downtime runs FastPKI on more than one host (or with the
# published ports removed so replicas can coexist) and points their own LB at them. We
# make that possible; we do not implement it.
set -eu

DC="${DOCKER_COMPOSE:-docker compose}"
# ⚠️ ASK COMPOSE WHAT IS DEPLOYED — do not hardcode the eight protocols. A
# deployment only runs what the install wizard was asked for (COMPOSE_PROFILES in .env),
# so a fixed list would try to roll containers that were never created: `up -d` on a
# service whose profile is inactive silently does nothing, and the loop below would then
# wait out its health timeout for a container that will never appear, turning "we do not
# run SCEP here" into a minutes-long failure on every update.
#
# `config --services` honours the active profiles, so this is the same list `up -d` acts
# on. The fallback keeps the script working if compose cannot be reached yet.
ALL="$($DC config --services 2>/dev/null | tr '\n' ' ')"
COMPOSE_KNOWN=1
if [ -z "${ALL// /}" ]; then
  COMPOSE_KNOWN=0
  ALL="web ocsp est acme cmp ms store scep"
fi
# Two sets, not one.
#
# PROTO — the protocol services. These are what "rolling" means: one at a time, each
# verified answering before the next is touched.
#
# AUX — every OTHER service built from the same image. These are NOT rolled one at a
# time (nothing dials them on a port, so there is nothing to verify that way), but they
# DO have to end up on the new image, and that is the part this script used to miss.
#
# ⚠️ WHY AUX EXISTS AT ALL. This script rolled the eight protocols and stopped, so the
# token server and the certificate-renewal job kept running the PREVIOUS image after
# every single update — measured across a whole three-node lab, where the deploy and the
# post-deploy validator disagreed for months and the validator was right. They share one
# image with everything else, so "we only changed the protocol binaries" is never true:
# a shared-library change lands in them too. The renewal job runs issuance code on a
# timer, which is precisely the kind of thing that must not silently be a version behind.
#
# The database is excluded by NAME and deliberately: it is a different image, it holds
# the data, and recreating it is a failover, not an update.
PROTO=""; AUX=""
for _s in $ALL; do
  case "$_s" in
    web|ocsp|est|acme|cmp|ms|store|scep) PROTO="$PROTO $_s" ;;
    postgres)                            : ;;
    *)                                   AUX="$AUX $_s" ;;
  esac
done
PROTO="${PROTO# }"; AUX="${AUX# }"
SERVICES="${*:-$PROTO}"
TIMEOUT="${HEALTH_TIMEOUT:-60}"

say(){ printf '== %s\n' "$*"; }

# A service is "back" when its container is running AND its port answers. Compose's
# own health status is not enough here: a container can be `running` with the process
# still starting, and rolling on to the next service then hides a broken one.
port_of(){
  case "$1" in
    web) echo 8090 ;; ocsp) echo 8080 ;; est) echo 8443 ;; acme) echo 8444 ;;
    cmp) echo 8445 ;; ms)  echo 8446 ;; store) echo 8447 ;; scep) echo 8448 ;;
    *) echo "" ;;
  esac
}

wait_up(){
  local svc="$1" port; port="$(port_of "$svc")"
  local i=0
  while [ "$i" -lt "$TIMEOUT" ]; do
    if [ "$($DC ps "$svc" --format '{{.State}}' 2>/dev/null | head -1)" = "running" ]; then
      # No port to probe (shouldn't happen for these services) → running is enough.
      [ -z "$port" ] && return 0
      # Any answer at all means the listener is up: a TLS service answers a plain
      # request with a protocol error, which is still proof it is accepting.
      if curl -sk -o /dev/null --max-time 2 "https://127.0.0.1:$port/" 2>/dev/null \
      || curl -s  -o /dev/null --max-time 2 "http://127.0.0.1:$port/"  2>/dev/null; then
        return 0
      fi
    fi
    i=$((i+1)); sleep 1
  done
  return 1
}

# An auxiliary service has no port to dial, so "is it back?" has to be asked a different
# way. `running` alone is too weak: the token server is `running` for a moment before it
# has created the socket every other container reaches it through, and starting the
# protocols against a socket that does not exist yet is a crash loop. Where compose knows
# a healthcheck, wait for it to pass; where it does not, `running` is genuinely all there
# is to wait for.
aux_ready(){
  local svc="$1" i=0 st h
  while [ "$i" -lt "$TIMEOUT" ]; do
    st="$($DC ps "$svc" --format '{{.State}}' 2>/dev/null | head -1)"
    if [ "$st" = "running" ]; then
      h="$($DC ps "$svc" --format '{{.Health}}' 2>/dev/null | head -1)"
      case "$h" in healthy|""|"<nil>") return 0 ;; esac
    fi
    i=$((i+1)); sleep 1
  done
  return 1
}

# Which auxiliary services are actually up right now. Derived from the deployment rather
# than from a list, for the same reason the protocol set is: a service added to compose
# tomorrow is covered on the day it lands.
#
# Asking whether it is RUNNING is also what separates a long-lived sidecar from a
# one-shot. The transport-cert and bootstrap steps are `restart: "no"` — they ran once
# and exited — and recreating those under an update would re-run provisioning that has
# already happened. They have no running container, so they fall out here with no name
# needed.
aux_running(){
  local out="" s
  for s in $AUX; do
    [ "$($DC ps "$s" --format '{{.State}}' 2>/dev/null | head -1)" = "running" ] && out="$out $s"
  done
  echo "${out# }"
}

say "rolling ${SERVICES// /, }"
say "image: ${FASTPKI_IMAGE:-<compose default>}"

# The schema step runs FIRST, here, rather than being an instruction in a
# runbook. The honest weakness of option C is that the ordering is the operator's to get
# right, and a skipped step fails exactly the way `bfee7b4`'s certs.cert_id did. Putting
# it in the script is what removes that failure mode: you cannot roll past it.
# Expand/contract is what makes this safe to do before the binaries change — see
# the schema-step rules in docs/postgres.md §4.3.
if [ "${SKIP_SCHEMA:-}" = "1" ]; then
  say "SKIP_SCHEMA=1 — not applying schema steps (you are on your own)"
else
  say "applying schema steps"
  # Default psql to the compose stack's own postgres. This IS the compose path, and a
  # Docker host has no reason to have a psql client installed — defaulting to a bare
  # `psql` would block the rollout on a missing tool rather than on anything real.
  # Invoked through `bash` rather than relying on the exec bit: this repo has
  # core.fileMode=false (it is Syncthing-synced from Windows), so a fresh clone hands
  # you a 0644 script and `./schema-apply.sh` dies with "command not found" — which is
  # exactly what it did on all three lab DCs the first time I ran this.
  # MESH_BIN follows PSQL for the same reason: fastpki-mesh lives inside the image, not on
  # the Docker host, and schema-apply.sh uses it to REGENERATE the replication conflict
  # triggers. Without it the rollout prints a warning and leaves them stale -- which is how
  # a column rename jammed every apply worker on the lab while every other signal read
  # healthy.
  # ⚠️ THE TRIGGER GENERATOR MUST BE THE IMAGE BEING ROLLED **TO**, NOT THE ONE RUNNING.
  # schema-apply.sh regenerates the replication conflict triggers with `fastpki-mesh
  # --triggers`, and the obvious wrapper — exec it inside the running container — reaches
  # for the image we are rolling AWAY from, because at this point in the script nothing
  # has been replaced yet. If the step just applied changed a replicated table's primary
  # key, the old generator writes the old key map and the last-writer-wins trigger then
  # locates rows by the wrong columns: an arriving row silently overwrites an unrelated
  # one on the peer. Nothing reports an error at any stage.
  #
  # `--triggers` only prints SQL — it is topology-free and opens no database — so running
  # it in a throwaway container off the target image is both correct and cheap. Falls back
  # to the running container only when no target image was named, where they are the same
  # thing anyway.
  DOCKER="${DOCKER:-docker}"
  if [ -n "${MESH_BIN:-}" ]; then
    :                                        # the operator named one — theirs wins
  elif [ -n "${FASTPKI_IMAGE:-}" ]; then
    MESH_BIN="$DOCKER run --rm $FASTPKI_IMAGE fastpki-mesh"
  else
    MESH_BIN="$DC exec -T web fastpki-mesh"
  fi
  say "trigger generator: $MESH_BIN"
  if ! PSQL="${PSQL:-$DC exec -T postgres psql -U ${PGUSER:-fastpki} -d ${PGDATABASE:-fastpki}}" \
       MESH_BIN="$MESH_BIN" \
       bash "$(dirname "$0")/schema-apply.sh"; then
    echo "FAIL: the schema step did not complete. NOTHING was rolled — every service is" >&2
    echo "      still on the old image and still matches the old schema." >&2
    exit 1
  fi
fi

# Naming services on the command line is a TARGETED operation — roll exactly those and
# touch nothing else. The auxiliary services are only brought along on a full update,
# which is the case that is supposed to leave the whole deployment on one image.
AUXR=""
# Records WHY AUXR is empty, which the closing report needs and cannot infer: on a targeted
# roll it is empty by design, and on a full roll it is empty because nothing was running.
AUX_LEFT_ALONE=0
if [ "$#" -gt 0 ]; then
  AUX_LEFT_ALONE=1
  say "explicit service list — auxiliary services (${AUX:-none}) left alone"
elif [ "$COMPOSE_KNOWN" = "0" ]; then
  # Do not let this pass as coverage. Without the service list there is no way to know
  # what else is deployed, and silently updating only the eight built-in protocol names
  # is exactly the gap this section exists to close.
  echo "WARN: compose did not answer 'config --services', so only the built-in protocol" >&2
  echo "      list is being rolled. Anything else deployed here — the token server, the" >&2
  echo "      renewal job — is NOT being updated and will stay on the old image." >&2
else
  AUXR="$(aux_running)"
fi

# Pull once up front. Pulling per service would leave the rollout half on the old image
# if the registry goes away midway.
say "pulling"
if ! $DC pull $SERVICES $AUXR >/dev/null 2>&1; then
    # ⚠️ A FAILED PULL IS NOT THE SAME AS A MISSING IMAGE, and treating them as one made
    # this script unusable for the install path docs/deployment.md actually documents. A tarball
    # install does `docker load` and names no registry, so `compose pull` has nowhere to
    # pull FROM and fails every time — leaving an operator holding a correct, freshly built
    # image that the rollout refuses to deploy, with a message blaming the registry.
    #
    # So ask the daemon the question that matters: is the image each service needs actually
    # here? Only refuse when it is not. The safety this guard was written for — never start
    # a rollout that cannot finish — is preserved exactly, because that is the condition
    # being tested now rather than a proxy for it.
    _missing=""
    for _svc in $SERVICES $AUXR; do
        _img=$($DC config --images "$_svc" 2>/dev/null | head -1)
        [ -n "$_img" ] || continue
        # ${DOCKER:-docker}, not $DOCKER: that variable is assigned inside the mesh branch
        # above, which does not always run, and this file is under `set -u`.
        "${DOCKER:-docker}" image inspect "$_img" >/dev/null 2>&1 || _missing="$_missing $_img"
    done
    if [ -n "$_missing" ]; then
        echo "FAIL: could not pull, and these images are not present locally either:" >&2
        for _m in $_missing; do echo "        $_m" >&2; done
        echo "      Nothing was touched. Load or build the image first (docs/deployment.md 3)." >&2
        exit 1
    fi
    say "nothing to pull — every image is already present locally"
fi

# ⚠️ AUXILIARY SERVICES GO FIRST, BEFORE ANY PROTOCOL IS TOUCHED — and the ordering is
# the whole point, not an implementation detail.
#
# Every protocol container reaches the token through the sidecar's socket. Recreating the
# sidecar invalidates every session handed out across that socket. Doing it here costs
# nothing, because each protocol service is replaced by the loop below anyway and picks
# up a live session as it starts. Doing it AFTERWARDS would leave eight freshly started
# services holding handles to a token server that is then pulled out from under them,
# with nothing left to restart them — the strictly larger blast radius, and the reason
# "recreate the leftovers at the end" is the wrong shape even though it reads safer.
for svc in $AUXR; do
  say "updating $svc"
  $DC up -d --force-recreate --no-deps "$svc" >/dev/null 2>&1 || {
    echo "FAIL: '$svc' would not start. NOTHING was rolled — every protocol service is" >&2
    echo "      still on the old image." >&2
    exit 1; }
  aux_ready "$svc" || {
    echo "FAIL: '$svc' did not become ready within ${TIMEOUT}s. Rollout STOPPED before any" >&2
    echo "      protocol service was touched — they are all still serving on the old image." >&2
    echo "      Check: $DC logs --tail 50 $svc" >&2
    exit 1; }
  say "$svc is ready"
done

DONE=""
for svc in $SERVICES; do
  say "updating $svc"
  $DC up -d --no-deps "$svc" >/dev/null 2>&1 || {
    echo "FAIL: '$svc' would not start. Rollout STOPPED." >&2
    echo "      Updated so far:${DONE:- none}. Still on the old image: the rest." >&2
    exit 1; }
  if wait_up "$svc"; then
    say "$svc is back"
    DONE="$DONE $svc"
  else
    echo "FAIL: '$svc' did not come back within ${TIMEOUT}s. Rollout STOPPED so the" >&2
    echo "      remaining services keep serving on the old image." >&2
    echo "      Check: $DC logs --tail 50 $svc" >&2
    exit 1
  fi
done

echo
say "done — updated:${AUXR:+ $AUXR}${DONE}"
say "each was verified answering before the next was touched"
# Say what was deliberately NOT updated, every time. A deploy that lists only what it did
# reads as "everything", and the one service left behind is invisible until something
# else goes looking for it.
SKIPPED=""
for _s in $AUX; do
  case " $AUXR " in *" $_s "*) ;; *) SKIPPED="$SKIPPED $_s" ;; esac
done
# ⚠️ THE REASON DEPENDS ON WHICH RUN THIS IS, and only a full roll ever looked. On a targeted
# roll AUXR is empty by design — the branch above has already said the auxiliary services are
# left alone — so reporting them as "not running here" told the operator the token server and
# the certificate-renewal job were down on a host where both are running, and contradicted
# this script's own earlier line. aux_running() is consulted on the full path only, so that is
# the only path entitled to say anything about what is running.
if [ "$AUX_LEFT_ALONE" = 1 ]; then
  say "not updated, by design: the database${SKIPPED:+ · left alone (explicit service list):$SKIPPED}"
else
  say "not updated, by design: the database${SKIPPED:+ · not running here:$SKIPPED}"
fi

# ── TEST ON WHAT WE SHIP, WHEN ASKED ────────────────────────────────────────────────────
# The Mac suite runs on arm64/macOS/OpenSSL 3.6.3; we ship x86_64/musl/OpenSSL 3.5.7. Six
# suites (hsm_sidecar, ldap, saml, acme_lifecycle, acme_eab, lab_replication_mesh) cannot
# run on the Mac at all and were absent from every "168/168 green" we ever reported.
# lab-test.sh runs the whole suite inside a container built FROM the image just rolled, so
# the binaries, libc and OpenSSL under test are the ones now serving.
#
# ⚠️ OPT-IN: RUN_LAB_TEST=1. An operator's update is the rolled services answering, which the
# loop above already verified; the suite is a release-validation step that takes hours and
# needs tests/ beside deploy/, which a release tree does not ship. Run by default, every
# production update became a multi-hour job, or a failure on a tree without tests. The lab
# and a release candidate ask for it explicitly. (The container gate, tests/run-in-container.sh,
# is where an image is verified before it is ever rolled.)
#
# Invoked as `bash "$LAB_TEST"` and found with `-f`, never `-x`: lab-test.sh is committed
# 100644, and a `-x` test once meant the suite silently never ran.
LAB_TEST="$(dirname "$0")/lab-test.sh"
if [ "${RUN_LAB_TEST:-}" = "1" ]; then
  if [ ! -f "$LAB_TEST" ]; then
    echo "ERROR: RUN_LAB_TEST=1 but there is no lab-test.sh beside this script — the rolled" >&2
    echo "       image was NOT tested. Run from a source checkout to test it." >&2
    exit 1
  fi
  say "running the full suite against the image just rolled (RUN_LAB_TEST=1)"
  if FASTPKI_IMAGE="${FASTPKI_IMAGE:-}" bash "$LAB_TEST"; then
    say "suite green on the shipped image"
  else
    echo "WARN: the suite FAILED against the rolled image. The services are up and serving" >&2
    echo "      — this does not roll them back — but do not hand this build on" >&2
    echo "      until it is explained." >&2
    exit 1
  fi
fi
