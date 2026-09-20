#!/usr/bin/env bash
# pg_priv.sh — run the Postgres SERVER binaries from a suite that is running as root.
#
# ⚠️ WHY THIS EXISTS, AND WHAT IT WAS HIDING.
#
# initdb, pg_ctl and pg_basebackup refuse to run as root, by design:
#
#     initdb: error: cannot be run as root
#     hint: Please log in (using, e.g., "su") as the (unprivileged) user that will
#           own the server process.
#
# `tests/run_all.sh` runs as root inside the shipped image — `deploy/lab-test.sh`
# starts the test container with no `--user`. So every suite that creates its OWN
# throwaway cluster hit that refusal, printed its "SKIP: initdb failed" line, and
# exited 0. Measured in-image at 593c02b:
#
#     pg_reconnect.sh        SKIP: initdb did not produce a data dir
#     acme_reconnect.sh      SKIP: initdb did not produce a data dir
#     replication_stream.sh  SKIP: could not start the throwaway clusters
#     ha_failover.sh         SKIP: initdb failed (no usable Postgres)
#
# Those four are the reconnect, replication and HA suites — the ones that cover the
# mesh, which is the part of the product only a DC can exercise. They asserted
# NOTHING in the in-image tier, on every run since that tier was written, while the
# run reported `197 passed` and counted all four among the 197. run_all.sh does say
# `(SKIPPED — asserted nothing)` on each line, so the accounting was never a lie —
# but a skip whose cause is the harness rather than the machine reads exactly like
# "this environment cannot run it", and nobody looked again.
#
# The fix is the one the product's own compose already uses for the same problem
# (`command -v gosu || command -v su-exec`, then `$AS postgres postgres …`): drop to
# an unprivileged user for the server, stay root for everything else. The client
# binaries — psql, createdb, pg_isready — do not care and are left alone.
#
# ⚠️ ON A DEVELOPER MACHINE NOTHING HERE FIRES. `id -u` is not 0, so `pg_as` is a
# passthrough and `pg_own` is a no-op; the Mac tier behaves byte-for-byte as before.
# That is also why this could only ever be verified in-image.

# The account the server runs as when we are root. `postgres` (uid 70) exists in the
# product image because the Postgres packages create it; `nobody` is the fallback for
# a base that does not.
#
# !! RESOLVED ON FIRST USE, NOT AT SOURCE TIME, AND UNDER A DEADLINE. Both halves of
# this matter and both were learned the hard way.
#
# Sourcing must have no side effects: this file is pulled in by pg_helpers.sh, which
# the clients demo sources before it prints anything at all. Anything that blocks here
# blocks the caller with an empty screen -- no banner, no error, nothing to report but
# "it just sits there". A helper being sourced is not permission to run a program.
#
# And `id` and `su` are both able to block indefinitely. They are not local lookups:
# every NSS backend the host has configured answers them, so an unreachable LDAP or
# SSSD makes `id postgres` wait, and `su` additionally runs the whole PAM stack, which
# on a systemd host talks to logind over dbus. None of that can happen on a developer
# Mac -- `id -u` is not 0 there, so nothing below even runs -- which is exactly why an
# unbounded call could sit here looking harmless.
_PG_PRIV_USER=""
_PG_PRIV_OK=""
_PG_PRIV_READY=""

# Run a command with a deadline, in portable shell. NOT `timeout`: that is a coreutils
# program and macOS does not ship it, so depending on it would trade a hang on Linux
# for a "command not found" on the Mac.
_pg_priv_bounded() {   # <seconds> <cmd...>
    local secs=$1; shift
    "$@" >/dev/null 2>&1 &
    local pid=$! waited=0
    while [ "$waited" -lt "$secs" ] && kill -0 "$pid" 2>/dev/null; do
        sleep 1; waited=$((waited+1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
        return 124
    fi
    wait "$pid"
}

_pg_priv_init() {
    [ -z "$_PG_PRIV_READY" ] || return 0
    _PG_PRIV_READY=1
    # ⚠️ COMPARE AS A STRING, and record when the answer is missing rather than empty.
    # This was `[ "$(id -u)" -eq 0 ]`. When the command substitution came back EMPTY --
    # observed in a full sharded run, where six containers fork concurrently -- `-eq`
    # aborted with
    #     pg_priv.sh: line 82: [: : integer expected
    # printed into the middle of an unrelated suite's output, and the non-zero status
    # then took the `|| return 0` path. So the privilege drop silently did not happen,
    # every server binary ran as root, initdb refused, and the suite skipped citing a
    # missing Postgres. A string comparison cannot abort, and the reason is kept for
    # pg_priv_reason() so the skip names THIS instead of blaming the environment.
    local _uid; _uid=$(id -u 2>/dev/null || true)
    if [ -z "$_uid" ]; then
        _PG_PRIV_WHY="could not determine the current uid (id -u returned nothing)"
        return 0
    fi
    [ "$_uid" = "0" ] || return 0
    local _u
    for _u in postgres nobody; do
        if _pg_priv_bounded 5 id "$_u"; then _PG_PRIV_USER="$_u"; break; fi
    done
    [ -n "$_PG_PRIV_USER" ] || return 0
    _pg_priv_bounded 10 _pg_priv_run true && _PG_PRIV_OK=1
}

# ⚠️ `su`, NOT `setpriv`. The first version of this file used setpriv when
# `command -v setpriv` found it, and every suite still skipped — because the
# shipped image is Alpine and its setpriv is BUSYBOX setpriv, which has no
# user-switching options at all:
#
#     setpriv: unrecognized option: reuid=postgres
#     Usage: setpriv [OPTIONS] PROG ARGS
#       -d,--dump / --nnp / --inh-caps / --ambient-caps        <- capabilities only
#
# The NAME being on PATH said nothing about the FEATURE existing, and the failure
# looked identical to "no Postgres here". `su -s /bin/sh <user> -c` is what the
# initdb hint itself recommends, it is present on Alpine and macOS alike, and it
# was measured working in the image before this was written.
#
# It takes a single shell string rather than an argv, so every argument is re-quoted
# with printf %q: a data directory under
# /var/folders/rw/c2glhg_j7l3457lmxdgnqxwm0000gn/T/… is a real macOS path and one
# unquoted space would silently start the server on the wrong directory.
#
# PATH and LC_ALL are carried across explicitly. ha_failover.sh calls `initdb` and
# `pg_ctl` by bare name, and su resets the environment, so without PATH the drop
# would turn "refuses as root" into "command not found" — the same dead end wearing
# a third message.
_pg_priv_run() {
    local q="" a
    for a in "$@"; do q="$q $(printf '%q' "$a")"; done
    su -s /bin/sh "$_PG_PRIV_USER" -c \
       "export PATH=$(printf '%q' "$PATH") LC_ALL=$(printf '%q' "${LC_ALL:-}"); exec$q"
}

# Whether the drop actually works here is still PROVED by running something rather
# than inferred from a binary being installed -- that inference is what made the first
# version of this file report a wrong cause on its own failure. What changed is only
# WHEN: _pg_priv_init above runs it on first use, under a deadline, so the proof costs
# nothing until a caller actually needs to drop privileges.

# pg_own <path>... — give the unprivileged account ownership of a directory the
# server will write into. A no-op unless we are root.
#
# ⚠️ REQUIRED, NOT COSMETIC. `mktemp -d` returns a 0700 directory owned by root, so
# the dropped-privilege initdb cannot create its data directory inside it and fails
# with a permission error instead of the root error — a different message for the
# same dead end.
pg_own() {
    _pg_priv_init
    [ -n "$_PG_PRIV_USER" ] || return 0
    chown -R "$_PG_PRIV_USER" "$@" 2>/dev/null || true
}

# pg_as <command> [args...] — run one Postgres server binary, unprivileged when root.
# A plain passthrough when we are not root, or when no working drop is available (in
# which case the binary's own root refusal is the honest outcome, and pg_priv_reason
# below can name why).
pg_as() {
    _pg_priv_init
    if [ -z "$_PG_PRIV_OK" ]; then "$@"; return $?; fi
    _pg_priv_run "$@"
}

# pg_priv_reason — one line naming which dead end a suite hit, for the skip message.
# Without it "initdb failed" is indistinguishable from "no Postgres installed", which
# is precisely how the four suites above stayed invisible for so long.
pg_priv_reason() {
    _pg_priv_init
    # Same string comparison as _pg_priv_init, and for the same reason: this function
    # exists to explain a failure, so it must not abort with one of its own.
    [ -z "$_PG_PRIV_WHY" ] || { echo "$_PG_PRIV_WHY"; return; }
    local _uid; _uid=$(id -u 2>/dev/null || true)
    if [ "$_uid" = "0" ] && [ -z "$_PG_PRIV_OK" ]; then
        if [ -z "$_PG_PRIV_USER" ]; then
            echo "running as root and no postgres or nobody account exists to drop to"
        else
            echo "running as root and 'su $_PG_PRIV_USER' does not work in this image"
        fi
        return
    fi
    echo "no usable Postgres server binaries"
}
