#!/bin/sh
# node-run.sh — start one FastPKI process inside an fastpki-node pod.
#
#   command: ["/bin/sh", "/scripts/node-run.sh", "fastpki-web", "--config", "/app/config/bootstrap.conf"]
#
# Two things a Compose host gets from its .env and from depends_on, which a container in a pod
# does not get by itself:
#
#   STANDBY_OF   the pod this one's database follows, from /var/pki/standby_of on the pod's
#                own claim (start-postgres.sh writes it when it seeds, and removes it when the
#                pod is a primary). The console reports it, which is how the Replication page
#                knows the pod's role. It is read at start, which is why a promotion restarts
#                the containers that report it.
#   the database  every container of the pod starts at once, beside this pod's own Postgres,
#                so a process that resolves its keys and certificates at startup waits for a
#                read-write database first instead of crash-looping into a back-off.
#
# ⚠️ AND THIS SCRIPT STAYS PID 1, SO `kubectl exec -c <name> -- kill 1` RESTARTS THE CONTAINER.
# The FastPKI binaries install no signal handlers, and the kernel delivers a signal to a PID
# namespace's init from inside that namespace only if init handles it — so an exec'd binary as
# PID 1 ignores `kill 1` and even `kill -9 1`, measured in the shipped image. That is the one
# restart a listener has that leaves the pod's database running: after a certificate is
# re-issued (apply.sh), after a promotion (pg-promote.sh). The shell traps the signal and passes
# it to the process, which exits, and the kubelet starts the container again. It also makes a
# pod's own termination prompt instead of waiting out the grace period for a SIGKILL.
set -eu

if [ -r /var/pki/standby_of ]; then
    STANDBY_OF="$(tr -d '[:space:]' < /var/pki/standby_of)"
    [ -n "$STANDBY_OF" ] && export STANDBY_OF
fi

_child=""
_stop() {
    [ -n "$_child" ] && kill -TERM "$_child" 2>/dev/null
    [ -n "$_child" ] || exit 143
}
trap _stop TERM INT

# `list`, not `get <KEY>`: get exits 1 for a key with no row in the overlay, which is the
# ordinary state of a new deployment, and this would then wait for ever on a healthy database.
# The conninfo carries target_session_attrs=read-write, so a connection is a read-write one.
_n=0
until fastpki-config --config /app/config/bootstrap.conf list >/dev/null 2>&1; do
    _n=$((_n + 1))
    [ $((_n % 20)) = 1 ] && echo "node-run: waiting for a read-write database before starting $1"
    sleep 3
done

set +e
"$@" &
_child=$!
# `wait` returns early when the trapped signal arrives; wait again for the process to exit, so
# the container's exit status is the process's own.
wait "$_child"
_rc=$?
while kill -0 "$_child" 2>/dev/null; do
    wait "$_child"
    _rc=$?
done
exit "$_rc"
