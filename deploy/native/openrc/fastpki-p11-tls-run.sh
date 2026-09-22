#!/bin/sh
# fastpki-p11-tls-run.sh — exec stunnel for the token transport, carrying the environment
# OpenRC cannot hand it. Named by $command in fastpki-p11-tls.initd.
#
# ⚠️ stunnel NEEDS TWO THINGS AND OpenRC DELIVERS ONLY ONE. It must run as ${FASTPKI_USER} —
# p11-kit-server checks the peer uid, and since the transport key became a token object
# stunnel opens the token while BUILDING its TLS contexts, before its own `setuid` would
# apply — and it needs OPENSSL_CONF to see the pkcs11 provider at all plus
# P11_KIT_SERVER_ADDRESS to find the socket. command_user handles the uid; neither
# start_pre's `export` nor supervise_daemon_args="--env ..." reaches the child across that
# switch. Measured, all four combinations: as root it fails either way; as ${FASTPKI_USER}
# it fails without these two and reports "Configuration successful" with them.
#
# It is a SHIPPED file rather than one start_pre writes because OpenRC validates $command
# before start_pre runs, so a file created there does not exist yet and the service fails
# earlier, with no log line to say why.
set -u

# ⚠️ NOT `[ -r f ] && . f` under `set -e`: a false guard would become this script's exit
# status and it would die silently. conf.d is 0600 root — it carries the token PIN — so this,
# running unprivileged, normally cannot read it, and the defaults below are what apply.
if [ -r /etc/conf.d/fastpki ]; then
    . /etc/conf.d/fastpki
fi

: "${P11_SOCKET_DIR:=/run/p11}"
: "${P11_SOCKET:=${P11_SOCKET_DIR}/pkcs11.sock}"

OPENSSL_CONF="${P11_SOCKET_DIR}/stunnel-openssl.cnf"
P11_KIT_SERVER_ADDRESS="unix:path=${P11_SOCKET}"
export OPENSSL_CONF P11_KIT_SERVER_ADDRESS

exec /usr/bin/stunnel "${P11_SOCKET_DIR}/stunnel-p11.conf"
