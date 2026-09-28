#!/bin/sh
# renew-loop.sh — the renewal container of every fastpki-node pod: Compose's `certrenew` service.
#
# The same loop, for the same reasons, run by every server of the deployment, in this order:
#
#   certgen.sh --p11-only, then publish and sync
#       this pod's own token-transport pair, which nothing else renews
#   key sync --from-peers
#       every key this server needs and its token does not hold, from whichever other server
#       holds it. The rows arrive through streaming replication; no key ever does.
#   renew-service-certs --create-missing --re-issue-self-signed
#       the OCSP, CMP and SCEP credentials, the listeners' certificates and the database
#       certificate (the sweep owns it once PG_TLS_CA_ID names a CA). An advisory lock makes
#       one server do the work at a time.
#
# It replaced a CronJob that ran once for the whole deployment. That was the right shape while
# the deployment had one token; with a token per server each one has its own transport pair to
# renew and its own keys to converge, which a single Job pod cannot reach.
#
# ⚠️ AND THE POSTGRES TRUST BUNDLE, EVERY MINUTE, NOT ONLY WHEN THE LOOP COMES ROUND. pg-trust.sh
# caches this PKI's root CAs while the database connection works, and a peer's switch to a
# CA-issued database certificate is safe only if that root is already cached here — see the
# header of pg-trust.sh. A day between refreshes would be a day in which that switch can strand
# this pod.
set -u

CONF=/app/config/bootstrap.conf

( while :; do
    sh /scripts/pg-trust.sh --refresh-roots >/dev/null 2>&1 || true
    sleep 60
  done ) &

while :; do
    SOON=0
    CREATE=--create-missing

    # ⚠️ KEYS FIRST, THEN THE SWEEP. When a credential's row exists and its key is not in this
    # token, `renew-service-certs --create-missing` mints a replacement — the remedy for a server
    # nothing can copy the key to. Run before the sync, it was the ordinary state of a pair: the
    # second server replaced every credential the first had just made, the first replaced them
    # back on its next pass, and each night one server's OCSP, CMP and SCEP had keys only the
    # other held. So the sync runs first and the sweep may mint only when the sync says no retry
    # can help: 0 (nothing missing), 2 (never replicable), 3 (nobody to copy from).
    if [ "${P11_TLS:-off}" = "on" ]; then
        if sh /scripts/certgen.sh --p11-only; then
            fastpki-config --config "$CONF" p11-server-publish || \
                echo "could not publish this server's transport server certificate"
            fastpki-config --config "$CONF" p11-client-publish || \
                echo "could not publish this server's transport client certificate"
            fastpki-config --config "$CONF" p11-clients-sync >/dev/null 2>&1 || true
            fastpki-config --config "$CONF" p11-servers-sync >/dev/null 2>&1 || true
            # ⚠️ FROM EVERY OTHER SERVER, NOT ONLY FROM THE PRIMARY. The console's Service spreads
            # its requests across the servers, so a New CA form is served by either pod and the
            # CA's key is minted in THAT pod's token; so is a credential the sweep below mints on
            # whichever server took its lock. Syncing only standby-from-primary left those keys
            # out of the primary's token for ever. After the trust sync above, because
            # that is what admits this server to the others' tunnels. --from-peers never asks
            # another data center: in a mesh a replicable key is opt-in to bound blast radius.
            # Every server's token shares the Secret's PIN, so no --source-pin-file is needed.
            fastpki-ca --config "$CONF" key sync --from-peers
            case $? in
                0|2|3) ;;
                *) SOON=1; CREATE=""
                   echo "key sync did not complete — until it does, losing the other server can" \
                        "leave this one unable to sign, and no credential is re-minted here" ;;
            esac
        else
            CREATE=""
            echo "the token transport certificates are not being renewed — once they expire" \
                 "the mTLS tunnel stops handshaking"
        fi
    fi

    fastpki-ca --config "$CONF" renew-service-certs $CREATE --re-issue-self-signed || \
        echo "renew-service-certs failed (rc=$?) — retrying at the next tick"

    if [ "$SOON" = 1 ]; then sleep 300; else sleep 86400; fi
done
