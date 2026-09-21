#!/bin/sh
# node-init.sh — the init container of every fastpki-node pod, run as root once the pod's token is
# serving and before any service starts.
#
# It is the pod-sized form of what Compose does before `up`: `certgen` (the token PIN file,
# this pod's own token-transport keypair under P11_TLS, and the self-signed database
# certificate the pod starts on) and the file half of `bootstrap.sh` (the directories, handed
# to the unprivileged runtime user). The database half of bootstrap — the console admin —
# is run once for the deployment by apply.sh, because a pod's init container runs before that
# pod's own Postgres exists.
#
# ⚠️ PG_BIND IS THIS POD'S OWN NAME, `fastpki-node-N.fastpki-node`, and certgen puts it in the database
# certificate. Every application reaches every pod's database by exactly that name under
# sslmode=verify-full, so a certificate without it is refused by every peer — which is also
# what would leave a standby unable to seed. It is the same variable a Compose or native host
# sets to its own address, for the same reason.
set -eu

sh /scripts/certgen.sh

mkdir -p /var/pki/ca /var/pki/tls
chown -R fastpki:fastpki /var/pki
chmod 600 /var/pki/tls/pg/server.key 2>/dev/null || true

sh /scripts/pg-trust.sh
echo "[node-init] $PG_BIND prepared"
