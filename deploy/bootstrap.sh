#!/bin/sh
# deployment-path: compose-only — native bootstraps inside install-native.sh; Kubernetes in each server pod's init container (k8s/node-init.sh) and apply.sh's admin seed
# One-time FastPKI bootstrap, run inside the image (POSIX sh — the runtime image
# has no bash). Prepares the shared /var/pki volume and a first EST/MS auth user.
# Idempotent: each step is skipped if its output already exists. See docs/deployment.md §4.
#
#   docker compose run --rm bootstrap
#
# A fresh deployment starts with NO CAs. The admin's
# first job is to create the root and sub CAs from the console — with the key
# stored where they prefer (software / PKCS#11 / Vault). So this script no longer
# mints a CA hierarchy or CA-signed TLS certs. The console comes up over HTTPS on
# the self-signed transport cert certgen generated (web.crt); the other
# TLS-terminating services (EST/ACME/MS) stay down until the admin has created a
# CA and issued certs for them.
#
# Runs AFTER `up -d postgres` (it seeds the DB console admin). certgen must have
# run before postgres — see docker-compose.yml.
set -eu

# Paths default to the container's /var/pki + /app/config, but are overridable
# (PKI_DIR / PKI_CONF) so the bootstrap can be exercised outside a container in tests
# The seed retry budget is overridable too, for the same reason.
PKI_DIR="${PKI_DIR:-/var/pki}"
CADIR="$PKI_DIR/ca"
TLSDIR="$PKI_DIR/tls"
CONF="${PKI_CONF:-/app/config/bootstrap.conf}"
SEED_RETRIES="${BOOTSTRAP_SEED_RETRIES:-30}"
SEED_DELAY="${BOOTSTRAP_SEED_DELAY:-2}"

mkdir -p "$CADIR" "$TLSDIR"

# Default admin (web_users) — the ONLY user store. One row serves both the
# console and EST/MS Basic auth: pki::authenticate() resolves every username against
# web_users, so there is no separate PBKDF2 users file to seed.
# admin/admin, and it is FORCED TO CHANGE on first login. A permanent,
# well-known credential on a PKI product is the weak-default class that draws a CVE,
# so `--must-reset` is not optional here: the console lets that session reach only
# /api/me, /api/password and /api/logout until the password is changed, and
# pki::authenticate() refuses the row outright so the same credential cannot enrol a
# certificate over EST/MS/SCEP/CMP in the meantime.
# --if-absent keeps it idempotent: a re-run must NOT reset the
# password of an admin who has already changed it. Connects to Postgres over the
# TLS conninfo in bootstrap.conf, so both certgen and `up -d postgres` must precede this.
# Retry the seed until Postgres accepts a TLS-authenticated connection, and
# FAIL LOUDLY if it never does. The wait-postgres gate uses `pg_isready`, which only
# proves the TCP port is open — NOT that the TLS handshake + auth + DB are ready — so a
# one-shot seed here can hit a not-yet-ready server. The old `|| echo WARN` SWALLOWED
# that failure, leaving a deployment with no console admin and no error. Retrying the
# real operation (and exiting non-zero on exhaustion) means a broken deploy can't look
# clean. --if-absent returns success immediately on a re-run, so this stays idempotent.
echo "[bootstrap] seeding default console admin (admin/admin, must change on first login)"
seeded=0
i=0
while [ "$i" -lt "$SEED_RETRIES" ]; do
    if fastpki-config --config "$CONF" web-user admin admin --role admin --must-reset --if-absent; then
        seeded=1
        break
    fi
    i=$((i + 1))
    echo "[bootstrap] Postgres not ready for a TLS-authenticated connection yet — retry $i/${SEED_RETRIES}…"
    sleep "$SEED_DELAY"
done
# ⚠️ Record which protocols this deployment was BUILT with, in the DB.
# The build-time state of the optional protocols belongs in the DB as a config variable,
# so anything that depends on those protocols can check before committing to a job.
#
# It is deliberately NOT the same key as <PROTO>_ENABLED. That one is the runtime
# switch an operator flips in the console; this one says whether the container exists at
# all. Without the distinction the Endpoints page shows a protocol that was never installed
# exactly like one an admin turned off, and anything scheduling work for it — a renewal, a
# health check — has no way to know the difference.
#
# install.sh passes these through .env; compose puts them in the environment; here they
# become rows in `config`, which is the source of truth (§3f). Absent means installed, so
# a deployment that predates the wizard's question reads as fully installed, which it is.
for _p in EST ACME CMP SCEP MS STORE; do
    eval "_v=\${${_p}_INSTALLED:-}"
    [ -n "$_v" ] || continue
    fastpki-config --config "$CONF" set "${_p}_INSTALLED" "$_v" >/dev/null 2>&1 \
        && echo "[bootstrap] ${_p}_INSTALLED=$_v" \
        || echo "[bootstrap] WARNING: could not record ${_p}_INSTALLED" >&2
done

if [ "$seeded" -ne 1 ]; then
    echo "[bootstrap] ERROR: could not seed the console admin — Postgres never accepted a TLS-authenticated connection. Check that certgen ran and PG_CONNINFO has the right sslmode/sslrootcert." >&2
    exit 1
fi

# Hand the volume back to the unprivileged runtime user so the services (which run
# as fastpki) can read/write under /var/pki.
chown -R fastpki:fastpki "$PKI_DIR" 2>/dev/null || true
# ⚠️ tls/pg is NO LONGER re-chowned to the postgres uid, and must not be. The
# broad chown above is now the CORRECT end state: the console writes this pair when it
# issues the CA-signed Postgres certificate and it runs as `fastpki`, so handing the
# directory to uid 70 would lock the writer out of its own delivery point. Postgres
# reads a copy it makes and chowns inside its own container, so nothing out here needs
# to match its uid. The key still has to be 0600 wherever it lives; certgen sets that
# and the container's copy re-asserts it.
chmod 600 "$PKI_DIR/tls/pg/server.key" 2>/dev/null || true

echo "[bootstrap] done — /var/pki prepared (no CAs yet), console admin = admin/admin (you MUST set a new password at first login; until then it cannot enrol)."
echo "[bootstrap] create your first root/sub CA from the console (HTTPS, self-signed"
echo "[bootstrap] transport cert until you issue a real one)."
