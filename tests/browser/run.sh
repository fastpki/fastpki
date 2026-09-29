#!/bin/sh
# Drive the console of one FastPKI image in a real browser over a slow link.
#
#   tests/browser/run.sh <fastpki image> [delay ms per request, default 1000]
#
# Starts Postgres and fastpki-web from the image on a private Docker network, seeds three
# console accounts, and runs tests/browser/console_latency.js in Microsoft's Playwright image.
# Needs Docker and network access to pull postgres and the Playwright image; run it on a lab
# node, never on a workstation. Exits non-zero when the browser test fails.
set -u
IMG=${1:?usage: run.sh <fastpki image> [delay ms]}
DELAY=${2:-1000}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PW_IMG=${PW_IMG:-mcr.microsoft.com/playwright:v1.47.0-jammy}
PW_VER=${PW_VER:-1.47.0}
N=fcbrowser$$
CFG=$(mktemp -d)
cleanup() {
    docker rm -f "$N-pw" "$N-web" "$N-pg" >/dev/null 2>&1
    docker network rm "$N" >/dev/null 2>&1
    rm -rf "$CFG"
}
trap cleanup EXIT

docker network create "$N" >/dev/null
docker run -d --name "$N-pg" --network "$N" -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=fastpki \
    postgres:17-alpine >/dev/null
i=0; until docker exec "$N-pg" pg_isready -U postgres -d fastpki >/dev/null 2>&1; do
    i=$((i+1)); [ $i -gt 60 ] && { echo "postgres did not start"; exit 1; }; sleep 1; done
sleep 2
docker exec -i "$N-pg" psql -q -U postgres -d fastpki -v ON_ERROR_STOP=1 < "$ROOT/sql/createdb.sql" \
    >/dev/null || { echo "createdb.sql failed"; exit 1; }

chmod 755 "$CFG"
printf 'PG_CONNINFO=host=%s-pg user=postgres password=pw dbname=fastpki\nWEB_BIND=0.0.0.0\nWEB_PORT=8090\nWEB_ALLOW_REVOKE=true\nLOG_LEVEL=info\n' \
    "$N" > "$CFG/bootstrap.conf"
chmod 644 "$CFG/bootstrap.conf"
for u in admin:admin alice:requester bob:requester; do
    docker run --rm --network "$N" -v "$CFG:/cfg:ro" --entrypoint fastpki-config "$IMG" \
        --config /cfg/bootstrap.conf web-user "${u%%:*}" 'Passw0rd!' --role "${u#*:}" >/dev/null \
        || { echo "seeding ${u%%:*} failed"; exit 1; }
done
docker run -d --name "$N-web" --network "$N" -v "$CFG:/cfg:ro" --entrypoint fastpki-web "$IMG" \
    --config /cfg/bootstrap.conf >/dev/null
sleep 3
docker ps --filter "name=$N-web" --format '{{.Status}}' | grep -q Up \
    || { echo "fastpki-web did not start:"; docker logs "$N-web" 2>&1 | tail -20; exit 1; }
# The browser runs in its own container, and RTT_MS of real network delay is added to THAT
# container's interface: between the browser and the console, as over a long link, and not
# between the console and Postgres, which sit on one host in every deployment. (Delaying the
# console's own interface also delayed each of its database queries, and answers took 9-15 s.)
docker run -d --name "$N-pw" --network "$N" --ipc=host -e NODE_PATH=/tmp/node_modules \
    -v "$ROOT/tests/browser:/t:ro" -w /tmp "$PW_IMG" sleep infinity >/dev/null
docker exec "$N-pw" sh -c "npm i -s --no-audit --no-fund playwright@$PW_VER >/dev/null 2>&1" \
    || { echo "could not install playwright $PW_VER"; exit 1; }
RTT_MS=${RTT_MS:-250}
if [ "$RTT_MS" -gt 0 ]; then
    docker run --rm --network "container:$N-pw" --cap-add NET_ADMIN alpine:3.24 \
        sh -c "apk add -q iproute2 >/dev/null 2>&1 && tc qdisc add dev eth0 root netem delay ${RTT_MS}ms" \
        || { echo "could not add ${RTT_MS} ms of network delay"; exit 1; }
fi
docker exec -e BASE="http://$N-web:8090" -e DELAY_MS="$DELAY" -e BROWSER="${BROWSER:-chromium}" \
    -e IDLE_MS="${IDLE_MS:-}" -e DEBUG="${DEBUG:-}" "$N-pw" node /t/console_latency.js
rc=$?
[ $rc = 0 ] || { echo "--- fastpki-web log (last 20 lines) ---"; docker logs "$N-web" 2>&1 | tail -20; }
exit $rc
