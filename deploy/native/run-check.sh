#!/bin/sh
# deploy/native/run-check.sh — BOOT the native deployment locally and prove it works.
#
#   ../native/build-check.sh --image fastpki-baked:local   # bake first (~20 min)
#   ./run-check.sh                                         # then boot and check (~3 min)
#   ./run-check.sh --keep                                  # leave the container running
#
# ── WHAT THIS IS FOR ──────────────────────────────────────────────────────────────────
#
# build-check.sh proves the image BUILDS. It does not prove the deployment RUNS, and
# neither does `packer build` — the cloud bake never starts a service either. Everything
# about the native path that is genuinely new therefore had no coverage at all: OpenRC
# supervising the binaries, the token server handing its socket to the runtime user,
# PostgreSQL coming up on a certificate certgen self-signed minutes earlier, and the
# crash-only restart cycle.
#
# All of that is answerable in a privileged container with OpenRC, for free, in about
# three minutes. So it is answered here rather than deferred to a running cloud instance.
#
# ⚠️ THE HEADLINE ASSERTION IS THE SUPERVISOR. FastPKI exits with status 0 on purpose when
# a protocol is switched off in the console, and expects to be brought back. OpenRC's
# DEFAULT supervisor does not respawn at all, and supervise-daemon's DEFAULT respawn_max
# is a budget of ten. Measured in this very container: start-stop-daemon started a
# cleanly-exiting service once and never again; supervise-daemon with the default budget
# gave up after six; with respawn_max=0 it was still going at fourteen. That is the
# difference between "switch a protocol back on in the console" and "the protocol is
# permanently down with nothing in any log". It is asserted here against a REAL FastPKI
# service, not a stand-in.
#
# ── WHAT IT STILL CANNOT TELL YOU ─────────────────────────────────────────────────────
#
# A container is not an instance: no cloud-init, no ENA or NVMe driver, no bootloader, no
# kernel of its own. For cloud-init and the bootloader the substitute is local and one step
# away — deploy/cloud/image/build-qemu.sh emits the same image as a bootable disk and
# deploy/cloud/boot-check.sh boots it under QEMU, which is where first boot, the answers
# file and surviving a reboot are actually asserted. What remains genuinely AWS-only is the
# hardware surface: the ENA and NVMe drivers, and AMI registration.
set -eu

case "$0" in
    */*) HERE="$(cd "${0%/*}" && pwd)" ;;
    *)   HERE="$(pwd)" ;;
esac

IMAGE="${FASTPKI_BAKED_IMAGE:-fastpki-baked:local}"
NAME=fastpki-run-check
KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --image) IMAGE="${2:?--image needs a tag}"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

command -v docker >/dev/null 2>&1 || { echo "run-check: docker is not on PATH" >&2; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || {
    echo "run-check: no image '$IMAGE'." >&2
    echo "  Bake one first:  sh $HERE/build-check.sh --image $IMAGE" >&2
    exit 1; }

pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
dex(){ docker exec "$NAME" sh -c "$1"; }
dexq(){ docker exec "$NAME" sh -c "$1" 2>/dev/null || true; }
# ⚠️ A YES/NO ABOUT THE CONTAINER IS AN EXIT STATUS, AND dexq CANNOT GIVE ONE. dexq ends in
# `|| true` so that a failed command still yields its output, which makes it ALWAYS succeed.
# Every wait loop here was built on it, so "wait until listening" (`&& break`) stopped at
# once and "wait until closed" (`|| break`) never stopped early. The switch-on cell therefore
# asked once, straight after the switch, before the service's 10s re-check could run, and
# reported a service that came back seconds later as failed.
dexs(){ docker exec "$NAME" sh -c "$1" >/dev/null 2>&1; }

cleanup() {
    if [ "$KEEP" = 1 ]; then
        echo "==> container kept as $NAME (docker exec -it $NAME sh)" >&2
    else
        docker rm -f "$NAME" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

docker rm -f "$NAME" >/dev/null 2>&1 || true
echo "==> booting $IMAGE with OpenRC" >&2
# --privileged, because OpenRC wants to mount its own cgroup and tmpfs bookkeeping, and
# supervise-daemon needs to signal processes it did not fork directly. A container is the
# cheapest thing that has a real init and real service supervision; the alternative is a VM.
#
# ⚠️ --init, BECAUSE `sleep infinity` AS PID 1 REAPS NOTHING. supervise-daemon forks to
# detach, and the parent it leaves behind is reparented to PID 1 and becomes a zombie that a
# real init would collect. `supervise-daemon --stop` then waits on it for ever. Nothing here
# stopped a service until the installer's P11_TLS path did — it starts the token early for
# certgen and stops it again before the final start — and the install hung at
# `rc-service fastpki-token stop` with a defunct [supervise-daemo] as the only trace.
docker run -d --init --privileged --name "$NAME" "$IMAGE" sh -c '
    mkdir -p /run/openrc && touch /run/openrc/softlevel
    openrc default >/dev/null 2>&1 || true
    exec sleep infinity' >/dev/null

# ── 1. the installer runs end to end ──────────────────────────────────────────────────
echo "=== 1. fastpki-install-native completes on a bare baked image ==="
docker exec -i "$NAME" sh -c 'cat > /root/answers.env' <<'ANS'
DEPLOYMENT=single
PKI_DNS=pki.local
PG_LOCAL=yes
PG_BIND=127.0.0.1
P11_TLS=on
KEY_BACKEND=softhsm
WANT_EST=yes
WANT_ACME=no
WANT_CMP=no
WANT_SCEP=no
WANT_MS=no
WANT_STORE=no
ANS
set +e
docker exec "$NAME" fastpki-install-native --answers /root/answers.env > /tmp/run-check-install.log 2>&1
irc=$?
set -e
chk "the installer exits 0" 0 "$irc"
[ "$irc" -eq 0 ] || { echo "  --- last 30 lines ---"; tail -30 /tmp/run-check-install.log | sed 's/^/  /'; }

# ── 2. the pieces the installer was supposed to create ────────────────────────────────
echo "=== 2. what the installer built ==="
chk "the p11-kit socket exists"      yes "$(dexq '[ -S /run/p11/pkcs11.sock ] && echo yes || echo no')"
chk "the token PIN file is 0400"     400 "$(dexq 'stat -c %a /var/pki/tls/pin 2>/dev/null')"
chk "the config is 0640"             640 "$(dexq 'stat -c %a /etc/fastpki/bootstrap.conf 2>/dev/null')"
chk "the OpenRC settings are 0600"   600 "$(dexq 'stat -c %a /etc/conf.d/fastpki 2>/dev/null')"
chk "PostgreSQL is accepting"        yes "$(dexq 'su postgres -s /bin/sh -c "pg_isready -q" && echo yes || echo no')"
chk "PostgreSQL is serving TLS"      on  "$(dexq 'su postgres -s /bin/sh -c "psql -tAc \"show ssl\"" 2>/dev/null')"
# Single quotes outside, double inside, and no literal in the SQL — nesting three levels
# of quoting through `docker exec sh -c` and `su -c` is how these assertions end up
# testing the shell rather than the database.
chk "the schema is loaded"           yes \
    "$(dexq 'su postgres -s /bin/sh -c "psql -d fastpki -tAc \"select count(*) from certs\""' | grep -qE '^[0-9]+$' && echo yes || echo no)"
chk "the console admin is seeded"    1   \
    "$(dexq 'su postgres -s /bin/sh -c "psql -d fastpki -tAc \"select count(*) from web_users\""' | tr -d ' ')"
# `rc-update show default` lists what is ENABLED in the runlevel, which is the question —
# `rc-status` reports what is currently running, which is a different one.
chk "a declined protocol is not in the runlevel" no \
    "$(dexq 'rc-update show default 2>/dev/null | grep -q fastpki-scep && echo yes || echo no')"
chk "a chosen protocol IS in the runlevel" yes \
    "$(dexq 'rc-update show default 2>/dev/null | grep -q fastpki-est && echo yes || echo no')"

# ── 3. the services are actually up ───────────────────────────────────────────────────
echo "=== 3. the services are running and listening ==="
i=0; while [ "$i" -lt 30 ]; do
    dexs 'netstat -lnt 2>/dev/null | grep -q ":8090 "' && break
    sleep 2; i=$((i+1))
done
chk "the console is listening on 8090" yes \
    "$(dexq 'netstat -lnt 2>/dev/null | grep -q ":8090 " && echo yes || echo no')"
chk "the console serves HTTPS"         yes \
    "$(dexq 'curl -sk -o /dev/null -w %{http_code} https://127.0.0.1:8090/ 2>/dev/null' | grep -qE '^(200|302|401)$' && echo yes || echo no)"
chk "OCSP is listening on 8080"        yes \
    "$(dexq 'netstat -lnt 2>/dev/null | grep -q ":8080 " && echo yes || echo no')"
chk "fastpki-web is supervised"        yes \
    "$(dexq 'rc-service fastpki-web status 2>&1' | grep -qi 'started\|running' && echo yes || echo no)"

# ── 4. THE CRASH-ONLY CYCLE, on a real service ────────────────────────────────────────
# Switch OCSP off in the config table. Within kPoll (10s) the watcher exits(0); the
# supervisor must bring the process back, and it must come back with its PORT SHUT,
# blocked at the start gate. Then switch it on and it must start listening again.
#
# Under start-stop-daemon the process would never return, and `rc-service status` would
# say "crashed" forever. That is the whole reason these services use supervise-daemon.
echo "=== 4. a protocol switched off exits, is respawned, and comes back idle ==="
# ⚠️ RAISE THE LOG LEVEL FIRST, because the process that has to answer this section is the one
# the switch-off restarts, and a service reads LOG_LEVEL at startup. These deployments run at
# err, where the gate's whole vocabulary — "switched off — stopping", "not listening,
# re-enable it in the console", "switched back on — starting the listener" — is info and
# therefore absent. That is why a failure here has twice been reported with an empty log and
# no way to tell a blocked gate from a process that never reached it.
dexq 'fastpki-config --config /etc/fastpki/bootstrap.conf set LOG_LEVEL info >/dev/null 2>&1'
dexq 'fastpki-config --config /etc/fastpki/bootstrap.conf set OCSP_ENABLED false >/dev/null 2>&1'
i=0; while [ "$i" -lt 20 ]; do
    dexs 'netstat -lnt 2>/dev/null | grep -q ":8080 "' || break
    sleep 2; i=$((i+1))
done
chk "the port closes after the switch-off" yes \
    "$(dexq 'netstat -lnt 2>/dev/null | grep -q ":8080 " && echo no || echo yes')"
chk "the service is still supervised (respawned, not dead)" yes \
    "$(dexq 'rc-service fastpki-ocsp status 2>&1' | grep -qi 'started\|running' && echo yes || echo no)"
dexq 'fastpki-config --config /etc/fastpki/bootstrap.conf set OCSP_ENABLED true >/dev/null 2>&1'
# Up to 180s. A deployment completes this cycle in seconds: the gate logs "switched off —
# stopping", the supervisor respawns the process, the new one blocks with its port closed, and
# it binds within its 10s re-check after the switch-on. The ceiling only bounds a failure.
# When the port is still closed, the log is printed: these services run at LOG_LEVEL=err, so
# without the level raised above the cell would fail with nothing recorded anywhere.
i=0; while [ "$i" -lt 90 ]; do
    dexs 'netstat -lnt 2>/dev/null | grep -q ":8080 "' && break
    sleep 2; i=$((i+1))
done
_back="$(dexq 'netstat -lnt 2>/dev/null | grep -q ":8080 " && echo yes || echo no')"
[ "$_back" = yes ] && echo "  (it came back after about $((i * 2))s)"
chk "it listens again once switched back on" yes "$_back"
if [ "$_back" != yes ]; then
    echo "  --- it did not come back within 180s; fastpki-ocsp log:"
    dexq 'tail -20 /var/log/fastpki/fastpki-ocsp.log 2>/dev/null' | sed 's/^/  /'
    echo "  --- supervisor and processes:"
    dexq 'rc-service fastpki-ocsp status 2>&1; ps -o pid,args 2>/dev/null | grep "[f]astpki-ocsp"' | sed 's/^/  /'
fi

# ── 5. THIS HOST'S OWN IDENTITY REACHES THE SERVICES ──────────────────────────────────
# PG_BIND names the machine: the services publish their token-transport certificates, report
# to the Replication page and run key sync under it, falling back to PKI_DNS — which the two
# hosts of an HA pair share. It sat in a conf.d the init scripts source without exporting, so
# every native host used PKI_DNS, and a pair's second host overwrote the first's transport
# certificates. Asserted against the running services, because whether an OpenRC export
# survives supervise-daemon and command_user is a question only a real boot answers.
# (SQL goes in on stdin: literals inside three levels of shell quoting test the shell.)
echo "=== 5. PG_BIND, P11_TLS and STANDBY_OF reach the services ==="
sql(){ printf '%s\n' "$1" | docker exec -i "$NAME" su postgres -s /bin/sh -c 'psql -d fastpki -tAq' 2>/dev/null || true; }
chk "the installer wrote PG_BIND to conf.d" yes \
    "$(dexq 'grep -qx PG_BIND=127.0.0.1 /etc/conf.d/fastpki && echo yes || echo no')"
chk "fastpki-web runs with it in its environment" yes \
    "$(dexq 'tr "\0" "\n" < /proc/$(pidof fastpki-web | cut -d" " -f1)/environ | grep -qx PG_BIND=127.0.0.1 && echo yes || echo no')"
chk "the transport certificates are published under PG_BIND, not PKI_DNS" 127.0.0.1 \
    "$(sql "select string_agg(host_id, ',') from p11_transport;")"
i=0; while [ "$i" -lt 45 ]; do
    [ "$(sql "select count(*) from node_status where host_id = '127.0.0.1' and report like '%\"p11_tls\":true%';")" = 1 ] && break
    sleep 2; i=$((i+1))
done
chk "the console reports under PG_BIND, with P11_TLS on" 127.0.0.1 \
    "$(sql "select string_agg(host_id, ',') from node_status where report like '%\"p11_tls\":true%';")"
dexq 'printf "STANDBY_OF=127.0.0.1\n" >> /etc/conf.d/fastpki; rc-service fastpki-web restart >/dev/null 2>&1'
i=0; while [ "$i" -lt 45 ]; do
    [ "$(sql "select count(*) from node_status where host_id = '127.0.0.1' and report like '%\"standby_of\":\"127.0.0.1\"%';")" = 1 ] && break
    sleep 2; i=$((i+1))
done
chk "a standby's STANDBY_OF reaches the console's report" 1 \
    "$(sql "select count(*) from node_status where host_id = '127.0.0.1' and report like '%\"standby_of\":\"127.0.0.1\"%';")"
# The nightly job: with no CA yet there is nothing to copy, so key sync finishes at once — and
# records its result under the host id it was given.
dexq '/etc/periodic/daily/fastpki-certrenew > /tmp/certrenew.log 2>&1'
chk "the nightly job runs key sync" yes \
    "$(dexq 'grep -q "key sync: this node holds every key" /tmp/certrenew.log && echo yes || echo no')"
chk "  and records it under PG_BIND" 127.0.0.1 \
    "$(sql "select string_agg(host_id, ',') from node_status where key_sync_at > 0;")"

echo
echo "=== NATIVE RUN CHECK: PASS=$pass FAIL=$fail ==="
# ⚠️ KEEP THIS IN STEP WITH THE HEADER BLOCK ABOVE, which states the coverage correctly.
# This line used to call cloud-init and the bootloader "not coverable locally", which sends
# an operator to spend a cloud instance-hour on coverage the repository already provides for
# free, and reads as licence to skip boot-check.sh — the only check in the tree that can show
# the "first boot works, second does not" failure, because a container is destroyed between
# runs by design. Only the hardware surface is genuinely AWS-only.
echo "  Not covered HERE, because a container is not an instance: cloud-init, the bootloader"
echo "  and a kernel of its own. Those are asserted locally by deploy/cloud/boot-check.sh,"
echo "  which boots the same image under QEMU and also proves it survives a reboot:"
echo "    deploy/cloud/image/build-qemu.sh && deploy/cloud/boot-check.sh"
echo "  Genuinely needs a real instance: the ENA and NVMe drivers, and AMI registration."
[ "$fail" -eq 0 ] || exit 1
