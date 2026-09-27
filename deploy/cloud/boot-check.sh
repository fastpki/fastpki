#!/bin/sh
# boot-check.sh — BOOT the cloud image and prove a first boot actually configures a node.
#
#   image/build-qemu.sh                    # build the qcow2 (~20 min)
#   ./boot-check.sh --image <qcow2>        # boot it and check (~4 min)
#   ./boot-check.sh --image <qcow2> --keep # leave the VM running to poke at
#
# ── WHAT THIS IS FOR ──────────────────────────────────────────────────────────────────
#
# deploy/native/run-check.sh boots the baked image in a privileged container with OpenRC,
# which covers the supervisor and the services. It cannot cover the two things most likely
# to be wrong on a real first boot, and its own header says so: a container has no
# cloud-init and no kernel of its own.
#
# That left the artifact a cloud user actually boots with no local test at all, and the
# path every one of them takes — cloud-init hands the instance an answers file, the
# installer consumes it — asserted nowhere. provision.sh checks that the cloud-init
# SERVICE exists in the image and stops there.
#
# ⚠️ THE REBOOT IS THE POINT, not the first boot. "It came up once" is the easy half. A
# cloud image's whole promise is a durable instance, and "first boot works, second boot
# does not" is the classic way to break one — a token initialised into a tmpfs, a service
# not added to the runlevel, a database directory that was never persisted. Nothing else
# in this repository can catch that: a container is destroyed between runs by design.
#
# ⚠️ IT DOES NOT TEST THE OpenTofu TEMPLATE. deploy/cloud/aws/user-data.sh.tftpl is
# AWS-specific — it configures an interconnect ENI and a separate EBS data volume — and it
# is rendered by OpenTofu, not runnable here. What this shares with it, and what is checked
# here, is the contract underneath both: cloud-init delivers a KEY=VALUE answers file and
# `fastpki-install-native --answers` consumes it. If that contract breaks, both break.
set -eu

case "$0" in
    */*) HERE="$(cd "${0%/*}" && pwd)" ;;
    *)   HERE="$(pwd)" ;;
esac

IMAGE=""
KEEP=0
SSH_PORT=${FASTPKI_BOOT_SSH_PORT:-2222}
WEB_PORT=${FASTPKI_BOOT_WEB_PORT:-18090}
case "$(uname -s)" in
    Darwin) ACCEL=hvf ;;
    Linux)  [ -e /dev/kvm ] && ACCEL=kvm || ACCEL=tcg ;;
    *)      ACCEL=tcg ;;
esac

while [ $# -gt 0 ]; do
    case "$1" in
        --image) IMAGE="${2:?--image needs a qcow2}"; shift 2 ;;
        --accel) ACCEL="${2:?--accel needs kvm, hvf or tcg}"; shift 2 ;;
        --keep)  KEEP=1; shift ;;
        -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# Default to whatever build-qemu.sh last produced, so the common case needs no argument.
if [ -z "$IMAGE" ]; then
    IMAGE=$(ls -1 "$HERE"/image/output-qemu/*.qcow2 2>/dev/null | head -1 || true)
fi
[ -n "$IMAGE" ] && [ -f "$IMAGE" ] || {
    echo "boot-check.sh: no image. Build one first:" >&2
    echo "    $HERE/image/build-qemu.sh" >&2
    echo "  or name it with --image <qcow2>." >&2
    exit 1; }

for t in qemu-system-x86_64 qemu-img ssh-keygen; do
    command -v "$t" >/dev/null 2>&1 || { echo "boot-check.sh: $t is not installed" >&2; exit 1; }
done

pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

W="$(mktemp -d)"
VMPID=""
cleanup() {
    [ -n "$VMPID" ] && kill "$VMPID" 2>/dev/null || true
    [ "$KEEP" = 1 ] || rm -rf "$W"
}
trap cleanup EXIT INT TERM

# ⚠️ AN OVERLAY, NOT THE IMAGE. The VM writes to its disk, and a check that mutated the
# artifact would mean the second run tested something the first one had already changed —
# and, worse, that the thing shipped is not the thing tested.
qemu-img create -q -f qcow2 -F qcow2 -b "$(cd "$(dirname "$IMAGE")" && pwd)/$(basename "$IMAGE")" \
    "$W/disk.qcow2" >/dev/null

ssh-keygen -t ed25519 -N '' -C fastpki-boot-check -f "$W/id" >/dev/null

# ── the seed: exactly what a cloud instance is handed ──────────────────────────────────
#
# ⚠️ NO SECRETS IN THE ANSWERS, matching the OpenTofu template's reasoning: PG_PASSWORD and
# PKCS11_PIN are deliberately absent so the installer generates both from the node's
# CSPRNG. user-data is readable by anything on the instance that can reach the metadata
# service, so a token PIN protecting every CA key has no business in it.
cat > "$W/meta-data" <<EOF
instance-id: fastpki-boot-check
local-hostname: fastpki-boot-check
EOF
cat > "$W/user-data" <<EOF
#cloud-config
users:
  - name: alpine
    shell: /bin/sh
    # ⚠️ WITHOUT THIS cloud-init RUNS \`passwd -l alpine\` AND sshd REFUSES OUR KEY. The
    # account already exists in the image with a \`*\` shadow field, so cloud-init takes its
    # pre-existing-user path: it installs the key and still applies lock_passwd, which
    # defaults to true. OpenSSH with UsePAM unset — Alpine's default — refuses PUBLIC KEY
    # logins for an account whose shadow field begins \`!\`, not just password ones. The image
    # patches its own cloud.cfg against this, but only for the \`default\` user entry, and this
    # list does not name \`default\`.
    lock_passwd: false
    # No sudo or doas key here: the image already carries permit nopass :wheel and this
    # account is in wheel. Alpine's cloud image installs no sudo, so a sudo: key only
    # writes a sudoers file nothing can read.
    ssh_authorized_keys:
      - $(cat "$W/id.pub")
write_files:
  - path: /root/fastpki-answers.env
    permissions: '0600'
    content: |
      DEPLOYMENT=single
      PKI_DNS=fastpki-boot-check.test
      PG_LOCAL=yes
      PG_BIND=127.0.0.1
      KEY_BACKEND=softhsm
      P11_TLS=on
      WANT_EST=yes
      WANT_ACME=no
      WANT_CMP=no
      WANT_SCEP=no
      WANT_MS=no
      WANT_STORE=no
runcmd:
  - [ /bin/sh, -c, "/usr/local/bin/fastpki-install-native --answers /root/fastpki-answers.env >> /var/log/fastpki-firstboot.log 2>&1; echo \$? > /var/log/fastpki-firstboot.rc" ]
EOF

if command -v cloud-localds >/dev/null 2>&1; then
    cloud-localds "$W/seed.iso" "$W/user-data" "$W/meta-data"
elif command -v genisoimage >/dev/null 2>&1; then
    genisoimage -quiet -output "$W/seed.iso" -volid cidata -joliet -rock \
        "$W/user-data" "$W/meta-data"
elif command -v mkisofs >/dev/null 2>&1; then
    mkisofs -quiet -output "$W/seed.iso" -volid cidata -joliet -rock \
        "$W/user-data" "$W/meta-data"
else
    echo "boot-check.sh: need cloud-localds, genisoimage or mkisofs to build the seed" >&2
    exit 1
fi

# ⚠️ UEFI, because the image is the -uefi- cloud build. Booting it with the default SeaBIOS
# gets no bootloader and a black screen that looks exactly like a hung kernel. The helper
# resolves the same firmware pair image/build-qemu.sh built this disk with.
. "$HERE/ovmf-firmware.sh"

# ⚠️ A COPY OF THE VARIABLE STORE, for the reason the disk above is an overlay: UEFI WRITES
# to it, and the file the distribution ships is shared and read-only. A fresh copy per run
# also means the reboot below starts from the empty NVRAM a cloud instance is given rather
# than from whatever the first boot left behind.
cp "$OVMF_VARS" "$W/efivars.fd"

echo "=== booting $(basename "$IMAGE") (accel: $ACCEL, firmware: $(basename "$OVMF_CODE")) ==="
# ⚠️ THE SEED IS A CD ON THE MACHINE'S OWN CONTROLLER. `if=virtio` with `media=cdrom` asks
# virtio-blk for a media type it does not have; cloud-init's NoCloud datasource only needs a
# block device whose filesystem is labelled `cidata`, and a plain CD is what a cloud instance
# is handed.
qemu-system-x86_64 \
    -machine q35,accel="$ACCEL" -cpu max -m 2048 -smp 2 \
    -drive if=pflash,unit=0,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,unit=1,format=raw,file="$W/efivars.fd" \
    -drive file="$W/disk.qcow2",if=virtio,format=qcow2 \
    -drive file="$W/seed.iso",media=cdrom \
    -netdev user,id=n0,hostfwd=tcp::"$SSH_PORT"-:22,hostfwd=tcp::"$WEB_PORT"-:8090 \
    -device virtio-net-pci,netdev=n0 \
    -nographic -serial file:"$W/console.log" -monitor none \
    >"$W/qemu.log" 2>&1 &
VMPID=$!

SSHQ="ssh -q -i $W/id -p $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 -o LogLevel=ERROR alpine@127.0.0.1"

wait_ssh() {   # <seconds>
    _i=0
    while [ "$_i" -lt "$1" ]; do
        kill -0 "$VMPID" 2>/dev/null || { echo "  (the VM exited — see $W/console.log)"; return 1; }
        $SSHQ true 2>/dev/null && return 0
        sleep 5; _i=$((_i + 5))
    done
    return 1
}

echo "=== 1. the instance boots and cloud-init lets us in ==="
wait_ssh 300 && r=up || r=down
chk "the VM booted and SSH answers" up "$r"
[ "$r" = up ] || { echo "  --- last 25 console lines ---"; tail -25 "$W/console.log" 2>/dev/null; exit 1; }

echo "=== 1b. the alpine account can escalate ==="
# ⚠️ EVERY PROBE BELOW RUNS THROUGH doas, AND EVERY ONE OF THEM SWALLOWS ITS OWN STDERR.
# A broken escalator therefore does not fail them — it makes all of them answer "no", and
# makes the reboot in §5 a formality. Alpine's cloud image ships doas (not sudo) with
# `permit nopass :wheel` and the alpine account in wheel; assert it once, loudly, here.
esc="$($SSHQ 'doas -n id -u' 2>&1 || true)"
chk "doas escalates to uid 0" 0 "$esc"
[ "$esc" = 0 ] || { echo "  --- escalation is broken; every check below would be meaningless ---"; exit 1; }

echo "=== 2. cloud-init delivered the answers and the installer consumed them ==="
# ⚠️ THE ANSWERS FILE IS THE ASSERTION, not just "a service is running". A node that came
# up with its built-in defaults, ignoring user-data entirely, would pass every liveness
# check below while being configured by nobody — which is precisely the failure that has
# no coverage today.
chk "the answers file reached the instance" yes \
    "$($SSHQ 'doas -n test -f /root/fastpki-answers.env && echo yes || echo no' 2>/dev/null)"
chk "  and the installer ran to completion" 0 \
    "$($SSHQ 'doas -n cat /var/log/fastpki-firstboot.rc 2>/dev/null || echo missing' 2>/dev/null)"
chk "  configuring the name it was GIVEN, not a default" yes \
    "$($SSHQ 'doas -n grep -q "^PKI_DNS=fastpki-boot-check.test" /etc/fastpki/bootstrap.conf && echo yes || echo no' 2>/dev/null)"

echo "=== 3. OpenRC is supervising the services under a real init ==="
chk "the token service is running"   yes \
    "$($SSHQ 'doas -n rc-service fastpki-token status 2>/dev/null | grep -q started && echo yes || echo no' 2>/dev/null)"
chk "the console is running"         yes \
    "$($SSHQ 'doas -n rc-service fastpki-web status 2>/dev/null | grep -q started && echo yes || echo no' 2>/dev/null)"
chk "EST is running, as asked for"   yes \
    "$($SSHQ 'doas -n rc-service fastpki-est status 2>/dev/null | grep -q started && echo yes || echo no' 2>/dev/null)"
# A protocol NOT asked for must not be in the runlevel: an installer that starts everything
# regardless would pass the three checks above while ignoring the answers it was given.
chk "  and a protocol NOT asked for is absent" no \
    "$($SSHQ 'doas -n rc-status default 2>/dev/null | grep -q fastpki-scep && echo yes || echo no' 2>/dev/null)"

echo "=== 3b. the token is published over mTLS, because the answers asked for it ==="
# ⚠️ THIS SECTION EXISTS BECAUSE ITS ABSENCE SHIPPED A BROKEN IMAGE. P11_TLS=on is the one
# answer whose service starts LAST and depends on everything else being right — the token
# socket, the uid, the provider config — so it is the first thing to break and the only one
# nothing else here would notice. A node with the transport dead still boots, still serves
# HTTPS, and still passes every other check on this page.
chk "the mTLS publisher is running" yes \
    "$($SSHQ 'doas -n rc-service fastpki-p11-tls status 2>/dev/null | grep -q started && echo yes || echo no' 2>/dev/null)"
# ⚠️ AND IT MUST RUN AS THE TOKEN'S OWN USER, NOT root. p11-kit-server authorises its peer
# by uid over SO_PEERCRED, so a publisher started as root cannot open the socket it exists
# to publish — and it reports that as CKR_DEVICE_ERROR, which names neither the uid nor the
# socket. "A process is running" is not the assertion; whose it is, is.
chk "  as the token's own user, not root" fastpki \
    "$($SSHQ 'ps -o user,args 2>/dev/null | grep "[s]tunnel /run" | awk "{print \$1}" | head -1' 2>/dev/null)"
chk "  and it actually bound the port" yes \
    "$($SSHQ 'doas -n sh -c "ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null" | grep -q ":12345" && echo yes || echo no' 2>/dev/null)"
# ⚠️ THE LOG IS EVIDENCE, NOT DECORATION. supervise-daemon opens the service's log as root
# and only then drops to command_user, so a root-owned log file silences the child
# completely: the service fails with no diagnostic anywhere. An empty log here means that
# fault is back, whatever the status line says.
chk "  its log is writable by that user" yes \
    "$($SSHQ 'doas -n sh -c "[ -s /var/log/fastpki/fastpki-p11-tls.log ] && [ \"\$(stat -c %U /var/log/fastpki/fastpki-p11-tls.log)\" = fastpki ]" && echo yes || echo no' 2>/dev/null)"
# ⚠️ AND THE TRUST DIRECTORIES, WHICH FAIL A DAY LATER RATHER THAN NOW. start_pre runs as
# root whatever command_user says, so the p11-*-sync calls in it can create these owned by
# root — and the DAILY renewal job, which runs as the service user, then cannot rewrite
# them. Peer trust converges once, at this boot, and never again: a peer that renews its
# transport certificate is locked out about a day later, and a node meshed after this one
# is never admitted at all. Nothing reports it — both sync call sites swallow the error —
# so the only symptom is the peer's `tlsv1 alert unknown ca` and a key replication that
# fails with CKR_DEVICE_ERROR. Owner, not existence, is the whole assertion.
for _d in clients servers; do
    chk "  the $_d trust directory belongs to that user" fastpki \
        "$($SSHQ "doas -n stat -c %U /var/pki/tls/p11/$_d 2>/dev/null" 2>/dev/null)"
done

echo "=== 3c. the database role can do what a mesh join needs ==="
# ⚠️ REPLICATION IS TWO PERMISSIONS AND THE SECOND FAILS LATER. The fastpki role is created
# LOGIN REPLICATION and deliberately not SUPERUSER; REPLICATION covers being a publication
# SOURCE. Creating a subscription is separate — PostgreSQL 16 moved it off superuser onto
# the predefined role pg_create_subscription — so without the grant a native node completes
# pass 1 of a mesh bootstrap and fails pass 2 with `permission denied to create
# subscription`, after every CA, credential and certificate is already done. compose and
# Kubernetes never meet it: their entrypoint makes that role a superuser.
chk "fastpki may create a subscription" t \
    "$($SSHQ 'doas -n su postgres -s /bin/sh -c "psql -tAc \"select pg_has_role('"'"'fastpki'"'"', '"'"'pg_create_subscription'"'"', '"'"'member'"'"')\"" 2>/dev/null | tr -d " \r"' 2>/dev/null)"
# And may read a standby's replication state, which the console's Replication page shows.
chk "fastpki may read pg_stat_replication in full" t \
    "$($SSHQ 'doas -n su postgres -s /bin/sh -c "psql -tAc \"select pg_has_role('"'"'fastpki'"'"', '"'"'pg_read_all_stats'"'"', '"'"'member'"'"')\"" 2>/dev/null | tr -d " \r"' 2>/dev/null)"

echo "=== 4. the console answers on the port a client would use ==="
chk "the console serves HTTPS" yes \
    "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 \
        "https://127.0.0.1:$WEB_PORT/" 2>/dev/null | grep -qE '^(200|302|401)$' && echo yes || echo no)"

echo "=== 5. ⚠️ AND IT SURVIVES A REBOOT, which no container can tell us ==="
# The token, the database and the config all have to come back. A first boot that works and
# a second that does not is the classic cloud-image failure, and it is invisible until
# somebody reboots an instance that has been serving a CA for a month.
# ⚠️ "SSH ANSWERS AGAIN" IS NOT "IT REBOOTED". reboot drops the connection, so ssh cannot
# report success and its status has to be ignored — which means a reboot that never
# happened looks exactly like one that did. The kernel regenerates boot_id on every boot,
# so comparing it is the difference between an assertion and a formality.
boot_before="$($SSHQ 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || echo none)"
$SSHQ 'doas -n reboot' >/dev/null 2>&1 || true
sleep 10
wait_ssh 300 && r=up || r=down
chk "the instance came back" up "$r"
boot_after="$($SSHQ 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || echo none)"
chk "  and it is a NEW boot, not the same one" changed \
    "$([ "$boot_before" != none ] && [ "$boot_after" != "$boot_before" ] && echo changed || echo same)"
if [ "$r" = up ]; then
    chk "  the token service came back"  yes \
        "$($SSHQ 'doas -n rc-service fastpki-token status 2>/dev/null | grep -q started && echo yes || echo no' 2>/dev/null)"
    chk "  the console came back"        yes \
        "$($SSHQ 'doas -n rc-service fastpki-web status 2>/dev/null | grep -q started && echo yes || echo no' 2>/dev/null)"
    chk "  and it still serves HTTPS"    yes \
        "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 \
            "https://127.0.0.1:$WEB_PORT/" 2>/dev/null | grep -qE '^(200|302|401)$' && echo yes || echo no)"
    # ⚠️ THE TOKEN IS THE ONE THAT MATTERS. A CA key lives in it, so a token that is empty
    # after a reboot means the deployment came back looking healthy and unable to sign.
    chk "  the token still holds its slot" yes \
        "$($SSHQ 'doas -n softhsm2-util --show-slots 2>/dev/null | grep -qi "label:.*fastpki" && echo yes || echo no' 2>/dev/null)"
    # The publisher has to come back too, and as the right user again: its log is recreated
    # by checkpath on every start, so the ownership fault would reappear here rather than on
    # the first boot if checkpath were ever dropped.
    chk "  the mTLS publisher came back" yes \
        "$($SSHQ 'doas -n rc-service fastpki-p11-tls status 2>/dev/null | grep -q started && echo yes || echo no' 2>/dev/null)"
    chk "    still as the token's own user" fastpki \
        "$($SSHQ 'ps -o user,args 2>/dev/null | grep "[s]tunnel /run" | awk "{print \$1}" | head -1' 2>/dev/null)"
fi

echo
echo "=== CLOUD IMAGE BOOT: PASS=$pass FAIL=$fail ==="
[ "$KEEP" = 1 ] && {
    echo "VM left running (pid $VMPID). ssh -i $W/id -p $SSH_PORT alpine@127.0.0.1"
    VMPID=""
}
[ "$fail" -eq 0 ]
