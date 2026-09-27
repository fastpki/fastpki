#!/bin/sh
# build-qemu.sh — build the cloud image as a BOOTABLE DISK, not an AMI.
#
#   ./build-qemu.sh                       # build from HEAD into ./output-qemu
#   ./build-qemu.sh --ref v0.1.0          # build a named commit or tag
#   ./build-qemu.sh --accel tcg           # no KVM/HVF available (slow, but works)
#
# ── WHY THIS EXISTS ───────────────────────────────────────────────────────────────────
#
# fastpki.pkr.hcl's amazon-ebs source produces an AMI, and an AMI can only be booted by
# launching an EC2 instance — so the artifact every cloud user actually boots had no local
# test of any kind. provision.sh says why a container cannot stand in: it has no init and
# no cloud-init, so the two things most likely to be wrong on first boot are the two things
# a container cannot check.
#
# The qemu source runs the SAME provision.sh over the SAME Alpine release and emits a
# qcow2 that boots under QEMU here and on the lab hypervisor.
#
# ⚠️ THE SSH KEY IS GENERATED HERE, AND THAT IS NOT A STYLE CHOICE. Packer's own
# build.SSHPublicKey is not available inside a source block, and the obvious alternative —
# an ssh_password in the cloud-init seed — is written into /etc/shadow by cloud-init and
# would therefore be baked into the artifact. So an ephemeral keypair is made here, handed
# to the VM through the seed, and removed again by the last provisioner along with the
# cloud-init instance state.
set -eu

case "$0" in
    */*) HERE="$(cd "${0%/*}" && pwd)" ;;
    *)   HERE="$(pwd)" ;;
esac

REF=HEAD
OUT="$HERE/output-qemu"
# kvm on Linux, hvf on macOS, tcg everywhere. Defaulted by uname rather than left to the
# operator: the wrong one is a hard failure on some hosts and merely very slow on others,
# and the slow case is the one nobody notices until a build takes an hour.
case "$(uname -s)" in
    Darwin) ACCEL=hvf ;;
    Linux)  [ -e /dev/kvm ] && ACCEL=kvm || ACCEL=tcg ;;
    *)      ACCEL=tcg ;;
esac

# ⚠️ SIZE THE BUILD FROM THIS MACHINE. The provisioner compiles four C/C++ projects against
# a 60-minute timeout, so cores decide whether the build finishes or is discarded at minute
# 60 — a two-core host reached about 15 of 70 objects an hour. Half the cores, so a build
# does not monopolise a hypervisor that is also running other people's VMs, and at least 2.
# Capped at 8: this is a `make -j` curve, and past that the 19k-line translation unit is the
# critical path rather than the core count.
CPUS=$( { nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2; } | head -1 )
CPUS=$(( CPUS / 2 ))
[ "$CPUS" -lt 2 ] && CPUS=2
[ "$CPUS" -gt 8 ] && CPUS=8
# 1 GB per core, floor 2 GB: parallel compilation of that translation unit is memory-hungry
# per job, and a build that starts swapping is slower than one with fewer cores.
MEM=$(( CPUS * 1024 ))
[ "$MEM" -lt 2048 ] && MEM=2048

# ⚠️ AND BOUNDED BY WHAT THE HOST CAN ACTUALLY SPARE. Core count says nothing about free
# memory: a hypervisor with 32 threads may have most of its RAM already committed to other
# people's VMs, and asking for more than is free either fails outright or pushes the host
# into swap — which harms every guest on it, not just this build. Leave a quarter of what is
# available, and drop cores to match rather than running a starved VM.
if [ -r /proc/meminfo ]; then
    AVAIL=$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)
    CAP=$(( AVAIL * 3 / 4 ))
    if [ "$CAP" -lt "$MEM" ]; then
        MEM=$CAP
        [ "$MEM" -lt 2048 ] && { echo "build-qemu.sh: only ${AVAIL} MB free — the build needs 2048 MB" >&2; exit 1; }
        [ "$(( MEM / 1024 ))" -lt "$CPUS" ] && CPUS=$(( MEM / 1024 ))
        [ "$CPUS" -lt 2 ] && CPUS=2
    fi
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --ref)   REF="${2:?--ref needs a commit or tag}"; shift 2 ;;
        --accel) ACCEL="${2:?--accel needs kvm, hvf or tcg}"; shift 2 ;;
        --out)   OUT="${2:?--out needs a directory}"; shift 2 ;;
        -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# ⚠️ SIBLINGS OF THE OUTPUT DIRECTORY, NOT CHILDREN. Packer's qemu builder deletes the whole
# output directory when a build halts (builder/qemu/step_prepare_output_dir.go), so a console
# log written inside it is destroyed by exactly the run that needed it.
CONSOLE="$OUT.console.log"
PACKERLOG="$OUT.packer.log"

command -v packer >/dev/null 2>&1 || { echo "build-qemu.sh: packer is not installed" >&2; exit 1; }
command -v qemu-system-x86_64 >/dev/null 2>&1 || {
    echo "build-qemu.sh: qemu-system-x86_64 is not installed" >&2; exit 1; }

# ⚠️ MEMBERSHIP OF `kvm`, NOT JUST THE PRESENCE OF THE DEVICE. Without write access QEMU
# exits during startup with "Could not access KVM kernel module: Permission denied", which
# packer reports only as "Qemu failed to start. Please run with PACKER_LOG=1" — seventeen
# seconds and no hint of the cause, on a host that is otherwise perfectly capable. .github/
# workflows/ci.yml asserts this for the gate; a person running the script by hand deserves
# the same answer, so it is checked here rather than only there.
if [ "$ACCEL" = kvm ] && [ ! -w /dev/kvm ]; then
    echo "build-qemu.sh: /dev/kvm is not writable by $(id -un) — add yourself to the 'kvm'" >&2
    echo "  group and start a new session:  sudo usermod -aG kvm $(id -un)" >&2
    echo "  or pass --accel tcg to emulate, which is correct but far too slow for this build." >&2
    exit 1
fi

# ⚠️ THE FIRMWARE IS A PREREQUISITE, NOT A DETAIL. The base is Alpine's -uefi- cloud image
# and has no BIOS boot path, so a build started without OVMF gets a VM that never executes a
# bootloader — packer sees only that SSH never answers and spends its whole ssh_timeout on
# it. Resolved here so the failure is one line before the download instead.
. "$HERE/../ovmf-firmware.sh"

# Packer refuses to write into a directory that already exists, and says so in a way that
# reads like a configuration error. Saying it here names the fix instead.
if [ -e "$OUT" ]; then
    echo "build-qemu.sh: $OUT already exists — remove it or pass --out elsewhere." >&2
    exit 1
fi

KEYDIR="$(mktemp -d)"
trap 'rm -rf "$KEYDIR"' EXIT INT TERM
ssh-keygen -t ed25519 -N '' -C fastpki-image-build -f "$KEYDIR/id" >/dev/null

packer init "$HERE" >/dev/null

rm -f "$CONSOLE" "$PACKERLOG"

echo "==> building a bootable image from '$REF' (accelerator: $ACCEL, firmware: $(basename "$OVMF_CODE"))"
echo "    build VM:      ${CPUS} vCPU, ${MEM} MB"
echo "    guest console: $CONSOLE"
echo "    packer log:    $PACKERLOG"

# ⚠️ PACKER_LOG IS NOT OPTIONAL HERE, AND IT GOES TO A FILE. At its default level packer
# prints one line — "Timeout waiting for SSH." — for a guest that never booted, a guest with
# no network, a guest that found no datasource and a guest whose sshd refused the key. Only
# the debug log carries the QEMU command line it actually ran and the per-attempt SSH errors
# that tell those apart, and this lane has already spent two CI runs learning nothing.
rc=0
PACKER_LOG=1 PACKER_LOG_PATH="$PACKERLOG" packer build \
    -only=fastpki.qemu.alpine \
    -var "source_ref=$REF" \
    -var "qemu_accelerator=$ACCEL" \
    -var "qemu_output_dir=$OUT" \
    -var "qemu_console_log=$CONSOLE" \
    -var "qemu_build_cpus=$CPUS" \
    -var "qemu_build_memory=$MEM" \
    -var "qemu_efi_code=$OVMF_CODE" \
    -var "qemu_efi_vars=$OVMF_VARS" \
    -var "build_ssh_public_key=$(cat "$KEYDIR/id.pub")" \
    -var "build_ssh_private_key_file=$KEYDIR/id" \
    "$HERE" || rc=$?

if [ "$rc" -ne 0 ]; then
    echo
    echo "=== the QEMU command line packer ran ==="
    grep -m1 'Executing .*qemu-system' "$PACKERLOG" 2>/dev/null || echo "  (not found in $PACKERLOG)"
    echo
    echo "=== what SSH actually did (last 20 lines) ==="
    grep -E 'TCP connection to SSH|Attempting SSH connection|SSH handshake err|authentication error' \
        "$PACKERLOG" 2>/dev/null | tail -20 || true
    echo
    echo "=== guest serial console, last 80 lines ($CONSOLE) ==="
    if [ -s "$CONSOLE" ]; then
        tail -80 "$CONSOLE"
    else
        echo "  EMPTY — the guest wrote nothing to ttyS0, so it never reached a bootloader."
        echo "  Alpine's cloud image puts GRUB on the serial port, so a boot menu is the first"
        echo "  thing a disk that boots at all prints here. Read the pflash arguments above."
    fi
    exit "$rc"
fi

echo
echo "Wrote:"
ls -1 "$OUT" 2>/dev/null | sed 's/^/  /'
echo
echo "Boot it with deploy/cloud/boot-check.sh, which hands it a cloud-init answers file"
echo "and asserts the deployment comes up — the first-boot path a container cannot test."
