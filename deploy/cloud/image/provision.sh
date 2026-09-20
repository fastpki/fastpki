#!/bin/sh
# Runs inside the Packer builder, as root, on Alpine's official cloud image.
#
# It does the BAKE half of the install and nothing else: the patched PKCS#11 stack, the
# FastPKI binaries, the OpenRC services. It deliberately does NOT create a token, a
# database, a CA or any configuration — an AMI that carried a token would put the same CA
# key material on every instance launched from it, which is the one thing a PKI image must
# never do. Configuration happens at first boot, from user-data, via
# fastpki-install-native.
set -eu

RELEASE="${FASTPKI_RELEASE:-dev}"

# ── where the build happens ───────────────────────────────────────────────────────────
#
# ⚠️ NOT ON THE ROOT VOLUME, WHEN THERE IS SOMEWHERE ELSE TO PUT IT. The root volume of this
# builder becomes the root volume of every instance launched from the finished image, and a
# root can never be smaller than the snapshot behind it. Measured: the build's high-water
# mark is about 1 GB — 760 MB of sources, object trees and toolchain over ~200 MB of base
# system — while a running node uses 264 MB. Building on the root therefore made every
# deployed node carry a volume sized for a compiler it does not have.
#
# fastpki.pkr.hcl attaches a scratch volume to the builder for exactly this, absent from the
# AMI and deleted with the instance. When it is not there — the local container bake, or
# anyone driving this script by hand — /tmp is used and nothing changes.
BUILD_ROOT=/tmp
SCRATCH_DEV=""
for cand in /dev/disk/by-id/*sdb /dev/sdb /dev/xvdb /dev/nvme1n1; do
    [ -b "$cand" ] && { SCRATCH_DEV="$cand"; break; }
done
if [ -n "$SCRATCH_DEV" ]; then
    echo "==> build scratch: $SCRATCH_DEV"
    # Blank by construction — it is created with the builder — but checked all the same,
    # because a mkfs on the wrong device is not a recoverable mistake and the cost of asking
    # is one command.
    blkid "$SCRATCH_DEV" >/dev/null 2>&1 || mkfs.ext4 -q -L fastpki-build "$SCRATCH_DEV"
    mkdir -p /mnt/build
    mount "$SCRATCH_DEV" /mnt/build
    BUILD_ROOT=/mnt/build
fi
SRC="$BUILD_ROOT/fastpki-src"
# build-native.sh takes its working directory from the environment; without this it would
# put the object trees back on the root volume and the scratch disk would hold only sources.
WORK="${WORK:-$BUILD_ROOT/fastpki-native-build}"
export WORK

# ⚠️ ONE SCRIPT, TWO PLACES IT RUNS, AND THAT IS DELIBERATE.
#
#   FASTPKI_BAKE_LOCAL unset  the Packer builder, on Alpine's official cloud AMI.
#   FASTPKI_BAKE_LOCAL=1      a throwaway container on a developer machine
#                             (deploy/native/build-check.sh).
#
# The local run exists so a bake failure costs nothing instead of costing a twenty-minute
# EC2 round trip, and it is only worth having if it exercises THIS script rather than a
# copy of it — a second script asserting the same things is the drift problem that the
# Dockerfile pin extraction already exists to prevent.
#
# Exactly two steps are cloud-only, and both are about a machine that BOOTS: enabling
# crond in a runlevel, and asserting the base image can receive user-data. A container has
# no init and no cloud-init, so neither is answerable there. Everything that can actually
# fail in a bake — the patches, the mechanism probe, the compile, the binaries — runs in
# both.
BAKE_LOCAL="${FASTPKI_BAKE_LOCAL:-0}"

echo "==> apk update"
apk update

# The tree arrives as a `git archive` tarball — the tracked set, and nothing a working
# directory happens to be carrying. See the file provisioner in fastpki.pkr.hcl.
echo "==> unpacking the source"
rm -rf "$SRC"; mkdir -p "$SRC"
tar xzf /tmp/fastpki-src.tar.gz -C "$SRC"
rm -f /tmp/fastpki-src.tar.gz
test -f "$SRC/deploy/native/build-native.sh" \
  || { echo "FATAL: the source archive does not look like the FastPKI tree" >&2; exit 1; }

echo "==> building FastPKI natively (patched pkcs11-provider, p11-kit, SoftHSM)"
sh "$SRC/deploy/native/build-native.sh"

# ── prove the image can actually do the thing it exists to do ─────────────────────────
# The patched stack is the ONLY reason this AMI exists, and its failure mode is silent: an
# unpatched p11-kit does not relay four mechanisms, so an Ed25519 or ML-DSA CA reports
# CKR_TOKEN_NOT_PRESENT — a message about the SLOT, for a problem about the ALGORITHM —
# months later, in production.
#
# ⚠️ ASK THE TOKEN, DO NOT GREP THE LIBRARY. The patch adds `case CKM_ML_DSA_KEY_PAIR_GEN:`
# and a serializer — numeric constants and code, not strings — so `strings libp11-kit.so`
# proves nothing either way. The capability question has a direct answer: stand the real
# arrangement up (SoftHSM behind p11-kit, reached through the client shim, exactly as a
# running deployment does) and ask what it advertises. This is the same probe
# tests/hsm_helpers.sh uses before it attempts an ML-DSA keygen.
echo "==> verifying the patched PKCS#11 stack end to end"
# ⚠️ AND THAT NOTHING WILL QUIETLY UNDO IT. The patched libraries overwrite files Alpine's
# p11-kit and p11-kit-server packages own, so an image whose world file does not hold those
# packages loses the patch at the first `apk upgrade` — which Proxmox's user-data runs at
# first boot on a node with internet access (deploy/native/hold-p11-kit.sh).
for pkg in p11-kit p11-kit-server; do
    grep -q "^$pkg=" /etc/apk/world \
      || { echo "FATAL: $pkg is not held in /etc/apk/world — apk upgrade would replace the patched library" >&2; exit 1; }
done
test -f /usr/lib/ossl-modules/pkcs11.so \
  || { echo "FATAL: the pkcs11 OpenSSL provider is missing" >&2; exit 1; }

BAKE_TOK="$(mktemp -d)"
BAKE_SOCK=/run/p11-bake.sock
bake_cleanup() {
    [ -n "${BAKE_SRV:-}" ] && kill "$BAKE_SRV" 2>/dev/null || true
    rm -f "$BAKE_SOCK"
    # ⚠️ THE TOKEN MUST NOT SURVIVE INTO THE IMAGE. A token baked into an AMI would put
    # the same key material on every instance launched from it, which is the one thing a
    # PKI image must never do. It is removed here, on every exit path.
    rm -rf "$BAKE_TOK"
    # ⚠️ NOR MUST THE BUILDER'S DNS. The bake runs under qemu's user-mode networking, whose
    # resolver is 10.0.2.3 — an address that exists only inside that build VM. Snapshotting
    # /etc/resolv.conf with it ships a machine image that cannot resolve anything: measured
    # on a deployed node, where the file's mtime was the BAKE time, hours before the boot,
    # and every name lookup failed while the configured nameserver answered perfectly when
    # asked directly. Same class as the token above — builder state that must not ship.
    # Truncated rather than deleted: cloud-init and dhcpcd both rewrite it, and a missing
    # file makes resolution fail differently on the paths that do not.
    : > /etc/resolv.conf 2>/dev/null || true
}
trap bake_cleanup EXIT INT TERM

SOFTHSM2_CONF="$BAKE_TOK/softhsm2.conf"
export SOFTHSM2_CONF
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
    "$BAKE_TOK" > "$SOFTHSM2_CONF"
softhsm2-util --init-token --free --label bakecheck --so-pin 0000 --pin 1234 >/dev/null

/usr/libexec/p11-kit/p11-kit-server -f -n "$BAKE_SOCK" \
    --provider /usr/lib/softhsm/libsofthsm2.so "pkcs11:" &
BAKE_SRV=$!
i=0; while [ ! -S "$BAKE_SOCK" ] && [ "$i" -lt 60 ]; do sleep 0.5; i=$((i + 1)); done
[ -S "$BAKE_SOCK" ] || { echo "FATAL: p11-kit-server did not create $BAKE_SOCK" >&2; exit 1; }

MECHS="$(P11_KIT_SERVER_ADDRESS="unix:path=$BAKE_SOCK" \
    pkcs11-tool --module /usr/lib/pkcs11/p11-kit-client.so \
                --token-label bakecheck --list-mechanisms 2>/dev/null)"

# ML-DSA and EdDSA are the two the patch exists for. opensc prints an unknown mechanism
# by its hex type, so accept either spelling — 0x1C/0x1D are CKM_ML_DSA_KEY_PAIR_GEN and
# CKM_ML_DSA.
printf '%s' "$MECHS" | grep -qiE 'ml-dsa|mechtype-0x1[cd]' || {
    echo "FATAL: the token advertises no ML-DSA mechanism through p11-kit." >&2
    echo "       The p11-kit RPC patch did not take effect — an ML-DSA CA would be" >&2
    echo "       impossible on every instance launched from this image." >&2
    exit 1; }
printf '%s' "$MECHS" | grep -qiE 'eddsa|edwards' || {
    echo "FATAL: the token advertises no EdDSA mechanism through p11-kit." >&2
    echo "       The p11-kit RPC patch did not take effect — an Ed25519 CA would be" >&2
    echo "       impossible on every instance launched from this image." >&2
    exit 1; }
echo "    ML-DSA and EdDSA relayed through p11-kit — the patched stack is live."
bake_cleanup
trap - EXIT INT TERM

# ⚠️ THE CRITERION IS "PRINTS USAGE WITHOUT TOUCHING THE DATABASE", NOT "EXITS 0", and
# the difference is not pedantry — it is the shipped convention. fastpki-ca, -config and
# -audit exit 2 on a bare --help, because for them --help with no subcommand means "you
# did not tell me what to do"; the servers and -mesh exit 0. An exit-code check here fails
# the image build on three binaries that are working exactly as designed, which is how a
# gate teaches people to disable it.
#
# What actually matters is what tests/cli_help.sh asserts: --help is the one invocation
# that provably needs no database, and it is the first thing an operator runs — normally
# before any config exists. A binary that opens Postgres first answers a request for help
# with "role does not exist", sending them after their database when nothing is wrong with
# it. In an image with no database at all, that is also the only way to run one.
for b in web ocsp est acme cmp scep ms store ca config mesh audit; do
    test -x "/usr/local/bin/fastpki-$b" \
      || { echo "FATAL: /usr/local/bin/fastpki-$b is missing" >&2; exit 1; }
    hout="$("/usr/local/bin/fastpki-$b" --help 2>&1 || true)"
    printf '%s' "$hout" | grep -qi usage \
      || { echo "FATAL: fastpki-$b --help printed no usage:" >&2
           printf '%s\n' "$hout" | head -5 >&2; exit 1; }
    printf '%s' "$hout" | grep -qiE 'connect failed|role .* does not exist|could not connect' \
      && { echo "FATAL: fastpki-$b --help touched the database:" >&2
           printf '%s\n' "$hout" | head -5 >&2; exit 1; }
done
echo "    all 12 binaries print usage with no database present."

# ── shrink ────────────────────────────────────────────────────────────────────────────
# The build set is ~600MB of toolchain that a running CA has no use for, and every byte of
# it is attack surface on a host holding CA keys. The runtime set stays.
echo "==> removing the build toolchain"
apk del --no-network \
    build-base cmake ninja pkgconf openssl-dev libpq-dev openldap-dev krb5-dev \
    xmlsec-dev libxml2-dev zlib-dev meson git patch \
    p11-kit-dev libtasn1-dev libffi-dev autoconf automake libtool 2>/dev/null || true
rm -rf "$WORK" "$SRC" /var/cache/apk/* /root/.cache
# The scratch volume goes with the builder, but it must not be mounted when the snapshot is
# taken: a mount point that exists in the image and has nothing behind it is a puzzle for the
# next person, and /etc/fstab is deliberately untouched so nothing tries to mount it at boot.
if [ "$BUILD_ROOT" != /tmp ]; then
    cd /
    umount /mnt/build 2>/dev/null || true
    rmdir /mnt/build 2>/dev/null || true
fi

if [ "$BAKE_LOCAL" = 1 ]; then
    echo "==> local bake: skipping the two steps that need a machine that boots"
    echo "    (rc-update add crond; the cloud-init assertion) — a container has neither."
else
    # busybox crond runs /etc/periodic/daily, which is where the service-certificate
    # renewal job lives. compose spends a whole container on that loop because it has no
    # scheduler; Alpine has one, and it is off by default.
    rc-update add crond default

    # cloud-init is what delivers the answers file. It is already present and enabled on
    # Alpine's cloudinit variant; asserting it beats discovering at first boot that the
    # instance came up with no configuration and no explanation.
    rc-service --list 2>/dev/null | grep -q cloud-init \
      || { echo "FATAL: this is not an Alpine cloudinit image — user-data would be ignored" >&2; exit 1; }

    # boot-check.sh and every operator reach this image through the unprivileged `alpine`
    # account, so the artifact has to keep an escalation tool. Alpine's cloud image ships
    # doas with `permit nopass :wheel` and `alpine` in wheel; the apk del above names build
    # packages only and doas is in /etc/apk/world, so it survives — assert that instead of
    # discovering it from a boot check whose every probe answers "no" with no cause.
    command -v doas >/dev/null 2>&1 \
      || { echo "FATAL: doas is gone — nothing on this image can escalate from the alpine account" >&2; exit 1; }
fi

printf '%s\n' "$RELEASE" > /etc/fastpki-release
echo "==> FastPKI $RELEASE baked. Configure an instance with fastpki-install-native."
