#!/bin/sh
# ovmf-firmware.sh — find this host's UEFI firmware, or name the package that supplies it.
#
# SOURCE it. It sets OVMF_CODE and OVMF_VARS, and exits its caller when the host has
# neither:
#
#     . "$HERE/ovmf-firmware.sh"          # from deploy/cloud/
#     . "$HERE/../ovmf-firmware.sh"       # from deploy/cloud/image/
#
# ⚠️ EVERYTHING THAT BOOTS THIS IMAGE NEEDS IT. image/fastpki.pkr.hcl builds on Alpine's
# `-uefi-` cloud image, which is GPT with an EFI system partition and carries no BIOS boot
# code at all. Start QEMU without firmware and it runs its built-in SeaBIOS, which finds
# nothing to execute: the process stays healthy, VNC answers, the disk and the seed are both
# attached, and the only symptom is that SSH never comes up. That reads as a hung kernel or
# a broken cloud-init seed, and it costs a full SSH timeout to learn nothing from.
#
# ⚠️ PROBED, NOT DEFAULTED. Packer's qemu builder defaults to /usr/share/OVMF/OVMF_CODE.fd,
# which is one distribution's name for one firmware build. The name differs across
# distributions and across QEMU's own packaging, so the pair is resolved here, once, and
# handed to both the build and the boot check rather than assumed by either.
#
# ⚠️ CODE AND VARS ARE A MATCHED PAIR — one firmware build, one flash size. A 4MB code image
# against a 2MB variable store gives a firmware that loads and then cannot read its own
# variables, so each candidate names both halves and only counts when both exist.
#
# x86_64 only, which is what this image is: fastpki.pkr.hcl names an x86_64 qcow2 and
# boot-check.sh runs qemu-system-x86_64.
#
# The pve-edk2-firmware pair is a Proxmox host: it ships its own firmware and does NOT
# install Debian's `ovmf` package, so a probe that only knew /usr/share/OVMF reported no
# firmware on a machine that has it — and a hypervisor is exactly where someone builds or
# boots this image by hand.
OVMF_CODE=""
OVMF_VARS=""
for _pair in \
    "/usr/share/OVMF/OVMF_CODE_4M.fd|/usr/share/OVMF/OVMF_VARS_4M.fd" \
    "/usr/share/OVMF/OVMF_CODE.fd|/usr/share/OVMF/OVMF_VARS.fd" \
    "/usr/share/pve-edk2-firmware/OVMF_CODE_4M.fd|/usr/share/pve-edk2-firmware/OVMF_VARS_4M.fd" \
    "/usr/share/pve-edk2-firmware/OVMF_CODE.fd|/usr/share/pve-edk2-firmware/OVMF_VARS.fd" \
    "/usr/share/edk2/x64/OVMF_CODE.4m.fd|/usr/share/edk2/x64/OVMF_VARS.4m.fd" \
    "/usr/share/edk2/ovmf/OVMF_CODE.fd|/usr/share/edk2/ovmf/OVMF_VARS.fd" \
    "/opt/homebrew/share/qemu/edk2-x86_64-code.fd|/opt/homebrew/share/qemu/edk2-i386-vars.fd" \
    "/usr/local/share/qemu/edk2-x86_64-code.fd|/usr/local/share/qemu/edk2-i386-vars.fd"
do
    # QEMU's own firmware ships the x86_64 code with an `i386` variable store — there is no
    # edk2-x86_64-vars.fd, and that pairing is QEMU's, not a typo here.
    _code="${_pair%|*}"
    _vars="${_pair#*|}"
    if [ -f "$_code" ] && [ -f "$_vars" ]; then
        OVMF_CODE="$_code"; OVMF_VARS="$_vars"; break
    fi
done
unset _pair _code _vars

if [ -z "$OVMF_CODE" ]; then
    echo "no UEFI firmware on this host, and the cloud image is Alpine's -uefi- build:" >&2
    echo "    Debian/Ubuntu   apt-get install ovmf" >&2
    echo "    Alpine          apk add ovmf" >&2
    echo "    Fedora/RHEL     dnf install edk2-ovmf" >&2
    echo "    macOS           brew install qemu" >&2
    exit 1
fi
