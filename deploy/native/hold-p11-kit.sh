#!/bin/sh
# deploy/native/hold-p11-kit.sh — hold Alpine's p11-kit packages at the installed version.
#
# build-native.sh installs FastPKI's PATCHED p11-kit over two files that Alpine packages
# own: /usr/lib/libp11-kit.so.0 (p11-kit) and /usr/lib/pkcs11/p11-kit-client.so
# (p11-kit-server). apk still records them as its own, so an `apk upgrade` that brings a
# newer build of either package puts the unpatched library back, and every CA with an
# Ed25519, Ed448 or ML-DSA key stops working — reported as CKR_TOKEN_NOT_PRESENT, a message
# about the slot. That upgrade happens without anyone choosing it: Proxmox's generated
# user-data runs one at first boot on a node with internet access.
#
# A version constraint in /etc/apk/world is what `apk upgrade` honours. Measured on Alpine
# 3.24 against edge's newer p11-kit: unpinned, the upgrade replaced the library; pinned, it
# left the package and the patched file alone and still exited 0.
#
# Run by build-native.sh (the bake) and by fastpki-install-native (so a node baked before
# this existed is held from its next update). Offline: it only rewrites the world file.
set -eu
command -v apk >/dev/null 2>&1 || exit 0
for pkg in p11-kit p11-kit-server; do
    v="$(apk list -I "$pkg" 2>/dev/null | sed -n "s/^$pkg-\([0-9][^ ]*\) .*/\1/p" | head -1)"
    if [ -z "$v" ]; then
        echo "hold-p11-kit: $pkg is not installed, so there is nothing to hold" >&2
        exit 1
    fi
    # Its stderr is shown only if it fails. On a host installed with `apk add --no-cache` there
    # is no index cache, and every successful pin printed "WARNING: opening from cache …
    # APKINDEX.tar.gz: No such file or directory" — noise in the first-boot log that sends
    # whoever reads it after a real failure after the wrong thing. Pinning an installed package
    # needs no index, so the warning never means anything here.
    _err=$(mktemp)
    if ! apk add --no-network --quiet "$pkg=$v" >/dev/null 2>"$_err"; then
        cat "$_err" >&2; rm -f "$_err"
        echo "hold-p11-kit: could not hold $pkg at $v" >&2
        exit 1
    fi
    rm -f "$_err"
done
