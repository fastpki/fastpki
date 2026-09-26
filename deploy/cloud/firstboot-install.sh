#!/bin/sh
# firstboot-install.sh — put FastPKI on a cloud server at its first boot, then configure it.
#
#   firstboot-install.sh <mirror> <version|""> <release-pubkey.pem> <answers-file>
#
# deployment-path: cloud — embedded by both cloud first boots, deploy/cloud/aws/user-data.sh.tftpl
# and deploy/cloud/proxmox/vendor-data.yaml.tftpl, so the two install FastPKI the same way and
# check it the same way. It is one file so that the signature check exists once.
#
# On an image built with deploy/cloud/image, fastpki-install-native is already there, and this
# only runs it: nothing is downloaded. On Alpine's own cloud image — the default — FastPKI is
# downloaded from the release mirror first. Either way nothing is compiled: the patched PKCS#11
# stack arrives prebuilt in the release package.
#
# ⚠️ NOTHING DOWNLOADED RUNS UNTIL IT IS VERIFIED. install.sh is the first thing fetched and
# the first thing that would execute, so it is checked here, against SHA256SUMS, whose
# signature is checked against <release-pubkey.pem>. That key is rendered in from the
# operator's own checkout (docs/release-keys/), never taken from anything the mirror served —
# so the mirror has to be reachable, not trusted. install.sh then checks the package against
# the same signature before it unpacks it.
#
# The mirror rather than github.com because github.com publishes no IPv6 address, and cloud
# servers are IPv6-only unless they were given IPv4.
#
# Exit status is the installer's: 0 means configured.
set -eu

MIRROR="${1:?mirror}"; V="${2:-}"; PUBKEY="${3:?release public key}"; ANSWERS="${4:?answers file}"

if [ -x /usr/local/bin/fastpki-install-native ]; then
    echo "=== FastPKI is on the image; nothing to download ==="
    exec /usr/local/bin/fastpki-install-native --answers "$ANSWERS"
fi

echo "=== installing FastPKI from $MIRROR ==="
REL=/var/lib/fastpki-firstboot
mkdir -p "$REL"
get() { wget -q -T 30 -O "$2" "$1"; }   # busybox wget; the mirror answers over IPv6

if [ -z "$V" ]; then
    get "$MIRROR/latest" "$REL/latest" \
        || { echo "FATAL: cannot reach $MIRROR to find the newest release" >&2; exit 1; }
    V=$(tr -d ' \r\n' < "$REL/latest")
    [ -n "$V" ] || { echo "FATAL: $MIRROR/latest is empty" >&2; exit 1; }
fi
echo "release: $V"

for f in SHA256SUMS SHA256SUMS.sig install.sh; do
    get "$MIRROR/$V/$f" "$REL/$f" \
        || { echo "FATAL: cannot download $f for $V from $MIRROR" >&2; exit 1; }
done

# Alpine's cloud image carries libssl but not the openssl command. Alpine's package mirror is
# reachable over IPv6, which is more than github.com is.
command -v openssl >/dev/null 2>&1 || apk add --no-cache openssl >/dev/null \
    || { echo "FATAL: cannot install openssl, which the signature check needs" >&2; exit 1; }

# OpenSSL's own error line is dropped: the sentence below says what failed, and the raw
# "EVP_DigestVerifyFinal: provider signature failure" printed above it added nothing an
# operator can act on.
openssl dgst -sha256 -verify "$PUBKEY" -signature "$REL/SHA256SUMS.sig" "$REL/SHA256SUMS" >/dev/null 2>&1 \
    || { echo "FATAL: the SHA256SUMS signature for $V does not verify — installing nothing" >&2; exit 1; }
want=$(sed -n 's#^\([0-9a-f]\{64\}\)[[:space:]]*[*]\{0,1\}\(\./\)\{0,1\}install\.sh$#\1#p' "$REL/SHA256SUMS")
got=$(sha256sum "$REL/install.sh" | cut -d' ' -f1)
[ -n "$want" ] && [ "$want" = "$got" ] \
    || { echo "FATAL: install.sh for $V does not match its signed SHA256SUMS — not running it" >&2; exit 1; }
echo "verified: the SHA256SUMS signature, and install.sh against it"

# install.sh checks the package against the same key, unpacks it, adds the Alpine packages it
# needs, and hands over to fastpki-install-native with these answers.
export FASTPKI_DOWNLOAD_BASE="$MIRROR/$V"
export FASTPKI_RELEASE_PUBKEY="$PUBKEY"
exec sh "$REL/install.sh" --native --version "$V" --answers "$ANSWERS"
