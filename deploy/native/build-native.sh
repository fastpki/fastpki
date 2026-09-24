#!/bin/sh
# deploy/native/build-native.sh — build and install FastPKI natively on Alpine.
#
# This is the BAKE step. It is what runs inside the cloud-image builder
# (deploy/cloud/image/) and what you run by hand on an Alpine box you want to install on;
# deploy/native/install-native.sh is the separate CONFIGURE step that follows it and asks
# the deployment questions. Splitting them is the whole point of a custom cloud image:
# every instance boots with this already done and only runs the configure step.
#
#   ./build-native.sh                 # build + install into / (needs root)
#   DESTDIR=/mnt ./build-native.sh    # stage into a root filesystem being assembled
#   ./build-native.sh --deps-only     # just the apk packages (a cache-warming step)
#
#   FASTPKI_VERSION=v1.2.3 ./build-native.sh    # stamp that version into the binaries
#
# Set FASTPKI_VERSION whenever the result is going to be shipped. Without it the binaries
# fall back to `git describe`, and then to a dev marker — so a bake from a tree with no
# .git produces binaries that report 0.0.0-dev and cannot say which commit they are.
#
# ── WHY THIS IS NOT `apk add openssl p11-kit softhsm` ──────────────────────────────────
#
# Alpine's packaged p11-kit and SoftHSM cannot run a FastPKI CA to its full capability,
# and the failure is silent rather than loud. Three components are built from source with
# patches that live in deploy/:
#
#   pkcs11-provider   deploy/pkcs11-provider-allowed-mechs.patch
#   p11-kit           deploy/p11-kit-mechanisms.patch      — relays CKA_ALLOWED_MECHANISMS
#   SoftHSM           deploy/softhsm-allowed-mechs.patch
#
# Unpatched, p11-kit's RPC layer drops CKM_ML_DSA, CKM_ML_DSA_KEY_PAIR_GEN, CKM_EDDSA and
# CKM_EC_EDWARDS_KEY_PAIR_GEN — the token advertises 82 mechanisms and 62 are relayed — so
# an Ed25519 or ML-DSA CA cannot be created at all, and the error names the SLOT
# (CKR_TOKEN_NOT_PRESENT) for a problem about the ALGORITHM. That is why the shipped
# container image builds all three, and it is why a native install has to as well.
# See docs/deployment.md §7.2 and the patch files themselves for the full reasoning.
#
# ── THE VERSION PINS ARE READ OUT OF THE DOCKERFILE, NOT RESTATED HERE ────────────────
#
# Two build paths compiling the same three projects at two different pins is a bug that
# reports itself as "works in the container, fails on the host" months later. The
# Dockerfile is the source of truth; this script greps it, and FAILS if a pin it needs has
# moved or been renamed rather than quietly building whatever HEAD is today.
set -eu

HERE="$(cd "${0%/*}" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DESTDIR="${DESTDIR:-}"
DEPS_ONLY=0
# ⚠️ JOBS IS A MEMORY BUDGET AS MUCH AS A CPU ONE, which is why every build below honours
# it — including the two ninja invocations. Left to itself, ninja parallelises to nproc+2
# and cmake to nproc, and FastPKI's console is a 17.5k-line translation unit that pulls in
# all of cpp-httplib and nlohmann/json: several of those at once want gigabytes. On a box
# where the container's memory is smaller than its CPU count suggests — a Docker VM, a
# shared CI runner — the result is an OOM kill in the middle of a twenty-minute build,
# reported as a compiler that "crashed".
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"
WORK="${WORK:-/tmp/fastpki-native-build}"

while [ $# -gt 0 ]; do
    case "$1" in
        --deps-only) DEPS_ONLY=1; shift ;;
        -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[ -f "$ROOT/Dockerfile" ] || { echo "build-native: cannot find $ROOT/Dockerfile" >&2; exit 1; }
command -v apk >/dev/null 2>&1 || {
    echo "build-native: this builds on Alpine Linux only (no apk on PATH)." >&2
    echo "  Alpine is the one native platform FastPKI supports: it is the base of the" >&2
    echo "  shipped image, so it is the only native target the test suite has ever run" >&2
    echo "  against. See docs/deployment.md." >&2
    exit 1; }

# ── pins, read from the Dockerfile ────────────────────────────────────────────────────
pin() {   # pin <ARG name>
    v="$(sed -n "s/^ARG $1=\\(.*\\)\$/\\1/p" "$ROOT/Dockerfile" | head -1)"
    [ -n "$v" ] || { echo "build-native: Dockerfile no longer declares ARG $1 — the two build paths have drifted apart. Fix this script and the Dockerfile together." >&2; exit 1; }
    printf '%s' "$v"
}
P11P_COMMIT="$(pin P11P_COMMIT)"
SOFTHSM_COMMIT="$(pin SOFTHSM_COMMIT)"
HTTPLIB_VERSION="$(pin HTTPLIB_VERSION)"
JSON_VERSION="$(pin JSON_VERSION)"
# p11-kit is pinned by branch in its clone line rather than by an ARG.
P11KIT_VERSION="$(sed -n 's|.*--branch \([0-9][0-9.]*\) https://github.com/p11-glue/p11-kit.*|\1|p' "$ROOT/Dockerfile" | head -1)"
[ -n "$P11KIT_VERSION" ] || { echo "build-native: could not read the p11-kit version from the Dockerfile — the two build paths have drifted apart." >&2; exit 1; }

echo "==> pins from Dockerfile: pkcs11-provider=$P11P_COMMIT p11-kit=$P11KIT_VERSION softhsm=$SOFTHSM_COMMIT" >&2

# ── packages ──────────────────────────────────────────────────────────────────────────
# Split exactly the way the Dockerfile splits them: the build set is removed again at the
# end of an image bake, the runtime set stays. LDAP, SAML and Kerberos are ON by default
# in CMakeLists.txt, so their headers are not optional.
BUILD_PKGS="build-base cmake ninja pkgconf openssl-dev libpq-dev openldap-dev krb5-dev
            xmlsec-dev libxml2-dev zlib-dev meson git patch curl
            p11-kit-dev libtasn1-dev libffi-dev autoconf automake libtool"
RUNTIME_PKGS="libstdc++ openssl libpq libldap krb5-libs xmlsec libxml2 zlib
              postgresql17 postgresql17-client p11-kit p11-kit-server opensc
              openrc bash stunnel"

echo "==> apk add (runtime + build)" >&2
# shellcheck disable=SC2086
apk add --no-cache $RUNTIME_PKGS $BUILD_PKGS
[ "$DEPS_ONLY" = 1 ] && { echo "deps installed."; exit 0; }

rm -rf "$WORK"; mkdir -p "$WORK"
# ⚠️ EVERY PATH THIS SCRIPT INSTALLS IS RECORDED, because that list is what updates a node
# started from the cloud image. Such a node has no toolchain and often no route to the
# internet, so it cannot run this script; deploy/native/build-check.sh --package builds and
# verifies once, in a throwaway container, and packages exactly these paths
# (docs/admin-guide.md §14.4). A path installed without being recorded here is a file every
# updated node silently keeps at its old version.
# The token store and /etc/softhsm2.conf are written below but NOT recorded: on a node they
# already exist and belong to it, and unpacking a package over them would reset the owner
# and mode of the directory holding the CA keys.
MANIFEST="$WORK/installed-files"
: > "$MANIFEST"
record() { printf '%s\n' "${1#/}" >> "$MANIFEST"; }
inst() { install -D -m "$1" "$2" "${DESTDIR}$3"; record "$3"; }

# ── pkcs11-provider ───────────────────────────────────────────────────────────────────
echo "==> pkcs11-provider $P11P_COMMIT" >&2
git clone --depth 1 https://github.com/openssl-projects/pkcs11-provider "$WORK/p11p"
git -C "$WORK/p11p" fetch --depth 1 origin "$P11P_COMMIT"
git -C "$WORK/p11p" checkout "$P11P_COMMIT"
patch -p1 --forward -d "$WORK/p11p" -i "$ROOT/deploy/pkcs11-provider-allowed-mechs.patch" </dev/null
# -w on the third-party stages only, as in the Dockerfile: 159 of the 163 warnings these
# three projects produce are -Wdeprecated-declarations from upstream code calling OpenSSL 3
# APIs we do not control. FastPKI's own build below keeps every warning.
CFLAGS="-w -DNDEBUG" CXXFLAGS="-w -DNDEBUG" \
    meson setup "$WORK/p11p/build" "$WORK/p11p" --prefix=/usr --libdir=lib -Dbuildtype=release
ninja -C "$WORK/p11p/build" -j"$JOBS"
inst 0755 "$WORK/p11p/build/src/pkcs11.so" /usr/lib/ossl-modules/pkcs11.so

# ── p11-kit (patched: relays ML-DSA and EdDSA) ────────────────────────────────────────
echo "==> p11-kit $P11KIT_VERSION (patched)" >&2
git clone --depth 1 --branch "$P11KIT_VERSION" https://github.com/p11-glue/p11-kit "$WORK/p11kit"
patch -p1 --forward -d "$WORK/p11kit" -i "$ROOT/deploy/p11-kit-mechanisms.patch" </dev/null
# The same two assertions the Dockerfile makes. A patch that applied with fuzz and landed
# in the wrong place still exits 0, and the symptom would be an Ed25519 CA that cannot be
# created — three layers away from the cause.
grep -q 'CKM_EDDSA, p11_rpc_buffer_add_eddsa_mechanism_value' "$WORK/p11kit/p11-kit/rpc-message.c"
grep -q 'case CKM_ML_DSA_KEY_PAIR_GEN:' "$WORK/p11kit/p11-kit/rpc-message.c"
CFLAGS="-w -DNDEBUG" CXXFLAGS="-w -DNDEBUG" \
    meson setup "$WORK/p11kit/build" "$WORK/p11kit" --prefix=/usr --libdir=lib \
        -Dbuildtype=release -Dnls=false
ninja -C "$WORK/p11kit/build" -j"$JOBS"
# ⚠️ BOTH SIDES OF THE SOCKET. The client shim every app loads, the library behind it, and
# the `p11-kit server` the sidecar runs all have to be the patched build. Installing one
# side leaves the mechanism filter in place at the other end — the sort of half-fix that
# looks like it worked until an ML-DSA CA is attempted.
#
# Two files carry the whole patch, and between them they cover both ends: the patch edits
# p11-kit/rpc-message.{c,h}, which compile into libp11-kit.so.0 — so the PACKAGED
# /usr/libexec/p11-kit/p11-kit-server binary (from apk) picks the fix up through the
# shared library it links, and the client shim carries its own copy. That is exactly what
# the Dockerfile installs, and replacing the server binary as well would only add a
# version skew between it and the rest of the apk package.
inst 0755 "$WORK/p11kit/build/p11-kit/p11-kit-client.so" /usr/lib/pkcs11/p11-kit-client.so
inst 0755 "$WORK/p11kit/build/p11-kit/libp11-kit.so.0"   /usr/lib/libp11-kit.so.0
# Both files belong to Alpine packages as well; hold those packages, or the next
# `apk upgrade` puts the unpatched libraries back (deploy/native/hold-p11-kit.sh).
sh "$HERE/hold-p11-kit.sh"

# ── SoftHSM (patched, main branch: ML-DSA) ───────────────────────────────────────────
echo "==> SoftHSM $SOFTHSM_COMMIT (patched)" >&2
git clone --depth 1 --branch main https://github.com/softhsm/SoftHSMv2 "$WORK/softhsm"
git -C "$WORK/softhsm" fetch --depth 1 origin "$SOFTHSM_COMMIT"
git -C "$WORK/softhsm" checkout "$SOFTHSM_COMMIT"
patch -p1 --forward -d "$WORK/softhsm" -i "$ROOT/deploy/softhsm-allowed-mechs.patch" </dev/null
# WITH_CRYPTO_BACKEND=openssl is pinned rather than auto-detected: the default may pick
# Botan, which lacks ML-DSA at the version Alpine ships.
cmake -S "$WORK/softhsm" -B "$WORK/softhsm/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF -DDISABLE_NON_PAGED_MEMORY=ON \
    -DWITH_CRYPTO_BACKEND=openssl -DOPENSSL_ROOT_DIR=/usr -DENABLE_MLDSA=ON \
    -DCMAKE_C_FLAGS=-w -DCMAKE_CXX_FLAGS=-w
cmake --build "$WORK/softhsm/build" -- "-j$JOBS"
strings "$WORK/softhsm/build/src/lib/libsofthsm2.so" | grep -q "ML.DSA" \
    || { echo "build-native: SoftHSM built without ML-DSA support" >&2; exit 1; }
inst 0755 "$WORK/softhsm/build/src/lib/libsofthsm2.so"       /usr/lib/softhsm/libsofthsm2.so
inst 0755 "$WORK/softhsm/build/src/bin/util/softhsm2-util"   /usr/bin/softhsm2-util
mkdir -p "${DESTDIR}/usr/local/lib/softhsm"
ln -sf /usr/lib/softhsm/libsofthsm2.so "${DESTDIR}/usr/local/lib/softhsm/libsofthsm2.so"
record /usr/local/lib/softhsm/libsofthsm2.so
# ⚠️ THE TOKEN STORE AND ITS CONFIG, mirroring the runtime stage of the Dockerfile. Left
# out, the native path diverges from the image in a way that only appears at first boot:
# `checkpath -d /var/lib/softhsm/tokens` does NOT create parent directories, so
# fastpki-token fails to start with "could not open softhsm: No such file or directory"
# — a message about the PARENT, from a service that names only the child.
#
# /etc/softhsm2.conf is for a human running softhsm2-util by hand; the service exports its
# own SOFTHSM2_CONF so the two can never disagree about where the tokens live.
mkdir -p "${DESTDIR}/var/lib/softhsm/tokens"
chmod 0700 "${DESTDIR}/var/lib/softhsm/tokens"
printf 'directories.tokendir = /var/lib/softhsm/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' \
    > "${DESTDIR}/etc/softhsm2.conf"

# ── FastPKI itself ───────────────────────────────────────────────────────────────────
echo "==> FastPKI binaries" >&2
mkdir -p "$ROOT/third_party/nlohmann"
fetch() { curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors -o "$1" "$2" \
       || curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors -o "$1" "$3"; }
[ -s "$ROOT/third_party/httplib.h" ] || fetch "$ROOT/third_party/httplib.h" \
    "https://cdn.jsdelivr.net/gh/yhirose/cpp-httplib@${HTTPLIB_VERSION}/httplib.h" \
    "https://raw.githubusercontent.com/yhirose/cpp-httplib/${HTTPLIB_VERSION}/httplib.h"
[ -s "$ROOT/third_party/nlohmann/json.hpp" ] || fetch "$ROOT/third_party/nlohmann/json.hpp" \
    "https://cdn.jsdelivr.net/gh/nlohmann/json@${JSON_VERSION}/single_include/nlohmann/json.hpp" \
    "https://raw.githubusercontent.com/nlohmann/json/${JSON_VERSION}/single_include/nlohmann/json.hpp"

# ⚠️ NO -DFASTPKI_WITH_* FLAGS, for the same reason the Dockerfile names none: they are ON
# by default in CMakeLists.txt, and restating them here would let this path keep working
# if a default were ever flipped — silently recreating the divergence where the image had
# LDAP/SAML/Kerberos and another build did not.
# ⚠️ STAMP THE VERSION, OR EVERY NATIVE NODE REPORTS 0.0.0-dev. CMakeLists falls back to
# `git describe` and then to a dev marker, and neither survives this path: the cloud image
# bakes from a copied tree with no .git, so every instance built this way reported
# 0.0.0-dev whatever commit it came from, and the AMI NAME was the only record of what it
# holds. "Which build is this node running?" is the first question an upgrade has to
# answer, and it was unanswerable from the node itself. The container path has always done
# this — release.yml passes -DFASTPKI_VERSION and then checks the binary reports it — so
# this is the same flag on the path that was missing it. Unset, the CMake fallbacks apply
# exactly as before.
cmake -S "$ROOT" -B "$ROOT/build-native" -G Ninja -DCMAKE_BUILD_TYPE=Release \
      ${FASTPKI_VERSION:+-DFASTPKI_VERSION="$FASTPKI_VERSION"}
cmake --build "$ROOT/build-native" -- "-j$JOBS"

for b in "$ROOT"/build-native/fastpki-*; do
    [ -f "$b" ] && [ -x "$b" ] || continue
    inst 0755 "$b" "/usr/local/bin/${b##*/}"
done
inst 0644 "$ROOT/config/bootstrap.conf.example" /usr/share/fastpki/bootstrap.conf.example
mkdir -p "${DESTDIR}/usr/share/fastpki/sql"
cp -R "$ROOT/sql/." "${DESTDIR}/usr/share/fastpki/sql/"
record /usr/share/fastpki/sql
inst 0755 "$ROOT/deploy/certgen.sh"      /usr/share/fastpki/certgen.sh
inst 0755 "$ROOT/deploy/bootstrap.sh"    /usr/share/fastpki/bootstrap.sh
inst 0755 "$ROOT/deploy/schema-apply.sh" /usr/share/fastpki/schema-apply.sh
# The standby's promotion, which docs/high-availability.md section 4 has a native or cloud
# operator run on the node itself. It detects a native host on its own.
inst 0755 "$ROOT/deploy/pg-promote.sh"   /usr/share/fastpki/pg-promote.sh
# And the join that builds the pair, run on each host by deploy/ha-join-pair.sh.
inst 0755 "$ROOT/deploy/ha-join.sh"      /usr/share/fastpki/ha-join.sh
inst 0755 "$HERE/pg-tls-sync.sh"         /usr/libexec/fastpki/pg-tls-sync
inst 0755 "$HERE/hold-p11-kit.sh"        /usr/libexec/fastpki/hold-p11-kit
inst 0755 "$HERE/install-native.sh"      /usr/local/bin/fastpki-install-native

# The licences travel with the binaries, not only with the source tree: MIT (cpp-httplib,
# nlohmann/json — compiled in), BSD (SoftHSM, p11-kit) and Apache (pkcs11-provider,
# OpenSSL) each require their notice to accompany a binary redistribution, and a machine
# image someone boots is a binary redistribution.
inst 0644 "$ROOT/LICENSE.md" /usr/share/fastpki/LICENSE.md
inst 0644 "$ROOT/NOTICE.md"  /usr/share/fastpki/NOTICE.md
inst 0644 "$WORK/softhsm/LICENSE" /usr/share/fastpki/licences/SoftHSMv2.LICENSE
inst 0644 "$WORK/p11kit/COPYING"  /usr/share/fastpki/licences/p11-kit.COPYING
inst 0644 "$WORK/p11p/COPYING"    /usr/share/fastpki/licences/pkcs11-provider.COPYING
# ⚠️ NO ALPINE PACKAGE LIST OR ALPINE LICENCE TEXTS HERE, unlike the Docker image. Those exist
# because publishing the image redistributes the Alpine packages inside it. A native install
# takes them from the operator's own repositories onto the operator's own host, and a cloud
# image is built by the operator in their own account from Alpine's official image — FastPKI
# publishes no machine image — so neither path redistributes anything of Alpine's.

# ── init scripts ─────────────────────────────────────────────────────────────────────
# The template is installed once and symlinked per protocol, the OpenRC equivalent of the
# systemd template unit. install-native.sh decides which symlinks get enabled — a
# protocol the operator declined is not started and not monitored.
echo "==> OpenRC services" >&2
inst 0755 "$HERE/openrc/fastpki.initd"          /etc/init.d/fastpki
inst 0755 "$HERE/openrc/fastpki-token.initd"  /etc/init.d/fastpki-token
inst 0755 "$HERE/openrc/fastpki-p11-tls.initd"  /etc/init.d/fastpki-p11-tls
inst 0755 "$HERE/openrc/fastpki-p11-tls-run.sh" /usr/libexec/fastpki/fastpki-p11-tls-run.sh
inst 0755 "$HERE/openrc/fastpki-auditfwd.initd" /etc/init.d/fastpki-auditfwd
inst 0755 "$HERE/openrc/fastpki-pgtls.initd"    /etc/init.d/fastpki-pgtls
inst 0755 "$HERE/openrc/fastpki-pgstale.initd"  /etc/init.d/fastpki-pgstale
for p in ocsp web est acme cmp ms store scep; do
    ln -sf fastpki "${DESTDIR}/etc/init.d/fastpki-$p"
    record "/etc/init.d/fastpki-$p"
done
inst 0755 "$HERE/periodic/fastpki-certrenew" /etc/periodic/daily/fastpki-certrenew

# The runtime package list travels too: a package unpacked on a node brings files, not
# packages, so a release that needs a new one must be able to say which.
printf '%s\n' $RUNTIME_PKGS > "$WORK/runtime-packages"
inst 0644 "$WORK/runtime-packages" /usr/share/fastpki/runtime-packages

# ⚠️ AND THE ALPINE RELEASE IT WAS BUILT ON, because the binaries are tied to it and nothing
# else records it. Alpine's sonames move between releases: a package built on 3.24 links
# libxmlsec1-openssl.so.10311, which 3.23 does not have. Unpacked on the wrong release the
# install SUCCEEDS — every file lands, every service reports "started" — and then every
# binary dies at exec with
#
#     Error loading shared library libxmlsec1-openssl.so.10311: No such file or directory
#
# Measured by installing a 3.24 package on a stock Alpine 3.23 cloud image: exit 0, ten
# services "started", console answering nothing at all. install.sh compares this against the
# host and refuses rather than leaving a deployment that looks installed and is dead.
cut -d. -f1,2 /etc/alpine-release > "$WORK/alpine-release"
inst 0644 "$WORK/alpine-release" /usr/share/fastpki/alpine-release
record /usr/share/fastpki/installed-files
inst 0644 "$MANIFEST" /usr/share/fastpki/installed-files

echo
echo "Built and installed. The image is now a FastPKI host with nothing configured."
echo "Configure it with:   fastpki-install-native"
