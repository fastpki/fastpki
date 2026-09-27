#!/bin/sh
# ⚠️ POSIX sh, NOT bash, AND THAT IS NOT A STYLE CHOICE. `--native` targets Alpine, and a
# stock Alpine host has no bash at all. The documented one-liner therefore failed on the
# only platform that path exists for: piped to `sh` it died with `syntax error: unexpected
# "("` on the first array, and piped to `bash` with `bash: not found`. Measured on a fresh
# Alpine 3.23 cloud instance.
#
# `sh` parses the whole file before running any of it, so a bash-ism anywhere breaks the
# native path even though it sits in a branch of its own — which is why this is POSIX
# throughout rather than only where it has to be. What that costs: argument lists are built
# as quoted strings and restored with `eval set --` instead of arrays. Keep it that way.
# deployment-path: dispatch — it hands over. Compose itself; --k8s to deploy/k8s/apply.sh; --native to the
# published native package, or deploy/native/install-native.sh from a checkout. Cloud nodes are
# native, and deploy/cloud/cloud-install.sh drives the whole VPC rather than one host.
# FastPKI interactive install wizard. Run on a fresh server to
# generate this node's deploy/.env — the per-node/per-deployment overrides that
# compose injects into every container — then it prints the exact
# build / bootstrap / up commands. Keeps the git-tracked bootstrap.compose.conf
# universal; nothing here patches a committed file.
#
# The headline feature is multi-data-center provisioning: in an N-node active-active
# mesh every node mints certificate serials under a 2-octet prefix that is its own
# so two nodes can never produce the same serial — which
# matters because the serial is the certs primary key, and a collision stalls a peer's
# replication apply worker. This node's index IS its prefix. EVERY node is installed the
# same way — the same answers file with only DC_INDEX, PKI_DNS and PG_BIND changed.
#
# ⚠️ THE PREFIX IS NOT WRITTEN INTO .env, ON PURPOSE. Only DATACENTER_ID is. The
# prefix lives in the `datacenters` table, which `fastpki-mesh --map` fills from the
# topology file, and the node reads its own row at startup. One source of truth: the
# earlier design had the bound in TWO places (this .env and the guard trigger) with
# nothing comparing them.
#
# Dependencies: bash + coreutils ONLY. This used to do 160-bit base-16 long division in
# pure shell to slice the serial space; a small integer per node replaced all of it.
#
# Usage — from a checkout:
#   ./install.sh                     # interactive
#   ./install.sh --k8s               # deploy to Kubernetes instead of compose
#   ./install.sh --native            # this Alpine host, no containers at all
#   ./install.sh --package P.tar.gz  # native, from a package already on this host
#   ./install.sh --answers ans.env   # non-interactive (CI / scripted / next node)
#   ./install.sh --answers ans.env --print-env   # write nothing; print .env to stdout
#   ./install.sh --no-deploy         # write .env and STOP; print the commands instead
#
# Usage — one command, no checkout (the script bootstraps itself):
#   URL=https://github.com/fastpki/fastpki/releases/latest/download/install.sh
#   curl -fsSL $URL | bash                                # latest release
#   curl -fsSL $URL | bash -s -- --version v0.1.0         # pinned (the tag, leading v included)
#   curl -fsSL $URL | bash -s -- --k8s --non-interactive  # unattended, Kubernetes
#   wget -qO- $URL | doas sh -s -- --native               # a native Alpine host
#
# ⚠️ `wget` AND `sh` ON ALPINE, BECAUSE A STOCK ONE HAS NEITHER curl NOR bash. wget is part
# of busybox and is already there; this script is POSIX sh for the same reason — see the note
# at the very top. Measured on a fresh alpine-3.24.1 cloud image: no curl, no bash, and
# `wget -qO- … | sh -s -- --native` installs a working deployment. `curl … | bash` is fine
# anywhere that has them.
#
# ⚠️ github.com PUBLISHES NO IPv6 ADDRESS, so an IPv6-only host — which is how FastPKI's own
# cloud module builds them — cannot reach it at all. The same signed releases are served from
# fastpki.com over both families, and this script falls back to it by itself. On such a host
# fetch the script from there too:
#   wget -qO- https://fastpki.com/install.sh | doas sh -s -- --native
# With no route to either, copy the package, SHA256SUMS and SHA256SUMS.sig over together:
#   sudo ./install.sh --package fastpki-native-<version>-<arch>.tar.gz
#
# ⚠️ EVERY PATH CHECKS THE RELEASE SIGNATURE: the source tarball, the native download, and a
# local --package. SHA256SUMS alone comes from the same server as the files, so it catches a
# corrupted download and not a substituted one; SHA256SUMS.sig is what says we made it. There
# is no flag to skip this, and an unsigned release is refused.
#
# ── WHAT --native DOES DIFFERENTLY ────────────────────────────────────────────────────
#
# Piped, it does NOT download the source: a native host has nothing to compile it with, and
# install-native.sh configures services around binaries rather than building them. It takes
# the published fastpki-native-<version>-<arch>.tar.gz for THIS machine's architecture,
# verifies the release signature and then the package against SHA256SUMS, unpacks it into / —
# which is what puts fastpki-install-native on the PATH — and hands over to it. It needs root
# for the unpack.
#
# From a checkout there is no published package for the code in front of you, so it hands
# straight to deploy/native/install-native.sh, which says to run build-native.sh first if
# the binaries are not there yet.
#
# Piped, it downloads the release tarball, VERIFIES it against the published SHA256SUMS,
# unpacks it (--dir, default ./fastpki-<version>) and re-execs itself from there. It also
# re-attaches the terminal, because `| bash` has already spent stdin on the script — without
# that every prompt reads EOF and takes its default, which looks like an installer that
# ignored you. With no terminal available an interactive run is refused, not defaulted.
#
# By default this finishes the install: it writes .env and then runs the build /
# postgres / bootstrap / up sequence, because those four commands are the same four
# every time and splitting them off just means an operator can stop half-installed
# --no-deploy is the escape hatch when you want the .env only.
#
# Answers file / env keys (all optional; sensible defaults):
#   DEPLOYMENT=single|cluster   FASTPKI_IMAGE=  PKI_DNS=  PG_BIND=
#   DC_INDEX=<i>   (cluster only; i in 1..32767, unique across the mesh)
#   KEY_BACKEND=softhsm|hsm      PKCS11_MODULE=<abs path>  PKCS11_TOKEN=  (when KEY_BACKEND=hsm)
#   WANT_EST= WANT_ACME= WANT_CMP= WANT_SCEP= WANT_MS= WANT_STORE=   yes|no per protocol
#   HA_ENABLED=yes|no            this data center will have a standby on a second host:
#                                the key tunnel on, service keys created copyable. The
#                                standby itself is joined later with deploy/ha-join.sh.
#                                Unrelated to DEPLOYMENT=cluster, which is about several
#                                data centers.
# `pipefail` is not POSIX: bash and busybox ash have it, dash does not, and on dash asking
# for it is a fatal error before anything has run. Asked for where it exists, skipped where
# it does not.
set -eu
( set -o pipefail ) 2>/dev/null && set -o pipefail || true
# ⚠️ NO `dirname` HERE. It is an external command, and on a PATH without it the
# substitution is empty and this becomes `cd ""`. Alpine — what we ship — treats that as
# fatal ("null directory") and the wizard stops before writing anything. macOS bash 3.2
# treats it as a no-op that SUCCEEDS, so on the dev box HERE silently became the current
# directory, which happened to be right, and the assertion covering this went green for
# the wrong reason. `set -euo pipefail` does not catch it either: a failing command
# substitution inside an assignment does not trip `set -e`.
#
# Parameter expansion needs no PATH lookup at all. The no-slash case is `install.sh`
# resolved through PATH, where the script's directory is not derivable from $0 — fall
# back to the working directory and say so rather than guessing silently.
case "$0" in
    */*) HERE="$(cd "${0%/*}" && pwd)" ;;
    *)   HERE="$(pwd)"
         echo "install.sh: invoked without a path; assuming the deploy directory is $HERE" >&2 ;;
esac
ENV_OUT="$HERE/.env"

# Keep the ORIGINAL arguments: the curl-pipe bootstrap below re-execs this script from the
# tree it downloads, and it has to hand on exactly what the operator typed.
#
# Held as a single shell-quoted string rather than an array, because this script must parse
# under POSIX sh (see the top). `eval set -- "$ORIG_ARGS"` restores them exactly, spaces and
# quotes included, which a space-separated list would not.
quote_arg() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
ORIG_ARGS=''
for _a in "$@"; do ORIG_ARGS="$ORIG_ARGS $(quote_arg "$_a")"; done
unset _a

ANSWERS=""; PRINT_ONLY=0; DO_DEPLOY=1; PKG_FILE=""
TARGET=compose; WANT_VERSION=""; DEST_DIR=""; NONINTERACTIVE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --answers) ANSWERS="${2:?--answers needs a file}"; shift 2 ;;
    --print-env) PRINT_ONLY=1; shift ;;
    --no-deploy) DO_DEPLOY=0; shift ;;
    --compose) TARGET=compose; shift ;;
    --k8s|--kubernetes) TARGET=k8s; shift ;;
    --native) TARGET=native; shift ;;
    # ⚠️ FOR A NODE THAT CANNOT REACH GITHUB, which is the normal case for the cloud
    # image: deploy/cloud/README.md says a node has no build tools "and often no
    # internet access", and FastPKI's own module builds IPv6-only nodes, which cannot
    # reach github.com at all because it publishes no AAAA record. Download the package
    # where you can and name it here; everything after the download is identical.
    --package) TARGET=native; PKG_FILE="${2:?--package needs a file}"; shift 2 ;;
    --version) WANT_VERSION="${2:?--version needs a tag, e.g. v0.1.0}"; shift 2 ;;
    --dir) DEST_DIR="${2:?--dir needs a path}"; shift 2 ;;
    --non-interactive) NONINTERACTIVE=1; shift ;;
    -h|--help) sed -n '2,50p' "$0"; exit 0 ;;   # the whole header, not a truncated half
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# ── curl-pipe bootstrap ──────────────────────────────────────────────────────────────
#
# `curl -fsSL .../install.sh | bash` delivers this file and nothing else, while the wizard
# below reads its siblings by relative path — docker-compose.yml, schema-apply.sh,
# pki.compose.conf, k8s/. Piped, it would die on the first one. So when the siblings are
# absent, this is a BOOTSTRAPPER: fetch the release tarball, verify it, unpack it, and
# re-exec the copy inside it with the operator's own arguments. The wizard is unchanged and
# is still the thing that does the install.
#
# ⚠️ THE DOWNLOAD IS VERIFIED, AND FOR A CA THAT IS NOT OPTIONAL. A pipe-to-shell installer
# that unpacks whatever arrives is a supply-chain hole in the one product whose whole job is
# to be trusted. release.yml already publishes SHA256SUMS beside the tarball, so the sums
# are fetched and checked before anything is extracted, and a mismatch aborts.
#
# ⚠️ AND STDIN IS ALREADY GONE. `| bash` gives the shell the SCRIPT on stdin, so every
# prompt in the wizard reads EOF and silently takes its default — an installer that appears
# to ignore every answer. The tty is re-attached when there is one; when there is not (CI, a
# provisioning script), an interactive run is REFUSED rather than run on defaults, and the
# message names the two flags that make it valid.
# ⚠️ "ANY REAL SIBLING", NOT "ALL OF THEM". This required docker-compose.yml AND k8s/, which
# is wrong twice over: tests/schema_version.sh stages a copy of this script in a temp dir
# with only a stub schema-apply.sh beside it, and a partial checkout is a legitimate shape
# too. Both were treated as "piped from curl" and tried to DOWNLOAD A RELEASE — the suite
# saw exit 1 where it expected 0, and an operator would have watched a local install
# silently fetch the internet. A genuine curl-pipe lands in a directory with none of these.
in_tree() {
    [ -f "$HERE/schema-apply.sh" ] || [ -f "$HERE/docker-compose.yml" ] || [ -d "$HERE/k8s" ]
}

if ! in_tree; then
  REPO="${FASTPKI_REPO:-fastpki/fastpki}"
  API="${FASTPKI_API_BASE:-https://api.github.com}"
  fetch() { # <url> <out>
    # A bounded connect: on an IPv6-only host github.com does not refuse, it simply never
    # answers, and an unbounded wait there held the whole install for ~25 seconds before the
    # mirror could even be tried.
    if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 10 "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then wget -q -T 10 -O "$2" "$1"
    else echo "install.sh: need curl or wget to bootstrap" >&2; return 1; fi
  }
  sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
    else echo "install.sh: need sha256sum or shasum to verify the download" >&2; return 1; fi
  }

  # ── THE RELEASE SIGNATURE ─────────────────────────────────────────────────────────────
  # ⚠️ A CHECKSUM FROM THE SAME PLACE AS THE FILE PROVES NOTHING ABOUT WHO MADE IT. This
  # compared each download against SHA256SUMS and stopped there — but SHA256SUMS comes from
  # the same server, so anyone able to replace the package could replace the list to match.
  # It caught a corrupted download and never a substituted one.
  #
  # Every release now carries SHA256SUMS.sig, made on the maintainer's own machine with a key
  # that never reaches CI. The public half is written below, so the check needs no network:
  # the signature makes the list trustworthy, and the list makes every file trustworthy.
  #
  # ECDSA P-256 rather than the release's ML-DSA-87 signature, because this runs on whatever
  # OpenSSL the host has, and the 3.0 that several long-term distributions ship cannot read
  # ML-DSA. FASTPKI_RELEASE_PUBKEY points at another PEM for someone publishing their own builds.
  #
  # There is no way to skip this. A release without a signature is refused, and so is a local
  # package without SHA256SUMS and SHA256SUMS.sig beside it.
  RELEASE_PUBKEY_ECDSA='-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkm3I0lmBE/YqkZfr1QBtviiE/bBG
Sh/CXT5NtA7TIGNJVZa3U2KEhKN1IGZRkYNHMLtzjpj2GB/cZMfevZH8LA==
-----END PUBLIC KEY-----'

  need_openssl() {
    command -v openssl >/dev/null 2>&1 && return 0
    # Alpine's cloud image ships the library and not the command. Its package mirror is
    # reachable over IPv6, which is more than github.com is.
    if command -v apk >/dev/null 2>&1 && [ "$(id -u)" = 0 ]; then
      echo "== installing openssl to check the release signature"
      apk add --no-cache openssl >/dev/null || return 1
      return 0
    fi
    echo "install.sh: openssl is needed to check the release signature — install it and re-run" >&2
    return 1
  }

  verify_sums() { # <dir holding SHA256SUMS and SHA256SUMS.sig>
    [ -s "$1/SHA256SUMS.sig" ] || {
      echo "install.sh: no SHA256SUMS.sig — this release is not signed, so it is not installed." >&2
      return 1; }
    need_openssl || return 1
    if [ -n "${FASTPKI_RELEASE_PUBKEY:-}" ]; then _k="$FASTPKI_RELEASE_PUBKEY"
    else _k="$1/release-ecdsa.pub"; printf '%s\n' "$RELEASE_PUBKEY_ECDSA" > "$_k"; fi
    if ! openssl dgst -sha256 -verify "$_k" -signature "$1/SHA256SUMS.sig" "$1/SHA256SUMS" >/dev/null 2>&1; then
      echo "install.sh: SIGNATURE CHECK FAILED for SHA256SUMS." >&2
      echo "  The list of hashes was not signed with the FastPKI release key, so nothing it" >&2
      echo "  vouches for can be trusted. Nothing has been unpacked." >&2
      return 1
    fi
    echo "== release signature verified (SHA256SUMS, ECDSA P-256)"
  }

  sum_matches() { # <file> <name as listed> <SHA256SUMS>
    # Dots escaped: in the pattern an unescaped one matches any character, so a name would
    # also match lines it should not.
    _n=$(printf '%s' "$2" | sed 's/[.]/\\./g')
    _want=$(sed -n "s#^\([0-9a-f]\{64\}\)[[:space:]]*[*]\{0,1\}\(\./\)\{0,1\}$_n\$#\1#p" "$3" | head -1)
    _got=$(sha256_of "$1") || return 1
    [ -n "$_want" ] || { echo "install.sh: SHA256SUMS has no entry for $2" >&2; return 1; }
    [ "$_want" = "$_got" ] || {
      echo "install.sh: CHECKSUM MISMATCH for $2" >&2
      echo "  expected $_want" >&2
      echo "  got      $_got" >&2
      return 1; }
    echo "== $2 matches the signed SHA256SUMS (sha256 $(printf '%.8s' "$_got"))"
  }

  # ⚠️ THE PACKAGE BRINGS FILES, NOT PACKAGES, and its programs are linked against Alpine's.
  # build-native.sh ships the list inside the package for exactly this, and until now nothing
  # acted on it: a fresh host had 4 of the 16 — and `bash` was among the missing, which
  # fastpki-install-native itself needs to start. So the handover died with
  #
  #     env: can't execute 'bash': No such file or directory
  #
  # after the unpack had already happened, leaving a half-installed host. Measured on a stock
  # Alpine 3.23 cloud image.
  # ⚠️ THE PACKAGE IS TIED TO THE ALPINE RELEASE IT WAS BUILT ON. Sonames move between
  # releases, so a 3.24 package on 3.23 unpacks perfectly, reports success, starts ten
  # services — and every binary then dies at exec for want of libxmlsec1-openssl.so.10311.
  # Refusing here is the difference between a clear message and a deployment that looks
  # installed and answers nothing. Checked after the unpack because the package is what
  # carries the answer.
  check_alpine_release() {
    [ -r /usr/share/fastpki/alpine-release ] || return 0
    [ -r /etc/alpine-release ] || return 0
    _built=$(cat /usr/share/fastpki/alpine-release)
    _host=$(cut -d. -f1,2 /etc/alpine-release)
    [ "$_built" = "$_host" ] && { unset _built _host; return 0; }
    echo "install.sh: this package was built for Alpine $_built and this host is $_host." >&2
    echo "  Alpine moves shared-library versions between releases, so the programs would" >&2
    echo "  install cleanly and then fail to start, which is worse than stopping here." >&2
    echo "  Use an Alpine $_built host, or a package built for $_host." >&2
    return 1
  }

  # $1 is the package just unpacked. ⚠️ IT IS UNPACKED AGAIN AFTER apk ADDS ANYTHING. The
  # package carries patched builds of p11-kit's libraries (/usr/lib/libp11-kit.so.0 and
  # p11-kit-client.so), and p11-kit is one of the packages listed here. On a fresh host,
  # `apk add p11-kit` writes Alpine's stock libraries over the patched ones, which drop the
  # EdDSA and ML-DSA mechanisms, so the console reported Ed25519, Ed448 and ML-DSA keys as
  # absent from the token. The list lives inside the package, so it cannot be read first.
  install_runtime_packages() {
    [ -r /usr/share/fastpki/runtime-packages ] || return 0
    if ! command -v apk >/dev/null 2>&1; then
      echo "install.sh: this package is built for Alpine and this host has no apk." >&2
      echo "  Its programs need these, however your system provides them:" >&2
      tr '\n' ' ' < /usr/share/fastpki/runtime-packages >&2; echo >&2
      return 1
    fi
    _missing=''
    for _p in $(cat /usr/share/fastpki/runtime-packages); do
      apk info -e "$_p" >/dev/null 2>&1 || _missing="$_missing $_p"
    done
    [ -n "$_missing" ] || return 0
    echo "== installing the Alpine packages this release needs:$_missing"
    # Word-splitting is what is wanted here: the list is package names, never paths.
    apk add --no-cache $_missing >/dev/null \
      || { echo "install.sh: could not install:$_missing" >&2; return 1; }
    ( umask 022; tar xzf "$1" -C / ) \
      || { echo "install.sh: could not unpack $1 again over the Alpine packages" >&2; return 1; }
    unset _missing _p
  }

  # ⚠️ A LOCAL PACKAGE SHORT-CIRCUITS EVERYTHING ABOVE, INCLUDING THE VERSION LOOKUP. The
  # point of --package is a node that cannot reach GitHub, so it must not ask GitHub what the
  # latest release is on the way past.
  #
  # ⚠️ AND IT IS VERIFIED ALL THE SAME, WITHOUT THE NETWORK. This used to unpack whatever it
  # was given, on the grounds that re-checking would need the network this path avoids. A
  # signature needs no network: SHA256SUMS and SHA256SUMS.sig copied over beside the package,
  # and the public key written above, are everything the check reads.
  if [ -n "$PKG_FILE" ]; then
    [ -f "$PKG_FILE" ] || { echo "install.sh: no such package: $PKG_FILE" >&2; exit 1; }
    [ "$(id -u)" = 0 ] || { echo "install.sh: unpacking a native package needs root" >&2; exit 1; }
    case "$PKG_FILE" in
      *-"$(uname -m | sed 's/^x86_64$/amd64/; s/^aarch64$/arm64/')".tar.gz) ;;
      *) echo "install.sh: $PKG_FILE does not look like the package for $(uname -m)." >&2
         echo "  A package built for another architecture unpacks cleanly and then every" >&2
         echo "  service fails to exec. Take the one matching this host." >&2
         exit 1 ;;
    esac
    # The package's directory by parameter expansion: this script calls no dirname.
    case "$PKG_FILE" in */*) _pdir=${PKG_FILE%/*} ;; *) _pdir=. ;; esac
    _pdir=$(cd "${_pdir:-/}" && pwd)
    if [ ! -f "$_pdir/SHA256SUMS" ] || [ ! -f "$_pdir/SHA256SUMS.sig" ]; then
      echo "install.sh: copy SHA256SUMS and SHA256SUMS.sig from the same release into $_pdir" >&2
      echo "  beside the package. They are what prove it came from FastPKI." >&2
      exit 1
    fi
    TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
    cp "$_pdir/SHA256SUMS" "$_pdir/SHA256SUMS.sig" "$TMP/"
    verify_sums "$TMP" || exit 1
    sum_matches "$PKG_FILE" "$(basename "$PKG_FILE")" "$TMP/SHA256SUMS" || exit 1
    echo "== installing from $PKG_FILE"
    # umask 022 for the unpack, as below.
    ( umask 022; tar xzf "$PKG_FILE" -C / )
    check_alpine_release || exit 1
    install_runtime_packages "$PKG_FILE" || exit 1
    command -v fastpki-install-native >/dev/null 2>&1 \
      || { echo "install.sh: the package did not provide fastpki-install-native" >&2; exit 1; }
    echo "== unpacked; handing over to fastpki-install-native"
    if [ -n "$ANSWERS" ]; then
      case "$ANSWERS" in /*) ;; *) ANSWERS="$PWD/$ANSWERS" ;; esac
      exec fastpki-install-native --answers "$ANSWERS"
    fi
    exec fastpki-install-native
  fi

  # ⚠️ GITHUB FIRST, AND FASTPKI.COM WHEN GITHUB CANNOT BE REACHED. github.com publishes no
  # IPv6 address, so an IPv6-only host — which is what FastPKI's own cloud module builds —
  # cannot reach it at all, however healthy its network is: HTTP 000 after 25 seconds,
  # measured on a fresh Alpine instance in that VPC. fastpki.com serves the same signed
  # releases over both address families.
  #
  # Where the files come from does not change what is trusted: every path below checks the
  # release signature, so the mirror needs to be reachable, not trusted.
  MIRROR="${FASTPKI_MIRROR:-https://fastpki.com/releases}"
  # Asked at most once, and only when the answer is needed: a caller that names both the
  # version and FASTPKI_DOWNLOAD_BASE, as a cloud first boot does, never waits on it.
  github_ok=unknown
  github_probe() {
    [ "$github_ok" = unknown ] || return 0
    if fetch "$API" /dev/null 2>/dev/null; then github_ok=yes; else github_ok=no; fi
  }

  V="$WANT_VERSION"
  if [ -z "$V" ]; then
    # The newest published release. Deliberately NOT a branch: an installer that tracks a
    # moving target installs something different every time it is run.
    github_probe
    if [ "$github_ok" = yes ]; then
      V=$(fetch "$API/repos/$REPO/releases/latest" /dev/stdout 2>/dev/null \
          | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1) || true
    fi
    if [ -z "$V" ]; then
      V=$(fetch "$MIRROR/latest" /dev/stdout 2>/dev/null | tr -d ' \r\n') || true
    fi
    if [ -z "$V" ]; then
      echo "install.sh: cannot find the latest release: neither $API nor $MIRROR answered." >&2
      echo "  Pass --version <tag> if you know it, or copy the package over and use --package." >&2
      exit 1
    fi
  fi
  if [ -n "${FASTPKI_DOWNLOAD_BASE:-}" ]; then
    BASE="$FASTPKI_DOWNLOAD_BASE"
  elif github_probe; [ "$github_ok" = yes ]; then
    BASE="https://github.com/$REPO/releases/download/$V"
  else
    BASE="$MIRROR/$V"
    echo "== github.com is unreachable (it has no IPv6 address); downloading from $MIRROR"
  fi

  # ⚠️ A NATIVE HOST WANTS THE COMPILED PACKAGE, NOT THE SOURCE. install-native.sh
  # configures OpenRC services, Postgres and /etc/fastpki around binaries that must already
  # be on the host; it downloads nothing. So --native takes the published
  # fastpki-native-<version>-<arch>.tar.gz, verifies it, unpacks it — which is what puts
  # fastpki-install-native on the PATH — and hands over. The source tarball is never
  # fetched, because nothing here would compile it.
  #
  # THE ARCHITECTURE IS THE NODE'S OWN, from `uname -m`. This package is compiled, so the
  # wrong one does not fail here: it fails later as an exec format error from a service,
  # after this script has reported success.
  if [ "$TARGET" = native ]; then
    case "$(uname -m)" in
      x86_64|amd64)  NARCH=amd64 ;;
      aarch64|arm64) NARCH=arm64 ;;
      *) echo "install.sh: no native package is published for $(uname -m)" >&2; exit 1 ;;
    esac
    PKG="fastpki-native-$V-$NARCH.tar.gz"
    echo "== FastPKI $V native package for $NARCH"
    [ "$(id -u)" = 0 ] || { echo "install.sh: unpacking a native package needs root" >&2; exit 1; }
    TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
    fetch "$BASE/$PKG" "$TMP/$PKG" \
      || { echo "install.sh: could not download $PKG from $BASE" >&2; exit 1; }
    fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" \
      || { echo "install.sh: could not download SHA256SUMS — refusing to unpack unverified binaries" >&2; exit 1; }
    fetch "$BASE/SHA256SUMS.sig" "$TMP/SHA256SUMS.sig" 2>/dev/null || true
    verify_sums "$TMP" || exit 1
    sum_matches "$TMP/$PKG" "$PKG" "$TMP/SHA256SUMS" || exit 1
    # ⚠️ umask 022 FOR THE UNPACK, WHATEVER THE CALLER'S. The package lists files and not their
    # directories, so tar creates any missing directory itself, with the current umask. Under a
    # strict one — a hardened host, or a first-boot script that set 077 for its secrets —
    # /usr/lib/pkcs11 came out 0700, the services running as fastpki could not reach the
    # PKCS#11 module, and they crash-looped while the install reported success.
    ( umask 022; tar xzf "$TMP/$PKG" -C / )
    check_alpine_release || exit 1
    install_runtime_packages "$TMP/$PKG" || exit 1
    command -v fastpki-install-native >/dev/null 2>&1 \
      || { echo "install.sh: the package did not provide fastpki-install-native" >&2; exit 1; }
    # ⚠️ BUILT HERE, NOT FROM PASS_ARGS. That array is assembled further down, for the
    # re-exec of the SOURCE tree, and does not exist yet on this path — using it would
    # silently drop --answers and turn a scripted install into an interactive one that
    # then finds no terminal. Only the flags install-native.sh actually takes are passed;
    # --answers is resolved to an absolute path because we are about to exec from /.
    echo "== unpacked; handing over to fastpki-install-native"
    if [ -n "$ANSWERS" ]; then
      case "$ANSWERS" in /*) ;; *) ANSWERS="$PWD/$ANSWERS" ;; esac
      exec fastpki-install-native --answers "$ANSWERS"
    fi
    exec fastpki-install-native
  fi

  DEST="${DEST_DIR:-$PWD/fastpki-$V}"

  echo "== FastPKI $V -> $DEST"
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
  fetch "$BASE/fastpki-$V.tar.gz" "$TMP/src.tar.gz" \
    || { echo "install.sh: could not download fastpki-$V.tar.gz from $BASE" >&2; exit 1; }
  fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" \
    || { echo "install.sh: could not download SHA256SUMS — refusing to unpack unverified source" >&2; exit 1; }
  fetch "$BASE/SHA256SUMS.sig" "$TMP/SHA256SUMS.sig" 2>/dev/null || true
  verify_sums "$TMP" || exit 1

  # ⚠️ MATCH ON THE BASENAME, which sum_matches does. release.yml generates the sums with
  # `cd dist && sha256sum ./*.tar.gz`, so every line is prefixed `./` — comparing the paths
  # verbatim would never match and the check would either always fail or, if written the other
  # way, always pass.
  cp "$TMP/src.tar.gz" "$TMP/fastpki-$V.tar.gz"
  sum_matches "$TMP/fastpki-$V.tar.gz" "fastpki-$V.tar.gz" "$TMP/SHA256SUMS" || exit 1

  mkdir -p "$DEST"
  # --strip-components=1: the archive carries a fastpki-<version>/ prefix (git archive
  # --prefix in release.yml), and the operator asked for $DEST, not $DEST/fastpki-<v>/.
  tar -xzf "$TMP/src.tar.gz" -C "$DEST" --strip-components=1
  [ -x "$DEST/deploy/install.sh" ] || { echo "install.sh: the tarball has no deploy/install.sh" >&2; exit 1; }

  # Re-attach a terminal before handing over, or the wizard inherits this script on stdin.
  if [ "$NONINTERACTIVE" -eq 0 ] && [ -z "$ANSWERS" ] && [ ! -t 0 ]; then
    if [ -e /dev/tty ] && (exec </dev/tty) 2>/dev/null; then
      exec </dev/tty
    else
      echo "install.sh: stdin is not a terminal, so the wizard cannot ask anything." >&2
      echo "  Re-run with --answers <file> or --non-interactive (defaults for everything)." >&2
      exit 2
    fi
  fi
  # ⚠️ STRIP THE BOOTSTRAP-ONLY FLAGS. The script doing the fetching is the NEWEST one —
  # whatever the operator curl'd — but the script it hands over to came out of the PINNED
  # tarball and may be older than these flags. Forwarding `--version` to a 0.1.0 installer
  # that never had it aborts the install with "unknown arg" after the download has already
  # succeeded, which is the most confusing possible moment to fail. They are also spent:
  # the version has been fetched and the directory has been chosen.
  PASS_ARGS=''; _skip=0
  eval "set -- $ORIG_ARGS"
  for _a in "$@"; do
    if [ "$_skip" -eq 1 ]; then _skip=0; continue; fi
    case "$_a" in
      --version|--dir) _skip=1 ;;
      *) PASS_ARGS="$PASS_ARGS $(quote_arg "$_a")" ;;
    esac
  done
  unset _a _skip
  # ⚠️ AN INSTALL FROM A RELEASE PULLS THE PUBLISHED IMAGE; IT DOES NOT COMPILE ONE.
  # We know the tag here - it is what was just downloaded and checksum-verified - so the
  # wizard's image default is that release's image rather than the bare name that means
  # "build from source". Without this, the documented one-liner compiled four C/C++
  # projects on the operator's server: 15-25 minutes on a small node, and on a 2-CPU
  # machine it can exhaust memory and take the host down. A checkout still defaults to
  # fastpki:local, which is correct there, because a checkout has no published tag.
  #
  # Passed as an ENV VAR, not a flag. The script handing over is the newest one and the
  # one receiving it came out of the pinned tarball, so it may be older: an unknown env
  # var is ignored, while an unknown flag aborts the install after the download has
  # already succeeded. GHCR paths are lowercase, hence the tr.
  FASTPKI_RELEASE_IMAGE="ghcr.io/$(echo "$REPO" | tr '[:upper:]' '[:lower:]'):$V"
  export FASTPKI_RELEASE_IMAGE
  echo "== handing over to $DEST/deploy/install.sh"
  eval "exec \"\$DEST/deploy/install.sh\"$PASS_ARGS"
fi

# ── in-tree from here down ───────────────────────────────────────────────────────────
# A piped run has already re-exec'd above, so a non-tty here is a scripted invocation and
# must say so rather than answering its own questions.
if [ "$NONINTERACTIVE" -eq 0 ] && [ -z "$ANSWERS" ] && [ ! -t 0 ]; then
  echo "install.sh: stdin is not a terminal — use --answers <file> or --non-interactive." >&2
  exit 2
fi

# Kubernetes is a different deployment entirely: its own manifests, its own env, its own
# apply script. The wizard below writes a compose .env, which k8s does not read, so Kubernetes
# has a wizard of its own, deploy/k8s/k8s-install.sh: the same questions under the same
# answers-file keys, writing k8s/env.local, and then apply.sh.
# ⚠️ A NATIVE HOST INSTALLS THE PUBLISHED PACKAGE, NOT THIS TREE. install-native.sh
# configures services around binaries that must already exist; it downloads nothing. From a
# release we therefore fetch and verify the package for THIS architecture, unpack it — which
# is what puts fastpki-install-native on the PATH — and hand over to it. From a checkout
# there is no published package for the code in front of you, so we hand over directly and
# install-native.sh says to run build-native.sh first if the binaries are not there.
#
# The architecture is the node's own, read from `uname -m`, because the package is compiled:
# an arm64 node needs the arm64 build and the failure otherwise is an exec format error from
# a service, long after this script has reported success.
if [ "$TARGET" = native ]; then
  [ -x "$HERE/native/install-native.sh" ] || { echo "install.sh: $HERE/native/install-native.sh is missing" >&2; exit 1; }
  echo "== native target: $HERE/native/install-native.sh"
  echo "   (a checkout has no published package for the code in it, so the binaries must"
  echo "    already be installed — deploy/native/build-native.sh puts them there)"
  # ⚠️ NOT PASS_ARGS. It is built only on the curl-pipe path, so on a checkout it is unset
  # and every flag would be dropped without a word — an --answers install would turn
  # interactive and then fail for want of a terminal.
  if [ -n "$ANSWERS" ]; then
    exec "$HERE/native/install-native.sh" --answers "$ANSWERS"
  fi
  exec "$HERE/native/install-native.sh"
fi

if [ "$TARGET" = k8s ]; then
  [ -f "$HERE/k8s/k8s-install.sh" ] || { echo "install.sh: $HERE/k8s/k8s-install.sh is missing" >&2; exit 1; }
  # ⚠️ NOT PASS_ARGS, for the reason given at the native hand-over above: it exists only on the
  # curl-pipe path. The wizard's own flags are rebuilt from what this script already parsed.
  set --
  [ -n "$ANSWERS" ]          && set -- "$@" --answers "$ANSWERS"
  [ "$NONINTERACTIVE" = 1 ]  && set -- "$@" --non-interactive
  [ "$PRINT_ONLY" = 1 ]      && set -- "$@" --print-env
  [ "$DO_DEPLOY" = 0 ]       && set -- "$@" --no-deploy
  exec sh "$HERE/k8s/k8s-install.sh" "$@"
fi


# ⚠️ THESE HELPERS MUST BE DEFINED BEFORE THE FIRST CALLER, and the first caller is the
# database-preservation block immediately below — not the wizard. `ansval` used to be
# defined ~50 lines further down, so `KEEP_DB="$(ansval KEEP_DB)"` on the non-interactive
# path hit `ansval: command not found` and `set -euo pipefail` killed the script with
# exit 127: no .env written, and the schema step below never reached.
# It is invisible interactively, because a tty takes the `read -r -p` branch instead.
# In --answers mode we read defaults from the file and never prompt.
if [ -n "$ANSWERS" ]; then
  [ -r "$ANSWERS" ] || { echo "cannot read answers file: $ANSWERS" >&2; exit 2; }
fi
ansval() { [ -n "$ANSWERS" ] && sed -n "s/^$1=//p" "$ANSWERS" | head -1 || true; }
interactive() { [ -z "$ANSWERS" ] && [ -t 0 ]; }

# ── Database preservation ──────────────────────────────────────────────────
# When a volume from a previous deployment already exists, the answers to every
# question below are already in the DB and .env — asking them again is noise.
# Offer to keep the volume, skip the interactive wizard, and jump straight to
# build + restart (no bootstrap — the schema and seed data stay intact).
KEEP_DB="no"
if [ "$DO_DEPLOY" = 1 ] && command -v docker >/dev/null 2>&1; then
  if docker volume inspect fastpki_pgdata >/dev/null 2>&1; then
    echo "Found an existing FastPKI database volume and .env — your CAs," >&2
    echo "certificates, users, roles and all settings are preserved on the volume." >&2
    if [ -t 0 ]; then
      printf '%s' "Reuse existing database and skip configuration? (yes/no) [yes]: " >&2
      read -r ans || true
      case "${ans:-yes}" in y|Y|yes|YES|Yes) KEEP_DB="yes" ;; *) KEEP_DB="no" ;; esac
    else
      KEEP_DB="$(ansval KEEP_DB)"
      [ -z "$KEEP_DB" ] && KEEP_DB="no"
    fi
  fi
fi

# ── build it here, or pull what a release published ─────────────────────────────
#
# ⚠️ BOTH PATHS USED TO BUILD, AND THAT MADE A PUBLISHED IMAGE UNREACHABLE. The compose
# file already distinguishes the two — `image: ${FASTPKI_IMAGE:-fastpki:local}` with a
# `build:` beside it — but the installer only ever ran `docker compose build`, so an
# operator who answered the image question with a registry tag got a 15-25 minute compile
# of whatever source happened to be on that node, and the tag they named was applied to
# it. That is not "installing a release"; the released bytes never arrive.
#
# The discriminator is the '/': a registry reference always carries a path
# (ghcr.io/owner/fastpki:v0.1.0, 10.0.0.1:5000/fastpki:latest), and a bare local tag never
# does (fastpki:local). No parsing of hosts or ports, and no new question to answer.
#
# Pulling is also the only correct behaviour on a node that has no source: the cluster
# instructions tell peers to set the tag precisely because they are not build nodes.
obtain_image() {
  # ⚠️ THE REUSE PATH NEVER RAN THE WIZARD, so FASTPKI_IMAGE is not in this shell — it is
  # in .env, which compose reads and this script did not. The case below then fell to its
  # default and BUILT the image from source: answering "yes" to "reuse existing database"
  # started a 15-25 minute compile instead of pulling the release tag the deployment was
  # already running. Reported from a second-datacenter install.
  if [ -z "${FASTPKI_IMAGE:-}" ] && [ -f "$HERE/.env" ]; then
    FASTPKI_IMAGE="$(sed -n 's/^FASTPKI_IMAGE=//p' "$HERE/.env" | head -1)"
    if [ -n "$FASTPKI_IMAGE" ]; then echo "==> image from .env: $FASTPKI_IMAGE" >&2; fi
  fi
  case "${FASTPKI_IMAGE:-}" in
    */*)
      echo "==> pulling $FASTPKI_IMAGE" >&2
      docker pull "$FASTPKI_IMAGE" || {
        echo "FAILED: docker pull $FASTPKI_IMAGE" >&2
        echo "        The image is named by FASTPKI_IMAGE in deploy/.env. If it is in a" >&2
        echo "        private registry, 'docker login' to that registry first." >&2
        return 1; }
      ;;
    *)
      echo "==> building the image locally (FASTPKI_IMAGE=${FASTPKI_IMAGE:-fastpki:local}" \
           "names no registry)" >&2
      docker compose build || { echo "FAILED: docker compose build" >&2; return 1; }
      ;;
  esac
}

# ⚠️ DOCKER DESKTOP REFUSES TO MOUNT A PATH IT WAS NOT TOLD TO SHARE, AND IT REFUSES LATE.
# compose bind-mounts three files out of this directory — bootstrap.compose.conf,
# certgen.sh and bootstrap.sh — so an unshared directory means nothing can start. Without
# this probe the refusal arrives from `compose up`, AFTER the network and both volumes have
# been created, so the operator is left with a half-built deployment and a message about
# one file rather than about the directory. Unpacking a release tarball somewhere outside
# the shared list — ~/Downloads is the usual one — hits this every time.
#
# Probed with the image we already have, so it costs one container start and no pull.
check_bind_mounts() {
  _img="${FASTPKI_IMAGE:-fastpki:local}"
  _err=$(docker run --rm -v "$HERE:/probe:ro" "$_img" true 2>&1) && return 0
  case "$_err" in
    *"not shared from the host"*|*"mounts denied"*|*"is not known to Docker"*)
      echo "FAILED: Docker will not mount $HERE" >&2
      echo "        Docker Desktop shares only the paths it is given. Either add this one:" >&2
      echo "          Settings -> Resources -> File sharing -> +" >&2
      echo "            $HERE" >&2
      echo "          then Apply & restart, and re-run ./install.sh" >&2
      echo "        or move the deployment under a directory that is already shared." >&2
      ;;
    *)
      echo "FAILED: a test bind mount of $HERE did not work:" >&2
      echo "        $_err" >&2
      ;;
  esac
  return 1
}

# ⚠️ `compose up -d` RETURNS WHEN THE CONTAINER STARTS, NOT WHEN POSTGRES ACCEPTS.
# The compose file has a healthcheck (pg_isready, 5s x 12) and `up -d` does not wait for it
# without --wait, so the very next step — schema-apply.sh — raced initdb. It then reported
# "cannot reach the database with PSQL='psql'" and printed the two wrapper commands to set
# by hand, none of which was the problem: the database simply was not up yet. Reported from
# a first-data-center install, where initdb on a cold volume takes longer than the wizard's
# next line.
#
# Polled rather than `up -d --wait`, which needs Compose v2.1.1+ and fails as an unknown
# flag on anything older — a hard failure on a machine where the plain form would have
# worked after a second.
wait_postgres() {
  # ⚠️ pg_isready IS NOT ENOUGH, and this is why. The postgres image runs initdb, brings up
  # a TEMPORARY server so the init scripts can run, stops it, then starts the real one.
  # pg_isready answers yes against that temporary instance, so a wait built on it returns
  # during the init window and the next step lands in the gap while the server restarts —
  # which is exactly what happened on a second-data-center install: the wait passed, then
  # schema-apply.sh failed to connect through a wrapper that worked perfectly a minute
  # later.
  #
  # So wait for a real query, and require it TWICE with a gap. One success can be the
  # temporary server; two across two seconds means the real one is up and staying up.
  _n=0; _ok=0
  while :; do
    if docker compose exec -T postgres psql -U fastpki -d fastpki -w -tAqc 'SELECT 1' \
         >/dev/null 2>&1; then
      _ok=$((_ok + 1))
      if [ "$_ok" -ge 2 ]; then return 0; fi
    else
      _ok=0
    fi
    _n=$((_n + 1))
    if [ "$_n" -ge 90 ]; then
      echo "FAILED: postgres did not accept queries within 90s" >&2
      echo "  docker compose logs postgres    # the reason will be in there" >&2
      return 1
    fi
    if [ "$_n" = 5 ]; then echo "    still waiting for postgres to accept queries..." >&2; fi
    sleep 1
  done
}

if [ "$KEEP_DB" = yes ]; then
  echo "Reusing the existing database — skipping the wizard." >&2
  if [ "$DO_DEPLOY" = 1 ]; then
    cd "$HERE"
    obtain_image || exit 1
    check_bind_mounts || exit 1
    # THIS is the path that was missing the schema step, and it is the one that
    # needs it most — an existing volume is by definition a database from an older build.
    # Without it every service crash-loops on the schema-version startup guard:
    #   "database schema is version 26 but this build needs 27. The schema step of the
    #    deployment was not run (or not run first)."
    # Postgres must be up first, and the app services must NOT be, so the step lands
    # before any binary reads the schema.
    echo "==> starting postgres" >&2
    docker compose up -d postgres || { echo "FAILED: docker compose up -d postgres" >&2; exit 1; }
    wait_postgres || exit 1
    echo "==> applying schema steps (expand/contract)" >&2
    bash "$HERE/schema-apply.sh" || {
        echo "FAILED: schema-apply.sh — do NOT start the new binaries; they will refuse" >&2
        echo "        to run against the older schema. Fix the cause and re-run." >&2
        exit 1; }
    echo "==> restarting services" >&2
    docker compose up -d || { echo "FAILED: docker compose up -d" >&2; exit 1; }
    echo "Installed (database kept)." >&2
  else
    echo "Next steps (run from $HERE):" >&2
    echo "  1. docker compose build   # or: docker pull \$FASTPKI_IMAGE, if it names a registry" >&2
    echo "  2. docker compose up -d postgres" >&2
    echo "  3. ./schema-apply.sh        # BEFORE the app starts, or it refuses the older schema" >&2
    echo "  4. docker compose up -d" >&2
  fi
  exit 0
fi

ask() { # ask VAR "prompt" "default"
  local var="$1" prompt="$2" def="${3:-}" cur ans
  cur="$(ansval "$1")"
  [ -n "$cur" ] && def="$cur"
  # POSIX: no `read -p` and no `printf -v`. Both are bash, and `./install.sh` runs under
  # /bin/sh, which is dash on Debian and Ubuntu — there the compose wizard died at its first
  # question with "printf: Illegal option -v". $var is always one of our own variable names,
  # never input, so the eval assigns and nothing else.
  if interactive; then
    printf '%s' "$prompt [${def}]: " >&2
    read -r ans || true
    eval "$var=\${ans:-\$def}"
  else
    eval "$var=\$def"
  fi
}
# Defined beside ask, before its first use: bash resolves a function when it is CALLED, so a
# yesno defined below the HA_ENABLED question was "command not found" there, and set -e
# stopped every install before .env was written.
yesno() {   # yesno <VAR> <prompt> <default yes|no>
  eval "ask $1 \"$2 (yes/no)\" $3"
  eval "_v=\$$1"
  case "$_v" in
    # true/false too: Kubernetes spells HA_ENABLED that way, and one name means one thing.
    y|Y|yes|YES|Yes|true|TRUE|True)  eval "$1=yes" ;;
    n|N|no|NO|No|false|FALSE|False)  eval "$1=no"  ;;
    *) echo "install: $1 must be yes or no (got '$_v')" >&2; exit 1 ;;
  esac
}

# ⚠️ THE TWO WORDS DO NOT MEAN WHAT THEY LOOK LIKE, so say it before asking. "cluster" is
# about DATACENTERS, not about redundancy inside one — it asks for a mesh size and this
# node's index, and that index becomes the node's certificate-serial prefix. Reported by
# somebody who read "cluster" and reasonably expected the other thing.
#
# ⚠️ NEITHER ANSWER IS "HIGH AVAILABILITY", and saying so here is the point. Surviving the
# loss of THIS host means a second host joining as a streaming standby (deploy/ha-join.sh),
# which is a later step on that host, not an answer here. Nothing covers signing either,
# because a CA key is a handle into this node's token and a peer that replicates the CA
# row cannot sign with it. Calling either answer HA is what sent an operator looking for
# failover that does not exist.
#
# Banner and explanation both interactive-only: a scripted run (--answers / --print-env)
# has nobody to explain a question to, and every such line is one an operator has to
# scroll past to reach the numbered steps below.
if interactive; then
  echo "── FastPKI install wizard ─────────────────────────────────────────────" >&2
  echo "  single  - ONE data center. To survive losing this host, a second host joins" >&2
  echo "            it as a streaming standby later: deploy/ha-join.sh, see docs/high-availability.md." >&2
  echo "  cluster - SEVERAL data centers replicating active-active, each with its own" >&2
  echo "            serial prefix. Neither answer gives you host or HSM failover." >&2
fi
ask DEPLOYMENT   "Deployment type (single / cluster)" "single"
case "$DEPLOYMENT" in single|cluster) ;; *) echo "DEPLOYMENT must be 'single' or 'cluster'" >&2; exit 1 ;; esac

# Installed from a release, the default is that release's published image, so the common
# case downloads ~36 MB instead of compiling. From a checkout there is no published tag and
# the default stays fastpki:local, which builds. Either way a registry tag typed here wins.
ask FASTPKI_IMAGE "Container image (a registry tag is downloaded; a bare name is built)" \
    "${FASTPKI_RELEASE_IMAGE:-fastpki:local}"
ask PKI_DNS       "Public FQDN of this deployment" "pki.example.org"
DC_LINES=""
if [ "$DEPLOYMENT" = cluster ]; then
  # ⚠️ THERE IS NO "NUMBER OF Data centers" TO ANSWER, and asking for one was misleading.
  # This used to prompt for N and then use it for nothing but range-checking the index typed
  # next — N was never written to .env, to the config table or to the database. It sized
  # nothing: the serial prefix is 2 octets whatever N is. But being asked for it up front
  # reads like a ceiling, so an operator with three sites today believed a fourth would need
  # the mesh rebuilding. It does not: install this script on the new node with the next free
  # index and the existing nodes are untouched.
  ask DC_INDEX "This node's data center index — it IS this node's certificate-serial prefix" "1"
  ask PG_BIND  "This node's mesh-reachable IP (peers subscribe to Postgres here)" "127.0.0.1"
  case "$DC_INDEX" in ''|*[!0-9]*) echo "install: DC_INDEX must be a positive integer" >&2; exit 1 ;; esac
  [ "$DC_INDEX" -ge 1 ] || { echo "install: DC_INDEX must be >= 1" >&2; exit 1; }
  # 32767 is the real bound, and now the only one. A DER integer is SIGNED: a prefix with its
  # high bit set makes OpenSSL pad the serial to 21 octets, past the RFC 5280 §4.1.2.2 limit.
  [ "$DC_INDEX" -le 32767 ] || { echo "install: DC_INDEX must be <= 32767 (serial prefix is 2 octets, high bit reserved)" >&2; exit 1; }
  # Each index must be unique across the mesh — that is what stops two data centers minting
  # the same serial — and nothing here can check that, because this node cannot see the
  # others yet. `fastpki-mesh` refuses a duplicate when the nodes are joined.
  # This node's index IS its serial prefix. Only the id goes in .env — see the header.
  DC_LINES=$(printf 'DATACENTER_ID=%s\n' "$DC_INDEX")
else
  ask PG_BIND "Postgres publish address (127.0.0.1 for a single server; this server's own IP if you will add an HA standby)" "127.0.0.1"
  # ⚠️ A SINGLE NODE IS Data center 1, NOT "no data center". It costs nothing now and it is
  # the difference between growing into a mesh later and living with a permanent seam.
  #
  # Without an id, set_random_serial() mints FULL-WIDTH serials carrying no prefix. Add
  # data centers later and every certificate issued before that moment is outside this
  # node's partition forever: the guarantee that two data centers can never mint the same
  # serial only holds from the conversion onward, and `certs_dc_range` refuses those
  # historical rows on any LOCAL insert — which is what a database restore is. With the id
  # set from the first certificate, the history is already inside the partition and none of
  # that arises.
  #
  # The cost is 16 bits of the serial: 18 random octets instead of 20, so 144 bits of
  # entropy against the CA/Browser Forum's 64-bit floor. That is not a trade, it is a
  # rounding error. And a deployment that never grows is unaffected either way — nothing
  # reads the prefix until a second datacenter exists.
  #
  # 1 rather than a question: the first node of a future mesh is data center 1, and asking
  # a single-node operator to pick an index they have no basis to choose is noise.
  DC_INDEX=1
  DC_LINES=$(printf 'DATACENTER_ID=%s\n' "$DC_INDEX")
fi

# ⚠️ ONE SWITCH FOR A PAIR, AND IT IS THE SAME ON EVERY DEPLOYMENT PATH. HA_ENABLED means
# "this data center will have a standby": the key tunnel (P11_TLS) on, so the standby can be
# given copies of the CA keys, and the OCSP, CMP RA and SCEP RA keys created copyable
# (SERVICE_KEYS_REPLICABLE). The second has to be decided NOW. A key is copyable or not from
# the moment it is generated, those keys are generated as soon as a CA exists, and a
# standby that cannot receive them cannot answer OCSP or CMP after a failover — with nothing
# able to fix it later but new keys. Kubernetes (HA_ENABLED), native (the same answer) and
# the AWS module (standby_dcs) set exactly these two.
yesno HA_ENABLED "Will this data center have a standby server that takes over if this one is lost" no
if [ "$HA_ENABLED" = yes ]; then
  case "$PG_BIND" in
    ""|127.*|localhost|::1)
      echo "install: a data center with a standby needs PG_BIND to be this server's own routable" >&2
      echo "  address, because the standby connects to Postgres there. Got '$PG_BIND'." >&2
      exit 1 ;;
  esac
fi

# ⚠️ CMP_CLIENT_CA_ID IS NOT ASKED HERE, and cannot be. It names "a registered CA id", and at
# install time no CA exists — the deployment is created first and CAs are made afterwards from
# the console. So the only answer an operator could give was blank, and a prompt whose only
# valid answer is blank teaches them to press enter through the wizard. Set it later, when
# there is a CA to name: the console's Config page, or `fastpki-config set CMP_CLIENT_CA_ID`.

# Key storage backend. A private key lives in a token and never in a file
# (§3f), so the question is WHICH token, not whether — "file" is deliberately not
# on offer. It was originally specified as a file-vs-HSM choice; the equivalent choice was
# then removed from the console CA form, because only HSM is supported for key
# storage, so this follows the later ruling.
#
#   softhsm  the bundled token container — ONE for the whole deployment, not one
#            per service. p11-kit serves the token over a unix socket so the app
#            never loads SoftHSM in-process (that combination deadlocks).
#            Dev/test posture.
#   hsm      your own PKCS#11 module, loaded directly. The production default.
# Two secrets the wizard used to leave at a shipped default, which meant every
# deployment that followed docs/deployment.md had the same ones. Both are
# offered as a freshly generated value; accepting the offer is the secure path and takes
# one keystroke, which is the only way a default ever gets used.
#
# Generated from the kernel CSPRNG, not $RANDOM — $RANDOM is 15 bits of a seeded PRNG and
# has no business anywhere near a token PIN or a database password.
#
# `head -c` comes FIRST, bounding the read. The obvious spelling puts it last —
# `tr -dc … < /dev/urandom | head -c 32` — and that is a trap: head closes the pipe after
# 32 bytes, tr dies of SIGPIPE, `set -o pipefail` turns the 141 into the pipeline's status
# and `set -e` exits the wizard. It cost a wizard that printed its banner and vanished.
# Only the seven utilities the bare-PATH test allows are used (head, tr, cut).
rand_secret() {
  local n="${1:-32}" s
  s=$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-"$n")
  [ "${#s}" -eq "$n" ] || { echo "install: could not generate $n random characters" >&2; exit 1; }
  printf '%s' "$s"
}
# ⚠️ A SECRET AN EXISTING VOLUME ALREADY DEPENDS ON MUST NOT BE REGENERATED.
#
# POSTGRES_PASSWORD is honoured by the postgres image only at initdb: on a volume that
# already exists the role keeps the password it was created with, so a fresh one does not
# take effect, it merely stops matching. FASTPKI_PIN is the same for the softhsm token
# volume — the token is initialised once, with that PIN.
#
# Declining "Reuse existing database and skip configuration?" means re-answering the
# QUESTIONS; the prompt says configuration, and the line above it says the volume holds
# your CAs. It has never meant "wipe the data". But it re-ran this block, so the install
# then had a new password against an old database: schema-apply.sh still worked (it goes
# through the container's local socket) while bootstrap failed on the TCP connection with
# "password authentication failed for user fastpki". Reported from a second-datacenter
# install.
#
# Carry the old value forward while the volume it belongs to exists. A volume that is gone
# takes its secret with it, and a fresh one is generated exactly as before.
_carry_secret() {   # <volume> <key-in-.env> -> the existing value, or nothing
  docker volume inspect "$1" >/dev/null 2>&1 || return 0
  [ -f "$HERE/.env" ] || return 0
  sed -n "s/^$2=//p" "$HERE/.env" | head -1
}

ask PG_PASSWORD "Postgres password (blank = generate one)" ""
if [ -z "${PG_PASSWORD:-}" ]; then
  PG_PASSWORD="$(_carry_secret fastpki_pgdata POSTGRES_PASSWORD)"
  if [ -n "$PG_PASSWORD" ]; then
    echo "  keeping the existing database password — the pgdata volume still holds it" >&2
  else
    PG_PASSWORD="$(rand_secret 32)"; echo "  generated a 32-character password" >&2
  fi
fi

ask PKCS11_PIN "Token PIN (blank = generate one)" ""
if [ -z "${PKCS11_PIN:-}" ]; then
  PKCS11_PIN="$(_carry_secret fastpki_softhsm-tokens FASTPKI_PIN)"
  if [ -n "$PKCS11_PIN" ]; then
    echo "  keeping the existing token PIN — the token volume still holds it" >&2
  else
    PKCS11_PIN="$(rand_secret 32)"; echo "  generated a 32-character PIN" >&2
  fi
fi

# The global SCEP_CHALLENGE is gone from config and demo, because the challenge is
# per user now. This wizard used to generate a deployment-wide challenge, on the reasoning
# that a challengePassword is the only thing standing between a network peer and an
# issued certificate. That reasoning still holds — what changed is where the value lives.
# Every user now has their own "<user>:<secret>", minted with their role, so the
# wizard has nothing to generate: a SCEP client gets its credential from the console like
# every other protocol, and revoking one device no longer means rotating a secret shared
# by all of them.
# The SERVICES never see the PIN: they get PKCS11_PIN_FILE and read it off disk, because
# a value in the environment shows up in `docker inspect` and in /proc/<pid>/environ for
# every process the container runs. It does pass through the .env once — certgen has to
# be told what to write into that file — which is why the .env is created under `umask
# 077` and chmod 0600 below, and why the wizard redacts it when echoing the file back.
# certgen.sh writes /var/pki/tls/pin 0400 owned by the fastpki user.
PKCS11_PIN_FILE="${PKCS11_PIN_FILE:-/var/pki/tls/pin}"

ask KEY_BACKEND "Key storage (softhsm = bundled token container, dev/test; hsm = your own PKCS#11 module)" "softhsm"

# FastPKI mints keys for ITSELF — the web/EST/ACME/MS transport keys, created inside
# the token the first time each service starts. Nobody asks for them, so until now
# nobody could choose them either: the algorithm was hardcoded ec/P-256.
#
# ⚠️ ASKED PER SERVICE. The first cut of this asked two questions covering every key;
# The wizard is expected to ask key questions for EACH service rather than two questions
# covering all keys, so a customer has full control over the keys per service.
#
# Defaults are exactly what was hardcoded, so Enter throughout produces the keys FastPKI
# has always minted.
#
# ⚠️ ASKING IS NOT MINTING, AND THE TWO GROUPS DIFFER ON THE SECOND.
#
# Four services need a self-signed certificate to START when there are no CAs yet — web
# console, EST, ACME and MS — so their keys are created in the token at first start.
# OCSP, CMP and SCEP do not: they run without their credential and leave the feature off
# until one exists, so minting here would create token objects before any CA could certify
# them.
#
# But the ANSWER is still worth collecting for all seven. Whatever creates an RA credential
# later — `fastpki-ca`, or the console — has to know what key type was wanted, and an
# unattended install has nobody to ask at that point. The answers land in the config table
# as OCSP_RESPONDER_KEY_ALGO / CMP_RA_KEY_ALGO / SCEP_RA_KEY_BITS and wait there.
#
# ⚠️ THE ALLOWED SET IS PER SERVICE, and passed in rather than hardcoded here, because the
# four constraints are genuinely different and a single list would be wrong for three of
# them (docs/compatibility.md §1):
#
#   listeners  ec, rsa, rsa-pss     a TLS peer has to negotiate the key, which rules out
#                                   Ed and ML-DSA whatever the token can hold
#   OCSP       ec, rsa, rsa-pss     a responder answers everything that asks, Windows and
#                                   libpq included, so it gets no less reach than a listener
#   CMP        all eight            the client is OpenSSL, not a browser — the one place a
#                                   post-quantum credential is reachable from the wizard
#   SCEP       rsa, size only       the RA key DECRYPTS the PKIOperation envelope, so it
#                                   needs keyEncipherment: RSA-PSS is signature-only and EC
#                                   does key agreement. Not asked at all — see below.
#
# Do not collapse these back into one list. `generate_key_in_token()` deleted its own
# allow-list for exactly this reason ("a list of names is exactly the thing that goes
# stale"), and a list that is narrower than the product is how the wizard came to offer
# two algorithms when the console offered eight.
#
# ⚠️ This does NOT cover CA signing keys. Those are chosen per CA when the CA is created
# (console or `fastpki-ca create --key/--bits/--curve`), because a CA key is a decision per
# hierarchy, not per install.
ask_service_key() {   # ask_service_key <PREFIX> <human name> <allowed algorithms> [ask digest: yes|no]
  _p="$1"; _n="$2"; _allowed="$3"; _want_md="${4:-no}"
  _list="$(printf '%s' "$_allowed" | sed 's/ /, /g')"
  eval "ask ${_p}_KEY_ALGO \"Key type for the ${_n} key (${_list})\" ec"
  eval "_a=\$${_p}_KEY_ALGO"
  # Membership rather than a case arm per algorithm: the set is the caller's, so the
  # validation has to be too.
  case " $_allowed " in
    *" $_a "*) ;;
    *) echo "install: ${_p}_KEY_ALGO must be one of: ${_list} (got '$_a')" >&2; exit 1 ;;
  esac
  # Clear all three first: an algorithm carries at most one size-or-curve answer, and a
  # value left over from an earlier pass through this function would be written to .env
  # for a key it does not describe.
  eval "${_p}_KEY_BITS=''; ${_p}_KEY_CURVE=''; ${_p}_KEY_MD=''"
  case "$_a" in
    ec)
      eval "ask ${_p}_KEY_CURVE \"  EC curve for the ${_n} key (P-256, P-384, P-521)\" P-256"
      eval "_c=\$${_p}_KEY_CURVE"
      case "$_c" in
        P-256|P-384|P-521) ;;
        *) echo "install: ${_p}_KEY_CURVE must be P-256, P-384 or P-521 (got '$_c')" >&2; exit 1 ;;
      esac ;;
    rsa|rsa-pss)
      eval "ask ${_p}_KEY_BITS \"  RSA size for the ${_n} key (2048, 3072, 4096)\" 3072"
      eval "_b=\$${_p}_KEY_BITS"
      case "$_b" in
        2048|3072|4096) ;;
        *) echo "install: ${_p}_KEY_BITS must be 2048, 3072 or 4096 (got '$_b')" >&2; exit 1 ;;
      esac ;;
    # ed25519, ed448 and the ML-DSA parameter sets carry their size in the algorithm name.
    # There is nothing further to ask, and asking would imply a choice that does not exist.
  esac
  # ⚠️ THE DIGEST IS A QUESTION ONLY WHERE A CHOICE EXISTS. EC, Ed and ML-DSA either carry
  # their own digest or are one-shot schemes, so the prompt appears for RSA alone — the
  # same reason KEY_BITS appears for RSA and KEY_CURVE for EC. Blank means auto-match the
  # key, which is what every deployment before this setting got.
  if [ "$_want_md" = yes ]; then
    case "$_a" in
      rsa|rsa-pss)
        eval "ask ${_p}_KEY_MD \"  Signature digest for the ${_n} certificate (blank = auto; sha256, sha384, sha512, sha3-256, sha3-384, sha3-512)\" ''"
        eval "_m=\$${_p}_KEY_MD"
        case "$_m" in
          ''|sha256|sha384|sha512|sha3-256|sha3-384|sha3-512) ;;
          *) echo "install: ${_p}_KEY_MD must be blank or one of sha256, sha384, sha512, sha3-256, sha3-384, sha3-512 (got '$_m')" >&2; exit 1 ;;
        esac ;;
    esac
  fi
}

# The two sets used below, named so the call sites read as intent rather than as a list.
TLS_KEY_ALGOS='ec rsa rsa-pss'
CMP_KEY_ALGOS='ec rsa rsa-pss ed25519 ed448 ML-DSA-44 ML-DSA-65 ML-DSA-87'
# ── WHICH PROTOCOLS TO DEPLOY AT ALL ────────────────────────────────────────────
# Better still, ask whether the customer wants EST, ACME and MS at all — they may not need
# every one of them, and a protocol nobody chose needs no container built, run or
# monitored.
#
# The answer becomes COMPOSE_PROFILES in .env, and each optional service carries a
# matching `profiles:` in docker-compose.yml — so a declined protocol is not built, not
# started, not restarted and not listed by `docker compose ps`. Nothing to monitor
# because nothing exists.
#
# ⚠️ The console is NOT offered: without it there is no way to create a CA, and without a
# CA no protocol can issue anything, so "no console" is not a deployment, it is a
# container that answers nothing.
if interactive; then
  echo
  echo "Which protocols should this deployment run? Anything you decline is not built,"
  echo "not started and not monitored — you can add it later in .env (add it to COMPOSE_PROFILES"
  echo "and set its <PROTO>_INSTALLED=true) and re-running 'docker compose up -d'."
fi
yesno WANT_EST   "  EST (RFC 7030)"                       yes
yesno WANT_ACME  "  ACME (RFC 8555)"                      yes
yesno WANT_CMP   "  CMP (RFC 4210/9483)"                  yes
yesno WANT_SCEP  "  SCEP (RFC 8894)"                      yes
yesno WANT_MS    "  MS-XCEP/WSTEP (Windows auto-enrol)"   yes
yesno WANT_STORE "  Certificate store (RFC 4387)"         yes
# ⚠️ OCSP IS NOT ASKED. It is treated the same as the web console: not optional, so not a
# question. That is right and the first version of this was wrong to
# offer it: fastpki-ocsp serves the CRL endpoints too, so a PKI without it issues
# certificates and publishes no revocation information at all. That is not a smaller
# deployment, it is an incomplete one — the same reason the console is not offered.
WANT_OCSP=yes


COMPOSE_PROFILES=""
for _pair in est:$WANT_EST acme:$WANT_ACME cmp:$WANT_CMP scep:$WANT_SCEP \
             ms:$WANT_MS store:$WANT_STORE ocsp:yes; do
  _svc=${_pair%%:*}; _want=${_pair##*:}
  [ "$_want" = yes ] && COMPOSE_PROFILES="${COMPOSE_PROFILES:+$COMPOSE_PROFILES,}$_svc"
done
# The key tunnel is a service of its own on compose: HA_ENABLED runs it (see above).
[ "$HA_ENABLED" = yes ] && COMPOSE_PROFILES="$COMPOSE_PROFILES,p11tls"
echo
# ocsp is always there and p11tls is not a protocol — keep both out of the line that lists
# what this deployment SERVES.
_proto_list=$(printf '%s' "$COMPOSE_PROFILES" | sed -e 's/,\{0,1\}p11tls//' -e 's/,\{0,1\}ocsp,\{0,1\}//')
echo "Deploying: web console, OCSP+CRL${_proto_list:+, }$_proto_list"

if interactive; then
  echo "FastPKI generates one key per service inside the token at first start."
  echo "Answer per service, or press Enter for the default (ec / P-256)."
fi
ask_service_key WEB    "web console TLS"           "$TLS_KEY_ALGOS" yes
# Only for the listeners this deployment will actually run. Asking an operator to
# choose a curve for a service they just declined is the kind of question that makes a
# wizard feel like a form rather than a conversation — and it would write settings for a
# container that does not exist.
[ "$WANT_EST"  = yes ] && ask_service_key EST  "EST listener TLS"  "$TLS_KEY_ALGOS" yes
[ "$WANT_ACME" = yes ] && ask_service_key ACME "ACME listener TLS" "$TLS_KEY_ALGOS" yes
[ "$WANT_MS"   = yes ] && ask_service_key MS   "MS-XCEP/WSTEP listener TLS" "$TLS_KEY_ALGOS" yes

# The RA and responder credentials. Same question, but the answer is stored rather than
# acted on now: these keys are created once a CA exists to certify them (§4.4b), and
# without a recorded answer an unattended install has to guess or ask nobody.
#
# OCSP is unconditional because the responder is not an optional protocol — it ships in
# every deployment.
ask_service_key OCSP_RESPONDER "OCSP responder" "$TLS_KEY_ALGOS"
[ "$WANT_CMP" = yes ] && ask_service_key CMP_RA "CMP RA" "$CMP_KEY_ALGOS"
# ⚠️ SIZE ONLY, and deliberately not routed through ask_service_key: a SCEP RA key must be
# plain RSA, so an algorithm prompt here would be a question with one right answer and
# several ways to break enrolment. The SCEP service and the console both refuse anything
# else, and this is the third place that has to agree — by not asking.
if [ "$WANT_SCEP" = yes ]; then
  ask SCEP_RA_KEY_BITS "RSA size for the SCEP RA key (2048, 3072, 4096) — SCEP requires RSA" 3072
  case "$SCEP_RA_KEY_BITS" in
    2048|3072|4096) ;;
    *) echo "install: SCEP_RA_KEY_BITS must be 2048, 3072 or 4096 (got '$SCEP_RA_KEY_BITS')" >&2; exit 1 ;;
  esac
fi
# ⚠️ INTERACTIVE ONLY, like the other explanations in this wizard. A non-interactive run
# (--answers / --print-env) is scripted: nobody is reading a caveat about questions that
# were never asked, and this block plus the three above accounted for 18 of the 24 lines a
# scripted install printed before it got to anything actionable. The same caveat is in
# docs/deployment.md 4.4, which is where it belongs.
if interactive; then
  echo "  note: the CMP RA, SCEP RA and OCSP responder credentials are NOT created here."
  echo "        Those services start without them and leave the feature off until one exists."
  echo "        Once a CA is created, finish the deployment with:"
  echo "            fastpki-ca renew-service-certs --create-missing --re-issue-self-signed"
  echo "        which issues all three AND replaces this node's self-signed listener"
  echo "        certificates with CA-issued ones. Or do it from the console"
  echo "        (Inventory -> Request, key in HSM -> Serve as ...)."
  echo "        A SCEP RA key must be RSA."
fi
PKCS11_MODULE_OUT=""
case "$KEY_BACKEND" in
  softhsm)
    : ;;   # compose already defaults PKCS11_MODULE to the p11-kit client shim
  hsm)
    ask PKCS11_MODULE "Absolute path to the vendor PKCS#11 module inside the container" ""
    # Validate before writing: a module NAME rather than a path is the
    # mistake this catches — the loader would fail at first use, long after here.
    case "${PKCS11_MODULE:-}" in
      /*) ;;
      "") echo "install: KEY_BACKEND=hsm needs PKCS11_MODULE=<absolute path to the vendor .so>" >&2; exit 1 ;;
      *)  echo "install: PKCS11_MODULE must be an ABSOLUTE path (got '$PKCS11_MODULE')" >&2; exit 1 ;;
    esac
    PKCS11_MODULE_OUT="$PKCS11_MODULE"
    # The bundled token is always labelled `fastpki`; somebody else's HSM is labelled
    # whatever they labelled it, and every key URI names the token.
    ask PKCS11_TOKEN "Token label on that module" "fastpki" ;;
  *)
    echo "install: KEY_BACKEND must be 'softhsm' or 'hsm'" >&2; exit 1 ;;
esac

# Assemble the .env.
ENV_BODY=$(
  # ⚠️ ONE NAME. PKI_DNS is the deployment hostname everywhere — the config key the binaries
  # read and the variable docker-compose.yml interpolates for certgen — so do not write a
  # second name beside it here. certgen.sh falls back to "localhost", which makes a
  # deployment that sets one name and not the other issue every transport certificate for
  # the wrong name, quietly: a certificate for "localhost" still verifies against itself.
  printf 'FASTPKI_IMAGE=%s\nPG_BIND=%s\nPKI_DNS=%s\n' "$FASTPKI_IMAGE" "$PG_BIND" "$PKI_DNS"
  [ -n "$DC_LINES" ] && printf '%s\n' "$DC_LINES"
  [ "$HA_ENABLED" = yes ] && printf 'HA_ENABLED=true\nP11_TLS=on\nSERVICE_KEYS_REPLICABLE=true\n'
  # Only written for an external HSM: leaving it unset keeps compose's own default
  # (the p11-kit client shim), so the softhsm path has one source of truth, not two.
  [ -n "$PKCS11_MODULE_OUT" ] && printf 'PKCS11_MODULE=%s\n' "$PKCS11_MODULE_OUT"
  # POSTGRES_PASSWORD is read by the postgres image; PG_CONNINFO carries the same value
  # to the apps. PKCS11_TOKEN / PKCS11_PIN_FILE give the console's slot picker and PIN
  # box a real default instead of a placeholder the operator has to guess.
  printf 'POSTGRES_PASSWORD=%s\n' "$PG_PASSWORD"
  printf 'FASTPKI_PIN=%s\n' "$PKCS11_PIN"
  printf 'PKCS11_TOKEN=%s\nPKCS11_PIN_FILE=%s\n' "${PKCS11_TOKEN:-fastpki}" "$PKCS11_PIN_FILE"
  # Per service, and only the settings that APPLY -- an EC answer carries no _BITS
  # and an RSA one no _CURVE, so the file never states a value the algorithm ignores.
  # The chosen protocol set, written once. Every later `docker compose up -d`,
  # `pull`, `ps` and rolling-update.sh reads it from here, so the deployment's shape lives
  # in one place instead of in whichever service names someone typed last.
  printf 'COMPOSE_PROFILES=%s\n' "$COMPOSE_PROFILES"
  # ⚠️ THE BUILD-TIME STATE, per protocol, so anything that needs to know the shape
  # of this deployment can ask instead of guessing: the build-time state of the optional
  # protocols belongs in the DB, so anything depending on them can check before committing
  # to a job.
  #
  # This is NOT the same as <PROTO>_ENABLED, which is the runtime switch an operator
  # flips in the console. A protocol can be installed and switched off; one that was never
  # installed is a different state, and the Endpoints page could not tell them apart —
  # a declined protocol rendered exactly like one an admin had disabled.
  #
  # bootstrap.sh copies these into the `config` table, which is the source of truth (§3f);
  # they travel through .env only because that is how the wizard reaches the container.
  for _pair in EST:$WANT_EST ACME:$WANT_ACME CMP:$WANT_CMP SCEP:$WANT_SCEP \
               MS:$WANT_MS STORE:$WANT_STORE; do
    printf '%s_INSTALLED=%s\n' "${_pair%%:*}" "$([ "${_pair##*:}" = yes ] && echo true || echo false)"
  done
  # Key settings only for the services that exist — see the ask above.
  # OCSP_RESPONDER and CMP_RA ride the same loop because their variables are named for the
  # config keys they become — the prefix IS the key prefix, so nothing here has to special-
  # case them. An empty _BITS/_CURVE/_MD is omitted rather than written blank: the config
  # parser treats a key it never saw and a key set to nothing differently only by accident,
  # and an absent line is the honest way to say "the algorithm decides".
  for _p in WEB $([ "$WANT_EST" = yes ] && echo EST) $([ "$WANT_ACME" = yes ] && echo ACME) \
            $([ "$WANT_MS" = yes ] && echo MS) OCSP_RESPONDER \
            $([ "$WANT_CMP" = yes ] && echo CMP_RA); do
    eval "_a=\$${_p}_KEY_ALGO; _b=\${${_p}_KEY_BITS:-}; _c=\${${_p}_KEY_CURVE:-}; _m=\${${_p}_KEY_MD:-}"
    printf '%s_KEY_ALGO=%s\n' "$_p" "$_a"
    [ -n "$_b" ] && printf '%s_KEY_BITS=%s\n'  "$_p" "$_b"
    [ -n "$_c" ] && printf '%s_KEY_CURVE=%s\n' "$_p" "$_c"
    [ -n "$_m" ] && printf '%s_KEY_MD=%s\n'    "$_p" "$_m"
    true
  done
  # SCEP has no algorithm line to write — see the prompt.
  [ "$WANT_SCEP" = yes ] && printf 'SCEP_RA_KEY_BITS=%s\n' "$SCEP_RA_KEY_BITS"
  true                     # keep the subshell's exit status 0 under set -e
)

if [ "$PRINT_ONLY" = 1 ]; then
  printf '%s\n' "$ENV_BODY"
  exit 0
fi

# 0600 BEFORE the write, not after: between creating a world-readable file and
# chmod'ing it there is a window in which the password is readable, and it is exactly
# the sort of window that is never noticed because nothing fails.
( umask 077; printf '# fastpki deploy/.env — generated by install.sh.\n# CONTAINS SECRETS (database password, token PIN). Do not commit. Mode 0600.\n%s\n' "$ENV_BODY" > "$ENV_OUT" )
chmod 600 "$ENV_OUT" 2>/dev/null || true
echo
# ⚠️ DO NOT ECHO .env BACK. This used to print the whole file — 26 lines for a cluster
# node — immediately after naming the path it had just written, which was a fifth of the
# wizard's entire output and told the operator nothing they could not `cat`. What they
# cannot guess is that the file carries secrets, so say only that.
echo "Wrote $ENV_OUT (mode 0600) — it holds the database password and the token PIN."
# ── finish the install ────────────────────────────────────────────────────────
# The four steps are always the same four and the ORDER is not cosmetic: certgen
# runs as postgres comes up (so the app<->DB link is TLS from first boot), and
# bootstrap must land after postgres is accepting connections and before the rest
# of the stack starts. Leaving them to be pasted by hand is how a deployment ends
# up half-installed with no error anywhere.
# The fresh-install sequence, in order — printed by --no-deploy AND by a failure. A
# half-finished install is precisely when somebody needs to know what is left, and saying
# "finish by hand with the remaining steps" without naming them is how a deployment ends up
# with every service running and its database never bootstrapped: no web_users row, so the
# console opens in OPEN MODE as anonymous/admin. That reads as a broken login rather than as
# an install that stopped halfway, and the two have nothing to do with each other.
remaining_steps() {
  echo "  1. docker compose build                 # build node only; others pull the image tag"
  echo "  2. docker compose up -d postgres        # certgen runs first (transport TLS), then postgres"
  echo "     docker compose exec -T postgres pg_isready -U fastpki -d fastpki   # WAIT for it"
  echo "  3. ./schema-apply.sh                    # before ANY binary reads the schema"
  echo "  4. docker compose run --rm bootstrap   # seeds admin/admin (must-reset at first login)"
  # ⚠️ STEP 5 IS NOT OPTIONAL ON A CLUSTER, AND LEAVING IT OUT OF THIS LIST WAS THE SAME
  # DEFECT ONE LEVEL UP. The automatic path registers this row (see the run_step below) —
  # this list is what an operator follows when the deploy is skipped or has failed, and
  # without the row est, acme, cmp, scep, ms and web restart forever with
  #   fatal: DATACENTER_ID=N has no row in `datacenters`
  # while ocsp and store, which do not issue, run happily and make it look partly working.
  # Measured on the lab twice: once from the wizard before it inserted the row, and again
  # following THIS list after it did.
  if [ "$DEPLOYMENT" = cluster ]; then
    echo "  5. register this node as its own data center (its index IS its serial prefix):"
    echo "     docker compose exec -T postgres psql -U fastpki -d fastpki -v ON_ERROR_STOP=1 \\"
    echo "       -c \"INSERT INTO datacenters(dc_id, serial_prefix) VALUES('$DC_INDEX', $DC_INDEX)\\"
    echo "            ON CONFLICT (dc_id) DO UPDATE SET serial_prefix=EXCLUDED.serial_prefix;\""
    echo "  6. docker compose up -d"
  else
    echo "  5. docker compose up -d"
  fi
}

run_step() {   # <human description> <cmd...>
  echo
  echo "==> $1"
  shift
  if ! "$@"; then
    echo >&2
    echo "FAILED: $*" >&2
    echo "  .env is written and valid — fix the cause and re-run ./install.sh," >&2
    echo "  or finish by hand from $HERE — the full sequence, skip what already ran:" >&2
    remaining_steps >&2
    exit 1
  fi
}

if [ "$DO_DEPLOY" = 1 ] && ! command -v docker >/dev/null 2>&1; then
  echo "docker is not on PATH — writing .env only." >&2
  DO_DEPLOY=0
fi

if [ "$DO_DEPLOY" = 1 ]; then
  cd "$HERE"
  run_step "obtaining the image (pulled when FASTPKI_IMAGE names a registry, else built)" \
      obtain_image
  run_step "checking Docker can mount this directory" check_bind_mounts
  # certgen is a dependency of postgres in the compose file, so this one command
  # generates the transport certificate and then starts the database.
  run_step "starting postgres (certgen issues the transport certificate first)" \
      docker compose up -d postgres
  run_step "waiting for postgres to accept connections" wait_postgres
  # Harmless on a fresh database — createdb.sql is born current, so every step is
  # already recorded and this is a no-op. It runs anyway because this script is also the
  # upgrade path for a volume that was NOT reused above, and a step that only runs on the
  # branch someone remembered is the shape schema versioning exists to prevent.
  #
  # ⚠️ AND IT MUST PRECEDE BOOTSTRAP, not follow it. `bootstrap` runs `fastpki-config`,
  # which carries the schema-version startup guard — so on the path that MATTERS here (an old
  # pgdata volume exists and the operator declined to reuse it, so postgres came up on
  # the old schema) bootstrap is the binary that refuses, and the install dies one step
  # before the step that would have fixed it. Nothing is lost by going first: on a fresh
  # database this is a no-op, and the guard only ever reads a schema nobody has written to.
  run_step "applying schema steps (expand/contract)" \
      bash "$HERE/schema-apply.sh"
  run_step "bootstrapping the database and seeding admin/admin (change it at first login)" \
      docker compose run --rm bootstrap
  # ⚠️ SEED THIS NODE'S OWN data centers ROW, or the install ends in a crash loop.
  #
  # Every issuing binary refuses at startup while `datacenters` has no row for
  # DATACENTER_ID — est, acme, cmp, scep, ms and web restart forever while ocsp and store,
  # which do not issue, run happily. A previous version of this script only WARNED that
  # this would happen and printed the mesh commands at the end; the deployment still
  # finished broken, and "it told you" is not the same as working. Reported twice from a
  # lab build, the second time on the release that added the warning.
  #
  # This node's index IS its serial prefix — the wizard says so where it asks — so the row
  # is derivable here without a topology file, which needs every OTHER data center's conninfo
  # and cannot exist yet on the first node. Same statement fastpki-mesh --map emits, so a
  # later --map with the real topology simply updates it. conninfo is left NULL: the peers
  # supply theirs, and this node does not subscribe to itself.
  # ⚠️ UNCONDITIONAL. A single node is data center 1, not "no data center" — see where
  # DC_INDEX is set. Registering the row here is what lets it mint prefixed serials from its
  # FIRST certificate, so a later expansion has no pre-mesh history sitting outside its own
  # partition, and no rows that `certs_dc_range` would refuse on a local restore.
  run_step "registering this node as data center '$DC_INDEX' (its serial prefix)" \
      sh -c "docker compose exec -T postgres psql -U fastpki -d fastpki -v ON_ERROR_STOP=1 -c \
        \"INSERT INTO datacenters(dc_id, serial_prefix) VALUES('$DC_INDEX', $DC_INDEX)
           ON CONFLICT (dc_id) DO UPDATE SET serial_prefix=EXCLUDED.serial_prefix;\" >/dev/null"

  # ⚠️ PG_TLS_SANS IS DERIVED, NOT ASKED AGAIN, and leaving it to the operator was a manual
  # step with a silent failure at the end of it. `fastpki-ca pg-tls` takes the names for
  # the database certificate from CONFIG rather than from its arguments, so a node whose
  # config omits its interconnect address is issued a certificate without that SAN — and
  # every peer refuses it under sslmode=verify-full, long after the CAs exist and the hard
  # part looks done. PG_BIND is exactly that address: this installer already asked for it
  # as "this node's mesh-reachable IP (peers subscribe to Postgres here)".
  #
  # ⚠️ NO LONGER WRITTEN, AND THE PREMISE THAT PUT IT HERE WAS WRONG. This recorded
  # PG_BIND into the DB overlay, reasoning that "the `config` table is deliberately not
  # replicated, which is what makes it the right home". That holds for a MESH, where each
  # data center has its own config table. It does not hold for an HA pair, which replicates
  # the whole database physically: both hosts then read one config table and one
  # PG_TLS_SANS row, so this node's address became the STANDBY's certificate name too, and
  # the standby's own was nowhere in it.
  #
  # `fastpki-ca pg-tls` and certgen.sh now read PG_BIND from the environment directly, which
  # is per-node in compose and cannot be overwritten by a row the peer wrote. Nothing needs
  # recording. k8s and install-native still derive the value into their own per-node config,
  # which is correct there — neither shares a config table with another host.
  #
  # ⚠️ NOT CLUSTER-ONLY. This sat inside `if [ "$DEPLOYMENT" = cluster ]`, and the guard
  # below is already the whole condition: an operator who gave a routable PG_BIND wants that
  # address certified whatever the deployment type. The case it excluded is exactly the HA
  # PRIMARY — a single-host deployment whose standby lives on another machine and dials it
  # under verify-full — so `ha-join.sh` on the standby refused the anchor, or Postgres
  # refused the stream, for a certificate the installer had been told how to issue.
  # docs/high-availability.md §2 has each host of a pair give its own routable PG_BIND; this is
  # what makes the certificate carry it for a single node as well as a mesh node.
  run_step "starting the remaining services" \
      docker compose up -d
  echo
  echo "Installed."
else
  echo "Next steps (run from $HERE):"
  remaining_steps
fi
# ⚠️ THIS SCRIPT IS ALSO THE UPGRADE PATH (docs/deployment.md 8.0a, "Updating": run install.sh
# again), so the closing text asks the database what it holds instead of assuming a first
# install. Printed unconditionally, it told the operator of a working deployment to sign in
# as admin / admin (the seed is --if-absent, so that password is long gone), to create CAs
# that already issue, and to connect a mesh that already replicates.
#   _dcs  data centers this database knows. More than one means meshed: that row set
#         replicates, so the answer is right on a standby too. As install-native.sh.
#   _cas  CAs in the database, the rows `fastpki-ca list` shows. As apply.sh.
# No answer counts as zero, which prints the first-install text: what this printed before.
_q() { (cd "$HERE" && docker compose exec -T postgres psql -U fastpki -d fastpki -w -tAqc "$1") \
         2>/dev/null | tr -d '[:space:]' || true; }
_dcs=$(_q 'SELECT count(*) FROM datacenters')
_cas=$(_q 'SELECT count(DISTINCT id) FROM certs WHERE is_ca AND id IS NOT NULL')
[ "${_dcs:-0}" -gt 0 ] 2>/dev/null || _dcs=0
[ "${_cas:-0}" -gt 0 ] 2>/dev/null || _cas=0
echo
if [ "$_dcs" -le 1 ] && [ "$_cas" -eq 0 ]; then
  echo "Console: https://$PKI_DNS:8090 — log in as admin / admin and change it immediately."
  echo "  (self-signed until you issue the console a certificate, so expect a browser warning)"
else
  echo "Console: https://$PKI_DNS:8090 — log in as admin."
fi
echo
# ⚠️ IDENTITY AND POINTERS ONLY — DO NOT GROW A MANUAL BACK IN HERE. This block used to
# print ~80 lines that exist in docs/deployment.md word for word: the trust-bootstrap CA
# sequence, the topology line format, both mesh passes, and an essay on the key backend.
# Eleven actionable lines were buried in it, and the whole run came to 146 lines for a
# 3-data-center node. Reported as "the output at the end of install.sh is too lengthy —
# all the lyrics and prose should go to docs/deployment.md".
#
# ⚠️ AND NO `fastpki-ca` SEQUENCE. Operators create the root, the sub CAs and the
# transport certificates in the WEB CONSOLE; a printed CLI walkthrough is a second,
# diverging copy of §7a that nobody re-tests.
_keyline="key backend $KEY_BACKEND"
if [ -n "$PKCS11_MODULE_OUT" ]; then _keyline="$_keyline ($PKCS11_MODULE_OUT)"; fi
if [ "$DEPLOYMENT" = cluster ] && [ "$_dcs" -gt 1 ]; then
  echo "This node: data center $DC_INDEX — $_keyline."
  echo "It is already part of a mesh of $_dcs data centers and keeps replicating; there is"
  echo "  nothing to connect. docs/deployment.md 9.2 is the check."
elif [ "$DEPLOYMENT" = cluster ]; then
  echo "This node: data center $DC_INDEX — that index IS its certificate-serial prefix"
  echo "  — $_keyline, certified as ${PG_BIND:-<no routable address — peers cannot verify this node>}. EVERY node"
  echo "  installs the same way: same answers file, only DC_INDEX, PKI_DNS and PG_BIND differ."
  echo "It does not replicate yet. Once every node is installed, connect them from your own"
  echo "  machine with deploy/mesh-join.sh (docs/deployment.md 9.0 step 3). Its first run stops for"
  echo "  the CAs, created in the console (CAs -> + New CA); run it again and it finishes."
  # ⚠️ A POINTER, NOT A COMMAND — see the block above. Step 5b is the one an operator drops:
  # the RA and responder credentials are per-node and replicate from nowhere, so a node that
  # joins the mesh correctly still refuses CMP, answers OCSP internalerror and serves
  # self-signed listeners. Measured on a 3-node lab: 7 failing demo steps on the joined node.
  echo "  9.1 step 5b issues THIS node's OCSP/CMP/SCEP credentials — they replicate from"
  echo "  nowhere, so a node that skips it joins the mesh and still refuses CMP and OCSP."
elif [ "$_cas" -gt 0 ]; then
  echo "This node: datacenter 1 (single), $_keyline. $_cas CA instance(s) present."
else
  echo "This node: datacenter 1 (single), $_keyline. No CA exists yet — create the root and"
  echo "  issuing CAs in the console (CAs -> + New CA); docs/deployment.md 4.3 walks through it."
  # ⚠️ A POINTER, NOT A COMMAND — see the block above. It earns its two lines because
  # "Installed." is the last thing an operator reads, and it is not true yet: the OCSP
  # responder, CMP RA and SCEP RA credentials do not exist until §4.4a is run, and every
  # container is healthy the whole time. Naming the symptom is what makes anyone act on it.
  echo "  Then §4.4a: it issues the OCSP/CMP/SCEP credentials and replaces the listeners'"
  echo "  self-signed certs. Until it runs, OCSP answers internalerror and CMP refuses."
fi
