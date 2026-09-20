#!/bin/sh
# Collect the licence texts of every Alpine package the Docker image carries.
#
#   deploy/licences/collect-alpine.sh <alpine-packages.txt> <out-dir>
#
# Run it inside alpine:3.24, as root, on a machine with a fast link — it downloads each
# package's upstream source, and GCC's alone is about 90 MB:
#
#   docker run --rm -v "$PWD:/w" alpine:3.24 \
#       sh /w/deploy/licences/collect-alpine.sh /w/alpine-packages.txt /w/deploy/licences/alpine
#
# <alpine-packages.txt> is the file the image build writes to /app/licences/, taken from a
# freshly built image: docker run --rm --entrypoint cat fastpki:local /app/licences/alpine-packages.txt
#
# WHY THIS EXISTS. Publishing the image redistributes these packages, and most of their
# licences (MIT, BSD, Zlib, OLDAP, PostgreSQL) require the licence text and copyright notice
# to travel with a binary redistribution. Alpine's runtime packages carry no licence files,
# and its -doc packages are almost all man pages: installing every -doc package for this image
# yielded licence files for 3 of 39 packages. So the texts come from the source each package
# was built from, which is what the APKBUILD names.
#
# For every source package (the {origin} in the list) it:
#   1. fetches <repo>/<origin>/APKBUILD from aports, branch 3.24-stable (main, then community)
#   2. reads pkgver and source= from it by sourcing it — an APKBUILD is shell, and sourcing
#      only assigns variables; none of its functions runs
#   3. downloads each remote source, unpacks it, and copies the licence files found at its top
#      level or one directory below: COPYING*, LICENSE*, LICENCE*, COPYRIGHT*, NOTICE*
#   4. copies the same names from the aports directory itself, which is where a package
#      authored by Alpine keeps its licence
#
# Output: <out-dir>/<origin>/<file> for each text, and <out-dir>/SOURCES.txt recording, per
# package, the version, every URL used and every file taken. An origin that yields nothing is
# listed in SOURCES.txt as NONE, and the script exits 1, so the gap is fixed by hand before
# the result is committed — the image build refuses to finish with an origin uncovered.
#
# Filling one by hand means writing <out-dir>/<origin>/NOTE: which licence Alpine declares,
# where the package's source is, and why it has no licence file, plus the standard text of
# that licence where it is one (GPL, MPL). Never a copyright line nobody published. A later
# run keeps a NOTE and records the package as filled by hand.
set -eu
LIST="${1:?usage: collect-alpine.sh <alpine-packages.txt> <out-dir>}"
OUT="${2:?usage: collect-alpine.sh <alpine-packages.txt> <out-dir>}"
BRANCH="${APORTS_BRANCH:-3.24-stable}"
APORTS="https://gitlab.alpinelinux.org/alpine/aports/-/raw/$BRANCH"
TREE="https://gitlab.alpinelinux.org/api/v4/projects/alpine%2Faports/repository/tree"
DISTFILES="${DISTFILES:-https://distfiles.alpinelinux.org/distfiles/v3.24}"

apk add --no-cache -q curl tar xz zstd bzip2 unzip jq >/dev/null

mkdir -p "$OUT"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
SOURCES="$OUT/SOURCES.txt"
{
    echo "# Where each licence text under this directory came from."
    echo "# Written by deploy/licences/collect-alpine.sh from aports $BRANCH. Do not edit by hand"
    echo "# except to fill a NONE, and say so on that line."
    echo
} > "$SOURCES"

is_licence() {
    case "$(basename "$1" | tr 'a-z' 'A-Z')" in
        COPYING*|LICENSE*|LICENCE*|COPYRIGHT*|NOTICE*) return 0 ;;
    esac
    return 1
}

missing=""
for origin in $(sed -E 's/.*\{([^}]*)\}.*/\1/' "$LIST" | sort -u); do
    d="$WORK/$origin"; mkdir -p "$d/src" "$d/aport"
    repo=""
    for r in main community; do
        if curl -fsSL "$APORTS/$r/$origin/APKBUILD" -o "$d/APKBUILD" 2>/dev/null; then
            repo=$r; break
        fi
    done
    if [ -z "$repo" ]; then
        echo "$origin  NONE  (no APKBUILD in main or community on $BRANCH)" >> "$SOURCES"
        missing="$missing $origin"; continue
    fi

    # Variables only. A subshell, so nothing one APKBUILD sets leaks into the next.
    vars=$( cd "$d" && sh -c '. ./APKBUILD >/dev/null 2>&1; printf "%s\n" "$pkgver"; printf "%s\n" "$source"' ) || vars=""
    pkgver=$(printf '%s\n' "$vars" | sed -n 1p)
    srcs=$(printf '%s\n' "$vars" | sed 1d)

    taken=""; urls=""
    for s in $srcs; do
        case "$s" in
            *::*) name=${s%%::*}; url=${s#*::} ;;
            *)    name=$(basename "$s"); url=$s ;;
        esac
        case "$url" in
            http://*|https://*|ftp://*) ;;
            *) continue ;;   # a local file of the aport; step 4 covers those
        esac
        # Upstream first; then Alpine's own copy of the exact file it built from. Snapshot
        # URLs move — ncurses' "current" archive 404s once a newer snapshot replaces it — while
        # the distfiles mirror keeps every source file a release was built from, by name.
        if curl -fsSL --retry 3 "$url" -o "$d/$name" 2>/dev/null; then
            urls="$urls $url"
        elif curl -fsSL --retry 3 "$DISTFILES/$name" -o "$d/$name" 2>/dev/null; then
            urls="$urls $DISTFILES/$name"
        else
            echo "  $origin: could not download $url, nor $DISTFILES/$name" >&2; continue
        fi
        x="$d/src/$name.d"; mkdir -p "$x"
        case "$name" in
            *.tar.*|*.tgz|*.tbz2|*.txz) tar -xf "$d/$name" -C "$x" 2>/dev/null || true ;;
            *.zip)                      unzip -q "$d/$name" -d "$x" 2>/dev/null || true ;;
            *)                          continue ;;
        esac
        # Top level of the unpacked tree, and one directory below it: most tarballs unpack
        # into <name>-<version>/, so the licence is one level down from $x.
        for f in "$x"/* "$x"/*/*; do
            [ -f "$f" ] && is_licence "$f" || continue
            mkdir -p "$OUT/$origin"
            cp "$f" "$OUT/$origin/$(basename "$f")"
            taken="$taken $(basename "$f")"
        done
    done

    # The aport's own files: where a package Alpine authors keeps its licence, and where a
    # few upstreams that ship none have one added.
    files=$(curl -fsSL "$TREE?path=$repo/$origin&ref=$BRANCH&per_page=100" 2>/dev/null \
                | jq -r '.[] | select(.type=="blob") | .name' 2>/dev/null || true)
    for n in $files; do
        is_licence "$n" || continue
        if curl -fsSL "$APORTS/$repo/$origin/$n" -o "$d/aport/$n" 2>/dev/null; then
            mkdir -p "$OUT/$origin"
            cp "$d/aport/$n" "$OUT/$origin/aport-$n"
            taken="$taken aport-$n"; urls="$urls $APORTS/$repo/$origin/$n"
        fi
    done

    if [ -n "$taken" ]; then
        echo "$origin  $pkgver  files:$taken  from:$urls" >> "$SOURCES"
    elif [ -f "$OUT/$origin/NOTE" ]; then
        # Filled by hand on an earlier run: the package has no licence file anywhere, and
        # NOTE says what it has instead. Kept, and not reported as missing.
        echo "$origin  $pkgver  by hand, see $origin/NOTE" >> "$SOURCES"
    else
        echo "$origin  $pkgver  NONE  searched:${urls:- (no remote source)}" >> "$SOURCES"
        missing="$missing $origin"
    fi
    rm -rf "$d"
done

if [ -n "$missing" ]; then
    echo "no licence text found for:$missing — fill these by hand before committing" >&2
    exit 1
fi
echo "every package has a licence text; see $SOURCES"
