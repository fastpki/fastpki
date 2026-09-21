#!/bin/sh
# docs/publish.sh — the guides as per-chapter HTML and PDF, for fastpki.com.
#
#   docs/publish.sh                          # HTML + PDF into docs/.publish/
#   docs/publish.sh --out DIR                # somewhere else
#   docs/publish.sh --version v0.2.0         # stamp the release on every page
#   docs/publish.sh --html-only              # skip the PDFs (no LaTeX image needed)
#
# ⚠️ IT RUNS PANDOC IN A CONTAINER, so nothing has to be installed to publish. That is the
# same reasoning as every other tool this project reaches for: a ready-made image beats a
# machine-specific install, and the person running it does not end up with a LaTeX
# distribution they did not ask for. Docker is the only requirement, and this project already
# needs it everywhere.
#
# HTML comes from pandoc/core, which is small. PDF needs a LaTeX engine, which lives in
# pandoc/latex and is a much larger pull — hence --html-only for anyone who only wants the
# web pages, and why the two images are separate variables.
#
# ── WHAT IT PRODUCES ──────────────────────────────────────────────────────────────────
#
#   <out>/<guide>/index.html        the guide's contents page
#   <out>/<guide>/N.M-<title>.html  one page per chapter, with prev/next/up links
#   <out>/<guide>.pdf               the whole guide, for reading away from a screen
#   <out>/images/                   the screenshots the guides reference
#
# The chapter split is `--split-level=2`, which is the `## ` headings — every guide is
# written with one `# ` title and its chapters at `## `, so this gives one page per chapter
# rather than one enormous page or a page per sub-heading.
set -eu

case "$0" in */*) HERE="$(cd "${0%/*}" && pwd)" ;; *) HERE="$(pwd)" ;; esac
ROOT="$(cd "$HERE/.." && pwd)"

OUT="$HERE/.publish"
VERSION=""
HTML_ONLY=0
PANDOC_IMAGE="${FASTPKI_PANDOC_IMAGE:-pandoc/core:latest}"
PANDOC_PDF_IMAGE="${FASTPKI_PANDOC_PDF_IMAGE:-pandoc/latex:latest}"

# ⚠️ architecture.md IS DELIBERATELY NOT PUBLISHED. It is the design record — written for
# whoever is changing the code, with every claim tagged by how it is known — and it is not
# what somebody deciding whether to deploy FastPKI, or how to run it, is looking for. It
# stays in the repository. publish.lua turns links to it into links to the file on GitHub,
# and gets this same list so the two cannot disagree.
UNPUBLISHED="architecture.md"

while [ $# -gt 0 ]; do
    case "$1" in
        --out)       OUT="${2:?--out needs a directory}"; shift 2 ;;
        --version)   VERSION="${2:?--version needs a value}"; shift 2 ;;
        --html-only) HTML_ONLY=1; shift ;;
        -h|--help)   sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

command -v docker >/dev/null 2>&1 || { echo "publish: docker is not on PATH" >&2; exit 1; }

case "$OUT" in /*) ;; *) OUT="$(pwd)/$OUT" ;; esac
rm -rf "$OUT"; mkdir -p "$OUT"

# The guides to publish: every docs/*.md except the design record and the images README,
# which documents the screenshot convention for contributors and is not a guide.
GUIDES=""
for f in "$HERE"/*.md; do
    b="${f##*/}"
    case " $UNPUBLISHED " in *" $b "*) continue ;; esac
    GUIDES="$GUIDES $b"
done

# ⚠️ EVERY GUIDE SAYS WHICH RELEASE IT DESCRIBES, or a reader cannot tell whether a page
# matches the FastPKI they are running. Passed as metadata rather than edited into the
# source, so the repository's own copy stays version-free.
META=""
[ -z "$VERSION" ] || META="--metadata=subtitle:$VERSION"

# ⚠️ THE OUTPUT IS ITS OWN MOUNT, NOT A PATH INSIDE THE SOURCE. Writing it as a path relative
# to the guides only works while --out happens to be under docs/, and fails silently the
# moment it is not: pandoc writes somewhere inside the container that nothing then looks at,
# every guide reports zero pages, and the run still exits 0. Two mounts, and the container
# never has to know where the output lives on the host.
ERRLOG="$(mktemp)"
trap 'rm -f "$ERRLOG"' EXIT
# ⚠️ AS THE CALLER, NOT AS ROOT. The pandoc images run as root, so on Linux every generated
# file lands owned by root in a directory the invoking user owns — and the next run cannot
# even delete it ("rm: cannot remove ...: Permission denied", once per page). The person
# publishing then needs sudo to clean up output they asked for.
pandoc_run() {   # pandoc_run <image> <args...>
    _img="$1"; shift
    docker run --rm --user "$(id -u):$(id -g)" \
        -v "$HERE:/data:ro" -v "$OUT:/out" -w /data \
        -e "FASTPKI_DOCS_UNPUBLISHED=$UNPUBLISHED" \
        -e "FASTPKI_DOCS_PDF=${PDF_MODE:-0}" \
        "$_img" "$@" 2>"$ERRLOG"
}

echo "==> HTML, one page per chapter ($PANDOC_IMAGE)" >&2
for g in $GUIDES; do
    name="${g%.md}"
    pandoc_run "$PANDOC_IMAGE" \
        -t chunkedhtml --split-level=2 -s --toc \
        --lua-filter=publish.lua $META \
        -o "/out/$name" "$g" \
      || { echo "publish: pandoc failed on $g:" >&2; sed 's/^/    /' "$ERRLOG" >&2; exit 1; }
    n=$(find "$OUT/$name" -name '*.html' 2>/dev/null | wc -l | tr -d ' ')
    [ "$n" -gt 0 ] || { echo "publish: $g produced no pages" >&2; exit 1; }
    printf '    %-28s %s pages\n' "$name" "$n" >&2
done

# The screenshots travel with the pages that reference them. docs/images/README.md is the
# convention for contributors and has no place on the site.
if [ -d "$HERE/images" ]; then
    mkdir -p "$OUT/images"
    find "$HERE/images" -type f ! -name 'README.md' -exec cp {} "$OUT/images/" \; 2>/dev/null || true
    echo "    images: $(find "$OUT/images" -type f | wc -l | tr -d ' ') file(s)" >&2
fi

# ⚠️ REFUSE TO PUBLISH A BROKEN LINK, because nobody will notice one. The guides link to each
# other and to files elsewhere in the repository as `something.md`, which names nothing on a
# site made of directories of chapter pages. publish.lua rewrites them; this checks it did.
# A surviving relative .md href is a 404 on every page that carries it, and the only way to
# find out otherwise is a reader hitting it.
BROKEN=$(grep -rhoE 'href="[^"]*\.md(#[^"]*)?"' "$OUT" 2>/dev/null \
         | grep -v '^href="https\?://' | sort -u || true)
if [ -n "$BROKEN" ]; then
    echo "publish: these links would 404 on the site — publish.lua did not rewrite them:" >&2
    printf '  %s\n' $BROKEN >&2
    exit 1
fi
echo "    links: every .md reference rewritten" >&2

if [ "$HTML_ONLY" = 1 ]; then
    echo "==> --html-only: no PDFs" >&2
else
    # ⚠️ THE STOCK pandoc/latex IMAGE HAS LATIN MODERN AND NOTHING ELSE, and the guides are
    # written with arrows, box-drawing diagrams and ⚠ — none of which it can set. xelatex
    # stops on the first character it has no glyph for, so one arrow costs the whole PDF.
    #
    # The answer is a font, not rewriting the guides. Substituting "->" for "→" and "+" for
    # the corners of every diagram was the first attempt, and it quietly degrades the PDF to
    # work around a packaging gap — the diagrams stop looking like diagrams. One apk layer on
    # top of the image fixes it for good, is a few megabytes, and is cached after the first
    # build. DejaVu covers every symbol in the guides; the one thing it does not carry is the
    # camera emoji on a screenshot placeholder, which publish.lua still turns into a word.
    PDF_IMAGE_LOCAL=fastpki-pandoc-pdf:local
    if ! docker image inspect "$PDF_IMAGE_LOCAL" >/dev/null 2>&1; then
        echo "==> building $PDF_IMAGE_LOCAL (once): $PANDOC_PDF_IMAGE + DejaVu" >&2
        printf 'FROM %s\nUSER root\nRUN apk add --no-cache font-dejavu\n' "$PANDOC_PDF_IMAGE" \
          | docker build -q -t "$PDF_IMAGE_LOCAL" - >/dev/null \
          || { echo "publish: could not add fonts to $PANDOC_PDF_IMAGE" >&2; exit 1; }
    fi

    echo "==> PDF, one per guide ($PDF_IMAGE_LOCAL)" >&2
    # xelatex rather than the default pdflatex: the guides are full of typography — em
    # dashes, section marks, quotes, an ellipsis — and pdflatex refuses every character
    # outside its own encoding. xelatex takes Unicode directly.
    PDF_MODE=1
    for g in $GUIDES; do
        name="${g%.md}"
        pandoc_run "$PDF_IMAGE_LOCAL" \
            -s --toc --lua-filter=publish.lua $META \
            --pdf-engine=xelatex \
            -V mainfont="DejaVu Sans" -V monofont="DejaVu Sans Mono" \
            -V geometry:margin=2.5cm \
            -o "/out/$name.pdf" "$g" \
          || { echo "publish: PDF failed on $g:" >&2; sed 's/^/    /' "$ERRLOG" >&2; exit 1; }
        printf '    %-28s %s bytes\n' "$name.pdf" "$(wc -c < "$OUT/$name.pdf" | tr -d ' ')" >&2
    done
fi

# ⚠️ WITHOUT A LANDING PAGE THE SET IS UNREACHABLE. Each guide has a contents page, but
# nothing lists the guides, so /docs answers 404 and a reader has to already know that
# `deployment` is a directory to get anywhere. It is generated rather than written by hand
# because the list of guides is decided here, and a hand-kept copy drifts the first time one
# is added.
#
# The title comes out of each guide's own `# ` heading, so the page says what the project
# calls them and nothing has to be restated.
{
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
    echo '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
    printf '<title>Documentation%s — FastPKI</title>\n' "${VERSION:+ $VERSION}"
    echo '<link rel="icon" type="image/svg+xml" href="/favicon.svg">'
    echo '<link rel="stylesheet" href="/assets/css/styles.css">'
    echo '<link rel="stylesheet" href="/assets/css/site.css">'
    echo '<style>'
    echo '  .doc-wrap{max-width:820px;margin:0 auto;padding:64px 20px 96px}'
    echo '  .doc-list{display:grid;gap:14px;margin-top:28px}'
    echo '  .doc-row{display:flex;justify-content:space-between;align-items:baseline;gap:16px;'
    echo '           padding:14px 16px;border:1px solid rgba(128,128,128,.25);border-radius:10px}'
    echo '  .doc-row a{text-decoration:none}.doc-pdf{font-size:.85em;opacity:.75;white-space:nowrap}'
    echo '</style></head><body><main class="doc-wrap">'
    printf '<h1>Documentation</h1>\n'
    if [ -n "$VERSION" ]; then
        printf '<p>These pages describe FastPKI <strong>%s</strong>. Each guide is split into a page\n' "$VERSION"
        printf 'per chapter, and is also available as a PDF.</p>\n'
    else
        printf '<p>Each guide is split into a page per chapter, and is also available as a PDF.</p>\n'
    fi
    echo '<div class="doc-list">'
    for g in $GUIDES; do
        name="${g%.md}"
        title=$(head -1 "$HERE/$g" | sed 's/^# *//')
        printf '  <div class="doc-row"><a href="%s/index.html">%s</a>' "$name" "$title"
        [ "$HTML_ONLY" = 1 ] || printf '<a class="doc-pdf" href="%s.pdf">PDF</a>' "$name"
        printf '</div>\n'
    done
    echo '</div></main></body></html>'
} > "$OUT/index.html"
echo "    index: $(echo $GUIDES | wc -w | tr -d ' ') guides listed" >&2

echo >&2
echo "Published $(echo $GUIDES | wc -w | tr -d ' ') guides to $OUT" >&2
echo "  Copy the contents into fastpki.com's public/ and link them from the site's nav." >&2
[ -n "$VERSION" ] || echo "  No --version given, so no page says which release it describes." >&2
