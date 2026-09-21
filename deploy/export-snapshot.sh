#!/bin/sh
# export-snapshot.sh — publish the source tree to the public repository, without history.
#
# The public release is a SEPARATE repository holding a snapshot: the tree as it stands,
# with no commit history and no issues carried across. This script is the mechanism, so
# that an export is a reproducible command rather than a sequence somebody retypes and
# gets subtly wrong.
#
#   deploy/export-snapshot.sh --to owner/repo                  # push the snapshot
#   deploy/export-snapshot.sh --to owner/repo --tag v1.2.3      # and tag it there
#   deploy/export-snapshot.sh --to owner/repo --dry-run         # show, push nothing
#
# ⚠️ WHY AN ORPHAN COMMIT AND NOT A CLONE. `git clone` or a plain push carries every
# commit message, author line and merge with it. The release candidate is already built
# this way — one commit, no parents, the tree verbatim — and the public repository's first
# commit is the same operation aimed somewhere else. Nothing here rewrites the source
# repository: the export is a new object graph that the private one never references.
#
# ⚠️ THE HYGIENE SUITE IS THE GATE, AND IT IS THE ONLY ONE. Under the snapshot model the
# tree is the ONLY thing that becomes public, so what that suite checks — lab hostnames,
# developer names, ticket numbers, private work timelines — is exactly the boundary. An
# export that skipped it would be the one way those reach a public reader. It runs here
# directly rather than through the container harness because it inspects tracked files
# with `git grep` and starts no binary and no database; the container would prove nothing
# extra about a pure tree inspection.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)

TO=""; BRANCH="main"; TAG=""; FORCE=0; DRY=0; MSGFILE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --to)      TO="${2:?--to needs owner/repo}"; shift 2;;
        --branch)  BRANCH="${2:?--branch needs a name}"; shift 2;;
        --tag)     TAG="${2:?--tag needs a name}"; shift 2;;
        --message) MSGFILE="${2:?--message needs a file}"; shift 2;;
        --force)   FORCE=1; shift;;
        --dry-run) DRY=1; shift;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0;;
        *) echo "export-snapshot.sh: unknown argument: $1" >&2; exit 2;;
    esac
done
[ -n "$TO" ] || { echo "export-snapshot.sh: --to owner/repo is required" >&2; exit 2; }
case "$TO" in
    */*) ;;
    *) echo "export-snapshot.sh: --to must be owner/repo, got '$TO'" >&2; exit 2;;
esac

cd "$ROOT"

# Paths that exist to publish the project and have no business inside the published tree.
# A list rather than a single name because it will grow; each entry earns its place by
# being meaningless to someone who only ever sees the public repository.
EXCLUDE="deploy/export-snapshot.sh"

# ⚠️ A DIRTY TREE MAKES THE GATE LIE. The export takes HEAD's committed tree, while the
# hygiene suite greps the working tree. Let those differ and the suite can pass over a
# file whose committed content is the one that ships. Refuse instead of choosing.
if [ -n "$(git status --porcelain)" ]; then
    echo "export-snapshot.sh: working tree is not clean — commit or stash first, or the" >&2
    echo "  hygiene gate below would inspect different content than the export ships." >&2
    exit 1
fi

SRC=$(git rev-parse HEAD)
echo "== exporting $(git rev-parse --short HEAD) ($(git symbolic-ref --quiet --short HEAD || echo detached)) -> $TO [$BRANCH]"

echo "== hygiene gate =="
GATE=$(mktemp)
if bash tests/public_repo_hygiene.sh >"$GATE" 2>&1; then :; fi
# The verdict is parsed from the output, not taken from the exit status alone: a suite
# here reports its own counters, and a non-zero FAIL with a zero exit has happened.
if grep -qE 'FAIL=[1-9]|RESULT: FAIL' "$GATE"; then
    echo "export-snapshot.sh: the tree is NOT publishable — refusing to export." >&2
    grep -E 'FAIL=[1-9]|RESULT: FAIL|\[FAIL\]' "$GATE" >&2 || true
    echo "  full output: $GATE" >&2
    exit 1
fi
grep -E 'PASS=' "$GATE" | tail -1
rm -f "$GATE"

# Build the tree to publish in a scratch index, so the real index is never touched.
IDX=$(mktemp)
export GIT_INDEX_FILE="$IDX"
git read-tree "$SRC^{tree}"
# shellcheck disable=SC2086
git rm --cached -q --ignore-unmatch -- $EXCLUDE >/dev/null
TREE=$(git write-tree)
unset GIT_INDEX_FILE
rm -f "$IDX"

if [ -n "$MSGFILE" ]; then
    [ -f "$MSGFILE" ] || { echo "export-snapshot.sh: no such message file: $MSGFILE" >&2; exit 2; }
else
    MSGFILE=$(mktemp)
    {
        echo "FastPKI${TAG:+ $TAG}"
        echo
        echo "Source snapshot. This repository carries the tree only — the development"
        echo "history and the issue tracker are not part of it."
    } > "$MSGFILE"
fi

COMMIT=$(git commit-tree "$TREE" -F "$MSGFILE")
echo "== snapshot commit $(git rev-parse --short "$COMMIT"), $(git ls-tree -r --name-only "$COMMIT" | wc -l | tr -d ' ') files"
echo "   excluded: $EXCLUDE"

URL="https://github.com/$TO.git"
PUSH="$COMMIT:refs/heads/$BRANCH"

# A history-free re-export always diverges from what is already there, so every push after
# the first is a non-fast-forward. That is normal for this model and still worth making
# deliberate: replacing a published tree is not something to do by accident.
if [ -n "$(GIT_TERMINAL_PROMPT=0 git ls-remote --heads "$URL" "$BRANCH" 2>/dev/null)" ] && [ "$FORCE" -eq 0 ]; then
    echo "export-snapshot.sh: $TO already has '$BRANCH'. A snapshot export cannot" >&2
    echo "  fast-forward onto it — re-run with --force to replace the published tree." >&2
    exit 1
fi

if [ "$DRY" -eq 1 ]; then
    echo "== DRY RUN — nothing pushed. Would run:"
    echo "   git push${FORCE:+ }$( [ "$FORCE" -eq 1 ] && echo '--force') $URL $PUSH"
    if [ -n "$TAG" ]; then echo "   git push $URL $COMMIT:refs/tags/$TAG"; fi
    exit 0
fi

# shellcheck disable=SC2086
git push $( [ "$FORCE" -eq 1 ] && echo --force ) "$URL" "$PUSH"
if [ -n "$TAG" ]; then git push "$URL" "$COMMIT:refs/tags/$TAG"; fi

echo "== published https://github.com/$TO tree $(git rev-parse --short "$TREE")"
