#!/usr/bin/env bash
# The bench's ACME cell bind-mounts a webroot into nginx, and the cell is only as good as
# that mount.
#
# ⚠️ A PATH DOCKER DOES NOT SHARE MOUNTS AS AN EMPTY DIRECTORY — IT DOES NOT FAIL. Docker
# Desktop does this for any host path outside its file-sharing list, and `mktemp -d` on a
# Mac (/var/folders/...) is such a path. nginx then starts, serves 404 for every challenge,
# and the cell skips blaming the network — while the identical code is fine on Linux, where
# the temp dir is shared. So the webroot cannot be a fixed guess; it has to be measured.
#
# ⚠️ This drives the REAL acme_pick_webroot out of demo/pki-bench.sh with `docker` stubbed,
# rather than grepping for the candidate list. A grep proves the paths are mentioned; it
# does not prove the fallthrough happens, that a rejected candidate is cleaned up, or that
# the cell refuses when nothing is mountable.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
W="$(mktemp -d)"; trap 'rm -rf "$W" "$HOME/.cache/fastpki-bench" "$ROOT/.bench-webroot"' EXIT
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# A `docker` that reports a readable mount only for the paths named in $MOUNTABLE. Every
# invocation is recorded, so the suite can assert on the ORDER candidates were tried in.
mkdir -p "$W/bin"
cat > "$W/bin/docker" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DOCKER_CALLS"
for m in $MOUNTABLE; do
  case "$*" in *"-v $m:/w:ro"*) exit 0;; esac
done
exit 1
STUB
chmod +x "$W/bin/docker"
export PATH="$W/bin:$PATH" DOCKER_CALLS="$W/calls.txt"

# Extract the chooser from the shipped bench and run THAT. Sourcing the whole script would
# run a benchmark; this takes the definition only, and fails loudly if it is renamed away.
sed -n '/^acme_pick_webroot(){/,/^}$/p' "$ROOT/demo/pki-bench.sh" > "$W/fn.sh"
chk "acme_pick_webroot was found in demo/pki-bench.sh" yes \
    "$([ -s "$W/fn.sh" ] && echo yes || echo no)"
. "$W/fn.sh"

run_pick(){   # <mountable paths...>  -> sets ACME_WEBROOT / ACME_WEBROOT_TMP / PICK_RC
    : > "$DOCKER_CALLS"
    rm -rf "$WORK" "$HOME/.cache/fastpki-bench" "$ROOT/.bench-webroot"
    mkdir -p "$WORK"
    ACME_WEBROOT=; ACME_WEBROOT_TMP=
    MOUNTABLE="$*" acme_pick_webroot; PICK_RC=$?
}
WORK="$W/work"; HOMEBASE="${HOME:-/root}/.cache/fastpki-bench/webroot"

echo "=== 1. the temp dir works (Linux, the lab): it is chosen, nothing else is tried ==="
run_pick "$WORK/webroot"
chk "the chooser succeeds" 0 "$PICK_RC"
chk "and picks the work directory" "$WORK/webroot" "$ACME_WEBROOT"
chk "nothing outside \$WORK is registered for cleanup" "" "$ACME_WEBROOT_TMP"
chk "it stopped at the first candidate" 1 "$(wc -l < "$DOCKER_CALLS" | tr -d ' ')"

echo
echo "=== 2. the temp dir is NOT shared (Docker Desktop): it falls through ==="
run_pick "$HOMEBASE"
chk "the chooser still succeeds" 0 "$PICK_RC"
chk "and lands on the shareable candidate" "$HOMEBASE" "$ACME_WEBROOT"
chk "which is registered for cleanup, since \$WORK will not remove it" "$HOMEBASE" "$ACME_WEBROOT_TMP"
chk "the unshareable candidate was tried FIRST" yes \
    "$(head -1 "$DOCKER_CALLS" | grep -qF "$WORK/webroot" && echo yes || echo no)"
# The work directory is deliberately NOT removed here — cleanup() takes $WORK whole, and
# deleting it early would be the one candidate that costs nothing to leave.

echo
echo "=== 2b. a rejected candidate OUTSIDE \$WORK is cleaned up ==="
# ⚠️ Candidates are created BEFORE they are tested, and $WORK is the only one cleanup()
# owns. Without this, every run on a machine that rejects the first two would leave an
# empty webroot tree in the user's home directory.
run_pick "$ROOT/.bench-webroot"
chk "the chooser lands on the last candidate" "$ROOT/.bench-webroot" "$ACME_WEBROOT"
chk "and the rejected home-directory candidate is gone" no \
    "$([ -d "$HOMEBASE" ] && echo yes || echo no)"

echo
echo "=== 3. nothing is mountable: the cell refuses instead of serving 404s ==="
run_pick "none"
chk "the chooser fails" 1 "$PICK_RC"
chk "and names no webroot" "" "$ACME_WEBROOT"
chk "every candidate was tried before giving up" 3 "$(wc -l < "$DOCKER_CALLS" | tr -d ' ')"
chk "and it left none of them behind" no \
    "$([ -d "$HOMEBASE" ] || [ -d "$ROOT/.bench-webroot" ] && echo yes || echo no)"

echo
echo "=== 4. the caller acts on the refusal ==="
# The chooser is only useful if a false return actually skips the cell — the `continue`
# lives in a one-iteration loop precisely because a bare `continue` here would fall
# through to certbot and report a 0/N row for the wrong reason.
guard=$(grep -A1 'if ! acme_pick_webroot; then' "$ROOT/demo/pki-bench.sh" | tail -1)
chk "a failed pick skips the ACME cell" yes \
    "$(echo "$guard" | grep -q 'acme.*(skip)' && echo yes || echo no)"
chk "and the skip reaches a 'continue', not a fallthrough" yes \
    "$(sed -n '/if ! acme_pick_webroot; then/,/^    fi$/p' "$ROOT/demo/pki-bench.sh" \
       | grep -q '^      continue$' && echo yes || echo no)"

echo
echo "=== BENCH WEBROOT: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
