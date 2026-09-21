#!/usr/bin/env bash
# A failing hygiene gate must stop the image being built, not merely complain.
#
# The gate is only worth having if `docker build` does NOT run after it fails. That is the
# whole claim, and it is the one that would rot silently: a wrapper that prints a failure
# and builds anyway looks identical in every log anyone reads.
#
# ⚠️ ASSERT ON WHETHER DOCKER WAS INVOKED, not on the exit code. A wrapper could exit
# non-zero for any reason -- including because docker itself failed -- so the exit code
# cannot distinguish "refused to build" from "tried to build and it broke". A stub docker
# that records being called answers exactly the question.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
mkdir -p "$W/bin"
cat > "$W/bin/docker" <<'STUB'
#!/bin/sh
echo "docker was invoked: $*" >> "$DOCKER_STUB_LOG"
exit 0
STUB
chmod +x "$W/bin/docker"

printf '#!/bin/sh\necho "pretend violation" >&2\nexit 1\n' > "$W/fails.sh"
printf '#!/bin/sh\necho "pretend clean"\nexit 0\n'          > "$W/passes.sh"
chmod +x "$W/fails.sh" "$W/passes.sh"

run(){ : > "$W/dockerlog"
       DOCKER_STUB_LOG="$W/dockerlog" PATH="$W/bin:$PATH" HYGIENE="$1" \
         sh "$ROOT/deploy/build-image.sh" >"$W/out" 2>&1 </dev/null; echo $?; }

echo "=== a failing gate refuses to build ==="
RC=$(run "$W/fails.sh")
chk "the wrapper exits non-zero"      no  "$([ "$RC" = 0 ] && echo yes || echo no)"
chk "  and docker was NEVER invoked"  no  "$(grep -q 'docker was invoked' "$W/dockerlog" && echo yes || echo no)"
chk "  and it says why, in the output" yes "$(grep -qi 'not building' "$W/out" && echo yes || echo no)"

echo "=== a passing gate builds ==="
RC=$(run "$W/passes.sh")
chk "docker WAS invoked" yes "$(grep -q 'docker was invoked' "$W/dockerlog" && echo yes || echo no)"
chk "  with a tag"       yes "$(grep -q '\-t' "$W/dockerlog" && echo yes || echo no)"
# PRECONDITION for the pair above: if the stub were never on PATH, both halves would agree
# for the wrong reason -- "never invoked" would be true because docker does not exist here.
chk "PRECONDITION: the stub docker is what answered" yes \
    "$(grep -q 'docker was invoked' "$W/dockerlog" && echo yes || echo no)"

echo
echo "=== BUILD IMAGE GATED: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
