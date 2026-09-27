#!/usr/bin/env bash
# The environment banner must be TRUE.
#
# tests/env_report.sh carries two facts the harness ACTS on: which tier this is (a skip is
# fatal in the production image, and the full harness refuses to run outside it) and whether
# openssl is loading a pkcs11 provider from its default config. Both are load-bearing, so
# both are asserted — docs_accurate.sh and config_keys_live.sh exist because a claim nobody
# checks rots silently and is then acted on.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT" || exit 1
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

. "$ROOT/tests/env_report.sh"
B="$(env_banner 2>&1)"

echo "=== 1. the banner says something at all ==="
# The vacuity guard: every assertion below greps $B, so an env_report.sh that printed
# nothing would satisfy all of them.
chk "the banner has content"          yes "$([ "$(printf '%s' "$B" | wc -l | tr -d ' ')" -ge 2 ] && echo yes || echo no)"
chk "it names an ENVIRONMENT"         yes "$(printf '%s' "$B" | grep -q 'ENVIRONMENT:' && echo yes || echo no)"

echo "=== 2. the tier it claims is the tier the IMAGE declares ==="
# env_id() must read the marker file and nothing else. A run that could name its own tier
# could declare itself the gate without being it — or silence the skip rule by pretending
# not to be.
WANT="$(cat /etc/fastpki-test-env 2>/dev/null || echo host)"
chk "env_id agrees with /etc/fastpki-test-env" "$WANT" "$(env_id)"
chk "  and the banner shows that tier"        yes "$(printf '%s' "$B" | grep -q "ENVIRONMENT: $WANT" && echo yes || echo no)"

echo "=== 3. the pkcs11 probe agrees with what openssl actually loads ==="
O="${OSSL:-openssl}"
if command -v "$O" >/dev/null 2>&1; then
    REAL=$("$O" list -providers 2>/dev/null | grep -qE '^[[:space:]]+pkcs11$' && echo yes || echo no)
    chk "env_pkcs11_in_default_conf matches openssl list -providers" "$REAL" \
        "$(env_pkcs11_in_default_conf && echo yes || echo no)"
    chk "  and the banner warns iff it is loaded" "$REAL" \
        "$(printf '%s' "$B" | grep -q 'loads a pkcs11 provider' && echo yes || echo no)"
else
    echo "  [SKIP] no openssl on PATH to compare against"
fi

echo "=== 4. the tier marker exists where it must ==="
# In the production image this file is the whole basis of the skip rule; if the Dockerfile
# ever stopped writing it, env_id would silently answer "host", the harness would refuse to
# run, and the refusal would look like a bug in the runner rather than in the image.
if [ -f /etc/fastpki-test-env ]; then
    chk "the marker names a known tier" yes \
        "$(grep -qxE 'test-image|build-image' /etc/fastpki-test-env && echo yes || echo no)"
else
    echo "  [note] no marker here, so this is somebody's own machine — as expected off-image"
fi

echo
echo "=== ENV HONEST: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
