#!/usr/bin/env bash
# The p11-kit mechanism patch must be a FILE a native install can apply.
#
# Background. p11-kit's RPC layer transports a CK_MECHANISM only if
# p11_rpc_mechanism_is_supported() says yes, which is
#
#     mechanism_has_no_parameters (m) || mechanism_has_sane_parameters (m)
#
# A mechanism answering neither is DROPPED — it never reaches C_GetMechanismList
# through p11-kit-client.so. Four are in that state at 0.26.4, and they are exactly the
# ones a post-quantum or Edwards CA needs: CKM_ML_DSA{,_KEY_PAIR_GEN} and
# CKM_EDDSA / CKM_EC_EDWARDS_KEY_PAIR_GEN. Through an unpatched sidecar those algorithms
# do not exist, and the failure reads CKR_TOKEN_NOT_PRESENT — a message about the slot,
# for a problem about the algorithm.
#
# THE BUG THIS GUARDS. The fix used to be a `sed -i` inside a Dockerfile RUN line, so it
# reached exactly one audience: people who build our image. A source install (DEPLOYMENT
# §6) loaded its distro's p11-kit and silently lost both algorithms. The release gap had
# to be closed; a patch that only exists inside a build recipe cannot be applied by
# anyone who is not running that recipe. So the patch is a file, the Dockerfile applies
# THE FILE, and §6 tells a native installer to apply the same one.
#
# What is asserted here is what can be checked without a network: that the file exists,
# that it covers all four mechanisms in the RIGHT WAY, that the Dockerfile applies it and
# no longer carries the inline sed, and that the docs point at it. The real proof — it
# applies to 0.26.4 and the result compiles and passes p11-kit's own test suite — needs a
# clone and a toolchain, so it runs only when git and network are present, and SKIPs
# cleanly otherwise (§3d).
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"
pass=0; fail=0; skip=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
note(){ echo "  [SKIP] $1"; skip=$((skip+1)); }

PATCH=deploy/p11-kit-mechanisms.patch

echo "=== 1. the patch exists as a file ==="
chk "deploy/p11-kit-mechanisms.patch is in the tree" yes "$([ -f "$PATCH" ] && echo yes || echo no)"
# Without the file every remaining read of it is an error rather than an assertion, so
# sections 1-2 and 5 report the absence once instead of 20 times. Sections 3 and 4 read
# the Dockerfile and the docs, so they still run and still say what is missing.
HAVE_PATCH=no; [ -f "$PATCH" ] && HAVE_PATCH=yes

if [ "$HAVE_PATCH" = yes ]; then
# A patch with no hunks applies successfully and changes nothing — the exact shape of
# failure that let a busybox-sed no-op ship green once already.
chk "it has hunks" yes "$([ "$(grep -c '^@@' "$PATCH")" -ge 3 ] && echo yes || echo no)"
chk "it patches rpc-message.c" 1 "$(grep -c '^+++ b/p11-kit/rpc-message.c$' "$PATCH")"
chk "it patches rpc-message.h" 1 "$(grep -c '^+++ b/p11-kit/rpc-message.h$' "$PATCH")"
fi

echo "=== 2. all four mechanisms are covered, each the correct way ==="
if [ "$HAVE_PATCH" = yes ]; then
# The two *_KEY_PAIR_GEN mechanisms genuinely take no parameters, so they belong in the
# switch. The two SIGNING mechanisms do NOT — CKM_EDDSA takes an optional
# CK_EDDSA_PARAMS and CKM_ML_DSA an optional CK_SIGN_ADDITIONAL_CONTEXT. Declaring those
# parameterless would relay the mechanism while silently discarding a supplied parameter,
# and both structs hold a POINTER, so the generic byte-array fallback would copy a raw
# host pointer across the socket. They need real serializers, and this asserts the
# distinction rather than merely that the four names appear somewhere.
chk "CKM_EC_EDWARDS_KEY_PAIR_GEN added to the parameterless switch" 1 \
    "$(grep -c '^+	case CKM_EC_EDWARDS_KEY_PAIR_GEN:$' "$PATCH")"
chk "CKM_ML_DSA_KEY_PAIR_GEN added to the parameterless switch" 1 \
    "$(grep -c '^+	case CKM_ML_DSA_KEY_PAIR_GEN:$' "$PATCH")"
# ⚠️ AND THE ONE KEY REPLICATION RESTS ON. CKM_AES_KEY_WRAP_PAD takes no parameter, so it
# belongs in the switch rather than needing a serializer. Measured: SoftHSM wraps a private
# key with it happily when driven DIRECTLY, and an unpatched p11-kit rejects the same call
# with CKR_MECHANISM_INVALID (0x70) — every FastPKI process reaches its token through
# p11-kit, so without this `fastpki-ca key replicate` cannot wrap anything.
chk "CKM_AES_KEY_WRAP_PAD added to the parameterless switch" 1 \
    "$(grep -c '^+	case CKM_AES_KEY_WRAP_PAD:$' "$PATCH")"
chk "CKM_EDDSA gets a serializer, not the switch" yes \
    "$(grep -q '^+.*{ CKM_EDDSA, p11_rpc_buffer_add_eddsa_mechanism_value' "$PATCH" && echo yes || echo no)"
chk "CKM_ML_DSA gets a serializer, not the switch" yes \
    "$(grep -q '^+.*{ CKM_ML_DSA, p11_rpc_buffer_add_sign_additional_context_mechanism_value' "$PATCH" && echo yes || echo no)"
# The inverse: neither signing mechanism may be declared parameterless.
chk "CKM_EDDSA is NOT in the parameterless switch" 0 \
    "$(grep -c '^+	case CKM_EDDSA:$' "$PATCH")"
chk "CKM_ML_DSA is NOT in the parameterless switch" 0 \
    "$(grep -c '^+	case CKM_ML_DSA:$' "$PATCH")"

# Both serializers must handle the pointer field explicitly, which is the whole reason
# they exist rather than the byte-array fallback.
chk "the EdDSA serializer copies the context string by value" yes \
    "$(grep -q '^+.*params.pContextData' "$PATCH" && echo yes || echo no)"
chk "the ML-DSA serializer copies the context string by value" yes \
    "$(grep -q '^+.*params.pContext,' "$PATCH" && echo yes || echo no)"
# A serializer pair with only an encoder is a one-way trip: the value goes over the
# socket and cannot be read back.
for f in eddsa sign_additional_context; do
    chk "p11_rpc_buffer_add_${f}_mechanism_value is defined" yes \
        "$(grep -q "^+p11_rpc_buffer_add_${f}_mechanism_value" "$PATCH" && echo yes || echo no)"
    chk "p11_rpc_buffer_get_${f}_mechanism_value is defined" yes \
        "$(grep -q "^+p11_rpc_buffer_get_${f}_mechanism_value" "$PATCH" && echo yes || echo no)"
done
fi

echo "=== 3. the Dockerfile applies the FILE and nothing else ==="
chk "the patch is copied into the p11kit stage" yes \
    "$(grep -q 'COPY deploy/p11-kit-mechanisms.patch' Dockerfile && echo yes || echo no)"
chk "the p11kit stage runs patch(1)" yes \
    "$(grep -q 'patch -p1 --forward -d /tmp/p11kit -i /tmp/p11-kit-mechanisms.patch' Dockerfile && echo yes || echo no)"
# patch(1) has to be a PACKAGE in the `deps` stage every patching stage builds FROM, or the
# image build dies with `patch: not found`. So look inside that stage's `apk add`, with
# continuation lines joined first and the package name matched as a whole word. The old form
# accepted any indented line containing `patch`, which the three `patch -p1 --forward`
# invocations satisfy — so removing the package passed, and the assertion directly above,
# which REQUIRES one of those invocations, made this one incapable of failing.
chk "patch(1) is installed in the build deps" yes \
    "$(sed -e ':a' -e '/\\$/{N;s/\\\n//;ba' -e '}' Dockerfile \
       | awk '/^FROM .*[Aa][Ss] deps/{d=1;next} /^FROM /{d=0} d && /apk add/' \
       | sed -e 's/^/ /' -e 's/$/ /' \
       | grep -qE '[^A-Za-z0-9_-]patch[^A-Za-z0-9_-]' && echo yes || echo no)"
# The old form. A `sed -i` here is what made the fix unreachable from outside the image,
# and busybox sed silently no-ops on a GNU-style multi-line insert while still exiting 0
# — so its absence is worth asserting, not just the new form's presence.
#
# Continuation lines are JOINED first. The sed this replaces spanned three of them, with
# `sed -i` on the first and `rpc-message.c` on the third, so a line-at-a-time grep for
# 'sed .*rpc-message.c' found nothing and passed against the very tree it was written to
# reject. An assertion that holds for the wrong reason is worse than no assertion.
chk "no inline sed patches rpc-message.c" 0 \
    "$(sed -e ':a' -e '/\\$/{N;s/\\\n//;ba' -e '}' Dockerfile | grep -c 'sed .*rpc-message\.c')"
# Applying a patch that did nothing is the same green build as applying one that worked.
chk "the build asserts the patch actually landed" yes \
    "$(grep -q "grep -q 'case CKM_ML_DSA_KEY_PAIR_GEN:' /tmp/p11kit/p11-kit/rpc-message.c" Dockerfile && echo yes || echo no)"

echo "=== 4. a native installer is told about it ==="
# The gap this closes: the from-source path said nothing about any of this.
#
# ⚠️ MATCH THE COMMAND BY PREFIX, AND FIND THE SECTION BY ITS TITLE. Both assertions used
# to pin exact text -- the whole patch command including its `-i` argument, and an awk
# range hard-coded to `## 6.` .. `## 7.`. Renumbering the guide moved the native install
# from 6 to 7 and this suite went red for a document that had got BETTER, which is a test
# asserting a line number rather than a fact. The facts are: the command is shown, and it
# is shown in the native-install section wherever that section now sits.
chk "docs/deployment.md names the patch file" yes \
    "$(grep -q 'deploy/p11-kit-mechanisms.patch' docs/deployment.md && echo yes || echo no)"
chk "docs/deployment.md shows how to apply it" yes \
    "$(grep -q 'patch -p1 --forward -d /tmp/p11kit -i' docs/deployment.md && echo yes || echo no)"
chk "the guidance is in the native-install section" yes \
    "$(awk '/^## [0-9]+\. Native install/{s=1; next} /^## [0-9]+\. /{s=0} s' docs/deployment.md \
        | grep -q 'p11-kit-mechanisms.patch' && echo yes || echo no)"
chk "it says which algorithms are affected" yes \
    "$(grep -q 'CKM_EC_EDWARDS_KEY_PAIR_GEN' docs/deployment.md && echo yes || echo no)"

echo "=== 5. the patch really applies to 0.26.4 (needs git + network) ==="
# Everything above reads the patch as text. This is the only check that proves it is a
# valid diff against the real 0.26.4 tree — the difference between a file that looks
# right and one that works.
if [ "$HAVE_PATCH" != yes ]; then
    note "no patch file to apply"
elif ! command -v git >/dev/null 2>&1 || ! command -v patch >/dev/null 2>&1; then
    note "git or patch(1) missing — cannot apply against a real checkout"
elif ! git ls-remote --exit-code --heads https://github.com/p11-glue/p11-kit >/dev/null 2>&1; then
    note "no network to github — cannot clone p11-kit 0.26.4"
else
    TD=$(mktemp -d) || TD=""
    if [ -z "$TD" ]; then
        note "mktemp failed"
    else
        trap 'rm -rf "$TD"' EXIT
        if git clone --depth 1 --branch 0.26.4 https://github.com/p11-glue/p11-kit \
               "$TD/p11kit" >/dev/null 2>&1; then
            # --forward, like the Dockerfile: without it, patch offered an already-applied
            # patch will cheerfully REVERSE it and exit 0.
            out=$(patch -p1 --forward --no-backup-if-mismatch -d "$TD/p11kit" \
                        -i "$ROOT/$PATCH" </dev/null 2>&1)
            rc=$?
            chk "patch -p1 applies to 0.26.4" 0 "$rc"
            # Fuzz means it applied at a shifted offset — it worked today and is one
            # upstream edit away from applying to the wrong place.
            chk "it applies with no fuzz" 0 "$(printf '%s' "$out" | grep -ci 'fuzz')"
            chk "the switch case is present afterwards" 1 \
                "$(grep -c 'case CKM_ML_DSA_KEY_PAIR_GEN:' "$TD/p11kit/p11-kit/rpc-message.c")"
            chk "the EdDSA table entry is present afterwards" 1 \
                "$(grep -c '{ CKM_EDDSA, p11_rpc_buffer_add_eddsa_mechanism_value' "$TD/p11kit/p11-kit/rpc-message.c")"
            chk "the declarations reached the header" 2 \
                "$(grep -c 'p11_rpc_buffer_\(add\|get\)_eddsa_mechanism_value' "$TD/p11kit/p11-kit/rpc-message.h")"
            # Applying twice must be refused — proof the first apply was not a no-op
            # against an already-patched tree, which is how a green build means nothing.
            again=$(patch -p1 --dry-run --forward -d "$TD/p11kit" -i "$ROOT/$PATCH" \
                          </dev/null 2>&1)
            chk "re-applying is refused (so the first apply did the work)" yes \
                "$(printf '%s' "$again" | grep -qi 'previously applied' && echo yes || echo no)"
        else
            note "clone of p11-kit 0.26.4 failed"
        fi
    fi
fi

echo "=== 6. the patch WORKS: ask the token what it advertises through the client shim ==="
# Sections 1-5 all read TEXT — the patch file, the Dockerfile, docs/deployment.md, and an
# apply against a fresh clone. Every one of them can be true while the shipped image
# carries an UNPATCHED library, because the image is assembled by copying build artifacts
# over apk-installed ones and nothing checked which won.
#
# That is not hypothetical. deploy/lab-test.sh carried `apk add p11-kit p11-kit-server` on
# top of the runtime image; it was a no-op only while the installed version still satisfied
# the index, and the first Alpine bump would have restored the unpatched library over ours
# with no signal at all. The symptom would have been ML-DSA and Ed25519 cells SKIPPING,
# which reads like a host limitation rather than a broken image.
#
# So ask the running token, through p11-kit-client.so, which is the path every binary
# actually uses. This is the same probe hsm_mint_key() uses before it tries an ML-DSA key.
if ! command -v "${HSM_PKTOOL:-}" >/dev/null 2>&1; then
    . "$ROOT/tests/hsm_helpers.sh" 2>/dev/null || true
fi
ENV_ID="$(cat /etc/fastpki-test-env 2>/dev/null || echo host)"
if ! hsm_available 2>/dev/null; then
    note "no PKCS#11 toolchain here ($(hsm_skip_reason 2>/dev/null || echo 'helpers unavailable'))"
elif ! hsm_server_start >/dev/null 2>&1; then
    note "could not start a p11-kit server to ask"
else
    MECHS="$("$HSM_PKTOOL" --module "$HSM_CLIENT" --list-mechanisms 2>/dev/null)"
    for m in 'ml-dsa|mechtype-0x1[cd]' 'eddsa|edwards'; do
        got="$(printf '%s' "$MECHS" | grep -qiE "$m" && echo yes || echo no)"
        # ⚠️ ASSERTED ONLY WHERE IT MUST HOLD. On a developer Mac the Homebrew p11-kit and
        # SoftHSM are unpatched by construction, so demanding this would fail every local
        # run for a fact about the host. In the image we build it is a promise, and the
        # image says which it is: /etc/fastpki-test-env is written by deploy/Dockerfile.test
        # and by the Dockerfile's build stage, so a run cannot claim the wrong tier.
        if [ "$ENV_ID" = test-image ]; then
            chk "  the token advertises $m through p11-kit-client.so" yes "$got"
        else
            note "  $m advertised: $got (env=$ENV_ID — asserted only in the test image)"
        fi
    done
    hsm_server_stop >/dev/null 2>&1 || true
fi

echo "=== P11KITPATCH: PASS=$pass FAIL=$fail SKIP=$skip ==="
[ "$fail" -eq 0 ]
