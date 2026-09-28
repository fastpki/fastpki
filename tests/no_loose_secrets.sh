#!/usr/bin/env bash
# No private key may sit in this work tree, ignored or not.
#
# .gitignore is the passive half: it stops key material being COMMITTED. It does nothing
# about key material being PRESENT, and present is where this started. A census found
# seven private keys loose in the tree — four OCSP responder keys with their certificates,
# CSRs, serial and extension files left in the repo root by a manual openssl session, two
# demo client keys, and a certbot ACME account key under demo/coredns. None was ignored;
# all were one `git add -A` away from a public repository.
#
# ⚠️ AN IGNORED SECRET IS STILL A SECRET, and widening .gitignore to cover *.key/*.pem
# makes the next one INVISIBLE rather than absent — it stops appearing in `git status` at
# all. So this asserts the stronger property, that the key is not there. The ignore rules
# are asserted separately in §3 because they answer a different question.
#
# Every suite writes its key material into a mktemp directory and tears it down, so a key
# inside the tree means a suite leaked one or a person left one behind. Both earn a red run.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT" || exit 1
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# ⚠️ POSIX ERE, never -P: busybox grep in the shipped image has no PCRE.
#
# ⚠️ ANCHORED AT BOTH ENDS, and that is not cosmetic. A real PEM carries the marker alone
# on its own line; a SOURCE file that merely names it has it inside a string literal after
# a quote or a backtick. Unanchored, this reported tests/web_keygen_der.mjs, which builds
# a key at runtime and holds no key material at all — and a census that cries wolf is one
# that gets an exclusion list bolted onto it, which is how a real key eventually hides.
#
# ⚠️ AND ALWAYS PASSED VIA -e. Before the anchor the pattern began with five dashes, so
# `grep -lE "$KEYRE"` handed grep what looked like a bundle of options: it exited 2 having
# read nothing, xargs printed nothing, and every census reported a clean tree. That is how
# §1 and §2 passed against a tree with a planted key in it. §4 is what caught it, and is
# why §4 exists.
KEYRE='^-----BEGIN ([A-Z]+ )?PRIVATE KEY-----$'

# build/ holds compiled objects and the demo's throwaway work dirs; .git/ holds packfiles.
# Neither is source, and scanning them is slow enough to discourage running this at all.
scan_tree() {
    find . -type d \( -name .git -o -name build -o -name 'build-*' \) -prune -o \
           -type f -print 2>/dev/null \
      | xargs grep -l -E -e "$KEYRE" 2>/dev/null
}

echo "=== 1. no private key anywhere in the work tree ==="
chk "no file in the tree carries a PEM private key block" "" "$(echo $(scan_tree))"

echo "=== 2. and none is TRACKED (published, which is a worse failure than present) ==="
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    chk "no tracked file carries a PEM private key block" "" \
        "$(echo $(git grep -l -E -e "$KEYRE" -- . 2>/dev/null))"
    # History too: a key deleted from the tip is still in every clone that ever fetched it.
    chk "no key-shaped file was ever added in history" 0 \
        "$(git log --all --diff-filter=A --name-only --format='' -- \
             '*.key' '*.p12' '*.pfx' 2>/dev/null | grep -c . | tr -d ' ')"
else
    echo "  [SKIP] not a git work tree — sections 2 and 3 read the index and history"
fi

echo "=== 3. the ignore rules cover the classes, so a new one cannot be committed ==="
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    for n in stray.key stray.pem stray.p12 stray.pfx stray.csr; do
        chk "  .gitignore covers $n" yes "$(git check-ignore -q "$n" && echo yes || echo no)"
    done
    # ⚠️ AND DOES NOT SWALLOW THE FUZZ CORPUS. Those are tracked ASN.1 inputs carrying no
    # key material; an ignore rule that hid them would make a corpus update silently do
    # nothing, which is the same class of quiet failure as the one above.
    chk "  ...but not the tracked fuzz corpus" no \
        "$(git check-ignore -q fuzz/corpus/cmp/ir.der && echo yes || echo no)"
fi

echo "=== 4. PRECONDITION: the census can actually see a planted key ==="
# Without this, every check above passes on an empty scan the day the pattern, the prune
# list or a grep flag stops matching — the vacuous shape this repo keeps re-learning. It
# has already earned its place once: see the -e note above.
PLANT="./.no_loose_secrets_probe.key"
printf '%s\n%s\n%s\n' '-----BEGIN PRIVATE KEY-----' 'MIIBVQIBADAN' '-----END PRIVATE KEY-----' > "$PLANT"
chk "a planted private key is found" yes \
    "$(scan_tree | grep -q 'no_loose_secrets_probe' && echo yes || echo no)"
rm -f "$PLANT"
chk "  and the tree is clean again once it is removed" "" "$(echo $(scan_tree))"

echo
echo "=== NO LOOSE SECRETS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
