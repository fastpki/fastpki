#!/usr/bin/env bash
# A suite that counts failures must be ABLE to fail the run.
#
# Found on the lab: install_wizard.sh printed five real [FAIL] lines and run_all.sh
# recorded it as `ok`. Twenty-two suites had the same shape — they end with
#
#     echo "=== X: PASS=$pass FAIL=$fail ==="
#
# and nothing else. `echo` returns 0, so the script's exit status is 0 no matter what
# the counter says. run_all.sh judges a suite by its exit status (tests/run_all.sh:4),
# so every assertion in those suites was decoration: it could print red forever and the
# summary would still say ALL GREEN.
#
# That is the same class as the fuzz probe that skipped on every machine and the guard
# that had never been watched failing. The counter is not the verdict — the exit status
# is, and the two have to be connected.
#
# Two checks, because either alone is weak:
#   1. STATIC — every suite that increments `fail` also gates its exit on it.
#      Cheap, covers all 171, and is the property we actually want.
#   2. WITNESS — take a real suite, break one assertion, run it, and require a non-zero
#      exit. A static check can be satisfied by a gate that is unreachable (dead code
#      after an early exit, or inside a branch that never runs). This proves the
#      mechanism end to end on at least one suite, so the static check is standing on
#      something demonstrated rather than on the presence of a string.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# Both idioms count as a gate: `[ "$fail" -eq 0 ]` as the final command, and the
# explicit `if [ "$fail" -ne 0 ]; then exit 1; fi` that no_default_ca.sh uses.
GATE='\$fail" *-(eq|ne|gt) *0|\$fail *-(eq|ne|gt) *0'

echo "=== every failure-counting suite gates its exit on the counter ==="
counting=0; ungated=""; notlast=""
for f in tests/*.sh; do
    grep -qF 'fail=$((fail+1))' "$f" || continue
    counting=$((counting+1))
    grep -qE "$GATE" "$f" || { ungated="$ungated $(basename "$f")"; continue; }
    # ⚠️ Presence of the string is not enough, and I proved that on myself. Appending the
    # gate to a file with NO trailing newline glued it onto the echo above:
    #
    #     echo "=== CMP AUTHZ: PASS=$pass FAIL=$fail ==="[ "$fail" -eq 0 ]
    #
    # which is one `echo` call with a strange argument, exit 0. Three suites looked fixed
    # and were not, and the string check above passed all three. So require the gate to be
    # the LAST executable line, standing alone.
    #
    # ⚠️ There are TWO valid gates and I nearly "fixed" eight working suites by forgetting
    # the second. run_all.sh:199 counts a suite FAILED if it exits non-zero OR prints
    # "RESULT: FAIL", so
    #
    #     [ "$fail" -eq 0 ] || echo "RESULT: FAIL"
    #     exit 0
    #
    # is a real gate through the output channel. Accept it; requiring the exit-status form
    # would have been a change dressed up as a fix.
    if grep -qF '[ "$fail" -eq 0 ] || echo "RESULT: FAIL"' "$f"; then continue; fi
    # Match on the gate LEADING the final line rather than on an exact string. Suites
    # legitimately write `[ "$fail" -eq 0 ]`, `… || exit 1`, and the `if … -ne 0` form;
    # enumerating every spelling is a losing game, and the property that actually matters
    # is that the line STARTS with the test rather than having it glued onto an echo.
    last=$(grep -vE '^[[:space:]]*(#|$)' "$f" | tail -1)
    case "$last" in
        '[ "$fail" -eq 0 ]'*|'if [ "$fail" -ne 0 ]'*) ;;
        *) notlast="$notlast $(basename "$f")" ;;
    esac
done
# A floor, so this suite cannot quietly pass by finding no suites at all — the exact
# way the old fuzz probe passed forever.
chk "there are suites to check at all" yes "$([ "$counting" -ge 100 ] && echo yes || echo no)"
chk "no suite counts failures it cannot report" "" "$ungated"
chk "and the gate is the last command, not glued to another" "" "$notlast"

echo "=== the gate really works: break an assertion, the suite must exit non-zero ==="
# install_wizard.sh is the witness because it needs no Postgres, no token and no network,
# so this stays a CORE check that runs on any dev box.
PROBE="tests/_exit_honest_probe.sh"
trap 'rm -f "$ROOT/$PROBE"' EXIT
sed 's|chk "node1 id"  1 |chk "node1 id"  CANNOT_MATCH |' tests/install_wizard.sh > "$PROBE"
bash "$PROBE" >/tmp/_exit_honest_probe.log 2>&1; mutated=$?
bash tests/install_wizard.sh >/tmp/_exit_honest_base.log 2>&1
broke=$(grep -c '\[FAIL\]' /tmp/_exit_honest_probe.log)
base=$(grep -c '\[FAIL\]' /tmp/_exit_honest_base.log)
# ⚠️ MEASURE THE DELTA, not the absolute count, and this is not hypothetical tidiness.
# The first version asserted "exactly 1 failure when mutated" and "0 when not", which
# silently required the witness suite to be GREEN. On the lab install_wizard.sh had five
# real failures of its own, so this guard went red reporting 6-instead-of-1 and
# 1-instead-of-0 — a complaint about exit gating whose actual cause was somewhere else
# entirely. A guard that fails for reasons outside what it guards is noise, and worse,
# it trains you to ignore it.
#
# The mutation still has to LAND: +1 failure. That is what catches a no-op mutation,
# where a non-zero exit would prove nothing about the gate because the script merely died.
chk "the mutation adds exactly one failure" "$((base + 1))" "$broke"
chk "a broken assertion exits non-zero"     yes "$([ "$mutated" -ne 0 ] && echo yes || echo no)"

echo "=== 3. and a suite that exists is actually RUN ==="
# The same class as the two checks above, one step earlier: an assertion that cannot fail
# the run is decoration, and an assertion in a file the harness never opens is not even
# that. run_all.sh has no discovery — SUITES is built from four hand-written arrays — so a
# file can sit in tests/ for months looking like coverage while running zero times.
#
# Three were found this way, and note that NONE of them is detectable by reading the file:
#   smoke_acme.sh   never wired in the repo's entire history; deleted, since
#                   acme_lifecycle.sh covers register->issue->revoke and is wired
#   deploy_env.sh   dropped from CORE by bc32eaa, whose message lists the 16 tests it
#                   DELETED and does not mention the two it merely unwired. It is the only
#                   suite asserting the DATACENTER_ID -> serial-prefix chain — the
#                   mechanism that crash-looped all 12 services on all 3 DCs — and it
#                   passes 8/0, so it was working coverage that simply stopped being read.
#   cppcheck.sh     dropped by the same commit while README still calls it a live gate.
#
# A file here is legitimate in exactly three ways: named in run_all.sh, sourced as a
# helper, or on the list below with a reason. Anything else is an orphan.
declare -a NOT_SUITES=(
    run_all.sh              # the harness itself
    build_openssl_dev.sh    # dev build tool for boxes whose system OpenSSL is too old
    clang_tidy.sh           # analysis gate, never wired in repo history — wiring it is a
                            # runtime-cost decision, not a restoration; see the ticket
    diag_cmp_rr.sh          # manual diagnostic, no assertions
    diag_genm.sh            # manual diagnostic, no assertions
    ocsp_nonce_req.sh       # DER generator, invoked BY PATH from ocsp_abuse.sh (not sourced)
    run-in-container.sh     # the RUNNER, not a suite: it builds the test image from the
                            # shipped one and executes run_all.sh (or one suite) inside it.
                            # Wiring it into a tier would make the harness invoke itself.
)
orphans=""; wired=0
for f in "$ROOT"/tests/*.sh; do
    b=$(basename "$f")
    # ⚠️ Skip our OWN scratch file. Check 2 above copies a real suite to
    # tests/_exit_honest_probe.sh, mutates it and runs it — so while this suite is
    # running there is, by construction, a file in tests/ that is in no array and sourced
    # by nobody. The first version of this loop dutifully reported it as an orphan, which
    # is a guard failing on the conditions its own sibling check creates. The leading
    # underscore is the convention that marks it as scratch.
    case "$b" in _*) continue;; esac
    skip=no
    for x in "${NOT_SUITES[@]}"; do [ "$b" = "$x" ] && skip=yes; done
    [ "$skip" = yes ] && continue
    # ⚠️ AS ITS OWN WORD, NOT A SUBSTRING. A bare `grep -q "$b"` counted a suite as wired
    # whenever a LONGER suite name contained its name, so removing it from every tier array
    # left it reported as wired and running zero times — exactly the regression this section
    # exists for, and its own header names two suites that were dropped from CORE that way.
    # Measured collisions: web.sh inside notify_web.sh and profiles_web.sh, crl.sh inside
    # imported_crl.sh and store_crl.sh, store_uri.sh inside pg_store_uri.sh, store_hash.sh
    # inside pg_store_hash.sh, discover.sh inside web_discover.sh, backup.sh inside
    # web_backup.sh, and mesh.sh inside lab_replication_mesh.sh — that last one matching only
    # in the LAB array, which runs only under RUN_LAB=1. The anti-vacuity count below could
    # not see any of it, because the other ~250 names match for real.
    besc=$(printf '%s' "$b" | sed 's/[].[^$()*+?{}|\\]/\\&/g')
    if sed -e "s/^/ /" -e "s/$/ /" "$ROOT/tests/run_all.sh" \
       | grep -qE "[^A-Za-z0-9_.-]${besc}[^A-Za-z0-9_.-]"; then
        wired=$((wired+1)); continue
    fi
    # A helper is a file another suite pulls in with `source` or `.`; it has no business
    # being in run_all.sh and is not an orphan.
    grep -lE "(source|\.)[[:space:]]+[^[:space:]]*/$b" "$ROOT"/tests/*.sh >/dev/null 2>&1 && continue
    orphans="$orphans $b"
done
chk "no suite sits in tests/ unrun"        "" "$orphans"
# ⚠️ The loop must be counting something. If run_all.sh were emptied or renamed, `wired`
# would be 0 and the check above would pass with nothing examined — the vacuous shape.
chk "  ... and the check saw the harness"  yes \
    "$([ "$wired" -ge 100 ] && echo yes || echo "no (only $wired wired)")"

echo "=== 4. the ACME suites are SHELL-ONLY, and no suite names a driver that is gone ==="
# §3e: every test is a self-contained shell script — no Python.
# Converted the last ACME drivers to certbot + the shell JWS client
# (tests/acme_jws.sh). This keeps them converted.
#
# Scoped to ACME on purpose. `oidc.sh`, `saml.sh`, `update.sh`, `web_csrmap.sh`,
# `web_onboarding.sh`, `ocsp_abuse.sh` and `ca_rollover_chain.sh` still shell out to
# python3 for a mock IdP / feed / cryptography probe. §3e calls those legacy to migrate
# off, not a pattern to copy — a blanket check would fail today and get muted, which is
# worse than a narrow one that holds.
acme_py=$(grep -lE '^[^#]*\b(python3?|\$PY)\b' "$ROOT/tests"/acme_*.sh 2>/dev/null | tr '\n' ' ')
chk "no tests/acme_*.sh executes python" "" "$(echo $acme_py)"
chk "no tests/acme_*.py driver is left"  "" \
    "$(ls "$ROOT/tests"/acme_*.py 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')"
# ⚠️ The vacuity guard: the glob has to have matched something. If the ACME suites were
# renamed, both checks above would pass having examined nothing.
chk "  ... and the check saw the ACME suites" yes \
    "$([ "$(ls "$ROOT/tests"/acme_*.sh 2>/dev/null | wc -l | tr -d ' ')" -ge 10 ] && echo yes || echo no)"

# A COMMENT that names a driver file is documentation, and documentation pointing at a
# deleted file sends the next reader looking for it. acme_keychange.sh said it "drives the
# protocol with tests/acme_keychange.py" long after that file was removed.
#
# ⚠️ PAST TENSE IS EXCUSED, and it is matched per PARAGRAPH, not per line — the same
# lesson docs_accurate.sh already learned about config keys. "§3e: was
# tests/acme_retry_after.py" is history worth keeping: it tells the next reader why the
# suite looks the way it does. What must never survive is a claim that a deleted file is
# what the suite USES.
#
# Per line is not good enough: a comment wraps, so the filename and the word that excuses
# it routinely land on different lines. This check flagged its OWN header for exactly that
# reason before the paragraph form went in.
missing_py=""
for f in "$ROOT/tests"/*.sh; do
    # Join each run of consecutive comment lines into one paragraph, then judge that.
    while IFS= read -r para; do
        case "$para" in
            *was*|*replac*|*remov*|*delet*|*gone*|*"no longer"*|*"used to"*) continue ;;
        esac
        for ref in $(printf '%s' "$para" | grep -oE 'tests/[A-Za-z0-9_]+\.py' | sort -u); do
            [ -f "$ROOT/$ref" ] || missing_py="$missing_py $(basename "$f"):$ref"
        done
    done < <(awk '/^[[:space:]]*#/ { p = (p == "" ? $0 : p " " $0); next }
                  { if (p != "") print p; p = "" }
                  END { if (p != "") print p }' "$f" 2>/dev/null)
done
chk "no suite claims to USE a tests/*.py that does not exist" "" "$(echo $missing_py)"

echo
echo "=== 5. no suite uses a grep option busybox does not have ==="
# ⚠️ GUARD THE SHAPE, NOT THE SITE. `grep -b` (byte offset) is a GNU extension. On the
# Alpine image we actually ship, busybox grep REJECTS it and prints its usage text, so the
# caller gets a usage dump where it expected a number — and every comparison built on it
# fails as though the product had stopped emitting the thing being located.
#
# This has now happened THREE times: web_hsm_leaf.sh and web_endpoint_controls.sh were
# fixed and each left a warning comment, and the panel-order guard was written
# afterwards with the same bug — so that check had never once run on the platform we ship.
# Two one-site fixes plus a comment did not stop the third. A census does.
#
# `grep -P` is the same class (PCRE, GNU-only) and is banned here for the same reason.
# The portable replacement is awk's index(), which is literal and present on both:
#     off(){ printf '%s' "$FLAT" | awk -v n="$needle" '{i=index($0,n); if(i){print i-1; exit}}'; }
# Flatten with `tr '\n' ' '` first — awk is line-oriented.
# ⚠️ TWO FALSE POSITIVES THIS SCANNER HAD ON ITS FIRST RUN, both worth keeping in mind:
#   * `pgrep -P` matched, because "pgrep" ENDS IN "grep". Hence the leading boundary.
#   * this file matched ITSELF, because the pattern it searches for is written in it —
#     the mirror of the guard that passed forever by matching its own comment. It is
#     excluded by name, and the probe below is what keeps that exclusion honest.
# Only lines that RUN it count: the two fixed suites carry `grep -bo` in warning prose.
SCAN='(^|[^a-zA-Z_.-])grep +-[a-zA-Z]*[bP]'
bad_grep=$(for f in "$ROOT"/tests/*.sh; do
             b=$(basename "$f")
             if [ "$b" != suite_exit_honest.sh ] && grep -Eq "^[^#]*$SCAN" "$f"; then
                 echo "$b"
             fi
           done)
chk "no suite runs grep -b or grep -P (busybox lacks both)" "" "$(echo $bad_grep)"
# ⚠️ A census that matches nothing is vacuous, and this one excludes a file by name — so
# prove it still SEES a real hit, and that the two near-misses above stay unmatched.
probe=$(mktemp)
printf 'x=$(grep -bo foo bar)\n' > "$probe"
chk "  ... and the scanner detects a real one" yes \
    "$(grep -Eq "^[^#]*$SCAN" "$probe" && echo yes || echo no)"
printf 'kids=$(pgrep -P "$PID")\n' > "$probe"
chk "  ... and does NOT trip on pgrep -P" yes \
    "$(grep -Eq "^[^#]*$SCAN" "$probe" && echo no || echo yes)"
printf '# a comment mentioning grep -bo as prose\n' > "$probe"
chk "  ... nor on a warning comment about it" yes \
    "$(grep -Eq "^[^#]*$SCAN" "$probe" && echo no || echo yes)"

# ⚠️ AND THE FILE-SELECTION OPTIONS, WHICH ARE WORSE THAN -b/-P BECAUSE THEY DO NOT FAIL.
# `--include` / `--exclude` / `--exclude-dir` are GNU. busybox does not implement them and
# does not complain either: measured inside the shipped image,
#   grep -rh --include='*.cpp' --include='*.hpp' -v PATTERN src include
# returns ZERO lines and EXIT 0. A census built on that examines no files, and every
# assertion whose healthy answer is "found nothing" then passes by finding nothing.
#
# It had already happened twice in this tree, in a role census and in a check that a
# removed authorization-bypass config key stays removed — both green on a GNU-grep dev box
# and both vacuous on the only platform we ship. `-b`/`-P` at least error out loudly.
# Select the extension from grep's OUTPUT instead (`| grep -E '\.(cpp|hpp):[0-9]+:'`),
# which both greps spell the same way.
SCAN2='(^|[^a-zA-Z_.-])grep +[^|;)]*--(include|exclude|exclude-dir)'
bad_inc=$(for f in "$ROOT"/tests/*.sh "$ROOT"/deploy/*.sh; do
            [ -f "$f" ] || continue
            b=$(basename "$f")
            if [ "$b" != suite_exit_honest.sh ] && grep -Eq "^[^#]*$SCAN2" "$f"; then
                echo "$b"
            fi
          done)
chk "no suite uses grep --include/--exclude (busybox answers NOTHING)" "" "$(echo $bad_inc)"
printf 'n=$(grep -rh --include="*.cpp" foo src)\n' > "$probe"
chk "  ... and the scanner detects a real one" yes \
    "$(grep -Eq "^[^#]*$SCAN2" "$probe" && echo yes || echo no)"
printf '# prose about grep --include being GNU-only\n' > "$probe"
chk "  ... nor on a warning comment about it" yes \
    "$(grep -Eq "^[^#]*$SCAN2" "$probe" && echo no || echo yes)"
rm -f "$probe"

echo
echo "=== 6. no suite asks BSD stat first and falls back on exit status ==="
# ⚠️ `stat -f` MEANS TWO DIFFERENT THINGS. On BSD/macOS it introduces a format string;
# on GNU coreutils it means "display FILESYSTEM status" — and on a regular file that
# SUCCEEDS. So `stat -f '%Lp' f || stat -c '%a' f` never reaches the fallback on Linux: it
# returns exit 0 with `  File: "..."` and the caller compares a mode against filesystem
# prose. Green on a Mac, red on Linux, and only visible where it runs:
#
#   [FAIL] readable only by its owner (expected '600' got '  File: "/tmp/.../svc.keytab"
#
# The knowledge was already in pg_tls_issue.sh ("GNU FORM FIRST") and a later site got it
# backwards anyway, which is what makes this a guard rather than a comment. Ordering alone
# is the weaker fix; judging the OUTPUT (does it look like a mode?) is the strong one, and
# either satisfies this check — what it forbids is BSD-first with an exit-status fallback.
statfirst=""
# ⚠️ SELF-EXCLUSION IS LOAD-BEARING. This suite necessarily contains the pattern it looks
# for -- in the comment above and in the planted control below -- and the first run of this
# check reported `suite_exit_honest.sh` as the offender. A guard that matches its own prose
# is a guard that can never go green, which is how guards get deleted.
#
# ⚠️ AND IT HAS TO WORK WITHOUT git. The in-image run has no git at all -- which is why
# public_repo_hygiene.sh SKIPS there -- and a `git grep` that finds nothing looks exactly
# like a clean tree. That suite enforces the rule repo-wide ("every wired suite using git
# also handles git being absent") and caught THIS section on its first run: the guard
# catching the guard, which is the point of having it. `find` works in both places.
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    statfiles=$(git grep -lE "stat -f" -- tests ':!tests/suite_exit_honest.sh' 2>/dev/null)
else
    statfiles=$(find "$ROOT/tests" -name '*.sh' ! -name 'suite_exit_honest.sh' \
                  -exec grep -lE "stat -f" {} + 2>/dev/null)
fi
for f in $statfiles; do
    grep -qE "stat -f[^|]*\|\|[^|]*stat -c" "$f" && statfirst="$statfirst $(basename "$f")"
done
chk "no suite chains BSD stat -f before GNU stat -c" "" "${statfirst# }"

# ⚠️ POSITIVE CONTROL. The pattern above is three alternations deep; if it stops matching,
# the check passes over every file forever.
# ⚠️ EXIT TRAPS DO NOT STACK. The trap set at the top of this file removes the planted
# `_exit_honest_probe.sh`; a second `trap ... EXIT` here REPLACES it, and the probe then
# leaks into tests/ on every run -- an untracked file in the very directory this suite
# polices, one `git add -A` away from being committed. Caught by `git status` before
# staging, not by anything automatic. So this trap removes BOTH.
PLANT=$(mktemp); trap 'rm -f "$PLANT" "$ROOT/$PROBE"' EXIT
printf 'MODE=$(stat -f %s%%Lp%s "$f" 2>/dev/null || stat -c %s%%a%s "$f" 2>/dev/null)\n' "'" "'" "'" "'" > "$PLANT"
chk "  PRECONDITION: the matcher fires on a planted chain" yes \
    "$(grep -qE "stat -f[^|]*\|\|[^|]*stat -c" "$PLANT" && echo yes || echo no)"
# ...and the shape we WANT is not reported, or the guard would forbid the fix.
printf 'MODE=$(stat -c %s%%a%s "$f" 2>/dev/null || stat -f %s%%Lp%s "$f" 2>/dev/null)\n' "'" "'" "'" "'" > "$PLANT"
chk "  and GNU-first is accepted" no \
    "$(grep -qE "stat -f[^|]*\|\|[^|]*stat -c" "$PLANT" && echo yes || echo no)"

echo "=== SUITE EXIT HONEST: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
