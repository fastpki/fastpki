#!/usr/bin/env bash
# `--help` must answer, from anywhere, without loading anything.
#
# ⚠️ THE DEMO'S HELP USED TO DEPEND ON THE WHOLE TEST HARNESS. `-h|--help` was a case arm
# in the argument loop, ninety lines below five `source`s of tests/*.sh. On a machine where
# any of that is slow or unhappy the flag is never reached, so `--help` prints NOTHING and
# a bare run sits there silently — and they fail identically, which is exactly how it was
# reported: "no output, no activity".
#
# ⚠️ AND IT MUST DESCRIBE THE FLAGS. Both scripts printed a `sed` range of their own header
# comment, so the help was whatever that comment happened to contain. The bench had TWO
# such handlers printing two DIFFERENT ranges, so the answer depended on which one you
# reached. §4 below is the guard that matters longest: every option the argument loop
# accepts has to appear in the help, or the next flag added is undocumented by default.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ grep -qF -- "$2" <<<"$1" && echo yes || echo no; }
# An option counts as documented only when the help names it AS A WORD. A bare substring
# match lets `-k` be "documented" by the word `--ca-keys` and `-h` by `--help`, so a
# single-letter flag can go missing with nothing to show for it.
# ⚠️ Pad the stream and use ONE bracket class. `(^|[^A-Za-z])` is not a word boundary in
# BSD grep — `^` inside an alternation matches nothing there, so such an expression looks
# right and silently matches nothing at all.
has_opt(){ printf '%s\n' "$1" | sed -e 's/^/ /' -e 's/$/ /' \
           | grep -qE "[^A-Za-z0-9_-]$2[^A-Za-z0-9_-]" && echo yes || echo no; }

for s in pki-demo pki-bench; do
  F="$ROOT/demo/$s.sh"
  echo "=== $s.sh ==="

  out=$(bash "$F" --help 2>&1); rc=$?
  chk "  --help exits 0" 0 "$rc"
  chk "  and prints something" yes "$([ -n "$out" ] && echo yes || echo no)"
  # ⚠️ A HEADER COMMENT IS NOT HELP. Both scripts used to sed their own comment block out
  # of themselves, so the first line came back starting with '#'.
  # ⚠️ NOT a `case` here: an unquoted `)` in a case pattern closes the surrounding $( )
  # and the whole assertion becomes a syntax error that still reports a FAIL, so it reads
  # like a product problem.
  chk "  and it is usage text, not this file's comment header" no \
      "$([ "${out:0:1}" = "#" ] && echo yes || echo no)"
  chk "  which names the script" yes "$(has "$out" "demo/$s.sh")"

  # ⚠️ RUN IT SOMEWHERE WITH NO tests/ BESIDE IT. This is the real failure, and it is the
  # env-independent way to provoke it: chmod 000 proves nothing when the suite runs as
  # root, which it does in the in-image tier.
  mkdir -p "$W/$s/demo"; cp "$F" "$W/$s/demo/"
  out2=$(bash "$W/$s/demo/$s.sh" --help 2>&1); rc2=$?
  chk "  --help still answers with no tests/ helpers to load at all" 0 "$rc2"
  chk "  and prints the same text" yes "$([ "$out2" = "$out" ] && echo yes || echo no)"

  # Structural: the help must be answered ABOVE the first source line, not merely work today.
  hline=$(grep -n 'usage; exit 0' "$F" | head -1 | cut -d: -f1)
  sline=$(grep -n '^source "' "$F" | head -1 | cut -d: -f1)
  chk "  the help handler sits above the first source line ($hline < $sline)" yes \
      "$([ -n "$hline" ] && [ -n "$sline" ] && [ "$hline" -lt "$sline" ] && echo yes || echo no)"

  # ⚠️ EVERY ACCEPTED OPTION IS DOCUMENTED. Read the argument loop's own case arms rather
  # than a hand-kept list, so a flag added later is caught instead of quietly undocumented.
  #
  # ⚠️ THE ARMS ARE NOT ONE PER LINE, and an extractor anchored at the start of a line
  # compares only the first of each group against the help. pki-bench.sh packs
  # `-n) …;;  -k) …;;  -p) …;;` onto ONE line and both scripts write `-h|--help)`, so `-k`,
  # `-p` and `--help` were never compared against anything at all — a flag added to such a
  # line was undocumented by default, which is the one thing this cell exists to stop.
  # Split on `;;` and on `|` first, then read each pattern up to its own `)`.
  #
  # ⚠️ AND COUNT WHAT CAME OUT. "nothing missing" is also what an EMPTY list looks like, so
  # a renamed loop header (`while [ "$#" -gt 0 ]`) used to turn this into a comparison over
  # zero options. The range pattern tolerates either spelling and the count cell says out
  # loud how many arms were read.
  opts=$(sed -n '/^while \[ *"*\$#"* -gt 0 \]/,/^done$/p' "$F" \
         | tr ';|' '\n\n' | sed 's/).*$//' \
         | grep -oE '^[[:space:]]*--?[a-z][a-z0-9-]*' | tr -d ' ' | sort -u)
  nopt=$(printf '%s\n' "$opts" | grep -c .)
  chk "  the argument loop's own case arms were read (got $nopt)" yes \
      "$([ "$nopt" -ge 4 ] && echo yes || echo no)"
  miss=
  for opt in $opts; do
      [ "$(has_opt "$out" "$opt")" = yes ] || miss="$miss $opt"
  done
  chk "  every option the argument loop accepts is in the help" "" "$miss"

  bad=$(bash "$F" --definitely-not-a-flag 2>&1); rcb=$?
  chk "  an unknown option exits 2" 2 "$rcb"
  chk "  and points at --help" yes "$(has "$bad" "--help")"
  echo
done

echo "=== the bench's key-type list matches the code ==="
# ⚠️ THE SPELLINGS DIFFER BETWEEN THE TWO SCRIPTS — the demo takes rsa:2048, the bench
# takes rsa2048 — which is precisely the sort of thing help gets wrong. Read the default
# list out of the code and require the help to name every one of them.
DEFAULTS=$(grep -m1 '^COUNT=[0-9]*; KEYTYPES=' "$ROOT/demo/pki-bench.sh" | sed 's/.*KEYTYPES="//; s/".*//')
chk "the default key list was found in the code" yes "$([ -n "$DEFAULTS" ] && echo yes || echo no)"
bhelp=$(bash "$ROOT/demo/pki-bench.sh" --help 2>&1)
miss=
for k in $DEFAULTS; do [ "$(has "$bhelp" "$k")" = yes ] || miss="$miss $k"; done
chk "every key type the bench runs by default is named in its help" "" "$miss"

echo
echo "=== DEMO HELP: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
