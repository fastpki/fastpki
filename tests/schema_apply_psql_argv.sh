#!/usr/bin/env bash
# A database password must never reach psql's argv.
#
# The long-running field report was:
#
#   psql: warning: extra command-line argument "<32 chars>" ignored
#
# once per schema step. The cause is a PSQL override written as `-W <password>`. psql's
# `-W` takes NO argument, so psql reads the token as a POSITIONAL (its positionals are
# [dbname [username]]), has nowhere to put it once -d/-U are given, warns, and DISCARDS
# it. Three separate problems, none of them the operator's intent:
#
#   * the password authenticates nothing — it is thrown away;
#   * it sits in argv, so `ps` shows it to every user on the box, once per step;
#   * `-W` forces a prompt, in a script that feeds SQL on stdin.
#
# schema-apply.sh repairs it: the token moves to PGPASSWORD and `-W` goes with it.
#
# ⚠️ THE ASSERTION IS ABOUT ARGV, NOT ABOUT THE WARNING TEXT. Grepping for the warning
# would tie this to one psql build's wording, and would pass on any host whose psql is
# absent. A stub psql records exactly what it was called with, so the claim is measured
# on every host and says the thing that actually matters: the secret is not in argv.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
SECRET="ThisIsTheDatabasePasswordDoNotLeak"

# A stub psql that records its argv and its environment's PGPASSWORD, then answers
# anything asked of it well enough for the script to keep going.
mkdir -p "$W/bin"
cat > "$W/bin/psql" <<'STUB'
#!/usr/bin/env bash
{ printf 'ARGV:'; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'
  printf 'PGPASSWORD_SET:%s\n' "${PGPASSWORD:+yes}"; } >> "$PSQL_STUB_LOG"
# ⚠️ DO NOT READ STDIN. The script feeds SQL to psql for a step but not for every probe,
# and a stub that drains stdin blocks on the terminal when there is nothing to drain --
# which hung this suite before the redirect below was added as well.
echo 0
STUB
chmod +x "$W/bin/psql"

run_with(){   # <PSQL value> -> writes $W/log
    : > "$W/log"
    PSQL_STUB_LOG="$W/log" PATH="$W/bin:$PATH" PGPASSWORD= \
      PSQL="$1" SCHEMA_STEPS_DIR="$W/nosteps" \
      sh "$ROOT/deploy/schema-apply.sh" --check >"$W/out" 2>&1 </dev/null || true
}

echo "=== a password written as \`-W <password>\` never reaches argv ==="
mkdir -p "$W/nosteps"
run_with "psql -U fastpki -d fastpki -h 127.0.0.1 -p 5432 -W $SECRET"
chk "PRECONDITION: the stub psql was actually invoked" yes \
    "$(grep -q '^ARGV:' "$W/log" && echo yes || echo no)"
chk "the secret is in no argv" no \
    "$(grep '^ARGV:' "$W/log" | grep -q "$SECRET" && echo yes || echo no)"
chk "  and no bare -W is left to prompt on" no \
    "$(grep '^ARGV:' "$W/log" | grep -q '\[-W\]' && echo yes || echo no)"
chk "  it was moved to PGPASSWORD, where it authenticates" yes \
    "$(grep -q '^PGPASSWORD_SET:yes' "$W/log" && echo yes || echo no)"
# ⚠️ THE NOTE IS GONE BY REQUEST, so this no longer asserts the operator is told. What it
# still asserts is the part that matters and the part that could regress silently: the
# secret is in no argv, and it is not echoed anywhere in the output either. A repair that
# quietly stopped happening would look identical in a log that says nothing.
chk "  and the secret is not echoed in the output" no \
    "$(grep -q "$SECRET" "$W/out" && echo yes || echo no)"
chk "  and no note is printed about it" no \
    "$(grep -qi 'visible in ps' "$W/out" && echo yes || echo no)"
# The connection details must survive the surgery — dropping the wrong token would send
# psql at the wrong database, which is a worse outcome than the warning.
chk "  -U/-d/-h/-p are untouched" yes \
    "$(grep '^ARGV:' "$W/log" | head -1 | grep -q '\[-U\] \[fastpki\] \[-d\] \[fastpki\] \[-h\] \[127.0.0.1\] \[-p\] \[5432\]' && echo yes || echo no)"

echo "=== a BARE -W is a deliberate request to be prompted, and is left alone ==="
run_with "psql -W -U fastpki -d fastpki"
chk "bare -W survives" yes \
    "$(grep '^ARGV:' "$W/log" | head -1 | grep -q '\[-W\]' && echo yes || echo no)"
chk "  and the username is not eaten as if it were a secret" yes \
    "$(grep '^ARGV:' "$W/log" | head -1 | grep -q '\[-U\] \[fastpki\]' && echo yes || echo no)"

echo
echo "=== SCHEMA-APPLY PSQL ARGV: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
