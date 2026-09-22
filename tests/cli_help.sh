#!/usr/bin/env bash
# Every CLI must print its usage on --help WITHOUT touching the database.
#
# fastpki-ca and fastpki-config used to load the config and open Postgres before deciding
# what the user asked for, so `--help` -- the first thing anyone runs, normally before any
# config exists -- answered with
#
#     fastpki-ca: postgres connect failed: ... FATAL:  role "someuser" does not exist
#
# which sends a new operator after Postgres and their role name when nothing is wrong with
# either. It is also the one invocation that provably needs no database.
#
# The suite runs from an empty directory with the environment pointed at a port nothing
# listens on, so a binary that still connects cannot accidentally succeed against whatever
# Postgres the developer happens to be running.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
BIN="${BIN:-$ROOT/build}"
W="$(mktemp -d)"; cd "$W"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# Point every libpq default at a closed port. Not a nonexistent host: DNS failure and
# connection-refused take different code paths, and refused is the one a developer with a
# live local Postgres would otherwise never hit.
export PGHOST=127.0.0.1 PGPORT=59999 PGDATABASE=nope PGUSER=nope PGCONNECT_TIMEOUT=2

echo "=== --help prints usage and never reaches the database ==="
found=0
for b in fastpki-ca fastpki-config fastpki-update fastpki-mesh fastpki-audit \
         fastpki-discover fastpki-notify; do
    [ -x "$BIN/$b" ] || continue
    found=$((found+1))
    out=$("$BIN/$b" --help 2>&1)
    chk "$b --help prints usage"        yes "$(printf '%s' "$out" | grep -qi '^ *usage' && echo yes || echo no)"
    # ⚠️ Match what a FAILED CONNECTION prints, not the word "postgres". The bare word is a
    # grep-proxy and it produced a false positive the moment a --help text legitimately
    # explained a Postgres behaviour (fastpki-mesh --triggers). The real signal is
    # libpq's own wording, measured:
    #   fastpki-config: postgres connect failed: connection to server at "127.0.0.1" ...
    # so `connect failed` and `connection to server` both fire on a genuine attempt, and
    # neither can appear in prose that is not describing an error.
    chk "$b --help never reaches the database" yes \
        "$(printf '%s' "$out" | grep -qiE 'connect failed|connection to server|could not connect|FATAL:|role .* does not exist' && echo no || echo yes)"
done
chk "found CLIs to check (the loop is not vacuous)" yes "$([ "$found" -ge 5 ] && echo yes || echo no)"
# ⚠️ ...and the pattern above must still FIRE on a real connection failure, or tightening it
# would have turned the check off rather than fixing it. Provoke one for real: the same
# unreachable PG* environment, a command that does touch the database.
REAL=$("$BIN/fastpki-config" --config /dev/null get X 2>&1)
chk "the pattern still detects a REAL connection failure" no \
    "$(printf '%s' "$REAL" | grep -qiE 'connect failed|connection to server|could not connect|FATAL:|role .* does not exist' && echo no || echo yes)"

echo "=== every subcommand a tool IMPLEMENTS is listed in its own --help ==="
# ⚠️ Why this exists. A command that works but is absent from --help is, to anyone who
# has not read the source, a command that does not exist. Reported on
# That fastpki-ca had "no disable" and proposed building it; it had been there all
# along, and he agreed to a plan to rebuild a feature that was already complete AND
# already tested. (My own error was `--help | head -20`, but an unlisted command is the
# same trap with no truncation needed.)
#
# The implemented set is read from the dispatch chain -- `cmd == "x"` -- so this compares
# the tool against ITSELF and cannot drift: add a subcommand without documenting it and
# this fails on the next run.
for src in "$ROOT"/src/tools/*.cpp; do
    tool="fastpki-$(basename "$src" .cpp)"
    [ -x "$BIN/$tool" ] || continue
    help=$("$BIN/$tool" --help 2>&1)
    # ⚠️ MATCH AS A WHOLE WORD, NOT A SUBSTRING. A bare `grep -q -- "$c"` counted a subcommand
    # as documented whenever a longer command name or a prose word contained it: for
    # fastpki-config `set` was satisfied by `unset <KEY>`, `list` by `templates-list`, `import`
    # by `templates-import`; for fastpki-ca `csr` by `sign-csr`. Delete the
    # `set <KEY> <VALUE>` line — the one subcommand every operator needs, and exactly the
    # "a command absent from --help does not exist" defect this file's header describes — and
    # this still passed. It also broke the stronger claim above that the check cannot drift: a
    # new `cmd == "sync"` was pre-satisfied by `p11-clients-sync`, so it could ship
    # undocumented.
    #
    # A hyphen counts as a word character here, which is what separates `csr` from `sign-csr`.
    # The three help shapes in this tree put the subcommand at line start (`  list …`), after
    # a pipe (`enable <id> | disable <id>`) and mid-invocation
    # (`fastpki-audit --config <f> verify`), so this cannot be anchored to the line. Padding
    # both ends gives a word at either edge a non-word neighbour WITHOUT `(^|…)` — BSD grep
    # does not treat `^` as an anchor inside a parenthesised alternation, so that form matches
    # nothing at all on a developer's machine while looking correct.
    padded=$(printf '%s' "$help" | sed -e 's/^/ /' -e 's/$/ /')
    missing=""
    # Only real subcommands: skip the flags and the help aliases themselves.
    for c in $(grep -oE 'cmd == "[a-z][a-z0-9-]*"' "$src" | sed 's/.*"\(.*\)"/\1/' | sort -u); do
        case "$c" in help|h) continue ;; esac
        printf '%s' "$padded" | grep -qE "[^A-Za-z0-9_-]${c}[^A-Za-z0-9_-]" \
            || missing="$missing $c"
    done
    chk "$tool: every implemented subcommand appears in --help" "" "$missing"
done

echo "=== a config file that exists but cannot be read is an error, not an empty config ==="
# Treated as absent, it left a native node running on built-in defaults with no error: no
# DATACENTER_ID, the console on 8090, PKI_DNS pki.example.org. An absent file stays
# optional. Needs a user the file's mode can actually keep out, and root is never kept out,
# so as root the check runs as the image's `fastpki` user.
printf 'PKI_DNS=unreadable.example\n' > "$W/locked.conf"; chmod 000 "$W/locked.conf"
chmod 711 "$W"
as_other=""
if [ "$(id -u)" -ne 0 ]; then as_other=self
elif id fastpki >/dev/null 2>&1; then as_other=fastpki; fi
if [ -n "$as_other" ]; then
    for b in fastpki-config fastpki-ca; do
        if [ "$as_other" = self ]; then
            out=$("$BIN/$b" --config "$W/locked.conf" list 2>&1); rc=$?
        else
            out=$(su -s /bin/sh fastpki -c "PGHOST=$PGHOST PGPORT=$PGPORT PGCONNECT_TIMEOUT=2 '$BIN/$b' --config '$W/locked.conf' list" 2>&1); rc=$?
        fi
        chk "$b refuses an unreadable --config" yes \
            "$([ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "cannot read $W/locked.conf" && echo yes || echo no)"
    done
    out=$("$BIN/fastpki-config" --config "$W/absent.conf" list 2>&1)
    chk "  and an absent one is still optional" no \
        "$(printf '%s' "$out" | grep -q 'cannot read' && echo yes || echo no)"
else
    echo "  [SKIP] running as root with no fastpki user to test as"
fi

echo
echo "=== CLI HELP: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
