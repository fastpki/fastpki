#!/usr/bin/env bash
# Every variable the demo READS must have something that WRITES it.
#
# This defect has landed twice in demo/pki-demo.sh. Both times the symptom was a step that
# skipped with a reason naming a cause the operator could not act on:
#
#   ACME_DNSSTUB  -> "build/dnsstub not built (cmake --build build)" on a tree where it WAS
#                    built; rebuilding changes nothing when the VARIABLE is what is empty.
#   ADB           -> the ACME leg's database, read and never assigned (see the note that
#                    still stands where it used to be).
#
# A skip is the demo saying "this host cannot do that". When the real cause is a missing
# assignment, the demo blames the host for the script's own gap -- and unlike a failure, a
# skip is not read as something to fix.
#
# THE RULE. A name is a finding when it is read, never assigned, not part of the target
# descriptor's contract, and not an environment variable -- AND every one of its reads
# either has no default or defaults to EMPTY. `${X:-}` is `set -u` protection, not a
# fallback: it turns "unset" into "empty" and the guard below into a coin toss.
# `${X:-$Y}` and `${X:-something}` are real fallbacks and are fine by construction.
#
# THE DESCRIPTOR CONTRACT IS DERIVED, NOT LISTED. demo/provision-target.sh writes the
# descriptor the demo sources, so the names it emits are read from that script. A
# hand-maintained allowlist here would become the place every new finding goes to be
# excused, and would drift from the writer the moment a key was added.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
PY=$(command -v python3 || true)
[ -n "$PY" ] || { echo "SKIP: python3 not available"; exit 0; }
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

scan(){   # <demo script> <provisioner> -> prints offending names, one per line
  "$PY" - "$1" "$2" <<'PYEOF'
import re, sys
import os
raw  = open(sys.argv[1]).read()
prov = open(sys.argv[2]).read()

# ⚠️ STRIP FULL-LINE COMMENTS BEFORE SCANNING. This file documents its own past findings
# by name -- the note where $ADB used to live still spells it -- so a scanner that reads
# prose reports the very bug the prose says was fixed. Prose is not a read.
demo = "\n".join("" if re.match(r'\s*#', ln) else ln for ln in raw.splitlines())

# ⚠️ A SOURCED FILE IS A WRITER. The demo sources helpers, and their assignments are as
# real as its own; without this the guard reports every helper-provided name. The list is
# read from the demo's own `source`/`.` lines rather than hardcoded.
sourced = ""
here = os.path.dirname(os.path.abspath(sys.argv[1]))
root = os.path.dirname(here)
for m in re.finditer(r'(?:^|\s)(?:source|\.)\s+"?([^"\s;]+)', demo):
    cand = m.group(1)
    cand = cand.replace('$ROOT', root).replace('${ROOT}', root)
    cand = cand.replace('$(dirname "$0")', here).replace('$SCRIPT_DIR', here)
    if '$' in cand: continue
    try: sourced += open(cand).read()
    except OSError: pass

# Names the descriptor supplies: exactly what the provisioner emits into it.
contract = set(re.findall(r'echo "([A-Z][A-Z0-9_]*)=', prov))

both = demo + "\n" + sourced
assigned  = set(re.findall(r'(?:^|[;\s(])([A-Z][A-Z0-9_]{2,})=', both, re.M))
assigned |= set(re.findall(r'(?:local|export|declare|readonly)\s+(?:-\w+\s+)?([A-Z][A-Z0-9_]{2,})', both))
assigned |= set(re.findall(r'for\s+([A-Z][A-Z0-9_]{2,})\s+in', both))
assigned |= set(re.findall(r'read\s+(?:-\w+\s+)*([A-Z][A-Z0-9_]{2,})', both))

ENV = {'PATH','HOME','PWD','SHELL','USER','TMPDIR','LANG','LC_ALL','OSTYPE','HOSTNAME',
       'RANDOM','UID','IFS','BASH_SOURCE','FUNCNAME','BASH_VERSION','SECONDS','PPID',
       'PGHOST','PGPORT','PGUSER','PGPASSWORD','PGDATABASE','OPENSSL_CONF','OPENSSL_LIBDIR',
       'LD_LIBRARY_PATH','DYLD_LIBRARY_PATH','SSL_CERT_FILE','REQUESTS_CA_BUNDLE','SUDO_USER'}

# Every read of every name, with the default it was given (None = no default given).
reads = {}
for m in re.finditer(r'\$\{([A-Z][A-Z0-9_]{2,})(:-([^}]*))?\}', demo):
    reads.setdefault(m.group(1), []).append(m.group(3) if m.group(2) else None)
for m in re.finditer(r'\$([A-Z][A-Z0-9_]{2,})\b', demo):
    reads.setdefault(m.group(1), []).append(None)

out = []
for name, defaults in sorted(reads.items()):
    if name in assigned or name in contract or name in ENV: continue
    if name.startswith('FASTPKI_') or name.startswith('DEMO_ONLY_'): continue
    # A real fallback anywhere makes the read safe; only empty/absent defaults are findings.
    if any(d for d in defaults): continue
    out.append(name)
print("\n".join(out))
PYEOF
}

echo "=== every variable the demo reads has a writer ==="
HITS=$(scan "$ROOT/demo/pki-demo.sh" "$ROOT/demo/provision-target.sh")
[ -n "$HITS" ] && printf '      %s\n' $HITS
chk "no variable is read with no writer and no real default" "" "$(printf '%s' "$HITS" | tr '\n' ' ' | sed 's/ *$//')"

# ⚠️ A CHECKER THAT CANNOT FAIL IS A DECORATION. Both controls run against synthetic
# copies, so they prove the scanner reacts to the defect rather than to this tree.
echo "=== positive controls ==="
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cp "$ROOT/demo/provision-target.sh" "$T/prov.sh"
{ cat "$ROOT/demo/pki-demo.sh"; echo 'echo "${TOTALLY_UNWRITTEN_THING:-}"'; } > "$T/planted.sh"
chk "  a planted unwritten name is caught" yes \
    "$(scan "$T/planted.sh" "$T/prov.sh" | grep -q TOTALLY_UNWRITTEN_THING && echo yes || echo no)"
{ cat "$ROOT/demo/pki-demo.sh"; echo 'echo "${ALSO_UNWRITTEN_THING:-$HOME}"'; } > "$T/withdefault.sh"
chk "  but one with a REAL default is not" no \
    "$(scan "$T/withdefault.sh" "$T/prov.sh" | grep -q ALSO_UNWRITTEN_THING && echo yes || echo no)"

echo
echo "=== DEMO VARS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
