#!/usr/bin/env bash
# PG_CONNINFO is a BOOTSTRAP key — the deployment environment outranks the tracked
# config file. This pins both halves of that rule, because only one of them was true.
#
# ── Why this exists ──────────────────────────────────────────────────────────────
#
# `deploy/bootstrap.compose.conf` is tracked and shipped, and used to carry a dev-default
# password. The compose environment carries the REAL generated one. The file was read
# after the environment and overwrote it, so a real deployment used the dev password.
# The fix skipped bootstrap keys when reading the file.
#
# Skipping them UNCONDITIONALLY goes one step too far, and the step is a silent one. A
# single-node install that sets PG_CONNINFO only in `bootstrap.conf` — which is what
# docs/deployment.md documents — then has its own setting discarded. It does not fail: libpq
# falls back to the PG* environment variables and connects to whatever `PGDATABASE`
# happens to be, with nothing in any log to say the configured value was dropped.
#
# The test harness is exactly that shape (PG_CONNINFO in the file, never exported), which
# is how this surfaced: multi-database suites had their servers quietly talk to the wrong
# database, and the failure looked like a profile-resolution bug three layers away.
#
# So: the environment wins WHEN IT IS SET, and the file is honoured when it is not.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# Two databases. A CA is registered in the FIRST; the second is left empty. Which one a
# binary lists CAs from is the whole question, and it cannot be faked by a status code.
pg_setup cfgboot_a; CONN_A="$PG_CONNINFO"; DB_A="$PGDATABASE"
pg_setup cfgboot_b; CONN_B="$PG_CONNINFO"; DB_B="$PGDATABASE"
trap 'PGDATABASE=$DB_A pg_cleanup; PGDATABASE=$DB_B pg_cleanup' EXIT

"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout a.key -out a.pem -days 3650 \
    -subj "/CN=Bootstrap Key CA" -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
PGDATABASE=$DB_A PG_CONNINFO=$CONN_A pg_seed_ca_row only-in-a a.pem "" true >/dev/null

CA="$ROOT/build/fastpki-ca"
lists(){ # <conf> [env-conninfo] -> the CA ids the binary sees
    if [ -n "${2:-}" ]; then PG_CONNINFO="$2" "$CA" --config "$1" list 2>/dev/null | awk '{print $1}' | tr '\n' ' '
    else "$CA" --config "$1" list 2>/dev/null | awk '{print $1}' | tr '\n' ' '; fi
}

printf 'PG_CONNINFO=%s\nLOG_LEVEL=err\n' "$CONN_A" > a.conf
printf 'PG_CONNINFO=%s\nLOG_LEVEL=err\n' "$CONN_B" > b.conf

echo "=== 1. with NO environment override, the config FILE is honoured ==="
# The regression: this silently read database B (or wherever PG* pointed) and reported an
# empty CA list, which reads exactly like "no CAs are registered".
chk "a.conf sees the CA that lives in A" "only-in-a " "$(env -u PG_CONNINFO bash -c "$(declare -f lists); CA=$CA; lists a.conf")"
chk "b.conf sees nothing (B is empty)"   ""           "$(env -u PG_CONNINFO bash -c "$(declare -f lists); CA=$CA; lists b.conf")"

echo "=== 2. when the environment SETS it, the environment wins ==="
# This is the actual fix and it must stay true: a tracked file carrying a dev default
# must never override the deployment's real value.
chk "env B beats file A" ""           "$(lists a.conf "$CONN_B")"
chk "env A beats file B" "only-in-a " "$(lists b.conf "$CONN_A")"

echo "=== 3. an EMPTY environment value is not a value ==="
# An exported-but-empty variable is the shape a shell leaves behind after `VAR=`; treating
# it as "the environment has spoken" would discard the file for no reason.
chk "empty env falls back to the file" "only-in-a " "$(PG_CONNINFO="" "$CA" --config a.conf list 2>/dev/null | awk '{print $1}' | tr '\n' ' ')"

echo
echo "=== CONFIG BOOTSTRAP KEYS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
