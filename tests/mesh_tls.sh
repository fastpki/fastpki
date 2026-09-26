#!/usr/bin/env bash
# fastpki-mesh must refuse to generate a mesh that ships credentials in cleartext.
#
# Inter-DC logical replication carries web_users — username, role AND the
# pbkdf2 password hash — and the subscription conninfo embeds the replication
# role's password. Found live on the 3-DC lab: `show ssl` = off, pg_stat_ssl for
# every replication connection = false, and no topology conninfo named sslmode, so
# all of that crossed the interconnect in the clear.
#
# The trap is libpq's default sslmode=`prefer`: it silently falls back to PLAINTEXT
# when the peer has ssl=off, so "replication works" is NOT evidence of encryption.
# `require` encrypts but does not authenticate the peer, so it does not stop an
# active MITM harvesting those credentials — only verify-ca/verify-full do.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MESH="$ROOT/build/fastpki-mesh"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

topo(){ printf 'dc1|host=10.0.0.1 dbname=pki user=r%s|1|http://dc1.example\ndc2|host=10.0.0.2 dbname=pki user=r%s|2|http://dc2.example\n' "$1" "$1" > "$W/t.txt"; }
# echo the exit status of a generate run
run(){ topo "$1"; shift; "$MESH" --topology "$W/t.txt" --node dc1 "$@" >"$W/out" 2>"$W/err"; echo $?; }
# NB: `grep -c` prints 0 AND exits 1 on no-match, so `|| echo 0` would emit "0\n0".
emitted(){ grep -c 'CREATE SUBSCRIPTION' "$W/out" 2>/dev/null | head -1; }

echo "=== SECURE BY DEFAULT: no sslmode named -> verify-full is injected ==="
# The operator must not have to remember. An unspecified sslmode means libpq's
# `prefer`, which downgrades silently, so fastpki-mesh supplies verify-full itself.
chk "absent sslmode accepted"                 0 "$(run " sslrootcert=/r.crt")"
chk "  ...DDL emitted"                        1 "$(emitted)"
# Twice: the conninfo is in the CREATE SUBSCRIPTION and in the ALTER ... CONNECTION that keeps
# an existing subscription on the topology's current connection.
chk "  ...conninfo carries sslmode=verify-full" 2 \
    "$(grep -c 'sslmode=verify-full' "$W/out" | head -1)"
chk "  ...never emits a bare/plaintext conninfo" 0 \
    "$(grep -cE 'sslmode=(disable|allow|prefer)' "$W/out" | head -1)"
chk "  ...the injection is announced on stderr" yes \
    "$(grep -qi 'defaulting to sslmode=verify-full' "$W/err" && echo yes || echo no)"
# The map DDL persists each conninfo into `datacenters`, so it must carry the
# same secured value — otherwise a node reading the map back would use a plaintext
# conninfo. Both DCs in the fixture must be secured, hence 2.
chk "--map conninfo is also secured (both DCs)" 2 \
    "$(topo " sslrootcert=/r.crt"; "$MESH" --topology "$W/t.txt" --map 2>/dev/null | grep -c 'sslmode=verify-full' | head -1)"

echo "=== an EXPLICIT downgrade is refused, not silently upgraded ==="
# Deliberately weaker settings are a decision, not an oversight — surface them.
chk "sslmode=disable rejected"       2 "$(run " sslmode=disable")"
chk "  ...and no DDL was emitted"    0 "$(emitted)"
chk "error names the credential risk" yes \
    "$(grep -qi 'password hash\|pbkdf2' "$W/err" && echo yes || echo no)"
chk "sslmode=allow rejected"         2 "$(run " sslmode=allow")"
# The subtle one: `prefer` LOOKS like TLS but silently downgrades.
chk "sslmode=prefer rejected (silently downgrades)" 2 "$(run " sslmode=prefer")"

echo "=== encrypted-but-unauthenticated is also refused, with a DIFFERENT reason ==="
chk "sslmode=require rejected"       2 "$(run " sslmode=require")"
chk "  ...error says it does not authenticate the server" yes \
    "$(grep -qi 'does NOT authenticate' "$W/err" && echo yes || echo no)"

echo "=== an explicit authenticated sslmode is honoured as given ==="
chk "sslmode=verify-full accepted"   0 "$(run " sslmode=verify-full sslrootcert=/r.crt")"
chk "  ...DDL emitted"               1 "$(emitted)"
chk "sslmode=verify-ca accepted"     0 "$(run " sslmode=verify-ca sslrootcert=/r.crt")"
chk "  ...verify-ca NOT overwritten by the default" 2 \
    "$(grep -c 'sslmode=verify-ca' "$W/out" | head -1)"
chk "case-insensitive (VERIFY-FULL)" 0 "$(run " sslmode=VERIFY-FULL sslrootcert=/r.crt")"

echo "=== verify-* without a trust anchor warns (fails confusingly at apply time) ==="
chk "missing sslrootcert warns" yes \
    "$(run "" >/dev/null; grep -qi 'no sslrootcert' "$W/err" && echo yes || echo no)"

echo "=== the closed-network override works, but is never silent ==="
chk "--allow-plaintext-transport proceeds" 0 "$(run "" --allow-plaintext-transport)"
chk "  ...DDL emitted"                     1 "$(emitted)"
chk "  ...but a WARNING is printed"        yes \
    "$(grep -qi 'WARNING' "$W/err" && echo yes || echo no)"

echo
echo "=== MESH TLS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
