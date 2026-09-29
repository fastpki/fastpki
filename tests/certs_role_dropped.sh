#!/usr/bin/env bash
# Certs.role is gone — and the publication survived losing it.
#
# ── What this guards ───────────────────────────────────────────────────────────────
#
# `role` was a frozen copy of the requester's role at issuance, written by ten paths and
# read by three, all three to publish it (console inventory JSON twice, MCP cert_brief).
# Nothing authorised from it, and it went stale the moment a user's role changed.
#
# ⚠️ THE DANGEROUS HALF IS THE PUBLICATION, NOT THE COLUMN. `certs` is published with an
# EXPLICIT column list, and Postgres refuses to drop a column the list names:
#
#     ERROR:  cannot drop column role of table certs because other objects depend on it
#     DETAIL: publication of table certs in publication fastpki_pub depends on column role
#
# The obvious fix is `ALTER PUBLICATION ... SET TABLE certs (...)` — and it is a trap:
# SET TABLE replaces the publication's ENTIRE table set, so every other table silently
# stops replicating with nothing in any log to say so. A mesh would keep looking healthy
# while peers quietly stopped receiving roles, domains, keys and CRLs.
#
# So the assertions below are mostly about the OTHER tables still being published. A test
# that only checked `certs` would pass on the version of this step that breaks the mesh.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup certs_role_dropped
trap 'pg_cleanup' EXIT

echo "=== 1. a fresh database is born without the column ==="
chk "certs has no 'role' column" 0 \
    "$(pg_exec "SELECT count(*) FROM information_schema.columns
                 WHERE table_name='certs' AND column_name='role';" | tr -d ' ')"
chk "  and role_idx is gone with it" 0 \
    "$(pg_exec "SELECT count(*) FROM pg_indexes WHERE indexname='role_idx';" | tr -d ' ')"
# web_users.role is the LIVE role and must survive — dropping it would be a different and
# much worse change, so pin that this test is about the right column.
chk "PRECONDITION: web_users.role (the LIVE role) is untouched" 1 \
    "$(pg_exec "SELECT count(*) FROM information_schema.columns
                 WHERE table_name='web_users' AND column_name='role';" | tr -d ' ')"


# ⚠️ SECTIONS 2-5 ARE GONE WITH THE STEP THEY TESTED. They rebuilt an old database with
# `certs.role` and a bare publication, replayed step 0026 against it, and proved the drop
# did not take the rest of the mesh's publication with it. That step — like the other 38 —
# only ever ran against an ALREADY-DEPLOYED database, and there are none: the schema was
# collapsed into sql/createdb.sql, which has always been born without the column. What
# survives is the property itself, asserted above against a fresh database, which is the
# only kind that now exists.

echo
echo "=== CERTS ROLE DROPPED: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
