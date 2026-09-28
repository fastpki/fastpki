#!/usr/bin/env bash
# mesh-join and the local accounts two data centers each set before they were joined.
#
# ⚠️ WHY THIS IS A TEST. Every installer seeds its own `admin` row, and an operator sets its
# password on each data center before the mesh exists. After mesh-join the two data centers
# still held DIFFERENT rows, each console accepting only its own password, while mesh-join
# reported one of them "in force everywhere". Two faults:
#   - the rows never converged: both were written before the mesh installed the triggers that
#     stamp `updated`, so both carried 0, and last-writer-wins on a tie keeps the local row;
#   - the report read data center 1 alone, found its own row there, and called it universal.
#
# Two throwaway Postgres clusters stand in for two data centers, joined by the real
# deploy/mesh-join.sh and the real fastpki-mesh. Only the way mesh-join REACHES a server is
# replaced (the na_* functions of deploy/node-access.sh), since there is no SSH or kubectl
# here; everything it does once it gets there is the product's. Asserted: both data centers
# end with one row per account, the row chosen is the one with a password set, an account
# whose password was set on more than one data center must be changed at the next sign-in,
# and the report says what each data center holds.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
MESH="$ROOT/build/fastpki-mesh"
export LC_ALL=C

PGBIN=""
if command -v pg_ctl >/dev/null 2>&1; then PGBIN="$(dirname "$(command -v pg_ctl)")"
else PGBIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)"; fi
if [ -z "$PGBIN" ] || [ ! -x "$PGBIN/initdb" ]; then
    echo "SKIP: Postgres server binaries (initdb/pg_ctl) not found"; exit 0
fi
[ -x "$MESH" ] || { echo "SKIP: fastpki-mesh not built"; exit 0; }
source "$ROOT/tests/pg_priv.sh"

W="$(mktemp -d)"; PA=${PA:-16564}; PB=${PB:-16565}
pg_own "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
q(){ "$PGBIN/psql" -X -h 127.0.0.1 -p "$1" -U postgres -d fastpki -tAq -v ON_ERROR_STOP=1 -c "$2" 2>&1; }
cleanup(){ pg_as "$PGBIN/pg_ctl" -D "$W/a" -m immediate stop >/dev/null 2>&1
           pg_as "$PGBIN/pg_ctl" -D "$W/b" -m immediate stop >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT

start_node(){ # <dir> <port>
    if ! pg_as "$PGBIN/initdb" -D "$1" -U postgres --auth=trust > "$W/initdb.log" 2>&1; then
        echo "FAIL: initdb could not create the cluster at $1"; sed 's/^/    initdb: /' "$W/initdb.log"; exit 1
    fi
    cat >> "$1/postgresql.conf" <<EOF
wal_level = logical
max_wal_senders = 10
max_replication_slots = 10
listen_addresses = '127.0.0.1'
port = $2
unix_socket_directories = '$1'
EOF
    pg_as "$PGBIN/pg_ctl" -D "$1" -l "$1/pg.log" start >/dev/null 2>&1
    local i; for i in $(seq 1 40); do "$PGBIN/pg_isready" -h 127.0.0.1 -p "$2" >/dev/null 2>&1 && break; sleep 0.5; done
    "$PGBIN/createdb" -h 127.0.0.1 -p "$2" -U postgres fastpki >/dev/null 2>&1
    "$PGBIN/psql" -X -h 127.0.0.1 -p "$2" -U postgres -d fastpki -c "CREATE ROLE fastpki LOGIN SUPERUSER REPLICATION" >/dev/null 2>&1
    "$PGBIN/psql" -X -h 127.0.0.1 -p "$2" -U postgres -d fastpki -f "$ROOT/sql/createdb.sql" >/dev/null 2>&1
}
echo "=== two data centers, each with its own accounts ==="
start_node "$W/a" "$PA"
start_node "$W/b" "$PB"
if ! "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PA" >/dev/null 2>&1 || ! "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PB" >/dev/null 2>&1; then
    echo "FAIL: the throwaway clusters did not start"; exit 1
fi

# The rows each installer and each operator wrote before the join. The hash values stand in
# for PBKDF2 hashes; only their equality matters here.
#   admin : a password set on BOTH data centers              -> data center 1's is kept, and
#                                                               must be changed at next sign-in
#   ops   : set on data center 2 only, seeded on data center 1 -> data center 2's is kept, as is
#   same  : one identical row on both                        -> nothing to choose
seed(){ q "$1" "INSERT INTO web_users(username, role, hash, must_reset, auth_provider)
                VALUES ('$2', 'admin', '$3', $4, 'local')
                ON CONFLICT (username) DO UPDATE SET hash = EXCLUDED.hash, must_reset = EXCLUDED.must_reset" >/dev/null; }
seed "$PA" admin hash-admin-dc1 0;  seed "$PB" admin hash-admin-dc2 0
seed "$PA" ops   hash-ops-seed1 1;  seed "$PB" ops   hash-ops-dc2   0
seed "$PA" same  hash-same      0;  seed "$PB" same  hash-same      0
chk "PRECONDITION: the two data centers hold different admin rows" no \
    "$([ "$(q "$PA" "select hash from web_users where username='admin'")" = "$(q "$PB" "select hash from web_users where username='admin'")" ] && echo yes || echo no)"

# mesh-join as shipped, with the part that reaches a server replaced: servers `fake:a` and
# `fake:b` are the two clusters above.
mkdir -p "$W/deploy"
cp "$ROOT/deploy/mesh-join.sh" "$W/deploy/"
cp "$ROOT/deploy/node-access.sh" "$W/deploy/node-access.sh"
cat >> "$W/deploy/node-access.sh" <<EOF

# ---- test stand-ins: reach two local clusters instead of servers ----
na_resolve() { NA_KIND=fake; case "\$1" in fake:a) NA_PORT=$PA NA_DC=1 ;; fake:b) NA_PORT=$PB NA_DC=2 ;; *) na_die "unknown server \$1" ;; esac; }
# mesh-join refuses a loopback database address, as it should for a real server, so each
# data center reports a documentation address and na_mesh turns it back into 127.0.0.1.
na_facts() {
    na_resolve "\$1"
    printf 'KIND=fake\nDCID=%s\nPKI_DNS=dc%s.example\nBIND=192.0.2.%s\nPORTS=%s\nPASSWORD=unused\nANCHOR=/nonexistent/ca.crt\n' "\$NA_DC" "\$NA_DC" "\$NA_DC" "\$NA_PORT"
}
na_sql() { na_resolve "\$1"; "$PGBIN/psql" -X -q -At -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "\$NA_PORT" -U fastpki -d fastpki; }
# The topology names verify-full and an anchor file; these clusters have no TLS, so both go
# and the link is declared plaintext. Everything else in it is mesh-join's.
na_mesh() {
    _s=\$1; shift; na_resolve "\$_s"
    _t=\$(mktemp); sed -e 's/ sslmode=verify-full//' -e 's/ sslrootcert=[^ |]*//' -e 's/host=192\.0\.2\.[0-9]*/host=127.0.0.1/' > "\$_t"
    "$MESH" --allow-plaintext-transport --topology "\$_t" "\$@"; _rc=\$?; rm -f "\$_t"; return \$_rc
}
# Each data center already has its issuing CA and database certificate: the CA steps are
# not what this test is about.
na_cli() {
    na_resolve "\$1"; shift
    case "\$*" in
        "fastpki-ca list") printf 'dc%s-sub\tactive\tintermediate\tx\tca_key=pkcs11:token=t;object=dc%s-sub\n' "\$NA_DC" "\$NA_DC" ;;
        *) : ;;
    esac
}
EOF
sh "$W/deploy/mesh-join.sh" fake:a fake:b > "$W/join.out" 2>&1
rc=$?
sed 's/^/    | /' "$W/join.out"
chk "mesh-join completes" 0 "$rc"

echo "=== every data center holds one row per account ==="
row(){ q "$1" "select hash || '|' || must_reset from web_users where username='$2'"; }
wait_same(){ local i; for i in $(seq 1 30); do [ "$(row "$PA" "$1")" = "$(row "$PB" "$1")" ] && return 0; sleep 1; done; return 1; }
wait_same admin; wait_same ops
chk "admin: both data centers hold the same row"          "$(row "$PA" admin)" "$(row "$PB" admin)"
chk "  and it is data center 1's, to be changed at the next sign-in" "hash-admin-dc1|1" "$(row "$PB" admin)"
chk "ops: both data centers hold the same row"            "$(row "$PA" ops)"   "$(row "$PB" ops)"
chk "  and it is the one with a password set (dc 2)"     "hash-ops-dc2|0"     "$(row "$PA" ops)"
chk "same: unchanged on both"                             "hash-same|0 hash-same|0" "$(row "$PA" same) $(row "$PB" same)"

echo "=== the report says what each data center holds ==="
chk "admin: reported as data center 1's password everywhere" yes \
    "$(grep -q "'admin': every data center now uses the password set on data center 1" "$W/join.out" && echo yes || echo no)"
chk "  and that a new one is asked for at the next sign-in" yes \
    "$(grep -A1 "'admin': every data center now uses" "$W/join.out" | grep -q 'asked to choose a new one' && echo yes || echo no)"
chk "ops: reported as data center 2's password everywhere" yes \
    "$(grep -q "'ops': every data center now uses the password set on data center 2; it works" "$W/join.out" && echo yes || echo no)"
chk "no account is reported as still differing"           0 "$(grep -c 'still a different row' "$W/join.out")"
chk "same: nothing to report"                             0 "$(grep -c "'same'" "$W/join.out")"
# The old wording claimed a row "in force everywhere" from one data center's view.
chk "nothing claims a row is in force everywhere"         0 "$(grep -c 'in force everywhere' "$W/join.out")"

echo "=== the forced change, made on data center 2, replicates and clears the flag ==="
q "$PB" "UPDATE web_users SET hash = 'hash-admin-later', must_reset = 0 WHERE username = 'admin'" >/dev/null
_i=0; while [ $_i -lt 30 ] && [ "$(row "$PA" admin)" != "hash-admin-later|0" ]; do sleep 1; _i=$((_i+1)); done
chk "a change on data center 2 reaches data center 1"     "hash-admin-later|0" "$(row "$PA" admin)"

echo
echo "=== MESH JOIN ACCOUNTS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
