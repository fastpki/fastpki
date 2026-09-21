#!/usr/bin/env bash
# Per-node config from the environment (the deploy/.env approach).
# The docker-compose stack injects an untracked, per-node deploy/.env into every
# container's environment; the config loader (Config::from_env) must apply any key
# NOT present in the universal, git-tracked bootstrap.compose.conf. This proves it at the
# config layer: with the config file carrying NO DATACENTER_* keys, DATACENTER_ID supplied
# purely via the ENVIRONMENT governs issuance.
#
# ⚠️ THE ENV KEY IS THE ID, NOT THE BOUND. The node resolves that id to a serial
# prefix through its own `datacenters` row at startup, so this suite has to seed that row
# before the server starts — and it now proves the whole chain end to end: env id ->
# database row -> the top two octets of every serial minted. If the env id were ignored,
# the server would mint full-width random serials and the prefix would show up in roughly
# one issuance in 65536, not five out of five.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/json_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"   # macOS
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18268
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
lc(){ printf '%s' "$1" | tr 'A-Z' 'a-z'; }

DC=envnode                                   # this node's id, supplied ONLY via the env
PFX=4660                                     # its serial prefix, 0x1234
PFXHEX=1234                                  # ...as the serial's top two octets

ca_in_token ca.pem "/CN=Env Node CA" 5
printf "internal\nexample.org\n" > domains.txt
pg_setup deploy_env
seed_domains $W/domains.txt   # allowed_domains is the sole source
# ⚠️ BEFORE the server starts: it reads this row once, at startup, and a node whose
# DATACENTER_ID has no row refuses to issue rather than minting unprefixed.
pg_exec "INSERT INTO datacenters(dc_id, serial_prefix) VALUES('$DC', $PFX)
         ON CONFLICT (dc_id) DO UPDATE SET serial_prefix=EXCLUDED.serial_prefix;" >/dev/null
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
# NOTE: the config file deliberately has NO DATACENTER_* keys — the node's slice
# comes only from the environment (the deploy/.env mechanism).
cat > w.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
WEB_SELFSERVICE_IDENTITY_SUBJECT=false
LOG_LEVEL=err
EOF
seed_ca_from_conf w.conf   # register the CA (SIGNING_CA_* no longer seed it)
chk "config file carries NO DATACENTER_* (universal)" "" "$(grep -E '^DATACENTER_' w.conf || true)"

# Start fastpki-web with the per-node id ONLY in the environment.
DATACENTER_ID="$DC" "$WEB" --config w.conf >w.log 2>&1 & PID=$!
sleep 1; trap 'pg_cleanup; kill $PID 2>/dev/null' EXIT
if ! kill -0 $PID 2>/dev/null; then echo "web died:"; cat w.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -o /dev/null -X POST "$U/api/users" -d 'username=boss&password=bosspw12&role=admin'
curl -s -c b.cj -X POST "$U/api/login" -d 'username=boss&password=bosspw12' >/dev/null

# x509_serial_hex() strips leading zeros, so a prefix below 0x1000 comes back short.
# Left-pad to 40 before reading the top four characters — the same restoration the DB-side
# guard does with lpad(...,40,'0'), and the reason a prefixed serial must be 20 octets.
serial_prefix_of() {
    local v="$1"
    [ -n "$v" ] || return 1
    v=$(printf '%s' "$v" | tr 'A-F' 'a-f')
    while [ ${#v} -lt 40 ]; do v="0$v"; done
    printf '%s' "${v:0:4}"
}

issue(){ # CN -> echoes issued serial (lowercase)
  "$OSSL" req -new -newkey rsa:2048 -nodes -keyout /dev/null -subj "/CN=$1" -out csr.pem >/dev/null 2>&1
  local s; s=$(curl -s -b b.cj -X POST --data-binary @csr.pem "$U/api/certs/request?ca_instance=ca-global" \
        | { json_str "$(cat)" serial; })
  lc "$s"
}

echo "=== every serial carries the prefix the env-supplied id resolves to ==="
ok=yes; distinct=$(mktemp)
for i in 1 2 3 4 5; do
  S=$(issue "host$i.internal")
  echo "$S" >> "$distinct"
  got=$(serial_prefix_of "$S")
  [ "$got" = "$PFXHEX" ] || { ok=no; echo "    issuance $i serial=$S prefix=$got, want $PFXHEX"; }
done
chk "5/5 issued serials carry prefix $PFXHEX" yes "$ok"
chk "serials are distinct (no PK collision)" 5 "$(sort -u "$distinct" | grep -c .)"
# And the DB agrees: every persisted serial this node minted carries the prefix.
#
# ⚠️ Scoped to `NOT is_ca`, and that scope is still right even though the app now
# prefix a CA certificate too. This CA was created by the test harness BEFORE the
# `datacenters` row existed, so it legitimately has no prefix — exactly like an imported
# CA or one signed by an offline root, which is why the DB guard exempts is_ca. Sweeping
# it in would make this assertion permanently red, and a test nobody re-reads would not
# have flagged a genuine regression either.
OUT=$(pg_exec "SELECT lower(serial) FROM certs WHERE NOT is_ca;")
n=0; bad=0; for s in $OUT; do n=$((n+1)); [ "$(serial_prefix_of "$s")" = "$PFXHEX" ] || bad=$((bad+1)); done
chk "all $n persisted serials carry the prefix (end-to-end)" 0 "$bad"

echo '=== a node whose id has NO datacenters row must REFUSE to start ==='
# ⚠️ The whole reason this is fatal rather than a warning. Without the row the node does
# not know its prefix, so it would mint full-width random serials that can collide with a
# peer's — and the collision lands on the certs PRIMARY KEY, which stops that peer's
# replication apply worker for every published table, not just certs. The lab ran for
# months with this map empty on all three DCs and nothing in any log said so, which is
# exactly why the failure has to be loud and at startup.
kill $PID 2>/dev/null; wait $PID 2>/dev/null
DATACENTER_ID=ghostnode "$WEB" --config w.conf >ghost.log 2>&1 & G=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "w.conf" WEB_PORT "$G" || true
kill -0 $G 2>/dev/null && alive=yes || alive=no
kill $G 2>/dev/null; wait $G 2>/dev/null
chk "an id with no row does not come up" no "$alive"
# And for the RIGHT reason: a server that died of a typo'd conninfo would also read "no".
chk "  and the log names the missing row" yes \
    "$(grep -q 'no row in .datacenters.' ghost.log && echo yes || echo no)"
chk "  and it names the command that fixes it" yes \
    "$(grep -q 'fastpki-mesh --map' ghost.log && echo yes || echo no)"
# The positive control. Without it this proves only that the binary can fail to start:
# give the SAME id a row and it must come up.
pg_exec "INSERT INTO datacenters(dc_id, serial_prefix) VALUES('ghostnode', 777)
         ON CONFLICT (dc_id) DO NOTHING;" >/dev/null
DATACENTER_ID=ghostnode "$WEB" --config w.conf >ghost2.log 2>&1 & G2=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "w.conf" WEB_PORT "$G2" || true
kill -0 $G2 2>/dev/null && alive2=yes || alive2=no
kill $G2 2>/dev/null; wait $G2 2>/dev/null
chk "  while the same id WITH a row starts normally" yes "$alive2"

echo "=== the compose .env is DATA, not a shell script ==="
# ⚠️ MEASURED ON A DC. `docker compose` accepts an unquoted value containing spaces —
# `PG_CONNINFO=host=db port=5432 sslmode=verify-full` is an ordinary line in that file. A script that does
# `. .env` reads the same line as an assignment followed by the COMMAND `email`, and dies
# before doing any work. That is exactly what happened: lab-test.sh exited on
# "email: command not found", the in-image tier ran nothing at all, and the gate compared an
# empty summary against "0" and reported a bare mismatch.
#
# So: no deploy script may EXECUTE that file, and the one value lab-test.sh wants must
# survive a realistic .env. Both halves are asserted, because the grep alone would pass on a
# script that had simply stopped reading .env at all.
LT="$ROOT/deploy/lab-test.sh"
chk "lab-test.sh does not source the compose .env" no \
    "$(grep -qE '^\s*\.\s+"\$HERE/\.env"' "$LT" && echo yes || echo no)"

E="$(mktemp -d)"; trap 'pg_cleanup; kill ${PID:-} 2>/dev/null; rm -rf "$E"' EXIT
printf 'FASTPKI_IMAGE=reg.example:5000/fastpki:latest\nPG_CONNINFO=host=db port=5432 sslmode=verify-full\nPKI_DNS=host.example\n' > "$E/.env"
GOT="$(sed -n 's/^[[:space:]]*FASTPKI_IMAGE=//p' "$E/.env" | head -1)"
chk "  the image is read from a .env with a spaced value" "reg.example:5000/fastpki:latest" "$GOT"
# Anti-vacuity: prove the shell really would have choked on that same file, so the assertion
# above is measuring the difference and not just a sed that always works.
# ⚠️ ANTI-VACUITY WITHOUT ASSERTING SHELL BEHAVIOUR. The first version of this ran the
# fixture through `. file` and required the shell to die. That is not portable: whether a
# command-not-found inside a sourced file aborts the caller depends on the shell and on
# `set -e` semantics, so it passed on one platform and failed on another while the product
# was identical. Assert the property that MAKES the file hostile to `.` instead — a value
# containing whitespace — which is the same on every platform.
chk "  fixture: the .env really holds a value with spaces" yes \
    "$(grep -qE '^[A-Z_][A-Z0-9_]*=[^ ]+ +[^ ]' "$E/.env" && echo yes || echo no)"

echo
echo "=== DEPLOY ENV: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
