#!/usr/bin/env bash
# Concurrent enrolment: many clients at once, and more than one SERVER at once.
#
# ── The gap this closes ──────────────────────────────────────────────────────────────
#
# `cmp_concurrent.sh` already drives N simultaneous CMP clients, and it earned its place —
# it found one `OSSL_CMP_SRV_CTX` serialized per MESSAGE rather than per TRANSACTION. But
# it was the ONLY concurrency suite in the tree, it covers one protocol, and every client
# it starts talks to a single server process. Two things were therefore never exercised:
#
#   1. any protocol other than CMP under simultaneous load, and
#   2. two server PROCESSES issuing from the same CA against the same database — which is
#      not an exotic case but the ordinary HA deployment: several nodes, one Postgres.
#
# ⚠️ THE INVARIANT IS "NOTHING IS LOST", NOT "NOTHING COLLIDES". `certs.serial` is a
# PRIMARY KEY (sql/createdb.sql), so two identical serials can never both be stored — the
# second INSERT is REJECTED. A collision therefore does not appear as a duplicate row. It
# appears as a certificate the CA signed, spent a serial on, handed to a client, and then
# failed to record: the client trusts a certificate the CA cannot revoke, because the CA
# has no row for it. Counting ROWS is what detects that. Counting DISTINCT serials would
# report a perfectly healthy database in exactly that case, which is why both are asserted
# and why the row count is the one that matters.
#
# ⚠️ A SHARED CA KEY LIVES IN A TOKEN, and both servers sign through the same p11-kit
# session. That is deliberate: the PKCS#11 stack is the component most likely to serialise
# badly or deadlock under parallel signing, and nothing else in the tree signs from two
# processes at once. SUITE_TIMEOUT reports a deadlock as a hang rather than a pass.
#
# N defaults to the machine's core count because the point is to have requests genuinely
# in flight together rather than merely interleaved. It is clamped to [4,16]: below 4 the
# test proves little, and above 16 the suite spends its time in RSA keygen rather than in
# the CA. CONC_N overrides it.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
BIN="${BIN:-$ROOT/build/fastpki-est}"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF

W="$(mktemp -d)"; cd "$W"
PORT_A=18510; PORT_B=18511
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
        else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

# ── how many at once ────────────────────────────────────────────────────────────────
# Three probes, because the shipped image is busybox+musl and a developer's box is not:
# `nproc` is the common one, `getconf` is POSIX, /proc/cpuinfo is the fallback that needs
# no tool at all. Anything non-numeric falls to 4 rather than to an empty N, which would
# make `seq 1 $N` produce nothing and every count below compare 0 against 0.
N="${CONC_N:-}"
if [ -z "$N" ]; then
    N=$(nproc 2>/dev/null || true)
    [ -z "$N" ] && N=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
    [ -z "$N" ] && N=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || true)
fi
case "$N" in ''|*[!0-9]*) N=4 ;; esac
[ "$N" -lt 4 ]  && N=4
[ "$N" -gt 16 ] && N=16
echo "=== concurrency N=$N (cores: $(nproc 2>/dev/null || echo '?')) ==="
# ⚠️ ANTI-VACUITY: with N<2 nothing below is a concurrency test at all, and every count
# would still line up and print green.
chk "PRECONDITION: N is genuinely concurrent (>=2)" yes "$([ "$N" -ge 2 ] && echo yes || echo no)"

ca_in_token ca.pem "/CN=Concurrent CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

pg_setup concurrent_enrol
trap 'pg_cleanup' EXIT
printf "internal\n" > domains.txt
seed_domains "$W/domains.txt"
seed_web_user tester secret requester

mkconf() {   # <file> <port>
    cat > "$1" <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
EST_BIND=127.0.0.1
EST_PORT=$2
AUTH_BACKEND=local
CERT_VALIDITY_DAYS=365
LOG_LEVEL=info
EOF
}
mkconf a.conf "$PORT_A"
mkconf b.conf "$PORT_B"
seed_ca_from_conf a.conf   # one CA row; b.conf names the same SIGNING_CA_ID

"$BIN" --config "$W/a.conf" > "$W/a.log" 2>&1 & PA=$!
"$BIN" --config "$W/b.conf" > "$W/b.log" 2>&1 & PB=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "$W/a.conf" EST_PORT "$PA" || true
# ⚠️ The final EXIT trap must be a superset of every earlier one (tests/trap_cleanup.sh):
# bash REPLACES traps rather than stacking them, so this repeats pg_cleanup.
trap 'pg_cleanup; kill $PA $PB 2>/dev/null' EXIT
chk "PRECONDITION: both servers are up" yes \
    "$(kill -0 $PA 2>/dev/null && kill -0 $PB 2>/dev/null && echo yes || echo no)"

# ── one enrolment, so a failure below means CONCURRENCY and not "EST is broken" ──────
#
# ⚠️ KEYGEN IS SPLIT OUT FROM THE REQUEST, AND THAT IS THE WHOLE POINT. Generating an
# RSA-2048 key takes far longer than the enrolment it precedes, so a worker that does
# `genpkey` and then POSTs spends almost all of its life in keygen and hits the server at
# a moment of its own choosing. N such workers do NOT put N requests in flight together —
# they arrive smeared out, the server handles them one after another, and the suite proves
# nothing while printing green. So every key and CSR is minted UP FRONT, and the workers
# then block on a start gate so the POSTs are released at once.
prep() {    # <cn> <out-prefix>
    "$OSSL" req -new -newkey rsa:2048 -nodes -keyout "$2.key" -subj "/CN=$1" \
        -out "$2.csr" >/dev/null 2>&1
    "$OSSL" req -in "$2.csr" -outform DER 2>/dev/null | "$OSSL" base64 > "$2.b64"
}
fire() {    # <port> <out-prefix>  -- writes <prefix>.pem when it succeeds
    # The gate: spin until it opens. `sleep 0` keeps this from being a tight CPU spin that
    # would itself starve the very requests being measured.
    while [ ! -f "$W/GO" ]; do sleep 0.05; done
    curl -sk -u tester:secret --data-binary "@$2.b64" -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$1/.well-known/est/ca/simpleenroll" > "$2.resp" 2>/dev/null
    [ -s "$2.resp" ] || return 1
    "$OSSL" base64 -d -A < "$2.resp" 2>/dev/null \
        | "$OSSL" pkcs7 -inform DER -print_certs -out "$2.pem" 2>/dev/null
    [ -s "$2.pem" ]
}
enrol() {   # <port> <cn> <out-prefix>  -- the serial form, for the baseline
    prep "$2" "$3"; : > "$W/GO"; fire "$1" "$3"
}
serial_of() { "$OSSL" x509 -in "$1" -noout -serial 2>/dev/null | sed 's/serial=//' \
              | tr 'A-F' 'a-f' | sed 's/^0*//'; }

echo "=== a lone enrolment works (the baseline) ==="
enrol "$PORT_A" solo.internal solo || true
chk "one client, one certificate" yes "$([ -s solo.pem ] && echo yes || echo no)"
chk "  and the CA recorded it" 1 \
    "$(pg_exec "select count(*) from certs where serial='$(serial_of solo.pem)';" 2>/dev/null | tr -d ' ')"

# ── phase 1: N clients, ONE server ──────────────────────────────────────────────────
echo "=== $N clients at once against ONE server ==="
for i in $(seq 1 "$N"); do prep "a$i.internal" "a$i"; done
rm -f "$W/GO"; PIDS=""
for i in $(seq 1 "$N"); do ( fire "$PORT_A" "a$i" ) & PIDS="$PIDS $!"; done
sleep 0.5; : > "$W/GO"          # every worker is parked on the gate; open it
for p in $PIDS; do wait "$p" 2>/dev/null; done
GOT_A=$(ls a[0-9]*.pem 2>/dev/null | wc -l | tr -d ' ')
chk "every client got a certificate" "$N" "$GOT_A"

# ── phase 2: N clients split across TWO server processes, one CA, one database ──────
echo "=== $N clients at once across TWO server processes ==="
for i in $(seq 1 "$N"); do prep "b$i.internal" "b$i"; done
rm -f "$W/GO"; PIDS=""
for i in $(seq 1 "$N"); do
    if [ $((i % 2)) -eq 0 ]; then P=$PORT_A; else P=$PORT_B; fi
    ( fire "$P" "b$i" ) & PIDS="$PIDS $!"
done
sleep 0.5; : > "$W/GO"
for p in $PIDS; do wait "$p" 2>/dev/null; done
GOT_B=$(ls b[0-9]*.pem 2>/dev/null | wc -l | tr -d ' ')
chk "every client got a certificate" "$N" "$GOT_B"
# Prove BOTH processes actually issued. Splitting round-robin and then having one server
# answer everything would pass every count above while testing nothing cross-process.
chk "  and both processes served some of them" yes \
    "$(if grep -qE 'issued|simpleenroll' a.log 2>/dev/null && \
          grep -qE 'issued|simpleenroll' b.log 2>/dev/null; then echo yes; else echo no; fi)"

# ── what the CA actually kept ───────────────────────────────────────────────────────
echo "=== the database agrees with the clients ==="
EXPECT=$((1 + GOT_A + GOT_B))     # the solo one, plus both phases
ROWS=$(pg_exec "select count(*) from certs where owner='tester';" 2>/dev/null | tr -d ' ')
# ⚠️ THE ROW COUNT IS THE LOAD-BEARING ASSERTION -- see the header. A signed certificate
# with no row is one the CA can neither list nor revoke.
chk "every certificate a client holds has a row" "$EXPECT" "${ROWS:-none}"
UNIQ=$(pg_exec "select count(distinct serial) from certs where owner='tester';" 2>/dev/null | tr -d ' ')
chk "  and every stored serial is distinct" "$ROWS" "${UNIQ:-none}"

# Client-side distinctness too: the DB cannot show two clients handed the SAME certificate,
# because that is one row and looks correct from inside Postgres.
if [ "$((GOT_A + GOT_B))" -gt 0 ]; then
    CU=$(for f in a[0-9]*.pem b[0-9]*.pem; do [ -s "$f" ] && serial_of "$f"; done | sort -u | wc -l | tr -d ' ')
    chk "no two clients were handed the same certificate" "$((GOT_A + GOT_B))" "$CU"
else
    echo "  [n/a]  client-side distinctness — nothing reached a client"
    fail=$((fail+1))
fi

chk "no certificate was left non-valid" 0 \
    "$(pg_exec "select count(*) from certs where owner='tester' and status<>0;" 2>/dev/null | tr -d ' ')"
# A crash under load is the other way this fails, and a dead server would otherwise be
# invisible: the counts above would simply be short.
chk "both servers survived" yes \
    "$(kill -0 $PA 2>/dev/null && kill -0 $PB 2>/dev/null && echo yes || echo no)"

echo
echo "=== CONCURRENT ENROL: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
