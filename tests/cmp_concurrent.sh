#!/usr/bin/env bash
# CMP with more than one client at a time.
#
# ── What this found ──────────────────────────────────────────────────────────────
#
# `fastpki-cmp` holds ONE `OSSL_CMP_SRV_CTX` for the whole process and serializes
# access to it with a mutex held for the length of ONE MESSAGE. A CMP transaction is
# not one message: an enrolment is `ir` -> `ip`, then `certConf` -> `pkiConf`, and the
# SRV_CTX carries the transaction's state — including its transactionID — in between.
#
# So when a second client's `ir` arrives between the first client's `ir` and its
# `certConf`, it overwrites that state, and the first client's `certConf` is answered:
#
#     CMP error: transactionid unmatched:
#       expected = 72:81:8B:7D:11:A6:2E:4D:86:F0:75:EB:C8:15:6F:57
#       actual   = A7:F5:8F:FC:C9:48:F7:6E:59:9F:41:B4:A8:48:0C:AD
#
# Both clients then fail. Worse, both certificates were already issued and persisted
# **on-hold** (status 2) — a certConf is what makes them valid — so the CA has minted
# certificates that nobody holds and that will never become usable. Measured with 8
# concurrent clients: 8 issued, 8 stranded on-hold, 0 delivered.
#
# The source comments the constraint accurately and then does not meet it:
#
#     // The SRV_CTX carries per-transaction state and is NOT safe for
#     // concurrent use; serialize all request processing through it.
#
# Per-MESSAGE serialization is not per-TRANSACTION serialization.
#
# ── Why this test is shaped this way ─────────────────────────────────────────────
#
# Six clients rather than two. Two can pass by luck — if the first finishes entirely
# before the second starts, nothing overlaps and nothing is wrong. Six makes a full
# serialization vanishingly unlikely while keeping the run short, and the assertions
# are on the OUTCOME (every client got its certificate; no certificate was left
# on-hold), which is true whenever the server is correct and false whenever any two
# transactions interleaved.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; PORT=18461; N=6
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
        else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=CMP Concurrent CA" 3650
cp ca.pem root.pem
pg_setup cmp_concurrent
# CMP protects responses with a per-CA RA credential and has NO CA-key
# fallback, so this is required setup — without it every exchange below is a 503.
cmp_ra_setup ca.pem "$CA_KEY_URI" \
    || { echo "SKIP: could not provision the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
C=
trap 'pg_cleanup; kill $C 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt
cat > cmp.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
CMP_BIND=127.0.0.1
CMP_PORT=$PORT
CMP_PATH=/cmp
LOG_LEVEL=info
EOF
seed_ca_from_conf cmp.conf
# CMP PBM is PER USER — the global CMP_PBM_SECRET is gone. Every reference the
# client sends below needs its own `keys` row, or the server installs no secret and the
# MAC cannot verify. That is the point of the change: there is nothing to fall back to.
pg_exec "INSERT INTO keys(kid,protocol,key) VALUES('1234','cmp','0000') ON CONFLICT (kid,protocol) DO UPDATE SET key=EXCLUDED.key;" >/dev/null
# The credential needs an IDENTITY holding a profile grant, or
# resolve_profile refuses. seed_enrolling_identity leaves an existing role alone.
seed_enrolling_identity 1234
cmp_ra_conf_lines >> cmp.conf   # CMP_RA_CERT_ID_PREFIX + CMP_RA_KEY
"$ROOT/build/fastpki-cmp" --config cmp.conf > srv.log 2>&1 & C=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$C" || true
if ! kill -0 $C 2>/dev/null; then echo "fastpki-cmp died:"; cat srv.log; exit 1; fi

# One control run first. If the SEQUENTIAL case were broken this suite would be
# reporting something else entirely, and a negative result would prove nothing about
# concurrency (a refusal that fires for the wrong reason reads exactly like a pass).
echo "=== control: one client at a time works ==="
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out k0.key >/dev/null 2>&1
"$OSSL" cmp -cmd ir -server "http://127.0.0.1:$PORT/cmp/ca" -recipient "/CN=CMP Concurrent CA" \
    -trusted ca.pem -expect_sender "/CN=cmp-ra.test" -secret pass:0000 -ref 1234 \
    -newkey k0.key -subject "/CN=solo.internal" -certout solo.pem >solo.log 2>&1
chk "a lone enrolment gets its certificate" yes "$([ -s solo.pem ] && echo yes || echo no)"
SER=$("$OSSL" x509 -in solo.pem -noout -serial 2>/dev/null | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
chk "and it is valid, not on-hold" 0 "$(pg_exec "select status from certs where serial='$SER';" 2>/dev/null | tr -d ' ')"

echo "=== $N clients at the same time ==="
PIDS=""
for i in $(seq 1 $N); do "$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out k$i.key >/dev/null 2>&1; done
for i in $(seq 1 $N); do
    ( "$OSSL" cmp -cmd ir -server "http://127.0.0.1:$PORT/cmp/ca" -recipient "/CN=CMP Concurrent CA" \
        -trusted ca.pem -expect_sender "/CN=cmp-ra.test" -secret pass:0000 -ref 1234 \
        -newkey k$i.key -subject "/CN=h$i.internal" -certout leaf$i.pem >out$i.log 2>&1 ) &
    PIDS="$PIDS $!"
done
# Not a bare `wait`: that would also wait for the server, which never exits.
for p in $PIDS; do wait $p 2>/dev/null; done

GOT=$(ls leaf*.pem 2>/dev/null | wc -l | tr -d ' ')
chk "every client got its certificate" "$N" "$GOT"

# The sharper assertion. A cert issued and left on-hold is worse than a failed request:
# the CA has spent a serial and signed a certificate that no one holds and that nothing
# will ever confirm, and the client saw an error, so it will simply ask again.
HELD=$(pg_exec "select count(*) from certs where status=2;" 2>/dev/null | tr -d ' ')
chk "no certificate is stranded on-hold" 0 "${HELD:-none}"

# Name the mechanism, so a future failure says WHY rather than only that a count moved.
chk "no transaction-ID was answered with another client's" 0 \
    "$(grep -c 'transactionid unmatched' srv.log | tr -d ' ')"
chk "no message arrived on a foreign transaction state" 0 \
    "$(grep -c 'unexpected pkibody' srv.log | tr -d ' ')"

# Every issued certificate must be a distinct, valid one — a shared context could also
# hand the same certificate to two clients.
# Guarded on GOT: with nothing issued, "all distinct" is 0 == 0 and reads as a pass
# beside four failures, which is exactly the kind of assertion that makes a broken run
# look partly healthy.
if [ "$GOT" -gt 0 ]; then
    UNIQ=$(for f in leaf*.pem; do [ -s "$f" ] && "$OSSL" x509 -in "$f" -noout -serial; done | sort -u | wc -l | tr -d ' ')
    chk "the certificates are all distinct" "$GOT" "$UNIQ"
else
    echo "  [n/a]  distinctness — no certificate reached a client"
fi

echo
echo "=== CMP CONCURRENT: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
