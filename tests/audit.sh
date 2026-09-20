#!/usr/bin/env bash
# Tamper-evident audit log:
#   - fastpki-audit append builds a hash-chained log; verify reports PASS
#   - content tamper (UPDATE a row) -> verify FAILs at that seq
#   - row deletion (gap) -> verify FAILs with a sequence gap
#   - export emits one JSON line per row
#   - EST issuance writes a 'cert_issued' audit entry (real producer)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
# Only adopt the system openssl.cnf where it really is one. On macOS this path is a
# stub that defines no providers, and exporting it breaks every pkcs11 load — the
# CA key then cannot be minted and the suite SKIPs for a reason that looks nothing
# like "wrong openssl.cnf". Tests must not assume a Linux layout (§3d).
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; PORT=18450
AUDIT="$ROOT/build/fastpki-audit"
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

pg_setup audit
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
LOG_LEVEL=err
EOF

echo "=== append a chain of events ==="
"$AUDIT" --config bootstrap.conf append auth         login        alice success "" "ip=10.0.0.1" >/dev/null
"$AUDIT" --config bootstrap.conf append pki_lifecycle cert_issued  alice success "ABCD" "cn=host1" >/dev/null
"$AUDIT" --config bootstrap.conf append pki_lifecycle cert_revoked bob   success "ABCD" "reason=keyCompromise" >/dev/null
"$AUDIT" --config bootstrap.conf append auth         login_fail   eve   failure "" "bad password" >/dev/null
N=$(pg_exec "SELECT COUNT(*) FROM audit_log;")
chk "4 entries appended" 4 "$N"

echo "=== verify intact chain ==="
"$AUDIT" --config bootstrap.conf verify; rc=$?
chk "verify exit 0 on intact chain" 0 "$rc"

echo "=== export -> JSON lines ==="
EXPN=$("$AUDIT" --config bootstrap.conf export | grep -c '"seq":')
chk "export emits 4 JSON lines" 4 "$EXPN"
# first entry must chain to the genesis hash (64 zeros)
GEN=$("$AUDIT" --config bootstrap.conf export | head -1 | grep -o '"prev_hash":"0*"' | grep -o '0*' | head -1)
chk "first entry prev_hash is genesis (64 zeros)" "$(printf '0%.0s' $(seq 64))" "$GEN"

echo "=== content tamper detection ==="
pg_exec "UPDATE audit_log SET detail='HACKED' WHERE seq=2;"
OUT=$("$AUDIT" --config bootstrap.conf verify); rc=$?
chk "verify exit 1 after tamper" 1 "$rc"
echo "$OUT" | grep -q "seq 2" && a=yes || a=no
chk "failure pinpoints seq 2" yes "$a"

echo "=== gap (deletion) detection ==="
# restore the tampered row's detail, then delete a middle row to create a gap
pg_exec "UPDATE audit_log SET detail='cn=host1' WHERE seq=2;"
pg_exec "DELETE FROM audit_log WHERE seq=3;"
OUT=$("$AUDIT" --config bootstrap.conf verify); rc=$?
chk "verify exit 1 after deletion" 1 "$rc"
echo "$OUT" | grep -qi "gap\|link" && a=yes || a=no
chk "deletion reported as gap/broken link" yes "$a"

echo "=== EST issuance is audited (real producer) ==="
ca_in_token ca.pem "/CN=Audit CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3650 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup audit2
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
seed_web_user tester s3cret requester
cat > est.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$PORT
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
seed_ca_from_conf est.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-est" --config est.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
"$OSSL" req -new -subj "/CN=host.internal" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr >/dev/null 2>&1
"$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
curl -sk -u tester:s3cret --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
    "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll" >/dev/null
sleep 1
AN=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='cert_issued';")
chk "EST issuance wrote a cert_issued audit row" 1 "$AN"
# and that emitted chain verifies
cat > est-audit.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
LOG_LEVEL=err
EOF
"$AUDIT" --config est-audit.conf verify >/dev/null; rc=$?
chk "EST-emitted audit chain verifies" 0 "$rc"

echo "=== signed checkpoint ==="
# Reuse the CA created above; a fresh, intact chain to sign + anchor.
pg_setup audit3
cat > ck.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
LOG_LEVEL=err
EOF
seed_ca_from_conf ck.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$AUDIT" --config ck.conf append auth login alice success >/dev/null
"$AUDIT" --config ck.conf append pki_lifecycle cert_issued alice success >/dev/null
"$AUDIT" --config ck.conf append auth login bob success >/dev/null
"$AUDIT" --config ck.conf --ca ca sign >/dev/null; rc=$?
chk "sign checkpoint exit 0" 0 "$rc"
OUT=$("$AUDIT" --config ck.conf --ca ca verify); rc=$?
chk "verify with valid checkpoint exit 0" 0 "$rc"
echo "$OUT" | grep -q "checkpoint OK" && a=yes || a=no
chk "checkpoint reported OK" yes "$a"
# tail-truncate (drop the newest row) — the hash chain alone can't catch this,
# but the signed checkpoint must.
pg_exec "DELETE FROM audit_log WHERE seq=(SELECT MAX(seq) FROM audit_log);"
OUT=$("$AUDIT" --config ck.conf --ca ca verify); rc=$?
chk "verify after tail-truncation exit 1" 1 "$rc"
echo "$OUT" | grep -qi "truncat" && a=yes || a=no
chk "checkpoint detects tail truncation" yes "$a"
# corrupting the signature must also fail closed
pg_exec "DELETE FROM audit_log WHERE seq>2;" 2>/dev/null
pg_exec "UPDATE audit_checkpoints SET signature='00';"
OUT=$("$AUDIT" --config ck.conf --ca ca verify); rc=$?
echo "$OUT" | grep -qi "signature invalid" && a=yes || a=no
chk "bad checkpoint signature -> FAIL" yes "$a"

echo "=== signed compliance export ==="
pg_setup audit4
cat > ex.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
LOG_LEVEL=err
EOF
seed_ca_from_conf ex.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$AUDIT" --config ex.conf append auth login alice success >/dev/null
"$AUDIT" --config ex.conf append pki_lifecycle cert_issued alice success ABCD "cn=h1" >/dev/null
"$AUDIT" --config ex.conf append pki_lifecycle cert_revoked bob success ABCD "reason=1" >/dev/null
"$AUDIT" --config ex.conf --ca ca export-signed --out report.ndjson >/dev/null; rc=$?
chk "export-signed exit 0" 0 "$rc"
chk "export wrote the ndjson" yes "$([ -s report.ndjson ] && echo yes || echo no)"
chk "export wrote a detached .sig" yes "$([ -s report.ndjson.sig ] && echo yes || echo no)"
chk "export contains 3 rows" 3 "$(grep -c '"seq":' report.ndjson)"
"$AUDIT" --config ex.conf --ca ca verify-export --out report.ndjson >/dev/null; rc=$?
chk "verify-export exit 0 on intact export" 0 "$rc"
# Tamper with the exported bytes -> digest no longer matches the signed value.
sed -i.bak 's/alice/mallory/' report.ndjson && rm -f report.ndjson.bak
OUT=$("$AUDIT" --config ex.conf --ca ca verify-export --out report.ndjson); rc=$?
chk "verify-export exit 1 after byte tamper" 1 "$rc"
echo "$OUT" | grep -qi "digest mismatch" && a=yes || a=no
chk "tampered export fails closed (digest)" yes "$a"
# A forged signature over an intact file must also fail closed.
"$AUDIT" --config ex.conf --ca ca export-signed --out r2.ndjson >/dev/null
sed -i.bak 's/^signature=.*/signature=00/' r2.ndjson.sig && rm -f r2.ndjson.sig.bak
"$AUDIT" --config ex.conf --ca ca verify-export --out r2.ndjson >/dev/null 2>&1; rc=$?
chk "forged signature -> verify-export exit 1" 1 "$rc"
# --after exports only the tail range.
"$AUDIT" --config ex.conf --ca ca export-signed --after 2 --out tail.ndjson >/dev/null
chk "export --after 2 keeps only newer rows" 1 "$(grep -c '"seq":' tail.ndjson)"

echo "=== SIEM forwarding (RFC 5424) ==="
pg_setup audit5
cat > fw.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
LOG_LEVEL=err
EOF
"$AUDIT" --config fw.conf append auth login_fail eve failure "" "bad pw" >/dev/null
"$AUDIT" --config fw.conf append pki_lifecycle cert_issued alice success ABCD "cn=h" >/dev/null
FOUT=$("$AUDIT" --config fw.conf forward)
echo "$FOUT" | grep -q '^<84>1 ' && a=yes || a=no   # failure -> severity 4 -> PRI 84
chk "failure event -> syslog PRI 84 (warning)" yes "$a"
echo "$FOUT" | grep -q '^<86>1 ' && a=yes || a=no   # success -> severity 6 -> PRI 86
chk "success event -> syslog PRI 86 (info)" yes "$a"
echo "$FOUT" | grep -q 'fastpki@32473' && a=yes || a=no
chk "RFC 5424 structured data present" yes "$a"
chk "2 events forwarded" 2 "$(echo "$FOUT" | grep -c '^<')"
chk "--after skips older events" 1 "$("$AUDIT" --config fw.conf forward --after 1 | grep -c '^<')"
# ⚠️ THE LISTEN PORT IS POSITIONAL ON OpenBSD nc, WHERE -p IS THE *SOURCE* PORT. Written as
# `nc -u -l -p PORT` the listener never bound the port we then sent to, so the capture came
# up empty and the cell reported "inconclusive (nc variant)" -- a skip that reads like doubt
# about the product and was a wrong flag. BusyBox nc wants the -p form, so both are tried:
# whichever variant is present, one of them binds.
if command -v nc >/dev/null 2>&1; then
    UPORT=18614
    : > udp.txt
    nc -u -l "$UPORT" > udp.txt 2>/dev/null &
    NCP=$!; sleep 0.5
    if ! kill -0 "$NCP" 2>/dev/null; then           # this variant wants -p
        nc -u -l -p "$UPORT" > udp.txt 2>/dev/null &
        NCP=$!; sleep 0.5
    fi
    # ⚠️ AND THE PROTOCOL HAS TO BE UDP, WHICH IT WAS NOT. AUDIT_FORWARD_PROTO defaults to
    # tcp, and SyslogStream is a TCP/TLS transport -- so `--syslog host:port` opened a TCP
    # connection while this cell listened on a UDP socket. Nothing could ever arrive, and
    # "inconclusive (nc variant)" blamed the toolbox for a test that was watching the wrong
    # transport. udp_send() is a real, separate code path and this is the only thing that
    # covers it.
    { cat fw.conf; echo "AUDIT_FORWARD_PROTO=udp"; } > fwu.conf
    "$AUDIT" --config fwu.conf forward --syslog "127.0.0.1:$UPORT" >/dev/null 2>&1 || true
    sleep 0.5; kill "$NCP" 2>/dev/null
    # ⚠️ NO LONGER A SKIP. Tests run only in the production image, where nc is present and
    # one of the two spellings above binds -- so "nothing arrived" is a real finding about
    # the send path, not a fact about the host, and it fails.
    if grep -q 'fastpki@32473' udp.txt 2>/dev/null; then
        echo "  [PASS] syslog datagram delivered over UDP"; pass=$((pass+1))
    else
        echo "  [FAIL] no syslog datagram arrived over UDP"; fail=$((fail+1))
    fi
fi

echo
echo "=== AUDIT: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
