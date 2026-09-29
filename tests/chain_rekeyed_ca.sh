#!/usr/bin/env bash
# The TLS chain a listener sends when its issuing CA has been REKEYED.
#
# ── Why this suite exists ────────────────────────────────────────────────────────
#
# build_issuer_chain() sends intermediates so a client that trusts only the ROOT can
# build a path — the WinHttp 12045 failure the chain builder was written to fix. Rekeying silently
# undid it, and nothing noticed for two reasons:
#
#   1. transport_cert_stable.sh says so itself: "Here the issuing CA IS the root
#      (self-signed) ... The multi-level case is asserted on the lab". By hand. So the
#      only automated chain assertion was the one case with nothing to send.
#   2. A rekeyed CA certificate is SELF-ISSUED (subject == issuer) but NOT self-signed —
#      it is certified by the CA's own previous key. Two places treated `subject ==
#      issuer` as "this is a root": the walk stopped there, and the is_root check broke
#      BEFORE appending, so a leaf issued by a rekeyed CA got an EMPTY chain.
#
# Nothing here needs an HSM: the point is chain ASSEMBLY, and file keys exercise it
# identically. That matters — the HSM suites skip on macOS, which is how a chain bug
# gets to be a lab-only discovery in the first place.
#
# ── The fixture is the shape that broke ──────────────────────────────────────────
#
#   root                     self-signed anchor, must NOT be sent (RFC 8446 4.4.2)
#    └─ sub (generation 1)   a normal intermediate, signed by root
#        └─ sub (generation 2)   SAME subject, new key, signed by generation 1
#            └─ leaf         the transport certificate the listener serves
#
# Generation 2 is what a rekey produces. A client anchored on root can only verify the
# leaf if BOTH generations are on the wire: gen2 bridges to gen1, gen1 bridges to root.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box —
# fall back to whatever is on PATH before giving up, or this suite is unrunnable
# anywhere the file is not at that exact location.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
[ -n "$OSSL" ] || { echo "FAIL: no openssl on PATH — set OSSL"; exit 1; }
W="$(mktemp -d)"; cd "$W"; PORT=18477
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

caext(){ printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n'; }
caext > ca.ext
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > leaf.ext

# root
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 3650 \
    -subj "/CN=Rekey Chain Root" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "subjectKeyIdentifier=hash" >/dev/null 2>&1
# sub generation 1 — a normal intermediate
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout sub1.key -out sub1.csr \
    -subj "/CN=Rekey Chain Sub CA" >/dev/null 2>&1
"$OSSL" x509 -req -in sub1.csr -CA root.pem -CAkey root.key -CAcreateserial -days 3000 \
    -extfile ca.ext -out sub1.pem >/dev/null 2>&1
# sub generation 2 — same subject, new key, certified by generation 1, hence subject ==
# issuer. The console's /renew has the parent sign a sub CA's renewal instead, but a
# self-issued generation is still a certificate the chain builder can be handed (an
# imported CA, or a root's bridge, which has exactly this shape).
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout sub2.key -out sub2.csr \
    -subj "/CN=Rekey Chain Sub CA" >/dev/null 2>&1
"$OSSL" x509 -req -in sub2.csr -CA sub1.pem -CAkey sub1.key -CAcreateserial -days 3000 \
    -extfile ca.ext -out sub2.pem >/dev/null 2>&1
# the transport leaf, issued by generation 2
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout ms.key -out ms.csr \
    -subj "/CN=localhost" >/dev/null 2>&1
"$OSSL" x509 -req -in ms.csr -CA sub2.pem -CAkey sub2.key -CAcreateserial -days 825 \
    -extfile leaf.ext -out ms.crt >/dev/null 2>&1

echo "=== 1. the fixture really is a rekeyed intermediate ==="
s=$("$OSSL" x509 -in sub2.pem -noout -subject | sed 's/subject=//')
i=$("$OSSL" x509 -in sub2.pem -noout -issuer  | sed 's/issuer=//')
chk "generation 2 is SELF-ISSUED (subject == issuer)" yes \
    "$([ "$s" = "$i" ] && echo yes || echo no)"
# ...and NOT self-signed: it does not verify against its own key. This is the whole
# distinction the product got wrong.
"$OSSL" verify -CAfile sub2.pem sub2.pem >/dev/null 2>&1 && ss=yes || ss=no
chk "but it is NOT self-signed"                        no  "$ss"
"$OSSL" verify -CAfile root.pem -untrusted sub1.pem -untrusted sub2.pem ms.crt >/dev/null 2>&1 \
    && v=yes || v=no
chk "leaf verifies to root when BOTH generations are supplied" yes "$v"

echo "=== 2. seed the CAs and start a listener serving the leaf ==="
pg_setup chain_rekeyed
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains "$W/domains.txt"
seed_web_user tester s3cret requester
pg_seed_ca_row root "$W/root.pem" "$W/root.key"
# BOTH generations under one id — `certs.id` is indexed, not unique, precisely so a
# rollover can keep two live certificates.
pg_seed_ca_row sub  "$W/sub1.pem" "$W/sub1.key"
pg_seed_ca_row sub  "$W/sub2.pem" "$W/sub2.key"

cat > bootstrap.conf <<EOF
PKI_DNS=localhost
ROOT_CA_PEM=$W/root.pem
MS_KEY=$W/ms.key
MS_CERT_ID=ms
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
MS_BIND=127.0.0.1
MS_PORT=$PORT
XCEP_PATH=/msxcep
WSTEP_PATH=/mswstep
LOG_LEVEL=info
EOF

"$ROOT/build/fastpki-ms" --config bootstrap.conf >srv.log 2>&1 & P=$!
up=no
for _ in $(seq 1 40); do
    echo | "$OSSL" s_client -connect 127.0.0.1:$PORT >/dev/null 2>&1 && { up=yes; break; }
    sleep 0.25
done
[ "$up" = yes ] || { echo "  fastpki-ms did not come up:"; tail -8 srv.log; echo "=== CHAIN REKEYED CA: PASS=$pass FAIL=$((fail+1)) ==="; exit 1; }

echo "=== 3. what the listener actually puts on the wire ==="
echo | "$OSSL" s_client -showcerts -connect 127.0.0.1:$PORT 2>/dev/null > wire.txt
# Split the presented certs: [0] is the leaf, the rest are the chain the server sent.
awk '/BEGIN CERTIFICATE/{n++} n>0{print > ("w" n ".pem")}' wire.txt
NSENT=$(( $(ls w*.pem 2>/dev/null | wc -l) - 1 ))
chk "server sends BOTH generations as intermediates" 2 "$NSENT"
cat w2.pem w3.pem > sent.pem 2>/dev/null || true
# The decisive one: a client holding ONLY the root must be able to verify the leaf from
# what the server sent. Counting certs alone would pass on two copies of the same one.
"$OSSL" verify -CAfile root.pem -untrusted sent.pem w1.pem >/dev/null 2>&1 && ok=yes || ok=no
chk "a root-only client can verify the served leaf"  yes "$ok"
# The anchor itself must not be on the wire (RFC 8446 4.4.2).
grep -c "$("$OSSL" x509 -in root.pem -outform DER | "$OSSL" dgst -sha256 -r | cut -c1-16)" \
    /dev/null >/dev/null 2>&1
RSENT=0
for f in w2.pem w3.pem w4.pem; do
    [ -f "$f" ] || continue
    "$OSSL" x509 -in "$f" -noout -fingerprint -sha256 2>/dev/null | grep -qF \
        "$("$OSSL" x509 -in root.pem -noout -fingerprint -sha256 | sed 's/.*=//')" && RSENT=$((RSENT+1))
done
chk "the root anchor is NOT sent"                    0 "$RSENT"

kill $P 2>/dev/null; wait $P 2>/dev/null
echo
echo "=== CHAIN REKEYED CA: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
