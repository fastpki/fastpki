#!/usr/bin/env bash
# Deployment transport TLS (deploy/certgen.sh + the app<->DB verify-full conninfo +
# the default admin/admin seed). Proves, without Docker, the security-relevant
# behaviour the compose deployment relies on:
#   1. one self-signed cert secures BOTH the app<->Postgres link and the console;
#   2. the app reaches Postgres over sslmode=verify-full against that cert;
#   3. fastpki-config seeds a working admin/admin console login;
#   4. the console serves HTTPS with the same cert and that admin can log in.
#
# Self-contained + platform/configuration-agnostic: it builds its own throwaway
# Postgres cluster, cert, DB and config under a temp dir and removes all of it on
# exit — nothing machine-specific, so it runs the same on any dev box or in CI.
# Skips cleanly where the Postgres server binaries aren't installed.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export LC_ALL=C   # macOS: a UTF-8 locale makes initdb's postmaster die multithreaded
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"

# Locate the Postgres server binaries (throwaway cluster).
PGBIN=""
if command -v pg_ctl >/dev/null 2>&1; then PGBIN="$(dirname "$(command -v pg_ctl)")"
else PGBIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)"; fi
[ -n "$PGBIN" ] && [ -x "$PGBIN/initdb" ] || { echo "SKIP: Postgres server binaries not found"; exit 0; }

WEB="$ROOT/build/fastpki-web"; CFG="$ROOT/build/fastpki-config"
for b in "$WEB" "$CFG"; do [ -x "$b" ] || { echo "SKIP: $b not built"; exit 0; }; done

# ca_in_token only. NOT pg_helpers: this suite provisions its own cluster on its own
# port, and pg_helpers would start a second one on 5432 at source time.
source "$(cd "$(dirname "$0")" && pwd)/hsm_helpers.sh"
# ⚠️ pg_priv, BECAUSE THIS SUITE STARTS ITS OWN CLUSTER AND THE LAB TIER IS ROOT.
# Measured in-image at 2d5f9557a449: initdb refused as root, $W/pg was never created,
# the three `cp`s into it failed, and the suite exited 0 on
# "SKIP: throwaway Postgres would not start" — 3 assertions of 16, counted among
# `212 passed`. The verify-full half, the admin seed, the console login and the
# Digest checks had never run in that tier. pg_priv.sh already existed for this
# exact refusal; four mesh suites were converted and this one was missed.
source "$(cd "$(dirname "$0")" && pwd)/pg_priv.sh"
# ⚠️ THIS SUITE OWNS ITS CLUSTER, SO IT OWNS ITS PORT — do not inherit PGPORT.
# The harness EXPORTS PGPORT for the cluster the whole run shares, and `${PGPORT:-16991}`
# treated that as an operator's choice. It is not: it points at a cluster this suite is not
# using, whose port is already occupied. The suite's own TLS-enabled postmaster then loses
# the bind, and every assertion below connects to the SHARED cluster instead, which has TLS
# off — so the failure reads
#   fastpki-config: postgres connect failed: ... server does not support SSL, but SSL was required
# as though the product could not do TLS, when nothing of ours was ever contacted.
# DEPLOY_TLS_PGPORT stays as a deliberate override under a name the harness does not set.
W="$(mktemp -d)"; PGPORT=${DEPLOY_TLS_PGPORT:-16991}; WEBPORT=${WEBPORT:-18991}
export PGPORT
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
cleanup(){ if [ -n "${WEBPID:-}" ]; then kill "$WEBPID" 2>/dev/null; wait "$WEBPID" 2>/dev/null; fi
           pg_as "$PGBIN/pg_ctl" -D "$W/pg" -m immediate stop >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT

# ── 1. one self-signed cert (this is exactly what deploy/certgen.sh generates) ──
# SANs cover the console host (here 'localhost', the deploy default) and 'postgres', the
# compose service name the app dials — verify-full pins each host. A standby on another
# host is NOT covered by this certificate and cannot be: it dials by a routable address,
# which is what PG_TLS_SANS + `fastpki-ca pg-tls` put into a CA-issued one.
cat > "$W/san.cnf" <<EOF
[req]
distinguished_name=dn
x509_extensions=v3
prompt=no
[dn]
CN=localhost
[v3]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:postgres,IP:127.0.0.1
EOF
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout "$W/ss.key" -out "$W/ss.crt" \
    -days 825 -config "$W/san.cnf" >/dev/null 2>&1
chmod 600 "$W/ss.key"
echo "=== the deploy-time self-signed cert ==="
chk "cert has SAN for the DB hostname (postgres)" yes \
    "$("$OSSL" x509 -in "$W/ss.crt" -noout -text 2>/dev/null | grep -q 'DNS:postgres' && echo yes || echo no)"
chk "cert is its own trust anchor (self-signed)" yes \
    "$("$OSSL" verify -CAfile "$W/ss.crt" "$W/ss.crt" >/dev/null 2>&1 && echo yes || echo no)"

# ── 2. throwaway Postgres serving TLS with that cert ──────────────────────────
D="$W/pg"
# mktemp -d is 0700 and owned by root, so the dropped-privilege initdb cannot create
# its data directory inside it — a permission error for the same dead end. pg_own is
# a no-op off root, so the Mac path is unchanged.
mkdir -p "$D"; pg_own "$W" "$D"
pg_as "$PGBIN/initdb" -D "$D" -U postgres --auth=trust >"$W/initdb.log" 2>&1
[ -f "$D/postgresql.conf" ] || {
    echo "SKIP: initdb produced no data dir — $(pg_priv_reason)"
    sed -n '1,5p' "$W/initdb.log" | sed 's/^/       /'; exit 0; }
cp "$W/ss.crt" "$D/server.crt"; cp "$W/ss.key" "$D/server.key"
# The key is copied by root AFTER initdb ran as postgres; Postgres refuses a key it
# cannot read, so hand both files to the account that will serve them.
pg_own "$D/server.crt" "$D/server.key"; chmod 600 "$D/server.key"
cat >> "$D/postgresql.conf" <<EOF
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
listen_addresses = '127.0.0.1'
port = $PGPORT
unix_socket_directories = '$D'
EOF
pg_as "$PGBIN/pg_ctl" -D "$D" -l "$D/pg.log" start >/dev/null 2>&1
for i in $(seq 1 40); do "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PGPORT" >/dev/null 2>&1 && break; sleep 0.5; done
"$PGBIN/pg_isready" -h 127.0.0.1 -p "$PGPORT" >/dev/null 2>&1 || {
    # ⚠️ NAME THE DEAD END. "would not start" served both "no Postgres here" and
    # "the harness is root", and that ambiguity is what hid this for every in-image
    # run since the tier was written.
    echo "SKIP: throwaway Postgres would not start — $(pg_priv_reason)"
    [ -f "$D/pg.log" ] && sed -n '1,8p' "$D/pg.log" | sed 's/^/       /'
    exit 0; }
"$PGBIN/createdb" -h 127.0.0.1 -p "$PGPORT" -U postgres pki >/dev/null 2>&1
"$PGBIN/psql" -h 127.0.0.1 -p "$PGPORT" -U postgres -d pki -f "$ROOT/sql/createdb.sql" >/dev/null 2>&1

# The app conninfo the deployment uses: verify-full against the self-signed cert.
# Dial 'localhost' (in the cert SAN) — stands in for 'postgres' in the container.
CONN="host=localhost port=$PGPORT dbname=pki user=postgres sslmode=verify-full sslrootcert=$W/ss.crt"

echo "=== app-style connection is TLS/verify-full against the self-signed cert ==="
SSLVER=$("$PGBIN/psql" "$CONN" -tAc "select version from pg_stat_ssl where pid=pg_backend_pid();" 2>/dev/null)
chk "connects over TLS (verify-full)" yes "$([ -n "$SSLVER" ] && echo yes || echo no)"
echo "    negotiated: ${SSLVER:-<none>}"
chk "an UNTRUSTED anchor is rejected" yes \
    "$("$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -out "$W/bad.crt" -days 1 -subj /CN=bad >/dev/null 2>&1
       "$PGBIN/psql" "host=127.0.0.1 port=$PGPORT dbname=pki user=postgres sslmode=verify-full sslrootcert=$W/bad.crt" \
         -tAc 'select 1' 2>&1 | grep -qi 'certificate verify failed' && echo yes || echo no)"

# ── 3. seed the default admin the way bootstrap.sh does ───────────────────────
cat > "$W/bootstrap.conf" <<EOF
PG_CONNINFO=$CONN
EOF
echo "=== fastpki-config web-user seeds admin/admin over the TLS conninfo ==="
SEED=$("$CFG" --config "$W/bootstrap.conf" web-user admin admin --role admin --if-absent 2>&1)
chk "seed succeeded"      yes "$(echo "$SEED" | grep -q 'written' && echo yes || echo no)"
chk "admin row present"   1   "$("$PGBIN/psql" "$CONN" -tAc "select count(*) from web_users where username='admin' and role='admin';" 2>/dev/null)"
chk "re-seed --if-absent is idempotent" yes \
    "$("$CFG" --config "$W/bootstrap.conf" web-user admin OTHERPW --role admin --if-absent 2>&1 | grep -q 'left unchanged' && echo yes || echo no)"

# ── 4. the console serves HTTPS with the same cert, and admin/admin logs in ────
printf 'internal\n' > "$W/domains.txt"
# allowed_domains is the sole source. This suite runs its OWN cluster, so it
# imports against its own conninfo rather than through the shared pg_helpers seeder.
"$CFG" --config "$W/bootstrap.conf" domains-import "$W/domains.txt" >/dev/null
ca_in_token "$W/ca.pem" "/CN=CA" 3650
cat > "$W/web.conf" <<EOF
PG_CONNINFO=$CONN
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
WEB_BIND=127.0.0.1
WEB_PORT=$WEBPORT
WEB_TLS_CERT=$W/ss.crt
WEB_TLS_KEY=$W/ss.key
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
# A CA exists only as a ca_instances row. Registered directly against this
# suite's own cluster rather than via seed_ca_from_conf, which targets the shared one.
"$PGBIN/psql" "$CONN" -tAq -c "INSERT INTO ca_instances(id,name,status,signing_ca_pem,signing_ca_key,created)
   VALUES('ca','ca','active','$W/ca.pem','$CA_KEY_URI',0)
   ON CONFLICT (id) DO UPDATE SET signing_ca_key=EXCLUDED.signing_ca_key;" >/dev/null 2>&1
hsm_conf_lines >> "$W/web.conf"
"$WEB" --config "$W/web.conf" >"$W/web.log" 2>&1 & WEBPID=$!
for i in $(seq 1 40); do curl -sk -o /dev/null "https://127.0.0.1:$WEBPORT/api/me" && break; sleep 0.25; done
if ! kill -0 "$WEBPID" 2>/dev/null; then echo "  [FAIL] fastpki-web died:"; sed 's/^/    /' "$W/web.log"; echo "=== DEPLOY TLS: PASS=$pass FAIL=$((fail+1)) ==="; exit 1; fi

echo "=== console HTTPS uses the deploy self-signed cert ==="
"$OSSL" s_client -connect "127.0.0.1:$WEBPORT" </dev/null 2>/dev/null \
  | "$OSSL" x509 -outform PEM > "$W/served.pem" 2>/dev/null
SRV=$("$OSSL" x509 -in "$W/served.pem" -noout -subject 2>/dev/null)
chk "console presents the self-signed cert" yes "$(echo "$SRV" | grep -q 'CN *= *localhost' && echo yes || echo no)"

# ⚠️ This certificate is the SUITE'S OWN (`openssl req -x509` at the top, handed to the
# server via WEB_TLS_CERT), mirroring what deploy/certgen.sh writes. Do NOT put the digest
# signature assertion here: it would be measuring openssl's default digest, not ours, and
# would pass forever whatever selfsign_tls_cert() did. The real one is below, against a
# server given NO certificate at all.

echo "=== admin/admin can log in; wrong password cannot ==="
chk "login admin/admin -> 200" 200 \
    "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 -d 'username=admin&password=admin' "https://127.0.0.1:$WEBPORT/api/login")"
chk "login admin/wrong  -> 401" 401 \
    "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 -d 'username=admin&password=wrong' "https://127.0.0.1:$WEBPORT/api/login")"
# The app process itself is talking to Postgres over TLS (not just our psql probe).
APPSSL=$("$PGBIN/psql" "$CONN" -tAc "select count(*) from pg_stat_ssl s join pg_stat_activity a on a.pid=s.pid where a.datname='pki' and s.ssl and a.application_name<>'psql';" 2>/dev/null)
chk "fastpki-web's own DB connections are TLS" yes "$([ "${APPSSL:-0}" -ge 1 ] && echo yes || echo no)"

echo "=== The certificate the PRODUCT mints when given none ==="
# ⚠️ THE REPORT: our self-signed certs were issued with ecdsa-with-SHA1, which is not
# secure… browsers give an error."
#
# ⚠️ The certificate attached to that ticket decodes as **ecdsa-with-SHA256**, and so does
# every live TLS endpoint on the lab (web/est/acme/ms) and every transport cert on disk. So
# the SHA-1 report is not reproducible — but nothing in the suite could have said so, which
# is the real defect. signing_digest.sh covers CA certificates minted by `fastpki-ca`; the
# transport cert comes from selfsign_tls_cert() and NOTHING decoded it.
#
# ⚠️ A SECOND SERVER, with WEB_TLS_CERT/KEY pointing at paths that do not exist, so
# resolve_transport_cert() falls to make_selfsigned_tls_pem() and we measure OUR code. The
# instance above is served a certificate this script generated; asserting a digest there
# would test `openssl req`.
WEBPORT2=$((WEBPORT + 1))
sed -e "s#^WEB_PORT=.*#WEB_PORT=$WEBPORT2#" \
    -e "s#^WEB_TLS_CERT=.*#WEB_TLS_CERT=$W/absent.crt#" \
    -e "s#^WEB_TLS_KEY=.*#WEB_TLS_KEY=$W/absent.key#" "$W/web.conf" > "$W/web2.conf"
"$WEB" --config "$W/web2.conf" >"$W/web2.log" 2>&1 & WEBPID2=$!
for i in $(seq 1 40); do curl -sk -o /dev/null "https://127.0.0.1:$WEBPORT2/api/me" && break; sleep 0.25; done
if kill -0 "$WEBPID2" 2>/dev/null; then
    "$OSSL" s_client -connect "127.0.0.1:$WEBPORT2" </dev/null 2>/dev/null \
      | "$OSSL" x509 -outform PEM > "$W/minted.pem" 2>/dev/null
    MSIG=$("$OSSL" x509 -in "$W/minted.pem" -noout -text 2>/dev/null \
           | sed -n 's/.*Signature Algorithm: *//p' | head -1 | tr -d " \t")
    MSUBJ=$("$OSSL" x509 -in "$W/minted.pem" -noout -subject 2>/dev/null)
    chk "PRECONDITION: it minted its own certificate, not the one above" no \
        "$(cmp -s "$W/minted.pem" "$W/served.pem" && echo yes || echo no)"
    chk "  and that certificate decoded" yes "$([ -n "$MSIG" ] && echo yes || echo no)"
    # Asserted as "not weak" rather than "== ecdsa-with-SHA256": the digest follows the key
    # (ca_signing_md), so pinning one name goes red the day the default key shape changes
    # and says nothing about security either way. SHA-1 and MD5 are what browsers refuse.
    chk "  it is NOT signed with SHA-1 or MD5" no \
        "$(printf '%s' "$MSIG" | grep -qiE 'sha1|md5' && echo yes || echo no)"
    chk "  the digest is one a browser accepts" yes \
        "$(printf '%s' "$MSIG" | grep -qiE 'sha(256|384|512)|ed25519|ml-dsa' && echo yes || echo no)"
    echo "    minted: $MSUBJ  sigalg=$MSIG"
    kill "$WEBPID2" 2>/dev/null; wait "$WEBPID2" 2>/dev/null
else
    echo "  [FAIL] the second fastpki-web (no cert files) did not come up:"; sed 's/^/    /' "$W/web2.log"
    fail=$((fail+1))
fi

echo
echo "=== DEPLOY TLS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
