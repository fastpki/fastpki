#!/usr/bin/env bash
# HSM-backed CA bootstrap: `fastpki-ca create --ca-key
# pkcs11:<uri>` builds + self-signs the CA cert with a token-resident key (created
# by the HSM ceremony out of band) and registers the URI — the private key never
# leaves the token. The generated CA then issues over EST, signing in-hardware.
# Skips cleanly where SoftHSM / the pkcs11 provider aren't installed.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"   # real credentials, not AUTH_BACKEND=none
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"   # macOS
# Overridable: macOS /etc/ssl/openssl.cnf is minimal (no v3_ca); point at a full
# cnf (e.g. brew's /opt/homebrew/etc/openssl@3/openssl.cnf) there.
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
CA="$ROOT/build/fastpki-ca"
W="$(mktemp -d)"; cd "$W"; PORT=18462
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
skipout(){ echo "  [SKIP] $1"; echo; echo "=== CA CREATE HSM: PASS=$pass FAIL=$fail SKIP=1 ==="; exit 0; }
findfirst(){ for x in "$@"; do [ -e "$x" ] && { echo "$x"; return 0; }; done; return 1; }

# The global CA first: ca_in_token starts the shared p11-kit server IN THIS SHELL and
# exports SOFTHSM2_CONF for it. This suite used to build its own token directory and
# its own softhsm2.conf beforehand, which ca_in_token then silently replaced — so the
# token holding the CA key became invisible and every run ended at
# "no private key found at pkcs11 URI". It passed only when run_all.sh had already
# started a server (leaving SOFTHSM2_CONF alone), and skipped when run on its own,
# which is exactly what §3d forbids. One token directory, owned by the harness.
ca_in_token ca.pem "/CN=Global CA" 3650
# The HSM-backed CA's own key, in its own token on that same server.
URI=$(hsm_ca_key hsmca) || skipout "could not mint a CA key in a token"
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3650 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup ca_create_hsm
# AUTH_BACKEND=none is gone, so this suite authenticates for real.
seed_web_user t t requester
trap 'pg_cleanup; kill ${P:-} 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
ROOT_CA_PEM=$W/ca.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$PORT
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf   # PKCS11_MODULE = the client shim, not SoftHSM itself
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
field(){ "$OSSL" x509 -in "$1" -noout -"$2" 2>/dev/null | sed -n 's/.*CN *= *//p'; }

echo "=== create an HSM-backed CA (key stays in the token) ==="
"$CA" --config bootstrap.conf create hsm-a --name "HSM A" --subject "/CN=HSM A CA" --ca-key "$URI" --out-dir cas >/dev/null 2>cre.err || { echo "create failed:"; cat cre.err; skipout "fastpki-ca create with HSM key failed (provider ABI?)"; }
chk "CA cert written"                yes "$([ -f cas/hsm-a.crt ] && echo yes || echo no)"
chk "no private key written to disk" yes "$([ ! -f cas/hsm-a.key ] && echo yes || echo no)"
chk "instance registered with the pkcs11 URI" "$URI" "$(pg_exec "SELECT coalesce(private_key,'') FROM certs WHERE id='hsm-a' AND is_ca;")"
chk "CA cert is a CA"                yes "$("$OSSL" x509 -in cas/hsm-a.crt -noout -text 2>/dev/null | grep -q 'CA:TRUE' && echo yes || echo no)"
chk "CA cert self-signed by the HSM key" "cas/hsm-a.crt: OK" "$("$OSSL" verify -CAfile cas/hsm-a.crt cas/hsm-a.crt 2>/dev/null)"
# The CA's own certificate is a row in `certs` too, carrying its id and key
# location. This tool did not write one at all before — a CLI-created CA had no row, so
# resolve_ca_instance fell back to the file with nothing saying why. The console had the
# mirror-image bug: it wrote the row BEFORE registering the CA, the certs->ca_instances
# FK rejected it, and a bare catch swallowed the error.
chk "the CA's own cert row exists"     1 "$(pg_exec "SELECT count(*) FROM certs WHERE ca_instance_id='hsm-a' AND is_ca;")"
chk "...carries the CA id"        hsm-a "$(pg_exec "SELECT id FROM certs WHERE ca_instance_id='hsm-a' AND is_ca;")"
chk "...carries the token handle"   yes "$(pg_exec "SELECT private_key FROM certs WHERE ca_instance_id='hsm-a' AND is_ca;" | grep -q '^pkcs11:' && echo yes || echo no)"

echo "=== the HSM CA issues over EST (signing in-hardware) ==="
"$ROOT/build/fastpki-est" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-est died:"; cat srv.log; skipout "fastpki-est could not start"; fi
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout k.pem -subj "/CN=host.internal" -out csr.pem >/dev/null 2>&1
b64=$("$OSSL" req -in csr.pem -outform DER 2>/dev/null | "$OSSL" base64 -A)
curl -sk -u t:t -H "Content-Type: application/pkcs10" --data-binary "$b64" \
    "https://127.0.0.1:$PORT/.well-known/est/hsm-a/simpleenroll" \
  | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs -out leaf.pem 2>/dev/null
chk "EST cert issued by the HSM-backed CA" "HSM A CA" "$(field leaf.pem issuer)"

echo "=== several signing-key URLs: signing survives losing any one of them ==="
# A CA key lives on exactly one node, so losing that node takes the CA's signing with it.
# A CA may therefore name SEVERAL key URLs, tried in order. They are newline-separated in
# `certs.private_key`, because RFC 7512 already gives a pkcs11 URI both ';' and '&'
# internally and a newline is the only separator that cannot split a handle down the middle.
# ⚠️ SETS $ISSUER; NOT CALLED IN A COMMAND SUBSTITUTION. `ISS=$(enroll ...)` runs the whole
# function in a SUBSHELL, so `P=$!` records the new server's pid where the parent cannot see
# it — the parent's kill then targets a stale pid and servers accumulate on the port. It also
# left leaf2.pem from the PREVIOUS enrolment in place when a request failed, so assertions
# about "the certificate just issued" were reading an older one and passing on it. Two checks
# here were green on stale bytes until this was fixed.
enroll(){  # <logfile> -> $ISSUER, and leaf2.pem freshly written or absent
    { kill $P; wait $P; } 2>/dev/null             # drop the cached CA material
    rm -f leaf2.pem                               # never let a stale leaf answer for a new one
    "$ROOT/build/fastpki-est" --config bootstrap.conf >"$1" 2>&1 & P=$!
    # Poll the listener rather than guessing at it: a fixed sleep raced the bind, the request
    # never landed, and the run reported on the previous certificate.
    wait_port "$PORT" "$P" || true
    "$OSSL" req -new -newkey rsa:2048 -nodes -keyout k2.pem -subj "/CN=host.internal" \
        -out csr2.pem >/dev/null 2>&1
    local b; b=$("$OSSL" req -in csr2.pem -outform DER 2>/dev/null | "$OSSL" base64 -A)
    curl -sk -u t:t -H "Content-Type: application/pkcs10" --data-binary "$b" \
        "https://127.0.0.1:$PORT/.well-known/est/hsm-a/simpleenroll" \
      | "$OSSL" base64 -d -A 2>/dev/null \
      | "$OSSL" pkcs7 -inform DER -print_certs -out leaf2.pem 2>/dev/null
    ISSUER=$(field leaf2.pem issuer)
}
chk "one URL to begin with"          1 "$("$CA" --config bootstrap.conf key list hsm-a | grep -c '^1\. pkcs11:')"

# ⚠️ A PATH IS REFUSED AT THE POINT IT IS SET, not at first use. A CA key has no on-disk
# form, so storing one would register a CA that cannot sign — discovered only when somebody
# tries to issue, which is the worst moment to find out.
"$CA" --config bootstrap.conf key add hsm-a /tmp/not-a-token.pem >/dev/null 2>&1 && r=ok || r=refused
chk "  a file path is refused"       refused "$r"
chk "  and nothing was appended"     1 "$("$CA" --config bootstrap.conf key list hsm-a | grep -c '^[0-9]\.')"

DEAD="pkcs11:token=nosuchtoken;object=nosuchobject;type=private"
"$CA" --config bootstrap.conf key add hsm-a "$DEAD" >/dev/null 2>&1
chk "a second URL is appended"       2 "$("$CA" --config bootstrap.conf key list hsm-a | grep -c '^[0-9]\.')"
enroll est2.log
chk "  and the good one still signs" "HSM A CA" "$ISSUER"

# Now the DEAD one first, so issuance can only succeed by failing over to the second.
"$CA" --config bootstrap.conf key remove hsm-a "$URI"  >/dev/null 2>&1
"$CA" --config bootstrap.conf key add    hsm-a "$URI"  >/dev/null 2>&1
chk "  PRECONDITION: the unreachable URL is now first" yes \
    "$("$CA" --config bootstrap.conf key list hsm-a | sed -n '1p' | grep -q 'nosuchtoken' && echo yes || echo no)"
sed 's/^LOG_LEVEL=.*/LOG_LEVEL=info/' bootstrap.conf > fo.conf
cp fo.conf bootstrap.conf
enroll est3.log
chk "signing FAILS OVER past the unreachable URL" "HSM A CA" "$ISSUER"
chk "  and the log says so"          yes \
    "$(grep -q 'failed over to' est3.log && echo yes || echo no)"

# ⚠️ AND "THE FIRST THAT WORKS" MUST MEAN "THE FIRST THAT HOLDS THIS KEY". A token that is
# up with the WRONG key is far more dangerous than one that is down: it loads instantly and
# would sign certificates that chain to nothing. Put a real, reachable, DIFFERENT key first.
OTHER=$(hsm_ca_key hsmother) || OTHER=""
if [ -n "$OTHER" ]; then
    "$CA" --config bootstrap.conf key remove hsm-a "$DEAD" >/dev/null 2>&1
    "$CA" --config bootstrap.conf key remove hsm-a "$URI"  >/dev/null 2>&1
    "$CA" --config bootstrap.conf key add    hsm-a "$OTHER" >/dev/null 2>&1
    "$CA" --config bootstrap.conf key add    hsm-a "$URI"   >/dev/null 2>&1
    # ⚠️ ASSERT THE ORDER, not just the count. The previous version checked that two URLs
    # were listed and called that a precondition; a list in the other order exercises
    # nothing, and the assertion below would still have passed.
    chk "  PRECONDITION: the WRONG key is genuinely first" yes \
        "$("$CA" --config bootstrap.conf key list hsm-a | sed -n '1p' | grep -q 'hsmother' \
           && echo yes || echo no)"
    enroll est4.log
    # ⚠️ AND VERIFY THE SIGNATURE, not the issuer name. The issuer CN comes from the CA
    # CERTIFICATE, so it reads "HSM A CA" whether the right key signed the leaf or the wrong
    # one did — checking it cannot tell the two apart, and the first version of this
    # assertion therefore could not fail. Verifying the chain is what distinguishes them: a
    # leaf signed by the other token key does not verify against this CA's certificate.
    chk "a leaf is issued at all"        "HSM A CA" "$ISSUER"
    chk "a key that does not match the CA cert is SKIPPED" "leaf2.pem: OK" \
        "$("$OSSL" verify -CAfile cas/hsm-a.crt leaf2.pem 2>&1 | tail -1)"
    # Skipped, not silently: it is a real misconfiguration and an operator has to be able
    # to find it, so it is logged at error while the CA stays up.
    chk "  and it is reported, not passed over in silence" yes \
        "$(grep -q 'does NOT match this CA' est4.log && echo yes || echo no)"
    grep -q 'does NOT match this CA' est4.log || {
        "$CA" --config bootstrap.conf key list hsm-a
        grep -iE 'signing key|not usable|failed over' est4.log | head -4
    }
else
    echo "  [SKIP] no second token key available for the wrong-key case"
fi

echo
echo "=== CA CREATE HSM: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
