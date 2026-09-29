#!/usr/bin/env bash
# CMP per-user PBM secret. fastpki-cmp parses the senderKID the OpenSSL CMP
# server API hides (pki::parse_cmp_request, our own minimal ASN.1) and uses it to
# key a per-user PBM secret from the `keys` table.
#
#   PBM keyed by senderKID (on enrollment / ir)
#     - ref=alice + alice's secret           -> ACCEPTED (per-user secret)
#     - ref=alice + wrong secret             -> REJECTED
#     - ref=bob (no keys row) + ANY secret    -> REJECTED (nothing to fall back to)
#
# ⚠️ THE BOB CASES INVERTED. They used to assert that a reference with no `keys`
# row falls back to the server-wide CMP_PBM_SECRET and is ACCEPTED. That global is gone:
# one secret shared by everyone authenticates nobody in particular, and while it existed
# a completely broken per-user lookup was invisible, because the request still succeeded
# on the fallback. So "no row -> refused" is now the assertion that gives this suite its
# value.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
# These suites use -trusted, not -srvcert. Responses are protected by the RA
# credential now, so pinning the CA as the exact server cert can never match; the
# client validates the chain RA -> CA against that anchor instead.
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
W="$(mktemp -d)"; cd "$W"; PORT=18097
OTHER=notalices999   # a well-formed secret belonging to nobody
ALICE=alicesecret123
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=PerUser CA" 3650
# CMP has no CA-key fallback — issue the RA credential from THIS CA
# while CA_KEY_URI still names it, and publish it once the DB exists.
cmp_ra_issue ca.pem "$CA_KEY_URI" || { echo "SKIP: no CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }

pg_setup cmp_peruser
cmp_ra_publish || { echo "SKIP: could not publish the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
# Per-user PBM secret for 'alice' (the senderKID/reference). 'bob' has none.
pg_exec "INSERT INTO keys(kid,protocol,key) VALUES('alice','cmp','$ALICE');"
# The credential needs an IDENTITY holding a profile grant, or
# resolve_profile refuses. seed_enrolling_identity leaves an existing role alone.
seed_enrolling_identity alice
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
cat > cmp.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
CMP_BIND=127.0.0.1
CMP_PORT=$PORT
CMP_PATH=/cmp
# The same CA that issues is also the client-auth anchor — exactly the shape
# the lab runs (CMP_CLIENT_CA_ID=sub-ca), and what makes a certificate this server
# issued usable to sign its own renewal.
CMP_CLIENT_CA_ID=ca
LOG_LEVEL=info
EOF
seed_ca_from_conf cmp.conf   # register the CA (SIGNING_CA_* no longer seed it)
cmp_ra_conf_lines >> cmp.conf
"$ROOT/build/fastpki-cmp" --config cmp.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT

base=( -cmd ir -server "http://127.0.0.1:$PORT/cmp/ca" -recipient "/CN=PerUser CA" -trusted ca.pem
       -subject "/CN=host.example.internal" -keep_alive 0 -newkey scratch.key )
issued() { [ -f "$1" ] && echo issue || echo reject; }

echo "=== Per-user PBM secret (keyed by senderKID) ==="

rm -f a.pem
"$OSSL" cmp "${base[@]}" -ref alice -secret "pass:$ALICE" -certout a.pem >/dev/null 2>&1
chk "ref=alice + alice secret accepted" issue "$(issued a.pem)"

rm -f aw.pem
"$OSSL" cmp "${base[@]}" -ref alice -secret "pass:wrongwrong" -certout aw.pem >/dev/null 2>&1
chk "ref=alice + wrong secret rejected" reject "$(issued aw.pem)"

# bob has NO keys row. Under the old global he was accepted; now there is no secret to
# install for him, so the MAC cannot verify whatever he sends.
rm -f b.pem
"$OSSL" cmp "${base[@]}" -ref bob -secret "pass:$OTHER" -certout b.pem >/dev/null 2>&1
chk "ref=bob (no keys row) rejected — no global to fall back to" reject "$(issued b.pem)"

rm -f ba.pem
"$OSSL" cmp "${base[@]}" -ref bob -secret "pass:$ALICE" -certout ba.pem >/dev/null 2>&1
chk "ref=bob + alice's secret rejected"           reject "$(issued ba.pem)"

# ...and the secret really is bound to the reference, not merely "some known secret".
rm -f x.pem
"$OSSL" cmp "${base[@]}" -ref nosuchuser -secret "pass:$ALICE" -certout x.pem >/dev/null 2>&1
chk "an unknown reference cannot borrow a valid secret" reject "$(issued x.pem)"

echo "=== A CMP-issued certificate CARRIES its owner (SDA), not just the log ==="
# ⚠️ THE REPORT: inspecting example.com.crt showed no Subject Directory Attributes
# extension and hence, no owner."
#
# ⚠️ WHY THIS WENT UNNOTICED. tests/sda.sh proves the extension on the EST path only, and
# the CMP handler DID log `CMP issued ... owner=alice` and DID write `certs.owner`. So the
# log said an owner, the database said an owner, and the one artifact the client actually
# holds said nothing — `issue_cert_from_parts` was called with owner="" on the CRMF branch
# while `id.user` sat two lines away. Decode the certificate; never trust the log line.
T249=$("$OSSL" x509 -in a.pem -noout -text 2>/dev/null)
chk "the issued cert decodes"                       yes "$([ -n "$T249" ] && echo yes || echo no)"
chk "  it carries a Subject Directory Attributes extension" yes \
    "$(grep -q 'Subject Directory Attributes' <<<"$T249" && echo yes || echo no)"
# The VALUE, not merely the extension: an SDA carrying somebody else would satisfy the
# line above. `alice` is the senderKID this request authenticated as.
chk "  and the owner in it is alice"                yes \
    "$(grep -A2 -i 'owner:' <<<"$T249" | grep -q 'CN=alice' && echo yes || echo no)"

echo "=== A certificate is renewed by its OWNER, not by its subject ==="
# ⚠️ THE SHAPE THAT BROKE. A user enrolled `/CN=example.com` over PBM as themselves,
# then could not renew it:
#
#     PKIFailureInfo: badRequest; StatusString: "this identity may not enrol over CMP
#     against CA 'sub-ca'"
#
# cmp_identity() took a signature-protected request's user from the signing certificate's
# SUBJECT CN. For a certificate issued TO a hostname ON BEHALF OF a person that is the
# hostname, which holds no cmp:enrol — so FastPKI refused to renew a certificate it had
# just issued. It only worked when subject and owner happened to be the same string, which
# is why `ir`+PBM and `cr`+signature looked like they were "processed differently".
#
# The subject here is deliberately NOT the username. That is the whole cell: with
# -subject "/CN=alice" it passes on the broken code too.
rm -f own.pem own.key ren.pem ren.key
# ⚠️ `openssl cmp -newkey X` LOADS X, it does not generate it. Passing a path that does not
# exist fails client-side before a byte is sent, with "cannot set up CMP context" — the same
# message the recipient bug turned out to be, and equally nothing to do with the server.
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out own.key >/dev/null 2>&1
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ren.key >/dev/null 2>&1
"$OSSL" cmp -cmd ir -server "http://127.0.0.1:$PORT/cmp/ca" -recipient "/CN=PerUser CA" \
    -trusted ca.pem -keep_alive 0 -newkey own.key -certout own.pem \
    -subject "/CN=notalice.internal" -ref alice -secret "pass:$ALICE" >own.log 2>&1
chk "PBM enrol of a name that is NOT the username" issue "$(issued own.pem)"

# ⚠️ KEEP ENROLLING UNTIL THE SERIAL HAS A LEADING ZERO, because that is the only case the
# bug this cell guards can be seen in — and it happens roughly one run in sixteen.
#
# `certs.serial` is stored canonical (lowercase, leading zeros stripped). The CMP code used
# to look the signer up by a hand-rolled BN_bn2hex string, which pads to an even digit count
# — so a serial whose top nibble is zero was sent as "0abc…" against a stored "abc…", the
# lookup missed, and the owner's own renewal was refused. With a random serial this guard
# was green 15 times out of 16: it passed on my machine and failed in the shipped image,
# which reads exactly like a platform difference and is nothing of the kind. A guard that
# only fires on luck is not a guard.
serial_is_padded(){   # does the BIGNUM form of this cert's serial carry a leading zero?
    RAW=$("$OSSL" x509 -in "$1" -noout -serial 2>/dev/null | sed 's/.*=//' | tr 'A-Z' 'a-z')
    RAW=${RAW#00}     # DER's positive-sign pad byte is not part of the integer
    case "$RAW" in 0*) return 0 ;; *) return 1 ;; esac
}
TRIES=0
while [ -f own.pem ] && ! serial_is_padded own.pem && [ $TRIES -lt 80 ]; do
    TRIES=$((TRIES+1)); rm -f own.pem
    "$OSSL" cmp -cmd ir -server "http://127.0.0.1:$PORT/cmp/ca" -recipient "/CN=PerUser CA" \
        -trusted ca.pem -keep_alive 0 -newkey own.key -certout own.pem \
        -subject "/CN=notalice.internal" -ref alice -secret "pass:$ALICE" >own.log 2>&1
done
chk "  PRECONDITION: forced a serial whose canonical form differs (took $TRIES tries)" yes \
    "$([ -f own.pem ] && serial_is_padded own.pem && echo yes || echo no)"
[ -f own.pem ] || echo "      client said: $(grep -oE 'StatusString: \"[^\"]*\"' own.log | head -1)"
if [ -f own.pem ]; then
    # PRECONDITIONS. Without these the renewal below could pass for the wrong reason —
    # a certificate whose subject already IS `alice` renews fine even on the old code.
    OWNSUB=$("$OSSL" x509 -in own.pem -noout -subject 2>/dev/null)
    chk "  PRECONDITION: its subject is NOT alice" yes \
        "$(grep -q 'notalice.internal' <<<"$OWNSUB" && ! grep -qE 'CN *= *alice$' <<<"$OWNSUB" \
           && echo yes || echo no)"
    OWNSER=$("$OSSL" x509 -in own.pem -noout -serial 2>/dev/null | sed 's/.*=//' | tr 'A-Z' 'a-z' | sed 's/^0*//')
    DBOWN=$(pg_exec "SELECT owner FROM certs WHERE lower(serial) LIKE '%$OWNSER';" | tr -d ' ')
    chk "  PRECONDITION: the DB records its owner as alice" alice "$DBOWN"

    # THE ASSERTION. Renew it, signed by itself. On the old code this is refused.
    rm -f ren.pem
    "$OSSL" cmp -cmd kur -server "http://127.0.0.1:$PORT/cmp/ca" -recipient "/CN=PerUser CA" \
        -trusted ca.pem -keep_alive 0 -cert own.pem -key own.key -oldcert own.pem \
        -newkey ren.key -certout ren.pem -implicit_confirm >kur.log 2>&1
    chk "the OWNER may renew it (kur signed by the cert itself)" issue "$(issued ren.pem)"
    [ -f ren.pem ] || echo "      server said: $(grep -oE 'StatusString: \"[^\"]*\"' kur.log | head -1)"
    if [ -f ren.pem ]; then
        # Decode it: the renewal must still belong to alice, not to the hostname.
        chk "  and the renewal is still filed under alice" alice \
            "$(pg_exec "SELECT owner FROM certs WHERE cn='notalice.internal' ORDER BY \"notBefore\" DESC LIMIT 1;" | tr -d ' ')"
    fi

    # ⚠️ THE OTHER HALF OF WHAT WAS REPORTED: "I then cannot renew or
    # REVOKE this cert using cmp kur or rr command", and every one of my four replies
    # talked only about renewal — one of them even says "Only the RENEWAL differed". The
    # fix does cover both, because rr_cb resolves the caller through the same
    # cmp_identity() that kur does (src/cmp/main.cpp:752), but "it follows from the same
    # function" is an argument, not evidence. This makes it evidence.
    # ⚠️ THE SERIAL COMES FROM THE CERTIFICATE, not from a query. My first version asked
    # the DB for the newest row with this CN — and this suite creates FIFTEEN of them
    # inside the same second, so `ORDER BY "notBefore" DESC LIMIT 1` returned an arbitrary
    # one and the assertion reported the product as broken when the right row was revoked.
    # Same one-second-granularity trap already recorded on the ordering elsewhere.
    # x509_serial_hex() stores it lowercase with leading zeros stripped.
    RSER=$("$OSSL" x509 -in ren.pem -noout -serial 2>/dev/null | sed 's/serial=//' \
           | tr 'A-Z' 'a-z' | sed 's/^0*//')
    "$OSSL" cmp -cmd rr -server "http://127.0.0.1:$PORT/cmp/ca" -recipient "/CN=PerUser CA" \
        -trusted ca.pem -keep_alive 0 -cert ren.pem -key ren.key -oldcert ren.pem \
        >rr.log 2>&1
    RRC=$?
    chk "the OWNER may REVOKE it too (rr signed by the cert itself)" 0 "$RRC"
    [ "$RRC" -ne 0 ] && echo "      server said: $(grep -oE 'StatusString: \"[^\"]*\"' rr.log | head -1)"
    # ⚠️ Decode what the DATABASE holds, not the exit code: an rr that reported success and
    # revoked nothing is the failure shape this repo keeps finding.
    chk "  and the DB records it revoked" "-1" \
        "$(pg_exec "SELECT status FROM certs WHERE serial='$RSER';" | tr -d ' ')"
fi

echo
echo "(revocation via PBM is intentionally refused in strict mode; the rr"
echo " revocation-reason recording is covered with signature auth in"
echo " tests/cmp_authz.sh.)"
echo
echo "=== CMP PER-USER: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
