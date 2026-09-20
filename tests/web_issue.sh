#!/usr/bin/env bash
# Console certificate issuance. A logged-in
# self-service user submits a CSR; fastpki-web issues via the shared policy/profile
# engine, forces owner = the session user, persists it, and returns the cert. The
# domain allowlist + profile still govern; issuance is gated on WEB_ALLOW_REVOKE
# and the signing CA being loaded in-process.
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
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18215; PORT2=18216
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

ca_in_token ca.pem "/CN=Issue CA" 3
cp ca.pem root.pem
printf "internal\n" > domains.txt
pg_setup web_issue; PG_CONNINFO1="$PG_CONNINFO"; PGDATABASE1="$PGDATABASE"
seed_domains $W/domains.txt   # allowed_domains is the sole source
pg_setup web_issue2
seed_domains $W/domains.txt   # the second instance has its own database
trap 'PGDATABASE="$PGDATABASE1"; pg_cleanup; PGDATABASE="${PG_CONNINFO##*dbname=}"; PGDATABASE="${PGDATABASE%% *}"; pg_cleanup; kill $P $P2 2>/dev/null' EXIT
cat > web.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO1
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
WEB_SELFSERVICE_IDENTITY_SUBJECT=false
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
seed_ca_from_conf web.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$WEB" --config web.conf >web.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P $P2 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"

# bootstrap admin + a requester self-service user, log in as the user
code -X POST "$U/api/users" -d 'username=boss&password=bosspw12&role=admin' >/dev/null
curl -s -c boss.cj -X POST "$U/api/login" -d 'username=boss&password=bosspw12' >/dev/null
code -b boss.cj -X POST "$U/api/users" -d 'username=alice&password=alicepw12&role=requester' >/dev/null
curl -s -c alice.cj -X POST "$U/api/login" -d 'username=alice&password=alicepw12' >/dev/null

echo "=== a requester requests a cert from the console ==="
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout k.pem -out ok.csr -subj "/CN=host.internal" >/dev/null 2>&1
chk "issue request -> 201" 201 "$(code -b alice.cj -X POST --data-binary @ok.csr "$U/api/certs/request?ca_instance=ca-global")"
RESP=$(curl -s -b alice.cj -X POST --data-binary @ok.csr "$U/api/certs/request?ca_instance=ca-global")
chk "response carries a PEM" yes "$(has "$RESP" 'BEGIN CERTIFICATE')"
json_pem "$RESP" pem issued.pem
chk "issued cert verifies against the CA" yes \
    "$("$OSSL" verify -CAfile ca.pem issued.pem >/dev/null 2>&1 && echo yes || echo no)"
chk "issued cert CN = host.internal" yes \
    "$("$OSSL" x509 -in issued.pem -noout -subject 2>/dev/null | grep -q 'host.internal' && echo yes || echo no)"

echo "=== the issued cert is owned by alice and shows in her inventory ==="
chk "alice's inventory now lists host.internal" yes "$(has "$(curl -s -b alice.cj "$U/api/certs")" 'host.internal')"
# Query the first DB (where the web server issued the cert)
PGDATABASE="$PGDATABASE1" chk "DB records owner=alice" "alice" "$(PGDATABASE="$PGDATABASE1" pg_exec "SELECT owner FROM certs WHERE cn='host.internal' LIMIT 1;")"

echo "=== the search box finds a certificate by a SAN and by its thumbprint ==="
# The two things people arrive with and could not search for: a DNS name that is not the CN,
# and a fingerprint copied out of Windows, a browser or this console's own detail view. Both
# are columns filled from the DER at insert, so this also proves they are being written.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout ksan.pem -out san.csr \
    -subj "/CN=cn-only.internal" -addext "subjectAltName=DNS:searchme.internal" >/dev/null 2>&1
SR=$(curl -s -b alice.cj -X POST --data-binary @san.csr "$U/api/certs/request?ca_instance=ca-global")
json_pem "$SR" pem san.pem
# ⚠️ WITHOUT LEADING ZEROS, THE FORM THE CONSOLE RETURNS. openssl pads a serial to an even
# number of hex digits, so one whose first digit is 0 prints as 0d6a44f7…, while the API
# answers d6a44f7…: the search found the certificate and the match against its output
# failed. That is one run in sixteen, and it failed all five positive cells at once.
SSER=$("$OSSL" x509 -in san.pem -noout -serial | sed 's/serial=//; s/^0*//' | tr 'A-F' 'a-f')
FP1=$("$OSSL" x509 -in san.pem -noout -fingerprint -sha1 | sed 's/.*=//')          # AB:CD:…
FP1_SPACED=$(printf '%s' "$FP1" | tr -d ':' | sed 's/..../& /g')                    # "abcd ef12 …"
FP256=$("$OSSL" x509 -in san.pem -noout -fingerprint -sha256 | sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f')
# ⚠️ Says what came back when it misses. A miss here is one of three different faults — the
# row is not in the database, the query did not match it, or the endpoint answered nothing at
# all — and a bare "expected yes got no" cannot tell them apart.
found() {
    local body
    body=$(curl -s -b alice.cj "$U/api/certs?q=$(printf '%s' "$1" | sed 's/ /%20/g; s/:/%3A/g')")
    if printf '%s' "$body" | grep -qi "$SSER"; then echo yes; else
        # A JSON array that simply holds no match is the negative cell below working as
        # intended, and saying so every run would be noise. Anything else — empty, an error
        # object, HTML — is the interesting case and gets printed.
        case "$body" in
            \[*\]) ;;
            *) echo "    q=[$1] returned ${#body} bytes: $(printf '%s' "$body" | head -c 200)" >&2 ;;
        esac
        # And the row, when a search for the certificate itself misses: whether the row is
        # there as the search expects is what separates a search fault from a test fault.
        [ "$1" = 'no-such-name.internal' ] || echo "    q=[$1] missed; the row now: $(PGDATABASE="$PGDATABASE1" pg_exec \
            "SELECT owner, sans, fp_sha1, encode(fingerprint, 'hex'), status FROM certs WHERE lower(serial) = '$SSER';" | tr -s ' ')" >&2
        echo no
    fi
}
chk "the certificate was issued at all" yes "$([ -n "$SSER" ] && echo yes || echo no)"
chk "found by a name that is only a SAN"          yes "$(found 'searchme.internal')"
chk "  and still by its CN"                       yes "$(found 'cn-only.internal')"
chk "found by its SHA-1 thumbprint, colons and all" yes "$(found "$FP1")"
chk "  and grouped in fours, as Windows prints it"  yes "$(found "$FP1_SPACED")"
chk "found by its SHA-256 fingerprint"            yes "$(found "$FP256")"
chk "a name that matches nothing still finds nothing" no "$(found 'no-such-name.internal')"

echo "=== a request written by Windows certreq is taken as it stands ==="
# ⚠️ WINDOWS SPELLS THE PEM HEADER DIFFERENTLY. `certreq -new` writes
# -----BEGIN NEW CERTIFICATE REQUEST-----, the pre-standard label, and that is exactly the
# file the user guide tells a Windows user to paste into the CSR form. Asserted because the
# guide promises it: nothing else in the tree reads that spelling, and a reader who had to
# re-label the file by hand would have no way of knowing that was the problem.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout kwin.pem -out win.csr -subj "/CN=win.internal" >/dev/null 2>&1
sed -e 's/BEGIN CERTIFICATE REQUEST/BEGIN NEW CERTIFICATE REQUEST/' \
    -e 's/END CERTIFICATE REQUEST/END NEW CERTIFICATE REQUEST/' win.csr > winnew.csr
chk "the certreq header is what the file carries" yes \
    "$(head -1 winnew.csr | grep -q 'BEGIN NEW CERTIFICATE REQUEST' && echo yes || echo no)"
chk "a NEW CERTIFICATE REQUEST is accepted -> 201" 201 \
    "$(code -b alice.cj -X POST --data-binary @winnew.csr "$U/api/certs/request?ca_instance=ca-global")"

echo "=== policy still governs (domain allowlist) ==="
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout k2.pem -out bad.csr -subj "/CN=evil.example.com" >/dev/null 2>&1
chk "CN outside the domain allowlist -> 400" 400 "$(code -b alice.cj -X POST --data-binary @bad.csr "$U/api/certs/request?ca_instance=ca-global")"

echo "=== gates: writes + CA availability + auth ==="
chk "auditor-less requester path: unauth request -> 401" 401 "$(code -X POST --data-binary @ok.csr "$U/api/certs/request?ca_instance=ca-global")"
# There is no "issuance not configured" (501) state anymore — issuance is per-CA
# and always names ?ca_instance. Omitting it is refused (400), whatever CAs exist.
P2=   # the old "second instance without a signing CA" case is obsolete
chk "issuance without ?ca_instance -> 400" 400 \
    "$(code -b alice.cj -X POST --data-binary @ok.csr "$U/api/certs/request")"

echo "=== the per-requester cap fires on the console too ==="
# The ask was to cap it like the rest. The console was the one issuance path
# with no cap once EST/CMP/MS/ACME had one.
#
# ⚠️ THE CONSOLE SPENDS THE OPERATOR'S QUOTA, NOT THE SUBJECT'S. certs.owner is forced to
# the session user (that is this file's own "forces owner = the session user"), so an admin
# issuing on behalf of a fleet stops at N. That is the trade-off chosen over leaving the
# console uncapped; assert it deliberately rather than let it look like an accident.
#
# alice has already issued above, so the cap is what changes here — not some pre-existing
# refusal. Set it AFTER those certificates exist, or this could pass on a build where
# console issuance was broken all along.
HELD=$(PGDATABASE="$PGDATABASE1" pg_exec "SELECT count(*) FROM certs WHERE owner='alice' AND status IN (0,2) AND cert_id IS NULL;" | tr -d ' ')
chk "alice already holds certificates" yes "$([ "${HELD:-0}" -ge 1 ] && echo yes || echo no)"
# The first assertion of the block: with no number set, nothing is capped. Without this the
# refusals below could pass on a server that refused every console request for any reason.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout kq.pem -out q0.csr -subj "/CN=uncapped.internal" >/dev/null 2>&1
chk "no max_certs set -> still issues" 201 \
    "$(code -b alice.cj -X POST --data-binary @q0.csr "$U/api/certs/request?ca_instance=ca-global")"

PGDATABASE="$PGDATABASE1" pg_exec "UPDATE roles SET max_certs=1 WHERE name='requester';" >/dev/null
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout kq2.pem -out q1.csr -subj "/CN=capped-web.internal" >/dev/null 2>&1
chk "over the cap -> 429" 429 \
    "$(code -b alice.cj -X POST --data-binary @q1.csr "$U/api/certs/request?ca_instance=ca-global")"
chk "  the body says why, as JSON" yes \
    "$(curl -s -b alice.cj -X POST --data-binary @q1.csr "$U/api/certs/request?ca_instance=ca-global" \
       | grep -q 'issuance limit' && echo yes || echo no)"
chk "  and issued nothing" 0 \
    "$(PGDATABASE="$PGDATABASE1" pg_exec "SELECT count(*) FROM certs WHERE cn='capped-web.internal';" | tr -d ' ')"
# 429 and not 403: a quota refusal is not a permission refusal, and the console has to be
# able to tell them apart to say anything useful.
chk "  it is NOT reported as a permission error" no \
    "$([ "$(code -b alice.cj -X POST --data-binary @q1.csr "$U/api/certs/request?ca_instance=ca-global")" = 403 ] && echo yes || echo no)"

# The HSM form is a SECOND handler with its own copy of the owner logic — that was exactly
# this shape, one call site of a shared helper differing from the rest. It has to be driven
# as an ADMIN: /api/certs/request-hsm requires `hsm:manage`, so a requester is refused 403
# by RBAC long before the cap could fire, and asserting 429 there tests nothing. (My first
# version did exactly that and went red for the wrong reason.)
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout kb.pem -out b1.csr -subj "/CN=boss-one.internal" >/dev/null 2>&1
chk "boss issues one first" 201 \
    "$(code -b boss.cj -X POST --data-binary @b1.csr "$U/api/certs/request?ca_instance=ca-global")"
PGDATABASE="$PGDATABASE1" pg_exec "UPDATE roles SET max_certs=1 WHERE name='admin';" >/dev/null
# ⚠️ The keyref below is deliberately a token object that does not exist. A 429 proves the
# cap fires BEFORE any token work — if the order were reversed this would be a 400/500 about
# the missing object and the quota would be spent on a request that could never succeed.
chk "the HSM leaf form is capped too" 429 \
    "$(code -b boss.cj -X POST "$U/api/certs/request-hsm" \
        -d 'cn=capped-hsm.internal&ca_instance=ca-global&keyref=pkcs11:token=fastpki;object=nope;type=private')"
PGDATABASE="$PGDATABASE1" pg_exec "UPDATE roles SET max_certs=NULL WHERE name='admin';" >/dev/null

# ⚠️ ANTI-VACUITY. Lift the cap and the console must issue again.
PGDATABASE="$PGDATABASE1" pg_exec "UPDATE roles SET max_certs=NULL WHERE name='requester';" >/dev/null
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout kq3.pem -out q2.csr -subj "/CN=recapped.internal" >/dev/null 2>&1
chk "lift the cap and the console issues again" 201 \
    "$(code -b alice.cj -X POST --data-binary @q2.csr "$U/api/certs/request?ca_instance=ca-global")"

echo
echo "=== WEB ISSUE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
