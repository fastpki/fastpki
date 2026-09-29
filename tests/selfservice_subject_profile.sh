#!/usr/bin/env bash
# The PROFILE decides whether issuance rewrites the subject to the caller's
# identity — not a capability the caller happens to hold.
#
# WEB_SELFSERVICE_IDENTITY_SUBJECT replaces the CSR's CN with the authenticated username
# (and OUs with the session groups). A profile can opt out with no_override_subject.
# The opt-out used to be ANDed with `!issues_for_others(req)`, a capability predicate true
# for anyone holding *:* or cert:read — so for an admin the expression
# short-circuited and the profile setting was never consulted. The checkbox was dead for
# exactly the people most likely to set it — as reported, it worked for `requester` and
# not for `admin`. Same shape as its siblings: a second gate re-deciding what policy decided.
#
# The capability term is gone and the builtin `admin` profile ships with
# no_override_subject=true, so an admin using the `admin` profile sees no change — but an
# admin who picks `requester` now gets the identity binding, which is what picking it means.
#
# Asserted by decoding the issued certificate's subject, never by reading the flag back.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/json_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: that default path is a Linux convention and is absent on plenty of dev boxes.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18219
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Subject Profile CA" 3
cp ca.pem root.pem
printf "internal\n" > domains.txt
pg_setup selfservice_subject
seed_domains $W/domains.txt
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > web.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
ROOT_CA_PEM=$W/root.pem
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
WEB_SELFSERVICE_IDENTITY_SUBJECT=true
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
seed_ca_from_conf web.conf
"$WEB" --config web.conf >web.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"

curl -s -o /dev/null -X POST "$U/api/users" -d 'username=boss&password=bosspw12&role=admin'
curl -s -c boss.cj  -X POST "$U/api/login" -d 'username=boss&password=bosspw12'   >/dev/null
curl -s -o /dev/null -b boss.cj -X POST "$U/api/users" -d 'username=alice&password=alicepw12&role=requester'
curl -s -c alice.cj -X POST "$U/api/login" -d 'username=alice&password=alicepw12' >/dev/null

# Issue with the given cookie + profile and report the issued CN.
issue_cn() {   # <cookiejar> <profile> <csr-cn> -> CN of the issued certificate
    local jar="$1" prof="$2" cn="$3"
    "$OSSL" req -new -newkey rsa:2048 -nodes -keyout "k_$prof.pem" -out "r_$prof.csr" \
        -subj "/CN=$cn" >/dev/null 2>&1
    # ⚠️ The endpoint answers JSON with the PEM in a field, not a bare PEM. Writing the
    # response straight to a .pem gave openssl garbage and every assertion compared
    # against "" — which the preconditions caught, as they are there to.
    local resp; resp=$(curl -s -b "$jar" -X POST --data-binary "@r_$prof.csr" \
        "$U/api/certs/request?ca_instance=ca-global&profile=$prof" 2>/dev/null)
    json_pem "$resp" pem "c_$prof.pem" 2>/dev/null || return 0
    "$OSSL" x509 -in "c_$prof.pem" -noout -subject 2>/dev/null \
        | sed -n 's/.*CN *= *\([^,]*\).*/\1/p'
}

echo "=== the control: a requester always gets the identity binding ==="
R_CN=$(issue_cn alice.cj requester host.internal)
# PRECONDITION: an empty CN would make every comparison below meaningless.
chk "PRECONDITION: the requester's certificate decoded" yes \
    "$([ -n "$R_CN" ] && echo yes || echo no)"
chk "requester + requester profile -> CN is the username" "alice" "$R_CN"

echo "=== an ADMIN using the 'admin' profile keeps the CSR subject ==="
# no_override_subject=true on the builtin admin profile. This is what keeps host
# certificates working: rewriting CN=web01.internal to CN=boss would be wrong.
A_CN=$(issue_cn boss.cj admin web01.internal)
chk "PRECONDITION: the admin-profile certificate decoded" yes \
    "$([ -n "$A_CN" ] && echo yes || echo no)"
chk "admin + admin profile -> CSR subject preserved" "web01.internal" "$A_CN"

echo "=== ⚠️ UNTICK the box on the admin profile and the binding applies ==="
# THE TICKET, and the only reachable form of it: an admin cannot select the `requester`
# profile at all — the union of permitted profiles refuses it with
#   {"error":"policy: profile 'requester' is not permitted for this identity"}
# so the case worth guarding is the one that was reported: the checkbox on the
# admin's OWN profile. Before the fix `!issues_for_others(req)` short-circuited for an
# admin and the profile was never consulted, so unticking it changed nothing.
#
# Posted through the real editor endpoint rather than an UPDATE against a guessed table:
# omitting no_override_subject is how the console sends an unticked box.
curl -s -o /dev/null -b boss.cj -X POST "$U/api/profiles" \
  -d 'name=admin&allow_wildcard=true&allow_ca=true&manage_aia=true&manage_crldp=true&allowed_custom_extensions=*'
chk "PRECONDITION: the admin profile now reports the box unticked" "false" \
    "$(curl -s -b boss.cj "$U/api/profiles" 2>/dev/null \
       | tr '{' '\n' | grep '"name":"admin"' \
       | grep -o '"no_override_subject":[a-z]*' | head -1 | cut -d: -f2)"
B_CN=$(issue_cn boss.cj admin laptop.internal)
chk "PRECONDITION: that certificate decoded" yes "$([ -n "$B_CN" ] && echo yes || echo no)"
chk "admin, box UNticked -> CN is the admin's username" "boss" "$B_CN"

echo
echo "=== SELFSERVICE SUBJECT PROFILE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
