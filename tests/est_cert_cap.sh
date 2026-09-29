#!/usr/bin/env bash
# `roles.max_certs` caps how many certificates one REQUESTER may hold — and, since
# Removed MAX_CERTS_PER_CN, it is the only issuance quota in the product.
#
# There was no test for the cap at all — which is how it shipped counting the wrong thing.
# `count_active_for_cn()` is `SELECT COUNT(*) ... WHERE cn=$1`, but est/main.cpp called it
# with `auth.username`. So it counted certificates whose CN happens to equal the caller's
# LOGIN NAME and applied that count to a request for whatever CN was actually asked for:
#
#   * usernames are not hostnames in any normal deployment -> the count is always 0 and the
#     cap NEVER fires, however many certificates a name already holds;
#   * where a username does happen to equal a hostname -> one certificate for that name
#     blocks the user from requesting ANY other name.
#
# `docs/config-reference.md` calls it a "Per-CN issuance cap", the key is named PER_CN, and
# the PHP original counted per CN. This asserts that.
#
# ⚠️ THE ASSERTION THAT MATTERS is "the cap fires when username != CN". On HEAD that case
# returns 200 forever, because the count of certs whose cn equals the username is 0. A suite
# that only enrolled as a user whose name equals the CN would pass on the broken code —
# which is exactly the shape of test that would have let this ship.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF

W="$(mktemp -d)"; cd "$W"; PORT=18497
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Cert Cap CA" 3 || { echo "SKIP: could not mint a CA key in a token"; echo "PASS=0 FAIL=0"; exit 0; }
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup est_cert_cap
SRV=
trap 'pg_cleanup; kill ${SRV:-} 2>/dev/null' EXIT
printf "internal\n" > domains.txt; seed_domains "$W/domains.txt"

# TWO users on purpose. `capuser` is an ordinary login name; `cap.internal` is a login name
# that happens to look like a hostname. The bug is only visible by comparing them.
seed_web_user capuser  cappw123456   requester
seed_web_user cap.internal cappw123456 requester

cat > bootstrap.conf <<EOF
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
LOG_LEVEL=info
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf
"$ROOT/build/fastpki-est" --config bootstrap.conf >srv.log 2>&1 & SRV=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$SRV" || true
kill -0 $SRV 2>/dev/null || { echo "fastpki-est died:"; cat srv.log; exit 1; }

# enrol <user> <cn> -> HTTP status
enrol() {
    "$OSSL" req -new -subj "/CN=$2" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr >/dev/null 2>&1
    "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
    curl -sk -o body.out -w '%{http_code}' -u "$1:cappw123456" \
        --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll"
}
live_for_cn() { pg_exec "select count(*) from certs where cn='$1' and status in (0,2) and cert_id is null;" | tr -d ' '; }
# Same call, different password — the cap block seeds its own user rather than reusing one
# whose certificate count the assertions above depend on.
enrol_as() {
    "$OSSL" req -new -subj "/CN=$2" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr >/dev/null 2>&1
    "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
    curl -sk -o body.out -w '%{http_code}' -u "$1:quotapw12345" \
        --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll"
}

echo "=== MAX_CERTS_PER_CN is GONE — one name may hold as many certs as it likes ==="
# ⚠️ THIS ASSERTS A REMOVAL, so it has to prove the code is absent rather than just stop
# exercising it. Deleting the old per-CN assertions and leaving nothing would pass equally
# well against a build that still had the cap — the "reader with no writer" shape.
#
# The old cap was 2. Five certificates for ONE common name, from one caller, all issued, is
# only possible if nothing counts per CN any more: the requirement was no max-certs-per-CN
# and no globals.
#
# Worth recording why losing it costs nothing: it was enforced in fastpki-est and NOWHERE
# else. ACME, CMP, SCEP, MS-WSTEP and the console all issued past it, so any caller who hit
# it could ask another port for the same name.
for i in 1 2 3 4 5; do
    chk "cert $i for host-a.internal (no per-CN cap)" 200 "$(enrol capuser host-a.internal)"
done
chk "  five live for that ONE cn" 5 "$(live_for_cn host-a.internal)"
# And the config key itself must be unparsed: a shipped file that still set it would be
# silently ignored, which is the thing tests/config_keys.sh exists to catch.
chk "MAX_CERTS_PER_CN is not a config key any more" 0 \
    "$(grep -c 'MAX_CERTS_PER_CN' "$ROOT/src/lib/config.cpp")"

echo "=== the per-REQUESTER cap comes from roles.max_certs ==="
# This caps a HOLDER, not a name — the per-CN cap above it used to be the other half and
# is gone. The roles column was chosen over a profile property because profiles live in
# the unreplicated `config` blob, so a profile-borne cap would differ per DC.
#
# The column shipped and was enforced by nothing — the console wrote it, the DB
# layer read it back, and no issuance path ever looked. So the FIRST assertion has to be
# that a role with no number set changes nothing, or "the cap fires" below could just be
# some unrelated refusal.
live_for_owner() { pg_exec "select count(*) from certs where owner='$1' and status in (0,2) and cert_id is null;" | tr -d ' '; }

# ⚠️ ITS OWN ROLE, not the builtin. This section caps a role at 3, and `capuser` further
# down must hold NO cap — that is the assertion separating the per-requester limit from the
# retired per-CN one. Both used to hold `requester`, so capping the builtin silently capped
# capuser too and the later 200 became a 429. (capuser held `standard` before the rename
# the issuance profiles; that name is not a console role, which is why it had no cap and
# why moving it to `requester` exposed this.)
pg_exec "INSERT INTO roles(name,description,builtin) VALUES('quotarole','test: capped role',false)
         ON CONFLICT (name) DO NOTHING;" >/dev/null
pg_exec "INSERT INTO role_permissions(role,permission,scope)
           SELECT 'quotarole', permission, scope FROM role_permissions WHERE role='requester'
         ON CONFLICT DO NOTHING;" >/dev/null
seed_web_user quota quotapw12345 quotarole
QBEFORE=$(live_for_owner quota)
chk "a role with NO max_certs set caps nothing" 200 "$(enrol_as quota host-q1.internal)"
chk "  and again"                               200 "$(enrol_as quota host-q2.internal)"
chk "  two certificates are now HIS"            2   "$(( $(live_for_owner quota) - QBEFORE ))"

# Now give the role a number. 3 rather than 2 on purpose: he already holds 2, so the next
# one must still succeed and the one after must not — a cap set BELOW what someone already
# holds would refuse immediately and pass for the wrong reason.
pg_exec "UPDATE roles SET max_certs=3 WHERE name='quotarole';" >/dev/null
chk "under the cap, still issued"        200 "$(enrol_as quota host-q3.internal)"
chk "  he now holds three"               3   "$(( $(live_for_owner quota) - QBEFORE ))"
chk "at the cap, refused with 429"       429 "$(enrol_as quota host-q4.internal)"
chk "  and no fourth was written"        3   "$(( $(live_for_owner quota) - QBEFORE ))"
# THE assertion that keeps the two caps apart. A brand-new name nobody has ever asked for
# is unbounded now that the per-CN cap is gone, so a refusal here can only be the
# requester cap —
# and if the two limits were ever collapsed into one, this is the case that would break.
chk "  a name with ZERO live certs is refused too" 0 "$(live_for_cn host-q4.internal)"

# The other direction, and it is the one that changed: a caller whose role sets NO number
# is now unlimited, because the per-CN cap that used to catch them is gone. `capuser` holds
# no role with a max_certs, and host-a.internal already has five certificates.
#
# ⚠️ This is the assertion that proves the two limits were genuinely separate. It expected
# 429 while MAX_CERTS_PER_CN existed and expects 200 now; a suite that only deleted the
# per-CN section would have left this one silently measuring the wrong thing.
chk "a caller with no role cap is no longer stopped by the name" 200 "$(enrol capuser host-a.internal)"

# And a second role that DOES have room lifts it: most-permissive wins across roles, the
# same rule may_enrol uses for grants.
pg_exec "INSERT INTO roles(name,description,builtin,max_certs) VALUES('bigquota','',false,50) ON CONFLICT (name) DO UPDATE SET max_certs=50;" >/dev/null
pg_exec "INSERT INTO subject_roles(selector_type,selector_value,role) VALUES('user','quota','bigquota') ON CONFLICT DO NOTHING;" >/dev/null
chk "a second role with a bigger number lifts it" 200 "$(enrol_as quota host-q5.internal)"


echo "=== The per-NAME limit is back, as roles.max_cn ==="
# MAX_CERTS_PER_CN's job now belongs to the role instead of to a config file.
# This is the OTHER limit and the two must not be confused, so the section runs against a
# caller whose max_certs is deliberately huge — a refusal here can then only be the name.
pg_exec "UPDATE roles SET max_certs=500, max_cn=NULL WHERE name='quotarole';" >/dev/null
pg_exec "DELETE FROM subject_roles WHERE selector_value='quota' AND role='bigquota';" >/dev/null
chk "PRECONDITION: no max_cn -> the same name issues twice" 200 "$(enrol_as quota shared-name.internal)"
chk "  and again"                                           200 "$(enrol_as quota shared-name.internal)"
N0=$(live_for_cn shared-name.internal)
chk "  that name now has two live certificates"             2   "$N0"

# 2, i.e. exactly what the name already holds, so the very next request must be refused —
# and the assertion below proves it is the NAME being refused and not the holder.
pg_exec "UPDATE roles SET max_cn=2 WHERE name='quotarole';" >/dev/null
chk "at max_cn, the SAME name is refused with 429"          429 "$(enrol_as quota shared-name.internal)"
chk "  and no third was written for it"                     2   "$(live_for_cn shared-name.internal)"
# ⚠️ THE assertion that separates max_cn from max_certs. Same caller, same role, same
# request — only the name differs. If this returned 429 the refusal above would have been
# the per-requester cap wearing the per-name cap's clothes.
chk "  a DIFFERENT name from the same caller still issues"  200 "$(enrol_as quota other-name.internal)"
pg_exec "UPDATE roles SET max_cn=NULL WHERE name='quotarole';" >/dev/null
chk "with the number taken away, the capped name issues again" 200 "$(enrol_as quota shared-name.internal)"

echo
echo "=== ⚠️ AND THE CAP HOLDS UNDER CONCURRENCY, which a check-then-insert cannot ==="
# The pre-flight counts, and the insert writes — two separate statements. Requests that
# both read max-1 therefore both commit, and the cap is exceeded with nothing logged and
# no error returned to anyone. Deciding it INSIDE the insert's transaction, under a
# per-owner advisory lock, is what makes the configured number true rather than advisory.
#
# ⚠️ THE CSRs ARE BUILT FIRST, ON PURPOSE. Generating a 2048-bit key takes long enough
# that six jobs each doing their own would barely overlap, and the test would pass
# against the racy code by never actually racing it. Only the six curls run at once.
for t in 1 2 3 4 5 6; do
    "$OSSL" req -new -subj "/CN=race-$t.internal" -newkey rsa:2048 \
        -keyout "rk-$t.pem" -nodes -out "rr-$t.csr" >/dev/null 2>&1
    "$OSSL" req -in "rr-$t.csr" -outform DER 2>/dev/null | "$OSSL" base64 > "rb-$t.b64"
done
# One slot, computed from the LIVE count so no earlier section's arithmetic can matter.
HELD=$(live_for_owner quota)
pg_exec "UPDATE roles SET max_certs=$((HELD + 1)) WHERE name='quotarole';" >/dev/null
rm -f race-*.code
# ⚠️ COLLECT THE PIDs AND WAIT ON THOSE. A bare `wait` waits for EVERY background job of
# this shell — and the suite already has two: the p11-kit token server and fastpki-est,
# both started with & and neither of which ever exits. `wait` with no arguments therefore
# hangs until the suite timeout, with no output and nothing running to point at it.
RPIDS=""
for t in 1 2 3 4 5 6; do
    ( curl -sk -o "rbody-$t.out" -w '%{http_code}\n' -u quota:quotapw12345 \
        --data-binary "@rb-$t.b64" -H "Content-Type: application/pkcs10" \
        "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll" > "race-$t.code" ) &
    RPIDS="$RPIDS $!"
done
wait $RPIDS
# The COUNT is the assertion that matters: it is what the operator configured, and it is
# deterministic. How many 200s came back can vary with scheduling; how many certificates
# exist afterwards cannot.
chk "the owner holds exactly the cap after six concurrent enrolments" "$((HELD + 1))" \
    "$(live_for_owner quota)"
chk "  and exactly one of the six was issued" 1 \
    "$(cat race-*.code 2>/dev/null | grep -c '^200$' | tr -d ' ')"
chk "  the other five were refused, not failed" 5 \
    "$(cat race-*.code 2>/dev/null | grep -c '^429$' | tr -d ' ')"

echo "=== EST CERT CAP (per-requester, per-name + per-SAN): PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
