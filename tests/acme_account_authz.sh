#!/usr/bin/env bash
# Two ACME authorization rules that were never enforced: a challenge belongs to ONE
# account, and a deactivated account is finished.
#
#   1. THE CHALLENGE TRIGGER CHECKED ONLY THE CHALLENGE ID. The JWS proves the caller is
#      *an* account; nothing tied the challenge to *that* account. So any registered
#      client could POST to any challenge URL — driving somebody else's validation and
#      reading back the response, which carries the challenge `token`.
#
#   2. A DEACTIVATED ACCOUNT KEPT WORKING. RFC 8555 §7.3.6: "A deactivated account can no
#      longer request certificate issuance or access resources related to the account,
#      such as orders or authorizations. If a server receives a POST or POST-as-GET from
#      a deactivated account, it MUST return an error response with status code 401
#      (Unauthorized) and type urn:ietf:params:acme:error:unauthorized."
#      Deactivation is what a client does when it thinks the account key is COMPROMISED,
#      so a deactivation that leaves the key working is the one failure that matters.
#
# ⚠️ WHY EVERY REFUSAL HERE IS PAIRED WITH A CONTROL. Both fixes refuse things, and a
# refusal that fires for the WRONG reason reads exactly like a pass — a broken route, a
# dead server or a mistyped URL would satisfy every negative assertion on its own. So each
# "must be refused" is immediately preceded or followed by the SAME request that must
# still succeed, which is what makes the refusal evidence rather than a coincidence.
#
# §3d self-contained, §3e pure shell. No privileges (no :80) — validation is never
# allowed to succeed here, only triggered.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; PORT=18468
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

source "$ROOT/tests/acme_jws.sh"
ca_in_token ca.pem "/CN=Authz CA" 3650
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

cp ca.pem root.pem
pg_setup acme_account_authz
cat > acme.conf <<EOF
BASE_URL=https://localhost:$PORT
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
ACME_CERT=$W/acme.pem
ACME_KEY=$W/acme.key
PG_CONNINFO=$PG_CONNINFO
ACME_BIND=127.0.0.1
ACME_PORT=$PORT
ACME_BASE_PATH=/acme
LOG_LEVEL=err
EOF
# The CA has to be REGISTERED; the SIGNING_CA_* keys above are only how this helper
# is told which material to register, not a code path that seeds one.
seed_ca_from_conf acme.conf
printf "test\n" > domains.txt; seed_domains "$W/domains.txt"
"$ROOT/build/fastpki-acme" --config acme.conf >srv.log 2>&1 & SRV=$!
sleep 1; trap 'pg_cleanup; kill $SRV 2>/dev/null' EXIT
if ! kill -0 $SRV 2>/dev/null; then echo "fastpki-acme died:"; cat srv.log; echo "RESULT: FAIL"; exit 1; fi

JWS_TMP="$W/jws"; mkdir -p "$JWS_TMP"
acme_dir "https://127.0.0.1:$PORT/acme/ca/directory"
acme_seed_eab acme-authz
chk "directory advertises newOrder" yes "$([ -n "$ACME_NEW_ORDER" ] && echo yes || echo no)"

# ── two accounts ────────────────────────────────────────────────────────────────
jws_newkey ka.pem; acme_new_account ka.pem; KIDA=$ACME_LOCATION
jws_newkey kb.pem; acme_new_account kb.pem; KIDB=$ACME_LOCATION
chk "account A registered" yes "$([ -n "$KIDA" ] && echo yes || echo no)"
chk "account B registered" yes "$([ -n "$KIDB" ] && [ "$KIDB" != "$KIDA" ] && echo yes || echo no)"

# ── A opens an order and reaches one of its challenges ──────────────────────────
acme_post_kid ka.pem "$KIDA" "$ACME_NEW_ORDER" \
    '{"identifiers":[{"type":"dns","value":"chall.test"}]}'
chk "A's newOrder -> 201" 201 "$ACME_STATUS"
AUTHZ=$(json_str "$ACME_BODY" authorizations)
[ -n "$AUTHZ" ] || AUTHZ=$(printf '%s' "$ACME_BODY" | sed -n 's/.*"authorizations":\["\([^"]*\)".*/\1/p')
chk "the order names an authorization" yes "$([ -n "$AUTHZ" ] && echo yes || echo no)"

acme_post_kid ka.pem "$KIDA" "$AUTHZ" ""
chk "A can read its own authorization -> 200" 200 "$ACME_STATUS"
CHALL=$(printf '%s' "$ACME_BODY" | tr '{' '\n' | sed -n 's/.*"url":"\([^"]*chall[^"]*\)".*/\1/p' | head -1)
# ⚠️ ANTI-VACUITY, and this is the assertion the whole suite rests on. If CHALL were
# empty, every request below would go to a nonsense URL, the server would answer 404 for
# a reason that has nothing to do with ownership, and the cross-account check would
# "pass" while testing nothing at all.
chk "and it carries a challenge URL" yes "$([ -n "$CHALL" ] && echo yes || echo no)"
[ -n "$CHALL" ] || { echo "  (authz body was: $ACME_BODY)"; echo "RESULT: FAIL"; exit 1; }

# ── 1. the challenge belongs to A, and only A ───────────────────────────────────
# B first: if the ownership check were absent this returns 200 and hands B the token.
acme_post_kid kb.pem "$KIDB" "$CHALL" '{}'
chk "B triggering A's challenge -> 404" 404 "$ACME_STATUS"
chk "  and B is not told the token" yes \
    "$(printf '%s' "$ACME_BODY" | grep -q '"token"' && echo no || echo yes)"
# THE CONTROL. Same URL, same payload, A's key — this must still work, or the 404 above
# is just a broken route and proves nothing about ownership.
acme_post_kid ka.pem "$KIDA" "$CHALL" '{}'
chk "  control: A triggering its OWN challenge -> 200" 200 "$ACME_STATUS"
chk "  and A does get the token" yes \
    "$(printf '%s' "$ACME_BODY" | grep -q '"token"' && echo yes || echo no)"

# ── 1b. a deactivation that could NOT be written must not report success ──────────
# ⚠️ THE 200 USED TO BE RENDERED FROM MEMORY. The handler set acc->status = 1, called
# save_account() inside a try whose catch was empty, and then answered 200 with a body
# built from the in-memory object — so a failed write told the client its COMPROMISED
# account was deactivated while the row was untouched and the key went on enrolling.
# The try is there so a malformed payload does not 500; it must not span the write.
#
# The write is made to fail without breaking reads: a BEFORE UPDATE trigger. Renaming
# the table would have failed the account LOOKUP first, and the refusal would have
# been evidence of nothing.
#
# ⚠️ ITS OWN ACCOUNT. This test ends by deactivating the account it uses, so borrowing
# B would leave B dead for the control further down that requires the OTHER account to
# still work — and that control would then fail for a reason having nothing to do with
# what it tests.
jws_newkey kc.pem; acme_new_account kc.pem; KIDC=$ACME_LOCATION
pg_exec "CREATE OR REPLACE FUNCTION t_no_update() RETURNS trigger AS \$\$
         BEGIN RAISE EXCEPTION 'update refused by test'; END; \$\$ LANGUAGE plpgsql;
         CREATE TRIGGER t_accounts_no_update BEFORE UPDATE ON accounts
         FOR EACH ROW EXECUTE FUNCTION t_no_update();" >/dev/null 2>&1
acme_post_kid kc.pem "$KIDC" "$KIDC" '{"status":"deactivated"}'
chk "a deactivation that cannot be written is NOT a 200" no \
    "$([ "$ACME_STATUS" = 200 ] && echo yes || echo no)"
chk "  and the body does not claim deactivated" no \
    "$(printf '%s' "$ACME_BODY" | grep -q '"status":"deactivated"' && echo yes || echo no)"
pg_exec "DROP TRIGGER t_accounts_no_update ON accounts;" >/dev/null 2>&1
# CONTROL: with the trigger gone the same request succeeds, so the refusal above was
# the write failing and not a broken route, a dead server or a bad KID.
acme_post_kid kc.pem "$KIDC" "$KIDC" '{"status":"deactivated"}'
chk "  and the SAME request succeeds once the write can land" 200 "$ACME_STATUS"
chk "  the row really says deactivated now" 1 \
    "$(pg_exec "SELECT count(*) FROM accounts WHERE status=1;" | tr -d ' ')"

# ── 2. deactivation actually deactivates ────────────────────────────────────────
acme_post_kid ka.pem "$KIDA" "$KIDA" '{"status":"deactivated"}'
chk "A deactivates itself -> 200" 200 "$ACME_STATUS"
chk "  and the account reports deactivated" yes \
    "$(printf '%s' "$ACME_BODY" | grep -q '"status":"deactivated"' && echo yes || echo no)"

# The RFC names both the code and the type; assert both, because a 401 carrying the wrong
# problem type is what a client keys its retry logic off.
acme_post_kid ka.pem "$KIDA" "$AUTHZ" ""
chk "deactivated account reading its authz -> 401" 401 "$ACME_STATUS"
chk "  with type urn:ietf:params:acme:error:unauthorized" yes \
    "$(printf '%s' "$ACME_BODY" | grep -q 'acme:error:unauthorized' && echo yes || echo no)"
acme_post_kid ka.pem "$KIDA" "$ACME_NEW_ORDER" \
    '{"identifiers":[{"type":"dns","value":"after.test"}]}'
chk "deactivated account ordering a certificate -> 401" 401 "$ACME_STATUS"
acme_post_kid ka.pem "$KIDA" "$CHALL" '{}'
chk "deactivated account triggering its challenge -> 401" 401 "$ACME_STATUS"

# THE CONTROL for the whole deactivation block: B was never deactivated, so if the server
# had simply stopped answering, this would fail too.
acme_post_kid kb.pem "$KIDB" "$KIDB" ""
chk "  control: the OTHER account still works -> 200" 200 "$ACME_STATUS"

kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
echo
echo "=== ACME ACCOUNT AUTHZ: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
