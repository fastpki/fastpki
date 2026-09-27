#!/usr/bin/env bash
# External Account Binding is not optional. There is no setting.
#
# `ACME_EAB_REQUIRED=true` is the agreed default. An ACME server
# that accepts any self-generated account key will issue to anyone who can answer a
# challenge for a name in allowed_domains — reasonable for a public CA, wrong for an
# internal one. A later change DELETED the key: not a default any more, the only
# behaviour there is.
#
# ⚠️ WHY THIS SUITE STILL EXISTS AFTER THE KEY IS GONE.
#
# Deleting a config key proves nothing on its own. `acme_eab_required` was a plain bool read
# in three places; a later edit that reintroduces `if (something) require_eab` would compile,
# every other ACME suite would stay green — they all register WITH a binding now — and the
# hole would be back with no test looking at it. This suite is the one that asks the running
# server both questions: is an unbound account refused, and is a bound one accepted?
#
# It is a CORE suite on purpose: refusing newAccount happens before any challenge, so nothing
# here needs :80 or root. acme_eab.sh (the certbot EAB path) is in ROOT_SUITES because it
# drives certbot --standalone, and an assertion parked there would never run unprivileged.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
[ -n "$OSSL" ] || { echo "SKIP: no openssl on PATH"; exit 0; }
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; PORT=18482
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

source "$ROOT/tests/acme_jws.sh"
ca_in_token ca.pem "/CN=Default EAB CA" 3650 || { echo "SKIP: could not mint a CA key in a token"; exit 0; }
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_default_eab
P=
trap 'kill ${P:-} 2>/dev/null; pg_cleanup' EXIT

# ⚠️ NOTHING BELOW CONFIGURES EAB, because there is nothing to configure. The
# server must require it because that is what it does, not because this file said so.
cat > bootstrap.conf <<EOF
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
chk "the config configures no EAB policy at all" 0 \
    "$(grep -c 'ACME_EAB' bootstrap.conf | tr -d ' ')"

seed_ca_from_conf bootstrap.conf
printf "internal\n" > domains.txt
seed_domains "$W/domains.txt"
"$ROOT/build/fastpki-acme" --config bootstrap.conf > srv.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-acme died:"; cat srv.log; exit 1; }
B="https://localhost:$PORT/acme/ca"

echo "=== the directory advertises the requirement (RFC 8555 §7.1.1) ==="
DIR=$(curl -sk --max-time 10 "$B/directory")
chk "directory is served"                     yes "$(printf '%s' "$DIR" | grep -q newAccount && echo yes || echo no)"
# RFC 8555 §7.1.1: meta.externalAccountRequired tells a client to expect EAB BEFORE it
# wastes a round trip generating a key and being refused.
chk "  meta.externalAccountRequired is true"  yes \
    "$(printf '%s' "$DIR" | grep -q '"externalAccountRequired"[[:space:]]*:[[:space:]]*true' && echo yes || echo no)"

echo "=== and newAccount without EAB is refused ==="
# acme_dir + acme_post_jwk come from acme_jws.sh. newAccount is a plain HTTPS POST — no
# challenge, nothing bound to :80 — which is what keeps this suite in the CORE tier.
# ⚠️ acme_post_jwk PRINTS NOTHING — acme_http() puts the response in $ACME_BODY and the
# code in $ACME_STATUS. Capturing its stdout gives an empty string, and "does the body
# contain valid?" then answers no for the wrong reason: my first version passed the refusal
# assertion against an empty capture. Read the variables the helper actually sets.
acme_dir "$B/directory" >/dev/null 2>&1
jws_newkey acct.key
acme_post_jwk acct.key "$ACME_NEW_ACCT" '{"termsOfServiceAgreed":true}' || true
printf '%s\n' "$ACME_BODY" > newacct.out
chk "the response body is not empty"          yes \
    "$([ -n "$ACME_BODY" ] && echo yes || echo no)"
chk "the server refuses the account"          400 "$ACME_STATUS"
# ⚠️ Assert the REASON, not just the refusal. A server that is simply broken also fails to
# create an account, and that would pass a bare "not valid" check — the vacuous shape.
chk "  and says why: externalAccountRequired"  yes \
    "$(printf '%s' "$ACME_BODY" | grep -q 'externalAccountRequired' && echo yes || echo no)"
chk "  no account row was created"            0 \
    "$(pg_exec 'SELECT count(*) FROM accounts;' | tr -d ' ')"

echo "=== and WITH a binding the same client is accepted (RFC 8555 §7.3.4) ==="
# ⚠️ WHY THE POSITIVE CASE LIVES HERE TOO. Until now the shell ACME client could not
# register on a deployment that requires EAB — it had no binding helper — so its own
# default locked it out of every real deployment, and demo/pki-demo.sh's live ACME leg had
# nothing to drive. acme_eab.sh covers the positive path with CERTBOT and is in
# ROOT_SUITES, so it never runs unprivileged and could not guard this.
#
# Asserting both directions in one suite is also what makes the refusal above meaningful:
# a server that refuses EVERY newAccount would pass the refusal on its own.
EAB_KID=tester
EAB_SECRET=$("$OSSL" rand 32 | "$OSSL" base64 -A | tr '+/' '-_' | tr -d '=')
pg_exec "INSERT INTO keys(kid,protocol,key) VALUES('$EAB_KID','eab','$EAB_SECRET');" >/dev/null
chk "the EAB credential is seeded"            1 \
    "$(pg_exec "SELECT count(*) FROM keys WHERE kid='$EAB_KID' AND protocol='eab';" | tr -d ' ')"

jws_newkey acct2.key
acme_post_newacct_eab acct2.key "$ACME_NEW_ACCT" "$EAB_KID" "$EAB_SECRET" || true
printf '%s\n' "$ACME_BODY" > eabacct.out
chk "newAccount WITH a binding is accepted"   201 "$ACME_STATUS"
chk "  and the account is bound to the kid"   1 \
    "$(pg_exec "SELECT count(*) FROM accounts WHERE kid='$EAB_KID';" | tr -d ' ')"
# ⚠️ A WRONG key must be refused, or the check above proves only that the field was
# PRESENT. This is the assertion that shows the HMAC is really verified — and it is the one
# that catches the -hmac/-macopt trap: `openssl dgst -hmac` takes a STRING key, so signing
# with the base64 TEXT instead of the decoded bytes would fail here and nowhere else.
jws_newkey acct3.key
WRONG=$("$OSSL" rand 32 | "$OSSL" base64 -A | tr '+/' '-_' | tr -d '=')
acme_post_newacct_eab acct3.key "$ACME_NEW_ACCT" "$EAB_KID" "$WRONG" || true
# 401, not 403: RFC 8555 §7.3.4 maps a bad binding to urn:...:error:unauthorized, and 401
# is that problem type's status. I expected 403 and the SERVER was right — asserting the
# problem type as well as the code is what makes this readable next time.
chk "  a WRONG HMAC key is refused"           401 "$ACME_STATUS"
chk "    with error:unauthorized"             yes \
    "$(printf '%s' "$ACME_BODY" | grep -q 'acme:error:unauthorized' && echo yes || echo no)"
chk "  and no second account was created"     1 \
    "$(pg_exec 'SELECT count(*) FROM accounts;' | tr -d ' ')"

# ⚠️ A member of the WRONG JSON TYPE, not merely absent. verify_eab() checked contains() and
# then called .get<std::string>(); nlohmann throws json::type_error, which is NOT pki::Error,
# so it flew past the catch above and reached the client as a bare 500 with no problem
# document. An ACME client can act on urn:...:error:unauthorized and cannot act on a 500 —
# and the difference is one malformed field any client can send unauthenticated.
jws_newkey acct4.key
acme_post_jwk acct4.key "$ACME_NEW_ACCT" \
  '{"termsOfServiceAgreed":true,"externalAccountBinding":{"protected":"e30","payload":7,"signature":"AA"}}' \
  || true
chk "  a non-string EAB member is refused"    401 "$ACME_STATUS"
chk "    as a problem document, not a 500"    yes \
    "$(printf '%s' "$ACME_BODY" | grep -q 'acme:error:unauthorized' && echo yes || echo no)"
chk "  and still no second account"           1 \
    "$(pg_exec 'SELECT count(*) FROM accounts;' | tr -d ' ')"

echo "=== and no suite anywhere sets the removed key ==="
# ⚠️ THIS GUARD IS THE INVERSE OF THE ONE IT REPLACES, and that is the whole point.
#
# It used to demand that every account-registering suite PIN ACME_EAB_REQUIRED=false,
# because the flipped default had broken them. The key is gone, so the same
# fourteen suites now register with a REAL binding instead — and the thing worth guarding
# is the opposite: nobody may bring the key back. A suite that sets it would be writing a
# config the parser ignores, which is silent, and if the key itself ever returned that
# suite would go quietly back to testing a configuration we do not ship.
#
# ⚠️ Strip comments, and name the two checkers rather than anchoring the pattern. Two traps
# in one line here:
#
#   1. This file, and most of the converted suites, mention the key in prose explaining why
#      it went — a bare grep flags every one of them. Fifth time here.
#   2. SELF-MATCH. Stripping comments is not enough: the guard's own grep pattern and its
#      own chk label are CODE, so the first version of this loop reported
#      acme_default_eab.sh and no_insecure_settings.sh — the two files doing the checking.
#      Same shape as a `pgrep -f` pattern matching its own command line. Those two are
#      skipped BY NAME, which is how the loop below handles its own exemption too.
#
# ⚠️ AND DO NOT ANCHOR TO A LINE-LEADING ASSIGNMENT. That assumed a suite sets a key as a
# config line in a heredoc, and the dominant idiom in this tree is appending to a conf that
# is already written (`echo "KEY=value" >> bootstrap.conf`, see est_serverkeygen.sh), with
# sed-injection close behind (crl.sh, ca_create_hsm.sh) and `fastpki-config set KEY value`
# writing the DB row with no `=` anywhere. The anchored pattern saw none of those, so it
# passed on every shape a suite is actually written in. The key does not exist in the
# parser, so ANY mention of it outside a comment is the thing to report.
sets_key=""
for f in "$ROOT"/tests/*.sh "$ROOT"/demo/*.sh; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in
        acme_default_eab.sh|no_insecure_settings.sh) continue ;;   # the two doing the checking
    esac
    grep -vE '^[[:space:]]*#' "$f" | grep -q 'ACME_EAB_REQUIRED' \
        && sets_key="$sets_key $(basename "$f")"
done
chk "no suite or demo names ACME_EAB_REQUIRED in code" "" "$sets_key"

# And the suites that DO register must be reaching newAccount with a binding — otherwise
# "nobody sets the key" would also be satisfied by nobody registering at all.
echo "=== the account-registering suites still register, and register bound ==="
n_sel=0; unbound=""
for f in "$ROOT"/tests/*.sh; do
    b=$(basename "$f")
    [ "$b" = "acme_default_eab.sh" ] && continue      # this one registers UNBOUND on purpose
    # A device registers unbound by design (device-attest-01: the attestation replaces the
    # binding), and that suite asserts the refusal when no ticket is outstanding.
    [ "$b" = "acme_device_attest.sh" ] && continue
    grep -qE '^ACME_PORT=|^ACME_BIND=' "$f" || continue
    # ⚠️ THIS SELECTOR USED TO MATCH THE WORD `certbot` ANYWHERE, comments included,
    # and it went red on demo_clients.sh — a suite that has never registered an account.
    # Two separate mistakes met:
    #
    #   1. Asymmetry. The line below stripped nothing while the binding check underneath
    #      strips comments, so a file could be SELECTED on the strength of a comment and
    #      then JUDGED on code alone. Any suite that merely talks about certbot was
    #      guaranteed to be reported unbound.
    #   2. `certbot` in prose. demo_clients.sh drives the shipped demo scripts and asserts
    #      things ABOUT them — `chk "bench: certbot uses --webroot" ...` is an assertion
    #      LABEL, not an invocation. (What put it over the line was a bootstrap.conf being added
    #      heredoc with `ACME_PORT=1` in it, which is how it started matching the first
    #      filter at all.)
    #
    # So: strip comments here too, and require certbot in COMMAND POSITION — start of a
    # pipeline, or behind `command -v`. Registration through the shell helpers counts as
    # well; a suite that calls acme_new_account is registering just as much as one that
    # shells out. Widening those beats the old list: 13 suites selected where the buggy
    # version found 12, and the two it had been missing (acme_preauth_alpn,
    # acme_retry_after) really do register.
    grep -vE '^[[:space:]]*#' "$f" \
        | grep -qE 'acme_new_account|acme_post_newacct_eab|acme_dns01_order|ACME_NEW_ACCT|(^|[;&|(]|command -v )[[:space:]]*certbot[[:space:]]' \
        || continue
    n_sel=$((n_sel+1))
    # A binding arrives one of three ways: the shell helper, an explicit EAB post, or
    # certbot's own flags.
    grep -vE '^[[:space:]]*#' "$f" \
        | grep -qE 'acme_new_account|acme_post_newacct_eab|acme_dns01_order|eab-kid' \
        || unbound="$unbound $b"
done
chk "every account-registering suite binds" "" "$unbound"
# The selector must actually select something, or both loops above are no-ops that pass on
# an empty tree — the vacuous shape this repo keeps hitting. 13 today.
chk "  ... and the selector is not matching nothing" yes \
    "$([ "$n_sel" -ge 10 ] && echo yes || echo "no (only $n_sel)")"

[ "$fail" -eq 0 ] || { echo "--- newAccount said:"; head -20 newacct.out; echo "--- server:"; tail -10 srv.log; }
echo
echo "=== ACME DEFAULT EAB: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
