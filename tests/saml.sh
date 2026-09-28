#!/usr/bin/env bash
# SAML 2.0 SSO console login. Drives the full
# SP-initiated Web SSO flow against a mock IdP (tests/mock_saml.py) that returns
# a real xmlsec1-signed assertion: status, AuthnRequest -> signed Response -> ACS
# session, group->role mapping, local-user-wins, plus the security-critical
# rejections — replay (InResponseTo one-shot), tampered assertion (bad signature),
# and a wrong-signer cert (trust is pinned to the provider's idp_cert).
#
# Self-skips when python3 or xmlsec1 is unavailable, or when fastpki-web was built
# without -DFASTPKI_WITH_SAML (then /api/saml/status reports enabled:false).
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="${WEB:-$ROOT/build/fastpki-web}"
PY=$(command -v python3 || true)
XMLSEC=$(command -v xmlsec1 || true)
if [ -z "$PY" ]; then echo "SKIP: python3 not available (mock SAML IdP needs it)"; exit 0; fi
if [ -z "$XMLSEC" ]; then echo "SKIP: xmlsec1 CLI not available (mock SAML IdP signs with it)"; exit 0; fi
[ -x "$WEB" ] || { echo "SKIP: $WEB not built"; exit 0; }

W="$(mktemp -d)"; cd "$W"; MP=18230; MP2=18231; WP=18232; WP2=18233
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
# ⚠️ FIXED STRING, NOT A PATTERN. A federated login is stored and reported as
# `<provider>\<user>`, and JSON escapes that backslash to TWO characters -- as a grep
# pattern a backslash escapes what follows, so the obvious spelling silently misses.
hasf(){ echo "$1" | grep -qF "$2" && echo yes || echo no; }
juser(){ printf '"user":"%s\\\\%s"' "$1" "$2"; }

# IdP signing keypair (trusted) + an attacker keypair (must be rejected).
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout idp.key -out idp.crt -days 2 -subj "/CN=mock-idp" >/dev/null 2>&1
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout evil.key -out evil.crt -days 2 -subj "/CN=evil-idp" >/dev/null 2>&1
pg_setup saml; pg_setup saml2
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT

IDP_ENTITY="https://mock-idp.test/idp"; SP_ENTITY="https://fastpki.test/sp"
start_idp(){ # $1=port $2=key $3=cert
  MOCK_PORT=$1 MOCK_KEY="$W/$2" MOCK_CERT="$W/$3" MOCK_IDP_ENTITY="$IDP_ENTITY" \
    MOCK_SP_ENTITY="$SP_ENTITY" MOCK_USER="alice@example.org" MOCK_GROUPS="pki-admins" \
    MOCK_GROUPS_ATTR="groups" MOCK_XMLSEC="$XMLSEC" exec "$PY" "$ROOT/tests/mock_saml.py" ; }
# ⚠️ `exec` is load-bearing. `start_idp … &` backgrounds a SUBSHELL; without exec the
# python is that subshell's CHILD, so $! is the wrapper and `kill $MOCK` reaps the
# wrapper while python is reparented to init and keeps the port. Measured: two orphaned
# mock IdPs (ppid 1) still holding 18230/18231 after the suite exited, which then broke
# notify_web.sh — a DIFFERENT suite, on the same ports — with a bare "listen failed".
# With exec the subshell BECOMES python, so $! is the process the trap needs to kill.
P=""; P2=""   # web PIDs (set later); pre-declared so the EXIT trap is set -u safe
start_idp $MP  idp.key  idp.crt  >mock.log 2>&1 & MOCK=$!
start_idp $MP2 evil.key evil.crt >mock2.log 2>&1 & MOCK2=$!
trap 'pg_cleanup; kill $MOCK $MOCK2 $P $P2 2>/dev/null' EXIT
# Both IdPs, not just one: a single fixed sleep covered two launches and the second was
# the one more likely to still be starting (wait_port, pg_helpers.sh).
wait_port "$MP"  "$MOCK"  || true
wait_port "$MP2" "$MOCK2" || true

# ⚠️ THE SETTINGS ARE A ROW, NOT CONFIG. There is no SAML_* config key any more: an
# entityID, an SSO URL and a pinned IdP certificate are per-provider values, and a flat
# file could name exactly one identity provider. Seed the pair of rows the server reads —
# `auth_providers` declares a provider of this kind, `saml_providers` carries its
# settings — before the server starts, because it resolves the provider once at startup.
#   seed_saml <acs-port, unused: the ACS address is the node's own> <require_local_user:true|false>
seed_saml(){
  pg_exec "
    INSERT INTO auth_providers(id,kind,display_name,enabled,priority,created,updated)
      VALUES('default-saml','saml','SAML',true,100,0,0)
      ON CONFLICT (id) DO UPDATE SET enabled=true;
    INSERT INTO saml_providers(provider_id,idp_entity_id,idp_sso_url,idp_cert,
                               sp_entity_id,admin_group,auditor_group,
                               require_local_user)
      VALUES('default-saml','$IDP_ENTITY','http://127.0.0.1:$MP/sso','$W/idp.crt',
             '$SP_ENTITY','pki-admins','pki-auditors',$2)
      ON CONFLICT (provider_id) DO UPDATE SET
             require_local_user=EXCLUDED.require_local_user;" >/dev/null
}

saml_conf(){ cat <<EOF
WEB_BIND=127.0.0.1
WEB_PORT=$1
WEB_TOKEN=t0
WEB_ALLOW_REVOKE=true
$2
LOG_LEVEL=err
EOF
}

# Fetch a fresh, signed SAMLResponse for a real (server-issued) AuthnRequest.
# $1 = web base URL, $2 = IdP port to actually sign it (MP=trusted, MP2=attacker).
get_resp(){
  local loc; loc=$(curl -s -D - -o /dev/null "$1/api/saml/login" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
  loc=$(echo "$loc" | sed "s/:$MP\//:$2\//")
  curl -s "$loc" | grep -o 'name="SAMLResponse" value="[^"]*"' | sed 's/.*value="//; s/"$//'
}
post_acs(){ curl -s -o /dev/null -c "$2" -b "$2" --data-urlencode "SAMLResponse=$1" --data-urlencode "RelayState=/" "$3/api/saml/acs"; }

echo "=== SAML SSO: group -> role mapping ==="
seed_saml "$WP" false
saml_conf "$WP" "" > web.conf
"$WEB" --config web.conf >web.log 2>&1 & P=$!
sleep 1; if ! kill -0 $P 2>/dev/null; then echo "web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$WP"
ST=$(curl -s "$U/api/saml/status")
if [ "$(has "$ST" '"enabled":true')" != yes ]; then
  echo "SKIP: fastpki-web built without FASTPKI_WITH_SAML (status: $ST)"; exit 0
fi
chk "SAML status reports enabled" yes "$(has "$ST" '"enabled":true')"
chk "unauthenticated -> 401" 401 "$(curl -s -o /dev/null -w '%{http_code}' "$U/api/me")"
chk "metadata is served" yes "$(has "$(curl -s "$U/api/saml/metadata")" 'AssertionConsumerService')"

R=$(get_resp "$U" "$MP"); post_acs "$R" j1.cj "$U"
ME=$(curl -s -b j1.cj "$U/api/me")
chk "signed assertion created a session for the IdP user" yes "$(hasf "$ME" "$(juser default-saml alice@example.org)")"
chk "group pki-admins mapped to admin role" yes "$(has "$ME" '"role":"admin"')"

echo "=== replay is rejected (InResponseTo is one-shot) ==="
R2=$(get_resp "$U" "$MP")
post_acs "$R2" jr1.cj "$U"            # first use: succeeds
chk "first use establishes a session" 200 "$(curl -s -o /dev/null -w '%{http_code}' -b jr1.cj "$U/api/me")"
post_acs "$R2" jr2.cj "$U"            # replay: InResponseTo already consumed
chk "replayed Response -> no session" 401 "$(curl -s -o /dev/null -w '%{http_code}' -b jr2.cj "$U/api/me")"

echo "=== a tampered assertion is rejected (signature breaks) ==="
R3=$(get_resp "$U" "$MP"); echo "$R3" | base64 -d > tr.xml
sed 's/alice@example.org/eviluser@example.org/' tr.xml > tr2.xml
RT=$(base64 tr2.xml | tr -d '\n')
post_acs "$RT" jt.cj "$U"
chk "tampered NameID -> no session" 401 "$(curl -s -o /dev/null -w '%{http_code}' -b jt.cj "$U/api/me")"

echo "=== TWO providers at once: each signs in, with ITS OWN trust and ITS OWN groups ==="
# ⚠️ THE POINT OF THE TICKET, AND UNTESTABLE UNTIL NOW. The console resolved "the first
# enabled provider" once at startup, so a second SAML row was storable, manageable and
# replicated — and could not sign anybody in. Two rows now, with DIFFERENT IdP certificates
# and DIFFERENT admin groups, so a pass here cannot come from them being interchangeable.
#
# `evil.crt` is the same key the wrong-signer case below rejects. That is deliberate: the
# one thing separating "a second legitimate IdP" from "an attacker" is whether a provider
# row vouches for that certificate. Registering it makes MP2 legitimate FOR THAT PROVIDER
# and leaves it untrusted for the first one, which is exactly the property being claimed.
pg_exec "
  INSERT INTO auth_providers(id,kind,display_name,enabled,priority,created,updated)
    VALUES('partner-saml','saml','Partner',true,200,0,0)
    ON CONFLICT (id) DO UPDATE SET enabled=true;
  INSERT INTO saml_providers(provider_id,idp_entity_id,idp_sso_url,idp_cert,
                             sp_entity_id,admin_group,auditor_group,
                             require_local_user)
    VALUES('partner-saml','$IDP_ENTITY','http://127.0.0.1:$MP2/sso','$W/evil.crt',
           '$SP_ENTITY','partner-admins','partner-auditors',false)
    ON CONFLICT (provider_id) DO UPDATE SET idp_cert=EXCLUDED.idp_cert;" >/dev/null

# ⚠️ NO RESTART. The provider is resolved per request now, so a row added while the server
# is running is usable immediately — the same rule the CA material follows. If this ever
# needs a restart to pass, the resolution has silently gone back to being cached.
LOC2=$(curl -s -D - -o /dev/null "$U/api/saml/login?provider=partner-saml" \
        | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
chk "a second provider issues its own AuthnRequest" yes \
    "$([ -n "$LOC2" ] && echo yes || echo no)"
# It must go to the SECOND IdP, not the first: the redirect target is the provider's own
# idp_sso_url, and sending the user to the wrong IdP is the failure this whole change is about.
chk "  and it points at that provider's IdP, not the first one" yes \
    "$(printf '%s' "$LOC2" | grep -q ":$MP2/" && echo yes || echo no)"

R4=$(curl -s "$LOC2" | grep -o 'name="SAMLResponse" value="[^"]*"' | sed 's/.*value="//; s/"$//')
post_acs "$R4" jp.cj "$U"
MEP=$(curl -s -b jp.cj "$U/api/me")
chk "the second provider signs a user in" 200 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b jp.cj "$U/api/me")"
# ⚠️ AND THE ROLE COMES FROM THE SECOND PROVIDER'S GROUPS. This is the half that was still
# wrong after the assertion was being verified correctly: federated_role() read the STARTUP
# row, so a partner identity was mapped through the FIRST provider's admin_group. The IdP
# asserts `pki-admins`, which is admin for `default-saml` and means nothing for
# `partner-saml` — so a role of admin here would prove the wrong row was consulted.
# ⚠️ ASSERTED AS ONE VALUE, BECAUSE "not admin" IS ALSO TRUE OF A FAILED LOGIN. Written as
# a bare `role != admin` this passes when the session was never created — green in exactly
# the case it exists to catch. So it demands BOTH: a real session for the IdP's user, AND a
# role that did not come from the other provider's group.
chk "  mapped by ITS OWN groups, not the first provider's" "signed-in,not-admin" \
    "$(printf '%s,%s' \
        "$([ "$(hasf "$MEP" "$(juser partner-saml alice@example.org)")" = yes ] && echo signed-in || echo no-session)" \
        "$([ "$(has "$MEP" '"role":"admin"')" = yes ] && echo admin || echo not-admin)")"

# ⚠️ AND THE SIGN-IN PAGE MUST OFFER BOTH, or "the user picks one" is a claim about an
# API nobody can reach. The page used to ask /api/oidc/status and only fall back to SAML if
# that said no — so with both kinds configured the SAML button was unreachable, and with
# two providers of one kind the second was unreachable full stop.
IDPS=$(curl -s "$U/api/auth-idps")
chk "the pre-auth list offers BOTH providers" 2 \
    "$(printf '%s' "$IDPS" | grep -o '"kind":"saml"' | grep -c . | tr -d ' ')"
chk "  and names each one" yes \
    "$(printf '%s' "$IDPS" | grep -q 'Partner' && printf '%s' "$IDPS" | grep -q 'default-saml' \
       && echo yes || echo no)"
# ⚠️ IT IS PRE-AUTH, so it must carry nothing an anonymous visitor should not have. The
# admin view (/api/auth-providers, config:manage) is where certificates and secrets live.
chk "  and leaks no provider internals" yes \
    "$(printf '%s' "$IDPS" | grep -qE 'idp_cert|client_secret|idp_sso_url|sp_entity' \
       && echo no || echo yes)"

chk "an unknown provider id is refused, and named" 404 \
    "$(curl -s -o /dev/null -w '%{http_code}' "$U/api/saml/login?provider=no-such-idp")"
chk "  the message names what was asked for" yes \
    "$(curl -s "$U/api/saml/login?provider=no-such-idp" | grep -q "no-such-idp" && echo yes || echo no)"

# ⚠️ HAND THE SUITE BACK THE WORLD IT LENT US. Everything below assumes ONE enabled
# provider; leaving `partner-saml` behind changed which row answers a bare /api/saml/login
# and broke "local web_users role (auditor) is used" three sections later — a failure with
# nothing to do with the code it was testing. Disabled, not deleted, so the rows stay
# visible for anyone reading the database after a failed run.
pg_exec "UPDATE auth_providers SET enabled=false WHERE id='partner-saml';" >/dev/null
# ⚠️ AND THE USER ROW THIS SECTION CAUSED. Signing in through the partner provider onboards
# alice as a brand-new federated identity — her `pki-admins` group means nothing to THAT
# provider — and a brand-new user is PERSISTED so an admin can assign a role later. The
# section below then does a bare INSERT for the same username with no ON CONFLICT clause,
# which fails on the duplicate key, leaves the role as onboarded, and reports
# "local web_users role (auditor) is used" as a product failure. It is not: it is this
# section's leftover. Measured, after disabling the provider alone did not fix it.
pg_exec "DELETE FROM web_users WHERE username='default-saml\\alice@example.org';" >/dev/null
chk "  and the second provider is stood down for the sections that follow" 1 \
    "$(pg_exec "SELECT count(*) FROM auth_providers WHERE id='partner-saml' AND enabled=false;" 2>/dev/null | tr -d ' ')"

echo "=== a wrong-signer cert is rejected (trust is pinned) ==="
RE=$(get_resp "$U" "$MP2")           # validly-structured but signed by evil.key
post_acs "$RE" je.cj "$U"
chk "assertion signed by untrusted key -> no session" 401 "$(curl -s -o /dev/null -w '%{http_code}' -b je.cj "$U/api/me")"

echo "=== a local user record wins over the group mapping ==="
# ⚠️ NO `scope` COLUMN. Step 0008 dropped it (`ALTER TABLE web_users DROP COLUMN IF EXISTS
# scope`), so this INSERT failed outright and the row was never created — federated_role
# then found no local user and fell through to the group mapping, which is what the
# assertion below saw. The product was right the whole time. Nothing caught it because
# saml.sh needs xmlsec and had never run on any machine.
pg_exec "INSERT INTO web_users(username,role,hash,must_reset,created) VALUES('default-saml\\alice@example.org','auditor','x',0,0);"
R4=$(get_resp "$U" "$MP"); post_acs "$R4" j2.cj "$U"
chk "local web_users role (auditor) is used" yes "$(has "$(curl -s -b j2.cj "$U/api/me")" '"role":"auditor"')"

echo "=== A federated login mints the user's enrolment credentials ==="
# The question was whether LDAP/SAML/OIDC users get a CMP secret and an ACME EAB key the
# way local users do. They did not: ensure_enrolment_creds() was only reached from
# POST /api/users and `fastpki-config web-user`. Decommissioning the global
# CMP_PBM_SECRET without this leaves every federated identity unable to use CMP PBM.
#
# alice is 'auditor' here, which does NOT enrol, so nothing should be minted for her —
# minting for a role that cannot enrol would hand out a live credential nobody should
# hold. Give her a role that DOES enrol and log in again; the secrets appear.
#
# ⚠️ CLEAR THE ROWS FIRST, and this is not tidiness. alice logged in as a group-mapped
# ADMIN several times higher up (the mapping and replay sections), and admin DOES enrol,
# so her credentials already exist by the time we get here. Without the delete this
# assertion reads the earlier logins' work and fails.
#
# It fails only where SAML logins actually succeed. On macOS none do, so `keys` is empty
# for the opposite reason and the assertion passed — vacuously, proving nothing. The lab
# run on the shipped image is what caught it (expected '0' got '1'). An assertion that
# passes because the thing under test never ran is the failure mode this suite exists to
# avoid, so measure THIS login, not the suite's history.
# ⚠️ THE CLEANUP AND THE ASSERTION MUST NAME THE SAME KEY. This delete used to match
# the bare name while the count below reads the qualified subject, so it silently cleared
# nothing and the assertion measured the earlier admin logins instead of this one --
# exactly the history-reading failure the paragraph above exists to prevent.
# Equality, not LIKE: in a LIKE pattern Postgres treats the backslash as an ESCAPE, so
# `default-saml\alice` would match the literal `default-samlalice` and never fire.
pg_exec "DELETE FROM keys WHERE kid = 'default-saml\\alice@example.org';" >/dev/null
R4a=$(get_resp "$U" "$MP"); post_acs "$R4a" j2a.cj "$U"
chk "an auditor login mints NO enrolment credentials" 0 \
    "$(pg_exec "select count(*) from keys where kid='default-saml\\alice@example.org';")"
pg_exec "UPDATE web_users SET role='requester' WHERE username='default-saml\\alice@example.org';" >/dev/null
R4b=$(get_resp "$U" "$MP"); post_acs "$R4b" j2b.cj "$U"
chk "a requester's CMP secret is minted at login"  1 \
    "$(pg_exec "select count(*) from keys where kid='default-saml\\alice@example.org' AND protocol='cmp';")"
chk "  and the ACME EAB key alongside it"          1 \
    "$(pg_exec "select count(*) from keys where kid='default-saml\\alice@example.org' AND protocol='eab';")"
# Idempotent: a second login must not churn the secret a client already holds.
S1=$(pg_exec "select key from keys where kid='default-saml\\alice@example.org' AND protocol='cmp';")
R4c=$(get_resp "$U" "$MP"); post_acs "$R4c" j2c.cj "$U"
chk "  a second login does not rotate it"          yes \
    "$([ "$S1" = "$(pg_exec "select key from keys where kid='default-saml\\alice@example.org' AND protocol='cmp';")" ] && echo yes || echo no)"
kill $P 2>/dev/null; wait $P 2>/dev/null

echo "=== require_local_user rejects an unprovisioned identity ==="
# ⚠️ alice MUST NOT have a local row here — that is the whole point of this section, and
# both web instances share one database. She was provisioned above, so remove her first.
#
# This assertion used to pass only because the INSERT above silently failed on the dropped
# `scope` column: alice was never provisioned at all, so "no local row" was accidentally
# true. Fixing that seed turned this green check red — a passing test resting on a broken
# one, which is worse than either failure alone.
pg_exec "DELETE FROM web_users WHERE username='default-saml\\alice@example.org';"
pg_exec "INSERT INTO web_users(username,role,hash,must_reset,created) VALUES('bob','admin','x',0,0);"
# ⚠️ ONE DATABASE, so ONE provider row — and the two servers need opposite values of
# require_local_user. That works only because the provider is resolved ONCE at startup:
# the first server is already holding its own snapshot (false) when this rewrites the row,
# and the second reads the new value when it starts. Re-seeding also restores the ACS URL
# to this server's own port.
seed_saml "$WP2" true
saml_conf "$WP2" "" > web2.conf
"$WEB" --config web2.conf >web2.log 2>&1 & P2=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web2.conf" WEB_PORT "$P2" || true
U2="http://127.0.0.1:$WP2"
R5=$(get_resp "$U2" "$MP"); post_acs "$R5" j3.cj "$U2"
chk "alice (no local row) is refused -> no session" 401 "$(curl -s -o /dev/null -w '%{http_code}' -b j3.cj "$U2/api/me")"

echo
echo "=== SAML: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
