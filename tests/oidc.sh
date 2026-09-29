#!/usr/bin/env bash
# OIDC SSO console login. Drives the full Authorization
# Code + PKCE flow against a mock IdP (tests/mock_oidc.py) that returns a real
# RS256-signed id_token: status, login -> session, group->role mapping, local
# user wins over group, invalid-state rejection, and require_local_user.
# Self-skips without python3.
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
WEB="$ROOT/build/fastpki-web"
PY=$(command -v python3 || true)
if [ -z "$PY" ]; then echo "SKIP: python3 not available (mock OIDC provider needs it)"; exit 0; fi
W="$(mktemp -d)"; cd "$W"; MP=18210; WP=18211; WP2=18212; MP2=18214; WP4=18215; WP5=18216
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
# ⚠️ MATCH THE QUALIFIED SUBJECT AS A FIXED STRING. A login is stored and reported as
# `<provider>\<user>`, and JSON escapes that backslash to TWO characters -- as a grep
# PATTERN a backslash then means "escape the next thing", so the obvious spelling either
# fails to match or matches something else. `grep -F` removes the question.
hasf(){ echo "$1" | grep -qF "$2" && echo yes || echo no; }
# The subject as it appears INSIDE json: one backslash written as two.
juser(){ printf '"user":"%s\\\\%s"' "$1" "$2"; }

"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out idp.key >/dev/null 2>&1
pg_setup oidc; PG_CONNINFO1="$PG_CONNINFO"; PGDATABASE1="$PGDATABASE"
pg_setup oidc2
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
ISS="http://127.0.0.1:$MP"
MOCK_PORT=$MP MOCK_ISSUER="$ISS" MOCK_CLIENT_ID=fastpki MOCK_KEY="$W/idp.key" \
  MOCK_USER="alice@example.org" MOCK_GROUPS="pki-admins" MOCK_OSSL="$OSSL" \
  "$PY" "$ROOT/tests/mock_oidc.py" >mock.log 2>&1 & MOCK=$!
P=""; P2=""; P4=""; MOCK2=""
trap 'pg_cleanup; kill $MOCK $MOCK2 $P $P2 $P4 2>/dev/null' EXIT
# Poll the mock IdP's port, do not sleep at it (wait_port, pg_helpers.sh).
wait_port "$MP" "$MOCK" || true
chk "mock IdP discovery is up" yes "$(has "$(curl -s "$ISS/.well-known/openid-configuration")" 'authorization_endpoint')"

# ⚠️ THE SETTINGS ARE A ROW, NOT CONFIG. There is no OIDC_* config key any more: an
# issuer, a client and a secret are per-provider values, and a flat file could name
# exactly one of each. Seed the pair of rows the server actually reads — `auth_providers`
# says a provider of this kind exists and is enabled, `oidc_providers` carries its
# settings — into the database this server will open, BEFORE it starts, because the
# console resolves the provider once at startup.
#   seed_oidc <dbname> <issuer> <web-port, unused: the callback is the node's own> <require_local_user:true|false>
seed_oidc(){
  "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$1" -tAq -c "
    INSERT INTO auth_providers(id,kind,display_name,enabled,priority,created,updated)
      VALUES('default-oidc','oidc','OIDC',true,100,0,0)
      ON CONFLICT (id) DO UPDATE SET enabled=true;
    INSERT INTO oidc_providers(provider_id,issuer,client_id,client_secret,
                               admin_group,auditor_group,require_local_user)
      VALUES('default-oidc','$2','fastpki','secret',
             'pki-admins','pki-auditors',$4)
      ON CONFLICT (provider_id) DO UPDATE SET issuer=EXCLUDED.issuer,
             require_local_user=EXCLUDED.require_local_user;" >/dev/null
}

oidc_conf(){ cat <<EOF
PG_CONNINFO=$1
WEB_BIND=127.0.0.1
WEB_PORT=$2
# ⚠️ THE NODE HAS TO KNOW ITS OWN NAME. The OIDC callback is derived from this node's own
# config — the provider tables replicate and hold no callback, because one stored
# value cannot serve a mesh where every console has its own FQDN. So PKI_DNS is not
# decoration here: leave it at the shipped placeholder and the node asks the IdP to send
# the browser to pki.example.org, which is nobody. A real node sets it; so does this one.
PKI_DNS=127.0.0.1
WEB_TOKEN=t0
WEB_ALLOW_REVOKE=true
$3
LOG_LEVEL=err
EOF
}

echo "=== OIDC SSO: group -> role mapping ==="
seed_oidc "$PGDATABASE1" "$ISS" "$WP" false
oidc_conf "$PG_CONNINFO1" "$WP" "" > web.conf
"$WEB" --config web.conf >web.log 2>&1 & P=$!
sleep 1; if ! kill -0 $P 2>/dev/null; then echo "web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$WP"
chk "OIDC status reports enabled" yes "$(has "$(curl -s "$U/api/oidc/status")" '"enabled":true')"
chk "unauthenticated -> 401" 401 "$(curl -s -o /dev/null -w '%{http_code}' "$U/api/me")"
curl -s -L -c j1.cj "$U/api/oidc/login" >/dev/null
ME=$(curl -s -b j1.cj "$U/api/me")
chk "SSO created a session for the IdP user" yes "$(hasf "$ME" "$(juser default-oidc alice@example.org)")"
chk "group pki-admins mapped to admin role" yes "$(has "$ME" '"role":"admin"')"
chk "invalid callback state -> 400" 400 "$(curl -s -o /dev/null -w '%{http_code}' "$U/api/oidc/callback?code=x&state=bogus")"

echo "=== a local user record wins over the group mapping ==="
PGDATABASE=$PGDATABASE1 pg_exec "INSERT INTO web_users(username,role,hash,must_reset,created) VALUES('default-oidc\\alice@example.org','auditor','x',0,0);"
curl -s -L -c j2.cj "$U/api/oidc/login" >/dev/null
chk "local web_users role (auditor) is used" yes "$(has "$(curl -s -b j2.cj "$U/api/me")" '"role":"auditor"')"
kill $P 2>/dev/null; wait $P 2>/dev/null

echo "=== require_local_user rejects an unprovisioned identity ==="
pg_exec "INSERT INTO web_users(username,role,hash,must_reset,created) VALUES('bob','admin','x',0,0);"
seed_oidc "$PGDATABASE" "$ISS" "$WP2" true
oidc_conf "$PG_CONNINFO" "$WP2" "" > web2.conf
"$WEB" --config web2.conf >web2.log 2>&1 & P2=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web2.conf" WEB_PORT "$P2" || true
U2="http://127.0.0.1:$WP2"
curl -s -L -c j3.cj "$U2/api/oidc/login" >/dev/null
chk "alice (no local row) is refused -> no session" 401 "$(curl -s -o /dev/null -w '%{http_code}' -b j3.cj "$U2/api/me")"

echo "=== an IdP with NO groups claim maps the role from the local user ==="
# Google (and many IdPs) send no groups claim, so the console role can't come
# from the provider's admin_group/auditor_group. It must come from the user's local
# web_users record — the console-RBAC namespace, NOT an issuance profile.
# A groups-less mock IdP + a pre-provisioned local requester proves it.
#
# Step 2b: this used to assert a per-user `scope` came back too. Scope is no
# longer a property of the user — it comes from the CA ids on the grants of the roles
# held — so what an SSO login must carry over from the local record is the ROLE, and
# the scope follows from that wherever the role is scoped.
ISS2="http://127.0.0.1:$MP2"
MOCK_PORT=$MP2 MOCK_ISSUER="$ISS2" MOCK_CLIENT_ID=fastpki MOCK_KEY="$W/idp.key" \
  MOCK_USER="nogroups@example.org" MOCK_GROUPS="" MOCK_OSSL="$OSSL" \
  "$PY" "$ROOT/tests/mock_oidc.py" >mock2.log 2>&1 & MOCK2=$!
# Poll the mock IdP's port, do not sleep at it (wait_port, pg_helpers.sh).
wait_port "$MP2" "$MOCK2" || true
chk "groups-less mock IdP is up" yes "$(has "$(curl -s "$ISS2/.well-known/openid-configuration")" 'authorization_endpoint')"
pg_setup oidc3; PG_CONNINFO3="$PG_CONNINFO"
# The Google-style user, pre-provisioned locally as a requester. Onboarding would give
# it `none`, so seeing `requester` back proves the local record was consulted.
pg_exec "INSERT INTO web_users(username,role,hash,must_reset,created) VALUES('default-oidc\\nogroups@example.org','requester','x',0,0);"
seed_oidc "$PGDATABASE" "$ISS2" "$WP4" false
oidc_conf "$PG_CONNINFO3" "$WP4" "" > web4.conf
"$WEB" --config web4.conf >web4.log 2>&1 & P4=$!
sleep 1; if ! kill -0 $P4 2>/dev/null; then echo "web died:"; cat web4.log; exit 1; fi
U4="http://127.0.0.1:$WP4"
curl -s -L -c j5.cj "$U4/api/oidc/login" >/dev/null
ME4=$(curl -s -b j5.cj "$U4/api/me")
chk "no-groups SSO created a session"               yes "$(hasf "$ME4" "$(juser default-oidc nogroups@example.org)")"
chk "role resolved from local record (requester)"   yes "$(has "$ME4" '"role":"requester"')"

# --- Two OIDC providers live at once, and the user picks --------------------
# Both mocks are already running: mock 1 asserts alice@example.org in pki-admins,
# mock 2 asserts nogroups@example.org with no groups. Registering BOTH against
# this one server makes the returned USERNAME name the provider that was used --
# a discriminator no amount of provider mix-up can satisfy by accident.
#
# The two rows deliberately disagree on admin_group. Authenticating against the
# right issuer but mapping roles through the other row's groups is a distinct
# defect from picking the wrong issuer, and it is the one that grants admin, so
# it gets its own assertion rather than riding along on the login working.
pg_exec "UPDATE oidc_providers SET admin_group='corp-admins' WHERE provider_id='default-oidc';
  INSERT INTO auth_providers(id,kind,display_name,enabled,priority,created,updated)
    VALUES('partner-oidc','oidc','Partner',true,200,0,0);
  INSERT INTO oidc_providers(provider_id,issuer,client_id,client_secret,
                             admin_group,auditor_group,require_local_user)
    VALUES('partner-oidc','$ISS','fastpki','secret',
           'pki-admins','pki-auditors',false);"
IDPS=$(curl -s "$U4/api/auth-idps")
chk "both providers are offered to the sign-in page" 2 \
    "$(printf '%s' "$IDPS" | grep -o '"id"' | wc -l | tr -d ' ')"
chk "  the partner provider is named"       yes "$(has "$IDPS" 'partner-oidc')"
curl -s -L -c j6.cj "$U4/api/oidc/login?provider=partner-oidc" >/dev/null
ME6=$(curl -s -b j6.cj "$U4/api/me")
chk "chosen provider authenticated its own user" yes "$(hasf "$ME6" "$(juser partner-oidc alice@example.org)")"
chk "  role mapped through THAT provider's groups" yes "$(has "$ME6" '"role":"admin"')"
# The default must not shift because a second provider exists.
curl -s -L -c j7.cj "$U4/api/oidc/login" >/dev/null
chk "no provider named still uses the default" yes \
    "$(hasf "$(curl -s -b j7.cj "$U4/api/me")" "$(juser default-oidc nogroups@example.org)")"
# An unknown id must not fall back to "whatever is first" -- that fallback is how
# a mistyped provider silently authenticates against the wrong IdP.
chk "unknown provider id is refused, not defaulted" no \
    "$(has "$(curl -s -L -c j8.cj "$U4/api/oidc/login?provider=nope" -o /dev/null -w '%{http_code}'; curl -s -b j8.cj "$U4/api/me")" '"user":"')"

# --- one name, two providers: the row must belong to ONE of them ---------------
# The sharp case for qualification. A THIRD provider is registered against mock 1, so it
# asserts the SAME username as the corp provider -- which is the whole risk of running
# providers side by side: any IdP can claim to be `alice@example.org`.
#
# Its admin_group is one mock 1 does NOT assert, so the only route to `admin` is finding
# a local row. A BARE row is seeded holding exactly that: the key the login used to look
# up. Before qualification the rogue provider's login found it and became admin; now the
# lookup is for `rogue-oidc\alice@...` and the bare row is not it.
pg_exec "INSERT INTO web_users(username,role,hash,must_reset,created)
           VALUES('alice@example.org','admin','x',0,0)
           ON CONFLICT (username) DO UPDATE SET role='admin';
  INSERT INTO auth_providers(id,kind,display_name,enabled,priority,created,updated)
    VALUES('rogue-oidc','oidc','Rogue',true,300,0,0);
  INSERT INTO oidc_providers(provider_id,issuer,client_id,client_secret,
                             admin_group,auditor_group,require_local_user)
    VALUES('rogue-oidc','$ISS','fastpki','secret',
           'admins-of-a-group-this-idp-never-asserts','none-either',false);"
curl -s -L -c j9.cj "$U4/api/oidc/login?provider=rogue-oidc" >/dev/null
ME9=$(curl -s -b j9.cj "$U4/api/me")
chk "a same-named login is a DIFFERENT subject" yes \
    "$(hasf "$ME9" "$(juser rogue-oidc alice@example.org)")"
chk "  and does NOT inherit the bare row's admin" no "$(has "$ME9" '"role":"admin"')"

echo "=== a provider added AFTER startup completes a login, with no restart ==="
# ⚠️ EVERY SECTION ABOVE SEEDS THE PROVIDER AND THEN STARTS THE SERVER, so none of them
# could see this: /api/oidc/callback, /api/oidc/status and /api/saml/{status,metadata,acs}
# gated on OidcClient/SamlSp objects built ONCE at startup, while /api/oidc/login resolved
# the row per request. A fresh deployment boots with zero SSO rows — which is how every
# deployment boots — so an admin who adds a provider on the console got a correct redirect
# to the IdP and a 404 on the way back, for as long as the service stayed up.
#
# Order is the whole test: start with NO rows, seed afterwards, and never restart.
U5="http://127.0.0.1:$WP5"
# ⚠️ THE ROWS GO BEFORE THE SERVER STARTS, and the order is the entire reproduction.
# Deleting them AFTER boot proves nothing: the unfixed build snapshots whatever existed at
# startup, so with the earlier sections' rows still present it reported "enabled" and the
# two assertions below passed against the very bug they exist to catch. Caught by reverting
# the fix and re-running, which is the only way that class of mistake shows up.
pg_exec "DELETE FROM oidc_providers; DELETE FROM auth_providers WHERE kind='oidc';" >/dev/null
oidc_conf "$PG_CONNINFO" "$WP5" "" > web5.conf
"$WEB" --config web5.conf >web5.log 2>&1 & P5=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web5.conf" WEB_PORT "$P5" || true
if ! kill -0 $P5 2>/dev/null; then echo "web5 died:"; cat web5.log; else
    chk "PRECONDITION: no provider at startup -> status disabled" yes \
        "$(has "$(curl -s "$U5/api/oidc/status")" '"enabled":false')"
    chk "  and the callback is closed while none exists" 404 \
        "$(curl -s -o /dev/null -w '%{http_code}' "$U5/api/oidc/callback?state=x&code=y")"

    seed_oidc "$PGDATABASE" "$ISS" "$WP5" false      # the admin adds one, server still up

    chk "status turns on with no restart" yes \
        "$(has "$(curl -s "$U5/api/oidc/status")" '"enabled":true')"
    # ⚠️ NOT 404 — that is the bug. A bare callback with an unknown state is expected to be
    # REFUSED (400, invalid state), and the distinction is the whole point: 404 means "OIDC
    # is off here", 400 means "OIDC is on and that state is not one of mine".
    C5=$(curl -s -o /dev/null -w '%{http_code}' "$U5/api/oidc/callback?state=nosuch&code=y")
    chk "  and the callback is reachable (400 invalid state, NOT 404)" 400 "$C5"
    # End to end, through the real IdP: the login the admin just enabled must complete.
    curl -s -L -c j10.cj "$U5/api/oidc/login" >login5.log 2>&1
    ME10=$(curl -s -b j10.cj "$U5/api/me")
    chk "  a full login now succeeds, as the IdP subject" yes \
        "$(hasf "$ME10" "$(juser default-oidc alice@example.org)")"
    [ "$(hasf "$ME10" "$(juser default-oidc alice@example.org)")" = yes ] || \
        { echo "    /api/me said: $ME10"; tail -6 web5.log | sed 's/^/      web5.log: /'; }
    kill $P5 2>/dev/null
fi

echo
echo "=== the callback is THIS node's own address ==="
# ⚠️ oidc_providers REPLICATES, AND EVERY NODE HAS ITS OWN FQDN, which is why the table has no
# redirect URI column: a stored value would be one node's URL for the whole mesh, and a login
# begun on node B would come back to node A, whose in-flight state map — per process,
# necessarily — has no entry for B's state. Each node asks the IdP for its own callback.
chk "the provider table carries no redirect URI to go stale" 0 \
    "$(pg_exec "SELECT count(*) FROM information_schema.columns WHERE table_name='oidc_providers' AND column_name='redirect_uri';")"
WP6=18217; U6="http://127.0.0.1:$WP6"
oidc_conf "$PG_CONNINFO" "$WP6" "" > web6.conf
pg_exec "DELETE FROM oidc_providers; DELETE FROM auth_providers WHERE kind='oidc';" >/dev/null
seed_oidc "$PGDATABASE" "$ISS" "$WP6" false
"$WEB" --config web6.conf >web6.log 2>&1 & P6=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web6.conf" WEB_PORT "$P6" || true
if ! kill -0 $P6 2>/dev/null; then echo "web6 died:"; cat web6.log; else
    # The authorize URL this node sends the browser to must carry ITS OWN callback.
    LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "$U6/api/oidc/login")
    chk "the login redirect carries THIS node's callback" yes \
        "$(printf '%s' "$LOC" | grep -q "127.0.0.1%3A$WP6%2Fapi%2Foidc%2Fcallback\|127.0.0.1:$WP6/api/oidc/callback" && echo yes || echo no)"
    # End to end: the flow completes on the node it started on.
    curl -s -L -c j11.cj "$U6/api/oidc/login" >/dev/null
    chk "  a full login completes on this node" yes \
        "$(hasf "$(curl -s -b j11.cj "$U6/api/me")" "$(juser default-oidc alice@example.org)")"
    kill $P6 2>/dev/null
fi
echo "=== OIDC: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]