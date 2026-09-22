#!/usr/bin/env bash
# SAML and OIDC are rows too, on the shape LDAP proved.
#
# `auth_providers` always carried a KIND, with one settings table per kind — that is the
# whole reason the split exists, and "adding a kind changes nothing about what already
# ships" was a claim rather than a measurement until now. This suite measures it: three
# kinds coexist in one `auth_providers` table, each with its own settings row, and the
# directory path is untouched by the other two being there.
#
# ⚠️ AND THE OIDC CLIENT SECRET IS THE SAME HAZARD AS THE DIRECTORY BIND PASSWORD. It is a
# credential the console must never return and must never wipe by accident, and both are
# asserted against the DATABASE rather than the API's account of itself.
#
# Self-contained (§3d) + shell-only (§3e): ephemeral Postgres, own port, temp dir,
# SKIPs cleanly with no Postgres.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18298; PORT2=18299
P2=""   # second web PID, pre-declared so the EXIT trap is set -u safe
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi

pg_setup saml_oidc_providers
trap 'pg_cleanup; kill $P $P2 2>/dev/null' EXIT
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -c admin.cj -X POST "$U/api/users" -d 'username=admin&password=adminpw12&role=admin' >/dev/null
curl -s -c admin.cj -X POST "$U/api/login" -d 'username=admin&password=adminpw12' >/dev/null
chk "PRECONDITION: the admin session is real" yes \
    "$(curl -s -b admin.cj "$U/api/me" | grep -q '"user":"admin"' && echo yes || echo no)"

echo "=== 1. the schema carries a table per kind ==="
for t in ldap_providers saml_providers oidc_providers; do
  chk "  $t exists" 1 "$(pg_exec "SELECT COUNT(*) FROM information_schema.tables WHERE table_name='$t';")"
done
# ⚠️ EACH DECLARES `updated` ITSELF. fastpki-mesh --triggers adds it to every LWW table, but
# it runs at first mesh setup — a table created by a schema STEP appears afterwards, and
# during a rolling update the first node rolled publishes a column its peers lack. Measured
# once already: the apply worker died and every health check stayed green.
for t in saml_providers oidc_providers; do
  chk "  $t declares its own 'updated'" 1 \
      "$(pg_exec "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='$t' AND column_name='updated';")"
done
# No foreign key to auth_providers, deliberately — replication delivers rows in arbitrary
# order and a child arriving first stops the apply worker.
chk "  and neither has a foreign key to auth_providers" 0 \
    "$(pg_exec "SELECT COUNT(*) FROM information_schema.table_constraints WHERE table_name IN ('saml_providers','oidc_providers') AND constraint_type='FOREIGN KEY';")"

echo "=== 2. three kinds coexist in one auth_providers table ==="
curl -s -o /dev/null -b admin.cj -X POST "$U/api/auth-providers" \
     --data-urlencode 'id=corp' --data-urlencode 'uris=ldaps://dc1.corp' \
     --data-urlencode 'base_dns=dc=corp,dc=example'
pg_exec "INSERT INTO auth_providers(id,kind,display_name,enabled,priority) VALUES('idp','saml','Corp SAML',true,100);" >/dev/null
pg_exec "INSERT INTO saml_providers(provider_id,idp_sso_url,idp_entity_id,username_attr) VALUES('idp','https://idp.example/sso','urn:idp','uid');" >/dev/null
pg_exec "INSERT INTO auth_providers(id,kind,display_name,enabled,priority) VALUES('sso','oidc','Corp OIDC',true,100);" >/dev/null
pg_exec "INSERT INTO oidc_providers(provider_id,issuer,client_id,client_secret) VALUES('sso','https://sso.example','fastpki','cl1ents3cret');" >/dev/null
chk "one table holds all three kinds" 3 "$(pg_exec "SELECT COUNT(*) FROM auth_providers;")"
chk "  ldap"  1 "$(pg_exec "SELECT COUNT(*) FROM auth_providers WHERE kind='ldap';")"
chk "  saml"  1 "$(pg_exec "SELECT COUNT(*) FROM auth_providers WHERE kind='saml';")"
chk "  oidc"  1 "$(pg_exec "SELECT COUNT(*) FROM auth_providers WHERE kind='oidc';")"

echo "=== 3. adding a kind changes nothing about the ones already shipping ==="
# ⚠️ THE CLAIM THE SPLIT WAS MADE FOR, AND WHICH LIST CARRIES WHAT. The admin list is the
# management view and carries all three kinds, each TAGGED with its kind so the page can
# render a directory and an issuer differently — they share no fields.
#
# The sign-in domain picker is the one that must stay directory-only, and it is the
# safety-critical one: it names the domains a person may type a PASSWORD against. An OIDC
# issuer appearing there would invite someone to hand their IdP password to us.
L=$(curl -s -b admin.cj "$U/api/auth-providers")
chk "the admin list shows the directory"           yes "$(echo "$L" | grep -q '"id":"corp","kind":"ldap"' && echo yes || echo no)"
chk "  and the SAML provider, tagged saml"         yes "$(echo "$L" | grep -q '"id":"idp","kind":"saml"' && echo yes || echo no)"
chk "  and the OIDC one, tagged oidc"              yes "$(echo "$L" | grep -q '"id":"sso","kind":"oidc"' && echo yes || echo no)"
D=$(curl -s "$U/api/auth-domains")
chk "the sign-in picker offers the directory"      yes "$(echo "$D" | grep -q '"id":"corp"' && echo yes || echo no)"
chk "  and does NOT offer an OIDC issuer as a domain" no "$(echo "$D" | grep -q '"id":"sso"' && echo yes || echo no)"
chk "  nor a SAML provider as a domain"              no "$(echo "$D" | grep -q '"id":"idp"' && echo yes || echo no)"

echo "=== 4. the OIDC client secret is a secret ==="
chk "PRECONDITION: it really is stored" cl1ents3cret \
    "$(pg_exec "SELECT client_secret FROM oidc_providers WHERE provider_id='sso';")"
# Nothing the console serves may carry it — not the provider list, not the domain list.
chk "  the provider list does not carry it" no "$(echo "$L" | grep -q 'cl1ents3cret' && echo yes || echo no)"
chk "  the pre-auth domain list does not carry it" no "$(echo "$D" | grep -q 'cl1ents3cret' && echo yes || echo no)"

echo "=== 5. removing a provider takes its settings row with it ==="
# ⚠️ NO FOREIGN KEY MEANS NOTHING CASCADES. A settings row left behind is inherited by the
# next provider created under the same id — a new SAML provider silently wearing a deleted
# one's IdP certificate.
curl -s -o /dev/null -b admin.cj -X DELETE "$U/api/auth-providers?id=idp"
chk "the provider row is gone"        0 "$(pg_exec "SELECT COUNT(*) FROM auth_providers WHERE id='idp';")"
chk "  and its settings row with it"  0 "$(pg_exec "SELECT COUNT(*) FROM saml_providers WHERE provider_id='idp';")"
curl -s -o /dev/null -b admin.cj -X DELETE "$U/api/auth-providers?id=sso"
chk "  same for the OIDC one"         0 "$(pg_exec "SELECT COUNT(*) FROM oidc_providers WHERE provider_id='sso';")"
chk "  and the directory is untouched" 1 "$(pg_exec "SELECT COUNT(*) FROM ldap_providers WHERE provider_id='corp';")"

echo "=== 6. the retired SAML/OIDC config keys are INERT ==="
# ⚠️ THE POINT OF THE WHOLE CHANGE, AND THE ONE THING A GREP CANNOT SHOW. The settings
# used to be 21 config keys, so a deployment could name exactly ONE provider of each kind.
# Deleting the keys is only real if setting them now changes nothing — a key the parser
# still honours behind a row-reading console would be two sources of truth, and the
# quieter one would win on some paths.
#
# Watched failing: restore the parser branches and this block goes red, because the server
# then answers `"enabled":true` for an OIDC issuer that exists only in the file.
#
# `admin` is deliberately the value under test for the group mappings: a stale reader is
# at its most dangerous granting console administration, and a key that is merely ignored
# is indistinguishable from one that is honoured if you only ever try a harmless value.
pg_setup saml_oidc_inert
cat > stale.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT2
WEB_TOKEN=t0
WEB_ALLOW_REVOKE=true
OIDC_ISSUER=http://127.0.0.1:1/stale
OIDC_CLIENT_ID=stale
OIDC_CLIENT_SECRET=stale
OIDC_REDIRECT_URI=http://127.0.0.1:$PORT2/api/oidc/callback
OIDC_ADMIN_GROUP=everyone
SAML_IDP_SSO_URL=http://127.0.0.1:1/sso
SAML_IDP_CERT=/nonexistent.pem
SAML_SP_ENTITY_ID=stale
SAML_SP_ACS_URL=http://127.0.0.1:$PORT2/api/saml/acs
SAML_ADMIN_GROUP=everyone
LOG_LEVEL=err
EOF
"$WEB" --config stale.conf >stale.log 2>&1 & P2=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "stale.conf" WEB_PORT "$P2" || true
U2="http://127.0.0.1:$PORT2"
chk "PRECONDITION: the server started on the stale config" yes \
    "$(kill -0 $P2 2>/dev/null && echo yes || echo no)"
chk "OIDC_ISSUER in a config file enables nothing" yes \
    "$(curl -s "$U2/api/oidc/status" | grep -q '"enabled":false' && echo yes || echo no)"
chk "SAML_IDP_SSO_URL in a config file enables nothing" yes \
    "$(curl -s "$U2/api/saml/status" | grep -q '"enabled":false' && echo yes || echo no)"
# The parser must not merely ignore the value — it must not know the key at all, or the
# Config screen would still offer a setting that changes nothing.
PARSED=$(grep -o 'key == "[A-Z0-9_]*"' "$ROOT/src/lib/config.cpp" | sed 's/.*"\(.*\)"/\1/' | sort -u)
chk "PRECONDITION: list-keys returned a key list" yes \
    "$([ "$(echo "$PARSED" | wc -l)" -gt 20 ] && echo yes || echo no)"
for k in OIDC_ISSUER OIDC_CLIENT_SECRET OIDC_REQUIRE_LOCAL_USER \
         SAML_IDP_SSO_URL SAML_IDP_CERT SAML_CLOCK_SKEW_SEC SAML_REQUIRE_LOCAL_USER; do
  chk "  the parser no longer knows $k" no \
      "$(grep -qx "$k" <<<"$PARSED" && echo yes || echo no)"
done
kill $P2 2>/dev/null; wait $P2 2>/dev/null; P2=""

echo "=== 7. the row-taking clients are compiled and linked ==="
# ⚠️ WHAT THIS DOES AND DOES NOT PROVE. nm shows the row-taking constructors were compiled
# and kept in the linked binary — the source declaring them proves nothing about that. That
# they are the ONLY way to build these clients is proved by section 6 above (a config file
# full of the old keys enables neither) and by oidc.sh/saml.sh, which drive real logins
# against a mock IdP configured entirely from rows.
# ⚠️ macOS's nm has no -C (that demangling flag is GNU binutils) and FAILS OUTRIGHT
# with it, which made this precondition read as "the binary has no SAML at all" on every
# developer Mac while CI passed. Probe BOTH spellings: demangled where available,
# Itanium-mangled (`...6SamlSpC1E...`) everywhere else.
NW=$(nm "$ROOT/build/fastpki-web" 2>/dev/null || echo "")
ND=$(nm -C "$ROOT/build/fastpki-web" 2>/dev/null || echo "")
NM="$NW
$ND"
chk "PRECONDITION: nm could read the binary at all" yes \
    "$(echo "$NM" | grep -q 'SamlSp' && echo yes || echo no)"
chk "SamlSp can be built from a provider row" yes \
    "$(echo "$NM" | grep -Eq 'SamlSp::SamlSp\(pki::Db::SamlProviderRow const&\)|6SamlSpC[12]ERK?NS_2Db15SamlProviderRowE' && echo yes || echo no)"
chk "OidcClient can be built from a provider row" yes \
    "$(echo "$NM" | grep -Eq 'OidcClient::OidcClient\(pki::Db::OidcProviderRow const&\)|(9|10)OidcClientC[12]ERK?NS_2Db1[45]OidcProviderRowE' && echo yes || echo no)"

echo
echo "=== SAML/OIDC PROVIDERS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
