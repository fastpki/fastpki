#!/usr/bin/env bash
# SSO user onboarding with a pending role. A new externally-authenticated
# (OIDC/SAML) user with no local web_users row and no matching group is PERSISTED with
# the role `none` (no access) so an admin can assign them a role later, rather than
# silently defaulting them to a working role. Drives the full lifecycle against a
# groups-less mock IdP.
#
# ⚠️ That role is FIXED and there is no config key for it. This suite used to
# assert the opposite — `DEFAULT_ROLE=requester` onboarding as requester — because the
# key existed. The rule is no defaults — no DEFAULT_ROLE setting, removed from every
# path. The last section is now the guard that it is gone:
# it sets DEFAULT_ROLE to the MOST privileged role there is and asserts nothing moves.
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
WEB="$ROOT/build/fastpki-web"; PY=$(command -v python3 || true)
[ -n "$PY" ] || { echo "SKIP: python3 not available (mock OIDC needs it)"; exit 0; }
W="$(mktemp -d)"; cd "$W"; MP=18240; WP=18241; WP2=18242
pass=0; fail=0; MOCK=""; P=""; P2=""
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
trap 'kill $MOCK $P $P2 2>/dev/null' EXIT

"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out idp.key >/dev/null 2>&1
ISS="http://127.0.0.1:$MP"
# Groups-less IdP (like Google): the id_token carries no groups claim.
MOCK_PORT=$MP MOCK_ISSUER="$ISS" MOCK_CLIENT_ID=fastpki MOCK_KEY="$W/idp.key" \
  MOCK_USER="newbie@example.org" MOCK_GROUPS="" MOCK_OSSL="$OSSL" \
  "$PY" "$ROOT/tests/mock_oidc.py" >mock.log 2>&1 & MOCK=$!
# Poll the mock IdP's port, do not sleep at it (wait_port, pg_helpers.sh).
wait_port "$MP" "$MOCK" || true
chk "mock IdP up" yes "$(has "$(curl -s "$ISS/.well-known/openid-configuration")" 'authorization_endpoint')"

# ⚠️ THE SETTINGS ARE A ROW, NOT CONFIG — there is no OIDC_* config key. Seed the two
# rows the server reads at startup: `auth_providers` declares the provider, and
# `oidc_providers` carries its settings.
#   seed_oidc <issuer> <web-port>
seed_oidc(){
  pg_exec "
    INSERT INTO auth_providers(id,kind,display_name,enabled,priority,created,updated)
      VALUES('default-oidc','oidc','OIDC',true,100,0,0)
      ON CONFLICT (id) DO UPDATE SET enabled=true;
    INSERT INTO oidc_providers(provider_id,issuer,client_id,client_secret,
                               admin_group,auditor_group)
      VALUES('default-oidc','$1','fastpki','secret','pki-admins','pki-auditors')
      ON CONFLICT (provider_id) DO UPDATE SET issuer=EXCLUDED.issuer;" >/dev/null
}

conf(){ cat <<EOF
WEB_BIND=127.0.0.1
WEB_PORT=$1
# The OIDC callback is derived from this node's own config — the replicated provider
# tables hold none, since one stored value cannot serve a mesh of consoles — so
# the node has to know its own name — exactly as a real node does.
PKI_DNS=127.0.0.1
WEB_TOKEN=t0
WEB_ALLOW_REVOKE=true
$2
LOG_LEVEL=err
EOF
}

echo "=== default DEFAULT_ROLE=none: a new SSO user is onboarded with no access ==="
DB="$W/a.db"; pg_setup web_onboarding
trap 'pg_cleanup; kill $MOCK $P $P2 2>/dev/null' EXIT
seed_oidc "$ISS" "$WP"
conf "$WP" "" > a.conf
"$WEB" --config a.conf >a.log 2>&1 & P=$!
sleep 1; if ! kill -0 $P 2>/dev/null; then echo "web died:"; cat a.log; exit 1; fi
U="http://127.0.0.1:$WP"; ADM=(-H "Authorization: Bearer t0")
curl -s -L -c u.cj "$U/api/oidc/login" >/dev/null            # SSO login as newbie
ME=$(curl -s -b u.cj "$U/api/me")
# ⚠️ THE ONBOARDED ROW IS KEYED ON THE QUALIFIED SUBJECT. A federated login is
# `<provider>\<user>`, the same spelling a directory login has always had, so every
# lookup below -- the session, the users list, the SQL, and the role an admin assigns --
# has to name it that way or it silently measures a different (absent) row.
chk "SSO session created"                 yes "$(echo "$ME" | grep -qF '"user":"default-oidc\\newbie@example.org"' && echo yes || echo no)"
chk "onboarded role is 'none'"            yes "$(has "$ME" '"role":"none"')"
chk "no access to the cert inventory (403)" 403 "$(code -b u.cj "$U/api/certs")"
chk "may still log out (not forbidden)"    200 "$(code -X POST -b u.cj "$U/api/logout")"
# Persisted in the DB for the admin to find.
# `source` is now the provider that authenticated this identity, not the storage
# it landed in — an SSO-onboarded user reports `oidc`, which is the whole point of the
# column. This kept expecting the old literal.
chk "persisted with role=none and source=oidc"   "none|oidc" \
    "$(curl -s "${ADM[@]}" "$U/api/users" | "$PY" -c 'import sys,json
d=json.load(sys.stdin); u=[x for x in d if x["username"]=="default-oidc\\newbie@example.org"]
print((u[0]["role"]+"|"+u[0].get("source",""))) if u else print("MISSING")')"
chk "stored with a non-password sentinel hash (no password login possible)" \
    "!external" "$(pg_exec "SELECT hash FROM web_users WHERE username='default-oidc\\newbie@example.org';")"

echo "=== admin assigns 'requester'; the next SSO login has access ==="
# ⚠️ THE ADMIN MUST BE ABLE TO NAME THE ROW THE PRODUCT CREATED. /api/users validated
# usernames against a character set that excluded the backslash -- the very separator
# qualify_subject() writes -- so an onboarded federated or directory account was listed
# in the Users tab, stuck at `none`, and could not be given a role at all. Assert the
# call SUCCEEDS, not just that a role appears later: a silent 400 here would otherwise
# read as "the assignment did not take effect yet".
RESP=$(curl -s "${ADM[@]}" --data-urlencode 'username=default-oidc\newbie@example.org' -d 'role=requester' "$U/api/users")
chk "an admin can assign a role to the qualified name" no \
    "$(echo "$RESP" | grep -q 'invalid username' && echo yes || echo no)"
curl -s -L -c u2.cj "$U/api/oidc/login" >/dev/null
ME2=$(curl -s -b u2.cj "$U/api/me")
chk "role now reflects the admin assignment" yes "$(has "$ME2" '"role":"requester"')"
chk "requester can now reach the inventory (200)" 200 "$(code -b u2.cj "$U/api/certs")"

echo "=== DEFAULT_ROLE is GONE — setting it grants nothing ==="
# Watched failing: with the key still parsed this block goes red on all three, and the
# first one reads `"role":"admin"` — a config file handing full console administration
# to any identity the IdP is willing to name. `admin` is deliberately the value under
# test: a stale reader would be at its most dangerous here, and a key that is merely
# ignored is indistinguishable from one that is honoured if you only ever try `none`.
pg_setup web_onboarding2
seed_oidc "$ISS" "$WP2"
conf "$WP2" "DEFAULT_ROLE=admin" > b.conf
"$WEB" --config b.conf >b.log 2>&1 & P2=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "b.conf" WEB_PORT "$P2" || true
U2="http://127.0.0.1:$WP2"
curl -s -L -c v.cj "$U2/api/oidc/login" >/dev/null
ME3=$(curl -s -b v.cj "$U2/api/me")
chk "PRECONDITION: the SSO login worked, so a role WAS assigned here" \
    yes "$(echo "$ME3" | grep -qF '"user":"default-oidc\\newbie@example.org"' && echo yes || echo no)"
chk "DEFAULT_ROLE=admin still onboards as 'none'" yes "$(has "$ME3" '"role":"none"')"
chk "and it really holds no access (403)" 403 "$(code -b v.cj "$U2/api/certs")"
chk "the persisted row says none too" "none" \
    "$(pg_exec "SELECT role FROM web_users WHERE username='default-oidc\\newbie@example.org';" | tr -d ' ')"

echo
echo "=== WEB ONBOARDING: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
