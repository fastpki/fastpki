#!/usr/bin/env bash
# Context-aware CSR mapping. When a non-admin self-service
# user requests a cert from the console, the issued subject is bound to the
# AUTHENTICATED identity instead of the CSR: CN <- the session username, OU <-
# the session groups (from OIDC/SAML). Admins keep the CSR subject. Gated by
# WEB_SELFSERVICE_IDENTITY_SUBJECT (default on). Self-skips without python3.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
PY=$(command -v python3 || true)
if [ -z "$PY" ]; then echo "SKIP: python3 not available"; exit 0; fi
W="$(mktemp -d)"; cd "$W"; P1=18220; P2=18221; P3=18222; MP=18224
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
subj(){ "$OSSL" x509 -in "$1" -noout -subject -nameopt RFC2253 2>/dev/null; }
getpem(){ echo "$1" | "$PY" -c 'import json,sys;open("issued.pem","w").write(json.load(sys.stdin).get("pem",""))'; }
mkcsr(){ "$OSSL" req -new -newkey rsa:2048 -nodes -keyout "$2.key" -out "$2" -subj "$1" >/dev/null 2>&1; }

ca_in_token ca.pem "/CN=Map CA" 3
cp ca.pem root.pem; printf "internal\n" > domains.txt
"$OSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out idp.key >/dev/null 2>&1
pg_setup web_csrmap; pg_setup web_csrmap2; pg_setup web_csrmap3; pg_setup web_csrmap4
seed_domains $W/domains.txt   # allowed_domains is the sole source
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
base_conf(){ cat <<EOF
# The OIDC callback is derived from this node's own config — the replicated provider
# tables hold none, since one stored value cannot serve a mesh of consoles — so
# the node has to know its own name — exactly as a real node does.
PKI_DNS=127.0.0.1
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
ROOT_CA_PEM=$W/root.pem
WEB_BIND=127.0.0.1
WEB_ALLOW_REVOKE=true
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
}
mklogin(){ # $1=url  -> create admin boss + requester alice, cookie jars boss.cj/alice.cj
  curl -s -o /dev/null -X POST "$1/api/users" -d 'username=boss&password=bosspw12&role=admin'
  curl -s -c "$2boss.cj" -X POST "$1/api/login" -d 'username=boss&password=bosspw12' >/dev/null
  curl -s -o /dev/null -b "$2boss.cj" -X POST "$1/api/users" -d 'username=alice&password=alicepw12&role=requester'
  curl -s -c "$2alice.cj" -X POST "$1/api/login" -d 'username=alice&password=alicepw12' >/dev/null
}

echo "=== Part A: identity-subject ON — local self-service user ==="
{ base_conf; echo "PG_CONNINFO=$PG_CONNINFO"; echo "WEB_PORT=$P1"; } > w1.conf
seed_ca_from_conf w1.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$WEB" --config w1.conf >w1.log 2>&1 & A=$!
sleep 1; trap 'pg_cleanup; kill $A $B $C $MOCK 2>/dev/null' EXIT
if ! kill -0 $A 2>/dev/null; then echo "web died:"; cat w1.log; exit 1; fi
U1="http://127.0.0.1:$P1"; mklogin "$U1" ""
mkcsr "/CN=evil.example.org" a.csr
S=$(getpem "$(curl -s -b alice.cj -X POST --data-binary @a.csr "$U1/api/certs/request?ca_instance=ca-global")"; subj issued.pem)
chk "alice's CN is bound to her identity (CN=alice)" yes "$(has "$S" 'CN=alice')"
chk "the CSR-supplied CN is discarded"               no  "$(has "$S" 'evil.example.org')"
# admin keeps the CSR subject (issues for hosts)
mkcsr "/CN=host.internal" h.csr
S=$(getpem "$(curl -s -b boss.cj -X POST --data-binary @h.csr "$U1/api/certs/request?ca_instance=ca-global")"; subj issued.pem)
chk "an admin keeps the CSR CN (CN=host.internal)" yes "$(has "$S" 'CN=host.internal')"

echo "=== Part B: WEB_SELFSERVICE_IDENTITY_SUBJECT=false — CSR honored ==="
{ base_conf; echo "PG_CONNINFO=$PG_CONNINFO"; echo "WEB_PORT=$P2"; echo "WEB_SELFSERVICE_IDENTITY_SUBJECT=false"; } > w2.conf
seed_ca_from_conf w2.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$WEB" --config w2.conf >w2.log 2>&1 & B=$!
sleep 1; U2="http://127.0.0.1:$P2"; mklogin "$U2" "x"
mkcsr "/CN=host.internal" h2.csr
S=$(getpem "$(curl -s -b xalice.cj -X POST --data-binary @h2.csr "$U2/api/certs/request?ca_instance=ca-global")"; subj issued.pem)
chk "flag off: a requester's CSR CN is honored" yes "$(has "$S" 'CN=host.internal')"

echo "=== Part C: federated (OIDC) group -> OU ==="
ISS="http://127.0.0.1:$MP"
MOCK_PORT=$MP MOCK_ISSUER="$ISS" MOCK_CLIENT_ID=fastpki MOCK_KEY="$W/idp.key" \
  MOCK_USER="engineer1" MOCK_GROUPS="engineering" MOCK_OSSL="$OSSL" \
  "$PY" "$ROOT/tests/mock_oidc.py" >mock.log 2>&1 & MOCK=$!
# Poll the mock IdP's port, do not sleep at it (wait_port, pg_helpers.sh).
wait_port "$MP" "$MOCK" || true
{ base_conf; echo "PG_CONNINFO=$PG_CONNINFO"; echo "WEB_PORT=$P3"; } > w3.conf
# ⚠️ THE SETTINGS ARE A ROW, NOT CONFIG — there is no OIDC_* config key. The server
# resolves the provider once at startup, so both rows must exist before it runs.
pg_exec "
  INSERT INTO auth_providers(id,kind,display_name,enabled,priority,created,updated)
    VALUES('default-oidc','oidc','OIDC',true,100,0,0)
    ON CONFLICT (id) DO UPDATE SET enabled=true;
  INSERT INTO oidc_providers(provider_id,issuer,client_id,client_secret,
                             admin_group,auditor_group)
    VALUES('default-oidc','$ISS','fastpki','secret','pki-admins','pki-auditors')
    ON CONFLICT (provider_id) DO UPDATE SET issuer=EXCLUDED.issuer;" >/dev/null
# ⚠️ A federated identity in no group onboards as `none`, and there is no config key to
# change that (DEFAULT_ROLE is gone). This suite needs engineer1 to be a working
# requester, so PRE-PROVISION the row: a local web_users record wins over onboarding,
# which is the supported way to give a directory identity a role.
pg_exec "INSERT INTO web_users(username,role,hash,must_reset,created)
         VALUES('default-oidc\\engineer1','requester','!external',0,0) ON CONFLICT DO NOTHING;" >/dev/null
seed_ca_from_conf w3.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$WEB" --config w3.conf >w3.log 2>&1 & C=$!
sleep 1; U3="http://127.0.0.1:$P3"
curl -s -L -c oidc.cj "$U3/api/oidc/login" >/dev/null
ME=$(curl -s -b oidc.cj "$U3/api/me")
chk "federated user engineer1 has a session"  yes "$(echo "$ME" | grep -qF '"user":"default-oidc\\engineer1"' && echo yes || echo no)"
chk "engineer1 (non-admin group) is requester"  yes "$(has "$ME" '"role":"requester"')"
mkcsr "/CN=ignored.example.org" f.csr
S=$(getpem "$(curl -s -b oidc.cj -X POST --data-binary @f.csr "$U3/api/certs/request?ca_instance=ca-global")"; subj issued.pem)
# ⚠️ THE CN IS THE PERSON; THE PROVIDER IS A SEPARATE RDN.
# The identity-subject binding names the authenticated identity, and a federated session is
# `<provider>\<user>` -- but a commonName holding both stops being a name, and carries a
# backslash inside a DN component while it is at it. The provider is stamped as a
# domainComponent instead, so two IdPs asserting the same username are still told apart.
#
# NOT an OU: the OUs here are the caller's GROUPS (asserted below), so a provider stamped
# there would be indistinguishable from a group the user is in.
chk "federated CN is the identity ALONE (CN=engineer1)" yes \
    "$(echo "$S" | grep -qF 'CN=engineer1' && echo yes || echo no)"
chk "  the provider is a separate RDN, not part of the name" yes \
    "$(echo "$S" | grep -qF 'DC=default-oidc' && echo yes || echo no)"
chk "  and no backslash survives anywhere in the DN" no \
    "$(printf '%s' "$S" | grep -q '\\\\' && echo yes || echo no)"
chk "federated group mapped to OU (OU=engineering)" yes "$(has "$S" 'OU=engineering')"

echo
echo "=== WEB CSR-MAP: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
