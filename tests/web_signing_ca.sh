#!/usr/bin/env bash
# Console Signing-CA selector. POST /api/certs/request accepts an
# optional ?ca_instance=<id> that selects WHICH registered CA signs the cert:
#   - empty                -> no CA selected (issuance requires ?ca_instance);
#   - a named instance     -> that instance's signing material, gated by the
#     caller's tenant scope and requiring active, key-bearing material.
# Proven by decoding the issued leaf (issuer DN + verify against the chosen CA).
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
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18262
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }

# Two independent self-signed CAs: A = the global signing CA, B = a second
# registered instance.
ca_in_token caA.pem "/CN=CA-A Global" 3 caa
CAA_KEY_URI="$CA_KEY_URI"
ca_in_token caB.pem "/CN=CA-B Tenant" 3 cab
CAB_KEY_URI="$CA_KEY_URI"
printf "internal\n" > domains.txt
pg_setup web_signing_ca
seed_domains $W/domains.txt   # allowed_domains is the sole source
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
# Register CA-B (active) and a disabled variant. A CA IS a `certs` row carrying
# its own certificate, so these are cert rows — two of them sharing one certificate on
# purpose, because this suite is about the STATUS gate and not about the crypto. The
# disabled one gets a distinct serial since serial is the primary key.
CAB_DER=$("$OSSL" x509 -in caB.pem -outform DER | xxd -p | tr -d '\n')
CAB_SER=$("$OSSL" x509 -in caB.pem -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
NOW_S=$(date +%s)
pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,cn,cert,
                           id,name,ca_enabled,private_key,is_ca,ca_instance_id)
  VALUES('$CAB_SER',0,$NOW_S,$((NOW_S + 315360000)),'CN=CA B','CA B','\\x$CAB_DER'::bytea,
         'cab','CA B',true,'$CAB_KEY_URI',true,'cab'),
        ('${CAB_SER}ff',0,$NOW_S,$((NOW_S + 315360000)),'CN=CA B down','CA B down','\\x$CAB_DER'::bytea,
         'cabdown','CA B down',false,'$CAB_KEY_URI',true,'cabdown')
  ON CONFLICT (serial) DO NOTHING;"

printf 'SIGNING_CA_PEM=%s\nSIGNING_CA_KEY=%s\nSIGNING_CA_ID=ca-a\nPG_CONNINFO=%s\nWEB_BIND=127.0.0.1\nWEB_PORT=%s\nWEB_ALLOW_REVOKE=true\nWEB_SELFSERVICE_IDENTITY_SUBJECT=false\nLOG_LEVEL=err\n' \
  "$W/caA.pem" "$CAA_KEY_URI" "$PG_CONNINFO" "$PORT" > w.conf
seed_ca_from_conf w.conf
"$WEB" --config w.conf >w.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "web died:"; cat w.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -o /dev/null -X POST "$U/api/users" -d 'username=boss&password=bosspw12&role=admin'
curl -s -c b.cj -X POST "$U/api/login" -d 'username=boss&password=bosspw12' >/dev/null
# A requester scoped ONLY to 'cab' — used for the per-CA gate. Scope is
# a property of the ROLE now, so she is given a role whose grants name that one CA
# rather than a `scope` field on her user record.
pg_exec "INSERT INTO roles(name, description, builtin) VALUES('requester@cab','test: requester limited to cab',false) ON CONFLICT (name) DO NOTHING;" >/dev/null
# ⚠️ ONLY THE CA-SCOPED GRANTS ARE NARROWED TO 'cab'. A profile or template grant's scope
# names a profile or template, not a CA: rewriting `profile:use|requester` to
# `profile:use|cab` granted a profile that does not exist, which issuance used to paper over
# by falling back to `requester` and now refuses, as it should.
pg_exec "INSERT INTO role_permissions(role, permission, scope)
           SELECT 'requester@cab', permission,
                  CASE WHEN permission LIKE 'profile:%' OR permission LIKE 'template:%' THEN scope ELSE 'cab' END
             FROM role_permissions WHERE role='requester'
           ON CONFLICT DO NOTHING;" >/dev/null
curl -s -o /dev/null -b b.cj -X POST "$U/api/users" -d 'username=tina&password=tinapw123&role=requester@cab'
curl -s -c t.cj -X POST "$U/api/login" -d 'username=tina&password=tinapw123' >/dev/null

"$OSSL" req -new -newkey rsa:2048 -nodes -keyout k.pem -out csr.pem -subj "/CN=host.internal" >/dev/null 2>&1
issue(){ # $1 = query (may be empty); writes cert.pem; echoes serial
  local q="$1"
  curl -s -b b.cj -X POST --data-binary @csr.pem "$U/api/certs/request$q" > r.json
  local j; j=$(cat r.json)
  json_pem "$j" pem cert.pem
  json_str "$j" serial
}

# There is no implicit CA — issuance must always name ?ca_instance.
# CA-A is registered with the id 'ca-a', so name it explicitly.
echo "=== ?ca_instance=ca-a: signed by CA-A ==="
SER=$(issue "?ca_instance=ca-a")
ISS=$("$OSSL" x509 -in cert.pem -noout -issuer 2>/dev/null)
chk "issuer is CA-A" yes "$(has "$ISS" 'CA-A Global')"
chk "verifies against CA-A" yes "$("$OSSL" verify -CAfile caA.pem cert.pem >/dev/null 2>&1 && echo yes || echo no)"
chk "does NOT verify against CA-B" no "$("$OSSL" verify -CAfile caB.pem cert.pem >/dev/null 2>&1 && echo yes || echo no)"
chk "inventory attributes it to 'ca-a'" ca-a "$(pg_exec "SELECT ca_instance_id FROM certs WHERE serial='$SER';")"

echo "=== ?ca_instance=cab: signed by the selected CA (CA-B) ==="
SER=$(issue "?ca_instance=cab")
ISS=$("$OSSL" x509 -in cert.pem -noout -issuer 2>/dev/null)
chk "issuer is CA-B" yes "$(has "$ISS" 'CA-B Tenant')"
chk "verifies against CA-B" yes "$("$OSSL" verify -CAfile caB.pem cert.pem >/dev/null 2>&1 && echo yes || echo no)"
chk "does NOT verify against CA-A" no "$("$OSSL" verify -CAfile caA.pem cert.pem >/dev/null 2>&1 && echo yes || echo no)"
chk "inventory attributes it to 'cab'" cab "$(pg_exec "SELECT ca_instance_id FROM certs WHERE serial='$SER';")"

echo "=== error paths ==="
chk "unknown instance -> 404" 404 "$(code -b b.cj -X POST --data-binary @csr.pem "$U/api/certs/request?ca_instance=nope")"
chk "disabled instance -> 409" 409 "$(code -b b.cj -X POST --data-binary @csr.pem "$U/api/certs/request?ca_instance=cabdown")"
# tina is scoped to 'cab' only: a different instance is out of her scope -> 403,
# refused before any CA is even resolved.
chk "out-of-scope instance -> 403" 403 "$(code -b t.cj -X POST --data-binary @csr.pem "$U/api/certs/request?ca_instance=zzz")"
# ...but her in-scope instance is allowed (self-service binds her own CN).
chk "in-scope instance allowed for scoped user (201)" 201 "$(code -b t.cj -X POST --data-binary @csr.pem "$U/api/certs/request?ca_instance=cab")"

echo "=== The Signing-CA dropdown reflects the requester's scope ==="
# The self-service issue form's populateSigningCa() fetches GET /api/ca-instances.
# A scoped requester was denied that path (403) -> the dropdown stayed empty and
# fell back to the global 'default' CA, so her configured CA scope was ignored.
chk "scoped requester may GET /api/ca-instances (was 403)" 200 "$(code -b t.cj "$U/api/ca-instances")"
CAS=$(curl -s -b t.cj "$U/api/ca-instances")
chk "list includes her scoped CA 'cab'"     yes "$(json_has "$CAS" id cab)"
chk "list EXCLUDES the global 'ca-a' CA"  yes "$([ "$(json_has "$CAS" id ca-a)" = no ] && echo yes || echo no)"
chk "list EXCLUDES out-of-scope 'cabdown'"   yes "$([ "$(json_has "$CAS" id cabdown)" = no ] && echo yes || echo no)"
# ...but read-only only: POST/create stays admin-only via the method gate.
chk "scoped requester cannot POST-create a CA -> 403" 403 "$(code -b t.cj -X POST "$U/api/ca-instances" --data-urlencode 'id=sneaky' --data-urlencode 'subject=/CN=x')"
chk "scoped requester cannot toggle a CA -> 403" 403 "$(code -b t.cj -X POST "$U/api/ca-instances/cab/status?status=disabled")"

echo
echo "=== WEB SIGNING CA: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
