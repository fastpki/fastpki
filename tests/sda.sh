#!/usr/bin/env bash
# Subject Directory Attributes. The authenticated identity is now
# carried in an RFC 5280 §4.2.1.8 Subject Directory Attributes extension —
# `owner` (2.5.4.32) as a synthesized DN, `role` (2.5.4.72) as a string — instead
# of as Subject DN RDNs. Verified end-to-end via a console-issued cert.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/json_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18260
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

ca_in_token ca.pem "/CN=SDA CA" 3
printf "internal\n" > domains.txt
pg_setup sda
seed_domains $W/domains.txt   # allowed_domains is the sole source
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf 'SIGNING_CA_PEM=%s\nSIGNING_CA_KEY=%s\nSIGNING_CA_ID=ca-global\nPG_CONNINFO=%s\nWEB_BIND=127.0.0.1\nWEB_PORT=%s\nWEB_ALLOW_REVOKE=true\nWEB_SELFSERVICE_IDENTITY_SUBJECT=false\nLOG_LEVEL=err\n' \
  "$W/ca.pem" "$W/ca.key" "$PG_CONNINFO" "$PORT" > w.conf
seed_ca_from_conf w.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$WEB" --config w.conf >w.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "web died:"; cat w.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s -o /dev/null -X POST "$U/api/users" -d 'username=boss&password=bosspw12&role=admin'
curl -s -c b.cj -X POST "$U/api/login" -d 'username=boss&password=bosspw12' >/dev/null

# The SDA `role` attribute is now driven by the resolved cert
# PROFILE's org_role — a descriptive organizational label — NOT the requester's
# console RBAC role. Create a profile carrying an org_role and bind alice to it.
curl -s -o /dev/null -b b.cj -X POST "$U/api/profiles" \
  --data-urlencode 'name=engineering' \
  --data-urlencode 'allowed_ku=digitalSignature' --data-urlencode 'default_ku=digitalSignature' \
  --data-urlencode 'allowed_eku=clientAuth' --data-urlencode 'default_eku=clientAuth' \
  --data-urlencode 'org_role=Engineering Dept'
# A profile is granted to a ROLE, and alice must hold the profile INSTEAD of the
# builtin's. Adding `engineering` on top of `requester` (which ships holding
# `profile:use|requester`) would leave her union with two members, merged for a request that
# names neither, so requester's defaults would mix into hers. So the operator's expression
# is a role that carries requester's access with a different profile, and alice IS that
# role. Driven entirely through the API, which is what an admin actually clicks.
curl -s -o /dev/null -b b.cj -X POST "$U/api/roles" \
  --data-urlencode 'name=engineering-role' --data-urlencode 'description=requester, engineering profile'
curl -s -o /dev/null -b b.cj -X POST "$U/api/roles/engineering-role/permissions" \
  --data-urlencode 'grants=cert:request|*
cert:read|*
cert:revoke|*
ca:read|*
self:manage|*
est:enrol|*
profile:use|engineering'

curl -s -o /dev/null -b b.cj -X POST "$U/api/users" -d 'username=alice&password=alicepw12&role=engineering-role'
curl -s -c a.cj -X POST "$U/api/login" -d 'username=alice&password=alicepw12' >/dev/null
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout k.pem -out csr.pem -subj "/CN=host.internal" >/dev/null 2>&1
curl -s -b a.cj -X POST --data-binary @csr.pem "$U/api/certs/request?ca_instance=ca-global" > resp.json
json_pem "$(cat resp.json)" pem c.pem

# A second requester with NO profile assignment lands on the CA-default profile
# ("requester"), which carries no org_role — so its cert gets an owner but NO role.
curl -s -o /dev/null -b b.cj -X POST "$U/api/users" -d 'username=bob&password=bobpw1234&role=requester'
curl -s -c bob.cj -X POST "$U/api/login" -d 'username=bob&password=bobpw1234' >/dev/null
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout kb.pem -out csrb.pem -subj "/CN=host2.internal" >/dev/null 2>&1
curl -s -b bob.cj -X POST --data-binary @csrb.pem "$U/api/certs/request?ca_instance=ca-global" > respb.json
json_pem "$(cat respb.json)" pem cb.pem

TEXT=$("$OSSL" x509 -in c.pem -noout -text 2>/dev/null)
SUBJ=$("$OSSL" x509 -in c.pem -noout -subject -nameopt RFC2253 2>/dev/null)
TEXTB=$("$OSSL" x509 -in cb.pem -noout -text 2>/dev/null)

echo "=== owner/role moved OUT of the Subject DN ==="
chk "subject keeps the requested CN" yes "$(has "$SUBJ" 'CN=host.internal')"
chk "subject has no owner RDN (2.5.4.32)" no "$(has "$SUBJ" '2.5.4.32')"
chk "subject has no role RDN (2.5.4.72)"  no "$(has "$SUBJ" '2.5.4.72')"

echo "=== ...and INTO a Subject Directory Attributes extension ==="
chk "SDA extension present" yes "$(has "$TEXT" 'Subject Directory Attributes')"
chk "owner carried as a synthesized DN (CN=alice)" yes \
    "$(echo "$TEXT" | grep -A2 -i 'owner:' | grep -q 'CN=alice' && echo yes || echo no)"

echo "=== NO role of any kind reaches a certificate ==="
# ⚠️ INVERTED. This used to require the org_role in the certificate.
# The rule: x509 certificates are about authentication, not authorization. Any code that
# writes or reads roles to or from the subject DN or the SDA has to go — roles belong to
# RBAC, assigned to users, groups and DNs, never to certificates. So id-at-role
# (2.5.4.72) is gone from every certificate, and the profile field that fed it went with
# it: an org LABEL is still a role-shaped claim inside an authentication artefact, which
# is exactly the model mixing the rule forbids.
# ⚠️ ASSERT ON WHAT OPENSSL ACTUALLY PRINTS. My first inversion grepped for the dotted
# OID "2.5.4.72" and passed with id-at-role RESTORED — `x509 -text` renders the attribute
# as `role:` with its value, never as the OID, so the check could not fail either way.
# The original assertion above it had it right: `role:` is the token.
chk "NO role attribute in the cert, whatever the profile said" no "$(has "$TEXT" 'role:')"
chk "  and the org label itself is absent"  no "$(has "$TEXT" 'Engineering')"
# The console role for alice is 'requester' — it must NOT leak into the cert.
chk "console role 'requester' does NOT appear in the cert" no "$(has "$TEXT" 'requester')"
# The default-profile cert (bob) has no org_role, so it gets owner but no role.
chk "default-profile cert has an SDA (owner)" yes \
    "$(echo "$TEXTB" | grep -A2 -i 'owner:' | grep -q 'CN=bob' && echo yes || echo no)"
chk "default-profile cert carries NO role attribute" no "$(has "$TEXTB" 'role:')"

echo "=== the extension is signed (cert still verifies) ==="
chk "cert verifies against the issuing CA" yes \
    "$("$OSSL" verify -CAfile ca.pem c.pem >/dev/null 2>&1 && echo yes || echo no)"
# RFC 5280: this extension must be non-critical.
chk "SDA is non-critical" no "$(echo "$TEXT" | grep -A1 'Subject Directory Attributes' | grep -qi critical && echo yes || echo no)"

echo "=== A CSR CANNOT supply its own SubjectDirectoryAttributes ==="
# The owner is the CA's statement about who this certificate belongs to. A requester that
# can set it can name anyone -- and self-renewal authenticates on exactly this field.
#
# ⚠️ `boss` is used deliberately: it holds the console role `admin`, so its cert profile is
# the `admin` built-in whose allowed_custom_extensions is "*". That wildcard is what made
# the extension eligible for copying; under any narrower profile this CSR is refused for a
# DIFFERENT reason and the test would pass without proving anything.
# The forged extension is STATED rather than hand-encoded: `openssl asn1parse -genconf`
# takes the structure and emits the DER, where this used to carry a small DER encoder
# written in python. Tests are shell-only — python3 exists in the test image solely as
# certbot's runtime, and nothing we own may call it. Verified byte-identical to what the
# python produced: 301D301B0603550420311430123110300E06035504030C076D616C6C6F7279
#
#   SubjectDirectoryAttributes ::= SEQUENCE OF Attribute
#     Attribute { type = 2.5.4.32 (id-at-owner), values = SET OF Name }
#       Name = RDNSequence -> SET -> AttributeTypeAndValue { 2.5.4.3 (CN), "mallory" }
#
# od, not xxd: POSIX, so it is present on macOS, under busybox and in the image alike.
cat > "$W/sda253.cnf" <<'ASN1'
asn1 = SEQUENCE:sda
[sda]
attr = SEQUENCE:owner_attr
[owner_attr]
oid  = OID:2.5.4.32
vals = SET:owner_set
[owner_set]
name = SEQUENCE:rdnseq
[rdnseq]
rdn  = SET:rdn_set
[rdn_set]
atv  = SEQUENCE:cn_atv
[cn_atv]
oid  = OID:2.5.4.3
val  = UTF8:mallory
ASN1
"$OSSL" asn1parse -genconf "$W/sda253.cnf" -out "$W/sda253.der" -noout 2>/dev/null
od -An -tx1 "$W/sda253.der" | tr -d ' \n' | tr 'a-f' 'A-F' > "$W/sda253.hex"
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout k253.pem -out csr253.pem \
    -subj "/CN=host3.internal" -addext "2.5.29.9=DER:$(cat "$W/sda253.hex")" >/dev/null 2>&1
# The control: the CSR really does carry it, or everything below passes vacuously.
chk "the CSR really carries a forged owner" yes \
    "$("$OSSL" req -in csr253.pem -noout -text 2>/dev/null | grep -q mallory && echo yes || echo no)"
curl -s -b b.cj -X POST --data-binary @csr253.pem "$U/api/certs/request?ca_instance=ca-global" > resp253.json
json_pem "$(cat resp253.json)" pem c253.pem
T253=$("$OSSL" x509 -in c253.pem -noout -text 2>/dev/null)
chk "the certificate was still issued"      yes "$([ -n "$T253" ] && echo yes || echo no)"
# COUNT the extension. "does it name mallory = no" alone would also pass on a cert that
# carries no SDA at all, which would be a different bug.
chk "  it carries EXACTLY ONE SDA extension" 1 \
    "$(echo "$T253" | grep -c 'X509v3 Subject Directory Attributes')"
chk "  and the owner is boss, the authenticated requester" yes \
    "$(echo "$T253" | grep -A2 -i 'owner:' | grep -q 'CN=boss' && echo yes || echo no)"
chk "  the forged owner does not appear anywhere" no \
    "$(echo "$T253" | grep -q mallory && echo yes || echo no)"

echo
echo "=== SDA: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
