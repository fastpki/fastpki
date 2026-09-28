#!/usr/bin/env bash
# Certificate policy profiles. Drives EST enrollment to
# prove the profile engine: KU/EKU are honored from the CSR within the profile's
# allow-list (and defaulted when the CSR requests none), CA-only KU is refused,
# wildcards are gated per-profile (built-in requester vs admin), and a profile stored in
# the cert_profiles table is loaded, applied, and overrides the built-in.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
W="$(mktemp -d)"; cd "$W"; PORT=18260; PORT2=18261
P=; P2=
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

ca_in_token ca.pem "/CN=Profile CA" 3
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout est.key -out est.pem -days 3 -subj "/CN=localhost" >/dev/null 2>&1
pg_setup cert_profiles; PG_CONNINFO1="$PG_CONNINFO"; PGDATABASE1="$PGDATABASE"
pg_setup cert_profiles2
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
# Each EST instance reads allowed_domains from its OWN database, so seed both.
( PG_CONNINFO="$PG_CONNINFO1"; seed_domains $W/domains.txt )
seed_domains $W/domains.txt
# Each EST instance authenticates against its OWN database, so seed both: 'tester'
# enrols against instance 1 and 2, 'admin' only against instance 1.
( PG_CONNINFO="$PG_CONNINFO1"
  # ⚠️ `requester`, not `standard`. See the note on the `admin` line below — this is the
  # SAME trap one row up, and the no-defaults rule is what finally makes it fail loudly: a role
  # matching no `roles` row now grants nothing, and a subject with no profile grant cannot
  # issue at all rather than quietly receiving a CA default.
  seed_web_user tester s3cret-t requester
  # ⚠️ The CONSOLE role `admin`, not the ISSUANCE role `master`. This user
  # was seeded with `master`, which was a cert-profile name and not a `roles` row — so under
  # the union model subject_roles.known is EMPTY, no profile grant applies, and the wildcard
  # case below fails. Under profile_assignments it worked because the row keyed on the
  # username and never looked at the role at all. Two namespaces sharing words, which is
  # exactly the point at issue.
  seed_web_user admin  s3cret-m admin )
seed_web_user tester s3cret-t requester
# The console role no longer selects a cert profile — a role
# HOLDS a profile as a permission. `admin` ships holding `profile:use|admin` (the wildcard-
# allowing one) and `requester` holds `profile:use|requester` (no wildcards).
# ⚠️ A subject whose roles hold NOTHING no longer "gets the CA default" —
# it is refused outright, which is why both users above name a real console role.
# The seed in sql/createdb.sql is what grants it, so nothing extra is needed
# here — and asserting that is better than re-inserting it, because a seed that stopped
# shipping would otherwise be invisible.
#
# ⚠️ THE SCOPE STAYS 'admin', AND THAT IS THE POINT. /api/profiles enforces the grant's
# scope on write and delete now, and it would have been easy to widen this row to '*' so the
# builtin admin could still administer every profile — but profiles_for_identity() counts
# ro and rw alike, so that would also let admin ISSUE under every profile, which
# profile_choice.sh pins as forbidden. Administration rides on a separate grant,
# `profile:edit|*`, which is not counted at issuance.
PGDATABASE=$PGDATABASE1 pg_exec "SELECT 1 FROM role_permissions WHERE role='admin' AND permission='profile:use' AND scope='admin';" | grep -q 1 \
  || { echo "  [FAIL] the shipped schema no longer grants admin profile:use on the admin profile"; fail=$((fail+1)); }

mkconf(){ cat <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
EST_CERT=$W/est.pem
EST_KEY=$W/est.key
PG_CONNINFO=$1
AUTH_BACKEND=local
EST_BIND=127.0.0.1
EST_PORT=$2
CERT_VALIDITY_DAYS=365
$3
LOG_LEVEL=err
EOF
}

# enroll USER PASS SUBJECT [openssl-req-args...] -> prints the issued PEM (empty on reject)
enroll(){ local u=$1 p=$2 s=$3; shift 3
  "$OSSL" req -new -subj "/CN=$s" -newkey rsa:2048 -keyout k.pem -nodes -out r.csr "$@" >/dev/null 2>&1
  "$OSSL" req -in r.csr -outform DER 2>/dev/null | "$OSSL" base64 > r.b64
  curl -sk -u "$u:$p" --data-binary @r.b64 -H "Content-Type: application/pkcs10" \
    "https://127.0.0.1:$PORT/.well-known/est/ca/simpleenroll" \
    | "$OSSL" base64 -d -A 2>/dev/null | "$OSSL" pkcs7 -inform DER -print_certs 2>/dev/null
}
issued(){ has "$1" "BEGIN CERTIFICATE"; }
ext(){ echo "$1" | "$OSSL" x509 -noout -ext "$2" 2>/dev/null; }

mkconf "$PG_CONNINFO1" "$PORT" "" > bootstrap.conf
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$ROOT/build/fastpki-est" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P $P2 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "est died:"; cat srv.log; exit 1; fi

echo "=== built-in 'requester': KU/EKU defaults when the CSR requests none ==="
C=$(enroll tester s3cret-t host.internal)
chk "default cert issued" yes "$(issued "$C")"
KU=$(ext "$C" keyUsage); EKU=$(ext "$C" extendedKeyUsage)
# Slice 3, the new defaults for this profile: remove keyEncipherment
# from default KU, ServerAuth and ClientAuth from default EKU". So a bare CSR now gets
# digitalSignature and NOTHING else, and no ExtendedKeyUsage extension at all.
chk "default KeyUsage = digitalSignature ONLY" yes \
    "$([ "$(has "$KU" 'Digital Signature')" = yes ] && [ "$(has "$KU" 'Key Encipherment')" = no ] && echo yes || echo no)"
# ⚠️ Assert the EXTENSION IS ABSENT, not that a string is missing from it: `has` on an
# empty `ext` output answers "no" for every needle, so "no serverAuth" would also pass
# against a cert carrying codeSigning, or against a decode that failed outright.
chk "no ExtendedKeyUsage extension is emitted at all" yes \
    "$([ -z "$(echo "$EKU" | tr -d '[:space:]')" ] && echo yes || echo no)"
chk "  ...and the KU extension IS present (the control for the line above)" yes \
    "$([ -n "$(echo "$KU" | tr -d '[:space:]')" ] && echo yes || echo no)"

echo "=== KU/EKU honored from the CSR within the allow-list ==="
C=$(enroll tester s3cret-t host.internal -addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=clientAuth")
chk "requested-KU/EKU cert issued" yes "$(issued "$C")"
KU=$(ext "$C" keyUsage); EKU=$(ext "$C" extendedKeyUsage)
chk "honored KU = digitalSignature only (no keyEncipherment)" yes \
    "$([ "$(has "$KU" 'Digital Signature')" = yes ] && [ "$(has "$KU" 'Key Encipherment')" = no ] && echo yes || echo no)"
chk "honored EKU = clientAuth only (no serverAuth)" yes \
    "$([ "$(has "$EKU" 'Client')" = yes ] && [ "$(has "$EKU" 'Server')" = no ] && echo yes || echo no)"

echo "=== CA-only KeyUsage is refused for an end-entity ==="
C=$(enroll tester s3cret-t host.internal -addext "keyUsage=critical,keyCertSign")
chk "keyCertSign request -> rejected" no "$(issued "$C")"

echo "=== wildcard gated by the resolved profile ==="
chk "a subject whose roles grant no profile cannot request a wildcard CN" no \
    "$(issued "$(enroll tester s3cret-t '*.internal')")"
chk "a subject whose role holds profile:use|admin CAN"                     yes \
    "$(issued "$(enroll admin  s3cret-m '*.internal')")"

echo "=== The fallback profile is derived from the CONSOLE ROLE, not kDefaultProfile ==="
# ⚠️ THE REPORT: the admin user had the standard profile associated with it by default —
# I was surprised by that." Every protocol passed a hardcoded ca_default of "standard", so an
# admin with no assignment could not request a wildcard. The fallback is now role-derived,
# and the role and the profile it holds now share a name: admin -> admin,
# requester -> requester.
#
# ⚠️ ALL THREE CASES, because the whole design decision is "a DEFAULT, not a BINDING". He
# asked whether to bind profile to role outright; case 2 is what binding would have cost —
# `admin` is the profile that allows wildcards, so an unconditional admin==admin would mean
# no operator could ever stop an admin minting *.example.com.
( PG_CONNINFO="$PG_CONNINFO1"
  seed_web_user rolladmin s3cret-ra admin        # console role admin, NO assignment
  seed_web_user rollreq   s3cret-rr requester    # console role requester, NO assignment
  seed_web_user boundadm  s3cret-ba restricted-admin )   # see the role created below
# ⚠️ THE SEPARATION-OF-DUTIES CASE, and the model changes HOW an operator expresses it
# without changing WHETHER they can. admin->master was requested as a
# DEFAULT and not a binding, precisely so an operator could pin a particular admin to a
# restricted profile and have it hold.
#
# Under profile_assignments that was an explicit row beating the role default. Under the
# union it is a DIFFERENT ROLE: one that grants the same console access but holds
# `profile:use|requester` instead of `profile:use|admin`. The property is the same — an
# operator can stop an admin minting *.example.com — and it is now visible in one place
# (the role) rather than split across a role and an assignment table.
PGDATABASE=$PGDATABASE1 pg_exec "
  INSERT INTO roles(name,description) VALUES('restricted-admin','admin access, requester profile only') ON CONFLICT DO NOTHING;
  INSERT INTO role_permissions(role,permission,scope)
    SELECT 'restricted-admin', permission, scope FROM role_permissions
     WHERE role='admin' AND permission <> 'profile:use'
  ON CONFLICT DO NOTHING;
  INSERT INTO role_permissions(role,permission,scope) VALUES('restricted-admin','profile:use','requester')
  ON CONFLICT DO NOTHING;" >/dev/null

chk "admin holds profile:use|admin, so a wildcard is issued" yes \
    "$(issued "$(enroll rolladmin s3cret-ra '*.internal')")"
chk "  requester holds only profile:use|requester, so a wildcard is refused" no \
    "$(issued "$(enroll rollreq s3cret-rr '*.internal')")"
chk "  an admin on a role granting only 'requester' is STILL refused" no \
    "$(issued "$(enroll boundadm s3cret-ba '*.internal')")"
# ⚠️ The plain-CN control. Without it, all three assertions above are satisfied by a server
# that refuses everything -- and two of the three EXPECT a refusal, so a total breakage would
# read as two passes out of three.
chk "  and every one of them can still issue an ordinary CN" yes \
    "$([ "$(issued "$(enroll rolladmin s3cret-ra ra.internal)")" = yes ] \
       && [ "$(issued "$(enroll rollreq s3cret-rr rr.internal)")" = yes ] \
       && [ "$(issued "$(enroll boundadm s3cret-ba ba.internal)")" = yes ] && echo yes || echo no)"

echo "=== a stored profile loads, applies, and overrides the built-in ==="
# Tighten 'requester' so serverAuth is no longer allowed (only clientAuth). Stored as its
# row before the second instance starts, which is when a service reads profiles.
seed_cert_profiles '{"requester":{"allowed_ku":["digitalSignature","keyEncipherment"],"allowed_eku":["clientAuth"],"default_ku":["digitalSignature"],"default_eku":["clientAuth"],"allow_wildcard":false}}'
mkconf "$PG_CONNINFO" "$PORT2" "" > pki2.conf
seed_ca_from_conf pki2.conf   # register the CA in the second DB
"$ROOT/build/fastpki-est" --config pki2.conf >srv2.log 2>&1 & P2=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "pki2.conf" EST_PORT "$P2" || true
PORT=$PORT2   # point enroll() at the tightened instance
if ! kill -0 $P2 2>/dev/null; then echo "est2 died:"; cat srv2.log; exit 1; fi
# ⚠️ THIS ASSERTION CHANGED SIDES. It expected a DENY; it was confirmed
# the opposite rule — "'drop the not-allowed attribute' confirmed" — so a serverAuth the
# profile does not allow is now REMOVED from the request and the certificate is issued
# without it. Asserting the drop rather than the refusal is what keeps this covered: the
# property that matters is that serverAuth never reaches the certificate, and a bare
# "was it refused?" can no longer see that.
#
# Both halves are load-bearing. Issued-but-still-carrying-serverAuth would be the actual
# bug, and issued-with-NO-EKU-at-all is the legitimate empty case for EKU (his note: a
# missing EKU may simply be rejected by the relying application, unlike an empty KeyUsage
# which RFC 5280 4.2.1.3 forbids outright).
CD=$(enroll tester s3cret-t host.internal -addext 'extendedKeyUsage=serverAuth')
chk "a serverAuth request is still issued (dropped, not denied)" yes "$(issued "$CD")"
# ⚠️ `ext`, not a bare `eku` — there is no such helper here, and an unknown command
# yields the empty string, so `has "" 'Server'` answers "no" and this assertion would
# have PASSED whatever the certificate contained.
chk "  and serverAuth is NOT in the issued cert"                 no \
    "$(has "$(ext "$CD" extendedKeyUsage)" 'Server')"
C=$(enroll tester s3cret-t host.internal -addext "extendedKeyUsage=clientAuth")
chk "tightened requester still issues clientAuth" yes "$(issued "$C")"

echo "=== KeyUsage: drop what the profile forbids, but never issue an EMPTY KeyUsage ==="
# 'Drop the not-allowed attribute' was confirmed — and then the one
# exception: "we should not issue a cert without any key usage because it would violate the
# RFC5280 4.2.1.3 ... So in cases like this, the request should be denied."
#
# The tightened profile above allows digitalSignature + keyEncipherment and nothing else,
# so keyCertSign is the forbidden bit to probe with.
#
# a) MIXED — one allowed, one not. The certificate issues, carrying only the allowed bit.
CM=$(enroll tester s3cret-t host.internal -addext 'keyUsage=digitalSignature,keyCertSign')
chk "mixed KU issues (the forbidden bit is dropped)" yes "$(issued "$CM")"
chk "  digitalSignature survived"                    yes "$(has "$(ext "$CM" keyUsage)" 'Digital Signature')"
chk "  keyCertSign did NOT"                          no  "$(has "$(ext "$CM" keyUsage)" 'Certificate Sign')"

# b) ALL DROPPED — nothing the profile allows is left, so issuing would mean a certificate
#    with NO KeyUsage restriction at all. That is the widening RFC 5280 4.2.1.3 forbids, and
#    it is why this one case denies instead of dropping. ⚠️ The two halves are separate: a
#    suite that only checked "was it refused?" would also pass if the server refused for an
#    unrelated reason, so the reason is asserted too.
CE=$(enroll tester s3cret-t host.internal -addext 'keyUsage=keyCertSign')
chk "KU that drops to EMPTY is refused"  no  "$(issued "$CE")"
chk "  and the reason names RFC 5280"    yes \
    "$(tail -30 srv2.log | grep -q '4.2.1.3' && echo yes || echo no)"

echo
echo "=== CERT PROFILES: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
