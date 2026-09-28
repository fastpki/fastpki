#!/usr/bin/env bash
# Importing MS certificate templates straight out of the directory, instead of asking an
# operator to export a CSV from AD and paste it back into the console.
#
# ⚠️ WHAT THIS SUITE IS ACTUALLY FOR: the DECODERS. Three of the attributes are not strings
# and every one of them is easy to get silently wrong — a wrong answer here does not throw,
# it produces a template that looks plausible and is not what the directory said:
#
#   pKIExpirationPeriod   a NEGATIVE 64-bit LITTLE-ENDIAN count of 100-nanosecond ticks.
#                         Read as a positive big-endian integer — the obvious mistake —
#                         "one year" becomes a number in the billions.
#   pKIKeyUsage           the raw CONTENTS of a KeyUsage BIT STRING, most significant bit
#                         first, one or two bytes. Not DER, not a number. A one-byte value
#                         has to be shifted into the high half of the 16-bit bitmap.
#   pKIDefaultCSPs        ORDER-PREFIXED: "1,Microsoft RSA SChannel Cryptographic
#                         Provider". The number is Windows UI display order and is not part
#                         of the provider name.
#
# So the fixture below stores those attributes exactly as AD stores them and the assertions
# decode them back. Every expected value is DERIVED here rather than pasted, so the fixture
# and the assertion cannot drift apart into agreeing on the same wrong number.
#
# ⚠️ AND WHAT IT IS NOT. This is a throwaway slapd carrying the AD attribute NAMES, not
# Active Directory. It proves the search path, the naming-context lookup and the decoding.
# It does NOT prove anything about AD's own OIDs, its access control, or that a given
# domain publishes templates at all — the schema OIDs below are private stand-ins, because
# the product matches on attribute names and never on their OIDs. A real-directory run is
# a separate exercise and needs a read-only bind account.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
BUILD="${FASTPKI_BUILD:-$ROOT/build}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
W="$(mktemp -d)"; cd "$W"; PORT=18301; LPORT=13899
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# ⚠️ The LDAP-enabled binary, or this suite measures nothing. A build without
# FASTPKI_WITH_LDAP answers 501 on the route and every assertion below would be about the
# refusal rather than the import — a suite that passes while testing nothing.
WEB="$BUILD/fastpki-web"
[ -x "$WEB" ] || { echo "SKIP: no fastpki-web at $BUILD"; exit 0; }
if ! grep -q 'pKICertificateTemplate' "$WEB" 2>/dev/null; then
    echo "SKIP: $WEB has no LDAP template support built in"
    echo "      (configure with -DFASTPKI_WITH_LDAP=ON and point FASTPKI_BUILD at that tree)"
    exit 0
fi

SLAPD=""
for c in "$(command -v slapd 2>/dev/null)" /usr/sbin/slapd /usr/local/libexec/slapd \
         /opt/homebrew/opt/openldap/libexec/slapd /usr/local/opt/openldap/libexec/slapd; do
    [ -n "$c" ] && [ -x "$c" ] && { SLAPD="$c"; break; }
done
[ -n "$SLAPD" ] || { echo "SKIP: openldap (slapd) not installed"; exit 0; }
case "$SLAPD" in */libexec/slapd) PATH="${SLAPD%/libexec/slapd}/bin:${SLAPD%/libexec/slapd}/sbin:$PATH"; export PATH;; esac
SCH=""
for d in /etc/openldap/schema /etc/ldap/schema /usr/local/etc/openldap/schema \
         /opt/homebrew/etc/openldap/schema; do [ -f "$d/core.schema" ] && { SCH="$d"; break; }; done
[ -n "$SCH" ] || { echo "SKIP: no openldap schema directory"; exit 0; }
# back_mdb is a loadable module on some distributions and compiled in on others. An empty
# MODP means "compiled in" and the conf omits the moduleload lines.
#
# ⚠️ THIS LIST MUST COVER ALPINE (`/usr/lib/openldap`), and leaving it out is not a
# theoretical gap — it is what made this suite the only LDAP failure in the shipped image
# while the sibling LDAP suite passed beside it. MODP came back empty, the conf dropped
# `moduleload back_mdb`, and slapd refused `database mdb` with "Unrecognized database type
# (mdb)". That reads like a broken fixture on every platform at once, when it is really one
# missing directory. The sibling suite already had the right list; the two had no reason to
# differ and nothing kept them in agreement.
MODP=""
for d in /usr/lib/ldap /usr/lib/openldap /usr/lib64/openldap \
         /usr/lib/x86_64-linux-gnu/openldap /opt/homebrew/opt/openldap/libexec/openldap; do
    [ -f "$d/back_mdb.so" ] && { MODP="$d"; break; }
done
if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT"; exit 0
fi

# ⚠️ THE PAIRING GUARD. Two suites provision a slapd and each carries its own copy of the
# module search path. They drifted once and cost a full lab run, so the drift itself is
# now an assertion rather than something a reader has to notice: every directory the
# sibling LDAP suite searches must also be searched here. It runs before any fixture, so a
# drift is reported as a drift and not as an unexplained slapd failure.
_sib="$ROOT/tests/ldap.sh"
if [ -r "$_sib" ]; then
    _missing=""
    # ⚠️ Strip the shell punctuation the paths sit next to (`... ; do`, a line continuation)
    # rather than dropping such entries: a guard that skips what it cannot parse silently
    # stops covering exactly the lines most likely to differ.
    for d in $(sed -n '/^MODP=/,/^done/p' "$_sib" | tr ' \t' '\n' | grep '^/' | sed 's/[;\\]*$//'); do
        case " /usr/lib/ldap /usr/lib/openldap /usr/lib64/openldap /usr/lib/x86_64-linux-gnu/openldap /opt/homebrew/opt/openldap/libexec/openldap " in
            *" $d "*) ;;
            *) _missing="$_missing $d" ;;
        esac
    done
    [ -z "$_missing" ] || { echo "RESULT: FAIL — the sibling LDAP suite searches module dirs this one does not:$_missing"; exit 1; }
fi

LP=; P=; MSP=; OP=
cleanup(){ kill $OP 2>/dev/null; kill $MSP 2>/dev/null; kill $P 2>/dev/null; kill $LP 2>/dev/null; pg_cleanup; }
pg_setup ad_template_import

trap cleanup EXIT

echo "=== a throwaway directory carrying the AD template schema ==="
mkdir -p ldap/data
# The attribute NAMES are AD's; the OIDs are private stand-ins under an unassigned arc,
# because nothing in the product looks at them. Syntaxes matter and are AD's: the two
# binary attributes are octetString, everything else is a directory string or an integer.
cat > ad-pki.schema <<'SCHEMA'
attributetype ( 1.3.6.1.4.1.99999.1.1 NAME 'msPKI-Cert-Template-OID'
  EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.99999.1.2 NAME 'msPKI-Template-Schema-Version'
  EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.99999.1.3 NAME 'msPKI-Template-Minor-Revision'
  EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.99999.1.4 NAME 'msPKI-Minimal-Key-Size'
  EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.99999.1.5 NAME 'msPKI-Certificate-Name-Flag'
  EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.99999.1.6 NAME 'msPKI-Enrollment-Flag'
  EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.99999.1.7 NAME 'msPKI-Private-Key-Flag'
  EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.99999.1.8 NAME 'pKIExpirationPeriod'
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.99999.1.15 NAME 'pKIOverlapPeriod'
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.99999.1.9 NAME 'pKIKeyUsage'
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.99999.1.10 NAME 'pKIDefaultKeySpec'
  EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.99999.1.11 NAME 'pKIDefaultCSPs'
  EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 1.3.6.1.4.1.99999.1.12 NAME 'pKIExtendedKeyUsage'
  EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributetype ( 1.3.6.1.4.1.99999.1.13 NAME 'revision'
  EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.99999.1.14 NAME 'flags'
  EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
objectclass ( 1.3.6.1.4.1.99999.2.2 NAME 'container' SUP top STRUCTURAL MUST ( cn ) )
objectclass ( 1.3.6.1.4.1.99999.2.1 NAME 'pKICertificateTemplate' SUP top STRUCTURAL
  MUST ( cn ) MAY ( displayName $ msPKI-Cert-Template-OID $ msPKI-Template-Schema-Version $
    msPKI-Template-Minor-Revision $ msPKI-Minimal-Key-Size $ msPKI-Certificate-Name-Flag $
    msPKI-Enrollment-Flag $ msPKI-Private-Key-Flag $ pKIExpirationPeriod $
    pKIOverlapPeriod $ pKIKeyUsage $
    pKIDefaultKeySpec $ pKIDefaultCSPs $ pKIExtendedKeyUsage $ revision $ flags ) )
SCHEMA

# ⚠️ WHAT THIS FIXTURE CANNOT DO, stated rather than papered over. In production the
# templates container is FOUND: the product asks the server for its
# configurationNamingContext, because in a forest that context is not a suffix of the
# domain NC and deriving it from a base DN is how an import works on one domain and not the
# next. slapd will not serve that attribute — its `rootDSE` directive parses and the
# attribute is simply not returned, measured — so this suite names the container directly
# with LDAP_TEMPLATE_BASE instead.
#
# That means the DISCOVERY step is NOT covered here; only a real directory exercises it.
# What IS covered is everything after it, which is where the decoding risk lives.
cat > slapd.conf <<EOF
include $SCH/core.schema
include $SCH/cosine.schema
include $SCH/inetorgperson.schema
include $W/ad-pki.schema
${MODP:+modulepath $MODP}
${MODP:+moduleload back_mdb}
pidfile $W/ldap/slapd.pid
argsfile $W/ldap/slapd.args
database mdb
maxsize 33554432
suffix "dc=fastpki,dc=test"
rootdn "cn=admin,dc=fastpki,dc=test"
rootpw adminpass
directory $W/ldap/data
EOF
LURI="ldap://127.0.0.1:$LPORT"
# ⚠️ THE DIRECTORY IS A ROW, AND THE CONF NO LONGER MENTIONS IT AT ALL. The LDAP_* keys
# were left in these fixtures for a while after the reader stopped consulting them, which
# quietly MASKED a bug: the console gated its whole directory surface on cfg.ldap_uris, and
# the fixture kept satisfying that gate with a value nothing else read. They are gone, so
# this row is the only thing that can make a directory exist here.
# ⚠️ EVERY directory setting this suite relies on has to be on the ROW, not only the URI.
# The bind account and the TEMPLATE BASE are provider columns now: the conf below still
# spells LDAP_BIND_DN / LDAP_TEMPLATE_BASE, and nothing reads them. Seeding only the URI
# left the template fetch with no container to search and turned 20 assertions red while
# the directory itself was perfectly healthy — a fixture half-moved to the new source.
TPLBASE='cn=Certificate Templates,cn=Public Key Services,cn=Services,cn=Configuration,dc=fastpki,dc=test'
seed_ldap_provider default "$LURI" "dc=fastpki,dc=test" \
    "cn=admin,dc=fastpki,dc=test" "adminpass" --template-base "$TPLBASE" || {
    echo "cannot seed the directory — the assertions below would measure a deployment"
    echo "with no directories at all."; exit 1; }
"$SLAPD" -h "$LURI/" -f slapd.conf -d 0 >slapd.log 2>&1 & LP=$!
# ⚠️ POLL, DO NOT SLEEP AT IT. `sleep 1` held only while suites ran one at a time. Under
# six parallel shards slapd had not finished binding and loading its LDIF, so the import
# read an empty directory and this suite failed with "the fixture directory loaded
# completely: expected 8 got 0" — which reads as a broken template importer rather than a
# directory that was still starting. The kill -0 below stays: it distinguishes "slapd died"
# from "slapd never answered", and wait_ldap returns immediately in the first case.
wait_ldap "$LP" "$LURI" || { echo "slapd did not answer:"; tail -20 slapd.log; echo "RESULT: FAIL"; exit 1; }
kill -0 $LP 2>/dev/null || { echo "slapd failed to start:"; cat slapd.log; echo "RESULT: FAIL"; exit 1; }

# ── the fixture values, DERIVED so the expectation cannot drift from the input ──────────
# 365 days as AD stores it: negative, little-endian, 100-nanosecond ticks.
DAYS=365
TICKS=$(( DAYS * 86400 * 10000000 ))
NEG=$(( 0 - TICKS ))
# ⚠️ WRITTEN TO A FILE, NOT BUILT IN A VARIABLE. Command substitution STRIPS NUL bytes, and
# this value has them — 365 days is a whole number of 256-tick units, so its low byte is
# 0x00. Assembling the 8 bytes with $( ) silently produced a SEVEN-byte attribute, the
# decoder correctly rejected the wrong length, and the import fell back to the default
# validity. The suite reported that as a decoder failure when the fixture was the thing
# that was broken.
le8_file(){  # <signed 64-bit> <path> — its 8 little-endian bytes, NULs intact
    local v="$1" i
    : > "$2"
    for i in 0 1 2 3 4 5 6 7; do
        printf "\\$(printf '%03o' $(( (v >> (8*i)) & 0xff )) )" >> "$2"
    done
}
le8_file "$NEG" exp.bin
EXP_B64="$(base64 < exp.bin | tr -d '\n')"
# ⚠️ SUB-DAY ON PURPOSE — this is the case the obvious implementation loses. The renewal
# overlap is stored the same way as the expiration period, and a directory routinely gives
# a short-lived template an overlap measured in HOURS. Decoding it into whole days would
# round this to zero, i.e. "renew only at expiry" — a different policy that still looks
# like a plausible number. Eight hours cannot survive a day-granular reader.
OVL_SEC=$(( 8 * 3600 ))
le8_file "$(( 0 - OVL_SEC * 10000000 ))" ovl.bin
OVL_B64="$(base64 < ovl.bin | tr -d '\n')"
# KeyUsage 0xA0 in ONE byte — digitalSignature|keyEncipherment. The product must widen it
# to 0xA000 (40960); a decoder that used the byte as-is would report 160.
printf '\240' > ku.bin
KU_B64="$(base64 < ku.bin | tr -d '\n')"
EXP_KU=40960
chk "fixture: the expiry attribute really is 8 bytes" 8 "$(wc -c < exp.bin | tr -d ' ')"

ldapadd -x -H "$LURI" -D "cn=admin,dc=fastpki,dc=test" -w adminpass >add.log 2>&1 <<LDIF
dn: dc=fastpki,dc=test
objectClass: top
objectClass: dcObject
objectClass: organization
o: FastPKI Test
dc: fastpki

dn: cn=Configuration,dc=fastpki,dc=test
objectClass: top
objectClass: container
cn: Configuration

dn: cn=Services,cn=Configuration,dc=fastpki,dc=test
objectClass: top
objectClass: container
cn: Services

dn: cn=Public Key Services,cn=Services,cn=Configuration,dc=fastpki,dc=test
objectClass: top
objectClass: container
cn: Public Key Services

dn: cn=Certificate Templates,cn=Public Key Services,cn=Services,cn=Configuration,dc=fastpki,dc=test
objectClass: top
objectClass: container
cn: Certificate Templates

dn: cn=LabWebServer,cn=Certificate Templates,cn=Public Key Services,cn=Services,cn=Configuration,dc=fastpki,dc=test
objectClass: pKICertificateTemplate
cn: LabWebServer
msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.9999.1
msPKI-Template-Schema-Version: 2
msPKI-Minimal-Key-Size: 3072
revision: 100
msPKI-Template-Minor-Revision: 3
pKIDefaultKeySpec: 1
pKIExpirationPeriod:: $EXP_B64
pKIOverlapPeriod:: $OVL_B64
pKIKeyUsage:: $KU_B64
pKIDefaultCSPs: 1,Microsoft RSA SChannel Cryptographic Provider
pKIDefaultCSPs: 2,Microsoft Software Key Storage Provider
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.1

dn: cn=LabNoOverlap,cn=Certificate Templates,cn=Public Key Services,cn=Services,cn=Configuration,dc=fastpki,dc=test
objectClass: pKICertificateTemplate
cn: LabNoOverlap
msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.9999.2
msPKI-Template-Schema-Version: 2
msPKI-Minimal-Key-Size: 2048
pKIExpirationPeriod:: $EXP_B64

dn: cn=LabNoOid,cn=Certificate Templates,cn=Public Key Services,cn=Services,cn=Configuration,dc=fastpki,dc=test
objectClass: pKICertificateTemplate
cn: LabNoOid
msPKI-Minimal-Key-Size: 2048
LDIF
# ⚠️ EVERY entry, not "at least one". The first version checked for a single "adding new
# entry" line, which passed while the four container entries were all being rejected —
# `container` is not in slapd's core schema and had to be defined above. A partial fixture
# is how a suite ends up measuring the wrong thing.
if grep -q '^ldap_add:' add.log; then echo "ldapadd failed:"; cat add.log; echo "RESULT: FAIL"; exit 1; fi
chk "the fixture directory loaded completely" 8 "$(grep -c '^adding new entry' add.log)"

echo "=== the console reads them out of the directory ==="
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
seed_web_user tadmin tadminpw12345 admin
"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; tail -20 web.log; echo "RESULT: FAIL"; exit 1; }
JAR="$W/c.jar"
# ⚠️ PRECONDITION, NOT DECORATION. This login used to be fire-and-forget, so a session that
# was never established turned every console assertion below into a 401 and the suite
# reported twenty failures about decoders and imports that had never been exercised at all.
# A fixture that fails must not be reportable as the product failing.
LOGIN="$(curl -s -c "$JAR" -o login.json -w '%{http_code}' -X POST \
         "http://127.0.0.1:$PORT/api/login" -d 'username=tadmin&password=tadminpw12345')"
if [ "$LOGIN" != 200 ]; then
    echo "  console login failed (HTTP $LOGIN) — every assertion below would be a 401:"
    head -3 login.json 2>/dev/null
    tail -20 web.log
    echo "RESULT: FAIL"; exit 1
fi
PREVIEW="$(curl -s -b "$JAR" "http://127.0.0.1:$PORT/api/templates/ad")"
jnum(){ printf '%s' "$PREVIEW" | tr ',' '\n' | grep -m1 "\"$1\":" | sed 's/.*: *//; s/[^0-9-].*//'; }
# The preview now carries more than one template, so a whole-document grep would answer
# about whichever happens to come first. Read the field out of the named template's object.
tnum(){ printf '%s' "$PREVIEW" | tr '{' '\n' | grep "\"name\":\"$1\"" \
        | grep -o "\"$2\":-\{0,1\}[0-9]*" | head -1 | sed 's/.*://'; }

chk "the preview reads the directory"       yes "$(printf '%s' "$PREVIEW" | grep -q 'LabWebServer' && echo yes || echo no)"
# ⚠️ EXACTLY ONE. The second fixture entry has a cn but no OID, and a template with no OID
# cannot be offered over XCEP at all — importing it would put a row in the table that every
# enrolment path then skips, which is a silent half-import.
chk "a template with no OID is skipped"     2   "$(jnum count)"
chk "  and it is the one WITH an OID"       no  "$(printf '%s' "$PREVIEW" | grep -q 'LabNoOid' && echo yes || echo no)"

echo "=== the three decoders, against values stored the way AD stores them ==="
chk "pKIExpirationPeriod -> $DAYS days"     "$DAYS" "$(tnum LabWebServer validity_days)"
chk "pKIOverlapPeriod -> $OVL_SEC seconds" "$OVL_SEC" "$(tnum LabWebServer overlap_seconds)"
# ⚠️ AND THE ENTRY THAT CARRIES NONE, which is the branch deciding whether the policy
# document derives an overlap or honours one. A decoder answering 0 for an absent attribute
# would be indistinguishable from a directory configuring "renew only at expiry".
chk "  a template with no overlap attribute stays 'derive'" -1 \
    "$(tnum LabNoOverlap overlap_seconds)"
chk "pKIKeyUsage 0xA0 -> 0xA000 bitmap"     "$EXP_KU" "$(tnum LabWebServer key_usage)"
chk "msPKI-Minimal-Key-Size carried"        3072 "$(tnum LabWebServer min_key_size)"
chk "revision carried"                      100  "$(tnum LabWebServer major_rev)"
chk "minor revision carried"                3    "$(tnum LabWebServer minor_rev)"
# The order prefix must be gone, and the NAME must survive intact.
chk "pKIDefaultCSPs loses its order prefix" yes \
    "$(printf '%s' "$PREVIEW" | grep -q '"Microsoft RSA SChannel Cryptographic Provider"' && echo yes || echo no)"
chk "  and does not keep the '1,'"          no \
    "$(printf '%s' "$PREVIEW" | grep -q '1,Microsoft RSA SChannel' && echo yes || echo no)"
chk "both providers survive"                yes \
    "$(printf '%s' "$PREVIEW" | grep -q 'Microsoft Software Key Storage Provider' && echo yes || echo no)"
chk "the EKU came across"                   yes \
    "$(printf '%s' "$PREVIEW" | grep -q '1.3.6.1.5.5.7.3.1' && echo yes || echo no)"

echo "=== preview WRITES NOTHING; apply is the step that does ==="
chk "nothing in ms_templates after a preview" 0 \
    "$("$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -tAc \
        "select count(*) from ms_templates where name='LabWebServer'" 2>/dev/null)"
count_tpl(){ "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -tAc \
             "select count(*) from ms_templates where name='$1'" 2>/dev/null; }

echo "=== the apply imports WHAT WAS SELECTED, and nothing else ==="
# An apply that names no template is a mistake, not "import everything" — the bulk import
# is precisely what the selection replaces, and a silent fallback to it would put the whole
# directory in the table on an empty click.
NONE="$(curl -s -o none.json -w '%{http_code}' -b "$JAR" -X POST "http://127.0.0.1:$PORT/api/templates/ad")"
chk "an apply naming no template -> 400"      400 "$NONE"
chk "  and it wrote nothing"                  0   "$(count_tpl LabWebServer)"

# A name the directory does not hold. The operator picked from a list that has since
# changed, so importing "whatever still matches" would report success for a selection it
# did not honour — and say nothing about which entry went missing.
#
# ⚠️ THIS RUNS BEFORE THE SUCCESSFUL APPLY ON PURPOSE. The "wrote nothing" assertion below
# is only a measurement while the table is still empty; after a successful import the row
# it looks for exists either way and the check passes without testing anything.
GONE="$(curl -s -o gone.json -w '%{http_code}' -b "$JAR" -X POST "http://127.0.0.1:$PORT/api/templates/ad" \
        -d 'name=LabWebServer' -d 'name=LabVanished')"
chk "a name the directory no longer holds -> 409" 409 "$GONE"
chk "  and the refusal names the missing one"     yes \
    "$(grep -q 'LabVanished' gone.json && echo yes || echo no)"
# NOTHING WRITTEN, not even the half that WAS still there. A partial apply leaves the
# operator with some of the selection in the table and no way to tell which part.
chk "  and the still-present half was not written either" 0 "$(count_tpl LabWebServer)"

# ⚠️ THE LOAD-BEARING ASSERTION IS THE SECOND ONE. The directory offers two importable
# templates and this apply names ONE. "The named one arrived" passes just as well when the
# server ignores the selection and imports the lot — only the absence of the OTHER one
# separates a selective import from a bulk import that happens to include what was asked
# for. Watched failing: with the name filter removed, LabNoOverlap lands too.
APPLY="$(curl -s -o ap.json -w '%{http_code}' -b "$JAR" -X POST "http://127.0.0.1:$PORT/api/templates/ad" \
         -d 'name=LabWebServer')"
chk "apply succeeds"                          200 "$APPLY"
chk "  the selected template is in the table" 1   "$(count_tpl LabWebServer)"
chk "  THE UNSELECTED ONE IS NOT"             0   "$(count_tpl LabNoOverlap)"
chk "  and the count it reports is the selection, not the offer" 1 \
    "$(grep -o '"imported":[0-9]*' ap.json | sed 's/.*://')"
# Decode what the system HOLDS, not the status code: the stored row must carry the DECODED
# validity, or the import wrote a template that is not what the directory said.
chk "  the stored validity is the decoded one" "$DAYS" \
    "$("$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -tAc \
        "select validity_days from ms_templates where name='LabWebServer'" 2>/dev/null)"
chk "  and the audit trail names the source"  1 \
    "$("$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -tAc \
        "select least(count(*),1) from audit_log where action='web_templates_imported' and detail like '%source=ad%'" 2>/dev/null)"


# ── THE IMPORTED TEMPLATE HAS TO ISSUE, REVOKE AND VALIDATE ──────────────────────────
#
# ⚠️ EVERYTHING ABOVE STOPS AT THE TABLE, AND THAT IS NOT WHERE A DECODER BUG COSTS
# ANYTHING. A wrong pKIExpirationPeriod, pKIKeyUsage or msPKI-Minimal-Key-Size in
# ms_templates is only a wrong number until an enrolment reads it; what it actually
# produces is a CERTIFICATE that is not what the directory said, or a refusal that should
# not have happened. Nothing here proved a row imported from a directory is ever honoured
# at issuance.
#
# The join is the point: this enrols against the row THIS SUITE IMPORTED, not one written
# by hand. Then the certificate is revoked and validated, because a certificate a CA cannot
# revoke is worse than one it never issued.
echo "=== the imported template ISSUES: enrol, revoke, validate ==="

source "$ROOT/tests/service_cert_helpers.sh"

MSPORT=18302; OCSPPORT=18303
ca_in_token ca.pem "/CN=AD Tmpl Import CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout ms.key -out ms.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

cat > ms.conf <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=adca
ROOT_CA_PEM=$W/root.pem
MS_CERT=$W/ms.pem
MS_KEY=$W/ms.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
MS_BIND=127.0.0.1
MS_PORT=$MSPORT
XCEP_PATH=/msxcep
WSTEP_PATH=/mswstep
CERT_VALIDITY_DAYS=90
LOG_LEVEL=info
EOF
# ⚠️ CERT_VALIDITY_DAYS IS DELIBERATELY 90 AND THE DIRECTORY SAYS 365. An MS template states
# what this CA will issue, so it is HONOURED rather than treated as a ceiling: the shorter
# server default must not win. Set the two equal and the assertion below would pass whether
# the template was consulted or ignored, which is why they differ and why the default is the
# SHORTER of the two — the direction a cap could not produce.
seed_ca_from_conf ms.conf

seed_web_user adenrol adenrolpw12345 adrequester
pg_exec "INSERT INTO roles(name,description) VALUES('adrequester','imported template')
         ON CONFLICT DO NOTHING;"
pg_exec "INSERT INTO role_permissions(role,permission,scope) VALUES
           ('adrequester','ms:enrol','*'),
           ('adrequester','template:use','LabWebServer')
         ON CONFLICT DO NOTHING;"

"$BUILD/fastpki-ms" --config ms.conf >ms.log 2>&1 & MSP=$!
wait_conf "ms.conf" MS_PORT "$MSP" || true
kill -0 $MSP 2>/dev/null || { echo "fastpki-ms died:"; tail -20 ms.log; echo "RESULT: FAIL"; exit 1; }

# The CSR is built here rather than with ms_csr_b64, which is fixed at rsa:2048 — this
# template's imported minimum is 3072, and the key size is one of the values under test.
ad_csr_b64() {   # <cn> <template> <keyfile> <bits>
    printf '[req]\ndistinguished_name=dn\nreq_extensions=v3\nprompt=no\n[dn]\nCN=%s\n[v3]\n1.3.6.1.4.1.311.20.2=ASN1:BMPSTRING:%s\n' \
        "$1" "$2" > "$3.cnf"
    "$OSSL" req -new -newkey "rsa:$4" -nodes -keyout "$3" -out "$3.csr" \
        -config "$3.cnf" >/dev/null 2>&1
    "$OSSL" req -in "$3.csr" -outform DER 2>/dev/null | "$OSSL" base64 -A
}
ad_wstep() {     # <csr-b64> -> raw RSTR
    curl -sk -H 'Content-Type: application/soap+xml; charset=utf-8' --data \
      '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><s:Header><wsse:Security><wsse:UsernameToken><wsse:Username>adenrol</wsse:Username><wsse:Password>adenrolpw12345</wsse:Password></wsse:UsernameToken></wsse:Security></s:Header><s:Body><wst:RequestSecurityToken><wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType><wsse:BinarySecurityToken>'"$1"'</wsse:BinarySecurityToken></wst:RequestSecurityToken></s:Body></s:Envelope>' \
      "https://127.0.0.1:$MSPORT/mswstep/adca"
}

# ⚠️ THE NEGATIVE FIRST, AND IT IS NOT FILLER. msPKI-Minimal-Key-Size is one of the imported
# values; if it were dropped or mis-decoded, a 2048-bit key would sail through and the
# POSITIVE case below would still pass. Only the refusal proves the imported minimum
# reaches the issuing path at all.
SMALL="$(ad_wstep "$(ad_csr_b64 small.localhost LabWebServer small.key 2048)")"
chk "a key under the template's imported minimum is refused" yes \
    "$(printf '%s' "$SMALL" | grep -q 'Fault' && echo yes || echo no)"
chk "  and the log names the imported minimum, not a server default" yes \
    "$(grep -q "requires at least 3072" ms.log && echo yes || echo no)"

RSTR="$(ad_wstep "$(ad_csr_b64 adenrol.localhost LabWebServer leaf.key 3072)")"
# ⚠️ THE RSTR CARRIES TWO BinarySecurityTokens and the FIRST is the PKCS#7 chain, not the
# leaf. Taking "the first one" decodes to something that is not the certificate and every
# assertion below then measures the chain instead.
printf '%s' "$RSTR" | sed 's|<wst:RequestedSecurityToken>|\n&|' | grep 'RequestedSecurityToken' \
  | sed 's|.*<wsse:BinarySecurityToken[^>]*>||; s|</wsse:BinarySecurityToken>.*||' > leaf.b64
chk "the imported template issues to a conforming key" yes \
    "$([ -s leaf.b64 ] && echo yes || echo no)"
"$OSSL" base64 -d -A -in leaf.b64 2>/dev/null | "$OSSL" x509 -inform DER -out leaf.pem 2>/dev/null
chk "  and it parses as a certificate" yes "$([ -s leaf.pem ] && echo yes || echo no)"

if [ -s leaf.pem ]; then
    NB=$("$OSSL" x509 -in leaf.pem -noout -startdate | sed 's/notBefore=//')
    NA=$("$OSSL" x509 -in leaf.pem -noout -enddate   | sed 's/notAfter=//')
    NBS=$(date -d "$NB" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$NB" +%s 2>/dev/null)
    NAS=$(date -d "$NA" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$NA" +%s 2>/dev/null)
    SPAN=$(( (NAS - NBS) / 86400 ))
    chk "  the validity is the DIRECTORY's $DAYS days, NOT the shorter server default 90" yes \
        "$([ "$SPAN" -ge $((DAYS - 2)) ] && [ "$SPAN" -le $((DAYS + 2)) ] && echo yes || echo no)"
    KU=$("$OSSL" x509 -in leaf.pem -noout -text | grep -A1 "X509v3 Key Usage" | tail -1)
    chk "  the key usage is the decoded pKIKeyUsage (0xA0 -> digitalSignature+keyEncipherment)" yes \
        "$(printf '%s' "$KU" | grep -q "Digital Signature" \
           && printf '%s' "$KU" | grep -q "Key Encipherment" && echo yes || echo no)"
fi

SER=$("$OSSL" x509 -in leaf.pem -noout -serial 2>/dev/null | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
chk "  the certificate is in the database" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE lower(serial)=lower('$SER');" | tr -d ' ')"

# ── validation, before and after revocation ─────────────────────────────────────────
printf 'PG_CONNINFO=%s\nOCSP_BIND=127.0.0.1\nOCSP_PORT=%s\nSIGNING_CA_PEM=%s\nSIGNING_CA_KEY=%s\nSIGNING_CA_ID=adca\nROOT_CA_PEM=%s\nLOG_LEVEL=err\n' \
    "$PG_CONNINFO" "$OCSPPORT" "$W/ca.pem" "$CA_KEY_URI" "$W/root.pem" > ocsp.conf
grep '^PKCS11_MODULE=' ms.conf >> ocsp.conf 2>/dev/null
printf 'OCSP_RESPONDER_KEY=%s\n' "$(ocsp_responder_key "$W/ca.pem" "$CA_KEY_URI" adca "$W")" >> ocsp.conf
"$BUILD/fastpki-ocsp" --config ocsp.conf >ocsp.log 2>&1 & OP=$!
wait_conf "ocsp.conf" OCSP_PORT "$OP" || true
ocsp_status() { "$OSSL" ocsp -issuer ca.pem -cert leaf.pem -url "http://127.0.0.1:$OCSPPORT/ocsp" \
                -noverify 2>/dev/null | grep -oE "good|revoked" | head -1; }
chk "OCSP says good before revocation" good "$(ocsp_status)"

# Revoked through the CONSOLE, which is the path an operator actually has.
RV="$(curl -s -o rv.json -w '%{http_code}' -b "$JAR" -X POST \
      "http://127.0.0.1:$PORT/api/certs/$SER/revoke?reason=1")"   # keyCompromise; the API takes the code
chk "the console revokes it" 200 "$RV"
chk "  and the database says revoked" -1 \
    "$(pg_exec "SELECT status FROM certs WHERE lower(serial)=lower('$SER');" | tr -d ' ')"
chk "OCSP says revoked after revocation" revoked "$(ocsp_status)"

kill $OP 2>/dev/null; wait $OP 2>/dev/null; OP=
kill $MSP 2>/dev/null; wait $MSP 2>/dev/null; MSP=

echo "=== a directory that is not there is reported, not swallowed ==="
kill $LP 2>/dev/null; wait $LP 2>/dev/null; LP=
DOWN="$(curl -s -o down.json -w '%{http_code}' -b "$JAR" "http://127.0.0.1:$PORT/api/templates/ad")"
chk "an unreachable directory -> 502"       502 "$DOWN"
chk "  and the reason names the bind"       yes \
    "$(grep -qi 'bind' down.json && echo yes || echo no)"

kill $P 2>/dev/null; wait $P 2>/dev/null
echo
echo "=== AD TEMPLATE IMPORT: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
