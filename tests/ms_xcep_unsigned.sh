#!/usr/bin/env bash
# Every MS-XCEP element the schema types unsigned must be serialized unsigned.
#
# ── Why this exists ──────────────────────────────────────────────────────────────
#
# The policy document is validated as a whole by the Windows client. ONE element whose
# text does not match its declared XSD type makes the client reject the ENTIRE response —
# not that one template — so a single bad value takes every template down with it and the
# policy server cannot be added at all. That is a strange failure to read from the outside:
# it looks like a size or count limit, because offering a smaller set of templates that
# happens to exclude the bad one makes the whole thing start working.
#
# It has now happened twice, with two different fields:
#
#   * the four flag bitmasks. A directory returns msPKI-Certificate-Name-Flag as a signed
#     decimal (-1509949440 is really 0xA6000000), xcep types them unsignedInt, and the
#     client answered WS_E_NUMERIC_OVERFLOW.
#   * renewalPeriodSeconds, which was emitted as `validity - 30 days`. The directory's own
#     default templates include a 7-day and a 14-day one, so that arithmetic went NEGATIVE
#     into an xs:unsignedLong and the client answered WS_E_INVALID_FORMAT.
#
# Fixing one site at a time is what let the second one happen, so this asserts the SHAPE:
# no element in the unsigned set may ever carry a minus sign, whatever is in the database.
# The list below is the complete set of unsigned elements in the published XCEP schema
# (xs:unsignedInt, plus the two xs:unsignedLong in certificateValidity). The OID-reference
# elements are xs:int and are deliberately NOT in it — they are allowed to be negative.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; PORT=18455
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=XCEP Unsigned CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout ms.key -out ms.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup ms_xcep_unsigned
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
seed_web_user boss bosspw admin
printf "internal\n" > domains.txt
seed_domains $W/domains.txt

cat > bootstrap.conf <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
MS_CERT=$W/ms.pem
MS_KEY=$W/ms.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
MS_BIND=127.0.0.1
MS_PORT=$PORT
XCEP_PATH=/msxcep
WSTEP_PATH=/mswstep
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf

echo "=== the fixture: the directory values that actually broke this ==="
# ⚠️ THESE ARE REAL NUMBERS OFF A REAL DIRECTORY, not invented extremes.
#
# CAExchange really ships with a 7-day lifetime and OCSPResponseSigning with 14, which is
# what drove renewalPeriodSeconds negative; and -1509949440 is the signed rendering of the
# 0xA6000000 name-flag that several stock templates carry. A template a directory would
# never produce could be dismissed as an unrealistic input; these cannot.
pg_exec "INSERT INTO ms_templates
           (name,oid,schema,validity_days,min_key_size,key_spec,key_usage,
            major_rev,minor_rev,subject_name_flags,enrollment_flags,general_flags)
         VALUES
           ('ShortSeven','1.3.6.1.4.1.99999.34.1',2,7,2048,1,8192,106,0,1,1,65600),
           ('ShortFourteen','1.3.6.1.4.1.99999.34.2',3,14,2048,2,32768,101,0,402653184,20480,66112),
           ('NegativeFlags','1.3.6.1.4.1.99999.34.3',1,365,2048,1,40960,4,1,-1509949440,41,66106)
         ON CONFLICT (name) DO UPDATE SET validity_days=EXCLUDED.validity_days,
           subject_name_flags=EXCLUDED.subject_name_flags;" >/dev/null
# Two more, for the overlap the directory itself configures. The serializer only derives a
# default when the template carries none, so both branches need a row: one with a stored
# overlap that must come out unchanged, and one whose stored overlap is longer than the
# lifetime and must be clamped rather than emitted as-is.
pg_exec "INSERT INTO ms_templates
           (name,oid,schema,validity_days,min_key_size,key_spec,key_usage,
            major_rev,minor_rev,subject_name_flags,enrollment_flags,general_flags,overlap_seconds)
         VALUES
           ('StoredOverlap','1.3.6.1.4.1.99999.34.4',2,365,2048,1,40960,100,0,1,1,65600,604800),
           ('OverlapTooLong','1.3.6.1.4.1.99999.34.5',2,10,2048,1,40960,100,0,1,1,65600,31536000)
         ON CONFLICT (name) DO UPDATE SET validity_days=EXCLUDED.validity_days,
           overlap_seconds=EXCLUDED.overlap_seconds;" >/dev/null
# At least two — a count would have to be edited every time a row is added for some other
# reason, and an edit like that is how a precondition quietly stops meaning anything.
chk "PRECONDITION: templates shorter than the old 30-day subtraction exist" yes \
    "$([ "$(pg_exec "SELECT count(*) FROM ms_templates WHERE validity_days < 30;" | tr -d ' ')" \
        -ge 2 ] && echo yes || echo no)"
chk "PRECONDITION: and one carries a negative directory flag" 1 \
    "$(pg_exec "SELECT count(*) FROM ms_templates WHERE subject_name_flags < 0;" | tr -d ' ')"

"$ROOT/build/fastpki-ms" --config bootstrap.conf >ms.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-ms died:"; cat ms.log; exit 1; }
U="https://127.0.0.1:$PORT"

XCEP_REQ='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"><client><lastUpdate xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/><preferredLanguage xsi:nil="true" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/></client></GetPolicies></s:Body></s:Envelope>'
curl -sk -u boss:bosspw -H "Host: localhost:$PORT" \
     -H "Content-Type: application/soap+xml; charset=utf-8" \
     --data "$XCEP_REQ" "$U/msxcep/ca" > resp.xml

echo "=== the response really contains the hostile templates ==="
# ⚠️ ANTI-VACUITY, AND IT IS THE ASSERTION THAT MATTERS MOST HERE. Every check below is of
# the form "no element contains a minus sign", which an EMPTY or refused response satisfies
# perfectly. Without this the suite would go green against a server that answered nothing.
chk "a policy document came back" yes \
    "$([ -s resp.xml ] && grep -q '<policies>' resp.xml && echo yes || echo no)"
for t in ShortSeven ShortFourteen NegativeFlags StoredOverlap OverlapTooLong; do
    chk "  and it offers $t" yes "$(grep -q "$t" resp.xml && echo yes || echo no)"
done

echo "=== no unsigned element carries a negative value ==="
# The complete unsigned set from the published schema. Kept as one list so a new field
# added to the serializer is a one-line addition here rather than a new kind of check.
UNSIGNED="policySchema validityPeriodSeconds renewalPeriodSeconds minimalKeyLength
          keySpec keyUsageProperty majorRevision minorRevision privateKeyFlags
          subjectNameFlags enrollmentFlags generalFlags clientAuthentication priority
          nextUpdateHours rASignatures symmetricAlgorithmKeyLength group"
bad=""
for tag in $UNSIGNED; do
    # The whole envelope is one line, so grep -o and inspect each occurrence.
    if grep -o "<$tag>[^<]*</$tag>" resp.xml | grep -q '>-'; then
        bad="$bad $tag=$(grep -o "<$tag>-[^<]*</$tag>" resp.xml | head -1)"
    fi
done
chk "every unsigned element is non-negative" "" "$bad"

echo "=== and the renewal period is a sane overlap, not a subtraction ==="
# renewalPeriodSeconds is how long BEFORE expiry renewal should begin, so it can never
# exceed the lifetime, whatever produced it.
vals(){ grep -o "<$1>[^<]*</$1>" resp.xml | sed "s|<$1>||; s|</$1>||"; }
paste -d' ' <(vals validityPeriodSeconds) <(vals renewalPeriodSeconds) > pairs.txt
chk "fixture: validity/renewal pairs were extracted" yes \
    "$([ -s pairs.txt ] && echo yes || echo no)"
overlong=$(awk '$2 > $1 { c++ } END { print c+0 }' pairs.txt)
chk "no renewal period exceeds its own validity" 0 "$overlong"
# ⚠️ AND NOT ZERO EVERYWHERE. Clamping negatives to 0 would satisfy every assertion above
# while telling every client never to renew early — a silent regression wearing a green
# suite. At least the long-lived templates must carry a real overlap.
realistic=$(awk '$2 > 0 { c++ } END { print c+0 }' pairs.txt)
chk "templates do get a non-zero renewal overlap" yes \
    "$([ "$realistic" -gt 0 ] && echo yes || echo no)"

echo "=== the DIRECTORY's overlap is used where the template carries one ==="
# ⚠️ PER-TEMPLATE, because the aggregate checks above cannot tell the two sources apart.
# The envelope is one line; split it so each policy block is its own line and the three
# fields can be read together.
sed 's|<policy>|\n&|g' resp.xml | grep '<commonName>' > policies.txt
pol(){   # <template name> <element> -> its text
    grep "<commonName>$1</commonName>" policies.txt \
        | grep -o "<$2>[^<]*</$2>" | head -1 | sed "s|<$2>||; s|</$2>||"
}
chk "fixture: policies split one per line" yes \
    "$([ "$(wc -l < policies.txt)" -ge 5 ] && echo yes || echo no)"
# The derived default: no stored overlap, so it must stay under half the lifetime or the
# client would start renewing the moment it was issued.
for t in ShortSeven ShortFourteen NegativeFlags; do
    v=$(pol $t validityPeriodSeconds); r=$(pol $t renewalPeriodSeconds)
    chk "  $t derives an overlap under half its lifetime ($r of $v)" yes \
        "$([ -n "$v" ] && [ -n "$r" ] && [ "$r" -le $((v / 2)) ] && echo yes || echo no)"
done
# ⚠️ THE CONTROL IS A TEMPLATE WITH THE SAME LIFETIME. NegativeFlags and StoredOverlap are
# both 365 days; only one carries a stored overlap. If the serializer ignored the column
# the two would emit the SAME renewal period, so this cannot pass by accident — and it
# needs no constant copied out of the product, which is what would rot.
chk "a stored overlap is emitted verbatim" 604800 "$(pol StoredOverlap renewalPeriodSeconds)"
chk "  and differs from what the same lifetime derives" no \
    "$([ "$(pol StoredOverlap renewalPeriodSeconds)" = "$(pol NegativeFlags renewalPeriodSeconds)" ] \
       && echo yes || echo no)"
# A directory may hold an overlap LONGER than the validity — nothing in AD forbids it — and
# emitting that says "renew before this was issued". The ceiling is the lifetime itself.
chk "an overlap longer than the lifetime is clamped to it" \
    "$(pol OverlapTooLong validityPeriodSeconds)" "$(pol OverlapTooLong renewalPeriodSeconds)"
chk "  and it is not silently replaced by the derived default" no \
    "$([ "$(pol OverlapTooLong renewalPeriodSeconds)" \
        -le $(( $(pol OverlapTooLong validityPeriodSeconds) / 2 )) ] && echo yes || echo no)"

echo "=== the serializer has no raw signed rendering left in an unsigned element ==="
# ⚠️ THE CENSUS, because fixing one site at a time is exactly how the second instance of
# this bug happened. A field added later with a plain std::to_string would pass every
# runtime assertion above as long as today's fixtures happen to be positive; this fails on
# the day it is written. It matches CODE, not prose: `std::to_string` inside an element
# whose name is in the unsigned set.
MSSRC="$ROOT/src/msxcep/main.cpp"
chk "fixture: the serializer source was read" yes \
    "$([ -s "$MSSRC" ] && echo yes || echo no)"
raw=""
for tag in $UNSIGNED; do
    grep -q "\"<$tag>\" *+ *std::to_string" "$MSSRC" && raw="$raw $tag"
done
chk "no unsigned element is built with a raw signed conversion" "" "$raw"
# ⚠️ AND THE PROBE MUST BE ABLE TO SEE ONE. Both greps above return nothing on a file that
# does not exist, on a typo'd tag name, or on a serializer written in some other style —
# so prove the pattern matches where it SHOULD: the OID references are xs:int, they are
# built exactly this way on purpose, and they are the positive control.
chk "CONTROL: the signed xs:int elements do match that pattern" yes \
    "$(grep -q '"<algorithmOIDReference>" *+ *std::to_string' "$MSSRC" && echo yes || echo no)"

echo
echo "=== MS XCEP UNSIGNED: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
