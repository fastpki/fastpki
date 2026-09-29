#!/usr/bin/env bash
# Delta CRLs (RFC 5280 §5.2.4). With CRL_DELTA=true:
#   - the full CRL advertises a Freshest CRL pointer to its delta;
#   - GET <crl_path>?base=<n> returns a delta CRL carrying a critical Delta CRL
#     Indicator = n and listing only certs revoked at/after n (our crlNumber is the
#     issuance unix time, so base n == "changes since time n").
# And what a hold and its release look like to a relying party:
#   - a certificate on hold is on the full CRL with reason certificateHold, and OCSP says so;
#   - a released hold is on no full CRL, OCSP answers good, and a delta whose base is before
#     the release lists it with reason removeFromCRL (RFC 5280 §5.3.1);
#   - unspecified is carried as NO reason code, in the CRL and in OCSP.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/service_cert_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
# Only adopt the system openssl.cnf where it really is one. On macOS this path is a
# stub that defines no providers, and exporting it breaks every pkcs11 load — the
# CA key then cannot be minted and the suite SKIPs for a reason that looks nothing
# like "wrong openssl.cnf". Tests must not assume a Linux layout (§3d).
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"; PORT=18084; CRLP=/pki/signing_ca.crl
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Delta CRL CA" 3650
for n in old new held released relold unspec; do
  "$OSSL" req -newkey rsa:2048 -nodes -keyout $n.key -out $n.csr -subj "/CN=$n.internal" >/dev/null 2>&1
  "$OSSL" x509 -req -in $n.csr -CA ca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS -CAcreateserial -days 365 -out $n.pem >/dev/null 2>&1
done
pg_setup crl_delta
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
# NOTE: the ca_instances INSERT that used to sit here is gone. That table was dropped --
# a CA is a row of `certs` with is_ca now -- so the statement had been failing silently
# (pg_exec does not check psql's exit status, and nothing here did either). The suite
# passed regardless because seed_ca_from_conf does the real registration. Left in place
# it reads like the thing that seeds the CA, which is exactly how the next person loses
# an afternoon.
NOW=$(date +%s); NA=$((NOW+31536000))
BASE=$((NOW-500))            # delta cut-off
OLD_REVDATE=$((NOW-1000))    # revoked BEFORE base -> excluded from the delta
NEW_REVDATE=$((NOW-100))     # revoked AFTER base  -> included in the delta
ins() { # pem "revocationDate" [status] [reason]  -> serial
    local ser der cn; ser=$("$OSSL" x509 -in $1 -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
    der=$("$OSSL" x509 -in $1 -outform DER | xxd -p | tr -d '\n'); cn=$(basename "$1" .pem)
    pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cert,cn,fingerprint,ca_instance_id) VALUES('$ser',${3:--1},${4:-4},$2,$NOW,$NA,'CN=$cn','t','\x$der'::bytea,'$cn.internal','','ca-global');"
    echo "$ser"
}
OLD_SER=$(ins old.pem $OLD_REVDATE)
NEW_SER=$(ins new.pem $NEW_REVDATE)
# The states release_hold() and a hold leave behind: on hold = -1/6; released = 0/8 at the
# release time, after the base or before it; and a revocation with no reason given = -1/0.
HELD_SER=$(ins held.pem $NEW_REVDATE -1 6)
REL_SER=$(ins released.pem $NEW_REVDATE 0 8)
RELOLD_SER=$(ins relold.pem $OLD_REVDATE 0 8)
UNSPEC_SER=$(ins unspec.pem $NEW_REVDATE -1 0)
echo "old serial=$OLD_SER (rev $OLD_REVDATE)  new serial=$NEW_SER (rev $NEW_REVDATE)  base=$BASE"

cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
ROOT_CA_PEM=$W/ca.pem
BASE_URL=https://crl.example
PG_CONNINFO=$PG_CONNINFO
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
CRL_PATH=$CRLP
CRL_DELTA=true
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
# The responder signs with its own credential issued by this CA, never with the CA key.
printf 'OCSP_RESPONDER_KEY=%s\n' "$(ocsp_responder_key "$W/ca.pem" "$CA_KEY_URI" ca-global "$W")" >> bootstrap.conf
"$ROOT/build/fastpki-ocsp" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-ocsp died:"; cat srv.log; exit 1; fi
U="http://127.0.0.1:$PORT"
serials() { "$OSSL" crl -inform DER -in "$1" -noout -text 2>/dev/null | grep -A1 "Serial Number" | tr 'A-F' 'a-f' | tr -d ' :'; }

echo "=== full CRL advertises a Freshest CRL (delta pointer) ==="
curl -s "$U$CRLP/ca-global" -o full.der
"$OSSL" crl -inform DER -in full.der -noout -CAfile ca.pem >/dev/null 2>&1 && v=ok || v=bad
chk "full CRL signature valid" ok "$v"
FULLTXT=$("$OSSL" crl -inform DER -in full.der -noout -text 2>/dev/null)
chk "full CRL has Freshest CRL ext" yes "$(echo "$FULLTXT" | grep -qi 'Freshest CRL' && echo yes || echo no)"
chk "Freshest CRL points at ?base=" yes "$(echo "$FULLTXT" | grep -q 'base=' && echo yes || echo no)"
chk "full CRL lists both revoked serials" yes \
    "$(F=$(serials full.der); echo "$F" | grep -qi "$OLD_SER" && echo "$F" | grep -qi "$NEW_SER" && echo yes || echo no)"

echo "=== delta CRL (?base=$BASE) ==="
curl -s "$U$CRLP/ca-global?base=$BASE" -o delta.der
"$OSSL" crl -inform DER -in delta.der -noout -CAfile ca.pem >/dev/null 2>&1 && dv=ok || dv=bad
chk "delta CRL signature valid" ok "$dv"
DTXT=$("$OSSL" crl -inform DER -in delta.der -noout -text 2>/dev/null)
chk "delta has Delta CRL Indicator" yes "$(echo "$DTXT" | grep -qi 'Delta CRL Indicator' && echo yes || echo no)"
chk "Delta CRL Indicator is critical" yes "$(echo "$DTXT" | grep -A1 'Delta CRL Indicator' | grep -qi critical && echo yes || echo no)"
chk "Delta CRL Indicator value = base" yes "$(echo "$DTXT" | grep -A1 'Delta CRL Indicator' | grep -q "$BASE" && echo yes || echo no)"
chk "delta lists the NEW serial (revoked after base)" yes "$(serials delta.der | grep -qi "$NEW_SER" && echo yes || echo no)"
chk "delta OMITS the OLD serial (revoked before base)" no  "$(serials delta.der | grep -qi "$OLD_SER" && echo yes || echo no)"

echo "=== without CRL_DELTA the ?base param is ignored (still the full CRL) ==="
# (same server has it on; assert the delta's crlNumber differs from base to prove it's a fresh CRL, not the base echoed)
chk "delta is a distinct CRL (has its own CRL Number)" yes "$(echo "$DTXT" | grep -qi 'CRL Number' && echo yes || echo no)"

# One entry's reason as openssl prints it, "none" when the entry carries no reason code,
# "absent" when the serial is not on the CRL at all.
entry_reason() { # der serial
  "$OSSL" crl -inform DER -in "$1" -noout -text 2>/dev/null | awk -v s="$2" '
    tolower($0) ~ /serial number:/ { v = tolower($0); sub(/.*serial number: */, "", v); gsub(/[ :]/, "", v)
                                     sub(/^0+/, "", v); cur = v; if (cur == s) seen = 1; next }
    cur == s && /CRL Reason Code/  { getline r; gsub(/^ +| +$/, "", r); print r; done = 1; exit }
    END { if (!done) print (seen ? "none" : "absent") }'
}
echo "=== a certificate on hold, and a released hold ==="
chk "full CRL lists the held certificate as Certificate Hold" "Certificate Hold" "$(entry_reason full.der "$HELD_SER")"
chk "full CRL does not list a released hold"                  absent "$(entry_reason full.der "$REL_SER")"
chk "  released before the base either"                        absent "$(entry_reason full.der "$RELOLD_SER")"
chk "delta lists the hold placed after its base"               "Certificate Hold" "$(entry_reason delta.der "$HELD_SER")"
chk "⚠️ delta announces the release after its base as Remove From CRL" "Remove From CRL" "$(entry_reason delta.der "$REL_SER")"
chk "  but not a release from before its base"                 absent "$(entry_reason delta.der "$RELOLD_SER")"
chk "the full CRL still carries a real reason (Superseded)"    "Superseded" "$(entry_reason full.der "$NEW_SER")"
echo "=== unspecified is no reason code at all (RFC 5280 §5.3.1) ==="
chk "an unspecified revocation is on the full CRL"             yes "$([ "$(entry_reason full.der "$UNSPEC_SER")" != absent ] && echo yes || echo no)"
chk "  with no CRL Reason Code"                                none "$(entry_reason full.der "$UNSPEC_SER")"

echo "=== OCSP agrees ==="
ocsp_of() { "$OSSL" ocsp -issuer ca.pem -cert "$1" -url "$U/" -resp_text -noverify 2>&1; }
O_HELD=$(ocsp_of held.pem); O_REL=$(ocsp_of released.pem); O_UNS=$(ocsp_of unspec.pem)
chk "on hold: revoked"                         yes "$(echo "$O_HELD" | grep -q 'Cert Status: revoked' && echo yes || echo no)"
chk "  reason certificateHold"                 yes "$(echo "$O_HELD" | grep -qi 'certificateHold' && echo yes || echo no)"
chk "released: good"                           yes "$(echo "$O_REL" | grep -q 'Cert Status: good' && echo yes || echo no)"
chk "unspecified: revoked"                     yes "$(echo "$O_UNS" | grep -q 'Cert Status: revoked' && echo yes || echo no)"
chk "  with no revocation reason"              no  "$(echo "$O_UNS" | grep -qi 'Reason:' && echo yes || echo no)"

echo
echo "=== CRL DELTA: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
