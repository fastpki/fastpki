#!/usr/bin/env bash
# CRL generation: revoke a cert, fetch the CRL from the OCSP binary, and prove
#   - the CRL is valid and signed by the CA
#   - the revoked serial is listed
#   - openssl verify -crl_check rejects the revoked cert and accepts a good one
#   - thisUpdate/nextUpdate are present and honour CRL_NEXT_UPDATE_DAYS
#
# The nextUpdate part was missing entirely: the field is set from that setting and NO
# test read it back. It is not decoration — RFC 5280 §5.1.2.5 is what a client caches
# against, so a wrong or absent value means either revocations go unnoticed until it
# expires, or every client refetches the CRL constantly. A regression there would have
# been invisible to the whole suite.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
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
W="$(mktemp -d)"; cd "$W"; PORT=18080; CRLP=/pki/signing_ca.crl
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=CRL CA" 3650
# two leaf certs
for n in good revoked; do
  "$OSSL" req -newkey rsa:2048 -nodes -keyout $n.key -out $n.csr -subj "/CN=$n.internal" >/dev/null 2>&1
  "$OSSL" x509 -req -in $n.csr -CA ca.pem -CAkey "$CA_KEY_URI" $CA_OSSL_ARGS -CAcreateserial -days 365 -out $n.pem >/dev/null 2>&1
done
pg_setup crl
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
# NOTE: the ca_instances INSERT that used to sit here is gone. That table was dropped --
# a CA is a row of `certs` with is_ca now -- so the statement had been failing silently
# (pg_exec does not check psql's exit status, and nothing here did either). The suite
# passed regardless because seed_ca_from_conf does the real registration. Left in place
# it reads like the thing that seeds the CA, which is exactly how the next person loses
# an afternoon.
NB=$(date +%s); NA=$((NB+31536000))
ins() { # pem status
    local ser der; ser=$("$OSSL" x509 -in $1 -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
    der=$("$OSSL" x509 -in $1 -outform DER | xxd -p | tr -d '\n')
    local cn; cn=$(basename "$1" .pem)
    pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cert,cn,fingerprint,ca_instance_id) VALUES('$ser',$2,1,$NB,$NB,$NA,'CN=$cn','t','\\x$der'::bytea,'$cn.internal','','ca');"
    echo "$ser"
}
GOOD_SER=$(ins good.pem 0)
REV_SER=$(ins revoked.pem -1)
echo "good serial=$GOOD_SER  revoked serial=$REV_SER"

cat > bootstrap.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
OCSP_BIND=127.0.0.1
OCSP_PORT=$PORT
CRL_PATH=$CRLP
CRL_NEXT_UPDATE_DAYS=3
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)

# --- a revoked SUB CA belongs on its ISSUER's CRL, not its own -------------------------
# Registered through `fastpki-ca add`, never hand-written SQL: the parent is derived by
# matching this certificate's "iHash" to the parent's "sHash", and a raw INSERT leaves
# both NULL — the fixture would then build state the product cannot build, and the
# assertion below would pass or fail for the wrong reason.
#
# Revoked BEFORE the server starts, so the first /ca fetch already reflects it. The
# responder caches a generated CRL for CRL_CACHE_TTL_SEC (300s by default), so revoking
# after that fetch would be answered from cache and this would fail with the fix in place.
PARENT_KEY_URI="$CA_KEY_URI"
# ⚠️ AND THE id-NULL CA SHAPE, which is the one a naive id predicate loses. A CROSS-SIGNED
# FOREIGN CA is stored is_ca=true (insert_cert derives that from the DER) with **id NULL**,
# because it is a CA certificate that is not one of ours — see the cross-sign handler in
# src/web/main.cpp where it builds the row. It is not a leaf, so a CRL query keyed on
# `NOT is_ca` skips it; and `id IS NOT NULL` in the CA branch skipped it too, which put a
# revoked cross-certificate on NO CRL at all. Signed here with the PARENT's key, while
# $CA_KEY_URI still names it.
source "$ROOT/tests/x509_der.sh"      # x509_selectors <pem> -> sHash iHash iAndSHash sKIDHash
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout foreign.key -out foreign.csr \
    -subj "/CN=CRL Foreign CA" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > foreign.ext
"$OSSL" x509 -req -in foreign.csr -CA ca.pem -CAkey "$PARENT_KEY_URI" $CA_OSSL_ARGS \
    -CAcreateserial -days 365 -extfile foreign.ext -out foreign.pem >/dev/null 2>&1
FOREIGN_SER=$("$OSSL" x509 -in foreign.pem -noout -serial 2>/dev/null | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
FDER=$("$OSSL" x509 -in foreign.pem -outform DER | xxd -p | tr -d '\n')
read -r FSH FIH _ _ <<<"$(x509_selectors foreign.pem)"
# id NULL and ca_instance_id set to the SIGNER, exactly as the cross-sign handler writes it.
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",
                           subject,cn,cert,is_ca,ca_instance_id,\"sHash\",\"iHash\")
         VALUES('$FOREIGN_SER',-1,0,$NB,$NB,$NA,'CN=CRL Foreign CA','CRL Foreign CA',
                '\\x$FDER'::bytea,true,'ca','\\x$FSH'::bytea,'\\x$FIH'::bytea);" >/dev/null
ca_in_token subca.pem "/CN=CRL Sub CA" 3650 crlsub ca.pem "$PARENT_KEY_URI"
"$ROOT/build/fastpki-ca" --config bootstrap.conf add crlsub --name "CRL Sub CA" \
    --ca-pem "$W/subca.pem" --ca-key "$CA_KEY_URI" >/dev/null 2>&1
SUB_SER=$("$OSSL" x509 -in subca.pem -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
pg_exec "UPDATE certs SET status=-1,\"revocationReason\"=0,\"revocationDate\"=$NB WHERE id='crlsub' AND is_ca;"
"$ROOT/build/fastpki-ocsp" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT

echo "=== fetch + validate CRL ==="
# Sampled BEFORE the request that generates the CRL, so it is strictly earlier
# than the generation instant. The backdate assertion further down needs that ordering.
T0_CRL=$(date -u +'%Y-%m-%d %H:%M:%S')
curl -s "http://127.0.0.1:$PORT$CRLP/ca" -o crl.der   # per-CA CRL (base /crl 404s; no default)
"$OSSL" crl -inform DER -in crl.der -noout -CAfile ca.pem >/dev/null 2>&1 && v=ok || v=bad
chk "CRL signature valid (signed by CA)" ok "$v"

# revoked serial listed? openssl crl prints serials uppercase; compare case-insensitively
LIST=$("$OSSL" crl -inform DER -in crl.der -noout -text 2>/dev/null | grep -A1 "Serial Number" | tr 'A-F' 'a-f' | tr -d ' :' )
echo "$LIST" | grep -qi "$REV_SER" && f=yes || f=no
chk "revoked serial in CRL" yes "$f"
echo "$LIST" | grep -qi "$GOOD_SER" && fg=yes || fg=no
chk "good serial NOT in CRL" no "$fg"

# ⚠️ THE CA-REVOCATION CASE. get_revoked_certs() asked for "revoked rows whose
# ca_instance_id is X". For a leaf that is the issuer, because issuance stamps it. For a
# CA row it is NOT: ca_instance_id is an ownership/partition key and a CA row carries its
# OWN id, so a revoked sub CA landed on its own CRL and never on its parent's — revoking
# a CA succeeded and no relying party could ever observe it. No suite revoked a CA, so
# nothing caught it.
echo "$LIST" | grep -qi "$SUB_SER" && fs=yes || fs=no
chk "revoked SUB CA is listed on its ISSUER's CRL" yes "$fs"
# The id-NULL shape must land on the SAME CRL. This is the assertion that catches an
# exclusion written as `id IS NOT NULL AND id <> $1` instead of `id IS NULL OR id <> $1`.
echo "$LIST" | grep -qi "$FOREIGN_SER" && ff=yes || ff=no
chk "a revoked CROSS-SIGNED FOREIGN CA (is_ca, id NULL) is on its signer's CRL" yes "$ff"
# And it must not merely have moved: a self-signed root is excluded from its own CRL by
# the same id guard, so prove the parent's own serial is not on the parent's CRL either.
CA_SER=$("$OSSL" x509 -in ca.pem -noout -serial | sed 's/serial=//' | tr 'A-F' 'a-f' | sed 's/^0*//')
echo "$LIST" | grep -qi "$CA_SER" && fr=yes || fr=no
chk "the issuing CA is NOT on its own CRL" no "$fr"
# The other half of the fix: a revoked CA must stop SIGNING. Its CRL keeps being served —
# exactly as a disabled CA's is, asserted at the end of this suite — because certificates
# it already issued still need somewhere to resolve. What has to stop is issuance.
#
# resolve_ca_instance() used to fall through get_ca_cert_der()'s status filter to the
# signing_ca_pem fallback, which had no status predicate, so the CA resolved active and
# every protocol kept signing with it. `fastpki-ca sign-csr` is the cheapest path to that
# resolver — and it was ALSO the one call site that never checked `active` at all, so a
# disabled CA could sign from the command line while every server refused.
"$OSSL" req -newkey rsa:2048 -nodes -keyout probe.key -out probe.csr \
    -subj "/CN=probe.internal" >/dev/null 2>&1
"$ROOT/build/fastpki-ca" --config bootstrap.conf sign-csr crlsub \
    --csr probe.csr --out probe.crt >signcsr.log 2>&1 && sr=signed || sr=refused
chk "a revoked CA cannot sign" refused "$sr"
grep -qi "revoked" signcsr.log && sm=yes || sm=no
chk "  and the refusal says revoked, not disabled" yes "$sm"

echo "=== openssl verify -crl_check ==="
"$OSSL" crl -inform DER -in crl.der -out crl.pem >/dev/null 2>&1
"$OSSL" verify -CAfile ca.pem -CRLfile crl.pem -crl_check good.pem >/dev/null 2>&1 && vg=ok || vg=bad
chk "good cert passes crl_check" ok "$vg"
"$OSSL" verify -CAfile ca.pem -CRLfile crl.pem -crl_check revoked.pem >/dev/null 2>&1 && vr=ok || vr=bad
chk "revoked cert fails crl_check" bad "$vr"

# Audit producer: generating the CRL must log a crl_generated event.
AC=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='crl_generated';")
chk "CRL generation audited" yes "$([ "${AC:-0}" -ge 1 ] && echo yes || echo no)"

echo "=== validity window (RFC 5280 §5.1.2.4/5.1.2.5) ==="
LU=$("$OSSL" crl -in crl.pem -noout -lastupdate 2>/dev/null | sed 's/^lastUpdate=//')
NU=$("$OSSL" crl -in crl.pem -noout -nextupdate 2>/dev/null | sed 's/^nextUpdate=//')
chk "thisUpdate present" yes "$([ -n "$LU" ] && echo yes || echo no)"
# ⚠️ FOR CRLs. The existing verify at the top of this suite cannot see this: the
# generator and the verifier share one clock, so a same-second stamp always compares as
# "not in the future" and passes. It only breaks against a client whose clock trails the
# issuer — and OpenSSL's check_crl_time() allows NO skew at all, so one second early is
# X509_V_ERR_CRL_NOT_YET_VALID outright. (OCSP survives the same stamping only because
# OCSP_check_validity takes an explicit tolerance; CRL validation has no such knob.)
LU_ISO=$(echo "$LU" | ossl_date_iso)
chk "thisUpdate decoded"                      yes "$([ -n "$LU_ISO" ] && echo yes || echo no)"
chk "thisUpdate is backdated (before $T0_CRL)" yes \
    "$([ -n "$LU_ISO" ] && [ "$LU_ISO" \< "$T0_CRL" ] && echo yes || echo no)"
chk "nextUpdate present" yes "$([ -n "$NU" ] && echo yes || echo no)"
# CRL_NEXT_UPDATE_DAYS=3 above, so the gap must be 3 days. Compare as epoch seconds and
# allow a minute of slack for the two ASN1_TIME_set calls; anything else means the
# setting is not reaching the CRL.
if [ -n "$LU" ] && [ -n "$NU" ]; then
    to_epoch() {   # portable: try BSD date, then GNU date
        date -j -f "%b %e %T %Y %Z" "$1" +%s 2>/dev/null || date -d "$1" +%s 2>/dev/null
    }
    L=$(to_epoch "$LU"); N=$(to_epoch "$NU")
    if [ -n "$L" ] && [ -n "$N" ]; then
        D=$(( (N - L + 30) / 86400 ))
        chk "nextUpdate honours CRL_NEXT_UPDATE_DAYS=3" 3 "$D"
    else
        chk "the CRL dates parse" yes "no ($LU / $NU)"
    fi
fi
# And it must be in the FUTURE — a CRL whose nextUpdate has passed is treated as stale
# by every validator, which is the failure mode an off-by-one in the units would cause.
chk "nextUpdate is in the future" ok \
    "$("$OSSL" crl -in crl.pem -noout -nextupdate >/dev/null 2>&1 && \
       [ "$(to_epoch "$NU")" -gt "$(date +%s)" ] && echo ok || echo stale)"

echo "=== ⚠️ a DISABLED CA still publishes its CRL ==="
# Reported:   curl -k http://localhost:8080/root-ca.crl  ->  CA instance disabled
#
# An offline root is the RECOMMENDED posture and "disabled" is how an operator says so,
# so this refusal fires exactly when the CA is most locked down. The consequence is not
# a missing file: without the CRL every certificate that root ever signed becomes
# unverifiable, and a REVOKED one reads to a relying party as "cannot determine" — the
# revocation quietly stops counting. Disabling must stop ISSUANCE, not withdraw the
# revocation information already published.
#
# The whole responder is left running and only the DB flag flips, so a failure here can
# only be the gate.
#
# The OCSP half is guarded in ocsp_responder.sh, not here: this suite configures
# no responder credential, so an OCSP query fails for that reason whether the CA is
# enabled or not. I only found that out by asserting the ENABLED baseline first — without
# it the failure reads as "the disable gate is still there" and sends you to re-fix code
# that is already correct.
pg_exec "UPDATE certs SET ca_enabled=false WHERE id='ca';"
DIS=$(curl -s -o crl_dis.der -w '%{http_code}' "http://127.0.0.1:$PORT$CRLP/ca")
chk "the CRL is still SERVED for a disabled CA" 200 "$DIS"
# Served is not enough — it has to be the real, signed, current CRL, not an empty body
# with a 200 on it. Decode it and find the revoked serial again.
"$OSSL" crl -inform DER -in crl_dis.der -noout -CAfile ca.pem >/dev/null 2>&1 && dv=ok || dv=bad
chk "  and it still verifies against the CA" ok "$dv"
DLIST=$("$OSSL" crl -inform DER -in crl_dis.der -noout -text 2>/dev/null \
        | grep -A1 "Serial Number" | tr 'A-F' 'a-f' | tr -d ' :')
chk "  and still lists the revoked serial" yes \
    "$(echo "$DLIST" | grep -qi "$REV_SER" && echo yes || echo no)"
# ⚠️ And the other half of the ruling: disabling MUST still stop issuance. If this ever
# goes green-by-accident the fix has been turned into "disable does nothing".
chk "  but the CA is genuinely marked disabled" f \
    "$(pg_exec "SELECT ca_enabled FROM certs WHERE id='ca';" | tr -d ' ')"
pg_exec "UPDATE certs SET ca_enabled=true WHERE id='ca';"


echo "=== ⚠️ an EXPIRED CA refuses to sign ==="
# This assertion exists because its absence hid a dead control. `expired` was computed in
# kCaSelect and never read back in read_ca(), so CaInstance::expired stayed false, an expired
# CA went on signing through the signing_ca_pem fallback, and the whole suite stayed green
# over it. A gate nothing asserts is a gate that can be deleted by accident.
pg_exec "UPDATE certs SET \"notAfter\"=$((NB-86400)) WHERE id='ca' AND is_ca;"
"$OSSL" req -newkey rsa:2048 -nodes -keyout expprobe.key -out expprobe.csr \
    -subj "/CN=expired-probe.internal" >/dev/null 2>&1
"$ROOT/build/fastpki-ca" --config bootstrap.conf sign-csr ca \
    --csr expprobe.csr --out expprobe.crt >expsign.log 2>&1 && er=signed || er=refused
chk "an expired CA cannot sign" refused "$er"
chk "  and the refusal names expiry, not 'disabled'" yes \
    "$(grep -qi "expired" expsign.log && echo yes || echo no)"
# Put it back: later sections and the teardown expect a live CA.
pg_exec "UPDATE certs SET \"notAfter\"=$NA WHERE id='ca' AND is_ca;"
chk "  PRECONDITION restored: the CA is live again" yes \
    "$("$ROOT/build/fastpki-ca" --config bootstrap.conf sign-csr ca --csr expprobe.csr \
        --out expprobe2.crt >/dev/null 2>&1 && echo yes || echo no)"
echo "=== ⚠️ a CRL this node SIGNS is published, so a peer can serve it once this node is gone ==="
# A CRL must be signed by the CA, and a CA key lives on exactly one node. When that node
# dies, the certificates it issued stay deployed and become uncheckable: no peer can sign a
# CRL, and no peer can answer OCSP either, because a delegated responder key would have to
# be issued by the same absent CA. Per-node sub-CAs under a shared root therefore buy fault
# ISOLATION, not availability — the blast radius is one CA, but that CA's revocation goes
# dark, which is the half that actually endangers relying parties.
#
# The `crls` table already replicates through the mesh, and all three serving paths already
# prefer a stored CRL before refusing. The only thing missing was anything WRITING to it
# besides an operator running `fastpki-ca import-crl` for an offline root.
#
# Restarted with the cache off because the assertions below turn on what a REGENERATION
# does: at the default 300s TTL the second fetch returns the first CRL from memory and
# would prove nothing either way.
kill $P 2>/dev/null; wait $P 2>/dev/null
sed 's/^LOG_LEVEL=.*/LOG_LEVEL=err/' bootstrap.conf > pub.conf
echo "CRL_CACHE_TTL_SEC=0" >> pub.conf
"$ROOT/build/fastpki-ocsp" --config pub.conf >pub.log 2>&1 & P=$!
wait_port "$PORT" "$P" || true

curl -s -o pub1.crl "http://127.0.0.1:$PORT/ca.crl"
chk "serving a CRL stores it"                1     "$(pg_exec "SELECT count(*) FROM crls WHERE ca_id='ca' AND NOT is_delta;" | tr -d ' ')"
# ⚠️ Provenance must be honest. `imported_by` meant one thing — an operator imported this
# for a CA we cannot sign for — and a self-generated row disguised as an import sends
# whoever reads it looking for a ceremony that never happened. It names the node instead,
# which is also the actionable part when the row goes stale: WHICH node stopped refreshing.
chk "  and says it was generated here, not imported" yes     "$(pg_exec "SELECT imported_by FROM crls WHERE ca_id='ca';" | tr -d ' ' \
       | grep -q '^generated' && echo yes || echo no)"
pg_exec "SELECT encode(crl,'hex') FROM crls WHERE ca_id='ca' AND NOT is_delta;" \
    | tr -d ' \n' | xxd -r -p > stored.crl 2>/dev/null
chk "  the stored bytes are a real CRL"      yes     "$("$OSSL" crl -in stored.crl -inform DER -noout >/dev/null 2>&1 && echo yes || echo no)"
chk "  listing the revoked serial"           yes     "$("$OSSL" crl -in stored.crl -inform DER -noout -text 2>/dev/null \
       | grep -qi "$REV_SER" && echo yes || echo no)"

# ⚠️ AND IT MUST NOT REWRITE ON EVERY REGENERATION. generate_crl() stamps crlNumber with
# the current time, so two CRLs listing identical revocations differ in bytes every time —
# a naive byte comparison would write, and MESH-REPLICATE, a new CRL every cache TTL for a
# CA where nothing has been revoked in months. crl_number is the signal here because
# `updated` is stamped by a mesh-installed trigger this single-node database has not got.
N1=$(pg_exec "SELECT crl_number FROM crls WHERE ca_id='ca' AND NOT is_delta;" | tr -d ' ')
sleep 2
curl -s -o pub2.crl "http://127.0.0.1:$PORT/ca.crl"
N2=$(pg_exec "SELECT crl_number FROM crls WHERE ca_id='ca' AND NOT is_delta;" | tr -d ' ')
chk "an unchanged CRL is not rewritten"      "$N1" "$N2"
chk "  and the two responses differ, so the cache was genuinely off" no     "$(cmp -s pub1.crl pub2.crl && echo yes || echo no)"

# A NEW revocation is content, and content must reach the peers.
#
# ⚠️ Revoke the cert this suite ALREADY issued rather than signing a fresh one. The CA key
# is in the token and the OCSP daemon has the token open, so an `openssl x509 -req -CAkey
# pkcs11:...` here silently produces no file — and the serial then comes back EMPTY, which
# turns the "lists BOTH" assertion into `grep -qi ""` and passes on a build that stored
# nothing. That is exactly what the first version of this section did.
pg_exec "UPDATE certs SET status=-1,\"revocationReason\"=1,\"revocationDate\"=$NB WHERE serial='$GOOD_SER';"
chk "  PRECONDITION: the CA now has two revocations" 2 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE ca_instance_id='ca' AND status=-1 AND NOT is_ca;" | tr -d ' ')"
sleep 2
curl -s -o pub3.crl "http://127.0.0.1:$PORT/ca.crl"
N3=$(pg_exec "SELECT crl_number FROM crls WHERE ca_id='ca' AND NOT is_delta;" | tr -d ' ')
chk "a new revocation DOES rewrite the stored CRL" no \
    "$([ "$N2" = "$N3" ] && echo yes || echo no)"
pg_exec "SELECT encode(crl,'hex') FROM crls WHERE ca_id='ca' AND NOT is_delta;" \
    | tr -d ' \n' | xxd -r -p > stored2.crl 2>/dev/null
"$OSSL" crl -in stored2.crl -inform DER -noout -text > stored2.txt 2>/dev/null
chk "  and the stored copy lists the newly revoked serial" yes \
    "$(grep -qi "$GOOD_SER" stored2.txt && echo yes || echo no)"
chk "  without dropping the first one"       yes \
    "$(grep -qi "$REV_SER" stored2.txt && echo yes || echo no)"

# ⚠️ A DELTA IS NEVER STORED. Its base point is chosen by the CLIENT (?base=N), and the
# table holds one row per (ca_id, is_delta) — so a stored delta would be one caller's
# window served to everyone else as though it were theirs.
curl -s -o delta.crl "http://127.0.0.1:$PORT/ca.crl?base=$N1"
chk "a delta CRL is served but never stored" 0     "$(pg_exec "SELECT count(*) FROM crls WHERE ca_id='ca' AND is_delta;" | tr -d ' ')"

# ⚠️ AND IT MUST NOT DEPEND ON SOMEBODY HAVING FETCHED IT FIRST. Publishing only when a
# CRL happens to be generated covers only CAs that were queried on THIS node while it was
# still up — and the situation the stored copy exists for is a node that has stopped
# answering. A CA nobody happened to ask about would replicate nothing and go dark exactly
# as before, the quiet CAs being the ones most likely to be missed. So the daemon sweeps.
pg_exec "DELETE FROM crls;"
chk "  PRECONDITION: nothing is stored now"  0 \
    "$(pg_exec "SELECT count(*) FROM crls;" | tr -d ' ')"
kill $P 2>/dev/null; wait $P 2>/dev/null
sed 's/^LOG_LEVEL=.*/LOG_LEVEL=info/' pub.conf > sweep.conf
echo "CRL_PUBLISH_SWEEP_SEC=2" >> sweep.conf
"$ROOT/build/fastpki-ocsp" --config sweep.conf >sweep.log 2>&1 & P=$!
wait_port "$PORT" "$P" || true
# No fetch of any kind here — that is the whole assertion. The sweep sleeps before its
# first pass, so allow a couple of intervals.
sleep 7
chk "the sweep publishes with NO request having been made" 1 \
    "$(pg_exec "SELECT count(*) FROM crls WHERE ca_id='ca' AND NOT is_delta;" | tr -d ' ')"
chk "  and it announces itself in the log"   yes \
    "$(grep -q "CRL publication sweep every 2s" sweep.log && echo yes || echo no)"

# ⚠️ A SUB CA CERTIFIED BY sign-csr MUST CARRY ITS PARENT'S CRL DP.
#
# Without it `openssl verify -crl_check_all` fails at DEPTH 1 for everything that sub CA
# goes on to issue: the leaves carry perfectly good CRL DPs, and the intermediate above
# them carries nothing to check itself against. sign-csr is the documented
# multi-data-center bootstrap (docs/deployment.md 9.1) — it is how EVERY mesh node's sub CA is
# certified — and it set no URLs at all, so the whole mesh validated only as far as depth 0.
# Measured on the three-DC lab: eight demo steps failed with "unable to get certificate
# CRL", including all four listener TLS probes.
echo "=== a sub CA signed by sign-csr carries the parent's CRL DP and AIA ==="
# Its own config: derive_ca_urls needs a host (BASE_URL or PKI_DNS) to build URLs from, and
# adding one to the suite's shared bootstrap.conf would put CRL DPs on every certificate
# the cells above already assert about.
sed 's/^LOG_LEVEL=.*/LOG_LEVEL=err/' bootstrap.conf > urls.conf
printf 'PKI_DNS=crl-urls.example.test\n' >> urls.conf
"$OSSL" req -newkey rsa:2048 -nodes -keyout urlsub.key -out urlsub.csr \
    -subj "/CN=URL Sub CA" >/dev/null 2>&1
"$ROOT/build/fastpki-ca" --config urls.conf sign-csr ca \
    --csr urlsub.csr --out urlsub.crt >urlsign.log 2>&1 || true
chk "sign-csr produced a certificate" yes "$([ -s urlsub.crt ] && echo yes || echo no)"
URLTXT=$("$OSSL" x509 -in urlsub.crt -noout -text 2>/dev/null)
chk "  it carries a CRL Distribution Point" yes \
    "$(printf '%s' "$URLTXT" | grep -q 'CRL Distribution Points' && echo yes || echo no)"
chk "  naming the PARENT's CRL, not its own" yes \
    "$(printf '%s' "$URLTXT" | grep -q 'ca\.crl' && echo yes || echo no)"
chk "  and a caIssuers AIA" yes \
    "$(printf '%s' "$URLTXT" | grep -q 'CA Issuers' && echo yes || echo no)"
# The parent has no delegated responder here, so advertising an OCSP URI would name an
# endpoint that cannot answer for this certificate (RFC 6960 §4.2.2.2).
chk "  but NO OCSP URI, because the parent has no responder certificate" no \
    "$(printf '%s' "$URLTXT" | grep -q 'OCSP - URI' && echo yes || echo no)"
chk "  and it says so rather than silently omitting it" yes \
    "$(grep -q 'omitting the AIA OCSP URI' urlsign.log && echo yes || echo no)"

echo
echo "=== CRL: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
