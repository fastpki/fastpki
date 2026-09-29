#!/usr/bin/env bash
# Everything that READS config must run AFTER overlay_config(), and the pre-overlay
# SNAPSHOT must be taken exactly once.
#
# The DB `config` table is the console's half of the settings: a binary
# loads bootstrap.conf, connects, then calls overlay_config() to merge what the operator set in
# the console over the file. Any code that reads cfg BEFORE that call sees the file and
# not the effective value.
#
# The first instance found: SCEP's "no challenge configured" warning
# ran before the overlay, so a SCEP_CHALLENGE set in the console was invisible and the log
# warned at every start. Fixed in e47051f. This suite exists because the ordering is not
# something a reader can see — the call is 40 lines away from what depends on it — so the
# same mistake is free to recur in every binary, and did:
#
#   msxcep   the AUTH_BACKEND banner. A deployment that set AUTH_BACKEND=ldap in the
#            console still read "WARNING: AUTH_BACKEND=none — MS-WSTEP accepts any
#            username/password" forever. A log that lies about an AUTHENTICATION posture.
#   scep     SCEP_NEXT_CA_CERT was not merely mis-logged, it was LOADED pre-overlay — so
#            setting it from the console produced no rollover certificate at all and
#            GetNextCACert stayed off, silently.
#   cmp      the pre-overlay snapshot ran TWICE (f215fa5 duplicated an existing block).
#            The second copy ran AFTER the first overlay, so the "base" it captured was
#            the DB value — leaving eff() with nothing to fall back to and killing the
#            revert path.
#
# ⚠️ WHY THE FIXTURE PUTS THE VALUE ONLY IN THE DATABASE. Every existing suite sets these
# keys in bootstrap.conf, which is why none of them could catch this: with the value in the file
# the pre- and post-overlay reads agree, and the bug is invisible. The setting has to exist
# in the DB and NOWHERE ELSE for the assertion to mean anything.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
unset OPENSSL_CONF
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ echo "$1" | grep -q "$2" && echo yes || echo no; }

pg_setup config_overlay
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT

# A CA so the daemons have something to start against; not otherwise used here.
ca_in_token ca.pem "/CN=Overlay Test CA" 3650 ovca

base_conf() {   # $1 = extra lines
    cat > "$2" <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ovca
LOG_LEVEL=info
$1
EOF
    hsm_conf_lines >> "$2"
}
setdb(){ pg_exec "INSERT INTO config(key,value) VALUES('$1','$2') ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value;" >/dev/null; }
deldb(){ pg_exec "DELETE FROM config WHERE key='$1';" >/dev/null; }

# ── 1. MS: the AUTH_BACKEND banner ────────────────────────────────────────────
echo "=== msxcep: the auth-backend banner reports the EFFECTIVE backend ==="
# ⚠️ THIS SECTION USED `none` AS ITS FILE VALUE and asserted the absence of the
# "WARNING: AUTH_BACKEND=none" banner. Both the value and the banner are gone, so the
# old assertions could no longer fail for the right reason — the file would not even
# parse. The BEHAVIOUR being guarded is unchanged and still worth guarding: a binary that
# reads config BEFORE the DB overlay reports the file's value, one that reads after
# reports the console's. Only the example pair moved, to local (file) vs ldap (DB).
base_conf "AUTH_BACKEND=local
MS_PORT=18401" ms.conf
setdb AUTH_BACKEND ldap
"$ROOT/build/fastpki-ms" --config ms.conf >ms.log 2>&1 & P=$!
sleep 2; kill $P 2>/dev/null; wait $P 2>/dev/null
MSLOG=$(cat ms.log)
chk "it names the backend the console set"      yes "$(has "$MSLOG" 'auth backend: ldap')"
chk "  and NOT the one in the file"             no  "$(has "$MSLOG" 'auth backend: local')"
deldb AUTH_BACKEND

# The other direction, or the assertion above would also pass on a binary that simply
# stopped logging: with nothing in the DB the file's value must come through.
echo "=== msxcep: with no DB row the FILE value is what shows ==="
"$ROOT/build/fastpki-ms" --config ms.conf >ms2.log 2>&1 & P=$!
sleep 2; kill $P 2>/dev/null; wait $P 2>/dev/null
chk "the file's AUTH_BACKEND=local is what shows" yes "$(has "$(cat ms2.log)" 'auth backend: local')"

# ── 2. SCEP: the challenge warning ────────────────────────────────────────────
echo "=== scep: the challenge line honours a console-set SCEP_DYNAMIC_CHALLENGE ==="
base_conf "SCEP_PORT=18402" scep.conf
# ⚠️ THE SUBJECT HERE IS THE ORDERING, not the key. The report was that fastpki-scep read its
# config BEFORE the DB overlay, so anything an operator set in the console was invisible
# at startup. The key this used to drive with — SCEP_CHALLENGE — has been deleted, so
# it drives the same ordering with the SCEP key that remains and still changes the line.
setdb SCEP_DYNAMIC_CHALLENGE "true"
"$ROOT/build/fastpki-scep" --config scep.conf >scep.log 2>&1 & P=$!
sleep 2; kill $P 2>/dev/null; wait $P 2>/dev/null
chk "no per-user-only line when the console enabled dynamic tokens" no \
    "$(has "$(cat scep.log)" 'requires a PER-USER challengePassword')"
deldb SCEP_DYNAMIC_CHALLENGE
# And it still says so when there genuinely is nothing set — otherwise "never log it"
# would pass just as well, and the ordering would be untested in the direction that broke.
"$ROOT/build/fastpki-scep" --config scep.conf >scep2.log 2>&1 & P=$!
sleep 2; kill $P 2>/dev/null; wait $P 2>/dev/null
chk "  but it DOES say so when nothing is set anywhere" yes \
    "$(has "$(cat scep2.log)" 'requires a PER-USER challengePassword')"

# ── 3. SCEP: the rollover certificate is LOADED, not just logged ──────────────
echo "=== scep: SCEP_NEXT_CA_CERT set from the console actually loads ==="
# This is the one that was a functional gap rather than a wrong log line: the certificate
# is loaded at startup, so a pre-overlay read meant GetNextCACert could not be enabled
# from the console at all.
cp ca.pem next.pem
setdb SCEP_NEXT_CA_CERT "$W/next.pem"
"$ROOT/build/fastpki-scep" --config scep.conf >scep3.log 2>&1 & P=$!
sleep 2; kill $P 2>/dev/null; wait $P 2>/dev/null
chk "GetNextCACert is enabled from the DB setting" yes \
    "$(has "$(cat scep3.log)" 'GetNextCACert enabled')"
deldb SCEP_NEXT_CA_CERT

# ── 4. CMP: the pre-overlay snapshot is taken exactly ONCE ────────────────────
echo "=== cmp: the client-anchor base is the FILE value, not the DB one ==="
# the refresher computes (DB config, else base). If `base` were captured after the
# overlay it would equal the DB value and a deletion could never revert. The duplicated
# snapshot block did exactly that.
#
# Asserted on the SOURCE rather than at runtime: proving the revert needs the refresher's
# full interval to elapse twice, and the property that actually broke is structural —
# "snapshot exactly once, before the only overlay".
CMPSRC="$ROOT/src/cmp/main.cpp"
chk "overlay_config is called exactly once in cmp" 1 \
    "$(grep -c 'pki::overlay_config' "$CMPSRC")"
chk "  and the anchor base is snapshotted exactly once" 1 \
    "$(grep -c 'st.base_client_ca_id     =' "$CMPSRC")"
chk "  with the snapshot BEFORE the overlay" yes \
    "$([ "$(grep -n 'st.base_client_ca_id     =' "$CMPSRC" | cut -d: -f1)" -lt \
        "$(grep -n 'pki::overlay_config' "$CMPSRC" | cut -d: -f1)" ] && echo yes || echo no)"

# ── 5. the class, swept ───────────────────────────────────────────────────────
echo "=== no binary reads config before its overlay ==="
# The sweep that found instances 2-4. It is the assertion that keeps the class closed
# rather than these four instances: a new pre-overlay read fails here on the day it lands,
# in whichever binary someone adds it to.
BAD=0
for f in "$ROOT"/src/*/main.cpp; do
    OV=$(grep -n "overlay_config" "$f" | head -1 | cut -d: -f1); [ -z "$OV" ] && continue
    MAIN=$(grep -n "^int main" "$f" | head -1 | cut -d: -f1); [ -z "$MAIN" ] && continue
    # pg_conninfo and log_level are the two legitimate exceptions and always will be: the
    # first is how we REACH the database to do the overlay, and the second must take
    # effect before there is anything to log. base_client_ca_* is the deliberate
    # pre-overlay snapshot asserted in section 4.
    N=$(awk -v m="$MAIN" -v o="$OV" '
        NR>m && NR<o && /st\.cfg\.|cfg\./ &&
        !/pg_conninfo|log_level|conf_path|base_client_ca/ {c++} END{print c+0}' "$f")
    if [ "$N" -ne 0 ]; then
        echo "         $(basename "$(dirname "$f")") reads config $N time(s) before overlay_config:"
        awk -v m="$MAIN" -v o="$OV" '
            NR>m && NR<o && /st\.cfg\.|cfg\./ &&
            !/pg_conninfo|log_level|conf_path|base_client_ca/ {printf "           %d: %s\n", NR, $0}' "$f"
        BAD=$((BAD+1))
    fi
done
chk "every binary defers config reads until after the overlay" 0 "$BAD"

echo

# ── changing the public name says what it does NOT reach ─────────────────────────────────
#
# ⚠️ CORRECTING PKI_DNS REPAIRS NOTHING THAT ALREADY EXISTS. It supplies the host in every AIA
# and CRL distribution point, and those are fixed when a certificate is minted — so an
# operator who fixes a wrong name watches the console go on serving the old one with nothing
# to tell them which lever to pull. Measured on a live deployment, where redeploying turned
# out to be the only way out.
#
# Told, never done: re-issuing a CA is a staged rollover and belongs to the operator, not to a
# side effect of writing a config row.
echo "=== changing PKI_DNS names what has to be re-issued ==="
base_conf "PKI_DNS=old.example" nm.conf
OUT=$("$ROOT/build/fastpki-config" --config nm.conf set PKI_DNS new.example 2>&1)
chk "the change is applied" yes "$(echo "$OUT" | grep -q '^set PKI_DNS' && echo yes || echo no)"
chk "  and it says the existing certificates keep their addresses" yes \
    "$(echo "$OUT" | grep -q 'cannot be changed' && echo yes || echo no)"
chk "  naming the service-certificate command" yes \
    "$(echo "$OUT" | grep -q 'renew-service-certs --force' && echo yes || echo no)"
chk "  and the sub CA one" yes \
    "$(echo "$OUT" | grep -q 'fastpki-ca renew <ca-id>' && echo yes || echo no)"
# ⚠️ ONLY WHEN IT ACTUALLY CHANGES. A scheduled or scripted re-apply writes the same value
# repeatedly, and a paragraph of advice on every no-op run is how a deployment teaches its
# operators to stop reading the output.
OUT=$("$ROOT/build/fastpki-config" --config nm.conf set PKI_DNS new.example 2>&1)
chk "re-setting the SAME value says nothing further" no \
    "$(echo "$OUT" | grep -q 'cannot be changed' && echo yes || echo no)"
# CONTROL: an unrelated key is silent, so the notice is tied to the public name and not to
# `set` in general.
OUT=$("$ROOT/build/fastpki-config" --config nm.conf set LOG_LEVEL debug 2>&1)
chk "an unrelated key says nothing" no \
    "$(echo "$OUT" | grep -q 'cannot be changed' && echo yes || echo no)"
echo "=== CONFIG OVERLAY ORDERING: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
