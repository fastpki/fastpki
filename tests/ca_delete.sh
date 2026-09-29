#!/usr/bin/env bash
# A CA instance can be REMOVED — but only when removing it is safe.
#
# ── Why this exists ──────────────────────────────────────────────────────────────
#
# There used to be no way to remove a CA through any supported interface: no
# DELETE route, no `fastpki-ca delete`. A CA created with a typo was permanent, and
# undoing one by hand meant `psql` for the row plus `pkcs11-tool` for the keypair —
# which is precisely how the orphaned-keypair condition gets recreated.
#
# ── The two refusals are the point ───────────────────────────────────────────────
#
# 1. A CA that has ISSUED anything cannot be deleted. Every certificate it signed still
#    needs its issuer to build a chain and to have its status answered, so deleting the
#    issuer orphans all of them. `disable` is the operation for "no longer current": it
#    stops new issuance and keeps CRL/OCSP/chain serving.
#
# 2. The token keypair goes WITH the row. Deleting the row alone leaves a key in the HSM
#    referenced by nothing — indistinguishable from a live key. The key is destroyed
#    first, so a failure there leaves the row (recoverable) rather than the key (not).
#
# Assertions decode real state: the DB row, the token object listing, and the HTTP codes.
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
[ -n "${OPENSSL_LIBDIR:-}" ] && export DYLD_LIBRARY_PATH="$OPENSSL_LIBDIR"
W="$(mktemp -d)"; cd "$W"; PORT=18496
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
skipout(){ echo "  [SKIP] $1"; echo; echo "=== CA DELETE: PASS=$pass FAIL=$fail SKIP=1 ==="; exit 0; }

pg_setup ca_delete
P=
trap 'kill $P 2>/dev/null; pg_cleanup' EXIT

ca_in_token ca.pem "/CN=Delete Bootstrap CA" 3650 || skipout "no token"
seed_web_user boss bosspw admin

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=boot
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
hsm_conf_lines >> bootstrap.conf
seed_ca_from_conf bootstrap.conf

CA="$ROOT/build/fastpki-ca"
"$ROOT/build/fastpki-web" --config bootstrap.conf >web.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat web.log; exit 1; }
U="http://127.0.0.1:$PORT"
curl -s -c boss.cj -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null

TOK=$(sed -n 's/.*token=\([^;?]*\).*/\1/p' <<<"$CA_KEY_URI")
mk_ca() {   # mk_ca <id> <ckaid> -> creates a CA whose key is minted in the token
    local id="$1" ckaid="$2"
    # The URI needs BOTH a distinct CKA_ID and the PIN: without pin-value the provider
    # cannot open a logged-in session and reports "token was not present in its slot",
    # which reads like missing hardware rather than a missing credential.
    curl -s -o "mk_$id.json" -w '%{http_code}' -b boss.cj "$U/api/ca-instances" \
      --data-urlencode "id=$id" --data-urlencode "name=$id" \
      --data-urlencode "subject=/CN=$id" \
      --data-urlencode 'keyloc=pkcs11' \
      --data-urlencode "keyref=pkcs11:token=$TOK;object=$id;id=$ckaid;type=private?pin-value=1234" \
      --data-urlencode 'keygen=true' --data-urlencode 'key=rsa' \
      --data-urlencode 'bits=2048' --data-urlencode 'md=sha256' --data-urlencode 'days=3650'
}
# ⚠️ NAME THE TOKEN AND LOG IN. Without --token-label, pkcs11-tool reads the FIRST slot
# with a token present — and on the shared p11-kit server that is whichever suite happened
# to mint one first, not ours. That is not theoretical: this suite scored 20/0 for as long
# as it was the first token-minting suite in CORE, and dropped to 18/2 the moment f1b7d1a
# inserted est_mtls_role.sh ahead of it. Nothing about the product changed.
#
# Without --login the private half is invisible too (CKA_PRIVATE), so the count could only
# ever see the public object — a second way to read zero and call it a missing key.
#
# The label match is anchored: the two CA ids here are `used` and `unused`, and an
# unanchored "label:.*used" matches BOTH.
tok_objects(){ "$HSM_PKTOOL" --module "$HSM_CLIENT" --token-label "$TOK" --login --pin 1234 \
                   -O 2>/dev/null | grep -cE "label:[[:space:]]+$1\$" || true; }

echo "=== an UNUSED CA deletes, and its token key goes with it ==="
C=$(mk_ca unused %21)
# A skip that hides the server's reason is how a broken environment and a broken change
# look identical — print what it actually said.
[ "$C" = 201 ] || skipout "could not create a token-backed CA here (create -> $C: $(head -c 300 mk_unused.json 2>/dev/null))"
chk "create the CA -> 201" 201 "$C"
chk "  its key exists in the token" yes "$([ "$(tok_objects unused)" -ge 1 ] && echo yes || echo no)"

C=$(curl -s -o del.json -w '%{http_code}' -b boss.cj -X DELETE "$U/api/ca-instances/unused")
chk "DELETE an unused CA -> 200" 200 "$C"
chk "  the row is gone" 0 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='unused' AND is_ca;" | tr -d ' ')"
# ⚠️ THE assertion that separates this from a row delete: the keypair must not survive,
# or we have simply moved that orphan into the delete path.
chk "  and the token keypair is destroyed" 0 "$(tok_objects unused)"
chk "  the response reports what it destroyed" yes \
    "$(grep -q 'tokenObjectsDestroyed' del.json && echo yes || echo no)"

echo "=== a CA that has ISSUED something is REFUSED, and told what to do instead ==="
C=$(mk_ca used %22)
chk "create the second CA -> 201" 201 "$C"
# One issued leaf is enough to make deletion unsafe.
"$OSSL" req -new -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj "/CN=leaf.test" >/dev/null 2>&1
C=$(curl -s -o iss.json -w '%{http_code}' -b boss.cj -X POST --data-binary @leaf.csr \
      "$U/api/certs/request?ca_instance=used")
chk "issue one leaf from it" yes "$([ "$C" = 200 ] || [ "$C" = 201 ] && echo yes || echo no)"
# Without a leaf the whole refusal half is vacuous — it would "pass" by deleting a CA
# that had issued nothing, which is the OTHER branch. Assert the precondition really held.
chk "  the DB agrees it issued exactly one" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE ca_instance_id='used' AND NOT is_ca;" | tr -d ' ')"

C=$(curl -s -o refuse.json -w '%{http_code}' -b boss.cj -X DELETE "$U/api/ca-instances/used")
chk "DELETE a CA that has issued -> 409" 409 "$C"
chk "  the row SURVIVES the refusal" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='used' AND is_ca;" | tr -d ' ')"
# A refusal that destroyed the key first would be far worse than no refusal at all.
chk "  and its token key is untouched" yes "$([ "$(tok_objects used)" -ge 1 ] && echo yes || echo no)"
chk "  the message names the count" yes \
    "$(grep -q '"issued":1' refuse.json && echo yes || echo no)"
chk "  and points at Disable instead" yes \
    "$(grep -qi 'disable' refuse.json && echo yes || echo no)"

echo "=== disable remains the operation for a CA that HAS issued ==="
C=$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj -X POST "$U/api/ca-instances/used/status?status=disabled")
chk "disable it -> 200" 200 "$C"
chk "  fastpki-ca show agrees" disabled "$("$CA" --config bootstrap.conf show used 2>/dev/null | cut -f2)"

echo "=== the CLI refuses on the same rule, so the two cannot disagree ==="
"$CA" --config bootstrap.conf delete used >cli.out 2>&1; rc=$?
chk "fastpki-ca delete <used> -> non-zero" yes "$([ "$rc" -ne 0 ] && echo yes || echo no)"
chk "  and says why, naming disable" yes \
    "$(grep -qi 'disable' cli.out && echo yes || echo no)"
chk "  the row still survives" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='used' AND is_ca;" | tr -d ' ')"

echo "=== a missing CA is a 404, not a silent success ==="
chk "DELETE an unknown id -> 404" 404 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj -X DELETE "$U/api/ca-instances/nosuchca")"

echo "=== A REGISTERED id cannot be taken over by a second registration ==="
# ⚠️ REGISTERING A NEW CA UNDER AN EXISTING ACTIVE CA id IS DENIED. Re-keying is not the
# same as creating a new CA with the same id: nothing guarantees the other attributes match,
# so it is not re-keying.
#
# ⚠️ THIS IS NOT HYPOTHETICAL. get_ca_instance() returns the NEWEST certificate for an id,
# so a second registration silently captures every lookup for that id — issuance, OCSP
# signer choice, everything. On the lab a smoke test registered a throwaway root under the
# production id `issuing` and from then on `issuing` resolved to "Smoke Test Root CA".
# Nothing reported it; it was found by reading rows, not by any failure.
#
# The console already refused; `fastpki-ca create` already refused; `fastpki-ca add` did
# NOT, and add is the path the smoke test used. That asymmetry IS the bug.
C=$(mk_ca dupe %31)
[ "$C" = 201 ] || skipout "could not create the first CA for the id-reuse check (-> $C)"
chk "PRECONDITION: the first CA registers" 201 "$C"
# ⚠️ Ask the API, not `certs.status` — that column is the CERTIFICATE's status (0 =
# valid); the CA's active/disabled state is a different thing and reads as "0" here,
# which is what my first version compared against "active" and failed on.
chk "  and it is active" yes \
    "$(curl -s -b boss.cj "$U/api/ca-instances" | tr '{' '\n' | grep '\"id\":\"dupe\"' \
       | grep -q '\"status\":\"active\"' && echo yes || echo no)"
# A DIFFERENT CKA_ID, so this is a genuinely different CA asking for the same NAME.
# Non-discriminating on its own: the console ALREADY refused any duplicate id.
chk "a SECOND CA under the same active id -> 409 (control: 409 either way)" 409 "$(mk_ca dupe %32)"
# ⚠️ Decode what the DB HOLDS: a refusal that still wrote a row is the failure shape here.
chk "  and no second CA row was written" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='dupe' AND is_ca;" | tr -d ' ')"
# The CLI half — the path that actually let it happen.
ADDOUT=$("$CA" --config bootstrap.conf add dupe --ca-key "$CA_KEY_URI" --ca-pem ca.pem 2>&1); ADDRC=$?
# ⚠️ THE EXIT CODE ALONE DOES NOT DISCRIMINATE — measured: it is non-zero on the OLD
# binary too, for an unrelated reason. A refusal firing for the wrong reason reads exactly
# like a pass, so the MESSAGE below is the real assertion and this one is only a guard
# against `add` silently succeeding.
chk "fastpki-ca add refuses the registered id (control: non-zero either way)" yes \
    "$([ "$ADDRC" -ne 0 ] && echo yes || echo no)"
chk "  and says which CA holds it" yes \
    "$(printf '%s' "$ADDOUT" | grep -qi 'already registered under id' && echo yes || echo no)"

echo "=== ⚠️ DISABLING a CA does NOT release its id ==="
# THE DISCRIMINATING ASSERTIONS OF THIS CHANGE, and the ones that go red on a revert.
#
# My first cut read "existing ACTIVE CA id" as licence to let a DISABLED CA's name be taken,
# on the reasoning that deletion releases it. That was wrong: a root CA is normally DISABLED
# precisely because it is offline, and letting its id be overridden would be catastrophic.
# and he is right — an offline root is disabled precisely BECAUSE it is precious, so
# `disabled` selects for the CAs least safe to shadow, not the most. Disabling is not
# deletion; only deleting the CA frees its id, and `unused` above already proves delete
# works. Under the old rule every assertion below returned 201 and wrote a second row —
# i.e. the catastrophic case he named, reached through the ordinary console.
C=$(curl -s -o /dev/null -w '%{http_code}' -b boss.cj -X POST "$U/api/ca-instances/dupe/status?status=disabled")
chk "PRECONDITION: disable it -> 200" 200 "$C"
chk "PRECONDITION: it really reads back disabled" disabled \
    "$("$CA" --config bootstrap.conf show dupe 2>/dev/null | cut -f2)"
chk "a second CA under the DISABLED id -> 409" 409 "$(mk_ca dupe %33)"
# ⚠️ Ask the DB, not the status code: a 409 that still inserted is the shape that would
# leave the shadowing row in place while reporting a refusal.
chk "  and STILL no second CA row was written" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='dupe' AND is_ca;" | tr -d ' ')"
DISOUT=$("$CA" --config bootstrap.conf add dupe --ca-key "$CA_KEY_URI" --ca-pem ca.pem 2>&1)
chk "fastpki-ca add refuses the disabled id too" yes \
    "$(printf '%s' "$DISOUT" | grep -qi 'already registered under id' && echo yes || echo no)"
# The message must name the state, or "already registered" reads as "it is live" and an
# operator goes looking for a CA the console shows as disabled.
chk "  and names it as disabled" yes \
    "$(printf '%s' "$DISOUT" | grep -qi 'disabled' && echo yes || echo no)"

echo
echo "=== CA DELETE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
