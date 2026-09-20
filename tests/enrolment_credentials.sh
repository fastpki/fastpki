#!/usr/bin/env bash
# Enrolment credentials follow the role.
#
# Before this, the `keys` table had a READER (get_shared_secret, serving both the
# CMP PBM secret and the ACME EAB HMAC key) and no writer at all — every credential
# had to be INSERTed by hand, and the downloadable CMP config shipped the literal
# string "secret = pass:CHANGE_ME". Granting a role that permits enrolment now mints
# both secrets, and the config a user downloads comes out carrying them.
#
# The decisive assertion is the last one: the config file is downloaded from the
# console and handed UNEDITED to the real `openssl cmp` client, which enrols. That
# is the ticket's user story executed end to end — not a grep for a token.
#
# Self-contained (§3d/§3e): ephemeral Postgres, own ports, temp dir, pure shell,
# SKIPs cleanly with no Postgres.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/cmp_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
W="$(mktemp -d)"; cd "$W"; WPORT=18272; CPORT=18273
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
# One JSON string field, without a JSON parser (§3e: shell only).
jget(){ sed -n 's/.*"'"$2"'":"\([^"]*\)".*/\1/p' <<<"$1"; }
# One column of one row.
q(){ pg_exec "$1" | tr -d ' \n'; }

if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT (set PGHOST/PGPORT/PGUSER/PGPASSWORD)"; exit 0
fi

ca_in_token ca.pem "/CN=Enrol Creds CA" 3650

pg_setup enrol_creds
# CMP protects responses with a per-CA RA credential and has NO CA-key
# fallback, so this is required setup — without it every exchange below is a 503.
cmp_ra_setup ca.pem "$CA_KEY_URI" \
    || { echo "SKIP: could not provision the CMP RA credential"; echo "PASS=0 FAIL=0"; exit 0; }
trap 'pg_cleanup; kill $PW $PC 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source

# fastpki-web mints the credentials and serves the configs; fastpki-cmp is the real
# server the downloaded config is pointed at. Same database, as in a deployment.
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$WPORT
WEB_ALLOW_REVOKE=true
PKI_DNS=127.0.0.1
CMP_PORT=$CPORT
CMP_PATH=/cmp
LOG_LEVEL=err
EOF
cat > cmp.conf <<EOF
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/ca.pem
PG_CONNINFO=$PG_CONNINFO
CMP_BIND=127.0.0.1
CMP_PORT=$CPORT
CMP_PATH=/cmp
LOG_LEVEL=err
EOF
seed_ca_from_conf cmp.conf
seed_web_user root1 root1pass admin

"$ROOT/build/fastpki-web" --config web.conf >web.log 2>&1 & PW=$!
cmp_ra_conf_lines >> cmp.conf   # CMP_RA_CERT_ID_PREFIX + CMP_RA_KEY (cmp.conf, not web.conf)
"$ROOT/build/fastpki-cmp" --config cmp.conf >cmp.log 2>&1 & PC=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$PW" || true
kill -0 $PW 2>/dev/null || { echo "fastpki-web died:"; cat web.log; exit 1; }
kill -0 $PC 2>/dev/null || { echo "fastpki-cmp died:"; cat cmp.log; exit 1; }
U="http://127.0.0.1:$WPORT"
curl -s -c admin.cj -X POST "$U/api/login" -d 'username=root1&password=root1pass' >/dev/null

echo "=== a role that permits enrolment mints both secrets ==="
# The CLI seeded root1 as admin, which enrols — so its credentials exist already,
# proving fastpki-config takes the same path as the console.
chk "CLI-seeded admin got a CMP secret"    1 "$(q "SELECT count(*) FROM keys WHERE kid='root1' AND protocol='cmp'")"
chk "CLI-seeded admin got an EAB key"      1 "$(q "SELECT count(*) FROM keys WHERE kid='root1' AND protocol='eab'")"

chk "create alice (requester) -> 201" 201 "$(code -b admin.cj -X POST "$U/api/users" \
     -d 'create=1&username=alice&password=alicepw12&role=requester')"
chk "alice has a CMP secret"     1 "$(q "SELECT count(*) FROM keys WHERE kid='alice' AND protocol='cmp'")"
chk "alice has an EAB key"       1 "$(q "SELECT count(*) FROM keys WHERE kid='alice' AND protocol='eab'")"
chk "alice has a SCEP challenge" 1 "$(q "SELECT count(*) FROM keys WHERE kid='alice' AND protocol='scep'")"
ALICE_CMP=$(q "SELECT key FROM keys WHERE kid='alice' AND protocol='cmp'")
ALICE_EAB=$(q "SELECT key FROM keys WHERE kid='alice' AND protocol='eab'")
ALICE_SCEP=$(q "SELECT key FROM keys WHERE kid='alice' AND protocol='scep'")
# 32 random bytes, base64url, unpadded = 43 chars from [A-Za-z0-9_-].
chk "CMP secret is 43 base64url chars" yes \
    "$(printf '%s' "$ALICE_CMP" | grep -Eq '^[A-Za-z0-9_-]{43}$' && echo yes || echo no)"
chk "EAB key is 43 base64url chars"    yes \
    "$(printf '%s' "$ALICE_EAB" | grep -Eq '^[A-Za-z0-9_-]{43}$' && echo yes || echo no)"
chk "SCEP secret is 43 base64url chars" yes \
    "$(printf '%s' "$ALICE_SCEP" | grep -Eq '^[A-Za-z0-9_-]{43}$' && echo yes || echo no)"
# ⚠️ All THREE distinct, not just two. One shared value would mean a leaked SCEP
# challengePassword is also a CMP PBM secret and an ACME EAB key — three protocols
# compromised by one exposure, and the per-user design exists to stop a shared secret, not to add one.
chk "all three secrets differ"         yes \
    "$([ "$ALICE_CMP" != "$ALICE_EAB" ] && [ "$ALICE_CMP" != "$ALICE_SCEP" ] && \
       [ "$ALICE_EAB" != "$ALICE_SCEP" ] && echo yes || echo no)"

echo "=== a role that does NOT enrol gets nothing ==="
curl -s -b admin.cj -X POST "$U/api/users" -d 'create=1&username=arch&password=archpw123&role=auditor' >/dev/null
chk "auditor has no CMP secret"   0 "$(q "SELECT count(*) FROM keys WHERE kid='arch'")"
chk "auditor has no EAB key"      0 "$(q "SELECT count(*) FROM keys WHERE kid='arch' AND protocol='eab'")"
chk "auditor has no SCEP challenge" 0 "$(q "SELECT count(*) FROM keys WHERE kid='arch' AND protocol='scep'")"

echo "=== re-saving a user never rotates a secret already in someone's config ==="
curl -s -b admin.cj -X POST "$U/api/users" -d 'username=alice&role=requester' >/dev/null
chk "CMP secret unchanged on re-save" "$ALICE_CMP" "$(q "SELECT key FROM keys WHERE kid='alice' AND protocol='cmp'")"
chk "EAB key unchanged on re-save"    "$ALICE_EAB" "$(q "SELECT key FROM keys WHERE kid='alice' AND protocol='eab'")"

echo "=== losing every enrolling role removes them; regaining one mints fresh ==="
curl -s -b admin.cj -X POST "$U/api/users" -d 'username=alice&role=auditor' >/dev/null
chk "demoted: CMP secret gone" 0 "$(q "SELECT count(*) FROM keys WHERE kid='alice'")"
chk "demoted: EAB key gone"    0 "$(q "SELECT count(*) FROM keys WHERE kid='alice' AND protocol='eab'")"
chk "demoted: SCEP challenge gone" 0 "$(q "SELECT count(*) FROM keys WHERE kid='alice' AND protocol='scep'")"
curl -s -b admin.cj -X POST "$U/api/users" -d 'username=alice&role=requester' >/dev/null
NEW_CMP=$(q "SELECT key FROM keys WHERE kid='alice' AND protocol='cmp'")
chk "re-granted: a secret exists again" yes "$([ -n "$NEW_CMP" ] && echo yes || echo no)"
chk "re-granted: it is a NEW secret"    yes "$([ "$NEW_CMP" != "$ALICE_CMP" ] && echo yes || echo no)"

echo "=== an extra console role also mints (many-to-many) ==="
curl -s -b admin.cj -X POST "$U/api/subject-roles" \
     -d 'selector_type=user&selector_value=arch&role=requester' >/dev/null
chk "auditor + granted requester -> minted" 1 "$(q "SELECT count(*) FROM keys WHERE kid='arch' AND protocol='cmp'")"
curl -s -b admin.cj -X DELETE "$U/api/subject-roles?selector_type=user&selector_value=arch&role=requester" >/dev/null
chk "revoking the extra role removes them"  0 "$(q "SELECT count(*) FROM keys WHERE kid='arch'")"

echo "=== a requester reads their OWN credentials and cannot read anyone else's ==="
curl -s -c alice.cj -X POST "$U/api/login" -d 'username=alice&password=alicepw12' >/dev/null
MINE=$(curl -s -b alice.cj "$U/api/enrolment-credentials")
chk "GET own credentials -> 200" 200 "$(code -b alice.cj "$U/api/enrolment-credentials")"
chk "returns alice's own kid"    alice "$(jget "$MINE" username)"
chk "returns the stored secret"  "$NEW_CMP" "$(jget "$MINE" cmp_secret)"
# The SCEP challengePassword has to come back HERE, or a user cannot obtain it at
# all and their only option is the deployment-wide SCEP_CHALLENGE.
#
# ⚠️ That value names NO USER, so fastpki-scep resolves it to the shared `scep` identity,
# which holds no role and therefore no profile — and an empty profile
# union is a refusal. Exactly this was hit on a live deployment:
#
#   ERR SCEP PKCSReq refused by policy: policy: this identity holds no profile
#       permission, so no certificate profile applies.
#
# Minted the per-user credential and wired it into the downloadable client config,
# but this endpoint never returned it and the console never displayed it. A credential
# nobody can fetch is the same as one that does not exist — the reader-with-no-writer
# shape, inverted.
MINE_SCEP=$(jget "$MINE" scep_challenge)
chk "the SCEP challenge is returned too" yes \
    "$([ -n "$MINE_SCEP" ] && echo yes || echo no)"
# It must be HER credential, not the deployment-wide value: the server splits on the one
# ':' to recover the kid, so the prefix is what makes the profile resolve for alice.
# The kid is the bare username, so the wire form is "<user>:<secret>" — the
# redundant middle field is gone.
chk "  and it is the per-user form <user>:<secret>" yes \
    "$(printf '%s' "$MINE_SCEP" | grep -q '^alice:[^:]*$' && echo yes || echo no)"
chk "  carrying the secret actually stored for her" yes \
    "$([ "$MINE_SCEP" = "alice:$(q "SELECT key FROM keys WHERE kid='alice' AND protocol='scep'")" ] && echo yes || echo no)"

# ⚠️ THE SECOND HALF — and the first fix was incomplete without it. An account whose
# credentials were minted BEFORE SCEP had an identity has a CMP secret and an EAB key and no SCEP row, and
# nothing back-fills one: ensure_enrolment_creds() runs on user creation, on a role change
# and on federated login, so a local account keeps its incomplete set indefinitely.
#
# Measured on the lab after deploying the first half: `admin` held scep:enrol, the field
# was served, and it was EMPTY. The API was honest and SCEP was still unusable.
#
# Simulated exactly: delete the row an older account never had, then FETCH.
q "DELETE FROM keys WHERE kid='alice' AND protocol='scep'" >/dev/null
chk "PRECONDITION: the SCEP row is gone, as on an older account" 0 \
    "$(q "SELECT count(*) FROM keys WHERE kid='alice' AND protocol='scep'")"
BACK=$(curl -s -b alice.cj "$U/api/enrolment-credentials")
chk "  fetching credentials MINTS the missing SCEP secret" 1 \
    "$(q "SELECT count(*) FROM keys WHERE kid='alice' AND protocol='scep'")"
chk "  and the response carries it, not an empty string" yes \
    "$(printf '%s' "$(jget "$BACK" scep_challenge)" | grep -q '^alice:.' && echo yes || echo no)"
# ⚠️ It must MINT, not ROTATE. A back-fill that regenerated the CMP secret would silently
# break every client config already downloaded — the opposite of a repair.
chk "  the CMP secret is untouched by the back-fill" "$NEW_CMP" "$(jget "$BACK" cmp_secret)"
# The dangerous case: a non-admin naming someone else. The parameter must be ignored,
# NOT honoured — otherwise any requester could read the admin's secret.
OTHER=$(curl -s -b alice.cj "$U/api/enrolment-credentials?username=root1")
chk "?username=root1 as requester returns HER OWN" alice "$(jget "$OTHER" username)"
chk "and NOT root1's secret" yes \
    "$([ "$(jget "$OTHER" cmp_secret)" != "$(q "SELECT key FROM keys WHERE kid='root1' AND protocol='cmp'")" ] && echo yes || echo no)"
# ⚠️ AN ADMIN MUST NOT READ SOMEBODY ELSE'S SECRET EITHER. This used to assert the
# opposite — "an admin MAY name another user" — because ?username= was honoured for
# admins. These are authentication secrets: an admin who can read them can enrol AS that
# user, and the audit trail then names the wrong actor. The rule is reset, never read.
ADM=$(curl -s -b admin.cj "$U/api/enrolment-credentials?username=alice")
chk "?username=alice as ADMIN returns the admin's own" root1 "$(jget "$ADM" username)"
chk "and NOT alice's secret" yes \
    "$([ "$(jget "$ADM" cmp_secret)" != "$NEW_CMP" ] && echo yes || echo no)"
# The SUMMARY: whether a user has credentials, never the values. The Users dialog needs it for
# the row on screen; the full read can only ever answer about the caller.
SUMA=$(curl -s -b admin.cj "$U/api/enrolment-credentials?summary=1&username=alice")
chk "an admin's summary of alice names alice" alice "$(jget "$SUMA" username)"
chk "  says she has credentials"              yes "$(grep -q '"enrolment":true' <<<"$SUMA" && echo yes || echo no)"
chk "  and carries no secret"                 "" "$(jget "$SUMA" cmp_secret)"
chk "a requester may not ask about another user (403)" 403 \
    "$(code -b alice.cj "$U/api/enrolment-credentials?summary=1&username=root1")"
chk "her own summary carries no secret either" "" "$(jget "$(curl -s -b alice.cj "$U/api/enrolment-credentials?summary=1")" cmp_secret)"
# Rotation is the one thing an admin still does for someone else — a leaked credential has
# to be revocable — but the reply carries no secret material, only confirmation.
# Either spelling works — cpp-httplib parses the query string into req.params for every
# method, and a form body on top of that. -d here only to match the rest of the file.
ROT=$(curl -s -b admin.cj -X POST "$U/api/enrolment-credentials" -d 'username=alice')
# ⚠️ jget reads QUOTED values only — `"rotated":true` is an unquoted JSON boolean, so
# jget can never return it and an assertion built on it could never pass. Match the raw
# JSON instead. (The identity below still goes through jget: "username" is a string.)
chk "an admin MAY rotate another user's credentials" yes \
    "$(grep -q '"rotated":true' <<<"$ROT" && echo yes || echo no)"
chk "the rotate names the target user"               alice "$(jget "$ROT" username)"
chk "the rotate reply carries NO secret"             "" "$(jget "$ROT" cmp_secret)"
chk "and it really did change alice's secret"        yes \
    "$([ "$(q "SELECT key FROM keys WHERE kid='alice' AND protocol='cmp'")" != "$NEW_CMP" ] && echo yes || echo no)"
NEW_CMP=$(q "SELECT key FROM keys WHERE kid='alice' AND protocol='cmp'")   # later sections compare against it

echo "=== the downloaded configs carry the credentials, not placeholders ==="
curl -s -b alice.cj "$U/api/client-config/cmp"  -o fastpki-cmp.cnf
curl -s -b alice.cj "$U/api/client-config/acme" -o certbot-cli.ini
chk "CMP config has no unsubstituted token"  no  "$(grep -q '{{' fastpki-cmp.cnf && echo yes || echo no)"
chk "CMP config has no CHANGE_ME"            no  "$(grep -q 'CHANGE_ME' fastpki-cmp.cnf && echo yes || echo no)"
chk "CMP config carries alice's reference"   yes "$(grep -qE "^ref *= *alice( +#.*)?$" fastpki-cmp.cnf && echo yes || echo no)"
chk "CMP config carries the real secret"     yes "$(grep -q "^secret *= *pass:$NEW_CMP$" fastpki-cmp.cnf && echo yes || echo no)"
NEW_EAB=$(q "SELECT key FROM keys WHERE kid='alice' AND protocol='eab'")
chk "ACME config has no unsubstituted token" no  "$(grep -q '{{' certbot-cli.ini && echo yes || echo no)"
# ⚠️ HYPHENS. certbot's cli.ini keys are its long option names verbatim, so
# `--eab-kid` is `eab-kid`; with underscores certbot rejects the file. This suite asserted
# the underscore form, so it AGREED with the bug — which is why the bug shipped.
chk "ACME config carries the EAB kid"        yes "$(grep -q "^eab-kid *= *alice$" certbot-cli.ini && echo yes || echo no)"
chk "ACME config carries the EAB key"        yes "$(grep -q "^eab-hmac-key *= *$NEW_EAB$" certbot-cli.ini && echo yes || echo no)"
chk "  and no underscore spelling survives"  no  "$(grep -qE "^eab_(kid|hmac_key) *=" certbot-cli.ini && echo yes || echo no)"
# The default config text was supplied, and the keys below
# are the ones that make it WORK against this deployment rather than against Let's Encrypt.
# The old template said `certbot certonly --standalone`, which cannot succeed here: our
# ACME needs a challenge the operator is walked through, and nothing told them to trust the
# PKI's own root, so certbot died in the TLS handshake before any ACME ran.
chk "ACME config selects the http challenge"  yes "$(grep -q '^preferred-challenges *= *http$' certbot-cli.ini && echo yes || echo no)"
chk "  and agrees to the ToS non-interactively" yes "$(grep -q '^agree-tos *= *true$' certbot-cli.ini && echo yes || echo no)"
chk "  and suppresses the EFF mailing prompt" yes "$(grep -q '^no-eff-email$' certbot-cli.ini && echo yes || echo no)"
# The two instructions without which the file is unusable: trust the root, and use --manual.
chk "  and says to export REQUESTS_CA_BUNDLE" yes "$(grep -q 'REQUESTS_CA_BUNDLE=root-ca.crt' certbot-cli.ini && echo yes || echo no)"
chk "  and shows --config with --manual"      yes "$(grep -q -- '--config certbot-cli.ini --manual' certbot-cli.ini && echo yes || echo no)"
# ⚠️ The old advice must be GONE, not merely joined by the new: two contradictory recipes in
# one file is what sent an operator down the --standalone path in the first place.
chk "  and the old --standalone recipe is gone" no "$(grep -q -- '--standalone' certbot-cli.ini && echo yes || echo no)"

# The Dashboard label must name the file the button actually delivers. It said
# "openssl.cnf"/"certbot.ini" while serving fastpki-cmp.cnf/certbot-cli.ini, so an operator
# went looking for a file that is never written.
WEBSRC="$ROOT/src/web/main.cpp"
for pair in "cmp:fastpki-cmp.cnf" "acme:certbot-cli.ini" "ms:fastpki-request.inf"; do
  k="${pair%%:*}"; f="${pair##*:}"
  chk "Dashboard label for '$k' names $f" yes \
      "$(grep -qF "['$k','" "$WEBSRC" && grep -F "['$k','" "$WEBSRC" | grep -qF "$f" && echo yes || echo no)"
done
# The SCEP config was the one that carried NO credential at all — the whole
# ticket. The SCEP_CHALLENGE substitution was not included in it, which is a bug.
curl -s -b alice.cj "$U/api/client-config/scep" -o fastpki-scep-enroll.sh
NEW_SCEP=$(q "SELECT key FROM keys WHERE kid='alice' AND protocol='scep'")
chk "SCEP config has no unsubstituted token" no  "$(grep -q '{{' fastpki-scep-enroll.sh && echo yes || echo no)"
chk "SCEP config carries alice's challenge"  yes "$(grep -q "^CHALLENGE=\"alice:$NEW_SCEP\"$" fastpki-scep-enroll.sh && echo yes || echo no)"
# ⚠️ And it must NOT be the deployment-wide value. That is option 1 on the ticket, the
# one that was not chosen, and it is what is_secret_config_key() masks on the Config
# page precisely so a user cannot read it there.
chk "  and NOT the shared SCEP_CHALLENGE"    no  "$(grep -q 'sharedsecret123' fastpki-scep-enroll.sh && echo yes || echo no)"
chk "  the challengePassword is in the CSR"  yes "$(grep -q 'challengePassword = \$CHALLENGE' fastpki-scep-enroll.sh && echo yes || echo no)"

echo "=== the URLs name a CA — the base enrolment paths 404 ==="
chk "CMP server URL names the CA id"  yes "$(grep -q "^server *= *http://127.0.0.1:$CPORT/cmp/ca$" fastpki-cmp.cnf && echo yes || echo no)"
chk "ACME directory names the CA id"  yes "$(grep -q "/ca/directory" certbot-cli.ini && echo yes || echo no)"

echo "=== the EAB key is usable as an HMAC key in the form verify_eab expects ==="
# verify_eab base64url-DECODES the stored string and HMACs with those bytes. Decode
# it the same way and prove it is exactly a 256-bit key.
printf '%s' "$NEW_EAB" | tr '_-' '/+' | { cat; printf '='; } | "$OSSL" base64 -d -A > eab.bin 2>/dev/null
chk "EAB key decodes to 32 bytes" 32 "$(wc -c < eab.bin | tr -d ' ')"
HEXKEY=$(od -An -v -tx1 < eab.bin | tr -d ' \n')
SIG=$("$OSSL" dgst -sha256 -mac HMAC -macopt "hexkey:$HEXKEY" -binary <<<'test' | "$OSSL" base64 -A)
chk "HMAC-SHA256 with it produces a signature" yes "$([ -n "$SIG" ] && echo yes || echo no)"

echo "=== THE USER STORY: the downloaded config enrols, unedited, via a real client ==="
# No hand-editing. The file exactly as the console served it, plus the trust anchor
# the config tells the user to download. This is what the credential flow promises.
"$OSSL" genrsa -out client.key 2048 >/dev/null 2>&1
"$OSSL" cmp -config fastpki-cmp.cnf -section cmp,ir \
       -subject "/CN=host.example.internal" -newkey client.key \
       -recipient "/CN=Enrol Creds CA" -trusted ca.pem -expect_sender "/CN=cmp-ra.test" \
       -certout issued.pem -keep_alive 0 >cmpclient.log 2>&1
chk "openssl cmp enrolled with the downloaded config" yes \
    "$([ -s issued.pem ] && echo yes || echo no)"
chk "and the issued cert decodes with the right subject" yes \
    "$("$OSSL" x509 -in issued.pem -noout -subject 2>/dev/null | grep -q 'host.example.internal' && echo yes || echo no)"

echo "=== regenerating invalidates the old secret ==="
OLD=$NEW_CMP
curl -s -b admin.cj -X POST "$U/api/enrolment-credentials" -d 'username=alice' >/dev/null
ROT=$(q "SELECT key FROM keys WHERE kid='alice' AND protocol='cmp'")
chk "rotate changed the CMP secret" yes "$([ "$ROT" != "$OLD" ] && echo yes || echo no)"
rm -f old.pem
"$OSSL" cmp -server "http://127.0.0.1:$CPORT/cmp/ca" -cmd ir -ref alice -secret "pass:$OLD" \
       -subject "/CN=stale.example.internal" -newkey client.key \
       -recipient "/CN=Enrol Creds CA" -trusted ca.pem -expect_sender "/CN=cmp-ra.test" -certout old.pem -keep_alive 0 >/dev/null 2>&1
chk "the superseded secret no longer enrols" no "$([ -s old.pem ] && echo yes || echo no)"
chk "rotate for a non-enrolling user -> 409" 409 \
    "$(code -b admin.cj -X POST "$U/api/enrolment-credentials" -d 'username=arch')"

# ── the CONSOLE side of the same rules ───────────────────────────────────────────
#
# The server contract is asserted above; these three are about what the page DOES with
# the answer, which is where both follow-ups actually landed. §3e: grep
# proxies are weak, but they catch a reintroduction, and the shell harness cannot run JS.
curl -s "$U/" -o console.html
echo "=== The dashboard must not paint secrets on the front page ==="
chk "the panel starts masked"            yes \
    "$(grep -q '••••••••' console.html && echo yes || echo no)"
chk "  and offers an explicit Reveal"    yes \
    "$(grep -q "id=\"credreveal\"" console.html && echo yes || echo no)"
chk "  the first draw is the masked one" yes \
    "$(grep -q 'draw(null);' console.html && echo yes || echo no)"
# The real property, not just the markup: nothing is fetched until Reveal is pressed, so
# the secrets never enter the page unhidden. A hidden field would be one inspection away.
chk "  values are fetched on demand, not at render" yes \
    "$(grep -q 'draw(shown ? null : await load())' console.html && echo yes || echo no)"

echo "=== Another user's row must never show the CALLER's secrets ==="
# The server ignores ?username= (asserted above), so the reply is always the caller's.
# The page has to notice that rather than render it under the row's name.
chk "the modal asks about THAT user, as a summary" yes \
    "$(grep -q "'?summary=1&username='+encodeURIComponent(username)" console.html && echo yes || echo no)"
chk "  and the Dashboard's first call carries no secret" yes \
    "$(grep -q 'c = await load(true);' console.html && echo yes || echo no)"
chk "  and shows (set) instead of a value"         yes \
    "$(grep -q "row('CMP secret', '(set)')" console.html && echo yes || echo no)"
chk "  Regenerate is still offered to an admin"    yes \
    "$(grep -q 'umcredsrot' console.html && echo yes || echo no)"

echo "=== A confirm dialog must render above the modal that raised it ==="
chk "#confirmmodal is raised out of the shared stack" yes \
    "$(grep -q '#confirmmodal{z-index:300;}' console.html && echo yes || echo no)"
chk "  and that is above the .modal default"          yes \
    "$(grep -q 'z-index:100' console.html && echo yes || echo no)"

echo "=== deleting the user takes the credentials with it ==="
curl -s -b admin.cj -X DELETE "$U/api/users?username=alice" >/dev/null
chk "deleted user: CMP secret gone" 0 "$(q "SELECT count(*) FROM keys WHERE kid='alice'")"
chk "deleted user: EAB key gone"    0 "$(q "SELECT count(*) FROM keys WHERE kid='alice' AND protocol='eab'")"
chk "deleted user: SCEP challenge gone" 0 "$(q "SELECT count(*) FROM keys WHERE kid='alice' AND protocol='scep'")"

echo
echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] || exit 1
