#!/usr/bin/env bash
# Console sign-in with passkeys (WebAuthn), driven by a software authenticator.
#
# passkey-authn plays the phone: it makes the key pair and answers the console's registration
# and sign-in challenges the way a browser hands them to the server. It can also answer the
# ways a real authenticator must never be accepted — without user verification, from another
# origin, for another site, as the wrong ceremony, signed with another key — and every one of
# those is asserted refused here.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=
WEB="$ROOT/build/fastpki-web"
AUTHN="$ROOT/build/passkey-authn"
W="$(mktemp -d)"; cd "$W" || exit 1
PORT=18380; PORT2=18381
P=; P2=
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

[ -x "$AUTHN" ] || { echo "no $AUTHN"; echo "RESULT: FAIL"; exit 1; }
pg_setup web_passkeys
trap 'pg_cleanup; kill $P $P2 2>/dev/null; rm -rf "$W"' EXIT

"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout srv.key -out srv.pem -days 30 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1
seed_web_user alice x auditor
seed_web_user bob   y admin

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_TLS_CERT=$W/srv.pem
WEB_TLS_KEY=$W/srv.key
PKI_DNS=localhost
WEB_SIGNIN_METHODS=password,passkey
LOG_LEVEL=err
EOF
"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 2
kill -0 $P 2>/dev/null || { echo "fastpki-web died:"; cat srv.log; echo "RESULT: FAIL"; exit 1; }
U="https://127.0.0.1:$PORT"
ORIGIN="https://localhost:$PORT"
code() { curl -sk -o /dev/null -w '%{http_code}' "$@"; }
login() { curl -sk -c "$2" -d "username=$1" -d "password=$3" "$U/api/login" >/dev/null; }
field() { printf '%s' "$1" | sed -n 's/.*"'"$2"'":"\([^"]*\)".*/\1/p' | head -1; }

# Registration: begin as the cookie's owner, answer with passkey-authn, finish. Extra
# arguments go to passkey-authn. Prints the finish status; the reply is in reg.out.
register() { # jar keyfile [authn args...]
    local jar="$1" key="$2"; shift 2
    local opts ch
    opts=$(curl -sk -b "$jar" -X POST "$U/api/me/passkeys/begin")
    ch=$(field "$opts" challenge)
    printf '%s' "$opts" | sed -n 's/.*"user":{"id":"\([^"]*\)".*/\1/p' > "$key.uh"
    "$AUTHN" register --key "$key" --rp localhost --origin "$ORIGIN" --challenge "$ch" "$@" > reg.json
    curl -sk -b "$jar" -o reg.out -w '%{http_code}' -H 'Content-Type: application/json' \
         --data-binary "$(sed 's/}$/,"name":"test key"}/' reg.json)" "$U/api/me/passkeys/finish"
}
# Sign-in: begin, answer, finish. Prints the finish status; the cookie goes to the jar given.
signin() { # jar keyfile [authn args...]
    local jar="$1" key="$2"; shift 2
    local ch
    ch=$(field "$(curl -sk -X POST "$U/api/signin/passkey/begin")" challenge)
    "$AUTHN" assert --key "$key" --rp localhost --origin "$ORIGIN" --challenge "$ch" \
        --user-handle "$(cat "$key.uh")" "$@" > as.json
    curl -sk -c "$jar" -o as.out -w '%{http_code}' -H 'Content-Type: application/json' \
         --data-binary @as.json "$U/api/signin/passkey/finish"
}

echo "=== the sign-in page offers passkeys ==="
chk "methods" '"methods":["password","passkey"]' \
    "$(curl -sk "$U/api/signin/methods" | grep -o '"methods":\[[^]]*\]')"
chk "the sign-in challenge names PKI_DNS as the relying party" localhost \
    "$(field "$(curl -sk -X POST "$U/api/signin/passkey/begin")" rpId)"

echo "=== registering a passkey ==="
login alice a.jar x
login bob b.jar y
chk "registration needs a session" 401 "$(code -X POST "$U/api/me/passkeys/begin")"
chk "alice registers an ES256 passkey" 200 "$(register a.jar alice.pem)"
chk "  the reply names it" yes "$(grep -q '"name":"test key"' reg.out && echo yes || echo no)"
chk "  and her list shows it" 1 "$(curl -sk -b a.jar "$U/api/me/passkeys" | grep -o '"id":' | wc -l | tr -d ' ')"
chk "  stored with the user handle the options named" "$(cat alice.pem.uh)" \
    "$(pg_exec "SELECT user_handle FROM passkeys WHERE subject='alice';")"
chk "the same answer again is refused (the challenge is used)" 400 \
    "$(curl -sk -b a.jar -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
       --data-binary @reg.json "$U/api/me/passkeys/finish")"
chk "a second passkey keeps the same user handle" 200 "$(register a.jar alice-ed.pem --alg ed25519)"
chk "  (Ed25519)" "$(cat alice.pem.uh)" "$(cat alice-ed.pem.uh)"
chk "an RS256 passkey registers" 200 "$(register a.jar alice-rsa.pem --alg rs256)"

echo "=== registrations that must be refused ==="
chk "no user verification" 400 "$(register a.jar x1.pem --no-uv)"
chk "  and says why" yes "$(grep -q 'did not verify the user' reg.out && echo yes || echo no)"
chk "another origin" 400 "$(register a.jar x2.pem --origin https://evil.example)"
chk "another site's rp id" 400 "$(register a.jar x3.pem --rp-hash evil.example)"
chk "the wrong ceremony type" 400 "$(register a.jar x4.pem --type webauthn.get)"
# bob starts a registration; alice answers it with her own session.
BCH=$(field "$(curl -sk -b b.jar -X POST "$U/api/me/passkeys/begin")" challenge)
"$AUTHN" register --key x5.pem --rp localhost --origin "$ORIGIN" --challenge "$BCH" > x5.json
chk "someone else's registration challenge" 400 \
    "$(curl -sk -b a.jar -o x5.out -w '%{http_code}' -H 'Content-Type: application/json' \
       --data-binary @x5.json "$U/api/me/passkeys/finish")"
chk "  and says so" yes "$(grep -q 'started by someone else' x5.out && echo yes || echo no)"
chk "  PRECONDITION: none of these was stored" 3 "$(pg_exec "SELECT count(*) FROM passkeys;")"
login alice old.jar x
pg_exec "UPDATE web_sessions SET created = created - 3600 WHERE lower(username)='alice' AND created > 0;" >/dev/null
chk "a sign-in older than 10 minutes may not add a passkey" 403 "$(code -b old.jar -X POST "$U/api/me/passkeys/begin")"
login alice a.jar x

echo "=== signing in with a passkey ==="
chk "alice signs in with her passkey" 200 "$(signin pk.jar alice.pem --count 1)"
chk "  the session is alice's" yes \
    "$(curl -sk -b pk.jar "$U/api/me" | grep -q '"user":"alice","role":"auditor"' && echo yes || echo no)"
chk "  and is recorded as a passkey session" passkey \
    "$(pg_exec "SELECT DISTINCT method FROM web_sessions WHERE username='alice' AND method='passkey';")"
chk "  the audit log says how" yes \
    "$(pg_exec "SELECT detail FROM audit_log WHERE action='web_login' AND actor='alice';" | grep -q 'auth=passkey' && echo yes || echo no)"
chk "  and last use is recorded" yes \
    "$([ "$(pg_exec "SELECT last_used FROM passkeys WHERE credential_id='$(cat alice.pem.id)';")" -gt 0 ] && echo yes || echo no)"
chk "the same answer again is refused (the challenge is used)" 401 \
    "$(curl -sk -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
       --data-binary @as.json "$U/api/signin/passkey/finish")"
chk "a signature counter that did not advance is refused" 401 "$(signin n.jar alice.pem --count 1)"
chk "  and a higher one is accepted" 200 "$(signin n.jar alice.pem --count 5)"
chk "an Ed25519 passkey signs in" 200 "$(signin n.jar alice-ed.pem)"
chk "an RS256 passkey signs in" 200 "$(signin n.jar alice-rsa.pem)"

echo "=== sign-ins that must be refused ==="
chk "no user verification" 401 "$(signin n.jar alice.pem --count 10 --no-uv)"
chk "another origin" 401 "$(signin n.jar alice.pem --count 11 --origin https://evil.example)"
chk "another site's rp id" 401 "$(signin n.jar alice.pem --count 12 --rp-hash evil.example)"
chk "the wrong ceremony type" 401 "$(signin n.jar alice.pem --count 13 --type webauthn.create)"
chk "another user handle" 401 "$(signin n.jar alice.pem --count 14 --user-handle AAAA)"
cp alice-ed.pem forged.pem; cp alice.pem.id forged.pem.id; cp alice.pem.uh forged.pem.uh
chk "a signature by another key under alice's credential id" 401 "$(signin n.jar forged.pem --count 15)"
chk "  and says why" yes "$(grep -q 'signature does not verify' as.out && echo yes || echo no)"
"$AUTHN" register --key stray.pem --rp localhost --origin "$ORIGIN" --challenge AAAA >/dev/null
cp alice.pem.uh stray.pem.uh
chk "an unregistered passkey" 401 "$(signin n.jar stray.pem)"
chk "a finish with no challenge issued" 401 \
    "$("$AUTHN" assert --key alice.pem --rp localhost --origin "$ORIGIN" --challenge bm90aXNzdWVk --count 20 > nc.json;
       curl -sk -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @nc.json "$U/api/signin/passkey/finish")"

echo "=== removing passkeys ==="
chk "bob registers one" 200 "$(register b.jar bob.pem)"
BOBID=$(cat bob.pem.id)
chk "alice cannot remove bob's through her own list" 404 "$(code -b a.jar -X DELETE "$U/api/me/passkeys?id=$BOBID")"
chk "alice cannot remove bob's as a user administrator" 403 \
    "$(code -b a.jar -X DELETE "$U/api/users/passkeys?username=bob&id=$BOBID")"
chk "alice cannot list bob's" 403 "$(code -b a.jar "$U/api/users/passkeys?username=bob")"
chk "an admin lists alice's" 3 "$(curl -sk -b b.jar "$U/api/users/passkeys?username=alice" | grep -o '"id":' | wc -l | tr -d ' ')"
chk "an admin removes one of alice's" 200 \
    "$(code -b b.jar -X DELETE "$U/api/users/passkeys?username=alice&id=$(cat alice-rsa.pem.id)")"
chk "  and it no longer signs in" 401 "$(signin n.jar alice-rsa.pem --count 30)"
chk "alice removes her own" 200 "$(code -b a.jar -X DELETE "$U/api/me/passkeys?id=$(cat alice-ed.pem.id)")"
chk "  and it no longer signs in" 401 "$(signin n.jar alice-ed.pem --count 31)"

echo "=== the policy decides ==="
sed -e "s/^WEB_PORT=.*/WEB_PORT=$PORT2/" -e "s/^WEB_SIGNIN_METHODS=.*/WEB_SIGNIN_METHODS=password/" \
    bootstrap.conf > nopk.conf
"$WEB" --config nopk.conf >nopk.log 2>&1 & P2=$!
sleep 2
U2="https://127.0.0.1:$PORT2"
chk "PRECONDITION: the passkey session works where passkeys are allowed" 200 "$(code -b pk.jar "$U/api/me")"
chk "the same session is refused where they are not" 401 "$(code -b pk.jar "$U2/api/me")"
chk "a passkey sign-in cannot even begin there" 403 "$(code -X POST "$U2/api/signin/passkey/begin")"
chk "  and the page is not offered it" '"methods":["password"]' \
    "$(curl -sk "$U2/api/signin/methods" | grep -o '"methods":\[[^]]*\]')"

echo "=== deleting a user removes their passkeys ==="
chk "an admin deletes alice" 200 "$(code -b b.jar -X DELETE "$U/api/users?username=alice")"
chk "  and her passkeys are gone" 0 "$(pg_exec "SELECT count(*) FROM passkeys WHERE subject='alice';")"

echo "=== WEB-PASSKEYS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
