#!/usr/bin/env bash
# ACME wildcard authorizations (RFC 8555 §7.1.3 / §7.1.4), driven by REAL certbot.
#
# ⚠️ dns-01 IS NOT THE ONLY WILDCARD-CAPABLE CHALLENGE. http-01 works for wildcards too —
# it did in the PHP server this is a port of — and the reason we believed otherwise was a
# bug of ours, not a property of the protocol.
#
# ⚠️ THE AUTHZ IDENTIFIER MUST NOT CARRY THE "*." PREFIX. RFC 8555 §7.1.3: "An
# authorization returned by the server for a wildcard domain name identifier MUST NOT
# include the asterisk and full stop ("*.") prefix in the authorization identifier value.
# The returned authorization MUST include the optional "wildcard" field, with a value of
# true." §7.1.4 repeats it: "Wildcard domain names (with "*" as the first label) MUST NOT
# be included in authorization objects."
#
# We stored the raw "*.example.org" instead. Two consequences, and the second is the one
# that produced the false belief:
#   1. the authorization object was non-conformant on the wire;
#   2. http-01 and tls-alpn-01 CONNECT to the identifier, so they would have dialled a host
#      literally named "*.example.org" — so they were withheld from wildcards, and a code
#      comment justified that with "RFC 8555 §8.4 / RFC 8737 §3". Neither section says it.
#      The word "wildcard" appears NOWHERE in §8 of RFC 8555 and nowhere at all in RFC
#      8737. Requiring dns-01 for a wildcard is CA policy (Let's Encrypt's), not protocol.
#
# ⚠️ WHAT THIS SUITE MEASURES, AND WHAT IT DOES NOT. It proves the SERVER side: a wildcard
# authorization is now RFC-shaped (base identifier + wildcard flag) and is offered all three
# challenge types, so nothing is left for a connect-based validator to trip over. It does
# NOT drive a wildcard order to completion over http-01 — that needs :80 and a name that
# resolves to this host, which is what keeps acme_lifecycle.sh in ROOT_SUITES. Do not read
# the green run as "certbot issued a wildcard over http-01"; it did not, and no claim here
# says it did. The wildcard order below is completed over dns-01 to prove issuance still
# works end to end.
# â ï¸ THIS SUITE REGISTERS WITH A REAL EAB BINDING, and that is the point. It used to
# pin ACME_EAB_REQUIRED=false because it tests ACME PROTOCOL mechanics and not deployment
# policy â but the switch is gone, and pinning it meant fourteen suites exercised a
# configuration FastPKI does not ship. The binding is now provisioned the way a real
# deployment provisions one: acme_seed_eab writes a kid + HMAC to the `keys` table and
# certbot presents them with --eab-kid/--eab-hmac-key.
# The DEFAULT itself is still exercised by acme_default_eab.sh, which provisions NOTHING.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/acme_jws.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
[ -n "$OSSL" ] || { echo "SKIP: no openssl on PATH"; exit 0; }
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
command -v certbot >/dev/null 2>&1 || { echo "SKIP: certbot not installed (needs the real client)"; exit 0; }
[ -x "$ROOT/build/dnsstub" ] || { echo "SKIP: build/dnsstub not built"; exit 0; }

W="$(mktemp -d)"; cd "$W"; PORT=18471; DNSP=15371
BASE=wild.example.org; WILD="*.$BASE"; OFFER=offer.example.org; PLAIN=plain.example.org
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

ca_in_token ca.pem "/CN=Wildcard CA" 3650 || { echo "SKIP: could not mint a CA key in a token"; exit 0; }
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout acme.key -out acme.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup acme_wildcard
SRV=
trap 'kill $SRV 2>/dev/null; pkill -f "dnsstub $DNSP" 2>/dev/null; pg_cleanup' EXIT
cat > bootstrap.conf <<EOF
BASE_URL=https://localhost:$PORT
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca
ROOT_CA_PEM=$W/root.pem
ACME_CERT=$W/acme.pem
ACME_KEY=$W/acme.key
PG_CONNINFO=$PG_CONNINFO
ACME_BIND=127.0.0.1
ACME_PORT=$PORT
ACME_BASE_PATH=/acme
ACME_DNS_RESOLVER=127.0.0.1:$DNSP
LOG_LEVEL=info
EOF
seed_ca_from_conf bootstrap.conf
"$ROOT/build/fastpki-acme" --config bootstrap.conf > srv.log 2>&1 & SRV=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$SRV" || true
kill -0 $SRV 2>/dev/null || { echo "fastpki-acme died:"; cat srv.log; exit 1; }

export REQUESTS_CA_BUNDLE="$W/acme.pem"
acme_seed_eab wildcard
CB=(--server "https://localhost:$PORT/acme/ca/directory"
    --config-dir "$W/cb" --work-dir "$W/cbw" --logs-dir "$W/cbl" -n
    --eab-kid "$ACME_EAB_KID" --eab-hmac-key "$ACME_EAB_HMAC")

cat > authhook.sh <<'HOOK'
#!/usr/bin/env bash
set -u
pkill -f "dnsstub $DNSP" 2>/dev/null; sleep 0.2
rm -f "$W/dns.log"
"$ROOT/build/dnsstub" "$DNSP" "TXT:_acme-challenge.$CERTBOT_DOMAIN=$CERTBOT_VALIDATION" > "$W/dns.log" 2>&1 &
for i in $(seq 1 40); do grep -q READY "$W/dns.log" 2>/dev/null && break; sleep 0.1; done
HOOK
printf '#!/usr/bin/env bash\nexit 0\n' > cleanhook.sh
chmod +x authhook.sh cleanhook.sh
export ROOT W DNSP

echo "=== a wildcard order, driven by real certbot over dns-01 ==="
certbot certonly --manual --preferred-challenges dns "${CB[@]}" \
    --manual-auth-hook "$W/authhook.sh" --manual-cleanup-hook "$W/cleanhook.sh" \
    --register-unsafely-without-email --agree-tos \
    --cert-name wildcard -d "$WILD" > certbot-wild.log 2>&1
chk "certbot completed the wildcard order" yes \
    "$([ -f "$W/cb/live/wildcard/cert.pem" ] && echo yes || echo no)"

echo "=== RFC 8555 §7.1.3/§7.1.4: the AUTHZ identifier is the base name, never '*.' ==="
# ⚠️ identifier is BYTEA holding JSON — convert_from() or no LIKE can ever match.
wild_ident=$(pg_exec "select convert_from(identifier,'UTF8') from authorizations
                      where wildcard=1;" | tr -d ' ')
chk "the wildcard authz exists"                1 \
    "$(pg_exec "select count(*) from authorizations where wildcard=1;" | tr -d ' ')"
chk "  its identifier is the BASE domain"      "{\"type\":\"dns\",\"value\":\"$BASE\"}" "$wild_ident"
chk "  and carries no asterisk at all"         0 \
    "$(pg_exec "select count(*) from authorizations
                where convert_from(identifier,'UTF8') like '%*%';" | tr -d ' ')"

echo "=== the ORDER still carries the wildcard — that is what goes in the certificate ==="
chk "the order identifier keeps '*.'"          1 \
    "$(pg_exec "select count(*) from orders
                where convert_from(identifiers,'UTF8') like '%\\*.$BASE%';" | tr -d ' ')"
chk "the order reached valid"                  3 \
    "$(pg_exec "select status from orders
                where convert_from(identifiers,'UTF8') like '%\\*.$BASE%';" | tr -d ' ')"

echo "=== a VALIDATED authz keeps only the winning challenge (why the block below exists) ==="
# ⚠️ READ THIS BEFORE ASSERTING ON CHALLENGE ROWS. On success the server DELETES the
# siblings — src/acme/main.cpp: "Drop sibling challenges; only the verified one survives."
# So the authz certbot just completed has exactly ONE challenge row, dns-01, no matter what
# was offered. My first version of this suite asserted the three types here and went red on
# a working fix. Pin the behaviour so the next reader does not repeat it.
chk "the validated authz kept exactly one challenge" 1 \
    "$(pg_exec "select count(*) from challenges c
                join authorizations a on c.\"authorization\"=a.id
                where a.wildcard=1;" | tr -d ' ')"
chk "  and it is the one that validated"            dns-01 \
    "$(pg_exec "select c.type from challenges c
                join authorizations a on c.\"authorization\"=a.id
                where a.wildcard=1;" | tr -d ' ')"

echo "=== so the OFFER is measured on an authz that was never completed ==="
# The authz must exist and NOT be completed, so that it still carries every challenge the
# server offered — a validated one keeps only the winner, as the block above proves.
#
# ⚠️ THIS ORDER IS PLACED DIRECTLY, NOT THROUGH certbot, AND THE REASON IS 256 SECONDS.
# It used to run certbot with a hook that published no TXT record. That works, but "leave
# the order failing" means waiting out the CLIENT's entire retry and backoff schedule for
# something the suite wants to abandon on purpose: measured at 148s here and 108s for the
# plain case below, against 3s for the real issuance above and ~7s for all twenty
# assertions. 96% of this suite was spent watching certbot give up, and because it is the
# slowest suite in the tree it also set the floor for the whole parallel run.
#
# What is under test is what the SERVER writes when an order is created, so create the
# order and stop. The rows are identical — same authz, same challenges, still not
# completed — and this is the same newOrder call the enforcement section below already
# uses. certbot is kept for the issuance above, which is the cell that actually needs a
# real client we do not control; it is not needed to prove a server-side row exists.
acme_dir "https://localhost:$PORT/acme/ca/directory" >/dev/null 2>&1
jws_newkey uncompleted.pem; acme_new_account uncompleted.pem >/dev/null 2>&1
UNKID=$ACME_LOCATION
chk "fixture: an account for the un-completed orders" yes \
    "$([ -n "$UNKID" ] && echo yes || echo no)"
acme_post_kid uncompleted.pem "$UNKID" "$ACME_NEW_ORDER" \
    "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"*.$OFFER\"}]}" >/dev/null 2>&1
chk "the un-completed wildcard authz exists"    1 \
    "$(pg_exec "select count(*) from authorizations
                where wildcard=1 and convert_from(identifier,'UTF8') like '%$OFFER%';" | tr -d ' ')"
chk "  its identifier is the BASE domain too"   "{\"type\":\"dns\",\"value\":\"$OFFER\"}" \
    "$(pg_exec "select convert_from(identifier,'UTF8') from authorizations
                where wildcard=1 and convert_from(identifier,'UTF8') like '%$OFFER%';" | tr -d ' ')"
wild_types(){ pg_exec "select coalesce(string_agg(distinct c.type,',' order by c.type),'') from challenges c
                       join authorizations a on c.\"authorization\"=a.id
                       where a.wildcard=1 and convert_from(a.identifier,'UTF8') like '%$OFFER%';" | tr -d ' '; }
chk "a wildcard is offered dns-01 and nothing else" dns-01 "$(wild_types)"

echo "=== anti-vacuity: a PLAIN un-completed order, same treatment ==="
# Without this, "3 challenges" could pass on a server that never sets the wildcard flag at
# all — the wildcard rows would simply be plain rows and nobody would notice.
acme_post_kid uncompleted.pem "$UNKID" "$ACME_NEW_ORDER" \
    "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"$PLAIN\"}]}" >/dev/null 2>&1
chk "the plain authz is NOT flagged wildcard"   1 \
    "$(pg_exec "select count(*) from authorizations
                where wildcard=0 and convert_from(identifier,'UTF8') like '%$PLAIN%';" | tr -d ' ')"
chk "  it offers the same three types"          3 \
    "$(pg_exec "select count(*) from challenges c
                join authorizations a on c.\"authorization\"=a.id
                where a.wildcard=0 and convert_from(a.identifier,'UTF8') like '%$PLAIN%'
                  and c.type in ('http-01','tls-alpn-01','dns-01');" | tr -d ' ')"
# ⚠️ AND THE TWO SETS MUST DIFFER. The plain assertion above is what stops "only dns-01"
# passing on a server that stopped offering the connect-based challenges ALTOGETHER — that
# would satisfy every wildcard check here while silently breaking every ordinary order.
chk "wildcard and plain do NOT offer the same set" differ \
    "$([ "$(wild_types)" \
      = "$(pg_exec "select string_agg(distinct c.type,',' order by c.type) from challenges c
                    join authorizations a on c.\"authorization\"=a.id
                    where a.wildcard=0 and convert_from(a.identifier,'UTF8') like '%$PLAIN%';" | tr -d ' ')" ] \
     && echo same || echo differ)"

echo "=== and the refusal is ENFORCED, not merely un-offered ==="
# ⚠️ THE ASSERTIONS ABOVE ARE ABOUT WHAT A WELL-BEHAVED CLIENT IS SHOWN. Withholding a
# challenge from the authorization object is not a control: anything that puts a challenge
# row on a wildcard authorization by some other route — a row written before this rule, a
# future code path — would still validate, and a wildcard becoming valid because one host
# answered is exactly what must not happen. So drive that case directly: put an http-01
# challenge on the wildcard authorization by hand and ask the server to validate it.
acme_dir "https://localhost:$PORT/acme/ca/directory" >/dev/null 2>&1
jws_newkey enf.pem; acme_new_account enf.pem >/dev/null 2>&1; ENFKID=$ACME_LOCATION
chk "fixture: an account for the enforcement probe" yes \
    "$([ -n "$ENFKID" ] && echo yes || echo no)"
acme_post_kid enf.pem "$ENFKID" "$ACME_NEW_ORDER" \
    '{"identifiers":[{"type":"dns","value":"*.enforce.example.org"}]}' >/dev/null 2>&1
ENFAUTHZ=$(pg_exec "select id from authorizations
                    where wildcard=1 and convert_from(identifier,'UTF8') like '%enforce.example.org%';" | tr -d ' ')
chk "fixture: the wildcard authz was created" yes \
    "$([ -n "$ENFAUTHZ" ] && echo yes || echo no)"
chk "  and it was given exactly one challenge" 1 \
    "$(pg_exec "select count(*) from challenges where \"authorization\"='$ENFAUTHZ';" | tr -d ' ')"
# The injected row: same authorization, same token, type http-01. Its URL is the dns-01
# one with the new id substituted, so it is reachable exactly as a real challenge is.
DNSURL=$(pg_exec "select url from challenges where \"authorization\"='$ENFAUTHZ' and type='dns-01';" | tr -d ' ')
DNSTOK=$(pg_exec "select token from challenges where \"authorization\"='$ENFAUTHZ' and type='dns-01';" | tr -d ' ')
INJID=999000111222333
INJURL=$(printf '%s' "$DNSURL" | sed "s|[^/]*\$|$INJID|")
pg_exec "insert into challenges(id,type,url,status,token,\"authorization\")
         values('$INJID','http-01','$INJURL',0,'$DNSTOK','$ENFAUTHZ');" >/dev/null
chk "fixture: an http-01 challenge now exists on the wildcard authz" 1 \
    "$(pg_exec "select count(*) from challenges where id='$INJID';" | tr -d ' ')"
acme_post_kid enf.pem "$ENFKID" "$INJURL" '{}' >/dev/null 2>&1
for i in $(seq 1 40); do
    [ "$(pg_exec "select status from challenges where id='$INJID';" | tr -d ' ')" = "-1" ] && break
    sleep 0.25
done
chk "http-01 on a wildcard does not become valid" -1 \
    "$(pg_exec "select status from challenges where id='$INJID';" | tr -d ' ')"
# ⚠️ THE LINE ABOVE IS NECESSARY AND NOT SUFFICIENT, AND THE REASON BELOW IS THE REAL
# ASSERTION. Measured by removing the refusal and re-running: the status check STILL
# passed. With the policy gone the server genuinely attempts http-01, cannot reach a host
# named enforce.example.org, and marks the challenge invalid for that — the same -1, from
# a failed TCP connect rather than from any decision. So "it ended up invalid" is
# satisfied by a server with no policy at all, on this fixture and on any fixture whose
# identifier does not resolve. Only the recorded REASON separates the two, and that is
# the assertion that went red on the revert.
chk "  and it is refused BY THE RULE, not by a failed connection" yes \
    "$(pg_exec "select error from challenges where id='$INJID';" | grep -qi 'wildcard' && echo yes || echo no)"
# ⚠️ CONTROL. Every assertion above is satisfied by a server that refuses EVERYTHING —
# a crashed verifier, a dead thread, a challenge that never leaves pending. The authz's
# own dns-01 challenge must NOT be refused for this reason.
chk "CONTROL: the dns-01 challenge is not refused as a wildcard violation" no \
    "$(pg_exec "select coalesce(error,'') from challenges
                where \"authorization\"='$ENFAUTHZ' and type='dns-01';" | grep -qi 'wildcard' && echo yes || echo no)"

echo "=== the issued artifact is decoded, not trusted (§3d) ==="
chk "the leaf carries the WILDCARD SAN"        yes \
    "$("$OSSL" x509 -in "$W/cb/live/wildcard/cert.pem" -noout -text 2>/dev/null \
       | grep -q "DNS:\*\.$BASE" && echo yes || echo no)"
chk "  and it chains to our CA"                yes \
    "$("$OSSL" verify -CAfile "$W/root.pem" -untrusted "$W/cb/live/wildcard/chain.pem" \
        "$W/cb/live/wildcard/cert.pem" >/dev/null 2>&1 && echo yes || echo no)"

[ "$fail" -eq 0 ] || { echo "--- certbot (wildcard):"; tail -25 certbot-wild.log; echo "--- server:"; tail -20 srv.log; }
echo
echo "=== ACME WILDCARD: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
