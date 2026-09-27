#!/usr/bin/env bash
# Read-only web management UI — fastpki-web.
#   - serves the SPA at / and a JSON API over the existing DB
#   - /api/* is gated by WEB_TOKEN (bearer); 401 without it
#   - inventory / audit / discovered endpoints reflect the DB rows
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
WEB="$ROOT/build/fastpki-web"
AUDIT="$ROOT/build/fastpki-audit"
W="$(mktemp -d)"; cd "$W"; PORT=18090
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

pg_setup web
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
NOW=$(date +%s)
# Two managed certs: one valid, one revoked.
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint) VALUES('a1',0,0,0,$((NOW-86400)),$((NOW+86400)),'CN=web.host','alice','web.host','ff11');"
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint) VALUES('b2',-1,1,$NOW,$((NOW-86400)),$((NOW+86400)),'CN=gone.host','bob','gone.host','ff22');"
# A managed cert WITH a stored DER blob (for the detail drill-down): real
# RSA cert carrying two DNS SANs, inserted as a hex blob into the cert column.
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.pem -days 365 \
  -subj "/CN=detail.host" -addext "subjectAltName=DNS:detail.host,DNS:alt.host" >/dev/null 2>&1
"$OSSL" x509 -in leaf.pem -outform DER -out leaf.der 2>/dev/null
DHEX=$(xxd -p leaf.der | tr -d '\n')
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,cert) VALUES('d4',0,0,0,$((NOW-86400)),$((NOW+86400)),'CN=detail.host','carol','detail.host','ff44','\x$DHEX'::bytea);"
# A weak (RSA-1024) cert with a stored DER, far-future expiry — for the
# compliance/risk report. weak_key, not expiring.
"$OSSL" req -x509 -newkey rsa:1024 -nodes -keyout w.key -out w.pem -days 4000 -subj "/CN=weak.host" >/dev/null 2>&1
"$OSSL" x509 -in w.pem -outform DER -out w.der 2>/dev/null
WHEX=$(xxd -p w.der | tr -d '\n')
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint,cert) VALUES('w1',0,0,0,$((NOW-86400)),$((NOW+4000*86400)),'CN=weak.host','dan','weak.host','ff55','\x$WHEX'::bytea);"
# A discovered (unmanaged) cert with a compliance flag.
pg_exec "INSERT INTO discovered_certs(target,serial,subject,issuer,\"notBefore\",\"notAfter\",\"keyAlgo\",\"keyBits\",\"sigAlgo\",sans,fingerprint,\"selfSigned\",flags,\"discoveredAt\") VALUES('10.0.0.9:443','c3','CN=legacy','CN=legacy',$((NOW-86400)),$((NOW+86400)),'RSA',1024,'sha1WithRSAEncryption','','ab',1,'weak_key,weak_sig,self_signed',$NOW);"

# A signing CA so the web can produce the signed compliance export.
ca_in_token ca.pem "/CN=Web CA" 3650
"$OSSL" x509 -in ca.pem -pubkey -noout > capub.pem 2>/dev/null
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_TOKEN=s3cret
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
# Console (web_users) logins for browser login + RBAC — DB-only now.
source "$ROOT/tests/user_helpers.sh"
seed_web_user admin   adminpw admin
seed_web_user auditor auditpw auditor
# A proper hash-chained audit event via the tool.
"$AUDIT" --config bootstrap.conf append pki_lifecycle cert_issued alice success a1 "cn=web.host" >/dev/null

"$WEB" --config bootstrap.conf >srv.log 2>&1 & P=$!
sleep 1; trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat srv.log; exit 1; fi
URL="http://127.0.0.1:$PORT"
AUTH=(-H "Authorization: Bearer s3cret")

echo "=== static console + health ==="
curl -s "$URL/" | grep -q "FastPKI" && a=yes || a=no
chk "GET / serves the console HTML" yes "$a"
# The login overlay must hide via the [hidden] attribute. A bare `#login{display:flex}`
# rule outranks the UA [hidden]{display:none}, pinning the overlay open after login;
# guard the :not([hidden]) form so that regression can't return unnoticed.
# (the rule may group other overlays, e.g. ",#setup:not([hidden])", before {display:flex})
curl -s "$URL/" | grep -qE '#login:not\(\[hidden\]\)[^{]*\{display:flex\}' && a=yes || a=no
chk "login overlay only displays when not [hidden]" yes "$a"
chk "GET /healthz -> ok" ok "$(curl -s "$URL/healthz")"

echo "=== the Domains list carries the shared list controls ==="
# The same shape the subjects and templates lists use: a checkbox at the left of each row
# and ONE bulk-delete button, instead of a remove button on every row.
#
# ⚠️ EXPRESSIONS, NOT PROSE. The served page embeds this file's own source comments, so a
# grep for a phrase would match the explanation whether or not the wiring exists.
curl -s "$URL/" -o dompage.html
dp(){ grep -qF -- "$1" dompage.html && echo yes || echo no; }
chk "each domain row carries a checkbox"   yes "$(dp "<input type=\"checkbox\" data-dom=\"' + esc(d) + '\"")"
chk "the header carries a select-all"      yes "$(dp "id=\"domall\"")"
chk "one bulk remove, with the count"      yes "$(dp "Delete selected (' + domSel.size + ')")"
# ⚠️ THE ABSENCE IS THE ASK, and it is only worth anything because the pattern USED to be
# there: `data-deldom` appeared twice in the previous revision and appears zero times now.
chk "the per-row remove button is gone"    no  "$(dp 'data-deldom')"
# The confirmation must be the console's own dialog: a browser told to prevent additional
# dialogs makes window.confirm() return false for the rest of the page, which would turn
# the bulk removal into a silent no-op that reports success.
chk "removal goes through askConfirm"      yes "$(dp "await askConfirm('Remove ' + names.length")"
# Anti-vacuity: if the page had not been fetched, every check above would read 'no'.
chk "  fixture: the console page was served" yes "$(dp 'renderDomains')"

echo "=== bearer-token gate ==="
chk "no token -> 401" 401 "$(curl -s -o /dev/null -w '%{http_code}' "$URL/api/certs")"
chk "wrong token -> 401" 401 "$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer nope' "$URL/api/certs")"
chk "valid token -> 200" 200 "$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$URL/api/certs")"

echo "=== inventory API ==="
C=$(curl -s "${AUTH[@]}" "$URL/api/certs")
echo "$C" | grep -q '"cn":"web.host"' && a=yes || a=no
chk "certs API lists the valid cert" yes "$a"
echo "$C" | grep -q '"statusText":"revoked"' && a=yes || a=no
chk "certs API maps status -> revoked" yes "$a"
echo "$C" | grep -q '"cert"' && a=yes || a=no
chk "certs API omits the DER blob" no "$a"

echo "=== advanced inventory query ==="
Q=$(curl -s "${AUTH[@]}" "$URL/api/certs?q=detail")
echo "$Q" | grep -q 'detail.host' && a=yes || a=no
chk "?q= substring search finds the match" yes "$a"
echo "$Q" | grep -q 'web.host' && a=yes || a=no
chk "?q= excludes non-matches" no "$a"
SF=$(curl -s "${AUTH[@]}" "$URL/api/certs?status=-1")
echo "$SF" | grep -q 'gone.host' && a=yes || a=no
chk "?status=-1 returns the revoked cert" yes "$a"
echo "$SF" | grep -q 'web.host' && a=yes || a=no
chk "?status=-1 excludes valid certs" no "$a"
SR=$(curl -s "${AUTH[@]}" "$URL/api/certs?sort=cn&order=asc")
echo "$SR" | grep -o '"cn":"[^"]*"' | head -1 | grep -q 'detail.host' && a=yes || a=no
chk "?sort=cn&order=asc orders by CN" yes "$a"
TC=$(curl -s -D - -o /dev/null "${AUTH[@]}" "$URL/api/certs?q=host" | grep -i 'X-Total-Count' | tr -d '\r' | awk '{print $2}')
chk "X-Total-Count header reflects total matches" 4 "$TC"

echo "=== cert detail drill-down ==="
DT=$(curl -s "${AUTH[@]}" "$URL/api/certs/d4")
echo "$DT" | grep -q '"cn":"detail.host"' && a=yes || a=no
chk "detail returns the cert by serial" yes "$a"
echo "$DT" | grep -q 'dns:detail.host' && a=yes || a=no
chk "detail decodes SANs from the stored DER" yes "$a"
echo "$DT" | grep -q 'dns:alt.host' && a=yes || a=no
chk "detail lists every SAN" yes "$a"
echo "$DT" | grep -q '"keyAlgo":"RSA","keyBits":2048' && a=yes || a=no
chk "detail reports key algorithm + size" yes "$a"
echo "$DT" | grep -q 'BEGIN CERTIFICATE' && a=yes || a=no
chk "detail includes the PEM" yes "$a"
chk "unknown serial -> 404" 404 "$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$URL/api/certs/deadbeef")"

echo "=== audit API ==="
A=$(curl -s "${AUTH[@]}" "$URL/api/audit")
echo "$A" | grep -q '"action":"cert_issued"' && a=yes || a=no
chk "audit API lists the appended event" yes "$a"
echo "$A" | grep -q '"hash":"' && a=yes || a=no
chk "audit API exposes the chain hash" yes "$a"

echo "=== discovered API ==="
D=$(curl -s "${AUTH[@]}" "$URL/api/discovered")
echo "$D" | grep -q '10.0.0.9:443' && a=yes || a=no
chk "discovered API lists the endpoint" yes "$a"
echo "$D" | grep -q 'weak_key' && a=yes || a=no
chk "discovered API carries compliance flags" yes "$a"

echo "=== config API ==="
G=$(curl -s "${AUTH[@]}" "$URL/api/config")
echo "$G" | grep -q '"key":"PG_CONNINFO"' && a=yes || a=no
chk "config API surfaces the DB connection key" yes "$a"
echo "$G" | grep -q '"key":"WEB_TOKEN","value":"(set)"' && a=yes || a=no
chk "config API redacts WEB_TOKEN to (set)" yes "$a"
echo "$G" | grep -q 's3cret' && a=yes || a=no
chk "config API never leaks the token value" no "$a"
# Completeness + Authentication area + per-key descriptions.
echo "$G" | grep -q '"section":"Authentication"' && a=yes || a=no
chk "config API exposes the Authentication area" yes "$a"
# ⚠️ WAS LDAP_URIS, WHICH NO LONGER EXISTS. The directories moved into auth_providers +
# ldap_providers, so the console must NOT offer LDAP_URIS as a settable key — a config row
# an operator fills in that nothing reads is exactly what this suite's siblings guard
# against. AUTH_BACKEND is the Authentication-area key that survived, and it is a real one:
# it chooses a backend, which is not a directory.
echo "$G" | grep -q '"key":"AUTH_BACKEND"' && a=yes || a=no
chk "config API surfaces an Authentication key that still exists" yes "$a"
echo "$G" | grep -q '"key":"LDAP_URIS"' && a=yes || a=no
chk "  and no longer offers the retired LDAP_URIS" no "$a"
# ⚠️ AND THE SSO KEYS WENT THE SAME WAY AS LDAP_URIS. An issuer, a client secret and an
# IdP certificate are per-provider values: a flat config could name exactly one of each,
# which is why "several identity providers" was never a feature we were missing. They are
# rows now, managed on the Directories page, so the Config screen must not offer them —
# a key on that screen that changes nothing is worse than no key at all.
echo "$G" | grep -q '"key":"OIDC_ISSUER"' && a=yes || a=no
chk "  and no longer offers the retired OIDC_ISSUER" no "$a"
echo "$G" | grep -q '"key":"SAML_IDP_SSO_URL"' && a=yes || a=no
chk "  nor the retired SAML_IDP_SSO_URL" no "$a"
echo "$G" | grep -q '"key":"OIDC_CLIENT_SECRET"' && a=yes || a=no
chk "  nor OIDC_CLIENT_SECRET" no "$a"
echo "$G" | grep -qE '"key":"PG_CONNINFO","value":"[^"]*","desc":"' && a=yes || a=no
chk "config API carries a per-key description" yes "$a"
# The console ships a per-Area sub-nav (client-side) built from the
# config sections — assert the element + its builder are served.
IDX=$(curl -s "$URL/")
echo "$IDX" | grep -q 'id="cfgsubmenu"' && a=yes || a=no
chk "console serves the Config Area sub-nav element" yes "$a"
echo "$IDX" | grep -q 'function renderCfgSubmenu' && a=yes || a=no
chk "console ships the Area sub-nav builder" yes "$a"
# Downloadable client configs (per-protocol) generated from live settings.
echo "$IDX" | grep -q 'function downloadClientConfig' && a=yes || a=no
chk "console ships the client-config download" yes "$a"
CC=$(curl -s "${AUTH[@]}" "$URL/api/client-config/cmp")
echo "$CC" | grep -q '^\[cmp\]' && a=yes || a=no
chk "client-config API returns a CMP openssl.cnf" yes "$a"
chk "unknown client-config kind -> 404" 404 "$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$URL/api/client-config/nope")"

echo "=== signed audit export (via web) ==="
chk "export needs a token (401)" 401 "$(curl -s -o /dev/null -w '%{http_code}' "$URL/api/audit/export-signed?ca_instance=ca-global")"
E=$(curl -s "${AUTH[@]}" "$URL/api/audit/export-signed?ca_instance=ca-global")
echo "$E" | grep -q '"signature":"' && a=yes || a=no
chk "export endpoint returns a signature" yes "$a"
echo "$E" | grep -q 'cert_issued' && a=yes || a=no
chk "export embeds the audit ndjson" yes "$a"
# The CA signature is over "<head_seq>:<sha256>" (EVP_DigestSign SHA-256) — verify it.
SHA=$(echo "$E" | grep -o '"sha256":"[0-9a-f]*"' | head -1 | sed 's/.*:"//; s/"$//')
HSEQ=$(echo "$E" | grep -o '"head_seq":[0-9]*' | head -1 | sed 's/.*://')
SIG=$(echo "$E" | grep -o '"signature":"[0-9a-f]*"' | head -1 | sed 's/.*:"//; s/"$//')
printf '%s' "$SIG" | xxd -r -p > sig.bin 2>/dev/null
printf '%s:%s' "$HSEQ" "$SHA" | "$OSSL" dgst -sha256 -verify capub.pem -signature sig.bin >/dev/null 2>&1 && a=yes || a=no
chk "CA signature over head_seq:digest verifies" yes "$a"

echo "=== summary ==="
S=$(curl -s "${AUTH[@]}" "$URL/api/summary")
echo "$S" | grep -q '"certs":4' && a=yes || a=no
chk "summary counts 4 certs" yes "$a"
echo "$S" | grep -q '"discovered":1' && a=yes || a=no
chk "summary counts 1 discovered" yes "$a"

echo "=== local login + sessions ==="
chk "wrong password -> 401" 401 "$(curl -s -o /dev/null -w '%{http_code}' -d 'username=admin&password=nope' "$URL/api/login")"
curl -s -c admin.cj -d 'username=admin&password=adminpw' "$URL/api/login" > login.json
grep -q '"role":"admin"' login.json && a=yes || a=no
chk "admin login returns role" yes "$a"
grep -qi 'fastpki_session' admin.cj && a=yes || a=no
chk "login sets a session cookie" yes "$a"
chk "session cookie authorizes /api/certs" 200 "$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj "$URL/api/certs")"
curl -s -b admin.cj "$URL/api/me" | grep -q '"role":"admin"' && a=yes || a=no
chk "/api/me reflects the session role" yes "$a"
# the login attempts are audited
AN=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='web_login';")
chk "successful login is audited" 1 "$AN"
AF=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='web_login_fail';")
chk "failed login is audited" 1 "$AF"

echo "=== RBAC: auditor is restricted to audit views ==="
curl -s -c audit.cj -d 'username=auditor&password=auditpw' "$URL/api/login" >/dev/null
chk "auditor may read the audit log" 200 "$(curl -s -o /dev/null -w '%{http_code}' -b audit.cj "$URL/api/audit")"
chk "auditor may pull the signed export" 200 "$(curl -s -o /dev/null -w '%{http_code}' -b audit.cj "$URL/api/audit/export-signed?ca_instance=ca-global")"
chk "auditor is denied the cert inventory (403)" 403 "$(curl -s -o /dev/null -w '%{http_code}' -b audit.cj "$URL/api/certs")"
chk "auditor is denied discovered (403)" 403 "$(curl -s -o /dev/null -w '%{http_code}' -b audit.cj "$URL/api/discovered")"
chk "auditor is denied the config view (403)" 403 "$(curl -s -o /dev/null -w '%{http_code}' -b audit.cj "$URL/api/config")"
chk "auditor is denied client-config downloads (403)" 403 "$(curl -s -o /dev/null -w '%{http_code}' -b audit.cj "$URL/api/client-config/cmp")"
chk "auditor is denied a cert detail (403)" 403 "$(curl -s -o /dev/null -w '%{http_code}' -b audit.cj "$URL/api/certs/d4")"

echo "=== compliance & risk report ==="
CO=$(curl -s "${AUTH[@]}" "$URL/api/compliance")
echo "$CO" | grep -q '"weakKey":1' && a=yes || a=no
chk "compliance counts the RSA-1024 weak key" yes "$a"
echo "$CO" | grep -qE 'weak.host.*weak_key|weak_key.*weak.host' && a=yes || a=no
chk "the weak cert is flagged weak_key" yes "$a"
echo "$CO" | grep -q '"expiringSoon":' && a=yes || a=no
chk "report has an expiring-soon bucket" yes "$a"
echo "$CO" | grep -q 'gone.host' && a=yes || a=no
chk "revoked cert excluded from the live-risk report" no "$a"
echo "$CO" | grep -q '"scanned":' && a=yes || a=no
chk "report states how many certs were scanned" yes "$a"
chk "auditor is denied compliance (403)" 403 "$(curl -s -o /dev/null -w '%{http_code}' -b audit.cj "$URL/api/compliance")"

echo "=== revocation ==="
# /api/me advertises the write capability so the console can show the action.
curl -s -b admin.cj "$URL/api/me" | grep -q '"writeEnabled":true' && a=yes || a=no
chk "/api/me advertises writeEnabled" yes "$a"
# auditor may not revoke (RBAC gate, 403)
chk "auditor cannot revoke (403)" 403 "$(curl -s -o /dev/null -w '%{http_code}' -b audit.cj -X POST "$URL/api/certs/a1/revoke")"
# an out-of-range RFC 5280 reason is rejected
chk "invalid revocation reason -> 400" 400 "$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X POST "$URL/api/certs/a1/revoke?reason=7")"
# admin revokes the valid cert a1 with a named RFC 5280 reason (keyCompromise=1)
chk "admin revokes with a reason code (200)" 200 "$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X POST "$URL/api/certs/A1/revoke?reason=1")"
chk "revoked cert is status -1 in the DB" -1 "$(pg_exec "SELECT status FROM certs WHERE serial='a1';")"
chk "RFC 5280 reason stored (keyCompromise=1)" 1 "$(pg_exec "SELECT \"revocationReason\" FROM certs WHERE serial='a1';")"
chk "revocation audited (web_cert_revoked)" 1 "$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='web_cert_revoked' AND target='a1';")"
# re-revoking is an idempotent no-op
curl -s -b admin.cj -X POST "$URL/api/certs/a1/revoke" | grep -q '"alreadyRevoked":true' && a=yes || a=no
chk "re-revoke is idempotent" yes "$a"
chk "revoke of unknown serial -> 404" 404 "$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj -X POST "$URL/api/certs/deadbeef/revoke")"

echo "=== reasons, and a hold that can be released ==="
# Inserted here, after the counts above, so it changes none of them.
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint) VALUES('e5',0,0,0,$((NOW-86400)),$((NOW+86400)),'CN=hold.host','alice','hold.host','ff55e5');" >/dev/null
rv(){ curl -s -o rv.json -w '%{http_code}' -b admin.cj -X POST "$URL/api/certs/$1/$2"; }
chk "removeFromCRL (8) is not a revocation reason -> 400" 400 "$(rv e5 'revoke?reason=8')"
chk "  and says what it is for" yes "$(grep -q 'released hold' rv.json && echo yes || echo no)"
chk "aACompromise (10) -> 400" 400 "$(rv e5 'revoke?reason=10')"
chk "a reason that is not a number -> 400" 400 "$(rv e5 'revoke?reason=hold')"
chk "  and none of them touched the certificate" 0 "$(pg_exec "SELECT status FROM certs WHERE serial='e5';")"
chk "releasing a certificate that is not on hold -> 409" 409 "$(rv e5 release)"
chk "put on hold (certificateHold, 6) -> 200" 200 "$(rv e5 'revoke?reason=6')"
chk "  the answer says on_hold" yes "$(grep -q '"status":"on_hold"' rv.json && echo yes || echo no)"
chk "  stored as a revocation with reason 6" "-1|6" \
    "$(pg_exec "SELECT status||'|'||\"revocationReason\" FROM certs WHERE serial='e5';")"
chk "  the inventory labels it on_hold, not revoked" yes \
    "$(curl -s "${AUTH[@]}" "$URL/api/certs/e5" | grep -q '"statusText":"on_hold"' && echo yes || echo no)"
chk "holding it again is a no-op" yes "$(rv e5 'revoke?reason=6' >/dev/null; grep -q '"alreadyRevoked":true' rv.json && echo yes || echo no)"
chk "an auditor cannot release (403)" 403 \
    "$(curl -s -o /dev/null -w '%{http_code}' -b audit.cj -X POST "$URL/api/certs/e5/release")"
chk "release -> 200" 200 "$(rv e5 release)"
chk "  valid again, recorded as removeFromCRL at the release" "0|8" \
    "$(pg_exec "SELECT status||'|'||\"revocationReason\" FROM certs WHERE serial='e5';")"
chk "  audited (web_cert_hold_released)" 1 \
    "$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='web_cert_hold_released' AND target='e5';")"
chk "  releasing again -> 409" 409 "$(rv e5 release)"
chk "on hold again, then revoked for good (keyCompromise) -> 200" "200 200" "$(rv e5 'revoke?reason=6') $(rv e5 'revoke?reason=1')"
chk "  now revoked, reason 1" "-1|1" \
    "$(pg_exec "SELECT status||'|'||\"revocationReason\" FROM certs WHERE serial='e5';")"
chk "  and a revocation for good cannot be released -> 409" 409 "$(rv e5 release)"
chk "  nor turned back into a hold" "-1|1" \
    "$(rv e5 'revoke?reason=6' >/dev/null; pg_exec "SELECT status||'|'||\"revocationReason\" FROM certs WHERE serial='e5';")"
PAGE=$(curl -s -b admin.cj "$URL/")
chk "the console offers Release hold on a held certificate" yes \
    "$(echo "$PAGE" | grep -q "id=\"releasehold\"" && echo yes || echo no)"
chk "  and the CA Revoke picks a reason from the CA list" yes \
    "$(echo "$PAGE" | grep -q "CA_REASONS.filter(k => !(row.onHold && k === 6))" && echo yes || echo no)"
chk "  and no picker offers removeFromCRL or aACompromise" yes \
    "$(echo "$PAGE" | grep -q 'const CA_REASONS   = \[0, 2, 3, 4, 5, 6, 9\];' && echo "$PAGE" | grep -q 'const LEAF_REASONS = \[0, 1, 3, 4, 5, 6, 9\];' && echo yes || echo no)"
# A second instance with the write switch turned OFF refuses the write.
#
# ⚠️ SET TO false EXPLICITLY, NOT OMITTED. Writes are enabled by default now — a console
# that refuses to issue or revoke is not what anyone installs — so DELETING the line no
# longer disables anything, and a version of this that dropped it would have gone on
# reporting 403 for a while and then silently started measuring nothing. The switch still
# exists, for pinning an instance read-only; this is the assertion that it still works.
grep -v '^WEB_ALLOW_REVOKE=' bootstrap.conf | sed "s/^WEB_PORT=.*/WEB_PORT=$((PORT+1))/" > pki_ro.conf
echo 'WEB_ALLOW_REVOKE=false' >> pki_ro.conf
"$WEB" --config pki_ro.conf >ro.log 2>&1 & RP=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "pki_ro.conf" WEB_PORT "$RP" || true
chk "revoke refused when the write switch is off -> 403" 403 "$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" -X POST "http://127.0.0.1:$((PORT+1))/api/certs/b2/revoke")"
kill $RP 2>/dev/null

echo "=== the Replication page: each host's report, the warnings, and key sync requests ==="
# Behind a load balancer a console is served by whichever host was picked and can read only
# its own token, so every host publishes a row about itself and the page reads them all.
code_of(){ curl -s -o "$1" -w '%{http_code}' "${@:2}"; }
chk "GET /api/replication -> 200" 200 "$(code_of repl.json -b admin.cj "$URL/api/replication")"
SELF=$(sed -n 's/.*"self":"\([^"]*\)".*/\1/p' repl.json)
chk "  it names the host that served it" yes "$([ -n "$SELF" ] && echo yes || echo no)"
chk "  and that host published its own report" 1 \
    "$(pg_exec "SELECT count(*) FROM node_status WHERE host_id='$SELF' AND reported_at > 0 AND report LIKE '%\"conninfo_hosts\"%';" | tr -d ' ')"
chk "an auditor cannot read it (403)" 403 "$(code_of /dev/null -b audit.cj "$URL/api/replication")"

# A second host of the pair, reporting the silent failures docs/high-availability.md describes: no PG_BIND,
# a one-host conninfo, a CA key and a credential key missing from its token, and a disabled
# subscription. And a third that stopped reporting twenty minutes ago.
RNOW=$(date +%s)
REPORT_B='{"at":'"$RNOW"',"pg_bind":"","standby_of":"10.0.0.1","p11_tls":true,"database":{"connected_host":"10.0.0.1","conninfo_hosts":["10.0.0.1"],"state":{"in_recovery":false,"replication":[],"slots":[],"subscriptions":[{"name":"sub_b_from_c","enabled":false,"worker":false,"apply_errors":2,"sync_errors":0}]},"probes":[]},"token":{"readable":true},"cas":[{"id":"ca-global","object":"cakey","key":"missing"}],"credentials":[{"prefix":"ocsp-ra","name":"OCSP responder","issued":true,"object":"ocsp-ra","key":"missing"}]}'
pg_exec "INSERT INTO node_status(host_id, dc_id, reported_at, report) VALUES('peer-b', '', $RNOW, '$REPORT_B');" >/dev/null
pg_exec "INSERT INTO node_status(host_id, dc_id, reported_at, report) VALUES('peer-c', '', $((RNOW - 1200)), '{}');" >/dev/null
curl -s -b admin.cj "$URL/api/replication" -o repl2.json
has(){ grep -qF -- "$1" repl2.json && echo yes || echo no; }
chk "every reported host is listed" yes "$(has '"hostId":"peer-b"')"
chk "warning: PG_BIND unset on a pair host"          yes "$(has 'PG_BIND is not set')"
chk "warning: a one-host PG_CONNINFO"               yes "$(has 'names only one database host')"
chk "warning: a CA key missing from a host's token" yes "$(has "has no key for CA 'ca-global'")"
chk "warning: a credential key missing"             yes "$(has 'has no key for the OCSP responder credential')"
chk "warning: PG_TLS_CA_ID unset"                   yes "$(has 'PG_TLS_CA_ID is not set')"
chk "warning: no standby streaming"                 yes "$(has 'no standby is streaming')"
chk "warning: a disabled subscription"              yes "$(has 'subscription sub_b_from_c is disabled')"
chk "warning: subscription errors"                  yes "$(has 'has recorded 2 apply')"
chk "warning: a host that stopped reporting"        yes "$(has 'has not reported for 20 minutes')"

# ── "list this host first" must recognise the loopback ────────────────────────────────────
#
# ⚠️ THE RULE IS "THIS HOST FIRST", AND THE CHECK COMPARED NAMES. `127.0.0.1` is not the
# string `fastpki-node-0`, so a Kubernetes server whose conninfo starts with the loopback — which
# IS this host, in the strongest possible form — warned on every healthy deployment, for ever.
# The remedy it gave was also wrong: the loopback entry is what lets a pod reach its own
# database when cluster DNS is down, and every pod shares one PG_CONNINFO from a ConfigMap, so
# `127.0.0.1` is the only spelling that means "this host" on all of them at once.
#
# A warning that is always present teaches operators to skim the page where the real ones are.
RNOW2=$(date +%s)
LOOP_DB='{"connected_host":"127.0.0.1","conninfo_hosts":["127.0.0.1","fastpki-node-0","fastpki-node-1"],"state":{"in_recovery":false,"replication":[],"slots":[],"subscriptions":[]},"probes":[{"host":"fastpki-node-0","ok":true,"verifies":true}]}'
PEER_DB='{"connected_host":"fastpki-node-1","conninfo_hosts":["fastpki-node-1","fastpki-node-0"],"state":{"in_recovery":false,"replication":[],"slots":[],"subscriptions":[]},"probes":[{"host":"fastpki-node-0","ok":true,"verifies":true}]}'
pg_exec "INSERT INTO node_status(host_id, dc_id, reported_at, report) VALUES('loop-a', 'dcl', $RNOW2,
  '{\"at\":$RNOW2,\"pg_bind\":\"fastpki-node-0\",\"p11_tls\":false,\"database\":$LOOP_DB,\"token\":{\"readable\":true}}');" >/dev/null
pg_exec "INSERT INTO node_status(host_id, dc_id, reported_at, report) VALUES('peer-first', 'dcl', $RNOW2,
  '{\"at\":$RNOW2,\"pg_bind\":\"fastpki-node-0\",\"p11_tls\":false,\"database\":$PEER_DB,\"token\":{\"readable\":true}}');" >/dev/null
curl -s -b admin.cj "$URL/api/replication" -o repl_loop.json
chk "a loopback first entry is already 'this host first'" no \
    "$(grep -qF 'PG_CONNINFO lists 127.0.0.1 first' repl_loop.json && echo yes || echo no)"
# CONTROL: a genuinely foreign host listed first still warns, so the check above is the
# loopback being recognised and not the warning having been removed.
chk "  but a peer listed first still warns" yes \
    "$(grep -qF 'PG_CONNINFO lists fastpki-node-1 first' repl_loop.json && echo yes || echo no)"

# ⚠️ A LIFETIME COUNTER IS NOT AN ALARM. pg_stat_subscription_stats counts from when the
# subscription was created, so a fault fixed hours ago warned for ever with nothing to tell it
# from one happening now. Each report carries when the counts last moved; two hosts in one data
# center report the SAME counters, because a standby is a physical copy of the catalogue.
STALE=$((RNOW - 3600))
SUBX='{"name":"sub_x_from_y","enabled":true,"worker":true,"apply_errors":0,"sync_errors":115,"errors_stable_since":'"$STALE"'}'
for h in peer-d peer-e; do
  pg_exec "INSERT INTO node_status(host_id, dc_id, reported_at, report) VALUES('$h', 'dcx', $RNOW,
    '{\"at\":$RNOW,\"p11_tls\":false,\"database\":{\"connected_host\":\"10.0.0.9\",\"conninfo_hosts\":[\"10.0.0.9\"],\"state\":{\"in_recovery\":false,\"replication\":[],\"slots\":[],\"subscriptions\":[$SUBX]}},\"token\":{\"readable\":true}}');" >/dev/null
done
curl -s -b admin.cj "$URL/api/replication" -o repl3.json
chk "errors that stopped an hour ago read as history" yes \
    "$(grep -qF 'none in the last 60 minutes' repl3.json && echo yes || echo no)"
chk "  and are not reported as failing now" no \
    "$(grep -qF 'sub_x_from_y has recorded 0 apply and 115 sync errors, and the count is still rising' repl3.json && echo yes || echo no)"
chk "  said once for the data center, not once per host" 1 \
    "$(grep -o 'subscription sub_x_from_y has recorded' repl3.json | wc -l | tr -d ' ')"

chk "key sync for a host that has not reported -> 404" 404 \
    "$(code_of /dev/null -b admin.cj -X POST "$URL/api/replication/key-sync?host=nosuch")"
# ⚠️ REFUSED FOR HAVING NO TOKEN TRANSPORT, NOT FOR BEING A PRIMARY. A primary can be the host
# missing a key its standby minted, so the one host with nothing to sync is one that has
# no tunnel to copy over — which is this console, started without P11_TLS.
chk "key sync for a host with no token transport -> 409" 409 \
    "$(code_of ks.json -b admin.cj -X POST "$URL/api/replication/key-sync?host=$SELF")"
chk "  saying why" yes "$(grep -q 'P11_TLS off' ks.json && echo yes || echo no)"
chk "an auditor cannot request one (403)" 403 \
    "$(code_of /dev/null -b audit.cj -X POST "$URL/api/replication/key-sync?host=peer-b")"
chk "key sync for a standby -> 202" 202 \
    "$(code_of /dev/null -b admin.cj -X POST "$URL/api/replication/key-sync?host=peer-b")"
chk "  recorded as a request for that host, by who asked" "1|admin" \
    "$(pg_exec "SELECT count(*)||'|'||max(requested_by) FROM node_sync_requests WHERE host_id='peer-b' AND requested_at > 0;" | tr -d ' ')"
chk "  and audited" 1 \
    "$(pg_exec "SELECT count(*) FROM audit_log WHERE action='replication_key_sync_requested' AND target='peer-b';" | tr -d ' ')"

# ⚠️ THE HOST ITSELF RUNS IT. A second console, standing in for a standby host (its own PG_BIND,
# STANDBY_OF and P11_TLS), picks up a request made through the FIRST console and runs
# `fastpki-ca key sync` there. Nothing listens on the peer address, so the outcome does not
# matter here — that the request is claimed, run, and its result and output recorded does.
grep -v '^WEB_PORT=' bootstrap.conf > web3.conf; echo "WEB_PORT=$((PORT+2))" >> web3.conf
PG_BIND=10.9.9.9 STANDBY_OF=127.0.0.1 P11_TLS=on "$WEB" --config web3.conf >web3.log 2>&1 & W3P=$!
trap 'pg_cleanup; kill $P ${W3P:-} 2>/dev/null' EXIT
for _ in $(seq 1 40); do
  [ "$(pg_exec "SELECT count(*) FROM node_status WHERE host_id='10.9.9.9' AND reported_at > 0;" | tr -d ' ')" = 1 ] && break
  sleep 0.5
done
chk "the standby's console published its own row" 1 \
    "$(pg_exec "SELECT count(*) FROM node_status WHERE host_id='10.9.9.9' AND report LIKE '%\"standby_of\":\"127.0.0.1\"%';" | tr -d ' ')"
chk "key sync requested through the OTHER console -> 202" 202 \
    "$(code_of /dev/null -b admin.cj -X POST "$URL/api/replication/key-sync?host=10.9.9.9")"
KS=""
for _ in $(seq 1 90); do
  KS=$(pg_exec "SELECT key_sync FROM node_status WHERE host_id='10.9.9.9';")
  printf '%s' "$KS" | grep -q '"state":"finished"' && break
  sleep 1
done
chk "the standby ran it and recorded the result" yes \
    "$(printf '%s' "$KS" | grep -q '"state":"finished"' && echo yes || echo no)"
chk "  with fastpki-ca's output" yes "$(printf '%s' "$KS" | grep -q '"output":"[^"]' && echo yes || echo no)"
chk "  answering the request it claimed" 1 \
    "$(pg_exec "SELECT count(*) FROM node_status n JOIN node_sync_requests q USING (host_id) WHERE host_id='10.9.9.9' AND n.key_sync_request = q.requested_at;" | tr -d ' ')"
[ "$(printf '%s' "$KS" | grep -c '"state":"finished"')" = 1 ] || { echo "    --- web3.log ---"; tail -8 web3.log; }
kill $W3P 2>/dev/null; wait $W3P 2>/dev/null

PAGE=$(curl -s -b admin.cj "$URL/")
chk "the console has a Replication tab, for admin only" yes \
    "$(echo "$PAGE" | grep -q 'data-tab="replication"' && echo "$PAGE" | grep -q "replication: \['\*:\*'\]" && echo yes || echo no)"
chk "  with Sync keys now wired to the request route" yes \
    "$(echo "$PAGE" | grep -q "fetch('/api/replication/key-sync?host=' + encodeURIComponent(b.dataset.sync)" && echo yes || echo no)"
# ⚠️ NO PLATFORM IS SPECIAL-CASED. Kubernetes once ran one token for the whole cluster, and the
# page said so with a "Kubernetes cluster" pill and a "not applicable" key sync. Every path now
# has a token per server, so a platform branch here would describe a difference that no
# longer exists — and would tell a Kubernetes operator their standby cannot be synced.
chk "  and no platform gets a key-sync branch of its own" no \
    "$(echo "$PAGE" | grep -qE "platform === 'kubernetes'|one token for the cluster" && echo yes || echo no)"

echo "=== the search box is shown only where it actually searches ==="
# One box in the TOPBAR served all nineteen pages, and hiding the controls row — which the
# full-bleed pages do — never hid it, because it is not in that row. It filtered on seven
# pages. On the rest, typing did nothing at all under a placeholder promising certificates:
# CAs, HSM, Dashboard, Profiles, Roles, Domains, Notifications, Backup, Updates and Client
# configs paint their own panels and never read it, and Users/Computers have their own
# filter box beside it.
#
# ONE table now decides both whether the box is shown and what it says. ⚠️ Every entry must
# name a page whose renderer really reads the box — adding a key is what makes the control
# appear, so an entry for a page that ignores it recreates this exact defect.
curl -s "$URL/" -o searchpage.html
sp(){ grep -qF -- "$1" searchpage.html && echo yes || echo no; }
chk "fixture: the console page was served"        yes "$(sp 'id="q"')"
chk "one table decides where search is offered"   yes "$(sp 'const SEARCHABLE = {')"
# ⚠️ EXTRACT THE TABLE AND ASK INSIDE IT. A bare `  cas:` also matches the column map and
# the per-tab capability map, both of which legitimately carry a `cas` key — the first
# version of this passed "searchable" for pages that are not in this table at all.
awk '/const SEARCHABLE = \{/,/^\};/' searchpage.html > searchable.js
chk "fixture: the table was extracted"            yes "$([ -s searchable.js ] && echo yes || echo no)"
st(){ grep -qE "^  $1: +'" searchable.js && echo yes || echo no; }
for t in certs compliance audit endpoints config discovered templates; do
  chk "  $t is searchable"                        yes "$(st "$t")"
done
# The pages he named as inert must NOT be in the table.
for t in cas hsm profiles roles domains notifications backup updates dashboard clientcfg users computers; do
  chk "  $t is not offered a search box"          no  "$(st "$t")"
done
chk "visibility is driven by that table"          yes "$(sp "const searchable = SEARCHABLE[tab];")"
# ⚠️ style.display, NOT the `hidden` attribute: `.search-wrap` sets display:flex and an
# author rule beats the user agent's [hidden]{display:none}, so `hidden` would leave the
# box on screen while the code reads as if it had hidden it.
chk "  and hides the WRAPPER via style.display"   yes \
    "$(sp "document.querySelector('.search-wrap').style.display = searchable ? 'flex' : 'none';")"
chk "  a term is cleared when the box goes away"  yes "$(sp "if (!searchable) qbox.value = '';")"
# The handler must consult the SAME table, or the two drift — which is what happened: the
# handler carried its own hardcoded list naming three pages that cannot search.
chk "typing consults the same table"              yes "$(sp 'if (!SEARCHABLE[tab]) return;')"
# ⚠️ ABSENCE, AND BOTH WERE PRESENT BEFORE: the hardcoded list matched once in the previous
# revision and the certificate-flavoured placeholder twice (the static attribute and the
# updateChrome default). Neither name is used anywhere else.
chk "  the hardcoded page list is gone"           no  "$(sp "['certs','cas','users','computers'].includes(tab)")"
chk "  and the one-size placeholder with it"      no  "$(sp 'Search certs, serials, domains')"

echo "=== every page that shows the row count writes one ==="
# The count sits in the shared controls row and NOTHING clears it between pages, so a page
# that does not write it displays whatever the previous page left there — Roles showed
# "12 profile(s)" over a table of roles, and HSM keys and Domains did the same.
#
# ⚠️ A CENSUS, NOT A LIST OF SITES. Checking the three that were broken would pass forever
# while the next page added repeats it, which is how this shape keeps coming back. This
# asks the question of EVERY renderer that paints its own panel, so a new one fails here
# until it writes a count.
for r in renderRoles renderDomains renderHsmKeys renderProfiles renderTemplates \
         renderCAs renderUsers renderNotify renderBackup renderUpdates renderReplication; do
  chk "  $r reports its row count"                yes \
      "$(awk "/^(async )?function $r\(/,/^\}/" searchpage.html | grep -q "getElementById('rowcount')" \
         && echo yes || echo no)"
done

echo "=== the default bind serves IPv6, and says which address it took ==="
# ⚠️ WHAT THIS CATCHES. Every listener used to default to 0.0.0.0, the IPv4 wildcard, so a
# node on an IPv6 network started, logged "listening", reported itself healthy — and
# answered no client at all. The failure is invisible from the server side, which is why it
# is asserted from a client socket rather than by reading the config.
#
# A SECOND console on its own port, because the one above is deliberately pinned to
# 127.0.0.1 for the rest of the suite.
V6PORT=$((PORT+7))
sed -e '/^WEB_BIND=/d' -e "s/^WEB_PORT=.*/WEB_PORT=$V6PORT/" -e 's/^LOG_LEVEL=.*/LOG_LEVEL=info/' \
    bootstrap.conf > v6.conf
"$WEB" --config v6.conf >v6.log 2>&1 & PV6=$!
sleep 1
trap 'pg_cleanup; kill $P ${W3P:-} $PV6 2>/dev/null' EXIT
# Both branches assert something: a host with an IPv6 stack must answer on ::1, and one
# without must say out loud that it fell back — silence is the bug either way.
if ip -6 addr show lo 2>/dev/null | grep -q '::1' || ifconfig lo0 2>/dev/null | grep -q '::1'; then
    chk "the console answers on ::1 with no WEB_BIND set" 200 \
        "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://[::1]:$V6PORT/")"
    chk "  and on IPv4 through the same dual-stack socket" 200 \
        "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$V6PORT/")"
    chk "  and the log names the address it bound" yes \
        "$(grep -q 'listening on ::' v6.log && echo yes || echo no)"
else
    chk "with no IPv6 stack it falls back to IPv4 and says so" yes \
        "$(grep -q 'no usable IPv6 stack' v6.log && echo yes || echo no)"
    chk "  and still serves IPv4" 200 \
        "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$V6PORT/")"
fi
# ⚠️ THE LAST TRAP STAYS A SUPERSET of every earlier one — bash REPLACES traps rather than
# stacking them, so narrowing it here would silently drop the cleanups the earlier ones
# promised (tests/trap_cleanup.sh fails the build on exactly that). The second console is
# killed now; the trap keeps naming it because killing a dead pid is harmless and a trap
# that forgets a process is not.
kill $PV6 2>/dev/null || true

echo "=== logout invalidates the session ==="
curl -s -b admin.cj -X POST "$URL/api/logout" >/dev/null
chk "after logout the cookie is rejected (401)" 401 "$(curl -s -o /dev/null -w '%{http_code}' -b admin.cj "$URL/api/certs")"

echo
echo "=== WEB: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
