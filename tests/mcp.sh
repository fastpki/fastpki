#!/usr/bin/env bash
# MCP server — fastpki-mcp. Read-only PKI inventory over the MCP
# stdio transport (newline-delimited JSON-RPC 2.0). Each check pipes one request
# to stdin and asserts on the single response line (the server is stateless, so
# tools/call works without a prior initialize).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
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
MCP="$ROOT/build/fastpki-mcp"
AUDIT="$ROOT/build/fastpki-audit"
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }

pg_setup mcp
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
NOW=$(date +%s)
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint) VALUES('a1',0,0,0,$((NOW-86400)),$((NOW+86400)),'CN=web.host','alice','web.host','ff11');"
pg_exec "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\",\"notBefore\",\"notAfter\",subject,owner,cn,fingerprint) VALUES('b2',-1,1,$NOW,$((NOW-86400)),$((NOW+86400)),'CN=gone.host','bob','gone.host','ff22');"
pg_exec "INSERT INTO discovered_certs(target,serial,subject,issuer,\"notBefore\",\"notAfter\",\"keyAlgo\",\"keyBits\",\"sigAlgo\",sans,fingerprint,\"selfSigned\",flags,\"discoveredAt\") VALUES('10.0.0.9:443','c3','CN=legacy','CN=legacy',$((NOW-86400)),$((NOW+86400)),'RSA',1024,'sha1WithRSAEncryption','','ab',1,'weak_key',$NOW);"
cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
LOG_LEVEL=err
EOF
"$AUDIT" --config bootstrap.conf append pki_lifecycle cert_issued alice success a1 "cn=web.host" >/dev/null

# call <json-request>  -> single response line on stdout
call() { printf '%s\n' "$1" | "$MCP" --config bootstrap.conf 2>/dev/null; }

echo "=== initialize / capabilities ==="
R=$(call '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
echo "$R" | grep -q '"serverInfo"' && a=yes || a=no
chk "initialize returns serverInfo" yes "$a"
echo "$R" | grep -q 'fastpki-mcp' && a=yes || a=no
chk "serverInfo names the server" yes "$a"
echo "$R" | grep -q '"protocolVersion"' && a=yes || a=no
chk "advertises a protocolVersion" yes "$a"

echo "=== tools/list ==="
T=$(call '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
for t in list_certificates get_certificate list_expiring list_discovered list_audit summary; do
  echo "$T" | grep -q "\"$t\"" && a=yes || a=no
  chk "tools/list advertises $t" yes "$a"
done
echo "$T" | grep -q '"inputSchema"' && a=yes || a=no
chk "tools carry an inputSchema" yes "$a"

echo "=== tools/call: inventory ==="
C=$(call '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_certificates","arguments":{"limit":10}}}')
echo "$C" | grep -q 'web.host' && a=yes || a=no
chk "list_certificates returns the valid cert" yes "$a"
echo "$C" | grep -q 'gone.host' && a=yes || a=no
chk "list_certificates returns the revoked cert" yes "$a"
echo "$C" | grep -q 'revoked' && a=yes || a=no
chk "status mapped to text (revoked)" yes "$a"

echo "=== tools/call: get_certificate ==="
G=$(call '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_certificate","arguments":{"serial":"A1"}}}')
echo "$G" | grep -q 'web.host' && a=yes || a=no
chk "get_certificate resolves serial (case-insensitive)" yes "$a"
echo "$G" | grep -q 'revocationReason' && a=yes || a=no
chk "get_certificate includes detail fields" yes "$a"
GN=$(call '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_certificate","arguments":{"serial":"deadbeef"}}}')
echo "$GN" | grep -q 'no such serial' && a=yes || a=no
chk "unknown serial reported cleanly" yes "$a"

echo "=== tools/call: expiring / discovered / audit / summary ==="
E=$(call '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"list_expiring","arguments":{"days":3650}}}')
echo "$E" | grep -q 'daysLeft' && a=yes || a=no
chk "list_expiring reports daysLeft" yes "$a"
D=$(call '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"list_discovered"}}')
echo "$D" | grep -q '10.0.0.9:443' && a=yes || a=no
chk "list_discovered returns the endpoint" yes "$a"
A=$(call '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"list_audit"}}')
echo "$A" | grep -q 'cert_issued' && a=yes || a=no
chk "list_audit returns the event" yes "$a"
S=$(call '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"summary","arguments":{}}}')
echo "$S" | grep -q 'discovered' && a=yes || a=no
chk "summary carries the headline keys" yes "$a"

echo "=== write tools gated by MCP_ALLOW_WRITE ==="
# default (read-only): revoke_certificate is neither advertised nor callable
echo "$T" | grep -q 'revoke_certificate' && a=yes || a=no
chk "revoke tool hidden when writes disabled" no "$a"
RD=$(call '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"revoke_certificate","arguments":{"serial":"a1"}}}')
echo "$RD" | grep -q 'writes are disabled' && a=yes || a=no
chk "revoke refused when writes disabled" yes "$a"
chk "cert still valid after refused revoke" 0 "$(pg_exec "SELECT status FROM certs WHERE serial='a1';")"
# enable writes -> revoke works + is audited
cat > pkiw.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
MCP_ALLOW_WRITE=true
LOG_LEVEL=err
EOF
callw() { printf '%s\n' "$1" | "$MCP" --config pkiw.conf 2>/dev/null; }
echo "$(callw '{"jsonrpc":"2.0","id":21,"method":"tools/list"}')" | grep -q 'revoke_certificate' && a=yes || a=no
chk "revoke tool advertised when writes enabled" yes "$a"
# The one reason rule: removeFromCRL is what a delta CRL says about a released hold, never a
# revocation, and a value outside RFC 5280 would land in the CRL as it is.
for bad in 8 10 42; do
  RB=$(callw '{"jsonrpc":"2.0","id":23,"method":"tools/call","params":{"name":"revoke_certificate","arguments":{"serial":"a1","reason":'"$bad"'}}}')
  chk "revoke tool refuses reason $bad" yes \
      "$(echo "$RB" | grep -q '"isError": *true' && echo "$RB" | grep -q 'revocation reason' && echo yes || echo no)"
done
chk "  and the cert is still valid" 0 "$(pg_exec "SELECT status FROM certs WHERE serial='a1';")"
RW=$(callw '{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"revoke_certificate","arguments":{"serial":"A1","reason":1}}}')
echo "$RW" | grep -q 'revoked' && a=yes || a=no
chk "revoke tool returns a revoked result" yes "$a"
chk "cert is revoked in the DB (status -1)" -1 "$(pg_exec "SELECT status FROM certs WHERE serial='a1';")"
chk "revocation audited (mcp_cert_revoked)" 1 "$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='mcp_cert_revoked' AND target='a1';")"

echo "=== error handling ==="
M=$(call '{"jsonrpc":"2.0","id":10,"method":"bogus/method"}')
echo "$M" | grep -q 'method not found' && a=yes || a=no
chk "unknown method -> -32601" yes "$a"
UT=$(call '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"nope","arguments":{}}}')
echo "$UT" | grep -q '"isError":true' && a=yes || a=no
chk "unknown tool -> isError result" yes "$a"
PE=$(printf 'not json\n' | "$MCP" --config bootstrap.conf 2>/dev/null)
echo "$PE" | grep -q -- '-32700' && a=yes || a=no
chk "malformed line -> parse error" yes "$a"

echo
echo "=== MCP: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
