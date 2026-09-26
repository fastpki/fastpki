#!/usr/bin/env bash
# Inventory per-column filters: the console Inventory (certs) tab has
# a filter row under the header — one control per column. Text columns (CN, Serial,
# Owner, Expires) match a case-insensitive substring; low-cardinality columns (CA,
# Role, Status) are dropdowns built from the loaded rows. Filters AND together,
# refine the loaded set client-side (they stack with the server-side search box and
# CA pivot), and a "clear filters" link resets them.
#
# This is a frontend feature with NO server contract (the filtering runs in the
# browser), so the shell tier guards the *served markup*: it asserts the builder +
# filter logic are shipped and wired, which would otherwise regress silently (the
# console HTML is one big embedded string). The behaviour itself was verified in a
# real browser before deploy (§3e), and — where `node` is available (dev + CI) — an
# OPTIONAL block below re-checks the pure filter logic against fixtures. The block
# SKIPs cleanly when node is absent, so the suite stays shell-only and autonomous.
#
# Self-contained (§3d): ephemeral Postgres via pg_helpers, own port, temp dir,
# SKIPs cleanly when no Postgres is reachable. Asserts on the real bytes served by
# a running fastpki-web.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
export OPENSSL_CONF=${OPENSSL_CONF:-/etc/ssl/openssl.cnf}
WEB="$ROOT/build/fastpki-web"
W="$(mktemp -d)"; cd "$W"; PORT=18262
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
present(){ grep -qF -- "$1" index.html && echo yes || echo no; }

# Need a reachable Postgres; SKIP (not FAIL) when absent so the suite is portable.
if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "SKIP: no Postgres reachable at $PGHOST:$PGPORT (set PGHOST/PGPORT/PGUSER/PGPASSWORD)"; exit 0
fi

pg_setup inventory_filters
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
cat > web.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
WEB_ALLOW_REVOKE=true
LOG_LEVEL=err
EOF
"$WEB" --config web.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "web.conf" WEB_PORT "$P" || true
if ! kill -0 $P 2>/dev/null; then echo "fastpki-web died:"; cat web.log; exit 1; fi
U="http://127.0.0.1:$PORT"
curl -s "$U/" -o index.html
chk "index page served" yes "$([ -s index.html ] && echo yes || echo no)"

echo "=== the Inventory per-column filter row is shipped + wired ==="
chk "certFilters state present"          yes "$(present 'let certFilters')"
chk "filter-kind map present"            yes "$(present 'CERT_FILTER_KIND')"
chk "applyCertFilters() present"         yes "$(present 'function applyCertFilters')"
chk "certFiltersActive() present"        yes "$(present 'function certFiltersActive')"
chk "refilterCerts() (body-only) present" yes "$(present 'function refilterCerts')"
chk "shared body painter present"        yes "$(present 'function paintTableBody')"
chk "filter row rendered on certs"       yes "$(present 'class="filterrow"')"
chk "per-column filter controls (data-fk)" yes "$(present 'data-fk=')"
chk "clear-filters affordance present"   yes "$(present 'clearfilters')"

echo "=== CA / Status are dropdowns; the rest are substring text boxes ==="
kindrow=$(grep -o "CERT_FILTER_KIND = {[^}]*}" index.html)
chk "CA column is a dropdown"      yes "$(echo "$kindrow" | grep -q "caInstance: 'select'" && echo yes || echo no)"
chk "Status column is a dropdown"  yes "$(echo "$kindrow" | grep -q "statusText: 'select'" && echo yes || echo no)"
# A certificate carries no role — nothing stores or returns one — so the column was always empty.
chk "no Role column on the Inventory" no \
    "$(grep -q "\['owner','Owner'\],\['role','Role'\]" index.html && echo yes || echo no)"
# CN/serial/owner/notAfter are NOT in the kind map -> they render as text boxes.
chk "CN column is not a dropdown"     no  "$(echo "$kindrow" | grep -q 'cn:' && echo yes || echo no)"
chk "Expires column is not a dropdown" no "$(echo "$kindrow" | grep -q 'notAfter:' && echo yes || echo no)"

echo "=== filters refine client-side, so the server /api/certs contract is unchanged ==="
# The Inventory data still comes from the same server list endpoint; the filters
# operate on the loaded set, so this endpoint must keep answering as before.
curl -s -c cj -X POST "$U/api/users" -d 'username=root1&password=root1pass&role=admin' >/dev/null
curl -s -c cj -X POST "$U/api/login" -d 'username=root1&password=root1pass' >/dev/null
chk "/api/certs still answers 200" 200 "$(curl -s -o /dev/null -w '%{http_code}' -b cj "$U/api/certs?limit=10")"

# ── OPTIONAL behaviour check: exercise the pure filter logic under node ──────────
# node is not a required test dependency (the suite is shell-only). Where it exists
# (dev + CI) we extract the three pure functions from the SERVED bytes and assert
# the real filtering semantics: substring for text, exact for dropdowns, AND across
# columns, and clear. Absent node, this block SKIPs and the structural guards stand.
if command -v node >/dev/null 2>&1; then
  echo "=== behaviour: applyCertFilters semantics (via node, on the served logic) ==="
  cat > check.js <<'JS'
const fs = require('fs');
const html = fs.readFileSync('index.html', 'utf8');
const grab = (re, name) => { const m = html.match(re); if (!m) { console.error('EXTRACT_FAIL:' + name); process.exit(2); } return m[0]; };
const kind  = grab(/const CERT_FILTER_KIND = \{[^}]*\};/, 'CERT_FILTER_KIND');
const activ = grab(/function certFiltersActive\(\)[^\n]*\n/, 'certFiltersActive');
const apply = grab(/function applyCertFilters\(list\) \{[\s\S]*?\n\}/, 'applyCertFilters');
const data = [
  {serial:'01', cn:'web01.example.com', caInstance:'issuing-ca', owner:'alice', statusText:'valid'},
  {serial:'02', cn:'web02.example.com', caInstance:'issuing-ca', owner:'bob',   statusText:'revoked'},
  {serial:'03', cn:'vpn.example.com',   caInstance:'edge-ca',    owner:'alice', statusText:'valid'},
  {serial:'04', cn:'db.internal',       caInstance:'edge-ca',    owner:'carol', statusText:'expired'}
];
const run = (filters) => {
  const body = 'let certFilters = ' + JSON.stringify(filters) + ';\n' + kind + '\n' + activ + '\n' + apply +
               '\nreturn { active: certFiltersActive(), cns: applyCertFilters(' + JSON.stringify(data) + ').map(o=>o.cn).sort() };';
  return new Function(body)();
};
let ok = 0, bad = 0;
const t = (name, got, want) => { const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g === w) { console.log('  [PASS] ' + name); ok++; } else { console.log('  [FAIL] ' + name + ' got ' + g + ' want ' + w); bad++; } };
t('no filters -> all, inactive',      run({}),                                        { active:false, cns:['db.internal','vpn.example.com','web01.example.com','web02.example.com'] });
t('CN substring "web" -> web01/web02', run({cn:'web'}).cns,                            ['web01.example.com','web02.example.com']);
t('CN substring is case-insensitive',  run({cn:'WEB'}).cns,                            ['web01.example.com','web02.example.com']);
t('Status dropdown exact "valid"',     run({statusText:'valid'}).cns,                  ['vpn.example.com','web01.example.com']);
t('Status exact does NOT substring',   run({statusText:'val'}).cns,                    []);
t('CN AND Status combine',             run({cn:'web', statusText:'valid'}).cns,        ['web01.example.com']);
t('CA dropdown "edge-ca"',             run({caInstance:'edge-ca'}).cns,                ['db.internal','vpn.example.com']);
t('Owner substring "ali"',             run({owner:'ali'}).cns,                         ['vpn.example.com','web01.example.com']);
t('active flag true when a filter set', run({cn:'x'}).active,                          true);
t('empty-string filter is inactive',   run({cn:''}),                                   { active:false, cns:['db.internal','vpn.example.com','web01.example.com','web02.example.com'] });
console.log('NODE_RESULT ' + ok + ' ' + bad);
process.exit(bad === 0 ? 0 : 1);
JS
  node check.js | tee node.out
  nres=$(grep -o 'NODE_RESULT [0-9]* [0-9]*' node.out)
  nfail=$(echo "$nres" | awk '{print $3}')
  nok=$(echo "$nres" | awk '{print $2}')
  if [ -z "$nres" ]; then chk "node behaviour block ran" yes no
  else pass=$((pass+nok)); fail=$((fail+${nfail:-1})); fi
else
  echo "  [SKIP] node not present — behaviour verified in-browser before deploy (§3e); structural guards above stand"
fi

echo
echo "=== INVENTORY FILTERS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
