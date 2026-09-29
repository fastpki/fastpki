#!/usr/bin/env bash
# '#' is a legal character in a config VALUE, and every reader of the file must agree.
#
# ── Why this exists ──────────────────────────────────────────────────────────────
#
# The file parser stripped comments by cutting at the FIRST '#' anywhere on the line,
# including one inside a value. The value most likely to contain one is a password inside
# the database connection string — the installer generates alphanumeric passwords, so a
# generated one never trips it, but an operator typing their own hits it immediately. The
# connection then fails with a credentials error that says nothing about the config file
# having been truncated, which is the worst possible way for this to surface.
#
# ⚠️ AND THE READERS DISAGREED, WHICH IS THE HALF A ONE-SITE FIX WOULD HAVE LEFT BEHIND.
# The console's config-file editor already treated '#' as a comment only at the START of a
# line, so it displayed and preserved `a#b` faithfully — while the server read the same
# file and got `a`. One file, two parsers, opposite answers, and nothing compared them.
#
# ⚠️ AND IT ASKS THE PRODUCT, NOT A RE-IMPLEMENTATION. Every value below is read back
# through something the deployment actually runs — the console's effective-config endpoint
# and the config CLI — rather than a shell parser written here, which would only prove
# that two of my own parsers agree.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
W="$(mktemp -d)"; cd "$W"; WPORT=18262
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

CFG="$ROOT/build/fastpki-config"; WEB="$ROOT/build/fastpki-web"
pg_setup config_value_hash
P=
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
seed_web_user boss bosspw admin

echo "=== the case that motivated this: a '#' inside the connection string ==="
# ⚠️ THE SHARPEST FORM OF THIS TEST IS THAT THE SERVER STARTS AT ALL. The '#' is placed
# BEFORE the rest of the connection keywords, so a parser that cuts at it leaves a
# conninfo with no database to connect to — exactly what happens to an operator whose
# password contains one. This does not assert a string; it asserts that the product can
# still reach its database, which is the thing that was actually broken.
cat > srv.conf <<EOF
PG_CONNINFO=application_name=pki#ops $PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$WPORT
WEB_ALLOW_REVOKE=true
PKI_DNS=kept.example   # this trailing part must not survive
BASE_URL=https://pki.example.test/a#frag
LOG_LEVEL=err
EOF
# ⚠️ WITH THE PG* ENVIRONMENT CLEARED, AND THAT IS NOT TIDINESS. The harness exports
# PGHOST/PGPORT/PGDATABASE so psql can reach its throwaway cluster, and libpq falls back to
# them for anything the connection string does not say. So a truncated conninfo still
# connected, and this assertion passed just as happily against the broken parser — it was
# decoration until the environment was taken away. Measured, not assumed: with the old
# parser and these unset, the console cannot start.
env -u PGHOST -u PGPORT -u PGDATABASE -u PGUSER -u PGPASSWORD \
    "$WEB" --config srv.conf >web.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "srv.conf" WEB_PORT "$P" || true
chk "the console starts with a '#' inside PG_CONNINFO" yes \
    "$(kill -0 $P 2>/dev/null && echo yes || echo no)"
if ! kill -0 $P 2>/dev/null; then
    echo "       --- fastpki-web log ---"; sed 's/^/       /' web.log | tail -5
fi
U="http://127.0.0.1:$WPORT"
curl -s -c cj.txt -d 'username=boss&password=bosspw' "$U/api/login" >/dev/null 2>&1
CFGJSON=$(curl -s -b cj.txt "$U/api/config" 2>/dev/null)
# ⚠️ FIXTURE FIRST. Every assertion below reads a value out of this JSON; if the request
# failed, each one compares two empty strings and the suite goes green having measured
# nothing at all.
chk "fixture: the effective config was served" yes \
    "$(printf '%s' "$CFGJSON" | grep -q 'PKI_DNS' && echo yes || echo no)"
# The catalog is a list of {section,key,value,desc,owner} objects, and several suites
# already depend on `key` being immediately followed by `value` — so read the pair, not a
# bare "KEY":"…" which does not exist in this shape.
jval(){ printf '%s' "$CFGJSON" | grep -o "\"key\":\"$1\",\"value\":\"[^\"]*\"" | head -1 \
        | sed 's/.*"value":"//; s/"$//'; }

echo "=== a '#' inside a value survives, a real comment still does not ==="
chk "a value containing '#' is not truncated" "https://pki.example.test/a#frag" "$(jval BASE_URL)"
# The other half: a genuine trailing comment must still be removed, or this would have
# "fixed" the bug by simply never stripping comments.
chk "a comment after whitespace is still stripped" "kept.example" "$(jval PKI_DNS)"

echo "=== the config CLI reads the same file the same way ==="
# ⚠️ THIS IS THE ASSERTION THAT CATCHES A ONE-SITE FIX. The importer is a SECOND parser
# over the same file, in a different binary. It had the same defect, and fixing only the
# server's copy would leave an operator's imported password silently truncated in the DB —
# where it then outlives the file.
cat > imp.conf <<EOF
EMAIL_FROM=cli#ops@example.test
PKI_DNS=cli.example    # trailing comment
EOF
"$CFG" --config srv.conf import imp.conf >/dev/null 2>&1
chk "the CLI keeps the '#' in an imported value" "cli#ops@example.test" \
    "$("$CFG" --config srv.conf get EMAIL_FROM 2>/dev/null)"
chk "  and still strips a real comment"          "cli.example" \
    "$("$CFG" --config srv.conf get PKI_DNS 2>/dev/null)"

echo "=== a commented-out setting stays disabled ==="
# The leading-'#' case is the one the rule must NOT break: it is how an operator disables
# a setting, and treating it as a value would silently switch things back on.
cat > lead.conf <<EOF
EMAIL_FROM=live@example.test
#EMAIL_FROM=disabled@example.test
EOF
"$CFG" --config srv.conf import lead.conf >/dev/null 2>&1
chk "a commented-out line is not read as a value" "live@example.test" \
    "$("$CFG" --config srv.conf get EMAIL_FROM 2>/dev/null)"

echo "=== a quoted value may contain a '#' even after a space ==="
cat > q.conf <<EOF
EMAIL_FROM="a # b"
EOF
"$CFG" --config srv.conf import q.conf >/dev/null 2>&1
chk "quotes are stripped and the '#' inside is kept" "a # b" \
    "$("$CFG" --config srv.conf get EMAIL_FROM 2>/dev/null)"

echo "=== nobody cuts at the first '#' any more ==="
# A census on top of the behavioural checks: the two readers above are exercised for real,
# but a THIRD reader added later would not be, and this is what fails on the day it lands.
LIB="$ROOT/src/lib/config.cpp"; TOOL="$ROOT/src/tools/config.cpp"; NOT="$ROOT/src/tools/notify.cpp"
chk "fixture: all three sources were read" yes \
    "$([ -s "$LIB" ] && [ -s "$TOOL" ] && [ -s "$NOT" ] && echo yes || echo no)"
raw=""
for f in "$LIB" "$TOOL" "$NOT"; do
    grep -qE "find\('#'\)" "$f" && raw="$raw $(basename "$f")"
done
chk "no KEY=value reader cuts at the first '#'" "" "$raw"
# ⚠️ CONTROL for that grep: it must be able to match the thing it looks for, or "clean" and
# "my expression is wrong" are indistinguishable. Point it at a file that legitimately
# still contains the pattern — the discovery targets list, which is a plain list of hosts
# and not a KEY=value file, so it is out of scope for this rule and keeps the old form.
chk "CONTROL: the expression does match where the form remains" yes \
    "$(grep -qE "find\('#'\)" "$ROOT/src/tools/discover.cpp" && echo yes || echo no)"

echo
echo "=== CONFIG VALUE HASH: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
