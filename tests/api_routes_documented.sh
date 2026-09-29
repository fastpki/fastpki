#!/usr/bin/env bash
# Every HTTP route a binary registers must appear in the documentation.
#
# ⚠️ WHY THIS EXISTS. The docs were written by reading the code once and then maintained by
# hand, so a route added later was documented only if somebody remembered. Nothing compared
# the two, and a reader cannot tell a missing endpoint from one that does not exist. Found
# by diffing, all of them live and none of them written down anywhere:
#
#   GET /<ca_id>.crt            the AIA caIssuers target every issued certificate points at
#   GET /<ca_id>/<ski>.p7c      the rekey rollover bundle
#   GET  /.well-known/est/<id>/csrattrs      per-CA, while every other EST operation had its
#   POST /.well-known/est/<id>/serverkeygen  per-CA form documented beside the base one
#   38 console routes, including db-backup/restore, pg-tls, pkcs11/slots, roles,
#                               permissions, foreign-anchors, ldap/users and config/file
#
# It reads files and starts nothing, so it costs a moment.
#
# ⚠️ IT COMPARES EXISTENCE, NOT ACCURACY. A documented route may still describe the wrong
# auth or the wrong status codes; only a person reading it catches that. What this catches is
# the one failure that recurs: adding a route and not writing it down.
#
# ⚠️ LITERAL ROUTES ONLY, AND THAT IS A DELIBERATE FLOOR. Routes are also registered from
# concatenated or config-driven paths (`p + "/new-nonce"` in acme, `cfg.cmp_path` in cmp,
# scep and ms) and as regexes for the per-CA forms. Those cannot be compared by string, so
# they are out of scope here rather than silently counted as covered — the count printed
# below says how many ARE compared, so a change that moves routes out of literal form shows
# up as the number falling rather than as a pass.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT" || exit 1
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# ⚠️ THE SPACE IS LOAD-BEARING: some files register as `srv.Get (` and a pattern requiring
# `srv.Get("` misses every one of them, which reads as a binary with no routes at all.
routes_of(){ grep -rhoE 'srv[a-z_]*\. *(Get|Post|Put|Delete) *\( *"[^"]+"' "$@" 2>/dev/null \
             | sed -E 's/.*(Get|Post|Put|Delete) *\( *"/\1 /; s/"$//' | sort -u; }

echo "== the console: every route is in api-reference.md's summary table =="
WEB=$(routes_of src/web/main.cpp)
n_web=$(printf '%s\n' "$WEB" | grep -c .)
chk "the extractor still finds the console's routes" yes \
    "$([ "$n_web" -gt 50 ] && echo yes || echo no)"
echo "     comparing $n_web literal console routes"
undoc=""
while read -r m p; do
    [ -z "$p" ] && continue
    M=$(printf '%s' "$m" | tr '[:lower:]' '[:upper:]')
    grep -qE "^\| [0-9]+[a-z]? \| $M \| \`$p\`" docs/api-reference.md || undoc="$undoc $M $p;"
done <<EOF
$WEB
EOF
chk "no console route is missing from the summary table" "" "$undoc"

echo "== the protocol binaries: every literal route is in protocol-apis.md =="
# ocsp, est and certstore register literal paths; the rest are computed (see the header).
for d in ocsp est certstore; do
    R=$(routes_of "src/$d"/*.cpp)
    n=$(printf '%s\n' "$R" | grep -c .)
    chk "  $d still yields routes to compare" yes "$([ "$n" -gt 0 ] && echo yes || echo no)"
    miss=""
    while read -r m p; do
        [ -z "$p" ] && continue
        # A regex route is documented under its human form (`<id>`, `<b64>`), so compare the
        # literal ones only; a pattern is recognisable by the characters a path never has.
        case "$p" in *'('*|*'['*|*'\\'*) continue ;; esac
        grep -qF -- "\`$p\`" docs/protocol-apis.md || miss="$miss $p"
    done <<EOF
$R
EOF
    chk "  every literal $d route is documented" "" "$miss"
done

# ⚠️ ANTI-VACUITY. Both loops above pass when the matcher matches everything — a `grep -q`
# that always succeeds, or an extractor that yields nothing, look identical to full coverage.
# Prove the matcher can still say no.
chk "PRECONDITION: an invented console route IS reported" no \
    "$(grep -qE '^\| [0-9]+[a-z]? \| GET \| `/api/not-a-real-route`' docs/api-reference.md \
       && echo yes || echo no)"
chk "PRECONDITION: a real console route IS found" yes \
    "$(grep -qE '^\| [0-9]+[a-z]? \| GET \| `/api/certs`' docs/api-reference.md && echo yes || echo no)"

echo
echo "=== API ROUTES DOCUMENTED: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
