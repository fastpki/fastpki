#!/usr/bin/env bash
# FastPKI has no setting that turns a security control off.
#
# Raised after deploy/bootstrap.compose.conf shipped AUTH_BACKEND=none:
#
#   "my take is that to avoid any future bugs like this, we should remove all
#    unprotected/test/dev vars and settings from FastPKI code. So please get rid of
#    CMP_ACCEPT_UNPROTECTED, ACME_EAB_REQUIRED, OIDC_TLS_SKIP_VERIFY, AUTH_BACKEND=none
#    and any other similar settings that weaken the security of the product and open
#    holes for attacks."
#
# ⚠️ WHY A SUITE AND NOT JUST DELETING THEM. Every guard this repo had checked config-key
# NAMES — "does the parser know this key?", "does a doc name a key the parser ignores?" —
# and `AUTH_BACKEND` is a perfectly real key. Its dangerous VALUE was invisible to all of
# them, which is how it shipped. So the assertion here is not "the key is gone from a
# file"; it is that the PARSER no longer knows the key at all, so a stale config carrying
# it is a loud unknown-key rather than a silent revert to the weak behaviour.
#
# This suite grows one section per setting removed. It is deliberately the single place
# that fails if any of them comes back.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
CONFIG_CPP="$ROOT/src/lib/config.cpp"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

[ -f "$CONFIG_CPP" ] || { echo "SKIP: no $CONFIG_CPP"; exit 0; }

# The keys apply() compares against — the code that actually runs, same authority
# config_keys_live.sh uses.
PARSED=$(grep -o 'key == "[A-Z0-9_]*"' "$CONFIG_CPP" | sed 's/.*"\(.*\)"/\1/' | sort -u)
# ⚠️ The control for every "the parser does not know X" assertion below. If this grep ever
# stops matching — a refactor away from `key == "..."`, say — PARSED goes empty and every
# one of those passes vacuously while the settings are still live.
chk "the parser key list was extracted at all" yes \
    "$([ "$(printf '%s\n' "$PARSED" | wc -l | tr -d ' ')" -gt 20 ] && echo yes || echo no)"
chk "  and it still contains a key we KEEP"    yes \
    "$(grep -qx 'AUTH_BACKEND' <<<"$PARSED" && echo yes || echo no)"

echo "=== OIDC_TLS_SKIP_VERIFY is gone; OIDC TLS is always verified ==="
chk "the parser does not know OIDC_TLS_SKIP_VERIFY" no \
    "$(grep -qx 'OIDC_TLS_SKIP_VERIFY' <<<"$PARSED" && echo yes || echo no)"
chk "  no Config field survives either"             no \
    "$(grep -rq 'oidc_tls_skip_verify' "$ROOT/src" "$ROOT/include" 2>/dev/null && echo yes || echo no)"
# The behaviour, not just the absence of the switch: verification is now a constant.
chk "  oidc.cpp verifies unconditionally"           yes \
    "$(grep -q 'enable_server_certificate_verification(true)' "$ROOT/src/lib/oidc.cpp" && echo yes || echo no)"
chk "  and never from a variable"                   no \
    "$(grep -qE 'enable_server_certificate_verification\(!' "$ROOT/src/lib/oidc.cpp" && echo yes || echo no)"
# The supported way to trust a private issuer CA must still exist, or this removal would
# have taken a legitimate deployment shape with it. It is no longer a config key — it is
# the provider's own `ca_cert`, because which anchor to trust is a property of ONE issuer
# and a flat file could only ever name one.
# Assert the CAPABILITY, not a spelling: the column is declared on the OIDC provider
# table (not just anywhere in the schema), and the client hands it to the TLS layer.
chk "  a private-CA anchor still exists, per provider" yes \
    "$(awk '/create table if not exists oidc_providers/,/\);/' "$ROOT/sql/createdb.sql" \
         | grep -q 'ca_cert' && \
       grep -q 'set_ca_cert_path(ca_cert' "$ROOT/src/lib/oidc.cpp" && echo yes || echo no)"
# A doc that still advertises it would send an operator looking for a switch that is gone.
chk "  no doc still advertises it"                  no \
    "$(grep -rq 'OIDC_TLS_SKIP_VERIFY' "$ROOT/docs" 2>/dev/null && echo yes || echo no)"
chk "  no shipped deploy file sets it"              no \
    "$(grep -rq 'OIDC_TLS_SKIP_VERIFY' "$ROOT/deploy" "$ROOT/config" 2>/dev/null && echo yes || echo no)"

echo "=== AUTH_BACKEND=none is gone; the parser refuses the value ==="
# ⚠️ THE ONE THAT IS A VALUE, NOT A KEY. `AUTH_BACKEND` stays — it is how you choose
# between local and ldap — so "the parser does not know this key" is the WRONG assertion
# here, and asserting it would be a guard that can never fire. What must be gone is the
# `none` BRANCH, which is the shape every other guard in this repo was blind to.
chk "AUTH_BACKEND itself still exists"        yes \
    "$(grep -qx 'AUTH_BACKEND' <<<"$PARSED" && echo yes || echo no)"
chk "  auth.cpp has no 'none' branch"          no \
    "$(grep -qE 'be == "none"' "$ROOT/src/lib/auth.cpp" && echo yes || echo no)"
# Refused at PARSE time, not left to deny every login later: a service that starts and then
# rejects everybody is the confusing failure, and gives the operator no line to act on.
chk "  config.cpp rejects any value but local|ldap" yes \
    "$(grep -q "AUTH_BACKEND must be 'local' or 'ldap'" "$ROOT/src/lib/config.cpp" && echo yes || echo no)"
# The startup WARNINGs are gone with the value — a branch that can never be true is not
# dormant, it is wrong (it would print for a value that no longer parses).
#
# ⚠️ Match the CODE, not the file. Both of these still MENTION the string in comments
# explaining why the branch went, and an earlier version of this assertion failed on
# exactly that prose — the same trap that once flagged a guard's own header.
for b in est msxcep; do
  chk "  src/$b has no auth_backend==none branch" no \
      "$(grep -qE 'auth_backend *== *"none"' "$ROOT/src/$b/main.cpp" && echo yes || echo no)"
done
chk "  no test suite still configures it"      no \
    "$(grep -rq '^AUTH_BACKEND=none' "$ROOT/tests" 2>/dev/null && echo yes || echo no)"

echo "=== SCEP: a challengePassword is never optional ==="
# ⚠️ THE FIFTH ONE, WHICH WAS NOT NAMED — the instruction was "and any
# other similar settings", and this is the same shape as AUTH_BACKEND=none: a legitimate
# key whose VALUE switched authentication off, with a startup WARNING as the only guard.
#
#     require_challenge = !is_renewal &&
#         (!scep_challenge.empty() || scep_dynamic_challenge);   <-- removed
#
# Empty challenge + dynamic off required no challengePassword at all. install.sh
# generates one, so a wizard install was safe; skipping the wizard, or clearing the field
# in the console, was not.
#
# The conditional had to go; the KEY was removed as well ("it's per user now"), so
# there is no longer any value an operator can set that switches the challenge off.
chk "require_challenge is unconditional for a non-renewal" yes \
    "$(grep -q 'const bool require_challenge = !is_renewal;' "$ROOT/src/scep/main.cpp" && echo yes || echo no)"
# ⚠️ STRIP COMMENTS FIRST. The block above this assertion QUOTES the old condition to
# explain why it went, so grepping the raw file matches the explanation and the guard
# fails on correct code. Third time this trap has fired here — comments that document
# a removal necessarily contain the thing removed.
chk "  the old empty-challenge condition is gone"          no \
    "$(grep -v '^[[:space:]]*//' "$ROOT/src/scep/main.cpp" \
       | grep -qE 'require_challenge = !is_renewal &&' && echo yes || echo no)"
# A renewal legitimately bypasses it (proof-of-possession of a live cert, bound to its
# identity) — removing THAT would be a different bug, so pin it.
# ⚠️ PIN THE CONSUMPTION SITE, NOT THE SYMBOL — and strip comments, as every other assertion
# in this file does. `grep -q is_renewal` over the RAW file was satisfied by the comment that
# quotes the removed guard, by the declaration, and by two unrelated uses further down, so the
# behaviour could be inverted with this green: widen the gate to
# `if (require_challenge || is_renewal)` and a renewal DEMANDS a challengePassword instead of
# bypassing it through proof-of-possession of a live certificate. No assertion in this section
# read where require_challenge is consumed, and that is the only place the behaviour lives.
chk "  renewal still bypasses the challenge"               yes \
    "$(grep -v '^[[:space:]]*//' "$ROOT/src/scep/main.cpp" \
       | grep -qE 'if \(require_challenge\) \{' && echo yes || echo no)"
chk "    and nothing is ORed into that gate"               no \
    "$(grep -v '^[[:space:]]*//' "$ROOT/src/scep/main.cpp" \
       | grep -qE 'if \(require_challenge[[:space:]]*(\|\||&&)' && echo yes || echo no)"
# The startup line must no longer claim enrolment needs no password — it said something
# true and dangerous, and the truth has changed.
chk "  startup no longer says 'requires no challenge'"     no \
    "$(grep -v '^[[:space:]]*//' "$ROOT/src/scep/main.cpp" \
       | grep -q 'requires no challenge' && echo yes || echo no)"
chk "  and points at the per-user path instead"            yes \
    "$(grep -q 'requires a PER-USER challengePassword' "$ROOT/src/scep/main.cpp" && echo yes || echo no)"

echo "=== ACME_EAB_REQUIRED is gone; External Account Binding is unconditional ==="
# The one named that was already defaulting to the SAFE value. That
# made it the most likely to be waved through — "the default is right, leave the switch" —
# and it is exactly the AUTH_BACKEND shape: a legitimate key whose dangerous VALUE our own
# suites were setting. FOURTEEN test suites and one shipped demo pinned it false, so the
# posture we ship had almost no coverage while 166 suites went green.
chk "the parser does not know ACME_EAB_REQUIRED" no \
    "$(grep -qx 'ACME_EAB_REQUIRED' <<<"$PARSED" && echo yes || echo no)"
chk "  no Config field survives either"          no \
    "$(grep -rq 'acme_eab_required' "$ROOT/src" "$ROOT/include" 2>/dev/null && echo yes || echo no)"
# The behaviour, not the absence of the switch: the directory must always advertise the
# requirement (RFC 8555 §7.1.1) so a client knows before it wastes a round trip.
chk "  the directory advertises it unconditionally" yes \
    "$(grep -q '{"externalAccountRequired", true}' "$ROOT/src/acme/main.cpp" && echo yes || echo no)"
# ⚠️ THE BYPASS THIS REMOVAL EXPOSED, and the reason a key deletion was not enough.
# handle_new_order gated BOTH the acme:enrol check and the per-requester cap on
# `if (!account->kid.empty())`. kid is set only from the EAB binding, so with the switch off
# an unbound account had no kid and skipped both — silently, with a 201. Now that no such
# account can be created, an empty kid is refused rather than waved through: a permissive
# fallback on a state that should be unreachable is how the switch became a hole.
chk "  an account with no kid is REFUSED, not skipped" yes \
    "$(grep -q 'this account carries no external account binding' "$ROOT/src/acme/main.cpp" \
       && echo yes || echo no)"
# ⚠️ Strip comments first — the block above the code QUOTES the old guard to explain why it
# went. Fourth time this trap has fired here.
chk "  and the old permissive guard is gone"           no \
    "$(grep -v '^[[:space:]]*//' "$ROOT/src/acme/main.cpp" \
       | grep -qE 'if \(!post->account->kid\.empty\(\)\)' && echo yes || echo no)"
# No shipped file may still set it — including the demos, which are shipped scripts and
# were BOTH found setting removed keys earlier in this ticket.
chk "  no shipped file sets it"                  no \
    "$(grep -rq 'ACME_EAB_REQUIRED=' "$ROOT/deploy" "$ROOT/config" "$ROOT/demo" 2>/dev/null \
       && echo yes || echo no)"
# ⚠️ Matches the SETTING SHAPE, not the name. docs/authentication.md tells an operator, in
# prose, that this key was removed and EAB can no longer be switched off — which is worth
# saying and would fail a bare name grep. The OIDC assertion above can stay bare only
# because no doc there needed that sentence; if one ever does, narrow it the same way.
# A live setting looks like a config-reference table row or an assignment.
chk "  no doc presents it as a live setting"     no \
    "$(grep -rqE '^\| `ACME_EAB_REQUIRED`|ACME_EAB_REQUIRED=' "$ROOT/docs" 2>/dev/null \
       && echo yes || echo no)"

echo "=== CMP_ACCEPT_UNPROTECTED is gone; an unprotected CMP message is always refused ==="
# The last of the five named. Unlike AUTH_BACKEND, we never shipped the
# dangerous VALUE — deploy/bootstrap.compose.conf, config/bootstrap.conf.example and the compiled
# default all said `false`. NINE test suites said `true`, which is the same coverage gap
# ACME_EAB_REQUIRED had: the shipped posture was barely exercised.
chk "the parser does not know CMP_ACCEPT_UNPROTECTED" no \
    "$(grep -qx 'CMP_ACCEPT_UNPROTECTED' <<<"$PARSED" && echo yes || echo no)"
# ⚠️ Strip comments: src/cmp/main.cpp explains WHY the flag went and necessarily names it.
#
# ⚠️ NO `--include`: IT IS A GNU OPTION AND WE SHIP BUSYBOX. Measured inside the shipped
# image, `grep -rh --include='*.cpp' --include='*.hpp' -v ... src include` returns **0
# lines** and exit 0 — it does not fail, it answers nothing. Those zero lines were then
# searched for the symbol, found nothing, and the assertion's expected value is `no`. So
# this check for a removed AUTHORIZATION BYPASS passed by examining no files at all, on
# the only platform we ship. It was green on a dev box with GNU grep the whole time.
#
# Select the extension from the OUTPUT instead — both greps spell that the same way — and
# search for the symbol FIRST so the pipeline stays cheap. `grep -qv` here means "some line
# naming the symbol is not a comment", which is the question.
find_noncomment(){   # symbol -> yes|no
    grep -rn "$1" "$ROOT/src" "$ROOT/include" 2>/dev/null \
      | grep -E '\.(cpp|hpp):[0-9]+:' \
      | sed 's/^[^:]*:[0-9]*://' \
      | grep -qv '^[[:space:]]*//' && echo yes || echo no
}
chk "  no Config field survives either"               no "$(find_noncomment cmp_accept_unprotected)"
# ⚠️ ANTI-VACUITY, which is exactly what was missing above. An assertion whose healthy
# answer is "found nothing" cannot tell "the symbol is gone" from "the search reached no
# files". A symbol that certainly exists in a .cpp must come back `yes` through the SAME
# pipeline, or the `no` above means nothing.
chk "  PRECONDITION: the same search finds a symbol that IS there" yes \
    "$(find_noncomment enforce_issuance_policy)"
# The behaviour: OpenSSL is told to refuse, as a constant.
chk "  the server refuses unprotected as a constant" yes \
    "$(grep -q 'OSSL_CMP_SRV_CTX_set_accept_unprotected(srv, 0)' "$ROOT/src/cmp/main.cpp" \
       && echo yes || echo no)"
# ⚠️ THE SECOND AUTHORIZATION BYPASS THIS TICKET FOUND, and the reason removing the key was
# not enough on its own. handle_rr gated PBM-refusal, signer identity AND the revoke-ownership
# check on `if (!cfg.cmp_accept_unprotected)`. With the flag on, any caller could revoke any
# certificate — and the nine suites that set it could never have caught an ownership
# regression. Assert the three are now unconditional by pinning that the wrapper is gone.
chk "  the revoke-ownership check is not wrapped in it" no \
    "$(grep -v '^[[:space:]]*//' "$ROOT/src/cmp/main.cpp" \
       | grep -qE 'if \(!st->cfg\.cmp_accept_unprotected\)' && echo yes || echo no)"
# ...and that the checks themselves still exist, or "the wrapper is gone" would also pass
# if someone deleted the body with it.
for want in 'revocation requires signature-based protection' \
            'cannot determine the authenticated signer for revocation' \
            'cert:revoke'; do
  # ⚠️ COMMENT-STRIPPED, like the negative assertions above — this positive one was not, and
  # `cert:revoke` occurs three times in the explanatory block ABOVE the gate as well as in
  # the gate itself. Deleting the whole subject_holds(…, "cert:revoke", …) authorization
  # check — after which any authenticated CMP signer can revoke any certificate of that CA —
  # left those comments untouched and this printing PASS. The other two strings in this loop
  # occur only at their throw sites, so only the cert:revoke iteration ever lied.
  chk "  rr still enforces: $want" yes \
      "$(grep -v '^[[:space:]]*//' "$ROOT/src/cmp/main.cpp" \
         | grep -q "$want" && echo yes || echo no)"
done
# ⚠️ Comment-stripped: demo/pki-demo.sh explains in a comment why the branch went, and the
# shell comment marker is `#`, not `//`.
chk "  no shipped file sets it"                       no \
    "$(grep -rh -v '^[[:space:]]*#' "$ROOT/deploy" "$ROOT/config" "$ROOT/demo" 2>/dev/null \
       | grep -q 'CMP_ACCEPT_UNPROTECTED=' && echo yes || echo no)"
chk "  no test suite sets it either"                  no \
    "$(grep -rqE '^[[:space:]]*CMP_ACCEPT_UNPROTECTED=' "$ROOT/tests" 2>/dev/null && echo yes || echo no)"
# ⚠️ README.md is a doc too and it is NOT under docs/ — it sits at the repo root, so it is
# named separately. A guide kept outside docs/ once told operators to "Only set `true` for
# throwaway dev" while this sweep looked only under docs/.
chk "  no doc presents it as a live setting"          no \
    "$(grep -rqE '^\| `CMP_ACCEPT_UNPROTECTED`|CMP_ACCEPT_UNPROTECTED=' \
        "$ROOT/docs" "$ROOT/README.md" 2>/dev/null && echo yes || echo no)"

echo
echo "=== NO INSECURE SETTINGS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
