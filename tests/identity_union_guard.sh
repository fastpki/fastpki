#!/usr/bin/env bash
# THE RECURRENCE IS THE BUG.
#
# Twelve times now, a second gate has re-decided "who is this caller?" from the user
# selector alone, after the RBAC gate already answered it from the union of user + groups:
# the profile gate, certificate scoping, enrolment credentials and
# (cmp/scep/acme enrolment), and the eight this ticket found. Each was invisible until
# somebody granted a role to a GROUP, and each was fixed one site at a time.
#
# So this is not another per-bug assertion. It is a census: every call to a function that
# resolves a subject's roles must be given the caller's groups, and a call that is not
# fails here — including the next one somebody writes.
#
# ⚠️ HOW IT READS A CALL. Grepping one line is not enough: most of these calls wrap. awk
# accumulates from the function name until the parentheses balance, then asks whether the
# argument list mentions any known group-carrying expression. That is a heuristic about
# NAMES, so it can be fooled by a variable called something else — which is why every
# exemption below has to be written down and justified rather than silently skipped.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# The functions whose LAST parameter is the group list. All default it to {}, which is what
# makes the omission silent: it compiles, it runs, and it answers about a different person.
FUNCS='role_limits|subject_roles|subject_holds|may_enrol|role_cert_cap'

# Anything that is plausibly the caller's groups. Deliberately generous — the guard's job
# is to catch "no groups anywhere near this call", not to police naming.
GROUPISH='groups|GROUPS'

# ── EXEMPTIONS ───────────────────────────────────────────────────────────────────────
# file:line -> why this call legitimately has no groups. An exemption is a claim that the
# subject has no group membership that could matter; it is not "this one is awkward".
# Empty for now: every call site in the tree passes them.
EXEMPT=""

SRC=$(find "$ROOT/src" "$ROOT/include" -name '*.cpp' -o -name '*.hpp' | sort)

# The call sites, one per line as "file:line:<full call text>".
CALLS=$(awk -v funcs="$FUNCS" '
  function flush_ready() { }
  {
    line = $0
    # Strip // comments so a mention inside prose is not read as a call. (Not perfect for
    # a // inside a string literal; no call site in this tree has one.)
    sub(/\/\/.*$/, "", line)
    if (acc != "") {
      acc = acc " " line
      n = gsub(/\(/, "(", line); m = gsub(/\)/, ")", line)
      depth += n - m
      if (depth <= 0) { print accfile ":" accline ":" acc; acc = "" }
      next
    }
    # ⚠️ SQL, not C++. `INSERT INTO subject_roles(` is the TABLE, and matching it reported
    # the DB layer as an unguarded call site. The table and the resolver share a name.
    if (line ~ /INSERT INTO|SELECT |DELETE FROM| FROM /) next
    # ⚠️ A WORD BOUNDARY, or `list_subject_roles(` matches `subject_roles(` and five
    # perfectly correct enumerations are reported as identity checks. A guard that cries
    # wolf six times gets its assertion deleted, which is worse than not having it.
    if (match(line, "(^|[^A-Za-z0-9_])(pki::)?(" funcs ")[ \t]*\\(")) {
      rest = substr(line, RSTART)
      n = gsub(/\(/, "(", rest); m = gsub(/\)/, ")", rest)
      depth = n - m
      if (depth <= 0) { print FILENAME ":" FNR ":" rest }
      else { acc = rest; accfile = FILENAME; accline = FNR }
    }
  }
' $SRC)

# ⚠️ A CENSUS THAT FINDS NOTHING PASSES EVERY ASSERTION BELOW. If the awk above stops
# matching — a rename, a refactor, a broken regex — this file would go green while
# checking nothing at all, which is the "guard that counts to zero over an empty input"
# shape this project has already shipped once. So the population is asserted first.
TOTAL=$(echo "$CALLS" | grep -c . )
chk "the census finds call sites at all" yes \
    "$([ "${TOTAL:-0}" -ge 15 ] && echo yes || echo no)"
echo "  [note] $TOTAL call sites of ${FUNCS//|/, }"

# A definition or declaration is not a call — drop the ones that carry a parameter type.
BAD=""
while IFS= read -r c; do
    [ -z "$c" ] && continue
    file=${c%%:*}; rest=${c#*:}; line=${rest%%:*}; text=${rest#*:}
    case "$text" in
        *"const std::vector<std::string>& groups"*) continue ;;   # the declaration itself
        *"std::vector<std::string> groups"*)        continue ;;
    esac
    echo "$text" | grep -qE "$GROUPISH" && continue
    rel=${file#"$ROOT"/}
    case " $EXEMPT " in *" $rel:$line "*) continue ;; esac
    BAD="$BAD$rel:$line "
done <<EOF
$CALLS
EOF

chk "every subject-role resolution is given the caller's groups" "" "$BAD"
if [ -n "$BAD" ]; then
    echo "  ⚠️ Each of these asks WHO THIS CALLER IS without their group memberships, so a"
    echo "     role granted to a group is invisible to it. Pass the groups the surrounding"
    echo "     handler already has, or — if the subject genuinely has none — add the site to"
    echo "     EXEMPT above WITH the reason. Do not delete the assertion."
    for b in $BAD; do
        f=${b%%:*}; l=${b##*:}
        echo "     --- $b"
        sed -n "${l}p" "$ROOT/$f" | sed 's/^[[:space:]]*/         /'
    done
fi

# ── The same defect one layer down ───────────────────────────────────────────────────
# `roles_for_subject()` takes a SELECTOR LIST rather than a groups argument, so the census
# above cannot judge it — but `{{"user", x}}` is the identical mistake spelled differently,
# and it is how the credential minter, sync_enrolment_creds and both /api/enrolment-credentials handlers
# were wrong. A literal one-element user selector is never right: if the subject genuinely
# has no groups the list is simply empty, and building it costs one loop.
USERONLY=$(grep -rn 'roles_for_subject({{"user"' "$ROOT/src" "$ROOT/include" 2>/dev/null | sed "s|$ROOT/||" | cut -d: -f1,2 | tr '\n' ' ')
chk "no call asks roles_for_subject with the USER selector alone" "" "$USERONLY"
[ -n "$USERONLY" ] && {
    echo "  ⚠️ Build the selector list: {\"user\",u} plus one {\"group\",g} per group the"
    echo "     caller has. An empty group list produces the old behaviour honestly."
}
# And the population again, for the same reason as above.
RFS=$(grep -rc 'roles_for_subject(' "$ROOT/src"/*/*.cpp "$ROOT/src/lib"/*.cpp 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
chk "  …and that pattern is actually searched for" yes \
    "$([ "${RFS:-0}" -ge 3 ] && echo yes || echo no)"

# ── The same shape at the OTHER end: naming the subject ───────────────────────────────
# The census above asks whether a call is given the caller's GROUPS. This one asks whether
# it is given the caller's NAME — and the answer used to be no, in three places.
#
# `pki::authenticate()` decides who the caller is: a directory identity is qualified by the
# directory that accepted it (`<provider>\<user>`), a local one is not. Every consumer must
# take that name from `AuthResult::subject`. All three took it from the string the CLIENT
# SENT instead, before authenticating:
#
#   est/main.cpp      a.username = user                 -> a.username = r.subject
#   msxcep/main.cpp   a.user = creds.substr(0, colon)   -> a.user     = r.subject   (Basic)
#   msxcep/main.cpp   a.user = *user                    -> a.user     = r.subject   (WS)
#   web/main.cpp      canon (derived from the typed u)  -> canon      = r.subject
#
# Two of those are in ONE file, which is the second-gate shape exactly: fixing the Basic
# path and not the UsernameToken path would authorize a qualified login over one transport
# and refuse it over the other, for the same account.
# ⚠️ EXECUTABLE LINES ONLY. Three more files DISCUSS pki::authenticate in a comment —
# enrol_gate.cpp explains what it fills in — and a guard that counts those reports a
# consumer that does not exist, which is a false failure somebody eventually deletes.
# ⚠️ NO `--include`: IT IS A GNU OPTION AND WE SHIP BUSYBOX. busybox grep does not
# recognise it and does not fail on it either — it folds the pattern into the search and
# answers a DIFFERENT, larger set (measured: 30 lines against 10). Everything downstream
# then filtered to nothing, so the census examined no files at all and the assertion below
# it passed vacuously. It was green here and vacuous in the image we ship, which is the
# whole reason the precondition exists. Select the extension from the OUTPUT instead, which
# both greps spell the same way.
AUTHFILES=$(grep -rn 'pki::authenticate(' "$ROOT/src" 2>/dev/null \
            | grep -E '\.cpp:[0-9]+:' \
            | grep -vE ':[[:space:]]*(//|\*)' \
            | cut -d: -f1 | grep -v '/lib/auth\.cpp$' | sed "s|$ROOT/||" | sort -u)
MISSING=""
for f in $AUTHFILES; do
    # The ASSIGNMENT, not the word: a bare /r\.subject/ also matches `issuer.subject`,
    # which is how the negative control below first passed against a file that has none.
    grep -qE '=[[:space:]]*r\.subject' "$ROOT/$f" || MISSING="$MISSING $f"
done
chk "every caller of pki::authenticate names its subject from r.subject" "" "$(echo $MISSING)"
[ -n "$MISSING" ] && {
    echo "  ⚠️ A consumer that keeps the typed string authenticates one identity and then"
    echo "     authorizes a different one. See AuthResult::subject."
}
# ⚠️ Anti-vacuity, twice over: the file list must be non-empty (an empty list passes the
# loop above without examining anything), and the pattern must be one that can fail.
chk "  PRECONDITION: consumers of authenticate() were actually found" yes \
    "$([ "$(printf '%s\n' $AUTHFILES | grep -c .)" -ge 3 ] && echo yes || echo no)"
chk "  PRECONDITION: the matcher fires on a file that lacks it" yes \
    "$(grep -qE '=[[:space:]]*r\.subject' "$ROOT/src/lib/x509.cpp" && echo no || echo yes)"

echo "=== a SUBJECT is never handed to the directory unsplit ==="
# ⚠️ THE SECOND HALF OF THE SAME DEFECT, and it was live until it was measured. The subject
# a request is authorized under carries its directory (`<provider>\<user>`); the DIRECTORY
# has no entry by that name. So every reader that turns a subject back into a directory
# question has to split it first and send the bare name — otherwise it asks for
# `CN=<provider>\<user>,<base>`, finds nothing, and answers "this subject is in no group".
#
# That failure is silent and points the safe way: the caller is simply refused, exactly as
# if no grant existed. It cost the group-granted enrolment credentials of every directory
# user — five protocols read their groups through this one helper.
#
# The invariant is about the ARGUMENT, not the call site, so it is spelled as one: inside
# auth.cpp, `ldap_groups_for_user` may be passed the split name and nothing else.
UNSPLIT=$(grep -nE 'ldap_(groups|mail)_for_user\(p, ' "$ROOT/src/lib/auth.cpp" \
          | grep -vE 'ldap_(groups|mail)_for_user\(p, q\.user\)' || true)
chk "ldap_groups_for_user and ldap_mail_for_user are only ever passed the split name" "" "$(echo $UNSPLIT)"
[ -n "$UNSPLIT" ] && {
    echo "  ⚠️ Passing the qualified subject through asks the directory for an entry that"
    echo "     cannot exist, and the empty answer reads as 'holds no group'."
}
# Anti-vacuity: a typo in the helper name would make the grep above match nothing forever.
chk "  PRECONDITION: the helper is actually called here" yes \
    "$(grep -qc 'ldap_groups_for_user(p, q\.user)' "$ROOT/src/lib/auth.cpp" && echo yes || echo no)"
# Every reader of a login name must split it — the bind path, the membership path, and the
# owner's email address for expiry notices, which asks the same directory about the same name.
# ⚠️ Counted as CALLS (`= split_...`), not occurrences: the definition lives in this file
# too, so a bare count includes it and would keep passing if a call were deleted.
chk "  PRECONDITION: all three readers split the login" 3 \
    "$(grep -c '= split_qualified_login(' "$ROOT/src/lib/auth.cpp" | tr -d ' ')"
chk "  PRECONDITION: the email reader calls the directory with the split name" yes \
    "$(grep -qc 'ldap_mail_for_user(p, q\.user)' "$ROOT/src/lib/auth.cpp" && echo yes || echo no)"

echo
echo "=== IDENTITY UNION GUARD: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
