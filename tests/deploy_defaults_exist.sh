#!/usr/bin/env bash
# A SHIPPED file must not name a CA, a database role or a database that a fresh
# deployment does not have.
#
# ── The two that shipped ─────────────────────────────────────────────────────────
#
# `bootstrap.compose.conf` carried `CMP_CLIENT_CA_ID=issuing,root`. A fresh deployment has **no
# CA at all** — the operator creates one in the console — so every first start logged
#
#     ERR  CMP: CMP_CLIENT_CA_ID 'issuing' is not a known CA instance — skipped
#     ERR  CMP: CMP_CLIENT_CA_ID 'root' is not a known CA instance — skipped
#
# Two ERR lines, at startup, on a system that is working correctly. That is worse than
# useless: it teaches an operator that errors in this log are normal.
#
# `docs/high-availability.md` still told operators to use `dbname=pki user=pki`, from before the
# rename to `fastpki`. Following it produced
#
#     FATAL:  password authentication failed for user "pki"
#     DETAIL: Role "pki" does not exist.
#
# ── Why a test rather than just a fix ────────────────────────────────────────────
#
# Both are the same failure: a shipped default naming something the deployment does not
# create. Nothing compares the two sides, so they drift silently and the operator finds out
# from a log. This compares them.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

CC="$ROOT/deploy/bootstrap.compose.conf"
DC="$ROOT/deploy/docker-compose.yml"

# ⚠️ SHIPPED-IMAGE SAFE FILE LIST — do NOT go back to `git ls-files`.
#
# Two assertions below ask "is this referenced anywhere in the tree?". They used
# `git ls-files`, which works in a checkout and returns NOTHING inside the shipped
# container, because the image has no .git. That is not a harmless difference:
#
#   * §4 (new) reported five perfectly good variables — FASTPKI_IMAGE, KEY_BACKEND,
#     PSQL, RUN_LAB_TEST, SKIP_SUITE — as unimplemented, because the "is it read?"
#     lookup could not see a single file. Caught by deploy/lab-test.sh, which runs
#     this suite inside the image we actually ship; the Mac run was green.
#   * §3 is worse and older: it COUNTS matches and expects 0, so an empty file list
#     makes it pass VACUOUSLY. It has been proving nothing in the image the whole
#     time, while reading as a pass.
#
# §3d: a test must not assume the layout of the machine it runs on. `find` is the
# portable answer and needs no VCS.
repo_files() {
    find "$ROOT" -type f \
        \( -name '*.sh' -o -name '*.md' -o -name '*.yml' -o -name '*.yaml' \
           -o -name '*.cpp' -o -name '*.hpp' -o -name '*.conf' -o -name '*.sql' \
           -o -name '*.example' -o -name 'Dockerfile*' \) \
        -not -path '*/build/*' -not -path '*/.git/*' -not -path '*/third_party/*' 2>/dev/null
}

echo "=== 1. no shipped config names a CA that a fresh deployment does not have ==="
# A fresh deployment is CA-less by design, so ANY non-empty value here is wrong in the
# tracked file — it can only be right for the one deployment it was copied from.
VAL=$(sed -n 's/^CMP_CLIENT_CA_ID=//p' "$CC" | head -1)
chk "CMP_CLIENT_CA_ID ships blank" "" "$VAL"
# ⚠️ COMMENTED OUT, NOT SET BLANK — and this assertion used to require the opposite.
# Measured why: Config::load() seeds from the environment and THEN parses this file,
# calling apply() for every key it FINDS, and the env-wins skip covers only PG_CONNINFO.
# So `CMP_CLIENT_CA_ID=` with no value OVERWRITES a real value the deployment set in its
# environment, with nothing in any log to say so — which is exactly how CMP ended up with
# zero client anchors and refused every signature-protected request on the lab.
#
# The key must still be DOCUMENTED here so an operator can find it, but as a commented
# example. This suite kept asserting the older shape (`^CMP_CLIENT_CA_ID=`), so it went
# red the moment 982b63e made the file correct — two assertions in one suite demanding
# opposite things.
chk "  and it is still a documented key" yes \
    "$(grep -qE '^# *CMP_CLIENT_CA_ID=' "$CC" && echo yes || echo no)"
# ...and NOT set to an empty value, which is the thing forbidden here.
chk "  but never set to an empty value"  no \
    "$(grep -qE '^CMP_CLIENT_CA_ID= *$' "$CC" && echo yes || echo no)"
# ⚠️ install.sh MUST NOT ASK FOR IT. This asserted the opposite — that the wizard prompts,
# defaulting to blank. The value names a registered CA id, and at install time no CA exists:
# the deployment is created first and CAs are made afterwards from the console. So the only
# answer an operator could give was blank, and a question whose sole valid answer is blank
# teaches them to press enter through the wizard. It is set later, when there is a CA to
# name, from the Config page or `fastpki-config set`.
chk "install.sh does NOT ask for it" no \
    "$(grep -qE '^ *ask +CMP_CLIENT_CA_ID' "$ROOT/deploy/install.sh" && echo yes || echo no)"
chk "  and never writes it into .env"  no \
    "$(grep -qE "printf +'CMP_CLIENT_CA_ID=" "$ROOT/deploy/install.sh" && echo yes || echo no)"
# The same rule for the other id-shaped keys: they name a CERT id, which bootstrap
# does create, so those may legitimately carry a value. Assert they are not CA ids by
# checking they are not in the CA-id form the CMP key used.
for k in EST_CERT_ID ACME_CERT_ID CMP_RA_CERT_ID_PREFIX; do
    v=$(sed -n "s/^$k=//p" "$CC" | head -1)
    chk "$k names one transport cert, not a CA list" no \
        "$(printf '%s' "$v" | grep -q ',' && echo yes || echo no)"
done

echo "=== 2. every documented DB role/name matches what the deployment creates ==="
# The compose file is the authority: it creates the role and the database.
PGUSER_REAL=$(sed -n 's/^ *POSTGRES_USER: *//p' "$DC" | head -1)
PGDB_REAL=$(sed -n 's/^ *POSTGRES_DB: *//p' "$DC" | head -1)
chk "compose creates a role"     yes "$([ -n "$PGUSER_REAL" ] && echo yes || echo no)"
chk "compose creates a database" yes "$([ -n "$PGDB_REAL" ] && echo yes || echo no)"
# Any conninfo in a shipped doc or config must name THOSE, not something historical.
BAD=""
# ⚠️ src/tools/mesh.cpp is in this list because its header comment IS the documentation
# for the topology-file format — it is what `--help` describes and what an operator copies
# to build their own. It carried `dbname=pki` in all four examples long after the rename,
# so anyone following it got 'database "pki" does not exist'. A doc that ships inside a
# .cpp is still a doc; scanning only deploy/*.md could never see it.
for f in "$ROOT"/deploy/*.md "$ROOT"/deploy/*.conf "$ROOT"/deploy/*.example "$ROOT"/src/tools/mesh.cpp; do
    [ -e "$f" ] || continue
    while IFS= read -r line; do
        u=$(printf '%s' "$line" | sed -n 's/.*[^a-z]user=\([A-Za-z0-9_]*\).*/\1/p')
        d=$(printf '%s' "$line" | sed -n 's/.*dbname=\([A-Za-z0-9_]*\).*/\1/p')
        # `repl`/`replicator` is the replication role, created separately by the mesh docs.
        case "$u" in ""|"$PGUSER_REAL"|repl|replicator|postgres|'<user>'|'$PGUSER') ;;
            *) BAD="$BAD $(basename "$f"):user=$u" ;; esac
        # ⚠️ `replication` is the walsender PSEUDO-database, not a database anyone
        # creates — and docs/high-availability.md's only mention of it is the sentence warning
        # operators not to use it. Without this the guard fails on the prose that
        # documents the trap, which is how a guard teaches people to delete the prose.
        case "$d" in ""|"$PGDB_REAL"|replication|'<db>'|'$PGDATABASE') ;;
            *) BAD="$BAD $(basename "$f"):dbname=$d" ;; esac
    done < <(grep -h "PG_CONNINFO\|conninfo\|dbname=" "$f" 2>/dev/null)
done
chk "no shipped doc names a role or database the deployment never creates" "" "$(echo $BAD)"

echo "=== no shipped file reads a path nothing writes ==="
# ⚠️ Removed the console's writes to /var/pki/ca-instances, and left TWO readers
# behind: certgen.sh still created the directory, and demo/setup-after-deploy.sh still
# signed the CMP RA certificate with /var/pki/ca-instances/issuing.{crt,key}. The .key
# half had already been dead (a CA key is a pkcs11: handle and has no on-disk
# form), so that script could not have worked for some time and nothing referenced it —
# but the .crt half was live until later, which is how removing a writer turned a stale
# script into a broken one.
#
# This is the project's recurring shape in its other direction: usually a writer with no
# reader, here readers left behind by a removed writer. Cheap to assert, so assert it.
# ⚠️ ACTIVE references only. The first version of this counted every occurrence and
# tripped on its OWN docstring and on certgen.sh's note explaining the removal — a guard
# that fails on the prose describing it teaches people to delete the prose. Comment lines
# are excluded, and so is this file.
chk "nothing ACTIVELY references the removed CA material directory" 0 \
    "$(repo_files | xargs grep -n '/var/pki/ca-instances' 2>/dev/null \
        | grep -v 'deploy_defaults_exist.sh:' \
        | grep -vE ':[0-9]+: *#' | wc -l | tr -d ' ')"

echo "=== no deploy script tells the operator to set a variable nothing reads ==="
# ⚠️ Db-restore-online.sh finished by printing the way back to a redundant pair:
#
#     STANDBY_OF=<primary> docker compose up -d postgres
#
# and `grep -rn STANDBY_OF` matched that echo and nothing else. Not one no-op instruction
# among many: it is the LAST line of the online-restore runbook, so it is on the path
# every operator takes at the moment they are recovering from something.
#
# And it was worse than inert. The script removes the old primary's data volume in the
# step immediately before, so an empty PGDATA meant docker-entrypoint.sh ran initdb plus
# createdb.sql and produced a SECOND, EMPTY, read-write Postgres beside the real primary
# — with target_session_attrs=read-write, applications can land on either.
#
# Same family as the section above: a reader with no writer, here an instruction with no
# implementation. The general assertion is what keeps it closed — any FUTURE deploy script
# that prints VAR=... for a variable no shipped file consumes fails here on the day it
# lands, whichever script someone adds it to.
#
# A variable counts as implemented if docker-compose.yml declares it (that is what passes
# a shell variable into a container at all), if the CONFIG PARSER knows it as a key, or if
# some shipped file reads it.
#
# ⚠️ The config-parser arm is not a loophole, it is a third real implementation. A key like
# DATACENTER_ID is consumed by the binary straight out of the environment (Config::from_env),
# so nothing in any shell script expands ${DATACENTER_ID} and no compose service declares it
# — yet an operator who sets it gets exactly the documented effect. Without this arm the
# guard fires on a working key, which is how a guard stops being read. It stays sharp on the
# case it was written for: STANDBY_OF is a compose/entrypoint variable and no config key, so
# it is still only excused by a real compose declaration.
BADVARS=""
while IFS= read -r v; do
    [ -z "$v" ] && continue
    # Declared for a container, or read by a shipped script? Either is an implementation.
    if grep -qE "^[[:space:]]*$v:[[:space:]]*\\\$\{$v" "$ROOT/deploy/docker-compose.yml" 2>/dev/null; then
        continue
    fi
    # A key the config parser applies. Match the quoted key in an `else if (key == "V")`
    # arm or the known-keys list — both are in config.cpp and both mean the binary acts on it.
    if grep -q "\"$v\"" "$ROOT/src/lib/config.cpp" 2>/dev/null; then
        continue
    fi
    # ⚠️ A psql -v ASSIGNMENT IS NOT A DEPLOYMENT VARIABLE. `psql -v ON_ERROR_STOP=1` sets a
    # variable inside psql for that one invocation; it is not a config key, not a compose
    # variable, and nothing in this repo could ever "implement" it. Printing a runnable psql
    # command is exactly what the multi-DC steps do, so without this arm the guard fires on
    # a correct instruction. Narrow on purpose: only names that appear immediately after
    # `-v ` in the line that prints them are excused, so a real variable that happens to be
    # printed elsewhere is still caught.
    if grep -rhE "\\-v[[:space:]]+$v=" "$ROOT"/deploy/*.sh >/dev/null 2>&1; then
        continue
    fi
    # Read by some shipped file? ⚠️ THE TEST IS WHERE IT IS READ, NOT WHICH FILE READS IT.
    # Excluding the printing script by name was close but wrong: a script that prints its
    # OWN usage line (`PRIMARY_HOST=<addr> $0 <dump>`) and then reads ${PRIMARY_HOST} is a
    # complete, working contract, and excluding it failed that as though nothing implemented
    # the variable. What the guard is actually for is a variable that is only ever ECHOED --
    # STANDBY_OF was printed as an instruction for compose to consume while no file read it
    # at all. So ignore echo/printf lines and comments, and treat an expansion anywhere else
    # as the implementation, whichever file it lives in.
    if repo_files | xargs grep -hE "\\\$\{?$v\}?" 2>/dev/null \
        | grep -vE "^[[:space:]]*(#|echo|printf)" | grep -q .; then
        continue
    fi
    BADVARS="$BADVARS $v"
done <<EOF
$(grep -rhoE '^[[:space:]]*echo "[^"]*[[:space:]]([A-Z][A-Z0-9_]{3,})=' "$ROOT"/deploy/*.sh 2>/dev/null \
    | sed -E 's/.*[[:space:]]([A-Z][A-Z0-9_]{3,})=$/\1/' | sort -u)
EOF
chk "every variable a deploy script prints is actually implemented" "" "$(echo $BADVARS)"
# And the specific one, named, so a regression says WHICH contract broke rather than only
# that some variable is unimplemented.
chk "  STANDBY_OF reaches the container (declared under environment:)" yes \
    "$(grep -qE '^[[:space:]]*STANDBY_OF:[[:space:]]*\$\{STANDBY_OF' "$ROOT/deploy/docker-compose.yml" \
       && echo yes || echo no)"
chk "  and the primary acts on it instead of initialising a new cluster" yes \
    "$(grep -q 'STANDBY_OF:-' "$ROOT/deploy/docker-compose.yml" && echo yes || echo no)"


echo "=== no test-only binary is named so the image ships it ==="
# ⚠️ THE IMAGE COPIES BY PREFIX: `COPY --from=build /src/build/fastpki-* /usr/local/bin/`.
# So the ONLY thing keeping a test tool out of production is its name, and two of them —
# fastpki-scep-testclient and fastpki-cmp-testclient — carried the prefix and shipped a
# client that can enrol into every image. A comment in tests/fuzz_lane.sh even asserted one
# of them was "not shipped" while naming the glob that shipped it, which is how it survived.
# Names, not memory: anything that is a test tool must not start with fastpki-.
BADTOOLS=""
for _t in $(grep -oE '^[[:space:]]*add_executable\([A-Za-z0-9_-]+' "$ROOT/CMakeLists.txt" \
            | sed -E 's/.*add_executable\(//'); do
    case "$_t" in
        fastpki-*testclient|fastpki-*-test|fastpki-*stub|fastpki-*mock|fastpki-test*)
            BADTOOLS="$BADTOOLS $_t" ;;
    esac
done
chk "no add_executable(fastpki-*) is a test tool" "" "$(echo $BADTOOLS)"
# And the glob itself must still be what makes that true — if the Dockerfile ever copies
# binaries by an explicit list instead, the naming rule stops being load-bearing and this
# check silently guards nothing.
chk "the image still copies binaries by the fastpki-* prefix" yes \
    "$(grep -qE 'COPY .*build/fastpki-\*' "$ROOT/Dockerfile" && echo yes || echo no)"

echo "=== every postgres launcher names the client in its log ==="
# ⚠️ COUNTED, NOT GREPPED FOR PRESENCE. postgres is exec'd from more than one place -- the
# compose server and the k8s server pod, whichever role it starts in -- and a prefix on some of them leaves the
# rest's auth failures untraceable, which is the whole point. Missing one occurrence in a
# file already being edited is exactly how this shipped half-fixed, so it asserts the count
# matches the number of launchers rather than "somebody set it somewhere".
#
# The launcher count is DERIVED, not hardcoded: add a fourth exec without a prefix and the
# two numbers diverge here on the day it lands.
# ⚠️ THE FILE LIST IS FOUND, NOT NAMED. It used to grep two hardcoded paths while the
# comment above claimed it derived them -- so a postgres launcher added in a NEW file was
# invisible, which is the one case the whole assertion exists for. Search deploy/ instead.
LFILES=$(find "$ROOT/deploy" \( -name '*.yml' -o -name '*.yaml' -o -name '*.sh' \) -type f 2>/dev/null | sort)
LAUNCHERS=$(printf '%s\n' "$LFILES" | xargs grep -hcE '^[[:space:]]*exec ([^ ]+ )*postgres( |$)|^[[:space:]]*exec docker-entrypoint\.sh postgres' 2>/dev/null \
            | awk '{n+=$1} END{print n+0}')
PREFIXED=$(printf '%s\n' "$LFILES" | xargs grep -hc "log_line_prefix=" 2>/dev/null \
            | awk '{n+=$1} END{print n+0}')
chk "there are postgres launchers to check at all (not a vacuous 0==0)" yes \
    "$([ "${LAUNCHERS:-0}" -ge 2 ] && echo yes || echo no)"
chk "every postgres launcher sets log_line_prefix" "$LAUNCHERS" "$PREFIXED"
# The prefix has to carry the two fields the ticket needs, or it is decoration: %u@%d names
# the role that failed and %h the address it came from. %q keeps background processes clean.
# ⚠️ DERIVED, like the launcher count above. Hardcoding "2" here meant that deleting a
# postgres launcher failed this as a missing PREFIX rather than as a changed inventory --
# a true statement reported as a defect, which costs exactly as much time as a false one.
CPREFIX=$(grep -c "log_line_prefix=" "$ROOT/deploy/docker-compose.yml" | awk '{print $1+0}')
for tok in '%u' '%h' '%q'; do
    chk "  the prefix carries $tok" "$CPREFIX" \
        "$(grep -rhc "log_line_prefix=.*$tok" "$ROOT/deploy/docker-compose.yml" | awk '{print $1+0}')"
done

echo "=== no deploy path creates the CA token under a published PIN ==="
# ⚠️ THE TOKEN HOLDS EVERY CA PRIVATE KEY, so a literal PIN in a tracked file is that key
# material's password published in the repository. certgen already refuses to run without
# FASTPKI_PIN — "refuses to fall back to a well-known value" — but the token is CREATED
# somewhere else, and compose defaulted to `--pin 1234` with the guard intact and bypassed.
#
# The SO PIN is not a lesser case: its purpose is to RESET the user PIN, so `--so-pin 0000`
# hands the token to anyone who can reach it however strong FASTPKI_PIN is. Both must come
# from the environment; the OpenRC service always did it correctly, and this is what stops
# the other paths drifting away from it again.
#
# The cloud bake check is excluded BY LABEL, not by filename: it initialises a throwaway
# token called `bakecheck` in a temp directory with a cleanup trap, purely to prove the
# image's PKCS#11 stack works. It holds nothing.
# ⚠️ THE DEFECT IS THE FALLBACK, NOT A BARE LITERAL. It was written `${FASTPKI_PIN:-1234}`
# and `${HSM_SO_PIN:-0000}` — a variable reference, so a check for a literal argument finds
# nothing and passes. (Written that way first, and it passed against the unfixed file.) What
# has to be asserted is that a PIN variable's DEFAULT is either empty or another variable.
LITERAL=""
for f in "$ROOT/deploy/docker-compose.yml" "$ROOT/deploy/k8s/token.sh" \
         "$ROOT/deploy/k8s/env.sh" "$ROOT/deploy/native/openrc/fastpki-token.initd"; do
    [ -f "$f" ] || continue
    # any *PIN:-<something> where <something> is neither empty nor a $-reference
    if grep -oE '[A-Z_]*PIN:-[^}"]*' "$f" | grep -qvE 'PIN:-(\$|$)'; then
        LITERAL="$LITERAL $(basename "$f")"
    fi
    # and no bare literal argument either
    if grep -oE -- '--(so-)?pin +[0-9A-Za-z]' "$f" >/dev/null 2>&1; then
        LITERAL="$LITERAL $(basename "$f")"
    fi
done
chk "no token PIN is a literal in a tracked deploy file" "" "${LITERAL# }"
# ⚠️ THE ONLY ONE, NOT "ONE OF THEM". `grep -rl … | grep -qx <provision.sh>` asked whether
# the bake check is AMONG the files carrying a literal PIN, so a second file publishing one
# — necessarily outside the closed four-file loop above, which is the only way one gets here
# unseen — left this green with a real CA token's SO PIN in the repository. The whole list is
# compared now, and it looks for any literal PIN ARGUMENT rather than the one string
# `--so-pin 0000`, so `--so-pin 9999` in a new deploy script is caught too. A `"$VAR"` or
# '$VAR' argument does not match: a literal starts with an alphanumeric, the same test the
# loop above uses.
# The walk covers the whole deploy tree minus the two gitignored areas a working copy
# carries — deploy/lab/ (this lab's own plumbing) and a generated deploy/.env — neither of
# which ships, and either would fail the check on the developer's machine rather than on a
# defect.
PIN_LITERAL_FILES="$(cd "$ROOT" && grep -rlE -- '--(so-)?pin +[0-9A-Za-z]' deploy 2>/dev/null \
                     | grep -vE '^deploy/(lab/|\.env)' | sort | tr '\n' ' ')"
chk "  and the bake check is the only literal anywhere" \
    "deploy/cloud/image/provision.sh" "${PIN_LITERAL_FILES% }"
chk "  which uses a throwaway token, not the CA's" yes \
    "$(grep -q -- '--label bakecheck' "$ROOT/deploy/cloud/image/provision.sh" && echo yes || echo no)"

echo
echo "=== DEPLOY DEFAULTS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
