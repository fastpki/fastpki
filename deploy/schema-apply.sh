#!/usr/bin/env bash
# deployment-path: any — driven by $PSQL, which is a compose exec, a kubectl exec or a bare psql
# deploy/schema-apply.sh — bring an EXISTING database up to the schema this release
# needs. Schema changes are an explicit, ordered step of the
# deployment, run BEFORE the new binaries roll — not a migration runner inside them.
#
#   ./schema-apply.sh                 # apply everything pending
#   ./schema-apply.sh --check         # report only; exit 1 if anything is pending
#
# $PSQL may be a wrapper that runs psql elsewhere — step SQL is fed on stdin so it
# crosses a container boundary:
#   PSQL="docker compose exec -T postgres psql -U fastpki -d fastpki" ./schema-apply.sh
#   PSQL="kubectl exec -i -n fastpki fastpki-node-0 -c postgres -- psql -U fastpki -d fastpki" ./schema-apply.sh
#     (on Kubernetes, the server pod whose database is read-write — fastpki-node-0 unless promoted)
#
# HOW IT FITS THE ROLLOUT. Each step must leave the database readable AND writable by
# BOTH the old and the new binaries, because a rolling update runs them side by side
# against one database for the length of the rollout. That is the expand/contract rule:
#
#   expand    add the new column/table, nullable, written by nobody. Old code ignores it.
#   migrate   new code writes both shapes; a backfill fills history. Both versions work.
#   contract  once every replica is new, stop writing the old shape and drop it.
#
# Only expand and contract touch the schema, and each is compatible with the version on
# either side. A step that is not safe in a mixed rollout does not belong here — it
# belongs in a maintenance window, and should say so in its own header.
#
# RUN IT ON EVERY MESH NODE. schema_version is node-local under LOGICAL replication and is
# deliberately not carried (see src/tools/mesh.cpp): it describes one database's own state.
# In a multi-DC mesh, apply the step at each DC as you roll that DC.
#
# ⚠️ AN HA PAIR IS THE OPPOSITE — APPLY ON THE PRIMARY ONLY. A pair is one database
# streamed byte-for-byte, so the step AND the schema_version row it writes both reach the
# standby on their own. Running this there is a no-op when the step has already arrived,
# and `ERROR: cannot execute ALTER TABLE in a read-only transaction` when it has not —
# on a database that is perfectly healthy. Measured on a pair: primary 1 -> 2, standby
# read 2 with the new column, seconds later, nothing run on it.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
STEPS="${SCHEMA_STEPS_DIR:-$HERE/../sql/steps}"
PSQL="${PSQL:-psql}"

# ⚠️ `psql -W` TAKES NO ARGUMENT, SO `-W <password>` IS A CREDENTIAL IN ARGV.
#
# This is the shape behind the long-running "extra command-line argument ... ignored"
# report, and it is worth being precise about what it does, because none of it is what
# the operator intended:
#
#   * psql reads `-W` as "prompt me", and the token after it as a POSITIONAL — psql's
#     positionals are [dbname [username]], and with -d/-U already given it has nowhere to
#     put it, so it warns and DISCARDS it. The password never authenticates anything.
#   * the token is still in argv, so it is visible in `ps` to every user on the box, for
#     as long as the command runs, once per schema step.
#   * `-W` also forces a prompt, which in a script feeding SQL on stdin is a hazard of its
#     own.
#
# So it is repaired rather than reported: the token moves to PGPASSWORD, where it actually
# authenticates and where it stays out of every argv, and `-W` goes with it. Deliberately
# NARROW — only a `-W` followed by a NON-FLAG token, which psql cannot use and which no
# correct command line contains. A bare `psql -W -U fastpki` is a legitimate request to be
# prompted and is left exactly as written.
_pw_in_argv=$(printf '%s' "$PSQL" | awk '{for(i=1;i<NF;i++) if($i=="-W" && substr($(i+1),1,1)!="-"){print $(i+1); exit}}')
if [ -n "$_pw_in_argv" ]; then
    PSQL=$(printf '%s' "$PSQL" | awk '{o=""; for(i=1;i<=NF;i++){ if($i=="-W" && i<NF && substr($(i+1),1,1)!="-"){i++; continue} o=o $i " "} print o}' | sed 's/ *$//')
    if [ -z "${PGPASSWORD:-}" ]; then PGPASSWORD="$_pw_in_argv"; export PGPASSWORD; fi
    # ⚠️ SILENT ON PURPOSE. This used to print a three-line note explaining the move.
    # Asked to drop it: the operator whose PSQL carries `-W <password>` already knows what
    # they typed, and a lecture on every run of every step is noise. The REPAIR is the
    # point and it still happens -- the password leaves argv either way, which is the part
    # that mattered. Nothing about the outcome changed, only the commentary.
fi
unset _pw_in_argv

CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

# install.sh worked but asked for the postgres password several times, when it could
# read it from .env — and it should have.
#
# TWO causes, and the second is the one that made it ask REPEATEDLY.
#
# 1. This script lifted POSTGRES_USER and POSTGRES_DB out of .env and not the PASSWORD,
#    so anything reaching a server that wants one had to ask. Exported here, once, before
#    any probe — the same file compose itself reads.
[ -z "${PGPASSWORD:-}" ] && [ -f "$HERE/.env" ] && {
    _p="$(sed -n 's/^POSTGRES_PASSWORD=//p' "$HERE/.env" | head -1)"
    [ -n "$_p" ] && { PGPASSWORD="$_p"; export PGPASSWORD; }
    unset _p
}

# ⚠️ STDERR, THE SAME STREAM psql WARNS ON — otherwise the position of a psql message
# among these lines means nothing. This script's progress went to stdout while every
# psql diagnostic goes to stderr, so the two interleave by buffering rather than by
# order, and a warning that appeared to sit between "applying X" and the next line could
# have come from any call in the run. That is not a cosmetic difference: a report of
# "psql printed a warning here" is only actionable if "here" is real.
say(){ printf '== %s\n' "$*" >&2; }
# ⚠️ `-w` — NEVER PROMPT, on EVERY psql call and not just this probe. It was added here in
# 82ddd80 and missed on the three invocations that do the actual work (the step apply, the
# trigger regeneration and the subscription refresh), so the prompts simply moved from the
# probes to the steps — which is what the re-test showed: a `Password:` under
# "applying 0028-…" and another under "regenerating conflict-resolution triggers".
#
# The detection below probes with a bare `psql` FIRST and falls
# back to the compose service only when that fails, and `q` is called several times on the
# way. Without -w each of those probes stops and asks for a password, which is exactly the
# "a few times" he saw: they were not one prompt repeated by accident, they were separate
# probes each blocking. With -w a server that needs a credential we do not have fails
# immediately and the fallback gets its turn.
q(){ $PSQL -w -tAq -c "$1"; }

# A database that predates the table reports 0, which is exactly right: every step is
# pending. Do not create the table here — `sql/createdb.sql` owns the schema, and a
# tool that both defines and migrates the schema is the runner option C rejected.
current() {
    local v
    # `|| echo 0` on the pipeline would not fire: head/tr succeed on empty input even
    # when psql failed, so the pipeline exits 0 and prints nothing. Capture, then decide.
    v="$(q "SELECT COALESCE(MAX(version),0) FROM schema_version" 2>/dev/null | head -1 | tr -d ' ')"
    case "$v" in ''|*[!0-9]*) echo 0 ;; *) echo "$v" ;; esac
}

# FIND THE COMPOSE DATABASE OURSELVES rather than making the operator describe it.
# The old failure told them to set PSQL to a `docker compose exec` wrapper, and the very
# natural next move — using the CONTAINER name from `docker compose ps`
# (fastpki-postgres-1) — is rejected by compose, which wants the SERVICE name (postgres).
# That is exactly what happened, and it had to be worked out from `docker compose ps` output
# that shows both columns. The whole detour is avoidable: if this script is sitting next to
# a docker-compose.yml whose postgres service is up, that IS the database.
if ! q "SELECT 1" >/dev/null 2>&1 && [ -z "${PSQL_EXPLICIT:-}" ] && [ "${PSQL}" = "psql" ]; then
    if command -v docker >/dev/null 2>&1 && [ -f "$HERE/docker-compose.yml" ]; then
        _u="fastpki"; _d="fastpki"
        # The credentials live in the .env compose already reads; fall back to the
        # image defaults the compose file itself uses.
        [ -f "$HERE/.env" ] && {
            _v="$(sed -n 's/^POSTGRES_USER=//p' "$HERE/.env" | head -1)"; [ -n "$_v" ] && _u="$_v"
            _v="$(sed -n 's/^POSTGRES_DB=//p'   "$HERE/.env" | head -1)"; [ -n "$_v" ] && _d="$_v"
        }
        for _svc in postgres; do
            # ⚠️ `-e PGPASSWORD` WITH NO VALUE, and that is the whole point.
            #
            # $PSQL is a COMMAND STRING that every call site expands UNQUOTED, so it is
            # word-split on purpose — which means no value inside it may contain a space or
            # a shell metacharacter. The password is the one value that can: install.sh
            # GENERATES [A-Za-z0-9] but also lets the operator TYPE one
            # (`ask PG_PASSWORD "Postgres password (blank = generate one)"`), and a typed
            # password with a space would fragment here into positional arguments:
            #     psql: warning: extra command-line argument "<db password>" ignored
            #
            # ⚠️ THAT IS A REAL HAZARD BUT IT IS NOT WHAT THE REPORTED WARNING WAS. This
            # comment used to claim the field report showed exactly that fragmentation. It
            # cannot have: the password in that report is 32 characters of [A-Za-z0-9] with
            # no space or metacharacter, so it is a single shell word on every path here
            # and cannot become a positional by splitting. The mechanism was written down
            # because it was plausible and fitted the message, not because it was measured
            # — and it then read as a settled explanation to anyone who came after.
            # The reported warning remains unexplained; do not treat it as closed.
            #
            # Bare `-e VAR` makes docker forward the value from OUR environment, so the
            # secret never appears in any argv at all. That also keeps it out of `ps`,
            # which is the same reason the console passes secrets to children by env.
            _try="docker compose -f $HERE/docker-compose.yml exec -T -e PGPASSWORD $_svc psql -U $_u -d $_d"
            if PSQL="$_try" q "SELECT 1" >/dev/null 2>&1; then
                PSQL="$_try"
                say "using the running compose database (service '$_svc', user '$_u')"
                break
            fi
        done
    fi
fi

# ⚠️ SAY WHICH CLIENT WON, WITH ANY CREDENTIAL REDACTED.
#
# Three paths can supply it — an operator's PSQL, a bare `psql` reaching a server the
# environment already points at, or the compose fallback below — and until now only the
# compose one announced itself. A report of "psql printed a warning" was then unanswerable
# without the reporter's machine, because nothing said which command had actually run.
#
# ⚠️ THIS USED TO PRINT $PSQL RAW, UNDER A COMMENT CLAIMING IT CARRIED NO SECRET. That claim
# was wrong, and wrong in exactly the case this diagnostic exists to debug: `psql -W` takes
# NO argument, so an operator who writes `-W <password>` leaves the password sitting in
# argv as a discarded positional — which is the very misuse that produced the report this
# line was added to explain. The line then echoed it into the terminal, and from there into
# a pasted bug report. A diagnostic that prints a command line must assume that command
# line contains a credential, because the ones worth debugging are the malformed ones.
#
# Redaction is targeted rather than clever: a token after a bare `-W`, and the value of
# PGPASSWORD= or a conninfo password=. Anything it does not recognise is still printed, so
# this reduces exposure without pretending to be a general secret scrubber.
redact_psql(){
    printf '%s' "$*" | awk '{
        for (i = 1; i <= NF; i++) {
            # ⚠️ ONLY a NON-FLAG token after -W. Correct usage takes no argument, so the
            # next token is normally another option and redacting it blindly mangles a
            # perfectly good command line — `psql -W -U fastpki` became `-W <redacted>
            # fastpki`, hiding the username and reading as though a secret had been found.
            # A leaked password is the token that does NOT start with a dash.
            if ($i == "-W" && i < NF && substr($(i+1),1,1) != "-") { printf "-W <redacted> "; i++; continue }
            if ($i ~ /^PGPASSWORD=/)  { printf "PGPASSWORD=<redacted> ";  continue }
            if ($i ~ /^password=/)    { printf "password=<redacted> ";    continue }
            printf "%s ", $i
        }
    }' | sed 's/ $//'
}
say "database client: $(redact_psql "$PSQL")"

if ! q "SELECT 1" >/dev/null 2>&1; then
    # Redacted for the same reason as the line above — this is the path a MALFORMED PSQL
    # reaches, so it is the likeliest of all of them to be carrying a credential in argv.
    echo "FAIL: cannot reach the database with PSQL='$(redact_psql "$PSQL")'." >&2
    echo "      Set PGHOST/PGPORT/PGUSER/PGDATABASE/PGPASSWORD, or PSQL to a wrapper." >&2
    echo "      With the compose stack, the SERVICE name is 'postgres' — NOT the container" >&2
    echo "      name 'fastpki-postgres-1' that 'docker compose ps' shows in its first column:" >&2
    echo "        PSQL='docker compose exec -T postgres psql -U fastpki -d fastpki' ./schema-apply.sh" >&2
    echo "      Or reach the published port directly:" >&2
    echo "        PSQL='psql -U fastpki -d fastpki -h 127.0.0.1 -p 5432' ./schema-apply.sh" >&2
    exit 1
fi

HAVE="$(current)"
say "database schema version: $HAVE"

# ⚠️ ON A STANDBY THERE IS NOTHING TO DO, AND IT SAYS SO. The header above says a pair applies
# steps on the primary alone; this is where that is kept rather than left to whoever runs it.
# Run on a standby, the trigger step wrote to a read-only database and failed, and every
# caller stopped: deploy/rolling-update.sh refused to roll a lab pair's standby at all, with
# advice about MESH_BIN that had nothing to do with it, and a native re-install on a standby
# runs this same script. The steps and the triggers both reach a standby by replication.
if [ "$(q 'SELECT pg_is_in_recovery()' 2>/dev/null | tr -d '[:space:]')" = t ]; then
    say "this database is a standby: its schema steps and replication triggers arrive from"
    say "the primary by replication, so there is nothing to apply here. Apply them on the"
    say "primary; a release that changes the schema needs the primary done first."
    exit 0
fi

# ── Regenerate the conflict-resolution triggers ─────────────────────────────────
# A schema step can leave a PL/pgSQL trigger body naming a column that no longer exists.
# Postgres does NOT re-check a function body when a column is renamed, so `fastpki-mesh`'s
# generated `fastpki_lww_<t>()` / `fastpki_<t>_skip_dup()` keep the old name and fail only
# when a row actually replicates — as an apply worker that errors, exits, restarts and
# errors again, on a publisher that reads perfectly healthy.
#
# Measured on the lab: a rename of `role_permissions.ca_id` -> `scope`, the generator was
# updated in the same commit, and nothing re-ran it against the live databases. Both apply
# workers on all three DCs jammed for hours — ~1700 errors per node in two hours — and the
# only outward sign was the postgres log. The publication, the subscriptions and the
# schema_version were all correct.
#
# So: re-emit them here, from the same generator that owns their shape, every time. The
# SQL is CREATE OR REPLACE / DROP ... IF EXISTS throughout, so a run that changes nothing
# is a no-op. Topology-independent, hence `--triggers` needs no topology file.
regen_triggers() {
# ⚠️ A COMMAND, not a path — same shape as $PSQL, and for the same reason. On a DC the
# binary lives inside the image while this script runs on the host, so the working value is
# a wrapper:  MESH_BIN='docker compose exec -T web fastpki-mesh'. Expanded unquoted so a
# multi-word wrapper splits; `command -v` on the first word is what decides whether it is
# runnable at all.
MESH_BIN="${MESH_BIN:-$(command -v fastpki-mesh 2>/dev/null || echo "$(dirname "$0")/../build/fastpki-mesh")}"
# ⚠️ ONLY A NODE THAT REPLICATES NEEDS THEM, AND ON ONE THAT DOES A GAP IS FATAL.
# The conflict-resolution triggers decide which version of a row survives, so skipping the
# regeneration after a step that added or reshaped a replicated table leaves those tables
# with NO last-writer-wins resolution, and the node keeps reporting healthy while
# conflicting rows resolve arbitrarily. A standalone node has no triggers to refresh:
# `fastpki-mesh --node` installs them, together with the publication, when a node joins.
# Asked FIRST, so a standalone node never runs the generator at all — on Kubernetes that
# is a one-shot pod of the new image, which is not free.
#
# A publication is the honest test for "does this node replicate": fastpki-mesh creates one
# on every node that participates, and nothing else does.
if [ "$(q "SELECT count(*) FROM pg_publication WHERE pubname='fastpki_pub'" 2>/dev/null | tr -d ' ')" != "1" ]; then
    say "no publication on this node — nothing replicates, so the conflict-resolution triggers are not needed"
    return 0
fi
trigger_gap() {
    echo "FAIL: $1" >&2
    echo "      This node REPLICATES (fastpki_pub exists), so the conflict-resolution" >&2
    echo "      triggers decide which version of a row survives. Continuing would leave" >&2
    echo "      the replicated tables with no last-writer-wins resolution while every" >&2
    echo "      health check still reports green." >&2
    echo "      Fix: re-run with MESH_BIN pointing at the image you are rolling TO, e.g." >&2
    echo "      MESH_BIN='docker run --rm <image> fastpki-mesh' $0" >&2
    exit 1
}
set -- $MESH_BIN
command -v "$1" >/dev/null 2>&1 || [ -x "$1" ] \
    || trigger_gap "fastpki-mesh not found (set MESH_BIN) — the replication triggers were NOT regenerated."
say "regenerating conflict-resolution triggers"
# ⚠️ GENERATE TO A FILE, CHECK IT, THEN APPLY. Piped straight into psql, a generator that
# failed — an image that would not pull, a pod that never started — handed psql an EMPTY
# script, psql succeeded on it, and the pipeline's status was psql's: "regenerated" with
# nothing applied. The header line is what `fastpki-mesh --triggers` prints first, so its
# absence also catches a wrapper that wrote something else to stdout.
_trig="$(mktemp)"
if ! $MESH_BIN --triggers > "$_trig" 2>/dev/null || ! head -1 "$_trig" | grep -q '^-- Conflict-resolution triggers'; then
    rm -f "$_trig"
    trigger_gap "the trigger generator failed or printed something else ('$MESH_BIN --triggers')."
fi
if ! $PSQL -w -v ON_ERROR_STOP=1 -q < "$_trig" >/dev/null 2>&1; then
    rm -f "$_trig"
    trigger_gap "could not apply the regenerated replication triggers."
fi
rm -f "$_trig"
}

# ⚠️ A TABLE ADDED TO createdb.sql REACHES A NEW INSTALL ONLY, and until the release there
# are no migration steps to carry it to an existing one — that is a deliberate decision, not
# an oversight (see the schema rules: a schema change is an edit to createdb.sql and nothing
# else, because nothing deployed has contents that must survive).
#
# The decision is fine. Discovering its consequence from a crash loop is not. Measured on an
# update of a deployment a few days old: five tables added since that install were simply
# absent, schema_version read 1 on BOTH the old and the new deployment so nothing detected the
# gap, this script said "nothing to apply", and the rollout then died on
#
#     fatal: list_cert_profiles: ERROR: relation "cert_profiles" does not exist
#
# after replacing three services — leaving the deployment on two different images, which is
# the state a rolling update exists to avoid.
#
# So: compare the tables createdb.sql declares against the ones the database has, and refuse
# BEFORE anything is rolled. Cheap, and it turns a mid-rollout casualty into a list of names.
#
# ⚠️ NOT REPAIRED AUTOMATICALLY. `create table if not exists` would make the missing ones and
# leave the rest alone, which is tempting and wrong as a default: it cannot fix a table that
# exists with an older SHAPE, so it would repair the easy half of a gap and report success for
# the whole of it. The operator is told what is missing and decides.
#
# And the answer it points at is REBUILD, not hand-written DDL. Until the first public release
# there are no deployments whose contents have to survive — that is the same reasoning that
# says a schema change is an edit to createdb.sql and nothing else. Migration steps come back
# with the first change made after a real deployment exists.
check_declared_tables() {
    local schema="$HERE/../sql/createdb.sql"
    [ -r "$schema" ] || return 0
    local want have missing t
    # ⚠️ NO `\+` — BSD sed does not take it, and this script runs on a Docker host as often
    # as in the image. The GNU-only form matched nothing at all on macOS, which made the whole
    # check a silent no-op: it would have "passed" on every deployment by finding no tables to
    # want. A check that cannot fail is worse than no check, because it reads as coverage.
    want=$(sed -n 's/^[[:space:]]*create table if not exists  *\([A-Za-z_][A-Za-z0-9_]*\).*/\1/p' \
             "$schema" | sort -u)
    # So: refuse to be a no-op. createdb.sql declares dozens of tables; finding none means the
    # pattern stopped matching, not that the schema emptied.
    if [ -z "$want" ]; then
        echo "FAIL: could not read any table name out of $schema — the extraction is broken," >&2
        echo "      so this check cannot tell whether the database is complete." >&2
        return 1
    fi
    have=$(q "SELECT tablename FROM pg_tables WHERE schemaname='public'" 2>/dev/null \
             | tr -d ' ' | sort -u)
    # An empty answer means the database could not be read, not that it has no tables. Saying
    # "every table is missing" there would be a confident lie about a connection problem.
    [ -n "$have" ] || return 0
    missing=""
    for t in $want; do
        printf '%s\n' "$have" | grep -qx "$t" || missing="$missing $t"
    done
    [ -n "$missing" ] || return 0
    echo "FAIL: this database is missing tables that sql/createdb.sql declares:" >&2
    for t in $missing; do echo "        $t" >&2; done
    echo "" >&2
    echo "      They were added after this deployment was installed. createdb.sql only runs" >&2
    echo "      against an empty database, and there are no migration steps before the" >&2
    echo "      release, so nothing creates them on a live one." >&2
    echo "" >&2
    echo "      NOTHING has been rolled. Services reading those tables would crash-loop on" >&2
    echo "      the new image, part-way through, leaving the deployment on two images." >&2
    echo "" >&2
    echo "      Until the first public release the answer is to REBUILD: recreate the" >&2
    echo "      database and let sql/createdb.sql make it. There are no deployments whose" >&2
    echo "      contents have to survive, which is why there are no migration steps." >&2
    echo "" >&2
    echo "      If this deployment's contents DO matter to you, create the tables above from" >&2
    echo "      sql/createdb.sql on the PRIMARY — a physical standby receives them" >&2
    echo "      automatically — and run this again." >&2
    return 1
}
check_declared_tables || exit 1

if [ ! -d "$STEPS" ]; then
    say "no steps directory ($STEPS) — nothing to apply"
    regen_triggers
    exit 0
fi

# Steps are NNNN-name.sql, applied in numeric order. A step is pending when its number
# is greater than the database's current version.
PENDING=""
for f in "$STEPS"/[0-9]*.sql; do
    [ -e "$f" ] || continue
    b="$(basename "$f")"
    n="${b%%-*}"
    case "$n" in ''|*[!0-9]*) echo "FAIL: '$b' is not NNNN-name.sql" >&2; exit 1 ;; esac
    # 10#: force base 10 so 0009 is nine, not an invalid octal literal.
    if [ "$((10#$n))" -gt "$((10#$HAVE))" ]; then PENDING="$PENDING $f"; fi
done

if [ -z "$PENDING" ]; then
    # ⚠️ Regenerate even with NOTHING pending. The triggers can be stale independently of
    # the version number: a step that renamed a column bumps schema_version and is then
    # "applied" forever, while the generated PL/pgSQL still names the old column. That is
    # exactly how that rename jammed every apply worker on a mesh reporting version 18
    # everywhere. Re-running this script must be able to REPAIR that, and it could not if
    # the repair sat behind a pending step.
    say "up to date — nothing to apply"
    regen_triggers
    exit 0
fi

say "pending:$(for f in $PENDING; do printf ' %s' "$(basename "$f")"; done)"
if [ "$CHECK_ONLY" -eq 1 ]; then
    echo "FAIL: schema steps are pending. Run $0 before starting the new binaries." >&2
    exit 1
fi

# Show a step's psql diagnostics, minus the two nested-transaction notices explained at
# the call site. `grep -v` exits 1 when it prints nothing -- which is the ordinary case for
# a clean step -- and this script runs under `set -e`, so the `|| true` is load-bearing:
# without it a step that produced no other output would abort the whole apply.
_step_stderr(){ grep -vE 'WARNING:[[:space:]]+there is (already a|no) transaction in progress' "$1" >&2 || true; }

# Each step file is responsible for its own INSERT INTO schema_version, so applying it
# and recording it are ONE transaction. Recording separately would let a crash between
# the two leave a step applied but pending — and a re-run of a non-idempotent step.
for f in $PENDING; do
    b="$(basename "$f")"
    say "applying $b"
    # Fed on STDIN, not `-f`: $PSQL may be a wrapper that runs psql somewhere else
    # (`docker compose exec -T postgres psql`, `kubectl exec -i …`), and `-f` would
    # look for the file over THERE. Stdin crosses the container boundary; a path
    # does not — and the failure would be a confusing "No such file or directory"
    # for a file that plainly exists.
    # ⚠️ TWO WARNINGS THAT SAY NOTHING TO AN OPERATOR AND READ LIKE A PROBLEM:
    #
    #     WARNING:  there is already a transaction in progress
    #     WARNING:  there is no transaction in progress
    #
    # Every step runs under --single-transaction, so a step that also opens its own
    # BEGIN/COMMIT makes psql say so twice: once for the nested BEGIN, once for the
    # wrapper's COMMIT finding the transaction already closed. Five shipped steps do
    # this, and a shipped step is immutable -- editing one is a no-op against exactly
    # the databases it targets -- so they will produce these two lines on every fresh
    # install for good. They are cosmetic HERE only because COMMIT is the last
    # statement in all five, which is asserted by tests/schema_step_transactions.sh.
    # That guard is what keeps this filter from ever hiding a NEW step's warning.
    #
    # Nothing else is filtered, and psql localises these strings -- under a non-English
    # server locale they simply do not match and are shown, which is the old behaviour.
    _serr="$(mktemp)"
    if ! $PSQL -w -v ON_ERROR_STOP=1 --single-transaction < "$f" >/dev/null 2>"$_serr"; then
        _step_stderr "$_serr"; rm -f "$_serr"
        echo "FAIL: '$b' did not apply. The database is unchanged by this step" >&2
        echo "      (it ran in one transaction). Nothing after it was attempted." >&2
        echo "      Do NOT start the new binaries: they will refuse anyway." >&2
        exit 1
    fi
    _step_stderr "$_serr"; rm -f "$_serr"
done

# ── refresh the subscribers ────────────────────────────────────────────────────
# A step changes the schema on THIS node. Replication does not follow on its own: a
# subscriber keeps using the table set and column lists it last resolved, so a table a
# step added, or a column list a step narrowed, is invisible to every peer until its
# subscription is refreshed. Nothing else does this — `fastpki-mesh` is a SQL generator an
# operator runs by hand, and no service reconciles the publication.
#
# That is not theoretical: 0010 created `foreign_anchors` and applied cleanly on all three
# lab DCs, after which an anchor registered on one node was invisible on the other two.
# 0002/0005/0006 have the same shape and their comments claimed this script printed a
# reminder about it. It did not. Now it does the work instead of describing it.
#
# OUTSIDE the loop above, and outside any transaction: ALTER SUBSCRIPTION ... REFRESH
# cannot run inside a transaction block, and every step is applied with
# --single-transaction, so a step could never do this itself.
#
# REFRESH only copies tables NEWLY added to the subscription; tables already replicating
# are untouched and no data is re-copied. Scoped to the current database because
# pg_subscription is a SHARED catalog listing every database's subscriptions.
SUBS="$(q "SELECT subname FROM pg_subscription
            WHERE subdbid = (SELECT oid FROM pg_database WHERE datname = current_database())
              AND subenabled" 2>/dev/null | tr -d ' \r')"
if [ -n "$SUBS" ]; then
    for sub in $SUBS; do
        say "refreshing subscription $sub"
        # A peer that is unreachable right now must not fail the schema apply: the schema
        # IS updated, and a refresh can be retried by re-running this script. Reported
        # loudly rather than swallowed, because a missed refresh is invisible otherwise.
        if ! $PSQL -w -v ON_ERROR_STOP=1 -c "ALTER SUBSCRIPTION $sub REFRESH PUBLICATION" >/dev/null 2>&1; then
            echo "WARN: could not refresh subscription '$sub' — the schema is applied, but" >&2
            echo "      this node's peers may not replicate newly published tables until" >&2
            echo "      '$0' is re-run or the refresh is issued by hand." >&2
        fi
    done
else
    say "no enabled subscriptions — nothing to refresh"
fi

regen_triggers

say "now at version $(current)"
