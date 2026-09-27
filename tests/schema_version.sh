#!/usr/bin/env bash
# Schema version guard + the ordered deploy step.
#
# The failure this exists to prevent, in full: `bfee7b4` added `certs.cert_id`, the
# running lab databases never got it, and fastpki-cmp crash-looped on
#   ERROR:  column "cert_id" does not exist
# with nothing in the log pointing at the schema. It had to be applied by hand on three
# DCs. In production that is an outage with a misleading error, during what the operator
# was told was a routine update.
#
# So assert the four properties that turn that into a non-event:
#   1. a database built from createdb.sql is already at the version the binary needs;
#   2. a binary REFUSES to start against an older schema, and says what to run;
#   3. schema-apply.sh applies pending steps in order and is idempotent;
#   4. a NEWER database is accepted — without this, expand/contract is impossible,
#      because a rolling update runs old binaries against the expanded schema.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
W="$(mktemp -d)"; cd "$W"; PORT=18480
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ grep -qF "$2" <<<"$1" && echo yes || echo no; }

pg_setup schema_version
trap 'pg_cleanup' EXIT

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
LOG_LEVEL=err
EOF

# The version the built binary requires, read from the header rather than hardcoded —
# a test that pins the number would have to be edited on every schema bump and would
# quietly stop testing anything if someone forgot.
NEED=$(sed -n 's/^constexpr int kSchemaVersion = \([0-9]*\);.*/\1/p' "$ROOT/include/pki/schema.hpp" | head -1)
chk "schema.hpp declares a version" yes "$([ -n "$NEED" ] && echo yes || echo no)"

echo "=== 1. a fresh createdb.sql database is already current ==="
HAVE=$(pg_exec "SELECT COALESCE(MAX(version),0) FROM schema_version;" | tr -d ' ')
# `db >= required`, NOT equality. The guard in the binaries is a MINIMUM for a reason
# (see schema.hpp): during a rolling update the schema is expanded first and old binaries
# run against a NEWER database. Asserting equality here would make this suite fail on the
# very next pure-expand step — as it did the moment 0002 landed — and would pressure
# whoever hit it into bumping kSchemaVersion, which is exactly the needless downtime
# expand/contract exists to avoid.
chk "fresh database is at least what the binary needs" yes \
    "$([ "$HAVE" -ge "$NEED" ] && echo yes || echo no)"

# Start a real binary against it. fastpki-web needs no CA, so it isolates the guard.
"$ROOT/build/fastpki-web" --config bootstrap.conf >ok.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
chk "binary starts against a current schema" yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"
kill $P 2>/dev/null; wait $P 2>/dev/null

echo "=== 2. an OLDER schema is refused, with the fix named ==="
pg_exec "DELETE FROM schema_version;" >/dev/null
"$ROOT/build/fastpki-web" --config bootstrap.conf >old.log 2>&1
RC=$?
OUT=$(cat old.log)
chk "binary exits non-zero on an old schema" no "$([ "$RC" -eq 0 ] && echo yes || echo no)"
chk "the error names the actual versions"    yes "$(has "$OUT" "version 0 but this build needs $NEED")"
chk "the error names the command to run"     yes "$(has "$OUT" 'deploy/schema-apply.sh')"
# The guard must never be the thing that changes the schema (e18e760 removed in-code
# DDL after a startup 'migration' destroyed two real lab CAs).
STILL=$(pg_exec "SELECT COUNT(*) FROM schema_version;" | tr -d ' ')
chk "a refused start wrote nothing"          0 "$STILL"

echo "=== 3. schema-apply.sh applies pending steps, in order, idempotently ==="
mkdir -p steps
cat > steps/0001-baseline.sql <<'SQL'
insert into schema_version(version,name,applied) values (1,'baseline',0)
  on conflict (version) do nothing;
SQL
cat > steps/0002-probe.sql <<'SQL'
create table if not exists schema_probe(id integer PRIMARY KEY);
insert into schema_version(version,name,applied) values (2,'probe',0)
  on conflict (version) do nothing;
SQL
export PGDATABASE PGHOST PGPORT PGUSER PGPASSWORD
APPLY(){ SCHEMA_STEPS_DIR="$W/steps" PSQL="$PSQL_BIN -h $PGHOST -p $PGPORT -U $PGUSER -d $PGDATABASE" \
         bash "$ROOT/deploy/schema-apply.sh" ${1:-}; }

OUT=$(APPLY 2>&1)
chk "applies both pending steps"        yes "$([ "$(has "$OUT" '0001-baseline.sql')" = yes ] && has "$OUT" '0002-probe.sql')"
chk "step 2 really ran (table exists)"  1   "$(pg_exec "SELECT COUNT(*) FROM information_schema.tables WHERE table_name='schema_probe';" | tr -d ' ')"
chk "version is now 2"                  2   "$(pg_exec "SELECT MAX(version) FROM schema_version;" | tr -d ' ')"

OUT=$(APPLY 2>&1)
chk "a second run is a no-op"           yes "$(has "$OUT" 'up to date')"
chk "--check passes when up to date"    0   "$(APPLY --check >/dev/null 2>&1; echo $?)"

# --check must FAIL while something is pending: that is what stops a rollout.
pg_exec "DELETE FROM schema_version WHERE version=2;" >/dev/null
chk "--check fails while a step is pending" 1 "$(APPLY --check >/dev/null 2>&1; echo $?)"

echo "=== 4. a NEWER schema is accepted (expand/contract needs this) ==="
# During a no-downtime update the schema is expanded FIRST, so for the length of the
# rollout the OLD binaries run against a newer database. An exact-version check would
# refuse exactly then, and option C could not work at all.
pg_exec "INSERT INTO schema_version(version,name,applied) VALUES (99,'future',0) ON CONFLICT DO NOTHING;" >/dev/null
"$ROOT/build/fastpki-web" --config bootstrap.conf >new.log 2>&1 & P=$!
# Poll the listener rather than guessing: see wait_port in pg_helpers.sh.
wait_port "$PORT" "$P" || true
chk "binary starts against a NEWER schema" yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"
kill $P 2>/dev/null; wait $P 2>/dev/null
# The future row is this section's fixture only; left behind, section 6 reads 99 as the
# version the real steps reached.
pg_exec "DELETE FROM schema_version WHERE version=99;" >/dev/null

echo "=== 5. schema_version is not replicated (it is per-node state) ==="
# If it replicated, DC1 applying a step would instantly claim DC2 was upgraded too —
# the precise opposite of what the guard is for during a staggered rollout.
cat > topo.txt <<'EOF'
dc1|host=10.1.0.1 dbname=pki user=repl|1|http://dc1.example
dc2|host=10.2.0.1 dbname=pki user=repl|2|http://dc2.example
EOF
MESH=$("$ROOT/build/fastpki-mesh" --allow-plaintext-transport --topology topo.txt --publication 2>/dev/null || true)
# ⚠️ STRIP THE SQL COMMENTS FIRST. The generator now PRINTS the deliberately-node-local
# table list as a `--` comment so an operator reading the SQL can see what stays behind
# rather than inferring it from an absence — and `schema_version` is in that list, by name.
# Searching the raw output then finds the word in the very comment that documents its
# exclusion and reports the table as published. What this assertion is about is the
# STATEMENT, so that is what it now reads.
MESH_SQL=$(printf '%s\n' "$MESH" | sed 's/--.*//')
chk "the publication was generated"        yes "$(has "$MESH_SQL" 'CREATE PUBLICATION')"
chk "the publication omits schema_version" no  "$(has "$MESH_SQL" 'schema_version')"

echo "=== 6. a database cannot be born unversioned ==="
# The case that actually bit: a database created before schema_version existed had the
# whole schema but no way to say so, so every binary refused to start. Step 0001 existed to
# introduce the table and heal exactly that.
#
# ⚠️ THAT SCENARIO IS NOW UNREACHABLE, and the assertion follows it. The pre-release steps
# were collapsed into sql/createdb.sql, which CREATES schema_version and seeds it in the same
# file, and every published release was born that way. There is no moment at which a
# database has the schema and cannot say so. Asserted on the file rather than by dropping
# the table and hoping a step puts it back.
CREATEDB="$ROOT/sql/createdb.sql"
chk "createdb.sql creates the schema_version table" yes \
    "$(grep -qiE 'create table( if not exists)? +schema_version' "$CREATEDB" && echo yes || echo no)"
chk "  and seeds it in the same file" yes \
    "$(grep -qi 'insert into schema_version' "$CREATEDB" && echo yes || echo no)"
# Anti-vacuity: the seeded number must be the one the binary demands, or a fresh install is
# told at startup to run a migration that does not exist. Same invariant as
# schema_steps_immutable.sh section 1, asserted here against the live NEED this suite read.
SEEDED=$(grep -A1 'insert into schema_version(version, name, applied)' "$CREATEDB" \
           | grep -oE 'values *\( *[0-9]+' | grep -oE '[0-9]+' | tail -1)
chk "  and the seeded version is exactly what the binary requires" "$NEED" "$SEEDED"

# The real steps must carry the database to the required version.
if [ -d "$ROOT/sql/steps" ] && ls "$ROOT"/sql/steps/[0-9]*.sql >/dev/null 2>&1; then
    PSQL="$PSQL_BIN -h $PGHOST -p $PGPORT -U $PGUSER -d $PGDATABASE" bash "$ROOT/deploy/schema-apply.sh" >/dev/null 2>&1
    AFTER=$(pg_exec "SELECT COALESCE(MAX(version),0) FROM schema_version;" | tr -d ' ')
    chk "the real steps carry it to at least the required version" yes \
        "$([ "$AFTER" -ge "$NEED" ] && echo yes || echo no)"
    HEAD_STEP=$(ls "$ROOT"/sql/steps/[0-9]*.sql | sed 's#.*/\([0-9]*\)-.*#\1#' | sort -n | tail -1 | sed 's/^0*//')
    chk "...and to the newest step on disk" "$HEAD_STEP" "$AFTER"
fi

# The binary must start against this database — the whole point of the guard agreeing.
"$ROOT/build/fastpki-web" --config bootstrap.conf >heal.log 2>&1 & P=$!
wait_port "$PORT" "$P" || true
chk "and the binary starts against it" yes "$(kill -0 $P 2>/dev/null && echo yes || echo no)"
kill $P 2>/dev/null; wait $P 2>/dev/null

echo "=== Every deploy path RUNS the schema step ==="
# Reported: a reused database + new binaries, and every service crash-looped on
# the version guard — "the schema step of the deployment was not run (or not run first)".
# rolling-update.sh ran it; install.sh did not, on EITHER branch. The reuse branch is the
# one that needs it most: an existing volume is by definition a database from an older
# build.
#
# ⚠️ Grep-proxies, because running install.sh needs docker and a whole stack. They pin the
# thing that was actually missing — the CALL — rather than anything about its behaviour,
# which schema_version.sh already covers above.
INS="$ROOT/deploy/install.sh"
# ⚠️ COMMENTS ARE NOT CALLS, and this proxy could not tell the difference. It measured the
# FIRST TEXTUAL MENTION of schema-apply.sh, so a comment naming the file anywhere above the
# postgres line read as "schema is applied before postgres starts" and failed a correctly
# ordered script. It fired the moment install.sh grew a curl-pipe bootstrap whose comments
# and in_tree() predicate name schema-apply.sh as one of the siblings they look for.
#
# A proxy for "is the CALL in the right place" has to ignore comment lines, or it pins prose
# rather than code — and the header above says the point is to pin the call.
# An INVOCATION is `bash "$HERE/schema-apply.sh"`. The file is also named by an existence
# test in in_tree() and by two operator messages, none of which run anything — matching the
# bare filename counted all four and put the "first call" 128 lines before the real one.
ins_code() { grep -vE '^[[:space:]]*#' "$INS"; }
ins_call() { ins_code | grep -nE '(bash|sh|exec)[[:space:]]+"?[^"]*schema-apply\.sh'; }

chk "install.sh calls schema-apply.sh at all"  yes \
    "$([ -n "$(ins_call)" ] && echo yes || echo no)"
# The reuse branch is textually before the wizard; the fresh branch after the bootstrap
# step. Both must have it, so count rather than merely detect.
chk "  on BOTH the reuse and the fresh path"   yes \
    "$([ "$(ins_call | wc -l | tr -d ' ')" -ge 2 ] && echo yes || echo no)"
# Ordering is the whole point: postgres up, schema applied, THEN the app services.
RB=$(ins_call | head -1 | cut -d: -f1)
PG=$(ins_code | grep -n 'up -d postgres' | head -1 | cut -d: -f1)
chk "  after postgres is started, not before"  yes \
    "$([ -n "$RB" ] && [ -n "$PG" ] && [ "$PG" -lt "$RB" ] && echo yes || echo no)"
# And the hint an operator gets when it cannot connect must name the SERVICE, because the
# container name from `docker compose ps` is what they will reach for first — that is
# exactly the detour reported on the ticket.
SA="$ROOT/deploy/schema-apply.sh"
chk "the failure hint warns service != container name" yes \
    "$(grep -q 'fastpki-postgres-1' "$SA" && echo yes || echo no)"

# ⚠️ …AND BEFORE BOOTSTRAP. `bootstrap` runs fastpki-config, which carries the
# startup guard, so on the path that matters — an old pgdata volume exists and the
# operator DECLINED to reuse it, leaving postgres up on the old schema — bootstrap is
# the binary that refuses, one step before the step that would have fixed it. The two
# calls are ordered in what RUNS and in what the --no-deploy branch PRINTS; both are
# checked, because an operator following the printed list is the other way in.
# ⚠️ THE ANCHORS ARE ASSERTED BEFORE THEY ARE COMPARED. An anchor grep stops matching the
# day the line it looks for is reworded or a variable named in it is removed — and then both
# comparisons run against an EMPTY string, and `[ -n "$BS_RUN" ]` turns the whole ordering
# check into a silent `no`. Measured here once already. A guard whose anchor has drifted must
# say so, not report the thing it guards as broken.
SA_RUN=$(grep -n 'bash "\$HERE/schema-apply\.sh"'      "$INS" | grep -v 'echo' | tail -1 | cut -d: -f1)
BS_RUN=$(grep -n 'docker compose run --rm bootstrap'  "$INS" | grep -v 'echo' | tail -1 | cut -d: -f1)
chk "  the run-path anchors were both found"     "" \
    "$([ -n "$SA_RUN" ] && [ -n "$BS_RUN" ] || echo "SA_RUN='$SA_RUN' BS_RUN='$BS_RUN'")"
chk "  and BEFORE bootstrap, which runs a schema-guarded binary" yes \
    "$([ -n "$SA_RUN" ] && [ -n "$BS_RUN" ] && [ "$SA_RUN" -lt "$BS_RUN" ] && echo yes || echo no)"
SA_DOC=$(grep -n 'echo "  [0-9]\. \./schema-apply\.sh'                  "$INS" | tail -1 | cut -d: -f1)
BS_DOC=$(grep -n 'echo "  [0-9]\. docker compose run --rm bootstrap'    "$INS" | tail -1 | cut -d: -f1)
chk "  the printed-step anchors were both found" "" \
    "$([ -n "$SA_DOC" ] && [ -n "$BS_DOC" ] || echo "SA_DOC='$SA_DOC' BS_DOC='$BS_DOC'")"
chk "  in the printed manual steps too"          yes \
    "$([ -n "$SA_DOC" ] && [ -n "$BS_DOC" ] && [ "$SA_DOC" -lt "$BS_DOC" ] && echo yes || echo no)"

# ⚠️ NOT A GREP-PROXY — the one below RUNS install.sh, because the defect it guards is
# invisible to every grep: `ansval` was CALLED on the database-preservation path and
# DEFINED fifty lines further down, so `set -euo pipefail` killed a non-interactive
# install with `ansval: command not found` (exit 127) before .env was written and long
# before any of the schema-apply calls asserted above could run. A tty never sees it —
# the interactive branch takes `read -r -p` instead — so it survived every hand test.
#
# Self-contained per §3d: a stub `docker` that claims the volume exists, a stub
# schema-apply that leaves a marker, and a copy of install.sh in a temp dir.
IW="$(mktemp -d)"; mkdir -p "$IW/bin"
cat > "$IW/bin/docker" <<'STUB'
#!/bin/sh
case "$1 $2" in "volume inspect") exit 0 ;; esac
exit 0
STUB
chmod +x "$IW/bin/docker"
cp "$INS" "$IW/install.sh"
printf '#!/bin/sh\ntouch "$(dirname "$0")/REACHED"\n' > "$IW/schema-apply.sh"
chmod +x "$IW/schema-apply.sh"
printf 'KEEP_DB=yes\n' > "$IW/answers"
IOUT="$IW/out.txt"
PATH="$IW/bin:$PATH" bash "$IW/install.sh" --answers "$IW/answers" </dev/null >"$IOUT" 2>&1
IRC=$?
chk "a NON-INTERACTIVE install over an existing volume does not abort" 0 "$IRC"
chk "  no helper is called before it is defined"  0 \
    "$(grep -c 'command not found' "$IOUT" 2>/dev/null | head -1)"
chk "  and it REACHES the schema step"           yes \
    "$([ -f "$IW/REACHED" ] && echo yes || echo no)"
[ "$IRC" -eq 0 ] || { echo "  --- install.sh output ---"; sed 's/^/    /' "$IOUT" | head -20; }
rm -rf "$IW"

# Follow-up report: install.sh worked but asked for the postgres password
# a few times. Why? It can get it from .env, right?"
#
# ⚠️ THE REPEAT WAS THE TELL. They were not one prompt shown twice — the script probes with
# a bare `psql` before falling back to the compose service, and `q` runs several times on
# the way, so each probe blocked on its own prompt. Two fixes, both asserted here:
# the password comes out of .env, and no probe may EVER prompt.
chk "schema-apply reads POSTGRES_PASSWORD from .env" yes \
    "$(grep -q "s/\^POSTGRES_PASSWORD=//p" "$SA" && echo yes || echo no)"
chk "  and exports it before any probe runs"        yes \
    "$([ "$(grep -n 'export PGPASSWORD' "$SA" | head -1 | cut -d: -f1)" -lt \
        "$(grep -n 'q "SELECT 1"' "$SA" | head -1 | cut -d: -f1)" ] && echo yes || echo no)"
# ⚠️ The one that actually stops the asking: -w makes psql fail instead of prompting.
chk "every probe runs psql with -w (never prompt)"  yes \
    "$(grep -q 'q(){ \$PSQL -w ' "$SA" && echo yes || echo no)"
chk "  and the compose wrapper carries it inward"   yes \
    "$(grep -q 'exec -T -e PGPASSWORD' "$SA" && echo yes || echo no)"
# ⚠️ THAT ASSERTION WAS TOO WEAK — it matched both the broken and the fixed form, so it
# passed on the very build that was re-tested and reported still prompting. The two
# below are the discriminating halves.
#
# (a) -w ON THE INVOCATIONS THAT DO THE WORK, not only on the probe. 82ddd80 added it to
#     `q()` and missed the step apply, the trigger regeneration and the subscription
#     refresh — so the prompts moved from the probes to the steps, which is exactly the
#     `Password:` under "applying 0028-…" and under "regenerating conflict-resolution
#     triggers" in his paste. Count them: every `$PSQL` that runs SQL must carry -w.
chk "EVERY psql invocation carries -w, not just the probe" 0 \
    "$(grep -cE '\$PSQL (-v|-tAq|-q|<|-c)' "$SA")"
# (b) THE PASSWORD MUST NOT BE INTERPOLATED INTO $PSQL. $PSQL is a command string that
#     every call site expands UNQUOTED — deliberately, so a wrapper like
#     `docker compose exec …` word-splits into argv. A password with a space therefore
#     fragments into extra arguments, and install.sh lets an operator TYPE one. Bare
#     `-e PGPASSWORD` makes docker forward the value from our environment instead, so the
#     secret never reaches an argv at all (and never reaches `ps`).
#     ⚠️ SCOPED TO THE COMMAND-STRING ASSIGNMENTS, AND SPELLING-AGNOSTIC. This knew exactly
#     one spelling — `=` followed immediately by $PGPASSWORD — so the quoted form
#     `-e PGPASSWORD="$PGPASSWORD"`, which is how anyone would naturally "fix" the bare
#     `-e`, slipped past it and passed while the secret sat in the docker argv. What the
#     requirement actually is: no line that BUILDS a psql command string may carry a
#     PGPASSWORD=/password= token at all. Bare `-e PGPASSWORD` has no `=`; every
#     interpolated spelling ($PGPASSWORD, "${PGPASSWORD}", ${_p}, a literal) has one.
#     The env-var assignments that legitimately do PGPASSWORD="$_p" are not command
#     strings and are out of scope, and so is redact_psql's awk, which must contain the
#     token in order to mask it. The second arm, `-e <VAR>PGPASSWORD=`, does not depend on
#     what the command-string variable is called: handing docker a VALUE has no legitimate
#     form here, so it is a violation wherever it is written.
SA_CMD=$(grep -v '^[[:space:]]*#' "$SA" \
         | grep -E '^[[:space:]]*(if[[:space:]]+)?(PSQL|_try)=|-e [A-Za-z_]*PGPASSWORD=')
chk "  the command-string assignments were found"   yes \
    "$([ -n "$SA_CMD" ] && echo yes || echo no)"
chk "  and the password is never interpolated into the command" no \
    "$(printf '%s\n' "$SA_CMD" | grep -qE '(PGPASSWORD|password)=' && echo yes || echo no)"

echo "=== 6. the script never PRINTS a credential that reached \$PSQL anyway ==="
# ⚠️ THIS IS A REAL LEAK THAT HAPPENED, NOT A HYPOTHETICAL. `psql -W` takes NO argument, so
# an operator who writes `-W <password>` leaves it in argv as a discarded positional — the
# exact misuse the "database client:" diagnostic was added to explain. The diagnostic then
# echoed the whole of $PSQL, under a comment asserting it carried no secret, and the value
# travelled from a terminal into a pasted bug report.
#
# The assertion drives the SCRIPT, not the helper: what matters is that no output path
# prints the value, and there are two of them (the client announcement and the FAIL hint).
# A source grep for the helper's name would pass while a third print site leaked.
SECRET='Zq7-not-a-real-password-9Vx'
LEAKOUT=$(PSQL="$PSQL_BIN -h $PGHOST -p $PGPORT -U $PGUSER -d $PGDATABASE -W $SECRET" \
          bash "$ROOT/deploy/schema-apply.sh" 2>&1 || true)
chk "fixture: the run produced output to inspect" yes \
    "$([ -n "$LEAKOUT" ] && echo yes || echo no)"
chk "fixture: it announced which client it used"  yes \
    "$(printf '%s' "$LEAKOUT" | grep -q 'database client:' && echo yes || echo no)"
chk "the password does NOT appear anywhere in the output" no \
    "$(printf '%s' "$LEAKOUT" | grep -qF "$SECRET" && echo yes || echo no)"
# ⚠️ THIS USED TO ASSERT `-W <redacted>` IN THE OUTPUT, and that is no longer the
# behaviour -- it is now weaker than what happens. Redacting the announcement kept the
# password out of the LOG while leaving it in psql's ARGV, where `ps` shows it to every
# user on the box once per step, and where psql discards it anyway because `-W` takes no
# argument. The script now moves the token to PGPASSWORD and drops the flag with it, so
# there is nothing left to redact on this path.
# ⚠️ SCOPED TO THE ANNOUNCED CLIENT LINE. The note explaining the repair necessarily
# quotes `-W` itself, so a whole-output grep matches the explanation and reports the flag
# as still present -- a guard reading its own prose.
chk "  the discarded flag is GONE from the client line, not merely redacted" no \
    "$(printf '%s' "$LEAKOUT" | grep 'database client:' | grep -q -- '-W' && echo yes || echo no)"
# ⚠️ THE NOTE IS GONE BY REQUEST -- it printed on every step of every run for an operator
# who already knew what they had typed. What still has to hold is that the repair happened
# SILENTLY rather than not at all, which no message can testify to any more: the flag is
# absent from the client line, and the secret appears nowhere in the output.
chk "  and the secret is nowhere in the output" no \
    "$(printf '%s' "$LEAKOUT" | grep -qF "$SECRET" && echo yes || echo no)"
# ⚠️ AND REDACTION MUST NOT EAT A LEGITIMATE ARGUMENT. Correct `-W` usage takes no argument,
# so the next token is normally another option; a blind "redact whatever follows -W" hid the
# username and made a healthy command line read as though a secret had been found.
LEGIT=$(PSQL="$PSQL_BIN -W -h $PGHOST -p $PGPORT -U $PGUSER -d $PGDATABASE" \
        bash "$ROOT/deploy/schema-apply.sh" 2>&1 || true)
chk "a bare -W leaves the following FLAG intact"   yes \
    "$(printf '%s' "$LEGIT" | grep -q -- '-W -h' && echo yes || echo no)"

echo
echo "=== SCHEMA VERSION: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
