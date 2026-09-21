#!/usr/bin/env bash
# Interactive install wizard. deploy/install.sh generates a node's
# deploy/.env non-interactively via --answers; for a multi-data-center mesh its
# job is naming THIS node, whose index is also its 2-octet certificate-serial prefix.
# This drives --print-env and asserts the cluster and single-node paths emit the
# right keys and that bad input is refused.
#
# ⚠️ WHAT THIS SUITE MUST *NOT* FIND ANY MORE. It used to assert a 160-bit serial-space
# split — that node_i.MAX == node_{i+1}.MIN, that the thirds were 5555…/aaaa…, that five
# slices tiled [0, ffff…] with no gaps. All of that arithmetic is gone: the wizard writes
# DATACENTER_ID and nothing else, and the prefix reaches the node from its `datacenters`
# row. A serial bound in .env is now the DEFECT, so the assertion below is that no such
# key is emitted at all.
#
# The wizard must still run with no interpreter — an install wizard has to
# work on a bare fresh server that may have neither python3 nor bc — so this suite guards
# that none creeps back in.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
SH="$ROOT/deploy/install.sh"
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
# print-env for a given answers body
gen(){ printf '%s\n' "$1" > ans.env; bash "$SH" --answers ans.env --print-env 2>/dev/null; }
field(){ printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -1; }

echo "=== 3-DC mesh: each node gets its own id, and that id IS its prefix ==="
N1=$(gen "DEPLOYMENT=cluster
DC_INDEX=1")
N2=$(gen "DEPLOYMENT=cluster
DC_INDEX=2")
N3=$(gen "DEPLOYMENT=cluster
DC_INDEX=3")
chk "node1 id"  1 "$(field "$N1" DATACENTER_ID)"
chk "node2 id"  2 "$(field "$N2" DATACENTER_ID)"
chk "node3 id"  3 "$(field "$N3" DATACENTER_ID)"
# ⚠️ NO serial bound may be emitted, by any spelling. The prefix lives in the
# `datacenters` table; a copy in .env would be a second source that can silently disagree
# with the guard trigger, which is the exact failure the ticket removed. Match the whole
# DATACENTER_ prefix rather than the two old key names, so a differently-named bound
# cannot slip back in.
for n in 1 2 3; do
  eval "E=\$N$n"
  chk "node$n emits DATACENTER_ID and no serial bound" "DATACENTER_ID" \
      "$(printf '%s\n' "$E" | sed -n 's/^\(DATACENTER_[A-Z_]*\)=.*/\1/p' | sort -u | tr '\n' ' ' | sed 's/ $//')"
done
# The ceiling, and it is a correctness bound rather than a style choice: 32768 sets the
# high bit of the leading octet, DER integers are signed, so the serial would be padded to
# 21 octets and leave RFC 5280 §4.1.2.2.
printf 'DEPLOYMENT=cluster\nDC_INDEX=32768\n' > toobig.env
bash "$SH" --answers toobig.env --print-env >/dev/null 2>&1
chk "DC_INDEX above 32767 -> non-zero exit" fail "$([ $? -ne 0 ] && echo fail || echo ok)"
printf 'DEPLOYMENT=cluster\nDC_INDEX=32767\n' > atmax.env
chk "  ... and 32767 is accepted" 32767 \
    "$(field "$(bash "$SH" --answers atmax.env --print-env 2>/dev/null)" DATACENTER_ID)"

# ⚠️ A SINGLE NODE IS Data center 1, NOT "no data center", and this assertion used to say the
# opposite. Without an id, set_random_serial() mints FULL-WIDTH serials carrying no prefix —
# so every certificate issued before a later expansion sits outside that node's partition
# forever. The guarantee that two data centers can never mint the same serial would then hold
# only from the conversion onward, and `certs_dc_range` refuses those historical rows on any
# LOCAL insert, which is what a database restore is. Setting it up front costs 16 bits of a
# 160-bit serial — 144 bits of entropy against a 64-bit floor — and nothing reads the prefix
# until a second datacenter exists. So a deployment that never grows pays nothing, and one
# that grows has no seam.
echo "=== single-node: datacenter 1, so it can grow into a mesh later ==="
S=$(gen "DEPLOYMENT=single
PKI_DNS=host.local")
chk "single is data center 1"  "1" "$(field "$S" DATACENTER_ID)"
chk "single carries PKI_DNS"       host.local "$(field "$S" PKI_DNS)"

echo "=== passthrough + optional CMP_CLIENT_CA_ID ==="
P=$(gen "DEPLOYMENT=cluster
DC_INDEX=1
FASTPKI_IMAGE=reg/fastpki:v9
PKI_DNS=pki.acme.test
PG_BIND=10.0.0.1
CMP_CLIENT_CA_ID=clientanchor")
chk "image passthrough"  reg/fastpki:v9 "$(field "$P" FASTPKI_IMAGE)"
chk "PG_BIND passthrough" 10.0.0.1 "$(field "$P" PG_BIND)"
# ⚠️ CMP_CLIENT_CA_ID IS NOT AN INSTALLER QUESTION. It names a registered CA id, and at
# install time no CA exists — the deployment comes first and CAs are created afterwards. The
# only answer an operator could give was blank. It is set later, from the console's Config
# page or `fastpki-config`, and must not reappear in .env from the wizard.
chk "no CMP_CLIENT_CA_ID in the wizard's output" "" "$(field "$P" CMP_CLIENT_CA_ID)"
# ⚠️ AND NEITHER IS A Data center COUNT. It sized nothing and was never stored; asking read
# as a ceiling, so an operator with three sites believed a fourth meant rebuilding the mesh.
chk "no DC_COUNT in the wizard's output"         "" "$(field "$P" DC_COUNT)"

echo "=== bad input is rejected (non-zero exit, no .env) ==="
# ⚠️ A FOURTH Data center IS NOT AN ERROR, and asserting it was is what made the removed
# count read as a ceiling. Index 4 is valid on its own; the bound is 1..32767.
printf 'DEPLOYMENT=cluster\nDC_INDEX=4\n' > ok4.env
chk "a fourth data center installs without touching the others" 4 \
    "$(field "$(bash "$SH" --answers ok4.env --print-env 2>/dev/null)" DATACENTER_ID)"
printf 'DEPLOYMENT=cluster\nDC_INDEX=0\n' > bad.env
bash "$SH" --answers bad.env --print-env >/dev/null 2>&1; chk "DC_INDEX 0 -> non-zero exit" fail "$([ $? -ne 0 ] && echo fail || echo ok)"
printf 'DEPLOYMENT=weird\n' > bad2.env
bash "$SH" --answers bad2.env --print-env >/dev/null 2>&1; chk "bad DEPLOYMENT -> non-zero exit" fail "$([ $? -ne 0 ] && echo fail || echo ok)"
printf 'DEPLOYMENT=cluster\nDC_INDEX=abc\n' > bad3.env
bash "$SH" --answers bad3.env --print-env >/dev/null 2>&1; chk "non-numeric DC_INDEX -> non-zero exit" fail "$([ $? -ne 0 ] && echo fail || echo ok)"

echo "=== the wizard needs no interpreter (runs on a bare server) ==="
# An install wizard runs on a freshly provisioned box: no python3 / no bc. Prove
# install.sh invokes neither, and that it still works with them removed from PATH.
# Any python3/bc token must appear only in comments, never as a command.
chk "no python/bc command (comments aside)" 0 "$(grep -nE '\b(python3?|bc)\b' "$SH" | grep -vE '^[0-9]+:[[:space:]]*#' | grep -c .)"
# ⚠️ `command -v` returns a BARE WORD for a shell builtin or alias, not a path — on this
# machine `printf` (and `grep`, where it is aliased) came back as themselves, so
# `ln -sf printf $BARE/printf` made a self-referential dangling symlink and the "bare
# PATH" was not the set of tools it claimed. Link only what resolves to a real file.
BARE=$(mktemp -d)
for t in bash sed grep printf cut head tr; do
    p=$(command -v "$t" 2>/dev/null)
    case "$p" in /*) ln -sf "$p" "$BARE/$t" 2>/dev/null ;; esac
done
printf 'DEPLOYMENT=cluster\nDC_INDEX=2\n' > np.env
NP=$(PATH="$BARE" bash "$SH" --answers np.env --print-env 2>/dev/null | sed -n 's/^DATACENTER_ID=//p')
chk "cluster env generates with only core utils on PATH" 2 "$NP"
# The wizard must not reach for an external command before it can even find itself.
# `dirname` was the one that did, and the failure was invisible on macOS because bash 3.2
# treats `cd ""` as a successful no-op while Alpine — what we ship — calls it fatal. So
# assert the DEPENDENCY is gone, not just that today's bare set happens to be enough.
chk "install.sh needs no dirname at all" 0 \
    "$(grep -vE '^[[:space:]]*#' "$SH" | grep -c 'dirname' | tr -d ' ')"

echo "=== per-deployment secrets, not shipped defaults ==="
# Until now every deployment that followed docs/deployment.md shared one Postgres password
# (`fastpki`) and one token PIN (`1234`), because both were literals in tracked files.
# The wizard now offers a generated value for each.
S1=$(gen "DEPLOYMENT=single")
S2=$(gen "DEPLOYMENT=single")
PW1=$(field "$S1" POSTGRES_PASSWORD); PW2=$(field "$S2" POSTGRES_PASSWORD)
PIN1=$(field "$S1" FASTPKI_PIN)
chk "a password is generated"        32 "${#PW1}"
chk "a PIN is generated"             32 "${#PIN1}"
# The assertion that matters: generated, not merely present. A constant would pass a
# length check and reproduce the exact bug the ticket is about.
chk "two deployments differ"        yes "$([ "$PW1" != "$PW2" ] && echo yes || echo no)"
chk "and it is not the old default" yes "$([ "$PW1" != fastpki ] && echo yes || echo no)"
chk "nor is the PIN the old 1234"   yes "$([ "$PIN1" != 1234 ] && echo yes || echo no)"
# An answer must win over the generator, and must not kill the wizard. `[ -z X ] && {…}`
# returns 1 when X is set, and under `set -e` that exited the script — supplying your own
# password made the wizard vanish after printing its banner.
OWN=$(gen "DEPLOYMENT=single
PG_PASSWORD=my-own-pw
PKCS11_PIN=my-own-pin")
chk "a supplied password is honoured" my-own-pw  "$(field "$OWN" POSTGRES_PASSWORD)"
chk "a supplied PIN is honoured"      my-own-pin "$(field "$OWN" FASTPKI_PIN)"
# The services read the PIN from a file; the .env value exists only so certgen can write
# that file. Both halves must be present or the token is unusable.
chk "the PIN file is named"     /var/pki/tls/pin "$(field "$S1" PKCS11_PIN_FILE)"
chk "the token is named"                 fastpki "$(field "$S1" PKCS11_TOKEN)"

# The generator must survive the bare PATH too. `tr < /dev/urandom | head -c N` makes head
# close the pipe on an infinite producer; tr dies of SIGPIPE and `set -o pipefail` exits
# the wizard. That failure looked exactly like the wizard printing its banner and stopping.
BS=$(PATH="$BARE" bash "$SH" --answers np.env --print-env 2>/dev/null | sed -n 's/^POSTGRES_PASSWORD=//p')
chk "secrets generate on a bare PATH"  32 "${#BS}"

echo "=== the generated password actually reaches the apps ==="
# A generated password nobody uses is worse than a default: postgres would take the new
# one and every service would still present `password=fastpki`. bootstrap.compose.conf is
# tracked, so it cannot hold a per-deployment secret — compose passes PG_CONNINFO as an
# environment override, which the config parser lets win over the file.
CC="$ROOT/deploy/bootstrap.compose.conf"; DC="$ROOT/deploy/docker-compose.yml"
# COUNTS ROT. This asserted "exactly one PG_CONNINFO:" and broke the moment bootstrap
# legitimately needed the database too (7d2299f) — the code was right and the number was
# stale. What actually matters is that EVERY occurrence carries the generated password
# rather than a literal, and that the tracked file carries no password at all.
NPG=$(grep -cE '^[[:space:]]+PG_CONNINFO:' "$DC")
chk "compose overrides PG_CONNINFO"   yes "$([ "$NPG" -ge 1 ] && echo yes || echo no)"
chk "  every occurrence uses the generated password" "$NPG" \
    "$(grep -A3 -E '^[[:space:]]+PG_CONNINFO:' "$DC" | grep -cF 'password=${POSTGRES_PASSWORD:-fastpki}')"
chk "  and the app services get it"   yes \
    "$(awk '/^  [a-z]/{svc=$1} /^[[:space:]]+PG_CONNINFO:/{print svc}' "$DC" | grep -q . && echo yes || echo no)"
chk "postgres itself takes it"       yes \
    "$(grep -qF 'POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-fastpki}' "$DC" && echo yes || echo no)"
# Presence is not placement. This assertion used to be `grep FASTPKI_PIN "$DC"`, it
# passed, and the key was on the POSTGRES service — where it does nothing, and where it
# created a second `environment:` that made the whole file unparseable. The lab could not
# run `docker compose ps` at all until it was moved.
CERTGEN_ENV=$(awk '/^  certgen:$/{f=1;next} f&&/^  [a-z]/{exit} f' "$DC")
chk "certgen is given the PIN"       yes \
    "$(printf '%s' "$CERTGEN_ENV" | grep -qE 'FASTPKI_PIN' && echo yes || echo no)"
# ...and nothing else is, because a value in the environment is visible in
# `docker inspect` and /proc/<pid>/environ to everything that service runs.
# Same rot, same reason: bootstrap needs the PIN to mint the first CA in the token
# (251b405). The invariant is not "one service" — it is that the value reaches ONLY the
# services that use the token, and never postgres, which is where it broke the YAML and
# did nothing. Assert by service name, not by count.
# ...and the same trap here: the token service's entrypoint writes `$${FASTPKI_PIN:-1234}`,
# which a naive match reads as a key on that service. It is a shell default, not a
# variable the service is GIVEN, so it must not count.
PIN_SVCS=$(awk '/^  [a-z]/{svc=$1} /^[[:space:]]+FASTPKI_PIN:[[:space:]]/{print svc}' "$DC" | tr -d ':' | sort -u | tr '\n' ' ')
chk "the PIN reaches certgen and bootstrap only" "bootstrap certgen " "$PIN_SVCS"
chk "  and never postgres"                       no \
    "$(printf '%s' "$PIN_SVCS" | grep -qw postgres && echo yes || echo no)"

# The compose file must PARSE. Nothing checked this, which is how a duplicate key
# shipped. `docker compose config` is the real check and is used when docker is here;
# the awk pass runs everywhere and catches exactly the duplicate-key class.
DUPS=$(awk '/^  [a-z][a-z0-9_-]*:$/{svc=$1; delete seen}
            /^    [a-z_]+:/{k=$1; if(k in seen) print svc" "k; seen[k]=1}' "$DC")
[ -n "$DUPS" ] && echo "    duplicate service keys: $DUPS"
chk "no service defines a key twice"  "" "$DUPS"
ANCHOR_DUPS=$(awk '/^x-[a-z-]+:/{delete seen} /^  [a-z_]+:/{k=$1; if(k in seen) print k; seen[k]=1}' "$DC")
[ -n "$ANCHOR_DUPS" ] && echo "    duplicate anchor keys: $ANCHOR_DUPS"
chk "nor does the shared anchor"      "" "$ANCHOR_DUPS"
# ⚠️ `docker compose config` USED TO RUN HERE, CONDITIONALLY, and that was the wrong place.
# The harness runs in the production image, which has no docker and must not be handed the
# host socket — a large shell harness with control of the host daemon is effectively root
# on the host. So the full parse moved to tests/run-in-container.sh, which runs it on the
# HOST as a pre-flight and refuses to start the run if the file does not parse. Same
# precedent as deploy/build-image.sh running the hygiene gate on the host because that is
# the only place it CAN run.
#
# The awk checks above stay and now run everywhere unconditionally: they catch the
# duplicate-key class that actually shipped a bug, and they need nothing but the file.
# The override and the file must not disagree about anything EXCEPT the password, or the
# apps would silently get a different host list or TLS mode than the file documents.
FILE_CI=$(sed -n 's/^PG_CONNINFO=//p' "$CC")
norm(){ printf '%s' "$1" | tr ' ' '\n' | grep -vE '^(password=|$)' | sort | tr '\n' ' '; }
# ⚠️ EVERY OVERRIDE, NOT JUST THE FIRST. The continuation pattern used to be a LITERAL six
# spaces and the walk stopped at the first line that did not match, so only the x-fastpki
# anchor's block was ever read — the `bootstrap` service carries its own PG_CONNINFO,
# indented eight, and could have named a different host list or TLS mode than the file
# documents while this still printed PASS. A continuation is now "any line indented deeper
# than its key", so a block is read at whatever depth it sits, the plain one-line form is
# read too, and every value found is compared. A sed RANGE is still the wrong tool: the line
# after a block is LESS indented, not more, so the range never terminates and silently
# swallows the rest of the compose file.
ENV_BLOCKS=$(awk '
    /^ *PG_CONNINFO:/ {
        if (f) print blk
        blk = ""; f = 0; match($0, /^ */); ind = RLENGTH
        val = substr($0, RLENGTH + 1); sub(/^PG_CONNINFO: */, "", val)
        if (val == "" || val ~ /^[>|]/) { f = 1; next }
        gsub(/"/, "", val); print val; next }
    f { match($0, /^ */)
        if (RLENGTH > ind && length($0) > RLENGTH) { blk = blk substr($0, RLENGTH + 1) " "; next }
        print blk; blk = ""; f = 0 }
    END { if (f) print blk }' "$DC" | tr -s ' ' | sed 's/ $//')
# Anti-vacuity, both halves. The apps get their conninfo from this file, so there must BE an
# override; and one extracted value per key, so a reindent, a rename or a folding style the
# walk cannot follow cannot quietly reduce the loop below to nothing — a loop over no values
# reports no disagreement.
CI_KEYS=$(grep -vE '^ *#' "$DC" | grep -cE '^ *PG_CONNINFO:')
chk "the compose file overrides PG_CONNINFO at all" yes \
    "$([ "$CI_KEYS" -gt 0 ] && echo yes || echo no)"
chk "every PG_CONNINFO override was extracted" "$CI_KEYS" \
    "$(printf '%s\n' "$ENV_BLOCKS" | grep -c .)"
CI_BAD=""
while IFS= read -r _blk; do
    [ -n "$_blk" ] || continue
    [ "$(norm "$FILE_CI")" = "$(norm "$_blk")" ] || CI_BAD="$CI_BAD{$_blk}"
done <<ENVCI
$ENV_BLOCKS
ENVCI
chk "every override matches the file but for the password" "" "$CI_BAD"

echo "=== key storage backend ==="
# A private key lives in a token, never a file (§3f) — so the wizard asks WHICH
# token, and "file" is deliberately not an answer. `softhsm` must write NO
# PKCS11_MODULE: compose already defaults it to the p11-kit client shim, and a
# second copy of that default in .env is exactly how the two drift apart.
SOFT=$(gen "DEPLOYMENT=single")
chk "softhsm is the default"              "" "$(field "$SOFT" KEY_BACKEND)"
chk "softhsm writes no PKCS11_MODULE"     "" "$(field "$SOFT" PKCS11_MODULE)"

HSM=$(gen "DEPLOYMENT=single
KEY_BACKEND=hsm
PKCS11_MODULE=/opt/nfast/toolkits/pkcs11/libcknfast.so")
chk "an external module is written through" /opt/nfast/toolkits/pkcs11/libcknfast.so \
    "$(field "$HSM" PKCS11_MODULE)"

# Validate BEFORE writing. A module NAME instead of a path is the realistic
# mistake: the loader would fail at first key use, long after the wizard exited.
printf 'DEPLOYMENT=single\nKEY_BACKEND=hsm\nPKCS11_MODULE=libcknfast.so\n' > k1.env
bash "$SH" --answers k1.env --print-env >/dev/null 2>&1
chk "a bare module NAME is rejected"       fail "$([ $? -ne 0 ] && echo fail || echo ok)"
printf 'DEPLOYMENT=single\nKEY_BACKEND=hsm\n' > k2.env
bash "$SH" --answers k2.env --print-env >/dev/null 2>&1
chk "hsm with no module is rejected"       fail "$([ $? -ne 0 ] && echo fail || echo ok)"
printf 'DEPLOYMENT=single\nKEY_BACKEND=file\n' > k3.env
bash "$SH" --answers k3.env --print-env >/dev/null 2>&1
chk "KEY_BACKEND=file is rejected"         fail "$([ $? -ne 0 ] && echo fail || echo ok)"

# The sidecar must actually exist in the deploy it hands off to, or the default
# answer is a promise the compose file doesn't keep.
CF="$ROOT/deploy/docker-compose.yml"
# The service is named for what it PROVIDES, not how: everything else depends on one thing
# from it — that the token socket exists and is healthy — and a local SoftHSM token and a
# tunnel to a remote one both satisfy that. Naming it for the implementation would mean the
# second shape needed a different service name, and every depends_on would change with it.
chk "compose defines the token service"    yes "$(grep -qE '^  token:' "$CF" && echo yes || echo no)"
chk "services depend on it being healthy"  yes "$(grep -A2 '^    token:$' "$CF" | grep -q 'service_healthy' && echo yes || echo no)"
chk "compose defaults PKCS11_MODULE"       yes "$(grep -q 'PKCS11_MODULE: \${PKCS11_MODULE:-' "$CF" && echo yes || echo no)"

echo "=== a script the docs tell you to run must be runnable ==="
# `git config core.fileMode=false` in this repo (the tree is synced from Windows), so
# a local `chmod +x` NEVER reaches the index — the file stays 100644 for everyone who
# clones. docs/deployment.md §3.1 says `./install.sh`, and on a fresh lab checkout that was
# exactly "Permission denied". Caught by running it on a real server, not locally,
# where the bit happened to be set. Assert the INDEX mode, which is what a clone gets.
# ⚠️ This needs git, and the SHIPPED test image has none — `git ls-files` produced an
# empty string there and all three read as mode-less, i.e. three failures that say
# nothing about file modes. Skip loudly instead: a silent skip is how the fuzz probe
# passed on every machine for months.
if ! (cd "$ROOT" && git rev-parse --is-inside-work-tree >/dev/null 2>&1); then
    echo "  [SKIP] deploy script index modes — no git work tree here (the test image has no git)"
else
    for s in install.sh pg-promote.sh db-restore-online.sh; do
        chk "deploy/$s is executable in the index" 100755 \
            "$(cd "$ROOT" && git ls-files -s "deploy/$s" | awk '{print $1}')"
    done
fi

echo "=== it finishes the install, and --no-deploy opts out ==="
# The four build/postgres/bootstrap/up commands used to be printed for the operator to
# paste. They are the same four every time and their ORDER matters, so leaving them to be
# pasted is how a deployment ends up half-installed with no error anywhere.
chk "install.sh runs the compose sequence itself" yes \
    "$(grep -q 'docker compose build' "$SH" && grep -q 'docker compose up -d postgres' "$SH" \
       && grep -q 'run --rm bootstrap' "$SH" && echo yes || echo no)"
chk "  ... in that order (certgen+postgres before bootstrap)" yes \
    "$(awk '/docker compose up -d postgres/{a=NR} /run --rm bootstrap/{b=NR} END{print (a&&b&&a<b)?"yes":"no"}' "$SH")"
chk "  ... and a failed step stops rather than continuing" yes \
    "$(grep -q 'FAILED:' "$SH" && echo yes || echo no)"
chk "--no-deploy is accepted" yes \
    "$(grep -q '\-\-no-deploy) DO_DEPLOY=0' "$SH" && echo yes || echo no)"
# A box with no docker must still be able to generate its .env — writing the file is
# useful on its own and failing there would be gratuitous.
chk "  ... and a box without docker degrades to .env only" yes \
    "$(grep -q 'docker is not on PATH' "$SH" && echo yes || echo no)"
# --print-env must still exit BEFORE any of this: the wizard is driven that way by this
# very suite, and by anyone scripting a node, neither of which wants containers started.
chk "--print-env still exits before deploying" yes \
    "$(awk '/PRINT_ONLY/{p=NR} /docker compose build/{d=NR} END{print (p&&d&&p<d)?"yes":"no"}' "$SH")"

echo "=== The installer asks per SERVICE, not once for all keys ==="
# Five services mint their own key inside the token on first start. The first cut of
# this asked two questions covering every key. That is not enough: the wizard has to ask
# key questions for EACH service rather than two questions covering all keys, so a
# customer has full control over the key of every service.
for p in WEB EST ACME MS; do
  chk "it asks for the $p key" yes \
      "$(grep -q "ask_service_key $p" "$SH" && echo yes || echo no)"
done
chk "  and refuses anything but ec/rsa" yes \
    "$(grep -q '_KEY_ALGO must be' "$SH" && echo yes || echo no)"
# ⚠️ SCEP RA and the OCSP responder are NOT minted here — neither has a
# generate_key_in_token call site — so the wizard must say where they DO come from rather
# than leave an operator expecting an answer it never asked for.
chk "  and says CMP/SCEP/OCSP are NOT minted here" yes \
    "$(grep -q 'are NOT created here' "$SH" && echo yes || echo no)"
# ⚠️ ASKING IS NOT MINTING, and the invariant here is about MINTING. The CMP RA key type
# is asked for, because `renew-service-certs --create-missing` has to know what to create
# once a CA exists and an unattended install has nobody to ask at that point. What must
# never happen is a key being created HERE, before any CA could certify it — which is what
# the "NOT minted here" assertion above covers, and what the .env check below pins down.
chk "  and DOES ask for the CMP RA key type"    yes \
    "$(grep -q 'ask_service_key CMP_RA' "$SH" && echo yes || echo no)"
# ⚠️ SCEP is asked for a SIZE ONLY. Its RA key decrypts the PKIOperation envelope, so it
# must be plain RSA — there is deliberately no SCEP_RA_KEY_ALGO for a config to get wrong,
# and no algorithm prompt that could offer one.
chk "  and asks SCEP for a key size"            yes \
    "$(grep -q 'ask SCEP_RA_KEY_BITS' "$SH" && echo yes || echo no)"
chk "  but never offers a SCEP algorithm choice" no \
    "$(grep -q 'ask_service_key SCEP' "$SH" && echo yes || echo no)"
chk "  and still says a SCEP RA key must be RSA" yes \
    "$(grep -q 'SCEP RA key must be RSA' "$SH" && echo yes || echo no)"

# The generated .env must carry every service's answer, and must NOT state a value the
# algorithm ignores — an EC install has no bit size to honour.
OUT_EC=$(gen 'PKI_DNS=pki.example.test')
for p in WEB EST ACME MS; do
  chk "default install writes ${p}_KEY_ALGO=ec" yes \
      "$(printf '%s' "$OUT_EC" | grep -qE "^ *${p}_KEY_ALGO=ec" && echo yes || echo no)"
  chk "  ...and ${p}_KEY_CURVE" yes \
      "$(printf '%s' "$OUT_EC" | grep -qE "^ *${p}_KEY_CURVE=P-256" && echo yes || echo no)"
  chk "  ...and NOT an RSA bit size it would ignore" no \
      "$(printf '%s' "$OUT_EC" | grep -qE "^ *${p}_KEY_BITS=" && echo yes || echo no)"
done
# ⚠️ THE POINT OF THE REWORK: one service can differ from the rest.
# gen() writes ONE argument to the answers file, so multiple answers go in one string.
OUT_MIX=$(gen "PKI_DNS=pki.example.test
MS_KEY_ALGO=rsa")
chk "MS can be RSA while the others stay EC" yes \
    "$(printf '%s' "$OUT_MIX" | grep -qE '^ *MS_KEY_BITS=' && echo yes || echo no)"
chk "  and the web key is untouched by that answer" yes \
    "$(printf '%s' "$OUT_MIX" | grep -qE '^ *WEB_KEY_ALGO=ec' && echo yes || echo no)"
chk "  and MS carries no curve it would ignore" no \
    "$(printf '%s' "$OUT_MIX" | grep -qE '^ *MS_KEY_CURVE=' && echo yes || echo no)"
# The ANSWER is recorded, so whatever creates the credential later knows what to mint.
chk "  and the CMP RA key TYPE is recorded" yes \
    "$(printf '%s' "$OUT_MIX" | grep -qE '^ *CMP_RA_KEY_ALGO=' && echo yes || echo no)"
# ⚠️ But NOT a key URI, which is the thing that would make something mint one. That comes
# from the shipped config; the key itself is created only by `renew-service-certs
# --create-missing`, after a CA exists to certify it. This is the assertion that keeps
# "the wizard records an answer" from drifting into "the wizard provisions a key".
chk "  but no key is provisioned for it here" no \
    "$(printf '%s' "$OUT_MIX" | grep -qE '^ *CMP_RA_KEY=' && echo yes || echo no)"

echo "=== HA_ENABLED: the pair switch turns on the key tunnel and copyable service keys ==="
# The same switch as native and Kubernetes. Decided at install because a key is copyable or
# not from the moment it is generated.
HA=$(gen "DEPLOYMENT=single
PG_BIND=10.0.0.1
HA_ENABLED=yes")
chk "HA_ENABLED=yes writes P11_TLS=on"                 on   "$(field "$HA" P11_TLS)"
chk "  and SERVICE_KEYS_REPLICABLE=true"               true "$(field "$HA" SERVICE_KEYS_REPLICABLE)"
chk "  and runs the tunnel service (p11tls profile)"   yes \
    "$(field "$HA" COMPOSE_PROFILES | tr ',' '\n' | grep -qx p11tls && echo yes || echo no)"
chk "  Kubernetes' spelling, true, means the same"     on \
    "$(field "$(gen "PG_BIND=10.0.0.1
HA_ENABLED=true")" P11_TLS)"
NOHA=$(gen "DEPLOYMENT=single")
chk "without it, no tunnel and no copyable keys"       "" \
    "$(field "$NOHA" P11_TLS)$(field "$NOHA" SERVICE_KEYS_REPLICABLE)"
printf 'PG_BIND=127.0.0.1\nHA_ENABLED=yes\n' > haloop.env
bash "$SH" --answers haloop.env --print-env >/dev/null 2>&1
chk "HA_ENABLED with a loopback PG_BIND is refused: the standby could not connect" fail \
    "$([ $? -ne 0 ] && echo fail || echo ok)"

echo
echo "=== INSTALL WIZARD: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
