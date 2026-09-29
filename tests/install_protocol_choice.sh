#!/usr/bin/env bash
# The wizard asks which protocols to deploy, and a declined one is not
# deployed at all.
#
# The requirement: ask whether a customer wants EST, ACME and MS at all. They may not
# need all of them, or any of them, for their PKI. If a protocol is not chosen there is no
# reason to build a container for it, run it or monitor it — the installer builds, runs
# and monitors only what was chosen during the wizard.
#
# ⚠️ WHY THIS IS A TEST AND NOT A DOC NOTE. The mechanism is `profiles:` in the compose
# file plus COMPOSE_PROFILES in .env, and it fails SILENTLY in both directions: a service
# that loses its profile is deployed to everyone forever, and a profile name that does not
# match the compose file leaves the protocol permanently undeployed with no error from
# anything. Neither shows up in any other suite, because every other suite runs the
# binaries directly and never reads the compose file.
#
# No docker required: this asserts on what the wizard WRITES and what the compose file
# DECLARES, which is the contract between them.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
COMPOSE="$ROOT/deploy/docker-compose.yml"
INSTALL="$ROOT/deploy/install.sh"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
# ⚠️ A FUNCTION, not an inline `case`. Written as `$(case ",$L," in *",$p,"*) ...)` bash
# takes the pattern's own `)` as the end of the command substitution and the whole file
# stops parsing — it fails as a syntax error at run time, which in a suite that reports
# PASS/FAIL counts looks like nine assertion failures rather than one typo.
inlist(){ # inlist <comma-list> <item>
  case ",$1," in
    *",$2,"*) echo yes ;;
    *)        echo no  ;;
  esac
}

echo "=== 1. every optional protocol carries its own compose profile ==="
for p in ocsp est acme cmp ms store scep; do
    chk "$p is profile-gated" yes \
        "$(grep -qE "^  $p: *\{[^}]*profiles: *\[$p\]" "$COMPOSE" && echo yes || echo no)"
done
# ⚠️ The console must NOT be gated. A deployment with no console cannot create a CA, and
# without a CA every other protocol answers nothing — so "web declined" is not a smaller
# install, it is a broken one.
chk "the web console is NOT profile-gated" no \
    "$(grep -qE "^  web: *\{[^}]*profiles:" "$COMPOSE" && echo yes || echo no)"
# Infrastructure must never be gated by a PROTOCOL choice — that would let "we do not want
# SCEP" break the database. ⚠️ Note the invariant is about protocol names, NOT about having
# a profile at all: `bootstrap` legitimately carries profiles:["setup"], a one-shot kept out
# of `up -d`. Asserting "no profiles" here fails on that, correctly — the test would be
# wrong, not the compose file.
for s in postgres token certgen bootstrap; do
    _prof=$(sed -n "/^  $s:/,/^  [a-z]/p" "$COMPOSE" | sed -n 's/.*profiles: *\[\{0,1\}"\{0,1\}\([a-z-]*\).*/\1/p' | head -1)
    chk "$s is not gated by a protocol choice" no \
        "$([ -n "$_prof" ] && inlist "est,acme,cmp,scep,ms,store,ocsp" "$_prof" || echo no)"
done

echo "=== 2. the wizard writes the chosen set, and only the chosen set ==="
# --answers + --print-env: no docker, no writes, just the .env the wizard would produce.
cat > "$W/all.env" <<EOF
DEPLOYMENT=single
PKI_DNS=pki.test
KEY_BACKEND=softhsm
WANT_EST=yes
WANT_ACME=yes
WANT_CMP=yes
WANT_SCEP=yes
WANT_MS=yes
WANT_STORE=yes
WANT_OCSP=yes
EOF
ALLENV=$(bash "$INSTALL" --answers "$W/all.env" --print-env 2>/dev/null)
PALL=$(printf '%s' "$ALLENV" | sed -n 's/^COMPOSE_PROFILES=//p')
chk "all-yes lists every optional protocol" yes \
    "$(for p in est acme cmp scep ms store ocsp; do [ "$(inlist "$PALL" "$p")" = yes ] || echo MISSING; done | grep -q MISSING && echo no || echo yes)"

# The one that matters: decline three and they must be absent.
sed -e 's/^WANT_SCEP=yes/WANT_SCEP=no/' -e 's/^WANT_MS=yes/WANT_MS=no/' \
    -e 's/^WANT_ACME=yes/WANT_ACME=no/' "$W/all.env" > "$W/some.env"
SOMEENV=$(bash "$INSTALL" --answers "$W/some.env" --print-env 2>/dev/null)
PSOME=$(printf '%s' "$SOMEENV" | sed -n 's/^COMPOSE_PROFILES=//p')
echo "  (COMPOSE_PROFILES=$PSOME)"
for p in scep ms acme; do
    chk "declined $p is NOT in COMPOSE_PROFILES" no "$(inlist "$PSOME" "$p")"
done
for p in est cmp store ocsp; do
    chk "chosen $p IS in COMPOSE_PROFILES"      yes "$(inlist "$PSOME" "$p")"
done

echo "=== 2b. OCSP is NOT asked — it is mandatory like the console ==="
# OCSP is treated like the web console and is not offered as a choice. The first version
# of the wizard offered it; this asserts it cannot be declined.
sed 's/^WANT_OCSP=yes/WANT_OCSP=no/' "$W/all.env" > "$W/noocsp.env"
NOOCSP=$(bash "$INSTALL" --answers "$W/noocsp.env" --print-env 2>/dev/null)
POC=$(printf '%s' "$NOOCSP" | sed -n 's/^COMPOSE_PROFILES=//p')
chk "answering no to OCSP does not remove it"  yes "$(inlist "$POC" ocsp)"
chk "the wizard does not ask about OCSP"       no  \
    "$(grep -q 'yesno WANT_OCSP' "$INSTALL" && echo yes || echo no)"

echo "=== 2c. the BUILD-TIME state reaches the DB, per protocol ==="
# The build-time state of each optional protocol is recorded as a config variable in the
# DB, so anything that depends on it can do a simple check before committing a job.
# ⚠️ This is NOT <PROTO>_ENABLED — that is the runtime switch. Without the
# distinction the Endpoints page shows a protocol that was never installed exactly like
# one an admin turned off.
chk "declined SCEP is recorded as not installed" yes \
    "$(printf '%s' "$SOMEENV" | grep -q '^SCEP_INSTALLED=false' && echo yes || echo no)"
chk "declined MS likewise"                       yes \
    "$(printf '%s' "$SOMEENV" | grep -q '^MS_INSTALLED=false'   && echo yes || echo no)"
chk "chosen EST is recorded as installed"        yes \
    "$(printf '%s' "$SOMEENV" | grep -q '^EST_INSTALLED=true'   && echo yes || echo no)"
chk "bootstrap writes them into the DB"          yes \
    "$(grep -q 'set "${_p}_INSTALLED"' "$ROOT/deploy/bootstrap.sh" && echo yes || echo no)"
chk "compose passes them to bootstrap"           yes \
    "$(grep -q 'SCEP_INSTALLED:' "$COMPOSE" && echo yes || echo no)"
chk "the console reports installed per endpoint" yes \
    "$(grep -q '\\"installed\\":' "$ROOT/src/web/main.cpp" && echo yes || echo no)"
chk "  and renders 'not installed' rather than off" yes \
    "$(grep -q "row.installed === false" "$ROOT/src/web/main.cpp" && echo yes || echo no)"

echo "=== 3. a declined listener gets no key questions written either ==="
# Asking an operator to pick a curve for a service they declined would be noise, and the
# setting would describe a container that does not exist.
chk "no ACME_KEY_ALGO for a declined ACME" no \
    "$(printf '%s' "$SOMEENV" | grep -q '^ACME_KEY_ALGO=' && echo yes || echo no)"
chk "no MS_KEY_ALGO for a declined MS"     no \
    "$(printf '%s' "$SOMEENV" | grep -q '^MS_KEY_ALGO='   && echo yes || echo no)"
chk "EST_KEY_ALGO is still written"        yes \
    "$(printf '%s' "$SOMEENV" | grep -q '^EST_KEY_ALGO='  && echo yes || echo no)"
chk "WEB_KEY_ALGO is always written"       yes \
    "$(printf '%s' "$SOMEENV" | grep -q '^WEB_KEY_ALGO='  && echo yes || echo no)"

echo "=== 4. rolling-update rolls what is deployed, not a hardcoded list ==="
# A fixed list would `up -d` a service whose profile is inactive — which silently does
# nothing — and then wait out the health timeout for a container that never appears.
chk "rolling-update asks compose for the service list" yes \
    "$(grep -q 'config --services' "$ROOT/deploy/rolling-update.sh" && echo yes || echo no)"

echo
echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] || echo "RESULT: FAIL"
exit 0
