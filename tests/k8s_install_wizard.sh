#!/usr/bin/env bash
# The Kubernetes path has an install wizard, and it is the compose wizard: the same questions in
# the same order under the same answers-file keys, writing deploy/k8s/env.local. And a protocol
# declined there is not deployed: no container in the server pods, no Service.
#
# ⚠️ WHY THIS IS A TEST. Before it, `install.sh --k8s` asked nothing and every Kubernetes
# operator hand-wrote env.local, so the settings a deployment cannot work without — the Services
# published outside the cluster, the interconnect addresses of a mesh — were missed in practice.
# Every protocol also always ran, because the manifests had no switch for any of them. Both are
# silent: a missing setting deploys a cluster nobody outside can reach, and a switch that does
# not reach the manifests deploys the declined protocol anyway.
#
# No cluster required: it asserts on what the wizard WRITES and what `apply.sh --render` would
# APPLY, which is the contract between them. It runs on a copy of deploy/k8s, so nothing is
# written into the tree.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
val(){ sed -n "s/^$1=//p" "$2" | head -1; }     # val <KEY> <file>
has(){ grep -q "^$1=" "$2" && echo yes || echo no; }
# ⚠️ A FUNCTION, not an inline `case` inside `$( )`: bash reads the pattern's own `)` as the end of
# the command substitution, and the line stops parsing.
inlist(){ case " $1 " in *" $2 "*) echo yes ;; *) echo no ;; esac; }   # inlist <space-list> <item>

WIZ="$ROOT/deploy/k8s/k8s-install.sh"
[ -f "$WIZ" ] || { echo "  [FAIL] deploy/k8s/k8s-install.sh does not exist"; echo "=== K8S INSTALL WIZARD: PASS=0 FAIL=1 ==="; exit 1; }
mkdir -p "$W/deploy"
cp -R "$ROOT/deploy/k8s" "$W/deploy/k8s"
cp "$ROOT/deploy/bootstrap.compose.conf" "$ROOT/deploy/certgen.sh" "$W/deploy/" 2>/dev/null
rm -f "$W/deploy/k8s/env.local" "$W/deploy/k8s/env.local.bak"
K="$W/deploy/k8s"

# ── answers files ─────────────────────────────────────────────────────────
cat > "$W/single.env" <<'EOF'
DEPLOYMENT=single
FASTPKI_IMAGE=registry.example.org/fastpki:v9.9.9
PKI_DNS=pki.example.org
WANT_EST=no
WANT_SCEP=no
EOF
cat > "$W/pair-dc2.env" <<'EOF'
DEPLOYMENT=cluster
FASTPKI_IMAGE=registry.example.org/fastpki:v9.9.9
PKI_DNS=pki2.example.org
DC_INDEX=2
PG_BIND=192.0.2.10,192.0.2.11
HA_ENABLED=yes
PG_PASSWORD=pw-from-answers
PKCS11_PIN=pin-from-answers
KEY_BACKEND=hsm
PKCS11_MODULE=/opt/vendor/lib/pkcs11.so
CMP_RA_KEY_ALGO=rsa
CMP_RA_KEY_BITS=4096
SCEP_RA_KEY_BITS=2048
EOF

echo "=== 1. install.sh --k8s runs the Kubernetes wizard ==="
sh "$ROOT/deploy/install.sh" --k8s --answers "$W/single.env" --print-env > "$W/via-install.out" 2>"$W/via-install.err"
chk "install.sh --k8s --print-env exits 0" 0 "$?"
chk "  and prints env.local (IMAGE line)" registry.example.org/fastpki:v9.9.9 "$(val IMAGE "$W/via-install.out")"

echo "=== 2. a single data center: what the answers become ==="
sh "$K/k8s-install.sh" --answers "$W/single.env" --print-env > "$W/single.out" 2>/dev/null
chk "wizard exits 0" 0 "$?"
chk "IMAGE from FASTPKI_IMAGE"          registry.example.org/fastpki:v9.9.9 "$(val IMAGE "$W/single.out")"
chk "PKI_DNS"                           pki.example.org "$(val PKI_DNS "$W/single.out")"
chk "the console is published"          LoadBalancer "$(val WEB_SERVICE_TYPE "$W/single.out")"
chk "the protocols are published"       LoadBalancer "$(val PROTO_SERVICE_TYPE "$W/single.out")"
chk "a declined protocol: EST off"      false "$(val EST_INSTALLED "$W/single.out")"
chk "a declined protocol: SCEP off"     false "$(val SCEP_INSTALLED "$W/single.out")"
for p in ACME CMP MS STORE; do
  chk "$p on by default"                true "$(val ${p}_INSTALLED "$W/single.out")"
done
chk "no mesh settings for a single data center" no "$(has PG_INTERCONNECT "$W/single.out")"
chk "no HA_ENABLED unless asked"        no "$(has HA_ENABLED "$W/single.out")"
chk "a blank password is left to apply.sh" no "$(has PG_PASSWORD "$W/single.out")"
chk "a blank PIN is left to apply.sh"   no "$(has FASTPKI_PIN "$W/single.out")"
chk "service key default: ec"           ec "$(val WEB_KEY_ALGO "$W/single.out")"
chk "service key default: P-256"        P-256 "$(val WEB_KEY_CURVE "$W/single.out")"
chk "no key settings for a declined protocol" no "$(has EST_KEY_ALGO "$W/single.out")"
chk "no SCEP key size when SCEP is off" no "$(has SCEP_RA_KEY_BITS "$W/single.out")"

echo "=== 3. a pair in data center 2, on an HSM ==="
sh "$K/k8s-install.sh" --answers "$W/pair-dc2.env" --print-env > "$W/pair.out" 2>/dev/null
chk "wizard exits 0" 0 "$?"
chk "DC_INDEX"                          2 "$(val DC_INDEX "$W/pair.out")"
chk "PG_BIND becomes PG_INTERCONNECT"   192.0.2.10,192.0.2.11 "$(val PG_INTERCONNECT "$W/pair.out")"
chk "the database is published to peers" LoadBalancer "$(val PG_EXTERNAL_TYPE "$W/pair.out")"
chk "HA_ENABLED"                        true "$(val HA_ENABLED "$W/pair.out")"
chk "PG_PASSWORD kept"                  pw-from-answers "$(val PG_PASSWORD "$W/pair.out")"
chk "PKCS11_PIN becomes FASTPKI_PIN"    pin-from-answers "$(val FASTPKI_PIN "$W/pair.out")"
chk "hsm: the bundled token is off"     false "$(val SOFTHSM_ENABLED "$W/pair.out")"
chk "hsm: the vendor module"            /opt/vendor/lib/pkcs11.so "$(val PKCS11_MODULE "$W/pair.out")"
chk "CMP RA key type"                   rsa "$(val CMP_RA_KEY_ALGO "$W/pair.out")"
chk "CMP RA key size"                   4096 "$(val CMP_RA_KEY_BITS "$W/pair.out")"
chk "SCEP RA key size"                  2048 "$(val SCEP_RA_KEY_BITS "$W/pair.out")"

echo "=== 4. what it refuses, before writing anything ==="
refuses(){ # refuses <label> <answers-lines...>
  _l="$1"; shift; printf '%s\n' "$@" > "$W/bad.env"
  sh "$K/k8s-install.sh" --answers "$W/bad.env" --print-env >/dev/null 2>&1
  chk "refuses: $_l" 1 "$?"
}
refuses "a pair with one mesh address"  DEPLOYMENT=cluster DC_INDEX=2 PG_BIND=192.0.2.10 HA_ENABLED=yes
refuses "a mesh address on loopback"    DEPLOYMENT=cluster DC_INDEX=2 PG_BIND=127.0.0.1
refuses "a mesh with no address"        DEPLOYMENT=cluster DC_INDEX=2
refuses "DC_INDEX 0"                    DEPLOYMENT=cluster DC_INDEX=0 PG_BIND=192.0.2.10
refuses "an hsm with no module"         KEY_BACKEND=hsm
refuses "a protocol answer that is not yes/no" WANT_EST=maybe
refuses "an unknown key type"           WEB_KEY_ALGO=dsa

echo "=== 5. the compose wizard asks the same questions, in the same order ==="
# The question each wizard asks, in file order, first occurrence only: `ask VAR`, `yesno VAR` and
# the per-service key questions. Compose asks its single-server Postgres publish address, which a
# cluster's servers do not need; that is the one question allowed to differ.
questions(){ grep -oE '^[[:space:]]*(\[ "\$WANT_[A-Z]+" +=[[:space:]]+yes \] +&& )?(ask|yesno|ask_service_key) [A-Z0-9_]+' "$1" \
               | awk '{print $NF}' | awk '!seen[$0]++' | tr '\n' ' '; }
c_q="$(questions "$ROOT/deploy/install.sh")"
k_q="$(questions "$WIZ")"
chk "same questions in the same order" "$c_q" "$k_q"
[ -n "$c_q" ] && [ "$(printf '%s' "$c_q" | wc -w)" -ge 15 ] \
  && chk "  (the list is not vacuous: ${c_q%% *} … )" yes yes \
  || chk "  the question list was read" yes no

echo "=== 6. one answers file serves both wizards ==="
sh "$ROOT/deploy/install.sh" --answers "$W/single.env" --print-env >/dev/null 2>&1
chk "the compose wizard accepts the same file" 0 "$?"

echo "=== 7. a declined protocol is not deployed ==="
render(){ ( set -a; . "$1"; set +a; sh "$K/apply.sh" --render ) 2>/dev/null; }
render "$W/single.out" > "$W/single.yaml"
containers="$(grep -E '^        - name: ' "$W/single.yaml" | sed 's/.*name: //' | tr '\n' ' ')"
services="$(grep -E '^  name: fastpki-' "$W/single.yaml" | sed 's/.*name: fastpki-//' | tr '\n' ' ')"
chk "the render produced a StatefulSet" yes "$(grep -q '^kind: StatefulSet' "$W/single.yaml" && echo yes || echo no)"
for p in est scep; do
  chk "no $p container"  no "$(inlist "$containers" "$p")"
  chk "no $p Service"    no "$(inlist "$services" "$p")"
done
for p in web ocsp acme cmp ms store renew; do
  chk "$p container still there" yes "$(inlist "$containers" "$p")"
done
for p in ocsp acme cmp ms store; do
  chk "$p Service still there"   yes "$(inlist "$services" "$p")"
done
chk "no switch comment is left in the output" 0 "$(grep -cE '^[[:space:]]*# @(if|end)' "$W/single.yaml")"
( EST_INSTALLED=yes sh "$K/apply.sh" --render ) >/dev/null 2>&1
chk "apply.sh refuses a protocol switch that is not true/false" 1 "$?"

echo "=== 8. existing settings are reused or kept ==="
printf 'PKI_DNS=old.example.org\nSOMETHING_ELSE=kept\n' > "$K/env.local"
{ cat "$W/single.env"; echo KEEP_DB=no; } > "$W/replace.env"
sh "$K/k8s-install.sh" --answers "$W/replace.env" --no-deploy >/dev/null 2>&1
chk "--no-deploy writes env.local"      pki.example.org "$(val PKI_DNS "$K/env.local")"
chk "  and keeps the old one aside"     kept "$(val SOMETHING_ELSE "$K/env.local.bak")"
# `ls -l` rather than stat: the BSD and GNU stat flags mean different things, and the BSD form
# succeeds on Linux with other output, so a fallback between them never runs there
# (tests/suite_exit_honest.sh).
chk "  env.local is private"            "-rw-------" "$(ls -l "$K/env.local" | cut -c1-10)"
cp "$K/env.local.bak" "$K/env.local"
{ cat "$W/single.env"; echo KEEP_DB=yes; } > "$W/keep.env"
sh "$K/k8s-install.sh" --answers "$W/keep.env" --no-deploy >/dev/null 2>&1
chk "KEEP_DB=yes leaves env.local alone" old.example.org "$(val PKI_DNS "$K/env.local")"
rm -f "$K/env.local" "$K/env.local.bak"

echo "=== 9. no cluster, no questions ==="
# A PATH with the basic tools and no kubectl. The wizard must stop before it asks or writes.
mkdir -p "$W/bin"
for t in sh sed grep head tr awk cat cp printf mkdir rm; do
  _p="$(command -v "$t" 2>/dev/null)"; [ -n "$_p" ] && ln -sf "$_p" "$W/bin/$t"
done
PATH="$W/bin" sh "$K/k8s-install.sh" --answers "$W/single.env" > "$W/nok.out" 2>&1
chk "stops with no kubectl"             1 "$?"
chk "  and says to install Kubernetes first" yes "$(grep -q 'Install Kubernetes first' "$W/nok.out" && echo yes || echo no)"
chk "  and wrote nothing"               no "$([ -f "$K/env.local" ] && echo yes || echo no)"

echo "=== K8S INSTALL WIZARD: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
