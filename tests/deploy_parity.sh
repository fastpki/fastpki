#!/usr/bin/env bash
# Every compose service must have a Kubernetes counterpart.
#
# ⚠️ WHY THIS EXISTS. FastPKI ships two deployment paths and only one of them is exercised:
# compose is driven by demo/pki-demo.sh, install_wizard.sh, demo_scripts.sh and the whole
# harness, while NOTHING in tests/ has ever run kubectl. Drift was therefore invisible by
# construction, and it accumulated for a month:
#
#   softhsm            never ported  -> no token backend, so every HTTPS service bound its
#                                       port and was then killed by the liveness guard
#   auditfwd           never ported
#   PKCS11_MODULE      never defined -> a k8s deployment could not use a real HSM at all
#   FASTPKI_PIN        never defined -> certgen crash-looped, Postgres never started
#   --config           dropped in 51f6a6f's rename -> every pod read built-in defaults and
#                                       dialled libpq's LOCAL SOCKET in a cluster
#
# Each was found by hand, on a live cluster, one at a time. This suite is the thing that
# would have said so on the day. It reads files and starts nothing, so it costs a moment.
#
# ⚠️ IT COMPARES SERVICES, NOT BEHAVIOUR. A counterpart existing does not prove it works —
# that is what a real cluster run proves. What this catches is the specific, repeated failure
# of adding a service to one path and forgetting the other, which is the one no reviewer
# noticed six times running.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT" || exit 1
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

COMPOSE="deploy/docker-compose.yml"
K8SDIR="deploy/k8s/manifests"
[ -f "$COMPOSE" ] || { echo "RESULT: FAIL — no $COMPOSE"; exit 1; }
[ -d "$K8SDIR" ]  || { echo "RESULT: FAIL — no $K8SDIR"; exit 1; }

# ── the two inventories ──────────────────────────────────────────────────────────────
# compose: top-level keys under `services:`. The `volumes:` block that follows is a
# different section and must not be read as services — which is why this stops at the first
# non-indented key rather than grepping the whole file.
compose_services() {
    awk '/^services:/{s=1; next} s && /^[a-z]/{exit} s && /^  [a-z][a-z0-9_-]*:/ {
        # both forms: a block service (`web:` then indented keys) and an inline one
        # (`web:   { <<: *fastpki, ... }`), which the previous anchor-to-end-of-line missed —
        # and the anti-vacuity check below is what caught that.
        sub(/:.*/,""); gsub(/[[:space:]]/,""); print }' "$COMPOSE" | sort -u
}
# k8s: the object names, minus the fastpki- prefix every manifest uses — AND the containers of each
# pod. A Compose host's services are the containers of one fastpki-node pod here (a server per pod,
# with its own token), so a service ported as a container is ported. A container is a list item
# whose next line names an image, which is what tells it apart from a volume at the same depth.
k8s_workloads() {
    { grep -h '^  name: fastpki-' "$K8SDIR"/*.yaml 2>/dev/null | sed 's/.*name: fastpki-//'
      awk '/^[[:space:]]*- name: [a-z][a-z0-9-]*[[:space:]]*$/ { n = $3; next }
           n != "" && /^[[:space:]]*image:/ { print n }
           { n = "" }' "$K8SDIR"/*.yaml 2>/dev/null
    } | sort -u
}

# ⚠️ AN ALIAS MAP, NOT AN EXEMPTION LIST. Every entry here says "this IS ported, under
# another name", and each is argued. Nothing may be added meaning "we chose not to port
# this" — a register of what is missing is how the coverage stops moving.
alias_of() {
    case "$1" in
        # compose runs the renewal as a sleep-loop container; so does every k8s server pod,
        # named for what it does.
        certrenew)   echo "renew" ;;
        # compose has one-shot `certgen` and `bootstrap` services ordered before the listeners;
        # each k8s server pod runs certgen and bootstrap's file half in its `init` container,
        # which is that ordering (the admin seed is apply.sh's, once for the deployment).
        certgen|bootstrap) echo "init" ;;
        # compose names its volumes as top-level keys; k8s expresses the same storage as
        # PVCs and volumeClaimTemplates, which carry these names already.
        pgdata|pki-data|p11-socket|softhsm-tokens) echo "$1" ;;
        *)           echo "$1" ;;
    esac
}

echo "=== every compose service has a Kubernetes counterpart ==="
MISSING=""
for svc in $(compose_services); do
    want="$(alias_of "$svc")"
    # A volume-shaped name is satisfied by a PVC/claimTemplate rather than a workload.
    if grep -qE "name: (fastpki-)?$want\$" "$K8SDIR"/*.yaml 2>/dev/null; then continue; fi
    if k8s_workloads | grep -qx "$want"; then continue; fi
    MISSING="$MISSING $svc"
done
chk "no compose service is missing from deploy/k8s" "" "$MISSING"

# ⚠️ ANTI-VACUITY. If either inventory comes back empty — a parser that stopped matching
# after a formatting change — every service "has a counterpart" and this passes while
# checking nothing. That is the failure mode this whole file exists to prevent, so it is
# asserted here rather than assumed.
NC=$(compose_services | wc -l | tr -d ' ')
NK=$(k8s_workloads | wc -l | tr -d ' ')
chk "PRECONDITION: the compose inventory parsed" yes "$([ "$NC" -ge 8 ] && echo yes || echo no)"
chk "PRECONDITION: the k8s inventory parsed"     yes "$([ "$NK" -ge 8 ] && echo yes || echo no)"
echo "         compose: $NC services, k8s: $NK workloads"

# ── the knobs, not just the workloads ────────────────────────────────────────────────
# A service can be ported and still be unusable if the setting that steers it is not. Both
# of these were absent from k8s while compose had them, and both cost a live debugging
# session: PKCS11_MODULE is what points at a real HSM, FASTPKI_PIN is what unlocks the token.
echo "=== the settings that steer them exist on both paths ==="
# DIRECTORY_DNS joined this list the day it was added: a directory is reached by NAME, and
# without a resolver that knows the AD zone every AD feature fails with "Can't contact LDAP
# server" — a compose-only fix would have left kubernetes with the same invisible gap this
# file exists to catch.
for key in PKCS11_MODULE P11_KIT_SERVER_ADDRESS DIRECTORY_DNS; do
    inc=$(grep -c "$key" "$COMPOSE" 2>/dev/null)
    ink=$(grep -rc "$key" deploy/k8s/env.sh deploy/k8s/manifests/ 2>/dev/null | awk -F: '{t+=$2} END{print t+0}')
    chk "  $key is on both paths" yes \
        "$([ "${inc:-0}" -gt 0 ] && [ "${ink:-0}" -gt 0 ] && echo yes || echo no)"
done


# ── certgen.sh is handed the variable it actually reads ──────────────────────────────
#
# ⚠️ THE FALLBACK IS WHAT MAKES THIS SILENT. certgen.sh defaults the deployment FQDN to
# `localhost`, so a call site that spells the variable wrong does not fail — it issues every
# transport certificate for the wrong name, and a certificate for `localhost` still verifies
# against itself. Measured on the native installer, whose ask() assigns with `printf -v` (a
# shell variable, never exported): a name it does not hand to certgen explicitly reaches the
# script through nothing at all. Derived from certgen.sh itself so a future rename cannot
# re-open it.
echo "=== certgen.sh is handed the variable it reads, at every call site ==="
CG="$ROOT/deploy/certgen.sh"
CGVAR=$(grep -oE '^FQDN="\$\{[A-Z_]+' "$CG" | grep -oE '[A-Z_]+$' | head -1)
chk "  certgen.sh names a FQDN variable" yes "$([ -n "$CGVAR" ] && echo yes || echo no)"
# ⚠️ AND PG_BIND, which names the self-signed database certificate's subject. A path that does
# not pass it gives both servers of a pair the deployment's name, and a trust file holding two
# same-named self-signed anchors verifies against the first one only.
chk "  certgen.sh names the database certificate after PG_BIND" yes \
    "$(grep -qE '^PG_CN="\$\{PG_BIND' "$CG" && grep -q 'CN = \$PG_CN' "$CG" && echo yes || echo no)"
for CGVAR in $CGVAR PG_BIND; do
    # ⚠️ JOIN CONTINUATIONS FIRST. The invocation is one command spread over several physical
    # lines, and a per-line grep reported the variable missing the moment another was added
    # beside it — a false failure about a call site that was correct.
    chk "  install-native.sh passes $CGVAR to certgen.sh" yes \
        "$(sed -e :a -e '/\\$/N; s/\\\n//; ta' "$ROOT/deploy/native/install-native.sh" \
           | grep 'certgen\.sh' | grep -q "$CGVAR=" && echo yes || echo no)"
    # ⚠️ AND KUBERNETES, which runs the same script from an init container. The first
    # version of this guard checked the native installer and the compose service and stopped
    # there — so the identical defect sat in postgres-statefulset.yaml, handing certgen a
    # name it does not read, while the suite reported the class fixed.
    # certgen.sh is reached through node-init.sh in every server pod's init container, which
    # passes its environment on unchanged — so the manifest running node-init.sh is the one that
    # must set the variable.
    for m in "$ROOT"/deploy/k8s/manifests/*.yaml; do
        grep -qE '/scripts/(certgen|node-init)\.sh' "$m" || continue
        chk "  $(basename "$m") passes $CGVAR to certgen.sh" yes \
            "$(grep -q "name: $CGVAR" "$m" && echo yes || echo no)"
    done
    chk "  the compose certgen service sets $CGVAR" yes \
        "$(awk '/^  certgen:/{f=1;next} f&&/^  [a-z]/{f=0} f' "$COMPOSE" | grep -q "$CGVAR:" \
           && echo yes || echo no)"
done

# ── the deployment hostname has exactly ONE name, repo-wide ──────────────────────────
#
# ⚠️ PKI_DNS IS THAT NAME. A second spelling of one value is what made the defect above
# silent: two names in two namespaces, every path having to map one onto the other, and the
# path that forgot issued its transport certificates for `localhost` with nothing failing.
# So the retired second name is banned outright — no call site, no manifest, no demo and no
# document may name it, and nothing may read it as a fallback beside PKI_DNS.
#
# ⚠️ THE BANNED NAME IS ASSEMBLED FROM TWO PIECES so this file does not contain the string
# it searches for and report ITSELF as an offender, forever and unfixably. Do not
# "simplify" it into a literal.
echo "=== the deployment hostname has exactly one name, repo-wide ==="
RETIRED="PKI_""FQDN"
# ⚠️ `find`, NEVER `git ls-files`: the shipped test image has no git checkout, so a
# VCS-derived file list is EMPTY there and both checks below would read nothing. Untracked
# files are in scope deliberately — deploy/.env is exactly where a stale name gets pasted,
# and it steers a real deployment.
scan_for() {
    find "$ROOT" -type f \
        -not -path '*/.git/*' -not -path '*/build/*' -not -path '*/build-*/*' \
        -not -path '*/third_party/*' -exec grep -l -- "$1" {} + 2>/dev/null \
        | sed "s|^$ROOT/||" | sort
}
chk "  no file anywhere in the tree names the retired hostname variable" "" \
    "$(scan_for "$RETIRED" | tr '\n' ' ' | sed 's/ *$//')"
# ⚠️ ANTI-VACUITY, RUNNING THE SAME SEARCH. An empty result is what "nobody names it" and
# "the scan read no files" both look like, so the identical machinery is pointed at the name
# that MUST be there: a wrong root, a find that stops matching or a grep whose flags changed
# takes both to zero and fails HERE rather than passing above.
chk "  PRECONDITION: the scan reads the tree (PKI_DNS is found)" yes \
    "$([ "$(scan_for PKI_DNS | wc -l | tr -d ' ')" -ge 10 ] && echo yes || echo no)"

# ── every variable a manifest interpolates must actually be set ──────────────────────
#
# ⚠️ envsubst IS CALLED WITH NO VARIABLE LIST (apply.sh:330 onwards), so a `$NAME` the k8s
# scripts never set is NOT left alone for Kubernetes to resolve — envsubst replaces it with
# the EMPTY STRING. The manifest still applies, the workload still starts, and the setting
# is simply gone. That is not hypothetical: $PKCS11_TOKEN reached three manifests while
# PKCS11_MODULE and PKCS11_PIN_FILE beside it were exported, so every pod got
# PKCS11_TOKEN="" — and an env var set to empty is SET, so Config::from_env() applied it
# over both the ConfigMap value and the compiled-in default.
echo "=== every variable a k8s manifest interpolates is set by the k8s scripts ==="
K8S_SCRIPTS="$ROOT/deploy/k8s/env.sh $ROOT/deploy/k8s/apply.sh"
# Referenced: $NAME and ${NAME} alike.
MAN_VARS=$(grep -ohE '\$\{?[A-Z][A-Z0-9_]*\}?' "$K8SDIR"/*.yaml \
           | tr -d '${}' | sort -u)
# Set: `export NAME=`, a bare `NAME=` assignment at any indentation, and every name in a
# grouped `export A B C` line. Deliberately generous — a false "it is set" only weakens the
# check, while a false "missing" would make the suite cry wolf on a real deployment file.
K8S_SET=$( { grep -ohE '^[[:space:]]*(export[[:space:]]+)?[A-Z][A-Z0-9_]*=' $K8S_SCRIPTS \
               | sed 's/export//; s/=.*//; s/[[:space:]]//g'
             grep -ohE '^[[:space:]]*export[[:space:]]+[A-Z][A-Z0-9_ ]*$' $K8S_SCRIPTS \
               | sed 's/export//' | tr ' ' '\n'; } | grep -v '^$' | sort -u )
chk "  no manifest interpolates a variable the scripts never set" "" \
    "$(comm -23 <(echo "$MAN_VARS") <(echo "$K8S_SET") | tr '\n' ' ' | sed 's/ *$//')"
# ⚠️ ANTI-VACUITY, BOTH SIDES. If either extraction stops matching, the set difference is
# empty and the check above passes over nothing at all.
chk "  PRECONDITION: manifest variables were extracted" yes \
    "$([ "$(echo "$MAN_VARS" | grep -c .)" -ge 20 ] && echo yes || echo no)"
chk "  PRECONDITION: the scripts' variables were extracted" yes \
    "$([ "$(echo "$K8S_SET" | grep -c .)" -ge 20 ] && echo yes || echo no)"

# ⚠️ MULTI-DATA-CENTER IS A CAPABILITY COMPOSE HAD AND KUBERNETES DID NOT — not a broken
# version of it, an absent one. compose gets a mesh from DEPLOYMENT=cluster / DC_INDEX /
# PG_BIND; k8s set no DATACENTER_ID, registered no `datacenters` row, and exposes Postgres
# through a HEADLESS Service that no peer cluster can reach. So a k8s deployment could not
# be meshed at all, and nothing said so — the same invisible-by-construction drift this
# whole file exists for.
#
# Static, like the rest of this suite: it reads the files rather than driving a cluster.
echo "=== the multi-datacenter mesh exists on both paths ==="
APPLY="$ROOT/deploy/k8s/apply.sh"
ENVSH="$ROOT/deploy/k8s/env.sh"
INSTALL="$ROOT/deploy/install.sh"

# The knobs. PG_INTERCONNECT is k8s's answer to compose's PG_BIND: the address a PEER dials.
# ⚠️ DC_COUNT IS NOT IN THIS LIST, AND THAT IS THE POINT. It used to be, and asserting it
# outlived the variable: deploy/k8s/apply.sh gates the mesh on DC_INDEX — "DC_INDEX IS THE
# SWITCH, not a count" — because asking whether DC_COUNT > 1 made a single-node deployment
# that would later grow indistinguishable from one that never would. Compose has no such
# knob either, so requiring it here demanded parity with something neither path has.
for key in DC_INDEX PG_INTERCONNECT PG_EXTERNAL_TYPE; do
    chk "  env.sh defines $key" yes \
        "$(grep -qE "^export $key=" "$ENVSH" && echo yes || echo no)"
done

# Both installers must WRITE the identity into the config, not merely offer a knob.
# DATACENTER_ID is what makes a node mint in its own serial partition; PG_TLS_SANS is what
# puts the interconnect address into the database certificate, and it has to be set before
# `fastpki-ca pg-tls` runs because the SANs come from config, not from its arguments.
for key in DATACENTER_ID PG_TLS_SANS; do
    chk "  apply.sh writes $key into bootstrap.conf" yes \
        "$(grep -qE "^$key=" "$APPLY" && echo yes || echo no)"
done

# ⚠️ THE ROW, NOT JUST THE ID. A node with DATACENTER_ID and no `datacenters` row refuses to
# issue: est, acme, cmp, scep, ms and web restart forever while ocsp and store run happily,
# which reads as a partly-working deployment. compose learned this twice; asserted on both
# so k8s cannot regress to the version that only set the variable.
for f in "$INSTALL" "$APPLY"; do
    # Backticks inside a double-quoted string are COMMAND SUBSTITUTION, so this label ran
    # `datacenters` as a command and printed "datacenters: command not found" twice per run
    # while the assertion itself silently lost the word from its name.
    chk "  $(basename "$f") registers the datacenters row" yes \
        "$(grep -qiE "INSERT INTO datacenters" "$f" && echo yes || echo no)"
done

# The interconnect Service, and its cleanup. A LoadBalancer left behind keeps billing for a
# deployment that is gone, so delete.sh must name it even though apply.sh creates it
# conditionally.
chk "  a Service exposes Postgres to peer clusters" yes \
    "$([ -f "$ROOT/deploy/k8s/manifests/postgres-external.yaml" ] && echo yes || echo no)"
# ⚠️ ONE SERVER PER SERVICE, NOT ONE SERVICE ACROSS BOTH. A Service spreading a peer's
# subscription over a primary and a standby hands it to the standby half the time, where it
# connects and never advances; which server is primary changes at a promotion, so no fixed
# selector can name it either. The peers list every server's address instead.
chk "    and it selects ONE server by pod name" yes \
    "$(grep -qE 'statefulset.kubernetes.io/pod-name: fastpki-node-\$NODE_ORDINAL' "$ROOT/deploy/k8s/manifests/postgres-external.yaml" && echo yes || echo no)"
# One Service per server, so delete.sh removes them by the label the manifest carries rather
# than by a name that includes the ordinal.
_ic_label="$(sed -n 's/^ *app.kubernetes.io\/component: \(postgres-interconnect\)$/\1/p' "$ROOT/deploy/k8s/manifests/postgres-external.yaml")"
chk "    and delete.sh removes it" yes \
    "$([ -n "$_ic_label" ] && grep -q "component=$_ic_label" "$ROOT/deploy/k8s/delete.sh" && echo yes || echo no)"

# ⚠️ REFUSE, DO NOT WARN — the rule this repo keeps relearning. A cluster deployed with
# DC_COUNT > 1 and no interconnect address comes up healthy and can never be meshed, and
# the failure only surfaces later, when a peer rejects a certificate that could not carry a
# SAN nobody supplied.
# A flag, not an awk RANGE: /fi/ as a range end matches any line containing those two
# letters, and "topology file's host=" ends it three lines early — the check then passed
# over a block with no exit in it, which is the vacuous-pass shape this suite is about.
chk "  apply.sh REFUSES a mesh with no interconnect address" yes \
    "$(awk '/-z "\$\{PG_INTERCONNECT:-\}"/{f=1; next} f&&/^[[:space:]]*fi[[:space:]]*$/{exit} f&&/exit 1/{print "found"; exit}' "$APPLY" | grep -q found && echo yes || echo no)"

# ⚠️ A LATER RUN KEEPS THE IMAGE, as compose keeps FASTPKI_IMAGE in deploy/.env. install.sh
# names the release image for the one run it starts and saves it nowhere, so a later
# apply.sh fell back to fastpki:latest, which no registry holds (ErrImagePull).
chk "  apply.sh notes whether an image was chosen BEFORE env.sh defaults it" yes \
    "$(awk '/IMAGE_CHOSEN=/{c=NR} /\. "\$SCRIPT_DIR\/env.sh"/{e=NR} END{print (c && e && c<e) ? "yes" : "no"}' "$APPLY")"
chk "  and, when none was, reads the running StatefulSet's image" yes \
    "$(grep -q 'get statefulset fastpki-node' "$APPLY" && grep -q 'IMAGE="\$RUNNING_IMAGE"' "$APPLY" && echo yes || echo no)"

# ⚠️ /pki, NOT /var/pki. Apps mount the volume at /var/pki; POSTGRES mounts it at /pki, and
# the subscription is opened by the postgres server. The compose path was corrected for this
# after it produced 'root certificate file does not exist' with every mesh command still
# reporting success — so the k8s instructions must not reintroduce it.
# ⚠️ SCOPED TO THE GUIDANCE BLOCK, because the app's OWN conninfo legitimately uses the
# app-side path: PG_CONNINFO is built with sslrootcert=/var/pki/tls/pg/ca.crt, which is
# correct for a pod that mounts the volume at /var/pki. A file-wide absence check would
# therefore fail on correct code, and the previous form dodged that by appending a `|` to the
# pattern — which, in a BRE, is a LITERAL pipe. `ca.crt|` occurs nowhere in apply.sh, so the
# grep could never match, the expression always yielded "yes", and the check passed
# unconditionally: switching the topology conninfo to the app-side path, the regression the
# ⚠️ above exists to prevent, went unnoticed. The requirement concerns the MESH GUIDANCE an
# operator copies, so read that block alone — the LAST block gated on PG_INTERCONNECT, since an
# earlier one validates the address count and the conninfo lies between the two.
MESHBLK="$(awk '/^if \[ -n "\$\{PG_INTERCONNECT:-\}" \]; then$/{b=""; f=1} f{b=b $0 "\n"} END{printf "%s", b}' "$APPLY")"
chk "  the mesh guidance block was found" yes \
    "$([ -n "$MESHBLK" ] && echo yes || echo no)"
# The topology and its anchor path are deploy/mesh-join.sh's job now, the same command on every
# path (the Kubernetes anchor is asserted with node-access.sh below), so the guidance gives that
# command in its Kubernetes form rather than a topology to write by hand.
chk "  the k8s mesh guidance gives deploy/mesh-join.sh in its k8s: form" yes \
    "$(printf '%s' "$MESHBLK" | grep -q "deploy/mesh-join.sh k8s:" && echo yes || echo no)"
chk "    and never the app-side one" yes \
    "$(printf '%s' "$MESHBLK" | grep -qE "sslrootcert=/var/pki/tls/pg/(ca|trust).crt" && echo no || echo yes)"

# The same mistake on every path: the topology deploy/mesh-join.sh builds names, in
# sslrootcert=, the anchor each SUBSCRIBING Postgres reads, and deploy/node-access.sh is where
# that path is held per deployment path (ANCHOR=). On native and cloud the postgres server
# reads a copy pg-tls-sync delivers into a directory postgres owns, because /var/pki is
# fastpki:fastpki 0750 and postgres cannot enter it; a topology naming /var/pki/tls/pg/ca.crt
# failed every CREATE SUBSCRIPTION with `root certificate file ... does not exist`. On compose
# and Kubernetes the postgres container mounts the volume at /pki. The native path is read
# from pg-tls-sync itself, so moving the copy moves the expectation with it.
PG_DST="$(sed -n 's/^DST="\${PG_TLS_DST:-\([^}]*\)}"$/\1/p' "$ROOT/deploy/native/pg-tls-sync.sh")"
NA="$ROOT/deploy/node-access.sh"
na_anchor() { awk -v k="$1" '/^na_facts\(\)/ {in_f=1} in_f && $1 == k")" {f=1} f && /ANCHOR=/ {sub(/.*ANCHOR=/, ""); sub(/[ ;\x27].*/, ""); print; exit}' "$NA"; }
chk "  pg-tls-sync names the directory it delivers to" yes \
    "$([ -n "$PG_DST" ] && echo yes || echo no)"
chk "  a native or cloud topology names the postgres-owned copy" "$PG_DST/ca.crt" "$(na_anchor native)"
chk "  a compose topology names the postgres container's path"  "/pki/tls/pg/ca.crt" "$(na_anchor compose)"
chk "  a Kubernetes topology names the postgres container's path" "/pki/tls/pg/ca.crt" "$(na_anchor k8s)"

echo "=== the mesh and the pair are one command, the same on every path ==="
# deploy/mesh-join.sh and deploy/ha-join-pair.sh do the same steps on every path and reach a
# server only through deploy/node-access.sh, so a path is supported when every function there
# has a branch for it. A pair on Kubernetes is apply.sh's HA_ENABLED, asserted above; compose
# and native each need both halves of the join.
for fn in na_sql na_cli na_mesh na_facts na_anchor_pem; do
    body=$(awk -v f="$fn" '$0 ~ "^"f"\\(\\)" {p=1} p {print} p && /^}$/ {exit}' "$NA")
    for k in native compose k8s; do
        chk "  $fn reaches a $k server" yes \
            "$(printf '%s\n' "$body" | grep -qE "^[[:space:]]+$k\)" && echo yes || echo no)"
    done
done
# ⚠️ THE MESH COLLAPSES THE LOCAL admin ROWS, AND THE TOOL THAT DOES IT HAS TO SAY SO. Every
# installer on every path seeds its own admin/admin row, web_users replicates last-writer-wins
# on the username alone, and one row survives the join. Two of the four paths documented it
# and two said nothing, so a native or cloud operator met it as a console that accepted the
# password on one data center and answered 401 on another. mesh-join.sh reaches every path
# through node-access.sh, so it is the one place that covers all four at once.
chk "  mesh-join.sh reads the local accounts before it joins anything" yes \
    "$(grep -q 'from web_users' "$ROOT/deploy/mesh-join.sh" && echo yes || echo no)"
# ⚠️ AND IT LOOKS FOR THE VALUE THE SEEDER ACTUALLY WRITES. A web_users row's auth_provider
# says where its password lives: 'local' is a PBKDF2 hash in this table, 'dn' comes from an
# EST client certificate, a provider's name means a directory holds it, and empty means a
# stub a directory has yet to claim. Only a 'local' row can exist twice with two different
# passwords, which is the entire subject of the check above.
#
# This was written as `auth_provider = ''`, which nothing writes. It matched no rows on any
# real deployment, so the check ran, found nothing, and printed nothing — indistinguishable
# from working. Found by running mesh-join.sh against a live two-data-center mesh, not by any
# test. The two spellings are not discoverable from each other, so they are pinned together.
chk "    naming the value fastpki-config seeds, not one nothing writes" yes \
    "$(grep -qF "auth_provider = 'local'" "$ROOT/deploy/mesh-join.sh" \
       && grep -qF 'auth_provider = "local"' "$ROOT/src/tools/config.cpp" && echo yes || echo no)"
# What each data center holds after the join, read from every one of them, is asserted by
# running mesh-join against two clusters in tests/mesh_join_accounts.sh.
chk "    and names the data center whose password every data center now uses" yes \
    "$(grep -q 'every data center now uses the password set on data center' "$ROOT/deploy/mesh-join.sh" && echo yes || echo no)"
# The operator-facing entry point of each path says it too, because that is where the password
# is set — before mesh-join.sh ever runs.
for f in docs/deployment.md deploy/native/README.md deploy/cloud/README.md deploy/cloud/aws/outputs.tf; do
    chk "    $f says the mesh keeps one admin row" yes \
        "$(grep -qiE "(one account across the mesh|same password on every (node|server)|replicates? .?admin.? as one account)" "$ROOT/$f" && echo yes || echo no)"
done
# ⚠️ THE UPDATE PATH RUNS ON THE STANDBY TOO, AND A STANDBY CANNOT BE WRITTEN TO. Updating a
# native or cloud node means running install-native.sh again, so everything it writes — the
# role, the database, the schema, the seeded admin, the datacenters row — is attempted on the
# standby of a pair, where all of it arrived by replication and the cluster is read-only. It
# stopped at the first write, AFTER the new files were already unpacked, so the node ran the
# old programs while reporting the new version. Compose and Kubernetes never meet this: their
# update paths are rolling-update.sh and apply.sh, and apply.sh seeds against the primary by
# name. pg_is_in_recovery() is the same authority schema-apply.sh already uses.
chk "  the native installer knows it is on a standby" yes \
    "$(grep -q 'pg_is_in_recovery' "$ROOT/deploy/native/install-native.sh" && echo yes || echo no)"
chk "    and skips the steps the primary owns" yes \
    "$(grep -cE '\$PG_STANDBY. = (yes|no)' "$ROOT/deploy/native/install-native.sh" | grep -qE '^[2-9]' && echo yes || echo no)"
chk "    as schema-apply.sh already does" yes \
    "$(grep -q 'pg_is_in_recovery' "$ROOT/deploy/schema-apply.sh" && echo yes || echo no)"
# Joined across its line continuations first: the seeding command spans two lines, and a
# per-line grep for it silently matches nothing and reports the wrong verdict.
chk "  Kubernetes seeds the console admin against the primary, never a replica" yes \
    "$(awk '/kx "\$PRIMARY"/ { c=$0; while (c ~ /\\$/) { if ((getline nl) <= 0) break; c = c nl } print c }' \
         "$ROOT/deploy/k8s/apply.sh" | grep -q 'web-user admin' && echo yes || echo no)"
chk "  ha-join.sh has both halves on compose and on native" yes \
    "$(grep -q '^compose_primary()' "$ROOT/deploy/ha-join.sh" && grep -q '^native_primary()' "$ROOT/deploy/ha-join.sh" \
       && grep -q '^native_standby()' "$ROOT/deploy/ha-join.sh" && grep -q 'compose_check_host$' "$ROOT/deploy/ha-join.sh" && echo yes || echo no)"
# ⚠️ A POSTGRES THAT DOES NOT ANSWER IS NOT "NO CA", ON BOTH HALVES. The guard that refuses to
# replace a database holding CAs counted them by asking the local server, and a stopped one
# answered nothing, read as zero — on native and on compose alike, so a failed primary's
# database was replaced without --replace-local-database. Each half now asks `select 1` first.
chk "  ha-join.sh refuses a stopped Postgres without --replace-local-database, on native" yes \
    "$(grep -q "elif \[ \"\$(npq_local 'select 1')\" != 1 \]" "$ROOT/deploy/ha-join.sh" && echo yes || echo no)"
chk "    and on compose" yes \
    "$(grep -q "elif \[ \"\$(cpq 'select 1')\" != 1 \]" "$ROOT/deploy/ha-join.sh" && echo yes || echo no)"

# ⚠️ AN HA PAIR'S DATABASE HOST LIST MUST SURVIVE THE UPDATE PROCEDURE ON EVERY PATH.
# ha-join.sh writes a PG_CONNINFO naming BOTH hosts with target_session_attrs=read-write, and
# that line IS the failover: libpq uses whichever host accepts writes, so a promotion needs no
# reconfiguration. Whatever an operator runs to UPDATE a node must therefore leave it alone.
# Native rebuilt it from PG_HOST and silently pointed the node back at its own Postgres; on
# the standby that database is read-only, so every service lost its writes and fastpki-web
# could not start at all — it prunes expired sessions on startup, which is a DELETE.
#
# The extraction is read OUT of the installer and run here, so this cannot pass against a
# copy that has drifted from the expression the installer actually uses.
_NAT="$ROOT/deploy/native/install-native.sh"
_TMPC="$(mktemp)"
printf 'PG_CONNINFO=host=10.0.0.1,10.0.0.2 port=5432,5432 dbname=fastpki user=fastpki password=s3cret sslmode=verify-full sslrootcert=/var/pki/tls/pg/ca.crt target_session_attrs=read-write connect_timeout=5\n' > "$_TMPC"
_sedexpr() {   # <variable name> — the sed script install-native.sh uses to recover it
    grep -F "$1=\"\$(sed -n" "$_NAT" | sed -E "s/.*sed -n '([^']*)'.*/\1/" | head -1
}
chk "  install-native.sh recovers an HA host list from a conninfo it wrote" "10.0.0.1,10.0.0.2" \
    "$(sed -n "$(_sedexpr _PREV_PG_HOSTS)" "$_TMPC" 2>/dev/null | head -1)"
chk "    and the matching port list" "5432,5432" \
    "$(sed -n "$(_sedexpr _PREV_PG_PORTS)" "$_TMPC" 2>/dev/null | head -1)"
chk "    and target_session_attrs" "read-write" \
    "$(sed -n "$(_sedexpr _PREV_PG_TSA)" "$_TMPC" 2>/dev/null | head -1)"
rm -f "$_TMPC"
chk "  and it carries them into the conninfo it writes" yes \
    "$(grep -q 'sslrootcert=\$PG_SSLROOTCERT\$_PG_TSA' "$_NAT" && echo yes || echo no)"
# Only with a local Postgres: with PG_LOCAL=no the address the operator just typed is theirs.
chk "  only when Postgres is local, so an operator's own PG_HOST still wins" yes \
    "$(awk '/^case "\$_PREV_PG_HOSTS" in/,/^esac/' "$_NAT" | grep -q 'PG_LOCAL" = yes' && echo yes || echo no)"
# Compose keeps the same property a different way, and that is fine: ha-join.sh puts the pair's
# conninfo in docker-compose.override.yml, a file install.sh never writes.
chk "  compose: install.sh never writes the override ha-join.sh owns" yes \
    "$(grep -q 'docker-compose.override' "$ROOT/deploy/install.sh" && echo no || echo yes)"
# Kubernetes never had the defect: apply.sh builds the two-host form itself on every apply.
chk "  k8s: apply.sh builds the read-write host list itself" yes \
    "$(grep -qE '^PG_CONNINFO=host=\$_hosts port=\$_ports .*target_session_attrs=read-write' \
        "$ROOT/deploy/k8s/apply.sh" && echo yes || echo no)"
# ⚠️ ONE NAME FOR A STANDBY'S SLOT ON EVERY PATH. Compose used fastpki_rebuilt (and a
# STANDBY_SLOT setting no other path had), native fastpki_standby, Kubernetes one per pod, so
# every guide and script that named the slot differed by path. Each now derives it from the
# standby's own PG_BIND with the same pipeline.
SLOTRULE="tr 'A-Z' 'a-z' | tr -c 'a-z0-9\\n' '_' | cut -c1-63"
for f in deploy/ha-join.sh deploy/docker-compose.yml deploy/k8s/start-postgres.sh; do
    chk "  $f names a standby's slot fastpki_<its PG_BIND>" yes \
        "$(grep -F "printf 'fastpki_%s'" "$ROOT/$f" | grep -qF "$SLOTRULE" && echo yes || echo no)"
done
chk "    and no path keeps a fixed slot name or its own setting for it" yes \
    "$(grep -rlE 'fastpki_rebuilt|fastpki_standby|STANDBY_SLOT' "$ROOT/deploy" "$ROOT/docs" | grep -v '/deploy/lab/' | grep -q . && echo no || echo yes)"
# ⚠️ THE PROMOTION SIGNS AS THE SERVICES DO. Compose and Kubernetes run fastpki-ca inside a
# service container, as its user; native ran it as root, which the token server refuses, so
# both signing steps of a promotion failed there. The native branch goes through nfastpki.
chk "  pg-promote.sh runs fastpki-ca as the fastpki user on native, as the services do" yes \
    "$(awk '/^fastpki_ca\(\)/{p=1} p&&/native\)/{print; exit}' "$ROOT/deploy/pg-promote.sh" | grep -q 'nfastpki fastpki-ca' \
       && grep -q "nfastpki fastpki-ca --config \"\$NATIVE_CONF\" pg-tls" "$ROOT/deploy/pg-promote.sh" && echo yes || echo no)"

# ⚠️ THE PAIR'S SHARED ADDRESS NEEDS AN ARBITER ON EVERY PATH, AND THE CLOUD PATH HAS TO
# SUPPLY ITS OWN. On a VIP pair keepalived is the arbiter: a node that returns after a
# failover comes up as a backup and does not claim the address. A VPC holds no election, so
# a boot script that adds the address unconditionally leaves a host that was DOWN during the
# failover — the case `move` cannot reach to clean up — coming back with the address the
# survivor now serves configured on its own interface. The instance metadata service is the
# arbiter, so the generated boot script must consult it and must be willing to remove the
# address, not only add it.
HAADDR="$ROOT/deploy/cloud/aws-ha-address.sh"
chk "  the cloud pair's boot-time address claim asks AWS who holds it" yes \
    "$(grep -q '169\.254\.169\.254' "$HAADDR" && echo yes || echo no)"
chk "    and gives the address up when the answer is not this node" yes \
    "$(grep -q 'ip -6 addr del' "$HAADDR" && echo yes || echo no)"
chk "    and no path writes an unconditional claim into /etc/local.d" yes \
    "$(grep -rn "local.d/fastpki-ha-address" "$ROOT/deploy" "$ROOT/docs" 2>/dev/null \
       | grep -v '/deploy/lab/' | grep -qE "printf 'ip -6 addr add" && echo no || echo yes)"

# A cloud pair copies its CA keys over the key tunnel. First boot turning P11_TLS on is half
# of it; the interconnect security group admitting the tunnel's port is the other half, and
# a standby with only the first half finds no peer and never holds a key.
AWS="$ROOT/deploy/cloud/aws"
# ⚠️ BOTH CLOUD MODULES SAY WHETHER FIRST BOOT WORKED, IN THE SAME FILE. A node whose first
# boot failed boots, answers SSH and serves nothing. Proxmox recorded the exit status in
# /var/log/fastpki-firstboot.rc and its outputs told the operator to read it; AWS wrote only
# the log, so the same question had no answer there and boot-check.sh could not be aimed at it.
chk "  both cloud first boots record their exit status in /var/log/fastpki-firstboot.rc" yes \
    "$(grep -q '> /var/log/fastpki-firstboot.rc' "$AWS/user-data.sh.tftpl" \
       && grep -q '> /var/log/fastpki-firstboot.rc' "$ROOT/deploy/cloud/proxmox/vendor-data.yaml.tftpl" && echo yes || echo no)"
chk "  the cloud first boot passes HA_ENABLED for a data center with a standby" yes \
    "$(grep -q '^HA_ENABLED=yes$' "$AWS/user-data.sh.tftpl" && echo yes || echo no)"
chk "    and the interconnect security group admits the key tunnel's port" yes \
    "$(awk '/resource "aws_vpc_security_group_ingress_rule"/{r=$0} r && /security_group_id *= aws_security_group.interconnect.id/{i=1} r && /from_port *= 12345/{if(i) print "yes"; r=""; i=0}' "$AWS/security.tf" | grep -q yes && echo yes || echo no)"
# ⚠️ EC2 REFUSES USER-DATA OVER 16384 BYTES, AT PLAN TIME, FOR EVERY NODE. The first-boot
# script grew past it (17729 bytes) with nothing to say so until an apply failed, which left
# the cloud path unable to launch a node at all. It is sent gzipped; this keeps both halves.
# ⚠️ THE TEMPLATE AND WHAT IS RENDERED INTO IT, TOGETHER. firstboot-install.sh and the release
# key are inserted as values, so measuring the template file alone undercounted by the whole
# script — which is how the limit was crossed once before, unnoticed until an apply.
UDSZ=$(cat "$AWS/user-data.sh.tftpl" "$ROOT/deploy/cloud/firstboot-install.sh" \
           "$ROOT/docs/release-keys/release-ecdsa.pub" | gzip -9 -c | base64 | tr -d '\n' | wc -c | tr -d ' ')
chk "  the cloud first-boot script is sent gzipped" yes \
    "$(grep -q 'user_data_base64 = base64gzip(templatefile' "$AWS/instances.tf" && ! grep -qE '^  user_data += ' "$AWS/instances.tf" && echo yes || echo no)"
chk "    and fits EC2's 16384 bytes with room for the rendered values ($UDSZ now)" yes \
    "$([ "${UDSZ:-99999}" -lt 15000 ] && echo yes || echo no)"

# ⚠️ A CLOUD SERVER STARTS FROM ALPINE'S OWN IMAGE AND INSTALLS FastPKI AT FIRST BOOT. Both
# cloud modules — AWS and Proxmox — do it with ONE script, so the signature check exists once;
# two copies would drift and one of them would be the unchecked one.
FBI="$ROOT/deploy/cloud/firstboot-install.sh"
chk "  both cloud first boots embed deploy/cloud/firstboot-install.sh" yes \
    "$(grep -q 'firstboot_install = file("${path.module}/../firstboot-install.sh")' "$AWS/instances.tf" \
       && grep -q 'firstboot_install = file("${path.module}/../firstboot-install.sh")' "$ROOT/deploy/cloud/proxmox/vm.tf" \
       && grep -q '${firstboot_install}' "$AWS/user-data.sh.tftpl" \
       && grep -q 'firstboot_install)' "$ROOT/deploy/cloud/proxmox/vendor-data.yaml.tftpl" && echo yes || echo no)"
chk "    and both anchor it on the release key in this checkout, not on anything downloaded" yes \
    "$(grep -q 'docs/release-keys/release-ecdsa.pub' "$AWS/instances.tf" \
       && grep -q 'docs/release-keys/release-ecdsa.pub' "$ROOT/deploy/cloud/proxmox/vm.tf" && echo yes || echo no)"
# The first thing downloaded is the first thing that would run, so it must be checked before it
# runs: the signature, then install.sh against the signed list, and only then `exec`.
chk "    and nothing it downloads runs before the signature is checked" yes \
    "$(awk '/openssl dgst -sha256 -verify/{v=NR} /\[ "\$want" = "\$got" \]/{h=NR} /^exec sh "\$REL\/install.sh"/{x=NR} END{print (v && h && x && v<h && h<x) ? "yes" : "no"}' "$FBI")"
chk "    and an image that already carries FastPKI downloads nothing" yes \
    "$(awk '/\[ -x \/usr\/local\/bin\/fastpki-install-native \]/{a=NR} /exec \/usr\/local\/bin\/fastpki-install-native/{b=NR} /^get\(\)/{g=NR} END{print (a && b && g && a<b && b<g) ? "yes" : "no"}' "$FBI")"

# ⚠️ ONE RELEASE KEY, WRITTEN IN FOUR PLACES, AND THEY MUST BE THE SAME KEY. It is compiled into
# the programs, written into install.sh, published in docs/release-keys/, and rendered into
# every cloud first boot from that file. A key changed in one place and not another makes that
# path reject every genuine release — and silently, until the next install.
_kdoc=$(grep -v '^-----' "$ROOT/docs/release-keys/release-ecdsa.pub" | tr -d '\n')
_kins=$(awk '/RELEASE_PUBKEY_ECDSA=/{f=1;next} f&&/^-----END/{exit} f' "$INSTALL" | tr -d '\n ')
_kcpp=$(awk '/kReleasePubKeyEcdsa\[\] =/{f=1;next} f&&/END PUBLIC KEY/{exit} f' "$ROOT/src/lib/update.cpp" | sed 's/[" ]//g; s/\\n//g' | grep -v BEGIN | tr -d '\n')
chk "  the ECDSA release key is the same in install.sh, the programs and docs/release-keys" yes \
    "$([ -n "$_kdoc" ] && [ "$_kdoc" = "$_kins" ] && [ "$_kdoc" = "$_kcpp" ] && echo yes || echo no)"

# ⚠️ THE PACKAGE LISTS FILES, NOT DIRECTORIES, so tar makes any missing directory with the
# caller's umask. The AWS first boot had set 077 for its secrets file and never restored it, so
# on Alpine's own image /usr/lib/pkcs11 came out 0700 and every service that needed its TLS key
# crash-looped — while first boot recorded success. Both halves are held here.
# Three: the downloaded package, the local one, and the second unpack after apk adds packages.
chk "  install.sh unpacks a package under umask 022, whatever the caller's" 3 \
    "$(grep -c '( umask 022; tar xzf ' "$INSTALL")"
chk "    and the AWS first boot restores umask 022 before anything is installed" yes \
    "$(awk '/^umask 077$/{s=NR} /^umask 022$/{r=NR} /fastpki-firstboot-install .\$\{release_mirror\}/{i=NR} END{print (s && r && i && s<r && r<i) ? "yes" : "no"}' "$AWS/user-data.sh.tftpl")"

# Every way install.sh obtains FastPKI checks the signature: a download of the native package,
# a download of the source, and a package copied over for --package.
chk "  install.sh checks the release signature on all three paths" 3 \
    "$(grep -c '^ *verify_sums "\$TMP" || exit 1$' "$INSTALL")"
chk "    and has no way to skip it" no \
    "$(grep -qiE -- '--(insecure|no-verify|skip-verify|unsigned)' "$INSTALL" && echo yes || echo no)"

# ⚠️ crond RUNS THE DAILY RENEWAL, AND ALPINE SHIPS IT OFF. Only the cloud image build used to
# turn it on, so a native install from plain Alpine installed the daily job and never ran it.
chk "  install-native.sh enables crond itself" yes \
    "$(grep -q 'rc-update add crond default' "$ROOT/deploy/native/install-native.sh" && echo yes || echo no)"

# A CA judges notBefore/notAfter, CRL thisUpdate/nextUpdate and every client's handshake by
# its clock, and Alpine's chrony ships `pool pool.ntp.org` — on the IPv4 internet, which a
# node deployed with public_ipv4 = false has no route to. chronyd then runs and disciplines
# nothing. This is the one case that is genuinely cloud-only rather than an asymmetry: both
# EC2 time addresses are reachable with no route off the VPC, and resolve to nothing
# anywhere else, so compose, native and Kubernetes get no equivalent and must not.
chk "  the cloud first boot points chrony at EC2's time service, both families" yes \
    "$(grep -q 'server fd00:ec2::123' "$AWS/user-data.sh.tftpl" &&
       grep -q 'server 169.254.169.123' "$AWS/user-data.sh.tftpl" && echo yes || echo no)"
chk "    as a conf.d drop-in, leaving the distro's pool line as a fallback" yes \
    "$(grep -q '/etc/chrony/conf.d/' "$AWS/user-data.sh.tftpl" && echo yes || echo no)"

# The Docker image is the one artifact FastPKI publishes that carries Alpine packages, so it
# carries their list and their licence texts. Native and cloud do not apply, and
# build-native.sh says why at the line: the operator installs a native host from their own
# repositories and builds a cloud image in their own account, so neither redistributes them.
chk "  the Docker image writes the Alpine package list beside its licences" yes \
    "$(grep -q 'apk list -I.*> */app/licences/alpine-packages.txt' "$ROOT/Dockerfile" && echo yes || echo no)"
chk "    and copies in every package's licence texts" yes \
    "$(grep -q 'deploy/licences/alpine/ */app/licences/alpine/' "$ROOT/Dockerfile" && echo yes || echo no)"

echo "=== a pair is one switch, HA_ENABLED, with the same effect on every path ==="
# "This data center will have a standby" has to turn on the key tunnel AND create the OCSP,
# CMP RA and SCEP RA keys copyable, on every path, at install: a key is copyable or not from
# the moment it is generated, so a path that leaves either to the operator builds pairs whose
# standby cannot sign or answer OCSP after a failover. Kubernetes had the switch; compose,
# native and cloud gained it together. Each installer must read it and write both effects.
for f in deploy/install.sh deploy/native/install-native.sh deploy/k8s/apply.sh; do
    chk "  $f reads HA_ENABLED" yes \
        "$(grep -qE '(yesno|ask) HA_ENABLED|HA_ENABLED:-' "$ROOT/$f" && echo yes || echo no)"
    chk "    and turns the key tunnel on" yes \
        "$(grep -qE 'P11_TLS=on' "$ROOT/$f" && echo yes || echo no)"
    chk "    and creates service keys copyable" yes \
        "$(grep -q 'SERVICE_KEYS_REPLICABLE' "$ROOT/$f" && echo yes || echo no)"
done
# Compose's config file is tracked and shared, so the key reaches the services only through
# .env, which the loader reads only for the keys it lists.
chk "  the loader reads SERVICE_KEYS_REPLICABLE from the environment (compose's route)" yes \
    "$(sed -n '/^Config Config::from_env/,/^    }) {/p' "$ROOT/src/lib/config.cpp" | grep -q '"SERVICE_KEYS_REPLICABLE"' && echo yes || echo no)"

# ⚠️ AN ENVSUBST BLOCK MUST NOT CARRY ITS OWN INDENTATION. Every placeholder in the
# manifests is already indented to the depth its key belongs at — `  $STORAGE_CLASS_BLOCK`
# under a PVC's spec, eight spaces under a volumeClaimTemplate's — and envsubst substitutes
# in place, so leading spaces in the VALUE are added to the template's and put the key one
# level too deep. Measured against a real cluster:
#
#   PersistentVolumeClaim ... strict decoding error: unknown field
#   "spec.resources.storageClassName"
#
# It stopped the deploy at the PVC step, and it had been there unnoticed because
# STORAGE_CLASS and INGRESS_* are EMPTY by default — an empty value renders a
# whitespace-only line that YAML ignores, so only a deployment that actually asks for a
# storage class or an ingress ever saw it. Which is every real one.
#
# A multi-line block gets the template's indentation on its FIRST line only, so this checks
# the first line and leaves the continuations, which carry their own relative depth.
echo "=== envsubst blocks carry no indentation of their own ==="
badblocks=""
for v in $(grep -oE '^[[:space:]]*[A-Z_]+_BLOCK=' "$APPLY" | tr -d ' =' | sort -u); do
    # The assigned value, first line only, non-empty assignments only.
    first=$(grep -hE "^[[:space:]]*$v=\"[^\"]" "$APPLY" | head -1 | sed -E "s/^[[:space:]]*$v=\"//")
    case "$first" in
        ' '*|'\t'*) badblocks="$badblocks $v" ;;
    esac
done
chk "  no *_BLOCK value starts with whitespace" "" "$(echo $badblocks)"
# Anti-vacuity: if the extraction stops finding blocks the check above passes forever.
chk "  PRECONDITION: blocks were found to check" yes \
    "$([ "$(grep -cE '^[[:space:]]*[A-Z_]+_BLOCK=' "$APPLY")" -gt 0 ] && echo yes || echo no)"
# And every placeholder in a manifest must be one apply.sh actually defines, or it renders
# empty and the key silently vanishes.
undef=""
for v in $(grep -rhoE '\$[A-Z_]+_BLOCK' "$ROOT/deploy/k8s/manifests/" | tr -d '$' | sort -u); do
    grep -qE "^[[:space:]]*$v=" "$APPLY" || undef="$undef $v"
done
chk "  every manifest block placeholder is defined by apply.sh" "" "$(echo $undef)"

# ⚠️ A subPath ConfigMap MOUNT IS FROZEN AT POD START. Kubernetes updates a ConfigMap volume
# in place, but NOT when it is mounted with subPath — and bootstrap.conf is, because it lands
# as a single file inside /app/config. So `apply.sh` rewriting the ConfigMap changed nothing
# a running pod could see, and would not until that pod was recreated for some unrelated
# reason. Measured on a real cluster: DATACENTER_ID and PG_TLS_SANS were correct in the
# ConfigMap and absent from the pod, so `fastpki-ca pg-tls` issued the database certificate
# WITHOUT the interconnect SAN — a certificate every peer refuses under verify-full, with
# nothing to look at, because the ConfigMap said the right thing all along.
#
# Hashing the rendered config into each pod template makes `kubectl apply` roll the pods
# exactly when the content differs, and do nothing when it does not.
echo "=== a config change reaches the pods ==="
chk "  apply.sh computes a config hash" yes \
    "$(grep -qE '^CONFIG_HASH=' "$APPLY" && echo yes || echo no)"
chk "    and exports it for envsubst" yes \
    "$(grep -qE '^export CONFIG_HASH' "$APPLY" && echo yes || echo no)"
# Every LONG-LIVED workload that mounts the config must carry it. Jobs run once and a
# CronJob re-reads the ConfigMap on its next run, so neither needs to roll.
missing=""
for f in "$ROOT"/deploy/k8s/manifests/*.yaml; do
    [ -f "$f" ] || continue
    grep -qE '^kind: (Deployment|StatefulSet|DaemonSet)$' "$f" || continue   # long-lived only
    grep -q "fastpki-bootstrap" "$f" || continue          # only the ones that mount it
    grep -q 'config-hash: "\$CONFIG_HASH"' "$f" || missing="$missing $(basename "$f")"
done
chk "  every workload mounting the config carries the hash" "" "$(echo $missing)"
# Anti-vacuity: if the loop stops matching files the check above passes over nothing.
chk "  PRECONDITION: workloads were found to check" yes \
    "$([ "$(grep -rlE '^kind: (Deployment|StatefulSet|DaemonSet)$' "$ROOT/deploy/k8s/manifests/" | wc -l | tr -d ' ')" -gt 0 ] && echo yes || echo no)"

# ⚠️ EVERY NODE HAS ITS OWN TOKEN, ON EVERY DEPLOYMENT PATH (docs/architecture.md §4). Kubernetes
# once ran one token Deployment for the cluster, with every pod mounting a node-local socket
# claim: the CA keys sat on one node's disk and losing that node lost them and the deployment
# with it. A storage class to move that token or a selector to pin it kept ONE copy of the keys.
# So what is asserted is the shape, not a setting: the token is a container of the server pod,
# its store is a claim per server, its socket never leaves the pod, and the second server
# replicates keys into its own token.
echo "=== every Kubernetes server has its own token ==="
NODE_SS="$K8SDIR/node-statefulset.yaml"
chk "  the servers are a StatefulSet" yes \
    "$(grep -qE '^kind: StatefulSet$' "$NODE_SS" 2>/dev/null && grep -q 'name: fastpki-node$' "$NODE_SS" && echo yes || echo no)"
chk "  the token is a container of the server pod" yes \
    "$(awk '/^[[:space:]]*- name: token[[:space:]]*$/{t=1; next} t&&/image:/{print "yes"; exit} t&&/- name:/{exit}' "$NODE_SS" 2>/dev/null | grep -q yes && echo yes || echo no)"
chk "  its store is a claim PER SERVER (a volumeClaimTemplate)" yes \
    "$(awk '/volumeClaimTemplates:/{v=1} v&&/name: softhsm-tokens$/{print "yes"; exit}' "$NODE_SS" 2>/dev/null | grep -q yes && echo yes || echo no)"
chk "  its socket never leaves the pod (an emptyDir)" yes \
    "$(grep -A1 -E '^[[:space:]]*- name: p11-socket[[:space:]]*$' "$NODE_SS" 2>/dev/null | grep -q 'emptyDir' && echo yes || echo no)"
chk "  no manifest shares a claim between servers" "" \
    "$(grep -lE '^kind: PersistentVolumeClaim$' "$K8SDIR"/*.yaml 2>/dev/null | xargs -r -n1 basename | tr '\n' ' ' | sed 's/ *$//')"
chk "  no other workload runs a token" "" \
    "$(grep -lE 'p11-kit-server|/scripts/token\.sh' "$K8SDIR"/*.yaml 2>/dev/null | grep -v 'node-statefulset.yaml' | xargs -r -n1 basename | tr '\n' ' ' | sed 's/ *$//')"
chk "  every server's renewal loop replicates keys into its own token" yes \
    "$(grep -q 'key sync --from-peers' "$ROOT/deploy/k8s/renew-loop.sh" 2>/dev/null && echo yes || echo no)"

# ⚠️ AND THE SAME RULE ON EVERY PATH. A key is minted on whichever host created it, so each host
# of a pair copies what it is missing from the other. A loop still syncing only a standby
# from its primary leaves keys minted on the standby out of the primary's token for ever.
echo "=== every nightly loop syncs keys from the other hosts of its data center ==="
for f in "$COMPOSE" "$ROOT/deploy/native/periodic/fastpki-certrenew" "$ROOT/deploy/k8s/renew-loop.sh"; do
    chk "  $(basename "$f") runs key sync --from-peers" yes \
        "$(grep -q 'key sync --from-peers' "$f" && echo yes || echo no)"
    chk "    and never the one-way --from \$STANDBY_OF" no \
        "$(grep -qE 'key sync[^#]*--from "?\$\$?\{?STANDBY_OF' "$f" && echo yes || echo no)"
    # ⚠️ BEFORE THE SWEEP, AND THE SWEEP'S --create-missing HELD BACK WHEN THE SYNC MAY STILL
    # SUCCEED. --create-missing re-mints a credential whose key is not in this token, so a loop
    # sweeping first took each credential away from the other host of the pair every night.
    # Line numbers of the first COMMAND line of each, comments excluded.
    _ks=$(grep -nE '^[[:space:]]*fastpki-ca .*key sync --from-peers|/fastpki-ca .*key sync --from-peers' "$f" \
          | grep -v '^[0-9]*:[[:space:]]*#' | head -1 | cut -d: -f1)
    _rs=$(grep -nE 'renew-service-certs' "$f" | grep -v '^[0-9]*:[[:space:]]*#' | head -1 | cut -d: -f1)
    chk "    and runs it before renew-service-certs" yes \
        "$([ -n "$_ks" ] && [ -n "$_rs" ] && [ "$_ks" -lt "$_rs" ] && echo yes || echo no)"
    chk "    whose --create-missing is a variable the key sync result can clear" yes \
        "$(grep -qE 'CREATE=""' "$f" && ! grep -vE '^[[:space:]]*#' "$f" | grep -q 'renew-service-certs --create-missing' \
           && echo yes || echo no)"
done
chk "  HA_ENABLED turns the token transport on, and refuses it off" yes \
    "$(grep -q 'HA_ENABLED=true with P11_TLS=off' "$APPLY" && echo yes || echo no)"

# ⚠️ SoftHSM KEEPS THE PIN ITS TOKEN WAS INITIALISED WITH, and nothing can change it from
# the deploy side. A re-apply that minted a fresh PIN therefore wrote one into the Secret
# that could not open the token: every issuing service failed with "The specified PIN is
# invalid", and fastpki-ca reported "no private key found at pkcs11 URI" for CAs whose keys
# were in the token, intact, the whole time. Measured on a real cluster — it took the
# deployment down and needed the original PIN recovered by hand.
#
# The old code PRINTED "save it if you will re-apply", which is the shape this repo keeps
# correcting: warning that the next run will break something is not the same as not
# breaking it. apply.sh must read the PIN back from the cluster instead.
echo "=== a re-apply does not invent a new token PIN ==="
chk "  apply.sh reads an existing PIN from the Secret" yes \
    "$(grep -q 'fastpkiPin' "$APPLY" && grep -q 'EXISTING_PIN' "$APPLY" && echo yes || echo no)"
chk "    and only generates when there is none" yes \
    "$(awk '/EXISTING_PIN=/{f=1} f&&/^    else$/{e=1} e&&/urandom/{print "found"; exit}' "$APPLY" | grep -q found && echo yes || echo no)"

# ⚠️ PG_TLS_SANS MUST BE DERIVED, NOT LEFT TO THE OPERATOR, on every path. `fastpki-ca
# pg-tls` reads the names for the database certificate out of CONFIG rather than from its
# arguments, so a node whose config omits its interconnect address is issued a certificate
# without that SAN — and every peer refuses it under sslmode=verify-full, long after the CAs
# exist and the hard part looks done. All three installers already ASK for that address
# (compose and native as PG_BIND, k8s as PG_INTERCONNECT), so requiring it to be typed a
# second time only creates a way to disagree with yourself.
echo "=== every installer derives PG_TLS_SANS for a mesh node ==="
# ⚠️ ONLY TWO PATHS WRITE THE KEY; COMPOSE DERIVES THE NAME AT ISSUE TIME. Asking all three
# with a bare `grep PG_TLS_SANS` put the wrong question to install.sh and passed anyway, on
# install.sh's own ⚠️ block explaining that compose writes that key NOWHERE: prose
# documenting an absence satisfied an assertion about a presence, contradicting the two
# checks below, and trimming that comment would have turned it red. So comments are
# stripped, the value has to come from the address the installer already asked for, and the
# native write is read out of conf_body() — the function that GENERATES bootstrap.conf —
# because the install summary prints the same `PG_TLS_SANS=$PG_BIND` text and must not stand
# in for a write.
NATIVE="$ROOT/deploy/native/install-native.sh"
CONFBODY="$(awk '/^conf_body\(\) [{]/{f=1; next} f&&/^[}]/{exit} f&&!/^[[:space:]]*#/' "$NATIVE")"
chk "  PRECONDITION: native's conf_body() was read" yes \
    "$([ -n "$CONFBODY" ] && echo yes || echo no)"
chk "  install-native.sh writes PG_TLS_SANS from PG_BIND into its own config" yes \
    "$(printf '%s\n' "$CONFBODY" | grep 'PG_TLS_SANS=' | grep -q 'PG_BIND' && echo yes || echo no)"
# apply.sh's write into bootstrap.conf is asserted above; what belongs here is that the
# VALUE is derived from PG_INTERCONNECT rather than being a second answer an operator has to
# keep consistent with the first.
chk "  apply.sh derives PG_TLS_SANS from PG_INTERCONNECT" yes \
    "$(grep -v '^[[:space:]]*#' "$APPLY" | grep 'PG_TLS_SANS=' | grep -q 'PG_INTERCONNECT' \
       && echo yes || echo no)"
# compose writes no such key, so its half of the requirement is that the address reaches the
# ISSUING container's environment instead — `fastpki-ca pg-tls` and certgen.sh read PG_BIND
# there, asserted below. install.sh puts it in the .env every service loads via env_file.
ENVBODY="$(awk '/^ENV_BODY=[$][(]/{f=1; next} f&&/^[)]/{exit} f&&!/^[[:space:]]*#/' "$INSTALL")"
chk "  PRECONDITION: install.sh's .env body was read" yes \
    "$([ -n "$ENVBODY" ] && echo yes || echo no)"
chk "  install.sh puts PG_BIND in the compose .env instead" yes \
    "$(printf '%s\n' "$ENVBODY" | grep -q 'PG_BIND' && echo yes || echo no)"
# ⚠️ THE CONDITION IS A ROUTABLE ADDRESS, NOT A MESH — and getting that wrong cost a whole
# HA bring-up. "A single-node deployment has no interconnect and no peers" was the stated
# reason for gating this on DEPLOYMENT=cluster, and it is false: an HA pair's PRIMARY (docs/high-availability.md §3) is
# a single-host deployment whose standby lives on another machine and dials it under
# sslmode=verify-full. Gated that way, compose issued the database certificate with no
# interconnect SAN, so the standby could not verify the primary — while the HA guide (§2) has every host of a pair give a
# routable address. The `PG_BIND != 127.0.0.1`
# guard is already the whole condition; the deployment type adds nothing to it.
chk "  compose does NOT gate it on a cluster deployment" no \
    "$(awk '/PG_TLS_SANS IS DERIVED/{f=1} f&&$0!~/^[[:space:]]*#/&&/DEPLOYMENT.*=.*cluster/{print "gated"; exit}
            f&&/starting the remaining services/{exit}' "$INSTALL" | grep -q gated && echo yes || echo no)"
# ⚠️ AND COMPOSE DOES NOT WRITE IT AT ALL ANY MORE — it reads the address at issue time.
# install.sh used to record PG_BIND into the DB overlay, reasoning that the `config` table
# is not replicated. That is true of a MESH, where each data center has its own; it is false
# of an HA pair, which replicates the whole database physically, so both hosts read one
# config table and one PG_TLS_SANS row. The primary's address became the STANDBY's
# certificate name and the standby's own was absent — found by promoting.
#
# So the guard is now inverted: compose must NOT put an interconnect address in the shared
# row, and the node's own address must reach the certificate from its environment instead.
chk "  compose does NOT record it into the shared config table" yes \
    "$(awk '/PG_TLS_SANS IS DERIVED/{f=1} f&&$0!~/^[[:space:]]*#/&&/set PG_TLS_SANS/{print "writes"; exit}
            f&&/starting the remaining services/{exit}' "$INSTALL" | grep -q writes && echo no || echo yes)"
# ⚠️ THE ISSUANCE IS IN THE LIBRARY, NOT THE CLI. It moved there so the renewal sweep could call
# it too — a database certificate maintained only by its own command is one every scheduled
# renewer has to remember, and two of three did not. The CLI is now a wrapper, so asserting
# against it would report this missing the moment it was merely relocated.
chk "  pg-tls certifies this node's own PG_BIND" yes \
    "$(grep -qE 'getenv\("PG_BIND"\)' "$ROOT/src/lib/pg_tls.cpp" && echo yes || echo no)"
chk "  and certgen does the same for the pre-CA pair" yes \
    "$(awk '/^san_list\(\)/{f=1} f&&/PG_BIND/{print "reads"; exit} f&&/^}/{exit}' \
        "$ROOT/deploy/certgen.sh" | grep -q reads && echo yes || echo no)"
# native keeps its cluster gate on purpose: docs/manual-procedures.md §11 walks a VM/native operator through
# setting this by hand (Step 0), so the two paths differ in automation, not in the rule.
# ⚠️ THE GATE HAS TO ENCLOSE THE WRITE, and the previous form could not tell: its disarm
# pattern /^conf_body/ matched the single line that OPENS the function, which comes BEFORE
# the arming match, so the flag was raised by a comment naming the key and never cleared —
# any later "DEPLOYMENT … cluster" line then satisfied it, including the install summary's
# own, and deleting the gate so conf_body wrote the key unconditionally left this green.
# conf_body() alone is read, comments stripped, and the write must follow the DEPLOYMENT
# test and precede the `fi` that closes it.
chk "  native gates it on a cluster deployment" yes \
    "$(printf '%s\n' "$CONFBODY" \
        | awk '/DEPLOYMENT/&&/cluster/{g=1; next} g&&/^[[:space:]]*fi[[:space:]]*$/{g=0; next}
               g&&/PG_TLS_SANS=/{print "gated"; exit}' | grep -q gated && echo yes || echo no)"
echo
# ⚠️ A SECRET MUST NEVER BE NAMED IN A MANIFEST. apply.sh renders every file through
# plain envsubst, which fills in ANY variable the environment holds. So a `value:
# "$PG_PASSWORD"`, or a shell command that names $PG_PASSWORD, puts the cleartext
# secret into the object that reaches the API server — where `kubectl get deployment
# -o yaml` shows it to anyone who can read workloads, and where it lands in whatever
# GitOps repository or audit log captures applied objects. A pod receives a secret
# through secretKeyRef; secret.yaml is the one file allowed to name one.
echo "=== no manifest names a secret for envsubst to fill in ==="
SECRETVARS="PG_PASSWORD|PG_REPL_PASSWORD|FASTPKI_PIN|SOFTHSM_SO_PIN|WEB_ADMIN_PASSWORD"
for m in "$K8SDIR"/*.yaml; do
    [ "$(basename "$m")" = secret.yaml ] && continue
    chk "  $(basename "$m")" no \
        "$(grep -qE "[$][{]?($SECRETVARS)" "$m" && echo yes || echo no)"
done
# Not vacuous: the Secret must still carry them, or the loop above would pass on a
# deployment that simply never delivers a password anywhere.
for k in PG_PASSWORD FASTPKI_PIN SOFTHSM_SO_PIN; do
    chk "  secret.yaml supplies $k" yes \
        "$(grep -qE "[$][{]?$k" "$K8SDIR/secret.yaml" && echo yes || echo no)"
done

# ⚠️ AND THE PASSWORD MUST NOT TRAVEL IN THE ConfigMap EITHER. bootstrap.conf becomes
# fastpki-bootstrap, which is cleartext to anyone who can read ConfigMaps. Every workload that
# opens a database connection takes the password from the Secret as PGPASSWORD, which
# libpq applies when the conninfo omits `password=` (PQconnectdb, db_postgres.cpp).
echo "=== the database password reaches every workload from the Secret ==="
chk "  apply.sh builds PG_CONNINFO without a password" yes \
    "$(grep -E '^PG_CONNINFO=' deploy/k8s/apply.sh | grep -q 'password=' && echo no || echo yes)"
for m in "$K8SDIR"/*.yaml; do
    grep -q 'subPath: bootstrap.conf' "$m" || continue
    chk "  $(basename "$m") takes PGPASSWORD from the Secret" yes \
        "$(grep -q 'name: PGPASSWORD' "$m" && echo yes || echo no)"
done

# ⚠️ THE DATABASE CERTIFICATE IS MAINTAINED BY THE SWEEP, NOT BY EACH RENEWER'S OWN COMMAND.
# It is not in the listener spec table, because its private key is a FILE rather than a token
# object — PostgreSQL's ssl_key_file takes a path and the server has no PKCS#11 support — and
# because issuance has to WRITE that pair for a third-party server that cannot re-resolve it from
# the database. Those are delivery differences. They were never a reason to keep the credential
# out of renew_service_certs_for_ca, and keeping it out cost a real outage class: while it was
# maintained only by `fastpki-ca pg-tls`, every scheduled renewer had to call that command for
# itself, the k8s and native ones never did, and compose's call sat inside `if P11_TLS = on`,
# which is off unless asked for. The certificate was issued once by hand and then expired with
# nothing to replace it, which fails every application's sslmode=verify-full against a database
# that is up and read-write.
#
# So the invariant asserted here is the one that now holds, and it is stronger than the old one:
# the SWEEP owns the credential, and every scheduled renewer runs the sweep. A renewer cannot
# forget a step it does not have to take, which is why these checks no longer look for a
# `pg-tls` call in the renewer scripts — finding one would mean the credential had drifted back
# to being somebody's job to remember.
echo "=== the renewal sweep owns the database certificate ==="
chk "  the sweep itself maintains it" yes \
    "$(grep -q 'maintain_pg_tls' "$ROOT/src/lib/service_cert.cpp" && echo yes || echo no)"
chk "  gated on PG_TLS_CA_ID naming THIS CA, not whichever came first" yes \
    "$(grep -q 'cfg.pg_tls_ca_id == ca_id' "$ROOT/src/lib/service_cert.cpp" && echo yes || echo no)"
# Not vacuous: the CLI must be a wrapper over the same function rather than a second
# implementation, or the two paths drift and only one of them gets fixed.
chk "  the CLI subcommand calls the same function" yes \
    "$(grep -q 'maintain_pg_tls' "$ROOT/src/tools/ca.cpp" && echo yes || echo no)"
# And the console, which calls the sweep too. A fix applied only to the CLI would have left a
# console-driven renewal skipping the database — the same bug one layer up.
chk "  the console renews through the same sweep" yes \
    "$(grep -q 'renew_service_certs_for_ca' "$ROOT/src/web/main.cpp" && echo yes || echo no)"

# ⚠️ AND EVERY SCHEDULED RENEWER MUST RUN THAT SWEEP, which is what makes the above reach all
# three deployment paths. The Kubernetes renewer is a SCRIPT, not the manifest: every server pod's
# renew container runs deploy/k8s/renew-loop.sh, reaching the pod through the fastpki-bootstrap ConfigMap,
# because apply.sh renders manifests through envsubst and that rewrote an inline script's
# accumulated exit status to an empty string.
echo "=== every nightly renewer runs the sweep ==="
PERIODIC="$ROOT/deploy/native/periodic/fastpki-certrenew"
K8SCRON="$ROOT/deploy/k8s/renew-loop.sh"
for f in "$COMPOSE" "$K8SCRON" "$PERIODIC"; do
    chk "  $(basename "$f") runs renew-service-certs" yes \
        "$(grep -q 'renew-service-certs' "$f" && echo yes || echo no)"
    # With the same flags: the native job ran it bare, so a native install never got its RA
    # credentials and kept its self-signed HTTPS certificates.
    chk "  $(basename "$f") creates missing credentials and replaces self-signed ones" yes \
        "$(grep -q 'create-missing' "$f" && grep -q 're-issue-self-signed' "$f" && echo yes || echo no)"
done

# ⚠️ AN OPERATIONAL SCRIPT THAT ONLY WORKS ON COMPOSE IS A DEFECT UNLESS IT SAYS SO.
#
# FastPKI ships four deployment paths — compose, native (Alpine + OpenRC), Kubernetes, and
# cloud, where a node IS a native install — and the guides send operators of all of them to
# the same scripts under deploy/. deploy/pg-promote.sh drove `docker compose` from its first
# call while three places told native and cloud operators to run it: on those hosts
# every safeguard it exists for — the refusal that stops a promotion silently dropping the
# data center out of the mesh, clearing the inherited synchronized_standby_slots, rewriting
# the conninfo and the anchor, removing STANDBY_OF — did not run at all, and nothing said so.
#
# So every script here is classified, and a NEW one fails this suite until somebody decides
# which it is. Two ways to pass:
#
#   * handle native as well — a mode switch, or reading /etc/fastpki, /etc/conf.d/fastpki,
#     or driving rc-service;
#   * declare `# deployment-path: compose-only` in the header, which is a statement that the
#     other paths have their own route to the same outcome and that the guides do not send
#     their operators here;
#   * declare `# deployment-path: any`, for a script that takes the tooling as input rather
#     than assuming it — schema-apply.sh is driven by $PSQL, which is a compose exec, a
#     kubectl exec or a bare psql depending on who runs it;
#   * declare `# deployment-path: dispatch`, for an entry point that serves every path by
#     handing over to the right one — install.sh, whose --k8s and --native modes exec
#     apply.sh and the native installer. It must carry a real --native branch to claim it.
#
# This checks the SHAPE, not the behaviour: a script carrying a native branch that does not
# work is not caught here, and nothing mechanical can catch a guide that points the wrong
# operator at the wrong tool. What it catches is the one failure that has recurred — a
# capability added on one path and left off the others.
echo "=== the native install runs on a host that has only what Alpine ships ==="
# ⚠️ FOUR SEPARATE THINGS STOPPED `install.sh --native` WORKING ON THE ONE PLATFORM IT IS
# FOR, and no suite would have caught any of them — they were found by running the documented
# one-liner on a fresh Alpine cloud instance. Each check below is one of them.
#
# A PARSE, NOT A GREP. install.sh is piped to `sh` on a stock Alpine, which has no bash, and
# sh parses the whole file before running any of it — so a single array anywhere broke the
# native path even though it sat in a branch of its own. Measured: `syntax error: unexpected
# "("`, exit 2. Grepping for bash-isms would be a guess at the list; this asks the question.
chk "  deploy/install.sh parses under POSIX sh" yes \
    "$(sh -n "$ROOT/deploy/install.sh" 2>/dev/null && echo yes || echo no)"
chk "    and does not ask for bash in its shebang" yes \
    "$(head -1 "$ROOT/deploy/install.sh" | grep -q bash && echo no || echo yes)"

# ⚠️ github.com PUBLISHES NO AAAA RECORD, so an IPv6-only host cannot reach it however
# healthy its network — and FastPKI's own cloud module builds IPv6-only nodes. The message
# said "no published release found", which sends the operator to the releases page instead of
# the network. Two things must exist: a message that names the real problem, and --package,
# which is how such a node is installed at all.
chk "  install.sh tells a node that cannot reach GitHub so" yes \
    "$(grep -q 'cannot reach' "$ROOT/deploy/install.sh" \
       && grep -q 'no IPv6 address' "$ROOT/deploy/install.sh" && echo yes || echo no)"
chk "    and offers --package for a node with no route to it" yes \
    "$(grep -qE '^\s+--package\)' "$ROOT/deploy/install.sh" && echo yes || echo no)"

# ⚠️ THE PACKAGE BRINGS FILES, NOT PACKAGES. build-native.sh has always shipped the list its
# programs link against and nothing acted on it: a fresh host had 4 of 16, `bash` among the
# missing — which install-native.sh itself needs — so the handover died with
# "env: can't execute 'bash'" AFTER the unpack, leaving a half-installed host.
chk "  install.sh installs the packages the release declares" yes \
    "$(grep -q 'install_runtime_packages()' "$ROOT/deploy/install.sh" && echo yes || echo no)"
chk "    at both the downloaded and the local-package unpack" 2 \
    "$(grep -c 'install_runtime_packages "[^"]*" || exit 1' "$ROOT/deploy/install.sh")"

# ⚠️ AND apk MUST NOT HAVE THE LAST WORD. p11-kit is on that list, and on a fresh host
# `apk add p11-kit` wrote Alpine's stock libp11-kit.so.0 over the patched one the package had
# just unpacked. Every service still started; the token simply offered no EdDSA or ML-DSA
# keys. Measured on alpine:3.24 with the v0.3.0 package: patched, stock after apk, patched
# again after a second unpack.
chk "    and unpacks the package again after apk adds anything" yes \
    "$(awk '/^  install_runtime_packages\(\)/{f=1} f&&/apk add --no-cache \$_missing/{a=1} f&&a&&/tar xzf "\$1" -C \//{print "yes"; exit} f&&/^  }/{exit}' "$ROOT/deploy/install.sh")"
chk "  build-native.sh records the checksums of the patched libraries" yes \
    "$(grep -q '/usr/share/fastpki/patched-libs.sha256' "$ROOT/deploy/native/build-native.sh" && echo yes || echo no)"
chk "  install-native.sh refuses a host where a stock library replaced one" yes \
    "$(grep -q 'sha256sum -c /usr/share/fastpki/patched-libs.sha256' "$ROOT/deploy/native/install-native.sh" && echo yes || echo no)"

# ⚠️ AND THE WORST OF THE FOUR: A PACKAGE IS TIED TO THE ALPINE RELEASE IT WAS BUILT ON.
# Sonames move between releases, so a 3.24 package on 3.23 unpacks perfectly, the installer
# reports success, ten services report "started", and every binary then dies at exec for want
# of libxmlsec1-openssl.so.10311. Exit 0, console answering nothing. The package must record
# what it was built on, and BOTH installers must check it — install-native.sh needs its own
# copy because the documented update path unpacks by hand and never runs install.sh.
chk "  the package records the Alpine release it was built on" yes \
    "$(grep -q 'alpine-release' "$ROOT/deploy/native/build-native.sh" && echo yes || echo no)"
chk "    install.sh refuses a package built for another Alpine" yes \
    "$(grep -q 'check_alpine_release()' "$ROOT/deploy/install.sh" \
       && grep -q 'check_alpine_release || exit 1' "$ROOT/deploy/install.sh" && echo yes || echo no)"
chk "    and install-native.sh refuses it too, on its own path" yes \
    "$(grep -q 'usr/share/fastpki/alpine-release' "$ROOT/deploy/native/install-native.sh" && echo yes || echo no)"

echo "=== every operational script is classified for the paths it serves ==="
UNCLASSIFIED=""
for f in "$ROOT"/deploy/*.sh; do
    b="$(basename "$f")"
    grep -qE 'docker compose|\$DC ' "$f" 2>/dev/null || continue     # not a compose driver
    # Runs on the operator's machine and reaches servers of every path (deploy/node-access.sh),
    # so it is never installed on a node: that would give one host root on its peers.
    if grep -qE '^# deployment-path: operator' "$f" 2>/dev/null; then
        echo "  [PASS] $b runs on the operator's machine, for every path"; pass=$((pass+1)); continue
    fi
    # ⚠️ A DISPATCHER IS SERVED BY THE RELEASE, NOT BY THE NODE. install.sh handles every
    # path by handing over to the right one — --k8s to k8s/apply.sh, --native to the
    # published native package or to native/install-native.sh — so it genuinely serves
    # native and would be caught by the branch below as "serves native but is not installed
    # on the node". It is not installed there on purpose: the native route is the published
    # one-liner, which fetches the script itself, and what the package leaves behind is
    # fastpki-install-native. Requiring a compose wizard on a native host to satisfy this
    # check would put a file there that nothing runs.
    #
    # Narrow on purpose: it must actually HAVE the native branch. Otherwise this becomes
    # the blanket excuse that `compose-only` is not allowed to be.
    if grep -qE '^# deployment-path: dispatch' "$f" 2>/dev/null; then
        if grep -qE '^ *--native\)|TARGET=native' "$f" 2>/dev/null; then
            echo "  [PASS] $b dispatches to every path, and has the native branch to prove it"
            pass=$((pass+1)); continue
        fi
        echo "  [FAIL] $b declares dispatch but has no --native branch"; fail=$((fail+1)); continue
    fi
    if grep -qE '/etc/fastpki|/etc/conf\.d/fastpki|rc-service|FASTPKI_PROMOTE_MODE' "$f" 2>/dev/null; then
        # Serving native is only real if the native build puts the script on the node.
        # pg-promote.sh supported native for a long time while the guide told a cloud
        # operator to run it on a node that did not have it.
        if grep -qE "inst [0-9]+ \"\\\$ROOT/deploy/$b\"" "$ROOT/deploy/native/build-native.sh"; then
            echo "  [PASS] $b serves native as well as compose, and the native build installs it"
            pass=$((pass+1))
        else
            UNSHIPPED="${UNSHIPPED:-} $b"
        fi
        continue
    fi
    if grep -qE '^# deployment-path: (compose-only|any)' "$f" 2>/dev/null; then
        echo "  [PASS] $b declares its paths: $(sed -n 's/^# deployment-path: //p' "$f" | head -1)"
        pass=$((pass+1)); continue
    fi
    UNCLASSIFIED="$UNCLASSIFIED $b"
done
chk "no compose-driving script is unclassified" "" "$UNCLASSIFIED"
chk "every script that serves native is installed by the native build" "" "${UNSHIPPED:-}"
# The census must actually have read something: a glob that matched nothing, or a tree
# without deploy/, would otherwise pass this silently.
chk "  PRECONDITION: the census saw the scripts" yes \
    "$([ "$(ls "$ROOT"/deploy/*.sh 2>/dev/null | wc -l)" -ge 8 ] && echo yes || echo no)"

# ── every topology line anyone can copy has all FOUR fields ───────────────────────────────
# fastpki-mesh takes dc_id|conninfo|serial_prefix|base_url and refuses a line with three, so
# a three-field example is not a typo an operator can work around: it stops the mesh at the
# first command. Both the cloud module's mesh_topology output and §12's example shipped with
# base_url missing, and the operator following them hit "expected 4 '|'-separated fields".
# base_url is the address a CLIENT fetches the CRL and CA certificate from, and it is written
# into every certificate the mesh issues, so it cannot be added afterwards either.
#
# A topology line is recognised by its `<digits>|host=` opening, which is what every example
# and every generator uses, and nothing else in these files looks like.
BAD_TOPOLOGY=""
for f in "$ROOT"/docs/*.md "$ROOT"/deploy/cloud/aws/*.tf "$ROOT"/deploy/cloud/*.md; do
    [ -f "$f" ] || continue
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        # Count the separators on the topology line itself, after stripping any markdown or
        # HCL quoting around it. Four fields means exactly three '|'.
        bars=$(printf '%s' "$line" | tr -cd '|' | wc -c | tr -d ' ')
        [ "$bars" -eq 3 ] || BAD_TOPOLOGY="$BAD_TOPOLOGY $(basename "$f"):${bars}bars"
    done <<EOF
$(grep -hoE '[0-9]+\|host=[^"]*' "$f" 2>/dev/null)
EOF
done
chk "every topology example and generator emits four fields" "" "$BAD_TOPOLOGY"

echo "=== every install wizard asks the compose wizard's questions, in its order ==="
# The compose wizard is the reference. Each other wizard asks its questions in the same order,
# under the same answers-file keys, so one answers file serves every path and an operator who
# learnt one wizard knows them all. Four wizards drifted apart before this: the native one
# still asked a data-center COUNT and a CMP trust anchor that compose had dropped, asked the
# standby question in another place, and was the only one to ask an HSM's token label; the
# cloud one asked no service keys at all; Kubernetes had no wizard.
#
# ⚠️ EVERY DIFFERENCE IS ARGUED HERE, BY NAME. `skips` is a compose question a path answers
# another way; `adds` is a question only that path can ask. Anything outside both lists — a
# question added to one wizard, or asked in another order — fails.
wizard_questions(){   # <file> -> VAR VAR … in file order, first occurrence only
    grep -oE '^[[:space:]]*(\[ "\$WANT_[A-Z]+" +=[[:space:]]+yes \] +&& )?(ask|yesno|ask_service_key) [A-Z0-9_]+' "$1" \
        | awk '{print $NF}' | awk '!seen[$0]++' | tr '\n' ' ' | sed 's/ $//'
}
REF_Q="$(wizard_questions deploy/install.sh)"
chk "  PRECONDITION: the compose wizard's questions were read" yes \
    "$([ "$(printf '%s' "$REF_Q" | wc -w)" -ge 20 ] && echo yes || echo no)"
wizard_parity(){   # <label> <file> <skips> <adds>
    _got="$(wizard_questions "$2")"
    _want=""; for q in $REF_Q; do
        case " $3 " in *" $q "*) ;; *) _want="${_want:+$_want }$q" ;; esac
    done
    _common=""; _extra=""
    for q in $_got; do
        case " $REF_Q " in
            *" $q "*) _common="${_common:+$_common }$q" ;;
            *) case " $4 " in *" $q "*) ;; *) _extra="${_extra:+$_extra }$q" ;; esac ;;
        esac
    done
    chk "$1: the compose questions, in compose's order" "$_want" "$_common"
    chk "$1: no question of its own beyond the argued ones" "" "$_extra"
}
# Kubernetes: the same wizard, question for question.
wizard_parity "Kubernetes" deploy/k8s/k8s-install.sh "" ""
# Native: no container image — the installed package is what runs. What it adds is a database
# that may live elsewhere (a managed PostgreSQL), which compose never needed.
wizard_parity "native" deploy/native/install-native.sh "FASTPKI_IMAGE" \
    "PG_LOCAL PG_HOST PG_PORT PG_SSLROOTCERT"
# Cloud: it provisions the hosts, so it asks what only a cloud can answer, and answers these
# compose questions another way: the deployment type and each node's data-center index and
# address come from the number of data centers it builds, a standby from STANDBY_DCS, the
# release from the image or version, and the password and PIN are generated on each node so
# that no secret is in the tfvars or the state.
wizard_parity "cloud" deploy/cloud/cloud-install.sh \
    "DEPLOYMENT FASTPKI_IMAGE DC_INDEX PG_BIND HA_ENABLED PG_PASSWORD PKCS11_PIN" \
    "CLOUD DEPLOYMENT_NAME REGION AWS_ACCOUNT_ID DC_COUNT STANDBY_DCS INSTANCE_TYPE WEB_PORT DATA_GB AMI_ID FASTPKI_VERSION ADMIN_CIDRS REALLY CLIENT_CIDRS SSH_KEY ROUTE53_ZONE PUBLIC_IPV4"
# The cloud answers reach each node: what the wizard asks, the node's answers file carries.
chk "cloud: the token label reaches each node's answers" yes \
    "$(grep -q '^PKCS11_TOKEN=\${pkcs11_token}' deploy/cloud/aws/user-data.sh.tftpl && echo yes || echo no)"
chk "cloud: the service keys reach each node's answers" yes \
    "$(grep -q 'for k, v in service_keys' deploy/cloud/aws/user-data.sh.tftpl && echo yes || echo no)"
chk "cloud: both node templates are given them" 2 \
    "$(grep -c 'service_keys *= var.service_keys' deploy/cloud/aws/instances.tf)"

echo "=== every cloud module takes the installer's key storage values, and passes them on ==="
# ⚠️ A CLOUD MODULE WRITES ITS VARIABLES INTO A NATIVE ANSWERS FILE, SO THEIR VALUES ARE THE
# INSTALLER'S. The Proxmox module accepted key_backend = "pkcs11", wrote it unchanged, and
# install-native.sh stopped every node's first boot with "KEY_BACKEND must be 'softhsm' or
# 'hsm'". It also had no pkcs11_module or pkcs11_token, so an HSM could not be named at all.
_native_kb=$(sed -n 's/^case "\$KEY_BACKEND" in \([a-z|]*\)).*/\1/p' deploy/native/install-native.sh | head -1 | tr '|' '\n' | sort | tr '\n' ' ')
chk "PRECONDITION: the installer's key storage values were read" "hsm softhsm " "$_native_kb"
for _m in aws proxmox; do
    _d="deploy/cloud/$_m"
    _tpl=$(ls "$_d"/*.tftpl | head -1)
    _mod_kb=$(sed -n '/^variable "key_backend"/,/^}/p' "$_d/variables.tf" | sed -n 's/.*contains(\[\(.*\)\], var.key_backend).*/\1/p' | tr -d '" ' | tr ',' '\n' | sort | tr '\n' ' ')
    chk "$_m: key_backend accepts exactly the installer's values" "$_native_kb" "$_mod_kb"
    for _v in pkcs11_module pkcs11_token service_keys; do
        chk "$_m: declares $_v"                    yes "$(grep -q "^variable \"$_v\"" "$_d/variables.tf" && echo yes || echo no)"
        chk "$_m: hands $_v to the node template" yes "$(grep -qE "^ *$_v *= var.$_v" "$_d"/*.tf && echo yes || echo no)"
    done
    chk "$_m: the answers carry PKCS11_MODULE and PKCS11_TOKEN" yes \
        "$(grep -q 'PKCS11_MODULE=\${pkcs11_module}' "$_tpl" && grep -q 'PKCS11_TOKEN=\${pkcs11_token}' "$_tpl" && echo yes || echo no)"
    chk "$_m: the answers carry each service key"             yes \
        "$(grep -q 'for k, v in service_keys' "$_tpl" && echo yes || echo no)"
done
# The round trip, when OpenTofu is here: render a Proxmox node's answers for an HSM and give
# them to the real installer. Not counted when OpenTofu is absent.
if command -v tofu >/dev/null 2>&1; then
    _W=$(mktemp -d)
    printf 'templatefile("%s", { deployment = "single", ci_user = "fastpki", pki_dns = "pki.example.org", dc_index = 1, pg_local = "yes", key_backend = "hsm", pkcs11_module = "/usr/lib/vendor/p11.so", pkcs11_token = "hsm-1", service_keys = { WEB_KEY_ALGO = "rsa", WEB_KEY_BITS = "3072" }, nameservers = [], p11_tls = "off", pkcs11_pin = "", interconnect_ip = "", enabled_protocols = ["est"], all_protocols = ["est"], release_version = "v0", release_mirror = "", release_pubkey = "K", firstboot_install = "true" })\n' \
        "$ROOT/deploy/cloud/proxmox/vendor-data.yaml.tftpl" | (cd "$_W" && tofu console -no-color 2>/dev/null) \
      | awk '/path: \/root\/fastpki-answers.env/{f=1; next} f && /content: \|/{c=1; next} c && /^  - path:/{exit} c {sub(/^      /,""); if ($0 != "") print}' > "$_W/answers.env"
    chk "proxmox: a rendered HSM node's answers name the module" yes "$(grep -qx 'PKCS11_MODULE=/usr/lib/vendor/p11.so' "$_W/answers.env" && echo yes || echo no)"
    bash deploy/native/install-native.sh --answers "$_W/answers.env" --print-conf > "$_W/conf.txt" 2>/dev/null
    chk "proxmox: the installer accepts them"                   0   "$?"
    chk "  and every key lives on the HSM's token"              yes "$(grep -q '^WEB_TLS_KEY=pkcs11:token=hsm-1;' "$_W/conf.txt" && echo yes || echo no)"
    chk "  and the chosen service key reaches the config"       yes "$(grep -qx 'WEB_KEY_ALGO=rsa' "$_W/conf.txt" && echo yes || echo no)"
    rm -rf "$_W"
else
    echo "  (OpenTofu not installed: the rendered round trip is not run)"
fi

# ⚠️ A RE-APPLY IS ALSO AN UPGRADE. apply.sh's closing text said "It does not replicate yet"
# on every apply with an interconnect address, so upgrading a working mesh ended by telling the
# operator to connect it again. The block is run here, with the one database call stubbed, for
# a cluster that knows 2 data centers, 1, and a database that did not answer.
echo "=== k8s: the closing text on a cluster that is already meshed ==="
_blk=$(awk '/IDENTITY AND POINTERS ONLY — DO NOT REPRINT THE MESH/{on=1} on{print} on && /^fi$/{exit}' "$ROOT/deploy/k8s/apply.sh")
_closing() {   # <datacenters count, empty for no answer> <PG_INTERCONNECT>
    STUB_DCS=$1 PG_INTERCONNECT=$2 DC_INDEX=1 NAMESPACE=fastpki PRIMARY=fastpki-node-0 \
        PG_USER=fastpki PG_DB=fastpki bash -c "kx(){ [ -n \"\$STUB_DCS\" ] && echo \"\$STUB_DCS\"; }; $_blk" 2>&1
}
chk "PRECONDITION: the closing block is found in apply.sh" yes \
    "$(printf '%s\n' "$_blk" | grep -q 'mesh-join.sh' && echo yes || echo no)"
_o=$(_closing 2 10.0.0.1)
chk "  2 data centers: it says the cluster is already meshed" yes \
    "$(printf '%s\n' "$_o" | grep -q 'already part of a mesh of 2 data centers' && echo yes || echo no)"
chk "  2 data centers: and does not say it does not replicate" no \
    "$(printf '%s\n' "$_o" | grep -q 'does not replicate yet' && echo yes || echo no)"
chk "  1 data center: it points at mesh-join.sh" yes \
    "$(_closing 1 10.0.0.1 | grep -q 'does not replicate yet' && echo yes || echo no)"
chk "  no answer from the database: it points at mesh-join.sh" yes \
    "$(_closing '' 10.0.0.1 | grep -q 'does not replicate yet' && echo yes || echo no)"
chk "  no interconnect address: it prints nothing about a mesh" "" "$(_closing 2 '')"

# The same for the two installers, which are also their deployments' upgrade path: install.sh
# for Docker Compose, install-native.sh for a native host and for the cloud images (AWS,
# Proxmox), which run it. On a first install the closing text is unchanged; on an update it
# must not say admin / admin, that no CA exists, or that the node does not replicate. Each
# closing block runs to the end of its script, under the script's own `set` options, with the
# database stubbed (`docker` for compose, `psql` for native) and a marker printed after it, so a
# database that does not answer cannot end the install there.
_inst_closing() {   # <file> <stub function> <set options> <deployment> <data centers> <CAs>
    _b=$(awk '/THIS SCRIPT IS ALSO THE UPGRADE PATH/{on=1} on{print}' "$ROOT/$1")
    STUB_DCS=$5 STUB_CAS=$6 HERE=/nonexistent DEPLOYMENT=$4 DC_INDEX=2 KEY_BACKEND=hsm \
        PKCS11_MODULE_OUT= _keyline="key backend hsm" _sansline="PG_TLS_SANS=10.0.0.2" \
        PG_BIND=10.0.0.2 PG_HOST=127.0.0.1 PG_PORT=5432 PKI_DNS=pki.example.org \
        CONF=/nonexistent/fastpki.conf bash -c "set $3
cd(){ :; }
$2(){ case \"\$*\" in *datacenters*) _s=\$STUB_DCS;; *is_ca*) _s=\$STUB_CAS;; *) _s=;; esac
      [ -n \"\$_s\" ] && echo \"\$_s\"; }
$_b
echo CLOSING-TEXT-COMPLETE" 2>&1
}
_has(){ printf '%s\n' "$1" | grep -qF -- "$2" && echo yes || echo no; }
for _p in "compose|deploy/install.sh|docker|-eu -o pipefail" \
          "native|deploy/native/install-native.sh|psql|-euo pipefail"; do
    IFS='|' read -r _l _f _stub _set <<EOF
$_p
EOF
    echo "=== $_l: the closing text on a first install and on an update ==="
    chk "PRECONDITION: the closing block is found in $_f" yes \
        "$(_has "$(_inst_closing "$_f" "$_stub" "$_set" single 1 0)" 'CLOSING-TEXT-COMPLETE')"
    _o=$(_inst_closing "$_f" "$_stub" "$_set" single 1 0)
    chk "  first install, single: admin / admin"                  yes "$(_has "$_o" 'admin / admin')"
    chk "  first install, single: no CA exists yet"               yes "$(_has "$_o" 'No CA exists yet')"
    _o=$(_inst_closing "$_f" "$_stub" "$_set" cluster 1 0)
    chk "  first install, cluster: admin / admin"                 yes "$(_has "$_o" 'admin / admin')"
    chk "  first install, cluster: it does not replicate yet"     yes "$(_has "$_o" 'does not replicate yet')"
    _o=$(_inst_closing "$_f" "$_stub" "$_set" single 1 2)
    chk "  update, single with 2 CAs: no admin / admin"           no  "$(_has "$_o" 'admin / admin')"
    chk "  update, single with 2 CAs: no 'no CA exists yet'"      no  "$(_has "$_o" 'No CA exists yet')"
    chk "  update, single with 2 CAs: it says the CAs are there"  yes "$(_has "$_o" '2 CA instance(s) present')"
    _o=$(_inst_closing "$_f" "$_stub" "$_set" cluster 2 3)
    chk "  update, meshed cluster: no admin / admin"              no  "$(_has "$_o" 'admin / admin')"
    chk "  update, meshed cluster: already part of a mesh"        yes "$(_has "$_o" 'already part of a mesh')"
    chk "  update, meshed cluster: not 'does not replicate yet'"  no  "$(_has "$_o" 'does not replicate yet')"
    _o=$(_inst_closing "$_f" "$_stub" "$_set" cluster '' '')
    chk "  no answer from the database: the install still ends"  yes "$(_has "$_o" 'CLOSING-TEXT-COMPLETE')"
    chk "  no answer from the database: first-install text"      yes "$(_has "$_o" 'does not replicate yet')"
done

echo "=== DEPLOY PARITY: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
