#!/usr/bin/env bash
# The Services that publish a Kubernetes pair to its peer data centers each take their own port,
# and the mesh dials each server on the port its Service really has.
#
# ⚠️ WHY THIS IS A TEST. Both servers' database Services were published on 5432, and both
# token-transport Services on 12345. A load balancer that publishes on the machines' own
# addresses — k3s's does — claims the port on every machine, so the first Service took 5432 on
# both machines and the second never got an address. Every peer address then led to
# fastpki-node-0, which works exactly as long as fastpki-node-0 is the primary: after a promotion
# no peer could reach the new primary, and replication out of that data center stopped with
# nothing reporting it. mesh-join also wrote port=5432 for every address, so a per-server port
# has to reach the topology too, or the Services change and the peers still dial 5432.
#
# No cluster required: it asserts on what `apply.sh --render` would apply, on what
# node-access.sh reads back through a stand-in kubectl, and on how mesh-join turns that into
# the topology's ports.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

mkdir -p "$W/deploy"
cp -R "$ROOT/deploy/k8s" "$W/deploy/k8s"
cp "$ROOT/deploy/bootstrap.compose.conf" "$ROOT/deploy/certgen.sh" "$W/deploy/" 2>/dev/null
K="$W/deploy/k8s"

render() {   # render <env.local lines...>: the rendered manifests on stdout
    rm -f "$K/env.local" "$K/env.local.bak"
    printf '%s\n' "IMAGE=fastpki:test" "$@" > "$K/env.local"
    sh "$K/apply.sh" --render 2>/dev/null
}
# "<name> <port> <nodePort>" for every rendered Service of a type, one line each.
services_of_type() {   # services_of_type <type> < manifests
    awk -v want="$1" '
        function flush() { if (kind == "Service" && type == want) for (i = 1; i <= np; i++) print name, port[i], node[i]; }
        /^---/ { flush(); kind = ""; type = ""; name = ""; np = 0; next }
        /^kind:/ { kind = $2 }
        /^  name:/ && name == "" { name = $2 }
        /^  type:/ { type = $2 }
        /(^|[ {,])port: *[0-9]+/ { s = $0; sub(/.*(^|[ {,])port: */, "", s); sub(/[^0-9].*/, "", s); port[++np] = s; node[np] = "-" }
        /nodePort: *[0-9]+/ { s = $0; sub(/.*nodePort: */, "", s); sub(/[^0-9].*/, "", s); node[np] = s }
        END { flush() }'
}
port_of() { awk -v n="$1" '$1 == n { print $2 }' "$2"; }
node_port_of() { awk -v n="$1" '$1 == n { print $3 }' "$2"; }

echo "=== a pair published through a load balancer: one port per server ==="
render HA_ENABLED=true DC_INDEX=1 PG_INTERCONNECT=10.0.0.1,10.0.0.2 PG_EXTERNAL_TYPE=LoadBalancer \
       P11_TLS_SERVICE_TYPE=LoadBalancer PROTO_SERVICE_TYPE=LoadBalancer > "$W/pair.yaml"
services_of_type LoadBalancer < "$W/pair.yaml" > "$W/pair.lb"
chk "fastpki-node-0's database is published on 5432"       5432  "$(port_of postgres-external-0 "$W/pair.lb")"
chk "fastpki-node-1's database is published on 5433"       5433  "$(port_of postgres-external-1 "$W/pair.lb")"
chk "both reach the database's own port 5432"              "2"   "$(awk '/^---/ { if (pe && tp) n++; pe = tp = 0 } /name: postgres-external-/ { pe = 1 } /targetPort: 5432/ { tp = 1 } END { if (pe && tp) n++; print n + 0 }' "$W/pair.yaml")"
chk "fastpki-node-0's token transport is published on 12345" 12345 "$(port_of fastpki-p11-tls-0 "$W/pair.lb")"
chk "fastpki-node-1's token transport is published on 12346" 12346 "$(port_of fastpki-p11-tls-1 "$W/pair.lb")"
# The shape, not the two sites: whatever else is added later, no two LoadBalancer Services may
# claim one port, because such a load balancer can publish only one of them.
_dup=$(awk '{ print $2 }' "$W/pair.lb" | sort | uniq -d | tr '\n' ' ')
chk "no two LoadBalancer Services claim the same port"     ""    "$_dup"
chk "PRECONDITION: the LoadBalancer Services were found"   yes   "$([ "$(wc -l < "$W/pair.lb")" -ge 10 ] && echo yes || echo no)"

echo "=== a single server keeps 5432 ==="
render DC_INDEX=2 PG_INTERCONNECT=10.0.0.3 PG_EXTERNAL_TYPE=LoadBalancer > "$W/one.yaml"
services_of_type LoadBalancer < "$W/one.yaml" > "$W/one.lb"
chk "the one server's database is published on 5432"      5432  "$(port_of postgres-external-0 "$W/one.lb")"
chk "and there is no second database Service"             ""    "$(port_of postgres-external-1 "$W/one.lb")"

echo "=== a pair published through node ports: one node port per server ==="
render HA_ENABLED=true DC_INDEX=1 PG_INTERCONNECT=10.0.0.1,10.0.0.2 PG_EXTERNAL_TYPE=NodePort > "$W/np.yaml"
services_of_type NodePort < "$W/np.yaml" > "$W/np.lb"
chk "fastpki-node-0's node port is PG_NODEPORT"            31432 "$(node_port_of postgres-external-0 "$W/np.lb")"
chk "fastpki-node-1's node port is PG_NODEPORT+1"          31433 "$(node_port_of postgres-external-1 "$W/np.lb")"

echo "=== node-access reads each server's port back from its Service ==="
# A stand-in kubectl answering the three reads na_facts makes of a Kubernetes data center.
mkdir -p "$W/bin"
cat > "$W/bin/kubectl" <<'EOF'
#!/bin/sh
case "$*" in
    *"get configmap fastpki-bootstrap"*)
        printf 'DATACENTER_ID=1\nPKI_DNS=pki.example.org\nPG_TLS_SANS=10.0.0.1,10.0.0.2\n' ;;
    *"get secret fastpki-secret"*) printf 'cHc=' ;;
    *"get service postgres-external-"*)
        _o=$(printf '%s' "$*" | sed -n 's/.*postgres-external-\([0-9]*\).*/\1/p')
        [ "$_o" -lt "${FAKE_SERVICES:-2}" ] || exit 1
        printf '%s %s %s' "$FAKE_TYPE" $((5432 + _o)) $((31432 + _o)) ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$W/bin/kubectl"
facts() { ( PATH="$W/bin:$PATH"; . "$ROOT/deploy/node-access.sh"; na_facts k8s:dc1/fastpki ) | sed -n "s/^$1=//p"; }
chk "the addresses are read as before"                    10.0.0.1,10.0.0.2 "$(FAKE_TYPE=LoadBalancer facts BIND)"
chk "LoadBalancer: each server's Service port"            5432,5433         "$(FAKE_TYPE=LoadBalancer facts PORTS)"
chk "NodePort: each server's node port"                   31432,31433       "$(FAKE_TYPE=NodePort facts PORTS)"
chk "a Service that is missing leaves its port empty"     5432,             "$(FAKE_TYPE=LoadBalancer FAKE_SERVICES=1 facts PORTS)"

echo "=== mesh-join dials each address on its own port ==="
# db_ports is mesh-join's; lifted out so it runs without a mesh.
{ sed -n '/^upto()/p' "$ROOT/deploy/mesh-join.sh"; sed -n '/^db_ports()/,/^}/p' "$ROOT/deploy/mesh-join.sh"; } > "$W/db_ports.sh"
chk "PRECONDITION: mesh-join has db_ports"                yes "$(grep -q '^db_ports()' "$W/db_ports.sh" && echo yes || echo no)"
dbp() { ( . "$W/db_ports.sh"; db_ports "$1" "$2" ) 2>/dev/null || echo REFUSED; }
chk "a Kubernetes pair: the ports it reported"            5432,5433   "$(dbp 10.0.0.1,10.0.0.2 5432,5433)"
chk "native or Compose (no ports reported): 5432 each"    5432,5432   "$(dbp 10.0.0.1,10.0.0.2 '')"
chk "a single server with none reported: 5432"            5432        "$(dbp 10.0.0.3 '')"
chk "a port missing for one address is refused"           REFUSED     "$(dbp 10.0.0.1,10.0.0.2 5432,)"
chk "the topology takes its ports from PORTS_i"           yes "$(sed -n '/^topology_for()/,/^}/p' "$ROOT/deploy/mesh-join.sh" | grep -q '_ports=\\\$PORTS_' && echo yes || echo no)"

echo
echo "=== K8S INTERCONNECT PORTS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
