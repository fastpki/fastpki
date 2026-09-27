#!/usr/bin/env bash
# REAL cross-DC replication, against the three lab DCs — issue on one, watch it land on
# the others, CUT the dedicated interconnect, write on both sides of the break, heal, and
# watch it converge.
#
# ⚠️ WHY THIS EXISTS AND WHY tests/replication*.sh IS NOT ENOUGH.
# `replication.sh` and `replication_stream.sh` start two throwaway Postgres clusters on
# 127.0.0.1 of whoever runs the suite. That proves the MECHANISM — publication,
# subscription, a row crossing a slot — and it is genuinely useful. What it cannot
# reach is anything that needs three real nodes, a real link, and time:
#
#   * publication FROZEN at first setup — tables added by a later schema step were never
#     added to `fastpki_pub`, so they silently stopped replicating. A two-cluster test
#     built from the CURRENT schema in one shot can never see this.
#   * mesh peers holding ORPHANED certs — a divergence that only appears once three
#     nodes have been writing independently.
#
# Both were found by hand, on this lab. Nothing re-ran them. This is that check, automated.
#
# The lab exists precisely so the link CAN be broken: each DC has a dedicated interconnect
# NIC (eth1, 10.10.10.0/24) separate from NetBird management, so cutting replication does
# not cut our own SSH.
#
# SAFETY. This suite deliberately breaks a shared lab. Two rules it follows:
#   1. the EXIT trap ALWAYS restores the link and removes the markers — including on
#      Ctrl-C, a failed assertion, or an SSH timeout;
#   2. the last assertions verify the link really is back and no rule of ours survives.
#      A test that leaves the lab partitioned is worse than no test at all.
#
# Opt-in: needs the lab, so it is NOT part of the default tiers. Run it explicitly, or
# with RUN_LAB=1 from run_all.sh. SKIPs cleanly when the lab is not reachable (§3d).
set -u

KEY="${LAB_SSH_KEY:-$HOME/.ssh/fastpki_lab_ed25519}"
SSHO="-i $KEY -o StrictHostKeyChecking=no -o ConnectTimeout=8 -o BatchMode=yes"
# mgmt-ip : interconnect-ip : name   (mgmt = how WE reach it; link = what replicates)
#
# Read from an untracked per-site file, never written here: this repository names no
# infrastructure of ours, and pointing the suite at a different lab is one file.
LAB_ENV="${LAB_ENV:-$(cd "$(dirname "$0")/.." && pwd)/deploy/lab/nodes.env}"
[ -r "$LAB_ENV" ] && . "$LAB_ENV"
DCS=""
for i in 1 2 3; do
    eval "m=\${LAB_DC${i}_MGMT:-}; l=\${LAB_DC${i}_LINK:-}"
    [ -n "$m" ] && [ -n "$l" ] && DCS="$DCS ${m}:${l}:dc${i}"
done
# ⚠️ SAY WHICH KIND OF SKIP THIS IS. "lab unreachable" and "no lab configured" are
# different problems with the same silence, and the reachability probe below cannot tell
# them apart — with no addresses it would report every node down and read as an outage.
if [ -z "$DCS" ]; then
    echo "SKIP: no lab topology configured — copy deploy/lab/nodes.env.example to $LAB_ENV"
    echo "      (this is a MISSING CONFIG, not an unreachable lab)"
    echo "=== LAB REPLICATION MESH: PASS=0 FAIL=0 ==="
    exit 0
fi
# The account we SSH in as, and where that account keeps the deploy tree. One place, so a
# different lab is two env vars and not a grep-and-replace.
LAB_USER="${LAB_SSH_USER:-admin}"
LAB_REPO="${LAB_REPO:-/home/$LAB_USER/FastPKI}"
MARK="labtest-$$-$(date +%s)"          # unique per run, so a stale row cannot fake a pass
TAG="fastpki-labtest"                  # iptables comment, so cleanup is exact
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

mgmt(){ echo "$1" | cut -d: -f1; }
link(){ echo "$1" | cut -d: -f2; }
name(){ echo "$1" | cut -d: -f3; }
on(){ ssh $SSHO "$LAB_USER@$1" "$2" 2>/dev/null; }
# ⚠️ ALWAYS filter to current_database(). pg_subscription is a SHARED catalog — it carries
# rows for every database in the cluster, and this lab has leftover restore databases whose
# subscriptions are legitimately disabled. Reading it unfiltered says "replication is down"
# on a perfectly healthy mesh; it fooled me for a minute before this suite existed.
sql(){ on "$1" "sudo docker exec fastpki-postgres-1 psql -U fastpki -d fastpki -tAc \"$2\"" | tr -d ' \r'; }

echo "=== 0. is the lab reachable? ==="
REACH=0
for dc in $DCS; do [ "$(on "$(mgmt "$dc")" 'echo ok')" = ok ] && REACH=$((REACH+1)); done
if [ "$REACH" -ne 3 ]; then
    echo "SKIP: need all three lab DCs reachable over SSH (got $REACH/3)."
    echo "      Bring NetBird up, or set LAB_SSH_KEY. PASS=0 FAIL=0"
    exit 0
fi
echo "  all three DCs answer"

# ── restore EVERYTHING, whatever happens ────────────────────────────────────────────────
restore_link(){
  for dc in $DCS; do
    on "$(mgmt "$dc")" "sudo iptables-save | grep -q '$TAG' && sudo iptables-save \
        | grep -v '$TAG' | sudo iptables-restore || true"
  done
}
drop_markers(){
  for dc in $DCS; do
    sql "$(mgmt "$dc")" "DELETE FROM allowed_domains WHERE domain LIKE '${MARK}%';" >/dev/null
  done
}
cleanup(){ restore_link; drop_markers; }
trap cleanup EXIT INT TERM

DC1=$(echo $DCS | cut -d' ' -f1); DC2=$(echo $DCS | cut -d' ' -f2); DC3=$(echo $DCS | cut -d' ' -f3)
M1=$(mgmt "$DC1"); M2=$(mgmt "$DC2"); M3=$(mgmt "$DC3")
L1=$(link "$DC1"); L2=$(link "$DC2"); L3=$(link "$DC3")

echo
echo "=== 1. the mesh is healthy BEFORE we touch it ==="
# Every DC subscribes to both peers. A missing or disabled subscription here means the rest
# of this suite would be testing nothing, so it is a precondition, not a nice-to-have.
for dc in $DCS; do
  n=$(name "$dc")
  chk "$n has 2 ENABLED subscriptions" 2 \
      "$(sql "$(mgmt "$dc")" "SELECT count(*) FROM pg_subscription s JOIN pg_database d ON d.oid=s.subdbid WHERE d.datname=current_database() AND s.subenabled;")"
done
# ⚠️ THE FROZEN-PUBLICATION CHECK. This is the one a localhost test structurally cannot do:
# it builds both clusters from today's schema in one shot, so publication and schema always
# agree. On a long-lived node they drift — a schema step adds a table and nobody adds it to
# the publication, so it stops replicating with no error anywhere.
# The expected set is PINNED, not derived. "everything except a hand-written exclusion
# list" was my first attempt and it was wrong: 16 tables are unpublished and most are
# legitimately node-local (schema_version by design, web_sessions,
# config, audit_log, the ACME order/challenge working set). A guessed exclusion list fails
# noisily on healthy nodes, which trains everyone to ignore it.
#
# Pinning cuts both ways, which is the point:
#   * a table that silently LEAVES the publication fails here (the frozen-publication bug);
#   * a NEW replicable table added by a schema step fails here too, until someone adds it
#     to the publication AND to this list — a deliberate decision instead of an omission.
# ⚠️ COMMA-separated, because sql() ends in `tr -d ' \r'` to make numeric comparisons
# safe — which also eats the separator out of a space-joined string_agg and turned this
# assertion into an unreadable run-together blob. Pick a separator the helper cannot eat.
# `crls` joined the publication when an offline root gained the ability to publish a CRL
# it signed elsewhere: uploaded on one node, it has to serve from all of them, or an
# operator who uploads to dc1 and whose clients reach dc3 still gets a 503. This list was
# not updated at the time, so the check sat red on every lab run since — which is exactly
# what pinning is for, and exactly why the list has to be maintained by hand rather than
# derived from the generator. Deriving it would make the test agree with the code by
# construction and stop it noticing a table added to the publication without a decision.
# The four auth-provider tables joined the publication when directories, SAML and OIDC
# became rows instead of config keys, and — exactly as with `crls` above — this list was
# not updated at the time, so the check sat red on every lab run since. Recording the
# decision now: they MUST replicate. A provider that exists on one node and not its peers
# means the same login succeeds or fails depending which node the balancer picked, and a
# subject qualified `<id>\user` on one node has no such directory on another. The settings
# tables are separate from `auth_providers` on purpose (one per kind, no foreign key
# between them), so all four are named here rather than just the parent.
# client_configs (admin-authored, like ms_templates) and p11_transport (the token tunnel's
# trust) are in the publication too, each with its reason at the list in src/tools/mesh.cpp.
EXPECTED_PUB="allowed_domains,auth_providers,ca_xcep_uris,cert_profiles,cert_uris,certs,client_configs,crls,datacenters,foreign_anchors,keys,ldap_providers,ms_templates,node_status,node_sync_requests,oidc_providers,p11_transport,role_permissions,roles,saml_providers,subject_roles,web_users"
for dc in $DCS; do
  n=$(name "$dc")
  GOT=$(sql "$(mgmt "$dc")" "SELECT string_agg(tablename, ',' ORDER BY tablename) FROM pg_publication_tables WHERE pubname='fastpki_pub';")
  chk "$n publishes exactly the expected tables" "$EXPECTED_PUB" "$GOT"
done

echo
echo "=== 2. a write on dc1 reaches dc2 and dc3 (the link is UP) ==="
sql "$M1" "INSERT INTO allowed_domains(domain) VALUES ('${MARK}-up') ON CONFLICT DO NOTHING;" >/dev/null
seen(){ # mgmt-ip suffix  -> 1 when the row is there
  local i
  for i in $(seq 1 30); do
    [ "$(sql "$1" "SELECT count(*) FROM allowed_domains WHERE domain='${MARK}-$2';")" = "1" ] && { echo 1; return; }
    sleep 1
  done
  echo 0
}
chk "dc2 received it" 1 "$(seen "$M2" up)"
chk "dc3 received it" 1 "$(seen "$M3" up)"

echo
echo "=== 3. CUT the interconnect — dc1 is isolated from dc2 and dc3 ==="
# Drop only replication traffic on eth1, both directions, tagged so cleanup is exact.
# Management (NetBird) is a different NIC, so our SSH survives — which is the whole reason
# the lab has a dedicated interconnect.
# ⚠️ DOCKER-USER, not INPUT/OUTPUT. Postgres is a PUBLISHED CONTAINER PORT
# (`docker port` -> 5432/tcp -> 10.10.10.21:5432, DNAT to 172.18.0.12), so replication
# traffic is DNAT'd in PREROUTING and traverses FORWARD — it never reaches the INPUT or
# OUTPUT chains at all. My first version filtered there and the "partition" changed
# nothing: every row still replicated and the suite said so. DOCKER-USER is the documented
# hook Docker consults inside FORWARD before its own rules.
# Both directions: subscribers dial the publisher, so dc1 must neither accept from a peer
# nor reach one.
# ⚠️ NO PORT MATCH — and that is not laziness, it is the second bug this test found in
# itself. Replication data travels server->client, so those packets carry sport=5432 and an
# EPHEMERAL dport. Matching `--dport 5432` blocked only the dial-out and let the entire
# inbound WAL stream through: dc2's writes kept arriving at dc1 while the suite claimed the
# link was cut. Cutting the peer address outright is also the honest simulation — eth1 is
# the dedicated interconnect and carries nothing else, so this IS "the link is down".
for peer in "$L2" "$L3"; do
  on "$M1" "sudo iptables -I DOCKER-USER 1 -s $peer -m comment --comment $TAG -j DROP"
  on "$M1" "sudo iptables -I DOCKER-USER 1 -d $peer -m comment --comment $TAG -j DROP"
done
chk "the DROP rules are in place on dc1" 4 "$(on "$M1" "sudo iptables-save | grep -c $TAG")"

echo
echo "=== 4. BOTH sides keep working while partitioned ==="
# The point of a mesh: an isolated DC is still a working PKI, not a read-only cripple.
sql "$M1" "INSERT INTO allowed_domains(domain) VALUES ('${MARK}-iso1') ON CONFLICT DO NOTHING;" >/dev/null
sql "$M2" "INSERT INTO allowed_domains(domain) VALUES ('${MARK}-iso2') ON CONFLICT DO NOTHING;" >/dev/null
chk "dc1 still accepts a local write" 1 "$(sql "$M1" "SELECT count(*) FROM allowed_domains WHERE domain='${MARK}-iso1';")"
chk "dc2 still accepts a local write" 1 "$(sql "$M2" "SELECT count(*) FROM allowed_domains WHERE domain='${MARK}-iso2';")"
# ...and the partition is REAL. Without this the whole suite could pass on a link that was
# never actually cut, which is the failure mode that makes a chaos test worthless.
sleep 8
chk "dc1's write did NOT reach dc2 while cut" 0 "$(sql "$M2" "SELECT count(*) FROM allowed_domains WHERE domain='${MARK}-iso1';")"
chk "dc2's write did NOT reach dc1 while cut" 0 "$(sql "$M1" "SELECT count(*) FROM allowed_domains WHERE domain='${MARK}-iso2';")"
# dc2<->dc3 were never cut, so that pair must still be converging — proof we broke exactly
# the link we meant to and not the whole mesh.
chk "dc3 DID receive dc2's write (that pair is intact)" 1 "$(seen "$M3" iso2)"

echo
echo "=== 5. HEAL the link — both sides converge ==="
restore_link
chk "no DROP rule of ours survives on dc1" 0 "$(on "$M1" "sudo iptables-save | grep -c $TAG")"
chk "dc1's isolated write now reaches dc2" 1 "$(seen "$M2" iso1)"
chk "dc2's isolated write now reaches dc1" 1 "$(seen "$M1" iso2)"
chk "dc3 also converged on dc1's write"    1 "$(seen "$M3" iso1)"

echo
echo "=== 6. the lab is left exactly as we found it ==="
drop_markers
for dc in $DCS; do
  n=$(name "$dc")
  chk "$n has no leftover marker rows" 0 \
      "$(sql "$(mgmt "$dc")" "SELECT count(*) FROM allowed_domains WHERE domain LIKE '${MARK}%';")"
  chk "$n subscriptions still enabled"  2 \
      "$(sql "$(mgmt "$dc")" "SELECT count(*) FROM pg_subscription s JOIN pg_database d ON d.oid=s.subdbid WHERE d.datname=current_database() AND s.subenabled;")"
done


echo
echo "=== LAB REPLICATION MESH: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
