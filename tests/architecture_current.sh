#!/usr/bin/env bash
# docs/architecture.md is the design record, so it has to stay true on its own.
#
# ⚠️ THIS EXISTS BECAUSE THE DESIGN LIVED IN COMMENTS AND THEY WENT STALE. Four separate
# claims were repeated into decisions before anyone measured them: that openssl cannot sign
# with an EC token key, that certgen mints the transport keys in the token, that a token
# refuses key import, and that no key-replication mechanism had ever been built. Each was
# false, each had been copied into a default or a workaround, and two of them were quoted
# back at the owner as proof of what the product could not do.
#
# A document cannot be kept honest by good intentions, so the MECHANICAL claims in it are
# asserted here against the source. The judgement claims — which topology is wanted, whether
# the single-name shape is retained — cannot be tested and are deliberately not attempted;
# what this catches is the architecture document drifting away from code that moved
# underneath it.
#
# Static analysis of a document and a few sources. No deployment, no network.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
DOC="$ROOT/docs/architecture.md"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

[ -r "$DOC" ] || { echo "SKIP: $DOC not readable"; echo "=== ARCHITECTURE CURRENT: PASS=0 FAIL=0 ==="; exit 0; }

echo "=== the document declares how each claim is known ==="
# Every section should carry at least one tagged claim, so a reader can tell a decision from
# a measurement from a guess. A section with none is prose nobody can check.
for tag in invariant measured code open; do
    chk "it uses [$tag]" yes \
        "$(grep -q "\[$tag\]" "$DOC" && echo yes || echo no)"
done

echo "=== §6: the multi-URI key list is generation selection, not host failover ==="
# A CA names one key per GENERATION — a re-key adds a certificate and its key, both stay live
# through the rollover, and the certificate being signed under selects its own key. The HA
# reading is wrong and was carried in four places at once; these assertions pin the real one.
chk "load_signing_key splits several key URLs" yes \
    "$(grep -q "split_key_urls" "$ROOT/src/lib/x509.cpp" && echo yes || echo no)"
chk "fastpki-ca offers 'key add'" yes \
    "$(grep -qE "key add <id>" "$ROOT/src/tools/ca.cpp" && echo yes || echo no)"
# The selection is real only because resolve_ca_instance passes the certificate in use. It is
# the ONLY caller that does; if that argument is ever dropped, the list silently reverts to
# "first URL that loads" and a rekeyed CA signs with whichever generation answers first.
chk "resolve_ca_instance passes the certificate as 'expect'" yes \
    "$(grep -q "load_signing_key(rc.key, cfg, cert.get())" "$ROOT/src/lib/ca_instance.cpp" \
       && echo yes || echo no)"
chk "the document says the list does not span hosts" yes \
    "$(grep -qi "does not span hosts" "$DOC" && echo yes || echo no)"
# The claim that was wrong in the commit message, the code comment, the CLI help and docs/high-availability.md.
# The cloud modules are on this list because the phrasing survived in them once: they carry
# the same design in variable descriptions, and nothing else reads those for correctness.
for f in "$DOC" "$ROOT/docs/high-availability.md" "$ROOT/docs/cli-reference.md" "$ROOT/docs/deployment.md" \
         "$ROOT/deploy/cloud/aws/variables.tf" "$ROOT/deploy/cloud/aws/instances.tf" \
         "$ROOT/deploy/cloud/proxmox/variables.tf" \
         "$ROOT/deploy/cloud/proxmox/terraform.tfvars.example"; do
    [ -r "$f" ] || continue
    chk "${f#"$ROOT"/} does not call the key list host failover" "" \
        "$(grep -lE "survives losing the node holding|falls over between them" "$f" 2>/dev/null | xargs -r basename)"
done

echo "=== §6: the replication claims rest on a probe that still exists ==="
# The document calls the transfer [measured]. It is measured by ONE program; if that program
# is gone or renamed, the measurement is a claim again.
PROBE="$ROOT/tests/wrapprobe.c"
chk "tests/wrapprobe.c exists" yes "$([ -r "$PROBE" ] && echo yes || echo no)"
chk "the document names it" yes \
    "$(grep -q "wrapprobe.c" "$DOC" && echo yes || echo no)"
if [ -r "$PROBE" ]; then
    for m in CKM_AES_KEY_WRAP_PAD CKM_ECDH1_DERIVE; do
        chk "  the probe exercises $m" yes \
            "$(grep -q "$m" "$PROBE" && echo yes || echo no)"
    done
fi
# The mechanism is envelope encryption over the token API. softhsm2-util --import needs the
# private key as a plaintext file, which the token invariant forbids and no HSM offers.
chk "the document states envelope encryption" yes \
    "$(grep -qi "envelope encryption" "$DOC" && echo yes || echo no)"

echo "=== §8: the node-local table list matches src/tools/mesh.cpp ==="
# mesh.cpp is the authority for what deliberately does not replicate; this asserts the
# document did not drift from it.
MESH="$ROOT/src/tools/mesh.cpp"
for t in nonces accounts orders authorizations challenges \
         scep_challenges scep_pending cert_req_ids \
         audit_log audit_checkpoints audit_forward_state \
         discovered_certs schema_version config \
         web_sessions directory_groups directory_group_members; do
    in_code=$(awk '/kNodeLocalTables/{f=1;n=0} f&&n<32{print;n++}' "$MESH" | grep -qw "$t" && echo yes || echo no)
    in_doc=$(grep -q "\`$t\`" "$DOC" && echo yes || echo no)
    chk "  $t: node-local in mesh.cpp and named in the doc" "$in_code" "$in_doc"
done

echo "=== §5: no node signs through another node's token ==="
# The arrangement that was removed: a node whose /run/p11/pkcs11.sock was a tunnel to
# somebody else's token. It stops every node signing when that host is lost, and certificates
# issued under its key can never afterwards be renewed or revoked. The deploy paths are
# asserted by tests/hsm_tls_transport.sh; this pins the statement itself.
chk "the document says it" yes \
    "$(grep -qi "reaches another node.s token" "$DOC" && echo yes || echo no)"
HA="$ROOT/docs/high-availability.md"
if [ -r "$HA" ]; then
    chk "docs/high-availability.md agrees that reachability is not failover" yes \
        "$(grep -qi "reachability is not failover" "$HA" && echo yes || echo no)"
    chk "  and points at the design record" yes \
        "$(grep -q "](architecture.md)" "$HA" && echo yes || echo no)"
fi

echo "=== §9: CMP implicit confirmation, which the addressing table rests on ==="
chk "the server grants implicit confirm" yes \
    "$(grep -rq "OSSL_CMP_SRV_CTX_set_grant_implicit_confirm" "$ROOT/src/cmp/" && echo yes || echo no)"
chk "the console writes implicit_confirm into the client config" yes \
    "$(grep -q "implicit_confirm" "$ROOT/src/web/main.cpp" && echo yes || echo no)"

echo "=== no stale absolute in the document ==="
# Both claims broke decisions. Measured: softhsm2-util --import loads an RSA and an EC
# private key into a token, and tests/wrapprobe.c wraps a private key out of one and signs
# with it in another. Neither absolute may reappear.
for f in "$DOC" "$ROOT/docs/deployment.md"; do
    [ -r "$f" ] || continue
    chk "$(basename "$f") does not assert tokens refuse key import" "" \
        "$(grep -l "tokens refuse key import" "$f" 2>/dev/null | xargs -r basename)"
    chk "$(basename "$f") does not deny a wrap/unwrap step exists" "" \
        "$(grep -lE "no wrap/unwrap" "$f" 2>/dev/null | xargs -r basename)"
done

echo "=== §1: the ports it lists match include/pki/config.hpp ==="
CFG="$ROOT/include/pki/config.hpp"
for p in "ocsp_port{8080}" "est_port{8443}" "acme_port{8444}" "cmp_port{8445}" \
         "ms_port{8446}" "store_port{8447}" "scep_port{8448}" "web_port{8090}"; do
    num="${p##*\{}"; num="${num%\}}"
    chk "  ${p%%_port*} on $num" yes \
        "$(grep -q "$p" "$CFG" && grep -q "$num" "$DOC" && echo yes || echo no)"
done

echo "=== §3: PG_CONNINFO is still the only bootstrap-only key ==="
chk "is_bootstrap_config_key names exactly PG_CONNINFO" yes \
    "$(awk '/is_bootstrap_config_key/,/^}/' "$ROOT/src/lib/config.cpp" \
       | grep -q 'key == "PG_CONNINFO"' && echo yes || echo no)"
chk "  and nothing else" 1 \
    "$(awk '/is_bootstrap_config_key/,/^}/' "$ROOT/src/lib/config.cpp" | grep -c 'key == "')"

echo "=== §2: the identity and gate claims point at real symbols ==="
chk "qualify_subject exists" yes \
    "$(grep -q "qualify_subject" "$ROOT/include/pki/auth.hpp" && echo yes || echo no)"
chk "may_enrol exists" yes \
    "$(grep -q "may_enrol" "$ROOT/include/pki/enrol_gate.hpp" && echo yes || echo no)"
chk "subject_roles is shared with profile resolution" yes \
    "$(grep -q "subject_roles" "$ROOT/src/lib/cert_profile.cpp" && echo yes || echo no)"
chk "gate_protocol exists" yes \
    "$(grep -q "gate_protocol" "$ROOT/include/pki/endpoint_gate.hpp" && echo yes || echo no)"

echo "=== §10: serial layout and schema baseline ==="
chk "the serial really is prefix<<48 | nextval" yes \
    "$(grep -q "<< 48) | nextval" "$ROOT/src/lib/db_postgres.cpp" && echo yes || echo no)"
DOCVER=$(grep -oE 'baseline is [0-9]+' "$DOC" | grep -oE '[0-9]+' | head -1)
CODEVER=$(grep -oE 'kSchemaVersion = [0-9]+' "$ROOT/include/pki/schema.hpp" | grep -oE '[0-9]+' | head -1)
chk "the baseline the doc states matches kSchemaVersion" "$CODEVER" "$DOCVER"

echo "=== §10: the audit chain claim ==="
chk "audit rows are linked by prev_hash" yes \
    "$(grep -q "prev_hash" "$ROOT/src/lib/audit.cpp" && echo yes || echo no)"
echo
echo "=== ARCHITECTURE CURRENT: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
