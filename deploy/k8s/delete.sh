#!/bin/sh
# delete.sh — tear down the FastPKI k8s deployment.
# Removes all resources created by apply.sh in the target namespace.
#
#   deploy/k8s/delete.sh                     # the servers and Services; data and the Secret stay
#   DELETE_PVCS=true deploy/k8s/delete.sh    # and every server's claims, and the Secret with them
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Load env ───────────────────────────────────────────────────────────────
[ -f "$SCRIPT_DIR/env.local" ] && . "$SCRIPT_DIR/env.local"
. "$SCRIPT_DIR/env.sh"
[ -f "$SCRIPT_DIR/env.local" ] && . "$SCRIPT_DIR/env.local"

NAMESPACE="${NAMESPACE:-fastpki}"

echo "==> Deleting all FastPKI resources in namespace '$NAMESPACE'"
echo "    (this will NOT delete the namespace itself or PVCs unless DELETE_PVCS=true)"

# The servers. Every token, database and listener of the deployment lives in these pods.
kubectl delete statefulset fastpki-node -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
kubectl delete service fastpki-node -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true

# The Services that spread across them.
for proto in web ocsp est acme cmp ms store scep; do
    kubectl delete service "fastpki-${proto}" -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
done

# The per-server interconnect Services, created only on a mesh. Deleted by label: their names
# carry the pod ordinal, and a LoadBalancer left behind keeps billing a cloud address for a
# deployment that is gone.
kubectl delete service -n "$NAMESPACE" -l app.kubernetes.io/component=postgres-interconnect \
    --ignore-not-found 2>/dev/null || true
kubectl delete service -n "$NAMESPACE" -l app.kubernetes.io/component=p11-tls \
    --ignore-not-found 2>/dev/null || true

# The schema-trigger pod apply.sh runs, if a run was interrupted while it existed.
kubectl delete pod fastpki-mesh-triggers -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true

kubectl delete ingress fastpki-web -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true

# ConfigMaps. The Secret is NOT deleted here — see below. fastpki-pg-anchors is: apply.sh rebuilds it
# from what the servers hold, and a stale anchor for a database that no longer exists is worse
# than none.
kubectl delete configmap fastpki-bootstrap fastpki-pg-anchors -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true

# ⚠️ DELETING THE SECRET WHILE THE TOKENS SURVIVE BRICKS THE DEPLOYMENT. fastpki-secret holds the PIN
# every server's SoftHSM token was INITIALISED with, and SoftHSM keeps that PIN for ever. The
# token claims are not deleted by default, so removing the Secret would leave tokens holding
# every CA private key and destroy the only copy of the value that opens them. A re-apply then
# generates a fresh PIN that opens nothing — "The specified PIN is invalid" from every issuing
# service. So the Secret goes only when the tokens it opens go with it.

echo "==> PVCs (NOT deleted by default — data persists)"
echo "    Every server has three: pgdata-fastpki-node-N, pki-fastpki-node-N and softhsm-tokens-fastpki-node-N."
echo "    To delete them all:"
echo "      kubectl -n $NAMESPACE delete pvc -l app.kubernetes.io/instance=fastpki"
if [ "${DELETE_PVCS:-}" = "true" ]; then
    echo "    DELETE_PVCS is set — deleting every server's claims and the Secret that opens the tokens"
    # ⚠️ WAIT FOR THE PODS TO ACTUALLY GO FIRST. The deletes above return as soon as the API
    # accepts them, and a claim whose consumer is still running sits in Terminating for ever.
    printf "    waiting for pods to terminate"
    _n=0
    while [ "$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/component=node --no-headers 2>/dev/null | wc -l)" -gt 0 ] \
          && [ "$_n" -lt 60 ]; do
        printf "."; sleep 2; _n=$((_n + 1))
    done
    echo
    if [ "$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/component=node --no-headers 2>/dev/null | wc -l)" -gt 0 ]; then
        echo "    WARNING: pods still present after 2 minutes — the PVC deletes below will" >&2
        echo "    hang in Terminating until they go. kubectl get pods -n $NAMESPACE" >&2
    fi
    # ⚠️ BY NAME PATTERN AS WELL AS LABEL. A volumeClaimTemplate's claims carry the StatefulSet's
    # selector labels, but a claim created by an older manifest does not, and leaving a token
    # claim behind leaves CA keys behind.
    kubectl delete pvc -n "$NAMESPACE" -l app.kubernetes.io/instance=fastpki --ignore-not-found 2>/dev/null || true
    for _pvc in $(kubectl get pvc -n "$NAMESPACE" -o name 2>/dev/null \
                  | grep -E 'persistentvolumeclaim/(pgdata|pki|softhsm-tokens)-fastpki-node-[0-9]+$' || true); do
        kubectl delete -n "$NAMESPACE" "$_pvc" --ignore-not-found 2>/dev/null || true
    done
    # Only now: the PIN is worthless once the tokens it opens are gone.
    kubectl delete secret fastpki-secret -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
else
    echo "    fastpki-secret is KEPT: it holds the PIN that opens the surviving tokens, and"
    echo "    SoftHSM cannot be given a different one. Deleting it would strand every CA key."
fi

echo ""
echo "FastPKI resources removed from namespace '$NAMESPACE'."
echo "Namespace itself was NOT deleted (kubectl delete namespace $NAMESPACE to remove it)."
