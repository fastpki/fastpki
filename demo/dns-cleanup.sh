#!/bin/sh
# certbot manual-cleanup-hook, and the demo's own tidy-up after a shell-client order.
# Removes the CoreDNS container dns-auth.sh started — wherever it started it.
set -u
# The cluster form: remove the CoreDNS the dns-01 cells stood up beside the deployment.
# Same contract as the SSH branch — best-effort, never fails the run.
if [ -n "${DNS_K8S_NAMESPACE:-}" ]; then
    kubectl -n "$DNS_K8S_NAMESPACE" delete deploy/fastpki-dns svc/fastpki-dns \
        configmap/fastpki-dns --ignore-not-found >/dev/null 2>&1 || true
    exit 0
fi
if [ -n "${DNS_SSH_TARGET:-}" ]; then
    ssh ${DNS_SSH_OPTS:-} "$DNS_SSH_TARGET" \
        'docker rm -f fastpki-dns >/dev/null 2>&1; rm -rf /tmp/fastpki-demo-dns' >/dev/null 2>&1 || true
else
    docker stop fastpki-dns 2>/dev/null || true
fi
exit 0
