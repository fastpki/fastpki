#!/bin/sh
# env.sh — FastPKI k8s deployment variables.
# Source this before running apply.sh, or export these yourself.
# Copy to env.local and edit for your cluster (env.local is gitignored).

# ── Image ──────────────────────────────────────────────────────────────────
# Installed from a release, install.sh exports FASTPKI_RELEASE_IMAGE naming that release's
# published image, and the cluster pulls it. From a checkout there is no published tag, so
# the default is the local name and the image has to be built and made reachable first.
# IMAGE set in the environment or in env.local wins over both.
export IMAGE="${IMAGE:-${FASTPKI_RELEASE_IMAGE:-fastpki:latest}}"
export IMAGE_PULL_POLICY="${IMAGE_PULL_POLICY:-IfNotPresent}"

# ── Namespace ──────────────────────────────────────────────────────────────
export NAMESPACE="${NAMESPACE:-fastpki}"

# ── PKI ────────────────────────────────────────────────────────────────────
export PKI_DNS="${PKI_DNS:-pki.example.org}"

# The console admin is seeded admin/admin by bootstrap.sh (must be changed at first
# login) and is not configurable
# here — change the password at first login.

# ── Postgres ───────────────────────────────────────────────────────────────
export PG_IMAGE="${PG_IMAGE:-postgres:17-alpine}"
export PG_USER="${PG_USER:-fastpki}"
export PG_DB="${PG_DB:-fastpki}"
# ⚠️ NO DEFAULT. `fastpki` was a published literal protecting the database that holds every
# certificate, every user and every role — the same class as a well-known token PIN. apply.sh
# reuses the password already in the Secret, or generates one; it is never guessed.
export PG_PASSWORD="${PG_PASSWORD:-}"
# A fresh database is 47.9 MB, and what grows it is issuance — bounded by PostgreSQL's 1 GB
# max_wal_size default. So 1Gi is ~20x the measured size and matches every other path: the
# cloud module's data_volume_gb is 1 and nothing else declares a size at all. Raise it for a
# deployment that keeps years of issuance, not on principle.
export PG_DATA_SIZE="${PG_DATA_SIZE:-1Gi}"

# ── Storage ────────────────────────────────────────────────────────────────
# Every claim belongs to ONE server — its database, its /var/pki and its token — so one class
# serves them all, and the node-local default (local-path on k3s) is the right one. Losing a node
# loses that server's copy and nothing else: the other server has its own token with the keys
# replicated into it, and its own database streaming the same history. Nothing is shared between
# pods, so no claim needs ReadWriteMany and nothing needs NFS.
export STORAGE_CLASS="${STORAGE_CLASS:-}"
export PKI_DATA_SIZE="${PKI_DATA_SIZE:-1Gi}"

# ── CMP ────────────────────────────────────────────────────────────────────

# ── Web ────────────────────────────────────────────────────────────────────
export WEB_SERVICE_TYPE="${WEB_SERVICE_TYPE:-ClusterIP}"  # ClusterIP | NodePort | LoadBalancer
# ⚠️ THE ENROLMENT PROTOCOLS HAVE TO BE REACHABLE BY CLIENTS, and clients are not in the
# cluster. EST, ACME, CMP, SCEP, OCSP and the RFC 4387 store are what a CA is FOR; left on
# ClusterIP they are reachable only from inside, which makes the deployment a console and a
# database. ClusterIP stays the default so nothing is published by surprise.
#
# ⚠️ NOT A TLS-TERMINATING INGRESS, for most of them. EST and CMP authenticate the CLIENT
# with its certificate, so an ingress that terminates TLS destroys the very thing being
# verified. NodePort and LoadBalancer pass the connection through intact, and so does an
# ingress controller in TLS PASSTHROUGH (nginx ssl-passthrough, Traefik tls.passthrough):
# that forwards the TCP stream unopened and mTLS survives. Terminating is the problem, not
# ingress. See docs/deployment.md 8.5.
export PROTO_SERVICE_TYPE="${PROTO_SERVICE_TYPE:-ClusterIP}"  # ClusterIP | NodePort | LoadBalancer
export WEB_PORT="${WEB_PORT:-8090}"

# ── Protocols ──────────────────────────────────────────────────────────────
# Which enrolment protocols this deployment runs, as the compose path's install wizard asks.
# A protocol set to false has no container in the server pods and no Service, and the console
# records it as not installed. The web console and OCSP always run. true | false
export EST_INSTALLED="${EST_INSTALLED:-true}"
export ACME_INSTALLED="${ACME_INSTALLED:-true}"
export CMP_INSTALLED="${CMP_INSTALLED:-true}"
export SCEP_INSTALLED="${SCEP_INSTALLED:-true}"
export MS_INSTALLED="${MS_INSTALLED:-true}"
export STORE_INSTALLED="${STORE_INSTALLED:-true}"

# ── Ingress (optional) ─────────────────────────────────────────────────────
export INGRESS_ENABLED="${INGRESS_ENABLED:-false}"
export INGRESS_CLASS="${INGRESS_CLASS:-}"
export INGRESS_HOST="${INGRESS_HOST:-}"
export INGRESS_TLS="${INGRESS_TLS:-true}"

# ── SoftHSM (optional) ─────────────────────────────────────────────────────
# ⚠️ DEFAULTS TO TRUE, because without a token backend nothing that serves HTTPS can start.
# It was false, and no manifest implemented it either way — so every deployment ran with no
# token at all and web/est/acme/ms bound their ports and then stopped on the PKCS#11
# liveness guard, while the four plain-HTTP services stayed up. A half-running deployment
# is a worse default than an opinionated one.
#
# Set false ONLY with PKCS11_MODULE pointing at a real HSM's module: every server's token
# sidecar and token claim are then left out, and each process loads the vendor module and talks
# to the appliance over the network.
export SOFTHSM_ENABLED="${SOFTHSM_ENABLED:-true}"

# The PKCS#11 module every FastPKI container loads. compose has had this knob since the
# beginning (`PKCS11_MODULE: ${PKCS11_MODULE:-/usr/lib/pkcs11/p11-kit-client.so}`); k8s
# defined it NOWHERE, so a Kubernetes deployment had no way to use a real HSM at all. The
# default is the p11-kit client shim, which forwards to the socket of the server's own token.
export PKCS11_MODULE="${PKCS11_MODULE:-/usr/lib/pkcs11/p11-kit-client.so}"
# Where that shim looks for the server, and where the PIN is read from. Both match compose.
export P11_KIT_SERVER_ADDRESS="${P11_KIT_SERVER_ADDRESS:-unix:path=/run/p11/pkcs11.sock}"
export PKCS11_PIN_FILE="${PKCS11_PIN_FILE:-/var/pki/tls/pin}"
# ⚠️ AND THE TOKEN LABEL, which must be exported even though bootstrap.conf already sets it.
# apply.sh runs envsubst with no variable list, so every $NAME in a manifest is substituted
# and one this file does not export becomes the EMPTY STRING — not left alone. Three
# manifests pass $PKCS11_TOKEN into a container, and while the shell consumers write
# ${PKCS11_TOKEN:-fastpki} and so survive an empty value, the binaries do not:
# Config::from_env() applies any variable getenv returns non-NULL for, and a variable set to
# "" is set. It therefore overwrites both the ConfigMap's PKCS11_TOKEN and the compiled-in
# default with "", and the console then lists objects in a token named "".
export PKCS11_TOKEN="${PKCS11_TOKEN:-fastpki}"
# ⚠️ NO DEFAULT. An SO PIN's purpose is to RESET the user PIN, so a published value hands
# the token — and every CA private key in it — to anyone who can reach it, however strong
# FASTPKI_PIN is. Empty here means token.sh falls back to FASTPKI_PIN, which is generated.
export SOFTHSM_SO_PIN="${SOFTHSM_SO_PIN:-}"
# (SOFTHSM_PIN is deliberately absent: the token PIN is FASTPKI_PIN, generated per
# deployment by apply.sh and carried in the Secret. A second, defaulted PIN variable that
# nothing read was worse than none — it looked like the knob and was not.)
export SOFTHSM_TOKEN_SIZE="${SOFTHSM_TOKEN_SIZE:-1Gi}"

# ── single-DC HA ─────────────────────────────────────────────────────────────────────
# Two servers on two nodes instead of one: the Compose pair. Each has its own token, its own
# /var/pki and its own database; the second server's database streams from the first's and its
# renewal loop replicates every CA and service key into its own token, so losing either node
# leaves a server that can promote its database and keep issuing. Off by default: it doubles the
# footprint, and a single-node cluster cannot place the second server anywhere.
#
# ⚠️ It turns P11_TLS on, because key replication runs over it, and refuses P11_TLS=off beside
# it. It needs two schedulable nodes: the servers are required to be on different ones.
export HA_ENABLED="${HA_ENABLED:-false}"

# ── audit forwarding ─────────────────────────────────────────────────────────────────
# `fastpki-audit forward --follow` ships each audit entry to the configured sink. compose
# gates the same service behind `profiles: [auditfwd]`. Off by default, like compose: with
# no sink configured the follower has nowhere to send and would only restart.
export AUDITFWD_ENABLED="${AUDITFWD_ENABLED:-false}"

# ── multi-data-center mesh ────────────────────────────────────────────────────────────
# One FastPKI datacenter is one Kubernetes cluster. These knobs are what compose gets from
# DEPLOYMENT=cluster / DC_INDEX / PG_BIND, and k8s had none of them: it could not run a
# mesh at all, because nothing set DATACENTER_ID, nothing registered the node's row in
# `datacenters`, and Postgres was reachable only inside its own cluster.
#
# ⚠️ DC_INDEX IS THE SERIAL PREFIX, and it must be unique and stable across the mesh. Every
# certificate this data center mints carries it, which is what lets three data centers issue
# concurrently without ever minting the same serial. It is also the `dc_id` in the topology
# file — spelled exactly the same, digits only. `dc1` never matches `1`.
export DC_INDEX="${DC_INDEX:-1}"

# The addresses the OTHER clusters dial to reach THIS cluster's servers' databases — one per
# server, comma-separated, in pod order (fastpki-node-0 first). They go into the topology file's
# `host=` and into PG_TLS_SANS, so the peers' sslmode=verify-full has a name to match — a
# database certificate that does not carry the address is refused by every peer, which is the
# single most common way a mesh fails to come up. With HA_ENABLED there are two, because after a
# promotion the primary is the other server and the peers must reach it too.
#
# Empty on a single-data-center deployment, and REQUIRED on every cluster that has peers —
# data center 1 included, since its peers dial it too. apply.sh refuses a non-default
# DC_INDEX without it, and a count that does not match the servers, rather than deploying a
# cluster that cannot be meshed.
export PG_INTERCONNECT="${PG_INTERCONNECT:-}"

# How each server's Postgres is exposed to its peers — one Service per server. The in-cluster
# `fastpki-node` Service is headless and unreachable from outside, which is right for everything
# except the mesh.
#   LoadBalancer  — a cloud LB address per server; set PG_INTERCONNECT to the addresses handed out
#   NodePort      — PG_NODEPORT for fastpki-node-0, PG_NODEPORT+1 for fastpki-node-1, on every node
#   none          — you route to it yourself (an existing VPN, a service mesh, a manual
#                   Service); apply.sh then creates nothing and trusts PG_INTERCONNECT
# ⚠️ This port carries web_users password hashes and every peer's replication password, so
# it must not face the public internet. Peer it privately.
#
# ⚠️ AND THAT IS WHY THE DEFAULT IS `none`. DC_INDEX defaults to 1, so apply.sh's guard is
# satisfied on every deployment including a single cluster that has no peer to serve — a
# default of LoadBalancer therefore asked a cloud provider for a public address for the
# database on an ordinary `apply.sh`, which is the exposure the paragraph above forbids.
# Publishing the port is a mesh decision, so the mesh operator makes it: set this to
# LoadBalancer or NodePort together with PG_INTERCONNECT, having decided how it is reached.
export PG_EXTERNAL_TYPE="${PG_EXTERNAL_TYPE:-none}"
export PG_NODEPORT="${PG_NODEPORT:-31432}"

# Active Directory's DNS. A directory is reached by NAME, and the cluster resolver does not
# know the AD zone — LDAP login, user/group import, MS template import and Kerberos all fail
# with "Can't contact LDAP server" until these are set. Several entries are FAILOVER between
# replicas of one resolver, not a union of zones — an authoritative NXDOMAIN from the first
# ends the query, so two forests need one resolver doing conditional forwarding, not two
# nameservers here.
# Appended to cluster DNS (dnsPolicy stays ClusterFirst), so Service names are unaffected.
export DIRECTORY_DNS="${DIRECTORY_DNS:-}"
export DIRECTORY_DNS_SEARCH="${DIRECTORY_DNS_SEARCH:-}"

# Each server's token over mTLS (deploy/docker-compose.yml's `p11-tls` service), which is what a
# CA key is REPLICATED over into another server's own token. Empty means "on with HA_ENABLED, off
# without it" — apply.sh decides, and refuses off beside HA_ENABLED. It is also what makes certgen
# mint the pinned keypair each end needs. The servers of this cluster reach each other through
# the headless Service whatever this says; ClusterIP publishes nothing more, and LoadBalancer or
# NodePort publishes each server's token to a PEER data center, the same choice PG_EXTERNAL_TYPE
# makes for the Postgres interconnect.
export P11_TLS="${P11_TLS:-}"
export P11_TLS_SERVICE_TYPE="${P11_TLS_SERVICE_TYPE:-ClusterIP}"
#
# ⚠️ A KUBERNETES DEPLOYMENT COULD NOT CHOOSE ITS SERVICE KEYS AT ALL. install.sh asks for
# these per service and writes them; apply.sh knew none of them, so every k8s deployment
# silently took the compiled defaults and an operator who wanted, say, an RSA console key or
# a P-521 OCSP responder had no way to say so.
#
# Empty means "the compiled default", so a deployment that sets nothing is unchanged — and
# only non-empty values are written, which keeps bootstrap.conf free of blank keys that
# Config::load() would apply as deliberate empties.
#
# ⚠️ SCEP TAKES A SIZE AND NOT AN ALGORITHM. RFC 8894 fixes its envelope on RSA key
# transport, so SCEP_RA_KEY_ALGO deliberately does not exist — an unsettable field cannot be
# set wrong. Only the modulus size is an answer.
export WEB_KEY_ALGO="${WEB_KEY_ALGO:-}"
export WEB_KEY_BITS="${WEB_KEY_BITS:-}"
export WEB_KEY_CURVE="${WEB_KEY_CURVE:-}"
export WEB_KEY_MD="${WEB_KEY_MD:-}"
export EST_KEY_ALGO="${EST_KEY_ALGO:-}"
export EST_KEY_BITS="${EST_KEY_BITS:-}"
export EST_KEY_CURVE="${EST_KEY_CURVE:-}"
export EST_KEY_MD="${EST_KEY_MD:-}"
export ACME_KEY_ALGO="${ACME_KEY_ALGO:-}"
export ACME_KEY_BITS="${ACME_KEY_BITS:-}"
export ACME_KEY_CURVE="${ACME_KEY_CURVE:-}"
export ACME_KEY_MD="${ACME_KEY_MD:-}"
export MS_KEY_ALGO="${MS_KEY_ALGO:-}"
export MS_KEY_BITS="${MS_KEY_BITS:-}"
export MS_KEY_CURVE="${MS_KEY_CURVE:-}"
export MS_KEY_MD="${MS_KEY_MD:-}"
export OCSP_RESPONDER_KEY_ALGO="${OCSP_RESPONDER_KEY_ALGO:-}"
export OCSP_RESPONDER_KEY_BITS="${OCSP_RESPONDER_KEY_BITS:-}"
export OCSP_RESPONDER_KEY_CURVE="${OCSP_RESPONDER_KEY_CURVE:-}"
export CMP_RA_KEY_ALGO="${CMP_RA_KEY_ALGO:-}"
export CMP_RA_KEY_BITS="${CMP_RA_KEY_BITS:-}"
export CMP_RA_KEY_CURVE="${CMP_RA_KEY_CURVE:-}"
export SCEP_RA_KEY_BITS="${SCEP_RA_KEY_BITS:-}"
