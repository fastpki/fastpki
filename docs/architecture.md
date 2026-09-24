<!-- fastpki:not-published — this file stays in the repository and is not put on the website.
     It is the design record: written for whoever is changing the code, with every claim
     tagged by how it is known, and it is not what somebody deciding whether to deploy
     FastPKI, or how to run it, is looking for. docs/publish.sh reads this marker, so the
     exclusion travels with the file and survives a rename; links to it from a published
     guide become links to the file on GitHub. -->

# FastPKI architecture

## Contents

- [Scope and precedence](#scope-and-precedence)
- [1. Components](#1-components)
- [2. Identity and authorisation](#2-identity-and-authorisation)
- [3. Configuration](#3-configuration)
- [4. Tokens and private keys](#4-tokens-and-private-keys)
- [5. The token channel (P11_TLS)](#5-the-token-channel-p11_tls)
- [6. Signing keys: generations and replication](#6-signing-keys-generations-and-replication)
- [7. CA topologies](#7-ca-topologies)
- [8. Replicated and node-local state](#8-replicated-and-node-local-state)
- [9. Addressing](#9-addressing)
- [10. Serials, schema and audit](#10-serials-schema-and-audit)
- [11. Resource footprint](#11-resource-footprint)

## Scope and precedence

This document is the design record. Where a code comment, a guide or a commit message
disagrees with it, this document is correct and the other is stale — unless a measurement
shows otherwise, in which case correct this document first and the other afterwards.

Comments reference this document rather than restating it.

Each claim is tagged with how it is known:

| tag | meaning |
|---|---|
| **[invariant]** | A product decision. Changing it is a design change, not a fix. |
| **[measured]** | Verified by running it. The observation is stated. |
| **[code]** | Read from the source. The location is stated. |
| **[open]** | Not decided, or decided and not built. |

`tests/architecture_current.sh` asserts the mechanical claims below against the source.

---

## 1. Components

**[code] One binary per enrolment protocol, over one shared library.** Each binary uses
cpp-httplib for transport, OpenSSL for crypto and ASN.1, and `pki_lib` for configuration,
database, policy, authentication and issuance.

| binary | port | binary | port |
|---|---|---|---|
| `fastpki-ocsp` | 8080 | `fastpki-ms` (MS-XCEP/WSTEP) | 8446 |
| `fastpki-est` | 8443 | `fastpki-store` (RFC 4387) | 8447 |
| `fastpki-acme` | 8444 | `fastpki-scep` | 8448 |
| `fastpki-cmp` | 8445 | `fastpki-web` (console) | 8090 |

Ports are defaults from `include/pki/config.hpp`.

**[invariant] There are four deployment paths and they carry the same capabilities.**
`deploy/` (Docker Compose), `deploy/native/` (Alpine + OpenRC), `deploy/k8s/`, and
`deploy/cloud/` (the machine image plus the OpenTofu module — a cloud node is a native
install). Anything added to one — a config key, an installer answer, an exported variable, a
script, an operational step, a documented procedure — belongs in all of them in the same
change, or the omission is stated at the line with the reason it cannot apply. A capability
present on one path and absent from another is a defect, not an ordering: the operators of
the other paths are told to perform the step by the same guides, and what they meet is a
command that fails at its first call rather than a feature that is missing. `deploy/pg-promote.sh`
drove `docker compose` unconditionally while three places instructed native and cloud
operators to run it, so on those hosts every safeguard it exists for silently did not run.
`tests/deploy_parity.sh` enforces the mechanical half.

**[invariant] PostgreSQL is the only database, and certificates live in it — never in
files.** The one exception is the PostgreSQL server's own transport certificate and key,
written as files under `PG_TLS_DIR` because PostgreSQL reads both from disk and cannot load
a PKCS#11 key.

**[invariant] There is no default or bootstrap signing CA.** Every CA is a row in `certs`
holding its own certificate, `ca_id`, name, enabled flag and MS-WSTEP enrolment permission.

**[code] `resolve_ca_instance()` turns a `ca_id` from a protocol path into a `ResolvedCa`.**
`chain_ders` holds every live certificate for that CA — a renewed CA has several until the
older ones expire, and all of them belong in a served chain. `has_local_key` is false on a node that replicates a CA it cannot
sign for.

---

## 2. Identity and authorisation

**[invariant] A name from an external authority is provider-qualified.**
`qualify_subject()` joins as `provider\user`; `subject_provider()` and `subject_user()`
split it (`include/pki/auth.hpp`).

**[invariant] An unqualified name means local** — the `web_users` table. 

**[invariant] Resolution is by qualifier alone.** There is no priority order between
providers, no "first provider that answers", and no merging of identities across providers.

**[code] Authentication and authorisation are separate layers.** `authenticate()`
(`src/lib/auth.cpp`) dispatches across local PBKDF2 users, LDAP/AD, OIDC, SAML and mTLS.
Authorisation is data: `roles`, `role_permissions`, `subject_roles`.

**[code] Effective grants are the union** of the primary role and roles held through
`subject_roles`.

**[invariant] `may_enrol()` fails closed** (`include/pki/enrol_gate.hpp`). It answers whether
a subject may enrol over a given protocol against a given CA, and if the tables cannot be
read the answer is no. The one deliberate exception is a database holding no `roles` rows at
all, where the gate is inert and says so in the log rather than refusing traffic it cannot
judge.

**[code] Every gate resolves a subject's roles through one function.** `subject_roles()` is
exported so that `profiles_for_identity()` (`src/lib/cert_profile.cpp`) asks exactly the
question `may_enrol()` asks. A second reader reconstructing the rule would hand profiles to
subjects the permission gate does not recognise.

**[code] `gate_protocol()` runs in each binary immediately before it binds**
(`include/pki/endpoint_gate.hpp`). `<PROTO>_ENABLED=false` in the `config` table means the
port is never opened; setting it false at runtime exits the process, so the restart policy
returns it to the gate. A disabled protocol is absent, not firewalled.

---

## 3. Configuration

**[code] Resolution order:** `config/bootstrap.conf` or the environment → the `config` table
overlay (`overlay_config()`, `src/lib/config.cpp`) → the effective `pki::Config`.

**[invariant] The database wins for every key except `PG_CONNINFO`.**
`is_bootstrap_config_key()` returns true for that key alone. Every other setting is
changeable from the console or `fastpki-config`; editing the file on a running deployment
has no effect, because the overlay is applied over it.

**[invariant] No setting may disable a security control.** `tests/no_insecure_settings.sh`
asserts the parser does not recognise such keys, so a stale configuration containing one
fails as an unknown key rather than weakening the deployment silently.

**[code] An unknown key is ignored** — `apply()` is an if/else-if chain with no final
`else`. `tests/config_keys_live.sh` therefore asserts in both directions that every shipped
and documented key is one the parser reads.

---

## 4. Tokens and private keys

**[invariant] Every node has its own token**, in every deployment shape. If a node is lost,
key material that existed only in its token is lost with it.

**[invariant] Private keys are generated inside a token and never leave it in plaintext.**
The exception is the PostgreSQL server key, which PostgreSQL reads from a file itself.
`fastpki-ca` refuses a `--ca-key` that is not a `pkcs11:` handle.

**[invariant] No FastPKI process loads `libsofthsm2.so` in-process.** SoftHSM's OpenSSL
backend re-enters libcrypto while libcrypto holds a lock, and the process deadlocks. Every
consumer reaches the token through `p11-kit-client.so` to a `p11-kit-server` over a unix
socket named by `P11_KIT_SERVER_ADDRESS` (`unix:path=/run/p11/pkcs11.sock`).

**[measured] The deadlock is not algorithm-specific.** Pointing the OpenSSL pkcs11 provider
directly at `libsofthsm2.so` hangs or fails non-deterministically.

---

## 5. The token channel (P11_TLS)

**[code] P11_TLS is a mutually authenticated channel between two nodes' token layers.**
`p11-kit` speaks neither TLS nor TCP, so a token is otherwise local to its host. `P11_TLS=on`
places an stunnel pair around the socket; each end pins the other's certificate.

**[invariant] Its sole purpose is replicating a key (§6).** The destination token receives
its own copy, after which each node signs from its own token and depends on no peer to
issue, renew or revoke.

**[invariant] No node ever reaches another node's token to sign with it.**
`/run/p11/pkcs11.sock` is always this node's own token, in every deployment shape. A
deployment in which every node signed through one host's token would stop signing entirely
when that host was lost, and certificates issued under its key could never afterwards be
renewed or revoked.

**[invariant] The tunnel's own keypairs live in the node's own token.** `certgen.sh` generates
two per node — `p11-server` and `p11-client` — and stunnel loads each as a `pkcs11:` URI.
Only their certificates are on disk.

**[code] Both are renewed by the daily certificate job**, which runs `certgen.sh --p11-only`
and then republishes them. They are self-signed and pinned, so `renew-service-certs` — which
renews what a CA issued — does not cover them, and without this their only renewal would be
a redeploy. The keys are never regenerated; only the certificates are re-issued.

**[invariant] The two are separate identities, not one dual-purpose certificate.** Each end
verifies the other against a different trust set: the publishing side against
`p11/clients/`, the dialling side against `p11/servers/`, and `fastpki-config` publishes
each half into a different `datacenters` column. A single shared identity would mean any
node authorised to publish its token was thereby authorised to dial every other node's. 

---

## 6. Signing keys: generations and replication

**[invariant] A CA's several key URLs are its generations, not its replicas.** A CA has one
key per generation: a renewal with a new key adds a certificate and the key that goes with it,
and a renewal with the current key or a cross-signed certificate is another certificate over a
key already in the list. Every generation stays live until it expires, so the rows carry every
key.

**[code] The certificate in use selects the key.** `resolve_ca_instance()`
(`src/lib/ca_instance.cpp`) passes the CA certificate being signed under to
`load_signing_key()` as `expect`, which returns the first URL whose key matches it. It is the
only caller that passes `expect`. `fastpki-ca key add <ca-id> pkcs11:<uri>` appends a URL.

**[code] The list does not span hosts.** Every candidate is opened through
`load_signing_key_one()`, which uses the one `PKCS11_MODULE` the process has. The URLs select
a different *key* on that token, never a different token.

**[invariant] Surviving the loss of a host is a separate mechanism** — an appliance
presenting several tokens, or the key replicated into this node's own token (below). The key
list is not HA and must not be described as it.

**[invariant] Placement is envelope encryption over the token API.** The destination holds a
long-lived key-encryption keypair (KEK) in its own token and publishes only its public
point. The source generates an ephemeral EC keypair in its own token, ECDH-derives an
AES-256 key from it and that point, and wraps the CA private key under it. The destination
derives the same AES key from its KEK private half and the ephemeral public point, and
unwraps directly into its token. Plaintext key material never exists outside a token; what
crosses the wire is one wrapped blob and two public EC points.

**[invariant] The KEK private half is itself non-extractable.** It decrypts every key
replicated to that node, so it must never be replicable in turn.

**[code] `fastpki-ca key replicate <ca-id> --from <host:port>` performs it**, run on the
destination. It raises the mTLS tunnel for the length of the operation, wraps in the source
token, unwraps into its own, verifies the result against the CA's certificate, and only then
registers the handle in this node's `certs.private_key`. `--source-socket` uses a tunnel that
is already up. The engine is in `src/lib/pkcs11_helpers.cpp`; `tests/key_replication.sh`
proves a replicated key signs and that the CA certificate verifies that signature.

**[code] A replicated key is extractable at the destination too.** A copy that could not be
replicated onward would make the second node a single point of failure the moment the first
was lost.

**[invariant] `softhsm2-util --import` is not the mechanism.** It requires the private key as
a plaintext PKCS#8 file on disk, which violates §4, and it does not exist on a hardware HSM.

**[measured] The platform supports the transfer.** `tests/wrapprobe.c` proves the round trip
rather than the capability bit: generate, wrap, unwrap, sign with the unwrapped handle, and
verify that signature against the original public key. It passes in a container built from
the shipped image, by both the RSA-OAEP and the static-static ECDH (`CKM_ECDH1_DERIVE`) route.
Re-run it there after any SoftHSM or p11-kit change; its header states how.

**[invariant] The transfer key is derived by ECDH, not wrapped with RSA-OAEP.**
`CKM_ECDH1_DERIVE` with `CKD_NULL` takes no hash parameter, so the design does not depend on
which OAEP hash a given token accepts.

**[invariant] `CKA_EXTRACTABLE` is set at key generation and cannot be granted later.** A key
generated non-extractable can never be replicated, and no later flag changes that. Whether a
key may be replicated is therefore decided wherever it is generated: `fastpki-ca create`, `csr`
and `renew-service-certs --create-missing` take `--replicable`, and the four console forms that
generate a key (New CA, CA CSR, CA renew, Inventory HSM request) take `replicable`. A renewal
with a new key generates that key and does not inherit the choice from the one it replaces.

**[code] One function generates every replicable key.** `generate_key_in_token(…, replicable)`
generates it through PKCS#11 directly (`pkcs11_generate_replicable_keypair`), because the OpenSSL
pkcs11 provider it otherwise drives exposes no parameter for that attribute, and loads the
key back by URI. `CKA_SENSITIVE` stays set beside it: the key may leave the token, but only
ever wrapped.

**[code] Every CA key algorithm can be replicated:** RSA, RSA-PSS, EC P-256/P-384/P-521,
Ed25519, Ed448 and ML-DSA-44/65/87. `pkcs11_replicable_refusal()` refuses anything else, and
the console asks it before a handle is checked or overwritten, so a refused request costs no
existing key.

**[measured] The shipped token wraps, unwraps and signs with every one of them.**
`tests/wrapprobe.c`, run in a container built from the shipped image, both with SoftHSM
loaded directly and through `p11-kit server`, generates each key type extractable, wraps it
under an AES key, unwraps it, signs with the copy and verifies with the original public key.
A host run is not this measurement: a stock SoftHSM and an unpatched p11-kit hold none of
Ed25519, ML-DSA or a PSS-restricted key.

**[invariant] An RSA-PSS key's mechanism restriction travels with it.** RSA-PSS is `CKK_RSA`
plus `CKA_ALLOWED_MECHANISMS`, which the wrapped PKCS#8 blob does not carry. The source reads
the list and the destination's unwrap template sets it; a copy without it would load as plain
RSA and sign PKCS#1 v1.5 under an `rsassaPss` certificate.

**[code] A CA created without it refuses replication with a message naming the cause.** The
token returns `CKR_KEY_UNEXTRACTABLE`, and the operator's next step is to create the CA
differently, not to retry.

---

## 7. CA topologies

**Scenario A — one global root, one sub CA per data center.** Each data center signs with
its own sub CA under a shared root, is separately addressable, and depends on no other data
center in order to issue. `deployment.md` §9 covers it operationally.

**Scenario B — one global root, one global sub CA present in every data center.** Every data
center issues from the same CA. Requires §6 to be implemented, and under a single shared name
additionally requires §9 to be resolved.

**[invariant] Key replication is an option within a topology, not a topology of its own.**
Under scenario A, replicating a sub CA key means losing that data center does not take its
sub CA's signing with it.

---

## 8. Replicated and node-local state

**[code] Every table is either replicated or deliberately node-local**, and both lists are in
`src/tools/mesh.cpp`. `tests/mesh_publication_complete.sh` asserts that the two lists
partition `sql/createdb.sql` exactly, so a new table fails the build until it is classified.

Node-local, with the reason each is:

| tables | why |
|---|---|
| `nonces`, `accounts`, `orders`, `authorizations`, `challenges`, `acme_device_tickets` | ACME session state — see below. A device ticket is used by the node that issued it, because its Apple profile names that node's ACME directory |
| `scep_challenges`, `scep_pending`, `cert_req_ids` | per-node protocol session state |
| `audit_log`, `audit_checkpoints`, `audit_forward_state` | a per-node hash chain (§10); a cursor into one's own log cannot describe a peer's |
| `discovered_certs` | bigserial primary key, not partition-safe |
| `schema_version` | applying a step on one node must not claim the others were upgraded |
| `config` | `DATACENTER_ID`, bind addresses and TLS paths are each node's identity |
| `web_sessions` | a session was authenticated against one data center and does not follow the user to another |
| `directory_groups`, `directory_group_members` | each node refreshes from the directory it can reach; a stale peer must not decide membership for it |
| `notify_sent` | only the data center whose serial prefix a certificate carries emails its owner, so each row has one writer and no peer acts on it |

**[code] Each host describes itself in `node_status`, and that table replicates.** A console
behind a load balancer is served by an arbitrary host and can read only its own token, so every
host's console writes one row about its own host (keys held, database connection and
certificate, replication its server sees, last key sync) and the Replication page reads all of
them (`src/lib/node_status.cpp`). Each row has one writer, the host it describes; a console's
"Sync keys now" request is a row in `node_sync_requests` instead, which the named host claims
and runs. Both are last-writer-wins in a mesh.

**[invariant] `nonces` must never replicate.** A nonce is single-use, and asynchronous
replication of the consuming `DELETE` leaves a replay window equal to the replication lag.

**[open] The remaining ACME tables are excluded without cause.** `accounts`, `orders`,
`authorizations` and `challenges` carry no node-specific column, use random identifiers and
absolute URLs. See §9.

---

## 9. Addressing

**[invariant] `PKI_DNS` is the only name for the deployment hostname**, in Docker Compose,
Kubernetes, native/OpenRC and the cloud modules alike. It holds the public FQDN of the
deployment: `derive_ca_urls()` (`src/lib/x509.cpp`) takes every issued certificate's CRLDP
and AIA host from `BASE_URL`, or from `PKI_DNS` when `BASE_URL` is unset — and `apply()`
(`src/lib/config.cpp`) sets `BASE_URL` to `https://<PKI_DNS>` whenever `BASE_URL` is empty or
still holds the shipped example value. So `PKI_DNS` must resolve wherever relying parties
run: a short or node-local hostname resolves only on the node itself, and the CRL and issuer
certificate are then unfetchable off it.

Two shapes are supported: one name per node, or one name round-robined across every node.
The cloud modules take `pki_dns` as either, so the choice is configuration rather than code
(`deployment.md` §9.7).

**[measured] Protocol behaviour under one round-robin name**, on a three-node mesh:

| protocol | result | cause |
|---|---|---|
| EST `simpleenroll` | 10/10 | single request |
| OCSP, CRL, RFC 4387 store | 10/10 | read replicated data |
| CMP with `-implicit_confirm` | 10/10 | single request |
| CMP without it | 5/10 | `certConf` is a second request, reaching a node that did not serve the first |
| ACME | fails | nonce issued by one node is `badNonce` at another |

**[invariant] That table is about a MESH, and does not carry over to an HA pair.** Every failure
in it is caused by the nodes having SEPARATE databases: a nonce row, an ACME order row or a
CMP `certConf` row written at one node is not yet at the next. The two hosts of an HA pair share
ONE database — both dial the same multi-host `PG_CONNINFO` with
`target_session_attrs=read-write`, so whichever Postgres is currently primary serves both — and
every one of those objects is a row in it (`nonces`, `accounts`, `orders`, `authorizations`,
`challenges`, `cert_req_ids`). There is no replication lag between the hosts and no node-local
state, so a pair behind one name is safe for every protocol precisely where a mesh is not.

**[measured] ACME works on a pair behind one name**, which is the case the mesh fails. On a
two-host pair fronted by haproxy in TCP passthrough, with requests landing on either host:
`certbot` dns-01 issued in 31 s and the certificate validated, and an http-01 order issued;
EST `simpleenroll`, CMP `ir`, OCSP, SCEP and the RFC 4387 store all succeeded through the same
name. The `badNonce` that breaks ACME on a mesh cannot arise here, because the nonce row one
host issued is the same row the other consumes.

**[invariant] Behind a load balancer, EVERY backend must be able to validate an ACME
challenge.** The protocol state crosses hosts freely — that is the measurement above — but
http-01, tls-alpn-01 and dns-01 all require the SERVER to reach back to something the client
controls, and the backend that validates is whichever one the balancer picked. A challenge
target reachable from only one host therefore fails for the fraction of orders the others
serve, and the error names the challenge rather than the topology.

Measured on the pair: the bench's http-01 cell scored 4/10, and the other host's ACME service
could not resolve the responder's name at all (`getent hosts` → nothing), because the bench
runs it as a container reachable only through the local Docker DNS. Every cell needing no
callback — EST, CMP, SCEP, OCSP, the store — scored 10/10 in the same run. The demo's
wildcard dns-01 and tls-alpn-01 legs fail the same way, for the same reason.

So an ACME deployment behind a balancer needs its challenge path uniform across backends: one
resolver every node can query for dns-01, and a route to the client's :80 and :443 from every
node for http-01 and tls-alpn-01.

**[open] CMP without `-implicit_confirm` is still unmeasured on a pair.** The console's
generated client configuration sets `implicit_confirm = 1`, so the run above did not exercise
the two-request shape. The reasoning says it is safe — `cert_req_ids` is a row in the shared
database — but that is reasoning, not a measurement.

**[measured] A standby issues its own certificates while still a standby**, so no certificate
work belongs to a promotion. Its applications reach the PRIMARY's database through the
multi-host `PG_CONNINFO`, so a write from it lands there; the only precondition is the CA key
in its own token, which `key sync` supplies. Measured on a standby reporting
`pg_is_in_recovery() = t`: its Postgres certificate was CA-issued and carried its OWN address,
and all four listener certificates were CA-issued, `certrenew` having re-issued them
unprompted.

**[invariant] An HA pair advertises ONE address, and that is a requirement rather than a
choice.** The CRLDP, AIA and SANs baked into a certificate are a contract with every client
already holding one, and a certificate cannot be told a new URL afterwards — so a pair is
fronted by a load balancer or a shared name, and `BASE_URL`/`PKI_DNS` are that name on both
hosts. Per-host URL lists are not the alternative: they would oblige every relying party and
pinned client configuration to learn the second host. `PG_BIND` stays per-host, because it
identifies the MACHINE — to Postgres replication, and in `p11_transport` (`high-availability.md` §3).

**[code] CMP is safe when the client requests implicit confirmation.** The server grants it
(`OSSL_CMP_SRV_CTX_set_grant_implicit_confirm`, `src/cmp/main.cpp`) and the console writes
`implicit_confirm = 1` into the client configuration it generates. The client must request
it; the server cannot impose it.

**[open] ACME can be made to work across data centers.** It requires the four object tables
of §8 to be replicated, and nonces to be derived rather than stored — for example an HMAC
over a timestamp and randomness under a key shared across data centers, with a short
validity — so that no row exists to replicate and no replay window exists. The residual cost
is replication lag on the object tables: a follow-up request reaching a node that has not yet
received the row returns 404 until it does.

**[open] Whether the single-name shape is retained is undecided.**

---

## 10. Serials, schema and audit

**[code] A certificate serial carries the issuing node in its high bits**:
`(prefix::bigint << 48) | nextval('certs_seq_local')` (`src/lib/db_postgres.cpp`). Two nodes
signing with one CA use disjoint serial ranges, so RFC 5280's per-issuer uniqueness holds
without coordination.

**[invariant] `sql/createdb.sql` is the schema, and is purely declarative** — every table
created outright, no `ALTER`, no `DROP` — because it runs only against an empty database.

**[invariant] `kSchemaVersion` is the minimum schema a binary runs against**, not an exact
match, so an expand/contract rollout may run old and new binaries against one database.

**[code] The schema version is 2.** Version 1 is the baseline of v0.1.0 through v0.2.3;
`sql/steps/0002-acme-device-attestation.sql` takes a version 1 database to version 2.

**[invariant] A database created by any published release upgrades with
`deploy/schema-apply.sh` followed by the new binaries.** So every schema change is one
commit containing a new `sql/steps/NNNN-*.sql`, the same change in `sql/createdb.sql`, the
seed version in `sql/createdb.sql`, the `kSchemaVersion` bump and the `sql/steps/CHECKSUMS`
line. A step that creates a replicated table adds it to the `fastpki_pub` publication. Steps
are immutable once shipped, and `deploy/schema-apply.sh` applies them before new binaries
roll.

**[code] The audit log is a per-node hash chain**: each row's `prev_hash` equals the previous
row's hash (`src/lib/audit.cpp`). This is why it is node-local — chains from different nodes
cannot be merged, and `audit_forward_state` is a node's cursor into its own log.

---

## 11. Resource footprint

**[invariant] A deployment is sized from what it is measured to use.** Low resource
consumption is a property of the product, so a default that pads against a workload the
deployment does not have is a defect, not caution.

**[invariant] The same binaries run on every deployment path**, so the differences between
the rows below belong to the platform, not to FastPKI.

**[measured] One node, every enrolment protocol running, no CA created, no load, read after
roughly ten minutes idle.** Each row was taken with the tool native to its path, and the
accounting differs: `free` counts the whole machine including the kernel, while `docker
stats` and `kubectl top` count only the containers' working set.

| path | CPU | memory | disk | instrument |
|---|---|---|---|---|
| Native / cloud | load average **0.00** on 2 vCPU | **239 MB** of a 924 MB machine — ten services and Postgres | root **263.9 MB**, data **64.0 MB** | `free -m`, `df -h`, `/proc/loadavg` on an AWS `t3.micro` |
| Docker Compose | every container **0.00%**; host load **0.29** on 2 CPU | **165 MB** over 11 containers — Postgres 84, the token 23, each listener 4-9 | volumes **48 MB**; images **556 MB** (`fastpki` 132 MB, `postgres:17-alpine` 424 MB) | `docker stats --no-stream`, `du` per volume |
| Kubernetes | **20-22m**, about one fiftieth of a processor | **100 MB** for the server pod's 11 containers — Postgres 55, the token 20, each listener 2-3 | claims in use **48 MB** | `kubectl top pod --containers`, k3s v1.36.4 |

**[measured] Memory keeps rising for several minutes after start-up, then levels off.** The
Compose deployment read 126 MB one minute in, 158 MB at ninety seconds and 165 MB from about
six minutes onward. An early reading understates a deployment by a third, so take these
figures after the services have settled.

**[measured] Postgres is the largest component on every path, and the token the second.**
Every listener is single digits: the protocol binaries are not what a node is sized for.

**[measured] A fresh database is 47.9 MB on every path** — 47.9 MB in `pgdata` under Compose
and Kubernetes, inside the 64.0 MB data volume on a cloud node. What grows it is issuance,
bounded by PostgreSQL's 1 GB `max_wal_size` default, so a 1 GB volume or claim holds a
demo and a small production deployment alike.

**[code] Only the Kubernetes path declares storage sizes** — `PG_DATA_SIZE`,
`PKI_DATA_SIZE` and `SOFTHSM_TOKEN_SIZE` in `deploy/k8s/env.sh`, each defaulting to `1Gi`.
Compose uses unsized Docker volumes, a native install uses the host's filesystem, and the
cloud module's `data_volume_gb` defaults to 1.
