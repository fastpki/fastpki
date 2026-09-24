# FastPKI

FastPKI is an enterprise Certificate Authority (CA) for organisations issuing certificates to
servers, laptops, mobile devices, network equipment, and users.

It serves standard enrolment protocols natively, so no proprietary agents need to be installed
on client devices. It supports Windows Autoenrolment, ACME, EST, SCEP, CMP, and OCSP/CRLs for
revocation checking.

A single FastPKI instance can host multiple CAs. CA signing keys are secured inside Hardware
Security Modules (HSMs), operational data is stored in PostgreSQL, and deployments can run
active-active across multiple data centers.

* **Language/Stack:** C++20 on OpenSSL 3.5
* **Architecture:** One lightweight binary per protocol with a shared core library

---

## Key Features

### Agentless, Pull-Based Issuance
* **Native Protocol Support:** Supports MS-XCEP/WSTEP for Windows domains, ACME for Linux and
  Unix servers, ACME with device attestation and SCEP for Macs, iPhones and iPads, SCEP for
  switches, firewalls and MDMs, CMP for industrial and telecom equipment, and EST for scripts.
* **Windows, macOS, iOS, Linux and Unix:** Windows domain members enrol themselves through
  autoenrolment. Macs, iPhones and iPads enrol from a configuration profile, downloaded ready-made
  from the console or delivered by an MDM platform; with ACME device attestation the device proves
  it is genuine Apple hardware and its key stays in the Secure Enclave. Linux and Unix hosts use any standard
  ACME, EST or CMP client.
* **One Policy for Every Protocol:** Every protocol issues under the same policy, the same roles
  and the same audit trail.
* **Pull-Based Model:** Clients generate their own private keys and request certificates
  directly from the CA. The CA never initiates connections to target hosts.
* **Minimal Firewall Exposure:** Requires a single outbound rule to the CA rather than inbound
  rules for every managed host.
* **Exceptions:**
  * **ACME Validation:** `http-01` and `tls-alpn-01` challenges connect back to verify domain
    control (`dns-01` does not).
  * **EST Server Keygen:** Allows key generation on the CA for devices that cannot generate a
    good key themselves (disabled by default).

### Hardware-Backed Key Security
* **Token Protection:** Every CA key exists solely as a PKCS#11 handle. `fastpki-ca` refuses
  key files.
* **Secure Key Replication:** Each node has its own token. A CA key reaches another node only
  by being replicated into that node's token over a mutually authenticated channel.
* **On-Token Key Generation:** Supports generating end-entity certificate keys directly inside
  the token, so nobody can copy them — including the requester.

### Active-Active Multi-Data Center Support
* **Multi-Master Replication:** Nodes run active-active over PostgreSQL logical replication.
* **Collision-Free Serials:** Nodes assign serial numbers from dedicated ranges.
* **High-Availability Revocation:** Certificates list a CRL endpoint for every data center, for
  automatic fallback by relying parties. The OCSP endpoint names the issuing data center, or
  every data center once the OCSP responder keys are replicated to them.
* **Unified Configuration:** Roles, profiles, templates, approved domains, and user directories
  replicate across all data centers.

### Post-Quantum Cryptography
* **ML-DSA Ready:** Supports ML-DSA for both CA signing keys and end-entity certificates.
* **Algorithm Compatibility:** See [`docs/compatibility.md`](docs/compatibility.md) for client
  support for ML-DSA, Ed25519, Ed448, EC and RSA, and for the limits inside FastPKI itself.

### Unified Policy & Governance
* **Data-Driven Policies:** All profiles, roles, and domain restrictions are edited via the
  console and stored in PostgreSQL.
* **Certificate Profiles:** Define the names, key usages, and lifetimes a certificate may have.
  Roles grant profiles, and holding several combines what they allow.
* **Active Directory Integration:** Import and serve Windows templates directly from AD.
* **Role-Based Access Control (RBAC):** Restrict roles to specific CAs, cap issuance quotas, and
  set approved-domain allowlists.

### Authentication & Identity
* **Console Sign-In:** Local accounts, LDAP/Active Directory, and single sign-on over OIDC or
  SAML (for example AD FS). Client certificates (mTLS) and API bearer tokens are also accepted.
* **Multiple Directories:** Several directories can be connected at once. Names are
  provider-qualified (`corp\alice`), and an unqualified name always means a local account.
* **Directory Groups:** Roles can be granted to directory groups, so group membership decides
  what a user may do.
* **Enrolment Authentication:**
  * **EST:** HTTP Basic or a TLS client certificate.
  * **Windows (MS-XCEP/WSTEP):** Kerberos, HTTP Basic, or a WS-Security UsernameToken.
  * **CMP:** A per-user shared secret or a certificate signature.
  * **SCEP:** A per-user or one-time challenge password.
  * **ACME:** Account keys, with optional External Account Binding.
* **Brute-Force Protection:** Failed logins trigger a backoff that doubles per account and per
  address, instead of locking accounts out.
* **Secure Defaults:** The seeded administrator must set a new password before doing anything
  else, and no setting turns authentication off.

### Discovery & Auditing
* **Certificate Discovery:** Scans IP addresses and CIDR ranges to map active certificates
  (including ones FastPKI never issued) and flag weak keys or deprecated algorithms.
* **Automated Expiry Alerts:** Triggers webhook notifications (JSON, Slack, Teams, ServiceNow) and email
  alerts to certificate owners at defined warning thresholds.
* **Tamper-Evident Audit Log:** Events are hash-chained to previous entries and validated with
  signed checkpoints. Supports direct forwarding to syslog and Splunk HEC.

### Automation
* **Clients Renew Themselves:** ACME clients, EST re-enrolment, SCEP renewal, CMP key update and
  Windows autoenrolment all renew certificates without an administrator.
* **Service Certificates Renew Themselves:** A daily job renews the OCSP responder, CMP RA,
  SCEP RA and HTTPS certificates at 75% of their lifetime, and the running services pick up the
  renewal without a restart. It also replaces the self-signed certificates the services start
  with, and creates any missing credentials.
* **Keys Converge on Their Own:** In an HA pair, each host copies the CA keys it is missing from
  the other every night.
* **Rolling Updates:** `rolling-update.sh` applies schema changes first, then replaces the
  services one at a time.
* **API and MCP:** Everything the console does is available over its HTTP/JSON API, and
  `fastpki-mcp` exposes the certificate inventory to MCP clients (read-only unless
  `MCP_ALLOW_WRITE` is set).

### Fast Deployment
* **One Command, No Checkout:** `curl -fsSL <release URL> | bash` downloads a release, checks its
  signature, and runs the install wizard.
* **Unattended Installs:** `install.sh --answers <file>` installs from an answers file. The next
  data center's file is the first one's with three values changed.
* **Every Path Scripted:** Kubernetes installs with `deploy/k8s/apply.sh`, and AWS from a
  machine image you build once and an OpenTofu module.
* **HA and Mesh in One Command Each:** `deploy/ha-join-pair.sh` joins a standby to its primary,
  and `deploy/mesh-join.sh` connects data centers into a mesh, both run from the operator's
  machine.

### Operations
* **Console & CLI Parity:** Web console covers all administration tasks, with matching
  commands available in the CLI.
* **Lightweight Footprint:** 128 MB AlpineLinux image with no JVM or application server overhead.
* **Flexible Deployment Options:** Run via Docker Compose, Kubernetes, native Alpine + OpenRC,
  or a cloud image.
* **Pluggable Tokens:** Ships with a built-in software token; swap to a hardware HSM by setting
  `PKCS11_MODULE` to the vendor's module.

---

## Protocol Support & Status

| Protocol | Specification | Status & Features |
| :--- | :--- | :--- |
| **OCSP** | RFC 6960 | Working — Status responses, delegated responder, CRLs, and delta CRLs. |
| **EST** | RFC 7030 | Working — `cacerts`, `simpleenroll`, `simplereenroll`, `csrattrs`, optional `serverkeygen`. |
| **ACME** | RFC 8555 | Working — `http-01`, `dns-01`, `tls-alpn-01`, wildcards, CAA, External Account Binding (EAB), and `device-attest-01` for Apple devices. |
| **CMP** | RFC 9810 | Working — `ir`, `cr`, `p10cr`, `kur`, revocation, `certConf`, `genm`, RA mode. |
| **SCEP** | RFC 8894 | Working — Enrolment, renewal, CA rollover, one-time or per-user challenges; Apple configuration profiles. |
| **MS-XCEP / MS-WSTEP** | Microsoft Specs | Working — Unattended Windows autoenrolment against Active Directory. |
| **Certificate Store** | RFC 4387 | Working — Search by 9 selectors; outputs DER or PKCS#7. |

> **Database Note:** PostgreSQL is the only supported database engine.
>
> **Known Limitation:** MS-WSTEP does not sign its responses (no WS-Security signature or
> timestamp). The native Windows client accepts this, but relying parties requiring signed
> WSTEP responses are unsupported. See [`docs/user-guide.md`](docs/user-guide.md) §10.3.

---

## Performance

Measured with `demo/pki-bench.sh` against a throwaway deployment inside the shipped Alpine
image, on an Apple M1 (Docker Desktop, 4 vCPUs).

> **Single thread, so per core:** the bench runs one client and sends one request at a time.
> Every figure is what one core delivers, not the capacity of a multi-core host. Each operation
> also includes the client's own process start and, for EST, a TLS handshake.

| Operation | Key Types | Rate per Core |
| :--- | :--- | :--- |
| **CMP enrolment** | RSA, RSA-PSS, EC, Ed25519, ML-DSA | 54–68 certificates/s |
| **SCEP enrolment** | RSA, EC | 34–38 certificates/s |
| **EST enrolment** | RSA, RSA-PSS, EC, Ed25519, ML-DSA | 20 certificates/s |
| **OCSP status** | — | 78 responses/s |
| **Certificate store search** | — | 466 searches/s |

* **Memory:** Idle on a running Docker Compose deployment (`docker stats`, on a 2-vCPU server),
  each of the eight services uses 2–4 MiB, the token 14 MiB and PostgreSQL 63 MiB — about
  100 MiB in all.
* **ACME:** not measured here; its bench leg drives certbot in a container of its own.

---

## Documentation Index

| File | Description |
| :--- | :--- |
| [`docs/user-guide.md`](docs/user-guide.md) | **End Users:** Console usage and enrolment protocols from the client perspective, with worked examples. |
| [`docs/admin-guide.md`](docs/admin-guide.md) | **Administrators:** Console and CLI workflows for CAs, certificates, users, roles, backups, and updates. |
| [`docs/deployment.md`](docs/deployment.md) | **Installation:** Guides for Docker Compose, Kubernetes, Alpine + OpenRC, and AWS cloud images. |
| [`docs/high-availability.md`](docs/high-availability.md) | **HA Setup:** Database standby on a second host, failover procedures, and restoring the pair. |
| [`docs/postgres.md`](docs/postgres.md) | **Database:** Connection setup, TLS configuration, schema changes, backup/restore, and table reference. |
| [`docs/config-reference.md`](docs/config-reference.md) | **Configuration:** Complete reference of configuration keys, the services that read them, and default values. |
| [`docs/cli-reference.md`](docs/cli-reference.md) | **CLI:** Complete command and subcommand reference. |
| [`docs/protocol-apis.md`](docs/protocol-apis.md) | **Protocol APIs:** Protocol endpoint specs, authentication schemes, and HTTP status codes. |
| [`docs/components.md`](docs/components.md) | **Binaries:** Each binary, the endpoints it serves, and the configuration keys that change its behaviour. |
| [`docs/api-reference.md`](docs/api-reference.md) | **REST API:** Complete HTTP/JSON API reference for the management console. |
| [`docs/authentication.md`](docs/authentication.md) | **Auth:** Local authentication, LDAP/AD, OIDC, SAML, and mTLS configuration. |
| [`docs/rbac.md`](docs/rbac.md) | **Access Control:** Roles, permissions, scopes, and verbs reference. |
| [`docs/windows-autoenrolment.md`](docs/windows-autoenrolment.md) | **Windows:** Setup for unattended Active Directory domain autoenrolment. |
| [`docs/compatibility.md`](docs/compatibility.md) | **Cryptography:** Algorithm verification compatibility across relying parties (ML-DSA, Ed25519, RSA). Read before choosing a CA key. |
| [`docs/architecture.md`](docs/architecture.md) | **Design Record:** Tokens and keys, HA, mesh state, and addressing, with each claim tagged by how it is known. |

---

## Licence & Third-Party Code

FastPKI is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE.md). You are free
to inspect, modify, and redistribute this software for noncommercial purposes. Commercial use
requires a separate commercial licence from FastPKI.

### Included Dependencies
* **Compiled into binaries:** `cpp-httplib` (MIT), `nlohmann/json` (MIT)
* **Built from source and bundled:** `SoftHSMv2` (BSD 2-Clause), `p11-kit` (BSD 3-Clause),
  `pkcs11-provider` (Apache 2.0)
* **Linked from Alpine packages:** `OpenSSL` (Apache 2.0), `libpq` (PostgreSQL), `OpenLDAP`
  (OLDAP-2.8) with `Cyrus SASL` (BSD), `MIT Kerberos` (MIT), `libxml2` (MIT), `xmlsec` (MIT)
  with `libxslt` (X11), `zlib` (Zlib), and the C and C++ runtimes, `musl` (MIT) and
  `libstdc++` (GPL/LGPL)
* **Also in the image, from Alpine packages:** `stunnel` (GPL-2.0+ with the OpenSSL exception)
  for the key tunnel, and `OpenSC` (LGPL-2.1+) and the PostgreSQL client (PostgreSQL) for the
  deployment scripts

For full licensing notices, including every package each of those depends on, see
[`NOTICE.md`](NOTICE.md). Container deployments provide attribution at `/app/NOTICE.md`,
individual project licences at `/app/licences/`, the licence texts of every Alpine package at
`/app/licences/alpine/`, and the exact list of Alpine packages in the image, with versions and
licences, at `/app/licences/alpine-packages.txt`.
