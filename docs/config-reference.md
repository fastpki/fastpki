# FastPKI Configuration Reference

**Settings live in the database.** The `config` table is where a setting belongs and where
it wins: a row there overrides whatever `bootstrap.conf` or the environment said, for every
key but `PG_CONNINFO`. Every service applies the table, and so do `fastpki-ca`,
`fastpki-audit`, `fastpki-notify` and `fastpki-scep --issue-challenge`; `fastpki-mcp` and
`fastpki-update` do not, and read only `bootstrap.conf` and the environment.

Most keys have a field on the console's **Config** page. The ones below do not; set them by
adding a `KEY=value` line in that page's **Edit full config file** editor, with `fastpki-config
set <KEY> <VALUE>`, or through `PUT /api/config/db`:

- the per-service key settings — `WEB_KEY_ALGO`, `WEB_KEY_BITS`, `WEB_KEY_CURVE`,
  `WEB_KEY_MD`, `EST_KEY_ALGO`, `EST_KEY_BITS`, `EST_KEY_CURVE`, `EST_KEY_MD`,
  `ACME_KEY_ALGO`, `ACME_KEY_BITS`, `ACME_KEY_CURVE`, `ACME_KEY_MD`, `MS_KEY_ALGO`,
  `MS_KEY_BITS`, `MS_KEY_CURVE`, `MS_KEY_MD`, `OCSP_RESPONDER_KEY_ALGO`,
  `OCSP_RESPONDER_KEY_BITS`, `OCSP_RESPONDER_KEY_CURVE`, `CMP_RA_KEY_ALGO`,
  `CMP_RA_KEY_BITS`, `CMP_RA_KEY_CURVE`, `SCEP_RA_KEY_BITS`
- the response digests — `OCSP_RESPONSE_MD`, `CMP_RESPONSE_MD`, `SCEP_RESPONSE_MD`
- `PKCS11_TOKEN`, `PKCS11_PIN_FILE`, `CMP_CLIENT_CA_REFRESH_SEC`,
  `SERVICE_CERT_RENEW_FRACTION`, `ALLOW_WEAK_SIGNATURE_DIGEST`, `LOGIN_FAILURE_THRESHOLD`,
  `LOGIN_LOCKOUT_SEC`, `SCEP_ALLOW_SHA1`, `SCEP_ALLOW_DES3`

Neither the editor nor `fastpki-config set` checks a key against the parser, so a misspelt key
is stored and then ignored. Certificate profiles are not settings: they are a table of their
own (see §24).

`bootstrap.conf` (default: `config/bootstrap.conf`) carries what is needed *before* the database can be
read — `PG_CONNINFO` above all, which is the one bootstrap key and is refused from the
table — plus anything a particular node wants as a fallback. It is not the place to keep a
setting the table can hold.

Overlay values are applied at startup, so a key changed in the table shows as *pending
restart* on the Config page until the service that reads it has been restarted.

Keys marked **file-only** are not accepted from environment variables.

## Contents

- [Legend](#legend)
- [1. Global / PKI Identity](#1-global--pki-identity)
- [2. CA Material](#2-ca-material)
- [3. PKCS#11 HSM](#3-pkcs11-hsm)
- [4. Database](#4-database)
- [5. Data center Replication](#5-data-center-replication)
- [6. OCSP Responder](#6-ocsp-responder)
- [7. CRL](#7-crl)
- [8. EST (RFC 7030)](#8-est-rfc-7030)
- [9. ACME (RFC 8555)](#9-acme-rfc-8555)
- [10. Notify (Expiry Notifications)](#10-notify-expiry-notifications)
- [11. Software Update](#11-software-update)
- [12. Discovery](#12-discovery)
- [13. CMP (RFC 4210/9810)](#13-cmp-rfc-42109810)
- [14. MS-XCEP / MS-WSTEP](#14-ms-xcep--ms-wstep)
- [15. RFC 4387 Certificate Store](#15-rfc-4387-certificate-store)
- [16. Web Console](#16-web-console)
- [17. MCP Server](#17-mcp-server)
- [18. SSO — OIDC and SAML 2.0](#18-sso--oidc-and-saml-20)
- [19. SCEP (RFC 8894)](#19-scep-rfc-8894)
- [20. LDAP (Auth Backend)](#20-ldap-auth-backend)
- [21. Issuance Policy & Constraints](#21-issuance-policy--constraints)
- [22. Domain & IP Restrictions](#22-domain--ip-restrictions)
- [23. Certificate Extension URLs](#23-certificate-extension-urls)
- [24. Auth, Users & Profiles](#24-auth-users--profiles)
- [25. Logging](#25-logging)
- [Environment Variable Override](#environment-variable-override)
- [Bootstrap Keys](#bootstrap-keys)
- [Side-Effect Keys](#side-effect-keys)

## Legend

| Type | Meaning |
|------|---------|
| `string` | Free text |
| `path` | Filesystem path |
| `int` | Integer |
| `bool` | `1`/`true`/`yes` (or `0`/`false`/`no`) |
| `csv` | Comma-separated list |
| `semi` | Semicolon-separated list (for DNs containing commas) |

---

## 1. Global / PKI Identity

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `PKI_DNS` | string | `pki.example.org` | FQDN of this PKI deployment. Auto-sets `BASE_URL` if still default. |
| `BASE_URL` | string | `https://pki.example.org` | Public HTTPS URL. ACME directory advertises this. |
| `ALLOW_WEAK_SIGNATURE_DIGEST` | bool | `false` | Permit MD5, SHA-1, MD2/MD4 and RIPEMD-160 as **signature** digests. Off, every place a digest can be named — a certificate request's `md=`, a CA certificate's own signature hash, the OCSP and SCEP response digests — refuses them, and the console answers 400 saying so. Turn it on only for equipment that verifies nothing stronger. Matched by algorithm rather than by the name written, so every spelling OpenSSL accepts for a given digest is covered by one rule. |
| `LOGIN_FAILURE_THRESHOLD` | int | `5` | Consecutive failed sign-ins tolerated, per account and per client address, before a delay applies. Below this nothing happens. |
| `LOGIN_LOCKOUT_SEC` | int | `300` | Ceiling on that delay. Past the threshold it doubles (1s, 2s, 4s …) up to this, measured from the **last** failure, so continuing to guess is what keeps the door shut. A correct password clears the count. Per node and in memory, not shared across a mesh. |

## 2. CA Material

**A signing CA is not configured here.** It is a row in the `certs` table carrying `is_ca=true`
created from the console or the API, and addressed by its id in every
protocol path. There are no `SIGNING_CA_*` keys — a fresh deployment has no CA and
the enrolment services stay down until one exists.

## 3. PKCS#11 HSM

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `PKCS11_MODULE` | path | *(empty)* | Path to the vendor/SoftHSM `.so` module. |
| `PKCS11_PROVIDER_PATH` | path | *(empty)* | Directory holding OpenSSL pkcs11.so provider. |
| `PKCS11_TOKEN` | string | `fastpki` | Token label to generate new keys in. |
| `PKCS11_PIN_FILE` | path | *(empty)* | File holding the token PIN, so it is never in a config value or a URI. |

## 4. Database

PostgreSQL is the only backend.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `PG_CONNINFO` | string | *(empty)* | libpq connection string. **Bootstrap key** — cannot be overridden by the DB `config` table. |
| `PG_TLS_DIR` | path | `/var/pki/tls/pg` | Where the Postgres server's own `server.crt` / `server.key` / `ca.crt` live. **The one private key in FastPKI that is a file** — PostgreSQL's `ssl_key_file` takes a path and the server has no PKCS#11 support, so the HSM route every other listener uses cannot serve it. Written by the console: Inventory → **Issue Postgres certificate** (it is not the ordinary "Request (key in HSM)" action, because this key cannot live in a token), by `fastpki-ca pg-tls`, and by the daily `fastpki-ca renew-service-certs` run when `PG_TLS_CA_ID` is set. |
| `PG_TLS_SANS` | string | *(empty)* | Extra SANs for that certificate, comma-separated. `postgres`, `localhost`, `127.0.0.1`, `PKI_DNS` and this node's own `PG_BIND` are always included, so a node does not need this to certify the address its peers dial. `PG_BIND` is a deployment environment variable (the address this node's Postgres listens on), not a config key, which is what keeps it per host; where it is not set, only the other four and this list are named. ⚠️ It is read from the `config` table, which is node-local in a mesh but SHARED by the two hosts of an HA pair — so an address recorded here becomes a name on the other host's certificate too. Leave interconnect addresses to `PG_BIND`. |
| `PG_TLS_CA_ID` | string | *(empty)* | Which CA issues that certificate when nothing is there to be asked — the nightly job that keeps it current. An operator naming a CA on the command line does not need it. Unset, that job does nothing and says so. Unlike `PG_TLS_SANS` this is deployment-wide, so an HA pair sharing one row is correct — both hosts should issue from the same CA. |

## 5. Data center Replication

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `DATACENTER_ID` | string | *(empty)* | This **data center's** id, and the key into the `datacenters` table. Set = every serial this node assigns carries the 2-octet prefix from that row. Empty = single node, full-width random serials. Digits, matching the topology's `dc_id` exactly — the lookup is against this literal value, and the installers write the bare index, so `dc1` matches nothing. |

It identifies the **data center, not the host**. The two hosts of an HA pair therefore carry
the **same** value — a pair is one data center twice — while every data center in a mesh
carries a different one. A standby that is left unset assigns full-width serials outside its
data center's partition from the moment it is promoted, permanently and with nothing warning:
the certificates are valid and enrolment succeeds. See `high-availability.md`.

Two hosts sharing an id also share the per-node ids derived from it, including the
`web-<id>` / `est-<id>` / `acme-<id>` / `ms-<id>` rows their listener certificates are
published under, so a pair holds several rows per id and each host serves the one matching
the key it holds.

There is no config key for the serial prefix itself: it lives in this node's own
`datacenters` row, written by `fastpki-mesh --map`, so the bound has one source of
truth. A node whose `DATACENTER_ID` has no matching row **refuses to issue** —
assigning an unprefixed serial could collide with a peer's, and the serial is the `certs`
primary key, so a collision stalls that peer's replication apply worker.

## 6. OCSP Responder

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `OCSP_BIND` | string | `::` | Bind address. The default is the IPv6 wildcard, which is DUAL-STACK: IPv6 clients and IPv4 ones (as IPv4-mapped addresses) both reach it. `0.0.0.0` serves IPv4 only. On a host whose IPv6 stack is disabled the wildcard falls back to `0.0.0.0` and logs that it did. |
| `OCSP_PORT` | int | `8080` | Listen port. |
| `OCSP_RESPONDER_CERT_ID_PREFIX` | string | `ocsp-ra` | `cert_id` **prefix** for the delegated responder certificate. The real id is `<this>-<ca_id>`, and the certificate must be issued **by that CA** (RFC 6960 §4.2.2.2). Held in the DB, not a file. |
| `OCSP_RESPONDER_KEY` | path | *(empty)* | Delegated responder key. Supports `pkcs11:` URI. |
| `OCSP_RESPONSE_MD` | str | – | Digest every **OCSP response** is signed with, e.g. `sha384`, `sha512`, `sha3-256`. Honoured for `rsa`/`rsa-pss` responder keys only — EC auto-matches its curve, Ed25519 and ML-DSA carry their own digest, and an RFC 4055 restriction published by the responder certificate always wins. An unknown name falls back to the key's default rather than taking OCSP down over a label. |
| `OCSP_EXPIRY_SWEEP_SEC` | int | `3600` | Background expired-cert sweep interval (0 = disabled). |
| `CRL_PUBLISH_SWEEP_SEC` | int | `3600` | How often this node re-signs and **stores** the CRL of every CA whose key it holds, so the mesh replicates it and peers can serve that CA's revocation while this node is down (0 = disabled). The stored copy is rewritten only when the revocations changed or it is past half its validity, so a quiet CA costs one query per sweep and no replication traffic. Full CRLs only — a delta is relative to a base point the client chooses, so it is not a thing a peer can serve on someone else's behalf. |
| `SERVICE_CERT_RENEW_FRACTION` | float | `0.75` | How far through its own lifetime a **service credential** (OCSP responder, CMP RA, SCEP RA) must be before `fastpki-ca renew-service-certs` reissues it. A fraction, not a fixed lead time: 30 days is most of a 90-day responder certificate and a rounding error on a ten-year one. Values outside `(0,1)` fall back to `0.75`. |

### Keys FastPKI generates for itself

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `WEB_KEY_ALGO` | str | `ec` | Algorithm of the key the **web console TLS** generates for itself in the token at first start: `ec`, `rsa` or `rsa-pss`. A TLS listener key is limited to these three because a peer has to negotiate it (see `docs/compatibility.md` §1). |
| `WEB_KEY_BITS` | int | – | RSA size for that key. Ignored when the algorithm is `ec`. |
| `WEB_KEY_CURVE` | str | `P-256` | EC curve for that key. Ignored when the algorithm is `rsa`. |
| `WEB_KEY_MD` | str | – | Digest the **web console**'s self-signed certificate is signed with, e.g. `sha384`, `sha512`, `sha3-256`. Honoured for `rsa`/`rsa-pss` only — EC, Ed25519 and ML-DSA carry their own digest and auto-match, and an RFC 4055 restriction on the key always wins. An unknown name falls back to the default rather than stopping the listener. |
| `EST_KEY_ALGO` | str | `ec` | Algorithm of the key the **EST listener TLS** generates for itself in the token at first start: `ec`, `rsa` or `rsa-pss`. A TLS listener key is limited to these three because a peer has to negotiate it (see `docs/compatibility.md` §1). |
| `EST_KEY_BITS` | int | – | RSA size for that key. Ignored when the algorithm is `ec`. |
| `EST_KEY_CURVE` | str | `P-256` | EC curve for that key. Ignored when the algorithm is `rsa`. |
| `EST_KEY_MD` | str | – | Digest the **EST listener**'s self-signed certificate is signed with, e.g. `sha384`, `sha512`, `sha3-256`. Honoured for `rsa`/`rsa-pss` only — EC, Ed25519 and ML-DSA carry their own digest and auto-match, and an RFC 4055 restriction on the key always wins. An unknown name falls back to the default rather than stopping the listener. |
| `ACME_KEY_ALGO` | str | `ec` | Algorithm of the key the **ACME listener TLS** generates for itself in the token at first start: `ec`, `rsa` or `rsa-pss`. A TLS listener key is limited to these three because a peer has to negotiate it (see `docs/compatibility.md` §1). |
| `ACME_KEY_BITS` | int | – | RSA size for that key. Ignored when the algorithm is `ec`. |
| `ACME_KEY_CURVE` | str | `P-256` | EC curve for that key. Ignored when the algorithm is `rsa`. |
| `ACME_KEY_MD` | str | – | Digest the **ACME listener**'s self-signed certificate is signed with, e.g. `sha384`, `sha512`, `sha3-256`. Honoured for `rsa`/`rsa-pss` only — EC, Ed25519 and ML-DSA carry their own digest and auto-match, and an RFC 4055 restriction on the key always wins. An unknown name falls back to the default rather than stopping the listener. |
| `MS_KEY_ALGO` | str | `ec` | Algorithm of the key the **MS-XCEP/WSTEP listener TLS** generates for itself in the token at first start: `ec`, `rsa` or `rsa-pss`. A TLS listener key is limited to these three because a peer has to negotiate it (see `docs/compatibility.md` §1). |
| `MS_KEY_BITS` | int | – | RSA size for that key. Ignored when the algorithm is `ec`. |
| `MS_KEY_CURVE` | str | `P-256` | EC curve for that key. Ignored when the algorithm is `rsa`. |
| `MS_KEY_MD` | str | – | Digest the **MS-XCEP/WSTEP listener**'s self-signed certificate is signed with, e.g. `sha384`, `sha512`, `sha3-256`. Honoured for `rsa`/`rsa-pss` only — EC, Ed25519 and ML-DSA carry their own digest and auto-match, and an RFC 4055 restriction on the key always wins. An unknown name falls back to the default rather than stopping the listener. |

**These are the four services that need a self-signed certificate to start before any CA exists.** `_BITS` applies to RSA, `_CURVE` to EC; the other is ignored.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `SERVICE_KEYS_REPLICABLE` | bool | `false` | `true` generates the OCSP responder, CMP RA and SCEP RA keys extractable, so they can be replicated into another node's token (`fastpki-ca key replicate`). Read by `renew-service-certs` when `--replicable` is not on its command line, which is how the scheduled job — Compose's `certrenew`, each Kubernetes server's `renew` container, the OpenRC periodic — can generate keys an HA pair's standby will be able to receive. ⚠️ It decides what the NEXT key generation does: `CKA_EXTRACTABLE` is fixed at generation, so a key already generated cannot be changed. Leave it `false` on a single node, where a key that cannot leave its token is the stronger position. |
| `OCSP_RESPONDER_KEYS_REPLICATED` | bool | `false` | `true` lets a certificate advertise **every** data center's OCSP responder in AIA, not only the one that issued it. Leave it `false` unless the `ocsp-ra-<ca-id>` private keys really are replicated to every data center. The CRL distribution point and the caIssuers URL name every data center regardless: a CRL and a CA certificate are signed once and the mesh replicates them, so any node can serve a copy. An OCSP response is signed **per request** with that CA's responder key, so a data center that does not hold the key cannot answer at all — and a certificate's URLs are fixed when it is issued, so a responder named here that cannot answer stays named for the life of the certificate. Replicate the keys with `fastpki-ca key sync` or `key replicate` (which needs keys generated `--replicable`), confirm every data center answers, and only then set this. |
| `HTTPS_CA_ID` | string | *(empty)* | Which CA replaces those four self-signed certificates when the node has **more than one** issuing CA. The daily `fastpki-ca renew-service-certs --re-issue-self-signed` run uses `--ca` if given, then this setting, then the node's only issuing CA. With several issuing CAs and neither `--ca` nor this setting, it re-issues nothing and reports the candidates. A root CA is used only when named. Only a certificate that is still self-signed is affected: one already issued by a CA is renewed by that CA, whatever this says. Unlike `PG_TLS_SANS` this is deployment-wide, so both hosts of an HA pair use the same value. |

⚠️ **CMP RA, SCEP RA and the OCSP responder are different**: they start without their credential and leave the feature off until one exists, so their keys are created after a CA does — not at first start. The settings below say what to create when that happens.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `OCSP_RESPONDER_KEY_ALGO` | str | `ec` | Algorithm of the **OCSP responder** key: `ec`, `rsa` or `rsa-pss`. A responder answers every client that asks, including Windows and libpq, so it is held to the same reach as a listener. |
| `OCSP_RESPONDER_KEY_BITS` | int | – | RSA size for that key. Ignored when the algorithm is `ec`. |
| `OCSP_RESPONDER_KEY_CURVE` | str | `P-256` | EC curve for that key. Ignored for RSA. |
| `CMP_RA_KEY_ALGO` | str | `ec` | Algorithm of the **CMP RA** key. The widest of the three: `ec`, `rsa`, `rsa-pss`, `ed25519`, `ed448` and `ML-DSA-44`/`-65`/`-87` are all usable, because the CMP client is OpenSSL rather than a TLS peer or a Windows stack. |
| `CMP_RA_KEY_BITS` | int | – | RSA size for that key. Ignored for the other algorithms. |
| `CMP_RA_KEY_CURVE` | str | `P-256` | EC curve for that key. Ignored for the other algorithms. |
| `SCEP_RA_KEY_BITS` | int | `3072` | RSA size for the **SCEP RA** key. |

The size is the only choice a SCEP RA key offers. That key decrypts the PKIOperation
envelope, so it is always plain RSA.

`deploy/install.sh` asks for these and writes only the ones that apply, so an EC install
carries no `<SERVICE>_KEY_BITS` and an RSA one no `<SERVICE>_KEY_CURVE`.

These do **not** govern CA signing keys: a CA key is chosen per CA at creation time (the
console's CA form, or `fastpki-ca create --key/--bits/--curve`), because it is a decision
per hierarchy rather than per install.

⚠️ **The SCEP RA key is not free to choose.** It decrypts the SCEP PKIOperation envelope
(`CMS_decrypt`), which requires key transport, and FastPKI implements that for RSA only —
`key_can_encipher()` accepts RSA/RSA-PSS and `key_usage_for_key()` silently strips
`keyEncipherment` from anything else. An EC SCEP RA key is generated without complaint, the
service starts cleanly, and the failure appears as a 400 at the first enrolment. With the
services defaulting to `ec`, issue the SCEP RA credential separately as RSA — it is not created at install at all.

### Renewing the service credentials

FastPKI issues itself three certificates that are neither CA certificates nor certificates a
client asked for — the OCSP responder, the CMP RA and the SCEP RA.
They are reissued by a **scheduled invocation of the CLI**, not by a timer inside each
service:

```bash
# Compose
docker compose run --rm --no-deps --entrypoint fastpki-ca web \
    --config /app/config/bootstrap.conf renew-service-certs \
    [--ca <id>] [--create-missing] [--re-issue-self-signed] [--replicable] [--dry-run] [--force]

# Native / cloud
doas su -s /bin/sh fastpki -c 'fastpki-ca --config /etc/fastpki/bootstrap.conf \
    renew-service-certs [--ca <id>] [--create-missing] [--re-issue-self-signed] [--replicable] [--dry-run] [--force]'
```

`--create-missing` also creates the credentials a CA does not have yet;
`--re-issue-self-signed` replaces this node's self-signed listener certificates with
CA-issued ones; `--replicable` generates new credential keys extractable, which is what
`SERVICE_KEYS_REPLICABLE` does for a run with no command line. [cli-reference.md](cli-reference.md)
describes each in full.

The docker-compose stack ships this as the `certrenew` service, the Kubernetes deploy as the
`renew` container of every server pod and a native install as `/etc/periodic/daily/fastpki-certrenew`;
all three tick daily, which is a *polling* interval — the renewal threshold is
`SERVICE_CERT_RENEW_FRACTION` above.

⚠️ **The token transport's own pair is renewed by the same daily job, on a different
schedule and by a different mechanism.** `renew-service-certs` covers what a CA issued; the
two certificates the `P11_TLS` tunnel presents (`p11-server` and `p11-client`) are
self-signed and pinned, so they are not `certs` rows and it never sees them. The daily job
therefore also runs `certgen.sh --p11-only`, which re-issues each once it is within
`SELFSIGNED_RENEW_DAYS` (default 90) of the end of its `SELFSIGNED_DAYS` (default 825)
lifetime and does nothing before that. The keys are untouched — they stay token objects —
so only the certificates change. The job then republishes them and re-syncs the peers', so a
renewal reaches the nodes that pin it without anyone restarting a service.

⚠️ `certs` is logically replicated, so this command runs concurrently on every node. It is
safe because it is idempotent and takes a Postgres advisory lock: the first invoker renews
and the rest print `another node is already renewing service certificates` and exit 0.

Renewing a CA with a new key updates its credentials automatically: the console reissues that CA's service
credentials under the new key, because otherwise they chain only through the CA's previous
certificate and stop verifying when it expires.

## 7. CRL

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `CRL_PATH` | string | `/pki/signing_ca.crl` | URL path where the CRL is served. |
| `CRL_NEXT_UPDATE_DAYS` | int | `30` | CRL validity period. |
| `CRL_DELTA` | bool | `false` | Delta CRL support (RFC 5280 §5.2.4). |
| `CRL_CACHE_TTL_SEC` | int | `300` | CRL regeneration throttle (0 = no cache). |

## 8. EST (RFC 7030)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `EST_BIND` | string | `::` | Bind address. The default is the IPv6 wildcard, which is DUAL-STACK: IPv6 clients and IPv4 ones (as IPv4-mapped addresses) both reach it. `0.0.0.0` serves IPv4 only. On a host whose IPv6 stack is disabled the wildcard falls back to `0.0.0.0` and logs that it did. |
| `EST_PORT` | int | `8443` | Listen port (HTTPS). |
| `EST_CERT` | path | *(empty)* | Server TLS cert **from a file**. **File-only.** Unset: the certificate is the `certs` row `EST_CERT_ID` names. A path here wins over that row and freezes the listener on whatever the file holds. |
| `EST_CERT_ID` | string | `est` | Which CA-issued cert to serve from the `certs` table, by id. Set by default, so a DB-held certificate is the normal path and a file is the fallback. |
| `EST_KEY` | pkcs11 URI or path | `pkcs11:token=fastpki;object=est-tls;type=private?pin-source=/var/pki/tls/pin` | Server TLS key. A `pkcs11:` URI keeps it in the token, which is the default; a PEM path is the fallback. |
| `EST_CSRATTRS` | string | *(empty)* | Legacy global OIDs (dotted, comma/space-separated). |
| `EST_DEFAULT_PROFILE` | string | *(empty)* | Profile for anonymous `/csrattrs`. |
| `EST_SERVERKEYGEN` | bool | `false` | Server-side key generation (RFC 7030 §4.4). |
| `EST_SERVERKEYGEN_ENCRYPT` | bool | `true` | Encrypt returned key with CMS EnvelopedData. |
| `EST_SERVERKEYGEN_BITS` | int | `2048` | RSA key size for server keygen. |
| `EST_CLIENT_CA_ID` | string | *(empty)* | CA id(s), comma-separated, whose certificate is a client-cert trust anchor for EST enrolment (RFC 7030 §3.3.2). Empty = EST never asks for a client certificate and callers use HTTP Basic over TLS. |
| `EST_CLIENT_CA_BUNDLE` | string | *(empty)* | PEM text for client-cert trust anchors that are not CAs registered here. Additive with `EST_CLIENT_CA_ID`. |

## 9. ACME (RFC 8555)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ACME_BIND` | string | `::` | Bind address. The default is the IPv6 wildcard, which is DUAL-STACK: IPv6 clients and IPv4 ones (as IPv4-mapped addresses) both reach it. `0.0.0.0` serves IPv4 only. On a host whose IPv6 stack is disabled the wildcard falls back to `0.0.0.0` and logs that it did. |
| `ACME_PORT` | int | `8444` | Listen port (HTTPS). |
| `ACME_CERT` | path | *(empty)* | Server TLS cert **from a file**. **File-only.** Unset: the certificate is the `certs` row `ACME_CERT_ID` names. A path here wins over that row and freezes the listener on whatever the file holds. |
| `ACME_CERT_ID` | string | `acme` | Which CA-issued cert to serve from the `certs` table, by id. Set by default, so a DB-held certificate is the normal path and a file is the fallback. |
| `ACME_KEY` | pkcs11 URI or path | `pkcs11:token=fastpki;object=acme-tls;type=private?pin-source=/var/pki/tls/pin` | Server TLS key. A `pkcs11:` URI keeps it in the token, which is the default; a PEM path is the fallback. |
| `ACME_BASE_PATH` | string | `/acme` | Mounted under `BASE_URL`. |
| `NONCE_EXPIRES_SEC` | int | `300` | ACME replay-nonce lifetime, seconds (RFC 8555 §6.5). Read only by `fastpki-acme`. |
| `ORDER_EXPIRES_DAYS` | int | `7` | Order validity before finalization. |
| `ACME_DNS_RESOLVER` | string | *(empty)* | DNS-01 + CAA validator resolver, `host[:port]` — an IPv4 or IPv6 literal or a **name** (bracket a v6 literal to give it a port: `[::1]:5353`). Resolved and queried from inside `fastpki-acme`, so under compose or Kubernetes it must name something reachable on that container's own network; a resolver listening only on the docker host is not, and the unanswered query is reported as `dns-01 TXT record missing or mismatched`. Empty = `/etc/resolv.conf`. |
| `ACME_TLS_ALPN_PORT` | int | `443` | TLS-ALPN-01 verifier target port (RFC 8737). |
| `ACME_NEW_AUTHZ` | bool | `false` | Pre-authorization (RFC 8555 §7.4.1). |
| `ACME_CAA_IDENTITY` | string | *(empty)* | CAA issuer-domain-name. Empty = no CAA check. |
| `ACME_SWEEP_SEC` | int | `600` | Background sweep for expired nonces/orders. |

## 10. Notify (Expiry Notifications)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `NOTIFY_DAYS` | string | `30,14,7` | Comma-separated warning windows in days, in any order. `fastpki-notify` uses them when run without `--days`, and the console's Notifications preview shows the same buckets. |
| `NOTIFY_WEBHOOK` | string | *(empty)* | Webhook `fastpki-notify` posts the report to when run without `--webhook`. There is no default: empty, the tool only prints its report. A **secret**, shown as `(set)`: a Slack or Teams webhook URL lets whoever holds it post to the channel. |
| `NOTIFY_WEBHOOK_FORMAT` | string | `json` | What is posted, to the webhook and to every `--routes` target when run without `--webhook-format`: `json` (the report as a JSON document, for a generic receiver such as a script, Jira Automation or ServiceNow), `slack` (a Slack message) or `teams` (a Microsoft Teams Adaptive Card message). Slack and Teams refuse the `json` document. Any other value is refused. |

| `NOTIFY_EMAIL_FALLBACK` | string | *(empty)* | Address that receives the expiry emails for certificates whose owner has no address: a directory account without `mail`, an account with an empty Email field, a computer. Empty: those certificates are only in the report. |
| `SMTP_SERVER` | string | *(empty)* | The mail relay `fastpki-notify` emails certificate owners through, as `host` or `host:port` (an IPv6 address in brackets). The port defaults to 587 with `SMTP_TLS=starttls`, 465 with `tls` and 25 with `none`. Empty: no email. |
| `SMTP_TLS` | string | `starttls` | `starttls`: connect in plain text and require the relay to offer STARTTLS, or send nothing. `tls`: TLS from the first byte. With either, the relay's certificate and name are verified. `none`: a relay that speaks no TLS; refused while `SMTP_USER` is set, so a password is never sent unencrypted. Any other value is refused. |
| `SMTP_USER` | string | *(empty)* | Account the relay signs the notifier in with (AUTH PLAIN, or LOGIN when the relay offers only that). Empty: submit without signing in, as a relay that trusts this server's address expects. Must be empty with `SMTP_TLS=none`. |
| `SMTP_PASSWORD` | string | *(empty)* | Password for `SMTP_USER`. A **secret**, shown as `(set)` and never logged. |
| `SMTP_FROM` | string | *(empty)* | Sender address of the expiry emails. Required when `SMTP_SERVER` is set. |
| `SMTP_CA_FILE` | string | *(empty)* | PEM file of a CA to trust for the relay's certificate, in addition to the system trust store. |

`fastpki-notify` applies the `config` table on every run, so a value saved on the
console's **Notifications** page is used by the next run without restarting anything. The relay
keys are stored per node, like the rest of the `config` table; the email template is a
replicated table instead (`notify_templates`), edited on the same page.

## 11. Software Update

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `UPDATE_FEED_URL` | string | *(empty)* | Self-hosted JSON manifest override. Empty = the fastpki/fastpki GitHub releases. |
| `RELEASE_PUBKEY` | path | *(empty)* | PEM public-key file for artifact verification. |

The console's **Updates** page uses the `config` table's values. The `fastpki-update` CLI
reads both keys from `bootstrap.conf` only — it does not apply the table, and neither key is
read from the environment.

## 12. Discovery

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `DISCOVER_BIN` | string | `fastpki-discover` | Path/name of discovery scanner binary. |

## 13. CMP (RFC 4210/9810)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `CMP_BIND` | string | `::` | Bind address. The default is the IPv6 wildcard, which is DUAL-STACK: IPv6 clients and IPv4 ones (as IPv4-mapped addresses) both reach it. `0.0.0.0` serves IPv4 only. On a host whose IPv6 stack is disabled the wildcard falls back to `0.0.0.0` and logs that it did. |
| `CMP_PORT` | int | `8445` | Listen port. |
| `CMP_PATH` | string | `/cmp` | HTTP path for CMP transactions. |
| `CMP_EXTRACERTS_CA` | bool | `false` | Add the **issued certificate's** CA chain to a cert response. It does **not** govern message protection: the RA credential's issuer chain is sent unconditionally, because a response the client cannot authenticate is not a configuration choice. So with this `false` and an RA configured, the CA still appears in `extraCerts` whenever the RA and the leaf share an issuer. |
| `CMP_CLIENT_CA_ID` | CSV | *(empty)* | CA ids (`certs.id` where `is_ca`) to trust as client-cert anchors. |
| `CMP_CLIENT_CA_BUNDLE` | string | *(empty)* | Additional client-cert anchors as inline PEM. |
| `CMP_CLIENT_CA_REFRESH_SEC` | int | `20` | How often the client-auth trust store is re-read from the DB. |
| `CMP_RA_KEY` | path | *(empty)* | RA mode: signing key. Supports `pkcs11:` URI. |
| `CMP_RA_CERT_ID_PREFIX` | string | `cmp-ra` | Prefix for the RA certificate id in the `certs` table; the real id is `<this>-<ca_id>`. |
| `CMP_RESPONSE_MD` | str | – | Digest that protects a **signature-protected CMP response**, e.g. `sha384`, `sha512`. Governs the RA credential's own signature only: a client that authenticates with a shared secret gets a password-based MAC, whose one-way function and MAC are a different axis this key does not touch. Honoured for `rsa`/`rsa-pss` RA keys — EC auto-matches its curve, Ed25519/ML-DSA carry their own digest, and an RFC 4055 restriction published by the RA certificate always wins. An unknown or too-weak name falls back to the key's default rather than failing the message. |

## 14. MS-XCEP / MS-WSTEP

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `MS_BIND` | string | `::` | Bind address. The default is the IPv6 wildcard, which is DUAL-STACK: IPv6 clients and IPv4 ones (as IPv4-mapped addresses) both reach it. `0.0.0.0` serves IPv4 only. On a host whose IPv6 stack is disabled the wildcard falls back to `0.0.0.0` and logs that it did. |
| `MS_PORT` | int | `8446` | Listen port (HTTPS). |
| `MS_CERT` | path | *(empty)* | Server TLS cert **from a file**. **File-only.** Unset: the certificate is the `certs` row `MS_CERT_ID` names. A path here wins over that row and freezes the listener on whatever the file holds. |
| `MS_CERT_ID` | string | `ms` | Which CA-issued cert to serve from the `certs` table, by id. Set by default, so a DB-held certificate is the normal path and a file is the fallback. |
| `MS_KEY` | pkcs11 URI or path | `pkcs11:token=fastpki;object=ms-tls;type=private?pin-source=/var/pki/tls/pin` | Server TLS key. A `pkcs11:` URI keeps it in the token, which is the default; a PEM path is the fallback. |
| `XCEP_PATH` | string | `/msxcep` | MS-XCEP endpoint path. |
| `WSTEP_PATH` | string | `/mswstep` | MS-WSTEP endpoint path. |
| `MS_XCEP_GUID` | string | *(created per node)* | The `<policyID>` this node advertises in MS-XCEP `GetPolicies`. Blank by default: `fastpki-ms` creates a v4 GUID on first start and stores it in the **node-local** `config` table, so every DC gets its own. A shared id makes Windows treat two different DCs as the same enrollment policy and they collide in its policy cache. Set it only to pin a specific value. |
| `MS_XCEP_FRIENDLY_NAME` | string | `FastPKI Certificate Enrollment Policy` | The `<policyFriendlyName>` shown to Windows enrollment clients. |
| `MS_XCEP_NEXT_UPDATE_HOURS` | int | `24` | **Pending restart** — like every key here except the runtime switches, it is read once at startup and snapshotted, so changing it in the `config` table takes effect when `fastpki-ms` next starts. The `<nextUpdateHours>` in `GetPolicies` — how long a Windows client may keep using the policy it already fetched. ⚠️ **A template change is invisible to a client until this expires, and it fails silently**: the client builds from its cached copy, never contacts the server, and nothing reaches any log. Set it to `1` (or `0` for no caching) while developing templates. Clear an existing cache with `certutil -f -policyserver * -policycache delete`. |

## 15. RFC 4387 Certificate Store

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `STORE_BIND` | string | `::` | Bind address. The default is the IPv6 wildcard, which is DUAL-STACK: IPv6 clients and IPv4 ones (as IPv4-mapped addresses) both reach it. `0.0.0.0` serves IPv4 only. On a host whose IPv6 stack is disabled the wildcard falls back to `0.0.0.0` and logs that it did. |
| `STORE_PORT` | int | `8447` | Listen port. |

## 16. Web Console

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `WEB_BIND` | string | `::` | Bind address, like every other listener — the IPv6 wildcard, which is dual-stack and also accepts IPv4 as mapped addresses. `0.0.0.0` serves IPv4 only; a host with IPv6 disabled falls back to it with a log line. |
| `WEB_PORT` | int | `8090` | Listen port. |
| `WEB_TOKEN` | string | *(empty)* | Bearer token for API auth. |
| `WEB_TLS_CERT` | path | *(empty)* | Console TLS cert (optional). |
| `WEB_CERT_ID` | string | `web` | Which CA-issued cert to serve from the `certs` table, by id. Set by default, so a DB-held certificate is the normal path and a file is the fallback. |
| `WEB_TLS_KEY` | path | *(empty)* | Console TLS key (optional). |
| `WEB_CLIENT_CA_ID` | CSV | *(empty)* | mTLS: ids of registered CAs a console client cert must chain to. DB-first, the same shape as `EST_CLIENT_CA_ID`. |
| `WEB_CLIENT_CA_BUNDLE` | PEM | *(empty)* | mTLS: trust bundle for external client CAs not registered here, stored in the DB. |
| `WEB_CLIENT_CA` | path | *(empty)* | mTLS: a PEM **file** of the same thing. The last-resort fallback — setting a CA id here fails the listener. |
| `WEB_ALLOW_REVOKE` | bool | `true` | State-changing actions. Set false to pin an instance read-only. |
| `WEB_SELFSERVICE_IDENTITY_SUBJECT` | bool | `true` | For a certificate requested in the console (a pasted CSR, or a key generated in the HSM), bind the subject to the requester's identity: the CN becomes the user name, one OU is added per group of the session, and a directory or SSO identity adds its provider as a domainComponent. The other subject attributes stay as requested. The certificate profile decides whether it applies — a profile with `no_override_subject` keeps the requested CN, and the built-in `admin` profile sets it while `requester` does not. `false` keeps the requested subject under every profile. Enrolment protocols are not affected. |

## 17. MCP Server

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `MCP_ALLOW_WRITE` | bool | `false` | Offer the `revoke_certificate` tool. `fastpki-mcp` reads this from `bootstrap.conf` or the environment only; it does not apply the `config` table, so a row there has no effect. |

## 18. SSO — OIDC and SAML 2.0

**These are not configuration keys.** An identity provider is a row in `auth_providers`
(id, kind, display name, enabled, priority) plus a row in `saml_providers` or
`oidc_providers` carrying that provider's own settings, so one deployment can name several
providers at once.

Manage them on the console's **Directories** page, under *Federated sign-in*, or through
`/api/auth-providers` (`kind=saml` or `kind=oidc`). Both tables replicate to every node
like the rest of the configuration.

| Setting | Kind | Default | Meaning |
|---|---|---|---|
| `issuer` | OIDC | *(empty)* | IdP discovery base URL. |
| `client_id` | OIDC | *(empty)* | OAuth2 client ID. |
| `client_secret` | OIDC | *(empty)* | OAuth2 client secret. Write-only in the console. |
| `scopes` | OIDC | `openid email profile` | OAuth2 scopes. |
| `username_claim` | OIDC | `email` | JWT claim used as the local username. |
| `groups_claim` | OIDC | `groups` | JWT claim carrying group membership. |
| `ca_cert` | OIDC | *(empty)* | Path to a PEM file holding the trust anchor for the IdP's TLS certificate. The file is read by `fastpki-web`, so it must exist at that path on every node that serves the console. Empty = the system trust store. |
| `idp_entity_id` | SAML | *(empty)* | Expected `<Issuer>` (optional pin). |
| `idp_sso_url` | SAML | *(empty)* | IdP SSO endpoint (HTTP-Redirect binding). |
| `idp_cert` | SAML | *(empty)* | Path to a PEM certificate file whose key is pinned as the assertion-signature anchor. The file is read by `fastpki-web` at each sign-in, so it must exist at that path on every node that serves the console. Required. |
| `sp_entity_id` | SAML | — (required) | Our SP EntityID. |
| `username_attr` | SAML | *(empty)* | Attribute for the username; empty uses the NameID. |
| `groups_attr` | SAML | `groups` | Attribute carrying group membership. |
| `clock_skew_sec` | SAML | `120` | Tolerance for NotBefore/NotOnOrAfter. |
| `admin_group` | both | *(empty)* | Group membership mapping to the admin role. |
| `auditor_group` | both | *(empty)* | Group membership mapping to the auditor role. |
| `require_local_user` | both | `false` | Require a matching `web_users` row as well. |

An empty `scopes`, `username_claim`, `groups_claim` or `groups_attr` means "not set" and
falls back to the default above — it does not mean an empty scope list or a claim whose
name is the empty string.

There is no setting for the address the identity provider returns people to: each node uses its
own console address followed by `/api/oidc/callback` or `/api/saml/acs`
([authentication.md](authentication.md)).

## 19. SCEP (RFC 8894)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `SCEP_BIND` | string | `::` | Bind address. The default is the IPv6 wildcard, which is DUAL-STACK: IPv6 clients and IPv4 ones (as IPv4-mapped addresses) both reach it. `0.0.0.0` serves IPv4 only. On a host whose IPv6 stack is disabled the wildcard falls back to `0.0.0.0` and logs that it did. |
| `SCEP_PORT` | int | `8448` | Listen port. |
| `SCEP_PATH` | string | `/scep` | Base path; a CA is addressed at `<SCEP_PATH>/{ca_id}`. |
| `SCEP_DYNAMIC_CHALLENGE` | bool | `false` | Accept one-time tokens from `scep_challenges` table. |
| `SCEP_MANUAL_APPROVAL` | bool | `false` | Async PENDING enrollment. |
| `SCEP_RA_KEY` | path | *(empty)* | RA mode: message-layer key (`pkcs11:` URI). Setting it enables RA mode. |
| `SCEP_RA_CERT_ID_PREFIX` | string | `scep-ra` | `certs.cert_id` **prefix** for the per-CA RA certificate; the real id is `<this>-<ca_id>` and the certificate lives in the DB, resolved per request. There is no per-instance RA certificate path. |
| `SCEP_RENEWAL` | bool | `true` | Certificate renewal (RFC 8894 §3.3.2). |
| `SCEP_NEXT_CA_CERT` | path | *(empty)* | CA key rollover (RFC 8894 §3.5.3). |
| `SCEP_ALLOW_SHA1` | bool | `false` | Allow SHA-1 in GetCACaps. **File-only.** |
| `SCEP_ALLOW_DES3` | bool | `false` | Allow DES3 in GetCACaps. **File-only.** |
| `SCEP_RESPONSE_MD` | str | – | Digest the **CertRep SignedData** is signed with, e.g. `sha384`, `sha512`. The two rows above govern what a *client* may send; this is the server's own signature. Honoured for `rsa`/`rsa-pss` (and a SCEP RA key must be RSA anyway); an EdDSA/ML-DSA **CA** key signing GetNextCACert gets a null digest, as those schemes require. Unknown name → the key's default. |

## 20. LDAP (Auth Backend)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `DIRECTORY_GROUP_REFRESH_SEC` | int | `43200` | How often `fastpki-web` re-reads the member list of every group holding a console role, so a group edited in the directory is picked up without waiting for anyone to sign in again. 12 h by default. `0` (or any value below 1) starts no sweep: a group's members are then read when the group is first granted a role, when a granted group with no stored member list is first shown, and when an operator presses **↻** on the group's row on the **Users** page. The sweep runs only when a directory is configured, and a refresh the directory refuses keeps the previous member list rather than emptying the group. Read at startup. Set it on the **Config** page — it is a `config` table row, and nothing in `deploy/` writes it to a file. |

## 21. Issuance Policy & Constraints

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `CERT_VALIDITY_DAYS` | int | `730` | Default cert lifetime. |
| `CERT_SERIAL_BYTES` | int | `20` | Random serial number length. |
| `MIN_RSA_BITS` | int | `2048` | Minimum RSA key size. Applies to issued certificates **and** to a CA — created, or imported through the console. |
| `MIN_DSA_BITS` | int | `1024` | Minimum DSA key size. |
| `MIN_EC_BITS` | int | `256` | Minimum EC key size. Applies to CA keys as well as leaves. |

> **No issuance limit is a config key.** All three live on the role, as columns of
> `roles`, editable from the console's role editor under **Issuance limits**:
>
> | column | limits |
> |---|---|
> | `max_certs` | active certificates this SUBJECT may hold |
> | `max_cn` | active certificates for the requested NAME |
> | `max_san` | SubjectAltName entries in ONE certificate |
>
> They are replicated columns rather than settings, so one number reaches every data center.
> **NULL or 0 means the role sets no limit**, which is what every role ships with — a
> deployment that has never opened the role editor has no issuance limits at all. Where a
> subject holds several roles the **largest** number wins: holding one more role is never
> worse than holding one fewer.
>
> Every enrolment protocol and the console enforce all three from one shared helper
> (`pki::role_limits` + `pki::role_limit_refusal`) and encode the refusal their own way —
> EST and the console 429, CMP a PKIStatusInfo, MS-WSTEP a soap:Fault, ACME an RFC 8555
> `rateLimited` problem document, SCEP a CertRep with `badRequest`. SCEP applies them only
> to an enrolment whose per-user challengePassword names a user; a one-time token or a
> renewal names no subject and is not limited.

## 22. Domain & IP Restrictions

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ALLOWED_IPS_REGEX` | string | `^10\.(...)$` | ECMAScript regex an IP SAN must match. Default allows 10.0.0.0/8 only. **Empty = unrestricted**, matching the approved-domain list — it does not mean "refuse every IP SAN". |

## 23. Certificate Extension URLs

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `CRL_DPS` | csv | *(empty)* | CRL Distribution Points for certificates issued **without** a CA instance. Enrolment through a CA — every protocol — derives them per CA instead, one entry per data center from `datacenters.base_url`. |
| `AIA_CA_ISSUERS` | csv | *(empty)* | AIA caIssuers for the same non-CA-instance case as `CRL_DPS`. |
| `AIA_OCSP` | csv | *(empty)* | AIA OCSP responders for the same non-CA-instance case as `CRL_DPS`. |

## 24. Auth, Users & Profiles

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `AUTH_BACKEND` | string | `local` | `local` (the `web_users` table) or `ldap`. Any other value is refused at startup (see `docs/authentication.md`). |

**Certificate profiles are not a key.** They are rows of the replicated `cert_profiles` table,
written by the console's **Profiles** page and by `fastpki-config profiles-import` (see
[cli-reference.md](cli-reference.md)). A profile's definition is a JSON object whose keys
include `allowed_ku`, `allowed_eku`, `default_ku`, `default_eku`, `allow_wildcard`,
`custom_extensions` (what the profile stamps), `allowed_custom_extensions` (what a CSR may carry
in; `*` = any), `no_override_subject`, and `manage_aia` / `manage_crldp` (below); see
[components.md](components.md) for how a profile is applied.

**`manage_aia` / `manage_crldp`** — *"the requester MAY omit"*, not *"always omit"*.
When a profile sets one, the console's request form shows the matching **omit AIA** /
**omit CRL DP** checkbox and the server honours it for that request; when it does not, the
request's `omit_aia` / `omit_crldp` parameters are ignored and the extension is emitted as
usual. Neither half alone suppresses anything.

One such profile therefore serves both jobs: ordinary certificates, and an authorized OCSP
responder certificate, which carries neither AIA nor CRLDP (RFC 6960 §4.2.2.2.1).

⚠️ Enrolment protocols (EST, ACME, SCEP, CMP) have **no field to ask with**, so a
certificate issued over them always keeps AIA/CRLDP regardless of the profile. Only the
console request form can exercise this.

## 25. Logging

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `LOG_LEVEL` | string | `err` | `err` / `info` / `debug`. |

### Forwarding the audit log to a collector

There are two kinds of log here and they leave the machine by different routes.

**Container logs** — every binary writes to stderr and nothing else, so these are collected
by the container runtime: a Docker log driver, or a cluster log collector on Kubernetes.
That picks up Postgres and the token container too. `deploy/docker-compose.logging.yml`
is a ready overlay; apply it with `-f docker-compose.yml -f docker-compose.logging.yml`.

**The audit log** — a hash-chained table, not a text stream, so it needs a real shipper
that walks it in order and remembers where it got to. That is `fastpki-audit forward
--follow`, packaged as the `auditfwd` compose service (profile `auditfwd`). Run exactly
one per node: every service on a node writes into the same node-local `audit_log`, and the
position is a single row per destination, so two shippers against one database would send
the same rows twice. The audit log is not replicated between data centers, so each node ships
its own.

Where it got to is stored in `audit_forward_state`, keyed by destination. Restarting the
shipper therefore resumes rather than re-sending the whole log or skipping whatever arrived
while it was down. Pointing it at a different collector starts that collector from the
beginning instead of inheriting the previous one's position.

These settings are on the console's **Config -> Logging** page, and like every other
setting they live in the `config` table. Repoint a collector by editing the row there
rather than by rewriting a file on each node. The page marks a change "pending restart"
until the shipper itself has restarted; restarting a listener does not clear it, because
the shipper is the only process that reads these keys.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `AUDIT_FORWARD` | string | `off` | `off` / `syslog` / `hec`. An unrecognised value is refused at startup rather than treated as `off`. |
| `AUDIT_FORWARD_TARGET` | string | — | syslog: `host:port` (default port 514, or 6514 with TLS). HEC: the full collector URL, e.g. `https://splunk.example.org:8088/services/collector/event`. |
| `AUDIT_FORWARD_PROTO` | string | `tcp` | syslog only. `tcp` frames each message with its octet count (RFC 6587); `udp` sends one datagram per message and loses events with no way to find out, so it must be asked for by name. |
| `AUDIT_FORWARD_TLS` | bool | `false` | syslog only. Wraps the stream in TLS and **verifies** the collector — both the chain and the host name. |
| `AUDIT_FORWARD_TOKEN` | string | — | HEC authentication token, sent as `Authorization: Splunk <token>`. Never written to the log. |
| `AUDIT_FORWARD_CA_ID` | string | — | A registered CA id whose certificate anchors the collector's TLS certificate, for a collector that is not in the host trust store. Empty means the system trust store. |
| `AUDIT_FORWARD_INTERVAL_SEC` | int | `10` | How often `--follow` looks for new rows. |
| `AUDIT_FORWARD_BATCH` | int | `500` | Rows read per pass. HEC sends the whole batch in one request; syslog sends one message per row. |

---

## Environment Variable Override

Most keys can be set via an environment variable of the same name — 122 of the 154 the
parser knows. `Config::from_env()` (`src/lib/config.cpp`) is an **allow-list**: a key
outside it is read from the file or the database `config` table only. Setting one of these
in the environment has **no effect and raises no unknown-key error**, because the parser
that would object never sees it.

These **32** are file- or DB-only:

- transport certificates and keys — `EST_CERT`, `EST_KEY`, `ACME_CERT`, `ACME_KEY`,
  `MS_CERT`, `MS_KEY`
- the certificate-id settings — `WEB_CERT_ID`, `EST_CERT_ID`, `ACME_CERT_ID`,
  `MS_CERT_ID`, `CMP_RA_CERT_ID_PREFIX`
- `SCEP_ALLOW_SHA1`, `SCEP_ALLOW_DES3`, `ALLOW_WEAK_SIGNATURE_DIGEST`
- `ACME_CAA_IDENTITY`, `LOGIN_FAILURE_THRESHOLD`, `LOGIN_LOCKOUT_SEC`
- `NOTIFY_DAYS`, `NOTIFY_WEBHOOK`, `NOTIFY_WEBHOOK_FORMAT`, `OCSP_EXPIRY_SWEEP_SEC`
- `NOTIFY_EMAIL_FALLBACK`, `SMTP_SERVER`, `SMTP_TLS`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`,
  `SMTP_CA_FILE`
- `WEB_SELFSERVICE_IDENTITY_SUBJECT`, `DISCOVER_BIN`, `RELEASE_PUBKEY`, `UPDATE_FEED_URL`

⚠️ This list and the one in `deployment.md` are the same set, derived from the same
function. Nothing compares either list against `apply()` minus `from_env()`, so both are
maintained by hand: adding a key to the parser or to the allow-list means updating them.

## Bootstrap Keys

This key cannot be overridden by the DB `config` table — it must remain in `bootstrap.conf`
(it is how the server reaches that table in the first place):

- `PG_CONNINFO`

## Side-Effect Keys

- `PKI_DNS` — also sets `BASE_URL = "https://" + val` if BASE_URL is still default.
