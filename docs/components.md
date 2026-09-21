# Component reference

One section per binary: the endpoints it serves, the configuration keys that change its
behaviour, and the reasoning behind the defaults. This is the operator's view of each
component.

Two neighbouring documents cover the same protocols from other angles, and are usually
what you want instead: [`user-guide.md`](user-guide.md) for the *client* side of each
protocol with worked examples, and [`protocol-apis.md`](protocol-apis.md) for the
endpoint-by-endpoint API listing with status codes.

**Where the command-line examples are typed.** The `fastpki-*` tools are inside the image
on Docker Compose and Kubernetes, and on the host on a native install. The examples below
write `--config bootstrap.conf` for the configuration file of the deployment you are on.
On Docker Compose that means the in-image path, reached through a throwaway container:

```bash
cd deploy
docker compose run --rm --no-deps --entrypoint fastpki-config web \
    --config /app/config/bootstrap.conf list
```

On a native install and the cloud images, run the tool directly as the `fastpki` user with
`--config /etc/fastpki/bootstrap.conf`. [`admin-guide.md`](admin-guide.md) §1.4 gives the
wrapper for each deployment as a shell function, including Kubernetes.

## Contents

- [EST (`fastpki-est`)](#est-fastpki-est)
- [ACME (`fastpki-acme`)](#acme-fastpki-acme)
- [CMP (`fastpki-cmp`)](#cmp-fastpki-cmp)
- [MS-XCEP + MS-WSTEP (`fastpki-ms`)](#ms-xcep--ms-wstep-fastpki-ms)
- [RFC 4387 store (`fastpki-store`)](#rfc-4387-store-fastpki-store)
- [SCEP (`fastpki-scep`)](#scep-fastpki-scep)
- [Expiry notifications (`fastpki-notify`)](#expiry-notifications-fastpki-notify)
- [Certificate discovery (`fastpki-discover`)](#certificate-discovery-fastpki-discover)
- [Web management UI (`fastpki-web`)](#web-management-ui-fastpki-web)
- [Multi-data-center active-active replication (`fastpki-mesh`)](#multi-data-center-active-active-replication-fastpki-mesh)
- [MCP server (`fastpki-mcp`)](#mcp-server-fastpki-mcp)
- [PKCS#11 HSM / smart-card CA key](#pkcs11-hsm--smart-card-ca-key)
- [Multi-CA / multi-root control plane](#multi-ca--multi-root-control-plane)

## EST (`fastpki-est`)

Endpoints under `/.well-known/est/{ca_id}/` — every EST request names a CA; the
id-less base paths answer `404`:

| URI | Method | Auth | Behaviour |
|-------------------|--------|------|-----------|
| `cacerts` | GET | none | PKCS#7 certs-only with signing CA + root |
| `csrattrs` | GET | none | RFC 7030 §4.5 CSR attributes (`EST_CSRATTRS` OIDs; 204 when unset) |
| `simpleenroll` | POST | yes | PKCS#10 CSR → issues cert → PKCS#7 certs-only |
| `simplereenroll` | POST | yes | renews an **existing** cert — requires a valid cert for the CSR subject (RFC 7030 §4.2.2) |
| `serverkeygen` | POST | yes | **off by default, discouraged** — server generates the key (see below) |

**Server-side key generation (`serverkeygen`, RFC 7030 §4.4).** Disabled by
default (`EST_SERVERKEYGEN=false`) and **not recommended** — a client should
generate its own key. When explicitly enabled, the server generates the key,
issues the cert, and returns both in a `multipart/mixed` reply. **The private key
is never stored** (no DB row, no log) — it exists only to encode the response —
and by default it is returned **encrypted** (`EST_SERVERKEYGEN_ENCRYPT=true`): a
CMS `EnvelopedData` to the public key in the client's CSR, which the client
decrypts with the key it signed the CSR with. Set `EST_SERVERKEYGEN_ENCRYPT=false`
only for a client that cannot decrypt CMS. `EST_SERVERKEYGEN_BITS` sizes the RSA
key (default 2048). **Key archival is intentionally not implemented.**

**EST is HTTPS-only** (RFC 7030 §3.3): `fastpki-est` terminates TLS itself via
`EST_CERT` / `EST_KEY` (it does **not** run plain HTTP). Behind a reverse proxy,
either re-encrypt to it or use L4 passthrough.

Auth (precedence highest first):
1. RFC 7030 §3.3.2 **client certificate**, verified by fastpki-est's own TLS stack against
 `EST_CLIENT_CA_ID` / `EST_CLIENT_CA_BUNDLE`. The identity is the verified peer's CN.
 ⚠️ The client certificate is verified by this service itself — there is no way to
 assert an identity through a request header. **A proxy in front of EST must forward TCP
 without terminating TLS.**
2. HTTP Basic — `Authorization: Basic <b64>`, validated by `pki::authenticate`
 against the `AUTH_BACKEND` (`local` = the `web_users` table, which is what the shipped
 compose sets, or `ldap`). See "Users & authentication".

There is no third mechanism. Authorization comes from roles, profiles and templates —
never from a global list of privileged usernames. A certificate profile comes from the
identity's `profile:use` grants (see "Certificate policy profiles").

### Verifying EST

EST is HTTPS, so use `https://` (and `-k` against a self-signed `EST_CERT`):

```bash
# cacerts — should print two certs (signing CA + root)
curl -sk https://localhost:8443/.well-known/est/{ca_id}/cacerts \
 | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs

# simpleenroll — RFC 7030 body is base64 DER PKCS#10
openssl req -new -newkey rsa:2048 -nodes -keyout client.key \
 -subj "/CN=test.example.org" -out client.csr
openssl req -in client.csr -outform DER | openssl base64 > client.b64
curl -sk -u alice:test \
 --data-binary @client.b64 \
 -H "Content-Type: application/pkcs10" \
 https://localhost:8443/.well-known/est/{ca_id}/simpleenroll \
 | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs
```

### EST issuance policy

Issuance runs through `pki::enforce_issuance_policy` (`src/lib/policy.cpp`), which
every issuing path shares:

- **Key-size floor** — RSA ≥ 2048, DSA ≥ 1024, EC ≥ 256 bits (`MIN_*_BITS`).
- **Approved-domain allowlist** — the CN and every DNS SAN must match a suffix in
 the `allowed_domains` table (the sole source; manage it in the console
 or with `fastpki-config domains-import`). **The table ships empty, and an empty
 table means any name is accepted** — issuance is still gated by auth, the profile,
 key sizes and SAN types, but not by name. Add domains when you want a deployment
 confined to names you own. This applies on every path that has no proof of control
 of its own: the console, EST, CMP, SCEP and MS-WSTEP. ACME names are proven by
 challenge instead and skip the allowlist by design.
- **Wildcards** are accepted only when the cert policy profile allows it
 (built-in `admin` does, `requester` does not — see below).
- **SAN allowlist** — email / DNS / IP SANs are checked against the profile's
 permitted GeneralName types; IP SANs must match `ALLOWED_IPS_REGEX` (default
 10.0.0.0/8). The COUNT is capped by `roles.max_san` on the requester's role —
 there is no global setting for it, so a deployment
 that sets no number on any role has no SAN count limit.
- **KU / EKU** come from the cert policy profile (see below), not a fixed set.
- The `owner` (authenticated username) is recorded in the DB `owner` column.

### Certificate policy profiles

A **profile** declares which CSR-requested attributes the CA will honor
(`include/pki/cert_profile.hpp`, `src/lib/cert_profile.cpp`). At issuance
(`pki::evaluate_profile_extensions`):

- **KeyUsage.** The bits the CSR requests are checked against the profile's
  `allowed_ku`; a bit the profile does not allow is **dropped** and the rest are issued.
  If the CSR requested bits and none of them is allowed, the request is **refused**,
  because a KeyUsage extension with no bit set is not valid (RFC 5280 §4.2.1.3). A CSR
  that requests no KeyUsage gets the profile's `default_ku`, filtered the same way.
  `keyCertSign` and `cRLSign` are ordinary entries of the list: `admin` allows them and
  `requester` does not.
- **ExtendedKeyUsage.** The purposes the CSR requests are checked against `allowed_eku`
  (`*` allows any) and a purpose the profile does not allow is **dropped**. If none is
  left, the certificate carries no ExtendedKeyUsage extension; the request is not
  refused. A CSR that requests none gets `default_eku`. Purposes are compared by OID, so
  `serverAuth`, `TLS Web Server Authentication` and `1.3.6.1.5.5.7.3.1` are the same
  entry.
- **Implied KeyUsage.** `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`,
  `timeStamping`, `OCSPSigning`, `cmcRA` and the Microsoft Certificate Request Agent
  purpose add `digitalSignature` when the profile allows that bit and the request lacks
  it.

A profile also controls whether **wildcards** are allowed, which **SAN types** are
permitted, an optional **validity cap**, which CSR-supplied **custom extensions** may be
carried through (`allowed_custom_extensions`; `*` means any), whether the console keeps
the requested subject (`no_override_subject`, see "Context-aware CSR mapping") and
whether it may issue a CA certificate (`allow_ca`). These are profile settings, not
compiled-in policy.

Two built-ins ship, named after the roles that hold them (`builtin_profile_default` in
`src/lib/cert_profile.cpp`):

| | `requester` | `admin` |
|---|---|---|
| allowed KU | `digitalSignature`, `nonRepudiation`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `encipherOnly`, `decipherOnly` | the same plus `keyCertSign`, `cRLSign` |
| allowed EKU | `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `OCSPSigning`, `cmcRA`, `ipsecIKE`, `msSmartcardLogin`, `1.3.6.1.4.1.311.20.2.1` (Certificate Request Agent) | `*` (any) |
| default KU | `digitalSignature` | *(none)* |
| default EKU | *(none)* | *(none)* |
| wildcards | no | yes |
| SAN types | dns, ip, email, uri | + othername |
| may omit AIA / CRL DP (`manage_aia`, `manage_crldp`) | no | yes |
| custom extensions from the CSR | none | `*` (any) |
| keeps the requested subject in the console (`no_override_subject`) | no | yes |
| may issue a CA certificate (`allow_ca`) | no | yes |
| validity cap | none | none |

Both are editable and clonable in the console, and neither can be deleted. An edited
built-in is stored as a row of `cert_profiles` and wins over the shipped definition; an edit
back to the shipped definition removes the row.
Which profiles a subject may issue under is a role permission (`profile:use`, scoped to
the profile name), managed on the **Roles** tab.

Profiles live in the `cert_profiles` table, one row per profile holding its definition as
JSON, and that table is **replicated** (last-writer-wins, like `ms_templates`) because the
role grants naming a profile replicate too. `pki::load_cert_profiles` fills
`Config::cert_profiles` from it after the config overlay: each enrolment service once at
start, the console before every profile read, write and issuance, so it follows edits made on
another node or with `fastpki-config`. A row that does not parse is logged and skipped. The
console's **Profiles** page writes one row per save; `fastpki-config profiles-import` takes a
JSON object of profiles, the same shape `profiles-export` prints and the backup carries:

```json
{"tls-client":{"allowed_ku":["digitalSignature"],"allowed_eku":["clientAuth"],"default_ku":["digitalSignature"],"default_eku":["clientAuth"],"allow_wildcard":false,"allowed_san_types":["dns","email"],"max_validity_days":90}}
```

**Binding profiles to identities.** A profile is a **permissioned resource**,
not a row in a mapping table. A role holds `profile:use` (may issue under it) or
`profile:edit` (may change it) on a profile named in `role_permissions.scope`, and
`*` means every profile that exists. The two are separate: `profile:edit` does **not**
entitle a subject to issue under a profile, which is how the built-in `admin` edits every
profile while issuing under `admin` alone (see [rbac.md](rbac.md) §5). What a subject may
issue under is the **union** of its `profile:use` grants over every role it holds — its own
`web_users.role` plus every role `subject_roles` binds to its user name or to one of its
directory groups.

`pki::profiles_for_identity` builds that union and `pki::resolve_profile` answers
with it (`src/lib/cert_profile.cpp`):

1. the union is **empty** → **refused**: the identity holds no profile permission;
2. a **request** for a profile in the union is honoured, and that profile applies alone;
 one outside the union is refused;
3. no request and exactly one member → it;
4. no request and several members → their **merge**, returned as a profile named
 `a+b` and passed to issuance as `profile_override`:
 - every **allowance** is the union: allowed KU and EKU, SAN types, wildcards, custom
   extensions the CSR may carry, `manage_aia`/`manage_crldp`, `no_override_subject`,
   `allow_ca`, and the widest `max_validity_days` and `max_path_len`;
 - every **default** (default KU and EKU, `validity_days`, stamped `custom_extensions`) is
   the members' common value; where they differ, the member named after the subject's
   **primary** role (the role it authenticated with, else its `web_users.role`) decides;
   where that is not a member either, the default is left undecided, and
   `evaluate_profile_extensions` refuses a request that relies on it, naming what differs.
   EST's `csrattrs` hint is left empty instead.

Not-allowed attributes are dropped, as for a single profile. There are no priorities, and
no role other than the primary one breaks a tie. Crucially the **CSR subject is never a selector** — only
attributes the server authenticated — so a requester cannot pick a privileged profile by
crafting their CSR. How each path supplies the identity, and whether it can name a
profile:

| Path | Identity the profile is resolved for | Can name a profile |
|---|---|---|
| Console request | the signed-in user and the session's groups | yes on the key-in-browser and CSR forms (`profile`); the key-in-HSM form displays the resolved profile |
| EST | the authenticated user and its directory groups | no |
| CMP | the authenticated sender and its directory groups | yes, `certProfile` in the header (OpenSSL ≥ 3.5) |
| ACME | the user the account's External Account Binding names | no |
| SCEP, per-user challengePassword | the user the challenge names | no |
| SCEP, one-time token | the `scep` subject | the profile the token was created for |
| SCEP renewal | the owner of the certificate being renewed | no |
| EST device self-renewal (a caller without `est:enrol` presenting its own unrevoked client certificate and asking for the same identity) | none: the certificate is issued under a profile read off the certificate it renews, which allows no more than that certificate carries | no |

A one-time SCEP token, and a request approved from the manual-approval queue, resolve
against a subject named `scep`, so a role granting `profile:use` must reach that name —
through a `web_users` row called `scep` or a `user` binding in `subject_roles`.
`fastpki-scep --issue-challenge` refuses to create a token for a profile that subject may not use.

**MS-WSTEP issues under a template, not a profile.** The requested certificate template
is checked against the caller's `template:use` grants and converted into the policy the
certificate is issued under, so a profile grant has no effect there.

**Console UI.** The **Profiles** tab defines the profiles themselves — a form for the
KU/EKU/SAN/wildcard/validity fields, saved as that profile's row in `cert_profiles`, which the
enrolment services read at startup. *Who may issue under one* is set on the **Roles** tab
instead, as a `profile:use` permission scoped to the profile's name. `GET|POST|DELETE
/api/profiles` needs `profile:edit` (scoped to the profile being written), mutations also
need `WEB_ALLOW_REVOKE`, and changes are audited.

**`owner` is not embedded in the subject DN** (some implementations write `owner=<user>`
into the subject). It is stored in the `owner` column and carried in a Subject Directory
Attributes extension.

## ACME (`fastpki-acme`)

An ACME client registers an account (with the mandatory External Account Binding), creates
an order, completes an HTTP-01 **or DNS-01** challenge, finalizes, downloads a PEM chain,
revokes, and rolls over its account key.

ACME is **HTTPS-only** (terminates its own TLS via `ACME_CERT`/`ACME_KEY`). The
directory advertises endpoints under `BASE_URL` when set (production, behind a
proxy); otherwise it reflects the request's `Host` header, so it works on whatever
address/port it's reached on. `X-Forwarded-Proto` chooses the scheme, but only when the
request comes from an address named in `TRUSTED_PROXIES`; from anywhere else the header is
ignored and the scheme is `https`. `BASE_URL` is the answer for a deployment that
terminates TLS at a proxy.

What works — every path below sits under the CA's own prefix, `<ACME_BASE_PATH>/{ca_id}`
(for example `/acme/issuing-ca/directory`); the id-less paths answer `404`:

- `GET /acme/{ca_id}/directory` → JSON of endpoint URLs + `meta`.
- `GET /acme/{ca_id}/new-nonce`, `HEAD /acme/{ca_id}/new-nonce` → 204 + `Replay-Nonce`.
- `POST /acme/{ca_id}/new-account` → JWS verify (ES256 / RS256), nonce
 consumption, RFC 7638 JWK thumbprint, account create-or-fetch.
- `POST /acme/{ca_id}/new-order` → creates order + one authz per identifier +
 one HTTP-01 challenge per authz. Returns 201 with `Location`.
- `POST /acme/{ca_id}/order/<id>` (POST-as-GET) → order JSON.
- `POST /acme/{ca_id}/authz/<id>` → authz JSON; also accepts
 `{"status":"deactivated"}` payload.
- `POST /acme/{ca_id}/chall/<id>` → marks the challenge `processing`, returns
 200, and **spawns a detached worker thread** that fetches
 `http://<identifier>/.well-known/acme-challenge/<token>` and compares
 to `token + "." + thumbprint(account jwk)`. On success: drops sibling
 challenges, marks authz valid, and if all authz of the order are valid
 marks the order `ready`.
- `POST /acme/{ca_id}/order/<id>/finalize` → decodes the CSR from the base64url payload and
 issues the certificate from the order's CA.
- `POST /acme/{ca_id}/cert/<serial>` → returns
 `application/pem-certificate-chain`: the leaf, then the issuing CA's certificates and its
 ancestors, all read from the database.
- `POST /acme/{ca_id}/new-account` with **External Account Binding** — the directory
 always advertises `externalAccountRequired`
 and newAccount must carry an EAB JWS (HS256 HMAC) keyed by `kid` in the
 `keys` table. `verify_eab` checks the MAC, that the inner payload equals the
 account JWK, and the URL binding. See "ACME accounts" below.
- `POST /acme/{ca_id}/revoke-cert` — RFC 8555 §7.6. Verifies the signer is the account
 that owns the cert or the certificate key itself, then marks
 `certs.status = -1`.
- `POST /acme/{ca_id}/account/<id>` — account deactivation / unregister.
- `POST /acme/{ca_id}/key-change` — RFC 8555 §7.3.5 account key roll-over: verifies the
 inner JWS (new key) and its `account`/`oldKey` bindings, then swaps the
 account JWK + jwk_hash. Rejects a new key already in use (409).
- **DNS-01 challenge** — RFC 8555 §8.4. Each authz offers `dns-01` (and
 `http-01` for non-wildcards; wildcards get `dns-01` only). The verifier looks
 up the TXT record at `_acme-challenge.<domain>` via a small built-in UDP
 resolver and checks it equals `base64url(SHA256(key authorization))`. Point it
 at a specific resolver with `ACME_DNS_RESOLVER` (default: system).

### Verifying ACME

```bash
# Directory
curl -sk https://localhost:8444/acme/{ca_id}/directory | jq

# Get a nonce
curl -ik https://localhost:8444/acme/{ca_id}/new-nonce

# Full flow — use a real ACME client pointed at the directory URL. The
# server hands out http-01 challenges, so the certbot machine has to be
# reachable on port 80 from the ACME server's network:
certbot certonly \
 --server https://localhost:8444/acme/{ca_id}/directory \
 --standalone -d host.example.org --no-eff-email \
 --register-unsafely-without-email
```

## CMP (`fastpki-cmp`)

Built entirely on OpenSSL 3.x's server-side CMP API
(`OSSL_CMP_SRV_CTX`). OpenSSL owns the PKIMessage wire format, header/body
construction, response protection, transaction state, and nonce handling.
FastPKI supplies two callbacks and the HTTP transport.

Endpoints: `POST /cmp/{ca_id}` and the standardized **`POST /.well-known/cmp/{ca_id}`**
(RFC 6712 / RFC 9483 §6) — the CA instance is a trailing path segment, mirroring EST's
inline label. The id-less `/cmp` and `/.well-known/cmp` answer `404`.
`Content-Type: application/pkixcmp`, matched per RFC 7231 — case-insensitive and
ignoring parameters, so `application/pkixcmp; charset=…` is accepted.

What works:

- **Certificate request** — `ir` / `cr` / `p10cr` / `kur`. The
 `cert_request_cb` extracts subject + public key + extensions from either
 the CRMF template (`OSSL_CRMF_CERTTEMPLATE_get0_*`) or a PKCS#10 CSR, then
 calls `pki::issue_cert_from_parts` / `pki::issue_cert`, persists the row
 (status = pending certConf), and returns an `accepted` PKIStatusInfo.
- **Revocation** — `rr`. The `rr_cb` normalizes the serial, checks the reason with
 `pki::revocation_reason_refusal`, and calls `pki::Db::revoke_cert`, answering `certRevoked`
 when the certificate is already revoked.
- **Transport** — `d2i_OSSL_CMP_MSG` → `OSSL_CMP_SRV_process_request` →
 `i2d_OSSL_CMP_MSG`.

### What CMP covers

ir/cr/kur/p10cr issuance, rr revocation, certConf and genm (which returns the CA
certificates). **Request-protection validation is unconditional** — the server is fail
closed and validates per-user PBM (the `keys` table) and client-certificate signature
(`CMP_CLIENT_CA_ID`) authentication.

Five features are handled by decoding the request directly (`lib/cmp_asn1`), because
OpenSSL's CMP **server** API does not expose these fields:

1. **Per-user authorization.** Revocation (`rr`) must be
 **signature-protected** (PBM is for enrollment only, and unprotected `rr` is
 refused), and a caller may revoke **only certs it owns** unless one of its roles
 grants `cert:revoke` for that CA. The caller is the validated
 signer: OpenSSL verifies the protection, and we take the header `sender` CN
 only after confirming it matches a cert in the request's `extraCerts`
 (anti-spoof). The cert's `owner` is likewise set from the validated sender at
 issuance.
2. **Per-user PBM secrets.** When a request carries a `senderKID`
 (the RFC 4210 reference), `fastpki-cmp` decodes it from the raw message
 (`pki::parse_cmp_request`) and keys the `keys`-table lookup on it, applying
 that user's secret for the request and clearing it afterwards, so it cannot
 authenticate the next one. An unknown reference gets no secret and is refused
 — there is no global to fall back to.
3. **Revocation reason.** The `rr` `CRLReason` is parsed from the
 request's `RevDetails.crlEntryDetails` and recorded on the cert.
4. **Pending until certConf.** Certs are persisted pending (status 2; OCSP
 `certificateHold`) and flipped to valid only when the client's `certConf`
 confirms them — unless the client requested implicit confirmation (detected
 from the header `generalInfo` via `pki::parse_cmp_request`), in which case no
 `certConf` follows and the cert is valid at once. A rejecting `certConf`
 revokes it.
5. **`extraCerts` / `caPubs`.** Honour `CMP_EXTRACERTS_CA` and optionally put
 the root CA in `caPubs`.

### RFC 9810 (CMPv3) conformance

RFC 9810 obsoletes RFC 4210; since the wire format is OpenSSL's, conformance is
mostly about our transport + support-message surface, scoped to the **Lightweight
CMP profile (RFC 9483)**:

- **Standardized HTTP endpoint** `/.well-known/cmp/{ca_id}` (RFC 6712/9483) alongside the
 configurable `CMP_PATH`, whose per-CA form is `/cmp/{ca_id}`.
- **RFC 7231 Content-Type matching** — the media type is compared
 case-insensitively with parameters ignored, so a conformant client sending a `charset`
 is accepted.
- **genm support messages** — we answer the requested infoTypes: `id-it-caCerts`
 (signing CA), **`id-it-rootCaCert`** (the configured root, §5.3.19), and — on
 OpenSSL ≥ 3.5 — **`id-it-crlStatusList → id-it-crls`** (Get CRLs, RFC 9483
 §4.3.4), returning this CA instance's current CRL. A bare `genm` defaults to
 caCerts.
- **`certProfile`** (RFC 9483) — a client may name a profile in the request
 header (`openssl cmp -profile`); the server honors it **only if the identity is
 assigned that profile** (no escalation — see the cert-policy-profiles section),
 else rejects. OpenSSL ≥ 3.5.
- **Central key generation refused** — a `-centralkeygen` request is detected and
 rejected (no server-side key generation). OpenSSL ≥ 3.5.

The OpenSSL-3.5-gated items above need OpenSSL 3.5: its CMP API is the one that
exposes them. Out of scope: **PBMAC1** protection (RFC 9579) and **genm
`certReqTemplate`**, neither of which OpenSSL's CMP API exposes. The supported
operations are pvno-2 messages, so no pvno-3 handling is required.

### OpenSSL version requirement

CMP needs the CRMF template public-key accessor
(`OSSL_CRMF_CERTTEMPLATE_get0_publicKey`), which requires **OpenSSL ≥ 3.2**.
The CMake build gates `fastpki-cmp` on this; on an older OpenSSL the target is
skipped. OpenSSL 3.5 is the supported baseline; the target also builds on 3.2–3.4.

### Verifying CMP

```bash
# OpenSSL 3's built-in CMP client. `-newkey` loads a key file, so generate one first.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client.key

openssl cmp -cmd ir \
  -server http://localhost:8445/cmp/{ca_id} \
  -recipient "/CN=signing-ca" \
  -trusted ca-chain.pem \
  -ref alice -secret "pass:$CMP_SECRET" \
  -newkey client.key -subject "/CN=test.example.org" \
  -certout issued.pem
```

Every request is protected: `-ref` is a username and `-secret` that user's CMP secret from
the console's Enrolment credentials page; a client certificate (`-cert`/`-key`) is the
other accepted form. `-trusted` anchors the RA-protected response.

## MS-XCEP + MS-WSTEP (`fastpki-ms`)

Both SOAP 1.2 protocols share one listener.
**HTTPS-only** (`MS_CERT`/`MS_KEY`): Windows enrollment clients require TLS —
`certreq`/`certlm.msc` reject plain-HTTP policy servers outright.

| Path | Protocol | Behaviour |
|-------------|-----------|-----------|
| `/msxcep/{ca_id}` | MS-XCEP | `GetPolicies` → `GetPoliciesResponse` built from the `ms_templates` table, or the built-in GenericUser, Email and GenericComputer when it holds no enabled row. |
| `/mswstep/{ca_id}` | MS-WSTEP | `RequestSecurityToken` carrying a base64 PKCS#10 → extract CSR, authenticate (Kerberos / Basic / `UsernameToken`), issue a cert, return it as an X.509 `BinarySecurityToken`. |

### MS-WSTEP authentication (Kerberos SSO + fallback matrix)

The WSTEP endpoint accepts three credential types, tried in order:

1. **Kerberos / SPNEGO** — `Authorization: Negotiate`. With a service keytab
 (a keytab uploaded for the directory) the server verifies the client's Kerberos ticket via
 GSSAPI and maps the principal (`user@REALM`) to the issuance owner/role, so
 domain-joined Windows clients enroll **passwordlessly**. Built in by default and
 linked against MIT krb5 GSSAPI.
2. **HTTP Basic** — `Authorization: Basic`, checked against the password backend
 (local / LDAP), same as EST.
3. **WS-Security `UsernameToken`** in the SOAP body.

When all fail the response depends on what was offered. A Basic or Kerberos attempt
gets a `401` advertising `WWW-Authenticate: Basic`, plus `Negotiate` **only when a
keytab is loaded for an enabled directory** — a deployment with no keytab never offers
Kerberos, which is why a Windows machine reports `WS_E_SERVER_REQUIRES_BASIC_AUTH`. A
WS-Security `UsernameToken` that fails is answered instead with a SOAP
`FailedAuthentication` fault carrying HTTP 500, and no `WWW-Authenticate` header at all.

The SOAP envelopes are built directly rather than generated from the WSDLs, and incoming
XML is matched by local name, so a namespace prefix does not matter. **WS-Security
response signing is not implemented** — a client that requires a signed response is
unsupported.

**Certificate templates from AD.** The templates `GetPolicies` advertises are not
hard-coded. They live in the `ms_templates` DB table, and there are **two ways to get them
there** — read them out of the directory, or import a file.

*From the directory, over LDAP.* The console's **Templates** tab has an AD import that
reads `pKICertificateTemplate` objects from every **enabled** LDAP directory
(`GET /api/templates/ad`), lists what it found, and imports the ones chosen
(`POST /api/templates/ad`). Prefer this path. Two things about it matter: it needs a
directory configured on the **Directories** page, since it reads through the same
`ldap_providers` rows the authentication backend uses; and on import the **server re-reads
the templates from AD itself** rather than storing what the browser sent, so choosing a
subset cannot become a way to write a template of the browser's composition.

*From a CSV.* The CSV is FastPKI's own format, not an export Active Directory or
`certutil` produces, so a file from the AD side has to be rewritten into it. Import it
with `fastpki-config --config bootstrap.conf templates-import <file.csv>` or
by pasting it into the console (`POST /api/templates/import`). The first non-comment line
is a header naming the columns, and the column names are the template's field names:
`name`, `oid`, `schema`, `enroll`, `auto_enroll`, `validity_days`, `min_key_size`,
`key_spec`, `key_usage`, `major_rev`, `minor_rev`, `private_key_flags`,
`subject_name_flags`, `enrollment_flags`, `general_flags`, `pk_oid`, `pk_name`,
`hash_oid`, `hash_name`, `crypto_providers`, `ekus`, `private_key_permissions`,
`overlap_seconds`, `enabled`. `ekus` and `crypto_providers` are `|`-separated in-cell;
lines starting with `#` are skipped. `name` and `oid` are required and a missing column
takes the default. Use this when the CA cannot reach the directory, or when the templates
are being edited before they land.

`templates-list` and `templates-delete` manage the table from the CLI. `fastpki-ms` reads
the table at startup: it serves the enabled rows when there is at least one, and the three
built-in defaults (GenericUser / Email / GenericComputer) when there is none. The **Templates** tab
covers list, add/edit and delete as well as both imports, and is gated on the
**`template:edit`** capability, which a custom role can hold without reaching any other admin
surface.

**Per-CA enrolment endpoints in the policy.** Everything the
`GetPoliciesResponse` `<cAs>` block says about a CA is per-CA data in the DB, not a
literal: `ca_xcep_uris` carries one row per advertised `<cAURI>` — its `uri`,
`clientAuthentication` (1 anonymous / 2 Kerberos / 4 username+password / 8 X.509),
`priority` and `renewalOnly` — and the CA row's `ms_enroll_permission` carries
`<enrollPermission>`. `xcep.xsd` allows 1..n URIs per CA, so a CA can advertise a
load-balanced pair, or an anonymous renewal-only endpoint beside a
username+password one. A blank `uri`, and a CA with no rows at all, advertises this
server's own `/mswstep/{ca_id}` derived from the host the client reached — so a new
CA is enrollable with no configuration. **Every** `crypto_providers` entry of a
template is emitted, and the SDDL `private_key_permissions`
(msPKI-Private-Key-Security-Descriptor) is carried through to
`<privateKeyAttributes><permissions>`. Edit in the console's CA
detail panel or over `GET`/`POST /api/ca-instances/{id}/xcep`.

## RFC 4387 store (`fastpki-store`)

`GET /certificates/search?<attr>=<value>` over `pki::Db::search_certs`.
Supported attrs: `certHash` (→ fingerprint), `name` (→ subject), `cn`,
`serial`, `sHash`, `iHash`, `iAndSHash`, `sKIDHash`, and `uri` — a
SubjectAltName URI, matched through the `cert_uris` table indexed at
issuance. Single match → DER
(`application/pkix-cert`); multiple → PKCS#7 bundle. `GET /crls/search?iHash=<hash>`
(or `?sKIDHash=<hash>`) picks a registered CA by hash and returns that CA's current
CRL (`application/pkix-crl`); exactly one of the two selectors is required.
`fastpki-ocsp` serves the same CRL at `/{ca_id}.crl`.

```bash
curl "http://localhost:8447/certificates/search?cn=test.example.org" \
 -o cert.der && openssl x509 -in cert.der -inform DER -noout -text
```

## SCEP (`fastpki-scep`)

SCEP (RFC 8894) enrolls legacy network devices (Cisco, MDM, etc.). It runs over
**plain HTTP** — all security is in the CMS (PKCS#7) message layer — and exposes
one endpoint per CA — `<SCEP_PATH>/{ca_id}`, e.g. `/scep/issuing-ca`. The bare
`SCEP_PATH` answers 404 ("this endpoint is per-CA"); it is a prefix, not a working URL.
Requests are routed
on the `operation` query parameter:

- `GET ?operation=GetCACert` → the signing CA certificate (DER,
 `application/x-x509-ca-cert`) — the cert clients encrypt PKIOperation
 envelopes to.
- `GET ?operation=GetCACaps` → capability list. `POSTPKIOperation`, `SHA-256`,
 `AES` and `SCEPStandard` are always advertised; `SHA-1` and `DES3` are added
 only by `SCEP_ALLOW_SHA1` / `SCEP_ALLOW_DES3` (both off by default), `Renewal`
 by `SCEP_RENEWAL` (default true), and `GetNextCACert` once `SCEP_NEXT_CA_CERT`
 names a rollover certificate.
- `POST ?operation=PKIOperation` (or `GET …&message=<base64>`) → a SCEP
 `pkiMessage`.

`PKIOperation` (PKCSReq) pipeline: verify the outer SignedData, read the SCEP
authenticated attributes (`messageType`, `transactionID`, `senderNonce`),
decrypt the inner EnvelopedData with the CA key to recover the PKCS#10, validate
the **challengePassword** (per-user, or a one-time token), issue through the shared
`pki::issue_cert` (so RBAC/validity/audit match EST), then return a **CertRep**:
the issued cert as a degenerate certs-only PKCS#7, encrypted to the requester's
cert and signed by the CA, with `pkiStatus` SUCCESS/FAILURE + nonces.

Config: `SCEP_BIND` / `SCEP_PORT` (default 8448), `SCEP_PATH`. Front it with
the reverse proxy like the other binaries.

**The challengePassword is PER USER.** There is no deployment-wide challenge setting.
The value is `"<user>:<secret>"`, created with the user's role
alongside their CMP and ACME credentials, and shown in the console under Users. It names
a `web_users` row, which is what makes `scep:enrol` enforceable and lets one device's
access be revoked without rotating a secret shared by all of them. A challengePassword is
never optional.

**Dynamic challenge tokens:** set `SCEP_DYNAMIC_CHALLENGE=true` to
also accept **one-time, expiring** challenge passwords created out-of-band:

```bash
TOKEN=$(fastpki-scep --config bootstrap.conf --issue-challenge device-profile --ttl 3600)
# hand TOKEN to the device; it uses it once as the CSR challengePassword
```

Tokens live in the `scep_challenges` table; `consume` is atomic (a used or
expired token is rejected with `pkiStatus=FAILURE`). A token names no user, so it is the
one remaining device path that carries no identity to authorize — per-user credentials
and dynamic tokens are accepted side by side.

**Manual-approval (async) enrollment — GetCertInitial / PENDING:**
set `SCEP_MANUAL_APPROVAL=true` and a PKCSReq is parked instead of issued inline;
the server answers `pkiStatus=PENDING` and the device polls with **GetCertInitial**
(reusing its `transactionID`) until an operator decides:

```bash
fastpki-scep --config bootstrap.conf --list-pending # txid <tab> subject CN
fastpki-scep --config bootstrap.conf --approve <txid> --ca <ca_id> # issues; prints the serial
fastpki-scep --config bootstrap.conf --reject <txid>
```

`--approve` needs `--ca`: the queue does not record which CA the request arrived for, and
there is no default CA. An approved request is issued for the `scep` subject, so its profile
comes from that subject's `profile:use` grants (see "Certificate policy profiles").

Parked requests live in the `scep_pending` table (status: pending → issued/rejected).
Re-sending the same `transactionID` is idempotent (returns the current state).
After approval the next GetCertInitial returns the issued cert (SUCCESS); a reject
returns FAILURE.

**Query operations:**
- `GetCert` — fetch a previously issued cert by `IssuerAndSerialNumber`
 (`pkiStatus=SUCCESS` with the cert, or FAILURE if unknown).
- `GetCRL` — return the CA CRL (the same `generate_crl` the OCSP binary serves)
 in a crl-only degenerate PKCS#7.

**RA mode:** set `SCEP_RA_KEY` (a `pkcs11:` URI) to front
the SCEP message layer with a separate Registration Authority credential. The RA
*certificate* is per CA and lives in the database under `cert_id` `<SCEP_RA_CERT_ID_PREFIX>-<ca_id>`,
issued by that CA and resolved per request — the same shape as the CMP RA and the
delegated OCSP responder, because an RA that fronts one CA must be certified by it.
Clients then encrypt
PKIOperation envelopes to the RA (not the CA) and the RA signs CertReps;
**issuance still uses the signing CA**. `GetCACert` returns the RA+CA pair as a
certs-only PKCS#7 (`application/x-x509-ca-ra-cert`, RA first). The key alone enables RA
mode; a CA with no RA certificate is refused with the `cert_id` to issue, never a silent
fall back to the CA key. Unset, the signing CA fronts the message
layer and `GetCACert` returns the single CA cert (`application/x-x509-ca-cert`).

`scep-testclient` is a small OpenSSL-based reference/test client
(`build`/`getcertinitial`/`getcert`/`getcrl` requests, `parse`/`parsecrl` of a
CertRep) used by the SCEP test suites.

```bash
# the CA certificate a device encrypts its PKIOperation envelope to
curl -o ca.der "http://localhost:8448/scep/{ca_id}?operation=GetCACert"
# what this CA advertises; the device then sends PKCSReq with a challenge password
curl "http://localhost:8448/scep/{ca_id}?operation=GetCACaps"
```

The SCEP surface (RFC 8894) covers GetCACert (incl. RA chain), GetCACaps,
PKIOperation (PKCSReq, GetCertInitial, GetCert, GetCRL), per-user and one-time
challenges, and manual-approval (PENDING) enrollment.

## Expiry notifications (`fastpki-notify`)

`fastpki-notify` scans the `certs` table for valid certificates approaching
expiry and reports / alerts on them, and emails each certificate's owner — run it daily from cron.

```bash
# text report (default warning windows: 30/14/7 days)
fastpki-notify --config bootstrap.conf
# JSON summary on stdout, and POST the report to a webhook in its receiver's format
fastpki-notify --config bootstrap.conf --json
fastpki-notify --config bootstrap.conf --days 30,14,7 --webhook https://receiver.example/hook
fastpki-notify --config bootstrap.conf --webhook-format slack --webhook https://hooks.slack.com/services/...
# per-owner routing: each team gets only its own certs
fastpki-notify --config bootstrap.conf --routes routes.txt
# monitoring gate for cron/CI: exit 3 if anything is at/above a severity
fastpki-notify --config bootstrap.conf --fail-on critical
# also alert on expiring DISCOVERED (unmanaged) certs from fastpki-discover
fastpki-notify --config bootstrap.conf --include-discovered
# who would be emailed, without posting, sending or recording anything
fastpki-notify --config bootstrap.conf --dry-run
# prove the relay settings deliver
fastpki-notify --config bootstrap.conf --test-email me@example.org
```

Each cert is bucketed by time-to-expiry, with the windows sorted largest first:
**expired** (past its notAfter), **critical** (within the smallest window), **warning**
(within the second-largest window but not the smallest), **info** (within the largest
window only). With the default `30,14,7` that is critical at 7 days or fewer, warning at
8–14 and info at 15–30. The console's preview uses the same rule. Revoked/expired-status
rows are skipped.

**Webhook format (`--webhook-format`, `NOTIFY_WEBHOOK_FORMAT`).** The receiver decides what it
accepts, so the body is chosen per deployment:

| Format | Body | For |
|---|---|---|
| `json` (default) | the same JSON document `--json` prints | a generic receiver: a script, Jira Automation, a ServiceNow scripted endpoint |
| `slack` | `{"text": …}` in Slack mrkdwn: a title, the counts per severity, one line per certificate | a Slack incoming webhook |
| `teams` | `{"type":"message","attachments":[…]}` carrying one Adaptive Card (version 1.4): title, a fact set of counts, the certificate list | a Teams Workflows "when a webhook request is received" flow, or an incoming webhook |

Slack and Teams refuse the `json` document. The chat formats list at most 50 certificates and
say how many more there are. All three are built with a JSON library, so a CN or owner
containing quotes or control characters cannot break the payload.

**Per-owner routing (`--routes <file>`):** one `owner=url` per line (`#` comments
allowed). The expiring certs are grouped by `owner` and each owner's subset is
POSTed to its own webhook, so a team is alerted only about its own certificates.
`--webhook` (the whole summary to one endpoint) and `--routes` can be combined.

**Monitoring gate (`--fail-on <severity>`):** exit `3` when any reported cert is
at or above the given severity (`expired` > `critical` > `warning` > `info`) — handy for
a cron/CI job that should alert on its own exit status. A webhook or route delivery
failure exits `1` instead, and is reported ahead of the gate.

**Discovered certs (`--include-discovered`):** also scan the
`discovered_certs` inventory harvested by `fastpki-discover` and fold any
expiring unmanaged certs into the same report / JSON / webhooks / `--fail-on`
gate, tagged `owner=discovered`.

**Email to owners (`SMTP_SERVER`).** With a relay set, the owner of each managed certificate
this data center issued gets one email per run listing their certificates. A certificate is
included once as it enters each window and once when it expires; `notify_sent` (node-local)
records the tightest window each serial was emailed at, written only after the relay accepts
the message. The address is the directory's `mail` for a `<directory>\<user>` owner, else the
account's `web_users.email`, else `NOTIFY_EMAIL_FALLBACK`. A certificate whose owner holds a newer
valid certificate with the same subject and names is treated as replaced and left out. The
serial prefix decides which data center emails, so a mesh does not email one owner per site,
and a server whose database is in recovery (a standby) sends nothing.

The client is FastPKI's own (`src/lib/smtp.cpp`, over OpenSSL): STARTTLS is required with
`SMTP_TLS=starttls`, `tls` speaks TLS from the first byte, and with either the relay certificate
and name are verified against the system store plus `SMTP_CA_FILE`. `none` talks to a relay that
speaks no TLS. AUTH uses PLAIN, or LOGIN when that is all the relay offers, and never without TLS:
`SMTP_TLS=none` with `SMTP_USER` set is refused. Messages are UTF-8 plain text, base64-encoded, with
`Auto-Submitted: auto-generated`. The subject, per-certificate line and body come from the
replicated `notify_templates` table, or the built-in text when it has no row.

**Console panel.** The web console's **Notifications** tab
(`config:manage`) gives a read-only **preview** of what a `fastpki-notify` run would
alert on — `GET /api/notify` does the same in-process expiry scan and returns the
stored windows plus the soon-to-expire managed certs bucketed by severity, each marked when it
has been replaced — and editors for the warning windows (`NOTIFY_DAYS`), the webhook
(`NOTIFY_WEBHOOK`, shown only as set or not) and its format (`NOTIFY_WEBHOOK_FORMAT`), with
**Remove webhook** to clear a stored one; the relay (`SMTP_SERVER` and the keys beside it, the
password shown only as set) and
`NOTIFY_EMAIL_FALLBACK`, with **Send test email**; and the email template. Settings are written to
the database `config` table and the template to `notify_templates`. `fastpki-notify`
applies that table over `bootstrap.conf` on every run, so a run without `--days` /
`--webhook` uses the saved values and needs no restart of anything; a flag on the command
line still wins. Apart from the test message, the console sends nothing itself: dispatch is the
scheduled `fastpki-notify` run.

## Certificate discovery (`fastpki-discover`)

`fastpki-discover` harvests the certificates served by TLS endpoints to build an
inventory of *unmanaged* certs and flag the ones that need remediation.

```bash
# scan a few endpoints (host defaults to port 443) + a file of targets
fastpki-discover --config bootstrap.conf one.example.org:443 10.0.0.5:8443
# an IPv4 CIDR fans out to its usable hosts (network + broadcast skipped)
fastpki-discover --config bootstrap.conf 10.0.0.0/29:8443
fastpki-discover --config bootstrap.conf --targets targets.txt --json
```

For each target it TLS-connects **without verification** (so it can inventory
self-signed/untrusted/legacy endpoints — security level is lowered to accept
SHA-1 / small-key servers), extracts the leaf cert (subject, issuer, validity,
key algorithm + size, signature algorithm, SANs, SHA-256 fingerprint), records
it in the `discovered_certs` table, and computes compliance **flags**:
`expired`, `expiring` (≤30d), `weak_key` (RSA<2048 / EC<256), `self_signed`,
`weak_sig` (SHA-1/MD5). Unreachable targets are reported and counted.

A target host part may be an **IPv4 CIDR** (`10.0.0.0/29:8443`): it is expanded
to its usable host addresses (the network and broadcast addresses are skipped;
`/31` and `/32` are scanned in full). Blocks larger than `/16` are refused to
guard against accidental internet-wide sweeps.

**Migration trigger (`--migrate-webhook <url>`):** after the scan, the
non-compliant endpoints (any cert with a flag) are POSTed as a JSON *work list*
(`{generated, count, migrations:[{target, subject, fingerprint, notAfter,
keyAlgo, keyBits, flags}]}`) to an external re-enrollment agent — an
Ansible/EST/ACME cron that pulls the list and re-enrolls those hosts onto the
managed CA. A delivery failure exits non-zero.

```bash
fastpki-discover --config bootstrap.conf 10.0.0.0/24:443 --migrate-webhook https://reenroll.example/work
```

The console's **Discovered** page lists the inventory (`GET /api/discovered`, which needs
`ca:manage` and is refused to a CA-scoped caller) and can start a scan of up to 64
targets (`POST /api/discover`), which runs the binary named by `DISCOVER_BIN` with a
5-second timeout; starting a scan needs `*:*` and `WEB_ALLOW_REVOKE`. Nothing schedules a
recurring scan — run `fastpki-discover` from cron for that.

## Web management UI (`fastpki-web`)

`fastpki-web` is the management console: a single-page UI plus the JSON API behind it,
over the same database the protocol services use. Every page and every route is gated by
the caller's permissions ([rbac.md](rbac.md)), and the routes that change what the
deployment holds — certificates, CAs, users, roles, configuration — also need
`WEB_ALLOW_REVOKE` (on by default; `false` pins the instance read-only; signing in and
changing one's own password still work). The full route list is in
[api-reference.md](api-reference.md).

```bash
fastpki-web --config bootstrap.conf # serves on WEB_BIND:WEB_PORT, 0.0.0.0:8090 by default
```

- `GET /` — the console (vanilla JS, no external assets). Its pages are **Dashboard**,
 **Inventory**, **CAs**, **Audit log**, **Discovered**, **Compliance**,
 **Notifications**, **Endpoints**, **Users**, **Computers**, **Roles**, **Profiles**,
 **HSM keys**, **Templates**, **Domains**, **Directories**, **Config**,
 **Client Configs**, **Backup** and **Updates**. A page is shown only to a caller holding
 the permission its routes need — for example `cert:read` for Inventory and Compliance,
 `audit:read` for Audit log, `config:manage` for Config, Endpoints, Notifications,
 Domains, Directories, Client Configs and Updates, `profile:edit` for Profiles,
 `template:edit` for Templates, `hsm:read` for HSM keys. The Dashboard is shown to
 every signed-in subject. The server enforces the same permissions, so hiding a page is
 presentation, not the control.
- `GET /api/certs`, `/api/audit`, `/api/discovered` — paginated JSON
 (`?limit=&offset=`); the inventory omits the DER blob. The inventory also
 supports **server-side search/filter/sort**:
 `?q=<substring>` (across cn/owner/subject/serial), `?status=<n>`, `?ca=<ca_id>`,
 `?sort=<cn|owner|serial|status|notBefore|notAfter>&order=<asc|desc>`; a filtered or
 sorted query returns an `X-Total-Count` response header. The console's search box and
 clickable column headers drive these. `/api/audit` and `/api/discovered` are refused
 (`403`) to a CA-scoped caller, because neither carries a per-CA partition.
- `GET /api/certs/<serial>` — full **detail** for one managed cert: the stored
 DER is decoded for SANs, key algorithm/size, signature algorithm, issuer and
 PEM, alongside the lifecycle fields. The Inventory tab opens this in a panel
 when you click a row. Needs `cert:read`.
- `GET /api/config` — the **effective server configuration** (`config:manage`). A value
 whose key names a token, secret, password, conninfo, PBM or challenge value is returned as
 `(set)`/`(not set)`, so an operator can confirm a secret is configured without seeing it.
- `GET/PUT/DELETE /api/config/db` — the **editable config overlay** (see "Dynamic
 configuration in the DB" below); `PUT ?key=&value=` sets, `DELETE ?key=` reverts.
 Writes are audited.
- `GET /api/compliance` — a **risk report** over the managed inventory (`cert:read`):
 flags weak keys (RSA < 2048 / EC < 256), deprecated signatures (SHA-1 / MD5), and
 expiring/expired certs (window via `?days=`, default 30), with headline counts. Revoked
 certs are excluded, and a caller whose `cert:read` is scoped `own` sees only its own
 certificates. The Compliance tab shows the counts banner + the flagged certs.
- `GET /api/audit/export-signed?ca_instance=<ca_id>` — the **signed compliance export**
 (`audit:read`): an envelope with the audit NDJSON, its SHA-256, and a detached signature
 over `"<head_seq>:<sha256>"` by the CA the request names. There is no default CA, so
 without `ca_instance` it answers `400`; a CA-scoped caller gets `403`; a CA whose key
 this node cannot use gets `503`; a broken hash chain gets `409`. The Audit tab's
 **⬇ Download signed audit export** button asks which CA signs (listing the enabled,
 unexpired, unrevoked non-root CAs this node can sign with, which needs `ca:read`) and
 saves `audit-export.ndjson` + `audit-export.ndjson.sig`. Check them with
 `fastpki-audit verify-export --ca <ca_id> --out audit-export.ndjson`, which reads that
 CA's certificate from the database.
- `GET /api/summary` — headline counts (`audit:read`); `GET /healthz` — liveness.
- `GET /api/setup` (`*:*`) — `{initialized, managedCas, pkiDns, baseUrl, writeEnabled, …}`,
 where *initialized* means at least one CA the caller may see has its certificate stored.
 The console does not use it; it is there for a deployment script that wants to know
 whether a CA exists. CAs are created on the **CAs** page (see "Multi-CA dashboard").

**Roles & self-service.** There are no role names in the console's code; what a caller
sees follows its permissions. The shipped roles ([rbac.md](rbac.md) §7) come out as:

- **`admin`** holds `*:*` and reaches every page.
- **`auditor`** holds `audit:read`, `hsm:read` and `self:manage`: the Dashboard, Audit
 log, HSM keys, and its own entry on Users, where it can change its password. The signed
 export route itself needs only `audit:read`, but the Audit tab's button lists CAs, which
 needs `ca:read`; without it the button says so, and the export is taken by naming the CA
 in the request or with `fastpki-audit export-signed`.
- **`requester`** holds `cert:read` and `cert:revoke` scoped `own`, `cert:request`,
 `ca:read`, the five `<protocol>:enrol` grants, `profile:use` on the `requester`
 profile, `template:use` on the three built-in templates and `self:manage`. The Inventory
 tab is labelled **My certificates** for it: `GET /api/certs`, `/api/certs/<serial>`,
 `/api/compliance` and the revoke route return or act on only the certs whose `owner` is
 the session user — enforced server-side, so someone else's serial is `404`.
- **`none`** holds nothing: an onboarded directory or SSO identity waiting for an
 administrator.

**Requesting a certificate.** A caller holding `cert:request` can issue from the console.
`POST /api/certs/request?ca_instance=<ca_id>` takes a PEM PKCS#10 CSR (the private key
stays with the client) and issues it through the **same policy/profile engine** as the
enrolment protocols: `owner` is forced to the session user, the profile is resolved for
that user (`?profile=` names one — see "Certificate policy profiles"), and the role's
issuance limits apply (`429` when one is reached). The CA must be named, must be in the
caller's CA scope (`403`), and its key must be usable on this node (`409` when it is not).
The certificate is stored, so it appears in the requester's inventory.
`POST /api/certs/request-hsm` instead generates the key inside this node's token and needs
`hsm:manage`. Both need `WEB_ALLOW_REVOKE`.

**Context-aware CSR mapping.** For a console request the certificate profile decides
whether the subject is bound to the *authenticated identity*. When the profile does not
set `no_override_subject` and `WEB_SELFSERVICE_IDENTITY_SUBJECT` is on (the default), the
CN is replaced with the session's user name, one OU is added for each group the session
carries, and a directory or SSO identity (`provider\user`) adds the provider as a
domainComponent rather than putting a backslash in the CN. The other subject attributes
stay as requested. The built-in `admin` profile sets `no_override_subject`, so a
certificate issued under it keeps the requested subject — it is the profile used to issue
for hosts and services; `requester` does not. The enrolment protocols never apply this
mapping.

**Subject Directory Attributes.** Every issued cert carries the owner in an RFC 5280
§4.2.1.8 **Subject Directory Attributes** extension (non-critical) rather than as Subject
DN RDNs: `owner` (OID 2.5.4.32) as a *synthesized* DN — `CN=<user>`, plus
`DC=<provider>` for a provider-qualified owner — because not every authentication path
yields a directory DN. No role is written into the certificate. The extension is built
before signing, so it is covered by the signature.

### Dynamic configuration in the DB

Configuration lives in the database rather than `bootstrap.conf`, so it's editable
from the console (or CLI) without touching files. A `config(key, value, updated)` table
holds a **key/value overlay** that every service applies on top of the file/env config
**at startup — the DB value wins**. Keys are the uppercase `bootstrap.conf` names and
reuse the same parser. Only the **bootstrap key** that says how to reach the DB —
`PG_CONNINFO` — stays file-only (and is rejected by the setters). The table belongs to one
database and is not replicated by the mesh, so each data center has its own; the two hosts
of an HA pair share one. `fastpki-notify`, `fastpki-ca` and `fastpki-audit` apply the
table too; `fastpki-mcp` and `fastpki-update` read `bootstrap.conf` and the environment
only.

Manage it with **`fastpki-config`** (or the console's **Config** tab, whose **Edit full
config file** editor also takes keys that have no field on the page — see
[config-reference.md](config-reference.md)):

```bash
fastpki-config --config bootstrap.conf set CERT_VALIDITY_DAYS 365
fastpki-config --config bootstrap.conf list # secrets shown as (set)
fastpki-config --config bootstrap.conf import old.conf # migrate a file into the DB
fastpki-config --config bootstrap.conf unset MIN_RSA_BITS # revert to file/default
```

Servers pick up changes on restart (the overlay is read once at startup, like the
file).

**Backup & restore.** A portable JSON backup of the management/config tables — the
config overlay (without the per-process start and restart markers), console users with
their password hashes, CA instances (certificate and key reference), roles with their
permissions and issuance limits, role assignments (`subject_roles`) and MS templates —
from the CLI or the console's **Backup** tab. `--passphrase-file <f>` encrypts it in the
`.fpkibak` format, which both the CLI and the console read:

```bash
fastpki-config --config bootstrap.conf backup --out backup.json # plain JSON, mode 0600
fastpki-config --config bootstrap.conf backup --out backup.fpkibak --passphrase-file pass.txt
fastpki-config --config bootstrap.conf restore backup.json # idempotent upserts
fastpki-config --config bootstrap.conf restore backup.fpkibak --passphrase-file pass.txt
```

The console exposes the same through `GET /api/backup` and `POST /api/backup` (with an
optional `passphrase`) and `POST /api/backup/restore`, all needing `backup:manage`;
restore also needs `WEB_ALLOW_REVOKE`. The configuration backup does not carry the
issued-cert inventory, the audit log, directories and identity providers, the
approved-domain list or the per-user enrolment secrets, nor any **CA private key**, which
stays in its token. For those, the **Backup** page also takes a full database dump
(`POST /api/db-backup`, made with `pg_dump`, optionally encrypted) and restores one in a
single transaction (`POST /api/db-backup/restore`); `fastpki-config decrypt-backup`
decrypts an encrypted download without a database. Both kinds of file carry password
hashes and secrets, so treat them as sensitive.

**Versioning & safe updates.** Every binary is stamped with a build-time
version (`git describe`, overridable with `-DFASTPKI_VERSION=`). The **`fastpki-update`**
tool checks for a newer release and verifies a release signature; the console's
**Updates** tab (`config:manage`) runs the check:

```bash
fastpki-update version # the running version
fastpki-update check # exit 10 = update available, 0 = up to date, 1 = check failed
fastpki-update verify dist.tgz dist.tgz.sig # check a detached signature (RELEASE_PUBKEY)
```

`check` polls the fastpki/fastpki GitHub releases by default, or a self-hosted
JSON manifest when `UPDATE_FEED_URL` is set (air-gapped / enterprise). The web tier
mirrors this at `GET /api/version` (bare = running version; `?check=1` queries the feed).
The CLI reads `UPDATE_FEED_URL` and `RELEASE_PUBKEY` from `bootstrap.conf` only, while the
console uses the values in the `config` table. Artifacts are verified against the PEM key
pinned in `RELEASE_PUBKEY` before being trusted (SHA-256; RSA or ECDSA). Applying an update
is deployment-specific and is not an in-process action: the procedure for each deployment
is in [admin-guide.md](admin-guide.md) (Updating FastPKI). A 404 from the GitHub feed is
reported as a failed check, because it also means the repository is not visible to this
host.

### The first CA

A fresh deployment has no CA, and the console opens on its ordinary pages. CAs are created
on the **CAs** page at any point in an instance's life — a root first, then an issuing CA
under it — and nothing can be issued until one exists. `GET /api/setup` reports whether
one does, for a script.

The same page registers an **existing** CA through `POST /api/ca-instances` with
`cert_pem` (the pasted CA certificate) and `key`, a `pkcs11:` handle naming the key in a
token — the private key is never uploaded, and a file path is refused. Leaving `key` out
registers a verify-only trust anchor that this deployment never signs with.

### Endpoint-configuration engine

The console's **Endpoints** tab maps every listener to the URLs clients use.
`GET /api/endpoints` (`config:manage`) returns one row each for EST, ACME, CMP, SCEP,
OCSP, CRL, MS-XCEP, MS-WSTEP, Store, the Web Console and PostgreSQL: the listener
`bind:port` and path, the **effective external URL** (`BASE_URL` + path when `BASE_URL` is
set explicitly, otherwise `<scheme>://<PKI_DNS>:<port><path>`), the URL **advertised in
issued certs** for OCSP and CRL, and the config keys that drive the row. The advertised
URL is the per-CA shape issuance derives from `BASE_URL` / `PKI_DNS` and the CA id (for
example `http://pki.example.org:8080/<ca_id>.crl`); `CRL_DPS` and `AIA_OCSP` do not
appear there, because they apply only to a certificate issued without a CA instance.

The map is computed from the stored configuration on every request, so an edited key
shows at once; the service that reads it uses the new value after its restart. Each
protocol row (not CRL, the console or PostgreSQL) carries an on/off switch and a
**Restart** action; the console row carries **Restart** only, and the PostgreSQL row no
action. `GET /api/endpoints/health` probes each listener with a TCP connect.

### DB-backed users + initial admin

Console login users live in the DB (a `web_users` table) — the single source,
managed at runtime and replicated across data centers — there is no file backend. They
feed the login / mTLS / RBAC path, and EST / MS-WSTEP password auth. **Bootstrap:** with
no `WEB_TOKEN` and no users, `fastpki-web` is in *open mode* — every `/api/*` caller is
treated as `admin`, and a startup warning says so — so keep it on loopback and
`POST /api/users` to create the first user; that flips the server into login-required
mode. The first user is `admin` when the request names no role; every later create must
name one. Deployments normally skip open mode by seeding the first account with
`fastpki-config web-user … --if-absent`. From then on, users are managed from the
**Users** tab (`GET/POST/DELETE /api/users`, `user:manage`, write-gated by
`WEB_ALLOW_REVOKE`, audited): create or update with a role that exists in `roles`, or
delete (not your own account). A caller can only assign a role whose grants it already
holds, and nobody changes their own role ([rbac.md](rbac.md) §6). CA scope is part of a
role's grants, not a user setting. A caller holding only `self:manage` can change its own
password there and nothing else.

A user created with **`mustReset`** must change its password before doing anything
else: the session is flagged, the pre-routing gate blocks everything except
`/api/me`, `/api/password`, and `/api/logout`, and the console shows a
**set-new-password** overlay. `POST /api/password` (old + new, ≥ 8 chars) verifies
the current password, stores the new `pbkdf2$…` hash, and clears the flag.

### OIDC single sign-on

The console can federate login to an **OpenID Connect** IdP (Keycloak, Entra ID,
Okta, Google, …) via the **Authorization Code flow with PKCE**.

**An identity provider is a row, not configuration.** Add it on the console's
**Directories** page under *Federated sign-in*, or through `/api/auth-providers`:

```
POST /api/auth-providers
kind=oidc id=corp display_name=Corp
issuer=https://idp.example.org # discovery base
client_id=fastpki-console
client_secret=… # write-only; never returned by the API
scopes=openid email profile # default when left empty
username_claim=email # claim used as the local username
groups_claim=groups
admin_group=pki-admins # group membership -> admin
auditor_group=pki-auditors # group membership -> auditor
require_local_user=true # only allow pre-provisioned users
ca_cert=/var/pki/tls/idp-ca.pem # trust anchor for the IdP's TLS, on the shared volume
```

The settings live in `auth_providers` + `oidc_providers` and replicate to every node.
There is no config key for an identity provider: a flat file holds one value per key, so
it could name only one IdP. `ca_cert` is a file path read by `fastpki-web`, so the file
must exist on every node that serves the console.

`GET /api/oidc/login` redirects to the IdP (storing `state` + `nonce` + the PKCE
verifier); `GET /api/oidc/callback` exchanges the code at the token endpoint and
**verifies the ID token** — the RS256/ES256 signature against the IdP's JWKS
(reusing `lib/jws`), plus `iss`/`aud`/`exp`/`nonce`. The user name is qualified with the
provider id (`corp\alice`) and maps to a role:

1. a **`web_users` row with that name wins** — its role is used, so an administrator
 can pre-assign one;
2. otherwise, with `require_local_user` set, the sign-in is refused;
3. otherwise membership of `admin_group` gives `admin` and of `auditor_group` gives
 `auditor`, re-evaluated at every sign-in and not stored;
4. otherwise the identity is stored as a `web_users` row with role **`none`** and no
 usable password, so an administrator can find it and grant it a role.

Roles bound to the identity's groups through `subject_roles` apply on top, as for every
subject. The sign-in page shows one **Sign in with …** button per enabled provider.

### SAML 2.0 single sign-on

The console also supports **SAML 2.0 SP-initiated Web SSO** (ADFS, Entra ID,
Shibboleth, Keycloak, …). It is built in by default and links **libxmlsec1** (the
XML-DSig engine), libxml2 and zlib, because verifying a SAML assertion safely needs a
real XML-signature stack. Building with `-DFASTPKI_WITH_SAML=OFF` compiles a disabled
stub instead, if you are working somewhere those libraries are not available. Like OIDC, an IdP is a row — added on the **Directories** page
under *Federated sign-in*, or through `/api/auth-providers`:

```
POST /api/auth-providers
kind=saml id=corp display_name=Corp
idp_sso_url=https://idp.example.org/sso # IdP SSO endpoint (HTTP-Redirect)
idp_cert=/var/pki/tls/idp-signing.pem # PINNED assertion-signature anchor, on the shared volume
sp_entity_id=https://pki.example.org/sp # our EntityID (AuthnRequest Issuer + Audience), required
idp_entity_id=https://idp.example.org/idp # optional <Issuer> pin
groups_attr=groups # attribute holding the user's groups
username_attr= # attribute for the username (default: NameID)
admin_group=pki-admins # group membership -> admin
auditor_group=pki-auditors # group membership -> auditor
require_local_user=true # only allow pre-provisioned users
clock_skew_sec=120
```

`GET /api/saml/login` emits an AuthnRequest (HTTP-Redirect binding) and tracks
its ID; the IdP POSTs a signed Response to `POST /api/saml/acs`. The security of
this path is entirely in the **assertion signature check** (`pki::SamlSp`,
`src/lib/saml.cpp`): trust is **pinned to the provider's `idp_cert`** and that key is loaded
directly into the verify context, so the Response's own `<KeyInfo>` can never
substitute a different signing key. It hardens against **XML Signature Wrapping**
(exactly one `<Assertion>`; the signature must be a direct child of it; the signed
Reference URI must equal the assertion's unique ID; no DTD/DOCTYPE → no XXE;
SHA-1/MD5 signature & digest methods rejected), then validates Status=Success,
Audience, the Conditions / SubjectConfirmationData time windows, the ACS
Recipient, and **InResponseTo** against an AuthnRequest we actually issued
(one-shot, so a captured Response cannot be replayed). The identity → role mapping and the
per-provider sign-in button work exactly as for OIDC. `idp_cert` is a file path read by
`fastpki-web` at each sign-in, so the file must exist on every node that serves the
console.

**HTTPS and client-certificate login.** Setting `WEB_TLS_KEY` (a `pkcs11:` URI by
default) or `WEB_TLS_CERT` makes the console terminate TLS itself. Its certificate is the
`certs` row named by `WEB_CERT_ID`; `WEB_TLS_CERT` only imports a file into that row, and
with neither a row nor a file the console creates a self-signed certificate in the token.
Leave both unset to run plain HTTP behind a TLS-terminating proxy.

With TLS on, `WEB_CLIENT_CA_ID` (registered CA ids), `WEB_CLIENT_CA_BUNDLE` (PEM for
anchors not registered here) or `WEB_CLIENT_CA` (a PEM file) make the console **ask** for a
client certificate. Presenting one is optional — a browser without one gets the ordinary
sign-in page — and a presented one is verified against those anchors. It then signs the
caller in without a password:

- a certificate this deployment issued (found by serial in `certs`) must not be revoked,
 and it must name the `owner` recorded at issuance: its CN equals the owner, or, for a
 directory or SSO owner `corp\alice`, its CN is `alice` and its domainComponent `corp`, as
 self-service issuance writes it. That owner's `web_users` row gives the role. A host or
 service certificate, whose subject names something other than its owner, is not a login;
- a certificate from an anchor with no `certs` row maps to the user `dn\<CN>`, which must
 exist in `web_users`.

A certificate that matches neither falls through to the session cookie and the bearer
token, and with neither the API answers `401`. The resulting flow: sign in, request a
`clientAuth` certificate from the console under a profile that binds the subject to the
identity, and use that certificate to sign in afterwards.

**Password login.** Console accounts live in `web_users`; seed one non-interactively
with `fastpki-config web-user <name> <pw> --role <role>`, or manage them from the console
Users page. User names are matched case-insensitively.

```bash
fastpki-config --config bootstrap.conf web-user alice '<password>' --role admin
```

`POST /api/login` (form `username`/`password`) authenticates through `AUTH_BACKEND` — a
local account by its PBKDF2 hash, or with `ldap` a directory login such as `corp\alice`
([authentication.md](authentication.md)) — and answers `501` when the backend is `local` and
no account exists yet. Repeated failures are delayed per account and per address
(`LOGIN_FAILURE_THRESHOLD`, `LOGIN_LOCKOUT_SEC`; `429` while delayed). A success opens a
12 h **session** (an HttpOnly `SameSite=Strict` cookie, `Secure` when the console serves
TLS; an OIDC or SAML session uses `SameSite=Lax`, which the IdP's redirect back needs).
Attempts are audited (`web_login` / `web_login_fail`). `POST /api/logout` ends the
session; `GET /api/me` reports the user, its effective roles and permissions,
`writeEnabled` and `mustReset`.

**Revocation.** A caller holding `cert:revoke` can revoke from the Inventory drill-down
(`POST /api/certs/<serial>/revoke?reason=<n>`), choosing a standard **RFC 5280 reason
code**; codes outside 0–10, and 7, are rejected `400`. A caller whose `cert:revoke` is
scoped `own` may revoke only its own certificates. Revoking a CA certificate also revokes
that CA's other certificate generations. The status and reason are written to the
database, so OCSP answers reflect it at once and the CRL (which carries the `CRLReason`)
from its next regeneration; the action is audited as `web_cert_revoked`. It needs
`WEB_ALLOW_REVOKE`; the session cookie is `SameSite=Strict`, which blocks cross-site POSTs
(CSRF).

Config: `WEB_BIND` (default `0.0.0.0`), `WEB_PORT` (8090), `WEB_TOKEN` (a bearer token for
automation, which acts as `admin`), and `WEB_ALLOW_REVOKE` (default **on**). With neither a
token nor any DB user, `/api/*` is open — warned at startup.

⚠️ **The listener binds every interface by default, and writes are enabled by
default.** Set `WEB_BIND=127.0.0.1` and front it with a TLS-terminating reverse
proxy in production, or otherwise make sure the port is not reachable from
somewhere it should not be.

## Multi-data-center active-active replication (`fastpki-mesh`)

For low-latency local enrollment plus global inventory visibility, multiple
data centers can run a native, full-mesh PostgreSQL **logical replication**
topology of the *public* certificate inventory. Two guarantees keep
it conflict-free:

1. **A serial prefix per data center.** Every certificate a node issues carries a
 2-octet prefix that is its own, in the top two bytes of a 20-octet serial, so
 the `certs` primary key never collides across sites.
 The node reads that prefix from its own row in the `datacenters` table, keyed
 by `DATACENTER_ID` — there is no config key for the prefix, so the bound has
 one source of truth. A node whose id has no row **refuses to issue** rather
 than issuing unprefixed. A generated `BEFORE INSERT` **trigger** enforces the
 prefix as defence-in-depth. It fires only for local writes
 (`session_replication_role = 'origin'`) and is skipped during apply, so it does
 not reject certificates issued in another data center's partition.

 The prefix range is `1`–`32767`, not `1`–`65535`: DER integers are signed, so a
 leading octet with its high bit set would be padded with `0x00` and push the
 serial to 21 octets, outside RFC 5280 §4.1.2.2. The remaining 18 random octets
 give 144 bits of entropy; the CA/Browser Forum requires at least 64.
2. **Loop-free subscriptions.** Every `CREATE SUBSCRIPTION` carries
 `WITH (origin = none)` so replicated rows are never transitively forwarded
 back around the mesh.

`fastpki-mesh` turns a topology file into the DDL. The file holds one line per data
center, `dc_id|conninfo|serial_prefix|base_url`.

⚠️ `dc_id` must be EXACTLY the value of `DATACENTER_ID` in that node's `.env`.
The lookup is `SELECT serial_prefix FROM datacenters WHERE dc_id=$1` against that value, and
`install.sh` writes the bare index (`1`), so a topology naming its data centers `dc1` never
matches and every issuing service refuses to start with "has no row in `datacenters`".

```bash
fastpki-mesh --topology dcs.txt --all # publication + map + every node
fastpki-mesh --topology dcs.txt --node 1 # just data center 1's prefix trigger + subscriptions
fastpki-mesh --topology dcs.txt --publication # the public-only publication
fastpki-mesh --topology dcs.txt --map # the datacenters rows every node reads
fastpki-mesh --topology dcs.txt --node 1 --verify # what is MISSING or STALE on data center 1
```

The publication carries the tables a deployment has to agree on across every node —
the certificate inventory, the CAs, revocation, the management tables (`web_users`,
`roles`, `role_permissions`, `subject_roles`, `allowed_domains`, `ms_templates`,
`auth_providers` and the per-kind provider settings), and the per-user enrolment
secrets in `keys`. That last one is deliberate: a credential stranded on the node
that created it would make a downloaded client config enrol against one node out of
three.

**What never leaves a node is the CA private key**, and it is excluded by a COLUMN
LIST on `certs` rather than by omitting a table — so a column added later cannot
quietly start replicating it.
Node-local state (`schema_version`) is likewise unpublished.

For *N* data centers it emits *N×(N−1)*
subscriptions. Run each node's section on that node; run the publication on all
of them.

## MCP server (`fastpki-mcp`)

`fastpki-mcp` exposes the PKI inventory to **MCP** clients (agents, IDEs)
over the Model Context Protocol **stdio** transport — newline-delimited JSON-RPC
2.0 on stdin/stdout. An agent can then answer "which certs expire
this week?" or "is serial `<x>` revoked?" directly against the live database.

The MCP client launches the binary itself, so it has to be able to reach both the binary
and the configuration file. On a native install both are on the host:

```jsonc
// configure as an MCP server (e.g. in an MCP client's config):
{ "command": "fastpki-mcp", "args": ["--config", "/etc/fastpki/bootstrap.conf"] }
```

On Docker Compose and Kubernetes the binary is inside the image, so the client's command
is the container wrapper — `docker compose run --rm --no-deps --entrypoint fastpki-mcp web
--config /app/config/bootstrap.conf` — which keeps stdin and stdout attached.

By default the surface is **read-only**, offering the same data as the web console as
MCP tools:

| Tool | Returns |
|------|---------|
| `list_certificates` | managed certs (paged), status + validity |
| `get_certificate` | one cert by hex serial, with revocation detail |
| `list_expiring` | valid certs expiring within N days |
| `list_discovered` | discovered/unmanaged certs |
| `list_audit` | the tamper-evident audit log, newest first |
| `summary` | headline counts |

A **write** tool, `revoke_certificate` (by hex serial; sets the cert revoked so
OCSP/CRL reflect it, audited as `mcp_cert_revoked`), is added **only when
`MCP_ALLOW_WRITE=true`**. `fastpki-mcp` reads that key, like `PG_CONNINFO`, from
`bootstrap.conf` or the environment; it does not apply the database `config` table. The
stdio transport is a single trusted local client, so gating is via that flag and who can
launch the binary. There is no issuance tool.

`initialize` / `tools/list` / `tools/call` are implemented; logs go to stderr
(stdout is reserved for protocol frames).

## PKCS#11 HSM / smart-card CA key

A CA signing key lives in a **PKCS#11 token** (Thales / YubiHSM / Nitrokey /
SoftHSM) rather than an on-disk PEM, so the private key never resides in plaintext
in the app or DB. The key is a `pkcs11:` URI on the CA's row — the
default for a console-created CA — and the module is named in `bootstrap.conf`:

```ini
# on the CA row: pkcs11:token=fastpki;object=signing-ca;type=private?pin-source=/var/pki/tls/pin
PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so # the vendor's PKCS#11.so
PKCS11_PROVIDER_PATH=/usr/lib/ossl-modules # dir holding OpenSSL's pkcs11.so (optional)
```

`pki::load_signing_key` detects the `pkcs11:` scheme and loads the key handle
via OpenSSL's **pkcs11 provider + `OSSL_STORE`**; everything downstream
(`X509_sign`, `X509_CRL_sign`, OCSP/CMS signing across OCSP, EST, ACME, CMP,
SCEP, MS-WSTEP, the store and `fastpki-audit`) then signs **through the HSM**
transparently. There is **no build dependency** — the provider and token module
are loaded at runtime. A CA key is always a `pkcs11:` handle; a PEM file path is accepted
only as the last-resort fallback for the keys that allow one, such as a listener's TLS key.

The token label and the `object=` name in a `pkcs11:` URI are free choices. The shipped
deployment uses the token label `fastpki` and reads the PIN from a file with
`pin-source=`, so no PIN appears on a command line or in a configuration file.

## Multi-CA / multi-root control plane

One instance hosts several certificate authorities. Each is a row with a real
id — a root, or a sub-CA via its parent — and every issued certificate records which
CA issued it. There is deliberately **no default CA**: a fresh deployment has none,
and the enrolment services stay up but refuse to issue until an admin creates one.

Every CA signing key is a `pkcs11:` handle in a token. There is no on-disk CA key
path and no configuration key that names a CA.

**`fastpki-ca`** manages CA instances from the control plane:

```bash
fastpki-ca --config bootstrap.conf list
# Generate the key in the token and register the CA in one step:
fastpki-ca --config bootstrap.conf create root-ca --name "Example Root CA" \
 --subject "/CN=Example Root CA" --ca-key "pkcs11:token=fastpki;object=root-ca" --keygen
fastpki-ca --config bootstrap.conf create issuing-ca --name "Example Issuing CA" \
 --parent root-ca --subject "/CN=Example Issuing CA" --key ec \
 --ca-key "pkcs11:token=fastpki;object=issuing-ca" --keygen # Sub-CA, EC key in the token
# Or register pre-existing material (a pkcs11: URI is allowed for the key):
fastpki-ca --config bootstrap.conf add legacy --name "Legacy" --ca-pem ca.crt \
 --ca-key "pkcs11:token=fastpki;object=legacy"
fastpki-ca --config bootstrap.conf disable issuing-ca # / enable / show <id>
```

Each instance is a Root CA (no `--parent`) or a Sub-CA of one. **`create`**
builds the CA certificate (self-signed root, or a Sub-CA signed by `--parent`, which must
be a CA this node can sign with), stores it as the CA's `certs` row and registers the key
URI — so no pre-placed PEM files are needed. `--ca-key pkcs11:<uri>` is required and names
the key in the token:

- with `--keygen`, `create` generates the key inside that token (`--key`, default `rsa`;
 `--bits`, default 4096; `--curve`), and `--replicable` generates it so `key replicate` can
 later copy it into another node's token;
- without `--keygen`, the key must already exist in the token, created out of band.

Either way the private key never leaves the token. `--out-dir` optionally writes a copy of
the certificate; nothing is written without it.

**`add`** registers an already-existing CA from its certificate (`--ca-pem <file>`) and,
optionally, its key (`--ca-key pkcs11:<uri>`). Without `--ca-key` the CA is a verify-only
trust anchor. A CA signing key is always a `pkcs11:` handle.

**Per-CA routing.** Every enrolment protocol names its CA in the path, as a
trailing segment: EST `/.well-known/est/{ca_id}/...`, ACME `<acme_base>/{ca_id}/...`,
CMP `/cmp/{ca_id}`, SCEP `<scep_path>/{ca_id}`, and the MS endpoints
`<xcep_path>/{ca_id}` and `<wstep_path>/{ca_id}`. The base paths without an id
return `404` — a request has to say which CA it wants, because "issue me a
certificate" says nothing about who should sign it. An unknown CA is `404` and a
disabled one `503`.

OCSP is the exception and needs no id: the request already names its issuer, so the
shared `/ocsp` matches the request's CertID against this instance's CAs. Disabling a
CA stops issuance but not publication — its CRL and OCSP answers keep being served,
because refusing them would make everything it ever signed unverifiable.

**ACME is virtualized too:** every route is mirrored under
`<ACME_BASE_PATH>/{ca_instance_id}/...`. Because every advertised ACME URL is built
from a per-request base, prefixing that base with the instance threads the whole
flow (directory → account → order → authz → challenge → finalize) through that
CA instance, and `finalize` issues from that instance's CA and tags the cert with
its `ca_instance_id`. An unknown/disabled instance's directory returns `404`/`503`.

**SCEP is virtualized too** under `<SCEP_PATH>/{ca_instance_id}`
(a trailing segment like CMP's `/cmp/{id}`): SCEP
secures the message rather than the channel, so every crypto step (GetCACert,
envelope decryption, CertRep signing, issuance) is bound to a per-request state
holding the instance's CA pair; the issued cert is tagged with its
`ca_instance_id`. Unknown/disabled instances get `404`/`503`.

**CMP is virtualized too** under `/cmp/{ca_instance_id}`: the handler
swaps the SRV_CTX's signer to the instance's CA for the transaction (cached per
instance, serialized by the existing mutex), so the cert is issued by *and the
CMP response is signed by* that instance's CA, and is tagged with its `ca_instance_id`.

**OCSP is virtualized too** under `/ocsp/{ca_instance_id}`: one `fastpki-ocsp`
answers for many CA instances, each
response signed by **that instance's CA** via a per-instance `Responder` (cached,
built from the resolved instance material). Unknown/disabled instances get `404`/`503`.

**Per-CA CRLs too:** `GET <CRL_PATH>/{id}` returns that instance's CRL —
only *its* revoked certs (`get_revoked_certs` is scoped by `ca_instance_id`),
signed by *its* CA, cached per instance. The canonical URL is `GET /{ca_id}.crl`;
the id-less `CRL_PATH` alias answers `404` (`use /{ca_id}.crl`), since no CA is the
default. SCEP `GetCRL` is per-instance as well.
**Per-CA routing covers status, issuance and revocation on every protocol that enrols
or answers for a certificate: EST, ACME, SCEP, CMP, MS-XCEP/WSTEP and OCSP.**

**CA-scoped access control.** A console user can be confined to a set of CAs: the
confinement is the scope on its roles' CA grants (`role_permissions.scope`, set from the
console's role editor or `POST /api/roles`; `*` means every CA — see [rbac.md](rbac.md)
§4). A scoped caller only sees and can act on its own CAs' certificates: the inventory,
search, certificate detail, revocation and the compliance report are all filtered, and a
certificate outside the scope is `404` on both read and revoke — hidden rather than merely
refused. The audit log and the discovery inventory carry no per-CA partition, so a scoped
caller is refused them (`403`). The inventory shows each cert's owning CA.

**Multi-DC CA registry:** CA rows replicate across data centers with the rest of the
certificate inventory, but `fastpki-mesh` publishes `certs` through a **column list**
that carries the CA's identity and certificate and **omits `certs.private_key`** — so a
CA defined in one data center is visible everywhere while the reference to its signing key
stays on the node that holds it. Every node has its own token; a CA key reaches another
node's token only by `fastpki-ca key replicate`, and only when it was generated replicable.
`resolve_ca_instance` pins cert and key *together*: a node that has a CA's cert but not a
key for it reports the instance not-servable (the per-CA endpoints return `503`) rather
than signing with the wrong key.

**Multi-CA dashboard.** The console has a **CAs** tab and a small
control-plane API over the CA registry — the HTTP twin of
`fastpki-ca`. `GET /api/ca-instances` (`ca:read`) lists every registered CA the caller may
see, each annotated with:

- `kind` — `root` when the certificate is self-signed (its signature verifies under its
 own key) and `intermediate` otherwise, so a self-issued certificate signed by a previous
 key reads as `intermediate`. Only when the stored certificate cannot be
 parsed does it fall back to `root` / `sub` from the registered parent;
- `keyLocation` — `HSM` when the row carries a key reference at all, `none` when it carries
 none (an offline root, or a verify-only trust anchor). It does **not** say whether this
 node's token holds the key;
- `signable` — whether **this node** can sign with the CA: `false` with no key reference,
 and `false` when the reference names a token object this node's token does not hold,
 which is the ordinary state of a mesh peer replicating a CA it cannot sign for. When the
 token cannot be read at all, `signable` is `true` rather than a guess of "no";
- the certificate's subject, issuer, serial, key and signature algorithms, fingerprints and
 validity, a live count of issued certs, and whether the certificate is revoked or expired.

`POST /api/ca-instances` creates a root or Sub-CA — it generates the key **inside the
token** (a CA private key is always a `pkcs11:` handle), builds a self-signed or
parent-signed CA cert, and stores that certificate as its `certs` row; nothing is written
to disk. With `cert_pem` it registers an existing CA instead (see "The first CA").
`POST /api/ca-instances/<id>/status` enables/disables one. Both writes need `ca:manage`
and `WEB_ALLOW_REVOKE`, and are audited (`web_ca_created` / `web_ca_imported` /
`web_ca_status`); creating or importing a CA additionally requires an *unscoped* caller,
while a CA-scoped caller may only see and toggle CAs in its own scope. The inventory has a
**pivot-by-CA** filter (`/api/certs?ca=<id>`).

