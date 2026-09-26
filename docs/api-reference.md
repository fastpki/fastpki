# FastPKI Web Console — API Reference

Base URL: `https://<PKI_DNS>:<WEB_PORT>` (default port 8090). The console serves plain HTTP
when no TLS certificate is configured for it.

Requests carry their parameters as `application/x-www-form-urlencoded` fields or as query
parameters unless a route says otherwise. Responses are JSON unless a route says otherwise, and
an error is `{"error":"<message>"}`.

## Contents

- [Conventions](#conventions)
- [1. Sign-in and session](#1-sign-in-and-session)
- [2. OIDC single sign-on](#2-oidc-single-sign-on)
- [3. SAML 2.0 single sign-on](#3-saml-20-single-sign-on)
- [4. Certificates](#4-certificates)
- [5. Audit log](#5-audit-log)
- [6. Discovery](#6-discovery)
- [7. Compliance and notifications](#7-compliance-and-notifications)
- [8. MS certificate templates](#8-ms-certificate-templates)
- [9. Users and roles](#9-users-and-roles)
- [10. Directories and identity providers](#10-directories-and-identity-providers)
- [11. Certificate profiles](#11-certificate-profiles)
- [12. Approved domains](#12-approved-domains)
- [13. CA instances](#13-ca-instances)
- [14. The token](#14-the-token)
- [15. Configuration](#15-configuration)
- [16. Endpoints, restarts and client configurations](#16-endpoints-restarts-and-client-configurations)
- [17. Backup and restore](#17-backup-and-restore)
- [18. PostgreSQL TLS](#18-postgresql-tls)
- [19. System](#19-system)
- [Summary Table](#summary-table)

---

## Conventions

### Who is calling

The console decides who a request comes from in this order:

1. **Open mode.** When `WEB_TOKEN` is empty and no console user exists, every `/api/` route is
   served without authentication and without a permission check. This is how the first
   administrator is created (`POST /api/users`). Open mode ends as soon as a user exists.
2. **Client certificate** (when `WEB_CLIENT_CA` is set). A certificate this deployment issued
   is looked up by serial: it must be valid, and it must name the owner recorded when it was
   issued — its CN equals the owner, or, for a directory or SSO owner `corp\alice`, its CN is
   `alice` and its domainComponent `corp`. The caller is that owner's user row. A certificate
   from a foreign anchor
   (`WEB_CLIENT_CA_BUNDLE`) has no row here and maps to the user `dn\<CN>`.
3. **Session cookie** `fastpki_session`: `HttpOnly; Path=/; Max-Age=43200` (12 hours), plus
   `Secure` when the console serves TLS. `SameSite=Strict` after a password login,
   `SameSite=Lax` after an OIDC or SAML login. The session also ends after 15 minutes without
   a request. A request without a valid session gets `401` with the header
   `X-FastPKI-Login: required`. Every response carries `Cache-Control: no-store`.
4. **Bearer token** `Authorization: Bearer <WEB_TOKEN>`: the caller is `api-token` and holds
   the `admin` role.

Any other request to a gated route is refused with `401` `{"error":"unauthorized"}`.

### Routes that need no authentication

- every path outside `/api/`: `GET /` and `GET /healthz`
- `POST /api/login`
- `GET /api/auth-domains` and `GET /api/auth-idps`
- everything under `/api/oidc/` and `/api/saml/`

### Permissions

Every other `/api/` route names the permissions it needs, and the **Auth** line of each route
below lists them. A caller passes when its effective roles — the role on its user row, plus
every role bound to its user name or to one of its session's directory groups — grant **any**
of the listed permissions, or `*:*`. `ca:manage` also satisfies `ca:read`, and `hsm:manage`
satisfies `hsm:read`. A route with no mapping needs `*:*`. "Any authenticated caller" means no
permission is needed.

This check matches permission names only. Scopes are applied by the route handlers: a role
confined to some CAs sees and acts on those CAs only, a `cert:read` or `cert:revoke` grant
scoped `own` reaches the caller's own certificates only, and the profile and template editors
check the grant's scope against the name being written. [rbac.md](rbac.md) describes the model.

A refusal is `403` `{"error":"forbidden: roles [<roles>] lack <permission> for <path>"}`.

A session whose password must be reset may reach only `GET /api/me`, `POST /api/password` and
`POST /api/logout`; every other route answers `403` `{"error":"password reset required"}`.

### Built-in roles

| Role | Grants |
|------|--------|
| `admin` | `*:*` and every other permission at scope `*`, except `profile:use`, which is scoped to the `admin` profile |
| `auditor` | `audit:read`, `hsm:read`, `self:manage` |
| `requester` | `cert:read` and `cert:revoke` scoped `own`, `cert:request`, `ca:read`, the five `<protocol>:enrol` permissions, `profile:use` on the `requester` profile, `template:use` on `GenericUser`, `Email` and `GenericComputer`, `self:manage` |
| `none` | nothing; the caller reaches only `GET /api/me`, `GET /api/start-time` and `POST /api/logout` |

### Write gate

A route marked "requires `WEB_ALLOW_REVOKE=true`" answers `403`
`{"error":"console writes disabled (set WEB_ALLOW_REVOKE=true)"}` while that setting is false
(the revoke route says `revocation disabled` instead). The console reads the setting when it
starts. `GET /api/me` reports it as `writeEnabled`.

Reads are never write-gated, and neither are `POST /api/login`, `POST /api/logout`,
`POST /api/password`, `POST /api/backup`, `POST /api/db-backup`,
`POST /api/directory-groups/<group>/refresh` and `POST /api/client-config/<kind>/preview`.

### Request size

A request body may be at most 1 MB, except on `POST /api/backup/restore` and
`POST /api/db-backup/restore`, which accept 64 MB. A larger declared body is refused with `413`
`{"error":"request body too large"}` before authentication.

---

## 1. Sign-in and session

### POST /api/login

Authenticate with a user name and password and create a session.

**Auth:** none

**Parameters:** `username`, `password`. A directory user may qualify the name with the
directory (`CORP\alice`).

The password is first checked against the local `web_users` row. When that does not
authenticate the caller and `AUTH_BACKEND` is not `local`, the configured directories are
asked; the session then belongs to the provider-qualified subject the directory returns, and
its role is resolved as for an OIDC or SAML login (the local row, or `none` for a new identity,
which is stored so an administrator can grant it a role).

**Response:**
- `200` `{"user":"<name>","role":"<role>","mustReset":bool}` with the session cookie
- `401` `{"error":"invalid credentials"}`
- `429` too many failed attempts for this account or address; `Retry-After` gives the wait in
  seconds
- `501` `{"error":"local login not configured"}` — no user exists and `AUTH_BACKEND` is `local`

**Audit:** `web_login`, `web_login_fail`, `web_login_throttled`

---

### POST /api/logout

Destroy the session and clear the cookie.

**Auth:** any authenticated caller

**Response:** `200` `{"ok":true}` with `Set-Cookie: fastpki_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`

---

### POST /api/password

Change your own password. Needs a session cookie and a local user row. Works in a session that
must reset its password, clears that flag, and ends every other session of the same user.

**Auth:** `self:manage`

**Parameters:** `old` (current password), `new` (at least 8 characters)

**Response:**
- `200` `{"ok":true}`
- `400` new password too short, or the user has no local row
- `401` no session cookie, or the current password is wrong
- `500`

**Audit:** `web_password_changed`

---

### GET /api/me

The caller's identity, roles, permissions and the console's login and write state.

**Auth:** any authenticated caller

**Response:** `200`
```json
{
  "user": "<name>",
  "role": "<primary role>",
  "roles": ["<effective role>"],
  "groups": ["<provider>\\<group>"],
  "capabilities": ["<permission>"],
  "loginRequired": true,
  "mustReset": false,
  "writeEnabled": true
}
```

- `roles` — the effective roles: the primary role plus roles bound to the user or its groups
- `groups` — present for a session only: the directory groups the session authenticated with
- `capabilities` — the permissions those roles grant; the console shows its pages and buttons
  from this list
- `loginRequired` — whether any console user exists (false for a client-certificate caller)
- `writeEnabled` — the value of `WEB_ALLOW_REVOKE`

In open mode the answer is `user` `anonymous`, `role` `admin`, `roles` `["admin"]` and
`capabilities` `["*:*"]`. With the bearer token `user` is `api-token`.

---

### GET /api/auth-domains

The enabled directories, for the sign-in page's domain picker.

**Auth:** none

**Response:** `200` `[{"id":"<id>","display_name":"<name>"}]` — the display name falls back to
the id. An unreadable database yields `[]`.

---

### GET /api/auth-idps

The enabled SAML and OIDC providers, for the sign-in page's buttons, ordered by priority and
then id.

**Auth:** none

**Response:** `200` `[{"id":"<id>","kind":"saml|oidc","display_name":"<name>"}]`

---

## 2. OIDC single sign-on

A federated login's user name is `<provider id>\<asserted name>`. Its role is the role on a
local user row of that name. Without such a row, a provider that sets `require_local_user`
refuses the login; otherwise the role is `admin` or `auditor` when the provider's
`admin_group` or `auditor_group` is among the asserted groups, and else `none`, in which case
the identity is stored so an administrator can grant it a role. The asserted groups travel in
the session.

### GET /api/oidc/status

**Auth:** none

**Response:** `200` `{"enabled":bool}` — whether an enabled OIDC provider exists

---

### GET /api/oidc/login

Start the authorization code flow with PKCE.

**Auth:** none

**Parameters:** `provider` (optional provider id; the first enabled OIDC provider otherwise)

**Response:**
- `302` to the identity provider
- `404` (text) no enabled OIDC provider, or none with that id
- `502` (text) the provider's discovery document could not be fetched

---

### GET /api/oidc/callback

The redirect target. Checks the state, exchanges the code with the provider that started the
flow, resolves the role and creates the session (`SameSite=Lax`).

**Auth:** none

**Parameters:** `state`, `code`, `error` (optional)

**Response:**
- `302` to `/` on success
- `302` to `/?sso_error=<reason>`: the provider's own `error`, `provider_gone` (the provider is
  disabled or deleted), `login_failed`, `no_local_user`
- `400` (text) unknown or expired state
- `404` no OIDC provider is enabled

**Audit:** `web_login` / `web_login_fail`

---

## 3. SAML 2.0 single sign-on

### GET /api/saml/status

**Auth:** none

**Response:** `200` `{"enabled":bool}` — whether an enabled SAML provider exists

---

### GET /api/saml/metadata

The service provider metadata of the first enabled SAML provider.

**Auth:** none

**Response:** `200` `Content-Type: application/samlmetadata+xml`; `404` (text) no SAML provider;
`500` (text)

---

### GET /api/saml/login

Build an AuthnRequest and redirect to the identity provider.

**Auth:** none

**Parameters:** `provider` (optional provider id; the first enabled SAML provider otherwise),
`RelayState` (optional, defaults to `/`)

**Response:**
- `302` to the identity provider's SSO URL
- `404` (text) no enabled SAML provider, or none with that id
- `502` (text) the AuthnRequest could not be built

---

### POST /api/saml/acs

Assertion Consumer Service. Verifies the signed response against the certificate of the
provider whose request it answers, resolves the role as for OIDC and creates the session
(`SameSite=Lax`).

**Auth:** none

**Parameters:** `SAMLResponse` (base64), `RelayState` (optional)

**Response:**
- `302` to `RelayState` when it is a same-site path, else to `/`
- `302` to `/?sso_error=login_failed` or `/?sso_error=no_local_user`
- `404` no SAML provider is enabled

**Audit:** `web_login` / `web_login_fail`

---

## 4. Certificates

### GET /api/certs

The certificate inventory. Registered CAs' own certificates are not listed; cross-certificates
are.

**Auth:** `cert:read` — a grant scoped `own` lists the caller's own certificates only

**Parameters:**
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 100 | 1–500 |
| `offset` | int | 0 | 0–1000000 |
| `q` | string | — | case-insensitive substring of cn, owner, subject, serial or any SubjectAltName. A value that is only hex digits (with spaces, colons or dashes between them, as fingerprints are printed) also matches the SHA-1 and SHA-256 fingerprints and the RFC 4387 selector hashes `sHash`, `iHash`, `iAndSHash` and `sKIDHash` |
| `status` | int | -2 | -2 any, -1 revoked (on hold included), 0 valid, 1 expired, 2 pending, 3 superseded |
| `sort` | string | notBefore | `cn`, `owner`, `serial`, `status`, `notAfter`, `notBefore` |
| `order` | string | desc | `asc` or `desc` |
| `ca` | string | — | CA instance id |

**Response:** `200` JSON array. When any of `q`, `status`, `sort` or `ca` is sent, the
`X-Total-Count` header carries the number of matches before paging.
```json
[{
  "serial": "<hex>",
  "crossCert": true,
  "cn": "<cn>",
  "subject": "<subject>",
  "owner": "<owner>",
  "ownerKind": "user|computer",
  "status": 0,
  "statusText": "valid",
  "notBefore": "<RFC 3339>",
  "notAfter": "<RFC 3339>",
  "caInstance": "<CA id>",
  "certId": "<service id, or empty>",
  "fingerprint": "<SHA-256 hex>"
}]
```

`crossCert` appears only on a cross-certificate, `ownerKind` only when the row has an owner.
`statusText` is one of:

- `valid`
- `expired`
- `revoked`
- `on_hold` — revoked with reason certificateHold, which can be released
- `pending` — CMP issued it and is waiting for the client's certConf
- `superseded` — a service certificate replaced by a newer one

---

### GET /api/certs/<serial>

Full detail of one certificate. The serial is hex, case- and leading-zero-insensitive.

**Auth:** `cert:read` — `own` scope as for the list

**Response:** `200`
```json
{
  "serial": "<hex>",
  "cn": "<cn>",
  "subject": "<subject>",
  "subjectDn": "/CN=.../O=...",
  "issuer": "/CN=...",
  "owner": "<owner>",
  "ownerKind": "user|computer",
  "status": 0,
  "statusText": "valid",
  "revocationReason": 0,
  "revocationDate": "",
  "notBefore": "<RFC 3339>",
  "notAfter": "<RFC 3339>",
  "keyAlgo": "RSA",
  "keyBits": 2048,
  "sigAlgo": "sha256WithRSAEncryption",
  "sans": "dns:host.example.org,ip:10.0.0.5",
  "certId": "<service id, or empty>",
  "caInstanceId": "<CA id>",
  "keyRef": "<pkcs11: URI, or empty>",
  "fingerprint": "<SHA-256 hex>",
  "fingerprintSha1": "<SHA-1 hex>",
  "pem": "<PEM>",
  "text": "<decoded certificate>"
}
```

- `sans` — one comma-joined string of `type:value` entries: `dns`, `ip`, `email`, `uri`, `upn`,
  or `othername:<oid>;<value>`
- `revocationReason` — the RFC 5280 reason code as an integer; `revocationDate` is empty until
  the certificate is revoked
- `keyRef` — the token key the certificate uses: for a listener or RA credential the key its
  setting names, otherwise the handle recorded at issuance. Any PIN in the URI is redacted.

`404` when the serial is unknown or outside the caller's scope.

---

### POST /api/certs/<serial>/revoke

Revoke a certificate, or put it on hold. Revoking a CA's own certificate also revokes that CA's
other generations that the caller could revoke directly.

`certificateHold` (6) puts the certificate on hold: it is revoked until
`POST /api/certs/<serial>/release`. A certificate on hold can still be revoked for good with any
other reason. Every other reason is final.

**Auth:** `cert:revoke` — a grant scoped `own` reaches the caller's own certificates only;
requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `reason` (int, default 0)
| Value | Reason |
|-------|--------|
| 0 | unspecified — carried as no reason code in the CRL and in OCSP |
| 1 | keyCompromise — for an end-entity certificate |
| 2 | cACompromise — for a CA certificate |
| 3 | affiliationChanged |
| 4 | superseded |
| 5 | cessationOfOperation |
| 6 | certificateHold — can be released |
| 9 | privilegeWithdrawn |

`removeFromCRL` (8) is refused: a delta CRL uses it to announce a released hold. `aACompromise`
(10) is refused: it applies to attribute certificates. So are 7 and anything outside 0–10. The
same rule applies to CMP, ACME and the MCP tool.

**Response:**
- `200` `{"serial":"<hex>","status":"revoked|on_hold","reason":<int>}`
- `200` `{"serial":"<hex>","status":"revoked|on_hold","alreadyRevoked":true}` — already
  revoked for good, or already on hold and `reason` is 6 again
- `400` a refused reason
- `403` the caller can read the certificate but may revoke only its own
- `404` unknown serial, or not visible to the caller
- `500`

**Audit:** `web_cert_revoked` (the detail lists every other generation revoked with it)

---

### POST /api/certs/<serial>/release

Release a hold: a certificate revoked with reason `certificateHold` becomes valid again, or
expired if it ran out meanwhile. OCSP answers `good` at once, full CRLs no longer list it, and
a delta CRL whose base is before the release lists it with reason `removeFromCRL`. For a CA's
own certificate, every generation of the CA that is on hold is released.

**Auth:** `cert:revoke`, on the same certificates the caller could revoke; requires
`WEB_ALLOW_REVOKE=true`

**Response:**
- `200` `{"serial":"<hex>","status":"valid|expired","released":true,"alsoReleased":["<hex>"]}`
- `403` the caller can read the certificate but may release only its own
- `404` unknown serial, or not visible to the caller
- `409` the certificate is not on hold
- `500`

**Audit:** `web_cert_hold_released` (the detail lists every other generation released with it)

---

### POST /api/certs/request

Issue a certificate for a PEM PKCS#10 request. The caller is recorded as the owner.

**Auth:** `cert:request`; requires `WEB_ALLOW_REVOKE=true`

**Request:** the body is the PEM request (it must contain `-----BEGIN`). Query parameters:

| Param | Description |
|-------|-------------|
| `ca_instance` | **required** — the signing CA id. There is no default CA. |
| `profile` | a profile the caller holds `profile:use` on; without it the profile is resolved from the caller's grants |
| `omit_aia`, `omit_crldp` | `true`/`1` to leave those extensions out, honoured only when the profile sets `manage_aia` / `manage_crldp` |
| `md` | signature digest, where the CA's key type allows a choice |

When `WEB_SELFSERVICE_IDENTITY_SUBJECT` is true and the profile does not set
`no_override_subject`, the subject is bound to the caller: CN is the user name, a DC
component names the provider of a directory or federated identity, and each session group
becomes an OU.

**Response:**
- `201` `{"serial":"<hex>","cn":"<cn>","pem":"<PEM>"}`
- `400` not a PEM request, no `ca_instance`, an invalid request, or a policy refusal
- `403` the CA is outside the caller's scope
- `404` unknown CA
- `409` the CA is disabled, revoked or expired
- `429` a role's issuance limit (certificate count, per-CN or SAN count) is reached
- `500` the CA's signing key could not be loaded

**Audit:** `web_cert_issued` / `web_cert_request_fail`

---

### POST /api/certs/request-hsm

Issue a certificate whose key is generated **inside the token** and never leaves it.

⚠️ Gated on `hsm:manage` rather than `cert:request`, and by route rather than by a
`keygen=true` parameter.

**Auth:** `hsm:manage`; requires `WEB_ALLOW_REVOKE=true`

**Request:** `application/x-www-form-urlencoded` or `multipart/form-data`.

| Parameter | |
|---|---|
| `ca_instance` | **Required.** Signing CA id. |
| `keyref` | **Required.** The **token object** to generate the key into, or to adopt, e.g. `pkcs11:token=fastpki;object=ocsp-ra;type=private?pin-source=/var/pki/tls/pin`. There is no server-side default. |
| `keygen` | `false`/`0` adopts a key already at `keyref`; any other value, or none, generates a new one. |
| `key`, `bits`, `curve` | Key algorithm (default `rsa`), RSA size (default 3072) and EC curve. |
| `overwrite` | `true` to destroy an existing object at `keyref` before generating the key. A key in use is refused even so. |
| `replicable` | `true` to generate the key with CKA_EXTRACTABLE, so it can later be copied into another node's token. On an HA pair the OCSP responder, CMP RA and SCEP RA keys need it. Requires a generated key; a `400` otherwise. |
| `cn`, `o`, `ou`, `c`, `st`, `l`, `email` | Subject fields. `cn` is required unless the subject is bound to the caller, as for `POST /api/certs/request`. |
| `sans` | Subject alternative names, one per line or comma-separated. |
| `ku`, `eku` | Comma-separated key usages. **These are the caller's choice, not derived** — an OCSP responder needs `OCSPSigning`. An `OCSPSigning` EKU adds id-pkix-ocsp-nocheck. |
| `profile`, `md` | As for `POST /api/certs/request`. |
| `omit_aia`, `omit_crldp` | `true` to leave those extensions off, where the profile allows it. |
| `custom_extensions` | JSON array of `{oid, value, critical}`, filtered by the profile's `allowed_custom_extensions`. |
| `cert_id` | What makes this a **service credential**. |
| `rekey` | With `cert_id`: generate a new key at a different handle and repoint the service's key setting to it. |

**`cert_id` values.** A listener's id — `web`, `est`, `acme` or `ms`, the values of
`WEB_CERT_ID`, `EST_CERT_ID`, `ACME_CERT_ID` and `MS_CERT_ID` — is scoped to this node by the
server (`web` becomes `web-<DATACENTER_ID>`), and so is the object name in `keyref`. The `keyref`
must be the key that listener loads (`WEB_TLS_KEY`, `EST_KEY`, `ACME_KEY`, `MS_KEY`); another
handle is a `400` naming the expected one, unless `rekey=true`. An RA credential's id is its
prefix plus the CA id, and **the caller assembles it**: `ocsp-ra-<ca_id>`, `cmp-ra-<ca_id>` or
`scep-ra-<ca_id>` (the prefixes are `OCSP_RESPONDER_CERT_ID_PREFIX`, `CMP_RA_CERT_ID_PREFIX` and
`SCEP_RA_CERT_ID_PREFIX`). A SCEP RA credential must use an RSA key. When the service's key
setting is empty, a generated key is written to it.

Issuing under a `cert_id` marks the previous certificate for that id superseded (status 3).

A listener (console, EST, ACME, MS) serves a new certificate for the key it already holds
within 30 seconds; a certificate on a new key takes effect when the listener restarts.
The CLI issues the same set of credentials without a browser. Run it on the node itself:

```bash
# Compose
docker compose run --rm --no-deps --entrypoint fastpki-ca web \
    --config /app/config/bootstrap.conf renew-service-certs --create-missing --re-issue-self-signed

# Native / cloud
doas su -s /bin/sh fastpki -c 'fastpki-ca --config /etc/fastpki/bootstrap.conf \
    renew-service-certs --create-missing --re-issue-self-signed'
```

deployment.md §4.4a covers both routes.

**Response:**
- `201` `{"serial","cn","pem","keyref","cert_id"}`, plus `"repointed":"<setting>"` and
  `"repointWasUnset":bool` when a key setting was written
- `400` invalid request, policy refusal, wrong handle, unsupported algorithm, key generation
  failure
- `403` the CA is outside the caller's scope
- `404` unknown CA, or no key at `keyref` to adopt
- `409` the CA is not active, or a key already exists at `keyref` (`"handleTaken":true`), or the
  key to overwrite is in use
- `429` a role's issuance limit is reached
- `500`
- `502` a key may exist at `keyref` but could not be read

**Audit:** `web_cert_issued_hsm`, `web_cert_request_hsm_fail`; `web_config_set_rekey` when a key
setting is written

---

### GET /api/cert-algos

Counts of non-revoked certificates by key algorithm, for the dashboard. CA certificates are
counted too.

**Auth:** `cert:read` — scoped to the caller's CAs, and to its own certificates under an `own`
grant

**Response:** `200` `[{"algo":"RSA","count":42},{"algo":"EC","count":7}]`, largest count first

---

### GET /api/my-profiles

The profiles the caller may issue under.

⚠️ Gated on `cert:request`, not `profile:edit`.

**Auth:** `cert:request`

**Response:** `200`
`{"default":"<profile or empty>","profiles":["<name>"],"manageAia":bool,"manageCrldp":bool}` —
`default` is the profile a request naming none is issued under: one profile's name, or the
names of several joined with `+` when they are combined (admin-guide §8.1). It is empty when
the caller holds no profile. `manageAia` and `manageCrldp` describe that profile.

---

### GET /api/enrolment-credentials · POST /api/enrolment-credentials

Read and rotate the caller's enrolment credentials: the key id, the CMP shared secret, the ACME
external account key and the SCEP challenge (`kid`, `cmp_secret`, `acme_eab_hmac`,
`scep_challenge`). The GET creates them when the caller's roles allow enrolment and they are
missing.

- `GET ?summary=1` returns only `{"username","enrolment":true|false}` — no secret.
- `GET ?summary=1&username=<other>` does the same for another user; needs `user:manage`.
  A full read is always the caller's own: another user's secrets cannot be read.
- `POST /api/enrolment-credentials` replaces all three secrets. `username=<other>` (with `user:manage`) rotates another
  user's, and the reply then carries no secret.

**Auth:** `cert:request` or `self:manage`; POST requires `WEB_ALLOW_REVOKE=true`

**Response:** `200`; `403` for another user without `user:manage`; POST also `409` (no role allows
enrolment), `500` · **Audit:** `enrolment_credentials_rotated`

---

### Enrolment codes: GET · POST /api/device-tickets · DELETE /api/device-tickets/<ticket>

One-time tickets for ACME device attestation (user-guide.md §6.5). A ticket lets one Mac, iPhone
or iPad enrol once, against one CA, with the certificate issued to its owner.

- **GET** lists the newest 500: `[{"ticket","source","ca","owner","profile","created","expires",
  "state","device_serial","certificate"}]`. `state` is `unused`, `in progress`, `used` or
  `expired`; `ticket` is the full value only while `unused`, otherwise its first 8 characters.
  `source` is `serial` for the ticket an order by a registered serial got.
- **POST** issues one: `ca`, `owner`, optional `profile` and `ttl` (seconds, default 604800).
  It refuses (`400`) when the CA does not exist, when `owner` holds no `acme:enrol` for it, or
  when the profile does not apply. Returns `{"ticket","expires","ca","owner"}`, or with
  `format=mobileconfig` the finished Apple ACME profile for the owner as a file, signed as
  `GET /api/client-config/<kind>` describes.
- `DELETE /api/device-tickets/<ticket>` cancels an unused ticket; `404` when it is unknown or
  already used.

**Auth:** `user:manage`; POST and DELETE require `WEB_ALLOW_REVOKE=true` · **Audit:**
`acme_device_ticket_issued`, `acme_device_ticket_cancelled`

### Enrolment codes: GET · POST /api/device-serials · DELETE /api/device-serials/<serial>

The device serial numbers an MDM fleet enrols by, without tickets: the profile's
`ClientIdentifier` is the device's serial, and Apple attests it. Replicated across a mesh.

- **GET** lists them: `[{"serial","ca","owner","profile","created"}]`.
- **POST** adds one (`serial`, `ca`, `owner`, optional `profile`) or many (`csv`: one
  `serial[,owner[,profile]]` per line, where `ca`, `owner` and `profile` fill in what a line
  leaves out; blank lines and lines starting with `#` are skipped). Each is checked like a
  ticket: a serial of 6 to 40 letters and digits, a CA that exists, an owner with `acme:enrol`
  for it, a profile that applies. Returns `{"added":n,"errors":[{"line","error"}]}`; a single
  serial that is refused answers `400` with the reason.
- `DELETE /api/device-serials/<serial>?ca=<ca-id>` removes one; `404` when it is not listed.

**Auth:** `user:manage`; POST and DELETE require `WEB_ALLOW_REVOKE=true` · **Audit:**
`acme_device_serials_added`, `acme_device_serial_removed`

### Enrolment codes: GET · POST /api/scep-challenges · DELETE /api/scep-challenges/<token>

SCEP one-time challenges, issued to the SCEP identity (`scep`) and optionally bound to a profile.

- **GET** lists the newest 500: `[{"token","profile","created","expires","state"}]`, with the token
  in full only while `unused`.
- **POST** issues one: optional `profile` and `ttl` (seconds, default 3600). Refuses (`400`) when
  the SCEP identity has no profile that applies. Returns `{"token","expires","accepted"}`, and a
  `warning` when `SCEP_DYNAMIC_CHALLENGE` is off, because the SCEP service then refuses it.
- `DELETE /api/scep-challenges/<token>` cancels an unused challenge.

**Auth:** `user:manage`; POST and DELETE require `WEB_ALLOW_REVOKE=true` · **Audit:**
`scep_challenge_issued`, `scep_challenge_cancelled`

---

## 5. Audit log

The audit trail is deployment-wide and carries no per-CA partition, so a caller confined to
some CAs is refused both routes with `403`.

### GET /api/audit

The hash-chained audit log, newest first.

**Auth:** `audit:read`

**Parameters:** `limit` (1–500, default 100), `offset` (default 0)

**Response:** `200`
```json
[{
  "seq": 12345,
  "ts": "<RFC 3339 time, UTC>",
  "category": "pki_lifecycle",
  "action": "web_cert_revoked",
  "actor": "alice",
  "actorKind": "user",
  "actorIp": "192.0.2.1",
  "target": "<serial>",
  "status": "success",
  "detail": "iface=web reason=4",
  "hash": "<SHA-256>"
}]
```

- `ts` — RFC 3339, UTC
- `category` — `auth`, `pki_lifecycle`, `config` or `key_mgmt`
- `actorKind` — `user` or `computer`, present only when there is an actor
- `status` — `success` or `failure`

---

### GET /api/audit/export-signed

The audit log as NDJSON with a signature by a named CA over `<head_seq>:<sha256>`, verified by
`fastpki-audit verify-export`.

**Auth:** `audit:read`

**Parameters:** `ca_instance` (**required**, the signing CA), `after` (int, sequence number;
default 0 = the whole log)

**Response:** `200`
```json
{
  "sha256": "<hex>",
  "head_seq": 100,
  "count": 50,
  "signed_at": 1700000000,
  "signer": "<CA CN>",
  "signature": "<base64>",
  "ndjson": "<NDJSON>"
}
```

Each NDJSON line: `{"seq","ts","category","action","actor","actor_ip","target","status","detail","prev_hash","hash"}`,
with `ts` in Unix seconds.

`400` no `ca_instance`; `403` a CA-scoped caller, or the CA outside the caller's scope; `404`
unknown CA; `503` the CA cannot sign (not active, or its key is unavailable); `409` the audit
chain does not verify.

---

## 6. Discovery

The discovery inventory is deployment-wide, so a caller confined to some CAs is refused
`GET /api/discovered` and `GET /api/discovered/<id>/cert-text` with `403`.

### GET /api/discovered

Certificates found by discovery scans.

**Auth:** `ca:manage`

**Parameters:** `limit` (1–500, default 100), `offset` (default 0)

**Response:** `200`
```json
[{
  "id": 1,
  "target": "host:port",
  "subject": "<subject>",
  "issuer": "<issuer>",
  "keyAlgo": "<algo>",
  "keyBits": 2048,
  "sigAlgo": "<algo>",
  "notAfter": "<RFC 3339>",
  "fingerprint": "<SHA-256 hex>",
  "flags": "<flags>",
  "discoveredAt": "<RFC 3339>"
}]
```

---

### GET /api/discovered/<id>/cert-text

The decoded text of a discovered certificate.

**Auth:** `ca:manage`

**Response:** `200` text/plain; `404` no stored certificate; `500` it could not be decoded

---

### POST /api/discover

Run a discovery scan with `fastpki-discover` (`DISCOVER_BIN`) and wait for it.

**Auth:** `*:*`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `targets` (or the raw body) — `host:port` or `CIDR:port` entries separated by
commas, newlines, spaces or tabs; at most 64, each at most 128 characters of letters, digits and
`. : / - _`

**Response:**
- `200` `{"scanned":<targets>,"rc":0,"found":<int>,"flagged":<int>,"unreachable":<int>}`
- `400` no targets, too many, an invalid target, or `{"error":"scan failed: <reason>","rc":2}`
  when the scanner refuses a target (for example a range too large to expand)
- `500` the scanner is missing, could not be started, or failed:
  `{"error":"scan failed: <reason>","rc":<int>}`

**Audit:** `web_discovery_scan`

---

## 7. Compliance and notifications

### GET /api/compliance

Weak-key, weak-signature and expiry report over the non-revoked certificates.

**Auth:** `cert:read` — scoped to the caller's CAs, and to its own certificates under an `own`
grant

**Parameters:** `days` (1–3650, default 30) — the expiring-soon window

**Response:** `200`
```json
{
  "generated": "<RFC 3339>",
  "scanned": 1000,
  "expiringWindowDays": 30,
  "counts": {"weakKey": 5, "weakSig": 2, "expiringSoon": 12, "expired": 3},
  "certificates": [{"serial","cn","owner","keyAlgo","keyBits","sigAlgo","notAfter","daysLeft","flags"}]
}
```

`flags` is a comma-joined string of `weak_key` (RSA below 2048 bits, EC below 256),
`weak_sig` (SHA-1 or MD5), `expired` and `expiring_soon`. Only flagged certificates are listed.

---

### GET /api/notify

A preview of what `fastpki-notify` would report, using the stored `NOTIFY_DAYS` and
`NOTIFY_WEBHOOK`, with the stored email settings and template.

**Auth:** `config:manage` — scoped to the caller's CAs

**Response:** `200`
```json
{
  "days": [30, 14, 7],
  "webhook": "(set)",
  "webhookFormat": "json",
  "email": {"server": "mail.example.org:587", "tls": "starttls", "user": "pki",
            "password": "(set)", "from": "pki@example.org", "caFile": "",
            "fallback": "pki-team@example.org"},
  "template": {"subject": "…", "line": "…", "body": "…", "custom": false},
  "counts": {"expired": 3, "critical": 5, "warning": 7, "info": 12},
  "items": [{"serial","cn","owner","notAfter","daysLeft","bucket","replaced"}]
}
```

`webhook` is `(set)` or empty; `webhookFormat` is the stored `NOTIFY_WEBHOOK_FORMAT` (`json`,
`slack` or `teams`). A certificate lands in the tightest window it fits: the smallest
is `critical`, the widest `info`, anything between `warning`. `email` holds the stored relay
keys, with `password` only `(set)` or empty. `template` is the stored email template, or the
built-in one with `custom` false. `replaced` is true when the owner holds a newer valid
certificate with the same subject and names, so no email is sent about this one.

---

### PUT /api/notify/template · DELETE /api/notify/template

Store the expiry email template, or delete it to return to the built-in one. The template is a
row of the replicated `notify_templates` table.

**Auth:** `config:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters (PUT):**
| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `subject` | string | yes | the subject line |
| `line` | string | yes | the line written for each certificate |
| `body` | string | yes | the message; must contain `{{certificates}}` |

**Response:** `200` `{"ok":true}`; `400` a part is missing, or the body has no `{{certificates}}`

**Audit:** `web_notify_template_set` / `web_notify_template_reset`

---

### POST /api/notify/test-email

Send one test message through the stored relay settings.

**Auth:** `config:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:**
| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `to` | string | yes | one email address |

**Response:**
- `200` `{"ok":true}` — the relay accepted the message
- `400` `to` is not one address, or `SMTP_SERVER` is not set
- `502` the relay could not be reached, failed TLS or certificate verification, refused the
  credentials or refused the message; `error` says which

**Audit:** `web_notify_test_email`

---

## 8. MS certificate templates

The template routes check the grant's scope against the template name: a caller holding
`template:edit|GenericUser` sees and writes `GenericUser` only.

### GET /api/templates

The MS-XCEP/WSTEP templates the caller may edit: every stored template, disabled ones included,
plus the built-in templates while no stored template is enabled.

**Auth:** `template:edit`

**Response:** `200` JSON array of template objects with fields: `name`, `oid`, `schema`, `enroll`, `auto_enroll`, `validity_days`, `min_key_size`, `key_spec`, `key_usage`, `major_rev`, `minor_rev`, `private_key_flags`, `subject_name_flags`, `enrollment_flags`, `general_flags`, `pk_oid`, `pk_name`, `hash_oid`, `hash_name`, `crypto_providers`, `ekus`, `private_key_permissions`, `overlap_seconds`, `enabled`, `builtin`

---

### POST /api/templates

Create or update one template. Fields not sent keep their stored value.

**Auth:** `template:edit` covering the name; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `name` and `oid` (required), plus optional `schema`, `validity_days`, `min_key_size`, `key_spec`, `key_usage` (decimal or `0x` hex), `major_rev`, `minor_rev`, `private_key_flags`, `subject_name_flags`, `enrollment_flags`, `general_flags` (the four flags accept `0x` hex), `pk_name`, `pk_oid`, `hash_name`, `hash_oid`, `crypto_providers` (pipe-separated), `private_key_permissions`, `overlap_seconds` (-1 derives one), `ekus` (pipe-separated), `enroll`, `auto_enroll`, `enabled`

**Response:** `200` `{"name":"<name>"}`; `400` name or oid missing; `403` no grant covers the
name; `500`

**Audit:** `web_template_saved`

---

### GET /api/templates/ad

Read certificate templates from Active Directory without importing them. Queries every
**enabled** directory, so it needs at least one configured on the Directories page.

**Auth:** `template:edit`

**Response:** `200` `{"templates":[…],"count":<int>}`; `502` no template could be read and a
directory reported an error; `501` the build has no LDAP support (the shipped image has it).

---

### POST /api/templates/ad

Import a chosen subset of the templates the directory holds.

**Auth:** `template:edit` covering every chosen name; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `name`, repeated once per template to import.

⚠️ The server **re-reads the templates from AD itself** rather than storing what the client
sent, so a request can select which templates are imported but cannot dictate their content.
A name the directory does not return on that read is a `409`, and nothing is imported.

**Response:** `200` `{"imported":<int>}`; `400` no name; `403` a name no grant covers; `404`
the directory returned no templates; `409` a requested name is not among them; `500`; `501`
no LDAP support; `502` the directory could not be read.

**Audit:** `web_templates_imported`

---

### POST /api/templates/import

Import templates from CSV exported from Active Directory. Every row is checked before any is
written.

**Auth:** `template:edit` covering every row; requires `WEB_ALLOW_REVOKE=true`

**Request:** raw CSV body (first non-comment line is the header; `name` and `oid` required)

**Response:** `200` `{"imported":<int>}`; `400` the CSV does not parse; `403`; `500`

**Audit:** `web_templates_imported`

---

### DELETE /api/templates/<name>

Delete the stored template with that name.

**Auth:** `template:edit` covering the name; requires `WEB_ALLOW_REVOKE=true`

**Response:** `200` `{"deleted":"<name>"}`; `403`; `500`

**Audit:** `web_template_deleted`

---

## 9. Users and roles

### GET /api/users

The console users.

**Auth:** `user:manage` or `self:manage` — a caller without `user:manage` gets its own row only

**Response:** `200`
```json
[{
  "username": "<user>",
  "role": "<role>",
  "mustReset": false,
  "kind": "user|computer",
  "source": "local",
  "email": "<address or empty>"
}]
```

`source` is the provider recorded for the account (`local`, `ldap`, `oidc`, `saml`); an account
with none recorded reads `local` when it has a password and `external` otherwise. `email` is
where expiry emails for the account's certificates go when no directory gives an address.

---

### POST /api/users

Create or update a console user.

**Auth:** `user:manage`, or `self:manage` for your own password and email only; requires `WEB_ALLOW_REVOKE=true`

**Parameters:**
| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | yes | letters, digits and `- _ . @ $ / \`, max 64 chars |
| `email` | string | no | where expiry emails for the account's certificates go; empty clears it, omitted keeps it. A `self:manage` caller may send it without a password, and then nothing else changes |
| `password` | string | yes (new user) | min 8 chars, on a create and on an update; omit to keep the current password. Setting one ends the account's other sessions |
| `old` | string | yes (`self:manage` caller changing the password) | your current password |
| `role` | string | **yes** on a create, except the open-mode bootstrap | any role in the `roles` table; omitted on an update, the stored role is kept. The first user on a console in open mode is created as `admin`: open mode closes the moment it exists, so any lesser role locks the deployment out. |
| `create` | string | no | "1" to refuse when the name already exists (any case) |
| `mustReset` | string | no | "true" or "1" to force a password change. Refused when the account's roles do not grant `self:manage` |

**Response:**
- `201` (create) `{"username":"<user>","role":"<role>"}`
- `200` (update) `{"username":"<user>","role":"<role>"}`
- `400` invalid username, email, password, role or forced reset
- `401` wrong current password (`self:manage` caller)
- `403` a `self:manage` caller naming another account; changing your own role; a role granting
  permissions the caller does not hold
- `409` `create=1` and the name exists

**Audit:** `web_user_created` / `web_user_updated`

---

### DELETE /api/users

Delete a DB-backed user, with its enrolment credentials, the extra roles bound to its username,
and its open sessions. Cannot delete your own account.

**Auth:** `user:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `username` (string)

**Response:** `200` `{"username":"<user>","deleted":true}`; `400` no username, or your own
account; `403` without `user:manage`; `404` no such user; `500`

**Audit:** `web_user_deleted`

---

### GET /api/subject-roles

The extra roles bound to users and groups.

**Auth:** `user:manage`

**Response:** `200`
```json
[{
  "selector_type": "user|group",
  "selector_value": "<value>",
  "role": "<role>",
  "kind": "user|computer"
}]
```

`kind` appears on `user` selectors only.

---

### POST /api/subject-roles

Bind a role to a user or a directory group.

**Auth:** `user:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `selector_type` | string | `user` or `group` |
| `selector_value` | string | at most 512 characters; no control characters, and none of `<`, `>`, `"`, `'`, `&` or a backtick. A group is named `<directory>\<group>` |
| `role` | string | any role in the `roles` table except `none` |

The caller may bind only a role whose grants it holds. A `user` binding creates or removes that
user's enrolment credentials to match its roles. A `group` binding resolves the group's members
at once when a directory is configured.

**Response:** `201`
`{"selector_type","selector_value","role"}`, plus
`"directory":{"resolved":bool,"members":<int>,"error":"<message>"}` for a group when a directory
is configured (`error` only when the lookup failed); `400`; `403` the role grants more than the
caller holds; `500`

**Audit:** `subject_role_granted`

---

### DELETE /api/subject-roles

Remove a role binding. When the last binding of a group goes, its stored member list is deleted.

**Auth:** `user:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `selector_type`, `selector_value`, `role` (all required)

**Response:** `200` `{"deleted":true}`; `400`; `500`

**Audit:** `subject_role_revoked`

---

### GET /api/assignable-roles

Role names with `builtin` and `assignable` flags, for populating a role picker. `none` is
reported `assignable: false`.

**Auth:** `user:manage` or `role:manage`

**Response:** `200` `[{"name":"<role>","builtin":bool,"assignable":bool}]`

---

### GET /api/roles

Every role with its description, its builtin flag, any per-role ceilings
(`maxCerts`, `maxCn`, `maxSan`, each present only when set) and its `grants` array of
`{permission, scope}` pairs.

**Auth:** `role:manage` · **Response:** `200` JSON array

---

### POST /api/roles

Create or update a role's row: its description and issuance limits. Grants are set with
`POST /api/roles/<role>/permissions`.

**Auth:** `role:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `name` (alphanumeric with `. _ - @`, 64 max), `description`, `maxCerts`,
`maxCn`, `maxSan` (each optional; an empty value leaves the ceiling unset), `create` ("1" to
refuse a name that already exists)

**Response:** `201` `{"name":"<name>"}`; `400` invalid name or non-numeric ceiling; `409` the
name exists and `create=1` was sent; `500`

**Audit:** `role_upsert`

---

### POST /api/roles/<role>/permissions

Replace a role's grants with the list sent.

**Auth:** `role:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `grants` — one `permission|scope` per line; a line without `|` means scope `*`.

**Refused with `400`:** an unknown permission; a profile or template scope naming nothing that
exists; scope `own` on anything but `cert:read` and `cert:revoke`; any scope but `*` on a
permission with no scope (`self`, `user`, `role`, `audit`, `config`, `backup`, `hsm`).
**`409`:** removing `role:manage` from the last role that grants it. **`404`:** no such role.

**Response:** `200` `{"role":"<role>","grants":<int>}`

**Audit:** `role_permissions_set`

---

### DELETE /api/roles/<role>

Delete a custom role.

**Auth:** `role:manage`; requires `WEB_ALLOW_REVOKE=true`

**Response:** `200` `{"deleted":"<role>"}`; `404` no such role; `409` a built-in role, or the
last role granting `role:manage`; `500`

**Audit:** `role_delete`

---

### GET /api/permissions

The capability vocabulary — every permission string a grant may name. The list the role
editor offers, so a capability missing here cannot be granted through the console.

**Auth:** `role:manage` · **Response:** `200` JSON array of strings

---

## 10. Directories and identity providers

### GET /api/auth-providers

Every configured provider: LDAP directories, SAML and OIDC providers, each with `id`, `kind`
(`ldap`, `saml`, `oidc`), `display_name`, `enabled` and `priority`.

- **ldap:** `uris`, `base_dns`, `bind_dn`, `bind_pw_set`, `group_filter`, `group_attr`,
  `ca_cert_file`, `network_timeout_sec`, `template_base`, `netbios_name`, `dns_root`
- **saml:** `idp_entity_id`, `idp_sso_url`, `idp_cert`, `sp_entity_id`, `callback_url`,
  `username_attr`, `groups_attr`, `admin_group`, `auditor_group`, `clock_skew_sec`,
  `require_local_user`
- **oidc:** `issuer`, `client_id`, `client_secret_set`, `callback_url`, `scopes`,
  `username_claim`, `groups_claim`, `admin_group`, `auditor_group`, `ca_cert`,
  `require_local_user`

The bind password and the client secret are never returned; `bind_pw_set` and
`client_secret_set` say whether one is stored. `callback_url` is not stored: it is this
console's own `/api/saml/acs` or `/api/oidc/callback` URL, to register with the identity
provider.

**Auth:** `config:manage` · **Response:** `200` JSON array

---

### POST /api/auth-providers

Add or update a provider.

**Auth:** `config:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:**
- `id` — required, at most 64 characters, no space, `/`, `\` or `@`
- `kind` — `ldap` (default), `saml` or `oidc`
- `display_name`, `priority` (default 100), `enabled` (anything but `false` enables),
  `require_local_user` (`true`)
- **ldap:** `uris` and `base_dns` (required), `bind_dn`, `bind_pw` (an empty value keeps the
  stored password; `bind_pw_clear=true` clears it), `group_filter`, `group_attr`,
  `ca_cert_file`, `network_timeout_sec` (default 3), `template_base`, `netbios_name`,
  `dns_root`. A blank `netbios_name` or `dns_root` is read from Active Directory when the
  directory can be bound.
- **saml:** `idp_sso_url`, `idp_cert` and `sp_entity_id` (all required), `idp_entity_id`,
  `username_attr`, `groups_attr`, `admin_group`, `auditor_group`, `clock_skew_sec`
  (default 120)
- **oidc:** `issuer` and `client_id` (required), `client_secret` (an empty value keeps the
  stored secret; `client_secret_clear=true` clears it), `scopes`, `username_claim`,
  `groups_claim`, `admin_group`, `auditor_group`, `ca_cert`

**Response:**
- `201` `{"id":"<id>"}`
- `400` invalid id or kind, or a required field missing
- `409` the id belongs to a provider of another kind; or, for a directory, its id, display
  name, NetBIOS name or DNS root (compared case-insensitively) equals one of those of another
  directory
- `500`

**Audit:** `auth_provider_saved`

---

### DELETE /api/auth-providers

Remove a provider. Grants held by identities it authenticated are **not** deleted; they stop
matching anyone, because every such identity was authorized as `provider\user`.

**Auth:** `config:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `id`

**Response:** `200` `{"deleted":true,"orphaned_grants":<int>}` — the number of role bindings
that name this provider (-1 when they could not be counted); `400`; `500`

**Audit:** `auth_provider_removed`

---

### GET /api/ms-keytab · POST /api/ms-keytab

A directory's Kerberos keytab for the MS-XCEP service.

**Auth:** `config:manage`; POST requires `WEB_ALLOW_REVOKE=true`

**GET** `?provider=<directory id>` — `200` `{"path":"<path>","present":bool,"bytes":<int>}`.
The keytab itself is never returned.

**POST** `?provider=<directory id>` with the keytab file as the raw body. It is written to the
directory's recorded keytab path, or to `/var/pki/ms/<id>.keytab`, which is then recorded.
Response `200` `{"path":"<path>","bytes":<int>}`; `400` no `provider`, empty body, or not a
keytab; `404` no such directory; `500`.

**Audit:** `ms_keytab_uploaded`

---

### GET /api/ldap/users · GET /api/ldap/groups

Browse the enabled directories for import. Names are qualified as `<directory>\<name>`.

**Auth:** `user:manage`

**Parameters:** `GET /api/ldap/users` takes `q`, a search string.

**Response:**
- `200` `{"enabled":false}` when no directory is configured
- `200` `{"enabled":true,"users":[{"username","display","dn"}]}` or
  `{"enabled":true,"groups":["<directory>\\<group>"]}`, with `"searchError"` when a search was
  refused
- `502` a directory error

---

### GET /api/ldap/groups/<group>/members

The members of one directory group, asked of that group's directory only. `<group>` is the
URL-encoded `<directory>\<group>`.

**Auth:** `user:manage`

**Response:** `200`
`{"enabled":true,"group":"<group>","members":[{"username","display"}]}`, with `"searchError"`
when the search was refused or the name carries no directory (then `members` is empty);
`{"enabled":false}` with no directory configured; `502` a directory error.

---

### GET /api/directory-subjects

The people who reach the console through group bindings, from the stored member lists. A group
whose members were never looked up is looked up once, on this request.

**Auth:** `user:manage`

**Response:** `200`
```json
{
  "enabled": true,
  "subjects": [{"username","display","kind","role","via"}],
  "groups": [{"name","refreshed","attempted","members","error"}],
  "searchError": "<group>: <message>"
}
```

`via` names the group that confers `role`. `refreshed` and `attempted` are Unix times, 0 when
never; `searchError` is present when a stored refresh failed. `{"enabled":false}` with no
directory configured; `502` a database or directory error. The stored lists are refreshed every
`DIRECTORY_GROUP_REFRESH_SEC` seconds.

---

### POST /api/directory-groups/<group>/refresh

Look up one group's members again and store them. Only a group bound to a role can be
refreshed. Not write-gated: it changes no authorization.

**Auth:** `user:manage`

**Response:**
- `200` `{"group","ok":true,"refreshed":<unix>,"members":[{"username","display"}]}`
- `502` `{"group","ok":false,"refreshed","members","kept":bool,"error"}` — `members` is the list
  stored before, and `kept` says whether there is one
- `400` no directory configured; `404` no role is bound to the group; `501` the build has no
  LDAP support

**Audit:** `directory_group_refresh`

---

## 11. Certificate profiles

The profile routes check the grant's scope against the profile name: a caller holding
`profile:edit|tenant-a` sees and writes `tenant-a` only.

### GET /api/profiles

The certificate profiles the caller may edit. `GET /api/my-profiles` is the list a requester
issues under.

**Auth:** `profile:edit`

**Response:** `200` JSON array with fields: `name`, `builtin`, `allowed_ku`, `allowed_eku`,
`default_ku`, `default_eku`, `allow_wildcard`, `allowed_san_types`, `max_validity_days`,
`validity_days`, `csr_attrs`, `custom_extensions` (`[{oid, value, critical}]`),
`allowed_custom_extensions`, `manage_aia`, `manage_crldp`, `no_override_subject`, `allow_ca`,
`max_path_len`

---

### POST /api/profiles

Create or replace a certificate profile, built-ins included. Every save writes the whole
profile from the parameters sent. The two built-ins (`requester`, `admin`) may be edited but not
deleted.

**Auth:** `profile:edit` covering the name; requires `WEB_ALLOW_REVOKE=true`

**Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `name` | string | letters, digits and `- _ .`, max 64 chars |
| `allowed_ku` | string | CSV of allowed key usages |
| `default_ku` | string | CSV of key usages applied when the request asks for none |
| `allowed_eku` | string | CSV of allowed extended key usages (names or OIDs) |
| `default_eku` | string | CSV of extended key usages applied when the request asks for none |
| `allowed_san_types` | string | CSV of `dns`, `ip`, `email`, `uri`, `othername`; empty means `dns,ip,email` |
| `allow_wildcard` | string | `true`/`1` |
| `max_validity_days` | int | 0 = no profile cap |
| `validity_days` | int | the validity this profile grants, even above the deployment default; 0 = not stated. Left out, the stored profile's value is kept |
| `csr_attrs` | string | JSON array of EST CSR attributes: an OID, or `{oid, values}` |
| `custom_extensions` | string | JSON array of `{oid, value, critical}` |
| `allowed_custom_extensions` | string | CSV of extension OIDs a request may carry; `*` allows any |
| `manage_aia`, `manage_crldp` | string | `true`/`1` lets a request leave AIA / CRL DP out |
| `no_override_subject` | string | `true`/`1` keeps the request's subject instead of binding it to the caller |
| `allow_ca` | string | `true`/`1` permits basicConstraints CA:TRUE |
| `max_path_len` | int | cap on pathLenConstraint; blank = no cap |

**Response:** `201` `{"name":"<name>"}`; `400` invalid name, `max_path_len` or `validity_days`; `403` no grant
covers the name; `500`

**Audit:** `cert_profile_set`

---

### DELETE /api/profiles

Delete a custom profile. Built-in profiles cannot be deleted.

**Auth:** `profile:edit` covering the name; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `name` (string)

**Response:** `200` `{"name":"<name>","deleted":true}`; `400` no name, or a built-in; `403`;
`404` no such custom profile; `500`

**Audit:** `cert_profile_deleted`

> **Who may USE a profile is not set here.** There is no
> `/api/profile-assignments` — a profile is a permissioned resource. Grant a role
> `profile:use` (may enrol under it) or `profile:edit` (may edit it), scoped to the
> profile's name, via `POST /api/roles/<role>/permissions`; `*` means every profile. What a
> subject may use is the union of those grants over the roles it holds. An unknown profile
> name in a `profile:` scope is rejected with `400`.

---

## 12. Approved domains

A qualified name (one containing a dot) in a subject CN or a DNS SAN must be an approved domain
or a name under one. An empty list does not restrict names, and ACME requests, whose names are
proven by challenge, are not checked against it.

### GET /api/domains

**Auth:** `config:manage`

**Response:** `200` `["example.org","corp.example"]` — `corp.example` covers `corp.example` and
every name under it

---

### POST /api/domains

Add an approved domain.

**Auth:** `config:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `domain` (at most 253 characters, no whitespace, `/` or `\`)

**Response:** `201` `{"domain":"<domain>"}`; `400`; `500`

**Audit:** `allowed_domain_added`

---

### DELETE /api/domains

Remove an approved domain.

**Auth:** `config:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `domain`

**Response:** `200` `{"deleted":true}`; `400`; `500`

**Audit:** `allowed_domain_removed`

---

## 13. CA instances

Every CA is a row in `certs`; there is no default CA. The routes below that take a CA id answer
`404` for a CA outside the caller's scope.

### GET /api/ca-instances

The CAs the caller may see.

**Auth:** `ca:read`

**Response:** `200`
```json
[{
  "id": "<id>",
  "name": "<name>",
  "parentId": "<parent>",
  "status": "active|disabled",
  "kind": "root|intermediate|sub",
  "keyType": "HSM|none",
  "signable": true,
  "revoked": false,
  "onHold": false,
  "expired": false,
  "keyLocation": "HSM|none",
  "subject": "<CN>",
  "issuer": "<DN>",
  "serial": "<hex>",
  "ski": "<hex>",
  "aki": "<hex>",
  "fingerprint": "<SHA-256 hex>",
  "fingerprintSha1": "<SHA-1 hex>",
  "keyAlgo": "<algo>",
  "keyDesc": "<desc>",
  "sigAlgo": "<algo>",
  "notBefore": "<RFC 3339>",
  "notAfter": "<RFC 3339>",
  "certs": 150,
  "managed": true
}]
```

- `kind` — `root` for a self-signed certificate, `intermediate` otherwise. When the certificate
  cannot be parsed: `sub` if a parent is recorded, else `root`
- `keyType` / `keyLocation` — `HSM` when a key reference is recorded, `none` for a verify-only
  trust anchor
- `signable` — whether this node's token holds the key (true when the token cannot be read)
- `certs` — certificates this CA issued

---

### POST /api/ca-instances

Create a CA (root or subordinate) with its key in the token, or import an existing CA
certificate.

**Auth:** `ca:manage`, and a caller confined to CAs is refused; requires `WEB_ALLOW_REVOKE=true`

**Parameters (create):**
| Param | Type | Description |
|-------|------|-------------|
| `id` | string | required, letters, digits and `- _ .`, max 64, not `default` |
| `name` | string | display name; defaults to the id |
| `parent` | string | parent CA id, which must be registered and active; empty = root |
| `subject` | string | DN, e.g. `/CN=My CA/O=Org`; defaults to `/CN=<name>` |
| `key` | string | `rsa` (default), `ec`, `ed25519`, `ed448`, `rsa-pss`, `ML-DSA-44`/`65`/`87` |
| `bits` | int | default 4096 |
| `curve` | string | `P-256`, `P-384`, `P-521` |
| `md` | string | default `sha256` |
| `keyloc` | string | must be `pkcs11` (or omitted). A CA private key lives in a token |
| `keyref` | string | required: the pkcs11: handle naming the token object |
| `keygen` | string | "true"/"1" to generate the key inside the token; omit to adopt a key already there |
| `overwrite` | string | "true"/"1" to destroy an existing token object at `keyref` and generate a key over it. Without it a taken handle is refused; a key backing a registered CA or a live listener is refused even with it. |
| `replicable` | string | "true"/"1" to generate the key with CKA_EXTRACTABLE, so it can later be copied into another node's token (`fastpki-ca key replicate`). Decided at generation and never afterwards. Every `key` value above can be replicable; requires `keygen`. An EC curve other than P-256/P-384/P-521, or `replicable` on an adopted key, is a `400` before the handle is checked. |
| `days` | int | default 3650, used when `notAfter` is not sent |
| `notBefore`, `notAfter` | int | Unix seconds |
| `neverExpire` | string | "true"/"1" |
| `pathlen` | int | -1 = not set |
| `ku` | string | CSV of key usages; empty means `keyCertSign,cRLSign` |
| `ncPermitted` | string | name constraints permitted |
| `ncExcluded` | string | name constraints excluded |
| `crldp` | string | CSV of CRL distribution points |
| `aiaIssuers` | string | CSV of AIA issuer URIs |
| `aiaOcsp` | string | CSV of AIA OCSP URIs |
| `policies` | string | CSV of certificate policy OIDs |
| `profile` | string | the profile to check the request against |
| `disabled` | string | "true"/"1" for initial disabled state |

The resolved profile must set `allow_ca`, allow every requested key usage, and permit the path
length under its `max_path_len`; otherwise `403`.

**Parameters (import):** `id`, `name`, `disabled`, `cert_pem` (the CA certificate), and
optionally `key` (the pkcs11: handle of the CA's key in this node's token) with `keyloc`
`pkcs11`. With neither `key` nor `keyloc` the CA is registered as a **verify-only trust anchor**
this node holds no key for. The parent is read from the certificate.

An import under an `id` that is already registered is a **renewal**: the certificate becomes
that CA's next certificate, and `name` and `disabled` default to the CA's current values. It is
accepted only when the certificate has the CA's subject and is signed by the CA's parent (any
live certificate of it), or is self-signed when the CA is a root.

**Response:**
- `201` (create) `{"id":"<id>","status":"active|disabled"}`
- `201` (import) `{"id":"<id>","status":"active|disabled","imported":true,"renewal":true|false,"serial":"<hex>"}`
- `400` invalid id, parent not found, invalid certificate or not a CA, a key below `MIN_RSA_BITS`/`MIN_EC_BITS` or of an
  unsupported algorithm (a CA must be at least as strong as the certificates it issues),
  `keyloc` naming anything but `pkcs11`, a key the token cannot generate or load
- `403` a CA-scoped caller, or a profile refusal
- `404` no key at `keyref` to adopt
- `409` a CA is already registered under this id (create), or the imported certificate is not
  a renewal of that CA: a different subject, not signed by its parent, or not self-signed for a root
- `409` the parent is disabled, revoked or expired
- `409` the parent's key is not in this server's token. With `P11_TLS=on` the console first runs
  `fastpki-ca key sync --from-peers` to copy it from another server of the data center, so this
  answer means the copy failed, and it quotes the end of that run
- `409` `{"handleTaken":true}` — a key already exists at `keyref`; retry with `overwrite=true`,
  adopt it with `keygen=false`, or choose another name
- `409` the certificate is already registered (a certificate is stored once, keyed by serial)
- `500`; `502` a key may exist at `keyref` but could not be read

Fetch the certificate with `GET /api/ca-instances/<id>/cert-pem`.

**Audit:** `web_ca_created` / `web_ca_imported`

---

### GET /api/ca-instances/derived-urls

The AIA and CRL distribution point URLs a CA's issued certificates carry, one per data center.

**Auth:** `ca:manage`

**Parameters:** `id` (optional) — without it the answer is the URL shape with `{id}` in place
of the CA id

**Response:** `200` `{"ca_issuers":["<url>"],"ocsp":["<url>"],"crl":["<url>"]}`

---

### POST /api/ca-instances/csr

Generate or adopt a CA key in this node's token and return a PKCS#10 request for it, to be
signed by a CA on another node (`POST /api/ca-instances/sign-csr`) and then imported here
(`POST /api/ca-instances` with `cert_pem` and `key`).

**Auth:** `ca:manage`, and a CA-scoped caller is refused; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `subject` (required, `/CN=...` form), `keyref` (required pkcs11: handle),
`keyloc`, `key`, `bits`, `curve`, `md`, `keygen` (generates the key unless `false`/`0`), `overwrite`,
`replicable`, `pathlen`, `ku`, `ncPermitted`, `ncExcluded`, `policies`, `profile` — as for
`POST /api/ca-instances`

**Response:** `201` `{"csr":"<PEM>","key":"<keyref>","subject":"<DN>"}`; `400`; `403` a CA-scoped
caller or a profile refusal; `404`, `409`, `502` as for the handle checks of CA creation; `500`

**Audit:** `web_ca_csr_created`

---

### POST /api/ca-instances/sign-csr

Sign a CA request with one of this node's CAs and return the certificate. The certificate is
recorded on this node as a CA certificate with no CA id, under the signing CA, so it can be listed
and revoked; no CA is registered. Importing it (`POST /api/ca-instances`) registers the CA on
that record.

**Auth:** `ca:manage`, and a CA-scoped caller is refused; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `csr` (PEM, required), `parent` (the signing CA id, required), `md`, `days`,
`notBefore`, `notAfter`, `neverExpire`, `pathlen`, `ku`, `ncPermitted`, `ncExcluded`,
`policies`, `profile`, and `crldp`, `aiaIssuers`, `aiaOcsp` as `true`/`1` flags that include the
signing CA's own URLs. The AIA OCSP URL is included only when the signing CA has an OCSP
responder certificate. The subject comes from the request; basic constraints, key usage and name
constraints come from these parameters, never from the request.

**Response:** `201` `{"cert":"<PEM>","subject":"<DN>","signer":"<parent>","serial":"<hex>"}`;
`400` missing or invalid request, weak key or digest; `403`; `404` unknown signing CA; `409` the
signing CA is not active; `500`

**Audit:** `web_ca_csr_signed`

---

### POST /api/ca-instances/<id>/status

Enable or disable a CA instance.

**Auth:** `ca:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `status` (`active` or `disabled`)

**Response:** `200` `{"id":"<id>","status":"active|disabled"}`; `400`; `404`; `500`

**Audit:** `web_ca_status`

---

### DELETE /api/ca-instances/<id>

Delete a CA that has issued nothing, together with its key in the token.

**Auth:** `ca:manage`; requires `WEB_ALLOW_REVOKE=true`

**Response:**
- `200` `{"id":"<id>","deleted":true,"tokenObjectsDestroyed":<int>}`
- `404` no such CA
- `409` `{"error":…,"issued":<int>}` — the CA has issued certificates; disable it instead
- `409` the token key could not be destroyed, so nothing was deleted
- `500`

**Audit:** `web_ca_delete`

---

### POST /api/ca-instances/<id>/renew

Renew a CA: issue it a new certificate with a new validity, over a new key generated in the token
or over its current key. The current certificate stays live.

- **Sub CA:** the certificate is signed by the parent, with an end date no later than the
  parent's, and CRL distribution point and AIA URLs derived from the parent. The parent's key
  must be on this node and the parent active.
- **Root:** the certificate is self-signed. With a new key, two cross-certificates are also
  issued: the new key signed by the current root (`bridgeSerial`, stored under the CA's id and
  ending no later than the current root) and the current key signed by the new root
  (`crossSerial`, stored without an id).

With a new key, the OCSP responder, CMP RA and SCEP RA credentials the CA issued are re-signed.

| Param | Description |
|---|---|
| `samekey` | "true"/"1" to renew with the current key; `keyref`, `key`, `bits`, `curve` and `replicable` are then ignored |
| `keyref` | pkcs11: handle for the NEW key. Must differ from the current key, and nothing may exist at it yet (`409`). |
| `key`, `bits`, `curve`, `md`, `days` | as for `POST /api/ca-instances`; `days` defaults to 3650 |
| `replicable` | "true"/"1" to generate the new key with CKA_EXTRACTABLE. **Not inherited** from the current key — on an HA pair, pass it on every renewal with a new key. |

**Auth:** `ca:manage`; requires `WEB_ALLOW_REVOKE=true`

**Response:** `201` `{"id","serial","notAfter","sameKey","signer","bridgeSerial","crossSerial","keyref","serviceCertsRenewed","serviceCertsFailed"}`
(`signer` is the parent's id, or the CA's own for a root; `bridgeSerial` and `crossSerial` are
empty unless a root was renewed with a new key);
`400` no `keyref` and no `samekey`, or `keyref` is the current key; `404`;
`409` a key exists at `keyref`; `409` `{"csrRoute":true,"parent":"<id>"}` — the parent's key is
not on this node, so renew through a CSR signed there and imported here under the same id;
`409` the parent is disabled, revoked or expired; `503` the CA is not active; `500` ·
**Audit:** `web_ca_renewed`

`fastpki-ca renew` is the same operation, and audits as `cli_ca_renewed`.

---

### POST /api/ca-instances/<id>/cross-sign

Cross-sign a registered foreign CA under this CA. The certificate carries this CA's CRL
distribution point and AIA URLs and is stored as an inventory row.

**Auth:** `ca:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `fingerprint` (a registered foreign anchor), `permitted` (required: permitted
name-constraint subtrees, comma- or newline-separated), `pathlen` (required), `days` (default
3650), `md`

**Response:** `201` `{"serial":"<hex>","subject":"<DN>","pem":"<PEM>"}`; `400` no `permitted`,
no `pathlen`, weak digest, or signing failed; `404` unknown CA, or the fingerprint is not
registered; `503` the CA is not active; `500` its key could not be loaded

**Audit:** `web_ca_cross_signed`

---

### GET /api/ca-instances/<id>/cert-text

The decoded text of a CA's certificate.

**Auth:** `ca:read`

**Response:** `200` text/plain; `404` (text) no such CA or no certificate; `500`

---

### GET /api/ca-instances/<id>/cert-pem

The CA's certificate as one PEM certificate.

**Auth:** `ca:read`

**Response:** `200` `Content-Type: application/x-pem-file`; `404` (text); `500`

---

### GET /api/ca-instances/<id>/xcep

The CA's MS-XCEP `<cAs><cA>` configuration — the endpoints `GetPolicies` advertises
for it.

**Auth:** `ca:manage`

**Response:** `200`
`{"id":"<id>","enrollPermission":true,"uris":[{"uri":"","clientAuth":4,"priority":1,"renewalOnly":false}]}`

An empty `uris` array means the CA has none configured, and `fastpki-ms` advertises
this server's own `/mswstep/<id>` — built from `BASE_URL` when that is set explicitly,
and otherwise from the `Host` header the client used, falling back to `PKI_DNS:MS_PORT`.

---

### POST /api/ca-instances/<id>/xcep

Replace the CA's advertised XCEP endpoints.

**Auth:** `ca:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:**
- `uris` (string) — one endpoint per line, `uri|client_auth|priority|renewal_only`.
  A blank `uri` means "this server's own WSTEP endpoint for this CA"; `priority` `-1`
  serializes as `xsi:nil`; `client_auth` is 1 (anonymous, renewals only), 2 (Kerberos),
  4 (username+password) or 8 (X.509). An empty value clears the list.
- `enrollPermission` (bool, default true) — the CA-level `<enrollPermission>`.

**Response:** `200` `{"id":"<id>","uris":<n>,"enrollPermission":true|false}`
· `400` if `client_auth` is not one of 1/2/4/8 · `404` · `500`

**Audit:** `web_ca_xcep`

---

### GET /api/foreign-anchors

The foreign CAs registered as eligible for cross-signing.

**Auth:** `ca:manage`

**Response:** `200` `[{"fingerprint","subject","note","registeredBy","registered"}]` —
`registered` in Unix seconds

---

### POST /api/foreign-anchors

Register a foreign CA certificate for cross-signing.

⚠️ Gated on `*:*` — harder than the cross-signing itself, which needs only `ca:manage`.

**Auth:** `*:*`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `pem` (exactly one PEM certificate, which must be a CA), `note`

**Response:** `201` `{"fingerprint":"<SHA-256 hex>","subject":"<DN>"}`; `400`; `500`

**Audit:** `web_foreign_anchor_registered`

---

### DELETE /api/foreign-anchors/<fingerprint>

Remove a registered anchor. A cross-certificate already issued from it stays valid until it is
revoked or expires.

**Auth:** `*:*`; requires `WEB_ALLOW_REVOKE=true`

**Response:** `200` `{"removed":"<fingerprint>","note":"…"}`

**Audit:** `web_foreign_anchor_removed`

---

## 14. The token

### GET /api/pkcs11/slots

The slots of the configured PKCS#11 module, with the deployment's token defaults.

**Auth:** `hsm:read`

**Response:** `200`
```json
{
  "module": "<module path>",
  "error": "",
  "token": "<PKCS11_TOKEN>",
  "pinFile": "<PKCS11_PIN_FILE path>",
  "datacenterId": "<DATACENTER_ID>",
  "transportKeys": {"web-1": "pkcs11:token=...;object=web-tls-1"},
  "slots": [{"slot": 0, "token": "<label>", "algorithms": ["rsa", "ec"]}]
}
```

`transportKeys` maps each listener id (in both its bare and node-scoped form) and each RA
prefix to the key handle it loads, without any `?` query part. An empty `algorithms` array
means the token did not say.

---

### GET /api/pkcs11/keys

The objects in a token, read-only.

**Auth:** `hsm:read`

**Parameters:** `token` (optional label; defaults to `PKCS11_TOKEN`)

**Response:** `200`
`{"token":"<label>","error":"","objects":[{"label","id","class","keyType","curve","bits","cas"}]}` —
`cas` lists the CAs (within the caller's scope) that sign with a private key

---

## 15. Configuration

### GET /api/config

Effective server configuration (file + DB overlay). Secrets redacted.

**Auth:** `config:manage`

**Response:** `200`
```json
[{
  "section": "<section>",
  "key": "<key>",
  "value": "<value>",
  "desc": "<description>",
  "owner": "<gate id, or empty>"
}]
```

`owner` names the process that READS the setting, as the gate id used by
`/api/endpoints/<id>/restart` — `est`, `acme`, `cmp`, `scep`, `ms`, `ocsp`, `store` or
`web`. **An empty string means every listener reads it**, either because it is general
(`LOG_LEVEL`, `DATACENTER_ID`) or because a key that looks protocol-specific is in fact
read through `src/lib/` and so is linked into all of them — `OCSP_PORT`, for instance, is
baked into the AIA URL of every certificate any issuer issues. The console uses this to
decide which processes a changed setting is still pending a restart on.

---

### GET /api/config/status

Whether the stored configuration is in use. When a stored value cannot be parsed the console
serves its built-in defaults and says so here.

**Auth:** `config:manage`

**Response:** `200` `{"live":true}` or `{"live":false,"error":"<parse error>"}`

---

### GET /api/config/db

The rows of the `config` table.

**Auth:** `config:manage`

**Response:** `200`
```json
[
  {"key": "<key>", "value": "<value>", "secret": false, "updated": 1700000000},
  {"key": "<key>", "unset": true, "updated": 1700000000}
]
```

A secret's value is `(set)`. An `unset` row marks a key whose override was deleted, so the
Config page can show it as pending a restart.

---

### PUT /api/config/db

Set one key in the `config` table.

**Auth:** `config:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `key`, `value`

**Response:** `200` `{"key":"<key>","ok":true}`; `400` no key, `PG_CONNINFO` (it stays in
bootstrap.conf), or a value the setting does not accept; `500`

**Audit:** `web_config_set`

---

### DELETE /api/config/db

Delete one key's override from the `config` table.

**Auth:** `config:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `key`

**Response:** `200` `{"key":"<key>","ok":true}`; `400`; `500`

**Audit:** `web_config_unset`

---

### GET /api/config/file · PUT /api/config/file

The whole configuration as one text file. GET returns the text last saved through this route,
with each value refreshed to the live one, or a file rendered from the effective configuration
when none was saved.

**Auth:** `config:manage`; PUT requires `WEB_ALLOW_REVOKE=true`

**GET response:** `200` exactly `{"text":"<file text>"}`

**PUT parameters:** `text`, and `force=true` to save even though bootstrap.conf changed on disk
after the console loaded it. The keys that differ are written to the `config` table, deleted
lines unset their key, and the text is stored with secret values masked as `(set)`.

**PUT response:** `200` `{"set":<int>,"unset":<int>}`; `400` a line that does not parse; `409`
`{"error":…,"fileDrift":true}` — bootstrap.conf changed on disk and `force=true` was not sent;
`500`

**Audit:** `web_config_file_edit`

---

### GET /api/config/file/drift

Whether bootstrap.conf on disk is newer than the copy this console loaded.

**Auth:** `config:manage`

**Response:** `200`
`{"drift":bool,"path":"<bootstrap.conf path>","fileMtime":<unix, 0 without drift>,"loadedMtime":<unix>}`

---

## 16. Endpoints, restarts and client configurations

### GET /api/endpoints

Per-protocol endpoint map.

**Auth:** `config:manage`

**Response:** `200`
```json
[{
  "protocol": "EST",
  "bind": "<addr:port>",
  "path": "<path>",
  "url": "<external URL>",
  "advertised": "<URL carried in certificates, or empty>",
  "gate": "est",
  "switchedWith": "",
  "restartable": true,
  "selfRestart": false,
  "gateable": true,
  "enabled": true,
  "installed": true,
  "keys": ["EST_BIND", "EST_PORT"]
}]
```

Rows: EST, ACME, CMP, SCEP, OCSP, CRL, MS-XCEP, MS-WSTEP, Store, Web Console, PostgreSQL.
`gate` is the protocol id for the enable and restart routes (empty for the console and
PostgreSQL). `switchedWith` names the row holding the switch when this row is a second address
of the same service (`"OCSP"` on the CRL row, `"MS-XCEP"` on the MS-WSTEP row); such a row keeps the `gate`, so
`enabled` and `installed` follow the service, but it is not `gateable` or `restartable`.
`selfRestart` marks the console; `installed` is false when the deployment recorded that the
protocol was not installed; `keys` names the settings that drive the row.

---

### GET /api/endpoints/health

A TCP connect probe of each listener, with a 1.5-second timeout.

**Auth:** `config:manage`

**Response:** `200` `[{"protocol":"EST","healthy":true,"ms":3,"error":""}]` for EST, ACME, CMP,
SCEP, OCSP, CRL, MS-XCEP, MS-WSTEP and Store

---

### GET /api/replication

Every host of the deployment as it reports itself, and the warnings made from those reports — the
Replication page (admin guide §12.5). The host serving the request publishes its own report first.

**Auth:** `*:*`

**Response:** `200`
```json
{
  "self": "<host id of the host that served this>",
  "now": 1757800000,
  "pgTlsCaId": "<PG_TLS_CA_ID, or empty>",
  "nodes": [{
    "hostId": "<PG_BIND, or PKI_DNS>", "dcId": "<DATACENTER_ID>",
    "reportedAt": 1757799990,
    "report": {
      "version": "…", "pg_bind": "…", "standby_of": "…", "p11_tls": true,
      "database": {
        "connected_host": "…", "conninfo_hosts": ["…"], "sslmode": "…",
        "probes": [{"host": "…", "ok": true, "tls_failure": false, "verifies": true, "detail": ""}],
        "state": {"in_recovery": false, "replication": [], "slots": [], "subscriptions": []}
      },
      "token": {"readable": true},
      "cas": [{"id": "…", "object": "…", "key": "present|missing|unknown|none", "extractable": true}],
      "credentials": [{"prefix": "ocsp-ra", "name": "OCSP responder", "issued": true, "object": "…", "key": "present"}]
    },
    "keySync": {"state": "running|refused|finished", "rc": 0, "missing": 0, "replicated": 0, "failed": 0, "failed_ids": [], "output": "…"},
    "keySyncAt": 1757799000, "keySyncRequest": 0, "requestedAt": 0, "requestedBy": "",
    "transport": {"client": true, "server": true}
  }],
  "datacenters": [{"dcId": "…", "baseUrl": "…"}],
  "warnings": [{"severity": "error|warning", "host": "…", "message": "…"}]
}
```
`state.replication` is `pg_stat_replication`, `state.slots` is `pg_replication_slots` and
`state.subscriptions` is this database's subscriptions with their error counts, as seen by the
server the host is connected to. The host id is `PG_BIND` where set, otherwise `PKI_DNS`.

---

### POST /api/replication/key-sync

Ask a host to run `fastpki-ca key sync --from-peers` now, copying every key it is missing from the
other hosts of its data center. The request is recorded, and the host it names starts it from its
own console within about 15 seconds, whichever host served this call. Its progress and result
appear in that host's `keySync` in `GET /api/replication`.

**Auth:** `*:*`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `host` — the host id

**Response:**
- `202` `{"host":"<host id>","requestedAt":<unix time>}`
- `403` console writes are disabled
- `404` no host with that id has reported
- `409` the host has `P11_TLS` off, so it has no token transport to copy keys over

**Audit:** `replication_key_sync_requested`

---

### POST /api/endpoints/<protocol>/enabled

Switch a protocol listener on or off. `<protocol>` is `est`, `acme`, `cmp`, `scep`, `ms`, `ocsp`
or `store`.

The console writes the protocol's enable flag (for example EST_ENABLED) to the `config` table
and touches no container. The listener reads the flag itself: switched off, the running process
exits and, when its service manager starts it again, does not open its port until the flag is
back on.

**Auth:** `config:manage`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `enabled` (`true` or `false`)

**Response:** `200` `{"protocol":"<protocol>","enabled":bool,"note":"takes effect within ~10s"}`;
`400`; `404` unknown protocol; `500`

**Audit:** `endpoint_enabled` / `endpoint_disabled`

---

### POST /api/endpoints/<protocol>/restart

Restart a protocol listener (`est`, `acme`, `cmp`, `scep`, `ms`, `ocsp`, `store`). The console
writes the current time as that protocol's restart marker (for example EST_RESTART_AT) in the
`config` table; the listener's own watcher sees a marker newer than its start, stops within
about 10 seconds, and its restart policy starts it again.

**Auth:** `config:manage`; requires `WEB_ALLOW_REVOKE=true`

**Response:** `200` `{"protocol":"<protocol>","restartAt":<unix>,"note":"…"}`; `404` unknown
protocol; `500`

**Audit:** `endpoint_restarted`

---

### POST /api/endpoints/web/restart

Restart the console by re-executing its own binary in the same process, after the reply is
sent. Works without a supervisor; if the re-execution fails the process exits with status 0 for
its supervisor to start it again.

**Auth:** `config:manage`; requires `WEB_ALLOW_REVOKE=true`

**Response:** `200` `{"restarting":true,"note":"the console will be unavailable for a moment"}`

**Audit:** `web_restart`

---

### POST /api/restart

Restart the console by exiting half a second after the reply. The service manager or container
restart policy has to start it again; without one the console stays down.

**Auth:** `config:manage`; requires `WEB_ALLOW_REVOKE=true`

**Response:** `200` `{"restarting":true}`

**Audit:** `web_restart`

---

### GET /api/client-config/<kind>

Download a ready-to-use client configuration file: the stored override if one exists, else the
generated file, with its `{{TOKENS}}` filled from the current settings and the caller's own
enrolment credentials.

**Auth:** `cert:request`

**Parameters:** `ca` — the CA the file enrols against. Without it: the first enabled CA that is
neither revoked nor expired, preferring one that is not a root.

**Response:** the file. For `appleacme` and `applescep` on a console serving HTTPS, the profile
is a DER CMS SignedData made with the console's TLS certificate and key, the chain included,
with the XML as its content (`openssl cms -verify -inform DER -noverify` prints it). Over plain
HTTP it is the XML. A preview is always the XML.

`GET /api/client-config/<kind>/edit` returns the editable body and token legend,
`PUT /api/client-config/<kind>` stores an override (`body`), `DELETE /api/client-config/<kind>`
removes it, and `POST /api/client-config/<kind>/preview` (`body`,
optional `ca`) returns the posted text as a download would substitute it, without storing it. All
four need `config:manage`.

**Kinds:**
| Kind | Filename | Content-Type |
|------|----------|-------------|
| `cmp` | `fastpki-cmp.cnf` | text/plain |
| `acme` | `certbot-cli.ini` | text/plain |
| `scep` | `fastpki-scep-enroll.sh` | text/x-shellscript |
| `ms` | `fastpki-request.inf` | text/plain |

**Response:** `200` with `Content-Disposition: attachment; filename="<filename>"`

---

## 17. Backup and restore

A configuration backup holds the `config` table, the console users (with their password
hashes), the CA registrations with their certificates, the roles with their grants, the role
bindings and the MS templates. Every download is audited.

### GET /api/backup

Download the configuration backup as JSON.

**Auth:** `backup:manage`

**Response:** `200` `Content-Disposition: attachment; filename="fastpki-backup.json"`; `500`

**Audit:** `web_backup_downloaded`

---

### POST /api/backup

Download the configuration backup, encrypted when a passphrase is sent. The passphrase is not
stored. Not write-gated: it changes nothing.

**Auth:** `backup:manage`

**Parameters:** `passphrase` (optional)

**Response:** `200` — with a passphrase, `application/octet-stream` named
`fastpki-backup.fpkibak`; without, the same JSON as `GET /api/backup`. `400` encryption failed;
`500`.

**Audit:** `web_backup_downloaded`

---

### POST /api/backup/restore

Restore a configuration backup. Rows are upserted; rows the backup does not contain are kept.

**Auth:** `backup:manage`; requires `WEB_ALLOW_REVOKE=true`

**Request:** `multipart/form-data` with the backup as `file` and an optional `passphrase` field,
or the backup JSON as the raw body (a `passphrase` query parameter decrypts an encrypted raw
body). An encrypted backup is recognised and decrypted.

**Response:** `200` `{"restored":"<summary>"}`; `400` no file, wrong passphrase, or not a
FastPKI backup

**Audit:** `web_config_restored`

---

### POST /api/db-backup

Download a full database dump (`pg_dump`), encrypted when a passphrase is sent. Not
write-gated: it changes nothing.

**Auth:** `backup:manage`

**Parameters:** `passphrase` (optional)

**Response:** `200` — `application/sql` named `fastpki-db.sql`, or `application/octet-stream`
named `fastpki-db.sql.fpkibak` with a passphrase; `400` encryption failed; `500` the dump
failed

**Audit:** `web_db_backup`

---

### POST /api/db-backup/restore

Replace the database with an uploaded dump, applied in a single transaction: a file that fails
part-way rolls back and leaves the database untouched.

**Auth:** `backup:manage`; requires `WEB_ALLOW_REVOKE=true`

**Request:** `multipart/form-data` with the dump as `file` (at most 64 MB) and an optional
`passphrase` field for an encrypted dump

**Response:** `200` `{"restored":"database restored — <n> bytes applied in one transaction"}`;
`400` not multipart, no file, or wrong passphrase; `409` the node is part of a multi-data-center
mesh, which is restored with `fastpki-mesh --restore` instead ([`postgres.md`](postgres.md) §6.3);
`413` over 64 MB; `500` `{"error":"database restore failed (rolled back): <psql error>"}`

**Audit:** `web_db_restored`

---

## 18. PostgreSQL TLS

### POST /api/pg-tls

Issue the database's own TLS certificate from a CA and write `server.crt` (with its chain),
`server.key` and `ca.crt` into `PG_TLS_DIR`. The key is a software key on disk, because
PostgreSQL reads its key from a file. The SANs are `postgres`, `localhost`, `127.0.0.1`,
`PKI_DNS`, this node's database bind address and `PG_TLS_SANS`; the request cannot add names.
`ca.crt` gains the new trust anchor and keeps the previous ones.

**Auth:** `*:*`; requires `WEB_ALLOW_REVOKE=true`

**Parameters:** `ca_instance` (required), `key` (default `rsa`), `bits` (default 3072), `curve`,
`profile`

**Response:** `200`
`{"serial","cn","ca","notAfter":<unix>,"dir","sans":[…],"anchorAdded":bool,"note"}`; `400`;
`403` the CA is outside the caller's scope; `404` unknown CA; `409` the CA is not active, signs
with a scheme that has no separate digest (Ed25519, Ed448, ML-DSA), or does not chain to a
registered trust anchor; `500` (including `PG_TLS_DIR` unset)

**Audit:** `pg_tls_issued`

---

## 19. System

### GET /

The single-page console. Its styles, fonts and scripts are embedded.

**Auth:** none

**Response:** `200` text/html; charset=utf-8

---

### GET /healthz

Liveness probe.

**Auth:** none

**Response:** `200` text/plain `ok`

---

### GET /api/start-time

When this console process started, so the Config page can tell whether a changed setting is
pending a restart.

**Auth:** any authenticated caller

**Response:** `200` `{"time":<unix seconds>}`

---

### GET /api/version

The running version. With `check` (any value) it also queries the release feed:
`UPDATE_FEED_URL`, or the project's GitHub releases when that is empty.

**Auth:** `config:manage`

**Response (without check):** `200`
```json
{
  "version": "<version>",
  "license": {
    "state": "licensed",
    "number": "FPK-2026-0007",
    "customer": "Acme Corporation",
    "tier": "enterprise",
    "issued": "YYYY-MM-DD",
    "expires": "YYYY-MM-DD",
    "nodes": "3",
    "perpetual": false,
    "detail": "",
    "summary": "licensed: FPK-2026-0007 (Acme Corporation), expires YYYY-MM-DD"
  }
}
```

`license.state` is one of `evaluation`, `evaluation_over`, `licensed`, `expired` or `invalid`.
For the built-in evaluation, `number` is `FPK-EVAL`, `customer` is empty and `expires` is the
day the evaluation ends. `detail` says why a licence is `invalid` and is empty otherwise. Empty
fields are fields the licence does not carry. Nothing in the product acts on any of them.

**Response (with check):** the same, plus
```json
{
  "latest": "<latest>",
  "available": true,
  "notes": "<release notes>",
  "downloadUrl": "<url>",
  "error": ""
}
```

---

### POST /api/license

Install a licence. The body is the licence file's text, exactly as issued. The signature is
checked before anything is stored, and the text is saved to the `config` table as `LICENSE`,
so on a mesh it reaches every node by replication.

**Auth:** `config:manage` · requires `WEB_ALLOW_REVOKE=true`

**Response:** `200` `{"ok":true,"summary":"licensed: FPK-2026-0007 (Acme Corporation), expires YYYY-MM-DD"}`

**Errors:** `400` when the body is empty, does not parse, or its signature does not verify —
`error` says which. An expired licence that verifies is accepted and reported as expired.

---

### DELETE /api/license

Remove the installed licence. The deployment goes back to the built-in evaluation.

**Auth:** `config:manage` · requires `WEB_ALLOW_REVOKE=true`

**Response:** `200` `{"ok":true}`

---

### GET /api/setup

Whether a CA exists yet. The console does not call it.

**Auth:** `*:*`

**Response:** `200`
```json
{
  "initialized": true,
  "hasGlobalCa": false,
  "managedCas": 2,
  "pkiDns": "pki.example.org",
  "baseUrl": "https://pki.example.org",
  "writeEnabled": true
}
```

`managedCas` counts registered CAs with a certificate, within the caller's scope;
`initialized` is true when there is at least one. `hasGlobalCa` is always false.

---

### GET /api/summary

Headline counts for the dashboard.

**Auth:** `audit:read`

**Response:** `200` `{"certs":<int>,"audit":<int>,"discovered":<int>}` — `certs` counts issued
certificates within the caller's scope; `audit` and `discovered` are `null` for a CA-scoped
caller

---

## Summary Table

| # | Method | Path | Permission | Write Gate |
|---|--------|------|------------|------------|
| 1 | POST | `/api/login` | none | — |
| 2 | POST | `/api/logout` | any authenticated | — |
| 3 | POST | `/api/password` | `self:manage` | — |
| 4 | GET | `/api/me` | any authenticated | — |
| 5 | GET | `/api/auth-domains` | none | — |
| 6 | GET | `/api/auth-idps` | none | — |
| 7 | GET | `/api/oidc/status` | none | — |
| 8 | GET | `/api/oidc/login` | none | — |
| 9 | GET | `/api/oidc/callback` | none | — |
| 10 | GET | `/api/saml/status` | none | — |
| 11 | GET | `/api/saml/metadata` | none | — |
| 12 | GET | `/api/saml/login` | none | — |
| 13 | POST | `/api/saml/acs` | none | — |
| 14 | GET | `/api/certs` | `cert:read` | — |
| 15 | GET | `/api/certs/<serial>` | `cert:read` | — |
| 16 | POST | `/api/certs/<serial>/revoke` | `cert:revoke` | YES |
| 16a | POST | `/api/certs/<serial>/release` | `cert:revoke` | YES |
| 17 | POST | `/api/certs/request` | `cert:request` | YES |
| 18 | POST | `/api/certs/request-hsm` | `hsm:manage` | YES |
| 19 | GET | `/api/cert-algos` | `cert:read` | — |
| 20 | GET | `/api/my-profiles` | `cert:request` | — |
| 21 | GET | `/api/enrolment-credentials` | `cert:request` or `self:manage` | — |
| 22 | POST | `/api/enrolment-credentials` | `cert:request` or `self:manage` | YES |
| 22a | GET | `/api/device-tickets` | `user:manage` | — |
| 22b | POST | `/api/device-tickets` | `user:manage` | YES |
| 22c | DELETE | `/api/device-tickets/<ticket>` | `user:manage` | YES |
| 22d | GET | `/api/device-serials` | `user:manage` | — |
| 22e | POST | `/api/device-serials` | `user:manage` | YES |
| 22f | DELETE | `/api/device-serials/<serial>` | `user:manage` | YES |
| 22g | GET | `/api/scep-challenges` | `user:manage` | — |
| 22h | POST | `/api/scep-challenges` | `user:manage` | YES |
| 22i | DELETE | `/api/scep-challenges/<token>` | `user:manage` | YES |
| 23 | GET | `/api/audit` | `audit:read` | — |
| 24 | GET | `/api/audit/export-signed` | `audit:read` | — |
| 25 | GET | `/api/discovered` | `ca:manage` | — |
| 26 | GET | `/api/discovered/<id>/cert-text` | `ca:manage` | — |
| 27 | POST | `/api/discover` | `*:*` | YES |
| 28 | GET | `/api/compliance` | `cert:read` | — |
| 29 | GET | `/api/notify` | `config:manage` | — |
| 29a | PUT | `/api/notify/template` | `config:manage` | YES |
| 29b | DELETE | `/api/notify/template` | `config:manage` | YES |
| 29c | POST | `/api/notify/test-email` | `config:manage` | YES |
| 30 | GET | `/api/templates` | `template:edit` | — |
| 31 | POST | `/api/templates` | `template:edit` on the name | YES |
| 32 | GET | `/api/templates/ad` | `template:edit` | — |
| 33 | POST | `/api/templates/ad` | `template:edit` on every name | YES |
| 34 | POST | `/api/templates/import` | `template:edit` on every row | YES |
| 35 | DELETE | `/api/templates/<name>` | `template:edit` on the name | YES |
| 36 | GET | `/api/users` | `user:manage` or `self:manage` | — |
| 37 | POST | `/api/users` | `user:manage`, or `self:manage` for your own password | YES |
| 38 | DELETE | `/api/users` | `user:manage` | YES |
| 39 | GET | `/api/subject-roles` | `user:manage` | — |
| 40 | POST | `/api/subject-roles` | `user:manage` | YES |
| 41 | DELETE | `/api/subject-roles` | `user:manage` | YES |
| 42 | GET | `/api/assignable-roles` | `user:manage` or `role:manage` | — |
| 43 | GET | `/api/roles` | `role:manage` | — |
| 44 | POST | `/api/roles` | `role:manage` | YES |
| 45 | POST | `/api/roles/<role>/permissions` | `role:manage` | YES |
| 46 | DELETE | `/api/roles/<role>` | `role:manage` | YES |
| 47 | GET | `/api/permissions` | `role:manage` | — |
| 48 | GET | `/api/auth-providers` | `config:manage` | — |
| 49 | POST | `/api/auth-providers` | `config:manage` | YES |
| 50 | DELETE | `/api/auth-providers` | `config:manage` | YES |
| 51 | GET | `/api/ms-keytab` | `config:manage` | — |
| 52 | POST | `/api/ms-keytab` | `config:manage` | YES |
| 53 | GET | `/api/ldap/users` | `user:manage` | — |
| 54 | GET | `/api/ldap/groups` | `user:manage` | — |
| 55 | GET | `/api/ldap/groups/<group>/members` | `user:manage` | — |
| 56 | GET | `/api/directory-subjects` | `user:manage` | — |
| 57 | POST | `/api/directory-groups/<group>/refresh` | `user:manage` | — |
| 58 | GET | `/api/profiles` | `profile:edit` | — |
| 59 | POST | `/api/profiles` | `profile:edit` on the name | YES |
| 60 | DELETE | `/api/profiles` | `profile:edit` on the name | YES |
| 61 | GET | `/api/domains` | `config:manage` | — |
| 62 | POST | `/api/domains` | `config:manage` | YES |
| 63 | DELETE | `/api/domains` | `config:manage` | YES |
| 64 | GET | `/api/ca-instances` | `ca:read` | — |
| 65 | POST | `/api/ca-instances` | `ca:manage` (unscoped) | YES |
| 66 | GET | `/api/ca-instances/derived-urls` | `ca:manage` | — |
| 67 | POST | `/api/ca-instances/csr` | `ca:manage` (unscoped) | YES |
| 68 | POST | `/api/ca-instances/sign-csr` | `ca:manage` (unscoped) | YES |
| 69 | POST | `/api/ca-instances/<id>/status` | `ca:manage` | YES |
| 70 | DELETE | `/api/ca-instances/<id>` | `ca:manage` | YES |
| 71 | POST | `/api/ca-instances/<id>/renew` | `ca:manage` | YES |
| 72 | POST | `/api/ca-instances/<id>/cross-sign` | `ca:manage` | YES |
| 73 | GET | `/api/ca-instances/<id>/cert-text` | `ca:read` | — |
| 74 | GET | `/api/ca-instances/<id>/cert-pem` | `ca:read` | — |
| 75 | GET | `/api/ca-instances/<id>/xcep` | `ca:manage` | — |
| 76 | POST | `/api/ca-instances/<id>/xcep` | `ca:manage` | YES |
| 77 | GET | `/api/foreign-anchors` | `ca:manage` | — |
| 78 | POST | `/api/foreign-anchors` | `*:*` | YES |
| 79 | DELETE | `/api/foreign-anchors/<fingerprint>` | `*:*` | YES |
| 80 | GET | `/api/pkcs11/slots` | `hsm:read` | — |
| 81 | GET | `/api/pkcs11/keys` | `hsm:read` | — |
| 82 | GET | `/api/config` | `config:manage` | — |
| 83 | GET | `/api/config/status` | `config:manage` | — |
| 84 | GET | `/api/config/db` | `config:manage` | — |
| 85 | PUT | `/api/config/db` | `config:manage` | YES |
| 86 | DELETE | `/api/config/db` | `config:manage` | YES |
| 87 | GET | `/api/config/file` | `config:manage` | — |
| 88 | PUT | `/api/config/file` | `config:manage` | YES |
| 89 | GET | `/api/config/file/drift` | `config:manage` | — |
| 90 | GET | `/api/endpoints` | `config:manage` | — |
| 91 | GET | `/api/endpoints/health` | `config:manage` | — |
| 91a | GET | `/api/replication` | `*:*` | — |
| 91b | POST | `/api/replication/key-sync` | `*:*` | YES |
| 92 | POST | `/api/endpoints/<protocol>/enabled` | `config:manage` | YES |
| 93 | POST | `/api/endpoints/<protocol>/restart` | `config:manage` | YES |
| 94 | POST | `/api/endpoints/web/restart` | `config:manage` | YES |
| 95 | POST | `/api/restart` | `config:manage` | YES |
| 96 | GET | `/api/client-config/<kind>` | `cert:request` | — |
| 97 | GET | `/api/client-config/<kind>/edit` | `config:manage` | — |
| 98 | PUT | `/api/client-config/<kind>` | `config:manage` | YES |
| 99 | DELETE | `/api/client-config/<kind>` | `config:manage` | YES |
| 100 | POST | `/api/client-config/<kind>/preview` | `config:manage` | — |
| 101 | GET | `/api/backup` | `backup:manage` | — |
| 102 | POST | `/api/backup` | `backup:manage` | — |
| 103 | POST | `/api/backup/restore` | `backup:manage` | YES |
| 104 | POST | `/api/db-backup` | `backup:manage` | — |
| 105 | POST | `/api/db-backup/restore` | `backup:manage` | YES |
| 106 | POST | `/api/pg-tls` | `*:*` | YES |
| 107 | GET | `/` | none | — |
| 108 | GET | `/healthz` | none | — |
| 109 | GET | `/api/start-time` | any authenticated | — |
| 110 | GET | `/api/version` | `config:manage` | — |
| 111 | POST | `/api/license` | `config:manage` | YES |
| 112 | DELETE | `/api/license` | `config:manage` | YES |
| 113 | GET | `/api/setup` | `*:*` | — |
| 114 | GET | `/api/summary` | `audit:read` | — |
