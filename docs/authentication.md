# How authentication works in FastPKI

**Authentication** answers *who is this?* **Authorization** answers *may they do this?*
They are separate layers here. This page is about the first; §7 summarises the second and
[`rbac.md`](rbac.md) is the full account of it.

## Contents

- [1. The one-page answer](#1-the-one-page-answer)
- [2. The shared core](#2-the-shared-core)
- [3. EST and MS](#3-est-and-ms)
- [4. CMP](#4-cmp)
- [5. SCEP](#5-scep)
- [6. ACME](#6-acme)
- [6a. Federated console login: SAML (AD FS) and OIDC](#6a-federated-console-login-saml-ad-fs-and-oidc)
- [7. Authorization, briefly](#7-authorization-briefly)
- [8. Preparing a directory or identity provider](#8-preparing-a-directory-or-identity-provider)

---

## 1. The one-page answer

| surface | methods it accepts | credential store | can it be switched off? |
|---|---|---|---|
| **Console** (`fastpki-web`) | mTLS cert → session cookie → `WEB_TOKEN` bearer; sessions created by local login, OIDC, or SAML | `web_users` | open mode when no users exist and no `WEB_TOKEN` |
| **EST** | HTTP Basic; a TLS client certificate verified by `fastpki-est` itself (§3.1) | `web_users` | no |
| **MS-WSTEP** | Kerberos/SPNEGO → HTTP Basic → WS-Security UsernameToken | keytab; `web_users` | Kerberos only, by unsetting its keytab |
| **MS-XCEP** | Kerberos/SPNEGO → HTTP Basic → WS-Security UsernameToken (the same ladder as WSTEP) | keytab; `web_users` | Kerberos only, by unsetting its keytab |
| **ACME** | account-key JWS every request; External Account Binding once, at newAccount | `accounts.jwk`; `keys` | no — EAB is mandatory |
| **CMP** | PBM shared secret; certificate signature | `keys`; DB-built trust store | no — every message must be protected |
| **SCEP** | challengePassword (per-user or one-time); renewal bound to the cert it renews | `keys`; `scep_challenges`; `certs` | no — every non-renewal request must carry one (§5.1) |
| **OCSP / CRL** | none, by design | — | n/a |
| **Cert store** | none | — | n/a |

Three things follow from that table:

- **There is no single front door.** `pki::authenticate()` — the function that reads
  `web_users`, honours `AUTH_BACKEND`, and enforces the must-reset refusal — is called from
  **four places in three files**: `src/est/main.cpp` (Basic), `src/msxcep/main.cpp` twice
  (Basic and WS-Security UsernameToken), and `src/web/main.cpp`, the console's
  `/api/login`. ACME, CMP and SCEP never call it; each carries its own credential type and
  checks it itself.
- **`AUTH_BACKEND` reaches the console too, but only past the local hash.** `/api/login`
  tries `web_users` first and a local password still wins; when that does not authenticate
  and `AUTH_BACKEND` is not `local`, the console calls the shared function, so a directory
  user can sign in — onboarded with role `none` until an admin grants something (§2.2).
- **Every protocol requires a credential before it issues.** The one surface that answers
  without issuing anything is MS-XCEP, which returns a policy document — and it
  authenticates too, on the same ladder as WSTEP (§3.3).

---

## 2. The shared core

### 2.1 `pki::authenticate()` — `src/lib/auth.cpp`

```
authenticate(cfg, username, password, db) -> AuthResult{ok, role, ...}
```

In order:

1. Empty username or empty password → deny (`auth.cpp`).
2. **`web_users` is consulted first, and answers only when it holds a real password.** A row
   whose hash begins `pbkdf2$` is authoritative: the function returns there, success or
   failure, and never falls through to the backend. A row whose hash is anything else — the
   `!external` sentinel written when a federated identity is onboarded — has no local
   password to check, so the local store does not answer and the configured backend does.
   That row's **role** is still carried forward and applied to whatever the backend returns.
   Lookup is case-insensitive and returns the canonical row.
3. `verify_password` (`auth.cpp`) — PBKDF2-HMAC-SHA256, 16-byte salt, 32-byte output,
   210 000 iterations, constant-time compare.
4. **The must-reset refusal** (`auth.cpp`): a correct password on a row with
   `must_reset` set is still a deny. The console's must-reset gate is a *different* gate
   covering console routes only, so this one is what stops an unreset account enrolling
   over EST and MS.

`AUTH_BACKEND` selects what happens for a username **not** in `web_users`:

| value | behaviour for an unknown username | role it gets |
|---|---|---|
| `local` (default, and what `deploy/bootstrap.compose.conf` ships) | deny | — |
| `ldap` | LDAP simple bind (`ldap_auth.cpp`) against **the one directory the name qualifies**, see below | none — a directory login carries no role of its own. It gets whatever a `web_users` row or a `subject_roles` grant names for that qualified name, and nothing until one does |

> ⚠️ **Those two are the whole set.** No value of this key, and no other setting, turns
> password authentication off; the parser accepts nothing else.

#### An unqualified login is a LOCAL account, and reaches no directory

With `AUTH_BACKEND=ldap`, a name that carries **no directory** is not tried against the
directories. `web_users` has already been consulted and had no such row, so the answer is a
deny.

```
alice                    -> the web_users table, and nothing else
corp\alice               -> the directory whose id / display name / NetBIOS name / DNS root / realm is `corp`
alice@corp.example       -> the same, by DNS root
alice@CORP.EXAMPLE       -> the same, by Kerberos realm (the DNS root upper-cased)
```

The rule is the same whether one directory is configured or ten.

⚠️ **Those five names are compared case-insensitively and nothing checks them for uniqueness
across directories.** The first directory in priority order whose id, display name, NetBIOS
name, DNS root or realm matches wins. Keep every one of them distinct between directories —
in particular, do not give a directory a display name that is another directory's id.

The console's sign-in page carries a domain picker so nobody has to know the spelling; its
first option is "local account", so a directory is always a deliberate choice rather than one
inherited from list order. Non-console clients (EST, CMP, SCEP, MS Basic auth) send the
qualified name directly.

Two properties of the return value that matter to anyone reading a caller:

* **`AuthResult.role` is empty by default, including on failure** (`include/pki/auth.hpp`).
  There is no default role: a denial returns `{}`, so `ok` is false and `role` is the empty
  string, and a role appears only where a `web_users` row or a `subject_roles` grant put one.
  A caller must still test `ok` first, and all four call sites do.
* **Two sentinel hashes exist and neither can ever verify**: an empty string, written when
  EST auto-onboards an mTLS CN (`src/est/main.cpp`), and `"!external"`, written when
  OIDC or SAML onboards a federated user (`src/web/main.cpp`). `verify_password`
  returns false on a malformed stored value (`auth.cpp`), so these identities exist
  as rows and roles but hold no password by construction.

### 2.2 The console is a second door onto the same function

`/api/login` (`src/web/main.cpp`) tries the local `web_users` hash first, and a local
password still wins. When that does not authenticate **and** `AUTH_BACKEND` is not `local`,
it calls `pki::authenticate()` (`src/web/main.cpp`) — the same function EST and MS use.

- **`AUTH_BACKEND=ldap` therefore governs console sign-in as well as enrolment.** A
  directory user with no `web_users` row is onboarded on first successful sign-in with the
  sentinel hash `!external` and role `none`, so they reach the console and can do nothing
  until an admin grants a role (§7). Prepare the directory as §8 describes, then add it on
  the console's Directories page — see [`admin-guide.md`](admin-guide.md) §7.
- **A local-only deployment never reaches that path.** With `AUTH_BACKEND=local` the gate
  is closed and `web_users` is the whole story.
- The must-reset rule is enforced twice, by two different mechanisms — `auth.cpp` for
  enrolment, and a pre-routing gate in `fastpki-web` that lets a must-reset session reach
  only `/api/me`, `/api/password` and `/api/logout`.

### 2.3 Per-user enrolment credentials — `src/lib/enrol_creds.cpp`

`pki::ensure_enrolment_creds` creates **three** secrets for a user when any role they hold
grants `*:*` or a `<protocol>:enrol` permission:

| credential | used by | encoding on the wire |
|---|---|---|
| CMP PBM secret | CMP | the stored string, verbatim |
| ACME EAB HMAC | ACME | base64url-**decoded** to raw HMAC key bytes |
| SCEP challengePassword | SCEP | `<username>:<secret>` (§5.2) |

All three are 32 random bytes, base64url-encoded, and all three are stored under the
**plain username** as `keys.kid`. The `keys` table is keyed on `(kid, protocol)`, so the
`protocol` column is what keeps them apart — a client sends its bare username as the CMP
`-ref` value and as the ACME EAB kid, and each lookup is scoped to its own protocol.

Creating is idempotent: it fills in whatever is missing and never rotates a secret already
issued, so a config already downloaded stays valid.

⚠️ **Every path that asks "does this user enrol?" unions the group selectors in.** The
question is asked with a `user` selector *and* a `group` selector per group the subject
holds, so an identity whose enrolling role arrives through a group grant is treated exactly
like one granted directly. This matters in both directions, because one of these paths is
destructive: the user-write path **drops** the credentials when the answer is no, so asking
without the groups would revoke, on the next unrelated edit, the credentials another path
had just created.

Credentials are created at directory, SAML and OIDC sign-in; when a user is created, saved or
given a role (including by `fastpki-config web-user`); and by `GET /api/enrolment-credentials`
— which *ensures* rather than merely reads, so an account whose credentials predate a role
grant materialises the missing ones when it asks for them. They are dropped only when a user's
own account or role bindings are saved and no role enrols; editing or deleting a role, or
unbinding a role from a group, leaves them in place.
They are substituted into the downloadable client configs as `{{CMP_KID}}`,
`{{CMP_SECRET}}`, `{{ACME_EAB_KID}}`, `{{ACME_EAB_HMAC}}` and `{{SCEP_CHALLENGE}}`.

---

## 3. EST and MS

Both are password-capable, but they are not the same surface: EST also accepts a client
certificate and MS does not, while MS also accepts Kerberos and EST does not. The three
subsections below give each ladder in the order the server tries it.

### 3.1 EST — two methods, both real TLS

**HTTP Basic over TLS** (RFC 7030 §3.2.3) — `src/est/main.cpp` → `pki::authenticate`.
Cannot be disabled. This is how most callers, and every one of our own suites that does
not specifically test certificates, enrol.

**Client certificate** (RFC 7030 §3.3.2) — `fastpki-est` verifies the certificate with
its own TLS stack and takes the identity from `req.peer_cert().subject_cn()`. Anchors
come from `EST_CLIENT_CA_ID` (ca_instance ids, read from the DB) and
`EST_CLIENT_CA_BUNDLE` (PEM for external CAs) — the same additive, DB-first pair CMP uses.
Both are empty by default, and then EST never asks for a certificate at
all — Basic-over-TLS is the whole authentication surface, as RFC 7030 §3.2.3 allows.

The verifier is installed with `SSL_VERIFY_PEER` and deliberately **not**
`SSL_VERIFY_FAIL_IF_NO_PEER_CERT` (`pki::install_client_trust`, `src/lib/ca_instance.cpp`).
Sending no certificate is allowed and falls through to Basic; sending one that does not
verify terminates the handshake. That combination is what lets the handler treat a
non-empty `peer_cert()` as proof rather than a claim.

**A proxy in front of EST must not terminate TLS.** Forward TCP at L4 (DNAT, or nginx's
`stream {}` block) so the handshake reaches the process that can check it. There is no
way for a terminating proxy to tell EST what it verified, on purpose.

#### The DN supplies the name, and nothing else

A `role=` RDN in the client's own certificate is ignored: that RDN is written by whoever
asked for the certificate, so presenting it over verified mTLS proves only that they asked
for it. The role is resolved from `web_users` by CN, and a CN with no row is refused
(role `none`) and onboarded for an admin to grant. No request header can supply an
identity, or override the certificate a client did present.

**Unauthenticated EST routes:** `/cacerts` (by RFC 7030 §4.1 design) and `/csrattrs`, where
authentication is *optional* — an unauthenticated caller is served `EST_DEFAULT_PROFILE`
rather than refused.

### 3.2 MS-WSTEP — three methods, none of them a certificate

Tried in order, first success wins. This is one function, `ms_authenticate()`
(`src/msxcep/main.cpp`), shared with XCEP rather than copied into it:

1. **Kerberos / SPNEGO** — `Authorization: Negotiate`. Genuinely implemented: a real GSSAPI
   acceptor at `src/msxcep/kerberos.cpp`, multi-leg NTLM explicitly refused.
   Requires a keytab uploaded for the directory (Directories page → the directory's
   editor) *and* a build with Kerberos support; either
   missing disables it silently. The identity is **provider-qualified**, exactly as it is on
   Basic and UsernameToken: `alice@CORP.EXAMPLE` authorizes `corp\alice`, not bare `alice`. The
   directory is chosen from the ticket's realm, and from nothing else — a directory's realm is
   its DNS root upper-cased, the same rule Windows uses. If the realm names no directory, or
   names more than one, the ticket is **refused**: a name with no qualifier means the local
   `web_users` table, and calling a directory principal local would let one account collect
   every directory's group memberships at once. Set exactly one directory's DNS root so its
   realm resolves.

   The directory comes from the realm and never from which keytab accepted the ticket. Under
   a cross-forest trust one keytab accepts clients from every realm that trusts it, so the
   keytab does not identify a directory.

   A principal seen for the first time is onboarded into `web_users` with role `none` and
   `auth_provider = kerberos`, so an admin can see it in order to grant it something; the
   ticket stays the only credential, as there is no password hash to verify against.
   Authorization is the union of that row's role and the subject's `subject_roles` grants.
2. **HTTP Basic** → `pki::authenticate`.
3. **WS-Security UsernameToken** — `<Username>`/`<Password>` in the SOAP body →
   `pki::authenticate`. Matched by local name, namespace prefix ignored.

There is **no client-certificate path on MS-WSTEP at all.**

#### A domain computer is a principal like any other — and is labelled as one

Windows autoenrolment for a machine template runs as the **machine account**, so the
Kerberos client principal is `WS01$@CORP.EXAMPLE` and the identity FastPKI records is
`corp\WS01$` — qualified by the directory that realm resolves to, like any other
principal. (`pki::principal_kind()` is unaffected by the qualifier — it tests for a
trailing `$` or an embedded `/`, and a prefix changes neither — so a machine account is
still labelled a computer.) Two consequences:

* **It needs two grants, and it has no account to hang them on.** Nothing is granted by
  default, so a freshly joined machine gets `WSTEP 403 — … lacks ms:enrol` — or, if it
  lacks the template grant instead, a policy document with an EMPTY template list, which
  the client reports as `WS_E_INVALID_FORMAT` and which names no permission at all. The
  role needs both:

  ```
  ms:enrol|<ca_id>          the {ca_id} in the /msxcep/{ca_id} URL the client is pointed at
  template:use|<Template>   the template it will enrol with
  ```

  Scope `ms:enrol` to a named CA rather than `*` unless every CA in the estate should serve
  machines.

  ⚠️ **Bind it to a PROVIDER-QUALIFIED name.** Every group and every principal is qualified
  by the directory that authenticated it, so the selector is `<directory-id>\Domain
  Computers` — a bare `Domain Computers` matches nobody. It fails silently: the role is
  created, the binding is accepted, every call returns 200, and the grant simply never
  applies. The server names the identity it is deciding for in its log
  (`XCEP offering 0 of N templates to 'corp\WS01$'`), which is the fastest way to see the
  form it expects. The Directories page lists groups in exactly that qualified form.

  Binding to the **group** rather than the computer is the maintainable choice, and
  `Domain Computers` works even though it is a machine's *primary* group — AD expresses
  that as `primaryGroupID` rather than a `member` link, and `directory_groups_for()`
  synthesises it so the grant resolves. Binding to one machine
  (`<directory-id>\WS01$`) is equally valid and is what a test rig usually wants.
* **The console says `computer`, not `user`.** `pki::principal_kind()`
  (`include/pki/auth.hpp`) classifies a principal from its name: a trailing `$` (AD
  mandates it for machine accounts) or a `/` anywhere (the `service/instance` form, which a
  non-Windows client with a keytab presents). It is DERIVED, never stored, and it is the
  only implementation — every surface that names a principal asks it: the Users tab,
  directory-derived group members, grant rows, the Inventory Owner column and its detail
  modal, and the Audit Actor column.

### 3.3 MS-XCEP — the same ladder as WSTEP

`POST <XCEP_PATH>/{ca_id}` (GetPolicies) calls `ms_authenticate()` — the same
Kerberos → Basic → UsernameToken ladder §3.2 describes, because it is literally the same
function. Windows fronts XCEP with IIS authentication, so a client already expects to
authenticate here.

**It refuses with 401 and a `WWW-Authenticate` challenge, never a soap:Fault.** XCEP is the
first call a Windows autoenrolment client makes, before it holds any credential context: it
expects to be challenged and to retry. WSTEP maps a bad UsernameToken to a soap:Fault; that
mapping is not applied here.

**Authentication only — no `ms:enrol` check.** GetPolicies returns the template catalogue,
not a certificate. A subject who may sign in but not enrol reads the policy and is refused
at WSTEP, where the refusal describes the real problem.

---

## 4. CMP

### 4.1 PBM — per-user shared secret

FastPKI re-decodes the raw PKIMessage itself (`src/lib/cmp_asn1.cpp`) because
OpenSSL's server API hides the sender, takes `header.senderKID` verbatim, and looks it up in
`keys` (`db_postgres.cpp`). The kid **is** the username. The secret is installed into the
OpenSSL context (`src/cmp/main.cpp`) and cleared afterwards.

No `keys` row means no secret is installed, so the MAC cannot verify — **that is the
refusal**. There is no server-wide fallback secret and no key that configures one: a
per-user `keys` row is the only source, so an unknown `senderKID` is a denial rather than a
fall-through to something shared.

### 4.2 Certificate signature

Trust anchors are assembled **from the database**, never a file
(`build_cmp_client_store`, `src/cmp/main.cpp`), from two additive sources:
`CMP_CLIENT_CA_ID` and `CMP_CLIENT_CA_BUNDLE`. Both default empty. The anchor CA does not
have to be one FastPKI can issue from. The store hot-reloads under the same mutex the
request path uses.

### 4.3 Protection is mandatory, and revocation is stricter still

`OSSL_CMP_SRV_CTX_set_accept_unprotected` is a hard `0`: every message must carry PBM or a
signature. No configuration key changes that, and the parser does not recognise one — a
config that tries to weaken it fails loudly as an unknown key rather than quietly taking
effect.

Revocation (`rr`) is held to a higher bar than enrolment, and all four rules are
unconditional:

1. **PBM is refused.** A shared secret is an enrolment credential; revoking requires
   signature-based protection, so the caller is a verified certificate holder.
2. **The signer must be identifiable** — the sender CN bound to a certificate in
   `extraCerts`, after OpenSSL has verified the protection.
3. **The target must belong to the CA the request was posted to.** This is decided before
   the grant check, because `revoke_cert()` matches on serial alone; without it a caller
   authorized on one CA could revoke certificates belonging to every other CA.
4. **A caller may revoke only what it owns**, unless one of its roles grants
   `cert:revoke` scoped to that CA. That check uses `subject_holds()` rather than
   `may_enrol()` — the strict form, which does not answer true on a deployment with no roles
   defined — and it unions the caller's directory groups, so a grant held through a group
   counts.

---

## 5. SCEP

### 5.1 A challengePassword is never optional

`require_challenge` is `!is_renewal`, unconditionally: every enrolment that is not a
renewal must carry a challengePassword. No configuration turns that off — a caller presents
a per-user credential (§5.2) or a one-time token (§5.3), and both live in tables rather
than in config.

### 5.2 Per-user challenge

This is the one SCEP credential that names somebody, so it is the only one `scep:enrol`
can be enforced for (§5.5), and one device's access can be withdrawn without rotating
what every other device uses. §2.3 creates it — the same call
that creates the CMP PBM secret and the ACME EAB key — under the plain username as kid, in
the `keys` table, distinguished from the others by the `protocol` column. The wire form is:

    <username>:<43-char base64url secret>

The server splits on the **first** colon (`parse_scep_challenge`), looks the kid up scoped
to the SCEP protocol, and compares the secret with `CRYPTO_memcmp`. Exactly one colon is
permitted: a value whose secret half contains another is rejected outright rather than
guessed at, so a username containing `:` cannot be smuggled past the split.

Nothing about RFC 8894 changes: the challengePassword is a PKCS#9 attribute in the CSR and
the RFC never said its value had to be shared. What changes is that a request carrying one
names a `web_users` row — which is what makes §5.5's permission enforceable.

The downloadable SCEP config carries this per-user value, so a user who can download a
config receives only their own secret.

### 5.3 One-time challenge — `SCEP_DYNAMIC_CHALLENGE`

A token in the `scep_challenges` table, consumed once. Default off. It can be created
**only from the CLI**: `fastpki-scep --config <path> --issue-challenge [profile]`. There is no console
route and no API — `add_scep_challenge` has exactly one caller in the tree.

The token carries a cert **profile**, written by `--issue-challenge` and returned by the SQL, and it
is honoured at issuance. It goes through `resolve_profile()` like any other request, so a
token cannot escalate to a profile the SCEP identity is not entitled to — and `--issue-challenge` asks
the same question up front, so an unusable profile is refused at the mistake rather than at
some device's enrolment weeks later.

### 5.4 Renewal — `SCEP_RENEWAL`, **default true**

If the CMS signer certificate verifies against the CA public key, is currently valid, and
its `certs` row is status 0, the request is treated as a renewal and **the challenge is not
required**. This is the one path that bypasses the challenge, and it is on by default.

A renewal is bound to the certificate it renews: the CSR's subject must match exactly
(`X509_NAME_cmp`, canonical encoding) and its SANs must be a **subset** of the old
certificate's. Dropping a name is allowed — clients legitimately do it when a hostname is
retired — and adding one is refused, which is the escalation. Expiry and notBefore are
checked, and a `certs` lookup that FAILS is not treated as "not revoked".

### 5.5 Authorization: `scep:enrol`, on the per-user path only

The gate applies **only** to a per-user challengePassword (§5.2), because that is the only
SCEP credential naming a `web_users` row. A device presenting a one-time dynamic token, or
renewing an existing certificate, has no user, so there is nothing to authorize and it
passes the gate.

A per-user enrolment also records the real owner: `certs.owner` is the username, not the
literal `scep`, and the profile is resolved for that user rather than a shared `scep`
identity.

### 5.6 Unauthenticated SCEP operations

`GetCACert`, `GetCACaps`, `GetNextCACert` (all correct per RFC 8894 §4.2), plus `GetCRL`,
`GetCert` (returns any certificate by issuer-and-serial), and `GetCertInitial` (keyed on
transactionID alone — nothing binds the poller to the original requester).

---

## 6. ACME

**Every POST** carries a JWS. `parse_acme_post` (`src/acme/main.cpp`) requires
`application/jose+json`, a matching `url`, a live nonce, and a verified signature. ES256 and
RS256 only; EC restricted to P-256 (`src/lib/jws.cpp`).

Two forms:

- **kid-form** — the key is fetched from `accounts.jwk` and the signature checked against it.
  This proves *the same key as last time*. It never proves *which person*.
- **jwk-form** — the key is taken from the request and the signature checked against itself.
  A self-signed JWS always verifies, so on its own it proves possession of a key and nothing
  more. RFC 8555 §6.2 permits this form on newAccount, revokeCert and the key-change inner
  JWS only, and that is what the code enforces: newAccount **requires** it
  (`newAccount must use jwk`), key-change **refuses** it on the outer JWS, and every other
  route answers `kid required`. On revokeCert it is accepted only when the request's key
  matches the certificate's own SubjectPublicKeyInfo — the RFC 8555 §7.6 authorization.

**EAB is the only thing that ties an ACME account to a local identity**, and it happens
**once**, at newAccount (`verify_eab`, `src/acme/main.cpp`, HS256 with a constant-time
compare). The binding's kid is the caller's plain username and the HMAC key is read from
`keys` scoped to the EAB protocol (§2.3), so an account is bound to a `web_users` identity
that holds an enrolling role. After that the account stands on its own key.

EAB is MANDATORY: a newAccount request without one is refused with
`externalAccountRequired`, and no setting accepts an ACME account that is not bound to a
local identity.

Challenge validation (http-01, dns-01, tls-alpn-01) proves **control of a domain name**, not
the identity of a person. `allowed_domains` and CAA are policy applied to the name. Neither
is authentication.

Note that http-01 validation is hardcoded to port 80 (`src/acme/main.cpp`), as RFC 8555
§8.3 requires; tls-alpn-01 uses `ACME_TLS_ALPN_PORT`.

---

## 6a. Federated console login: SAML (AD FS) and OIDC

These sign a user **into the console**. They do not authenticate an enrolment protocol —
EST, CMP, SCEP, ACME and MS-XCEP have their own credentials, covered above.

⚠️ **There are no `SAML_*` or `OIDC_*` config keys.** A federated provider is a row, added
on the **Directories** page or with `POST /api/auth-providers` (`kind=saml` or `kind=oidc`),
exactly like an LDAP directory. Looking for a config key and finding none reads as "not
supported"; it is the same table, and the same provider id qualifies every subject it
authenticates.

**The four endpoints**, under this node's own console address — `BASE_URL` when it is set,
otherwise `<PKI_DNS>:<console port>`, over https when the console has a TLS key:

| endpoint | who calls it |
|---|---|
| `GET /api/saml/metadata` | you, to hand the SP metadata to AD FS |
| `GET /api/saml/login` | the browser, to start sign-on |
| `POST /api/saml/acs` | the identity provider, posting the assertion |
| `GET /api/saml/status` | reports whether SAML is set up; the sign-in page's buttons come from `GET /api/auth-idps` |

OIDC is the same shape with `/api/oidc/login`, `/api/oidc/callback` and `/api/oidc/status`.

**What a SAML row holds**: `idp_entity_id`, `idp_sso_url`, `idp_cert`, `sp_entity_id`,
`username_attr`, `groups_attr`, `admin_group`, `auditor_group`, `require_local_user`,
`clock_skew_sec` (default 120). `idp_sso_url`, `idp_cert` and `sp_entity_id` are required.

**The email address is taken at every sign-in**, for expiry emails about the person's
certificates, and written to the account's `web_users.email` when the account has a row. OIDC
reads the standard `email` claim, unless the provider marks it with `email_verified` false. SAML
reads the first of these attributes the assertion carries:
`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` (AD FS, Entra ID),
`urn:oid:0.9.2342.19200300.100.1.3`, `mail`, `email`. Failing those, it uses the NameID when its
format is `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`. There is no setting for it. To
have AD FS send it, add a rule issuing the `emailaddress` claim from the `mail` LDAP attribute. An
account signed in through a group mapping alone has no row, so its address is not kept.

**The address the identity provider sends people back to is not stored.** The provider tables
replicate across a mesh, so one stored value would send every node's users back to one node.
Each node uses its own console address followed by `/api/saml/acs` or `/api/oidc/callback`; the
Directories page shows it as `callback_url`, and that is the address to register with the
identity provider — once per node. `/api/saml/acs` and `GET /api/saml/metadata` answer for the
first enabled SAML provider; with more than one, register the others by hand.

⚠️ **`idp_cert` is a FILE PATH inside the container**, not the certificate text — the same
shape as an LDAP directory's `ca_cert_file`, and the console labels it that way. Pasting the
PEM in fails at the first assertion with `SAML: cannot load IdP certificate` followed by the
PEM itself, which reads as a malformed certificate rather than a value in the wrong form.
Put it on the shared `/var/pki` volume and name it there.

### Setting it up against AD FS

Measured against Windows Server 2022 AD FS:

```powershell
# on the AD FS server — import our SP metadata rather than typing the endpoints
Add-AdfsRelyingPartyTrust -Name "FastPKI Console" `
  -MetadataUrl "https://pki.example.org:8090/api/saml/metadata"

# permit everyone the trust applies to, then emit the two claims FastPKI reads
Set-AdfsRelyingPartyTrust -TargetName "FastPKI Console" `
  -IssuanceAuthorizationRules '=> issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");' `
  -IssuanceTransformRules @'
@RuleName = "UPN"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"), query = ";userPrincipalName;{0}", param = c.Value);

@RuleName = "Groups as roles"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://schemas.microsoft.com/ws/2008/06/identity/claims/role"), query = ";tokenGroups;{0}", param = c.Value);
'@
```

**Back in FastPKI**, on the Directories page (or `POST /api/auth-providers`), set
`username_attr` to the UPN claim URI and `groups_attr` to the role claim URI above.

The last field, `idp_cert`, is the AD FS token-signing certificate. Export it on the AD FS
server:

```powershell
$c = (Get-AdfsCertificate -CertificateType Token-Signing)[0].Certificate
[Convert]::ToBase64String($c.RawData)
```

That prints one long base64 line, and `idp_cert` is a **file path**, not the text. Wrap the
base64 at 64 columns, put `-----BEGIN CERTIFICATE-----` above it and
`-----END CERTIFICATE-----` below it, and save the result on the shared `/var/pki` volume
of **every node that serves the console** — for example `/var/pki/tls/adfs-signing.pem`.
That path is what goes in `idp_cert`.

⚠️ **AD FS binds its HTTPS listener in HTTP.SYS, not IIS.** If that binding names a
certificate that is not in `LocalMachine\My`, every TLS handshake is reset with no
error anywhere — the service still reports Running. `netsh http show sslcert` shows the
bound thumbprint; compare it against the store before suspecting the network. FastPKI can
issue the replacement, and `netsh http update sslcert hostnameport=… certhash=… appid=…`
rebinds it.

⚠️ **A SAML assertion is time-bounded**, and `clock_skew_sec` is the only tolerance. A
console that rejects every assertion when nothing has changed is a clock problem before it
is a certificate problem.

### The group asymmetry, which is the sharp edge here

**`admin_group` and `auditor_group` take a BARE group name.** The groups an IdP asserts are
stored provider-qualified (`corp\pki-admins`) so they cannot collide between providers, and
the code qualifies the configured name with the same provider before comparing. So write
`pki-admins`, not `corp\pki-admins`.

⚠️ **This is the opposite of an RBAC grant.** A `subject_roles` selector is matched against
the qualified name as stored, so there you write `corp\pki-admins`. Getting either backwards
fails the same silent way: the row saves, the login succeeds, and the user quietly lands on
`none`.

|  | what you type |
|---|---|
| a provider's `admin_group` / `auditor_group` | `pki-admins` — bare |
| an RBAC `subject_roles` selector | `corp\pki-admins` — qualified |

⚠️ **The auto-map only runs while the user has no `web_users` row, and a first login that
matches nothing CREATES one.** The two halves are asymmetric, and the second is the trap:

| first login | what happens | afterwards |
|---|---|---|
| matches `admin_group` / `auditor_group` | role assigned, **nothing persisted** | re-evaluated every login, so revoking the group takes effect next sign-in |
| matches neither | onboarded as `none` and **persisted** | the row wins from then on — granting the group later changes nothing |

So a user who signs in *before* being put in the right group is stuck on `none`, and adding
them to the group afterwards does not fix it. Either delete the row so the auto-map runs
again at the next sign-in, or set the role on the row directly — which is what the
persisted row is for: it is how an administrator finds a federated user who has appeared
and needs a role.

`require_local_user=true` turns the auto-map off entirely: only users who already exist in
`web_users` may sign in.

## 7. Authorization, briefly

Authentication produces a subject. Authorization is table-driven and separate, and this
section is a summary — **[`rbac.md`](rbac.md) is the full account**: every verb, what scope
means, how a role is granted, and the sharp edges an operator has to know before designing
one.

- **Enrolment**: `pki::may_enrol(db, user, role, verb, ca_id)` — `src/lib/enrol_gate.cpp`.
  Verbs are `est:enrol`, `acme:enrol`, `cmp:enrol`, `ms:enrol` and `scep:enrol` — the last
  enforced on the per-user path only, since a shared credential names no one to check
  (§5.5). Roles are resolved from three sources: the caller's role, the `web_users` row, and
  `subject_roles`. `*:*` is the wildcard here — see the note below, because it is not
  one in the console.
- **Console**: `required_caps(path, method)` (`src/web/main.cpp`) maps a route to a set
  of capability verbs; holding any one passes. The default is `*:*`, so a route nobody
  mapped is admin-only rather than open. Permissions live in `roles` / `role_permissions`,
  whose `scope` column narrows a grant to a CA id, a profile name or a template name
  depending on the verb; `*` means every one of them.
- **Profiles and templates** restrict *what may be in the certificate*. They are a different
  plane from roles and do not grant or deny access to a protocol.

**`*:*` is a wildcard everywhere.** `may_enrol()`, `subject_holds()`, the console's route gate
`caps_allow()`, and the handler checks past it (`/api/users` deciding whether a caller manages
every account; the profile and template editors deciding which names a caller may write) all
accept it in place of any verb — the handler checks only at scope `*`, because a `*:*` scoped
to a CA names a CA and not a profile or template. See [`rbac.md`](rbac.md) §2.

### 7.1 Granting a role is bounded by what the grantor holds

`user:manage` lets a subject administer accounts. It is **not** a route to `admin`, and two
rules keep it that way, both enforced server-side:

1. **A caller may only assign a role whose grants it already holds** — on `POST /api/users`
   and on `POST /api/subject-roles`, since binding a role to a group is the same act by
   another door. Both halves of a grant bind, so a CA-scoped admin (`*:*|ca-a`) can hand out
   `*:*|ca-a` and not `*:*|*`. `*:*` counts as a wildcard over *verbs* for this test — the
   builtin `admin` does not literally hold every permission the other builtins do, so a
   name-for-name subset test would stop an admin assigning `requester` — but the scope half
   still binds.
2. **Nobody changes their own primary role**, including an admin — on `POST /api/users`.
   Compared against the stored value, so an ordinary edit that re-posts the role it already
   has is unaffected.

Neither rule covers **removing** a role (`DELETE /api/subject-roles`, `DELETE /api/users`), and
neither covers the role editor: a holder of `role:manage` may add any grant to any role,
including one it holds. `role:manage` is therefore an administrator's permission; see
[`rbac.md`](rbac.md) §6.

The open-mode bootstrap — no users, no session, therefore no grants — is exempt from both
rules, exactly as it is for `manages_users()`, or the request that creates the first
administrator could never be authorized.

### 7.2 Profiles and templates: which one applies, and to what

They are the same kind of thing — a resource a role is granted on — and they divide by
protocol, not by importance:

| | selects the policy for | granted as |
|---|---|---|
| **certificate profile** | every protocol *except* MS-WSTEP | `profile:use` / `profile:edit`, scoped to the profile name |
| **MS certificate template** | MS-WSTEP only | `template:use` / `template:edit`, scoped to the template name |

A Windows enrolment client names the template it wants in the CSR — as a BMPString in
`szOID_ENROLL_CERTTYPE_EXTENSION` (`1.3.6.1.4.1.311.20.2`), or as the template OID inside
`szOID_CERTIFICATE_TEMPLATE` (`1.3.6.1.4.1.311.21.7`). Both are read. The template is then
resolved by the same rules a profile is:

1. a named template is honoured **only if** one of the caller's roles grants it;
2. with no name, a single permitted template is unambiguous;
3. anything else is refused, naming the choice — **including holding no template grant at
   all**, which is a refusal and never a fallback to "issue whatever was asked for".

The resolved template supplies the certificate's key usage, EKUs and maximum validity, and
those same fields are the allow-list the CSR is checked against. A request asking for a key
usage or EKU the template does not list has it **dropped**, not refused: the certificate is
issued carrying only what the template allows. The one refusal is a request whose every
requested key-usage bit was dropped, because an empty KeyUsage would violate RFC 5280
§4.2.1.3. `min_key_size` is enforced separately because a profile has no equivalent field.

The permission is what matters, not the role name — a template granted to a **group** the
caller belongs to counts exactly as one granted to the user.

---

## 8. Preparing a directory or identity provider

This section is the work done **outside** FastPKI before a provider is added. Adding it — the
fields of the Directories page and the equivalent command — is
[`admin-guide.md`](admin-guide.md) §7.

**None of these are configuration keys.** Every provider is a row, and so is its keytab:

| | Rows in | Added with |
|---|---|---|
| LDAP / Active Directory | `auth_providers` + `ldap_providers` | the Directories page, or `fastpki-config auth-providers-add` |
| SAML | `auth_providers` + `saml_providers` | the Directories page |
| OIDC | `auth_providers` + `oidc_providers` | the Directories page |
| Kerberos keytab | `ldap_providers.krb_keytab`, a field of an Active Directory directory | an upload on the Directories page |

An `LDAP_*` key in a config file configures nothing and is ignored. Neither do `OIDC_*` and
`SAML_*` variables; `fastpki-web` logs an error when it finds one of seven it checks for by
name (the issuer, client id and secret and redirect address for OIDC; the IdP sign-in address,
entity id and certificate for SAML). Directory sign-in also needs `AUTH_BACKEND=ldap`
(§2.1).

### 8.1 LDAP or Active Directory

1. **A read-only service account.** In *Active Directory Users and Computers* add an ordinary
   user, for example `svc-fastpki`, with **Password never expires** ticked and **User must
   change password at next logon** cleared. It needs no group beyond *Domain Users*: FastPKI
   only reads.
2. **The container that holds the users.** A password check binds as `CN=<username>,<base>`,
   one attempt per base, so the base list must name the container the user entries are in,
   not only the domain. On Active Directory accounts are under `CN=Users` by default, and a
   base of only `DC=corp,DC=example` fails every login with `invalid credentials` while the
   directory is perfectly reachable. Give the user container first, then the domain root if
   group search needs the whole tree: `CN=Users,DC=corp,DC=example;DC=corp,DC=example`.
3. **The CA certificate behind LDAPS.** For `ldaps://` (which you should use), export the CA
   that signed the domain controllers' certificates as Base-64 PEM and place it where the
   services can read it, for example on the `/var/pki` volume. Give the **root**, not only the
   issuing CA: libldap does not accept a partial chain. FastPKI can issue the domain
   controllers' certificates itself — see
   [`windows-autoenrolment.md`](windows-autoenrolment.md).
4. **Name resolution.** The directory is reached by name, and keep it a name: an `ldaps://`
   certificate is issued to the domain controller's name, and Kerberos needs the SRV records
   only the AD DNS serves. A host that is not domain-joined has usually never heard of the AD
   zone, and the failure reads like a firewall or a credentials fault:

   ```
   ldap_list_groups: bind failed @ ldap://dc1.corp.example: Can't contact LDAP server
   ```

   Point the deployment at the domain's DNS, in `deploy/.env` (Docker Compose) or
   `deploy/k8s/env.sh` (Kubernetes), then `docker compose up -d` or re-run `apply.sh`:

   ```bash
   DIRECTORY_DNS=192.0.2.53
   DIRECTORY_DNS_SEARCH=corp.example
   ```

   On Docker Compose give one address. On Kubernetes several may be listed, separated by
   commas — ⚠️ **as failover, not as a union of zones**: the resolver moves to the next server
   only on a timeout, and an authoritative "no such name" from the first ends the query.
   For two independent forests, point this at one resolver that forwards each zone to its own
   servers. On Kubernetes the entries are added after cluster DNS, so in-cluster names are
   unaffected. Check from inside a container: `docker compose exec web nslookup dc1.corp.example`.
   A host that already resolves the AD zone needs neither variable.

### 8.2 A Kerberos keytab

Creating the service account, the SPN and the keytab on a domain controller, and checking it
with `kinit`, is [`windows-autoenrolment.md`](windows-autoenrolment.md) "Setting it up". The
keytab is then uploaded onto the Active Directory directory it belongs to.

### 8.3 A SAML identity provider

1. **Register FastPKI as a service provider.** The provider needs two values: an **entity ID**
   of your choice, for example `https://pki.example.org/sp`, entered identically in FastPKI's
   `sp_entity_id`; and the **assertion consumer service (ACS) address**, which is each node's
   own console address followed by `/api/saml/acs` (§6a) — register one per node. Against
   AD FS, import the metadata instead, as §6a shows.
2. **Release the claims**: a username attribute and, for role mapping, a groups attribute.
3. **Export the provider's signing certificate** as Base-64 PEM, and place it where the
   services can read it; `idp_cert` is its path.

### 8.4 An OIDC identity provider

1. **Register a confidential client** with the provider (Entra ID, Keycloak, Okta …). The
   redirect address is each node's own console address followed by `/api/oidc/callback`;
   register one per node.
2. **Collect** the issuer URL (the one serving `/.well-known/openid-configuration`), the client
   id and the client secret.
3. **Decide scopes and claims.** `openid email profile` covers most deployments; note which
   claim carries the username (FastPKI defaults to `email`) and which carries groups
   (default `groups`).
4. If the issuer's HTTPS certificate comes from a private CA, place that CA's certificate where
   the services can read it; `ca_cert` is its path.

