# FastPKI Protocol Server APIs

This document covers the HTTP APIs exposed by the 7 protocol server binaries (not the web console — see [API Reference](api-reference.md) for that).

## Contents

- [1. OCSP Responder — `fastpki-ocsp` (RFC 6960)](#1-ocsp-responder--fastpki-ocsp-rfc-6960)
- [2. EST Responder — `fastpki-est` (RFC 7030)](#2-est-responder--fastpki-est-rfc-7030)
- [3. ACME Server — `fastpki-acme` (RFC 8555)](#3-acme-server--fastpki-acme-rfc-8555)
- [4. CMP Server — `fastpki-cmp` (RFC 4210/9810)](#4-cmp-server--fastpki-cmp-rfc-42109810)
- [5. SCEP Server — `fastpki-scep` (RFC 8894)](#5-scep-server--fastpki-scep-rfc-8894)
- [6. MS-XCEP + MS-WSTEP — `fastpki-ms`](#6-ms-xcep--ms-wstep--fastpki-ms)
- [7. Certificate Store — `fastpki-store` (RFC 4387)](#7-certificate-store--fastpki-store-rfc-4387)
- [Summary](#summary)

---

## 1. OCSP Responder — `fastpki-ocsp` (RFC 6960)

**Default:** `http://0.0.0.0:8080` | **Transport:** Plain HTTP | **Payload limit:** 64 KiB

### GET `/{ca_id}.crl` — CRL Distribution (the canonical route)

Returns the DER-encoded Certificate Revocation List for one CA. **This is the URL baked into
every issued certificate's CRL distribution point**, so it is the one a relying party actually
fetches (`u.crl = base + "/" + ca_id + ".crl"`, `src/lib/x509.cpp`).

| Aspect | Detail |
|--------|--------|
| Path | `/{ca_id}.crl` — e.g. `/issuing-ca.crl` |
| Auth | None |
| Query | `?base=<n>` — delta CRL base (when `CRL_DELTA` enabled) |
| Response 200 | `Content-Type: application/pkix-crl`, `Cache-Control: no-cache`, DER CRL |
| Response 503 | "CRL unavailable: the CA signing key is remote" |

Every revoked certificate is listed, certificates on hold included (reason `certificateHold`).
An entry revoked as `unspecified` carries no CRL Reason Code, as RFC 5280 §5.3.1 recommends. A
delta CRL (`?base=<n>`) lists the revocations and holds made at or after `n`, and the holds
released at or after `n` with reason `removeFromCRL`; a full CRL simply no longer lists a
released certificate.

> ⚠️ **The id-less `/<crl_path>` alias answers 404** (`use /{ca_id}.crl`). `CRL_PATH` is the
> prefix of the per-CA form below, not a URL that serves anything by itself — there is
> no default CA whose revocations it could list.

### GET `/<crl_path>/{ca_id}` — Per-CA CRL

Returns DER CRL for a specific CA instance.

| Aspect | Detail |
|--------|--------|
| Path | e.g. `/pki/signing_ca.crl/dept-a` |
| Auth | None |
| Response 404 | "unknown CA instance" |
| Response 503 | "CA instance disabled" or "CA signing key is remote" |

### GET `/<ca_id>.crt` — CA Certificate (AIA `caIssuers`)

The DER certificate for a CA instance. This is what the `caIssuers` accessPoint in an
issued certificate points at, so a relying party building a path fetches it here.

| Aspect | Detail |
|--------|--------|
| Path | e.g. `/dept-a.crt` |
| Auth | None |
| Response 200 | `application/pkix-cert`, DER |
| Response 404 | "unknown CA instance" |

It serves **the newest certificate an issuer above actually signed**. A certificate for the
CA's key signed by its own previous key (subject equal to issuer) carries no AIA of its own,
so a client given it could not build a path any further up. For a root, which has no issuer
above, it serves the root's current certificate.

### GET `/<ca_id>/<ski>.p7c` — CA Certificate Bundle

Every live generation of a CA as a PKCS#7 certs-only bundle, addressed by Subject Key
Identifier. After a CA is renewed (admin guide §3.8) it has several live certificates until
the older ones expire, and all of them belong in a served chain.

| Aspect | Detail |
|--------|--------|
| Path | `/<ca_id>/<ski>.p7c`, the SKI lower-case hex |
| Auth | None |
| Response 200 | `application/pkcs7-mime`, certs-only |
| Response 404 | "unknown CA instance" |

### POST `/ocsp` — OCSP Request (POST)

| Aspect | Detail |
|--------|--------|
| Content-Type | `application/ocsp-request` (415 if wrong) |
| Auth | None (CMS-level authentication) |
| Request | DER-encoded OCSP request |
| Response 200 | `Content-Type: application/ocsp-response`, DER OCSP response |
| Cache | `Cache-Control: no-cache`, `Pragma: no-cache` |
| Status | `good`; `revoked` with the revocation reason — `certificateHold` for a certificate on hold, and no reason at all for `unspecified`; `good` again once a hold is released. A CMP certificate still waiting for its certConf answers `revoked` / `certificateHold` |

### POST `/` — OCSP Request at the root

Same as POST `/ocsp` above.

### POST `/ocsp/{ca_id}` — Per-CA OCSP POST

OCSP request signed by a specific CA instance.

### GET `/ocsp/<b64>` — OCSP Request (GET)

RFC 6960 Appendix A.1 GET form. Base64url-encoded DER OCSP request as final URL path segment.

### GET `/ocsp/{ca_id}/<b64>` — Per-CA OCSP GET

Per-CA variant of the GET form.

---

## 2. EST Responder — `fastpki-est` (RFC 7030)

**Default:** `https://0.0.0.0:8443` | **Transport:** HTTPS (required) | **Payload limit:** 256 KiB

### Authentication (all POST endpoints)

Precedence:
1. TLS client certificate (RFC 7030 §3.3.2), verified by `fastpki-est` itself against
   `EST_CLIENT_CA_ID` / `EST_CLIENT_CA_BUNDLE`. The identity is the subject CN. Off
   unless one of those is set. A proxy must pass TCP through at L4 — terminating TLS
   re-originates the connection and the client certificate never arrives.
2. HTTP Basic over TLS (RFC 7030 §3.2.3): `Authorization: Basic ...` validated against
   LDAP or the local auth backend

There is no anonymous fallback and no setting that creates one: an unauthenticated
request is rejected, never accepted under a blank identity.

### GET `/.well-known/est/{ca_id}/cacerts` — CA Certificate Retrieval

> ⚠️ **The id-less form 404s.** `/.well-known/est/cacerts`,
> `/.well-known/est/simpleenroll`, `/.well-known/est/simplereenroll`,
> `/.well-known/est/csrattrs` and, when server key generation is on,
> `/.well-known/est/serverkeygen` are all registered, and all answer
> `404 "this endpoint is per-CA: use /.well-known/est/{ca_id}/..."`. There is no default
> CA. Every EST path below takes the CA id.

| Aspect | Detail |
|--------|--------|
| RFC | 7030 §4.1 |
| Auth | None (public) |
| Response 200 | `Content-Type: application/pkcs7-mime; smime-type=certs-only`, base64 PKCS#7 (signing CA + root) |
| Response 404 | unknown CA |
| Response 503 | disabled CA |

### GET `/.well-known/est/{ca_id}/csrattrs` — CSR Attributes

The CA instance is resolved first, so an unknown CA is a 404 rather than a set of
attributes for nothing.

| Aspect | Detail |
|--------|--------|
| RFC | 7030 §4.5 |
| Auth | Optional (anonymous gets default profile; authenticated gets resolved profile's attrs) |
| Response 200 | `Content-Type: application/csrattrs`, base64 AttrOrOID DER |
| Response 204 | No Content (no attrs configured) |

### POST `/.well-known/est/{ca_id}/simpleenroll` — Initial Enrollment

Issued with the named CA's signing material.

| Aspect | Detail |
|--------|--------|
| RFC | 7030 §4.2.1 |
| Auth | Required (mTLS or Basic) |
| Content-Type | `application/pkcs10` (415 if wrong) |
| Request | Base64 DER PKCS#10 CSR (or PEM; whitespace-stripped) |
| Response 200 | `Content-Type: application/pkcs7-mime; smime-type=certs-only`, base64 PKCS#7 with issued cert |
| Response 401 | "unauthorized" + `WWW-Authenticate: Basic realm="EST"` |
| Response 429 | "per-CN issuance limit reached" |

### POST `/.well-known/est/{ca_id}/simplereenroll` — Re-enrollment

| Aspect | Detail |
|--------|--------|
| RFC | 7030 §4.2.2 |
| Auth | Required |
| Request | Base64 DER PKCS#10 |
| Additional | Requires a currently-valid certificate for the CSR's CN (403 if none found) |

### POST `/.well-known/est/{ca_id}/serverkeygen` — Server Key Generation (opt-in)

| Aspect | Detail |
|--------|--------|
| RFC | 7030 §4.4 |
| Condition | Only when `EST_SERVERKEYGEN=true` |
| Auth | Required |
| Request | Base64 DER PKCS#10 |
| Response 200 | `Content-Type: multipart/mixed; boundary="estServerKeyGenBoundary"` — Part 1: private key (`application/pkcs8` or CMS-enveloped), Part 2: issued cert (PKCS#7 certs-only) |

---

## 3. ACME Server — `fastpki-acme` (RFC 8555)

**Default:** `https://0.0.0.0:8444/acme` | **Transport:** HTTPS (required) | **Payload limit:** 256 KiB

### Authentication

All POST endpoints use JWS-signed requests (`application/jose+json`):
- **`jwk`-form**: Protected header carries the public JWK inline (for `new-account`)
- **`kid`-form**: Protected header carries `kid` (account URL); signature verified against stored account JWK

Replay nonces are mandatory and consumed per-request.

### GET `/acme/{ca_id}/directory` — Service Directory

> ⚠️ **The id-less form 404s**, for the same reason as EST: there is no default CA. An ACME
> client is pointed at one CA's directory, and everything it advertises stays in that
> scope, so every path below carries the same `{ca_id}`.

| Aspect | Detail |
|--------|--------|
| RFC | 8555 §7.1.1 |
| Response 200 | JSON: `{newNonce, newAccount, newOrder, revokeCert, keyChange, meta: {termsOfService, externalAccountRequired}}` |

### GET `/acme/{ca_id}/new-nonce` — Replay Nonce

| Aspect | Detail |
|--------|--------|
| RFC | 8555 §7.2 |
| Response 204 | `Replay-Nonce: <base64url>`, `Cache-Control: no-store`, empty body |

### POST `/acme/{ca_id}/new-account` — Account Registration

| Aspect | Detail |
|--------|--------|
| RFC | 8555 §7.3 |
| Auth | JWK-form JWS |
| Request | `{termsOfServiceAgreed?, contact?, onlyReturnExisting?, externalAccountBinding?}` |
| Response 200/201 | `{status, contact, orders}`, Location header |

### POST `/acme/{ca_id}/new-order` — New Order

| Aspect | Detail |
|--------|--------|
| RFC | 8555 §7.4 |
| Request | `{identifiers: [{type: "dns", value: "..."}]}` |
| Response 201 | `{status, expires, identifiers, authorizations, finalize}`, Location: `/acme/order/<id>` |
| Response 400 | `malformed` for any identifier type other than `dns`; `rejectedIdentifier` when a value is not a syntactically valid DNS name (1–253 bytes, labels 1–63 of letters, digits, `-` and `_`, no empty label, no leading or trailing hyphen, no trailing dot; a leading `*.` is accepted here and the wildcard itself is decided by the profile). Refused at order time rather than at finalize, where the client would already have solved every challenge. |

### POST `/acme/{ca_id}/new-authz` — Pre-Authorization (opt-in)

| Aspect | Detail |
|--------|--------|
| RFC | 8555 §7.4.1 |
| Condition | Only when `ACME_NEW_AUTHZ=true` |
| Request | `{identifier: {type: "dns", value: "..."}}` |
| Response 201 | Authorization object with challenges, Location: `/acme/authz/<id>` |

### POST `/acme/{ca_id}/account/<id>` — Account Management

| Aspect | Detail |
|--------|--------|
| RFC | 8555 §7.3.6 |
| Request | `{"status": "deactivated"}` |

### POST `/acme/{ca_id}/account/<id>/orders` — List Orders

| Aspect | Detail |
|--------|--------|
| RFC | 8555 §7.1.2.1 (POST-as-GET) |
| Response | `{orders: ["/acme/order/<id>", ...]}` |

### POST `/acme/{ca_id}/order/<id>` — Get Order

| Aspect | Detail |
|--------|--------|
| RFC | 8555 §7.1.3 (POST-as-GET) |
| Response | `{status, expires, identifiers, authorizations, finalize, certificate}`. `Retry-After: 2` when "processing"; a pending authorization and a triggered challenge carry the same hint. The listener keeps an idle connection open for 5 seconds, so a client that waits the hint and reuses its connection finds it still open. |

### POST `/acme/{ca_id}/order/<id>/finalize` — Finalize Order

| Aspect | Detail |
|--------|--------|
| RFC | 8555 §7.5.2 |
| Request | `{csr: "<base64url-DER-PKCS#10>"}` |
| Response 200 | Order with `status: "valid"`, `certificate` URL |
| Response 400 | `badCSR`. The CSR's SubjectAltName must match the order's identifiers **exactly, across every GeneralName type** — an order authorizes DNS identifiers only, so an `rfc822Name`, `iPAddress`, `uniformResourceIdentifier` or `otherName` in the CSR names something no challenge proved and is refused rather than stripped. The Subject CN, if present, must also be one of the ordered identifiers. |
| Response 403 | `orderNotReady`, `unauthorized`, `caa` (CAA policy blocks) |

### POST `/acme/{ca_id}/authz/<id>` — Get/Deactivate Authorization

| Aspect | Detail |
|--------|--------|
| RFC | 8555 §7.5.1 (POST-as-GET or deactivation) |
| Response | `{status, identifier, expires, wildcard?, challenges: [{type, url, status, token}]}` |

### POST `/acme/{ca_id}/chall/<id>` — Trigger Challenge Validation

| Aspect | Detail |
|--------|--------|
| RFC | 8555 §8.2 |
| Request | Empty body (triggers async validation) |
| Background | HTTP-01, DNS-01, TLS-ALPN-01 verification + CAA re-check (RFC 8659) |

### POST `/acme/{ca_id}/cert/<serial>` — Download Certificate

| Aspect | Detail |
|--------|--------|
| RFC | 8555 §7.4.2 (POST-as-GET) |
| Response 200 | `Content-Type: application/pem-certificate-chain` — PEM chain (leaf + signing CA + root) |

### POST `/acme/{ca_id}/key-change` — Account Key Rollover

| Aspect | Detail |
|--------|--------|
| RFC | 8555 §7.3.5 |
| Request | Outer JWS (kid-form, old key) wrapping inner JWS (jwk-form, new key) |

### POST `/acme/{ca_id}/revoke-cert` — Revoke Certificate

| Aspect | Detail |
|--------|--------|
| RFC | 8555 §7.6 |
| Auth | kid-form (account that owns cert) OR jwk-form (signed by cert's own key) |
| Request | `{certificate: "<base64url-DER>", reason: <int>}` |
| Reasons | 0–6 and 9. 6 (`certificateHold`) puts the certificate on hold, which an administrator can release in the console. 7, 8 (`removeFromCRL`), 10 (`aACompromise`) and anything outside 0–10 answer `badRevocationReason` |
| Already revoked | `alreadyRevoked`, unless the certificate is on hold and the request gives another reason, which revokes it for good |

### Per-CA Virtualization

Every path above carries the CA instance id as its first segment (for example
`/acme/dept-a/directory`), and every URL the server advertises stays within that CA's
scope.

---

## 4. CMP Server — `fastpki-cmp` (RFC 4210/9810)

**Default:** `http://0.0.0.0:8445/cmp` | **Transport:** Plain HTTP | **Payload limit:** 1 MiB

### Authentication

Two modes, and there is no third — an unprotected request is always refused:
1. **Signature-based**: Client cert signed by a trusted CA (`CMP_CLIENT_CA_ID` and/or `CMP_CLIENT_CA_BUNDLE`)
2. **PBM**: per-user secret from the `keys` table, keyed by senderKID — there is no server-wide secret

All CMP operations are serialized through a single mutex.

### POST `/cmp/{ca_id}` — CMP Operations

All CMP operations are dispatched through one per-CA POST endpoint, selected by the PKIMessage
body type.

> ⚠️ **The id-less `/cmp` and `/.well-known/cmp` answer 404** ("this endpoint is per-CA: use
> /cmp/{ca_id}"). They are registered so the refusal names the real problem rather than
> answering "no route". There is no default CA.

| Operation | RFC | Description |
|-----------|-----|-------------|
| `ir` / `cr` | 4210 | Initial/Certification Request — issues certificate |
| `p10cr` | 4210 | PKCS#10 CSR — issues certificate |
| `kur` | 4210 | Key Update Request — re-key existing cert |
| `rr` | 4210 | Revocation Request — revokes cert by serial (signature-protected only). Reasons 0–6 and 9; 6 (`certificateHold`) puts it on hold, which an administrator can release in the console. Any other reason is rejected with `badRequest`; a certificate already revoked is rejected with `certRevoked`, unless it is on hold and the request gives another reason |
| `certConf` | 4210 | Certificate Confirmation — confirms or rejects a pending cert |
| `genm` | 4210 | General Message — responds with `id-it-caCerts`, `id-it-rootCaCert`, optionally `id-it-crlStatusList` (OpenSSL >= 3.5) |
| `pollReq` | 4210 | Poll Request — deferred issuance polling |

| Aspect | Detail |
|--------|--------|
| Content-Type | `application/pkixcmp` (415 if wrong) |
| Request | DER-encoded `OSSL_CMP_MSG` (PKIMessage) |
| Response 200 | `Content-Type: application/pkixcmp`, DER `OSSL_CMP_MSG` response |

### POST `/.well-known/cmp/{ca_id}` — Standardized CMP Endpoint

The same per-CA endpoint under the standardized path (RFC 6712 §3.6, RFC 9483 §6).
Registered only when `CMP_PATH` is not already `/.well-known/cmp`.

**Special behaviors:**
- **On-hold vs valid**: Without implicit confirmation, cert is on-hold (status=2) until `certConf`
- **Per-user PBM**: senderKID or sender DN keys lookup in `keys` table
- **RA mode**: responses are protected by a per-CA RA credential — one `CMP_RA_KEY`, and a certificate per CA at `certs.cert_id = <CMP_RA_CERT_ID_PREFIX>-<ca_id>` issued BY that CA, so a client anchored on that CA validates the protection and one anchored elsewhere does not. A CA with no such certificate cannot serve CMP (503)
- **certProfile** (RFC 9483, OpenSSL >= 3.5): Client can request a named profile via `generalInfo`

---

## 5. SCEP Server — `fastpki-scep` (RFC 8894)

**Default:** `http://0.0.0.0:8448/scep` | **Transport:** Plain HTTP | **Payload limit:** 256 KiB

### Authentication
- **Challenge password**: per-user (`<user>:<secret>`, created with the user's role) or dynamic one-time tokens (`SCEP_DYNAMIC_CHALLENGE`)
- **Renewal** (RFC 8894 §3.3.2): Proof-of-possession of valid cert bypasses challengePassword
- **Manual approval** (`SCEP_MANUAL_APPROVAL`): CSR parked as PENDING

All operations are dispatched via the `operation` query parameter on the per-CA path
`<SCEP_PATH>/{ca_id}` — for example `/scep/dept-a?operation=GetCACert`. The bare
`SCEP_PATH` answers 404: there is no default CA.

### GET `?operation=GetCACert` — Get CA Certificate

| Aspect | Detail |
|--------|--------|
| RFC | 8894 §4.2 |
| Non-RA | `Content-Type: application/x-x509-ca-cert`, DER X.509 CA cert |
| RA mode | `Content-Type: application/x-x509-ca-ra-cert`, PKCS#7 certs-only (RA cert + CA cert) |

### GET `?operation=GetCACaps` — Get CA Capabilities

| Aspect | Detail |
|--------|--------|
| RFC | 8894 §3.5.2 |
| Response | `Content-Type: text/plain`. Always: `POSTPKIOperation`, `SHA-256`, `AES`, `SCEPStandard`. Conditional: `SHA-1` (if `SCEP_ALLOW_SHA1`), `DES3` (if `SCEP_ALLOW_DES3`), `Renewal` (if `SCEP_RENEWAL`), `GetNextCACert` (if next CA configured) |

### GET `?operation=GetNextCACert` — Next CA Certificate (Key Rollover)

| Aspect | Detail |
|--------|--------|
| RFC | 8894 §3.5.3, §4.7 |
| Response | `Content-Type: application/x-x509-next-ca-cert`. CMS SignedData carrying rollover CA cert. |
| Response 404 | "no next CA certificate configured" |

### POST `?operation=PKIOperation` — PKI Operation

| Aspect | Detail |
|--------|--------|
| RFC | 8894 §4.3 |
| Request | DER CMS SignedData (pkiMessage). Outer: self-signed client cert. Inner: EnvelopedData (encrypted to CA/RA key). |
| Response 200 | `Content-Type: application/x-pki-message`. DER CMS SignedData (CertRep) with authenticated attributes: messageType, pkiStatus, transactionID, recipientNonce, senderNonce |

**SCEP message types dispatched:**

| Type | RFC | Description |
|------|-----|-------------|
| PKCSReq | §3.3.1 | Decrypt EnvelopedData → PKCS#10 CSR. Validate challengePassword. Issue cert or park as PENDING. |
| GetCertInitial | §3.3.2 | Poll manual-approval by transactionID. Returns PENDING/FAILURE/SUCCESS. |
| GetCert | §3.3.3 | Fetch previously issued cert by IssuerAndSerialNumber. |
| GetCRL | §3.3.4 | Returns CA CRL in degenerate PKCS#7. |

### GET `?operation=PKIOperation&message=<b64>` — Legacy GET Form

Same as POST PKIOperation but with base64-encoded CMS as query parameter.

### Per-CA Virtualization

Every operation above runs against one CA instance, named in the path:
`/scep/{ca_id}?operation=...`. Unknown CA ids answer 404 and disabled ones 503.

---

## 6. MS-XCEP + MS-WSTEP — `fastpki-ms`

**Default:** `https://0.0.0.0:8446` | **Transport:** HTTPS (required) | **Payload limit:** 1 MiB

### POST `/msxcep/{ca_id}` — MS-XCEP (Certificate Enrollment Policy)

> ⚠️ **The base paths 404.** `/msxcep` and `/mswstep` without a `/{ca_id}` return 404, the
> same as EST, ACME, SCEP and CMP. Point the Windows XCEP URL (GPO or registry) at
> `/msxcep/{ca_id}`; `GetPolicies` then hands the client that CA's own id-bearing WSTEP
> URI, so no base path is ever needed.

| Aspect | Detail |
|--------|--------|
| Protocol | SOAP 1.2 |
| Auth | Kerberos/SPNEGO → HTTP Basic → WS-Security UsernameToken — the same ladder as WSTEP, in `ms_authenticate()`. A refusal is 401 with a `WWW-Authenticate` challenge, never a soap:Fault. No `ms:enrol` check: it returns the template catalogue, not a certificate. |
| Content-Type | `application/soap+xml` |
| Response | SOAP 1.2 `GetPoliciesResponse` (XML: `http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy`) containing policyID, certificate templates (commonName, OIDs, permissions, key attributes, extensions), CA URI + cert, policy OIDs |

**Template source:** `ms_templates` DB table when populated; otherwise built-in defaults (`GenericUser`, `Email`, `GenericComputer`).

**`<cAs>` source:** per-CA, from the DB — nothing in the block is a
server-wide constant. `ca_xcep_uris` holds one row per advertised `<cAURI>`
(`uri`, `client_auth`, `priority`, `renewal_only`; `xcep.xsd` allows 1..n), and
`certs.ms_enroll_permission` supplies `<enrollPermission>`. A blank `uri` —
and a CA with no rows at all — advertises this server's own `/mswstep/{ca_id}`,
built from `BASE_URL` when that is set explicitly, and otherwise from the `Host`
header the client used, falling back to `PKI_DNS:MS_PORT`. Edit via the console
CA detail panel or
`GET`/`POST /api/ca-instances/{id}/xcep` on `fastpki-web`.

### POST `/mswstep/{ca_id}` — MS-WSTEP (WS-Trust X.509 Token Enrollment)

| Aspect | Detail |
|--------|--------|
| Protocol | SOAP 1.2 / WS-Trust |
| Content-Type | `application/soap+xml` |

**Authentication (tried in order):**
1. Kerberos/SPNEGO: `Authorization: Negotiate <base64>` (requires a keytab uploaded for at least one directory)
2. HTTP Basic: `Authorization: Basic <base64>` (LDAP/local backend)
3. WS-Security UsernameToken: `<wsse:Username>` + `<wsse:Password>` in SOAP body

**Request:** SOAP 1.2 envelope with `<wsse:BinarySecurityToken>` containing base64 DER PKCS#10 CSR.

**Response 200:** SOAP 1.2 `RequestSecurityTokenResponseCollection` containing:
- `TokenType` = X509v3
- `DispositionMessage` = "Issued"
- `BinarySecurityToken` = PKCS#7 cert chain (CMC full PKI response signed by CA)
- `RequestedSecurityToken` = single issued cert

**Response 400:** "missing BinarySecurityToken"

**Response 401:** `WWW-Authenticate: Negotiate` and/or `WWW-Authenticate: Basic realm="FastPKI MS-WSTEP"`

**Response 500:** SOAP 1.2 Fault with `wsse:FailedAuthentication` subcode. A failed
WS-Security `UsernameToken` is answered this way, not with HTTP 401.

---

## 7. Certificate Store — `fastpki-store` (RFC 4387)

**Default:** `http://0.0.0.0:8447` | **Transport:** Plain HTTP | **Payload limit:** 64 KiB

### GET `/certificates/search` — Certificate Search

| Aspect | Detail |
|--------|--------|
| RFC | 4387 §2 |
| Auth | None |
| Query params | Exactly **one** attribute required: |

**Supported query attributes:**

| Attribute | DB Column | Description |
|-----------|-----------|-------------|
| `certHash` | `fingerprint` | SHA-256 fingerprint |
| `name` | `subject` | Certificate subject/DN |
| `cn` | `cn` | Common Name |
| `serial` | `serial` | Serial number (hex) |
| `sHash` | `sHash` | SHA-1 of subject Name DER |
| `iHash` | `iHash` | SHA-1 of issuer Name DER |
| `iAndSHash` | `iAndSHash` | SHA-1 of (issuer, serial) |
| `sKIDHash` | `sKIDHash` | SHA-1 of SubjectKeyIdentifier value |
| `uri` | `uri` | SubjectAltName URI (via `cert_uris` table) |

**Response:**
- 1 match: `Content-Type: application/pkix-cert`, single DER cert
- N matches: `Content-Type: application/pkcs7-mime`, DER PKCS#7 certs-only bundle
- No match: 404

### GET `/crls/search` — CRL Retrieval

| Aspect | Detail |
|--------|--------|
| RFC | 4387 §3 |
| Auth | None |
| Query params | Optional, at most one: `iHash`, `sKIDHash`, or none (returns current CRL) |

**Response 200:** `Content-Type: application/pkix-crl`, DER-encoded CRL (TTL-cached)

---

## Summary

| Binary | Default Port | Transport | Endpoints | Auth |
|--------|-------------|-----------|-----------|------|
| `fastpki-ocsp` | 8080 | HTTP | 7 routes (CRL + OCSP, global + per-CA) | CMS-level |
| `fastpki-est` | 8443 | HTTPS | 8 routes (cacerts, csrattrs, enroll, reenroll, keygen + per-CA) | mTLS / HTTP Basic |
| `fastpki-acme` | 8444 | HTTPS | 14 + 14 per-CA = 28 routes | JWS (jwk/kid) |
| `fastpki-cmp` | 8445 | HTTP | 4 routes (2 global + 2 per-CA) | Signature / PBM |
| `fastpki-scep` | 8448 | HTTP | 5 + 5 per-CA = 10 routes (operation dispatch) | Challenge password |
| `fastpki-ms` | 8446 | HTTPS | 2 routes (XCEP + WSTEP) | Kerberos / Basic / WS-Security |
| `fastpki-store` | 8447 | HTTP | 2 routes (cert search + CRL) | None |
