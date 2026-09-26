# FastPKI CLI Reference

Every binary is in `/usr/local/bin`, both in the image and on a native install (a source build leaves them in `./build/`). Under Compose a CLI runs inside the image: `docker compose run --rm --no-deps --entrypoint <tool> web --config /app/config/bootstrap.conf …`. All tools read `config/bootstrap.conf` by default (override with `--config <path>`). All servers handle `SIGINT`/`SIGTERM` for graceful shutdown.

## Contents

1. [Management & Administration Tools](#1-management--administration-tools)
   - [fastpki-config](#fastpki-config)
   - [The token transport's trust (`p11-*`)](#the-token-transports-trust-p11-)
   - [Directories (`auth-providers-*`)](#directories-auth-providers-)
   - [MS certificate templates (`templates-*`)](#ms-certificate-templates-templates-)
   - [fastpki-ca](#fastpki-ca)
   - [fastpki-audit](#fastpki-audit)
   - [fastpki-notify](#fastpki-notify)
   - [fastpki-discover](#fastpki-discover)
   - [fastpki-mesh](#fastpki-mesh)
   - [fastpki-update](#fastpki-update)
2. [Server Daemons](#2-server-daemons)
   - [fastpki-web](#fastpki-web)
   - [fastpki-ocsp](#fastpki-ocsp)
   - [fastpki-est](#fastpki-est)
   - [fastpki-acme](#fastpki-acme)
   - [fastpki-cmp](#fastpki-cmp)
   - [fastpki-scep](#fastpki-scep)
   - [fastpki-ms](#fastpki-ms)
   - [fastpki-store](#fastpki-store)
   - [fastpki-mcp](#fastpki-mcp)
3. [Common Exit Codes](#3-common-exit-codes)

---

## 1. Management & Administration Tools

### fastpki-config

Manage the DB config overlay (runtime overrides for `bootstrap.conf` keys).

```
fastpki-config <command> [args...]
```

| Command | Description |
|---------|-------------|
| `list` | Print every row of the DB config overlay, secrets masked. It shows the `config` table only, not values that come from `bootstrap.conf`, the environment or a compiled-in default |
| `get <KEY>` | Print one key's value from the DB overlay; exits 1 with `not set` when the table has no row for it |
| `set <KEY> <VALUE>` | Write a key into the DB overlay. Any key but `PG_CONNINFO` is accepted, including one the parser does not read, so check the spelling against [config-reference.md](config-reference.md) |
| `unset <KEY>` | Remove a key from the DB overlay, so the file, environment or default value applies again |
| `import <file>` | Store every non-bootstrap `KEY=VALUE` line of a `bootstrap.conf`-style file into the DB overlay |
| `export` | Print the DB overlay as `KEY=VALUE` lines, unmasked, in a form `import` reads back |
| `auth-providers-list` | List the directories this deployment authenticates against |
| `auth-providers-add <id> --uris U --base-dns B [...]` | Create or replace one directory |
| `auth-providers-remove <id>` | Remove one directory and its stored settings |
| `templates-import <csv>` | Import MS certificate templates from a CSV |
| `templates-list` | List the MS templates in the database, marking the disabled ones |
| `templates-delete <name>` | Remove one MS template |
| `profiles-export` | Print the stored certificate profiles (every custom one and every edited built-in) as one JSON object |
| `profiles-import <file>` | Store every profile in a JSON object of that shape, replacing same-named ones. Nothing is stored if one of them does not parse |
| `profiles-delete <name>` | Remove a stored profile; for a built-in, return it to its shipped definition. Role grants naming a deleted profile stay until removed |
| `domains-list` / `domains-add` / `domains-remove` / `domains-import` | The approved-domain allow-list |
| `backup [--out <file>] [--passphrase-file <f>]` | Write a config backup: JSON, or encrypted in the console's `.fpkibak` format with the passphrase on the first line of `<f>`. The file is created mode 0600 |
| `restore <file> [--passphrase-file <f>]` | Restore a config backup, plain or encrypted |
| `decrypt-backup <file> --passphrase-file <f> --out <plain>` | Decrypt a `.fpkibak` downloaded from the console — a config backup or a database dump. Needs no database, so it works while the database is being rebuilt |
| `web-user <name> <pw> [--role R] [--must-reset] [--if-absent] [--email ADDRESS]` | Create or update a local console login (a `web_users` row with a PBKDF2 password). `--role` defaults to `admin`; `--must-reset` makes the account change its password at first sign-in; `--if-absent` leaves an existing account untouched instead of resetting its password; `--email` sets where expiry emails for the account's certificates go (an empty value clears it) |
| `p11-client-publish [<pem>]` | Publish this node's PKCS#11 transport **client** certificate into its `datacenters` row |
| `p11-server-publish [<pem>]` | Publish this node's transport **server** certificate, so nodes dialling its token can verify it |
| `p11-clients-sync [<dir>]` | Materialise every published client certificate into the trust directory. Run where the token is SERVED |
| `p11-servers-sync [<dir>]` | Materialise every published server certificate. Run where a peer's token will be DIALLED to replicate a key out of it |

`list` masks a value as `(set)` when the key name contains "password", "secret", "token",
"conninfo", "pbm" or "challenge". Every other value prints verbatim, a `*_KEY` `pkcs11:` URI included, so
keep the token PIN out of the URI itself — `?pin-source=/var/pki/tls/pin`, never
`?pin-value=<PIN>` — before pasting the output anywhere.

**Config keys:** `PG_CONNINFO` (bootstrap — must stay in `bootstrap.conf`)

### The token transport's trust (`p11-*`)

With `P11_TLS=on` a node publishes its own PKCS#11 token over mutually authenticated TLS, so
that a peer can **replicate a CA private key out of it** into that peer's own token
(`fastpki-ca key replicate`). Every node keeps its own token and signs from it; no node ever
signs through another's. Both ends verify the other, and neither can issue the certificate
the other must trust — so each publishes its own into its `datacenters` row, and each
materialises a trust directory from what the mesh has replicated. Only certificates travel;
publishing a file containing a private key is refused.

On the node **publishing** its token:

```
fastpki-config p11-server-publish   # advertise what this host presents
fastpki-config p11-clients-sync     # trust the nodes allowed to dial in
```

On a node that will **dial** one to replicate a key:

```
fastpki-config p11-client-publish   # advertise this host's identity
fastpki-config p11-servers-sync     # trust the token hosts it may dial
```

Every deployment path runs these at service start, so a node is brought up to date on its own; the
commands are here for diagnosis and for adding a node out of band. Clearing a node's
column and re-running the matching sync is how a node is locked out.

### Directories (`auth-providers-*`)

A directory is a row, not a set of config keys. Each row carries its own URIs, base DNs and
search bind, so one deployment can authenticate against several AD domains at once.

```bash
fastpki-config auth-providers-add corp \
    --uris ldaps://dc1.corp.example,ldaps://dc2.corp.example \
    --base-dns 'DC=corp,DC=example' \
    --display-name 'Corp AD' --netbios CORP --dns-root corp.example
```

`--uris` is comma-separated. **`--base-dns` is semicolon-separated**, because a base DN
contains commas itself — `'OU=people,DC=corp,DC=example;OU=svc,DC=corp,DC=example'` is two
base DNs, not four. Both are required. Also accepted:
`--bind-dn`, `--bind-pw-file`, `--group-filter`, `--group-attr`, `--ca-cert`, `--timeout`,
`--template-base`, `--priority`, `--disabled`.

**`--netbios` and `--dns-root` are the domain's other two names.** A login may name this
directory by its id, its display name, its NetBIOS short name, its DNS root, or its Kerberos
realm — the DNS root upper-cased, which is how Windows forms it. The match ignores case. So
`corp\alice`, `CORP\alice`, `alice@corp.example` and `alice@CORP.EXAMPLE` all reach the same
directory. A `domain\user` login whose domain matches no directory is refused; a
`user@domain` login whose domain matches none is treated as a local account name, `@`
included.

⚠️ **A login that names NO directory is a local account** and is never tried against a
directory, however many are configured. `alice` means the `web_users` table; a directory
identity is `corp\alice`. The console's sign-in page offers a domain picker so nobody has to
know the spelling, and its first option is "local account".

The same rows are managed on the console's **Directories** page.

### MS certificate templates (`templates-*`)

⚠️ **The table is all-or-nothing, and it is global.** `fastpki-ms` serves the enabled templates
in `ms_templates` when there are any, and the built-in defaults only when **no row is enabled**:

```
MS-XCEP serving 3 certificate template(s) (built-in defaults)
MS-XCEP serving 7 certificate template(s) (from DB)
```

`ms_templates` is keyed on the template name alone — there is no per-CA scoping — so a
single enabled row anywhere switches **every** CA to DB-only, and the three built-ins
(`GenericUser`, `Email`, `GenericComputer`) stop being offered to anyone. `templates-list`
tells you which mode you are in: it prints every row, with `disabled` after the ones that are
off, and a list with no enabled row means built-ins.

To go back, delete (or disable) the imported rows:

```bash
fastpki-config templates-list                     # what is in the table
fastpki-config templates-delete GenericComputer   # per name
```

**The catalogue is read at startup.** `fastpki-ms` loads it once, so a change takes effect
when that service restarts. The console's restart control signals it (the service exits and
the restart policy brings it back re-reading the table); there is nothing to run by hand.

A Windows client caches the policy separately and keeps offering the template set it already
fetched. Clear the cache on the client, in the context whose certificates you are enrolling:

```powershell
certutil -f       -policyserver * -policycache delete   # machine certificates
certutil -f -user -policyserver * -policycache delete   # user certificates
```

---

### fastpki-ca

Multi-CA control plane CLI (single-tenant).

```
fastpki-ca <command> [args...]
```

| Command | Description |
|---------|-------------|
| `list` | List all configured CAs |
| `show <id> [--pem] [--out <f>]` | Show details for a specific CA; `--pem` prints its **certificate**, which is what another node needs to register it as a trust anchor |
| `urls <id>` | Show the AIA and CRL URLs a certificate issued by this CA now would carry. It also compares them with the ones the CA's **own** certificate carries, which is what a client checking a chain sees: those were fixed when the CA was created and cannot be changed, so after `PKI_DNS` or `BASE_URL` is corrected they name the old host. On a difference it prints what the certificate carries, says to run `renew <id>`, and **exits 3** — so a sweep over `list` finds every CA that needs re-issuing. A root carries no URLs of its own and is never reported. |
| `key list <id>` | List the CA's signing-key URLs, in the order they are tried. After each: `[in this node's token, replicable]`, `[in this node's token, NOT replicable: …]`, `[not in this node's token]`, or `[token not readable]` (the reason goes to stderr) |
| `key add <id> <pkcs11-uri>` | Append a signing-key URL. A CA names one key per generation — a renewal with a new key adds a certificate and its key, and both stay live through the rollover — so the certificate being signed under selects its own key from the list. A file path is refused |
| `key remove <id> <pkcs11-uri>` | Drop one signing-key URL |
| `key replicate <id>` | Copy this CA's private key from a peer's token into **this** node's, so losing that node does not take the CA with it. Run on the destination. `--from <host:port>` raises the mTLS tunnel for the operation; `--source-socket <unix:path=…>` uses one already up. `--source-key <pkcs11-uri>` names the object in the source token (default `object=<id>`). `--source-pin-file <path>` holds the SOURCE node's token PIN: the wrap happens inside that token, and two separately installed nodes each generated their own PIN, so this is needed unless both were given the same one. The key is wrapped inside the source token and unwrapped inside this one, so it never exists in plaintext outside either; the result is checked against the CA's certificate before it is registered. Requires a CA created with `--replicable` |
| `key sync` | Replicate **every key this node needs in order to serve** and does not have: each CA whose key is missing from its token, and the OCSP/CMP/SCEP RA credentials, naming none of them. A standby receives every row through database replication and no key at all, so this is what makes promoting it give you an issuer *and* the three protocols that need an RA credential, rather than only a database. Listener TLS keys are not included — each host answers under its own name and has its own. Takes the same `--from` / `--source-socket`, `--source-pin-file` and `--kek-label` as `key replicate`, or `--from-peers`, which takes each missing key from whichever other host of this node's data center holds it — a primary can be missing a key its standby created, so a pair copies both ways, and hosts of other data centers are never asked. `--source-key` does not apply, because each object's source name defaults to its own id. Every host's nightly job runs `key sync --from-peers` whenever `P11_TLS=on` — the `certrenew` service under compose, `/etc/periodic/daily/fastpki-certrenew` on a native install, the `renew` container of each server pod on Kubernetes — so it is normally an operator command only to bring one up to date immediately. A key generated without `--replicable` can never be wrapped, and the failure says which remedy each kind needs. A key counts as present only when it matches its certificate: a token object under the right name holding a different key is reported as not matching, and replaced by the copy once that copy has been wrapped on the source. Exit status: `0` nothing is missing any more; `1` something was not copied and a retry may succeed (a peer restarting); `2` every failure was a key generated without `--replicable`; `3` `--from-peers` found no other host of this data center to copy from. The nightly job runs `key sync` **before** `renew-service-certs --create-missing`, and leaves `--create-missing` off after an exit `1`: that sweep creates a replacement for a credential whose key is not in this token, which on a pair would take the credential away from the other host while it may only be restarting |
| `add <id>` | Register an **existing** CA (see flags below). When `<id>` is already registered, the certificate is added as that CA's **renewal** — accepted only if it has the CA's subject and is signed by the CA's parent, or is self-signed for a root; the name and state are kept unless `--name` or `--disabled` is given |
| `create <id>` | Build + self-sign a new CA with a **token** key and register it |
| `csr <id>` | Build a CSR for a CA whose key is in **this** node's token, to be signed by a root held elsewhere — the multi-data-center bootstrap (deployment.md §9, manual-procedures.md §3) |
| `sign-csr <parent-id>` | Sign such a CSR with a CA this node **can** sign with, producing that node's sub CA certificate. The certificate is recorded here (no CA id) so it can be listed and revoked; `add` registers the CA on that record |
| `pg-tls <ca-id>` | Issue the **database's own** TLS certificate from `<ca-id>`, replacing the self-signed pair `certgen` made at deploy time. Names come from `PKI_DNS` and `PG_TLS_SANS` |
| `renew <id>` | Give the CA a **new certificate**: new validity, and — for an issuing CA — the CRL distribution point and AIA addresses derived from its parent again, so a data center added since the old certificate is included. This is the only way to correct those addresses, because they are fixed when a certificate is issued. Without `--new-key` the CA keeps its current key and nothing already issued is affected; the old certificate stays live until its own end date. `--new-key pkcs11:<uri>` **re-keys**: it generates a key at that handle (which must be free), and for a root also issues two cross-certificates — the new key signed by the old root and the old key signed by the new one — so relying parties on either anchor keep working. A re-key then re-signs every OCSP responder, CMP RA and SCEP RA certificate this CA has issued, because those were signed by the old key. `--key`, `--bits`, `--curve` and `--replicable` shape that new key and are refused, not ignored, without `--new-key`. `--days` (3650) and `--md` (sha256) set the validity and signature hash. An issuing CA's renewal is signed by its **parent**, which must be enabled and hold its key on this node — otherwise the command says which of the two is missing, and a parent held elsewhere is renewed through `csr` + `sign-csr` instead. Same code as the console's **Renew**; restart this node's services afterwards so they load the new certificate |
| `import-crl <id> <file>` | Publish a CRL this deployment did **not** sign (an offline root's). Refused unless it verifies against that CA's key |
| `renew-service-certs` | Reissue the credentials FastPKI holds for itself (OCSP responder, CMP RA, SCEP RA) and this node's CA-issued listener certificates (web/EST/ACME/MS) once each is past `SERVICE_CERT_RENEW_FRACTION` of its lifetime, or now with `--force`; `--ca <id>` limits the run to one CA, `--dry-run` changes nothing. The running services serve a renewal without a restart. `--create-missing` also creates the ones a CA does not have yet, generating the key in the token; roots are skipped, because nothing enrols against a root. `--re-issue-self-signed` replaces this node's self-signed listener certificates (web/EST/ACME/MS) with CA-issued ones, keeping each key; they are signed by `--ca`, else by the CA the `HTTPS_CA_ID` setting names, else by this node's only issuing CA. With several issuing CAs and neither named, nothing is re-issued and the run fails naming the candidates, but only while a certificate is still self-signed. A root is used only when named. `--replicable` generates a NEW credential key extractable, so it can be copied into the other token of an HA pair and a promotion needs no re-issuance — it applies only where a key is GENERATED, because CKA_EXTRACTABLE is fixed at generation, and a run that reuses an existing key says so. Without the flag the setting `SERVICE_KEYS_REPLICABLE` decides, which is how a scheduled run — with no command line to put the flag on — generates keys an HA pair's standby can receive. Run from **one** invoker, never a per-service timer. A credential whose key in this token does not match its certificate is never renewed with that key. Without `--create-missing` the run fails naming it, and `key sync` copies the right key. With `--create-missing` a key that matches none of the credential's certificates is deleted and a new one generated in its place. A key that another CA's certificate for the credential certifies is certified for this CA as well |
| `cross-sign <signer-id>` | Vouch for a foreign CA; name constraints and an explicit `--pathlen` are required |
| `enable <id>` | Enable a CA |
| `disable <id>` | Disable a CA — stops new issuance, keeps CRL/OCSP/chain serving |
| `delete <id> [--keep-key]` | **Remove** a CA. Refused unless it has issued nothing; destroys the token keypair with it unless `--keep-key` |

**Several signing-key URLs.** A CA's key lives in one token, so losing the node that holds
it takes that CA's signing with it. `key add` gives the CA more than one URL; they are tried
in order and the first usable one signs.

A candidate that is unreachable is skipped and logged at info. A candidate that is reachable
but holds a key which does **not** match the CA's certificate is also skipped, and logged at
**error**. "The first URL that works" means the first that holds *this* key, not the first
that answers.

`certs.private_key` is not replicated between data centers — it names a key object on the
node that holds it — so this list is per-node, and a URL is only useful from a node that can
reach the token it names.

**Add flags:** `--name <name>`, `--ca-pem <file>`, `--ca-key pkcs11:<uri>`, `--disabled` — **no `--parent`**: a CA's parent is read from its certificate's issuer, so declaring it separately could contradict the bytes. Omit `--ca-key` to register a verify-only trust anchor.

**csr / sign-csr flags:** `csr`: `--ca-key pkcs11:<uri>` (required), `--subject` (default `/CN=<id>`), `--keygen`, `--key` (default `rsa`), `--bits` (default 4096), `--curve` (default `P-256`), `--md` (default `sha256`), `--pathlen <n>` (written into the request's basicConstraints; omitted, the request carries no path length — `fastpki-ca sign-csr` takes only the subject and public key from a request, so the path length is for a signer that reads it), `--replicable`, `--out` (default: standard output). `--replicable` applies with `--keygen` and generates the key so that `key replicate` can later copy it into another node's token; PKCS#11 fixes that attribute at generation, so it cannot be added afterwards. Without `--keygen` the key named by `--ca-key` must already exist. `sign-csr`: `--csr <file>` (required), `--days` (default 1825), `--md`, `--out`. A CA certificate signed by `create --parent` or `sign-csr` never ends after the signing CA: a later end date is shortened to the signer's

**pg-tls flags:** `--key rsa|ec`, `--bits`, `--curve`, `--dir <path>` (defaults to `PG_TLS_DIR`), `--if-needed`. The `<ca-id>` argument may be omitted, and is then taken from `PG_TLS_CA_ID`. `--if-needed` leaves the certificate alone when it is already issued by that CA, covers every name and is not near expiry, so a scheduled run is a no-op rather than a new certificate every day. The names are `postgres`, `localhost`, `127.0.0.1`, `PKI_DNS`, this node's own `PG_BIND` and anything in `PG_TLS_SANS`

**Create flags:** `--name`, `--ca-key pkcs11:<uri>` (required), `--parent`, `--subject`, `--days`, `--key` (`rsa`, `rsa-pss`, `ec`, `ed25519`, `ed448`, `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`), `--bits`, `--curve`, `--md`, `--keygen`, `--replicable`, `--out-dir`, `--disabled`. `--replicable` generates a key that `key replicate` can later copy into another node's token — it can only be chosen here, because PKCS#11 fixes `CKA_EXTRACTABLE` at generation and does not allow granting it afterwards

> `delete` is narrow. Deleting a CA that has issued certificates is refused, with the
> count and a pointer to `disable` — every certificate it signed still needs its issuer
> to build a chain and to have its revocation status answered. Deletion also destroys
> the CA's keypair inside the HSM, unless `--keep-key` is given.

**Config keys:** `PG_CONNINFO`

---

### fastpki-audit

Tamper-evident audit log management and verification.

```
fastpki-audit <command> [args...]
```

| Command | Description |
|---------|-------------|
| `verify [--ca <ca_id>]` | Verify the hash chain, then the latest signed checkpoint. `--ca` is required once a checkpoint exists — the checkpoint's signature is checked against that CA's certificate. |
| `sign --ca <ca_id>` | Sign a checkpoint over the current head, so a truncated log fails `verify`. Refuses a broken chain; the CA's key must be on this node. |
| `append <cat> <action> <actor> <status> [target] [detail]` | Append an entry |
| `export [after_seq]` | Export log entries as JSON lines (optionally after a sequence number) |
| `export-signed [--after <seq>] --ca <ca_id> --out <path>` | Write the rows as NDJSON to `<path>` plus a detached CA signature at `<path>.sig`. `--ca` is **required** — there is no default CA. Refuses a broken chain. |
| `verify-export --ca <ca_id> --out <path>` | Verify `<path>` against `<path>.sig`. `--ca` is **required** — the signature is checked against that CA's certificate, which is read from the database, so this needs a database connection. |
| `forward [--follow] [--after <seq>] [--syslog host:port] [--stdout]` | Ship rows to the collector named by `AUDIT_FORWARD` / `AUDIT_FORWARD_TARGET`. The position is stored per destination; `--after` overrides it for one run, `--syslog` overrides the destination, `--follow` keeps running. |

**Exit:** 0 = success (verification passed), 1 = error or verification failed, 2 = usage error (including `export-signed` or `verify-export` without `--out`)

**Example** (native paths; under Compose run each as
`docker compose run --rm --no-deps --entrypoint fastpki-audit web --config /app/config/bootstrap.conf …`).
Name an issuing CA whose key is on this node, never the root:

```bash
fastpki-audit --config /etc/fastpki/bootstrap.conf sign --ca issuing-ca
fastpki-audit --config /etc/fastpki/bootstrap.conf verify --ca issuing-ca
fastpki-audit --config /etc/fastpki/bootstrap.conf export-signed --after 100 --ca issuing-ca --out /backup/audit.ndjson
fastpki-audit --config /etc/fastpki/bootstrap.conf verify-export --ca issuing-ca --out /backup/audit.ndjson
```

**Config keys:** `PG_CONNINFO` (a signing CA is a `certs` row with `is_ca=true`, not a config key)

---

### fastpki-notify

Certificate expiry scanner, webhook dispatcher, and emailer of certificate owners.

```
fastpki-notify [options]
```

| Flag | Description |
|------|-------------|
| `--config <path>` | Bootstrap file naming the database |
| `--days <days>` | Warning windows for this run, comma-separated (default: `NOTIFY_DAYS`, whose default is "30,14,7") |
| `--webhook <url>` | Webhook for the whole report (default: `NOTIFY_WEBHOOK`, which is empty unless set) |
| `--webhook-format <format>` | What is posted to the webhook and every route: `json`, `slack` or `teams` (default: `NOTIFY_WEBHOOK_FORMAT`, whose default is `json`) |
| `--routes <file>` | One `owner=url` per line; each owner's certificates go to its own webhook, in the same format |
| `--fail-on <severity>` | Exit 3 when a certificate is at this severity or worse: `expired` > `critical` > `warning` > `info` |
| `--include-discovered` | Include discovered certificates in the report (they are never emailed) |
| `--json` | Output in JSON format |
| `--no-email` | Do not email certificate owners, even with `SMTP_SERVER` set |
| `--dry-run` | Print what would be posted and who would be emailed; post, send and record nothing |
| `--test-email <address>` | Send one test message through the relay settings and exit |

`fastpki-notify` applies the database `config` table over `bootstrap.conf`, as the services
do, so the windows, webhook and relay saved on the console's **Notifications** page are what a
run without `--days` / `--webhook` uses. A flag given on the command line wins.

With `SMTP_SERVER` set, each owner of a certificate this data center issued is emailed once as the
certificate enters each window and once when it expires, at the directory's `mail` for a directory
account, otherwise the account's email, otherwise `NOTIFY_EMAIL_FALLBACK`. What was sent is recorded,
and a certificate already replaced by a newer one with the same subject and names is left out.
Each run ends with a line counting what was sent, failed, already emailed, already replaced and
issued by another data center. On a standby server it sends nothing.

**Exit:** 0 = success, 1 = error, or a webhook, route or email delivery failed (reported ahead of
`--fail-on`), 2 = usage error (also `--help`, and a `--days` value with no window in it),
3 = `--fail-on` threshold met

**Config keys:** `NOTIFY_DAYS`, `NOTIFY_WEBHOOK`, `NOTIFY_WEBHOOK_FORMAT`, `NOTIFY_EMAIL_FALLBACK`,
`SMTP_SERVER`, `SMTP_TLS`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_CA_FILE`, `PG_CONNINFO`

---

### fastpki-discover

Pull-based TLS certificate discovery scanner.

```
fastpki-discover [options] [host:port ...]
```

| Flag | Description |
|------|-------------|
| `--config <path>` | Bootstrap file naming the database |
| `--targets <file>` | File with targets (host:port per line, `#` comments allowed) |
| `--timeout <seconds>` | Connection timeout (default: 5) |
| `--json` | Output in JSON format |
| `--migrate-webhook <url>` | After the scan, POST the non-compliant endpoints (any certificate with a flag) to this URL as a JSON work list |

- A target with no port uses 443
- Supports IPv4 CIDR expansion (e.g., `192.0.2.0/24:443`); a block larger than `/16` is refused
- Records each certificate found in the `discovered_certs` table

**Exit:** 0 = success, 1 = error, or the migration webhook delivery failed, 2 = usage error (also `--help`, no targets, or a target that cannot be expanded)

**Config keys:** `PG_CONNINFO`

---

### fastpki-mesh

Multi-DC logical replication topology generator (standalone, no DB).

```
fastpki-mesh [options]
```

| Flag | Description |
|------|-------------|
| `--topology <file>` | Topology definition file |
| `--node <dc_id>` | Emit one data center's section |
| `--all` | Emit every data center's section (the default) |
| `--publication` | Emit only the publication |
| `--map` | Emit only the data-center map |
| `--verify` | Emit SELECTs that list every mesh object MISSING or STALE on a node |
| `--leave` | Emit the SQL that REMOVES a data center from the mesh. Prints one section for the node leaving and one for each node that stays — a subscription owns a slot on the *other* node, so both halves are needed. With no `--node`, dissolves the whole mesh. |
| `--restore` | With `--node`, emit the SQL that brings that data center back from a dump of its own database: one file, run once per step with `psql -v node=<the node psql is on> -v step=<detach\|rebuild\|resubscribe\|finish>`. Without both variables it does nothing. [`postgres.md`](postgres.md) §6.3 gives the order. |
| `--triggers` | Emit only the conflict-resolution triggers; needs no `--topology` |
| `--allow-plaintext-transport` | Leave a conninfo that names no `sslmode` untouched instead of defaulting it to `verify-full` |
| `--no-preflight` | Skip the peer check `--node` runs before it emits anything |
| `--check-anchor <file>` | The CA file the peer check verifies peers with, where `fastpki-mesh` runs, when that is not the topology's `sslrootcert=` (which is the path on the Postgres server that subscribes). In a compose or Kubernetes web container it is `/var/pki/tls/pg/ca.crt`; `deploy/mesh-join.sh` passes it on every path |

⚠️ The per-node sections of `--all` and `--leave` are for **different machines**. Run each
on the node it names rather than piping the whole output into one `psql`.

**The release check.** `--node` connects to this node's database and to each peer named in
the topology, and compares what this node would publish against the tables the peer has,
and what the peer publishes against the tables this node has. A difference means the two
sides are on different releases, and it refuses to emit anything rather than let a
subscription fail later with `relation "public.<table>" does not exist` — an error that
names the healthy node's database and reads as a fault there.

The same check refuses a peer that publishes nothing yet, which is a peer where pass 1 ran
`--map` but not `--publication`:

```
fastpki-mesh: data center '2' does not publish anything yet: it has no fastpki_pub publication.
  Run pass 1 there first (--map, then --publication), then re-run this command.
  Nothing was created.
```

Subscribing anyway is not recoverable in place. `CREATE SUBSCRIPTION` only warns and
succeeds, and on PostgreSQL 17 the subscription then fails on every change with
`publication "fastpki_pub" does not exist`, even after the peer publishes. The only fix is
to drop it and subscribe again ([`deployment.md`](deployment.md) §9.6).

A peer that cannot be reached is a note, not a failure. `--no-preflight` asks nobody, which
is what you want when generating SQL for a data center that does not exist yet.

Topology line: `dc_id|conninfo|serial_prefix|base_url`, where the prefix is a decimal integer
1–32767, unique across the topology. It is permanent once that data center has issued
anything.

**Config keys:** `DATACENTER_ID` (the prefix itself comes from the `datacenters` table)

---

### fastpki-update

Version check and update feed + signature verification.

```
fastpki-update <command> [args...]
```

| Command | Description |
|---------|-------------|
| `version` | Show current version |
| `check` | Check the feed for a newer release: the fastpki/fastpki GitHub releases, or the JSON manifest `UPDATE_FEED_URL` names |
| `verify <artifact> <sig> [--pubkey <pem>]` | Verify a release's detached signature. With neither `--pubkey` nor `RELEASE_PUBKEY` it uses the keys compiled into FastPKI — the ones releases are signed with — so it needs no setup. Accepts either the ECDSA `.sig` or the post-quantum `.mldsa.sig` |

**Exit:**

| Command | Code | Meaning |
|---------|------|---------|
| `check` | 0 | Up to date |
| `check` | 10 | Update available |
| `check` | 1 | The check failed (the feed could not be read, or answered 404) |
| `verify` | 0 | Signature valid |
| `verify` | 1 | Signature invalid |
| `verify` | 2 | No public key given, or the key, artifact or signature file cannot be read |
| any | 2 | Usage error (no command, an unknown command, or `verify` with fewer than two files) |

**Config keys:** `UPDATE_FEED_URL`, `RELEASE_PUBKEY`. `fastpki-update` reads them from
`bootstrap.conf` only: it does not apply the database `config` table, and neither key is
read from the environment. The console's **Updates** page runs in `fastpki-web`, which does
apply the table.

---

## 2. Server Daemons

All servers read `bootstrap.conf` via `--config <path>` (default: `config/bootstrap.conf`). All handle `SIGINT`/`SIGTERM` for graceful shutdown.

### fastpki-web

Admin web UI + JSON API server.

```
fastpki-web [--config <path>]
```

**Transport:** HTTP or HTTPS (with optional TLS via `WEB_TLS_CERT`/`WEB_TLS_KEY`)

**Config keys:**
| Key | Default | Description |
|-----|---------|-------------|
| `WEB_BIND` | `::` | Bind address (dual-stack wildcard) |
| `WEB_PORT` | `8090` | Listen port |
| `WEB_TOKEN` | — | Bearer token for API auth |
| `WEB_TLS_CERT` | — | TLS cert (optional) |
| `WEB_TLS_KEY` | — | TLS key (optional) |
| `WEB_CLIENT_CA_ID` | — | mTLS: registered CA ids (preferred) |
| `WEB_CLIENT_CA` | — | mTLS: PEM file fallback |
| `WEB_ALLOW_REVOKE` | `true` | Enable write actions; set false to pin an instance read-only |
| `WEB_SELFSERVICE_IDENTITY_SUBJECT` | `true` | Console certificate requests: set the CN to the requester's user name and add the session's groups as OUs, unless the certificate profile sets `no_override_subject` |

See [API Reference](api-reference.md) for the console's HTTP endpoints, their roles and write gates.

---

### fastpki-ocsp

OCSP responder (RFC 6960) with CRL distribution.

```
fastpki-ocsp [--config <path>]
```

**Transport:** Plain HTTP (no TLS — OCSP uses CMS-level authentication)

**Config keys:**
| Key | Default | Description |
|-----|---------|-------------|
| `OCSP_BIND` | `::` | Bind address (dual-stack wildcard) |
| `OCSP_PORT` | `8080` | Listen port |
| `OCSP_RESPONDER_CERT_ID_PREFIX` | `ocsp-ra` | `cert_id` prefix for the responder cert; real id is `<this>-<ca_id>` |
| `OCSP_RESPONDER_KEY` | — | Delegated responder key (supports `pkcs11:` URI) |
| `OCSP_EXPIRY_SWEEP_SEC` | `3600` | Background expired-cert sweep interval |
| `CRL_PATH` | `/pki/signing_ca.crl` | CRL serving path |
| `CRL_NEXT_UPDATE_DAYS` | `30` | CRL validity period |
| `CRL_DELTA` | `false` | Delta CRL support |
| `CRL_CACHE_TTL_SEC` | `300` | CRL regeneration throttle |

**HTTP endpoints:** GET/POST `/ocsp`, GET CRL, per-CA variants — see [Protocol APIs](protocol-apis.md)

---

### fastpki-est

EST responder (RFC 7030).

```
fastpki-est [--config <path>]
```

**Transport:** HTTPS (required per RFC 7030 §3.3)

**Config keys:**
| Key | Default | Description |
|-----|---------|-------------|
| `EST_BIND` | `::` | Bind address (dual-stack wildcard) |
| `EST_PORT` | `8443` | Listen port |
| `EST_CERT` | – | Server TLS cert **from a file**. Unset: the certificate is a `certs` row addressed by `EST_CERT_ID` (default `est`). A path here wins over the row and freezes the listener on whatever the file holds. |
| `EST_KEY` | – | Server TLS key. No path default — the shipped config sets a `pkcs11:` URI and the key is generated **inside the token** at first start. A PEM path is the last-resort fallback, not the default. |
| `EST_CSRATTRS` | — | Legacy global OIDs |
| `EST_DEFAULT_PROFILE` | — | Profile for anonymous `/csrattrs` |
| `EST_SERVERKEYGEN` | `false` | Server-side key generation |
| `EST_SERVERKEYGEN_ENCRYPT` | `true` | Encrypt returned key with CMS |
| `EST_SERVERKEYGEN_BITS` | `2048` | RSA key size for server keygen |

**HTTP endpoints:** `/cacerts`, `/csrattrs`, `/simpleenroll`, `/simplereenroll`, `/serverkeygen`, per-CA variants — see [Protocol APIs](protocol-apis.md)

---

### fastpki-acme

ACME server (RFC 8555).

```
fastpki-acme [--config <path>]
fastpki-acme [--config <path>] --issue-device-ticket --ca <ca_id> --owner <user> [--profile <name>] [--ttl <seconds>]
```

`--issue-device-ticket` prints a one-time ticket for ACME device attestation and exits. Put
it in an Apple ACME configuration profile as `ClientIdentifier`. The ticket enrols one device
against `<ca_id>`: the certificate is issued to `<user>`, under `<name>` or, without
`--profile`, under the profiles `<user>`'s roles grant. `--ttl` defaults to 604800 seconds (7
days). The command refuses up front when the CA does not exist, when `<user>` holds no
`acme:enrol` for it, or when the profile does not apply to `<user>`. See
[user-guide.md](user-guide.md) §6.5.

**Transport:** HTTPS (required)

**Config keys:**
| Key | Default | Description |
|-----|---------|-------------|
| `ACME_BIND` | `::` | Bind address (dual-stack wildcard) |
| `ACME_PORT` | `8444` | Listen port |
| `ACME_CERT` | – | Server TLS cert **from a file**. Unset: the certificate is a `certs` row addressed by `ACME_CERT_ID` (default `acme`). A path here wins over the row and freezes the listener on whatever the file holds. |
| `ACME_KEY` | – | Server TLS key. No path default — the shipped config sets a `pkcs11:` URI and the key is generated **inside the token** at first start. A PEM path is the last-resort fallback, not the default. |
| `ACME_BASE_PATH` | `/acme` | URL base path |
| `NONCE_EXPIRES_SEC` | `300` | Replay nonce lifetime |
| `ORDER_EXPIRES_DAYS` | `7` | Order validity |
| `ACME_DNS_RESOLVER` | — | DNS-01/CAA resolver, host[:port]; name, IPv4 or [IPv6] (empty = /etc/resolv.conf) |
| `ACME_TLS_ALPN_PORT` | `443` | TLS-ALPN-01 verifier target port |
| `ACME_NEW_AUTHZ` | `false` | Pre-authorization |
| `ACME_CAA_IDENTITY` | — | CAA issuer-domain-name |
| `ACME_ATTESTATION_ROOTS` | — | Extra trust anchors for device attestation, beside Apple's compiled-in root: PEM, or base64 of PEM on one line |
| `ACME_ATTEST_MIN_OS` | — | Device attestation: refuse an attested OS version below this, e.g. `26.0` |
| `ACME_ATTEST_REQUIRE_SIP` | `false` | Device attestation: refuse a Mac with System Integrity Protection off |
| `ACME_SWEEP_SEC` | `600` | Background sweep interval |

**HTTP endpoints:** `directory`, `new-nonce`, `new-account`, `new-order`, `new-authz`, `order`, `authz`, `chall`, `cert`, `key-change`, `revoke-cert`, per-CA variants — see [Protocol APIs](protocol-apis.md)

---

### fastpki-cmp

CMP server (RFC 4210/9810).

```
fastpki-cmp [--config <path>]
```

**Transport:** Plain HTTP (CMP uses its own message-layer protection)

**Config keys:**
| Key | Default | Description |
|-----|---------|-------------|
| `CMP_BIND` | `::` | Bind address (dual-stack wildcard) |
| `CMP_PORT` | `8445` | Listen port |
| `CMP_PATH` | `/cmp` | HTTP path |
| `CMP_EXTRACERTS_CA` | `false` | Include signing CA in extraCerts |
| `CMP_CLIENT_CA_ID` | — | Registered CA id whose cert anchors client certs |
| `CMP_CLIENT_CA_BUNDLE` | — | PEM bundle in the DB config, as an additional anchor |
| `CMP_RA_KEY` | — | RA mode: signing key |

**Requires:** OpenSSL 3.2+ for CRMF APIs

**HTTP endpoints:** POST `/cmp` (handles ir, cr, p10cr, kur, rr, certConf, genm, pollReq), per-CA variants — see [Protocol APIs](protocol-apis.md)

---

### fastpki-scep

SCEP server (RFC 8894).

```
fastpki-scep [--config <path>]
```

**Transport:** Plain HTTP (SCEP secures the message layer, not the channel)

**Config keys:**
| Key | Default | Description |
|-----|---------|-------------|
| `SCEP_BIND` | `::` | Bind address (dual-stack wildcard) |
| `SCEP_PORT` | `8448` | Listen port |
| `SCEP_PATH` | `/scep` | Base path; a CA is addressed at `<SCEP_PATH>/{ca_id}` |
| `SCEP_DYNAMIC_CHALLENGE` | `false` | Accept one-time tokens |
| `SCEP_MANUAL_APPROVAL` | `false` | Async PENDING enrollment |
| `SCEP_RA_KEY` | — | RA mode: message-layer key (`pkcs11:` URI); setting it enables RA mode |
| `SCEP_RA_CERT_ID_PREFIX` | `scep-ra` | cert_id prefix for the per-CA RA certificate, held in the DB as `<this>-<ca_id>` |
| `SCEP_RENEWAL` | `true` | Certificate renewal |
| `SCEP_NEXT_CA_CERT` | — | CA key rollover |
| `SCEP_ALLOW_SHA1` | `false` | Allow SHA-1 (file-only) |
| `SCEP_ALLOW_DES3` | `false` | Allow DES3 (file-only) |

**SCEP admin CLI operations:**
```
fastpki-scep --issue-challenge [profile] --ttl <seconds>   # create dynamic challenge token
fastpki-scep --list-pending                       # list manual-approval queue
fastpki-scep --approve <txid> --ca <ca_id>        # issue the pending CSR from that CA
fastpki-scep --reject <txid>                      # reject pending CSR
```

`--approve` needs `--ca`: the queue does not record which CA a request arrived for, and
there is no default CA. `--ttl` defaults to 3600 seconds.

**HTTP endpoints:** GetCACert, GetCACaps, GetNextCACert, PKIOperation (GET/POST), per-CA variants — see [Protocol APIs](protocol-apis.md)

---

### fastpki-ms

MS-XCEP + MS-WSTEP server (Microsoft enrollment protocols).

```
fastpki-ms [--config <path>]
```

**Transport:** HTTPS (required)

**Config keys:**
| Key | Default | Description |
|-----|---------|-------------|
| `MS_BIND` | `::` | Bind address (dual-stack wildcard) |
| `MS_PORT` | `8446` | Listen port |
| `MS_CERT` | – | Server TLS cert **from a file**. Unset: the certificate is a `certs` row addressed by `MS_CERT_ID` (default `ms`). A path here wins over the row and freezes the listener on whatever the file holds. |
| `MS_KEY` | – | Server TLS key. No path default — the shipped config sets a `pkcs11:` URI and the key is generated **inside the token** at first start. A PEM path is the last-resort fallback, not the default. |
| `XCEP_PATH` | `/msxcep` | MS-XCEP endpoint path |
| `WSTEP_PATH` | `/mswstep` | MS-WSTEP endpoint path |
| `MS_XCEP_GUID` | *(created per node)* | This node's enrollment policy GUID |
| `MS_XCEP_FRIENDLY_NAME` | `FastPKI Certificate Enrollment Policy` | Policy display name |

**HTTP endpoints:** POST `/msxcep/{ca_id}` (SOAP policy), POST `/mswstep/{ca_id}` (WS-Trust enrollment) — see [Protocol APIs](protocol-apis.md). Both are per-CA: the bare `/msxcep` and `/mswstep` answer 404 naming the CA-scoped form.

---

### fastpki-store

RFC 4387 certificate store HTTP service.

```
fastpki-store [--config <path>]
```

**Transport:** Plain HTTP

**Config keys:**
| Key | Default | Description |
|-----|---------|-------------|
| `STORE_BIND` | `::` | Bind address (dual-stack wildcard) |
| `STORE_PORT` | `8447` | Listen port |

**HTTP endpoints:** GET `/certificates/search`, GET `/crls/search` — see [Protocol APIs](protocol-apis.md)

---

### fastpki-mcp

MCP (Model Context Protocol) server — exposes the inventory to MCP clients.

```
fastpki-mcp [--config <path>]
```

**Transport:** stdin/stdout (JSON-RPC 2.0) — logs to stderr only

**Config keys:** `PG_CONNINFO`, `MCP_ALLOW_WRITE` (default false). Both are read from
`bootstrap.conf` or the environment: `fastpki-mcp` does not apply the database `config`
table, so a `MCP_ALLOW_WRITE` row there has no effect on it.

**Tools:** `list_certificates`, `get_certificate`, `list_expiring`, `list_discovered`,
`list_audit`, `summary`, and `revoke_certificate` only when `MCP_ALLOW_WRITE=true`. See
[components.md](components.md) for what each returns.

---

## 3. Common Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success / clean shutdown |
| 1 | General error / fatal |
| 2 | Invalid input or usage error |
| 3 | `--fail-on` threshold met (`fastpki-notify` only) |
| 10 | Update available (`fastpki-update check` only) |
