# FastPKI administrator guide

This guide is for the people who run FastPKI once it is installed. It walks through every
page of the web console, explains each form and field, and gives the command-line way to do
the same thing where there is one. It also covers the regular jobs: backups and restores,
updates, users, CAs, and the certificates FastPKI's own services use.

It does not repeat what other guides already explain:

| For | Read |
|---|---|
| Installing FastPKI | [deployment.md](deployment.md) |
| How FastPKI is built: tokens, keys, replication, addressing | [architecture.md](architecture.md) |
| How each protocol and the console sign people in, and preparing a directory or identity provider | [authentication.md](authentication.md) |
| Roles and permissions in detail | [rbac.md](rbac.md) |
| The database: connections, schema, dumps, restores, tables | [postgres.md](postgres.md) |
| Every setting | [config-reference.md](config-reference.md) |
| Every command | [cli-reference.md](cli-reference.md) |
| The HTTP API | [api-reference.md](api-reference.md) |
| Requesting certificates as an ordinary user | [user-guide.md](user-guide.md) |
| Windows autoenrolment | [windows-autoenrolment.md](windows-autoenrolment.md) |
| A database standby on a second host | [high-availability.md](high-availability.md) |
| Which clients can verify which key algorithms | [compatibility.md](compatibility.md) |

In the examples, `pki.example.org` is the deployment's public name (the `PKI_DNS` setting)
and `issuing-ca` is the id of an issuing CA. Use your own values.

## Contents

1. [Before you start](#1-before-you-start)
2. [Dashboard](#2-dashboard)
3. [Certificate authorities](#3-certificate-authorities)
4. [Certificates](#4-certificates)
5. [Certificates for FastPKI's own services](#5-certificates-for-fastpkis-own-services)
6. [Users, computers and roles](#6-users-computers-and-roles)
7. [Directories and single sign-on](#7-directories-and-single-sign-on)
8. [What may be issued: profiles, templates and domains](#8-what-may-be-issued-profiles-templates-and-domains)
9. [Client configs](#9-client-configs)
10. [Endpoints](#10-endpoints)
11. [Settings](#11-settings)
12. [Watching the deployment](#12-watching-the-deployment)
13. [Backup and restore](#13-backup-and-restore)
14. [Updating FastPKI](#14-updating-fastpki)
15. [When something goes wrong](#15-when-something-goes-wrong)

---

## 1. Before you start

### 1.1 Signing in

Open the console at `https://pki.example.org:8090` (or the address your deployment
publishes). The sign-in form has:

- **Username** and **Password**.
- A **domain list**, shown only when at least one directory is enabled. **local account**
  means an account that exists only in FastPKI. Choosing a directory signs you in as
  `<directory id>\<username>`. You can also type a qualified name yourself, such as
  `CORP\alice` or `alice@corp.example`.
- A **Sign in with …** button for each enabled SAML or OIDC provider.

If your browser has a client certificate that the console is configured to trust
(`WEB_CLIENT_CA_ID`), that certificate signs you in without the form, with the roles of the
account the certificate belongs to. There is no logout for such a session; close the browser,
or use one that does not send the certificate, to sign in as someone else.

A wrong name or password shows **Invalid credentials**. FastPKI also slows down repeated failures:
after a few wrong passwords each further attempt must wait longer (1 s, 2 s, 4 s …), and the sign-in
page then says how long to wait.

**The first sign-in.** Installation creates the account `admin` with the password `admin`,
and forces a new password at the first sign-in. Enter the current password and a new one of
at least 8 characters.

**Sessions** last 12 hours from sign-in, whether you are active or not. When a session ends,
pages simply come up empty; reload the page to get the sign-in form. To sign out, use
**logout** next to your name at the bottom of the sidebar. The ☀ / ☾ button beside it
switches between the dark and light theme.

Two things about sessions that matter to an administrator:

- A change to someone's **primary role** takes effect the next time they sign in. Extra
  roles (§6.5) take effect at once.
- Deleting an account, or setting a new password for it, ends its open sessions (for a new
  password, all but the session that set it).

### 1.2 What you see depends on your roles

Each tab in the sidebar appears only if one of your roles holds the permission it needs. The
built-in roles see these:

| Tab | Shown to a role holding | `admin` | `auditor` | `requester` |
|---|---|---|---|---|
| Dashboard | anyone signed in | yes | yes | yes |
| Inventory | `cert:read` | yes | — | yes, named **My certificates** |
| CAs | `ca:read` or `ca:manage` | yes | — | yes |
| Audit log | `audit:read` | yes | yes | — |
| Discovered | `ca:manage` | yes | — | — |
| Compliance | `cert:read` | yes | — | own certificates |
| Notifications | `config:manage` | yes | — | — |
| Endpoints | `config:manage` | yes | — | — |
| Users | `user:manage` or `self:manage` | yes | own account | own account |
| Computers | `user:manage` | yes | — | — |
| Roles | `role:manage` | yes | — | — |
| Profiles | `profile:edit` | yes | — | — |
| HSM keys | `hsm:read` or `hsm:manage` | yes | yes | — |
| Templates | `template:edit` | yes | — | — |
| Domains, Directories, Config, Client Configs | `config:manage` | yes | — | — |
| Backup | `backup:manage` | yes | — | — |
| Version | `config:manage` | yes | — | — |

The buttons on a page follow the same permissions: a role that may change what a page shows
gets the buttons to do it (for example `ca:manage` on the CAs page, `cert:request` for the
request buttons, `cert:revoke` for Revoke). Three actions need `*:*` because of what they do on
the server: starting a discovery scan, issuing the PostgreSQL certificate, and registering or
removing a foreign CA for cross-signing. Permissions, scopes and how to build your own roles are
in [rbac.md](rbac.md).

A refused action names the missing permission, for example:

```
forbidden: roles [requester] lack audit:read for /api/audit
```

### 1.3 The read-only switch

The setting `WEB_ALLOW_REVOKE` controls whether the console may change anything. It is `true`
by default. When it is `false`:

- a **read-only** badge appears above the page content;
- buttons that change things are hidden, and anything that still reaches the server is
  refused with `console writes disabled (set WEB_ALLOW_REVOKE=true)`.

The console reads this setting when it starts, so a change needs a restart of the console.
Once writes are off, the console cannot switch them back on. Use the command line — the full
form on Docker Compose, from the `deploy` folder:

```bash
docker compose run --rm --no-deps --entrypoint fastpki-config web \
    --config /app/config/bootstrap.conf set WEB_ALLOW_REVOKE true
docker compose restart web          # or the restart command for your deployment (§1.5)
```

§1.4 gives the same command for a native, cloud or Kubernetes node, and defines the `cfg`
shorthand the rest of this guide uses for it.

### 1.4 Running the command-line tools

The `fastpki-*` tools are inside the container image on Docker Compose and Kubernetes, and
on the host on a native install. The examples in this guide use three short names —
`ca`, `cfg` and `audit` — for `fastpki-ca`, `fastpki-config` and `fastpki-audit`. Define them
once for your deployment.

**Docker Compose**, from the `deploy` folder:

```bash
cd deploy
ca()    { docker compose run --rm --no-deps --entrypoint fastpki-ca     web --config /app/config/bootstrap.conf "$@"; }
cfg()   { docker compose run --rm --no-deps --entrypoint fastpki-config web --config /app/config/bootstrap.conf "$@"; }
audit() { docker compose run --rm --no-deps --entrypoint fastpki-audit  web --config /app/config/bootstrap.conf "$@"; }
```

These run in a throwaway container, so they work even when the console is down. The
container sees only its own files: a file a command reads (a CSR, a CSV, a certificate) or
writes with `--out` must be in a host folder mounted into it, as §13.4 shows with
`-v /backup:/backup`.

**Native install (Alpine and OpenRC), and the cloud images**, which are native installs. Work
as the `fastpki` user — commands that reach the token fail as root with
`C_Initialize failed (rc=48)`:

```bash
su -s /bin/sh fastpki            # on a cloud image: doas su -s /bin/sh fastpki
ca()    { fastpki-ca     --config /etc/fastpki/bootstrap.conf "$@"; }
cfg()   { fastpki-config --config /etc/fastpki/bootstrap.conf "$@"; }
audit() { fastpki-audit  --config /etc/fastpki/bootstrap.conf "$@"; }
```

**Kubernetes:**

```bash
ca()    { kubectl -n fastpki exec statefulset/fastpki-node -c web -- fastpki-ca     --config /app/config/bootstrap.conf "$@"; }
cfg()   { kubectl -n fastpki exec statefulset/fastpki-node -c web -- fastpki-config --config /app/config/bootstrap.conf "$@"; }
audit() { kubectl -n fastpki exec statefulset/fastpki-node -c web -- fastpki-audit  --config /app/config/bootstrap.conf "$@"; }
```

A file written with `--out` lands inside the pod; copy it out with `kubectl cp`.

The other tools (`fastpki-notify`, `fastpki-discover`, `fastpki-update`) run the same way:
replace the tool name.

### 1.5 When a change takes effect

Most settings are read by each service **when it starts**. After you change one, the Config
page marks it **pending restart** and names the services that still run the old value.

| What you changed | When it applies |
|---|---|
| Users, roles, role assignments | at once (a primary role: at the user's next sign-in) |
| Enabling or disabling a CA | at once |
| Switching a protocol on or off (Endpoints page) | within about 10 seconds |
| A new or renewed certificate for a service's existing key | within about 30 seconds (§5.1) |
| Settings, profiles, approved domains, MS templates, a new key for an HTTPS service | when the service that uses them restarts |

Restart a service from the Endpoints page (§10), or with the command for your deployment:

| Deployment | Restart one service | Restart all protocol services |
|---|---|---|
| Docker Compose | `docker compose restart est` | `docker compose restart web ocsp est acme cmp scep ms store` |
| Native | `rc-service fastpki-est restart` | `for s in web ocsp est acme cmp scep ms store; do rc-service fastpki-$s restart; done` |
| Kubernetes | `kubectl -n fastpki exec fastpki-node-0 -c est -- kill 1` | `for c in web ocsp est acme cmp scep ms store; do kubectl -n fastpki exec fastpki-node-0 -c $c -- kill 1; done` |

On Kubernetes each service is a container in every server pod, so in a pair run the command for
`fastpki-node-1` as well. It restarts that container in place and leaves the pod's database running.

Leave out any protocol your deployment does not run.

### 1.6 Finding your way around

- The **sidebar** on the left lists the tabs.
- The **top bar** shows the page title, a search box on the pages that have one, and the
  counts `N certs · N audit · N discovered` (for roles that can read the audit log).
- **Messages** appear in the corner. Errors stay until you close them; information messages
  disappear after 8 seconds.
- **Confirmation dialogs** ask before anything that cannot be undone. **Enter** confirms and
  **Esc** cancels.

---

## 2. Dashboard

The Dashboard is the landing page. It changes nothing.

| Panel | Shows |
|---|---|
| **Active certificates** | valid certificates |
| **Issued (24h)** | certificates issued in the last 24 hours |
| **Expiring < 7 days** | valid certificates that expire within a week (amber when not zero) |
| **Revoked** | revoked certificates (red when not zero) |
| **Issuance · last 14 days** | a bar per day, and the number of CAs |
| **Key algorithms** | the four most common key types among issued certificates |
| **My enrolment credentials** | your own secrets for CMP, ACME and SCEP clients (below) |
| **Recent activity** | the six newest audit events |

The four numbers and the chart are counted from the **newest 100 certificates** only. For a
larger deployment use the Inventory page or `fastpki-audit`. Like the rest of the page, the
key-algorithm panel counts only the certificates you may see.

**My enrolment credentials** appears for users who hold `cert:request` and whose roles allow
them to enrol over a protocol. It holds four values, hidden until you press **Reveal**:

| Value | Used by |
|---|---|
| **Key id** | CMP (as the reference) and ACME (as the external account key id) |
| **CMP shared secret** | a CMP client |
| **ACME EAB HMAC** | an ACME client such as certbot |
| **SCEP challenge** | a SCEP client |

The four download buttons give ready-to-use client files with these values filled in: a CMP
configuration for `openssl cmp`, a certbot configuration, a Windows `certreq` request file,
and a SCEP enrolment script, for the CA chosen under **Files enrol against**. They are the same
files as on the Client Configs page (§9).

Nobody else can read your credentials, administrators included. To replace them, open the
Users page, your own row, and press **Regenerate** (§6.7).

---

## 3. Certificate authorities

A **CA** (certificate authority) signs certificates. FastPKI usually runs a **root CA**, which
signs only other CAs, and one or more **issuing CAs** (also called sub CAs), which sign the
certificates people and machines use. Every CA's private key lives in a PKCS#11 **token** — a
hardware security module, or the bundled SoftHSM — and never leaves it.

### 3.1 Decisions to make before you create a CA

These are hard or impossible to change later.

- **The key algorithm.** RSA and EC work with every client. Ed25519, Ed448 and the ML-DSA
  (post-quantum) algorithms do not: Windows cannot validate a chain from such a CA, and
  PostgreSQL cannot use a certificate from one. Changing a CA's algorithm later means creating
  a new key and re-issuing everything below it. Read [compatibility.md](compatibility.md)
  first.
- **Replicable or not.** A key created as **replicable** can be copied, encrypted, into
  another node's token. Only then can a second node sign with the same CA — needed for an HA
  pair and for sharing one CA across data centers. This is decided when the key is created
  and cannot be added afterwards. A single server that will never have a second node does not
  need it. See [architecture.md](architecture.md) §6.
- **The id.** A CA's id appears in every enrolment URL and cannot be renamed. In a
  multi-data-center deployment give each data center's CAs their own ids (for example
  `dc1-sub`, `dc2-sub`), because CA registrations replicate and two data centers must not use
  the same id.
- **The validity.** A CA cannot be valid for longer than its parent: an end date after the
  parent's, including "never expires", is shortened to the parent's end date, because no client
  could build a chain past it. The log says when that happened.
- **The public name.** The addresses of the CRL and of the CA certificate are written into
  every certificate a CA signs, from `BASE_URL` (or `PKI_DNS`). Set them to the name clients
  will use **before** creating CAs; see [deployment.md](deployment.md) §4.3.

### 3.2 The CAs page

The page lists every CA registered in this deployment.

| Column | Shows |
|---|---|
| **Subject** | the CA's common name |
| **Issuer** | who signed the CA certificate |
| **Serial** | the certificate serial number (hover for all of it) |
| **Key** | the key type and size, for example `RSA-4096` or `EC P-256` |
| **Key location** | `HSM` when the CA's record names a key in a token — even one held on another node, which the Status column then marks `no key here`; `none` when the CA was registered without a key |
| **Status** | see below |

Status labels:

| Label | Meaning |
|---|---|
| `active` | the CA can sign |
| `disabled` | an administrator stopped new issuance; everything already issued keeps working |
| `no key here` | shown beside `active`: this node does not hold the key (for example another data center's CA, or an offline root). Its certificate is still served in chains, but this node cannot issue, sign a CRL or answer OCSP for it |
| `on hold` | the CA certificate is on hold (revoked with reason certificateHold): it cannot sign and everything it issued stops validating, until the hold is released |
| `revoked` | the CA certificate is revoked; it can never sign again |
| `expired` | the CA certificate has expired; create a replacement CA |

Row buttons (for `admin`, when writes are allowed):

| Button | Does |
|---|---|
| **Disable** / **Enable** | stops or restarts new issuance at once (§3.10) |
| **Renew** | opens the CA's details at the Renew section (§3.8) |
| **Revoke** | revokes an issuing CA, or puts it on hold (§3.10); not offered for a root |
| **Release hold** | shown on a CA that is on hold, with **Revoke** and **Delete** (§3.10) |
| **Delete** | removes a CA that has issued nothing (§3.10) |

Click anywhere else on a row to open the CA's details (§3.6).

Above the table are four buttons: **+ New CA**, **Import an existing CA**, **+ Create CSR (key
in HSM)** and **Request from a CSR**.

**From the command line:** `ca list` lists the CAs; `ca show <id>` shows one;
`ca show <id> --pem` prints its certificate.

#### The key picker

The New CA, Import, Create CSR and Renew forms share the same fields for choosing where a key
lives:

| Field | What to enter |
|---|---|
| **Slot** | the token to use. The deployment's own token (`PKCS11_TOKEN`) is chosen for you |
| **Token** | filled in from the slot |
| **Key name** | a name for the key object in the token, for example `issuing-ca`. Use a name nothing else uses |
| **PIN file** | the file holding the token PIN, filled in from `PKCS11_PIN_FILE`. The PIN itself is never sent to the browser |
| **PKCS#11 URL** | built from the fields above, for example `pkcs11:token=fastpki;object=issuing-ca;type=private?pin-source=/var/pki/tls/pin`. Copy it if you will need it later |

Algorithms the chosen token cannot generate are greyed out and marked **not in this token**.

### 3.3 Creating a CA

Press **+ New CA**.

**Identity**

| Field | What to enter |
|---|---|
| **id** | a short, permanent name: letters, digits, `-`, `_` and `.`, up to 64 characters. Not `default` |
| **display name** | a friendly name. Leave empty to use the id |
| **Parent CA** | **— none (root) —** for a root CA. For an issuing CA, the CA that signs it. Only active CAs whose key is on this node are listed |
| **CN** | the CA's common name, for example `Example Issuing CA`. Required |
| **OU, O, L, ST, C** | optional parts of the name: organisational unit, organisation, locality, state, two-letter country code |

**Key & signature**

| Field | What to enter |
|---|---|
| **Algorithm** | RSA, RSA-PSS, EC (ECDSA), Ed25519, Ed448, ML-DSA-44, ML-DSA-65 or ML-DSA-87. See §3.1 |
| **RSA bits** | 2048, 3072 or 4096 (default). RSA and RSA-PSS only |
| **Curve** | P-256, P-384 or P-521. EC only |
| **Hash** | the digest of the signature on this CA's own certificate — made by the parent, for an issuing CA: sha256 (default), sha384, sha512, sha3-256, sha3-384, sha3-512. Only RSA and EC let you choose; the others have a built-in digest, which the field shows. It does not decide the digest the CA uses when it signs certificates later |
| **use an existing key already in the token** | leave unticked to create a new key (the normal case). Tick it only to use a key that is already in the token under **Key name** |
| **replicable key** | tick for an HA pair or a CA shared across data centers. On an HA pair every CA needs it, the root included |
| key picker | see §3.2 |

When you tick **use an existing key**, **Algorithm** and **Hash** are locked and ignored: the
certificate is built from the key already in the token, and signed with sha256 where the key
takes a hash.

**Validity**

| Field | What to enter |
|---|---|
| **Not before** | the first day the CA is valid. Leave empty for now |
| **Not after** | the last day the CA is valid. Leave empty for ten years from now. Under a parent, never later than the parent's end date (§3.1) |
| **never expires (9999-12-31)** | ticks the special "no expiry" date instead. Under a parent that expires, the parent's end date is used |

**Constraints**

| Field | What to enter |
|---|---|
| **Path length** | how many levels of CA may exist below this one. `0` means this CA may sign only end certificates. Empty means no limit |
| **Key usage** | what the CA key may be used for. **keyCertSign** and **cRLSign** are ticked, which is what a CA needs |
| **Name constraints — Permitted / Excluded** | limits on the names this CA may certify, one per line: `DNS:example.org`, `IP:10.0.0.0/8`, `email:.example.org`, `URI:.example.org`. Leave empty for no limits |

**Advanced (AIA / CRL DP / policies)**

| Field | What to enter |
|---|---|
| **Enable AIA caIssuers URIs** | puts the address of the parent CA's certificate into this CA's certificate, so clients can find the chain. Ticked for an issuing CA; not available for a root |
| **Enable CRL distribution URIs** | puts the address of the parent's CRL into this CA's certificate. Leave it ticked: without it no client can find out that this CA was revoked. Not available for a root |
| **Certificate policy OIDs** | optional policy identifiers, separated by commas |

The addresses are derived from the CA ids and `BASE_URL`; you cannot type them. After
creating an issuing CA, open its details and check **All attributes** to see exactly what it
carries.

Press **Create CA**. The key is created in the token, the certificate is signed (by itself for
a root, by the parent otherwise), and the CA is ready.

Refusals you may see:

| Message | Meaning |
|---|---|
| `a CA is already registered under this id` | pick another id, or delete the old CA |
| `a key already exists at that handle` | another key already has this **Key name**. You are asked whether to replace it: replacing destroys the old key, and a key another CA or a running service uses is never replaced. Or cancel and tick **use an existing key** to certify that key |
| `the token '…' does not generate … keys` | choose another algorithm |
| `policy: RSA key too short (…)` or `EC key too short` | a CA key must be at least `MIN_RSA_BITS` or `MIN_EC_BITS` |
| `the profile '…' does not permit basicConstraints CA:TRUE` | your own role's certificate profile does not allow creating CAs (§8.2) |
| `CA certificate is revoked`, `has expired`, `no signing key for this CA on this node`, `CA instance disabled` | the chosen parent cannot sign |

**From the command line:**

```bash
ca create issuing-ca --name "Example Issuing CA" --parent root-ca \
    --subject "/CN=Example Issuing CA" --days 1825 \
    --key ec --curve P-384 --keygen \
    --ca-key 'pkcs11:token=fastpki;object=issuing-ca;type=private?pin-source=/var/pki/tls/pin'
```

`--key` takes `rsa`, `rsa-pss`, `ec`, `ed25519`, `ed448`, `ML-DSA-44`, `ML-DSA-65` or
`ML-DSA-87`. Add `--replicable` for a replicable key, `--bits` for RSA, `--md` for the digest.
Leave out `--keygen` to use a key already in the token. The command line has no options for
the start date, path length, key usage, name constraints or policies; use the console for
those.

### 3.4 Importing an existing CA

Use **Import an existing CA** to register a CA whose certificate already exists: a CA signed
on another node, a CA whose key you already put in the token, or another data center's CA
that this node should trust but never sign with. A certificate this node signed with **Request
from a CSR** is already in the Inventory; importing it registers the CA on that record. Any other
certificate that is already stored is refused. An id that is already registered is accepted only
for a renewal of that CA (§3.8).

| Field | What to enter |
|---|---|
| **id**, **display name** | as for a new CA |
| **Certificate** | paste the CA certificate (PEM), or upload a `.pem`, `.crt` or `.cer` file |
| **This node holds the key in its token** | choose this when the CA's private key is in this node's token. Fill in the key picker with that key's name. Nothing is generated or uploaded |
| **Trust anchor only — this node never signs with it** | choose this to register a CA this node only verifies against — for example a shared root, or a peer data center's CA |

The parent is read from the certificate itself.

The import does not check that the key matches the certificate. A wrong key shows up at the
first signature as `the CA certificate and its private key do not match`.

**From the command line:** `ca add <id> --name "<name>" --ca-pem <file> --ca-key pkcs11:<uri>`.
Leave out `--ca-key` for a trust anchor.

### 3.5 An issuing CA whose key is on another node

When the root lives on one node and the issuing CA's key must be in another node's token
(the usual multi-data-center setup), the key never travels. Instead:

1. **On the node that will hold the key**, press **+ Create CSR (key in HSM)**. This creates
   the key in that node's token and gives you a certificate request (CSR).
2. **On the node with the parent CA**, press **Request from a CSR**, paste the CSR, and sign
   it. You get the new CA's certificate.
3. **Back on the first node**, use **Import an existing CA** with that certificate and the
   same key name.

The full walk-through, including the trust steps a mesh needs, is
[deployment.md](deployment.md) §9.1.

**Create CSR (key in HSM)** fields:

| Field | What to enter |
|---|---|
| **CN, OU, O, L, ST, C** | the new CA's name. Type only the value, for example `Example DC2 Issuing CA` |
| **Algorithm, RSA bits, Curve** | the new key |
| **Hash** | the digest used to sign the request itself |
| **use an existing key already in the token** | build the request for a key already in the token |
| **replicable key** | as for a new CA |
| key picker | where the key is created |
| **Path length, Key usage, Name constraints, Certificate policy OIDs** | what you are asking for. The signing CA decides what it actually grants |

Press **Create CSR**. If a key already has that name, you are asked whether to replace it.
Replacing destroys the old key for good, and is refused if the key belongs to a CA or a service.
The request appears with a **Download .csr** link.
Nothing is registered on this node yet.

**Request from a CSR** fields (on the CAs page this signs a CA request; the button of the
same name on the Inventory page is for ordinary certificates):

| Field | What to enter |
|---|---|
| **Issue from** | the CA that signs, normally your root |
| **The request** | paste the CSR, or upload a `.csr` / `.pem` file. Its signature is checked first, and its key must meet `MIN_RSA_BITS` / `MIN_EC_BITS`, as for a new CA |
| **Not before, Not after, never expires** | the new CA's validity. Empty dates give ten years, never later than the signing CA's end date |
| **Hash** | the signature digest, where the signing key allows a choice |
| **Path length, Key usage, Name constraints, Certificate policy OIDs** | what the signing CA grants. What the request asked for is ignored |
| **AIA caIssuers**, **CRL distribution point** | ticked: the addresses are derived from the signing CA |
| **AIA OCSP** | adds the signing CA's OCSP address, if it has an OCSP responder certificate |

Press **Sign request**. The certificate appears with a **Download .crt** link. This node records
it in the Inventory as a CA certificate it signed, so it can be found and revoked here, but does
not register the CA: that happens where the CA's key is, when that node imports the certificate
(§3.4). Importing it on this node registers the CA on the same record.

**From the command line:**

```bash
ca csr dc2-sub --subject "/CN=Example DC2 Issuing CA" --key ec --curve P-384 --keygen \
    --ca-key 'pkcs11:token=fastpki;object=dc2-sub;type=private?pin-source=/var/pki/tls/pin' \
    --out dc2-sub.csr                                   # on the node that holds the key
ca sign-csr root-ca --csr dc2-sub.csr --days 1825 --out dc2-sub.crt    # on the root's node
ca add dc2-sub --name "DC2 Issuing CA" --ca-pem dc2-sub.crt \
    --ca-key 'pkcs11:token=fastpki;object=dc2-sub;type=private?pin-source=/var/pki/tls/pin'
```

`ca sign-csr` defaults to 1825 days (the console to ten years).

### 3.6 A CA's details

Click a CA's row. The details show the id, name, type (`root` or `intermediate`), subject,
issuer, serial number, key, key location, signature algorithm, key identifiers, validity
dates, the number of certificates it has issued, its status (`active`, `disabled`, `revoked` or
`expired`), whether this node can sign with it, and its SHA-256 and SHA-1 fingerprints.

- **PEM** — **Copy** or **Download** the CA certificate. This is what you give to clients
  that must trust the CA.
- **All attributes** — the full decoded certificate.
- **MS-XCEP endpoints** (§3.7) follow for every CA. **Renew** (§3.8) and **Cross-sign**
  (§3.9) follow for `admin` when writes are allowed, on a CA that is active and neither revoked
  nor expired.

### 3.7 MS-XCEP endpoints

This section decides what Windows clients are told about this CA when they fetch the
enrolment policy. Most deployments leave it alone.

| Column | What to enter |
|---|---|
| **Endpoint URI** | the enrolment address Windows should use. Leave empty to advertise this server's own address for this CA |
| **Client auth** | how the client authenticates there: **Anonymous (renewals only)**, **Kerberos**, **Username + password**, or **X.509 client certificate** |
| **Priority** | lower numbers are tried first; `-1` sends no priority |
| **Renewal only** | tick if this address serves only renewals |

**+ endpoint** adds a row; the bin icon removes one. **Clients may enrol against this CA**,
when unticked, makes Windows offer this CA for renewals only. Press **Save**. Removing every
row goes back to advertising this server's own address. There is no command-line equivalent.
[windows-autoenrolment.md](windows-autoenrolment.md) explains the whole Windows setup.

### 3.8 Renewing a CA

Renewing gives a CA a **new certificate with a new validity**, so it keeps working after its
current certificate expires. You can renew with a **new key** or keep the **current key**. The
current certificate stays valid until its own end date, so everything it signed keeps
working, and nothing is revoked. The CA signs with the new certificate from then on.

Who signs the new certificate depends on the CA:

- **An issuing CA** (it has a parent): its parent signs it. Its end date is never later than
  the parent's. The CRL distribution point and AIA addresses are derived from the parent again,
  so a data center added since the old certificate is included. The parent's key must be on
  this node and the parent must be enabled. If the parent's key is on another node, see
  *Renewing through a CSR* below.
- **A root**: it signs its own new certificate. Clients have to add the new root to their
  trusted roots. With a new key, FastPKI also issues two cross-certificates: the new key signed
  by the old root, so clients that still trust only the old root keep working until it expires,
  and the old key signed by the new root.

Open the CA's details (or press **Renew** in its row) and fill in the **Renew** section:

| Field | What to enter |
|---|---|
| **Keep the current key** | tick to renew the certificate only. The key fields below are then hidden |
| **Slot, New key name, PIN file** | where the new key goes. The name must be new, for example `issuing-ca-2` |
| **Algorithm, RSA bits, Curve** | the new key |
| **replicable key** | the new key does not inherit this from the old one; tick it again if you need it |
| **Hash** | sha256, sha384 or sha512 |
| **Validity (days)** | 3650 by default |

Press **Renew**. The message shows the new certificate's serial number and end date.

With a new key, FastPKI then re-signs whichever OCSP responder, CMP RA and SCEP RA certificates
this CA has. The services pick up the new certificates by themselves; no restart is needed.
With the current key there is nothing to re-sign.

A CA that is revoked or expired cannot be renewed; create a replacement CA instead.

#### Renewing through a CSR

When an issuing CA's parent key is on another node (for example a root on one node and an
issuing CA on each of the others), **Renew** refuses and says so. Renew it the same way it was
created (§3.5), keeping its id:

1. **On the node that holds the CA's key**, press **+ Create CSR (key in HSM)** with the CA's
   exact subject. Tick **use an existing key already in the token** to keep the current key, or
   create a new key.
2. **On the parent's node**, press **Request from a CSR**, choose the parent, and sign.
3. **Back on the first node**, use **Import an existing CA** with the **same id** as the CA, the
   new certificate and its key. It is registered as the CA's next certificate and keeps the
   CA's name and state.

An import under an id that is already registered is accepted only as a renewal: the same
subject, signed by the CA's parent, or self-signed for a root. Anything else is refused.

**From the command line:**

```bash
ca csr dc2-sub --subject "/CN=Example DC2 Issuing CA" \
    --ca-key 'pkcs11:token=fastpki;object=dc2-sub;type=private?pin-source=/var/pki/tls/pin' \
    --out dc2-sub-renew.csr                             # on the node that holds the key
ca sign-csr root-ca --csr dc2-sub-renew.csr --days 1825 --out dc2-sub-renew.crt   # on the root's node
ca add dc2-sub --ca-pem dc2-sub-renew.crt \
    --ca-key 'pkcs11:token=fastpki;object=dc2-sub;type=private?pin-source=/var/pki/tls/pin'
```

#### Renewing from the command line

`ca renew` does exactly what the **Renew** section does — it is the same code — so a node you
reach only over SSH needs no browser:

```bash
ca renew issuing-ca                                # keep the current key
ca renew issuing-ca --days 1825 --md sha384        # and set the validity and hash
ca renew issuing-ca --new-key 'pkcs11:token=fastpki;object=issuing-ca-2;type=private?pin-source=/var/pki/tls/pin' \
    --key ec --curve P-256 --replicable            # re-key
```

Without `--new-key` the CA keeps its current key. The key options (`--key`, `--bits`,
`--curve`, `--replicable`) apply only to a new key, so the command refuses them rather than
ignoring them when you have not asked for one.

The same refusals apply as in the console: a CA whose parent is on another node is told to use
the CSR route above, and a CA whose parent is disabled is told to enable it for the renewal.
That last one is the common case if you followed the advice to disable the root once your
issuing CAs are signed:

```bash
ca enable root-ca
ca renew issuing-ca
ca disable root-ca
```

Restart this node's services afterwards so they load the new certificate.

### 3.9 Cross-signing another organisation's CA

A cross-certificate lets clients that trust your CA accept certificates issued by a partner's
CA, within limits you set. It is done from the details of the CA that vouches for the partner.

First register the partner's CA: press **Register a foreign CA…**, paste its certificate
(exactly one PEM certificate), write in **Why it is trusted** how you verified it (for
example, the fingerprint was confirmed by phone), and press **Register**. **Remove selected**
takes an entry out of the list; cross-certificates already issued stay valid until revoked or
expired. Registering and removing need a role holding `*:*`; cross-signing a registered CA
needs `ca:manage`.

Then fill in:

| Field | What to enter |
|---|---|
| **Foreign CA** | the registered CA to vouch for |
| **Path length** | how many CA levels the partner may have below its CA. `0` (the default) means none |
| **Validity (days)** | 3650 by default |
| **Hash** | the signature digest, for an RSA CA. An EC, Ed25519 or ML-DSA CA uses the digest its key requires |
| **Permitted subtrees** | required: the names the partner may certify, one per line, for example `DNS:partner.example` |

Press **Cross-sign**. The certificate appears with a **Download** button. It is also listed on the
Inventory page, marked `cross-certificate` in **Serves**, where it can be revoked (§4.5).

**From the command line:**
`ca cross-sign issuing-ca --foreign-pem partner-ca.pem --permitted DNS:partner.example --pathlen 0`.
The command line also accepts `--excluded`, which the console does not offer.

### 3.10 Disabling, revoking and deleting a CA

**Disable** stops new issuance at once. Everything the CA already issued stays valid, and its
CRL and OCSP keep answering. Enrolment against a disabled CA is refused. **Enable** reverses
it. This is the right tool for a CA that is simply no longer in use.
Command line: `ca disable <id>` and `ca enable <id>`.

**Revoke** puts the CA's certificate on its **parent's** CRL. The CA stops signing on every
node, and every certificate it ever issued stops validating as clients pick up that CRL. Every
certificate the CA has — each generation after a renewal — is revoked together. Choose the
reason in the dialog:

| Reason | Use it when |
|---|---|
| **unspecified** | no other reason fits. The CRL entry then carries no reason code |
| **cACompromise** | the CA's private key is, or may be, compromised |
| **affiliationChanged** | the CA's name or organisation no longer applies |
| **superseded** | the CA has been replaced by another |
| **cessationOfOperation** | the CA is no longer needed |
| **certificateHold** | the CA must stop for now, for example while a suspected compromise is investigated. This is the one reason that can be undone |
| **privilegeWithdrawn** | the CA is no longer allowed to issue |

Every reason except certificateHold is **final**.

**Release hold** (on a CA's row while it is on hold) undoes a hold. Every certificate of the CA
is valid again, the CA signs again at once and OCSP answers `good` for it. Clients that already
fetched the parent's CRL keep rejecting the CA until they fetch a newer one. A CA on hold can
also be revoked for good, from its row, with any other reason.

A root cannot usefully be revoked — it would only appear on its own CRL, which nobody checks —
so for a root, disable it and remove it from the clients' trust stores instead. Revoking an
issuing CA reaches clients only if the CA's own certificate carries a CRL address (§3.3);
otherwise they have nowhere to learn of it. There is no command-line equivalent.

**Delete** removes a CA **that has issued nothing**, and destroys its key in the token. It is
refused for a CA with issued certificates: use Disable for those. A trust anchor (no key) is
removed without touching the token. Command line: `ca delete <id>`, or
`ca delete <id> --keep-key` to leave the key in the token.

**An offline root's CRL.** A root whose key is not on any node cannot sign its own CRL. Sign
the CRL where the key is, then publish it here with `ca import-crl <id> <file>`; FastPKI checks
it against the root's certificate first.

### 3.11 The HSM keys page

The HSM keys page lists every object in this deployment's token, so you can see keys without
logging in to the host. It changes nothing: there is no delete button.

| Column | Shows |
|---|---|
| **Key name** | the object's label |
| **Class** | `private`, `certificate`, `secret` or `other` |
| **Type** | the key type and size or curve, for example `RSA 4096` or `EC P-256` |
| **CKA_ID** | the object's id in hexadecimal |
| **Serves** | what uses this key: `CA <id>` for a CA's signing key, or the listener or service credential — `web`, `est`, `acme`, `ms`, `cmp-ra`, `ocsp-ra`, `scep-ra` |

Keep in mind:

- An empty **Serves** cell means no CA, listener or service credential uses the key. That is normal for
  an ordinary certificate's key.
- An error line at the top explains why the list could not be read, for example
  `C_Login failed … check the token PIN`.

Keys are created by the CA forms (§3.3–§3.8) and by **+ Request (key in HSM)** on the
Inventory page (§4.3). A key is destroyed only when a CA is deleted, when you confirm
replacing a key, or when a failed creation cleans up after itself.

Copying keys between nodes is done from the command line with `ca key replicate` and
`ca key sync`; see [architecture.md](architecture.md) §6 and [high-availability.md](high-availability.md).

---

## 4. Certificates

The **Inventory** page lists issued certificates — including cross-certificates, but not a CA's own
certificate — and is where the
console issues and revokes them. A `requester` sees only their own, on a tab named **My
certificates**.

### 4.1 The list

| Column | Shows |
|---|---|
| **CN** | the certificate's common name |
| **Serves** | for a certificate FastPKI's own services use: which one, for example **OCSP responder for issuing**, or the service id such as `web-1` for the console on data center 1. Empty for an ordinary certificate |
| **Serial** | the serial number |
| **CA** | the CA that issued it |
| **Owner** | who requested it; a `computer` label marks a machine account |
| **Status** | `valid`, `expired`, `revoked`, `on_hold` (revoked with reason certificateHold, until released), `pending` (CMP issued it and is waiting for the client to confirm), or `superseded` (a service certificate replaced by a newer one). Superseded is not revoked: OCSP answers `good` for it and the CRL does not list it, until it expires. To have both refuse it, revoke it with reason `superseded`; its status then reads `revoked` |
| **Expires** | the end date |

- The **search box** finds certificates across the whole inventory by CN, subject, owner,
  serial number or any of their additional names (SANs). Paste a **fingerprint** and it finds
  that certificate: SHA-1 or SHA-256, with the colons `openssl` prints or the spacing Windows
  shows. The four selector hashes the RFC 4387 certificate store searches by work here too.
- Click a column header to sort (CN, Owner, Serial, Status and Expires sort properly).
- The row under the headers filters the loaded rows: type in a text box, or choose from a
  list for CA and Status.
- The page loads at most 500 certificates at a time; use the search box to find others.

Click a row to open the certificate's details (§4.5).

Above the table are the request buttons (for `admin` and `requester`, when writes are allowed):
**+ Request (key in browser)**, **+ Request (key in HSM)** (roles with `hsm:manage`),
**+ Request from a CSR**, and **Issue Postgres certificate** (`admin`, §5.5).

Whichever way a certificate is requested, it follows the **certificate profile** the
requester's roles allow (§8.2). When `WEB_SELFSERVICE_IDENTITY_SUBJECT` is on (the default)
and the profile does not say otherwise, the common name is replaced by the requester's own
username.

### 4.2 Requesting with a key made in the browser

**+ Request (key in browser)** generates the key pair on your computer, in the browser, and
sends the server only the certificate request. When the certificate comes back, the browser
saves it together with the private key as files on your computer. The private key is never
sent anywhere. The console must be opened over HTTPS for this to work.

| Field | What to enter |
|---|---|
| **Issue from** | the CA that signs |
| **Profile** | leave it *not named* to apply the profiles the requester's roles grant, combined if there are several; or pick one of them to apply only that profile (§8.1) |
| **CN** | the common name. Required |
| **O, OU, C, ST, L** | optional name parts (C is a two-letter country code) |
| **Email** | optional; goes into the name. Add it to the SANs too if you need an email SAN |
| **Subject alternative names** | the names the certificate is for, one per line or separated by commas: DNS names, IP addresses, email addresses and URIs are recognised; write `upn:user@domain` for a Windows UPN. **Nothing is added for you** — for a server certificate, put its DNS name here |
| **Algorithm** | RSA, RSA-PSS, EC or Ed25519 |
| **Key size** / **Curve** | 2048, 3072 or 4096 bits for RSA; P-256, P-384 or P-521 for EC |
| **Key usage** | digitalSignature and keyEncipherment are ticked. keyEncipherment is RSA-only |
| **Extended key usage** | serverAuth and clientAuth are ticked; add others as needed, or dotted OIDs in the text box |
| **Encrypt key with password** | protects the saved private key file. Leave empty for an unprotected key |
| **Download format** | PEM (certificate and key as `.pem`), DER (`.crt` and `.key`), or PKCS#12 (one `.p12` file, for Windows, Java or macOS; needs a password) |
| **omit AIA / omit CRL DP** | leave out the CA addresses, as an OCSP responder certificate needs. On this form they appear only for roles that can edit profiles, and only when some profile allows them; the server still checks your own profile |

Press **Generate & request**. The files download and the table reloads. The profile may
remove key usages or purposes it does not allow.

There is no command-line equivalent; scripts use the enrolment protocols instead
([user-guide.md](user-guide.md)).

### 4.3 Requesting with a key in the HSM

**+ Request (key in HSM)** creates the key inside the token. You get the certificate; there is
no private key to download. Use it for service identities and anything whose key must not be
copyable. §5 explains the **Serve as** field, which turns the request into one of FastPKI's own
service certificates.

| Field | What to enter |
|---|---|
| **Serve as** | **— an ordinary certificate —**, or one of FastPKI's own listeners (§5.4). ⚠️ **Do not use the three RA entries** — CMP RA, SCEP RA, OCSP responder. FastPKI creates those credentials for each issuing CA itself (`fastpki-ca renew-service-certs --create-missing`, which the scheduled job also runs), one per CA with the right subject, purposes and addresses. Choosing one here on a CA that already has the credential generates a key under the same label and fails on the key name, which describes nothing useful. The four listener entries are not affected: they are the only way to give a listener a CA-issued certificate whose key is generated in the token |
| **Issue from** | the CA that signs. Only CAs that can sign on this node are listed |
| **Token slot** | the token. The deployment's own token is chosen for you |
| **Use existing key** | tick to certify a key already in the token under **Key name**; its type is then read from the token |
| **Algorithm, Key size, Curve** | the new key. RSA keys default to 3072 bits |
| **replicable key** | tick if the key must be copyable to another node, for example on an HA pair |
| **Key name** | the key's name in the token. Filled in when **Serve as** is set |
| **PIN file** | the token PIN file, filled in from `PKCS11_PIN_FILE` |
| **Key handle** | the resulting PKCS#11 URL (read-only) |
| **CN, Organisation, Org. unit, Country, State, Locality, Email** | the certificate's name. CN is required |
| **SANs** | one name per line; DNS, IP, email and URI are recognised, `upn:user@domain` for a UPN |
| **Key usage, Extended KU, Custom EKU** | the certificate's purposes; **Custom EKU** takes dotted OIDs |
| **Profile** | the profile the server will apply (read-only) |
| **Signature hash** | for an RSA CA, the digest (CA default follows the key size). For other CAs it is fixed |
| **omit AIA / omit CRL DP** | shown when the profile allows it |
| **Custom extensions** | one per line: `OID value`, or `!OID value` for a critical extension. Your profile decides which are allowed |

Press **Generate in HSM & request**. If a key already has that name you are asked whether to
replace it; replacing destroys the old key, and a key a CA or a running service uses is never
replaced.

### 4.4 Requesting from a CSR

**+ Request from a CSR** is meant for a request made elsewhere (for example with
`openssl req`). Choose the CA in **Issue from**, optionally a **Profile** as on the browser
form (§4.2), paste the PEM request and press **Request**;
the certificate downloads. **Issue from** lists the same CAs as the browser form: CAs that can
sign on this node, are enabled, are neither revoked nor expired, and are not roots. When it
reads *no CA on this node can issue certificates*, there is nothing to sign with here.

### 4.5 A certificate's details

Click a row. The details show the name, serial, which service it serves, subject, issuer,
alternative names, status, fingerprints, revocation date and reason (if revoked), owner,
validity, key and signature algorithm, **All attributes** (the full decoded certificate), and
the certificate as PEM text.

At the bottom:

- **Revoke** — for `admin` and `requester` (a `requester` only for their own certificates).
  Choose a reason — unspecified, keyCompromise, affiliationChanged, superseded,
  cessationOfOperation, certificateHold or privilegeWithdrawn; a cross-certificate offers
  cACompromise instead of keyCompromise — and press **Revoke**. Every reason except
  certificateHold is final. If it fails, the message says why.
- **Release hold** and **Revoke for good** — on a certificate that is on hold. Release makes it
  valid again: OCSP answers `good` at once and the next CRL no longer lists it. Revoke for good
  replaces the hold with a final reason.
- **Renew** and **Re-key** — for certificates whose key is in the token, for roles with
  `hsm:manage`. See §5.3.

### 4.6 How revocation reaches clients

- **OCSP** answers `revoked` immediately, and `good` again as soon as a hold is released.
- The **CRL** is rebuilt at most every `CRL_CACHE_TTL_SEC` seconds (300 by default), so a new
  revocation can appear in OCSP a few minutes before it appears in the CRL. That is normal. A
  certificate on hold is on the CRL until it is released; with delta CRLs on (`CRL_DELTA`), the
  release is announced in the delta as `removeFromCRL`.
- A revocation with reason unspecified carries no reason code, in the CRL and in OCSP.
- A client can also revoke its own certificate over ACME or CMP.

An expired certificate stays in the inventory; nothing is ever deleted.

### 4.7 Why a request is refused

The message names the reason. The common ones:

| Message | Cause | Where to fix it |
|---|---|---|
| `policy: CN '…' is not in the approved domains` (or `SAN DNS '…'`) | the name is outside the approved domains | Domains page (§8.4) |
| `policy: … not permitted by profile '…'` | the profile does not allow that type of name (DNS, IP, email, URI, UPN). Usages and extensions a profile does not allow are left out rather than refused, unless no requested key usage is left | Profiles page (§8.2) |
| `policy: this identity holds no profile permission` | none of the requester's roles has a `profile:use` grant | Roles page (§6.11) |
| `policy: the profiles this identity holds (…) set a different …` | the requester holds several profiles that disagree on a default (key usage, extended key usage, validity or stamped extensions), none is named like the requester's role, and the request did not decide it | ask for the key usages in the request, name a profile, or align the profiles; see §8.1 |
| `too many SubjectAltName entries`, `per-requester issuance limit reached`, `per-name issuance limit reached`, `certificate limit reached` | a role's issuance limits | Roles page (§6.11) |
| `CA certificate is revoked`, `CA certificate has expired`, `no signing key for this CA on this node`, `CA instance disabled` | the CA cannot sign | CAs page (§3) |
| `policy: RSA key too short` or `policy: EC key too short` | the key is below `MIN_RSA_BITS` or `MIN_EC_BITS` | use a larger key |
| `the token '…' does not generate … keys` | the token does not support that algorithm | choose another algorithm |

---

## 5. Certificates for FastPKI's own services

FastPKI's services need certificates of their own. Installation creates them
([deployment.md](deployment.md) §4.4); this chapter is about keeping them valid.

### 5.1 What they are

| Certificate | Used for | Shown in Serves as | Key |
|---|---|---|---|
| **Console TLS** | the console's HTTPS | `web` (or `web-<DATACENTER_ID>`) | in the token (`WEB_TLS_KEY`) |
| **EST TLS**, **ACME TLS**, **MS-XCEP/WSTEP TLS** | those services' HTTPS | `est`, `acme`, `ms` (with the same suffix) | in the token (`EST_KEY`, `ACME_KEY`, `MS_KEY`) |
| **OCSP responder**, one per issuing CA | signing OCSP answers | `ocsp-ra-<ca id>` | in the token (`OCSP_RESPONDER_KEY`) |
| **CMP RA**, one per issuing CA | protecting CMP answers | `cmp-ra-<ca id>` | in the token (`CMP_RA_KEY`) |
| **SCEP RA**, one per issuing CA | SCEP encryption and signing | `scep-ra-<ca id>` | in the token (`SCEP_RA_KEY`); RSA only |
| **PostgreSQL** | the database's TLS | `postgres` | a file, because PostgreSQL cannot use a token key |

Until an HTTPS service has a certificate from your CA, it uses a self-signed one of its own,
and browsers and clients warn. Until OCSP, CMP or SCEP has its key and certificate, OCSP
answers `internalerror`, CMP refuses every request, and SCEP enrolment fails; each service's
log says which part is missing.

None of these services needs a restart for a new certificate on the key it already has. The
HTTPS services check every 30 seconds for a renewed certificate and serve it to new
connections; OCSP, CMP and SCEP look their certificate up as they work, and notice a newly
created key within about 20 seconds. Only a **new key** for an HTTPS service (a re-key, §5.3)
needs that service restarted.

### 5.2 What renews them automatically

A daily job runs `fastpki-ca renew-service-certs`: the `certrenew` service on Docker Compose,
the `renew` container of every server pod on Kubernetes, and `/etc/periodic/daily/fastpki-certrenew`
on a native install. It:

- renews each **OCSP responder, CMP RA and SCEP RA** certificate, and each **HTTPS
  certificate** (console, EST, ACME, MS) that comes from your CA, once it is 75% of the way
  through its life (`SERVICE_CERT_RENEW_FRACTION`). It keeps the key, and for an HTTPS
  certificate also the names and the lifetime; the running service serves the renewal within
  30 seconds;
- renews the **PostgreSQL** certificate, but only if `PG_TLS_CA_ID` names the CA to use
  (§5.5);
- creates any missing OCSP, CMP and SCEP credentials;
- replaces the **self-signed HTTPS certificates** (console, EST, ACME, MS) with ones from your
  issuing CA. Each of these services makes a self-signed certificate the first time it starts,
  because it has to answer HTTPS before any CA exists. The job replaces it on its next run
  after the service has started and an issuing CA exists, keeping the key and the name
  (`PKI_DNS`). A service that has not started yet is skipped until it has.

**Which CA signs them.** With one issuing CA, that one. With more than one, the job does not
choose: set **`HTTPS_CA_ID`** to the CA you want, on the Config page (section Certificate
Authority) or with `cfg set HTTPS_CA_ID issuing-ca`. Until then the job reports
`this node has more than one issuing CA` with the candidates, and the services keep their
self-signed certificates. A root CA is never picked by itself. Once a certificate comes from a
CA, that same CA renews it; the setting only decides the first one.

The HTTPS certificates FastPKI issues by itself last 90 days; ones you issue in the console last
as long as the profile allows. Either way the job renews them in time, as long as it runs and the
CA that issued them can still sign.

To see what the job would do now:

```bash
ca renew-service-certs --dry-run --create-missing --re-issue-self-signed
```

In the Inventory, sort by **Expires**, or type a service id (`web`, `est`, `ocsp-ra`, …) in the
**Serves** filter, to see when each certificate runs out.

### 5.3 Renewing or re-keying one by hand

**In the console:** open the certificate's details on the Inventory page and press:

- **Renew** — a new certificate for the same key. The service serves it within 30 seconds.
- **Re-key** — a new key in the token (the form suggests the next name, such as `web-tls-2`)
  and a certificate for it; the service's key setting is changed to the new key. A re-keyed
  HTTPS service must be **restarted** (§1.5) to load its new key; OCSP, CMP and SCEP follow by
  themselves.

Both open the **Request (key in HSM)** form filled in from the old certificate — the service,
the CA, the name and the alternative names. Check it and press **Generate in HSM & request**.
The old certificate stays valid until it expires or you revoke it.

**From the command line**, every certificate the daily job would renew, now instead of when it
falls due (no restart needed):

```bash
ca renew-service-certs --force                  # all of them
ca renew-service-certs --force --ca issuing-ca  # only the ones one CA issued
```

There is no command for a re-key.

### 5.4 Creating one by hand

On the Inventory page press **+ Request (key in HSM)** and set **Serve as**:

| Serve as | Creates |
|---|---|
| **Console TLS (WEB_CERT_ID)**, **EST TLS**, **ACME TLS**, **MS-XCEP/WSTEP TLS** | an HTTPS certificate for that service. **Tick Use existing key**: the service already has a key and is using it, and a key a running service uses is never replaced. Put the public name (`PKI_DNS`) in **CN** and in **SANs**, plus any other name clients connect to — modern clients check only the SANs |
| **CMP RA**, **OCSP responder**, **SCEP RA** | the credential for the CA chosen in **Issue from** |

Choosing a service fills in the key name, the usages and the extensions it needs. SCEP RA is
locked to RSA, because it decrypts requests. On a new install the settings already name the
OCSP, CMP and SCEP keys (`ocsp-ra`, `cmp-ra`, `scep-ra`) but the keys are not in the token yet;
the form fills in that name and creates the key. On an HA pair tick **replicable key**.

Press **Generate in HSM & request**. The service picks the new certificate up by itself: an
HTTPS service within 30 seconds, since it keeps its key; OCSP, CMP and SCEP as soon as the
key and certificate exist.

CMP accepts requests signed with a client certificate only from the CA named in
`CMP_CLIENT_CA_ID`. Set it to your issuing CA on the Config page, or with
`cfg set CMP_CLIENT_CA_ID issuing-ca`, and restart `cmp`; without it CMP accepts only
shared-secret requests, so a client cannot revoke its own certificate.

**From the command line**, all the missing OCSP, CMP and SCEP credentials at once, and every
self-signed HTTPS certificate replaced.

On an HA pair, set `SERVICE_KEYS_REPLICABLE=true` (§11) **first**, before anything creates
these credentials. A key that was not generated replicable can never become so, and the
scheduled nightly run has no command line to carry `--replicable`.

```bash
ca renew-service-certs --create-missing --re-issue-self-signed
```

Running services serve their new certificates within 30 seconds. A service that was not
running is skipped (`skipped … nothing published yet`); start it and run the command again.
With more than one issuing CA, set `HTTPS_CA_ID` first (§5.2). `--ca <id>` names the CA too,
but it also limits the OCSP, CMP and SCEP credentials to that one CA.

### 5.5 The PostgreSQL certificate

PostgreSQL reads its certificate and key from files in `PG_TLS_DIR`, so this one is handled
separately.

**In the console:** on the Inventory page press **Issue Postgres certificate**.

| Field | What to enter |
|---|---|
| **Issuing CA** | the CA that signs. It must use an RSA or EC key |
| **Key** | RSA 3072 or EC P-256 |

Press **Issue**. FastPKI writes `server.crt`, `server.key` and `ca.crt` into `PG_TLS_DIR`, and
PostgreSQL loads them within about 30 seconds; open connections keep the old certificate until
they reconnect. The certificate covers `postgres`, `localhost`, `127.0.0.1`, `PKI_DNS`, this
node's `PG_BIND` address and every name in `PG_TLS_SANS`.

**Then set `PG_TLS_CA_ID`** on the Config page (area **Database**) to the same CA id. The
console does not do this for you, and without it the daily job never renews the certificate:
when it expires, every service loses its database connection.

**From the command line:**

```bash
ca pg-tls issuing-ca
cfg set PG_TLS_CA_ID issuing-ca
```

More detail, including the refusals, is in [postgres.md](postgres.md) §2.1.

---

## 6. Users, computers and roles

### 6.1 How access is decided

Every person or machine that signs in is a **subject**. What a subject may do is the
combination of:

- its **primary role** — the role on its account;
- **extra roles** given to its username (§6.5);
- roles given to any **directory group** it belongs to (§6.6).

Everything these roles allow is added together. A subject with no role, or only the role
`none`, can sign in and see an empty Dashboard, and nothing more. The details are in
[rbac.md](rbac.md).

Names from a directory are always written with the directory's id in front, such as
`corp\alice`. A name without one is a local account. The same person in two directories is two
different subjects.

The built-in roles are:

| Role | For |
|---|---|
| `admin` | everything |
| `auditor` | reading the audit log and the token's key list; issues nothing |
| `requester` | requesting, reading and revoking their own certificates, over the console and every protocol |
| `none` | the role a directory or SSO user gets on first sign-in until you give them something |

### 6.2 The Users page

The page lists the subjects that are people; machine accounts are on the Computers page
(§6.10). With the `self:manage` permission alone, you see only your own account.

The buttons above the list (for roles with `user:manage`, when writes are allowed) are
**+ New user**, **+ New group**, **Import groups from LDAP**, **Import user from LDAP**, and
**Delete selected**. The search box filters by name and role.

When groups hold roles, the page shows:

- **Groups** — each group that holds a role, with its roles and where it comes from. Click a
  group to list its members next to it.
- **Members of <group>** — the subjects that group reaches.
- **Not in any group** — everyone else.

Each subject row shows:

| Column | Shows |
|---|---|
| **Type** | `user`, `computer` or `group` |
| **Name** | the name, the display name if different, and `via <group>` for someone listed through a group |
| **Role** | the primary role and extra roles |
| **Source** | `local` for a FastPKI password; otherwise how the person signs in: `ldap`, `saml` or `oidc` (`external` when not recorded) |
| **Must reset** | `yes` when the next sign-in must set a new password |
| ⚙ | opens the subject (§6.4 or §6.5) |

If the directory refused the member search, a warning at the top says so, and group members
are missing from the list.

### 6.3 Adding a local user

Press **+ New user**.

| Field | What to enter |
|---|---|
| **Username** | letters, digits and `- _ . @ $ / \`, up to 64 characters. Names are not case-sensitive |
| **Email** | optional: where emails about this user's expiring certificates go (§12.2) |
| **Password** | at least 8 characters |
| **Role** | the primary role. Required: the list starts on *choose a role* |
| **Force password reset on next login** | tick to make the user choose their own password at first sign-in. Refused for an account whose roles do not grant `self:manage` (such as `none`), because it could not change its password |

Press **Save**. If the role allows enrolment, the user's enrolment credentials are created
(§6.7).

You can only give a role whose permissions you hold yourself, and you cannot change your own
role. Ask another administrator.

**From the command line:**

```bash
cfg web-user alice 'Initial-Pass-1' --role requester --must-reset --email alice@example.org
```

The command line does not check that the role exists, does not apply the two rules above, and
always sets the password. Without `--role` it gives `admin`.

People who sign in through a directory or single sign-on do not need an account here: they are
added at their first sign-in with the primary role `none`, unless their SAML or OIDC provider's
admin or auditor group matches (§7.4). Roles given to them or to their groups (§6.5, §6.6)
apply on top. Signing in through a directory also needs the setting `AUTH_BACKEND=ldap` (§7.2).

### 6.4 Editing a user

Click the ⚙ on an account's row.

| Field | What to enter |
|---|---|
| **Email** | where emails about this user's expiring certificates go (§12.2), or empty. For a directory account the directory's own address is used when it has one; for a SAML or OIDC account this field is filled from the provider each time the user signs in |
| **Password** | a new password of at least 8 characters, or leave empty to keep the current one. Typing a password here also turns a directory account into a local one. A new password signs the user out of their open sessions |
| **Role** | the primary role. It applies at the user's next sign-in. A stored role that is not in the list is shown as *(current)* and kept |
| **Force password reset on next login** | tick to make the user choose a new password. Refused for an account whose roles do not grant `self:manage` |

Below are **Console role assignments** (§6.5) and **Enrolment credentials** (§6.7). Changes in
those two sections apply as soon as you make them; **Save** applies the fields above.

### 6.5 Extra roles for a user or a group

The **Console role assignments** section, in the user dialog and in the group dialog, lists the
roles given directly to this user or group, on top of any primary role.

- To add one, choose the role and press **+**. The role `none` is not offered.
- To remove one, press **×** beside it and confirm.

**+** and **×** are shown only when writes are allowed.

The same rule applies as for accounts: you can only give roles whose permissions you hold.

A subject with no account — a directory user or group — opens a dialog with only this section.
A subject left with no roles disappears from the list.

### 6.6 Groups

A **group** here is a group name from your directory or identity provider (an LDAP or Active
Directory group, or a group claim from SAML or OIDC). Everyone who signs in as a member gets the
group's roles. Membership is managed in the directory, not in FastPKI.

**+ New group**:

| Field | What to enter |
|---|---|
| **Name** | the group name, with the directory or provider id in front: `<id>\<group>`, for example `corp\PKI Admins` |
| **Role** | the role to give the group |

Press **Create**. A message then says how many members the directory reported, or that it
reported none (check the name) or could not be read.

**Import groups from LDAP** lists the groups the directories offer, already qualified. Tick the
groups, press **members** beside one to see who is in it, choose **Assign role**, and press
**Import selected**.

**Import user from LDAP** searches the directories for people. Tick the users, choose **Assign
role** and press **Import selected**. This gives the person a role; it does not create a local
account.

The member lists on this page are read from the directory again every
`DIRECTORY_GROUP_REFRESH_SEC` seconds. Each group row says how many members were found and when;
press **↻** on the row to read that group again now. What a person may do follows the groups the directory or
identity provider reports **when they sign in**, so a membership change reaches a session at the
next sign-in.

### 6.7 Enrolment credentials

Each user whose roles allow enrolment over a protocol has three secrets: a CMP shared secret, an
ACME external account key, and a SCEP challenge. They let the user's own clients enrol as that
user, and let you cut one user off without changing a secret everyone shares.

- They are **created automatically**: when a user with an enrolling role is created, given a
  role, or signs in, and when the user opens their Dashboard.
- They are **removed** when the user's account or own role assignments are saved and none of their
  roles allows enrolment any more. Editing or deleting a role, or taking a role away from a group,
  does not remove them.
- **Only the user can see them**, on their Dashboard (§2) if they hold `cert:request`. The
  Enrolment credentials section of someone else's user dialog says whether they have them, as
  `(set)`, and never shows the values.
- **Regenerate** replaces all three. Every client configured with the old values stops working.
  You can regenerate another user's credentials (with `user:manage`) but not see the new ones; the
  user finds them on their Dashboard.

### 6.8 Deleting users and subjects

Tick the rows and press **Delete selected**, then confirm. For an account, this deletes the
account, its enrolment credentials and the extra roles given to its username, and signs it out
of every open session. For a group or a directory user, it removes every role given to it.

You cannot delete your own account.

There is no command-line equivalent.

### 6.9 Changing your own password or email address

Open the Users page, press ⚙ on your own row, type your **Current password** and a **New password**
of at least 8 characters, and press **Save**. Your other sessions are signed out; this one stays.
A forced reset (the screen shown at sign-in) works the same way.

To change only your **Email**, type it and press **Save**, leaving both password fields empty. No
password is needed for that.

### 6.10 The Computers page

The Computers page is the same as the Users page, for machine subjects: names ending in `$`
(Windows computer accounts, such as `CORP\WEB01$`) or containing `/` (service principals such as
`host/web01.corp.example`). A domain computer usually has no account; it appears as a member of
a group that holds a role, for example `corp\Domain Computers`. The buttons and dialogs are those
of the Users page, and the tab is shown to roles holding `user:manage`.

### 6.11 The Roles page

Roles decide what their holders may do and which CAs, profiles and templates they may do it to.

| Column | Shows |
|---|---|
| **Role** | the name; a `built-in` label for the four built-in roles |
| **Description** | what the role is for |
| **Grants** | how many permissions it has, and which CAs, profiles or templates they are limited to |
| **Issuance limits** | the three limits below, or `no limits` |

Click a row for the full details, or ⚙ to edit.

**Creating a role:** type a **name** (letters, digits, `. _ - @`, up to 64 characters) and a
**description** under the table and press **create role**. The new role has no permissions until
you edit it. A name that already exists is refused; edit that role with its ⚙ instead.

**Editing a role** (⚙):

| Field | What to enter |
|---|---|
| **Description** | what the role is for |
| **Certificates this subject may hold** | the most valid certificates one holder may have. Empty for no limit |
| **Active certificates for one requested name** | the most valid certificates for the same name |
| **SubjectAltName entries in one certificate** | the most alternative names in one certificate |
| **Grants** | one row per permission: choose the **Permission** and its **Scope** |

For a subject holding several roles, the largest number any of them sets applies; a role
with an empty limit does not lift another role's limit.

**Scope** limits a permission: for `profile:…` choose a profile, for `template:…` a template,
and for the CA-related permissions (`ca:…`, `cert:…` and the five `…:enrol`) a CA. `*` means all.
`cert:read` and `cert:revoke` also offer `own`: only the holder's own certificates. The other
permissions have no scope, and the list offers only `—`.

**add grant** adds a row; choose its permission before saving. **remove** deletes a row. Press
**save role**.

The permissions, and what each allows, are listed in [rbac.md](rbac.md) §3. The ones most often
needed:

| To let holders … | Grant |
|---|---|
| request certificates in the console | `cert:request`, `cert:read` (scope `own` for their own only), `ca:read`, and `profile:use` on one profile |
| enrol over EST, ACME, CMP, SCEP or Windows | `est:enrol`, `acme:enrol`, `cmp:enrol`, `scep:enrol` or `ms:enrol`, scoped to the CA, plus `profile:use` (or `template:use` for Windows) |
| manage accounts | `user:manage` and `self:manage` |
| read the audit log | `audit:read` |

**Deleting roles:** tick them and press **Delete selected**. Built-in roles cannot be deleted,
but they can be edited. Deleting a role removes its assignments to users and groups; accounts
whose primary role it was keep the name and are refused everything until you give them another
role. The last role holding `role:manage` can be neither deleted nor stripped of that permission.

There is no command-line equivalent for roles.

---

## 7. Directories and single sign-on

The Directories page lists every identity provider this deployment signs people in against:
LDAP and Active Directory directories, and SAML and OIDC providers. How each kind of sign-in
works, and how to prepare the directory or identity provider, is in
[authentication.md](authentication.md).

A provider's **id** becomes part of every name it authenticates (`corp\alice`), so choose it
carefully: it cannot be changed, and renaming it later means giving every role again.

### 7.1 The page

**Directories** lists the LDAP and Active Directory connections: id, name, state, priority,
server addresses, NetBIOS name, DNS root, realm (the DNS root in capitals), and whether a search
password is stored. **Federated sign-in** lists the SAML and OIDC providers: id, kind, name,
state, priority, sign-in address or issuer, and whether a local account is required.

**+ Add directory** and **+ Add provider** create them; **edit** and **remove** act on a row
(for `admin`, when writes are allowed).

### 7.2 Adding an LDAP or Active Directory directory

| Field | What to enter |
|---|---|
| **id** | a short name with no spaces, slashes or `@`, for example `corp`. Cannot be changed |
| **display_name** | shown in the sign-in page's domain list, for example `Corp AD` |
| **uris** | the directory servers, separated by commas, for example `ldaps://dc1.corp.example,ldaps://dc2.corp.example`. Use names, not IP addresses. Required |
| **base_dns** | where user entries are, separated by **semicolons**, tried in order. A password check looks for `CN=<user>,<base>`, so name the container that holds the users, for example `CN=Users,DC=corp,DC=example;DC=corp,DC=example`. Required |
| **bind_dn** | the read-only account used to search the directory. Empty for an anonymous search |
| **bind_pw** | that account's password. It is never shown again; leave empty on an edit to keep it |
| **clear bind_pw** | on an edit, removes the stored password |
| **netbios_name** | the domain's short name, for example `CORP`, so people can sign in as `CORP\alice` |
| **dns_root** | the domain's DNS name, for example `corp.example`, so people can sign in as `alice@corp.example` |
| **group_filter** | the search filter for groups. Empty uses a filter that finds the usual group types |
| **group_attr** | the attribute holding a group's name. Empty uses `cn` |
| **ca_cert_file** | for `ldaps://`: the path, on the FastPKI host or container, of the CA certificate that signed the directory's certificate |
| **template_base** | where Active Directory keeps certificate templates, for the template import (§8.3). Empty finds it automatically |
| **priority** | order in the domain list; lower first. Default 100 |
| **network_timeout_sec** | how long to wait for a server, in seconds. Default 3 |
| **enabled** | untick to stop using the directory without deleting it |

When **netbios_name** or **dns_root** is left empty, FastPKI asks the directory for it on saving,
using the search account; if that fails, fill them in yourself. A person may sign in with any of
the directory's id, display name, NetBIOS name, DNS root or realm, so a name another directory
already answers to is refused. The id cannot be one another provider — directory, SAML or OIDC —
already uses.

Press **add directory**.

Directories are used for signing in only when the setting `AUTH_BACKEND` is `ldap` (the default
is `local`, which accepts FastPKI accounts only). Set it on the Config page, area
**Authentication**, and restart the console, EST and MS (§1.5). Then sign in as `corp\someone` to
test it: a person with no role yet reaching an empty Dashboard means the sign-in itself worked.

**From the command line:**

```bash
cfg auth-providers-add corp \
    --uris ldaps://dc1.corp.example,ldaps://dc2.corp.example \
    --base-dns 'CN=Users,DC=corp,DC=example;DC=corp,DC=example' \
    --bind-dn 'CN=svc_fastpki,OU=Service,DC=corp,DC=example' --bind-pw-file /run/secrets/svc_fastpki \
    --display-name 'Corp AD' --netbios CORP --dns-root corp.example \
    --ca-cert /var/pki/tls/corp-ldaps-ca.pem
cfg auth-providers-list
```

Every option you leave out is reset, except the stored password and keytab. The full option
list is in [cli-reference.md](cli-reference.md).

### 7.3 A Kerberos keytab for Windows enrolment

A keytab lets domain-joined Windows computers enrol with their Kerberos ticket, with no password
prompt. It belongs to an Active Directory directory: open the directory with **edit**, and under
**Kerberos keytab** choose the file and press **upload keytab**. The upload happens at once,
separately from **save**. The status line says where the file is stored.

The keytab's realm is the directory's DNS root in capitals, and its key servers are the
directory's **uris**. How to create the keytab on a domain controller is in
[windows-autoenrolment.md](windows-autoenrolment.md). There is no command-line equivalent.

### 7.4 Adding a SAML provider

Press **+ Add provider** and choose **SAML**.

| Field | What to enter |
|---|---|
| **id** | a short name, as for a directory |
| **display_name** | the text of the sign-in button: **Sign in with …** |
| **idp_entity_id** | the identity provider's entity ID. When set, assertions from any other issuer are refused |
| **idp_sso_url** | the provider's sign-in address. Required |
| **idp_cert** | the path, on the FastPKI host or container, of the provider's signing certificate (PEM). Required |
| **sp_entity_id** | FastPKI's own entity ID, as registered with the provider, for example `https://pki.example.org/sp`. Required |
| **ACS address** | shown, not typed: the address to register with the provider (below) |
| **username_attr** | the attribute holding the username. Empty uses the NameID |
| **groups_attr** | the attribute holding group names. Empty uses `groups` |
| **clock_skew_sec** | how far the clocks may differ, in seconds. Default 120 |
| **admin_group**, **auditor_group** | a group name (without the provider id) whose members get `admin` or `auditor`, for people with no local account |
| **priority** | the order of the sign-in buttons |
| **require local account** | tick to let in only people who already have an account here |
| **enabled** | untick to hide the button |

Register FastPKI with the provider using the address `https://pki.example.org:8090/api/saml/acs`
(the console's own address — `BASE_URL` when set — followed by `/api/saml/acs`). In a
multi-data-center deployment, register each node's own address. The console publishes its
metadata at `/api/saml/metadata`; with several SAML providers, only the first one's metadata is
served there.

### 7.5 Adding an OIDC provider

Press **+ Add provider** and choose **OIDC**. Changing the kind clears what you typed.

| Field | What to enter |
|---|---|
| **id**, **display_name** | as for SAML |
| **issuer** | the provider's issuer URL, the one serving `/.well-known/openid-configuration`. Required |
| **client_id** | the client id registered with the provider. Required |
| **client_secret** | the client secret. It is never shown again; leave empty on an edit to keep it |
| **clear client_secret** | on an edit, removes the stored secret |
| **redirect address** | shown, not typed: the address to register with the provider (below) |
| **scopes** | empty uses `openid email profile` |
| **username_claim** | the claim holding the username. Empty uses `email` |
| **groups_claim** | the claim holding group names. Empty uses `groups` |
| **ca_cert** | for a provider behind a private CA: the path of that CA's certificate |
| **admin_group**, **auditor_group**, **priority**, **require local account**, **enabled** | as for SAML |

Register the redirect address `https://pki.example.org:8090/api/oidc/callback` (the console's
own address followed by `/api/oidc/callback`) with the provider, once for each node.

SAML and OIDC providers have no command-line equivalent.

### 7.6 Removing a provider

Press **remove** and confirm. The roles given to that provider's users and groups are not
deleted, but they stop matching anyone, so those people lose access until a provider with the
same id exists again. The message after removal counts the affected user and group assignments.

---

## 8. What may be issued: profiles, templates and domains

Three things limit what a certificate may contain:

- A **certificate profile** limits key usages, purposes, name types, validity and extensions.
  It applies to the console, EST, ACME, CMP and SCEP. A requester may use the profiles their
  roles grant with `profile:use`.
- An **MS certificate template** does the same for Windows enrolment. A requester may use the
  templates their roles grant with `template:use`.
- The **approved domains** limit which DNS names may appear. They apply everywhere except ACME,
  which checks domain ownership itself.

### 8.1 How a profile is chosen

A requester's roles grant one or more profiles; if they grant none, every request is refused.

- **The request names a profile** (the **Profile** list on the console's key-in-browser and
  CSR forms, CMP `-profile`, or a SCEP one-time token created for one): that profile alone
  applies, and only if the requester holds it. The key-in-HSM form does not name one; it shows
  the profile that will apply.
- **One profile, none named:** it applies.
- **Several, none named:** they are combined. A request may have anything **any** of them
  allows: key usages and extended key usages, name types, wildcards, extensions from the
  request, leaving out AIA or CRL DP, and the longest maximum validity. Anything none of them
  allows is left out, as with a single profile.

Some settings are not permissions but what a profile adds when the request says nothing: the
default key usage and extended key usage, a fixed validity, and extensions the profile stamps.
When the combined profiles agree on one of these, that value applies. When they differ, the
profile named like the requester's own role decides, which is how the built-in `admin` and
`requester` roles and profiles pair up. When none is named like that role either, a request
that relies on the setting is refused with a message naming it. A request that asks for its
key usages itself is not affected, and naming one profile always works.

The profiles are stored in the database and reach every data center, with the role grants that
name them. The console uses a change at once; the enrolment services read profiles when they
start, so restart them after a change (§1.5).

### 8.2 The Profiles page

| Column | Shows |
|---|---|
| **Name** | the profile's name; `built-in` for `requester` and `admin` |
| **No override** | whether the requested name is kept as it is |
| **CA** | `CA:TRUE` if the profile allows creating CAs, with any path length cap |
| **Default KU**, **Default EKU** | usages added when a request asks for none |
| **SAN types** | the alternative name types allowed |
| **Wildcard** | whether `*.example.org` names are allowed |
| **Max days** | the longest validity allowed |

Click a row for all the details and the **Clone this profile** button; ⚙ edits it; **+ New
profile** creates one. The two built-ins can be edited and cloned but not deleted.

| Built-in | Allows |
|---|---|
| `requester` | end-certificate key usages; named purposes including server, client, code signing, email, time stamping, OCSP, CMC RA and smart card logon; DNS, IP, email and URI names; no wildcards; no custom extensions. The CN is replaced by the requester's username |
| `admin` | everything `requester` allows, plus CA key usages, any purpose, `othername` names, wildcards, any custom extension, omitting AIA and CRL addresses, and creating CAs. The requested name is kept |

**The profile editor:**

| Field | What to enter |
|---|---|
| **Name** | letters, digits, `- _ .`, up to 64 characters. Changing the name of an existing profile saves a **new** profile and leaves the old one |
| **Do not override Subject** | tick to keep the requested name as it is, even when `WEB_SELFSERVICE_IDENTITY_SUBJECT` would replace the CN with the username |
| **May create a CA** | tick to allow creating CAs on the CAs page under this profile. Also allow keyCertSign and cRLSign below. Ordinary certificates are never CAs, whatever this says |
| **Max path length** | the largest path length a CA created under this profile may have. Empty for no cap. A cap also refuses a CA with no path length |
| **Allowed Key Usage** | the key usages a certificate may carry. A requested usage that is not ticked is dropped; a request left with none is refused |
| **Default Key Usage** | added when the request asks for none. Defaults count as allowed |
| **Allowed Extended Key Usage** | the purposes a certificate may carry, plus dotted OIDs in the text box, or `*` for any. Others are dropped |
| **Default Extended Key Usage** | added when the request asks for none |
| **Allowed SAN types** | `dns`, `ip`, `email`, `uri`, `othername`. Ticking none saves `dns`, `ip` and `email` |
| **Max validity (days)** | shortens certificates to this many days. `0` means no extra limit: `CERT_VALIDITY_DAYS` still applies |
| **Allow wildcard names** | tick to allow `*.example.org` |
| **CSR attributes (EST /csrattrs)** | what EST clients are told to put in their requests: challengePassword, extensionRequest, a key type, a signature algorithm, extra OIDs. Empty uses `EST_CSRATTRS` |
| **Custom extensions** | extensions added to every certificate, one per line: `<oid> <value>`, with the value in OpenSSL's format (`DER:05:00`, `ASN1:UTF8:text`); `!` before the OID makes it critical |
| **Allowed custom extensions (from the CSR)** | extensions a request may bring in, as OIDs separated by commas, or `*` for any |
| **Suppress default extensions** | **requester may omit AIA** and **requester may omit CRL DP** let a request leave out those addresses — needed for an OCSP responder certificate |

**Clear** empties the form. Press **Save profile**; a profile with the same name is replaced
without asking. A profile has no key algorithm or key size setting; key strength is controlled by
`MIN_RSA_BITS` and `MIN_EC_BITS`.

**Deleting profiles:** tick them and press **Delete selected**. Role grants naming a deleted
profile stay behind, and the Roles page will refuse to save that role until you remove them.

Who may use or edit a profile is set on the Roles page, with `profile:use` and `profile:edit`.

**From the command line:** `cfg profiles-export` prints the stored profiles (every profile you
added and every built-in you edited) as one JSON object, and `cfg profiles-import <file>` stores
each profile in a file of that shape, replacing those with the same names. Nothing is stored if
any profile in the file cannot be read. `cfg profiles-delete <name>` removes one, or returns a
built-in to its shipped definition. The console sees these changes at once.

### 8.3 The Templates page

This page holds the Microsoft certificate templates that Windows clients are offered and that
FastPKI enforces when they enrol. [windows-autoenrolment.md](windows-autoenrolment.md) covers the
whole Windows setup.

**Built-ins or your own, never both.** While the list holds no enabled templates of your own,
FastPKI offers three built-ins: `GenericUser`, `Email` and `GenericComputer`. As soon as one of
your own is enabled, only your enabled templates are offered, for every CA, and a yellow note says
so. Delete or disable all of yours to go back to the built-ins. Disabled templates stay in the list
so you can edit, enable or delete them.

Templates are stored in the database and reach every data center, disabled ones included; the
config backup carries all of them too. Changes reach Windows only after `fastpki-ms` restarts, and
Windows also keeps its own copy of the policy. Clear it on the Windows client, in the context
whose certificates you are enrolling: `certutil -f -policyserver * -policycache delete` for
machine certificates, `certutil -f -user -policyserver * -policycache delete` for user ones.

| Column | Shows |
|---|---|
| **Name** | the template name; `built-in` for the three built-ins |
| **OID** | the template's object identifier |
| **Validity (d)** | the validity in days |
| **EKUs** | the purposes |
| **Enabled** | whether it is offered |

The search box finds templates by name, OID or purpose. Click a row for the details, with every
flag spelled out.

**+ New template** and ⚙ open the editor. A new template starts from the default values, enabled
and open for enrolment; an existing one shows what is stored.

| Field | What to enter |
|---|---|
| **Name** | the template name. It cannot be changed on an existing template: to rename one, create a new template and delete the old one |
| **Template OID** | the object identifier. Required, with **Name** |
| **Schema** | the template schema version: 1, 2, 3 or 4 |
| **Enroll**, **Auto-enroll** | whether clients may enrol and autoenrol |
| **Validity (days)** | how long certificates last |
| **Renewal overlap (seconds, -1 = derive)** | how long before expiry Windows renews. `-1` uses 42 days or half the validity, whichever is shorter |
| **Min key size** | the smallest key accepted |
| **Key spec** | `0` for a modern (CNG) key, `1` for a legacy CryptoAPI exchange key |
| **Key usage** | one box per key usage |
| **Major revision**, **Minor revision** | the template version Windows compares |
| **Private-key flags**, **Subject-name flags**, **Enrollment flags**, **General flags** | one box per Microsoft flag, named as in the Windows template console. A template imported without Enrollment or General flags shows no box ticked, and keeps them absent unless you tick one |
| **Public-key algorithm** | RSA, ECDSA P-256/P-384/P-521 or ECDH P-256; fills in **Public-key OID** |
| **Hash algorithm** | sha256, sha384, sha512 or sha1; fills in **Hash OID** |
| **Crypto providers** | provider names separated by `\|` |
| **EKUs** | purposes, as names or dotted OIDs, separated by `\|` |
| **Private-key permissions (SDDL)** | an access rule for the private key, or empty |
| **Enabled** | whether the template is offered |

Press **Save template**. Emptying a text field (EKUs, providers, SDDL) clears the stored value.
**Clear** puts the default values back, keeping the name of a template you are editing.

**Import from AD (CSV)** takes a comma-separated list. Press **Download CSV template** for the
exact format: the first line names the columns (`name` and `oid` are required; the others are the
editor's fields), list values are separated by `|`, and values must not contain commas. It is
FastPKI's own format; a raw export from Active Directory does not fit it. Press **Import CSV**.
Templates with the same names are replaced. Command line: `cfg templates-import <file.csv>`.

**Import from AD (LDAP)** reads the templates straight from every enabled directory (§7.2), using
its search account. Tick the templates to import — `overwrites` marks one that already exists
here — and press **Import N selected**.

**Deleting:** tick templates and press **Delete selected**. Command line:
`cfg templates-delete <name>`. `cfg templates-list` lists the templates of your own, marking the
disabled ones; when none is enabled, the built-ins are offered.

### 8.4 The Domains page

The approved domains are the DNS names certificates may carry. A certificate's CN and every DNS
alternative name must equal an approved domain or end in `.` followed by one. `example.org`
therefore allows `example.org` and `www.example.org`. A name without any dot is always allowed, and
a wildcard name only when the profile allows wildcards. Matching is case-sensitive, and an entry
like `*.example.org` is not a wildcard — `example.org` already covers everything under it.

**An empty list means no restriction at all**, not "nothing allowed". The console, EST, CMP, SCEP
and MS each log `policy: NO approved domains configured — issuance is UNRESTRICTED by domain name`
at start in that case.

To add a domain, type it under the list and press **add domain**. To remove, tick domains and press
**Delete selected**. The console applies a change to its own requests at once; **restart EST, CMP,
SCEP and MS** for them to see it (§1.5). The list replicates to every data center.

**From the command line:**

```bash
cfg domains-list
cfg domains-add example.org corp.example
cfg domains-remove old.example
cfg domains-import domains.txt      # one domain per line
```

---

## 9. Client configs

This page offers four files that point a client straight at this deployment:

| Button | File | For |
|---|---|---|
| **CMP config** | `fastpki-cmp.cnf` | `openssl cmp` |
| **ACME config** | `certbot-cli.ini` | certbot |
| **MS enrolment file** | `fastpki-request.inf` | Windows `certreq` |
| **SCEP enrolment script** | `fastpki-scep-enroll.sh` | `sscep` |

Each file is built from the current settings (addresses, ports, paths) and the downloading user's
own enrolment credentials. Users get the same files from their Dashboard (§2).

**For CA** chooses the CA the files enrol against; it lists the CAs that can issue on this node and
are not roots. The Dashboard has the same choice.

**✎ Edit** (for `admin`, when writes are allowed) stores your own version of a file. The editor
shows the stored version, or the generated one with its values replaced by tokens. Tokens are
filled in at every download, so a stored file stays correct when settings change:

| Token | Becomes |
|---|---|
| `{{CMP_URL}}`, `{{ACME_DIRECTORY}}`, `{{SCEP_URL}}`, `{{XCEP_URL}}`, `{{WSTEP_URL}}` | the enrolment addresses |
| `{{BASE_URL}}`, `{{PKI_DNS}}` | the public address and name |
| `{{CMP_RA_CN}}` | the name of the CA's CMP RA certificate |
| `{{CMP_KID}}`, `{{CMP_SECRET}}`, `{{ACME_EAB_KID}}`, `{{ACME_EAB_HMAC}}`, `{{SCEP_CHALLENGE}}` | the downloading user's credentials |

The **Substituted tokens** list shows the current values. **Save** stores the text; **Revert to
generated** deletes the stored version; **Download preview** downloads the text in the editor, saved
or not, with its tokens filled in for the CA chosen on the page. Stored versions apply in every data
center.

There is no command-line equivalent.

---

## 10. Endpoints

The Endpoints page shows every service this node runs: where it listens, the address clients use,
whether it answers, and the switches to turn it off or restart it.

### 10.1 The table

| Column | Shows |
|---|---|
| **Health** | ✓ answering, ✗ not answering (hover for the error and time), – not checked |
| **On** | the on/off switch and **restart** button, or a label (below) |
| **Protocol** | EST, ACME, CMP, SCEP, OCSP, CRL, MS-XCEP, MS-WSTEP, Store, Web Console, PostgreSQL |
| **External URL** | the address clients use, from `BASE_URL`, or `PKI_DNS` and the port |
| **Advertised in certs** | for OCSP and CRL: the address written into certificates |
| **Listener** | the address and port the service binds to |
| **Path** | the path under that address |

The values shown are those the services will use after their next restart.

**↻ Recheck** checks again whether each service accepts a connection. The console and PostgreSQL
are not checked. The check is made by the console itself, so it connects the way the console
reaches each service, not the way clients do:

| Deployment | The console connects to |
|---|---|
| Docker Compose | each service by its container name (`est`, `acme`, `cmp`, `scep`, `ocsp`, `ms`, `store`), which Docker's own name service resolves on the deployment's network |
| Kubernetes | each service by its Kubernetes Service name (`fastpki-est`, `fastpki-acme`, …), resolved by the cluster's DNS |
| Native install and cloud images | this host (`127.0.0.1`), or the service's listen address when it listens on one address only |

A ✓ therefore means the service accepts connections on its port. It does not prove that clients
can reach the **External URL**; that goes through your load balancer, firewall and DNS.

### 10.2 Switching a protocol off and on

The **On** column shows one of:

| Shown | Meaning |
|---|---|
| blue **on** and **restart** | the protocol is on |
| red **off** | an administrator switched it off. The service keeps running but does not open its port |
| **not installed** | the protocol was not chosen at installation, so there is nothing to switch |
| **restart** only | the Web Console, which cannot be switched off from itself |
| – | **CRL** and **MS-WSTEP**, which are second addresses of the service on the row above them (hover to see which), and PostgreSQL |

One service serves two addresses in two cases, and each keeps a row per address because clients
use them separately: the OCSP service also serves the CRL, and the MS service serves both
MS-XCEP and MS-WSTEP. The switch and **restart** are on the first row only (OCSP, MS-XCEP), and
switching it off stops both addresses.

Press **on** to switch a protocol off; confirm. The confirmation names every address that stops.
It stops serving within about 10 seconds and its port stays closed until you press **off** to
switch it back on, which takes effect within 10 seconds with no restart.

This relies on the service manager restarting a service that exits normally, which every shipped
deployment does. **From the command line:** `cfg set EST_ENABLED false` (or `true`); the same
`<PROTOCOL>_ENABLED` setting the switch writes.

A **not installed** protocol is added by installing it. On Docker Compose, edit `.env`: add its
profile to `COMPOSE_PROFILES` and set its installed line to true (for EST, `EST_INSTALLED=true`),
then run `docker compose up -d`, which records it so the page shows it. On a native install, re-run
`install-native.sh` and choose it.

### 10.3 Restarting a service

Press **restart** beside a protocol and confirm. The service stops within about 10 seconds and
comes straight back; the page reloads after 12 seconds. Do this after changing a setting it reads
or giving it a new certificate.

**restart** on the Web Console row restarts the console itself. It is unreachable for a few
seconds; the page reconnects by itself and you stay signed in.

The command-line equivalents are in §1.5.

### 10.4 Editing an endpoint setting

Above the table, **Edit an endpoint setting** changes one of the address, port and path settings
these services use: choose the **Key**, type the **Value**, and press **Set**. The change is saved
to this node's settings and applies when the service restarts (§10.3). `PG_CONNINFO` is in the list
but cannot be changed here; it is set at installation, in `bootstrap.conf` or the service's
environment, and never in the database.

A `…_BIND` setting takes an address only, and a `…_PORT` setting a number from 1 to 65535.

---

## 11. Settings

The Config page shows every setting the console knows about, with its current value and a
description, and lets `admin` change them. Settings are stored in each data center's own
database and are not copied to other data centers. The meaning of each is in
[config-reference.md](config-reference.md).

### 11.1 Where a setting's value comes from

Each service starts from its `bootstrap.conf` file (and environment variables), then applies the
values stored in the database on top. So a value set here wins over the file, and editing the file
does not change a value set here. The one exception is `PG_CONNINFO`, the database connection,
which is never read from the database.

### 11.2 The page

The **area** buttons (Identity, Certificate Authority, Database, Authentication, Web Console, …)
show one group of settings; **All** shows them all. The search box searches every area.

| Column | Shows |
|---|---|
| **Area** | the group |
| **Setting** | the setting's name |
| **Value** | the value; `(set)` or `(not set)` for passwords and secrets, which are never shown |
| **Description** | what it does |

A value marked **pending restart: est, cmp …** was changed after those services last started, so
they still run the old value. Restart them (§10.3). **pending restart (unset)** means the value was
removed and those services still use it. A service switched off on the Endpoints page is not
counted: it reads the current value when it is switched on.

A red banner **These are not your settings** means the stored settings could not be read, and the
page is showing the values the console started with. The banner names the setting at fault. Fix or remove that
setting from the command line (`cfg unset <KEY>`), then reload.

### 11.3 Changing one setting

Under **DB config overlay**, choose the setting in **Key** — its description appears — type the
**Value**, and press **Set**. The value is checked before it is saved; for example a port must be a
number from 1 to 65535. Secrets are typed in plain text here.

To remove a value you set, press **unset** on its row. The service goes back to the value in
`bootstrap.conf`, or to the built-in default, when it restarts.

Some settings are not in the Key list (for example the login and key-type settings). Add them
through the file editor, or with `cfg set`.

### 11.4 Editing all settings as a file

**✎ Edit full config file…** opens every setting as one text file, one `KEY=value` per line, grouped
by area. The first time, a comment marks each value that differs from `bootstrap.conf`; after you
save, your own text and comments are kept, with the values refreshed.

- Change a value, add a line, or delete a line to remove the stored value. Lines starting with `#`
  are comments.
- A secret typed here is stored as the setting, and kept in the file text as `(set)`. A secret left
  as `(set)` keeps its value.
- **Save** stores the changes and says how many values were set and removed. **Save & Restart** also
  restarts the console. Other services still need their own restart.

If `bootstrap.conf` changed on disk after the console started, the dialog says so when it opens, and
**Save** asks before writing the older values back over it. To keep the file's values instead,
cancel and restart the console.

### 11.5 From the command line

```bash
cfg list                           # the values stored in the database (secrets hidden)
cfg get PG_TLS_CA_ID               # one stored value; says "not set" when none is stored
cfg set PG_TLS_CA_ID issuing-ca    # store a value (no checking)
cfg unset PG_TLS_CA_ID             # remove a stored value
cfg export > settings.conf         # every stored value, secrets included
cfg import settings.conf           # store every KEY=value line in the file
```

`cfg get` shows only a value stored in the database, not one that comes from `bootstrap.conf`.
`cfg set` does not check the value, so double-check what you type. The file editor's own text is
stored in the database too: `cfg list` shows only its line count, and `cfg export` and `cfg import`
leave it out.

**If a setting locks you out of the console**, `cfg` still works, because it needs only the database:

```bash
cfg get WEB_CLIENT_CA_ID
cfg unset WEB_CLIENT_CA_ID
docker compose restart web          # or the restart command for your deployment
```

---

## 12. Watching the deployment

### 12.1 The audit log

Every issuance, revocation, setting change, sign-in and failed sign-in is recorded in the audit log:
by EST, ACME, CMP, SCEP, MS and the console. Each entry is linked to the one before it by a hash, so
changing, removing or reordering an entry breaks the chain, and `fastpki-audit verify` shows where.
Each node keeps its own log; it is not replicated.

**The Audit log page** lists the newest 500 entries, newest first:

| Column | Shows |
|---|---|
| **#** | the entry's sequence number |
| **Time** | when it happened (UTC) |
| **Category** | `auth`, `pki_lifecycle`, `config` or `key_mgmt` |
| **Action** | what happened, for example `web_login_fail` or `web_cert_revoked` |
| **Actor** | who did it; a `computer` label marks a machine account |
| **Status** | `success` or `failure` |
| **Target** | what it was done to |

The search box searches the loaded entries, including the details and source address that the table
does not show. For older entries use the command line. A role limited to certain CAs sees an empty
log: the audit log is for the whole node.

**⬇ Download signed audit export** downloads the whole log (`audit-export.ndjson`) and a signature
file (`audit-export.ndjson.sig`) made with a CA key, for an auditor. It needs `ca:read` as well as
`audit:read`. When more than one CA on this node can sign, it asks which one; roots, revoked, expired
and disabled CAs are not offered. Verify the export later with that CA. The export is refused if the
chain is broken.

**From the command line.** `--ca` must name an issuing CA whose key is on this node, never the
root:

```bash
audit verify --ca issuing-ca                       # check the chain and the latest checkpoint
audit sign --ca issuing-ca                         # record a signed checkpoint of the current end
audit export 0                                     # print every entry, oldest first
audit export-signed --ca issuing-ca --out report.ndjson
audit verify-export --ca issuing-ca --out report.ndjson   # check an export (reads the CA from the database)
```

Each command exits with an error when a check fails, so it can run from a scheduler.
**Schedule `sign` hourly and `verify` daily**: the chain alone cannot show that its newest entries
were cut off, and a signed checkpoint can. Nothing schedules them for you.

**Forwarding to a SIEM.** Set `AUDIT_FORWARD` to `syslog` or `hec` and `AUDIT_FORWARD_TARGET`, then run
the forwarding service: the `auditfwd` Compose profile, `AUDITFWD_ENABLED=true` on Kubernetes, or the
`fastpki-auditfwd` service on a native install. Run exactly one per node. The settings are in
[config-reference.md](config-reference.md).

### 12.2 Expiry notifications

**The Notifications page** previews what the expiry notifier would report: valid certificates that
expire within the largest warning window, grouped as `expired`, `critical` (within the smallest
window), `warning` and `info` (only within the largest). Each row shows the CN, serial, owner, expiry
date, days left and severity.

The form above the table stores three settings:

| Field | What to enter |
|---|---|
| **Warning windows (days)** | the windows, such as `30,14,7` (`NOTIFY_DAYS`) |
| **Webhook** | the address the notifier posts its report to (`NOTIFY_WEBHOOK`). There is none by default: without one the notifier only prints its report. Once set it shows as *(set)*; leave the field empty to keep it, or press **Remove webhook** to delete it |
| **Format** | what the receiver accepts (`NOTIFY_WEBHOOK_FORMAT`): **JSON** for a generic receiver such as a script, Jira Automation or ServiceNow; **Slack** for a Slack incoming webhook; **Microsoft Teams** for a Teams workflow ("post to a channel when a webhook request is received") or incoming webhook |

Slack and Teams refuse the JSON report, so choose their format for them. A Slack or Teams message
shows the counts per severity and up to 50 certificates. Treat the webhook address as a password:
whoever has it can post to the channel. The page never shows it. The preview follows
a saved change straight away.

**Emailing each certificate's owner.** With a mail relay set, the notifier also emails the person
who owns each certificate. The page's **Email** section stores the relay:

| Field | What to enter |
|---|---|
| **SMTP server** | the relay, as `host` or `host:port`, such as `mail.example.org:587` (`SMTP_SERVER`). Empty means no email |
| **TLS** | **STARTTLS** for a relay that upgrades a plain connection, usually on port 587; **TLS from the start** for one that expects TLS from the first byte, usually on port 465; **None** for an internal relay that speaks no TLS, usually on port 25 (`SMTP_TLS`). With STARTTLS, a relay that does not offer it is refused and nothing is sent. With either TLS choice the relay's certificate and name are checked |
| **User** and **Password** | the account the relay signs the notifier in with (`SMTP_USER`, `SMTP_PASSWORD`). Leave both empty for a relay that accepts this server without signing in. With **None** they must be empty: signing in without TLS would send the password unencrypted, so the page and the notifier refuse it. A stored password shows as *(set)*: leave the field empty to keep it, or press **Remove password** |
| **From** | the sender address (`SMTP_FROM`). Required |
| **Relay CA file** | a PEM file on this server holding the CA that issued the relay's certificate, when the system does not already trust it (`SMTP_CA_FILE`). Not used with **None** |
| **Fallback address** | where emails go for certificates whose owner has no address, such as the PKI team's mailbox (`NOTIFY_EMAIL_FALLBACK`). Empty: those certificates are only in the report |

Press **Save**, then type an address beside **Send test email** and press it. It sends one message
through the saved settings and says whether the relay accepted it, or why not. The relay settings
are stored on this server only, so set them on each data center.

An owner's address comes from, in this order:

1. For a directory account, such as `corp\alice`: its `mail` attribute in that directory.
2. The **Email** field of the account on the Users page (§6.4). Users can set their own, and a SAML
   or OIDC account's is filled from its provider each time it signs in.
3. Otherwise the fallback address. Computer accounts usually have no address, so their certificates
   go there.

What is sent, and when:

- **One email per owner per run**, listing each of their certificates that needs attention.
- **Once per window.** A certificate is included once when it enters each warning window and once
  when it expires, so with windows of `30,14,7` its owner hears about it at most four times. A
  delivery the relay refuses is tried again at the next run.
- **Not about a certificate already replaced**: one whose owner holds a newer valid certificate with
  the same subject and the same names, which is what an automatic renewal leaves behind. The page
  marks such a certificate *(replaced)*.
- **Each data center emails only about the certificates it issued**, so an owner is not emailed once
  per data center. A standby server sends nothing; its primary does.
- Certificates found by discovery are never emailed.

**The email template.** The **Email template** section edits the message. The template is shared by
every data center.

| Field | What it is |
|---|---|
| **Subject** | the subject line |
| **Each certificate** | the line written for each certificate |
| **Body** | the message. It must contain `{{certificates}}`, where the lines go |

In the subject and body, `{{owner}}` is the owner (in an email to the fallback address, every owner
it covers), `{{count}}` the number of certificates, `{{severity}}` the most urgent of them and
`{{days}}` the warning windows. In each certificate's line, `{{name}}` is its CN (or subject),
followed by `{{severity}}`, `{{serial}}`, `{{ca}}`, `{{expires}}` (a date), `{{when}}` (such as
*in 5 day(s)*), `{{days_left}}` and `{{owner}}`. A misspelt placeholder appears in the email as typed.
Press **Save template**; **Reset to built-in** returns to the shipped text.

**The notifier does not run by itself.** Schedule `fastpki-notify` daily. It uses the windows,
webhook, format and email settings stored on this page; `--days`, `--webhook` and `--webhook-format`
on its command line override them for that run:

```bash
# Docker Compose, from the host's crontab (run from the deploy folder)
0 7 * * *  cd <deploy folder> && docker compose run --rm --no-deps --entrypoint fastpki-notify web \
             --config /app/config/bootstrap.conf

# Native: /etc/periodic/daily/fastpki-notify (make it executable)
#!/bin/sh
su -s /bin/sh fastpki -c 'fastpki-notify --config /etc/fastpki/bootstrap.conf'
```

Without a webhook or a relay it only prints its report. A delivery that the receiver or the relay
does not accept makes the run exit with status 1. `--dry-run` prints what would be posted and who
would be emailed, and sends and records nothing; `--no-email` skips the emails;
`--test-email <address>` sends one test message and exits. `--json` prints the report for a monitoring system,
`--fail-on critical` exits with status 3 when there is anything at that level or worse, and
`--include-discovered` adds certificates found by discovery (§12.3). It groups certificates exactly as
the page does.

### 12.3 Discovery

Discovery connects to network addresses, records the certificate each one serves — including
certificates from other CAs — and flags the risky ones: `expired`, `expiring` (under 30 days),
`weak_key`, `weak_sig` and `self_signed`.

**The Discovered page** lists the newest 100 findings: endpoint, subject, key, signature algorithm,
expiry and flags. Click a row for the details and the full certificate. Every scan adds new rows; there
is no delete. Roles holding `ca:manage` see the page; a role limited to certain CAs is refused,
because the findings belong to the whole deployment.

**🔍 Scan for certificates** (roles holding `*:*`) takes up to 64 targets, one per line or separated
by commas: `host:port`, or a network such as `192.0.2.0/24:443` (no larger than a /16). Without a
port, 443 is used. Press
**Scan**; the page waits until the scan finishes and then says how many certificates were found and
flagged and how many targets did not answer. When nothing answered, the dialog stays open and says
so. A target the scanner refuses, such as a network larger than a /16, is reported as an error.

**From the command line.** Run `fastpki-discover` the way §1.4 runs a tool on your deployment;
the paths below are a native install's:

```bash
fastpki-discover --config /etc/fastpki/bootstrap.conf 192.0.2.0/24:443
fastpki-discover --config /etc/fastpki/bootstrap.conf --targets targets.txt --json
```

Schedule it to keep the findings current.

### 12.4 Compliance

The Compliance page lists certificates in the inventory that need attention: `weak_key` (RSA under
2048 bits or EC under 256), `weak_sig` (SHA-1 or MD5 signature), `expired`, and `expiring_soon`
(within 30 days). The line above the table gives the totals. Unlike the Inventory page, it includes
CA certificates and replaced service certificates. Revoked certificates are left out. A role holding
`cert:read` sees the certificates it may read — a `requester` its own. There is no command-line
equivalent.

### 12.5 Replication

The Replication page (for `admin` only) shows every host of the deployment: both hosts of an HA
pair, and on a mesh the other data centers too. Behind a load balancer the page is served by
whichever host the balancer picked, and one host cannot look into another's token. So each host's
console reports on its own host about once a minute, and the page shows every report. It names
the host that served it.

**Warnings** come first. Each one names a host and says what is wrong. The page warns about:

- a host that has not reported for more than five minutes;
- on a pair:
  - `PG_BIND` not set;
  - a `PG_CONNINFO` naming only one database host, or listing the other host first once this
    host's own database certificate verifies;
  - a database certificate a host's services cannot verify;
  - token-transport certificates a host has not published;
  - a CA key or OCSP/CMP/SCEP key missing from a host's token, or created without **replicable
    key** where another host lacks it;
  - `PG_TLS_CA_ID` not set;
  - no standby streaming, or a standby more than a minute behind;
  - a failed key sync;
- on a mesh: a subscription that is disabled, not running, recording errors, or silent for more
  than ten minutes.

A subscription's error counts are **lifetime totals** — PostgreSQL counts them from when the
subscription was created and clears them only on `pg_stat_reset_subscription_stats()` — so the
warning says whether they are still rising. One that is says replication from that data center is
failing now and points at this node's PostgreSQL log; one that is not names how long the count
has stood still, which is how a fault fixed hours ago reads as history instead of an alarm. Both
hosts of a pair report the same counters, because a standby is a physical copy of the primary's
catalogue, so this warning is stated once per data center rather than once per host.

[high-availability.md](high-availability.md) explains each HA item.

The tables below them:

| Table | Shows |
|---|---|
| **Hosts** | each host's data center and role (primary, or the host it follows), when it last reported, the hosts in its `PG_CONNINFO` and the one it is connected to, whether each database host presents a certificate its services accept, whether it published its token-transport certificates, and its last key sync |
| **Streaming replication** | each standby as its primary sees it: state, synchronous or not, and how far behind it is |
| **Replication slots** | the primary's slots, whether each is in use, and how much WAL it holds back |
| **Key copies** | for every CA and every OCSP/CMP/SCEP credential, whether each host's token holds a key under that key's name, and whether a key that is there can be copied (`not replicable` if not). The page reads the token's list of objects. It does not load the keys, so it cannot tell a key the certificate does not certify from the right one. **Sync keys now** makes that check and replaces a key that does not match |
| **Mesh subscriptions** | each host's subscriptions to other data centers: enabled, running, last message, error counts |

The standby's details need a database role that may read them. Compose and Kubernetes connect as
a superuser, and the native installer grants `pg_read_all_stats`, so nothing needs doing. For a
database set up by hand, grant it once on the primary. This is a PostgreSQL that FastPKI did
not install, so there is no image wrapper: run it against that database as a database
superuser.

```bash
psql -d fastpki -c 'GRANT pg_read_all_stats TO fastpki'
```

On a mesh, do this on each data center. Without the grant the page says so, and leaves those
columns empty.

**Sync keys now** has the last column of the Hosts table to itself, so it is in the same place on
every row. It appears on the row of every host with `P11_TLS=on`. It copies every key that host is
missing from the other hosts of its data center — a primary as well as a standby, because a key is
created on whichever host served the form or ran the job that created it. That is the same key
sync every host's nightly job runs (high-availability.md §3), started now instead of tonight. The
request is recorded; that host's own console starts it within about 15 seconds, whichever host
served your page. The row shows it as requested, then running, then the result, with the output
behind **output**. Keys that were created without **replicable key** fail, and the output says
what fixes each one.

On Kubernetes each server pod is a row of its own, named `fastpki-node-0.fastpki-node`,
`fastpki-node-1.fastpki-node` and so on ([deployment.md](deployment.md) §8.5).

---

## 13. Backup and restore

### 13.1 What to back up

A FastPKI deployment is three things, and a backup needs all three:

| What | Where | Lose it and … |
|---|---|---|
| **The token** — every CA private key | the `softhsm-tokens` volume on Docker Compose with the bundled SoftHSM; your HSM otherwise | no CA can ever sign again. There is no recovery. Back it up by your HSM vendor's procedure; for SoftHSM, back up the volume. Some HSMs cannot export keys at all — decide before a CA goes into production |
| **The database** — certificates, CAs, users, roles, settings, audit log | PostgreSQL | everything FastPKI knows. See [postgres.md](postgres.md) |
| **The node's own files** — `bootstrap.conf` (with the database password), `.env` on Docker Compose, the token PIN file, the PostgreSQL TLS files, and any Kerberos keytab uploaded for a directory (`/var/pki/ms/`) | the host or its volumes | the node cannot start or reach its database and token, and Windows Kerberos enrolment fails |

On top of those, the **config backup** (§13.3) is a small copy of the settings and management tables —
useful when someone deletes a role or a template.

Practise a restore on a spare machine.

### 13.2 The Backup page

| Button | Does |
|---|---|
| **⬇ Config backup** | downloads a config backup (§13.3) |
| **⬆ Restore config** | loads a config backup into this node (shown when writes are allowed) |
| **⬇ Database backup** | downloads a full database dump |
| **⬆ Restore database** | replaces this node's whole database with a dump (shown when writes are allowed) |
| **How to restore a database** | where the command-line restore steps are, and how to decrypt a file first |

**Creating a backup.** Both download forms have one field, **Passphrase**. With a passphrase the file
is encrypted (AES-256-GCM, with the key derived from the passphrase) and ends in `.fpkibak`; without
one it is plain (`fastpki-backup.json` or `fastpki-db.sql`). The passphrase is not stored anywhere:
lose it and the backup is lost. Every download is recorded in the audit log, encrypted or not.

A database backup contains the database passwords of any replication links, so encrypt it or keep it
as carefully as a password. It does not contain replication subscriptions, so restoring one never
starts replication by itself. It can take a while on a large database.

**Restoring a config backup.** Choose the **Backup file** (`.json` or `.fpkibak`), type the
**Passphrase** if it is encrypted, press **Restore** and confirm. Rows in the file are added or
overwritten: settings, console accounts, CAs, roles with their permissions and issuance limits, role
assignments and templates. A role in the file gets exactly the permissions the file lists. Nothing
missing from the file is deleted. The result appears in the dialog. The usual target is a fresh
installation. The file may be at most **64 MB**.

**Restoring a database backup.** Choose the file and passphrase, press **Restore database** and
confirm. This **replaces every certificate, user, CA and audit entry on this node** with the dump. It
happens in one transaction: a good dump is restored completely, and a bad one changes nothing. You may
be signed out, and services may report errors while it runs. The file may be at most **64 MB**; for a
larger dump, use the command line (§13.5). **On a data center in a mesh the restore is refused**:
there the other data centers hold newer copies of most rows, and a restore takes them from
there — [postgres.md](postgres.md) §6.3.

### 13.3 What each backup contains

| Data | Config backup | Database backup |
|---|---|---|
| Settings stored in the database | yes | yes |
| Certificate profiles: those you added, and built-ins you edited | yes | yes |
| Console accounts, with password hashes, email addresses and how each signs in | yes | yes |
| The expiry email template, if you edited it | yes | yes |
| CAs: certificates and key locations (never the keys) | yes | yes |
| Roles, their permissions and issuance limits, and role assignments | yes | yes |
| MS templates, disabled ones included | yes | yes |
| Approved domains, directories and SSO providers, enrolment credentials, client configs, foreign CAs, XCEP endpoints | no | yes |
| Issued certificates, CRLs, audit log, ACME accounts, sessions, which expiry emails were sent | no | yes |
| CA private keys | no | no — they are in the token |

The config backup holds every account's password hash. Only `backup:manage` (the `admin` role) can
create or restore one; keep the file safe.

### 13.4 Backups from the command line

**Config backup** (the file is created readable by its owner only):

```bash
# Docker Compose: mount a host folder so the file survives the throwaway container.
# The folder must be writable by the container's fastpki user.
docker compose run --rm --no-deps -v /backup:/backup --entrypoint fastpki-config web \
    --config /app/config/bootstrap.conf backup --out /backup/fastpki-config.json

# Native
cfg backup --out /backup/fastpki-config.json
```

Restore it with `restore /backup/fastpki-config.json` in place of `backup --out …`.

To encrypt, put the passphrase on the first line of a file readable only by you and add
`--passphrase-file <file>`: `backup --out /backup/fastpki-config.fpkibak --passphrase-file /backup/pass.txt`.
The result is the same format the Backup page downloads, so either can restore it. `restore` takes the
same option for an encrypted file.

**Decrypting a file downloaded from the Backup page**, for example an encrypted database dump you want
to restore from the command line:

```bash
cfg decrypt-backup /backup/fastpki-db.sql.fpkibak --passphrase-file /backup/pass.txt \
    --out /backup/fastpki-db.sql
```

`decrypt-backup` does not use the database, so it works while the database is being rebuilt. The
decrypted file is created readable by its owner only; delete it when the restore is done.

**Database dump:** the commands for each deployment are in [postgres.md](postgres.md) §5.1.

### 13.5 Restoring from the command line

- **One host, a stop-and-restore:** [postgres.md](postgres.md) §6.1. It stops every service that uses
  the database, recreates it, loads the dump in one transaction, and starts everything again.
- **An HA pair, without downtime:** [postgres.md](postgres.md) §6.2, which restores onto the standby
  and switches over.
- **A data center in a mesh:** [postgres.md](postgres.md) §6.3.

After restoring the database onto a new machine, restore the token and the node's own files too
(§13.1); a database whose CA keys are missing lists every CA and can sign with none.

---

## 14. Updating FastPKI

### 14.1 The Version page

The **Version** page shows the running version. **Check for updates** asks the release feed (GitHub's
latest release, or `UPDATE_FEED_URL`) whether a newer version exists, and shows its release notes and
download link. The check is made by the server, so the server needs outbound HTTPS. If the feed cannot
be read — including a GitHub repository this host cannot see — the page says the check failed.

The page does not install anything. Follow the steps below for your deployment.

**From the command line:** `fastpki-update version`, and `fastpki-update check`, which exits with 10
when an update is available, 0 when up to date and 1 when the check failed. To check a downloaded
release against the published signing key:
`fastpki-update verify <file> <file>.sig --pubkey <release-key.pem>`.

### 14.2 Before any update

1. Read the release notes.
2. Take a database backup and a config backup (§13).
3. Plan the order. **The database schema is always updated before the programs**: a program refuses
   to start against a schema older than it needs, and says which command to run. The update scripts
   below do this for you.

### 14.3 Docker Compose

1. Get the new image:
   - **From a registry:** set `FASTPKI_IMAGE` in `deploy/.env` to the new tag, then
     `docker compose pull`.
   - **Built on this host:** update the source tree to the new release, then from its top folder run
     `IMAGE=fastpki:local sh deploy/build-image.sh`.
2. Update the database schema and replace the services one at a time:

   ```bash
   cd deploy
   FASTPKI_IMAGE=<the new image> ./rolling-update.sh
   ```

   The script applies any schema change first and stops if that fails, with nothing replaced. It
   then updates the token and the other helper services, and after them each protocol service in
   turn, checking each answers before moving on; a service that does not come back stops the update.
   Each service is briefly unavailable while its container is replaced, one at a time.

   With `RUN_LAB_TEST=1` the script finishes by running FastPKI's whole test suite against the new
   image. That takes hours and needs the `tests` folder of the source tree beside `deploy`, so it is
   for validating a release, not for a routine update.

Do not wipe any volume during an update. [deployment.md](deployment.md) §4.6 explains what each
volume holds.

### 14.4 Native install and the cloud image

A node started from the cloud image has no build tools, and often no internet access, so it is
updated from a package built somewhere else. Build that package first — *Building the package
for cloud nodes*, below — and copy it to the node. A native install needs no package: it builds
on the node itself.

On each node, as root:

1. Install the new programs and PKCS#11 components over the old ones:
   - **A native install**: put the new release's source tree on the node and run
     `sh deploy/native/build-native.sh`.
   - **A node started from the cloud image**: `tar xzf fastpki-native-<version>.tar.gz -C /`.
2. Run the installer again with the same answers:
   `fastpki-install-native --answers <your answers file>` — on a cloud node the file is
   `/root/fastpki-answers.env`. It keeps the existing database, token PIN, database password
   and console port, applies any schema change, and restarts the FastPKI services on the new
   programs. The services
   are unavailable for the few seconds of that restart. If the new release needs an Alpine package
   the node does not have, the installer stops before changing anything and names it; `apk add`
   it and run the installer again.

On a cloud node the services keep running on the old programs while the package is unpacked.

**Building the package for cloud nodes.** On any machine with Docker and a git checkout that
contains the release, on the same processor architecture as the nodes (an arm64 node needs a
package built on arm64):

```bash
sh deploy/native/build-check.sh --ref <release tag> --package fastpki-native-<version>.tar.gz
```

It builds in a throwaway Alpine container exactly as the cloud image is built, checks that the
patched PKCS#11 components and every program work, and packages the files that build installed.
The package holds no token and no configuration, so one package serves every node. Copy it to
each node, for example with `scp`.

Two of the patched libraries, `/usr/lib/libp11-kit.so.0` and `/usr/lib/pkcs11/p11-kit-client.so`,
replace files that Alpine's `p11-kit` and `p11-kit-server` packages install. So the build and the
installer hold both packages at the installed version in `/etc/apk/world`, and `apk upgrade`
leaves them alone; a newer p11-kit arrives with a FastPKI update instead. Removing the hold lets an
upgrade put the unpatched libraries back, after which CAs with Ed25519, Ed448 or ML-DSA keys stop
working.

### 14.5 Kubernetes

Set `IMAGE` to the new image and re-run `deploy/k8s/apply.sh`. It applies any schema change before
anything starts on the new image, on a mesh node too. To go back,
`kubectl -n fastpki rollout undo deploy/<name>`. See [deployment.md](deployment.md) §8.7.

### 14.6 An HA pair

Update the schema on the **primary only** — the standby receives it — then update the standby, switch
over, and update the other host. The steps are [high-availability.md](high-availability.md) §5a.

### 14.7 Several data centers

Update one data center at a time. The schema is updated **on every data center**, because each has its
own database; on a mesh node the schema step also needs the trigger generator (`MESH_BIN`) from the
new image, which `rolling-update.sh` arranges when given `FASTPKI_IMAGE` and `apply.sh` arranges
from `IMAGE`. The details are in
[deployment.md](deployment.md) §11.1.

---

## 15. When something goes wrong

| Symptom | Where to look |
|---|---|
| A service restarts over and over right after an update | the schema. Its log names the command to run; see [postgres.md](postgres.md) §4 |
| Sign-in always says **Invalid credentials** | the password. For a directory user, the directory's `base_dns` (§7.2) and whether the name is qualified |
| The console shows only the Dashboard | the user holds no role, or only `none` (§6.1) |
| A page's tab is there but the table is empty | a role limited to certain CAs is reading a page that covers the whole deployment (the audit log, discovery) |
| Every change is refused with `console writes disabled` | `WEB_ALLOW_REVOKE` is `false` (§1.3) |
| Enrolment returns 503 | the CA cannot sign: disabled, revoked, expired, or no key on this node. The message says which; check the CAs page |
| OCSP answers `internalerror`, or CMP refuses everything | the OCSP responder or CMP RA key or certificate is missing; the service's log says which (§5.4) |
| A browser warns about the console's certificate | the console still has its self-signed certificate, its certificate expired (§5.2), or the browser does not trust your root CA |
| Services cannot connect to the database with a certificate error | the PostgreSQL certificate expired; check `PG_TLS_CA_ID` (§5.5) |
| Issuance fails with a PKCS#11 error | the token: is the token service running, is `PKCS11_MODULE` the p11-kit client (not SoftHSM itself), is the PIN file readable. On a native install, run commands as the `fastpki` user (§1.4) |
| A CA is listed but cannot sign | its key is not in this node's token: the HSM keys page shows what the token holds |
| A remote client reports `unable to get certificate CRL` | the CRL address in the certificate names something that client cannot reach; see [deployment.md](deployment.md) §13 |
| A setting change has no effect | the service has not restarted (§1.5), or the value comes from `bootstrap.conf` and a stored value overrides it (§11.1) |
| A new MS template is not offered | it was saved without **Enabled** (§8.3), `fastpki-ms` was not restarted, or the Windows client's policy cache is stale |
| A certificate is refused with a `policy:` message | §4.7 |
| Owners get no expiry email | press **Send test email** on the Notifications page (§12.2), then run `fastpki-notify --dry-run`: it lists who would be emailed and names every owner without an address. A certificate already emailed at its current window, already replaced, or issued by another data center is counted and not sent |

### 15.1 Logs

| Deployment | Where |
|---|---|
| Docker Compose | `docker compose logs <service>` |
| Kubernetes | `kubectl -n fastpki logs fastpki-node-0 -c <service>` (and `fastpki-node-1` in a pair) |
| Native | `/var/log/fastpki/fastpki-<service>.log`, and `rc-service fastpki-<service> status` |

The default log level is `err`, so a healthy service writes almost nothing. When a service runs but
misbehaves, set `LOG_LEVEL` to `debug` (§11.3), restart it, and read its log again.
