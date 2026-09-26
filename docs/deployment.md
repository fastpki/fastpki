# FastPKI — Deployment Guide

This guide takes you from an empty machine to a FastPKI installation that issues
certificates over every protocol. It shows the **automated way**: the installer and the
one-command tools. Each step says what to run, what it does, what you see when it worked, and
what to do when it did not.

Every script here also has its steps written out one by one in
[Manual procedures](manual-procedures.md), for when you cannot run the script or need to
finish a step it reported as failed. You do not need that guide to install FastPKI.

**How to read the commands**

- A grey box is a command. Copy it and run it.
- Words in capitals, such as `A-ADDRESS` or `YOUR-CA-ID`, stand for your own values. Replace
  them before you run the command. They are written without `<>` because a literal `<name>`
  in a command makes the shell try to read a file called `name`.
- Each step says **where** to run it: on a server, or on your own computer.

**A few words used throughout**

| Word | What it means |
|---|---|
| **CA** (certificate authority) | the part of FastPKI that signs certificates |
| **root CA** | the top CA. Clients trust it. It signs only other CAs |
| **issuing CA** | the CA below the root. It signs the certificates that people, servers and devices ask for |
| **key store** (also called the **token**) | a protected place where FastPKI creates and keeps private keys. A key never leaves it as a file |
| **console** | FastPKI's web page for administrators, at `https://YOUR-NAME:8090` |
| **standby** | a second server that keeps a live copy of the first, and can take over if the first is lost |
| **data center** | one FastPKI installation: one server, or a server and its standby. Several data centers can copy their data to each other; together they are a **mesh** |

## Contents

| Section | |
|---|---|
| [**1. Architectures**](#1-architectures) | the ways you can run FastPKI |
| [**2. Components & ports**](#2-components--ports) | the services and where they listen |
| [**3. Quick start**](#3-quick-start) | install with one command |
| [**4. First run: bootstrap, then create the CA**](#4-first-run-bootstrap-then-create-the-ca) | create the CAs and finish the setup |
| [**5. Configuration**](#5-configuration) | where settings live, and which ones matter |
| [**6. First issuance (smoke test)**](#6-first-issuance-smoke-test) | prove that it issues certificates |
| [**6a. High availability: add a standby server**](#6a-high-availability-add-a-standby-server) | a second server that can take over |
| [**7. Native install — Alpine + OpenRC (no Docker)**](#7-native-install--alpine--openrc-no-docker) | install without Docker |
| [**8. Kubernetes**](#8-kubernetes) | install on Kubernetes |
| [**9. Multi-data-center**](#9-multi-data-center) | connect two or more data centers |
| [**10. TLS / reverse proxy**](#10-tls--reverse-proxy) | putting a proxy in front |
| [**11. Day-2 operations**](#11-day-2-operations) | running it after installation |
| [**12. Cloud deployment (AWS)**](#12-cloud-deployment-aws) | install on AWS |
| [**13. Troubleshooting**](#13-troubleshooting) | common problems and their fixes |

**Where to start.** One server: §3, then §4, then §6. A standby: §6a. More data centers: §9.
Something is broken: §13, or §9.6 when it is replication.

---

## 1. Architectures

FastPKI is a set of small services, one for each protocol: OCSP, EST, ACME, CMP,
MS-XCEP/WSTEP, SCEP, the RFC 4387 certificate store, and the web console. They share one
database and the CAs registered in it. There is no single program that runs everything; you
start the services you need, and the installers do that for you.

You can run them in four ways:

- with **Docker Compose** on one or more servers (§3) — the most common;
- directly on **Alpine Linux**, without Docker (§7);
- on **Kubernetes** (§8);
- on **AWS**, with the servers created for you (§12).

The published image works on both Intel or AMD processors (`amd64`) and ARM processors
(`arm64`); `docker pull` picks the right one. Both are also published under their own names,
`:<version>-amd64` and `:<version>-arm64`.

Every release also comes with a ready-built image file for each processor type, for a machine
that cannot reach `ghcr.io`:

```bash
docker load  -i fastpki-<version>-image-amd64.tar.gz   # or -image-arm64.tar.gz
docker image ls fastpki                                 # the name it loaded
```

⚠️ **The installer in §3.1 does not use an image you loaded.** A plain name such as
`fastpki:local` is always built from source, and a name containing `/` is always downloaded,
so a loaded image is replaced either way. To install from a loaded image, see
[Manual procedures §1](manual-procedures.md#1-installing-with-docker-compose-by-hand).

---

## 2. Components & ports

| Service | Program | What it does | Port | Uses HTTPS itself? |
|---|---|---|---|---|
| Web console | `fastpki-web` | the administrator's web page | 8090 | yes |
| OCSP and CRL | `fastpki-ocsp` | answers "is this certificate revoked?" | 8080 | no |
| EST | `fastpki-est` | enrolment for devices and servers | 8443 | yes |
| ACME | `fastpki-acme` | enrolment for web servers (certbot and similar) | 8444 | yes |
| CMP | `fastpki-cmp` | enrolment, renewal and revocation | 8445 | no |
| MS-XCEP / WSTEP | `fastpki-ms` | enrolment for Windows computers | 8446 | yes |
| Certificate store | `fastpki-store` | lets clients search for certificates | 8447 | no |
| SCEP | `fastpki-scep` | enrolment for network devices and phones | 8448 | no |

The console needs HTTPS because generating a key in the browser and choosing a slot in the key
store work only on a secure connection. The services on plain HTTP should sit behind your own
reverse proxy if they face the internet (§10).

**Command-line tools** in the same image, with no port: `fastpki-ca` (create and manage CAs),
`fastpki-config` (settings, backup and restore, and `web-user` for console logins),
`fastpki-audit`, `fastpki-notify`, `fastpki-update`, `fastpki-discover`, `fastpki-mesh`, and
`fastpki-mcp` (the certificate inventory for MCP clients). §5 shows how to run them on each
kind of installation.

---

## 3. Quick start

### Before you start: install Docker

The installer needs **Docker Engine** with the **Compose plugin**, and your user must be able
to run Docker without `sudo`.

1. Install Docker by following Docker's guide for your Linux:
   <https://docs.docker.com/engine/install/>.
2. Let your user run Docker:
   ```bash
   sudo usermod -aG docker $USER
   ```
3. **Log out and log in again.** The change only works in a new login.
4. Check that both commands run without an error:
   ```bash
   docker ps                 # prints an empty table header
   docker compose version    # prints a version number
   ```

If `docker ps` says `permission denied while trying to connect to the docker API`, step 2 or
step 3 is not done. The installer fails with the same message.

**What one server uses**, measured after ten minutes idle: 2 processors, sitting at 0% when
nothing is being issued; 165 MB of memory for all the containers together; 556 MB of disk for
the two images and 48 MB of data to begin with. [`architecture.md`](architecture.md#11-resource-footprint)
§11 has the same figures for the other ways of running FastPKI.

### 3.1 Guided — `./install.sh`

One command downloads the newest release, checks that it really comes from FastPKI, and
starts the installer:

```bash
curl -fsSL https://github.com/fastpki/fastpki/releases/latest/download/install.sh | bash
```

The installer asks a few questions and then does the whole installation: it prepares the
database, starts every service, and creates the first console user.

The download is checked before anything is unpacked: the signature on `SHA256SUMS` against
the FastPKI release key written into the script, then the release files against `SHA256SUMS`.
A missing or wrong signature stops the install. There is no option to skip the check.

Other ways to run it:

```bash
URL=https://github.com/fastpki/fastpki/releases/latest/download/install.sh
curl -fsSL $URL | bash -s -- --version <version>         # a pinned release, leading v included
curl -fsSL $URL | bash -s -- --k8s                       # Kubernetes: asks the §3.1 questions, writes k8s/env.local, runs k8s/apply.sh
curl -fsSL $URL | bash -s -- --k8s --non-interactive     # unattended, Kubernetes (§8)

# From a release tarball or a checkout, in its deploy folder:
./install.sh                          # interactive
./install.sh --answers node2.env      # answers from a file, no questions
./install.sh --no-deploy              # write .env only, and print the commands instead
./install.sh --answers node2.env --print-env   # write nothing, show the .env it would write
```

`--dir` chooses where the release is unpacked (default `./fastpki-<version>`). A release
tarball unpacks to `fastpki-<version>/`, so its installer is `fastpki-<version>/deploy/install.sh`.

Where there is no terminal, such as a provisioning script, an interactive run is refused
rather than taking every default: pass `--answers <file>` or `--non-interactive`.

**The questions that matter most:**

| Question | What to answer |
|---|---|
| **Deployment**: `single` or `cluster` | `single` for one data center — also the right answer if you will add a standby later, because the standby is set up on the other server (§6a). `cluster` only for several data centers; it then asks for this server's number, from 1 to 32767. That number goes into the serial number of every certificate this server issues, so two data centers can never issue the same serial. It is permanent |
| **Container image** (`FASTPKI_IMAGE`) | press Enter. Installed from a release, the default is that release's published image and it is downloaded in seconds. From a source checkout the default is `fastpki:local`, which is built on this server and is slow. A name containing `/`, such as `registry.example.org/fastpki:1.0`, is downloaded from that registry (§3.3) |
| **Public FQDN** (`PKI_DNS`) | the name clients use to reach this server, for example `pki.example.org`. It is written into every certificate as the address of the revocation list and the CA certificate, so it must resolve on every client, not only on this server. A CA keeps it for its whole life, so get it right before you create one (§4.3) |
| **Postgres publish address** (`PG_BIND`) | `127.0.0.1` on a single server. This server's own IP address if you will add a standby (§6a) or more data centers (§9): the other server connects to the database there, and the address is written into the database certificate |
| **Will this data center have a standby** (`HA_ENABLED`) | `yes` if a second server may ever take over from this one. It turns on the key tunnel (`P11_TLS=on`) so the standby can receive copies of the CA keys, and creates the OCSP, CMP and SCEP keys copyable (`SERVICE_KEYS_REPLICABLE=true`). Decide now: a key is copyable or not from the moment it is created. It needs `PG_BIND` set to this server's own address |
| **Key storage** | `softhsm` to use the key store that ships with FastPKI, `hsm` for your own hardware security module; it then asks for the absolute path of your vendor's PKCS#11 module and its token label (`PKCS11_TOKEN`, `fastpki` unless your HSM's owner labelled it otherwise) |

**Every server of a mesh is installed the same way**, answering `cluster` and changing only
three answers per server: its number (`DC_INDEX`), its own public name (`PKI_DNS`) and its own
address (`PG_BIND`). An answers file for server 2 is server 1's with those three changed:

```bash
printf 'DEPLOYMENT=cluster\nDC_INDEX=2\nFASTPKI_IMAGE=%s\nPKI_DNS=%s\nPG_BIND=%s\n' \
    registry.example.org/fastpki:1.0 pki-dc2.example.org 198.51.100.10 > node2.env
./install.sh --answers node2.env
```

⚠️ `PKI_DNS` and `PG_BIND` are **that server's own**, never a copy of server 1's.

**When the installer finishes**, go to §4.3.

### 3.2 Manual — Docker Compose

`install.sh` does this. To do it by hand, one command at a time, see
[Manual procedures §1](manual-procedures.md#1-installing-with-docker-compose-by-hand).

### 3.3 Several servers — build once, pull from a registry

Only if you build your own image. Build it once, push it to your own registry, and give its
name to the installer's **Container image** question on every server. Each server then
downloads it instead of building it.

On the build machine, from the top of the source tree:

```bash
IMAGE=registry.example.org:5000/fastpki:1.0 sh deploy/build-image.sh
docker push registry.example.org:5000/fastpki:1.0
```

Use `deploy/build-image.sh`, not a bare `docker build`: it runs the public-repository check
that the build itself cannot run.

On every other server, if the registry has no certificate those servers trust, allow it first:

```bash
echo '{"insecure-registries":["registry.example.org:5000"]}' | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker
```

Each server still runs its own installer, has its own database and key store, and gets its
own issuing CA (§4, and §9 for a mesh). **Updating these servers later** needs no CA work:
push the new image, set `FASTPKI_IMAGE` to it on each server, and run `./rolling-update.sh`
([`admin-guide.md`](admin-guide.md) §14.3).

---

## 4. First run: bootstrap, then create the CA

After the installer, FastPKI is running but has **no CA**, so it cannot issue anything yet.
§4.1 and §4.2 are already done. You start at §4.3.

| Step | Done by | What it is |
|---|---|---|
| 4.1 Transport certificate | the installer | a temporary certificate, so the database connection is encrypted from the start |
| 4.2 Bootstrap | the installer | prepares FastPKI's folders and creates the `admin` user |
| 4.3 Create the CAs | **you** | the root CA and the issuing CA |
| 4.4 Service certificates | **you** | certificates for OCSP, CMP, SCEP, the HTTPS services and the database |
| 4.5 First console admin | **you** | sign in as `admin` / `admin` and set a new password |

To check that 4.1 and 4.2 are done: open `https://YOUR-NAME:8090`. The console opens, with a
browser warning about its certificate, and `admin` / `admin` signs in and asks for a new
password.

### 4.1 Transport certificate: `deploy/certgen.sh` (automatic, already done by the installer)

Gives the database a temporary certificate signed by itself, so the connection between
FastPKI and its database is encrypted from the very first start. It writes the database's
certificate and key and the key store password (`/var/pki/tls/pin`), and never overwrites
files that exist. §4.4 replaces the certificate with one from your CA.

The console, EST, ACME and the Windows service do not get their certificate here. Each creates
its key in the key store when it first starts, signs itself a certificate valid for 90 days,
and saves it in the database. It reuses that certificate at every restart until §4.4 replaces
it.

### 4.2 Bootstrap: `deploy/bootstrap.sh` (automatic, already done by the installer)

Creates FastPKI's folders under `/var/pki`, and the first console account: user `admin`,
password `admin`, which must be changed at the first sign-in (§4.5). It creates no CA and
issues no certificate. PostgreSQL creates the database tables itself, from `sql/createdb.sql`,
the first time it starts.

To run §4.1 and §4.2 yourself, see
[Manual procedures §1](manual-procedures.md#1-installing-with-docker-compose-by-hand).

### 4.3 Create your CAs (you do this)

You create two CAs in the console: a **root CA**, the top of the trust chain, and an
**issuing CA** below it. Each CA's private key is created inside the key store and never
exists as a file.

**First, check three things:**

1. **The public name is right.** Every certificate a CA signs carries this server's name, in
   the addresses where a client fetches the revocation list and the CA certificate. Those
   addresses cannot be changed afterwards. The form shows them before you create the CA.
2. **Will you ever add a standby?** Then tick **replicable key** on *every* CA, the root
   included. It lets the key be copied into the standby's key store. It cannot be turned on
   afterwards: a key is copyable or not from the moment it is created, and a CA whose key is
   on one server only cannot be signed with after that server is lost. On a single server
   that will stay alone, leave it off: a key that cannot leave its key store is the safer
   choice.
3. **Will you have several data centers?** Then call the issuing CA `dc1-sub` instead of
   `issuing-ca`. The id is only a label, but §9 uses `dc1-sub`, `dc2-sub` and so on. On a
   mesh, also connect the data centers (§9.0 step 3) **before** you create a CA: every
   certificate names one address per data center known when it is issued, and a CA created
   before the others are known names only its own.

Open the console at `https://YOUR-NAME:8090`, sign in (§4.5), and go to the **CAs** tab.

**Step 1 — create the root CA.** Click **+ New CA** and fill in:

- **id**: `root-ca` — the short name that addresses and commands use
- **display name** and **CN**: a name such as `Example Root CA`
- **Parent CA**: leave it as **— none (root) —**
- **Algorithm**: **RSA**, **4096** bits. It works with every client; read
  [`compatibility.md`](compatibility.md) before you choose another one
- **replicable key**: tick it if you will add a standby
- **Key name**: `root-ca` — the key's name in the key store, which must not be in use
- **Validity**: leave empty for 10 years
- leave everything else as it is, and click **Create CA**

**Step 2 — create the issuing CA.** Click **+ New CA** again:

- **id**: `issuing-ca` (or `dc1-sub`, see check 3)
- **display name** and **CN**: a name such as `Example Issuing CA`
- **Parent CA**: the root CA
- **Algorithm**: **RSA**, **3072** bits
- **replicable key**: tick it if you will add a standby. This CA signs every certificate, so
  without it a standby cannot issue anything
- **Key name**: `issuing-ca`
- **Validity**: leave empty, or set **Not after** about 5 years ahead. It is shortened to the
  root's end date if it would outlive the root
- open **Advanced** and check the two addresses under **caIssuers** and **CRL DP**. They must
  contain your public name, for example `http://pki.example.org:8080/root-ca.crl`. If they
  do not, stop and fix the name first (`PKI_DNS` and `BASE_URL`, §5)
- click **Create CA**

**Step 3 — check.** The CAs tab lists both CAs as `active`, and the issuing CA's **Issuer**
shows the root's name.

**Step 4 — disable the root CA.** Click **Disable** on the root CA's row. It has done its job
of signing the issuing CA. Disabling stops it signing anything else; its revocation list,
OCSP answers and place in every chain keep working. Enable it again only for as long as it
takes to sign the next issuing CA. The stronger arrangement keeps the root's key off these
servers altogether and publishes its revocation list with `fastpki-ca import-crl`
([`admin-guide.md`](admin-guide.md) §3).

A CA renewed later with a new key is replicable only if you tick **replicable key** again in
the renewal form. A renewal that keeps the current key keeps its setting.

To create CAs from the command line instead, see
[Manual procedures §3](manual-procedures.md#3-creating-cas-from-the-command-line).

### 4.4 Service certificates: finish the setup (do this after §4.3)

Several services need a certificate of their own from your issuing CA before they work.
Until they have one, every container still looks healthy, so nothing else tells you:

| Service | What it needs | Until it has it |
|---|---|---|
| **OCSP** | a responder certificate, `ocsp-ra-<ca-id>` | every OCSP request gets `internalerror`. CRLs still work |
| **CMP** | an RA certificate, `cmp-ra-<ca-id>` | every CMP request is refused, with `no RA credential` in the log |
| **SCEP** | an RA certificate | SCEP enrolment fails |
| **Console, EST, ACME, MS** | a TLS certificate from your CA | clients and browsers warn about the temporary one |
| **PostgreSQL** | a database certificate from your CA | it keeps the temporary one from §4.1 |

On the server, in FastPKI's `deploy` folder:

**Step 1 — tell FastPKI which CA to use.** Replace `YOUR-CA-ID` with your issuing CA's id,
for example `issuing-ca`. `fastpki-ca list` prints the ids you have:

```bash
docker compose exec web fastpki-config set PG_TLS_CA_ID YOUR-CA-ID
docker compose exec web fastpki-config set CMP_CLIENT_CA_ID YOUR-CA-ID
```

`PG_TLS_CA_ID` is the CA that signs the database's certificate and keeps renewing it.
`CMP_CLIENT_CA_ID` is the CA whose certificates CMP accepts from clients; without it CMP
refuses every signed request, so a client cannot renew or revoke its own certificate. Neither
is guessed.

**Step 2 — issue every service certificate in one command:**

```bash
docker compose exec web fastpki-ca renew-service-certs --create-missing --re-issue-self-signed --replicable
```

⚠️ **Decide `--replicable` now.** This run creates the OCSP, CMP and SCEP keys. Keep the flag
if you have or will have a standby; remove it on a server that will stay alone. A key created
without it can never be copied, and a later run keeps the key it finds.

It creates the OCSP, CMP and SCEP certificates for every issuing CA, replaces the temporary
certificates of the console, EST, ACME and the Windows service, and, because step 1 named the
CA, issues the database certificate. PostgreSQL loads that within about 30 seconds, without a
restart.

**Step 3 — restart the services**, so they start using their new certificates. Leave out any
protocol you did not install:

```bash
docker compose restart ocsp cmp scep est acme ms web
```

**Step 4 — run step 2 again.** A service that was not running the first time was skipped
(`skipped … nothing published yet`). When the command reports nothing skipped, you are done.

**Step 5 — check** that nothing reports a missing certificate. CMP and SCEP announce their RA
mode at startup:

```bash
docker compose logs ocsp cmp scep
```

The full test, issuing a certificate and asking OCSP about it, is §6.

**On a native or cloud server**, run step 2 as the `fastpki` user (§5), and restart with
`for s in ocsp cmp scep est acme ms web; do doas rc-service fastpki-$s restart; done`.
**On Kubernetes**, set the two values and run `apply.sh` again (§8.0 step 7); it issues the
certificates and restarts the services.

A CA you add later gets its service certificates on its own: the nightly renewal job repeats
step 2. It has no command line, so it reads `SERVICE_KEYS_REPLICABLE` to decide whether new
keys are copyable; a server installed for a pair has it set to `true`.

To issue these certificates one at a time in the console instead, for example a listener
certificate with extra names, see
[Manual procedures §4](manual-procedures.md#4-service-certificates-one-at-a-time-in-the-console).

### 4.4a What `renew-service-certs` and `pg-tls` do

Reference: what the commands in §4.4 do. Nothing to run.

- **`--create-missing`** creates the OCSP responder, CMP RA and SCEP RA certificates, each
  with a new key in the key store. Their subject and purposes are built in. The key type
  comes from `OCSP_RESPONDER_KEY_ALGO`, `CMP_RA_KEY_ALGO` and `SCEP_RA_KEY_BITS`. Root CAs are
  skipped: nothing enrols against a root.
- **`--re-issue-self-signed`** replaces the temporary certificate of each HTTPS service,
  keeping its key. It signs with `--ca <id>` if given, else with the CA in `HTTPS_CA_ID`, else
  with this server's only issuing CA. It never picks a root. With more than one issuing CA,
  set `HTTPS_CA_ID`, or the nightly job replaces nothing and reports
  `this node has more than one issuing CA`:
  ```bash
  docker compose exec web fastpki-config set HTTPS_CA_ID YOUR-CA-ID
  ```
- **A service that has never started is skipped**, because it has no certificate yet to
  replace. `checked` in the summary counts the services it could see.
- **`--replicable`** takes effect only when a key is created. For an existing key it renews the
  certificate, keeps the key, and says so. To change a key that was created without it, see
  [Manual procedures §5](manual-procedures.md#5-replacing-the-ocsp-cmp-and-scep-keys-with-copyable-ones).
- **`--dry-run`** shows what it would do and changes nothing.

On a fresh installation the command also prints:

```
fastpki-ca: the database still uses the self-signed certificate made at install. Replace it with `fastpki-ca pg-tls <ca-id>`, and set PG_TLS_CA_ID to that CA so it is renewed.
```

Setting `PG_TLS_CA_ID` in §4.4 step 1 does exactly that, and the message stops. The database
is the one service that cannot take a certificate from the key store, because PostgreSQL needs
its key as a file, so `pg-tls` writes one. With `PG_TLS_CA_ID` unset, the nightly job leaves
the certificate alone until it expires, and every service then fails to connect to a database
that is working.

**How each HTTPS service finds its certificate.** Each one keeps it in the database, under an
id, and uses the newest certificate there that matches the key it holds:

| Service | id setting | shipped value | key setting |
|---|---|---|---|
| Console | `WEB_CERT_ID` | `web` | `WEB_TLS_KEY` |
| EST | `EST_CERT_ID` | `est` | `EST_KEY` |
| ACME | `ACME_CERT_ID` | `acme` | `ACME_KEY` |
| MS-XCEP/WSTEP | `MS_CERT_ID` | `ms` | `MS_KEY` |

`EST_CERT`, `ACME_CERT`, `MS_CERT` and `WEB_TLS_CERT` are only for bringing in a certificate
from outside: a file there is read once and saved to the database. A renewal is picked up
within 30 seconds, without a restart.

### 4.4b Why OCSP and CMP need their own certificate, and what their errors mean

Reference, for when something does not work.

**OCSP.** RFC 6960 requires the responder certificate to be issued **by the CA it answers
for**, so there is one per CA: `ocsp-ra-issuing-ca` for a CA called `issuing-ca`. Responses
are never signed with the CA key. Three things must all be true: the key exists, the
certificate was issued by that CA, and `ocsp` was restarted afterwards. If OCSP still answers
`internalerror`, `docker compose logs ocsp` says which is missing. To check it, ask about a
certificate your CA issued (§6); `Cert Status: good` means it works.

**CMP.** Without its RA certificate, `fastpki-cmp` refuses every request. The client sees only
`missing content type: expected=application/pkixcmp`, which names neither CMP nor a
credential, so read the server log. It says:

```
CMP: refusing the transaction — no RA credential. Issue a certificate for
CMP_RA_CERT_ID_PREFIX 'cmp-ra' in the console (Inventory -> Request, key in HSM ->
Serve as CMP RA). No restart is needed: this process re-checks its token every 20s and
starts serving as soon as the key is there.
```

If `CMP_CLIENT_CA_ID` names a CA that does not exist, CMP starts anyway and logs
`WARNING: CMP has no client-CA trust anchor`. Check the log, not the container status.

**SCEP** reads its RA key on every request.

### 4.5 First console admin

Open `https://YOUR-NAME:8090`. Your browser warns about the certificate until §4.4 is done and
your browser trusts your root CA; continue past the warning. Sign in as **`admin`** with the password **`admin`**. The console
makes you choose a new password straight away, and until you do that session can do nothing
else. The seeded password is also refused by every enrolment protocol.

### 4.6 Updating an existing deployment (what to keep, what to wipe)

To update to a new release, get the new image and run `./rolling-update.sh` in the `deploy`
folder ([`admin-guide.md`](admin-guide.md) §14.3). It updates the database first, then the
services, and stops if the database update fails. Every release that changes the database
ships the change as a numbered step, and the script applies every step newer than your
database, in order, so you can update from any earlier release directly.

Four volumes hold the deployment:

| Volume | Holds | Wipe it? |
|---|---|---|
| `fastpki_softhsm-tokens` | **every CA private key** — the key store | **Never.** Without it nothing can sign with your CAs again |
| `fastpki_pgdata` | the database: every CA, certificate, revocation and user | **Never.** An update carries the database forward |
| `fastpki_pki-data` | the service TLS files and the key store password `/var/pki/tls/pin` | Almost never |
| `fastpki_p11-socket` | the key store's socket | freely — it holds nothing |

⚠️ **The two that matter are `fastpki_pgdata` and `fastpki_softhsm-tokens`.** Together they
*are* your CA, and one without the other is useless. `docker compose down -v` deletes both. To
start again from nothing, take a database dump first ([`postgres.md`](postgres.md) §5).

⚠️ `down -v` deletes only this compose project's volumes. Run `docker volume ls` afterwards and
remove anything left by another project by name, or a later install can come back with an old
CA's files.

---

## 5. Configuration

Settings live in one file, `bootstrap.conf`, which starts as a copy of
`config/bootstrap.conf.example`, and in the database.

There are three places a setting can come from:

| where | which settings |
|---|---|
| the file | all 162 of them |
| an environment variable of the same name | 127 of the 162 |
| the database, editable in the console's **Config** tab | all but `PG_CONNINFO`, which says how to reach the database and so has to be in the file |

The database wins over the file, so once a deployment is running, **change a setting in the
console's Config tab** (or with `fastpki-config set`) rather than editing the file.

⚠️ **Only those 127 settings can be set from the environment, and the rest are ignored
without a word.** These 35 have to go in the file or in the database. Several of them are the
certificate settings this guide asks you to change, which is why
`deploy/bootstrap.compose.conf` puts them in the file and not in `.env`:

```
ACME_CAA_IDENTITY   ACME_CERT      ACME_CERT_ID   ACME_KEY
ALLOW_WEAK_SIGNATURE_DIGEST        CMP_RA_CERT_ID_PREFIX     DISCOVER_BIN
EST_CERT            EST_CERT_ID    EST_KEY
LICENSE             LICENSE_FILE
LOGIN_FAILURE_THRESHOLD            LOGIN_LOCKOUT_SEC
MS_CERT             MS_CERT_ID     MS_KEY
NOTIFY_DAYS         NOTIFY_WEBHOOK NOTIFY_WEBHOOK_FORMAT     OCSP_EXPIRY_SWEEP_SEC
NOTIFY_EMAIL_FALLBACK              OCSP_RESPONDER_KEYS_REPLICATED
RELEASE_PUBKEY
SCEP_ALLOW_DES3     SCEP_ALLOW_SHA1
SMTP_CA_FILE        SMTP_FROM      SMTP_PASSWORD  SMTP_SERVER  SMTP_TLS  SMTP_USER
UPDATE_FEED_URL     WEB_CERT_ID    WEB_SELFSERVICE_IDENTITY_SUBJECT
```

**Running a FastPKI command yourself.** Every command needs `--config`, and on each kind of
installation it runs in a different place:

| Installation | How to run `fastpki-ca` (the same for `fastpki-config`) |
|---|---|
| Docker Compose, in `deploy/` | `docker compose exec web fastpki-ca --config /app/config/bootstrap.conf …` |
| Native and cloud | `doas su -s /bin/sh fastpki -c 'fastpki-ca --config /etc/fastpki/bootstrap.conf …'` |
| Kubernetes | `kubectl -n fastpki exec statefulset/fastpki-node -c web -- fastpki-ca --config /app/config/bootstrap.conf …` |

⚠️ **Leaving `--config` off gives no error.** The program uses its built-in settings and tries
a database on the local machine, so the symptom is a database connection failure.

⚠️ **On a native or cloud server, run it as the `fastpki` user, not as root.** The key store
answers only that user, and as root a command fails with `C_Initialize failed (rc=48)`, which
reads like a broken key store.

**Settings worth checking on any real installation:**

| Setting | What it is |
|---|---|
| `PKI_DNS`, `BASE_URL` | the public name clients use. `BASE_URL`, such as `https://pki.example.org`, is what the ACME directory advertises; set it, or ACME hands out wrong addresses |
| `PG_CONNINFO` | how to reach the database. PostgreSQL is the only database FastPKI uses |
| `PG_TLS_CA_ID`, `PG_TLS_SANS` | the CA that issues the database's certificate (§4.4), and extra names for it |
| `AUTH_BACKEND` | where passwords are checked: FastPKI itself (`local`) or your directory (`ldap`). There is no setting that turns authentication off |
| `WEB_ALLOW_REVOKE` | whether the console may change anything. `true` by default; `false` makes the console read-only |
| `CMP_CLIENT_CA_ID` | which CA CMP trusts for signed requests (§4.4) |
| `ALLOWED_IPS_REGEX`, `MIN_*_BITS` | which names and key sizes you are willing to sign. The approved domains are the `allowed_domains` table, and per-role limits are columns of the `roles` table |
| `CRL_DPS`, `AIA_CA_ISSUERS`, `AIA_OCSP` | fallback addresses, used only for a certificate issued outside any CA. Certificates from a CA get their addresses from that CA and the data center list |

**Where the keys are.** Every CA key is a `pkcs11:` address in a key store. The installer's
**Key storage** answer sets these:

| Setting | What it is |
|---|---|
| `PKCS11_MODULE` | the PKCS#11 module to load. With the key store that ships with FastPKI this is a small client that reaches the key store over a socket, never the key store's own library |
| `PKCS11_PROVIDER_PATH` | the folder holding OpenSSL's `pkcs11.so` provider |
| `PKCS11_TOKEN`, `PKCS11_PIN_FILE` | the key store's name, and the file holding its password on the server. The password is never sent to a browser |

For production, answer `hsm` and give your vendor's module path; it is loaded directly.

---

## 6. First issuance (smoke test)

Check that FastPKI really issues certificates. Run these on the server, in the `deploy`
folder, in order: each produces what the next needs. Replace `issuing-ca` with your issuing
CA's id if it is different. On native, cloud or Kubernetes, run step 1 in the form §5 shows.

**1. Create a user that is allowed to request certificates.** Choose your own password. The
`requester` role can enrol; `standard` cannot:

```bash
docker compose exec web fastpki-config --config /app/config/bootstrap.conf \
    web-user demo 'YOUR-PASSWORD' --role requester
```

**2. Download the CA chain** — the certificates of your two CAs:

```bash
curl -sk https://localhost:8443/.well-known/est/issuing-ca/cacerts \
  | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out ca-chain.pem
openssl x509 -in ca-chain.pem -noout -subject -issuer
```

It must show your CAs.

**3. Request a test certificate over EST:**

```bash
openssl req -new -newkey rsa:2048 -nodes -keyout test.key -out test.csr -subj "/CN=test"
curl -sk -u demo:'YOUR-PASSWORD' \
  --data-binary @<(openssl req -in test.csr -outform DER | openssl base64 -A) \
  -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" \
  https://localhost:8443/.well-known/est/issuing-ca/simpleenroll \
  | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out test.pem
openssl x509 -in test.pem -noout -subject -issuer
```

The subject must be `CN = test`, and the issuer your issuing CA.

**4. Ask whether it is revoked.** The answer must be `good`. `Responder Error: internalerror`
means §4.4 is not finished (§4.4b):

```bash
openssl ocsp -issuer ca-chain.pem -cert test.pem \
    -url http://localhost:8080/ocsp -resp_text -noverify | grep "Cert Status"
```

**5. Download the revocation list**, published for each CA at `/<ca-id>.crl`:

```bash
curl -s http://localhost:8080/issuing-ca.crl -o crl.der && openssl crl -inform DER -in crl.der -noout -text | head
```

If all five work, the installation is ready. [`user-guide.md`](user-guide.md) §6–§10 has full
client examples for EST, ACME with certbot, CMP with `openssl cmp`, SCEP and Windows.

---

## 6a. High availability: add a standby server

This adds a second server, the **standby**, to a Docker Compose installation. It keeps a live
copy of the database and its own copy of the CA keys. If the first server — the **primary** —
is lost, you switch to the standby and it carries on issuing certificates.
[`high-availability.md`](high-availability.md) covers the same for a native or cloud pair.

Below, **A** is the server you already have, and **B** is the new standby. Commands marked
**on A** or **on B** run in that server's `deploy` folder. The join runs **on your own
computer**.

Several checks ask the database `SELECT pg_is_in_recovery()`. It answers `t` on a
**standby** and `f` on the **primary**.

### Before you start: check server A

1. **A was installed for a pair.** On A:
   ```bash
   grep -E '^(HA_ENABLED|P11_TLS|SERVICE_KEYS_REPLICABLE|PG_BIND)=' .env
   ```
   It must show `HA_ENABLED=true`, `P11_TLS=on`, `SERVICE_KEYS_REPLICABLE=true`, and
   `PG_BIND` set to A's own address, not `127.0.0.1`. If not, A has to be installed again
   (§4.6 says what to delete).
2. **Every CA was created with *replicable key* ticked** (§4.3). Check each CA on A:
   ```bash
   docker compose exec web fastpki-ca --config /app/config/bootstrap.conf key list YOUR-CA-ID
   ```
   Every line must end with `[in this node's token, replicable]`. A line ending
   `NOT replicable: it can never be copied to another host` cannot be fixed: A has to be
   installed again.
3. **The public name is shared**, such as `pki.example.org`, not A's own machine name. It is
   in every certificate, so it must still work when B takes over.
4. **A and B can reach each other**, both ways, on ports 5432 (database) and 12345 (CA key
   copy).

**Your own computer must log in to both servers without typing a password**, because the
join tool connects by itself and cannot answer a password prompt. Do this once:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/fastpki_ops
ssh-copy-id -i ~/.ssh/fastpki_ops.pub YOUR-LOGIN@A-ADDRESS
ssh-copy-id -i ~/.ssh/fastpki_ops.pub YOUR-LOGIN@B-ADDRESS
```

The login must be able to run `docker compose` on the server. Use addresses your own computer
can reach.

### Step 1 — on B: install it for a pair

Install B with the **same release** as A, using `./install.sh` (§3.1). Give the same answers
as on A, except:

- **Postgres publish address**: B's own address;
- **Will this data center have a standby**: `yes`;
- on a server that is part of a mesh, the data center number is the **same** as A's: a pair is
  one data center.

**Do not create any CA on B.** B's database is replaced with a copy of A's in the next step,
and the join refuses a B that holds a CA.

### Step 2 — join B to A, from your own computer

One command, run on **your own computer**, from the folder of the FastPKI release:

```bash
deploy/ha-join-pair.sh --primary YOUR-LOGIN@A-ADDRESS --standby YOUR-LOGIN@B-ADDRESS \
    -i ~/.ssh/fastpki_ops
```

If FastPKI is not in `~/FastPKI/deploy` on a server, add its folder after the address, for
example `YOUR-LOGIN@A-ADDRESS:/home/YOUR-LOGIN/fastpki-v1.0/deploy`.

It checks both servers before it changes anything, then copies A's database to B, points both
servers' services at both databases, copies the CA keys into B's key store, and issues B its
own database certificate. Passwords and key store PINs travel only inside the command's own
connections. It takes about two minutes and ends like this:

```
ha-join-pair: standby: holds every key it needs to serve
ha-join-pair: primary: holds every key it needs to serve
ha-join-pair: standby: database certificate issued from the pair's CA
ha-join-pair: standby: its services now reach the standby first, then the primary
ha-join-pair: done: YOUR-LOGIN@B-ADDRESS streams from YOUR-LOGIN@A-ADDRESS and holds the CA keys.
```

If it stops, the message says why; fix that and run the same command again. It is safe to run
at any time.

### Step 3 — check the pair

**On B**, this must print `t`:

```bash
docker compose exec postgres psql -U fastpki -d fastpki -tAc 'SELECT pg_is_in_recovery()'
```

**On A**, this must show B's address and `streaming`:

```bash
docker compose exec postgres psql -U fastpki -d fastpki -c 'SELECT client_addr, state FROM pg_stat_replication'
```

The console's **Replication** page shows the same for both servers.

### Step 4 — test a failover

Do this once, before you rely on the pair. It pretends A has been lost.

1. **On A**, check that B is streaming, then stop the database:
   ```bash
   docker compose exec postgres psql -U fastpki -d fastpki -c 'SELECT client_addr, state FROM pg_stat_replication'
   docker compose stop postgres
   ```
2. **On B**, make B the primary, and load its new settings:
   ```bash
   ./pg-promote.sh
   docker compose up -d
   ```
   It prints `OK: postgres is now a read-write primary`, removes B's standby mark, and
   restarts the services. A line `could not reach the database at A-ADDRESS … Connection
   refused` is expected, because A's database is stopped. A line starting `WARN:` names
   something that failed.

   ⚠️ Always stop A's database first. Promoting B while A still runs gives you two databases
   that both accept changes, and one side's changes are lost.
3. **On B**, the same check as step 3 must now print `f`.
4. **Point your public name at B** (its DNS record, or `/etc/hosts` on each client in a test).
   A load balancer in front of both servers does this for you
   ([`high-availability.md`](high-availability.md)). Then issue a test certificate from B
   (§6); B signs with its own copy of the CA keys.

Leave A's database stopped. The next step brings A back.

### Step 5 — after the failover: make A the standby of B

A comes back as B's standby. Only A's **database** is replaced, with a copy of B's: A's own
database split from B's at the promotion, and cannot simply be started again. A's key store,
keys, certificates and settings stay as they are. From **your own computer**, with A's
database still stopped:

```bash
deploy/ha-join-pair.sh --primary YOUR-LOGIN@B-ADDRESS --standby YOUR-LOGIN@A-ADDRESS \
    --replace-local-database -i ~/.ssh/fastpki_ops
```

`--replace-local-database` is required, because A's database is thrown away. It takes about
two minutes. Check it as in step 3, with A and B swapped. The pair is complete again, with B as
the primary; either server can be the primary.

### Step 6 — switch back: make A the primary again (optional)

Not required: the pair works with either server as the primary. To switch back, repeat step 4
with A and B swapped, point your public name back at A, and make B A's standby with the step 5
command, A and B swapped. A planned switch loses nothing: issuing pauses only between stopping
one database and promoting the other.

---

## 7. Native install — Alpine + OpenRC (no Docker)

For **Alpine Linux** with OpenRC only; the installer stops on anything else. On a new Alpine
machine, as `root`, one command:

```sh
wget -qO- https://github.com/fastpki/fastpki/releases/latest/download/install.sh | sh -s -- --native
```

A stock Alpine has `wget` and `sh` but neither `curl` nor `bash`, which is why this line uses
them.

It downloads the ready-built programs for this machine's processor, checks the release
signature and then the package, installs the Alpine packages the release needs, and asks the
same questions as §3.1. Nothing is compiled on your server. Add `--answers <file>` to answer
from a file (the same file `install.sh` accepts), or `--version <tag>` to pin a release.

- **On a machine with IPv6 only**, github.com cannot be reached. Use fastpki.com, which serves
  the same signed releases over both address families:
  ```sh
  wget -qO- https://fastpki.com/install.sh | sh -s -- --native
  ```
- **On a machine with no internet**, copy the release package and `SHA256SUMS` and
  `SHA256SUMS.sig` from the same release into one folder, and name the package:
  ```sh
  sh install.sh --package fastpki-native-<version>-<arch>.tar.gz
  ```
  The two small files prove the package came from FastPKI; without them the installer
  refuses. The package must match the machine's processor and Alpine release.

The installer writes `/etc/fastpki/bootstrap.conf` (the programs' settings) and
`/etc/conf.d/fastpki` (the services' settings), sets up PostgreSQL, and switches on one
service for each protocol you chose.

Then create your CAs (§4.3) and the service certificates (§4.4, in its native form). On a
native server, FastPKI's commands run as the `fastpki` user (§5). A standby for a native
server is [`high-availability.md`](high-availability.md) §4; more data centers are §9.

**What one server uses**, measured after ten minutes idle: 2 processors at a load average of
0.00, 239 MB of memory, 264 MB of disk for the system and 64 MB for the data.

To install from a source checkout instead of a release, see
[Manual procedures §6](manual-procedures.md#6-native-install-from-a-source-checkout).

### 7.1 The services are restarted for you, even when they exit cleanly

A FastPKI service exits on purpose, reporting success, in three cases: its connection to the
key store has died, you switched its protocol off in the console, or something asked it to
restart. Each time it expects to be started again. Every service file uses `supervise-daemon`
with no restart limit, so that always happens. To check a service:

```bash
rc-service fastpki-web status
rc-service fastpki-web restart
rc-status                              # everything in the default runlevel
tail -f /var/log/fastpki/fastpki-web.log
```

### 7.2 Key storage on a native install — patched p11-kit

Ed25519, Ed448 and ML-DSA keys need patched builds of p11-kit and SoftHSM, because the
versions Alpine ships drop those algorithms. The release package installs the patched builds,
and the installer checks at every run that they are still the ones on disk. If Alpine's own
build has replaced one, it stops and says so:

```
install-native: Alpine's stock p11-kit or SoftHSM has replaced the patched build this package installed (...) — unpack the FastPKI package again (tar xzf fastpki-native-<version>-<arch>.tar.gz -C /), then run this again
```

Do what it says. RSA and EC keys work either way. If Ed25519 or ML-DSA is missing from the
**New CA** form's algorithm list on a native install, this is the reason.

A vendor HSM module is loaded directly (`PKCS11_MODULE`), and none of this applies to it. To
build the patched software yourself, see
[Manual procedures §6](manual-procedures.md#6-native-install-from-a-source-checkout).

### 7.3 Checking a native deployment without a cloud account

Two scripts test a native installation on your own computer, in containers:

```bash
sh deploy/native/build-check.sh --image fastpki-baked:local   # the build, about 20 minutes
sh deploy/native/run-check.sh                                 # the first start, about 3 minutes
```

`run-check.sh` starts the built image with a real init system, runs the installer to the end,
and checks that PostgreSQL starts with its certificate, the key store answers the service
user, the console answers over HTTPS, and a protocol you did not ask for stays off. Neither
starts a real machine.

---

## 8. Kubernetes

The same FastPKI, as a Kubernetes installation. You need `kubectl` and `envsubst` (the
`gettext` package) on the machine you install from, and a storage class that gives each
server ordinary disks of its own; the cluster default is normally right. The manifests use
only `v1`, `apps/v1` and `networking.k8s.io/v1`. The key store container needs Kubernetes 1.29
or later.

The walkthroughs install it step by step, for one server (§8.0) or a pair (§8.0b). Choose one
of the two. §8.0c adds a data center to either.

**What one server uses**, measured after ten minutes idle on k3s: 20 millicores of processor,
100 MB of memory for the pod's containers, and 48 MB of disk to begin with.

`deploy/k8s/delete.sh` removes the namespace and everything in it.

### 8.0 Install a single server on Kubernetes, step by step

The commands use **k3s**, a small Kubernetes that installs with one command; only step 1 is
specific to it. You need one Linux server with 2 GB of memory; k3s and FastPKI together
used about 1 GB of it. Replace `NODE-ADDRESS` with the server's IP address.

**Step 1. Run on the server — install k3s:**

```bash
curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644 --disable traefik
echo 'export KUBECONFIG=/etc/rancher/k3s/k3s.yaml' >> ~/.profile
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
for i in $(seq 60); do kubectl get nodes 2>/dev/null | grep -qw Ready && break; sleep 2; done
kubectl get nodes
```

The server must show `Ready`. The loop waits up to two minutes for that: for a few seconds
after k3s starts, `kubectl get nodes` answers `No resources found`. If it still shows
`NotReady`, wait a minute and run `kubectl get nodes` again. Both install options matter:
`--write-kubeconfig-mode 644` lets your own user run `kubectl`, and `--disable traefik` keeps
ports 80 and 443 free for ACME's http-01 and tls-alpn-01 checks (§8.6).

**Step 2. Run on the server — install FastPKI** with one command:

```bash
cd ~ && curl -fsSL https://github.com/fastpki/fastpki/releases/latest/download/install.sh | bash -s -- --k8s --dir ~/fastpki
```

It downloads the latest release into `~/fastpki` and checks its signature. Then it asks the
questions of step 3, and installs. Nothing is compiled: the cluster downloads the release's
published image.

**Step 3. Run on the server — answer the questions.** They are the same questions as the
Docker installer's (§3.1). For one server:

| Question | What to answer |
|---|---|
| **Deployment type** | `single` |
| **Container image** | press Enter |
| **Public FQDN** | the name clients use to reach this deployment, for example `pki.example.org`. It goes into every certificate, so it must work on every client |
| **Will this data center have a standby** | `no`. For a pair of servers, use §8.0b instead |
| **Postgres password**, **Token PIN** | press Enter: they are generated and kept in the cluster |
| **Key storage** | `softhsm` to try FastPKI out, `hsm` for your own hardware key store. With `hsm` it then asks for the module's path and its token label (`PKCS11_TOKEN`, `fastpki` unless your HSM's owner labelled it otherwise) |
| **EST**, **ACME**, **CMP**, **SCEP**, **MS-XCEP/WSTEP**, **Certificate store** | `yes` for each protocol you want. A protocol you answer `no` does not run |
| **Key type** for each service | press Enter (`ec`, `P-256`) |

The console and the protocols are published outside the cluster without a question. The
answers are saved in `~/fastpki/deploy/k8s/env.local`: to change one later, edit that file and
run `cd ~/fastpki/deploy/k8s && bash apply.sh`. §8.4 lists every other setting.

**Step 4. Run on the server — check it is running:**

```bash
kubectl -n fastpki get pods
```

`fastpki-node-0` must show `Running`, with the two numbers in the READY column equal. If it
shows `Pending` or `ErrImagePull`, `kubectl -n fastpki describe pod fastpki-node-0 | tail -20`
says why.

**Step 5. On your own computer, in a web browser — open the console.** Open this address:

```
https://NODE-ADDRESS:8090
```

The browser warns that the connection is not private. This is expected: the console uses its
own temporary certificate until your CA replaces it in step 7. Continue past the warning.

Sign in as `admin` with the password `admin`. The console then asks you to choose a new
password.

**Step 6. On your own computer, in the console — create the CAs.** You create two: a **root
CA**, which clients trust, and an **issuing CA** below it, which signs the certificates people
and devices ask for.

Before you start:

- **Will you ever add a second server (§8.0b)?** Then tick **replicable key** on *both* CAs.
  It lets the key be copied to the second server. It cannot be turned on afterwards.
- **Will you have several data centers (§8.0c)?** Then call the issuing CA `dc1-sub` instead
  of `issuing-ca`.

In the console, go to the **CAs** tab.

1. **Create the root CA.** Click **+ New CA** and fill in:
   - **id**: `root-ca`
   - **display name** and **CN**: a name such as `Example Root CA`
   - **Parent CA**: leave it as **— none (root) —**
   - **Algorithm**: **RSA**, **4096** bits
   - **replicable key**: tick it if you will add a second server
   - **Key name**: `root-ca`
   - leave everything else as it is, and click **Create CA**
2. **Create the issuing CA.** Click **+ New CA** again:
   - **id**: `issuing-ca` (or `dc1-sub`, see above)
   - **display name** and **CN**: a name such as `Example Issuing CA`
   - **Parent CA**: the root CA
   - **Algorithm**: **RSA**, **3072** bits
   - **replicable key**: tick it if you will add a second server
   - **Key name**: `issuing-ca`
   - open **Advanced** and check that the two web addresses contain the public name you gave
     in step 3. If they do not, stop and fix the name first
   - click **Create CA**
3. **Check.** The CAs tab lists both CAs as `active`.
4. **Disable the root CA.** Click **Disable** on the root CA's row. It has done its job of
   signing the issuing CA. Disabling it stops it signing anything else, and everything it
   already signed keeps working.

The issuing CA's id (`issuing-ca` or `dc1-sub`) is `YOUR-CA-ID` in step 7.

**Step 7. Run on the server — issue the service certificates.** Replace `YOUR-CA-ID` with your
issuing CA's id.

**If you may add a second server later (§8.0b)**, run this line first. It makes the OCSP, CMP
and SCEP keys copyable to a second server, so adding one later needs no new keys:

```bash
kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set SERVICE_KEYS_REPLICABLE true
```

**A standalone server that will stay alone:** skip this line. The keys then never leave the
server, which is the safer choice. If you add a second server after all, step 1 of
[Adding a second server to a running one](#adding-a-second-server-to-a-running-one) makes the
keys copyable at that point.

Then, in every case:

```bash
kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set PG_TLS_CA_ID YOUR-CA-ID
kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set CMP_CLIENT_CA_ID YOUR-CA-ID
cd ~/fastpki/deploy/k8s && bash apply.sh
```

`apply.sh` issues every service certificate, the database certificate included, and restarts
the services. §4.4 says what each certificate is for.

**Step 8. Run on the server — test it.** Reload the console first. It now uses a certificate
from your CA, so the browser warning is gone once your browser trusts your root CA.

Then run these on the server, in order. Replace `NODE-ADDRESS` with the server's address,
`issuing-ca` with your issuing CA's id if it is different, and `YOUR-PASSWORD` with a password
you choose.

1. Create a user that is allowed to request certificates:

   ```bash
   kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
       fastpki-config --config /app/config/bootstrap.conf web-user demo 'YOUR-PASSWORD' --role requester
   ```

2. Download the CA chain:

   ```bash
   cd ~
   curl -sk https://NODE-ADDRESS:8443/.well-known/est/issuing-ca/cacerts \
     | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out ca-chain.pem
   openssl x509 -in ca-chain.pem -noout -subject -issuer
   ```

   It must show your CAs. If it prints nothing, `PROTO_SERVICE_TYPE` is not `LoadBalancer`.

3. Request a test certificate:

   ```bash
   openssl req -new -newkey rsa:2048 -nodes -keyout test.key -out test.csr -subj "/CN=test"
   curl -sk -u demo:'YOUR-PASSWORD' \
     --data-binary @<(openssl req -in test.csr -outform DER | openssl base64 -A) \
     -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" \
     https://NODE-ADDRESS:8443/.well-known/est/issuing-ca/simpleenroll \
     | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out test.pem
   openssl x509 -in test.pem -noout -subject -issuer
   ```

   The subject must be `CN = test`, and the issuer your issuing CA.

4. Ask whether it is revoked. The answer must be `good`; `internalerror` means step 7 did not
   finish:

   ```bash
   openssl ocsp -issuer ca-chain.pem -cert test.pem \
       -url http://NODE-ADDRESS:8080/ocsp -resp_text -noverify | grep "Cert Status"
   ```

5. Download the revocation list:

   ```bash
   curl -s http://NODE-ADDRESS:8080/issuing-ca.crl -o crl.der && openssl crl -inform DER -in crl.der -noout -text | head
   ```

If all five work, the installation is ready.

To install from a source checkout, or with an image you build yourself, see
[Manual procedures §7](manual-procedures.md#7-kubernetes-from-a-source-checkout).

### 8.0a What is different from the Docker install

| | Docker Compose | Kubernetes |
|---|---|---|
| Settings | `deploy/.env`, written by the installer | `deploy/k8s/env.local`, written by the same installer |
| Reaching the console | published on the server's port | only with `WEB_SERVICE_TYPE=LoadBalancer`, or a port-forward (§8.6) |
| Run a FastPKI command | `docker compose exec web …` | `kubectl -n fastpki exec statefulset/fastpki-node -c web -- …` |
| Restart a service | `docker compose restart NAME` | `kubectl -n fastpki exec fastpki-node-0 -c NAME -- kill 1`, on each server |
| Update | run `./rolling-update.sh` with the new image | set the new `IMAGE`, run `apply.sh` again (§8.7) |

Everything else is the same: the console, the CAs and the certificates.

### 8.0b Install a pair of servers for high availability, step by step

Two machines, one Kubernetes cluster, one FastPKI server on each, each with its own key store
and database. Either machine can be lost: the second server's database streams from the
first, and each server copies every key it is missing from the other.

- **Starting from nothing?** Follow steps 1 to 10 below. You need two Linux servers with 2 GB
  of memory each, and nothing else: no shared storage and no third machine.
- **Already running one server from §8.0?** Do not install again. Go to
  [Adding a second server to a running one](#adding-a-second-server-to-a-running-one) at the
  end of this section.

Replace `FIRST-ADDRESS` with the first machine's IP address wherever it appears.

Each step starts by saying where to run it: on the **first machine**, on the **second
machine**, or on **your own computer** (in a web browser).

**Step 1. Run on the first machine — install k3s.** On the first machine only, not on the second:

```bash
curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644 --disable traefik
echo 'export KUBECONFIG=/etc/rancher/k3s/k3s.yaml' >> ~/.profile
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
for i in $(seq 60); do kubectl get nodes 2>/dev/null | grep -qw Ready && break; sleep 2; done
kubectl get nodes
```

The machine must show `Ready`. The loop waits up to two minutes for that: for a few seconds
after k3s starts, `kubectl get nodes` answers `No resources found`.

**Step 2. Run on the first machine, then on the second machine — join the second machine.**

⚠️ **Do not install k3s on the second machine yourself.** The line this step prints installs
it there as an *agent*, which joins the first machine's cluster. The step 1 command would
install a *server* instead, which is a second, separate cluster.

On the **first** machine, find its address. Use the one under `INTERNAL-IP`:

```bash
kubectl get nodes -o wide
```

Still on the **first** machine, print the join command. **Replace `FIRST-ADDRESS` with that
address before you run it**, without any `/24` after it:

```bash
echo "curl -sfL https://get.k3s.io | K3S_URL=https://FIRST-ADDRESS:6443 K3S_TOKEN=$(sudo cat /var/lib/rancher/k3s/server/node-token) sh -"
```

Check that the printed line shows the address, not `FIRST-ADDRESS`. Copy that whole line and
run it on the **second** machine. That is the only command the second machine runs. It
returns to the prompt when the join succeeds; if it stays at `systemd: Starting k3s-agent`,
the address is wrong (`sudo journalctl -u k3s-agent -n 20` says why). Then, back on the
**first** machine:

```bash
kubectl get nodes
```

Both machines must show `Ready`, and only the first one `control-plane`. **All the commands
from here run on the first machine.** On the second machine, `kubectl` answers `The connection
to the server localhost:8080 was refused`, or, once it has joined, `the server could not find
the requested resource`. Both are expected: the second machine holds no cluster configuration.
Run the command again on the first machine.

**If the second machine already has k3s** (a join that failed, or k3s installed there by
mistake), remove it on the second machine, then run the join line again:

```bash
sudo /usr/local/bin/k3s-agent-uninstall.sh
sudo /usr/local/bin/k3s-uninstall.sh
```

Each command removes one kind of install. The one that is not there answers `No such file
or directory`, which is fine.

**Step 3. Run on the first machine — install FastPKI** with one command:

```bash
cd ~ && curl -fsSL https://github.com/fastpki/fastpki/releases/latest/download/install.sh | bash -s -- --k8s --dir ~/fastpki
```

It downloads the latest release into `~/fastpki` and checks its signature. Then it asks the
questions of step 4, and installs. Both machines download the published image by themselves.

**Step 4. Run on the first machine — answer the questions.** They are the same questions as
the Docker installer's (§3.1). For a pair:

| Question | What to answer |
|---|---|
| **Deployment type** | `single` |
| **Container image** | press Enter |
| **Public FQDN** | the name clients use to reach this deployment, for example `pki.example.org`. It must be a name for the deployment, not one machine's host name. It goes into every certificate, so it must work on every client |
| **Will this data center have a standby** | `yes`. This is what gives you two servers, one on each machine, and turns on the channel keys are copied over (`P11_TLS`) |
| **Postgres password**, **Token PIN** | press Enter: they are generated and kept in the cluster |
| **Key storage** | `softhsm` to try FastPKI out, `hsm` for your own hardware key store. With `hsm` it then asks for the module's path and its token label (`PKCS11_TOKEN`, `fastpki` unless your HSM's owner labelled it otherwise) |
| **EST**, **ACME**, **CMP**, **SCEP**, **MS-XCEP/WSTEP**, **Certificate store** | `yes` for each protocol you want. A protocol you answer `no` does not run |
| **Key type** for each service | press Enter (`ec`, `P-256`) |

The console and the protocols are published outside the cluster without a question. The
answers are saved in `~/fastpki/deploy/k8s/env.local`: to change one later, edit that file and
run `cd ~/fastpki/deploy/k8s && bash apply.sh`.

**Step 5. Run on the first machine — check both servers are running:**

```bash
kubectl -n fastpki get pods -o wide
```

`fastpki-node-0` and `fastpki-node-1` must both show `Running`, on different machines (the
NODE column). `Pending` with `didn't match pod anti-affinity rules` means only one machine can
take a server: step 2 did not finish.

**Step 6. Run on the first machine — check the standby.** This must print `t`:

```bash
kubectl -n fastpki exec fastpki-node-1 -c postgres -- \
    psql -U fastpki -d fastpki -tAc 'SELECT pg_is_in_recovery()'
```

**Step 7. On your own computer, in a web browser — open the console.** Open this address:

```
https://FIRST-ADDRESS:8090
```

The browser warns that the connection is not private. This is expected: the console uses its
own temporary certificate until your CA replaces it in step 9. Continue past the warning.

Sign in as `admin` with the password `admin`. The console then asks you to choose a new
password.

**Step 8. On your own computer, in the console — create the CAs.** A new installation has no
CA, so it cannot issue anything yet. You create two: a **root CA**, which clients trust, and an
**issuing CA** below it, which signs the certificates people and devices ask for.

⚠️ **Tick replicable key on both.** It lets the second server copy the keys and sign. It cannot
be turned on afterwards.

If you will have several data centers (§8.0c), call the issuing CA `dc1-sub` instead of
`issuing-ca`.

In the console, go to the **CAs** tab.

1. **Create the root CA.** Click **+ New CA** and fill in:
   - **id**: `root-ca`
   - **display name** and **CN**: a name such as `Example Root CA`
   - **Parent CA**: leave it as **— none (root) —**
   - **Algorithm**: **RSA**, **4096** bits
   - **replicable key**: tick it
   - **Key name**: `root-ca`
   - leave everything else as it is, and click **Create CA**
2. **Create the issuing CA.** Click **+ New CA** again:
   - **id**: `issuing-ca` (or `dc1-sub`, see above)
   - **display name** and **CN**: a name such as `Example Issuing CA`
   - **Parent CA**: the root CA
   - **Algorithm**: **RSA**, **3072** bits
   - **replicable key**: tick it
   - **Key name**: `issuing-ca`
   - open **Advanced** and check that the two web addresses contain the public name you gave
     in step 4. If they do not, stop and fix the name first
   - click **Create CA**
3. **Check.** The CAs tab lists both CAs as `active`.
4. **Disable the root CA.** Click **Disable** on the root CA's row. It has done its job of
   signing the issuing CA. Disabling it stops it signing anything else, and everything it
   already signed keeps working.

The issuing CA's form may be served by the server that does not hold the root's key yet; the
console copies it from the other server first, so the form can take a few seconds longer.

**Step 9. Run on the first machine — issue the service certificates and copy the keys.**
Replace `YOUR-CA-ID` with your issuing CA's id (`issuing-ca` or `dc1-sub`):

```bash
kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set PG_TLS_CA_ID YOUR-CA-ID
kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set CMP_CLIENT_CA_ID YOUR-CA-ID
cd ~/fastpki/deploy/k8s && bash apply.sh
```

`apply.sh` issues every service certificate and restarts the services on both servers. Then
copy the keys between the two servers. Run these two commands, then run them both again. The
second time, each must say `this node holds every key it needs to serve`:

```bash
kubectl -n fastpki exec fastpki-node-0 -c renew -- \
    fastpki-ca --config /app/config/bootstrap.conf key sync --from-peers
kubectl -n fastpki exec fastpki-node-1 -c renew -- \
    fastpki-ca --config /app/config/bootstrap.conf key sync --from-peers
```

A failure naming a key that is not replicable means that CA was created without **replicable
key** in step 8.

**Step 10. Run on the first machine — test it.** Reload the console: the browser warning is
gone once your browser trusts your root CA. Then run the five checks of §8.0 step 8, with `FIRST-ADDRESS` in place of
`NODE-ADDRESS`. If all five work, the pair is ready. §8.5 covers switching to the second server
when a machine is lost.

#### Adding a second server to a running one

For a server already installed with §8.0. Its CAs must have **replicable key** ticked
(§8.0 step 6). If they do not, a second server can never sign with them: stop here.

**Step 1. Run on the first machine — make the OCSP, CMP and SCEP keys copyable.** Skip this
step if you set `SERVICE_KEYS_REPLICABLE` in §8.0 step 7. Otherwise, on the **first** machine,
replace the three keys with replicable ones:

```bash
kubectl -n fastpki exec fastpki-node-0 -c renew -- sh -c 'for l in ocsp-ra cmp-ra scep-ra; do
  for t in privkey pubkey; do
    pkcs11-tool --module "$PKCS11_MODULE" --token-label "${PKCS11_TOKEN:-fastpki}" --login \
        --pin "$(cat /var/pki/tls/pin)" --delete-object --type $t --label $l >/dev/null 2>&1
  done
done'
kubectl -n fastpki exec fastpki-node-0 -c renew -- \
    fastpki-ca --config /app/config/bootstrap.conf renew-service-certs --create-missing --replicable
```

The second command must report `created` for all three.

**Step 2. Run on the first machine, then on the second machine — join the second machine**,
exactly as step 2 of §8.0b above.

**Step 3. Run on the first machine — turn on the second server:**

```bash
echo 'HA_ENABLED=true' >> ~/fastpki/deploy/k8s/env.local
cd ~/fastpki/deploy/k8s && bash apply.sh
```

**Step 4. Run on the first machine — check both servers are running:**

```bash
kubectl -n fastpki get pods -o wide
```

`fastpki-node-0` and `fastpki-node-1` must both show `Running`, on different machines.

**Step 5. Run on the first machine — check the standby.** This must print `t`:

```bash
kubectl -n fastpki exec fastpki-node-1 -c postgres -- \
    psql -U fastpki -d fastpki -tAc 'SELECT pg_is_in_recovery()'
```

**Step 6. Run on the first machine — copy the keys to the second server**, with the two
`key sync` commands of §8.0b step 9, run twice.

### 8.0c Add a data center, step by step

A second data center (**DC2**) is a second, separate Kubernetes cluster. It shares DC1's root
CA, has its own issuing CA, and copies its database to and from DC1. **DC1** is the
installation you already have, from §8.0 or §8.0b. Nothing on DC1 is reinstalled.

Replace these wherever they appear:

| Written here | Means |
|---|---|
| `DC1-ADDRESSES` | the address of each DC1 server, as `kubectl get nodes -o wide` on DC1 shows under `INTERNAL-IP`. For a pair, both, comma-separated, first machine first: `10.0.0.1,10.0.0.2` |
| `DC2-ADDRESS` | the DC2 machine's address, as `kubectl get nodes -o wide` on DC2 shows under `INTERNAL-IP` |
| `pki2.example.org` | DC2's own public name. It must be different from DC1's |
| `YOUR-LOGIN` | your login name on the DC2 machine |

**Step 1. Run on DC2's machine — install DC2 as a single server.** Follow §8.0 steps 1 to 5.
In §8.0 step 3, answer these questions differently, and the rest as shown there:

| Question | What to answer |
|---|---|
| **Deployment type** | `cluster` |
| **Public FQDN** | DC2's own name, `pki2.example.org`. Not DC1's |
| **This data center's index** | `2`. It keeps DC2's certificate serial numbers apart from DC1's |
| **This data center's mesh-reachable address** | `DC2-ADDRESS`: the address DC1 reaches DC2's database on |

The installer then publishes DC2's database on that address, for DC1.

**`admin` is one account across the mesh.** DC2's `admin` gets its own password in §8.0 step 5.
The join in step 9 keeps DC1's, because DC1 is named first; then, because both data centers had
set one, the next sign-in on either asks for a new password.

⚠️ **Stop after §8.0 step 5. Do not create CAs in DC2's console.** DC2's CA is signed by DC1's
root in steps 5 to 7 below.

**If DC2 is already installed as a `single` deployment**, it registered itself as data center 1.
Remove it and start step 1 again. On DC2's machine:

```bash
sudo /usr/local/bin/k3s-uninstall.sh
rm -rf ~/fastpki
```

**Step 2. Run on DC1's first machine — make DC1 a data center too.** Its peers need an
address to reach it on as well:

```bash
cat >> ~/fastpki/deploy/k8s/env.local <<'EOF'
DC_INDEX=1
PG_INTERCONNECT=DC1-ADDRESSES
PG_EXTERNAL_TYPE=LoadBalancer
EOF
cd ~/fastpki/deploy/k8s && bash apply.sh
```

`apply.sh` also re-issues DC1's database certificates so they carry these addresses.

**Step 3. Run on DC1's first machine — give it access to DC2's cluster.** The mesh command
in step 4 works on both clusters, so this machine needs both, named `dc1` and `dc2`:

```bash
mkdir -p ~/.kube
sed 's/: default$/: dc1/' /etc/rancher/k3s/k3s.yaml > ~/.kube/dc1.yaml
ssh YOUR-LOGIN@DC2-ADDRESS cat /etc/rancher/k3s/k3s.yaml \
  | sed -e 's/: default$/: dc2/' -e 's#https://127.0.0.1:6443#https://DC2-ADDRESS:6443#' > ~/.kube/dc2.yaml
export KUBECONFIG=~/.kube/dc1.yaml:~/.kube/dc2.yaml
kubectl --context dc1 get nodes
kubectl --context dc2 get nodes
```

Each of the last two commands must list its cluster's machines as `Ready`. The `export` lasts
until you close this terminal: in a new one, run the `export` line again before step 4 or 9.

**Step 4. Run on DC1's first machine — start the mesh:**

```bash
cd ~/fastpki && deploy/mesh-join.sh k8s:dc1/fastpki k8s:dc2/fastpki
```

It tells each data center about the other, then stops with:

```
mesh-join: stopped: these data centers have no issuing CA of their own yet: 2
```

That is expected: DC2 has no CA yet. **This is the point to do steps 5 to 7.**

**Step 5. On your own computer, in DC2's console — create DC2's key and a request.** Open
`https://DC2-ADDRESS:8090` and sign in. **CAs** → **+ Create CSR (key in HSM)**:

- **Key name**: `dc2-sub`
- **CN**: a name such as `Example DC2 Sub`
- **Algorithm**: **RSA**, **3072** bits

Click **Create CSR**, then **Download .csr**.

**Step 6. On your own computer, in DC1's console — sign the request with the root.** Open
DC1's console. On the **CAs** tab:

1. If the root CA is disabled, click **Enable** on its row.
2. Click the `root-ca` row, scroll to **PEM** and press **Download**. You get `root-ca.pem`, the
   root's certificate. Step 7 needs it.
3. **Request from a CSR**: **Issue from**: the root CA. Upload the `.csr` from step 5. **Not
   after**: no later than the root's own end date. Click **Sign request**, then
   **Download .crt**.
4. Click **Disable** on the root CA's row again.

**Step 7. On your own computer, in DC2's console — register the two CAs.** **CAs** →
**Import an existing CA**, twice:

1. The **root**: **id** `root-ca`, the `root-ca.pem` from step 6, and **Trust anchor only — this
   node never signs with it**.
2. DC2's **own CA**: **id** `dc2-sub`, the `.crt` from step 6, **This node holds the key in its
   token**, **Key name** `dc2-sub`.

The **CAs** tab then lists both.

**Step 8. Run on DC2's machine — issue DC2's service certificates:**

```bash
kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set PG_TLS_CA_ID dc2-sub
kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set CMP_CLIENT_CA_ID dc2-sub
cd ~/fastpki/deploy/k8s && bash apply.sh
```

**Step 9. Run on DC1's first machine — finish the mesh,** with the same command as step 4:

```bash
cd ~/fastpki && deploy/mesh-join.sh k8s:dc1/fastpki k8s:dc2/fastpki
```

This time it goes all the way, which takes a minute or two. It ends with:

```
mesh-join: done: every data center holds N certificates, and each is subscribed to the other
```

**Step 10. On your own computer — check.** In either console, the **CAs** tab now shows both
data centers' CAs, and a certificate issued in one data center appears in the other within
seconds. §9.3 has the Kubernetes details of a mesh.

### 8.1 What `apply.sh` creates, in order

Reference. The order matters, because each step depends on the one before:

1. the namespace and the `fastpki-secret` Secret. The database password and the key store PINs
   are only there, never in the ConfigMap or a pod spec;
2. the `fastpki-bootstrap` ConfigMap: `bootstrap.conf` and the scripts the pods run;
3. on a re-run, **the database update**, before any server restarts on a new image;
4. **the servers**: the `fastpki-node` StatefulSet — one pod, or two with `HA_ENABLED`;
5. each server's database anchor, in the `fastpki-pg-anchors` ConfigMap, so each server can
   verify the other's database before any CA exists;
6. the database schema, this cluster's data center row, and the `admin` console user;
7. the protocol Services and the console Service;
8. any missing service certificates, and a restart of each server's services when it creates
   any.

Step 8 can do nothing on the first run, because no CA exists yet. That is why §8.0 step 7 runs
`apply.sh` again once the CAs exist. With `HA_ENABLED`, `apply.sh` sets
`SERVICE_KEYS_REPLICABLE=true`; do not turn it off, or new service keys cannot be copied to the
other server.

### 8.2 One server per pod, each with its own token

Every server is one pod of the `fastpki-node` StatefulSet, and holds everything a Compose
server holds:

| Container | What it is |
|---|---|
| `token` | this server's key store, on a disk of its own |
| `init` | prepares the server: the key store password, its transport keys, and its temporary database certificate |
| `postgres` | this server's database, on a disk of its own |
| `p11-tls` | the encrypted channel keys are copied over, when `P11_TLS=on` (§8.3) |
| `web`, `ocsp`, `est`, `acme`, `cmp`, `ms`, `store`, `scep` | the console and each protocol |
| `renew` | renews certificates on a schedule, and copies any key this server is missing from the other |

Each server also has its own `/var/pki`, on a third disk. Nothing is shared between pods, so
no disk has to be shared storage or NFS. **Every server has its own key store**: a CA key
reaches the other server by being copied into its key store (§8.3), never by one server
signing through another's.

A server's name inside the cluster, such as `fastpki-node-0.fastpki-node`, is the address its
database is reached on and the name on its database certificate.

### 8.3 A key in another server's token

Two ways, and both leave every server signing with a key store it reaches locally:

- **A network hardware security module.** Set `SOFTHSM_ENABLED=false` and point
  `PKCS11_MODULE` at the vendor's library. No key store runs in the pod; every service reaches
  the appliance over the network. This is what a production deployment does.
- **The key store that ships with FastPKI, with keys copied between servers.** `P11_TLS=on`
  runs an encrypted channel in front of each server's own key store, on port 12345, with both
  ends checking each other's certificate. It is how one server copies a key into its own key
  store. `HA_ENABLED` turns it on. To let a server in **another data center** copy a key, set
  `P11_TLS_SERVICE_TYPE` to `LoadBalancer` or `NodePort`; each server is then published on its
  own, `fastpki-p11-tls-0` on port 12345 and `fastpki-p11-tls-1` on port 12346, because the key
  that other data center needs may be in either one.

### 8.4 The settings that matter

| Variable | Default | For |
|---|---|---|
| `IMAGE`, `IMAGE_PULL_POLICY` | the image the deployment already runs; on a first install, that release's published image, else `fastpki:latest`; `IfNotPresent` | which image, and whether to re-pull |
| `NAMESPACE` | `fastpki` | everything lands here |
| `PKI_DNS` | `pki.example.org` | the name the deployment answers to |
| `WEB_SERVICE_TYPE`, `WEB_PORT` | `ClusterIP`, `8090` | how to publish the console, and on which port |
| `INGRESS_ENABLED`, `INGRESS_CLASS`, `INGRESS_HOST`, `INGRESS_TLS` | `false`, —, —, `true` | front the console with an Ingress instead |
| `PROTO_SERVICE_TYPE` | `ClusterIP` | how clients reach the enrolment protocols. Use `LoadBalancer`: it keeps the port numbers written inside your certificates (§8.6). Do not put a TLS-terminating Ingress in front of them |
| `STORAGE_CLASS` | cluster default | the three disks each server gets. Each belongs to one server, so ordinary node-local disks such as `local-path` are right |
| `PG_DATA_SIZE`, `PKI_DATA_SIZE`, `SOFTHSM_TOKEN_SIZE` | `1Gi`, `1Gi`, `1Gi` | the size of each disk. A fresh database is about 48 MB |
| `SOFTHSM_ENABLED`, `PKCS11_MODULE` | `true`, the p11-kit client | §8.3 |
| `HA_ENABLED` | `false` | two servers on two machines instead of one (§8.5). Turns `P11_TLS` on as well |
| `P11_TLS` | on with `HA_ENABLED`, otherwise off | the encrypted channel keys are copied over (§8.3) |
| `AUDITFWD_ENABLED` | `false` | send the audit log elsewhere as it is written |
| `EST_INSTALLED`, `ACME_INSTALLED`, `CMP_INSTALLED`, `SCEP_INSTALLED`, `MS_INSTALLED`, `STORE_INSTALLED` | `true` | which enrolment protocols run. A protocol set to `false` has no container in the server pods and no Service, and the console shows it as not installed. The web console and OCSP always run |
| `PG_EXTERNAL_TYPE` | `none` | how each server's database is published to peer clusters (§9.3): `LoadBalancer` (port 5432 for `fastpki-node-0`, 5433 for `fastpki-node-1`), or `NodePort` (`PG_NODEPORT` for `fastpki-node-0`, `PG_NODEPORT`+1 for `fastpki-node-1`) |

Ports are the same everywhere: console `8090`, OCSP `8080`, EST `8443`, ACME `8444`, CMP
`8445`, Windows `8446`, store `8447`, SCEP `8448`.

⚠️ **An image from your own registry: k3s does not read Docker's settings.** A registry served
over plain HTTP, or with a certificate the machines do not trust, has to be declared to k3s
**on every machine in the cluster**, and k3s restarted there. The symptom otherwise is
`http: server gave HTTP response to HTTPS client`:

```bash
sudo tee /etc/rancher/k3s/registries.yaml >/dev/null <<'EOF'
mirrors:
  "registry.example.org:5000":
    endpoint:
      - "http://registry.example.org:5000"
EOF
sudo systemctl restart k3s          # k3s-agent on the other machines
```

⚠️ **k3s writes its kubeconfig readable by root only**, unless installed with
`--write-kubeconfig-mode 644`. Then `apply.sh` stops with `error loading config file
"/etc/rancher/k3s/k3s.yaml": permission denied`. Give yourself a copy and point `KUBECONFIG` at
it:

```bash
mkdir -p ~/.kube && sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown "$(id -u):$(id -g)" ~/.kube/config && chmod 600 ~/.kube/config
export KUBECONFIG=$HOME/.kube/config
```

⚠️ **Reusing a machine that has run k3s before: remove the cluster, not just the namespace.**
Deleting the namespace leaves rules that still send ports 80 and 443 to pods that no longer
exist, and ACME's checks then fail on ports that look free:

```bash
sudo /usr/local/bin/k3s-uninstall.sh          # the server machine
sudo /usr/local/bin/k3s-agent-uninstall.sh    # each agent machine
sudo iptables-save | grep -c CNI-HOSTPORT     # must print 0 before you install again
```

### 8.5 A pair of servers, and promoting one

`HA_ENABLED=true` runs two servers, `fastpki-node-0` and `fastpki-node-1`, on two different
machines. It is the Compose pair (§6a) on Kubernetes: one key store and one database per
server, the second database streaming from the first, a full set of services on each, and each
server copying every key it is missing from the other. The two servers need two machines; with
one, `fastpki-node-1` stays `Pending`. §8.0b installs a pair, and *Adding a second server to a
running one* turns a single server into one.

**Checking the pair.** `fastpki-node-1` must answer `t`, `fastpki-node-0` must list it as
`streaming`, and `key sync` on each must say `this node holds every key it needs to serve`:

```bash
kubectl -n fastpki exec fastpki-node-1 -c postgres -- \
    psql -U fastpki -d fastpki -tAc 'SELECT pg_is_in_recovery()'
kubectl -n fastpki exec fastpki-node-0 -c postgres -- \
    psql -U fastpki -d fastpki -c 'SELECT application_name, client_addr, state FROM pg_stat_replication'
kubectl -n fastpki exec fastpki-node-0 -c renew -- \
    fastpki-ca --config /app/config/bootstrap.conf key sync --from-peers
kubectl -n fastpki exec fastpki-node-1 -c renew -- \
    fastpki-ca --config /app/config/bootstrap.conf key sync --from-peers
```

The console's **Replication** page shows the same for each server.

**Promoting the standby.** When the machine running the primary is lost, from any machine with
`kubectl` for the cluster:

```bash
FASTPKI_PROMOTE_MODE=k8s NAMESPACE=fastpki deploy/pg-promote.sh fastpki-node-1
```

It refuses while the other server's database still answers as a primary. If the lost pod is
still reported `Running` because its machine has not been marked down yet, confirm the
machine is gone (`kubectl get nodes`) and delete that pod first. It promotes the database,
removes the standby mark, gives the server the certificates it needs, and restarts its
services. The services move to the promoted database on their next request; confirm with a
write, because a read succeeds against either database.

⚠️ **This needs a working Kubernetes API.** A cluster installed as §8.0b has one control plane,
on the first machine. Losing that machine leaves the surviving server serving, but no
`kubectl` command works, so nothing can be promoted until it returns. For the cluster itself
to survive losing either machine, install k3s with `--cluster-init` and three servers.

**Restoring the second server.** A promoted server stays the primary, and the old one comes
back only as a new standby of it. If the old machine comes back, `fastpki-node-0` refuses to
start its database as a second primary (`kubectl -n fastpki logs fastpki-node-0 -c postgres`
says so). Delete its database disk and its pod; it copies the database from `fastpki-node-1`
when it starts:

```bash
kubectl -n fastpki delete pvc pgdata-fastpki-node-0 --wait=false
kubectl -n fastpki delete pod fastpki-node-0
```

If the old machine is gone for good, remove it and all three of the pod's disks, and add a
replacement machine to the cluster. The pod starts there with an empty key store, and copies
every key from `fastpki-node-1`:

```bash
kubectl delete node OLD-NODE-NAME
kubectl -n fastpki delete pvc pgdata-fastpki-node-0 pki-fastpki-node-0 softhsm-tokens-fastpki-node-0 --wait=false
kubectl -n fastpki delete pod fastpki-node-0
```

Then run `apply.sh` again: it republishes both servers' database anchors, which the rebuilt
server needs, and waits until both servers are ready.

### 8.6 Reaching the deployment

`apply.sh` prints the right command for the service type you chose. With the default
`ClusterIP`, only a port-forward reaches the console:

```bash
kubectl -n fastpki port-forward svc/fastpki-web 8090:8090   # then https://localhost:8090/
```

That does not make the CA usable: clients enrol against EST, ACME, CMP, SCEP and the store,
which are `ClusterIP` too by default. Publish them with `PROTO_SERVICE_TYPE=LoadBalancer`.

⚠️ **Use `LoadBalancer`, not `NodePort`.** The revocation list and CA certificate addresses in
every certificate carry the listener's own port, such as `:8080`. A NodePort service answers on
a different, allocated port, so those addresses answer nothing outside the cluster and a client
checking revocation waits until it times out. k3s's built-in load balancer publishes the real
ports on every machine.

⚠️ **Not a TLS-terminating Ingress in front of the protocols.** EST and CMP check the client's
certificate, which an Ingress that ends the TLS connection throws away. An Ingress controller
in **TLS passthrough** mode (nginx-ingress with `ssl-passthrough`, or a Traefik TCP router with
`tls.passthrough`) is fine, and you add that route yourself. The Ingress `INGRESS_ENABLED`
creates fronts the console only.

⚠️ **ACME's http-01 and tls-alpn-01 checks need ports 80 and 443**, which k3s's bundled Traefik
holds. Install k3s with `--disable traefik` (§8.0 step 1), or add `disable: [traefik]` to
`/etc/rancher/k3s/config.yaml` and restart k3s. dns-01 works either way.

⚠️ **`PKI_DNS` must resolve wherever relying parties are**, and both it and the service type
must be right **before you create the CAs**: a CA keeps the addresses it was created with.

**Testing it with the demo.** `demo/provision-target.sh` creates a demo user and its
credentials through the console, and writes a descriptor with every listener's port:

```bash
demo/provision-target.sh --web-url https://pki.example.org:8090 --namespace fastpki \
    --ssh-target USER@NODE --admin-pass 'CURRENT-ADMIN-PASSWORD' --out demo/.target-k8s.env
demo/pki-demo.sh  --target demo/.target-k8s.env
demo/pki-bench.sh --target demo/.target-k8s.env
```

- Use the deployment's own name, the one in `PKI_DNS`, in `--web-url`; certbot checks it.
- `--ssh-target` names a login on a machine where `kubectl` works, such as a cluster node: the
  ACME checks start a DNS server and a temporary Service in the namespace from there. Leave it
  out when `kubectl` on the demo machine already reaches the cluster.
- The machine running the demo also needs `certbot`, ports 80 and 443 free, and must be
  reachable from the cluster on those ports, plus `--challenge-fqdn` with a name the cluster
  resolves to it. [`demo/README.md`](../demo/README.md) has the details.

### 8.7 Updating

Set the new `IMAGE` in `env.local` and run `bash apply.sh` again. It updates the database
before any server restarts on the new image, then replaces the servers one at a time, so a
pair keeps serving throughout. Without `IMAGE` set, `apply.sh` keeps the image the deployment
already runs and says so:

```
==> Keeping the image this deployment runs: ghcr.io/fastpki/fastpki:<version> (set IMAGE to change it).
```

Roll back with `kubectl -n fastpki rollout undo statefulset/fastpki-node`.

---

## 9. Multi-data-center

A data center is one complete FastPKI deployment: its own database, its own key store and its
own CA key. Several of them copy certificates, revocations, users, roles, profiles and
templates to each other, in both directions, and all of them can issue. They share one root
CA. Each signs with its own issuing CA, because a server can sign only with a key in its own
key store.

### 9.0 Add a data center, step by step

**DC1** is the installation you already have — one server, or a pair (§6a). **DC2** is the
new one. Nothing on DC1 has to be undone or reinstalled: every installer already made it data
center 1.

On Kubernetes, use §8.0c; the CA steps below (5 to 7) are the same in the console.

**Step 1 — install DC2** with `./install.sh` (§3.1), answering:

- **Deployment**: `cluster`, and this server's number: **`2`**;
- **Public FQDN**: DC2's **own** name, such as `pki-dc2.example.org`, not DC1's;
- **Postgres publish address**: DC2's own IP address, on the network the data centers share.

**Step 2 — know which `admin` password survives.** `admin` is one account across the mesh:
each installer created its own row, and the join keeps one. Where only one data center has
changed the password, that password is kept. Where several have, the first data center named
to `mesh-join.sh` wins, and the next sign-in on any data center asks for a new password. The
join says which, for example:

```
mesh-join: 'admin': every data center now uses the password set on data center 1. You will
mesh-join:   be asked to choose a new one at your next sign-in, on any data center.
```

To set it again afterwards, run `fastpki-config web-user admin 'NEW-PASSWORD'` on any data center;
[`admin-guide.md`](admin-guide.md) §1.4 shows how to run it on each deployment path.
Directory accounts are not affected.

**Step 3 — start the mesh, from your own computer.** One argument per data center; a data
center with a standby is written `PRIMARY+STANDBY`:

```bash
deploy/mesh-join.sh YOUR-LOGIN@DC1-ADDRESS YOUR-LOGIN@DC2-ADDRESS -i ~/.ssh/fastpki_ops
```

It needs SSH to each server as a user that runs `docker compose` there, without a password
prompt (§6a, *Before you start*). If FastPKI is not in `~/FastPKI/deploy` on a server, add
its folder after the address, as `YOUR-LOGIN@DC2-ADDRESS:/opt/fastpki/deploy`. For servers
reachable only through another host, put `NA_SSH_JUMP=YOUR-LOGIN@JUMP-HOST` in front of the
command.

It reads each data center's number, address, public name and database password from the
servers, tells each data center about the others, and then stops, because DC2 has no CA yet.
That is expected:

```
mesh-join: pass 1 done: every data center knows the others and publishes
mesh-join: stopped: these data centers have no issuing CA of their own yet: 2
```

⚠️ **This comes before any CA is created on DC2.** Every certificate names one revocation list
address per data center known when it is issued, and cannot be told a new one afterwards.

**Step 4 — done by step 3.**

**Step 5 — on DC2's console, create DC2's key and a request.** **CAs** → **+ Create CSR (key
in HSM)**:

- **Key name**: `dc2-sub` — write it down, step 7 needs the same name
- **CN**: a name such as `Example DC2 Sub`
- **Algorithm**: RSA 3072, or EC P-256; the data centers need not match
- **replicable key**: tick it only if DC2 will later get a standby of its own

Click **Create CSR**, then **Download .csr**. The key stays in DC2's key store; only the
request travels.

**Step 6 — on DC1's console, sign the request with the root.** If the root CA is disabled,
enable it first. On a pair, use the primary. **CAs** → **Request from a CSR**:

- **Issue from**: the root CA, not the issuing CA you use every day
- paste or upload the request
- **Not after**: no later than the root's own end date
- **Hash**: `sha256`

Click **Sign request**, then **Download .crt**. Also get the root's certificate: click the
root's row on the CAs page, and **Download** under **PEM**. A CA certificate is public.

**Step 7 — on DC2's console, register the two CAs.** **CAs** → **Import an existing CA**,
twice:

- the **root**: id `root-ca`, the root's certificate from DC1, and **Trust anchor only — this
  node never signs with it**;
- DC2's **own CA**: id `dc2-sub`, the `.crt` from step 6, **This node holds the key in its
  token**, **Key name** `dc2-sub`.

The CAs page now lists `root-ca` marked *no key here*, and `dc2-sub` with its own key and the
root as its issuer. If `dc2-sub` shows no issuer, or the page says the certificate does not
match the key, the key name is not the one from step 5.

Then go back to DC1 and **disable the root CA** again.

**Step 8 — on DC2, issue its service certificates**, exactly as §4.4, with `dc2-sub` as the CA
id. `PG_TLS_CA_ID` and `CMP_CLIENT_CA_ID` belong to each data center, so DC2 needs its own. Add
`--replicable` only if DC2 will have a standby of its own.

**Step 9 — finish the mesh, from your own computer**, with the same command as step 3:

```bash
deploy/mesh-join.sh YOUR-LOGIN@DC1-ADDRESS YOUR-LOGIN@DC2-ADDRESS -i ~/.ssh/fastpki_ops
```

This time it goes all the way: it sets `PG_TLS_CA_ID` where it is unset, issues each
database certificate, subscribes each data center to the other, and waits until both hold the
same data:

```
mesh-join: pass 2 done: every data center subscribes to every other
mesh-join: done: every data center holds 28 certificates, and each is subscribed to the other
```

It stops, saying why, if a data center has several issuing CAs and no `PG_TLS_CA_ID`: set it
(§4.4 step 1) and run it again. It is safe to run at any time; each step checks first and
changes only what is missing.

**Step 10 — check.** Step 9 already compares the two data centers. In either console, the
**CAs** page now shows both data centers' CAs, and a certificate issued on one appears in the
other's **Inventory** within seconds.

**Step 11 — optional: give the older CAs every address.** CAs created before the mesh existed
name only their own data center's revocation list, so a client that cannot reach that data
center has nowhere else to look. Renewing each of them once, keeping its key, gives it every
data center's address ([`admin-guide.md`](admin-guide.md) §3.8).

**A third data center**, and every one after it, is the same: install it with the next
number, create and sign its CA (steps 5 to 8), and run `mesh-join.sh` with one more argument.

To do what `mesh-join.sh` does by hand, see
[Manual procedures §8](manual-procedures.md#8-joining-data-centers-by-hand).

### 9.1 Making the servers trust each other before they copy data — reference

Two data centers copy data only after each has verified the other's database certificate in
full. Every server starts with a database certificate it signed itself, which no other server
trusts, so each server's database certificate has to be issued by a CA they all trust first.
That is why the mesh is **one root CA, and one issuing CA per data center**: each data center
signs its own database certificate with a key in its own key store, and every certificate
leads back to the one root. `mesh-join.sh` issues those certificates between its two runs.

Until that is true, subscribing fails with `SSL error: certificate verify failed`. To build
the same trust from the command line, for a scripted installation, see
[Manual procedures §8](manual-procedures.md#8-joining-data-centers-by-hand).

### 9.2 Confirming every data center holds the same data

Compare the data centers; do not rely on PostgreSQL's own status views, which can report every
connection healthy while a data center is missing rows. On **every** server, the count must be
the same:

```bash
docker compose exec -T postgres psql -U fastpki -d fastpki -tAc "select count(*) from certs"
```

To see each connection as well:

```bash
docker compose exec -T postgres psql -U fastpki -d fastpki -tAc \
  "select s.subname, (r.pid is not null) as connected, r.latest_end_lsn
     from pg_subscription s
     left join pg_stat_subscription r on r.subname = s.subname order by 1"
```

Every row must show `t` for connected. Each data center has one connection for every other,
so with three data centers each has two. The console's **Replication** page
([`admin-guide.md`](admin-guide.md) §12.5) shows the connections for every data center in one
place, but only comparing counts proves the data matches.

Every data center copies from every other when it joins, so each receives some rows it already
has. Every copied table knows what to do with a duplicate, so this costs only bandwidth, once.

### 9.3 On Kubernetes

One data center is one Kubernetes cluster. Everything in §9.0 and §9.1 applies unchanged; the
settings in §8.0c make a cluster a data center of a mesh. `apply.sh` refuses a `DC_INDEX` other
than 1 without `PG_INTERCONNECT`, or a number of addresses that does not match the number of
servers.

**What `apply.sh` does for a mesh:** it writes this cluster's number, registers its data
center row before any service starts, publishes each server's database as its own Service,
`postgres-external-0` on port 5432 and `postgres-external-1` on port 5433, and ends by printing
the `mesh-join.sh` command that connects the clusters. Each server has its own port because a
load balancer that publishes on the machines' own addresses, as k3s's does, can publish only
one Service per port. In the topology, a Kubernetes pair is therefore `port=5432,5433`, where a
Compose pair is `port=5432,5432`.

**Connecting the clusters.** From a machine with `kubectl` access to every cluster, one
context per cluster, each written `k8s:<context>/<namespace>`:

```bash
deploy/mesh-join.sh k8s:dc1/fastpki k8s:dc2/fastpki
```

It finds the server holding the read-write database by asking each pod, so after a promotion
it uses `fastpki-node-1`. The first run stops for the CAs, exactly as on Compose; create them
in the consoles (§9.0 steps 5 to 7), then run it again.

⚠️ **Set the `admin` password on each cluster to the same value** after they are joined, or
the console accepts your password on one cluster and answers `401` on the other:

```bash
kubectl --context CONTEXT -n fastpki exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf web-user admin 'PASSWORD' --role admin
```

⚠️ **The other clusters' names must resolve inside the cluster.** The connection to a peer is
opened by the postgres container, so the cluster's DNS resolves it, not the machine's. If it
cannot, subscribing fails with `could not translate host name … Name does not resolve`. Give
CoreDNS the zone with a ConfigMap, then run `kubectl -n kube-system rollout restart
deploy/coredns`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns-custom
  namespace: kube-system
data:
  example-com.server: |
    example.com:53 {
      errors
      cache 30
      forward . 192.0.2.53      # your DNS server
    }
```

⚠️ **The database port must not face the public internet.** The replication stream carries
password hashes and enrolment secrets. Connect the clusters privately, and restrict the
Service with `loadBalancerSourceRanges` or a NetworkPolicy.

To run the CA commands from the command line in a cluster, see
[Manual procedures §3](manual-procedures.md#3-creating-cas-from-the-command-line).

### 9.4 Growing one server into several data centers

Every installer registers a server as data center 1, whether or not a mesh is planned, so its
certificates already carry that number in their serial numbers and nothing needs correcting.
To grow it:

1. **Publish its database on its own address.** On Compose, set `PG_BIND` in `deploy/.env` to
   the server's address on the network the data centers share, and run `docker compose up -d`.
   On Kubernetes, add the §8.0c settings and run `apply.sh`.
2. **Re-issue its database certificate**, so it carries that address. Run §4.4 step 2 again,
   or on Compose:
   ```bash
   docker compose exec web fastpki-ca --config /app/config/bootstrap.conf pg-tls YOUR-CA-ID
   ```
   It prints every name it certified; the address must be among them.
3. **Add the new data center with §9.0.**

The CA certificates it already holds name only this data center, until renewed (§9.0 step 11).

Growing again later is the same: install the new server with the next free number and run
`mesh-join.sh` with every data center.

### 9.5 Removing a data center from the mesh

`fastpki-mesh --leave` writes the SQL. It needs the topology file `mesh-join.sh` writes, or one
written by hand ([Manual procedures §8](manual-procedures.md#8-joining-data-centers-by-hand)):

```bash
# Compose, from deploy/, where the topology file sits
docker compose run --rm --no-deps --user 0:0 -v "$PWD/topology:/topology:ro" \
    --entrypoint fastpki-mesh web --topology /topology --node 3 --leave > leave-dc3.sql

# native or cloud
fastpki-mesh --topology /root/topology --node 3 --leave > leave-dc3.sql
```

⚠️ **Do not run the whole file on one server.** It has a section for each server, saying which
one it belongs to: the leaving data center drops its subscriptions, each remaining data center
drops its subscription to the leaver, and the leaver removes anything left last. Run them while
every server is still reachable, so each drop frees its replication slot at the other end.

Skipping the remaining data centers' half leaves each with a replication slot for a consumer
that never returns, which keeps database history until the disk fills.

If the leaving server is already gone, each remaining data center's section carries the
commands to use instead, as a comment.

Confirm on every remaining server:

```bash
docker compose exec postgres psql -U fastpki -d fastpki -c "
  SELECT count(*) AS subs FROM pg_subscription;
  SELECT count(*) AS slots FROM pg_replication_slots;"
```

Both are `0` on a server that is now alone; a server still in a smaller mesh keeps one of each
per remaining data center. Without `--node`, `--leave` takes the whole mesh apart.

⚠️ A departed data center keeps its number. Reusing that number for another data center makes
two data centers issue the same serial numbers.

Bringing a data center back from a dump of its own database is `fastpki-mesh --restore`, in the
order [`postgres.md`](postgres.md) §6.3 gives.

### 9.6 When a data center does not catch up

Work in this order. First the verdict — on every server, the certificate counts must match
(§9.2). Then the connections: `N-1` rows on an `N`-server mesh, every one `connected = t`.

| Symptom | Cause | Fix |
|---|---|---|
| a subscription is missing entirely | subscribing failed, and a failed subscription leaves nothing behind | fix the cause below, then run `mesh-join.sh` again |
| `could not find digest for NID UNDEF` | the peer's database certificate is signed with Ed25519, Ed448 or ML-DSA, which the database connection cannot use | re-issue that server's database certificate from a CA with an RSA or EC key ([`compatibility.md`](compatibility.md) §5.1) |
| `certificate verify failed` | the peer's database certificate does not lead to this server's root, or does not name the address dialled | re-issue it (§9.4 step 2), and check `PG_BIND` |
| `password authentication failed for user "fastpki"` | the connection carries the wrong peer's password | run `mesh-join.sh` again; it reads each password from its server |
| `publication "fastpki_pub" does not exist`, repeated at the same position | this data center subscribed before the peer published | the subscription has to be dropped and created again |
| connected, but the counts still differ | a table's first copy is stuck | read the subscriber's database log |

Each of these repairs by hand is in
[Manual procedures §9](manual-procedures.md#9-repairing-replication-by-hand).

### 9.7 Addresses: one name for everything, or one per data center

A mesh copies **data**, not the ability to sign. A server asked to issue from a CA whose key
is not in its key store refuses with `no signing key for this CA on this node`. That decides
how clients address the deployment:

**One name per data center — the default.** Every data center is addressed on its own, so a
client enrolling against `dc2-sub` reaches the server that holds that key. No key leaves the
key store it was created in, so a compromised server exposes one data center's CA.

**One name, shared by every data center.** One address for clients, but correct **only if
every server can sign with the CA a client asks for**. That means either a network HSM that
every server reaches, or the CA key copied into each server's key store:

```bash
docker compose exec web fastpki-ca --config /app/config/bootstrap.conf \
    key replicate shared-sub --from PEER-HOST:12345 --source-pin-file /var/pki/tls/srcpin
```

Both servers need `P11_TLS=on`, the CA must have been created with **replicable key**, and
`--source-pin-file` names a file holding the **peer's** key store PIN, since every server has
its own. Before the first copy, run `fastpki-config p11-clients-sync` and
`fastpki-config p11-servers-sync` on every server, so each trusts the others' channel. A copied
key means a compromised server exposes every CA it holds, so this is chosen per CA.

⚠️ **No server ever signs through another server's key store.** Losing that server would stop
every server signing, and certificates issued under that key could never be renewed or
revoked.

**An HA pair is different**: it is one data center, and every CA there is created replicable,
the root included (§6a).

Revocation checks can always use a name shared by every data center: revocation lists, OCSP and
the certificate store serve data every data center has.

⚠️ **Enrolment through a shared name:**

- **EST** and the **certificate store**: safe; one enrolment is one request.
- **CMP**: safe only if every client asks for implicit confirmation. Without it, one enrolment
  is two exchanges, and the second can reach a data center that never saw the first. The
  configuration file the console generates switches it on.
- **ACME: not safe.** ACME's single-use tokens and orders are never copied between data
  centers, so an order started at one is permanently unknown at another. Give each data center
  its own name, or use a load balancer that keeps each client on one data center.

---

## 10. TLS / reverse proxy

The console, EST, ACME and the Windows service use HTTPS themselves. OCSP, CMP, SCEP and the
certificate store use plain HTTP; if they face the internet, keep them on the local address
and put your own reverse proxy in front of them. FastPKI does not ship one;
`deploy/nginx.conf.example` is a starting point.

A proxy in front of an HTTPS service has to encrypt the connection again on the way through,
or, for EST with client certificates, pass the traffic along untouched. The console must stay
on HTTPS: key generation in the browser works only on a secure connection.

Set `BASE_URL` to your public `https://` address, so that ACME hands out that address.

---

## 11. Day-2 operations

Running FastPKI after installation — backups, updates, users, CAs and every console page — is
covered in the [Administration Guide](admin-guide.md). The database — backups, restores and
the table reference — is covered in [postgres.md](postgres.md).

### 11.1 Schema changes during an update

`rolling-update.sh` (Compose), `apply.sh` (Kubernetes) and a re-run of `install-native.sh`
(native and cloud) update the database before the services, and stop if that fails. Nothing to
do.

- **On a mesh**, every data center is updated on its own: each database records its own
  schema version.
- **On a pair**, only the primary's database is updated; the standby receives the change by
  streaming. On the standby the update finds nothing to do.

Each program refuses to start against a database older than it needs, and names the command
to run. A newer database is accepted, so old and new programs can run side by side during an
update.

To apply a database change by hand, see
[Manual procedures §10](manual-procedures.md#10-applying-a-schema-change-by-hand).

---

## 12. Cloud deployment (AWS)

One command creates the network, the disks and the servers on AWS, one server per data center
plus any standbys. Each server starts from Alpine's own image and installs FastPKI by itself
when it first starts, from fastpki.com, which answers over IPv6. Before anything downloaded
runs, it checks the release signature against the public key in your own copy of the
repository (`docs/release-keys/`). A cloud server is an ordinary native install (§7).

Steps 1 to 5 run on **your own computer**; the rest run on the servers or from your own
computer, as each step says. Which steps you need:

| You are building | Steps |
|---|---|
| one server | 3 to 8 |
| one data center with a standby | 3 to 8, then 12 |
| several data centers | 3 to 12 |

Add steps 1 and 2 only if you build your own image.

**What one server uses**, measured on a `t3.micro` after ten minutes idle: a load average of
0.00, 239 MB of memory of its 924 MB, and two 1 GB disks with 264 MB used on the system disk and
64 MB on the data disk. [`deploy/cloud/README.md`](../deploy/cloud/README.md) describes what
gets created.

### Before you start

On your own computer install `opentofu` and the AWS command line tool (`packer` and Docker
only if you build your own image). Every command below runs from the top of the repository.

1. **An AWS profile**, so this deployment stays apart from any other account you use:
   ```bash
   aws configure --profile fastpki      # key id, secret, region, output=json
   aws sts get-caller-identity --profile fastpki
   export AWS_PROFILE=fastpki
   ```
   Write down the account number it prints; step 3 asks for it, and the deployment then
   refuses to touch any other account. The user needs `AdministratorAccess`, because the
   deployment creates a network, firewall rules, disks and servers.
2. **An SSH key pair in AWS.** Step 3 asks for its name. Write the key to a temporary file
   first, so a failure cannot empty a key you already have:
   ```bash
   aws ec2 create-key-pair --region us-east-1 --key-name fastpki-cloud \
       --key-type ed25519 --query KeyMaterial --output text > /tmp/fastpki-cloud.pem
   install -m 600 /tmp/fastpki-cloud.pem ~/.ssh/fastpki_cloud_ed25519 && rm -f /tmp/fastpki-cloud.pem
   ```
   You log in to a server as the user `alpine`.
3. **On the AWS free plan**, only a few server types start, and the default one is not among
   them; AWS refuses with `The specified instance type is not eligible for Free Tier`. List
   them, and answer the server-type question in step 3 with `t3.micro`:
   ```bash
   aws ec2 describe-instance-types --filters Name=free-tier-eligible,Values=true \
       --query 'InstanceTypes[].InstanceType' --output text
   ```

### Step 1 — prove the image builds, without AWS (only if you build your own image)

Only needed when the servers will have no internet at their first start: an image with FastPKI
already on it downloads nothing. Most people skip steps 1 and 2.

```bash
packer init deploy/cloud/image
sh deploy/native/build-check.sh              # the build, in a container on your computer
deploy/cloud/image/build-qemu.sh             # the same build, as a bootable disk image
deploy/cloud/boot-check.sh                   # boot it and check the first start
```

The last two need `qemu-system-x86_64`, `packer`, UEFI firmware (the `ovmf` package) and your
user in the `kvm` group, on a real Linux machine rather than a virtual one.

### Step 2 — build the machine image (only if you build your own image)

```bash
packer build -only=fastpki.amazon-ebs.alpine -var 'release=1.2.3' deploy/cloud/image
```

`release` is any label; it becomes part of the image name. With changes you have not
committed, add `-var 'source_ref=<commit or tag>'`. On the free plan, add
`-var 'instance_type=m7i-flex.large' -var 'source_ami_arch=x86_64'`, and use an Intel server
type in step 3. It takes about 15 minutes and prints the image id; give that to step 3.

### Step 3 — create the deployment

```bash
deploy/cloud/cloud-install.sh
```

It asks questions, saves the answers in `deploy/cloud/aws/terraform.tfvars`, shows what it
will create, and creates it when you confirm. Where they overlap, they are the Docker
installer's questions (§3.1), in its order: key storage, the protocols, each service's key
type and the SCEP RA key size, and for your own HSM its module path and token label. Answers
that matter most:

- **Public name** — one name, or one per data center, comma separated.
- **Number of data centers** — one server each. Answering `2` gives two data centers, not a
  server and its standby. Not asked when you gave one public name per data center: the
  installer counts the names. Each server goes in a different availability zone.
- **Which data centers get a standby** — for example `1`, or leave it empty. Both servers of
  that data center get the key tunnel (`P11_TLS`), and step 7 must create its CAs replicable.
- **Who may reach the console** — the administrators' address ranges, which reach SSH and the
  console. **Who may reach the enrolment protocols** — the clients' ranges, which reach the
  protocols and the console, where users download their device profiles. The console asks
  every user to log in. SSH is open to the administrators' ranges only.
- **Console port** — `443` needs no port number in the address.
- **Public IPv4 addresses** — answer no, and the servers are reachable over IPv6 only, which
  saves the IPv4 charge. Answer no only if everyone who needs the servers has IPv6.

Each server's hostname is its name in the EC2 console: `<deployment name>-1`, `-2` and so on,
and `-1-standby` for a standby.

Then read what it created:

```bash
tofu -chdir=deploy/cloud/aws output   # console_urls, node_public_ipv6, mesh_join, standby_join
```

Keep `-chdir`: without it `tofu output` finds no state and prints `No outputs found`.

**Check that each server finished its first start**, for each address in `node_public_ipv6`:

```bash
ssh -i ~/.ssh/fastpki_cloud_ed25519 alpine@SERVER-ADDRESS doas cat /var/log/fastpki-firstboot.rc
```

It prints `0` when the server is ready. Any other number means a step failed, and
`/var/log/fastpki-firstboot.log` says which. No file yet means it is still running.

The clock is set up for you: each server uses the Amazon Time Sync Service, which answers from
inside the network without a route to the internet. `doas grep -i 'selected source'
/var/log/messages | tail -2` shows it; do not check it with `ping`, which it does not answer.

### Step 4 — publish the addresses in DNS

With a Route 53 zone given in step 3, the records are published for you. Otherwise point each
server's public name at its address, as a plain DNS record (not behind a CDN, which does not
carry FastPKI's ports):

```bash
tofu -chdir=deploy/cloud/aws output node_public_ipv6    # or node_public_ips, with IPv4
```

The addresses survive stopping, starting and replacing a server.

⚠️ **A data center with a standby publishes one shared address instead**, which moves to the
standby when it takes over, so a failover changes nothing outside. Create it before you publish
anything, on your own computer:

```bash
deploy/cloud/aws-ha-address.sh create --deployment fastpki --node 1 \
    --ssh alpine@PRIMARY-ADDRESS -i ~/.ssh/fastpki_cloud_ed25519
deploy/cloud/aws-ha-address.sh show   --deployment fastpki --node 1
```

`--deployment` is the deployment name from step 3 (`grep deployment_name
deploy/cloud/aws/terraform.tfvars`), and `--node` the data center the pair belongs to. `create`
prints an IPv6 address: that is what the data center's **AAAA** record holds. Each machine
keeps its own address too, for logging in. After a failover, `aws-ha-address.sh move` carries
the shared address to the survivor ([`high-availability.md`](high-availability.md) §4a).

With IPv6 only, check the record as AAAA: `dig AAAA pki.example.org +short`.

### Step 5 — open the console and change the admin password

```bash
tofu -chdir=deploy/cloud/aws output console_urls
```

Sign in as `admin` / `admin` and set a new password. With several data centers, `admin` is one
account across the mesh once they are joined in step 10: the join keeps data center 1's
password, and the next sign-in on any server asks for a new one.

The browser warns about the certificate, because no CA exists yet: accept it once (in Firefox,
**Advanced → Accept the Risk and Continue**). If there is no such button, the browser has been
told this name is always valid HTTPS; open the server by its address instead.

### Step 6 (mesh only) — tell every server about the others, part one

Do this **before** creating any CA: every certificate names one address per data center known
when it is issued. From your own computer:

```bash
deploy/mesh-join.sh -i ~/.ssh/fastpki_cloud_ed25519 \
    alpine@DC1-ADDRESS+alpine@DC1-STANDBY-ADDRESS alpine@DC2-ADDRESS
```

One argument per data center; write a data center with a standby as
`alpine@PRIMARY+alpine@STANDBY`, and leave `+…` out where there is none. It stops, because no
CA exists yet:

```
mesh-join: pass 1 done: every data center knows the others and publishes
mesh-join: stopped: these data centers have no issuing CA of their own yet: 1 2
```

That stop is expected. If `fastpki-mesh` reports `timeout expired` instead, see §13.

### Step 7 — create your CAs

In the console, as §4.3. With several data centers: one root CA, and one issuing CA per data
center, signed by that root (§9.0 steps 5 to 7).

⚠️ **Tick replicable key on every CA of a data center with a standby.** It applies to each CA
on the server that holds its key, so with a standby in data center 1 only:

| CA | lives on | replicable key? |
|---|---|---|
| the root | server 1 | **yes** — server 1 has a standby |
| `dc1-sub` | server 1 | **yes** |
| `dc2-sub` | server 2 | no |

It cannot be turned on afterwards. To create the CAs from the command line instead, see
[Manual procedures §3](manual-procedures.md#3-creating-cas-from-the-command-line).

### Step 8 — issue the service certificates

On each server, as the `fastpki` user:

```bash
doas su -s /bin/sh fastpki -c \
    'fastpki-ca --config /etc/fastpki/bootstrap.conf renew-service-certs --create-missing --re-issue-self-signed --replicable'
for s in ocsp cmp scep est acme ms web; do doas rc-service fastpki-$s restart; done
```

Remove `--replicable` on a server whose data center has no standby. A server listed as having
a standby has `SERVICE_KEYS_REPLICABLE=true`, so its nightly job also creates copyable keys.
If you already ran it without the flag where it was needed, see
[Manual procedures §5](manual-procedures.md#5-replacing-the-ocsp-cmp-and-scep-keys-with-copyable-ones).

One server with no standby is now finished; test it with §6.

### Step 9 (mesh or standby) — give each database its certificate

Done for you by the commands in steps 10 and 12. Nothing to run.

### Step 10 (mesh only) — tell every server about the others, part two

Run the step 6 command again. This time it issues each database certificate, connects the
data centers, and ends with `done: every data center holds N certificates, and each is
subscribed to the other`.

### Step 11 — check every server holds the same data

Step 10's command checks this itself. To check by hand, on every server as `alpine`, the number
must be the same:

```bash
doas su postgres -s /bin/sh -c "psql -tAc 'select count(*) from certs' fastpki"
```

§9.6 covers counts that do not settle. Then issue a certificate end to end with §6.

### Step 12 (standby only) — join each standby to its primary

From your own computer, once for each standby:

```bash
deploy/ha-join-pair.sh --primary alpine@PRIMARY-ADDRESS --standby alpine@STANDBY-ADDRESS \
    -i ~/.ssh/fastpki_cloud_ed25519
```

It ends with `done: … streams from … and holds the CA keys.` It is safe to run again. Then
test a failover ([`high-availability.md`](high-availability.md) §4 step 5) before you rely on
it.

### Changing the deployment later

Your answers are saved in `deploy/cloud/aws/terraform.tfvars`. Edit the file, then:

```bash
tofu -chdir=deploy/cloud/aws plan     # shows what would change
tofu -chdir=deploy/cloud/aws apply    # makes the change
```

⚠️ **Read the plan for the words "destroy" and "replaced" before you confirm.** Adding a
standby or changing who may reach the servers changes nothing that runs. Changing an answer a
server was given when it first started — the protocols, the console port, its data center
number — replaces that server. A replaced server loses its database password and key store
PIN, which live on its system disk, so it cannot open its own database and refuses to start.

**To update a deployment that holds a CA**, leave the servers where they are and install the
new release on them as a package ([`admin-guide.md`](admin-guide.md) §14.4).

Replacing servers is for a deployment you will build again from nothing. The data disks carry
`prevent_destroy` in `deploy/cloud/aws/instances.tf`; to start from nothing on purpose, set it
to `false` for one apply, name the disks to replace, and set it back:

```bash
tofu -chdir=deploy/cloud/aws plan -out=rebuild.tfplan \
    -replace='aws_ebs_volume.data["1"]' -replace='aws_ebs_volume.standby_data["1"]'
tofu -chdir=deploy/cloud/aws apply rebuild.tfplan
```

A replaced server has a new SSH host key; remove the old one with `ssh-keygen -R ADDRESS`.

### Testing it

The demo enrols over every protocol against a running deployment, from your own machine, and
the bench measures issuance rates:

```bash
demo/provision-target.sh --web-url https://dc2.example.org \
    --admin-pass 'CURRENT-ADMIN-PASSWORD' \
    --challenge-fqdn client.example.org --ssh-target alpine@dc2.example.org \
    --out demo/.target-dc2.env
demo/pki-demo.sh  --target demo/.target-dc2.env
demo/pki-bench.sh --target demo/.target-dc2.env
```

- `--web-url` is one data center's console. Run it once per data center you want to test.
- `--ssh-target` lets the demo test ACME dns-01. The login must be able to run `doas`, which
  the `alpine` user on a cloud server can.
- `--challenge-fqdn` is a name the deployment resolves to the machine running the demo. The
  ACME http-01 and tls-alpn-01 checks need it, because the server connects back to that
  machine on ports 80 and 443. A machine behind NAT with no inbound route fails those two
  checks, and only those two.
- The names in the certificates must resolve on the machine running the demo, because it
  checks every certificate against its revocation list.

[`demo/README.md`](../demo/README.md) has the details, including how to run the SCEP and CMP
checks, which need the test clients from the test image.

### Tearing it down

**From your own computer**:

```bash
deploy/cloud/cloud-install.sh --destroy
```

This deletes the servers, the network cards and the network. It **keeps the data disks**,
standbys' included: they hold every certificate you issued and, unless you use a hardware
security module, every CA private key. It ends by listing them:

```
Kept in AWS, unattached and still billed: vol-0a1b2c3d4e5f60718 vol-0f1e2d3c4b5a69788
```

A kept disk cannot be started again, because its database password was on the deleted system
disk; keep it as an archive you can mount and read. The next `cloud-install.sh` run creates new
disks. Deleting a kept disk is a separate command:

```bash
aws ec2 delete-volume --volume-id vol-...
```

---

## 13. Troubleshooting

### The console sits on "Loading dashboard…" and never finishes

On a native or cloud server, the key store has run out of sessions. Check, as `alpine`:

```bash
for f in /proc/[0-9]*/comm; do doas cat $f; done | grep -c p11-kit-remote
```

A number near 128 means it is at its limit. Restart it; every service reconnects by itself:

```bash
doas rc-service fastpki-token restart
```

On a healthy server the number stays in single digits. If it climbs steadily, something is
leaking sessions.

### A native or cloud node runs out of memory, and PostgreSQL will not start again

Everything that uses the database fails with `Connection refused`. Check, as `alpine`:

```bash
ls -d /proc/[0-9]* | wc -l                     # about 100 is normal
free -m
doas dmesg | grep -i "out of memory" | tail
```

Several hundred processes, nearly all `p11-kit-remote`, mean a restart loop filled the memory
and the kernel stopped PostgreSQL. Repair it in this order; the order matters:

```bash
for s in web ocsp est acme cmp ms scep store pgtls p11-tls; do doas rc-service fastpki-$s stop; done
doas rc-service fastpki-token stop
doas pkill -f p11-kit-remote
doas rc-service postgresql zap                 # clears the "crashed" state
doas rc-service fastpki-pgstale restart        # removes the socket file the stopped server left
doas rc-service postgresql start
doas rc-service fastpki-token start
for s in web ocsp est acme cmp ms scep store pgtls; do doas rc-service fastpki-$s start; done
```

`fastpki-pgstale` is required: without it PostgreSQL refuses with `Socket conflict. A server
is already listening`, when nothing is. It also runs at every boot, so a simple reboot needs
none of this.

### CMP refuses every transaction, or OCSP answers `internalerror`

The services started before their certificates existed (§4.4). Restart them, including the
three without an HTTPS certificate of their own:

```bash
docker compose restart ocsp cmp scep est acme ms web
```

Native or cloud: `for s in ocsp cmp scep est acme ms web; do doas rc-service fastpki-$s restart; done`.

### A protocol answers `403 forbidden: this account may not enrol`

The user has no role that allows enrolment over that protocol against that CA. Give it the
`requester` role; `standard` does not enrol:

```bash
docker compose exec web fastpki-config --config /app/config/bootstrap.conf \
    web-user alice 'PASSWORD' --role requester
```

### A client elsewhere says `unable to get certificate CRL`, but the same check passes on the server

```
error 3 at 0 depth lookup: unable to get certificate CRL
```

The revocation list address in the certificate uses a name that works only on the server
itself. The address comes from `BASE_URL`, or from `PKI_DNS` if that is unset. Set a name your
clients can resolve, and re-issue anything that must be checked from elsewhere, since issued
certificates keep their address:

```bash
docker compose exec web fastpki-config --config /app/config/bootstrap.conf set BASE_URL https://pki.example.org
docker compose restart ocsp est cmp scep acme ms web
openssl x509 -in leaf.pem -noout -ext crlDistributionPoints    # what a new certificate carries
```

### `curl -fsSL .../releases/latest/download/install.sh` returns 404

The one-command install works only from a public release. Download the release yourself
(`gh release download <tag>`), check `SHA256SUMS` and its signature, and run
`deploy/install.sh` from it.

### Locked out of the console

A wrong setting can make the console unreachable, and then you cannot use it to fix the
setting. Every setting is also in the database, so change it with `fastpki-config`, which
needs only the database:

```bash
cd deploy
cfg() { docker compose run --rm --no-deps --entrypoint fastpki-config web \
          --config /app/config/bootstrap.conf "$@"; }
cfg get   WEB_CLIENT_CA_ID     # what is set
cfg unset WEB_CLIENT_CA_ID     # remove it
docker compose restart web
```

`unset` returns a setting to the file's value or the built-in default. If it is still set, it
is also in `.env` or `bootstrap.conf`, which you edit by hand.

### A mesh server cannot reach its peer (`timeout expired`)

On AWS, each server reaches the other data centers through its second network interface,
`eth1`. Ask how it reaches a peer, on data center 1:

```bash
ip route get 198.51.100.10     # data center 2's interconnect address
```

It must answer `… dev eth1 …`. An answer naming `dev eth0` is the fault: only traffic from
another interconnect interface is allowed. The first start adds these routes and keeps them
across reboots; `/var/log/fastpki-firstboot.log` has an `interconnect:` line saying which it
added. To get going, add them by hand on both sides, through each server's own interconnect
router, the `.1` address of its `eth1` subnet:

```bash
doas ip route replace 198.51.100.0/24 via 192.0.2.1 dev eth1     # on data center 1
doas ip route replace 192.0.2.0/24 via 198.51.100.1 dev eth1     # on data center 2
```

### Other common problems

| Problem | Fix |
|---|---|
| The browser refuses the client certificate step, or asks for a certificate you do not have | the console is set to accept client certificates: `cfg unset WEB_CLIENT_CA_ID` (and `WEB_CLIENT_CA_BUNDLE`, `WEB_CLIENT_CA`) as above, and restart it. With none set, the console never asks |
| Every change in the console is refused | `WEB_ALLOW_REVOKE` was set to `false`. `cfg set WEB_ALLOW_REVOKE true` and restart the console |
| EST, ACME or MS does not start | its protocol is not listed in `COMPOSE_PROFILES`, or it is switched off (the log says `est is switched off (EST_ENABLED=false) — not listening`), or this server's data center row is missing |
| CMP rejects everything | set `CMP_CLIENT_CA_ID` (§4.4); for password-protected requests, check the user has an enrolment secret |
| ACME gives out the wrong addresses | set `BASE_URL` to your public `https://` address |
| Issued certificates' OCSP or CRL addresses are unreachable | `BASE_URL`, or a data center's address, names something clients cannot reach. `fastpki-ca urls YOUR-CA-ID` prints what is being issued |
| Console issuance returns `specify ?ca_instance=<id>` | issuance names a CA; there is no default |
| Console issuance fails for the CA it named | 404: no such CA. 409: the CA is disabled, expired or revoked. 500 `CA material unavailable`: its key cannot be loaded; check `PKCS11_MODULE` and the key store |
| Another server cannot download the image, `http: server gave HTTP response to HTTPS client`, with Docker | that server does not trust your registry (§3.3) |
| The same, on Kubernetes | declare the registry to k3s on every machine (§8.4); Docker's settings do not apply |

`config/bootstrap.conf.example` describes every setting, and [`user-guide.md`](user-guide.md)
§6–§10 has client examples for every protocol.
