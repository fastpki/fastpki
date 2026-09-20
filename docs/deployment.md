# FastPKI — Deployment Guide

This guide takes you from a clean host to a running FastPKI installation serving
every protocol. The fastest path is the **`./install.sh` wizard** (§3.1), which asks a
few questions and writes this node's config; §3.2 is the same thing done by hand with
Docker Compose. A from-source / OpenRC path (Alpine only) is in §7, and Kubernetes is §8.

> FastPKI is **not** a single daemon. Each protocol is its own binary/process
> (OCSP, EST, ACME, CMP, MS-XCEP/WSTEP, SCEP, the RFC 4387 store, and the web
> console). They share one **config file**, one **database**, and the **CAs registered
> in that database** — every CA is a row in `certs`, and every enrolment path names its
> id. You start the ones you need. This is the most important thing to understand
> before deploying — there is no `fastpki serve` that runs everything; you run (or
> compose) one service per protocol.

## Contents

| Section | |
|---|---|
| [**1. Architectures**](#1-architectures) | which shape to deploy |
| [**2. Components & ports**](#2-components--ports) | what each binary is and where it listens |
| [**3. Quick start**](#3-quick-start) | the wizard, by hand with Compose, or several nodes from a registry |
| [**4. First run: bootstrap, then create the CA**](#4-first-run-bootstrap-then-create-the-ca) | certgen, bootstrap, the CAs, service TLS, the first admin |
| [**5. Configuration**](#5-configuration) | the keys that matter and where they live |
| [**6. First issuance (smoke test)**](#6-first-issuance-smoke-test) | prove the deployment issues before trusting it |
| [**6a. High availability: add a standby server**](#6a-high-availability-add-a-standby-server) | a second server that takes over when the first is lost, step by step, a failover test, rebuilding the old primary as the new standby, and switching back |
| [**7. Native install — Alpine + OpenRC (no Docker)**](#7-native-install--alpine--openrc-no-docker) | the same binaries on a host, with the patched PKCS#11 stack |
| [**8. Kubernetes**](#8-kubernetes) | three walkthroughs — **one node (8.0)**, **a pair for HA (8.0b)**, **a data center (8.0c)** — then the reference behind them |
| [**9. Multi-data-center**](#9-multi-data-center) | **add a data center step by step (9.0)** — then the reference behind it: establishing trust, confirming every data center holds the same data, growing into a mesh, and what to do when they do not |
| [**10. TLS / reverse proxy**](#10-tls--reverse-proxy) | terminating in front of the services |
| [**11. Day-2 operations**](#11-day-2-operations) | updates, backups, schema changes |
| [**12. Cloud deployment (AWS)**](#12-cloud-deployment-aws) | twelve steps from an empty account to a working mesh: prerequisites, the AMI, the apply, DNS, the CAs, replication |
| [**13. Troubleshooting**](#13-troubleshooting) | symptom to cause |

Deploying one node: §3 then §4, and stop. Adding a standby server to it: §6a. Adding data centers: §9. Something is already
broken: §13, or §9.6 when it is replication.

---

## 1. Architectures

The published image covers both **linux/amd64** and **linux/arm64**. `docker pull` picks the
right one for you, whether you are on an Intel server, an Apple Silicon Mac or an AWS
Graviton machine. You do not have to say which you want.

Both are also published under their own names, `:<version>-amd64` and `:<version>-arm64`, so
you can say exactly which one you mean when something goes wrong with only one of them.

Every release also comes with a ready-built image file, one per processor type. On a machine
where building from source is slow, load one instead: the build compiles four C and C++
projects, which on a small server is the difference between half an hour and a few seconds.

```bash
docker load  -i fastpki-<tag>-image-amd64.tar.gz   # or -image-arm64.tar.gz
docker image ls fastpki                       # the tag it loaded, for FASTPKI_IMAGE
```

Loading a file is for a machine that cannot reach `ghcr.io`. When the server has internet
access you do not need it: installing from a release downloads the published image already.

⚠️ **The installer in §3.1 will not use an image you loaded.** It decides from the name you
give it as `FASTPKI_IMAGE`. A plain name such as `fastpki:local` is always built from source.
A name with a `/` in it, which means a name on a registry, is always downloaded. Either way,
your loaded image is replaced. To use the one you loaded, install with Compose by hand
(§3.2): put its name in `.env` as `FASTPKI_IMAGE`, and do not run `docker compose build`.

---

## 2. Components & ports

| Service | Binary | Default port | Terminates its own TLS? |
|---|---|---|---|
| Web console | `fastpki-web` | 8090 | Yes — required by WebCrypto API |
| OCSP + CRL | `fastpki-ocsp` | 8080 | No |
| EST (RFC 7030) | `fastpki-est` | 8443 | **Yes** (`EST_CERT`/`EST_KEY`) |
| ACME (RFC 8555) | `fastpki-acme` | 8444 | **Yes** (`ACME_CERT`/`ACME_KEY`) |
| CMP (RFC 4210/9810) | `fastpki-cmp` | 8445 | No |
| MS-XCEP / WSTEP | `fastpki-ms` | 8446 | **Yes** (`MS_CERT`/`MS_KEY`) |
| RFC 4387 store | `fastpki-store` | 8447 | No |
| SCEP | `fastpki-scep` | 8448 | No |

EST, ACME and MS speak HTTPS directly (the protocols/clients require it), so they need
a server cert+key. **So does the web console**, for a different reason: the in-browser
key generation and the HSM slot picker are Web Crypto, which browsers only expose
in a secure context — over plain HTTP those features vanish rather than merely being
unencrypted. OCSP, CMP, SCEP and the cert store speak plain HTTP and should sit behind a
reverse proxy that terminates TLS — your infrastructure, not shipped with FastPKI.

**Command-line tools** (same image, no listening port): `fastpki-ca` (create/manage
CAs), `fastpki-config` (DB config + backup/restore, incl. `web-user` for console and
EST/MS logins), `fastpki-audit`, `fastpki-notify`, `fastpki-update`, `fastpki-discover`,
`fastpki-mesh`, and `fastpki-mcp` (the PKI inventory for MCP clients, over stdio).

---

## 3. Quick start

### Before you start: install Docker

The installer needs **Docker Engine** with the **Compose plugin** (the `docker compose`
command). Your user must also be able to run Docker **without `sudo`**. A new server
usually has neither, so do these steps first.

1. Install Docker Engine and the Compose plugin. Follow Docker's guide for your Linux
   distribution: <https://docs.docker.com/engine/install/>.
2. Let your user run Docker:
   ```bash
   sudo usermod -aG docker $USER
   ```
3. **Log out and log in again.** A new group only works in a new login session.
4. Check that it works. Both commands must run without an error:
   ```bash
   docker ps                 # prints an empty table header
   docker compose version    # prints a version number
   ```

To get FastPKI you also need `git` (to clone the repository) or `curl` (for the
one-command install below).

**Hardware for one server**

| | |
|---|---|
| **CPU** | 2 processors. Every container sits at 0% when nothing is being issued |
| **Memory** | 165 MB for all eleven containers together, once they have settled. Postgres is 84 MB of that |
| **Disk** | 556 MB for the two images (`fastpki` 132 MB, `postgres:17-alpine` 424 MB), and 48 MB of data to begin with |

These are measured, not estimates. [`architecture.md`](architecture.md#11-resource-footprint)
§11 has the same figures for the other three ways of running FastPKI, and says how each was
taken.

If `docker ps` says `permission denied while trying to connect to the docker API`, step 2
or step 3 is not done. The installer fails with the same message, at the step where it
builds the image.

### 3.1 Guided — `./install.sh`

The wizard is the whole path: it asks a handful of questions, writes this node's
`deploy/.env`, and then **completes the installation** — build, start Postgres (certgen
issues the transport certificate first), bootstrap the database and seed `admin/admin` (which must be changed at first login),
start the rest. It needs **bash + coreutils only, docker for compose install** — no python, no bc — so it works on a
bare, freshly-provisioned server.

```bash
# from a clone:
cd FastPKI/deploy
# from a downloaded release tarball — it unpacks to fastpki-<tag>/, NOT FastPKI/,
# and the tag carries its leading v (fastpki-v0.1.0.tar.gz -> fastpki-v0.1.0/):
tar xzf fastpki-v0.1.0.tar.gz && cd fastpki-v0.1.0/deploy

./install.sh                          # interactive — installs
./install.sh --k8s                    # deploy to Kubernetes instead of compose
./install.sh --answers node2.env      # non-interactive (CI, or the next DC)
./install.sh --no-deploy              # write .env only, print the commands instead
./install.sh --answers node2.env --print-env   # write nothing, just show the .env
```

#### Without a checkout — one command

The same script bootstraps itself. Piped, it fetches the release tarball, **verifies it
against the published `SHA256SUMS`**, unpacks it and re-execs itself from there, so the
one-liner and the checkout run identical code:

```bash
URL=https://github.com/fastpki/fastpki/releases/latest/download/install.sh

curl -fsSL $URL | bash                                # latest release
curl -fsSL $URL | bash -s -- --version v0.1.0         # pinned (the tag, leading v included)
curl -fsSL $URL | bash -s -- --k8s --non-interactive  # unattended, Kubernetes
```

`--dir` chooses where the tree lands (default `./fastpki-<version>`).

The asset above is a copy of `deploy/install.sh` from the tagged tree — release assets have
no directories, so it is published flat while living under `deploy/` in the repository.
There is no `install.sh` at the repository root, and a raw URL would need
`.../deploy/install.sh`.

#### The first question: `single` or `cluster`

They are about **how many data centers**, not about redundancy:

| | Means |
|---|---|
| `single` | One data center. This is still the right answer when you want a second server for failover, because you set that up on the other server, not here (`deploy/ha-join.sh`, and `high-availability.md`). Remember that with the key store that ships with FastPKI, the CA key lives on this server only. A second server can take over reading, but it cannot issue certificates. |
| `cluster` | **Several** data centers, all of them issuing, all copying to each other. It then asks for this server's number, from 1 to 32767. Every certificate this server issues carries that number in its serial number, so two data centers can never produce the same serial. |

`cluster` is therefore not a synonym for high availability, and choosing `single` does not
rule it out.

The wizard does not ask about a standby at all — there is nothing to answer here, because a
standby is set up on the *other* host. It says so as it asks the question above:

```
  single  - ONE data center. To survive losing this host, a second host joins
            it as a streaming standby later: deploy/ha-join.sh, see docs/high-availability.md.
  cluster - SEVERAL data centers replicating active-active, each with its own
            serial prefix. Neither answer gives you host or HSM failover.
```

To put a standby on a second host, which is the arrangement that survives losing this one,
install the release there, answering yes to the standby question, and join it from your own
computer with `deploy/ha-join-pair.sh`. §6a is the step-by-step guide for Compose (`high-availability.md` §3 explains each step, §4 covers a native pair).

Either answer records this server as a data center in its own right, so it can issue
certificates straight away. A single server is data center 1. That means its serial numbers
carry a data center number from the very first certificate, so if you add data centers later,
nothing it issued before sits outside the numbering.

If you answered `cluster`, §9.1 is the sequence that adds the other data centers and sets up
the copying between them. The installer points you there rather than printing the commands.
§9.3 covers the Kubernetes version, and §9.2 is how you confirm every data center holds the
same data.

To add a second server for failover, do it on that second server: install the release there
and run `./ha-join.sh <this host> primary-ca.crt`. Then list both addresses in `PG_CONNINFO`
on both servers, so that if one takes over, the services move across without being restarted.
`high-availability.md` §3 has the sequence.

Independent of `single`/`cluster`: a single data center can have it, and a mesh node can
decline it.

Two behaviours to be aware of before running it:

- **The download is checked.** A mismatch against `SHA256SUMS` aborts before anything is
  unpacked, and a missing `SHA256SUMS` is refused rather than skipped.
- **It will not answer its own questions.** `| bash` spends stdin on the script itself, so
  the wizard re-attaches your terminal. Where there is no terminal — CI, a provisioning
  script — an interactive run is *refused* instead of silently taking every default; pass
  `--answers <file>` or `--non-interactive`.

The installer runs these four itself. The order is required: certgen runs as Postgres comes up so that the app↔DB link
is TLS from first boot, and bootstrap must land after Postgres accepts connections and
before the rest of the stack starts. A step that fails stops the run and says which one,
rather than leaving a half-installed deployment with no error anywhere. A box where
`docker` is not installed still writes its `.env` and says so.

What it asks:

| Question | Why it matters |
|---|---|
| **Deployment** `single` / `cluster` | For a cluster it also asks this node’s **index**, and that is the only mesh question. The index is the node’s serial prefix: it goes into `.env` as `DATACENTER_ID` and into the `datacenters` table as the top 2 octets of every serial this node assigns, so two data centers can never produce the same serial. It must be unique per data center, and between 1 and 32767 — a DER integer is signed, so a prefix with the high bit set would push the serial past the RFC 5280 §4.1.2.2 limit. Per data center, not per host: the two hosts of an HA pair carry the same index, because a pair is one data center twice (`high-availability.md`). **There is no “number of data centers” to declare**: nothing is sized by it, so adding a fourth site later needs nothing from the first three. |
| **Container image** (`FASTPKI_IMAGE`) | Where this server gets the FastPKI container image. **Press Enter.** When you installed from a release, the default is that release's published image and the installer downloads it, which takes seconds. When you installed from a source checkout there is no published image to name, so the default is `fastpki:local` and the installer builds it on this server — that works with nothing else set up, but it compiles four C/C++ projects and is slow. The rule the installer follows is the name itself: a name containing `/`, such as `registry.example.org/fastpki:1.0`, is **downloaded** from that registry; a plain name such as `fastpki:local` is **built**. Run `docker login` first if the registry is private. Name your own registry when you build once and install many servers from it (§3.3). |
| **Public FQDN** (`PKI_DNS`) | The DNS name that clients use to reach this server, for example `pki.example.org`. The console is at `https://<this name>:8090`. The name is also written into certificates, as the address where clients download the CRL and the CA certificate. So it must resolve on **every** machine that checks those certificates, not only on this server. A CA certificate keeps this address for its whole life, so get the name right before you create a CA (§4.3). |
| **Postgres publish address** (`PG_BIND`) | The address where this server's database port (5432) is published. **On a single server, keep `127.0.0.1`**: only this server can connect to the database. **If you will add an HA standby (§6a), enter this server's own IP address** on the network the standby shares, for example `192.0.2.10`. The standby connects to the database on this address, and `127.0.0.1` cannot be joined. Decide now: changing it later means re-issuing the database certificate. On a cluster node, also enter this server's IP address that the other servers can reach. The address is also added to the database certificate, so the other servers can verify it. |
| **Will this data center have a standby** (`HA_ENABLED`) | Answer yes if a second server will later take over from this one ([`high-availability.md`](high-availability.md)). It turns on the key tunnel (`P11_TLS=on` and the `p11tls` service), so the standby can be given copies of the CA keys, and creates the OCSP, CMP RA and SCEP RA keys copyable (`SERVICE_KEYS_REPLICABLE=true`). **Decide before any CA exists**: a key is copyable or not from the moment it is generated, and those keys are generated as soon as a CA exists. It needs `PG_BIND` to be this server's own address, because the standby connects to Postgres there. The native installer asks the same question, Kubernetes has the same setting, and on AWS listing the data center in `standby_dcs` answers it. |
| **Key storage** `softhsm` / `hsm` | Where private keys live. `softhsm` (default) uses the bundled container; `hsm` takes the absolute path of your own PKCS#11 module. **There is no "file" option** — a private key belongs in a token (§4). |

**Every node of a mesh is installed exactly the same way.** There is no "first node" mode
and no second procedure: run the same `install.sh`, answer `cluster`, and change only
three answers per node — `DC_INDEX` (this node's index, which becomes its serial prefix),
`PKI_DNS` (that node's own FQDN) and `PG_BIND` (that node's own interconnect address).
`FASTPKI_IMAGE` is the same everywhere. So an answers file for node 2 is node 1's with three
values changed:

```bash
printf 'DEPLOYMENT=cluster\nDC_INDEX=2\nFASTPKI_IMAGE=%s\nPKI_DNS=%s\nPG_BIND=%s\n' \
    registry.example.org/fastpki:1.0 pki-dc2.example.org 198.51.100.10 > node2.env
./install.sh --answers node2.env
```

⚠️ `PKI_DNS` and `PG_BIND` are **that node's**, never a copy of node 1's. Copying them
gives every data center the same public name, and each one then issues and serves under a
name that belongs to another host.

**Key storage in more detail.** With `softhsm`, `docker compose up -d` starts the
container, which initialises token `fastpki` and serves it over `/run/p11/pkcs11.sock`
via p11-kit — so no application ever loads SoftHSM in-process, which is the
combination that deadlocks. That is dev/test posture. For production choose
`hsm` and give the wizard your vendor's module path; it is written to
`PKCS11_MODULE` and loaded directly. The wizard rejects a bare module *name*,
because a non-path only fails much later, at first key use.

**When it finishes**, skip §3.2, which is the same work done by hand, and continue at §4.3
to create the CAs (§9.1 on a cluster).

### 3.2 Manual — Docker Compose

Everything below uses the files in `deploy/`. From a clean Linux host with Docker:

```bash
# 1. Get the source (production: clone the repo; the Dockerfile self-vendors deps)
git clone https://github.com/fastpki/fastpki.git
cd FastPKI/deploy

# 2. Edit the install-time seed (see §5 for the keys that matter)
$EDITOR bootstrap.compose.conf

# 2b. Per-node / per-deployment settings go in an untracked .env — compose injects it
#     into every container, and this is where the hostname lives. REQUIRED even for a
#     single node: PKI_DNS is your public FQDN, and it is written into every certificate
#     as its CRLDP and AIA URL, so a short hostname resolves on this node and nowhere a
#     relying party runs; certgen is fail-closed without FASTPKI_PIN and postgres waits
#     on certgen completing, so step 3 never starts without it; and POSTGRES_PASSWORD
#     otherwise falls back to the well-known compose default. Fill in all three.
#     Multi-datacenter: also set THIS node's DATACENTER_ID + PG_BIND (the serial prefix
#     comes from the datacenters table, not from .env).
cp .env.example .env && $EDITOR .env

# 3. Build the image, generate the transport cert, then start the database.
#    certgen runs BEFORE postgres: it makes ONE self-signed cert used for
#    both app<->DB TLS and the console, so the deployment is encrypted from first
#    boot even before a CA exists (§4). postgres then starts with TLS.
docker compose build
docker compose run --rm certgen
docker compose up -d postgres
docker compose exec postgres sh -c 'until pg_isready -U fastpki; do sleep 1; done'

# 4. ONE-TIME bootstrap: prepares the shared pki-data volume and seeds the default
#    admin. admin/admin works for the FIRST console sign-in only: the row is seeded
#    must_reset, so the console allows nothing but the password change until you set
#    one, and pki::authenticate() refuses the row entirely, so the seeded password
#    cannot enrol a certificate over EST/MS/SCEP/CMP either. That one
#    web_users row serves the console AND EST/MS Basic auth. No CA — see §4.
docker compose run --rm bootstrap

# 5. Bring up the console and CREATE THE CA (§4). The console self-signs its own TLS
#    and starts now. EST/ACME/MS are simply not started by this command (each sits
#    behind its own compose profile); when you bring them up in step 6 they serve on
#    self-signed transport certs of their own until you issue CA-signed ones (§4.4).
docker compose up -d postgres web
#    → create the root + issuing CA from the console, or with `fastpki-ca create` (§4),
#      then replace the console's self-signed certificate in the DB (§4.4a):
#        docker compose exec web fastpki-ca renew-service-certs --create-missing --re-issue-self-signed
#      Only the console is running yet, so this reaches only the console; step 6b runs it
#      again once the protocol listeners exist. The shipped config keeps every listener key
#      in the token, so there are no .crt/.key files to write.

# 6. Start the services you deploy (do this once the CA exists, so enrolment works
#    immediately). EVERY protocol service carries a compose profile, so a bare
#    `up -d` starts only postgres/token/web — no enrolment, and no error saying so.
#    Name the set in .env (install.sh writes this line for you from the protocols you
#    picked):
#      COMPOSE_PROFILES=ocsp,est,acme,cmp,ms,store,scep
docker compose up -d
#    or, without editing .env:  docker compose --profile est --profile acme up -d

# 6b. Promote the listener certificates, now that the listeners exist. EST, ACME and MS
#     self-sign at first start, and §4.4a's run before this point could only reach the
#     console — the others had no container yet, and it reported them as
#     "nothing published yet; the listener creates its own at first start". Run it again
#     here and they are re-issued under the signing CA:
docker compose exec web fastpki-ca renew-service-certs --create-missing --re-issue-self-signed
docker compose restart ocsp cmp scep est acme ms web

# 7. Check. The console serves its OWN TLS: the in-browser key generation and
#    the HSM slot picker need a secure context, so plain HTTP would disable them.
#    On a fresh deployment the cert is the self-signed one certgen made (§4.1), hence -k.
docker compose ps
curl -sk https://localhost:8090/healthz && echo " web OK"
```

Open the console at `https://<host>:8090`. On a fresh deployment its certificate is
self-signed, so expect a browser warning until you replace it with a CA-issued one.
Log in with the admin created in step 4.

> **Order matters.** `fastpki-ca` needs the database schema present (Postgres loads
> `sql/createdb.sql` on first container start). EST/ACME/MS *do* start without a CA —
> each generates a key in the token and serves a **temporary self-signed** transport
> certificate, logging `serving HTTPS on a TEMPORARY self-signed cert`, until you issue a
> CA-signed one under its `*_CERT_ID` (§4.4). What they cannot do is **issue** anything
> before a signing CA exists, so create the CA first.

### 3.3 Several servers — build once, pull from a registry

For more than one host, build the image **once** and have the others pull it,
rather than building on each. The compose `image:` is parameterized by
`FASTPKI_IMAGE` for exactly this:

```bash
# On the build node, from the REPO ROOT: build through the wrapper, then push.
IMAGE=myregistry:5000/fastpki:latest sh deploy/build-image.sh
docker push myregistry:5000/fastpki:latest
```

⚠️ **Through `deploy/build-image.sh`, not a bare `docker build`.** The wrapper runs the
public-repo hygiene gate on the host first, and the host is the only place it can run:
`.dockerignore` excludes `.git/`, so the build context is not a repository and the gate has
no tracked file set to check. `tests/build_image_gated.sh` exists to stop that being
bypassed. The image is identical either way — the gate decides whether it gets built, not
what is in it.

```bash
# On every other node: allow the registry (skip for a TLS registry with a
# trusted cert), then deploy pointing at the pulled image — no build:
echo '{"insecure-registries":["myregistry:5000"]}' | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker
docker pull myregistry:5000/fastpki:latest
cd FastPKI/deploy
# This node needs its own .env, exactly as §3.2 step 2b describes: compose injects it into
# every container, and an exported shell variable does not reach them. certgen is fail-closed
# without FASTPKI_PIN and postgres waits on certgen finishing, so without it the next line
# never starts. Multi-datacenter: set this node's DATACENTER_ID and PG_BIND here too.
cp .env.example .env
$EDITOR .env        # FASTPKI_IMAGE=myregistry:5000/fastpki:latest, PKI_DNS=node2.example.org,
                    # FASTPKI_PIN=…, POSTGRES_PASSWORD=…
docker compose up -d postgres && docker compose run --rm bootstrap
# then create this node's CA + service TLS certs (§4) before the final `up -d`:
docker compose up -d
```

The build node leaves `FASTPKI_IMAGE` unset (defaults to building `fastpki:local`).
Each node runs its own bootstrap (volume + admin user), its own database, and needs
its own signing CA + service TLS certs (§4). For multi-DC, sign each node's issuing
Sub-CA from one shared offline root so every leaf chains to a single trust anchor.

**Updating these nodes later** needs no bootstrap and no CA work: push the new image, then
on each node set `FASTPKI_IMAGE` to it, `docker compose pull`, and run `./rolling-update.sh`
([`admin-guide.md`](admin-guide.md) §14.3).

---

## 4. First run: bootstrap, then create the CA

> **Did you install with `./install.sh` (§3.1)? Then 4.1 and 4.2 are already done.**
> The installer ran both for you. **Start at §4.3.**
>
> Did you follow the manual steps in §3.2? They are done there too: step 3 runs certgen
> (4.1) and step 4 runs bootstrap (4.2).
>
> To check, open `https://<your public FQDN>:8090`. If the console opens (with a browser
> warning about a self-signed certificate) and `admin` / `admin` signs in and asks you to
> set a new password, 4.1 and 4.2 are done.

A new installation has **no CA**, so it cannot issue certificates yet. But it already uses
TLS between the services and the database, and it already has a console admin. This is
the order of the work:

| Step | Performed by | Description |
|---|---|---|
| 4.1 Transport certificate | **automatic**: the installer | a self-signed certificate, so the database connection uses TLS from the start |
| 4.2 Bootstrap | **automatic**: the installer | prepares the data volume and creates the `admin` user |
| 4.3 Create the CAs | **you** | the root CA and the issuing CA |
| 4.4, 4.4a, 4.4b Service certificates and credentials | **you** | replace the self-signed certificates, and give OCSP, CMP and SCEP their credentials |
| 4.5 First console admin | **you** | sign in as `admin` / `admin` and set a new password |

Sections 4.1 and 4.2 explain what the automatic steps did. Read them when you need to
understand or repair a deployment. You do not need to run anything from them.

### 4.1 Transport certificate: `deploy/certgen.sh` (automatic, already done by the installer)

This step gives the database a certificate, so the connection between FastPKI and PostgreSQL
is encrypted from the first start, before any CA exists.

```bash
docker compose run --rm certgen
```

It creates one certificate, signed by itself, and writes three things:

| file | what it is |
|---|---|
| `/var/pki/tls/pg/server.crt` and `.key` | the certificate and key PostgreSQL uses |
| `/var/pki/tls/pg/ca.crt` | the copy every service checks that certificate against |
| `/var/pki/tls/pin` | the password to the key store, readable only by its owner |

The certificate covers the name in `PKI_DNS`, plus `postgres`, `localhost` and `127.0.0.1`.
Running the command again does no harm: it leaves existing files alone. **Run it before you
start PostgreSQL**, because PostgreSQL reads the key as it starts.

The web console does not get its certificate here, and neither do EST, ACME or the Windows
service. Each creates its own key in the key store the first time it runs, signs a
certificate with it, and saves that certificate in the database. When you issue a proper one
from your CA in §4.4, they pick it up. Nothing writes a console key to a file.

All of these certificates are signed by the server itself, which is fine for getting started.
A real deployment replaces them with CA-issued ones in §4.4.

### 4.2 Bootstrap: `deploy/bootstrap.sh` (automatic, already done by the installer)

Run this after PostgreSQL has started:

```bash
docker compose run --rm bootstrap
```

It does three things:

1. Creates the folders FastPKI keeps its files in, under `/var/pki`.
2. Creates the first console account: user `admin`, password `admin`. The account must
   change its password at the first sign-in (§4.5). If you have already changed it, this
   step leaves it alone.
3. Puts the ownership of `/var/pki` back the way the services expect, so PostgreSQL can
   still read its key.

**It does not create any CA, and it does not issue certificates.** You choose where the CA
keys are kept — in the key store that ships with FastPKI, or in your own hardware security
module — before any key exists. The install wizard asks; the setting is `KEY_BACKEND` in §5.

**All the HTTPS services still start**, including EST, ACME and the Windows service. The
first time each one runs, it creates its key in the key store, signs itself a certificate
good for 90 days, and saves that certificate in the database. Nothing is written to a file:
the certificate lives in the database, and the key never leaves the key store. Each service
reuses the same certificate every time it starts, so restarting does not give your clients a
new identity to get used to. §4.4 replaces these with certificates from your own CA.

It does not create the database tables either. PostgreSQL creates those itself, from
`sql/createdb.sql`, the first time it starts.

### 4.3 Create your CAs (you do this)

A new installation has **no CA**, so it cannot issue anything yet. You create two CAs:

- a **root CA**: the top of the trust chain. Clients trust it. It signs only other CAs.
- an **issuing CA** (a sub CA): signed by the root. It signs the certificates that
  users, servers and devices ask for.

Each CA's private key is created inside the key store, and it never exists as a file you
could copy.

⚠️ **When the issuing CAs are signed, put the root out of use** — `fastpki-ca disable root-ca`,
or **Disable** on its row in the console. The root's job is to sign issuing CAs and nothing
else, so leaving it able to sign is a standing risk for no benefit. Disabling stops new
issuance and leaves the root's revocation list, OCSP answers and chain serving exactly as
they were: a root that stopped answering for revocation would make everything it ever signed
unverifiable. Re-enable it for as long as it takes to sign the next issuing CA, then disable
it again. The stronger arrangement keeps the root's key off these machines altogether: it
signs its own revocation list wherever it lives, and you publish the bytes here with
`fastpki-ca import-crl` ([`admin-guide.md`](admin-guide.md) §3 has that).

#### Before you start: three things to check

1. **The public name is right.** Every certificate this CA signs carries this server's name,
   in the addresses where a client goes to fetch the revocation list and the CA certificate.
   Those addresses cannot be changed afterwards. `install.sh` set the name from your answer
   to *Public FQDN*, and the form shows you the addresses before you create the CA. Check
   them there.
2. **A second server for failover needs keys that can be copied.** If you will ever add a
   standby server (see `high-availability.md`), every CA key has to be created so that it can
   be copied into that server's key store. A key created without this can never be given it
   later, and the standby will never be able to sign anything.

   In the console, tick **replicable key** under *Key & signature* for each CA. On the
   command line, add `--replicable`. It works with every key algorithm. On a single server,
   leave it off.

   The nightly job that renews FastPKI's own certificates runs with no options, so it cannot
   make that choice for you. On a pair, either set **`SERVICE_KEYS_REPLICABLE=true`** before
   it first runs, or create those certificates yourself (§4.4). Either way, do it before the
   first key is created.
3. **Several data centers use different names.** If you plan more than one (§9), call the
   issuing CA `dc1-sub` rather than `issuing-ca`.

The reasons for all three are explained under *Details* at the end of this section.

#### Option A: in the web console (recommended)

Sign in to the console as an admin and open the **CAs** tab.

**Step 1: create the root CA.**

1. Click **+ New CA**.
2. **Identity**:
   - **id**: `root-ca`. This is the short name that URLs and commands use.
   - **display name**: `Example Root CA` (any text).
   - **Parent CA**: leave **— none (root) —**.
   - **CN**: `Example Root CA`. The other name fields (OU, O, L, ST, C) are optional.
3. **Key & signature**:
   - **Algorithm**: keep **RSA** with **4096** bits. It works with every client. Read
     `compatibility.md` before you choose another one.
   - Leave **use an existing key** unticked. A new key is created in the token.
   - **replicable key**: tick it only if you will add an HA standby (check 2 above). You
     cannot change it later.
   - **Slot** and **PIN file** are filled in for you. Do not change them.
   - **Key name**: `root-ca`. This is the key's name inside the token, and it must not be
     used by another key.
4. **Validity**: leave the dates empty. The CA is then valid for 10 years.
5. Leave **Constraints** and **Advanced** as they are. For a root CA the AIA and CRL boxes
   are greyed out. This is correct, because a root CA carries neither.
6. Click **Create CA**.

**Step 2: create the issuing CA.**

1. Click **+ New CA** again.
2. **Identity**:
   - **id**: `issuing-ca` (`dc1-sub` if you plan a mesh).
   - **display name**: `Example Issuing CA`.
   - **Parent CA**: select **root**.
   - **CN**: `Example Issuing CA`.
3. **Key & signature**:
   - **Algorithm**: keep **RSA**, and choose **3072** bits.
   - Leave **use an existing key** unticked.
   - **replicable key**: **tick it if you will add an HA standby**, exactly as for the root.
     Every CA of an HA pair needs it. This CA signs every certificate, so without it a
     promoted standby cannot issue anything. You cannot change it later.
   - **Key name**: `issuing-ca` (the same as the id).
4. **Validity**: leave empty, or set **Not after** to about 5 years from today. An issuing
   CA cannot be valid longer than its root: a later date, including the ten-year default, is
   shortened to the root's end date.
5. Open **Advanced** and check the two addresses under **caIssuers** and **CRL DP**. They
   must contain your public FQDN, for example `http://pki.example.org:8080/root-ca.crl`.
   If they show a different name, or no name, stop here and fix the name first
   (`PKI_DNS` and `BASE_URL`, §5).
6. Click **Create CA**.

**Step 3: check the result.** The CAs tab now lists two CAs. Both show **Status**
`active`. The issuing CA's **Issuer** shows the root CA's name, `Example Root CA`.

**Step 4: press Disable on the root's row.** It has signed the issuing CA, which is all a
root is for. This is the warning at the top of this section: new issuance stops, while the
revocation list, the OCSP answers and the chain keep working exactly as before.

**Next: §4.4.** Some services need their own certificate from the issuing CA you just
created. §4.4 gives the commands. Until you run them, OCSP and CMP do not work, even though
every container looks healthy.

#### Option B: from the command line

**A CA private key lives in a token — always.** `--ca-key` must be a `pkcs11:` handle; there
is no software option and the console offers no key-location control. A file path is refused
when the CA is registered.

`fastpki-ca` does the same as the console. `--keygen` creates the key inside the token
named by `--ca-key`.

⚠️ **`fastpki-ca` lives inside the image, not on your PATH**, and `/app/config/bootstrap.conf`
is a path inside the container. Define both wrappers once, from `deploy/`, and use them for
every `ca` and `cfg` command in this guide:

```bash
cd deploy
ca()  { docker compose run --rm --no-deps \
          --entrypoint fastpki-ca     web --config /app/config/bootstrap.conf "$@"; }
cfg() { docker compose run --rm --no-deps \
          --entrypoint fastpki-config web --config /app/config/bootstrap.conf "$@"; }
```

On a **native** install the binaries really are on the PATH and the config is
`/etc/fastpki/bootstrap.conf` — drop the wrappers and say
`fastpki-ca --config /etc/fastpki/bootstrap.conf …` instead.

⚠️ **Run it as the `fastpki` user, not under `doas` or `sudo`.** The token is served by
`p11-kit-server -u fastpki`, which authorises by the connecting process's uid, so root is
refused as firmly as a stranger — and what it reports names the device rather than the
user:

```
fastpki-ca: C_Initialize failed (rc=48)
```

`rc=48` is `CKR_DEVICE_ERROR`. Nothing in it suggests a permission problem, so it reads as
a broken token on a node whose token is perfectly healthy. Log in as `fastpki`, or
`su -s /bin/sh fastpki -c '…'`; every command in this guide that touches a key follows the
same rule, because they all reach the token the same way.

On **Kubernetes** they are in the `web` container of a server pod, and the config is at the
same path the container image uses. Name the container: a server pod runs a dozen, and
without `-c` kubectl picks one for you.

```bash
ca()  { kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
          fastpki-ca     --config /app/config/bootstrap.conf "$@"; }
cfg() { kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
          fastpki-config --config /app/config/bootstrap.conf "$@"; }
```

⚠️ **A step that writes a file has nowhere to write it here.** `--out-dir` and `--out` land
inside a pod that is replaced on the next roll, so the CA-export and CSR steps below need
`kubectl cp` out of the pod, or the console's download buttons, which is what §9.1's console
walkthrough uses.

For an HA pair, add `--replicable` to **both** commands: the root and the issuing CA.

```bash
ca create root-ca \
    --name "Example Root" --subject "/CN=Example Root CA" --days 3650 \
    --key rsa --bits 4096 --keygen \
    --ca-key 'pkcs11:token=fastpki;object=root-ca;type=private?pin-source=/var/pki/tls/pin' \
    --out-dir /var/pki/ca
ca create issuing-ca --parent root-ca \
    --name "Example Issuing CA" --subject "/CN=Example Issuing CA" --days 1825 \
    --key rsa --bits 3072 --keygen \
    --ca-key 'pkcs11:token=fastpki;object=issuing-ca;type=private?pin-source=/var/pki/tls/pin' \
    --out-dir /var/pki/ca
```

#### Details: keys that can be copied, the public name, and names across data centers

⚠️ **Decide replicability now — it cannot be added later.** `CKA_EXTRACTABLE` is fixed when
a key is generated and PKCS#11 has no way to grant it afterwards, so whether a CA key can
ever be copied into another token is settled when the CA is created and by nothing else.
Tick **replicable key** in the console, or add `--replicable` on the command line, to generate
it extractable. Every algorithm a CA key can use — RSA, RSA-PSS, EC P-256/P-384/P-521,
Ed25519, Ed448 and ML-DSA — can be generated this way:

```bash
ca create root-ca --name "Example Root" … --keygen --replicable \
    --ca-key 'pkcs11:token=fastpki;object=root-ca;type=private?pin-source=/var/pki/tls/pin'
```

**For an HA pair, use it on every CA, the root included.** A pair is not two data centers —
it is one data center twice, and it exists to survive losing a host. A CA whose key sits on
only one of the two is the failure the second host exists to prevent: the survivor
keeps issuing under whatever it already holds, and no further sub CA can ever be created
under a root it does not have. There is no repair short of building the hierarchy again and
re-issuing everything beneath it.

**For a mesh it is opt-in.** Each data center holding only its own key means compromising one
node exposes one data center's CA; a key present everywhere means compromising any node
exposes every CA it signs for. §9.7 sets out that trade.

Nothing else changes: a replicable key signs identically, and `fastpki-ca key replicate`
(§9.7) is what later copies it into a peer's token.

⚠️ **A renewal with a new key does not inherit it.** Renewing a CA with a new key (its detail
view in the console → *Renew*) generates that key, and it is replicable only if **replicable key**
is ticked there. On an HA pair, tick it every time, or the renewed CA can no longer reach the
other host. A renewal that keeps the current key keeps its replicability.

⚠️ **Set this node's public name before creating a CA.** The CRLDP and AIA URLs a CA
certificate carries are derived at the moment it is issued, from `BASE_URL` where it is set
and `PKI_DNS` otherwise, plus `OCSP_PORT` and the CA's own id — `fastpki-ocsp` serves
`/{ca_id}.crl`, `/{ca_id}.crt` and `/ocsp` on that port over plain HTTP, which is why those
fetches never depend on the PKI being validated. `install.sh` records the name it asked
for, so a node it installed is already right; a CA created while both are empty carries a
URL with no host in it.

A sub CA's CRLDP names its **parent** — a sub CA under `root-ca` gets `…/root-ca.crl` — because
the parent is what publishes the CRL covering it. Leaves name their issuing CA.

**On a mesh, create the sub CA after `fastpki-mesh --map`.** Every certificate carries one
CRLDP and one AIA entry per row in `datacenters`, so a relying party unable to reach one
data center has another to try, and those rows are what `--map` writes. A sub CA created
before the map exists carries this node's URL alone, and cannot be told another afterwards.
Leaves are unaffected — issuance derives their URLs afresh every time — so the symptom is
narrow and easy to miss: every certificate verifies on its own, and strict chain validation
fails at depth 1 with `unable to get certificate CRL` as soon as the single data center
named there is unreachable. Create the sub CA after `--map` rather than planning to correct it
later: correcting one means **renewing** it (admin guide §3.8), which gives it a new
certificate with the URLs derived at that moment. The renewal can keep the current key, and
the old certificate stays live until it expires, so certificates already issued still
validate — but relying parties that cached the old CA certificate go on using its URLs.

Creating a CA from the **console** shows the derived URLs before you commit, which is what
`/api/ca-instances/derived-urls` is for.

**Planning a mesh? Name the issuing CA `dc1-sub` instead of `issuing-ca`.** §9.1 builds one
root with a sub CA per data center — `dc1-sub`, `dc2-sub`, `dc3-sub` — and every command
there names this node's as `dc1-sub`. The id is arbitrary and `issuing-ca` works exactly as
well, but it has to be the id you then pass to `ca pg-tls` and pick as the *Issuing CA* in
the console, so choosing the mesh name now saves translating every later step. Nothing has
to be re-issued if you decide later; the id is a label, not a property of the key.

`fastpki-ca` writes `<id>.crt` into the out-dir and **no key file** — the private half
was made inside the token and has no on-disk form. Registering the CA is part of the
same command: a CA is a **row in `certs` with `is_ca=true`** whose `id` is what every
enrolment path names — e.g. `/.well-known/est/<id>/simpleenroll`. No CA is registered implicitly
at startup.

`--keygen` is the **recommended way to put a CA in an HSM**: the private half is generated
inside the token and has never existed anywhere else. Whether a key can be *imported*
instead depends on the token — SoftHSM accepts both RSA and EC (as PKCS#8) via
`softhsm2-util --import`, while a production HSM usually refuses by policy. On hardware that
refuses, "migrating" a file-backed CA means renewing it with a new key generated in the token
(admin guide §3.8), and letting certificates under the old key expire naturally.

**Keep the root key offline in production.** Create the root in a token on an air-gapped
box, sign the issuing Sub-CA with it, and ship **only** the Sub-CA (its own token key,
generated on that node) to the servers — no DC holds the root key at all. For multi-DC, one
shared root signing a per-DC issuing Sub-CA gives every node its own local signing key
while all leaves still chain to a single trust anchor. §9.1 builds this.

### 4.4 Service certificates: finish the setup (do this after §4.3)

Creating the CAs is not the last step. Several services need a certificate of their own,
signed by your issuing CA, before they work at all. Until they have one, every container
still looks healthy in `docker compose ps`, so nothing tells you anything is wrong.

| Service | What it needs | What happens until it has it |
|---|---|---|
| **OCSP** (answers "is this certificate revoked?") | an OCSP responder certificate, `ocsp-ra-<ca_id>` | every OCSP request gets the error `internalerror`. CRLs still work. |
| **CMP** | a CMP RA certificate, `cmp-ra-<ca_id>` | every CMP request is refused, with `no RA credential` in the log |
| **SCEP** | a SCEP RA certificate | SCEP enrolment fails |
| **Console, EST, ACME, MS** (the HTTPS services) | a TLS certificate from your CA | each one keeps its own temporary self-signed certificate, so clients and browsers warn |
| **PostgreSQL** | a database certificate from your CA | it keeps the self-signed certificate that certgen made (§4.1) |

#### The short way: two settings and one command

The deployment issues these certificates **itself**. You only have to name the CA it should
use, and then either wait for the nightly job or — during an install — run it now.

**1. Name the CA.** Both values are the **id you gave your issuing CA in §4.3** — not the
word below. If you followed §4.3's advice and called it `dc1-sub` because you plan more than
one data center, then `dc1-sub` is what goes here. `fastpki-ca list` prints the ids you have.
In the console this is the **Config** tab; on the command line, from the `deploy` directory of
wherever you unpacked or cloned FastPKI:

```bash
docker compose exec web fastpki-ca list                        # the ids you actually have
docker compose exec web fastpki-config set PG_TLS_CA_ID <your-issuing-ca-id>
docker compose exec web fastpki-config set CMP_CLIENT_CA_ID <your-issuing-ca-id>
```

FastPKI does not guess either of these. Set both.

`PG_TLS_CA_ID` names the CA that signs the database's certificate. A database certificate
from the wrong CA is worse than one you have not replaced yet.

`CMP_CLIENT_CA_ID` names the CA that CMP trusts when a client signs its own request. That is
what lets a client revoke its own certificate.

**2. Issue everything, in one command.** It creates the OCSP, CMP and SCEP credentials for
every issuing CA, replaces the four listeners' self-signed certificates, and — because step 1
named the CA — issues the database certificate too.

⚠️ **Decide `--replicable` before you run it, because this run creates those keys.** On a
deployment that has, or will have, a standby, leave the flag in. On a single server with no
standby planned, delete it — a key that cannot leave the store is the safer default. There is
no third chance: a key that was not created copyable can never be made copyable, and a later
run with the flag keeps the key it finds and tells you so.

```bash
docker compose exec web fastpki-ca renew-service-certs --create-missing --re-issue-self-signed --replicable
```

A key created without that option can never be copied to the standby. Whether a key can be
copied is decided when it is created, and nothing can change it afterwards. The nightly job
has no command line; it reads `SERVICE_KEYS_REPLICABLE` instead, which a server installed for a
pair has set to `true` (§6a, *Before you start*).

**On a native or cloud node** the binary is on the PATH and reads its own config. Run it as
the `fastpki` user, which is the rule for every command that touches a key: the token socket
belongs to that user, so as `root` the listener keys cannot be opened and the run ends with
four `could not load the listener key` failures on a node whose token is perfectly healthy.

```bash
doas su -s /bin/sh fastpki -c \
    'fastpki-ca --config /etc/fastpki/bootstrap.conf renew-service-certs --create-missing --re-issue-self-signed --replicable'
```

Drop `--replicable` here too if this server will never have a standby. The same rule applies:
the flag is read once, when the keys are created.

**On Kubernetes** each server does this work itself, on a schedule. `apply.sh` runs it
straight away rather than waiting. Set both ids from step 1 first, so that run has them.
With more than one server `apply.sh` also writes `SERVICE_KEYS_REPLICABLE=true`, so the keys
it generates can be copied between the servers' tokens. From `deploy/k8s`:

```bash
kubectl -n <namespace> exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set PG_TLS_CA_ID <ca-id>
kubectl -n <namespace> exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set CMP_CLIENT_CA_ID <ca-id>
bash apply.sh
```

**3. Restart the services.** CMP reads `CMP_CLIENT_CA_ID` only when it starts, and a service
may not notice a key that appeared after it was already running. Leave out any protocol you
did not install:

```bash
docker compose restart ocsp cmp scep est acme ms web
```

Native or cloud: `for s in ocsp cmp scep est acme ms web; do rc-service fastpki-$s restart; done`.
Kubernetes: `apply.sh` has already restarted them when it created or re-issued anything; to do it
by hand, `for c in ocsp cmp scep est acme ms store web; do kubectl -n <namespace> exec fastpki-node-0 -c $c -- kill 1; done`,
and the same for `fastpki-node-1` in a pair.

**4. Run step 2 again.** The command can only replace the certificate of a service that has
already run at least once, so anything that was down the first time is reported as
`skipped … nothing published yet`. When nothing is skipped, you are done.

**5. Check it**, as step 8 of the console walkthrough below describes: CMP and SCEP announce
their RA mode at startup, and OCSP should answer `good` for a certificate this CA issued.

**You do not have to do any of this on a CA you add later.** The `certrenew` service repeats
step 2 at every start and then daily, so a new CA gets its credentials and a new listener gets
a CA-issued certificate on their own — with the one exception above, that the job cannot
create replicable keys for an HA pair.

#### By hand, in the web console

Use this when the one command above cannot do what you need: a listener that must carry
**extra names**, a certificate you want to issue **one at a time**, or simply to watch what is
being created. It produces exactly what the command produces.

These steps are for one issuing CA. In them, `issuing-ca` is the id of your issuing CA from
§4.3. Use your own id if it is different (for example `dc1-sub`).

Every certificate in steps 1 to 4 uses the same form: **Inventory** → **+ Request (key in
HSM)**. In that form:

- **Serve as** says which service the certificate is for. When you choose it, the form fills
  in the **Key name** and the certificate purposes (key usage) for that service. Do not
  change them.
- **Issue from**: choose your issuing CA, `issuing-ca`.
- **Token slot** and **PIN file** are filled in for you.
- On an HA pair, tick **replicable key** in **steps 1 to 3** (OCSP, CMP, SCEP), so the
  standby can copy these keys. You cannot change this later (§4.4a). Step 4 does not need it.
- Click **Generate in HSM & request** at the bottom.

**Step 1: the OCSP responder certificate.**
- **Serve as**: **OCSP responder (OCSP_RESPONDER_CERT_ID_PREFIX)**
- **CN**: `FastPKI OCSP Responder` (any name)

**Step 2: the CMP RA certificate.**
- **Serve as**: **CMP RA (CMP_RA_CERT_ID_PREFIX)**
- **CN**: `FastPKI CMP RA`

**Step 3: the SCEP RA certificate.**
- **Serve as**: **SCEP RA (SCEP_RA_CERT_ID_PREFIX)**
- **CN**: `FastPKI SCEP RA`
- The form allows only **RSA** here. SCEP needs an RSA key.

Skip step 2 or step 3 if you did not install CMP or SCEP.

**Step 4: the TLS certificates of the HTTPS services.** Do this four times, once for each of
**Console TLS (WEB_CERT_ID)**, **EST TLS (EST_CERT_ID)**, **ACME TLS (ACME_CERT_ID)** and
**MS-XCEP/WSTEP TLS (MS_CERT_ID)**. Skip a service you did not install.
- **Serve as**: the service.
- ⚠️ **Tick "use a key already in the token".** Each service already has a key, and it uses
  that key now. If you leave the box unticked, the form tries to create a new key with the
  same name, and the server refuses to replace a key that a running service uses.
- **replicable key** is not needed here, even on an HA pair. Each server keeps its own TLS
  key, and the standby does not copy these keys.
- **CN**: your public FQDN, for example `pki.example.org`.
- **SANs**: your public FQDN again. Add any other name or IP address that clients use to
  connect, one per line.
- ⚠️ **Use exactly the name you gave the installer as *Public FQDN*** (`PKI_DNS` in
  `deploy/.env`): the name in your console address `https://<name>:8090`. Do not type
  another domain, and do not leave **SANs** empty. Modern clients check only the SAN, so
  with a different name or no SAN they refuse to connect. certbot, for example, stops with
  `Hostname mismatch, certificate is not valid for '<name>'`.

**Step 5: the database certificate.**
1. **Inventory** → **Issue Postgres certificate**.
2. **Issuing CA**: `issuing-ca`. **Key**: keep **RSA 3072**.
3. Click **Issue**.

PostgreSQL loads the new certificate within about 30 seconds, without a restart.

**Step 6: two settings in the Config tab.** Open the **Config** tab and click **All** in the
row of areas. For each setting, choose it in the **Key** list, type `issuing-ca` in the
**value** field, and click **Set**.

| Key | Value | Why |
|---|---|---|
| `PG_TLS_CA_ID` | `issuing-ca` | keeps the database certificate from step 5 renewed. Without it, that certificate expires one day and every service then fails to connect to the database. |
| `CMP_CLIENT_CA_ID` | `issuing-ca` | lets CMP clients sign their requests with a certificate from your CA. Without it, CMP refuses every signed request, so a client cannot revoke its own certificate: it gets `no suitable sender cert`. The `cmp` log warns `CMP has no client-CA trust anchor`. |

`cmp` reads `CMP_CLIENT_CA_ID` when it starts, so the restart in step 7 applies it.

**Step 7: restart the services.** The console cannot restart the other services, so this
step needs the server's terminal. `docker compose` must run in the `deploy` folder, where
`docker-compose.yml` is. Otherwise it fails with `no configuration file provided: not found`.
The folder is inside wherever you cloned or unpacked FastPKI, for example:

```bash
cd ~/FastPKI/deploy
docker compose restart ocsp cmp scep est acme ms web
```

Leave out any protocol you did not install. The console is unavailable for a moment while
`web` restarts.

`store` is not in that list, and does not need to be: the certificate store serves plain
HTTP and holds no credential of its own, so nothing this command issued is anything it
reads. It answers from the database on every request.

On a native or cloud node, restart the OpenRC services instead:

```bash
for s in ocsp cmp scep est acme ms web; do rc-service fastpki-$s restart; done
```

**Step 8: check that it worked.**
- The **Inventory** tab lists the new certificates.
- Read the logs of the three services that fail quietly. A service that still has no
  certificate says so, and names what is missing:

  ```bash
  docker compose logs ocsp cmp scep
  ```

- Open the console at `https://<your public FQDN>:8090`. The browser warning about a
  self-signed certificate is gone once your browser trusts your root CA.
- The full test, issuing a certificate and asking OCSP about it, is §6.

#### Details: how the HTTPS services find their certificate

EST, ACME, MS and the console run their own TLS. Each one finds its certificate through
`resolve_transport_cert()`. It looks in the database (`certs.cert_id`) first, then in the
file system. Only if it finds neither does it create a self-signed certificate, so that the
service starts instead of crashing while you are still setting up. When a certificate from
your CA appears under its `cert_id`, the service uses it, and keeps it across restarts.

**The certificate lives in the database, under an id.** Each service has a `*_CERT_ID`
setting that names its row in `certs`:

| Listener | id setting | shipped value | key setting |
|---|---|---|---|
| Console | `WEB_CERT_ID` | `web` | `WEB_TLS_KEY` |
| EST | `EST_CERT_ID` | `est` | `EST_KEY` |
| ACME | `ACME_CERT_ID` | `acme` | `ACME_KEY` |
| MS-XCEP/WSTEP | `MS_CERT_ID` | `ms` | `MS_KEY` |
| CMP (RA) | `CMP_RA_CERT_ID_PREFIX` | `cmp-ra` | `CMP_RA_KEY` |

The `EST_CERT` / `ACME_CERT` / `MS_CERT` / `WEB_TLS_CERT` paths are for **importing** a
certificate, not for storing it. If the file exists, the service reads it once and saves it
to the database under its id. From then on the database copy is used. Leave these paths
empty unless you bring a certificate from outside.

A service key, unlike a CA key, can be a file **or** a `pkcs11:` handle, because it is not a
CA signing key (it loads through `load_key_file_or_token()`). The shipped configuration uses
`pkcs11:` for all of them, so each key is created in the token and never exists as a file.

**To replace one service's certificate later**, for example with a new name in its SANs,
repeat step 4 of the console walkthrough for that service only, then restart it (for example
`docker compose restart est`).

**`CMP_CLIENT_CA_ID`** (§4.4 step 1) names the CA whose certificates
`fastpki-cmp` accepts from clients: the issuing CA, not the root. Nothing sets it for you.
Without it, CMP accepts only enrolment protected with a shared secret (PBM), and it refuses
every signed request, including a client revoking its own certificate (`rr`).

If `CMP_CLIENT_CA_ID` (a registered CA id) or `CMP_CLIENT_CA_BUNDLE` (PEM in the DB config)
names something that does not resolve, it is **skipped, not fatal**: `fastpki-cmp` logs
that the id is not a known CA instance — likewise for a revoked CA, one with no certificate
in the DB, or a bundle it cannot parse — and starts anyway. If that leaves it with no trust
anchor, it logs `WARNING: CMP has no client-CA trust anchor` and keeps serving. **Check the
log, not `docker compose ps`**: the container is up either way.

### 4.4a What `renew-service-certs` and `pg-tls` do

This section explains the commands of §4.4, steps 1 and 2.

**`--create-missing`** creates the OCSP responder, CMP RA and SCEP RA certificates, and
creates each key in the token. The subject and purposes come from a built-in definition, so
there is nothing to type. The key type comes from the answers `install.sh` collected:
`OCSP_RESPONDER_KEY_ALGO`, `CMP_RA_KEY_ALGO` and `SCEP_RA_KEY_BITS`. **Root CAs are
skipped**: nothing enrols against a root, so only the issuing CAs get these certificates.

**`--re-issue-self-signed`** replaces the temporary certificates of the HTTPS services. Each
of them creates a self-signed certificate at first start, because it must answer HTTPS
before any CA exists, and nothing replaces it afterwards except this option. It keeps each
existing key and changes only the issuer. It signs with `--ca <id>`, else with the CA the
`HTTPS_CA_ID` setting names, else with this node's only issuing CA. It never picks a root CA
by itself.

⚠️ **With more than one issuing CA, name the one to use.** The daily job passes no `--ca`,
so on a node with several issuing CAs it replaces nothing until `HTTPS_CA_ID` is set, and
reports `this node has more than one issuing CA` with the candidates on every run:

```bash
docker compose exec web fastpki-config set HTTPS_CA_ID <ca-id>
```

Only a certificate that is still self-signed needs this. One already issued by a CA is
renewed by that same CA.

⚠️ **It can only replace the certificate of a service that has already started.** For a
service that is not running yet it prints `skipped … nothing published yet; the listener
creates its own at first start`, and that service then creates a self-signed certificate when
you start it. This is why §4.4 step 4 runs the command again. `checked` in the summary line
counts the services it could see. A lower number than you expect means some were not
running.

Add `--dry-run` to see what the command would do, without changing anything. An unattended
install (the AWS module, the Proxmox module, Kubernetes) runs this command right after it
creates its CA, and finishes without a browser.

⚠️ **On an HA pair, create these credentials as replicable. Only the run that creates them can do so.** Add
`--replicable` to the command below, or tick **replicable key** when you create one in the
console (§4.4, the console walkthrough). These certificates have their own keys, created in this node's token, and whether a key can ever be copied
(`CKA_EXTRACTABLE`) is fixed when the key is created, exactly as for a CA key. Created the
default way, the keys can never be copied to the other host. After a failover the surviving
host then cannot serve OCSP, CMP or SCEP, while EST and ACME, which sign with the CA key you
did replicate, keep looking healthy:

```
CMP:  refusing the transaction — no RA credential
OCSP: internalerror
SCEP: no default CA served over SCEP
```

```bash
docker compose exec web fastpki-ca renew-service-certs \
    --create-missing --re-issue-self-signed --replicable
```

Running it again later does **not** repair this. The flag only applies when a key is
created, so for an existing certificate it renews the certificate, keeps the key that cannot
be copied, and says so. The only fix is to delete the token object named by the
certificate's key URI and create it again, which changes the credential. It is much cheaper
to decide now.

A replicable key survives losing this host, but anyone who can reach the token can also
copy it. A single server that will never have a standby has no reason to use it.

**The database certificate: `pg-tls` and `PG_TLS_CA_ID`.** On a fresh deployment step 1 also
prints:

```
/var/pki/tls/pg/ca.crt holds no CA anchor at all — leaving it alone rather than
emptying the file every app verifies against.
```

This is expected, and step 1 still succeeded. The file holds the self-signed pair that
`certgen.sh` wrote before any CA existed. That is a leaf certificate, not a CA, and the
command refuses to empty a file that every service reads. Step 2 replaces both, and the
message stops.

⚠️ **Both commands of step 2, on every deployment.** PostgreSQL is the only service that
cannot pick up a CA-issued certificate by itself: libpq needs a key *file* and cannot use the
token, so `renew-service-certs` does not cover it. `pg-tls` replaces the self-signed pair.
`PG_TLS_CA_ID` is what lets the nightly renewal keep it valid. Set only the first, and the
certificate expires with nothing to replace it. Every application then fails
`sslmode=verify-full` against a database that is up and working, the CLIs included, because
they use the same connection string. When `PG_TLS_CA_ID` is not set, the nightly job prints
one line saying so and changes nothing. The CA is not guessed on purpose: a database
certificate from the wrong CA is worse than one not yet replaced.

PostgreSQL loads the new pair within about 30 seconds, without a restart. The server watches
for it on Compose and Kubernetes, and `fastpki-pgtls` does the same on a native install.

**Why step 3 restarts every service.** The OCSP, CMP and SCEP certificates belong to `ocsp`,
`cmp` and `scep`. These serve plain HTTP and have no TLS certificate, so they are easy to
leave out, and they are exactly the three that fail. CMP checks the token again every
20 seconds and starts on its own once its key exists, but the others may not see a new key
until they restart. A restart covers all of them. A
deployment where only the HTTPS services were restarted looks healthy and serves EST and
CRLs, but still refuses every CMP request with `no RA credential` and answers `internalerror`
to every OCSP request.

### 4.4b Why OCSP and CMP need their own certificate, and what their errors mean

§4.4 creates these certificates. This section is background, for when something does not
work.

**OCSP.** The shipped `deploy/bootstrap.compose.conf` sets

```
OCSP_RESPONDER_KEY=pkcs11:token=fastpki;object=ocsp-ra;type=private
```

and no installer creates that key. RFC 6960 §4.2.2.2 requires the responder certificate to be
issued **by the CA it answers for**, so there is one per CA. Its `cert_id` is
`OCSP_RESPONDER_CERT_ID_PREFIX` + `-` + the CA id: `ocsp-ra-issuing-ca` for a CA called
`issuing-ca`. The console adds the CA id for you when you choose **Issue from**.

Three things must all be true: the key exists, the certificate is issued by the right CA, and
the `ocsp` service was restarted after that. If OCSP still answers `internalerror`, one of
them is missing, and `docker compose logs ocsp` says which. To check it, ask about any
certificate your CA issued (§6 shows how to get one and the chain file). `Cert Status: good`
means OCSP works:

```bash
openssl ocsp -issuer ca-chain.pem -cert <a-cert>.pem \
    -url http://localhost:8080/ocsp -resp_text -noverify | grep "Cert Status"
```

**CMP.** Without its RA certificate, `fastpki-cmp` refuses every request. The client only sees
`missing content type: expected=application/pkixcmp`, because the server answered HTTP 415
instead of a CMP message. This names neither CMP nor a credential, so read the server log,
which says:

```
CMP: refusing the transaction — no RA credential. Issue a certificate for
CMP_RA_CERT_ID_PREFIX 'cmp-ra' in the console (Inventory -> Request, key in HSM ->
Serve as CMP RA). No restart is needed: this process re-checks its token every 20s and
starts serving as soon as the key is there.
```

`fastpki-cmp` checks the token every 20 seconds and starts serving on its own once the key is
there, so for CMP a restart only makes it immediate.

**SCEP** reads its RA key when it starts, so restart `scep` after creating its certificate.

### 4.5 First console admin

Bootstrap (§4.2) seeded `admin` / `admin` with `--must-reset`, so the first login is
**forced** to set a new password. Until it is changed that session reaches only
`/api/me`, `/api/password` and `/api/logout` — anything else is 403 — and
`pki::authenticate()` refuses the row outright, so the seeded credential cannot enrol a
certificate over EST/MS/SCEP/CMP either. The default is therefore not shippable *as a
working credential*; it is a one-use door into the console.

(Open-mode first-run — creating the first admin via `POST /api/users` when the table is
empty — exists as a fallback if the seed is skipped, though the default flow does not
rely on it.)

### 4.6 Updating an existing deployment (what to keep, what to wipe)

**Four** volumes, with very different lifetimes. The two that matter are `fastpki_pgdata`
and `fastpki_softhsm-tokens`: between them they are the CA, and losing either one alone
makes the other useless.

| Volume | Holds | Wipe it? |
|---|---|---|
| `fastpki_softhsm-tokens` | **Every CA private key** — the SoftHSM token (`/var/lib/softhsm/tokens`), mounted only into the `softhsm` service | **Never.** Wiping it orphans every CA row in `certs`: the certificates remain and nothing can sign with them again |
| `fastpki_pgdata` | schema, cert inventory, console users, the CA rows in `certs` | only on a schema break |
| `fastpki_pki-data` | **service TLS material only** — the `/var/pki/{ca,tls}` layout and the token PIN file `/var/pki/tls/pin` | **Almost never** |
| `fastpki_p11-socket` | the p11-kit socket directory | freely — it is a socket, not storage |

⚠️ **The token is not in `fastpki_pki-data`.** That volume holds the PIN and the service TLS
layout; the keys the PIN unlocks are in `fastpki_softhsm-tokens`. Preserving `pki-data` does
not preserve the keys.

- **Routine version update** — get the new image and run `./rolling-update.sh`, which
  applies any schema change before it replaces the services
  ([`admin-guide.md`](admin-guide.md) §14.3). Wipe nothing: all four volumes
  persist, so the CA, TLS certs and inventory survive — no bootstrap, no CA re-creation.
- **Schema-breaking release with no migration** — ⚠️ **wiping `fastpki_pgdata` destroys the
  deployment's certificates, not just its schema.** A CA *is* a row in `certs`, and so is
  every certificate it has issued, every revocation and everything the CRLs are built from.
  Nothing re-registers a CA from files — a CA exists only as its `certs` row — so the token
  keys surviving in `fastpki_softhsm-tokens` are then keys nothing can be attached to. Restore from a backup instead — a database dump
  ([`postgres.md`](postgres.md) §6) — and take the dump *before* you touch the
  volume.
- `docker compose down -v` destroys **every** volume, `fastpki_softhsm-tokens` included —
  the CA private keys as well as the CA rows. Use deliberately.
- ⚠️ **It only destroys volumes belonging to this compose project.** They are named
  `<project>_<volume>`, so a volume left by another deployment path, or by the same one
  under a different project name, is untouched and keeps whatever CA hierarchy it held.
  `docker volume ls` after the teardown and remove what remains by name: a stale
  `pki-data` is how a "clean" host comes back serving certificates from a CA nothing
  else knows about.

---

## 5. Configuration

Settings live in one file, `bootstrap.conf`, which starts as a copy of
`config/bootstrap.conf.example`.

There are three places a setting can come from, and they are not interchangeable:

| where | which settings |
|---|---|
| the file | all 154 of them |
| an environment variable of the same name | 122 of the 154 |
| the database, editable in the console's **Config** tab | all but `PG_CONNINFO`, which says how to reach the database and so has to be in the file |

The database wins over the file, so once a deployment is running, change a setting in the
console rather than editing the file.

⚠️ **Only those 122 settings can be set from the environment, and the rest are ignored
without a word.** There is no error, because the part of the program that reports unknown
settings never sees them. These 32 have to go in the file or in the database. Several of them
are the certificate settings this guide asks you to change elsewhere, which is why
`deploy/bootstrap.compose.conf` puts them in the file and not in `.env`:

```
ACME_CAA_IDENTITY   ACME_CERT      ACME_CERT_ID   ACME_KEY
ALLOW_WEAK_SIGNATURE_DIGEST        CMP_RA_CERT_ID_PREFIX     DISCOVER_BIN
EST_CERT            EST_CERT_ID    EST_KEY
LOGIN_FAILURE_THRESHOLD            LOGIN_LOCKOUT_SEC
MS_CERT             MS_CERT_ID     MS_KEY
NOTIFY_DAYS         NOTIFY_WEBHOOK NOTIFY_WEBHOOK_FORMAT     OCSP_EXPIRY_SWEEP_SEC
NOTIFY_EMAIL_FALLBACK
RELEASE_PUBKEY
SCEP_ALLOW_DES3     SCEP_ALLOW_SHA1
SMTP_CA_FILE        SMTP_FROM      SMTP_PASSWORD  SMTP_SERVER  SMTP_TLS  SMTP_USER
UPDATE_FEED_URL     WEB_CERT_ID    WEB_SELFSERVICE_IDENTITY_SUBJECT
```

⚠️ **Inside a container the file is somewhere else, so every command needs `--config`.** The
programs look for `config/bootstrap.conf` by default, but the image keeps it at
`/app/config/bootstrap.conf`. The image's own start-up command passes `--config`; anything
you run yourself has to as well.

Leaving `--config` off does not produce an error. The program falls back to its built-in
settings and tries to reach a database on the local machine, so the symptom is a database
connection failure with nothing to say the config file was never read.

**The keys you must review for any real deployment:**

| Key | Why |
|---|---|
| `PKI_DNS`, `BASE_URL` | Your public FQDN. `BASE_URL` (e.g. `https://pki.example.org`) is what the ACME directory advertises — set it or ACME hands out the wrong URLs. |
| `PG_CONNINFO` | The libpq connection string. Postgres is the only backend. |
| `PG_TLS_DIR`, `PG_TLS_SANS` | Where the database's own certificate lives. `certgen.sh` makes a temporary one before the first start. Once you have a CA, replace it from the console (Inventory → **Issue Postgres certificate**) or with `fastpki-ca pg-tls <ca-id>`, and set `PG_TLS_CA_ID` to that CA so the daily job keeps it renewed. PostgreSQL copies the certificate into its own container, so file ownership outside does not have to match, and it picks up a replacement within about 30 seconds without restarting. |
| `EST_CERT/KEY`, `ACME_CERT/KEY`, `MS_CERT/KEY` | TLS certs for the HTTPS-native protocols. |
| `AUTH_BACKEND` | How EST/MS authenticate enrollers: `local` (the `web_users` table — same rows as the console) or `ldap`. There is no `none`; a config carrying it fails to start, by design. |
| `WEB_ALLOW_REVOKE` | Whether the console may change anything at all. It is **`true` by default**, so a new install can issue, revoke, restore and manage users from the browser without you changing a setting. Set it to `false` only when you want a read-only copy, such as one for auditors or a server being taken out of service. Every action in the console is then refused, which is the usual reason for "why can't I do anything?". |
| *(none)* | CMP always requires authentication, and there is no setting that turns that off. A password works for any user who has been given an enrolment secret. Authenticating with a certificate instead needs a CA to check it against (`CMP_CLIENT_CA_ID` or `CMP_CLIENT_CA_BUNDLE`), and revoking over CMP needs one too. |
| `ALLOWED_IPS_REGEX`, `MIN_*_BITS` | Which names and key sizes you are willing to sign. The list of approved domains is not a setting: it is the `allowed_domains` table. Neither are the three per-role limits, which are columns on the `roles` table (`max_certs`, `max_cn`, `max_san`). |
| `CRL_DPS`, `AIA_CA_ISSUERS`, `AIA_OCSP` | Fallback addresses for the revocation list and the CA certificate. They are used only for a certificate issued outside any CA. When a client enrols, the addresses come from the CA it enrolled against and from the data center list, so changing these does not change what your clients receive. |

**Where the CA key lives is not a choice — it is a token.** Every CA key is
a `pkcs11:` URI; the two keys that make one reachable are:

| Key | Why |
|---|---|
| `PKCS11_MODULE` | The PKCS#11 module to load. In the shipped compose this is the **p11-kit client shim**, not SoftHSM itself — the token runs in its own `token` container and is reached over `/run/p11/pkcs11.sock`. The indirection matters: SoftHSM uses OpenSSL as its own backend, so loaded in-process it re-enters libcrypto and can deadlock. |
| `PKCS11_PROVIDER_PATH` | Directory holding OpenSSL's `pkcs11.so` provider. |
| `PKCS11_TOKEN`, `PKCS11_PIN_FILE` | This deployment's token label and the server-side file holding its PIN, offered as defaults by the console's slot picker. The PIN itself is never sent to a browser. |

`install.sh` asks **`KEY_BACKEND`** — `softhsm` (the bundled container; dev/test) or `hsm`
(your own module, and it then asks for the absolute path inside the container). This is an
install-wizard question, not a `bootstrap.conf` key: it decides what `PKCS11_MODULE` gets set to.

Keys that are **not** CA signing keys may still be files: the CMP/SCEP RA credential and
the transport TLS pair. Give OCSP/CMP/SCEP their own delegated responder/RA certs
(`OCSP_RESPONDER_*`, `CMP_RA_*`) so the CA key is only ever used by the issuance path.
See the comments in `config/bootstrap.conf.example`.

Inside containers, bind every service to `0.0.0.0` (so the published port works);
on bare metal behind a proxy, bind to `127.0.0.1`.

---

## 6. First issuance (smoke test)

Once up, confirm the chain works end to end. The commands use `issuing-ca`, the id §4.3
gives the issuing CA — substitute yours if you named it something else — and run in
order, because each one produces what the next needs. The `est` and `ocsp` profiles
must be among the ones you started (§3.2 step 6).

```bash
# EST cacerts — the chain (signing CA + root), and the anchor the checks below use
curl -sk https://localhost:8443/.well-known/est/issuing-ca/cacerts \
  | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out ca-chain.pem
openssl x509 -in ca-chain.pem -noout -subject -issuer

openssl req -new -newkey rsa:2048 -nodes -keyout test.key -out test.csr -subj "/CN=test"
# Either issue it in the console — log in at https://<host>:8090, "Inventory" -> "+ Request
# from a CSR", paste the CSR, download as test.pem — or enrol over EST, which needs no
# browser and is the only route on a headless deployment:
#
#   the account needs an ENROLLING role; `standard` is not one, `requester` is.
docker compose run --rm --no-deps --entrypoint fastpki-config web \
  --config /app/config/bootstrap.conf web-user demo 'D3mo…Pass' --role requester
curl -sk -u demo:'D3mo…Pass' --data-binary @<(openssl req -in test.csr -outform DER | openssl base64 -A) \
  -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" \
  https://localhost:8443/.well-known/est/issuing-ca/simpleenroll \
  | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out test.pem

# OCSP — status of that certificate. Needs the delegated responder from §4.4b: without it
# this answers `Responder Error: internalerror` on an otherwise healthy deployment.
openssl ocsp -issuer ca-chain.pem -cert test.pem \
    -url http://localhost:8080/ocsp -resp_text -noverify

# CRL — one per CA, at /{ca_id}.crl
curl -s http://localhost:8080/issuing-ca.crl -o crl.der
openssl crl -inform DER -in crl.der -noout -text | head -20
```

`user-guide.md` §6–§10 has full client examples (EST, ACME via
certbot, CMP via `openssl cmp`, SCEP, MS enrollment).

---

## 6a. High availability: add a standby server

This section adds a **second server** to a single-server deployment. The second server
(the **standby**) keeps a live copy of the database and of the CA keys. If the first server
(the **primary**) is lost, you promote the standby and it carries on issuing certificates.

This is the step-by-step version of [`high-availability.md`](high-availability.md) §3, for Docker Compose.
`high-availability.md` explains why each step is needed and what each error means.

In the steps below:

| Name | Meaning | Example |
|---|---|---|
| **A** | the primary: the server you installed with §3 and §4 | `192.0.2.10` |
| **B** | the new standby server | `192.0.2.11` |
| `A-ADDRESS`, `B-ADDRESS`, `YOUR-LOGIN` | each server's own IP address on the network the two servers share, and your login name on that server. **Replace them with your own values** — they are written this way, without `<>`, because a literal `<A>` in a command makes bash try to read a file called `A` |

Commands marked **on A** or **on B** run in the `deploy` directory of that server's checkout
(`cd ~/FastPKI/deploy`). The join itself runs **on your own computer**, the one you SSH to
both servers from.

Several checks below ask the database `SELECT pg_is_in_recovery()`, which means "is this a
read-only standby?". It answers `t` (true: a **standby**) or `f` (false: the **primary**).

### Before you start: check server A

Check all four. If one is not true, fix it first; a wrong answer here cannot be fixed later
without a new install.

1. **A was installed for a pair.** `install.sh` asks *Will this data center have a standby
   server that takes over if this one is lost*, and the answer must have been `yes`. It turns
   on the service that copies CA keys between the servers, and it makes the OCSP, CMP RA and
   SCEP RA keys copyable. On A:
   ```bash
   grep -E '^(HA_ENABLED|P11_TLS|SERVICE_KEYS_REPLICABLE|PG_BIND)=' .env
   ```
   It must print `HA_ENABLED=true`, `P11_TLS=on`, `SERVICE_KEYS_REPLICABLE=true`, and
   `PG_BIND=A-ADDRESS` (A's real address, not `127.0.0.1`: B connects to A's database there).
   If it does not, install A again from the start (§4.6 says what to delete).
2. **Every CA key can be copied to another server.** Each CA, the root included, must have
   been created with **replicable key** ticked (§4.3). You cannot turn this on afterwards.
   Check each CA on A:
   ```bash
   docker compose exec web fastpki-ca --config /app/config/bootstrap.conf key list <ca-id>
   ```
   Every line must end with `[in this node's token, replicable]`. A line ending
   `NOT replicable: it can never be copied to another host` means that CA was created without
   it; install A again from the start.
3. **`PKI_DNS` is a shared name for both servers**, such as `pki.example.org`, not A's own
   host name. It is written into every certificate, so it must still work when B takes
   over.
4. **The two servers reach each other**, both ways, on ports **5432** (database) and
   **12345** (CA key copy): B copies A's keys, and A copies any key created on B.

Your own computer needs SSH to both servers, as a user who can run `docker compose` there,
and a checkout of the same release (for `deploy/ha-join-pair.sh`).

### Step 1 — on B: install it for a pair

Install B with the **same release as A** and `./install.sh`, as §3 describes. Give the same
answers as on A, except for B's own address:

| Question | Answer on B |
|---|---|
| *Public FQDN of this deployment* (`PKI_DNS`) | the same as A |
| *Container image* | the same as A |
| *Postgres publish address* (`PG_BIND`) | `B-ADDRESS` |
| *Will this data center have a standby server …* | `yes` |
| data center index, on a server that is part of a mesh (§9) | the same as A: a pair is one data center twice |

B gets its own token and its own token PIN. **Do not create any CA on B.** Its database is
replaced by a copy of A's in the next step, and the join refuses a B whose database holds a CA.

### Step 2 — join B to A, from your own computer

```bash
deploy/ha-join-pair.sh --primary YOUR-LOGIN@A-ADDRESS --standby YOUR-LOGIN@B-ADDRESS \
    -i ~/.ssh/<your key>
```

If a checkout is not in `~/FastPKI/deploy` on that server, add its path after the address:
`YOUR-LOGIN@A-ADDRESS:/path/to/FastPKI/deploy`.

It checks both servers before it changes anything, then:

- replaces B's database with a copy of A's, and B streams A's changes from then on;
- points both servers' services at both databases, each server's own first;
- copies the CA keys between the two tokens, until each holds every key it needs;
- issues B its own database certificate from your CA.

It takes about two minutes (2 minutes 11 seconds on a lab pair) and ends like this:

```
ha-join-pair: standby: holds every key it needs to serve
ha-join-pair: primary: holds every key it needs to serve
ha-join-pair: standby: database certificate issued from the pair's CA
ha-join-pair: standby: its services now reach the standby first, then the primary
ha-join-pair: done: YOUR-LOGIN@B-ADDRESS streams from YOUR-LOGIN@A-ADDRESS and holds the CA keys.
```

Nothing secret is typed or copied by hand: A's database password and both token PINs travel
through the command's own memory, on its SSH connections. If it stops, the message above the
last line says why and what to fix; run the same command again afterwards. It is safe to run
at any time, and a B that already streams from A is not copied a second time.

### Step 3 — check the pair

**On B**, this must print `t` (`t` = true = B is a standby):

```bash
docker compose exec postgres psql -U fastpki -d fastpki -tAc 'SELECT pg_is_in_recovery()'
```

**On A**, this must show B's address with `streaming`:

```bash
docker compose exec postgres psql -U fastpki -d fastpki -c 'SELECT client_addr, state FROM pg_stat_replication'
```

**On B**, each CA's key must be there and replicable:

```bash
docker compose exec web fastpki-ca --config /app/config/bootstrap.conf key list <ca-id>
```

The console's **Replication** page shows the same for both servers at once.

### Step 4 — test a failover

Do this once, before you rely on the pair.

1. **On A**, check that B is still streaming (it must show B's address with `streaming`),
   then stop the database:
   ```bash
   docker compose exec postgres psql -U fastpki -d fastpki -c 'SELECT client_addr, state FROM pg_stat_replication'
   docker compose stop postgres
   ```
2. **On B**, promote B's database:
   ```bash
   ./pg-promote.sh
   ```
   ⚠️ Stop A's database first, always. Promoting while A still runs gives you two
   databases that both accept writes.

   It ends with the command that rebuilds A, and on the way it prints
   `OK: postgres is now a read-write primary`, removes `STANDBY_OF` from `.env`, rewrites
   `docker-compose.override.yml` for B's new role, and restarts the protocol services. A line
   `could not reach the database at A-ADDRESS … Connection refused` is expected: A's database
   is stopped. A line starting `WARN:` is not expected; it names what failed.
3. **On B**, load the rewritten settings. The script's own restart does not re-read the
   override file, so run:
   ```bash
   docker compose up -d
   docker compose exec web fastpki-config --config /app/config/bootstrap.conf get PG_TLS_CA_ID      # must print the CA id
   ```
4. **On B**, this must now print `f` (`f` = false = B is no longer a standby, it is the primary):
   ```bash
   docker compose exec postgres psql -U fastpki -d fastpki -tAc 'SELECT pg_is_in_recovery()'
   ```
5. **Point `PKI_DNS` at B.** Clients reach the deployment by that name, so change its DNS
   record (or, in a test setup, the `/etc/hosts` line on each client) to B's address. A load
   balancer in front of both servers does this for you (`high-availability.md` §9).
6. **Issue from B.** Run the §6 commands on B, or the demo (`demo/README.md`) from a client
   against B. It must succeed: B signs with its own copy of the CA keys.

⚠️ **Leave A's database stopped.** After a promotion the two databases have split, and A
cannot simply be started again. Step 5 rebuilds A as a standby of B.

### Step 5 — after the failover: rebuild A as the standby of B

After step 4, **B is the primary** and A's database is stopped. A cannot become the primary
again by starting its database: that database split from B's at the promotion, and every
certificate issued since is only in B's. So A comes back as B's **standby**. A keeps
everything else: its token, its keys, its certificates and its settings. Only A's
**database** is thrown away and copied again from B.

It is the join from step 2 with the roles swapped, and `--replace-local-database`. **From
your own computer**, with A's database still stopped:

```bash
deploy/ha-join-pair.sh --primary YOUR-LOGIN@B-ADDRESS --standby YOUR-LOGIN@A-ADDRESS \
    --replace-local-database -i ~/.ssh/<your key>
```

`--replace-local-database` is required because A's database is being thrown away, and the
join does not do that unless told to. Without it the join stops with `this host's Postgres is
not running, so what its database holds cannot be checked`. On a lab pair the rebuild took
2 minutes 11 seconds, and it ends like step 2, with the servers named the other way round.

Check it as in step 3, with A and B swapped. The pair is complete again, with B as the
primary. A can issue certificates too while it is the standby: its services sign with A's
own keys and write to B's database. Either server can be the primary; a pair has no fixed
main server.

### Step 6 — switch back: make A the primary again (optional)

After step 5, B is the primary and A is its standby. The pair works like that, and there is
no need to switch back. Do it when you want A to be the primary again, for example for
maintenance on B, or to test a planned switchover.

It is step 4 and step 5 with the roles swapped. Unlike a failure, a planned switch loses
nothing: A has a live copy up to the moment B's database stops. Issuing pauses between
stopping B's database and promoting A.

1. **On B**, check that A is streaming, then stop B's database:
   ```bash
   docker compose exec postgres psql -U fastpki -d fastpki -c 'SELECT client_addr, state FROM pg_stat_replication'
   docker compose stop postgres
   ```
2. **On A**, promote A, then load the settings the script rewrote. The last command must
   print `f`:
   ```bash
   ./pg-promote.sh
   docker compose up -d
   docker compose exec postgres psql -U fastpki -d fastpki -tAc 'SELECT pg_is_in_recovery()'
   ```
3. **Point `PKI_DNS` back at A** (the DNS record, or the `/etc/hosts` line on each client in a
   test setup).
4. **From your own computer**, rebuild B as A's standby, with B's database still stopped:
   ```bash
   deploy/ha-join-pair.sh --primary YOUR-LOGIN@A-ADDRESS --standby YOUR-LOGIN@B-ADDRESS \
       --replace-local-database -i ~/.ssh/<your key>
   ```

The pair is back where step 2 left it: A the primary, B the standby.

---

## 7. Native install — Alpine + OpenRC (no Docker)

**Alpine only.** The shipped container image is Alpine, so Alpine is the only platform these
binaries are tested on. The installer stops on anything else.

**Software.** Alpine Linux with OpenRC. The installer checks for both and stops if the host
is anything else. It also needs the `postgresql17` package when the database runs on the same
host. The patched key-storage software is built by step 1 below.

**Hardware for one server**

| | |
|---|---|
| **CPU** | 2 processors. The load average stays at 0.00 with every service running |
| **Memory** | 239 MB, measured on a machine with 924 MB |
| **Disk** | 264 MB for the system, 64 MB for the data |

[`architecture.md`](architecture.md#11-resource-footprint) §11 has the same figures for the
other ways of running FastPKI.

**From a release, it is one command.** On a new Alpine machine, as root:

```bash
curl -fsSL https://github.com/fastpki/fastpki/releases/latest/download/install.sh \
  | bash -s -- --native
```

That downloads the compiled package for this machine's processor, checks it against the
release's `SHA256SUMS`, unpacks it, and then asks the same questions as a Docker install.
Nothing is compiled on your server. Add `--answers <file>` to answer them from a file, or
`--version <tag>` to pin a release instead of taking the newest.

**From a source checkout it is two steps**, because a checkout has no published package for
the code in it — so the programs have to be built first. The two steps are separate on
purpose:

```bash
# On a new Alpine machine, as root.
# Step 1, BUILD. Slow, and exactly the same on every machine. It builds the patched
# pkcs11-provider, p11-kit and SoftHSM (§7.2 says why they are patched), then FastPKI
# itself, and installs the service files.
sh deploy/native/build-native.sh

# Step 2, CONFIGURE. Fast, and different on every machine. It asks the same questions as
# deploy/install.sh, in the same order, with the same defaults.
bash deploy/native/install-native.sh
```

`./install.sh --native` from a checkout runs step 2 for you, and says so if step 1 has not
been done.

You can give step 2 your answers in a file, with `install-native.sh --answers <file>`. It is
the same file `deploy/install.sh` accepts, so answers from a Docker install configure a
native one unchanged.

Step 2 writes the settings file the programs read (`/etc/fastpki/bootstrap.conf`) and the one
the services read (`/etc/conf.d/fastpki`), sets up PostgreSQL, runs the same three scripts
the Docker install runs, and switches on one service for each protocol you asked for.

The build and the configuration are separate steps: the build happens once, when the machine
image is made, and every server that starts from it runs only the configuration step (§12).

### 7.1 The services are restarted for you, even when they exit cleanly

This is the one place where a native install differs from the Docker install in a way that
breaks FastPKI, rather than just looking different.

FastPKI services are built to exit and be started again, rather than to repair themselves.
There are three times a service stops on purpose, reporting success rather than failure, and
each one expects something to start it again:

* Its connection to the key store has died, because the key store or the program in front of
  it restarted. A program sets that connection up once when it starts and cannot rebuild it,
  so only a fresh start recovers.
* You switched that protocol off in the console. The service exits, comes back, sees it is
  switched off, and waits without opening its port.
* Something asked that protocol to restart.

With Docker, `restart: unless-stopped` takes care of it. On a native install, every service
file in `deploy/native/openrc/` uses `supervise-daemon` with `respawn_max=0`. With OpenRC's
default supervisor a service that exits is started once and never again, so switching a
protocol back on in the console leaves it permanently down with nothing in any log to say
why; with `supervise-daemon`'s default restart limit the same thing happens on a server whose
key store has restarted a few times.

```bash
rc-service fastpki-web status
rc-service fastpki-web restart
rc-status                              # everything in the default runlevel
tail -f /var/log/fastpki/fastpki-web.log
```

### 7.2 Key storage on a native install — patch p11-kit first

**Read this before you create an Ed25519 or ML-DSA CA on a native install.** The p11-kit that
comes with your distribution hides both algorithms without saying so, and the error you get
names something else entirely.

Two pieces of software sit between FastPKI and the key store, and both matter:

| piece | why it is there |
|---|---|
| **pkcs11-provider** | the OpenSSL 3 provider that turns a `pkcs11:` URI into a usable key |
| **p11-kit server** (SoftHSM only) | runs SoftHSM **out of process**. In-process, SoftHSM's OpenSSL backend re-enters libcrypto while libcrypto holds a lock and the binary **deadlocks**. A hang is worse than a failure — it never returns. **A vendor HSM module usually has no such problem: load it directly (`PKCS11_MODULE=/opt/…/libcknfast.so`) and p11-kit is out of the path entirely, which is the recommended production shape.** |

When p11-kit passes requests along, it drops anything it does not recognise, and version
0.26.4 does not recognise four things FastPKI needs: `CKM_ML_DSA`,
`CKM_ML_DSA_KEY_PAIR_GEN`, `CKM_EDDSA` and `CKM_EC_EDWARDS_KEY_PAIR_GEN`. Measured against
SoftHSM, the key store offers 82 operations and p11-kit passes on 62 of them.

So without the patch, those two algorithms simply do not exist as far as FastPKI can tell.
Asking for one fails with `CKR_TOKEN_NOT_PRESENT`, which reads as "there is no key store
here" when the real answer is "that algorithm did not get through".

**Both the container image and a native install ship the patched build**, and neither
does it by hand: `deploy/native/build-native.sh` (§7) applies this patch and the two
others, and it reads its version pins **out of the Dockerfile** so the two build paths
cannot drift to different commits. The step is:

```bash
git clone --depth 1 --branch 0.26.4 https://github.com/p11-glue/p11-kit /tmp/p11kit
patch -p1 --forward -d /tmp/p11kit -i "$PWD/deploy/p11-kit-mechanisms.patch"
meson setup /tmp/p11kit/build /tmp/p11kit --prefix=/usr --libdir=lib -Dbuildtype=release
ninja -C /tmp/p11kit/build && sudo ninja -C /tmp/p11kit/build install
```

You need it by hand only if you are assembling a host some other way. Note that **both
sides of the socket** must carry it: the patch edits `p11-kit/rpc-message.c`, which
compiles into `libp11-kit.so.0`, so replacing that library and the client shim covers the
packaged `p11-kit-server` binary too — it picks the fix up through the library it links.

Reported upstream as
[p11-glue/p11-kit#776](https://github.com/p11-glue/p11-kit/issues/776). When a fix lands
in a release, a distro carrying that release needs none of this.

You do not need any of this for **RSA or ECDSA**: those relay fine unpatched. The
console tells you which algorithms the selected token will actually generate, so
if Ed25519 or ML-DSA is missing from the New CA dropdown on a native install, this
section is why.

---

### 7.3 Checking a native deployment without a cloud account

Two scripts, both free and both local:

```bash
sh deploy/native/build-check.sh --image fastpki-baked:local   # the BAKE  (~20 min)
sh deploy/native/run-check.sh                                 # the BOOT  (~3 min)
```

`build-check.sh` runs the real build script in a throwaway Alpine container. `run-check.sh`
then starts that image with a real init system, runs the installer from beginning to end, and
checks the things the build alone cannot show you:

- PostgreSQL starts, using the certificate `certgen` made for it minutes earlier;
- the key store hands its socket to the user the services run as;
- the console answers over HTTPS;
- a protocol you did not ask for is not running;
- a protocol switched off in the settings exits, gets started again, and comes back with its
  port closed.

Neither check starts a real machine, so the parts that only a real machine exercises — the
first-boot configuration, the AWS disk and network drivers, and the boot loader — stay
untested until you launch a server.

## 8. Kubernetes

The same deployment as §3, written as Kubernetes manifests. Nothing that exists on the Docker
Compose path is missing here.

**Software.** You need `kubectl` and `envsubst` (the `gettext` package) on the machine you run
`apply.sh` from. The cluster needs a storage class that gives out disks one server can write
to at a time; the cluster's default is normally right, because each disk belongs to a single
server. The manifests use only `v1`, `apps/v1` and `networking.k8s.io/v1`, so any current
Kubernetes will run them.

**Hardware for one server**

| | |
|---|---|
| **CPU** | 20 millicores — one fiftieth of a processor — while the server is idle |
| **Memory** | 100 MB for the pod's eleven containers, once settled. Postgres is 55 MB of that |
| **Disk** | three volumes per server; 48 MB in use to begin with |

[`architecture.md`](architecture.md#11-resource-footprint) §11 has the same figures for the
other ways of running FastPKI.

Three walkthroughs, then the reference behind them:

| | |
|---|---|
| **§8.0** | install **one server**: nine steps, from an empty machine to a CA that issues certificates |
| **§8.0a** | what is different from the Docker installation |
| **§8.0b** | install **two machines**, so one can take over from the other. A complete installation on its own, not an addition to §8.0 |
| **§8.0c** | add another **data center** |
| §8.1 – §8.7 | reference: what `apply.sh` creates, how each server keeps its own keys, how to copy a key to the other server, the settings, taking over after a failure, reaching the deployment from outside, and updating |

§8.0 and §8.0b are alternatives: choose one and follow it from its first step. §8.0c
extends either of them, and does not require a new installation.

The short form of the installation is:

```bash
./install.sh --k8s                        # hands straight over to k8s/apply.sh (env from k8s/env.sh, or env.local)
# or, directly:
IMAGE=ghcr.io/fastpki/fastpki:<version> PKI_DNS=pki.example.org bash deploy/k8s/apply.sh
```

Throughout this guide `<version>` means the release tag you are installing, written exactly
as the release names it, leading `v` included. The releases page lists them:
<https://github.com/fastpki/fastpki/releases>. When you install from a release rather than
from a checkout, `install.sh` already knows the tag and fills `IMAGE` in for you, so the
first command needs nothing else.

⚠️ Neither command installs Kubernetes, and neither builds the image. Set `IMAGE` to a
published release and the cluster pulls it; §8.0 step 3 covers both that and building your
own.

All configuration is by environment variables read from `deploy/k8s/env.sh`. Every setting
has a default, so the two shown above are the minimum worth setting.
`deploy/k8s/delete.sh` removes the namespace and everything in it.

### 8.0 Install a single server on Kubernetes, step by step

This section performs §3 and §4 on Kubernetes, on **one machine**. Completing it gives the
same working deployment: a console, a CA, and clients that can enrol. §8.1 onwards describes
each component in detail and is not required in order to install.

For a pair of machines with a database standby, use §8.0b instead. It is a complete
installation in itself and does not depend on this section.

The commands are written for **k3s**, a small Kubernetes distribution that installs with a
single command. Any other Kubernetes distribution can be used; only steps 1 and 3 are
specific to k3s.

Replace the following with your own values wherever they appear. They are written without
angle brackets, because a literal `<name>` in a command causes the shell to treat it as a
file redirection:

| Written here | Means |
|---|---|
| `pki.example.org` | the name clients will use to reach this deployment. It is written into every certificate, so it must resolve from wherever the clients run |
| `NODE-ADDRESS` | the server's own IP address |
| `YOUR-CA-ID` | the identifier of the CA created in step 7, for example `issuing-ca` |

#### Before you start

You need **one Linux server** with 2 GB of memory, and a web browser on your own computer to
reach the console. Measured on a 2 GB machine: k3s and one FastPKI server together used 1,032 MB
of memory and 2.4 GB of disk, the FastPKI pod 118 MiB of that memory.

A second data center can be added to this deployment later by running `apply.sh` again
(§8.0c). So can a second server on a second machine: join the machine to the cluster (§8.0b
step 2), set `HA_ENABLED=true` and run `apply.sh` again. The second server copies every key from
the first, which only works for keys created with **replicable key** (step 7).

⚠️ **Adding that second server also means replacing the OCSP, CMP and SCEP credentials**,
because a single server creates them without replicable keys — the stronger choice for one
server, and one that can never be copied afterwards. §8.5 gives the commands, and they run
when you add the second server, not now.

On the server you need `git`, `curl` and `envsubst`. `docker` is needed only if you build
the image yourself rather than using a published release (step 3). On Debian or Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y git curl docker.io gettext-base
sudo usermod -aG docker $USER
```

**Log out and log in again.** A new group membership takes effect only in a new login
session. Then check that both of these commands run without an error:

```bash
docker ps        # prints an empty table header
envsubst --help  # prints usage
```

#### Step 1 — on the server: install k3s

```bash
curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644 --disable traefik
```

Both options are required:

- `--write-kubeconfig-mode 644` allows `kubectl` to be run by your own user account.
  Without it, every command fails with `permission denied` (§8.4).
- `--disable traefik` leaves ports 80 and 443 free. k3s installs its own web front end on
  those ports, and ACME's http-01 and tls-alpn-01 challenges require them (§8.6).

Set the location of the cluster configuration for `kubectl`, and make it permanent:

```bash
cd ~
echo 'export KUBECONFIG=/etc/rancher/k3s/k3s.yaml' >> ~/.profile
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl get nodes
```

The node must report **Ready**. If it reports `NotReady`, wait a minute and run the
command again.

#### Step 2 — on the server: get the source

```bash
cd ~
git clone https://github.com/fastpki/fastpki.git
ls ~/FastPKI/Dockerfile
```

The last line must print the path, not `No such file or directory`. The remaining steps
are run from inside that directory.

#### Step 3 — decide where the image comes from

There are two ways to obtain the image. **Option A is the normal one**, and requires no
build and no further work on this step.

##### Option A — use a published release (recommended)

Each release publishes a multi-arch image to the GitHub container registry, for amd64 and
arm64. Nothing needs to be built or copied: the cluster pulls the image itself, on every
node, whenever a pod starts.

Find the current version on the
[releases page](https://github.com/fastpki/fastpki/releases), then use it in step 4:

```
IMAGE=ghcr.io/fastpki/fastpki:<version>
```

⚠️ **Name a version; do not use `:latest`.** A release candidate deliberately does not move
the `latest` tag, so `latest` may be older than the release you intend to install, or may
not exist at all.

⚠️ **The manifests and the image must be the same version.** `apply.sh` and the manifests
come from the checkout, the binaries from the image, and a newer manifest can require a
command the older image does not have. After cloning, check out the release you are
installing:

```bash
cd ~/FastPKI && git checkout <version>
```

If you want what is on `main`, which is usually ahead of the newest release, build the image
yourself with option B instead.

The cluster's nodes must be able to reach `ghcr.io`. Nothing else is required, and you can
go to step 4.

##### Option B — build it yourself

Build the image when you have changed the source, or when the cluster cannot reach
`ghcr.io`.

⚠️ **k3s does not use Docker.** It runs containerd, so an image listed by `docker images`
is not visible to the cluster, and the pods stop with `ErrImagePull`. Build the image, then
load it into the cluster:

```bash
cd ~/FastPKI && docker build -t fastpki:latest . \
    && docker save fastpki:latest | sudo k3s ctr images import -
```

Keep the `&&`. Without it, a `cd` that fails still allows the build to run in the wrong
directory, and the first error is followed by two more that are not the cause.

The build takes 15-25 minutes. Check the cluster can see the image:

```bash
sudo k3s ctr images ls | grep fastpki
```

It must print `docker.io/library/fastpki:latest`. This is the same image as
`fastpki:latest`, so step 4 refers to it as `fastpki:latest`. If your connection was
interrupted during the build, run this check before building again: the build runs in the
Docker daemon rather than in your shell, and usually continues.

⚠️ **An image built this way exists only on the machine that built it**, which is all a
single node needs. A cluster of more than one machine is simpler with a registry (§8.4).

#### Step 4 — on the server: write your settings

`env.sh` contains a default for every setting. Place only your own values in `env.local`,
which is read first and takes precedence:

```bash
cd ~/FastPKI/deploy/k8s
cat > env.local <<'EOF'
IMAGE=ghcr.io/fastpki/fastpki:<version>
PKI_DNS=pki.example.org
WEB_SERVICE_TYPE=LoadBalancer
PROTO_SERVICE_TYPE=LoadBalancer
EOF
```

These four settings have the following effect:

| Setting | Effect |
|---|---|
| `IMAGE` | the image chosen in step 3: a published release, as shown here, or `fastpki:latest` if you built it yourself |
| `PKI_DNS` | the name written into every certificate. **Set this correctly before step 7**: a CA retains the name it was created with |
| `WEB_SERVICE_TYPE=LoadBalancer` | publishes the console on the node's own address. The default, `ClusterIP`, is reachable only from within the cluster |
| `PROTO_SERVICE_TYPE=LoadBalancer` | publishes EST, ACME, CMP, SCEP, OCSP and the store in the same way. Without it, no client can enrol (§8.6) |

§8.4 lists the remaining settings.

A second data center is added later in §8.0c.

#### Step 5 — on the server: apply it

```bash
cd ~/FastPKI/deploy/k8s
bash apply.sh
```

It creates each object in order and waits for it before continuing (§8.1 lists what it
creates and why the order matters). It takes a few minutes. The final lines print how to
reach the console.

Check every pod is up:

```bash
kubectl -n fastpki get pods
```

The server, `fastpki-node-0`, must report `Running`, with every container ready — the two numbers
in the READY column equal. If it reports `Pending` or `ErrImagePull`, examine it:

```bash
kubectl -n fastpki describe pod fastpki-node-0 | tail -20
```

#### Step 6 — on your own computer: open the console

```
https://NODE-ADDRESS:8090/
```

Your browser will warn about the certificate. This is expected: the console signs its own
certificate until a CA exists to replace it (step 8). Continue past the warning.

Sign in as **admin** with the password **admin**. The console requires the password to be
changed immediately.

#### Step 7 — in the console: create the CAs

A new installation has no CA and cannot issue anything. You create two:

- a **root CA**, the top of the trust chain. Clients trust it, and it signs only other CAs.
- an **issuing CA** beneath it, which signs the certificates that users, servers and
  devices request.

Each CA's private key is created inside the token and never exists as a file. The console
is the same on every platform, so this is §4.3 performed on this deployment; §4.3 also
explains the reasons behind each choice.

⚠️ **Select "replicable key" on every CA, including the root, unless you are certain this
deployment will never have a second server (§8.0b).** A CA whose key is not replicable can
never be copied to a second token. It cannot be enabled afterwards, and the only remedy is to
create a new CA.

**Create the root CA.**

1. Open the **CAs** tab and click **+ New CA**.
2. Under **Identity**:
   - **id**: `root-ca`. This is the short name used by URLs and commands.
   - **display name**: `Example Root CA`, or any text you prefer.
   - **Parent CA**: leave **— none (root) —**.
   - **CN**: `Example Root CA`. The other name fields (OU, O, L, ST, C) are optional.
3. Under **Key & signature**:
   - **Algorithm**: keep **RSA** with **4096** bits. This works with every client. Read
     `compatibility.md` before choosing another algorithm.
   - Leave **use an existing key** unselected, so that a new key is created in the token.
   - **replicable key**: select it if a second server may be added. This cannot be changed
     later.
   - **Slot** and **PIN file** are completed for you. Do not change them.
   - **Key name**: `root-ca`. This is the key's name inside the token and must not already be
     in use.
4. Under **Validity**: leave both dates empty. The CA is then valid for ten years.
5. Leave **Constraints** and **Advanced** unchanged. For a root CA the AIA and CRL fields
   are unavailable, which is correct: a root CA carries neither.
6. Click **Create CA**.

**Create the issuing CA.**

1. Click **+ New CA** again.
2. Under **Identity**:
   - **id**: `issuing-ca`. Use `dc1-sub` instead if you plan to add data centers (§8.0c).
     Deciding later costs nothing: the id is a label, not a property of the key, and the
     second data center simply uses an id of its own. Two data centers must not share one id,
     because CA registrations replicate between them.
   - **display name**: `Example Issuing CA`.
   - **Parent CA**: select **root**.
   - **CN**: `Example Issuing CA`.
3. Under **Key & signature**:
   - **Algorithm**: keep **RSA**, and select **3072** bits.
   - Leave **use an existing key** unselected.
   - **replicable key**: select it if a second server may be added, exactly as for the
     root. This CA signs every certificate, so without it a second server cannot issue.
   - **Key name**: `issuing-ca`, the same as the id.
4. Under **Validity**: leave both dates empty, or set **Not after** to approximately five
   years from today. An issuing CA cannot be valid for longer than its root; a later date,
   including the ten-year default, is shortened to the root's end date.
5. Open **Advanced** and check the two addresses shown under **caIssuers** and **CRL DP**.
   They must contain the name you set as `PKI_DNS` in step 4, for example
   `http://pki.example.org:8080/root-ca.crl`. If they show a different name, or no name, stop
   here and correct the name first (§5). These addresses are written into every certificate
   and cannot be changed afterwards.
6. Click **Create CA**.

**Check the result.** The CAs tab now lists two CAs, both with **Status** `active`. The
issuing CA's **Issuer** column shows the root CA's name.

The id of the issuing CA — `issuing-ca`, unless you chose another — is the value to use as
`YOUR-CA-ID` in step 8.

⚠️ **Now press Disable on the root's row.** It has signed the issuing CA, which was its whole
job, and nothing else should ever be signed with it. Disabling stops new issuance and leaves
its revocation list, OCSP answers and chain serving untouched — §4.3 explains why those stay,
and how to re-enable it for as long as it takes to sign the next issuing CA.

#### Step 8 — on the server: issue the service certificates

This is §4.4 on Kubernetes. Name the CA in the two settings that need it, then run
`apply.sh` again rather than waiting for tonight's renewal:

```bash
cd ~/FastPKI/deploy/k8s
kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set PG_TLS_CA_ID YOUR-CA-ID
kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set CMP_CLIENT_CA_ID YOUR-CA-ID
bash apply.sh
```

`PG_TLS_CA_ID` names the CA that signs the database's certificate. `CMP_CLIENT_CA_ID` names
the CA that CMP trusts when a client signs its own request, and it is not optional in
practice: without it CMP refuses **every** signature-protected request, so a client can
enrol with a shared secret but can neither renew with `kur` nor revoke its own certificate.
The only other sign is a warning in the `cmp` log, `CMP has no client-CA trust anchor`.
Neither value is guessed. CMP reads its value at start, and `apply.sh` restarts the listeners.

It creates the OCSP, CMP and SCEP credentials, replaces the self-signed certificate on each
listener with one issued by your CA, issues the database certificate, and restarts the
listeners so they serve their new certificates. The lines under `Creating any missing service
credentials` list what it did.

#### Step 9 — issue a certificate and check the result

Reload the console. The browser warning is no longer shown, because the console now serves
a certificate issued by your CA.

Then confirm that the deployment issues certificates to a client. Run the following on the
server, in order: each command produces what the next one needs. Replace `NODE-ADDRESS`
with the server's address, and `issuing-ca` with your issuing CA's id if you chose another.

**1. Create an account that is allowed to enrol.** The `standard` role cannot enrol;
`requester` can. Choose your own password in place of `D3mo-Pass`:

```bash
kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf web-user demo 'D3mo-Pass' --role requester
```

**2. Fetch the CA chain over EST.** This is also the trust anchor the later checks use:

```bash
cd ~
curl -sk https://NODE-ADDRESS:8443/.well-known/est/issuing-ca/cacerts \
  | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out ca-chain.pem
openssl x509 -in ca-chain.pem -noout -subject -issuer
```

The subject and issuer printed must be your two CAs. If the command returns nothing,
`PROTO_SERVICE_TYPE` is not `LoadBalancer` (step 4) and the listener is not reachable.

**3. Create a key and a request, then enrol it over EST:**

```bash
openssl req -new -newkey rsa:2048 -nodes -keyout test.key -out test.csr -subj "/CN=test"
curl -sk -u demo:'D3mo-Pass' \
  --data-binary @<(openssl req -in test.csr -outform DER | openssl base64 -A) \
  -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" \
  https://NODE-ADDRESS:8443/.well-known/est/issuing-ca/simpleenroll \
  | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out test.pem
openssl x509 -in test.pem -noout -subject -issuer -dates
```

The certificate's subject must be `CN = test`, and its issuer your issuing CA.

**4. Ask OCSP for that certificate's status:**

```bash
openssl ocsp -issuer ca-chain.pem -cert test.pem \
    -url http://NODE-ADDRESS:8080/ocsp -resp_text -noverify | grep -A1 "Cert Status"
```

It must answer `good`. An answer of `Responder Error: internalerror` means step 8 has not
completed: the responder has no certificate of its own (§4.4b).

**5. Fetch the CRL**, which is published for each CA at `/{ca-id}.crl`:

```bash
curl -s http://NODE-ADDRESS:8080/issuing-ca.crl -o crl.der
openssl crl -inform DER -in crl.der -noout -text | head -20
```

The deployment is now working. `user-guide.md` §6–§10 has full client examples for EST,
ACME with certbot, CMP with `openssl cmp`, SCEP and Microsoft enrolment.
`demo/provision-target.sh --k8s` (§8.6) configures a client against this deployment with a
single command, and runs all of them.

---

### 8.0a What is different from the Docker install

| | Docker Compose (§3) | Kubernetes (§8) |
|---|---|---|
| Obtaining the image | `install.sh` builds it, or pulls it if `FASTPKI_IMAGE` names a registry | set `IMAGE` to a published release and the cluster pulls it, or build and load it yourself (step 3) |
| Prompts for configuration | yes, a wizard writes `deploy/.env` | no: you write `deploy/k8s/env.local` (step 4) |
| Where settings are held | `deploy/.env` | `deploy/k8s/env.local` |
| Reaching the console | published on the host's port | only when configured: `WEB_SERVICE_TYPE=LoadBalancer`, or a port-forward |
| Restarting a service | `docker compose restart NAME` | `kubectl -n fastpki exec fastpki-node-0 -c NAME -- kill 1`, on each server (`fastpki-node-1` too, in a pair). It restarts that container in place and leaves the pod's database running |
| Running a command in the CA | `docker compose exec web fastpki-ca …` | `kubectl -n fastpki exec statefulset/fastpki-node -c web -- fastpki-ca …` |
| Updating | run `install.sh` again | load the new image, then run `apply.sh` again (§8.7) |

Everything else is identical: the console, the CAs, the protocols and the certificates.

### 8.0b Install a pair of servers for high availability, step by step

This section installs FastPKI on **two machines**, as one Kubernetes cluster running two
FastPKI servers — one on each machine, each with its own token, its own database and a full set
of services. It is complete in itself: §8.0 installs a single node, and a reader following this
section does not need it.

**What a pair protects.** Either machine can be lost. The second server's database streams from
the first, and each server copies every CA and service key it is missing from the other, so the
survivor can promote its database and keep issuing. §8.5 describes the arrangement, promotion,
and bringing the lost server back.

The commands are written for **k3s**, a small Kubernetes distribution that installs with a
single command. Any other Kubernetes distribution can be used; only steps 1, 2 and 4 are
specific to k3s.

Replace the following with your own values wherever they appear. They are written without
angle brackets, because a literal `<name>` in a command causes the shell to treat it as a
file redirection:

| Written here | Means |
|---|---|
| `pki.example.org` | the name clients will use to reach this deployment. It is written into every certificate, so it must resolve from wherever the clients run |
| `FIRST-ADDRESS` | the first machine's own IP address |
| `SECOND-ADDRESS` | the second machine's own IP address |
| `YOUR-LOGIN` | your login name on the second machine |
| `YOUR-CA-ID` | the identifier of the issuing CA created in step 9, for example `issuing-ca` |

#### Before you start

You need **two Linux servers**, each with 2 GB of memory, and a web browser on your own computer
to reach the console. Measured on a pair of 2 GB machines: the first, which also runs the
cluster's control plane, used 1,032 MB of memory and 2.4 GB of disk; the second 497 MB and
2.1 GB. The two FastPKI pods used 118 MiB and 66 MiB. Nothing else: no shared storage and no third
machine, because the two servers share nothing but the network between them.

On **both** servers install the packages. `docker` is needed only on the first machine, and
only if you build the image yourself rather than using a published release (step 4):

```bash
sudo apt-get update
sudo apt-get install -y git curl docker.io gettext-base
sudo usermod -aG docker $USER
```

**Log out and log in again.** A new group membership takes effect only in a new login
session. Then check that both of these commands run without an error:

```bash
docker ps        # prints an empty table header
envsubst --help  # prints usage
```

#### Step 1 — on the first machine: install k3s

```bash
curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644 --disable traefik
```

Both options are required:

- `--write-kubeconfig-mode 644` allows `kubectl` to be run by your own user account.
  Without it, every command fails with `permission denied` (§8.4).
- `--disable traefik` leaves ports 80 and 443 free. k3s installs its own web front end on
  those ports, and ACME's http-01 and tls-alpn-01 challenges require them (§8.6).

Set the location of the cluster configuration for `kubectl`, and make it permanent:

```bash
cd ~
echo 'export KUBECONFIG=/etc/rancher/k3s/k3s.yaml' >> ~/.profile
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl get nodes
```

The node must report **Ready**. If it reports `NotReady`, wait a minute and run the command
again.

#### Step 2 — join the second machine to the cluster

⚠️ **Do not run step 1 on the second machine.** That command installs a k3s *server*, which
creates a second, independent cluster. The second machine joins the existing cluster as an
**agent**.

Both commands below run **on the first machine**. Only the line they produce is run on the
second machine.

**On the first machine**, find its own address. It must be one the second machine can
reach:

```bash
ip -4 -o addr show scope global | awk '{print $2, $4}'
```

It prints one line for each address, with the prefix length attached:

```
eth0 192.0.2.10/24
```

⚠️ **Use the address only, without the `/24`.** The address with the last part set to zero,
`192.0.2.0` here, is the network itself and nothing answers on it: the agent installs, then
retries for ever and never returns to the prompt.

Ignore the virtual interfaces in that list. `docker0`, `flannel.1` and `cni0` belong to
Docker and to k3s itself, and an interface belonging to a VPN is not a network the two
machines share directly.

If the machine has more than one real address, use the one the cluster already uses for
itself:

```bash
kubectl get nodes -o wide
```

The address under `INTERNAL-IP` is the one k3s chose when it was installed. Joining on that
same network keeps the API connection and the traffic between pods on one link, which
matters when a fault has to be traced. The address is permanent: it is written into the
agent's service file and used for every reconnection.

**Still on the first machine**, print the whole join command, replacing `FIRST-ADDRESS`
with that address. The command reads this machine's node token, which exists only here:

```bash
echo "curl -sfL https://get.k3s.io | K3S_URL=https://FIRST-ADDRESS:6443 K3S_TOKEN=$(sudo cat /var/lib/rancher/k3s/server/node-token) sh -"
```

Copy the single line it prints and run it on the **second** machine. It returns to the
prompt when the join succeeds. If it stops at `systemd: Starting k3s-agent` and stays there,
the address is wrong; press Ctrl-C and read the recovery note below.

⚠️ **Print the command; do not copy the token on its own.** It is long and belongs in the
middle of a line, and a paste that lands in the wrong place reports
`-bash: -sfL: command not found`, which does not indicate the real cause.

**If the join has to be repeated** — the wrong address, or a k3s server already installed —
remove what is there before running it again. On the **second** machine, whichever applies:

```bash
sudo /usr/local/bin/k3s-agent-uninstall.sh   # an agent, from a join that failed
sudo /usr/local/bin/k3s-uninstall.sh         # a server, which cannot coexist with an agent
```

`sudo journalctl -u k3s-agent -n 20` gives the reason a join failed.

Then, on the **first** machine, both machines must appear in one list:

```bash
kubectl get nodes
```

The first machine is listed with the role `control-plane`, the second with `<none>`. Both
must report `Ready`.

⚠️ **Every `kubectl` command in this section is run on the first machine.** An agent holds no
cluster configuration, so `kubectl` on the second machine answers with an error rather than
with the cluster: `The connection to the server localhost:8080 was refused` before it joins,
and `the server could not find the requested resource` afterwards. Both are the expected
answer on an agent, not a fault.

#### Step 3 — on the first machine: get the source

```bash
cd ~
git clone https://github.com/fastpki/fastpki.git
ls ~/FastPKI/Dockerfile
```

The last line must print the path, not `No such file or directory`. The remaining commands
are run from inside that directory, on the first machine, unless a step says otherwise.

#### Step 4 — decide where the image comes from

Both machines need the image: each runs one of the two servers, and a node without it reports
`ErrImagePull`, after which `apply.sh` stops waiting for that server's database certificate.

##### Option A — use a published release (recommended)

Each release publishes a multi-arch image to the GitHub container registry, for amd64 and
arm64. **Both nodes pull it themselves, so there is nothing further to do on this step.**

Find the current version on the
[releases page](https://github.com/fastpki/fastpki/releases), then use it in step 5:

```
IMAGE=ghcr.io/fastpki/fastpki:<version>
```

⚠️ **Name a version; do not use `:latest`.** A release candidate deliberately does not move
the `latest` tag, so `latest` may be older than the release you intend to install, or may
not exist at all.

⚠️ **The manifests and the image must be the same version.** `apply.sh` and the manifests
come from the checkout, the binaries from the image, and a newer manifest can require a
command the older image does not have. After cloning, check out the release you are
installing:

```bash
cd ~/FastPKI && git checkout <version>
```

If you want what is on `main`, which is usually ahead of the newest release, build the image
yourself with option B instead.

Both machines must be able to reach `ghcr.io`.

##### Option B — build it yourself

Build the image when you have changed the source, or when the cluster cannot reach
`ghcr.io`. A locally built image has to be placed on **both** machines by hand, and again
after every rebuild.

⚠️ **k3s does not use Docker.** It runs containerd, so an image listed by `docker images` is
not visible to the cluster. Build it on the first machine, then load it into the cluster:

```bash
cd ~/FastPKI && docker build -t fastpki:latest . \
    && docker save fastpki:latest | sudo k3s ctr images import -
```

Keep the `&&`. Without it, a `cd` that fails still allows the build to run in the wrong
directory, and the first error is followed by two more that are not the cause.

The build takes 15-25 minutes. Check the cluster can see the image:

```bash
sudo k3s ctr images ls | grep fastpki
```

It must print `docker.io/library/fastpki:latest`. This is the same image as
`fastpki:latest`, so step 5 refers to it as `fastpki:latest`.

Then copy it to the second machine. On the **first** machine:

```bash
docker save fastpki:latest -o /tmp/fastpki.tar
scp /tmp/fastpki.tar YOUR-LOGIN@SECOND-ADDRESS:/tmp/
ssh YOUR-LOGIN@SECOND-ADDRESS 'sudo k3s ctr images import /tmp/fastpki.tar && rm /tmp/fastpki.tar'
rm /tmp/fastpki.tar
```

A registry both machines can reach avoids this copy, and handles every node that joins
later without further work. §8.4 covers declaring a registry to containerd.

The second machine can also build its own copy, with the same two commands, provided it
builds the **same commit**: one tag serving two different builds is a fault that is hard to
trace. It costs a second build of 15-25 minutes and the disk the build cache uses, which
`docker builder prune -af` releases afterwards.

#### Step 5 — on the first machine: write your settings

`env.sh` contains a default for every setting. Place only your own values in `env.local`,
which is read first and takes precedence:

```bash
cd ~/FastPKI/deploy/k8s
cat > env.local <<'EOF'
IMAGE=ghcr.io/fastpki/fastpki:<version>
PKI_DNS=pki.example.org
WEB_SERVICE_TYPE=LoadBalancer
PROTO_SERVICE_TYPE=LoadBalancer
HA_ENABLED=true
EOF
```

| Setting | Effect |
|---|---|
| `IMAGE` | the image chosen in step 4: a published release, as shown here, or `fastpki:latest` if you built it yourself |
| `PKI_DNS` | the name written into every certificate. **Set this correctly before step 9**: a CA retains the name it was created with. It must be a name for the deployment, not one machine's host name |
| `WEB_SERVICE_TYPE=LoadBalancer` | publishes the console on the nodes' own addresses. The default, `ClusterIP`, is reachable only from within the cluster |
| `PROTO_SERVICE_TYPE=LoadBalancer` | publishes EST, ACME, CMP, SCEP, OCSP and the store in the same way. Without it, no client can enrol (§8.6) |
| `HA_ENABLED=true` | two servers instead of one, required to run on different machines, with the token transport the keys are copied over (§8.5) |

§8.4 lists the remaining settings. A second data center is added in §8.0c.

#### Step 6 — on the first machine: apply it

```bash
cd ~/FastPKI/deploy/k8s
bash apply.sh
```

It creates each object in order and waits for it before continuing (§8.1 lists what it
creates and why the order matters). It takes a few minutes. The last lines list both servers
with the machine each runs on, name the one holding the read-write database, and print how to
reach the console.

Check both servers are up, and on which machine each one runs:

```bash
kubectl -n fastpki get pods -o wide
```

`fastpki-node-0` and `fastpki-node-1` must each report `Running`, with every container ready — the two
numbers in the READY column equal — and they must be on different machines. If a server reports
`Pending` or `ErrImagePull`, examine it:

```bash
kubectl -n fastpki describe pod fastpki-node-1 | tail -20
```

`Pending` with `didn't match pod anti-affinity rules` means only one machine can take a server:
step 2 did not complete. `ErrImagePull` on the second machine means step 4 option B was not
completed there.

#### Step 7 — check the standby is streaming

`fastpki-node-1`'s database must answer `t` — "yes, I am a read-only standby":

```bash
kubectl -n fastpki exec fastpki-node-1 -c postgres -- \
    psql -U fastpki -d fastpki -tAc 'SELECT pg_is_in_recovery()'
```

`fastpki-node-0` must show it, with `state` = `streaming`:

```bash
kubectl -n fastpki exec fastpki-node-0 -c postgres -- \
    psql -U fastpki -d fastpki -c 'SELECT application_name, client_addr, state FROM pg_stat_replication'
```

Promoting the standby when the first server is really gone is §8.5.

#### Step 8 — on your own computer: open the console

```
https://FIRST-ADDRESS:8090/
```

Your browser will warn about the certificate. This is expected: the console signs its own
certificate until a CA exists to replace it (step 10). Continue past the warning.

Sign in as **admin** with the password **admin**. The console requires the password to be
changed immediately.

#### Step 9 — in the console: create the CAs

A new installation has no CA and cannot issue anything. You create two:

- a **root CA**, the top of the trust chain. Clients trust it, and it signs only other CAs.
- an **issuing CA** beneath it, which signs the certificates that users, servers and devices
  request.

Each CA's private key is created inside a server's token and never exists as a file. §4.3
explains the reasons behind each choice.

⚠️ **Select "replicable key" on every CA, including the root.** The key is created in the token
of whichever server's console served the form, and reaches the other server only by being
copied. A CA whose key is not replicable can never be copied, so the other server can never sign
under it. It cannot be enabled afterwards, and the only remedy is to create a new CA.

The issuing CA's form may be served by the server that did not create the root, and that server
does not yet hold the root's key. The console copies it from the other server before signing, so
that form can take a few seconds longer; nothing needs doing.

**Create the root CA.**

1. Open the **CAs** tab and click **+ New CA**.
2. Under **Identity**:
   - **id**: `root-ca`. This is the short name used by URLs and commands.
   - **display name**: `Example Root CA`, or any text you prefer.
   - **Parent CA**: leave **— none (root) —**.
   - **CN**: `Example Root CA`. The other name fields (OU, O, L, ST, C) are optional.
3. Under **Key & signature**:
   - **Algorithm**: keep **RSA** with **4096** bits. This works with every client. Read
     `compatibility.md` before choosing another algorithm.
   - Leave **use an existing key** unselected, so that a new key is created in the token.
   - **replicable key**: select it, as described above.
   - **Slot** and **PIN file** are completed for you. Do not change them.
   - **Key name**: `root-ca`. This is the key's name inside the token and must not already be
     in use.
4. Under **Validity**: leave both dates empty. The CA is then valid for ten years.
5. Leave **Constraints** and **Advanced** unchanged. For a root CA the AIA and CRL fields
   are unavailable, which is correct: a root CA carries neither.
6. Click **Create CA**.

**Create the issuing CA.**

1. Click **+ New CA** again.
2. Under **Identity**:
   - **id**: `issuing-ca`. Use `dc1-sub` instead if you plan to add data centers (§8.0c).
     Deciding later costs nothing: the id is a label, not a property of the key, and the
     second data center simply uses an id of its own. Two data centers must not share one id,
     because CA registrations replicate between them.
   - **display name**: `Example Issuing CA`.
   - **Parent CA**: select **root**.
   - **CN**: `Example Issuing CA`.
3. Under **Key & signature**:
   - **Algorithm**: keep **RSA**, and select **3072** bits.
   - Leave **use an existing key** unselected.
   - **replicable key**: select it, exactly as for the root. This CA signs every
     certificate.
   - **Key name**: `issuing-ca`.
4. Under **Validity**: leave both dates empty.
5. Click **Create CA**.

Both CAs now appear in the **CAs** tab. The issuing CA's id is `YOUR-CA-ID` in the steps
below.

⚠️ **Press Disable on the root's row now.** It has signed the issuing CA and has no further
work. Disabling stops new issuance and leaves its revocation list, OCSP answers and chain
serving untouched — §4.3 explains why, and how to re-enable it when another issuing CA has to
be signed.

#### Step 10 — on the first machine: issue the service certificates, and copy the keys

This is §4.4 on Kubernetes. Name the CA in the two settings that need it, then run
`apply.sh` again rather than waiting for tonight's renewal:

```bash
cd ~/FastPKI/deploy/k8s
kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set PG_TLS_CA_ID YOUR-CA-ID
kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set CMP_CLIENT_CA_ID YOUR-CA-ID
bash apply.sh
```

`PG_TLS_CA_ID` names the CA that signs each server's database certificate. `CMP_CLIENT_CA_ID`
names the CA that CMP trusts when a client signs its own request, and it is not optional in
practice: without it CMP refuses **every** signature-protected request, so a client can enrol
with a shared secret but can neither renew with `kur` nor revoke its own certificate. The only
other sign is a warning in the `cmp` log, `CMP has no client-CA trust anchor`. Neither value is
guessed. Both settings are held in the database, so they reach both
servers; CMP reads its value at start, and `apply.sh` restarts the listeners.

It creates the OCSP, CMP and SCEP credentials, replaces the self-signed certificate on each
listener with one issued by your CA, issues each server's database certificate, and restarts
the listeners on both servers.

Then make sure each server holds every key — both CAs and the three credentials — rather than
waiting for tonight's renewal to copy them. Both commands are **run on the first machine**, like
every other `kubectl` command here: they name the server to act on, `fastpki-node-0` or `fastpki-node-1`,
rather than being run on it. The second run of each must say `key sync: this node holds every
key it needs to serve`:

```bash
kubectl -n fastpki exec fastpki-node-0 -c renew -- \
    fastpki-ca --config /app/config/bootstrap.conf key sync --from-peers
kubectl -n fastpki exec fastpki-node-1 -c renew -- \
    fastpki-ca --config /app/config/bootstrap.conf key sync --from-peers
```

The first run copies what is missing and ends with **0 failed**. A failure naming a key that is
not replicable means that CA was created without **replicable key** in step 9.

#### Step 11 — issue a certificate and check the result

Reload the console. The browser warning is no longer shown, because the console now serves a
certificate issued by your CA.

Then confirm that the deployment issues certificates to a client. Run the following on the
first machine, in order: each command produces what the next one needs. Replace
`FIRST-ADDRESS` with that machine's address, and `issuing-ca` with your issuing CA's id if you
chose another.

**1. Create an account that is allowed to enrol.** The `standard` role cannot enrol;
`requester` can. Choose your own password in place of `D3mo-Pass`:

```bash
kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf web-user demo 'D3mo-Pass' --role requester
```

**2. Fetch the CA chain over EST.** This is also the trust anchor the later checks use:

```bash
cd ~
curl -sk https://FIRST-ADDRESS:8443/.well-known/est/issuing-ca/cacerts \
  | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out ca-chain.pem
openssl x509 -in ca-chain.pem -noout -subject -issuer
```

The subject and issuer printed must be your two CAs. If the command returns nothing,
`PROTO_SERVICE_TYPE` is not `LoadBalancer` (step 5) and the listener is not reachable.

**3. Create a key and a request, then enrol it over EST:**

```bash
openssl req -new -newkey rsa:2048 -nodes -keyout test.key -out test.csr -subj "/CN=test"
curl -sk -u demo:'D3mo-Pass' \
  --data-binary @<(openssl req -in test.csr -outform DER | openssl base64 -A) \
  -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" \
  https://FIRST-ADDRESS:8443/.well-known/est/issuing-ca/simpleenroll \
  | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out test.pem
openssl x509 -in test.pem -noout -subject -issuer -dates
```

The certificate's subject must be `CN = test`, and its issuer your issuing CA.

**4. Ask OCSP for that certificate's status:**

```bash
openssl ocsp -issuer ca-chain.pem -cert test.pem \
    -url http://FIRST-ADDRESS:8080/ocsp -resp_text -noverify | grep -A1 "Cert Status"
```

It must answer `good`. An answer of `Responder Error: internalerror` means step 10 has not
completed: the responder has no certificate of its own (§4.4b).

**5. Fetch the CRL**, which is published for each CA at `/{ca-id}.crl`:

```bash
curl -s http://FIRST-ADDRESS:8080/issuing-ca.crl -o crl.der
openssl crl -inform DER -in crl.der -noout -text | head -20
```

The pair is now working. `user-guide.md` §6–§10 has full client examples for EST, ACME with
certbot, CMP with `openssl cmp`, SCEP and Microsoft enrolment. §8.5 covers promoting the
standby when a machine is lost, and bringing the lost server back.

---

### 8.0c Add a data center, step by step

A mesh is two or more clusters, each installed as §8.0 or §8.0b, sharing one root CA and
replicating their databases to each other. A cluster of either shape can join a mesh. §9 is the whole subject; this is only what is
different on Kubernetes.

**This does not have to be decided before the first installation.** Every installation is
already data center 1: `DC_INDEX` defaults to `1` and the `datacenters` row is registered
whether or not a mesh is planned. The certificates already issued therefore belong to this
cluster's serial partition, and converting the cluster is a matter of running `apply.sh`
again. §9.4 describes the conversion in full.

⚠️ **The second data center must be installed with its own `DC_INDEX`, before it issues any
certificates.** A cluster installed on its own is also data center 1. Joining two such
clusters places both certificate histories in the same serial partition. New certificates
would use the new index correctly, but the guarantee that two data centers can never issue
the same serial number would no longer hold for the existing certificates.

#### On each cluster — three settings

In `deploy/k8s/env.local`, then `bash apply.sh` again:

```
DC_INDEX=1
PG_INTERCONNECT=THIS-CLUSTER-ADDRESS
PG_EXTERNAL_TYPE=LoadBalancer
```

| Setting | Why |
|---|---|
| `DC_INDEX` | this cluster's number — `1` for the first, `2` for the second. It **is** the serial prefix that keeps two data centers apart |
| `PG_INTERCONNECT` | the address the **other** clusters use to reach this cluster's database — one per server, comma-separated, in pod order, so two for a pair (`FIRST,SECOND`). They are also added as names in this cluster's database certificates, so they must be set before those certificates are issued: a peer using `sslmode=verify-full` rejects a certificate that does not contain the address it dialled |
| `PG_EXTERNAL_TYPE=LoadBalancer` | publishes each server's database on port 5432 so that peer clusters can connect to it. Without this setting, nothing listens on the addresses above |

`apply.sh` rewrites the ConfigMap, rolls the servers so they read it, registers the
`datacenters` row and creates one interconnect Service per server. In the topology, a pair is
listed with both addresses and `target_session_attrs=read-write`, exactly as a Compose pair is:
after a promotion the primary is the other server.

If this cluster already had CAs before you set these, re-issue its database certificate so
it carries the interconnect address (§8.0 step 8), and read §9.4's note about CA
certificates issued before the peers existed — they carry one CRL and AIA URL until the CA
is renewed.

#### Then the mesh itself

From a machine with `kubectl` access to both clusters, one context each:

```bash
deploy/mesh-join.sh k8s:dc1/fastpki k8s:dc2/fastpki
```

Its first run tells each cluster about the other and stops, because no CA exists yet. Create
the CAs (§9.3 has the commands in their Kubernetes form), then run it again: it issues each
database certificate, subscribes each cluster to the other, and waits until both hold the same
data. §9.0 is the whole sequence, §9.3 the Kubernetes specifics, §9.2 how to check the result.

---

### 8.1 What `apply.sh` creates, in order

The order is required, because each step depends on the one before it:

1. the namespace and the `fastpki-secret` Secret;
2. the `fastpki-bootstrap` ConfigMap: `bootstrap.conf` plus the scripts the pods run;

   The database password and both token PINs are in the Secret, never in the ConfigMap
   and never in a pod spec. `bootstrap.conf` gives libpq a connection string with no
   `password=`; every process that opens a database connection receives `PGPASSWORD`
   from `fastpki-secret`, which libpq applies in its place. So reading the ConfigMap — the
   object that gets swept into GitOps repositories and log shippers — yields no secret.

3. on a re-apply, **the schema**, through `kubectl exec` into whichever server's database is
   the primary, **before any server rolls** — new binaries never meet an old database. On a
   mesh node the replication triggers are regenerated by a one-shot pod of `IMAGE`,
   `fastpki-mesh-triggers`, so they come from the image being rolled to. On a first apply there is
   no database yet, and the schema is applied at step 6 instead;
4. **the servers**: the `fastpki-node` StatefulSet and its headless Service (§8.2) — one pod, or two
   with `HA_ENABLED`;
5. each server's **database anchor**, collected into the `fastpki-pg-anchors` ConfigMap so a server can
   verify the other's database before any CA exists;
6. the wait for a read-write database, then the schema, the `datacenters` row, and the `admin`
   console user;
7. the protocol Services and the web Service, spread across the servers;
8. any missing service credentials — the OCSP responder, CMP RA and SCEP RA certificates, and
   CA-issued replacements for listener certificates still on their self-signed ones — and a
   restart of each server's listeners when it creates any, because a running listener serves the
   certificate it picked when it started.

There is no CA at the end of a first apply. The console starts and self-signs its own TLS;
so do EST/ACME/MS, each on a temporary self-signed transport certificate until a CA-signed
one replaces it (§4.4). None of them can **issue** anything until a signing CA exists (§4).
The first sign-in is `admin` / `admin`, seeded `must_reset`.

⚠️ **Step 8 does nothing on that first apply, because it cannot.** The RA credentials can
only be created once a signing CA exists, and you create the CAs in the console afterwards.
Until they exist, CMP refuses every transaction with `no RA credential`. **Re-run `apply.sh`**
once the CAs are in place, or wait for each server's renewal loop to do it tonight. It runs the
same `renew-service-certs --create-missing --re-issue-self-signed` as every other platform
(§4.4), so it also promotes the listeners' self-signed certificates and, once `PG_TLS_CA_ID` is
set below, maintains each server's database certificate.

⚠️ **An HA pair needs replicable service keys** (§4.4). With `HA_ENABLED`, `apply.sh` sets
`SERVICE_KEYS_REPLICABLE=true` in the configuration it generates, so the renewal loop creates the
OCSP, CMP and SCEP credential keys replicable. Do not turn it off on the Config page: a key created
without it can never be copied to the other server.

⚠️ **And name the CA that signs the database certificates, which is the one thing nothing can
decide for you.** Each server's PostgreSQL comes up on the pair certgen self-signs in the pod's
init container, because libpq needs a key *file* and cannot reference the token — so the
database is the only credential that does not adopt a CA-issued certificate by itself. Set
`PG_TLS_CA_ID` once the CAs exist, then re-run `apply.sh`:

```bash
kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set PG_TLS_CA_ID <ca-id>
bash apply.sh
```

It is not inferred from anything. Left unset, the nightly loop prints one line saying the
certificate is not being maintained and changes nothing.

### 8.2 One server per pod, each with its own token

Every server is one pod of the `fastpki-node` StatefulSet, and holds everything a Compose host
holds:

| Container | What it is |
|---|---|
| `token` | this server's key store, on a disk of its own. Only this pod can reach it |
| `init` | prepares the server: the key store password, this server's own transport keys, and the temporary database certificate it starts with |
| `postgres` | this server's database, on a disk of its own |
| `p11-tls` | the encrypted channel to this server's key store, when `P11_TLS=on` (§8.3) |
| `web`, `ocsp`, `est`, `acme`, `cmp`, `ms`, `store`, `scep` | the console and each protocol |
| `renew` | renews certificates on a schedule, and copies any key this server is missing from the other |

Each server also has its own copy of `/var/pki`, on a third disk. Nothing is shared between
pods, so a server can run on any machine, and no disk has to be shared storage or NFS.

⚠️ **Every server has its own key store, whichever way you run FastPKI.** If all the keys
lived in one key store, losing the machine holding it would lose every key, however that
storage is arranged. So each server keeps its own, and a CA key gets to the other server by
being copied into its key store (§8.3).

A server's name inside the cluster, `fastpki-node-0.fastpki-node`, is also the address its database is
reached on. Its database certificate carries that name, and so do its transport certificates
and its row on the console's Replication page.

⚠️ **The key store container needs Kubernetes 1.29 or later.** It starts before the others and
keeps running for the life of the pod, which older versions cannot express. It has to work
that way: it must be serving the key store before the setup container creates this server's
transport keys in it.

### 8.3 A key in another server's token

Two ways, and both leave every server signing from a token it can reach locally.

**A hardware security module on the network.** Set `SOFTHSM_ENABLED=false` and point
`PKCS11_MODULE` at the vendor's library. No key store runs in the pod at all: each service
loads the library and talks to the appliance over the network. This is what a production
deployment does.

**The key store that ships with FastPKI, with keys copied between servers.** Setting
`P11_TLS=on` runs a small extra container in every server pod. It puts an encrypted channel
in front of that server's own key store, on port 12345, and both ends check each other's
certificate. It exists so that one server can copy a key out of another server's key store
into its own. Every server still keeps its own key store and signs with that.

Inside the cluster the servers find each other as `fastpki-node-0.fastpki-node:12345` and
`fastpki-node-1.fastpki-node:12345`, and each one regularly copies any key it is missing from the
other. `HA_ENABLED` turns this on.

To let a server in **another data center** copy a key out (§9, Scenario B), set
`P11_TLS_SERVICE_TYPE` to `LoadBalancer` or `NodePort`. `apply.sh` then publishes each server
separately, as `fastpki-p11-tls-0` and `fastpki-p11-tls-1`, because the key that other data center needs
may be in either one.

### 8.4 The settings that matter

| Variable | Default | For |
|---|---|---|
| `IMAGE`, `IMAGE_PULL_POLICY` | that release's published image, else `fastpki:latest`; `IfNotPresent` | which image, and whether to re-pull. Installed from a release, the default is `ghcr.io/fastpki/fastpki:<version>` and the cluster pulls it. From a checkout there is no published tag, so the default names a locally built image you must make reachable yourself (§8.0 step 3) |
| `NAMESPACE` | `fastpki` | everything lands here |
| `PKI_DNS` | `pki.example.org` | the name the deployment answers to |
| `WEB_SERVICE_TYPE`, `WEB_PORT` | `ClusterIP`, `8090` | how to expose the console, and on which port — `WEB_PORT` reaches the Service, the container, the readiness probe, the Ingress backend and the console's own config, so changing it works end to end |
| `INGRESS_ENABLED`, `INGRESS_CLASS`, `INGRESS_HOST`, `INGRESS_TLS` | `false`, —, —, `true` | front it with an Ingress instead |
| `PROTO_SERVICE_TYPE` | `ClusterIP` | how clients reach the enrolment protocols: EST, ACME, CMP, SCEP, OCSP, the Windows service and the store. Your clients are outside the cluster, so the default means none of them can enrol at all. Use `LoadBalancer`: it keeps the port numbers that are written inside your certificates (§8.6). `NodePort` lets clients enrol, but the addresses in those certificates then point at ports nothing answers on. Do not use an Ingress here: it ends the encrypted connection at the edge, and with it the client certificate that EST and CMP check |
| `STORAGE_CLASS` | cluster default | the three disks each server gets: its database, its files, and its key store. Each belongs to one server alone, so ordinary disks attached to one machine, such as `local-path`, are the right choice. Nothing here needs shared storage or NFS |
| `PG_DATA_SIZE`, `PKI_DATA_SIZE`, `SOFTHSM_TOKEN_SIZE` | `1Gi`, `1Gi`, `1Gi` | the size of each server's claims. A fresh database is 47.9 MB and a token 52 KB; raise `PG_DATA_SIZE` for a deployment that keeps years of issuance |
| `SOFTHSM_ENABLED`, `PKCS11_MODULE` | `true`, p11-kit client | §8.2 and §8.3 |
| `HA_ENABLED` | `false` | run two servers on two machines instead of one (§8.5). Turns `P11_TLS` on as well |
| `P11_TLS` | on with `HA_ENABLED`, otherwise off | the encrypted channel each server's key store is reached over, and the one keys are copied across (§8.3) |
| `AUDITFWD_ENABLED` | `false` | send the audit log somewhere else as it is written, from every server pod |

Ports are the same everywhere: web `8090`, ocsp `8080`, est `8443`, acme `8444`, cmp
`8445`, ms `8446`, store `8447`, scep `8448`.

⚠️ **If the image comes from your own registry, know that k3s ignores Docker's settings.**
k3s does not use Docker, so `/etc/docker/daemon.json`, and the list of insecure registries in
it, changes nothing about what a pod can download. Every other way of running FastPKI uses
that file, so the obvious fix is the one that cannot work here. A registry served over plain
HTTP, or with its own self-signed certificate, has to be declared to k3s instead — **on every
machine in the cluster** — and k3s restarted there:

```bash
sudo tee /etc/rancher/k3s/registries.yaml >/dev/null <<'EOF'
mirrors:
  "registry.example.org:5000":
    endpoint:
      - "http://registry.example.org:5000"
EOF
sudo systemctl restart k3s          # k3s-agent on the worker nodes
```

The symptom if it is missing is `http: server gave HTTP response to HTTPS client` on the pod's
pull, identical to the Docker one, which is why §13's troubleshooting table separates the two.
A registry with a certificate the nodes already trust needs none of this.

⚠️ **And k3s writes its kubeconfig root-only**, so `apply.sh` stops on its first `kubectl` call
with `error loading config file "/etc/rancher/k3s/k3s.yaml": permission denied` — even with a
perfectly good `~/.kube/config` in place, because k3s's `kubectl` prefers that path. Either
install k3s with `--write-kubeconfig-mode 644`, or give the operator a copy and point
`KUBECONFIG` at it, which copying alone does not do:

```bash
mkdir -p ~/.kube && sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown "$(id -u):$(id -g)" ~/.kube/config && chmod 600 ~/.kube/config
export KUBECONFIG=$HOME/.kube/config
```

⚠️ **Reusing a host that has run k3s before: delete the cluster, not just the namespace.**
`kubectl delete ns` removes the workloads and leaves the cluster's own leftovers — Traefik still
holding :80 and :443, and the CNI's `CNI-HOSTPORT-DNAT` iptables rules still redirecting the
ports the previous deployment published. The next deployment then looks healthy while traffic is
quietly sent to pods that no longer exist, and the ACME http-01 and tls-alpn-01 challenges fail
on ports that appear free. k3s ships the remover:

```bash
sudo /usr/local/bin/k3s-uninstall.sh          # the server node
sudo /usr/local/bin/k3s-agent-uninstall.sh    # each agent node
sudo iptables-save | grep -c CNI-HOSTPORT     # expect 0 before redeploying
ls /usr/local/bin/k3s*                        # expect nothing
```

### 8.5 A pair of servers, and promoting one

`HA_ENABLED=true` runs **two servers**, `fastpki-node-0` and `fastpki-node-1`, on two different nodes. It
is the Compose pair (§6a) on Kubernetes, with the same guarantees:

| | Compose (§6a) | Kubernetes, `HA_ENABLED=true` |
|---|---|---|
| Servers | two hosts | two pods of `fastpki-node`, required to be on different nodes |
| Token and CA keys | one token per server; each copies the keys it is missing from the other | the same |
| Database | primary and streaming standby | `fastpki-node-0` initialises the primary; `fastpki-node-1` seeds from it and streams |
| Application services | a full set on each server | a full set in each pod, behind Services that spread across both |
| Survives losing a machine | yes | yes |

Each server copies every key it does not hold from the other over the token transport, so a CA
created from the console reaches both tokens whichever server served the form. `HA_ENABLED`
switches `P11_TLS` on for that reason, and `apply.sh` refuses the two together with
`P11_TLS=off`.

⚠️ **Every CA must be created with "replicable key", the root included.** A key that is not
replicable can never be copied into the other server's token, and the second server can never
sign under it. It cannot be enabled afterwards.

⚠️ **The two servers need two schedulable nodes.** With one node, `fastpki-node-1` stays `Pending`.
Two servers on one node survive a process dying and nothing else, so that is not a pair.

#### Turning a single server into a pair

A server installed on its own (§8.0) created its OCSP, CMP and SCEP credentials **without**
replicable keys, and `CKA_EXTRACTABLE` cannot be granted afterwards. So before you set
`HA_ENABLED=true`, delete those three keys from the first server's token and generate replicable
ones:

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

The second command must report `created` for all three. Skip this and the second server creates
its own three credentials instead: the first server's OCSP, CMP and SCEP then sign with keys
that match no certificate until its renewal loop next runs key sync and replaces them, which
can take up to a day. **Sync keys now** on the console's **Replication** page does the same
at once.

Then join the second machine to the cluster (§8.0b step 2), set `HA_ENABLED=true` and run
`apply.sh` again.

Node-local storage — `local-path`, the k3s default — is the right storage for every claim.
Each claim belongs to one server, and losing a node loses only that server's copy.

#### Checking the pair

`fastpki-node-1`'s database must answer `t` — "yes, I am a read-only standby":

```bash
kubectl -n fastpki exec fastpki-node-1 -c postgres -- \
    psql -U fastpki -d fastpki -tAc 'SELECT pg_is_in_recovery()'
```

`fastpki-node-0` must show it, with `state` = `streaming`:

```bash
kubectl -n fastpki exec fastpki-node-0 -c postgres -- \
    psql -U fastpki -d fastpki -c 'SELECT application_name, client_addr, state FROM pg_stat_replication'
```

And each server must hold every key. On **each** pod, this must say
`key sync: this node holds every key it needs to serve`:

```bash
kubectl -n fastpki exec fastpki-node-0 -c renew -- \
    fastpki-ca --config /app/config/bootstrap.conf key sync --from-peers
kubectl -n fastpki exec fastpki-node-1 -c renew -- \
    fastpki-ca --config /app/config/bootstrap.conf key sync --from-peers
```

The first run on a new pair copies what is missing and reports it; the second must report
nothing missing. The console's **Replication** page shows the same thing per server.

#### Promoting the standby

When the node running the primary is lost, promote the other server's database:

```bash
FASTPKI_PROMOTE_MODE=k8s NAMESPACE=fastpki deploy/pg-promote.sh fastpki-node-1
```

⚠️ **This needs a working Kubernetes API, so plan for the cluster's own redundancy.** A cluster
installed as §8.0b describes has one control plane, on the first machine. Losing the second
machine costs nothing here: the API server is still there and the promotion runs. Losing the
**first** machine takes the API with it — the surviving server keeps running and keeps serving,
because a kubelet does not stop the pods it already has, but no `kubectl` command works until
that machine returns, so nothing can be promoted, inspected or re-applied in the meantime. A
deployment that must survive the loss of either machine needs a Kubernetes control plane that
survives it too: for k3s that means installing the servers with `--cluster-init` and running
three of them, which is a property of the cluster rather than of FastPKI.

It runs on any machine with `kubectl` for the cluster. It refuses while another server's database
still answers as a read-write primary: promotion demotes nothing, and two primaries give the
applications two databases to diverge between. When the lost pod is reported `Running` only
because its node has not yet been marked down, confirm the node is gone
(`kubectl get nodes`) and delete that pod first.

It then does on Kubernetes what it does on Compose:
- promotes the database;
- clears the `synchronized_standby_slots` it inherited;
- removes `fastpki-node-1`'s standby mark;
- gives the server a database certificate if it has none;
- promotes self-signed listener certificates;
- restarts the listeners, the console and the renewal loop.

The applications re-home on their next statement, because the connection string names both
servers with `target_session_attrs=read-write`. It names each pod's own database first, as
`127.0.0.1`, so the promoted server's applications reach it without cluster DNS, which may have
gone down with the lost node. The protocol Services already reach
`fastpki-node-1`, so there is no address to move. Confirm with a write, because a read succeeds
against either server and proves nothing.

#### Restoring the second server

A promoted server stays the primary, and the old one can only come back as a fresh standby of
it: its database timeline diverged at the promotion.

**If the old node comes back**, `fastpki-node-0` refuses to start its database as a second primary and
says so in its log (`kubectl -n fastpki logs fastpki-node-0 -c postgres`). Delete its database claim
and its pod, and it seeds from `fastpki-node-1` on the next start:

```bash
kubectl -n fastpki delete pvc pgdata-fastpki-node-0 --wait=false
kubectl -n fastpki delete pod fastpki-node-0
```

**If the old node is gone for good**, its claims are bound to that node and the pod cannot start
anywhere else. Remove the node and all three of the pod's claims, then add a replacement node to
the cluster; the pod starts there with an empty token, and its renewal loop copies every key into
it from `fastpki-node-1`:

```bash
kubectl delete node OLD-NODE-NAME
kubectl -n fastpki delete pvc pgdata-fastpki-node-0 pki-fastpki-node-0 softhsm-tokens-fastpki-node-0 --wait=false
kubectl -n fastpki delete pod fastpki-node-0
```

⚠️ **Then run `apply.sh` again.** It republishes both servers' database anchors, which a rebuilt
server needs to verify the primary it seeds from, and waits until both servers are ready.

```bash
cd ~/FastPKI/deploy/k8s
bash apply.sh
```

#### What the console's Replication page shows on Kubernetes

The page is the same as on Compose. Each server is a row of its own, named `fastpki-node-0.fastpki-node`
and `fastpki-node-1.fastpki-node`; `fastpki-node-1`'s role reads `standby of fastpki-node-0.fastpki-node`; and
**Sync keys now** runs the same key sync on whichever server's row you choose.

### 8.6 Reaching the deployment

`apply.sh` prints the right command for the service type you chose. With the default
`ClusterIP`:

```bash
kubectl -n fastpki port-forward svc/fastpki-web 8090:8090   # then https://localhost:8090/
```

⚠️ **A port-forward reaches the console; it does not make the CA usable.** Clients enrol
against EST, ACME, CMP, SCEP and the store, and those are `ClusterIP` too by default —
unreachable from anywhere a client actually runs. Publish them with
`PROTO_SERVICE_TYPE=NodePort` (or `LoadBalancer`) and they answer on every node:

```bash
kubectl -n fastpki get svc -o wide      # the assigned nodePort per listener
```

The ports are **assigned per deployment** from the cluster's NodePort range, not fixed, so
read them back rather than writing them down.

⚠️ **Not a TLS-TERMINATING Ingress, for most of them.** EST and CMP authenticate the client
by its certificate. An Ingress that terminates TLS presents its own connection to the
backend and the client certificate is gone — the deployment then rejects enrolments that are
perfectly valid. NodePort and LoadBalancer pass the connection through intact.

An Ingress controller running in **TLS passthrough** does too, and is a legitimate way to
front the enrolment protocols on one address: nginx-ingress with `ssl-passthrough` enabled,
or Traefik with a TCP router and `tls.passthrough`, forward the TCP stream unopened, so mTLS
survives and the backend still sees the client certificate. It is passthrough or nothing —
these are TCP routes selected by SNI, not HTTP rules, and the usual annotations for paths,
rewrites and header injection do not apply to them.

The Ingress `INGRESS_ENABLED` creates is the HTTP one, and fronts the console only. A
passthrough route for the protocols is deployment-specific — it depends on which controller
you run and how it is configured, so you must add it yourself; these manifests do not.

**Driving the demo against it.** `demo/provision-target.sh --k8s` creates the demo user,
creates its CMP/ACME/SCEP credentials through the console API and writes a descriptor with
every assigned port read back from its Service:

```bash
demo/provision-target.sh --k8s --out demo/.k8s-target.env
demo/pki-demo.sh  --target demo/.k8s-target.env
demo/pki-bench.sh --target demo/.k8s-target.env
```

It refuses with the service name if any listener is still `ClusterIP`, rather than writing
a descriptor full of ports nothing answers on.

⚠️ **The ACME cells need `certbot` on the machine that runs the demo, and ports 80 and 443
free there.** Without certbot they skip; the server connects back to that machine to validate
http-01 and tls-alpn-01, so it must also be a host the deployment can reach — a cluster node is
the simple choice. dns-01 additionally needs a descriptor that names the cluster's
namespace, which `--k8s` writes and `--web-url` does not: it is how the demo repoints the ACME
server's resolver and starts one for the challenge.

⚠️ **It logs in as `admin` with the password `admin`**, and performs the first-login password
change itself if the console still demands one. On a deployment where that password has
already been changed it stops at `could not create/update user 'demo' (response:
{"error":"unauthorized"})`. Give it the current password instead:

```bash
demo/provision-target.sh --k8s --admin-pass 'CURRENT-ADMIN-PASSWORD' --out demo/.k8s-target.env
```

`--admin-user` names a different administrator, which is the better choice when the console
is shared.


⚠️ **Use `LoadBalancer`, not `NodePort`.** The AIA and CRL Distribution Point URLs baked into
every certificate are built from the listener's port — `BASE_URL`'s own port is stripped,
because it is the console's port and not the OCSP listener's. A NodePort service answers on an allocated port
(30000–32767), so certificates advertise `:8080`, which nothing outside the cluster answers
on, and a relying party fetching that CRL hangs until it times out. NodePort still enrols
perfectly well; its certificates are simply not verifiable from outside. k3s's built-in
ServiceLB binds the service's real port on every node, so
`LoadBalancer` makes the advertised URLs true.

⚠️ **k3s bundles Traefik, and it holds `:80` and `:443`.** FastPKI does not use it —
`INGRESS_ENABLED` is `false` by default — but ACME's **http-01 and tls-alpn-01 challenges
need those two ports**, because the server validates by connecting back to them. Traefik
claims them with a `hostPort`, which is mapped by iptables rather than bound as a socket, so
`ss -lntp` shows nothing while a connection to `127.0.0.1:80` still succeeds — the port looks
free and is not. Disable it when the cluster serves ACME:

```yaml
# /etc/rancher/k3s/config.yaml
disable:
  - traefik
```

then `systemctl restart k3s`. dns-01 is unaffected and works with Traefik in place.

⚠️ **`PKI_DNS` must resolve, from wherever relying parties are.** It is the host in those
same URLs. A deployment reachable only by node IP issues certificates pointing at a name
nothing can look up — the same hang, one step earlier.

⚠️ **Both must be right before you create the CAs.** The URLs are written into the CA at
creation and are not recomputed afterwards, so fixing the exposure later does not fix
certificates already issued, nor the CA itself. `fastpki-ca delete` refuses a CA that has
issued anything, which is correct and means the practical remedy is a new CA id.

⚠️ **ACME needs a name the cluster can resolve back to the machine running the demo.** The
server validates http-01 and tls-alpn-01 by connecting to the identifier being claimed, so
pass `--challenge-fqdn <name>`; without it those cells skip. EST, CMP, SCEP, OCSP and the
store need nothing beyond the NodePorts.

### 8.7 Updating

Re-running `apply.sh` with the new `IMAGE` is the update: it applies the schema before any
server rolls onto the new image, on a mesh node included (§8.1 step 3). Kubernetes then
replaces the servers one at a time, so in a pair one server keeps serving while the other
restarts. Roll back with `kubectl -n fastpki rollout undo statefulset/fastpki-node`. The
schema-before-binaries order is not optional — see §11 for what it protects.

---

## 9. Multi-data-center

A data center is one complete FastPKI deployment: its own database, its own key store and its
own CA key. Several of them copy certificates to each other, in both directions, and all of
them can issue. What they never do is share a key.

Read §9.1 before §9.2. The servers have to trust each other before any copying can start.

### 9.0 Add a data center, step by step

This walks through the common job from start to finish: you have a working deployment — one
node, or an HA pair (§6a) — and you add a **second data center**. Every step says which
machine it runs on, and uses the web console wherever the console can do the work.

**Steps 1 to 10 complete the procedure.** Step 11 is optional, and everything from §9.1 onwards is
reference, not more work to do: it explains each step in depth, and is where to look when
something does not behave.

**What you get.** The two data centers copy certificates, revocations, users, roles, profiles
and templates to each other, in both directions. Each keeps its own CA key and signs with it.
They never share a key (§9.7).

**Names used below.**

| Name | Meaning | Example |
|---|---|---|
| **DC1** | your existing deployment. If you run two servers for failover, this means the one currently in charge: the standby only reads, and cannot serve another data center | `192.0.2.10` (and `192.0.2.11` for its standby) |
| **DC2** | the new machine | `198.51.100.10` |
| `dc1-sub`, `dc2-sub` | each data center's own issuing CA. `dc1-sub` is the CA you already have; its real id (often `issuing-ca`) is fine | |

Commands run in the `deploy` directory of the checkout on the machine named
(`cd ~/FastPKI/deploy`), and a new login starts in your home directory, so `cd` first.

⚠️ **You do not have to undo anything on the deployment you already have.** Whichever
installer set it up already made it data center 1, and its certificates already carry `0001`
at the front of their serial numbers, so there is nothing to repair (§9.4). You do not create
a second root CA either: §9.1 step 1 is already done.

#### On Kubernetes, before step 1

The steps below are written for Docker Compose. On Kubernetes one data center is one cluster,
and the sequence is the same, with three differences to settle first. §9.3 has the detail.

**Both clusters need three settings**, in `deploy/k8s/env.local`, and then `apply.sh`:

```
DC_INDEX=1                                  # this cluster's index: 1 on the existing one, 2 on the new one
PG_INTERCONNECT=ADDRESS[,ADDRESS]           # one address per server in this cluster, in pod order
PG_EXTERNAL_TYPE=LoadBalancer               # publishes each server's 5432 to the peer clusters
```

⚠️ **The existing cluster needs them too, and that is the step most easily missed.** Its peers
have to dial it, and `PG_INTERCONNECT` becomes a name in its database certificates. A pair
gives two addresses, `fastpki-node-0`'s first: `kubectl -n fastpki get pods -o wide` shows which
machine each server runs on. `apply.sh` refuses a count that does not match the number of
servers.

⚠️ **On a cluster that already has CAs, re-issue its database certificates after that
`apply.sh`.** The names come from configuration read when the certificate is issued, so an
existing certificate does not carry the interconnect address, and the peer's `verify-full`
rejects it — which surfaces only later, once the topology is in place and the hard part looks
finished. §8.0 step 8 is the command.

**Installing the new cluster:** follow §8.0 as far as **step 6**, with `DC_INDEX=2` and its own
`PKI_DNS`. Stop there. Do not create CAs in its console: step 5 below creates its key and a
request, DC1's root signs it in step 6, and §8.0 steps 7 to 9 would give you a second root that
then has to be discarded.

**Running the commands:** every `docker compose` form below has a Kubernetes equivalent in
§9.3, which defines the two shorthands the steps use.

#### Step 1 — install DC2

On the new machine, install Docker (§3 *Before you start*), get the same release, and run the
wizard (§3.1). Four answers matter:

| Question | Answer |
|---|---|
| Deployment type | `cluster` |
| This node's data center index | **`2`** — also its serial prefix, and permanent |
| Public FQDN (`PKI_DNS`) | **its own** name, for example `pki-dc2.example.org`, never the name the existing deployment uses |
| This node's mesh-reachable IP (`PG_BIND`) | its address on the network the data centers share, for example `198.51.100.10` |

Each data center is addressed separately, because a node can only sign with the CA whose key
is in its own token (§9.7). The name goes into every certificate this node issues, as its CRL
and AIA address, so it must resolve for your clients.

#### Step 2 — on DC2: sign in and set the admin password

Open `https://<DC2 name>:8090`, sign in as `admin` / `admin`, and set the password.

⚠️ **Use the same password as the existing deployment.** `admin` is one account across the
mesh: each install seeded its own row with its own hash, replication keeps one row per
username, and the last write wins — with nothing to say whose password survived.

#### Step 3 — from your own machine: start the mesh, in one command

Run this on the machine you SSH to the servers from, not on a server. It needs SSH to each
server as the user that runs `docker compose` there:

```bash
cd ~/FastPKI
deploy/mesh-join.sh admin@192.0.2.10+admin@192.0.2.11 admin@198.51.100.10
```

One argument per data center. A data center with a standby is written `<primary>+<standby>`,
as DC1 is here. A compose server's checkout is taken to be `~/FastPKI/deploy`; name another
directory as `admin@198.51.100.10:/opt/fastpki/deploy`. Add `-i <key>` for an SSH key, and
`NA_SSH_JUMP=admin@<host>` in front of the command for servers reachable only through
another host.

It reads each data center's number, address, public name and database password from the
server itself, puts the file below on every server (mode 600, removed again straight after),
does step 4 on every primary, and then stops, because DC2 has no CA yet:

```
mesh-join: data center 1: admin@192.0.2.10+admin@192.0.2.11 (compose), database at 192.0.2.10,192.0.2.11
mesh-join: data center 2: admin@198.51.100.10 (compose), database at 198.51.100.10
mesh-join: pass 1 done: every data center knows the others and publishes
mesh-join: stopped: these data centers have no issuing CA of their own yet: 2
mesh-join: create them: the root once, and a sub CA per data center or one shared by all
mesh-join: (docs/deployment.md 9.0 steps 5 to 7; on AWS, 12 steps 7 and 8; on Kubernetes, 9.3).
mesh-join: Then run this command again. It picks up from here.
```

Carry on with step 5. Step 9 runs the same command again, and it finishes from there. Running
it at any other point is safe too: every step it takes checks first and changes only what is
missing.

The rest of this step and step 4 are what the command does, for when you need to do it by
hand or understand a failure.

##### By hand: the file that lists them all

`fastpki-mesh` takes the whole mesh as one small file, and **the same file goes on every
node**. One line per data center, four `|`-separated fields
(`dc_id|conninfo|serial_prefix|base_url`); §9.1 step 8 explains every field and its traps.

You need each data center's database password. The two hosts of an HA pair share one.

Save it as `deploy/topology` on **every** node — the standby of a pair included, so the file
is already there if it is ever promoted. Here an existing pair as data center 1, plus the new
node as data center 2:

```
# dc_id | conninfo (dialled by the postgres container) | serial prefix | public base URL
1|host=192.0.2.10,192.0.2.11 port=5432,5432 dbname=fastpki user=fastpki password=<DC1 db password> sslmode=verify-full sslrootcert=/pki/tls/pg/ca.crt target_session_attrs=read-write|1|http://pki-dc1.example.org:8080
2|host=198.51.100.10 port=5432 dbname=fastpki user=fastpki password=<DC2 db password> sslmode=verify-full sslrootcert=/pki/tls/pg/ca.crt|2|http://pki-dc2.example.org:8080
```

**What the middle field (the `conninfo`) is made of.** It is one long string of
`key=value` pairs separated by spaces — how a peer's Postgres dials this data center:

| Part | What it means | What to put |
|---|---|---|
| `host=` | which machines to connect to | that data center's address, or **both** addresses separated by a comma on an HA pair |
| `port=` | the database port, one per host | `5432` (`5432,5432` for a pair) |
| `dbname=` | the database **name** | always `fastpki` |
| `user=` | the database **user** | always `fastpki` |
| `password=` | that data center's **database password** — the only secret in this file | the one you gave the installer for Postgres. If you let it generate one, it is `POSTGRES_PASSWORD` in that node's `deploy/.env`. No quotes, no spaces |
| `sslmode=` | check the server's certificate and its name | always `verify-full`; a weaker one is refused |
| `sslrootcert=` | which certificate to check it against | `/pki/tls/pg/ca.crt` — the path **inside the postgres container**, not `/var/pki/...` (on a native node: `/var/lib/postgresql/tls/ca.crt`) |
| `target_session_attrs=` | on a pair, pick the host that accepts writes | `read-write` on a pair; leave it out for a single node |

- **A pair is one line, naming both its hosts.** `target_session_attrs=read-write` picks
  whichever is the primary, so peers follow a promotion instead of dialling a host that is
  gone. Both hosts keep the same `DATACENTER_ID` and the same prefix: a pair is one data
  center twice.
- **`base_url` is where that data center serves its CRLs** — `http://<its own name>:8080`
  unless a reverse proxy (§10) sits in front of it.
- **The file holds passwords in the clear.** On every node:
  ```bash
  cd ~/FastPKI/deploy
  chmod 600 topology
  ```

#### Step 4 — tell each server about the others (part one): done by step 3's command

By hand, this writes the `datacenters` rows — which data centers exist, and each one's serial prefix
and public address — and creates each node's publication.

**Where to run it:** once per data center. On an HA pair that means the **primary only** —
never the standby. The standby shares the primary's database, so everything written here
reaches it within seconds by itself. The standby keeps only the `topology` file, ready for the
day it is promoted.

**On Docker Compose:**

```bash
cd ~/FastPKI/deploy
for s in map publication; do
  docker compose run --rm --no-deps --user 0:0 -v "$PWD/topology:/topology:ro" \
      --entrypoint fastpki-mesh web --topology /topology --$s \
    | docker compose exec -T postgres psql -U fastpki -d fastpki
done
```

**On Kubernetes**, from the directory holding `topology`. The PRIMARY value is the server with the
read-write database — on a single-server cluster `fastpki-node-0`; on a pair, the one this answers
`f` for (`t` means that one is the standby):

```bash
kubectl -n fastpki exec fastpki-node-0 -c postgres -- \
    psql -U fastpki -d fastpki -tAc 'SELECT pg_is_in_recovery()'
```

```bash
cd ~/mesh-bootstrap
NS=fastpki
PRIMARY=fastpki-node-0                   # fastpki-node-1 if that is the pod that answered f above
for s in map publication; do
  kubectl exec -i -n "$NS" "$PRIMARY" -c web -- sh -c \
      'cat > /tmp/topology && exec fastpki-mesh --topology /tmp/topology "$@"' _ --$s < topology \
    | kubectl exec -i -n "$NS" "$PRIMARY" -c postgres -- psql -U fastpki -d fastpki
done
```

`--map` must print two `INSERT 0 1` lines for two data centers, and `--publication` a
`CREATE PUBLICATION`. No line may begin with the word ERROR.

⚠️ **Do not run the Compose commands on a cluster.** There is no compose file there, so they
build a second, empty deployment on the machine — volumes, a network and a failed image pull —
and write nothing to the database, while looking like a real attempt.

⚠️ **`--user 0:0` is required.** The file is mode 600 and the image runs as uid 101: without
it `fastpki-mesh` reads nothing, and every step still reports success while changing nothing.

⚠️ **If you see these errors, you ran it on the standby.**

```
ERROR:  cannot execute INSERT in a read-only transaction
ERROR:  cannot execute ALTER PUBLICATION in a read-only transaction
```

A standby only ever reads, so it turned the commands down. Nothing changed, and you do not
have to undo anything. Run the same commands on the primary.

**Check it.** On every node, both rows must be listed:

```bash
docker compose exec -T postgres psql -U fastpki -d fastpki -c 'SELECT dc_id, serial_prefix FROM datacenters ORDER BY dc_id'
```

On Kubernetes — this one reads, so either server of a pair answers it:

```bash
kubectl -n fastpki exec fastpki-node-0 -c postgres -- \
    psql -U fastpki -d fastpki -c 'SELECT dc_id, serial_prefix FROM datacenters ORDER BY dc_id'
```

⚠️ **This comes before DC2's sub CA is created (step 5), not after.** A certificate's CRL and
AIA entries are built when it is issued, one per row in `datacenters`, so a CA created before
the map carries only one data center's address — permanently, because a certificate cannot be
told a new URL afterwards.

#### Step 5 — on DC2: create its own CA key and a request

DC2 needs its own issuing CA, and it must be signed by the root the existing deployment
already holds — that is what makes the two data centers one PKI. The key is generated inside
DC2's token and never leaves it. Only the **request** travels to the other machine.

**5.1 — open the form.** In DC2's console, go to **CAs** and press **+ Create CSR (key in
HSM)**.

**5.2 — fill it in.**

| Field | What to put |
|---|---|
| Key name | `dc2-sub` — the name of the key inside DC2's token. Write it down: step 7 needs the same name |
| CN | `Example DC2 Sub`. Type the value only; the form builds the `/CN=` around it |
| Algorithm | **RSA 3072**, to match the CAs you already have. **EC P-256** is also fine — the data centers need not match |
| Token, Slot, PIN file | leave as they are |
| replicable key | leave **unticked**. Tick it only if DC2 will later get its own HA standby (§6a), because it cannot be changed afterwards |

**5.3 — press `Create CSR`.** The key is generated in the token, and the request appears in
**The request** box at the bottom of the form.

**5.4 — press `Download .csr`.** Keep the file: only a certificate issued over this exact
request will match the key now sitting in DC2's token.

Nothing is registered as a CA yet. DC2's **CAs** page is unchanged until step 7.

#### Step 6 — on DC1: sign that request with the root

Take the request to the machine that holds the root key and sign it there. On an HA pair, use
the **primary**.

**6.1 — open the form.** In DC1's console, go to **CAs** and press **Request from a CSR**.

**6.2 — fill it in.**

| Section | Field | What to put |
|---|---|---|
| Signing CA | Issue from | **`root-ca`** — the root itself, not the issuing CA you use day to day |
| The request | the box | paste the text of `dc2-sub.csr`, or use *…or upload a .csr/.pem file* |
| Validity | Not after | a date no later than the root's own expiry. A sub CA must never outlive its root, and nothing shortens it for you |
| Validity | Hash | `sha256` |
| Granted constraints | Path length, name constraints, policies | leave empty unless you are deliberately limiting what DC2 may issue |

**6.3 — press `Sign request`.** The signed certificate appears in **The certificate** box.

**6.4 — press `Download .crt`.** The file is saved as `sub-ca.crt`. Rename it to
`dc2-sub.crt` if you like; the name is yours, the contents are what matter. Take it to DC2
for step 7.

DC1 keeps a record of the certificate it signed, so it can list and later revoke it, but it
does **not** register a CA here. A CA belongs to the machine holding its key, and that
machine registers it itself in step 7.

#### Step 7 — on DC2: register the root, then its own CA

DC2 now has to be told about two certificates: the **root**, so it can check chains, and its
**own** sub CA, so it can issue. Both go in through the same form, with one setting different.

**7.1 — on DC1: get a copy of the root certificate.**

1. Open DC1's console and go to **CAs**.
2. Click the `root-ca` row. Its details open.
3. Scroll to **PEM** and press **Download**. You get `root.pem`. (**Copy** works too, if you
   would rather paste it.)

A CA certificate is public, so copying it between machines gives nothing away. The root's
private key stays in DC1's token and never moves.

**7.2 — on DC2: register the root as a trust anchor.**

In DC2's console: **CAs** → **Import an existing CA**.

| Section | Field | What to put |
|---|---|---|
| Identity | id | `root-ca` — the same id the other data center uses |
| Identity | display name | `Example Root` (any text) |
| Certificate | the box | paste `root.pem`, or use *…or upload a PEM/CRT file* |
| Key location | the choice | **Trust anchor only — this node never signs with it** |

Press **Import CA**. Choosing *trust anchor only* is what makes this safe: no key is sent,
the row is stored without one, and DC2 can check chains up to the root but can never sign
with it.

**7.3 — on DC2: register its own sub CA.**

Same form again: **CAs** → **Import an existing CA**.

| Section | Field | What to put |
|---|---|---|
| Identity | id | `dc2-sub` |
| Identity | display name | `Example DC2 Sub` |
| Certificate | the box | paste the `dc2-sub.crt` you downloaded in step 6 |
| Key location | the choice | **This node holds the key in its token** (the default) |
| Key location | Key name | `dc2-sub` — the key you made in step 5 |
| Key location | Token, Slot, PIN file | leave as they are |

Press **Import CA**. The key name must match step 5 exactly. That is what ties this certificate to the key
already sitting in DC2's token; nothing else connects the two.

**7.4 — check it.** DC2's **CAs** page now lists two entries:

- `root-ca` — status active, marked **no key here**. Correct: DC2 verifies with it and never
  signs with it.
- `dc2-sub` — status active, with its own key, and **Issuer** showing the root's name.

If `dc2-sub` shows no issuer, or the page reports that the certificate does not match the
key, the key name in 7.3 is not the one from step 5.

⚠️ **Back on DC1, press Disable on the root's row** — it has now signed every data center's
issuing CA, which is all it is for. Disabling stops new issuance and leaves its revocation
list, OCSP answers and chain serving untouched (§4.3). Re-enable it when you add the next
data center, sign that CA, and disable it again. Do this on DC1 only: DC1 holds the root's
key, and on DC2 the root is a trust anchor with no key, which signs nothing to begin with.

#### Step 8 — on DC2: its service certificates

DC2 has a CA now, but its services still have nothing issued from it. This is §4.4 on the new
machine, and the short way works here too. Everything is issued from **`dc2-sub`**.

**8.1 — name the CA**, in DC2's **Config** tab (click **All** in the row of areas, choose each
key from the **Key** list, press **Set**), or on the command line:

```bash
cd ~/FastPKI/deploy
docker compose exec web fastpki-config set PG_TLS_CA_ID dc2-sub
docker compose exec web fastpki-config set CMP_CLIENT_CA_ID dc2-sub
```

On Kubernetes — `fastpki-node-0` on a single-server cluster, and on a pair the read-write server
found in step 4:

```bash
kubectl exec -n fastpki fastpki-node-0 -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set PG_TLS_CA_ID dc2-sub
kubectl exec -n fastpki fastpki-node-0 -c web -- \
    fastpki-config --config /app/config/bootstrap.conf set CMP_CLIENT_CA_ID dc2-sub
```

Both are **node-local in a mesh**, so DC2 needs its own values even though the other data
center already has them.

**8.2 — issue everything, in one command:**

```bash
cd ~/FastPKI/deploy
docker compose exec web fastpki-ca renew-service-certs --create-missing --re-issue-self-signed
```

On Kubernetes:

```bash
kubectl exec -n fastpki fastpki-node-0 -c web -- \
    fastpki-ca --config /app/config/bootstrap.conf renew-service-certs --create-missing --re-issue-self-signed
```

That creates DC2's OCSP, CMP and SCEP credentials, replaces its four listeners' self-signed
certificates, and issues its **database** certificate — which is not optional here, because
peers check it when they connect, so the mesh cannot come up without it.

⚠️ **Add `--replicable` only if DC2 will later have an HA standby of its own** (§6a). It
cannot be added afterwards. A single-host data center does not need it.

**8.3 — when you need the console instead.** The command uses this node's own name for the
listener certificates. If DC2 must answer to **extra names**, issue those four from the console
as §4.4's walkthrough step 4 describes — **CN** and **SANs** being **DC2's own FQDN** plus the
extra ones, never the other data center's name, and with **use a key already in the token**
ticked.

**8.4 — restart DC2's services** so they read the new credentials:

```bash
cd ~/FastPKI/deploy
docker compose restart ocsp cmp scep est acme ms web
```

On Kubernetes, one command restarts every server of the cluster, every listener included:

```bash
kubectl -n fastpki rollout restart statefulset/fastpki-node
```

**8.5 — check.** CMP and SCEP announce their RA mode in the log at every start:

```bash
docker compose logs --since 5m cmp scep | grep -iE 'RA mode'
```

On Kubernetes, each listener is its own container in the server pod:

```bash
kubectl -n fastpki logs fastpki-node-0 -c cmp  --since=5m | grep -iE 'RA mode'
kubectl -n fastpki logs fastpki-node-0 -c scep --since=5m | grep -iE 'RA mode'
```

OCSP says nothing there, because it only reports the responder key when that key **appears**
— which happened before this restart. Ask it instead. Both commands run on DC2, and
`dc2-sub` is its CA id:

```bash
wget -qO /tmp/iss.der http://DC2-ADDRESS:8080/dc2-sub.crt && openssl x509 -inform DER -in /tmp/iss.der -out /tmp/iss.pem
docker compose exec -T web cat /var/pki/tls/pg/server.crt > /tmp/pg.pem
#   Kubernetes: kubectl exec -n fastpki fastpki-node-0 -c web -- cat /var/pki/tls/pg/server.crt > /tmp/pg.pem
openssl ocsp -issuer /tmp/iss.pem -cert /tmp/pg.pem -url http://DC2-ADDRESS:8080/ocsp -noverify
```

The last line must end in `good`. That one answer proves the chain: the responder key is in
the token, its certificate was issued by `dc2-sub`, and the certificate being asked about is
one this data center issued. `Responder Error: internalerror` instead means step 8.2 did not
finish.

#### Step 9 — from your own machine: finish the mesh, with the same command

```bash
deploy/mesh-join.sh admin@192.0.2.10+admin@192.0.2.11 admin@198.51.100.10
```

This time it finds a CA in every data center and carries on. Where `PG_TLS_CA_ID` is unset it
sets it to that data center's issuing CA, issues each database certificate from it, waits for
Postgres to take the new certificates up, runs part two on every primary, and waits until both
data centers hold the same number of certificates (step 10):

```
mesh-join: pass 1 done: every data center knows the others and publishes
mesh-join: data center 2: PG_TLS_CA_ID=dc2-sub
mesh-join: data center 2: database certificate issued
mesh-join: waiting 65 seconds for Postgres to take up the new certificates
mesh-join: pass 2 done: every data center subscribes to every other
mesh-join: done: every data center holds 28 certificates, and each is subscribed to the other
```

It stops with the reason if a data center has several issuing CAs and no `PG_TLS_CA_ID`: it
cannot tell which one should issue the database certificate, so set it (§9.1 step 5 shows the command) and run
it again. The rest of this step and step 10 are what it does, by hand.

##### By hand: part two

Only now, once every node has a database certificate its peers can verify.

**Where to run it:** the same rule as step 4 — once per data center, on the **primary** of a
pair and never on the standby. The subscriptions this creates live in the shared database, so
a promoted standby takes over this data center's side of the mesh with them already in place.

**Put the node's own data center index after `--node`** — `1` on DC1, `2` on DC2. It is a
number, not a placeholder to leave in: typed as `--node INDEX`, bash reads `<` as a file
redirect and answers `syntax error near unexpected token`.

**On Kubernetes**, run it on **both** clusters, each with its own index. One run creates one
subscription, in one direction: until the second cluster has run its own, it receives nothing
and its row counts stay behind.

On the first cluster:

```bash
cd ~/mesh-bootstrap
NS=fastpki
PRIMARY=fastpki-node-0                   # fastpki-node-1 if that is the pod that answered f in step 4
kubectl exec -i -n "$NS" "$PRIMARY" -c web -- sh -c \
    'cat > /tmp/topology && exec fastpki-mesh --topology /tmp/topology "$@"' _ --node 1 < topology \
  | kubectl exec -i -n "$NS" "$PRIMARY" -c postgres -- psql -U fastpki -d fastpki
```

On the second cluster — the same, with `--node 2`:

```bash
cd ~/mesh-bootstrap
NS=fastpki
PRIMARY=fastpki-node-0                   # this cluster's read-write server
kubectl exec -i -n "$NS" "$PRIMARY" -c web -- sh -c \
    'cat > /tmp/topology && exec fastpki-mesh --topology /tmp/topology "$@"' _ --node 2 < topology \
  | kubectl exec -i -n "$NS" "$PRIMARY" -c postgres -- psql -U fastpki -d fastpki
```

On DC1:

```bash
cd ~/FastPKI/deploy
docker compose run --rm --no-deps --user 0:0 -v "$PWD/topology:/topology:ro" \
    --entrypoint fastpki-mesh web --topology /topology --node 1 \
  | docker compose exec -T postgres psql -U fastpki -d fastpki
```

On DC2:

```bash
cd ~/FastPKI/deploy
docker compose run --rm --no-deps --user 0:0 -v "$PWD/topology:/topology:ro" \
    --entrypoint fastpki-mesh web --topology /topology --node 2 \
  | docker compose exec -T postgres psql -U fastpki -d fastpki
```

Each run must end with a `CREATE SUBSCRIPTION` line, and print no line beginning with
ERROR.

⚠️ **If a pass-2 run failed for any reason, clear its slot before retrying.** The subscriber
asks the peer for a replication slot first and creates the subscription second, so a run that
dies in between leaves the slot behind on **the peer**. The retry then stops with:

```
ERROR:  could not create replication slot "sub_1_from_2": ERROR:  replication slot "sub_1_from_2" already exists
```

On the peer named in that message — the data center being subscribed to — drop it, then run
pass 2 again. The first command frees the slot if a dead connection still holds it:

```bash
cd ~/FastPKI/deploy
docker compose exec -T postgres psql -U fastpki -d fastpki \
  -c "select pg_terminate_backend(active_pid) from pg_replication_slots where slot_name='sub_1_from_2' and active_pid is not null"
docker compose exec -T postgres psql -U fastpki -d fastpki \
  -c "select pg_drop_replication_slot('sub_1_from_2')"
```

On Kubernetes, on that peer's read-write server — `fastpki-node-0` on a single-server cluster:

```bash
kubectl exec -n fastpki fastpki-node-0 -c postgres -- psql -U fastpki -d fastpki \
  -c "select pg_terminate_backend(active_pid) from pg_replication_slots where slot_name='sub_1_from_2' and active_pid is not null"
kubectl exec -n fastpki fastpki-node-0 -c postgres -- psql -U fastpki -d fastpki \
  -c "select pg_drop_replication_slot('sub_1_from_2')"
```

Dropping a slot no subscription is using loses nothing: it only tells the peer to stop keeping
WAL for a subscriber that does not exist. If the drop answers `replication slot … does not
exist`, terminating its holder already removed it — that is success, carry on.

**A third data center, and every one after it, follows the same shape.** Nothing here is
special to two:

- the topology file gets one more line and goes on **every** node, the existing ones included;
- **pass 1 runs again everywhere**, so each node knows all the `datacenters` rows and publishes
  to all of them;
- **pass 2 runs once per data center with its own index** — `--node 1`, `--node 2`, `--node 3`;
- each node ends up with **one subscription per peer**: two each on a three-data-center mesh,
  six in total;
- the new data center still needs its own sub CA signed by the same root, and its own service
  certificates — steps 5 to 8 above, unchanged.

#### Step 10 — check both data centers hold the same data

Step 9's command waits for this itself and says `done` when the counts match. To check
by hand, run this on **every** node. The counts must be identical:

```bash
cd ~/FastPKI/deploy
docker compose exec -T postgres psql -U fastpki -d fastpki -tAc 'select count(*) from certs'
```

On Kubernetes — a read, so either server of a pair answers it:

```bash
kubectl exec -n fastpki fastpki-node-0 -c postgres -- psql -U fastpki -d fastpki -tAc 'select count(*) from certs'
```

They may differ for a few seconds while the first copy runs. They stay different indefinitely
if step 9 has not been run on **both** data centers: each run subscribes one data center to the
other, so until both have run, one side receives nothing. `select subname from pg_subscription`
on each shows which one is missing. If both have a subscription and the counts still differ,
§9.6 is the fault-finding section. The console's **Replication** page shows each node's subscriptions,
but only comparing counts proves they hold the same data (§9.2).

A last check that the two data centers really are one PKI: on DC2, the **CAs** page now also
lists the other data center's CAs (with *no key here*), and a certificate issued on DC1
appears in DC2's **Inventory** within seconds.

#### Step 11 — optional: give the older CAs both addresses

The CA certificates that existed before step 4 name only their own data center, because a
certificate cannot be told a new URL later. Everything verifies until that node is the one
that is down. To close that, renew each of those CAs once now that both `datacenters` rows
exist, keeping the key (admin guide §3.8). Whether it is worth doing is a judgement about how
much the fallback matters to your relying parties; §9.4 has the detail.

### 9.1 Making the servers trust each other before they copy data — reference

Before two data centers will copy data to each other, each has to be satisfied that the other
really is who it claims to be. Each checks the other's database certificate, in full.

The problem is that every server starts with a database certificate it signed itself, which
no other server has any reason to believe. So nothing can be connected until every server's
database certificate has been signed by a CA they all trust.

Until that is true, the command that starts the copying fails with
`SSL error: certificate verify failed`. Worse, `psql` carries on after an error, so the
commands report success while nothing at all is being copied.

What works is **one root CA, and one issuing CA per server**. Each server signs its own
database certificate, and it can only sign with a key in its own key store — which at this
point means only a key it created itself. That rules out one shared issuing CA. Giving each
server its own means each has a key it can sign with, while every certificate still leads
back to the single root they all trust.

**You can do all of this in the console.** Almost every step below is a page in it, and a new
install can already make these changes — there is no security setting to relax first. Sign in
as the admin the installer created and work through the CAs page. The command line version
follows, for deployments that would rather script it.

#### From the console — see §9.0

The console walkthrough lives in **§9.0**, step by step, with every field and button named.
The rest of this section is what §9.0 does not cover: the
same sequence as commands, for a scripted or headless install, and the detail behind each
step — what it writes, what it refuses, and how each way of getting it wrong shows up.

Two points from §9.0 are worth repeating here, because they decide whether the result is
correct rather than merely working:

- **`admin` is a single account shared by every data center.** Each installer creates its own
  copy with its own password, and once the servers start copying to each other only one copy
  survives — the last one written, with nothing to tell you whose password that was. Set the
  same password everywhere, or set it on one server and let it reach the others.
- **Tell the servers about each other (step 0, and part one of step 9) before you create any
  CA.** The addresses inside a certificate are fixed when it is created, one for each data
  center the server knows about. A CA created before that list exists will name one data
  center for as long as its certificate is valid.

#### From the command line — the version you can script

The same bootstrap as one command per step, for a scripted or ssh-driven rollout. It is
the identical code path: the console's CA pages and `fastpki-ca` both go through
`pki::resolve_ca_instance()` and the same issuance in `src/lib/x509.cpp`.

#### The two shorthands used below

Run these on the node you are working on. They invoke a tool inside the shipped image
against that node's own database; `-v /tmp:/hosttmp` is only needed by the steps that read
or write a file.

⚠️ **A file written through `/hosttmp` belongs to the container's user, not to you.** The
image runs as its own uid, so `--out /hosttmp/root-ca.crt` lands in the host's `/tmp` owned by
whatever that maps to locally. It is world-readable, so the later steps here work — but you
cannot overwrite it, and a second run, or a later procedure that writes the same name, fails
or silently keeps the old file, so a node ends up configured with the wrong trust anchor
while every command reports success. Remove these by name when you are done with
them, and check a fingerprint after installing any anchor rather than trusting that the file
you just wrote is the file that is there.

```bash
cd deploy
ca()  { docker compose run --rm --no-deps -v /tmp:/hosttmp \
          --entrypoint fastpki-ca     web --config /app/config/bootstrap.conf "$@"; }
cfg() { docker compose run --rm --no-deps \
          --entrypoint fastpki-config web --config /app/config/bootstrap.conf "$@"; }
```

⚠️ **Write the `pkcs11:` URI out in full, every time** — `token=`, `object=`, `type=` and
`?pin-source=`. A shortened `pkcs11:object=x;type=private` resolves on some nodes and not
others: without `pin-source` the tool falls back to `PKCS11_PIN_FILE`, and when that
fallback does not fire the provider prompts for a PIN, fails to read one, and reports the
misleading `The token was not present in its slot`. Measured on a three-node deployment, where the
identical short URI worked on one node and failed on another.

#### Step 0 — on every server: the topology file, and `--map`

⚠️ **This comes before any CA is created.** The CRLDP and AIA entries in a certificate are
built when it is issued, from this node's `BASE_URL` plus one entry per row in the
`datacenters` table — and those rows come from `--map`. A sub CA created before them carries
its own node's URL alone, which is exactly the single point of failure the per-data-center
fallback exists to remove, and nothing warns you: every command succeeds and every
certificate verifies on its own. Getting it wrong means renewing each sub CA afterwards so
its certificate names every data center, which step 9 explains.

Write the topology file now — **step 8 gives the format and every field's traps** — and run
`--map` on every node:

```bash
# from deploy/, where the topology file sits
docker compose run --rm --no-deps --user 0:0 -v "$PWD/topology:/topology:ro" \
    --entrypoint fastpki-mesh web --topology /topology --map \
  | docker compose exec -T postgres psql -U fastpki -d fastpki
```

On a native or cloud node there is no container:

```bash
fastpki-mesh --topology /root/topology --map \
  | su postgres -s /bin/sh -c 'psql -q -v ON_ERROR_STOP=1 -U fastpki -d fastpki'
```

`--map` needs no CA and no replication — it only writes those rows — so it runs first.
`--publication` and `--node` belong in step 9, after the database certificates exist.

#### Step 1 — on server 1: the root CA, and server 1's own issuing CA

```bash
ca create root-ca --name "Example Root" --subject "/CN=Example Root" --days 3650 \
   --key ec --curve P-256 --keygen \
   --ca-key 'pkcs11:token=fastpki;object=root-ca;type=private?pin-source=/var/pki/tls/pin'

ca create dc1-sub --parent root-ca \
   --name "Example DC1 Sub" --subject "/CN=Example DC1 Sub" --days 1825 \
   --key ec --curve P-256 --keygen \
   --ca-key 'pkcs11:token=fastpki;object=dc1-sub;type=private?pin-source=/var/pki/tls/pin'

ca show root-ca --pem --out /hosttmp/root-ca.crt      # -> /tmp/root-ca.crt on this host
```

The root's key stays in node 1's token and is never needed anywhere else. `root-ca.crt` is a
**certificate**, which is public — copying it to the other nodes reveals nothing.

#### Step 2 — on every other server: its own CA key, and a request to sign it

Node 2 shown; node 3 is the same with `dc3-sub`.

```bash
ca csr dc2-sub --keygen --key ec --curve P-256 --subject "/CN=Example DC2 Sub" \
   --ca-key 'pkcs11:token=fastpki;object=dc2-sub;type=private?pin-source=/var/pki/tls/pin' \
   --out /hosttmp/dc2-sub.csr
```

Copy `/tmp/dc2-sub.csr` to node 1. The private key stays in node 2's token — only the CSR
travels.

⚠️ **Add `--replicable` here if this node's sub CA may ever need to sign from another
node.** It generates the key extractable, which is what lets `fastpki-ca key replicate` copy it
into a peer's token later (§9.7) so that losing this node does not take its CA's signing
with it. `CKA_EXTRACTABLE` is fixed when the key is generated and PKCS#11 has no way to
grant it afterwards, so a sub CA created without it is confined to this node for its whole
life — and if the node is lost, everything it issued can never be renewed or revoked. In a
mesh that confinement is the deliberate default (§9.7 explains the blast-radius trade-off);
decide it here, because it cannot be revisited.

#### Step 3 — back on server 1: sign that request with the root CA

```bash
ca sign-csr root-ca --csr /hosttmp/dc2-sub.csr --days 1825 --out /hosttmp/dc2-sub.crt
# signed /CN=Example DC2 Sub with 'root'
```

Copy `/tmp/dc2-sub.crt` **and** `/tmp/root-ca.crt` back to node 2.

#### Step 4 — on server 2: add the root certificate, then its own issuing CA

```bash
ca add root-ca --name "Example Root" --ca-pem /hosttmp/root-ca.crt
ca add dc2-sub --name "Example DC2 Sub" --ca-pem /hosttmp/dc2-sub.crt \
   --ca-key 'pkcs11:token=fastpki;object=dc2-sub;type=private?pin-source=/var/pki/tls/pin'
```

`root-ca` registers with **no `--ca-key`**: this node verifies against it and can never sign
with it, which is what a trust anchor is. `ca list` shows that as `ca_key=` empty.

⚠️ **`add` takes no `--parent`.** A CA's parent is read from its certificate's issuer, so
declaring it separately could contradict the bytes. `create` still takes `--parent`,
because there it decides who signs. Registering the root first is what lets `add dc2-sub`
resolve to `intermediate` rather than a second root.

⚠️ **Once every server's issuing CA is signed, disable the root on the node that holds its
key** — node 1 here: `ca disable root-ca`. That is the end of the root's work. Disabling stops
new issuance and leaves its revocation list, OCSP answers and chain serving untouched (§4.3),
and `ca enable root-ca` brings it back for as long as the next data center's signature takes.
The other nodes need nothing: their `root-ca` has no key and signs nothing.

#### Step 5 — on every server: the database certificate, from that server's own issuing CA

The certificate must name **the address this node's peers dial**, and it does so without
being told: `fastpki-ca pg-tls` adds this node's own `PG_BIND` from the environment, which
is per-node in compose and cannot be overridden by a config row. `PG_TLS_SANS` adds extra
names beyond that.

⚠️ **Do not put this node's interconnect address in `PG_TLS_SANS`.** It is read from the
`config` table, which is node-local in a mesh but shared by the two hosts of an HA pair —
one row for two machines. An address recorded there becomes a name on the other host's
certificate as well, and leaves that host's own address out. `PG_TLS_SANS` is normally
empty and should stay that way — `pg-tls` takes the interconnect address from this node's
own `PG_BIND` and prints every name it certified, so read that output rather than setting
anything:

```bash
ca pg-tls dc2-sub                      # node 1 uses dc1-sub, node 3 dc3-sub
#   names:  postgres, localhost, 127.0.0.1, <this node's PKI_DNS>, 198.51.100.10
```

If the interconnect address is missing from that list, this node's `PG_BIND` is still the
default `127.0.0.1`. Correct `PG_BIND` — it is the address peers actually dial — and
re-issue; the certificate follows from it. Use `PG_TLS_SANS` only for extra names
beyond the ones above.

That writes `server.crt`/`server.key` and **prepends the root to `pg/ca.crt`**, which is a
bundle of anchors rather than a single certificate. Postgres adopts the new pair within
~30s without a restart. `pg-tls` refuses outright if the CA does not chain to a registered
anchor — step 4 is what prevents that — so a half-applied state is not reachable.

⚠️ **Record which CA issued it, or nothing ever renews it.** Naming the CA on the command
line issues the certificate and no more; the nightly job that keeps it current asks
`PG_TLS_CA_ID`, and unset it does nothing and says so:

```
pg-tls: PG_TLS_CA_ID is unset, so the database certificate is not being maintained —
        a node promoted here would serve one its peers cannot verify
```

Set it to the same CA once, on every node:

```bash
cfg set PG_TLS_CA_ID dc2-sub          # node 1 uses dc1-sub, node 3 dc3-sub
```

It is not inferred from the last `pg-tls` run. Set it explicitly, or the nightly job leaves
the certificate alone.

The address must also be the one Postgres is **published** on. `PG_BIND` in `.env` governs
that, and it defaults to `127.0.0.1`, which no peer can reach:

```bash
grep PG_BIND .env          # PG_BIND=198.51.100.10
docker compose ps postgres # postgres  198.51.100.10:5432->5432/tcp
```

#### Step 6 — on every server: its own service certificates

Each node signs with its own sub CA, so the OCSP responder, CMP RA and SCEP RA credentials
are per-CA and per-node. **Nothing replicates them**: the key behind each is generated in the
token of the node that will use it, and a service credential is never replicated between
tokens — the same reason the mesh needs a sub CA per node in the first place.

A node that skips this joins the mesh, replicates correctly and serves CRLs, and then
refuses every CMP transaction with `no RA credential`, answers `internalerror` to every OCSP
request, reports `no default CA served over SCEP`, and serves all four listeners on the
self-signed certificates `certgen` made. Every container is healthy throughout.

```bash
docker compose exec web fastpki-ca renew-service-certs --create-missing --re-issue-self-signed
docker compose restart ocsp cmp scep est acme ms web
```

Native or cloud node. The renewal runs as the `fastpki` user — the token socket belongs to it,
and as `root` every listener key fails to open — while the restarts need root:

```bash
doas su -s /bin/sh fastpki -c \
    'fastpki-ca --config /etc/fastpki/bootstrap.conf renew-service-certs --create-missing --re-issue-self-signed'
for s in ocsp cmp scep est acme ms web; do doas rc-service fastpki-$s restart; done
```

§4.4a describes what each credential is. On a mesh node the summary reports the peers' CAs
as `skipped … (no signing key on this node)`, which is correct — this node holds a key for
its own sub CA alone.

#### Step 7 — check all of this before you connect the servers together

On any node, confirm the certificate chains to the shared root and carries the
interconnect address:

```bash
# -untrusted names the file holding the INTERMEDIATES. It is the same file, and it
# is not optional: `openssl verify` reads only the FIRST certificate out of the file
# it is asked to check, so the sub CA sitting directly after the leaf in server.crt
# is ignored, and a perfectly good chain reports
#   error 20 at 0 depth lookup: unable to get local issuer certificate
# A TLS client never hits this -- the server SENDS the intermediates -- so the bare
# form fails only in this hand-check, and only once a SUB CA issues the certificate.
openssl verify -CAfile /var/lib/docker/volumes/fastpki_pki-data/_data/tls/pg/ca.crt \
               -untrusted /var/lib/docker/volumes/fastpki_pki-data/_data/tls/pg/server.crt \
               /var/lib/docker/volumes/fastpki_pki-data/_data/tls/pg/server.crt
openssl x509 -in .../server.crt -noout -text | grep -A1 'Subject Alternative Name'
```

and that a peer can actually open a verified connection:

```bash
docker compose exec -T postgres psql \
  "host=<that peer's address> port=5432 user=fastpki dbname=fastpki \
   password=<that peer's db password> \
   sslmode=verify-full sslrootcert=/pki/tls/pg/ca.crt" -tAc 'select 1'
```

**On a native or cloud node**, the same two checks against the on-disk paths, and the peer
connection opened by the postgres system user so it reads the anchor Postgres itself uses:

```bash
openssl verify -CAfile /var/pki/tls/pg/ca.crt \
               -untrusted /var/pki/tls/pg/server.crt /var/pki/tls/pg/server.crt
openssl x509 -in /var/pki/tls/pg/server.crt -noout -text | grep -A1 'Subject Alternative Name'

su postgres -s /bin/sh -c 'psql "host=<that peer'"'"'s address> port=5432 user=fastpki dbname=fastpki \
   password=<that peer'"'"'s db password> sslmode=verify-full \
   sslrootcert=/var/lib/postgresql/tls/ca.crt" -tAc "select 1"'
```

⚠️ **`/var/lib/postgresql/tls/ca.crt`, the postgres-owned copy** — the same anchor, and the
same reason step 8 gives for the topology's `sslrootcert`: `/var/pki` is `drwxr-x---` owned
by `fastpki`, which postgres cannot traverse.

A `1` means trust is established. `certificate verify failed` means the peer's certificate
does not chain to this node's `pg/ca.crt`, or does not carry the address you dialled.

⚠️ **`password authentication failed for user "fastpki"` is the expected result of this step.** Each
installer generates that node's own `POSTGRES_PASSWORD`, so peers do not share one, and the
password is a per-peer value you supply here and in the topology's `conninfo`. TLS is
verified before any credential is examined, so reaching an authentication error proves the
certificate chained and the address matched — which is the only thing this step checks. Add
the peer's password (from its `deploy/.env`) to turn it into the `1`.

#### Step 8 — write the file that lists every server

`fastpki-mesh` takes the whole mesh as one small text file, and **the same file goes on
every node** — `--node <i>` selects whose subscriptions to emit from it. Nothing
generates it: the prefixes are decisions, not derivations (see below).

One data center per line, four `|`-separated fields, `#` comments and blank lines ignored:

```
dc_id|conninfo|serial_prefix|base_url
```

| Field | What it must be |
|---|---|
| `dc_id` | `[A-Za-z0-9_]`, and **exactly** that data center's `DATACENTER_ID` — a node reads its own and refuses to issue if no line carries it. The installers write digits (`DATACENTER_ID=2` from `DC_INDEX=2`), so the id is `2`. `dc2` parses fine and then matches nothing. |
| conninfo | A libpq string the **postgres container** dials — it is the Postgres server that opens the subscription, not any FastPKI process. Needs `host=`, `dbname=fastpki`, `user=fastpki`, that peer's database password, and `sslrootcert=/pki/tls/pg/ca.crt`. `sslmode=` defaults to `verify-full` and an explicitly weaker one is refused. |
| serial_prefix | A decimal integer 1–32767, unique across the file, and equal to that node's `DC_INDEX`. |
| base_url | The address a relying party fetches this node's **CRL and AIA** from — scheme, host and port, no path. ⚠️ **This must be an address that actually serves them, and by default that is `http://<host>:8080`**, because `fastpki-ocsp` serves `/{ca}.crl`, `/{ca}.crt` and `/ocsp` on port 8080 over plain HTTP. `https://<host>` is right only where a reverse proxy (§10) forwards 443 to it; without one, every certificate the mesh issues carries fallback URLs that answer nothing, and nothing warns you — the URLs are recorded, not probed. Every certificate issued anywhere in the mesh carries one **CRL distribution point** and one **AIA caIssuers** entry per data center, built from these, so a relying party that cannot reach one node has another to try. A certificate cannot be told a new URL after it is issued, so a data center missing here is one nothing will ever fall back to — and one named wrongly is worse, because it looks present. ⚠️ **The AIA OCSP entry names only the issuing data center**, unless you set `OCSP_RESPONDER_KEYS_REPLICATED=true`. A CRL and a CA certificate are signed once and replicate, so any node can serve a copy; an OCSP response is signed for each request with that CA's `ocsp-ra-<ca-id>` key, which another data center holds only if you replicated it (`fastpki-ca key sync`). Set that key once every data center really can answer for every CA — not before, because a responder named in a certificate that cannot answer stays named for the life of that certificate. |

A worked three-node file, `deploy/topology`:

```
# dc_id | conninfo (dialled by the postgres container) | serial prefix | public base URL
1|host=192.0.2.10 port=5432 dbname=fastpki user=fastpki password=<DC1 db password> sslmode=verify-full sslrootcert=/pki/tls/pg/ca.crt|1|http://pki-dc1.example.org:8080
2|host=198.51.100.10 port=5432 dbname=fastpki user=fastpki password=<DC2 db password> sslmode=verify-full sslrootcert=/pki/tls/pg/ca.crt|2|http://pki-dc2.example.org:8080
3|host=203.0.113.10 port=5432 dbname=fastpki user=fastpki password=<DC3 db password> sslmode=verify-full sslrootcert=/pki/tls/pg/ca.crt|3|http://pki-dc3.example.org:8080
```

```bash
chmod 600 deploy/topology
```

⚠️ **`chmod 600` it, and keep it out of the repo.** Each line carries a peer's database
password in the clear, and replication itself carries `web_users` password hashes and the
per-user enrolment secrets. That mode is also why step 9 runs the container as `--user
0:0`: the image runs as uid 101, which cannot read a 600 file owned by you, and the failure
is silent — `fastpki-mesh` says "cannot open topology file", the pipe feeds `psql` nothing,
and every step still reports success.

Four details, each of which is a failure mode rather than style:

- **`user=fastpki`, not `user=repl`.** Nothing in this deployment creates a `repl` role;
  every conninfo built from a template naming it failed to authenticate.
- **`sslrootcert=/pki/tls/pg/ca.crt`, not `/var/pki/...`.** The apps mount the volume at
  `/var/pki`; the postgres container mounts it read-only at `/pki`, and this path is
  resolved there. With `/var/pki` the peer connection fails with `root certificate file
  ... does not exist`, `CREATE SUBSCRIPTION` errors, and `--node` reports nothing wrong.
- **On a native or cloud node it is `/var/lib/postgresql/tls/ca.crt`** — a third path, for
  the same reason. There is no container, so the difference is the UNIX user: the
  subscription is opened by the postgres server, and `/var/pki` is `drwxr-x---` owned by
  `fastpki`, which postgres cannot traverse. The file inside it is world-readable, so it
  looks fine to anyone checking with `ls`, and postgres still reports
  `root certificate file "/var/pki/tls/pg/ca.crt" does not exist`. The installer already
  maintains a postgres-owned copy at `/var/lib/postgresql/tls/ca.crt` — the same anchor,
  beside the server certificate Postgres serves — and that is the path a native topology
  must name.
- **A prefix is permanent once its data center has issued anything**, so write it by hand
  and never change it. Two data centers using the same serial space is the one thing
  this mechanism exists to prevent.

**With intra-data-center HA (`high-availability.md`), name both of that DC's Postgres hosts** and let libpq
pick the live one — synchronised slots preserve the slot, not the address, and a single-host
conninfo means peers get connection refused after a failover however well the slots
survived:

```
2|host=198.51.100.10,198.51.100.11 port=5432,5432 dbname=fastpki user=fastpki password=<pw> sslmode=verify-full sslrootcert=/pki/tls/pg/ca.crt target_session_attrs=read-write|2|http://pki-dc2.example.org:8080
```

Each host's own database certificate names that host's own address, so `verify-full` holds
against whichever of the two libpq lands on, before and after a promote.

#### Step 9 — tell the servers about each other, in two parts, in this order

Run `--map` and `--publication` on **every** node first, then `--node <i>` on every node.
A subscription can only copy from a publication that already exists, so creating node 1's
subscriptions before nodes 2 and 3 have published leaves them with nothing to read.

Once both passes are done the data centers catch up with each other on their own — every node seeds from every peer
— and §9.2 is how to confirm it rather than a step you have to perform.

⚠️ **If you did not run `--map` before step 1, the sub CAs name only their own node until they
are renewed.** `--map` writes the `datacenters` rows, and issuance reads them to build one CRLDP
and one AIA entry per data center. A CA certificate issued before those rows existed carries its
own node's URL alone. A certificate cannot be changed, so the remedy is a **renewal**: a new CA
certificate, which can keep the current key, with the URLs derived when it is signed. The old
certificate stays live until it expires, so existing leaves still validate.

Leaves are never affected, because issuance derives their URLs afresh every time.

⚠️ **`ca urls` will not tell you this.** It prints the URLs a certificate issued now would
carry — derived from the current config and the `datacenters` rows — so it lists every data
center even for a CA whose own certificate names one. To see what a CA actually carries, read
the certificate:

```bash
ca show dc1-sub --pem --out /hosttmp/dc1-sub.crt
openssl x509 -in /tmp/dc1-sub.crt -noout -text | grep -A1 'Authority Information Access'
openssl x509 -in /tmp/dc1-sub.crt -noout -text | grep -A1 'CRL Distribution Points'
```

One URI of each on a three-data-center mesh means this CA was created before the map; three
means it was created after. Both name the parent, because the parent publishes the CRL covering
this CA.

If it lists one node and you want the fallback, renew that sub CA with its current key. Its
parent signs the renewal, so on a mesh, where the root's key is on one node, renew it through a
CSR (admin guide §3.8, *Renewing through a CSR*): `ca csr` on this node without `--keygen`,
`ca sign-csr root` on the root's node, `ca add dc1-sub` back here. Where the root's key is on
this node, `ca renew dc1-sub` does it in one step, and so does CAs → its row → **Renew** with
**Keep the current key**. If you disabled the root once the issuing CAs were signed, enable it
for the renewal and disable it again: `ca enable root-ca`, `ca renew dc1-sub`, `ca disable root-ca`.
Then
re-issue the database certificate and the service credentials beneath it and restart the
listeners:

```bash
ca pg-tls dc1-sub
docker compose exec web fastpki-ca renew-service-certs --create-missing --re-issue-self-signed
docker compose restart ocsp cmp scep est acme ms web
```

**Pass 1 — on every node**, so that every publication exists before any subscription does:

```bash
for s in map publication; do
  docker compose run --rm --no-deps --user 0:0 -v "$PWD/topology:/topology:ro" \
      --entrypoint fastpki-mesh web --topology /topology --$s \
    | docker compose exec -T postgres psql -U fastpki -d fastpki
done
```

**Pass 2 — only once pass 1 has finished everywhere**, on every node, with its own index:

```bash
docker compose run --rm --no-deps --user 0:0 -v "$PWD/topology:/topology:ro" \
    --entrypoint fastpki-mesh web --topology /topology --node <index> \
  | docker compose exec -T postgres psql -U fastpki -d fastpki
```

Both passes run from `deploy/`, where the topology file from step 8 sits.

**On a native or cloud node** there is no container and no `deploy/` directory. The binary
is on the PATH, the topology file is wherever you put it (`/root/topology` below, mode 600),
and the SQL goes to the local `psql` as the postgres system user — which is also why no
`--user 0:0` equivalent is needed:

```bash
# pass 1, on every node
for s in map publication; do
  fastpki-mesh --topology /root/topology --$s \
    | su postgres -s /bin/sh -c 'psql -q -v ON_ERROR_STOP=1 -U fastpki -d fastpki'
done

# pass 2, on every node, with its own index
fastpki-mesh --topology /root/topology --node <index> \
  | su postgres -s /bin/sh -c 'psql -q -v ON_ERROR_STOP=1 -U fastpki -d fastpki'
```

`fastpki-mesh` takes no `--config`: the topology file is its whole input.

**Pass 2 checks the releases match before it emits anything.** It connects to this node's
database and to each peer in the topology, and compares the tables each side has against
the tables each side publishes. If they differ, the two nodes are running different
releases, and it refuses with a message naming the table and which side is behind. Do not
work around it: a subscription created across a version gap fails at seeding with
`relation "public.<table>" does not exist`, and that error names the *healthy* node's
database, so it reads as damage there. Update the node it names, then re-run both passes.
It also refuses when a peer publishes nothing yet (`data center '2' does not publish
anything yet`): that peer ran `--map` without `--publication`. Run pass 1 there in full,
then pass 2 here again.
A peer that cannot be reached yet is a note rather than a failure. `--no-preflight` skips
the check, for generating a data center's SQL before that data center exists.

`--user 0:0` is required, and it is not tidiness: that file is mode 600 because it holds
every peer's database password, and the image runs as uid 101, which cannot read it —
`fastpki-mesh` reports "cannot open topology file", the pipe feeds `psql` nothing, and
every step still reports success while changing nothing. Root inside the container reads
the host file whatever its mode.

Check any node with `--node <i> --verify`, and confirm the subscriptions are live:

```bash
docker compose exec -T postgres psql -U fastpki -d fastpki -tAc \
  "select s.subname, (r.pid is not null) as connected, r.latest_end_lsn
     from pg_subscription s
     left join pg_stat_subscription r on r.subname = s.subname order by 1"
```

Every row must show `t` for connected. Each server has one connection for every other server,
so with three data centers each one has two.


### 9.2 Confirming every data center holds the same data

Every node subscribes to **every** peer with `copy_data = true`, so a first-time bootstrap
catches up on its own and there is no manual back-fill step.

Every node has to copy from every other one because at bootstrap no single node holds
everything: steps 1–5 necessarily give each node local rows before replication can start —
its own sub CA, service certificates and database certificate — because `sslmode=verify-full`
cannot come up without them. Seeding each node from one designated peer instead leaves the
third node's rows, its sub CA included, reaching nobody, and every health signal stays green
while it happens: subscriptions connected, all 18 tables at `srsubstate = 'r'`, publisher
slots active and flushing, and changes made *after* the mesh formed replicating correctly in
both directions.

Copying from every other data center means each server is sent rows it already has. That is
safe by design, not by luck: every table that is copied knows what to do with a duplicate.
Five of them ignore it, and the other sixteen keep whichever copy was written last. All of
those rules are in place before any copying starts. The only cost is the bandwidth, once,
when a data center joins.

The console's **Replication** page (admin guide §12.5) shows all of this in one place: which
connections are on, which are running, when each last received something, and how many errors
it has seen. It saves logging in to every server to find one that has stopped. What it cannot
tell you is whether the data actually matches, for the reason below.

**To check that, compare the servers. Do not ask PostgreSQL whether it is happy.** Throughout
the failure described above, it said everything was fine:

```bash
# run on EVERY node — all counts must be identical
docker compose exec -T postgres psql -U fastpki -d fastpki -tAc "select count(*) from certs"
```

If the counts differ, the servers are not in step, whatever PostgreSQL's own status views say.
To see the connections as well:

```bash
docker compose exec -T postgres psql -U fastpki -d fastpki -tAc \
  "select s.subname, (r.pid is not null) as connected, r.latest_end_lsn
     from pg_subscription s
     left join pg_stat_subscription r on r.subname = s.subname order by 1"
```

Every row must show `t` for connected. Each server has one connection for every other server,
so with three data centers each one has two.


### 9.3 On Kubernetes

**One FastPKI data center is one Kubernetes cluster.** The mesh is between clusters, not
between pods: each cluster runs its own Postgres, its own token and its own CA key, and
they replicate to each other. Everything in §9.1 applies unchanged — one root, one sub CA
per cluster, each signing its own database certificate — because the reason is the token,
not the packaging.

⚠️ **Every cluster bootstraps its own `admin`, and joining them does not merge the two.** Each
`apply.sh` seeds `admin` in its own database, so after the join there are two rows that were
written independently and only one survives — with nothing to say whose password it was. The
symptom is that the console accepts your password on one cluster and answers `401` on the
other, which reads as a replication fault rather than an account one. Set the password
yourself on **each** cluster once they are joined, to the same value:

```bash
kubectl --context <ctx> -n <namespace> exec statefulset/fastpki-node -c web -- \
    fastpki-config --config /app/config/bootstrap.conf web-user admin '<password>' --role admin
```

The same is true of any local account. Directory accounts are unaffected: they are not stored
here, so a login through a directory gives the same answer on every cluster.

The in-cluster `fastpki-node` Service is headless, so no peer can reach a server's database through
it. Three settings in `env.sh` make a cluster a data center of a mesh:

| Setting | Description |
|---|---|
| `DC_INDEX` | **This** cluster's index, which **is** its serial prefix. Unique, stable, digits only — it is also the `dc_id` in the topology, and `dc1` never matches `1`. |
| `PG_INTERCONNECT` | The addresses the **other** clusters dial to reach this cluster's databases — one per server, comma-separated, in pod order. No default. Required on every cluster that has peers — data center 1 included, since its peers must dial it too. |
| `PG_EXTERNAL_TYPE` | How each server's Postgres is exposed to peers: `none` (default), `LoadBalancer`, or `NodePort` (`PG_NODEPORT` for `fastpki-node-0`, `PG_NODEPORT`+1 for `fastpki-node-1`). |

`apply.sh` **refuses** to deploy with a `DC_INDEX` other than 1 and no `PG_INTERCONNECT`, or
with a different number of addresses than servers, rather than warning. A cluster without it comes up looking healthy and can never be meshed:
the peers have no host to dial, and this cluster's database certificate cannot carry a SAN
it was never told about, so `verify-full` refuses it later — after the CAs exist and the
hard part looks done.

`PG_INTERCONNECT` is what marks a cluster as part of a mesh — a cluster is part of one
exactly when peers have an address to dial it on. `DC_INDEX` cannot serve that purpose,
because it is never unset: a single cluster is data center 1, not "no data center", so that
a later expansion does not leave earlier certificates outside this cluster's serial
partition.

**`PG_EXTERNAL_TYPE` therefore defaults to `none`.** A default of `LoadBalancer` would ask
the cloud provider for a public address for the *database* on every ordinary `apply.sh`,
including single clusters with no peer to serve. Set it yourself when you build the mesh.

#### What apply.sh does for a mesh

- Writes `DATACENTER_ID` and `PG_TLS_SANS=$PG_INTERCONNECT` into the generated
  `bootstrap.conf`. `PG_TLS_SANS` has to be set **before** `fastpki-ca pg-tls` runs, because
  the SANs come from config rather than from that command's arguments.
- Registers this cluster's `datacenters` row straight after the schema and **before** any
  issuing pod starts. Without it `est`, `acme`, `cmp`, `scep`, `ms` and `web` restart
  forever on `DATACENTER_ID=N has no row in datacenters`, while `ocsp` and `store` — which
  do not issue — run happily and make it look partly working.
- Applies one Service per server, `postgres-external-0` and `postgres-external-1`, each
  exposing that server's 5432 to the peer clusters. Not one Service across both: a standby
  serves reads and cannot accept a replication slot, so a peer whose subscription landed on it
  would connect and never advance. The peers list every address with
  `target_session_attrs=read-write` instead, and reach whichever server is the primary.
- Ends a successful deploy by naming this cluster's data center and serial prefix and the
  addresses peers reach its databases on, then gives the `deploy/mesh-join.sh` command that
  connects the clusters. Creating the CAs between its two runs is yours; the shorthand below
  is what makes §9.1's CA commands runnable here.

#### Running §9.1's steps against a cluster

§9.1's `ca` and `cfg` shorthands are compose forms. These are the same two tools in the web
pod, and every step in §9.1 works verbatim once they are defined:

```bash
NS=fastpki
ca()  { kubectl exec -n "$NS" statefulset/fastpki-node -c web -- \
          fastpki-ca     --config /app/config/bootstrap.conf "$@"; }
cfg() { kubectl exec -n "$NS" statefulset/fastpki-node -c web -- \
          fastpki-config --config /app/config/bootstrap.conf "$@"; }
```

⚠️ **Drop `--out` and redirect instead, and there is no `/hosttmp` here.** `ca show --pem`,
`ca csr` and `ca sign-csr` all write the PEM to stdout when `--out` is omitted, so the file
lands on the machine you are typing on, owned by you — which also avoids the container-uid
ownership trap §9.1 warns about.

⚠️ **Redirect into a fresh directory you own, not `/tmp`.** A rebuilt cluster meets the same
trap from the other side: `/tmp` may still hold `root-ca.crt` and `dc2-sub.csr` from an earlier
bootstrap, possibly owned by another uid. A redirect onto a file you cannot overwrite fails
with `Permission denied` while the old file stays — and the next step registers a trust anchor
or signs a CSR from a hierarchy this deployment knows nothing about, with every command
reporting success — a stale CSR whose private key lived in a token that has since been wiped
signs perfectly well and is worth nothing. So:

```bash
mkdir -p ~/mesh-bootstrap && cd ~/mesh-bootstrap      # and check what you wrote is what is there
```

```bash
ca show root-ca --pem                       > root-ca.crt           # step 1
ca csr dc2-sub --keygen --key ec --curve P-256 \
   --subject "/CN=Example DC2 Sub" \
   --ca-key 'pkcs11:token=fastpki;object=dc2-sub;type=private?pin-source=/var/pki/tls/pin' \
                                         > dc2-sub.csr        # step 2
```

The two steps that take a file — `sign-csr --csr` and `add --ca-pem` — read it inside the pod,
so feed it on stdin and land it there first. Note `exec -i`, without which the pipe is silently
empty:

```bash
kubectl exec -i -n "$NS" statefulset/fastpki-node -c web -- sh -c \
  'cat > /tmp/in.csr && fastpki-ca --config /app/config/bootstrap.conf \
     sign-csr root-ca --csr /tmp/in.csr --days 1825' < dc2-sub.csr > dc2-sub.crt   # step 3

kubectl exec -i -n "$NS" statefulset/fastpki-node -c web -- sh -c \
  'cat > /tmp/in.crt && fastpki-ca --config /app/config/bootstrap.conf \
     add root-ca --name "Example Root" --ca-pem /tmp/in.crt' < root-ca.crt         # step 4
```

**Connecting the clusters: `deploy/mesh-join.sh`.** The same command as §9.0 step 3, run from
a machine that has `kubectl` access to every cluster, one context per cluster. Each data center
is written `k8s:<context>/<namespace>`:

```bash
cd ~/FastPKI
deploy/mesh-join.sh k8s:dc1/fastpki k8s:dc2/fastpki
```

It reads each cluster's data center number, its `PG_INTERCONNECT` addresses and its database
password from the cluster, and runs every step against the server that holds the read-write
database. It finds that server by asking each server pod, so after a promotion it is
`fastpki-node-1`. It gives each Postgres the topology with the trust-anchor path of its own
container, `/pki/tls/pg/ca.crt`. A cluster that is a pair has two addresses in
`PG_INTERCONNECT`, and its peers are given both.

The first run stops for the CAs, exactly as on compose. Create them with the `ca` shorthand
above (§9.1 steps 1 to 4), then run the same command again. Measured on two single-node k3s
clusters: the first run stopped in 4 seconds; the second issued both database certificates,
subscribed each cluster to the other and finished in 1 minute 23 seconds:

```
mesh-join: data center 1: k8s:dc1/fastpki (k8s), database at 192.0.2.10
mesh-join: data center 2: k8s:dc2/fastpki (k8s), database at 198.51.100.10
mesh-join: pass 1 done: every data center knows the others and publishes
mesh-join: data center 1: PG_TLS_CA_ID=dc1-sub
mesh-join: data center 1: database certificate issued
mesh-join: data center 2: PG_TLS_CA_ID=dc2-sub
mesh-join: data center 2: database certificate issued
mesh-join: waiting 65 seconds for Postgres to take up the new certificates
mesh-join: pass 2 done: every data center subscribes to every other
mesh-join: done: every data center holds 13 certificates, and each is subscribed to the other
```

⚠️ **The interconnect port must not face the public internet.** The replication stream
carries `web_users` PBKDF2 password hashes and the per-user enrolment secrets in `keys`, and
every peer's database password travels in the conninfo that opens it. Peer the clusters
privately and restrict the Service further with `loadBalancerSourceRanges` or a
NetworkPolicy.

#### The other servers' names must resolve inside the cluster

⚠️ The subscription is opened by the **Postgres pod**, so the `host=` in the topology is
resolved by the cluster's DNS — not by the node's. Configuring the node's resolver is not
enough: `CREATE SUBSCRIPTION` fails with

```
could not connect to the publisher: could not translate host name
  "pki-node2.example.com" to address: Name does not resolve
```

and, because the statement errors, no subscription is created at all — so a re-run of pass 2
is needed after fixing it, not just a wait.

If the peers' names come from a DNS server the cluster does not already use, give CoreDNS
that zone. k3s's Corefile carries `import /etc/coredns/custom/*.server`, so a ConfigMap is
enough:

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
      forward . 192.0.2.53      # the site's DNS server
    }
```

Then `kubectl -n kube-system rollout restart deploy/coredns`. The same names appear in every
certificate's CRL and AIA URLs, so anything in-cluster that fetches them needs this too.

#### The paths differ between the application containers and Postgres

⚠️ `sslrootcert` in the topology is **`/pki/tls/pg/ca.crt`**, not `/var/pki/...`. The
application containers mount each server's `pki` claim at `/var/pki`, but its postgres container
mounts it at `/pki` — and the subscription is opened by the Postgres server, so the path is
resolved in *that* container. The same asymmetry exists under compose and is the same one-character class of
mistake that produced `root certificate file does not exist` with every mesh command still
reporting success.

#### Confirming it

Compare the clusters, not the subscription views — those report healthy even when a cluster
is short of rows:

```bash
kubectl exec -n "$NAMESPACE" fastpki-node-0 -c postgres -- \
  psql -U fastpki -d fastpki -tAc 'select count(*) from certs'   # must match everywhere
```


### 9.4 Growing one server into several data centers

A deployment that starts as one node can become data center 1 of a mesh later. No certificate
becomes invalid and the serial history needs nothing done to it, but the conversion has a few
steps the installer does not do for you.

⚠️ **The CA certificates this node already holds name only this node, and joining peers does not
change that.** CRLDP and AIA entries are built when a certificate is issued, one per row in the
`datacenters` table, so a CA created while this was the only data center carries one URL — and
after the conversion a relying party that cannot reach this node has nowhere else to look for
its CRL. Leaves are unaffected, because issuance derives their URLs afresh every time, so the
symptom is narrow: everything verifies until this node is the one that is down.

Closing this means **renewing** each affected CA once the peers' `datacenters` rows exist (admin
guide §3.8); the renewal can keep the current key, and the old certificate stays live until it
expires. Whether that is worth doing is a judgement about how much the fallback matters to your
relying parties.

⚠️ **Read the certificate to find out, not `ca urls`.** That subcommand prints what a certificate
issued now would carry, so it lists every data center even for a CA whose own certificate names
only this one:

```bash
ca show dc1-sub --pem --out /hosttmp/dc1-sub.crt
openssl x509 -in /tmp/dc1-sub.crt -noout -text | grep -cE 'URI:http'
```

Two URIs on a three-data-center mesh — one caIssuers, one CRL DP, both naming this node — is a
CA created before the map. Six is one created after.

#### Every installer already made it data center 1

**A single node is deployed as data center 1, not as "no data center"** — all three installers
write `DATACENTER_ID=1` and register the `datacenters` row whether or not a mesh is planned.
Everything the FastPKI binaries issue therefore carries the `0001` serial prefix from the first
certificate, and expanding later requires no correction: the history is already inside this node's
partition.

⚠️ With one exception, which is harmless and worth naming rather than discovering. The
self-signed Postgres pair `certgen.sh` generates — so the database can serve TLS before any
CA exists — is made by `openssl` in a shell script that runs *before* the database, and
therefore before anything knows a data center id. Its serial is 16 bytes and carries no
prefix. It replicates to peers normally, because the guard is origin-only, and §9.1 step 5
replaces it with a CA-issued certificate. The only place it would ever be refused is a local
restore, which is why `db-restore-online.sh` replays under `session_replication_role=replica`.
The listeners are not seeded here: each self-signs at first start, and §4.4a's
`renew-service-certs --re-issue-self-signed` is what promotes them.

That is why the conversion below is short. Without an id, `set_random_serial()` assigns
**full-width serials with no prefix**, and every certificate issued before a later expansion
sits outside the node's partition forever — so the guarantee that two data centers can never
assign the same serial would hold only from the conversion onward. `certs_dc_range` also
refuses a prefix-less row on any **local** insert, which is what a database restore is. The
prefix costs 16 bits of a 160-bit serial: 144 bits of entropy against the CA/Browser Forum's
64-bit floor, and nothing reads it until a second data center exists.

⚠️ **Prefix-less rows already in the database are safe.** `certs_dc_range` is an **origin**
trigger — not `ENABLE REPLICA TRIGGER`, unlike the skip-dup triggers beside it — so it judges
what this node issues and never what arrives from a peer. Those rows replicate to new data
centers untouched, and a collision would be absorbed by `certs_skip_dup` rather than stalling
an apply worker. The one place it shows is a local restore of that history onto a meshed
node, which is why `db-restore-online.sh` replays under `session_replication_role=replica`.

#### On the server you already have — make it data center 1

`docker compose` shown; the native equivalents are the same values in
`/etc/fastpki/bootstrap.conf`.

```bash
cd deploy
# 1. Identity and interconnect. env_file injects the whole .env into every container.
#    DATACENTER_ID is already there — every installer writes it, as above — so check
#    rather than append, or .env ends up with the key twice.
grep -q '^DATACENTER_ID=' .env || printf 'DATACENTER_ID=1\n' >> .env
sed -i 's/^PG_BIND=.*/PG_BIND=192.0.2.10/' .env      # was 127.0.0.1; peers dial this

# 2. Its own row, or every issuing service refuses to start.
docker compose exec -T postgres psql -U fastpki -d fastpki -v ON_ERROR_STOP=1 \
  -c "INSERT INTO datacenters(dc_id, serial_prefix) VALUES('1', 1)
        ON CONFLICT (dc_id) DO UPDATE SET serial_prefix=EXCLUDED.serial_prefix;"

# 3. Recreate the containers so the new .env reaches them, and republish Postgres.
docker compose up -d
```

Then give it a sub CA it can sign with, if it has only a root, and re-issue its database
certificate so the certificate carries the interconnect address:

```bash
docker compose run --rm --no-deps --entrypoint fastpki-ca web \
  --config /app/config/bootstrap.conf pg-tls dc1-sub
#   names:  postgres, localhost, 127.0.0.1, <this node's PKI_DNS>, 192.0.2.10
```

⚠️ **Leave `PG_TLS_SANS` empty.** `pg-tls` takes the interconnect address from this node's
own `PG_BIND`, which is per-node in compose, and prints every name it certified — read that
output rather than setting anything. `PG_TLS_SANS` is read from the `config` table, which is
node-local in a mesh but shared by the two hosts of an HA pair, so an address recorded there
becomes a name on the other host's certificate and leaves that host's own address out. Use
it only for extra names beyond the ones above. If the interconnect address is missing from
that list, this node's `PG_BIND` is still `127.0.0.1`: correct it and re-issue.

#### On each new server

**Every node is installed the same way** — the same `install.sh`, answering `cluster`, with
only three answers changed per node: `DC_INDEX` (its own index, which becomes its serial
prefix), `PKI_DNS` (its own FQDN) and `PG_BIND` (its own interconnect address). There is no
total to keep in step. There is no separate "joining node" mode, and
nothing about node 1 makes it special beyond holding the root key.

Then §9.1 steps 2–5 unchanged: generate its sub CA key in its own token, have data center 1 sign
the CSR with the **existing** root, register the anchor and the sub CA, and issue its
database certificate. The root you already have is the mesh root; there is no second one to
create.

Finally rewrite the topology file with the new line (§9.1 step 8) and apply it (§9.1 step 9)
on **every** node including the original, then confirm they hold the same data by comparing row counts
across nodes (§9.2).

#### Growing again later

The same procedure, and **nothing about the existing nodes changes**. No count was ever
recorded, so there is no ceiling to raise: the serial prefix is 2 octets whether the mesh has
two data centers or two hundred. Install the new node with the next free index, rewrite the
topology file with the extra line, and re-run both passes everywhere.

#### On Kubernetes it is a re-apply

Set `DC_INDEX` and `PG_INTERCONNECT` in `env.sh` and run `apply.sh` again. It
rewrites the ConfigMap, rolls the pods so they actually read it, registers the
`datacenters` row and creates the interconnect Service. Re-running is safe: it reuses the
token PIN already in the namespace's Secret rather than generating one the existing token
cannot open.

### 9.5 Removing a data center from the mesh

`fastpki-mesh --leave` emits the SQL. Shrinking is not the reverse of §9.4, and the
asymmetry is why it needs its own command: a subscription owns a **replication slot on the
other node**, and `DROP SUBSCRIPTION` is what frees it — by connecting to that node. So
removing a data center is two different statements in two different places, and the command
prints both:

```bash
# from deploy/, where the topology file sits. The id is the digits the installers write.
docker compose run --rm --no-deps --user 0:0 -v "$PWD/topology:/topology:ro" \
    --entrypoint fastpki-mesh web --topology /topology --node 3 --leave > leave-dc3.sql

# native or cloud
fastpki-mesh --topology /root/topology --node 3 --leave > leave-dc3.sql
```

⚠️ **Do not pipe that into one `psql`.** Like `--all`, the sections are for different
nodes; each says which one it belongs to. Run them while every node is still **reachable** —
that is what lets each drop free its slot on the far end.

The generated file has three kinds of section:

- **on the node leaving** — `DROP SUBSCRIPTION sub_<leaver>_from_<peer>` for each peer,
  which frees the leaver's slot on each of them;
- **on each node that stays** — `DROP SUBSCRIPTION sub_<peer>_from_<leaver>`, which frees
  that peer's slot on the leaver;
- **on the node leaving, last** — a guarded `pg_drop_replication_slot()` for anything a
  peer left behind, skipped while a slot is still active.

Each drop reports what it cleaned up at the far end:

```
NOTICE:  dropped replication slot "sub_2_from_1" on publisher
DROP SUBSCRIPTION
```

Confirm on every node that remains:

```bash
docker compose exec postgres psql -U fastpki -d fastpki -c "
  SELECT count(*) AS subs FROM pg_subscription;
  SELECT count(*) AS slots FROM pg_replication_slots;"
```

Both are `0` on a node that is now standalone; a node still in a smaller mesh keeps one of
each per remaining peer.

⚠️ **Skipping the "nodes that stay" half is the expensive mistake.** Every survivor then
holds a slot for a consumer that never returns, and a slot pins WAL *and* the transaction
horizon. `max_slot_wal_keep_size` (`high-availability.md` §4, Step 1) is the only thing between that and a full volume —
past the cap the slot is invalidated instead, which is the visible failure you want rather
than the silent one.

**If the node is already gone**, its peers' `DROP SUBSCRIPTION` blocks trying to reach it.
The generated file carries the escape as a comment in each peer's section:

```sql
ALTER SUBSCRIPTION sub_1_from_3 DISABLE;
ALTER SUBSCRIPTION sub_1_from_3 SET (slot_name = NONE);
DROP SUBSCRIPTION sub_1_from_3;
```

With no `--node`, `--leave` dissolves the **whole** mesh — every node's section, which is
how a test deployment is taken apart.

Finally, a departed node keeps its data **and its data-center index**. It still assigns
serials under that prefix, so reusing the index for a different node later produces two data
centers issuing the same serials.

Bringing a data center back from a dump of its own database is not a leave and a rejoin:
`fastpki-mesh --restore` does it, in the order [`postgres.md`](postgres.md) §6.3
gives.
### 9.6 When a data center does not catch up

Work in this order. Each step's failure has one cause, and checking them out of order
produces the wrong conclusion — a certificate fault and an authentication fault both
surface as "could not connect to the publisher".

#### The two queries

```bash
# 1. THE VERDICT: run on every node, the counts must be identical.
docker compose exec -T postgres psql -U fastpki -d fastpki -tAc "select count(*) from certs"

# 2. THE MECHANISM: N-1 rows on an N-node mesh, every one connected = t.
docker compose exec -T postgres psql -U fastpki -d fastpki -tAc \
  "select s.subname, (r.pid is not null) as connected, r.latest_end_lsn
     from pg_subscription s
     left join pg_stat_subscription r on r.subname = s.subname order by 1"
```

Query 1 is the one that decides. Query 2 has reported six healthy subscriptions on a mesh
missing a third of its rows (§9.2), so a green subscription view does not prove they hold the same data.

#### A subscription is missing entirely

Count the rows of query 2 before reading them: a 3-node mesh needs **six** subscriptions,
two per node, named `sub_<this node>_from_<peer>`. Missing ones are the most common mesh
fault and the easiest to overlook, because the ones that exist are all healthy.

`CREATE SUBSCRIPTION` with `connect = true` is **all-or-nothing**: it validates the
connection, and on failure creates nothing at all. So a node whose certificate was briefly
unusable does not end up with a broken subscription to repair — it ends up with no
subscription, and no trace in `pg_subscription` that one was ever attempted. Fix the
underlying cause first, then create the missing subscription by hand:

```bash
cd deploy
read -rs -p "peer db password: " PWP; echo
docker compose exec -T postgres psql -U fastpki -d fastpki -v ON_ERROR_STOP=1 <<SQL
CREATE SUBSCRIPTION sub_1_from_3
  CONNECTION 'host=203.0.113.10 port=5432 dbname=fastpki user=fastpki password=$PWP sslmode=verify-full sslrootcert=/pki/tls/pg/ca.crt'
  PUBLICATION fastpki_pub
  WITH (origin = none, failover = true, copy_data = true);
SQL
unset PWP
```

The peer's database password is not in its `.env`; read it on that peer with

```bash
docker inspect fastpki-postgres-1 \
  --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^POSTGRES_PASSWORD=//p'
```

⚠️ **`failover = true` is not optional.** It marks the publisher-side slot as one a physical
standby must synchronise. Without it `sync_replication_slots` ignores the slot silently:
both sides report healthy, and the data center leaves the mesh one promote later.
`origin = none` and `copy_data = true` are equally load-bearing — they are what make seeding
from every peer safe (§9.2). The `WARNING: ... copy_data with origin = NONE but might copy
data that had a different origin` this raises is **expected and correct here**; the skip-dup
and last-writer-wins triggers exist precisely for it.

If the peer instead reports that the replication slot already exists, a previous attempt
died between creating the slot and recording the subscription. Drop the orphan **on the
publisher** — `select pg_drop_replication_slot('sub_1_from_3')` — then create it again.

#### `could not find digest for NID UNDEF`

The publisher's Postgres certificate is signed with **Ed25519, Ed448 or ML-DSA**. Those are
one-shot signature schemes that carry no separate digest, and RFC 5929
`tls-server-end-point` channel binding must hash the server certificate with the digest its
signature algorithm names. libpq looks it up, gets `NID_undef`, and refuses **before
authentication**. Channel binding is negotiated by default, so this is not specific to
replication: every new libpq connection to that database fails, including the node's own
services.

It is easy to misread as healthy, because established connections are unaffected — the node
keeps serving on the connections it already had and only fails to accept new ones.

Confirm it in one command, on the publisher:

```bash
sudo openssl x509 -in /var/lib/docker/volumes/fastpki_pki-data/_data/tls/pg/server.crt \
  -noout -text | grep -m1 'Signature Algorithm'
```

`ED25519`, `ED448` or `ML-DSA-*` is the fault. `sha256WithRSAEncryption`, `rsassaPss` or
`ecdsa-with-SHA*` are all fine.

**Fix:** re-issue that node's Postgres certificate from a CA whose key is **EC or RSA**
(`compatibility.md` §4.1 covers why, and what else this algorithm choice affects). The
signing CA's key decides the leaf's signature algorithm, so a node whose sub CA holds an
Ed448 key cannot produce a usable database certificate at all — renew that sub CA with an EC or
RSA key, or issue from another. `fastpki-ca pg-tls` and the console refuse this up front rather
than writing a certificate nothing can connect to.

Do **not** work around it with `channel_binding=disable` in the conninfo. It does work, and
it silently drops an authentication protection for every connection on that link.

#### `certificate verify failed`

The publisher's certificate does not chain to this node's `pg/ca.crt`, or does not carry
the address you dialled. Check the chain the way a client sees it, from a container that
has openssl — the `postgres` image does not:

```bash
docker exec fastpki-web-1 sh -c \
  "openssl s_client -connect <peer-address>:5432 -starttls postgres \
     -CAfile /var/pki/tls/pg/ca.crt -verify_return_error </dev/null 2>&1 \
   | grep -E 'Verification|Verify return code'"
```

`Verify return code: 0 (ok)` means the transport is fine and the fault is elsewhere.

⚠️ Do not diagnose this with `openssl verify -CAfile ca.crt server.crt`. That command reads
only the **first** certificate out of the file it is given, so the sub CA sitting right
after the leaf in `server.crt` is ignored and a perfectly good chain reports
`error 20 ... unable to get local issuer certificate`. Pass the intermediates explicitly:

```bash
openssl verify -CAfile .../pg/ca.crt -untrusted .../pg/server.crt .../pg/server.crt
```

A TLS client never has this problem, because the server sends its intermediates.

#### `password authentication failed for user "fastpki"`

The conninfo carries the wrong peer's password. Each node has its own; there is no shared
one. Re-read it on the publisher with the `docker inspect` command above, and note that
`ALTER SUBSCRIPTION ... CONNECTION` is how you correct an existing subscription rather than
dropping and recreating it.

#### `publication "fastpki_pub" does not exist`

The subscriber's Postgres log repeats this every five seconds, always at the same LSN:

```
ERROR:  could not receive data from WAL stream: ERROR:  publication "fastpki_pub" does not exist
CONTEXT:  slot "sub_1_from_2", output plugin "pgoutput", in the change callback, associated LSN 0/21D1A10
```

The console's node status reports the same fault from the outside: the subscription "has no
running apply worker", and its apply error count keeps rising.

It means this node subscribed to a peer that had not yet published. In this example data
center 1 ran pass 2 (`--node 1`) while data center 2 had run `--map` but never
`--publication`. `CREATE SUBSCRIPTION` only prints a warning when the publication is
missing, so pass 2 looked successful. `fastpki-mesh --node` checks every peer it can reach
and refuses in this case, so it happens only when the check was skipped: `--no-preflight`,
or a peer that could not be read at that moment.

Creating the publication now does **not** fix it. The subscription's replication slot on the
peer starts before the publication existed, and PostgreSQL 17 checks each change against the
publications that existed when that change was written. So every retry fails at the same
LSN, for good. Measured: after the peer published, the next attempts still failed at
`0/21D1A10`. The subscription has to be dropped and created again.

Here `psql` stands for the command that reaches Postgres on that node:

| Path | `psql` is |
|---|---|
| Compose | `docker compose exec -T postgres psql -U fastpki -d fastpki` |
| Native and cloud | `doas su postgres -s /bin/sh -c 'psql -U fastpki -d fastpki'` |
| Kubernetes | `kubectl exec -i -n fastpki fastpki-node-0 -c postgres -- psql -U fastpki -d fastpki`, naming the primary pod, which is `fastpki-node-1` after a standby has taken over |

```bash
# 1. On the peer (data center 2): pass 1, both halves.
fastpki-mesh --topology topology --map         | psql -q -v ON_ERROR_STOP=1
fastpki-mesh --topology topology --publication | psql -q -v ON_ERROR_STOP=1

# 2. On this node (data center 1): drop the broken subscription.
#    It connects to the peer and removes the replication slot there too.
psql -c 'DROP SUBSCRIPTION sub_1_from_2'

# 3. On this node: pass 2 again.
fastpki-mesh --topology topology --node 1      | psql -q -v ON_ERROR_STOP=1
```

Step 2 prints `NOTICE:  dropped replication slot "sub_1_from_2" on publisher`, and step 3
prints `NOTICE:  created replication slot "sub_1_from_2" on publisher`. Then run query 2
above: the subscription shows `connected = t`. Run query 1 on both nodes: the counts match.

#### Connected, but rows still do not match

The subscription is up and the initial copy is stuck or incomplete. Ask what state each
table is in — `r` is ready, `i`/`d`/`s` are mid-copy:

```bash
docker compose exec -T postgres psql -U fastpki -d fastpki -tAc \
  "select s.subname, c.relname, r.srsubstate
     from pg_subscription_rel r
     join pg_subscription s on s.oid = r.srsubid
     join pg_class c on c.oid = r.srrelid
    where r.srsubstate <> 'r' order by 1, 2"
```

Nothing returned means every table finished copying. If a table is stuck, the apply worker
is usually blocked on a constraint or a jammed trigger; `docker compose logs postgres` on
the **subscriber** names it. A publication that is short of tables is the other cause —
`select count(*) from pg_publication_tables where pubname = 'fastpki_pub'` must report the
same number on every node.

### 9.7 Addresses: one name for everything, or one per data center

A mesh replicates **data**, not the ability to sign. Each node has its own sub CA because
its signing key lives in that node's token (§9.1), and a node asked to issue from a CA whose
key it does not hold refuses:

```
no signing key for this CA on this node
```

That single fact decides how clients should address the deployment, and there are two
supported shapes. The cloud modules take `pki_dns` as either one name or one per node, so
the choice is made in the tfvars rather than in code.

**One name per node — the default, and the one to pick unless you decide otherwise.**
Every data center is separately addressable. A client enrolling against `dc2-sub` sends its
request to the node that holds that key, and nothing depends on where DNS points it. No key
material ever leaves the token it was generated in, so compromising one node exposes one
data center's CA.

**One name, round-robined across every node.** The nodes become interchangeable, which is
the more convenient shape for clients: one URL, no knowledge of which data center holds
what. It is correct **only if every node can sign with the CA a client asks for** — which
means the CA key is reachable from all of them. Two ways to get there:

- a **network or clustered HSM**: every node loads the same `PKCS11_MODULE` and the key
  lives in the appliance, so no copy exists on any node;
- the key **present in each node's token**, replicated there over `P11_TLS` (the `key replicate` command later in this section). Each node
  registers its own token's handle as that CA's signing key; there is no cross-host key list,
  because every candidate a node tries is opened through the one PKCS#11 module that node's
  processes have.

⚠️ **No node ever signs through another node's token.** That arrangement stops every node
signing when the token host is lost, and certificates issued under its key can never
afterwards be renewed or revoked — the opposite of what a mesh is for.
Nothing in the product prevents a shared signing key, and three things that look like they
would, do not:

| | |
|---|---|
| **Serial collisions** | The serial prefix is the **node's**, not the CA's — high bits from `DATACENTER_ID`, low bits from a local sequence. Two nodes signing with one CA use disjoint serial ranges, so RFC 5280's per-issuer uniqueness holds without coordination. |
| **CRL numbers** | `crlNumber` is the issuance time, not a shared counter, so two signers cannot collide on one. This does assume the nodes' clocks agree — skew is the one thing that can make it non-monotonic. |
| **Ownership checks** | There are none. Issuance is gated on whether the key resolves, not on which data center the CA "belongs" to. |

⚠️ **What it costs is blast radius.** With a key per node, compromising a node exposes that
data center's CA. With one key present on every node, compromising any node exposes every CA
that key signs for — the node holds the PIN and a path to the token, which is all that
issuing needs. So a shared key is opt-in: a CA is only ever replicable if it was created
that way.

⚠️ **An HA pair is the exception, and there every CA is replicable — the root included.**
The trade-off above weighs one data center's blast radius against another's. A pair is not
two data centers: it is one, twice, and it exists to survive losing a host. A CA whose key
sits on only one of the two is the failure the second host exists to prevent, and
because `CKA_EXTRACTABLE` is fixed at generation there is no way to grant it later — a root
created without it is unrecoverable the moment its host is, and the survivor can never
create another sub CA. Create both the root and the issuing CA with `--replicable` (in the
console, **replicable key**) and replicate each of them. `high-availability.md` is the design record for the pair.

##### Replicating a CA key to another node

The key is wrapped inside the source node's token and unwrapped inside the destination's, so
it never exists in plaintext outside either. Both nodes need `P11_TLS=on`, and the mesh
distributes the trust the tunnel needs.

This works on an HA pair as well as a mesh: `p11_transport` is keyed per host, so a data
center holding two of them — a primary and its standby — has room for both, and each
publishes under its own name. A standby carries the **same** `DATACENTER_ID` as its primary,
because a pair is one data center twice; it is not left unset, and it does not get one of its
own. `high-availability.md` §3 covers that case.

**1. Create the CA so that it can be replicated.** This is the only moment the choice
exists — PKCS#11 fixes `CKA_EXTRACTABLE` when a key is generated and does not allow granting
it afterwards:

```bash
docker compose exec web fastpki-ca create shared-sub --name "Shared Sub CA" \
    --ca-key 'pkcs11:token=fastpki;object=shared-sub;type=private?pin-source=/var/pki/tls/pin' \
    --keygen --key ec --replicable --parent root-ca
```

**2. On each node that needs it,** once the CA row has replicated there:

```bash
docker compose exec web fastpki-ca key replicate shared-sub --from <peer-host>:12345 \
    --source-pin-file /var/pki/tls/srcpin
```

It raises the tunnel for the operation, wraps in the peer's token, unwraps into this node's,
checks the result against the CA's certificate, and only then registers the handle. That
node can now issue, renew and revoke under that CA with no dependency on the peer.

⚠️ **`--source-pin-file` holds the peer's token PIN, and you almost always need it.** The
wrap happens inside the source token, so this command logs in to the peer's token, not to
this node's — and every installer generates each node's `FASTPKI_PIN` independently, so the
two differ. Without it the command falls back to this node's PIN and the login fails inside
the peer's token. Put the peer's PIN in a file this node can read and name it here. Omit the
flag only where both nodes deliberately share one PIN.

⚠️ **The tunnel's peer trust has to be in place on both sides first, and on a freshly meshed
deployment it has not.** Each node publishes its own transport certificates into
`p11_transport` and materialises its peers' from there, but it does that when
`fastpki-p11-tls` starts and in the daily renewal job — so a node meshed minutes ago still
trusts only itself, and this command fails with `C_Initialize failed (rc=48)`
(`CKR_DEVICE_ERROR`), which names nothing useful. The cause is visible only in the peer's
log, as `tlsv1 alert unknown ca`. Complete both directions on **every** node before
replicating anything:

```bash
docker compose exec web fastpki-config --config /app/config/bootstrap.conf \
    p11-clients-sync                   # who may dial IN to this node's token
docker compose exec web fastpki-config --config /app/config/bootstrap.conf \
    p11-servers-sync                   # whose token this node may dial OUT to
```

`key replicate` prints each stage it reaches — raising the tunnel, reading the key-encryption
point, wrapping on the source, unwrapping here, registering — so a failure names the step it
stopped at.

⚠️ **A CA created without a replicable key refuses** (`--replicable`, or **replicable key**
in the console), naming the cause:

```
this CA's key was generated non-extractable, so it can never leave its token.
```

There is no way to convert one afterwards; the CA has to be re-created and what it signed
re-issued.

Whichever you choose, **it never matters which data center answers a revocation check**.
Revocation lists, OCSP and the certificate store all serve data every data center has, so any
of them gives the right answer. A DNS name that rotates between all of them is always safe
for those, and it is a separate name from the one clients enrol against.

⚠️ **Being able to sign everywhere is not enough for a protocol that takes more than one
request.** Sharing the key settles who can issue a certificate. It says nothing about a
protocol that remembers something between messages. What matters is how many requests one
enrolment takes, and with CMP that is the client's choice. Measured across three data
centers, ten enrolments each time, with a new name for each:

| | through one node | through the round-robin name |
|---|---|---|
| CMP, no implicit confirm | 10/10 | **5/10** |
| CMP, `-implicit_confirm` | 10/10 | **10/10** |

Without implicit confirmation, one enrolment is two exchanges: the client asks, the server
answers, then the client confirms and the server acknowledges. If that second exchange lands
on a different data center, it meets a server that has never heard of the transaction. With
implicit confirmation, the whole enrolment is a single request and reply, and in the
measurement above the work spread 4, 3 and 3 across the three data centers.

FastPKI always offers implicit confirmation, and the configuration file the console generates
already switches it on. But the client is the one that asks for it, so the server cannot
protect a client that does not.

In summary:

- **Safe behind one round-robin name** — EST (`simpleenroll` is one request; measured 10/10
  on both key types), OCSP, CRL, the RFC 4387 store (measured 10/10, 252 ops/s), and **CMP
  provided every client uses implicit confirmation**.
- **Not safe: ACME.** No client option fixes this one. The tables ACME uses to track a
  request in progress are deliberately never copied between data centers. The single-use
  tokens ACME relies on would otherwise be usable twice, which is exactly the attack they
  exist to prevent. So a token issued by one data center is permanently rejected by another,
  and an order started at one is permanently missing at the other. This is not a delay in
  copying, and waiting does not help. **If you offer ACME, give each data center its own
  name, or use a load balancer that keeps each client on one of them.**

Two things this is not about. It is not where the CA key lives: it applies equally to a
network HSM and to a key replicated into every node's token. And it is not about several
`fastpki-acme` processes inside one data center — those share that data center's database, so
a round-robin across them is fine; the problem is only crossing into another node's database.

## 10. TLS / reverse proxy

Keep OCSP/CMP/SCEP/store on loopback and front them with a reverse proxy.
**The proxy is your infrastructure — FastPKI neither ships nor requires one**;
`deploy/nginx.conf.example` is a worked example to start from.
EST, ACME, the Windows service **and the console** handle their own encryption. A proxy in
front of them has to encrypt the connection again on the way through, or, for EST with client
certificates, pass the traffic along untouched.

The console is HTTPS only. Browsers only allow the features it depends on —
generating a key in the browser, and choosing a slot in the key store — on a secure
connection. Serving it over plain HTTP quietly loses those features rather than merely being
unencrypted.

Set `BASE_URL=https://<your name>` so that ACME hands out the public address.

---

## 11. Day-2 operations

Running a deployment once it is installed — backups, updates, users, CAs, certificates and
every console page — is [`admin-guide.md`](admin-guide.md). The database —
backups, restores, schema changes and the table reference — is
[`postgres.md`](postgres.md). This section keeps only what is specific to rolling
a schema change across a mesh.

### 11.1 Schema changes during an update

`deploy/rolling-update.sh` and `deploy/k8s/apply.sh` **apply the schema step first**, and
abort the rollout if it fails. Nothing is rolled unless the database is ready for it.

Applying by hand, or on a mesh DC — **from `deploy/`**, because the `PSQL` wrapper runs
`docker compose`, which needs the compose file beside it:

```bash
cd deploy
PSQL="docker compose exec -T postgres psql -U fastpki -d fastpki" \
MESH_BIN="docker run --rm ${FASTPKI_IMAGE:-fastpki:local} fastpki-mesh" \
  ./schema-apply.sh
```

⚠️ **`MESH_BIN` is required on a server that belongs to several data centers**, and it is not
housekeeping. The script rebuilds the rules that decide what happens when two data centers
change the same row, and the program that writes those rules lives in the image, not on the
machine. Without it the run stops and tells you to set it.

Point it at the image you are updating **to**. An older program writes older rules, which
will not know about anything the new version added. `MESH_BIN="docker compose exec -T web
fastpki-mesh"` is only safe when the image is not changing. A server that is not part of
several data centers — a single deployment, or either half of a failover pair — says so and
carries on without it.

`schema-apply.sh --check` changes nothing in the schema: it lists what is waiting to be
applied and exits with an error if anything is. It is **not** read-only, though. Even with
nothing pending it rebuilds those same rules, so on a server that belongs to several data
centers it needs `MESH_BIN` as well, and fails without it.

Run it on **every** data center. Each database records its own schema version, and that
record is not copied between them.

⚠️ **An HA pair is the opposite case — apply it on the primary only.** A pair is one
database streamed byte-for-byte, not two databases exchanging rows, so the step and the
`schema_version` row it writes both arrive at the standby on their own. Measured on a pair:
the primary went 1 to 2 and the standby read 2, with the new column present, seconds later
and nothing run there.

Running it on the standby is a no-op at best and an error at worst, because a standby
accepts no writes:

```
ERROR:  cannot execute ALTER TABLE in a read-only transaction
```

If the step is already replicated the script finds nothing pending and exits 0, which looks
like success and did nothing. If it is not yet applied on the primary — the standby reached
first, in the wrong order — that is the error above, on a database that is perfectly
healthy. So: **mesh, every node; pair, the primary and let it stream.**

Each binary refuses to start against a schema older than it needs, naming the command to
run, rather than crash-looping later on a missing column. A **newer** schema is accepted:
during a rolling update the schema is expanded first and the binaries follow, so old
binaries legitimately run against the new schema for the length of the rollout.

---

## 12. Cloud deployment (AWS)

`deploy/cloud/` runs FastPKI on AWS. It has two parts. One builds a machine image: an Alpine
Linux disk with FastPKI and its key-storage software already installed. The other is OpenTofu
code that creates the network, the disks and one server per data center.

A cloud server is an ordinary native install (§7). Once the servers are running, the work is
the same as on any other host.

Do the steps in order. **Steps 1 to 5 run on your own computer. Steps 6 to 11 run on the
servers, and step 12 runs partly on each.** Each command block says which, because running a
server command on your own computer is the easiest mistake to make here.

Which steps you do depends on what you are building:

| Deployment | Steps |
|---|---|
| One server, no standby | 1 to 8. You are finished at step 8. |
| One data center with a standby | 1 to 9, then 12. |
| A mesh, with or without standbys | all of them. |

Steps marked **(mesh only)**, **(mesh or standby)** and **(standby only)** say so in their
headings.

**Hardware for one server**

| | |
|---|---|
| **CPU** | 2 vCPU. This is a `t3.micro`, and its load average sits at 0.00 with every service running |
| **Memory** | 239 MB used, out of the 924 MB the server has |
| **Disk** | two 1 GB volumes: 263.9 MB used on the system volume, 64.0 MB on the data volume |

The system volume's size comes from the machine image, not from the deployment. See
[`deploy/cloud/README.md`](../deploy/cloud/README.md) for how the image is built and what the
OpenTofu code creates. The same figures for the other three ways of running FastPKI are in
[`architecture.md`](architecture.md#11-resource-footprint) §11.

### Before you start

On the computer you work from, install `packer`, `opentofu`, the AWS command line tool and
Docker. Step 1 uses Docker to build the image in a container. Every local command below is
written to be run from the top of the repository.

Then four more things. The steps need all of them, and none of them are done for you.

**1. AWS credentials in a named profile**, so this deployment stays clear of any other
account you use:

```bash
aws configure --profile fastpki      # key id, secret, region, output=json
aws sts get-caller-identity --profile fastpki
export AWS_PROFILE=fastpki           # packer and tofu read it the same way
```

Create the first access key in the AWS console: IAM → Users → create a user → Security
credentials → Create access key (CLI). Give the user `AdministratorAccess`. It needs that
much because the deployment creates a network, subnets, a gateway, firewall rules, network
interfaces, disks, servers and, if you ask for them, DNS records.

Write down the account number that `get-caller-identity` prints. Step 3 asks for it. Once it
is set, the deployment refuses to touch any other AWS account, so a wrong profile cannot
create servers somewhere you did not expect.

**2. An SSH key pair.** It has to exist before step 3 runs. Create it from the command line.
If you create it in the AWS console instead, you get a one-time download, and AWS never shows
you the private key again:

```bash
aws ec2 create-key-pair --region us-east-1 --key-name fastpki-cloud \
    --key-type ed25519 --query KeyMaterial --output text > /tmp/fastpki-cloud.pem
install -m 600 /tmp/fastpki-cloud.pem ~/.ssh/fastpki_cloud_ed25519 && rm -f /tmp/fastpki-cloud.pem
```

⚠️ Write the key to a temporary file first, then move it, exactly as above. Writing straight
to the final path empties that file before the command runs. If the command then fails, you
have destroyed a key you already had.

You log in to a server as the user `alpine`.

**3. Packer's plugins.** `packer build` does not download them for you:

```bash
packer init deploy/cloud/image
```

**4. The server types this account is allowed to start.** List them before you build
anything:

```bash
aws ec2 describe-instance-types --filters Name=free-tier-eligible,Values=true \
    --query 'InstanceTypes[].InstanceType' --output text
```

⚠️ **On the AWS free plan, nothing outside that list will start.** AWS refuses within
seconds:

```
InvalidParameterCombination: The specified instance type is not eligible for Free Tier
```

That stops the default build server (`c7g.2xlarge`) in step 2, and the default deployment
server (`t4g.medium`) in step 3. Decide which way you are going now, because the two use
different processor types and you cannot mix them:

- **Paid plan.** Keep the defaults. Your signup credit still pays for usage. The image is
  built on a `c7g.2xlarge`, which has 8 processors instead of the free plan's 2.
- **Free plan.** Use Intel processors everywhere. The free types have 2 processors, and the
  ones with enough memory to build on are Intel. Build the image on an `m7i-flex.large` and
  run the servers on `t3.micro`. Add these to the build in step 2:

  ```bash
  -var 'instance_type=m7i-flex.large' -var 'source_ami_arch=x86_64'
  ```

  Then give step 3 an Intel server type as well. An Intel image will not start on a `t4g.*`
  server, and you only find out at the end of step 3, after the image is built.

### Step 1 — prove the image builds, without AWS

```bash
sh deploy/native/build-check.sh              # build the current code in a throwaway container
sh deploy/native/build-check.sh --ref v1.0.0 # a specific ref
sh deploy/native/build-check.sh --keep       # leave the container to inspect
```

This builds FastPKI in a container on your own computer, using the same script the AWS build
uses. Most build problems show up here: a compile error, a patch that no longer applies, or
the key-storage software failing its self-test. Finding one here takes a few minutes.
Finding it in AWS takes fifteen and costs you a server-hour. Run this after every change.

A container cannot tell you whether the image starts up. Two more commands do that, again on
your own computer:

```bash
deploy/cloud/image/build-qemu.sh     # the same provision.sh, as a bootable qcow2
deploy/cloud/boot-check.sh           # boot it and assert the first-boot path
```

These two need `qemu-system-x86_64`, `packer`, UEFI firmware (the `ovmf` package on Debian
and Ubuntu) and your user in the `kvm` group. Run them on a real Linux machine. Inside a
virtual machine the build loses the processor features it needs, and it will not finish.

### Step 2 — build the machine image

```bash
packer build -only=fastpki.amazon-ebs.alpine -var 'release=1.2.3' deploy/cloud/image
```

- `release` can be any label you like. It becomes part of the image name
  (`fastpki-<release>-alpine<version>-<processor>`). A commit id works well when you are not
  making a release.
- If you have changes you have not committed, add `-var 'source_ref=<commit or tag>'`. The
  build takes its files from git, and it stops rather than quietly building without your
  changes.
- On the free plan, add the two settings from **Before you start**, item 4.
- The build takes about 15 minutes on an `m7i-flex.large`. It prints the image id at the end.
  Keep that id: step 3 asks for one. If you leave the answer empty, step 3 picks the newest
  FastPKI image your account owns.

### Step 3 — create the deployment

```bash
deploy/cloud/cloud-install.sh
```

The script asks you a series of questions, saves the answers in
`deploy/cloud/aws/terraform.tfvars`, shows you what it is about to create, and creates it
once you confirm.

It asks for: a name for the deployment, the AWS region, the number of data centers, which of
them get a standby, the server type, the image id from step 2, the name of your SSH key pair,
the size of the data disk, the public name of each server, which enrolment protocols to run,
where to keep the CA keys, the port for the web console, whether the servers get public IPv4
addresses, a Route 53 zone (optional), who may reach the enrolment protocols, who may reach
the console (this one has no default and you must answer it), and the AWS account number from
**Before you start**.

Three answers matter more than the rest:

- **Number of data centers.** One run creates all of them. Each server goes in a different
  availability zone and gets a number, 1 upwards, which it puts in the serial number of every
  certificate it issues. If the region has fewer zones than you asked for, nothing is
  created. To add servers one at a time instead, use §3.1 or §7.

  ⚠️ **This counts data centers, not machines.** Answering 2 gives you two data centers with
  one server each, not two servers that cover for each other.
- **Which data centers get a standby.** A standby is a second machine in the same data
  center. It streams the first one's database and takes over if that machine is lost.
  Answer `1` to give data center 1 a standby, `1,2` for both, or leave it blank for none.

  The installer creates the machine, its disks and its addresses. Joining it to the primary
  is one command from your own machine, `deploy/ha-join-pair.sh`, once the CAs exist
  (`high-availability.md` §4). The `standby_join` output prints it with your addresses.

  A pair also needs one shared address that moves between the two machines, so a failover
  changes nothing outside. Step 4 makes it, before you publish any DNS.

  ⚠️ **A standby can only ever hold a CA key that was created `--replicable`**, and that
  cannot be granted afterwards. Step 7 is where you decide it, for good. The copying itself
  is set up for you: both servers of a data center with a standby are installed with the key
  tunnel (`P11_TLS`) on, and its port is open between them.
- **Console port.** Answer `443` and the console address needs no port number in it. Any
  other answer has to be typed into every browser that ever opens the console.
- **Public IPv4 addresses.** Answer no and the servers are reachable over IPv6 only. AWS
  charges $0.005 an hour for each public IPv4 address, and nothing for IPv6. Answer no only
  if everyone who needs these servers has IPv6: administrators, enrolment clients, and
  anything that checks a certificate against the revocation list.

When it has finished, read the values it printed. The rest of this section uses them:

```bash
tofu -chdir=deploy/cloud/aws output   # console_urls, node_public_ipv6, node_interconnect_ips, mesh_join, standby_join
```

`-chdir` keeps you at the repository root, which is where every other command here expects to
be run from.

⚠️ **Leaving it out gets you `Warning: No outputs found`**, not an error about the directory.
Run from anywhere but `deploy/cloud/aws`, plain `tofu output` finds no state at all and says
the outputs are empty — which reads as though the deployment produced none. Every `tofu`
command in this section carries `-chdir` for that reason.

**Check that each server finished its first boot** before going on. From your own machine,
for each address in `node_public_ipv6`:

```bash
ssh -i <your ssh key> alpine@<address> doas cat /var/log/fastpki-firstboot.rc
```

It prints `0` when first boot configured the server. Any other number is the exit status of
the step that failed, and `/var/log/fastpki-firstboot.log` on that server says which step it
was. A server whose first boot failed still boots and answers SSH, but serves nothing, so this
file is the quickest way to tell. If the file does not exist yet, first boot is still
running: wait and ask again.

**The clock is set up for you.** A CA judges `notBefore`, `notAfter`, CRL `thisUpdate` and
`nextUpdate`, OCSP response times and every enrolling client's TLS handshake by its own
clock, and a certificate issued a few minutes fast is refused as not yet valid — by an error
that names the client. First boot points chrony at the Amazon Time Sync Service on
`fd00:ec2::123` and `169.254.169.123`, both of which answer from inside the VPC with no
route to the internet, so this works on a deployment with no public IPv4 addresses. Alpine's
own `pool.ntp.org` line stays as a fallback for a deployment that does have a route out.

Check it on a server with:

```bash
doas grep -i 'selected source' /var/log/messages | tail -2
```

⚠️ **Do not check it with `ping`.** Neither address answers ICMP, so a ping reports 100%
packet loss against a service that is working. `doas chronyd -Q -t 8 'server fd00:ec2::123
iburst'` asks the question properly and prints the offset it measured.

### Step 4 — publish the addresses in DNS

With `route53_zone_id` set the module publishes the records itself and you can skip to step
5. If you left it empty, publish the records yourself, wherever your domain is hosted. Get
the addresses with:

```bash
tofu -chdir=deploy/cloud/aws output node_public_ipv6   # or node_public_ips, with IPv4
```

Standbys are in that list too, keyed `1-standby` and so on. They are how you reach the
machine itself, for the join and for anything you do to it directly.

You only have to do this once. The addresses belong to the network cards, not to the servers,
so they survive stopping, starting and even replacing a server.

⚠️ **A data center with a standby needs one more address, and that is the one to publish —
not the primary's own.** Both machines answer on a single extra address that moves between
them, so when the standby takes over, nothing outside changes: no DNS edit, no waiting for a
cached record to expire, no client reconfigured. Make it before you publish anything, **on
your own computer**:

```bash
export AWS_PROFILE=fastpki        # the same profile as the rest of this section
deploy/cloud/aws-ha-address.sh create --deployment fastpki --node 1 \
    --ssh alpine@<the primary's own address> -i <your ssh key>
deploy/cloud/aws-ha-address.sh show   --deployment fastpki --node 1
```

`--ssh` is how the address reaches the machine. AWS routing it to an interface is only half
of it: until the address is on the interface the kernel answers nothing on it, and packets
arriving for it are dropped — which looks exactly like a security group problem and is not
one. With `--ssh`, `create` configures it there and installs a boot script, so the machine
takes the address again every time it starts. That script asks AWS at each boot whether the
address is still routed to this machine, and gives it up if it is not, so a machine that
returns after a failover does not claim an address the other one now holds.

Without `--ssh` the address is allocated in AWS and nothing answers on it. Run the same
command again with `--ssh` to finish.

The script takes `--profile` too. It needs one or the other: AWS credentials are ambient, so
a shell without a profile set reaches for the default one, and in another account there is
nothing of yours to find. It says which account it searched when it comes up empty.

`--deployment` is the deployment name you gave in step 3 — the word that prefixes every
resource this module made, `fastpki` unless you changed it. It is not a DNS name. If you are
not sure what you answered:

```bash
grep deployment_name deploy/cloud/aws/terraform.tfvars
```

`--node 1` is the data center the pair belongs to, so a pair in data center 2 would be
`--node 2`. Run `create` once per pair.

`create` prints an IPv6 address. That is what the DNS record for that data center points at:
if data center 1 answers to `dc1.example.org`, its **AAAA** record holds the address `create`
printed, not the one in `node_public_ipv6`. Each machine keeps its own address as well, and
you still use those to log in to a particular machine.

After a failover, `aws-ha-address.sh move` carries the shared address to the survivor —
[`high-availability.md`](high-availability.md) §4a has that, and why `keepalived` and a
virtual IP cannot work inside a VPC.

A data center with no standby publishes its machine's own address, as above.

⚠️ **Publish the records as plain DNS. Do not put them behind a CDN proxy.** A proxied record
gives out the CDN's address instead of your server's, and CDNs do not carry the ports FastPKI
uses. The console then times out, with nothing in any log to explain why. It also teaches the
browser that this name is always HTTPS with a valid certificate, which makes the warning in
step 5 impossible to click past.

⚠️ **With IPv6 only, checking websites will tell you the name does not resolve.** They ask
for IPv4 records by default, and there are none. Ask for **AAAA** records instead. Better,
ask the servers yourself:

```bash
dig @<your-nameserver> AAAA dc1.example.org +short   # authoritative, never cached
dig @1.1.1.1           AAAA dc1.example.org +short   # what a client actually gets
```

### Step 5 — open the console and change the admin password

This command prints one address per server, ready to paste into a browser:

```bash
tofu -chdir=deploy/cloud/aws output console_urls
```

Sign in as `admin` with the password `admin`, and set a new password straight away. Until you
do, the account can do nothing else — it cannot even issue a certificate.

⚠️ **The browser will refuse the certificate, and it is right to.** No CA exists yet, so the
console is using a certificate it signed itself. Firefox says
`MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT` and Chrome says `ERR_CERT_AUTHORITY_INVALID`. Accept it
once — in Firefox, **Advanced → Accept the Risk and Continue**. Step 8 replaces this
certificate with a real one, and the warning stops for good once you trust your own root CA.

⚠️ **If there is no "Accept the Risk" button at all**, the browser has been told this name is
always safe HTTPS, and that setting does not allow exceptions. It is remembered per name, so
open the server by its address instead. Or clear it: in Firefox, **History → Manage History
→** the domain **→ Forget About This Site**.

### Step 6 (mesh only) — tell every server about the others, part one

⚠️ **Do this before you create any CA.** Every certificate carries the addresses where a
client can fetch the CA certificate and the revocation list. Those addresses are written in
when the certificate is created, and they can never be changed afterwards. They come from the
list of data centers in the database, and this step is what fills that list in. A server that
knows only about itself will name only one data center, in every certificate it ever issues.

**From your own computer**, in the checkout you ran `tofu` from. The addresses are the
servers' public IPv6 addresses, which `tofu -chdir=deploy/cloud/aws output node_public_ipv6`
lists; a standby appears there as `<n>-standby`:

```bash
deploy/mesh-join.sh -i ~/.ssh/fastpki_cloud_ed25519 \
    alpine@<dc1-address>+alpine@<dc1-standby-address> alpine@<dc2-address>
```

One argument per data center. A data center with a standby is written
`<primary>+<standby>`, so that its peers are given both addresses and follow a failover;
leave `+<standby>` out where there is none. An IPv6 address needs no square brackets here:
brackets are a web address rule, not an SSH one.

It reads each server's data center number, interconnect address, public name and database
password from the server itself, gives each one the topology file for as long as
`fastpki-mesh` needs it, runs part one on every primary, and then stops, because no CA
exists yet:

```
mesh-join: data center 1: alpine@<dc1-address>+alpine@<dc1-standby-address> (native), database at 192.0.2.10,192.0.2.11
mesh-join: data center 2: alpine@<dc2-address> (native), database at 198.51.100.10
mesh-join: pass 1 done: every data center knows the others and publishes
mesh-join: stopped: these data centers have no issuing CA of their own yet: 1 2
```

That stop is expected. Carry on with step 7; step 10 runs the same command again and finishes
from there.

##### By hand: what the command does

The topology file has one line per data center, in the format §9.0 step 3 describes. Each
line names that data center's interconnect address (`tofu output node_interconnect_ips`),
followed by its standby's where it has one (`standby_interconnect_ips`), and its database
password, which every server generated for itself and which can only be read on that server:

```bash
ssh -i ~/.ssh/fastpki_cloud_ed25519 alpine@<node-address> \
    'doas sed -n "s/^PG_CONNINFO=.*password=\([^ ]*\).*/\1/p" /etc/fastpki/bootstrap.conf'
```

```
2|host=198.51.100.10 port=5432 dbname=fastpki user=fastpki password=<that-node-pw> sslmode=verify-full sslrootcert=/var/lib/postgresql/tls/ca.crt|2|http://pki-dc2.example.org:8080
```

`sslrootcert=` is `/var/lib/postgresql/tls/ca.crt`. The connection is opened by the PostgreSQL
server when it subscribes to a peer, not by FastPKI, so the path must be one the `postgres`
user can read. The copy under `/var/pki/tls/pg/` belongs to `fastpki`, and `postgres` cannot
open it: a topology that names it fails at `CREATE SUBSCRIPTION` with
`root certificate file "/var/pki/tls/pg/ca.crt" does not exist`, even though the file is there.

The same file goes on every primary as `/root/topology`, mode 600 because it holds every
database password, and part one runs there:

```bash
for s in map publication; do
  doas fastpki-mesh --topology /root/topology --$s \
    | doas su postgres -s /bin/sh -c 'psql -q -v ON_ERROR_STOP=1 -U fastpki -d fastpki'
done
```

⚠️ **The addresses are this deployment's, and nothing downstream will tell you if they are
not.** An address that belongs to no machine gives you `timeout expired` from `fastpki-mesh`,
and then step 10 waits inside `CREATE SUBSCRIPTION` for a server that does not exist. Worse,
the last field of each line goes into every certificate issued afterwards as the address a
client uses to reach that data center. So a wrong one there is written into the CAs you
create in step 7, and only re-creating them takes it out.

If the addresses are right and `fastpki-mesh` still reports `timeout expired`, ask the node
how it reaches a peer. On data center 1:

```bash
ip route get 198.51.100.10     # data center 2's interconnect address
```

A working node answers through `eth1`:

```
198.51.100.10 via 192.0.2.1 dev eth1 src 192.0.2.10
```

An answer that names `dev eth0` is the fault. The interconnect security group admits only
traffic that comes from another interconnect interface, so every packet sent out of `eth0` is
dropped. The first-boot script adds a route to each other data center's interconnect subnet
and keeps it across reboots with a dhcpcd hook (`deploy/cloud/README.md`, "What gets
created"). Its log, `/var/log/fastpki-firstboot.log`, has one `interconnect:` line saying
which routes it added, or that `eth1` was not there yet. To get going, add the routes by hand
on both sides, each through that node's own interconnect router (the `.1` address of its
`eth1` subnet). Routes added this way last until the next reboot:

```bash
doas ip route replace 198.51.100.0/24 via 192.0.2.1 dev eth1     # on data center 1
doas ip route replace 192.0.2.0/24 via 198.51.100.1 dev eth1     # on data center 2
```

### Step 7 — create your CAs

A new deployment has no CA, and the enrolment services stay down until one exists. You can
create the CAs in the console, under **CAs → Create**, or from the command line on the server.

If you use the command line, run these as the `fastpki` user. The CA keys live in a key store
that only answers to that user, and it turns root away with `C_Initialize failed (rc=48)`.
**On the server:**

```bash
doas su -s /bin/sh fastpki                                          # switch to the key store's user
ca()  { fastpki-ca     --config /etc/fastpki/bootstrap.conf "$@"; }  # used in steps 8 and 9
cfg() { fastpki-config --config /etc/fastpki/bootstrap.conf "$@"; }  # used in step 9
```

⚠️ **The `fastpki` user cannot run `doas`. Only `alpine` can.** So when you need to restart a
service, type `exit` first to get back to the `alpine` login. Step 8 does this.

One server needs a root CA and one issuing CA below it. **Several data centers need a root CA
and one issuing CA per server.** Each server signs its own database certificate in step 9,
and it can only sign with a key held in its own key store.

⚠️ **Decide now whether any of these servers will ever get a standby**, because this is the
one choice in the whole section you cannot revisit.

A standby can only sign with a key that was created **copyable**. Whether a key can be copied
is fixed at the moment it is created. You cannot grant it later, and the only remedy is to
create the CA again and re-issue everything it signed. A standby that holds no copy of the
signing key can serve read-only traffic and nothing else, which is not a failover.

The flag is `--replicable`, or **replicable key** in the console. **It applies to each CA
separately, on the server that holds that CA's key.** So in a deployment where data center 1
has a standby and data center 2 does not:

| CA | lives on | `--replicable`? |
|---|---|---|
| the root | server 1 | **yes** — server 1 has a standby |
| `dc1-sub` | server 1 | **yes** |
| `dc2-sub` | server 2 | no — nothing will ever stand by for server 2 |

Leave it off where no standby is planned: a key that cannot leave its key store is the safer
default, which is why it is not automatic. Step 8's service certificates need the same
decision, on the same servers.

Every command below is shown **with** the flag, because that is the case you cannot fix
afterwards. Delete `--replicable` on any server that will never have a standby.

**If you have one server**, these two commands are the whole of step 7:

```bash
ca create root-ca --name "Example Root" --subject "/CN=Example Root" --days 3650 \
   --key ec --curve P-256 --keygen --replicable \
   --ca-key 'pkcs11:token=fastpki;object=root-ca;type=private?pin-source=/var/pki/tls/pin'

ca create issuing-ca --parent root-ca --name "Example Issuing CA" \
   --subject "/CN=Example Issuing CA" --days 1825 --key ec --curve P-256 --keygen --replicable \
   --ca-key 'pkcs11:token=fastpki;object=issuing-ca;type=private?pin-source=/var/pki/tls/pin'
```

Go on to step 8.

**If you have several data centers**, the root CA is created on server 1 and its key never
leaves that server. Every other server creates its own key, asks server 1 to sign it, and
then registers the result. Server 2 is shown below; for a third server, change every `2` to a
`3`.

On **server 1**, as `fastpki`:

```bash
ca create root-ca --name "Example Root" --subject "/CN=Example Root" --days 3650 \
   --key ec --curve P-256 --keygen --replicable \
   --ca-key 'pkcs11:token=fastpki;object=root-ca;type=private?pin-source=/var/pki/tls/pin'

ca create dc1-sub --parent root-ca --name "Example DC1 Sub" \
   --subject "/CN=Example DC1 Sub" --days 1825 --key ec --curve P-256 --keygen --replicable \
   --ca-key 'pkcs11:token=fastpki;object=dc1-sub;type=private?pin-source=/var/pki/tls/pin'

ca show root-ca --pem --out /tmp/root-ca.crt
```

Both carry `--replicable` because server 1 is the one with a standby in the example above.
Drop it from both if no server in this deployment will ever have one.

Check that it took before going on, because a key's replicable setting cannot be changed
later:

```bash
ca key list root-ca
ca key list dc1-sub
```

Each prints its key URL and, after it, what this server's token holds:

```
1. pkcs11:token=fastpki;object=dc1-sub;type=private?pin-source=/var/pki/tls/pin  [in this node's token, replicable]
```

`[in this node's token, NOT replicable: it can never be copied to another host]` means that CA
was created without `--replicable`, and a standby will never be able to sign under it. Remove it
with `ca delete <id>` while it has issued nothing, and create it again.

The servers cannot reach each other over SSH, so files travel through **your own computer**:

```bash
scp -i ~/.ssh/fastpki_cloud_ed25519 alpine@<server 1>:/tmp/root-ca.crt .
scp -i ~/.ssh/fastpki_cloud_ed25519 root-ca.crt alpine@<server 2>:/tmp/root-ca.crt
```

On **server 2**, as `fastpki`, create its key and a request for server 1 to sign:

```bash
ca csr dc2-sub --keygen --key ec --curve P-256 --subject "/CN=Example DC2 Sub" \
   --ca-key 'pkcs11:token=fastpki;object=dc2-sub;type=private?pin-source=/var/pki/tls/pin' \
   --out /tmp/dc2-sub.csr
```

No `--replicable` here, because server 2 has no standby in the example. Add it if that server
will get one — this command is where server 2's key is created, so it is the only chance.

Carry `/tmp/dc2-sub.csr` to server 1 the same way, and sign it there, as `fastpki`:

```bash
ca sign-csr root-ca --csr /tmp/dc2-sub.csr --days 1825 --out /tmp/dc2-sub.crt
```

Carry `/tmp/dc2-sub.crt` back to server 2, and register both certificates there, as
`fastpki`:

```bash
ca add root-ca --name "Example Root" --ca-pem /tmp/root-ca.crt
ca add dc2-sub --name "Example DC2 Sub" --ca-pem /tmp/dc2-sub.crt \
   --ca-key 'pkcs11:token=fastpki;object=dc2-sub;type=private?pin-source=/var/pki/tls/pin'
```

`ca add root-ca` is given no key: this server checks certificates against
the root but can never sign with it. Only the request travels between servers. No private key
ever does.

§9.1 explains each of these steps in depth, and is where to look if one of them refuses.

**Now put the root out of use.** Its work is finished: it signed the issuing CAs, and nothing
else should ever be signed with it. On server 1, as `fastpki`:

```bash
ca disable root-ca
```

That stops anything new being signed by the root. It does **not** withdraw anything already
signed: the root keeps serving its revocation list, its OCSP answers and its certificate in
every chain. Those keep working, because a root whose revocation list stopped answering would
make every certificate it ever signed unverifiable.

Re-enable it for as long as it takes whenever a new issuing CA has to be signed — another
data center, a replacement for one whose key you are retiring — and disable it again
afterwards:

```bash
ca enable root-ca      # sign the new issuing CA, then:
ca disable root-ca
```

The stronger version of this is a root whose key is not on any of these machines at all. It
signs its own revocation list somewhere offline and you publish the bytes with
`fastpki-ca import-crl`. Disabling is the same intent, one step short.

### Step 8 — issue the service certificates

⚠️ **`--replicable` again, and this run is the only chance.** These keys are created by this
command. A key that was not created copyable can never be made copyable, and a standby that
cannot hold a copy leaves the revocation responder, CMP and SCEP dark after a promotion.
Delete `--replicable` on a server that will never have a standby, exactly as in step 7.

**On every server, as the `fastpki` user from step 7:**

```bash
ca renew-service-certs --create-missing --re-issue-self-signed --replicable
```

FastPKI needs a few certificates for itself, and this command issues them.
`--create-missing` creates the ones for the revocation responder and for the CMP and SCEP
services, generating each key inside that server's key store. `--re-issue-self-signed`
replaces the temporary certificates on the console, EST, ACME and Windows services with real
ones from your CA, keeping the keys they already have.

Until you run it, the revocation responder returns errors, CMP refuses every request, and
every service is still using a certificate nothing trusts.

The nightly job that renews these later has no command line of its own. It reads
`SERVICE_KEYS_REPLICABLE` instead, and a server listed in `standby_dcs` is installed with it
set to `true`, so on those servers the job also creates the keys copyable. Check it before
relying on that:

```bash
grep SERVICE_KEYS_REPLICABLE /etc/fastpki/bootstrap.conf    # SERVICE_KEYS_REPLICABLE=true
```

A server not listed in `standby_dcs` does not have it, and does not need it.

⚠️ **If you have already run this without the flag**, the keys exist and cannot be copied, and
running it again changes nothing: the command finds a key under that name and keeps it. It
says so, in those words. To recover, delete those three keys from the key store so the command
generates them again. **On the server, as the `fastpki` user:**

```bash
export P11_KIT_SERVER_ADDRESS=unix:path=/run/p11/pkcs11.sock XDG_RUNTIME_DIR=/run/p11
for k in ocsp-ra cmp-ra scep-ra; do
  pkcs11-tool --module /usr/lib/pkcs11/p11-kit-client.so --login \
      --pin "$(cat /var/pki/tls/pin)" --delete-object --type privkey --label "$k"
done
ca renew-service-certs --create-missing --re-issue-self-signed --replicable
```

Three details, each of which produces a wrong answer if it is missed:

- **The labels are `ocsp-ra`, `cmp-ra` and `scep-ra`** — the key's name in the store, not the
  credential's id. `ocsp-ra-<your-ca-id>` is the credential; the key it uses is `ocsp-ra`.
- **Those two environment variables are needed.** A shell as `fastpki` does not have them —
  the services get them from their service file — and without them `pkcs11-tool` reports
  `No slots`, which reads as a broken key store rather than a missing variable.
- **`--pin` puts the PIN in that machine's process list** for as long as the command runs.
  Leave it out on a machine anyone else can watch: the tool then asks, and the PIN is the
  contents of `/var/pki/tls/pin`.

The re-run says `generated a REPLICABLE <algorithm> key` for each one, which is the confirmation
to look for. Then restart the services as below.

Each service reads its certificate when it starts, so restart them. **Leave the `fastpki`
user first, because it cannot run `doas`:**

```bash
exit                                         # back to the alpine login
doas rc-service fastpki-web restart          # then each protocol you turned on:
doas rc-service fastpki-ocsp restart         # and fastpki-est, -acme, -cmp, -ms, -scep
```

A single-server deployment is finished here. Check that it works with the test in §6.

### Step 9 (mesh or standby) — give each database its certificate

A server that another machine connects to over the database port has to present a
certificate that machine can verify — a mesh peer copying data, or a standby streaming from
its primary. Until now every server has used the temporary database certificate it made for
itself, which nothing else has a reason to trust.

**The commands in steps 10 and 12 do this for you.** Each server gets a certificate signed by
its own data center's issuing CA, and `PG_TLS_CA_ID` is set to that CA so the nightly job
keeps it current; left unset, the job says it has nothing to do and the certificate expires.
Go on to step 10.

By hand, on every server, as the `fastpki` user (`doas su -s /bin/sh fastpki`):

```bash
ca pg-tls dc<N>-sub
cfg set PG_TLS_CA_ID dc<N>-sub
```

You do not have to tell `pg-tls` the address. The server already knows which address its
peers connect to, and puts it in the certificate. The command prints the names it used.

### Step 10 (mesh only) — tell every server about the others, part two

**From your own computer**, the same command as step 6:

```bash
deploy/mesh-join.sh -i ~/.ssh/fastpki_cloud_ed25519 \
    alpine@<dc1-address>+alpine@<dc1-standby-address> alpine@<dc2-address>
```

This time it finds a CA in every data center, gives each primary its database certificate
(step 9), waits for Postgres to take them up, runs part two on every primary, and waits
until every data center holds the same number of certificates (step 11):

```
mesh-join: data center 1: PG_TLS_CA_ID=dc1-sub
mesh-join: data center 1: database certificate issued
mesh-join: data center 2: PG_TLS_CA_ID=dc2-sub
mesh-join: data center 2: database certificate issued
mesh-join: waiting 65 seconds for Postgres to take up the new certificates
mesh-join: pass 2 done: every data center subscribes to every other
mesh-join: done: every data center holds 28 certificates, and each is subscribed to the other
```

By hand, only once step 6 has finished on every primary, on every primary with its own
number:

```bash
doas fastpki-mesh --topology /root/topology --node <index> \
  | doas su postgres -s /bin/sh -c 'psql -q -v ON_ERROR_STOP=1 -U fastpki -d fastpki'
```

### Step 11 — check every server holds the same data

Step 10's command waits for this and says `done` when the counts match. To check by
hand, count the certificates on each server and compare. Do not rely on the database's own
status views: they report a healthy connection even when a server is missing rows. **On
every server, logged in as `alpine`** — the number must be the same everywhere:

```bash
doas su postgres -s /bin/sh -c "psql -tAc 'select count(*) from certs' fastpki"
```

§9.2 has a fuller check. If the numbers do not settle at the same value, read §9.6. When they
do, issue a certificate from end to end with the test in §6.

### Step 12 (standby only) — join each standby to its primary

Until now a standby has been a separate, empty deployment sitting beside its primary. This
step replaces its database with a streaming copy of the primary's, points both servers'
services at both, and copies the CA keys across so the standby can sign if it ever has to
take over. **From your own computer**, once per standby:

```bash
deploy/ha-join-pair.sh --primary alpine@<dc1-address> --standby alpine@<dc1-standby-address> \
    -i ~/.ssh/fastpki_cloud_ed25519
```

It ends like this. On the t3.micro pair this guide was tested with, it took 2 minutes 57
seconds:

```
ha-join-pair: standby: holds every key it needs to serve
ha-join-pair: primary: holds every key it needs to serve
ha-join-pair: standby: database certificate issued from the pair's CA
ha-join-pair: standby: its services now reach the standby first, then the primary
ha-join-pair: done: alpine@<dc1-standby-address> streams from alpine@<dc1-address> and holds the CA keys.
```

Run it again at any time. A standby that already streams from its primary is not copied a
second time, and the line `database certificate issued` is missing when the standby already
has its own certificate. A second run on that pair took 1 minute 48 seconds.

[`high-availability.md`](high-availability.md) §4 is what it does, step by step, and §4 step 5
is a failover drill — do it before you rely on any of this.

Two things this deployment has already done for you: the shared address exists from step 4,
and the CA keys were created copyable in step 7. Without that second one the standby can hold
no signing key, and a failover would give you a machine that serves read-only traffic and
cannot issue.

### Changing the deployment later

Every answer you gave in step 3 is saved in `deploy/cloud/aws/terraform.tfvars`. To change
one — add a standby, move the console to another port, let more addresses reach the
protocols — edit that file and run these two commands **on your own computer**:

```bash
export AWS_PROFILE=fastpki
tofu -chdir=deploy/cloud/aws plan    # says what it would do, and does nothing
tofu -chdir=deploy/cloud/aws apply   # does it, after you type yes
```

`plan` is safe to run at any time: it compares the file with what exists and prints the
difference. `apply` makes that difference real.

⚠️ **Read the plan for the word "destroy" before you confirm.** Adding a standby only creates
new machines and leaves the running ones alone. But changing an answer a server was given at
installation — the protocols, the console port, its data center number — replaces that
server, because those answers are read only when a machine first starts. Its data volume
survives, since that is a separate disk, but the machine itself is rebuilt.

⚠️ **Replacing a server is not how you take an update, once a CA exists.** Each server's
database password and token PIN are created on the machine itself and kept on its system
disk. Replace the machine and those are gone, while the database and the keys they open are
still on the data disk — so the new machine cannot read its own database or sign with its own
keys. It refuses at first boot and says so, rather than coming up broken, but the deployment
is still down until you put it right.

To update a deployment that holds a CA, leave the machines where they are and install the new
release on them as a package: [`admin-guide.md`](admin-guide.md) §14.4. The machine keeps its
secrets and the CA keeps working. Replacing servers is for a deployment you are willing to
build again from nothing — and then delete the data disks with them, so the new machines
start clean.

The data disks refuse to be deleted: each carries `prevent_destroy = true` in
`deploy/cloud/aws/instances.tf`, because deleting one deletes every CA key and certificate on
it. To start from nothing on purpose, set those two lines to `false` for one apply, name the
disks to replace, and set them back straight after:

```bash
tofu -chdir=deploy/cloud/aws plan -out=rebuild.tfplan \
    -replace='aws_ebs_volume.data["1"]' -replace='aws_ebs_volume.data["2"]' \
    -replace='aws_ebs_volume.standby_data["1"]'     # one -replace per disk in your deployment
tofu -chdir=deploy/cloud/aws apply rebuild.tfplan   # with any -var you gave plan
```

⚠️ **A replaced server keeps its address but has a new SSH host key**, so the next `ssh` to it
stops with `REMOTE HOST IDENTIFICATION HAS CHANGED`, or `Host key verification failed` from a
script. That is the check doing its job. Remove the old key for each replaced server, then
connect again and accept the new one:

```bash
ssh-keygen -R <address>        # once per replaced server, the addresses from node_public_ipv6
```

### Tearing it down

**From your own machine**, not from a node:

```bash
deploy/cloud/cloud-install.sh --destroy
```

This deletes the servers, the network cards and the network. It **keeps the data disks**,
on purpose: they hold every certificate you have issued and, unless you use a hardware
security module, every CA private key as well. Deleting those is a separate decision, and a
separate command:

```bash
aws ec2 describe-volumes --filters Name=tag:Name,Values='<deployment>-data-*' \
    --query 'Volumes[].[VolumeId,Tags[?Key==`Name`].Value|[0]]' --output text
aws ec2 delete-volume --volume-id vol-...
tofu -chdir=deploy/cloud/aws state rm 'aws_ebs_volume.data["1"]'  # one per data center
```

A kept disk still holds the database and the keys, but not the password to the database: that
lived on the system disk, which is gone. So treat a kept disk as an archive you can mount and
read, not as a deployment you can start again.

---

## 13. Troubleshooting

### The console sits on "Loading dashboard…" and never finishes

The dashboard asks for four things at once and draws nothing until all four answer. If one
never answers, the page stays on that line — and a refresh shows the dashboard for a moment,
because the other three arrive first, before the fourth stalls it again.

The usual cause is the key store having no session left to give out. **On the node, as
`alpine`:**

```bash
for f in /proc/[0-9]*/comm; do doas cat $f; done | grep -c p11-kit-remote
```

A number near 128 means the key store is at its ceiling and cannot open another session, so
whatever asked for one is still waiting. Free them:

```bash
doas rc-service fastpki-token restart
```

Every service notices its dead handle, exits and is restarted with a fresh one, which is the
design in §7.1. The console works again as soon as it comes back.

A steadily climbing count means something is leaking sessions. On a healthy node the number
sits in single digits and stays there; watch it for two minutes and see whether it grows.

### A native or cloud node runs out of memory, and PostgreSQL will not start again

The symptom is anything that talks to the database failing at once:

```
fastpki-ca: postgres connect failed: connection to server at "127.0.0.1", port 5432 failed:
Connection refused
```

Check the process count and the free memory before anything else. **On the node, as
`alpine`:**

```bash
ls -d /proc/[0-9]* | wc -l                     # ~100 is normal
free -m
doas dmesg | grep -i "out of memory" | tail
```

Several hundred processes, nearly all of them `p11-kit-remote`, means the node is in a loop
that it cannot leave by itself. PostgreSQL stopped for some reason; every service exited, as
they are meant to; each restart left a `p11-kit-remote` behind; and when memory ran out the
kernel killed PostgreSQL, so the thing that caused the restarts can never fix itself.

Repair it in this order, **on the node, as `alpine`**:

```bash
for s in web ocsp est acme cmp ms scep store pgtls p11-tls; do doas rc-service fastpki-$s stop; done
doas rc-service fastpki-token stop
doas pkill -f p11-kit-remote                   # the stragglers, now that nothing is using them
doas rc-service postgresql zap                 # clears a "crashed" state OpenRC still believes
doas rc-service fastpki-pgstale restart        # removes a socket file the killed server left
doas rc-service postgresql start
doas rc-service fastpki-token start
for s in web ocsp est acme cmp ms scep store pgtls; do doas rc-service fastpki-$s start; done
```

⚠️ **`fastpki-pgstale` is not optional here.** When the kernel kills PostgreSQL, its socket
file stays behind, and the start script's only test is whether that file exists — so it
refuses with `Socket conflict. A server is already listening on /run/postgresql/.s.PGSQL.5432`
when nothing is listening at all. That service removes the file, and only when two separate
checks agree the server is gone: `pg_isready` gets no answer, and no postgres process exists.

It also runs by itself at every boot, before PostgreSQL, so a node that is simply rebooted
comes back without any of this. Use `restart` rather than `start` when repairing by hand: it
has already run this boot, and OpenRC will not run a started service again.

### CMP refuses every transaction, or OCSP answers `internalerror`

Both mean the service is running without the certificate it needs to sign its answers, and
both have the same cause. The certificates in §4.4a were created after those services had
already started, and a service only reads its certificate when it starts.

Restart them. Include the three that have no HTTPS certificate of their own, because those
are the ones people leave out:

```bash
docker compose restart ocsp cmp scep est acme ms web
```

Native or cloud node:

```bash
for s in ocsp cmp scep est acme ms web; do rc-service fastpki-$s restart; done
```

### A protocol answers `403 forbidden: this account may not enrol`

The account exists but holds no role granting enrolment over that protocol against that CA.
`--role standard` is not an enrolling role; `requester` is:

```bash
docker compose run --rm --no-deps --entrypoint fastpki-config web \
  --config /app/config/bootstrap.conf web-user alice 'S3cret…' --role requester
```

### A client elsewhere says `unable to get certificate CRL`, but the same check passes on the server

```
error 3 at 0 depth lookup: unable to get certificate CRL
```

The addresses for the revocation list and the CA certificate are written into every
certificate as it is issued. They come from `BASE_URL`, or from `PKI_DNS` if `BASE_URL` is not
set.

If that is the machine's own short name, it works on the machine itself and inside its Docker
network, so every check you run there passes. Nowhere else can resolve it, so nobody else can
fetch the revocation list.

Set a name your clients can resolve. Certificates that have already been issued keep the
address they were given, so re-issue anything that has to be checked from elsewhere:

```bash
docker compose run --rm --no-deps --entrypoint fastpki-config web \
  --config /app/config/bootstrap.conf set BASE_URL https://pki.example.org
docker compose restart ocsp est cmp scep acme ms web
```

Check what a freshly issued certificate carries:

```bash
openssl x509 -in leaf.pem -noout -ext crlDistributionPoints
```

### `curl -fsSL .../releases/latest/download/install.sh` returns 404

The one-line install in §3.1 downloads a file from a **public** release. Against a private
repository it returns 404 and says nothing about why.

Download the release yourself with a tool that can sign in (`gh release download <tag>`),
check the files against `SHA256SUMS`, unpack them, and run `deploy/install.sh` from there
instead. It is the same code either way.

### Locked out of the console

A wrong setting can make the console unreachable, and then you cannot use the console to
correct it. Every setting is also in the database, so the way back in is `fastpki-config`, run
in a throwaway container. It needs only the database, not the console:

```bash
cd deploy
cfg() { docker compose run --rm --no-deps --entrypoint fastpki-config web \
          --config /app/config/bootstrap.conf "$@"; }

cfg get   WEB_CLIENT_CA_ID     # what is actually set
cfg unset WEB_CLIENT_CA_ID     # remove it from the DB overlay
docker compose restart web
```

`unset` puts a setting back to whatever the file says, or to its built-in default. If the
value is still there afterwards, it is also set in `.env` or in `bootstrap.conf`. `cfg get`
only shows you what is in the database; those two files you edit by hand.

⚠️ **`WEB_CLIENT_CA_ID` accepts a client certificate; it does not demand one.** mTLS is one
console authentication method beside local passwords, LDAP, OIDC and SAML, so a browser with
no certificate completes the handshake and reaches the login page. A browser refused at the
TLS handshake — Firefox reports `SSL_ERROR_RX_CERTIFICATE_REQUIRED_ALERT`, with no
server-side log line — is not this key doing its job; use the `cfg unset` above and check
what else is terminating TLS.

| Symptom | Cause / fix |
|---|---|
| `SSL_ERROR_RX_CERTIFICATE_REQUIRED_ALERT`, `ERR_BAD_SSL_CLIENT_AUTH_CERT`, or a browser prompt for a certificate you do not have | The console is demanding a client certificate. Clear `WEB_CLIENT_CA_ID` / `WEB_CLIENT_CA_BUNDLE` / `WEB_CLIENT_CA` with the `cfg unset` recipe above and restart. mTLS is optional, so with none of those three set the console never asks for a client certificate. |
| Console loads but every write 403s | Someone set `WEB_ALLOW_REVOKE` to `false` — it is `true` by default, so this is a deliberate read-only pin, not a fresh-install state. `cfg set WEB_ALLOW_REVOKE true` and restart `fastpki-web`. |
| `fastpki-est`/`acme`/`ms` won't start / connection refused | **Not** a missing transport cert: each self-signs when `EST_CERT`/`EST_KEY` (etc.) are absent, and the shipped config leaves those unset on purpose. Check, in order: that the service's compose profile is in `COMPOSE_PROFILES` at all (§3.2); `<PROTO>_ENABLED` in the `config` table, since the gate refuses to open the port and logs `est is switched off (EST_ENABLED=false) — not listening`; and a `datacenters` row matching `DATACENTER_ID`, without which startup aborts. `EST_CERT`/`EST_KEY` are the cause only when they point at files that exist and are broken. |
| `fastpki-ca` errors about the DB / "no such table" | Schema not loaded. Ensure `createdb.sql` ran (fresh volume). |
| CMP rejects everything | Fail-closed auth, with no way to turn it off. For PBM, check the client's `-ref` names a user that has an enrolment secret (`keys.kid`); for signatures, set `CMP_CLIENT_CA_ID`/`CMP_CLIENT_CA_BUNDLE`. |
| ACME client gets wrong/loopback URLs | `BASE_URL` not set to the public `https://` URL. |
| Issued certs' OCSP/CRL URLs unreachable | `BASE_URL`, or a data center's `base_url` in the topology file, names an address a client cannot reach. A certificate carries one entry per data center; `fastpki-ca urls <ca_id>` prints exactly what is being issued. |
| Console issuance returns 400 `specify ?ca_instance=<id>` | Issuance is per-CA and there is no default: the request must name the CA. |
| Console issuance fails for the CA it named | 404 — no row in `certs` with that `id` and `is_ca=true`. 409 — the CA is not active (`ca_enabled=false`, expired or revoked; the message says which). 500 `CA material unavailable` — the row is fine but its key URI would not load: set `PKCS11_MODULE` where the key is in a token, and check the token is reachable. The console returns **501** only for "no users yet" and for LDAP in a build without it — never for a CA problem. |
| `bootstrap`: `mkdir: can't create directory '/var/pki/...': Permission denied` | The fresh named volume is root-owned and the runtime user is unprivileged. The compose runs `bootstrap` as root (`user: "0:0"`) and it `chown`s `/var/pki` back to `fastpki`. If you invoke the bootstrap by hand, run it as root. |
| `fastpki-acme`: database connection errors | Check `PG_CONNINFO`, and that the anchor it names is the one the database serves. |
| Other node can't pull the image / `http: server gave HTTP response to HTTPS client`, **on compose or native** | The pulling node's Docker doesn't trust the registry. Add it to `/etc/docker/daemon.json` `insecure-registries` (or use a TLS registry) and restart Docker — see "Multiple nodes" in §3. |
| The same message **on Kubernetes**, with `daemon.json` already correct | k3s runs containerd, which never reads Docker's `daemon.json` — so fixing that file and restarting Docker changes nothing, however many times it is repeated. Declare the registry to containerd instead, in `/etc/rancher/k3s/registries.yaml` **on every node**, then restart k3s there (§8.4). |

See `config/bootstrap.conf.example` for the exhaustive, commented key list, and the
`user-guide.md` §6–§10 for protocol-by-protocol client examples.
