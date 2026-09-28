# FastPKI — Manual procedures

Every procedure here is one that a script normally does for you. The deployment guide
([`deployment.md`](deployment.md)) and the high-availability guide
([`high-availability.md`](high-availability.md)) show the script. Use a chapter here only when
you cannot run that script, or to finish a step the script reported as failed.

Each chapter starts by naming the script it replaces.

## Contents

1. [Installing with Docker Compose by hand](#1-installing-with-docker-compose-by-hand)
2. [Building the image yourself](#2-building-the-image-yourself)
3. [Creating CAs from the command line](#3-creating-cas-from-the-command-line)
4. [Service certificates one at a time in the console](#4-service-certificates-one-at-a-time-in-the-console)
5. [Replacing the OCSP, CMP and SCEP keys with copyable ones](#5-replacing-the-ocsp-cmp-and-scep-keys-with-copyable-ones)
6. [Native install from a source checkout](#6-native-install-from-a-source-checkout)
7. [Kubernetes from a source checkout](#7-kubernetes-from-a-source-checkout)
8. [Joining data centers by hand](#8-joining-data-centers-by-hand)
9. [Repairing replication by hand](#9-repairing-replication-by-hand)
10. [Applying a schema change by hand](#10-applying-a-schema-change-by-hand)
11. [Joining a standby by hand](#11-joining-a-standby-by-hand)
12. [Promoting a standby by hand](#12-promoting-a-standby-by-hand)
13. [Copying keys between the tokens by hand](#13-copying-keys-between-the-tokens-by-hand)

---

## 1. Installing with Docker Compose by hand

`deploy/install.sh` normally does all of this. Do it by hand to install from an image you
loaded from a file (the installer would replace it), or to finish an installation the
installer stopped part-way through.

Everything below runs in the `deploy` folder of a release tarball or a checkout.

**1. Write the settings.** `bootstrap.compose.conf` is the install-time seed of settings, and
`.env` holds this server's own values; Compose passes `.env` to every container. Three values
in `.env` are required even on a single server:

- `PKI_DNS` — your public name. It is written into every certificate;
- `FASTPKI_PIN` — the key store PIN. The certificate step refuses to run without it, and the
  database waits for that step;
- `POSTGRES_PASSWORD` — the database password.

On a server of a mesh, also set `DATACENTER_ID` and `PG_BIND`. `FASTPKI_IMAGE` names the image;
for an image you loaded, give its name here and do not run `docker compose build`.

```bash
cp .env.example .env && $EDITOR .env
$EDITOR bootstrap.compose.conf      # optional; the shipped values work
```

**2. Build the image (unless you loaded one), create the database certificate, and start the
database.** The certificate step (`certgen`) must run before PostgreSQL, which reads its key as
it starts:

```bash
docker compose build
docker compose run --rm certgen
docker compose up -d postgres
docker compose exec postgres sh -c 'until pg_isready -U fastpki; do sleep 1; done'
```

`certgen` writes the database's certificate and key, the copy of it every service checks
against (`/var/pki/tls/pg/ca.crt`), and the key store PIN file (`/var/pki/tls/pin`). It never
overwrites files that exist.

**3. Bootstrap, once.** It creates FastPKI's folders under `/var/pki` and the `admin` user with
the password `admin`, which must be changed at the first sign-in:

```bash
docker compose run --rm bootstrap
```

**4. Start the console, and create the CAs** (deployment guide §4.3):

```bash
docker compose up -d postgres web
```

**5. Start the protocol services.** Every protocol has its own Compose profile, so name the
ones you want in `.env`; without it, `up -d` starts only the database, key store and console:

```
COMPOSE_PROFILES=ocsp,est,acme,cmp,ms,store,scep
```

```bash
docker compose up -d
```

**6. Issue the service certificates** (deployment guide §4.4), now that every service has
started once:

```bash
docker compose exec web fastpki-ca renew-service-certs --create-missing --re-issue-self-signed
docker compose restart ocsp cmp scep est acme ms web
```

**7. Check:**

```bash
docker compose ps
curl -sk https://localhost:8090/healthz && echo " web OK"
```

Open the console at `https://YOUR-NAME:8090`. Until step 6 it uses a certificate it signed
itself, so the browser warns.

## 2. Building the image yourself

A release's published image is what the installers use. Build your own only when you have
changed the source, or when the servers cannot reach `ghcr.io`.

**With Docker**, from the top of the source tree, always through the wrapper, which runs the
public-repository check first:

```bash
IMAGE=fastpki:local sh deploy/build-image.sh
```

To serve it to several servers, push it to your registry (deployment guide §3.3).

**For k3s**, which does not use Docker's images: build it, then load it into the cluster.
Keep the `&&`, so a failed `cd` does not build in the wrong folder:

```bash
cd ~/FastPKI && docker build -t fastpki:latest . \
    && docker save fastpki:latest | sudo k3s ctr images import -
sudo k3s ctr images ls | grep fastpki      # must print docker.io/library/fastpki:latest
```

The build takes 15 to 25 minutes. An image loaded this way exists only on that machine. For a
second machine, copy it there, or use a registry both reach (deployment guide §8.4):

```bash
docker save fastpki:latest -o /tmp/fastpki.tar
scp /tmp/fastpki.tar YOUR-LOGIN@SECOND-ADDRESS:/tmp/
ssh YOUR-LOGIN@SECOND-ADDRESS 'sudo k3s ctr images import /tmp/fastpki.tar && rm /tmp/fastpki.tar'
rm /tmp/fastpki.tar
```

Then set `IMAGE=fastpki:latest` in `deploy/k8s/env.local`.

## 3. Creating CAs from the command line

The console creates CAs (deployment guide §4.3). `fastpki-ca` does the same from the command
line, for a scripted installation.

**How to run it.** It runs inside the image, and every command needs `--config`. Define these
two shorthands once, in the form for your installation, and use them for every `ca` and `cfg`
command below:

```bash
# Docker Compose, from deploy/. -v /tmp:/hosttmp only for the steps that read or write a file.
ca()  { docker compose run --rm --no-deps -v /tmp:/hosttmp \
          --entrypoint fastpki-ca     web --config /app/config/bootstrap.conf "$@"; }
cfg() { docker compose run --rm --no-deps \
          --entrypoint fastpki-config web --config /app/config/bootstrap.conf "$@"; }

# Native or cloud: switch to the fastpki user first (doas su -s /bin/sh fastpki), then
ca()  { fastpki-ca     --config /etc/fastpki/bootstrap.conf "$@"; }
cfg() { fastpki-config --config /etc/fastpki/bootstrap.conf "$@"; }

# Kubernetes
ca()  { kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
          fastpki-ca     --config /app/config/bootstrap.conf "$@"; }
cfg() { kubectl -n fastpki exec statefulset/fastpki-node -c web -- \
          fastpki-config --config /app/config/bootstrap.conf "$@"; }
```

⚠️ **On native and cloud servers, run it as the `fastpki` user.** The key store answers only
that user; as root it fails with `C_Initialize failed (rc=48)`, which reads as a broken key
store. The `fastpki` user cannot run `doas`, so type `exit` before restarting a service.

⚠️ **With Compose, a file written through `/hosttmp` belongs to the container's user.** You
cannot overwrite it later, and a second run that writes the same name keeps the old file.
Remove such files by name when you are done, and check a certificate's fingerprint after
installing it.

⚠️ **On Kubernetes, leave out `--out` and redirect instead.** `ca show --pem`, `ca csr` and
`ca sign-csr` print to standard output without it, so the file lands on your machine. Redirect
into a fresh folder you own (`mkdir -p ~/mesh-bootstrap && cd ~/mesh-bootstrap`), not `/tmp`,
where an old file from an earlier installation may block the write. The steps that read a file
take it on standard input, with `exec -i`:

```bash
kubectl exec -i -n fastpki statefulset/fastpki-node -c web -- sh -c \
  'cat > /tmp/in.csr && fastpki-ca --config /app/config/bootstrap.conf \
     sign-csr root-ca --csr /tmp/in.csr --days 1825' < dc2-sub.csr > dc2-sub.crt
```

⚠️ **Write every `pkcs11:` address out in full**: `token=`, `object=`, `type=` and
`?pin-source=`. A shortened one can work on one server and fail on another with the misleading
`The token was not present in its slot`.

**One server: a root CA and an issuing CA.** `--keygen` creates each key inside the key store.
Add `--replicable` to both on a server that has or will have a standby; it cannot be added
later:

```bash
ca create root-ca \
    --name "Example Root" --subject "/CN=Example Root CA" --days 3650 \
    --key rsa --bits 4096 --keygen \
    --ca-key 'pkcs11:token=fastpki;object=root-ca;type=private?pin-source=/var/pki/tls/pin'
ca create issuing-ca --parent root-ca \
    --name "Example Issuing CA" --subject "/CN=Example Issuing CA" --days 1825 \
    --key rsa --bits 3072 --keygen \
    --ca-key 'pkcs11:token=fastpki;object=issuing-ca;type=private?pin-source=/var/pki/tls/pin'
ca disable root-ca
```

Check that each key was created as intended:

```bash
ca key list root-ca
```

`[in this node's token, replicable]` or `NOT replicable: it can never be copied to another
host` says which it is. A CA that is wrong can be removed with `ca delete <id>` while it has
issued nothing.

**Several data centers: one root, and an issuing CA per data center.** On a mesh, run the
first part of `mesh-join.sh` (deployment guide §9.0 step 3) before this, so every CA names every
data center. The root is created on server 1 and its key never leaves it. Every other server
creates its own key and a request, server 1 signs the request, and the other server registers
the result.

On **server 1**:

```bash
ca create root-ca --name "Example Root" --subject "/CN=Example Root" --days 3650 \
   --key ec --curve P-256 --keygen \
   --ca-key 'pkcs11:token=fastpki;object=root-ca;type=private?pin-source=/var/pki/tls/pin'
ca create dc1-sub --parent root-ca --name "Example DC1 Sub" \
   --subject "/CN=Example DC1 Sub" --days 1825 --key ec --curve P-256 --keygen \
   --ca-key 'pkcs11:token=fastpki;object=dc1-sub;type=private?pin-source=/var/pki/tls/pin'
ca show root-ca --pem --out /hosttmp/root-ca.crt      # native: --out /tmp/root-ca.crt
```

On **server 2** (server 3 is the same with `dc3-sub`), create its key and a request. Add
`--replicable` if this data center will have a standby:

```bash
ca csr dc2-sub --keygen --key ec --curve P-256 --subject "/CN=Example DC2 Sub" \
   --ca-key 'pkcs11:token=fastpki;object=dc2-sub;type=private?pin-source=/var/pki/tls/pin' \
   --out /hosttmp/dc2-sub.csr
```

Copy the request to server 1. On AWS the servers cannot reach each other over SSH, so copy
through your own computer with `scp`. Only certificates and requests travel; no private key
does. On **server 1**, sign it with the root (enable the root first if it is disabled):

```bash
ca sign-csr root-ca --csr /hosttmp/dc2-sub.csr --days 1825 --out /hosttmp/dc2-sub.crt
```

Copy `dc2-sub.crt` and `root-ca.crt` to server 2, and register both there:

```bash
ca add root-ca --name "Example Root" --ca-pem /hosttmp/root-ca.crt
ca add dc2-sub --name "Example DC2 Sub" --ca-pem /hosttmp/dc2-sub.crt \
   --ca-key 'pkcs11:token=fastpki;object=dc2-sub;type=private?pin-source=/var/pki/tls/pin'
```

`root-ca` is registered without a key: this server checks certificates against it and never
signs with it. Register the root first, so `dc2-sub` is recognised as its child. `add` takes no
`--parent`; the parent comes from the certificate.

When every issuing CA is signed, disable the root on server 1: `ca disable root-ca`. Enable it
again only while signing the next data center's CA.

Then continue with the service certificates (deployment guide §4.4, or §9.0 step 8).

## 4. Service certificates one at a time in the console

`fastpki-ca renew-service-certs --create-missing --re-issue-self-signed` normally does this
(deployment guide §4.4). Do it by hand in the console when a listener must carry extra names,
or to issue each certificate separately. The result is the same.

In these steps `issuing-ca` is your issuing CA's id. Every certificate in steps 1 to 4 uses the
same form, **Inventory** → **+ Request (key in HSM)**:

- **Serve as** says which service the certificate is for. It fills in the **Key name** and the
  key usage for that service; do not change them.
- **Issue from**: your issuing CA.
- **Token slot** and **PIN file** are filled in for you.
- On a pair, tick **replicable key** in steps 1 to 3, so the standby can copy these keys. It
  cannot be changed later.
- Click **Generate in HSM & request**.

**Step 1 — the OCSP responder certificate.** **Serve as**: **OCSP responder
(OCSP_RESPONDER_CERT_ID_PREFIX)**. **CN**: `FastPKI OCSP Responder`.

**Step 2 — the CMP RA certificate.** **Serve as**: **CMP RA (CMP_RA_CERT_ID_PREFIX)**. **CN**:
`FastPKI CMP RA`.

**Step 3 — the SCEP RA certificate.** **Serve as**: **SCEP RA (SCEP_RA_CERT_ID_PREFIX)**.
**CN**: `FastPKI SCEP RA`. Only RSA is offered: SCEP needs an RSA key.

Skip step 2 or 3 if you did not install CMP or SCEP.

**Step 4 — the TLS certificates of the HTTPS services**, once each for **Console TLS
(WEB_CERT_ID)**, **EST TLS (EST_CERT_ID)**, **ACME TLS (ACME_CERT_ID)** and **MS-XCEP/WSTEP TLS
(MS_CERT_ID)**:

- ⚠️ **Tick "use a key already in the token".** Each service already has its key. Unticked, the
  form tries to create a new key with the same name, and the server refuses.
- **replicable key** is not needed: each server keeps its own TLS key.
- **CN** and **SANs**: exactly the public name you gave the installer (`PKI_DNS`), plus any
  other name or address clients use, one per line. Do not leave **SANs** empty; clients check
  only the SAN, and certbot stops with `Hostname mismatch` otherwise.

**Step 5 — the database certificate.** **Inventory** → **Issue Postgres certificate**.
**Issuing CA**: your issuing CA; **Key**: RSA 3072. PostgreSQL loads it within about 30
seconds.

**Step 6 — two settings.** On the **Config** tab, click **All**, then set `PG_TLS_CA_ID` and
`CMP_CLIENT_CA_ID` to your issuing CA's id. The first keeps the database certificate renewed;
the second lets CMP accept signed requests.

**Step 7 — restart the services**, from the server's `deploy` folder:

```bash
docker compose restart ocsp cmp scep est acme ms web
```

On native or cloud: `for s in ocsp cmp scep est acme ms web; do doas rc-service fastpki-$s restart; done`.

**Step 8 — check.** The **Inventory** tab lists the new certificates, and
`docker compose logs ocsp cmp scep` reports no missing certificate.

To replace one service's certificate later, repeat step 4 for that service only; it is picked
up within 30 seconds.

## 5. Replacing the OCSP, CMP and SCEP keys with copyable ones

Needed when those keys were created without `--replicable` on a server that now needs a
standby. No script does this: `renew-service-certs --replicable` keeps a key it finds, so the
three keys have to be deleted from the key store first. The certificates are then re-issued for
the new keys.

The keys are named `ocsp-ra`, `cmp-ra` and `scep-ra` in the key store, whatever the CA.

**Docker Compose**, from `deploy/`:

```bash
docker compose exec web sh -c 'for l in ocsp-ra cmp-ra scep-ra; do
  for t in privkey pubkey; do
    pkcs11-tool --module "$PKCS11_MODULE" --token-label "${PKCS11_TOKEN:-fastpki}" --login \
        --pin "$(cat /var/pki/tls/pin)" --delete-object --type $t --label $l >/dev/null 2>&1
  done
done'
docker compose exec web fastpki-ca renew-service-certs --create-missing --replicable
docker compose restart ocsp cmp scep
```

**Native or cloud**, as the `fastpki` user. The two variables are set for the services by their
service file, and without them `pkcs11-tool` reports `No slots`:

```bash
export P11_KIT_SERVER_ADDRESS=unix:path=/run/p11/pkcs11.sock XDG_RUNTIME_DIR=/run/p11
for k in ocsp-ra cmp-ra scep-ra; do
  pkcs11-tool --module /usr/lib/pkcs11/p11-kit-client.so --login \
      --pin "$(cat /var/pki/tls/pin)" --delete-object --type privkey --label "$k"
done
fastpki-ca --config /etc/fastpki/bootstrap.conf renew-service-certs --create-missing --re-issue-self-signed --replicable
```

Then `exit` and restart the services as `alpine`.

**Kubernetes**: deployment guide §8.0b, *Adding a second server to a running one*, step 1.

`--pin` shows the PIN in the process list while the command runs; leave it out on a shared
machine and type the contents of `/var/pki/tls/pin` when asked. The re-run must print
`generated a REPLICABLE <algorithm> key` for each of the three.

## 6. Native install from a source checkout

`install.sh --native` normally installs a release's ready-built package. From a source
checkout there is no package for the code in it, so the programs are built on the machine
first. On a new Alpine machine, as root:

```bash
# 1. Build: slow, and the same on every machine. It builds the patched pkcs11-provider,
#    p11-kit and SoftHSM (below), then FastPKI, and installs the service files.
sh deploy/native/build-native.sh

# 2. Configure: asks the same questions as deploy/install.sh.
bash deploy/native/install-native.sh
```

`./install.sh --native` from a checkout runs step 2, and says so if step 1 has not been done.
`install-native.sh --answers <file>` takes the same answers file as `deploy/install.sh`.

### The patched PKCS#11 software

Two pieces sit between FastPKI and the key store: **pkcs11-provider**, the OpenSSL 3 provider
that turns a `pkcs11:` address into a key, and, with SoftHSM, the **p11-kit server**, which runs
SoftHSM in a separate process. Loaded into the same process, SoftHSM's use of OpenSSL can
deadlock. A vendor HSM module is loaded directly, and p11-kit is not involved.

p11-kit 0.26.4 drops four mechanisms FastPKI needs when it passes requests along:
`CKM_ML_DSA`, `CKM_ML_DSA_KEY_PAIR_GEN`, `CKM_EDDSA` and `CKM_EC_EDWARDS_KEY_PAIR_GEN`. Without
the patch, ML-DSA and Ed25519/Ed448 keys fail with `CKR_TOKEN_NOT_PRESENT`, which reads as "no
key store here". RSA and EC are not affected.

`deploy/native/build-native.sh` applies this patch and two others, and reads its version pins
from the Dockerfile so both builds use the same commits. To do the p11-kit step by hand:

```bash
git clone --depth 1 --branch 0.26.4 https://github.com/p11-glue/p11-kit /tmp/p11kit
patch -p1 --forward -d /tmp/p11kit -i "$PWD/deploy/p11-kit-mechanisms.patch"
meson setup /tmp/p11kit/build /tmp/p11kit --prefix=/usr --libdir=lib -Dbuildtype=release
ninja -C /tmp/p11kit/build && sudo ninja -C /tmp/p11kit/build install
```

Both ends of the socket need it. The patch changes `p11-kit/rpc-message.c`, which is built into
`libp11-kit.so.0`, so replacing that library and the client module (`p11-kit-client.so`) also
fixes the packaged `p11-kit-server`, which uses the library. Reported upstream as
[p11-glue/p11-kit#776](https://github.com/p11-glue/p11-kit/issues/776).

Alpine's own `p11-kit` package installs the unpatched library. The native installer holds that
package at its installed version so `apk upgrade` leaves the patched files alone, and stops if
they have been replaced (deployment guide §7.2).

## 7. Kubernetes from a source checkout

`install.sh --k8s` normally downloads a release and installs its published image
(deployment guide §8.0). From a source checkout:

```bash
cd ~ && git clone https://github.com/fastpki/fastpki.git FastPKI
cd ~/FastPKI && git checkout <version>
```

⚠️ **The manifests and the image must be the same version.** `apply.sh` and the manifests come
from the checkout and the programs from the image, and a newer manifest can need a command an
older image does not have. Name a release tag, not `:latest`.

Write your settings in `deploy/k8s/env.local` as deployment guide §8.0 step 2 shows, adding the
image:

```
IMAGE=ghcr.io/fastpki/fastpki:<version>
```

For an image you build yourself, see §2 and use `IMAGE=fastpki:latest`. Then apply it:

```bash
cd ~/FastPKI/deploy/k8s && bash apply.sh
```

`apply.sh` needs `kubectl` and `envsubst` (on Debian or Ubuntu, the `gettext-base` package).
Continue with deployment guide §8.0 step 4.

## 8. Joining data centers by hand

`deploy/mesh-join.sh` normally does all of this (deployment guide §9.0). Doing it by hand is
three parts: a file describing every data center, the first part on every data center, and —
once every data center's database has a certificate from its own CA — the second part on every
data center.

### The topology file

`fastpki-mesh` takes the whole mesh as one text file, and the **same file goes on every
server**: one line per data center, four `|`-separated fields, `#` comments allowed:

```
# dc_id | conninfo (dialled by the postgres server) | serial prefix | public base URL
1|host=192.0.2.10,192.0.2.11 port=5432,5432 dbname=fastpki user=fastpki password=DC1-DB-PASSWORD sslmode=verify-full sslrootcert=/pki/tls/pg/ca.crt target_session_attrs=read-write|1|http://pki-dc1.example.org:8080
2|host=198.51.100.10 port=5432 dbname=fastpki user=fastpki password=DC2-DB-PASSWORD sslmode=verify-full sslrootcert=/pki/tls/pg/ca.crt|2|http://pki-dc2.example.org:8080
```

| Field | What it must be |
|---|---|
| `dc_id` | exactly that data center's number, in digits: `2`, not `dc2` |
| conninfo | how the **postgres server** of a peer connects to this data center: `host=`, `port=`, `dbname=fastpki`, `user=fastpki`, this data center's database password, `sslmode=verify-full`, and `sslrootcert=` (below). A pair lists both addresses, one port per address (`port=5432,5432` for a Compose or native pair, `port=5432,5433` for a Kubernetes pair, whose second server has its own port), and `target_session_attrs=read-write`, so peers follow a promotion |
| serial prefix | the data center's number again, 1 to 32767, unique. It is permanent once the data center has issued anything |
| base URL | where this data center serves its revocation lists: `http://<its own name>:8080`, unless a reverse proxy serves them elsewhere. Every certificate carries one address per line of this file, and cannot be changed later |

`sslrootcert` names the file inside the **postgres server's** view, and it differs by
installation:

| Installation | `sslrootcert=` |
|---|---|
| Docker Compose and Kubernetes | `/pki/tls/pg/ca.crt` — the postgres container mounts the files at `/pki`, not `/var/pki` |
| Native and cloud | `/var/lib/postgresql/tls/ca.crt` — the `postgres` user cannot read `/var/pki` |

A wrong path fails at subscription with `root certificate file … does not exist`.

**The database password** is each data center's own. On Compose it is `POSTGRES_PASSWORD` in
that server's `deploy/.env`. On native and cloud:

```bash
ssh -i YOUR-KEY alpine@SERVER-ADDRESS \
    'doas sed -n "s/^PG_CONNINFO=.*password=\([^ ]*\).*/\1/p" /etc/fastpki/bootstrap.conf'
```

The file holds passwords in the clear. Keep it mode 600 and out of any repository. On Compose
it sits in `deploy/topology`; on native and cloud in `/root/topology`.

### Part one: on every data center, before any CA exists

It writes the list of data centers into the database (`--map`) and starts publishing
(`--publication`). Run it **once per data center, on the primary** of a pair; the standby
receives it by streaming, and refuses it with `cannot execute INSERT in a read-only
transaction` if you run it there. Keep the topology file on the standby too, for the day it is
promoted.

```bash
# Docker Compose, from deploy/
for s in map publication; do
  docker compose run --rm --no-deps --user 0:0 -v "$PWD/topology:/topology:ro" \
      --entrypoint fastpki-mesh web --topology /topology --$s \
    | docker compose exec -T postgres psql -U fastpki -d fastpki
done

# Native or cloud, as root
for s in map publication; do
  fastpki-mesh --topology /root/topology --$s \
    | su postgres -s /bin/sh -c 'psql -q -v ON_ERROR_STOP=1 -U fastpki -d fastpki'
done

# Kubernetes, from the folder holding topology. PRIMARY is the pod whose database answers f
# to SELECT pg_is_in_recovery(): fastpki-node-0, or fastpki-node-1 after a promotion.
PRIMARY=fastpki-node-0
for s in map publication; do
  kubectl exec -i -n fastpki "$PRIMARY" -c web -- sh -c \
      'cat > /tmp/topology && exec fastpki-mesh --topology /tmp/topology "$@"' _ --$s < topology \
    | kubectl exec -i -n fastpki "$PRIMARY" -c postgres -- psql -U fastpki -d fastpki
done
```

`--map` prints one `INSERT 0 1` per data center, and `--publication` a `CREATE PUBLICATION`. No
line may begin with ERROR. `--user 0:0` is required on Compose: the file is mode 600 and the
image's user cannot read it, and without it every step prints success while changing nothing.
Do not run the Compose commands on a Kubernetes machine.

Check on every server that every data center is listed:

```bash
docker compose exec -T postgres psql -U fastpki -d fastpki -c 'SELECT dc_id, serial_prefix FROM datacenters ORDER BY dc_id'
```

### The CAs and the database certificates

Create the root and each data center's issuing CA (§3, or the console as deployment guide §9.0
steps 5 to 7), and each data center's service certificates (deployment guide §4.4).

Then give each data center's database a certificate from its own issuing CA, and name that CA
so it is renewed. On each primary, with the §3 shorthands:

```bash
ca pg-tls dc2-sub                      # server 1 uses dc1-sub, server 3 dc3-sub
#   names:  postgres, localhost, 127.0.0.1, <this server's PKI_DNS>, 198.51.100.10
cfg set PG_TLS_CA_ID dc2-sub
```

`pg-tls` adds this server's own `PG_BIND` to the certificate and prints every name it used. If
the interconnect address is missing, `PG_BIND` is still `127.0.0.1`: correct it and run it
again. Leave `PG_TLS_SANS` empty: it is shared by both servers of a pair. PostgreSQL loads the
new certificate within about 30 seconds.

**Check before connecting.** On Compose, the database must be published on that address
(`docker compose ps postgres` shows `198.51.100.10:5432->5432/tcp`). A peer must be able to open
a verified connection:

```bash
docker compose exec -T postgres psql \
  "host=PEER-ADDRESS port=5432 user=fastpki dbname=fastpki password=PEER-DB-PASSWORD \
   sslmode=verify-full sslrootcert=/pki/tls/pg/ca.crt" -tAc 'select 1'
```

`1` means trust is in place. `certificate verify failed` means the peer's certificate does not
lead to this server's root, or does not name the address dialled. `password authentication
failed` with a wrong password still proves the certificate was accepted.

To check a certificate file, pass the file as both the certificate and its intermediates;
without `-untrusted`, `openssl verify` reads only the first certificate and reports a good chain
as `unable to get local issuer certificate`:

```bash
openssl verify -CAfile /var/pki/tls/pg/ca.crt -untrusted /var/pki/tls/pg/server.crt /var/pki/tls/pg/server.crt
```

### Part two: on every data center, after part one has finished everywhere

It subscribes this data center to every other. Run it on every primary, each with its own
number after `--node` — a digit, not a placeholder:

```bash
# Docker Compose, from deploy/
docker compose run --rm --no-deps --user 0:0 -v "$PWD/topology:/topology:ro" \
    --entrypoint fastpki-mesh web --topology /topology --node 2 \
  | docker compose exec -T postgres psql -U fastpki -d fastpki

# Native or cloud, as root
fastpki-mesh --topology /root/topology --node 2 \
  | su postgres -s /bin/sh -c 'psql -q -v ON_ERROR_STOP=1 -U fastpki -d fastpki'

# Kubernetes
kubectl exec -i -n fastpki "$PRIMARY" -c web -- sh -c \
    'cat > /tmp/topology && exec fastpki-mesh --topology /tmp/topology "$@"' _ --node 2 < topology \
  | kubectl exec -i -n fastpki "$PRIMARY" -c postgres -- psql -U fastpki -d fastpki
```

Each run ends with a `CREATE SUBSCRIPTION` line per peer and no ERROR line. Before it writes
anything it checks that each peer runs the same release and already publishes, and refuses
otherwise, naming the table or data center; update that one, run part one there, then this
again. `--no-preflight` skips the check.

⚠️ **If a part-two run failed, clear its slot before retrying.** A run that stopped between
reserving the slot on the peer and creating the subscription leaves the slot behind, and the
retry stops with `replication slot "sub_1_from_2" already exists`. On the peer named in that
message:

```bash
docker compose exec -T postgres psql -U fastpki -d fastpki \
  -c "select pg_terminate_backend(active_pid) from pg_replication_slots where slot_name='sub_1_from_2' and active_pid is not null"
docker compose exec -T postgres psql -U fastpki -d fastpki \
  -c "select pg_drop_replication_slot('sub_1_from_2')"
```

`replication slot … does not exist` from the second command means the first already removed it.

Then confirm the data centers hold the same data (deployment guide §9.2), and check any server
with `fastpki-mesh --topology … --node 2 --verify`.

**A third data center**: add its line to the file on **every** server, run part one again on
every data center, then part two on every data center. Each ends with one subscription per
peer.

### Giving an older CA every data center's address

A CA created before part one names only its own data center. Read what a CA carries from the
certificate itself; `ca urls` prints what a certificate issued **now** would carry:

```bash
ca show dc1-sub --pem --out /hosttmp/dc1-sub.crt
openssl x509 -in /tmp/dc1-sub.crt -noout -text | grep -A1 -E 'Authority Information Access|CRL Distribution Points'
```

One address of each, on a mesh of several data centers, is a CA created before the map. Renew
it keeping its key (admin guide §3.8). Its parent signs the renewal, so where the root's key is
on another server, renew through a request: `ca csr` here without `--keygen`, `ca sign-csr
root-ca` on the root's server, `ca add dc1-sub` back here. Then re-issue the database and
service certificates beneath it:

```bash
ca pg-tls dc1-sub
docker compose exec web fastpki-ca renew-service-certs --create-missing --re-issue-self-signed
docker compose restart ocsp cmp scep est acme ms web
```

## 9. Repairing replication by hand

`mesh-join.sh` creates every subscription, and running it again repairs most faults
(deployment guide §9.6). These are the repairs for when that is not possible. `psql` below
stands for the command that reaches PostgreSQL on that server:

| Installation | `psql` is |
|---|---|
| Docker Compose | `docker compose exec -T postgres psql -U fastpki -d fastpki` |
| Native and cloud | `doas su postgres -s /bin/sh -c 'psql -U fastpki -d fastpki'` |
| Kubernetes | `kubectl exec -i -n fastpki PRIMARY -c postgres -- psql -U fastpki -d fastpki` |

### A subscription is missing

A mesh of `N` data centers needs `N-1` subscriptions on each server, named
`sub_<this server>_from_<peer>`. Creating one either succeeds or leaves nothing, so after
fixing the cause, create the missing one:

```bash
read -rs -p "peer db password: " PWP; echo
docker compose exec -T postgres psql -U fastpki -d fastpki -v ON_ERROR_STOP=1 <<SQL
CREATE SUBSCRIPTION sub_1_from_3
  CONNECTION 'host=203.0.113.10 port=5432 dbname=fastpki user=fastpki password=$PWP sslmode=verify-full sslrootcert=/pki/tls/pg/ca.crt'
  PUBLICATION fastpki_pub
  WITH (origin = none, failover = true, copy_data = true);
SQL
unset PWP
```

All three options are required. `failover = true` lets a standby keep the subscription's slot
after a promotion; `origin = none` and `copy_data = true` make copying from every peer safe. The
warning `copy_data with origin = NONE but might copy data that had a different origin` is
expected here.

On Compose, a peer's database password can be read on that peer with:

```bash
docker inspect fastpki-postgres-1 \
  --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^POSTGRES_PASSWORD=//p'
```

If the peer reports that the slot already exists, drop it on the peer first
(`select pg_drop_replication_slot('sub_1_from_3')`).

### Wrong password in a subscription

Correct it in place rather than dropping the subscription:

```sql
ALTER SUBSCRIPTION sub_1_from_2 CONNECTION 'host=… password=NEW-PASSWORD …';
```

### `publication "fastpki_pub" does not exist`, repeated at the same position

This data center subscribed before the peer published. Creating the publication afterwards
does not help: every retry fails at the same position. Drop the subscription and create it
again:

```bash
# 1. On the peer (data center 2): part one, both halves.
fastpki-mesh --topology topology --map         | psql -q -v ON_ERROR_STOP=1
fastpki-mesh --topology topology --publication | psql -q -v ON_ERROR_STOP=1

# 2. On this server (data center 1): drop the broken subscription; it removes the peer's slot too.
psql -c 'DROP SUBSCRIPTION sub_1_from_2'

# 3. On this server: part two again.
fastpki-mesh --topology topology --node 1      | psql -q -v ON_ERROR_STOP=1
```

### `could not find digest for NID UNDEF`

Confirm which algorithm signed the peer's database certificate:

```bash
openssl x509 -in /var/pki/tls/pg/server.crt -noout -text | grep -m1 'Signature Algorithm'
```

`ED25519`, `ED448` or `ML-DSA-…` is the fault; re-issue it from a CA with an RSA or EC key. Do
not add `channel_binding=disable` to the connection: it works, and removes an authentication
protection from every connection on that link.

### `certificate verify failed`

Check the chain the way a client sees it, from a container that has `openssl` (the postgres
image does not):

```bash
docker exec fastpki-web-1 sh -c \
  "openssl s_client -connect PEER-ADDRESS:5432 -starttls postgres \
     -CAfile /var/pki/tls/pg/ca.crt -verify_return_error </dev/null 2>&1 \
   | grep -E 'Verification|Verify return code'"
```

`Verify return code: 0 (ok)` means the certificate is fine and the fault is elsewhere.

### Connected, but rows still do not match

Ask which tables have not finished their first copy; `r` is ready:

```bash
psql -tAc "select s.subname, c.relname, r.srsubstate
     from pg_subscription_rel r
     join pg_subscription s on s.oid = r.srsubid
     join pg_class c on c.oid = r.srrelid
    where r.srsubstate <> 'r' order by 1, 2"
```

A stuck table is usually a constraint or trigger the subscriber's database log names. Also
compare `select count(*) from pg_publication_tables where pubname = 'fastpki_pub'` on every
server; it must match.

### Growing an existing server into data center 1 by hand

Every installer registers its server as data center 1. If a server lacks its row, every issuing
service refuses to start; add it:

```bash
docker compose exec -T postgres psql -U fastpki -d fastpki -v ON_ERROR_STOP=1 \
  -c "INSERT INTO datacenters(dc_id, serial_prefix) VALUES('1', 1)
        ON CONFLICT (dc_id) DO UPDATE SET serial_prefix=EXCLUDED.serial_prefix;"
```

`DATACENTER_ID` in `.env` must match (`grep DATACENTER_ID .env`); add it only if it is missing.

## 10. Applying a schema change by hand

`rolling-update.sh` (Compose), `deploy/k8s/apply.sh` (Kubernetes) and a re-run of
`install-native.sh` (native and cloud) apply database changes before the services start on a
new release. To apply them by hand, run `deploy/schema-apply.sh` against the database, from the
`deploy` folder on Compose:

```bash
cd deploy
PSQL="docker compose exec -T postgres psql -U fastpki -d fastpki" \
MESH_BIN="docker run --rm ${FASTPKI_IMAGE:-fastpki:local} fastpki-mesh" \
  ./schema-apply.sh
```

[`postgres.md`](postgres.md) §4.2 has the native, cloud and Kubernetes forms.

- **`MESH_BIN` is required on a server of a mesh.** The script rebuilds the rules that decide
  which copy wins when two data centers change the same row, and the program that writes them
  is in the image. Point it at the image you are updating **to**. On a server that is not part
  of a mesh it is not needed.
- **`--check`** lists what is waiting and exits with an error if anything is. It still rebuilds
  those rules, so it needs `MESH_BIN` too.
- **On a mesh**, run it on every data center; **on a pair**, on the primary only. On a standby
  it either finds nothing to do or fails with `cannot execute ALTER TABLE in a read-only
  transaction`.

---

## 11. Joining a standby by hand

`deploy/ha-join-pair.sh` does all of this from your own machine ([`high-availability.md`](high-availability.md)
§3). Do it by hand only when you cannot run that script, or to finish a step it reported as
failed. **A** is the primary, **B** the new standby. On a cloud node you log in as `alpine`
and run commands with `doas`; on another native host, run them as root without `doas`.

### Where Postgres keeps its files on a native host

| What | Path | Owner |
|---|---|---|
| the data directory | `/var/lib/postgresql/17/data` | `postgres` |
| the settings | `/etc/postgresql/postgresql.conf`, `/etc/postgresql/pg_hba.conf` | `postgres` |
| FastPKI's own settings, included from `postgresql.conf` | `/etc/fastpki/postgresql.conf.d/fastpki.conf` | root |
| the certificate Postgres serves, and the anchors Postgres dials with | `/var/lib/postgresql/tls/` | `postgres` |
| the same files, where FastPKI writes them and its services read them | `/var/pki/tls/pg/` | `fastpki` |

`postgres` cannot read `/var/pki`, so the `fastpki-pgtls` service copies `server.crt`,
`server.key`, `ca.crt` and `primary-ca.crt` from `/var/pki/tls/pg/` into
`/var/lib/postgresql/tls/` every 30 seconds. So:

- **a FastPKI service dials** (`PG_CONNINFO`) with `sslrootcert=/var/pki/tls/pg/…`;
- **Postgres itself dials** (`pg_basebackup`, a standby's `primary_conninfo`, a mesh
  subscription) with `sslrootcert=/var/lib/postgresql/tls/…`.

The wrong one fails with `root certificate file "/var/pki/tls/pg/ca.crt" does not exist`,
although the file is there.

The settings live outside the data directory, so copying the database does not copy them.
Each host keeps its own `listen_addresses` and `pg_hba.conf`.

### Step 0 — A's database certificate names the address B dials

B verifies A with `sslmode=verify-full`, so A's certificate must carry the address B dials,
and must be issued by a CA. On A:

```console
$ doas openssl x509 -in /var/pki/tls/pg/server.crt -noout -ext subjectAltName -issuer
X509v3 Subject Alternative Name:
    DNS:postgres, DNS:localhost, IP Address:127.0.0.1, DNS:pki.example.org, IP Address:192.0.2.10
issuer=CN=Example Issuing CA
```

If the address is missing, add it to A's own `/etc/fastpki/bootstrap.conf` and issue a new
certificate:

```bash
printf 'PG_TLS_SANS=%s\n' <A-address> | doas tee -a /etc/fastpki/bootstrap.conf >/dev/null
doas su -s /bin/sh fastpki -c \
    'fastpki-ca --config /etc/fastpki/bootstrap.conf pg-tls <ca-id>'
```

Write the file, not `fastpki-config set`: the `config` table is shared by both hosts, and B
would later get a certificate naming A's address. Name the CA: without an argument `pg-tls`
uses `PG_TLS_CA_ID`, which may not be set yet. Postgres takes the new certificate within
about 30 seconds.

### Step 1 — check both hosts

On A and on B:

```console
$ doas grep -E '^(PG_BIND|P11_TLS)=' /etc/conf.d/fastpki
PG_BIND=192.0.2.10
P11_TLS=on
$ doas rc-service fastpki-p11-tls status
 * status: started
```

`PG_BIND` must be the host's own address. If `P11_TLS=on` is missing or the service is
stopped, re-run that host's installer with `HA_ENABLED=yes`; adding the line by hand does not
create the tunnel's certificate.

Postgres listens on A's address. On A:

```console
$ netstat -ltn | grep 5432
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN
tcp        0      0 192.0.2.10:5432         0.0.0.0:*               LISTEN
```

A is already configured to serve a standby. Check it:

```console
$ doas su postgres -s /bin/sh -c 'psql -d fastpki -tA' <<'SQL'
show wal_level;
show max_wal_senders;
show max_replication_slots;
select rolreplication from pg_roles where rolname = 'fastpki';
SQL
logical
10
10
t
$ doas grep '^hostssl' /etc/postgresql/pg_hba.conf
hostssl all         fastpki 127.0.0.1/32  scram-sha-256
hostssl all         fastpki ::1/128       scram-sha-256
hostssl all         fastpki all           scram-sha-256
hostssl replication fastpki all           scram-sha-256
```

B streams as the `fastpki` role with A's database password. Read it on A; B needs it in
Steps 2 and 3:

```bash
doas sed -n "s/^PG_CONNINFO=.*password=\([^ ]*\).*/\1/p" /etc/fastpki/bootstrap.conf
```

### Step 2 — copy A's database to B

**2a. Give B A's anchor.** Print it on A:

```bash
doas cat /var/pki/tls/pg/ca.crt
```

Install it on B as `primary-ca.crt`, and copy it for Postgres at once:

```bash
doas install -m 0644 -o fastpki -g fastpki /dev/stdin /var/pki/tls/pg/primary-ca.crt <<'PEM'
-----BEGIN CERTIFICATE-----
(A's certificate, pasted)
-----END CERTIFICATE-----
PEM
doas /usr/libexec/fastpki/pg-tls-sync once
```

Test the connection B's Postgres will make, giving A's password:

```console
$ doas su postgres -s /bin/sh -c 'psql "host=<A-address> port=5432 dbname=fastpki user=fastpki sslmode=verify-full sslrootcert=/var/lib/postgresql/tls/primary-ca.crt" -tAc "select 1"'
Password for user fastpki:
1
```

`certificate verify failed` means the pasted anchor is not the one A's certificate chains to.
`root certificate file ... does not exist` means `pg-tls-sync once` has not run.

**2b. Stop B and empty its data directory.**

```bash
for s in web est acme cmp ms scep ocsp store; do doas rc-service -s fastpki-$s stop; done
doas rc-service postgresql stop
doas su postgres -s /bin/sh -c 'rm -rf /var/lib/postgresql/17/data/*'
```

**2c. Copy A's database.** Give A's password when asked:

```bash
doas su postgres -s /bin/sh -c 'pg_basebackup -D /var/lib/postgresql/17/data -R -X stream -c fast \
  -C -S <standby-slot> \
  -d "host=<A-address> port=5432 user=fastpki dbname=fastpki sslmode=verify-full sslrootcert=/var/lib/postgresql/tls/primary-ca.crt"'
```

`<standby-slot>` is `fastpki_` followed by B's own address (`PG_BIND`) in lower case, with
every character other than a letter or digit written as `_`: `fastpki_192_0_2_11` for
`192.0.2.11`. The conninfo must name a real database (`dbname=fastpki`), or slot
synchronisation never connects.

**2d. Make B a standby and start it.**

```bash
printf 'sync_replication_slots = on\nhot_standby_feedback = on\n' \
    | doas tee /etc/fastpki/postgresql.conf.d/standby.conf >/dev/null
doas chown root:postgres /etc/fastpki/postgresql.conf.d/standby.conf
doas chmod 640 /etc/fastpki/postgresql.conf.d/standby.conf
doas rc-service postgresql start
doas rc-service fastpki-pgtls start
```

Start `fastpki-pgtls` too: stopping Postgres stopped it, and without it B keeps its
self-signed database certificate after Step 4.

Check: `select pg_is_in_recovery()` on B returns `t`, and `pg_stat_replication` on A shows B
with `state = streaming`.

On a **mesh node**, point A at the standby's slot, only once the slot exists:

```bash
doas su postgres -s /bin/sh -c "psql -d fastpki -c \"ALTER SYSTEM SET synchronized_standby_slots = '<standby-slot>'\" -c 'SELECT pg_reload_conf()'"
```

If the standby is later removed for good, clear this setting, or replication to the other
data centers stops.

Do not run `bootstrap.sh` on B.

### Step 3 — point every service at both databases

Edit the `PG_CONNINFO` line the installer wrote in `/etc/fastpki/bootstrap.conf`. On **A**,
only the host list changes:

```bash
doas sed -i '/^PG_CONNINFO=/{s/host=[^ ]*/host=<A-address>,<B-address>/; s/port=[^ ]*/port=5432,5432/; s/ target_session_attrs=[^ ]*//; s/ connect_timeout=/ target_session_attrs=read-write connect_timeout=/}' /etc/fastpki/bootstrap.conf
```

On **B**, the password and the anchor change too:

```bash
printf "A's database password: "; read -r PW
doas sed -i "/^PG_CONNINFO=/{s/host=[^ ]*/host=<A-address>,<B-address>/; s/port=[^ ]*/port=5432,5432/; s/ target_session_attrs=[^ ]*//; s/ connect_timeout=/ target_session_attrs=read-write connect_timeout=/; s/password=[^ ]*/password=$PW/; s#sslrootcert=[^ ]*#sslrootcert=/var/pki/tls/pg/primary-ca.crt#}" /etc/fastpki/bootstrap.conf
unset PW
```

- **B uses A's password**, because B's database is now a copy of A's.
- **A is listed first on both** for now. libpq stops at the first host whose certificate it
  cannot verify, and B still serves its self-signed certificate. After Step 4 has issued B's
  own certificate, list B first on B.
- **B's anchor is `primary-ca.crt`** until B is promoted.

Keep the file `0640 root:fastpki`. Then restart A's services and start B's:

```bash
# on A
for s in ocsp cmp scep est acme ms web store; do doas rc-service -s fastpki-$s restart; done
# on B
for s in $(rc-update show default | awk '$1 ~ /^fastpki-(web|est|acme|cmp|ms|scep|ocsp|store)$/ {print $1}'); do
  doas rc-service $s start
done
```

`rc-status | grep fastpki-web` must show a restart count of `(0)`. A rising count with
`password authentication failed for user "fastpki"` in the log means that host's
`PG_CONNINFO` does not carry A's password.

### Step 4 — mark the standby and copy the keys

On **B**:

```bash
printf 'STANDBY_OF=%s\n' <A-address> | doas tee -a /etc/conf.d/fastpki >/dev/null
doas rc-service fastpki-web restart
```

If the hosts have different token PINs, give each host the other's PIN
([copy keys between the tokens by hand](#13-copying-keys-between-the-tokens-by-hand)).

Name the CA that issues the database certificates, once, on either host:

```bash
doas su -s /bin/sh fastpki -c 'fastpki-config --config /etc/fastpki/bootstrap.conf set PG_TLS_CA_ID <ca-id>'
```

Copy the keys now, on **B** and then on **A**, twice each; the second run must print
`key sync: this node holds every key it needs to serve`:

```bash
doas /etc/periodic/daily/fastpki-certrenew
```

Use the job, or **Sync keys now** on the Replication page, rather than a bare
`fastpki-ca key sync`: a shell does not have the host's `PG_BIND`.

Check that both hosts published their tunnel certificates:

```console
$ doas su postgres -s /bin/sh -c "psql -d fastpki -tAc 'select host_id from p11_transport'"
192.0.2.10
192.0.2.11
```

Issue B's own database certificate, then list B first in B's `PG_CONNINFO`:

```bash
doas su -s /bin/sh fastpki -c 'fastpki-ca --config /etc/fastpki/bootstrap.conf pg-tls'
```

### Compose

On compose, `deploy/ha-join.sh` does Steps 2 to 4 on each host: on B
`./ha-join.sh <A-address> primary-ca.crt --primary-password-file <file>`, on A
`./ha-join.sh --on-primary <B-address>`. By hand:

**On A.** A's `PG_BIND` must be a routable address and A's database certificate must carry
it. For a deployment installed on loopback, put the address in A's `.env` as `PG_BIND`, then:

```sh
docker compose up -d
docker compose exec web fastpki-ca pg-tls <ca-id>
```

Export A's anchor and copy it to B:

```sh
docker compose exec postgres cat /pki/tls/pg/ca.crt > primary-ca.crt
scp primary-ca.crt <B>:/opt/fastpki/deploy/
```

**On B**, `.env` holds:

```sh
POSTGRES_PASSWORD=<the same value as A>
FASTPKI_PIN=<B's own token PIN, or A's to share one>
FASTPKI_IMAGE=<the same image A runs>
BASE_URL=<the shared name — the same value as A>
PKI_DNS=<the shared name — the same value as A>
PG_BIND=<B's own address>
COMPOSE_PROFILES=ocsp,est,acme,cmp,ms,store,scep,p11tls
DATACENTER_ID=<the same id as A>
HA_ENABLED=true
P11_TLS=on
SERVICE_KEYS_REPLICABLE=true
```

A host that was a deployment before needs both volumes cleared first — be certain neither
holds a CA key you still need:

```sh
docker compose down -v
```

Then join and start; Postgres copies A's database on its first start:

```sh
./ha-join.sh <A-address> primary-ca.crt
docker compose up -d
```

**Point every service at both databases**, on both hosts, in
`deploy/docker-compose.override.yml` — one entry for every service that reaches the database
(`web`, `est`, `acme`, `cmp`, `ms`, `scep`, `ocsp`, `store`, `certrenew` and `p11-tls`):

```yaml
services:
  web:
    environment:
      PG_CONNINFO: "host=<first host>,<second host> port=5432,5432 dbname=fastpki user=fastpki
        password=<the shared one> sslmode=verify-full
        sslrootcert=<anchor> target_session_attrs=read-write"
```

- On **A**: A first, `sslrootcert=/var/pki/tls/pg/ca.crt`.
- On **B**: A first and `sslrootcert=/var/pki/tls/pg/primary-ca.crt`, until B has its own
  database certificate from the pair's CA; then B first.

`fastpki-config set PG_CONNINFO` does not work: the services take `PG_CONNINFO` only from
their environment.

Name the CA that issues the database certificates, and issue B's:

```sh
docker compose exec web fastpki-config set PG_TLS_CA_ID <ca-id>
docker compose exec web fastpki-ca pg-tls <ca-id>
```

Copy the keys as in [copy keys between the tokens by hand](#13-copying-keys-between-the-tokens-by-hand).

---

## 12. Promoting a standby by hand

`pg-promote.sh` does all of this ([`high-availability.md`](high-availability.md) §5). Do it by
hand only if a step it ran printed `WARN:`. Stop the old primary first.

**1. Promote the database.** On B:

```console
$ doas su postgres -s /bin/sh -c 'pg_ctl -D /var/lib/postgresql/17/data promote'
$ doas su postgres -s /bin/sh -c "psql -d fastpki -tAc 'select pg_is_in_recovery()'"
f
```

On a mesh node, clear the setting B inherited from A, which names a standby B no longer has:

```bash
doas su postgres -s /bin/sh -c "psql -d fastpki -c \"ALTER SYSTEM SET synchronized_standby_slots = ''\" -c 'SELECT pg_reload_conf()'"
```

**2. Stop marking B as a standby.**

```bash
doas sed -i '/^STANDBY_OF=/d' /etc/conf.d/fastpki
```

Left in place, B's Postgres refuses to start on its next restart, and the Replication page
still calls B a standby.

**3. Make B's own `PG_CONNINFO` fit its new role.** In `/etc/fastpki/bootstrap.conf`, list B
first in `host=` and set `sslrootcert=/var/pki/tls/pg/ca.crt`.

**4. Issue B's database certificate, if B has none from the pair's CA.** This happens when B
was joined without the CA keys. B's applications then refuse B's self-signed database
certificate, and `pg-tls` cannot connect either, so connect once without verification:

```bash
doas su -s /bin/sh fastpki -c "PG_CONNINFO='host=127.0.0.1 port=5432 dbname=fastpki user=fastpki password=<PASSWORD> sslmode=require connect_timeout=5' \
  fastpki-ca --config /etc/fastpki/bootstrap.conf pg-tls --if-needed"
```

`<PASSWORD>` is the database password in `PG_CONNINFO`. `PG_CONNINFO` from the environment
overrides the file for this command only. Every later connection verifies normally.

**5. Replace self-signed listener certificates, if any remain:**

```bash
doas su -s /bin/sh fastpki -c 'fastpki-ca --config /etc/fastpki/bootstrap.conf renew-service-certs --re-issue-self-signed'
```

**6. Restart the protocol services**, so they read the new certificates:

```bash
for s in ocsp cmp scep est acme ms web store; do doas rc-service -s fastpki-$s restart; done
```

On compose, run `./pg-promote.sh` in `deploy/`; it does the same through `docker compose`.

---

## 13. Copying keys between the tokens by hand

Each host's nightly job copies the keys it is missing, and `ha-join-pair.sh` and **Sync keys
now** run the same copy at once. Do it by hand to copy one CA, or when the hosts have
different token PINs and `ha-join-pair.sh` was not used.

**Give each host the other's PIN** (skip this if both hosts share one PIN). Print A's PIN on
A:

```bash
doas cat /var/pki/tls/pin
```

and install it on B:

```bash
doas install -m 0600 -o fastpki -g fastpki /dev/stdin /var/pki/tls/srcpin <<'PIN'
(A's PIN, pasted)
PIN
```

Then B's PIN into A's `/var/pki/tls/srcpin` the same way. On compose, with the other host's
PIN in `other-pin.txt`:

```sh
docker compose run --rm --no-deps --user 0:0 --entrypoint sh \
    -v "$PWD/other-pin.txt":/in/srcpin:ro certgen -ec \
    'tr -d "\r\n" < /in/srcpin > /var/pki/tls/srcpin; chown fastpki:fastpki /var/pki/tls/srcpin; chmod 600 /var/pki/tls/srcpin'
```

The file must be owned by `fastpki`; otherwise it is ignored.

**Copy every missing key**, on the host that is missing them:

```sh
# compose
docker compose exec web fastpki-ca --config /app/config/bootstrap.conf \
  key sync --from-peers --source-pin-file /var/pki/tls/srcpin
# native or cloud: run the nightly job, which passes srcpin itself
doas /etc/periodic/daily/fastpki-certrenew
```

**Copy one CA** from a named host:

```sh
# compose
docker compose exec web fastpki-ca --config /app/config/bootstrap.conf \
    key replicate <ca-id> --from <peer-address>:12345 --source-pin-file /var/pki/tls/srcpin
# native or cloud, as the fastpki user
doas su -s /bin/sh fastpki -c \
    'fastpki-ca --config /etc/fastpki/bootstrap.conf key replicate <ca-id> --from <peer-address>:12345 --source-pin-file /var/pki/tls/srcpin'
```

Leave out `--source-pin-file` when both hosts share one PIN.

If the copy fails with `C_Initialize failed (rc=48)`, the tunnel on the source host has not
admitted this host yet. Read the source host's `p11-tls` log; if it still rejects this host's
certificate a minute after both hosts started, restart the tunnel there
(`docker compose restart p11-tls`, or `doas rc-service fastpki-p11-tls restart`).
