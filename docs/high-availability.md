# FastPKI — High Availability

**What this gives you:** a Postgres standby on a **second host**, promotable without
third-party tooling (no Patroni/etcd/repmgr) and without restarting the applications.

## Contents

- [1. What a standby is](#1-what-a-standby-is)
- [2. How it works](#2-how-it-works)
- [3. Docker Compose (the packaged path)](#3-docker-compose-the-packaged-path)
- [4. Configure it manually (VM / native deploys)](#4-configure-it-manually-vm--native-deploys)
- [4a. The pair's one address, in a cloud VPC](#4a-the-pairs-one-address-in-a-cloud-vpc)
- [5. Restoring redundancy after a promotion](#5-restoring-redundancy-after-a-promotion)
- [5a. Updating the pair without interrupting service](#5a-updating-the-pair-without-interrupting-service)
- [6. Restoring the database without downtime](#6-restoring-the-database-without-downtime)
- [7. Gotchas (each one is a real failure mode)](#7-gotchas-each-one-is-a-real-failure-mode)
- [8. This is NOT cross-DC mesh replication](#8-this-is-not-cross-dc-mesh-replication)
- [9. App-tier HA — scaling the protocol services behind a load balancer](#9-app-tier-ha--scaling-the-protocol-services-behind-a-load-balancer)

⚠️ **What this covers is the DATABASE.** Whether it covers the *data center* depends entirely
on where the CA key is:

- **The protocol services are NOT stateless.** They are stateless over HTTP and emphatically
  not for signing: every replica needs the same `pkcs11:` handle. With the bundled SoftHSM
  that handle resolves through a socket on **one host's** volume, so a replica anywhere else
  has no key and cannot issue a certificate. Promote the database onto a second host with a
  local token and you get a console, reads, and no issuance.
- **A second host can sign only if it holds the key.** That is either an HSM appliance — the
  same `PKCS11_MODULE` loaded by every host, with the key living in the appliance — or the
  key present in that host's OWN token. After either, the second host issues certificates
  following a promotion.
- **⚠️ Reachability is not failover.** Reaching one host's token over the network would move
  the single point of failure rather than removing it: such a deployment survives losing the
  database host and not the token host, because every node that signs depends on that one
  machine — and certificates issued under its key could never afterwards be renewed or
  revoked. FastPKI therefore has no such arrangement; `/run/p11/pkcs11.sock` is always the
  node's own token.
- **What removes it is a key in every token.** `P11_TLS` is the channel over which a CA key
  is replicated from one node's token into another's, by envelope encryption over the token
  API. Each node then signs from its own token and depends on no peer. Run on the node that
  needs the key:

  ```sh
  # Compose
  docker compose exec web fastpki-ca --config /app/config/bootstrap.conf \
      key replicate <ca-id> --from <peer-address>:12345
  # native or cloud, as the fastpki user
  doas su -s /bin/sh fastpki -c \
      'fastpki-ca --config /etc/fastpki/bootstrap.conf key replicate <ca-id> --from <peer-address>:12345'
  ```

  ⚠️ **EVERY PRIVATE KEY AN HA DEPLOYMENT NEEDS IN ORDER TO SERVE IS GENERATED
  REPLICABLE, AND THE CHOICE IS PERMANENT.** `CKA_EXTRACTABLE` is fixed when a key is
  generated and PKCS#11 does not allow granting it afterwards, so a key created without it
  can never be copied to the other host. That is two decisions, not one, and each is
  offered in the console and on the command line:

  - **Every CA, the root included** — tick **replicable key** on the console's New CA form,
    or `fastpki-ca create … --replicable` (deployment.md §4.3). Without it there is no
    repair short of building the hierarchy again and re-issuing everything under it. A
    **renewal with a new key** creates that key and does not inherit the choice, so tick it
    there too. Check each CA on the host that created it: `fastpki-ca key list <ca-id>` ends
    each key's line with `[in this node's token, replicable]`, and the console's
    Replication page marks a key that is not with *not replicable*.
  - **The OCSP responder, CMP RA and SCEP RA credentials** — tick **replicable key** on
    *Inventory → Request* with the key in the HSM, or `renew-service-certs
    --create-missing --replicable` (§4.4a). Each has its own key, generated in this node's
    token, and the same rule applies to all three.

    ⚠️ **Or tell the scheduled run, before it does it for you.** `certrenew` (and each
    Kubernetes server's `renew` container) runs `renew-service-certs --create-missing` with no
    flags, so on a pair
    a credential it creates first is one the standby can never receive — `CKA_EXTRACTABLE` is
    fixed when a key is generated and cannot be granted afterwards. Set
    **`SERVICE_KEYS_REPLICABLE=true`** on both hosts (the Config page, or `fastpki-config set`)
    and the scheduled run generates them replicable too. Set it when you build the pair, not after:
    it changes what the NEXT key generation does, and nothing can repair a key already generated.

  Every CA key algorithm can be replicable: RSA, RSA-PSS, EC P-256/P-384/P-521, Ed25519,
  Ed448 and ML-DSA.

  Both matter and they fail differently. Miss the CAs and the survivor cannot issue at all.
  Miss the credentials and it issues perfectly over EST and ACME — which sign from the CA —
  while CMP refuses every transaction, OCSP answers `internalerror` and SCEP serves nothing.
  The second is the nastier of the two precisely because the deployment looks alive.

  ⚠️ **AND THE PAIR NEEDS ONE NAME, DECIDED BEFORE THE CA IS CREATED.** The CRLDP and AIA
  URLs a CA certificate carries are derived when it is issued, from `BASE_URL` where it is
  set and `PKI_DNS` otherwise (deployment.md §4.3). Create the hierarchy on the primary with
  that host's own FQDN and every certificate names **the host that a failover kills**:

  ```
  # the issuing CA, created on the primary, after the primary is gone
  X509v3 CRL Distribution Points: URI:http://<primary>:8080/root.crl        <- unreachable
  ```

  Leaves are unaffected — the survivor issues those under its own name — so the symptom is
  narrow and appears only under strict validation, at depth 1:
  `unable to get certificate CRL`. Measured on a promoted pair: the survivor served the
  identical CRL at its own address with HTTP 200, while the URL inside the CA certificate
  answered nothing.

  A certificate cannot be told a new URL after it is issued, so decide this **before**
  `fastpki-ca create`: set `BASE_URL` to a name that resolves to whichever host is live —
  a shared DNS name or VIP in front of the pair — and create the CAs with it in place.
  [`deployment.md`](deployment.md) §9.7 sets out the same choice for a mesh.

  The repair, if the hierarchy already carries a dead host's name, is to re-issue the CA
  certificates under the SAME keys with the URLs corrected. Their serials change and
  nothing issued under them becomes invalid, because leaves chain by key and name.

  ⚠️ **The root needs it as much as the issuing CA does.** A non-replicable root survives
  only as long as the host holding it. Lose that host and the survivor keeps issuing,
  renewing and revoking under the sub CA it has, but no further sub CA can ever be created
  and the root is gone for good — so the deployment can no longer be extended or re-keyed,
  only run down. [`architecture.md`](architecture.md) §5–§6 is the design record.

  A replicable key survives losing its host and can also be copied by anyone who reaches the
  token, so it is a flag you set rather than something FastPKI infers from the deployment's
  shape. For a pair the answer is almost always yes; for a mesh node
  [`deployment.md`](deployment.md) §9.7 sets out why it is opt-in.

Neither SoftHSM nor p11-kit has a heartbeat, quorum or replica, so nothing decides on its own
that a token has died, and FastPKI has no mechanism that reacts to one dying.

⚠️ **The several `pkcs11:` URIs a CA key reference may hold are not that mechanism.** They
are the CA's keys across its generations — a re-key adds a certificate and the key that goes
with it, both stay live through the rollover, and the certificate being signed under selects
its own key from the list. Every candidate is opened through the one PKCS#11 module the
process has, so the list picks a different token on that module and never a different
machine. What survives the loss of a host is an appliance presenting several tokens, or the
key replicated into each node's own token as above.

Layers covered here:
- **Database redundancy** (§1–§8) — the hot standby; the stateful, hard part.
- **App-tier scaling** (§9) — N replicas behind *your* load balancer, which is genuine for
  HTTP throughput and is bounded by the key-access rule above.

> **Status.** §3 is the compose path (`deploy/ha-join.sh` + `STANDBY_OF`). §4 is the path for
> VM and native deploys, cloud nodes included: `deploy/ha-join-pair.sh` joins the pair
> in one command by running `ha-join.sh` on both hosts, and §4's steps are what it does.
> `deploy/pg-promote.sh` performs the promotion on either; a native node has it installed as
> `/usr/share/fastpki/pg-promote.sh`. It detects which deployment it is on, running `psql` and `pg_ctl`
> through `docker compose` on the packaged path and as the `postgres` system user on a
> native or cloud host, where it also edits `/etc/conf.d/fastpki` and
> `/etc/fastpki/bootstrap.conf` instead of `.env` and the compose override. `tests/ha_failover.sh` proves the promotion and app-re-homing
> mechanism against a Postgres pair it builds itself. This is **distinct from cross-DC mesh
> replication** — see §8.

---

## 1. What a standby is

Inside **one** data center, **two** things hold state: Postgres, and the token holding the
CA private keys. Every FastPKI protocol binary (`web`, `ocsp`, `est`, `acme`, `cmp`,
`scep`, `ms`, `store`) is stateless *in itself* — it reads and writes the DB and nothing
else — but signing goes through a `pkcs11:` handle, and that handle has to resolve to the
same key from wherever the replica runs.

So making the DATABASE highly available is what this document does, and it is sufficient
for a data center only when the key is reachable from more than one host (a network HSM).
With the bundled SoftHSM the token is the second stateful thing and it does not move:

```
          fastpki-web / ocsp / est / acme / …   (stateless over HTTP, N of them)
                   │
                   │  PG_CONNINFO = host=A,B port=5432,5432
                   │                target_session_attrs=read-write
           ┌───────┴────────┐
           ▼                ▼
   ┌───────────────┐  WAL   ┌───────────────┐
   │  HOST A       │ ─────► │  HOST B       │   hot copy of the SAME database,
   │  PRIMARY (RW) │ stream │  STANDBY (RO) │   read-only until promoted
   └───────────────┘        └───────────────┘
     two machines — that is what makes losing one survivable
```

The standby is a **byte-for-byte hot copy** of the same database, kept current by
Postgres streaming replication, read-only until you promote it.

⚠️ **Both halves on one machine is not this.** A second Postgres beside the first covers
the database process dying and nothing else — not the disk, the kernel, the power supply or
the host. FastPKI does not ship that arrangement.


---

## 2. How it works

Three native pieces, nothing bolted on:

### 2.1 Streaming replication (Postgres does this)
The standby is seeded once with `pg_basebackup` from the primary, then continuously
streams the primary's WAL. It stays a read-only mirror until promoted.

### 2.2 Automatic app-side failover (libpq multi-host + reconnect)
FastPKI passes `PG_CONNINFO` **verbatim** to libpq, so you list **both** hosts and let
libpq choose the writable one:

```
PG_CONNINFO=host=<primary-address>,<standby-address> port=5432,5432 dbname=fastpki user=fastpki \
  sslmode=verify-full sslrootcert=/var/pki/tls/pg/ca.crt \
  target_session_attrs=read-write connect_timeout=3
```

- `target_session_attrs=read-write` → libpq **skips the read-only standby** and connects
  to the primary during normal operation.
- When the primary dies, the app's cached connection goes `CONNECTION_BAD`. Before its
  next statement the app calls `PQreset` (the *reconnect-before-issue* path), which
  **re-runs the whole multi-host connect** — the dead primary is skipped, and once the
  standby is promoted (now read-write) the app lands on it. **No restart.**
- `connect_timeout=3` keeps a dead host from stalling the reconnect.

### 2.3 Manual promotion
Promotion is a deliberate operator action: `pg_ctl promote` on the standby. The instant
it becomes read-write, the apps re-home themselves on their next query. Between the crash
and the promote, writes are correctly **refused** (there is no writable node) — so there
is **no split-brain** where the app silently writes to a read-only replica.


---

## 3. Docker Compose (the packaged path)

Host A is the existing deployment; host B is the new machine that will hold the standby.

### The join, in one command

1. **Install both hosts with `./install.sh`**, answering yes to "Will this data center have a
   standby" (`HA_ENABLED=yes`). On A that answer has to be given before any CA exists: it is
   what turns the key tunnel on and creates the OCSP, CMP RA and SCEP RA keys copyable. B is
   installed like any other server, with the same `DATACENTER_ID` and `PKI_DNS` as A and its
   own `PG_BIND`; the join replaces its database.
2. **Create the CAs on A copyable** (`--replicable`, or **replicable key** in the console), or
   the standby can never sign with them.
3. **From your own machine**, the one you SSH to both hosts from:

   ```bash
   deploy/ha-join-pair.sh --primary admin@<A> --standby admin@<B> -i <ssh key>
   ```

It checks both hosts, copies A's database to B, points both hosts' services at both, copies
the CA keys between the two tokens, issues B its own database certificate from the pair's CA,
and then lists B first in B's own services. It takes about two minutes and ends like this
(measured on a lab pair):

```
ha-join-pair: standby: holds every key it needs to serve
ha-join-pair: primary: holds every key it needs to serve
ha-join-pair: standby: database certificate issued from the pair's CA
ha-join-pair: standby: its services now reach the standby first, then the primary
ha-join-pair: done: admin@192.0.2.21 streams from admin@192.0.2.20 and holds the CA keys.
```

Run it again at any time: a standby already streaming from A is not copied a second time.
The rest of this section is what it does, for doing a step by hand or understanding a
failure. `./ha-join.sh` in `deploy/` is the part that runs on each host: on B as
`./ha-join.sh <A-address> primary-ca.crt --primary-password-file <f>`, on A as
`./ha-join.sh --on-primary <B-address>`.

**On host A, once.** The standby dials A by address under `sslmode=verify-full`, so A's
transport certificate has to carry that address, and A's `PG_BIND` has to be routable
rather than loopback. `install.sh` does both whenever you give it a real address; on a
deployment that was installed on loopback:

```sh
# put a routable address in A's .env as PG_BIND, then:
docker compose up -d                                        # so the new value is in scope
docker compose exec web fastpki-ca pg-tls <ca-id>           # re-issue, naming that address
docker compose restart postgres                             # or wait ~30s for the reload
```

Then export A's trust anchor and copy it to B — it is the one thing B cannot derive for
itself, because B has no way to know who A is until it has it:

```sh
docker compose exec postgres cat /pki/tls/pg/ca.crt > primary-ca.crt
scp primary-ca.crt hostB:/opt/fastpki/deploy/
```

**On host B.** Install it with `./install.sh` like any server, or unpack the same release and
write `.env` by hand. An installed B has a database of its own, which `ha-join.sh` replaces
with a copy of A's: it stops B, removes B's data volume, sets `STANDBY_OF` and starts B
again, and Postgres then copies A's database by `pg_basebackup` on its first start. It refuses
a B whose database holds a CA, unless given `--replace-local-database`.

`POSTGRES_PASSWORD` must equal A's — B authenticates to A as the `fastpki` role, and
`ha-join.sh --primary-password-file` writes it — and the rest are this host's own. Written by
hand, B's `.env` is:

```sh
cat > .env <<EOF
POSTGRES_PASSWORD=<the same value as A>
FASTPKI_PIN=<a fresh secret for THIS host's token>
FASTPKI_IMAGE=<the same image A runs>
BASE_URL=<the SHARED name in front of the pair — the SAME value as A>
PKI_DNS=<the SHARED name in front of the pair — the SAME value as A, not this host's FQDN>
PG_BIND=<this host's address, so clients can reach it once it is promoted>
COMPOSE_PROFILES=ocsp,est,acme,cmp,ms,store,scep,p11tls
DATACENTER_ID=<the SAME id as A — a pair is one data center twice>
HA_ENABLED=true
P11_TLS=on
SERVICE_KEYS_REPLICABLE=true
EOF
```

The last three lines are what `install.sh` writes on A when you answer yes to "Will this data
center have a standby" (`HA_ENABLED`), and B needs the same: `P11_TLS=on` creates the key
tunnel's certificate in B's token, the `p11tls` profile runs the tunnel, and
`SERVICE_KEYS_REPLICABLE=true` creates any OCSP, CMP RA or SCEP RA key copyable, so the
two hosts can give each other the keys either one creates. A missing on A cannot be added
afterwards for keys that already exist; re-run `install.sh` on A with `HA_ENABLED=yes` before
any CA is created.

⚠️ **TWO KINDS OF NAME IN ONE FILE, WITH OPPOSITE RULES — this is the line to get right.**

| key | value | why |
|---|---|---|
| `BASE_URL`, `PKI_DNS` | the **shared** name in front of the pair, identical on both hosts | it is what CLIENTS use, and it is baked into every certificate's CRLDP, AIA and SANs. A pair advertises ONE address: that is what makes a failover invisible, and it is why per-host URLs are **not** the answer — a certificate already issued cannot be told a new URL, and every client holding one would have to be reconfigured. |
| `PG_BIND`, `PG_TLS_SANS` | **this host's own** address | they are for replication and for the apps' own multi-host conninfo, which must reach a specific machine. `PG_BIND` is also what identifies this host in `p11_transport`, so on a pair it is **required**: without it both hosts publish their token-transport certificates under the shared name and the second overwrites the first, after which no key can be replicated (§3). |

Set the first pair to the host's own FQDN and the deployment works perfectly until the
promotion, then serves CA certificates naming a host that is gone. Nothing warns, because
while both hosts are up that name resolves.

⚠️ **`DATACENTER_ID` must match A's, and nothing supplies it for you.** `ha-join.sh` refuses
the join if it is unset, if it has no row in the primary's `datacenters` table, or if the
primary is running as a different data center — so a mistake here stops the join rather than
surfacing at a promotion. Write it yourself, from A's `.env`. It is the high 15 bits
of every serial this node assigns. Absent, `set_random_serial()` produces **full-width serials
with no prefix**, so from the moment this host is promoted everything it issues sits outside
the data center's partition — permanently, because a serial cannot be changed after
issuance. Nothing warns: the certificates are valid and enrolment succeeds. It surfaces on a
local restore, which `certs_dc_range` refuses for a prefix-less row, and on any later
expansion into a mesh. Measured on a promoted pair: the primary issued `1e5c232e…` and the
survivor `5457d36a…`.

⚠️ **`FASTPKI_PIN` is not optional and its absence stops the node dead.** The token holds
every CA private key, so it refuses to be created under a default PIN: with `.env` carrying
only `POSTGRES_PASSWORD` the `token` container exits with `FATAL - FASTPKI_PIN is not set`,
`docker compose up -d` ends in `dependency failed to start: container fastpki-token-1 is
unhealthy`, and nothing else — Postgres included — ever starts. It is B's **own** PIN for
B's own token; it has nothing to do with A's, and the two need not match.

⚠️ **A HOST THAT WAS A DEPLOYMENT BEFORE NEEDS BOTH VOLUMES CLEARED, not just the data
directory.** `pgdata` holds the database; `pki-data` holds the CA material and the Postgres
certificate. Clearing only the first leaves B streaming correctly while serving a
certificate issued by the root its previous life created — a root this deployment does not
have. Nothing replaces it afterwards, and it surfaces only when you promote B. So on a reused
host, before the join:

```sh
docker compose down -v      # or: docker volume rm fastpki_pgdata fastpki_pki-data
```

`ha-join.sh` refuses both cases rather than letting them through, but the volumes are yours
to remove — be certain neither holds a CA key you still need.

Then join:

```sh
./ha-join.sh <primary-address> primary-ca.crt   # installs the anchor, records STANDBY_OF
docker compose up -d                            # seeds with pg_basebackup, then streams
```

`ha-join.sh` verifies before it changes anything that the anchor really validates A **and**
that A's certificate covers the address you gave, so a mismatch is one sentence here rather
than a restart loop later. Confirm the result on B:

```sh
docker compose exec postgres psql -U fastpki -d fastpki -c 'SELECT pg_is_in_recovery()'
```

`t` means it is a standby. On A, `pg_stat_replication` shows B's address with
`state = streaming`.

**Then point the applications at both hosts, on both hosts.** Nothing else re-homes them.

⚠️ **`fastpki-config set PG_CONNINFO` cannot do this, by design.** `PG_CONNINFO` is the one
key `is_bootstrap_config_key()` returns true for, so the database overlay is skipped for it —
a deployment must not be able to reconfigure how it reaches its own database from a row
inside that database. `set` leaves `get` reporting `not set: PG_CONNINFO` and the apps
keep the value they started with, so this reads as a command that ran and did nothing.

The apps take it from their environment, and `deploy/docker-compose.yml` supplies a literal
`host=postgres` with only the password interpolated. `ha-join.sh` writes this override on **each** host — on B when it joins, on A with `--on-primary`. By hand it is:

```sh
# deploy/docker-compose.override.yml — one entry for EVERY service that reaches the
# database, not only the protocol listeners: web, est, acme, cmp, ms, scep, ocsp, store,
# certrenew AND p11-tls. On the standby a service left out keeps pointing at the local
# read-only Postgres and either restart-loops or silently fails to publish.
services:
  web:
    environment:
      PG_CONNINFO: "host=<THIS host>,<the other> port=5432,5432 dbname=fastpki user=fastpki
        password=<the shared one> sslmode=verify-full
        sslrootcert=/var/pki/tls/pg/primary-ca.crt target_session_attrs=read-write"
```

⚠️ **LIST THIS HOST FIRST, and write a different order on each host — but NOT until that host
can be verified.** libpq stops at the first host whose certificate it cannot verify and never
tries the second (above), so with the PEER first a host that is merely being rebuilt takes this
one's tooling down with it. With THIS host first, a broken node only ever breaks itself, and a
standby still re-homes correctly because `target_session_attrs=read-write` skips its own
read-only database in the ordinary way — a read-only rejection is not a connection failure.

⚠️ **A FRESHLY JOINED STANDBY IS ITSELF THE UNVERIFIABLE HOST, so it starts the other way
round.** Until it has a database certificate from the pair's CA it is serving the self-signed
pair `certgen` wrote, which the anchor `ha-join.sh` placed cannot verify. Listed first, it breaks
every one of its own services: measured on a fresh pair, `web`, `est`, `acme`, `cmp`, `ms`,
`scep` and `store` all restart-loop and `p11-tls` logs *"could not publish this node's client
certificate"*, so the token tunnel never comes up either — and it cannot escape on its own,
because issuing its own certificate needs a CA key that arrives by `key sync`, which needs the
tunnel, which needs the database. `ha-join.sh` therefore writes the standby's file with the
PRIMARY first, and says so. Running `ha-join.sh` again reverses it once `key sync` has run,
`fastpki-ca pg-tls <ca-id>` has issued that host's own certificate, AND Postgres is serving
it. It checks the certificate Postgres serves, not the file: a new file is taken up within
30 seconds, and until then the services would still be offered the self-signed one.
`ha-join-pair.sh` does this for you, checking every 30 seconds, four times at most.

The primary's file, which `ha-join.sh --on-primary` writes, has its own address first and
`sslrootcert=/var/pki/tls/pg/ca.crt` — the primary is verifiable from the start, so the
steady-state order applies to it immediately.

```sh
docker compose up -d
```

⚠️ **On the STANDBY, the anchor is `primary-ca.crt`, not `ca.crt` — while it is a standby.**
`certgen` writes each host's own self-signed transport certificate over `pg/ca.crt` on every
`up`, so on B that file cannot verify A — the apps fail the handshake with
`certificate verify failed` while Postgres streams perfectly, because Postgres was pointed at
the out-of-band anchor `ha-join.sh` placed. Use that same path for the apps on B.

⚠️ **BOTH OF THOSE VALUES GO STALE AT A PROMOTION, and `pg-promote.sh` rewrites them for
you.** `ha-join.sh` writes the peer first and `primary-ca.crt` as the anchor, which is right for
a host that cannot yet be verified and wrong for the same host once it is the writer. Neither
is fatal alone, which is why it survives unnoticed: `target_session_attrs=read-write` still finds
the writer. But every new connection tries the peer first and waits out `connect_timeout`, and
the moment that peer is REBUILT — serving the self-signed pair again — libpq stops at the first
host it cannot verify and the promoted node's own tooling fails with an error naming the *other*
machine. Measured on a promoted pair mid-rebuild: `fastpki-config` and `fastpki-ca` both refused
to run on a node that was perfectly healthy. The anchor matters most: `primary-ca.crt` is a copy
of the old primary's `ca.crt`, so it verifies this node's own database only while both
certificates happen to come from the same CA. If you promote by hand rather than with
`pg-promote.sh`, reverse both yourself.

libpq keeps whichever of the two is read-write, so a promotion re-homes the applications
with no restart. A `PG_CONNINFO` naming only one host makes the standby unreachable at the
exact moment it matters.

⚠️ **BOTH HOSTS' POSTGRES CERTIFICATES MUST COME FROM THE SAME CA, or that re-homing lands
on a certificate the applications refuse.** libpq verifies whichever host it moves to
against `sslrootcert`, and B is serving the pair `certgen` self-signed at deploy time.
Nothing replaces it on its own: the console, EST, ACME and MS each generate a key in the token,
self-sign, and adopt a CA-issued certificate when one appears, but Postgres cannot — libpq's
`ssl_key_file` takes a filesystem path and cannot reference PKCS#11, so it keeps a file pair
that only an explicit `fastpki-ca pg-tls` re-issues. Run on the primary, that leaves B
untouched. So the anchor that verifies A cannot verify B, and after a promotion every
application on both hosts fails with `certificate verify failed` against a database that is
up and read-write.
The CLIs use that conninfo too, so the deployment cannot be repaired with its own tools:
recovery needs a hand-built conninfo naming a different anchor.

⚠️ **AND libpq DOES NOT FAIL OVER PAST A CERTIFICATE IT CANNOT VERIFY.** The multi-host
conninfo survives a peer that is DOWN or read-only — it moves to the next host and keeps
serving. It does not survive one that ANSWERS with an untrusted certificate: libpq stops at
that host and reports its error, and the healthy second host is never tried. Measured on a
pair, with everything else identical:

```
host=<bad>,<good>   ->  connection to server at "<bad>" failed: SSL error: certificate verify failed
host=<good>,<bad>   ->  1
```

with and without `target_session_attrs`, so it is the ordering and not the read-write
selection. The consequence is specific and easy to walk into: **rebuilding the old primary
as a standby (§5) puts it in exactly that state** — `down -v` clears `pki-data`, so it comes
back on the self-signed pair `certgen` writes, which the deployment's anchor refuses. From
that moment the SURVIVING primary's own CLI fails too, because its conninfo names the
rebuilt host first, and every `fastpki-ca` and `fastpki-config` call on a perfectly healthy
node stops with an error naming the other one.

So issue the rebuilt host's database certificate BEFORE it is reachable on the interconnect,
or accept that the pair's tooling is down until you do. Recovering from it needs the
hand-built conninfo above, naming the healthy host alone.

Each host certifies its OWN address without being told it: `pg-tls` and `certgen` read
`PG_BIND` from that host's environment, which the pair cannot share because it lives in
each host's `.env`. `PG_TLS_SANS` is for EXTRA names only, and in a pair it is one row for
two hosts — so do not put an interconnect address in it.

**And it happens on its own, once `PG_TLS_CA_ID` names the CA that issues it.** Each host's
nightly `certrenew` then keeps its own database certificate current, right after the key sync
that makes issuing possible. `ha-join.sh --on-primary` sets it when it is unset: to the CA
that issued the primary's database certificate, or else to the data center's one issuing CA.
By hand:

```sh
docker compose exec web fastpki-config set PG_TLS_CA_ID <ca-id>   # once, either host
```

The nightly job never chooses a CA itself: while `PG_TLS_CA_ID` is unset it does nothing and
says so each night. The run is a no-op once the certificate is already issued by that CA,
covers every name and is not near expiry — it does not issue a new one daily.

To bring a host up to date immediately rather than waiting for the nightly job:

```sh
docker compose exec web fastpki-ca pg-tls <ca-id>
```

`pg-tls` appends its issuing chain's root to `/var/pki/tls/pg/ca.crt`, so once both hosts
have run it `sslrootcert=/var/pki/tls/pg/ca.crt` verifies either of them. Postgres picks the
new certificate up within about 30 seconds, with no restart.

**Failing over.** On host B, promote its own Postgres — the standby IS the `postgres`
service on that host:

```sh
./pg-promote.sh postgres
```

⚠️ **Stop A's Postgres first.** Promotion does not demote anything: run this against a
healthy primary and you have two read-write databases and applications free to land on
either. See §4 Step 5.

⚠️ **A promoted B issues certificates only if it HOLDS the CA key.** With the bundled SoftHSM
that key is an object in A's token container, so B gets a console and reads and nothing
signed. What makes the other half true is a network HSM, or the key replicated into B's own
token over `P11_TLS`. This is the same rule stated at the top of this document, and it is the
one that decides whether a second host buys you a data center or a database.

### Replicating the CA key to the standby

Every CA must have been created with a replicable key, the root included (see the top of
this document), and each one is replicated separately — `key replicate` copies the CA you name.
Then, on BOTH hosts, publish the token transport material — `P11_TLS=on` and the `p11tls` profile in
`.env`, then `docker compose run --rm certgen`, which generates `p11-server` and `p11-client`
in each node's own token.

**The two ends admit each other through the database, but not on the first bring-up.** Each
host's `p11-tls` publishes both of its certificates into `p11_transport` at every start,
keyed by that host's name; the rows travel to the other host through the same replication
that carries everything else; and each `p11-tls` also runs `p11-clients-sync` and
`p11-servers-sync` **at start**, materialising what it finds into
`/var/pki/tls/p11/{clients,servers}` as `host-<name>.crt` with the hash links OpenSSL reads.

⚠️ **Two things follow, and a fresh pair hits both.**

*The standby cannot publish until its services point at the primary.* Its own Postgres is
read-only, so `p11-tls` there fails with `session is read-only` and logs `could not publish
this node's client certificate; peers cannot admit it until this succeeds`. The multi-host
`PG_CONNINFO` override below is what fixes it — so write that override **before** expecting
any of this to work, and give it to every service that touches the database, not only
the protocol listeners.

*Materialising at start is not enough on its own, so each `p11-tls` repeats it every minute.* The
host that started first admits the other within a minute of that host publishing. A host rebuilt
with a new transport keypair presents a certificate with the same name as the one it replaces, so
`p11-tls` also reloads stunnel whenever a certificate in `clients/` changes; OpenSSL would
otherwise keep verifying against the old one. Until the other host has been admitted, `key sync`
fails at the TLS handshake rather than at the token:

```
p11-tls (on the source): CERT: Pre-verification error: certificate not found in local
                         repository: self-signed certificate
                         Rejected by CERT at depth=0: CN=fastpki-p11-client-<id>
key replicate (on the standby): C_Initialize failed (rc=48)
```

`rc=48` is `CKR_DEVICE_ERROR` and names nothing about certificates, so read the SOURCE
host's `p11-tls` log before suspecting the PIN. If it still says this a minute after both hosts
have published, restart `p11-tls` on the source host:

```sh
docker compose restart p11-tls              # Compose
doas rc-service fastpki-p11-tls restart     # native or cloud
```

That table is keyed per HOST rather than per data center: a standby has no `DATACENTER_ID` of
its own, and a data center with two hosts in it needs room for both.

⚠️ **AND THE HOST IS IDENTIFIED BY `PG_BIND`, WHICH IS THEREFORE NOT OPTIONAL ON A PAIR.** The
id has to name the MACHINE, and the two hosts share `PKI_DNS` by design — so `PKI_DNS`
identifies the pair, not either host. Both publishing under it means the second overwrites the
first (the id is the primary key), and the symptom is this same `rc=48` with no certificate
error anywhere:

```
select host_id, dc_id from p11_transport;
 <the shared name> | 1          <- ONE row, for TWO machines

trust directory /var/pki/tls/p11/clients: 1 certificate(s)   <- should be 2
key sync: 5 missing, 0 replicated, 5 failed
```

So a pair whose hosts both carry only the shared name builds cleanly, streams cleanly, and
cannot replicate a single key — meaning a promotion yields a node that cannot sign. Set
`PG_BIND` to each host's own address, as Postgres already needs, and the two publish
separately.

**The keys then reach both hosts on their own too.** Each host's nightly `certrenew` runs

```sh
fastpki-ca key sync --from-peers
```

(inside the image — the runnable forms are below, under "To bring one up to date immediately")

which replicates every key that host needs in order to serve and does not have, naming none of
them: each CA whose key is missing from its token, **and the OCSP, CMP and SCEP RA
credentials**. Listener TLS keys are not included — each host answers under its own name and
already has its own. It runs after the trust sync above, because that is what materialises the
certificate the tunnel needs. A sync that could not complete retries in five minutes rather
than the next day.

It copies each missing key from whichever other host of the **same data center** holds it, and
it runs on both hosts, not only on B. A key is created in the token of whichever host created
it: the console behind the pair's one address serves the New CA form from either host, and the
nightly job creates missing credentials on whichever host gets there first. So A can be the one
missing a key, and B the one holding it. Hosts of other data centers are never asked, because in
a mesh `--replicable` is opt-in.

⚠️ **The credentials matter as much as the CAs and fail differently.** A pair missing the CA
keys cannot issue at all, which is found immediately. A pair missing the credentials issues
perfectly over EST and ACME — they sign from the CA — while CMP refuses every transaction,
OCSP answers `internalerror` and SCEP serves nothing. That is the worse of the two, because
the deployment looks alive: a bench against such a node reports `est 10/10, cmp 0/10`.

This matters most for a CA created *after* the pair was built. B receives its row through
database replication within moments and its key never, so without the sync B accumulates
CAs it cannot sign with — and every check short of issuing passes.

To bring one up to date immediately, run the same command by hand on the host that is missing keys —
**and pass the PIN file yourself** if the hosts have different PINs (a native pair runs its
nightly job instead, §4 Step 4):

```sh
docker compose exec web fastpki-ca --config /app/config/bootstrap.conf \
  key sync --from-peers --source-pin-file /var/pki/tls/srcpin
```

`fastpki-ca key replicate <ca-id> --from … --source-pin-file …` does a single named CA from the
host you name.

**Or from the console.** The **Replication** page (admin guide §12.5) shows, for both hosts, which
CA and credential keys each token holds and the result of each host's last key sync. It also
warns about the failures this document describes: `PG_BIND` unset, a one-host `PG_CONNINFO`, an
unverifiable database certificate, `PG_TLS_CA_ID` unset, a key that cannot be copied, and no
standby streaming. On either host's row, **Sync keys now** runs this same key sync on that host,
including `--source-pin-file` when `/var/pki/tls/srcpin` exists, whichever host served the page.

⚠️ **Give both hosts the same token PIN, or each needs the other's.** The wrap happens inside
the token the key is copied FROM, so the copying host logs in there, and each installer
generates its node's `FASTPKI_PIN` independently. The simplest arrangement is one PIN for the
pair: install B with A's `FASTPKI_PIN`, and no PIN file is needed on either host. Otherwise
place the other host's PIN at `/var/pki/tls/srcpin` on **each** host. For B,
`./ha-join.sh <A> primary-ca.crt --primary-pin-file <path>` installs A's. For A, copy B's
`FASTPKI_PIN` into that file by hand, owned by the service account:

```sh
# on A, with B's PIN in b-pin.txt
docker compose run --rm --no-deps --user 0:0 --entrypoint sh \
    -v "$PWD/b-pin.txt":/in/srcpin:ro certgen -ec \
    'tr -d "\r\n" < /in/srcpin > /var/pki/tls/srcpin; chown fastpki:fastpki /var/pki/tls/srcpin; chmod 600 /var/pki/tls/srcpin'
```

The nightly `certrenew` loop adds `--source-pin-file` on its own when that file exists;
`fastpki-ca` itself knows nothing about the path, so a command you type must name it. Without it
the run reaches the other host's token and stops there:

```
key replicate: C_Login to token 'fastpki' failed (rc=160): the PIN is wrong for THIS token
```

If the file is placed with the wrong owner, the flag is accepted and silently ignored, which reads
as the flag not having been passed.

Each host then signs from its own token and depends on the other for nothing, which is what
makes a promotion give you an issuer rather than only a database.

---

## 4. Configure it manually (VM / native deploys)

Two nodes in one DC — **node A = primary**, **node B = standby**. Both are ordinary native
installs (`install-native.sh`); a cloud node is one too. Only A's Postgres is live at first;
B's becomes a copy of it. On a cloud node you log in as `alpine` and run commands with
`doas`, as below; on another native host, run them as root and leave out `doas`.

**Where Postgres keeps its files on a native host.** Every path below follows from this:

| What | Path | Owner |
|---|---|---|
| the data directory | `/var/lib/postgresql/17/data` | `postgres` |
| the settings | `/etc/postgresql/postgresql.conf`, `/etc/postgresql/pg_hba.conf` | `postgres` |
| FastPKI's own settings (`listen_addresses`, the TLS files, replication), included from `postgresql.conf` | `/etc/fastpki/postgresql.conf.d/fastpki.conf` | root |
| the certificate Postgres serves, and the anchors Postgres itself dials with | `/var/lib/postgresql/tls/` | `postgres` |
| the same files, where FastPKI writes them and its services read them | `/var/pki/tls/pg/` | `fastpki` |

`/var/pki` is `fastpki:fastpki 0750`, so `postgres` cannot open anything under it. The
`fastpki-pgtls` service (`pg-tls-sync`) therefore copies `server.crt`, `server.key`, `ca.crt`
and `primary-ca.crt` from `/var/pki/tls/pg/` into `/var/lib/postgresql/tls/`, every 30
seconds. That gives one rule for every connection string:

- **A FastPKI service dials** (`PG_CONNINFO`): `sslrootcert=/var/pki/tls/pg/…`
- **Postgres itself dials** (`pg_basebackup`, a standby's `primary_conninfo`, a mesh
  subscription): `sslrootcert=/var/lib/postgresql/tls/…`

Get the second one wrong and the error is
`root certificate file "/var/pki/tls/pg/ca.crt" does not exist`, although the file is there.

The settings live outside the data directory, so `pg_basebackup` does not copy them. Each
host keeps its own `listen_addresses` and `pg_hba.conf`.

### The join, in one command

Run this from your own machine, the one that can SSH to both hosts:

```bash
deploy/ha-join-pair.sh --primary alpine@<A> --standby alpine@<B> -i ~/.ssh/fastpki_cloud_ed25519
```

`<A>` and `<B>` are the addresses you SSH to. On AWS they are the nodes' public IPv6
addresses, `1` and `1-standby` in `tofu output node_public_ipv6`.

It does Steps 1 to 4 below, in order, on the right host each time, and stops at the first one
that fails, with the reason. It reads the three things only the primary has — its database CA
certificate, its database password and its token PIN — over SSH and hands them to the other
host on standard input, so none of them is typed, pasted or written on your machine. It ends
by running the nightly job on each host until both hold every CA key they need.

It refuses to start unless:

- both hosts were installed with `P11_TLS=on` and their own `PG_BIND` (Step 1). On AWS that
  is what listing the data center in `standby_dcs` does;
- B's own database holds no CA. Joining replaces it with a copy of A's; if B's database is
  disposable, add `--replace-local-database`.

And it cannot finish unless the CA keys were created copyable (`--replicable`). A key that
was not can never leave A's token: the key step reports which one, and the standby can never
sign with it.

Run it again at any time: a standby already streaming from A is not copied a second time,
and every other step leaves a finished host as it is.

Without SSH from one machine to both hosts, run the two halves on the hosts themselves, as
root. On B, with A's `/var/pki/tls/pg/ca.crt`, A's database password and (if the two PINs
differ) A's `/var/pki/tls/pin` copied into files:

```bash
doas /usr/share/fastpki/ha-join.sh <primary-address> primary-ca.crt \
    --primary-password-file a-password [--primary-pin-file a-pin]
```

and then on A, with B's PIN in a file if they differ:

```bash
doas /usr/share/fastpki/ha-join.sh --on-primary <standby-address> [--standby-pin-file b-pin]
```

Steps 1 to 4 are what those two commands do, one at a time. Follow them by hand to understand
a failure, or to repeat a single step. Step 0 is a precondition neither command sets up: do it
first, on A.

### Step 0 — the certificate must name the address the standby dials
`sslmode=verify-full` checks the SAN, and a standby on another host dials the primary by a
routable address. `certgen.sh` certifies this host's `PG_BIND` alongside the internal names
(`postgres`, the FQDN, `localhost`, `127.0.0.1`), so a primary installed on a routable
address already carries it; one installed on loopback does not, and cannot be joined at all.

Check A's certificate first. On a cloud node this is already done: the installer set
`PG_TLS_SANS` to the interconnect address, and the `pg-tls` run in the deployment guide's
§12 issued the certificate from the data center's CA:

```console
$ doas openssl x509 -in /var/pki/tls/pg/server.crt -noout -ext subjectAltName -issuer
X509v3 Subject Alternative Name:
    DNS:postgres, DNS:localhost, IP Address:127.0.0.1, DNS:pki-dc1.example.org, IP Address:192.0.2.10
issuer=CN=Example DC1 Issuing CA G1
```

The address B dials (`192.0.2.10` here) must be in the list, and the issuer must be a CA,
not the certificate itself. If both hold, go to Step 1.

Otherwise the address goes in **this host's own** `/etc/fastpki/bootstrap.conf`, as an
extra name, and then a CA-issued certificate replaces the self-signed one:

```bash
printf 'PG_TLS_SANS=%s\n' <primary-address> >> /etc/fastpki/bootstrap.conf   # A, as B reaches it
# as the fastpki user: the token socket belongs to it, so as root the CA key cannot be opened
doas su -s /bin/sh fastpki -c \
    'fastpki-ca --config /etc/fastpki/bootstrap.conf pg-tls <ca-id>'
```

Postgres adopts the new pair within about 30 seconds; no restart is needed.

⚠️ **Write the file, not `fastpki-config set`.** That command writes the `config` TABLE, and
a pair replicates the whole database — so both hosts would read one row, and host B would
later be issued a certificate naming host A's address instead of its own, failing
verify-full at the moment of promotion against a database that is up. Each host's
`bootstrap.conf` is its own, and the database overlay only replaces keys that have a row,
so a per-host value written here stays per-host.

⚠️ **Name the CA.** With no argument, `pg-tls` falls back to `PG_TLS_CA_ID`, which is set in
Step 4 below; run before that, and with both empty, it exits without issuing anything.

### Step 1 — check both hosts before anything is copied

**The install answers, on both A and B.** Two of them decide whether the pair can work, and
both can only be set by the installer, so check them now, while B is still empty:

```console
$ doas grep -E '^(PG_BIND|P11_TLS)=' /etc/conf.d/fastpki
PG_BIND=192.0.2.10
P11_TLS=on
$ doas rc-service fastpki-p11-tls status
 * status: started
```

- `PG_BIND` must be this host's **own** address (A's on A, B's on B), never `127.0.0.1` and
  never the shared name. Postgres listens on it, and the host publishes its key-transport
  certificates under it. The two hosts share `PKI_DNS`, so without their own addresses the
  second host's certificates overwrite the first's and no key can be copied.
- `P11_TLS=on` is what lets Step 4 copy the CA keys from A's token into B's. Without it, B
  holds no key, and a promoted B cannot issue anything.

Adding `P11_TLS=on` to the file by hand does not work. The installer is what creates the
tunnel's certificate in the token and enables the `fastpki-p11-tls` service; with the line
added by hand, `rc-service fastpki-p11-tls status` still says `stopped` and Step 4 finds no
peer. Run the installer again with the right answers instead, which is simplest on B now,
before it holds a copy of A's database. On a cloud node, the AWS module installs both nodes
of every data center listed in `standby_dcs` with `P11_TLS=on`, and opens the tunnel's port
12345 between them.

**Postgres listens on A's address.** On A:

```console
$ netstat -ltn | grep 5432
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN
tcp        0      0 192.0.2.10:5432         0.0.0.0:*               LISTEN
```

Keep the `-n`. Without it, `netstat` prints the port by its service name
(`ip-192-0-2-10.ec2.internal:postgresql`), and `grep 5432` then matches only the Unix
socket, which looks as if Postgres were not listening on the address at all.

**Replication, on A.** The native installer has already configured A to serve a standby.
Check it rather than editing anything:

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

B streams as the `fastpki` role, with A's database password. That role is already allowed
to replicate (`rolreplication` is `t` above), and `pg_hba.conf` already admits it over TLS
twice. The
`replication` line is for the stream. The `all` line is for the ordinary connection to the
`fastpki` database that the slot-sync worker opens; without it slot synchronisation is
refused, and nothing in any log says so. `hostssl` makes TLS mandatory, and B's
`sslmode=verify-full` in Step 2 checks A's identity against the anchor. There is no
separate replication role to create.

Read A's database password now. B needs it in Steps 2 and 3:

```bash
doas sed -n "s/^PG_CONNINFO=.*password=\([^ ]*\).*/\1/p" /etc/fastpki/bootstrap.conf
```

Client-certificate auth (`cert` instead of `scram-sha-256`) is a reasonable hardening step,
but it is four more pieces, not a one-word change: `ssl_ca_file` on the primary so the server
can verify a client, a client certificate whose subject CN is exactly `fastpki` issued to
node B, and `sslcert=`/`sslkey=` added to BOTH the `pg_basebackup` conninfo and the
`primary_conninfo` it writes. Leave any one out and the standby cannot connect at all.

### Step 2 — standby (node B): seed + stream

**2a. Give B the primary's anchor.** B verifies A with `sslmode=verify-full`, and B's own
`/var/pki/tls/pg/ca.crt` cannot do it: until B is issued a certificate by the pair's CA in
Step 4, that file holds B's own self-signed certificate. So B needs a copy of A's. Print it
on A:

```bash
doas cat /var/pki/tls/pg/ca.crt
```

and paste it on B, as `primary-ca.crt` beside B's own files:

```bash
doas install -m 0644 -o fastpki -g fastpki /dev/stdin /var/pki/tls/pg/primary-ca.crt <<'PEM'
-----BEGIN CERTIFICATE-----
(A's certificate, pasted)
-----END CERTIFICATE-----
PEM
doas /usr/libexec/fastpki/pg-tls-sync once
```

`pg-tls-sync once` copies it to `/var/lib/postgresql/tls/primary-ca.crt` for Postgres
straight away, instead of within 30 seconds. B's services read the first copy and B's
Postgres reads the second.

Now prove the connection B's Postgres is about to make, as the user that will make it. Give
A's password when asked:

```console
$ doas su postgres -s /bin/sh -c 'psql "host=<primary-address> port=5432 dbname=fastpki user=fastpki sslmode=verify-full sslrootcert=/var/lib/postgresql/tls/primary-ca.crt" -tAc "select 1"'
Password for user fastpki:
1
```

`certificate verify failed` means the pasted anchor is not the one A's certificate chains to.
`root certificate file ... does not exist` means the copy under `/var/lib/postgresql/tls/`
is not there yet: run `pg-tls-sync once` again.

**2b. Stop B and empty its data directory.** Until it is joined, B is a separate deployment
with an empty database of its own, and everything in that database is about to be replaced.
Stop the services that use it first, so they do not restart in a loop against a database
that is not there:

```bash
for s in web est acme cmp ms scep ocsp store; do doas rc-service -s fastpki-$s stop; done
doas rc-service postgresql stop
doas su postgres -s /bin/sh -c 'rm -rf /var/lib/postgresql/17/data/*'
```

`-s` stops a service only if it is running, so a protocol this deployment does not serve is
skipped quietly. `fastpki-token` keeps running. `fastpki-pgtls` stops together with Postgres,
because it depends on it, and 2d starts it again.

**2c. Copy A's database.** `-R` writes `standby.signal` and the `primary_conninfo` for you,
from the conninfo given here, so the anchor named here is the one B's Postgres uses from now
on. Give A's password when asked:

```bash
doas su postgres -s /bin/sh -c 'pg_basebackup -D /var/lib/postgresql/17/data -R -X stream -c fast \
  -C -S <standby-slot> \
  -d "host=<primary-address> port=5432 user=fastpki dbname=fastpki sslmode=verify-full sslrootcert=/var/lib/postgresql/tls/primary-ca.crt"'
```

`<standby-slot>` is the name of the replication slot B holds on A: `fastpki_` followed by B's
own address (its `PG_BIND`), in lower case, with every character other than a letter or a
digit written as `_`. For a standby at `192.0.2.11` it is `fastpki_192_0_2_11`. Every
deployment path names it this way, so `ha-join.sh`, the compose Postgres service and a
Kubernetes server all agree on it.

⚠️ `-R` does NOT invent a `dbname`, and without one the slot-sync worker never connects.
It also must be a REAL database — `dbname=replication` is the walsender pseudo-database
and looks correct in `primary_conninfo` while synchronising nothing. Together with
`-C -S` (which is what writes `primary_slot_name`) and the two settings below, these are
the four things PG17 checks; miss any one and the symptom is identical — no synced
slots, and nothing in any log you are watching.

**2d. Make B a standby, and start it.** These two settings go in a file of their own beside
FastPKI's, which `pg_basebackup` does not touch:

```bash
printf 'sync_replication_slots = on\nhot_standby_feedback = on\n' \
    | doas tee /etc/fastpki/postgresql.conf.d/standby.conf >/dev/null
doas chown root:postgres /etc/fastpki/postgresql.conf.d/standby.conf
doas chmod 640 /etc/fastpki/postgresql.conf.d/standby.conf
doas rc-service postgresql start
doas rc-service fastpki-pgtls start
```

The last line is easy to miss. `fastpki-pgtls` depends on `postgresql`, so stopping Postgres
in 2b stopped it too, and starting Postgres does not bring it back. It is the service that
hands Postgres a new certificate, so without it B keeps serving its self-signed one after
Step 4 issues it a proper one.

Check both ends. On B:

```console
$ doas su postgres -s /bin/sh -c "psql -d fastpki -tAc 'select pg_is_in_recovery()'"
t
```

On A, B must appear, streaming:

```console
$ doas su postgres -s /bin/sh -c "psql -d fastpki -xc 'select client_addr, state, sync_state from pg_stat_replication'"
-[ RECORD 1 ]----------
client_addr | 192.0.2.11
state       | streaming
sync_state  | async
```

On a **mesh node**, point A at the standby's slot. This is what stops a peer data center from
receiving changes the standby has not received yet:

```bash
doas su postgres -s /bin/sh -c "psql -d fastpki -c \"ALTER SYSTEM SET synchronized_standby_slots = '<standby-slot>'\" -c 'SELECT pg_reload_conf()'"
```

⚠️ Only set it once the slot exists. Naming a slot that is absent makes every logical
walsender wait forever, with nothing but a `WARNING` to show for it. And it has a real
cost: if the standby is gone for good, cross-DC replication STALLS until you clear it.

⚠️ **PostgreSQL 17 is required** and a PG16 data directory cannot be reused: to
move an existing node, `pg_dump` it first, wipe the data dir, start 17, restore.

Do **not** run `bootstrap.sh` on B — it is a replica of A's database (same admin, same
CAs, same web users); bootstrapping would try to seed a second admin.

### Step 3 — point every service at both nodes
Each host's services find the database through `PG_CONNINFO` in its own
`/etc/fastpki/bootstrap.conf`. On **both** hosts it must name both nodes, so that after a
promotion the services find the new primary with no restart. Edit the line the installer
wrote rather than retyping it: a line typed by hand is how a host ends up with the other
host's password.

On **A** the password stays as it is. Only the host list changes:

```bash
doas sed -i '/^PG_CONNINFO=/{s/host=[^ ]*/host=<primary-address>,<standby-address>/; s/port=[^ ]*/port=5432,5432/; s/ target_session_attrs=[^ ]*//; s/ connect_timeout=/ target_session_attrs=read-write connect_timeout=/}' /etc/fastpki/bootstrap.conf
```

On **B** the password and the anchor change too. Give A's password (Step 1) when asked:

```bash
printf "A's database password: "; read -r PW
doas sed -i "/^PG_CONNINFO=/{s/host=[^ ]*/host=<primary-address>,<standby-address>/; s/port=[^ ]*/port=5432,5432/; s/ target_session_attrs=[^ ]*//; s/ connect_timeout=/ target_session_attrs=read-write connect_timeout=/; s/password=[^ ]*/password=$PW/; s#sslrootcert=[^ ]*#sslrootcert=/var/pki/tls/pg/primary-ca.crt#}" /etc/fastpki/bootstrap.conf
unset PW
```

Check the result on each host, with the password hidden:

```console
$ doas sed -n 's/password=[^ ]*/password=.../; /^PG_CONNINFO=/p' /etc/fastpki/bootstrap.conf
PG_CONNINFO=host=192.0.2.10,192.0.2.11 port=5432,5432 dbname=fastpki user=fastpki password=... sslmode=verify-full sslrootcert=/var/pki/tls/pg/ca.crt target_session_attrs=read-write connect_timeout=5
```

On B the only difference is `sslrootcert=/var/pki/tls/pg/primary-ca.crt`. Three things now
differ from what the installer wrote, and each one matters:

- **B uses A's password.** B's database is now a copy of A's, and the password B's installer
  generated existed only in the database that was just replaced. A keeps its own, which is
  the same one.
- **A is listed first on both.** libpq stops at the first host whose certificate it cannot
  verify and never tries the next one. B still serves its self-signed certificate, so B
  listed first would break every service on B. `target_session_attrs=read-write` skips B's
  read-only database in normal running either way. Once Step 4 has issued B its own
  certificate from the pair's CA, list B first on B.
- **B's anchor is `primary-ca.crt`**, for the reason in 2a. `pg-promote.sh` switches it
  back to `ca.crt` when B is promoted.

`sed -i` keeps the file's mode, `0640 root:fastpki`. Keep it that way if you edit the file
any other way. The services run as `fastpki`, and a service that cannot read the file refuses
to start, with this in its log:

```
fatal: config: cannot read /etc/fastpki/bootstrap.conf: Permission denied (on a native host it is 0640 root:fastpki — run as fastpki or root)
```

`doas chmod 640 /etc/fastpki/bootstrap.conf` and `doas chown root:fastpki` on the same file
put it right.

Then restart A's services so they read the new line, and start B's. B's were stopped in 2b, so B's
runlevel says which ones this host runs:

```bash
# on A
for s in ocsp cmp scep est acme ms web store; do doas rc-service -s fastpki-$s restart; done
# on B
for s in $(rc-update show default | awk '$1 ~ /^fastpki-(web|est|acme|cmp|ms|scep|ocsp|store)$/ {print $1}'); do
  doas rc-service $s start
done
```

Check that they stayed up, on each host. The number in brackets is how many times a service
has been restarted after failing, and it must stay at 0:

```console
$ rc-status | grep fastpki-web
 fastpki-web                                    [  started 00:01:12 (0) ]
$ doas tail -n 2 /var/log/fastpki/fastpki-web.log
```

A rising number, with `password authentication failed for user "fastpki"` in the log, means
that host's `PG_CONNINFO` does not carry A's password: compare it with A's, and run the
command above for that host again.

In normal running every service on both hosts writes to A's database, and B's Postgres
only streams.

### Step 4 — mark the standby, and replicate the keys

A promoted B issues certificates only if B's own token holds the CA keys (§3). They are
copied from A's token into B's over the key tunnel, `P11_TLS`, which Step 1 checked is on for
both hosts. Every command in this step runs with `doas`. The file edits especially: in
`doas printf … >> file` the `>>` is opened by your own shell, as `alpine`, before `doas`
starts, so it fails with `Permission denied`. `| doas tee -a` is the form that works.

**Mark B as the standby.** On **B** only:

```bash
printf 'STANDBY_OF=%s\n' <primary-address> | doas tee -a /etc/conf.d/fastpki >/dev/null
doas rc-service fastpki-web restart
```

With `STANDBY_OF` set, the Replication page reports B as the standby of A. The console reads it
when it starts, which is why `fastpki-web` is restarted. Keys are copied either way: each host's
nightly `/etc/periodic/daily/fastpki-certrenew` runs `key sync --from-peers`, which takes every
key that host is missing from the other one (§3 says why both directions matter).

**The other host's token PIN.** Each installer generates its own PIN, and a key is copied inside
the token it comes FROM, so each host needs the other's PIN. Skip this if both hosts were
installed with the same token PIN. Otherwise print A's PIN on A:

```bash
doas cat /var/pki/tls/pin
```

and install it on B as `srcpin`:

```bash
doas install -m 0600 -o fastpki -g fastpki /dev/stdin /var/pki/tls/srcpin <<'PIN'
(A's PIN, pasted)
PIN
```

Then the same the other way round: B's `/var/pki/tls/pin` becomes A's `/var/pki/tls/srcpin`.
The trailing newline the paste leaves is ignored. The nightly job and **Sync keys now** both
pass `srcpin` when it exists.

**The CA that issues the database certificates.** Once, on either host. `fastpki-config`
reads `/etc/fastpki/bootstrap.conf`, which only `fastpki` and root can read, so it runs as
`fastpki`:

```bash
doas su -s /bin/sh fastpki -c 'fastpki-config --config /etc/fastpki/bootstrap.conf set PG_TLS_CA_ID dc1-sub'
```

**Replicate now.** Run the nightly job instead of waiting for it, on **B** and then on **A**.
It switches to the `fastpki` user itself, so it is started as root:

```bash
doas /etc/periodic/daily/fastpki-certrenew
```

Run it a second time on each: it must print `key sync: this node holds every key it needs to
serve`.
Use the job, or **Sync keys now**, rather than a bare `fastpki-ca key sync` in a shell. A
shell does not have this host's `PG_BIND`, so the command records its result under the shared
name.

Each host's `fastpki-p11-tls` picks up the other host's certificates within a minute, so
nothing needs restarting on A. Check it on either host:

```console
$ doas su postgres -s /bin/sh -c "psql -d fastpki -tAc 'select host_id from p11_transport'"
192.0.2.10
192.0.2.11
```

One row per host. No rows means the tunnel is not running on either host: go back to Step 1's
check of `P11_TLS` and `fastpki-p11-tls`.

The Replication page shows two host rows, and B's role reads `standby of` A's address.

### Step 5 — failover drill (and after)

⚠️ **STOP THE PRIMARY FIRST, OR A DRILL LEAVES YOU WITH TWO OF THEM.** Promotion does not
demote anything: `pg_ctl promote` and `pg-promote.sh` both assume the primary has already
failed, which is why neither shuts it down. Rehearse on a healthy pair and both nodes are
read-write at once, and they diverge from that moment.

It does not look like a failure, which is what makes it dangerous. The apps connect with
`host=A,B … target_session_attrs=read-write`, and libpq takes the FIRST host that satisfies
that — still A. So the console logs in, writes succeed, and every check you would think to
run passes, while B receives none of it. Measured on a pair: a row written after the
promotion was present on A and absent on B. Whichever node you keep afterwards, the other's
writes are gone.

So a drill begins by taking the primary away:

```bash
# node A — simulate the loss
doas rc-service postgresql stop
```

```console
# node B — promote the standby to read-write
$ doas /usr/share/fastpki/pg-promote.sh
```

`pg-promote.sh` is installed on every native and cloud node, and it does this step and
everything below in it: the promotion, the checks around it, the database and listener
certificates, the restarts, and removing `STANDBY_OF`. The bare commands follow so that each
step is legible, not because the script is unavailable:

```console
$ doas su postgres -s /bin/sh -c 'pg_ctl -D /var/lib/postgresql/17/data promote'
$ doas su postgres -s /bin/sh -c "psql -d fastpki -tAc 'select pg_is_in_recovery()'"
f
```

⚠️ **CHECK WHETHER B ALREADY HAS ITS OWN DATABASE CERTIFICATE — on a properly joined standby
it does, and this step is a no-op.** A standby is **not** unable to issue. Its applications do
not use its own Postgres — they dial the multi-host `PG_CONNINFO` with
`target_session_attrs=read-write`, which reaches **A's** database — so a write from B lands on
the primary like any other. The real precondition is the CA KEY being in B's token, which
`key sync` puts there (§3) and B's nightly `certrenew` does unprompted.

Measured on a joined standby still reporting `pg_is_in_recovery() = t`: its Postgres
certificate was `issuer=CN=<the issuing CA>` with `IP Address:<B's own address>` in the SANs,
and all four of its listener certificates were CA-issued — none of it waiting for a
promotion.

So what follows applies to a standby that joined **without** key replication: with no CA key
it genuinely cannot sign, its Postgres still serves the self-signed pair `certgen` made at
deploy time, and because B's applications verify against the PRIMARY's anchor — which does
not certify that — every one of them fails the moment B is promoted:

```
connection to server at "<B>", port 5432 failed: SSL error: certificate verify failed
```

and `fastpki-ca pg-tls`, which would replace it, cannot connect either — it needs the
connection that is broken. Break the deadlock with a connection that does not verify, for
that one command:

```bash
doas su -s /bin/sh fastpki -c "PG_CONNINFO='host=127.0.0.1 port=5432 dbname=fastpki user=fastpki password=<PASSWORD> sslmode=require connect_timeout=5' \
  fastpki-ca --config /etc/fastpki/bootstrap.conf pg-tls --if-needed"
```

`<PASSWORD>` is the database password Step 3 put in both hosts' `PG_CONNINFO`. `PG_CONNINFO`
from the environment overrides the one in `bootstrap.conf`, for this command only.

`sslmode=require` here is a bootstrap escape, not a setting: it is used at the single moment
B has just become writable while its own certificate is still the wrong one. The pair it
writes chains to the deployment's root, and every later connection verifies normally. Pass
no `<ca-id>` — `PG_TLS_CA_ID` is a row in the `config` table and `pg-tls` reads it itself.

⚠️ **THE LISTENER CERTIFICATES ARE THE SAME STORY, WITH THE SAME CONDITION.** With the CA key
in this node's token they are already CA-issued, because B's `certrenew` promotes its own
while B is still a standby — measured, `listener certificates: checked 4, re-issued 4`. Only
the restart is outstanding then, since a listener picks its certificate at start.

Without the key they are still the self-signed certificates `certgen` made at install, and
nothing inside the deployment refuses those, so the state is invisible until a strict client
arrives: `certbot` aborts with `CERTIFICATE_VERIFY_FAILED: self-signed certificate`, and
`openssl s_client` reports `verify error:num=18:self-signed certificate`. Promote them under a
CA this node can sign with:

```bash
doas su -s /bin/sh fastpki -c 'fastpki-ca --config /etc/fastpki/bootstrap.conf renew-service-certs --re-issue-self-signed'
```

⚠️ **THEN RESTART THE PROTOCOL SERVICES — this is the half that gets left out.** A listener
picks its certificate at **start**, so the certificate just issued is not served until it
looks again. That is what makes the restart necessary, and `ocsp`, `cmp` and `scep` are in the
list for a different reason: they serve plain HTTP and have no listener certificate of their
own, which is exactly why they get left out — while they are the ones holding the RA
credentials a promoted node needs.

The RA credentials themselves do not need the restart. `fastpki-ocsp` and `fastpki-cmp`
re-check for a credential that was absent at startup and put it into service on their own, and
`fastpki-scep` reads its own per request, so a key `key sync` replicates becomes live without
intervention. Restarting only makes it immediate:

```bash
for s in ocsp cmp scep est acme ms web store; do doas rc-service -s fastpki-$s restart; done
```

`/usr/share/fastpki/pg-promote.sh` does all of this for you — the database certificate, the
listener certificates, the restart, and removing `STANDBY_OF` — so the steps above are what
it automates rather than a separate procedure. It runs `psql` and `pg_ctl` as the `postgres`
system user, runs `fastpki-ca` as the `fastpki` user (the key store answers no other user, so
as root every signing step fails), and edits `/etc/conf.d/fastpki` and
`/etc/fastpki/bootstrap.conf`, keeping each file's owner and mode. There is nothing to pass,
since it detects that it is on a native host. A step that fails is reported with a `WARN:`
line naming what is left undone.

Removing `STANDBY_OF` by hand, if you are following the manual steps rather than running it:

```bash
sed -i '/^STANDBY_OF=/d' /etc/conf.d/fastpki
rc-service fastpki-web restart
```

Left in place, B's nightly job keeps trying to copy keys from the host that failed, and the
Replication page goes on calling B a standby.

⚠️ **This does not bite a host being rebuilt as a standby of the new primary.** That host
keeps its `/var/pki` and therefore the certificate it issued while it was primary. It
is the machine that has only ever been a standby — the ordinary second host of a pair — that
arrives at its promotion with nothing it can serve.
The apps re-home to B automatically on their next request. Verify with a WRITE, not a read:
a read succeeds against either node and proves nothing about which one answered.

⚠️ **Do not restart A afterwards.** Its timeline diverged the moment B was promoted; bring
it back only as a fresh standby of B, per the rebuild below.

**On a mesh node there IS something else to touch.** Use `deploy/pg-promote.sh`
rather than a bare `pg_ctl promote`: it refuses when the peers' logical slots are not
synced and persisted on B (promoting anyway silently removes this DC from the mesh —
it keeps serving locally and stops replicating), and afterwards it clears the
`synchronized_standby_slots` value B inherited from A, which names a standby B no
longer has. Peers reach B because their subscription conninfo names BOTH of this DC's
servers (`host=<A>,<B> port=5432,5432 target_session_attrs=read-write`); if a peer names
only A it is dialling the server you just stopped and must be re-pointed with
`ALTER SUBSCRIPTION ... CONNECTION`.

To restore redundancy afterwards, rebuild A as the **new** standby of B, from your own
machine. Leave A's Postgres stopped:

```bash
deploy/ha-join-pair.sh --primary alpine@<B> --standby alpine@<A> \
    --replace-local-database -i <your ssh key>
```

It is the join from §4 with the roles swapped. It replaces A's database with a copy of B's,
points both hosts' services at both, and checks that each token holds every key. A keeps
its token, its keys and its certificates. On a cloud pair it took 1 minute 55 seconds.

`--replace-local-database` is required, because A's database is being thrown away and the join
will not do that without being told. Without it, the join stops with `this host's Postgres is
not running, so what its database holds cannot be checked`. Replacing it is the only option:
A's timeline split from B's at the promotion, so its data cannot be reused.

---

## 4a. The pair's one address, in a cloud VPC

A pair advertises **one** address: the CRLDP and AIA URLs inside an
already-issued certificate cannot be changed, so a failover that changed the address would
strand every certificate the CA has ever issued. On a hypervisor or bare metal that address
is a VIP, kept by `keepalived` or equivalent.

⚠️ **In a VPC it cannot be a VIP, and `keepalived` fails in the worst possible way there.**
VRRP relies on multicast and on a host being able to claim an address by advertising it on
the wire. A VPC does neither: traffic reaches only the interface an address is assigned to,
and the source/destination check drops the rest. So keepalived installs, runs, elects a
master and logs success — while the address it believes it holds is unreachable from
everywhere. The failure looks like a security-group problem and is not one.

What works is moving the address between the two nodes' network interfaces through the
cloud's own API. `deploy/cloud/aws-ha-address.sh` does it on AWS:

```sh
# once, when the pair is built — allocates the address, records it on the VPC and
# configures it on the primary
deploy/cloud/aws-ha-address.sh create --deployment fastpki --node 1 \
    --ssh alpine@<the primary> -i <your ssh key>

# any time — which node answers on it now
deploy/cloud/aws-ha-address.sh show --deployment fastpki --node 1

# after deploy/pg-promote.sh has promoted the standby
deploy/cloud/aws-ha-address.sh move --deployment fastpki --node 1 \
    --to-instance <survivor instance id> --ssh alpine@<the survivor> \
    --from-ssh alpine@<the old primary> -i <your ssh key>
```

`--ssh` does the half of the job the AWS API cannot. Assigning the address to an interface
makes the VPC deliver it there; until the operating system holds the address as well, the
kernel answers nothing and the packets are dropped. `create` and `move` configure it on the
host and install `/etc/local.d/fastpki-ha-address.start`, which takes the address again at
every boot.

That boot script asks the instance metadata service whether AWS still routes the address to
this machine, and removes it if not. This matters after a failover away from a machine that
was down: `move` could not reach it to take the address off, so it comes back holding an
address the other machine now serves. Asking at boot, it gives the address up by itself.
`--from-ssh` still does it immediately when the old host is alive.

It ends by checking the console on the address, at the port the node serves it on:

```
OK: the console answers on [<service address>]:443 — the pair's address follows the survivor.
```

The AWS calls use your ambient credentials, so run it with the profile of the account the
deployment is in (`AWS_PROFILE=<profile>`, or `--profile`). If it stops part way, run the same
command again: an address already on the survivor's interface is configured on the hosts
rather than refused. The standby's instance id is in the `standby_instance_ids` output, and
`show` prints the one that holds the address now.

Four things to know about it:

- **It does not promote anything.** `pg-promote.sh` promotes the database; this moves the
  address afterwards. Run them in that order.
- **It runs on the operator's machine, not on a node.** The nodes are never given an
  instance profile that can reassign addresses in their own VPC, so this will not work from
  one.
- **The address is recorded as a tag on the VPC**, not in a file on one workstation, so any
  machine with credentials for the account can find and move it.
- **It configures the address on the new holder too.** Assigning it in the API only makes it
  routable *to* the instance; until the operating system holds it, packets arrive and are
  dropped. The script adds it to the interface over SSH and persists it through
  `/etc/local.d/`, so a reboot does not silently drop the pair's address.

⚠️ **The standby must be launched into the SAME subnet as the primary.** An interface can
only hold addresses from its own subnet's prefix, so a standby placed in another
availability zone's subnet — which looks like the more resilient choice — cannot take the
address at all. So this pattern keeps the pair inside one availability zone, and the
cross-AZ redundancy of the deployment comes from the *mesh* rather than from the pair.

With IPv6 (`public_ipv4 = false` in the cloud module) extra addresses are free, and the
client sees the same address before and after, so there is no DNS record to update and no
TTL to wait out.

**For failover without a human**, put a Network Load Balancer in front of both nodes with
health checks. It passes TCP through, so the nodes still terminate their own TLS. This
script is the manual counterpart to a manual promotion, not a substitute for that.

---

## 5. Restoring redundancy after a promotion

A promoted standby is a primary, and the host it replaced can never rejoin by being
restarted: its timeline split from the new primary's at the promotion. It comes back only as
a **fresh standby of the new primary**, which means replacing its database.

**Compose, native and cloud.** From your own machine, with B the new primary and A the host
it replaced. Leave A's Postgres stopped:

```bash
deploy/ha-join-pair.sh --primary <user>@<B> --standby <user>@<A> \
    --replace-local-database -i <your ssh key>
```

`<user>@<host>` is written as for the join: `alpine@<address>` for a native or cloud server,
`admin@<host>[:/path/to/deploy]` for compose (§3). This is that join with the roles swapped.
It replaces A's database with a copy of B's, points both hosts' services at both, and checks
that each token holds every key. Only the database is replaced: A keeps its token, its keys
and its certificates. It ends like this, measured on a cloud pair in 1 minute 55 seconds:

```
ha-join-pair: standby: holds every key it needs to serve
ha-join-pair: primary: holds every key it needs to serve
ha-join-pair: standby: its services now reach the standby first, then the primary
ha-join-pair: done: alpine@<A> streams from alpine@<B> and holds the CA keys.
```

`--replace-local-database` is required, because A's database is thrown away and the join will
not do that unless told to. Without it the join stops with `this host's Postgres is not
running, so what its database holds cannot be checked`, or, if A's Postgres is running,
`this host's own database holds <n> CA certificate(s)`.

**Kubernetes.** Delete the old server pod's database claim and the pod; it seeds from the new
primary when it starts again. `pg-promote.sh` prints the two commands with the pod's name, and
[`deployment.md`](deployment.md) §8.5 has the whole sequence.


---


## 5a. Updating the pair without interrupting service

A pair is also what makes an **upgrade** an online operation, including one that carries a
schema change. The order is the whole trick, and one step is easy to leave out.

```sh
# 1. SCHEMA FIRST, on the primary only, with the OLD binaries still running.
PSQL="docker compose exec -T postgres psql -U fastpki -d fastpki" ./schema-apply.sh   # compose
PSQL="psql -U fastpki -d fastpki -h 127.0.0.1 -p 5432" ./schema-apply.sh              # native, cloud

# 2. DRAIN the standby from the load balancer, then update it.
#    (on the LB: remove that host's backends and reload)
docker compose pull && docker compose up -d      # on the standby, compose
fastpki-install-native --answers <answers file>  # on the standby, native and cloud
                                                 #   (admin-guide.md 14.4 installs the
                                                 #    new programs first)

# 3. Re-add it to the load balancer. Then promote it (§4) and repeat for the other host.
```

⚠️ **The schema goes first, and a pair needs it on the primary only.** `schema_version` rides
physical replication, so the standby reaches the new version with the new column seconds later,
having run nothing. (A MESH is the opposite — `schema_version` is node-local under logical
replication, so `schema-apply.sh` runs on every node.)

⚠️ **The two binary versions genuinely coexist, and that is what `kSchemaVersion` being a
MINIMUM buys you.** Measured on a pair: the primary kept serving on the old binaries against the
new schema for the length of the rollout — 26 consecutive probes of the console and the CRL, all
200, spanning the `schema-apply.sh` run. If that version were an exact match instead, the old
binaries would refuse the database the moment the step landed and the upgrade would be an outage.

⚠️ **DRAIN THE HOST FROM THE LOAD BALANCER BEFORE TOUCHING IT, or clients see errors however
healthy both versions are.** This is the step that gets skipped, because the deployment survives
without it and the damage is brief. Measured, same operation both ways:

| rolling a host | probes | failures |
|---|---|---|
| left in the LB pool | 40 | **4** — roughly 8s of connection failures |
| drained first | 60 | **0** |

The cause is not the upgrade: with `inter 3s fall 2` a health check needs up to 6s to notice the
backend went away, and every request balanced to it in the meantime fails. The upgrade itself is
invisible — it is the pool membership that is not.

⚠️ **A PROMOTION IS NOT FULLY TRANSPARENT FOR OCSP, and it is worth knowing which second hurts.**
Measured across a failover: the console answered 200 throughout (27 of 27), while the CRL endpoint
returned 500 for about six seconds. The applications re-home on NEW connections —
`target_session_attrs=read-write` finds the new writer — so a process holding a pooled connection
to the old primary errors until it reconnects. Nothing is lost and nothing needs doing; plan for a
few seconds rather than expecting zero.


## 6. Restoring the database without downtime

The pair is not only for surviving a crash — it is what makes a **restore** an online
operation. Run `deploy/db-restore-online.sh` **on the standby host**, telling it where the
primary is:

```bash
PRIMARY_HOST=<primary-address> ./db-restore-online.sh dump.sql
```

It refuses without `PRIMARY_HOST` — restoring into a second database on the same machine
protects nothing. Four steps:

1. **Detach** the standby: promote it, but immediately hold it at
   `default_transaction_read_only = on`.
2. **Restore** the dump into it. The primary is serving reads and writes throughout —
   this is where the entire restore window goes, and no client notices.
3. **Cut over**: it prints the command to stop the old primary, waits for that host to
   stop answering, VERIFIES it, and only then lifts the guard. Apps re-home on their next
   statement. It cannot stop a machine it is not standing on, and does not pretend to —
   an unverified "I stopped it" is how two read-write databases with different data start.
4. **Rebuild** the old primary as the new standby, with `ha-join.sh` on that host.

**What the read-only guard does.** The apps connect with
`target_session_attrs=read-write`, and libpq implements that by asking each candidate
host `SHOW transaction_read_only` and skipping any that answers `on`. So a promoted
standby carrying that setting is writable by the restore and *invisible to the apps*, and
no second read-write host appears for a reconnecting app to land on.

**Two traps, both real:**

- **The restore must set the GUC via `PGOPTIONS`, not a `SET` statement.** A
  `--single-transaction` restore has already opened its transaction by the time the first
  `SET` runs, and a transaction's read-only-ness is fixed at BEGIN — every statement then
  fails with *"cannot execute ... in a read-only transaction"*. `PGOPTIONS` applies at
  connection startup, before the transaction opens.
- **Use `ALTER DATABASE`, not `ALTER SYSTEM`, anywhere the node is shared.** `ALTER
  SYSTEM` persists to `postgresql.auto.conf`; if anything dies between setting and
  clearing it, the node stays read-only across restarts and every later operation fails
  with *"cannot execute CREATE DATABASE in a read-only transaction"*. `db-restore-online.sh`
  uses `ALTER SYSTEM` because it owns the node it is about to promote.

**The roles swap.** Afterwards the host you ran it on is the primary, and the old primary
is rebuilt as its standby, so the next restore runs the same way in the other direction.

**A restore is a point-in-time rollback.** Certificates issued between the dump and the
cutover vanish from the DB while still existing in the world, and will keep validating
against a CRL/OCSP that no longer knows them. The script refuses when the newest
certificate is younger than the dump; `--force` accepts that consequence. A data center that is part of a
multi-DC mesh is restored with `postgres.md` §6.3 instead, because its
replicated rows come back from the other data centers rather than from the dump.

---

## 7. Gotchas (each one is a real failure mode)

- **SAN must cover the address the standby dials** (§4 Step 0) or `verify-full` rejects it and
  failover silently can't connect.
- **ACME endpoint:** `acme_db_postgres.cpp` holds its *own* connection, and it carries the
  same reconnect, so ACME re-homes on failover like every other protocol.
- **Don't bootstrap the standby** (Step 2) — it already has the primary's admin/CAs.
- **Promotion is one-way.** A promoted standby is a primary; the old primary must be
  re-seeded as a fresh standby, never just restarted (its timeline has diverged).
- **connect_timeout** in the conninfo — without it, a dead primary can stall each
  reconnect attempt for the OS TCP timeout.

---

## 8. This is NOT cross-DC mesh replication

| | **HA standby** (this doc) | **Cross-DC mesh** |
|---|---|---|
| scope | two hosts within one DC | between DCs |
| replication | **physical** streaming (same DB) | **logical** (per-DC-unique DBs) |
| standby role | read-only hot copy, promotable | independent writable DB per DC |
| purpose | survive a DB-node failure in a DC | share issuance state across DCs |

They compose: a DC's **primary** is its mesh node; its standby on the second host simply
shadows that primary. Enabling one does not affect the other.

---

## 9. App-tier HA — scaling the protocol services behind a load balancer

§1–§8 make the **database** highly available. The **protocol services** (`web`, `ocsp`,
`est`, `acme`, `cmp`, `scep`, `ms`, `store`) are **stateless** — every piece of state
lives in the shared DB — so they scale horizontally the moment you want no-downtime on an
app crash: **run N replicas and put a load balancer in front.**

The load balancer is **your infrastructure** (it differs per site — cloud LB, haproxy,
nginx, DNS). FastPKI does not ship one.

### What lets FastPKI run behind one
- **No sticky sessions.** Console sessions live in the shared DB (`web_sessions`) and are
  read-through: a session created on instance A is validated on instance B via the DB.
  The LB may route any request to any instance.
- **All protocol state is in the shared DB** — ACME accounts/orders/nonces, issued certs,
  users, audit. Nothing important is instance-local.
- **Serials are random** (128-bit), so two instances issuing at once do not collide, and
  the database's serial uniqueness catches it if they ever did.

### What the operator must provide
1. **A load balancer** in front of the app Services, health-checking each instance. (For
   the console, `/` is a cheap health check; for the enrollment protocols, a TCP check.)
2. **The signing CA key present in every app instance's own token.** Each CA's key location
   is recorded on its `certs` row, and it is ALWAYS a `pkcs11:` URI — there is no
   file-based CA key, and `load_signing_key` has no on-disk branch. Every instance
   keeps its own token, and the CA's key is replicated into each of them (§1): create the CA
   with a replicable key (`fastpki-ca create --replicable`, or **replicable key** in the
   console), then `fastpki-ca key replicate <ca-id> --from <peer-address>:12345`. Pointing
   every instance at one token instead moves the single point of failure rather than
   removing it — losing that host stops all signing, and the certificates issued under that
   key can then never be renewed or revoked. The CA **cert** material is a `certs` row, so
   Postgres already shares it with every instance.

### How to scale
- **Docker Compose:** run the app services with `--scale web=3` (etc.) behind your LB, or
  run the compose stack on multiple hosts, each with its own token holding a replica of the
  CA key, and point the LB at all of them.
- **Kubernetes:** each FastPKI server is one pod of the `fastpki-node` StatefulSet, with its own
  token, `/var/pki` and database, and the protocol Services spread across the servers.
  `HA_ENABLED=true` runs two, on two nodes, with keys copied between their tokens
  ([`deployment.md`](deployment.md) §8.5). Front the `web` Service with an Ingress or LB.

### One caveat: cross-instance logout latency
Each instance keeps a small in-memory session cache in front of the DB. Logout deletes the
DB row and clears the local cache, so it is immediate **on the instance you logged out
from**; other instances that already cached that session keep honouring their copy until
it expires (bounded by the session TTL). If instant global logout matters for your threat
model, shorten the session TTL.
