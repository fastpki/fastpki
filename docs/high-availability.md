# FastPKI — High Availability

A **standby** is a second server in the same data center. It keeps a live copy of the
primary's database and, with the CA keys copied into its own token, can take over signing
when the primary is lost. No third-party tooling is involved (no Patroni, etcd or repmgr),
and the applications move to the new primary without a restart.

## Contents

- [1. What a standby covers](#1-what-a-standby-covers)
- [2. Decide before you create any CA](#2-decide-before-you-create-any-ca)
- [3. Build the pair](#3-build-the-pair)
- [4. Check the pair](#4-check-the-pair)
- [5. Fail over](#5-fail-over)
- [6. Restore redundancy after a failover](#6-restore-redundancy-after-a-failover)
- [7. The pair's one address in a cloud VPC](#7-the-pairs-one-address-in-a-cloud-vpc)
- [8. Update the pair without interrupting service](#8-update-the-pair-without-interrupting-service)
- [9. Restore the database without downtime](#9-restore-the-database-without-downtime)
- [10. When something goes wrong](#10-when-something-goes-wrong)
- [11. A pair is not a mesh](#11-a-pair-is-not-a-mesh)
- [12. More copies of the services behind a load balancer](#12-more-copies-of-the-services-behind-a-load-balancer)

Every step below uses the scripts FastPKI ships. What each script does, step by step, is in
[Manual procedures](manual-procedures.md), for when you cannot run it or need to finish a
step it reported as failed.

---

## 1. What a standby covers

A data center holds state in two places: the **database** and the **token** that holds the
CA private keys. The protocol services (`web`, `ocsp`, `est`, `acme`, `cmp`, `scep`, `ms`,
`store`) keep nothing else, but they sign through a `pkcs11:` key in the token.

```
          fastpki-web / ocsp / est / acme / …
                   │
                   │  PG_CONNINFO = host=A,B port=5432,5432
                   │                target_session_attrs=read-write
           ┌───────┴────────┐
           ▼                ▼
   ┌───────────────┐  WAL   ┌───────────────┐
   │  HOST A       │ ─────► │  HOST B       │   the same database,
   │  PRIMARY (RW) │ stream │  STANDBY (RO) │   read-only until promoted
   │  own token    │        │  own token    │
   └───────────────┘        └───────────────┘
```

- **The database** is copied by PostgreSQL streaming replication. The standby is read-only
  until you promote it.
- **The applications** on both hosts list both databases in `PG_CONNINFO` with
  `target_session_attrs=read-write`. They use whichever one is writable, so after a
  promotion they move to the new primary on their next query, without a restart.
- **The CA keys** are copied from one host's token into the other's over the key tunnel,
  `P11_TLS`. Each host then signs from its own token. A promoted standby without the keys
  serves the console and reads, and cannot issue anything.

⚠️ **Reachability is not failover.** Every host has its own token. FastPKI never has one host
sign through another host's token: if that host were lost, every host would stop signing,
and certificates issued under its keys could not be renewed or revoked afterwards.
[`architecture.md`](architecture.md) §5–§6 is the design record.

⚠️ **Promotion is a manual step.** Nothing detects that a primary has died and promotes the
standby for you. Between the loss and your promotion, writes are refused, so the two
databases cannot diverge.

⚠️ **Two databases on one machine is not a pair.** It survives the database process dying
and nothing else — not the disk, the kernel or the host. FastPKI does not ship that
arrangement.

---

## 2. Decide before you create any CA

Five choices are made at install or when a key is created, and most cannot be changed
afterwards. Make them before the first CA exists.

**1. Install the primary for a pair.** Answer yes to *Will this data center have a standby*
(`HA_ENABLED=yes`) when you install A. It turns the key tunnel on (`P11_TLS=on`) and sets
`SERVICE_KEYS_REPLICABLE=true`, so the OCSP, CMP and SCEP credentials are created copyable.
On AWS, listing the data center in `standby_dcs` does the same. On Kubernetes it is
`HA_ENABLED=true` for `apply.sh`.

**2. Create every CA with a replicable key, the root included.** Tick **replicable key** on
the console's New CA form, or pass `--replicable` to `fastpki-ca create`. A renewal with a
new key creates a new key, so tick it there too. A key created without it can never be
copied, and a promoted standby can never sign with it. Check each CA on the host that
created it:

```sh
fastpki-ca key list <ca-id>        # each line ends [in this node's token, replicable]
```

The console's Replication page marks a key that cannot be copied as *not replicable*.

Every CA key algorithm can be replicable: RSA, RSA-PSS, EC P-256/P-384/P-521, Ed25519, Ed448
and ML-DSA.

**3. Give the pair one name.** `BASE_URL` and `PKI_DNS` are the name clients use, and they
go into every certificate's CRL distribution point and AIA URLs. Set both to a name that
reaches whichever host is live — a shared DNS name or an address in front of the pair — on
**both** hosts, before the CAs are created. A certificate cannot be given a new URL later.
With the primary's own name instead, CA certificates point at a host that is gone after a
failover, and strict validation fails with `unable to get certificate CRL`.

**4. Give each host its own `PG_BIND`, and the same `DATACENTER_ID`.** `PG_BIND` is this
host's own address, never `127.0.0.1` and never the shared name: Postgres listens on it, the
standby streams from it, and the key tunnel identifies each host by it. `DATACENTER_ID` is
the same on both hosts: a pair is one data center. The installers ask for both.

**5. Give both hosts the same token PIN** (`FASTPKI_PIN`). A key is copied out of the token
it comes from, so the copying host logs in to the other host's token. With one PIN for the
pair nothing more is needed. With different PINs, each host needs the other's PIN in
`/var/pki/tls/srcpin`; `ha-join-pair.sh` puts it there.

---

## 3. Build the pair

Install B like any other server of the same data center: same `PKI_DNS`, `BASE_URL`,
`DATACENTER_ID` and release as A, its own `PG_BIND`, and `HA_ENABLED=yes`. B's own database
is replaced by a copy of A's when it joins.

### Compose, native and cloud: one command

From your own machine, the one you SSH to both hosts from:

```bash
# native and cloud
deploy/ha-join-pair.sh --primary alpine@<A> --standby alpine@<B> -i <your ssh key>
# compose
deploy/ha-join-pair.sh --primary admin@<A> --standby admin@<B> -i <your ssh key>
```

Write a compose server as `admin@<host>` or `admin@<host>:/path/to/deploy` if the deploy
directory is not the default. On AWS, `<A>` and `<B>` are the addresses of `1` and
`1-standby` in `tofu output node_public_ipv6`.

It checks both hosts first and stops, saying why, if either was not installed for a pair.
Then it:

1. copies A's database to B and makes B a streaming standby;
2. points the services on both hosts at both databases;
3. copies the CA keys and the OCSP, CMP and SCEP credentials between the two tokens;
4. issues B its own database certificate from the pair's CA, and then lists B first in B's
   own services.

A's database CA certificate, database password and token PIN are read from A over SSH and
passed to B on standard input. Nothing secret is typed or written on your machine. It takes
about two minutes and ends like this:

```
ha-join-pair: standby: holds every key it needs to serve
ha-join-pair: primary: holds every key it needs to serve
ha-join-pair: standby: database certificate issued from the pair's CA
ha-join-pair: standby: its services now reach the standby first, then the primary
ha-join-pair: done: alpine@<B> streams from alpine@<A> and holds the CA keys.
```

Run it again at any time. A standby already streaming from A is not copied a second time.

If it stops:

| Problem | What to do |
|---|---|
| a host lacks `P11_TLS=on` or its own `PG_BIND` | re-run that host's installer with `HA_ENABLED=yes` and its own address. Adding the lines to a file by hand does not start the key tunnel. |
| `this host's own database holds <n> CA certificate(s)` | B has CAs of its own. If B's database is disposable, add `--replace-local-database`. |
| a key could not be copied | that key was not created replicable (§2). It can never leave A's token. |
| `C_Login … failed (rc=160): the PIN is wrong for THIS token` | the PINs differ and the other host's PIN is missing or wrong in `/var/pki/tls/srcpin` (§10). |

**Without SSH from one machine to both hosts**, run the two halves on the hosts themselves,
as root. On B, with A's `/var/pki/tls/pg/ca.crt`, A's database password and, if the PINs
differ, A's `/var/pki/tls/pin` copied into files:

```bash
# native and cloud: /usr/share/fastpki/ha-join.sh    compose: ./ha-join.sh in deploy/
doas /usr/share/fastpki/ha-join.sh <A-address> primary-ca.crt \
    --primary-password-file a-password [--primary-pin-file a-pin]
```

Then on A, with B's PIN in a file if the PINs differ:

```bash
doas /usr/share/fastpki/ha-join.sh --on-primary <B-address> [--standby-pin-file b-pin]
```

Then run the key sync on B and then A, as in §4, so the keys are copied now rather than
tonight. To do each step of the join by hand, see
[Manual procedures: join a standby by hand](manual-procedures.md#11-joining-a-standby-by-hand).

### Kubernetes

Set `HA_ENABLED=true` and run `deploy/k8s/apply.sh`. It runs two servers on two nodes,
seeds the second from the first, and copies the keys between their tokens. The whole
sequence is in [`deployment.md`](deployment.md) §8.

---

## 4. Check the pair

**B is a standby.** On B:

```console
$ doas su postgres -s /bin/sh -c "psql -d fastpki -tAc 'select pg_is_in_recovery()'"
t
```

On compose: `docker compose exec postgres psql -U fastpki -d fastpki -tAc 'select pg_is_in_recovery()'`.

**A streams to B.** On A:

```console
$ doas su postgres -s /bin/sh -c "psql -d fastpki -xc 'select client_addr, state from pg_stat_replication'"
client_addr | <B-address>
state       | streaming
```

**Both tokens hold every key.** Run the key sync on each host, B first. It must end with
`key sync: this node holds every key it needs to serve`:

```bash
# native and cloud: the nightly job, started as root
doas /etc/periodic/daily/fastpki-certrenew
# compose, in deploy/ (leave out --source-pin-file when both hosts share one PIN)
docker compose exec web fastpki-ca --config /app/config/bootstrap.conf \
    key sync --from-peers --source-pin-file /var/pki/tls/srcpin
```

**The Replication page** in the console shows both hosts, B as `standby of` A, which keys
each token holds, and each host's last key sync. It warns about a missing `PG_BIND`, a
one-host `PG_CONNINFO`, a database certificate the applications cannot verify,
`PG_TLS_CA_ID` unset, a key that cannot be copied, and no standby streaming. **Sync keys
now** on a host's row runs the key sync on that host.

The keys stay in step on their own: each host's nightly job copies any key it is missing from
the other host of the same data center. A CA created later, on either host, reaches the other
host that night, or at once with **Sync keys now**.

---

## 5. Fail over

Use the same steps for a real failure and for a drill.

**1. Make sure the primary is stopped.** In a real failure it already is. In a drill, stop
it yourself:

```bash
doas rc-service postgresql stop        # on A — native and cloud
docker compose stop postgres           # on A — compose
```

⚠️ Promotion does not stop the old primary. If A is still running, you have two writable
databases, and the applications keep writing to A because it is listed first. Whichever you
keep afterwards, the other's writes are lost.

**2. Promote B.** On B:

```bash
doas /usr/share/fastpki/pg-promote.sh          # native and cloud
./pg-promote.sh                                # compose, in deploy/
```

On Kubernetes, from any machine with `kubectl` for the cluster:

```bash
FASTPKI_PROMOTE_MODE=k8s NAMESPACE=fastpki deploy/pg-promote.sh fastpki-node-1
```

It promotes B's database, clears settings B inherited from A, stops marking B as a standby,
issues B's database and listener certificates if B does not have them yet, rewrites B's own
`PG_CONNINFO` so B is listed first with its own anchor, and restarts the protocol services.
It ends with:

```
OK: postgres is now a read-write primary.
The app services re-home onto it on their next query (no restart needed).
```

A line starting `WARN:` names a step that did not complete; the steps are described one by
one in [Manual procedures: promote a standby by hand](manual-procedures.md#12-promoting-a-standby-by-hand).
On a mesh node it refuses to promote if the peers' replication slots are not synced to B;
see §10.

**3. Move the pair's address to B**, if the pair is behind one address you control:

- a VIP kept by `keepalived` follows on its own;
- in a cloud VPC, run `deploy/cloud/aws-ha-address.sh move` as `pg-promote.sh` prints (§7).

**4. Check with a write, not a read.** A read succeeds on either database and proves
nothing. Log in to the console and change something, for example a setting on the Config
page, or issue a certificate.

The OCSP and CRL endpoints may answer with errors for a few seconds while the services
reconnect.

⚠️ **Do not start A's Postgres again.** Its database diverged from B's at the promotion.
Bring A back as B's standby (§6).

---

## 6. Restore redundancy after a failover

A comes back as B's standby by **re-copying its database from B**. The machine, its token,
its keys and its certificates stay as they are; only the database is replaced. Leave A's
Postgres stopped, and from your own machine:

```bash
deploy/ha-join-pair.sh --primary alpine@<B> --standby alpine@<A> \
    --replace-local-database -i <your ssh key>
```

(`admin@…` for compose.) It is the join from §3 with the roles swapped, and takes about two
minutes. It ends like this:

```
ha-join-pair: standby: holds every key it needs to serve
ha-join-pair: primary: holds every key it needs to serve
ha-join-pair: standby: its services now reach the standby first, then the primary
ha-join-pair: done: alpine@<A> streams from alpine@<B> and holds the CA keys.
```

`--replace-local-database` is required, because the join does not discard a database unless
told to.

**Kubernetes.** Delete the old server pod's database claim and the pod; it seeds from the new
primary when it starts again. `pg-promote.sh` prints the two commands with the pod's name:

```bash
kubectl -n fastpki delete pvc pgdata-<old-pod> --wait=false
kubectl -n fastpki delete pod <old-pod>
```

---

## 7. The pair's one address in a cloud VPC

A pair advertises **one** address, because the URLs in issued certificates cannot change. On
a hypervisor or bare metal that address is a VIP kept by `keepalived` or similar.

⚠️ **In a VPC, use the script, not `keepalived`.** A VPC delivers traffic only to the
interface an address is assigned to, so `keepalived` runs, reports that it holds the address,
and nothing reaches it. `deploy/cloud/aws-ha-address.sh` moves the address between the two
nodes' interfaces through the AWS API, and configures it on the host over SSH.

Run it from your own machine, with the AWS profile of the account the deployment is in
(`AWS_PROFILE=<profile>`, or `--profile`):

```sh
# once, when the pair is built — allocates the address and puts it on the primary
deploy/cloud/aws-ha-address.sh create --deployment fastpki --node 1 \
    --ssh alpine@<the primary> -i <your ssh key>

# which node holds it now
deploy/cloud/aws-ha-address.sh show --deployment fastpki --node 1

# after pg-promote.sh has promoted the standby
deploy/cloud/aws-ha-address.sh move --deployment fastpki --node 1 \
    --to-instance <survivor instance id> --ssh alpine@<the survivor> \
    --from-ssh alpine@<the old primary> -i <your ssh key>
```

The standby's instance id is in the `standby_instance_ids` output. `move` ends with:

```
OK: the console answers on [<service address>]:443 — the pair's address follows the survivor.
```

- **It does not promote anything.** Run `pg-promote.sh` first, then this.
- **If it stops part way, run the same command again.**
- **The old primary gives the address up by itself** when it boots again, if `--from-ssh`
  could not reach it.
- **The standby must be in the same subnet as the primary.** An interface can hold addresses
  from its own subnet only, so the pair stays in one availability zone. Redundancy across
  zones comes from a mesh of data centers.

With IPv6 (`public_ipv4 = false`) the address is free and clients see the same address before
and after, so there is no DNS record to update.

**For failover without a person**, put a Network Load Balancer with health checks in front
of both nodes. It passes TCP through, so the nodes still terminate their own TLS.

---

## 8. Update the pair without interrupting service

In this order:

1. **Apply the schema on the primary only**, with the old programs still running
   ([`postgres.md`](postgres.md) §4.2 has the command for each path). The standby receives
   the change by streaming and must not run it. The old programs keep working against the new
   schema.
2. **Remove the standby from the load balancer**, then update it: `docker compose pull &&
   docker compose up -d` on compose, or the package update in
   [`admin-guide.md`](admin-guide.md) §14.4 on native and cloud.
3. **Put it back in the load balancer.** Then fail over to it (§5), re-copy the old primary
   (§6), and update that host the same way.

⚠️ Remove a host from the load balancer before you touch it. Otherwise requests sent to it
fail for as long as the health check takes to notice, typically several seconds.

---

## 9. Restore the database without downtime

Restore a dump into the standby while the primary keeps serving, then switch over.
`deploy/db-restore-online.sh` does it on every deployment path; [`postgres.md`](postgres.md)
§6.2 has the command for each.

- **Docker Compose and native:** run it **on the standby host**, naming the primary:

  ```bash
  PRIMARY_HOST=<primary-address> ./db-restore-online.sh dump.sql                     # compose, in deploy/
  PRIMARY_HOST=<primary-address> /usr/share/fastpki/db-restore-online.sh dump.sql    # native and cloud, as root
  ```

  It refuses without `PRIMARY_HOST`: a second database on the same machine protects nothing.
- **Kubernetes:** run it on any machine with `kubectl` for the cluster, naming the standby's
  pod. It finds the primary itself:

  ```bash
  NAMESPACE=fastpki deploy/db-restore-online.sh dump.sql fastpki-node-1
  ```

It:

1. promotes the standby but keeps it read-only to the applications, so they keep using the
   primary;
2. restores the dump into it, into an empty database — the whole restore time, with no
   interruption;
3. makes sure the old primary's database is stopped before it makes the restored one
   writable. On Docker Compose and native it prints the command to run on the other host and
   waits for that database to stop; on Kubernetes it stops it itself. The applications move
   to the restored database on their next query;
4. finishes the promotion as after a failover (§5), with `pg-promote.sh --already-promoted`;
5. re-copies the old primary's database from the restored one, making it the new standby
   (§6). On Kubernetes the script does this itself; on Docker Compose and native it prints the
   command to run.

⚠️ **A restore rolls the database back to the dump.** Certificates issued after the dump
disappear from the database but stay valid in the world, and revocation data no longer knows
them. The script refuses when the newest certificate is younger than the dump; `--force`
accepts that.

A data center in a mesh is restored with [`postgres.md`](postgres.md) §6.3 instead, because its
replicated rows come back from the other data centers rather than from the dump. The script
refuses a data center in a mesh.

---

## 10. When something goes wrong

**The applications fail with `certificate verify failed` after a promotion.** B's database
still serves the self-signed certificate made at install, because B had no CA key when it was
joined. Copy the keys (the nightly job, or **Sync keys now**), then issue B's database
certificate; see [Manual procedures: promote a standby by hand](manual-procedures.md#12-promoting-a-standby-by-hand).

**A standby was joined without the CA keys.** It streams correctly but cannot sign after a
promotion: CMP refuses every transaction, OCSP answers `internalerror` and SCEP serves
nothing, while EST and ACME may still work. Check the Replication page; if a key is marked
*not replicable*, it can never be copied, and the CA has to be re-created with a replicable
key.

**`key sync` fails with `C_Initialize failed (rc=48)`.** The key tunnel has not admitted the
other host yet. Each host publishes its tunnel certificate and admits the other's within a
minute. If it persists after both hosts are up, restart the tunnel on the host the key is
copied **from**:

```sh
doas rc-service fastpki-p11-tls restart     # native or cloud
docker compose restart p11-tls              # compose
```

If `select host_id from p11_transport` shows one row for two hosts, the hosts share an
identity: set each host's own `PG_BIND` (§2) by re-running its installer.

**`key replicate: C_Login to token 'fastpki' failed (rc=160)`.** The hosts have different
token PINs and the other host's PIN is missing from `/var/pki/tls/srcpin`. Re-run
`ha-join-pair.sh`, or place it by hand:
[Manual procedures: copy keys between the tokens by hand](manual-procedures.md#13-copying-keys-between-the-tokens-by-hand).

**Strict clients fail with `unable to get certificate CRL` at depth 1 after a failover.** The
CA certificates carry the old primary's own name in their URLs (§2, choice 3).
`pg-promote.sh` warns about it. Re-issue the CA certificates under the same keys with the
shared name; nothing issued under them becomes invalid.

**`pg-promote.sh` refuses on a mesh node** with `only <n> of <m> peer logical slots are
synced`. Promoting anyway takes this data center out of the mesh: it keeps serving locally
and stops replicating. Fix the standby's settings the message lists, or accept it with
`--force`. After a promotion, peers reach the new primary because their subscriptions name
both servers of this data center. A peer whose subscription names only the failed server
must be re-pointed on that peer:

```sql
ALTER SUBSCRIPTION <name> CONNECTION 'host=<A>,<B> port=5432,5432 ... target_session_attrs=read-write';
```

**Do not run `bootstrap.sh` on a standby.** It holds a copy of the primary's database, with
the same administrators and CAs.

---

## 11. A pair is not a mesh

| | **Pair** (this guide) | **Mesh** |
|---|---|---|
| scope | two hosts in one data center | between data centers |
| replication | physical streaming: one database | logical: each data center has its own database |
| second copy | read-only until promoted | writable in every data center |
| purpose | survive losing a host | share certificates and settings between data centers |

They combine: a data center's primary is its mesh node, and its standby follows that
primary. The mesh is in [`deployment.md`](deployment.md) §9.

---

## 12. More copies of the services behind a load balancer

The protocol services keep all their state in the database, so you can run several copies
behind a load balancer. FastPKI does not ship the load balancer.

- **No sticky sessions are needed.** Console sessions are stored in the database, so any
  copy can serve any request.
- **Serial numbers are random**, so copies issuing at the same time do not collide.
- **Each copy must have the CA keys in its own token.** Create the CAs replicable and copy
  the keys to each host (§2, §4). Do not point several hosts at one token: losing that host
  stops all signing.

Health checks: `/` for the console, a TCP check for the enrolment protocols.

- **Compose:** run the stack on several hosts, each with its own token holding copies of the
  CA keys, and put the load balancer in front of all of them.
- **Kubernetes:** each server pod has its own token and database; `HA_ENABLED=true` runs two.
  Put an Ingress or load balancer in front of the `web` Service.
