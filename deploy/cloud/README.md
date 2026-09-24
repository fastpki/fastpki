# Cloud deployment

Provision FastPKI in a public cloud: infrastructure-as-code that stands up the network, the
instances and the mesh. Each server starts from Alpine's own cloud image and installs FastPKI at
first boot, after checking the release signature.

```sh
deploy/cloud/cloud-install.sh                          # the wizard: asks, plans, applies
deploy/cloud/cloud-install.sh --destroy                # tear it down
```

Only for servers with no internet at first boot, build an image with FastPKI already on it:

```sh
deploy/native/build-check.sh                           # FIRST, and free: build locally
packer init deploy/cloud/image                         # plugins, once
packer build -only=fastpki.amazon-ebs.alpine \
    -var 'release=vX.Y.Z' deploy/cloud/image            # the AMI, once per release
```

⚠️ **None of that works on a fresh account until the prerequisites are in place** — a named
AWS profile, an SSH key pair that already exists, and an account permitted to launch the
instance types. **An account on the AWS free plan cannot launch the default build instance
at all** and fails in seconds with `InvalidParameterCombination: The specified instance type
is not eligible for Free Tier`, which forces an x86_64 build. [`deployment.md`](../../docs/deployment.md)
§12 has the whole list under **Before you start**, and the eleven steps from there to a
working mesh.

## Contents

- [Build locally first; build in the cloud only for a release](#build-locally-first-build-in-the-cloud-only-for-a-release)
- [Proxmox — the same contract, on a hypervisor](#proxmox--the-same-contract-on-a-hypervisor)
- [How big the image is, and why the build does not decide that](#how-big-the-image-is-and-why-the-build-does-not-decide-that)
- [Alpine's own image by default, and when to build one](#alpines-own-image-by-default-and-when-to-build-one)
- [What gets created](#what-gets-created)
- [Secrets](#secrets)
- [After apply](#after-apply)
- [Updating a running node](#updating-a-running-node)
- [An HA pair](#an-ha-pair)
- [Key storage](#key-storage)
- [Cost](#cost)

## Build locally first; build in the cloud only for a release

Nearly everything that can go wrong in the image build has nothing to do with EC2: a patch
that stopped applying against a new upstream commit, p11-kit no longer relaying ML-DSA, a
compile error, a binary that cannot print its own usage. Every one of those is answerable
in a container on a developer machine, and discovering them from a failed cloud build
costs twenty minutes and an instance-hour each time.

`deploy/native/build-check.sh` runs the build in a throwaway Alpine container — **the real
`deploy/cloud/image/provision.sh`, not a copy of it**, which is the only thing that makes
the result mean anything. It skips exactly two steps, both about a machine that boots
(enabling `crond` in a runlevel, and asserting the base image can receive user-data); a
container has no init and no cloud-init, so neither is answerable there.

So: **run it on every change, and run `packer build` only when there is a release to pin
an image to.**

Booting is proved by a third step, locally. `deploy/cloud/image/build-qemu.sh` runs the
same template and the same `provision.sh` through Packer's qemu builder, emitting a
bootable qcow2 instead of an AMI, and `deploy/cloud/boot-check.sh` starts that disk under
QEMU with a cloud-init seed exactly as an instance receives one:

```sh
deploy/cloud/image/build-qemu.sh     # the same provision.sh, as a qcow2
deploy/cloud/boot-check.sh           # boot it and assert the first-boot path
```

It asserts what no container can: the answers file reaches the instance, the installer
consumes it, the node is configured with the name it was GIVEN rather than a default,
OpenRC supervises the services under a real init, a protocol *not* asked for is absent,
the console answers HTTPS — and that all of it survives a reboot, compared by
`/proc/sys/kernel/random/boot_id` so that SSH answering again cannot pass for a restart.

Both need `qemu-system-x86_64`, `packer`, UEFI firmware (Debian and Ubuntu: `ovmf`; a
Proxmox host ships its own) and membership of the `kvm` group.

⚠️ **Give it real cores, and do not run it inside a VM.** The build compiles four C/C++
projects against a 60-minute provisioner timeout. On a machine that is itself virtualised,
packer's KVM is *nested* and the guest loses the host's CPU features — the same build that
takes minutes natively does not finish at all. `build-qemu.sh` sizes the VM from the host
and passes the host CPU through; what it cannot do is invent cores that are not there.

What still needs a real instance is the AWS hardware surface: the ENA and NVMe drivers, and
AMI registration itself.

### Why the AMI itself cannot be built locally

An AMI is an EBS snapshot in a region, so the *registration* step needs AWS. The two ways
to get locally-built bits into one are both worse than letting a throwaway instance do it:

- **VM Import/Export** (`aws ec2 import-image`) is blocked twice. AWS's requirements state
  plainly that "VMs using ARM64 architecture are not currently supported", and Alpine is
  not on the supported guest-OS list at all — so even an x86_64 Alpine disk is out.
- **EBS direct APIs plus `register-image`** genuinely work, arm64 included, with no
  instance. The input is a *bootable disk image*, and `build-qemu.sh` already produces one —
  it starts from Alpine's cloud image, and `boot-check.sh` proves it boots under UEFI with
  cloud-init and survives a reboot. So this route is not closed the way VM Import is, and it
  is worth being precise about what actually stops it:

  - **ENA and NVMe stay unproven.** Booting under QEMU says nothing about EC2's network and
    storage drivers, which is the one surface no local check can reach. A host that cannot
    see its root volume fails at first boot, and these hosts carry CA keys.
  - **The image has to be uploaded** block by block into a snapshot — around a gigabyte per
    release, from wherever the operator happens to be.

  Starting from Alpine's own AMI inherits the driver work on every release and uploads
  nothing, which is why the amazon-ebs path is the one that ships.

Building locally would save about ten cents per release and cost us the entire boot and
driver surface, on hosts holding CA keys. The local *build check* saves the round trip,
which is the cost that actually matters, and costs nothing.

**AWS ships today.** GCP and Azure modules go in `deploy/cloud/gcp/` and
`deploy/cloud/azure/`; the wizard refuses them by name rather than provisioning something
that half works.

## Proxmox — the same contract, on a hypervisor

`deploy/cloud/proxmox/` provisions FastPKI nodes on a Proxmox hypervisor with OpenTofu.
It exists because the AWS module cannot be tested: an AMI needs EC2 to boot, so the
first-boot contract — cloud-init delivers a KEY=VALUE answers file and
`fastpki-install-native` consumes it — is exercised nowhere but production. Here a node
costs nothing and can be destroyed and rebuilt in a minute.

The split is the same as AWS's, including the default: the template can be Alpine's own
generic cloud image (`generic_alpine-<version>-x86_64-uefi-cloudinit`), and each node installs
FastPKI at first boot with the same `firstboot-install.sh`. For a lab with no route out, Packer
builds an image with FastPKI on it instead. There the artifact is an AMI, here it is a Proxmox
**template** the module clones:

```sh
deploy/cloud/image/build-qemu.sh                # the qcow2
# import it once and `qm template` it — see terraform.tfvars.example
export PROXMOX_VE_API_TOKEN='user@realm!tofu=...'
tofu init && tofu apply
```

It is not a port of the AWS module and must not be refactored into one: what the two share
is the cloud-init contract, and everything else about AWS — ENIs, EBS volumes, security
groups, Route 53 — has no counterpart here.

## How big the image is, and why the build does not decide that

Sizes here are measured on a running deployment, not estimated:

| | |
|---|---|
| the image | **175 MB** |
| a node's root volume, in use | **264 MB** (`/usr` is 190 MB of it) |
| a node's data volume, in use | **64 MB** — Postgres 64 MB, `/var/pki` 32 KB, the token 48 KB |
| memory, whole machine | **107 MB** with the console, OCSP, EST and the token up; **239 MB** with all ten services running — every enrolment protocol, the token, p11-tls and Postgres |

Each listener is 13-17 MB RSS, each `p11-kit-remote` about 9 MB, and Postgres shares most of
its pages. So a node runs on the smallest instance and the smallest volumes the platform
sells: `root_volume_gb = 1`, `data_volume_gb = 1`, and a 1 GB instance.

What would fill those volumes, so the numbers are legible rather than lucky: on the data
volume, sustained issuance growing `pg_wal` toward PostgreSQL's 1 GB `max_wal_size`; on the
root volume, unrotated service logs after `LOG_LEVEL` is raised to `info` and left there.
Both are visible long before they bite, and both are one setting away from being fixed.

⚠️ **The root volume's size is set by the IMAGE, not by the deployment** — an instance's root
can never be smaller than the snapshot behind it, so `deploy/cloud/aws` does not pin a size
and inherits the AMI's. Change it with `-var root_volume_gb=N` on the `packer build`.

⚠️ **And the build does not happen on that volume.** Compiling pkcs11-provider, p11-kit,
SoftHSM and FastPKI peaks at about **1 GB** — 760 MB of sources, object trees and toolchain
over ~200 MB of base system, measured by sampling a build — so building on the root would
have made every node for ever carry a disk sized for a compiler it does not have. The
builder attaches a separate scratch volume (`build_scratch_gb`, 4 GB) which is absent from
the AMI and deleted with the build instance; `provision.sh` puts the sources and the object
trees there and falls back to `/tmp` when no such device exists, which is what the local
container build sees.

⚠️ **A dirty tracked tree refuses to build, and that is deliberate.** The image is built from
`git archive`, so an uncommitted change would be silently absent from a twenty-minute build.
Name what to build instead of committing under pressure — which is also what to do on a tree
two people share:

```sh
packer build -only=fastpki.amazon-ebs.alpine \
    -var 'release=1.2.3' -var 'source_ref=1.2.3' deploy/cloud/image
```

## Alpine's own image by default, and when to build one

FastPKI's CA keys live in a PKCS#11 token, and three components in that path are built
from source with our own patches (`deploy/pkcs11-provider-allowed-mechs.patch`,
`deploy/p11-kit-mechanisms.patch`, `deploy/softhsm-allowed-mechs.patch`). Alpine's
packaged versions are unpatched, and unpatched p11-kit drops four mechanisms from its RPC
relay — so an Ed25519 or ML-DSA CA cannot be created at all, and the error names the slot
(`CKR_TOKEN_NOT_PRESENT`) for a problem about the algorithm.

Every release publishes those three prebuilt, in its native package. So by default a server
starts from **Alpine's own cloud image** and `deploy/cloud/firstboot-install.sh` installs
FastPKI at first boot: it downloads the release from fastpki.com — which answers over IPv6,
where github.com does not — checks the release signature against the key in
`docs/release-keys/` of your checkout, and unpacks it. Nothing is compiled, and no toolchain
is ever on a CA host. The AWS and Proxmox modules both embed that one script, so the check
exists once.

**Build a custom image only for servers that cannot reach the internet at first boot.** It
carries FastPKI already, so its first boot downloads nothing — `ami_id` on AWS,
`template_vm_id` on Proxmox. The rest of this README is how to build one.

The image is built **on top of Alpine's official cloud AMI** rather than from an imported
disk. Alpine's own cloud-image build system already handles ENA, NVMe EBS and the
bootloader; starting from its output means inheriting that work on every release instead
of re-solving it, with no S3 upload and no `vmimport` role.

`deploy/cloud/image/provision.sh` finishes by standing the real arrangement up — SoftHSM
behind p11-kit, reached through the client shim — and asking the token what it advertises.
If ML-DSA and EdDSA are not relayed, the build fails and the image is not published. That
assertion is the reason the image exists, so it is not left to be discovered in production.
The throwaway token it uses is destroyed before the snapshot: **an image must never carry
a token**, or every instance launched from it would share CA key material.

## What gets created

Per data center (`dc_count`), in its own availability zone:

| | |
|---|---|
| **mgmt subnet**, public | SSH, the console (8090), the enrolment protocols. Routed to the internet gateway. |
| **interconnect subnet**, private | PostgreSQL logical replication, and nothing else. **No route off the VPC at all** — no NAT, no IGW. |
| **instance** | two ENIs, one in each subnet, both attached at launch. |
| **data volume** | encrypted gp3, separate from the root volume, `prevent_destroy`. Holds the database, `/var/pki` and the token. |
| **IPv6 address** | on the management interface, public and free. |
| **Elastic IP** | on the management interface — only when `public_ipv4 = true`. |

The management subnets are **dual-stack**; the interconnect is IPv4 only, because it must
have no route off the VPC and the mesh conninfos are built from those addresses.

**`public_ipv4 = false` is the cheap posture, and the question it answers is who has to
reach the nodes** — administrators, enrolment clients, and relying parties fetching CRL and
OCSP. If every one of them has IPv6, drop the Elastic IPs: AWS charges $0.005/hour for each
public IPv4 address, while an instance is running, while it is stopped, and while the
address merely sits allocated. A node keeps its **private** IPv4 address either way, so the
metadata service that delivers its answers file at first boot, the interconnect and the
replication conninfos are unchanged — what it loses is the route to the IPv4 internet.
There is no NAT gateway in this module, deliberately: one costs about $32/month, nine times
the addresses it would replace.

The two networks are separate for the same reason `deploy/lab/` separates them: the
partition test cuts the interconnect and must not drop its own SSH session. A deployment
where both ride one path cannot be tested that way — nor firewalled that way, which
matters more. The interconnect security group allows 5432 **from itself only**, which
stays correct when a node is replaced.

That rule only matches traffic that leaves through an interconnect interface. Each data
center's interconnect is a subnet of its own, because a subnet cannot span availability
zones, and a node on its own knows the route to its own interconnect subnet only. So the
first-boot script routes every other data center's interconnect subnet through `eth1`, via
that subnet's router:

```
$ ip route get 198.51.100.10       # data center 2's interconnect address, asked on node 1
198.51.100.10 via 192.0.2.1 dev eth1 src 192.0.2.10
```

It installs the routes as a dhcpcd hook, `/etc/dhcpcd.exit-hook`, so they come back after a
reboot and every lease renewal, and it sets `nogateway` on `eth1` in `/etc/dhcpcd.conf` so
the interconnect never carries a default route. Without the routes the kernel sends to a peer
through `eth0`, the peer's security group drops every packet, and `fastpki-mesh` reports
`timeout expired`.

## Secrets

There are none in the tfvars, none in the Terraform state, and none in user-data. Each
node generates its own database password and token PIN from the kernel CSPRNG at first
boot. user-data is readable by anything on the instance that can reach the metadata
service and is stored in the account; a token PIN protecting every CA key on the node has
no business in either.

## After apply

`tofu output next_steps` prints this, and it matters — the deployment is not finished when
the instances are running:

1. Open a console URL and change the admin password. The seeded `admin/admin` row is
   `must_reset`, so nothing else works until you do — it cannot even enrol a certificate.
   On a mesh, set the **same** password on every node: each one seeded its own `admin` row,
   and joining them replicates `admin` as one account, so one row survives and the other
   passwords stop working. `deploy/mesh-join.sh` reports which row the mesh kept.
2. **Create the root and issuing CA.** There is no CA yet, by design; the enrolment
   listeners stay down until one exists.
3. Issue the console/EST/ACME/MS service certificates from it.

For a mesh (`dc_count > 1`), the command in the `mesh_join` output, run twice from your own
machine:

- **before step 2.** Its first run tells every node about the others and stops, because no CA
  exists yet. It has to come first: a CA certificate carries the addresses where clients fetch
  its revocation list and its CA certificate, they are written in when it is created, from
  the list of data centers this run fills in, and they can never be changed afterwards.
- **after step 3.** The same command issues each database certificate from its data center's
  CA, connects the data centers, and waits until they hold the same data.

For a data center with a standby, the command in the `standby_join` output joins it, once the
CAs exist. `docs/deployment.md` §12, steps 6 to 12, walks through all of it.

## Updating a running node

⚠️ **Not by changing `ami_id` and applying.** That replaces the instance, and each node's
database password and token PIN are generated on the node at first boot and written to
`/etc/conf.d/fastpki` on the ROOT volume — the half a replacement throws away. The data
volume keeps the PostgreSQL role and the sealed token, so the new instance arrives with
freshly generated secrets that open neither.

`user-data.sh.tftpl` refuses at first boot when it finds a database on the volume and no
secrets on the machine, naming the three ways out, so the node no longer comes up
half-working. But the deployment is down until one of them is done. Replacing instances is
for a deployment you would be content to rebuild from nothing — and then the data volumes go
with them.


A node keeps the version its image was built with. To update one in place — keeping its database and
token — build a package of the new release with `deploy/native/build-check.sh --package` and
install it on the node; `docs/admin-guide.md` §14.4 gives the steps. The node needs no internet
access and no build tools for it.

## An HA pair

`standby_dcs` names the data centers that get one: `standby_dcs = [1]` gives data center 1 a
second machine, in the same availability zone and the same two subnets as its primary, with
its own data volume. `dc_count` still counts data centers, so `dc_count = 2` is two data
centers with one server each until you ask for a standby as well.

⚠️ **The module provisions the machine; one command from your own machine joins it:**

```bash
deploy/ha-join-pair.sh --primary alpine@<primary> --standby alpine@<standby> -i ~/.ssh/fastpki_cloud_ed25519
```

It copies the primary's database to the standby, points both servers at both, and copies the
CA keys into the standby's token (`high-availability.md` §4). It is not done at first boot
because it needs the primary's database password and token PIN, and neither may be in
user-data. The `standby_join` output prints it with this deployment's addresses.

⚠️ **Same availability zone as the primary, deliberately.** The pair's one address moves
between their interfaces through the EC2 API, and an address cannot cross a subnet boundary.
Surviving the loss of an availability zone is what the mesh is for; a pair survives the loss
of a machine.

⚠️ **And the CA keys have to be created `--replicable` before that standby exists.** A key is
copyable or it is not, decided when it is generated, and a standby that cannot receive a key
can never sign with it. Deciding this after the pair is wanted means re-creating every CA and
re-issuing everything they signed. It applies to the service credentials too
(`renew-service-certs --replicable`, or `SERVICE_KEYS_REPLICABLE=true` for the nightly job).

The keys are copied over the key tunnel, `P11_TLS`. Both servers of a data center in
`standby_dcs` are installed with `P11_TLS=on`, and the interconnect security group admits the
tunnel's port 12345 between its members, so nothing has to be added by hand.

### The address

A pair advertises one address, because the CRLDP and AIA URLs inside an already-issued
certificate cannot be changed. In a VPC that address cannot be a VIP — VRRP needs multicast
and a host able to claim an address on the wire, and a VPC gives neither, so `keepalived`
elects a master and logs success while the address it holds reaches nobody.

`aws-ha-address.sh` moves the address between the two nodes' interfaces through the EC2 API
instead: `create` once, `show` to see who answers, `move` after `deploy/pg-promote.sh` has
promoted the survivor. It runs on the operator's machine rather than on a node, so no host
holding CA keys needs an instance profile that can reassign addresses in its own VPC.

`create` and `move` take `--ssh`, which configures the address on the node and installs a
boot script. The script asks the instance metadata service at every boot whether AWS still
routes the address here, and gives it up if not — so a node that returns after a failover it
was down for does not come back claiming the address the survivor now holds.
[`high-availability.md`](../../docs/high-availability.md) §4a has the detail, including why
the standby must sit in the same subnet and when a Network Load Balancer is the better
answer.

## Key storage

`key_backend = "softhsm"` is the demo posture: CA keys in a software token on the
instance's data volume. For a SaaS offering that is the wrong answer, and because keys are
referenced by `pkcs11:` URI the alternative is one variable — point `pkcs11_module` at
CloudHSM's library and nothing else changes.

**This module does not provision a CloudHSM cluster.** That is a five-figure-a-year
resource with its own initialisation ceremony, its own trust anchor and its own crypto
officer; creating one as a side effect of `tofu apply` would be the wrong kind of surprise.
Point `pkcs11_module` at a cluster you already run.

## Cost

Nothing here is free tier at three nodes: three instances, three EBS data volumes, and
cross-AZ traffic for the replication — plus three Elastic IPs unless `public_ipv4 = false`,
which is the one line that changes the standing cost of a deployment that is powered off
between demos. `--destroy` removes the instances
and leaves the data volumes behind (they carry `prevent_destroy`) — deliberately, because
they hold every issued certificate and, with SoftHSM, every CA private key. Deleting them
is a manual act.
