# Native Alpine install

FastPKI running directly on an Alpine host — OpenRC services, a host PostgreSQL, no
Docker. This is what the cloud images in `../cloud/` are built from, and it is a supported
way to install on a machine you already have.

**Alpine only.** Not a preference: the shipped container image is Alpine, so Alpine is the
only platform the test suite has ever run the binaries against. A native install on
another distribution would be a runtime nothing has been tested on.

## Two steps, deliberately separate

| step | script | when |
|---|---|---|
| **bake** | `build-native.sh` | builds the patched PKCS#11 stack and the binaries, installs the OpenRC services. Slow (a from-source build of four projects), and identical on every host. |
| **configure** | `install-native.sh` | asks the deployment questions, writes the config, sets up the database, starts the services. Fast, and different on every host. |

Splitting them is what makes a custom cloud image worth building: the bake happens once,
at image build time, and every instance launched from it only runs the configure step.

```sh
# on a fresh Alpine box, as root
sh deploy/native/build-native.sh     # ~10-20 min: pkcs11-provider, p11-kit, SoftHSM, FastPKI
bash deploy/native/install-native.sh # the wizard
```

`install-native.sh --answers <file>` takes the same answers file as `deploy/install.sh`,
so a compose deployment's answers configure a native one unchanged.

The installer seeds the console account `admin` / `admin`, marked so it must be changed at
the first sign-in. If this host is going to join a mesh, set the **same** password you set on
the other data centers: every installer on every path seeds its own `admin` row, and joining
replicates `admin` as one account, keeping one row and discarding the rest.
`deploy/mesh-join.sh` warns before it joins and reports which row the mesh kept.

## Checking the bake without a cloud account

`build-check.sh` runs the whole bake in a throwaway Alpine container — the same
`deploy/cloud/image/provision.sh` the AMI build runs, not a copy — so a patch that stopped
applying, a p11-kit that no longer relays ML-DSA, or a compile error costs nothing to find
instead of a twenty-minute EC2 round trip.

```sh
sh deploy/native/build-check.sh              # bake HEAD, ~15-30 min, free
sh deploy/native/build-check.sh --ref v1.0.0 # a specific ref
sh deploy/native/build-check.sh --keep       # leave the container to poke at
```

Run it on every change. Run `packer build` only when there is a release to pin an image to.

`--package <file>` also writes the files that bake installed to a tarball, once the bake has
passed. That tarball is how a node already running from the cloud image is updated — it has no
toolchain to build with — and `docs/admin-guide.md` §14.4 gives the procedure. It holds no token
and no configuration.

It does not boot anything, so cloud-init, the ENA/NVMe drivers and OpenRC supervising the
services under a real init are outside its reach — but they are outside the cloud bake's
reach too, since the bake never starts a service.

## What is here

| file | |
|---|---|
| `build-native.sh` | the bake. Reads its version pins **out of the Dockerfile** so the container and native builds cannot drift to different commits. |
| `build-check.sh` | runs the bake locally in a container, via the real provision script; `--package` exports the result to update cloud nodes. |
| `run-check.sh` | boots the baked image under OpenRC and asserts the deployment actually comes up. |
| `install-native.sh` | the wizard. Same questions, order and defaults as `deploy/install.sh`. |
| `openrc/fastpki.initd` | template service, symlinked once per protocol (`fastpki-ocsp`, `fastpki-est`, …) — the OpenRC equivalent of `deploy/fastpki@.service`. |
| `openrc/fastpki-token.initd` | serves the SoftHSM token over p11-kit. Not enabled when a vendor PKCS#11 module is configured. |
| `openrc/fastpki-pgtls.initd` | adopts a CA-issued PostgreSQL certificate when the console issues one. |
| `openrc/fastpki-auditfwd.initd` | the audit forwarder (opt-in, like the compose `auditfwd` profile). |
| `pg-tls-sync.sh` | the certificate copy the above service runs. |
| `hold-p11-kit.sh` | holds Alpine's `p11-kit` packages at the installed version, so `apk upgrade` cannot replace the patched libraries. |
| `periodic/fastpki-certrenew` | daily service-certificate renewal, via busybox `crond`. |
## The one thing that is genuinely different from compose

**The services must be supervised by something that respawns them on a *clean* exit.**

FastPKI is crash-only by design. Three paths call `std::_Exit(0)` — exit status **0**, not
a failure — and every one of them expects to be restarted:

* a `pkcs11:` handle goes dead because SoftHSM or its p11-kit server restarted. A PKCS#11
  module is initialised once per process, so no reload can recover it; only a new process
  can.
* `<PROTO>_ENABLED` is switched off in the console: the process exits so it comes back at
  the blocked-start poll loop with its port shut.
* a `<PROTO>_RESTART_AT` marker is set.

compose supplies this with `restart: unless-stopped`. So every service here uses
`supervise-daemon` with `respawn_max=0`.

**Measured**, in a container running OpenRC, on three otherwise identical services whose
command exits 0 immediately:

| supervisor | restarts |
|---|---|
| `start-stop-daemon` — OpenRC's default | **1** — started once, never again |
| `supervise-daemon`, default `respawn_max` | **6**, then it gave up |
| `supervise-daemon`, `respawn_max=0` | **14** and counting |

So the default supervisor turns "switch a protocol back on in the console" into "the
protocol is permanently down, with nothing in any log", and the default *budget* turns it
into the same thing on a deployment whose token has restarted a few times. Neither of those
exits is a failure, so there is no failure count to bound.

`run-check.sh` re-runs this against a real FastPKI service: it switches a protocol off in
the config table, waits for the port to close, and asserts the service is still supervised
rather than dead — then switches it back on and asserts it listens again.

The blocked-*start* path polls rather than exiting, so there is no crash loop to guard
against.

## Service control

```sh
rc-service fastpki-web status          rc-service fastpki-web restart
rc-status                              # everything in the default runlevel
tail -f /var/log/fastpki/fastpki-web.log
```

Configuration lives in `/etc/fastpki/bootstrap.conf` (the binaries read it, 0640
root:fastpki) and `/etc/conf.d/fastpki` (the init scripts read it, 0600 root). The init
scripts pass three of its values to the services: `PG_BIND`, `P11_TLS` and, on an HA
standby, `STANDBY_OF` (`docs/high-availability.md` §4 Step 4). Everything
except `PG_CONNINFO` can also live in the `config` database table, which overrides the
file — manage it with `fastpki-config` or the console's Config page.
