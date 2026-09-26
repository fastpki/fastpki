# Changelog

What changed in each release. The newest is first.

## v0.3.1

**Updating from v0.3.0 changes the database schema.** The update adds one column, for the
console's idle timeout, as schema step `0003-web-session-idle.sql`. Update the usual way: the
schema first, then the programs. `rolling-update.sh`, `deploy/k8s/apply.sh` and a re-run of
`install-native.sh` do both in that order; on a mesh it is run in every data center.

**Every installer asks the same questions.** Kubernetes has an install wizard:
`install.sh --k8s` asks the Docker Compose installer's questions, in the same order and under
the same answers-file keys, and writes `deploy/k8s/env.local`, so one answers file serves every
path. The native and AWS wizards ask them in that order too. On Kubernetes each enrolment
protocol can be switched off (`EST_INSTALLED`, `ACME_INSTALLED` and so on), which leaves it
out of the servers entirely.

**Restoring the database without downtime works on every path.** `db-restore-online.sh`
restores a dump into the standby of a native, cloud or Kubernetes pair as it already did on
Docker Compose, accepts the dump formats the guides produce, and finishes the promotion
itself.

**Console sessions.** A session ends after 15 minutes without use, and 12 hours after sign-in
at the most. A console whose session has ended shows the sign-in page instead of empty pages,
and no console page or answer is cached. On an HA pair a session is the same on both servers,
so signing out, or changing a password, takes effect on both at once.

**The console works on a phone.** Below 760 pixels the side bar becomes a menu button, tables
scroll sideways, and forms and dialogs fit the screen, so users can download their device
profiles from an iPhone.

**The Apple profiles the console serves are signed** with the console's own certificate and
carry its chain, so iOS and macOS show who made them and reject a changed copy. They show as
*Verified* once the device trusts your root.

**The guides are reorganised.** The deployment and high-availability guides now show only
the automated steps: the installer and the other scripts, what each does and what success
looks like. Doing a step by hand is in a new guide, *Manual procedures*, one chapter per
script. The short deployment guide is merged into the deployment guide.

**Security:**

- **ACME http-01 validation follows a redirect only to http or https on port 80 or 443**, at
  most ten times, and checks every address before connecting. Before, an ACME account could
  make the CA fetch any address and port, including internal services and the cloud metadata
  address.
- **No console page or answer can be shown inside another site's frame**, and browsers may not
  guess its content type.
- **The console no longer risks overwriting its memory when it holds many connections.** Its
  endpoint check and the discovery scanner used a method limited to 1024 open connections.

**Fixed:**

- **A native or cloud install on a fresh Alpine host could not use Ed25519, Ed448 or ML-DSA
  keys.** Installing the Alpine packages the release needs put Alpine's own p11-kit over the
  patched copy the FastPKI package had just unpacked, and that copy is what lets those keys
  reach the token. Every AWS server was affected, because it starts from Alpine's own image.
  The installer now unpacks the package again after adding Alpine packages, and
  `install-native.sh` stops with the fix to apply if a patched library has been replaced.
  To repair a v0.3.0 server, unpack the v0.3.0 package over it again and restart the
  services: admin guide §14.4, steps 1 and 2 with the same package.
- **A Kubernetes pair in a mesh lost replication at its first promotion.** Both servers'
  databases were published on the same port, so every peer reached the first server only.
  Each server now has its own port, and an existing mesh picks up the new address the next
  time `mesh-join.sh` runs.
- **Accounts set up before a mesh join now converge.** The join keeps one password for each
  account. Where several data centers had set one, it keeps the first data center's, and the
  next sign-in on any data center asks for a new password. The join says which it kept.
- **OCSP over GET failed for some CAs**, including every request Windows makes, when the
  request's encoding contained a `/`.
- **OCSP asked about another data center's CA** answered with an internal error and logged a
  line per request; it answers `unauthorized` and logs once.
- **The OCSP service picks up a replaced responder key without a restart.** After the
  responder key was replaced, as when turning a single server into a pair, it refused every
  request until it was restarted.
- **Kubernetes: a later `apply.sh` keeps the image the deployment runs.** After a one-line
  install from a release, the next run fell back to `fastpki:latest`, which no registry holds,
  and the servers could not restart.
- **Updating a deployment no longer ends with first-install instructions.** The installers
  told an updated server to sign in as `admin`/`admin`, that no CA existed, or to join a mesh it
  was already part of.
- **Cloud: the same address range for administrators and clients stopped the plan** with
  "Duplicate object key". It is accepted now.
- **Cloud: `--destroy` failed on a deployment with a standby**, and a later install from the
  same folder reattached the kept data disks, which no new server can start from. Both kinds
  of data disk are kept, removed from the OpenTofu state, and listed at the end; the next
  install creates new ones.
- **Cloud: the wizard no longer asks how many data centers there are** when one public name
  per data center was given.
- **Cloud: users can reach the console to download their device profiles.** The console is
  now open to the clients' address ranges as well as the administrators'; SSH stays with the
  administrators. An IPv6 range written with a leading zero no longer shows as changed on
  every plan.
- **Cloud: each AWS server is named after its instance** (`fastpki-1`, `fastpki-1-standby`)
  rather than its private address, in its prompt, its system log and its forwarded audit
  records. This applies to servers created from now on.
- **Proxmox: the module accepts the installer's key storage values** (`softhsm` or `hsm`) and
  can name an HSM's module and token label.

## v0.3.0

**Releases are signed.** Every release publishes `SHA256SUMS`, which lists the hash of every
file in it, and two signatures of that list: `SHA256SUMS.sig` (ECDSA P-256, checkable with any
OpenSSL) and `SHA256SUMS.mldsa.sig` (ML-DSA-87, post-quantum, OpenSSL 3.5 or newer). Check the
signature first, then the hashes:

```bash
openssl dgst -sha256 -verify release-ecdsa.pub -signature SHA256SUMS.sig SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

The public keys are in `docs/release-keys/` and are also compiled into `fastpki-update`, so
`fastpki-update verify SHA256SUMS SHA256SUMS.sig` needs no setup. `install.sh` checks the
signature and the package's hash before it unpacks anything, on every path, and refuses an
unsigned or altered release. Container images pulled from the registry by tag are not covered
by these signatures; the image tarballs attached to a release are.

**A cloud server no longer needs a custom machine image.** The OpenTofu module starts each node
from Alpine's own published image, and the node installs FastPKI at first boot from
`https://fastpki.com/releases`, which answers over IPv6. Nothing downloaded runs until it is
verified: the release signature is checked against the public key in your own checkout, not
one the mirror supplies. A node was configured 44 seconds after launch on AWS. Building your
own image with `deploy/cloud/image` still works, and a node started from it downloads nothing.

**Licensing is shown, and never enforced.** FastPKI is free for non-commercial use under the
PolyForm Noncommercial licence; a commercial deployment needs a licence. Every build carries a
30-day evaluation, counted from the day a deployment first starts. The console's **Version**
page shows the state (the evaluation and the day it ends, licensed with the licence number
and expiry, expired, or evaluation ended) and installs a licence file: pick the file or paste
it, and the signature is checked before it is stored. Every service logs the state once at
startup. Nothing stops working when an evaluation or a licence ends.

**Apple devices can enrol over ACME with device attestation.** A Mac with Apple silicon or an
iPhone or iPad asks for a certificate from an ACME configuration profile and proves it is
genuine Apple hardware, with its key kept in the Secure Enclave. A later certificate for the
same device revokes the previous one as superseded. Two ways to authorise a device:

- **A one-time ticket**, for a device enrolled by hand. A user downloads a ready profile from
  the console's Dashboard, **Apple ACME profile**, and the profile carries a new ticket issued
  to them; on an iPhone, tapping the button in Safari offers the profile for installation.
  An administrator can issue tickets for someone else on the new **Enrolment codes** page, or
  with `fastpki-acme --issue-device-ticket --ca <ca-id> --owner <user>`.
- **A registered serial number**, for an MDM fleet. The MDM puts each device's serial in the
  profile, and the administrator lists the serials on the **Enrolment codes** page, one by one
  or as a CSV from the MDM. Apple attests the serial, so a device cannot claim another's. The
  list replicates to every data center.

MDM is not required: the profile works installed by hand. The user guide (§6.5) has a complete
profile.

Two options build on the attestation, both off by default:

- **The device's serial number in the certificate.** A certificate profile can add the
  serial number Apple attested to the SubjectAltName, as an RFC 4043 permanentIdentifier, so a
  RADIUS or VPN server can match the device to the MDM inventory. Leave it off for
  certificates shown to arbitrary servers.
- **Posture checks.** `ACME_ATTEST_MIN_OS` refuses a device whose attested OS version is lower
  (a device too old to attest its version is refused too), and `ACME_ATTEST_REQUIRE_SIP`
  refuses a Mac with System Integrity Protection off.

**Apple devices can also enrol over SCEP from a configuration profile**, installed by hand or
delivered by an MDM platform. Users download it ready-made from the Dashboard, **Apple SCEP
profile**, carrying their own SCEP challenge. The user guide (§8.5) has the details for macOS
and iOS.

**The Enrolment codes page** lists, issues and cancels ACME device tickets and SCEP one-time
challenges, and maintains the registered device serials, with the same actions in the API.
Both kinds of one-time code used to be issued only on the command line, with no way to see
which were still unused.

**What Apple devices accept is now measured.** macOS 15.5 and 27.0 accept RSA and EC
certificates, and reject RSA-PSS, Ed25519, Ed448 and ML-DSA; iOS 18.5 gave the same verdict on
every case tried. An EC P-521 key works for a CA but not for a TLS server: a console, EST,
ACME or MS-XCEP listener with a P-521 or `rsa-pss` key cannot be reached from a Mac or an
iPhone. The default, EC P-256, works everywhere. A root
installed from a profile by hand is not trusted for TLS until you turn that on. The
compatibility guide (§4) has the details and a `security verify-cert` command to test a chain
on a Mac.

**Updating from v0.2.x changes the database schema.** The update adds two tables for device
attestation, as schema step `0002-acme-device-attestation.sql`. Update the usual way: the
schema first, then the programs. `rolling-update.sh`, `deploy/k8s/apply.sh` and a re-run of
`install-native.sh` do both in that order; `postgres.md` §4.2 has the command for applying it
by hand, and on a mesh it is run in every data center.

**Fixed:**

- `./install.sh` failed at its first question on Debian and Ubuntu with `printf: Illegal
  option -v`. It runs under any POSIX shell again.
- On a stock Alpine host, the native installer left the scheduler (crond) disabled, so the
  nightly renewal of FastPKI's own certificates never ran, and it left the PostgreSQL data
  directory owned by root. Both are set up now.
- `fastpki-scep --issue-challenge` issued a one-time challenge that could never enrol when
  no profile was named and the SCEP identity held none. It now refuses at once and says what
  to grant.
- The ACME service now logs every request it refuses, with the reason. Before, a refusal
  reached only the client.
- The configuration reference and the deployment guide listed only some of the settings that
  cannot come from the environment, and gave the wrong totals. Both lists are complete.

## v0.2.3

**Updating a node no longer breaks a high-availability pair.** A native or cloud node is
updated by running the installer again with the same answers. That rebuilt the database
connection string from scratch and named a single host, which undid the two-host form the HA
join writes:

```
host=<primary>,<standby> port=5432,5432 … target_session_attrs=read-write
```

That line is the whole of failover: the PostgreSQL client tries each host and uses whichever
one accepts writes, so promoting the standby needs no reconfiguration anywhere. After the
update each node reached only its own PostgreSQL. On whichever node was the standby that
database is read-only, so the services there could no longer write and the console would not
start at all. The installer now keeps the host list, the ports and `target_session_attrs`
across a re-run, exactly as it already keeps the token PIN, the database password and the
console port. Docker Compose and Kubernetes were never affected.

**The console starts even when it cannot write to its database.** It cleared expired sessions
as it started, and that is a delete, so on a node whose PostgreSQL is a read-only standby it
exited before opening its port. The service supervisor restarts it without a limit, so it
looped every few seconds while `rc-status` still reported it as started. Expired sessions are
cleared by the primary and arrive by replication, so that sweep is now skipped instead of
stopping the console.

**The install command in the guides works on a bare Alpine.** The native one-liner was
`curl … | bash -s -- --native`, and a stock Alpine has neither program. It is now
`wget -qO- … | sh -s -- --native`: wget is part of busybox and is already on the machine.
Two refusals an operator can otherwise meet without warning are documented as well —
`--package`, for a host with no route to github.com, and that a package must match the node's
Alpine release as well as its processor.

## v0.2.2

**The guides are on fastpki.com, and they read like the rest of it.** Each guide is a page
per chapter with the whole contents down the left, the way the PDF has it, and the current
chapter marked. They carry the site's own design system, so they follow it into dark mode.
The list opens with the deployment guide and ends with the references, rather than opening
with the API reference because the alphabet said so.

**A native or cloud host can now be installed from a release, which is what v0.1.0 claimed.**
Four things stopped it, each found by running the documented one-liner on a fresh Alpine host:

- `install.sh` needed bash, and a stock Alpine has none. It is POSIX `sh` now, so
  `curl … | sh -s -- --native` works on the platform that path exists for.
- It assumed the host could reach github.com. An IPv6-only host cannot, because github.com
  publishes no IPv6 address, and FastPKI's own cloud module builds IPv6-only nodes. It now
  says so instead of reporting that the project has no releases.
- `--package <file>` installs from a package copied to a node that has no route to GitHub.
- The package brought files, not packages. The Alpine packages a release needs are now
  installed with it, `bash` among them.

**A package built for one Alpine release is refused on another.** Alpine moves
shared-library versions between releases, so a package built on 3.24 unpacked on 3.23 used to
install cleanly, report success, start every service, and then fail to run any of them. The
package records what it was built on and both installers check it.

## v0.2.1

The published guides carry a page that lists them, so the documentation has a front door.
Without it each guide could only be reached by already knowing its name.

This is the only change from v0.2.0.

## v0.2.0

**FastPKI can record the real client when something sits in front of it.** Behind a load
balancer or a reverse proxy every request arrives from that one address, so the audit log
could not say who did anything, and the sign-in backoff — which counts failures per account
**and** per client address — became deployment-wide, so one person's mistyped password
delayed everybody.

`TRUSTED_PROXIES` names the proxies whose `X-Forwarded-For` is believed, as addresses or CIDR
prefixes:

```
TRUSTED_PROXIES=10.20.0.0/24, 2001:db8:1::5
```

A request from one of those addresses has its forwarded address recorded; a request from
anywhere else is recorded by its connection address whatever headers it sends. There is no
default: name only proxies you run, because a believed header from anywhere else lets a
caller choose what is recorded about them. See the configuration reference for the whole
rule.

### Fixed

- Updating a native or cloud node failed on the standby of an HA pair. A standby's database
  is read-only, so the installer stopped at the first write — after the new files were
  already unpacked, which left the node running its old programs while reporting the new
  version. The installer now recognises a standby, skips the steps the primary owns, and
  restarts the services, which is all an update needs there.
- The installer's closing summary was written for a first install, so an upgrade ended by
  telling the operator to sign in with the seeded password and to connect a mesh that was
  already replicating. It now says what is true of the node in front of it.
- Joining data centers keeps one `admin` row and discarded the others silently, so a password
  set on one side could stop working with nothing to say why. `mesh-join.sh` now warns before
  it joins when two data centers each have a password set for one account, and afterwards
  names the data center whose row the mesh kept.
- CMP recorded no source address at all in the audit log, so CMP enrolments, revocations and
  refusals appeared to come from nowhere while every other protocol recorded one.
- ACME and MS-XCEP built the URLs they advertise using `X-Forwarded-Proto` from any client at
  all, so a caller could make either service hand back `http://` URLs for itself. Both now
  honour that header only from a trusted proxy.

### Also

- Every release now publishes what changed in it, instead of only how to install it.

## v0.1.0

**A native or cloud host installs from the release instead of compiling FastPKI itself.**
Every release now publishes a package of the installed files, one per processor architecture,
beside the container images:

```
fastpki-native-v0.1.0-amd64.tar.gz
fastpki-native-v0.1.0-arm64.tar.gz
```

Unpack it with `tar xzf … -C /` and run `fastpki-install-native`, or let the installer do the
whole thing:

```sh
curl -fsSL https://github.com/fastpki/fastpki/releases/latest/download/install.sh \
  | sh -s -- --native
```

It downloads the package for the host's architecture, checks it against the release's
`SHA256SUMS`, unpacks it and hands over to the native installer. A host with no compiler and
no build tools can now be a FastPKI node. Take the package matching the node: an arm64 node
needs the arm64 package.

**Every binary reports the release it came from.** `fastpki-web --version` on a native or
cloud node named a development version whatever it was built from, so the only record of what
a machine held was the name of the image it booted, and a node could not answer "which build
am I running?" at all. A release now refuses to publish a package whose binaries report
anything other than that release.

### Fixed

- Installing from a published release built the container image from source instead of
  pulling the published one, which took a quarter of an hour and needed a compiler on a
  machine that was told it needed none.
- `fastpki-config` accepted a CA id that names no CA. The setting was written, every protocol
  that read it then found nothing, and the deployment stopped serving with no indication of
  why. It is now refused, and the message lists the CA ids that exist.
- On AWS, a node that was down during a failover came back claiming the pair's shared address.
  The address had moved to the surviving node, but the failed one could not be reached at the
  time to take it off, so it reconfigured the address at its next start. Each node now asks
  AWS at every boot whether the address is still routed to it, and gives it up if not.
- The demo could not read a console URL written as an IPv6 address — the shape the AWS module
  itself prints. It split the address on the wrong colon, every probe then went nowhere, and
  the failure was reported as a problem with the deployment's CAs.
- The demo treated a Docker Compose deployment reached over the network as a native one, and
  both DNS-based ACME steps were skipped as a result.

### Documentation

- Installing from a published release is described as the normal way to deploy, rather than
  assuming a git checkout.
- Joining two Kubernetes clusters keeps one `admin` row: the guide says to set the same
  password on each cluster, and gives the command.
- Rebuilding a certificate authority leaves an Active Directory domain controller serving its
  old LDAPS certificate until the old one is deleted. The Windows guide says so, and how.
- An HA pair's ACME DNS resolver has to be reachable from both servers; the configuration
  reference says what to set it to.
- The cloud image's build machine is documented with its measured build time, and the AWS Free
  Tier restriction on which instance types may launch.
