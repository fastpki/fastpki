# Changelog

What changed in each release. The newest is first.

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
