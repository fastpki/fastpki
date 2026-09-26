# FastPKI clients demo

A runnable demonstration of the certificate lifecycle a real client performs
against a FastPKI deployment, driven with real clients — `openssl`
(EST/CMP/OCSP), `scep-testclient` (SCEP), `curl` (Store), `certbot`
(ACME) — and printed with per-step timing.

It runs in two modes: against a **throwaway** deployment it spins up itself, or
against an **already-running deployment** as a remote client.

⚠️ **`pki-bench.sh` needs `FASTPKI_BIN` when run from a release tarball.** It measures with
locally built client binaries and looks for them in `build/`, which a tarball does not
carry — `build/` is gitignored and the release is a `git archive`, so it contains no build
output by design. Point it at binaries you have:

```bash
FASTPKI_BIN=/path/to/build demo/pki-bench.sh …
```

`pki-demo.sh` runs from a tarball too, and every leg but one needs no build output. The
exception is SCEP, which drives `scep-testclient`: with no such binary in `FASTPKI_BIN` it
reports

```
→ SCEP enroll for scep-client.internal... skipped (no scep-testclient in <dir>)
```

and the rest of the lifecycle still runs. The same `FASTPKI_BIN` points both scripts at
binaries you have.

## Contents

- [Throwaway mode](#throwaway-mode)
- [Key and hash coverage (throwaway only)](#key-and-hash-coverage-throwaway-only)
- [Live mode (drive a running deployment remotely)](#live-mode-drive-a-running-deployment-remotely)
  - [A Kubernetes deployment](#a-kubernetes-deployment)
- [What the lifecycle shows](#what-the-lifecycle-shows)
- [Throughput benchmark](#throughput-benchmark)
- [Cleaning up after a run](#cleaning-up-after-a-run)

## Throwaway mode

```bash
demo/pki-demo.sh --throwaway
```

Stages its own **docker compose** stack — postgres, softhsm and every protocol
service — under a private project name on high loopback ports, runs the demo
against it, then tears it down with its volumes. Nothing is provisioned by hand:
the CA is created with `fastpki-ca`, every service credential is issued through
the console API, and every private key is generated inside the stack's SoftHSM, so
no private key ever exists on the host.

It needs a working `docker` and the `fastpki:local` image, which it builds via
`deploy/build-image.sh` if that image is missing. Honours `$OSSL` /
`$OPENSSL_LIBDIR` like the test suite (default `/opt/openssl-3.5` on Linux, or
the `openssl` on `PATH` — e.g. Homebrew `openssl@3` — on macOS).

Exit status is non-zero if any step fails, so it doubles as an end-to-end smoke
check. `FASTPKI_DEMO_KEEP_STACK=1` leaves the stack up for inspection.

**Live mode is the default** once `demo/.target.env` exists (see below), so pass
`--throwaway` explicitly to get the staged stack instead.

## Key and hash coverage (throwaway only)

The lifecycle above runs once. On top of it the demo sweeps the axes a PKI has to
get right — the CA key, the service credential key, the client key, the CSR
digest, and the OCSP/CMP response digest:

```bash
demo/pki-demo.sh --throwaway                 # four one-factor-at-a-time sweeps
demo/pki-demo.sh --throwaway --full-matrix   # the cross-product
demo/pki-demo.sh --throwaway --quick         # one per family — what tests/ drives
```

| Flag | Axis | Default |
|---|---|---|
| `--ca-keys`      | CA signing key            | `rsa:4096 rsa-pss:4096 ec:P-521 ed448 ml-dsa-87` |
| `--server-keys`  | service credential key    | `rsa:3072 rsa-pss:3072 ec:P-256 ed25519 ml-dsa-44` |
| `--client-keys`  | client key                | same as `--server-keys` |
| `--hashes`       | CSR signature digest      | `sha3-256 sha3-512` |
| `--response-mds` | OCSP/CMP response digest  | `sha3-256 sha3-512` |
| `--protocols`    | protocols exercised       | `est cmp scep acme` |

Every cell runs a full lifecycle — enroll, validate against the chain with
`-x509_strict` and a live CRL fetch through the certificate's own CRLDP, renew,
revoke, then validate again as revoked — not just an enrolment.

Combinations that cannot exist are refused rather than run, and the report names
each one: TLS carries no ML-DSA code point (RFC 8446), SCEP's RA must be RSA
(RFC 8894 §3.1 key transport), OpenSSL cannot encode an RSA-PSS SPKI restriction
naming a SHA-3 digest, and a one-shot scheme (Ed25519/Ed448/ML-DSA) prehashes
nothing — so for those client keys the hash axis collapses to one cell instead of
scoring the same CSR twice.

The key spec separator is a **colon**: `ec:P-384`, not `ec-384`.

## Live mode (drive a running deployment remotely)

Point the demo at a real deployment and it acts as a remote client. First provision a
target descriptor. `provision-target.sh` signs in to the console, creates a demo
`requester` user and its enrolment credentials, and reads every listener's port back from
the console, so it needs no login on the server for this:

```bash
demo/provision-target.sh --web-url https://pki.example.org:8090 --admin-pass 'ADMIN-PASSWORD'
demo/pki-demo.sh --target demo/.target.env
```

Use the deployment's own name, the one in `PKI_DNS`, in `--web-url`. certbot checks it
against the server's certificate, and the certbot cell fails with `Hostname mismatch`
under any other name.

`provision-target.sh` writes `demo/.target.env` (git-ignored — it holds
credentials). The demo bootstraps CA trust from EST `/cacerts` at run time, so
nothing about the CA leaves the node during provisioning. This is how the demo
runs from a workstation against a remote multi-data-center deployment over a VPN.

That is enough for EST, CMP, SCEP, OCSP, the store and the TLS checks. The ACME cells
need administrative access too, and each kind of deployment gets it differently:

| Deployment | Add to `provision-target.sh` |
|---|---|
| Docker Compose | `--ssh-target USER@HOST --challenge-fqdn NAME`, as for a native node below |
| Kubernetes | `--namespace NS`, and `--ssh-target USER@NODE` unless `kubectl` here reaches the cluster ([below](#a-kubernetes-deployment)) |
| Native or cloud | `--ssh-target USER@HOST --challenge-fqdn NAME` ([below](#a-native-or-cloud-deployment-no-container-runtime)) |

### A Kubernetes deployment

```bash
demo/provision-target.sh --web-url https://pki.example.org:8090 --namespace fastpki \
    --ssh-target admin@node.example.org --admin-pass 'ADMIN-PASSWORD' \
    --out demo/.target-k8s.env
demo/pki-demo.sh --target demo/.target-k8s.env
```

- `--ssh-target` is a login on a machine where `kubectl` works, such as a k3s node. The demo
  runs every `kubectl` command there, so this machine needs no kubeconfig. Leave it out when
  `kubectl` here already reaches the cluster.
- `provision-target.sh` checks that `kubectl` can see the deployment in the namespace, and
  stops if it cannot.
- For dns-01 the demo starts a CoreDNS in the namespace. For http-01 and tls-alpn-01 it
  publishes this machine to the cluster as a temporary Service, so no `--challenge-fqdn` is
  needed. Both are removed at the end.
- The cluster must reach this machine on ports 80 and 443. On macOS the demo takes those
  ports without `sudo`.

### A native or cloud deployment (no container runtime)

A node installed by `deploy/native/install-native.sh` — which is what the cloud image
produces — has no `docker` and no `kubectl`, so there is nothing to `exec` into. Provision
it through the console API instead:

```bash
demo/provision-target.sh --web-url https://pki-1.example.org:8090 \
    --challenge-fqdn driver.example.org \
    --ssh-target fastpki@pki-1.example.org
demo/pki-demo.sh --target demo/.target.env
```

- `--challenge-fqdn` is a name **that deployment resolves back to the machine running the
  demo**. The ACME http-01 and tls-alpn-01 cells need it, because the server connects to it
  on :80 and :443.
- `--ssh-target` is optional and buys one thing: dns-01. The server has to be told which
  resolver to ask for the challenge TXT, which means writing `ACME_DNS_RESOLVER` and
  restarting `fastpki-acme` — administrative access the demo user does not have. Without it
  everything else still runs and the two dns-01 cells skip.

⚠️ **The names in the certificates must resolve where the DEMO runs.** The CRL DP and AIA
URLs come from `PKI_DNS`, and the demo validates every certificate it is issued with
`chain + strict + CRL`. If those names do not resolve on the client, every one of those
checks fails with `unable to get certificate CRL` — about a CRL that is being served
perfectly well.

### Driving it from the test image

The enrolment test clients (`scep-testclient`, `fastpki-cmp`) are not in the shipped image,
so a host that has only the shipped image cannot run the SCEP or CMP cells. The test image
built by `tests/run-in-container.sh` carries them, and can drive a remote deployment:

```bash
docker run --rm --network host \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$HOME/.ssh:/root/.ssh:ro" \
  -v "$PWD:$PWD" -w "$PWD" -e OPENSSL_CONF= -e FASTPKI_BIN=/usr/local/bin \
  --entrypoint bash fastpki-test:local \
  demo/pki-demo.sh --target demo/.target.env
```

The docker socket and the SSH key are what the ACME cells need — CoreDNS runs in a
container, and dns-01 reconfigures the deployment over ssh.

⚠️ **Mount the repository at the same path inside as outside** (`-v "$PWD:$PWD" -w "$PWD"`).
CoreDNS is started as a *sibling* container through the host's daemon, so the `-v` it is
given is resolved by the host: a repo mounted at `/repo` inside makes docker create an empty
`/repo` outside, CoreDNS starts with no Corefile and exits, and certbot reports only
`All authorizations were not finalized`.

## What the lifecycle shows

| Protocol | Action | Client |
|----------|--------|--------|
| **EST** (RFC 7030)  | enroll (`simpleenroll`)         | `openssl req` + curl |
| **CMP** (RFC 4210)  | enroll (`ir`)                   | `openssl cmp` |
| **OCSP** (RFC 6960) | check status — *good*           | `openssl ocsp` |
| **CMP** (RFC 4210)  | revoke (`rr`) → OCSP *revoked*  | `openssl cmp` |
| **SCEP** (RFC 8894) | enroll (`PKCSReq`)              | `scep-testclient` |
| **Store** (RFC 4387)| retrieve by attribute           | curl |
| **ACME** (RFC 8555) | enroll (dns-01, see note)       | bundled ACME client |

Deliberately happy-path, as suggested on the ticket.

### Mode-specific notes

- **CMP revoke, live:** revocation requires signature-based protection by a cert
  whose CN equals the target's owner (self-service authorization), so the demo
  enrolls a short-lived `CN=<owner>` identity cert and signs the `rr` with it,
  judging success by the **OCSP status flip** (the `openssl` client exits
  non-zero validating the CA-signed response only because FastPKI's issuing-CA
  cert carries `keyCertSign`/`cRLSign` but not `digitalSignature` — a cosmetic
  interop nit). This needs `CMP_CLIENT_CA_ID` set on the CMP service; where it
  isn't, the live demo **skips** the step with a note and the full CMP revoke is
  shown in `--throwaway` mode.

- **ACME:** ACME's challenge validation is **inbound to the client** (the server
  connects back to prove domain control), so a purely remote client over a
  one-way link can't be validated. ACME is therefore run against a **co-located**
  `fastpki-acme` (identical binary) via a full RFC 8555 order over the **dns-01**
  challenge — **privilege-free** (no `:80`), using the repo's bundled ACME client
  (driven in shell by `tests/acme_jws.sh`, with `build/dnsstub` serving its own tiny UDP
  DNS server for the `_acme-challenge` TXT). `--no-acme` skips it.

- **MS-XCEP/WSTEP** is proven separately against the real Windows enrollment
  client; it slots in here once a lab Windows VM is available.

## Throughput benchmark

```bash
demo/pki-bench.sh [-n COUNT] [-k "rsa2048 rsa3072 ec256 ec384"] [-p "est cmp"]
```

Measures certificates **issued per second, per protocol, per key type**, with
real EST + CMP clients, against a throwaway deployment (so it never touches a
real database). Key generation is pre-computed and excluded, so the rate
reflects server-side issuance throughput. Live benchmarking into a shared DB is
deferred pending the maintainer's call on DB pollution.

**The bench's ACME leg is http-01, not dns-01**. The bench issues N certificates and
paid ~2.4 s each rebuilding a DNS container in its auth hook, against 0.003 s to write a file
into a webroot. The demo issues one, so it keeps dns-01 for coverage — **not** because dns-01
is the only wildcard-capable challenge. It is not: RFC 8555 says nothing of the kind,
and http-01 and tls-alpn-01 validate a wildcard's base domain like any other name. Requiring
dns-01 for wildcards is CA policy, not protocol. It runs one `nginx` container
for the whole run and orders through `certbot --webroot`. The identifier differs by mode
because "localhost" does not mean the same machine in both: throwaway runs `fastpki-acme`
as a host process, so nginx publishes `:80` and the order names `localhost`; `--target`
runs it in a container, so nginx joins that container's network and the order names
`fastpki-bench-http`, which docker's embedded DNS resolves. `tests/acme_dns01.sh` keeps
the dns-01 coverage either way. Needs `docker` and `certbot`; the leg skips without them.

## Cleaning up after a run

The demo removes what it issues — the closing line reports how many certificates it
revoked — and reverts anything it changed on the target. Two things it leaves are worth
knowing about, because neither is removed by a later run.

**Working directories under `build/`.** Each run keeps `build/.demo-XXXXXX` only when a step
failed, and says so on the last line. They are small, but if the run was driven with `sudo`
— which the ACME `http-01` and `tls-alpn-01` cells need, since they bind :80 and :443 — the
directory is owned by **root**. A later `rm -rf` as the ordinary user then fails with
`Permission denied` on a tree that looks like it should be yours:

```sh
sudo rm -rf build/.demo-*
```

**A generated `build/scep-testclient`.** On a host with no local build, the demo writes a
small shim there that runs the real client from a container image (see
`demo/testclient.sh`). It is a shell script, not a binary, and it is regenerated whenever it
is missing. Delete it, or build the real client over it, to go back to a local one.
