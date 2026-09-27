# Third-party notices

FastPKI itself is licensed under the PolyForm Noncommercial License 1.0.0 — see
[`LICENSE.md`](LICENSE.md).

It carries third-party code with its own terms. Those terms are independent of
FastPKI's licence and they travel with every redistribution, **including the
binaries and the Docker image**. This file is that notice; the runtime image
ships it at `/app/NOTICE.md` beside `/app/LICENSE.md`.

Four categories, because the obligations differ:

* **Derived from** — work this project was ported from, whose licence conditions
  follow the derived code wherever it goes, source or binary.

* **Compiled in** — header-only libraries vendored into `third_party/` and
  compiled into every `fastpki-*` binary. Their notices must accompany the
  binaries themselves.
* **Built from source and bundled** — libraries built from source by the
  `Dockerfile` (and by the native build) and copied into the image as shared
  objects. Their notices must accompany the image. Each project's own licence
  file is copied in alongside, under `/app/licences/`.
* **From Alpine packages** — installed from Alpine Linux 3.24 and used as they
  are. Each keeps its own licence. Publishing the Docker image redistributes
  them, so the image carries the exact list of packages it holds, with versions
  and licences, at `/app/licences/alpine-packages.txt`, and each package's
  licence texts under `/app/licences/alpine/`. A native install takes them from
  the operator's own repositories, and a cloud image is built by the operator
  from Alpine's official image, so neither redistributes them.

---

## Derived from

### The PHP PKI this was ported from — MIT

FastPKI began as a C++ port of an earlier PHP implementation, and parts of it
still follow that original closely enough to be a derived work — the MS-XCEP and
MS-WSTEP paths most of all, where the field sets, defaults and response shapes
were taken from it deliberately so that a Windows client would accept them. The
source comments in `src/msxcep/main.cpp` say where.

MIT's one condition is that its copyright and permission notice accompany all
copies or substantial portions of the software. That condition does not lapse
because the derived work is larger, is written in another language, or is
published under stricter terms — PolyForm Noncommercial here. This section is
that notice.

> Copyright (c) 2023 creatica-soft

Under the same MIT terms reproduced in full under
[The MIT License](#the-mit-license) below.

---

## Compiled in

### cpp-httplib 0.46.1 — MIT

HTTP/1.1 transport for every listener. `third_party/httplib.h`, upstream
<https://github.com/yhirose/cpp-httplib>.

> Copyright (c) 2026 Yuji Hirose. All rights reserved.

### nlohmann/json 3.12.0 — MIT

JSON parsing for ACME JWS and the console API. `third_party/nlohmann/json.hpp`,
upstream <https://github.com/nlohmann/json>.

> SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>

### The MIT License

The two libraries above and the PHP original under "Derived from" are all under
these terms, each with its own copyright line beside it:

> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

---

## Built from source and bundled

### SoftHSMv2 — BSD 2-Clause

The default key store. Built from source (`Dockerfile` stage 2b) rather than
installed from Alpine, because ML-DSA support is only on `main`; a local patch
adds `CKA_ALLOWED_MECHANISMS` so the token can be probed without attempting a
signature. Upstream <https://github.com/softhsm/SoftHSMv2>, licence at
`/app/licences/SoftHSMv2.LICENSE`.

> Copyright (c) 2010 .SE, The Internet Infrastructure Foundation
> Copyright (c) 2010 SURFnet bv

### p11-kit 0.26.4 — BSD 3-Clause

Relays PKCS#11 calls from each service to the one token container. Built from source
(`Dockerfile` stage 2a) with a local patch, because its RPC layer otherwise
drops `CKM_ML_DSA` and `CKM_EDDSA` and an ML-DSA or Ed25519 CA cannot be created
through that relay at all. Upstream <https://github.com/p11-glue/p11-kit>,
licence at `/app/licences/p11-kit.COPYING`.

Its third clause is worth stating here, since it constrains how FastPKI may be
marketed: the names of p11-kit contributors may not be used to endorse or
promote products derived from it without prior written permission.

### pkcs11-provider — Apache License 2.0

The OpenSSL provider that lets `EVP_*` reach a PKCS#11 key. Built from source
(`Dockerfile` stage 2) at a pinned commit with a local `CKA_ALLOWED_MECHANISMS`
patch. Upstream <https://github.com/openssl-projects/pkcs11-provider>, licence
at `/app/licences/pkcs11-provider.COPYING`.

> Copyright 2022 simo@redhat.com

---

## From Alpine packages

Installed from Alpine Linux 3.24 and used unmodified. The licence column is the
one Alpine declares for the package. The source of every package is in Alpine's
aports repository, branch `3.24-stable`:
<https://gitlab.alpinelinux.org/alpine/aports>. Each package's build recipe
there, its APKBUILD file, names the upstream source it was built from.

Each package's licence texts, taken from that source, are in the image under
`/app/licences/alpine/<package>/`. In this repository they are in
`deploy/licences/alpine/`, where `SOURCES.txt` records the version and URL each
came from, and `deploy/licences/collect-alpine.sh` collects them again when the
image's packages change.

### Linked by the FastPKI binaries

| Package | Why it is there | Licence |
|---|---|---|
| `openssl` (`libcrypto3`, `libssl3`) | all cryptography, ASN.1 and TLS | Apache-2.0 |
| `libpq` | the PostgreSQL client | PostgreSQL |
| `libldap` (OpenLDAP) | LDAP and Active Directory | OLDAP-2.8 |
| `libsasl` (Cyrus SASL) | needed by `libldap` | BSD-3-Clause-Attribution AND BSD-4-Clause |
| `krb5-libs` (MIT Kerberos) | Kerberos/SPNEGO for MS-XCEP and MS-WSTEP | MIT |
| `libcom_err` | needed by `krb5-libs` | GPL-2.0-or-later AND LGPL-2.0-or-later AND BSD-3-Clause AND MIT |
| `keyutils-libs` | needed by `krb5-libs` | GPL-2.0-or-later AND LGPL-2.0-or-later |
| `libxml2` | SAML, and the MS-XCEP and MS-WSTEP SOAP messages | MIT |
| `xmlsec` | SAML signatures | MIT |
| `libxslt` | needed by `xmlsec` | X11 |
| `libltdl` | needed by `xmlsec` | LGPL-2.0-or-later AND GPL-2.0-or-later |
| `xz-libs` | needed by `libxml2` | GPL-2.0-or-later AND 0BSD AND Public-Domain AND LGPL-2.1-or-later |
| `zlib` | compression | Zlib |
| `libstdc++`, `libgcc` | the C++ runtime | GPL-2.0-or-later AND LGPL-2.1-or-later |
| `musl` | the C library | MIT |

### In the image, not linked by FastPKI

| Package | Why it is there | Licence |
|---|---|---|
| `stunnel` | the `P11_TLS` key tunnel between nodes | GPL-2.0-or-later WITH OpenSSL-Exception |
| `opensc` | `pkcs11-tool`, used by the deployment scripts | LGPL-2.1-or-later |
| `postgresql17-client` | `psql`, used by the deployment scripts | PostgreSQL |
| `libffi` | needed by `p11-kit` | MIT |
| `p11-kit`, `p11-kit-server` | installed as packages, then overwritten by the patched build above | BSD-3-Clause |

The Alpine base system — BusyBox, `apk`, the CA certificate bundle and the rest —
is in `alpine-packages.txt` with the others.

Cyrus SASL's fourth condition applies to every redistribution, this one
included, so it is reproduced here as it requires:

> This product includes software developed by Computing Services at Carnegie
> Mellon University (http://www.cmu.edu/computing/).

---

## Patches we carry

The three patched projects above are modified before building. The patches are
tracked in this repository — `deploy/softhsm-allowed-mechs.patch`,
`deploy/p11-kit-mechanisms.patch`, `deploy/pkcs11-provider-allowed-mechs.patch`
— which is what BSD and Apache both require of a modified redistribution: the
changes are identifiable and the original terms still apply to them.
