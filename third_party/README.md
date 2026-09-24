# Vendored third-party headers

This directory holds single-header dependencies. Drop the file(s) listed below
in here before building — the project intentionally does not pull them via
CMake FetchContent so the build stays offline-friendly.

## Required — `httplib.h`

- **`httplib.h`** — cpp-httplib, header-only HTTP/1.1 server. **MIT**, Copyright
  (c) Yuji Hirose. Currently built against 0.46.1.
  Source: https://github.com/yhirose/cpp-httplib/blob/master/httplib.h

## Required — `nlohmann/json.hpp`

- **`nlohmann/json.hpp`** — nlohmann/json, for ACME JWS/JSON parsing. **MIT**,
  Copyright (c) 2013-2025 Niels Lohmann. Currently built against 3.12.0. Place at
  `third_party/nlohmann/json.hpp` (i.e. inside a `nlohmann/` subdir so the
  `#include <nlohmann/json.hpp>` paths resolve).
  Source: https://github.com/nlohmann/json/releases (download `json.hpp`)

## Licensing

Both headers are MIT, and both are **compiled into every `fastpki-*` binary**.
MIT requires their copyright and permission notice to accompany any
redistribution — of the source, and of the binaries and the Docker image alike.
The notice that discharges that lives in **`NOTICE.md`** at the repo root, and
the `Dockerfile` copies it to `/app/NOTICE.md` in the runtime image.

So: **if you bump either header, check its copyright line and version against
`NOTICE.md`.** The files themselves are gitignored and fetched at build time, so
`NOTICE.md` is the only place in the tree that records what we ship.

FastPKI's own licence is `LICENSE.md` at the repo root (PolyForm Noncommercial
1.0.0). It is more restrictive than MIT, which is allowed — permissive terms let
a larger work be distributed under stricter ones, provided the notices still
travel. They do.
