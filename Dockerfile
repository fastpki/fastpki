# Build + run all FastPKI binaries on Alpine (mirrors the PHP repo's base OS).
#
#   docker build -t fastpki .
#   docker run --rm -it -p 8080-8087:8080-8087 \
#       -v $PWD/config:/app/config -v /var/pki:/var/pki fastpki

# ---- Stage 1: ALL build dependencies (downloaded ONCE, cached as one layer) ----
FROM alpine:3.24 AS deps
# ⚠️ `llvm` is here for llvm-symbolizer, and it is NOT optional tooling.
# LeakSanitizer matches suppressions against SYMBOLIZED frames. Without a
# symbolizer the fuzz harnesses' suppression of libFuzzer's own 56-byte driver
# allocation silently fails to match, and every fuzz run aborts after 4
# executions while still printing "crashes: 0" — a tool that never ran,
# reporting nothing wrong. Measured: 4 units without it, 1.4M with it.
# ⚠️ clang-extra-tools IS clang-tidy, AND IT HAD NO HOME. tests/clang_tidy.sh runs the clang
# static analyzer — path-sensitive null-deref, leak, use-after-free and uninitialised-read
# checks, the heavier companion to cppcheck — and self-skips when the binary is absent. It
# was installed in no image and no CI job, so that gate had almost certainly never executed
# once, while the defect class it targets (a leaked stack, an uninitialised buffer) is
# exactly what a hand audit had to find instead. It lands in this build stage only.
#
# ⚠️ AND THE COMMENT LIVES HERE, NOT AMONG THE PACKAGES. The package list is one logical
# line joined by backslashes, so a `#` inside it does not start a Dockerfile comment — it
# starts a SHELL comment that swallows every package after it.
RUN apk add --no-cache \
        build-base cmake ninja pkgconf \
        clang compiler-rt \
        llvm \
        openssl-dev \
        libpq-dev openldap-dev krb5-dev \
        xmlsec-dev libxml2-dev zlib-dev xmlsec \
        openssl curl xxd bash \
        postgresql17-client \
        p11-kit p11-kit-server p11-kit-dev meson git patch softhsm opensc \
        cppcheck clang-extra-tools \
        libtasn1-dev libffi-dev

# ---- Stage 2: pkcs11-provider (FROM deps — no package download) ----
# -w on the THIRD-PARTY stages only. These three projects (pkcs11-provider,
# p11-kit, SoftHSM) produced 163 warnings in a build of this file — 159 of them
# `-Wdeprecated-declarations` from upstream code calling OpenSSL 3 APIs we do not
# control, and none from FastPKI, which compiles clean under -Wall -Wextra -Wpedantic
# on both clang and Alpine gcc. A wall of warnings nobody can act on is worse than no
# warnings: it is where a real one goes to hide. FastPKI's own stage keeps every warning.
FROM deps AS p11p
# Pinned to commit b21bceb (2025-07) so our CKA_ALLOWED_MECHANISMS patch applies
# deterministically.  Bump when updating the patch.
ARG P11P_COMMIT=b21bceb9cd410b538fccf4352c21045da20fb27b
COPY deploy/pkcs11-provider-allowed-mechs.patch /tmp/pkcs11-provider-allowed-mechs.patch
RUN git clone --depth 1 https://github.com/openssl-projects/pkcs11-provider /tmp/p11p && \
    git -C /tmp/p11p fetch --depth 1 origin ${P11P_COMMIT} && \
    git -C /tmp/p11p checkout ${P11P_COMMIT} && \
    patch -p1 --forward -d /tmp/p11p -i /tmp/pkcs11-provider-allowed-mechs.patch </dev/null && \
    CFLAGS="-w -DNDEBUG" CXXFLAGS="-w -DNDEBUG" meson setup /tmp/p11p/build /tmp/p11p --prefix=/usr --libdir=lib -Dbuildtype=release && \
    ninja -C /tmp/p11p/build && \
    test -f /tmp/p11p/build/src/pkcs11.so

# ---- Stage 2a: p11-kit from source (patched for ML-DSA + EdDSA relay) ----
# p11-kit's RPC layer drops any mechanism that is neither parameterless nor in
# its serializer table, so CKM_ML_DSA{,_KEY_PAIR_GEN} and CKM_EDDSA /
# CKM_EC_EDWARDS_KEY_PAIR_GEN never reach a client through the sidecar and an
# ML-DSA or Ed25519 CA cannot be created at all.  The fix is a real patch file
# rather than a sed line in this RUN, so that a NATIVE install can apply the
# same thing (docs/deployment.md §6) — the fix used to reach only people who build
# this image.  See deploy/p11-kit-mechanisms.patch for the full reasoning; it is
# the same patch offered upstream.
FROM deps AS p11kit
COPY deploy/p11-kit-mechanisms.patch /tmp/p11-kit-mechanisms.patch
RUN git clone --depth 1 --branch 0.26.4 https://github.com/p11-glue/p11-kit /tmp/p11kit && \
    patch -p1 --forward -d /tmp/p11kit -i /tmp/p11-kit-mechanisms.patch </dev/null && \
    grep -q 'CKM_EDDSA, p11_rpc_buffer_add_eddsa_mechanism_value' /tmp/p11kit/p11-kit/rpc-message.c && \
    grep -q 'case CKM_ML_DSA_KEY_PAIR_GEN:' /tmp/p11kit/p11-kit/rpc-message.c && \
    grep -q 'case CKM_AES_KEY_WRAP_PAD:' /tmp/p11kit/p11-kit/rpc-message.c && \
    CFLAGS="-w -DNDEBUG" CXXFLAGS="-w -DNDEBUG" meson setup /tmp/p11kit/build /tmp/p11kit --prefix=/usr --libdir=lib \
        -Dbuildtype=release -Dnls=false && \
    ninja -C /tmp/p11kit/build && \
    test -f /tmp/p11kit/build/p11-kit/p11-kit-client.so && \
    ! ldd /tmp/p11kit/build/p11-kit/p11-kit | grep -q libintl && \
    echo "p11-kit: 0.26.4 patched, ML-DSA/EdDSA relayed, AES key wrap relayed, no libintl"

# ---- Stage 2b: SoftHSM from source (main branch, post-2.7.0 with ML-DSA) ----
FROM deps AS softhsm
# Build from main to get ML-DSA support (opendnssec/SoftHSMv2#867, opendnssec/SoftHSMv2#870
# and opendnssec/SoftHSMv2#874, merged post-2.7.0).
# Pinned commit so the build is reproducible.  Bump to follow main.
ARG SOFTHSM_COMMIT=f12916ee8c6eb5c0025786479fcbf6b38480b134
# Pin the crypto backend to OpenSSL — the default (auto-detect) may pick Botan
# which lacks ML-DSA at the version shipped in Alpine.
COPY deploy/softhsm-allowed-mechs.patch /tmp/softhsm-allowed-mechs.patch
RUN git clone --depth 1 --branch main https://github.com/softhsm/SoftHSMv2 /tmp/softhsm && \
    git -C /tmp/softhsm fetch --depth 1 origin ${SOFTHSM_COMMIT} && \
    git -C /tmp/softhsm checkout ${SOFTHSM_COMMIT} && \
    patch -p1 --forward -d /tmp/softhsm -i /tmp/softhsm-allowed-mechs.patch </dev/null && \
    cmake -S /tmp/softhsm -B /tmp/softhsm/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTS=OFF \
        -DDISABLE_NON_PAGED_MEMORY=ON \
        -DWITH_CRYPTO_BACKEND=openssl \
        -DOPENSSL_ROOT_DIR=/usr \
        -DENABLE_MLDSA=ON \
        -DCMAKE_C_FLAGS=-w -DCMAKE_CXX_FLAGS=-w && \
    cmake --build /tmp/softhsm/build && \
    test -f /tmp/softhsm/build/src/lib/libsofthsm2.so && \
    test -f /tmp/softhsm/build/src/bin/util/softhsm2-util && \
    strings /tmp/softhsm/build/src/lib/libsofthsm2.so | grep -q "ML.DSA" && \
    echo "softhsm: ML-DSA support confirmed"

# ---- Stage 3: build FastPKI binaries (FROM deps — no package download) ----
FROM deps AS build
COPY --from=p11p /tmp/p11p/build/src/pkcs11.so /usr/lib/ossl-modules/pkcs11.so
WORKDIR /src
COPY . .

ARG HTTPLIB_VERSION=v0.46.1
ARG JSON_VERSION=v3.12.0
RUN set -eu; \
    fetch() { \
        curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors -o "$1" "$2" \
        || curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors -o "$1" "$3"; \
    }; \
    mkdir -p third_party/nlohmann; \
    fetch third_party/httplib.h \
        "https://cdn.jsdelivr.net/gh/yhirose/cpp-httplib@${HTTPLIB_VERSION}/httplib.h" \
        "https://raw.githubusercontent.com/yhirose/cpp-httplib/${HTTPLIB_VERSION}/httplib.h"; \
    fetch third_party/nlohmann/json.hpp \
        "https://cdn.jsdelivr.net/gh/nlohmann/json@${JSON_VERSION}/single_include/nlohmann/json.hpp" \
        "https://raw.githubusercontent.com/nlohmann/json/${JSON_VERSION}/single_include/nlohmann/json.hpp"; \
    test -s third_party/httplib.h && test -s third_party/nlohmann/json.hpp

ARG CMAKE_EXTRA_FLAGS=""
# ⚠️ NO -DFASTPKI_WITH_* HERE, DELIBERATELY. They are ON by default in CMakeLists.txt now,
# and naming them again would let the image keep working if a default were ever flipped
# back — silently restoring the divergence this fixes, where the image had LDAP, SAML and
# Kerberos and a developer's default build did not. The image builds what the defaults
# build, so the two cannot drift apart unnoticed.
RUN cmake -S . -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        ${CMAKE_EXTRA_FLAGS} && \
    cmake --build build -- -j2

# ⚠️ THE PATCHED p11-kit AND SoftHSM BELONG HERE TOO, NOT ONLY IN THE RUNTIME STAGE.
#
# This stage inherits `deps`, which apk-installs p11-kit 0.26.2 and SoftHSM 2.7.0. Neither
# can do what this project needs, and both fail SILENTLY:
#
#   * unpatched p11-kit drops CKM_ML_DSA, CKM_ML_DSA_KEY_PAIR_GEN, CKM_EDDSA and
#     CKM_EC_EDWARDS_KEY_PAIR_GEN from its RPC relay. Measured in this very stage before
#     this change: the token advertises 82 mechanisms and 62 cross the socket.
#   * SoftHSM gained ML-DSA only AFTER 2.7.0 (opendnssec/SoftHSMv2#867,
#     opendnssec/SoftHSMv2#870, opendnssec/SoftHSMv2#874), so
#     Alpine's package has none at all.
#
# Either alone empties the capability probe in tests/hsm_helpers.sh, and the token-backed
# suites then SKIP — several of them entirely, not merely a cell. A skip still prints ALL
# GREEN, so this stage reported success over code it had never executed. That includes the
# CI sanitizers job, which runs the suite here: ASan and UBSan had never once entered the
# ML-DSA, Ed25519-in-token or RSA-PSS token paths, which is the newest crypto in the tree
# and exactly where a sanitizer earns its cost.
#
# ⚠️ PLACED AFTER THE COMPILE ON PURPOSE. None of it is an input to the build, so putting
# it here means editing the token stack does not invalidate the 69-target compile above.
#
# ⚠️ AND THE SYMLINK IS NOT OPTIONAL — leaving it out is worse than not copying at all.
# The patched softhsm2-util is built with the default /usr/local prefix and looks for the
# module at /usr/local/lib/softhsm/libsofthsm2.so, while apk's put it under /usr/lib. Copy
# the binary without the link and token init dies with
#
#     ERROR: Could not load the PKCS#11 library/module: Error loading shared library
#            /usr/local/lib/softhsm/libsofthsm2.so: No such file or directory
#
# — having REPLACED a working packaged tool with one that cannot find its own library.
# Measured here, which is the only reason it is not in this image now.
#
# BOTH SIDES OF THE SOCKET, as in the runtime stage: the patch edits p11-kit/rpc-message.c,
# which compiles into libp11-kit.so.0 — so the packaged `p11-kit server` binary picks the
# fix up through the library it links, and the client shim carries its own copy.
COPY --from=p11kit /tmp/p11kit/build/p11-kit/p11-kit-client.so /usr/lib/pkcs11/p11-kit-client.so
COPY --from=p11kit /tmp/p11kit/build/p11-kit/libp11-kit.so.0 /usr/lib/libp11-kit.so.0
COPY --from=softhsm /tmp/softhsm/build/src/lib/libsofthsm2.so /usr/lib/softhsm/libsofthsm2.so
COPY --from=softhsm /tmp/softhsm/build/src/bin/util/softhsm2-util /usr/bin/softhsm2-util
RUN mkdir -p /usr/local/lib/softhsm && \
    ln -sf /usr/lib/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so && \
    mkdir -p /var/lib/softhsm/tokens && \
    printf 'directories.tokendir = /var/lib/softhsm/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' > /etc/softhsm2.conf

# This stage declares its own identity, so a run cannot claim a tier it is not in.
# tests/env_report.sh reads it and says what the run can and cannot prove: this stage has
# the patched pkcs11-provider but Alpine's UNPATCHED p11-kit and SoftHSM, so ML-DSA and
# Ed25519 cells still skip here. deploy/Dockerfile.test writes "test-image" instead.
RUN echo build-image > /etc/fastpki-test-env

# ---- Stage 3b: test tools, DELIBERATELY NOT PART OF THE RUNTIME IMAGE ----
#
# ⚠️ THE SUITES NEED CLIENTS THAT MUST NOT SHIP. scep-testclient and cmp-testclient drive
# our own servers in tests/scep*.sh and the demo; a production image has no business
# carrying a client that can enrol. They used to be named fastpki-* and were therefore
# swept into /usr/local/bin by the prefix glob below — shipped by accident, while a comment
# in tests/fuzz_lane.sh asserted the opposite.
#
# Renaming them alone would have broken the suites, because deploy/Dockerfile.test builds
# FROM the runtime image and could no longer find them. This stage is where they live
# instead: deploy/build-image.sh tags it separately and Dockerfile.test copies from it, so
# the tools reach the TEST image and never the shipped one.
#
# ⚠️ Placed BEFORE the runtime stage on purpose. `docker build` with no --target builds the
# LAST stage, so putting this after it would silently change what `build-image.sh` produces.
FROM alpine:3.24 AS testtools
COPY --from=build /src/build/scep-testclient /usr/local/bin/scep-testclient
COPY --from=build /src/build/cmp-testclient  /usr/local/bin/cmp-testclient

# ---- Stage 4: runtime image ----
FROM alpine:3.24

# ⚠️ stunnel is the OPT-IN mTLS transport for the token socket, and it is a SEPARATE
# PROCESS on both ends — p11-kit cannot speak TLS or TCP itself. Its client shim parses only
# `unix:path=` and `vsock:cid=;port=` and links no bind/listen, so a tunnel has to terminate
# at a local unix socket on each host; P11_KIT_SERVER_ADDRESS stays `unix:path=` everywhere
# and no FastPKI binary learns it is talking to a network.
#
# An Alpine package like the rest of this line, listed with its licence in NOTICE.md's
# "From Alpine packages" section. Unused unless the transport is switched on.
RUN apk add --no-cache \
        libstdc++ openssl libpq libldap krb5-libs \
        xmlsec libxml2 zlib postgresql17-client \
        p11-kit p11-kit-server opensc stunnel && \
    addgroup -S fastpki && adduser -S -G fastpki -H -s /sbin/nologin fastpki

COPY --from=build /usr/lib/ossl-modules/pkcs11.so /usr/lib/ossl-modules/pkcs11.so
# The patched p11-kit replaces the packaged 0.26.2, on BOTH sides of the socket —
# the client shim every app loads, the library behind it, and the `p11-kit server` the
# softhsm sidecar runs. Copying only one side would leave the filter in place at the
# other end, which is exactly the sort of half-fix that looks like it worked.
COPY --from=p11kit /tmp/p11kit/build/p11-kit/p11-kit-client.so /usr/lib/pkcs11/p11-kit-client.so
COPY --from=p11kit /tmp/p11kit/build/p11-kit/libp11-kit.so.0 /usr/lib/libp11-kit.so.0
COPY --from=softhsm /tmp/softhsm/build/src/lib/libsofthsm2.so /usr/lib/softhsm/libsofthsm2.so
COPY --from=softhsm /tmp/softhsm/build/src/bin/util/softhsm2-util /usr/bin/softhsm2-util
RUN mkdir -p /usr/local/lib/softhsm && \
    ln -s /usr/lib/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so && \
    mkdir -p /var/lib/softhsm/tokens && \
    printf 'directories.tokendir = /var/lib/softhsm/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' > /etc/softhsm2.conf

WORKDIR /app
COPY --from=build /src/build/fastpki-* /usr/local/bin/
COPY --from=build /src/config/bootstrap.conf.example /app/config/bootstrap.conf
COPY --from=build /src/sql /app/sql

# The licence and the third-party notices ship WITH the image, not only with the
# source tree.  MIT (cpp-httplib, nlohmann/json — compiled into every binary),
# BSD (SoftHSM, p11-kit) and Apache (pkcs11-provider, OpenSSL) each require their
# notice to accompany a binary redistribution, and an image someone pulls is a
# binary redistribution.  Copying each project's own licence file rather than
# transcribing it means the text cannot drift from what we actually built.
COPY --from=build /src/LICENSE.md /app/LICENSE.md
COPY --from=build /src/NOTICE.md /app/NOTICE.md
COPY --from=softhsm /tmp/softhsm/LICENSE /app/licences/SoftHSMv2.LICENSE
COPY --from=p11kit /tmp/p11kit/COPYING /app/licences/p11-kit.COPYING
COPY --from=p11p /tmp/p11p/COPYING /app/licences/pkcs11-provider.COPYING
# ⚠️ THE ALPINE PACKAGES NEED THEIR TEXTS TOO, AND ALPINE SHIPS NONE. Publishing this image
# redistributes every package in it, and MIT, BSD, Zlib, OLDAP and PostgreSQL each require
# the licence text and copyright notice to travel with a binary redistribution. Alpine's
# runtime packages carry no licence files and its -doc packages are almost all man pages, so
# the texts are collected from each package's upstream source by
# deploy/licences/collect-alpine.sh and committed — SOURCES.txt there says where each came from.
COPY --from=build /src/deploy/licences/alpine/ /app/licences/alpine/
# Every Alpine package in this image, with its exact version and the licence Alpine declares
# for it, written from the package database rather than transcribed. After the last apk add,
# so nothing installed later is missing from it.
#
# ⚠️ AND THE BUILD FAILS ON A PACKAGE WITH NO TEXT. A package added to the line above, or one
# pulled in as a new dependency of it, would otherwise ship with no notice, and nothing
# would say so; failing here names the package and the command that fixes it.
RUN apk list -I 2>/dev/null | sort > /app/licences/alpine-packages.txt && \
    missing=$(for o in $(sed -E 's/.*\{([^}]*)\}.*/\1/' /app/licences/alpine-packages.txt | sort -u); do \
                  [ -d "/app/licences/alpine/$o" ] || printf ' %s' "$o"; \
              done) && \
    if [ -n "$missing" ]; then \
        echo "no licence text in deploy/licences/alpine/ for:$missing" >&2; \
        echo "collect them with deploy/licences/collect-alpine.sh and commit the result" >&2; \
        exit 1; \
    fi

USER fastpki

# OCSP 8080, EST 8443, ACME 8444, CMP 8445, MS 8446, store 8447
EXPOSE 8080 8443 8444 8445 8446 8447

CMD ["fastpki-ocsp", "--config", "/app/config/bootstrap.conf"]
