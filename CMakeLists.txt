cmake_minimum_required(VERSION 3.20)
project(fastpki CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# MSVC is NOT a supported compiler.
# GCC/Clang only — on Windows the supported route is WSL2, which is Linux.
add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)

# Optional: AddressSanitizer + UndefinedBehaviorSanitizer build for the security
# test lane (§1). -DFASTPKI_SANITIZE=ON instruments pki_lib + every
# binary; run the suite under it to catch memory-corruption and the
# integer-overflow-into-length class that plagues parsers. Run with
# ASAN_OPTIONS=detect_leaks=0 — SoftHSM's PKCS#11 module is dlopen'd with
# RTLD_DEEPBIND, which the sanitizer runtime warns about but tolerates.
option(FASTPKI_SANITIZE "Build with ASan + UBSan (security testing)" OFF)
if(FASTPKI_SANITIZE)
    message(STATUS "FASTPKI_SANITIZE=ON: building with -fsanitize=address,undefined")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

# ---- Dependencies ----------------------------------------------------------
# OpenSSL 3.x is required (ASN.1, X.509, OCSP, PKCS#7, EVP). OpenSSL 3.5 is the
# supported/tested baseline (the Alpine 3.24 production/CI image ships 3.5.x) and
# the floor for ML-DSA (FIPS 204) PQC work. 3.5 is also the LTS series (supported to
# April 2030), which is why it is the target rather than a newer regular release.
# The core still builds on 3.2+ (fastpki-cmp needs >= 3.2); PQC features are
# gated on >= 3.5 via the FASTPKI_OPENSSL_GE_35 define below.
find_package(OpenSSL 3.0 REQUIRED)
if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.5")
    message(STATUS "OpenSSL ${OPENSSL_VERSION}: ML-DSA / PQC EVP APIs available")
else()
    message(STATUS "OpenSSL ${OPENSSL_VERSION}: < 3.5 — PQC (ML-DSA) features disabled; 3.5+ recommended")
endif()

# SQLite3 — REMOVED (Postgres-only).
# find_package(SQLite3 REQUIRED)  # REMOVED

# Threads for the HTTP server.
find_package(Threads REQUIRED)

if(APPLE)
    find_library(CORE_FOUNDATION CoreFoundation REQUIRED)
    find_library(SECURITY Security REQUIRED)
endif()

# PostgreSQL is the sole DB backend.
find_package(PostgreSQL REQUIRED)

# ── FEATURE FLAGS ARE ON BY DEFAULT, AND THAT IS THE POINT ──────────────────────────
# LDAP, SAML and Kerberos used to default OFF, so a plain `cmake -B build` produced a
# binary missing three features the product ships — and the suites that cover them
# SKIPPED, reporting a green run that had not exercised them. The image passed all three
# explicitly, which meant the thing developers built was not the thing we shipped.
#
# Tests run against the production image and nothing there may skip, so a feature that
# ships must be compiled by default. The cost is stated rather than hidden: a build now
# needs libxmlsec1, openldap and krb5 headers present. Turn one off deliberately
# (-DFASTPKI_WITH_SAML=OFF) if you are working without them; do not make that the default
# again.

# LDAP/AD authentication.
option(FASTPKI_WITH_LDAP "Build with OpenLDAP auth" ON)
if(FASTPKI_WITH_LDAP)
    find_library(LDAP_LIB ldap REQUIRED)
    find_library(LBER_LIB lber REQUIRED)
endif()

# libxml2 is a CORE pki_lib dependency, not a SAML extra: src/lib/xml.cpp reads
# MS-XCEP/WSTEP request bodies with it. It used to be pulled in only by FASTPKI_WITH_SAML,
# which is why the MS path had a hand-rolled byte scanner justified as "dependency-free" —
# false for the image we ship, where pki_lib has linked libxml2 since the SAML work.
# libxml2 is a CORE pki_lib dependency, not a SAML extra: src/lib/xml.cpp reads
# MS-XCEP/WSTEP request bodies with it.
find_package(LibXml2 REQUIRED)

# Optional: SAML 2.0 console SSO (issue #7, Component 2). Enable with
# -DFASTPKI_WITH_SAML=ON. Pulls in libxmlsec1 (the XML-DSig engine that verifies the
# assertion signature) + zlib (HTTP-Redirect DEFLATE). src/lib/saml.cpp compiles to a
# disabled stub when it is turned off. Located via pkg-config (xmlsec1-openssl).
# xmlsec1 is the genuinely SAML-specific half and stays optional; libxml2 above does not.
option(FASTPKI_WITH_SAML "Build SAML 2.0 console SSO (libxmlsec1)" ON)
if(FASTPKI_WITH_SAML)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(XMLSEC REQUIRED xmlsec1-openssl)
    find_package(ZLIB REQUIRED)

    # ⚠️ libxml2 MUST be the SAME one libxmlsec1 links, and nothing enforced it.
    #
    # xmlsec1 hands libxml2 a document and calls back into it to resolve the signature's
    # Reference. With TWO libxml2s in one process that resolution happens in the wrong
    # one and verification fails before any crypto runs. Measured on macOS, where
    # Homebrew's libxml2 is keg-only so FindLibXml2 picks the SDK stub by default:
    #
    #     fastpki-web -> /usr/lib/libxml2.2.dylib                       (2.9.13, system)
    #     libxmlsec1  -> /opt/homebrew/opt/libxml2/lib/libxml2.16.dylib (2.15.3)
    #
    #     ERR SAML login failed: SAML: signature verification error
    #     func=xmlSecXPathDataExecute … subj=xmlXPtrEval … xml error: 0: NULL
    #
    # tests/saml.sh sat at 9/15 for it. The message names an XPointer, which is xmlsec's
    # INTERNAL fallback for resolving URI="#_id" — NOT something the test's mock IdP
    # emits — and misreading that is why it was first filed against the mock.
    #
    # This REFUSES rather than guesses. There is no clean pkg-config derivation: xmlsec's
    # own `Requires: libxml-2.0` resolves through the default path to the wrong one,
    # precisely because Homebrew's is keg-only. Auto-picking would be a guess that can be
    # silently wrong; a hard stop naming the exact command cannot be. On Alpine and any
    # ordinary Linux there is one libxml2 and the two agree, so this never fires — the
    # shipped image is unaffected.
    if(APPLE AND EXISTS "${LIBXML2_LIBRARY}")
        execute_process(COMMAND sh -c
            "otool -L $(pkg-config --variable=libdir xmlsec1-openssl)/libxmlsec1.dylib 2>/dev/null | grep -o '/[^[:space:]]*libxml2[^[:space:]]*' | head -1"
            OUTPUT_VARIABLE XMLSEC_LIBXML2 OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
        if(XMLSEC_LIBXML2)
            get_filename_component(_xs_dir "${XMLSEC_LIBXML2}" DIRECTORY)
            get_filename_component(_our_dir "${LIBXML2_LIBRARY}" DIRECTORY)
            # Compare real paths: the SDK .tbd and /usr/lib are different spellings of
            # the same system library, and Homebrew's opt/ is a symlink into Cellar/.
            get_filename_component(_xs_real "${_xs_dir}" REALPATH)
            get_filename_component(_our_real "${_our_dir}" REALPATH)
            if(NOT _xs_real STREQUAL _our_real)
                message(FATAL_ERROR
                    "SAML is ON but libxml2 does not match the one libxmlsec1 links, so "
                    "signature verification would fail at runtime.\n"
                    "  this build : ${LIBXML2_LIBRARY}\n"
                    "  libxmlsec1 : ${XMLSEC_LIBXML2}\n"
                    "Configure a FRESH build directory with libxml2's pkgconfig first "
                    "(LIBXML2_LIBRARY is cached, so reconfiguring this one will not "
                    "re-resolve it):\n"
                    "  PKG_CONFIG_PATH=\"$(brew --prefix libxml2)/lib/pkgconfig:$PKG_CONFIG_PATH\" \\\n"
                    "  cmake -S . -B build -DFASTPKI_WITH_SAML=ON -DOPENSSL_ROOT_DIR=...")
            endif()
        endif()
    endif()
endif()

# Header-only deps fetched as submodules / sources in third_party/.
# - nlohmann/json     (ACME JSON)
# - yhirose/cpp-httplib (HTTP server)
# ⚠️ SYSTEM, so upstream headers do not warn in OUR builds.
#
# httplib.h is header-only and included by most of the tree, so one -Wtype-limits inside it
# ("comparison of unsigned expression in '>= 0' is always true") is emitted once per
# translation unit that includes it -- pages of identical noise from code we do not
# control, which is exactly what buries a real warning.
#
# SYSTEM is the scoped instrument here: it silences diagnostics from THESE headers only and
# disables no diagnostic anywhere else, so FastPKI's own code still compiles under
# -Wall -Wextra -Wpedantic with nothing suppressed. A -Wno-type-limits would have turned
# the check off for our code too, to fix a line that is not ours.
include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/third_party)

# ⚠️ cpp-httplib REFUSES A FORM BODY OVER 8 KiB, AND IT DOES IT BEFORE ROUTING.
# CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH defaults to 8192, and read_content()
# answers 413 for any application/x-www-form-urlencoded body above it — inside the library,
# before any handler runs, so nothing of ours logs a thing. `set_payload_max_length()` does
# NOT raise it: they are two separate limits and this one is a compile-time constant.
#
# 8 KiB was fine while every posted PEM was RSA or EC. It is not fine for PQC: an ML-DSA-87
# certificate carries a 2592-byte public key and a 4627-byte signature, so its PEM is ~10 KiB
# before form-encoding expands it further. Importing one into the console therefore failed
# with a bare 413 and an empty log — reported from a lab bringing up a mesh, where the sub CA
# that could not be imported was the whole point of the exercise.
#
# 1 MiB matches the console's OWN kMaxApiBodyBytes ceiling, which is enforced in its
# pre-routing handler and answers with a JSON error naming the problem. Raising the library
# limit to meet it does not widen anything: it moves the refusal from a silent library
# default to our check, which can explain itself. Every other binary caps the whole body
# with set_payload_max_length() well below this (64 KiB to 1 MiB), and that still binds.
add_compile_definitions(CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH=1048576)

# ---- Shared library --------------------------------------------------------
add_library(pki_lib STATIC
    src/lib/cmc.cpp

    src/lib/config.cpp
    src/lib/login_throttle.cpp
    src/lib/audit.cpp
    src/lib/ca_instance.cpp
    src/lib/ca_renew.cpp
    src/lib/pg_tls.cpp
    src/lib/cert_profile.cpp
    src/lib/ms_template.cpp
    src/lib/ms_template_policy.cpp
    src/lib/backup.cpp
    src/lib/version.cpp
    src/lib/update.cpp
    src/lib/cmp_asn1.cpp
    src/lib/auth.cpp
    src/lib/enrol_creds.cpp
    src/lib/enrol_gate.cpp
    src/lib/ra_reload.cpp
    src/lib/transport_reload.cpp
    src/lib/endpoint_gate.cpp
    src/lib/crl.cpp
    src/lib/jws.cpp
    src/lib/log.cpp
    src/lib/oidc.cpp
    src/lib/saml.cpp
    src/lib/policy.cpp
    src/lib/service_cert.cpp
    src/lib/smtp.cpp
    src/lib/notify_mail.cpp
    src/lib/x509.cpp
    src/lib/xml.cpp
    src/lib/pkcs11_helpers.cpp
    src/lib/node_status.cpp
)
target_include_directories(pki_lib PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(pki_lib PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    LibXml2::LibXml2
)
if(NOT APPLE)
    target_link_libraries(pki_lib PUBLIC ${CMAKE_DL_LIBS})   # dlopen on Linux
endif()

# Build-time version string: an explicit -DFASTPKI_VERSION wins, else
# `git describe`, else a dev marker. Only src/lib/version.cpp consumes it.
if(NOT DEFINED FASTPKI_VERSION)
    execute_process(COMMAND git describe --tags --always --dirty
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE FASTPKI_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    if(NOT FASTPKI_VERSION)
        set(FASTPKI_VERSION "0.0.0-dev")
    endif()
endif()
message(STATUS "FastPKI version: ${FASTPKI_VERSION}")
set_source_files_properties(src/lib/version.cpp PROPERTIES
    COMPILE_DEFINITIONS "FASTPKI_VERSION=\"${FASTPKI_VERSION}\"")
# PQC capability gate: ML-DSA (FIPS 204) EVP APIs require OpenSSL >= 3.5. Future
# PQC code keys off this; older toolchains still build the classical core.
if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.5")
    target_compile_definitions(pki_lib PUBLIC FASTPKI_OPENSSL_GE_35=1)
endif()
target_sources(pki_lib PRIVATE src/lib/db_postgres.cpp src/lib/acme_db_postgres.cpp)
target_link_libraries(pki_lib PUBLIC PostgreSQL::PostgreSQL)
if(FASTPKI_WITH_LDAP)
    target_sources(pki_lib PRIVATE src/lib/ldap_auth.cpp)
    target_link_libraries(pki_lib PUBLIC ${LDAP_LIB} ${LBER_LIB})
    target_compile_definitions(pki_lib PUBLIC FASTPKI_WITH_LDAP=1)
    # macOS deprecated the ENTIRE OpenLDAP C API in 10.11 in favour of the OpenDirectory
    # framework, so every call in this one file warns. Measured on a clean build with LDAP
    # enabled: 117 warnings, all -Wdeprecated-declarations, all from this file, all carrying
    # "use OpenDirectory Framework" — and nothing else warned anywhere in the tree.
    #
    # That is a statement about the host SDK, not about the code: the platform we ship is
    # Linux, where these functions are not deprecated and the same file compiles clean.
    # Left alone it buries a genuinely new warning under 117 lines of noise on every macOS
    # build, which is the opposite of what -Wall is for.
    #
    # ⚠️ SCOPED AS NARROWLY AS THE FACT IS: this ONE file, on Apple ONLY, and only that one
    # diagnostic. Every other warning in this file still fails the build gate, and on Linux
    # — where CI and the shipped image compile it — nothing is suppressed at all.
    if(APPLE)
        set_source_files_properties(src/lib/ldap_auth.cpp PROPERTIES
            COMPILE_OPTIONS "-Wno-deprecated-declarations")
    endif()
endif()
if(FASTPKI_WITH_SAML)
    target_include_directories(pki_lib PRIVATE ${XMLSEC_INCLUDE_DIRS})
    target_compile_options(pki_lib PRIVATE ${XMLSEC_CFLAGS_OTHER})
    target_link_libraries(pki_lib PUBLIC ${XMLSEC_LIBRARIES} ZLIB::ZLIB)
    target_link_directories(pki_lib PUBLIC ${XMLSEC_LIBRARY_DIRS})
    # FASTPKI_WITH_SAML must be visible to src/lib/saml.cpp (PRIVATE is enough;
    # PUBLIC lets the web binary also see it if it ever needs to).
    target_compile_definitions(pki_lib PUBLIC FASTPKI_WITH_SAML=1)
endif()

# ---- Executables -----------------------------------------------------------
# ⚠️ TEST-ONLY, and deliberately NOT named fastpki-* : the image copies binaries by prefix
# (`COPY --from=build /src/build/fastpki-* /usr/local/bin/`), so this is excluded from the
# product by the glob rather than by anyone remembering. There are no install() rules, so
# there is no other path that could ship it. See tests/tools/dnsstub.cpp for why a
# test needs a compiled helper at all: fastpki-acme validates dns-01 over raw UDP DNS, and
# shell cannot hold the NUL bytes a DNS packet is full of.
add_executable(dnsstub tests/tools/dnsstub.cpp)

add_executable(fastpki-ocsp src/ocsp/main.cpp src/ocsp/responder.cpp)
if(APPLE)
    target_link_libraries(fastpki-ocsp PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(fastpki-ocsp PRIVATE pki_lib)
endif()

add_executable(fastpki-est src/est/main.cpp)
if(APPLE)
    target_link_libraries(fastpki-est PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(fastpki-est PRIVATE pki_lib)
endif()

add_executable(fastpki-acme src/acme/main.cpp)
if(APPLE)
    target_link_libraries(fastpki-acme PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(fastpki-acme PRIVATE pki_lib)
endif()

# CMP needs OSSL_CRMF_CERTTEMPLATE_get0_publicKey, added in OpenSSL 3.2.
# Production (Alpine 3.24, OpenSSL 3.5.x) builds it; older dev OpenSSL skips it.
if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.2")
    add_executable(fastpki-cmp src/cmp/main.cpp)
    if(APPLE)
        target_link_libraries(fastpki-cmp PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
    else()
        target_link_libraries(fastpki-cmp PRIVATE pki_lib)
    endif()
else()
    message(STATUS "Skipping fastpki-cmp: requires OpenSSL >= 3.2 (found ${OPENSSL_VERSION})")
endif()

# MS-XCEP + MS-WSTEP share one binary (one listener, two paths).
add_executable(fastpki-ms src/msxcep/main.cpp src/msxcep/kerberos.cpp)
if(APPLE)
    target_link_libraries(fastpki-ms PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(fastpki-ms PRIVATE pki_lib)
endif()

# Kerberos/SPNEGO auth for MS-WSTEP (issue #3). Requires MIT krb5/GSSAPI dev libs. Override GSSAPI_INCLUDE_DIR / GSSAPI_GSS_LIBRARY /
# GSSAPI_KRB5_LIBRARY to point at a non-system krb5 (e.g. a userspace prefix).
option(FASTPKI_WITH_KERBEROS "Build MS-WSTEP Kerberos/SPNEGO support" ON)
if(FASTPKI_WITH_KERBEROS)
    find_path(GSSAPI_INCLUDE_DIR gssapi/gssapi.h)
    find_library(GSSAPI_GSS_LIBRARY NAMES gssapi_krb5 gssapi)
    find_library(GSSAPI_KRB5_LIBRARY NAMES krb5)
    if(NOT GSSAPI_INCLUDE_DIR OR NOT GSSAPI_GSS_LIBRARY)
        message(FATAL_ERROR "FASTPKI_WITH_KERBEROS=ON but GSSAPI headers/libs not found "
                            "(set GSSAPI_INCLUDE_DIR / GSSAPI_GSS_LIBRARY)")
    endif()
    target_compile_definitions(fastpki-ms PRIVATE FASTPKI_WITH_KERBEROS)
    target_include_directories(fastpki-ms PRIVATE ${GSSAPI_INCLUDE_DIR})    
    target_link_libraries(fastpki-ms PRIVATE ${GSSAPI_GSS_LIBRARY} ${GSSAPI_KRB5_LIBRARY})
    message(STATUS "MS-WSTEP Kerberos/SPNEGO: ENABLED (${GSSAPI_GSS_LIBRARY})")
endif()

# RFC 4387 certificate/CRL store.
add_executable(fastpki-store src/certstore/main.cpp)
if(APPLE)
    target_link_libraries(fastpki-store PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(fastpki-store PRIVATE pki_lib)
endif()

# Read-only web management UI: inventory + audit + discovered (issue #7).
add_executable(fastpki-web src/web/main.cpp)
if(APPLE)
    target_link_libraries(fastpki-web PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(fastpki-web PRIVATE pki_lib)
endif()

# SCEP (RFC 8894) for legacy network devices / MDM.
add_executable(fastpki-scep src/scep/main.cpp)
if(APPLE)
    target_link_libraries(fastpki-scep PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(fastpki-scep PRIVATE pki_lib)
endif()

# SCEP reference/test client (drives fastpki-scep in tests/scep.sh and the demo).
#
# ⚠️ TEST-ONLY, and deliberately NOT named fastpki-*, for the same reason as dnsstub above:
# the image copies binaries by prefix (`COPY --from=build /src/build/fastpki-* ...`), so a
# `fastpki-` name puts a client that can ENROL into every production image. Named without
# the prefix, the glob excludes it and nothing has to remember to.
add_executable(scep-testclient src/scep/client.cpp)
if(APPLE)
    target_link_libraries(scep-testclient PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(scep-testclient PRIVATE pki_lib)
endif()

# CMP reference/test client. It builds ONE message: a pollReq whose transactionID and PBM
# identity are both chosen by the caller, which `openssl cmp` cannot express because it
# generates its own transactionID per invocation. Drives the cross-requester poll case.
# ⚠️ TEST-ONLY, and named without the fastpki- prefix for the same reason as dnsstub and
# scep-testclient: the image copies `fastpki-*` by glob, and a test client that can enrol
# has no business in a production image.
add_executable(cmp-testclient src/cmp/client.cpp)
if(APPLE)
    target_link_libraries(cmp-testclient PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(cmp-testclient PRIVATE pki_lib)
endif()

# Audit log tool: verify chain integrity / append events / export (issue #5).
add_executable(fastpki-audit src/tools/audit.cpp)
if(APPLE)
    target_link_libraries(fastpki-audit PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(fastpki-audit PRIVATE pki_lib)
endif()

# Expiry-notification / alerting tool (issue #6).
add_executable(fastpki-notify src/tools/notify.cpp)
if(APPLE)
    target_link_libraries(fastpki-notify PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(fastpki-notify PRIVATE pki_lib)
endif()

# Pull-based TLS certificate discovery scanner (issue #8).
add_executable(fastpki-discover src/tools/discover.cpp)
if(APPLE)
    target_link_libraries(fastpki-discover PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(fastpki-discover PRIVATE pki_lib)
endif()

# Multi-datacenter replication topology generator (issue #2). Standalone (pure
# DDL text generation), but links pki_lib for consistency with the other tools.
add_executable(fastpki-mesh src/tools/mesh.cpp)
target_link_libraries(fastpki-mesh PRIVATE pki_lib)

# MCP server: read-only PKI inventory over the MCP stdio transport.
add_executable(fastpki-mcp src/mcp/main.cpp)
if(APPLE)
    target_link_libraries(fastpki-mcp PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(fastpki-mcp PRIVATE pki_lib)
endif()

# Multi-root CA control-plane tool.
add_executable(fastpki-ca src/tools/ca.cpp)
if(APPLE)
    target_link_libraries(fastpki-ca PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(fastpki-ca PRIVATE pki_lib)
endif()

# Dynamic-configuration overlay management tool (issue #7, Task 1.1).
add_executable(fastpki-config src/tools/config.cpp)
if(APPLE)
    target_link_libraries(fastpki-config PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(fastpki-config PRIVATE pki_lib)
endif()

# fastpki-update: version / update-check / release-signature verify.
add_executable(fastpki-update src/tools/updater.cpp)
if(APPLE)
    target_link_libraries(fastpki-update PRIVATE pki_lib ${CORE_FOUNDATION} ${SECURITY})
else()
    target_link_libraries(fastpki-update PRIVATE pki_lib)
endif()

# ---- Fuzzers ---------------------------------------------------------------
# fuzz/ held two finished libFuzzer harnesses that NOTHING built and NOTHING ran:
# no CMake target, no CI lane. A harness that is never compiled is not coverage,
# it is a file — and it rots silently, because nothing tells you when the API it
# calls changes underneath it.
#
# OFF by default and clang-only: libFuzzer ships with clang, and -fsanitize=fuzzer
# is not a GCC flag, so the ordinary GCC build (and the Alpine CI image) must be
# untouched. Turn it on with:
#
#     cmake -S . -B build-fuzz -DFASTPKI_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++
#     ./build-fuzz/fuzz_jws -max_total_time=60
#
# Both harnesses target hand-rolled parsers that run on fully attacker-controlled
# bytes BEFORE any signature is checked — the ACME JWS parser and our own CMP
# ASN.1 decoder — which is exactly where a fuzzer earns its keep.
option(FASTPKI_FUZZ "Build the libFuzzer harnesses in fuzz/" OFF)
if(FASTPKI_FUZZ)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR
            "FASTPKI_FUZZ needs clang (libFuzzer); this is ${CMAKE_CXX_COMPILER_ID}. "
            "Re-configure with -DCMAKE_CXX_COMPILER=clang++")
    endif()
    message(STATUS "FASTPKI_FUZZ=ON: building fuzz/ harnesses with -fsanitize=fuzzer")
    # address+undefined alongside fuzzer: a fuzzer that only finds crashes misses
    # the overreads and UB that are the actual bugs in a parser.
    #
    # ⚠️ THE INSTRUMENTATION MUST REACH pki_lib, NOT JUST THE HARNESS.
    #
    # This block used to put the flags on the fuzz_* executables alone. Those targets
    # compile ONE file each — fuzz/fuzz_*.cpp — while the parsers under test (jws.cpp,
    # cmp_asn1.cpp) live in pki_lib, a separate target that was built with no
    # -fsanitize at all. Proven from the generated flags:
    #
    #   pki_lib.dir/flags.make   CXX_FLAGS = -std=c++20 -Wall -Wextra -Wpedantic
    #   fuzz_jws.dir/flags.make  CXX_FLAGS = ... -fsanitize=fuzzer,address,undefined
    #
    # So libFuzzer saw coverage edges from the HARNESS only and had no signal from the
    # code it was meant to explore; UBSan (purely compile-time) was absent from that
    # code entirely, and ASan was left with little to instrument. A 900-second campaign
    # on this build reported "no crashes" while watching almost nothing — the same
    # always-passing shape as the probe that skipped everywhere. The question that
    # exposed it: is the fuzzer run under ASan or UBSan, or on its own? On its own it
    # makes little sense.
    #
    # FASTPKI_FUZZ=ON is a dedicated build tree (never the deploy build), so applying
    # the flags to pki_lib wholesale is safe and is the only way the parser TUs get
    # instrumented.
    target_compile_options(pki_lib PRIVATE
        -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer -g)
    target_link_options(pki_lib PUBLIC -fsanitize=address,undefined)
    foreach(f jws cmp_asn1 ms_xml cmc ms_template)
        add_executable(fuzz_${f} fuzz/fuzz_${f}.cpp)
        target_link_libraries(fuzz_${f} PRIVATE pki_lib)
        target_compile_options(fuzz_${f} PRIVATE
            -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g)
        target_link_options(fuzz_${f} PRIVATE -fsanitize=fuzzer,address,undefined)
    endforeach()
endif()

# ---- Tests -----------------------------------------------------------------
enable_testing()
add_subdirectory(tests)
