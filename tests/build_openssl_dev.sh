#!/usr/bin/env bash
# Build a modern OpenSSL from source for dev environments whose system OpenSSL is
# older (e.g. Ubuntu 24.04 ships 3.0.13). We target 3.5.x for two reasons:
#   - fastpki-cmp needs OSSL_CRMF_CERTTEMPLATE_get0_publicKey (added in 3.2);
#   - 3.5 is the first release with native ML-DSA (FIPS 204) EVP support, the
#     baseline for the PQC work (the 3.5+ path is endorsed).
# This matches the production/CI toolchain: Alpine 3.24 ships OpenSSL 3.5.x.
#
# Installs to /opt/openssl-3.5 (run as root). Build the project with:
#   cmake -S . -B build -DOPENSSL_ROOT_DIR=/opt/openssl-3.5
# and run a binary with:
#   LD_LIBRARY_PATH=/opt/openssl-3.5/lib64 ./build/fastpki-cmp ...
set -euo pipefail

VER=${VER:-3.5.7}
PREFIX=/opt/openssl-$(echo "$VER" | cut -d. -f1,2)
SRC=/tmp/openssl-$VER

apt-get install -y -qq perl make gcc >/dev/null 2>&1 || true

cd /tmp
if [ ! -f openssl-$VER.tar.gz ]; then
    curl -sSL -o openssl-$VER.tar.gz \
        "https://github.com/openssl/openssl/releases/download/openssl-$VER/openssl-$VER.tar.gz"
fi
rm -rf "$SRC"
tar xf openssl-$VER.tar.gz
cd "$SRC"

# Minimal, fast build: shared libs, no docs, no tests.
./Configure --prefix="$PREFIX" --openssldir="$PREFIX" shared >/dev/null
make -j"$(nproc)" >/dev/null
make install_sw >/dev/null

echo "INSTALLED $PREFIX"
LD_LIBRARY_PATH="$PREFIX/lib64" "$PREFIX/bin/openssl" version
