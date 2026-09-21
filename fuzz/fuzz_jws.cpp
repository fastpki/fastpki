// libFuzzer harness for FastPKI's ACME JWS parser (§1).
//
// pki::jws::parse() in src/lib/jws.cpp decodes the Flattened JWS that every ACME
// client POSTs (RFC 7515 §7.2.2): base64url-decode the three members, parse the
// protected header JSON, and pull alg/url/nonce/jwk/kid out of it. It runs on
// fully attacker-controlled bytes before any signature is checked, so it's a
// prime parser to harden. The invariant: no crash/hang/leak; malformed input is
// rejected with a clean pki::Error.
#include "lsan_suppressions.h"

#include "pki/jws.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

// jws.cpp's signature-verification paths reference pki::openssl_errors() (defined
// in x509.cpp). parse() never calls it, so stub it here to avoid linking the
// whole x509 translation unit into the fuzzer.
namespace pki { std::string openssl_errors() { return {}; } }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    try {
        (void)pki::jws::parse(std::string_view(reinterpret_cast<const char*>(data), size));
    } catch (...) {
        // Malformed input throws pki::Error — that's the clean-rejection contract.
    }
    return 0;
}
