// libFuzzer harness for FastPKI's passkey (WebAuthn) readers.
//
// pki::webauthn in src/lib/webauthn.cpp decodes what a browser returns when a person
// registers a passkey or signs in with one: the attestation object, the authenticator data
// with its COSE public key, and the client data JSON. All of it arrives before any signature
// is checked, over the shared CBOR reader in include/pki/cbor.hpp. The invariant: no crash,
// hang or leak; malformed input is rejected with a clean pki::Error.
//
// The first byte picks the reader, so one corpus reaches all of them:
//   0 authenticator data with a credential (registration)   1 without (sign-in)
//   2 attestation object   3 COSE key   4 client data JSON
#include "lsan_suppressions.h"

#include "pki/webauthn.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) return 0;
    const uint8_t which = data[0] % 5;
    const uint8_t* p = data + 1;
    const size_t n = size - 1;
    try {
        int alg = 0;
        switch (which) {
            case 0: (void)pki::webauthn::parse_auth_data(p, n, true); break;
            case 1: (void)pki::webauthn::parse_auth_data(p, n, false); break;
            case 2: (void)pki::webauthn::auth_data_of_attestation(p, n); break;
            case 3: (void)pki::webauthn::cose_key_to_spki(p, n, alg); break;
            default:
                (void)pki::webauthn::parse_client_data(
                    std::string_view(reinterpret_cast<const char*>(p), n));
                break;
        }
    } catch (...) {
        // Malformed input throws pki::Error — that is the clean-rejection contract.
    }
    return 0;
}
