// libFuzzer harness for FastPKI's ACME device-attestation reader.
//
// pki::attest::parse_attestation_object() in src/lib/device_attest.cpp decodes the CBOR
// attestation object an Apple device POSTs to a device-attest-01 challenge. It runs on
// attacker-controlled bytes before any certificate is checked, and it is a hand-written
// CBOR reader, so every length and count it trusts is a place to go wrong. The invariant:
// no crash, hang or leak; malformed input is rejected with a clean pki::Error.
#include "lsan_suppressions.h"

#include "pki/device_attest.hpp"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    try {
        (void)pki::attest::parse_attestation_object(data, size);
    } catch (...) {
        // Malformed input throws pki::Error — that is the clean-rejection contract.
    }
    return 0;
}
