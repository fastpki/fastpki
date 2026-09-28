#pragma once
// ACME device attestation (draft-ietf-acme-device-attest, challenge type
// "device-attest-01") for Apple devices: parsing the WebAuthn attestation object a device
// sends, and checking an Apple attestation against a challenge token.
//
// What the device sends (from Apple's com.apple.security.acme payload with Attest=true):
//   POST <challenge url>  {"attObj": base64url(CBOR attestation object)}
// The CBOR is a map {fmt: "apple", attStmt: {x5c: [leaf DER, intermediate DER, ...]}, ...}.
// The leaf is issued by Apple and chains to the Apple Enterprise Attestation Root CA; it
// carries the device's serial number, its UDID, and a freshness code equal to SHA-256 of
// the challenge token — which is what binds this attestation to THIS challenge.
#include <cstdint>
#include <string>
#include <vector>

namespace pki::attest {

// The two members of the attestation object this server reads. Everything else in the
// object (authData, and any other attStmt member) is ignored, as the draft requires.
struct AttestationObject {
    std::string fmt;
    std::vector<std::vector<unsigned char>> x5c;   // DER certificates, leaf first
};

// Decode the CBOR attestation object. Throws pki::Error(1, ...) on anything malformed:
// truncated input, an indefinite length, nesting deeper than a small limit, a missing or
// mistyped `fmt` / `attStmt` / `x5c`. Runs on bytes straight off the network before any
// signature is checked — fuzzed by fuzz/fuzz_attest.cpp.
AttestationObject parse_attestation_object(const unsigned char* data, size_t len);

// What a verified Apple attestation says about the device.
struct AppleDevice {
    std::string serial;                        // OID 1.2.840.113635.100.8.9.1
    std::string udid;                          // OID 1.2.840.113635.100.8.9.2 ("" if absent)
    std::vector<unsigned char> leaf_spki_der;  // the attested key: the CSR must carry exactly this
    // Posture, attested from iOS 17.2 and macOS 14.2. Apple documents a missing value as
    // "could not verify this property", so absent is its own answer, never a default.
    std::string os_version;                    // OID 1.2.840.113635.100.8.10.1 ("" if absent)
    int         sip{-1};                       // OID …8.13.1: 0 = SIP on; -1 = absent (not a Mac, or too old)
};

// Compares dotted version numbers numerically ("26.0.1" vs "26"): -1, 0 or 1.
int compare_versions(const std::string& a, const std::string& b);

// Check an attestation of format "apple":
//   1. x5c chains to one of the trust anchors — Apple's root (always), plus the PEM
//      certificates in `extra_roots_pem` (ACME_ATTESTATION_ROOTS);
//   2. the leaf's freshness code equals SHA-256(`token`);
//   3. the leaf names a serial number.
// Throws pki::Error(1, <reason>) on any failure; the reason is safe to show the client.
AppleDevice verify_apple(const AttestationObject& obj, const std::string& token,
                         const std::string& extra_roots_pem);

// Apple Enterprise Attestation Root CA — ECDSA P-384, valid from February 2022 to February 2047,
// SHA-256 CC:F5:9E:F8:FC:B3:01:7D:97:F8:B5:FA:6F:A9:0E:7A:3F:92:83:F7:6B:55:AC:6C:F6:ED:A8:B8:B9:49:F0:5B,
// from https://www.apple.com/certificateauthority/private/.
extern const char kAppleEnterpriseAttestationRoot[];

} // namespace pki::attest
