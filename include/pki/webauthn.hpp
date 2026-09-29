#pragma once
// Passkeys (WebAuthn Level 3): checking what a browser returns when a person registers a
// passkey for the console and when they sign in with it.
//
// What this checks and what it deliberately does not:
//   * the client data: its type, that its challenge is the one the console issued, and that
//     its origin is https://<rp id> (any port);
//   * the authenticator data: the rp id hash, user presence AND user verification (Face ID,
//     Touch ID, a PIN — the flag the passkey's second factor rests on), the signature counter;
//   * at registration, the credential id and its COSE public key, converted to a DER
//     SubjectPublicKeyInfo. Attestation is "none": the attestation statement is not read, so
//     a passkey proves the person, not a particular make of device;
//   * at sign-in, the signature over authenticatorData || SHA-256(clientDataJSON), with the
//     key stored at registration and ONLY the algorithm that key was registered with.
//
// Everything here reads bytes from the network before any signature is checked, so every
// failure throws pki::Error(1, <reason>) and the parsers are fuzzed (fuzz/fuzz_webauthn.cpp).
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace pki::webauthn {

// COSE algorithm numbers the console accepts.
constexpr int kES256 = -7;     // ECDSA P-256 with SHA-256
constexpr int kEdDSA = -8;     // Ed25519
constexpr int kRS256 = -257;   // RSASSA-PKCS1-v1_5 with SHA-256

// Authenticator data flags.
constexpr unsigned kUserPresent  = 0x01;
constexpr unsigned kUserVerified = 0x04;
constexpr unsigned kAttested     = 0x40;
constexpr unsigned kExtensions   = 0x80;

struct AuthData {
    std::string rp_id_hash;       // 32 bytes
    unsigned    flags{0};
    uint32_t    sign_count{0};
    // Present when the attested-credential flag is set (registration).
    std::string credential_id;    // raw bytes
    std::string spki;             // DER SubjectPublicKeyInfo, from the COSE key
    int         alg{0};
};
// Parses authenticator data (WebAuthn §6.1). `want_credential`: the attested credential data
// must be present (registration) or absent (sign-in).
AuthData parse_auth_data(const unsigned char* data, size_t len, bool want_credential);

// The authenticator data inside an attestation object; `fmt` and `attStmt` are not read.
std::string auth_data_of_attestation(const unsigned char* data, size_t len);

// A COSE_Key (RFC 9053) as DER SubjectPublicKeyInfo. Accepts EC2 P-256 with ES256, OKP
// Ed25519 with EdDSA, and RSA of at least 2048 bits with RS256; sets `alg`.
std::string cose_key_to_spki(const unsigned char* data, size_t len, int& alg);

struct ClientData { std::string type, challenge, origin; };
// Parses clientDataJSON. Refuses crossOrigin=true.
ClientData parse_client_data(std::string_view json);

// Is `origin` https://<rp_id>, with or without a port?
bool origin_matches(const std::string& origin, const std::string& rp_id);

struct Registered {
    std::string credential_id;    // base64url
    std::string spki;             // DER
    int         alg{0};
    uint32_t    sign_count{0};
};
// The whole registration check. `challenge` is the base64url challenge the console issued.
Registered verify_registration(std::string_view client_data_json,
                               const std::vector<unsigned char>& attestation_object,
                               const std::string& rp_id, const std::string& challenge);

// The whole sign-in check against the stored key. Returns the authenticator's new
// signature counter; the caller refuses one that did not advance (§6.1.1).
uint32_t verify_assertion(std::string_view client_data_json,
                          const std::vector<unsigned char>& authenticator_data,
                          const std::vector<unsigned char>& signature,
                          const std::string& rp_id, const std::string& challenge,
                          const std::string& spki, int alg);

} // namespace pki::webauthn
