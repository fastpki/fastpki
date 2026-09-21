#pragma once
#include "pki/x509.hpp"
#include "../../third_party/nlohmann/json.hpp"
#include <optional>
#include <string>
#include <vector>

namespace pki::jws {

// A parsed Flattened JWS (RFC 7515 §7.2.2): the three fields the wire format
// carries, plus their decoded forms for convenience.
struct ParsedJws {
    std::string    protected_b64;     // raw "protected" (base64url)
    std::string    payload_b64;       // raw "payload"   (base64url)
    std::string    signature_b64;     // raw "signature" (base64url)

    nlohmann::json protected_header;  // protected_b64 decoded + parsed
    std::vector<unsigned char> payload_bytes;   // payload_b64 decoded
    std::vector<unsigned char> signature_bytes; // signature_b64 decoded

    // protected.alg — currently "ES256" or "RS256".
    std::string alg;
    // protected.url — must match the request URL.
    std::string url;
    // protected.nonce — must be consumable.
    std::string nonce;
    // Exactly one of these is present per RFC 8555 §6.2.
    std::optional<nlohmann::json> jwk;   // for newAccount, revokeCert, keyChange
    std::optional<std::string>    kid;   // for everything else
};

// Parse a Flattened JWS document. Throws pki::Error(1, ...) on malformed.
ParsedJws parse(std::string_view body);

// Verify the signature over `parsed.protected_b64 + "." + parsed.payload_b64`
// using a public key derived from `jwk`. Supported alg/kty pairs:
//   ES256 + EC P-256
//   RS256 + RSA
// Throws pki::Error on failure. Returns the DER-encoded SubjectPublicKeyInfo
// of the verified key — used as the basis for the account JWK hash.
std::vector<unsigned char> verify(const ParsedJws& parsed,
                                  const nlohmann::json& jwk);

// RFC 7638 thumbprint of a JWK, returned base64url. Used as the JWK "hash"
// the PHP version stores in accounts.jwk_hash (PHP uses SHA-1 of the DER
// pubkey — this returns the standardized RFC 7638 thumbprint; the schema
// column stays TEXT either way).
std::string thumbprint(const nlohmann::json& jwk);

// Helpers (also used by acme/main.cpp).
std::string base64url_encode(const unsigned char* data, size_t len);
std::vector<unsigned char> base64url_decode(std::string_view s);

} // namespace pki::jws
