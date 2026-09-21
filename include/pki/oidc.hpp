// OpenID Connect SSO login for the console.
// Implements the Authorization Code flow with PKCE: redirect to the IdP, then
// exchange the returned code for tokens and verify the ID token (signature via
// the IdP's JWKS, plus iss/aud/exp/nonce). Reuses lib/jws for the RS256/ES256
// signature check and the httplib TLS client for the IdP round-trips.
#pragma once
#include "../../third_party/nlohmann/json.hpp"
#include "pki/db.hpp"

#include <memory>
#include <string>
#include <vector>

namespace pki {

struct Config;

struct OidcClaims {
    std::string username;                 // mapped from the configured username claim
    std::string subject;                  // the "sub" claim
    std::vector<std::string> groups;      // from the configured groups claim
    // The standard `email` claim, unless the provider marks it unverified. Stored on the
    // account at sign-in so expiry emails reach the person.
    std::string email;
    nlohmann::json raw;                   // the full verified ID-token payload
};

class OidcClient {
public:
    // Build from a provider ROW — see the note on SamlSp.
    explicit OidcClient(const Db::OidcProviderRow& row);
    ~OidcClient();
    OidcClient(const OidcClient&) = delete;
    OidcClient& operator=(const OidcClient&) = delete;

    // Configured? (issuer + client_id + redirect_uri all set.)
    bool enabled() const;

    // The IdP authorization-endpoint redirect URL for a login attempt.
    std::string auth_url(const std::string& state, const std::string& nonce,
                         const std::string& code_challenge);

    // Exchange `code` for tokens, verify the ID token, return its claims.
    // Throws pki::Error on any failure (bad code, bad signature, iss/aud/exp/nonce
    // mismatch). `code_verifier` is the PKCE verifier; `expected_nonce` must match
    // the id_token nonce claim.
    OidcClaims exchange(const std::string& code, const std::string& code_verifier,
                        const std::string& expected_nonce);

private:
    struct Impl;
    std::unique_ptr<Impl> p_;
};

} // namespace pki
