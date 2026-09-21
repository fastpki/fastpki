// SAML 2.0 SP-initiated Web SSO for the console.
// Builds an AuthnRequest (HTTP-Redirect binding) and consumes the IdP's signed
// Response at the ACS (HTTP-POST binding). The XML signature on the assertion is
// verified with libxmlsec1 against a *pinned* IdP certificate (embedded KeyInfo
// is ignored), and the assertion must be signed. Compiled only when built with
// -DFASTPKI_WITH_SAML=ON (pulls in libxml2 + libxmlsec1 + zlib); otherwise the
// class still exists but reports built()==false and enabled()==false so the web
// server cleanly 404s the /api/saml/* endpoints.
#pragma once
#include "pki/db.hpp"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace pki {

struct Config;

struct SamlAssertion {
    std::string name_id;                  // the <NameID> value
    std::string username;                 // mapped username (NameID, or a configured attribute)
    std::vector<std::string> groups;      // values of the configured groups attribute
    // The person's email address: the first of the usual email attributes the assertion
    // carries, or the NameID when its format says it is an address. Stored on the account at
    // sign-in so expiry emails reach the person.
    std::string email;
};

class SamlSp {
public:
    // Build from a provider ROW. `auth_providers` + `saml_providers` are the shape that
    // can express more than one IdP; the Config constructor above can only ever express
    // the single configured one and goes when its keys do.
    explicit SamlSp(const Db::SamlProviderRow& row);
    ~SamlSp();
    SamlSp(const SamlSp&) = delete;
    SamlSp& operator=(const SamlSp&) = delete;

    // Was this binary compiled with FASTPKI_WITH_SAML (libxmlsec1)?
    static bool built();
    // Configured? (idp_sso_url + idp_cert + sp_entity_id + sp_acs_url set AND built).
    bool enabled() const;

    // Build a fresh AuthnRequest and return the IdP HTTP-Redirect URL to send the
    // browser to. `relay_state` is echoed back by the IdP. `out_request_id` gets
    // the AuthnRequest ID so the caller can later match the Response's
    // InResponseTo. Throws pki::Error if not enabled.
    std::string login_redirect(const std::string& relay_state, std::string& out_request_id);

    // Consume a base64 SAMLResponse posted to the ACS. Verifies the assertion's
    // XML signature against the pinned IdP cert, then validates Status, Audience,
    // the SubjectConfirmation/Conditions time windows, and InResponseTo (via
    // `is_known_request`, which must return true exactly once for a request ID we
    // issued). Returns the assertion identity on success; throws pki::Error on any
    // validation failure.
    SamlAssertion consume(const std::string& saml_response_b64,
                          const std::function<bool(const std::string&)>& is_known_request);

    // SP metadata XML (EntityDescriptor) for registering this SP with the IdP.
    std::string metadata() const;

private:
    struct Impl;
    std::unique_ptr<Impl> p_;
};

} // namespace pki
