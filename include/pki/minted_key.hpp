#pragma once
// A keypair minted in a token, until something takes responsibility for it.
//
// A key minted and then abandoned stays in the token forever, referenced by nothing and
// indistinguishable from a real key. Arm this immediately after generate_key_in_token();
// call keep() only once the row naming it is safely persisted. Any path out in between — a
// throw, an early return on a refusal, a signing refusal from the provider — runs the
// destructor and takes the orphan with it.
//
// Deliberately a compensating action rather than another pre-flight. The failure that
// motivated it (RSA-PSS) is refused by the OpenSSL pkcs11-provider while the token itself
// advertises CKM_RSA_PKCS_PSS for sign/verify, so asking the token in advance would have
// said yes and the key would still have leaked.
//
// ⚠️ IT DESTROYS WHATEVER ANSWERS AT THE URI, not specifically what this call created. So
// the handle has to be known free before minting — a mint that fails over an occupied
// label would otherwise take the key that was already there with it.
#include <string>
#include <utility>

#include "pki/config.hpp"
#include "pki/log.hpp"
#include "pki/pkcs11_helpers.hpp"

namespace pki {

class MintedKey {
public:
    MintedKey(const Config& cfg, std::string uri) : cfg_(cfg), uri_(std::move(uri)) {}
    MintedKey(const MintedKey&) = delete;
    MintedKey& operator=(const MintedKey&) = delete;
    void keep() { armed_ = false; }
    ~MintedKey() {
        if (!armed_ || uri_.empty()) return;
        try {
            const std::string pin = pkcs11_resolve_pin(uri_, cfg_.pkcs11_pin_file);
            auto r = pkcs11_destroy_key(cfg_.pkcs11_module, uri_, pin);
            if (!r.error.empty())
                log::err("could not remove the orphaned token key " + pkcs11_uri_redacted(uri_) +
                         ": " + r.error);
            else
                log::info("removed " + std::to_string(r.destroyed) +
                          " orphaned token object(s) for " + uri_);
        } catch (const std::exception& e) {
            // A destructor must not throw, and a failed cleanup must never turn a reported
            // error into a crash — the caller is already returning a failure.
            log::err(std::string("orphan cleanup threw: ") + e.what());
        }
    }

private:
    const Config& cfg_;
    std::string   uri_;
    bool          armed_{true};
};

}  // namespace pki
