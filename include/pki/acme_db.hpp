#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace pki {

struct AcmeAccount {
    std::string id;                 // generated identifier (decimal string)
    int         status{0};          // 0=valid, 1=deactivated, 2=revoked
    int         terms_agreed{0};
    std::string jwk_hash;           // base64url RFC7638 thumbprint
    std::string kid;                // username this account is bound to (EAB)
    std::string jwk_json;
    std::string contacts_json;
    std::string eab_json;
};

// Status codes mirror the PHP schema:
//   order:        0=pending, 1=ready, 2=processing, 3=valid, -1=invalid
//   authz:        0=pending, 1=valid,  -1=invalid, -2=deactivated by client
//   challenge:    0=pending, 1=processing, 2=valid, -1=invalid

struct AcmeOrder {
    std::string id;
    int         status{0};
    int64_t     expires{0};
    std::string identifiers_json;   // JSON array of {type,value}
    int64_t     not_before{0};
    int64_t     not_after{0};
    std::string cert_serial;        // hex; empty until issuance
    std::string account_id;
    // The CA this order was authorized against, set at new-order (the CA whose
    // acme:enrol gate the account passed). finalize refuses when it does not match the CA
    // in the finalize URL — otherwise a grant on one CA issues from every CA. Empty only
    // for an order created by an older binary.
    std::string ca_instance_id;
};

struct AcmeAuthz {
    std::string id;
    std::string identifier_json;    // {type,value} object
    int         status{0};
    int64_t     expires{0};
    int         wildcard{0};
    std::string order_id;           // "" for a pre-authorization (RFC 8555 §7.4.1)
    std::string account_id;         // owning account (set for all authz)
};

struct AcmeChallenge {
    std::string id;
    std::string type;               // "http-01" | "dns-01"
    std::string url;                // self URL we hand to the client
    int         status{0};
    std::string token;
    std::string error;              // populated when status = invalid
    int64_t     validated{0};
    std::string authz_id;
};

class AcmeDb {
public:
    virtual ~AcmeDb() = default;

    // Nonces
    virtual void save_nonce(const std::string& nonce, const std::string& ip,
                            int64_t expires) = 0;
    // Consume a nonce: returns true if present (and removes it), false if not.
    virtual bool consume_nonce(const std::string& nonce) = 0;
    virtual void delete_expired_nonces(int64_t now_unix) = 0;

    // Accounts
    virtual std::optional<AcmeAccount> get_account_by_id(const std::string& id) = 0;
    virtual std::optional<AcmeAccount> get_account_by_jwk_hash(const std::string& hash) = 0;
    virtual void save_account(const AcmeAccount& a) = 0;
    virtual void delete_account(const std::string& id) = 0;

    // Orders
    virtual std::optional<AcmeOrder> get_order(const std::string& id) = 0;
    virtual void save_order(const AcmeOrder& o) = 0;
    virtual void delete_expired_orders(int64_t now_unix) = 0;
    // All orders belonging to an account, newest first (RFC 8555 §7.1.2.1 orders list).
    virtual std::vector<AcmeOrder> orders_for_account(const std::string& account_id) = 0;

    // Authorizations
    virtual std::optional<AcmeAuthz> get_authz(const std::string& id) = 0;
    virtual std::vector<AcmeAuthz>   authz_for_order(const std::string& order_id) = 0;
    virtual void save_authz(const AcmeAuthz& a) = 0;
    // A valid, unexpired authorization for this order key + identifier, if any.
    // Used to reuse a pre-authorization (RFC 8555 §7.4.1) when an order is placed.
    virtual std::optional<AcmeAuthz> find_valid_authz(const std::string& order_id,
                                                      const std::string& identifier_json,
                                                      int64_t now_unix) = 0;

    // Challenges
    virtual std::optional<AcmeChallenge> get_challenge(const std::string& id) = 0;
    virtual std::vector<AcmeChallenge>   challenges_for_authz(const std::string& authz_id) = 0;
    virtual void save_challenge(const AcmeChallenge& c) = 0;
    virtual void delete_challenge(const std::string& id) = 0;
};

std::unique_ptr<AcmeDb> make_acme_postgres_db(const std::string& conninfo);

} // namespace pki
