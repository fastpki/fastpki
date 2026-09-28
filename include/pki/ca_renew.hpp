#pragma once
// Renewing a CA — one implementation, called by the console and by `fastpki-ca renew`.
//
// ⚠️ THIS EXISTS SO THE TWO PATHS CANNOT DRIFT. The whole operation lived inside the
// console's POST /api/ca-instances/<id>/renew handler, which meant a CA could only be
// renewed from a browser: an operator on a cloud node reached over SSH had a documented
// remedy (deployment.md §9.0 step 11, admin-guide.md §3.8) they could not run from where
// they were. Re-implementing it in the CLI would have given the product two answers to
// "what does renewing a CA do", and a renewal from one path would stop meaning what it
// means from the other — so the logic moved here and both callers ask this.
//
// What renewing IS: a new certificate for the same CA, over its current key or a new one,
// signed by its parent (or self-signed for a root), so it can outlive the certificate it
// replaces. It is also how a CA acquires addresses it was minted without — a CA created
// before `fastpki-mesh --map` carries only its own data center in its CRL DP and AIA, and
// those are fixed at mint time, so a renewal is the only way to correct them.
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

#include "pki/ca_instance.hpp"
#include "pki/config.hpp"
#include "pki/db.hpp"

namespace pki {

// What to renew and how.
//
// ⚠️ `same_key` DEFAULTS TO TRUE, which is the opposite of the console form's historic
// default and is deliberate here. Renewing with the current key changes nothing a relying
// party has to re-learn; a re-key is a larger event — it mints a keypair, issues two
// cross-certificates and re-signs every service credential this CA has issued — so it is
// something a caller asks for by name rather than something it gets by leaving a field out.
struct CaRenewRequest {
    std::string ca_id;
    bool        same_key{true};
    // Where the NEW key goes, when !same_key. A CA private key lives in a token, so this
    // is a pkcs11: URI naming a handle nothing already answers at.
    std::string new_key_ref{};
    std::string key_algo{"rsa"};
    int         bits{4096};
    std::string curve{};
    int         days{3650};
    std::string md{"sha256"};
    // Mint the new key extractable, so it can later be copied into the other token of an
    // HA pair. Only meaningful with a new key: CKA_EXTRACTABLE is fixed at generation and
    // PKCS#11 forbids granting it afterwards.
    bool        replicable{false};

    // Who did this, for the audit row. `iface` names the interface and the audit action is
    // built from it — "web" keeps the console's existing `web_ca_renewed`, and the CLI
    // audits as `cli_ca_renewed` where it previously recorded nothing at all.
    std::string iface{"cli"};
    std::string actor{};
    std::string actor_ip{};
};

struct CaRenewResult {
    std::string serial;          // the renewed certificate — the CA's newest, and its signer
    std::string bridge_serial;   // new key under the OLD root  (re-key of a root only)
    std::string cross_serial;    // old key under the NEW root  (re-key of a root only)
    std::string key_ref;         // the key the CA row now names
    int64_t     not_after{0};
    std::string signer;          // the parent's id, or the CA's own id for a root
    bool        same_key{true};
    // The re-key cascade. Zero on a same-key renewal, where there is nothing to cascade:
    // every service credential was signed by that key and still chains through the renewed
    // certificate.
    int         service_certs_renewed{0};
    int         service_certs_failed{0};
};

// Why a renewal was refused, with enough for an HTTP caller to answer in kind.
//
// `status` carries the console's status codes (400 a malformed request, 404 no such CA,
// 409 the deployment is not in a state where this can proceed, 500 otherwise) so the
// handler does not have to re-derive them from the message and get them subtly different.
class CaRenewError : public std::runtime_error {
public:
    CaRenewError(int status, const std::string& what, bool csr_route = false,
                 std::string parent = {})
        : std::runtime_error(what), status_(status), csr_route_(csr_route),
          parent_(std::move(parent)) {}
    int  status()    const { return status_; }
    // The parent's key is on another node, so the renewal has to travel as a CSR. The
    // console renders a different dialog for this case, which is why it is a flag rather
    // than only a sentence.
    bool csr_route() const { return csr_route_; }
    const std::string& parent() const { return parent_; }
private:
    int         status_;
    bool        csr_route_;
    std::string parent_;
};

// Renew `req.ca_id`. Throws CaRenewError on a refusal and std::exception on anything else.
//
// ⚠️ NOTHING IS MINTED UNTIL EVERY REFUSAL HAS BEEN CHECKED, and a keypair that is minted
// and then not used is destroyed on the way out. A token object no certificate ever names
// is untracked, in hardware, and indistinguishable from a real key afterwards.
//
// `cache` is optional: pass the caller's CaMaterialCache so the entry for this CA is
// invalidated when the renewal lands. A caller without one (the CLI, a one-shot process)
// passes nullptr and a local cache is used.
CaRenewResult renew_ca(Db& db, const Config& cfg, const CaRenewRequest& req,
                       CaMaterialCache* cache = nullptr);

}  // namespace pki
