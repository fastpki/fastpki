#pragma once
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/x509.hpp"
#include <openssl/ocsp.h>
#include <string>
#include <vector>

namespace pki::ocsp {

// Stateless responder. Holds the signing CA cert/key and a DB handle. Each
// request is parsed, evaluated against the DB, and a signed BasicOCSPResponse
// is returned (or a status-only OCSPResponse for malformedRequest/etc.).
class Responder {
public:
    // The signing CA cert (DER from DB certs table) and key (pkcs11: URI or PEM path).
    // ca_id names WHICH CA this instance answers for, because the delegated
    // responder certificate is looked up per CA as "<OCSP_RESPONDER_CERT_ID_PREFIX>-<ca_id>".
    // `chain_ders` is EVERY live certificate this CA holds, newest first.
    // A signed OCSP response carries all of them, so a relying party anchored at the root
    // can build a path even while a rekey is rolling over — cert_der alone is the newest,
    // which after a rekey is a self-issued certificate that leads nowhere.
    Responder(const Config& cfg, Db& db, std::string ca_id,
              std::vector<unsigned char> ca_cert_der, const std::string& ca_key_ref,
              const std::vector<std::vector<unsigned char>>& chain_ders = {});

    // Returns DER-encoded OCSP response bytes for `request_der` (the raw body
    // of an HTTP POST application/ocsp-request). Never throws; on error
    // returns a status-only OCSPResponse with the appropriate status code.
    std::vector<unsigned char> handle(const unsigned char* request_der, size_t len);

    // This responder's signing CA — reused to build that instance's CRL.
    // ca_key() may be null when the CA key is remote: responses are
    // then signed by the delegated responder key and the CRL is unavailable.
    X509*     ca_cert() const { return ca_cert_.get(); }
    EVP_PKEY* ca_key()  const { return ca_key_.get(); }
    // Why ca_key() is null, in words an operator can act on. Empty when a key was
    // loaded. A CA whose key lives in ANOTHER node's token is not a fault of this
    // server — it is a fact about where the material is — so the answer is 503 naming
    // the CA, not 500.
    const std::string& ca_key_why() const { return ca_key_why_; }

private:
    static std::vector<unsigned char> status_response(int ocsp_status);

    // Resolve THIS CA's responder certificate from the DB. Per call, not cached —
    // a reissued credential then takes effect without a restart, and expiry or revocation
    // is noticed while the process runs. Returns null and fills `why` with something an
    // operator can act on.
    X509Ptr resolve_responder_cert(std::string& why) const;

    Config        cfg_;
    Db&           db_;
    std::string   ca_id_;
    X509Ptr       ca_cert_;
    std::vector<X509Ptr> ca_chain_;   // every live cert of this CA, newest first
    EvpPkeyPtr    ca_key_;
    std::string   ca_key_why_;        // empty unless ca_key_ is null
    // Delegated OCSP responder (RFC 6960). ONE key for the process; the
    // CERTIFICATE is resolved per request, per CA. The CA key is never a fallback — a CA
    // with no responder certificate cannot answer OCSP for its own certificates.
    EvpPkeyPtr    responder_key_;
    // Why responder_key_ is null. Loading it used to THROW out of the constructor,
    // which pick_responder could only render as 500 "CA material unavailable" — on the
    // CRL route, which does not use this key at all. Measured on lab DC3: /issuing.crl
    // returned 500 while /issuing-dc3.crl returned 200 from the same process, because
    // the CA key was fine and the RESPONDER key was not. Two independent credentials,
    // so two independent failures.
    std::string   responder_key_why_;
};

} // namespace pki::ocsp
