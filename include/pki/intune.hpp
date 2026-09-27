#pragma once
// Microsoft Intune as a SCEP challenge authority.
//
// Intune writes its own challenge into each managed device's CSR (an encrypted, signed blob
// naming the device and what the CSR must contain), so only Intune can check it. A device
// whose Intune SCEP profile points at <SCEP_PATH>/intune/<connection-id> is enrolled like
// this:
//
//   1. validate      POST {ScepRequestValidationFEService}/ScepActions/validateRequest
//   2. issue         only on code "Success"
//   3. notify        successNotification (thumbprint, serial, expiry, CA) or, when issuing
//                    failed after validation passed, failureNotification
//
// and Intune later asks for certificates to be revoked (a wiped or retired device) through
// {PkiConnectorFEService}/CertificateAuthorityRequests/downloadRevocationRequests.
//
// The wire format is Microsoft's reference library (microsoft/Intune-Resource-Access,
// src/CsrValidation), which is the specification: the documentation describes only the
// library's methods.
//
// ⚠️ THE APP AUTHENTICATES WITH A FASTPKI CERTIFICATE, NEVER A CLIENT SECRET. The key is one
// RSA key in the node's token (object `intune`); each issuing CA certifies it as the service
// credential `intune-<ca_id>`, renewed like the other service credentials. A renewed
// certificate is registered with the Entra app by Graph `addKey`, which needs no permission
// beyond proof of possession of the current key, and the one it replaced is then removed
// with `removeKey`. The administrator uploads a certificate by hand only once, when the
// connection is created, or again if every registered certificate has expired.
#include <openssl/x509.h>

#include <string>
#include <vector>

#include "pki/config.hpp"
#include "pki/db.hpp"

namespace pki::intune {

// Inline, not in intune.cpp: service_cert.cpp needs these, and every binary links that —
// including ones that carry no HTTPS client.
//
// The subject an Intune-validated enrolment speaks for: provider-qualified, because Intune
// is an external authority. Roles are granted to it through subject_roles.
inline std::string subject_for(const std::string& connection_id) { return "intune\\" + connection_id; }
// The service credential's cert_id for the CA a connection issues from.
inline std::string cert_id_for(const std::string& ca_id) { return "intune-" + ca_id; }
// The credential key in this node's token. Derived from PKCS11_TOKEN and PKCS11_PIN_FILE,
// like every key the console mints, so no setting names it.
inline std::string key_uri(const Config& cfg) {
    const std::string token = cfg.pkcs11_token.empty() ? "fastpki" : cfg.pkcs11_token;
    return "pkcs11:token=" + token + ";object=intune;type=private" +
           (cfg.pkcs11_pin_file.empty() ? std::string()
                                        : "?pin-source=" + cfg.pkcs11_pin_file.string());
}

// Why this id cannot name a connection, "" when it can. It becomes a URL path segment and
// half of a subject name, so it is 1 to 40 of [a-z0-9-].
std::string connection_id_refusal(const std::string& id);
// Why this row cannot be stored, "" when it can: the tenant and app ids are Entra GUIDs (the
// tenant may also be a verified domain name), and every URL is https.
std::string connection_refusal(const Db::IntuneConnectionRow& c);

struct Verdict {
    bool ok{false};
    std::string code{};          // Intune's code: "Success", "ChallengeExpired", …
    std::string description{};   // Intune's errorDescription
};

struct RevocationRequest {
    std::string request_context{}, serial{}, issuer_name{}, ca_configuration{};
};
struct RevocationResult {
    std::string request_context{};
    bool succeeded{false};
    // Microsoft's CARequestErrorCode name: "None", "CertificateNotFoundError", …
    std::string error_code{"None"};
    std::string error_message{};
};

// What the credential check found. `registered` is whether the Entra app lists the current
// certificate; `note` says what was done or what the administrator has to do.
struct CredentialStatus {
    bool registered{false};
    std::string note{};
};

// One tenant. Every call throws pki::Error(2) when Microsoft cannot be reached or refuses the
// app — the caller must treat that as "not validated", never as success.
class Client {
public:
    Client(const Config& cfg, Db& db, Db::IntuneConnectionRow row);

    Verdict validate(const std::string& txid, const std::string& csr_b64);
    Verdict notify_success(const std::string& txid, const std::string& csr_b64, X509* cert,
                           const std::string& issuing_ca);
    Verdict notify_failure(const std::string& txid, const std::string& csr_b64,
                           long hresult, const std::string& description);

    std::vector<RevocationRequest> download_revocations(const std::string& txid, int max,
                                                        const std::string& issuer_name);
    void upload_revocation_results(const std::string& txid,
                                   const std::vector<RevocationResult>& results);

    // Compare the Entra app's certificates with this CA's current credential. With `apply`,
    // register the current certificate if it is missing, and remove from the app every
    // certificate FastPKI retired — but only once the current one is registered.
    CredentialStatus sync_credential(bool apply);

private:
    const Config& cfg_;
    Db& db_;
    Db::IntuneConnectionRow row_;
};

// A fresh RFC 4122 version-4 UUID, lowercase.
std::string new_uuid();

// Store a connection, grant `role` (when not empty) to its subject, and make sure its CA has
// the credential certificate — minting the `intune` key the first time, replicable when
// SERVICE_KEYS_REPLICABLE is on. Throws pki::Error(1) naming the reason when the connection
// is refused, before anything is written. Returns what was done, for the operator; a
// credential that could not be created is reported there, and saving again retries it.
std::vector<std::string> save_connection(const Config& cfg, Db& db,
                                         const Db::IntuneConnectionRow& c,
                                         const std::string& role);

// Delete a connection and every role granted to its subject, so a connection created later
// under the same id starts with none. False when there is no such connection.
bool remove_connection(Db& db, const std::string& id);

// The credential certificate the administrator uploads to the Entra app, as PEM, or "" when
// the CA has none yet.
std::string credential_pem(Db& db, const std::string& ca_id);

// The name FastPKI gives Intune for a CA: its certificate's common name. Sent as the issuing
// authority with every success notification, and used to ask for that CA's revocations.
std::string issuer_name(Db& db, const std::string& ca_id);

// One revocation pass: download what Intune asks to be revoked for this connection's CA,
// revoke it, and upload how each went. Only certificates this connection issued, from its
// CA, are revoked; anything else is refused back to Intune, so a tenant cannot revoke what
// another tenant — or another protocol — issued.
struct PollResult { int requested{0}, revoked{0}, refused{0}; };
PollResult poll_revocations(const Config& cfg, Db& db, const Db::IntuneConnectionRow& conn);

}  // namespace pki::intune
