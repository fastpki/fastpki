#pragma once
// Serve a renewed listener certificate without restarting the listener.
//
// ⚠️ WHY THIS EXISTS. The console, EST, ACME and MS read their TLS certificate once, at
// startup. `fastpki-ca renew-service-certs` renews a CA-issued one before it expires
// (renew_ca_issued_transport_certs), but a renewal the running process never loads is not a
// renewal: the listener would go on presenting the old certificate until something restarted
// it, which nothing does on a schedule. Restarting from the renewal job instead would take
// every HTTPS protocol down on every renewal, on every node, from a job whose whole purpose
// is that nobody has to be there.
//
// So the listener watches for the renewal itself. Every kTransportReloadIntervalSec it asks
// the database for the certificates published under its node-scoped cert_id, takes the first
// one that certifies the key it ALREADY holds (the same selection resolve_transport_cert makes
// at startup), and when that is a different certificate from the one it is serving, swaps it
// in. New handshakes get the new certificate and its chain; connections already open keep the
// one they negotiated. The key never changes here: a RE-KEY is a different key, which this
// deliberately does not follow — that still needs a restart, and the console says so.
//
// The swap is done with SSL_CTX_set_cert_cb rather than by rewriting the live SSL_CTX, because
// an SSL_CTX is not safe to modify while other threads create connections from it. The
// callback installs the current certificate on each new SSL under a mutex.
#include <string>

#include "pki/config.hpp"
#include "pki/x509.hpp"

namespace pki {

class Db;

// How often a listener looks for a renewed certificate, in seconds. Not a config key, for the
// reason kRaReloadIntervalSec is not one: an internal cadence, not a deployment policy. A
// renewal happens a quarter of a certificate's lifetime before it expires, so a delay of
// this size is invisible; it only has to be short enough that an operator who renews by hand
// sees the new certificate served while still looking.
inline constexpr int kTransportReloadIntervalSec = 30;

// Watch `raw_cert_id` (scoped to this node here, as at startup) for a renewal of the
// certificate `served`, and install it on `ssl_ctx` when one appears. Does nothing for a
// certificate loaded from files (`served.use_files`), which is outside the database, or when
// any argument is missing. `db` must outlive the process's serving loop — every listener's
// database handle does. `service` names the binary in log lines ("est", "web", …).
void serve_renewed_transport_certs(void* ssl_ctx, Db* db, const Config& cfg,
                                   const std::string& raw_cert_id,
                                   const TransportCert& served, const std::string& service);

// The certificate, chain and key a listener presents on a NEW handshake right now: the
// renewal serve_renewed_transport_certs swapped in, or else the SSL_CTX's own. Each is an
// owned reference, so it outlives a later swap. The console signs the Apple profiles it
// serves with it, so the signer is the identity the device just connected to.
struct TransportIdentity {
    X509Ptr leaf{};
    std::vector<X509Ptr> chain{};
    std::shared_ptr<EVP_PKEY> key{};
};
// False when `ssl_ctx` is null or carries no certificate and key (a plain-HTTP listener).
bool current_transport_identity(void* ssl_ctx, TransportIdentity& out);

}  // namespace pki
