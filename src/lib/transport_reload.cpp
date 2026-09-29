#include "pki/transport_reload.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "pki/db.hpp"
#include "pki/log.hpp"

namespace pki {
namespace {

// What one listener is serving. Lives for the whole process: the SSL_CTX that points at it
// does, and a listener never tears its server down short of exiting.
struct Served {
    void* ctx{nullptr};                 // the SSL_CTX this record serves, for lookups
    std::mutex mu;
    std::atomic<bool> swapped{false};   // false: the SSL_CTX's own certificate is current
    X509Ptr leaf{};
    std::vector<X509Ptr> chain{};
    std::shared_ptr<EVP_PKEY> key{};
    std::string serial{};
};

std::mutex& registry_mu() { static std::mutex m; return m; }
std::vector<std::unique_ptr<Served>>& registry() {
    static std::vector<std::unique_ptr<Served>> r;
    return r;
}

// Called by OpenSSL for every new server handshake, on whichever thread accepted it.
// Until the first renewal it does nothing, so the certificate load_tls_context installed on
// the SSL_CTX is served exactly as before.
int install_current(SSL* ssl, void* arg) {
    auto* s = static_cast<Served*>(arg);
    if (!s || !s->swapped.load(std::memory_order_acquire)) return 1;
    std::lock_guard<std::mutex> lk(s->mu);
    // ⚠️ RETURN 1 EVEN WHEN A CALL FAILS. The SSL still carries the SSL_CTX's certificate —
    // the one that was being served before the renewal, valid for a while yet — and failing
    // the handshake instead would turn a renewal problem into an outage.
    if (SSL_use_certificate(ssl, s->leaf.get()) != 1) return 1;
    STACK_OF(X509)* st = sk_X509_new_null();
    if (st) {
        for (const auto& c : s->chain) sk_X509_push(st, c.get());
        SSL_set1_chain(ssl, st);   // up-refs each certificate; the stack itself is ours
        sk_X509_free(st);
    }
    SSL_use_PrivateKey(ssl, s->key.get());
    return 1;
}

std::shared_ptr<EVP_PKEY> key_of(const TransportCert& tc) {
    if (tc.key) return tc.key;
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(tc.key_pem.data(), static_cast<int>(tc.key_pem.size())), &BIO_free);
    if (!bio) return {};
    EVP_PKEY* k = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (!k) return {};
    return std::shared_ptr<EVP_PKEY>(k, EVP_PKEY_free);
}

}  // namespace

void serve_renewed_transport_certs(void* ssl_ctx, Db* db, const Config& cfg,
                                   const std::string& raw_cert_id,
                                   const TransportCert& served, const std::string& service) {
    if (!ssl_ctx || !db || served.use_files || raw_cert_id.empty()) return;
    auto key = key_of(served);
    auto leafs = load_certs_pem_mem(served.cert_pem);
    if (!key || leafs.empty()) return;

    auto owned = std::make_unique<Served>();
    Served* s = owned.get();
    s->ctx = ssl_ctx;
    s->key = key;
    s->serial = x509_serial_hex(leafs.front().get());
    {
        std::lock_guard<std::mutex> lk(registry_mu());
        registry().push_back(std::move(owned));
    }
    SSL_CTX_set_cert_cb(static_cast<SSL_CTX*>(ssl_ctx), install_current, s);

    const std::string cert_id = listener_cert_id(cfg, raw_cert_id);
    log::info(service + ": serving transport certificate " + s->serial + " for '" + cert_id +
              "'; a renewal published under that id is picked up within " +
              std::to_string(kTransportReloadIntervalSec) + "s, without a restart");

    std::thread([s, db, cert_id, service]() {
        for (;;) {
            std::this_thread::sleep_for(std::chrono::seconds(kTransportReloadIntervalSec));
            try {
                // The same selection resolve_transport_cert makes at startup: the candidates
                // come CA-issued first and newest first, and the first that certifies OUR key
                // is ours — a peer's row under the same id never is.
                for (const auto& cand : db->list_transport_candidates(cert_id)) {
                    if (cand.der.empty()) continue;
                    const unsigned char* p = cand.der.data();
                    X509Ptr x{d2i_X509(nullptr, &p, static_cast<long>(cand.der.size()))};
                    if (!x || !cert_certifies_key(x.get(), s->key.get())) continue;
                    const std::string serial = x509_serial_hex(x.get());
                    if (serial == s->serial) break;   // still the one being served

                    std::vector<X509Ptr> chain;
                    const std::string chain_pem = build_issuer_chain(*db, x.get());
                    if (!chain_pem.empty()) chain = load_certs_pem_mem(chain_pem);
                    const std::string old = s->serial;
                    {
                        std::lock_guard<std::mutex> lk(s->mu);
                        s->leaf = std::move(x);
                        s->chain = std::move(chain);
                        s->serial = serial;
                    }
                    s->swapped.store(true, std::memory_order_release);
                    log::info(service + ": now serving the renewed transport certificate " +
                              serial + " for '" + cert_id + "' (was " + old +
                              ") — no restart was needed");
                    break;
                }
            } catch (const std::exception& e) {
                // A database that is briefly unreachable is not worth a line every 30s at
                // err; the certificate already being served stays valid meanwhile.
                log::debug(service + ": could not check for a renewed transport certificate: " +
                           e.what());
            } catch (...) {}
        }
    }).detach();
}

bool current_transport_identity(void* ssl_ctx, TransportIdentity& out) {
    if (!ssl_ctx) return false;
    auto up = [](X509* x) { X509_up_ref(x); return X509Ptr{x}; };
    {
        std::lock_guard<std::mutex> rk(registry_mu());
        for (const auto& s : registry()) {
            if (s->ctx != ssl_ctx || !s->swapped.load(std::memory_order_acquire)) continue;
            std::lock_guard<std::mutex> lk(s->mu);
            if (!s->leaf || !s->key) return false;
            out.leaf = up(s->leaf.get());
            out.chain.clear();
            for (const auto& c : s->chain) out.chain.push_back(up(c.get()));
            out.key = s->key;
            return true;
        }
    }
    // Not renewed since startup: the SSL_CTX's own certificate is the one being served. It is
    // never modified after the listener starts (renewals go through the cert callback), so
    // reading it here does not race.
    auto* ctx = static_cast<SSL_CTX*>(ssl_ctx);
    X509* leaf = SSL_CTX_get0_certificate(ctx);
    EVP_PKEY* key = SSL_CTX_get0_privatekey(ctx);
    if (!leaf || !key) return false;
    out.leaf = up(leaf);
    EVP_PKEY_up_ref(key);
    out.key = std::shared_ptr<EVP_PKEY>(key, EVP_PKEY_free);
    out.chain.clear();
    // ⚠️ THE EXTRA CHAIN, NOT ONLY THE CERTIFICATE'S OWN. The listener loads its issuers with
    // SSL_CTX_add_extra_chain_cert (load_tls_ctx), and a handshake sends those. This read
    // SSL_CTX_get0_chain_certs, which is the certificate's own chain and was empty, so every
    // signed Apple profile carried the signer alone: an iPhone that trusts the root had no way
    // from the console's certificate to it and showed the profile as Not Verified.
    // SSL_CTX_get_extra_chain_certs returns the extra chain, or the certificate's own chain when
    // there is no extra one, which is exactly what a handshake sends.
    STACK_OF(X509)* chain = nullptr;
    SSL_CTX_get_extra_chain_certs(ctx, &chain);
    if (chain)
        for (int i = 0; i < sk_X509_num(chain); ++i) out.chain.push_back(up(sk_X509_value(chain, i)));
    return true;
}

}  // namespace pki
