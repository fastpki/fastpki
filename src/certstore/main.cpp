// fastpki-store — RFC 4387 "Certificate Store Access via HTTP".
//
// Endpoints:
//   GET /certificates/search?<attr>=<value>
//   GET /crls/search                          (serves the CA CRL, DER)
//
// Supported attributes map onto the `certs` table columns:
//   certHash → fingerprint, cn, name/subject → subject, serial, sHash,
//   iHash, iAndSHash, sKIDHash. The `uri` selector matches a SubjectAltName URI
//   (RFC 4387 §2), indexed one-per-row in the cert_uris table at issuance.
//
// A single match returns a DER cert (application/pkix-cert). Multiple matches
// return a PKCS#7 certs-only bundle (application/pkcs7-mime). This mirrors the
// PHP certificates/search.cgi behaviour closely enough for the common clients
// (openssl, browsers following AIA).

#include "pki/ca_instance.hpp"
#include "pki/version.hpp"
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/endpoint_gate.hpp"
#include "pki/error.hpp"
#include "pki/listen.hpp"
#include "pki/log.hpp"
#include "pki/x509.hpp"

#include "httplib.h"
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace {

std::string sha1_hex(const unsigned char* d, size_t n) {
    unsigned char md[SHA_DIGEST_LENGTH];
    SHA1(d, n, md);
    static const char* h = "0123456789abcdef";
    std::string s;
    for (unsigned char c : md) { s += h[c >> 4]; s += h[c & 0xf]; }
    return s;
}

// RFC 4387 §2.2 iHash: SHA-1 of the DER-encoded issuer Name. For a CRL the issuer
// is the CA's subject name.
std::string ca_ihash(X509* ca) {
    unsigned char* der = nullptr;
    int len = i2d_X509_NAME(X509_get_subject_name(ca), &der);
    if (len <= 0 || !der) return {};
    std::string out = sha1_hex(der, static_cast<size_t>(len));
    OPENSSL_free(der);
    return out;
}

// RFC 4387 §2.2 sKIDHash: SHA-1 of the subjectKeyIdentifier value ("" if the CA
// carries no SKID extension).
std::string ca_skidhash(X509* ca) {
    const ASN1_OCTET_STRING* skid = X509_get0_subject_key_id(ca);
    if (!skid) return {};
    return sha1_hex(ASN1_STRING_get0_data(skid),
                    static_cast<size_t>(ASN1_STRING_length(skid)));
}

// RFC 4387 query attribute → DB column.
std::string map_attr(const std::string& attr) {
    static const std::map<std::string, std::string> m = {
        {"certHash",  "fingerprint"},
        {"name",      "subject"},
        {"cn",        "cn"},
        {"serial",    "serial"},
        {"sHash",     "sHash"},
        {"iHash",     "iHash"},
        {"iAndSHash", "iAndSHash"},
        {"sKIDHash",  "sKIDHash"},
        {"uri",       "uri"},   // SubjectAltName URI (RFC 4387 §2), via cert_uris
    };
    auto it = m.find(attr);
    return it == m.end() ? std::string() : it->second;
}

void handle_search(pki::Db& db, const httplib::Request& req, httplib::Response& res) {
    // Exactly one query parameter, per RFC 4387.
    if (req.params.size() != 1) {
        res.status = 400;
        res.set_content("exactly one search attribute required", "text/plain");
        return;
    }
    const auto& [attr, value] = *req.params.begin();
    std::string column = map_attr(attr);
    if (column.empty()) {
        res.status = 400;
        res.set_content("unsupported attribute: " + attr, "text/plain");
        return;
    }

    try {
        auto certs = db.search_certs(column, value);
        if (certs.empty()) { res.status = 404; return; }

        if (certs.size() == 1) {
            res.status = 200;
            res.set_content(std::string(certs[0].begin(), certs[0].end()),
                            "application/pkix-cert");
            return;
        }

        // Multiple → PKCS#7 bundle. Parse each DER back into X509 for wrapping.
        std::vector<pki::X509Ptr> owned;
        std::vector<X509*> raw;
        for (auto& der : certs) {
            const unsigned char* p = der.data();
            X509* x = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
            if (x) { owned.emplace_back(x); raw.push_back(x); }
        }
        auto p7 = pki::pkcs7_certs_only(raw);
        res.status = 200;
        res.set_content(std::string(p7.begin(), p7.end()),
                        "application/pkcs7-mime");
    } catch (const pki::Error& e) {
        pki::log::err(std::string("store search error: ") + e.what());
        res.status = (e.code() == 1) ? 400 : 500;
        res.set_content(e.what(), "text/plain");
    }
}

} // namespace

int main(int argc, char** argv) {
    if (pki::handled_version_flag(argc, argv)) return 0;
    std::string conf_path = "config/bootstrap.conf";
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) conf_path = argv[++i];
        else if (std::strcmp(argv[i], "--help") == 0) {
            std::cout << "Usage: fastpki-store [--config path]\n";
            return 0;
        }
    }

    OpenSSL_add_all_algorithms();

    try {
        auto cfg = pki::Config::load(conf_path);
        if (cfg.log_level == "debug") pki::log::set_level(pki::log::Level::Debug);
        else if (cfg.log_level == "info") pki::log::set_level(pki::log::Level::Info);

        std::unique_ptr<pki::Db> db;
        db = pki::make_postgres_db(cfg.pg_conninfo);
        pki::overlay_config(cfg, db->get_config());   // DB config overlay

        // ⚠️ RE-APPLIED AFTER overlay_config, AND THAT IS THE WHOLE POINT. The level was
        // set above from bootstrap.conf ALONE, so LOG_LEVEL=debug in the `config` table — the
        // console's Config page, which is where an operator actually sets it — reached
        // st.cfg only here and never reached the logger at all. The reported symptom is
        // exactly that: "nothing is written in the logs even when LOG_LEVEL is set to
        // DEBUG in the Config table", which reads as a product with no diagnostics rather
        // than as a setting that was silently ignored.
        //
        // Applied TWICE on purpose. The early call governs anything logged before the
        // database is reachable — a bad conninfo, a dead token — which the DB obviously
        // cannot configure. This one governs everything after, and the DB is the source of
        // truth once it can be read.
        //
        // Same shape as the AUTH_BACKEND and SCEP-challenge lines fixed earlier in this
        // family: a value read before the overlay describes bootstrap.conf, not the deployment.
        if (cfg.log_level == "debug") pki::log::set_level(pki::log::Level::Debug);
        else if (cfg.log_level == "info") pki::log::set_level(pki::log::Level::Info);
        else pki::log::set_level(pki::log::Level::Err);

        // There is no default CA. The store signs each CA's CRL on demand,
        // resolving the CA from the RFC 4387 selector (iHash / sKIDHash) against the
        // registered CAs, with material loaded via the shared cache.
        pki::CrlCache crl_cache(cfg.crl_cache_ttl_sec);
        pki::CaMaterialCache ca_cache;

        httplib::Server srv;
        srv.set_payload_max_length(64 * 1024);
        srv.Get("/certificates/search",
                [&](const httplib::Request& req, httplib::Response& res) {
                    handle_search(*db, req, res); });
        srv.Get("/crls/search",
                [&](const httplib::Request& req, httplib::Response& res) {
                    // RFC 4387 §3. There is no default CA, so the client MUST select the issuer
                    // via exactly one of iHash / sKIDHash; we match it against the
                    // registered CAs and sign that CA's CRL. No/!=1 selector -> 400;
                    // unknown attribute -> 400; no matching CA -> 404.
                    if (req.params.size() != 1) {
                        res.status = 400;
                        res.set_content("select a CA via exactly one of iHash / sKIDHash", "text/plain");
                        return;
                    }
                    const auto& [attr, value] = *req.params.begin();
                    if (attr != "iHash" && attr != "sKIDHash") {
                        res.status = 400;
                        res.set_content("unsupported CRL attribute: " + attr, "text/plain");
                        return;
                    }
                    std::string got = value;
                    for (auto& c : got) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    std::string ca_id;
                    for (const auto& ci : db->list_ca_instances()) {
                        // ⚠️ ANY STATUS, NOT JUST ACTIVE. Disabling a CA stops it ISSUING;
                        // it does not retract the certificates it already signed, and those
                        // are precisely the ones whose revocation status a relying party
                        // still needs — more so after a disable, since one reason to disable
                        // a CA is that something went wrong with it. Filtering here left
                        // ca_id empty and returned 404 below, BEFORE the stored-CRL fallback
                        // further down could run, turning "revoked" into "unknown".
                        // signing_ca_pem is still required: without the certificate there is
                        // nothing to hash the request against.
                        if (ci.signing_ca_pem.empty()) continue;
                        try {
                            auto cc = pki::load_ca_cert_pem(ci.signing_ca_pem);
                            std::string h = (attr == "iHash") ? ca_ihash(cc.get()) : ca_skidhash(cc.get());
                            if (!h.empty() && h == got) { ca_id = ci.id; break; }
                        } catch (...) { /* unreadable CA — skip */ }
                    }
                    if (ca_id.empty()) { res.status = 404; return; }
                    // ⚠️ THE STORED CRL IS TRIED BEFORE THE MATERIAL CHECK, NOT AFTER, AND
                    // THAT ORDERING IS THE WHOLE FEATURE. resolve_ca_instance() marks a CA
                    // whose key lives on another node INACTIVE — `if (!pins_key) r.active =
                    // false` — so ca_cache.get() returns nullopt with 503 for exactly the
                    // peers a replicated CRL exists to serve. This used to sit below an
                    // `if (!m)` early return, which meant a node holding valid, unexpired
                    // CRL bytes in its own database answered "revocation status cannot be
                    // determined" while they sat there.
                    //
                    // It was also unreachable on its own terms: it was guarded by
                    // `if (!m->key)`, and a get() that SUCCEEDS has already loaded the key
                    // and checked it against the certificate, so m->key was never null.
                    auto serve_stored_crl = [&]() -> bool {
                        std::string stale;
                        auto stored = pki::imported_crl(*db, ca_id, /*is_delta=*/false, stale);
                        if (!stored) return false;
                        if (!stale.empty()) pki::log::err(stale);
                        // Never silent: serving it is right, but this is the only signal that
                        // the CA cannot be signed for here, and a mistyped pkcs11: handle
                        // would otherwise look healthy at this endpoint.
                        pki::log::info("CRL for CA '" + ca_id + "': no usable signing key "
                                       "here — serving the stored CRL instead");
                        res.status = 200;
                        res.set_content(std::string(stored->begin(), stored->end()),
                                        "application/pkix-crl");
                        return true;
                    };
                    int code = 500; std::string err;
                    auto m = ca_cache.get(*db, cfg, ca_id, code, err);
                    if (!m) {
                        if (serve_stored_crl()) return;
                        res.status = code; res.set_content(err, "text/plain"); return;
                    }
                    if (!m->key) {
                        if (serve_stored_crl()) return;
                        res.status = 503;
                        res.set_content("CRL unavailable: the CA signing key is remote", "text/plain");
                        return;
                    }
                    try {
                        auto der = crl_cache.get(cfg, *db, m->cert.get(), m->key.get(), ca_id);
                        res.status = 200;
                        res.set_content(std::string(der.begin(), der.end()),
                                        "application/pkix-crl");
                    } catch (const std::exception& e) {
                        pki::log::err(std::string("store CRL error: ") + e.what());
                        res.status = 500;
                        res.set_content(e.what(), "text/plain");
                    }
                });

        // Never open the port while this protocol is switched off in the
        // console, and stop if it is switched off later.
        pki::gate_protocol(*db, "store");
        std::string bound;
        if (!pki::bind_listener(srv, cfg.store_bind_addr, cfg.store_port, bound)) {
            std::cerr << "listen failed\n";
            return 1;
        }
        // After the bind, and naming what was bound: the wildcard falls back to IPv4 on a
        // host with no IPv6 stack, and a line printed first would name an address this
        // process is not serving on.
        pki::log::info("fastpki-store listening on " + bound + ":" +
                       std::to_string(cfg.store_port));
        if (!srv.listen_after_bind()) {
            std::cerr << "listen failed\n";
            return 1;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << '\n';
        return 1;
    }
}
