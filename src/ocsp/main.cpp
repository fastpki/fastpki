#include "responder.hpp"
#include "pki/ca_instance.hpp"
#include "pki/ra_reload.hpp"
#include "pki/version.hpp"
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/endpoint_gate.hpp"
#include "pki/listen.hpp"
#include "pki/log.hpp"
#include "pki/error.hpp"
#include "pki/x509.hpp"
#include <map>
#include <memory>

// Vendored header-only HTTP server: https://github.com/yhirose/cpp-httplib
// (Place httplib.h under third_party/ before building.)
#include "../../third_party/httplib.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

void set_log_level_from_string(std::string_view s) {
    using pki::log::Level;
    if      (s == "debug") pki::log::set_level(Level::Debug);
    else if (s == "info")  pki::log::set_level(Level::Info);
    else                   pki::log::set_level(Level::Err);
}

std::unique_ptr<pki::Db> open_db(const pki::Config& c) {
    return pki::make_postgres_db(c.pg_conninfo);
}

} // namespace

int main(int argc, char** argv) {
    if (pki::handled_version_flag(argc, argv)) return 0;
    std::string conf_path = "config/bootstrap.conf";
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) conf_path = argv[++i];
        else if (std::strcmp(argv[i], "--help") == 0) {
            std::cout << "Usage: fastpki-ocsp [--config path]\n";
            return 0;
        }
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    try {
        auto cfg = pki::Config::load(conf_path);
        auto db = open_db(cfg);
        pki::overlay_config(cfg, db->get_config());   // DB config overlay
        set_log_level_from_string(cfg.log_level);

        // No global/default responder — each CA's responder is built lazily from
        // its registered CA in pick_responder below.

        // Periodic expired-cert sweep: mark already-expired certs in
        // a background thread instead of on every OCSP request. Detached — it
        // runs for the process lifetime (the server below blocks forever). The
        // Db methods are mutex-guarded, so this is safe alongside request threads.
        if (cfg.ocsp_expiry_sweep_sec > 0) {
            pki::Db* dbp = db.get();
            int interval = cfg.ocsp_expiry_sweep_sec;
            std::thread([dbp, interval]() {
                for (;;) {
                    std::this_thread::sleep_for(std::chrono::seconds(interval));
                    try { dbp->mark_expired_now(); }
                    catch (const std::exception& e) {
                        pki::log::err(std::string("OCSP expiry sweep failed: ") + e.what());
                    }
                }
            }).detach();
            pki::log::info("OCSP expiry sweep every " + std::to_string(interval) + "s");
        }

        // Every CA (including the bootstrap SIGNING_CA) is a registered instance,
        // so CRLs — base and per-CA alike — are signed with the resolved instance's
        // material via pick_responder. No standalone global CA material is loaded here.
        pki::CrlCache crl_cache(cfg.crl_cache_ttl_sec);

        // Publish every local CA's CRL on a timer, so a peer can still answer for that CA
        // after the node holding its key is gone. The CRL bytes replicate through the mesh
        // (the `crls` table is in the publication), and all three serving paths already
        // prefer a stored CRL before refusing — so this is the piece that was missing.
        //
        // ⚠️ IT CANNOT BE LEFT TO REQUEST TRAFFIC. Storing a CRL whenever one happens to be
        // generated only ever covers CAs somebody fetched from THIS node while it was still
        // up, and the situation this exists for is a node that has stopped answering. A CA
        // nobody happened to query here would replicate nothing and go dark exactly as
        // before — the quiet CAs being the ones most likely to be missed.
        //
        // It goes through crl_cache rather than generate_crl so there is ONE path: the
        // cache decides freshness, emits the lifecycle audit event, and calls
        // publish_generated_crl, which in turn writes only when the revocations changed or
        // the stored copy is half-expired. A quiet CA therefore costs one signature per
        // sweep and no replication traffic at all.
        if (cfg.crl_publish_sweep_sec > 0) {
            pki::Db* dbp = db.get();
            const pki::Config* cfgp = &cfg;
            pki::CrlCache* cachep = &crl_cache;
            int interval = cfg.crl_publish_sweep_sec;
            std::thread([dbp, cfgp, cachep, interval]() {
                pki::CaMaterialCache mats;
                for (;;) {
                    std::this_thread::sleep_for(std::chrono::seconds(interval));
                    try {
                        for (const auto& ca : dbp->list_ca_instances()) {
                            int st = 0;
                            std::string msg;
                            auto m = mats.get(*dbp, *cfgp, ca.id, st, msg);
                            // No local key, disabled, or unloadable material: not this
                            // node's CA to sign for. Silent — on a mesh peer that is the
                            // ordinary state of most CAs, not a fault.
                            if (!m || !m->key || !m->cert) continue;
                            try {
                                cachep->get(*cfgp, *dbp, m->cert.get(), m->key.get(), ca.id);
                            } catch (const std::exception& e) {
                                // The sweep signs with the same token key the routes do, so
                                // it meets a dead session the same way — and it is often
                                // FIRST, since it runs whether or not anyone is fetching.
                                // Exiting here is what gets the process a live session back;
                                // logging alone leaves every CA's published CRL to go stale
                                // while the node looks healthy.
                                pki::exit_if_token_died(m->key.get(),
                                                        "fastpki-ocsp CRL publication sweep");
                                pki::log::err("CRL publication sweep, CA '" + ca.id +
                                              "': " + e.what());
                            }
                        }
                    } catch (const std::exception& e) {
                        pki::log::err(std::string("CRL publication sweep failed: ") + e.what());
                    }
                }
            }).detach();
            pki::log::info("CRL publication sweep every " +
                           std::to_string(interval) + "s");
        }

        httplib::Server srv;
        srv.set_payload_max_length(64 * 1024); // OCSP requests are small

        // NB: the base (no-id) CRL route is registered further down, after
        // pick_responder is defined — it serves the request tenant's first
        // CA's CRL, resolved the same way the per-CA route does.

        // Per-CA responders: one fastpki-ocsp answers for multiple CA
        // instances under /ocsp/{id} (trailing segment, consistent with CMP's
        // /cmp/{id} and SCEP's <scep_path>/{id}), each response signed
        // by THAT instance's CA so a tenant client (which trusts its own CA) can
        // verify it. Instance responders are built lazily and cached.
        std::mutex resp_mu;
        // ⚠️ KEYED ON THE MATERIAL, NOT JUST THE ID, BECAUSE A CA CAN BE RE-KEYED. This was
        // keyed on the id alone and never invalidated, so a responder built from generation 1
        // was reused for the process lifetime: after a rekey, OCSP responses and every CRL
        // regenerated through this responder were signed with the OLD key and carried the old
        // authorityKeyIdentifier, while the CA served the new certificate. A relying party
        // then cannot match the signature to any published CA certificate.
        //
        // CaMaterialCache beside it already does exactly this, tracking cert_ref and chain_ref
        // and reloading when either moves; the responder cache simply did not. Same signal:
        // the serial moves when a rekey adds a certificate, and the joined chain serials also
        // move when the old one expires out of the set, which the leaf serial alone cannot see.
        // ⚠️ shared_ptr, NOT unique_ptr, BECAUSE THE POINTER OUTLIVES THE LOCK. pick_responder
        // takes resp_mu, finds-or-builds, and RETURNS — releasing the lock — and the caller
        // then uses the responder for the length of a request: a DB scan, a CRL generation, a
        // token signature. resp_mu protects the MAP, never the lifetime of what it points at.
        //
        // So anything that removes an entry frees an object other threads are still inside.
        // With unique_ptr both removal paths did exactly that: the rekey eviction below
        // (erase on a changed mat_ref) and the responder-key watcher's clear(). The result is
        // a use-after-free on ca_cert_/ca_key_/responder_key_, whose raw pointers the
        // Responder hands out — worst under load, because that is when a request is most
        // likely to be in flight while the material changes.
        //
        // A shared_ptr makes removal mean "stop handing this out": in-flight requests keep
        // the object alive and the last one to finish destroys it.
        std::map<std::string, std::shared_ptr<pki::ocsp::Responder>> inst_resp;
        std::map<std::string, std::string> inst_resp_ref;   // id -> material reference
        // ⚠️ AND REBUILD WHEN THE RESPONDER CREDENTIAL ARRIVES, which mat_ref above cannot
        // see. It tracks the CA's material — cert serial, chain, key — and a Responder
        // loads OCSP_RESPONDER_KEY separately, in its constructor. A node whose token did
        // not hold that key yet cached the absence for the life of the process: measured on
        // a promoted HA standby, `fastpki-ca key sync` replicated the key and OCSP went on
        // answering that the CA "cannot answer OCSP here" until somebody restarted it.
        // Unlike SCEP there is no fallback to hide it — a responder never signs with the CA
        // key, deliberately — so the CA simply stops answering.
        //
        // Dropping the cache is the whole fix: the next request rebuilds each Responder,
        // whose constructor loads the key that now exists. Nothing live is mutated, and the
        // lock the cache already has is the only synchronisation needed. The watcher exits
        // on the first success, so a node that started with the key carries no thread.
        if (!cfg.ocsp_responder_key.empty()) {
            bool have_key = false;
            try {
                have_key = static_cast<bool>(
                    pki::load_key_file_or_token(cfg.ocsp_responder_key.string(), cfg));
            } catch (...) { have_key = false; }
            if (!have_key)
                pki::watch_for_ra_key(
                    cfg.ocsp_responder_key.string(), cfg, "OCSP",
                    [rmu = &resp_mu, ir = &inst_resp, irr = &inst_resp_ref](pki::EvpPkeyPtr) {
                        std::lock_guard<std::mutex> lk(*rmu);
                        ir->clear();
                        irr->clear();
                        pki::log::info("OCSP: the responder key appeared in this node's token "
                                       "— cached responders dropped, so the next request "
                                       "rebuilds with it. No restart was needed.");
                    });
        }
        // ⚠️ `require_active` exists because DISABLING A CA MUST NOT WITHDRAW ITS
        // REVOCATION INFORMATION. Reported as:
        //     curl -k http://localhost:8080/root-ca.crl  ->  CA instance disabled
        //
        // An offline root is the RECOMMENDED posture, and "disabled" is how an operator
        // expresses it. Refusing the CRL then makes every certificate that root ever
        // signed unverifiable — the failure is worst exactly when the CA is most locked
        // down, which is backwards. And a revoked certificate whose CRL 503s reads to a
        // relying party as "cannot determine", i.e. the revocation silently stops
        // counting.
        //
        // Disabling stops ISSUANCE — the enrolment paths resolve through
        // CaMaterialCache, which still refuses an inactive CA, so nothing new is signed.
        // Publishing what was already decided is a different act and stays available.
        auto pick_responder = [&](const std::string& id, const std::string& host,
                                  httplib::Response& res,
                                  std::string* resolved_id = nullptr,
                                  bool require_active = true) -> std::shared_ptr<pki::ocsp::Responder> {
            // Every responder must name a real per-tenant CA.
            auto rc = pki::resolve_ca_instance(*db, cfg, id);
            // A /{ca_id} route is honoured only for a CA of the request's tenant.
            if (!rc.found)
                { res.status = 404; res.set_content("unknown CA instance", "text/plain"); return nullptr; }
            if (require_active && !rc.active)
                // A mesh peer holds every CA's certificate and only its own CA's key,
                // so "disabled" was the wrong word about two CAs in three.
                { res.status = 503; res.set_content(pki::ca_unavailable_reason(rc), "text/plain"); return nullptr; }
            if (resolved_id) *resolved_id = rc.id;
            // No global responder — every CA has its own, built from its
            // CA cert (DER from DB certs table) + key ref, cached by id.
            std::lock_guard<std::mutex> lk(resp_mu);
            // The reference this responder was built from. Rebuild when it moves.
            const std::string mat_ref = rc.cert_serial + "|" + rc.chain_ref + "|" + rc.key;
            auto rit = inst_resp_ref.find(rc.id);
            if (rit != inst_resp_ref.end() && rit->second != mat_ref) {
                pki::log::info("OCSP instance '" + rc.id + "': CA material changed — "
                               "rebuilding the responder");
                inst_resp.erase(rc.id);
                inst_resp_ref.erase(rit);
            }
            auto it = inst_resp.find(rc.id);
            if (it == inst_resp.end()) {
                try {
                    inst_resp_ref[rc.id] = mat_ref;
                    it = inst_resp.emplace(rc.id,
                             std::make_shared<pki::ocsp::Responder>(cfg, *db, rc.id,
                                 std::vector<unsigned char>(rc.cert_der), rc.key,
                                 rc.chain_ders)).first;
                } catch (const std::exception& e) {
                    pki::log::err(std::string("OCSP instance '") + rc.id + "': " + e.what());
                    res.status = 500; res.set_content("CA material unavailable", "text/plain");
                    return nullptr;
                }
            }
            return it->second;
        };

        // Every issued cert's AIA points at the SHARED /ocsp, so the responder must
        // pick its signer from the REQUESTED cert rather than the URL: parse the
        // request's CertID and match its issuer (name+key hash, under whatever digest
        // the client used) against the CAs of the Host header's tenant. Falls back to
        // the tenant's first CA when nothing matches, so an unknown issuer still gets a
        // properly signed "unknown" rather than a wrong-signer response.
        auto responder_for_request = [&](const std::string& host, const std::string& body,
                                         httplib::Response& res) -> std::shared_ptr<pki::ocsp::Responder> {
            std::string want;
            bool parsed = false;
            const unsigned char* p = reinterpret_cast<const unsigned char*>(body.data());
            std::unique_ptr<OCSP_REQUEST, decltype(&OCSP_REQUEST_free)>
                reqo(d2i_OCSP_REQUEST(nullptr, &p, static_cast<long>(body.size())), &OCSP_REQUEST_free);
            if (reqo && OCSP_request_onereq_count(reqo.get()) > 0) {
                parsed = true;
                OCSP_ONEREQ*  one = OCSP_request_onereq_get0(reqo.get(), 0);
                OCSP_CERTID*  cid = one ? OCSP_onereq_get0_id(one) : nullptr;
                ASN1_OBJECT*  alg = nullptr;
                if (cid && OCSP_id_get0_info(nullptr, &alg, nullptr, nullptr, cid)) {
                    if (const EVP_MD* md = EVP_get_digestbyobj(alg)) {
                        for (const auto& ci : db->list_ca_instances()) {
                            // ⚠️ A DISABLED CA is still matched here. This loop only
                            // asks "who signed the certificate in the question?", and that
                            // is a fact about the past — disabling the CA does not unsign
                            // anything. Skipping it made the shared /ocsp answer
                            // `unauthorized` for every certificate an offline root ever
                            // issued, which a relying party reads as "cannot determine"
                            // and is therefore worse for a REVOKED certificate than for a
                            // good one. Refusing to ISSUE is enforced elsewhere
                            // (CaMaterialCache); this route issues nothing.
                            // Load CA cert via resolve_ca_instance (DB first, file fallback)
                            auto rc = pki::resolve_ca_instance(*db, cfg, ci.id);
                            if (!rc.found) continue;
                            // ⚠️ EVERY LIVE GENERATION, NOT JUST THE NEWEST. cert_der is the
                            // certificate this CA currently SIGNS with; a certificate issued
                            // before a re-key carries a CertID whose issuerKeyHash names the
                            // OLD generation, so matching cert_der alone answered
                            // `unauthorized` for everything issued before the rollover — and
                            // a relying party reads that as "cannot determine", which is
                            // worse for a REVOKED certificate than for a good one. chain_ders
                            // is exactly the set of live certificates for this CA (both
                            // generations during a rollover), which is what the question
                            // "who signed this?" has to be asked against.
                            std::vector<const std::vector<unsigned char>*> gens;
                            if (!rc.cert_der.empty()) gens.push_back(&rc.cert_der);
                            for (const auto& d : rc.chain_ders)
                                if (!d.empty() && &d != &rc.cert_der) gens.push_back(&d);
                            if (gens.empty()) continue;
                            bool matched = false;
                            for (const auto* der : gens) {
                                try {
                                    const unsigned char* pp = der->data();
                                    pki::X509Ptr cacert{d2i_X509(nullptr, &pp,
                                        static_cast<long>(der->size()))};
                                    if (!cacert) continue;
                                    std::unique_ptr<OCSP_CERTID, decltype(&OCSP_CERTID_free)>
                                        cand(OCSP_cert_to_id(md, nullptr, cacert.get()), &OCSP_CERTID_free);
                                    if (cand && OCSP_id_issuer_cmp(cand.get(), cid) == 0) {
                                        want = ci.id; matched = true; break;
                                    }
                                } catch (const std::exception&) { /* unreadable — skip */ }
                            }
                            if (matched) break;
                        }
                    }
                }
            }
            // No default responder. An unparseable request, or an issuer that no
            // hosted CA matches, has no signer here — return an unsigned "unauthorized"
            // OCSP response (RFC 6960 §2.3) rather than guessing a CA / wrong signer.
            if (want.empty()) {
                // RFC 6960 §2.3: unparseable request → malformedRequest; parsed but
                // no matching issuer → unauthorized.
                auto status = parsed ? OCSP_RESPONSE_STATUS_UNAUTHORIZED
                                     : OCSP_RESPONSE_STATUS_MALFORMEDREQUEST;
                OCSP_RESPONSE* ur = OCSP_response_create(status, nullptr);
                if (ur) {
                    int len = i2d_OCSP_RESPONSE(ur, nullptr);
                    std::string out(len > 0 ? static_cast<size_t>(len) : 0, '\0');
                    if (len > 0) { auto* pp = reinterpret_cast<unsigned char*>(out.data()); i2d_OCSP_RESPONSE(ur, &pp); }
                    OCSP_RESPONSE_free(ur);
                    res.status = 200; res.set_content(out, "application/ocsp-response");
                } else { res.status = 500; }
                return nullptr;
            }
            return pick_responder(want, host, res, nullptr, /*require_active=*/false);
        };

        // GET <crl_path>/{id} — the tenant's CRL: its own revoked certs,
        // signed by its CA, cached per instance. Trailing segment, matching the
        // OCSP/CMP/SCEP tenant style.
        srv.Get(cfg.crl_path + R"(/([^/]+))",
                [&](const httplib::Request& req, httplib::Response& res) {
            std::string iid;
            // A disabled CA still publishes its CRL — see pick_responder. This is
            // the SECOND route that serves one; patching only /{ca_id}.crl left an
            // offline root refusing its CRL here, on the same daemon, for the same reason.
            auto r = pick_responder(req.matches[1].str(), req.get_header_value("Host"), res, &iid,
                                     /*require_active=*/false);
            if (!r) return;   // 404/503/500 already set
            if (!r->ca_key()) {   // remote CA key — CRL signing isn't available
                // Before refusing, is there a CRL the offline root signed
                // elsewhere and an operator imported? That is the whole point of the
                // table — this deployment cannot sign for that CA, but it can publish.
                {
                    std::string stale;
                    if (auto stored = pki::imported_crl(*db, iid, /*is_delta=*/false, stale)) {
                        if (!stale.empty()) pki::log::err(stale);
                        // ⚠️ SAY SO EVEN WHEN THE STORED CRL IS FRESH. Serving it is right —
                        // a CA that cannot sign should still publish the last CRL it signed,
                        // and 503 with valid bytes in hand fails revocation closed for no
                        // reason. But this used to be the ONLY signal that a CA's key is not
                        // reachable from this node, and a mistyped pkcs11: handle now looks
                        // identical to a healthy CA at this endpoint. The operator still has
                        // to be able to find out, so the fallback is never silent.
                        pki::log::info("CRL for CA '" + iid + "': the signing key is not "
                                       "usable here (" +
                                       (r->ca_key_why().empty() ? std::string("no local key")
                                                                : r->ca_key_why()) +
                                       ") — serving the stored CRL instead");
                        res.status = 200;
                        res.set_content(std::string(stored->begin(), stored->end()),
                                        "application/pkix-crl");
                        return;
                    }
                }
                res.status = 503;
                res.set_content("CRL unavailable: " +
                                (r->ca_key_why().empty()
                                     ? std::string("the CA signing key is remote")
                                     : r->ca_key_why()), "text/plain");
                return;
            }
            int64_t base = 0;
            if (cfg.crl_delta_enabled && req.has_param("base")) {
                try { base = std::stoll(req.get_param_value("base")); } catch (...) { base = 0; }
            }
            try {
                auto der = base > 0
                    ? pki::generate_crl(cfg, *db, r->ca_cert(), r->ca_key(), iid, base)
                    : crl_cache.get(cfg, *db, r->ca_cert(), r->ca_key(), iid);
                res.status = 200;
                res.set_header("Cache-Control", "no-cache");
                res.set_content(std::string(der.begin(), der.end()), "application/pkix-crl");
            } catch (const std::exception& e) {
                // ⚠️ ASK WHETHER THE TOKEN DIED, exactly as response signing does. Without
                // this a dead provider session makes every CRL a 500 FOR EVER: fastpki-ocsp
                // passes no key handle to gate_protocol, so it has no liveness probe of its
                // own, and this path just logged and returned. Measured on a promoted node —
                // 40 minutes of "X509_CRL_sign failed: pkcs11::Some problem has occurred
                // with the token and/or slot", every relying party failing CRL checks, and
                // nothing exiting to get a fresh session. Response signing had the check;
                // CRL generation, which uses the same CA key, did not.
                pki::exit_if_token_died(r->ca_key(), "fastpki-ocsp CRL signing");
                pki::log::err(std::string("CRL generation error (instance '") + iid + "'): " + e.what());
                res.status = 500;
            }
        });

        // GET <crl_path> — the id-less alias. It 404s: the canonical URL is
        // /{ca_id}.crl. Nothing is guessed here — we never try to work out a
        // "first CA", which a root + subCA hierarchy makes ambiguous anyway.
        srv.Get(cfg.crl_path, [&](const httplib::Request&, httplib::Response& res) {
            // No default CA — the CRL is per-CA at /{ca_id}.crl; the id-less alias 404s.
            res.status = 404; res.set_content("use /{ca_id}.crl", "text/plain");
        });

        // The canonical per-CA URLs baked into issued certs — every CA has a real
        // id, so these always name it (no /{sn} fallback). Plain HTTP: a relying party
        // fetching a CRL / CA cert must not need TLS. The legacy <crl_path> routes above
        // stay for certs already issued against them.
        //
        // GET /{ca_id}.crl — this CA's CRL (the CRLDP target).
        srv.Get(R"(/([A-Za-z0-9_.\-]+)\.crl)", [&](const httplib::Request& req, httplib::Response& res) {
            std::string iid;
            // A disabled CA still publishes its CRL — see pick_responder.
            auto r = pick_responder(req.matches[1].str(), req.get_header_value("Host"), res, &iid,
                                     /*require_active=*/false);
            if (!r) return;   // 404/500 already set
            if (!r->ca_key()) {
                // Publish an imported CRL here too. Patching only the other route
                // left this one refusing the same CA on the same daemon — exactly the
                // mistake the comment above records for the disabled-CA case.
                {
                    std::string stale;
                    if (auto stored = pki::imported_crl(*db, iid, /*is_delta=*/false, stale)) {
                        if (!stale.empty()) pki::log::err(stale);
                        // ⚠️ SAY SO EVEN WHEN THE STORED CRL IS FRESH. Serving it is right —
                        // a CA that cannot sign should still publish the last CRL it signed,
                        // and 503 with valid bytes in hand fails revocation closed for no
                        // reason. But this used to be the ONLY signal that a CA's key is not
                        // reachable from this node, and a mistyped pkcs11: handle now looks
                        // identical to a healthy CA at this endpoint. The operator still has
                        // to be able to find out, so the fallback is never silent.
                        pki::log::info("CRL for CA '" + iid + "': the signing key is not "
                                       "usable here (" +
                                       (r->ca_key_why().empty() ? std::string("no local key")
                                                                : r->ca_key_why()) +
                                       ") — serving the stored CRL instead");
                        res.status = 200;
                        res.set_content(std::string(stored->begin(), stored->end()),
                                        "application/pkix-crl");
                        return;
                    }
                }
                res.status = 503;
                res.set_content("CRL unavailable: " +
                                (r->ca_key_why().empty()
                                     ? std::string("the CA signing key is remote")
                                     : r->ca_key_why()), "text/plain");
                return;
            }
            int64_t base = 0;
            if (cfg.crl_delta_enabled && req.has_param("base")) {
                try { base = std::stoll(req.get_param_value("base")); } catch (...) { base = 0; }
            }
            try {
                auto der = base > 0
                    ? pki::generate_crl(cfg, *db, r->ca_cert(), r->ca_key(), iid, base)
                    : crl_cache.get(cfg, *db, r->ca_cert(), r->ca_key(), iid);
                res.status = 200;
                res.set_header("Cache-Control", "no-cache");
                res.set_content(std::string(der.begin(), der.end()), "application/pkix-crl");
            } catch (const std::exception& e) {
                // Same as the instance route above: a dead session must exit for a fresh
                // one, not serve 500 until somebody notices.
                pki::exit_if_token_died(r->ca_key(), "fastpki-ocsp CRL signing");
                pki::log::err(std::string("CRL generation error ('") + iid + ".crl'): " + e.what());
                res.status = 500;
            }
        });
        // GET /{ca_id}.crt — this CA's certificate in DER (the AIA caIssuers target).
        // ── the GENERATION-QUALIFIED caIssuers target ──────────────────────────
        // /{ca_id}/{ski}.crt — serve EXACTLY the generation whose subjectKeyIdentifier is
        // named, with no heuristic at all.
        //
        // {ca_id} may not appear in cAIssuers and CRLDP links on its own: it is a prefix
        // or path, with a unique piece beside it that identifies the CA key GENERATION.
        //
        // ⚠️ WHY THIS ROUTE EXISTS AT ALL — two needs are one impossibility. After a
        // rekey the flat /{ca_id}.crt has to answer two incompatible questions with one
        // file: chain-building wants the PARENT-signed certificate (or the new generation has
        // no path UP to the root) and publication wants the SIGNING certificate (or the served cert cannot
        // chain the leaves this CA issues today). Naming the generation makes both
        // answerable, so this route needs no "pick" logic — the URL already said which one.
        //
        // A leaf's authorityKeyIdentifier.keyid IS its signer's SKI, so a client that holds
        // the leaf can construct this URL without a lookup. The flat route below is left
        // exactly as it was, for certificates issued before this shipped.
        //
        // ⚠️ A BUNDLE, NOT THE LONE GENERATION — and .p7c, not .crt. Measured on the live
        // dc1 while checking the Windows chain: following the qualified URL got the
        // right intermediate and then had NOWHERE TO GO. A rekeyed generation is
        // self-issued but NOT self-signed, it publishes no AIA of its own, and its subject
        // and issuer names are identical, so nothing in it tells a client where g1 lives:
        //
        //     root + g2        -> unable to get local issuer certificate
        //     root + g2 + g1   -> leaf.pem: OK
        //
        // It has to be a BUNDLE, and the extension and MIME content type differ from a
        // single certificate's — easy to forget when serving it.
        // RFC 5280 §4.2.2.1 says exactly that: a single certificate is application/pkix-cert
        // (.cer/.crt); a collection is a certs-only PKCS#7, application/pkcs7-mime, .p7c.
        //
        // The bundle is every live generation of THIS CA, named one first. It deliberately
        // stops there: the root is what the operator put in the trusted store, and a deeper
        // hierarchy walks one hop at a time because each intermediate's own AIA points at
        // its own bundle. That is the property per-generation URLs were chosen for.
        srv.Get(R"(/([A-Za-z0-9_.\-]+)/([0-9a-f]{8,80})\.p7c)", [&](const httplib::Request& req, httplib::Response& res) {
            const std::string id  = req.matches[1].str();
            const std::string ski = req.matches[2].str();
            auto rc = pki::resolve_ca_instance(*db, cfg, id);
            if (!rc.found)
                { res.status = 404; res.set_content("unknown CA instance", "text/plain"); return; }
            try {
                // Every live generation, newest first — the rekey rollover set. cert_der is
                // chain_ders.front() when the chain is populated, so de-duplicate by SKI
                // rather than pushing it unconditionally.
                std::vector<const std::vector<unsigned char>*> all;
                if (!rc.cert_der.empty()) all.push_back(&rc.cert_der);
                for (const auto& der : rc.chain_ders) {
                    bool dup = false;
                    for (const auto* have : all) if (*have == der) { dup = true; break; }
                    if (!dup) all.push_back(&der);
                }
                // Named generation first, the rest after it — a bag has no required order,
                // but a human reading the response should see what they asked for on top.
                std::vector<const std::vector<unsigned char>*> ordered;
                for (const auto* der : all) if (pki::cert_ski_hex(*der) == ski) ordered.push_back(der);
                if (ordered.empty()) {
                    // ⚠️ 404, NOT a fallback to some other generation. A client asked for a
                    // specific key; handing it a different one is the very substitution this
                    // ticket is about, and it would fail signature verification anyway —
                    // later, and less legibly.
                    res.status = 404;
                    res.set_content("no such CA key generation", "text/plain");
                    return;
                }
                for (const auto* der : all) if (pki::cert_ski_hex(*der) != ski) ordered.push_back(der);

                std::vector<pki::X509Ptr> keep;
                std::vector<X509*> certs;
                for (const auto* der : ordered) {
                    auto c = pki::parse_cert_der(*der);
                    if (!c) continue;
                    certs.push_back(c.get());
                    keep.push_back(std::move(c));
                }
                if (certs.empty()) throw std::runtime_error("no parsable CA certificate");
                const auto p7 = pki::pkcs7_certs_only(certs);
                res.status = 200;
                res.set_header("Cache-Control", "no-cache");
                res.set_content(std::string(p7.begin(), p7.end()), "application/pkcs7-mime");
            } catch (const std::exception& e) {
                pki::log::err("CA bundle fetch ('" + id + "/" + ski + ".p7c'): " + e.what());
                res.status = 500; res.set_content("CA material unavailable", "text/plain");
            }
        });
        srv.Get(R"(/([A-Za-z0-9_.\-]+)\.crt)", [&](const httplib::Request& req, httplib::Response& res) {
            const std::string id = req.matches[1].str();
            auto rc = pki::resolve_ca_instance(*db, cfg, id);
            if (!rc.found)
                { res.status = 404; res.set_content("unknown CA instance", "text/plain"); return; }
            try {
                // Serve the DER cert directly from DB (no PEM→X509→DER roundtrip)
                if (rc.cert_der.empty())
                    throw std::runtime_error("CA cert DER empty");
                // ⚠️ SERVE THE CERTIFICATE THAT CHAINS TO THE PARENT, not simply the
                // newest. A CA's live generations can include a SELF-ISSUED one — a
                // certificate for its key signed by its own previous key, as a root's bridge
                // is, or as an imported CA's may be — which carries no AIA of its own. A
                // client that fetched that one got no pointer any further up, so nothing
                // could build a path to the root: OCSP answers for perfectly good
                // certificates failed to verify.
                //
                // caIssuers means "where to get the issuer's certificate", so the right
                // answer is the newest one an issuer above actually signed.
                //
                // ⚠️ Comparing NAMES is correct here and only here. A rekeyed CA's
                // self-issued certificate has subject == issuer while NOT being
                // self-signed, so a name match must never be read as "this is a root" — and it
                // is not read that way: when nothing in the chain has a different issuer
                // this falls back to cert_der, which is the right answer for a real root
                // and a harmless one for anything else.
                const std::vector<unsigned char>* serve = &rc.cert_der;
                for (const auto& der : rc.chain_ders) {
                    auto c = pki::parse_cert_der(der);
                    if (!c) continue;
                    if (X509_NAME_cmp(X509_get_subject_name(c.get()),
                                      X509_get_issuer_name(c.get())) != 0) { serve = &der; break; }
                }
                res.status = 200;
                res.set_header("Cache-Control", "no-cache");
                res.set_content(std::string(serve->begin(), serve->end()),
                                "application/pkix-cert");
            } catch (const std::exception& e) {
                pki::log::err(std::string("CA cert fetch ('") + id + ".crt'): " + e.what());
                res.status = 500; res.set_content("CA material unavailable", "text/plain");
            }
        });

        // POST /ocsp  (and the legacy / endpoint for compatibility with PHP)
        auto do_post = [&](pki::ocsp::Responder& r, const httplib::Request& req, httplib::Response& res) {
            auto out = r.handle(
                reinterpret_cast<const unsigned char*>(req.body.data()),
                req.body.size());
            res.status = 200;
            res.set_header("Cache-Control", "no-cache");
            res.set_header("Pragma", "no-cache");
            res.set_content(std::string(out.begin(), out.end()),
                            "application/ocsp-response");
        };
        // The shared per-tenant responder — the signer is chosen from the requested
        // cert, so one path serves every CA of the tenant (this is the AIA OCSP target).
        srv.Post("/ocsp", [&](const httplib::Request& req, httplib::Response& res) {
            if (req.get_header_value("Content-Type") != "application/ocsp-request")
                { res.status = 415; res.set_content("expected application/ocsp-request", "text/plain"); return; }
            if (auto r = responder_for_request(req.get_header_value("Host"), req.body, res)) do_post(*r, req, res); });
        srv.Post("/",     [&](const httplib::Request& req, httplib::Response& res) {
            if (req.get_header_value("Content-Type") != "application/ocsp-request")
                { res.status = 415; res.set_content("expected application/ocsp-request", "text/plain"); return; }
            if (auto r = responder_for_request(req.get_header_value("Host"), req.body, res)) do_post(*r, req, res); });
        // POST /ocsp/{id} — tenant responder, trailing segment.
        srv.Post(R"(/ocsp/([^/]+))", [&](const httplib::Request& req, httplib::Response& res) {
            // Same reasoning as the CRL — a relying party asking about a certificate
            // signed by a now-disabled CA needs an answer. Refusing turns "revoked" into
            // "cannot determine", which is the one outcome revocation exists to prevent.
            if (auto r = pick_responder(req.matches[1].str(), req.get_header_value("Host"), res,
                                         nullptr, /*require_active=*/false)) do_post(*r, req, res);
        });

        // GET /ocsp/<base64-url-encoded-request>  — RFC 6960 §A.1. The GET form
        // base64-encodes the DER request as the last path segment; decode it to DER so
        // both the responder selection and the handler can use it. "" = malformed.
        auto get_req_der = [](const httplib::Request& req) -> std::string {
            auto pos = req.path.find_last_of('/');
            std::string b64 = (pos == std::string::npos) ? req.path : req.path.substr(pos + 1);
            // URL-decode '%' sequences (httplib gives us the raw path).
            std::string decoded;
            decoded.reserve(b64.size());
            // ⚠️ NO std::stoi HERE. It throws std::invalid_argument on a non-hex pair, and
            // this lambda is contracted to return "" for anything malformed — so `%zz` in
            // the path escaped as an exception and the client got 500 (a server fault)
            // instead of 400 (your request is wrong). Fold the nibbles by hand and treat a
            // bad escape as what it is: not a percent-escape, so it stays literal and the
            // base64 decode below rejects it the ordinary way.
            auto nib = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            for (size_t i = 0; i < b64.size(); ++i) {
                int hi = -1, lo = -1;
                if (b64[i] == '%' && i + 2 < b64.size() &&
                    (hi = nib(b64[i + 1])) >= 0 && (lo = nib(b64[i + 2])) >= 0) {
                    decoded.push_back(static_cast<char>((hi << 4) | lo));
                    i += 2;
                } else decoded.push_back(b64[i]);
            }
            // Base64 decode via OpenSSL's bio chain.
            BIO* b64bio = BIO_new(BIO_f_base64());
            BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);
            BIO* mem = BIO_new_mem_buf(decoded.data(), static_cast<int>(decoded.size()));
            b64bio = BIO_push(b64bio, mem);
            std::vector<unsigned char> der(decoded.size());
            int n = BIO_read(b64bio, der.data(), static_cast<int>(der.size()));
            BIO_free_all(b64bio);
            if (n <= 0) return {};
            return std::string(reinterpret_cast<const char*>(der.data()), static_cast<size_t>(n));
        };
        auto do_get = [&](pki::ocsp::Responder& r, const httplib::Request& req, httplib::Response& res) {
            const std::string der = get_req_der(req);
            if (der.empty()) { res.status = 400; return; }
            auto out = r.handle(reinterpret_cast<const unsigned char*>(der.data()), der.size());
            res.status = 200;
            res.set_header("Cache-Control", "no-cache");
            res.set_header("Pragma", "no-cache");
            res.set_content(std::string(out.begin(), out.end()),
                            "application/ocsp-response");
        };
        // GET /ocsp/{id}/{b64} — tenant responder: id + the base64 request.
        // Registered before the global single-segment form so it wins the 2-segment
        // path. do_get takes the last path segment as the b64, so it needs no change.
        srv.Get(R"(/ocsp/([^/]+)/.+)", [&](const httplib::Request& req, httplib::Response& res) {
            if (auto r = pick_responder(req.matches[1].str(), req.get_header_value("Host"), res,
                                         nullptr, /*require_active=*/false)) do_get(*r, req, res);
        });
        // GET /ocsp/{b64} — global, single segment (tightened from /ocsp/.* so it no
        // longer swallows the tenant path above). The b64 is percent-encoded by
        // compliant clients (RFC 6960 §A.1), so it carries no literal '/'.
        srv.Get(R"(/ocsp/[^/]+)", [&](const httplib::Request& req, httplib::Response& res) {
            // Same shared-responder selection as the POST form.
            if (auto r = responder_for_request(req.get_header_value("Host"), get_req_der(req), res))
                do_get(*r, req, res); });

        // Never open the port while this protocol is switched off in the
        // console, and stop if it is switched off later.
        pki::gate_protocol(*db, "ocsp");
        std::string bound;
        if (!pki::bind_listener(srv, cfg.ocsp_bind_addr, cfg.ocsp_port, bound)) {
            std::cerr << "listen failed\n";
            return 1;
        }
        // Logged AFTER the bind, and it names what was actually bound: the wildcard can
        // fall back to IPv4 on a host with no IPv6 stack, and a line printed beforehand
        // would have announced an address this process is not serving.
        pki::log::info("fastpki-ocsp listening on " + bound + ":" +
                       std::to_string(cfg.ocsp_port));
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
