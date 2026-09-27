#include "pki/ca_instance.hpp"
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/error.hpp"
#include "pki/log.hpp"
#include "pki/x509.hpp"   // CaUrls, derive_ca_urls, parse_cert_der, load_signing_key, load_cert_pem
#include <openssl/x509v3.h>
#include <openssl/ssl.h>   // install_client_trust configures the server SSL_CTX
#include <algorithm>
#include <cctype>
#include <ctime>
#include <fstream>
#include <mutex>
#include <set>
#include <sstream>

namespace pki {

namespace {

// ⚠️ THE PUBLIC NAME AS IT IS NOW, NOT AS IT WAS AT STARTUP.
//
// PKI_DNS and BASE_URL supply the host in every AIA and CRL distribution point a certificate
// carries, and those URLs are fixed the moment it is minted. Each service reads its Config
// once, at startup, so after `fastpki-config set PKI_DNS …` — or the console's Config page —
// every certificate issued until somebody restarts the listeners went on naming the OLD host,
// silently. An operator correcting the deployment's public name would fix the setting, watch
// new certificates keep the old URLs, and have nothing to tell them why.
//
// This is the same defect the ACME resolver had, and the same remedy: read it where it is
// used. The cost is proportionate — this function already reads the `datacenters` rows from
// the database on every issuance, so one more small read, cached for a few seconds, changes
// nothing about its shape.
//
// Best effort. A database that cannot be read here must not stop issuance; the startup value
// stands in, which is what it did before.
void refresh_issuance_host(Db& db, Config& c) {
    static std::mutex mu;
    static std::string cached_dns, cached_base;
    static std::time_t taken = 0;
    static bool have = false;
    const std::time_t now = std::time(nullptr);
    std::lock_guard<std::mutex> lk(mu);
    if (!have || now - taken >= 5) {
        try {
            const auto rows = db.get_config();
            const auto d = rows.find("PKI_DNS");
            const auto b = rows.find("BASE_URL");
            cached_dns  = (d != rows.end()) ? d->second : std::string();
            cached_base = (b != rows.end()) ? b->second : std::string();
            taken = now;
            have  = true;
        } catch (const std::exception& e) {
            log::debug(std::string("could not re-read PKI_DNS/BASE_URL (") + e.what() +
                       ") — using the values this process started with");
            return;
        }
    }
    // Only when the database actually carries one: an unset row must not blank a value the
    // file supplied, which is the overlay's rule everywhere else (config.cpp).
    if (!cached_dns.empty())  c.pki_dns  = cached_dns;
    if (!cached_base.empty()) c.base_url = cached_base;
}

}  // namespace

CaUrls ca_urls_for_instance(Db& db, const Config& cfg, const std::string& ca_id,
                            CaUrlScope scope) {
    Config live = cfg;
    refresh_issuance_host(db, live);
    CaUrls u = derive_ca_urls(live, ca_id);
    // ⚠️ EVERY OTHER DATA CENTER'S ADDRESS, ADDED BEFORE THE GENERATION QUALIFICATION
    // BELOW — so each entry gets the same treatment and a certificate never mixes a
    // qualified caIssuers URL for this node with flat ones for its peers.
    //
    // A certificate outlives the outage it has to survive and cannot be told a new URL
    // afterwards, so naming only the issuing node leaves a relying party with nowhere to
    // go when that node is down — and makes the CRLs every peer already replicates
    // unreachable in exactly the case they exist for.
    //
    // Best-effort: a database that cannot be read here must not stop issuance, and the
    // certificate then carries this node's URLs alone, which is what it carried before.
    // Our own row is skipped so the local entry stays first and unduplicated — this
    // node's BASE_URL and its datacenters row are two spellings of one address.
    // ⚠️ AND ONLY ONCE PER ADDRESS. Skipping our own row is not enough: under a single
    // round-robin name every data center's BASE_URL is the SAME string, so each peer
    // contributes another copy of the one address and the certificate ends up carrying the
    // identical CRLDP and caIssuers URI once per node — three times on a three-node mesh.
    // A relying party then makes the same fetch repeatedly before giving up, and the
    // extensions are that much larger for nothing. Compare the composed URL rather than the
    // data center id, because whether two rows name one address is a property of the
    // address and not of the ids.
    const auto add_once = [](std::vector<std::string>& v, std::string s) {
        if (std::find(v.begin(), v.end(), s) == v.end()) v.push_back(std::move(s));
    };
    try {
        const std::string self = cfg.datacenter_id;
        // A certificate this node issues to ITSELF names this node alone — see CaUrlScope.
        const auto peers = (scope == CaUrlScope::kThisNode)
                               ? std::vector<std::pair<std::string, std::string>>{}
                               : db.list_datacenter_base_urls();
        for (const auto& [dc, raw] : peers) {
            if (!self.empty() && dc == self) continue;
            std::string b = raw;
            while (!b.empty() && b.back() == '/') b.pop_back();
            if (b.empty()) continue;
            add_once(u.ca_issuers, b + "/" + ca_id + ".crt");
            // ⚠️ A PEER'S OCSP RESPONDER ONLY WHEN THE OPERATOR SAYS IT CAN ANSWER. The CRL
            // and the CA certificate replicate, so a peer serves copies of both. An OCSP
            // response is signed per request with that CA's ocsp-ra-<ca_id> private key, and
            // a peer holds that key only if somebody chose to replicate it — a policy
            // decision issuance must not assume. See Config::ocsp_responder_keys_replicated.
            if (cfg.ocsp_responder_keys_replicated) add_once(u.ocsp, b + "/ocsp");
            add_once(u.crl,        b + "/" + ca_id + ".crl");
        }
    } catch (const std::exception& e) {
        log::info(std::string("could not read peer base URLs for AIA/CRLDP (") + e.what() +
                  ") — this certificate names only this node");
    }
    // QUALIFY caIssuers AND CRLDP BY THE SIGNING GENERATION.
    //
    // The root cause is re-using {ca_id} for a re-keyed CA, so {ca_id} may not appear in
    // cAIssuers and CRLDP links on its own: it is a prefix or path, with a unique piece
    // beside it that identifies the CA key GENERATION.
    //
    // Rekeying leaves TWO live generations under one id. With one URL per id, a leaf
    // issued by g1 and a leaf issued by g2 carry identical AIA and CRLDP, and whatever
    // single certificate is served there is wrong for one of them:
    //   * chain-building needs the PARENT-signed g1, or the new generation has no path UP
    //   * publication needs the SIGNING generation, or the served cert cannot chain today's leaves
    // Those are two halves of one impossibility, which is why no single-certificate answer
    // at a shared URL is right. Per generation, both are satisfiable at once.
    //
    // ⚠️ THE TOKEN IS THE SIGNER'S SKI, and it is taken from the certificate that will
    // actually sign — get_ca_cert_der() returns the newest generation, the same one
    // issue_cert() uses. Deriving it from anything else would let the URL name a generation
    // different from the one that signed, which is precisely the defect being fixed.
    //
    // A CA whose certificate carries no SKID keeps the flat URLs: they still resolve, and
    // an un-fetchable qualified URL would be worse than an ambiguous one.
    if (auto info = db.get_ca_cert_der(ca_id)) {
        const std::string ski = cert_ski_hex(info->der);
        if (!ski.empty()) {
            const std::string flat_crt = "/" + ca_id + ".crt";
            // ⚠️ .p7c, NOT .crt — the qualified target is a BUNDLE. Measured on the lab:
            // the lone generation leaves an AIA-walking client one hop short, because a
            // rekeyed certificate is self-issued, publishes no AIA and is name-identical to
            // the generation that signed it. It has to be a BUNDLE — and the extension
            // and MIME content type differ from a single certificate's, which is easy to
            // forget when serving it. RFC 5280 §4.2.2.1: a collection is
            // a certs-only PKCS#7 — application/pkcs7-mime, .p7c.
            const std::string qual_crt = "/" + ca_id + "/" + ski + ".p7c";
            // Applied to EVERY entry: each data center's caIssuers URL ends in the same
            // /{ca_id}.crt, so the qualification is the same suffix swap on each.
            for (auto& ci_url : u.ca_issuers) {
                if (ci_url.size() >= flat_crt.size() &&
                    ci_url.compare(ci_url.size() - flat_crt.size(), flat_crt.size(), flat_crt) == 0)
                    ci_url.replace(ci_url.size() - flat_crt.size(), flat_crt.size(), qual_crt);
            }
            // ⚠️ CRLDP IS DELIBERATELY LEFT FLAT IN THIS SLICE, and that is not an oversight.
            //
            // These URLs are baked into a certificate and live as long as it does, so a
            // qualified CRLDP must not be emitted one commit before the route that answers
            // it exists — every certificate issued in between would carry a permanently
            // dangling CRL pointer, which is strictly worse than the ambiguity
            // reports. The generation-qualified /{ca_id}/{ski}.crl route needs the named
            // generation's OWN key to sign with (certs.private_key is per row, so it is
            // available) and lands next; CRLDP moves at the same time, not before.
            //
            // The CRLDP half of the defect is real and confirmed — the served CRL is signed
            // by the newest generation and carries its keyid, while the flat caIssuers
            // served the oldest — it is simply not fixable by a URL that 404s.
        }
    }
    return u;
}

std::string ca_unavailable_reason(const ResolvedCa& rc) {
    if (rc.on_hold)        return "CA certificate is on hold";
    if (rc.revoked)        return "CA certificate is revoked";
    if (rc.expired)        return "CA certificate has expired";
    if (!rc.has_local_key) return "no signing key for this CA on this node";
    return "CA instance disabled";
}

ResolvedCa resolve_ca_instance(Db& db, const Config& cfg, const std::string& id) {
    ResolvedCa r;
    r.id = id;
    auto ci = db.get_ca_instance(id);
    if (!ci) return r;                    // found=false: unknown instance
    r.found     = true;
    r.active    = (ci->status == "active");
    // ⚠️ A revoked CA must never sign again. get_ca_cert_der() already refuses to return
    // its DER (it filters status=0), but the signing_ca_pem fallback below reloads the
    // very same certificate from kCaSelect, which had no status predicate — so the CA
    // came back found+active and CaMaterialCache handed its key to every protocol.
    // Decided here, before either load runs, so no path can miss it.
    r.revoked   = ci->revoked;
    r.on_hold   = ci->on_hold;
    // ⚠️ AND EXPIRY, for exactly the same reason and by the same route. An expired CA kept
    // signing: get_ca_cert_der() refuses its DER once notAfter has passed, and then the
    // signing_ca_pem fallback — which has no validity predicate — handed the certificate
    // back anyway. Everything it then issued was clamped to a notAfter already in the past,
    // so a client received a certificate that was dead on arrival while the console showed
    // the CA as active and healthy.
    r.expired   = ci->expired;
    if (r.revoked || r.expired) r.active = false;

    // Load CA cert — prefer `certs` table (DER), fall back to file.
    // The query may return a leaf cert (status=0, ca_instance_id=id); reject anything
    // that is not actually a CA cert (basicConstraints cA=TRUE).
    // The whole live chain, newest first. During a rekey rollover this is two
    // certificates and BOTH have to reach a client — one for parties still anchored on
    // the old certificate, one for those on the new. cert_der stays the newest, which is
    // what signs; chain_ders is what gets served.
    for (auto& c : db.get_ca_chain_ders(id)) {
        if (c.der.empty()) continue;
        if (!r.chain_ref.empty()) r.chain_ref += ",";
        r.chain_ref += c.serial;
        r.chain_ders.push_back(std::move(c.der));
    }

    auto ca_cert = db.get_ca_cert_der(id);
    if (ca_cert && !ca_cert->der.empty()) {
        const unsigned char* pp = ca_cert->der.data();
        X509Ptr tmp{d2i_X509(nullptr, &pp, static_cast<long>(ca_cert->der.size()))};
        if (tmp && X509_check_ca(tmp.get())) {
            r.cert_der    = std::move(ca_cert->der);
            r.cert_serial = std::move(ca_cert->serial);
        }
        // else: not a CA cert — fall through to PEM file
    }
    if (r.cert_der.empty() && !ci->signing_ca_pem.empty()) {
        // signing_ca_pem is the certificate itself now, always — the CA IS its
        // `certs` row and db_postgres PEM-wraps the DER off it. The is-it-a-path guess
        // this used to make is gone with the second table that made it necessary.
        try {
            X509Ptr x = load_ca_cert_pem(ci->signing_ca_pem);
            if (x) {
                int len = i2d_X509(x.get(), nullptr);
                if (len > 0) {
                    r.cert_der.resize(static_cast<size_t>(len));
                    unsigned char* tmp = r.cert_der.data();
                    i2d_X509(x.get(), &tmp);
                }
            }
        } catch (...) { /* cert file missing or corrupt — CA not servable */ }
    }

    if (r.cert_der.empty()) { r.found = false; return r; }

    const bool pins_key = !ci->signing_ca_key.empty();
    r.key = ci->signing_ca_key;
    // Key is required: a CA without a signable key is not servable HERE. Record
    // WHICH of the two reasons applies — the caller has to be able to tell an operator
    // decision from a node that simply is not this CA's home.
    r.has_local_key = pins_key;
    if (!pins_key) r.active = false;
    return r;
}

std::optional<LoadedCa> CaMaterialCache::get(Db& db, const Config& cfg,
                                             const std::string& id,
                                             int& status, std::string& msg) {
    // Resolve outside the lock — it's a per-request DB read and must not serialize
    // issuance across every ca-id. This is also what makes rotation pull-based: a
    // console change lands in the row, and the next request here sees it.
    auto rc = resolve_ca_instance(db, cfg, id);
    if (!rc.found) { status = 404; msg = "unknown CA instance";  return std::nullopt; }
    if (!rc.active) {
        status = 503;
        // Three outcomes, three messages. Same status — the request cannot be served in
        // any of them — but an operator reading "CA instance disabled" about a CA the
        // console shows as active, or about one that is revoked, has been told something
        // false. The wording is shared with fastpki-ca so the two never drift.
        msg = ca_unavailable_reason(rc);
        return std::nullopt;
    }

    const std::string cert_ref = rc.cert_serial;
    const std::string key_ref  = rc.key;
    // The chain is part of what this entry answers, so it is part of what makes
    // the entry stale. cert_ref moves when a rekey adds a certificate; chain_ref moves
    // then AND when the old one expires out of the set, which cert_ref cannot see.
    const std::string chain_ref = rc.chain_ref;

    std::lock_guard<std::mutex> lk(mu_);
    auto it = cache_.find(rc.id);
    if (it != cache_.end() &&
        it->second.cert_ref == cert_ref && it->second.key_ref == key_ref &&
        it->second.chain_ref == chain_ref) {
        return LoadedCa{ it->second.cert, it->second.key, rc.id, it->second.chain };
    }
    // Miss, or the row's material reference changed (rotation) — (re)load. Loading a
    // pkcs11 key touches the token, so it happens here on a miss only, never per hit.
    try {
        const unsigned char* p = rc.cert_der.data();
        X509Ptr cert{d2i_X509(nullptr, &p, static_cast<long>(rc.cert_der.size()))};
        if (!cert) throw Error(2, "CA cert DER parse failed: " + openssl_errors());
        // The certificate goes IN, so that when this CA names several key URLs each
        // candidate is checked against it before use — "the first that works" has to mean
        // the first that holds THIS key. With one URL nothing changes: the explicit check
        // below still produces the error, and it is a better one.
        EvpPkeyPtr key = load_signing_key(rc.key, cfg, cert.get());
        Entry e;
        e.cert     = std::shared_ptr<X509>(cert.release(), X509_free);
        e.key      = std::shared_ptr<EVP_PKEY>(key.release(), EVP_PKEY_free);
        // The signer heads the chain by construction rather than by trusting the
        // query's ordering, and the rest follow. A DER that fails to parse is skipped —
        // one unreadable row must not cost a client the certificates that ARE readable.
        e.chain.push_back(e.cert);
        for (const auto& der : rc.chain_ders) {
            if (der == rc.cert_der) continue;               // already the head
            const unsigned char* q = der.data();
            X509Ptr extra{d2i_X509(nullptr, &q, static_cast<long>(der.size()))};
            if (extra) e.chain.push_back(std::shared_ptr<X509>(extra.release(), X509_free));
        }
        // ⚠️ THE CERTIFICATE AND THE KEY ARE TWO SEPARATE ROW FIELDS, AND NOTHING MADE THEM
        // AGREE. cert_der comes from the `certs` row and the key from its `private_key`
        // pkcs11: URI; a rekey that updates one, a hand-registered CA pointed at the wrong
        // token object, or a restored row beside a token that moved on, all leave a pair
        // that loads perfectly and signs nonsense. Every certificate issued from it would
        // carry a signature that verifies against NO published CA certificate -- the damage
        // is silent, lands on the client, and is only found when someone tries to validate
        // a chain. Every other credential path in this tree already checks: the CMP RA
        // (main.cpp), the SCEP RA, the OCSP responder and service_cert all call
        // cert_certifies_key. This one, which every protocol reaches for its CA signing
        // material, did not.
        //
        // cert_certifies_key(), not X509_check_private_key(): the latter compares EVP_PKEY
        // TYPES and reports a mismatch for a genuine pair whose key the pkcs11 provider
        // exposes as RSA-PSS while the certificate says RSA. That trap is recorded twice
        // already in this tree.
        //
        // Refusing is right. Serving 500 stops issuance for this CA and says so; the
        // alternative is minting certificates nothing can ever verify.
        if (!cert_certifies_key(e.cert.get(), e.key.get())) {
            throw Error(2, "the CA certificate and its private key do not match — the key at '" +
                           rc.key + "' does not correspond to the certificate stored for CA '" +
                           rc.id + "'. Nothing signed by this pair would verify against the "
                           "published CA certificate. Check that the pkcs11: object is the one "
                           "this CA was created with, and re-key the CA if it is not.");
        }
        e.cert_ref  = cert_ref;
        e.key_ref   = key_ref;
        e.chain_ref = chain_ref;
        Entry& slot = (cache_[rc.id] = std::move(e));
        return LoadedCa{ slot.cert, slot.key, rc.id, slot.chain };
    } catch (const std::exception& ex) {
        status = 500; msg = std::string("CA material unavailable: ") + ex.what();
        return std::nullopt;
    }
}

void CaMaterialCache::invalidate(const std::string& id) {
    std::lock_guard<std::mutex> lk(mu_);
    cache_.erase(id);
}

void CaMaterialCache::clear() {
    std::lock_guard<std::mutex> lk(mu_);
    cache_.clear();
}

// ---- shared client-certificate trust anchors -------------------------------
//
// This was `build_cmp_client_store` in src/cmp/main.cpp until EST needed the same
// anchors in EST. It is here, not copied, on purpose: the two protocols now decide
// "is this caller who they say they are" from ONE trust set, so a fix to the root-walk
// or the cA=TRUE rejection reaches both. A second copy is the shape that made scep's
// gate_protocol the only 2-arg call site.

// ⚠️ THE PRIVATE COPY OF split_csv IS GONE — pki::split_csv (config.hpp) is the one
// spelling. It was not identical: this one stripped whitespace INSIDE an element, the
// shared one trims only the ends. Both values parsed here are CA instance ids, which are
// [A-Za-z0-9_.-]+ and can contain no whitespace at all, so every legal input parses the
// same. For an ILLEGAL one the shared version is better: it yields a name that fails
// get_ca_instance and is logged as "not a known CA instance", where this one silently
// welded the halves into a different id.

// The CA certificate for `id`, as DER: the `certs` table first, then the instance's
// own PEM. get_ca_cert_der may hand back a LEAF (status=0, ca_instance_id=id), so
// anything without basicConstraints cA=TRUE is rejected rather than trusted.
static std::vector<unsigned char> ca_cert_der_for(Db* db, const std::string& id,
                                                  const std::string& signing_ca_pem) {
    std::vector<unsigned char> der;
    auto ca_cert = db->get_ca_cert_der(id);
    if (ca_cert && !ca_cert->der.empty()) {
        const unsigned char* pp = ca_cert->der.data();
        X509Ptr tmp{d2i_X509(nullptr, &pp, static_cast<long>(ca_cert->der.size()))};
        if (tmp && X509_check_ca(tmp.get()) == 1) der = std::move(ca_cert->der);
    }
    if (der.empty() && !signing_ca_pem.empty()) {
        try {
            // Always the certificate itself, never a path.
            X509Ptr x = load_ca_cert_pem(signing_ca_pem);
            if (x) {
                int len = i2d_X509(x.get(), nullptr);
                if (len > 0) {
                    der.resize(static_cast<size_t>(len));
                    unsigned char* tmp = der.data();
                    i2d_X509(x.get(), &tmp);
                }
            }
        } catch (...) {}
    }
    return der;
}

X509_STORE* build_client_trust_store(Db* db, const std::string& ids,
                                     const std::string& bundle,
                                     const char* who, const char* id_key,
                                     const char* bundle_key, int& anchors) {
    anchors = 0;
    X509_STORE* store = X509_STORE_new();
    if (!store) throw Error(2, "X509_STORE_new failed");
    const std::string tag = std::string(who) + ": " + id_key + " '";
    if (db) for (const auto& id : split_csv(ids)) {
        auto ci = db->get_ca_instance(id);
        if (!ci) {
            log::err(tag + id + "' is not a known CA instance — skipped");
            continue;
        }
        // ⚠️ A revoked CA is not a trust anchor. ca_cert_der_for() below falls through
        // get_ca_cert_der()'s status filter to signing_ca_pem — the same bypass that let a
        // revoked CA keep signing — so without this an operator who revoked a CA and left
        // it named here would go on authenticating clients against it, silently.
        if (ci->revoked) {
            log::err(tag + id + "' is REVOKED — not added as a client trust anchor");
            continue;
        }
        std::vector<unsigned char> cert_der = ca_cert_der_for(db, id, ci->signing_ca_pem);
        if (cert_der.empty()) {
            log::err(tag + id + "' has no certificate in the DB — skipped");
            continue;
        }
        try {
            const unsigned char* p = cert_der.data();
            X509Ptr cert{d2i_X509(nullptr, &p, static_cast<long>(cert_der.size()))};
            if (!cert) continue;
            if (X509_STORE_add_cert(store, cert.get()) != 1) {
                log::err(tag + id + "' could not be added to the trust store");
                continue;
            }
            ++anchors;

            // Walk up the issuer chain to add the self-signed root as a trust
            // anchor. Without it, chain validation fails because the intermediate alone
            // is not self-signed and OpenSSL treats X509_STORE_add_cert() certs as
            // untrusted intermediates.
            //
            // ⚠️ x509_is_self_signed(), never subject == issuer: a REKEYED CA is
            // self-ISSUED without being self-SIGNED, and stopping the walk there
            // would leave the real root out of the store.
            std::string parent_id = ci->parent_id;
            std::set<std::string> seen{id};
            while (!parent_id.empty() && seen.insert(parent_id).second) {
                auto parent_ci = db->get_ca_instance(parent_id);
                if (!parent_ci) break;
                // A revoked ancestor makes everything under it untrusted as well, so
                // stop the walk rather than anchoring the store on it.
                if (parent_ci->revoked) {
                    log::err(tag + id + "': ancestor '" + parent_id +
                             "' is REVOKED — chain not anchored above it");
                    break;
                }
                std::vector<unsigned char> pcert_der =
                    ca_cert_der_for(db, parent_id, parent_ci->signing_ca_pem);
                if (pcert_der.empty()) break;
                const unsigned char* pp = pcert_der.data();
                X509Ptr p_cert{d2i_X509(nullptr, &pp, static_cast<long>(pcert_der.size()))};
                if (!p_cert) break;
                X509_STORE_add_cert(store, p_cert.get());
                ++anchors;
                if (pki::x509_is_self_signed(p_cert.get())) break;
                parent_id = parent_ci->parent_id;
            }
        } catch (const std::exception& e) {
            log::err(tag + id + "': " + e.what());
        }
    }
    if (!bundle.empty()) {
        auto certs = load_certs_pem_mem(bundle);
        for (auto& c : certs) if (X509_STORE_add_cert(store, c.get()) == 1) ++anchors;
        if (certs.empty())
            log::err(std::string(who) + ": " + bundle_key +
                     " contained no parseable certificates");
    }
    return store;
}

std::string client_anchor_sig(Db* db, const std::string& ids, const std::string& bundle) {
    std::string sig = bundle;
    if (db) for (const auto& id : split_csv(ids)) {
        sig += '\x1e'; sig += id; sig += '=';
        try {
            auto ci = db->get_ca_instance(id);
            if (ci) {
                auto ca_cert = db->get_ca_cert_der(id);
                if (ca_cert && !ca_cert->der.empty())      sig += ca_cert->serial;
                else if (!ci->signing_ca_pem.empty())      sig += ci->signing_ca_pem;
            }
        } catch (...) {}
    }
    return sig;
}

namespace {

// Where the Db* rides so the verify callback below can reach it. SSL_CTX_set_verify takes a
// C function pointer, so there is nowhere to capture one.
int client_trust_db_idx() {
    static const int idx = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return idx;
}

// ⚠️ A SERIAL IS NOT AN IDENTITY, AND THIS IS WHERE THAT HAS TO BE ENFORCED.
//
// Every path that resolves a client certificate to a local account — the console's
// mtls_user(), EST's authenticate(), CMP's cmp_identity() — looks the presented certificate
// up in `certs` BY SERIAL. `certs.serial` is a deployment-global primary key and get_cert()
// scopes by nothing else, so a row found that way is "some certificate with this serial",
// not "this certificate". Serial and subject CN are both fields the ISSUER chooses.
//
// That is only safe while every certificate completing this handshake was issued by us. It
// stops being safe the moment an operator adds a foreign anchor — WEB_CLIENT_CA_BUNDLE,
// EST_CLIENT_CA_BUNDLE, CMP_CLIENT_CA_BUNDLE are all documented, supported settings. A
// partner CA can then mint a certificate carrying a serial we issued and a CN equal to that
// row's owner, and the owner==CN test downstream passes on a certificate we never issued.
//
// The handlers cannot close this themselves: cpp-httplib's PeerCert exposes subject_cn(),
// issuer_name() and serial() and no way to reach the bytes, and the header is refetched from
// upstream during the image build so it cannot be extended. But we own the SSL_CTX, so the
// check belongs here — at depth 0, with the leaf in hand, before any handler runs.
//
// Deliberately narrow: it refuses ONLY a certificate whose serial matches a row of ours and
// whose bytes do not. A certificate with no matching row is untouched and still reaches the
// handler to be treated as the foreign credential it is (`dn\<CN>`).
int client_cert_binding_cb(int preverify_ok, X509_STORE_CTX* store_ctx) {
    if (!preverify_ok || !store_ctx) return preverify_ok;
    if (X509_STORE_CTX_get_error_depth(store_ctx) != 0) return preverify_ok;  // leaf only

    X509* leaf = X509_STORE_CTX_get_current_cert(store_ctx);
    if (!leaf) return preverify_ok;

    SSL* ssl = static_cast<SSL*>(
        X509_STORE_CTX_get_ex_data(store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
    if (!ssl) return preverify_ok;
    SSL_CTX* sctx = SSL_get_SSL_CTX(ssl);
    if (!sctx) return preverify_ok;
    auto* db = static_cast<Db*>(SSL_CTX_get_ex_data(sctx, client_trust_db_idx()));
    if (!db) return preverify_ok;      // no database wired: nothing to collide with

    std::string serial;
    try {
        serial = canonical_serial(x509_serial_hex(leaf));
    } catch (...) { return preverify_ok; }
    if (serial.empty()) return preverify_ok;

    try {
        auto row = db->get_cert(serial);
        if (!row) return preverify_ok;                 // not one of ours; nothing to bind
        int len = i2d_X509(leaf, nullptr);
        if (len <= 0) return 0;
        std::vector<unsigned char> der(static_cast<size_t>(len));
        unsigned char* p = der.data();
        if (i2d_X509(leaf, &p) != len) return 0;
        if (!row->cert_der.empty() && row->cert_der == der) return preverify_ok;   // ours
        // A row with NO stored DER is a supported shape (imported and discovered rows carry
        // none), and it cannot be compared — so it cannot be confirmed as ours either.
        // Refusing is the safe direction, but say WHICH case it is or the operator is left
        // looking for an attacker where there is only a row with no bytes.
        log::err(row->cert_der.empty()
                     ? ("TLS: refusing a client certificate whose serial " + serial +
                        " matches a row that stores no certificate, so it cannot be "
                        "confirmed as one this deployment issued.")
                     : ("TLS: refusing a client certificate whose serial " + serial +
                        " matches one this deployment issued but whose bytes do not — it "
                        "was issued by someone else and is claiming our identity."));
        X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_CERT_REJECTED);
        return 0;
    } catch (const std::exception& e) {
        // A lookup FAILURE is not a permission. Every other path in this tree refuses
        // rather than guessing when it cannot check, and a database this listener cannot
        // reach has already broken far more than client authentication.
        log::err(std::string("TLS: refusing a client certificate whose identity could not "
                             "be checked: ") + e.what());
        X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }
}

} // namespace

bool install_client_trust(void* ssl_ctx, X509_STORE* store, Db* db) {
    auto* ctx = static_cast<SSL_CTX*>(ssl_ctx);
    if (!ctx || !store) return false;
    // Takes ownership of `store`.
    SSL_CTX_set_cert_store(ctx, store);

    // Advertise the acceptable issuer names so a client with several certificates in
    // its store picks the right one. Without this an openssl s_client / curl offers
    // whatever was named on the command line and nothing else, which hides a
    // misconfigured anchor set behind "the client sent no certificate".
    STACK_OF(X509_NAME)* names = sk_X509_NAME_new_null();
    if (names) {
        STACK_OF(X509_OBJECT)* objs = X509_STORE_get0_objects(store);
        for (int i = 0; i < sk_X509_OBJECT_num(objs); ++i) {
            X509* x = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objs, i));
            if (!x) continue;
            X509_NAME* n = X509_NAME_dup(X509_get_subject_name(x));
            if (n && sk_X509_NAME_push(names, n) <= 0) X509_NAME_free(n);
        }
        SSL_CTX_set_client_CA_list(ctx, names);   // takes ownership
    }

    // ⚠️ SSL_VERIFY_PEER alone — deliberately NOT SSL_VERIFY_FAIL_IF_NO_PEER_CERT.
    // A client that sends NO certificate must still reach the handler, because
    // RFC 7030 §3.2.3 HTTP Basic over TLS is a first-class EST authentication method
    // and is how most of our own suites enrol. A client that DOES send one must have
    // it verify, or OpenSSL terminates the handshake here. Those two together are
    // exactly what lets the handler treat a non-empty peer_cert() as proof.
    bind_client_certs(ctx, db);
    return true;
}

// ⚠️ EVERY LISTENER THAT ACCEPTS CLIENT CERTIFICATES MUST CALL THIS, not SSL_CTX_set_verify
// directly. The console has two anchor branches — a registered CA / DB bundle, and the
// WEB_CLIENT_CA file path — and only the first went through install_client_trust(). The
// second set SSL_VERIFY_PEER with a null callback of its own, so the binding above was
// installed on one of the two ways into the same listener. That is why this is a named
// function rather than three lines inside install_client_trust().
void bind_client_certs(void* ssl_ctx, Db* db) {
    auto* ctx = static_cast<SSL_CTX*>(ssl_ctx);
    if (!ctx) return;
    // SSL_VERIFY_PEER alone — deliberately NOT SSL_VERIFY_FAIL_IF_NO_PEER_CERT: a client
    // sending NO certificate must still reach the handler (HTTP Basic over TLS is a
    // first-class EST method, and a browser must reach the login page). One that DOES send
    // a certificate must have it verify, and now also be the certificate its serial names.
    if (db) SSL_CTX_set_ex_data(ctx, client_trust_db_idx(), db);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, db ? client_cert_binding_cb : nullptr);
}

} // namespace pki
