#include "pki/ca_renew.hpp"

#include <ctime>

#include <openssl/err.h>

#include "pki/audit.hpp"
#include "pki/log.hpp"
#include "pki/minted_key.hpp"
#include "pki/pkcs11_helpers.hpp"
#include "pki/service_cert.hpp"
#include "pki/x509.hpp"

namespace pki {

namespace {

// The signature floor, asked at the API boundary so a caller who names a broken digest is
// told so. Issuance refuses one anyway — the CA-certificate path falls back to a strong
// default rather than sign with SHA-1 — so this is not what makes the product safe. It is
// what makes it HONEST: without it a request for md=sha1 succeeds and returns a certificate
// signed under SHA-256, and the caller has no way to know the thing they asked for is not
// the thing they got.
//
// An unresolvable name is NOT refused: that case already has a defined meaning (the CA's own
// default applies), and turning it into an error would fail a renewal over a digest label
// this build of OpenSSL happens not to carry.
void refuse_weak_md(const Config& cfg, const std::string& name) {
    if (name.empty() || cfg.allow_weak_signature_digest) return;
    const EVP_MD* md = EVP_get_digestbyname(name.c_str());
    if (!md) { ERR_clear_error(); return; }
    if (!is_weak_signature_digest(md)) return;
    throw CaRenewError(400, "signature digest '" + name +
                            "' is below the signature floor and is refused");
}

}  // namespace

CaRenewResult renew_ca(Db& db, const Config& cfg, const CaRenewRequest& req,
                       CaMaterialCache* cache) {
    const std::string& id = req.ca_id;
    if (id.empty()) throw CaRenewError(400, "renew: no CA id");

    auto ci = db.get_ca_instance(id);
    if (!ci) throw CaRenewError(404, "no such CA instance: " + id);

    const bool samekey = req.same_key;
    const std::string newkey = samekey ? std::string() : req.new_key_ref;
    if (!samekey && newkey.rfind("pkcs11:", 0) != 0)
        throw CaRenewError(400, "a new key needs a pkcs11: handle naming where it goes — a CA "
                                "private key lives in a token (or renew with the current key)");
    if (!samekey && newkey == ci->signing_ca_key)
        throw CaRenewError(400, "that is the CA's current key. A new key must be a different "
                                "object — to renew with the current one, name no new key "
                                "(samekey=true over the API)");

    // The OLD material, which does the signing. Loaded BEFORE anything is minted: if the
    // current CA cannot sign, the whole operation is impossible, and finding that out after
    // generating a key would leave an orphaned keypair in the token.
    CaMaterialCache local;
    CaMaterialCache& cc = cache ? *cache : local;
    int code = 500;
    std::string err;
    auto old_mat = cc.get(db, cfg, id, code, err);
    if (!old_mat || !old_mat->key || !old_mat->cert)
        throw CaRenewError(code, err.empty() ? "the CA has no usable signing material" : err);

    const std::string keyalgo = req.key_algo.empty() ? std::string("rsa") : req.key_algo;
    const int bits = req.bits > 0 ? req.bits : 4096;
    const int days = req.days > 0 ? req.days : 3650;

    // ⚠️ WHO SIGNS THE RENEWAL, decided before anything is minted. A sub CA's new certificate
    // is signed by its PARENT, so the parent's key has to be on this node and the parent
    // usable; a root signs its own. When the parent's key is elsewhere — the ordinary mesh
    // case, a root on one node and a sub CA per node — the renewal is a CSR from here, signed
    // there and imported here, and saying so now beats minting a key that has nothing to
    // certify it.
    const std::string parent = ci->parent_id;
    std::optional<LoadedCa> parent_mat;
    if (!parent.empty()) {
        const auto prc = resolve_ca_instance(db, cfg, parent);
        if (!prc.found || !prc.has_local_key)
            throw CaRenewError(409,
                "this CA's parent '" + parent + "' has no signing key on this node, so the "
                "renewal has to be signed where it is: create a CSR for this CA here "
                "(fastpki-ca csr, or CAs -> Create CSR), sign it on the node holding the "
                "parent's key (fastpki-ca sign-csr, or Request from a CSR), and import the "
                "certificate here under this CA's id (fastpki-ca add, or Import an existing "
                "CA) — it becomes this CA's next certificate.",
                /*csr_route=*/true, parent);
        if (!prc.active)
            throw CaRenewError(409,
                "the parent CA '" + parent + "' cannot sign: " + ca_unavailable_reason(prc) +
                ". A renewal is signed by the parent, so enable it for the renewal "
                "(fastpki-ca enable " + parent + ") and disable it again afterwards.",
                /*csr_route=*/false, parent);
        int pcode = 500;
        std::string perr;
        parent_mat = cc.get(db, cfg, parent, pcode, perr);
        if (!parent_mat || !parent_mat->key || !parent_mat->cert)
            throw CaRenewError(pcode, "could not load the parent CA '" + parent + "': " + perr);
    }

    const bool replicable = !samekey && req.replicable;
    if (!samekey) {
        // Refuse an algorithm the token will not make, BY NAME, before minting. Silence is
        // consent: only a positive "no" from the token stops us.
        const std::string why =
            pkcs11_keygen_refusal(pkcs11_enumerate_slots(cfg.pkcs11_module), newkey, keyalgo);
        if (!why.empty()) throw CaRenewError(400, why);
        if (replicable) {
            const std::string rwhy = pkcs11_replicable_refusal(keyalgo, req.curve);
            if (!rwhy.empty()) throw CaRenewError(400, rwhy);
        }
        // ⚠️ THE NEW KEY NAME MUST BE FREE, and it has to be checked before MintedKey is
        // armed. ~MintedKey destroys whatever answers at the URI, not what this call created,
        // so a mint that fails over an occupied label would take the key that was already
        // there with it. A rekey mints a new key; it never adopts or replaces one, so there
        // is nothing to confirm here, only a name to change.
        bool taken = false;
        try { taken = static_cast<bool>(load_signing_key(newkey, cfg)); }
        catch (...) {}
        if (taken)
            throw CaRenewError(409, "a key already exists at that handle. A rekey generates a "
                                    "new key and never replaces one — choose a key name "
                                    "nothing uses.");
    }

    CaCertParams cap;
    cap.subject_dn = "";            // copied structurally from the old cert
    cap.not_after  = static_cast<int64_t>(std::time(nullptr)) + 60LL * 60 * 24 * days;
    cap.md         = req.md.empty() ? std::string("sha256") : req.md;
    cap.allow_weak_md = cfg.allow_weak_signature_digest;
    refuse_weak_md(cfg, cap.md);

    // Minted before anything is signed, and cross_sign_ca is the very operation the
    // pkcs11-provider refuses for some key types. Until the new row is stamped below, this
    // keypair belongs to nobody. With the current key nothing is minted.
    MintedKey minted(cfg, newkey);
    EvpPkeyPtr new_key;
    if (!samekey) {
        new_key = generate_key_in_token(newkey, cfg, keyalgo, bits, req.curve, replicable);
        if (!new_key) throw std::runtime_error("the token returned no key");
    }
    EVP_PKEY* old_pub = X509_get0_pubkey(old_mat->cert.get());
    EVP_PKEY* subject_pub = samekey ? old_pub : new_key.get();

    X509Ptr renewed, bridge, cross;
    if (!parent.empty()) {
        // A SUB CA: its parent signs, and the certificate carries the parent's CURRENT CRL DP
        // and AIA — the same derivation a sub CA created under it gets, so a mesh that has
        // grown since the old certificate is reflected. This is what makes a renewal the
        // remedy for a CA minted before `fastpki-mesh --map`. Nothing needs cross-signing:
        // old and new both chain to the parent.
        const CaUrls pu = ca_urls_for_instance(db, cfg, parent);
        cap.crldp = pu.crl;
        cap.aia_issuers = pu.ca_issuers;
        const std::string rid = cfg.ocsp_responder_cert_id_prefix + "-" + parent;
        bool parent_can_answer = false;
        try { auto d = db.get_cert_by_cert_id(rid); parent_can_answer = d && !d->empty(); }
        catch (...) {}
        if (parent_can_answer) cap.aia_ocsp = pu.ocsp;
        renewed = renew_ca_certificate(old_mat->cert.get(), subject_pub,
                                       parent_mat->cert.get(), parent_mat->key.get(), cap);
    } else {
        // A ROOT: a new self-signed certificate, which relying parties add as an anchor. With
        // a new key, two cross-certificates keep the rollover working for relying parties
        // still anchored on the current root:
        //   bridge  the NEW key signed by the OLD root — reaches the new key from the old
        //           anchor; bounded by the old root's life, which is the point
        //   cross   the OLD key signed by the NEW root — reaches everything the old key
        //           signed from the new anchor
        // ⚠️ The bridge is built BEFORE the renewal: both are id rows with the new key, and
        // the newest "notBefore" signs. Built after, a second boundary between the two would
        // make the bridge the signer, cutting every leaf to the old root's end date.
        if (!samekey)
            bridge = cross_sign_ca(old_mat->cert.get(), old_mat->key.get(), new_key.get(), cap);
        renewed = renew_ca_certificate(old_mat->cert.get(), subject_pub, nullptr,
                                       samekey ? old_mat->key.get() : new_key.get(), cap);
        if (!samekey)
            cross = cross_sign_ca(renewed.get(), new_key.get(), old_pub, cap);
    }

    const std::string row_key = samekey ? ci->signing_ca_key : newkey;
    auto store = [&](X509* x, bool as_ca_row) {
        CertRow r;
        r.serial      = x509_serial_hex(x);
        r.status      = 0;
        r.not_before  = x509_not_before_unix(x);
        r.not_after   = x509_not_after_unix(x);
        r.cn          = x509_cn(x);
        r.subject     = r.cn;
        r.cert_der    = x509_to_der(x);
        r.fingerprint = x509_fingerprint_sha256_hex(x);
        r.ca_instance_id = id;
        // An id row carries the key it certifies. The plain `cross` row is the OLD key under
        // the new root, and its type need not be `keyalgo` — a re-key may change algorithm —
        // so insert_cert derives it from that certificate's SPKI.
        if (as_ca_row) {
            r.ca_id = id; r.private_key = row_key;
            if (!samekey) r.key_algo = db_key_algo(keyalgo);
        }
        db.insert_cert(r);
        return r.serial;
    };
    // Stamp the CA's identity onto an id row. add_ca_instance is an UPDATE keyed on serial
    // and THROWS if the row is missing, so a failure here cannot leave a CA that lists but
    // cannot sign.
    auto stamp = [&](const std::string& serial) {
        Db::CaInstance nc = *ci;
        nc.serial = serial;
        nc.signing_ca_key = row_key;
        db.add_ca_instance(nc);
    };
    // ⚠️ THE RENEWED CERTIFICATE IS STORED LAST, so it is the CA's newest row and the one
    // that signs: get_ca_cert_der and get_ca_instance order by "notBefore", then ins_seq. The
    // bridge carries the same key and subject but ends with the OLD root; if it were picked,
    // every leaf would be cut to that date.
    CaRenewResult out;
    if (cross)  out.cross_serial  = store(cross.get(),  /*as_ca_row=*/false);
    if (bridge) { out.bridge_serial = store(bridge.get(), /*as_ca_row=*/true);
                  stamp(out.bridge_serial); }
    out.serial = store(renewed.get(), /*as_ca_row=*/true);
    stamp(out.serial);
    minted.keep();   // the CA row now names the new key (a no-op with the current key)
    cc.invalidate(id);

    out.key_ref   = row_key;
    out.not_after = x509_not_after_unix(renewed.get());
    out.signer    = parent.empty() ? id : parent;
    out.same_key  = samekey;

    // ⚠️ CASCADE — if a CA certificate is re-keyed, the dependent certificates must be
    // re-signed, and that has to be automatic. The OCSP responder / CMP RA / SCEP RA
    // credentials this CA issued are still signed by the OLD key: they now reach the new CA
    // only through the cross-certificate above. That is not a theoretical inconvenience — it
    // is precisely why the lab's DC1 responder returned "Response Verify Failure" until the
    // intermediate was passed by hand. Re-signing under the new key restores a direct chain.
    // A cascade failure does NOT undo the rekey (the CA is rekeyed either way) — it is
    // reported, so it surfaces here rather than at some client's next query.
    // With the CURRENT key there is nothing to cascade: every service credential was signed
    // by that key and still chains through the renewed certificate.
    if (!samekey) {
        try {
            const auto rr = renew_service_certs_for_ca(cfg, db, id, /*force=*/true,
                                                       /*dry_run=*/false);
            out.service_certs_renewed = rr.renewed;
            out.service_certs_failed  = rr.failed;
            for (const auto& n : rr.notes)  log::info("re-key, re-issuing its credentials: " + n);
            for (const auto& e : rr.errors) log::err("re-key, re-issuing its credentials: " + e);
        } catch (const std::exception& e) {
            ++out.service_certs_failed;
            log::err(std::string("could not re-issue the credentials after re-keying CA '") + id + "': " + e.what());
        }
    }

    try {
        AuditEvent ev;
        ev.category = audit_cat::kConfig;
        ev.action   = (req.iface.empty() ? std::string("cli") : req.iface) + "_ca_renewed";
        ev.actor    = req.actor;
        ev.actor_ip = req.actor_ip;
        ev.target   = id;
        ev.status   = audit_status::kSuccess;
        ev.detail   = "iface=" + (req.iface.empty() ? std::string("cli") : req.iface) +
                      " new=" + out.serial +
                      (samekey ? std::string(" samekey=1") : std::string()) +
                      (parent.empty() ? std::string() : " signer=" + parent) +
                      (out.bridge_serial.empty() ? std::string() : " bridge=" + out.bridge_serial) +
                      (out.cross_serial.empty() ? std::string() : " cross=" + out.cross_serial) +
                      (replicable ? " replicable=1" : "");
        db.append_audit(ev);
    } catch (...) {}
    log::info("renewed CA " + id + " new=" + out.serial +
              (samekey ? " with its current key" : " with a new key") +
              (parent.empty() ? " (self-signed root)" : " signed by " + parent) +
              (req.actor.empty() ? std::string() : " by=" + req.actor));
    return out;
}

}  // namespace pki
