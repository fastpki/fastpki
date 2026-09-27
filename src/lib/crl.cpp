// X.509 CRL generation from the revoked rows in the certs DB.

#include "pki/x509.hpp"
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/error.hpp"
#include "pki/log.hpp"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <ctime>
#include <memory>
#include <vector>

namespace {

// The set of revocations a CRL asserts, rendered comparably: serial:reason per entry, in
// the CRL's own sorted order. NOT the DER, and that distinction is the whole reason this
// function exists — generate_crl() stamps crlNumber with the current unix time and moves
// thisUpdate with it, so two CRLs listing exactly the same revocations differ in bytes
// every single time. Comparing bytes would mean writing, and then MESH-REPLICATING, a new
// CRL every cache TTL for a CA where nothing has been revoked in months.
//
// Returns empty on a CRL that will not parse, which callers treat as "unknown, write it":
// an unreadable stored row is one worth replacing.
std::string crl_revocation_fingerprint(const std::vector<unsigned char>& der) {
    if (der.empty()) return std::string();
    const unsigned char* p = der.data();
    std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)>
        crl(d2i_X509_CRL(nullptr, &p, static_cast<long>(der.size())), &X509_CRL_free);
    if (!crl) return std::string();
    std::string fp;
    STACK_OF(X509_REVOKED)* revoked = X509_CRL_get_REVOKED(crl.get());
    for (int i = 0; i < sk_X509_REVOKED_num(revoked); ++i) {
        const X509_REVOKED* e = sk_X509_REVOKED_value(revoked, i);
        std::unique_ptr<BIGNUM, decltype(&BN_free)>
            bn(ASN1_INTEGER_to_BN(X509_REVOKED_get0_serialNumber(e), nullptr), &BN_free);
        if (bn) {
            char* hex = BN_bn2hex(bn.get());
            if (hex) { fp += hex; OPENSSL_free(hex); }
        }
        // The reason too: re-revoking a serial under a different reason changes what the
        // CRL says without changing which serials are on it.
        fp += ':';
        if (ASN1_ENUMERATED* rsn = static_cast<ASN1_ENUMERATED*>(
                X509_REVOKED_get_ext_d2i(e, NID_crl_reason, nullptr, nullptr))) {
            fp += std::to_string(ASN1_ENUMERATED_get(rsn));
            ASN1_ENUMERATED_free(rsn);
        }
        fp += ',';
    }
    return fp;
}

const char* openssl_errors_crl() {
    static thread_local char buf[256];
    unsigned long e = ERR_get_error();
    if (e) { ERR_error_string_n(e, buf, sizeof buf); return buf; }
    return "";
}

// Sign a CRL, working around provider-specific quirks:
//  - RSA-PSS on pkcs11: X509_CRL_sign_ctx with PSS params.
//  - EC on pkcs11: pre-hash TBS, sign raw digest with CKM_ECDSA.
//  - EdDSA on pkcs11: pass NULL md to X509_CRL_sign so the pkcs11 provider
//    uses CKM_EDDSA without attempting a separate digest.
//  - All other key types use X509_CRL_sign.
void sign_crl_compat(X509_CRL* crl, EVP_PKEY* key, const EVP_MD* md) {
    // --- EdDSA (any provider): must use NULL md ---
    {
        int base = EVP_PKEY_get_base_id(key);
        if (base == EVP_PKEY_ED25519 || base == EVP_PKEY_ED448) {
            if (!X509_CRL_sign(crl, key, nullptr))
                throw pki::Error(2, std::string("X509_CRL_sign(EdDSA) failed: ") + openssl_errors_crl());
            return;
        }
    }

    // --- RSA-PSS on pkcs11: X509_CRL_sign_ctx with PSS params ---
    // Same rationale as sign_x509: X509_CRL_sign creates its own EVP_MD_CTX
    // without PSS parameters, so the pkcs11 provider falls back to
    // CKM_SHA256_RSA_PKCS which SoftHSM rejects for an RSA-PSS key.
    // X509_CRL_sign_ctx lets us pre-configure the PSS context so the provider
    // correctly selects CKM_SHA256_RSA_PKCS_PSS / CKM_SHA384_RSA_PKCS_PSS etc.
    // ⚠️ p11_rsa_requires_pss(), NOT is_rsa_pss_p11_key(). The latter reads the
    // provider's TYPE NAME, and OSSL_STORE loses that name on any key that is LOADED rather
    // than generated — which is every CA key a long-running service holds. So a PSS-only CA
    // key looked unrestricted here, v1.5 was attempted, and the token refused: CRL
    // generation failed for exactly the reason sub-CA creation did. Ask the token instead.
    if (pki::p11_rsa_requires_pss(key)) {
        const EVP_MD* use_md = md ? md : EVP_sha256();
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        if (!mctx) throw pki::Error(2, "EVP_MD_CTX_new failed");
        EVP_PKEY_CTX* pctx = nullptr;
        if (EVP_DigestSignInit(mctx, &pctx, use_md, nullptr, key) <= 0) {
            EVP_MD_CTX_free(mctx);
            throw pki::Error(2, std::string("EVP_DigestSignInit(RSA-PSS CRL) failed: ") + openssl_errors_crl());
        }
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, use_md) <= 0 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
            EVP_MD_CTX_free(mctx);
            throw pki::Error(2, std::string("EVP_PKEY_CTX RSA-PSS CRL params failed: ") + openssl_errors_crl());
        }
        if (!X509_CRL_sign_ctx(crl, mctx)) {
            EVP_MD_CTX_free(mctx);
            throw pki::Error(2, std::string("X509_CRL_sign_ctx(RSA-PSS) failed: ") + openssl_errors_crl());
        }
        EVP_MD_CTX_free(mctx);
        return;
    }

    // --- EC on pkcs11 ---
    if (!pki::is_ec_p11_key(key)) {
        if (!X509_CRL_sign(crl, key, md))
            throw pki::Error(2, std::string("X509_CRL_sign failed: ") + openssl_errors_crl());
        return;
    }
    // EC on pkcs11: pre-hash then sign with CKM_ECDSA.
    const EVP_MD* use_md = md;
    if (!use_md) {
        int bits = EVP_PKEY_get_bits(key);
        use_md = bits <= 256 ? EVP_sha256() : bits <= 384 ? EVP_sha384() : EVP_sha512();
    }
    int md_nid = EVP_MD_get_type(use_md);
    int sigalg_nid = NID_undef;
    if      (md_nid == NID_sha256) sigalg_nid = NID_ecdsa_with_SHA256;
    else if (md_nid == NID_sha384) sigalg_nid = NID_ecdsa_with_SHA384;
    else if (md_nid == NID_sha512) sigalg_nid = NID_ecdsa_with_SHA512;
    else if (md_nid == NID_sha224) sigalg_nid = NID_ecdsa_with_SHA224;
    else throw pki::Error(2, "unsupported digest for CRL EC pkcs11 prehash signing");

    // 1. Populate TBS-internal signatureAlgorithm so i2d_re_X509_CRL_tbs works on
    //    an unsigned CRL (same idea as sign_x509 for certs).  Also sign once with a
    //    throwaway software EC key: this initialises the outer signature BIT_STRING
    //    (unused-bits = 0) which ASN1_STRING_set0 in step 5 does NOT touch —
    //    without this, OpenSSL >= 3.6's verifier rejects the CRL with "invalid bit
    //    string bits left" because X509_CRL_new() leaves the BIT_STRING flags dirty.
    {
        EVP_PKEY* tmp = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
        if (!tmp) throw pki::Error(2, "temp EC keygen failed (CRL TBS sigalg populate)");
        int rc = X509_CRL_sign(crl, tmp, use_md);
        EVP_PKEY_free(tmp);
        if (!rc)
            throw pki::Error(2, std::string("temp X509_CRL_sign failed (CRL TBS sigalg "
                                            "populate): ") + openssl_errors_crl());
    }

    // 2. Extract TBS DER.
    int tbs_len = i2d_re_X509_CRL_tbs(crl, nullptr);
    if (tbs_len <= 0)
        throw pki::Error(2, std::string("i2d_re_X509_CRL_tbs failed: ") + openssl_errors_crl());
    std::vector<unsigned char> tbs(static_cast<size_t>(tbs_len));
    unsigned char* tp = tbs.data();
    if (i2d_re_X509_CRL_tbs(crl, &tp) != tbs_len)
        throw pki::Error(2, "i2d_re_X509_CRL_tbs mismatch");

    // 3. Hash TBS in software.
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (!EVP_Digest(tbs.data(), tbs.size(), hash, &hash_len, use_md, nullptr))
        throw pki::Error(2, std::string("CRL TBS digest failed: ") + openssl_errors_crl());

    // 4. Sign the raw hash via EVP_PKEY_sign (bypasses EVP_DigestSign layer).
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(key, nullptr);
    if (!pctx) throw pki::Error(2, "EVP_PKEY_CTX_new failed");
    if (EVP_PKEY_sign_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw pki::Error(2, std::string("EVP_PKEY_sign_init failed: ") + openssl_errors_crl());
    }
    size_t sig_len = 0;
    if (EVP_PKEY_sign(pctx, nullptr, &sig_len, hash, hash_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw pki::Error(2, std::string("EVP_PKEY_sign size-query failed: ") + openssl_errors_crl());
    }
    std::vector<unsigned char> sig_buf(sig_len);
    if (EVP_PKEY_sign(pctx, sig_buf.data(), &sig_len, hash, hash_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw pki::Error(2, std::string("EVP_PKEY_sign(prehash) failed: ") + openssl_errors_crl());
    }
    EVP_PKEY_CTX_free(pctx);

    // 5. Set outer signatureAlgorithm + signatureValue via const_cast.
    const X509_ALGOR* outer_alg = nullptr;
    X509_CRL_get0_signature(crl, nullptr, &outer_alg);
    X509_ALGOR_set0(const_cast<X509_ALGOR*>(outer_alg),
                    OBJ_nid2obj(sigalg_nid), V_ASN1_UNDEF, nullptr);

    const ASN1_BIT_STRING* psig = nullptr;
    X509_CRL_get0_signature(crl, &psig, nullptr);
    auto* sig_str = const_cast<ASN1_BIT_STRING*>(psig);
    auto* sig_copy = static_cast<unsigned char*>(OPENSSL_malloc(sig_len));
    if (!sig_copy) throw pki::Error(2, "OPENSSL_malloc failed");
    memcpy(sig_copy, sig_buf.data(), sig_len);
    ASN1_STRING_set0(sig_str, sig_copy, sig_len);
}

} // namespace

namespace pki {

std::string revocation_reason_refusal(int reason) {
    if (reason < 0 || reason > 10 || reason == 7)
        return "invalid revocation reason " + std::to_string(reason) +
               ": RFC 5280 defines 0-6 and 8-10";
    if (reason == kReasonRemoveFromCrl)
        return "revocation reason removeFromCRL (8) is refused: a delta CRL uses it to announce a "
               "released hold. To release a certificate on hold, use release";
    if (reason == 10)
        return "revocation reason aACompromise (10) is refused: it applies to attribute certificates, "
               "which this CA does not issue";
    return std::string();
}

std::optional<std::vector<unsigned char>>
imported_crl(Db& db, const std::string& ca_id, bool is_delta, std::string& stale_note) {
    stale_note.clear();
    try {
        auto row = db.get_stored_crl(ca_id, is_delta);
        if (!row || row->der.empty()) return std::nullopt;
        if (row->next_update > 0 && row->next_update < std::time(nullptr)) {
            // ⚠️ The advice depends on WHERE the row came from, and telling an operator to
            // "import a freshly signed one" for a CRL this deployment signed itself sends
            // them looking for an offline-root ceremony that has nothing to do with the
            // problem. A `generated:` row is one a node published for a CA it holds the key
            // for; its going stale means that node has stopped refreshing it — which is
            // very often the node being down, i.e. precisely the case the stored copy
            // exists to cover. Name it, because that is the actionable part.
            const bool generated = row->imported_by.rfind("generated", 0) == 0;
            if (generated) {
                const std::string node = row->imported_by.size() > 10
                                             ? row->imported_by.substr(10)
                                             : std::string("unknown");
                stale_note = "the replicated CRL for CA '" + ca_id + "' expired at " +
                             std::to_string(row->next_update) +
                             " — the node that signs for it (" + node +
                             ") has not refreshed it; revocation for this CA is now stale";
            } else {
                stale_note = "the imported CRL for CA '" + ca_id + "' expired at " +
                             std::to_string(row->next_update) +
                             " — import a freshly signed one";
            }
        }
        return row->der;
    } catch (const std::exception& e) {
        // An unreadable `crls` table is not a CRL.
        log::err(std::string("imported CRL lookup failed for CA '") + ca_id + "': " + e.what());
        return std::nullopt;
    }
}

std::vector<unsigned char> generate_crl(const Config& cfg, Db& db,
                                        X509* ca_cert, EVP_PKEY* ca_key,
                                        const std::string& ca_instance_id,
                                        int64_t base_crl_number) {
    const bool is_delta = base_crl_number > 0;
    std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> crl(X509_CRL_new(), &X509_CRL_free);
    if (!crl) throw Error(2, "X509_CRL_new failed");

    if (!X509_CRL_set_version(crl.get(), 1)) // v2
        throw Error(2, "X509_CRL_set_version failed");
    if (!X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(ca_cert)))
        throw Error(2, "X509_CRL_set_issuer_name failed: " + openssl_errors());

    const time_t now = std::time(nullptr);
    // ⚠️ THE BACKDATE APPLIES TO CRLs TOO, and here it is sharper than for certificates.
    // OpenSSL's check_crl_time() compares thisUpdate against the verifier's clock with
    // NO tolerance at all — a CRL one second in the client's future is
    // X509_V_ERR_CRL_NOT_YET_VALID outright. (OCSP escapes this only because
    // OCSP_check_validity takes an explicit 300s skew argument; CRL validation has no
    // such knob.) SCEP GetCRL and the CMP id-it-crls ITAV generate inline per request,
    // so without this the CRL a lagging client holds is ALWAYS stamped in its future.
    //
    // ⚠️ Backdate the STAMP, never `now` itself: `now` is also the crlNumber below and
    // the delta-CRL base point, so shifting it would renumber every CRL and move the
    // delta base by 300s, dropping revocations out of delta CRLs.
    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)>
        last(ASN1_TIME_set(nullptr, now - kClockSkewBackdateSec), &ASN1_TIME_free);
    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)>
        next(ASN1_TIME_set(nullptr, now + 60LL * 60 * 24 * cfg.crl_next_update_days),
             &ASN1_TIME_free);
    if (!last || !next) throw Error(2, "ASN1_TIME_set failed");
    X509_CRL_set1_lastUpdate(crl.get(), last.get());
    X509_CRL_set1_nextUpdate(crl.get(), next.get());

    // RFC 5280 extensions: crlNumber (monotonic — we use the issuance time, which
    // increases on every regeneration) and authorityKeyIdentifier (from the CA).
    {
        std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)>
            num(ASN1_INTEGER_new(), &ASN1_INTEGER_free);
        if (num && ASN1_INTEGER_set_int64(num.get(), static_cast<int64_t>(now)))
            X509_CRL_add1_ext_i2d(crl.get(), NID_crl_number, num.get(), 0, 0);

        X509V3_CTX ctx;
        // ⚠️ set_ctx_nodb FIRST. X509V3_set_ctx() does not touch ctx->db, so without this
        // the config-database pointer of a stack-allocated context is whatever was on the
        // stack. Nothing here reads it today — do_ext_nconf() only consults ctx->db for
        // `r2i` extensions and authorityKeyIdentifier is `v2i` — but that is an accident
        // of which extension this happens to add, not a property of the code.
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, ca_cert, nullptr, nullptr, crl.get(), 0);
        if (X509_EXTENSION* ex = X509V3_EXT_conf_nid(
                nullptr, &ctx, NID_authority_key_identifier, "keyid:always")) {
            X509_CRL_add_ext(crl.get(), ex, -1);
            X509_EXTENSION_free(ex);
        }

        // Delta CRLs (RFC 5280 §5.2.4/§5.2.6). A delta carries the Delta CRL
        // Indicator (critical) = the BaseCRLNumber it is relative to, and lists
        // only entries revoked since that base. Because our crlNumber IS the
        // issuance unix time, "base number N" means "changes since time N" — so a
        // client with the base CRL at N fetches ?base=N to get just the new
        // revocations. A full/base CRL instead advertises a Freshest CRL pointer
        // to its own delta (?base=<this crlNumber>) when deltas are enabled.
        if (is_delta) {
            std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)>
                base(ASN1_INTEGER_new(), &ASN1_INTEGER_free);
            if (base && ASN1_INTEGER_set_int64(base.get(), base_crl_number))
                X509_CRL_add1_ext_i2d(crl.get(), NID_delta_crl, base.get(), /*crit=*/1, 0);
        } else if (cfg.crl_delta_enabled) {
            const std::string base_url = cfg.base_url.empty()
                ? ("https://" + cfg.pki_dns) : cfg.base_url;
            const std::string dp = "URI:" + base_url + cfg.crl_path +
                                   "?base=" + std::to_string(static_cast<int64_t>(now));
            if (X509_EXTENSION* ex = X509V3_EXT_conf_nid(
                    nullptr, &ctx, NID_freshest_crl, dp.c_str())) {
                X509_CRL_add_ext(crl.get(), ex, -1);
                X509_EXTENSION_free(ex);
            }
        }
    }

    // The entries: every revocation (holds included), and in a delta the holds released since
    // its base, with reason removeFromCRL — RFC 5280 §5.3.1: that reason is only for delta
    // CRLs, and it tells a client holding the base CRL to drop the entry. A full CRL simply
    // no longer lists a released certificate.
    std::vector<Db::RevokedCert> entries = db.get_revoked_certs(ca_instance_id);
    if (is_delta) {
        for (auto& rel : db.get_released_holds(ca_instance_id, base_crl_number)) {
            rel.reason = kReasonRemoveFromCrl;
            entries.push_back(std::move(rel));
        }
    }
    for (const auto& rc : entries) {
        // A delta only carries revocations at/after its base point.
        if (is_delta && static_cast<int64_t>(rc.date) < base_crl_number) continue;
        X509_REVOKED* rev = X509_REVOKED_new();
        if (!rev) throw Error(2, "X509_REVOKED_new failed");

        // serial (lowercase hex in the DB) -> ASN1_INTEGER
        BIGNUM* bn = nullptr;
        if (BN_hex2bn(&bn, rc.serial_hex.c_str()) == 0 || !bn) {
            X509_REVOKED_free(rev);
            continue; // skip a malformed serial rather than failing the whole CRL
        }
        std::unique_ptr<BIGNUM, decltype(&BN_free)> bn_g(bn, &BN_free);
        std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)>
            ai(BN_to_ASN1_INTEGER(bn, nullptr), &ASN1_INTEGER_free);
        if (ai) X509_REVOKED_set_serialNumber(rev, ai.get());

        std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)>
            rt(ASN1_TIME_set(nullptr, static_cast<time_t>(rc.date)), &ASN1_TIME_free);
        if (rt) X509_REVOKED_set_revocationDate(rev, rt.get());

        // CRLReason extension. Absent for unspecified: RFC 5280 §5.3.1 says the extension
        // SHOULD be absent rather than carry unspecified (0).
        if (rc.reason != kReasonUnspecified) {
            std::unique_ptr<ASN1_ENUMERATED, decltype(&ASN1_ENUMERATED_free)>
                reason(ASN1_ENUMERATED_new(), &ASN1_ENUMERATED_free);
            if (reason && ASN1_ENUMERATED_set(reason.get(), rc.reason))
                X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason, reason.get(), 0, 0);
        }

        if (!X509_CRL_add0_revoked(crl.get(), rev)) { // takes ownership on success
            X509_REVOKED_free(rev);
            throw Error(2, "X509_CRL_add0_revoked failed: " + openssl_errors());
        }
    }

    X509_CRL_sort(crl.get());

    // ⚠️ The CRL signature digest must come from the SAME source the certificates use,
    // not a hardcoded SHA-256. leaf_signing_md() honours an RFC 4055 restriction
    // published in the CA's own SPKI — and a restricted RSA-PSS key REFUSES every other
    // digest:
    //
    //     rsa_check_padding:digest not allowed
    //
    // A 4096-bit PSS root publishes a sha384 restriction (the bits ladder), so its
    // sha256-signed CRL failed verification in EVERY client — chain validation of all
    // leaves under that CA died with it, while the certificates themselves (signed via
    // the same chooser) verified fine. Same rule as sign_x509: one digest chooser for
    // everything a CA key signs.
    sign_crl_compat(crl.get(), ca_key, leaf_signing_md(ca_key, ca_cert, ""));

    int len = i2d_X509_CRL(crl.get(), nullptr);
    if (len <= 0) throw Error(2, "i2d_X509_CRL size failed: " + openssl_errors());
    std::vector<unsigned char> out(static_cast<size_t>(len));
    unsigned char* p = out.data();
    if (i2d_X509_CRL(crl.get(), &p) != len)
        throw Error(2, "i2d_X509_CRL encode failed: " + openssl_errors());
    return out;
}

// ── publishing a CRL this node signed, so a peer can serve it after this node is gone ──
//
// A CRL must be signed by the CA, and the CA key lives on exactly one node. When that node
// dies its certificates stay deployed and become uncheckable: no peer can produce a CRL and
// no peer can answer OCSP, because a delegated responder key would have to be issued by the
// same absent CA. Per-node sub-CAs under a shared root therefore give fault ISOLATION, not
// availability — the blast radius is one CA, but that CA's revocation goes dark.
//
// The `crls` table already replicates through the mesh, and all three serving paths prefer a
// stored CRL before refusing (imported_crl above).
//
// ⚠️ TWO PATHS, NOT THREE, AND "BEFORE REFUSING" MEANS BEFORE RESOLVING CA MATERIAL.
// resolve_ca_instance() marks a CA whose key is on another node INACTIVE, so
// CaMaterialCache::get() fails on exactly the peers this exists for; the store's fallback
// sat below that failure and could never run.
//
// SCEP is not one of the paths and cannot be. Its GetCRL reply is a signed certRep, so
// answering needs the CA's own key — which a peer, by definition, does not have. A client
// whose CA's node is down fetches revocation over the RFC 4387 store or OCSP instead. The only thing missing was
// anything writing to it other than an operator running `fastpki-ca import-crl`. So: when a
// node signs a CRL, it stores it. Peers then serve that CA's revocation until the CRL's own
// nextUpdate, which turns "revocation goes dark" into "revocation keeps answering, and says
// how old it is" — the difference between a relying party failing safe and failing blind.
//
// This does NOT restore issuance, and nothing short of a shared key store would.
//
// ⚠️ FULL CRLs ONLY. A delta is generated against a base point the CLIENT chooses
// (?base=N), and the table holds one row per (ca_id, is_delta) — so persisting a delta
// would store one arbitrary client's window and serve it to everyone else as though it
// were theirs. A peer serving a full CRL is always correct; a peer serving someone else's
// delta is not.
void publish_generated_crl(const Config& cfg, Db& db, const std::string& ca_id,
                           const std::vector<unsigned char>& der) {
    if (ca_id.empty() || der.empty()) return;
    try {
        const std::time_t now = std::time(nullptr);
        auto stored = db.get_stored_crl(ca_id, /*is_delta=*/false);

        // Write when there is nothing stored, when the revocations changed, or when the
        // stored copy is past the halfway mark of its own validity. That last clause is
        // what keeps a replicated CRL usable: without it a CA with no new revocations
        // would keep serving peers the same row until it expired under them.
        bool write = true;
        if (stored && !stored->der.empty()) {
            const std::string have = crl_revocation_fingerprint(stored->der);
            const std::string want = crl_revocation_fingerprint(der);
            const bool same_content = !have.empty() && have == want;
            const bool still_fresh =
                stored->next_update > 0 && stored->this_update > 0 &&
                now < stored->this_update + (stored->next_update - stored->this_update) / 2;
            write = !(same_content && still_fresh);
        }
        if (!write) return;

        Db::StoredCrl row;
        row.der = der;
        {
            const unsigned char* p = der.data();
            std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)>
                crl(d2i_X509_CRL(nullptr, &p, static_cast<long>(der.size())), &X509_CRL_free);
            if (!crl) return;   // we just signed it; if it will not parse, do not store it
            row.this_update = asn1_time_to_unix(X509_CRL_get0_lastUpdate(crl.get()));
            if (const ASN1_TIME* nu = X509_CRL_get0_nextUpdate(crl.get()))
                row.next_update = asn1_time_to_unix(nu);
            if (ASN1_INTEGER* num = static_cast<ASN1_INTEGER*>(
                    X509_CRL_get_ext_d2i(crl.get(), NID_crl_number, nullptr, nullptr))) {
                int64_t v = 0;
                if (ASN1_INTEGER_get_int64(&v, num)) row.crl_number = v;
                ASN1_INTEGER_free(num);
            }
        }
        // ⚠️ Honest provenance. `imported_by` used to mean one thing — an operator ran
        // `fastpki-ca import-crl` for an offline root — and a self-generated row disguised
        // as an import would send whoever reads it looking for an import that never
        // happened. It names the node instead, which is also what a reader needs when the
        // stored CRL is stale: WHICH node stopped refreshing it.
        row.imported_by = cfg.datacenter_id.empty()
                              ? std::string("generated")
                              : "generated:" + cfg.datacenter_id;
        db.upsert_stored_crl(ca_id, /*is_delta=*/false, row);
    } catch (const std::exception& e) {
        // Never fail the request that produced the CRL. Serving it matters more than
        // storing it, and the next generation retries anyway.
        log::err(std::string("CRL publication failed for CA '") + ca_id + "': " + e.what());
    }
}

std::vector<unsigned char> CrlCache::get(const Config& cfg, Db& db,
                                         X509* ca_cert, EVP_PKEY* ca_key,
                                         const std::string& ca_instance_id) {
    std::lock_guard<std::mutex> lk(mu_);
    const std::time_t now = std::time(nullptr);
    Entry& e = entries_[ca_instance_id];
    if (e.cached.empty() || ttl_ <= 0 || (now - e.generated_at) >= ttl_) {
        e.cached = generate_crl(cfg, db, ca_cert, ca_key, ca_instance_id);
        e.generated_at = now;
        // Audit: a CRL (re)generation is a mandatory PKI-lifecycle
        // event. Only fires on an actual rebuild (TTL miss), not per request.
        try {
            AuditEvent ev;
            ev.category = audit_cat::kLifecycle;
            ev.action   = "crl_generated";
            ev.status   = audit_status::kSuccess;
            ev.detail   = "ca_instance=" + ca_instance_id +
                          " revoked=" + std::to_string(db.get_revoked_certs(ca_instance_id).size()) +
                          " bytes=" + std::to_string(e.cached.size());
            db.append_audit(ev);
        } catch (const std::exception& e2) {
            log::err(std::string("CRL audit append failed: ") + e2.what());
        }
        // Store it for the peers. Gated by the same TTL miss as the audit event above, and
        // gated again inside on whether the revocations actually changed.
        publish_generated_crl(cfg, db, ca_instance_id, e.cached);
    }
    return e.cached;
}

} // namespace pki
