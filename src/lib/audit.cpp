#include "pki/audit.hpp"
#include "pki/error.hpp"
#include "pki/x509.hpp"

#include <openssl/evp.h>

#include <array>
#include <string>
#include <vector>

namespace pki {
namespace {

// Unambiguous canonical serialization: each field is length-prefixed
// ("<len>:<bytes>") so no field value can be confused with a delimiter or with
// a different field boundary. Order is fixed and part of the contract.
void append_field(std::string& out, std::string_view v) {
    out += std::to_string(v.size());
    out += ':';
    out.append(v.data(), v.size());
}

std::string canonical(const AuditEvent& e) {
    std::string c;
    append_field(c, std::to_string(e.ts));
    append_field(c, e.category);
    append_field(c, e.action);
    append_field(c, e.actor);
    append_field(c, e.actor_ip);
    append_field(c, e.target);
    append_field(c, e.status);
    append_field(c, e.detail);
    return c;
}

} // namespace

const std::string& audit_genesis_hash() {
    static const std::string g(64, '0');
    return g;
}

std::string sha256_hex(std::string_view data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> md{};
    unsigned int md_len = 0;
    if (EVP_Digest(data.data(), data.size(), md.data(), &md_len,
                   EVP_sha256(), nullptr) != 1)
        throw Error(2, "EVP_Digest(sha256) failed");
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(md_len * 2);
    for (unsigned int i = 0; i < md_len; ++i) {
        out += hex[md[i] >> 4];
        out += hex[md[i] & 0x0f];
    }
    return out;
}

std::string audit_entry_hash(const AuditEvent& ev, const std::string& prev_hash) {
    return sha256_hex(canonical(ev) + prev_hash);
}

AuditVerifyResult verify_audit_chain(const std::vector<AuditRow>& rows) {
    AuditVerifyResult r;
    r.count = static_cast<int64_t>(rows.size());
    std::string expected_prev = audit_genesis_hash();
    int64_t expected_seq = 0;
    bool have_seq = false;
    for (const auto& row : rows) {
        // Sequence must be strictly increasing and contiguous (gap ⇒ a row was
        // deleted between entries).
        if (!have_seq) { expected_seq = row.seq; have_seq = true; }
        if (row.seq != expected_seq) {
            r.ok = false; r.broken_seq = row.seq;
            r.reason = "sequence gap: expected seq " + std::to_string(expected_seq) +
                       " got " + std::to_string(row.seq);
            return r;
        }
        // Linkage: this row's prev_hash must equal the previous row's hash.
        if (row.prev_hash != expected_prev) {
            r.ok = false; r.broken_seq = row.seq;
            r.reason = "broken link: prev_hash does not match previous entry";
            return r;
        }
        // Integrity: recompute this row's hash from its content + prev_hash.
        std::string recomputed = audit_entry_hash(row.ev, row.prev_hash);
        if (recomputed != row.hash) {
            r.ok = false; r.broken_seq = row.seq;
            r.reason = "content tampered: recomputed hash != stored hash";
            return r;
        }
        expected_prev = row.hash;
        ++expected_seq;
    }
    r.head_hash = expected_prev;   // genesis if empty
    return r;
}

namespace {
std::string to_hex(const unsigned char* d, size_t n) {
    static const char* h = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += h[d[i] >> 4]; s += h[d[i] & 0xf]; }
    return s;
}
std::vector<unsigned char> from_hex(const std::string& s) {
    auto v = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<unsigned char> out;
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        int hi = v(s[i]), lo = v(s[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return out;
}
// The exact bytes a checkpoint signs/verifies over.
std::string checkpoint_message(int64_t head_seq, const std::string& head_hash) {
    return std::to_string(head_seq) + ":" + head_hash;
}
} // namespace

std::string audit_sign_head(void* evp_pkey_signing, int64_t head_seq,
                            const std::string& head_hash) {
    auto* key = static_cast<EVP_PKEY*>(evp_pkey_signing);
    std::string msg = checkpoint_message(head_seq, head_hash);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw Error(2, "EVP_MD_CTX_new failed");
    std::string out;

    // ⚠️ Same correction as crl.cpp — the audit chain is signed with a LOADED CA key,
    // so the type-name check is blind to a PSS-only key and the checkpoint signature failed.
    if (p11_rsa_requires_pss(key)) {
        // ⚠️ THIS BRANCH HAD NEVER RUN, so its contents were never right.
        //
        // It used to be gated on is_rsa_pss_p11_key(), which reads the provider's type
        // name — and the audit chain is ALWAYS signed with a key resolved by URI, whose
        // name OSSL_STORE strips. The gate could not be true here, so the code below was
        // dead: it called EVP_PKEY_sign with NO padding configured, which asks the token
        // for PKCS#1 v1.5 and gets a refusal from a PSS-only key. Fixing the gate exposed
        // that immediately ("audit head signing failed").
        //
        // Sign the same way crl.cpp does and for the same reason: EVP_DigestSign with the
        // PSS parameters set explicitly, so the provider selects CKM_*_RSA_PKCS_PSS
        // instead of falling back to a mechanism the key forbids.
        EVP_MD_CTX* mctx = EVP_MD_CTX_new();
        bool ok = mctx != nullptr;
        EVP_PKEY_CTX* pctx = nullptr;
        if (ok) ok = EVP_DigestSignInit(mctx, &pctx, EVP_sha256(), nullptr, key) > 0;
        if (ok) ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
                     EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) > 0 &&
                     EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0;
        size_t siglen = 0;
        if (ok) ok = EVP_DigestSign(mctx, nullptr, &siglen,
                    reinterpret_cast<const unsigned char*>(msg.data()), msg.size()) > 0;
        if (ok) {
            std::vector<unsigned char> sig(siglen);
            ok = EVP_DigestSign(mctx, sig.data(), &siglen,
                        reinterpret_cast<const unsigned char*>(msg.data()), msg.size()) > 0;
            if (ok) out = to_hex(sig.data(), siglen);
        }
        if (mctx) EVP_MD_CTX_free(mctx);
    } else if (is_ec_p11_key(key)) {
        // SoftHSM lacks CKM_ECDSA_SHA256: pre-hash in software, sign
        // the raw digest with CKM_ECDSA via EVP_PKEY_sign.
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;
        if (EVP_Digest(msg.data(), msg.size(), hash, &hash_len,
                        EVP_sha256(), nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            throw Error(2, "audit message digest failed");
        }
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(key, nullptr);
        bool ok = pctx && EVP_PKEY_sign_init(pctx) > 0;
        size_t siglen = 0;
        if (ok) ok = EVP_PKEY_sign(pctx, nullptr, &siglen, hash, hash_len) > 0;
        if (ok) {
            std::vector<unsigned char> sig(siglen);
            ok = EVP_PKEY_sign(pctx, sig.data(), &siglen, hash, hash_len) > 0;
            if (ok) out = to_hex(sig.data(), siglen);
        }
        EVP_PKEY_CTX_free(pctx);
    } else {
        // EdDSA (any provider) rejects explicit digests — use NULL md.
        // All other key types use SHA-256.
        const EVP_MD* use_md = EVP_sha256();
        int base = EVP_PKEY_get_base_id(key);
        if (base == EVP_PKEY_ED25519 || base == EVP_PKEY_ED448)
            use_md = nullptr;
        bool ok = EVP_DigestSignInit(ctx, nullptr, use_md, nullptr, key) == 1;
        size_t siglen = 0;
        if (ok) ok = EVP_DigestSign(ctx, nullptr, &siglen,
                                    reinterpret_cast<const unsigned char*>(msg.data()),
                                    msg.size()) == 1;
        if (ok) {
            std::vector<unsigned char> sig(siglen);
            ok = EVP_DigestSign(ctx, sig.data(), &siglen,
                                reinterpret_cast<const unsigned char*>(msg.data()),
                                msg.size()) == 1;
            if (ok) out = to_hex(sig.data(), siglen);
        }
    }

    EVP_MD_CTX_free(ctx);
    if (!out.empty()) return out;
    throw Error(2, "audit head signing failed");
}

bool audit_verify_head(void* evp_pkey_public, int64_t head_seq,
                       const std::string& head_hash, const std::string& sig_hex) {
    auto* pub = static_cast<EVP_PKEY*>(evp_pkey_public);
    std::string msg = checkpoint_message(head_seq, head_hash);
    auto sig = from_hex(sig_hex);
    if (sig.empty()) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pub) == 1
           && EVP_DigestVerify(ctx, sig.data(), sig.size(),
                               reinterpret_cast<const unsigned char*>(msg.data()),
                               msg.size()) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

} // namespace pki
