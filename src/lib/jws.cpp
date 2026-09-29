#include "pki/jws.hpp"
#include "pki/error.hpp"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <sstream>

namespace pki::jws {
namespace {

// ---- base64url -------------------------------------------------------------

const char b64u_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string base64url_encode_impl(const unsigned char* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        unsigned v = data[i] << 16;
        if (i + 1 < len) v |= data[i + 1] << 8;
        if (i + 2 < len) v |= data[i + 2];
        out += b64u_chars[(v >> 18) & 63];
        out += b64u_chars[(v >> 12) & 63];
        if (i + 1 < len) out += b64u_chars[(v >> 6) & 63];
        if (i + 2 < len) out += b64u_chars[v & 63];
    }
    return out;
}

const std::array<int8_t, 256>& decode_table() {
    // Function-local static init is thread-safe (C++11 §6.7/4), so the table
    // is built exactly once even under concurrent first use.
    static const std::array<int8_t, 256> tbl = [] {
        std::array<int8_t, 256> t;
        t.fill(int8_t(-1));
        for (int i = 0; i < 64; ++i) t[(unsigned char)b64u_chars[i]] = int8_t(i);
        return t;
    }();
    return tbl;
}

std::vector<unsigned char> base64url_decode_impl(std::string_view s) {
    const auto& tbl = decode_table();
    std::vector<unsigned char> out;
    out.reserve(s.size() * 3 / 4);
    unsigned buf = 0;
    int bits = 0;
    for (char c : s) {
        int v = tbl[(unsigned char)c];
        if (v < 0) {
            if (c == '=' || c == '\r' || c == '\n') continue;
            throw Error(1, "invalid base64url char");
        }
        buf = (buf << 6) | static_cast<unsigned>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<unsigned char>((buf >> bits) & 0xff));
        }
    }
    return out;
}

// ---- JWK → EVP_PKEY --------------------------------------------------------

EvpPkeyPtr jwk_to_pubkey(const nlohmann::json& jwk) {
    if (!jwk.contains("kty")) throw Error(1, "jwk missing kty");
    std::string kty = jwk.at("kty").get<std::string>();

    if (kty == "EC") {
        if (jwk.value("crv", "") != "P-256")
            throw Error(1, "only EC P-256 supported (badPublicKey)");
        auto x = base64url_decode_impl(jwk.at("x").get<std::string>());
        auto y = base64url_decode_impl(jwk.at("y").get<std::string>());
        if (x.size() != 32 || y.size() != 32) throw Error(1, "EC point size != 32");

        // Build uncompressed point: 0x04 || X || Y.
        std::vector<unsigned char> pt;
        pt.reserve(1 + 64);
        pt.push_back(0x04);
        pt.insert(pt.end(), x.begin(), x.end());
        pt.insert(pt.end(), y.begin(), y.end());

        OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
        if (!bld) throw Error(2, "OSSL_PARAM_BLD_new failed");
        OSSL_PARAM_BLD_push_utf8_string(bld, "group", "prime256v1", 0);
        OSSL_PARAM_BLD_push_octet_string(bld, "pub", pt.data(), pt.size());
        OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
        OSSL_PARAM_BLD_free(bld);
        if (!params) throw Error(2, "OSSL_PARAM_BLD_to_param(EC) failed");

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
        if (!ctx) { OSSL_PARAM_free(params); throw Error(2, "EVP_PKEY_CTX_new_from_name(EC) failed"); }
        EVP_PKEY* pk = nullptr;
        int rc = (EVP_PKEY_fromdata_init(ctx) == 1)
                 && (EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_PUBLIC_KEY, params) == 1);
        EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(params);
        if (!rc || !pk) throw Error(1, "EVP_PKEY_fromdata(EC): " + openssl_errors());
        return EvpPkeyPtr{pk};
    }

    if (kty == "RSA") {
        auto n = base64url_decode_impl(jwk.at("n").get<std::string>());
        auto e = base64url_decode_impl(jwk.at("e").get<std::string>());
        BIGNUM* bn_n = BN_bin2bn(n.data(), static_cast<int>(n.size()), nullptr);
        BIGNUM* bn_e = BN_bin2bn(e.data(), static_cast<int>(e.size()), nullptr);
        if (!bn_n || !bn_e) {
            BN_free(bn_n); BN_free(bn_e);
            throw Error(1, "BN_bin2bn failed");
        }
        OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
        if (!bld) { BN_free(bn_n); BN_free(bn_e); throw Error(2, "OSSL_PARAM_BLD_new failed"); }
        OSSL_PARAM_BLD_push_BN(bld, "n", bn_n);
        OSSL_PARAM_BLD_push_BN(bld, "e", bn_e);
        OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
        OSSL_PARAM_BLD_free(bld);
        BN_free(bn_n); BN_free(bn_e);
        if (!params) throw Error(2, "OSSL_PARAM_BLD_to_param(RSA) failed");

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
        if (!ctx) { OSSL_PARAM_free(params); throw Error(2, "EVP_PKEY_CTX_new_from_name(RSA) failed"); }
        EVP_PKEY* pk = nullptr;
        int rc = (EVP_PKEY_fromdata_init(ctx) == 1)
                 && (EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_PUBLIC_KEY, params) == 1);
        EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(params);
        if (!rc || !pk) throw Error(1, "EVP_PKEY_fromdata(RSA): " + openssl_errors());
        return EvpPkeyPtr{pk};
    }

    throw Error(1, "unsupported kty: " + kty + " (badPublicKey)");
}

// ECDSA JWS signatures are the raw R||S (RFC 7515). OpenSSL wants the
// DER-encoded ECDSA-Sig-Value. Repack.
std::vector<unsigned char> ecdsa_raw_to_der(const std::vector<unsigned char>& raw) {
    if (raw.size() != 64) throw Error(1, "ES256 signature size != 64");
    BIGNUM* r = BN_bin2bn(raw.data(),       32, nullptr);
    BIGNUM* s = BN_bin2bn(raw.data() + 32,  32, nullptr);
    ECDSA_SIG* sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, r, s); // takes ownership of r, s
    int n = i2d_ECDSA_SIG(sig, nullptr);
    std::vector<unsigned char> out(static_cast<size_t>(n));
    unsigned char* p = out.data();
    i2d_ECDSA_SIG(sig, &p);
    ECDSA_SIG_free(sig);
    return out;
}

} // namespace

// ---- Public API ------------------------------------------------------------

std::string base64url_encode(const unsigned char* data, size_t len) {
    return base64url_encode_impl(data, len);
}
std::vector<unsigned char> base64url_decode(std::string_view s) {
    return base64url_decode_impl(s);
}

ParsedJws parse(std::string_view body) {
    nlohmann::json doc;
    try { doc = nlohmann::json::parse(body); }
    catch (const std::exception& e) { throw Error(1, std::string("malformed JSON: ") + e.what()); }
    if (!doc.is_object() || !doc.contains("protected") || !doc.contains("payload")
        || !doc.contains("signature"))
        throw Error(1, "malformed JWS: missing protected/payload/signature");

    ParsedJws p;
    p.protected_b64 = doc.at("protected").get<std::string>();
    p.payload_b64   = doc.at("payload").get<std::string>();
    p.signature_b64 = doc.at("signature").get<std::string>();

    auto prot_bytes = base64url_decode_impl(p.protected_b64);
    std::string_view prot_sv(reinterpret_cast<const char*>(prot_bytes.data()),
                             prot_bytes.size());
    try { p.protected_header = nlohmann::json::parse(prot_sv); }
    catch (const std::exception& e) { throw Error(1, std::string("malformed protected header: ") + e.what()); }

    if (!p.protected_header.contains("alg"))   throw Error(1, "missing alg");
    if (!p.protected_header.contains("url"))   throw Error(1, "missing url");
    if (!p.protected_header.contains("nonce")) throw Error(1, "missing nonce");
    p.alg   = p.protected_header.at("alg").get<std::string>();
    p.url   = p.protected_header.at("url").get<std::string>();
    p.nonce = p.protected_header.at("nonce").get<std::string>();

    bool has_jwk = p.protected_header.contains("jwk");
    bool has_kid = p.protected_header.contains("kid");
    if (has_jwk == has_kid)
        throw Error(1, "protected header must have exactly one of jwk/kid");
    if (has_jwk) p.jwk = p.protected_header.at("jwk");
    if (has_kid) p.kid = p.protected_header.at("kid").get<std::string>();

    p.payload_bytes   = base64url_decode_impl(p.payload_b64);
    p.signature_bytes = base64url_decode_impl(p.signature_b64);
    return p;
}

std::vector<unsigned char> verify(const ParsedJws& parsed,
                                  const nlohmann::json& jwk) {
    auto pk = jwk_to_pubkey(jwk);

    // Build the signing input: ASCII(BASE64URL(protected) || "." || BASE64URL(payload)).
    std::string signing_input;
    signing_input.reserve(parsed.protected_b64.size() + 1 + parsed.payload_b64.size());
    signing_input += parsed.protected_b64;
    signing_input += '.';
    signing_input += parsed.payload_b64;

    std::vector<unsigned char> sig;
    if      (parsed.alg == "ES256") sig = ecdsa_raw_to_der(parsed.signature_bytes);
    else if (parsed.alg == "RS256") sig = parsed.signature_bytes;
    else throw Error(1, "badSignatureAlgorithm: " + parsed.alg);

    EVP_MD_CTX* md = EVP_MD_CTX_new();
    if (!md) throw Error(2, "EVP_MD_CTX_new failed");
    if (EVP_DigestVerifyInit(md, nullptr, EVP_sha256(), nullptr, pk.get()) != 1) {
        EVP_MD_CTX_free(md);
        throw Error(2, "EVP_DigestVerifyInit failed: " + openssl_errors());
    }
    int rc = EVP_DigestVerify(md,
                              sig.data(), sig.size(),
                              reinterpret_cast<const unsigned char*>(signing_input.data()),
                              signing_input.size());
    EVP_MD_CTX_free(md);
    if (rc != 1) throw Error(1, "JWS signature verification failed");

    // Return the SubjectPublicKeyInfo DER for hashing into accounts.jwk_hash.
    int len = i2d_PUBKEY(pk.get(), nullptr);
    if (len <= 0) throw Error(2, "i2d_PUBKEY size failed: " + openssl_errors());
    std::vector<unsigned char> spki(static_cast<size_t>(len));
    unsigned char* p = spki.data();
    if (i2d_PUBKEY(pk.get(), &p) != len)
        throw Error(2, "i2d_PUBKEY failed: " + openssl_errors());
    return spki;
}

std::string thumbprint(const nlohmann::json& jwk) {
    // RFC 7638: canonical JSON of required members (kty + key-type-specific),
    // sorted lexicographically. For EC: crv,kty,x,y. For RSA: e,kty,n.
    nlohmann::ordered_json canonical;
    std::string kty = jwk.at("kty").get<std::string>();
    if (kty == "EC") {
        canonical["crv"] = jwk.at("crv");
        canonical["kty"] = jwk.at("kty");
        canonical["x"]   = jwk.at("x");
        canonical["y"]   = jwk.at("y");
    } else if (kty == "RSA") {
        canonical["e"]   = jwk.at("e");
        canonical["kty"] = jwk.at("kty");
        canonical["n"]   = jwk.at("n");
    } else {
        throw Error(1, "thumbprint: unsupported kty " + kty);
    }
    std::string s = canonical.dump();
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), md);
    return base64url_encode_impl(md, SHA256_DIGEST_LENGTH);
}

} // namespace pki::jws
