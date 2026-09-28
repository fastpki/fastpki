// Passkeys (WebAuthn) — see include/pki/webauthn.hpp.
#include "pki/webauthn.hpp"
#include "pki/cbor.hpp"
#include "pki/error.hpp"
#include "pki/jws.hpp"
#include "../../third_party/nlohmann/json.hpp"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <memory>

namespace pki::webauthn {

namespace {

using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

[[noreturn]] void bad(const std::string& why) { throw Error(1, "passkey: " + why); }

std::string sha256(const unsigned char* d, size_t n) {
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256(d, n, h);
    return std::string(reinterpret_cast<char*>(h), sizeof h);
}

std::string spki_of(EVP_PKEY* pk) {
    unsigned char* der = nullptr;
    const int n = i2d_PUBKEY(pk, &der);
    if (n <= 0) bad("cannot encode the public key");
    std::string out(reinterpret_cast<char*>(der), static_cast<size_t>(n));
    OPENSSL_free(der);
    return out;
}

// An EC P-256 or RSA public key from its parameters.
PkeyPtr from_params(const char* type, OSSL_PARAM_BLD* bld) {
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) bad("cannot build the public key");
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, type, nullptr);
    EVP_PKEY* pk = nullptr;
    const bool ok = ctx && EVP_PKEY_fromdata_init(ctx) == 1 &&
                    EVP_PKEY_fromdata(ctx, &pk, EVP_PKEY_PUBLIC_KEY, params) == 1;
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    if (!ok || !pk) bad("the public key is not a valid key");
    return PkeyPtr(pk, EVP_PKEY_free);
}

// Reads a COSE_Key from the reader and returns its SPKI.
std::string read_cose_key(cbor::Reader& c, int& alg) {
    int64_t kty = 0, a = 0, crv = 0;
    std::vector<unsigned char> x, y, n, e;
    bool have_kty = false, have_alg = false;
    const uint64_t count = c.map_count();
    if (count > 16) c.bad("too many members");
    // The labels are integers; x/y and n/e share -2, so they are read by kty afterwards.
    std::vector<unsigned char> m1_bytes, m2_bytes, m3_bytes;
    int64_t m1_int = 0;
    bool m1_is_int = false;
    for (uint64_t i = 0; i < count; ++i) {
        if (c.peek_major() != 0 && c.peek_major() != 1) { c.skip(1); c.skip(1); continue; }
        const int64_t label = c.integer();
        switch (label) {
            case 1: kty = c.integer(); have_kty = true; break;
            case 3: a = c.integer(); have_alg = true; break;
            case -1:
                if (c.peek_major() == 2) m1_bytes = c.bytes();
                else { m1_int = c.integer(); m1_is_int = true; }
                break;
            case -2: m2_bytes = c.bytes(); break;
            case -3: m3_bytes = c.bytes(); break;
            default: c.skip(1); break;
        }
    }
    if (!have_kty || !have_alg) c.bad("the key has no kty or alg");
    if (m1_is_int) crv = m1_int;

    if (kty == 2) {                                   // EC2
        if (a != kES256 || !m1_is_int || crv != 1) bad("an EC key must be P-256 with ES256");
        x = m2_bytes; y = m3_bytes;
        if (x.size() != 32 || y.size() != 32) bad("an EC P-256 point needs 32-byte x and y");
        std::vector<unsigned char> pt{0x04};
        pt.insert(pt.end(), x.begin(), x.end());
        pt.insert(pt.end(), y.begin(), y.end());
        OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
        if (!bld) bad("out of memory");
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pt.data(), pt.size());
        alg = kES256;
        return spki_of(from_params("EC", bld).get());
    }
    if (kty == 1) {                                   // OKP
        if (a != kEdDSA || !m1_is_int || crv != 6) bad("an OKP key must be Ed25519 with EdDSA");
        x = m2_bytes;
        if (x.size() != 32) bad("an Ed25519 key is 32 bytes");
        EVP_PKEY* pk = EVP_PKEY_new_raw_public_key_ex(nullptr, "ED25519", nullptr, x.data(), x.size());
        if (!pk) bad("the public key is not a valid key");
        PkeyPtr p(pk, EVP_PKEY_free);
        alg = kEdDSA;
        return spki_of(p.get());
    }
    if (kty == 3) {                                   // RSA
        if (a != kRS256 || m1_is_int) bad("an RSA key must be used with RS256");
        n = m1_bytes; e = m2_bytes;
        if (n.size() < 256 || n.size() > 1024 || e.empty() || e.size() > 8)
            bad("an RSA key must be 2048 to 8192 bits");
        BIGNUM* bn_n = BN_bin2bn(n.data(), static_cast<int>(n.size()), nullptr);
        BIGNUM* bn_e = BN_bin2bn(e.data(), static_cast<int>(e.size()), nullptr);
        OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
        if (!bn_n || !bn_e || !bld) {
            BN_free(bn_n); BN_free(bn_e); OSSL_PARAM_BLD_free(bld);
            bad("out of memory");
        }
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n);
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e);
        PkeyPtr p = from_params("RSA", bld);
        BN_free(bn_n); BN_free(bn_e);
        alg = kRS256;
        return spki_of(p.get());
    }
    bad("key type " + std::to_string(kty) + " is not supported");
}

} // namespace

AuthData parse_auth_data(const unsigned char* data, size_t len, bool want_credential) {
    if (len < 37) bad("authenticator data is shorter than 37 bytes");
    AuthData out;
    out.rp_id_hash.assign(reinterpret_cast<const char*>(data), 32);
    out.flags = data[32];
    out.sign_count = (static_cast<uint32_t>(data[33]) << 24) | (static_cast<uint32_t>(data[34]) << 16) |
                     (static_cast<uint32_t>(data[35]) << 8) | static_cast<uint32_t>(data[36]);
    cbor::Reader c{data + 37, data + len, "authenticator data"};
    const bool attested = (out.flags & kAttested) != 0;
    if (attested != want_credential)
        bad(want_credential ? "registration carries no credential"
                            : "sign-in carries a credential it should not");
    if (attested) {
        if (c.left() < 18) c.bad("truncated credential data");
        c.p += 16;                                        // AAGUID: not used
        const size_t idlen = (static_cast<size_t>(c.p[0]) << 8) | c.p[1];
        c.p += 2;
        if (idlen == 0 || idlen > 1023) c.bad("credential id length out of range");
        out.credential_id = std::string(c.take(idlen));
        const unsigned char* key_start = c.p;
        c.skip(1);                                        // bound the COSE key's extent
        out.spki = cose_key_to_spki(key_start, static_cast<size_t>(c.p - key_start), out.alg);
    }
    if (out.flags & kExtensions) c.skip(1);
    if (c.p != c.end) c.bad("trailing bytes");
    return out;
}

std::string cose_key_to_spki(const unsigned char* data, size_t len, int& alg) {
    cbor::Reader c{data, data + len, "passkey public key"};
    std::string spki = read_cose_key(c, alg);
    if (c.p != c.end) c.bad("trailing bytes");
    return spki;
}

std::string auth_data_of_attestation(const unsigned char* data, size_t len) {
    cbor::Reader c{data, data + len, "attestation object"};
    std::string auth;
    bool have = false;
    const uint64_t n = c.map_count();
    for (uint64_t i = 0; i < n; ++i) {
        if (c.key() == "authData") {
            const auto b = c.bytes();
            auth.assign(b.begin(), b.end());
            have = true;
        } else {
            c.skip(1);
        }
    }
    if (c.p != c.end) c.bad("trailing bytes after the object");
    if (!have) c.bad("no authData");
    return auth;
}

ClientData parse_client_data(std::string_view json) {
    nlohmann::json j;
    try { j = nlohmann::json::parse(json); }
    catch (const std::exception&) { bad("client data is not JSON"); }
    if (!j.is_object()) bad("client data is not a JSON object");
    auto str = [&](const char* k) -> std::string {
        auto it = j.find(k);
        if (it == j.end() || !it->is_string()) bad(std::string("client data has no ") + k);
        return it->get<std::string>();
    };
    ClientData cd{str("type"), str("challenge"), str("origin")};
    if (auto it = j.find("crossOrigin"); it != j.end() && it->is_boolean() && it->get<bool>())
        bad("a cross-origin request is not accepted");
    return cd;
}

bool origin_matches(const std::string& origin, const std::string& rp_id) {
    const std::string base = "https://" + rp_id;
    if (rp_id.empty() || origin.compare(0, base.size(), base) != 0) return false;
    if (origin.size() == base.size()) return true;
    if (origin[base.size()] != ':' || origin.size() == base.size() + 1) return false;
    for (size_t i = base.size() + 1; i < origin.size(); ++i)
        if (origin[i] < '0' || origin[i] > '9') return false;
    return true;
}

namespace {

// The checks registration and sign-in share: client data type, challenge and origin, and the
// authenticator data's rp id hash and flags.
void check_common(const ClientData& cd, const char* type, const AuthData& ad,
                  const std::string& rp_id, const std::string& challenge) {
    if (cd.type != type) bad(std::string("client data type is not ") + type);
    if (challenge.empty() || cd.challenge != challenge) bad("the challenge does not match");
    if (!origin_matches(cd.origin, rp_id))
        bad("the origin " + cd.origin + " is not https://" + rp_id);
    const std::string want = sha256(reinterpret_cast<const unsigned char*>(rp_id.data()), rp_id.size());
    if (ad.rp_id_hash != want) bad("the passkey is for another site");
    if (!(ad.flags & kUserPresent)) bad("the authenticator did not confirm user presence");
    if (!(ad.flags & kUserVerified))
        bad("the authenticator did not verify the user (Face ID, Touch ID or a PIN is required)");
}

} // namespace

Registered verify_registration(std::string_view client_data_json,
                               const std::vector<unsigned char>& attestation_object,
                               const std::string& rp_id, const std::string& challenge) {
    const ClientData cd = parse_client_data(client_data_json);
    const std::string auth = auth_data_of_attestation(attestation_object.data(),
                                                      attestation_object.size());
    const AuthData ad = parse_auth_data(reinterpret_cast<const unsigned char*>(auth.data()),
                                        auth.size(), true);
    check_common(cd, "webauthn.create", ad, rp_id, challenge);
    Registered r;
    r.credential_id = jws::base64url_encode(
        reinterpret_cast<const unsigned char*>(ad.credential_id.data()), ad.credential_id.size());
    r.spki = ad.spki;
    r.alg = ad.alg;
    r.sign_count = ad.sign_count;
    return r;
}

uint32_t verify_assertion(std::string_view client_data_json,
                          const std::vector<unsigned char>& authenticator_data,
                          const std::vector<unsigned char>& signature,
                          const std::string& rp_id, const std::string& challenge,
                          const std::string& spki, int alg) {
    const ClientData cd = parse_client_data(client_data_json);
    const AuthData ad = parse_auth_data(authenticator_data.data(), authenticator_data.size(), false);
    check_common(cd, "webauthn.get", ad, rp_id, challenge);

    const unsigned char* q = reinterpret_cast<const unsigned char*>(spki.data());
    EVP_PKEY* raw = d2i_PUBKEY(nullptr, &q, static_cast<long>(spki.size()));
    if (!raw) bad("the stored public key cannot be read");
    PkeyPtr pk(raw, EVP_PKEY_free);
    // Only the algorithm the key was registered with, and only with its own key type.
    const EVP_MD* md = nullptr;
    if (alg == kES256 && EVP_PKEY_is_a(pk.get(), "EC")) md = EVP_sha256();
    else if (alg == kRS256 && EVP_PKEY_is_a(pk.get(), "RSA")) md = EVP_sha256();
    else if (alg == kEdDSA && EVP_PKEY_is_a(pk.get(), "ED25519")) md = nullptr;
    else bad("the stored key does not match its algorithm");

    std::string msg(authenticator_data.begin(), authenticator_data.end());
    msg += sha256(reinterpret_cast<const unsigned char*>(client_data_json.data()),
                  client_data_json.size());
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const bool ok = ctx && EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pk.get()) == 1 &&
                    EVP_DigestVerify(ctx, signature.data(), signature.size(),
                                     reinterpret_cast<const unsigned char*>(msg.data()),
                                     msg.size()) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) bad("the signature does not verify");
    return ad.sign_count;
}

} // namespace pki::webauthn
