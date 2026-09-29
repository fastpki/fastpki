// passkey-authn — a software passkey authenticator for tests/web_passkeys.sh.
//
// It plays the phone: it creates a key pair and answers the console's registration and
// sign-in challenges exactly as a browser would hand them to the server — clientDataJSON, a
// "none" attestation object carrying the authenticator data and COSE key, and an assertion
// signed over authenticatorData || SHA-256(clientDataJSON). Flags let a test produce the
// answers a real authenticator must never be accepted with (no user verification, the wrong
// origin, another site's rp id, the wrong ceremony type).
//
// TEST-ONLY, named without the fastpki- prefix: the image copies `fastpki-*` by glob.
//
//   passkey-authn register --key k.pem --rp <rp id> --origin <origin> --challenge <b64url>
//                          [--alg es256|ed25519|rs256] [--no-uv] [--type T] [--rp-hash <rp id>]
//        writes the private key to k.pem and the credential id to k.pem.id; prints
//        {"clientDataJSON":..., "attestationObject":...}
//   passkey-authn assert   --key k.pem --rp <rp id> --origin <origin> --challenge <b64url>
//                          [--count N] [--no-uv] [--type T] [--rp-hash <rp id>] [--user-handle H]
//        prints {"id":..., "clientDataJSON":..., "authenticatorData":..., "signature":...,
//                "userHandle":...}
#include "pki/jws.hpp"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;

[[noreturn]] void die(const std::string& m) { std::cerr << "passkey-authn: " << m << "\n"; std::exit(2); }

std::string b64u(const Bytes& b) { return pki::jws::base64url_encode(b.data(), b.size()); }
std::string b64u(const std::string& s) {
    return pki::jws::base64url_encode(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}

Bytes sha256(const std::string& s) {
    Bytes h(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), h.data());
    return h;
}

// ---- a CBOR writer for the few shapes WebAuthn needs --------------------------------------
void head(Bytes& o, int major, uint64_t v) {
    const unsigned char m = static_cast<unsigned char>(major << 5);
    if (v < 24) { o.push_back(m | static_cast<unsigned char>(v)); return; }
    int n = v < 0x100 ? 1 : v < 0x10000 ? 2 : v < 0x100000000ULL ? 4 : 8;
    o.push_back(m | static_cast<unsigned char>(n == 1 ? 24 : n == 2 ? 25 : n == 4 ? 26 : 27));
    for (int i = n - 1; i >= 0; --i) o.push_back(static_cast<unsigned char>(v >> (8 * i)));
}
void cint(Bytes& o, int64_t v) {
    if (v >= 0) head(o, 0, static_cast<uint64_t>(v));
    else head(o, 1, static_cast<uint64_t>(-1 - v));
}
void cbytes(Bytes& o, const Bytes& b) { head(o, 2, b.size()); o.insert(o.end(), b.begin(), b.end()); }
void ctext(Bytes& o, const std::string& s) { head(o, 3, s.size()); o.insert(o.end(), s.begin(), s.end()); }

Bytes bn_bytes(EVP_PKEY* pk, const char* name) {
    BIGNUM* bn = nullptr;
    if (EVP_PKEY_get_bn_param(pk, name, &bn) != 1) die(std::string("no ") + name);
    Bytes b(static_cast<size_t>(BN_num_bytes(bn)));
    BN_bn2bin(bn, b.data());
    BN_free(bn);
    return b;
}

Bytes cose_key(EVP_PKEY* pk) {
    Bytes o;
    if (EVP_PKEY_is_a(pk, "EC")) {
        unsigned char pt[65]; size_t n = 0;
        if (EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY, pt, sizeof pt, &n) != 1 || n != 65)
            die("cannot read the EC point");
        head(o, 5, 5);
        cint(o, 1); cint(o, 2); cint(o, 3); cint(o, -7); cint(o, -1); cint(o, 1);
        cint(o, -2); cbytes(o, Bytes(pt + 1, pt + 33));
        cint(o, -3); cbytes(o, Bytes(pt + 33, pt + 65));
    } else if (EVP_PKEY_is_a(pk, "ED25519")) {
        Bytes x(32); size_t n = 32;
        if (EVP_PKEY_get_raw_public_key(pk, x.data(), &n) != 1) die("cannot read the Ed25519 key");
        head(o, 5, 4);
        cint(o, 1); cint(o, 1); cint(o, 3); cint(o, -8); cint(o, -1); cint(o, 6);
        cint(o, -2); cbytes(o, x);
    } else {
        head(o, 5, 4);
        cint(o, 1); cint(o, 3); cint(o, 3); cint(o, -257);
        cint(o, -1); cbytes(o, bn_bytes(pk, OSSL_PKEY_PARAM_RSA_N));
        cint(o, -2); cbytes(o, bn_bytes(pk, OSSL_PKEY_PARAM_RSA_E));
    }
    return o;
}

Bytes sign(EVP_PKEY* pk, const Bytes& msg) {
    const EVP_MD* md = EVP_PKEY_is_a(pk, "ED25519") ? nullptr : EVP_sha256();
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    size_t n = 0;
    if (!ctx || EVP_DigestSignInit(ctx, nullptr, md, nullptr, pk) != 1 ||
        EVP_DigestSign(ctx, nullptr, &n, msg.data(), msg.size()) != 1) die("sign init failed");
    Bytes sig(n);
    if (EVP_DigestSign(ctx, sig.data(), &n, msg.data(), msg.size()) != 1) die("sign failed");
    sig.resize(n);
    EVP_MD_CTX_free(ctx);
    return sig;
}

std::string read_file(const std::string& p) {
    std::ifstream f(p);
    if (!f) die("cannot read " + p);
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) die("usage: passkey-authn register|assert --key K --rp R --origin O --challenge C ...");
    const std::string cmd = argv[1];
    std::map<std::string, std::string> a;
    for (int i = 2; i < argc; ++i) {
        std::string k = argv[i];
        if (k == "--no-uv") { a[k] = "1"; continue; }
        if (i + 1 >= argc) die("missing value for " + k);
        a[k] = argv[++i];
    }
    auto need = [&](const char* k) { if (!a.count(k)) die(std::string("missing ") + k); return a[k]; };
    const std::string keyf = need("--key"), rp = need("--rp"), origin = need("--origin"),
                      challenge = need("--challenge");
    const std::string rp_for_hash = a.count("--rp-hash") ? a["--rp-hash"] : rp;
    const bool reg = cmd == "register";
    if (!reg && cmd != "assert") die("unknown command " + cmd);
    const std::string type = a.count("--type") ? a["--type"] : (reg ? "webauthn.create" : "webauthn.get");
    const std::string cdj = "{\"type\":\"" + type + "\",\"challenge\":\"" + challenge +
                            "\",\"origin\":\"" + origin + "\",\"crossOrigin\":false}";
    unsigned char flags = 0x01 | (a.count("--no-uv") ? 0 : 0x04);
    const uint32_t count = a.count("--count") ? static_cast<uint32_t>(std::stoul(a["--count"])) : 0;

    Bytes auth = sha256(rp_for_hash);
    EVP_PKEY* pk = nullptr;
    if (reg) {
        const std::string alg = a.count("--alg") ? a["--alg"] : "es256";
        pk = alg == "ed25519" ? EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519")
           : alg == "rs256"   ? EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<size_t>(2048))
                              : EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
        if (!pk) die("key generation failed");
        FILE* f = std::fopen(keyf.c_str(), "w");
        if (!f || PEM_write_PrivateKey(f, pk, nullptr, nullptr, 0, nullptr, nullptr) != 1) die("cannot write the key");
        std::fclose(f);
        Bytes id(16);
        if (RAND_bytes(id.data(), 16) != 1) die("RAND_bytes failed");
        std::ofstream(keyf + ".id") << b64u(id) << "\n";
        flags |= 0x40;
        auth.push_back(flags);
        for (int i = 3; i >= 0; --i) auth.push_back(static_cast<unsigned char>(count >> (8 * i)));
        auth.insert(auth.end(), 16, 0);                                    // AAGUID
        auth.push_back(0); auth.push_back(static_cast<unsigned char>(id.size()));
        auth.insert(auth.end(), id.begin(), id.end());
        const Bytes key = cose_key(pk);
        auth.insert(auth.end(), key.begin(), key.end());
        Bytes att;
        head(att, 5, 3);
        ctext(att, "fmt"); ctext(att, "none");
        ctext(att, "attStmt"); head(att, 5, 0);
        ctext(att, "authData"); cbytes(att, auth);
        std::cout << "{\"clientDataJSON\":\"" << b64u(cdj) << "\",\"attestationObject\":\""
                  << b64u(att) << "\"}\n";
    } else {
        FILE* f = std::fopen(keyf.c_str(), "r");
        if (!f) die("cannot read " + keyf);
        pk = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
        std::fclose(f);
        if (!pk) die("cannot parse " + keyf);
        auth.push_back(flags);
        for (int i = 3; i >= 0; --i) auth.push_back(static_cast<unsigned char>(count >> (8 * i)));
        Bytes msg = auth;
        const Bytes h = sha256(cdj);
        msg.insert(msg.end(), h.begin(), h.end());
        const Bytes sig = sign(pk, msg);
        std::cout << "{\"id\":\"" << read_file(keyf + ".id") << "\",\"clientDataJSON\":\"" << b64u(cdj)
                  << "\",\"authenticatorData\":\"" << b64u(auth) << "\",\"signature\":\"" << b64u(sig)
                  << "\",\"userHandle\":\"" << (a.count("--user-handle") ? a["--user-handle"] : "")
                  << "\"}\n";
    }
    EVP_PKEY_free(pk);
    return 0;
}
