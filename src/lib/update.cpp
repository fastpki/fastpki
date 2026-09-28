// Software update check + release-signature verification.
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "pki/update.hpp"
#include "pki/config.hpp"
#include "pki/version.hpp"
#include "../../third_party/httplib.h"
#include "../../third_party/nlohmann/json.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <array>
#include <string>

namespace pki {
namespace {

// Split "scheme://host[:port]/path" into the httplib base ("scheme://host:port")
// and the request path.
bool split_url(const std::string& url, std::string& base, std::string& path) {
    auto p = url.find("://");
    if (p == std::string::npos) return false;
    auto slash = url.find('/', p + 3);
    if (slash == std::string::npos) { base = url; path = "/"; }
    else { base = url.substr(0, slash); path = url.substr(slash); }
    return true;
}

// Parse the leading X.Y.Z of a version (ignoring a leading 'v' and any
// pre-release / git suffix) into a comparable tuple.
std::array<long, 3> semver(const std::string& s) {
    std::string t = s;
    if (!t.empty() && (t[0] == 'v' || t[0] == 'V')) t.erase(0, 1);
    std::array<long, 3> v{0, 0, 0};
    int idx = 0; std::string cur;
    bool saw_dot = false;
    auto flush = [&]{ if (idx < 3) { try { v[idx] = cur.empty() ? 0 : std::stol(cur); } catch (...) { v[idx] = 0; } ++idx; } cur.clear(); };
    for (char c : t) {
        if (c >= '0' && c <= '9') cur += c;
        else if (c == '.') { saw_dot = true; flush(); if (idx >= 3) break; }
        else {
            // A hex letter (a-f) right after digits with no preceding dot means
            // this is a git-hash version like "615b59a-dirty", not a semver.
            if (!saw_dot && !cur.empty() &&
                ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return {0, 0, 0};
            break;
        }
    }
    if (idx < 3) flush();
    return v;
}

bool is_newer(const std::string& latest, const std::string& current) {
    return semver(latest) > semver(current);   // std::array compares lexicographically
}

std::string http_get(const std::string& url, std::string& err) {
    std::string base, path;
    if (!split_url(url, base, path)) { err = "bad URL"; return ""; }
    httplib::Client cli(base.c_str());
    cli.set_connection_timeout(5);
    cli.set_read_timeout(8);
    cli.set_follow_location(true);
    httplib::Headers h = {{"User-Agent", "fastpki-update"}, {"Accept", "application/json"}};
    auto res = cli.Get(path.c_str(), h);
    if (!res) { err = "request failed (offline or TLS error)"; return ""; }
    if (res->status != 200) { err = "HTTP " + std::to_string(res->status); return ""; }
    return res->body;
}

}  // namespace

UpdateInfo check_for_update(const Config& cfg) {
    UpdateInfo u;
    u.current = fastpki_version();
    const bool github = cfg.update_feed_url.empty();
    const std::string url = github
        ? "https://api.github.com/repos/fastpki/fastpki/releases/latest"
        : cfg.update_feed_url;
    std::string err;
    std::string body = http_get(url, err);
    if (!err.empty()) {
        // ⚠️ A GITHUB 404 IS NOT "UP TO DATE". /releases/latest answers 404 both when the
        // repository has no published release and when it is PRIVATE to the caller — and the
        // second is exactly the case where releases exist and this check cannot see them. It
        // reported "Up to date", so an install that could not see its feed looked current.
        if (github && err.find("404") != std::string::npos) {
            u.error = "the release feed answered 404: the repository has no published release, "
                      "or it is not visible without credentials — set UPDATE_FEED_URL to a feed "
                      "this host can read";
            return u;
        }
        u.error = err;
        return u;
    }
    try {
        auto j = nlohmann::json::parse(body);
        if (github) {
            u.latest = j.value("tag_name", "");
            u.notes = j.value("body", "");
            if (j.contains("assets") && j["assets"].is_array() && !j["assets"].empty())
                u.download_url = j["assets"][0].value("browser_download_url", "");
        } else {
            u.latest = j.value("version", "");
            u.notes = j.value("notes", "");
            u.download_url = j.value("url", "");
        }
    } catch (const std::exception& e) {
        u.error = std::string("bad feed JSON: ") + e.what();
        return u;
    }
    if (u.latest.empty()) { u.error = "no version field in the update feed"; return u; }
    u.update_available = is_newer(u.latest, u.current);
    return u;
}
// ⚠️ PINNED AND COMPILED IN. A public key read from a path is a key somebody can replace,
// which would make every signature below prove only that a key existed. RELEASE_PUBKEY
// overrides these for a deployment that signs its own builds; empty means USE THESE, not
// "verify nothing", which is what it used to mean.
//
// Two keys because every artifact is signed twice: ECDSA P-256 so any OpenSSL can check it
// today, including the 3.0 that several long-term distributions still ship, and ML-DSA-87
// (FIPS 204) so the signature still means something after elliptic curves do not. A release
// signature has to be checkable BEFORE our binary is trusted, so an algorithm the
// operator's own openssl cannot read is not sufficient on its own.
const char kReleasePubKeyEcdsa[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkm3I0lmBE/YqkZfr1QBtviiE/bBG\n"
    "Sh/CXT5NtA7TIGNJVZa3U2KEhKN1IGZRkYNHMLtzjpj2GB/cZMfevZH8LA==\n"
    "-----END PUBLIC KEY-----\n";
const char kReleasePubKeyMlDsa[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "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\n"
    "Y/zAhnaZ0whprHZj6R30tEyfBd4myw==\n"
    "-----END PUBLIC KEY-----\n";


bool verify_release_signature(const std::string& pubkey_pem, const std::string& artifact,
                              const std::string& sig) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pubkey_pem.data(), static_cast<int>(pubkey_pem.size())), &BIO_free);
    if (!bio) return false;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pk(
        PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), &EVP_PKEY_free);
    if (!pk) return false;
    // ⚠️ TWO SHAPES OF SIGNATURE, AND THE ALGORITHM DECIDES WHICH. RSA and ECDSA hash the
    // artifact first, so they are initialised with SHA-256 and fed through Update/Final.
    // Ed25519 and ML-DSA do their own hashing internally and REFUSE a separate digest: they
    // are initialised with a null md and verified in one shot. Passing EVP_sha256() to an
    // ML-DSA key does not verify-and-fail, it fails at Init — so a lane that only knew the
    // first shape reported every post-quantum signature as bad rather than as unsupported.
    //
    // Releases are signed with both an ECDSA and an ML-DSA key, so this has to take either
    // without being told which it was handed.
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!ctx) return false;
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pk.get()) == 1) {
        if (EVP_DigestVerifyUpdate(ctx.get(), artifact.data(), artifact.size()) != 1) return false;
        return EVP_DigestVerifyFinal(ctx.get(),
            reinterpret_cast<const unsigned char*>(sig.data()), sig.size()) == 1;
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> one(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!one) return false;
    if (EVP_DigestVerifyInit(one.get(), nullptr, nullptr, nullptr, pk.get()) != 1) return false;
    return EVP_DigestVerify(one.get(),
        reinterpret_cast<const unsigned char*>(sig.data()), sig.size(),
        reinterpret_cast<const unsigned char*>(artifact.data()), artifact.size()) == 1;
}

// Verify against the keys compiled into this build. This is the normal case: an operator
// should be able to check a download without first being told to go and fetch a key, which is
// what an empty RELEASE_PUBKEY used to require.
//
// Either signature satisfies it. A release carries both, and which one a given machine can
// check depends on its OpenSSL — an ML-DSA signature is unreadable to the 3.0 that several
// long-term distributions still ship, and the ECDSA one is there precisely for them.
bool verify_release_signature_pinned(const std::string& artifact, const std::string& sig) {
    return verify_release_signature(kReleasePubKeyEcdsa, artifact, sig)
        || verify_release_signature(kReleasePubKeyMlDsa, artifact, sig);
}

} // namespace pki
