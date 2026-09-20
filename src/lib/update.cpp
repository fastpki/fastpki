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

bool verify_release_signature(const std::string& pubkey_pem, const std::string& artifact,
                              const std::string& sig) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pubkey_pem.data(), static_cast<int>(pubkey_pem.size())), &BIO_free);
    if (!bio) return false;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pk(
        PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), &EVP_PKEY_free);
    if (!pk) return false;
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!ctx) return false;
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pk.get()) != 1) return false;
    if (EVP_DigestVerifyUpdate(ctx.get(), artifact.data(), artifact.size()) != 1) return false;
    return EVP_DigestVerifyFinal(ctx.get(),
        reinterpret_cast<const unsigned char*>(sig.data()), sig.size()) == 1;
}

} // namespace pki
