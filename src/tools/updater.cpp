// fastpki-update — report the version, check the update feed, and verify a
// release signature. Applying an update is per deployment and is documented in
// docs/admin-guide.md (Updating FastPKI) and deploy/rolling-update.sh.
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/update.hpp"
#include "pki/version.hpp"

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::stringstream ss; ss << f.rdbuf();
    return ss.str();
}

int usage() {
    std::cerr <<
        "Usage: fastpki-update [--config <bootstrap.conf>] <command>\n"
        "  version                                     print the running version\n"
        "  check                                       check the update feed for a newer release\n"
        "                                              (exit 10 = update available, 0 = up to date)\n"
        "  verify <artifact> <sig> [--pubkey <pem>]    verify a release's detached signature\n"
        "\n"
        "Feed: UPDATE_FEED_URL (a self-hosted JSON manifest) overrides the default\n"
        "GitHub Releases check. RELEASE_PUBKEY pins the signing key for `verify`.\n";
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    std::string conf_path = "config/bootstrap.conf";
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) conf_path = argv[++i];
        else if (std::strcmp(argv[i], "--version") == 0) { std::cout << pki::fastpki_version() << "\n"; return 0; }
        else args.emplace_back(argv[i]);
    }
    if (args.empty()) return usage();
    const std::string cmd = args[0];

    if (cmd == "version") { std::cout << pki::fastpki_version() << "\n"; return 0; }

    pki::Config cfg;
    try { cfg = pki::Config::load(conf_path); } catch (...) { /* defaults are fine for check/verify */ }
    // The stored settings too: UPDATE_FEED_URL and RELEASE_PUBKEY are set on the console's
    // Config page, and neither is read from the environment, so without the overlay only a
    // value in bootstrap.conf ever reached this tool. Best effort: a check or a signature
    // verification must still work on a host that cannot reach the database.
    if (!cfg.pg_conninfo.empty()) {
        try { pki::overlay_config(cfg, pki::make_postgres_db(cfg.pg_conninfo)->get_config()); }
        catch (const std::exception& e) {
            std::cerr << "fastpki-update: database settings not applied (" << e.what()
                      << ") — using " << conf_path << " alone\n";
        }
    }

    if (cmd == "check") {
        pki::UpdateInfo u = pki::check_for_update(cfg);
        std::cout << "current: " << u.current << "\n";
        if (!u.error.empty()) { std::cerr << "check failed: " << u.error << "\n"; return 1; }
        std::cout << "latest:  " << u.latest << "\n";
        if (u.update_available) {
            std::cout << "UPDATE AVAILABLE: " << u.latest << "\n";
            if (!u.download_url.empty()) std::cout << "download: " << u.download_url << "\n";
            return 10;
        }
        std::cout << "up to date\n";
        return 0;
    }

    if (cmd == "verify") {
        if (args.size() < 3) return usage();
        std::string artifact = args[1], sigfile = args[2], pubkey = cfg.release_pubkey;
        for (size_t i = 3; i < args.size(); ++i)
            if (args[i] == "--pubkey" && i + 1 < args.size()) pubkey = args[++i];
        if (pubkey.empty()) { std::cerr << "no release public key (set RELEASE_PUBKEY or pass --pubkey)\n"; return 2; }
        std::string pub = read_file(pubkey), art = read_file(artifact), sig = read_file(sigfile);
        if (pub.empty() || art.empty() || sig.empty()) { std::cerr << "cannot read pubkey/artifact/signature\n"; return 2; }
        bool ok = pki::verify_release_signature(pub, art, sig);
        std::cout << (ok ? "signature OK\n" : "signature INVALID\n");
        return ok ? 0 : 1;
    }

    return usage();
}
