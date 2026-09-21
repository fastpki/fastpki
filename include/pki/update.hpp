// Software update check + release-signature verification. Shared by
// the fastpki-update CLI and the web console's Updates panel.
#pragma once
#include <string>

namespace pki {

struct Config;

struct UpdateInfo {
    std::string current;            // the running version
    std::string latest;            // latest available version (empty if the check failed)
    std::string notes;             // release notes / changelog (best effort)
    std::string download_url;      // artifact URL (best effort)
    std::string error;             // non-empty if the check failed (offline, bad feed, …)
    bool        update_available{false};
};

// Query the update feed and compare to the running version. Uses
// cfg.update_feed_url (a self-hosted JSON manifest) when set, else the
// fastpki/fastpki GitHub Releases API. Never throws — failures land in
// UpdateInfo::error.
UpdateInfo check_for_update(const Config& cfg);

// Verify a detached signature over `artifact` with the PEM public key
// `pubkey_pem` (SHA-256; RSA or ECDSA). Returns true iff valid. Never throws.
bool verify_release_signature(const std::string& pubkey_pem,
                              const std::string& artifact, const std::string& sig);

} // namespace pki
