#include "pki/ra_reload.hpp"

#include <chrono>
#include <thread>
#include <utility>

#include "pki/log.hpp"
#include "pki/pkcs11_helpers.hpp"

namespace pki {

void watch_for_ra_key(std::string key_ref, Config cfg, std::string service,
                      std::function<void(EvpPkeyPtr)> on_ready) {
    if (key_ref.empty() || !on_ready) return;

    log::info(service + ": watching for the RA credential to appear at '" +
              pkcs11_uri_redacted(key_ref) + "' — re-checking every " +
              std::to_string(kRaReloadIntervalSec) + "s, so a key replicated or created "
              "after startup takes effect without a restart.");

    std::thread([key_ref = std::move(key_ref), cfg = std::move(cfg),
                 service = std::move(service), on_ready = std::move(on_ready)]() {
        for (;;) {
            std::this_thread::sleep_for(std::chrono::seconds(kRaReloadIntervalSec));
            EvpPkeyPtr k;
            // ⚠️ A THROW HERE IS THE ORDINARY CASE, NOT AN ERROR, and it must not be logged
            // as one. The key is absent until somebody creates or replicates it, which may
            // be days; load_key_file_or_token throws for an empty token the same way it
            // throws for a broken one, and a line per attempt would bury the one message
            // that matters in a log nobody then reads.
            try { k = load_key_file_or_token(key_ref, cfg); }
            catch (const std::exception&) { continue; }
            catch (...) { continue; }
            if (!k) continue;
            // ⚠️ ONCE, THEN GONE. Handing the key over is the end of this thread's job: the
            // caller publishes it and every later request sees it, so a second pass would
            // re-publish a credential that is already live. It also means a healthy node
            // carries no watcher at all.
            try { on_ready(std::move(k)); }
            catch (const std::exception& e) {
                log::err(service + ": the RA credential appeared but could not be put into "
                         "service: " + e.what() + " — a restart will pick it up.");
            }
            return;
        }
    }).detach();
}

}  // namespace pki
