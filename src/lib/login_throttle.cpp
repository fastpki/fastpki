#include "pki/login_throttle.hpp"

#include <algorithm>
#include <chrono>
#include <vector>

#include "pki/config.hpp"

namespace pki {
namespace {

// Keys are namespaced so an account called after an address cannot collide with it.
//
// ⚠️ FOLDED AND TRIMMED, because the ACCOUNT LOOKUP is case-insensitive and this was not.
// `admin`, `Admin` and `aDmin` all authenticate against the one PBKDF2 hash, but each got
// its own bucket here — so the doubling backoff, which exists to make online guessing
// uneconomic, was reset by changing the case of a letter. An attacker gets the full
// allowance again per spelling, and 2^n spellings of an n-letter name is not a limit.
// Surrounding whitespace goes the same way, for the same reason.
std::string acct_key(const std::string& a) {
    std::string k = a;
    const auto b = k.find_first_not_of(" \t\r\n");
    const auto e = k.find_last_not_of(" \t\r\n");
    k = (b == std::string::npos) ? std::string() : k.substr(b, e - b + 1);
    for (auto& c : k) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return "u:" + k;
}
std::string addr_key(const std::string& a) { return "a:" + a; }

}  // namespace

int64_t LoginThrottle::now() const {
    using namespace std::chrono;
    return duration_cast<seconds>(steady_clock::now().time_since_epoch()).count() + clock_skew_;
}

// The backoff itself. Nothing happens for the first `threshold_` consecutive failures —
// people mistype passwords, and locking someone out on the third try is how a control
// gets switched off by whoever has to support it. Past that it doubles: 1s, 2s, 4s …
// up to `max_wait_`.
//
// Doubling rather than a flat lockout because the two failure modes want opposite things.
// A real user who is one character out gets a delay they will not notice. An attacker
// grinding a dictionary hits the ceiling within a dozen guesses and stays there for as
// long as they keep going — the delay is measured from the LAST failure, so continuing to
// attack is what keeps them locked out. Stopping for `max_wait_` is the only way through,
// which is exactly the cost being imposed.
int LoginThrottle::wait_for(const Entry& e, int64_t t) const {
    if (e.failures <= threshold_) return 0;
    int over = e.failures - threshold_;
    // Cap the shift before computing it: 1 << 40 is undefined behaviour, and a persistent
    // attacker WILL get the counter that high.
    int64_t window = (over >= 20) ? max_wait_ : (int64_t{1} << (over - 1));
    if (window > max_wait_) window = max_wait_;
    int64_t elapsed = t - e.last;
    if (elapsed >= window) return 0;
    return static_cast<int>(window - elapsed);
}

void LoginThrottle::evict_locked(int64_t t) {
    if (keys_.size() <= max_keys_) return;
    // Anything whose backoff has fully expired is dead weight — drop those first.
    for (auto it = keys_.begin(); it != keys_.end();) {
        if (wait_for(it->second, t) == 0 && t - it->second.last > max_wait_) it = keys_.erase(it);
        else ++it;
    }
    // Still over the bound: an attacker is manufacturing keys faster than they expire.
    // Drop the oldest, never the newest — the newest are the ones currently being
    // throttled, and evicting those would hand the attacker a reset by flooding.
    if (keys_.size() > max_keys_) {
        std::vector<std::pair<int64_t, std::string>> by_age;
        by_age.reserve(keys_.size());
        for (const auto& [k, e] : keys_) by_age.emplace_back(e.last, k);
        std::sort(by_age.begin(), by_age.end());
        size_t drop = keys_.size() - max_keys_ / 2;
        for (size_t i = 0; i < drop && i < by_age.size(); ++i) keys_.erase(by_age[i].second);
    }
}

int LoginThrottle::retry_after(const std::string& account, const std::string& client_ip) {
    std::lock_guard<std::mutex> lk(mu_);
    const int64_t t = now();
    int worst = 0;
    for (const std::string& k : {acct_key(account), addr_key(client_ip)}) {
        if (k.size() <= 2) continue;              // no account, or no address to key on
        auto it = keys_.find(k);
        if (it != keys_.end()) worst = std::max(worst, wait_for(it->second, t));
    }
    return worst;
}

void LoginThrottle::record_failure(const std::string& account, const std::string& client_ip) {
    std::lock_guard<std::mutex> lk(mu_);
    const int64_t t = now();
    for (const std::string& k : {acct_key(account), addr_key(client_ip)}) {
        if (k.size() <= 2) continue;
        Entry& e = keys_[k];
        // Saturate rather than wrap. The window is already clamped, so counting past this
        // buys nothing and an int that rolls over would hand out a free pass.
        if (e.failures < 1000) ++e.failures;
        e.last = t;
    }
    evict_locked(t);
}

void LoginThrottle::record_success(const std::string& account, const std::string& client_ip) {
    std::lock_guard<std::mutex> lk(mu_);
    // ⚠️ Clearing the ADDRESS on success is deliberate, and it is a trade rather than an
    // oversight: an attacker who owns one valid credential can clear their own address
    // penalty by logging in with it. That is not a bypass worth defending against — they
    // already have a working account — and the alternative punishes the real case this
    // exists to protect, an office behind one address where somebody keeps fat-fingering
    // their password while colleagues sign in normally.
    for (const std::string& k : {acct_key(account), addr_key(client_ip)}) {
        if (k.size() <= 2) continue;
        keys_.erase(k);
    }
}

void LoginThrottle::configure(const Config& cfg) {
    std::lock_guard<std::mutex> lk(mu_);
    threshold_ = cfg.login_failure_threshold > 0 ? cfg.login_failure_threshold : 5;
    max_wait_  = cfg.login_lockout_sec > 0 ? cfg.login_lockout_sec : 300;
}

void LoginThrottle::reset() {
    std::lock_guard<std::mutex> lk(mu_);
    keys_.clear();
    clock_skew_ = 0;
}

void LoginThrottle::advance_clock_for_test(int64_t sec) {
    std::lock_guard<std::mutex> lk(mu_);
    clock_skew_ += sec;
}

LoginThrottle& login_throttle() {
    static LoginThrottle t;
    return t;
}

}  // namespace pki
