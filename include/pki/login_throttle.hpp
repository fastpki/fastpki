#pragma once
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace pki {

struct Config;

// ── Online password-guessing backoff ────────────────────────────────────────────────────
//
// Every password door in this product answered as fast as it could, forever. There was no
// counter, no delay and no lockout anywhere: the console login, and the HTTP Basic auth in
// front of EST and MS-WSTEP, would each accept an unlimited number of attempts per second.
// A weak console password is a matter of minutes against that, and the console admin is
// the identity that can register a CA.
//
// ⚠️ TWO DOORS, AND THE SECOND ONE IS NOT THE OBVIOUS ONE. The console does its OWN
// user lookup and password check, and only calls the shared authenticate() when that fails
// AND a directory backend is configured. So a throttle placed inside authenticate() alone
// leaves local console password guessing completely unthrottled — the commonest
// deployment. Both call sites have to consult this, which is why it is a shared component
// rather than a few lines inside either one.
//
// WHAT THIS IS NOT. It is per-process and in memory, so it is per node: a deployment
// running three nodes throttles an attacker three times independently rather than once,
// and a restart clears the counters. Making it shared state would put a database write on
// every failed login and replicate a value that is worthless a minute later. This raises
// the cost of online guessing by orders of magnitude; it is not, and is not meant to be, a
// distributed rate limiter.
//
// Two keys are counted for every attempt — the account and the client address — and the
// LONGER of the two waits applies. Account-only would let one attacker spray many
// usernames from one host; address-only would let a botnet grind one account.
class LoginThrottle {
public:
    // Seconds the caller must wait before this attempt may be made at all; 0 = allowed.
    // Ask BEFORE verifying the password, so a locked-out attempt costs no hashing.
    int retry_after(const std::string& account, const std::string& client_ip);

    // A wrong password. Advances the backoff for both keys.
    void record_failure(const std::string& account, const std::string& client_ip);

    // A correct password. Clears the backoff for both keys — someone who mistypes twice
    // and then succeeds must not carry a penalty into their next login.
    void record_success(const std::string& account, const std::string& client_ip);

    // Policy, from the deployment's configuration.
    void configure(const Config& cfg);

    // Drop all state. For tests, and for an operator clearing a lockout.
    void reset();

    // Test seam: this measures elapsed time, and a suite cannot wait five minutes to prove
    // a lockout expires. Shifts this instance's idea of "now" forward by `sec`.
    void advance_clock_for_test(int64_t sec);

private:
    struct Entry {
        int     failures{0};
        int64_t last{0};      // when the most recent failure was recorded
    };
    int64_t now() const;
    int     wait_for(const Entry& e, int64_t t) const;
    // Called with mu_ held. Bounds the map so that spraying distinct usernames or spoofed
    // addresses cannot grow it without limit — an anti-abuse structure that is itself an
    // abuse vector is not an improvement.
    void evict_locked(int64_t t);

    mutable std::mutex mu_;
    std::unordered_map<std::string, Entry> keys_;
    int     threshold_{5};      // consecutive failures before any delay applies
    int     max_wait_{300};     // ceiling on the backoff, seconds
    size_t  max_keys_{20000};
    int64_t clock_skew_{0};     // test seam only
};

// The process-wide instance. Both password doors consult this one.
LoginThrottle& login_throttle();

}  // namespace pki
