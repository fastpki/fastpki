#pragma once
#include <stdexcept>
#include <string>

namespace pki {

class Error : public std::runtime_error {
public:
    Error(int code, std::string msg)
        : std::runtime_error(std::move(msg)), code_(code) {}
    int code() const noexcept { return code_; }
private:
    int code_;
};

// ⚠️ THE PKCS#11 TOKEN DID NOT ANSWER — as distinct from answering and holding no object
// under that label, which is code 2 and is the ordinary state of a fresh install.
//
// The difference decides whether a process can usefully carry on. PKCS#11 is initialised
// ONCE per process, so a provider that came up against an absent token stays broken for
// that process's life: measured, a listener in that state never recovered across four
// 20-second retries while a FRESH process read the same object without trouble. Nothing
// short of a new process fixes it, which is why a caller branches on this rather than
// retrying.
//
// It is a code and not a message match because the two cases are told apart by whether the
// OpenSSL error queue is empty, and that is known only where the throw happens. Codes 1 and
// 2 already mean "client error" and "server error" to the protocol binaries, which test for
// 1 specifically, so this reads as a server error wherever it is not handled.
inline constexpr int kErrTokenUnavailable = 3;

// Pull the latest OpenSSL error queue into a string (for diagnostics).
std::string openssl_errors();

} // namespace pki
