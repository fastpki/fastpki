#pragma once
// A CBOR reader (RFC 8949) for the small, untrusted objects WebAuthn produces: the ACME
// device attestation object, and a passkey's attestation object, authenticator data and COSE
// public key. Definite lengths only, which is all CTAP2's canonical encoding uses.
//
// Bounded rather than general: nesting stops at kMaxDepth and every length is checked
// against what is left of the input BEFORE it is used, so a length field claiming 2^64 bytes
// is a clean error, never an allocation or an out-of-bounds read. Every error throws
// pki::Error(1, "<what>: <reason>"). It reads bytes straight off the network before any
// signature is checked — fuzzed by fuzz/fuzz_attest.cpp and fuzz/fuzz_webauthn.cpp.
#include "pki/error.hpp"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace pki::cbor {

constexpr int kMaxDepth = 8;

struct Reader {
    const unsigned char* p;
    const unsigned char* end;
    const char* what;   // names the object in every error: "attestation object", ...

    [[noreturn]] void bad(const char* why) const {
        throw Error(1, std::string(what) + ": " + why);
    }
    unsigned char byte() {
        if (p >= end) bad("truncated");
        return *p++;
    }
    // Reads an item head: returns the major type and sets `arg`.
    int head(uint64_t& arg) {
        const unsigned char b = byte();
        const int major = b >> 5;
        const int info = b & 0x1f;
        if (info < 24) { arg = static_cast<uint64_t>(info); return major; }
        int n = 0;
        switch (info) {
            case 24: n = 1; break;
            case 25: n = 2; break;
            case 26: n = 4; break;
            case 27: n = 8; break;
            case 31: bad("indefinite lengths are not accepted");
            default: bad("reserved additional-information value");
        }
        arg = 0;
        for (int i = 0; i < n; ++i) arg = (arg << 8) | byte();
        return major;
    }
    size_t left() const { return static_cast<size_t>(end - p); }
    std::string_view take(uint64_t n) {
        if (n > left()) bad("length runs past the end");
        std::string_view v(reinterpret_cast<const char*>(p), static_cast<size_t>(n));
        p += n;
        return v;
    }
    // Skips one complete item of any type.
    void skip(int depth) {
        if (depth > kMaxDepth) bad("nested too deeply");
        uint64_t arg = 0;
        const int major = head(arg);
        switch (major) {
            case 0: case 1: return;                      // integers
            case 2: case 3: (void)take(arg); return;     // byte / text string
            case 4:                                      // array
                if (arg > left()) bad("array count runs past the end");
                for (uint64_t i = 0; i < arg; ++i) skip(depth + 1);
                return;
            case 5:                                      // map
                if (arg > left() / 2) bad("map count runs past the end");
                for (uint64_t i = 0; i < arg; ++i) { skip(depth + 1); skip(depth + 1); }
                return;
            case 6: skip(depth + 1); return;             // tag: skip the tagged item
            default:                                     // 7: simple values and floats
                return;                                  // head() already consumed their bytes
        }
    }
    std::string text() {
        uint64_t n = 0;
        if (head(n) != 3) bad("expected a text string");
        return std::string(take(n));
    }
    std::vector<unsigned char> bytes() {
        uint64_t n = 0;
        if (head(n) != 2) bad("expected a byte string");
        const std::string_view v = take(n);
        return std::vector<unsigned char>(v.begin(), v.end());
    }
    // An integer, major type 0 or 1, within int64 range.
    int64_t integer() {
        uint64_t n = 0;
        const int major = head(n);
        if (major != 0 && major != 1) bad("expected an integer");
        if (n > static_cast<uint64_t>(INT64_MAX)) bad("integer out of range");
        return major == 0 ? static_cast<int64_t>(n) : -1 - static_cast<int64_t>(n);
    }
    uint64_t map_count() {
        uint64_t n = 0;
        if (head(n) != 5) bad("expected a map");
        if (n > left() / 2) bad("map count runs past the end");
        return n;
    }
    uint64_t array_count() {
        uint64_t n = 0;
        if (head(n) != 4) bad("expected an array");
        if (n > left()) bad("array count runs past the end");
        return n;
    }
    // Reads a map key when it is a text string; otherwise skips the key and returns "".
    // Keys of other types are legal CBOR and are simply not ones the caller looks for.
    std::string key() {
        if (p >= end) bad("truncated");
        if ((*p >> 5) == 3) return text();
        skip(1);
        return {};
    }
    // The major type of the next item, without consuming it.
    int peek_major() const {
        if (p >= end) bad("truncated");
        return *p >> 5;
    }
};

} // namespace pki::cbor
