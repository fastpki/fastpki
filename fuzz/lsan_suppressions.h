#pragma once
// ⚠️ Why every fuzz harness needs this.
//
// libFuzzer's own driver allocates 56 bytes it never frees — 8 bytes plus a 48-byte
// object, both from `operator new` inside fuzzer::FuzzerDriver() (FuzzerDriver.cpp:832
// in clang 22 / compiler-rt on musl). LeakSanitizer reports them, and libFuzzer treats a
// leak found while reading the seed corpus as fatal:
//
//     INFO: a leak has been found in the initial corpus.
//     SUMMARY: AddressSanitizer: 56 byte(s) leaked in 2 allocation(s).
//     stat::number_of_executed_units: 4
//
// Four executions in a fifteen-minute campaign, exit code 0 from the wrapper, and
// "crashes: 0" in the summary. That is the exact failure this ticket already caught
// once: a tool that never ran, reporting nothing wrong. It cost a whole campaign before
// the stack was symbolized and showed the allocation was never ours.
//
// The allocation is constant — identical with one input and with eight, and present on
// an EMPTY input where the parser allocates nothing — so it is one-time driver
// bookkeeping, not anything FastPKI can free.
//
// The suppression is therefore matched on libFuzzer's own frame and nothing else. It
// deliberately does NOT suppress by allocator (`malloc`, `CRYPTO_zalloc`) or by library:
// those would hide real leaks in pki_lib and in OpenSSL calls we make, which is most of
// what running LSan is for. With this in place the nightly campaign runs with leak
// detection ON, where it belongs.
extern "C" const char* __lsan_default_suppressions() {
    return "leak:fuzzer::FuzzerDriver\n";
}
