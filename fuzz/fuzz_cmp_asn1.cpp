// libFuzzer harness for FastPKI's own ASN.1 decoder (§1).
//
// parse_cmp_request() in src/lib/cmp_asn1.cpp decodes the raw DER of a CMP
// PKIMessage to recover the fields OpenSSL hides behind private headers (the
// sender, senderKID, the central-keygen flag, the per-RevDetails CRLReason). It
// runs on fully attacker-controlled bytes, so it is exactly the kind of
// hand-rolled parser this fuzzer exists to harden. The invariant: no crash, no
// hang, no leak on any input — malformed input must yield a clean `false`/empty.
#include "pki/cmp_asn1.hpp"

#include "lsan_suppressions.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    pki::CmpRequestInfo info;
    // Exercise the revocation path (bodytype 11 = rr → CRLReason decode) and a
    // non-revocation body (ir = 0) so both branches see the same fuzzed bytes.
    pki::parse_cmp_request(data, static_cast<long>(size), 11, info);
    pki::parse_cmp_request(data, static_cast<long>(size), 0,  info);
    return 0;
}
