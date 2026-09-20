// pki::cmc_extract_pkcs10 is the DER walker every Windows enrolment request passes through
// on its way to the CSR parser: handle_wstep() base64-decodes the BinarySecurityToken and
// hands the bytes straight here.
//
// ⚠️ WHY THIS HARNESS EXISTS. The other three harnesses cover the ACME JWS parser, our CMP
// ASN.1 decoder and the MS-XCEP XML reader. This parser was added later and had none, and
// nothing in the tree noticed: tests/fuzz_lane.sh asserted that the harnesses which EXIST
// still compile and run, which cannot detect a parser that never got one. A hand-rolled
// walker over caller-supplied bytes with no fuzz coverage is precisely the gap the other
// three were written to close.
//
// ⚠️ AND IT IS NOT PRE-AUTHENTICATION, WHICH LOWERS THE SEVERITY WITHOUT REMOVING IT.
// ms_authenticate() and pki::may_enrol() both run before these bytes are reached, so the
// caller is an identity the deployment issued and permitted to enrol. That is a lower bar
// than it sounds: an enrolling identity is the least-privileged role a PKI hands out, and
// memory corruption inside a CA process is the most severe outcome the product has. A
// parser reachable by the lowest-privileged caller still deserves a fuzzer.
//
// The function is expected to return an empty vector for the overwhelming majority of
// inputs — random bytes are not a CMS. That is not wasted work: the interesting paths are
// the ones where d2i_CMS_ContentInfo SUCCEEDS and the hand-rolled walk over PKIData then
// runs on attacker-shaped lengths and tags, and libFuzzer's coverage feedback finds those
// far better than a corpus written by hand.
#include "pki/cmc.hpp"

#include "lsan_suppressions.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // The caller bounds the body at 1 MiB (msxcep set_payload_max_length), so anything
    // larger is not reachable in the product and only slows the campaign down.
    if (size > 1024u * 1024u) return 0;
    (void)pki::cmc_extract_pkcs10(data, size);
    return 0;
}
