#pragma once
#include <cstddef>
#include <vector>

namespace pki {

// The DER of the PKCS#10 carried by a CMC full PKI request (RFC 5272), or an EMPTY vector
// when `der` is not one.
//
// ⚠️ A WINDOWS CLIENT ENROLLING THROUGH AN XCEP POLICY DOES NOT SEND A BARE PKCS#10. It
// sends a CMS SignedData whose encapsulated content is id-cct-PKIData, with the PKCS#10
// inside a TaggedCertificationRequest. Handing those bytes to a PKCS#10 parser fails with
// "no start line; wrong tag; nested asn1 error", which is what every real Windows enrolment
// did until this existed.
//
// ⚠️ DETECTED BY CONTENT, NOT BY ValueType. Clients spell the BinarySecurityToken's
// ValueType inconsistently — three registered spellings, and the MS-specific one names
// PKCS10 even for a CMC body — so believing it would swap one failure mode for another.
// Returning empty for anything that is not a CMC is what lets the caller run its ordinary
// bare-PKCS#10 path unchanged.
//
// ⚠️ THIS PARSES BYTES A CALLER SUPPLIED, so it is written to return empty on anything
// unexpected rather than to trust a length. It lives in pki_lib rather than inside the
// msxcep binary for one reason: fuzz/fuzz_cmc.cpp can only reach it here. A hand-rolled DER
// walker with no fuzz harness is the shape of parser this project already fuzzes three of.
//
// The CMC SIGNATURE IS NOT VERIFIED, and that is a bounded decision rather than an
// oversight. Who is asking comes from the authenticated session; proof of possession of the
// requested key comes from the inner PKCS#10's own self-signature, which pki::parse_csr()
// verifies and refuses without. What a CMC signature would add is the enrolment-agent case,
// where the signer is a DIFFERENT party vouching for the subject — MS-WCCE's
// rARequirements, which is advertised as nil because it is not implemented.
std::vector<unsigned char> cmc_extract_pkcs10(const unsigned char* der, size_t n);

} // namespace pki
