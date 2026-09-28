// libFuzzer harness for the MS-XCEP / MS-WSTEP XML extraction.
//
// pki::XmlDoc is the XML reader every Windows enrolment request passes through *before
// authentication*: fastpki-ms pulls MessageID, BinarySecurityToken, Username and Password
// out of the raw SOAP body with it. libxml2 replaced the hand-rolled find/substr scanner,
// libxml2, so what this harness fuzzes now is our *configuration* of a real parser — the
// hardening in src/lib/xml.cpp, the DOCTYPE refusal, and the ownership of the document.
//
// The invariant is the same as the other harnesses: no crash, no overread, no UB, no hang
// on any input. Malformed input must yield a clean nullopt or some string — never a fault.
#include "pki/xml.hpp"

#include "lsan_suppressions.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string doc(reinterpret_cast<const char*>(data), size);

    // ONE parse, then many extractions — the shape the product uses. A document
    // that libxml2 rejects, or that carries a DOCTYPE, yields nullopt and there is nothing
    // more to do with it; that refusal path is itself worth fuzzing.
    auto parsed = pki::XmlDoc::parse(doc);
    if (!parsed) return 0;

    // The names the WSTEP path actually asks for. Fuzzing the *document* while holding the
    // element names fixed is the right way round: an attacker controls the body, not which
    // fields fastpki-ms looks for.
    static const char* kNames[] = {"MessageID", "BinarySecurityToken",
                                   "Username", "Password", "RequestType"};
    for (const char* n : kNames) (void)parsed->text(n);

    // Also drive the name side from the fuzzed bytes: the first line of the input as an
    // element name. This reaches the lookup with names that are empty, longer than the
    // document, or contain '<' and '/' — the cases hand-written callers never produce.
    const size_t nl = doc.find('\n');
    if (nl != std::string::npos && nl < 64) (void)parsed->text(doc.substr(0, nl));
    (void)parsed->text(std::string());

    // Move-assignment and destruction on every input, so a double-free or leak in the
    // ownership transfer shows up under ASan/LSan rather than only in production.
    pki::XmlDoc moved = std::move(*parsed);
    (void)moved.text("Username");

    // xml_escape now lives beside the parser and runs on every served response.
    (void)pki::xml_escape(doc);
    return 0;
}
