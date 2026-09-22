#pragma once
// XML reading for the MS-XCEP / MS-WSTEP path.
//
// This parses **fully attacker-controlled bytes, before authentication**: every WSTEP
// request reaches it to recover MessageID, BinarySecurityToken, Username and Password.
//
// It used to be a hand-rolled find/substr byte scanner, justified in src/msxcep/main.cpp
// as "XML construction + extraction is simpler and dependency-free". That justification
// was false for the artifact we ship: pki_lib has linked libxml2 since the SAML work, so
// every binary already carried a real XML parser while the most exposed parser in the
// codebase remained a hand-written one. The scanner is gone; libxml2 does the reading.
//
// ⚠️ A real parser is only safer if it is CONFIGURED to be. libxml2 will happily resolve
// entities and fetch external ones unless told not to, and swapping a byte scanner — which
// cannot expand an entity because it does not understand them — for a misconfigured real
// parser would be a downgrade, not an upgrade. See src/lib/xml.cpp for the exact posture;
// tests/ms_xxe.sh proves XXE, external DTD and expansion bombs fail CLOSED.
#include <optional>
#include <string>
#include <string_view>

namespace pki {

// A parsed, hardened XML document. Parse ONCE per request and extract many times.
//
// That shape is deliberate: handle_wstep needs four separate values out of one body, and
// re-parsing per value would build the DOM four times for every unauthenticated request —
// turning a real parser into a DoS amplifier the byte scanner never was.
class XmlDoc {
public:
    // Parse `xml` with entity substitution, external entities, DTD loading, network access
    // and XInclude all OFF, and a DOCTYPE of any kind refused outright.
    //
    // Returns nullopt when the document is malformed, carries a DOCTYPE, or exceeds
    // kMaxBytes. Callers must treat that as "reject the request", not "field absent" —
    // there is no partial/recovered parse.
    static std::optional<XmlDoc> parse(std::string_view xml);

    // Text content of the FIRST element (document order) whose *local* name equals
    // `local`, ignoring any namespace prefix. std::nullopt when no such element exists.
    //
    // ⚠️ Unlike the byte scanner this replaced, the result is DECODED: `&amp;` arrives as
    // `&`, `&#xD;` as a carriage return. That is what the sender actually meant, and it
    // removes the partial hand-rolled `&#xD;` stripper the base64 path used to need.
    std::optional<std::string> text(std::string_view local) const;

    // Hard input cap. This runs pre-auth on request bodies; a real WSTEP enrolment is a
    // few KB, so anything approaching this is not a client we need to serve.
    static constexpr size_t kMaxBytes = 1u << 20;   // 1 MiB

    ~XmlDoc();
    XmlDoc(XmlDoc&&) noexcept;
    XmlDoc& operator=(XmlDoc&&) noexcept;
    XmlDoc(const XmlDoc&) = delete;
    XmlDoc& operator=(const XmlDoc&) = delete;

private:
    explicit XmlDoc(void* doc) : doc_(doc) {}
    void* doc_;   // xmlDocPtr, kept opaque so libxml2 headers stay out of every TU
};

// Escape text for inclusion in served XML. Escapes & < > " AND ' — the apostrophe matters
// only inside single-quoted attribute values, but a function that is correct in one context
// and not the other is how the two former copies of this drifted apart.
std::string xml_escape(std::string_view s);

}  // namespace pki
