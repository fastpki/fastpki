#include "pki/xml.hpp"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlversion.h>

#include <mutex>

namespace pki {
namespace {

// ---------------------------------------------------------------------------
// Process-wide hardening.
//
// Done under call_once inside parse() rather than exported as an init function every
// main() must remember to call. An "install the safe entity loader" step that one binary
// forgets is indistinguishable from one that was never written — and this is the path that
// reads unauthenticated request bodies.
// ---------------------------------------------------------------------------

// Refuse EVERY external resource, whatever the parser options say. This is the braces to
// XML_PARSE_NONET's belt: NONET blocks http/ftp, so without this a `file:///` SYSTEM id is
// still a local-file read. Returning nullptr makes libxml2 raise a load error and fail.
extern "C" xmlParserInputPtr deny_all_external_entities(const char*, const char*,
                                                        xmlParserCtxtPtr) {
    return nullptr;
}

void harden_once() {
    static std::once_flag once;
    std::call_once(once, [] {
        xmlInitParser();
        xmlSetExternalEntityLoader(&deny_all_external_entities);
        // Beat any global another module may have set: libxml2 2.9's option handling is
        // set-only for these, so a stale global would survive our clean option mask.
        //
        // ⚠️ DEPRECATED IN libxml2 2.14 AND STILL REQUIRED HERE. The replacement is
        // per-parser-context options, which is exactly what our clean option mask already
        // does — but this call is not about OUR parser. It resets the process-wide default
        // that some other library in the image may have switched on, and there is no
        // non-deprecated way to do that. Suppressed narrowly, at this one call, so the
        // rest of the file keeps reporting deprecations: a blanket -Wno for the target
        // would hide the next one.
#if defined(__GNUC__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
        xmlSubstituteEntitiesDefault(0);
#if defined(__GNUC__)
#  pragma GCC diagnostic pop
#endif
    });
}

// The option mask. Nearly all of the safety here is achieved by NOT setting a flag —
// libxml2 with options 0 already leaves entity substitution, DTD loading and validation
// off, so the danger is entirely in what gets added. In particular:
//
//   ⚠️ XML_PARSE_NOENT does NOT mean "no entities". parser.h spells it
//      `XML_PARSE_NOENT = 1<<1, /* substitute entities */` — it sets replaceEntities=1,
//      and passing it is the single most common way a safe libxml2 config becomes a
//      working XXE. It is absent here on purpose and must stay absent.
//
// Deliberately NOT set: NOENT, DTDLOAD, DTDATTR, DTDVALID, XINCLUDE, HUGE, RECOVER, SAX1.
constexpr int kParseOptions =
      XML_PARSE_NONET        // no http/ftp fetches
    | XML_PARSE_NOERROR      // do not write parse errors to stderr
    | XML_PARSE_NOWARNING
    | XML_PARSE_NSCLEAN      // collapse redundant ns decls (ns-flood hygiene)
    | XML_PARSE_NOCDATA      // CDATA -> text, so extraction has one path
#if LIBXML_VERSION >= 21300
    // 2.13+ only. Refuses external entities outright instead of relying on the loader
    // above. Alpine (what we ship) has 2.13.9; the macOS SDK has 2.9.13, where the
    // guarantee comes from deny_all_external_entities() plus the DOCTYPE refusal below.
    | XML_PARSE_NO_XXE
#endif
    ;

// Depth-first pre-order search for the first element with this local name. `n->name` is
// already the LOCAL name in libxml2 — the prefix lives in n->ns — so this is namespace
// -prefix-insensitive by construction, which is what every caller wants (wsse:Username and
// Username are the same field). No XPath: that would mean compiling an expression built
// from a caller-supplied string to answer "first element named X".
const xmlNode* find_first(const xmlNode* n, std::string_view local) {
    for (; n; n = n->next) {
        if (n->type == XML_ELEMENT_NODE && n->name &&
            local == reinterpret_cast<const char*>(n->name))
            return n;
        if (const xmlNode* hit = find_first(n->children, local)) return hit;
    }
    return nullptr;
}

}  // namespace

std::optional<XmlDoc> XmlDoc::parse(std::string_view xml) {
    if (xml.empty() || xml.size() > kMaxBytes) return std::nullopt;
    harden_once();

    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (!ctxt) return std::nullopt;
    // Force the fields directly as well as through the option mask. In 2.9.x
    // xmlCtxtUseOptionsInternal() only ever SETS these from the mask and never clears
    // them, so a global left on elsewhere would otherwise survive our clean options.
    // ⚠️ These three fields are deprecated in libxml2 2.14 and still required. The
    // replacement is the option mask, which is already passed below — but the whole point
    // of writing them directly is that 2.9.x's option handling only ever SETS from the
    // mask and never clears, so a global another module left on would survive it. Belt and
    // braces on a security boundary; suppressed at exactly these three lines so the rest of
    // the file keeps reporting deprecations.
#if defined(__GNUC__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    ctxt->replaceEntities = 0;
    ctxt->loadsubset      = 0;
    ctxt->validate        = 0;
#if defined(__GNUC__)
#  pragma GCC diagnostic pop
#endif

    // URL and encoding are both null on purpose: a non-null URL becomes the base URI for
    // resolving relative external references, and the encoding must never be taken from an
    // attacker-supplied Content-Type charset.
    xmlDocPtr doc = xmlCtxtReadMemory(ctxt, xml.data(), static_cast<int>(xml.size()),
                                      nullptr, nullptr, kParseOptions);
    xmlFreeParserCtxt(ctxt);
    if (!doc) return std::nullopt;

    // ⚠️ Refuse any DOCTYPE, before reading a single node. SOAP 1.1 and 1.2 both forbid a
    // DTD in a message, so there is no legitimate one in this input — and refusing the
    // declaration outright is a stronger guarantee than any combination of parser flags,
    // because it removes the entity machinery rather than configuring it. Same posture as
    // src/lib/saml.cpp's xmlGetIntSubset() check.
    if (doc->intSubset || doc->extSubset) { xmlFreeDoc(doc); return std::nullopt; }

    return XmlDoc(doc);
}

std::optional<std::string> XmlDoc::text(std::string_view local) const {
    if (local.empty() || !doc_) return std::nullopt;
    const xmlNode* root = xmlDocGetRootElement(static_cast<xmlDocPtr>(doc_));
    const xmlNode* hit = find_first(root, local);
    if (!hit) return std::nullopt;

    // Safe because a DOCTYPE is refused above: with no entity declarations in the document
    // there is no entity-reference subtree for this to walk into.
    xmlChar* c = xmlNodeGetContent(const_cast<xmlNode*>(hit));
    if (!c) return std::string();
    std::string out(reinterpret_cast<const char*>(c));
    xmlFree(c);
    return out;
}

XmlDoc::~XmlDoc() { if (doc_) xmlFreeDoc(static_cast<xmlDocPtr>(doc_)); }

XmlDoc::XmlDoc(XmlDoc&& o) noexcept : doc_(o.doc_) { o.doc_ = nullptr; }

XmlDoc& XmlDoc::operator=(XmlDoc&& o) noexcept {
    if (this != &o) {
        if (doc_) xmlFreeDoc(static_cast<xmlDocPtr>(doc_));
        doc_ = o.doc_;
        o.doc_ = nullptr;
    }
    return *this;
}

std::string xml_escape(std::string_view s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s) switch (c) {
        case '&':  o += "&amp;";  break;
        case '<':  o += "&lt;";   break;
        case '>':  o += "&gt;";   break;
        case '"':  o += "&quot;"; break;
        case '\'': o += "&apos;"; break;
        default:   o += c;
    }
    return o;
}

}  // namespace pki
