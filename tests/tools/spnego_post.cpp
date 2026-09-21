// spnego-post — a Kerberos/SPNEGO HTTP client, for tests only.
//
// ⚠️ WHY THIS EXISTS AT ALL. tests/ms_kerberos.sh drives a real SPNEGO round-trip against
// fastpki-ms, and the client half of that needs something that can produce a `Negotiate`
// Authorization header. Alpine's curl is built WITHOUT GSS-API:
//
//     curl 8.21.0 (aarch64-alpine-linux-musl) libcurl/8.21.0 OpenSSL/3.5.7 ...
//     $ curl -V | grep GSS-API   ->   nothing
//
// so `curl --negotiate -u :` silently sends no credential and the round-trip cannot run.
// Since the production image is the ONLY place tests run, "skip it here" means the live
// SPNEGO path is never exercised anywhere — which is exactly what was happening.
//
// The alternatives were worse. A GSS-capable curl would mean building curl from source in
// the test image; python-requests-kerberos is out (python exists only as certbot's runtime
// and nothing we own may call it). A small compiled helper is the pattern this repository
// already uses for the same class of problem — tests/tools/dnsstub.cpp exists because shell
// cannot hold the NUL bytes of a DNS packet, and this exists because shell cannot hold a
// GSSAPI context.
//
// ⚠️ DELIBERATELY NOT NAMED fastpki-*. The Docker image copies /src/build/fastpki-* into
// /usr/local/bin, so a fastpki-prefixed name would ship this test client as part of the
// product. dnsstub is named that way for the same reason.
//
// Usage:
//     spnego-post <url> <service-principal> <content-type> <body-file>
//
// Writes the response body to stdout. Exit codes:
//     0  the request completed (any HTTP status — the caller inspects the body)
//     2  usage
//     3  GSSAPI could not produce a token (no ticket, wrong SPN, unreadable ccache)
//     4  the transport failed
//
// TLS verification is deliberately off: the suite's server holds a throwaway self-signed
// certificate, and this tool authenticates the SERVER nowhere — it is testing what the
// server does with a ticket, not who the server is.

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <curl/curl.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string b64(const unsigned char* data, size_t len) {
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        const unsigned b0 = data[i];
        const unsigned b1 = (i + 1 < len) ? data[i + 1] : 0u;
        const unsigned b2 = (i + 2 < len) ? data[i + 2] : 0u;
        out += T[b0 >> 2];
        out += T[((b0 & 0x03u) << 4) | (b1 >> 4)];
        out += (i + 1 < len) ? T[((b1 & 0x0Fu) << 2) | (b2 >> 6)] : '=';
        out += (i + 2 < len) ? T[b2 & 0x3Fu] : '=';
    }
    return out;
}

// Report the GSSAPI failure in the words the library uses. A bare "context failed" is what
// makes SPNEGO problems so hard to place — the minor status is where the real cause is
// (no ticket in the cache, no key for that principal, clock skew).
void report_gss(const char* what, OM_uint32 major, OM_uint32 minor) {
    std::cerr << "spnego-post: " << what << '\n';
    for (int which = 0; which < 2; ++which) {
        OM_uint32 ctx = 0, m = 0;
        const OM_uint32 code = which == 0 ? major : minor;
        const int type = which == 0 ? GSS_C_GSS_CODE : GSS_C_MECH_CODE;
        do {
            gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
            if (gss_display_status(&m, code, type, GSS_C_NO_OID, &ctx, &msg) != GSS_S_COMPLETE)
                break;
            std::cerr << "  " << (which == 0 ? "major: " : "minor: ")
                      << std::string(static_cast<const char*>(msg.value), msg.length) << '\n';
            gss_release_buffer(&m, &msg);
        } while (ctx != 0);
    }
}

size_t sink(char* ptr, size_t sz, size_t n, void* user) {
    static_cast<std::string*>(user)->append(ptr, sz * n);
    return sz * n;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 5) {
        std::cerr << "usage: spnego-post <url> <service-principal> <content-type> <body-file>\n";
        return 2;
    }
    const std::string url = argv[1], spn = argv[2], ctype = argv[3], bodyfile = argv[4];

    std::ifstream in(bodyfile, std::ios::binary);
    if (!in) { std::cerr << "spnego-post: cannot read " << bodyfile << '\n'; return 2; }
    std::ostringstream bs; bs << in.rdbuf();
    const std::string body = bs.str();

    // The SPN as the server will name itself. GSS_C_NT_HOSTBASED_SERVICE takes the
    // `HTTP@host` spelling, which is what a browser and what Windows both send.
    gss_buffer_desc nbuf;
    nbuf.value  = const_cast<char*>(spn.c_str());
    nbuf.length = spn.size();
    gss_name_t target = GSS_C_NO_NAME;
    OM_uint32 major = 0, minor = 0;
    major = gss_import_name(&minor, &nbuf, GSS_C_NT_HOSTBASED_SERVICE, &target);
    if (GSS_ERROR(major)) { report_gss("gss_import_name failed", major, minor); return 3; }

    // ONE leg only. SPNEGO with Kerberos is a single round in practice: the initiator's
    // first token already carries the AP-REQ, and fastpki-ms accepts on it. Mutual
    // authentication is NOT requested, because that is what would make a second leg
    // mandatory — and this tool has nothing to do with the server's identity.
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc out_tok = GSS_C_EMPTY_BUFFER;
    major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &ctx, target,
                                 GSS_C_NO_OID,          // the mechanism krb5 defaults to
                                 0, 0, GSS_C_NO_CHANNEL_BINDINGS,
                                 GSS_C_NO_BUFFER, nullptr, &out_tok, nullptr, nullptr);
    if (GSS_ERROR(major) || out_tok.length == 0) {
        report_gss("gss_init_sec_context produced no token", major, minor);
        OM_uint32 m = 0;
        gss_release_name(&m, &target);
        return 3;
    }
    const std::string token = b64(static_cast<const unsigned char*>(out_tok.value), out_tok.length);
    {
        OM_uint32 m = 0;
        gss_release_buffer(&m, &out_tok);
        gss_release_name(&m, &target);
        if (ctx != GSS_C_NO_CONTEXT) gss_delete_sec_context(&m, &ctx, GSS_C_NO_BUFFER);
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL* c = curl_easy_init();
    if (!c) { std::cerr << "spnego-post: curl_easy_init failed\n"; return 4; }
    std::string resp;
    curl_slist* hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, ("Content-Type: " + ctype).c_str());
    hdrs = curl_slist_append(hdrs, ("Authorization: Negotiate " + token).c_str());
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, sink);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 20L);
    const CURLcode rc = curl_easy_perform(c);
    long status = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(c);
    curl_global_cleanup();
    if (rc != CURLE_OK) {
        std::cerr << "spnego-post: transport failed: " << curl_easy_strerror(rc) << '\n';
        return 4;
    }
    // The HTTP status goes to stderr so a caller can see a 401 without it landing in the
    // response body it is parsing.
    std::cerr << "spnego-post: HTTP " << status << '\n';
    std::cout << resp;
    return 0;
}
