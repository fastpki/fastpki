#include "kerberos.hpp"

#include <mutex>
#include <fstream>

#ifdef FASTPKI_WITH_KERBEROS
#include <gssapi/gssapi.h>
#include <cstdlib>
#include <vector>
#include <algorithm>   // std::search — the NTLMSSP signature scan below
#include <cstring>     // std::begin/end over the signature array
#endif

namespace pki::krb {

#ifndef FASTPKI_WITH_KERBEROS

bool available() { return false; }

AcceptResult accept_spnego(const std::string&, const std::string&) {
    return {false, "", "Kerberos support not built (configure -DFASTPKI_WITH_KERBEROS=ON)"};
}

#else

bool available() { return true; }

namespace {
// The krb5 mechanism OID, 1.2.840.113554.1.2.2.
//
// Spelled out rather than including <gssapi/gssapi_krb5.h> for `gss_mech_krb5`: that
// header is MIT-specific, and this file already compiles against whatever GSSAPI the
// platform provides (Alpine krb5-dev in the image, Homebrew krb5 here).
unsigned char kKrb5MechOidBytes[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02};
gss_OID_desc kKrb5MechOid = {sizeof kKrb5MechOidBytes, kKrb5MechOidBytes};

// Flatten a GSSAPI major/minor status into a readable string.
//
// ⚠️ THE MECHANISM OID IS WHAT MAKES THE MINOR STATUS READABLE. A minor status is
// mechanism-specific, and `gss_display_status` picks the error table from its mech_type
// argument. This passed GSS_C_NO_OID, so there was no table to consult and every krb5
// minor collapsed to the same string:
//
//     gss_accept_sec_context: Unspecified GSS failure.  Minor code may provide more
//     information; Unknown error
//
// Three different faults rendered identically while bringing up the lab AD domain — wrong
// principal in the keytab, an RC4 service ticket against an AES256-only keytab, and a
// suspected kvno mismatch — each costing a round of hypothesis-and-test. krb5 names all
// of them outright ("Request ticket server ... not found in keytab", "Encryption type ...
// not permitted").
//
// The major status is generic to GSSAPI and is still decoded with no OID; only the minor
// needs the mechanism. `mech` is the mechanism the acceptor actually negotiated where we
// have it, and the krb5 OID otherwise — a keytab that cannot even be read fails before any
// mechanism is negotiated, and that error is a krb5 one.
std::string gss_err(OM_uint32 major, OM_uint32 minor, gss_OID mech = GSS_C_NO_OID) {
    std::string out;
    for (int which = 0; which < 2; ++which) {
        // ⚠️ A MINOR OF ZERO MEANS "THERE IS NO MINOR STATUS" — do not ask for it.
        // MEASURED: a malformed SPNEGO token fails with major="Invalid token was supplied"
        // and minor=0, and asking gss_display_status to render 0 produces the literal
        // "Unknown error". That trailing clause is what made every failure look alike; it
        // was never a decoding problem for this case, it was a status that does not exist
        // being printed as though it did.
        if (which == 1 && minor == 0) break;
        OM_uint32 code = which == 0 ? major : minor;
        int type = which == 0 ? GSS_C_GSS_CODE : GSS_C_MECH_CODE;
        gss_OID table = which == 0 ? GSS_C_NO_OID
                                   : (mech != GSS_C_NO_OID ? mech : &kKrb5MechOid);
        OM_uint32 ctx = 0, m = 0;
        do {
            gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
            if (gss_display_status(&m, code, type, table, &ctx, &msg) != GSS_S_COMPLETE)
                break;
            if (msg.length) {
                if (!out.empty()) out += "; ";
                out.append(static_cast<char*>(msg.value), msg.length);
            }
            gss_release_buffer(&m, &msg);
        } while (ctx != 0);
    }
    // ⚠️ Always carry the RAW minor code. A mechanism we did not anticipate still renders
    // as something unhelpful, and the number is greppable against krb5_err.et — which is
    // the difference between "unknown" and a five-second answer. Costs one short suffix.
    if (minor != 0) out += " [minor=" + std::to_string(static_cast<unsigned long>(minor)) + "]";
    return out.empty() ? "unknown GSSAPI error" : out;
}

// Is this Negotiate token NTLM rather than Kerberos?
//
// ⚠️ WORTH DETECTING SEPARATELY BECAUSE IT IS THE ONE FAILURE THAT LOOKS LIKE ALL THE
// OTHERS. gss_accept_sec_context() rejects an NTLM token with GSS_S_FAILURE and NO minor
// status — the same shape as a wrong service key, a stale kvno, or an SPN owned by another
// account. All four then read as "the keytab is broken", and the keytab is fine.
//
// It is also common rather than exotic. Windows falls back to NTLM whenever it cannot use
// Kerberos for a host: the URL is outside the Local Intranet zone (a public-suffix FQDN is,
// by default), or it names an IP address, or the caller holds no ticket. Measured while
// bringing this up: a probe using `Invoke-WebRequest -UseDefaultCredentials` against an
// internet-zone FQDN produced exactly this, and the ticket the machine account could
// perfectly well obtain was never requested.
//
// Recognised by the "NTLMSSP\0" signature alone — see the warning in the body for why the
// mechanism OID is the wrong thing to match, and beats parsing SPNEGO to answer a question
// that only needs a yes.
bool looks_like_ntlm(const std::string& t) {
    // ⚠️ THE "NTLMSSP\0" SIGNATURE, NEVER THE NTLM MECHANISM OID.
    //
    // The first version of this also searched for 1.3.6.1.4.1.311.2.2.10, and that is
    // wrong in a way that would have broken working deployments: a Windows NegTokenInit
    // advertises the mechanisms it SUPPORTS — normally [MS-KRB5, KRB5, NTLM] — so the NTLM
    // OID is present in the token even when Kerberos is the mechanism actually selected
    // and the authentication is about to succeed. Matching on it would report a healthy
    // Kerberos client as an NTLM fallback and refuse it before GSSAPI ever saw the token.
    //
    // The signature is the safe discriminator: it appears only inside a real NTLM message
    // (Negotiate/Challenge/Authenticate), never in a mechanism list. Searched anywhere in
    // the token rather than only at the start, because SPNEGO may carry it as the
    // mechToken of a NegTokenInit rather than the client sending it bare.
    static const char kSig[8] = {'N','T','L','M','S','S','P','\0'};
    if (t.size() < sizeof kSig) return false;
    return std::search(t.begin(), t.end(),
                       std::begin(kSig), std::end(kSig)) != t.end();
}

} // namespace

// ⚠️ NO SPN PARAMETER, BECAUSE THERE NEVER WAS ONE IN EFFECT. This took `spn` and
// discarded it — the parameter name was commented out — while the acceptor credential is
// acquired with GSS_C_NO_NAME, which means "any principal this keytab holds". A keytab for
// an HTTP service holds that service's key, so the SPN it would have named is the one the
// keytab already carries. The setting was rendered in the console and documented in three
// places, and changing it did nothing.
AcceptResult accept_spnego(const std::string& token, const std::string& keytab) {
    AcceptResult r;
    if (token.empty()) { r.error = "empty Negotiate token"; return r; }

    // Answer before GSSAPI does, because GSSAPI cannot say this.
    if (looks_like_ntlm(token)) {
        r.error = "the client offered NTLM, not Kerberos — this endpoint accepts Kerberos "
                  "only. Windows falls back to NTLM when it cannot use Kerberos for the "
                  "URL: the host is outside the Local Intranet zone, or the URL names an IP "
                  "address rather than the name the SPN was registered for, or the caller "
                  "holds no ticket (a local account and a key-authenticated SSH session "
                  "both have none). The keytab is not implicated.";
        return r;
    }

    // ⚠️ SERIALISED, AND NOT FOR THE SAKE OF THE CREDENTIAL CACHE. setenv() is not
    // thread-safe: it may reallocate and free the environment block, while getenv() inside
    // libkrb5 walks it. fastpki-ms is a threaded server and each directory carries its own
    // keytab, so two concurrent Negotiate requests had one thread rewriting KRB5_KTNAME
    // while another read it from inside gss_acquire_cred() — a use-after-free read, and on
    // musl two concurrent setenv() calls can free the same pointer twice.
    //
    // The keytab is per-directory, so this cannot simply be set once at startup. The lock
    // spans the whole acceptor rather than just the setenv, because the krb5 layer reads
    // the variable again while establishing the context, not only when acquiring the
    // credential. Kerberos acceptance is short and this costs concurrency only on the
    // SPNEGO path; a use-after-free costs the process.
    static std::mutex krb_env_mu;
    std::lock_guard<std::mutex> krb_lk(krb_env_mu);

    // Point the GSSAPI acceptor at the service keytab (the acceptor credential
    // is taken from it). Set before acquiring the credential.
    if (!keytab.empty()) ::setenv("KRB5_KTNAME", keytab.c_str(), 1);

    OM_uint32 major = 0, minor = 0;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                             GSS_C_NO_OID_SET, GSS_C_ACCEPT, &cred, nullptr, nullptr);
    if (GSS_ERROR(major)) {
        r.error = "gss_acquire_cred (keytab unreadable?): " + gss_err(major, minor);
        return r;
    }

    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_name_t   client = GSS_C_NO_NAME;
    gss_buffer_desc in_tok{token.size(), const_cast<char*>(token.data())};
    gss_buffer_desc out_tok = GSS_C_EMPTY_BUFFER;

    // ASK FOR THE MECHANISM. This out-parameter was nullptr, so the one value that
    // makes the minor status decodable was thrown away at the call that produces it.
    // Under SPNEGO the negotiated mechanism is normally krb5, but taking what the acceptor
    // reports beats assuming it.
    gss_OID mech = GSS_C_NO_OID;
    major = gss_accept_sec_context(&minor, &ctx, cred, &in_tok,
                                   GSS_C_NO_CHANNEL_BINDINGS, &client,
                                   &mech, &out_tok, nullptr, nullptr, nullptr);
    if (out_tok.length) gss_release_buffer(&minor, &out_tok);

    if (GSS_ERROR(major)) {
        r.error = "gss_accept_sec_context: " + gss_err(major, minor, mech);
    } else if (major & GSS_S_CONTINUE_NEEDED) {
        // We only support single-leg Kerberos (the common SPNEGO case); a
        // multi-round mechanism (e.g. NTLM) is rejected so the client falls back.
        r.error = "multi-leg negotiation not supported";
    } else {
        gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
        OM_uint32 m = 0;
        if (gss_display_name(&m, client, &name, nullptr) == GSS_S_COMPLETE && name.value) {
            r.principal.assign(static_cast<char*>(name.value), name.length);
            r.ok = !r.principal.empty();
            gss_release_buffer(&m, &name);
        } else {
            r.error = "gss_display_name failed";
        }
    }

    OM_uint32 m = 0;
    if (client != GSS_C_NO_NAME) gss_release_name(&m, &client);
    if (ctx != GSS_C_NO_CONTEXT)  gss_delete_sec_context(&m, &ctx, GSS_C_NO_BUFFER);
    if (cred != GSS_C_NO_CREDENTIAL) gss_release_cred(&m, &cred);
    return r;
}

#endif // FASTPKI_WITH_KERBEROS

// ⚠️ OUTSIDE THE #ifdef, ON PURPOSE. Writing a config file needs no GSSAPI, and keeping it
// outside means the rendering does not change with the build flag: a build without
// Kerberos still produces the same file from the same settings, so what an operator
// configured can be inspected — and tested — on a box that cannot accept a ticket. Behind
// the ifdef, the only way to see what we would write would be to have a krb5 build.
// ⚠️ THE SINGLE-REALM FORM DELEGATES rather than duplicating the rendering. Two writers
// producing "the same" file is how one of them quietly grows a difference -- and this one
// carries rules that matter (dns_lookup_kdc = false, refuse a realm with no KDC).
std::string write_krb5_conf(const std::string& realm,
                            const std::string& kdcs,
                            const std::string& path) {
    if (realm.empty()) return "";
    return write_krb5_conf(std::vector<std::pair<std::string, std::string>>{{realm, kdcs}}, path);
}

std::string write_krb5_conf(const std::vector<std::pair<std::string, std::string>>& realms,
                            const std::string& path) {
    if (realms.empty() || path.empty()) return "";
    const std::string& first = realms.front().first;
    if (first.empty()) return "";
    std::string body = "[libdefaults]\n    default_realm = " + first + "\n"
                       "    dns_lookup_kdc = false\n"
                       "    dns_lookup_realm = false\n"
                       "    rdns = false\n\n"
                       "[realms]\n";
    // ⚠️ dns_lookup_kdc = false IS THE POINT. Left true, krb5 silently ignores an empty or
    // wrong kdc list and goes back to the SRV lookup this file exists to replace — so a
    // misconfigured realm would still "work" on a host whose resolver happens to reach AD,
    // and fail on every other one. False makes the configuration the only answer.
    int n = 0;
    std::string domain_realm;
    for (const auto& [realm, kdcs] : realms) {
    if (realm.empty()) continue;
    body += "    " + realm + " = {\n";
    int n_this = 0;
    size_t start = 0;
    while (start <= kdcs.size()) {
        size_t comma = kdcs.find(',', start);
        std::string one = kdcs.substr(start, comma == std::string::npos ? std::string::npos
                                                                        : comma - start);
        // trim
        const size_t a = one.find_first_not_of(" \t");
        const size_t b = one.find_last_not_of(" \t");
        one = (a == std::string::npos) ? "" : one.substr(a, b - a + 1);
        if (!one.empty()) { body += "        kdc = " + one + "\n"; ++n; ++n_this; }
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    body += "    }\n";
    // The realm is the DNS root upper-cased, so the mapping back is the lower-cased realm.
    if (n_this > 0) {
        std::string dom = realm;
        for (char& c : dom) if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
        domain_realm += "    ." + dom + " = " + realm + "\n    " + dom + " = " + realm + "\n";
    }
    }
    // A realm with no KDC is not a configuration, it is a file that makes every ticket
    // request fail with "cannot find KDC" instead of falling back to something that might
    // have worked. Refuse to write it and say so by returning empty.
    if (n == 0) return "";
    body += "\n[domain_realm]\n" + domain_realm;

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return "";
    f << body;
    if (!f.good()) return "";
    f.close();
    ::setenv("KRB5_CONFIG", path.c_str(), 1);
    return path;
}

} // namespace pki::krb
